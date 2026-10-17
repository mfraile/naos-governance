"""Bounded native J2 terminal checkpoint with exact retained-object restart.

Publication and reversal are proved afresh under the same operation lock.
Every fully persisted move boundary resumes; partial preparation refuses.
"""

from __future__ import annotations

from . import v3_operation_context as operation_context
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
import ntpath
from types import SimpleNamespace
from pathlib import Path

from . import joint_capture as joint
from . import local_binding as lb, local_store as ls
from . import portable_provenance as pp
from . import rebind_checkpoint as leaf
from . import v3_j1_rebind_predecessor as j1
from . import v3_j2_registration as reg
from . import v3_operation_records as op
from . import v3_operation_program as programs
from .canonical import canonical_bytes
from . import v3_j2_publication as publication

CHECKPOINT = reg.J2 + "/checkpoint"
PROGRESS = CHECKPOINT + "/progress.json"
COMMITMENT = CHECKPOINT + "/commitment.json"
BINDING_STAGE = CHECKPOINT + "/binding.pending.json"
STATE_STAGE = CHECKPOINT + "/state.pending.json"
TERMINAL_STAGE = CHECKPOINT + "/terminal.pending.json"
OLD_BINDING = CHECKPOINT + "/binding.before.json"
OLD_STATE = CHECKPOINT + "/state.registered.before.json"
TERMINAL = reg.J2 + "/terminal.json"
SCHEMA = "naos.upgrade.v3_j2_checkpoint.v1"
PROGRESS_SCHEMA = "naos.upgrade.v3_j2_final_progress.v1"
JOURNALS = ("J00000001", "J00000002")


class J2CheckpointError(ValueError):
    pass


def _fail(message):
    raise J2CheckpointError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CheckpointInspection:
    phase: str
    outcome: str
    binding_sha256: str
    state_sha256: str
    terminal_sha256: str
    complete: bool
    mutation_authorized: bool = False
    pending_moves: tuple[tuple[str, str, str], ...] = ()


def checkpoint_records(plan, intent, registered, portable, capture, progress_raw):
    """Pure codecs, complete journal inventory, same binding ID in both outcomes."""
    _ctx = operation_context.for_plan(plan)
    p = plan.body
    journals = registered.body["journals"]
    body = {
        "schema": lb.BINDING_SCHEMA,
        "project_id": p["project_id"],
        "owner_sha256": p["owner_sha256"],
        "portable_head_sha256": portable.manifest_sha256,
        "binding_id": p["binding_id"],
        "observation": {
            "schema": lb.OBSERVATION_SCHEMA,
            "native": capture.body["native"],
            "leaves": capture.body["leaves"],
            "journals": journals,
            "transaction_state": "quiescent",
            "diagnostic_python_minor": None,
            "binding_id": p["binding_id"],
        },
    }
    from .foreign_store_version import BINDING_SCHEMA as RECEIVED_BINDING_SCHEMA, GATE_KEY
    # The registered state retains the exact predecessor gate. Its core journals
    # already include this operation; no receiving boundary is added here.
    from .foreign_store_version import STORE_SCHEMA as RECEIVED_STORE_SCHEMA, validate_gate
    if registered.body["schema"] == RECEIVED_STORE_SCHEMA:
        gate = registered.body[GATE_KEY]
        validate_gate(gate, journals)
        body["schema"] = RECEIVED_BINDING_SCHEMA
        body[GATE_KEY] = gate
    binding = lb.load_local_binding(lb.encode_local_binding(body))
    state = ls.load_local_store(
        ls.encode_local_store(
            {
                **registered.body,
                "binding_id": binding.body["binding_id"],
                "binding_sha256": binding.sha256,
                "active_journal_id": None,
            }
        )
    )
    progress = pp._load_json(progress_raw, "J2 final progress")
    terminal = ls.load_local_terminal(
        ls.encode_local_terminal(
            {
                "schema": ls.TERMINAL_SCHEMA,
                "intent_sha256": intent.sha256,
                "outcome": progress["outcome"],
                "progress_sha256": _sha(progress_raw),
                "binding_after_sha256": binding.sha256,
                "portable_head_sha256": portable.manifest_sha256,
            }
        )
    )
    ls.reconcile_registration(state, binding, _ctx.checkpoint.JOURNALS)
    ls.reconcile_terminal_reference(
        state,
        _ctx.journal_id,
        terminal,
        progress_sha256=_sha(progress_raw),
        binding_after=binding,
    )
    return binding, state, terminal


def _operation(native, plan, evidence):
    _ctx = operation_context.for_plan(plan)
    raw = native.read(_ctx.registration.INTENT)
    body = pp._load_json(raw, "J2 intent")
    intent = op.load_operation_intent(
        raw,
        plan,
        evidence["predecessor_binding"],
        evidence["predecessor_store"],
        evidence["capture"],
        body["storage_witnesses"],
        evidence["predecessor_record_witnesses"],
        approved_plan_sha256=plan.sha256,
        plan_evidence=evidence,
    )
    registered = op.registration_store(
        intent,
        plan,
        evidence["predecessor_binding"],
        evidence["predecessor_store"],
        plan_evidence=evidence,
    )
    return intent, registered


def _sources(native):
    _ctx = operation_context.from_custody(native)
    names = native.children(_ctx.checkpoint.CHECKPOINT)
    return {
        "binding": _ctx.checkpoint.OLD_BINDING if "binding.before.json" in names else _ctx.registration.BINDING,
        "state": _ctx.checkpoint.OLD_STATE if "state.registered.before.json" in names else _ctx.registration.STATE,
    }


def _result(root, custody, plan, evidence, program, sources=None, pending_sources=(), pending_identities=None):
    kwargs = {"checkpoint_sources": sources}
    if custody.windows:
        kwargs["checkpoint_pending_sources"] = pending_sources
        kwargs["checkpoint_pending_identities"] = pending_identities
    result = publication._inspect_locked(
        root, custody, plan, evidence, program, **kwargs
    )
    if getattr(result, "pending_moves", ()):
        _fail("Checkpoint requires settled native publication before local completion")
    if result.head_installed:
        if not result.complete:
            _fail(
                "Installed new head requires complete forward publication before checkpoint"
            )
        outcome = "committed"
    else:
        if result.phases != ("ready",) * len(program.body["publications"]) or any(
            x != "staged" for x in result.directory_phases
        ):
            _fail("Rollback checkpoint requires fully reversed native publication")
        outcome = "rolled_back"
    context = (
        joint._held_windows(str(root), (), custody.reader.handles)
        if custody.windows
        else joint._held_posix(root, ())
    )
    with context as held:
        portable, capture = held.result.portable, held.result.working_tree
    expected_head = plan.body[
        "prospective_head_sha256"
        if outcome == "committed"
        else "prior_portable_head_sha256"
    ]
    if (
        portable.manifest_sha256 != expected_head
        or portable.owner_sha256 != plan.body["owner_sha256"]
    ):
        _fail("Actual replayed portable head differs from proven outcome")
    return result, outcome, portable, capture


def _progress(plan, intent, program, result, outcome, portable, capture):
    _ctx = operation_context.for_plan(plan)
    return canonical_bytes(
        {
            "schema": _ctx.checkpoint.PROGRESS_SCHEMA,
            "journal_id": _ctx.journal_id,
            "plan_sha256": plan.sha256,
            "intent_sha256": intent.sha256,
            "program_sha256": program.sha256,
            "outcome": outcome,
            "portable_head_sha256": portable.manifest_sha256,
            "publication_phases": list(result.phases),
            "directory_phases": list(result.directory_phases),
            "capture": capture.body,
        }
    )


def _prepare(root, custody, plan, evidence, program, pins, requested_outcome):
    _ctx = operation_context.for_plan(plan)
    result, outcome, portable, capture = _result(root, custody, plan, evidence, program)
    if requested_outcome == "committed" and outcome != requested_outcome:
        _fail("Requested committed checkpoint has no installed new head")
    with reg._fresh_native(root, custody, custody.windows) as native:
        intent, registered = _operation(native, plan, evidence)
        old_binding_witness = reg._read_exact(
            native, _ctx.registration.BINDING, evidence["predecessor_binding"].raw
        )
        old_state_witness = reg._read_exact(native, _ctx.registration.STATE, registered.raw)
    progress = _progress(plan, intent, program, result, outcome, portable, capture)
    binding, state, terminal = checkpoint_records(
        plan, intent, registered, portable, capture, progress
    )
    directory_witness = reg._pin_directory(custody, _ctx.checkpoint.CHECKPOINT, create=True, pins=pins)
    new = {}
    for path, raw in (
        (_ctx.checkpoint.PROGRESS, progress),
        (_ctx.checkpoint.BINDING_STAGE, binding.raw),
        (_ctx.checkpoint.STATE_STAGE, state.raw),
        (_ctx.checkpoint.TERMINAL_STAGE, terminal.raw),
    ):
        new[path] = {
            "sha256": _sha(raw),
            "witness": leaf._write_new(custody, path, raw),
        }
    # Compare creation witnesses before committing them. Same-byte replacements
    # with unchanged commitments must never be adopted.
    with reg._fresh_native(root, custody, custody.windows) as native:
        reg._names(
            native,
            _ctx.checkpoint.CHECKPOINT,
            {
                "progress.json",
                "binding.pending.json",
                "state.pending.json",
                "terminal.pending.json",
            },
        )
        for path, raw in (
            (_ctx.checkpoint.PROGRESS, progress),
            (_ctx.checkpoint.BINDING_STAGE, binding.raw),
            (_ctx.checkpoint.STATE_STAGE, state.raw),
            (_ctx.checkpoint.TERMINAL_STAGE, terminal.raw),
        ):
            if reg._read_exact(native, path, raw) != new[path]["witness"]:
                _fail("Checkpoint stage substituted before commitment")
        if (
            reg._read_exact(native, _ctx.registration.BINDING, evidence["predecessor_binding"].raw)
            != old_binding_witness
            or reg._read_exact(native, _ctx.registration.STATE, registered.raw) != old_state_witness
        ):
            _fail("Checkpoint predecessor changed during preparation")
    body = {
        "schema": _ctx.checkpoint.SCHEMA,
        "plan_sha256": plan.sha256,
        "program_sha256": program.sha256,
        "intent_sha256": intent.sha256,
        "outcome": outcome,
        "directory_witness": directory_witness,
        "old_binding_witness": old_binding_witness,
        "old_state_witness": old_state_witness,
        "records": new,
    }
    if custody.windows:
        from .windows_v3_publication_witness import (
            capture_file_witnesses,
        )

        with reg._fresh_native(root, custody, True) as native:
            expected = []
            for path in (
                _ctx.registration.BINDING,
                _ctx.registration.STATE,
                _ctx.checkpoint.BINDING_STAGE,
                _ctx.checkpoint.STATE_STAGE,
                _ctx.checkpoint.TERMINAL_STAGE,
            ):
                native.read(path)
                expected.append(native.observations[path])
        body["windows_files"] = pp._load_json(
            capture_file_witnesses(custody, expected),
            "Windows checkpoint rename witnesses",
        )
        _windows_identities(body, evidence, (binding, state, terminal))
    witness = leaf._write_new(custody, _ctx.checkpoint.COMMITMENT, canonical_bytes(body))
    with reg._fresh_native(root, custody, custody.windows) as native:
        if reg._read_exact(native, _ctx.checkpoint.COMMITMENT, canonical_bytes(body)) != witness:
            _fail("New checkpoint commitment substituted")
    return outcome


def _inspect_locked(root, custody, plan, evidence, program):
    _ctx = operation_context.for_plan(plan)
    if custody.windows:
        return _inspect_windows_locked(root, custody, plan, evidence, program)
    with reg._fresh_native(root, custody, custody.windows) as native:
        sources = _sources(native)
    result, outcome, portable, capture = _result(
        root, custody, plan, evidence, program, sources
    )
    with reg._fresh_native(root, custody, custody.windows) as native:
        intent, registered = _operation(native, plan, evidence)
        progress = _progress(plan, intent, program, result, outcome, portable, capture)
        binding, state, terminal = checkpoint_records(
            plan, intent, registered, portable, capture, progress
        )
        raw = native.read(_ctx.checkpoint.COMMITMENT)
        commit = pp._load_json(raw, "J2 checkpoint commitment")
        required = {
            "schema",
            "plan_sha256",
            "program_sha256",
            "intent_sha256",
            "outcome",
            "directory_witness",
            "old_binding_witness",
            "old_state_witness",
            "records",
        }
        if (
            type(commit) is not dict
            or set(commit) != required
            or canonical_bytes(commit) != raw
            or commit["schema"] != _ctx.checkpoint.SCHEMA
            or commit["plan_sha256"] != plan.sha256
            or commit["program_sha256"] != program.sha256
            or commit["intent_sha256"] != intent.sha256
            or commit["outcome"] != outcome
            or commit["directory_witness"] != native.directory(_ctx.checkpoint.CHECKPOINT)
            or type(commit["records"]) is not dict
            or set(commit["records"])
            != {_ctx.checkpoint.PROGRESS, _ctx.checkpoint.BINDING_STAGE, _ctx.checkpoint.STATE_STAGE, _ctx.checkpoint.TERMINAL_STAGE}
        ):
            _fail("Malformed or substituted checkpoint commitment")
        for path, record_raw in (
            (_ctx.checkpoint.PROGRESS, progress),
            (_ctx.checkpoint.BINDING_STAGE, binding.raw),
            (_ctx.checkpoint.STATE_STAGE, state.raw),
            (_ctx.checkpoint.TERMINAL_STAGE, terminal.raw),
        ):
            row = commit["records"][path]
            if (
                type(row) is not dict
                or set(row) != {"sha256", "witness"}
                or row["sha256"] != _sha(record_raw)
            ):
                _fail("Checkpoint record content differs from fresh semantic replay")
            lb._validate_witness(
                row["witness"], capture.body["native"]["platform"], "file"
            )
        if (
            reg._read_exact(native, _ctx.checkpoint.PROGRESS, progress)
            != commit["records"][_ctx.checkpoint.PROGRESS]["witness"]
        ):
            _fail("Final progress substituted or current capture changed")
        expected = {"progress.json", "commitment.json"}
        root_names = native.children(_ctx.registration.ROOT)
        journal_names = native.children(_ctx.registration.J2)
        phases = []
        for source, live, retained, stage, old_raw, new_raw, old_witness in (
            (
                "binding",
                _ctx.registration.BINDING,
                _ctx.checkpoint.OLD_BINDING,
                _ctx.checkpoint.BINDING_STAGE,
                evidence["predecessor_binding"].raw,
                binding.raw,
                commit["old_binding_witness"],
            ),
            (
                "state",
                _ctx.registration.STATE,
                _ctx.checkpoint.OLD_STATE,
                _ctx.checkpoint.STATE_STAGE,
                registered.raw,
                state.raw,
                commit["old_state_witness"],
            ),
        ):
            names = native.children(_ctx.checkpoint.CHECKPOINT)
            retained_present = retained.rsplit("/", 1)[1] in names
            stage_present = stage.rsplit("/", 1)[1] in names
            live_present = live.rsplit("/", 1)[1] in root_names
            if not retained_present and live_present and stage_present:
                phase = "prepared"
                old_path, new_path = live, stage
            elif retained_present and not live_present and stage_present:
                phase = "retained"
                old_path, new_path = retained, stage
            elif retained_present and live_present and not stage_present:
                phase = "installed"
                old_path, new_path = retained, live
            else:
                _fail("Unknown checkpoint old/stage/live topology")
            if (
                reg._read_exact(native, old_path, old_raw) != old_witness
                or reg._read_exact(native, new_path, new_raw)
                != commit["records"][stage]["witness"]
            ):
                _fail("Checkpoint object substituted or changed")
            expected.update(
                x.rsplit("/", 1)[1]
                for x in (retained, stage)
                if x.rsplit("/", 1)[1] in names
            )
            phases.append(phase)
        terminal_present = "terminal.json" in journal_names
        terminal_stage_present = "terminal.pending.json" in native.children(_ctx.checkpoint.CHECKPOINT)
        if terminal_present == terminal_stage_present:
            _fail("Unknown checkpoint terminal stage/live topology")
        terminal_path = _ctx.checkpoint.TERMINAL if terminal_present else _ctx.checkpoint.TERMINAL_STAGE
        if (
            reg._read_exact(native, terminal_path, terminal.raw)
            != commit["records"][_ctx.checkpoint.TERMINAL_STAGE]["witness"]
        ):
            _fail("Checkpoint terminal substituted or changed")
        if terminal_stage_present:
            expected.add("terminal.pending.json")
        reg._names(native, _ctx.checkpoint.CHECKPOINT, expected)
        allowed = [
            ("prepared", "prepared", False),
            ("retained", "prepared", False),
            ("installed", "prepared", False),
            ("installed", "retained", False),
            ("installed", "installed", False),
            ("installed", "installed", True),
        ]
        topology = (*phases, terminal_present)
        if topology not in allowed:
            _fail("Out-of-order checkpoint topology")
        phase = (
            "prepared",
            "binding_retained",
            "binding_installed",
            "state_retained",
            "state_installed",
            "complete",
        )[allowed.index(topology)]
        # Full semantic terminal chain: J1 keeps its historical result binding.
        if _ctx != operation_context.DEFAULT or getattr(custody, 'migration_candidate', None) is not None:
            proof = custody.completed_prefix
            for journal, old_terminal, progress_sha, historical_binding in proof.terminals:
                ls.reconcile_terminal_reference(state, journal, old_terminal,
                    progress_sha256=progress_sha, binding_after=historical_binding)
        else:
            j1_names = native.children(j1.PROGRESS)
            last = j1.PROGRESS + "/" + sorted(j1_names)[-1]
            ls.reconcile_terminal_reference(
                state,
                "J00000001",
                ls.load_local_terminal(native.read(j1.TERMINAL)),
                progress_sha256=_sha(native.read(last)),
                binding_after=evidence["predecessor_binding"],
            )
        for directory in (_ctx.registration.ROOT, _ctx.registration.J2, _ctx.checkpoint.CHECKPOINT):
            native.children(directory, final=True)
    custody.check_lock()
    return (
        CheckpointInspection(
            phase,
            outcome,
            binding.sha256,
            state.sha256,
            terminal.sha256,
            phase == "complete",
        ),
        commit,
        (binding, state, terminal),
    )


def _validated(
    plan, expected_plan_sha256, evidence, program, expected_program_sha256, handles
):
    if (
        type(plan) is not op.ValidatedOperationPlan
        or plan.sha256 != expected_plan_sha256
        or type(program) is not programs.ValidatedPublicationProgram
        or program.sha256 != expected_program_sha256
    ):
        _fail("Exact approved plan and publication program required")
    op._verified_plan(plan, evidence)
    if plan.body["host"] != (
        "windows" if os.name == "nt" or handles is not None else "posix"
    ):
        _fail("Checkpoint host differs from approved native plan")
    programs.load_publication_program(program.raw, plan, evidence)


def inspect_j2_checkpoint(
    project_root,
    *,
    plan,
    expected_plan_sha256,
    plan_evidence,
    program,
    expected_program_sha256,
    handles=None,
):
    _ctx = operation_context.for_plan(plan)
    _validated(
        plan,
        expected_plan_sha256,
        plan_evidence,
        program,
        expected_program_sha256,
        handles,
    )
    root = Path(project_root)
    with operation_context.held_store(
        root, journal_ids=_ctx.checkpoint.JOURNALS, handles=handles
    , context=_ctx) as custody:
        return _inspect_locked(root, custody, plan, plan_evidence, program)[0]


def complete_j2_checkpoint(
    project_root,
    *,
    plan,
    expected_plan_sha256,
    plan_evidence,
    program,
    expected_program_sha256,
    outcome=None,
    handles=None,
):
    _ctx = operation_context.for_plan(plan)
    _validated(
        plan,
        expected_plan_sha256,
        plan_evidence,
        program,
        expected_program_sha256,
        handles,
    )
    if outcome not in (None, "committed", "rolled_back"):
        _fail("Unsupported requested checkpoint outcome")
    root = Path(project_root)
    try:
        with ExitStack() as pins:
            with operation_context.held_store(
                root, journal_ids=_ctx.checkpoint.JOURNALS, handles=handles
            , context=_ctx) as custody:
                with reg._fresh_native(root, custody, custody.windows) as native:
                    exists = "checkpoint" in native.children(_ctx.registration.J2)
                if not exists:
                    actual = _prepare(
                        root, custody, plan, plan_evidence, program, pins, outcome
                    )
                    if outcome == "committed" and actual != outcome:
                        _fail(
                            "Requested committed checkpoint has no installed new head"
                        )
                else:
                    reg._pin_directory(custody, _ctx.checkpoint.CHECKPOINT, create=False, pins=pins)
                for _ in range(11):
                    result, commit, records = _inspect_locked(
                        root, custody, plan, plan_evidence, program
                    )
                    if outcome == "committed" and result.outcome != outcome:
                        _fail(
                            "Requested committed checkpoint has no installed new head"
                        )
                    if result.pending_moves:
                        identities = _windows_identities(commit, plan_evidence, records)
                        with _windows_backend(root, custody) as backend:
                            for source, destination, original in result.pending_moves:
                                backend.restore_pending(
                                    source, destination, identities[original]
                                )
                        custody.check_lock()
                        continue
                    if result.complete:
                        return result
                    binding, state, terminal = records
                    moves = {
                        "prepared": (
                            _ctx.registration.BINDING,
                            _ctx.checkpoint.OLD_BINDING,
                            plan_evidence["predecessor_binding"].raw,
                            commit["old_binding_witness"],
                        ),
                        "binding_retained": (
                            _ctx.checkpoint.BINDING_STAGE,
                            _ctx.registration.BINDING,
                            binding.raw,
                            commit["records"][_ctx.checkpoint.BINDING_STAGE]["witness"],
                        ),
                        "binding_installed": (
                            _ctx.registration.STATE,
                            _ctx.checkpoint.OLD_STATE,
                            b"",
                            commit["old_state_witness"],
                        ),
                        "state_retained": (
                            _ctx.checkpoint.STATE_STAGE,
                            _ctx.registration.STATE,
                            state.raw,
                            commit["records"][_ctx.checkpoint.STATE_STAGE]["witness"],
                        ),
                        "state_installed": (
                            _ctx.checkpoint.TERMINAL_STAGE,
                            _ctx.checkpoint.TERMINAL,
                            terminal.raw,
                            commit["records"][_ctx.checkpoint.TERMINAL_STAGE]["witness"],
                        ),
                    }
                    # The registered source is semantically derived, never taken
                    # from an unchecked byte-only Path read as move authority.
                    if result.phase == "binding_installed":
                        with reg._fresh_native(
                            root, custody, custody.windows
                        ) as native:
                            _, registered = _operation(native, plan, plan_evidence)
                        moves[result.phase] = (
                            _ctx.registration.STATE,
                            _ctx.checkpoint.OLD_STATE,
                            registered.raw,
                            commit["old_state_witness"],
                        )
                    if custody.windows:
                        identities = _windows_identities(commit, plan_evidence, records)
                        source, destination, _raw, _witness = moves[result.phase]
                        original = {
                            _ctx.registration.BINDING: _ctx.registration.BINDING,
                            _ctx.checkpoint.BINDING_STAGE: _ctx.checkpoint.BINDING_STAGE,
                            _ctx.registration.STATE: _ctx.registration.STATE,
                            _ctx.checkpoint.STATE_STAGE: _ctx.checkpoint.STATE_STAGE,
                            _ctx.checkpoint.TERMINAL_STAGE: _ctx.checkpoint.TERMINAL_STAGE,
                        }[source]
                        with _windows_backend(root, custody) as backend:
                            backend.move_exact(
                                source, destination, identities[original]
                            )
                        custody.check_lock()
                    else:
                        reg._move_posix(custody, *moves[result.phase])
                _fail("Checkpoint exceeded fixed five-move completion bound")
    except J2CheckpointError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise J2CheckpointError(f"Native J2 checkpoint refused: {exc}") from exc


def _windows_expected(commit, evidence, records):
    _ctx = operation_context.for_evidence(evidence)
    binding, state, terminal = records
    registered = ls.load_local_store(
        ls.encode_local_store(
            {
                **state.body,
                "binding_sha256": evidence["predecessor_binding"].sha256,
                "active_journal_id": _ctx.journal_id,
            }
        )
    )
    values = (
        (
            _ctx.registration.BINDING,
            evidence["predecessor_binding"].raw,
            commit["old_binding_witness"],
        ),
        (_ctx.registration.STATE, registered.raw, commit["old_state_witness"]),
        (_ctx.checkpoint.BINDING_STAGE, binding.raw, commit["records"][_ctx.checkpoint.BINDING_STAGE]["witness"]),
        (_ctx.checkpoint.STATE_STAGE, state.raw, commit["records"][_ctx.checkpoint.STATE_STAGE]["witness"]),
        (_ctx.checkpoint.TERMINAL_STAGE, terminal.raw, commit["records"][_ctx.checkpoint.TERMINAL_STAGE]["witness"]),
    )
    expected = []
    for path, raw, witness in values:
        lb._validate_witness(witness, "Windows", "file")
        if (
            witness["presence"] != "present"
            or not witness["security"]["dacl_protected"]
        ):
            _fail("Windows checkpoint rename witnesses must be protected private files")
        expected.append(
            {
                "path": path,
                "metadata": witness,
                "content": {"sha256": _sha(raw), "size_decimal": str(len(raw))},
            }
        )
    return expected


def _windows_identities(commit, evidence, records):
    from .windows_v3_publication_witness import load_file_witnesses

    identities, _security = load_file_witnesses(
        canonical_bytes(commit["windows_files"]),
        _windows_expected(commit, evidence, records),
    )
    return identities


def _windows_backend(root, custody):
    _ctx = operation_context.from_custody(custody)
    from .windows_restoring_backend import WindowsRestoringBackend

    paths = (
        _ctx.registration.BINDING,
        _ctx.registration.STATE,
        _ctx.checkpoint.OLD_BINDING,
        _ctx.checkpoint.OLD_STATE,
        _ctx.checkpoint.BINDING_STAGE,
        _ctx.checkpoint.STATE_STAGE,
        _ctx.checkpoint.TERMINAL_STAGE,
        _ctx.checkpoint.TERMINAL,
    )
    return WindowsRestoringBackend(
        custody.reader.handles,
        {path: ntpath.join(str(root), *path.split("/")) for path in paths},
    )


def _pending_projected(actual, expected):
    if actual == expected:
        return True
    changed = dict(expected)
    if expected.get("attributes_hex") != "00000080":
        return False
    changed["attributes_hex"] = "00000020"
    return actual == changed


def _inspect_windows_locked(root, custody, plan, evidence, program):
    """Validate complete local topology and full identities before publication replay.

    Only the latest completed no-replace move can be pending. The publication
    anchor sees only fixed selected retained sources with independently proved
    NORMAL-to-ARCHIVE metadata transients. All native read lanes close before
    the caller can invoke the existing strict V2 restoration backend.
    """
    _ctx = operation_context.for_plan(plan)
    with joint._held_windows(str(root), (), custody.reader.handles) as held:
        portable, capture = held.result.portable, held.result.working_tree
    with reg._fresh_native(root, custody, True) as native:
        names = native.children(_ctx.checkpoint.CHECKPOINT)
        sources = _sources(native)
        intent, registered = _operation(native, plan, evidence)
        progress_raw = native.read(_ctx.checkpoint.PROGRESS)
        progress_body = pp._load_json(progress_raw, "Windows J2 final progress")
        outcome = progress_body.get("outcome")
        if outcome not in ("committed", "rolled_back"):
            _fail("Unsupported Windows checkpoint outcome")
        expected_head = plan.body[
            "prospective_head_sha256"
            if outcome == "committed"
            else "prior_portable_head_sha256"
        ]
        if (
            portable.manifest_sha256 != expected_head
            or portable.owner_sha256 != plan.body["owner_sha256"]
        ):
            _fail("Windows checkpoint actual portable head differs from outcome")
        declared = SimpleNamespace(
            phases=progress_body.get("publication_phases"),
            directory_phases=progress_body.get("directory_phases"),
        )
        progress = _progress(
            plan, intent, program, declared, outcome, portable, capture
        )
        if progress_raw != progress:
            _fail("Windows final progress differs from fresh complete native capture")
        binding, state, terminal = checkpoint_records(
            plan, intent, registered, portable, capture, progress
        )
        records = (binding, state, terminal)
        raw = native.read(_ctx.checkpoint.COMMITMENT)
        commit = pp._load_json(raw, "Windows J2 checkpoint commitment")
        required = {
            "schema",
            "plan_sha256",
            "program_sha256",
            "intent_sha256",
            "outcome",
            "directory_witness",
            "old_binding_witness",
            "old_state_witness",
            "records",
            "windows_files",
        }
        if (
            type(commit) is not dict
            or set(commit) != required
            or canonical_bytes(commit) != raw
            or commit["schema"] != _ctx.checkpoint.SCHEMA
            or commit["plan_sha256"] != plan.sha256
            or commit["program_sha256"] != program.sha256
            or commit["intent_sha256"] != intent.sha256
            or commit["outcome"] != outcome
            or commit["directory_witness"] != native.directory(_ctx.checkpoint.CHECKPOINT)
            or type(commit["records"]) is not dict
            or set(commit["records"])
            != {_ctx.checkpoint.PROGRESS, _ctx.checkpoint.BINDING_STAGE, _ctx.checkpoint.STATE_STAGE, _ctx.checkpoint.TERMINAL_STAGE}
        ):
            _fail("Malformed Windows checkpoint commitment")
        for path, record_raw in (
            (_ctx.checkpoint.PROGRESS, progress),
            (_ctx.checkpoint.BINDING_STAGE, binding.raw),
            (_ctx.checkpoint.STATE_STAGE, state.raw),
            (_ctx.checkpoint.TERMINAL_STAGE, terminal.raw),
        ):
            row = commit["records"][path]
            if (
                type(row) is not dict
                or set(row) != {"sha256", "witness"}
                or row["sha256"] != _sha(record_raw)
            ):
                _fail("Windows checkpoint record differs from fresh semantic replay")
            lb._validate_witness(row["witness"], "Windows", "file")
        if (
            reg._read_exact(native, _ctx.checkpoint.PROGRESS, progress)
            != commit["records"][_ctx.checkpoint.PROGRESS]["witness"]
        ):
            _fail("Windows final progress substituted")
        expected_names = {"progress.json", "commitment.json"}
        phases, current = [], {}
        root_names = native.children(_ctx.registration.ROOT)
        journal_names = native.children(_ctx.registration.J2)
        for live, retained, stage, old_raw, new_raw in (
            (
                _ctx.registration.BINDING,
                _ctx.checkpoint.OLD_BINDING,
                _ctx.checkpoint.BINDING_STAGE,
                evidence["predecessor_binding"].raw,
                binding.raw,
            ),
            (_ctx.registration.STATE, _ctx.checkpoint.OLD_STATE, _ctx.checkpoint.STATE_STAGE, registered.raw, state.raw),
        ):
            retained_present = retained.rsplit("/", 1)[1] in names
            stage_present = stage.rsplit("/", 1)[1] in names
            live_present = live.rsplit("/", 1)[1] in root_names
            if not retained_present and live_present and stage_present:
                phase, old_path, new_path = "prepared", live, stage
            elif retained_present and not live_present and stage_present:
                phase, old_path, new_path = "retained", retained, stage
            elif retained_present and live_present and not stage_present:
                phase, old_path, new_path = "installed", retained, live
            else:
                _fail("Unknown Windows checkpoint old/stage/live topology")
            reg._read_exact(native, old_path, old_raw)
            reg._read_exact(native, new_path, new_raw)
            current[live], current[stage] = old_path, new_path
            expected_names.update(
                x.rsplit("/", 1)[1]
                for x in (retained, stage)
                if x.rsplit("/", 1)[1] in names
            )
            phases.append(phase)
        terminal_present = "terminal.json" in journal_names
        terminal_stage_present = "terminal.pending.json" in names
        if terminal_present == terminal_stage_present:
            _fail("Unknown Windows terminal stage/live topology")
        terminal_path = _ctx.checkpoint.TERMINAL if terminal_present else _ctx.checkpoint.TERMINAL_STAGE
        reg._read_exact(native, terminal_path, terminal.raw)
        current[_ctx.checkpoint.TERMINAL_STAGE] = terminal_path
        if terminal_stage_present:
            expected_names.add("terminal.pending.json")
        reg._names(native, _ctx.checkpoint.CHECKPOINT, expected_names)
        root_expected = {"scope.lock", "journals"} | {
            path.rsplit("/", 1)[1]
            for path in (_ctx.registration.BINDING, _ctx.registration.STATE)
            if path.rsplit("/", 1)[1] in root_names
        }
        reg._names(native, _ctx.registration.ROOT, root_expected)
        reg._names(native, _ctx.registration.JOURNALS, set(_ctx.checkpoint.JOURNALS))
        reg._names(
            native,
            _ctx.registration.J2,
            (reg._prepared_names(native) - {"state.registered.pending.json"})
            | {"state.before.json", "publication", "checkpoint"}
            | ({"terminal.json"} if terminal_present else set()),
        )
        allowed = [
            ("prepared", "prepared", False),
            ("retained", "prepared", False),
            ("installed", "prepared", False),
            ("installed", "retained", False),
            ("installed", "installed", False),
            ("installed", "installed", True),
        ]
        topology = (*phases, terminal_present)
        if topology not in allowed:
            _fail("Out-of-order Windows checkpoint topology")
        index = allowed.index(topology)
        phase = (
            "prepared",
            "binding_retained",
            "binding_installed",
            "state_retained",
            "state_installed",
            "complete",
        )[index]
        moves = (
            (_ctx.registration.BINDING, _ctx.checkpoint.OLD_BINDING, _ctx.registration.BINDING),
            (_ctx.checkpoint.BINDING_STAGE, _ctx.registration.BINDING, _ctx.checkpoint.BINDING_STAGE),
            (_ctx.registration.STATE, _ctx.checkpoint.OLD_STATE, _ctx.registration.STATE),
            (_ctx.checkpoint.STATE_STAGE, _ctx.registration.STATE, _ctx.checkpoint.STATE_STAGE),
            (_ctx.checkpoint.TERMINAL_STAGE, _ctx.checkpoint.TERMINAL, _ctx.checkpoint.TERMINAL_STAGE),
        )
        frontier = None if index == 0 else moves[index - 1]
        identities = _windows_identities(commit, evidence, records)
        observations = dict(native.observations)
        if _ctx == operation_context.DEFAULT and getattr(custody, 'migration_candidate', None) is None:
            j1_names = native.children(j1.PROGRESS)
            last = j1.PROGRESS + "/" + sorted(j1_names)[-1]
            ls.reconcile_terminal_reference(
                state,
                "J00000001",
                ls.load_local_terminal(native.read(j1.TERMINAL)),
                progress_sha256=_sha(native.read(last)),
                binding_after=evidence["predecessor_binding"],
            )
        for directory in (_ctx.registration.ROOT, _ctx.registration.J2, _ctx.checkpoint.CHECKPOINT):
            native.children(directory, final=True)
    expected_observations = {
        row["path"]: row for row in _windows_expected(commit, evidence, records)
    }
    with _windows_backend(root, custody) as backend:
        pending = _windows_pending_moves(
            backend, current, identities, frontier, observations, expected_observations,
            context=_ctx,
        )
    pending_sources = tuple(
        move[1] for move in pending if move[1] in (_ctx.checkpoint.OLD_BINDING, _ctx.checkpoint.OLD_STATE)
    )
    result, actual_outcome, actual_portable, actual_capture = _result(
        root, custody, plan, evidence, program, sources, pending_sources,
        {destination:identities[original] for _source,destination,original in pending
         if destination in pending_sources},
    )
    if (
        _progress(
            plan,
            intent,
            program,
            result,
            actual_outcome,
            actual_portable,
            actual_capture,
        )
        != progress
        or actual_capture != capture
    ):
        _fail(
            "Windows publication semantics or capture changed during checkpoint validation"
        )
    if _ctx != operation_context.DEFAULT or getattr(custody, 'migration_candidate', None) is not None:
        # A cold restart has no cached completed-prefix facts. The publication
        # anchor above must rederive them under this custody before reconciliation.
        proof = custody.completed_prefix
        for journal, old_terminal, progress_sha, historical_binding in proof.terminals:
            ls.reconcile_terminal_reference(state, journal, old_terminal,
                progress_sha256=progress_sha, binding_after=historical_binding)
    custody.check_lock()
    return (
        CheckpointInspection(
            phase,
            outcome,
            binding.sha256,
            state.sha256,
            terminal.sha256,
            phase == "complete" and not pending,
            pending_moves=tuple(pending),
        ),
        commit,
        records,
    )


def _windows_pending_moves(
    backend, current, identities, frontier, observations, expected_observations, *, context
):
    # Topology has already proved the exact legal prefix. Compare the complete
    # five-object full-identity inventory, including every nominally absent slot.
    if type(context) is not operation_context.OperationContext:
        _fail("Windows checkpoint requires explicit operation context")
    _ctx = context
    originals = {_ctx.registration.BINDING, _ctx.registration.STATE, _ctx.checkpoint.BINDING_STAGE, _ctx.checkpoint.STATE_STAGE, _ctx.checkpoint.TERMINAL_STAGE}
    slots = (
        _ctx.registration.BINDING,
        _ctx.registration.STATE,
        _ctx.checkpoint.OLD_BINDING,
        _ctx.checkpoint.OLD_STATE,
        _ctx.checkpoint.BINDING_STAGE,
        _ctx.checkpoint.STATE_STAGE,
        _ctx.checkpoint.TERMINAL_STAGE,
        _ctx.checkpoint.TERMINAL,
    )
    if (
        set(current) != originals
        or set(identities) != originals
        or set(expected_observations) != originals
        or len(set(current.values())) != 5
        or not set(current.values()) <= set(slots)
    ):
        _fail("Incomplete or aliased Windows checkpoint identity inventory")
    pending = []
    for original, actual_path in current.items():
        expected = identities[original]
        observed = backend.observe(actual_path)
        if observed != expected:
            if (
                frontier is None
                or (actual_path, original) != (frontier[1], frontier[2])
                or not backend.pending_matches(actual_path, expected)
            ):
                _fail(
                    "Windows checkpoint identity differs outside single pending frontier"
                )
            pending.append(frontier)
        metadata = observations[actual_path]["metadata"]
        baseline = expected_observations[original]["metadata"]
        if metadata != baseline and (
            frontier is None
            or (actual_path, original) != (frontier[1], frontier[2])
            or pending != [frontier]
            or not _pending_projected(metadata, baseline)
        ):
            _fail(
                "Windows projected checkpoint witness differs from exact rename identity"
            )
    for slot in slots:
        if slot not in current.values() and backend.observe(slot) is not None:
            _fail("Unexpected Windows checkpoint object occupies absent slot")
    if len(pending) > 1:
        _fail("Multiple pending Windows checkpoint moves")
    return pending
