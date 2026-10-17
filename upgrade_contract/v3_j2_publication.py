"""Bounded J2 publication from a sealed stage set.

This internal publisher supports J1 rebind -> J2 file publication with owned
missing portable and managed parent directories. All moves are derived from the validated program and sealed native
observations. The public manifest object, not a progress marker, is the
forward-only boundary. Terminal checkpoint composition is below this layer.
"""

from __future__ import annotations

from . import v3_operation_context as operation_context

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os
import stat
import ntpath
from pathlib import Path

from . import local_binding as lb
from . import portable_provenance as pp
from . import rebind_checkpoint as checkpoint
from . import v3_j1_rebind_predecessor as j1
from . import v3_j2_registration as reg
from . import v3_operation_program as programs
from . import v3_operation_projection as projection
from . import v3_operation_records as operation
from . import v3_publication_stage as stage
from .canonical import canonical_bytes
from .transaction import rename_no_replace_at

DIRECTORY_STAGES = stage.PUBLICATION + "/directory-stages"
DIRECTORY_COMMITMENT = stage.PUBLICATION + "/directory-commitment.json"
WINDOWS_COMMITMENT = stage.PUBLICATION + "/windows-commitment.json"
DIRECTORY_SCHEMA = "naos.upgrade.v3_j2_directory_stages.v1"


class J2PublicationError(ValueError):
    pass


def _fail(message):
    raise J2PublicationError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _at(observation, path):
    return {**observation, "path": path}


def _same(actual, expected, path):
    return actual == _at(expected, path)


def _absent(observation):
    return (
        observation["content"] is None
        and observation["metadata"]["presence"] == "absent"
    )


@dataclass(frozen=True)
class PublicationInspection:
    phases: tuple[str, ...]
    head_installed: bool
    complete: bool
    directory_phases: tuple[str, ...] = ()
    mutation_authorized: bool = False
    pending_moves: tuple[tuple[str, str, str], ...] = ()


def _record_anchor(
    root,
    custody,
    plan,
    evidence,
    program,
    *,
    checkpoint_sources=None,
    checkpoint_pending_sources=(),
    checkpoint_pending_identities=None,
):
    """Re-derive the registered bridge and sealed private commitments.

    No old working-tree capture is required here: some approved slots may
    already have moved. Historical J1 semantics use the old portable overlay.
    """
    _ctx = operation_context.for_plan(plan)
    sources = {"binding": _ctx.registration.BINDING, "state": _ctx.registration.STATE}
    if checkpoint_sources is not None:
        if (
            type(checkpoint_sources) is not dict
            or set(checkpoint_sources) != set(sources)
            or checkpoint_sources["binding"]
            not in (_ctx.registration.BINDING, _ctx.registration.J2 + "/checkpoint/binding.before.json")
            or checkpoint_sources["state"]
            not in (_ctx.registration.STATE, _ctx.registration.J2 + "/checkpoint/state.registered.before.json")
        ):
            _fail("Invalid fixed checkpoint source mapping")
        sources = checkpoint_sources
    pending_allowed = {
        _ctx.registration.J2 + "/checkpoint/binding.before.json",
        _ctx.registration.J2 + "/checkpoint/state.registered.before.json",
    }
    if (
        type(checkpoint_pending_sources) is not tuple
        or len(set(checkpoint_pending_sources)) != len(checkpoint_pending_sources)
        or not set(checkpoint_pending_sources)
        <= pending_allowed & set(sources.values())
        or (checkpoint_pending_sources and not custody.windows)
    ):
        _fail("Invalid fixed checkpoint pending source selection")
    if checkpoint_pending_identities is not None:
        from .windows_rename_identity import RenameIdentity
        if (not custody.windows or type(checkpoint_pending_identities) is not dict or
                set(checkpoint_pending_identities) != set(checkpoint_pending_sources) or
                any(type(identity) is not RenameIdentity for identity in checkpoint_pending_identities.values())):
            _fail("Invalid fixed checkpoint pending identity mapping")
        for identity in checkpoint_pending_identities.values():
            identity.validate()
    with reg._fresh_native(root, custody, custody.windows) as native:
        root_names = native.children(_ctx.registration.ROOT)
        required_root = {"scope.lock", "journals"} | {
            key + ".json"
            for key, value in sources.items()
            if value == getattr(reg, key.upper())
        }
        if (
            not required_root
            <= root_names
            <= {"scope.lock", "journals", "state.json", "binding.json"}
        ):
            _fail("Unknown or missing checkpoint root inventory")
        if _ctx != operation_context.DEFAULT or getattr(custody, 'migration_candidate', None) is not None:
            if checkpoint_pending_sources and checkpoint_pending_identities is None:
                _fail('Repeat-operation pending source requires full checkpoint identities')
            from .v3_operation_history import _inspect_native
            prior_portable = pp.load_portable_snapshot(projection._Reader(evidence['portable_files']))
            proof = _inspect_native(native, prior_portable, _ctx,
                binding_source=sources['binding'], state_source=_ctx.registration.BACKUP, portable_files=evidence['portable_files'],
                pending_binding_identity=(checkpoint_pending_identities or {}).get(sources['binding']))
            prior_state, prior_binding = proof.state, proof.binding
            custody.completed_prefix = proof
            if (prior_state != evidence['predecessor_store'] or prior_binding != evidence['predecessor_binding'] or
                not _checkpoint_metadata_matches(native.observations[sources['binding']]['metadata'],
                    evidence['predecessor_record_witnesses']['binding'],sources['binding'],checkpoint_pending_sources) or
                native.observations[_ctx.registration.BACKUP]['metadata'] != evidence['predecessor_record_witnesses']['state']):
                _fail('Historical completed prefix differs from approved predecessor')
        else:
            reg._names(native, _ctx.registration.JOURNALS, set(_ctx.journal_ids))
            reg._names(
                native,
                j1.JOURNAL,
                {"plan.json", "intent.json", "progress", "terminal.json"},
            )
            progress_names = native.children(j1.PROGRESS)
            if not 1 <= len(progress_names) <= j1.MAX_PROGRESS or progress_names != {
                f"{i:08d}.json" for i in range(len(progress_names))
            }:
                _fail("Historical J1 progress inventory differs")
            prior_portable = pp.load_portable_snapshot(
                projection._Reader(evidence["portable_files"])
            )
            raw = {
                path: native.read(path)
                for path in (
                    j1.PLAN,
                    j1.INTENT,
                    *(j1.PROGRESS + "/" + x for x in sorted(progress_names)),
                    j1.TERMINAL,
                    _ctx.registration.BACKUP,
                    sources["binding"],
                )
            }
            raw[j1.STATE] = raw.pop(_ctx.registration.BACKUP)
            raw[_ctx.registration.BINDING] = raw.pop(sources["binding"])
            _j1_plan, j1_intent, j1_history, prior_state, prior_binding = j1._semantic_j1(
                raw, prior_portable
            )
            if (
                prior_state != evidence["predecessor_store"]
                or prior_binding != evidence["predecessor_binding"]
                or not _checkpoint_metadata_matches(
                    native.observations[sources["binding"]]["metadata"],
                    evidence["predecessor_record_witnesses"]["binding"],
                    sources["binding"],
                    checkpoint_pending_sources,
                )
                or native.observations[_ctx.registration.BACKUP]["metadata"]
                != evidence["predecessor_record_witnesses"]["state"]
                or not _checkpoint_metadata_matches(
                    native.observations[sources["binding"]]["metadata"],
                    j1_history.records[-1].body["publication_witness"],
                    sources["binding"],
                    checkpoint_pending_sources,
                )
                or native.lock_witness != j1_intent.body["storage_witnesses"]["lock"]
                or native.directory(j1.JOURNAL)
                != j1_intent.body["storage_witnesses"]["journal"]
            ):
                _fail("Historical J1 checkpoint or native witness changed")
        if (_native_directory(native, ".naos/upgrade-v1")["presence"] != "absent"
                and getattr(custody, 'migration_candidate', None) is None
                and getattr(custody, 'receiving_legacy', None) is None):
            _fail("Legacy control appeared")
        expected_j2 = (reg._prepared_names(native) - {"state.registered.pending.json"}) | {
            "state.before.json",
            "publication",
        }
        allowed_j2 = (
            (expected_j2,)
            if checkpoint_sources is None
            else (
                expected_j2 | {"checkpoint"},
                expected_j2 | {"checkpoint", "terminal.json"},
            )
        )
        if native.children(_ctx.registration.J2) not in allowed_j2:
            _fail("Unknown J2 inventory")
        reg._names(native, _ctx.registration.PROGRESS, set())
        if (
            native.read(_ctx.registration.PLAN) != plan.raw
            or native.read(_ctx.registration.PRIOR_BINDING) != prior_binding.raw
            or native.read(_ctx.registration.PRIOR_STATE) != prior_state.raw
        ):
            _fail("J2 prepared records differ from approved plan")
        intent_raw = native.read(_ctx.registration.INTENT)
        intent_body = pp._load_json(intent_raw, "J2 intent")
        intent = operation.load_operation_intent(
            intent_raw,
            plan,
            prior_binding,
            prior_state,
            evidence["capture"],
            intent_body["storage_witnesses"],
            evidence["predecessor_record_witnesses"],
            approved_plan_sha256=plan.sha256,
            plan_evidence=evidence,
        )
        if intent.body["storage_witnesses"][
            "lock"
        ] != custody.lock_witness or intent.body["storage_witnesses"][
            "journal"
        ] != native.directory(_ctx.registration.J2):
            _fail("J2 intent native storage witness changed")
        registered = operation.registration_store(
            intent, plan, prior_binding, prior_state, plan_evidence=evidence
        )
        if native.read(sources["state"]) != registered.raw:
            _fail("Registered state bytes changed")
        reg_commit = pp._load_json(
            native.read(_ctx.registration.COMMITMENT), "J2 registration commitment"
        )
        expected_reg = reg._commitment(
            plan,
            intent,
            prior_state,
            registered,
            reg_commit["stage_witness"],
            reg_commit["progress_witness"],
            reg_commit["old_rename_identity"],
            reg_commit["stage_rename_identity"],
            reg_commit.get("replay_binding"),
        )
        reg._validate_replay(native, reg_commit, plan, evidence)
        if (
            native.read(_ctx.registration.COMMITMENT) != expected_reg
            or not _checkpoint_metadata_matches(
                native.observations[sources["state"]]["metadata"],
                reg_commit["stage_witness"],
                sources["state"],
                checkpoint_pending_sources,
            )
            or native.directory(_ctx.registration.PROGRESS) != reg_commit["progress_witness"]
        ):
            _fail("Registered native object or commitment changed")
        base_names = {
            "program.json",
            "targets.json",
            "stages",
            "retained",
            "commitment.json",
        }
        publication_names = native.children(_ctx.staging.PUBLICATION)
        complete_names = base_names | {"directory-stages", "directory-commitment.json"}
        if custody.windows:
            complete_names.add("windows-commitment.json")
        if publication_names not in (base_names, complete_names):
            _fail("Unknown or partial J2 publication preparation inventory")
        if native.read(_ctx.staging.PROGRAM) != program.raw:
            _fail("Sealed publication program changed")
        targets_raw = native.read(_ctx.staging.TARGETS)
        targets = pp._load_json(targets_raw, "J2 target observations")
        sealed_raw = native.read(_ctx.staging.COMMITMENT)
        sealed = pp._load_json(sealed_raw, "J2 stage commitment")
        if (
            sealed.get("schema") != stage.SCHEMA
            or sealed.get("program_sha256") != program.sha256
            or sealed.get("intent_sha256") != intent.sha256
            or sealed.get("registered_state_sha256") != registered.sha256
            or sealed.get("target_observations_sha256") != _sha(targets_raw)
            or sealed.get("record_witnesses")
            != {
                _ctx.staging.PROGRAM: native.observations[_ctx.staging.PROGRAM],
                _ctx.staging.TARGETS: native.observations[_ctx.staging.TARGETS],
            }
            or sealed.get("storage_witnesses")
            != {
                path: native.directory(path)
                for path in (_ctx.staging.PUBLICATION, _ctx.staging.STAGES, _ctx.staging.RETAINED)
            }
            or canonical_bytes(sealed) != sealed_raw
        ):
            _fail("Publication stage commitment or native storage changed")
        if (
            type(targets) is not dict
            or set(targets) != {"directories", "leaves"}
            or type(sealed.get("stages")) is not list
            or len(sealed["stages"]) != len(program.body["publications"])
        ):
            _fail("Malformed target or stage inventory")
        _publication_children(native, _ctx.staging.STAGES)
        _publication_children(native, _ctx.staging.RETAINED)
        directory_commitment = None
        if "directory-commitment.json" in publication_names:
            directory_commitment = _directory_commitment(
                native, program, targets, intent.sha256
            )
            if custody.windows:
                from .windows_v3_publication_witness import (
                    load_file_witnesses,
                )

                windows_raw = native.read(_ctx.publication.WINDOWS_COMMITMENT)
                if (
                    _sha(windows_raw)
                    != directory_commitment["windows_commitment_sha256"]
                    or native.observations[_ctx.publication.WINDOWS_COMMITMENT]
                    != directory_commitment["windows_commitment_witness"]
                ):
                    _fail("Windows pre-move commitment changed")
                custody._j2_windows_authority = load_file_witnesses(
                    windows_raw, _windows_expected(sealed, targets, program)
                )
        for path in (
            j1.JOURNAL,
            j1.PROGRESS,
            _ctx.registration.J2,
            _ctx.registration.PROGRESS,
            _ctx.staging.PUBLICATION,
            _ctx.staging.STAGES,
            _ctx.staging.RETAINED,
        ):
            if path in (_ctx.staging.STAGES, _ctx.staging.RETAINED):
                _publication_children(native, path, final=True)
            else:
                native.children(path, final=True)
        _retain_history_baseline(native, custody, sources, root)
        return sealed, targets, directory_commitment


def _missing_directories(program, targets):
    _ctx = operation_context.for_program(program)
    observed = {x["path"]: x["witness"] for x in targets["directories"]}
    public_paths = {
        x["path"]
        for x in program.body["required_directories"]
        if x["path"] != _ctx.registration.J2
        and x["path"] != _ctx.staging.PUBLICATION
        and not x["path"].startswith(_ctx.staging.PUBLICATION + "/")
    }
    if set(observed) != public_paths:
        _fail("Directory target coverage differs from program")
    result = [
        x["path"]
        for x in program.body["required_directories"]
        if x["path"] in observed and observed[x["path"]]["presence"] == "absent"
    ]
    if result != sorted(result, key=lambda x: (x.count("/"), x)):
        _fail("Missing directory order differs from publication program")
    return result


def _retain_history_baseline(native, custody, sources, root):
    """Retain this call's immutable control objects across our own mutations.

    Binding/state are intentionally moved by the checkpoint layer, which
    validates their exact identities separately. This baseline is local to the
    held operation, not a new persistent authority or a byte-only repair rule.
    """
    _ctx = operation_context.from_custody(custody)
    custody.check_lock()
    _check_history_baseline(native, custody)
    if getattr(custody, "_j2_history_baseline", None) is None:
        proof = getattr(custody, 'completed_prefix', None)
        typed_payload_files = {} if proof is None else proof.retained_leaves
        records = deepcopy(
            {
                path: observation
                for path, observation in native.observations.items()
                # The fixed current lock is proved through the acquired handle,
                # not reopened as an immutable history file. Receiving capture
                # keeps its observation/inventory; all historical leaves remain.
                if path != reg.ris.LOCK and path not in sources.values() and path not in typed_payload_files and
                (getattr(custody, 'migration_candidate', None) is None or path != pp.MANIFEST_PATH)
            }
        )
        directories = {
            path: (
                deepcopy(native.directory(path)),
                native.children(path) if path != _ctx.registration.J2 else None,
            )
            for path in (j1.JOURNAL, j1.PROGRESS, _ctx.registration.J2, _ctx.registration.PROGRESS)
        }
        replay_binding = pp._load_json(native.read(_ctx.registration.COMMITMENT), "registration variant").get("replay_binding")
        proof = getattr(custody, 'completed_prefix', None)
        if proof is not None:
            directories.update(proof.directories)
        custody._j2_history_baseline = (root, records, directories, deepcopy(replay_binding),
            () if proof is None else proof.replay_bindings, {} if proof is None else proof.retained_leaves, {} if proof is None else proof.retained_directories)


def _check_history_baseline(native, custody):
    baseline = getattr(custody, "_j2_history_baseline", None)
    if baseline is None:
        return
    custody.check_lock()
    _root, records, directories, replay_binding, historical_replays, historical_leaves, historical_directories = baseline
    from .v3_operation_history import recheck_payload_directories
    recheck_payload_directories(native,historical_directories)
    for context, binding in historical_replays:
        reg.replay.snapshot(native, expected=binding, context=context)
    for path, expected in historical_leaves.items():
        if native.reader.leaf(path) != expected:
            _fail('Immutable historical retained object changed during native custody')
    if replay_binding is not None:
        reg.replay.snapshot(native, expected=replay_binding)
    for path, expected in records.items():
        native.read(path)
        if native.observations[path] != expected:
            _fail("Immutable operation history object changed during native custody")
    for path, (expected, names) in directories.items():
        if native.directory(path) != expected:
            _fail("Immutable operation history directory changed during native custody")
        if names is not None:
            from .v3_operation_history import historical_children
            actual = historical_children(native, path,
                context=operation_context.from_custody(custody))
            if actual != names:
                _fail("Immutable operation history inventory changed during native custody")


def _revalidate_history_before_move(custody):
    from .v3_j1_migration_predecessor import validate_legacy
    validate_legacy(custody)
    baseline = getattr(custody, "_j2_history_baseline", None)
    if baseline is not None:
        with reg._fresh_native(baseline[0], custody, custody.windows) as native:
            _check_history_baseline(native, custody)


def _directory_commitment(native, program, targets, intent_sha256):
    _ctx = operation_context.for_program(program)
    missing = _missing_directories(program, targets)
    raw = native.read(_ctx.publication.DIRECTORY_COMMITMENT)
    body = pp._load_json(raw, "J2 directory commitment")
    fields = {
        "schema",
        "program_sha256",
        "intent_sha256",
        "stage_root_witness",
        "directories",
    }
    if native.windows:
        fields |= {"windows_commitment_sha256", "windows_commitment_witness"}
    if (
        type(body) is not dict
        or set(body) != fields
        or body["schema"] != _ctx.publication.DIRECTORY_SCHEMA
        or body["program_sha256"] != program.sha256
        or body["intent_sha256"] != intent_sha256
        or body["stage_root_witness"] != native.directory(_ctx.publication.DIRECTORY_STAGES)
        or type(body["directories"]) is not list
        or [x.get("path") for x in body["directories"]] != missing
        or canonical_bytes(body) != raw
    ):
        _fail("Directory commitment differs from approved absent parents")
    for index, row in enumerate(body["directories"], 1):
        if (
            type(row) is not dict
            or set(row) != {"path", "stage", "witness"}
            or row["stage"] != _ctx.publication.DIRECTORY_STAGES + f"/{index:08d}"
        ):
            _fail("Malformed directory stage row")
        lb._validate_witness(
            row["witness"],
            "Windows" if native.windows else native.reader.platform,
            "directory",
        )
        if row["witness"]["presence"] != "present":
            _fail("Directory stage witness absent")
    return body


def prepare_j2_directories(
    project_root: Path | str,
    *,
    plan,
    expected_plan_sha256,
    plan_evidence,
    program,
    expected_program_sha256,
    handles=None,
):
    """Stage and commit exact absent parent objects before any public move."""
    _ctx = operation_context.for_plan(plan)
    if (
        type(program) is not programs.ValidatedPublicationProgram
        or program.sha256 != expected_program_sha256
        or type(plan) is not operation.ValidatedOperationPlan
        or plan.sha256 != expected_plan_sha256
    ):
        _fail("Exact approved plan/program required")
    operation._verified_plan(plan, plan_evidence)
    programs.load_publication_program(program.raw, plan, plan_evidence)
    root = Path(project_root)
    with ExitStack() as pins:
        with operation_context.held_store(
            root, journal_ids=_ctx.journal_ids, handles=handles
        , context=_ctx) as custody:
            sealed, targets, existing = _record_anchor(
                root, custody, plan, plan_evidence, program
            )
            if existing is not None:
                _directory_topology(
                    root, custody, existing, program, targets, require_staged=True
                )
                return existing
            reg._pin_directory(custody, _ctx.staging.PUBLICATION, create=False, pins=pins)
            windows_raw = None
            if custody.windows:
                from .windows_v3_publication_witness import (
                    capture_file_witnesses,
                    load_file_witnesses,
                )

                windows_raw = capture_file_witnesses(
                    custody, _windows_expected(sealed, targets, program)
                )
                custody._j2_windows_authority = load_file_witnesses(
                    windows_raw, _windows_expected(sealed, targets, program)
                )
            if _topology(root, custody, program, sealed, targets).phases != (
                "ready",
            ) * len(program.body["publications"]):
                _fail("Directory preparation requires all file stages untouched")
            missing = _missing_directories(program, targets)
            root_witness = reg._pin_directory(
                custody, _ctx.publication.DIRECTORY_STAGES, create=True, pins=pins
            )
            rows = []
            for index, path in enumerate(missing, 1):
                name = f"{index:08d}"
                if custody.windows:
                    key = custody.reader.directory(_ctx.publication.DIRECTORY_STAGES)
                    parent = custody.reader.directories[key]
                    with custody.reader.handles.create_private_directory(
                        parent, name
                    ) as child:
                        witness = lb.project_windows_witness(
                            child.info(), child.security()
                        )
                        if not witness["security"][
                            "dacl_protected"
                        ] or custody.reader.handles.list_children(child, max_entries=1):
                            _fail(
                                "New Windows directory stage must be private, protected and empty"
                            )
                else:
                    parent = custody.reader.fds[_ctx.publication.DIRECTORY_STAGES]
                    from .portable_provenance_posix import (
                        _same_namespace,
                        _witness,
                    )

                    os.mkdir(name, 0o755, dir_fd=parent)
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent,
                    )
                    pins.callback(os.close, child)
                    os.fchmod(child, 0o755)
                    os.fsync(child)
                    observed = _witness(child, leaf=False, label=path)
                    _same_namespace(parent, name, observed, leaf=False, label=path)
                    witness = lb.project_posix_witness(observed.metadata)
                    if witness["mode_octal"] != "0755" or os.listdir(child):
                        _fail("New directory stage metadata or empty inventory differs")
                    os.fsync(parent)
                rows.append(
                    {
                        "path": path,
                        "stage": _ctx.publication.DIRECTORY_STAGES + "/" + name,
                        "witness": witness,
                    }
                )
            body = {
                "schema": _ctx.publication.DIRECTORY_SCHEMA,
                "program_sha256": program.sha256,
                "intent_sha256": sealed["intent_sha256"],
                "stage_root_witness": root_witness,
                "directories": rows,
            }
            if custody.windows:
                windows_created = checkpoint._write_new(
                    custody, _ctx.publication.WINDOWS_COMMITMENT, windows_raw
                )
                with reg._fresh_native(root, custody, True) as native:
                    if (
                        native.read(_ctx.publication.WINDOWS_COMMITMENT) != windows_raw
                        or native.observations[_ctx.publication.WINDOWS_COMMITMENT]["metadata"]
                        != windows_created
                    ):
                        _fail("Windows witness bytes changed during preparation")
                    body["windows_commitment_sha256"] = _sha(windows_raw)
                    body["windows_commitment_witness"] = native.observations[
                        _ctx.publication.WINDOWS_COMMITMENT
                    ]
            _directory_topology(
                root, custody, body, program, targets, require_staged=True
            )
            raw = canonical_bytes(body)
            commitment_created = checkpoint._write_new(
                custody, _ctx.publication.DIRECTORY_COMMITMENT, raw
            )
            with reg._fresh_native(root, custody, custody.windows) as native:
                loaded = _directory_commitment(
                    native, program, targets, body["intent_sha256"]
                )
                if (
                    loaded != body
                    or native.observations[_ctx.publication.DIRECTORY_COMMITMENT]["metadata"]
                    != commitment_created
                ):
                    _fail("Directory commitment changed after creation")
            _directory_topology(
                root, custody, body, program, targets, require_staged=True
            )
            return body


def _directory_topology(
    root, custody, commitment, program, targets, *, require_staged=False
):
    _ctx = operation_context.for_program(program)
    rows = commitment["directories"]
    phases = []
    permitted_children = None
    with reg._fresh_native(root, custody, custody.windows) as native:
        _check_history_baseline(native, custody)
        names = _publication_children(native, _ctx.publication.DIRECTORY_STAGES)
        for row in rows:
            public = _native_directory(native, row["path"])
            private = _native_directory(native, row["stage"])
            if public["presence"] == "absent" and private == row["witness"]:
                phase = "staged"
            elif public == row["witness"] and private["presence"] == "absent":
                phase = "published"
            else:
                _fail("Unknown or substituted directory stage/public topology")
            checked = row["stage"] if phase == "staged" else row["path"]
            children = _publication_children(native, checked)
            if phase == "published" and permitted_children is None:
                permitted_children = {}
                for path in [x["path"] for x in rows] + [
                    x["destination"] for x in program.body["publications"]
                ]:
                    parent, _, name = path.rpartition("/")
                    permitted_children.setdefault(parent, set()).add(name)
            permitted = (
                permitted_children.get(row["path"], set())
                if phase == "published"
                else set()
            )
            if not children <= permitted:
                _fail("Unknown child in committed directory; preserved")
            _publication_children(native, checked, final=True)
            phases.append(phase)
        expected = {
            f"{index:08d}" for index, phase in enumerate(phases, 1) if phase == "staged"
        }
        if names != expected or (require_staged and any(x != "staged" for x in phases)):
            _fail("Directory stage inventory or phase differs")
        if phases != sorted(phases, key={"published": 0, "staged": 1}.get):
            _fail("Directory publication order differs")
        _publication_children(native, _ctx.publication.DIRECTORY_STAGES, final=True)
    return tuple(phases)


def _topology(root, custody, program, sealed, targets):
    _ctx = operation_context.for_program(program)
    slots = program.body["publications"]
    old = {x["path"]: x for x in targets["leaves"]}
    if set(old) != {x["destination"] for x in slots} | {
        x["path"] for x in program.body["reused_portable_evidence"]
    }:
        _fail("Target inventory differs from approved publication program")
    phases = []
    pending = []
    with reg._fresh_native(root, custody, custody.windows) as native:
        _check_history_baseline(native, custody)
        stage_names = _publication_children(native, _ctx.staging.STAGES)
        retained_names = _publication_children(native, _ctx.staging.RETAINED)
        for slot, witness in zip(slots, sealed["stages"]):
            target = slot["destination"]
            before = old[target]
            after = witness
            if (
                witness["path"] != slot["stage"]
                or witness["content"]
                != {k: slot["after"][k] for k in ("sha256", "size_decimal")}
                or before["content"]
                != (
                    None
                    if slot["before"] is None
                    else {k: slot["before"][k] for k in ("sha256", "size_decimal")}
                )
            ):
                _fail("Sealed stage or predecessor differs from approved slot")
            stage_now = native.reader.leaf(slot["stage"])
            target_now = native.reader.leaf(target)
            retained_now = native.reader.leaf(slot["retained"])
            is_stage = _same(stage_now, after, slot["stage"])
            is_new = _same(target_now, after, target)
            is_old = _same(target_now, before, target)
            is_retained = _same(retained_now, before, slot["retained"])
            match_kind = {}
            if custody.windows:
                for label, observed, origin in (
                    ("stage", stage_now, slot["stage"]),
                    ("new", target_now, slot["stage"]),
                    ("old", target_now, target),
                    ("retained", retained_now, target),
                ):
                    if origin == target and slot["before"] is None:
                        match_kind[label] = None
                    else:
                        match_kind[label] = _windows_match(custody, observed, origin)
                is_stage, is_new, is_old, is_retained = (
                    bool(match_kind[k]) for k in ("stage", "new", "old", "retained")
                )
            if slot["before"] is None:
                if is_stage and _absent(target_now) and _absent(retained_now):
                    phase = "ready"
                elif _absent(stage_now) and is_new and _absent(retained_now):
                    phase = "installed"
                else:
                    _fail("Unknown new-file publication topology")
            elif is_stage and is_old and _absent(retained_now):
                phase = "ready"
            elif is_stage and _absent(target_now) and is_retained:
                phase = "old_retained"
            elif _absent(stage_now) and is_new and is_retained:
                phase = "installed"
            else:
                _fail("Unknown replacement publication topology")
            if custody.windows:
                # Each recognized phase identifies the only possible last move.
                candidates = []
                if phase == "ready":
                    if slot["before"] is not None and match_kind["stage"] != "exact":
                        _fail(
                            "Pending reverse stage followed by old-object restoration"
                        )
                    candidates = [("stage", target, slot["stage"], slot["stage"])]
                    if slot["before"] is not None:
                        candidates.append(("old", slot["retained"], target, target))
                elif phase == "old_retained":
                    candidates = [
                        ("retained", target, slot["retained"], target),
                        ("stage", target, slot["stage"], slot["stage"]),
                    ]
                elif phase == "installed":
                    candidates = [("new", slot["stage"], target, slot["stage"])]
                    # An original retained object must be settled before the stage moves.
                    if slot["before"] is not None and match_kind["retained"] != "exact":
                        _fail("Pending original move followed by a later installation")
                for label, source, destination, origin in candidates:
                    if match_kind[label] == "pending":
                        pending.append((len(phases), source, destination, origin))
            phases.append(phase)
        expected_stage = {
            f"{i:08d}" for i, phase in enumerate(phases, 1) if phase != "installed"
        }
        expected_retained = {
            f"{i:08d}"
            for i, (slot, phase) in enumerate(zip(slots, phases), 1)
            if slot["before"] is not None and phase != "ready"
        }
        if stage_names != expected_stage or retained_names != expected_retained:
            _fail("Unknown or aliased stage/retained namespace object")
        for item in targets["directories"]:
            if (
                item["witness"]["presence"] == "present"
                and not lb.directory_witness_matches(
                    _native_directory(native, item["path"]), item["witness"],
                    platform="Windows" if native.windows else native.reader.platform,
                )
            ):
                _fail("Approved parent directory native identity changed")
        for reuse in program.body["reused_portable_evidence"]:
            if native.reader.leaf(reuse["path"]) != old[reuse["path"]]:
                _fail("Reused portable dependency changed")
        _publication_children(native, _ctx.staging.STAGES, final=True)
        _publication_children(native, _ctx.staging.RETAINED, final=True)
    manifest_index = len(slots) - 1
    if slots[manifest_index]["role"] != "portable_manifest_forward_only":
        _fail("Manifest is not the final program slot")
    order = {"installed": 0, "old_retained": 1, "ready": 2}
    if [order[phase] for phase in phases] != sorted(
        order[phase] for phase in phases
    ) or (phases.count("old_retained") > 1):
        _fail("Publication slot topology is not a legal ordered prefix")
    if (
        any(phase != "installed" for phase in phases[:manifest_index])
        and phases[manifest_index] != "ready"
    ):
        _fail("Manifest reached before prior publications")
    if phases[manifest_index] == "old_retained" and any(
        phase != "installed" for phase in phases[:manifest_index]
    ):
        _fail("Manifest detached before prior publications")
    if len(pending) > 1:
        _fail("Multiple Windows pending moves are not authorized")
    if pending:
        index = pending[0][0]
        if (phases[index] == "ready" and index != phases.index("ready")) or (
            phases[index] == "installed"
            and index
            != max(i for i, value in enumerate(phases) if value == "installed")
        ):
            _fail("Windows pending move is not the ordered publication frontier")
    return PublicationInspection(
        tuple(phases),
        phases[-1] == "installed",
        all(x == "installed" for x in phases) and not pending,
        pending_moves=tuple(x[1:] for x in pending),
    )


def _open_parent(
    custody, relative, expected_directories, stack, index_growth_parents=frozenset()
):
    from .portable_provenance_posix import _same_namespace, _witness

    parent = custody.reader.fds[""]
    prefix = ""
    for part in relative.split("/") if relative else ():
        path = part if not prefix else prefix + "/" + part
        if path not in expected_directories or expected_directories[path] is None:
            _fail("Move parent lacks approved native witness")
        child = os.open(
            part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        stack.callback(os.close, child)
        observed = _witness(child, leaf=False, label=path)
        projected = lb.project_posix_witness(observed.metadata)
        if projected != expected_directories[path] and (
            path not in index_growth_parents or not lb.directory_witness_matches(
                projected, expected_directories[path],
                platform=str(observed.metadata["platform"]),
            )
        ):
            _fail("Move parent native identity changed")
        _same_namespace(parent, part, observed, leaf=False, label=path)
        parent, prefix = child, path
    return parent


def _move_posix(
    custody, source, destination, expected, expected_directories, index_growth_parents=frozenset()
):
    """Move one exact object by no-replace rename beneath pinned root/parents."""
    from .portable_provenance_posix import _same_namespace, _witness

    with ExitStack() as stack:
        source_parent_path, _, source_name = source.rpartition("/")
        dest_parent_path, _, dest_name = destination.rpartition("/")
        source_parent = _open_parent(
            custody, source_parent_path, expected_directories, stack, index_growth_parents
        )
        dest_parent = _open_parent(
            custody, dest_parent_path, expected_directories, stack, index_growth_parents
        )
        fd = os.open(
            source_name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=source_parent,
        )
        stack.callback(os.close, fd)
        observed = _witness(fd, leaf=True, label=source)
        if lb.project_posix_witness(observed.metadata) != expected["metadata"]:
            _fail("Move source native identity changed")
        checkpoint._check_bytes(lambda n: os.read(fd, n), expected["raw"])
        _same_namespace(source_parent, source_name, observed, leaf=True, label=source)
        root_before = (
            os.fstat(custody.reader.fds[""])
            if not source_parent_path or not dest_parent_path else None
        )
        custody.check_lock()
        root_entries = (
            _root_file_move_inventory(custody.reader.fds[""])
            if not source_parent_path or not dest_parent_path else None
        )
        parent_entries = {
            path: (fd, _root_file_move_inventory(fd), _witness(fd, leaf=False, label=path))
            for path, fd in ((source_parent_path, source_parent), (dest_parent_path, dest_parent))
            if root_entries is not None and path and "/" not in path
        }
        for path, (parent_fd, _entries, _before) in parent_entries.items():
            if _root_entry_signature(os.fstat(parent_fd)) != root_entries[path]:
                _fail("Root child changed before the approved file move")
        custody.check_lock()
        if root_before is not None:
            root_after = os.fstat(custody.reader.fds[""])
            if ((root_before.st_mtime_ns, root_before.st_ctime_ns)
                    != (root_after.st_mtime_ns, root_after.st_ctime_ns)):
                _fail("Root changed before the approved file move")
        rename_no_replace_at(source_parent, source_name, dest_parent, dest_name)
        moved = _witness(fd, leaf=True, label=destination)
        if lb.project_posix_witness(moved.metadata) != expected["metadata"]:
            _fail("Moved object native identity changed")
        _same_namespace(dest_parent, dest_name, moved, leaf=True, label=destination)
        if root_entries is not None:
            _advance_owned_root_file_change(
                custody, source, destination, root_entries, fd, parent_entries
            )
        os.fsync(source_parent)
        os.fsync(dest_parent)
    custody.check_lock()


def _move(
    custody, source, destination, expected, expected_directories, index_growth_parents=frozenset()
):
    _revalidate_history_before_move(custody)
    if custody.windows:
        identity = _windows_identity(custody, expected)
        with _windows_move_backend(
            custody, source, destination, expected_directories
        ) as backend:
            backend.move_exact(source, destination, identity)
        from .v3_j1_migration_predecessor import validate_legacy
        validate_legacy(custody)
        return
    _move_posix(
        custody, source, destination, expected, expected_directories, index_growth_parents
    )
    from .v3_j1_migration_predecessor import validate_legacy
    validate_legacy(custody)


def _expected_bytes(slot, evidence, program, stage_observation, prior_observation):
    return {
        "metadata": stage_observation["metadata"],
        "raw": program.publication_bytes[slot["destination"]],
    }, {
        "metadata": prior_observation["metadata"],
        "raw": (
            evidence["current_bytes"][slot["destination"]]
            if slot["role"].startswith("working_")
            else evidence["portable_files"][slot["destination"]]
        ),
    } if slot["before"] is not None else None


def publish_j2_destinations(
    project_root: Path | str,
    *,
    plan,
    expected_plan_sha256,
    plan_evidence,
    program,
    expected_program_sha256,
    rollback=False,
    handles=None,
):
    """Publish or exactly reverse program slots under the current native lock.

    A caller must separately complete the terminal checkpoint. Rollback is
    accepted only while the exact new manifest has not been installed.
    """
    _ctx = operation_context.for_plan(plan)
    try:
        if (
            type(program) is not programs.ValidatedPublicationProgram
            or program.sha256 != expected_program_sha256
            or type(plan) is not operation.ValidatedOperationPlan
            or plan.sha256 != expected_plan_sha256
            or program.body["journal_id"] != _ctx.journal_id
        ):
            _fail("Exact approved J2 plan and publication program required")
        operation._verified_plan(plan, plan_evidence)
        programs.load_publication_program(program.raw, plan, plan_evidence)
        root = Path(project_root)
        with operation_context.held_store(
            root, journal_ids=_ctx.journal_ids, handles=handles
        , context=_ctx) as custody:
            sealed, targets, directories = _record_anchor(
                root, custody, plan, plan_evidence, program
            )
            if directories is None:
                _fail("Exact directory commitment required before any destination move")
            directory_phases = _directory_topology(
                root, custody, directories, program, targets
            )
            phases = _topology(root, custody, program, sealed, targets)
            _validate_publication_order(phases, directory_phases)
            if rollback and phases.head_installed:
                _fail(
                    "Exact new portable head is installed; only forward completion is legal"
                )
            target_by_path = {x["path"]: x for x in targets["leaves"]}
            expected_directories = _expected_directories(
                custody, sealed, targets, directories
            )
            # Only parents already present in the sealed targets may acquire
            # an index. Created/empty directory commitments remain exact.
            index_growth_parents = frozenset(
                item["path"] for item in targets["directories"]
                if item["witness"]["presence"] == "present"
            )
            for source, destination, origin in phases.pending_moves:
                with _windows_move_backend(
                    custody, source, destination, expected_directories
                ) as backend:
                    backend.restore_pending(
                        source, destination, custody._j2_windows_authority[0][origin]
                    )
            if phases.pending_moves:
                phases = _topology(root, custody, program, sealed, targets)
                if phases.pending_moves:
                    _fail("Windows pending repair did not settle")
            if not rollback:
                for row, phase in zip(directories["directories"], directory_phases):
                    if phase == "staged":
                        _move_directory(
                            custody,
                            row["stage"],
                            row["path"],
                            row["witness"],
                            expected_directories,
                            index_growth_parents,
                        )
                        _directory_topology(
                            root, custody, directories, program, targets
                        )
            slots = program.body["publications"]
            if rollback:
                indices = range(len(slots) - 1, -1, -1)
            else:
                indices = range(len(slots))
            for index in indices:
                # An already-terminal slot needs no move. This initial snapshot
                # never authorizes a move: all actual moves retain fresh full
                # topology checks below, followed by one closing full scan.
                if phases.phases[index] == ("ready" if rollback else "installed"):
                    continue
                slot = slots[index]
                before = target_by_path[slot["destination"]]
                after = sealed["stages"][index]
                new_expected, old_expected = _expected_bytes(
                    slot, plan_evidence, program, after, before
                )
                phase = _topology(root, custody, program, sealed, targets).phases[index]
                if rollback:
                    if phase == "installed":
                        _move(
                            custody,
                            slot["destination"],
                            slot["stage"],
                            new_expected,
                            expected_directories,
                            index_growth_parents,
                        )
                        phase = "old_retained" if old_expected is not None else "ready"
                    if phase == "old_retained":
                        _move(
                            custody,
                            slot["retained"],
                            slot["destination"],
                            old_expected,
                            expected_directories,
                            index_growth_parents,
                        )
                else:
                    if phase == "ready" and old_expected is not None:
                        _move(
                            custody,
                            slot["destination"],
                            slot["retained"],
                            old_expected,
                            expected_directories,
                            index_growth_parents,
                        )
                        phase = "old_retained"
                    if phase in ("ready", "old_retained"):
                        _move(
                            custody,
                            slot["stage"],
                            slot["destination"],
                            new_expected,
                            expected_directories,
                            index_growth_parents,
                        )
                # The next actionable slot obtains a fresh complete topology;
                # the closing scan below also covers an all-terminal suffix.
                # Individual moves retain their native and history guards.
            # Mandatory even when every slot was skipped; directory rollback
            # and final completion must see a fresh complete file topology.
            _topology(root, custody, program, sealed, targets)
            if rollback:
                for row in reversed(directories["directories"]):
                    dphases = _directory_topology(
                        root, custody, directories, program, targets
                    )
                    index = directories["directories"].index(row)
                    if dphases[index] == "published":
                        _move_directory(
                            custody,
                            row["path"],
                            row["stage"],
                            row["witness"],
                            expected_directories,
                            index_growth_parents,
                        )
                        _directory_topology(
                            root, custody, directories, program, targets
                        )
            return _inspect_locked(root, custody, plan, plan_evidence, program)
    except J2PublicationError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise J2PublicationError(f"J2 destination publication refused: {exc}") from exc


def _move_directory(
    custody, source, destination, expected, expected_directories, index_growth_parents=frozenset()
):
    """Exact empty-directory no-replace publication/reversal; retain every object."""
    _revalidate_history_before_move(custody)
    from .portable_provenance_posix import _same_namespace, _witness
    from .transaction import _directory_matches_empty_at

    if custody.windows:
        from .windows_v3_directory_moves import move_empty_directory

        return move_empty_directory(
            custody, source, destination, expected, expected_directories
        )
    with ExitStack() as stack:
        source_parent_path, _, source_name = source.rpartition("/")
        destination_parent_path, _, destination_name = destination.rpartition("/")
        source_parent = _open_parent(
            custody, source_parent_path, expected_directories, stack, index_growth_parents
        )
        destination_parent = _open_parent(
            custody, destination_parent_path, expected_directories, stack, index_growth_parents
        )
        fd = os.open(
            source_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=source_parent,
        )
        stack.callback(os.close, fd)
        observed = _witness(fd, leaf=False, label=source)
        if lb.project_posix_witness(observed.metadata) != expected:
            _fail("Directory move source native identity changed")
        if not _directory_matches_empty_at(
            source_parent, source_name, observed.metadata
        ):
            _fail("Directory move requires the exact empty committed object")
        _same_namespace(source_parent, source_name, observed, leaf=False, label=source)
        custody.check_lock()
        rename_no_replace_at(
            source_parent, source_name, destination_parent, destination_name
        )
        _advance_owned_root_directory_change(
            custody, source_parent_path, destination_parent_path
        )
        moved = _witness(fd, leaf=False, label=destination)
        if lb.project_posix_witness(moved.metadata) != expected:
            _fail("Directory native identity changed after move")
        _same_namespace(
            destination_parent, destination_name, moved, leaf=False, label=destination
        )
        if not _directory_matches_empty_at(
            destination_parent, destination_name, observed.metadata
        ):
            _fail("Moved directory is no longer exactly empty; preserved")
        os.fsync(source_parent)
        os.fsync(destination_parent)
    custody.check_lock()


def _inspect_locked(
    root,
    custody,
    plan,
    plan_evidence,
    program,
    *,
    checkpoint_sources=None,
    checkpoint_pending_sources=(),
    checkpoint_pending_identities=None,
):
    """Read-only pre-checkpoint inspection under the caller's existing scope lock.

    A known checkpoint child is permitted but not validated by this layer.
    Binding and state must still be the registered predecessor checkpoint.
    """
    sealed, targets, directories = _record_anchor(
        root,
        custody,
        plan,
        plan_evidence,
        program,
        checkpoint_sources=checkpoint_sources,
        checkpoint_pending_sources=checkpoint_pending_sources,
        checkpoint_pending_identities=checkpoint_pending_identities,
    )
    if directories is None:
        _fail("Directory commitment missing")
    dphases = _directory_topology(root, custody, directories, program, targets)
    result = _topology(root, custody, program, sealed, targets)
    _validate_publication_order(result, dphases)
    return PublicationInspection(
        result.phases,
        result.head_installed,
        result.complete,
        dphases,
        pending_moves=result.pending_moves,
    )


def _validate_publication_order(result, directory_phases):
    if any(x != "ready" for x in result.phases) and any(
        x != "published" for x in directory_phases
    ):
        _fail("Files moved before all required directories were published")


def inspect_j2_destinations(
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
    if (
        type(program) is not programs.ValidatedPublicationProgram
        or program.sha256 != expected_program_sha256
        or type(plan) is not operation.ValidatedOperationPlan
        or plan.sha256 != expected_plan_sha256
    ):
        _fail("Exact approved plan and program required")
    operation._verified_plan(plan, plan_evidence)
    programs.load_publication_program(program.raw, plan, plan_evidence)
    try:
        with operation_context.held_store(
            Path(project_root), journal_ids=_ctx.journal_ids, handles=handles
        , context=_ctx) as custody:
            return _inspect_locked(
                Path(project_root), custody, plan, plan_evidence, program
            )
    except J2PublicationError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise J2PublicationError(f"J2 destination inspection refused: {exc}") from exc


def _root_entry_signature(value):
    """No-follow entry identity; leaf data metadata also detects substitutions."""
    from .portable_provenance_posix import _stat_fields

    fields = _stat_fields(value, leaf=not stat.S_ISDIR(value.st_mode))
    return (fields + (value.st_mtime_ns, value.st_ctime_ns)
            if stat.S_ISDIR(value.st_mode) else fields)


def _root_file_move_inventory(fd):
    """Capture one bounded stable root namespace without following its children."""
    from .working_tree_capture import (
        MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_NAME_BYTES,
    )

    before = os.fstat(fd)
    result, name_bytes = {}, 0
    with os.scandir(fd) as entries:
        for entry in entries:
            name_bytes += len(os.fsencode(entry.name))
            if (len(result) >= MAX_DIRECTORY_ENTRIES
                    or name_bytes > MAX_DIRECTORY_NAME_BYTES):
                _fail("Root file-move inventory exceeds bound")
            result[entry.name] = _root_entry_signature(
                os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            )
    after = os.fstat(fd)
    if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
        _fail("Root namespace changed while capturing file-move inventory")
    return result


def _advance_owned_root_file_change(custody, source, destination, entries, moved_fd, parents):
    """Rebase only an exact own regular-file rename, on either link-count model."""
    from .portable_provenance_posix import _witness, _same_namespace

    reader = custody.reader.reader
    label, parent, name, fd, before = reader.chain[-1]
    if fd != custody.reader.fds[""]:
        _fail("Root custody descriptor differs")
    source_parent, _, source_name = source.rpartition("/")
    destination_parent, _, destination_name = destination.rpartition("/")
    expected = dict(entries)
    if not source_parent:
        if source_name not in expected:
            _fail("Root file-move source was not observed")
        del expected[source_name]
    if not destination_parent:
        if destination_name in expected:
            _fail("Root file-move destination was not absent")
        expected[destination_name] = _root_entry_signature(os.fstat(moved_fd))
    for path, (parent_fd, parent_entries, parent_before) in parents.items():
        expected_parent = dict(parent_entries)
        if source_parent == path:
            del expected_parent[source_name]
        if destination_parent == path:
            expected_parent[destination_name] = _root_entry_signature(os.fstat(moved_fd))
        if _root_file_move_inventory(parent_fd) != expected_parent:
            _fail("Root child namespace changed beyond the exact own file move")
        after_parent = _root_entry_signature(os.fstat(parent_fd))
        fields = list(expected[path])
        delta = int(destination_parent == path) - int(source_parent == path)
        if after_parent[3] - fields[3] not in {0, delta}:
            _fail("Root child link count changed beyond the exact own file move")
        fields[3] = after_parent[3]
        # Only this proved parent namespace change may advance directory times.
        fields[-2:] = after_parent[-2:]
        if (after_parent != tuple(fields)
                or _witness(parent_fd, leaf=False, label=path).metadata != parent_before.metadata):
            _fail("Root child metadata changed beyond the exact own file move")
        expected[path] = after_parent
    if _root_file_move_inventory(fd) != expected:
        _fail("Root namespace changed beyond the exact own file move")
    after = _witness(fd, leaf=False, label=label)
    delta = int(not destination_parent) - int(not source_parent)
    fields = list(before.stat_fields)
    # Linux regular-file renames preserve directory nlink; Darwin may count
    # every immediate directory entry. The exact inventory is mandatory for both.
    if after.stat_fields[3] - fields[3] not in {0, delta}:
        _fail("Root link count changed beyond the exact own file move")
    fields[3] = after.stat_fields[3]
    if after.stat_fields != tuple(fields) or after.metadata != before.metadata:
        _fail("Root metadata changed beyond the exact own file link count")
    _same_namespace(parent, name, after, leaf=False, label=label)
    from .v3_j1_migration_predecessor import mirror_owned_root
    mirror_owned_root(custody, before, after)
    reader.chain[-1] = (label, parent, name, fd, after)


def _advance_owned_root_directory_change(custody, source_parent, destination_parent):
    """Rebase only the exact own top-level directory link-count change.

    The immutable reader's root witness otherwise detects our own mkdir/rename
    as drift. No external ancestry or security field is permitted to change.
    """
    delta = int(destination_parent == "") - int(source_parent == "")
    if not delta:
        return
    from .portable_provenance_posix import _witness, _same_namespace

    reader = custody.reader.reader
    label, parent, name, fd, before = reader.chain[-1]
    if fd != custody.reader.fds[""]:
        _fail("Root custody descriptor differs")
    after = _witness(fd, leaf=False, label=label)
    fields = list(before.stat_fields)
    fields[3] += delta
    if after.stat_fields != tuple(fields) or after.metadata != before.metadata:
        _fail("Root changed beyond the exact own directory link count")
    _same_namespace(parent, name, after, leaf=False, label=label)
    from .v3_j1_migration_predecessor import mirror_owned_root
    mirror_owned_root(custody, before, after)
    reader.chain[-1] = (label, parent, name, fd, after)


def _publication_children(native, relative, *, final=False):
    """Bound publication inventories independently of J1's 16-record ceiling."""
    if native.windows:
        key = native.reader.directory(relative)
        names = frozenset(native.reader._names(key).values())
    else:
        with ExitStack() as stack:
            fd = native.reader._walk(relative, stack)
            if fd is None:
                _fail("Required publication directory absent")
            names = native.reader._scan(fd, relative, final=final)
    if len(names) > lb.MAX_ANCESTORS + programs.MAX_SLOTS + 1000:
        _fail("Publication inventory exceeds approved bounded work")
    if final and native.inventories.get(relative) != names:
        _fail("Publication directory inventory changed during inspection")
    native.inventories.setdefault(relative, names)
    return names


def _native_directory(native, path):
    return (
        native.reader.directory_witness(path)
        if native.windows
        else native.reader.directory(path)
    )


def _windows_expected(sealed, targets, program):
    destinations = {slot["destination"] for slot in program.body["publications"]}
    return sealed["stages"] + [
        x
        for x in targets["leaves"]
        if x["metadata"]["presence"] == "present" and x["path"] in destinations
    ]


def _expected_directories(custody, sealed, targets, directories):
    _ctx = operation_context.from_custody(custody)
    result = {x["path"]: x["witness"] for x in targets["directories"]}
    if custody.windows:
        prefix = custody.reader.project
        result.update(
            {
                "/".join(key[len(prefix) :]): value[1]
                for key, value in custody.reader.baselines.items()
                if key[: len(prefix)] == prefix
            }
        )
    else:
        result.update(custody.reader.witnesses)
    result.update(sealed["storage_witnesses"])
    result[_ctx.publication.DIRECTORY_STAGES] = directories["stage_root_witness"]
    result.update({x["path"]: x["witness"] for x in directories["directories"]})
    return result


def _windows_match(custody, observed, origin):
    if _absent(observed):
        return None
    identities, security = custody._j2_windows_authority
    expected = identities[origin]
    # Refuse unrelated objects without considering their security for repair.
    if observed["metadata"]["file_id_hex"] != expected.file_id.hex() or observed[
        "content"
    ] != {"sha256": expected.content_sha256, "size_decimal": str(expected.size)}:
        return None
    from .windows_v3_restoring_backend import WindowsV3RestoringBackend

    path = observed["path"]
    with WindowsV3RestoringBackend(
        custody.reader.handles,
        {path: ntpath.join(custody.reader.root, path.replace("/", "\\"))},
        security_witnesses=security,
    ) as backend:
        if backend.observe(path) == expected:
            return "exact"
        return "pending" if backend.pending_matches(path, expected) else None


def _windows_identity(custody, expected):
    identities = custody._j2_windows_authority[0]
    matches = [
        value
        for value in identities.values()
        if value.file_id.hex() == expected["metadata"]["file_id_hex"]
    ]
    if len(matches) != 1 or matches[0].content_sha256 != _sha(expected["raw"]):
        _fail("Move object lacks its exact committed Windows identity")
    return matches[0]


@contextmanager
def _windows_move_backend(custody, source, destination, expected_directories):
    from .windows_v3_directory_moves import move_parents
    from .windows_v3_restoring_backend import WindowsV3RestoringBackend

    with move_parents(custody, (source, destination), expected_directories):
        paths = {
            path: ntpath.join(custody.reader.root, path.replace("/", "\\"))
            for path in (source, destination)
        }
        with WindowsV3RestoringBackend(
            custody.reader.handles,
            paths,
            security_witnesses=custody._j2_windows_authority[1],
        ) as backend:
            yield backend


def _checkpoint_metadata_matches(actual, expected, source, pending_sources):
    """V3 checkpoint caller has independently proved full pending RenameIdentity.

    Only the two fixed retained predecessor sources may have their normal flag
    set to archive by a completed rename. Identity, all security fields and
    bytes remain exact; this does not authorize repair or affect V1/V2 rules.
    """
    if actual == expected:
        return True
    return (
        source in pending_sources
        and expected.get("attributes_hex") == "00000080"
        and actual.get("attributes_hex") == "00000020"
        and {**actual, "attributes_hex": "00000080"} == expected
    )
