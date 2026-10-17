"""Read-only completed-prefix replay, independent of later working-file edits.

Returned facts are detached observations. Mutation consumers must revalidate
these exact records, directories and replay bindings under their own held lock.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from copy import deepcopy
import hashlib
from types import SimpleNamespace
from . import local_binding as lb, local_store as ls, portable_provenance as pp
from . import v3_operation_context as contexts
from . import v3_j1_rebind_predecessor as j1, v3_operation_projection as projection
from .working_tree_capture import build_capture
from .canonical import canonical_bytes


@dataclass(frozen=True)
class CompletedPrefix:
    binding: lb.ValidatedLocalBinding
    state: ls.ValidatedLocalStore
    terminals: tuple
    records: dict
    directories: dict
    replay_bindings: tuple
    retained_leaves: dict
    retained_directories: dict = field(default_factory=dict)


def recheck_payload_directories(native, directories):
    """Exact typed payload directories keep existing real native-role checks."""
    from .v3_j2_publication import _native_directory, _publication_children
    for path,(witness,names) in directories.items():
        if _native_directory(native,path)!=witness or _publication_children(native,path)!=names:
            raise ValueError('Immutable historical payload directory changed')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _exact(native, path, raw, witness):
    if native.read(path) != raw or native.observations[path]["metadata"] != witness:
        raise ValueError(
            "Historical private record bytes/native identity differ: " + path
        )


def _consume_replay_budget(total, additional):
    if (
        type(total) is not int
        or type(additional) is not int
        or total < 0
        or additional < 0
        or additional > pp.MAX_CUMULATIVE_READ_BYTES - total
    ):
        raise ValueError("Complete historical replay cumulative byte budget exceeded")
    return total + additional


def historical_children(native, relative, *, context, expected=None):
    """Bound only exact prior-operation publication roles above 16 entries.

    Context is caller-validated operation scope. Ordinary journals/directories
    retain the native reader's existing ceiling. Expected inventories are
    detached proof facts and must be rechecked under the consumer's custody.
    """
    if type(context) is not contexts.OperationContext:
        raise ValueError("Historical inventory requires explicit operation context")
    gate = getattr(getattr(native, 'operation_custody', None), 'receiving_history_gate', None)
    if gate is not None:
        cutoff = int(gate['boundaries'][-1]['journal_id'][1:])
        for journal in context.prior_journal_ids[1:cutoff]:
            prior = contexts.for_journal(journal)
            if relative == prior.replay.BLOBS:
                from . import v3_durable_replay as replay
                current = replay._reader(native, prior)
                names = current.children(relative)
                if expected is not None and names != expected:
                    raise ValueError('Imported replay blob inventory changed')
                native.inventories.setdefault(relative, names)
                return names
    publication_roles = set()
    for journal in context.prior_journal_ids[1:]:
        prior = contexts.for_journal(journal)
        publication_roles.update((prior.staging.STAGES, prior.staging.RETAINED,
                                  prior.publication.DIRECTORY_STAGES))
    if relative in publication_roles:
        from .v3_j2_publication import _publication_children
        native.directory(relative)  # Preserve the private native-directory policy.
        names = _publication_children(native, relative)
    else:
        names = native.children(relative)
    if expected is not None and names != expected:
        raise ValueError("Immutable historical directory inventory changed")
    return names


def _result_sources(context, index, binding_source, state_source):
    if index == len(context.prior_journal_ids):
        return binding_source, state_source
    successor = contexts.for_journal(f"J{index + 1:08d}")
    return successor.checkpoint.OLD_BINDING, successor.registration.BACKUP


def _publication(native, ctx, plan, evidence, program, intent, registered, outcome):
    from . import v3_publication_stage as stage, v3_j2_publication as pub

    p = ctx.staging
    d = ctx.publication
    expected = {
        "program.json",
        "targets.json",
        "stages",
        "retained",
        "commitment.json",
        "directory-stages",
        "directory-commitment.json",
    }
    if native.windows:
        expected.add("windows-commitment.json")
    if (
        native.children(p.PUBLICATION) != expected
        or native.read(p.PROGRAM) != program.raw
    ):
        raise ValueError("Historical publication inventory/program differs")
    targets_raw = native.read(p.TARGETS)
    targets = pp._load_json(targets_raw, "historical targets")
    sealed_raw = native.read(p.COMMITMENT)
    sealed = pp._load_json(sealed_raw, "historical stages")
    if (
        set(sealed)
        != {
            "schema",
            "program_sha256",
            "intent_sha256",
            "registered_state_sha256",
            "target_observations_sha256",
            "storage_witnesses",
            "record_witnesses",
            "stages",
        }
        or canonical_bytes(sealed) != sealed_raw
        or sealed["schema"] != stage.SCHEMA
        or sealed["program_sha256"] != program.sha256
        or sealed["intent_sha256"] != intent.sha256
        or sealed["registered_state_sha256"] != registered.sha256
        or sealed["target_observations_sha256"] != _sha(targets_raw)
        or sealed["record_witnesses"]
        != {path: native.observations[path] for path in (p.PROGRAM, p.TARGETS)}
        or sealed["storage_witnesses"]
        != {
            path: native.directory(path)
            for path in (p.PUBLICATION, p.STAGES, p.RETAINED)
        }
        or type(targets) is not dict
        or set(targets) != {"leaves", "directories"}
        or type(sealed["stages"]) is not list
        or len(sealed["stages"]) != len(program.body["publications"])
    ):
        raise ValueError("Historical publication commitment differs")
    before = {x["path"]: x for x in targets["leaves"]}
    slots = program.body["publications"]
    if set(before) != {x["destination"] for x in slots} | {
        x["path"] for x in program.body["reused_portable_evidence"]
    }:
        raise ValueError("Historical target coverage differs")
    leaves = {}
    stages = set()
    retained = set()
    for index, (slot, after) in enumerate(zip(slots, sealed["stages"]), 1):
        old = before[slot["destination"]]
        if (
            after["path"] != slot["stage"]
            or after["content"]
            != {k: slot["after"][k] for k in ("sha256", "size_decimal")}
            or old["content"]
            != (
                None
                if slot["before"] is None
                else {k: slot["before"][k] for k in ("sha256", "size_decimal")}
            )
        ):
            raise ValueError(
                "Historical publication slot differs from approved program"
            )
        if outcome == "committed":
            if slot["before"] is not None:
                expected = pub._at(old, slot["retained"])
                if native.reader.leaf(slot["retained"]) != expected:
                    raise ValueError(
                        "Historical retained original was changed or substituted"
                    )
                leaves[slot["retained"]] = expected
                retained.add(f"{index:08d}")
        else:
            expected = pub._at(after, slot["stage"])
            if native.reader.leaf(slot["stage"]) != expected:
                raise ValueError("Historical rolled-back stage changed or substituted")
            leaves[slot["stage"]] = expected
            stages.add(f"{index:08d}")
    if (
        pub._publication_children(native, p.STAGES) != stages
        or pub._publication_children(native, p.RETAINED) != retained
    ):
        raise ValueError("Historical publication stage/retained inventory differs")
    # This validates the private commitment and recorded directory creation
    # witnesses, rather than replaying historical working destinations.
    directories = pub._directory_commitment(native, program, targets, intent.sha256)
    dirnames = set()
    for index, row in enumerate(directories["directories"], 1):
        if outcome == "rolled_back":
            name = f"{index:08d}"
            dirnames.add(name)
            if pub._native_directory(native, row["stage"]) != row["witness"]:
                raise ValueError("Historical rolled-back directory stage differs")
    if pub._publication_children(native, d.DIRECTORY_STAGES) != dirnames:
        raise ValueError("Historical directory stage inventory differs")
    if native.windows:
        from .windows_v3_publication_witness import load_file_witnesses

        raw = native.read(d.WINDOWS_COMMITMENT)
        if (
            _sha(raw) != directories["windows_commitment_sha256"]
            or native.observations[d.WINDOWS_COMMITMENT]
            != directories["windows_commitment_witness"]
        ):
            raise ValueError("Historical Windows publication commitment changed")
        load_file_witnesses(raw, pub._windows_expected(sealed, targets, program))
    return leaves, directories


_NO_OPERATION_INTENT = object()


class _CaptureReplayDecode:
    """Own exact-input pure replay results for one detached capture only.

    No result/proof is accepted from callers. Each journal is decoded by the
    original validator on first use; changed inputs are refused on reuse.
    Native snapshot, publication, checkpoint, receiving and lock inspection
    remain outside this object and run on both fresh readers.
    """

    def __init__(self, custody):
        from weakref import ref

        self._owner = ref(custody)
        self._decoded = {}
        self._operations = {}

    def _check_owner_lock(self, native, owner):
        # Callback-bearing reads/backends may replace custody after entry.
        # Recheck on both sides of the live lock check as well.
        if self._owner() is not owner or owner is not native.operation_custody:
            raise ValueError("Completed replay reuse belongs to another capture custody")
        owner.check_lock()
        if self._owner() is not owner or owner is not native.operation_custody:
            raise ValueError("Completed replay reuse belongs to another capture custody")

    def decode(self, native, context, index, blobs, plan, binding, state, *, intent_raw=_NO_OPERATION_INTENT):
        from . import v3_durable_replay as replay, v3_operation_records as records

        owner = self._owner()
        if owner is None or owner is not native.operation_custody:
            raise ValueError("Completed replay reuse belongs to another capture custody")
        if type(context) is not contexts.OperationContext:
            raise ValueError("Completed replay requires an exact operation context")
        if (any(type(raw) is not bytes for raw in (index, plan, binding, state))
                or type(blobs) is not dict
                or any(type(key) is not str or type(raw) is not bytes
                       for key, raw in blobs.items())
                or (intent_raw is not _NO_OPERATION_INTENT and type(intent_raw) is not bytes)):
            raise ValueError("Completed replay requires exact detached bytes")
        inputs = (index, blobs, plan, binding, state, intent_raw)
        # All six inputs are bound BEFORE either decoder or derivation runs.
        validated_inputs = (index, dict(blobs), plan, binding, state, intent_raw)
        def unchanged():
            if (type(blobs) is not dict
                    or any(type(key) is not str or type(raw) is not bytes
                           for key, raw in blobs.items())
                    or inputs != validated_inputs):
                raise ValueError("Completed replay inputs changed during validation")
        if intent_raw is not _NO_OPERATION_INTENT:
            self._check_owner_lock(native, owner)
            unchanged()
        prior = self._decoded.get(context)
        if prior is not None:
            if inputs != prior[0]:
                raise ValueError("Completed replay inputs changed during capture")
            canonical_bytes(None)  # Dynamic distribution/version/module checks.
            unchanged()
            detached = deepcopy(prior[1])
            if intent_raw is not _NO_OPERATION_INTENT:
                self._check_owner_lock(native, owner)
                unchanged()
            return detached
        result = replay.decode_bundle(*inputs[:5])
        unchanged()
        if contexts.for_plan(result[0]) != context:
            raise ValueError("Historical approved journal/prefix differs")
        products = None
        if intent_raw is not _NO_OPERATION_INTENT:
            evidence_inputs = records._exact_operation_input(result[:2])
            products = records._load_intent_and_registration(intent_raw, result[0], result[1])
            unchanged()
            if records._exact_operation_input(result[:2]) != evidence_inputs:
                raise ValueError("Completed operation inputs changed during validation")
        # A failure in either derivation leaves BOTH caches empty for this key.
        decoded = (validated_inputs, deepcopy(result))
        operation = deepcopy(products)
        if intent_raw is not _NO_OPERATION_INTENT:
            self._check_owner_lock(native, owner)
            unchanged()
            if records._exact_operation_input(result[:2]) != evidence_inputs:
                raise ValueError("Completed operation inputs changed during validation")
        self._decoded[context] = decoded
        if products is not None:
            self._operations[context] = operation
        return result

    def operation(self, native, context, plan, evidence):
        from . import v3_operation_records as records

        owner = self._owner()
        if owner is None or owner is not native.operation_custody:
            raise ValueError("Completed replay reuse belongs to another capture custody")
        self._check_owner_lock(native, owner)
        if type(context) is not contexts.OperationContext:
            raise ValueError("Completed operation requires an exact operation context")
        prior = self._decoded.get(context)
        if prior is None or context not in self._operations:
            raise ValueError("Completed operation requires this capture's decoded replay")
        inputs = records._exact_operation_input((plan, evidence))
        if inputs != records._exact_operation_input(prior[1][:2]):
            raise ValueError("Completed operation differs from this capture's replay inputs")
        # Preserve the checkpoint's read on BOTH inspectors in addition to the
        # early read binding all six immutable inputs before pure derivation.
        raw = native.read(context.registration.INTENT)
        if type(raw) is not bytes or raw != prior[0][5]:
            raise ValueError("Completed operation inputs changed during capture")
        canonical_bytes(None)
        if records._exact_operation_input((plan, evidence)) != inputs:
            raise ValueError("Completed operation inputs changed during validation")
        detached = deepcopy(self._operations[context])
        self._check_owner_lock(native, owner)
        if records._exact_operation_input((plan, evidence)) != inputs:
            raise ValueError("Completed operation inputs changed during validation")
        return detached


def _decode_completed_replay(native, context, index, blobs, plan, binding, state):
    from . import v3_durable_replay as replay

    owned = getattr(native, '_capture_replay_decode', None)
    if type(owned) is _CaptureReplayDecode:
        return owned.decode(native, context, index, blobs, plan, binding, state,
                            intent_raw=native.read(context.registration.INTENT))
    return replay.decode_bundle(index, blobs, plan, binding, state)


def _completed_operation(native, context, plan, evidence):
    from . import v3_j2_checkpoint as checkpoint

    owned = getattr(native, '_capture_replay_decode', None)
    if type(owned) is _CaptureReplayDecode:
        return owned.operation(native, context, plan, evidence)
    return checkpoint._operation(native, plan, evidence)


def _inspect_native(
    native,
    portable,
    context,
    *,
    binding_source,
    state_source,
    pending_binding_identity=None,
    portable_files=None,
):
    from . import (
        v3_j2_registration as reg,
        v3_durable_replay as replay,
        v3_j2_checkpoint as checkpoint,
    )

    if pending_binding_identity is not None:
        from .windows_rename_identity import RenameIdentity

        if (
            not native.windows
            or (context == contexts.DEFAULT and native.operation_custody.migration_candidate is None)
            or binding_source != context.checkpoint.OLD_BINDING
            or type(pending_binding_identity) is not RenameIdentity
        ):
            raise ValueError("Invalid latest historical pending binding authority")
        pending_binding_identity.validate()
    # Context selects a fixed prefix. Enumeration and every terminal prove it.
    names = native.children(reg.JOURNALS)
    if names not in (set(context.prior_journal_ids), set(context.journal_ids)):
        raise ValueError("Missing, extra or foreign operation journal prefix")
    operations = []
    replays = []
    leaves = {}
    payload_directories = {}
    history_bytes = 0
    import_gate = getattr(native.operation_custody, 'receiving_history_gate', None)
    import_frontier = int(import_gate['boundaries'][-1]['journal_id'][1:]) if import_gate is not None else 1
    for journal in context.prior_journal_ids[1:]:
        if int(journal[1:]) <= import_frontier:
            continue
        ctx = contexts.for_journal(journal)
        p = ctx.registration
        c = ctx.checkpoint
        expected = (reg.FILES_PREPARED - {"state.registered.pending.json"}) | {
            "state.before.json",
            "publication",
            "replay",
            "checkpoint",
            "terminal.json",
        }
        if native.children(p.J2) != expected or native.children(p.PROGRESS) != set():
            raise ValueError("Historical operation is incomplete or has unknown names")
        commit_raw = native.read(p.COMMITMENT)
        commit = pp._load_json(commit_raw, "historical registration")
        if (
            commit.get("schema") != ctx.registration.REPLAY_SCHEMA
            or "replay_binding" not in commit
        ):
            raise ValueError("Historical operation lacks supported durable replay")
        index, blobs, _ = replay.snapshot(
            native, expected=commit["replay_binding"], context=ctx
        )
        history_bytes = _consume_replay_budget(
            history_bytes, len(index) + sum(len(raw) for raw in blobs.values())
        )
        plan, evidence, program = _decode_completed_replay(
            native, ctx, index,
            blobs,
            native.read(p.PLAN),
            native.read(p.PRIOR_BINDING),
            native.read(p.PRIOR_STATE),
        )
        if contexts.for_plan(plan) != ctx:
            raise ValueError("Historical approved journal/prefix differs")
        operations.append((ctx, plan, evidence, program, commit_raw, commit))
        replays.append((ctx, deepcopy(commit["replay_binding"])))
    first_portable = (
        pp.load_portable_snapshot(
            projection._Reader(operations[0][2]["portable_files"])
        )
        if operations
        else portable
    )
    bsource, ssource = _result_sources(context, import_frontier, binding_source, state_source)
    if import_gate is not None:
        from .foreign_store_history import native_imported_seed
        imported = native_imported_seed(native, first_portable, context,
            import_gate['boundaries'][-1]['journal_id'], binding_source=bsource, state_source=ssource,
            portable_files=operations[0][2]['portable_files'] if operations else portable_files,
            pending_binding_identity=pending_binding_identity if import_frontier == len(context.prior_journal_ids) else None)
        binding, state = imported.binding, imported.state
        terminals = list(imported.terminals)
        leaves.update(imported.retained_leaves)
        payload_directories.update(imported.retained_directories)
    elif getattr(native.operation_custody, 'migration_candidate', None) is not None:
        from . import v3_j1_migration_predecessor as migration
        intent, migration_history, state, terminal, binding = migration.inspect(
            native, first_portable, context, binding_source=bsource,
            state_source=ssource, pending_binding_identity=pending_binding_identity)
        leaves.update(native.migration_content_leaves)
        terminals = [('J00000001', terminal, migration_history[-1].sha256, binding)]
    else:
        revisions = native.children(j1.PROGRESS)
        if (
            native.children(j1.JOURNAL)
            != {"plan.json", "intent.json", "progress", "terminal.json"}
            or not 1 <= len(revisions) <= j1.MAX_PROGRESS
            or revisions != {f"{i:08d}.json" for i in range(len(revisions))}
        ):
            raise ValueError("Historical J1 inventory differs")
        paths = (
            j1.PLAN,
            j1.INTENT,
            *(j1.PROGRESS + "/" + x for x in sorted(revisions)),
            j1.TERMINAL,
        )
        raw = {path: native.read(path) for path in paths}
        raw[j1.BINDING] = native.read(bsource)
        raw[j1.STATE] = native.read(ssource)
        _plan, j1intent, j1history, state, binding = j1._semantic_j1(raw, first_portable)
        if (
            native.observations[bsource]["metadata"]
            != j1history.records[-1].body["publication_witness"]
            or native.directory(j1.JOURNAL) != j1intent.body["storage_witnesses"]["journal"]
            or native.lock_witness != j1intent.body["storage_witnesses"]["lock"]
        ):
            raise ValueError("Historical J1 native identity differs")
        terminal = ls.load_local_terminal(raw[j1.TERMINAL])
        last = j1.PROGRESS + "/" + sorted(revisions)[-1]
        terminals = [("J00000001", terminal, _sha(raw[last]), binding)]
    current_portable = first_portable
    for number, (ctx, plan, evidence, program, commit_raw, commit) in enumerate(
        operations, import_frontier + 1
    ):
        p = ctx.registration
        c = ctx.checkpoint
        if (
            evidence["predecessor_binding"] != binding
            or evidence["predecessor_store"] != state
            or pp.load_portable_snapshot(projection._Reader(evidence["portable_files"]))
            != current_portable
        ):
            raise ValueError("Historical operation predecessor linkage differs")
        intent, registered = _completed_operation(native, ctx, plan, evidence)
        expected = reg._commitment(
            plan,
            intent,
            state,
            registered,
            commit["stage_witness"],
            commit["progress_witness"],
            commit["old_rename_identity"],
            commit["stage_rename_identity"],
            commit["replay_binding"],
        )
        if (
            commit_raw != expected
            or native.directory(p.J2) != intent.body["storage_witnesses"]["journal"]
            or native.lock_witness != intent.body["storage_witnesses"]["lock"]
            or native.directory(p.PROGRESS) != commit["progress_witness"]
        ):
            raise ValueError(
                "Historical registration native/semantic commitment differs"
            )
        _exact(
            native,
            p.BACKUP,
            state.raw,
            evidence["predecessor_record_witnesses"]["state"],
        )
        _exact(
            native,
            c.OLD_BINDING,
            binding.raw,
            evidence["predecessor_record_witnesses"]["binding"],
        )
        _exact(native, c.OLD_STATE, registered.raw, commit["stage_witness"])
        progress_raw = native.read(c.PROGRESS)
        progress = pp._load_json(progress_raw, "historical final progress")
        if type(progress) is not dict or set(progress) != {
            "schema",
            "journal_id",
            "plan_sha256",
            "intent_sha256",
            "program_sha256",
            "outcome",
            "portable_head_sha256",
            "publication_phases",
            "directory_phases",
            "capture",
        }:
            raise ValueError("Malformed historical final progress")
        outcome = progress["outcome"]
        if outcome not in ("committed", "rolled_back"):
            raise ValueError("Unknown historical outcome")
        files = dict(evidence["portable_files"])
        if outcome == "committed":
            files.update(
                {
                    path: raw
                    for path, raw in program._payloads
                    if path.startswith(pp.ROOT + "/")
                }
            )
        current_portable = pp.load_portable_snapshot(projection._Reader(files))
        capture = build_capture(
            progress["capture"]["native"], progress["capture"]["leaves"]
        )
        retained, directories = _publication(
            native, ctx, plan, evidence, program, intent, registered, outcome
        )
        leaves.update(retained)
        result = SimpleNamespace(
            phases=("installed" if outcome == "committed" else "ready",)
            * len(program.body["publications"]),
            directory_phases=("published" if outcome == "committed" else "staged",)
            * len(directories["directories"]),
        )
        if (
            checkpoint._progress(
                plan, intent, program, result, outcome, current_portable, capture
            )
            != progress_raw
        ):
            raise ValueError(
                "Historical final progress differs from deterministic replay"
            )
        binding, state, terminal = checkpoint.checkpoint_records(
            plan, intent, registered, current_portable, capture, progress_raw
        )
        cp_raw = native.read(c.COMMITMENT)
        cp = pp._load_json(cp_raw, "historical checkpoint")
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
        } | ({"windows_files"} if native.windows else set())
        if (
            type(cp) is not dict
            or set(cp) != required
            or canonical_bytes(cp) != cp_raw
            or cp["schema"] != ctx.checkpoint.SCHEMA
            or cp["plan_sha256"] != plan.sha256
            or cp["program_sha256"] != program.sha256
            or cp["intent_sha256"] != intent.sha256
            or cp["outcome"] != outcome
            or cp["directory_witness"] != native.directory(c.CHECKPOINT)
            or cp["old_binding_witness"]
            != evidence["predecessor_record_witnesses"]["binding"]
            or cp["old_state_witness"] != commit["stage_witness"]
            or set(cp["records"])
            != {c.PROGRESS, c.BINDING_STAGE, c.STATE_STAGE, c.TERMINAL_STAGE}
        ):
            raise ValueError("Historical checkpoint commitment differs")
        bsource, ssource = _result_sources(
            context, number, binding_source, state_source
        )
        for original, source, value in (
            (c.PROGRESS, c.PROGRESS, progress_raw),
            (c.BINDING_STAGE, bsource, binding.raw),
            (c.STATE_STAGE, ssource, state.raw),
            (c.TERMINAL_STAGE, c.TERMINAL, terminal.raw),
        ):
            row = cp["records"][original]
            if set(row) != {"sha256", "witness"} or row["sha256"] != _sha(value):
                raise ValueError("Historical checkpoint record digest differs")
            if (
                pending_binding_identity is not None
                and number == len(context.prior_journal_ids)
                and original == c.BINDING_STAGE
                and source == binding_source
            ):
                from .v3_j2_publication import _checkpoint_metadata_matches

                if native.read(source) != value or not _checkpoint_metadata_matches(
                    native.observations[source]["metadata"],
                    row["witness"],
                    source,
                    (source,),
                ):
                    raise ValueError(
                        "Latest pending binding bytes/projected witness differ"
                    )
            else:
                _exact(native, source, value, row["witness"])
        if native.children(c.CHECKPOINT) != {
            "progress.json",
            "commitment.json",
            "binding.before.json",
            "state.registered.before.json",
        }:
            raise ValueError("Historical checkpoint is pending or has unknown names")
        if native.windows:
            import ntpath
            from .windows_restoring_backend import WindowsRestoringBackend

            identities = checkpoint._windows_identities(
                cp, evidence, (binding, state, terminal)
            )
            sources = {
                p.BINDING: c.OLD_BINDING,
                p.STATE: c.OLD_STATE,
                c.BINDING_STAGE: bsource,
                c.STATE_STAGE: ssource,
                c.TERMINAL_STAGE: c.TERMINAL,
            }
            with WindowsRestoringBackend(
                native.reader.handles,
                {
                    key: ntpath.join(
                        capture.body["native"]["root_path"], *value.split("/")
                    )
                    for key, value in sources.items()
                },
            ) as backend:
                for key in sources:
                    if (
                        pending_binding_identity is not None
                        and number == len(context.prior_journal_ids)
                        and key == c.BINDING_STAGE
                        and sources[key] == binding_source
                    ):
                        # Both immutable producer and current rename frontier must
                        # authorize the same full native identity before repair.
                        if identities[key] != pending_binding_identity:
                            raise ValueError(
                                "Latest pending binding identity differs from historical producer"
                            )
                        if backend.observe(key) != identities[
                            key
                        ] and not backend.pending_matches(key, identities[key]):
                            raise ValueError(
                                "Latest historical pending binding identity differs"
                            )
                    elif backend.observe(key) != identities[key]:
                        raise ValueError(
                            "Historical Windows checkpoint identity differs"
                        )
        terminals.append((ctx.journal_id, terminal, _sha(progress_raw), binding))
    if current_portable != portable:
        raise ValueError("Latest portable history differs from completed prefix")
    ls.reconcile_registration(state, binding, context.prior_journal_ids)
    for journal, terminal, progress_sha, historical_binding in terminals:
        ls.reconcile_terminal_reference(
            state,
            journal,
            terminal,
            progress_sha256=progress_sha,
            binding_after=historical_binding,
        )
    prefixes = tuple(
        ris_root() + "/journals/" + journal + "/"
        for journal in context.prior_journal_ids
    )
    historical_roots = {prefix[:-1] for prefix in prefixes}

    def historical(path):
        return path in historical_roots or path.startswith(prefixes)

    files = {
        path: (native.raw[path], deepcopy(obs))
        for path, obs in native.observations.items()
        if path in native.raw
        and path not in leaves
        and (historical(path) or path in (binding_source, state_source))
    }
    dirs = {
        path: (deepcopy(native.directory(path)), frozenset(historical_children(
            native, path, context=context, expected=native.inventories[path])))
        for path in tuple(native.inventories)
        if historical(path) and path not in payload_directories and not any(path == ctx.replay.BLOBS for ctx, _ in replays)
    }
    proof = CompletedPrefix(
        binding, state, tuple(terminals), files, dirs, tuple(replays), leaves, payload_directories
    )
    native.completed_prefix = proof
    return proof


def ris_root():
    from .rebind_store_inspection import ROOT

    return ROOT


def inspect_completed_prefix_locked(
    root, custody, context, portable, *, binding_source, state_source
):
    from . import v3_j2_registration as reg

    with reg._fresh_native(root, custody, custody.windows) as native:
        return _inspect_native(
            native,
            portable,
            context,
            binding_source=binding_source,
            state_source=state_source,
        )


@dataclass(frozen=True)
class PredecessorCapture:
    context: contexts.OperationContext
    pair: object
    portable_files: dict
    current_bytes: dict
    binding: lb.ValidatedLocalBinding
    state: ls.ValidatedLocalStore
    record_witnesses: dict
    prefix: CompletedPrefix


def capture_completed_predecessor(root, extras=(), *, handles=None):
    """Detached complete historical proof plus independently fresh current C.

    A caller must pass these facts through build_operation_plan and the native
    registrar, which acquires its own lock and repeats all history/capture checks.
    """
    import os
    from pathlib import Path
    from . import (
        joint_capture as joint,
        rebind_store_inspection as ris,
        v3_j2_registration as reg,
    )
    from .v3_public_profile import _read_current

    root = Path(root)
    windows = handles is not None or os.name == "nt"

    def lane():
        return (
            joint._held_windows(str(root), extras, handles)
            if windows
            else joint._held_posix(root, extras)
        )

    with lane() as held:
        native = ris._NativeStore(held, windows)
        state = ls.load_local_store(native.read(reg.STATE))
        context = contexts.OperationContext(
            tuple(x["id"] for x in state.body["journals"]["entries"])
        )
    with contexts.held_store(
        root, journal_ids=context.prior_journal_ids, context=context, handles=handles
    ) as custody:
        capture_replay = _CaptureReplayDecode(custody)
        with lane() as held:
            native = reg._native(custody, windows)
            native._capture_replay_decode = capture_replay
            proof = _inspect_native(
                native,
                held.result.portable,
                context,
                binding_source=reg.BINDING,
                state_source=reg.STATE,
            )
            portable_files = {}

            class Tee:
                def read(self, path):
                    raw = held.portable_reader.read(path)
                    if raw is not None:
                        portable_files[path] = raw
                    return raw

            if pp.load_portable_snapshot(Tee()) != held.result.portable:
                raise ValueError("Portable evidence changed during predecessor capture")
            current = {
                leaf["path"]: _read_current(held.working_reader, leaf, windows)
                for leaf in held.result.working_tree.body["leaves"]
            }
            if (
                sum(len(raw) for raw in current.values() if raw is not None)
                > pp.MAX_CUMULATIVE_READ_BYTES
            ):
                raise ValueError("Complete current byte budget exceeded")
            witnesses = {
                key: native.observations[path]["metadata"]
                for key, path in [("binding", reg.BINDING), ("state", reg.STATE)]
            }
            result = PredecessorCapture(
                context,
                held.result,
                portable_files,
                current,
                proof.binding,
                proof.state,
                witnesses,
                proof,
            )
        with reg._fresh_native(root, custody, windows) as second:
            second._capture_replay_decode = capture_replay
            closing = _inspect_native(
                second,
                result.pair.portable,
                context,
                binding_source=reg.BINDING,
                state_source=reg.STATE,
            )
            if closing != proof:
                raise ValueError("Completed prefix changed during final revalidation")
        custody.check_lock()
        return result
