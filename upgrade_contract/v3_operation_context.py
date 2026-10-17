"""Explicit bounded operation paths; a context selects names, never authority."""

from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from . import local_binding as lb, local_store as ls, rebind_store_inspection as ris


@dataclass(frozen=True)
class OperationContext:
    prior_journal_ids: tuple[str, ...]

    def __post_init__(self):
        ids = self.prior_journal_ids
        if (
            type(ids) is not tuple
            or not ids
            or len(ids) >= lb.MAX_JOURNALS
            or ids != tuple(f"J{i:08d}" for i in range(1, len(ids) + 1))
        ):
            raise ValueError("Exact complete predecessor journal prefix required")

    @property
    def journal_id(self):
        return f"J{len(self.prior_journal_ids) + 1:08d}"

    @property
    def journal_ids(self):
        return (*self.prior_journal_ids, self.journal_id)

    @property
    def registration(self):
        root = ris.ROOT
        journals = root + "/journals"
        current = journals + "/" + self.journal_id
        return SimpleNamespace(
            ROOT=root,
            JOURNALS=journals,
            J2=current,
            STATE=root + "/state.json",
            BINDING=root + "/binding.json",
            PROGRESS=current + "/progress",
            STAGE=current + "/state.registered.pending.json",
            BACKUP=current + "/state.before.json",
            COMMITMENT=current + "/registration.json",
            PLAN=current + "/plan.json",
            INTENT=current + "/intent.json",
            PRIOR_BINDING=current + "/predecessor.binding.json",
            PRIOR_STATE=current + "/predecessor.state.json",
            REPLAY_SCHEMA="naos.upgrade.v3_j2_registration.v2"
            if self == DEFAULT
            else "naos.upgrade.v3_operation_registration.v1",
        )

    @property
    def staging(self):
        root = self.registration.J2 + "/publication"
        return SimpleNamespace(
            PUBLICATION=root,
            STAGES=root + "/stages",
            RETAINED=root + "/retained",
            PROGRAM=root + "/program.json",
            TARGETS=root + "/targets.json",
            COMMITMENT=root + "/commitment.json",
        )

    @property
    def publication(self):
        root = self.staging.PUBLICATION
        return SimpleNamespace(
            DIRECTORY_STAGES=root + "/directory-stages",
            DIRECTORY_COMMITMENT=root + "/directory-commitment.json",
            WINDOWS_COMMITMENT=root + "/windows-commitment.json",
            DIRECTORY_SCHEMA="naos.upgrade.v3_j2_directory_stages.v1"
            if self == DEFAULT
            else "naos.upgrade.v3_operation_directory_stages.v1",
        )

    @property
    def checkpoint(self):
        root = self.registration.J2 + "/checkpoint"
        return SimpleNamespace(
            CHECKPOINT=root,
            PROGRESS=root + "/progress.json",
            COMMITMENT=root + "/commitment.json",
            BINDING_STAGE=root + "/binding.pending.json",
            STATE_STAGE=root + "/state.pending.json",
            TERMINAL_STAGE=root + "/terminal.pending.json",
            OLD_BINDING=root + "/binding.before.json",
            OLD_STATE=root + "/state.registered.before.json",
            TERMINAL=self.registration.J2 + "/terminal.json",
            JOURNALS=self.journal_ids,
            SCHEMA="naos.upgrade.v3_j2_checkpoint.v1"
            if self == DEFAULT
            else "naos.upgrade.v3_operation_checkpoint.v1",
            PROGRESS_SCHEMA="naos.upgrade.v3_j2_final_progress.v1"
            if self == DEFAULT
            else "naos.upgrade.v3_operation_final_progress.v1",
        )

    @property
    def replay(self):
        root = self.registration.J2 + "/replay"
        return SimpleNamespace(
            J2=self.registration.J2,
            ROOT=root,
            BLOBS=root + "/blobs",
            INDEX=root + "/index.json",
            COMMITMENT=root + "/commitment.json",
        )


DEFAULT = OperationContext(("J00000001",))


def for_journal(journal_id):
    if (
        type(journal_id) is not str
        or len(journal_id) != 9
        or not journal_id.startswith("J")
        or any(ch < "0" or ch > "9" for ch in journal_id[1:])
    ):
        raise ValueError("Invalid operation journal ID")
    number = int(journal_id[1:])
    if not 2 <= number <= lb.MAX_JOURNALS:
        raise ValueError("Operation journal ID exceeds the supported bound")
    result = OperationContext(tuple(f"J{i:08d}" for i in range(1, number)))
    if result.journal_id != journal_id:
        raise ValueError("Noncanonical operation journal ID")
    return result


def for_plan(plan):
    result = for_journal(plan.body["next_journal_id"])
    if (
        tuple(x["id"] for x in plan.body["prior_journals"]["entries"])
        != result.prior_journal_ids
    ):
        raise ValueError("Plan prefix differs from explicit operation context")
    return result


def for_program(program):
    return for_journal(program.body["journal_id"])


def for_evidence(evidence):
    return OperationContext(evidence["journal_ids"])


def from_custody(custody):
    result = getattr(custody, "operation_context", DEFAULT)
    if type(result) is not OperationContext:
        raise ValueError("Invalid held operation context")
    return result


@contextmanager
def held_store(root, *, journal_ids, context, handles=None):
    from .v3_operation_custody import _held_operation_store

    if journal_ids not in (context.prior_journal_ids, context.journal_ids):
        raise ValueError("Held journal prefix differs from operation context")
    # Dispatch is read-only and grants no authority. The selected plan and all
    # historical objects are revalidated after legacy-then-local lock acquisition.
    from contextlib import ExitStack
    from . import v3_j1_migration_predecessor as migration
    from . import legacy_migration_custody as legacy
    from . import legacy_migration_inspection as mi
    import os
    from pathlib import Path
    with ExitStack() as stack:
        if handles is not None or os.name == 'nt':
            from .working_tree_capture_windows import _Capture
            from .windows_handles import WindowsHandles
            reader = _Capture(handles if handles is not None else WindowsHandles(), str(root), stack)
        else:
            from .working_tree_capture_posix import _Reader
            reader = stack.enter_context(_Reader(Path(root)))
        native = mi._MigrationStore(SimpleNamespace(working_reader=reader), handles is not None or os.name == 'nt')
        from . import foreign_store_version as received
        # Exact v2 state selects current receiving custody, never historical
        # root/lock authority. Complete history still validates after both locks.
        state_source = context.registration.STATE
        if 'state.json' not in native.children(context.registration.ROOT):
            state_source = context.registration.BACKUP
        selected_state = ls.load_local_store(native.read(state_source))
        received_gate = selected_state.body.get(received.GATE_KEY)
        if selected_state.body['schema'] == received.STORE_SCHEMA:
            received.validate_gate(received_gate, selected_state.body['journals'])
            first = native.read(ris.JOURNAL + '/plan.json')
            from .portable_provenance import _load_json
            first_body = _load_json(first, 'received migration-origin dispatch')
            source_format = first_body.get('source_format') if first_body.get('schema') in ('naos.upgrade.legacy_migration_plan.v1', 'naos.upgrade.legacy_migration_plan.v2') else None
        else:
            source_format = None
        if received_gate is None:
            candidate = migration.reconstruct(native)
        else:
            candidate = None
    if received_gate is not None:
        from .foreign_store_native import custody as held_received
        with held_received(root, journal_ids=journal_ids, source_format=source_format, handles=handles) as custody:
            custody.operation_context = context
            custody.migration_candidate = None
            custody.legacy_custody = None
            custody.receiving_history_gate = received_gate
            yield custody
        return
    with ExitStack() as stack:
        borrowed = (stack.enter_context(legacy._lock_legacy_for_plan(root,
            candidate, candidate.plan.sha256, handles)) if candidate is not None else None)
        custody = stack.enter_context(_held_operation_store(
            root, journal_ids=journal_ids, handles=handles))
        custody.operation_context = context
        custody.migration_candidate = candidate
        custody.legacy_custody = borrowed
        yield custody


def probe(root, *, handles=None):
    """Read-only selector; the operation consumer must validate complete history."""
    import os
    from pathlib import Path
    from contextlib import ExitStack

    windows = handles is not None or os.name == "nt"
    # A retained-old-head publication phase can legitimately have no live
    # manifest. Select only the private operation frontier here; exact replay,
    # retained/staged head topology and custody must still validate downstream.
    with ExitStack() as stack:
        if windows:
            from .working_tree_capture_windows import _Capture
            from .windows_handles import WindowsHandles
            reader = _Capture(handles if handles is not None else WindowsHandles(), str(root), stack)
        else:
            from .working_tree_capture_posix import _Reader
            reader = stack.enter_context(_Reader(Path(root)))
        native = ris._NativeStore(SimpleNamespace(working_reader=reader), windows)
        directories = {path: native.directory(path)
                       for path in (ris.ROOT, ris.ROOT + "/journals")}
        root_names = native.children(ris.ROOT)
        if (
            not {"scope.lock", "journals"}
            <= root_names
            <= {"scope.lock", "journals", "state.json", "binding.json"}
        ):
            raise ValueError("Unknown local root inventory during operation selection")
        names = native.children(ris.ROOT + "/journals")
        ids = tuple(f"J{i:08d}" for i in range(1, len(names) + 1))
        if not ids or names != set(ids):
            raise ValueError("Missing, extra or noncanonical operation journal prefix")
        context = for_journal(ids[-1])
        source = (
            ris.ROOT + "/state.json"
            if "state.json" in root_names
            else context.registration.BACKUP
        )
        parent = source.rpartition("/")[0]
        if parent not in directories:
            directories[parent] = native.directory(parent)
        state = ls.load_local_store(native.read(source))
        recorded = tuple(entry["id"] for entry in state.body["journals"]["entries"])
        if recorded == ids:
            if state.body["active_journal_id"] not in (None, ids[-1]):
                raise ValueError(
                    "Active state is outside the selected operation frontier"
                )
        elif recorded == ids[:-1] and state.body["active_journal_id"] is None:
            pass  # Prepared/retained bridge; exact replay and topology validate later.
        else:
            raise ValueError("State and native journal frontier differ")
        for path in tuple(native.inventories):
            native.children(path, final=True)
        if windows:
            reader.revalidate()
        else:
            reader._final_revalidate({"control_directories": [
                {"path": path, "witness": witness} for path, witness in directories.items()],
                "managed_ancestors": []}, list(native.observations.values()))
        return context
