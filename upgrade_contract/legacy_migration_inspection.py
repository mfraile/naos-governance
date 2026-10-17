"""Native inspection and custody for an already prepared migration journal.

An explicit approved candidate remains required. An on-disk self-declared plan
is not approval. Inspections bind the actual staging, retained original, fence,
portable publication and local binding/checkpoint states. Partial unrecorded
objects refuse. Pre-head rollback has a separate actual-state inspector.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from types import SimpleNamespace

from . import legacy_migration_custody as custody
from . import legacy_migration_journal as journal
from . import legacy_migration_progress as progress
from . import legacy_migration_plan_records as plans
from . import portable_provenance as pp
from . import rebind_publication as publication
from . import rebind_store_inspection as store
from .working_tree_capture import ancestor_paths, build_capture, managed_paths


class MigrationInspectionError(ValueError):
    """Unknown, incomplete, changed or foreign migration storage refuses."""


@dataclass(frozen=True)
class PreparedMigrationInspection:
    plan_sha256: str
    intent: journal.MigrationIntent
    phase: str = 'prepared'
    progress_history: tuple = ()
    mutation_authorized: bool = False
    source_state: str = 'original'
    rename_identity_raw: bytes | None = None
    fence_state: str = 'absent'
    head_state: str = 'absent'
    binding_state: str = 'absent'
    checkpoint_paths: tuple[str, ...] = ()
    checkpoint_complete: bool = False


class _MigrationStore(store._NativeStore):
    """Bound staged archive blobs separately from ordinary journal records."""
    def read(self, relative):
        from .legacy_migration_staging import STAGE
        self._leaf_limit = (pp.control_path_limit(pp.ROOT + relative[len(STAGE):])
                            if relative.startswith(STAGE + '/') else
                            pp.control_path_limit(relative) if relative.startswith(pp.ROOT + '/')
                            else pp.MAX_RECORD_BYTES)
        return super().read(relative)

    def _budget(self, size):
        if not 0 <= size <= self._leaf_limit or size > 512 * 1024 * 1024 - self.total_bytes:
            raise MigrationInspectionError('Migration journal/stage exceeds byte budget')

    def children(self, relative, *, final=False):
        self.directory(relative)
        if self.windows:
            key = self.reader.directory(relative)
            names = frozenset(self.reader._names(key).values())
        else:
            with ExitStack() as stack:
                fd = self.reader._walk(relative, stack)
                names = self.reader._scan(fd, relative, final=final)
        if len(names) > 20_000:
            raise MigrationInspectionError('Migration stage inventory exceeds count budget')
        if final and names != self.inventories[relative]:
            raise MigrationInspectionError('Migration directory inventory changed')
        self.inventories.setdefault(relative, names)
        return names


def _verify_stage(native, candidate, commitment, *, prefix=None):
    from .legacy_migration_staging import STAGE
    prefix = STAGE if prefix is None else prefix
    progress._candidate(commitment, candidate.plan.body,
                        candidate.plan.body['initial_capture']['native']['platform'])
    if native.directory(prefix) != commitment['stage_root']:
        raise MigrationInspectionError('Stage root native identity changed')
    files = candidate.projection_files
    children = {'': set()}
    for row in commitment['directories']:
        path = row['path']
        parent, _, name = path.rpartition('/')
        children.setdefault(parent, set()).add(name)
        children.setdefault(path, set())
        if native.directory(prefix + '/' + path) != row['witness']:
            raise MigrationInspectionError('Staged directory identity changed')
    for row in commitment['files']:
        relative = row['path'].removeprefix(pp.ROOT + '/')
        parent, _, name = relative.rpartition('/')
        children.setdefault(parent, set()).add(name)
        path = prefix + '/' + relative
        if (native.read(path) != files[row['path']]
                or native.observations[path]['metadata'] != row['witness']):
            raise MigrationInspectionError('Staged file native identity or bytes changed')
    for path, expected in children.items():
        if native.children(prefix + ('/' + path if path else '')) != expected:
            raise MigrationInspectionError('Unexpected or incomplete stage inventory')


def _windows_identity(reader, path):
    from .windows_restoring_backend import _capture
    parent, _, name = path.rpartition('/')
    key = reader.directory(parent)
    with reader.handles.open_child(reader.directories[key], name,
                                  kind='file', pin_for_read=True) as held:
        return _capture(held)


def _source_state(source, native, candidate, phase, history, names):
    """Classify actual paths without replacing immutable observations with history."""
    from .canonical import canonical_bytes
    planned = candidate.plan.body
    pointer = planned['fence']['path']
    original = next(r for r in planned['legacy_files'] if r['path'] == pointer)
    active = source.observations.get(pointer)
    retained_present = 'legacy-original.json' in names
    fence_phase = phase in {'fence_pending', 'fenced', 'head_pending', 'head_published', 'binding_pending', 'finalized'}
    pending = phase in {'retain_pending', 'original_retained'} or fence_phase
    if not pending and (retained_present or active != original):
        raise MigrationInspectionError('Original pointer changed before retention commitment')
    if fence_phase and not retained_present:
        raise MigrationInspectionError('Fenced migration lost retained original')
    if pending and not fence_phase and (active is not None) == retained_present:
        raise MigrationInspectionError('Original pointer must exist in exactly one location')
    if active is not None and not fence_phase:
        if active != original or phase == 'original_retained':
            raise MigrationInspectionError('Active original pointer state differs')
        path, state = pointer, 'original'
    else:
        if not fence_phase:
            _absent_leaf(source.reader, native, pointer)
        path, state = progress.RETAINED, 'retained'
        native.read(path)
        retained = native.observations[path]
        if retained['content'] != original['content']:
            raise MigrationInspectionError('Retained original bytes changed')
        if not source.windows and retained['metadata'] != original['metadata']:
            raise MigrationInspectionError('Retained original native identity changed')
    if state == 'original':
        absent = source.reader.leaf(progress.RETAINED)
        if absent['metadata']['presence'] != 'absent':
            raise MigrationInspectionError('Unwitnessed retained original exists')
        native.observations[progress.RETAINED] = absent
    rename_raw = None
    if source.windows:
        from .windows_rename_identity import identity_record, identity_from_record, matches_observation
        actual, info, security = _windows_identity(source.reader, path)
        rename_raw = canonical_bytes(identity_record(actual))
        if pending:
            expected = identity_from_record(history[2].body['commitment']['rename_identity'])
            if actual != expected:
                if (phase != 'retain_pending' or state != 'retained'
                        or not matches_observation(expected, info, security,
                            actual.content_sha256, allow_pending=True)):
                    raise MigrationInspectionError('Original Windows rename identity changed')
                state = 'retained_restore_pending'
    return state, rename_raw


def _absent_leaf(reader, native, path):
    absent = reader.leaf(path)
    if absent['metadata']['presence'] != 'absent':
        raise MigrationInspectionError('Expected absent migration path')
    native.observations[path] = absent


def _fence_state(source, native, candidate, phase, history, names, staged):
    """Verify fence identity separately from the always-retained original."""
    from .legacy_migration_fence import _expected_fence
    if staged is not None:
        if phase != 'original_retained':
            raise MigrationInspectionError('Ephemeral fence stage requires original_retained')
        commitment = staged
    elif phase in {'fence_pending', 'fenced', 'head_pending', 'head_published', 'binding_pending', 'finalized'}:
        commitment = history[4].body['commitment']
    else:
        if 'fence.pending.json' in names:
            raise MigrationInspectionError('Unrecorded fence stage is preserved and refused')
        _absent_leaf(source.reader, native, progress.FENCE_STAGE)
        return 'absent'
    planned = candidate.plan.body
    progress._fence(commitment, planned, planned['initial_capture']['native']['platform'])
    pointer = planned['fence']['path']
    stage_present = 'fence.pending.json' in names
    active_present = pointer in source.observations
    if stage_present == active_present:
        raise MigrationInspectionError('Fence must exist in exactly one permitted location')
    if stage_present:
        if phase != 'fence_pending' and staged is None:
            raise MigrationInspectionError('Completed fence is still staged')
        path, state = progress.FENCE_STAGE, 'staged'
        raw = native.read(path)
        observed = native.observations[path]
        _absent_leaf(source.reader, native, pointer)
    else:
        if staged is not None:
            raise MigrationInspectionError('Unrecorded fence cannot be active')
        path, state = pointer, 'installed'
        raw, observed = source.raw[path], source.observations[path]
        _absent_leaf(source.reader, native, progress.FENCE_STAGE)
    if raw != _expected_fence(candidate).raw:
        raise MigrationInspectionError('Fence bytes differ from approved successor')
    if source.windows:
        from .windows_rename_identity import identity_from_record, matches_observation
        actual, info, security = _windows_identity(source.reader, path)
        expected = identity_from_record(commitment['rename_identity'])
        if actual != expected:
            if (phase != 'fence_pending' or state != 'installed'
                    or not matches_observation(expected, info, security,
                        actual.content_sha256, allow_pending=True)):
                raise MigrationInspectionError('Fence Windows rename identity changed')
            state = 'install_restore_pending'
    elif observed['metadata'] != commitment['staged_witness']:
        raise MigrationInspectionError('Fence native identity or protection changed')
    return state


def _directory(reader, windows, path):
    return reader.directory_witness(path) if windows else reader.directory(path)


def _head_state(source, native, candidate, phase, history, names, tree_commitment, prepared):
    """Bind one entire tree at either its private stage or published location."""
    from .legacy_migration_staging import STAGE
    planned = candidate.plan.body
    parent, target = planned['portable_destinations']
    windows, reader = source.windows, source.reader
    if prepared is not None:
        if phase != 'fenced':
            raise MigrationInspectionError('Ephemeral head preparation requires installed fence')
        head = prepared
    elif phase in {'head_pending', 'head_published', 'binding_pending', 'finalized'}:
        head = history[6].body['commitment']
    else:
        head = None
    expected_parent = parent['witness']
    if head is not None:
        progress._head(head, planned, planned['initial_capture']['native']['platform'])
        if expected_parent['presence'] == 'present' and head['parent_witness'] != expected_parent:
            raise MigrationInspectionError('Existing portable parent identity changed')
        expected_parent = head['parent_witness']
        if parent['witness']['presence'] == 'absent':
            native._private(expected_parent)
    if _directory(reader, windows, parent['path']) != expected_parent:
        raise MigrationInspectionError('Unrecorded or changed portable parent')
    actual_target = _directory(reader, windows, target['path'])
    target_present = actual_target['presence'] == 'present'
    stage_present = 'portable.pending' in names
    if head is None or prepared is not None:
        if actual_target != target['witness'] or stage_present != (tree_commitment is not None):
            raise MigrationInspectionError('Unwitnessed stage or portable publication')
    elif stage_present == target_present or (phase != 'head_pending' and not target_present):
        raise MigrationInspectionError('Portable tree must exist in exactly one permitted location')
    if tree_commitment is not None:
        _verify_stage(native, candidate, tree_commitment, prefix=pp.ROOT if target_present else STAGE)
    if not stage_present and _directory(reader, windows, STAGE)['presence'] != 'absent':
        raise MigrationInspectionError('Published tree left an unexpected stage')
    return 'published' if target_present else 'staged' if stage_present else 'absent'



def _binding_state(source, native, candidate, intent, phase, history, root_names, names, staged):
    from .legacy_migration_binding_records import candidate_binding
    active = 'binding.json' in root_names
    pending = 'binding.pending.json' in names
    if staged is not None:
        if phase != 'head_published':
            raise MigrationInspectionError('Ephemeral binding requires published portable head')
        commitment = staged
    elif phase in {'binding_pending', 'finalized'}:
        commitment = history[8].body['commitment']
    else:
        if active or pending:
            raise MigrationInspectionError('Unrecorded migration binding is preserved and refused')
        _absent_leaf(source.reader, native, progress.BINDING_STAGE)
        _absent_leaf(source.reader, native, progress.BINDING_TARGET)
        return 'absent'
    planned = candidate.plan.body
    progress._binding(commitment, planned, planned['initial_capture']['native']['platform'])
    expected_record = candidate_binding(intent, candidate)
    if (commitment['sha256'] != expected_record.sha256
            or commitment['size_decimal'] != str(len(expected_record.raw))):
        raise MigrationInspectionError('Binding commitment differs from approved prospective record')
    if active == pending or (phase == 'finalized' and not active) or (staged is not None and active):
        raise MigrationInspectionError('Binding must exist in exactly one permitted location')
    path, absent = ((progress.BINDING_TARGET, progress.BINDING_STAGE) if active
                    else (progress.BINDING_STAGE, progress.BINDING_TARGET))
    if native.read(path) != expected_record.raw:
        raise MigrationInspectionError('Migration binding bytes changed')
    _absent_leaf(source.reader, native, absent)
    state = 'published' if active else 'staged'
    if source.windows:
        from .windows_rename_identity import identity_from_record, matches_observation
        actual, info, security = _windows_identity(source.reader, path)
        expected = identity_from_record(commitment['rename_identity'])
        if actual != expected:
            if (phase != 'binding_pending' or not active
                    or not matches_observation(expected, info, security,
                        actual.content_sha256, allow_pending=True)):
                raise MigrationInspectionError('Binding Windows rename identity changed')
            state = 'install_restore_pending'
    elif native.observations[path]['metadata'] != commitment['staged_witness']:
        raise MigrationInspectionError('Binding native identity or protection changed')
    return state


def _checkpoint_state(source, native, candidate, intent, phase, history, root_names, names):
    from . import rebind_checkpoint as checkpoint
    paths = tuple(path for name, inventory, path in (
        ('state.json', root_names, checkpoint.STATE),
        ('terminal.json', names, checkpoint.TERMINAL)) if name in inventory)
    if phase != 'finalized':
        if paths:
            raise MigrationInspectionError('Checkpoint appeared before migration finalization')
        return ()
    from .legacy_migration_binding_records import checkpoint_records
    state, terminal, _ = checkpoint_records(history, intent, candidate)
    for path, expected in ((checkpoint.STATE, state), (checkpoint.TERMINAL, terminal)):
        if path in paths:
            if native.read(path) != expected.raw:
                raise MigrationInspectionError('Migration checkpoint differs from exact completed history')
        else:
            _absent_leaf(source.reader, native, path)
    return paths


def _inspect_prepared(legacy, local, candidate, *, staged=None, fence_staged=None, head_prepared=None, binding_staged=None):
    """Close a complete immutable read lane while borrowing both held locks."""
    planned = candidate.plan.body
    from .legacy_migration_source_state import _actual_source_snapshot
    with _actual_source_snapshot(legacy, local) as source:
        reader = source.reader
        native = _MigrationStore(SimpleNamespace(working_reader=reader), legacy.windows)
        native.lock_handle, native.lock_witness = local.lock_handle, local.lock_witness
        native.check_lock()
        source.track_store(native)
        root_names = native.children(store.ROOT)
        if not {'scope.lock', 'journals'} <= root_names or root_names - {'scope.lock', 'journals', 'binding.json', 'state.json'}:
            raise MigrationInspectionError('Unexpected migration local store inventory')
        for path, expected in ((store.ROOT + '/journals', {journal.JOURNAL_ID}),):
            if native.children(path) != expected:
                raise MigrationInspectionError('Incomplete or unexpected prepared journal inventory')
        names = native.children(store.JOURNAL)
        if not {'plan.json', 'intent.json', 'progress'} <= names or names - ({
                'plan.json', 'intent.json', 'progress', 'portable.pending', 'legacy-original.json', 'fence.pending.json', 'binding.pending.json', 'terminal.json'} | (
                    set(plans.RAW_NAMES) if candidate.lineage._raw_archive else set())):
            raise MigrationInspectionError('Unexpected or incomplete migration journal inventory')
        revisions = native.children(store.PROGRESS)
        if not 1 <= len(revisions) <= 10 or revisions != {f'{i:08d}.json' for i in range(len(revisions))}:
            raise MigrationInspectionError('Unsupported or incomplete migration progress')
        if native.read(store.JOURNAL + '/plan.json') != candidate.plan.raw:
            raise MigrationInspectionError('Stored migration plan differs from explicit approval')
        plans.verify_raw_evidence(native, candidate)
        intent = journal.load_migration_intent(native.read(store.JOURNAL + '/intent.json'),
            candidate.plan, candidate.projection_files, candidate.lineage,
            approved_plan_sha256=candidate.plan.sha256)
        witnesses = intent.body['storage_witnesses']
        if (native.lock_witness != witnesses['lock']
                or native.directory(store.JOURNAL) != witnesses['journal']
                or native.directory(store.PROGRESS) != witnesses['progress']):
            raise MigrationInspectionError('Prepared storage native identity or protection changed')
        history = progress.load_progress_history(
            [native.read(store.PROGRESS + f'/{i:08d}.json') for i in range(len(revisions))],
            intent, candidate.plan, candidate.projection_files, candidate.lineage)
        phase = history[-1].body['phase']
        rollback = phase in {'rollback_pending', 'rolled_back'}
        if rollback:
            if any(value is not None for value in (staged, fence_staged, head_prepared, binding_staged)):
                raise MigrationInspectionError('Rollback cannot accept ephemeral forward stages')
            from .legacy_migration_rollback_inspection import inspect_rollback
            source_state, fence_state, head_state, checkpoint_paths = inspect_rollback(
                source, native, candidate, intent, phase, history, root_names, names)
            rename_raw, binding_state = None, 'absent'
            commitment = None
        elif phase == 'prepared':
            commitment = staged
        elif phase in {'candidate_ready', 'retain_pending', 'original_retained', 'fence_pending', 'fenced', 'head_pending', 'head_published', 'binding_pending', 'finalized'} and staged is None:
            commitment = history[1].body['commitment']
        else:
            raise MigrationInspectionError('Native migration phase is not yet supported')
        if not rollback:
            head_state = _head_state(source, native, candidate, phase, history, names,
                                     commitment, head_prepared)
        paths = managed_paths([row['path'] for row in planned['initial_capture']['leaves']])
        ancestors = ancestor_paths(paths)
        if legacy.windows:
            from .working_tree_capture_windows import _initial_capture
            current, leaves = _initial_capture(reader, reader.root, paths, ancestors)
        else:
            from .working_tree_capture_posix import _initial_capture
            current, leaves = _initial_capture(reader, paths, ancestors)
        if build_capture(current, leaves).body != intent.body['prepared_capture']:
            raise MigrationInspectionError('Working content or prepared checkout topology changed')
        if not rollback:
            source_state, rename_raw = _source_state(source, native, candidate, phase, history, names)
            fence_state = _fence_state(source, native, candidate, phase, history, names, fence_staged)
            binding_state = _binding_state(source, native, candidate, intent, phase, history,
                                           root_names, names, binding_staged)
            checkpoint_paths = _checkpoint_state(source, native, candidate, intent, phase,
                                                 history, root_names, names)
        pointer = planned['fence']['path']
        files = [source.observations[p] for p in sorted(source.observations) if p != pointer]
        directories = [{'path': p, 'witness': w}
                       for p, w in sorted(source.directory_witnesses.items())]
        if files != [r for r in planned['legacy_files'] if r['path'] != pointer] or directories != planned['legacy_directories']:
            raise MigrationInspectionError('Approved legacy source changed')
        for item in [planned['competing_legacy']]:
            observed = (reader.directory_witness(item['path']) if legacy.windows
                        else reader.directory(item['path']))
            if observed != item['witness']:
                raise MigrationInspectionError('Portable destination or competing store changed')
        for path in native.inventories:
            native.children(path, final=True)
        if legacy.windows:
            reader.revalidate()
        else:
            reader._final_revalidate(current, leaves + list(native.observations.values()))
        native.check_lock()
        result = PreparedMigrationInspection(candidate.plan.sha256, intent, phase, history,
                                             source_state=source_state, rename_identity_raw=rename_raw,
                                             fence_state=fence_state, head_state=head_state,
                                             binding_state=binding_state, checkpoint_paths=checkpoint_paths,
                                             checkpoint_complete=len(checkpoint_paths) == (1 if rollback else 2))
    # Exiting actual snapshot revalidates immutable source and closes all read handles.
    legacy.check_mutation_window()
    local.check_lock()
    return result


@contextmanager
def _held_prepared_migration(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Internal writer lane: exact prepared inspection precedes yielding custody."""
    try:
        with custody._lock_legacy_for_plan(project_root, candidate, expected_plan_sha256, handles) as legacy:
            active_handles = legacy.reader.handles if legacy.windows else None
            with publication._custody(project_root, active_handles) as local:
                result = _inspect_prepared(legacy, local, candidate)
                yield legacy, local, result
                legacy.check_mutation_window()
                local.check_lock()
    except MigrationInspectionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        raise MigrationInspectionError(f'Prepared migration inspection refused: {exc}') from exc


def inspect_prepared_migration(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Return detached observations; no mutation or continuing custody is granted."""
    with _held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (_legacy, _local, result):
        return result
