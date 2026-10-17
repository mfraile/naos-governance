"""Actual-state inspection of recorded pre-head rollback, without virtual history."""
from __future__ import annotations

from . import legacy_migration_inspection as inspection
from . import legacy_migration_progress as progress


def _object(source, native, path, expected_raw, witness, rename, *, pending):
    """Validate one actual object; report only the bounded Windows repair state."""
    if path in source.observations:
        raw, observed = source.raw[path], source.observations[path]
    else:
        raw = native.read(path)
        observed = native.observations[path]
    if raw != expected_raw:
        raise inspection.MigrationInspectionError('Rollback object bytes changed')
    if source.windows and rename is not None:
        from .windows_rename_identity import identity_from_record, matches_observation
        actual, info, security = inspection._windows_identity(source.reader, path)
        expected = identity_from_record(rename)
        if actual != expected:
            if not pending or not matches_observation(expected, info, security,
                    actual.content_sha256, allow_pending=True):
                raise inspection.MigrationInspectionError('Rollback Windows identity changed')
            return True
    elif observed['metadata'] != witness:
        raise inspection.MigrationInspectionError('Rollback native identity changed')
    return False


def inspect_rollback(source, native, candidate, intent, phase, history, root_names, names):
    """Return detached original/fence/tree/checkpoint states for this actual read."""
    from .legacy_migration_fence import _expected_fence
    from . import rebind_checkpoint as checkpoint
    if root_names != {'scope.lock', 'journals'} or 'binding.pending.json' in names:
        raise inspection.MigrationInspectionError('Rollback cannot contain binding or state')
    normal = history[:-1] if phase == 'rollback_pending' else history[:-2]
    source_phase = normal[-1].body['phase']
    commits = {r.body['phase']: r.body['commitment'] for r in normal if 'commitment' in r.body}
    planned = candidate.plan.body
    parent, target = planned['portable_destinations']
    expected_parent = (commits['head_pending']['parent_witness'] if 'head_pending' in commits
                       else parent['witness'])
    if inspection._directory(source.reader, source.windows, parent['path']) != expected_parent:
        raise inspection.MigrationInspectionError('Rollback portable parent changed or unrecorded')
    if inspection._directory(source.reader, source.windows, target['path']) != target['witness']:
        raise inspection.MigrationInspectionError('Published or foreign portable head forbids rollback')
    tree = commits.get('candidate_ready')
    if ('portable.pending' in names) != (tree is not None):
        raise inspection.MigrationInspectionError('Rollback candidate stage changed or unrecorded')
    if tree is not None:
        inspection._verify_stage(native, candidate, tree)
    elif inspection._directory(source.reader, source.windows, progress.PORTABLE_STAGE)['presence'] != 'absent':
        raise inspection.MigrationInspectionError('Unexpected rollback tree stage')

    pointer = planned['fence']['path']
    original = next(row for row in planned['legacy_files'] if row['path'] == pointer)
    original_raw = candidate.raw_archive[pointer]
    fence_raw = _expected_fence(candidate).raw
    active_raw = source.raw.get(pointer)
    pointer_kind = ('original' if active_raw == original_raw else
                    'fence' if active_raw == fence_raw else
                    'absent' if pointer not in source.observations else 'foreign')
    retained = 'legacy-original.json' in names
    fence_staged = 'fence.pending.json' in names
    retention = commits.get('retain_pending')
    fence = commits.get('fence_pending')
    if pointer_kind == 'foreign' or (pointer_kind == 'original') == retained:
        raise inspection.MigrationInspectionError('Rollback original must occupy exactly one slot')
    if retention is None and (retained or pointer_kind != 'original'):
        raise inspection.MigrationInspectionError('Original moved without committed retention')
    if fence is None:
        if pointer_kind == 'fence' or fence_staged:
            raise inspection.MigrationInspectionError('Unrecorded rollback fence')
    elif (pointer_kind == 'fence') == fence_staged:
        raise inspection.MigrationInspectionError('Committed rollback fence must occupy one slot')
    original_path = progress.RETAINED if retained else pointer
    repair_original = _object(source, native, original_path, original_raw,
        original['metadata'], retention['rename_identity'] if retention else None,
        pending=phase == 'rollback_pending' and (not retained or source_phase == 'retain_pending'))
    source_state = 'retained' if retained else 'original'
    if repair_original:
        source_state += '_restore_pending'
    fence_state = 'absent'
    if fence is not None:
        fence_path = progress.FENCE_STAGE if fence_staged else pointer
        repair_fence = _object(source, native, fence_path, fence_raw,
            fence['staged_witness'], fence['rename_identity'],
            pending=phase == 'rollback_pending' and (fence_staged or source_phase == 'fence_pending'))
        fence_state = 'staged' if fence_staged else 'installed'
        if repair_fence:
            fence_state = 'stage_restore_pending' if fence_staged else 'install_restore_pending'
        # Fence repair precedes original reversal, and forward retention repair
        # preceded any recorded fence. Neither unreachable mixture is adopted.
        if (repair_fence and pointer_kind == 'original') or (repair_original and retained):
            raise inspection.MigrationInspectionError('Unreachable rollback metadata repair order')
    if not retained:
        inspection._absent_leaf(source.reader, native, progress.RETAINED)
    if not fence_staged:
        inspection._absent_leaf(source.reader, native, progress.FENCE_STAGE)
    if pointer_kind == 'absent':
        inspection._absent_leaf(source.reader, native, pointer)
    if phase == 'rolled_back' and (source_state != 'original' or fence_state not in {'absent', 'staged'}):
        raise inspection.MigrationInspectionError('Rollback endpoint is not exact')
    checkpoint_paths = ()
    if 'terminal.json' in names:
        if phase != 'rolled_back':
            raise inspection.MigrationInspectionError('Rollback terminal appeared before endpoint')
        from .legacy_migration_binding_records import rollback_terminal
        if native.read(checkpoint.TERMINAL) != rollback_terminal(history, intent, candidate).raw:
            raise inspection.MigrationInspectionError('Rollback terminal differs from completed history')
        checkpoint_paths = (checkpoint.TERMINAL,)
    else:
        inspection._absent_leaf(source.reader, native, checkpoint.TERMINAL)
    return source_state, fence_state, 'staged' if tree is not None else 'absent', checkpoint_paths
