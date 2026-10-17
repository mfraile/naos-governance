"""Reverse only recorded legacy file moves before portable publication.

The stage, fence and journal are retained as evidence. Unknown objects are never
deleted or adopted. An actually published portable head is always forward-only.
"""
from __future__ import annotations

from contextlib import ExitStack
import ntpath
import os

from . import legacy_migration_binding_records as records
from . import legacy_migration_inspection as inspection
from . import legacy_migration_progress as progress
from . import legacy_migration_retention as retention
from . import local_binding as lb
from . import rebind_checkpoint as checkpoint
from . import rebind_store_inspection as store


class MigrationRollbackError(ValueError):
    """No exact pre-head rollback is authorized by the current actual state."""


def _reverse_file(legacy, local, source, target, raw, witness, rename_identity, *, restore_only=False):
    legacy.check_mutation_window()
    local.check_lock()
    if legacy.windows:
        from .windows_restoring_backend import WindowsRestoringBackend
        from .windows_rename_identity import identity_from_record
        paths = {key: ntpath.join(legacy.reader.root, *path.split('/'))
                 for key, path in (('source', source), ('destination', target))}
        expected = identity_from_record(rename_identity)
        with WindowsRestoringBackend(legacy.reader.handles, paths) as backend:
            if restore_only:
                backend.restore_pending('source', 'destination', expected)
            else:
                backend.move_exact('source', 'destination', expected)
    else:
        if restore_only:
            raise MigrationRollbackError('POSIX rollback cannot repair Windows metadata')
        from .portable_provenance_posix import _same_namespace, _witness
        from .transaction import rename_no_replace_at
        with ExitStack() as stack:
            def parent(path):
                if path.startswith(store.JOURNAL + '/'):
                    return stack.enter_context(checkpoint._parent(local, path))
                directory, _, name = path.rpartition('/')
                return legacy.reader._walk(directory, stack), name
            source_fd, source_name = parent(source)
            target_fd, target_name = parent(target)
            fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd)
            stack.callback(os.close, fd)
            before = _witness(fd, leaf=True, label=source)
            if lb.project_posix_witness(before.metadata) != witness:
                raise MigrationRollbackError('Recorded rollback object identity changed')
            _same_namespace(source_fd, source_name, before, leaf=True, label=source)
            checkpoint._check_bytes(lambda count: os.read(fd, count), raw)
            if _witness(fd, leaf=True, label=source) != before:
                raise MigrationRollbackError('Rollback object changed during read')
            legacy.check_mutation_window()
            local.check_lock()
            rename_no_replace_at(source_fd, source_name, target_fd, target_name)
            after = _witness(fd, leaf=True, label=target)
            if lb.project_posix_witness(after.metadata) != witness:
                raise MigrationRollbackError('Restored object identity or protection changed')
            _same_namespace(target_fd, target_name, after, leaf=True, label=target)
            os.fsync(source_fd)
            os.fsync(target_fd)
    legacy.check_mutation_window()
    local.check_lock()


def rollback_prepared_migration(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Restore the original object while retaining all committed migration evidence."""
    from .legacy_migration_fence import _expected_fence
    with inspection._held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (legacy, local, observed):
        if observed.phase in progress._ROLLBACK_SOURCES:
            if observed.head_state == 'published' or observed.binding_state != 'absent':
                raise MigrationRollbackError('Published portable history requires forward completion')
            retention._append(legacy, local, candidate, observed, 'rollback_pending',
                              {'source_phase': observed.phase})
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase == 'rollback_pending':
            commits = {r.body['phase']: r.body['commitment']
                       for r in observed.progress_history[:-1] if 'commitment' in r.body}
            pointer = candidate.plan.body['fence']['path']
            original = next(r for r in candidate.plan.body['legacy_files'] if r['path'] == pointer)
            original_raw = candidate.raw_archive[pointer]
            retained = commits.get('retain_pending')
            fenced = commits.get('fence_pending')
            if observed.source_state.endswith('_restore_pending'):
                source, target = ((pointer, progress.RETAINED) if observed.source_state == 'retained_restore_pending'
                                  else (progress.RETAINED, pointer))
                _reverse_file(legacy, local, source, target, original_raw,
                    original['metadata'], retained['rename_identity'], restore_only=True)
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.fence_state in {'install_restore_pending', 'stage_restore_pending'}:
                source, target = ((progress.FENCE_STAGE, pointer) if observed.fence_state == 'install_restore_pending'
                                  else (pointer, progress.FENCE_STAGE))
                _reverse_file(legacy, local, source, target, _expected_fence(candidate).raw,
                    fenced['staged_witness'], fenced['rename_identity'], restore_only=True)
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.fence_state == 'installed':
                _reverse_file(legacy, local, pointer, progress.FENCE_STAGE, _expected_fence(candidate).raw,
                              fenced['staged_witness'], fenced['rename_identity'])
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.source_state == 'retained':
                _reverse_file(legacy, local, progress.RETAINED, pointer, original_raw,
                              original['metadata'], retained['rename_identity'])
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.source_state != 'original' or observed.fence_state not in {'absent', 'staged'}:
                raise MigrationRollbackError('Rollback has not reached exact original endpoint')
            retention._append(legacy, local, candidate, observed, 'rolled_back')
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase != 'rolled_back':
            raise MigrationRollbackError('Only a pre-head journal can roll back')
        if not observed.checkpoint_complete:
            terminal = records.rollback_terminal(observed.progress_history, observed.intent, candidate)
            legacy.check_mutation_window()
            checkpoint._write_new(local, checkpoint.TERMINAL, terminal.raw)
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if not observed.checkpoint_complete:
            raise MigrationRollbackError('Rollback terminal is incomplete')
        return observed
