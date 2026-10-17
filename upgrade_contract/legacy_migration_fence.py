"""Journaled installation of a legacy-refusing successor control record.

The retained original remains immutable. The staged fence has its own recorded
native identity; equal bytes alone never authorize publication or cleanup.
"""
from __future__ import annotations

from contextlib import ExitStack
import ntpath
import os

from . import legacy_migration_inspection as inspection
from . import legacy_migration_progress as progress
from . import legacy_migration_retention as retention
from . import local_binding as lb
from . import rebind_checkpoint as checkpoint


class MigrationFenceError(ValueError):
    """The exact recorded fence transition cannot proceed safely."""


def _expected_fence(candidate):
    from .legacy_migration_records import build_fence
    planned = candidate.plan.body
    original = next(r for r in planned['legacy_files'] if r['path'] == planned['fence']['path'])
    fence = build_fence(candidate.lineage, approved_lineage_sha256=candidate.lineage.sha256,
                       original_pointer_bytes=candidate.raw_archive[planned['fence']['path']])
    if (fence.pointer_path != planned['fence']['path']
            or fence.sha256 != planned['fence']['sha256']
            or str(len(fence.raw)) != planned['fence']['size_decimal']):
        raise MigrationFenceError('Fence differs from explicit approved plan')
    return fence


def _stage_fence(legacy, local, candidate):
    legacy.check_mutation_window()
    local.check_lock()
    fence = _expected_fence(candidate)
    witness = checkpoint._write_new(local, progress.FENCE_STAGE, fence.raw)
    rename_identity = None
    if legacy.windows:
        from .windows_restoring_backend import WindowsRestoringBackend
        from .windows_rename_identity import identity_record
        path = ntpath.join(legacy.reader.root, *progress.FENCE_STAGE.split('/'))
        with WindowsRestoringBackend(legacy.reader.handles, {'stage': path}) as backend:
            rename_identity = identity_record(backend.observe('stage'))
    commitment = {'staged_path': progress.FENCE_STAGE, 'staged_witness': witness,
        'pointer_path': fence.pointer_path,
        'pointer_absent': lb.absent_witness(candidate.plan.body['initial_capture']['native']['platform'], 'file'),
        'sha256': fence.sha256, 'size_decimal': str(len(fence.raw)),
        'rename_identity': rename_identity}
    legacy.check_mutation_window()
    local.check_lock()
    return commitment


def _move_fence(legacy, local, candidate, commitment, *, restore_only=False):
    legacy.check_mutation_window()
    local.check_lock()
    source, target = progress.FENCE_STAGE, commitment['pointer_path']
    if legacy.windows:
        from .windows_restoring_backend import WindowsRestoringBackend
        from .windows_rename_identity import identity_from_record
        expected = identity_from_record(commitment['rename_identity'])
        paths = {key: ntpath.join(legacy.reader.root, *path.split('/'))
                 for key, path in (('source', source), ('destination', target))}
        with WindowsRestoringBackend(legacy.reader.handles, paths) as backend:
            if restore_only:
                backend.restore_pending('source', 'destination', expected)
            else:
                backend.move_exact('source', 'destination', expected)
    else:
        if restore_only:
            raise MigrationFenceError('POSIX fence cannot restore Windows metadata')
        from .portable_provenance_posix import _same_namespace, _witness
        from .transaction import rename_no_replace_at
        with ExitStack() as stack:
            target_parent, _, target_name = target.rpartition('/')
            target_fd = legacy.reader._walk(target_parent, stack)
            with checkpoint._parent(local, source) as (source_fd, source_name):
                fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd)
                stack.callback(os.close, fd)
                before = _witness(fd, leaf=True, label=source)
                if lb.project_posix_witness(before.metadata) != commitment['staged_witness']:
                    raise MigrationFenceError('Fence identity changed before publication')
                _same_namespace(source_fd, source_name, before, leaf=True, label=source)
                checkpoint._check_bytes(lambda count: os.read(fd, count), _expected_fence(candidate).raw)
                if _witness(fd, leaf=True, label=source) != before:
                    raise MigrationFenceError('Fence changed during read')
                legacy.check_mutation_window()
                local.check_lock()
                rename_no_replace_at(source_fd, source_name, target_fd, target_name)
                after = _witness(fd, leaf=True, label=target)
                if lb.project_posix_witness(after.metadata) != commitment['staged_witness']:
                    raise MigrationFenceError('Published fence identity or protection changed')
                _same_namespace(target_fd, target_name, after, leaf=True, label=target)
                os.fsync(source_fd)
                os.fsync(target_fd)
    legacy.check_mutation_window()
    local.check_lock()


def install_legacy_fence(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Install only the recorded successor while retaining exact original custody.

    A partial or unrecorded stage is preserved and refused. A recorded move may
    resume before or after publication, including bounded Windows metadata repair.
    Portable authority remains unpublished at this boundary.
    """
    with inspection._held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (legacy, local, observed):
        if observed.phase == 'original_retained':
            commitment = _stage_fence(legacy, local, candidate)
            inspection._inspect_prepared(legacy, local, candidate, fence_staged=commitment)
            retention._append(legacy, local, candidate, observed, 'fence_pending', commitment)
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase == 'fence_pending':
            commitment = observed.progress_history[4].body['commitment']
            if observed.fence_state in {'staged', 'install_restore_pending'}:
                _move_fence(legacy, local, candidate, commitment,
                            restore_only=observed.fence_state == 'install_restore_pending')
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.fence_state != 'installed':
                raise MigrationFenceError('Fence did not reach exact installed state')
            retention._append(legacy, local, candidate, observed, 'fenced')
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase != 'fenced' or observed.fence_state != 'installed':
            raise MigrationFenceError('Fence installation requires original_retained state')
        return observed
