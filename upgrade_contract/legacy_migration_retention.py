"""Retain the exact approved legacy pointer under both native locks.

A persisted pending record precedes the move. Recovery accepts only the exact
original object at exactly one location. This does not publish portable authority.
"""
from __future__ import annotations

from contextlib import ExitStack
import ntpath
import os

from . import legacy_migration_inspection as inspection
from . import legacy_migration_progress as progress
from . import local_binding as lb
from . import rebind_checkpoint as checkpoint
from . import rebind_store_inspection as store


class MigrationRetentionError(ValueError):
    """Retention cannot proceed from this exact observed state."""


def _append(legacy, local, candidate, observed, phase, commitment=None):
    record = progress.advance_progress(observed.progress_history[-1], phase, commitment,
        observed.intent, candidate.plan, candidate.projection_files, candidate.lineage)
    legacy.check_mutation_window()
    local.check_lock()
    checkpoint._write_new(local,
        store.PROGRESS + f'/{record.body["sequence"]:08d}.json', record.raw)


def _move_original(legacy, local, candidate, commitment, *, restore_only=False):
    legacy.check_mutation_window()
    local.check_lock()
    source, target = commitment['source_path'], progress.RETAINED
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
            raise MigrationRetentionError('POSIX retention cannot restore Windows metadata')
        from .portable_provenance_posix import _same_namespace, _witness
        from .transaction import rename_no_replace_at
        original = candidate.raw_archive[commitment['source_path']]
        parent, _, name = source.rpartition('/')
        with ExitStack() as stack:
            source_fd = legacy.reader._walk(parent, stack)
            with checkpoint._parent(local, target) as (target_fd, target_name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd)
                stack.callback(os.close, fd)
                before = _witness(fd, leaf=True, label=source)
                if lb.project_posix_witness(before.metadata) != commitment['source_witness']:
                    raise MigrationRetentionError('Original pointer identity changed before move')
                _same_namespace(source_fd, name, before, leaf=True, label=source)
                checkpoint._check_bytes(lambda count: os.read(fd, count), original)
                if _witness(fd, leaf=True, label=source) != before:
                    raise MigrationRetentionError('Original pointer changed during read')
                legacy.check_mutation_window()
                local.check_lock()
                rename_no_replace_at(source_fd, name, target_fd, target_name)
                after = _witness(fd, leaf=True, label=target)
                if lb.project_posix_witness(after.metadata) != commitment['source_witness']:
                    raise MigrationRetentionError('Retained pointer identity or protection changed')
                _same_namespace(target_fd, target_name, after, leaf=True, label=target)
                os.fsync(source_fd)
                os.fsync(target_fd)
    legacy.check_mutation_window()
    local.check_lock()


def retain_original_pointer(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Advance candidate_ready through restartable original retention.

    No source bytes are copied into a replacement authority. The original native
    object is moved without replacement; Windows transient rename metadata is
    restored only from the pre-move persisted identity. Unknown states refuse.
    """
    with inspection._held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (legacy, local, observed):
        if observed.phase == 'candidate_ready':
            pointer = candidate.plan.body['fence']['path']
            original = next(r for r in candidate.plan.body['legacy_files'] if r['path'] == pointer)
            from .canonical import loads_strict_json
            commitment = {'source_path': pointer, 'source_witness': original['metadata'],
                'retained_path': progress.RETAINED,
                'retained_absent': lb.absent_witness(
                    candidate.plan.body['initial_capture']['native']['platform'], 'file'),
                'sha256': original['content']['sha256'],
                'size_decimal': original['content']['size_decimal'],
                'rename_identity': (loads_strict_json(observed.rename_identity_raw)
                                    if legacy.windows else None)}
            _append(legacy, local, candidate, observed, 'retain_pending', commitment)
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase == 'retain_pending':
            commitment = observed.progress_history[2].body['commitment']
            if observed.source_state in {'original', 'retained_restore_pending'}:
                _move_original(legacy, local, candidate, commitment,
                               restore_only=observed.source_state == 'retained_restore_pending')
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.source_state != 'retained':
                raise MigrationRetentionError('Original retention did not reach exact retained state')
            _append(legacy, local, candidate, observed, 'original_retained')
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase != 'original_retained' or observed.source_state != 'retained':
            raise MigrationRetentionError('Retention requires a witnessed ready candidate')
        return observed
