"""Publish the recorded portable tree with one native no-replace directory move.

The installed legacy fence and retained original remain under both locks.
Once the tree is present, recovery must continue forward; this module never
restores the legacy writer or infers authority from matching content alone.
"""
from __future__ import annotations

from contextlib import ExitStack
import ntpath
import os

from . import legacy_migration_inspection as inspection
from . import legacy_migration_progress as progress
from . import legacy_migration_retention as retention
from . import local_binding as lb
from . import portable_provenance as pp
from . import rebind_checkpoint as checkpoint
from . import rebind_preparation as bootstrap


class MigrationHeadError(ValueError):
    """Recorded portable publication cannot safely proceed."""


def _prepare_parent(legacy, local, candidate):
    legacy.check_mutation_window()
    local.check_lock()
    planned = candidate.plan.body
    parent = planned['portable_destinations'][0]
    expected = parent['witness']
    if legacy.windows:
        from .windows_backend import WindowsExchangeBackend
        path = ntpath.join(legacy.reader.root, *parent['path'].split('/'))
        with WindowsExchangeBackend(legacy.reader.handles, {'parent': path}) as backend:
            slot = backend._slot('parent')
            opener = (legacy.reader.handles.create_private_directory(slot.parent, slot.name)
                      if expected['presence'] == 'absent' else
                      legacy.reader.handles.open_child(slot.parent, slot.name,
                                                       kind='directory', pin_for_read=True))
            with opener as held:
                witness = lb.project_windows_witness(held.info(), held.security())
    else:
        from .portable_provenance_posix import _same_namespace, _witness
        with ExitStack() as stack:
            ancestor, _, name = parent['path'].rpartition('/')
            parent_fd = legacy.reader._walk(ancestor, stack)
            fd = (bootstrap._mkdir_posix(parent_fd, name) if expected['presence'] == 'absent'
                  else os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd))
            stack.callback(os.close, fd)
            observed = _witness(fd, leaf=False, label=parent['path'])
            _same_namespace(parent_fd, name, observed, leaf=False, label=parent['path'])
            witness = lb.project_posix_witness(observed.metadata)
    if expected['presence'] == 'present':
        if witness != expected:
            raise MigrationHeadError('Approved portable parent changed')
    else:
        local._private(witness)
    legacy.check_mutation_window()
    local.check_lock()
    return {'stage_path': progress.PORTABLE_STAGE, 'target_path': pp.ROOT,
            'target_absent': planned['portable_destinations'][1]['witness'],
            'parent_path': parent['path'], 'parent_witness': witness}


def _move_tree(legacy, local, candidate, commitment, *, tree_commitment):
    legacy.check_mutation_window()
    local.check_lock()
    source, target = commitment['stage_path'], commitment['target_path']
    expected = tree_commitment['stage_root']
    if legacy.windows:
        from .windows_backend import WindowsExchangeBackend
        paths = {key: ntpath.join(legacy.reader.root, *path.split('/'))
                 for key, path in (('source', source), ('target', target))}
        handles = legacy.reader.handles
        with WindowsExchangeBackend(handles, paths) as backend:
            src, dst = backend._slot('source'), backend._slot('target')
            if lb.project_windows_witness(dst.parent.info(), dst.parent.security()) != commitment['parent_witness']:
                raise MigrationHeadError('Portable destination parent changed before move')
            with handles.open_child(src.parent, src.name, kind='directory', for_rename=True) as held:
                if lb.project_windows_witness(held.info(), held.security()) != expected:
                    raise MigrationHeadError('Staged tree root changed before move')
                legacy.check_mutation_window()
                local.check_lock()
                handles.rename_no_replace(held, dst.parent, dst.name)
                if lb.project_windows_witness(held.info(), held.security()) != expected:
                    raise MigrationHeadError('Published tree root identity or protection changed')
    else:
        from .portable_provenance_posix import _same_namespace, _witness
        from .transaction import rename_no_replace_at
        with ExitStack() as stack:
            ancestor, _, parent_name = commitment['parent_path'].rpartition('/')
            ancestor_fd = legacy.reader._walk(ancestor, stack)
            target_fd = os.open(parent_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=ancestor_fd)
            stack.callback(os.close, target_fd)
            parent_before = _witness(target_fd, leaf=False, label=commitment['parent_path'])
            if lb.project_posix_witness(parent_before.metadata) != commitment['parent_witness']:
                raise MigrationHeadError('Portable destination parent changed before move')
            _same_namespace(ancestor_fd, parent_name, parent_before, leaf=False, label=commitment['parent_path'])
            with checkpoint._parent(local, source) as (source_fd, source_name):
                fd = os.open(source_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd)
                stack.callback(os.close, fd)
                before = _witness(fd, leaf=False, label=source)
                if lb.project_posix_witness(before.metadata) != expected:
                    raise MigrationHeadError('Staged tree root changed before move')
                _same_namespace(source_fd, source_name, before, leaf=False, label=source)
                legacy.check_mutation_window()
                local.check_lock()
                target_name = target.rsplit('/', 1)[-1]
                rename_no_replace_at(source_fd, source_name, target_fd, target_name)
                after = _witness(fd, leaf=False, label=target)
                if lb.project_posix_witness(after.metadata) != expected:
                    raise MigrationHeadError('Published tree root identity or protection changed')
                _same_namespace(target_fd, target_name, after, leaf=False, label=target)
                parent_after = _witness(target_fd, leaf=False, label=commitment['parent_path'])
                if lb.project_posix_witness(parent_after.metadata) != commitment['parent_witness']:
                    raise MigrationHeadError('Portable parent protection changed during move')
                _same_namespace(ancestor_fd, parent_name, parent_after, leaf=False, label=commitment['parent_path'])
                os.fsync(source_fd)
                os.fsync(target_fd)
    legacy.check_mutation_window()
    local.check_lock()


def publish_migration_head(project_root, *, candidate, expected_plan_sha256, handles=None):
    """Resume only a recorded tree publication; preserve all unknown objects."""
    with inspection._held_prepared_migration(project_root, candidate=candidate,
            expected_plan_sha256=expected_plan_sha256, handles=handles) as (legacy, local, observed):
        if observed.phase == 'fenced':
            commitment = _prepare_parent(legacy, local, candidate)
            inspection._inspect_prepared(legacy, local, candidate, head_prepared=commitment)
            retention._append(legacy, local, candidate, observed, 'head_pending', commitment)
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase == 'head_pending':
            if observed.head_state == 'staged':
                _move_tree(legacy, local, candidate,
                    observed.progress_history[6].body['commitment'],
                    tree_commitment=observed.progress_history[1].body['commitment'])
                observed = inspection._inspect_prepared(legacy, local, candidate)
            if observed.head_state != 'published':
                raise MigrationHeadError('Portable head has not reached exact published state')
            retention._append(legacy, local, candidate, observed, 'head_published')
            observed = inspection._inspect_prepared(legacy, local, candidate)
        if observed.phase != 'head_published' or observed.head_state != 'published':
            raise MigrationHeadError('Portable publication requires an installed legacy fence')
        return observed
