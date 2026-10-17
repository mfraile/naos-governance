"""Exact empty, protected directory moves for an approved V3 program.

The caller owns the persisted creation witness, complete inventory validation,
scope lock and publication ordering. This primitive creates no authority.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager

from . import local_binding as lb
from .windows_handles import WindowsHandleError


def _witness(handle):
    before = handle.info()
    result = lb.project_windows_witness(before, handle.security())
    if before != handle.info():
        raise ValueError('Directory changed during observation')
    return result


@contextmanager
def move_parents(custody, paths, expected_directories):
    """Pin and validate every move ancestor without retaining moving children."""
    if not custody.windows:
        raise ValueError('Native Windows custody required')
    handles, reader = custody.reader.handles, custody.reader
    with ExitStack() as stack:
        parents = {path.rpartition('/')[0] for path in paths}
        root = reader.directories[reader.project]
        if '' in parents:
            root = stack.enter_context(
                handles.open_child(reader.directories[reader.project[:-1]],
                    reader.project[-1], kind='directory', for_publish=True)
                if reader.project else handles.open_root(reader.drive, for_publish=True))
            if _witness(root) != _witness(reader.directories[reader.project]):
                raise ValueError('Project root changed before move')
        held = {'': root}
        for relative in sorted(parents, key=lambda p: (p.count('/'), p)):
            current = ''
            for part in relative.split('/') if relative else ():
                path = part if not current else current + '/' + part
                if (part in ('', '.', '..') or '\\' in part or ':' in part
                        or path not in expected_directories):
                    raise ValueError('Directory move parent lacks exact approved witness')
                if path not in held:
                    held[path] = stack.enter_context(handles.open_child(
                        held[current], part, kind='directory',
                        for_publish=path in parents, pin_for_read=path not in parents))
                if _witness(held[path]) != expected_directories[path]:
                    raise ValueError('Directory move parent identity/protection changed')
                current = path
        custody.check_lock()
        yield {p: held[p] for p in parents}
        for path, handle in held.items():
            if path and _witness(handle) != expected_directories[path]:
                raise ValueError('Directory move ancestor changed')
        custody.check_lock()


def move_empty_directory(custody, source, destination, expected, expected_directories):
    """No-replace rename and post-close check of the exact empty directory."""
    lb._validate_witness(expected, 'Windows', 'directory')
    if (expected['presence'] != 'present' or not expected['security']['dacl_protected']
            or source == destination):
        raise ValueError('Exact protected directory creation witness required')
    handles = custody.reader.handles
    with move_parents(custody, (source, destination), expected_directories) as parents:
        sp, _, sn = source.rpartition('/')
        dp, _, dn = destination.rpartition('/')
        with handles.open_child(parents[sp], sn, kind='directory', for_rename=True) as child:
            if _witness(child) != expected or handles.list_children(child, max_entries=1):
                raise ValueError('Directory move requires exact empty committed object')
            custody.check_lock()
            handles.rename_no_replace(child, parents[dp], dn)
            if _witness(child) != expected or handles.list_children(child, max_entries=1):
                raise ValueError('Moved directory changed; preserve object')
        try:
            remaining = handles.open_child(parents[sp], sn, kind='directory', pin_for_read=True)
        except WindowsHandleError as exc:
            if exc.operation != 'NtCreateFile' or exc.ntstatus != 0xC0000034:
                raise
        else:
            remaining.close()
            raise ValueError('Directory source reappeared after move')
        with handles.open_child(parents[dp], dn, kind='directory', pin_for_read=True) as moved:
            if _witness(moved) != expected or handles.list_children(moved, max_entries=1):
                raise ValueError('Post-close directory witness differs')
