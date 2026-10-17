"""Atomic trace-name publication with bounded existing write/metadata preservation.

Publication retains the report writers' name-refresh gap. No writer lock or
power-loss durability claim. Unsupported metadata refuses before publication.
"""
from __future__ import annotations

import hashlib
import ctypes
import importlib
import os
from pathlib import Path
import secrets
import stat
import sys
import types

from naos_policy import _open_report_parent_fd, _report_metadata_at, _secure_directory_fd_writes_supported


def _metadata_module():
    sibling = Path(__file__).with_name('naos_posix_metadata')
    directory = sibling if sibling.is_dir() else Path(__file__).resolve().parents[1] / 'upgrade_contract'
    if not all((directory / filename).is_file() for filename in ('security.py', 'linux_primitives.py')):
        raise ValueError('Trace atomic publication metadata helper distribution is incomplete')
    name = '_naos_trace_posix_metadata'
    if name not in sys.modules:
        package = types.ModuleType(name)
        package.__path__ = [str(directory)]
        sys.modules[name] = package
    return importlib.import_module(name + '.security')


def _bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            return b''.join(chunks)
        chunks.append(block)


def _metadata_key(value):
    return tuple(value[key] for key in ('uid', 'gid', 'mode', 'flags', 'acl_entries', 'xattrs'))


def _stage_name_matches(parent: int, name: str, descriptor: int) -> bool:
    """Qualify the name against our still-held unique regular staging object."""
    try:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        held = os.fstat(descriptor)
    except OSError:
        return False
    return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
            and stat.S_ISREG(held.st_mode) and held.st_nlink == 1
            and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))


def publish_trace(path: Path, content: str, original: bytes | None) -> None:
    if os.name == 'nt':
        from naos_windows_report import write_strict_report
        write_strict_report(path, content, require_existing_write_access=True,
                            expected_preimage_sha256=hashlib.sha256(original).hexdigest() if original is not None else None,
                            expect_absent=original is None)
        return
    if not _secure_directory_fd_writes_supported() or not callable(getattr(os, 'fchown', None)):
        raise ValueError('Trace atomic publication metadata primitives unavailable')
    metadata = _metadata_module()
    parent, name = _open_report_parent_fd(path, strict_parent_topology=False)
    source = stage = -1
    temporary = None
    try:
        leaf = _report_metadata_at(parent, name, path)
        if (leaf is None) != (original is None):
            raise ValueError('Trace target changed before staging')
        observed = None
        if leaf is not None:
            # Actual write-open, not directory rename permission, binds authority.
            source = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            observed = metadata.observe_created_file_metadata_fd(source)
            if (observed['device'], observed['inode']) != (leaf.st_dev, leaf.st_ino) or _bytes(source) != original:
                raise ValueError('Trace target changed before staging')
            if not metadata.supported_metadata_flags(observed) or observed['acl_entries']:
                raise ValueError('Trace metadata preservation does not support these flags/ACLs')
        for _ in range(8):
            candidate = '.naos-trace-' + str(os.getpid()) + '-' + secrets.token_hex(8) + '.tmp'
            try:
                stage = os.open(candidate, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=parent)
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError('Cannot allocate trace publication stage')
        initial = metadata.observe_created_file_metadata_fd(stage)
        if not metadata.supported_metadata_flags(initial) or initial['acl_entries']:
            raise ValueError('Trace staging metadata is unsupported')
        if observed is not None:
            if (initial['uid'], initial['gid']) != (observed['uid'], observed['gid']):
                os.fchown(stage, observed['uid'], observed['gid'])
            os.fchmod(stage, observed['mode'])
            secured = metadata.observe_created_file_metadata_fd(stage)
            if tuple(secured[key] for key in ('uid', 'gid', 'mode')) != tuple(observed[key] for key in ('uid', 'gid', 'mode')):
                raise ValueError('Trace staging permissions could not be preserved before payload')
            if observed['platform'] == 'Linux':
                metadata.linux_primitives.copy_data_and_xattrs(source, stage)
            else:
                # Same bounded native xattr copy used by v3_publication_stage.
                libc = ctypes.CDLL(None, use_errno=True)
                copy = libc.fcopyfile
                copy.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
                copy.restype = ctypes.c_int
                if copy(source, stage, None, 0x00000004) != 0:  # COPYFILE_XATTR
                    raise OSError(ctypes.get_errno(), 'Native trace xattr preservation failed')
        payload = content.encode('utf-8')
        os.lseek(stage, 0, os.SEEK_SET)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(stage, remaining)
            if written <= 0:
                raise OSError('Trace staging write made no progress')
            remaining = remaining[written:]
        os.ftruncate(stage, len(payload))
        if observed is not None:
            os.fchmod(stage, observed['mode'])
        os.fsync(stage)
        staged = metadata.observe_created_file_metadata_fd(stage)
        expected = observed if observed is not None else initial
        if _metadata_key(staged) != _metadata_key(expected) or _bytes(stage) != payload:
            raise ValueError('Trace staging bytes/metadata preservation could not be verified')
        current = _report_metadata_at(parent, name, path)
        if observed is not None:
            if current is None or (current.st_dev, current.st_ino) != (observed['device'], observed['inode']):
                raise ValueError('Trace target identity changed before publication')
            if metadata.observe_created_file_metadata_fd(source) != observed or _bytes(source) != original:
                raise ValueError('Trace target content/metadata changed before publication')
        elif current is not None:
            raise ValueError('Trace target appeared before publication')
        if not _stage_name_matches(parent, temporary, stage):
            raise ValueError('Trace staging name no longer identifies the held stage; foreign occupant preserved')
        # Whole-file rename publication; the name can change after the last check.
        os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
    finally:
        try:
            # Never unlink a foreign occupant after an interrupted stage operation.
            if temporary is not None and stage >= 0 and _stage_name_matches(parent, temporary, stage):
                os.unlink(temporary, dir_fd=parent)
        finally:
            try:
                if source >= 0:
                    os.close(source)
            finally:
                try:
                    if stage >= 0:
                        os.close(stage)
                finally:
                    os.close(parent)
