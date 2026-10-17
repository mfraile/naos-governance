"""Held, read-only capture of a legacy scope using the current host's primitives.

This captures complete file and directory inventories under the existing source
lock. It does not interpret terminal journals, authorize mutation, change native
permissions, or treat historical IDs as current identities. The supported writer
concurrency model is lock-cooperating writers, not hostile same-user POSIX CAS.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import stat
from types import SimpleNamespace

from . import legacy_migration_records as records
from . import local_binding as binding
from .rebind_store_inspection import _NativeStore, RebindStoreInspectionError

MAX_DIRECTORIES = 1024
MAX_DEPTH = 64
_LAYOUT = {
    records.POSIX_MANAGED_V1: ('.naos/upgrade-v1/managed-content', 'lock'),
    records.WINDOWS_CONTENT_V1: ('.naos/upgrade-v1/windows-content', 'transactions/managed-scope.lock'),
}


class LegacyArchiveCaptureError(ValueError):
    """Unsafe source custody, unavailable lock or changing archive inventory."""


def _fail(message):
    raise LegacyArchiveCaptureError(message)


class _Capture(_NativeStore):
    def __init__(self, reader, windows, source_format):
        super().__init__(SimpleNamespace(working_reader=reader), windows)
        self.scope, suffix = _LAYOUT[source_format]
        self.source_format = source_format
        self.lock_path = self.scope + '/' + suffix
        self.directory_witnesses = {}
        self.active = True
        self._captured = False

    def directory(self, relative):
        result = super().directory(relative)
        previous = self.directory_witnesses.setdefault(relative, result)
        if result != previous:
            _fail('Legacy directory identity or protection changed')
        if len(self.directory_witnesses) > MAX_DIRECTORIES:
            _fail('Legacy directory count exceeds capture budget')
        return result

    def children(self, relative, *, final=False):
        self.directory(relative)
        if self.windows:
            key = self.reader.directory(relative)
            names = frozenset(self.reader._names(key).values())
        else:
            with ExitStack() as stack:
                fd = self.reader._walk(relative, stack)
                names = self.reader._scan(fd, relative, final=final)
        if len(names) > records.MAX_ARCHIVE_FILES + MAX_DIRECTORIES:
            _fail('Legacy directory inventory exceeds capture budget')
        if final and names != self.inventories[relative]:
            _fail('Legacy directory inventory changed')
        self.inventories.setdefault(relative, names)
        return names

    def read(self, relative):
        if self.windows:
            parent_path, _, name = relative.rpartition('/')
            parent = self.reader.directory(parent_path)
            # Native opens are case-insensitive. Register the exact source name
            # even for anchors outside the walked scope, so final revalidation
            # also rejects a same-identity case-only rename.
            if parent is None or not self.reader._check_name(parent, name):
                _fail('Required legacy source file spelling is absent')
        return super().read(relative)

    def _budget(self, size):
        if (not 0 <= size <= records.MAX_ARCHIVE_FILE_BYTES
                or size > records.MAX_ARCHIVE_BYTES - self.total_bytes
                or len(self.raw) >= records.MAX_ARCHIVE_FILES):
            _fail('Legacy archive bytes or file count exceed capture budget')

    @contextmanager
    def locked(self):
        self.directory('.naos/upgrade-v1')
        self.directory(self.scope)
        parent_path, _, name = self.lock_path.rpartition('/')
        self.directory(parent_path)
        if self.windows:
            parent = self.reader.directory(parent_path)
            with self.reader.handles.open_child(self.reader.directories[parent], name,
                                               kind='file', for_lock=True) as handle:
                self.lock_witness = self._private(binding.project_windows_witness(handle.info(), handle.security()))
                if handle.info().size:
                    _fail('Legacy scope lock is not empty')
                handle.lock_exclusive(nonblocking=True)
                self.lock_handle = handle
                try:
                    self.check_lock()
                    yield
                    self.check_lock()
                finally:
                    self.lock_handle = None
                    handle.unlock()
        else:
            import fcntl
            stack, _parent, _name, fd, before = self._posix_file(self.lock_path, locking=True)
            with stack:
                if os.fstat(fd).st_size:
                    _fail('Legacy scope lock is not empty')
                self.lock_witness = binding.project_posix_witness(before.metadata)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.lock_handle = fd
                try:
                    self.check_lock()
                    yield
                    self.check_lock()
                finally:
                    self.lock_handle = None
                    fcntl.flock(fd, fcntl.LOCK_UN)

    def check_lock(self):
        if not self.active or self.lock_handle is None:
            _fail('An active held legacy scope lock is required')
        parent_path, _, name = self.lock_path.rpartition('/')
        if self.windows:
            current = self._private(binding.project_windows_witness(
                self.lock_handle.info(), self.lock_handle.security()))
            if current != self.lock_witness or self.lock_handle.info().size:
                _fail('Legacy scope lock identity or bytes changed')
            parent = self.reader.directory(parent_path)
            # Share the write access required by the already-held lock.
            with self.reader.handles.open_child(self.reader.directories[parent], name, kind='file') as reopened:
                if binding.project_windows_witness(reopened.info(), reopened.security()) != current:
                    _fail('Legacy scope lock namespace changed')
        else:
            from .portable_provenance_posix import _witness, _same_namespace
            current = _witness(self.lock_handle, leaf=True, label=self.lock_path)
            if binding.project_posix_witness(current.metadata) != self.lock_witness or os.fstat(self.lock_handle).st_size:
                _fail('Legacy scope lock identity or bytes changed')
            with ExitStack() as stack:
                parent = self.reader._walk(parent_path, stack)
                _same_namespace(parent, name, current, leaf=True, label=self.lock_path)

    def _kind(self, parent_path, name):
        if self.windows:
            from .windows_handles import UnsafeWindowsPath
            parent = self.reader.directory(parent_path)
            try:
                with self.reader.handles.open_child(self.reader.directories[parent], name,
                                                   kind='file', pin_for_read=True):
                    return 'file'
            except UnsafeWindowsPath:
                # Both opens independently enforce no-reparse/stream/metadata
                # guards. A wrong-kind file open is never evidence of a safe dir.
                with self.reader.handles.open_child(self.reader.directories[parent], name,
                                                   kind='directory', pin_for_read=True):
                    return 'directory'
        with ExitStack() as stack:
            parent = self.reader._walk(parent_path, stack)
            observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            return 'directory'
        if stat.S_ISREG(observed.st_mode):
            return 'file'
        _fail('Legacy source contains a link or special object')

    def capture(self):
        self.check_lock()
        if self._captured:
            _fail('A held capture is immutable; open a fresh capture for another observation')
        pending = [self.scope]
        while pending:
            path = pending.pop()
            if path.count('/') > MAX_DEPTH:
                _fail('Legacy directory depth exceeds capture budget')
            for name in sorted(self.children(path)):
                child = path + '/' + name
                records._path(child, self.source_format)
                if child == self.lock_path:
                    self._budget(0)
                    self.raw[child] = b''
                    continue
                if self._kind(path, name) == 'directory':
                    pending.append(child)
                    if len(pending) + len(self.inventories) > MAX_DIRECTORIES:
                        _fail('Legacy directory count exceeds capture budget')
                else:
                    self.read(child)
        if self.source_format == records.POSIX_MANAGED_V1:
            self.read('.naos/upgrade-v1/OWNER.json')
        if not set(records._ANCHORS[self.source_format].values()) <= set(self.raw):
            _fail('Legacy source anchor is absent')
        self._captured = True
        self.revalidate()

    @property
    def archive_bytes(self):
        self.check_lock()
        if not self._captured:
            _fail('Legacy capture is not complete')
        return dict(self.raw)

    @property
    def directory_paths(self):
        self.check_lock()
        return tuple(sorted(self.inventories))

    def revalidate(self):
        self.check_lock()
        for path in self.inventories:
            self.children(path, final=True)
        if self.windows:
            self.reader.revalidate()
        else:
            native = {'control_directories': [{'path': path, 'witness': witness}
                       for path, witness in self.directory_witnesses.items()],
                      'managed_ancestors': []}
            self.reader._final_revalidate(native, list(self.observations.values()))
        self.check_lock()


@contextmanager
def held_legacy_archive(project_root, *, source_format, handles=None):
    """Yield a complete private source capture only while its native lock is held.

    Caller may validate historical records inside this read-only window. No
    mutation is permitted in this context; final revalidation must succeed.
    Returned byte copies are observations, never continuing native authority.
    """
    if type(source_format) is not str or source_format not in _LAYOUT:
        _fail('Unsupported legacy source format')
    native = None
    try:
        with ExitStack() as stack:
            windows = handles is not None or os.name == 'nt'
            if windows:
                from .working_tree_capture_windows import _Capture as Reader
                from .windows_handles import WindowsHandles
                reader = Reader(handles if handles is not None else WindowsHandles(), str(project_root), stack)
            else:
                from .working_tree_capture_posix import _Reader as Reader
                reader = stack.enter_context(Reader(Path(project_root)))
            native = _Capture(reader, windows, source_format)
            with native.locked():
                native.capture()
                yield native
                native.revalidate()
    except LegacyArchiveCaptureError:
        raise
    except (OSError, ValueError, TypeError, RebindStoreInspectionError) as exc:
        raise LegacyArchiveCaptureError(f'Legacy native capture refused: {exc}') from exc
    finally:
        if native is not None:
            native.active = False
