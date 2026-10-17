"""Fresh immutable observation of the *actual* legacy source namespace.

The active pointer may contain the original, the fence, or be absent. This
module does not invent a historical pointer or authorize any write. Its caller
must validate journal history and classify the actual native state separately.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import legacy_archive_capture as capture
from . import legacy_migration_custody as custody_module
from . import legacy_migration_records as records


class ActualSourceSnapshotError(ValueError):
    """The actual source inventory or immutable read lane could not be held."""


class _ActualSource(capture._Capture):
    """Reuse bounded native capture primitives without original-anchor rules."""

    def __init__(self, reader, windows, source_format):
        super().__init__(reader, windows, source_format)
        self._tracked_stores = []

    def scan_actual(self):
        """Read every current source object exactly as it exists now."""
        self.check_lock()
        if self._captured:
            raise ActualSourceSnapshotError('Actual source scan is immutable')
        for path in ('.naos/upgrade-v1', self.scope,
                     self.lock_path.rpartition('/')[0]):
            self.directory(path)
        pending = [self.scope]
        while pending:
            path = pending.pop()
            if path.count('/') > capture.MAX_DEPTH:
                raise ActualSourceSnapshotError('Legacy source directory depth exceeds budget')
            for name in sorted(self.children(path)):
                child = path + '/' + name
                records._path(child, self.source_format)
                if child == self.lock_path:
                    self.check_lock()  # proves the same held, empty lock object
                    self._budget(0)
                    self.raw[child] = b''
                elif self._kind(path, name) == 'directory':
                    pending.append(child)
                    if len(pending) + len(self.inventories) > capture.MAX_DIRECTORIES:
                        raise ActualSourceSnapshotError('Legacy source directory count exceeds budget')
                else:
                    self.read(child)
        if self.source_format == records.POSIX_MANAGED_V1:
            # This shared source anchor lies outside the managed-content scope.
            # Its current bytes are observed, without demanding an old schema.
            self.read('.naos/upgrade-v1/OWNER.json')
        self._captured = True
        self.revalidate()

    def track_store(self, native):
        """Include later same-reader local observations in final validation."""
        if native.reader is not self.reader or native in self._tracked_stores:
            raise ActualSourceSnapshotError('Tracked store must share this immutable reader')
        self._tracked_stores.append(native)

    def revalidate(self):
        """Recheck actual source and all attached local observations."""
        self.check_lock()
        for path in self.inventories:
            self.children(path, final=True)
        additional = []
        for native in self._tracked_stores:
            for path in native.inventories:
                native.children(path, final=True)
            additional.extend(native.observations.values())
        if self.windows:
            # The Windows reader also checks every file opened through it.
            self.reader.revalidate()
        else:
            native = {'control_directories': [{'path': path, 'witness': witness}
                       for path, witness in self.directory_witnesses.items()],
                      'managed_ancestors': []}
            self.reader._final_revalidate(native,
                list(self.observations.values()) + additional)
        self.check_lock()


@contextmanager
def _actual_source_snapshot(legacy, local):
    """Borrow both locks for one complete actual-state read, then close it.

    `actual.raw` contains only actual paths. Missing source pointer stays missing;
    a present successor retains its own actual bytes and native observation.
    Call `actual.track_store(native)` for each same-reader local journal reader
    used inside the context, so its observations join final revalidation.
    """
    if (type(legacy) is not custody_module._Custody or legacy.snapshot_active
            or local is None):
        raise ActualSourceSnapshotError('Separate held legacy and local custody required')
    legacy.check_root()
    legacy.check_lock()
    local.check_lock()
    legacy.snapshot_active = True
    actual = None
    try:
        with ExitStack() as read_stack:
            if legacy.windows:
                from .working_tree_capture_windows import _Capture as Reader
                reader = Reader(legacy.reader.handles, legacy.reader.root, read_stack)
            else:
                from .working_tree_capture_posix import _Reader as Reader
                reader = read_stack.enter_context(Reader(Path(legacy.reader.root_path)))
            actual = _ActualSource(reader, legacy.windows,
                                   legacy._approved_plan.body['source_format'])
            actual.lock_handle = legacy.lock_handle
            actual.lock_witness = legacy.lock_witness
            actual.scan_actual()
            try:
                yield actual
            finally:
                try:
                    actual.revalidate()
                finally:
                    actual.active = False
    finally:
        if actual is not None:
            actual.active = False
        legacy.snapshot_active = False
        legacy.check_root()
        legacy.check_lock()
        local.check_lock()
