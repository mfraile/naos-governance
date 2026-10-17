"""Current legacy pins with separate, closed immutable receiving read lanes.

Historical plans never supply current root or lock authority. This custody only
preserves freshly observed legacy evidence; the receiving/history inspectors
must still prove the complete semantics before granting any mutation authority.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path

from .legacy_migration_custody import _Custody, _PosixCustodyReader
from .legacy_migration_source_state import _ActualSource


class _CurrentLegacy:
    def __init__(self, root, custody, source_format):
        self.root, self.custody, self.source_format = root, custody, source_format
        self.reader, self.windows = custody.reader, custody.windows
        self.scope, self.lock_path = custody.scope, custody.lock_path
        self._baseline = None

    @property
    def lock_handle(self):
        return self.custody.lock_handle

    @property
    def lock_witness(self):
        return deepcopy(self.custody.lock_witness)

    @property
    def raw(self):
        return dict(self._baseline['raw'])

    @property
    def observations(self):
        return deepcopy(self._baseline['observations'])

    @property
    def directory_witnesses(self):
        return deepcopy(self._baseline['directories'])

    @property
    def inventories(self):
        return dict(self._baseline['inventories'])

    def children(self, path):
        self.revalidate()
        return self._baseline['inventories'][path]

    def _check_pins(self):
        self.custody.check_lock()
        if self.windows:
            from .v3_operation_custody import _windows_check
            _windows_check(self.reader)

    def check_lock(self):
        """Check continuous current custody; full evidence proof is explicit."""
        self._check_pins()

    def _fresh(self):
        """Borrow the real legacy lock, fully validate, then close all reads."""
        self._check_pins()
        actual = None
        try:
            with ExitStack() as stack:
                if self.windows:
                    from .working_tree_capture_windows import _Capture
                    reader = _Capture(self.reader.handles, str(self.root), stack)
                else:
                    from .working_tree_capture_posix import _Reader
                    reader = stack.enter_context(_Reader(Path(self.root)))
                actual = _ActualSource(reader, self.windows, self.source_format)
                actual.lock_handle, actual.lock_witness = self.lock_handle, self.lock_witness
                actual.scan_actual()
                # Complete immediate inventory also detects unknown/competing
                # legacy scopes; it is current evidence, not a historical map.
                actual.children('.naos/upgrade-v1')
                facts = {'raw': dict(actual.raw), 'observations': deepcopy(actual.observations),
                         'directories': deepcopy(actual.directory_witnesses),
                         'inventories': dict(actual.inventories)}
                actual.revalidate()
            self._check_pins()
            return facts
        finally:
            if actual is not None:
                actual.active = False

    def revalidate(self):
        facts = self._fresh()
        if self._baseline is None:
            self._baseline = facts
        elif facts != self._baseline:
            raise ValueError('Current receiving legacy evidence changed during custody')

    def mirror_owned_root(self, before, after):
        """Mirror only the caller's already proved exact own root transition."""
        if self.windows:
            raise ValueError('POSIX own-root mirror cannot select Windows custody')
        from .portable_provenance_posix import _witness, _same_namespace
        reader = self.reader.reader
        label, parent, name, fd, original = reader.chain[-1]
        if original.stat_fields != before.stat_fields or original.metadata != before.metadata:
            raise ValueError('Receiving legacy root differs from exact pre-move witness')
        observed = _witness(fd, leaf=False, label=label)
        if observed.stat_fields != after.stat_fields or observed.metadata != after.metadata:
            raise ValueError('Receiving legacy root differs from exact proved own move')
        _same_namespace(parent, name, observed, leaf=False, label=label)
        reader.chain[-1] = (label, parent, name, fd, observed)


@contextmanager
def held_current_legacy(root, *, windows, source_format, handles=None):
    """Hold current legacy custody before the caller acquires its local lock."""
    custody = None
    try:
        with ExitStack() as stack:
            if windows:
                from .working_tree_capture_windows import _Capture
                from .windows_handles import WindowsHandles
                reader = _Capture(handles if handles is not None else WindowsHandles(), str(root), stack)
            else:
                reader = _PosixCustodyReader(root, source_format, stack)
            # No historical approved plan is passed or relabelled. Only the
            # existing current-root/private-ancestor/lock primitive is borrowed.
            custody = _Custody(reader, windows, source_format, None)
            with custody.locked():
                current = _CurrentLegacy(root, custody, source_format)
                current.revalidate()
                yield current
                current.revalidate()
    finally:
        if custody is not None:
            custody.active = False
