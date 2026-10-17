"""Windows operation-v2 rename with recorded, narrowly bounded metadata repair.

Generic v1 exchange remains strict. Only an operation with a persisted v2
witness may reconcile an interrupted move through ``restore_pending``.
"""
from __future__ import annotations

from typing import Any

from .windows_backend import WindowsExchangeBackend, _MISSING_LEAF, _observe_pinned
from .windows_exchange import ExchangeConflict
from .windows_handles import WindowsHandleError
from .windows_rename_identity import RenameIdentity, capture_identity, matches_observation


def _capture(held: Any) -> tuple[RenameIdentity, Any, Any]:
    info, security = held.info(), held.security()
    leaf = _observe_pinned(held)
    if held.info() != info or held.security() != security:
        raise ExchangeConflict('Rename witness changed during capture')
    result = capture_identity(info, security, leaf.content_sha256)
    if result.metadata_sha256 != leaf.metadata_sha256:
        raise ExchangeConflict('Rename witness does not match opaque identity')
    return result, info, security


class WindowsRestoringBackend(WindowsExchangeBackend):
    """No-replace move, close, bounded metadata restore, close, exact reobserve."""

    def observe(self, slot: str) -> RenameIdentity | None:
        bound = self._slot(slot)
        try:
            opened = self._handles.open_child(bound.parent, bound.name,
                                              kind='file', pin_for_read=True)
        except WindowsHandleError as exc:
            if exc.operation == 'NtCreateFile' and exc.ntstatus == _MISSING_LEAF:
                return None
            raise
        with opened:
            result, _info, _security = _capture(opened)
        self._slot(slot)
        return result

    def pending_matches(self, slot: str, expected: RenameIdentity) -> bool:
        expected.validate()
        bound = self._slot(slot)
        with self._handles.open_child(bound.parent, bound.name,
                                      kind='file', pin_for_read=True) as held:
            actual, info, security = _capture(held)
            result = matches_observation(expected, info, security,
                                         actual.content_sha256, allow_pending=True)
        self._slot(slot)
        return result

    def restore_pending(self, source: str, destination: str,
                        expected: RenameIdentity) -> None:
        if type(expected) is not RenameIdentity or source == destination:
            raise ValueError('Restoration requires an operation-v2 identity and distinct slots')
        expected.validate()
        if self.observe(source) is not None:
            raise ExchangeConflict('Pending rename source is not absent')
        source_slot, destination_slot = self._slot(source), self._slot(destination)
        if source_slot.parent_identity[0] != destination_slot.parent_identity[0]:
            raise ExchangeConflict('Cross-volume restoration is forbidden')
        with self._handles.open_child(destination_slot.parent, destination_slot.name,
                                      kind='file', for_metadata_restore=True) as held:
            actual, info, security = _capture(held)
            if not matches_observation(expected, info, security,
                                       actual.content_sha256, allow_pending=True):
                raise ExchangeConflict('Pending rename differs from recorded repair authority')
            if self.observe(source) is not None:
                raise ExchangeConflict('Pending rename source reappeared')
            self._slot(source)
            self._slot(destination)
            if actual != expected:
                metadata = expected.rename_metadata
                self._handles.restore_rename_metadata(
                    held, creation_time=metadata.created_time,
                    attributes=metadata.attributes)
                restored, _info, _security = _capture(held)
                if restored != expected:
                    raise ExchangeConflict('Metadata restoration differs while handle is held')
        # Closing the rename handle itself can set ARCHIVE. No success/marker
        # is permitted until the restoration handle is also closed and checked.
        if self.observe(source) is not None or self.observe(destination) != expected:
            raise ExchangeConflict('Post-close restored rename differs; retain objects')

    def move_exact(self, source: str, destination: str, expected: RenameIdentity) -> None:
        if type(expected) is not RenameIdentity or source == destination:
            raise ValueError('Operation-v2 move requires a recorded rename witness')
        expected.validate()
        source_slot, destination_slot = self._slot(source), self._slot(destination)
        if source_slot.parent_identity[0] != destination_slot.parent_identity[0]:
            raise ExchangeConflict('Cross-volume exchange is forbidden')
        if self.observe(destination) is not None:
            raise ExchangeConflict('Exchange destination already exists')
        with self._handles.open_child(source_slot.parent, source_slot.name,
                                      kind='file', for_rename=True) as held:
            actual, _info, _security = _capture(held)
            if actual != expected:
                raise ExchangeConflict('Exchange source differs from recorded rename witness')
            self._slot(source)
            self._slot(destination)
            self._handles.rename_no_replace(held, destination_slot.parent, destination_slot.name)
        self.restore_pending(source, destination, expected)
