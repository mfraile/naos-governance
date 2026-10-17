"""Internal operation-v1 NORMAL restoration; generic exchange stays strict.

Only the operation's outstanding step and held full-topology audit authorize
repair. V1 binds owner/group/DACL/protection, not historical descriptor bytes.
"""
from __future__ import annotations

from dataclasses import replace
from .windows_backend import WindowsExchangeBackend, _observe_pinned, _metadata_digest
from .windows_exchange import ExchangeConflict, LeafIdentity


def _capture(held):
    info, security = held.info(), held.security()
    actual = _observe_pinned(held)
    if held.info() != info or held.security() != security:
        raise ExchangeConflict('V1 metadata changed during stable capture')
    return actual, info, security


def _matches(expected, actual, info, security):
    if type(expected) is not LeafIdentity:
        raise ValueError('V1 restoration requires the persisted LeafIdentity')
    expected.validate()
    if actual == expected:
        return True
    return (info.attributes == 0x20
        and (actual.volume, actual.file_id, actual.size, actual.content_sha256)
        == (expected.volume, expected.file_id, expected.size, expected.content_sha256)
        and _metadata_digest(replace(info, attributes=0x80), security)
        == expected.metadata_sha256)


class _WindowsV1RestoringBackend(WindowsExchangeBackend):
    """Operation-internal mechanism; observation never repairs any metadata."""

    def pending_matches(self, slot, expected):
        bound = self._slot(slot)
        with self._handles.open_child(bound.parent, bound.name,
                kind='file', pin_for_read=True) as held:
            actual, info, security = _capture(held)
            result = _matches(expected, actual, info, security)
        self._slot(slot)
        return result

    def move_exact(self, source, destination, expected):
        if type(expected) is not LeafIdentity or source == destination:
            raise ValueError('V1 move requires its persisted identity and distinct slots')
        expected.validate()
        src, dst = self._slot(source), self._slot(destination)
        if src.parent_identity[0] != dst.parent_identity[0]:
            raise ExchangeConflict('Cross-volume v1 move is forbidden')
        if self.observe(destination) is not None:
            raise ExchangeConflict('V1 destination already exists')
        with self._handles.open_child(src.parent, src.name,
                kind='file', for_rename=True) as held:
            if _observe_pinned(held) != expected:
                raise ExchangeConflict('V1 move source differs from persisted identity')
            self._slot(source)
            self._slot(destination)
            self._handles.rename_no_replace(held, dst.parent, dst.name)
        # No setter here: the operation must audit all journals and slots first.
        if self.observe(source) is not None or not self.pending_matches(destination, expected):
            raise ExchangeConflict('V1 move differs from finite pending witness')

    def restore_pending(self, source, destination, expected, *, audit):
        if type(expected) is not LeafIdentity or source == destination or not callable(audit):
            raise ValueError('V1 repair requires an operation-owned held topology audit')
        expected.validate()
        if self.observe(source) is not None:
            raise ExchangeConflict('V1 pending source is not absent')
        src, dst = self._slot(source), self._slot(destination)
        if src.parent_identity[0] != dst.parent_identity[0]:
            raise ExchangeConflict('Cross-volume v1 repair is forbidden')
        with self._handles.open_child(dst.parent, dst.name,
                kind='file', for_metadata_restore=True) as held:
            actual, info, security = _capture(held)
            if not _matches(expected, actual, info, security):
                raise ExchangeConflict('V1 pending metadata differs from finite authority')
            if self.observe(source) is not None:
                raise ExchangeConflict('V1 pending source reappeared')
            self._slot(source)
            self._slot(destination)
            audit(actual)  # Full operation proof immediately before the setter.
            if actual != expected:
                self._handles.restore_rename_metadata(held,
                    creation_time=info.created_time, attributes=0x80)
                restored, _info, restored_security = _capture(held)
                if restored != expected or restored_security != security:
                    raise ExchangeConflict('V1 held restoration differs from original witness')
        if self.observe(source) is not None or self.observe(destination) != expected:
            raise ExchangeConflict('V1 post-close restoration differs; retain objects')
