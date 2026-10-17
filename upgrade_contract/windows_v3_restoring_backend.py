"""V3-only exact ACL repair for a precommitted cross-parent rename witness.

The coordinator must persist and bind the supplied security witnesses before
any move. This backend neither creates that authority nor publishes a checkpoint.
V1 and V2 retain their existing strict security comparison.
"""
from __future__ import annotations

import ctypes
from typing import Mapping

from .windows_exchange import ExchangeConflict
from .windows_handles import (DACL_SECURITY_INFORMATION, HANDLE,
                              PROTECTED_DACL_SECURITY_INFORMATION,
                              UNPROTECTED_DACL_SECURITY_INFORMATION)
from .windows_rename_identity import RenameIdentity, matches_observation
from .windows_restoring_backend import WindowsRestoringBackend, _capture
from .windows_v3_security_witness import decode_security_witness


class WindowsV3RestoringBackend(WindowsRestoringBackend):
    """Repair only an exact recorded security descriptor or its one admitted transient."""

    def __init__(self, handles, slot_paths, *, security_witnesses: Mapping[str, bytes]):
        if (type(security_witnesses) is not dict or not security_witnesses
                or any(type(k) is not str or type(v) is not bytes
                       for k, v in security_witnesses.items())):
            raise ValueError('V3 requires immutable encoded security witnesses')
        self._security_witnesses = dict(security_witnesses)
        super().__init__(handles, slot_paths)

    def _security(self, expected):
        if type(expected) is not RenameIdentity:
            raise ValueError('V3 requires an exact recorded rename identity')
        expected.validate()
        try:
            raw = self._security_witnesses[expected.file_id.hex()]
        except KeyError:
            raise ExchangeConflict('Missing precommitted V3 security witness') from None
        return decode_security_witness(raw, expected)

    def pending_matches(self, slot: str, expected: RenameIdentity) -> bool:
        original, transient = self._security(expected)
        bound = self._slot(slot)
        with self._handles.open_child(bound.parent, bound.name,
                                      kind='file', pin_for_read=True) as held:
            actual, info, security = _capture(held)
            result = (security in (original, transient) and
                      matches_observation(expected, info, original,
                                          actual.content_sha256, allow_pending=True))
        self._slot(slot)
        return result

    def restore_pending(self, source: str, destination: str,
                        expected: RenameIdentity) -> None:
        original, transient = self._security(expected)
        if source == destination:
            raise ValueError('V3 repair requires distinct slots')
        if self.observe(source) is not None:
            raise ExchangeConflict('Pending V3 source is not absent')
        src, dst = self._slot(source), self._slot(destination)
        if src.parent_identity[0] != dst.parent_identity[0]:
            raise ExchangeConflict('Cross-volume V3 repair is forbidden')
        # WRITE_DAC and a no-write/no-delete sharing pin are narrowly scoped to
        # this leaf. Time/attribute restoration uses the existing separate mode.
        with self._handles.open_child(dst.parent, dst.name, kind='file',
                                      for_security_copy=True) as held:
            actual, info, security = _capture(held)
            if (security not in (original, transient) or
                    not matches_observation(expected, info, original,
                                            actual.content_sha256, allow_pending=True)):
                raise ExchangeConflict('Pending V3 file differs from exact repair authority')
            if security != original and src.parent_identity == dst.parent_identity:
                raise ExchangeConflict('ACL transient is not admitted for a same-parent move')
            if self.observe(source) is not None:
                raise ExchangeConflict('Pending V3 source reappeared')
            self._slot(source)
            self._slot(destination)
            if security != original:
                descriptor = ctypes.create_string_buffer(original.descriptor)
                protection = (PROTECTED_DACL_SECURITY_INFORMATION if original.protected
                              else UNPROTECTED_DACL_SECURITY_INFORMATION)
                status = held._ops.ntdll.NtSetSecurityObject(
                    held.value, DACL_SECURITY_INFORMATION | protection,
                    ctypes.cast(descriptor, HANDLE))
                held._ops._check_nt(status, 'NtSetSecurityObject(v3 recorded rename)')
                restored, after, observed = _capture(held)
                if (observed != original or not matches_observation(
                        expected, after, observed, restored.content_sha256,
                        allow_pending=True)):
                    raise ExchangeConflict('V3 security restoration differs while pinned')
        # The strict V2 repair now sees the exact original security, and performs
        # its existing time/attribute and post-close full-identity checks.
        super().restore_pending(source, destination, expected)

    def move_exact(self, source: str, destination: str, expected: RenameIdentity) -> None:
        # Validate authority before invoking the first native mutation. The base
        # move dispatches to this class's bounded restore_pending after rename.
        self._security(expected)
        super().move_exact(source, destination, expected)
