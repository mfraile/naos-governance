"""Exact Windows v3 cross-parent ACL transient witness.

This codec does not authorize a rename or repair. A native caller must still
prove the exact source/destination topology and file identity while held.
"""
from __future__ import annotations

import base64
import hashlib
import struct

from .canonical import canonical_bytes, loads_strict_json
from .windows_handles import SecurityParts
from .windows_rename_identity import RenameIdentity, identity_record

SCHEMA = "naos.upgrade.v3_cross_parent_acl_witness.v1"
MAX_DESCRIPTOR = 131072
MAX_WITNESS = 256000
_DACL_PRESENT = 0x0004
_SACL_PRESENT = 0x0010
_DACL_PROTECTED = 0x1000
_SELF_RELATIVE = 0x8000
_INHERITED_ACE = 0x10


class SecurityWitnessError(ValueError):
    pass


def _fail(message: str):
    raise SecurityWitnessError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sid(descriptor: bytes, offset: int) -> tuple[bytes, tuple[int, int]]:
    if offset < 20 or offset % 4 or offset + 8 > len(descriptor):
        _fail("Malformed self-relative SID offset")
    revision, count = descriptor[offset], descriptor[offset + 1]
    if revision != 1 or count > 15:
        _fail("Unsupported SID revision or subauthority count")
    end = offset + 8 + 4 * count
    if end > len(descriptor):
        _fail("Truncated self-relative SID")
    return descriptor[offset:end], (offset, end)


def _dacl(descriptor: bytes, offset: int) -> tuple[bytes, tuple[int, int], tuple[int, ...]]:
    if offset < 20 or offset % 4 or offset + 8 > len(descriptor):
        _fail("Malformed self-relative DACL offset")
    revision, reserved, size, count, reserved2 = struct.unpack_from("<BBHHH", descriptor, offset)
    if revision not in (2, 4) or reserved or reserved2 or not 8 <= size <= 65535:
        _fail("Unsupported ACL header")
    end = offset + size
    if end > len(descriptor):
        _fail("Truncated self-relative DACL")
    cursor = offset + 8
    flags = []
    for _ in range(count):
        if cursor + 4 > end:
            _fail("Truncated ACE header")
        ace_type, _ace_flags, ace_size = struct.unpack_from("<BBH", descriptor, cursor)
        # The initial v3 variant admits ordinary allow/deny ACEs only. Other
        # layouts can be added after separate native evidence, never guessed.
        if ace_type not in (0, 1) or ace_size < 8 or ace_size % 4 or cursor + ace_size > end:
            _fail("Unsupported or malformed ACE")
        ace_sid, sid_range = _sid(descriptor, cursor + 8)
        if sid_range[1] != cursor + ace_size or len(ace_sid) != ace_size - 8:
            _fail("Unsupported ACE SID body")
        flags.append(cursor + 1)
        cursor += ace_size
    if cursor != end:
        _fail("ACL trailing bytes or ACE count differs")
    return descriptor[offset:end], (offset, end), tuple(flags)


def _security_from_descriptor(descriptor: bytes) -> tuple[SecurityParts, tuple[int, ...]]:
    if type(descriptor) is not bytes or not 20 <= len(descriptor) <= MAX_DESCRIPTOR:
        _fail("Invalid descriptor byte length")
    revision, reserved, control, owner_at, group_at, sacl_at, dacl_at = struct.unpack_from(
        "<BBHLLLL", descriptor)
    if (revision != 1 or reserved or control & (_SELF_RELATIVE | _DACL_PRESENT)
            != (_SELF_RELATIVE | _DACL_PRESENT) or control & _SACL_PRESENT or sacl_at):
        _fail("Unsupported descriptor control or SACL")
    owner, owner_range = _sid(descriptor, owner_at)
    group, group_range = _sid(descriptor, group_at)
    dacl, dacl_range, flag_offsets = _dacl(descriptor, dacl_at)
    ranges = (owner_range, group_range, dacl_range)
    for i, first in enumerate(ranges):
        for second in ranges[i + 1:]:
            if first != second and max(first[0], second[0]) < min(first[1], second[1]):
                _fail("Overlapping descriptor components")
    if (max(owner_range[0], dacl_range[0]) < min(owner_range[1], dacl_range[1]) or
            max(group_range[0], dacl_range[0]) < min(group_range[1], dacl_range[1])):
        _fail("DACL overlaps SID")
    return SecurityParts(owner, group, dacl, bool(control & _DACL_PROTECTED), descriptor), flag_offsets


def _bound_original(expected: RenameIdentity, security: SecurityParts) -> None:
    if type(expected) is not RenameIdentity or type(security) is not SecurityParts:
        _fail("Exact v2 identity and native security are required")
    expected.validate()
    meta = expected.rename_metadata
    if (_sha(security.owner_sid) != meta.owner_sid_sha256 or
            _sha(security.group_sid) != meta.group_sid_sha256 or
            _sha(security.dacl) != meta.dacl_sha256 or
            _sha(security.descriptor) != meta.descriptor_sha256 or
            security.protected != meta.protected):
        _fail("Original descriptor differs from recorded rename identity")


def _derive(expected: RenameIdentity, descriptor: bytes) -> tuple[SecurityParts, SecurityParts]:
    original, offsets = _security_from_descriptor(descriptor)
    _bound_original(expected, original)
    changed = bytearray(descriptor)
    if not original.protected:
        for offset in offsets:
            changed[offset] &= ~_INHERITED_ACE
    transient, _ = _security_from_descriptor(bytes(changed))
    if (transient.owner_sid != original.owner_sid or transient.group_sid != original.group_sid
            or transient.protected != original.protected):
        _fail("Transient changed unrelated security")
    return original, transient


def encode_security_witness(expected: RenameIdentity, security: SecurityParts) -> bytes:
    """Commit exact original descriptor and one deterministic ACL transient."""
    if type(security) is not SecurityParts:
        _fail("Exact native SecurityParts required")
    original, transient = _derive(expected, security.descriptor)
    if security != original:
        _fail("Observed native security differs from descriptor components")
    body = {
        "schema": SCHEMA,
        "rename_identity": identity_record(expected),
        "original_descriptor_base64": base64.b64encode(original.descriptor).decode("ascii"),
        "transient_dacl_sha256": _sha(transient.dacl),
        "transient_descriptor_sha256": _sha(transient.descriptor),
    }
    raw = canonical_bytes(body)
    if len(raw) > MAX_WITNESS:
        _fail("Security witness exceeds byte budget")
    return raw


def decode_security_witness(raw: bytes, expected: RenameIdentity) -> tuple[SecurityParts, SecurityParts]:
    """Recompute the original and permitted transient from exact record bytes."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_WITNESS:
        _fail("Invalid security witness byte length")
    try:
        body = loads_strict_json(raw)
    except ValueError as exc:
        raise SecurityWitnessError("Malformed security witness JSON") from exc
    if (type(body) is not dict or set(body) != {"schema", "rename_identity",
            "original_descriptor_base64", "transient_dacl_sha256",
            "transient_descriptor_sha256"} or body["schema"] != SCHEMA or
            body["rename_identity"] != identity_record(expected) or
            canonical_bytes(body) != raw):
        _fail("Security witness schema, identity, or canonical bytes differ")
    encoded = body["original_descriptor_base64"]
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_DESCRIPTOR + 2) // 3):
        _fail("Invalid descriptor encoding")
    try:
        descriptor = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SecurityWitnessError("Malformed descriptor base64") from exc
    if base64.b64encode(descriptor).decode("ascii") != encoded:
        _fail("Noncanonical descriptor base64")
    original, transient = _derive(expected, descriptor)
    if (_sha(transient.dacl) != body["transient_dacl_sha256"] or
            _sha(transient.descriptor) != body["transient_descriptor_sha256"]):
        _fail("Transient security commitment differs")
    return original, transient
