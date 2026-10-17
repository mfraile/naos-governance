"""Pure, versioned identity witness for a recoverable Windows rename.

This module describes what may be observed after a v2 rename. It neither
performs native I/O nor upgrades a legacy five-field journal identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import struct
from typing import Any

from .windows_exchange import LeafIdentity


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX8 = re.compile(r"[0-9a-f]{8}\Z")
_MAX_I64 = (1 << 63) - 1
_MAX_U64 = (1 << 64) - 1
_ATTR_ARCHIVE = 0x20
_ATTR_NORMAL = 0x80
_IDENTITY_KEYS = frozenset({
    "volume_serial_hex", "file_id_hex", "size_bytes", "content_sha256",
    "metadata_sha256", "rename_metadata_v2",
})
_METADATA_KEYS = frozenset({
    "created_100ns_decimal", "last_write_100ns_decimal", "attributes_hex",
    "owner_sid_sha256", "group_sid_sha256", "dacl_sha256",
    "descriptor_sha256", "dacl_protected",
})


def _hex64(value: Any) -> bool:
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _decimal(value: Any, maximum: int, *, positive: bool) -> int:
    if (type(value) is not str or not value or len(value) > len(str(maximum))
            or not value.isascii() or not value.isdecimal()
            or (len(value) > 1 and value[0] == "0")):
        raise ValueError("Invalid canonical decimal")
    number = int(value)
    if number > maximum or (positive and number == 0):
        raise ValueError("Decimal outside supported range")
    return number


def _security_bytes(security: Any) -> tuple[bytes, bytes, bytes, bytes, bool]:
    try:
        owner = security.owner_sid
        group = security.group_sid
        dacl = security.dacl
        descriptor = security.descriptor
        protected = security.protected
    except AttributeError as exc:
        raise ValueError("Incomplete Windows security observation") from exc
    if (type(owner) is not bytes or not 8 <= len(owner) <= 256
            or type(group) is not bytes or not 8 <= len(group) <= 256
            or type(dacl) is not bytes or not 8 <= len(dacl) <= 65535
            or type(descriptor) is not bytes or not 20 <= len(descriptor) <= 131072
            or type(protected) is not bool):
        raise ValueError("Unsupported Windows security observation")
    return owner, group, dacl, descriptor, protected


def _info_fields(info: Any) -> tuple[int, bytes, int, int, int, int]:
    try:
        volume, file_id, size = info.volume, info.file_id, info.size
        created, modified, attributes = (info.created_time, info.modified_time,
                                         info.attributes)
        directory, links, tag = info.directory, info.links, info.reparse_tag
    except AttributeError as exc:
        raise ValueError("Incomplete Windows file observation") from exc
    if (type(volume) is not int or not 0 <= volume <= _MAX_U64
            or type(file_id) is not bytes or len(file_id) != 16
            or type(size) is not int or not 0 <= size <= _MAX_I64
            or type(created) is not int or not 0 < created <= _MAX_I64
            or type(modified) is not int or not 0 < modified <= _MAX_I64
            or type(attributes) is not int or attributes not in {_ATTR_ARCHIVE, _ATTR_NORMAL}
            or type(directory) is not bool or directory
            or type(links) is not int or links != 1
            or type(tag) is not int or tag != 0):
        raise ValueError("Unsupported Windows file observation")
    return volume, file_id, size, created, modified, attributes


def _metadata_digest(created: int, modified: int, attributes: int,
                     security: tuple[bytes, bytes, bytes, bytes, bool]) -> str:
    """Reproduce the v1 backend digest; descriptor is checked separately."""
    owner, group, dacl, _descriptor, protected = security
    digest = hashlib.sha256(b"naos.windows.leaf.metadata.v1\0")
    digest.update(struct.pack("<qqI?", created, modified, attributes, protected))
    for value in (owner, group, dacl):
        digest.update(struct.pack("<I", len(value)))
        digest.update(value)
    return digest.hexdigest()


@dataclass(frozen=True)
class RenameMetadata:
    """Exact authorized metadata and hashes of bounded native security bytes."""

    created_time: int
    modified_time: int
    attributes: int
    owner_sid_sha256: str
    group_sid_sha256: str
    dacl_sha256: str
    descriptor_sha256: str
    protected: bool

    def validate(self) -> None:
        if (type(self.created_time) is not int or not 0 < self.created_time <= _MAX_I64
                or type(self.modified_time) is not int or not 0 < self.modified_time <= _MAX_I64
                or type(self.attributes) is not int
                or self.attributes not in {_ATTR_ARCHIVE, _ATTR_NORMAL}
                or type(self.protected) is not bool
                or not all(_hex64(value) for value in (
                    self.owner_sid_sha256, self.group_sid_sha256,
                    self.dacl_sha256, self.descriptor_sha256))):
            raise ValueError("Invalid v2 rename metadata")


@dataclass(frozen=True)
class RenameIdentity(LeafIdentity):
    """V2 identity; v1 LeafIdentity and its readers stay unchanged."""

    rename_metadata: RenameMetadata

    def validate(self) -> None:
        super().validate()
        if (type(self.volume) is not int or self.volume > _MAX_U64
                or type(self.size) is not int or self.size > _MAX_I64
                or type(self.rename_metadata) is not RenameMetadata):
            raise ValueError("Invalid v2 rename identity")
        self.rename_metadata.validate()


def capture_identity(info: Any, security: Any, content_sha256: str) -> RenameIdentity:
    """Bind a caller's already stable, exact-byte content observation.

    The caller must prove that info/security and the supplied content hash
    describe one pinned, unchanged file. This pure helper cannot prove that.
    """
    volume, file_id, size, created, modified, attributes = _info_fields(info)
    parts = _security_bytes(security)
    owner, group, dacl, descriptor, protected = parts
    metadata = RenameMetadata(
        created, modified, attributes,
        hashlib.sha256(owner).hexdigest(), hashlib.sha256(group).hexdigest(),
        hashlib.sha256(dacl).hexdigest(), hashlib.sha256(descriptor).hexdigest(),
        protected,
    )
    identity = RenameIdentity(volume, file_id, size, content_sha256,
                              _metadata_digest(created, modified, attributes, parts), metadata)
    identity.validate()
    return identity


def identity_record(identity: RenameIdentity) -> dict[str, Any]:
    """Produce one exact v2 journal record, never a v1-compatible record."""
    if type(identity) is not RenameIdentity:
        raise ValueError("V2 record requires RenameIdentity")
    identity.validate()
    witness = identity.rename_metadata
    return {
        "volume_serial_hex": f"{identity.volume:016x}",
        "file_id_hex": identity.file_id.hex(),
        "size_bytes": str(identity.size),
        "content_sha256": identity.content_sha256,
        "metadata_sha256": identity.metadata_sha256,
        "rename_metadata_v2": {
            "created_100ns_decimal": str(witness.created_time),
            "last_write_100ns_decimal": str(witness.modified_time),
            "attributes_hex": f"{witness.attributes:08x}",
            "owner_sid_sha256": witness.owner_sid_sha256,
            "group_sid_sha256": witness.group_sid_sha256,
            "dacl_sha256": witness.dacl_sha256,
            "descriptor_sha256": witness.descriptor_sha256,
            "dacl_protected": witness.protected,
        },
    }


def identity_from_record(record: Any) -> RenameIdentity:
    """Decode strict v2 syntax; native bytes must validate its hashes later."""
    if type(record) is not dict or set(record) != _IDENTITY_KEYS:
        raise ValueError("Invalid v2 rename identity fields")
    nested = record["rename_metadata_v2"]
    if type(nested) is not dict or set(nested) != _METADATA_KEYS:
        raise ValueError("Invalid v2 rename metadata fields")
    volume, file_id, attributes = (record["volume_serial_hex"], record["file_id_hex"],
                                   nested["attributes_hex"])
    if (type(volume) is not str or _HEX16.fullmatch(volume) is None
            or type(file_id) is not str or _HEX32.fullmatch(file_id) is None
            or type(attributes) is not str or _HEX8.fullmatch(attributes) is None):
        raise ValueError("Invalid v2 rename hexadecimal encoding")
    witness = RenameMetadata(
        _decimal(nested["created_100ns_decimal"], _MAX_I64, positive=True),
        _decimal(nested["last_write_100ns_decimal"], _MAX_I64, positive=True),
        int(attributes, 16), nested["owner_sid_sha256"],
        nested["group_sid_sha256"], nested["dacl_sha256"],
        nested["descriptor_sha256"], nested["dacl_protected"],
    )
    identity = RenameIdentity(
        int(volume, 16), bytes.fromhex(file_id),
        _decimal(record["size_bytes"], _MAX_I64, positive=False),
        record["content_sha256"], record["metadata_sha256"], witness,
    )
    identity.validate()
    return identity


def matches_observation(expected: RenameIdentity, info: Any, security: Any,
                        content_sha256: str, allow_pending: bool = False) -> bool:
    """Compare exact identity or the two narrow, v2-authorized rename transients.

    Pending means creation time may change and NORMAL may become ARCHIVE.
    It never establishes why they changed or authorizes an actual repair.
    """
    if type(allow_pending) is not bool:
        raise ValueError("allow_pending must be bool")
    if type(expected) is not RenameIdentity:
        raise ValueError("Expected v2 rename identity")
    expected.validate()
    try:
        volume, file_id, size, created, modified, attributes = _info_fields(info)
        owner, group, dacl, descriptor, protected = _security_bytes(security)
    except ValueError:
        return False
    witness = expected.rename_metadata
    if ((volume, file_id, size, content_sha256) != (
            expected.volume, expected.file_id, expected.size, expected.content_sha256)
            or modified != witness.modified_time or protected != witness.protected
            or hashlib.sha256(owner).hexdigest() != witness.owner_sid_sha256
            or hashlib.sha256(group).hexdigest() != witness.group_sid_sha256
            or hashlib.sha256(dacl).hexdigest() != witness.dacl_sha256
            or hashlib.sha256(descriptor).hexdigest() != witness.descriptor_sha256):
        return False
    parts = owner, group, dacl, descriptor, protected
    if _metadata_digest(witness.created_time, witness.modified_time,
                        witness.attributes, parts) != expected.metadata_sha256:
        return False
    if not allow_pending:
        return created == witness.created_time and attributes == witness.attributes
    return (attributes == witness.attributes
            or (witness.attributes == _ATTR_NORMAL and attributes == _ATTR_ARCHIVE))
