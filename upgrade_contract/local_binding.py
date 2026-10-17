"""Pure v3 local binding and platform-specific continuity witnesses.

This codec establishes internal consistency, not ownership or native read safety.
A future held native reader must validate observations and exact journal bytes.
"""

from __future__ import annotations

import base64
import hashlib
import ntpath
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import CanonicalizationError, canonical_bytes
from .linux_primitives import FS_INDEX_FL, KERNEL_LAYOUT_FLAGS
from .portable_provenance import (
    PortableProvenanceError,
    ValidatedPortableSnapshot,
    _load_json,
    _path,
    _unique_paths,
)
from .security import (
    ContentPathError,
    supported_metadata_flags,
    validate_created_metadata_identity,
)
from .windows_handles import (
    FILE_ATTRIBUTE_DIRECTORY,
    HandleInfo,
    SecurityParts,
    SUPPORTED_DIRECTORY_ATTRIBUTES,
    SUPPORTED_FILE_ATTRIBUTES,
    UnsafeWindowsPath,
    validate_root_path,
)

BINDING_SCHEMA = "naos.upgrade.local_binding.v1"
OBSERVATION_SCHEMA = "naos.upgrade.local_observation.v1"
POSIX_WITNESS_SCHEMA = "naos.upgrade.posix_local_witness.v1"
WINDOWS_WITNESS_SCHEMA = "naos.upgrade.windows_local_witness.v1"
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_LEAVES = 10_000
MAX_ANCESTORS = 20_000
MAX_JOURNALS = 10_000
MAX_ROOT_COMPONENTS = 128
MAX_XATTRS = 256
MAX_ACL_ENTRIES = 256
MAX_DIAGNOSTIC_BYTES = 32
MAX_PATH_COMPONENTS = 128
MAX_TOTAL_PATH_COMPONENTS = 100_000
MAX_JSON_TOKENS = 250_000
MAX_JSON_DEPTH = 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX8 = re.compile(r"[0-9a-f]{8}\Z")
OCTAL4 = re.compile(r"[0-7]{4}\Z")
JOURNAL_ID = re.compile(r"J[0-9]{8}\Z")
BINDING_ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_U64 = (1 << 64) - 1
CONTROL_DIRECTORIES = (
    ".naos",
    ".naos/local",
    ".naos/local/managed-content-v3",
    ".naos/local/managed-content-v3/journals",
)


class LocalBindingError(ValueError):
    """Malformed binding, unsupported witness, or failed comparison precondition."""


def _fail(message: str) -> None:
    raise LocalBindingError(message)


def _fields(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(keys) or set(value) != keys:
        _fail(f"Invalid {label} fields")
    return value


def _bounded_input(value: Any) -> None:
    """Refuse wide/deep/large Python records before canonical serialization."""
    stack = [(value, 0)]
    tokens = estimated_bytes = 0
    while stack:
        current, depth = stack.pop()
        tokens += 1
        estimated_bytes += 8
        if (
            tokens > MAX_JSON_TOKENS
            or depth > MAX_JSON_DEPTH
            or estimated_bytes > MAX_RECORD_BYTES
        ):
            _fail("Local record exceeds structural or byte budget")
        if type(current) is dict:
            if len(current) > MAX_JSON_TOKENS - tokens - len(stack):
                _fail("Local record exceeds structural budget")
            for key, item in current.items():
                if type(key) is not str:
                    _fail("Local record has nontext key")
                if len(key) > MAX_RECORD_BYTES - estimated_bytes:
                    _fail("Local record exceeds byte budget")
                try:
                    estimated_bytes += len(key.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise LocalBindingError("Invalid local record Unicode") from exc
                if estimated_bytes > MAX_RECORD_BYTES:
                    _fail("Local record exceeds byte budget")
                stack.append((item, depth + 1))
        elif type(current) is list:
            if len(current) > MAX_JSON_TOKENS - tokens - len(stack):
                _fail("Local record exceeds structural budget")
            stack.extend((item, depth + 1) for item in current)
        elif type(current) is str:
            if len(current) > MAX_RECORD_BYTES - estimated_bytes:
                _fail("Local record exceeds byte budget")
            try:
                estimated_bytes += len(current.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise LocalBindingError("Invalid local record Unicode") from exc
        elif current is not None and type(current) is not bool:
            _fail("Local record contains unsupported value type")
        if estimated_bytes > MAX_RECORD_BYTES:
            _fail("Local record exceeds byte budget")


def _hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(f"Invalid {label}")
    return value


def _u64(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 20
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value[0] == "0")
    ):
        _fail(f"Invalid {label} decimal")
    if int(value) > MAX_U64:
        _fail(f"Overflowed {label} decimal")
    return value


def _native_u64(value: Any, label: str) -> str:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        _fail(f"Invalid native {label}")
    return str(value)


def _portable_path(value: Any) -> str:
    try:
        return _path(value)
    except PortableProvenanceError as exc:
        raise LocalBindingError("Unsafe local managed path") from exc


def _sorted_unique(paths: list[str], label: str) -> None:
    if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths):
        _fail(f"Unsorted or aliased {label}")


def _native_chain(root_path: Any, platform: str) -> list[str]:
    if type(root_path) is not str or len(root_path) > 4096:
        _fail("Invalid native root path")
    if platform in {"Darwin", "Linux"}:
        if (
            not root_path.startswith("/")
            or "//" in root_path
            or (root_path != "/" and root_path.endswith("/"))
            or "\x00" in root_path
        ):
            _fail("Noncanonical POSIX root path")
        parts = root_path.split("/")[1:]
        if any(part in {"", ".", ".."} for part in parts if root_path != "/"):
            _fail("Noncanonical POSIX root component")
        chain = ["/"]
        current = ""
        for part in parts if root_path != "/" else []:
            current += "/" + part
            chain.append(current)
    else:
        try:
            validate_root_path(root_path)
        except (UnsafeWindowsPath, ValueError) as exc:
            raise LocalBindingError("Noncanonical Windows root path") from exc
        drive, tail = ntpath.splitdrive(root_path)
        if drive != drive.upper() or (tail != "\\" and tail.endswith("\\")):
            _fail("Noncanonical Windows root path")
        chain = [drive + "\\"]
        current = drive
        for part in (part for part in tail.split("\\") if part):
            current += "\\" + part
            chain.append(current)
    if len(chain) > MAX_ROOT_COMPONENTS:
        _fail("Native root has too many ancestors")
    return chain


def _validate_xattrs(values: Any) -> list[dict[str, str]]:
    if type(values) is not list or len(values) > MAX_XATTRS:
        _fail("Invalid xattr inventory")
    previous = b""
    for item in values:
        _fields(item, {"name_base64", "size_decimal", "sha256"}, "xattr")
        name = item["name_base64"]
        if type(name) is not str or len(name) > 4096:
            _fail("Invalid xattr name")
        try:
            decoded = base64.b64decode(name, validate=True)
        except (ValueError, TypeError) as exc:
            raise LocalBindingError("Invalid xattr name") from exc
        if (
            not decoded
            or decoded <= previous
            or base64.b64encode(decoded).decode("ascii") != name
        ):
            _fail("Unsorted or noncanonical xattr name")
        previous = decoded
        _u64(item["size_decimal"], "xattr size")
        _hex(item["sha256"], HEX64, "xattr digest")
    return values


def _validate_witness(value: Any, platform: str, kind: str) -> None:
    if kind not in {"file", "directory"}:
        _fail("Invalid witness kind")
    if type(value) is not dict:
        _fail("Invalid native witness")
    schema = (
        POSIX_WITNESS_SCHEMA
        if platform in {"Darwin", "Linux"}
        else WINDOWS_WITNESS_SCHEMA
    )
    if value.get("schema") != schema or value.get("kind") != kind:
        _fail("Wrong native witness schema or kind")
    presence = value.get("presence")
    if presence == "absent":
        _fields(value, {"schema", "kind", "presence"}, "absent witness")
        return
    if presence != "present":
        _fail("Invalid native witness presence")
    if platform in {"Darwin", "Linux"}:
        _fields(
            value,
            {
                "schema",
                "kind",
                "presence",
                "device_decimal",
                "inode_decimal",
                "mode_octal",
                "uid_decimal",
                "gid_decimal",
                "flags_hex",
                "acl_entries",
                "xattrs",
            },
            "POSIX witness",
        )
        for name in ("device_decimal", "inode_decimal", "uid_decimal", "gid_decimal"):
            _u64(value[name], name)
        if (
            type(value["mode_octal"]) is not str
            or OCTAL4.fullmatch(value["mode_octal"]) is None
        ):
            _fail("Invalid full POSIX mode")
        flags = int(_hex(value["flags_hex"], HEX16, "POSIX flags"), 16)
        if kind == "file" and (
            platform == "Darwin"
            and flags != 0
            or platform == "Linux"
            and flags & ~KERNEL_LAYOUT_FLAGS
        ):
            _fail("Unsupported POSIX flags")
        acl = value["acl_entries"]
        if (
            type(acl) is not list
            or len(acl) > MAX_ACL_ENTRIES
            or any(type(item) is not str or len(item) > 4096 for item in acl)
            or (kind == "file" and acl)
        ):
            _fail("Unsupported POSIX extended ACL or unbounded ancestor ACL")
        _validate_xattrs(value["xattrs"])
    else:
        _fields(
            value,
            {
                "schema",
                "kind",
                "presence",
                "volume_serial_hex",
                "file_id_hex",
                "attributes_hex",
                "security",
            },
            "Windows witness",
        )
        _hex(value["volume_serial_hex"], HEX16, "volume serial")
        _hex(value["file_id_hex"], HEX32, "file ID")
        attributes = int(_hex(value["attributes_hex"], HEX8, "Windows attributes"), 16)
        allowed = (
            SUPPORTED_FILE_ATTRIBUTES
            if kind == "file"
            else SUPPORTED_DIRECTORY_ATTRIBUTES
        )
        if attributes & ~allowed or (kind == "directory" and not attributes & FILE_ATTRIBUTE_DIRECTORY):
            _fail("Unsupported Windows attributes")
        security = _fields(
            value["security"],
            {
                "owner_sid_sha256",
                "owner_sid_size_decimal",
                "group_sid_sha256",
                "group_sid_size_decimal",
                "dacl_sha256",
                "dacl_size_decimal",
                "descriptor_sha256",
                "descriptor_size_decimal",
                "dacl_protected",
            },
            "Windows security",
        )
        limits = {
            "owner_sid": (8, 256),
            "group_sid": (8, 256),
            "dacl": (8, 65535),
            "descriptor": (20, 131072),
        }
        for name, (minimum, maximum) in limits.items():
            _hex(security[name + "_sha256"], HEX64, name + " digest")
            size = int(_u64(security[name + "_size_decimal"], name + " size"))
            if not minimum <= size <= maximum:
                _fail("Unsupported Windows security byte length")
        if type(security["dacl_protected"]) is not bool:
            _fail("Invalid Windows DACL protection")


def project_posix_witness(native_metadata: dict[str, object]) -> dict[str, Any]:
    """Project an existing validated descriptor observation; strip Python/machine."""
    _fields(
        native_metadata,
        {
            "schema",
            "platform",
            "machine",
            "python_minor",
            "file_type",
            "device",
            "inode",
            "mode",
            "uid",
            "gid",
            "flags",
            "acl_entries",
            "xattrs",
        },
        "POSIX native metadata",
    )
    attrs = native_metadata["xattrs"]
    acl = native_metadata["acl_entries"]
    if (
        type(attrs) is not list
        or len(attrs) > MAX_XATTRS
        or type(acl) is not list
        or len(acl) > MAX_ACL_ENTRIES
    ):
        _fail("POSIX native metadata inventory exceeds bound")
    for item in attrs:
        if (
            type(item) is not dict
            or len(item) != 3
            or type(item.get("name_base64")) is not str
            or len(item["name_base64"]) > 4096
            or type(item.get("sha256")) is not str
            or len(item["sha256"]) != 64
        ):
            _fail("POSIX native xattr exceeds bound")
        _native_u64(item.get("size"), "xattr size")
    for item in acl:
        if type(item) is not str or len(item) > 4096:
            _fail("POSIX native ACL exceeds bound")
    for name in ("device", "inode", "uid", "gid", "flags"):
        _native_u64(native_metadata[name], name)
    if (
        type(native_metadata["mode"]) is not int
        or not 0 <= native_metadata["mode"] <= 0o7777
    ):
        _fail("Invalid native POSIX mode")
    kind_map = {"regular_file": "file", "directory": "directory"}
    file_type = native_metadata.get("file_type")
    kind = kind_map.get(file_type) if type(file_type) is str else None
    if kind is None:
        _fail("Unsupported POSIX metadata type")
    try:
        validate_created_metadata_identity(
            native_metadata, expected_type=str(native_metadata["file_type"])
        )
    except ContentPathError as exc:
        raise LocalBindingError("Invalid validated POSIX observation") from exc
    platform = native_metadata["platform"]
    # Directory witnesses protect read-only topology. Root ancestors such as
    # macOS / can carry native flags that are not allowed on created files.
    # File replacement support remains governed by the existing strict policy.
    if kind == "file" and (
        not supported_metadata_flags(native_metadata) or native_metadata["acl_entries"]
    ):
        _fail("Unsupported POSIX file metadata")
    witness = {
        "schema": POSIX_WITNESS_SCHEMA,
        "kind": kind,
        "presence": "present",
        "device_decimal": _native_u64(native_metadata["device"], "device"),
        "inode_decimal": _native_u64(native_metadata["inode"], "inode"),
        "mode_octal": f"{native_metadata['mode']:04o}",
        "uid_decimal": _native_u64(native_metadata["uid"], "uid"),
        "gid_decimal": _native_u64(native_metadata["gid"], "gid"),
        "flags_hex": f"{native_metadata['flags']:016x}",
        "acl_entries": list(native_metadata["acl_entries"]),
        "xattrs": [
            {
                "name_base64": item["name_base64"],
                "size_decimal": _native_u64(item["size"], "xattr size"),
                "sha256": item["sha256"],
            }
            for item in attrs
        ],
    }
    _validate_witness(witness, str(platform), kind)
    return witness


def project_windows_witness(
    info: HandleInfo, security: SecurityParts
) -> dict[str, Any]:
    """Project validated held-handle values; native caller must check EAs/streams."""
    if type(info) is not HandleInfo or type(security) is not SecurityParts:
        _fail("Missing Windows handle observation")
    kind = (
        "directory"
        if info.directory is True
        else "file"
        if info.directory is False
        else None
    )
    if kind is None or type(info.links) is not int or info.links < 1:
        _fail("Invalid Windows handle kind or link count")
    if kind == "file" and info.links != 1:
        _fail("Multiply linked Windows file")
    if (
        type(info.volume) is not int
        or not 0 <= info.volume <= MAX_U64
        or type(info.file_id) is not bytes
        or len(info.file_id) != 16
        or type(info.attributes) is not int
        or not 0 <= info.attributes < 2**32
        or type(info.reparse_tag) is not int
        or info.reparse_tag != 0
        or type(info.size) is not int
        or info.size < 0
    ):
        _fail("Invalid Windows native identity or metadata")
    permitted = (
        SUPPORTED_DIRECTORY_ATTRIBUTES
        if kind == "directory"
        else SUPPORTED_FILE_ATTRIBUTES
    )
    if info.attributes & ~permitted:
        _fail("Unsupported Windows attributes")
    limits = {
        "owner_sid": (8, 256),
        "group_sid": (8, 256),
        "dacl": (8, 65535),
        "descriptor": (20, 131072),
    }
    values = {}
    for name, (minimum, maximum) in limits.items():
        value = getattr(security, name)
        if type(value) is not bytes or not minimum <= len(value) <= maximum:
            _fail("Invalid Windows security bytes")
        values[name + "_sha256"] = hashlib.sha256(value).hexdigest()
        values[name + "_size_decimal"] = str(len(value))
    if type(security.protected) is not bool:
        _fail("Invalid Windows DACL protection")
    values["dacl_protected"] = security.protected
    witness = {
        "schema": WINDOWS_WITNESS_SCHEMA,
        "kind": kind,
        "presence": "present",
        "volume_serial_hex": f"{info.volume:016x}",
        "file_id_hex": info.file_id.hex(),
        "attributes_hex": f"{info.attributes:08x}",
        "security": values,
    }
    _validate_witness(witness, "Windows", kind)
    return witness


def absent_witness(platform: str, kind: str) -> dict[str, str]:
    if (
        type(platform) is not str
        or platform not in {"Darwin", "Linux", "Windows"}
        or type(kind) is not str
        or kind not in {"file", "directory"}
    ):
        _fail("Invalid absent witness platform or kind")
    return {
        "schema": POSIX_WITNESS_SCHEMA
        if platform != "Windows"
        else WINDOWS_WITNESS_SCHEMA,
        "kind": kind,
        "presence": "absent",
    }


def _validate_native(native: Any) -> dict[str, Any]:
    value = _fields(
        native,
        {
            "platform",
            "root_path",
            "root_chain",
            "managed_ancestors",
            "control_directories",
        },
        "native topology",
    )
    platform = value["platform"]
    if type(platform) is not str or platform not in {"Darwin", "Linux", "Windows"}:
        _fail("Unsupported native platform")
    expected_chain = _native_chain(value["root_path"], platform)
    chain = value["root_chain"]
    if type(chain) is not list or len(chain) != len(expected_chain):
        _fail("Incomplete native root chain")
    for path, item in zip(expected_chain, chain):
        _fields(item, {"path", "witness"}, "root ancestor")
        if item["path"] != path:
            _fail("Native root chain path mismatch")
        _validate_witness(item["witness"], platform, "directory")
        if item["witness"]["presence"] != "present":
            _fail("Native root ancestor is absent")
    ancestors = value["managed_ancestors"]
    if type(ancestors) is not list or len(ancestors) > MAX_ANCESTORS:
        _fail("Invalid managed ancestor inventory")
    names = []
    for item in ancestors:
        _fields(item, {"path", "witness"}, "managed ancestor")
        names.append(_portable_path(item["path"]))
        _validate_witness(item["witness"], platform, "directory")
    _sorted_unique(names, "managed ancestors")
    controls = value["control_directories"]
    if type(controls) is not list or len(controls) != len(CONTROL_DIRECTORIES):
        _fail("Incomplete or extra local control directory chain")
    for expected, item in zip(CONTROL_DIRECTORIES, controls):
        _fields(item, {"path", "witness"}, "local control directory")
        if item["path"] != expected:
            _fail("Aliased or reordered local control directory")
        _validate_witness(item["witness"], platform, "directory")
    for index, item in enumerate(controls[1:], start=1):
        if (
            controls[index - 1]["witness"]["presence"] == "absent"
            and item["witness"]["presence"] != "absent"
        ):
            _fail("Present local control child beneath absent directory")
    return value


def _validate_journals(value: Any) -> dict[str, Any]:
    value = _fields(value, {"head_id", "entries"}, "journal inventory")
    entries = value["entries"]
    if type(entries) is not list or len(entries) > MAX_JOURNALS:
        _fail("Invalid journal inventory count")
    for index, item in enumerate(entries, start=1):
        _fields(item, {"id", "sha256"}, "journal")
        if item["id"] != f"J{index:08d}":
            _fail("Missing, duplicate, or reordered local journal")
        _hex(item["sha256"], HEX64, "journal digest")
    if value["head_id"] != (entries[-1]["id"] if entries else None):
        _fail("Local journal head differs from complete inventory")
    return value


def _validate_leaves(leaves: Any, native: dict[str, Any]) -> list[dict[str, Any]]:
    if type(leaves) is not list or len(leaves) > MAX_LEAVES:
        _fail("Invalid managed leaf inventory")
    paths = []
    component_work = 0
    platform = native["platform"]
    for item in leaves:
        _fields(item, {"path", "metadata", "content"}, "managed leaf")
        path = _portable_path(item["path"])
        parts = path.split("/")
        component_work += len(parts)
        if (
            len(parts) > MAX_PATH_COMPONENTS
            or component_work > MAX_TOTAL_PATH_COMPONENTS
        ):
            _fail("Managed leaf path complexity exceeds bound")
        paths.append(path)
        _validate_witness(item["metadata"], platform, "file")
        if item["metadata"]["presence"] == "absent":
            if item["content"] is not None:
                _fail("Absent leaf has content")
        else:
            content = _fields(
                item["content"], {"sha256", "size_decimal"}, "leaf content"
            )
            _hex(content["sha256"], HEX64, "leaf content digest")
            _u64(content["size_decimal"], "leaf size")
    _sorted_unique(paths, "managed leaves")
    try:
        _unique_paths(paths)
    except PortableProvenanceError as exc:
        raise LocalBindingError("Managed file/descendant namespace collision") from exc
    expected_set: set[str] = set()
    for path in paths:
        parts = path.split("/")
        prefix = ""
        for part in parts[:-1]:
            prefix = part if not prefix else prefix + "/" + part
            expected_set.add(prefix)
            if len(expected_set) > MAX_ANCESTORS:
                _fail("Managed ancestor coverage exceeds bound")
    expected_ancestors = sorted(expected_set)
    actual_ancestors = [item["path"] for item in native["managed_ancestors"]]
    if actual_ancestors != expected_ancestors:
        _fail("Managed ancestor coverage is incomplete or extra")
    absent = {
        item["path"]
        for item in native["managed_ancestors"]
        if item["witness"]["presence"] == "absent"
    }

    def beneath_absent(path: str) -> bool:
        parts = path.split("/")
        prefix = ""
        for part in parts[:-1]:
            prefix = part if not prefix else prefix + "/" + part
            if prefix in absent:
                return True
        return False

    for item in native["managed_ancestors"]:
        if beneath_absent(item["path"]) and item["witness"]["presence"] != "absent":
            _fail("Present directory beneath absent ancestor")
    for item in leaves:
        if beneath_absent(item["path"]) and item["metadata"]["presence"] != "absent":
            _fail("Present leaf beneath absent ancestor")
    return leaves


def _validate_observation(body: Any) -> dict[str, Any]:
    body = _fields(
        body,
        {
            "schema",
            "native",
            "journals",
            "leaves",
            "transaction_state",
            "diagnostic_python_minor",
            "binding_id",
        },
        "local observation",
    )
    if body["schema"] != OBSERVATION_SCHEMA:
        _fail("Wrong local observation schema")
    native = _validate_native(body["native"])
    _validate_journals(body["journals"])
    _validate_leaves(body["leaves"], native)
    if type(body["transaction_state"]) is not str or body["transaction_state"] not in {
        "quiescent",
        "pending",
        "unknown",
    }:
        _fail("Invalid local transaction state")
    if body["binding_id"] is not None:
        _hex(body["binding_id"], BINDING_ID, "observed binding ID")
    diagnostic = body["diagnostic_python_minor"]
    if diagnostic is not None and (
        type(diagnostic) is not str
        or len(diagnostic) > MAX_DIAGNOSTIC_BYTES
        or diagnostic not in {"3.11", "3.12", "3.13"}
    ):
        _fail("Invalid diagnostic Python minor")
    return body


def _validate_binding(body: Any) -> dict[str, Any]:
    if type(body) is dict and body.get("schema") == "naos.upgrade.local_binding.v2":
        from .foreign_store_version import validate_binding
        return validate_binding(body)
    body = _fields(
        body,
        {
            "schema",
            "project_id",
            "owner_sha256",
            "portable_head_sha256",
            "binding_id",
            "observation",
        },
        "local binding",
    )
    if (
        body["schema"] != BINDING_SCHEMA
        or type(body["project_id"]) is not str
        or not body["project_id"]
    ):
        _fail("Wrong local binding schema or project")
    if len(body["project_id"]) > 128:
        _fail("Oversized local project ID")
    _hex(body["owner_sha256"], HEX64, "portable owner digest")
    _hex(body["portable_head_sha256"], HEX64, "portable head digest")
    _hex(body["binding_id"], BINDING_ID, "local binding ID")
    observation = dict(
        _fields(
            body["observation"],
            {
                "schema",
                "native",
                "journals",
                "leaves",
                "transaction_state",
                "diagnostic_python_minor",
                "binding_id",
            },
            "bound observation",
        )
    )
    _validate_observation(observation)
    if observation["binding_id"] != body["binding_id"]:
        _fail("Bound observation has a foreign binding ID")
    if observation["transaction_state"] != "quiescent":
        _fail("Cannot bind an unfinished or unknown transaction")
    if any(
        item["witness"]["presence"] != "present"
        for item in observation["native"]["control_directories"]
    ):
        _fail("Cannot bind absent local control storage")
    return body


def _encode(body: Mapping[str, Any], *, binding: bool) -> bytes:
    try:
        _bounded_input(body)
        (_validate_binding if binding else _validate_observation)(body)
    except LocalBindingError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise LocalBindingError("Malformed local record") from exc
    try:
        raw = canonical_bytes(body)
    except (
        CanonicalizationError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise LocalBindingError("Cannot canonicalize local record") from exc
    if len(raw) > MAX_RECORD_BYTES:
        _fail("Local record exceeds byte bound")
    return raw


def encode_local_binding(body: Mapping[str, Any]) -> bytes:
    return _encode(body, binding=True)


def encode_local_observation(body: Mapping[str, Any]) -> bytes:
    return _encode(body, binding=False)


@dataclass(frozen=True)
class ValidatedLocalBinding:
    sha256: str
    raw: bytes

    @property
    def body(self) -> dict[str, Any]:
        return _load_json(self.raw, "local binding")


@dataclass(frozen=True)
class ValidatedLocalObservation:
    sha256: str
    raw: bytes

    @property
    def body(self) -> dict[str, Any]:
        return _load_json(self.raw, "local observation")


def _load(
    raw: bytes, *, binding: bool
) -> ValidatedLocalBinding | ValidatedLocalObservation:
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        _fail("Missing or oversized local record")
    try:
        body = _load_json(raw, "local binding" if binding else "local observation")
        encoded = _encode(body, binding=binding)
    except (
        PortableProvenanceError,
        CanonicalizationError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ) as exc:
        if isinstance(exc, LocalBindingError):
            raise
        raise LocalBindingError("Malformed local record") from exc
    if encoded != raw:
        _fail("Noncanonical local record")
    digest = hashlib.sha256(raw).hexdigest()
    return (
        ValidatedLocalBinding(digest, raw)
        if binding
        else ValidatedLocalObservation(digest, raw)
    )


def load_local_binding(raw: bytes) -> ValidatedLocalBinding:
    result = _load(raw, binding=True)
    assert isinstance(result, ValidatedLocalBinding)
    return result


def load_local_observation(raw: bytes) -> ValidatedLocalObservation:
    result = _load(raw, binding=False)
    assert isinstance(result, ValidatedLocalObservation)
    return result


@dataclass(frozen=True)
class LocalComparison:
    status: str
    content_drift_paths: tuple[str, ...] = ()
    metadata_drift_paths: tuple[str, ...] = ()
    reason: str | None = None


def directory_witness_matches(
    observed: dict[str, Any], expected: dict[str, Any], *, platform: str
) -> bool:
    """Keep historical directory custody through Linux index promotion only.

    ext4 may set FS_INDEX_FL while adding an authorized directory entry. The
    recorded witness stays unchanged; identity, protections, ACLs, xattrs and
    every other flag (including FS_EXTENT_FL) remain exact. Index removal is
    not an authorized growth transition. File witnesses never use this rule.
    """
    if type(platform) is not str or platform not in {"Darwin", "Linux", "Windows"}:
        return False
    try:
        _validate_witness(observed, platform, "directory")
        _validate_witness(expected, platform, "directory")
    except LocalBindingError:
        return False
    if observed == expected:
        return True
    if (platform != "Linux" or observed["presence"] != "present"
            or expected["presence"] != "present"):
        return False
    promoted = dict(expected)
    promoted["flags_hex"] = f"{int(expected['flags_hex'], 16) | FS_INDEX_FL:016x}"
    return observed == promoted


def _metadata_comparison(
    left: dict[str, Any], right: dict[str, Any], platform: str
) -> bool:
    if left == right:
        return True
    if (
        platform != "Linux"
        or left.get("presence") != "present"
        or right.get("presence") != "present"
    ):
        return False
    normalized_left, normalized_right = dict(left), dict(right)
    normalized_left["flags_hex"] = (
        f"{int(left['flags_hex'], 16) & ~KERNEL_LAYOUT_FLAGS:016x}"
    )
    normalized_right["flags_hex"] = (
        f"{int(right['flags_hex'], 16) & ~KERNEL_LAYOUT_FLAGS:016x}"
    )
    return normalized_left == normalized_right


def compare_local_binding(
    binding: ValidatedLocalBinding,
    current: ValidatedLocalObservation,
    portable: ValidatedPortableSnapshot,
) -> LocalComparison:
    """Compare one same-binding observation; never authorize mutation or rebind."""
    if (
        type(binding) is not ValidatedLocalBinding
        or type(current) is not ValidatedLocalObservation
        or type(portable) is not ValidatedPortableSnapshot
    ):
        _fail("Comparison requires validated records and portable snapshot")
    if (
        load_local_binding(binding.raw) != binding
        or load_local_observation(current.raw) != current
    ):
        _fail("Local record digest or canonical validation changed")
    expected = binding.body
    observed = current.body
    if (
        expected["project_id"] != portable.project_id
        or expected["owner_sha256"] != portable.owner_sha256
        or expected["portable_head_sha256"] != portable.manifest_sha256
    ):
        return LocalComparison(
            "refuse-topology-drift", reason="foreign project, owner, or portable head"
        )
    if observed["transaction_state"] != "quiescent":
        return LocalComparison(
            "refuse-topology-drift", reason="unfinished or unknown local transaction"
        )
    if observed["binding_id"] != expected["binding_id"]:
        return LocalComparison(
            "refuse-topology-drift", reason="foreign or missing local binding ID"
        )
    prior = expected["observation"]
    native_prior, native_now = prior["native"], observed["native"]
    if (
        native_prior["platform"] != native_now["platform"]
        or native_prior["root_path"] != native_now["root_path"]
        or len(native_prior["root_chain"]) != len(native_now["root_chain"])
    ):
        return LocalComparison("refuse-topology-drift", reason="foreign native root")
    platform = native_prior["platform"]
    for old, new in zip(native_prior["root_chain"], native_now["root_chain"]):
        if old["path"] != new["path"] or not _metadata_comparison(
            old["witness"], new["witness"], platform
        ):
            return LocalComparison(
                "refuse-topology-drift",
                reason="root or ancestor identity/protection drift",
            )
    for old, new in zip(
        native_prior["control_directories"], native_now["control_directories"]
    ):
        if old["path"] != new["path"] or not _metadata_comparison(
            old["witness"], new["witness"], platform
        ):
            return LocalComparison(
                "refuse-topology-drift",
                reason="local control directory identity/protection drift",
            )
    if prior["journals"] != observed["journals"]:
        return LocalComparison(
            "refuse-topology-drift", reason="local journal head or inventory drift"
        )
    old_ancestors = native_prior["managed_ancestors"]
    new_ancestors = native_now["managed_ancestors"]
    if len(old_ancestors) != len(new_ancestors):
        return LocalComparison(
            "refuse-topology-drift", reason="managed ancestor inventory drift"
        )
    for old, new in zip(old_ancestors, new_ancestors):
        if old["path"] != new["path"] or not _metadata_comparison(
            old["witness"], new["witness"], platform
        ):
            return LocalComparison(
                "refuse-topology-drift",
                reason="managed ancestor identity/protection drift",
            )
    prior_leaves = prior["leaves"]
    current_leaves = observed["leaves"]
    snapshot_paths = sorted(portable.entries)
    if [item["path"] for item in prior_leaves] != snapshot_paths or [
        item["path"] for item in current_leaves
    ] != snapshot_paths:
        return LocalComparison(
            "refuse-topology-drift",
            reason="managed leaf coverage differs from portable history",
        )
    content_drift: list[str] = []
    metadata_drift: list[str] = []
    for old, new in zip(prior_leaves, current_leaves):
        if old["content"] != new["content"]:
            content_drift.append(old["path"])
        if not _metadata_comparison(old["metadata"], new["metadata"], platform):
            metadata_drift.append(old["path"])
    if content_drift:
        return LocalComparison(
            "preserve-content-drift", tuple(content_drift), tuple(metadata_drift)
        )
    if metadata_drift:
        return LocalComparison("preserve-metadata-drift", (), tuple(metadata_drift))
    return LocalComparison("unchanged")
