"""No-follow path controls shared by managed-content consumers."""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import os
import platform
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path


class ContentPathError(ValueError):
    """Raised when a managed-content source or destination is unsafe."""


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _darwin_xattrs(path: Path) -> list[dict[str, object]]:
    libc = ctypes.CDLL(None, use_errno=True)
    listxattr = libc.listxattr
    listxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    listxattr.restype = ctypes.c_ssize_t
    getxattr = libc.getxattr
    getxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    getxattr.restype = ctypes.c_ssize_t
    encoded_path = os.fsencode(path)
    nofollow = 0x0001
    size = listxattr(encoded_path, None, 0, nofollow)
    if size < 0:
        error_number = ctypes.get_errno()
        raise ContentPathError(
            f"UNSUPPORTED_METADATA: cannot enumerate xattrs for {path}: "
            f"{os.strerror(error_number)}"
        )
    if size == 0:
        names: list[bytes] = []
    else:
        buffer = ctypes.create_string_buffer(size)
        observed = listxattr(encoded_path, buffer, size, nofollow)
        if observed != size:
            raise ContentPathError(
                f"UNSUPPORTED_METADATA: xattr inventory changed for {path}"
            )
        names = sorted(name for name in buffer.raw[:observed].split(b"\0") if name)
    result: list[dict[str, object]] = []
    for name in names:
        value_size = getxattr(encoded_path, name, None, 0, 0, nofollow)
        if value_size < 0:
            error_number = ctypes.get_errno()
            raise ContentPathError(
                f"UNSUPPORTED_METADATA: cannot size xattr for {path}: "
                f"{os.strerror(error_number)}"
            )
        value_buffer = ctypes.create_string_buffer(value_size)
        observed_size = getxattr(
            encoded_path,
            name,
            value_buffer,
            value_size,
            0,
            nofollow,
        )
        if observed_size != value_size:
            raise ContentPathError(
                f"UNSUPPORTED_METADATA: xattr changed for {path}"
            )
        value = value_buffer.raw[:observed_size]
        result.append(
            {
                "name_base64": base64.b64encode(name).decode("ascii"),
                "size": observed_size,
                "sha256": hashlib.sha256(value).hexdigest(),
            }
        )
    return result


def _darwin_xattrs_fd(descriptor: int) -> list[dict[str, object]]:
    libc = ctypes.CDLL(None, use_errno=True)
    flistxattr = libc.flistxattr
    flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    flistxattr.restype = ctypes.c_ssize_t
    fgetxattr = libc.fgetxattr
    fgetxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    fgetxattr.restype = ctypes.c_ssize_t
    size = flistxattr(descriptor, None, 0, 0)
    if size < 0:
        error_number = ctypes.get_errno()
        raise ContentPathError(
            "UNSUPPORTED_METADATA: cannot enumerate descriptor xattrs: "
            f"{os.strerror(error_number)}"
        )
    if size == 0:
        names: list[bytes] = []
    else:
        buffer = ctypes.create_string_buffer(size)
        observed = flistxattr(descriptor, buffer, size, 0)
        if observed != size:
            raise ContentPathError(
                "UNSUPPORTED_METADATA: descriptor xattr inventory changed"
            )
        names = sorted(name for name in buffer.raw[:observed].split(b"\0") if name)
    result: list[dict[str, object]] = []
    for name in names:
        value_size = fgetxattr(descriptor, name, None, 0, 0, 0)
        if value_size < 0:
            error_number = ctypes.get_errno()
            raise ContentPathError(
                "UNSUPPORTED_METADATA: cannot size descriptor xattr: "
                f"{os.strerror(error_number)}"
            )
        value_buffer = ctypes.create_string_buffer(value_size)
        observed_size = fgetxattr(
            descriptor,
            name,
            value_buffer,
            value_size,
            0,
            0,
        )
        if observed_size != value_size:
            raise ContentPathError(
                "UNSUPPORTED_METADATA: descriptor xattr changed"
            )
        value = value_buffer.raw[:observed_size]
        result.append(
            {
                "name_base64": base64.b64encode(name).decode("ascii"),
                "size": observed_size,
                "sha256": hashlib.sha256(value).hexdigest(),
            }
        )
    return result


def _darwin_acl_entries_from_handle(
    *,
    encoded_path: bytes | None = None,
    descriptor: int | None = None,
) -> list[str]:
    libc = ctypes.CDLL(None, use_errno=True)
    if descriptor is None:
        acl_get = libc.acl_get_link_np
        acl_get.argtypes = [ctypes.c_char_p, ctypes.c_int]
    else:
        acl_get = libc.acl_get_fd_np
        acl_get.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get.restype = ctypes.c_void_p
    acl_to_text = libc.acl_to_text
    acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    acl_to_text.restype = ctypes.c_void_p
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    if descriptor is None:
        assert encoded_path is not None
        acl = acl_get(encoded_path, 0x00000100)  # ACL_TYPE_EXTENDED
    else:
        acl = acl_get(descriptor, 0x00000100)
    if not acl:
        error_number = ctypes.get_errno()
        # Darwin reports ENOENT when the existing object has no extended ACL.
        if error_number == errno.ENOENT:
            return []
        raise ContentPathError(
            "UNSUPPORTED_METADATA: cannot enumerate ACL: "
            f"{os.strerror(error_number)}"
        )
    text_pointer: int | None = None
    try:
        text_length = ctypes.c_ssize_t()
        ctypes.set_errno(0)
        text_pointer = acl_to_text(acl, ctypes.byref(text_length))
        if not text_pointer:
            error_number = ctypes.get_errno()
            raise ContentPathError(
                "UNSUPPORTED_METADATA: cannot serialize ACL: "
                f"{os.strerror(error_number)}"
            )
        text = ctypes.string_at(text_pointer, text_length.value).decode(
            "utf-8",
            errors="strict",
        )
        return [line.strip() for line in text.splitlines() if line.strip()]
    finally:
        if text_pointer:
            acl_free(text_pointer)
        acl_free(acl)


def _darwin_acl_entries(path: Path) -> list[str]:
    """Read a Darwin extended ACL without following the final path component."""

    return _darwin_acl_entries_from_handle(encoded_path=os.fsencode(path))


def _darwin_acl_entries_fd(descriptor: int) -> list[str]:
    return _darwin_acl_entries_from_handle(descriptor=descriptor)


def _metadata_adapter_tuple() -> tuple[str, str, tuple[int, int]]:
    system = platform.system()
    machine = platform.machine().lower()
    python_minor = (sys.version_info.major, sys.version_info.minor)
    if (
        system != "Darwin"
        or machine not in {"arm64", "aarch64"}
        or python_minor not in {(3, 11), (3, 12), (3, 13)}
    ):
        raise ContentPathError(
            "UNSUPPORTED_METADATA: create-only adapter requires "
            "Darwin arm64 and Python 3.11-3.13"
        )
    return system, machine, python_minor


def _metadata_value(
    metadata: os.stat_result,
    *,
    expected_type: str,
    acl_entries: list[str],
    xattrs: list[dict[str, object]],
) -> dict[str, object]:
    _system, machine, python_minor = _metadata_adapter_tuple()
    type_matches = (
        stat.S_ISREG(metadata.st_mode)
        if expected_type == "regular_file"
        else stat.S_ISDIR(metadata.st_mode)
    )
    if not type_matches or metadata.st_nlink < 1:
        raise ContentPathError(
            f"UNSUPPORTED_METADATA: expected {expected_type}"
        )
    if expected_type == "regular_file" and metadata.st_nlink != 1:
        raise ContentPathError(
            "UNSUPPORTED_METADATA: expected a unique regular file"
        )
    return {
        "schema": "naos.metadata.darwin_create_only.v1",
        "platform": "Darwin",
        "machine": machine,
        "python_minor": f"{python_minor[0]}.{python_minor[1]}",
        "file_type": expected_type,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "flags": int(getattr(metadata, "st_flags", 0)),
        "acl_entries": acl_entries,
        "xattrs": xattrs,
    }


def _observe_created_path_metadata(
    path: Path,
    *,
    expected_type: str,
) -> dict[str, object]:
    """Observe the supported Darwin create-only metadata tuple exactly."""

    # Refuse unsupported hosts before resolving Darwin-only libc symbols.
    # Without this ordering, Linux raises AttributeError from acl_get_link_np
    # instead of the controlled ContentPathError promised by the adapter.
    _metadata_adapter_tuple()
    metadata = os.lstat(path)
    return _metadata_value(
        metadata,
        expected_type=expected_type,
        acl_entries=_darwin_acl_entries(path),
        xattrs=_darwin_xattrs(path),
    )


def _observe_created_descriptor_metadata(
    descriptor: int,
    *,
    expected_type: str,
) -> dict[str, object]:
    # Keep the platform boundary ahead of Darwin-only descriptor APIs too.
    _metadata_adapter_tuple()
    metadata = os.fstat(descriptor)
    return _metadata_value(
        metadata,
        expected_type=expected_type,
        acl_entries=_darwin_acl_entries_fd(descriptor),
        xattrs=_darwin_xattrs_fd(descriptor),
    )


def observe_created_file_metadata(path: Path) -> dict[str, object]:
    return _observe_created_path_metadata(path, expected_type="regular_file")


def observe_created_directory_metadata(path: Path) -> dict[str, object]:
    return _observe_created_path_metadata(path, expected_type="directory")


def observe_created_file_metadata_fd(descriptor: int) -> dict[str, object]:
    return _observe_created_descriptor_metadata(
        descriptor,
        expected_type="regular_file",
    )


def observe_created_directory_metadata_fd(descriptor: int) -> dict[str, object]:
    return _observe_created_descriptor_metadata(
        descriptor,
        expected_type="directory",
    )


def validate_created_metadata_identity(
    value: object,
    *,
    expected_type: str,
) -> None:
    expected_keys = {
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
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ContentPathError("Managed-content metadata identity is invalid.")
    if (
        value.get("schema") != "naos.metadata.darwin_create_only.v1"
        or value.get("platform") != "Darwin"
        or value.get("machine") not in {"arm64", "aarch64"}
        or value.get("python_minor") not in {"3.11", "3.12", "3.13"}
        or value.get("file_type") != expected_type
    ):
        raise ContentPathError("Managed-content metadata adapter binding is invalid.")
    for field in ("device", "inode", "mode", "uid", "gid", "flags"):
        member = value.get(field)
        if isinstance(member, bool) or not isinstance(member, int) or member < 0:
            raise ContentPathError(
                f"Managed-content metadata field is invalid: {field}"
            )
    acl_entries = value.get("acl_entries")
    xattrs = value.get("xattrs")
    if (
        not isinstance(acl_entries, list)
        or not all(isinstance(item, str) for item in acl_entries)
        or not isinstance(xattrs, list)
    ):
        raise ContentPathError("Managed-content ACL/xattr inventory is invalid.")
    previous_name = b""
    for item in xattrs:
        if not isinstance(item, dict) or set(item) != {
            "name_base64",
            "size",
            "sha256",
        }:
            raise ContentPathError("Managed-content xattr identity is invalid.")
        name = item.get("name_base64")
        size = item.get("size")
        digest = item.get("sha256")
        try:
            decoded_name = (
                base64.b64decode(name, validate=True)
                if isinstance(name, str)
                else b""
            )
        except (ValueError, TypeError):
            decoded_name = b""
        if (
            not decoded_name
            or base64.b64encode(decoded_name).decode("ascii") != name
            or decoded_name <= previous_name
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
        ):
            raise ContentPathError("Managed-content xattr identity is invalid.")
        previous_name = decoded_name


def source_metadata_contract(
    observed: dict[str, object],
) -> dict[str, object]:
    """Remove ephemeral filesystem identity from planned source metadata."""

    validate_created_metadata_identity(observed, expected_type="regular_file")
    return {
        "schema": "naos.metadata.darwin_source.v1",
        **{
            key: value
            for key, value in observed.items()
            if key not in {"schema", "device", "inode"}
        },
    }


def validate_source_metadata_contract(value: object) -> None:
    if not isinstance(value, dict):
        raise ContentPathError("Managed-content source metadata is invalid.")
    expanded = {
        **value,
        "schema": "naos.metadata.darwin_create_only.v1",
        "device": 0,
        "inode": 0,
    }
    validate_created_metadata_identity(expanded, expected_type="regular_file")
    if value.get("schema") != "naos.metadata.darwin_source.v1":
        raise ContentPathError("Managed-content source metadata schema is invalid.")


def managed_creation_identity() -> dict[str, object]:
    """Bind created leaves to the executing user and primary group."""

    _metadata_adapter_tuple()
    return {
        "schema": "naos.metadata.creation_identity.v1",
        "policy": "executing_uid_primary_gid",
        "uid": os.getuid(),
        "gid": os.getgid(),
    }


def validate_managed_creation_identity(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "policy", "uid", "gid"}
        or value.get("schema") != "naos.metadata.creation_identity.v1"
        or value.get("policy") != "executing_uid_primary_gid"
    ):
        raise ContentPathError("Managed-content creation identity is invalid.")
    for field in ("uid", "gid"):
        member = value.get(field)
        if isinstance(member, bool) or not isinstance(member, int) or member < 0:
            raise ContentPathError(
                f"Managed-content creation identity field is invalid: {field}"
            )


def metadata_preservation_matches(
    source: dict[str, object],
    destination: dict[str, object],
    *,
    creation_identity: dict[str, object],
) -> bool:
    """Compare supported metadata after normalizing the installed-source group.

    Package resources can inherit an installation-directory group (for example,
    ``wheel`` under ``/tmp`` on Darwin).  That group is source evidence, not
    adopter-project metadata.  Managed leaves are created by the active user in
    transaction staging and therefore use that user's primary group.
    """

    try:
        validate_source_metadata_contract(source)
        validate_created_metadata_identity(destination, expected_type="regular_file")
        validate_managed_creation_identity(creation_identity)
    except ContentPathError:
        return False
    expected = dict(source)
    expected["uid"] = creation_identity["uid"]
    expected["gid"] = creation_identity["gid"]
    return expected == source_metadata_contract(destination)


def source_metadata_creation_equivalent(
    left: dict[str, object],
    right: dict[str, object],
    *,
    creation_identity: dict[str, object],
) -> bool:
    """Compare two source records after applying managed-creation identity.

    A cumulative manifest keeps the raw metadata of the source used by the
    introducing transaction. A later package installation can expose the same
    source bytes and supported metadata under a different installation group.
    That raw group remains provenance evidence, but it must not make an
    otherwise current managed leaf fail a non-mutating precondition.
    """

    try:
        validate_source_metadata_contract(left)
        validate_source_metadata_contract(right)
        validate_managed_creation_identity(creation_identity)
    except ContentPathError:
        return False
    normalized_left = dict(left)
    normalized_right = dict(right)
    for normalized in (normalized_left, normalized_right):
        normalized["uid"] = creation_identity["uid"]
        normalized["gid"] = creation_identity["gid"]
    return normalized_left == normalized_right


def created_file_metadata_matches(
    path: Path,
    expected: dict[str, object],
) -> bool:
    try:
        return observe_created_file_metadata(path) == expected
    except (OSError, ContentPathError):
        return False


def created_directory_metadata_matches(
    path: Path,
    expected: dict[str, object],
) -> bool:
    try:
        return observe_created_directory_metadata(path) == expected
    except (OSError, ContentPathError):
        return False


@dataclass(frozen=True)
class PathObservation:
    relative_path: Path
    status: str
    ancestor_identities: tuple[tuple[str, int, int], ...]


def safe_relative_path(value: str | Path) -> Path:
    raw = value.as_posix() if isinstance(value, Path) else value
    if not isinstance(raw, str):
        raise ContentPathError(f"Managed-content path must be text: {value!r}")
    if (
        not raw
        or raw != unicodedata.normalize("NFC", raw)
        or "\\" in raw
        or ":" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise ContentPathError(f"Unsafe managed-content relative path: {value}")
    raw_parts = raw.split("/")
    reserved_device_names = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
    if any(
        not component
        or component in {".", ".."}
        or component.endswith((" ", "."))
        or component.split(".", 1)[0].casefold() in reserved_device_names
        for component in raw_parts
    ):
        raise ContentPathError(f"Unsafe managed-content relative path: {value}")
    try:
        path = Path(raw)
    except (TypeError, ValueError) as exc:
        raise ContentPathError(
            f"Unsafe managed-content relative path: {value}"
        ) from exc
    reserved_roots = {".git", ".hg", ".svn", ".bzr", ".naos"}
    if (
        path.is_absolute()
        or path == Path(".")
        or ".." in path.parts
        or not path.parts
        or path.parts[0].casefold() in reserved_roots
    ):
        raise ContentPathError(f"Unsafe managed-content relative path: {value}")
    return path


def observe_regular_file_beneath_fd(
    root_descriptor: int,
    relative_path: str | Path,
) -> tuple[
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
]:
    """Observe one regular leaf through a no-follow walk beneath a held root."""

    relative = safe_relative_path(relative_path)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    held_directories: list[tuple[int, int, str]] = []
    ancestor_identities: list[dict[str, object]] = []
    traversed: list[str] = []
    current = os.dup(root_descriptor)
    leaf_descriptor: int | None = None
    try:
        for component in relative.parts[:-1]:
            traversed.append(component)
            child = os.open(component, directory_flags, dir_fd=current)
            try:
                opened = os.fstat(child)
                live = os.stat(
                    component,
                    dir_fd=current,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(live.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (live.st_dev, live.st_ino)
                ):
                    raise ContentPathError(
                        "Managed-content ancestor is unsafe or changed: "
                        + component
                    )
            except BaseException:
                os.close(child)
                raise
            held_directories.append((current, child, component))
            ancestor_identities.append(
                {
                    "path": "/".join(traversed),
                    "device": opened.st_dev,
                    "inode": opened.st_ino,
                }
            )
            current = child

        leaf_name = relative.name
        leaf_descriptor = os.open(
            leaf_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=current,
        )
        before = os.fstat(leaf_descriptor)
        live_leaf = os.stat(
            leaf_name,
            dir_fd=current,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_ISLNK(live_leaf.st_mode)
            or (before.st_dev, before.st_ino)
            != (live_leaf.st_dev, live_leaf.st_ino)
        ):
            raise ContentPathError(
                f"Managed-content leaf is unsafe or changed: {relative}"
            )

        digest = hashlib.sha256()
        while True:
            block = os.read(leaf_descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        created_metadata = observe_created_file_metadata_fd(leaf_descriptor)
        after = os.fstat(leaf_descriptor)
        current_leaf = os.stat(
            leaf_name,
            dir_fd=current,
            follow_symlinks=False,
        )
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (before.st_dev, before.st_ino)
            != (current_leaf.st_dev, current_leaf.st_ino)
        ):
            raise ContentPathError(
                f"Managed-content leaf changed while read: {relative}"
            )

        for parent, child, component in held_directories:
            opened = os.fstat(child)
            live = os.stat(
                component,
                dir_fd=parent,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or stat.S_ISLNK(live.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (live.st_dev, live.st_ino)
            ):
                raise ContentPathError(
                    f"Managed-content ancestor changed while read: {relative}"
                )
        return (
            {
                "kind": "file",
                "mode": stat.S_IMODE(before.st_mode),
                "size": before.st_size,
                "sha256": digest.hexdigest(),
            },
            created_metadata,
            ancestor_identities,
        )
    finally:
        if leaf_descriptor is not None:
            os.close(leaf_descriptor)
        directory_descriptors = {current}
        for parent, child, _component in held_directories:
            directory_descriptors.add(parent)
            directory_descriptors.add(child)
        for descriptor in directory_descriptors:
            os.close(descriptor)


def observe_regular_file_beneath(
    project_root: Path,
    relative_path: str | Path,
) -> tuple[
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
]:
    """Observe one regular file without following any component beneath root."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_descriptor = os.open(project_root, flags)
    try:
        opened = os.fstat(root_descriptor)
        live = os.lstat(project_root)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(live.st_mode)
            or (opened.st_dev, opened.st_ino) != (live.st_dev, live.st_ino)
        ):
            raise ContentPathError("Managed-content project root changed while opened.")
        result = observe_regular_file_beneath_fd(root_descriptor, relative_path)
        current = os.lstat(project_root)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ContentPathError("Managed-content project root changed while read.")
        return result
    finally:
        os.close(root_descriptor)


def normalized_collision_key(path: Path) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def validate_distinct_paths(paths: list[Path]) -> None:
    observed: dict[tuple[str, ...], Path] = {}
    ordered = sorted(paths, key=lambda item: (len(item.parts), item.as_posix()))
    for path in ordered:
        key = normalized_collision_key(path)
        if key in observed:
            raise ContentPathError(
                f"Unicode/case-equivalent managed-content collision: {observed[key]} and {path}"
            )
        for existing_key, existing in observed.items():
            if key[: len(existing_key)] == existing_key:
                raise ContentPathError(
                    f"Overlapping managed-content destinations: {existing} and {path}"
                )
        observed[key] = path


def observe_absent_leaf(project_root: Path, relative_path: Path) -> PathObservation:
    root = project_root.resolve(strict=True)
    relative = safe_relative_path(relative_path)
    ancestors: list[tuple[str, int, int]] = []
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ContentPathError(
                f"Managed-content destination ancestor is unsafe: {current.relative_to(root)}"
            )
        ancestors.append(
            (current.relative_to(root).as_posix(), metadata.st_dev, metadata.st_ino)
        )
    leaf = root / relative
    try:
        metadata = os.lstat(leaf)
    except FileNotFoundError:
        status = "absent"
    else:
        if stat.S_ISLNK(metadata.st_mode):
            status = "symlink"
        elif stat.S_ISREG(metadata.st_mode):
            status = "file"
        elif stat.S_ISDIR(metadata.st_mode):
            status = "directory"
        else:
            status = "special"
    return PathObservation(relative, status, tuple(ancestors))


def revalidate_absent_leaf(project_root: Path, observation: PathObservation) -> None:
    current = observe_absent_leaf(project_root, observation.relative_path)
    if current != observation:
        raise ContentPathError(
            f"Managed-content destination changed after planning: {observation.relative_path}"
        )
