"""Read-only Windows source observation through held, non-followed handles.

The record is Windows-native and deliberately has no POSIX uid/gid fields.
It is an input to a future journaled transaction adapter, not an install API.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import ntpath
from typing import Any

from .windows_handles import UnsafeWindowsPath, WindowsHandles, validate_component, validate_root_path


SCHEMA = "naos.metadata.windows_source.v1"
HASH_CHUNK = 1024 * 1024


def _parts(path: str) -> tuple[str, tuple[str, ...]]:
    validated = validate_root_path(path)
    drive, tail = ntpath.splitdrive(validated)
    return drive + "\\", tuple(validate_component(x) for x in tail.split("\\") if x)


def _relative_parts(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path or "\0" in path or "/" in path:
        raise UnsafeWindowsPath("Managed relative path must use ordinary backslash components")
    drive, tail = ntpath.splitdrive(path)
    if drive or tail.startswith("\\") or "\\\\" in tail or tail.endswith("\\"):
        raise UnsafeWindowsPath("Managed path must be relative and component-clean")
    return tuple(validate_component(x) for x in tail.split("\\"))


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _observe_with_handles(handles: Any, project_root: str, relative_path: str) -> dict[str, Any]:
    """Testable core; production callers use observe_regular_file.

    The drive root is the only path-based open. Every later component is opened
    relative to a held parent with a read pin (share-read only). Native errors
    propagate unchanged, including permission, sharing and missing errors.
    """
    drive_root, root_parts = _parts(project_root)
    child_parts = _relative_parts(relative_path)
    with ExitStack() as stack:
        parent = stack.enter_context(handles.open_root(drive_root))
        ancestors = []
        ancestor_handles = []
        for name in root_parts + child_parts[:-1]:
            parent = stack.enter_context(handles.open_child(parent, name, kind="directory", pin_for_read=True))
            info = parent.info()
            if not info.directory:
                raise UnsafeWindowsPath("Managed path ancestor is not a directory")
            ancestors.append((name, info.identity))
            ancestor_handles.append(parent)
        leaf = stack.enter_context(handles.open_child(
            parent, child_parts[-1], kind="file", pin_for_read=True))
        before = leaf.info()
        if before.directory or before.links != 1 or before.size < 0:
            raise UnsafeWindowsPath("Managed source is not a single-link regular file")
        security_before = leaf.security()
        leaf.seek(0)
        digest = hashlib.sha256()
        count = 0
        while True:
            block = leaf.read(HASH_CHUNK)
            if not block:
                break
            count += len(block)
            if count > before.size:
                raise UnsafeWindowsPath("Managed source grew during observation")
            digest.update(block)
        after = leaf.info()
        security_after = leaf.security()
        if count != before.size or after != before or security_after != security_before:
            raise UnsafeWindowsPath("Managed source changed during observation")
        # Revalidate each held ancestor after reading. Share-read pins deny
        # competing opens for write/delete, including rename requests.
        if any(held.info().identity != identity or not held.info().directory
               for held, (_, identity) in zip(ancestor_handles, ancestors)):
            raise UnsafeWindowsPath("Managed ancestor changed during observation")
        return {
            "schema": SCHEMA,
            "path": relative_path,
            # Native 64-bit serials and 100 ns timestamps exceed the exact
            # integer range of RFC 8785. Encode them losslessly before hashing.
            "identity": {"volume_serial_hex": f"{before.volume:016x}", "file_id_hex": before.file_id.hex()},
            "size_bytes": before.size,
            "sha256": digest.hexdigest(),
            "file_times_100ns": {
                "created": str(before.created_time),
                "modified": str(before.modified_time),
                "changed": str(before.changed_time),
            },
            "attributes": before.attributes,
            "security": {
                "owner_sid_sha256": _digest(security_before.owner_sid),
                "group_sid_sha256": _digest(security_before.group_sid),
                "dacl_sha256": _digest(security_before.dacl),
                "dacl_protected": security_before.protected,
            },
            "held_ancestors": [
                {"name": name, "volume_serial_hex": f"{identity[0]:016x}", "file_id_hex": identity[1].hex()}
                for name, identity in ancestors
            ],
        }


def observe_regular_file(project_root: str, relative_path: str) -> dict[str, Any]:
    """Observe one existing regular file; requires a native Windows runtime.

    The result can be compared only with the same schema/version. A planner may
    digest it, but must reobserve with held handles before a destructive step.
    """
    return _observe_with_handles(WindowsHandles(), project_root, relative_path)
