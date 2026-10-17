"""Minimal platform-bound transaction primitives retained for recovery."""

from __future__ import annotations

import ctypes
import copy
import errno
import hashlib
import json
import os
import platform
import re
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from . import linux_primitives
from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .planner import (
    CONTENT_AWARE_PLAN_SCHEMAS,
    ContentPlanningError,
    content_aware_drift_paths,
    OWNERSHIP_CLASSES,
    regular_file_identity,
    regular_file_observation,
    validate_content_aware_plan,
    validate_create_only_plan,
)
from .security import (
    supported_metadata_flags,
    supported_source_xattrs,
    ContentPathError,
    created_metadata_identity_matches,
    created_directory_metadata_matches,
    managed_creation_identity,
    observe_created_directory_metadata_fd,
    observe_created_file_metadata_fd,
    observe_regular_file_beneath,
    observe_regular_file_beneath_fd,
    metadata_preservation_matches,
    safe_relative_path,
    source_metadata_creation_equivalent,
    source_metadata_contract,
    validate_created_metadata_identity,
    validate_managed_creation_identity,
    validate_source_metadata_contract,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - apply is unsupported without flock.
    fcntl = None  # type: ignore[assignment]


RENAME_EXCL = 0x00000004
RENAME_SWAP = 0x00000002
RENAME_NOFOLLOW_ANY = 0x00000010
COPYFILE_XATTR = 0x00000004
COPYFILE_DATA = 0x00000008
COPYFILE_NOFOLLOW_SRC = 1 << 18
COPYFILE_NOFOLLOW_DST = 1 << 19
TERMINAL_CONTENT_STATES = {"COMMITTED", "ROLLED_BACK"}
CONTENT_AWARE_MINIMUM_RECOVERY_VERSION = "1.1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA3_512_RE = re.compile(r"^[0-9a-f]{128}$")
TRANSACTION_ID_RE = re.compile(r"^MC-[0-9a-f]{16}-[0-9a-f]{8}$")
_MANAGED_RUNTIME_RELATIVES = {
    "transaction_root": Path(".naos/upgrade-v1/managed-content/transactions"),
    "lock_path": Path(".naos/upgrade-v1/managed-content/lock"),
    "manifest_path": Path(".naos/upgrade-v1/managed-content/state/manifest.json"),
    "bases_root": Path(".naos/upgrade-v1/managed-content/state/bases"),
    "receipts_root": Path(".naos/upgrade-v1/managed-content/state/receipts"),
}


def _base_pending_name(transaction_id: str, digest: str) -> str:
    return f".{digest}.{transaction_id}.pending"


def _receipt_pending_name(transaction_id: str) -> str:
    return f".{transaction_id}.json.pending"


def _manifest_pending_name(transaction_id: str) -> str:
    return f".manifest.json.{transaction_id}.pending"


def _planned_directory_paths(plan: dict[str, Any]) -> list[str]:
    """Return every plan-time absent destination directory in publish order."""

    existing = {
        str(ancestor["path"])
        for item in plan.get("paths") or []
        for ancestor in item.get("ancestor_identities") or []
    }
    missing: set[str] = set()
    for item in plan.get("paths") or []:
        relative = safe_relative_path(str(item["path"]))
        for depth in range(1, len(relative.parts)):
            candidate = Path(*relative.parts[:depth]).as_posix()
            if candidate not in existing:
                missing.add(candidate)
    return sorted(missing, key=lambda value: (len(Path(value).parts), value))


def _planned_directory_publish_paths(plan: dict[str, Any]) -> list[str]:
    """Return missing directories in the order target traversal creates them."""

    existing = {
        str(ancestor["path"])
        for item in plan.get("paths") or []
        for ancestor in item.get("ancestor_identities") or []
    }
    result: list[str] = []
    observed: set[str] = set()
    for item in plan.get("paths") or []:
        relative = safe_relative_path(str(item["path"]))
        for depth in range(1, len(relative.parts)):
            candidate = Path(*relative.parts[:depth]).as_posix()
            if candidate not in existing and candidate not in observed:
                observed.add(candidate)
                result.append(candidate)
    return result


def _planned_directory_staging(plan: dict[str, Any]) -> dict[str, str]:
    return {
        relative: f"{index:06d}"
        for index, relative in enumerate(_planned_directory_paths(plan))
    }


class TransactionPrimitiveError(RuntimeError):
    """Raised when a required transaction primitive cannot be proven."""


@dataclass(frozen=True)
class CreateOnlyTransactionOutcome:
    status: str
    transaction_id: str | None
    receipt_path: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class _ReconciliationOutcome:
    """Classify rollback reconciliation without conflating content drift and failure."""

    status: str
    detail: str | None = None

    @property
    def reconciled(self) -> bool:
        return self.status == "reconciled"


def _reconciled() -> _ReconciliationOutcome:
    return _ReconciliationOutcome("reconciled")


def _content_conflict(detail: str) -> _ReconciliationOutcome:
    return _ReconciliationOutcome("content_conflict", detail)


def _rollback_failure(detail: str) -> _ReconciliationOutcome:
    return _ReconciliationOutcome("rollback_failure", detail)


def _require_canonical_runtime_paths(
    root: Path,
    *,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> None:
    """Bind every transaction artifact to the one provenance-owned runtime."""

    supplied = {
        "transaction_root": transaction_root,
        "lock_path": lock_path,
        "manifest_path": manifest_path,
        "bases_root": bases_root,
        "receipts_root": receipts_root,
    }
    root_metadata = os.lstat(root)
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise TransactionPrimitiveError("Managed-content project root is unsafe.")
    for name, relative in _MANAGED_RUNTIME_RELATIVES.items():
        expected = root / relative
        if supplied[name] != expected:
            raise TransactionPrimitiveError(
                f"Managed-content {name} is outside its canonical provenance binding."
            )
        current = root
        for component in relative.parts[:-1]:
            current /= component
            try:
                ancestor = os.lstat(current)
            except FileNotFoundError as exc:
                raise TransactionPrimitiveError(
                    f"Managed-content {name} has a missing runtime ancestor."
                ) from exc
            if (
                stat.S_ISLNK(ancestor.st_mode)
                or not stat.S_ISDIR(ancestor.st_mode)
                or ancestor.st_dev != root_metadata.st_dev
            ):
                raise TransactionPrimitiveError(
                    f"Managed-content {name} has an unsafe runtime ancestor."
                )
        try:
            metadata = os.lstat(expected)
        except FileNotFoundError:
            if name == "manifest_path":
                continue
            raise TransactionPrimitiveError(
                f"Managed-content {name} is unavailable at its canonical path."
            )
        if metadata.st_dev != root_metadata.st_dev or stat.S_ISLNK(metadata.st_mode):
            raise TransactionPrimitiveError(
                f"Managed-content {name} has unsupported filesystem topology."
            )
        if name in {"transaction_root", "bases_root", "receipts_root"}:
            valid = stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700
        else:
            valid = (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
            )
        if not valid:
            raise TransactionPrimitiveError(
                f"Managed-content {name} is unsafe at its canonical path."
            )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_leaf_bytes(name: str) -> bytes:
    """Encode one renameatx_np leaf without permitting path traversal."""

    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
    ):
        raise TransactionPrimitiveError(
            "Directory-handle rename names must be single path components."
        )
    return os.fsencode(name)


def rename_no_replace(source: Path, destination: Path) -> None:
    """Atomically publish a path only when the destination is absent on macOS."""

    if platform.system() == "Linux":
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        source_fd = os.open(source.parent, directory_flags)
        try:
            destination_fd = os.open(destination.parent, directory_flags)
            try:
                linux_primitives.rename_at(
                    source_fd, source.name, destination_fd, destination.name
                )
            finally:
                os.close(destination_fd)
        finally:
            os.close(source_fd)
        return
    if platform.system() != "Darwin":
        raise TransactionPrimitiveError(
            "Atomic no-replace publication requires a native POSIX adapter."
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = libc.renamex_np
    renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex_np.restype = ctypes.c_int
    result = renamex_np(os.fsencode(source), os.fsencode(destination), RENAME_EXCL)
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), str(destination))
    raise OSError(error_number, os.strerror(error_number), str(destination))


def rename_no_replace_at(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    """Atomically publish a leaf relative to already-open directory handles."""

    if platform.system() == "Linux":
        _rename_leaf_bytes(source_name)
        _rename_leaf_bytes(destination_name)
        linux_primitives.rename_at(
            source_directory_fd,
            source_name,
            destination_directory_fd,
            destination_name,
            exchange=False,
        )
        return
    if platform.system() != "Darwin":
        raise TransactionPrimitiveError(
            "Directory-handle no-replace publication requires the macOS adapter."
        )
    source_leaf = _rename_leaf_bytes(source_name)
    destination_leaf = _rename_leaf_bytes(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = libc.renameatx_np
    renameatx_np.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        source_directory_fd,
        source_leaf,
        destination_directory_fd,
        destination_leaf,
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), destination_name)
    raise OSError(error_number, os.strerror(error_number), destination_name)


def rename_exchange_at(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    """Atomically exchange two Darwin leaves beneath held directory handles."""

    if platform.system() == "Linux":
        _rename_leaf_bytes(source_name)
        _rename_leaf_bytes(destination_name)
        linux_primitives.rename_at(
            source_directory_fd,
            source_name,
            destination_directory_fd,
            destination_name,
            exchange=True,
        )
        return
    if platform.system() != "Darwin":
        raise TransactionPrimitiveError(
            "UNSUPPORTED_METADATA: atomic replacement is available only through "
            "the executed Darwin adapter."
        )
    source_leaf = _rename_leaf_bytes(source_name)
    destination_leaf = _rename_leaf_bytes(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = libc.renameatx_np
    renameatx_np.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx_np.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameatx_np(
        source_directory_fd,
        source_leaf,
        destination_directory_fd,
        destination_leaf,
        RENAME_SWAP | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


class StableFileLock:
    """A stable flock-backed lock; persisted metadata is diagnostic only."""

    def __init__(self, path: Path, metadata: dict[str, Any]) -> None:
        self.path = path
        self.metadata = metadata
        self.descriptor: int | None = None

    def acquire(self) -> "StableFileLock":
        if fcntl is None:
            raise TransactionPrimitiveError("Stable flock support is unavailable on this platform.")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags)
        try:
            opened = os.fstat(descriptor)
            live = os.lstat(self.path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (live.st_dev, live.st_ino)
            ):
                raise TransactionPrimitiveError(
                    f"Stable lock file is unsafe: {self.path}"
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise TransactionPrimitiveError(
                    f"Repository-intelligence transaction lock is held: {self.path}"
                ) from exc
        except BaseException:
            os.close(descriptor)
            raise
        # The kernel lock is the only authority.  Acquiring it deliberately
        # leaves the pre-created lock-file bytes and metadata unchanged so an
        # idempotent operation has no persistent lock-side effect.
        self.descriptor = descriptor
        return self

    def release(self) -> None:
        descriptor = self.descriptor
        if descriptor is None:
            return
        self.descriptor = None
        if fcntl is None:  # pragma: no cover - cannot follow a successful acquire.
            os.close(descriptor)
            return
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "StableFileLock":
        return self.acquire()

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()


def lock_observation(path: Path) -> dict[str, Any]:
    """Probe the kernel lock without changing persisted lock bytes.

    The nonblocking exclusive probe can briefly contend with a writer, which
    fails closed and may retry. The result is only a point-in-time observation;
    even ``available`` never authorizes a writer or replaces its own acquisition.
    Persisted PID metadata is diagnostic only.
    """

    if fcntl is None:
        return {
            "status": "unsupported",
            "path": str(path),
            "error": "stable flock support is unavailable",
        }
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {"status": "absent", "path": str(path)}
    except (OSError, ContentPathError) as exc:
        return {"status": "invalid", "path": str(path), "error": str(exc)}
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            return {"status": "invalid", "path": str(path), "error": "unsafe lock file"}
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            held = True
        else:
            held = False
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, 16_384)
        try:
            metadata = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            metadata = {"invalid_metadata": True}
        return {
            "status": "present",
            "path": str(path),
            "kernel_lock": "held" if held else "available",
            "metadata": metadata,
            "metadata_is_authority": False,
        }
    finally:
        os.close(descriptor)


def _safe_json_object(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TransactionPrimitiveError(f"Unsafe transaction JSON: {path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TransactionPrimitiveError(f"Transaction JSON changed while read: {path}")
    finally:
        os.close(descriptor)
    value = loads_strict_json(b"".join(chunks))
    if not isinstance(value, dict):
        raise TransactionPrimitiveError(f"Transaction JSON must be an object: {path}")
    return value


def _safe_json_object_at(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
) -> dict[str, Any]:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise TransactionPrimitiveError(f"Unsafe transaction JSON: {label}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TransactionPrimitiveError(
                f"Transaction JSON changed while read: {label}"
            )
    finally:
        os.close(descriptor)
    value = loads_strict_json(b"".join(chunks))
    if not isinstance(value, dict):
        raise TransactionPrimitiveError(
            f"Transaction JSON must be an object: {label}"
        )
    return value


def _write_bytes_new(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def _write_json_new(path: Path, value: dict[str, Any]) -> None:
    _write_bytes_new(path, canonical_bytes(value) + b"\n")


def _write_bytes_new_at(
    parent_descriptor: int,
    name: str,
    data: bytes,
    *,
    mode: int = 0o600,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(
        name,
        flags,
        mode,
        dir_fd=parent_descriptor,
    )
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent_descriptor)


def _write_json_new_at(
    parent_descriptor: int,
    name: str,
    value: dict[str, Any],
) -> None:
    _write_bytes_new_at(
        parent_descriptor,
        name,
        canonical_bytes(value) + b"\n",
    )


def _validate_pending_regular_at(parent_descriptor: int, name: str) -> None:
    metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise TransactionPrimitiveError(
            f"Managed-content pending evidence is unsafe: {name}"
        )


def _publish_bytes_new_at(
    parent_descriptor: int,
    name: str,
    data: bytes,
    *,
    pending_name: str,
) -> None:
    """Durably publish a new evidence file without exposing partial final bytes."""

    try:
        os.stat(pending_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        _validate_pending_regular_at(parent_descriptor, pending_name)
        raise TransactionPrimitiveError(
            f"Managed-content pending evidence requires recovery: {pending_name}"
        )
    _write_bytes_new_at(parent_descriptor, pending_name, data)
    if _read_regular_file_bytes_at(parent_descriptor, pending_name) != data:
        raise TransactionPrimitiveError(
            f"Managed-content pending evidence validation failed: {pending_name}"
        )
    rename_no_replace_at(
        parent_descriptor,
        pending_name,
        parent_descriptor,
        name,
    )
    os.fsync(parent_descriptor)


def _publish_json_new_at(
    parent_descriptor: int,
    name: str,
    value: dict[str, Any],
    *,
    pending_name: str,
) -> None:
    _publish_bytes_new_at(
        parent_descriptor,
        name,
        canonical_bytes(value) + b"\n",
        pending_name=pending_name,
    )


def _replace_json_atomically_at(
    parent_descriptor: int,
    name: str,
    value: dict[str, Any],
    *,
    pending_name: str,
    expected_current: dict[str, Any],
) -> None:
    """Replace JSON atomically after two exact comparisons with the loaded base."""

    current = _safe_json_object_at(parent_descriptor, name, label=name)
    if current != expected_current:
        raise TransactionPrimitiveError(
            f"Managed-content evidence changed before replacement: {name}"
        )
    try:
        os.stat(pending_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        _validate_pending_regular_at(parent_descriptor, pending_name)
        raise TransactionPrimitiveError(
            f"Managed-content pending evidence requires recovery: {pending_name}"
        )
    data = canonical_bytes(value) + b"\n"
    _write_bytes_new_at(parent_descriptor, pending_name, data)
    if _read_regular_file_bytes_at(parent_descriptor, pending_name) != data:
        raise TransactionPrimitiveError(
            f"Managed-content pending evidence validation failed: {pending_name}"
        )
    current = _safe_json_object_at(parent_descriptor, name, label=name)
    if current != expected_current:
        raise TransactionPrimitiveError(
            f"Managed-content evidence changed during replacement: {name}"
        )
    os.rename(
        pending_name,
        name,
        src_dir_fd=parent_descriptor,
        dst_dir_fd=parent_descriptor,
    )
    os.fsync(parent_descriptor)


def _descriptor_content_identity(descriptor: int) -> dict[str, object]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise TransactionPrimitiveError("Managed-content source descriptor is unsafe.")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    after = os.fstat(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise TransactionPrimitiveError(
            "Managed-content source changed while it was read."
        )
    return {
        "kind": "file",
        "mode": stat.S_IMODE(before.st_mode),
        "size": before.st_size,
        "sha256": digest.hexdigest(),
    }


def _copy_regular_file_new(
    source: Path,
    destination: Path,
    *,
    expected_content: dict[str, object],
    expected_metadata: dict[str, object],
    creation_identity: dict[str, object],
) -> None:
    """Copy data and supported POSIX metadata into exclusive private staging.

    Failed staging is retained; unsealed preparation has no delete authority.
    This helper has no authority to unlink a name after an open/copy failure.
    """

    source_descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    destination_descriptor: int | None = None
    try:
        source_content = _descriptor_content_identity(source_descriptor)
        observed_source_metadata = observe_created_file_metadata_fd(source_descriptor)
        source_metadata = source_metadata_contract(observed_source_metadata)
        if source_content != expected_content or source_metadata != expected_metadata:
            raise TransactionPrimitiveError(
                f"Managed-content source changed before staging: {source}"
            )
        if (
            not supported_metadata_flags(source_metadata)
            or not supported_source_xattrs(source_metadata)
            or source_metadata.get("acl_entries") != []
            or source_metadata.get("uid") != os.getuid()
            or int(source_metadata.get("mode") or 0) & ~0o777
        ):
            raise TransactionPrimitiveError(
                "UNSUPPORTED_METADATA: source flags, xattr namespace, ACL, owner, or special "
                f"mode is outside the selected POSIX create-only adapter: {source}"
            )
        destination_descriptor = os.open(
            destination,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if platform.system() == "Linux":
            linux_primitives.copy_data_and_xattrs(
                source_descriptor, destination_descriptor
            )
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            fcopyfile = libc.fcopyfile
            fcopyfile.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_uint32,
            ]
            fcopyfile.restype = ctypes.c_int
            os.lseek(source_descriptor, 0, os.SEEK_SET)
            if (
                fcopyfile(
                    source_descriptor,
                    destination_descriptor,
                    None,
                    COPYFILE_DATA
                    | COPYFILE_XATTR
                    | COPYFILE_NOFOLLOW_SRC
                    | COPYFILE_NOFOLLOW_DST,
                )
                != 0
            ):
                error_number = ctypes.get_errno()
                raise OSError(
                    error_number,
                    os.strerror(error_number),
                    str(destination),
                )
        os.fchown(
            destination_descriptor,
            int(creation_identity["uid"]),
            int(creation_identity["gid"]),
        )
        os.fchmod(destination_descriptor, int(expected_metadata["mode"]))
        os.fsync(destination_descriptor)
        if (
            _descriptor_content_identity(source_descriptor) != expected_content
            or source_metadata_contract(
                observe_created_file_metadata_fd(source_descriptor)
            )
            != expected_metadata
            or _descriptor_content_identity(destination_descriptor) != expected_content
        ):
            raise TransactionPrimitiveError(
                f"Managed-content staged content validation failed: {source}"
            )
        destination_metadata = observe_created_file_metadata_fd(destination_descriptor)
        if not metadata_preservation_matches(
            expected_metadata,
            destination_metadata,
            creation_identity=creation_identity,
        ):
            raise TransactionPrimitiveError(
                f"Managed-content staged metadata validation failed: {source}"
            )
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)
    fsync_directory(destination.parent)


def _copy_regular_file_new_at(
    source: Path,
    destination_parent_descriptor: int,
    destination_name: str,
    *,
    expected_content: dict[str, object],
    expected_metadata: dict[str, object],
    creation_identity: dict[str, object],
) -> None:
    """Stage through a held parent; preserve all leaves if the copy fails."""
    source_descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    destination_descriptor: int | None = None
    try:
        source_content = _descriptor_content_identity(source_descriptor)
        source_metadata = source_metadata_contract(
            observe_created_file_metadata_fd(source_descriptor)
        )
        if source_content != expected_content or source_metadata != expected_metadata:
            raise TransactionPrimitiveError(
                f"Managed-content source changed before staging: {source}"
            )
        if (
            not supported_metadata_flags(source_metadata)
            or not supported_source_xattrs(source_metadata)
            or source_metadata.get("acl_entries") != []
            or source_metadata.get("uid") != os.getuid()
            or int(source_metadata.get("mode") or 0) & ~0o777
        ):
            raise TransactionPrimitiveError(
                "UNSUPPORTED_METADATA: source flags, xattr namespace, ACL, owner, or special "
                f"mode is outside the selected POSIX create-only adapter: {source}"
            )
        destination_descriptor = os.open(
            destination_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=destination_parent_descriptor,
        )
        if platform.system() == "Linux":
            linux_primitives.copy_data_and_xattrs(
                source_descriptor, destination_descriptor
            )
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            fcopyfile = libc.fcopyfile
            fcopyfile.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_uint32,
            ]
            fcopyfile.restype = ctypes.c_int
            os.lseek(source_descriptor, 0, os.SEEK_SET)
            if (
                fcopyfile(
                    source_descriptor,
                    destination_descriptor,
                    None,
                    COPYFILE_DATA
                    | COPYFILE_XATTR
                    | COPYFILE_NOFOLLOW_SRC
                    | COPYFILE_NOFOLLOW_DST,
                )
                != 0
            ):
                error_number = ctypes.get_errno()
                raise OSError(
                    error_number,
                    os.strerror(error_number),
                    destination_name,
                )
        os.fchown(
            destination_descriptor,
            int(creation_identity["uid"]),
            int(creation_identity["gid"]),
        )
        os.fchmod(destination_descriptor, int(expected_metadata["mode"]))
        os.fsync(destination_descriptor)
        if (
            _descriptor_content_identity(source_descriptor) != expected_content
            or source_metadata_contract(
                observe_created_file_metadata_fd(source_descriptor)
            )
            != expected_metadata
            or _descriptor_content_identity(destination_descriptor) != expected_content
            or not metadata_preservation_matches(
                expected_metadata,
                observe_created_file_metadata_fd(destination_descriptor),
                creation_identity=creation_identity,
            )
        ):
            raise TransactionPrimitiveError(
                f"Managed-content staged content or metadata validation failed: {source}"
            )
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)
    os.fsync(destination_parent_descriptor)


def _replace_json(path: Path, value: dict[str, Any]) -> None:
    pending = path.with_name(f".{path.name}.pending")
    try:
        pending.unlink()
    except FileNotFoundError:
        pass
    _write_bytes_new(pending, canonical_bytes(value) + b"\n")
    os.replace(pending, path)
    fsync_directory(path.parent)


def _replace_json_at(
    parent_descriptor: int,
    name: str,
    value: dict[str, Any],
) -> None:
    pending = f".{name}.pending"
    try:
        metadata = os.stat(
            pending,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    else:
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TransactionPrimitiveError(
                f"Unsafe pending transaction JSON: {pending}"
            )
        os.unlink(pending, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    existing = os.stat(
        name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise TransactionPrimitiveError(f"Unsafe transaction JSON replacement: {name}")
    _write_bytes_new_at(
        parent_descriptor,
        pending,
        canonical_bytes(value) + b"\n",
    )
    os.rename(
        pending,
        name,
        src_dir_fd=parent_descriptor,
        dst_dir_fd=parent_descriptor,
    )
    os.fsync(parent_descriptor)


def _with_sha256_integrity(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "scope": "object_without_integrity",
        "value": canonical_sha256(result),
    }
    return result


def _validate_sha256_integrity(value: dict[str, Any], *, label: str) -> None:
    integrity = value.get("integrity")
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"algorithm", "canonicalization", "scope", "value"}
        or integrity.get("algorithm") != "sha256"
        or integrity.get("canonicalization") != "rfc8785"
        or integrity.get("scope") != "object_without_integrity"
        or not isinstance(integrity.get("value"), str)
        or SHA256_RE.fullmatch(str(integrity.get("value"))) is None
        or integrity.get("value")
        != canonical_sha256(
            {key: item for key, item in value.items() if key != "integrity"}
        )
    ):
        raise TransactionPrimitiveError(f"{label} integrity is invalid.")


def _file_matches(path: Path, expected: dict[str, Any]) -> bool:
    try:
        identity = regular_file_identity(path)
    except (OSError, ContentPlanningError):
        return False
    return (
        identity.mode == expected.get("mode")
        and identity.size == expected.get("size")
        and identity.sha256 == expected.get("sha256")
    )


def _managed_file_matches(
    root: Path,
    relative: str | Path,
    expected_content: dict[str, Any],
    expected_metadata: dict[str, Any],
    expected_ancestors: list[dict[str, Any]] | None = None,
) -> bool:
    try:
        content, metadata, ancestors = observe_regular_file_beneath(root, relative)
    except (OSError, ContentPathError):
        return False
    current_ancestors = {str(item["path"]): item for item in ancestors}
    return (
        content == expected_content
        and created_metadata_identity_matches(
            metadata, expected_metadata, expected_type="regular_file"
        )
        and (
            expected_ancestors is None
            or all(
                current_ancestors.get(str(item["path"])) == item
                for item in expected_ancestors
            )
        )
    )


def _managed_file_matches_at(
    root_descriptor: int,
    relative: str | Path,
    expected_content: dict[str, Any],
    expected_metadata: dict[str, Any],
    expected_ancestors: list[dict[str, Any]] | None = None,
) -> bool:
    try:
        content, metadata, ancestors = observe_regular_file_beneath_fd(
            root_descriptor,
            relative,
        )
    except (OSError, ContentPathError):
        return False
    current_ancestors = {str(item["path"]): item for item in ancestors}
    return (
        content == expected_content
        and created_metadata_identity_matches(
            metadata, expected_metadata, expected_type="regular_file"
        )
        and (
            expected_ancestors is None
            or all(
                current_ancestors.get(str(item["path"])) == item
                for item in expected_ancestors
            )
        )
    )


def _regular_file_identity_at(
    parent_descriptor: int,
    name: str,
) -> dict[str, object]:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_descriptor,
    )
    try:
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise TransactionPrimitiveError(
                f"Unsafe descriptor-relative regular file: {name}"
            )
        identity = _descriptor_content_identity(descriptor)
        return identity
    finally:
        os.close(descriptor)


def _file_matches_at(
    parent_descriptor: int,
    name: str,
    expected: dict[str, Any],
) -> bool:
    try:
        identity = _regular_file_identity_at(parent_descriptor, name)
    except (FileNotFoundError, OSError, TransactionPrimitiveError):
        return False
    return identity == expected


def _secure_regular_file_sha256(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TransactionPrimitiveError(f"Unsafe content-addressed file: {path}")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TransactionPrimitiveError(
                f"Content-addressed file changed while read: {path}"
            )
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _secure_regular_file_sha256_at(
    parent_descriptor: int,
    name: str,
) -> str:
    return str(_regular_file_identity_at(parent_descriptor, name)["sha256"])


def _content_addressed_base_matches_at(
    parent_descriptor: int,
    name: str,
    expected_sha256: str,
) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            return False
        return _secure_regular_file_sha256_at(parent_descriptor, name) == expected_sha256
    except (FileNotFoundError, OSError, TransactionPrimitiveError):
        return False


def _read_regular_file_bytes_at(
    parent_descriptor: int,
    name: str,
) -> bytes:
    descriptor = _open_regular_leaf_at(parent_descriptor, name)
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TransactionPrimitiveError(
                f"Managed-content runtime file changed while read: {name}"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_receipt(
    value: dict[str, Any],
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> str:
    expected_keys = {
        "schema",
        "project_id",
        "scope_integrity_sha3_512",
        "source_policy_sha256",
        "transaction_id",
        "plan_sha256",
        "status",
        "paths",
        "created_metadata",
        "replacement_performed",
        "integrity",
    }
    _validate_sha256_integrity(value, label="managed-content receipt")
    if set(value) != expected_keys:
        raise TransactionPrimitiveError("Managed-content receipt shape is invalid.")
    expected = {
        "schema": "naos.upgrade.managed_content_receipt.v1",
        "project_id": project_id,
        "scope_integrity_sha3_512": scope_integrity_sha3_512,
        "source_policy_sha256": source_policy_sha256,
        "transaction_id": transaction_id,
        "plan_sha256": plan["plan_sha256"],
        "status": "COMMITTED",
        "paths": plan["paths"],
        "replacement_performed": False,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise TransactionPrimitiveError(
                f"Managed-content receipt {field} binding is invalid."
            )
    created_metadata = value.get("created_metadata")
    planned_paths = {str(item["path"]) for item in plan["paths"]}
    if (
        not isinstance(created_metadata, dict)
        or set(created_metadata) != planned_paths
    ):
        raise TransactionPrimitiveError(
            "Managed-content receipt created-metadata inventory is invalid."
        )
    for identity in created_metadata.values():
        _validate_created_metadata(identity, expected_type="regular_file")
    return canonical_sha256(value)


def _load_receipt(
    path: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    value = _safe_json_object(path)
    digest = _validate_receipt(
        value,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        transaction_id=transaction_id,
        plan=plan,
    )
    return value, digest


def _load_receipt_at(
    receipts_descriptor: int,
    name: str,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    value = _safe_json_object_at(
        receipts_descriptor,
        name,
        label=f"managed-content receipt {name}",
    )
    digest = _validate_receipt(
        value,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        transaction_id=transaction_id,
        plan=plan,
    )
    return value, digest


def _content_mutation_items(plan: dict[str, Any]) -> list[dict[str, Any]]:
    items = [
        item
        for item in plan.get("paths") or []
        if isinstance(item, dict)
        and isinstance(item.get("mutation"), dict)
        and item["mutation"].get("eligible") is True
    ]
    if not items:
        raise TransactionPrimitiveError(
            "Content-aware plan contains no eligible mutation."
        )
    for item in items:
        kind = item["mutation"].get("kind")
        ownership = item.get("ownership") or {}
        if kind == "replace" and (
            item.get("action") != "UPDATE_FROM_UPSTREAM"
            or ownership.get("before") != "kit_owned_derived"
            or ownership.get("after") != "kit_owned_derived"
            or item.get("content_state") != "PROPOSE_UPDATE_FROM_UPSTREAM"
        ):
            raise TransactionPrimitiveError(
                "Managed-content replacement authority is invalid: "
                + str(item.get("path"))
            )
        if kind == "create" and not str(item.get("action") or "").startswith(
            "CREATE_"
        ):
            raise TransactionPrimitiveError(
                "Managed-content creation authority is invalid: "
                + str(item.get("path"))
            )
        if kind not in {"create", "replace"}:
            raise TransactionPrimitiveError(
                "Managed-content mutation kind is unsupported: "
                + str(item.get("path"))
            )
    return items


def _publication_adapter(kind: str, installed_metadata: dict[str, Any]) -> str:
    adapters = {
        ("Darwin", "create"): "darwin_rename_excl",
        ("Darwin", "replace"): "darwin_rename_swap",
        ("Linux", "create"): "linux_renameat2_noreplace",
        ("Linux", "replace"): "linux_renameat2_exchange",
    }
    try:
        return adapters[(installed_metadata.get("platform"), kind)]
    except (KeyError, TypeError) as exc:
        raise TransactionPrimitiveError("Unsupported publication adapter binding") from exc


def _validate_receipt_v2(
    value: dict[str, Any],
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> str:
    expected_keys = {
        "schema",
        "minimum_recovery_naos_version",
        "project_id",
        "scope_integrity_sha3_512",
        "source_policy_sha256",
        "transaction_id",
        "plan_sha256",
        "status",
        "actions",
        "replacement_performed",
        "integrity",
    }
    _validate_sha256_integrity(value, label="managed-content v2 receipt")
    if set(value) != expected_keys:
        raise TransactionPrimitiveError("Managed-content v2 receipt shape is invalid.")
    expected = {
        "schema": "naos.upgrade.managed_content_receipt.v2",
        "minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION,
        "project_id": project_id,
        "scope_integrity_sha3_512": scope_integrity_sha3_512,
        "source_policy_sha256": source_policy_sha256,
        "transaction_id": transaction_id,
        "plan_sha256": plan.get("plan_sha256"),
        "status": "COMMITTED",
    }
    if any(value.get(key) != member for key, member in expected.items()):
        raise TransactionPrimitiveError(
            "Managed-content v2 receipt provenance binding is invalid."
        )
    mutations = _content_mutation_items(plan)
    actions = value.get("actions")
    if not isinstance(actions, list) or len(actions) != len(mutations):
        raise TransactionPrimitiveError(
            "Managed-content v2 receipt action inventory is invalid."
        )
    expected_action_keys = {
        "path",
        "kind",
        "before",
        "after",
        "before_metadata",
        "after_metadata",
        "installed_metadata",
        "backup_metadata",
        "base_blob",
        "publication_adapter",
    }
    for action, planned in zip(actions, mutations, strict=True):
        if not isinstance(action, dict) or set(action) != expected_action_keys:
            raise TransactionPrimitiveError(
                "Managed-content v2 receipt action shape is invalid."
            )
        kind = planned["mutation"]["kind"]
        after = _content_aware_after_identity(planned)
        installed = action.get("installed_metadata")
        _validate_created_metadata(installed, expected_type="regular_file")
        backup = action.get("backup_metadata")
        if kind == "replace":
            _validate_created_metadata(backup, expected_type="regular_file")
        elif backup is not None:
            raise TransactionPrimitiveError(
                "Managed-content create receipt unexpectedly binds a backup."
            )
        if (
            action.get("path") != planned.get("path")
            or action.get("kind") != kind
            or action.get("before") != planned.get("before")
            or action.get("after") != planned.get("after")
            or action.get("before_metadata") != planned.get("before_metadata")
            or action.get("after_metadata") != planned.get("after_metadata")
            or action.get("base_blob")
            != {"path": after["sha256"], "sha256": after["sha256"]}
            or action.get("publication_adapter")
            != _publication_adapter(kind, installed)
        ):
            raise TransactionPrimitiveError(
                "Managed-content v2 receipt action binding is invalid: "
                + str(planned.get("path"))
            )
    expected_replacement = any(
        item["mutation"]["kind"] == "replace" for item in mutations
    )
    if value.get("replacement_performed") is not expected_replacement:
        raise TransactionPrimitiveError(
            "Managed-content v2 replacement receipt binding is invalid."
        )
    return canonical_sha256(value)


def _load_receipt_any_at(
    receipts_descriptor: int,
    name: str,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    value = _safe_json_object_at(
        receipts_descriptor,
        name,
        label=f"managed-content receipt {name}",
    )
    schema = value.get("schema")
    if schema == "naos.upgrade.managed_content_receipt.v1":
        digest = _validate_receipt(
            value,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction_id,
            plan=plan,
        )
        return value, digest, "v1"
    if schema == "naos.upgrade.managed_content_receipt.v2":
        digest = _validate_receipt_v2(
            value,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction_id,
            plan=plan,
        )
        return value, digest, "v2"
    minimum = value.get("minimum_recovery_naos_version")
    suffix = f" Minimum NAOS version: {minimum}." if isinstance(minimum, str) else ""
    raise TransactionPrimitiveError(
        "Managed-content receipt schema is unsupported." + suffix
    )


def _load_receipt_any(
    path: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    return _validate_receipt_any(
        _safe_json_object(path), project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        transaction_id=transaction_id, plan=plan,
    )


def _validate_receipt_any(
    value: dict[str, Any],
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    schema = value.get("schema")
    if schema == "naos.upgrade.managed_content_receipt.v1":
        digest = _validate_receipt(
            value,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction_id,
            plan=plan,
        )
        return value, digest, "v1"
    if schema == "naos.upgrade.managed_content_receipt.v2":
        digest = _validate_receipt_v2(
            value,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction_id,
            plan=plan,
        )
        return value, digest, "v2"
    minimum = value.get("minimum_recovery_naos_version")
    suffix = f" Minimum NAOS version: {minimum}." if isinstance(minimum, str) else ""
    raise TransactionPrimitiveError(
        "Managed-content receipt schema is unsupported." + suffix
    )


def _receipt_historical_base_digests(
    receipt: dict[str, Any],
    *,
    receipt_version: str,
    plan: dict[str, Any],
) -> set[str]:
    """Return every immutable base required to recover a bound transaction."""

    digests: set[str] = set()
    identities: list[object]
    if receipt_version == "v1":
        identities = [
            item.get("source")
            for item in plan.get("paths") or []
            if isinstance(item, dict)
        ]
    elif receipt_version == "v2":
        identities = [
            action.get(field)
            for action in receipt.get("actions") or []
            if isinstance(action, dict)
            for field in ("before", "after")
        ]
    else:  # pragma: no cover - receipt dispatch rejects unknown generations.
        raise TransactionPrimitiveError(
            "Managed-content receipt generation is unsupported."
        )
    for identity in identities:
        if not isinstance(identity, dict) or identity.get("presence") == "absent":
            continue
        digest = identity.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise TransactionPrimitiveError(
                "Managed-content historical base identity is invalid."
            )
        digests.add(digest)
    if not digests:
        raise TransactionPrimitiveError(
            "Managed-content transaction has no recoverable historical base."
        )
    return digests


def _validate_manifest(
    value: dict[str, Any],
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    _validate_manifest_record(
        value,
        validate_plan=lambda plan: validate_create_only_plan(plan, project_root=project_root),
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )


def _validate_manifest_record(
    value: dict[str, Any],
    *,
    validate_plan: Callable[[dict[str, Any]], Any],
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    expected_keys = {
        "schema",
        "project_id",
        "scope_integrity_sha3_512",
        "source_policy_sha256",
        "previous_integrity_sha256",
        "last_transaction_id",
        "last_plan_sha256",
        "entries",
        "transactions",
        "integrity",
    }
    _validate_sha256_integrity(value, label="managed-content manifest")
    if set(value) != expected_keys:
        raise TransactionPrimitiveError("Managed-content manifest shape is invalid.")
    if value.get("schema") != "naos.upgrade.managed_content_manifest.v1":
        raise TransactionPrimitiveError("Managed-content manifest schema is unsupported.")
    if (
        value.get("project_id") != project_id
        or value.get("scope_integrity_sha3_512") != scope_integrity_sha3_512
        or value.get("source_policy_sha256") != source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content manifest provenance binding is invalid."
        )
    previous = value.get("previous_integrity_sha256")
    if previous is not None and (
        not isinstance(previous, str) or SHA256_RE.fullmatch(previous) is None
    ):
        raise TransactionPrimitiveError(
            "Managed-content manifest previous-integrity binding is invalid."
        )
    entries = value.get("entries")
    transactions = value.get("transactions")
    if (
        not isinstance(entries, list)
        or not entries
        or not isinstance(transactions, list)
        or not transactions
    ):
        raise TransactionPrimitiveError(
            "Managed-content manifest inventories are invalid."
        )
    transaction_by_id: dict[str, dict[str, Any]] = {}
    expected_transaction_keys = {
        "transaction_id",
        "plan",
        "receipt_sha256",
    }
    for transaction in transactions:
        if not isinstance(transaction, dict) or set(transaction) != expected_transaction_keys:
            raise TransactionPrimitiveError(
                "Managed-content manifest transaction shape is invalid."
            )
        transaction_id = transaction.get("transaction_id")
        transaction_plan = transaction.get("plan")
        if (
            not isinstance(transaction_id, str)
            or TRANSACTION_ID_RE.fullmatch(transaction_id) is None
            or transaction_id in transaction_by_id
            or not isinstance(transaction.get("receipt_sha256"), str)
            or SHA256_RE.fullmatch(str(transaction.get("receipt_sha256"))) is None
            or not isinstance(transaction_plan, dict)
        ):
            raise TransactionPrimitiveError(
                "Managed-content manifest transaction binding is invalid."
            )
        validate_plan(transaction_plan)
        transaction_by_id[transaction_id] = transaction
    last_transaction_id = value.get("last_transaction_id")
    if (
        transactions[-1].get("transaction_id") != last_transaction_id
        or (transactions[-1].get("plan") or {}).get("plan_sha256")
        != value.get("last_plan_sha256")
    ):
        raise TransactionPrimitiveError(
            "Managed-content manifest last-transaction binding is invalid."
        )
    expected_entry_keys = {
        "path",
        "ownership",
        "creation_policy",
        "base",
        "source_metadata",
        "base_blob",
        "created_metadata",
        "introduced_by_transaction",
        "receipt_sha256",
    }
    observed_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise TransactionPrimitiveError(
                "Managed-content manifest entry shape is invalid."
            )
        path = entry.get("path")
        if not isinstance(path, str) or path in observed_paths:
            raise TransactionPrimitiveError(
                "Managed-content manifest path inventory is invalid."
            )
        safe_relative_path(path)
        observed_paths.add(path)
        base = entry.get("base")
        source_metadata = entry.get("source_metadata")
        base_blob = entry.get("base_blob")
        if (
            not isinstance(base, dict)
            or set(base) != {"kind", "mode", "size", "sha256"}
            or base.get("kind") != "file"
            or isinstance(base.get("mode"), bool)
            or not isinstance(base.get("mode"), int)
            or isinstance(base.get("size"), bool)
            or not isinstance(base.get("size"), int)
            or base.get("size", -1) < 0
            or not isinstance(base.get("sha256"), str)
            or SHA256_RE.fullmatch(str(base.get("sha256"))) is None
            or not isinstance(base_blob, dict)
            or set(base_blob) != {"path", "sha256"}
            or base_blob.get("path") != base.get("sha256")
            or base_blob.get("sha256") != base.get("sha256")
        ):
            raise TransactionPrimitiveError(
                f"Managed-content manifest base binding is invalid: {path}"
            )
        try:
            validate_source_metadata_contract(source_metadata)
        except ContentPathError as exc:
            raise TransactionPrimitiveError(str(exc)) from exc
        if source_metadata.get("mode") != base.get("mode"):
            raise TransactionPrimitiveError(
                f"Managed-content manifest source metadata differs: {path}"
            )
        _validate_created_metadata(
            entry.get("created_metadata"),
            expected_type="regular_file",
        )
        introduced = entry.get("introduced_by_transaction")
        transaction = transaction_by_id.get(str(introduced or ""))
        transaction_plan_items = {
            str(item.get("path")): item
            for item in ((transaction or {}).get("plan") or {}).get("paths") or []
            if isinstance(item, dict)
        }
        introducing_item = transaction_plan_items.get(str(path))
        if (
            transaction is None
            or introducing_item is None
            or entry.get("receipt_sha256") != transaction.get("receipt_sha256")
            or entry.get("ownership") not in OWNERSHIP_CLASSES
            or not isinstance(entry.get("creation_policy"), str)
            or entry.get("ownership") != introducing_item.get("ownership")
            or entry.get("creation_policy")
            != introducing_item.get("creation_policy")
            or entry.get("base") != introducing_item.get("source")
            or entry.get("source_metadata")
            != introducing_item.get("source_metadata")
        ):
            raise TransactionPrimitiveError(
                "Managed-content manifest introducing authority or receipt "
                f"binding is invalid: {path}"
            )
    if [str(entry["path"]) for entry in entries] != sorted(observed_paths):
        raise TransactionPrimitiveError(
            "Managed-content manifest entries are not deterministic."
        )


def _validate_transaction_plan_any(
    plan: dict[str, Any],
    *,
    project_root: Path,
) -> str:
    schema = plan.get("schema")
    if schema in {
        "naos.upgrade.create_only_plan.v1",
        "naos.upgrade.create_only_plan.v2",
    }:
        validate_create_only_plan(plan, project_root=project_root)
        return "create_only"
    if schema in CONTENT_AWARE_PLAN_SCHEMAS:
        validate_content_aware_plan(plan, project_root=project_root)
        return "content_aware"
    minimum = plan.get("minimum_recovery_naos_version")
    suffix = f" Minimum NAOS version: {minimum}." if isinstance(minimum, str) else ""
    raise TransactionPrimitiveError(
        "Managed-content transaction plan schema is unsupported." + suffix
    )


def _content_aware_after_identity(item: dict[str, Any]) -> dict[str, Any]:
    after = item.get("after")
    if not isinstance(after, dict) or after.get("presence") != "present":
        raise TransactionPrimitiveError(
            f"Managed-content v2 mutation has no installed identity: {item.get('path')}"
        )
    return {
        "kind": after["kind"],
        "mode": after["mode"],
        "size": after["size"],
        "sha256": after["sha256"],
    }


def _transaction_plan_item(
    plan: dict[str, Any],
    path: str,
) -> tuple[str, dict[str, Any]] | None:
    kind = (
        "content_aware"
        if plan.get("schema") in CONTENT_AWARE_PLAN_SCHEMAS
        else "create_only"
    )
    item = next(
        (
            member
            for member in plan.get("paths") or []
            if isinstance(member, dict) and member.get("path") == path
        ),
        None,
    )
    return (kind, item) if isinstance(item, dict) else None


def _validate_manifest_v2(
    value: dict[str, Any],
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    _validate_manifest_v2_record(
        value,
        validate_plan=lambda plan: _validate_transaction_plan_any(plan, project_root=project_root),
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )


def _validate_manifest_v2_record(
    value: dict[str, Any],
    *,
    validate_plan: Callable[[dict[str, Any]], Any],
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    expected_keys = {
        "schema",
        "minimum_recovery_naos_version",
        "project_id",
        "scope_integrity_sha3_512",
        "source_policy_sha256",
        "previous_integrity_sha256",
        "last_transaction_id",
        "last_plan_sha256",
        "entries",
        "transactions",
        "integrity",
    }
    _validate_sha256_integrity(value, label="managed-content v2 manifest")
    if set(value) != expected_keys:
        raise TransactionPrimitiveError("Managed-content v2 manifest shape is invalid.")
    if (
        value.get("schema") != "naos.upgrade.managed_content_manifest.v2"
        or value.get("minimum_recovery_naos_version")
        != CONTENT_AWARE_MINIMUM_RECOVERY_VERSION
        or value.get("project_id") != project_id
        or value.get("scope_integrity_sha3_512") != scope_integrity_sha3_512
        or value.get("source_policy_sha256") != source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content v2 manifest provenance binding is invalid."
        )
    previous = value.get("previous_integrity_sha256")
    if previous is not None and (
        not isinstance(previous, str) or SHA256_RE.fullmatch(previous) is None
    ):
        raise TransactionPrimitiveError(
            "Managed-content v2 manifest previous-integrity binding is invalid."
        )
    transactions = value.get("transactions")
    entries = value.get("entries")
    if (
        not isinstance(transactions, list)
        or not transactions
        or not isinstance(entries, list)
        or not entries
    ):
        raise TransactionPrimitiveError(
            "Managed-content v2 manifest inventories are invalid."
        )
    transaction_by_id: dict[str, dict[str, Any]] = {}
    for transaction in transactions:
        if not isinstance(transaction, dict) or set(transaction) != {
            "transaction_id",
            "plan",
            "receipt_sha256",
        }:
            raise TransactionPrimitiveError(
                "Managed-content v2 manifest transaction shape is invalid."
            )
        transaction_id = transaction.get("transaction_id")
        plan = transaction.get("plan")
        receipt_sha256 = transaction.get("receipt_sha256")
        if (
            not isinstance(transaction_id, str)
            or TRANSACTION_ID_RE.fullmatch(transaction_id) is None
            or transaction_id in transaction_by_id
            or not isinstance(plan, dict)
            or not isinstance(receipt_sha256, str)
            or SHA256_RE.fullmatch(receipt_sha256) is None
        ):
            raise TransactionPrimitiveError(
                "Managed-content v2 manifest transaction binding is invalid."
            )
        validate_plan(plan)
        transaction_by_id[transaction_id] = transaction
    last_transaction = transactions[-1]
    if (
        last_transaction.get("transaction_id") != value.get("last_transaction_id")
        or (last_transaction.get("plan") or {}).get("plan_sha256")
        != value.get("last_plan_sha256")
    ):
        raise TransactionPrimitiveError(
            "Managed-content v2 manifest last-transaction binding is invalid."
        )

    expected_entry_keys = {
        "path",
        "ownership",
        "creation_policy",
        "base",
        "source_metadata",
        "base_blob",
        "created_metadata",
        "introduced_by_transaction",
        "last_mutated_by_transaction",
        "receipt_sha256",
    }
    observed_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise TransactionPrimitiveError(
                "Managed-content v2 manifest entry shape is invalid."
            )
        path = entry.get("path")
        if not isinstance(path, str):
            raise TransactionPrimitiveError(
                "Managed-content v2 manifest path inventory is invalid."
            )
        safe_relative_path(path)
        observed_paths.append(path)
        base = entry.get("base")
        base_blob = entry.get("base_blob")
        if (
            not isinstance(base, dict)
            or set(base) != {"kind", "mode", "size", "sha256"}
            or base.get("kind") != "file"
            or isinstance(base.get("mode"), bool)
            or not isinstance(base.get("mode"), int)
            or isinstance(base.get("size"), bool)
            or not isinstance(base.get("size"), int)
            or int(base.get("size", -1)) < 0
            or not isinstance(base.get("sha256"), str)
            or SHA256_RE.fullmatch(str(base.get("sha256"))) is None
            or base_blob
            != {"path": base.get("sha256"), "sha256": base.get("sha256")}
        ):
            raise TransactionPrimitiveError(
                f"Managed-content v2 manifest base binding is invalid: {path}"
            )
        try:
            validate_source_metadata_contract(entry.get("source_metadata"))
            _validate_created_metadata(
                entry.get("created_metadata"),
                expected_type="regular_file",
            )
        except (ContentPathError, TransactionPrimitiveError) as exc:
            raise TransactionPrimitiveError(str(exc)) from exc
        introduced_id = entry.get("introduced_by_transaction")
        last_mutated_id = entry.get("last_mutated_by_transaction")
        introduced = transaction_by_id.get(str(introduced_id or ""))
        last_mutated = transaction_by_id.get(str(last_mutated_id or ""))
        if introduced is None or last_mutated is None:
            raise TransactionPrimitiveError(
                f"Managed-content v2 manifest lineage is invalid: {path}"
            )
        introduced_binding = _transaction_plan_item(introduced["plan"], path)
        current_binding = _transaction_plan_item(last_mutated["plan"], path)
        if introduced_binding is None or current_binding is None:
            raise TransactionPrimitiveError(
                f"Managed-content v2 manifest path lineage is invalid: {path}"
            )
        current_kind, current_item = current_binding
        if current_kind == "create_only":
            expected_ownership = current_item.get("ownership")
            expected_policy = current_item.get("creation_policy")
            expected_base = current_item.get("source")
            expected_metadata = current_item.get("source_metadata")
        else:
            ownership = current_item.get("ownership") or {}
            expected_ownership = ownership.get("after")
            expected_policy = ownership.get("creation_policy")
            expected_base = _content_aware_after_identity(current_item)
            expected_metadata = current_item.get("after_metadata")
        introduced_kind, introduced_item = introduced_binding
        if introduced_kind == "create_only":
            introduced_ownership = introduced_item.get("ownership")
            introduced_policy = introduced_item.get("creation_policy")
        else:
            introduced_ownership = (introduced_item.get("ownership") or {}).get(
                "after"
            )
            introduced_policy = (introduced_item.get("ownership") or {}).get(
                "creation_policy"
            )
        if (
            entry.get("ownership") not in OWNERSHIP_CLASSES
            or entry.get("ownership") != introduced_ownership
            or entry.get("ownership") != expected_ownership
            or entry.get("creation_policy") != introduced_policy
            or entry.get("creation_policy") != expected_policy
            or entry.get("base") != expected_base
            or entry.get("source_metadata") != expected_metadata
            or entry.get("receipt_sha256") != last_mutated.get("receipt_sha256")
            or not metadata_preservation_matches(
                expected_metadata,
                entry["created_metadata"],
                creation_identity=last_mutated["plan"]["creation_identity"],
            )
        ):
            raise TransactionPrimitiveError(
                f"Managed-content v2 manifest authority binding is invalid: {path}"
            )
    if observed_paths != sorted(observed_paths) or len(set(observed_paths)) != len(
        observed_paths
    ):
        raise TransactionPrimitiveError(
            "Managed-content v2 manifest entries are not deterministic."
        )


def _validate_manifest_any(
    value: dict[str, Any],
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> str:
    schema = value.get("schema")
    if schema == "naos.upgrade.managed_content_manifest.v1":
        _validate_manifest(
            value,
            project_root=project_root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        return "v1"
    if schema == "naos.upgrade.managed_content_manifest.v2":
        _validate_manifest_v2(
            value,
            project_root=project_root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        return "v2"
    minimum = value.get("minimum_recovery_naos_version")
    suffix = f" Minimum NAOS version: {minimum}." if isinstance(minimum, str) else ""
    raise TransactionPrimitiveError(
        "Managed-content manifest schema is unsupported." + suffix
    )


def _load_manifest(
    path: Path,
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> dict[str, Any] | None:
    try:
        value = _safe_json_object(path)
    except FileNotFoundError:
        return None
    _validate_manifest(
        value,
        project_root=project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    return value


def _load_manifest_at(
    state_descriptor: int,
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> dict[str, Any] | None:
    try:
        value = _safe_json_object_at(
            state_descriptor,
            "manifest.json",
            label="managed-content manifest",
        )
    except FileNotFoundError:
        return None
    _validate_manifest(
        value,
        project_root=project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    return value


def _load_manifest_any(
    path: Path,
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = _safe_json_object(path)
    except FileNotFoundError:
        return None, None
    version = _validate_manifest_any(
        value,
        project_root=project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    return value, version


def _load_manifest_any_at(
    state_descriptor: int,
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = _safe_json_object_at(
            state_descriptor,
            "manifest.json",
            label="managed-content manifest",
        )
    except FileNotFoundError:
        return None, None
    version = _validate_manifest_any(
        value,
        project_root=project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    return value, version


def load_managed_content_manifest_snapshot(
    project_root: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> dict[str, Any] | None:
    """Validate a persisted v1/v2 manifest and return a read-only planner view."""

    root = project_root.resolve(strict=True)
    manifest, manifest_version = _load_manifest_any(
        manifest_path,
        project_root=root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    if manifest is None:
        return None
    return _managed_content_snapshot_from_records(
        manifest, manifest_version=manifest_version, project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        load_receipt=lambda transaction: _load_receipt_any(
            receipts_root / f"{transaction['transaction_id']}.json",
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction["transaction_id"], plan=transaction["plan"],
        ),
        base_matches=lambda entry: _base_blob_matches(bases_root, entry),
        historical_base_matches=lambda digest: _historical_base_matches(bases_root, digest),
    )


def _managed_content_snapshot_from_records(
    manifest: dict[str, Any], *, manifest_version: str,
    project_id: str, scope_integrity_sha3_512: str, source_policy_sha256: str,
    load_receipt: Callable[[dict[str, Any]], tuple[dict[str, Any], str, str]],
    base_matches: Callable[[dict[str, Any]], bool],
    historical_base_matches: Callable[[str], bool],
) -> dict[str, Any]:
    """Shared projection after manifest validation; callbacks define the read boundary."""
    transactions = list(manifest["transactions"])
    creation_identities: dict[str, dict[str, Any]] = {}
    initialization_inputs: list[dict[str, Any]] = []
    transitioned_inputs: list[dict[str, Any]] = []
    historical_base_digests: set[str] = set()
    for transaction in transactions:
        transaction_id = str(transaction["transaction_id"])
        transaction_plan = transaction["plan"]
        creation_identity = transaction_plan.get("creation_identity")
        try:
            validate_managed_creation_identity(creation_identity)
        except ContentPathError as exc:
            raise TransactionPrimitiveError(str(exc)) from exc
        assert isinstance(creation_identity, dict)
        creation_identities[canonical_sha256(creation_identity)] = copy.deepcopy(
            creation_identity
        )
        if (
            transaction_plan.get("schema")
            in {
                "naos.upgrade.create_only_plan.v1",
                "naos.upgrade.create_only_plan.v2",
            }
            and transaction_plan.get("operation") == "naos-init"
        ):
            inputs = transaction_plan.get("inputs")
            required_inputs = {
                "mode",
                "profile",
                "archetype",
                "backend",
                "memory_choice",
            }
            if (
                not isinstance(inputs, dict)
                or not required_inputs.issubset(inputs)
                or any(not isinstance(inputs.get(key), str) for key in required_inputs)
                or inputs.get("mode") not in {"greenfield", "brownfield"}
                or (
                    inputs.get("mode") == "brownfield"
                    and not isinstance(inputs.get("repository_intelligence"), dict)
                )
            ):
                raise TransactionPrimitiveError(
                    "Managed-content initialization profile inputs are incomplete."
                )
            initialization_inputs.append(copy.deepcopy(inputs))
        elif (
            transaction_plan.get("schema") in CONTENT_AWARE_PLAN_SCHEMAS
        ):
            effective_inputs = (transaction_plan.get("profile") or {}).get(
                "effective_inputs"
            )
            if not isinstance(effective_inputs, dict):
                raise TransactionPrimitiveError(
                    "Managed-content profile-transition inputs are incomplete."
                )
            transitioned_inputs.append(copy.deepcopy(effective_inputs))
        receipt, receipt_sha256, receipt_version = load_receipt(transaction)
        expected_receipt_version = (
            "v2"
            if transaction_plan.get("schema") in CONTENT_AWARE_PLAN_SCHEMAS
            else "v1"
        )
        if receipt_version != expected_receipt_version:
            raise TransactionPrimitiveError(
                "Managed-content manifest plan/receipt generation differs: "
                + transaction_id
            )
        if receipt_sha256 != transaction["receipt_sha256"]:
            raise TransactionPrimitiveError(
                "Managed-content manifest receipt digest is invalid: "
                + transaction_id
            )
        historical_base_digests.update(
            _receipt_historical_base_digests(
                receipt,
                receipt_version=receipt_version,
                plan=transaction_plan,
            )
        )
    if len(creation_identities) != 1:
        raise TransactionPrimitiveError(
            "Managed-content creation identity lineage is ambiguous."
        )
    if not initialization_inputs:
        raise TransactionPrimitiveError(
            "Managed-content initialization profile lineage is missing."
        )
    profile_independent_keys = {
        key
        for inputs in initialization_inputs
        for key in inputs
        if key != "profile"
    }
    base_profile_inputs = initialization_inputs[-1]
    if any(
        any(
            inputs.get(key) != base_profile_inputs.get(key)
            for key in profile_independent_keys
        )
        for inputs in initialization_inputs
    ):
        raise TransactionPrimitiveError(
            "Managed-content initialization profile-independent inputs are ambiguous."
        )
    for effective_inputs in transitioned_inputs:
        if any(
            effective_inputs.get(key) != base_profile_inputs.get(key)
            for key in profile_independent_keys
        ):
            raise TransactionPrimitiveError(
                "Managed-content profile transition changed profile-independent inputs."
            )
    authoritative_profile_inputs = (
        transitioned_inputs[-1] if transitioned_inputs else base_profile_inputs
    )
    for entry in manifest["entries"]:
        if not base_matches(entry):
            raise TransactionPrimitiveError(
                "Managed-content manifest recoverable base is invalid: "
                + str(entry["path"])
            )
    for digest in sorted(historical_base_digests):
        if not historical_base_matches(digest):
            raise TransactionPrimitiveError(
                "Managed-content historical recoverable base is invalid: "
                + digest
            )
    if manifest_version == "v1":
        migration = {
            "source_schema": "naos.upgrade.managed_content_manifest.v1",
            "status": "normalized_v1_preserved_ownership",
            "ownership_reclassified": False,
            "persisted": False,
        }
    elif manifest_version == "v2":
        migration = {
            "source_schema": "naos.upgrade.managed_content_manifest.v2",
            "status": "validated_v2_preserved_ownership",
            "ownership_reclassified": False,
            "persisted": True,
        }
    else:  # pragma: no cover - _load_manifest_any rejects unknown schemas.
        raise TransactionPrimitiveError(
            "Managed-content manifest version is unavailable."
        )
    control = {
        "schema": "naos.upgrade.managed_content_manifest_snapshot.v2",
        "project_id": project_id,
        "scope_integrity_sha3_512": scope_integrity_sha3_512,
        "source_policy_sha256": source_policy_sha256,
        "source_manifest_integrity_sha256": manifest["integrity"]["value"],
        "migration": migration,
        "creation_identity": next(iter(creation_identities.values())),
        "previous_inputs": authoritative_profile_inputs,
        "entries": copy.deepcopy(manifest["entries"]),
    }
    return {**control, "snapshot_sha256": canonical_sha256(control)}


def _plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in plan.items() if key != "plan_sha256"}


def _validate_created_metadata(value: object, *, expected_type: str) -> None:
    try:
        validate_created_metadata_identity(value, expected_type=expected_type)
    except ContentPathError as exc:
        raise TransactionPrimitiveError(str(exc)) from exc


def _validate_journal(
    journal: dict[str, Any],
    *,
    project_root: Path,
) -> dict[str, Any]:
    return _validate_journal_record(
        journal, validate_plan=lambda plan: validate_create_only_plan(plan, project_root=project_root)
    )


def _validate_journal_record(
    journal: dict[str, Any],
    *,
    validate_plan: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "transaction_id",
        "plan",
        "state",
        "applied_paths",
        "applied_identities",
        "created_directories",
        "pending_action",
        "detail",
        "integrity",
    }
    _validate_sha256_integrity(journal, label="managed-content journal")
    if set(journal) != expected_keys:
        raise TransactionPrimitiveError("Managed-content journal shape is invalid.")
    transaction_id = journal.get("transaction_id")
    if (
        journal.get("schema") != "naos.upgrade.create_only_transaction.v1"
        or not isinstance(transaction_id, str)
        or TRANSACTION_ID_RE.fullmatch(transaction_id) is None
        or journal.get("state")
        not in {
            "PREPARED",
            "APPLYING",
            "VALIDATING",
            "ROLLING_BACK",
            "COMMITTED",
            "RECOVERY_REQUIRED",
            "ROLLED_BACK",
            "ROLLBACK_INCOMPLETE",
        }
        or (
            journal.get("detail") is not None
            and not isinstance(journal.get("detail"), str)
        )
    ):
        raise TransactionPrimitiveError(
            "Managed-content journal control fields are invalid."
        )
    plan = journal.get("plan")
    if not isinstance(plan, dict):
        raise TransactionPrimitiveError("Managed-content journal plan is invalid.")
    validate_plan(plan)
    planned_paths = [str(item["path"]) for item in plan["paths"]]
    applied_paths = journal.get("applied_paths")
    applied_identities = journal.get("applied_identities")
    created_directories = journal.get("created_directories")
    pending_action = journal.get("pending_action")
    if (
        not isinstance(applied_paths, list)
        or not all(isinstance(item, str) for item in applied_paths)
        or len(set(applied_paths)) != len(applied_paths)
        or any(path not in planned_paths for path in applied_paths)
        or not isinstance(applied_identities, dict)
        or any(path not in applied_paths for path in applied_identities)
        or not isinstance(created_directories, list)
        or not all(isinstance(item, dict) for item in created_directories)
    ):
        raise TransactionPrimitiveError(
            "Managed-content journal mutation inventory is invalid."
        )
    for relative_text, identity in applied_identities.items():
        safe_relative_path(relative_text)
        _validate_created_metadata(identity, expected_type="regular_file")
    if set(applied_identities) != set(applied_paths):
        raise TransactionPrimitiveError(
            "Managed-content applied path/identity inventories differ."
        )
    journal_state = str(journal.get("state"))
    applied_positions = [planned_paths.index(path) for path in applied_paths]
    ordered_applied_subsequence = applied_positions == sorted(applied_positions)
    if journal_state == "PREPARED":
        valid_applied_state = not applied_paths
    elif journal_state == "APPLYING":
        valid_applied_state = applied_paths == planned_paths[: len(applied_paths)]
    elif journal_state in {"VALIDATING", "COMMITTED"}:
        valid_applied_state = applied_paths == planned_paths
    elif journal_state in {
        "ROLLING_BACK",
        "RECOVERY_REQUIRED",
        "ROLLBACK_INCOMPLETE",
    }:
        valid_applied_state = ordered_applied_subsequence
    else:
        valid_applied_state = not applied_paths
    if not valid_applied_state:
        raise TransactionPrimitiveError(
            "Managed-content applied inventory is invalid for the journal state."
        )
    planned_directories = _planned_directory_publish_paths(plan)
    observed_directories: set[str] = set()
    observed_directory_order: list[str] = []
    for record in created_directories:
        if set(record) != {"path", "identity"} or not isinstance(record.get("path"), str):
            raise TransactionPrimitiveError(
                "Managed-content created-directory record is invalid."
            )
        relative_text = safe_relative_path(str(record["path"])).as_posix()
        if relative_text in observed_directories:
            raise TransactionPrimitiveError(
                "Managed-content created-directory inventory is duplicated."
            )
        observed_directories.add(relative_text)
        observed_directory_order.append(relative_text)
        _validate_created_metadata(record.get("identity"), expected_type="directory")
    rollback_states = {
        "ROLLING_BACK",
        "RECOVERY_REQUIRED",
        "ROLLBACK_INCOMPLETE",
    }
    if journal_state == "PREPARED":
        valid_directory_order = not observed_directory_order
    elif journal_state in {"VALIDATING", "COMMITTED"}:
        valid_directory_order = observed_directory_order == planned_directories
    elif journal_state in rollback_states:
        planned_positions = {
            relative: index for index, relative in enumerate(planned_directories)
        }
        observed_positions = [
            planned_positions.get(relative, -1)
            for relative in observed_directory_order
        ]
        valid_directory_order = (
            all(position >= 0 for position in observed_positions)
            and observed_positions == sorted(observed_positions)
        )
    else:
        valid_directory_order = observed_directory_order == planned_directories[
            : len(observed_directory_order)
        ]
    if not valid_directory_order:
        raise TransactionPrimitiveError(
            "Managed-content created-directory inventory is not a valid planned "
            "publish-order state."
        )
    if pending_action is not None:
        if not isinstance(pending_action, dict) or set(pending_action) != {
            "kind",
            "path",
            "identity",
        }:
            raise TransactionPrimitiveError(
                "Managed-content pending action is invalid."
            )
        kind = pending_action.get("kind")
        pending_path = pending_action.get("path")
        if not isinstance(pending_path, str):
            raise TransactionPrimitiveError(
                "Managed-content pending action path is invalid."
            )
        safe_relative_path(pending_path)
        if kind == "file_create":
            valid_binding = (
                pending_path in planned_paths and pending_path not in applied_paths
            )
            expected_type = "regular_file"
        elif kind == "file_rollback":
            valid_binding = (
                pending_path in planned_paths and pending_path in applied_paths
            )
            expected_type = "regular_file"
        elif kind == "directory_create":
            valid_binding = (
                pending_path in _planned_directory_paths(plan)
                and pending_path not in observed_directories
            )
            expected_type = "directory"
        elif kind == "directory_rollback":
            valid_binding = pending_path in observed_directories
            expected_type = "directory"
        else:
            valid_binding = False
            expected_type = "regular_file"
        if not valid_binding:
            raise TransactionPrimitiveError(
                "Managed-content pending action binding is invalid."
            )
        _validate_created_metadata(
            pending_action.get("identity"),
            expected_type=expected_type,
        )
        # A forward create intent can remain durable after recovery enters the
        # rollback phase; recovery must reconcile that exact intent before it
        # can publish a rollback-kind intent.  All pending kinds are therefore
        # confined to active mutation/recovery states, never terminal or
        # PREPARED/VALIDATING states.
        valid_pending_state = journal_state in {
            "APPLYING",
            "ROLLING_BACK",
            "RECOVERY_REQUIRED",
            "ROLLBACK_INCOMPLETE",
        }
        if not valid_pending_state:
            raise TransactionPrimitiveError(
                "Managed-content pending action is invalid for the journal state."
            )
    if journal.get("state") == "ROLLED_BACK" and (
        applied_paths
        or applied_identities
        or created_directories
        or pending_action is not None
    ):
        raise TransactionPrimitiveError(
            "Rolled-back managed-content journal retains mutation inventory."
        )
    return plan


def _journal_value(
    *,
    transaction_id: str,
    plan: dict[str, Any],
    state: str,
    applied_paths: list[str],
    applied_identities: dict[str, dict[str, object]],
    created_directories: list[dict[str, object]],
    pending_action: dict[str, object] | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return _with_sha256_integrity(
        {
            "schema": "naos.upgrade.create_only_transaction.v1",
            "transaction_id": transaction_id,
            "plan": plan,
            "state": state,
            "applied_paths": applied_paths,
            "applied_identities": applied_identities,
            "created_directories": created_directories,
            "pending_action": pending_action,
            "detail": detail,
        }
    )


def _transaction_checkpoint(_label: str) -> None:
    """Failure-injection seam; production execution deliberately does nothing."""


def _content_mutation_plan(plan: dict[str, Any]) -> dict[str, Any]:
    return {"paths": _content_mutation_items(plan)}


def _validate_v2_action_record(
    value: object,
    *,
    planned: dict[str, Any],
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "kind",
        "staged_name",
        "installed_identity",
        "backup_identity",
    }:
        raise TransactionPrimitiveError(
            "Managed-content v2 action record is invalid."
        )
    kind = str(planned["mutation"]["kind"])
    if value.get("path") != planned.get("path") or value.get("kind") != kind:
        raise TransactionPrimitiveError(
            "Managed-content v2 action authority differs from its plan."
        )
    staged_name = value.get("staged_name")
    if not isinstance(staged_name, str) or re.fullmatch(r"[0-9]{6}", staged_name) is None:
        raise TransactionPrimitiveError(
            "Managed-content v2 staged action binding is invalid."
        )
    _validate_created_metadata(
        value.get("installed_identity"),
        expected_type="regular_file",
    )
    if kind == "replace":
        _validate_created_metadata(
            value.get("backup_identity"),
            expected_type="regular_file",
        )
    elif value.get("backup_identity") is not None:
        raise TransactionPrimitiveError(
            "Managed-content v2 create action unexpectedly binds a backup."
        )


def _immutable_typed_json(value: Any) -> tuple[type, Any]:
    """Detach exact JSON types and values into an immutable local snapshot."""

    if isinstance(value, dict):
        return (type(value), tuple(
            (key, _immutable_typed_json(item)) for key, item in value.items()
        ))
    if isinstance(value, (list, tuple)):
        return (type(value), tuple(_immutable_typed_json(item) for item in value))
    return (type(value), value)


def _matches_typed_json_snapshot(value: Any, snapshot: tuple[type, Any]) -> bool:
    expected_type, expected = snapshot
    if type(value) is not expected_type:
        return False
    if isinstance(value, dict):
        return len(value) == len(expected) and all(
            key in value and _matches_typed_json_snapshot(value[key], item)
            for key, item in expected
        )
    if isinstance(value, (list, tuple)):
        return len(value) == len(expected) and all(
            _matches_typed_json_snapshot(item, saved)
            for item, saved in zip(value, expected, strict=True)
        )
    return value == expected


@dataclass(frozen=True)
class _ValidatedPlanProof:
    """Invocation-local immutable authority for already validated v2 plans."""

    root: str
    canonical_plan: bytes
    typed_plan: dict[str, Any]
    _typed_snapshot: tuple[type, Any] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        detached = copy.deepcopy(self.typed_plan)
        if (
            type(self.canonical_plan) is not bytes
            or canonical_bytes(detached) != self.canonical_plan
        ):
            raise TransactionPrimitiveError(
                "Managed-content v2 validated proof canonical snapshot differs."
            )
        object.__setattr__(self, "typed_plan", detached)
        object.__setattr__(self, "_typed_snapshot", _immutable_typed_json(detached))


def _validate_journal_v2(
    journal: dict[str, Any],
    *,
    project_root: Path,
    validated_plan_proof: _ValidatedPlanProof | None = None,
) -> dict[str, Any]:
    def validate_plan(plan):
        if validated_plan_proof is None:
            validate_content_aware_plan(plan, project_root=project_root)
        elif (
            str(project_root.resolve(strict=True)) != validated_plan_proof.root
            or not _matches_typed_json_snapshot(
                plan, validated_plan_proof._typed_snapshot
            )
        ):
            raise TransactionPrimitiveError(
                "Managed-content v2 checkpoint plan differs from its validated proof."
            )
    return _validate_journal_v2_record(journal, validate_plan=validate_plan)


def _validate_journal_v2_record(
    journal: dict[str, Any], *, validate_plan: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "minimum_recovery_naos_version",
        "transaction_id",
        "plan",
        "state",
        "applied_actions",
        "created_directories",
        "pending_action",
        "detail",
        "integrity",
    }
    _validate_sha256_integrity(journal, label="managed-content v2 journal")
    if set(journal) != expected_keys:
        raise TransactionPrimitiveError("Managed-content v2 journal shape is invalid.")
    if journal.get("schema") != "naos.upgrade.content_transaction.v2":
        raise TransactionPrimitiveError("Managed-content v2 journal control fields are invalid.")
    return _validate_content_checkpoint_fields(journal, journal.get("plan"), validate_plan=validate_plan)


def _validate_content_checkpoint_fields(
    journal: dict[str, Any], plan: dict[str, Any], *,
    validate_plan: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    """Exact v2 semantic controls shared by two distinct physical formats."""
    transaction_id = journal.get("transaction_id")
    state = journal.get("state")
    if (
        journal.get("minimum_recovery_naos_version")
        != CONTENT_AWARE_MINIMUM_RECOVERY_VERSION
        or not isinstance(transaction_id, str)
        or TRANSACTION_ID_RE.fullmatch(transaction_id) is None
        or state
        not in {
            "PREPARED",
            "APPLYING",
            "VALIDATING",
            "ROLLING_BACK",
            "COMMITTED",
            "RECOVERY_REQUIRED",
            "ROLLED_BACK",
            "ROLLBACK_INCOMPLETE",
        }
        or (journal.get("detail") is not None and not isinstance(journal.get("detail"), str))
    ):
        raise TransactionPrimitiveError(
            "Managed-content v2 journal control fields are invalid."
        )
    if not isinstance(plan, dict):
        raise TransactionPrimitiveError("Managed-content v2 journal plan is invalid.")
    validate_plan(plan)
    mutations = _content_mutation_items(plan)
    mutation_by_path = {str(item["path"]): item for item in mutations}
    mutation_paths = list(mutation_by_path)
    applied_actions = journal.get("applied_actions")
    if not isinstance(applied_actions, list):
        raise TransactionPrimitiveError(
            "Managed-content v2 applied-action inventory is invalid."
        )
    observed_applied: list[str] = []
    for action in applied_actions:
        if not isinstance(action, dict) or not isinstance(action.get("path"), str):
            raise TransactionPrimitiveError(
                "Managed-content v2 applied action is invalid."
            )
        path = str(action["path"])
        planned = mutation_by_path.get(path)
        if planned is None or path in observed_applied:
            raise TransactionPrimitiveError(
                "Managed-content v2 applied action is unplanned or duplicated."
            )
        _validate_v2_action_record(action, planned=planned)
        observed_applied.append(path)
    if state == "PREPARED":
        valid_applied = not observed_applied
    elif state == "APPLYING":
        valid_applied = observed_applied == mutation_paths[: len(observed_applied)]
    elif state in {"VALIDATING", "COMMITTED"}:
        valid_applied = observed_applied == mutation_paths
    elif state in {"ROLLING_BACK", "RECOVERY_REQUIRED", "ROLLBACK_INCOMPLETE"}:
        positions = [mutation_paths.index(path) for path in observed_applied]
        valid_applied = positions == sorted(positions)
    else:
        valid_applied = not observed_applied
    if not valid_applied:
        raise TransactionPrimitiveError(
            "Managed-content v2 applied inventory is invalid for its state."
        )

    created_directories = journal.get("created_directories")
    if not isinstance(created_directories, list):
        raise TransactionPrimitiveError(
            "Managed-content v2 directory inventory is invalid."
        )
    planned_directories = _planned_directory_publish_paths(
        _content_mutation_plan(plan)
    )
    observed_directories: list[str] = []
    for record in created_directories:
        if not isinstance(record, dict) or set(record) != {"path", "identity"}:
            raise TransactionPrimitiveError(
                "Managed-content v2 directory record is invalid."
            )
        relative = safe_relative_path(str(record.get("path") or "")).as_posix()
        if relative in observed_directories:
            raise TransactionPrimitiveError(
                "Managed-content v2 directory inventory is duplicated."
            )
        _validate_created_metadata(record.get("identity"), expected_type="directory")
        observed_directories.append(relative)
    if state == "PREPARED":
        valid_directories = not observed_directories
    elif state in {"VALIDATING", "COMMITTED"}:
        valid_directories = observed_directories == planned_directories
    elif state in {"ROLLING_BACK", "RECOVERY_REQUIRED", "ROLLBACK_INCOMPLETE"}:
        positions = [
            planned_directories.index(path)
            for path in observed_directories
            if path in planned_directories
        ]
        valid_directories = (
            len(positions) == len(observed_directories)
            and positions == sorted(positions)
        )
    else:
        valid_directories = observed_directories == planned_directories[
            : len(observed_directories)
        ]
    if not valid_directories:
        raise TransactionPrimitiveError(
            "Managed-content v2 directory inventory is invalid for its state."
        )

    pending = journal.get("pending_action")
    if pending is not None:
        if not isinstance(pending, dict) or set(pending) != {
            "direction",
            "path",
            "kind",
            "staged_name",
            "installed_identity",
            "backup_identity",
        }:
            raise TransactionPrimitiveError(
                "Managed-content v2 pending action is invalid."
            )
        direction = pending.get("direction")
        kind = pending.get("kind")
        path = str(pending.get("path") or "")
        if direction not in {"forward", "rollback"}:
            raise TransactionPrimitiveError(
                "Managed-content v2 pending direction is invalid."
            )
        if kind == "directory":
            safe_relative_path(path)
            if path not in planned_directories:
                raise TransactionPrimitiveError(
                    "Managed-content v2 pending directory is unplanned."
                )
            _validate_created_metadata(
                pending.get("installed_identity"),
                expected_type="directory",
            )
            if pending.get("backup_identity") is not None:
                raise TransactionPrimitiveError(
                    "Managed-content v2 directory cannot bind a backup."
                )
        else:
            planned = mutation_by_path.get(path)
            if planned is None:
                raise TransactionPrimitiveError(
                    "Managed-content v2 pending leaf is unplanned."
                )
            _validate_v2_action_record(
                {key: value for key, value in pending.items() if key != "direction"},
                planned=planned,
            )
        if state not in {
            "APPLYING",
            "ROLLING_BACK",
            "RECOVERY_REQUIRED",
            "ROLLBACK_INCOMPLETE",
        }:
            raise TransactionPrimitiveError(
                "Managed-content v2 pending action is invalid for its state."
            )
    if state == "ROLLED_BACK" and (
        applied_actions or created_directories or pending is not None
    ):
        raise TransactionPrimitiveError(
            "Rolled-back managed-content v2 journal retains mutation inventory."
        )
    return plan


def _journal_v2_value(
    *,
    transaction_id: str,
    plan: dict[str, Any],
    state: str,
    applied_actions: list[dict[str, Any]],
    created_directories: list[dict[str, object]],
    pending_action: dict[str, object] | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return _with_sha256_integrity(
        {
            "schema": "naos.upgrade.content_transaction.v2",
            "minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION,
            "transaction_id": transaction_id,
            "plan": plan,
            "state": state,
            "applied_actions": applied_actions,
            "created_directories": created_directories,
            "pending_action": pending_action,
            "detail": detail,
        }
    )


_COMPACT_JOURNAL_SCHEMA = "naos.upgrade.content_transaction.compact.v1"
_COMPACT_PLAN_NAME = "plan.json"


def _compact_plan_reference(plan_raw: bytes) -> dict[str, Any]:
    return {"name": _COMPACT_PLAN_NAME, "sha256": hashlib.sha256(plan_raw).hexdigest(),
            "size": len(plan_raw)}


def _validate_compact_journal_record(
    journal: dict[str, Any], plan_raw: bytes, *,
    validate_plan: Callable[[dict[str, Any]], Any],
    validated_plan_proof: _ValidatedPlanProof | None = None,
) -> dict[str, Any]:
    """Validate compact physical integrity once, then unchanged semantic controls."""
    _validate_sha256_integrity(journal, label="compact transaction journal")
    expected = {"schema", "minimum_recovery_naos_version", "transaction_id",
                "plan_ref", "state", "applied_actions", "created_directories",
                "pending_action", "detail", "integrity"}
    reference = journal.get("plan_ref")
    if (set(journal) != expected or journal.get("schema") != _COMPACT_JOURNAL_SCHEMA
            or type(reference) is not dict or set(reference) != {"name", "sha256", "size"}
            or reference.get("name") != _COMPACT_PLAN_NAME
            or type(reference.get("size")) is not int or reference["size"] < 1
            or type(reference.get("sha256")) is not str
            or SHA256_RE.fullmatch(reference["sha256"]) is None
            or type(plan_raw) is not bytes or len(plan_raw) != reference["size"]
            or hashlib.sha256(plan_raw).hexdigest() != reference["sha256"]):
        raise TransactionPrimitiveError("Compact checkpoint shape or plan binding is invalid.")
    plan = loads_strict_json(plan_raw)
    if type(plan) is not dict:
        raise TransactionPrimitiveError("Compact plan sidecar is not an object.")
    if validated_plan_proof is None:
        canonical_plan = canonical_bytes(plan)
    else:
        canonical_plan = validated_plan_proof.canonical_plan
        if not _matches_typed_json_snapshot(plan, validated_plan_proof._typed_snapshot):
            raise TransactionPrimitiveError("Compact plan differs from its validated proof.")
    if canonical_plan + b"\n" != plan_raw:
        raise TransactionPrimitiveError("Compact plan sidecar is not canonical JSON.")
    return _validate_content_checkpoint_fields(journal, plan, validate_plan=validate_plan)


def _validate_checkpoint_plan_proof(plan, *, project_root, proof):
    if (str(project_root.resolve(strict=True)) != proof.root
            or not _matches_typed_json_snapshot(plan, proof._typed_snapshot)):
        raise TransactionPrimitiveError("Compact checkpoint plan differs from its validated proof.")


def _read_compact_plan_at(parent_descriptor: int) -> bytes:
    descriptor = _open_safe_regular_at(
        parent_descriptor, _COMPACT_PLAN_NAME, flags=os.O_RDONLY,
        label="compact transaction plan sidecar")
    try:
        before = os.fstat(descriptor)
        metadata = observe_created_file_metadata_fd(descriptor)
        if not supported_metadata_flags(metadata) or metadata.get("acl_entries") != []:
            raise TransactionPrimitiveError("UNSUPPORTED_METADATA: compact plan sidecar.")
        chunks = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        live = os.stat(_COMPACT_PLAN_NAME, dir_fd=parent_descriptor, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino) != (live.st_dev, live.st_ino)
                or metadata != observe_created_file_metadata_fd(descriptor)):
            raise TransactionPrimitiveError("Compact plan sidecar changed while read.")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_content_checkpoint_at(parent_descriptor: int, *, project_root: Path,
                                label: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    journal = _safe_json_object_at(parent_descriptor, "journal.json", label=label)
    if journal.get("schema") == _COMPACT_JOURNAL_SCHEMA:
        plan = _validate_compact_journal_record(journal, _read_compact_plan_at(parent_descriptor),
            validate_plan=lambda selected: validate_content_aware_plan(selected, project_root=project_root))
        return journal, plan, "v2"  # Semantic recovery generation; raw schema stays explicit.
    plan, version = _validate_journal_any(journal, project_root=project_root)
    return journal, plan, version


def _load_runtime_content_checkpoint(runtime, transaction_name):
    with _open_runtime_transaction(runtime, transaction_name) as descriptor:
        return _load_content_checkpoint_at(descriptor, project_root=runtime.root,
                                           label=transaction_name)


def _load_content_checkpoint_path(path: Path, *, project_root: Path):
    descriptor = _open_project_root_handle(path.parent)
    try:
        result = _load_content_checkpoint_at(descriptor, project_root=project_root, label=str(path))
        if not _root_handle_matches_path(path.parent, descriptor):
            raise TransactionPrimitiveError("Transaction namespace changed while routed.")
        return result
    finally:
        os.close(descriptor)


def _compact_checkpoint_body(transaction_id, reference, state, applied_actions,
                             created_directories, *, pending_action=None, detail=None):
    return {"schema": _COMPACT_JOURNAL_SCHEMA,
            "minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION,
            "transaction_id": transaction_id, "plan_ref": dict(reference), "state": state,
            "applied_actions": applied_actions, "created_directories": created_directories,
            "pending_action": pending_action, "detail": detail}


def _persist_content_checkpoint(
    runtime, transaction_id, plan, state, applied_actions, created_directories, *,
    pending_action=None, detail=None, require_attached=True, validated_plan_proof=None,
):
    with _open_runtime_transaction(runtime, transaction_id) as descriptor:
        current = _safe_json_object_at(descriptor, "journal.json", label=transaction_id)
        compact = current.get("schema") == _COMPACT_JOURNAL_SCHEMA
        plan_raw = _read_compact_plan_at(descriptor) if compact else None
    arguments = dict(pending_action=pending_action, detail=detail,
                     require_attached=require_attached, validated_plan_proof=validated_plan_proof)
    if not compact:
        return _persist_journal_v2(runtime, transaction_id, plan, state,
                                   applied_actions, created_directories, **arguments)
    if current.get("transaction_id") != transaction_id:
        raise TransactionPrimitiveError("Compact checkpoint transaction-directory binding differs.")
    if validated_plan_proof is None:
        raise TransactionPrimitiveError("Compact checkpoint requires an invocation-local validated plan proof.")
    validate = lambda selected: _validate_checkpoint_plan_proof(
        selected, project_root=runtime.root, proof=validated_plan_proof)
    _validate_compact_journal_record(current, plan_raw, validate_plan=validate,
                                     validated_plan_proof=validated_plan_proof)
    validate(plan)
    body = _compact_checkpoint_body(transaction_id, current["plan_ref"], state,
        applied_actions, created_directories, pending_action=pending_action, detail=detail)
    _validate_content_checkpoint_fields(body, plan, validate_plan=validate)
    value = _with_sha256_integrity(body)
    _replace_runtime_journal(runtime, transaction_id, value, require_attached=require_attached)
    with _open_runtime_transaction(runtime, transaction_id) as descriptor:
        if _read_compact_plan_at(descriptor) != plan_raw:
            raise TransactionPrimitiveError("Compact plan sidecar changed during checkpoint.")
    return value


def _validate_journal_any(
    journal: dict[str, Any],
    *,
    project_root: Path,
) -> tuple[dict[str, Any], str]:
    schema = journal.get("schema")
    if schema == "naos.upgrade.create_only_transaction.v1":
        return _validate_journal(journal, project_root=project_root), "v1"
    if schema == "naos.upgrade.content_transaction.v2":
        return _validate_journal_v2(journal, project_root=project_root), "v2"
    minimum = journal.get("minimum_recovery_naos_version")
    suffix = f" Minimum NAOS version: {minimum}." if isinstance(minimum, str) else ""
    raise TransactionPrimitiveError(
        "Managed-content transaction journal schema is unsupported." + suffix
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_project_root_handle(root: Path) -> int:
    descriptor = os.open(root, _directory_open_flags())
    try:
        opened = os.fstat(descriptor)
        live = os.lstat(root)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(live.st_mode)
            or (opened.st_dev, opened.st_ino) != (live.st_dev, live.st_ino)
        ):
            raise ContentPathError(
                "Managed-content project root changed while opened."
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _root_handle_matches_path(root: Path, descriptor: int) -> bool:
    try:
        opened = os.fstat(descriptor)
        live = os.lstat(root)
    except OSError:
        return False
    return (
        stat.S_ISDIR(opened.st_mode)
        and not stat.S_ISLNK(live.st_mode)
        and (opened.st_dev, opened.st_ino) == (live.st_dev, live.st_ino)
    )


def _open_destination_parent_handle(
    root_handle: int,
    relative: Path,
    item: dict[str, Any],
    created: list[dict[str, object]],
    *,
    publish_directory: Callable[
        [int, str, str], tuple[int, dict[str, object]]
    ],
    on_created: Callable[[], None],
) -> int:
    """Traverse or journal-publish a parent relative to one stable root handle."""

    expected_existing = {
        str(ancestor["path"]): (
            int(ancestor["device"]),
            int(ancestor["inode"]),
        )
        for ancestor in item.get("ancestor_identities") or []
    }
    created_by_path = {
        str(record["path"]): record["identity"]
        for record in created
    }
    current = os.dup(root_handle)
    traversed: list[str] = []
    try:
        for component in relative.parts[:-1]:
            traversed.append(component)
            relative_text = "/".join(traversed)
            child: int | None = None
            try:
                try:
                    child = os.open(
                        component,
                        _directory_open_flags(),
                        dir_fd=current,
                    )
                except FileNotFoundError:
                    child, identity = publish_directory(
                        current,
                        component,
                        relative_text,
                    )
                    record = {"path": relative_text, "identity": identity}
                    created.append(record)
                    created_by_path[relative_text] = identity
                    on_created()
                metadata = os.fstat(child)
                expected = expected_existing.get(relative_text)
                created_identity = created_by_path.get(relative_text)
                if expected is not None:
                    valid = (metadata.st_dev, metadata.st_ino) == expected
                elif created_identity is not None:
                    valid = created_metadata_identity_matches(
                        observe_created_directory_metadata_fd(child),
                        created_identity,
                        expected_type="directory",
                    )
                else:
                    valid = False
                if not valid:
                    raise ContentPathError(
                        "Managed-content destination ancestor changed: "
                        f"{relative_text}"
                    )
            except BaseException:
                if child is not None:
                    os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _directory_handle_matches_topology(
    root: Path,
    root_handle: int,
    relative: Path,
    expected_parent_handle: int,
) -> bool:
    if not _root_handle_matches_path(root, root_handle):
        return False
    current = os.dup(root_handle)
    try:
        for component in relative.parts[:-1]:
            child = os.open(
                component,
                _directory_open_flags(),
                dir_fd=current,
            )
            os.close(current)
            current = child
        live = os.fstat(current)
        expected = os.fstat(expected_parent_handle)
        return (live.st_dev, live.st_ino) == (expected.st_dev, expected.st_ino)
    except OSError:
        return False
    finally:
        os.close(current)


def _open_regular_leaf_at(parent_handle: int, name: str) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_handle,
    )
    try:
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_handle, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_ISLNK(current.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (current.st_dev, current.st_ino)
        ):
            raise ContentPathError(
                f"Managed-content destination leaf is unsafe or changed: {name}"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_existing_parent_handle(root_handle: int, relative: Path) -> int:
    current = os.dup(root_handle)
    try:
        for component in relative.parts[:-1]:
            child = os.open(
                component,
                _directory_open_flags(),
                dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _open_existing_directory_handle(root_handle: int, relative: Path) -> int:
    current = os.dup(root_handle)
    try:
        for component in relative.parts:
            child = os.open(
                component,
                _directory_open_flags(),
                dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _created_directory_inventory_failures_at(
    root_handle: int,
    records: list[dict[str, Any]],
) -> list[str]:
    failures: list[str] = []
    for record in records:
        relative_text = str(record.get("path") or "")
        descriptor: int | None = None
        try:
            relative = safe_relative_path(relative_text)
            descriptor = _open_existing_directory_handle(root_handle, relative)
            if not created_metadata_identity_matches(
                observe_created_directory_metadata_fd(descriptor),
                record.get("identity"),
                expected_type="directory",
            ):
                failures.append(
                    f"created directory topology changed: {relative_text}"
                )
        except (OSError, ContentPathError, TransactionPrimitiveError):
            failures.append(f"created directory topology changed: {relative_text}")
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return failures


def _committed_content_topology_failures_at(
    root_handle: int,
    journal: dict[str, Any],
    plan: dict[str, Any],
) -> list[str]:
    """Validate every existing and transaction-created directory binding."""

    return [
        *_created_directory_inventory_failures_at(
            root_handle,
            [
                item
                for item in journal.get("created_directories") or []
                if isinstance(item, dict)
            ],
        ),
        *_plan_ancestor_inventory_failures_at(root_handle, plan),
    ]


def _plan_ancestor_inventory_failures_at(
    root_handle: int,
    plan: dict[str, Any],
) -> list[str]:
    expected: dict[str, tuple[int, int]] = {}
    for item in plan.get("paths") or []:
        if not isinstance(item, dict):
            continue
        for ancestor in item.get("ancestor_identities") or []:
            if not isinstance(ancestor, dict):
                continue
            relative_text = str(ancestor.get("path") or "")
            identity = (
                int(ancestor.get("device", -1)),
                int(ancestor.get("inode", -1)),
            )
            if relative_text in expected and expected[relative_text] != identity:
                return [f"conflicting ancestor identity: {relative_text}"]
            expected[relative_text] = identity
    failures: list[str] = []
    for relative_text, identity in sorted(expected.items()):
        descriptor: int | None = None
        try:
            descriptor = _open_existing_directory_handle(
                root_handle,
                safe_relative_path(relative_text),
            )
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != identity:
                failures.append(f"ancestor topology changed: {relative_text}")
        except (OSError, ContentPathError, TransactionPrimitiveError):
            failures.append(f"ancestor topology changed: {relative_text}")
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return failures


def _open_safe_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
    expected_mode: int | None = 0o700,
) -> int:
    descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or (
                expected_mode is not None
                and stat.S_IMODE(opened.st_mode) != expected_mode
            )
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise TransactionPrimitiveError(
                f"Managed-content runtime directory is unsafe: {label}"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_safe_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    flags: int,
    label: str,
) -> int:
    descriptor = os.open(
        name,
        flags | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise TransactionPrimitiveError(
                f"Managed-content runtime file is unsafe: {label}"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@dataclass
class _ManagedRuntimeHandles:
    root: Path
    root_fd: int
    naos_fd: int
    control_fd: int
    owner_fd: int
    runtime_fd: int
    scope_fd: int
    transactions_fd: int
    state_fd: int
    bases_fd: int
    receipts_fd: int
    lock_fd: int
    locked: bool = False

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        transaction_root: Path,
        lock_path: Path,
        manifest_path: Path,
        bases_root: Path,
        receipts_root: Path,
    ) -> "_ManagedRuntimeHandles":
        supplied = {
            "transaction_root": transaction_root,
            "lock_path": lock_path,
            "manifest_path": manifest_path,
            "bases_root": bases_root,
            "receipts_root": receipts_root,
        }
        for name, relative in _MANAGED_RUNTIME_RELATIVES.items():
            if supplied[name] != root / relative:
                raise TransactionPrimitiveError(
                    f"Managed-content {name} is outside its canonical provenance binding."
                )
        descriptors: list[int] = []
        try:
            root_fd = _open_project_root_handle(root)
            descriptors.append(root_fd)
            naos_fd = _open_safe_directory_at(
                root_fd,
                ".naos",
                label=".naos",
                expected_mode=None,
            )
            descriptors.append(naos_fd)
            control_fd = _open_safe_directory_at(
                naos_fd,
                "upgrade-v1",
                label=".naos/upgrade-v1",
            )
            descriptors.append(control_fd)
            owner_fd = _open_safe_regular_at(
                control_fd,
                "OWNER.json",
                flags=os.O_RDONLY,
                label="OWNER.json",
            )
            descriptors.append(owner_fd)
            runtime_fd = _open_safe_directory_at(
                control_fd,
                "managed-content",
                label=".naos/upgrade-v1/managed-content",
            )
            descriptors.append(runtime_fd)
            scope_fd = _open_safe_regular_at(
                runtime_fd,
                "scope.json",
                flags=os.O_RDONLY,
                label="managed-content/scope.json",
            )
            descriptors.append(scope_fd)
            transactions_fd = _open_safe_directory_at(
                runtime_fd,
                "transactions",
                label="managed-content/transactions",
            )
            descriptors.append(transactions_fd)
            state_fd = _open_safe_directory_at(
                runtime_fd,
                "state",
                label="managed-content/state",
            )
            descriptors.append(state_fd)
            bases_fd = _open_safe_directory_at(
                state_fd,
                "bases",
                label="managed-content/state/bases",
            )
            descriptors.append(bases_fd)
            receipts_fd = _open_safe_directory_at(
                state_fd,
                "receipts",
                label="managed-content/state/receipts",
            )
            descriptors.append(receipts_fd)
            lock_fd = _open_safe_regular_at(
                runtime_fd,
                "lock",
                flags=os.O_RDWR,
                label="managed-content/lock",
            )
            descriptors.append(lock_fd)
            result = cls(
                root=root,
                root_fd=root_fd,
                naos_fd=naos_fd,
                control_fd=control_fd,
                owner_fd=owner_fd,
                runtime_fd=runtime_fd,
                scope_fd=scope_fd,
                transactions_fd=transactions_fd,
                state_fd=state_fd,
                bases_fd=bases_fd,
                receipts_fd=receipts_fd,
                lock_fd=lock_fd,
            )
            result.assert_attached()
            return result
        except BaseException:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    @staticmethod
    def _same_entry(
        parent_descriptor: int,
        name: str,
        opened_descriptor: int,
    ) -> bool:
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(opened_descriptor)
        except OSError:
            return False
        return (
            not stat.S_ISLNK(current.st_mode)
            and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)
        )

    def assert_attached(self) -> None:
        if (
            not _root_handle_matches_path(self.root, self.root_fd)
            or not self._same_entry(self.root_fd, ".naos", self.naos_fd)
            or not self._same_entry(self.naos_fd, "upgrade-v1", self.control_fd)
            or not self._same_entry(self.control_fd, "OWNER.json", self.owner_fd)
            or not self._same_entry(
                self.control_fd,
                "managed-content",
                self.runtime_fd,
            )
            or not self._same_entry(self.runtime_fd, "scope.json", self.scope_fd)
            or not self._same_entry(
                self.runtime_fd,
                "transactions",
                self.transactions_fd,
            )
            or not self._same_entry(self.runtime_fd, "state", self.state_fd)
            or not self._same_entry(self.state_fd, "bases", self.bases_fd)
            or not self._same_entry(self.state_fd, "receipts", self.receipts_fd)
            or not self._same_entry(self.runtime_fd, "lock", self.lock_fd)
        ):
            raise TransactionPrimitiveError(
                "Managed-content runtime detached from its canonical project path."
            )

    def acquire(self) -> None:
        if fcntl is None:
            raise TransactionPrimitiveError(
                "Stable flock support is unavailable on this platform."
            )
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TransactionPrimitiveError(
                "Managed-content transaction lock is held."
            ) from exc
        self.locked = True
        self.assert_attached()

    def close(self) -> None:
        if self.locked and fcntl is not None:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            self.locked = False
        for descriptor in (
            self.lock_fd,
            self.receipts_fd,
            self.bases_fd,
            self.state_fd,
            self.transactions_fd,
            self.runtime_fd,
            self.scope_fd,
            self.owner_fd,
            self.control_fd,
            self.naos_fd,
            self.root_fd,
        ):
            os.close(descriptor)

    def __enter__(self) -> "_ManagedRuntimeHandles":
        try:
            self.acquire()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _require_live_scope_binding_at(
    runtime: _ManagedRuntimeHandles,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    from . import provenance

    owner = _safe_json_object_at(
        runtime.control_fd,
        "OWNER.json",
        label="OWNER.json",
    )
    live_project_id, owner_integrity = provenance._validate_owner(owner)
    scope = _safe_json_object_at(
        runtime.runtime_fd,
        "scope.json",
        label="managed-content/scope.json",
    )
    live_scope_integrity = provenance._validate_managed_content_scope(
        scope,
        project_id=live_project_id,
        owner_integrity=owner_integrity,
    )
    enrollment = scope.get("enrollment")
    live_policy = (
        enrollment.get("source_policy_sha256")
        if isinstance(enrollment, dict)
        else None
    )
    if (
        live_project_id != project_id
        or live_scope_integrity != scope_integrity_sha3_512
        or live_policy != source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content provenance changed before mutation."
        )
    runtime.assert_attached()


@contextmanager
def _open_runtime_transaction(
    runtime: _ManagedRuntimeHandles,
    name: str,
) -> Iterator[int]:
    descriptor = _open_safe_directory_at(
        runtime.transactions_fd,
        name,
        label=f"managed-content/transactions/{name}",
    )
    try:
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _open_runtime_staging(
    runtime: _ManagedRuntimeHandles,
    transaction_name: str,
) -> Iterator[int]:
    with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
        staging_fd = _open_safe_directory_at(
            transaction_fd,
            "staging",
            label=f"managed-content/transactions/{transaction_name}/staging",
        )
        try:
            yield staging_fd
        finally:
            os.close(staging_fd)


@contextmanager
def _open_runtime_directory_staging(
    runtime: _ManagedRuntimeHandles,
    transaction_name: str,
) -> Iterator[int]:
    with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
        directories_fd = _open_safe_directory_at(
            transaction_fd,
            "directories",
            label=f"managed-content/transactions/{transaction_name}/directories",
        )
        try:
            yield directories_fd
        finally:
            os.close(directories_fd)


def _replace_runtime_journal(
    runtime: _ManagedRuntimeHandles,
    transaction_name: str,
    value: dict[str, Any],
    *,
    require_attached: bool = True,
) -> None:
    if require_attached:
        runtime.assert_attached()
    with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
        _replace_json_at(transaction_fd, "journal.json", value)
    if require_attached:
        runtime.assert_attached()


def _load_runtime_journal(
    runtime: _ManagedRuntimeHandles,
    transaction_name: str,
) -> dict[str, Any]:
    with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
        return _safe_json_object_at(
            transaction_fd,
            "journal.json",
            label=f"{transaction_name}/journal.json",
        )


def _validated_terminal_journal_inventory_at(
    runtime: _ManagedRuntimeHandles,
    *,
    project_root: Path,
    source_policy_sha256: str,
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    inventory: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for transaction_name in sorted(os.listdir(runtime.transactions_fd)):
        if transaction_name.startswith(".preparing-"):
            raise TransactionPrimitiveError(
                "A managed-content transaction preparation requires recovery: "
                + transaction_name
            )
        journal = _load_runtime_journal(runtime, transaction_name)
        plan = _validate_journal(journal, project_root=project_root)
        if (
            journal.get("transaction_id") != transaction_name
            or plan.get("source_policy_sha256") != source_policy_sha256
        ):
            raise TransactionPrimitiveError(
                "Managed-content transaction binding is invalid."
            )
        if journal.get("state") not in TERMINAL_CONTENT_STATES:
            raise TransactionPrimitiveError(
                "A managed-content transaction requires recovery before current "
                f"state can be claimed: {transaction_name}"
            )
        inventory[transaction_name] = (journal, plan)
    return inventory


def _require_manifest_journal_coverage(
    manifest: dict[str, Any] | None,
    journals: dict[str, tuple[dict[str, Any], dict[str, Any]]],
) -> None:
    manifest_ids = {
        str(item.get("transaction_id"))
        for item in (manifest or {}).get("transactions") or []
        if isinstance(item, dict)
    }
    committed_ids = {
        transaction_id
        for transaction_id, (journal, _plan) in journals.items()
        if journal.get("state") == "COMMITTED"
    }
    if manifest_ids != committed_ids:
        missing = sorted(manifest_ids - committed_ids)
        unexpected = sorted(committed_ids - manifest_ids)
        detail: list[str] = []
        if missing:
            detail.append("missing committed journals: " + ", ".join(missing))
        if unexpected:
            detail.append(
                "unmanifested committed journals: " + ", ".join(unexpected)
            )
        raise TransactionPrimitiveError(
            "Managed-content cumulative journal inventory differs from the "
            "manifest: " + "; ".join(detail)
        )


def _unsealed_preparation_outcomes(
    runtime: _ManagedRuntimeHandles,
) -> list[CreateOnlyTransactionOutcome]:
    """Report preserved unsealed residue before any automatic recovery mutation."""
    runtime.assert_attached()
    outcomes = []
    for name in sorted(os.listdir(runtime.transactions_fd)):
        if not name.startswith(".preparing-"):
            continue
        transaction_id = name.removeprefix(".preparing-")
        detail = "Unsealed preparation has no durable object-identity inventory"
        try:
            with _open_runtime_transaction(runtime, name) as descriptor:
                try:
                    metadata = os.stat("journal.json", dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    detail += "; preparation journal is missing"
                else:
                    # Unsealed bytes supply no delete authority. Do not parse an
                    # unbounded record or open a FIFO/link merely to report residue.
                    detail += (
                        "; preparation journal is present but unsealed"
                        if stat.S_ISREG(metadata.st_mode)
                        else "; preparation journal is not a regular file"
                    )
        except (OSError, ValueError, TransactionPrimitiveError) as exc:
            detail += f"; preparation directory cannot be validated: {exc}"
        outcomes.append(CreateOnlyTransactionOutcome(
            "recovery_required",
            transaction_id if TRANSACTION_ID_RE.fullmatch(transaction_id) else None,
            detail=(detail + "; all residue was preserved at "
                    + str(runtime.root / ".naos/upgrade-v1/managed-content/transactions" / name)
                    + ". Owner review must reconcile this preparation before retry; "
                    "automatic recovery cannot delete or adopt unwitnessed objects."),
        ))
    runtime.assert_attached()
    return outcomes


def _require_supported_preparation_parents(runtime: _ManagedRuntimeHandles) -> None:
    """Refuse known unsupported inheritance before creating private residue.

    These held directories are the parents of staged and durable evidence files.
    Later per-object checks remain necessary: this is an early refusal, not a
    cached assertion about metadata on objects created after this observation.
    """
    runtime.assert_attached()
    for label, descriptor in (
        ("transactions", runtime.transactions_fd),
        ("state", runtime.state_fd),
        ("bases", runtime.bases_fd),
        ("receipts", runtime.receipts_fd),
    ):
        metadata = observe_created_directory_metadata_fd(descriptor)
        if not supported_metadata_flags(metadata) or metadata.get("acl_entries") != []:
            raise TransactionPrimitiveError(
                "UNSUPPORTED_METADATA: managed-content " + label
                + " parent has unsupported inode flags or ACL inheritance; "
                "no transaction preparation was created."
            )
    runtime.assert_attached()


def _remove_runtime_preparation(
    runtime: _ManagedRuntimeHandles,
    preparation_name: str,
) -> None:
    """Preserve an unsealed preparation: it has no durable delete authority.

    A v1/v2 preparation journal binds planned content, but does not bind the
    identities of every private object created before publication. Names, modes
    and even expected content cannot prove that a leaf is still ours. Preserve
    residue for explicit review instead of guessing during recovery. Even an
    empty directory cannot be deleted by a non-atomic name/identity check.
    """
    runtime.assert_attached()
    raise TransactionPrimitiveError(
        "Unsealed preparation has no durable object-identity inventory; "
        "all residue was preserved for review: " + preparation_name
    )


def _remove_runtime_staging(
    runtime: _ManagedRuntimeHandles,
    transaction_name: str,
    plan: dict[str, Any],
) -> None:
    with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
        for collection_name in ("staging", "directories"):
            try:
                metadata = os.stat(
                    collection_name,
                    dir_fd=transaction_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise TransactionPrimitiveError(
                    "Unsafe managed-content staging collection: "
                    f"{transaction_name}/{collection_name}"
                )
            collection_fd = _open_safe_directory_at(
                transaction_fd,
                collection_name,
                label=(
                    f"managed-content/transactions/{transaction_name}/"
                    f"{collection_name}"
                ),
            )
            try:
                if collection_name == "staging":
                    planned_by_name = {
                        f"{index:06d}": item
                        for index, item in enumerate(plan.get("paths") or [])
                    }
                    for name in sorted(os.listdir(collection_fd)):
                        planned = planned_by_name.get(name)
                        if planned is None or not _file_matches_at(
                            collection_fd,
                            name,
                            planned["source"],
                        ):
                            raise TransactionPrimitiveError(
                                "Unknown or changed managed-content staging residue: "
                                f"{transaction_name}/staging/{name}"
                            )
                        os.unlink(name, dir_fd=collection_fd)
                        os.fsync(collection_fd)
                else:
                    planned_names = set(_planned_directory_staging(plan).values())
                    for name in sorted(os.listdir(collection_fd)):
                        try:
                            staged_metadata = os.stat(
                                name,
                                dir_fd=collection_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            continue
                        if (
                            name not in planned_names
                            or stat.S_ISLNK(staged_metadata.st_mode)
                            or not stat.S_ISDIR(staged_metadata.st_mode)
                            or stat.S_IMODE(staged_metadata.st_mode) != 0o755
                        ):
                            raise TransactionPrimitiveError(
                                "Unknown or changed managed-content directory staging residue: "
                                f"{transaction_name}/directories/{name}"
                            )
                        staged_fd = _open_safe_directory_at(
                            collection_fd,
                            name,
                            label=(
                                f"managed-content/transactions/{transaction_name}/"
                                f"directories/{name}"
                            ),
                            expected_mode=0o755,
                        )
                        try:
                            if os.listdir(staged_fd):
                                raise TransactionPrimitiveError(
                                    "Managed-content staged directory is not empty: "
                                    f"{transaction_name}/directories/{name}"
                                )
                        finally:
                            os.close(staged_fd)
                        os.rmdir(name, dir_fd=collection_fd)
                        os.fsync(collection_fd)
            finally:
                os.close(collection_fd)
            os.rmdir(collection_name, dir_fd=transaction_fd)
            os.fsync(transaction_fd)


def _plan_present_identity(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("presence") != "present":
        raise TransactionPrimitiveError(
            "Managed-content plan does not bind a present regular-file identity."
        )
    return {
        "kind": value["kind"],
        "mode": value["mode"],
        "size": value["size"],
        "sha256": value["sha256"],
    }


def _leaf_observation_at(
    parent_descriptor: int,
    name: str,
) -> tuple[dict[str, object], dict[str, object]]:
    descriptor = _open_regular_leaf_at(parent_descriptor, name)
    try:
        return (
            _descriptor_content_identity(descriptor),
            observe_created_file_metadata_fd(descriptor),
        )
    finally:
        os.close(descriptor)


def _leaf_matches_exact_at(
    parent_descriptor: int,
    name: str,
    expected_content: dict[str, Any],
    expected_metadata: dict[str, Any],
) -> bool:
    try:
        content, metadata = _leaf_observation_at(parent_descriptor, name)
    except (OSError, ContentPathError, TransactionPrimitiveError):
        return False
    return content == expected_content and created_metadata_identity_matches(
        metadata, expected_metadata, expected_type="regular_file"
    )


def _leaf_observation_matches(
    observed: tuple[dict[str, object], dict[str, object]] | None,
    expected: tuple[dict[str, object], dict[str, object]],
) -> bool:
    return observed is not None and observed[0] == expected[0] and (
        created_metadata_identity_matches(
            observed[1], expected[1], expected_type="regular_file"
        )
    )


def _entry_absent_at(parent_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _require_same_filesystem_at(
    left_descriptor: int,
    right_descriptor: int,
    *,
    path: str,
) -> None:
    if os.fstat(left_descriptor).st_dev != os.fstat(right_descriptor).st_dev:
        raise TransactionPrimitiveError(
            "UNSUPPORTED_METADATA: transaction staging and target are on "
            f"different filesystems: {path}"
        )


def _remove_runtime_staging_v2(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    plan: dict[str, Any],
    actions: list[dict[str, Any]],
    *,
    committed: bool,
) -> None:
    action_by_path = {str(action["path"]): action for action in actions}
    mutations = _content_mutation_items(plan)
    with _open_runtime_transaction(runtime, transaction_id) as transaction_fd:
        staging_fd = _open_safe_directory_at(
            transaction_fd,
            "staging",
            label=f"managed-content/transactions/{transaction_id}/staging",
        )
        try:
            planned_names = {
                f"{index:06d}": item for index, item in enumerate(mutations)
            }
            for name in sorted(os.listdir(staging_fd)):
                item = planned_names.get(name)
                if item is None:
                    raise TransactionPrimitiveError(
                        "Unknown managed-content v2 staging residue: "
                        f"{transaction_id}/staging/{name}"
                    )
                action = action_by_path.get(str(item["path"]))
                if committed and item["mutation"]["kind"] == "replace":
                    if action is None:
                        raise TransactionPrimitiveError(
                            "Committed replacement has no cleanup evidence: "
                            + str(item["path"])
                        )
                    expected_content = _plan_present_identity(item["before"])
                    expected_metadata = action["backup_identity"]
                else:
                    expected_content = _plan_present_identity(item["after"])
                    if action is None:
                        observed_content, observed_metadata = _leaf_observation_at(
                            staging_fd,
                            name,
                        )
                        if (
                            observed_content != expected_content
                            or not metadata_preservation_matches(
                                item["after_metadata"],
                                observed_metadata,
                                creation_identity=plan["creation_identity"],
                            )
                        ):
                            raise TransactionPrimitiveError(
                                "Changed unapplied managed-content v2 staging residue "
                                f"was preserved: {transaction_id}/staging/{name}"
                            )
                        os.unlink(name, dir_fd=staging_fd)
                        os.fsync(staging_fd)
                        continue
                    expected_metadata = action["installed_identity"]
                if not _leaf_matches_exact_at(
                    staging_fd,
                    name,
                    expected_content,
                    expected_metadata,
                ):
                    raise TransactionPrimitiveError(
                        "Changed managed-content v2 staging residue was preserved: "
                        f"{transaction_id}/staging/{name}"
                    )
                os.unlink(name, dir_fd=staging_fd)
                os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        os.rmdir("staging", dir_fd=transaction_fd)
        os.fsync(transaction_fd)

        directories_fd = _open_safe_directory_at(
            transaction_fd,
            "directories",
            label=f"managed-content/transactions/{transaction_id}/directories",
        )
        try:
            planned_names = set(
                _planned_directory_staging(_content_mutation_plan(plan)).values()
            )
            for name in sorted(os.listdir(directories_fd)):
                if name not in planned_names:
                    raise TransactionPrimitiveError(
                        "Unknown managed-content v2 directory residue: "
                        f"{transaction_id}/directories/{name}"
                    )
                descriptor = _open_safe_directory_at(
                    directories_fd,
                    name,
                    label=f"{transaction_id}/directories/{name}",
                    expected_mode=0o755,
                )
                try:
                    if os.listdir(descriptor):
                        raise TransactionPrimitiveError(
                            "Managed-content v2 staged directory is not empty: "
                            f"{transaction_id}/directories/{name}"
                        )
                finally:
                    os.close(descriptor)
                os.rmdir(name, dir_fd=directories_fd)
                os.fsync(directories_fd)
        finally:
            os.close(directories_fd)
        os.rmdir("directories", dir_fd=transaction_fd)
        os.fsync(transaction_fd)


def _persist_journal_v2(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    plan: dict[str, Any],
    state: str,
    applied_actions: list[dict[str, Any]],
    created_directories: list[dict[str, object]],
    *,
    pending_action: dict[str, object] | None = None,
    detail: str | None = None,
    require_attached: bool = True,
    validated_plan_proof: _ValidatedPlanProof | None = None,
) -> dict[str, Any]:
    journal = _journal_v2_value(
        transaction_id=transaction_id,
        plan=plan,
        state=state,
        applied_actions=applied_actions,
        created_directories=created_directories,
        pending_action=pending_action,
        detail=detail,
    )
    _validate_journal_v2(
        journal,
        project_root=runtime.root,
        validated_plan_proof=validated_plan_proof,
    )
    _replace_runtime_journal(
        runtime,
        transaction_id,
        journal,
        require_attached=require_attached,
    )
    return journal


def _remove_runtime_evidence_pending_v2(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    plan: dict[str, Any],
) -> None:
    for item in _content_mutation_items(plan):
        digest = str(_content_aware_after_identity(item)["sha256"])
        _remove_pending_evidence_at(
            runtime.bases_fd,
            _base_pending_name(transaction_id, digest),
        )
    _remove_pending_evidence_at(
        runtime.receipts_fd,
        _receipt_pending_name(transaction_id),
    )
    _remove_pending_evidence_at(
        runtime.state_fd,
        _manifest_pending_name(transaction_id),
    )


def _v2_staging_observation(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    staged_name: str,
) -> tuple[dict[str, object], dict[str, object]] | None:
    with _open_runtime_staging(runtime, transaction_id) as staging_fd:
        if _entry_absent_at(staging_fd, staged_name):
            return None
        return _leaf_observation_at(staging_fd, staged_name)


def _v2_target_observation(
    runtime: _ManagedRuntimeHandles,
    path: str,
) -> tuple[dict[str, object], dict[str, object]] | None:
    relative = safe_relative_path(path)
    try:
        parent_fd = _open_existing_parent_handle(runtime.root_fd, relative)
    except FileNotFoundError:
        return None
    try:
        if _entry_absent_at(parent_fd, relative.name):
            return None
        return _leaf_observation_at(parent_fd, relative.name)
    finally:
        os.close(parent_fd)


def _v2_reconcile_forward_pending(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    plan: dict[str, Any],
    pending: dict[str, Any],
    applied_actions: list[dict[str, Any]],
    created_directories: list[dict[str, object]],
) -> tuple[bool, str | None]:
    path = str(pending["path"])
    kind = str(pending["kind"])
    if kind == "directory":
        staged_name = str(pending["staged_name"])
        with _open_runtime_directory_staging(runtime, transaction_id) as directories_fd:
            staged_present = not _entry_absent_at(directories_fd, staged_name)
        try:
            descriptor = _open_existing_directory_handle(
                runtime.root_fd,
                safe_relative_path(path),
            )
        except FileNotFoundError:
            target_identity = None
        else:
            try:
                target_identity = observe_created_directory_metadata_fd(descriptor)
            finally:
                os.close(descriptor)
        if staged_present and target_identity is None:
            return True, None
        if not staged_present and target_identity is not None and (
            created_metadata_identity_matches(
                target_identity,
                pending["installed_identity"],
                expected_type="directory",
            )
        ):
            if path not in {str(item["path"]) for item in created_directories}:
                created_directories.append(
                    {"path": path, "identity": pending["installed_identity"]}
                )
            return True, None
        return False, f"Directory publication state is ambiguous and was preserved: {path}"

    target = _v2_target_observation(runtime, path)
    staged = _v2_staging_observation(
        runtime,
        transaction_id,
        str(pending["staged_name"]),
    )
    installed = (
        _plan_present_identity(
            next(
                item["after"]
                for item in _content_mutation_items(plan)
                if item["path"] == path
            )
        ),
        pending["installed_identity"],
    )
    action_record = {
        key: copy.deepcopy(value)
        for key, value in pending.items()
        if key != "direction"
    }
    if kind == "create":
        if target is None and _leaf_observation_matches(staged, installed):
            return True, None
        if _leaf_observation_matches(target, installed) and staged is None:
            if path not in {str(action["path"]) for action in applied_actions}:
                applied_actions.append(action_record)
            return True, None
    else:
        before_content = _plan_present_identity(
            next(
                item["before"]
                for item in _content_mutation_items(plan)
                if item["path"] == path
            )
        )
        backup = (before_content, pending["backup_identity"])
        if _leaf_observation_matches(target, backup) and _leaf_observation_matches(
            staged, installed
        ):
            return True, None
        if _leaf_observation_matches(target, installed) and _leaf_observation_matches(
            staged, backup
        ):
            if path not in {str(action["path"]) for action in applied_actions}:
                applied_actions.append(action_record)
            return True, None
    return False, f"Leaf publication state is ambiguous and both sides were preserved: {path}"


def _reverse_v2_created_leaf(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    path: str,
    expected_content: dict[str, Any],
    action: dict[str, Any],
) -> _ReconciliationOutcome:
    """Reconcile the existing durable rollback intent through its private slot."""
    runtime.assert_attached()
    relative = safe_relative_path(path)
    try:
        with _open_runtime_staging(runtime, transaction_id) as staging_fd:
            try:
                parent_fd = _open_existing_parent_handle(runtime.root_fd, relative)
            except FileNotFoundError:
                # Never discard a private witness merely because public ancestry vanished.
                if not _entry_absent_at(staging_fd, action["staged_name"]):
                    return _content_conflict("Rollback public ancestry disappeared; private staging was preserved: " + path)
                return _reconciled()
            try:
                if not _directory_handle_matches_topology(runtime.root, runtime.root_fd, relative, parent_fd):
                    return _content_conflict("Rollback parent topology changed and was preserved: " + path)
                if (not _entry_absent_at(staging_fd, action["staged_name"])
                        and not _entry_absent_at(parent_fd, relative.name)):
                    return _content_conflict("Both rollback public and private leaves exist and were preserved: " + path)
                result = _quarantine_exact_regular_at(
                    parent_fd, relative=relative,
                    expected_content=expected_content,
                    expected_identity=action["installed_identity"],
                    quarantine_handle=staging_fd,
                    quarantine_name=action["staged_name"],
                )
                runtime.assert_attached()
                if result.reconciled and not _entry_absent_at(parent_fd, relative.name):
                    return _content_conflict("Rollback public leaf reappeared and was preserved: " + path)
                return result
            finally:
                os.close(parent_fd)
    except (OSError, ValueError, TransactionPrimitiveError) as exc:
        return _rollback_failure("Create rollback quarantine was preserved: " + path + ": " + str(exc))


def _rollback_v2_transaction(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    plan: dict[str, Any],
    journal: dict[str, Any],
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    reason: str,
    validated_plan_proof: _ValidatedPlanProof | None = None,
) -> CreateOnlyTransactionOutcome:
    applied_actions = copy.deepcopy(journal.get("applied_actions") or [])
    cleanup_actions = copy.deepcopy(applied_actions)
    created_directories = copy.deepcopy(journal.get("created_directories") or [])
    pending = copy.deepcopy(journal.get("pending_action"))

    def fail(detail: str) -> CreateOnlyTransactionOutcome:
        try:
            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "ROLLBACK_INCOMPLETE",
                applied_actions,
                created_directories,
                pending_action=pending,
                detail=detail,
                require_attached=False,
                validated_plan_proof=validated_plan_proof,
            )
        except Exception as journal_exc:
            detail += f"; rollback journal finalization failed: {journal_exc}"
        return CreateOnlyTransactionOutcome(
            "rollback_incomplete",
            transaction_id,
            detail=detail,
        )

    try:
        _persist_content_checkpoint(
            runtime,
            transaction_id,
            plan,
            "ROLLING_BACK",
            applied_actions,
            created_directories,
            pending_action=pending,
            detail=reason,
            require_attached=False,
            validated_plan_proof=validated_plan_proof,
        )
    except Exception as exc:
        return CreateOnlyTransactionOutcome(
            "rollback_incomplete",
            transaction_id,
            detail=f"Rollback transition could not be journaled: {exc}",
        )

    if pending is not None:
        direction = str(pending["direction"])
        path = str(pending["path"])
        kind = str(pending["kind"])
        if direction == "forward":
            reconciled, detail = _v2_reconcile_forward_pending(
                runtime,
                transaction_id,
                plan,
                pending,
                applied_actions,
                created_directories,
            )
            if not reconciled:
                return fail(detail or f"Pending forward action was preserved: {path}")
            cleanup_actions = copy.deepcopy(applied_actions)
        elif kind == "directory":
            try:
                descriptor = _open_existing_directory_handle(
                    runtime.root_fd,
                    safe_relative_path(path),
                )
            except FileNotFoundError:
                created_directories = [
                    item for item in created_directories if item.get("path") != path
                ]
            else:
                os.close(descriptor)
        else:
            installed_content = _plan_present_identity(
                next(
                    item["after"]
                    for item in _content_mutation_items(plan)
                    if item["path"] == path
                )
            )
            installed = (installed_content, pending["installed_identity"])
            if kind == "create":
                reconciliation = _reverse_v2_created_leaf(runtime, transaction_id, path, installed_content, pending)
                if not reconciliation.reconciled:
                    return fail(reconciliation.detail or "Create rollback topology was preserved: " + path)
                applied_actions = [
                    action for action in applied_actions if action.get("path") != path
                ]
            elif kind == "replace":
                target = _v2_target_observation(runtime, path)
                staged = _v2_staging_observation(
                    runtime,
                    transaction_id,
                    str(pending["staged_name"]),
                )
                before_content = _plan_present_identity(
                    next(
                        item["before"]
                        for item in _content_mutation_items(plan)
                        if item["path"] == path
                    )
                )
                backup = (before_content, pending["backup_identity"])
                if _leaf_observation_matches(target, backup) and _leaf_observation_matches(
                    staged, installed
                ):
                    applied_actions = [
                        action
                        for action in applied_actions
                        if action.get("path") != path
                    ]
        pending = None
        _persist_content_checkpoint(
            runtime,
            transaction_id,
            plan,
            "ROLLING_BACK",
            applied_actions,
            created_directories,
            detail="Durable pending action was reconciled before rollback.",
            require_attached=False,
            validated_plan_proof=validated_plan_proof,
        )

    for action in reversed(list(applied_actions)):
        runtime.assert_attached()
        path = str(action["path"])
        kind = str(action["kind"])
        relative = safe_relative_path(path)
        parent_fd = _open_existing_parent_handle(runtime.root_fd, relative)
        transaction_fd: int | None = None
        staging_fd: int | None = None
        try:
            installed_content = _plan_present_identity(
                next(
                    item["after"]
                    for item in _content_mutation_items(plan)
                    if item["path"] == path
                )
            )
            if not _leaf_matches_exact_at(
                parent_fd,
                relative.name,
                installed_content,
                action["installed_identity"],
            ):
                return fail(
                    "Rollback target changed; target and private backup were "
                    f"preserved: {path}"
                )
            pending = {"direction": "rollback", **copy.deepcopy(action)}
            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "ROLLING_BACK",
                applied_actions,
                created_directories,
                pending_action=pending,
                detail=f"Reversing exact {kind} leaf: {path}",
                require_attached=False,
                validated_plan_proof=validated_plan_proof,
            )
            _transaction_checkpoint(f"rollback:{path}:intent")
            if kind == "create":
                reconciliation = _reverse_v2_created_leaf(runtime, transaction_id, path, installed_content, action)
                if not reconciliation.reconciled:
                    return fail(reconciliation.detail or "Create rollback topology was preserved: " + path)
            else:
                transaction_fd = _open_safe_directory_at(
                    runtime.transactions_fd,
                    transaction_id,
                    label=f"managed-content/transactions/{transaction_id}",
                )
                staging_fd = _open_safe_directory_at(
                    transaction_fd,
                    "staging",
                    label=f"managed-content/transactions/{transaction_id}/staging",
                )
                before_content = _plan_present_identity(
                    next(
                        item["before"]
                        for item in _content_mutation_items(plan)
                        if item["path"] == path
                    )
                )
                if not _leaf_matches_exact_at(
                    staging_fd,
                    str(action["staged_name"]),
                    before_content,
                    action["backup_identity"],
                ):
                    return fail(
                        "Rollback backup changed; target and private backup were "
                        f"preserved: {path}"
                    )
                rename_exchange_at(
                    staging_fd,
                    str(action["staged_name"]),
                    parent_fd,
                    relative.name,
                )
                os.fsync(parent_fd)
                os.fsync(staging_fd)
            _transaction_checkpoint(f"rollback:{path}:mutation")
            if kind == "create":
                if not _entry_absent_at(parent_fd, relative.name):
                    return fail(f"Created target remains after rollback: {path}")
            else:
                before_content = _plan_present_identity(
                    next(
                        item["before"]
                        for item in _content_mutation_items(plan)
                        if item["path"] == path
                    )
                )
                if (
                    not _leaf_matches_exact_at(
                        parent_fd,
                        relative.name,
                        before_content,
                        action["backup_identity"],
                    )
                    or staging_fd is None
                    or not _leaf_matches_exact_at(
                        staging_fd,
                        str(action["staged_name"]),
                        installed_content,
                        action["installed_identity"],
                    )
                ):
                    return fail(
                        f"Exact replacement rollback validation failed: {path}"
                    )
            applied_actions.remove(action)
            pending = None
            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "ROLLING_BACK",
                applied_actions,
                created_directories,
                detail=f"Exact {kind} leaf reversed: {path}",
                require_attached=False,
                validated_plan_proof=validated_plan_proof,
            )
            _transaction_checkpoint(f"rollback:{path}:complete")
        except BaseException:
            raise
        finally:
            if staging_fd is not None:
                os.close(staging_fd)
            if transaction_fd is not None:
                os.close(transaction_fd)
            os.close(parent_fd)

    for directory_record in sorted(
        list(created_directories),
        key=lambda item: len(Path(str(item["path"])).parts),
        reverse=True,
    ):
        path = str(directory_record["path"])
        relative = safe_relative_path(path)
        parent_fd = _open_existing_parent_handle(runtime.root_fd, relative)
        try:
            descriptor = _open_safe_directory_at(
                parent_fd,
                relative.name,
                label=f"rollback directory {path}",
                expected_mode=0o755,
            )
            try:
                if (
                    not created_metadata_identity_matches(
                        observe_created_directory_metadata_fd(descriptor),
                        directory_record["identity"],
                        expected_type="directory",
                    )
                    or os.listdir(descriptor)
                ):
                    return fail(
                        f"Created directory changed and was preserved: {path}"
                    )
            finally:
                os.close(descriptor)
            pending = {
                "direction": "rollback",
                "path": path,
                "kind": "directory",
                "staged_name": _planned_directory_staging(
                    _content_mutation_plan(plan)
                )[path],
                "installed_identity": directory_record["identity"],
                "backup_identity": None,
            }
            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "ROLLING_BACK",
                applied_actions,
                created_directories,
                pending_action=pending,
                detail=f"Reversing exact created directory: {path}",
                require_attached=False,
                validated_plan_proof=validated_plan_proof,
            )
            _transaction_checkpoint(f"rollback-directory:{path}:intent")
            os.rmdir(relative.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            _transaction_checkpoint(f"rollback-directory:{path}:mutation")
            created_directories.remove(directory_record)
            pending = None
            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "ROLLING_BACK",
                applied_actions,
                created_directories,
                detail=f"Exact created directory reversed: {path}",
                require_attached=False,
                validated_plan_proof=validated_plan_proof,
            )
        finally:
            os.close(parent_fd)

    receipt_name = f"{transaction_id}.json"
    try:
        _receipt, _digest, receipt_version = _load_receipt_any_at(
            runtime.receipts_fd,
            receipt_name,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction_id,
            plan=plan,
        )
    except FileNotFoundError:
        pass
    except Exception as exc:
        return fail(f"Provisional receipt was preserved because it is invalid: {exc}")
    else:
        if receipt_version != "v2":
            return fail("Provisional receipt generation differs and was preserved.")
        os.unlink(receipt_name, dir_fd=runtime.receipts_fd)
        os.fsync(runtime.receipts_fd)
    try:
        _remove_runtime_evidence_pending_v2(runtime, transaction_id, plan)
        _remove_runtime_staging_v2(
            runtime,
            transaction_id,
            plan,
            cleanup_actions,
            committed=False,
        )
    except Exception as exc:
        return fail(f"Exact rollback cleanup failed and was preserved: {exc}")
    _persist_content_checkpoint(
        runtime,
        transaction_id,
        plan,
        "ROLLED_BACK",
        [],
        [],
        detail=reason,
        require_attached=False,
        validated_plan_proof=validated_plan_proof,
    )
    return CreateOnlyTransactionOutcome(
        "rolled_back",
        transaction_id,
        detail=reason,
    )


def _remove_pending_evidence_at(parent_descriptor: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    _validate_pending_regular_at(parent_descriptor, name)
    os.unlink(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _remove_runtime_evidence_pending(
    runtime: _ManagedRuntimeHandles,
    transaction_id: str,
    plan: dict[str, Any],
) -> None:
    for digest in sorted(
        {
            str(item["source"]["sha256"])
            for item in plan.get("paths") or []
            if isinstance(item, dict) and isinstance(item.get("source"), dict)
        }
    ):
        _remove_pending_evidence_at(
            runtime.bases_fd,
            _base_pending_name(transaction_id, digest),
        )
    _remove_pending_evidence_at(
        runtime.receipts_fd,
        _receipt_pending_name(transaction_id),
    )
    _remove_pending_evidence_at(
        runtime.state_fd,
        _manifest_pending_name(transaction_id),
    )


def _regular_leaf_matches_at(
    parent_handle: int,
    name: str,
    expected_content: dict[str, object],
    expected_identity: dict[str, object],
) -> bool:
    try:
        descriptor = _open_regular_leaf_at(parent_handle, name)
    except (FileNotFoundError, ContentPathError, OSError):
        return False
    try:
        return (
            _descriptor_content_identity(descriptor) == expected_content
            and created_metadata_identity_matches(
                observe_created_file_metadata_fd(descriptor),
                expected_identity,
                expected_type="regular_file",
            )
        )
    except (OSError, ContentPathError, TransactionPrimitiveError):
        return False
    finally:
        os.close(descriptor)


def _directory_matches_empty_at(
    parent_handle: int,
    name: str,
    expected_identity: dict[str, object],
) -> bool:
    try:
        descriptor = _open_safe_directory_at(
            parent_handle,
            name,
            label=f"rollback directory {name}",
            expected_mode=None,
        )
    except (FileNotFoundError, OSError, TransactionPrimitiveError):
        return False
    try:
        return (
            not os.listdir(descriptor)
            and created_metadata_identity_matches(
                observe_created_directory_metadata_fd(descriptor),
                expected_identity,
                expected_type="directory",
            )
        )
    except (OSError, ContentPathError):
        return False
    finally:
        os.close(descriptor)


def _unlink_exact_private_regular_at(
    parent_handle: int,
    name: str,
    expected_content: dict[str, object],
    expected_identity: dict[str, object],
) -> bool:
    descriptor: int | None = None
    try:
        descriptor = _open_regular_leaf_at(parent_handle, name)
        opened = os.fstat(descriptor)
        if (
            _descriptor_content_identity(descriptor) != expected_content
            or not created_metadata_identity_matches(
                observe_created_file_metadata_fd(descriptor),
                expected_identity,
                expected_type="regular_file",
            )
        ):
            return False
        current = os.stat(name, dir_fd=parent_handle, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            return False
        os.unlink(name, dir_fd=parent_handle)
        os.fsync(parent_handle)
        return True
    except (FileNotFoundError, OSError, ContentPathError, TransactionPrimitiveError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _rmdir_exact_private_directory_at(
    parent_handle: int,
    name: str,
    expected_identity: dict[str, object],
) -> bool:
    descriptor: int | None = None
    try:
        descriptor = _open_safe_directory_at(
            parent_handle,
            name,
            label=f"private rollback directory {name}",
            expected_mode=None,
        )
        opened = os.fstat(descriptor)
        if (
            os.listdir(descriptor)
            or not created_metadata_identity_matches(
                observe_created_directory_metadata_fd(descriptor),
                expected_identity,
                expected_type="directory",
            )
        ):
            return False
        current = os.stat(name, dir_fd=parent_handle, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            return False
        os.rmdir(name, dir_fd=parent_handle)
        os.fsync(parent_handle)
        return True
    except (FileNotFoundError, OSError, ContentPathError, TransactionPrimitiveError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _quarantine_exact_regular_at(
    parent_handle: int,
    *,
    relative: Path,
    expected_content: dict[str, object],
    expected_identity: dict[str, object],
    quarantine_handle: int,
    quarantine_name: str,
) -> _ReconciliationOutcome:
    """Reverse-publish an exact leaf into its private staging slot."""

    if _regular_leaf_matches_at(
        quarantine_handle,
        quarantine_name,
        expected_content,
        expected_identity,
    ):
        if not _unlink_exact_private_regular_at(
            quarantine_handle,
            quarantine_name,
            expected_content,
            expected_identity,
        ):
            return _rollback_failure(
                "exact private file staging changed before cleanup"
            )
        return _reconciled()
    try:
        os.stat(quarantine_name, dir_fd=quarantine_handle, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        return _rollback_failure(
            f"private file staging changed and was preserved: {relative}"
        )
    try:
        os.stat(relative.name, dir_fd=parent_handle, follow_symlinks=False)
    except FileNotFoundError:
        return _reconciled()
    if not _regular_leaf_matches_at(
        parent_handle,
        relative.name,
        expected_content,
        expected_identity,
    ):
        return _content_conflict(
            f"rollback target changed and was preserved: {relative}"
        )
    try:
        rename_no_replace_at(
            parent_handle,
            relative.name,
            quarantine_handle,
            quarantine_name,
        )
        os.fsync(parent_handle)
        os.fsync(quarantine_handle)
    except OSError as exc:
        try:
            original_absent = os.stat(
                relative.name,
                dir_fd=parent_handle,
                follow_symlinks=False,
            ) is None
        except FileNotFoundError:
            original_absent = True
        if original_absent and _regular_leaf_matches_at(
            quarantine_handle,
            quarantine_name,
            expected_content,
            expected_identity,
        ):
            pass
        elif original_absent:
            try:
                os.stat(
                    quarantine_name,
                    dir_fd=quarantine_handle,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return _reconciled()
            return _rollback_failure(
                f"private rollback staging changed and was preserved: {relative}"
            )
        else:
            return _rollback_failure(
                f"rollback quarantine publication failed: {relative}: {exc}"
            )
    if not _regular_leaf_matches_at(
        quarantine_handle,
        quarantine_name,
        expected_content,
        expected_identity,
    ):
        try:
            rename_no_replace_at(
                quarantine_handle,
                quarantine_name,
                parent_handle,
                relative.name,
            )
            os.fsync(quarantine_handle)
            os.fsync(parent_handle)
        except OSError:
            restored = False
        else:
            restored = True
        suffix = "restored" if restored else "preserved in quarantine"
        return _content_conflict(
            f"changed rollback target was {suffix}: {relative}"
        )
    if not _unlink_exact_private_regular_at(
        quarantine_handle,
        quarantine_name,
        expected_content,
        expected_identity,
    ):
        return _rollback_failure(
            "exact private file staging changed before cleanup"
        )
    return _reconciled()


def _quarantine_exact_directory_at(
    parent_handle: int,
    *,
    relative: Path,
    expected_identity: dict[str, object],
    quarantine_handle: int,
    quarantine_name: str,
) -> _ReconciliationOutcome:
    """Reverse-publish an exact empty directory into private staging."""

    if _directory_matches_empty_at(
        quarantine_handle,
        quarantine_name,
        expected_identity,
    ):
        if not _rmdir_exact_private_directory_at(
            quarantine_handle,
            quarantine_name,
            expected_identity,
        ):
            return _rollback_failure(
                "exact private directory staging changed before cleanup"
            )
        return _reconciled()
    try:
        os.stat(quarantine_name, dir_fd=quarantine_handle, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        return _rollback_failure(
            f"private directory staging changed and was preserved: {relative}"
        )
    try:
        os.stat(relative.name, dir_fd=parent_handle, follow_symlinks=False)
    except FileNotFoundError:
        return _reconciled()
    if not _directory_matches_empty_at(
        parent_handle,
        relative.name,
        expected_identity,
    ):
        return _content_conflict(
            f"created directory changed and was preserved: {relative}"
        )
    try:
        rename_no_replace_at(
            parent_handle,
            relative.name,
            quarantine_handle,
            quarantine_name,
        )
        os.fsync(parent_handle)
        os.fsync(quarantine_handle)
    except OSError as exc:
        return _rollback_failure(
            f"directory quarantine publication failed: {relative}: {exc}"
        )
    if not _directory_matches_empty_at(
        quarantine_handle,
        quarantine_name,
        expected_identity,
    ):
        try:
            rename_no_replace_at(
                quarantine_handle,
                quarantine_name,
                parent_handle,
                relative.name,
            )
            os.fsync(quarantine_handle)
            os.fsync(parent_handle)
        except OSError:
            restored = False
        else:
            restored = True
        suffix = "restored" if restored else "preserved in quarantine"
        return _content_conflict(
            f"changed created directory was {suffix}: {relative}"
        )
    if not _rmdir_exact_private_directory_at(
        quarantine_handle,
        quarantine_name,
        expected_identity,
    ):
        return _rollback_failure(
            "exact private directory staging changed before cleanup"
        )
    return _reconciled()


def _reconcile_pending_action_at(
    root: Path,
    runtime: _ManagedRuntimeHandles,
    transaction_name: str,
    plan: dict[str, Any],
    pending_action: dict[str, object],
) -> _ReconciliationOutcome:
    relative_text = str(pending_action["path"])
    relative = safe_relative_path(relative_text)
    kind = str(pending_action["kind"])
    expected_identity = pending_action["identity"]
    if kind in {"directory_create", "directory_rollback"}:
        staged_name = _planned_directory_staging(plan)[relative_text]
        try:
            with _open_runtime_directory_staging(
                runtime,
                transaction_name,
            ) as directories_fd:
                staged_matches = _directory_matches_empty_at(
                    directories_fd,
                    staged_name,
                    expected_identity,
                )
                try:
                    os.stat(
                        staged_name,
                        dir_fd=directories_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    staged_exists = False
                else:
                    staged_exists = True
        except FileNotFoundError:
            staged_matches = False
            staged_exists = False
        if staged_matches:
            try:
                with _open_runtime_directory_staging(
                    runtime,
                    transaction_name,
                ) as directories_fd:
                    if not _rmdir_exact_private_directory_at(
                        directories_fd,
                        staged_name,
                        expected_identity,
                    ):
                        return _rollback_failure(
                            "staged directory changed during reconciliation: "
                            f"{relative_text}"
                        )
            except OSError as exc:
                return _rollback_failure(
                    f"exact staged directory cleanup failed: {exc}"
                )
            return _reconciled()
        if staged_exists:
            return _rollback_failure(
                f"staged directory changed and was preserved: {relative_text}"
            )
        root_handle = _open_project_root_handle(root)
        parent_handle: int | None = None
        try:
            try:
                parent_handle = _open_existing_parent_handle(root_handle, relative)
            except FileNotFoundError:
                return _reconciled()
            if not _directory_handle_matches_topology(
                root,
                root_handle,
                relative,
                parent_handle,
            ):
                return _content_conflict(
                    f"pending directory topology changed: {relative_text}"
                )
            with _open_runtime_directory_staging(
                runtime,
                transaction_name,
            ) as directories_fd:
                return _quarantine_exact_directory_at(
                    parent_handle,
                    relative=relative,
                    expected_identity=expected_identity,
                    quarantine_handle=directories_fd,
                    quarantine_name=staged_name,
                )
        except (OSError, ContentPathError, TransactionPrimitiveError) as exc:
            return _rollback_failure(
                f"pending directory inspection failed for {relative_text}: {exc}"
            )
        finally:
            if parent_handle is not None:
                os.close(parent_handle)
            os.close(root_handle)

    planned_index = next(
        index
        for index, item in enumerate(plan["paths"])
        if item["path"] == relative_text
    )
    planned = plan["paths"][planned_index]
    staged_matches = False
    staged_exists = False
    staged_name = f"{planned_index:06d}"
    if kind in {"file_create", "file_rollback"}:
        try:
            with _open_runtime_staging(runtime, transaction_name) as staging_fd:
                staged_matches = _regular_leaf_matches_at(
                    staging_fd,
                    staged_name,
                    planned["source"],
                    expected_identity,
                )
                try:
                    os.stat(staged_name, dir_fd=staging_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    staged_exists = True
        except FileNotFoundError:
            pass
        if staged_matches:
            try:
                with _open_runtime_staging(runtime, transaction_name) as staging_fd:
                    if not _unlink_exact_private_regular_at(
                        staging_fd,
                        staged_name,
                        planned["source"],
                        expected_identity,
                    ):
                        return _rollback_failure(
                            "staged file changed during reconciliation: "
                            f"{relative_text}"
                        )
            except OSError as exc:
                return _rollback_failure(
                    f"exact staged file cleanup failed: {exc}"
                )
            return _reconciled()
        if staged_exists:
            return _rollback_failure(
                f"staged file changed and was preserved: {relative_text}"
            )
    root_handle = _open_project_root_handle(root)
    parent_handle: int | None = None
    try:
        try:
            parent_handle = _open_existing_parent_handle(root_handle, relative)
        except FileNotFoundError:
            return _reconciled()
        if not _directory_handle_matches_topology(
            root,
            root_handle,
            relative,
            parent_handle,
        ):
            return _content_conflict(
                f"pending action topology changed: {relative_text}"
            )
        with _open_runtime_staging(runtime, transaction_name) as staging_fd:
            return _quarantine_exact_regular_at(
                parent_handle,
                relative=relative,
                expected_content=planned["source"],
                expected_identity=expected_identity,
                quarantine_handle=staging_fd,
                quarantine_name=staged_name,
            )
    except (OSError, ContentPathError, TransactionPrimitiveError) as exc:
        return _rollback_failure(
            f"pending action inspection failed for {relative_text}: {exc}"
        )
    finally:
        if parent_handle is not None:
            os.close(parent_handle)
        os.close(root_handle)


def _revalidate_plan_destination(
    root: Path,
    item: dict[str, Any],
    *,
    created_directories: list[dict[str, object]],
) -> None:
    relative = safe_relative_path(str(item["path"]))
    root_metadata = os.lstat(root)
    for ancestor in item.get("ancestor_identities") or []:
        ancestor_path = root / safe_relative_path(str(ancestor["path"]))
        metadata = os.lstat(ancestor_path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != ancestor["device"]
            or metadata.st_ino != ancestor["inode"]
        ):
            raise ContentPathError(
                f"Managed-content destination ancestor changed: {ancestor['path']}"
            )
        if metadata.st_dev != root_metadata.st_dev:
            raise TransactionPrimitiveError(
                "UNSUPPORTED_METADATA: destination ancestor is on a different "
                f"filesystem: {ancestor['path']}"
            )
    for record in created_directories:
        path = root / safe_relative_path(str(record["path"]))
        if not created_directory_metadata_matches(path, record["identity"]):
            raise ContentPathError(
                f"Managed-content created directory changed: {record['path']}"
            )
    try:
        os.lstat(root / relative)
    except FileNotFoundError:
        return
    raise FileExistsError(f"Managed-content destination is no longer absent: {relative}")


def _require_live_scope_binding(
    root: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    # Local import avoids the provenance -> transaction module dependency at
    # import time while ensuring callers cannot supply their own authority.
    from .provenance import inspect_managed_content_scope

    live = inspect_managed_content_scope(root)
    if (
        getattr(live, "status", None) != "valid"
        or getattr(live, "project_id", None) != project_id
        or getattr(live, "scope_integrity", None) != scope_integrity_sha3_512
        or getattr(live, "source_policy_sha256", None) != source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content provenance changed before mutation."
        )


def _manifest_with_entries(
    existing: dict[str, Any] | None,
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
    receipt_sha256: str,
    created_metadata: dict[str, dict[str, object]],
) -> dict[str, Any]:
    entries = list(existing.get("entries") or []) if existing else []
    transactions = list(existing.get("transactions") or []) if existing else []
    existing_by_path = {
        str(item.get("path")): item for item in entries if isinstance(item, dict)
    }
    additions: list[dict[str, Any]] = []
    for item in plan["paths"]:
        path = str(item["path"])
        previous = existing_by_path.get(path)
        if previous is not None:
            if (
                previous.get("ownership") != item.get("ownership")
                or previous.get("creation_policy") != item.get("creation_policy")
                or previous.get("base") != item.get("source")
                or previous.get("source_metadata") != item.get("source_metadata")
            ):
                raise TransactionPrimitiveError(
                    "Managed-content manifest contains a different authority for "
                    f"the missing create-only path: {path}"
                )
            entries = [
                entry
                for entry in entries
                if not isinstance(entry, dict) or str(entry.get("path")) != path
            ]
        additions.append(
            {
                "path": path,
                "ownership": item["ownership"],
                "creation_policy": item["creation_policy"],
                "base": item["source"],
                "source_metadata": item["source_metadata"],
                "base_blob": {
                    "path": item["source"]["sha256"],
                    "sha256": item["source"]["sha256"],
                },
                "created_metadata": created_metadata[path],
                "introduced_by_transaction": transaction_id,
                "receipt_sha256": receipt_sha256,
            }
        )
    is_v2 = bool(existing and existing.get("schema") == "naos.upgrade.managed_content_manifest.v2")
    if is_v2:
        for entry in additions:
            entry["last_mutated_by_transaction"] = transaction_id
    result = _with_sha256_integrity(
        {
            "schema": "naos.upgrade.managed_content_manifest.v2" if is_v2 else "naos.upgrade.managed_content_manifest.v1",
            **({"minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION} if is_v2 else {}),
            "project_id": project_id,
            "scope_integrity_sha3_512": scope_integrity_sha3_512,
            "source_policy_sha256": source_policy_sha256,
            "previous_integrity_sha256": (
                (existing.get("integrity") or {}).get("value") if existing else None
            ),
            "last_transaction_id": transaction_id,
            "last_plan_sha256": plan["plan_sha256"],
            "entries": sorted([*entries, *additions], key=lambda item: str(item["path"])),
            "transactions": [
                *transactions,
                {
                    "transaction_id": transaction_id,
                    "plan": plan,
                    "receipt_sha256": receipt_sha256,
                },
            ],
        }
    )
    _validate_manifest_any(
        result,
        project_root=project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    return result


def _migrate_manifest_v1_to_v2(existing: dict[str, Any]) -> dict[str, Any]:
    """Return an ownership-preserving in-memory v2 representation."""

    if existing.get("schema") == "naos.upgrade.managed_content_manifest.v2":
        return copy.deepcopy(existing)
    if existing.get("schema") != "naos.upgrade.managed_content_manifest.v1":
        raise TransactionPrimitiveError(
            "Managed-content manifest cannot be migrated to v2."
        )
    entries = [
        {
            **copy.deepcopy(entry),
            "last_mutated_by_transaction": entry["introduced_by_transaction"],
        }
        for entry in existing["entries"]
    ]
    body = {
        key: copy.deepcopy(value)
        for key, value in existing.items()
        if key not in {"schema", "integrity"}
    }
    return _with_sha256_integrity(
        {
            "schema": "naos.upgrade.managed_content_manifest.v2",
            "minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION,
            **body,
            "entries": entries,
        }
    )


def _manifest_v2_with_actions(
    existing: dict[str, Any],
    *,
    project_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    transaction_id: str,
    plan: dict[str, Any],
    receipt_sha256: str,
    receipt_actions: list[dict[str, Any]],
) -> dict[str, Any]:
    migrated = _migrate_manifest_v1_to_v2(existing)
    entries_by_path = {
        str(entry["path"]): copy.deepcopy(entry)
        for entry in migrated["entries"]
    }
    actions_by_path = {str(action["path"]): action for action in receipt_actions}
    for item in _content_mutation_items(plan):
        path = str(item["path"])
        kind = str(item["mutation"]["kind"])
        previous = entries_by_path.get(path)
        ownership = item["ownership"]
        if kind == "replace":
            if previous is None:
                raise TransactionPrimitiveError(
                    f"Managed-content replacement provenance is missing: {path}"
                )
            before = item["before"]
            expected_before = {
                "kind": before["kind"],
                "mode": before["mode"],
                "size": before["size"],
                "sha256": before["sha256"],
            }
            if (
                previous.get("ownership") != "kit_owned_derived"
                or previous.get("ownership") != ownership.get("before")
                or previous.get("creation_policy")
                != ownership.get("creation_policy")
                or previous.get("base") != expected_before
            ):
                raise TransactionPrimitiveError(
                    f"Managed-content replacement authority changed: {path}"
                )
            introduced_by = previous["introduced_by_transaction"]
        else:
            if previous is not None:
                raise TransactionPrimitiveError(
                    f"Managed-content create unexpectedly has prior authority: {path}"
                )
            introduced_by = transaction_id
        after = _content_aware_after_identity(item)
        action = actions_by_path.get(path)
        if action is None:
            raise TransactionPrimitiveError(
                f"Managed-content receipt action is missing: {path}"
            )
        entries_by_path[path] = {
            "path": path,
            "ownership": ownership["after"],
            "creation_policy": ownership["creation_policy"],
            "base": after,
            "source_metadata": item["after_metadata"],
            "base_blob": {
                "path": after["sha256"],
                "sha256": after["sha256"],
            },
            "created_metadata": action["installed_metadata"],
            "introduced_by_transaction": introduced_by,
            "last_mutated_by_transaction": transaction_id,
            "receipt_sha256": receipt_sha256,
        }
    result = _with_sha256_integrity(
        {
            "schema": "naos.upgrade.managed_content_manifest.v2",
            "minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION,
            "project_id": project_id,
            "scope_integrity_sha3_512": scope_integrity_sha3_512,
            "source_policy_sha256": source_policy_sha256,
            "previous_integrity_sha256": existing["integrity"]["value"],
            "last_transaction_id": transaction_id,
            "last_plan_sha256": plan["plan_sha256"],
            "entries": sorted(entries_by_path.values(), key=lambda entry: str(entry["path"])),
            "transactions": [
                *copy.deepcopy(existing["transactions"]),
                {
                    "transaction_id": transaction_id,
                    "plan": plan,
                    "receipt_sha256": receipt_sha256,
                },
            ],
        }
    )
    _validate_manifest_v2(
        result,
        project_root=project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    return result


def _validate_content_mutation_authority(
    existing: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    """Reject mutation authority that differs from the current manifest."""

    migrated = _migrate_manifest_v1_to_v2(existing)
    entries_by_path = {
        str(entry["path"]): entry for entry in migrated["entries"]
    }
    for item in _content_mutation_items(plan):
        path = str(item["path"])
        kind = str(item["mutation"]["kind"])
        previous = entries_by_path.get(path)
        ownership = item["ownership"]
        if kind == "replace":
            if previous is None:
                raise TransactionPrimitiveError(
                    f"Managed-content replacement provenance is missing: {path}"
                )
            before = item["before"]
            expected_before = {
                "kind": before["kind"],
                "mode": before["mode"],
                "size": before["size"],
                "sha256": before["sha256"],
            }
            if (
                previous.get("ownership") != "kit_owned_derived"
                or previous.get("ownership") != ownership.get("before")
                or ownership.get("after") != ownership.get("before")
                or previous.get("creation_policy")
                != ownership.get("creation_policy")
                or previous.get("base") != expected_before
            ):
                raise TransactionPrimitiveError(
                    f"Managed-content replacement authority changed: {path}"
                )
        elif previous is not None:
            raise TransactionPrimitiveError(
                f"Managed-content create unexpectedly has prior authority: {path}"
            )


def _base_blob_matches(bases_root: Path, entry: dict[str, Any]) -> bool:
    base = entry["base"]
    base_blob = entry["base_blob"]
    if (
        base_blob.get("path") != base.get("sha256")
        or base_blob.get("sha256") != base.get("sha256")
    ):
        return False
    return _historical_base_matches(bases_root, str(base["sha256"]))


def _historical_base_matches(bases_root: Path, expected_sha256: str) -> bool:
    """Validate one immutable content-addressed base by its bound digest."""

    if SHA256_RE.fullmatch(expected_sha256) is None:
        return False
    path = bases_root / expected_sha256
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        return False
    try:
        digest = _secure_regular_file_sha256(path)
    except (OSError, TransactionPrimitiveError):
        return False
    return digest == expected_sha256


def _manifest_entry_lineage_status(
    manifest: dict[str, Any],
    *,
    transaction_id: str,
    path: str,
) -> tuple[str, dict[str, Any]] | None:
    """Resolve ordered installed authority through exact recreations and updates.

    Content-aware plans include non-mutating paths; only their eligible mutations
    advance lineage. Missing live leaves do not remove their recorded authority.
    """
    entry = next((item for item in manifest["entries"] if item["path"] == path), None)
    if entry is None:
        return None
    history: list[tuple[str, str, dict[str, Any]]] = []
    for transaction in manifest["transactions"]:
        plan = transaction["plan"]
        content_aware = plan.get("schema") in CONTENT_AWARE_PLAN_SCHEMAS
        items = _content_mutation_items(plan) if content_aware else plan["paths"]
        for item in items:
            if item["path"] == path:
                history.append((transaction["transaction_id"],
                                "content_aware" if content_aware else "create_only", item))
    positions = {identifier: index for index, (identifier, _kind, _item) in enumerate(history)}
    current_id = entry.get("last_mutated_by_transaction", entry["introduced_by_transaction"])
    if transaction_id not in positions or not history or current_id != history[-1][0]:
        return None

    previous: dict[str, Any] | None = None
    previous_kind: str | None = None
    previous_rule: Any = None
    for _identifier, kind, item in history:
        if kind == "create_only":
            authority = {
                "base": item["source"], "source_metadata": item["source_metadata"],
                "ownership": item["ownership"], "creation_policy": item["creation_policy"],
            }
            # A create-only successor may recreate only the exact preceding
            # authority, including an authority installed by a v2 replacement.
            if previous is not None and (
                authority != previous
                or (previous_kind == "create_only" and previous_rule != item.get("source_policy_rule"))
            ):
                return None
        else:
            ownership = item["ownership"]
            if previous is not None:
                if (
                    item["mutation"]["kind"] != "replace"
                    or _plan_present_identity(item["before"]) != previous["base"]
                    or ownership.get("before") != previous["ownership"]
                    or ownership.get("after") != previous["ownership"]
                    or ownership.get("creation_policy") != previous["creation_policy"]
                ):
                    return None
            elif item["mutation"]["kind"] != "create":
                return None
            authority = {
                "base": _content_aware_after_identity(item),
                "source_metadata": item["after_metadata"],
                "ownership": ownership["after"],
                "creation_policy": ownership["creation_policy"],
            }
        previous = authority
        previous_kind = kind
        previous_rule = item.get("source_policy_rule")
    if previous is None or any(entry.get(key) != value for key, value in previous.items()):
        return None
    if current_id == transaction_id:
        return "current", entry
    if any(kind == "content_aware" for _identifier, kind, _item in history[positions[transaction_id] + 1:]):
        return "superseded_content_update", entry
    return "superseded_exact_recreation", entry


def _base_blob_matches_at(
    bases_descriptor: int,
    entry: dict[str, Any],
) -> bool:
    base = entry["base"]
    base_blob = entry["base_blob"]
    if (
        base_blob.get("path") != base.get("sha256")
        or base_blob.get("sha256") != base.get("sha256")
    ):
        return False
    return _historical_base_matches_at(
        bases_descriptor,
        str(base["sha256"]),
    )


def _historical_base_matches_at(
    bases_descriptor: int,
    expected_sha256: str,
) -> bool:
    """Descriptor-relative equivalent of :func:`_historical_base_matches`."""

    if SHA256_RE.fullmatch(expected_sha256) is None:
        return False
    try:
        metadata = os.stat(
            expected_sha256,
            dir_fd=bases_descriptor,
            follow_symlinks=False,
        )
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            return False
        digest = _secure_regular_file_sha256_at(
            bases_descriptor,
            expected_sha256,
        )
    except (FileNotFoundError, OSError, TransactionPrimitiveError):
        return False
    return digest == expected_sha256


def _validated_transaction_receipt(
    manifest: dict[str, Any],
    *,
    transaction_id: str,
    receipts_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> tuple[dict[str, Any], str] | None:
    transaction = next(
        (
            item
            for item in manifest.get("transactions") or []
            if isinstance(item, dict)
            and item.get("transaction_id") == transaction_id
        ),
        None,
    )
    if transaction is None:
        return None
    receipt, receipt_sha256 = _load_receipt(
        receipts_root / f"{transaction_id}.json",
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        transaction_id=transaction_id,
        plan=transaction["plan"],
    )
    if transaction.get("receipt_sha256") != receipt_sha256:
        raise TransactionPrimitiveError(
            f"Managed-content manifest receipt digest is invalid: {transaction_id}"
        )
    for relative_text, identity in (receipt.get("created_metadata") or {}).items():
        lineage = _manifest_entry_lineage_status(
            manifest,
            transaction_id=transaction_id,
            path=str(relative_text),
        )
        if lineage is None or (
            lineage[0] == "current"
            and lineage[1].get("created_metadata") != identity
        ):
            raise TransactionPrimitiveError(
                f"Managed-content manifest created-metadata binding is invalid: {relative_text}"
            )
    return receipt, receipt_sha256


def _validated_transaction_receipt_at(
    manifest: dict[str, Any],
    *,
    transaction_id: str,
    receipts_descriptor: int,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> tuple[dict[str, Any], str] | None:
    transaction = next(
        (
            item
            for item in manifest.get("transactions") or []
            if isinstance(item, dict)
            and item.get("transaction_id") == transaction_id
        ),
        None,
    )
    if transaction is None:
        return None
    receipt, receipt_sha256, receipt_version = _load_receipt_any_at(
        receipts_descriptor,
        f"{transaction_id}.json",
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        transaction_id=transaction_id,
        plan=transaction["plan"],
    )
    if transaction.get("receipt_sha256") != receipt_sha256:
        raise TransactionPrimitiveError(
            f"Managed-content manifest receipt digest is invalid: {transaction_id}"
        )
    identities = (receipt.get("created_metadata") or {}) if receipt_version == "v1" else {
        action["path"]: action["installed_metadata"] for action in receipt["actions"]
    }
    for relative_text, identity in identities.items():
        lineage = _manifest_entry_lineage_status(
            manifest,
            transaction_id=transaction_id,
            path=str(relative_text),
        )
        if lineage is None or (
            lineage[0] == "current"
            and lineage[1].get("created_metadata") != identity
        ):
            raise TransactionPrimitiveError(
                "Managed-content manifest created-metadata binding is invalid: "
                f"{relative_text}"
            )
    return receipt, receipt_sha256


def _committed_transaction_failures(
    root: Path,
    manifest: dict[str, Any] | None,
    *,
    transaction_id: str,
    plan: dict[str, Any],
    bases_root: Path,
    receipts_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> list[str]:
    failures: list[str] = []
    transaction = (
        next(
            (
                item
                for item in manifest.get("transactions") or []
                if isinstance(item, dict)
                and item.get("transaction_id") == transaction_id
            ),
            None,
        )
        if manifest
        else None
    )
    if transaction is None:
        return ["cumulative manifest transaction is missing"]
    if transaction.get("plan") != plan:
        failures.append("manifest/journal plan differs")
    try:
        _validated_transaction_receipt(
            manifest,
            transaction_id=transaction_id,
            receipts_root=receipts_root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
    except Exception as exc:
        failures.append(f"receipt validation failed: {exc}")
    for item in plan["paths"]:
        relative_text = str(item["path"])
        lineage = _manifest_entry_lineage_status(
            manifest,
            transaction_id=transaction_id,
            path=relative_text,
        )
        entry = lineage[1] if lineage is not None else None
        if (
            entry is None
            or entry.get("base") != item["source"]
            or entry.get("source_metadata") != item["source_metadata"]
            or not _base_blob_matches(bases_root, entry)
            or not _managed_file_matches(
                root,
                relative_text,
                item["source"],
                entry["created_metadata"],
            )
        ):
            failures.append(relative_text)
    return failures


def _committed_transaction_failures_at(
    root: Path,
    manifest: dict[str, Any] | None,
    *,
    transaction_id: str,
    plan: dict[str, Any],
    journal: dict[str, Any],
    runtime: _ManagedRuntimeHandles,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> list[str]:
    failures: list[str] = []
    failures.extend(
        _created_directory_inventory_failures_at(
            runtime.root_fd,
            [
                item
                for item in journal.get("created_directories") or []
                if isinstance(item, dict)
            ],
        )
    )
    failures.extend(_plan_ancestor_inventory_failures_at(runtime.root_fd, plan))
    transaction = (
        next(
            (
                item
                for item in manifest.get("transactions") or []
                if isinstance(item, dict)
                and item.get("transaction_id") == transaction_id
            ),
            None,
        )
        if manifest
        else None
    )
    if transaction is None:
        return ["cumulative manifest transaction is missing"]
    if transaction.get("plan") != plan:
        failures.append("manifest/journal plan differs")
    try:
        _validated_transaction_receipt_at(
            manifest,
            transaction_id=transaction_id,
            receipts_descriptor=runtime.receipts_fd,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
    except Exception as exc:
        failures.append(f"receipt validation failed: {exc}")
    for item in plan["paths"]:
        relative_text = str(item["path"])
        lineage = _manifest_entry_lineage_status(
            manifest,
            transaction_id=transaction_id,
            path=relative_text,
        )
        entry = lineage[1] if lineage is not None else None
        if lineage is not None and lineage[0] == "superseded_content_update":
            if not _historical_base_matches_at(runtime.bases_fd, item["source"]["sha256"]):
                failures.append(relative_text)
            continue
        if (
            entry is None
            or entry.get("base") != item["source"]
            or entry.get("source_metadata") != item["source_metadata"]
            or not _base_blob_matches_at(runtime.bases_fd, entry)
        ):
            failures.append(relative_text)
    return failures


def _already_applied(
    root: Path,
    manifest: dict[str, Any] | None,
    plan: dict[str, Any],
    *,
    bases_root: Path,
    receipts_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> str | None:
    if not manifest:
        return None
    transaction = next(
        (
            item
            for item in reversed(manifest.get("transactions") or [])
            if isinstance(item, dict) and item.get("plan") == plan
        ),
        None,
    )
    if transaction is None:
        return None
    transaction_id = str(transaction["transaction_id"])
    _validated_transaction_receipt(
        manifest,
        transaction_id=transaction_id,
        receipts_root=receipts_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    entries = {
        str(item.get("path")): item
        for item in manifest.get("entries") or []
        if isinstance(item, dict)
    }
    for planned in plan.get("paths") or []:
        path = str(planned.get("path"))
        entry = entries.get(path)
        if (
            entry is None
            or entry.get("base") != planned.get("source")
            or entry.get("source_metadata") != planned.get("source_metadata")
        ):
            return None
        if (
            entry.get("introduced_by_transaction") != transaction_id
            or not _base_blob_matches(bases_root, entry)
            or not _managed_file_matches(
                root,
                path,
                planned["source"],
                entry["created_metadata"],
                [
                    ancestor
                    for ancestor in planned.get("ancestor_identities") or []
                    if isinstance(ancestor, dict)
                ],
            )
        ):
            return None
    return transaction_id


def _already_applied_at(
    root: Path,
    manifest: dict[str, Any] | None,
    plan: dict[str, Any],
    *,
    runtime: _ManagedRuntimeHandles,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> str | None:
    if not manifest:
        return None
    transaction = next(
        (
            item
            for item in reversed(manifest.get("transactions") or [])
            if isinstance(item, dict) and item.get("plan") == plan
        ),
        None,
    )
    if transaction is None:
        return None
    transaction_id = str(transaction["transaction_id"])
    _validated_transaction_receipt_at(
        manifest,
        transaction_id=transaction_id,
        receipts_descriptor=runtime.receipts_fd,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
    )
    entries = {
        str(item.get("path")): item
        for item in manifest.get("entries") or []
        if isinstance(item, dict)
    }
    for planned in plan.get("paths") or []:
        path = str(planned.get("path"))
        entry = entries.get(path)
        if (
            entry is None
            or entry.get("base") != planned.get("source")
            or entry.get("source_metadata") != planned.get("source_metadata")
            or entry.get("introduced_by_transaction") != transaction_id
            or not _base_blob_matches_at(runtime.bases_fd, entry)
            or not _managed_file_matches_at(
                runtime.root_fd,
                path,
                planned["source"],
                entry["created_metadata"],
                [
                    ancestor
                    for ancestor in planned.get("ancestor_identities") or []
                    if isinstance(ancestor, dict)
                ],
            )
        ):
            return None
    return transaction_id


def _require_manifest_topology_at(
    runtime: _ManagedRuntimeHandles,
    manifest: dict[str, Any],
    *,
    project_root: Path,
    source_policy_sha256: str,
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    inventory = _validate_terminal_transaction_inventory_any_at(
        runtime, manifest, project_root=project_root,
    )
    return {key: (journal, plan) for key, (journal, plan, _version) in inventory.items()}


def managed_content_sources_current(
    project_root: Path,
    *,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    sources: list[tuple[Path, Path]],
    operation: str,
    inputs: dict[str, Any],
    require_exact_operation_inventory: bool = False,
) -> tuple[bool, str | None]:
    """Return true only for the exact content, operation, and input request.

    Additional managed paths introduced by other operations may coexist.  When
    ``require_exact_operation_inventory`` is true, every path ever committed by
    the named operation must be part of this request; this prevents a smaller
    profile request from being reported as the complete current scaffold.
    """

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=root / _MANAGED_RUNTIME_RELATIVES["transaction_root"],
        lock_path=root / _MANAGED_RUNTIME_RELATIVES["lock_path"],
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=root / _MANAGED_RUNTIME_RELATIVES["transaction_root"],
        lock_path=root / _MANAGED_RUNTIME_RELATIVES["lock_path"],
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        manifest, _manifest_version = _load_manifest_any_at(
            runtime.state_fd,
            project_root=root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        if manifest is None:
            return False, None
        _require_manifest_topology_at(
            runtime,
            manifest,
            project_root=root,
            source_policy_sha256=source_policy_sha256,
        )
        _validate_manifest_evidence_any_at(
            runtime, manifest, project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        entries = {
            str(item.get("path")): item
            for item in manifest.get("entries") or []
            if isinstance(item, dict)
        }
        requested_paths = {
            safe_relative_path(relative).as_posix()
            for relative, _source in sources
        }
        if len(requested_paths) != len(sources):
            raise TransactionPrimitiveError(
                "Managed-content current-state request contains duplicate paths."
            )
        candidate: dict[str, Any] | None = None
        operation_paths: set[str] = set()
        for item in manifest.get("transactions") or []:
            if not isinstance(item, dict):
                continue
            plan = item.get("plan")
            if not isinstance(plan, dict) or plan.get("operation") != operation:
                continue
            plan_paths = {
                str(path.get("path"))
                for path in plan.get("paths") or []
                if isinstance(path, dict)
            }
            operation_paths.update(plan_paths)
            if plan.get("inputs") == inputs and plan_paths == requested_paths:
                candidate = item
        if candidate is None:
            return False, None
        if require_exact_operation_inventory and operation_paths != requested_paths:
            return False, None
        transaction_id = str(candidate.get("transaction_id") or "")
        if not transaction_id:
            return False, None
        _validated_transaction_receipt_at(
            manifest,
            transaction_id=transaction_id,
            receipts_descriptor=runtime.receipts_fd,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        for relative, source in sources:
            path = safe_relative_path(relative).as_posix()
            entry = entries.get(path)
            if entry is None:
                return False, None
            identity, source_metadata = regular_file_observation(source)
            expected = {
                "kind": identity.kind,
                "mode": identity.mode,
                "size": identity.size,
                "sha256": identity.sha256,
            }
            if (
                entry.get("base") != expected
                or entry.get("source_metadata")
                != source_metadata_contract(source_metadata)
                or entry.get("introduced_by_transaction") != transaction_id
                or not _base_blob_matches_at(runtime.bases_fd, entry)
                or not _managed_file_matches_at(
                    runtime.root_fd,
                    path,
                    expected,
                    entry["created_metadata"],
                )
            ):
                return False, None
        runtime.assert_attached()
        return True, transaction_id


def current_managed_content_paths(
    project_root: Path,
    *,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> set[str]:
    """Return only manifest paths whose current bytes still equal their base."""

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=root / _MANAGED_RUNTIME_RELATIVES["transaction_root"],
        lock_path=root / _MANAGED_RUNTIME_RELATIVES["lock_path"],
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=root / _MANAGED_RUNTIME_RELATIVES["transaction_root"],
        lock_path=root / _MANAGED_RUNTIME_RELATIVES["lock_path"],
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        manifest, _manifest_version = _load_manifest_any_at(
            runtime.state_fd,
            project_root=root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        if manifest is None:
            return set()
        _require_manifest_topology_at(
            runtime,
            manifest,
            project_root=root,
            source_policy_sha256=source_policy_sha256,
        )
        _validate_manifest_evidence_any_at(
            runtime, manifest, project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        result: set[str] = set()
        validated_receipts: set[str] = set()
        for entry in manifest.get("entries") or []:
            relative = safe_relative_path(str(entry.get("path") or ""))
            relative_text = relative.as_posix()
            base = entry.get("base")
            transaction_id = str(entry.get("introduced_by_transaction") or "")
            if transaction_id not in validated_receipts:
                _validated_transaction_receipt_at(
                    manifest,
                    transaction_id=transaction_id,
                    receipts_descriptor=runtime.receipts_fd,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=source_policy_sha256,
                )
                validated_receipts.add(transaction_id)
            if (
                _base_blob_matches_at(runtime.bases_fd, entry)
                and _managed_file_matches_at(
                    runtime.root_fd,
                    relative,
                    base,
                    entry["created_metadata"],
                )
            ):
                result.add(relative_text)
        runtime.assert_attached()
        return result


def recorded_managed_content_paths(
    project_root: Path,
    *,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> set[str]:
    """Return every strictly validated path without requiring a live leaf.

    This inventory preserves create-once ownership when adopter-owned content
    is later deleted.  Profile-transition lineage is deliberately irrelevant:
    a standalone add can prove what NAOS created without pretending that the
    project was initialized under a NAOS profile.
    """

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=root / _MANAGED_RUNTIME_RELATIVES["transaction_root"],
        lock_path=root / _MANAGED_RUNTIME_RELATIVES["lock_path"],
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=root / _MANAGED_RUNTIME_RELATIVES["transaction_root"],
        lock_path=root / _MANAGED_RUNTIME_RELATIVES["lock_path"],
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        manifest, manifest_version = _load_manifest_any_at(
            runtime.state_fd,
            project_root=root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        if manifest is None:
            return set()
        if manifest_version == "v1":
            _require_manifest_topology_at(
                runtime,
                manifest,
                project_root=root,
                source_policy_sha256=source_policy_sha256,
            )
        else:
            _validate_terminal_transaction_inventory_any_at(
                runtime,
                manifest,
                project_root=root,
            )
        _validate_manifest_evidence_any_at(
            runtime,
            manifest,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
        )
        result = {
            safe_relative_path(str(entry["path"])).as_posix()
            for entry in manifest["entries"]
        }
        runtime.assert_attached()
        return result


def _validate_plan_preconditions_at(
    root: Path,
    manifest: dict[str, Any] | None,
    plan: dict[str, Any],
    *,
    runtime: _ManagedRuntimeHandles,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    """Validate non-mutating managed paths while the transaction lock is held."""

    preconditions = plan.get("preconditions") or []
    if not preconditions:
        return
    if manifest is None:
        raise TransactionPrimitiveError(
            "Managed-content preconditions require an existing manifest."
        )
    entries = {
        str(item.get("path")): item
        for item in manifest.get("entries") or []
        if isinstance(item, dict)
    }
    validated_receipts: set[str] = set()
    for condition in preconditions:
        relative_text = str(condition["path"])
        entry = entries.get(relative_text)
        if entry is None:
            raise TransactionPrimitiveError(
                "Managed-content provenance precondition is missing: "
                f"{relative_text}"
            )
        transaction_id = str(entry.get("introduced_by_transaction") or "")
        if transaction_id not in validated_receipts:
            _validated_transaction_receipt_at(
                manifest,
                transaction_id=transaction_id,
                receipts_descriptor=runtime.receipts_fd,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=source_policy_sha256,
            )
            validated_receipts.add(transaction_id)
        if (
            entry.get("base") != condition.get("source")
            or not source_metadata_creation_equivalent(
                entry.get("source_metadata"),
                condition.get("source_metadata"),
                creation_identity=plan["creation_identity"],
            )
            or not _base_blob_matches_at(runtime.bases_fd, entry)
            or not _managed_file_matches_at(
                runtime.root_fd,
                relative_text,
                condition["source"],
                entry["created_metadata"],
                condition["ancestor_identities"],
            )
        ):
            raise TransactionPrimitiveError(
                "Managed-content provenance precondition changed: "
                f"{relative_text}"
            )
    runtime.assert_attached()


def apply_create_only_plan(
    project_root: Path,
    *,
    plan: dict[str, Any],
    sources: list[tuple[Path, Path]],
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> CreateOnlyTransactionOutcome:
    """Apply one all-or-nothing absent-file plan with a durable journal/receipt."""

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    validate_create_only_plan(plan, project_root=root)
    planned_creation_identity = plan.get("creation_identity")
    try:
        validate_managed_creation_identity(planned_creation_identity)
    except ContentPathError as exc:
        raise TransactionPrimitiveError(str(exc)) from exc
    if planned_creation_identity != managed_creation_identity():
        raise TransactionPrimitiveError(
            "UNSUPPORTED_METADATA: executing identity differs from the "
            "digest-bound managed-content creation identity."
        )
    assert isinstance(planned_creation_identity, dict)
    if (
        not project_id.startswith("urn:uuid:")
        or SHA3_512_RE.fullmatch(scope_integrity_sha3_512) is None
        or plan.get("source_policy_sha256") != scope_source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content apply provenance binding is invalid."
        )
    if plan.get("status") != "ready_create_only":
        return CreateOnlyTransactionOutcome(
            "blocked_collision", None, detail="Create-only plan contains a preserved collision."
        )
    expected_digest = canonical_sha256(_plan_payload(plan))
    if plan.get("plan_sha256") != expected_digest:
        raise TransactionPrimitiveError("Managed-content plan digest is invalid.")
    source_map = {safe_relative_path(relative).as_posix(): source for relative, source in sources}
    planned_paths = [str(item.get("path")) for item in plan.get("paths") or []]
    if (
        len(source_map) != len(sources)
        or len(planned_paths) != len(sources)
        or set(source_map) != set(planned_paths)
    ):
        raise TransactionPrimitiveError("Managed-content plan/source inventory differs.")
    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        existing_manifest, _manifest_version = _load_manifest_any_at(
            runtime.state_fd,
            project_root=root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        _validate_terminal_transaction_inventory_any_at(
            runtime, existing_manifest, project_root=root,
            source_policy_sha256=scope_source_policy_sha256,
        )
        if existing_manifest is not None:
            _validate_manifest_evidence_any_at(
                runtime, existing_manifest, project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
            )
        _validate_plan_preconditions_at(
            root,
            existing_manifest,
            plan,
            runtime=runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        prior_transaction = _already_applied_at(
            root,
            existing_manifest,
            plan,
            runtime=runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        if prior_transaction:
            return CreateOnlyTransactionOutcome(
                "already_applied",
                prior_transaction,
                str(receipts_root / f"{prior_transaction}.json"),
            )
        for item in plan["paths"]:
            _revalidate_plan_destination(
                root,
                item,
                created_directories=[],
            )
            path = root / safe_relative_path(str(item["path"]))
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                return CreateOnlyTransactionOutcome(
                    "blocked_collision",
                    None,
                    detail=f"Destination is no longer absent: {item['path']}",
                )
            observed_content, observed_metadata = regular_file_observation(
                source_map[str(item["path"])]
            )
            if observed_content.__dict__ != {
                "presence": "present",
                **item["source"],
            } or source_metadata_contract(observed_metadata) != item["source_metadata"]:
                raise TransactionPrimitiveError(
                    f"Managed-content source changed before staging: {item['path']}"
                )
        transaction_id = f"MC-{expected_digest[:16]}-{uuid.uuid4().hex[:8]}"
        preparation_name = f".preparing-{transaction_id}"
        runtime.assert_attached()
        _require_supported_preparation_parents(runtime)
        os.mkdir(preparation_name, 0o700, dir_fd=runtime.transactions_fd)
        os.fsync(runtime.transactions_fd)
        applied: list[str] = []
        applied_identities: dict[str, dict[str, object]] = {}
        created_directories: list[dict[str, object]] = []
        pending_action: dict[str, object] | None = None
        journal = _journal_value(
            transaction_id=transaction_id,
            plan=plan,
            state="PREPARED",
            applied_paths=applied,
            applied_identities=applied_identities,
            created_directories=created_directories,
        )
        directory_staged = _planned_directory_staging(plan)
        with _open_runtime_transaction(runtime, preparation_name) as preparation_fd:
            os.mkdir("staging", 0o700, dir_fd=preparation_fd)
            os.mkdir("directories", 0o700, dir_fd=preparation_fd)
            os.fsync(preparation_fd)
            staging_fd = _open_safe_directory_at(
                preparation_fd,
                "staging",
                label=f"{preparation_name}/staging",
            )
            directories_fd = _open_safe_directory_at(
                preparation_fd,
                "directories",
                label=f"{preparation_name}/directories",
            )
            try:
                _write_json_new_at(preparation_fd, "journal.json", journal)
                staged: dict[str, str] = {}
                for index, item in enumerate(plan["paths"]):
                    source = source_map[str(item["path"])]
                    staged_name = f"{index:06d}"
                    _copy_regular_file_new_at(
                        source,
                        staging_fd,
                        staged_name,
                        expected_content=item["source"],
                        expected_metadata=item["source_metadata"],
                        creation_identity=planned_creation_identity,
                    )
                    if not _file_matches_at(
                        staging_fd,
                        staged_name,
                        item["source"],
                    ):
                        raise TransactionPrimitiveError(
                            f"Staged content validation failed: {item['path']}"
                        )
                    staged[str(item["path"])] = staged_name
                os.fsync(staging_fd)
                for relative_text, staged_name in directory_staged.items():
                    os.mkdir(staged_name, 0o755, dir_fd=directories_fd)
                    os.chmod(
                        staged_name,
                        0o755,
                        dir_fd=directories_fd,
                        follow_symlinks=False,
                    )
                    staged_directory_fd = _open_safe_directory_at(
                        directories_fd,
                        staged_name,
                        label=(
                            f"{preparation_name}/directories/{staged_name} "
                            f"for {relative_text}"
                        ),
                        expected_mode=0o755,
                    )
                    try:
                        if os.listdir(staged_directory_fd):
                            raise TransactionPrimitiveError(
                                f"Staged directory is not empty: {relative_text}"
                            )
                    finally:
                        os.close(staged_directory_fd)
                    os.fsync(directories_fd)
                os.fsync(preparation_fd)
            finally:
                os.close(directories_fd)
                os.close(staging_fd)
        runtime.assert_attached()
        rename_no_replace_at(
            runtime.transactions_fd,
            preparation_name,
            runtime.transactions_fd,
            transaction_id,
        )
        os.fsync(runtime.transactions_fd)
        runtime.assert_attached()
        for item in plan["paths"]:
            base_name = str(item["source"]["sha256"])
            try:
                os.stat(
                    base_name,
                    dir_fd=runtime.bases_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                with _open_runtime_staging(runtime, transaction_id) as staging_fd:
                    _publish_bytes_new_at(
                        runtime.bases_fd,
                        base_name,
                        _read_regular_file_bytes_at(
                            staging_fd,
                            staged[str(item["path"])],
                        ),
                        pending_name=_base_pending_name(
                            transaction_id,
                            base_name,
                        ),
                    )
            else:
                if not _content_addressed_base_matches_at(
                    runtime.bases_fd,
                    base_name,
                    str(item["source"]["sha256"]),
                ):
                    raise TransactionPrimitiveError("Content-addressed base collision.")
            if not _content_addressed_base_matches_at(
                runtime.bases_fd,
                base_name,
                str(item["source"]["sha256"]),
            ):
                raise TransactionPrimitiveError(
                    f"Content-addressed base validation failed: {item['path']}"
                )
        receipt_name = f"{transaction_id}.json"
        receipt_path = receipts_root / receipt_name
        try:
            _replace_runtime_journal(
                runtime,
                transaction_id,
                _journal_value(
                    transaction_id=transaction_id,
                    plan=plan,
                    state="APPLYING",
                    applied_paths=applied,
                    applied_identities=applied_identities,
                    created_directories=created_directories,
                ),
            )
            for item in plan["paths"]:
                relative = safe_relative_path(str(item["path"]))

                def persist_created_directory() -> None:
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _journal_value(
                            transaction_id=transaction_id,
                            plan=plan,
                            state="APPLYING",
                            applied_paths=applied,
                            applied_identities=applied_identities,
                            created_directories=created_directories,
                            pending_action=pending_action,
                        ),
                    )

                def publish_created_directory(
                    destination_parent_fd: int,
                    destination_name: str,
                    relative_text: str,
                ) -> tuple[int, dict[str, object]]:
                    nonlocal pending_action
                    staged_name = directory_staged.get(relative_text)
                    if staged_name is None:
                        raise TransactionPrimitiveError(
                            "Destination directory was not absent in the bound plan: "
                            f"{relative_text}"
                        )
                    with _open_runtime_directory_staging(
                        runtime,
                        transaction_id,
                    ) as directories_fd:
                        staged_directory_fd = _open_safe_directory_at(
                            directories_fd,
                            staged_name,
                            label=(
                                f"managed-content/transactions/{transaction_id}/"
                                f"directories/{staged_name}"
                            ),
                            expected_mode=0o755,
                        )
                        try:
                            if os.listdir(staged_directory_fd):
                                raise TransactionPrimitiveError(
                                    "Managed-content staged directory changed: "
                                    f"{relative_text}"
                                )
                            staged_identity = observe_created_directory_metadata_fd(
                                staged_directory_fd
                            )
                            pending_action = {
                                "kind": "directory_create",
                                "path": relative_text,
                                "identity": staged_identity,
                            }
                            _replace_runtime_journal(
                                runtime,
                                transaction_id,
                                _journal_value(
                                    transaction_id=transaction_id,
                                    plan=plan,
                                    state="APPLYING",
                                    applied_paths=applied,
                                    applied_identities=applied_identities,
                                    created_directories=created_directories,
                                    pending_action=pending_action,
                                ),
                            )
                            runtime.assert_attached()
                            rename_no_replace_at(
                                directories_fd,
                                staged_name,
                                destination_parent_fd,
                                destination_name,
                            )
                            os.fsync(destination_parent_fd)
                            os.fsync(directories_fd)
                        finally:
                            os.close(staged_directory_fd)
                    child = os.open(
                        destination_name,
                        _directory_open_flags(),
                        dir_fd=destination_parent_fd,
                    )
                    try:
                        if (
                            not created_metadata_identity_matches(
                                observe_created_directory_metadata_fd(child),
                                staged_identity,
                                expected_type="directory",
                            )
                        ):
                            raise ContentPathError(
                                "Published directory metadata changed: "
                                f"{relative_text}"
                            )
                    except BaseException:
                        os.close(child)
                        raise
                    pending_action = None
                    return child, staged_identity

                root_handle = _open_project_root_handle(root)
                parent_handle: int | None = None
                transaction_handle: int | None = None
                staging_handle: int | None = None
                staged_handle: int | None = None
                destination_handle: int | None = None
                try:
                    runtime.assert_attached()
                    parent_handle = _open_destination_parent_handle(
                        root_handle,
                        relative,
                        item,
                        created_directories,
                        publish_directory=publish_created_directory,
                        on_created=persist_created_directory,
                    )
                    if not _directory_handle_matches_topology(
                        root,
                        root_handle,
                        relative,
                        parent_handle,
                    ):
                        raise ContentPathError(
                            f"Managed-content destination topology changed: {relative}"
                        )
                    transaction_handle = _open_safe_directory_at(
                        runtime.transactions_fd,
                        transaction_id,
                        label=f"managed-content/transactions/{transaction_id}",
                    )
                    staging_handle = _open_safe_directory_at(
                        transaction_handle,
                        "staging",
                        label=f"managed-content/transactions/{transaction_id}/staging",
                    )
                    staged_name = staged[str(item["path"])]
                    staged_handle = _open_regular_leaf_at(
                        staging_handle,
                        staged_name,
                    )
                    staged_identity = observe_created_file_metadata_fd(staged_handle)
                    pending_action = {
                        "kind": "file_create",
                        "path": relative.as_posix(),
                        "identity": staged_identity,
                    }
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _journal_value(
                            transaction_id=transaction_id,
                            plan=plan,
                            state="APPLYING",
                            applied_paths=applied,
                            applied_identities=applied_identities,
                            created_directories=created_directories,
                            pending_action=pending_action,
                        ),
                    )
                    runtime.assert_attached()
                    rename_no_replace_at(
                        staging_handle,
                        staged_name,
                        parent_handle,
                        relative.name,
                    )
                    os.fsync(parent_handle)
                    os.fsync(staging_handle)
                    runtime.assert_attached()
                    if not _directory_handle_matches_topology(
                        root,
                        root_handle,
                        relative,
                        parent_handle,
                    ):
                        raise ContentPathError(
                            f"Managed-content destination topology changed during publication: {relative}"
                        )
                    destination_handle = _open_regular_leaf_at(
                        parent_handle,
                        relative.name,
                    )
                    created_identity = observe_created_file_metadata_fd(
                        destination_handle
                    )
                    if not created_metadata_identity_matches(
                        created_identity, staged_identity, expected_type="regular_file"
                    ):
                        raise ContentPathError(
                            f"Managed-content published metadata changed: {relative}"
                        )
                    applied.append(relative.as_posix())
                    applied_identities[relative.as_posix()] = created_identity
                    pending_action = None
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _journal_value(
                            transaction_id=transaction_id,
                            plan=plan,
                            state="APPLYING",
                            applied_paths=applied,
                            applied_identities=applied_identities,
                            created_directories=created_directories,
                            pending_action=None,
                        ),
                    )
                finally:
                    for descriptor in (
                        destination_handle,
                        staged_handle,
                        staging_handle,
                        transaction_handle,
                        parent_handle,
                        root_handle,
                    ):
                        if descriptor is not None:
                            os.close(descriptor)
            _replace_runtime_journal(
                runtime,
                transaction_id,
                _journal_value(
                    transaction_id=transaction_id,
                    plan=plan,
                    state="VALIDATING",
                    applied_paths=applied,
                    applied_identities=applied_identities,
                    created_directories=created_directories,
                ),
            )
            for item in plan["paths"]:
                relative_text = str(item["path"])
                if (
                    relative_text not in applied_identities
                    or not _managed_file_matches_at(
                        runtime.root_fd,
                        relative_text,
                        item["source"],
                        applied_identities[relative_text],
                    )
                ):
                    raise TransactionPrimitiveError(
                        f"Post-apply content validation failed: {item['path']}"
                    )
            _validate_plan_preconditions_at(
                root,
                existing_manifest,
                plan,
                runtime=runtime,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
            )
            receipt = _with_sha256_integrity(
                {
                    "schema": "naos.upgrade.managed_content_receipt.v1",
                    "project_id": project_id,
                    "scope_integrity_sha3_512": scope_integrity_sha3_512,
                    "source_policy_sha256": scope_source_policy_sha256,
                    "transaction_id": transaction_id,
                    "plan_sha256": plan["plan_sha256"],
                    "status": "COMMITTED",
                    "paths": plan["paths"],
                    "created_metadata": applied_identities,
                    "replacement_performed": False,
                }
            )
            receipt_sha256 = _validate_receipt(
                receipt,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
                transaction_id=transaction_id,
                plan=plan,
            )
            runtime.assert_attached()
            _publish_json_new_at(
                runtime.receipts_fd,
                receipt_name,
                receipt,
                pending_name=_receipt_pending_name(transaction_id),
            )
            runtime.assert_attached()
            manifest = _manifest_with_entries(
                existing_manifest,
                project_root=root,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
                transaction_id=transaction_id,
                plan=plan,
                receipt_sha256=receipt_sha256,
                created_metadata=applied_identities,
            )
            if existing_manifest is None:
                _publish_json_new_at(
                    runtime.state_fd,
                    "manifest.json",
                    manifest,
                    pending_name=_manifest_pending_name(transaction_id),
                )
            else:
                _replace_json_atomically_at(
                    runtime.state_fd,
                    "manifest.json",
                    manifest,
                    pending_name=_manifest_pending_name(transaction_id),
                    expected_current=existing_manifest,
                )
            runtime.assert_attached()
            try:
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    _journal_value(
                        transaction_id=transaction_id,
                        plan=plan,
                        state="COMMITTED",
                        applied_paths=applied,
                        applied_identities=applied_identities,
                        created_directories=created_directories,
                    ),
                )
            except Exception as exc:
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    str(receipt_path),
                    f"Content and receipt committed; journal finalization requires recovery: {exc}",
                )
            try:
                _remove_runtime_staging(runtime, transaction_id, plan)
            except (OSError, TransactionPrimitiveError) as cleanup_exc:
                detail = (
                    "Content and commit evidence are durable, but exact staging "
                    f"cleanup requires recovery: {cleanup_exc}"
                )
                try:
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _journal_value(
                            transaction_id=transaction_id,
                            plan=plan,
                            state="RECOVERY_REQUIRED",
                            applied_paths=applied,
                            applied_identities=applied_identities,
                            created_directories=created_directories,
                            detail=detail,
                        ),
                    )
                except Exception as journal_exc:
                    detail += f"; journal finalization failed: {journal_exc}"
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    str(receipt_path),
                    detail,
                )
            return CreateOnlyTransactionOutcome(
                "committed", transaction_id, str(receipt_path)
            )
        except Exception as exc:
            pending_cleanup_failure: str | None = None
            try:
                _remove_runtime_evidence_pending(runtime, transaction_id, plan)
            except Exception as pending_exc:
                pending_cleanup_failure = str(pending_exc)
            try:
                visible_manifest, _manifest_version = _load_manifest_any_at(
                    runtime.state_fd,
                    project_root=root,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                )
            except FileNotFoundError:
                visible_manifest = None
            except Exception as manifest_exc:
                detail = (
                    "Manifest publication may have crossed the commit point and "
                    f"cannot be validated; target state was preserved: {exc}; "
                    f"manifest validation failed: {manifest_exc}"
                )
                if pending_cleanup_failure is not None:
                    detail += (
                        "; pending evidence cleanup failed: "
                        + pending_cleanup_failure
                    )
                try:
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _journal_value(
                            transaction_id=transaction_id,
                            plan=plan,
                            state="RECOVERY_REQUIRED",
                            applied_paths=applied,
                            applied_identities=applied_identities,
                            created_directories=created_directories,
                            pending_action=pending_action,
                            detail=detail,
                        ),
                        require_attached=False,
                    )
                except Exception as journal_exc:
                    detail += f"; journal finalization failed: {journal_exc}"
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    (
                        str(receipt_path)
                        if receipt_name in os.listdir(runtime.receipts_fd)
                        else None
                    ),
                    detail,
                )
            manifest_records_transaction = bool(
                visible_manifest
                and any(
                    isinstance(item, dict)
                    and item.get("transaction_id") == transaction_id
                    for item in visible_manifest.get("transactions") or []
                )
            )
            if manifest_records_transaction:
                detail = (
                    "Manifest commit point crossed; target state was preserved "
                    f"for recovery: {exc}"
                )
                if pending_cleanup_failure is not None:
                    detail += (
                        "; pending evidence cleanup failed: "
                        + pending_cleanup_failure
                    )
                try:
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _journal_value(
                            transaction_id=transaction_id,
                            plan=plan,
                            state="RECOVERY_REQUIRED",
                            applied_paths=applied,
                            applied_identities=applied_identities,
                            created_directories=created_directories,
                            pending_action=pending_action,
                            detail=detail,
                        ),
                        require_attached=False,
                    )
                except Exception as journal_exc:
                    detail += f"; journal finalization failed: {journal_exc}"
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    str(receipt_path),
                    detail,
                )
            rollback_failures: list[str] = []
            rollback_conflicts: list[str] = []
            if pending_cleanup_failure is not None:
                rollback_failures.append(
                    "pending evidence cleanup failed: " + pending_cleanup_failure
                )
            try:
                rollback_journal = _load_runtime_journal(runtime, transaction_id)
                _validate_journal(rollback_journal, project_root=root)
            except Exception as journal_exc:
                detail = (
                    f"{exc}; rollback journal could not be loaded safely: {journal_exc}"
                )
                return CreateOnlyTransactionOutcome(
                    "rollback_incomplete",
                    transaction_id,
                    detail=detail,
                )
            applied = list(rollback_journal.get("applied_paths") or [])
            applied_identities = dict(
                rollback_journal.get("applied_identities") or {}
            )
            created_directories = list(
                rollback_journal.get("created_directories") or []
            )
            pending_action = rollback_journal.get("pending_action")

            def persist_rollback_state(*, detail: str | None = None) -> None:
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    _journal_value(
                        transaction_id=transaction_id,
                        plan=plan,
                        state="ROLLING_BACK",
                        applied_paths=applied,
                        applied_identities=applied_identities,
                        created_directories=created_directories,
                        pending_action=pending_action,
                        detail=detail,
                    ),
                    require_attached=False,
                )

            try:
                persist_rollback_state(detail="Rollback started after apply failure.")
            except Exception as journal_exc:
                return CreateOnlyTransactionOutcome(
                    "rollback_incomplete",
                    transaction_id,
                    detail=f"Rollback transition could not be journaled: {journal_exc}",
                )

            if pending_action is not None:
                reconciliation = _reconcile_pending_action_at(
                    root,
                    runtime,
                    transaction_id,
                    plan,
                    pending_action,
                )
                if reconciliation.reconciled:
                    pending_kind = str(pending_action["kind"])
                    pending_path = str(pending_action["path"])
                    if pending_kind == "file_rollback":
                        if pending_path in applied:
                            applied.remove(pending_path)
                        applied_identities.pop(pending_path, None)
                    elif pending_kind == "directory_rollback":
                        created_directories = [
                            item
                            for item in created_directories
                            if item.get("path") != pending_path
                        ]
                    pending_action = None
                    try:
                        persist_rollback_state(
                            detail="Exact pending action was reversed during rollback."
                        )
                    except Exception as journal_exc:
                        return CreateOnlyTransactionOutcome(
                            "rollback_incomplete",
                            transaction_id,
                            detail=(
                                "Reconciled pending action could not be journaled; "
                                f"recovery must resume: {journal_exc}"
                            ),
                        )
                else:
                    detail = (
                        reconciliation.detail
                        or "pre-action intent could not be reconciled"
                    )
                    if reconciliation.status == "content_conflict":
                        rollback_conflicts.append(detail)
                    else:
                        rollback_failures.append(detail)
            try:
                _load_receipt_at(
                    runtime.receipts_fd,
                    receipt_name,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                    transaction_id=transaction_id,
                    plan=plan,
                )
            except FileNotFoundError:
                receipt_present = False
            except Exception as receipt_exc:
                rollback_failures.append(f"cannot validate provisional receipt: {receipt_exc}")
                receipt_present = False
            else:
                receipt_present = True
            if receipt_present:
                try:
                    os.unlink(receipt_name, dir_fd=runtime.receipts_fd)
                    os.fsync(runtime.receipts_fd)
                except OSError as receipt_exc:
                    rollback_failures.append(
                        f"cannot remove provisional receipt: {receipt_exc}"
                    )
            if pending_action is None:
                for relative_text in reversed(list(applied)):
                    applied_identity = applied_identities.get(relative_text)
                    if applied_identity is None:
                        rollback_failures.append(
                            f"applied identity is missing: {relative_text}"
                        )
                        continue
                    pending_action = {
                        "kind": "file_rollback",
                        "path": relative_text,
                        "identity": applied_identity,
                    }
                    try:
                        persist_rollback_state(
                            detail=f"Reversing exact applied leaf: {relative_text}"
                        )
                        reconciliation = _reconcile_pending_action_at(
                            root,
                            runtime,
                            transaction_id,
                            plan,
                            pending_action,
                        )
                    except Exception as rollback_exc:
                        reconciliation = _rollback_failure(str(rollback_exc))
                    if not reconciliation.reconciled:
                        detail = reconciliation.detail or (
                            f"cannot reverse exact applied leaf: {relative_text}"
                        )
                        if reconciliation.status == "content_conflict":
                            rollback_conflicts.append(detail)
                        else:
                            rollback_failures.append(detail)
                        break
                    applied.remove(relative_text)
                    applied_identities.pop(relative_text, None)
                    pending_action = None
                    try:
                        persist_rollback_state(
                            detail=f"Exact applied leaf reversed: {relative_text}"
                        )
                    except Exception as journal_exc:
                        return CreateOnlyTransactionOutcome(
                            "rollback_incomplete",
                            transaction_id,
                            detail=(
                                "Reversed leaf could not be journaled; recovery must "
                                f"resume: {relative_text}: {journal_exc}"
                            ),
                        )
            if pending_action is None:
                for directory_record in sorted(
                    list(created_directories),
                    key=lambda item: len(Path(str(item["path"])).parts),
                    reverse=True,
                ):
                    relative_text = str(directory_record["path"])
                    pending_action = {
                        "kind": "directory_rollback",
                        "path": relative_text,
                        "identity": directory_record["identity"],
                    }
                    try:
                        persist_rollback_state(
                            detail=f"Reversing exact created directory: {relative_text}"
                        )
                        reconciliation = _reconcile_pending_action_at(
                            root,
                            runtime,
                            transaction_id,
                            plan,
                            pending_action,
                        )
                    except Exception as rollback_exc:
                        reconciliation = _rollback_failure(str(rollback_exc))
                    if not reconciliation.reconciled:
                        detail = reconciliation.detail or (
                            f"cannot reverse created directory: {relative_text}"
                        )
                        if reconciliation.status == "content_conflict":
                            rollback_conflicts.append(detail)
                        else:
                            rollback_failures.append(detail)
                        break
                    created_directories = [
                        item
                        for item in created_directories
                        if item != directory_record
                    ]
                    pending_action = None
                    try:
                        persist_rollback_state(
                            detail=f"Exact created directory reversed: {relative_text}"
                        )
                    except Exception as journal_exc:
                        return CreateOnlyTransactionOutcome(
                            "rollback_incomplete",
                            transaction_id,
                            detail=(
                                "Reversed directory could not be journaled; recovery "
                                f"must resume: {relative_text}: {journal_exc}"
                            ),
                        )
            if pending_action is None:
                try:
                    _remove_runtime_staging(runtime, transaction_id, plan)
                except (OSError, TransactionPrimitiveError) as staging_exc:
                    rollback_failures.append(
                        f"cannot remove exact transaction staging: {staging_exc}"
                    )
            if rollback_failures:
                state = "ROLLBACK_INCOMPLETE"
            elif rollback_conflicts:
                state = "RECOVERY_REQUIRED"
            else:
                state = "ROLLED_BACK"
            detail = str(exc)
            if rollback_conflicts:
                detail += "; " + "; ".join(rollback_conflicts)
            if rollback_failures:
                detail += "; " + "; ".join(rollback_failures)
            try:
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    _journal_value(
                        transaction_id=transaction_id,
                        plan=plan,
                        state=state,
                        applied_paths=applied,
                        applied_identities=applied_identities,
                        created_directories=created_directories,
                        pending_action=pending_action,
                        detail=detail,
                    ),
                    require_attached=False,
                )
            except Exception as journal_exc:
                detail += f"; journal finalization failed: {journal_exc}"
                state = "ROLLBACK_INCOMPLETE"
            return CreateOnlyTransactionOutcome(
                (
                    "rollback_incomplete"
                    if state == "ROLLBACK_INCOMPLETE"
                    else "recovery_required"
                    if state == "RECOVERY_REQUIRED"
                    else "rolled_back"
                ),
                transaction_id,
                detail=detail,
            )


def _validate_terminal_transaction_inventory_any_at(
    runtime: _ManagedRuntimeHandles,
    manifest: dict[str, Any] | None,
    *,
    project_root: Path,
    source_policy_sha256: str | None = None,
) -> dict[str, tuple[dict[str, Any], dict[str, Any], str]]:
    manifest_transactions = {
        item["transaction_id"]: item
        for item in (manifest or {}).get("transactions") or []
    }
    expected_policy = source_policy_sha256 or (manifest or {}).get("source_policy_sha256")
    inventory: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {}
    for transaction_name in sorted(os.listdir(runtime.transactions_fd)):
        if transaction_name.startswith(".preparing-"):
            raise TransactionPrimitiveError(
                "A managed-content transaction preparation requires recovery "
                f"before apply: {transaction_name}"
            )
        if TRANSACTION_ID_RE.fullmatch(transaction_name) is None:
            raise TransactionPrimitiveError(
                "Managed-content transaction inventory contains an unknown entry: "
                + transaction_name
            )
        with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
            journal, transaction_plan, version = _load_content_checkpoint_at(
                transaction_fd, project_root=project_root, label=transaction_name)
        if journal.get("transaction_id") != transaction_name:
            raise TransactionPrimitiveError(
                "Managed-content transaction directory/journal binding differs."
            )
        state = str(journal.get("state") or "")
        if state not in TERMINAL_CONTENT_STATES:
            raise TransactionPrimitiveError(
                "A managed-content transaction requires recovery before apply: "
                + transaction_name
            )
        policy_digest = (
            transaction_plan.get("source_policy_sha256") if version == "v1"
            else (transaction_plan.get("source_policy", {}).get("provenance") or {}).get("binding_sha256")
        )
        if policy_digest != expected_policy:
            raise TransactionPrimitiveError(
                "Managed-content transaction source-policy binding differs."
            )
        if state == "ROLLED_BACK":
            try:
                os.stat(f"{transaction_name}.json", dir_fd=runtime.receipts_fd, follow_symlinks=False)
            except FileNotFoundError:
                receipt_exists = False
            else:
                receipt_exists = True
            if transaction_name in manifest_transactions or receipt_exists:
                raise TransactionPrimitiveError("A rolled-back managed-content transaction has conflicting commit evidence.")
        if state == "COMMITTED":
            if manifest_transactions.get(transaction_name, {}).get("plan") != transaction_plan:
                raise TransactionPrimitiveError("Managed-content manifest/journal plan binding differs: " + transaction_name)
            topology_failures = _committed_content_topology_failures_at(
                runtime.root_fd,
                journal,
                transaction_plan,
            )
            if topology_failures:
                raise TransactionPrimitiveError(
                    ("Committed managed-content topology differs: " if version == "v2"
                     else "Managed-content committed topology changed before apply; evidence recovery required: ")
                    + "; ".join(topology_failures)
                )
        inventory[transaction_name] = (journal, transaction_plan, version)
    manifest_transaction_ids = {
        str(item.get("transaction_id"))
        for item in (manifest or {}).get("transactions") or []
        if isinstance(item, dict)
    }
    committed_ids = {
        transaction_id
        for transaction_id, (journal, _plan, _version) in inventory.items()
        if journal.get("state") == "COMMITTED"
    }
    if manifest_transaction_ids != committed_ids:
        raise TransactionPrimitiveError(
            "Managed-content cumulative journal inventory differs from the manifest; "
            "missing committed journals: " + ", ".join(sorted(manifest_transaction_ids - committed_ids))
            + "; unmanifested committed journals: " + ", ".join(sorted(committed_ids - manifest_transaction_ids))
        )
    return inventory


def _validate_manifest_evidence_any_at(
    runtime: _ManagedRuntimeHandles,
    manifest: dict[str, Any],
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
) -> None:
    historical_base_digests: set[str] = set()
    for transaction in manifest.get("transactions") or []:
        transaction_id = str(transaction["transaction_id"])
        receipt, digest, receipt_version = _load_receipt_any_at(
            runtime.receipts_fd,
            f"{transaction_id}.json",
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=source_policy_sha256,
            transaction_id=transaction_id,
            plan=transaction["plan"],
        )
        expected_version = (
            "v2"
            if transaction["plan"].get("schema") in CONTENT_AWARE_PLAN_SCHEMAS
            else "v1"
        )
        if (
            digest != transaction.get("receipt_sha256")
            or receipt_version != expected_version
        ):
            raise TransactionPrimitiveError(
                "Managed-content receipt generation or digest differs: "
                + transaction_id
            )
        identities = (receipt.get("created_metadata") or {}) if receipt_version == "v1" else {
            action["path"]: action["installed_metadata"] for action in receipt["actions"]
        }
        for path, identity in identities.items():
            lineage = _manifest_entry_lineage_status(
                manifest, transaction_id=transaction_id, path=path,
            )
            if lineage is None:
                raise TransactionPrimitiveError(
                    "Managed-content historical installed-path lineage is invalid: " + path
                )
            if lineage[0] == "current" and lineage[1]["created_metadata"] != identity:
                raise TransactionPrimitiveError(
                    "Managed-content manifest created-metadata binding is invalid: " + path
                )
        for entry in manifest.get("entries") or []:
            current_id = entry.get("last_mutated_by_transaction", entry["introduced_by_transaction"])
            if current_id == transaction_id and identities.get(entry["path"]) != entry["created_metadata"]:
                raise TransactionPrimitiveError("Managed-content manifest created-metadata binding is invalid: " + entry["path"])
        historical_base_digests.update(
            _receipt_historical_base_digests(
                receipt,
                receipt_version=receipt_version,
                plan=transaction["plan"],
            )
        )
    for entry in manifest.get("entries") or []:
        if not _base_blob_matches_at(runtime.bases_fd, entry):
            raise TransactionPrimitiveError(
                "Managed-content recoverable base is invalid: "
                + str(entry.get("path"))
            )
    for digest in sorted(historical_base_digests):
        if not _historical_base_matches_at(runtime.bases_fd, digest):
            raise TransactionPrimitiveError(
                "Managed-content historical recoverable base is invalid: "
                + digest
            )


def _already_applied_v2_at(
    runtime: _ManagedRuntimeHandles,
    manifest: dict[str, Any],
    plan: dict[str, Any],
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    source_policy_sha256: str,
    allow_superseded: bool = False,
) -> str | None:
    transaction = next(
        (
            item
            for item in reversed(manifest.get("transactions") or [])
            if isinstance(item, dict) and item.get("plan") == plan
        ),
        None,
    )
    if transaction is None:
        return None
    transaction_id = str(transaction["transaction_id"])
    receipt, receipt_sha256, receipt_version = _load_receipt_any_at(
        runtime.receipts_fd,
        f"{transaction_id}.json",
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        source_policy_sha256=source_policy_sha256,
        transaction_id=transaction_id,
        plan=plan,
    )
    if (
        receipt_version != "v2"
        or receipt_sha256 != transaction.get("receipt_sha256")
    ):
        return None
    entries = {
        str(entry["path"]): entry
        for entry in manifest.get("entries") or []
        if isinstance(entry, dict)
    }
    for action in receipt["actions"]:
        path = str(action["path"])
        entry = entries.get(path)
        current_transaction_id = transaction_id
        current_receipt_sha256 = receipt_sha256
        if entry is not None and entry.get("last_mutated_by_transaction") != transaction_id:
            if not allow_superseded:
                return None
            # Recovery validates an immutable historical commit against the
            # manifest's later authority, not against the historical live leaf.
            # Exact-repeat apply retains the default, stricter current check.
            transactions = manifest.get("transactions") or []
            positions = {item["transaction_id"]: index for index, item in enumerate(transactions)}
            current_transaction_id = str(entry.get("last_mutated_by_transaction") or "")
            if (
                positions.get(current_transaction_id, -1) <= positions[transaction_id]
                or _manifest_entry_lineage_status(manifest, transaction_id=transaction_id, path=path) is None
            ):
                return None
            successor = transactions[positions[current_transaction_id]]
            current_receipt, current_receipt_sha256, current_version = _load_receipt_any_at(
                runtime.receipts_fd,
                f"{current_transaction_id}.json",
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=source_policy_sha256,
                transaction_id=current_transaction_id,
                plan=successor["plan"],
            )
            if current_receipt_sha256 != successor.get("receipt_sha256"):
                return None
            if current_version == "v1":
                current_item = next((item for item in current_receipt["paths"] if item["path"] == path), None)
                if current_item is None:
                    return None
                action = {
                    "after": {"presence": "present", **current_item["source"]},
                    "installed_metadata": current_receipt["created_metadata"][path],
                }
            else:
                current_action = next((item for item in current_receipt["actions"] if item["path"] == path), None)
                if current_action is None:
                    return None
                action = current_action
        if (
            entry is None
            or entry.get("last_mutated_by_transaction") != current_transaction_id
            or entry.get("receipt_sha256") != current_receipt_sha256
            or entry.get("base") != _plan_present_identity(action["after"])
            or entry.get("created_metadata") != action["installed_metadata"]
            or not _base_blob_matches_at(runtime.bases_fd, entry)
            or not _managed_file_matches_at(
                runtime.root_fd,
                path,
                entry["base"],
                entry["created_metadata"],
            )
        ):
            return None
    return transaction_id


def _validate_content_apply_inputs_at(
    runtime: _ManagedRuntimeHandles,
    plan: dict[str, Any],
    sources: list[tuple[Path, Path]],
) -> dict[str, Path]:
    source_map: dict[str, Path] = {}
    for relative, source in sources:
        path = safe_relative_path(relative).as_posix()
        if path in source_map:
            raise TransactionPrimitiveError(
                f"Managed-content source binding is duplicated: {path}"
            )
        source_map[path] = source
    required_sources = {
        str(item["path"])
        for item in plan["paths"]
        if isinstance(item.get("after"), dict)
        and item["after"].get("presence") == "present"
    }
    if set(source_map) != required_sources:
        raise TransactionPrimitiveError(
            "Managed-content content-aware plan/source inventory differs."
        )
    ancestor_failures = _plan_ancestor_inventory_failures_at(runtime.root_fd, plan)
    if ancestor_failures:
        raise TransactionPrimitiveError(
            "Managed-content destination topology changed before apply: "
            + "; ".join(ancestor_failures)
        )
    for item in plan["paths"]:
        path = str(item["path"])
        after = item["after"]
        if after["presence"] == "present":
            source_content, source_metadata = regular_file_observation(source_map[path])
            if (
                source_content.__dict__
                != {"presence": "present", **_plan_present_identity(after)}
                or source_metadata_contract(source_metadata)
                != item["after_metadata"]
            ):
                raise TransactionPrimitiveError(
                    f"Managed-content source changed before staging: {path}"
                )
        before = item["before"]
        if before["presence"] == "absent":
            if _v2_target_observation(runtime, path) is not None:
                raise TransactionPrimitiveError(
                    f"Managed-content target changed after planning: {path}"
                )
        elif before["presence"] == "present":
            if not _managed_file_matches_at(
                runtime.root_fd,
                path,
                _plan_present_identity(before),
                item["before_metadata"],
                item["ancestor_identities"],
            ):
                raise TransactionPrimitiveError(
                    f"Managed-content target changed after planning: {path}"
                )
        else:
            raise TransactionPrimitiveError(
                f"Managed-content apply refuses an unknown current identity: {path}"
            )
        mutation = item["mutation"]
        if mutation["eligible"] is not True:
            continue
        if mutation["kind"] == "create":
            if _v2_target_observation(runtime, path) is not None:
                raise TransactionPrimitiveError(
                    f"Managed-content create destination is no longer absent: {path}"
                )
    return source_map


def inspect_content_aware_plan_application(
    project_root: Path,
    *,
    plan: dict[str, Any],
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> CreateOnlyTransactionOutcome | None:
    """Return a verified exact prior application without creating a transaction."""

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    validate_content_aware_plan(plan, project_root=root)
    if plan.get("status") != "ready":
        return None
    if (
        plan.get("project")
        != {
            "root_binding": str(root),
            "project_id": project_id,
            "scope_integrity_sha3_512": scope_integrity_sha3_512,
        }
        or not project_id.startswith("urn:uuid:")
        or SHA3_512_RE.fullmatch(scope_integrity_sha3_512) is None
        or (plan.get("source_policy") or {}).get("provenance", {}).get(
            "binding_sha256"
        )
        != scope_source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content content-aware apply provenance binding is invalid."
        )
    try:
        validate_managed_creation_identity(plan.get("creation_identity"))
    except ContentPathError as exc:
        raise TransactionPrimitiveError(str(exc)) from exc
    if plan.get("creation_identity") != managed_creation_identity():
        raise TransactionPrimitiveError(
            "UNSUPPORTED_METADATA: executing identity differs from the "
            "digest-bound managed-content creation identity."
        )
    _content_mutation_items(plan)
    if plan.get("plan_sha256") != canonical_sha256(_plan_payload(plan)):
        raise TransactionPrimitiveError("Managed-content plan digest is invalid.")

    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        existing_manifest, _manifest_version = _load_manifest_any_at(
            runtime.state_fd,
            project_root=root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        if existing_manifest is None:
            raise TransactionPrimitiveError(
                "Content-aware apply requires a validated managed-content manifest."
            )
        _validate_terminal_transaction_inventory_any_at(
            runtime,
            existing_manifest,
            project_root=root,
        )
        _validate_manifest_evidence_any_at(
            runtime,
            existing_manifest,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        prior_transaction = _already_applied_v2_at(
            runtime,
            existing_manifest,
            plan,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        if prior_transaction is None:
            return None
        return CreateOnlyTransactionOutcome(
            "already_applied",
            prior_transaction,
            str(receipts_root / f"{prior_transaction}.json"),
        )


def apply_content_aware_plan(
    project_root: Path,
    *,
    plan: dict[str, Any],
    sources: list[tuple[Path, Path]],
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> CreateOnlyTransactionOutcome:
    """Apply one digest-bound content-aware create/replace transaction."""

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    # The caller retains its input object.  All later checkpoints use this
    # private, type-preserving copy of the exact plan that passed validation.
    plan = copy.deepcopy(plan)
    validate_content_aware_plan(plan, project_root=root)
    validated_plan_proof = _ValidatedPlanProof(
        root=str(root),
        canonical_plan=canonical_bytes(plan),
        typed_plan=copy.deepcopy(plan),
    )
    if plan.get("status") != "ready":
        return CreateOnlyTransactionOutcome(
            "blocked_collision",
            None,
            detail="Content-aware plan is not mutation-ready.",
        )
    if (
        plan.get("project")
        != {
            "root_binding": str(root),
            "project_id": project_id,
            "scope_integrity_sha3_512": scope_integrity_sha3_512,
        }
        or not project_id.startswith("urn:uuid:")
        or SHA3_512_RE.fullmatch(scope_integrity_sha3_512) is None
        or (plan.get("source_policy") or {}).get("provenance", {}).get(
            "binding_sha256"
        )
        != scope_source_policy_sha256
    ):
        raise TransactionPrimitiveError(
            "Managed-content content-aware apply provenance binding is invalid."
        )
    try:
        validate_managed_creation_identity(plan.get("creation_identity"))
    except ContentPathError as exc:
        raise TransactionPrimitiveError(str(exc)) from exc
    if plan.get("creation_identity") != managed_creation_identity():
        raise TransactionPrimitiveError(
            "UNSUPPORTED_METADATA: executing identity differs from the "
            "digest-bound managed-content creation identity."
        )
    mutations = _content_mutation_items(plan)
    expected_digest = canonical_sha256(_plan_payload(plan))
    if plan.get("plan_sha256") != expected_digest:
        raise TransactionPrimitiveError("Managed-content plan digest is invalid.")

    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        existing_manifest, _manifest_version = _load_manifest_any_at(
            runtime.state_fd,
            project_root=root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        if existing_manifest is None:
            raise TransactionPrimitiveError(
                "Content-aware apply requires a validated managed-content manifest."
            )
        _validate_terminal_transaction_inventory_any_at(
            runtime,
            existing_manifest,
            project_root=root,
        )
        _validate_manifest_evidence_any_at(
            runtime,
            existing_manifest,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        prior_transaction = _already_applied_v2_at(
            runtime,
            existing_manifest,
            plan,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        if prior_transaction is not None:
            return CreateOnlyTransactionOutcome(
                "already_applied",
                prior_transaction,
                str(receipts_root / f"{prior_transaction}.json"),
            )
        drift_paths = content_aware_drift_paths(plan["paths"])
        if drift_paths:
            raise TransactionPrimitiveError(
                "GOVERNANCE_DRIFT: selected kit-owned paths require review: "
                + ", ".join(drift_paths)
            )
        _validate_content_mutation_authority(existing_manifest, plan)
        snapshot = load_managed_content_manifest_snapshot(
            root,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
            manifest_path=manifest_path,
            bases_root=bases_root,
            receipts_root=receipts_root,
        )
        if (
            snapshot is None
            or snapshot.get("snapshot_sha256")
            != (plan.get("manifest") or {}).get("snapshot_sha256")
        ):
            raise TransactionPrimitiveError(
                "Managed-content manifest changed after the plan was bound."
            )
        source_map = _validate_content_apply_inputs_at(runtime, plan, sources)

        transaction_id = f"MC-{expected_digest[:16]}-{uuid.uuid4().hex[:8]}"
        preparation_name = f".preparing-{transaction_id}"
        published = False
        _require_supported_preparation_parents(runtime)
        os.mkdir(preparation_name, 0o700, dir_fd=runtime.transactions_fd)
        os.fsync(runtime.transactions_fd)
        applied_actions: list[dict[str, Any]] = []
        created_directories: list[dict[str, object]] = []
        pending_action: dict[str, object] | None = None
        plan_raw = validated_plan_proof.canonical_plan + b"\n"
        initial_body = _compact_checkpoint_body(transaction_id, _compact_plan_reference(plan_raw),
                                                "PREPARED", applied_actions, created_directories)
        _validate_content_checkpoint_fields(initial_body, plan,
            validate_plan=lambda selected: _validate_checkpoint_plan_proof(
                selected, project_root=root, proof=validated_plan_proof))
        initial_journal = _with_sha256_integrity(initial_body)
        staged_names = {
            str(item["path"]): f"{index:06d}"
            for index, item in enumerate(mutations)
        }
        directory_staged = _planned_directory_staging(
            _content_mutation_plan(plan)
        )
        try:
            with _open_runtime_transaction(runtime, preparation_name) as preparation_fd:
                os.mkdir("staging", 0o700, dir_fd=preparation_fd)
                os.mkdir("directories", 0o700, dir_fd=preparation_fd)
                os.fsync(preparation_fd)
                staging_fd = _open_safe_directory_at(
                    preparation_fd,
                    "staging",
                    label=f"{preparation_name}/staging",
                )
                directories_fd = _open_safe_directory_at(
                    preparation_fd,
                    "directories",
                    label=f"{preparation_name}/directories",
                )
                try:
                    _write_bytes_new_at(preparation_fd, _COMPACT_PLAN_NAME, plan_raw)
                    if _read_compact_plan_at(preparation_fd) != plan_raw:
                        raise TransactionPrimitiveError("Compact preparation plan readback differs.")
                    _transaction_checkpoint("prepare:plan")
                    _write_json_new_at(preparation_fd, "journal.json", initial_journal)
                    _transaction_checkpoint("prepare:journal")
                    for item in mutations:
                        path = str(item["path"])
                        _copy_regular_file_new_at(
                            source_map[path],
                            staging_fd,
                            staged_names[path],
                            expected_content=_plan_present_identity(item["after"]),
                            expected_metadata=item["after_metadata"],
                            creation_identity=plan["creation_identity"],
                        )
                        _transaction_checkpoint(f"stage:{path}")
                    os.fsync(staging_fd)
                    for path, staged_name in directory_staged.items():
                        os.mkdir(staged_name, 0o755, dir_fd=directories_fd)
                        os.chmod(
                            staged_name,
                            0o755,
                            dir_fd=directories_fd,
                            follow_symlinks=False,
                        )
                        descriptor = _open_safe_directory_at(
                            directories_fd,
                            staged_name,
                            label=f"{preparation_name}/directories/{staged_name}",
                            expected_mode=0o755,
                        )
                        try:
                            if os.listdir(descriptor):
                                raise TransactionPrimitiveError(
                                    f"Staged directory is not empty: {path}"
                                )
                        finally:
                            os.close(descriptor)
                        os.fsync(directories_fd)
                finally:
                    os.close(directories_fd)
                    os.close(staging_fd)
            rename_no_replace_at(
                runtime.transactions_fd,
                preparation_name,
                runtime.transactions_fd,
                transaction_id,
            )
            published = True
            os.fsync(runtime.transactions_fd)
            _transaction_checkpoint("prepare:published")

            for item in mutations:
                path = str(item["path"])
                after = _content_aware_after_identity(item)
                base_name = str(after["sha256"])
                try:
                    os.stat(
                        base_name,
                        dir_fd=runtime.bases_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    with _open_runtime_staging(runtime, transaction_id) as staging_fd:
                        _publish_bytes_new_at(
                            runtime.bases_fd,
                            base_name,
                            _read_regular_file_bytes_at(
                                staging_fd,
                                staged_names[path],
                            ),
                            pending_name=_base_pending_name(transaction_id, base_name),
                        )
                if not _content_addressed_base_matches_at(
                    runtime.bases_fd,
                    base_name,
                    base_name,
                ):
                    raise TransactionPrimitiveError(
                        f"Content-addressed base validation failed: {path}"
                    )
                _transaction_checkpoint(f"base:{path}:published")

            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "APPLYING",
                applied_actions,
                created_directories,
                validated_plan_proof=validated_plan_proof,
            )
            _transaction_checkpoint("state:applying")

            for item in mutations:
                path = str(item["path"])
                relative = safe_relative_path(path)

                def persist_created_directory() -> None:
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "APPLYING",
                        applied_actions,
                        created_directories,
                        pending_action=pending_action,
                        validated_plan_proof=validated_plan_proof,
                    )

                def publish_created_directory(
                    destination_parent_fd: int,
                    destination_name: str,
                    relative_text: str,
                ) -> tuple[int, dict[str, object]]:
                    nonlocal pending_action
                    staged_name = directory_staged.get(relative_text)
                    if staged_name is None:
                        raise TransactionPrimitiveError(
                            "Destination directory was not absent in the bound plan: "
                            + relative_text
                        )
                    with _open_runtime_directory_staging(
                        runtime,
                        transaction_id,
                    ) as directories_fd:
                        staged_fd = _open_safe_directory_at(
                            directories_fd,
                            staged_name,
                            label=f"{transaction_id}/directories/{staged_name}",
                            expected_mode=0o755,
                        )
                        try:
                            if os.listdir(staged_fd):
                                raise TransactionPrimitiveError(
                                    "Managed-content staged directory changed: "
                                    + relative_text
                                )
                            staged_identity = observe_created_directory_metadata_fd(
                                staged_fd
                            )
                            pending_action = {
                                "direction": "forward",
                                "path": relative_text,
                                "kind": "directory",
                                "staged_name": staged_name,
                                "installed_identity": staged_identity,
                                "backup_identity": None,
                            }
                            _persist_content_checkpoint(
                                runtime,
                                transaction_id,
                                plan,
                                "APPLYING",
                                applied_actions,
                                created_directories,
                                pending_action=pending_action,
                                validated_plan_proof=validated_plan_proof,
                            )
                            _transaction_checkpoint(
                                f"directory:{relative_text}:intent"
                            )
                            rename_no_replace_at(
                                directories_fd,
                                staged_name,
                                destination_parent_fd,
                                destination_name,
                            )
                            os.fsync(destination_parent_fd)
                            os.fsync(directories_fd)
                            _transaction_checkpoint(
                                f"directory:{relative_text}:mutation"
                            )
                        finally:
                            os.close(staged_fd)
                    child = os.open(
                        destination_name,
                        _directory_open_flags(),
                        dir_fd=destination_parent_fd,
                    )
                    try:
                        if (
                            not created_metadata_identity_matches(
                                observe_created_directory_metadata_fd(child),
                                staged_identity,
                                expected_type="directory",
                            )
                        ):
                            raise TransactionPrimitiveError(
                                "Published directory metadata changed: "
                                + relative_text
                            )
                    except BaseException:
                        os.close(child)
                        raise
                    pending_action = None
                    _transaction_checkpoint(f"directory:{relative_text}:validated")
                    return child, staged_identity

                root_fd = _open_project_root_handle(root)
                parent_fd: int | None = None
                transaction_fd: int | None = None
                staging_fd: int | None = None
                try:
                    parent_fd = _open_destination_parent_handle(
                        root_fd,
                        relative,
                        item,
                        created_directories,
                        publish_directory=publish_created_directory,
                        on_created=persist_created_directory,
                    )
                    if not _directory_handle_matches_topology(
                        root,
                        root_fd,
                        relative,
                        parent_fd,
                    ):
                        raise TransactionPrimitiveError(
                            f"Managed-content destination topology changed: {path}"
                        )
                    transaction_fd = _open_safe_directory_at(
                        runtime.transactions_fd,
                        transaction_id,
                        label=f"managed-content/transactions/{transaction_id}",
                    )
                    staging_fd = _open_safe_directory_at(
                        transaction_fd,
                        "staging",
                        label=f"managed-content/transactions/{transaction_id}/staging",
                    )
                    staged_name = staged_names[path]
                    installed_content, installed_identity = _leaf_observation_at(
                        staging_fd,
                        staged_name,
                    )
                    if installed_content != _plan_present_identity(item["after"]):
                        raise TransactionPrimitiveError(
                            f"Managed-content staged content changed: {path}"
                        )
                    kind = str(item["mutation"]["kind"])
                    _require_same_filesystem_at(
                        parent_fd,
                        staging_fd,
                        path=path,
                    )
                    if kind == "create":
                        if not _entry_absent_at(parent_fd, relative.name):
                            raise TransactionPrimitiveError(
                                f"Managed-content destination is no longer absent: {path}"
                            )
                        backup_identity = None
                    else:
                        before_content, backup_identity = _leaf_observation_at(
                            parent_fd,
                            relative.name,
                        )
                        if (
                            before_content != _plan_present_identity(item["before"])
                            or not created_metadata_identity_matches(
                                backup_identity,
                                item["before_metadata"],
                                expected_type="regular_file",
                            )
                        ):
                            raise TransactionPrimitiveError(
                                f"Managed-content replacement precondition changed: {path}"
                            )
                    action = {
                        "path": path,
                        "kind": kind,
                        "staged_name": staged_name,
                        "installed_identity": installed_identity,
                        "backup_identity": backup_identity,
                    }
                    pending_action = {"direction": "forward", **copy.deepcopy(action)}
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "APPLYING",
                        applied_actions,
                        created_directories,
                        pending_action=pending_action,
                        validated_plan_proof=validated_plan_proof,
                    )
                    _transaction_checkpoint(f"action:{path}:intent")
                    if kind == "create":
                        rename_no_replace_at(
                            staging_fd,
                            staged_name,
                            parent_fd,
                            relative.name,
                        )
                    else:
                        rename_exchange_at(
                            staging_fd,
                            staged_name,
                            parent_fd,
                            relative.name,
                        )
                    os.fsync(parent_fd)
                    os.fsync(staging_fd)
                    _transaction_checkpoint(f"action:{path}:mutation")
                    if not _leaf_matches_exact_at(
                        parent_fd,
                        relative.name,
                        installed_content,
                        installed_identity,
                    ):
                        raise TransactionPrimitiveError(
                            f"Managed-content published leaf validation failed: {path}"
                        )
                    if kind == "replace" and not _leaf_matches_exact_at(
                        staging_fd,
                        staged_name,
                        _plan_present_identity(item["before"]),
                        backup_identity,
                    ):
                        raise TransactionPrimitiveError(
                            f"Managed-content replacement backup validation failed: {path}"
                        )
                    _transaction_checkpoint(f"action:{path}:validated")
                    applied_actions.append(action)
                    pending_action = None
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "APPLYING",
                        applied_actions,
                        created_directories,
                        validated_plan_proof=validated_plan_proof,
                    )
                    _transaction_checkpoint(f"action:{path}:complete")
                finally:
                    if staging_fd is not None:
                        os.close(staging_fd)
                    if transaction_fd is not None:
                        os.close(transaction_fd)
                    if parent_fd is not None:
                        os.close(parent_fd)
                    os.close(root_fd)

            _persist_content_checkpoint(
                runtime,
                transaction_id,
                plan,
                "VALIDATING",
                applied_actions,
                created_directories,
                validated_plan_proof=validated_plan_proof,
            )
            _transaction_checkpoint("state:validating")
            for action, item in zip(applied_actions, mutations, strict=True):
                if not _managed_file_matches_at(
                    runtime.root_fd,
                    str(item["path"]),
                    _plan_present_identity(item["after"]),
                    action["installed_identity"],
                    item["ancestor_identities"],
                ):
                    raise TransactionPrimitiveError(
                        f"Post-apply content validation failed: {item['path']}"
                    )

            receipt_actions = [
                {
                    "path": str(item["path"]),
                    "kind": str(item["mutation"]["kind"]),
                    "before": item["before"],
                    "after": item["after"],
                    "before_metadata": item["before_metadata"],
                    "after_metadata": item["after_metadata"],
                    "installed_metadata": action["installed_identity"],
                    "backup_metadata": action["backup_identity"],
                    "base_blob": {
                        "path": _content_aware_after_identity(item)["sha256"],
                        "sha256": _content_aware_after_identity(item)["sha256"],
                    },
                    "publication_adapter": _publication_adapter(
                        str(item["mutation"]["kind"]), action["installed_identity"]
                    ),
                }
                for item, action in zip(mutations, applied_actions, strict=True)
            ]
            receipt = _with_sha256_integrity(
                {
                    "schema": "naos.upgrade.managed_content_receipt.v2",
                    "minimum_recovery_naos_version": CONTENT_AWARE_MINIMUM_RECOVERY_VERSION,
                    "project_id": project_id,
                    "scope_integrity_sha3_512": scope_integrity_sha3_512,
                    "source_policy_sha256": scope_source_policy_sha256,
                    "transaction_id": transaction_id,
                    "plan_sha256": plan["plan_sha256"],
                    "status": "COMMITTED",
                    "actions": receipt_actions,
                    "replacement_performed": any(
                        item["mutation"]["kind"] == "replace" for item in mutations
                    ),
                }
            )
            receipt_sha256 = _validate_receipt_v2(
                receipt,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
                transaction_id=transaction_id,
                plan=plan,
            )
            receipt_name = f"{transaction_id}.json"
            _publish_json_new_at(
                runtime.receipts_fd,
                receipt_name,
                receipt,
                pending_name=_receipt_pending_name(transaction_id),
            )
            _transaction_checkpoint("commit:receipt")
            manifest = _manifest_v2_with_actions(
                existing_manifest,
                project_root=root,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
                transaction_id=transaction_id,
                plan=plan,
                receipt_sha256=receipt_sha256,
                receipt_actions=receipt_actions,
            )
            _replace_json_atomically_at(
                runtime.state_fd,
                "manifest.json",
                manifest,
                pending_name=_manifest_pending_name(transaction_id),
                expected_current=existing_manifest,
            )
            _transaction_checkpoint("commit:manifest")
            try:
                _persist_content_checkpoint(
                    runtime,
                    transaction_id,
                    plan,
                    "COMMITTED",
                    applied_actions,
                    created_directories,
                    validated_plan_proof=validated_plan_proof,
                )
            except Exception as exc:
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    str(receipts_root / receipt_name),
                    "Content and manifest committed; journal finalization requires "
                    f"recovery: {exc}",
                )
            _transaction_checkpoint("commit:journal")
            try:
                _remove_runtime_staging_v2(
                    runtime,
                    transaction_id,
                    plan,
                    applied_actions,
                    committed=True,
                )
            except Exception as exc:
                detail = (
                    "Committed evidence is durable, but exact private-backup cleanup "
                    f"requires recovery: {exc}"
                )
                _persist_content_checkpoint(
                    runtime,
                    transaction_id,
                    plan,
                    "RECOVERY_REQUIRED",
                    applied_actions,
                    created_directories,
                    detail=detail,
                    validated_plan_proof=validated_plan_proof,
                )
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    str(receipts_root / receipt_name),
                    detail,
                )
            _transaction_checkpoint("commit:cleanup")
            return CreateOnlyTransactionOutcome(
                "committed",
                transaction_id,
                str(receipts_root / receipt_name),
            )
        except Exception as exc:
            if not published:
                try:
                    _remove_runtime_preparation(runtime, preparation_name)
                except Exception as cleanup_exc:
                    raise TransactionPrimitiveError(
                        f"Preparation failed and exact cleanup failed: {cleanup_exc}"
                    ) from exc
                raise
            try:
                visible_manifest, _version = _load_manifest_any_at(
                    runtime.state_fd,
                    project_root=root,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                )
            except Exception as manifest_exc:
                detail = (
                    "Manifest commit point cannot be determined; targets and private "
                    f"backups were preserved: {exc}; {manifest_exc}"
                )
                try:
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "RECOVERY_REQUIRED",
                        applied_actions,
                        created_directories,
                        pending_action=pending_action,
                        detail=detail,
                        require_attached=False,
                        validated_plan_proof=validated_plan_proof,
                    )
                except Exception:
                    pass
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    detail=detail,
                )
            manifest_records_transaction = bool(
                visible_manifest
                and any(
                    isinstance(item, dict)
                    and item.get("transaction_id") == transaction_id
                    for item in visible_manifest.get("transactions") or []
                )
            )
            if manifest_records_transaction:
                detail = (
                    "Manifest commit point crossed; exact target state and private "
                    f"backups were preserved for recovery: {exc}"
                )
                _persist_content_checkpoint(
                    runtime,
                    transaction_id,
                    plan,
                    "RECOVERY_REQUIRED",
                    applied_actions,
                    created_directories,
                    pending_action=pending_action,
                    detail=detail,
                    require_attached=False,
                    validated_plan_proof=validated_plan_proof,
                )
                return CreateOnlyTransactionOutcome(
                    "recovery_required",
                    transaction_id,
                    str(receipts_root / f"{transaction_id}.json"),
                    detail,
                )
            try:
                rollback_journal, _rollback_plan, _generation = _load_runtime_content_checkpoint(runtime, transaction_id)
                return _rollback_v2_transaction(
                    runtime,
                    transaction_id,
                    plan,
                    rollback_journal,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                    reason=f"Content-aware apply failed and was rolled back: {exc}",
                    validated_plan_proof=validated_plan_proof,
                )
            except Exception as rollback_exc:
                detail = (
                    "Content-aware apply failed and rollback could not complete: "
                    f"{exc}; {rollback_exc}"
                )
                try:
                    current_journal, _current_plan, _generation = _load_runtime_content_checkpoint(runtime, transaction_id)
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "ROLLBACK_INCOMPLETE",
                        copy.deepcopy(current_journal.get("applied_actions") or []),
                        copy.deepcopy(current_journal.get("created_directories") or []),
                        pending_action=copy.deepcopy(
                            current_journal.get("pending_action")
                        ),
                        detail=detail,
                        require_attached=False,
                        validated_plan_proof=validated_plan_proof,
                    )
                except Exception:
                    pass
                return CreateOnlyTransactionOutcome(
                    "rollback_incomplete",
                    transaction_id,
                    detail=detail,
                )


def _recover_create_only_transactions_v1(
    project_root: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> list[CreateOnlyTransactionOutcome]:
    """Resolve interrupted create-only journals without overwriting user changes."""

    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    outcomes: list[CreateOnlyTransactionOutcome] = []
    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        preparations = _unsealed_preparation_outcomes(runtime)
        if preparations:
            return preparations
        manifest_load_failure: str | None = None
        try:
            manifest, _manifest_version = _load_manifest_any_at(
                runtime.state_fd,
                project_root=root,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
            )
            if manifest is not None:
                _validate_manifest_evidence_any_at(
                    runtime, manifest, project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                )
        except Exception as exc:
            manifest = None
            manifest_load_failure = str(exc)
        if manifest is not None:
            present_transaction_names = {
                name
                for name in os.listdir(runtime.transactions_fd)
                if not name.startswith(".preparing-")
            }
            manifest_transaction_ids = {
                str(item.get("transaction_id"))
                for item in manifest.get("transactions") or []
                if isinstance(item, dict)
            }
            missing_journals = sorted(
                manifest_transaction_ids - present_transaction_names
            )
            if missing_journals:
                return [
                    CreateOnlyTransactionOutcome(
                        "recovery_required",
                        transaction_id,
                        detail=(
                            "Cumulative manifest transaction has no recoverable "
                            "journal directory; targets were preserved."
                        ),
                    )
                    for transaction_id in missing_journals
                ]
        for transaction_name in sorted(os.listdir(runtime.transactions_fd)):
            transaction_id = transaction_name.removeprefix(".preparing-")
            with _open_runtime_transaction(runtime, transaction_name) as transaction_fd:
                journal, historical_plan, historical_version = _load_content_checkpoint_at(
                    transaction_fd, project_root=root, label=transaction_name)
            policy_digest = (
                historical_plan.get("source_policy_sha256") if historical_version == "v1"
                else (historical_plan.get("source_policy", {}).get("provenance") or {}).get("binding_sha256")
            )
            if journal.get("transaction_id") != transaction_id or policy_digest != scope_source_policy_sha256:
                raise TransactionPrimitiveError("Managed-content recovery transaction binding is invalid.")
            recorded = next(
                (item for item in (manifest or {}).get("transactions") or []
                 if item["transaction_id"] == transaction_id), None,
            )
            if recorded is not None and recorded["plan"] != historical_plan:
                raise TransactionPrimitiveError(
                    "Managed-content manifest/journal plan binding differs: " + transaction_id
                )
            if journal.get("state") == "ROLLED_BACK":
                try:
                    os.stat(f"{transaction_id}.json", dir_fd=runtime.receipts_fd, follow_symlinks=False)
                except FileNotFoundError:
                    receipt_exists = False
                else:
                    receipt_exists = True
                if recorded is not None or receipt_exists:
                    return [CreateOnlyTransactionOutcome(
                        "recovery_required", transaction_id,
                        detail="Rolled-back journal conflicts with committed manifest or receipt evidence; targets were preserved.",
                    )]
        for transaction_name in sorted(os.listdir(runtime.transactions_fd)):
            if transaction_name.startswith(".preparing-"):
                transaction_id = transaction_name.removeprefix(".preparing-")
                if TRANSACTION_ID_RE.fullmatch(transaction_id) is None:
                    raise TransactionPrimitiveError(
                        f"Unknown managed-content preparation entry: {transaction_name}"
                    )
                with _open_runtime_transaction(runtime, transaction_name) as preparation_fd:
                    preparation, _preparation_plan, preparation_version = _load_content_checkpoint_at(
                        preparation_fd, project_root=root, label=transaction_name)
                if preparation_version == "v2":
                    continue
                try:
                    _remove_runtime_preparation(runtime, transaction_name)
                except TransactionPrimitiveError as exc:
                    return [*outcomes, CreateOnlyTransactionOutcome(
                        "recovery_required", transaction_id, detail=str(exc)
                    )]
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "rolled_back",
                        transaction_id,
                        detail="Incomplete transaction preparation removed before publication.",
                    )
                )
                continue
            journal, plan, version = _load_runtime_content_checkpoint(runtime, transaction_name)
            if version == "v2":
                continue
            state = str(journal.get("state") or "")
            transaction_id = str(journal.get("transaction_id") or "")
            if transaction_id != transaction_name:
                raise TransactionPrimitiveError(
                    "Managed-content journal transaction-directory binding is invalid."
                )
            if plan.get("source_policy_sha256") != scope_source_policy_sha256:
                raise TransactionPrimitiveError(
                    "Managed-content recovery source-policy binding is invalid."
                )
            if state != "COMMITTED":
                try:
                    _remove_runtime_evidence_pending(runtime, transaction_id, plan)
                except Exception as pending_exc:
                    final = dict(journal)
                    final.pop("integrity", None)
                    final["state"] = "RECOVERY_REQUIRED"
                    final["detail"] = (
                        "Transaction-specific pending evidence could not be removed: "
                        f"{pending_exc}"
                    )
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _with_sha256_integrity(final),
                    )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_id,
                            detail=final["detail"],
                        )
                    )
                    continue
            if manifest_load_failure is not None:
                final = dict(journal)
                final.pop("integrity", None)
                final["state"] = "RECOVERY_REQUIRED"
                final["detail"] = (
                    "Cumulative managed-content manifest is unreadable or invalid; "
                    f"targets were preserved: {manifest_load_failure}"
                )
                if state != "COMMITTED":
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _with_sha256_integrity(final),
                    )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "recovery_required",
                        transaction_id,
                        detail=final["detail"],
                    )
                )
                continue
            receipt_name = f"{transaction_id}.json"
            receipt_path = receipts_root / receipt_name
            manifest_transaction = (
                next(
                    (
                        item
                        for item in manifest.get("transactions") or []
                        if isinstance(item, dict)
                        and item.get("transaction_id") == transaction_id
                    ),
                    None,
                )
                if manifest
                else None
            )
            if state == "ROLLED_BACK":
                try:
                    receipt_exists = (
                        os.stat(
                            receipt_name,
                            dir_fd=runtime.receipts_fd,
                            follow_symlinks=False,
                        )
                        is not None
                    )
                except FileNotFoundError:
                    receipt_exists = False
                if manifest_transaction is None and not receipt_exists:
                    continue
                final = dict(journal)
                final.pop("integrity", None)
                final["state"] = "RECOVERY_REQUIRED"
                final["detail"] = (
                    "Rolled-back journal conflicts with committed manifest or receipt evidence."
                )
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    _with_sha256_integrity(final),
                )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "recovery_required",
                        transaction_id,
                        detail=final["detail"],
                    )
                )
                continue
            if state == "COMMITTED" and manifest_transaction is None:
                final = dict(journal)
                final.pop("integrity", None)
                final["state"] = "RECOVERY_REQUIRED"
                final["detail"] = (
                    "Committed journal is missing its cumulative manifest transaction; "
                    "targets were preserved."
                )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "recovery_required",
                        transaction_id,
                        detail=final["detail"],
                    )
                )
                continue
            pending_action = journal.get("pending_action")
            if pending_action is not None and state != "COMMITTED":
                if manifest_transaction is None and state != "ROLLING_BACK":
                    transitioning = dict(journal)
                    transitioning.pop("integrity", None)
                    transitioning["state"] = "ROLLING_BACK"
                    transitioning["detail"] = (
                        "Recovery entered rollback with a durable pending action."
                    )
                    journal = _with_sha256_integrity(transitioning)
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        journal,
                        require_attached=False,
                    )
                    state = "ROLLING_BACK"
                runtime.assert_attached()
                reconciliation = _reconcile_pending_action_at(
                    root,
                    runtime,
                    transaction_id,
                    plan,
                    pending_action,
                )
                if not reconciliation.reconciled:
                    exceptional_state = (
                        "RECOVERY_REQUIRED"
                        if reconciliation.status == "content_conflict"
                        else "ROLLBACK_INCOMPLETE"
                    )
                    outcome_status = (
                        "recovery_required"
                        if exceptional_state == "RECOVERY_REQUIRED"
                        else "rollback_incomplete"
                    )
                    final = dict(journal)
                    final.pop("integrity", None)
                    final["state"] = exceptional_state
                    final["detail"] = reconciliation.detail
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _with_sha256_integrity(final),
                    )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            outcome_status,
                            transaction_id,
                            detail=reconciliation.detail,
                        )
                    )
                    continue
                journal = dict(journal)
                journal.pop("integrity", None)
                pending_kind = str(pending_action["kind"])
                pending_path = str(pending_action["path"])
                if pending_kind == "file_rollback":
                    journal["applied_paths"] = [
                        path
                        for path in journal.get("applied_paths") or []
                        if path != pending_path
                    ]
                    journal["applied_identities"] = {
                        path: identity
                        for path, identity in (
                            journal.get("applied_identities") or {}
                        ).items()
                        if path != pending_path
                    }
                elif pending_kind == "directory_rollback":
                    journal["created_directories"] = [
                        record
                        for record in journal.get("created_directories") or []
                        if record.get("path") != pending_path
                    ]
                if manifest_transaction is None:
                    journal["state"] = "ROLLING_BACK"
                journal["pending_action"] = None
                journal["detail"] = "Exact pending action was reversed during recovery."
                journal = _with_sha256_integrity(journal)
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    journal,
                    require_attached=False,
                )
                try:
                    runtime.assert_attached()
                except TransactionPrimitiveError as exc:
                    final = dict(journal)
                    final.pop("integrity", None)
                    final["state"] = "ROLLBACK_INCOMPLETE"
                    final["detail"] = str(exc)
                    _replace_runtime_journal(
                        runtime,
                        transaction_id,
                        _with_sha256_integrity(final),
                        require_attached=False,
                    )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "rollback_incomplete",
                            transaction_id,
                            detail=final["detail"],
                        )
                    )
                    return outcomes
            paths = plan["paths"]
            applied_paths = set(journal.get("applied_paths") or [])
            foreign_preserved: list[str] = []
            present_or_unsafe: list[str] = []
            for item in paths:
                relative_text = str(item["path"])
                destination = root / safe_relative_path(str(item["path"]))
                try:
                    os.lstat(destination)
                except FileNotFoundError:
                    continue
                if relative_text not in applied_paths:
                    foreign_preserved.append(relative_text)
            if manifest_transaction is not None:
                commit_failures = _committed_transaction_failures_at(
                    root,
                    manifest,
                    transaction_id=transaction_id,
                    plan=plan,
                    journal=journal,
                    runtime=runtime,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                )
                if commit_failures:
                    final = dict(journal)
                    final.pop("integrity", None)
                    final["state"] = "RECOVERY_REQUIRED"
                    final["detail"] = (
                        "Manifest records this transaction, but committed evidence "
                        "is incomplete or conflicting: " + "; ".join(commit_failures)
                    )
                    if state != "COMMITTED":
                        _replace_runtime_journal(
                            runtime,
                            transaction_id,
                            _with_sha256_integrity(final),
                        )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_id,
                            detail=final["detail"],
                        )
                    )
                    continue
                try:
                    _remove_runtime_staging(runtime, transaction_id, plan)
                except (OSError, TransactionPrimitiveError) as cleanup_exc:
                    final = dict(journal)
                    final.pop("integrity", None)
                    final["state"] = "RECOVERY_REQUIRED"
                    final["detail"] = (
                        "Committed evidence is valid, but exact staging cleanup "
                        f"failed: {cleanup_exc}"
                    )
                    if state != "COMMITTED":
                        _replace_runtime_journal(
                            runtime,
                            transaction_id,
                            _with_sha256_integrity(final),
                        )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_id,
                            str(receipt_path),
                            final["detail"],
                        )
                    )
                    continue
                if state == "COMMITTED":
                    continue
                final = dict(journal)
                final.pop("integrity", None)
                final["state"] = "COMMITTED"
                final["detail"] = None
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    _with_sha256_integrity(final),
                )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "committed", transaction_id, str(receipt_path)
                    )
                )
                continue
            provisional_receipt_present = False
            try:
                os.stat(
                    receipt_name,
                    dir_fd=runtime.receipts_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                try:
                    _load_receipt_at(
                        runtime.receipts_fd,
                        receipt_name,
                        project_id=project_id,
                        scope_integrity_sha3_512=scope_integrity_sha3_512,
                        source_policy_sha256=scope_source_policy_sha256,
                        transaction_id=transaction_id,
                        plan=plan,
                    )
                except Exception as exc:
                    present_or_unsafe.append(
                        f"receipt:{transaction_id} ({exc})"
                    )
                else:
                    provisional_receipt_present = True
            rollback_failures: list[str] = [
                f"invalid rollback evidence preserved: {item}"
                for item in present_or_unsafe
            ]
            rollback_conflicts: list[str] = []
            remaining_applied = list(journal.get("applied_paths") or [])
            remaining_identities = dict(journal.get("applied_identities") or {})
            created_directories = list(journal.get("created_directories") or [])
            recovery_pending: dict[str, object] | None = None

            def persist_recovery_state(detail: str) -> None:
                nonlocal journal
                updated = dict(journal)
                updated.pop("integrity", None)
                updated["applied_paths"] = remaining_applied
                updated["applied_identities"] = remaining_identities
                updated["created_directories"] = created_directories
                updated["pending_action"] = recovery_pending
                updated["state"] = "ROLLING_BACK"
                updated["detail"] = detail
                journal = _with_sha256_integrity(updated)
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    journal,
                    require_attached=False,
                )

            persist_recovery_state(
                "Recovery entered the rollback phase for an uncommitted transaction."
            )

            for relative_text in reversed(list(remaining_applied)):
                runtime.assert_attached()
                identity = remaining_identities.get(relative_text)
                if identity is None:
                    rollback_failures.append(
                        f"applied identity is missing: {relative_text}"
                    )
                    continue
                recovery_pending = {
                    "kind": "file_rollback",
                    "path": relative_text,
                    "identity": identity,
                }
                persist_recovery_state(
                    f"Reversing exact applied leaf: {relative_text}"
                )
                reconciliation = _reconcile_pending_action_at(
                    root,
                    runtime,
                    transaction_id,
                    plan,
                    recovery_pending,
                )
                if not reconciliation.reconciled:
                    detail = reconciliation.detail or (
                        f"exact applied leaf could not be reversed: {relative_text}"
                    )
                    if reconciliation.status == "content_conflict":
                        rollback_conflicts.append(detail)
                    else:
                        rollback_failures.append(detail)
                    break
                remaining_applied.remove(relative_text)
                remaining_identities.pop(relative_text, None)
                recovery_pending = None
                persist_recovery_state(
                    f"Exact applied leaf reversed: {relative_text}"
                )
                try:
                    runtime.assert_attached()
                except TransactionPrimitiveError as exc:
                    rollback_failures.append(str(exc))
                    break
            if provisional_receipt_present:
                try:
                    os.unlink(receipt_name, dir_fd=runtime.receipts_fd)
                    os.fsync(runtime.receipts_fd)
                except OSError as exc:
                    rollback_failures.append(
                        f"provisional receipt could not be removed: {exc}"
                    )
            if recovery_pending is None:
                for directory_record in sorted(
                    list(created_directories),
                    key=lambda item: len(Path(str(item["path"])).parts),
                    reverse=True,
                ):
                    relative_text = str(directory_record["path"])
                    recovery_pending = {
                        "kind": "directory_rollback",
                        "path": relative_text,
                        "identity": directory_record["identity"],
                    }
                    persist_recovery_state(
                        f"Reversing exact created directory: {relative_text}"
                    )
                    reconciliation = _reconcile_pending_action_at(
                        root,
                        runtime,
                        transaction_id,
                        plan,
                        recovery_pending,
                    )
                    if not reconciliation.reconciled:
                        detail = reconciliation.detail or (
                            f"created directory could not be reversed: {relative_text}"
                        )
                        if reconciliation.status == "content_conflict":
                            rollback_conflicts.append(detail)
                        else:
                            rollback_failures.append(detail)
                        break
                    created_directories = [
                        item for item in created_directories if item != directory_record
                    ]
                    recovery_pending = None
                    persist_recovery_state(
                        f"Exact created directory reversed: {relative_text}"
                    )
                    try:
                        runtime.assert_attached()
                    except TransactionPrimitiveError as exc:
                        rollback_failures.append(str(exc))
                        break
            if recovery_pending is None:
                try:
                    _remove_runtime_staging(runtime, transaction_id, plan)
                except (OSError, TransactionPrimitiveError) as staging_exc:
                    rollback_failures.append(
                        f"exact transaction staging could not be removed: {staging_exc}"
                    )
            if rollback_failures or rollback_conflicts:
                if rollback_failures:
                    exceptional_state = "ROLLBACK_INCOMPLETE"
                    outcome_status = "rollback_incomplete"
                else:
                    exceptional_state = "RECOVERY_REQUIRED"
                    outcome_status = "recovery_required"
                details = [
                    *(f"conflicting content preserved: {item}" for item in rollback_conflicts),
                    *rollback_failures,
                ]
                final = dict(journal)
                final.pop("integrity", None)
                final["state"] = exceptional_state
                final["detail"] = "; ".join(details)
                _replace_runtime_journal(
                    runtime,
                    transaction_id,
                    _with_sha256_integrity(final),
                    require_attached=False,
                )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        outcome_status,
                        transaction_id,
                        detail=final["detail"],
                    )
                )
                continue
            final = dict(journal)
            final.pop("integrity", None)
            final["state"] = "ROLLED_BACK"
            final["detail"] = "Interrupted create-only transaction rolled back."
            if foreign_preserved:
                final["detail"] += (
                    " Foreign post-plan collisions were preserved: "
                    + ", ".join(foreign_preserved)
                )
            _replace_runtime_journal(
                runtime,
                transaction_id,
                _with_sha256_integrity(final),
                require_attached=False,
            )
            outcomes.append(
                CreateOnlyTransactionOutcome("rolled_back", transaction_id, detail=final["detail"])
            )
    return outcomes


def _recover_v2_transactions(
    project_root: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> list[CreateOnlyTransactionOutcome]:
    root = project_root.resolve(strict=True)
    _require_canonical_runtime_paths(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
    outcomes: list[CreateOnlyTransactionOutcome] = []
    with _ManagedRuntimeHandles.open(
        root,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    ) as runtime:
        _require_live_scope_binding_at(
            runtime,
            project_id=project_id,
            scope_integrity_sha3_512=scope_integrity_sha3_512,
            source_policy_sha256=scope_source_policy_sha256,
        )
        preparations = _unsealed_preparation_outcomes(runtime)
        if preparations:
            return preparations
        manifest_failure: str | None = None
        try:
            manifest, _manifest_version = _load_manifest_any_at(
                runtime.state_fd,
                project_root=root,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
            )
            if manifest is not None:
                _validate_manifest_evidence_any_at(
                    runtime,
                    manifest,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                )
        except Exception as exc:
            manifest = None
            manifest_failure = str(exc)

        # Validate the complete inventory under the scope lock before any mutation.
        # An uncommitted successor may temporarily displace a committed live leaf;
        # restore it before asking historical receipts to validate current targets.
        transaction_names = sorted(os.listdir(runtime.transactions_fd))
        manifested_ids = {
            item["transaction_id"]
            for item in (manifest or {}).get("transactions") or []
        }
        missing_journals = manifested_ids - set(transaction_names)
        if missing_journals:
            return [CreateOnlyTransactionOutcome(
                "recovery_required", transaction_id,
                detail="Cumulative manifest transaction has no recoverable journal directory; targets were preserved.",
            ) for transaction_id in sorted(missing_journals)]
        preparations: list[str] = []
        unfinished: list[str] = []
        for transaction_name in transaction_names:
            preparing = transaction_name.startswith(".preparing-")
            transaction_id = (
                transaction_name.removeprefix(".preparing-")
                if preparing else transaction_name
            )
            if preparing:
                if TRANSACTION_ID_RE.fullmatch(transaction_id) is None:
                    raise TransactionPrimitiveError(
                        f"Unknown managed-content preparation entry: {transaction_name}"
                    )
                with _open_runtime_transaction(runtime, transaction_name) as preparation_fd:
                    journal, _plan, version = _load_content_checkpoint_at(
                        preparation_fd, project_root=root, label=transaction_name)
                preparations.append(transaction_name)
            else:
                journal, _plan, version = _load_runtime_content_checkpoint(runtime, transaction_name)
            if journal.get("transaction_id") != transaction_id:
                raise TransactionPrimitiveError(
                    "Managed-content journal transaction-directory binding is invalid."
                )
            policy_digest = (
                _plan.get("source_policy_sha256") if version == "v1"
                else (_plan.get("source_policy", {}).get("provenance") or {}).get("binding_sha256")
            )
            if policy_digest != scope_source_policy_sha256:
                raise TransactionPrimitiveError(
                    "Managed-content recovery source-policy binding is invalid."
                )
            recorded = next(
                (item for item in (manifest or {}).get("transactions") or []
                 if item["transaction_id"] == transaction_id), None,
            )
            if recorded is not None and recorded["plan"] != _plan:
                raise TransactionPrimitiveError(
                    "Managed-content manifest/journal plan binding differs: " + transaction_id
                )
            if journal.get("state") == "ROLLED_BACK":
                try:
                    os.stat(f"{transaction_id}.json", dir_fd=runtime.receipts_fd, follow_symlinks=False)
                except FileNotFoundError:
                    receipt_exists = False
                else:
                    receipt_exists = True
                if recorded is not None or receipt_exists:
                    return [CreateOnlyTransactionOutcome(
                        "recovery_required", transaction_id,
                        detail="Rolled-back journal conflicts with committed manifest or receipt evidence; targets were preserved.",
                    )]
            if version == "v1" and (
                preparing or journal.get("state") not in TERMINAL_CONTENT_STATES
            ):
                raise TransactionPrimitiveError(
                    "An unfinished v1 transaction must be recovered before v2: "
                    + transaction_name
                )
            if (
                not preparing and version == "v2"
                and journal.get("state") not in TERMINAL_CONTENT_STATES
                and transaction_id not in manifested_ids
            ):
                unfinished.append(transaction_name)
        if not preparations and manifest_failure is None and len(unfinished) > 1:
            return [
                CreateOnlyTransactionOutcome(
                    "recovery_required", name,
                    detail=("Multiple uncommitted v2 transactions are ambiguous; "
                            "all state was preserved."),
                )
                for name in unfinished
            ]
        priority = preparations + (unfinished if manifest_failure is None else [])
        ordered_names = priority + [name for name in transaction_names if name not in priority]
        for transaction_name in ordered_names:
            if transaction_name.startswith(".preparing-"):
                transaction_id = transaction_name.removeprefix(".preparing-")
                if TRANSACTION_ID_RE.fullmatch(transaction_id) is None:
                    raise TransactionPrimitiveError(
                        f"Unknown managed-content preparation entry: {transaction_name}"
                    )
                with _open_runtime_transaction(runtime, transaction_name) as preparation_fd:
                    journal, _plan, version = _load_content_checkpoint_at(
                        preparation_fd, project_root=root, label=transaction_name)
                if version != "v2":
                    raise TransactionPrimitiveError(
                        "V1 transaction preparation must be recovered before v2."
                    )
                try:
                    _remove_runtime_preparation(runtime, transaction_name)
                except TransactionPrimitiveError as exc:
                    return [*outcomes, CreateOnlyTransactionOutcome(
                        "recovery_required", transaction_id, detail=str(exc)
                    )]
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "rolled_back",
                        transaction_id,
                        detail="Incomplete v2 transaction preparation removed before publication.",
                    )
                )
                continue

            journal, plan, version = _load_runtime_content_checkpoint(runtime, transaction_name)
            if journal.get("transaction_id") != transaction_name:
                raise TransactionPrimitiveError(
                    "Managed-content journal transaction-directory binding is invalid."
                )
            if version == "v1":
                if journal.get("state") not in TERMINAL_CONTENT_STATES:
                    raise TransactionPrimitiveError(
                        "An unfinished v1 transaction must be recovered before v2: "
                        + transaction_name
                    )
                if manifest_failure is not None:
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_name,
                            detail=(
                                "Cumulative managed-content evidence is invalid; "
                                "targets were preserved: " + manifest_failure
                            ),
                        )
                    )
                elif journal.get("state") == "COMMITTED":
                    failures = _committed_transaction_failures_at(
                        root, manifest, transaction_id=transaction_name, plan=plan,
                        journal=journal, runtime=runtime, project_id=project_id,
                        scope_integrity_sha3_512=scope_integrity_sha3_512,
                        source_policy_sha256=scope_source_policy_sha256,
                    )
                    if failures:
                        outcomes.append(CreateOnlyTransactionOutcome("recovery_required", transaction_name, detail="; ".join(failures)))
                continue
            transaction_id = transaction_name
            compact_proof = (_ValidatedPlanProof(root=str(root), canonical_plan=canonical_bytes(plan),
                              typed_plan=copy.deepcopy(plan))
                             if journal.get("schema") == _COMPACT_JOURNAL_SCHEMA else None)
            state = str(journal.get("state") or "")
            manifest_transaction = (
                next(
                    (
                        item
                        for item in (manifest or {}).get("transactions") or []
                        if isinstance(item, dict)
                        and item.get("transaction_id") == transaction_id
                    ),
                    None,
                )
                if manifest is not None
                else None
            )
            if manifest_failure is not None:
                detail = (
                    "Cumulative managed-content manifest is unreadable or invalid; "
                    f"targets and private backups were preserved: {manifest_failure}"
                )
                if state != "COMMITTED":
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "RECOVERY_REQUIRED",
                        copy.deepcopy(journal.get("applied_actions") or []),
                        copy.deepcopy(journal.get("created_directories") or []),
                        pending_action=copy.deepcopy(journal.get("pending_action")),
                        detail=detail,
                        require_attached=False,
                        validated_plan_proof=compact_proof,
                    )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "recovery_required",
                        transaction_id,
                        detail=detail,
                    )
                )
                continue
            if state == "ROLLED_BACK":
                if manifest_transaction is not None:
                    detail = (
                        "Rolled-back v2 journal conflicts with committed manifest evidence."
                    )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_id,
                            detail=detail,
                        )
                    )
                continue

            if manifest_transaction is not None:
                topology_failures = _committed_content_topology_failures_at(
                    runtime.root_fd,
                    journal,
                    plan,
                )
                if topology_failures:
                    detail = (
                        "Committed managed-content topology differs; all state "
                        "was preserved: " + "; ".join(topology_failures)
                    )
                    if state != "COMMITTED":
                        _persist_content_checkpoint(
                            runtime,
                            transaction_id,
                            plan,
                            "RECOVERY_REQUIRED",
                            copy.deepcopy(journal.get("applied_actions") or []),
                            copy.deepcopy(journal.get("created_directories") or []),
                            pending_action=copy.deepcopy(journal.get("pending_action")),
                            detail=detail,
                            require_attached=False,
                            validated_plan_proof=compact_proof,
                        )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_id,
                            detail=detail,
                        )
                    )
                    continue
                prior = _already_applied_v2_at(
                    runtime,
                    manifest,
                    plan,
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                    allow_superseded=True,
                )
                if prior != transaction_id:
                    detail = (
                        "Manifest records the v2 transaction, but exact committed "
                        "target/receipt evidence differs; all state was preserved."
                    )
                    if state != "COMMITTED":
                        _persist_content_checkpoint(
                            runtime,
                            transaction_id,
                            plan,
                            "RECOVERY_REQUIRED",
                            copy.deepcopy(journal.get("applied_actions") or []),
                            copy.deepcopy(journal.get("created_directories") or []),
                            pending_action=copy.deepcopy(journal.get("pending_action")),
                            detail=detail,
                            require_attached=False,
                            validated_plan_proof=compact_proof,
                        )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "recovery_required",
                            transaction_id,
                            detail=detail,
                        )
                    )
                    continue
                receipt, _digest, _receipt_version = _load_receipt_any_at(
                    runtime.receipts_fd,
                    f"{transaction_id}.json",
                    project_id=project_id,
                    scope_integrity_sha3_512=scope_integrity_sha3_512,
                    source_policy_sha256=scope_source_policy_sha256,
                    transaction_id=transaction_id,
                    plan=plan,
                )
                with _open_runtime_transaction(runtime, transaction_id) as transaction_fd:
                    durable_names = {"journal.json"}
                    if journal.get("schema") == _COMPACT_JOURNAL_SCHEMA:
                        if _read_compact_plan_at(transaction_fd) != compact_proof.canonical_plan + b"\n":
                            raise TransactionPrimitiveError("Compact terminal plan changed before cleanup.")
                        durable_names.add(_COMPACT_PLAN_NAME)
                    residue = set(os.listdir(transaction_fd)) - durable_names
                if residue:
                    try:
                        _remove_runtime_staging_v2(
                            runtime,
                            transaction_id,
                            plan,
                            [
                                {
                                    "path": action["path"],
                                    "kind": action["kind"],
                                    "staged_name": f"{index:06d}",
                                    "installed_identity": action["installed_metadata"],
                                    "backup_identity": action["backup_metadata"],
                                }
                                for index, action in enumerate(receipt["actions"])
                            ],
                            committed=True,
                        )
                    except Exception as exc:
                        detail = (
                            "Committed transaction private-backup cleanup remains "
                            f"incomplete: {exc}"
                        )
                        if state != "COMMITTED":
                            _persist_content_checkpoint(
                                runtime,
                                transaction_id,
                                plan,
                                "RECOVERY_REQUIRED",
                                copy.deepcopy(journal.get("applied_actions") or []),
                                copy.deepcopy(journal.get("created_directories") or []),
                                detail=detail,
                                require_attached=False,
                                validated_plan_proof=compact_proof,
                            )
                        outcomes.append(
                            CreateOnlyTransactionOutcome(
                                "recovery_required",
                                transaction_id,
                                detail=detail,
                            )
                        )
                        continue
                if state != "COMMITTED":
                    _persist_content_checkpoint(
                        runtime,
                        transaction_id,
                        plan,
                        "COMMITTED",
                        copy.deepcopy(journal.get("applied_actions") or []),
                        copy.deepcopy(journal.get("created_directories") or []),
                        require_attached=False,
                        validated_plan_proof=compact_proof,
                    )
                    outcomes.append(
                        CreateOnlyTransactionOutcome(
                            "committed",
                            transaction_id,
                            str(receipts_root / f"{transaction_id}.json"),
                        )
                    )
                continue

            if state == "COMMITTED":
                detail = (
                    "Committed v2 journal is missing its cumulative manifest "
                    "transaction; targets and private backups were preserved."
                )
                outcomes.append(
                    CreateOnlyTransactionOutcome(
                        "recovery_required",
                        transaction_id,
                        detail=detail,
                    )
                )
                continue
            outcome = _rollback_v2_transaction(
                runtime,
                transaction_id,
                plan,
                journal,
                project_id=project_id,
                scope_integrity_sha3_512=scope_integrity_sha3_512,
                source_policy_sha256=scope_source_policy_sha256,
                reason="Interrupted content-aware transaction rolled back during recovery.",
                validated_plan_proof=compact_proof,
            )
            outcomes.append(outcome)
            if outcome.status != "rolled_back":
                # Preserve historical terminal journals when pending recovery failed.
                return outcomes
    return outcomes


def recover_managed_content_transactions(
    project_root: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> list[CreateOnlyTransactionOutcome]:
    """Recover every supported receipt generation through one public command."""

    root = project_root.resolve(strict=True)
    arguments = {
        "project_id": project_id,
        "scope_integrity_sha3_512": scope_integrity_sha3_512,
        "scope_source_policy_sha256": scope_source_policy_sha256,
        "transaction_root": transaction_root,
        "lock_path": lock_path,
        "manifest_path": manifest_path,
        "bases_root": bases_root,
        "receipts_root": receipts_root,
    }
    if any(path.name.startswith(".preparing-") for path in transaction_root.iterdir()):
        # Presence is a routing hint, never permission to adopt or delete residue.
        return _recover_create_only_transactions_v1(root, **arguments)
    observed_v2 = False
    observed_unfinished_v1 = False
    for transaction_path in sorted(transaction_root.iterdir()):
        if not transaction_path.is_dir() or transaction_path.is_symlink():
            raise TransactionPrimitiveError(
                f"Unknown managed-content transaction entry: {transaction_path.name}"
            )
        journal, _plan, version = _load_content_checkpoint_path(
            transaction_path / "journal.json", project_root=root)
        if version == "v2":
            observed_v2 = True
        elif journal.get("state") not in TERMINAL_CONTENT_STATES:
            observed_unfinished_v1 = True

    if observed_unfinished_v1:
        outcomes = _recover_create_only_transactions_v1(root, **arguments)
        if observed_v2 and all(item.status in {"committed", "rolled_back"} for item in outcomes):
            outcomes.extend(_recover_v2_transactions(root, **arguments))
        return outcomes
    if observed_v2:
        return _recover_v2_transactions(root, **arguments)
    return _recover_create_only_transactions_v1(root, **arguments)


def recover_create_only_transactions(
    project_root: Path,
    *,
    project_id: str,
    scope_integrity_sha3_512: str,
    scope_source_policy_sha256: str,
    transaction_root: Path,
    lock_path: Path,
    manifest_path: Path,
    bases_root: Path,
    receipts_root: Path,
) -> list[CreateOnlyTransactionOutcome]:
    """Compatibility entry point for v1 and later managed-content recovery."""

    return recover_managed_content_transactions(
        project_root,
        project_id=project_id,
        scope_integrity_sha3_512=scope_integrity_sha3_512,
        scope_source_policy_sha256=scope_source_policy_sha256,
        transaction_root=transaction_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        bases_root=bases_root,
        receipts_root=receipts_root,
    )
