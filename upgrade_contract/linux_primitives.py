"""Linux descriptor operations used by the managed-content transaction engine.

Only native renameat2 is accepted: a check followed by ordinary rename cannot
provide no-clobber publication. Callers retain object-identity, metadata and
journal checks around these primitives. Native qualification is separate from
the deterministic ABI/error tests that can run on another host.
"""

from __future__ import annotations

import ctypes
import array
import base64
import errno
import hashlib
import os
import platform
import stat


RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
# Allocation layout is kernel managed; these bits do not grant permissions.
FS_INDEX_FL = 0x00001000
FS_EXTENT_FL = 0x00080000
# Only these kernel-managed allocation/index bits may differ between a bound
# historical observation and the same held object later. Keep this separate
# from the supported-flags policy if that policy is extended in the future.
KERNEL_LAYOUT_FLAGS = FS_INDEX_FL | FS_EXTENT_FL
SUPPORTED_INODE_FLAGS = KERNEL_LAYOUT_FLAGS


def _require_linux() -> None:
    if platform.system() != "Linux":
        raise OSError(errno.ENOTSUP, "Linux primitives require a native Linux host")


def _leaf(name: str) -> bytes:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
    ):
        raise ValueError("Rename names must be single path components")
    return os.fsencode(name)


def metadata_inventory(
    descriptor: int,
) -> tuple[int, list[str], list[dict[str, object]]]:
    """Observe inode flags and all visible xattrs through the held descriptor.

    POSIX ACLs are retained as exact base64 values as well as xattr digests.
    Their presence is not permission to reproduce them: the current engine
    rejects extended ACLs and unsupported flags before any target mutation.
    """
    _require_linux()
    import fcntl

    value = array.array("l", [0])
    # FS_IOC_GETFLAGS is _IOR('f', 1, long), whose size is ABI dependent.
    request = 0x80000000 | (value.itemsize << 16) | (ord("f") << 8) | 1
    fcntl.ioctl(descriptor, request, value, True)
    flags = int(value[0])
    if flags < 0:
        raise OSError(errno.EIO, "Invalid inode flags returned by the filesystem")
    names = sorted(os.fsencode(name) for name in os.listxattr(descriptor))
    attributes = [(name, os.getxattr(descriptor, name)) for name in names]
    if sorted(os.fsencode(name) for name in os.listxattr(descriptor)) != names:
        raise OSError(errno.EIO, "Attribute inventory changed during observation")
    acl = [
        name.decode("ascii") + ":" + base64.b64encode(data).decode("ascii")
        for name, data in attributes
        if name in {b"system.posix_acl_access", b"system.posix_acl_default"}
    ]
    xattrs = [
        {
            "name_base64": base64.b64encode(name).decode("ascii"),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for name, data in attributes
    ]
    return flags, acl, xattrs


def rename_at(
    source_directory: int,
    source_name: str,
    destination_directory: int,
    destination_name: str,
    *,
    exchange: bool = False,
) -> None:
    """Perform one kernel no-replace/exchange operation beneath held directories.

    Names contain exactly one component, so renameat2 never resolves an
    intermediate path. Like POSIX rename, a symlink leaf would be moved, not
    followed. The engine must still verify the observed/published leaf identity.
    No path-based or non-atomic fallback is used for an unsupported filesystem.
    """
    _require_linux()
    source_leaf, destination_leaf = _leaf(source_name), _leaf(destination_name)
    if not isinstance(exchange, bool):
        raise ValueError("exchange must be a boolean")
    for descriptor in (source_directory, destination_directory):
        if (
            isinstance(descriptor, bool)
            or not isinstance(descriptor, int)
            or descriptor < 0
        ):
            raise ValueError(
                "Rename directory descriptors must be nonnegative integers"
            )
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise NotADirectoryError(
                errno.ENOTDIR, "Rename requires held directory descriptors"
            )
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError(
            errno.ENOTSUP, "libc does not expose renameat2; no fallback is permitted"
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        source_directory,
        source_leaf,
        destination_directory,
        destination_leaf,
        RENAME_EXCHANGE if exchange else RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno() or errno.EIO
        raise OSError(error, os.strerror(error), destination_name)


def supported_source_xattr_name(name: str | bytes) -> bool:
    """Only user namespace attributes may be transported from Linux sources."""
    encoded = os.fsencode(name)
    return (
        encoded.startswith(b"user.")
        and len(encoded) > len(b"user.")
        and b"\x00" not in encoded
    )


def copy_data_and_xattrs(source: int, destination: int) -> None:
    """Copy held regular-file bytes and extended attributes into empty staging.

    The destination must already have been created exclusively by the caller.
    Ownership, mode, fsync and source/destination metadata comparison remain in
    the engine. Only user.* source xattrs are supported; destination security
    labels are never rewritten and exact metadata comparison remains required.
    """
    _require_linux()
    before = os.fstat(source)
    target = os.fstat(destination)
    if (
        not stat.S_ISREG(before.st_mode)
        or not stat.S_ISREG(target.st_mode)
        or before.st_nlink != 1
        or target.st_nlink != 1
        or target.st_size != 0
        or (before.st_dev, before.st_ino) == (target.st_dev, target.st_ino)
    ):
        raise OSError(
            errno.EINVAL,
            "Copy requires distinct unique regular files and empty staging",
        )
    names = sorted(os.fsencode(name) for name in os.listxattr(source))
    if any(not supported_source_xattr_name(name) for name in names):
        raise OSError(
            errno.ENOTSUP,
            "UNSUPPORTED_METADATA: Linux source xattrs must use the user.* namespace",
        )
    attributes = [(name, os.getxattr(source, name)) for name in names]
    # Complete policy/inventory validation before any payload or attribute write.
    if sorted(os.fsencode(name) for name in os.listxattr(source)) != names or any(
        os.getxattr(source, name) != value for name, value in attributes
    ):
        raise OSError(errno.EIO, "Source attributes changed before staging")
    os.lseek(source, 0, os.SEEK_SET)
    os.lseek(destination, 0, os.SEEK_SET)
    remaining = before.st_size
    while remaining:
        chunk = os.read(source, min(remaining, 1024 * 1024))
        if not chunk:
            raise OSError(errno.EIO, "Source shortened during staging")
        remaining -= len(chunk)
        pending = memoryview(chunk)
        while pending:
            written = os.write(destination, pending)
            if written <= 0:
                raise OSError(errno.EIO, "Staging write made no progress")
            pending = pending[written:]
    if os.read(source, 1):
        raise OSError(errno.EIO, "Source grew during staging")
    # Do not erase inherited destination ACL/security attributes: the caller's
    # exact metadata check must reject an incompatible staging environment.
    for name, value in attributes:
        os.setxattr(destination, name, value)
    if sorted(os.fsencode(name) for name in os.listxattr(source)) != names or any(
        os.getxattr(source, name) != value for name, value in attributes
    ):
        raise OSError(errno.EIO, "Source attributes changed during staging")
    after = os.fstat(source)
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise OSError(errno.EIO, "Source changed during staging")
