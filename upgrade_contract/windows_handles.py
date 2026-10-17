"""Windows handle primitives for a future, journaled managed-content adapter.

This module is import-safe on non-Windows hosts. Public operations require a
native Windows runtime; `_WindowsOps` permits ABI-only tests with injected DLLs.
Report-only replacement is separate from no-overwrite managed transactions.
This module does not implement a transaction protocol.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import re
import struct
import sys
from dataclasses import dataclass


# Windows ABI types must have Windows widths even when inspected on macOS.
DWORD = ctypes.c_uint32
USHORT = ctypes.c_uint16
WCHAR = ctypes.c_uint16
BOOLEAN = ctypes.c_uint8
HANDLE = ctypes.c_void_p
ULONG_PTR = ctypes.c_size_t


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", HANDLE)]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", DWORD), ("RootDirectory", HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", DWORD), ("SecurityDescriptor", HANDLE),
        ("SecurityQualityOfService", HANDLE),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("StatusOrPointer", HANDLE), ("Information", ULONG_PTR)]


class FILE_STANDARD_INFO(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_int64), ("EndOfFile", ctypes.c_int64),
        ("NumberOfLinks", DWORD), ("DeletePending", BOOLEAN),
        ("Directory", BOOLEAN),
    ]


class FILE_ID_INFO(ctypes.Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_uint64), ("FileId", ctypes.c_uint8 * 16)]


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", DWORD), ("ReparseTag", DWORD)]


class FILE_BASIC_INFO(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64), ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64), ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", DWORD),
    ]


class OVERLAPPED_OFFSET(ctypes.Structure):
    _fields_ = [
        ("Internal", ULONG_PTR), ("InternalHigh", ULONG_PTR),
        ("Offset", DWORD), ("OffsetHigh", DWORD), ("hEvent", HANDLE),
    ]


class FILE_RENAME_INFO_HEADER(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", DWORD), ("RootDirectory", HANDLE),
        ("FileNameLength", DWORD),
    ]


class ACL_HEADER(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_uint8), ("Sbz1", ctypes.c_uint8),
                ("AclSize", USHORT), ("AceCount", USHORT), ("Sbz2", USHORT)]


class FILE_STREAM_INFO_HEADER(ctypes.Structure):
    _fields_ = [("NextEntryOffset", DWORD), ("StreamNameLength", DWORD),
                ("StreamSize", ctypes.c_int64), ("StreamAllocationSize", ctypes.c_int64)]


class FILE_EA_INFORMATION(ctypes.Structure):
    _fields_ = [("EaSize", DWORD)]


FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001  # Directory-specific alias of FILE_READ_DATA.
FILE_READ_ATTRIBUTES = 0x0080
FILE_WRITE_ATTRIBUTES = 0x0100
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
FILE_WRITE_DATA = 0x0002
FILE_TRAVERSE = 0x0020
FILE_ADD_FILE = 0x0002
FILE_ADD_SUBDIRECTORY = 0x0004
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
FILE_OPEN = 0x1
FILE_CREATE = 0x2
FILE_DIRECTORY_FILE = 0x1
FILE_NON_DIRECTORY_FILE = 0x40
FILE_SYNCHRONOUS_IO_NONALERT = 0x20
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_OPEN_NO_RECALL = 0x00400000
OBJ_CASE_INSENSITIVE = 0x40
OBJ_DONT_REPARSE = 0x1000
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_DEVICE = 0x40
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_OPEN_NO_RECALL = 0x00100000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_STANDARD_INFO_CLASS = 1
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
FILE_ID_INFO_CLASS = 18
FILE_BASIC_INFO_CLASS = 0
FILE_RENAME_INFO_CLASS = 3
NT_FILE_RENAME_INFORMATION_CLASS = 10
FILE_STREAM_INFO_CLASS = 7
FILE_NAMES_INFORMATION_CLASS = 12
STATUS_NO_MORE_FILES = 0x80000006
NT_FILE_EA_INFORMATION_CLASS = 7
FILE_DISPOSITION_INFO_CLASS = 4
SUPPORTED_FILE_ATTRIBUTES = 0x20 | 0x80  # ARCHIVE | NORMAL
# Ordinary ancestor directories may be hidden/system/read-only or excluded
# from indexing. These flags are observed, never changed here; READONLY is
# explicitly not honored on directories by Win32. Reparse, compression,
# encryption, recall and other storage semantics remain outside this policy.
# https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
SUPPORTED_DIRECTORY_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY | 0x20 | 0x80 | 0x1 | 0x2 | 0x4 | 0x2000
LOCKFILE_FAIL_IMMEDIATELY = 0x1
LOCKFILE_EXCLUSIVE_LOCK = 0x2
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x1
GROUP_SECURITY_INFORMATION = 0x2
DACL_SECURITY_INFORMATION = 0x4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
SE_DACL_PROTECTED = 0x1000
SE_DACL_PRESENT = 0x0004
SE_SELF_RELATIVE = 0x8000
FILE_BEGIN = 0
MAX_IO_CHUNK = 1024 * 1024
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
TOKEN_PRIMARY_GROUP_CLASS = 5
ERROR_INSUFFICIENT_BUFFER = 122

_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(?:\.|$)", re.I)


class WindowsHandleError(OSError):
    """A failed native call, retaining its distinct error domain."""

    def __init__(self, operation: str, *, winerror: int, ntstatus: int | None = None):
        self.operation = operation
        self.ntstatus = ntstatus
        suffix = f"; NTSTATUS=0x{ntstatus:08X}" if ntstatus is not None else ""
        super().__init__(f"{operation} failed: Win32={winerror}{suffix}")
        # Windows OSError initializes its native winerror slot in __init__.
        # Preserve the supplied domain code after that initialization.
        self.winerror = winerror


class UnsafeWindowsPath(ValueError):
    """A name or opened object violates the no-follow boundary."""


def validate_component(name: str) -> str:
    """Accept one ordinary Win32 file component, never a stream or device name."""
    if (not isinstance(name, str) or not name or name in {".", ".."}
            or any(c in name for c in '/\\:\0<>"|?*')
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name)
            or name[-1] in " ." or _RESERVED.match(name)):
        raise UnsafeWindowsPath(f"Unsafe Windows file component: {name!r}")
    if len(name.encode("utf-16-le")) > 510:
        raise UnsafeWindowsPath("Windows component exceeds 255 UTF-16 units")
    return name


def validate_root_path(path: str | os.PathLike[str]) -> str:
    value = os.fspath(path)
    if not isinstance(value, str) or "\0" in value or value.startswith(("\\\\?\\", "\\\\.\\")):
        raise UnsafeWindowsPath("Root must be an ordinary absolute drive path")
    drive, tail = ntpath.splitdrive(value)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\"):
        raise UnsafeWindowsPath("Root must be an absolute drive path")
    if "\\\\" in tail[1:]:
        raise UnsafeWindowsPath("Root contains an empty path component")
    for component in tail.split("\\"):
        if component:
            validate_component(component)
    return value


def _utf16(name: str) -> tuple[ctypes.Array[WCHAR], int]:
    encoded = name.encode("utf-16-le")
    return (WCHAR * (len(encoded) // 2 + 1)).from_buffer_copy(encoded + b"\0\0"), len(encoded)


def _rename_buffer(destination_name: str, destination_parent: int, *, replace: bool = False) -> ctypes.Array[ctypes.c_char]:
    if type(replace) is not bool:
        raise ValueError("replace must be a boolean")
    encoded = validate_component(destination_name).encode("utf-16-le")
    # FILE_RENAME_INFO FileName starts at its actual ABI offset, not at sizeof(header).
    class _Prefix(ctypes.Structure):
        _fields_ = FILE_RENAME_INFO_HEADER._fields_ + [("FileName", WCHAR * 1)]
    offset = _Prefix.FileName.offset
    # Keep FileName at its ABI offset, but allocate the full padded structure
    # plus the UTF-16 payload as required by FILE_RENAME_INFORMATION. The
    # structure's WCHAR placeholder/padding also leaves the name NUL-terminated.
    buffer = ctypes.create_string_buffer(ctypes.sizeof(_Prefix) + len(encoded))
    header = FILE_RENAME_INFO_HEADER.from_buffer(buffer)
    header.ReplaceIfExists = int(replace)
    header.RootDirectory = destination_parent
    header.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
    return buffer


@dataclass(frozen=True)
class HandleInfo:
    volume: int
    file_id: bytes
    directory: bool
    links: int
    size: int
    attributes: int
    reparse_tag: int
    created_time: int
    modified_time: int
    changed_time: int

    @property
    def identity(self) -> tuple[int, bytes]:
        return self.volume, self.file_id


@dataclass(frozen=True)
class SecurityParts:
    """Exact owner, group, and DACL bytes; SACL is outside this policy."""

    owner_sid: bytes
    group_sid: bytes
    dacl: bytes
    protected: bool
    descriptor: bytes


class HeldHandle:
    """One owned kernel handle; close is explicit and idempotent."""

    def __init__(self, ops: _WindowsOps, value: int, *, writable: bool = False,
                 created: bool = False, delete_pinned: bool = False,
                 metadata_restore: bool = False,
                 origin: tuple[tuple[int, bytes], str] | None = None):
        if not value or value == INVALID_HANDLE_VALUE:
            raise ValueError("Invalid Windows handle")
        self._ops = ops
        self.value = value
        self._lock: OVERLAPPED_OFFSET | None = None
        self._writable = writable
        self._created = created
        self._delete_pinned = delete_pinned
        self._metadata_restore = metadata_restore
        self._origin = origin

    def close(self) -> None:
        if self.value is None:
            return
        value = self.value
        unlock_error = None
        if self._lock is not None:
            try:
                self.unlock()
            except WindowsHandleError as exc:
                unlock_error = exc
        self._ops._check_win(self._ops.k32.CloseHandle(value), "CloseHandle")
        self.value = None
        self._lock = None
        if unlock_error is not None:
            raise unlock_error

    def __enter__(self) -> HeldHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def info(self) -> HandleInfo:
        return self._ops.observe(self)

    def flush(self) -> None:
        self._ops.flush(self)

    def lock_exclusive(self, *, nonblocking: bool = False) -> None:
        """Acquire the byte-range lock, optionally refusing contention at once."""
        self._ops.lock_exclusive(self, nonblocking=nonblocking)

    def unlock(self) -> None:
        self._ops.unlock(self)

    def seek(self, offset: int) -> int:
        return self._ops.seek(self, offset)

    def read(self, count: int) -> bytes:
        return self._ops.read(self, count)

    def write_all(self, data: bytes) -> None:
        self._ops.write_all(self, data)

    def truncate(self, size: int) -> None:
        self._ops.truncate_created(self, size)

    def security(self) -> SecurityParts:
        return self._ops.observe_security(self)


class _WindowsOps:
    """Internal call layer; injection is only for cross-host ABI tests."""

    def __init__(self, k32: object, ntdll: object, *, last_error: object,
                 advapi: object | None = None):
        self.k32, self.ntdll, self.last_error, self.advapi = k32, ntdll, last_error, advapi

    def _check_win(self, result: int, operation: str) -> None:
        if not result:
            raise WindowsHandleError(operation, winerror=int(self.last_error()))

    def _check_nt(self, status: int, operation: str) -> None:
        status &= 0xFFFFFFFF
        if status != 0:
            code = int(self.ntdll.RtlNtStatusToDosError(status))
            raise WindowsHandleError(operation, winerror=code, ntstatus=status)

    def _query(self, handle: HeldHandle, cls: int, struct: object) -> object:
        if handle.value is None:
            raise ValueError("Closed Windows handle")
        self._check_win(
            self.k32.GetFileInformationByHandleEx(handle.value, cls, ctypes.byref(struct), ctypes.sizeof(struct)),
            "GetFileInformationByHandleEx",
        )
        return struct

    def _metadata_diagnostic(self, handle: HeldHandle, *, directory: bool,
                             attributes: int) -> str:
        """Describe held observations; component is not a reopened path."""
        permitted = SUPPORTED_DIRECTORY_ATTRIBUTES if directory else SUPPORTED_FILE_ATTRIBUTES
        component = handle._origin[1] if handle._origin is not None else None
        return (
            f"object_role={'directory' if directory else 'file'}; "
            f"relative_component={component!r}; "
            f"observed_attributes=0x{attributes:08X}; "
            f"permitted_attributes=0x{permitted:08X}; "
            f"unsupported_attributes=0x{attributes & ~permitted:08X}"
        )

    def observe(self, handle: HeldHandle) -> HandleInfo:
        standard = self._query(handle, FILE_STANDARD_INFO_CLASS, FILE_STANDARD_INFO())
        identity = self._query(handle, FILE_ID_INFO_CLASS, FILE_ID_INFO())
        tag = self._query(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS, FILE_ATTRIBUTE_TAG_INFO())
        basic = self._query(handle, FILE_BASIC_INFO_CLASS, FILE_BASIC_INFO())
        if basic.FileAttributes != tag.FileAttributes:
            raise UnsafeWindowsPath("File attributes changed during observation")
        if tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE):
            raise UnsafeWindowsPath(
                "Reparse point or device is not a regular managed-content object ("
                + self._metadata_diagnostic(handle, directory=bool(standard.Directory),
                                            attributes=tag.FileAttributes) + ")"
            )
        if bool(standard.Directory) != bool(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY):
            raise UnsafeWindowsPath("File type observations disagree")
        if standard.DeletePending:
            raise UnsafeWindowsPath("File is delete-pending")
        return HandleInfo(
            identity.VolumeSerialNumber, bytes(identity.FileId), bool(standard.Directory),
            standard.NumberOfLinks, standard.EndOfFile, tag.FileAttributes,
            tag.ReparseTag, basic.CreationTime, basic.LastWriteTime, basic.ChangeTime,
        )

    def assert_supported_metadata(self, handle: HeldHandle) -> HandleInfo:
        """Fail closed on links, unsupported attributes, EAs, and named streams."""
        info = self.observe(handle)
        permitted = SUPPORTED_DIRECTORY_ATTRIBUTES if info.directory else SUPPORTED_FILE_ATTRIBUTES
        if info.attributes & ~permitted:
            raise UnsafeWindowsPath(
                "Unsupported Windows attributes ("
                + self._metadata_diagnostic(handle, directory=info.directory,
                                            attributes=info.attributes) + ")"
            )
        if not info.directory and info.links != 1:
            raise UnsafeWindowsPath(
                "Unsupported hard-link count ("
                + self._metadata_diagnostic(handle, directory=False,
                                            attributes=info.attributes)
                + f"; observed_links={info.links}; permitted_links=1)"
            )
        iosb, ea = IO_STATUS_BLOCK(), FILE_EA_INFORMATION()
        status = self.ntdll.NtQueryInformationFile(
            handle.value, ctypes.byref(iosb), ctypes.byref(ea),
            ctypes.sizeof(ea), NT_FILE_EA_INFORMATION_CLASS,
        )
        self._check_nt(status, "NtQueryInformationFile(FileEaInformation)")
        if ea.EaSize:
            raise UnsafeWindowsPath("Extended attributes are unsupported")
        size = 4096
        while True:
            buffer = ctypes.create_string_buffer(size)
            if self.k32.GetFileInformationByHandleEx(handle.value, FILE_STREAM_INFO_CLASS,
                                                       buffer, size):
                break
            error = int(self.last_error())
            # FileStreamInfo reports ERROR_HANDLE_EOF when a directory has no
            # streams. This is an empty inventory, not a failed metadata read.
            # A regular file must still expose its default data stream.
            if error == 38 and info.directory:
                return info
            if error not in {122, 234} or size >= 1024 * 1024:
                raise WindowsHandleError("GetFileInformationByHandleEx(FileStreamInfo)", winerror=error)
            size *= 2
        position = 0
        allowed = {"::$DATA", "::$INDEX_ALLOCATION", ":$I30:$INDEX_ALLOCATION"} if info.directory else {"::$DATA"}
        while True:
            if position + ctypes.sizeof(FILE_STREAM_INFO_HEADER) > size:
                raise UnsafeWindowsPath("Malformed stream inventory")
            header = FILE_STREAM_INFO_HEADER.from_buffer_copy(buffer, position)
            length = header.StreamNameLength
            end = position + ctypes.sizeof(FILE_STREAM_INFO_HEADER) + length
            if length % 2 or end > size:
                raise UnsafeWindowsPath("Malformed stream name")
            stream = bytes(buffer[position + ctypes.sizeof(FILE_STREAM_INFO_HEADER):end]).decode("utf-16-le")
            if not info.directory and not stream:
                raise UnsafeWindowsPath("Missing default file stream inventory")
            if stream and stream.upper() not in allowed:
                raise UnsafeWindowsPath("Alternate data stream is unsupported")
            if not header.NextEntryOffset:
                break
            if header.NextEntryOffset % 8 or header.NextEntryOffset < ctypes.sizeof(FILE_STREAM_INFO_HEADER) + length:
                raise UnsafeWindowsPath("Malformed stream offset")
            position += header.NextEntryOffset
        return info

    def open_root(self, path: str | os.PathLike[str], *, for_publish: bool = False) -> HeldHandle:
        name = validate_root_path(path)
        if ntpath.splitdrive(name)[1] != "\\":
            raise UnsafeWindowsPath("Raw root open requires a drive root; walk other components through held parents")
        wide, _ = _utf16(name)
        access = FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE
        if for_publish:
            access |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
        raw = self.k32.CreateFileW(
            ctypes.cast(wide, HANDLE), access,
            (FILE_SHARE_READ | FILE_SHARE_WRITE) if for_publish else FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
            None,
        )
        if not raw or raw == INVALID_HANDLE_VALUE:
            raise WindowsHandleError("CreateFileW", winerror=int(self.last_error()))
        handle = HeldHandle(self, int(raw))
        try:
            if not self.assert_supported_metadata(handle).directory:
                raise UnsafeWindowsPath("Project root is not a directory")
            return handle
        except BaseException:
            handle.close()
            raise

    def open_child(self, parent: HeldHandle, name: str, *, kind: str,
                   for_rename: bool = False, create: bool = False,
                   for_lock: bool = False, for_write: bool = False,
                   for_publish: bool = False, for_delete: bool = False,
                   for_security_copy: bool = False,
                   for_metadata_restore: bool = False,
                   pin_for_read: bool = False) -> HeldHandle:
        validate_component(name)
        if parent.value is None:
            raise ValueError("Closed parent handle")
        if (kind not in {"directory", "file"}
                or (for_lock and kind != "file")
                or (for_publish and kind != "directory")):
            raise ValueError("kind must be directory or file")
        if type(for_metadata_restore) is not bool:
            raise ValueError("for_metadata_restore must be a boolean")
        if for_metadata_restore and (kind != "file" or any((
                create, for_rename, for_lock, for_write, for_publish, for_delete,
                for_security_copy, pin_for_read))):
            raise ValueError("Metadata restoration requires an exclusive file-only open mode")
        if create:
            raise NotImplementedError("Creation requires a protected security template")
        if pin_for_read and any((for_rename, for_lock, for_write, for_publish,
                                 for_delete, for_security_copy)):
            raise ValueError("read pin cannot be combined with mutation access")
        if not self.observe(parent).directory:
            raise UnsafeWindowsPath("Parent handle is not a directory")
        parent_identity = self.observe(parent).identity
        wide, length = _utf16(name)
        unicode_name = UNICODE_STRING(length, length + 2, ctypes.cast(wide, HANDLE))
        attrs = OBJECT_ATTRIBUTES(
            ctypes.sizeof(OBJECT_ATTRIBUTES), parent.value, ctypes.pointer(unicode_name),
            OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, None, None,
        )
        status_block = IO_STATUS_BLOCK()
        result = HANDLE()
        access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
        if kind == "file":
            access |= FILE_READ_DATA
        else:
            access |= FILE_TRAVERSE | FILE_LIST_DIRECTORY
            if for_publish:
                access |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
        if for_rename or for_delete:
            access |= DELETE
        if for_security_copy:
            access |= WRITE_DAC
        if for_metadata_restore:
            access |= FILE_WRITE_ATTRIBUTES
        if for_lock or for_write:
            # LockFileEx and FlushFileBuffers document GENERIC_READ/GENERIC_WRITE rights.
            access |= GENERIC_READ | GENERIC_WRITE
        # Type-neutral open: FILE_DIRECTORY_FILE has a narrower documented
        # compatibility list. The held handle is checked immediately below.
        options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL
        mutation_pinned = (for_rename or for_delete or for_write or for_lock or for_publish
                           or for_security_copy or for_metadata_restore or pin_for_read)
        # Directory child-add rights are write access. Compatible nested walks
        # must share those rights while denying DELETE (rename/unlink of this
        # directory). Leaf pins still deny competing content writes/deletes.
        share = FILE_SHARE_READ
        if kind == "directory" or not mutation_pinned:
            share |= FILE_SHARE_WRITE
        if not mutation_pinned:
            share |= FILE_SHARE_DELETE
        status = self.ntdll.NtCreateFile(
            ctypes.byref(result), access, ctypes.byref(attrs), ctypes.byref(status_block),
            None, 0, share,
            FILE_CREATE if create else FILE_OPEN, options, None, 0,
        )
        self._check_nt(status, "NtCreateFile")
        if not result.value:
            raise WindowsHandleError("NtCreateFile returned null handle", winerror=6)
        handle = HeldHandle(self, result.value, writable=for_write or for_lock,
                            created=create, delete_pinned=for_delete,
                            metadata_restore=for_metadata_restore,
                            origin=(parent_identity, name))
        try:
            info = self.assert_supported_metadata(handle)
            if info.directory != (kind == "directory") or (kind == "file" and info.links != 1):
                raise UnsafeWindowsPath("Child type or hard-link count is unsafe")
            return handle
        except BaseException:
            handle.close()
            raise

    def restore_rename_metadata(self, handle: HeldHandle, *, creation_time: int,
                                attributes: int) -> None:
        """Restore only journal-authorized creation time and NORMAL/ARCHIVE.

        The caller must verify the exact object and authorization before this
        call, close this metadata-only handle, then reopen and fully verify the
        result. Successful setting alone is not post-close verification.
        """
        if (not isinstance(handle, HeldHandle) or handle._ops is not self
                or handle.value is None or not handle._metadata_restore):
            raise ValueError("Metadata restoration requires its dedicated held handle")
        if (type(creation_time) is not int or not 0 < creation_time < 2**63
                or type(attributes) is not int or attributes not in {0x20, 0x80}):
            raise ValueError("Unsupported creation time or rename attributes")
        if self.assert_supported_metadata(handle).directory:
            raise UnsafeWindowsPath("Cannot restore file metadata on a directory")
        basic = FILE_BASIC_INFO(creation_time, 0, 0, 0, attributes)
        self._check_win(self.k32.SetFileInformationByHandle(
            handle.value, FILE_BASIC_INFO_CLASS, ctypes.byref(basic), ctypes.sizeof(basic)),
            "SetFileInformationByHandle(FileBasicInfo)")

    def rename_no_replace(self, source: HeldHandle, destination_parent: HeldHandle,
                          destination_name: str) -> None:
        if source.value is None or destination_parent.value is None:
            raise ValueError("Closed Windows handle")
        if source._delete_pinned:
            raise UnsafeWindowsPath("Delete-pinned handle cannot be renamed")
        if not self.assert_supported_metadata(destination_parent).directory:
            raise UnsafeWindowsPath("Destination parent is not a directory")
        source_info = self.assert_supported_metadata(source)
        if source_info.volume != self.observe(destination_parent).volume:
            raise UnsafeWindowsPath("Cross-volume rename is forbidden")
        buffer = _rename_buffer(destination_name, destination_parent.value)
        status_block = IO_STATUS_BLOCK()
        self._check_nt(
            self.ntdll.NtSetInformationFile(
                source.value, ctypes.byref(status_block), buffer,
                ctypes.sizeof(buffer), NT_FILE_RENAME_INFORMATION_CLASS),
            "NtSetInformationFile(FileRenameInformation)",
        )

    def replace_report(self, source: HeldHandle, destination_parent: HeldHandle,
                       destination_name: str) -> None:
        """Refresh one authorized report name beneath its pinned staging parent.

        This is not destination identity compare-and-swap. Callers validate the
        existing leaf before releasing its pin, as the POSIX report writer does.
        https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
        """
        validate_component(destination_name)
        if (source._ops is not self or destination_parent._ops is not self
                or source.value is None or destination_parent.value is None
                or not source._created or not source._writable or source._delete_pinned):
            raise UnsafeWindowsPath("Report replacement requires an owned writable stage")
        parent_info = self.assert_supported_metadata(destination_parent)
        info = self.assert_supported_metadata(source)
        if (not parent_info.directory or info.directory or info.links != 1
                or source._origin is None or source._origin[0] != parent_info.identity
                or source._origin[1].casefold() == destination_name.casefold()
                or info.volume != parent_info.volume):
            raise UnsafeWindowsPath("Report replacement must remain under its staging parent")
        buffer = _rename_buffer(destination_name, destination_parent.value, replace=True)
        status_block = IO_STATUS_BLOCK()
        self._check_nt(self.ntdll.NtSetInformationFile(
            source.value, ctypes.byref(status_block), buffer,
            ctypes.sizeof(buffer), NT_FILE_RENAME_INFORMATION_CLASS),
            "NtSetInformationFile(report replacement)")

    def replace_private_checkpoint(self, source: HeldHandle, parent: HeldHandle) -> None:
        """Rename a validated private state.pending.json over state.json.

        Caller must hold the operation lock and validate exact predecessor bytes
        and native identity immediately before calling. This is not destination
        compare-and-swap. Unlike report stages, an approved interrupted checkpoint
        stage may be reopened; ownership comes from its validated journal.
        """
        if (source._ops is not self or parent._ops is not self
                or source.value is None or parent.value is None or source._delete_pinned):
            raise UnsafeWindowsPath("Checkpoint replacement requires held native handles")
        info = self.assert_supported_metadata(source)
        parent_info = self.assert_supported_metadata(parent)
        if (info.directory or not parent_info.directory or info.links != 1
                or info.volume != parent_info.volume
                or source._origin != (parent_info.identity, 'state.pending.json')):
            raise UnsafeWindowsPath("Checkpoint replacement requires its exact same-parent stage")
        private = self._private_security()
        for handle in (source, parent):
            security = self.observe_security(handle)
            if any(getattr(security, field) != getattr(private, field)
                   for field in ('owner_sid', 'group_sid', 'dacl', 'protected')):
                raise UnsafeWindowsPath("Checkpoint replacement requires the current private policy")
        buffer = _rename_buffer('state.json', parent.value, replace=True)
        status_block = IO_STATUS_BLOCK()
        self._check_nt(self.ntdll.NtSetInformationFile(
            source.value, ctypes.byref(status_block), buffer,
            ctypes.sizeof(buffer), NT_FILE_RENAME_INFORMATION_CLASS),
            "NtSetInformationFile(private checkpoint replacement)")

    def flush(self, handle: HeldHandle) -> None:
        if handle.value is None:
            raise ValueError("Closed Windows handle")
        self._check_win(self.k32.FlushFileBuffers(handle.value), "FlushFileBuffers")

    def lock_exclusive(self, handle: HeldHandle, *, nonblocking: bool = False) -> None:
        if type(nonblocking) is not bool:
            raise ValueError("nonblocking must be a boolean")
        if handle.value is None or handle._lock is not None:
            raise ValueError("Handle closed or already locked")
        offset = OVERLAPPED_OFFSET()
        flags = LOCKFILE_EXCLUSIVE_LOCK
        if nonblocking:
            flags |= LOCKFILE_FAIL_IMMEDIATELY
        self._check_win(self.k32.LockFileEx(handle.value, flags, 0,
                                           1, 0, ctypes.byref(offset)), "LockFileEx")
        handle._lock = offset

    def unlock(self, handle: HeldHandle) -> None:
        if handle.value is None or handle._lock is None:
            raise ValueError("Handle closed or not locked")
        self._check_win(self.k32.UnlockFileEx(handle.value, 0, 1, 0,
                                             ctypes.byref(handle._lock)), "UnlockFileEx")
        handle._lock = None

    def seek(self, handle: HeldHandle, offset: int) -> int:
        if handle.value is None or not isinstance(offset, int) or not 0 <= offset < 2**63:
            raise ValueError("Invalid handle or absolute file offset")
        result = ctypes.c_int64()
        self._check_win(self.k32.SetFilePointerEx(handle.value, offset,
                                                 ctypes.byref(result), FILE_BEGIN), "SetFilePointerEx")
        return result.value

    def read(self, handle: HeldHandle, count: int) -> bytes:
        if handle.value is None or not isinstance(count, int) or not 0 <= count <= MAX_IO_CHUNK:
            raise ValueError("Invalid handle or read length")
        if self.assert_supported_metadata(handle).directory:
            raise UnsafeWindowsPath("Cannot read directory as file")
        if count == 0:
            return b""
        buffer = ctypes.create_string_buffer(count)
        transferred = DWORD()
        self._check_win(self.k32.ReadFile(handle.value, buffer, count,
                                          ctypes.byref(transferred), None), "ReadFile")
        if transferred.value > count:
            raise WindowsHandleError("ReadFile returned invalid length", winerror=13)
        return buffer.raw[:transferred.value]

    def write_all(self, handle: HeldHandle, data: bytes) -> None:
        if handle.value is None or not handle._writable or not isinstance(data, bytes):
            raise ValueError("Writable held file and bytes required")
        if self.assert_supported_metadata(handle).directory:
            raise UnsafeWindowsPath("Cannot write directory as file")
        position = 0
        while position < len(data):
            block = data[position:position + MAX_IO_CHUNK]
            buffer = ctypes.create_string_buffer(block)
            transferred = DWORD()
            self._check_win(self.k32.WriteFile(handle.value, buffer, len(block),
                                               ctypes.byref(transferred), None), "WriteFile")
            if not 0 < transferred.value <= len(block):
                raise WindowsHandleError("WriteFile made no valid progress", winerror=29)
            position += transferred.value

    def truncate_created(self, handle: HeldHandle, size: int) -> None:
        if handle.value is None or not handle._writable or not handle._created:
            raise ValueError("Truncation is limited to a newly created writable file")
        if self.assert_supported_metadata(handle).directory:
            raise UnsafeWindowsPath("Cannot truncate directory")
        self.seek(handle, size)
        self._check_win(self.k32.SetEndOfFile(handle.value), "SetEndOfFile")

    def observe_security(self, handle: HeldHandle) -> SecurityParts:
        if handle.value is None or self.advapi is None:
            raise RuntimeError("Native security descriptor observation unavailable")
        owner, group, dacl, descriptor = HANDLE(), HANDLE(), HANDLE(), HANDLE()
        code = self.advapi.GetSecurityInfo(
            handle.value, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), ctypes.byref(group), ctypes.byref(dacl), None,
            ctypes.byref(descriptor),
        )
        if code:
            raise WindowsHandleError("GetSecurityInfo", winerror=int(code))
        if not descriptor.value:
            raise UnsafeWindowsPath("Security descriptor is absent")
        try:
            control, revision = USHORT(), DWORD()
            self._check_win(self.advapi.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)),
                "GetSecurityDescriptorControl")
            if not control.value & SE_SELF_RELATIVE:
                raise UnsafeWindowsPath("Nonportable absolute security descriptor")
            if not (control.value & SE_DACL_PRESENT) or not owner.value or not group.value or not dacl.value:
                raise UnsafeWindowsPath("Missing owner, group, or non-null DACL")
            if not self.advapi.IsValidSid(owner) or not self.advapi.IsValidSid(group):
                raise UnsafeWindowsPath("Invalid owner or group SID")
            if not self.advapi.IsValidAcl(dacl):
                raise UnsafeWindowsPath("Invalid DACL")
            owner_len = int(self.advapi.GetLengthSid(owner))
            group_len = int(self.advapi.GetLengthSid(group))
            dacl_len = ACL_HEADER.from_address(dacl.value).AclSize
            descriptor_len = int(self.advapi.GetSecurityDescriptorLength(descriptor))
            if not (8 <= owner_len <= 256 and 8 <= group_len <= 256
                    and 8 <= dacl_len <= 65535 and 20 <= descriptor_len <= 131072):
                raise UnsafeWindowsPath("Security descriptor length is unsupported")
            return SecurityParts(
                ctypes.string_at(owner, owner_len), ctypes.string_at(group, group_len),
                ctypes.string_at(dacl, dacl_len), bool(control.value & SE_DACL_PROTECTED),
                ctypes.string_at(descriptor, descriptor_len),
            )
        finally:
            if self.k32.LocalFree(descriptor):
                raise WindowsHandleError("LocalFree", winerror=int(self.last_error()))

    def copy_protected_security(self, source: HeldHandle, destination: HeldHandle) -> None:
        if self.advapi is None:
            raise RuntimeError("Native security descriptor application unavailable")
        if not destination._created or not destination._writable:
            raise UnsafeWindowsPath("Security copy is limited to a new writable file")
        source_info, destination_info = self.assert_supported_metadata(source), self.assert_supported_metadata(destination)
        if source_info.directory or destination_info.directory or source_info.links != 1 or destination_info.links != 1:
            raise UnsafeWindowsPath("Security copy requires ordinary single-link files")
        source_sec = self.observe_security(source)
        dest_sec = self.observe_security(destination)
        if (not source_sec.protected or source_sec.owner_sid != dest_sec.owner_sid
                or source_sec.group_sid != dest_sec.group_sid):
            raise UnsafeWindowsPath("Protected source DACL and matching owner/group required")
        acl_buffer = ctypes.create_string_buffer(source_sec.dacl)
        code = self.advapi.SetSecurityInfo(
            destination.value, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, ctypes.cast(acl_buffer, HANDLE), None,
        )
        if code:
            raise WindowsHandleError("SetSecurityInfo", winerror=int(code))
        verified = self.observe_security(destination)
        if (verified.owner_sid, verified.group_sid, verified.dacl, verified.protected) != (
                source_sec.owner_sid, source_sec.group_sid, source_sec.dacl, True):
            raise UnsafeWindowsPath("Applied owner/group/DACL differs from source")

    def copy_report_security(self, source: HeldHandle, destination: HeldHandle) -> None:
        """Preserve selected owner/group/DACL on an empty private report stage.

        Unlike upgrade security copy, the source may inherit its DACL. Actual
        inheritance is observed and compared; unsupported preservation refuses.
        """
        if (source._ops is not self or destination._ops is not self
                or not destination._created or not destination._writable):
            raise UnsafeWindowsPath("Report security copy requires owned staging handles")
        src, dst = self.assert_supported_metadata(source), self.assert_supported_metadata(destination)
        if src.directory or dst.directory or src.links != 1 or dst.links != 1 or dst.size != 0:
            raise UnsafeWindowsPath("Report security must be selected before payload write")
        expected, current = self.observe_security(source), self.observe_security(destination)
        if (expected.owner_sid != current.owner_sid or expected.group_sid != current.group_sid):
            raise UnsafeWindowsPath("Report owner/group cannot be preserved")
        acl = ctypes.create_string_buffer(expected.dacl)
        flags = PROTECTED_DACL_SECURITY_INFORMATION if expected.protected else UNPROTECTED_DACL_SECURITY_INFORMATION
        code = self.advapi.SetSecurityInfo(destination.value, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | flags, None, None, ctypes.cast(acl, HANDLE), None)
        if code:
            raise WindowsHandleError("SetSecurityInfo(report)", winerror=int(code))
        actual = self.observe_security(destination)
        if (actual.owner_sid, actual.group_sid, actual.dacl, actual.protected) != (
                expected.owner_sid, expected.group_sid, expected.dacl, expected.protected):
            raise UnsafeWindowsPath("Report staging security differs from existing report")
        if self.observe_security(source) != expected:
            raise UnsafeWindowsPath("Existing report security changed during preservation")

    def copy_staged_file_security(self, source: HeldHandle, destination: HeldHandle) -> None:
        """Copy exact selected security onto an empty, newly created held file.

        A publication stage has a different parent from its working target.
        SetSecurityInfo with UNPROTECTED_DACL would inherit from that private
        parent. The documented user-mode NtSetSecurityObject API applies the
        observed descriptor directly; every selected byte must then match.
        https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetsecurityobject
        """
        if (source._ops is not self or destination._ops is not self
                or source.value is None or destination.value is None
                or source.value == destination.value
                or not destination._created or not destination._writable):
            raise UnsafeWindowsPath("Stage security copy requires distinct owned new-file handles")
        src, dst = self.assert_supported_metadata(source), self.assert_supported_metadata(destination)
        if (src.directory or dst.directory or src.links != 1 or dst.links != 1
                or src.identity == dst.identity or dst.size != 0):
            raise UnsafeWindowsPath("Stage security copy requires distinct ordinary files and empty destination")
        expected, current = self.observe_security(source), self.observe_security(destination)
        if expected.owner_sid != current.owner_sid or expected.group_sid != current.group_sid:
            raise UnsafeWindowsPath("Stage owner/group cannot be preserved")
        descriptor = ctypes.create_string_buffer(expected.descriptor)
        flags = (PROTECTED_DACL_SECURITY_INFORMATION if expected.protected
                 else UNPROTECTED_DACL_SECURITY_INFORMATION)
        status = self.ntdll.NtSetSecurityObject(
            destination.value, DACL_SECURITY_INFORMATION | flags,
            ctypes.cast(descriptor, HANDLE))
        self._check_nt(status, "NtSetSecurityObject(publication stage)")
        if self.observe_security(destination) != expected:
            raise UnsafeWindowsPath("Stage security differs from original descriptor")
        if self.observe_security(source) != expected:
            raise UnsafeWindowsPath("Source security changed during stage preservation")
        verified = self.assert_supported_metadata(destination)
        if (self.assert_supported_metadata(source) != src or
                (verified.identity, verified.directory, verified.links, verified.size,
                 verified.attributes, verified.reparse_tag, verified.created_time,
                 verified.modified_time) !=
                (dst.identity, dst.directory, dst.links, dst.size, dst.attributes,
                 dst.reparse_tag, dst.created_time, dst.modified_time)):
            raise UnsafeWindowsPath("File identity or metadata changed during security copy")

    def copy_supported_file_attributes(self, source: HeldHandle, destination: HeldHandle,
                                       *, expected_attributes: int) -> None:
        """Preserve approved ARCHIVE or NORMAL on a new, written staging file.

        FileBasicInfo's zero times leave the staging timestamps unchanged. Zero
        attributes mean no change, not NORMAL; NORMAL must be specified alone.
        https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info
        """
        if (type(expected_attributes) is not int or expected_attributes not in {0x20, 0x80}
                or not destination._created or not destination._writable):
            raise UnsafeWindowsPath("Attribute copy requires supported flags and a new writable file")
        source_info = self.assert_supported_metadata(source)
        destination_info = self.assert_supported_metadata(destination)
        if (source_info.directory or destination_info.directory
                or source_info.identity == destination_info.identity
                or source_info.attributes != expected_attributes):
            raise UnsafeWindowsPath("Attribute source differs from approved regular file")
        source_security = self.observe_security(source)
        destination_security = self.observe_security(destination)
        basic = FILE_BASIC_INFO(0, 0, 0, 0, expected_attributes)
        self._check_win(self.k32.SetFileInformationByHandle(
            destination.value, FILE_BASIC_INFO_CLASS, ctypes.byref(basic), ctypes.sizeof(basic)),
            "SetFileInformationByHandle(FileBasicInfo)")
        verified = self.assert_supported_metadata(destination)
        if (verified.identity != destination_info.identity
                or verified.directory or verified.size != destination_info.size
                or verified.attributes != expected_attributes
                or self.observe_security(destination) != destination_security
                or self.assert_supported_metadata(source) != source_info
                or self.observe_security(source) != source_security):
            raise UnsafeWindowsPath("Applied attributes, identity, or security differ from approved files")

    def _create_from_template(self, parent: HeldHandle, name: str,
                              template: HeldHandle, *, kind: str) -> HeldHandle:
        """Create exclusively beneath a held parent with a protected template SD."""
        if self.assert_supported_metadata(template).directory != (kind == "directory"):
            raise UnsafeWindowsPath("Security template type differs from requested type")
        return self._create_with_security(parent, name, self.observe_security(template), kind=kind)

    def _token_sid(self, token: HANDLE, information_class: int) -> bytes:
        if information_class not in {TOKEN_USER_CLASS, TOKEN_PRIMARY_GROUP_CLASS}:
            raise ValueError("Only token user and primary group SID queries are supported")
        header_size = ctypes.sizeof(HANDLE) * (2 if information_class == TOKEN_USER_CLASS else 1)
        length = DWORD()
        queried = self.advapi.GetTokenInformation(token, information_class, None, 0,
                                                  ctypes.byref(length))
        if queried or int(self.last_error()) != ERROR_INSUFFICIENT_BUFFER:
            raise WindowsHandleError("GetTokenInformation(size)", winerror=int(self.last_error()))
        if not header_size + 8 <= length.value <= 65536:
            raise UnsafeWindowsPath("Token SID buffer size is unsupported")
        buffer = ctypes.create_string_buffer(length.value)
        returned = DWORD()
        self._check_win(self.advapi.GetTokenInformation(
            token, information_class, buffer, length.value, ctypes.byref(returned)),
            "GetTokenInformation")
        if not header_size + 8 <= returned.value <= length.value:
            raise UnsafeWindowsPath("Token SID result size differs")
        address = HANDLE.from_buffer(buffer).value
        start, end = ctypes.addressof(buffer), ctypes.addressof(buffer) + returned.value
        if address is None or not start + header_size <= address <= end - 8:
            raise UnsafeWindowsPath("Token SID pointer is outside its buffer")
        # Bound the complete SID before asking native SID helpers to read it.
        header = ctypes.string_at(address, 8)
        sid_length = 8 + 4 * header[1]
        if header[0] != 1 or header[1] > 15 or address + sid_length > end:
            raise UnsafeWindowsPath("Token SID is truncated or unsupported")
        if (not self.advapi.IsValidSid(HANDLE(address))
                or int(self.advapi.GetLengthSid(HANDLE(address))) != sid_length):
            raise UnsafeWindowsPath("Invalid token SID")
        return ctypes.string_at(address, sid_length)

    def _sid_string(self, sid: bytes) -> str:
        buffer = ctypes.create_string_buffer(sid)
        pointer = HANDLE()
        self._check_win(self.advapi.ConvertSidToStringSidW(buffer, ctypes.byref(pointer)),
                        "ConvertSidToStringSidW")
        if not pointer.value:
            raise UnsafeWindowsPath("SID string was not returned")
        try:
            units = []
            for index in range(185):
                unit = WCHAR.from_address(pointer.value + 2 * index).value
                if unit == 0:
                    value = ''.join(chr(c) for c in units)
                    if not re.fullmatch(r'S-[0-9A-Fa-fx-]+', value):
                        raise UnsafeWindowsPath("Unexpected native SID string")
                    return value
                units.append(unit)
            raise UnsafeWindowsPath("Native SID string exceeds supported length")
        finally:
            if self.k32.LocalFree(pointer):
                raise WindowsHandleError("LocalFree(SID)", winerror=int(self.last_error()))

    def _private_security(self) -> SecurityParts:
        """New private objects grant full file access only to this process user.

        Query the primary token without enabling privileges or modifying it.
        Pass a protected descriptor during exclusive creation, so no inherited
        permissive-DACL window precedes a later ACL repair. This is for private
        runtime/templates, not a policy for replacing adopter file permissions.
        """
        token = HANDLE()
        self._check_win(self.advapi.OpenProcessToken(
            self.k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)), "OpenProcessToken")
        try:
            owner = self._token_sid(token, TOKEN_USER_CLASS)
            group = self._token_sid(token, TOKEN_PRIMARY_GROUP_CLASS)
            owner_text, group_text = self._sid_string(owner), self._sid_string(group)
            sddl, _ = _utf16(f"O:{owner_text}G:{group_text}D:P(A;;FA;;;{owner_text})")
            descriptor, length = HANDLE(), DWORD()
            self._check_win(self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), ctypes.byref(length)),
                "ConvertStringSecurityDescriptorToSecurityDescriptorW")
            if not descriptor.value:
                raise UnsafeWindowsPath("Private security descriptor is absent")
            try:
                if not 20 <= length.value <= 131072:
                    raise UnsafeWindowsPath("Private security descriptor size is unsupported")
                present, defaulted, dacl = ctypes.c_int(), ctypes.c_int(), HANDLE()
                self._check_win(self.advapi.GetSecurityDescriptorDacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)),
                    "GetSecurityDescriptorDacl")
                if not present.value or not dacl.value or not self.advapi.IsValidAcl(dacl):
                    raise UnsafeWindowsPath("Private DACL is missing or invalid")
                acl_length = ACL_HEADER.from_address(dacl.value).AclSize
                # One non-inherited ACCESS_ALLOWED_ACE, FILE_ALL_ACCESS, for
                # the exact token user. Reject unexpected converter output.
                ace = struct.pack('<BBHI', 0, 0, 8 + len(owner), 0x001F01FF) + owner
                expected_acl = struct.pack('<BBHHH', 2, 0, 8 + len(ace), 1, 0) + ace
                if acl_length != len(expected_acl) or ctypes.string_at(dacl, acl_length) != expected_acl:
                    raise UnsafeWindowsPath("Private DACL differs from the process-user-only policy")
                control, revision = USHORT(), DWORD()
                self._check_win(self.advapi.GetSecurityDescriptorControl(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)),
                    "GetSecurityDescriptorControl")
                required = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED
                if revision.value != 1 or control.value & required != required:
                    raise UnsafeWindowsPath("Private security descriptor is not protected")
                return SecurityParts(owner, group, expected_acl, True,
                                     ctypes.string_at(descriptor, length.value))
            finally:
                if self.k32.LocalFree(descriptor):
                    raise WindowsHandleError("LocalFree(SD)", winerror=int(self.last_error()))
        finally:
            self._check_win(self.k32.CloseHandle(token), "CloseHandle(token)")

    def _create_with_security(self, parent: HeldHandle, name: str,
                              security: SecurityParts | None, *, kind: str) -> HeldHandle:
        validate_component(name)
        if kind not in {"file", "directory"}:
            raise ValueError("Private child kind must be file or directory")
        if not self.assert_supported_metadata(parent).directory:
            raise UnsafeWindowsPath("Parent is not a directory")
        parent_identity = self.observe(parent).identity
        if security is not None and not security.protected:
            raise UnsafeWindowsPath("Template DACL is not protected")
        wide, length = _utf16(name)
        unicode_name = UNICODE_STRING(length, length + 2, ctypes.cast(wide, HANDLE))
        descriptor = ctypes.create_string_buffer(security.descriptor) if security is not None else None
        attrs = OBJECT_ATTRIBUTES(
            ctypes.sizeof(OBJECT_ATTRIBUTES), parent.value, ctypes.pointer(unicode_name),
            OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, ctypes.cast(descriptor, HANDLE), None,
        )
        result, iosb = HANDLE(), IO_STATUS_BLOCK()
        access = FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | SYNCHRONIZE
        if kind == "directory":
            access |= FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
            options = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
            share = FILE_SHARE_READ | FILE_SHARE_WRITE
        else:
            access |= GENERIC_READ | GENERIC_WRITE | DELETE
            options = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
            share = FILE_SHARE_READ
        status = self.ntdll.NtCreateFile(
            ctypes.byref(result), access, ctypes.byref(attrs), ctypes.byref(iosb),
            None, 0x20 if kind == "file" else 0, share,
            FILE_CREATE, options, None, 0,
        )
        self._check_nt(status, "NtCreateFile(exclusive create)")
        if not result.value or iosb.Information != 2:  # FILE_CREATED
            if result.value:
                self._check_win(self.k32.CloseHandle(result.value), "CloseHandle")
            raise WindowsHandleError("NtCreateFile did not create child", winerror=13)
        child = HeldHandle(self, result.value, created=True, writable=kind == "file",
                           origin=(parent_identity, name))
        try:
            if self.observe(parent).identity != parent_identity:
                raise UnsafeWindowsPath("Parent changed during exclusive creation")
            if self.assert_supported_metadata(child).directory != (kind == "directory"):
                raise UnsafeWindowsPath("New child has unexpected type")
            observed = self.observe_security(child)
            if security is not None and (observed.owner_sid, observed.group_sid, observed.dacl, observed.protected) != (
                    security.owner_sid, security.group_sid, security.dacl, True):
                raise UnsafeWindowsPath("New child security differs from template")
            return child
        except BaseException:
            child.close()
            raise

    def create_directory_from_template(self, parent: HeldHandle, name: str,
                                       template: HeldHandle) -> HeldHandle:
        return self._create_from_template(parent, name, template, kind="directory")

    def create_file_from_template(self, parent: HeldHandle, name: str,
                                  template: HeldHandle) -> HeldHandle:
        return self._create_from_template(parent, name, template, kind="file")

    def create_report_child(self, parent: HeldHandle, name: str, *, kind: str) -> HeldHandle:
        """Exclusive ordinary inherited-security creation for new report outputs."""
        return self._create_with_security(parent, name, None, kind=kind)

    def create_private(self, parent: HeldHandle, name: str, *, kind: str) -> HeldHandle:
        validate_component(name)
        return self._create_with_security(parent, name, self._private_security(), kind=kind)

    def delete_exact(self, parent: HeldHandle, name: str, target: HeldHandle) -> None:
        """Mark the pinned, exact child for deletion; caller journals this mutation."""
        validate_component(name)
        if not target._delete_pinned or target._origin != (self.observe(parent).identity, name):
            raise UnsafeWindowsPath("Target lacks matching delete-pinned origin")
        target_info = self.assert_supported_metadata(target)
        with self.open_child(parent, name,
                             kind="directory" if target_info.directory else "file") as live:
            if self.assert_supported_metadata(live).identity != target_info.identity:
                raise UnsafeWindowsPath("Child changed before deletion")
            disposition = BOOLEAN(1)
            self._check_win(self.k32.SetFileInformationByHandle(
                target.value, FILE_DISPOSITION_INFO_CLASS,
                ctypes.byref(disposition), ctypes.sizeof(disposition)),
                "SetFileInformationByHandle(FileDispositionInfo)",
            )
            target._delete_pinned = False

    def list_children(self, directory: HeldHandle, *, max_entries: int | None = None,
                      max_name_bytes: int | None = None) -> tuple[str, ...]:
        """Enumerate held names, optionally bounding count and UTF-16 storage."""
        for limit in (max_entries, max_name_bytes):
            if limit is not None and (type(limit) is not int or limit < 0):
                raise ValueError("Directory inventory limits must be nonnegative integers")
        if not self.assert_supported_metadata(directory).directory:
            raise UnsafeWindowsPath("Enumeration requires a held directory")
        names: list[str] = []
        name_bytes = 0
        restart = 1
        while True:
            buffer = ctypes.create_string_buffer(64 * 1024)
            iosb = IO_STATUS_BLOCK()
            status = self.ntdll.NtQueryDirectoryFile(
                directory.value, None, None, None, ctypes.byref(iosb), buffer,
                len(buffer), FILE_NAMES_INFORMATION_CLASS, 0, None, restart)
            restart = 0
            if status & 0xffffffff == STATUS_NO_MORE_FILES:
                break
            self._check_nt(status, "NtQueryDirectoryFile(FileNamesInformation)")
            length = int(iosb.Information)
            if not 12 <= length <= len(buffer):
                raise UnsafeWindowsPath("Invalid directory enumeration length")
            offset = 0
            while True:
                if offset + 12 > length:
                    raise UnsafeWindowsPath("Truncated directory enumeration entry")
                next_offset, _index, name_length = struct.unpack_from('<III', buffer, offset)
                if (name_length == 0 or name_length % 2 or name_length > 510
                        or offset + 12 + name_length > length):
                    raise UnsafeWindowsPath("Invalid directory enumeration name")
                name = buffer.raw[offset + 12:offset + 12 + name_length].decode('utf-16-le', 'strict')
                if name not in {'.', '..'}:
                    if (max_entries is not None and len(names) >= max_entries
                            or max_name_bytes is not None and name_bytes + name_length > max_name_bytes):
                        raise UnsafeWindowsPath("Held directory inventory exceeds its resource limit")
                    names.append(validate_component(name))
                    name_bytes += name_length
                if next_offset == 0:
                    break
                if next_offset % 4 or next_offset < 12 + name_length:
                    raise UnsafeWindowsPath("Invalid directory enumeration offset")
                offset += next_offset
        if len(names) != len({name.casefold() for name in names}):
            raise UnsafeWindowsPath("Aliased names in held directory")
        return tuple(sorted(names, key=str.casefold))


def _native_ops() -> _WindowsOps:
    if sys.platform != "win32" or os.name != "nt" or not hasattr(ctypes, "WinDLL"):
        raise RuntimeError("Native Windows handles require CPython on Windows")
    if sys.implementation.name != "cpython" or sys.version_info[:2] not in {(3, 11), (3, 12), (3, 13)}:
        raise RuntimeError("Native Windows handles require CPython 3.11, 3.12, or 3.13")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    prototypes = (
        (k32.CreateFileW, [HANDLE, DWORD, DWORD, HANDLE, DWORD, DWORD, HANDLE], HANDLE),
        (k32.CloseHandle, [HANDLE], ctypes.c_int),
        (k32.GetFileInformationByHandleEx, [HANDLE, ctypes.c_int, HANDLE, DWORD], ctypes.c_int),
        (k32.SetFileInformationByHandle, [HANDLE, ctypes.c_int, HANDLE, DWORD], ctypes.c_int),
        (k32.FlushFileBuffers, [HANDLE], ctypes.c_int),
        (k32.LockFileEx, [HANDLE, DWORD, DWORD, DWORD, DWORD, HANDLE], ctypes.c_int),
        (k32.UnlockFileEx, [HANDLE, DWORD, DWORD, DWORD, HANDLE], ctypes.c_int),
        (k32.SetFilePointerEx, [HANDLE, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), DWORD], ctypes.c_int),
        (k32.ReadFile, [HANDLE, HANDLE, DWORD, ctypes.POINTER(DWORD), HANDLE], ctypes.c_int),
        (k32.WriteFile, [HANDLE, HANDLE, DWORD, ctypes.POINTER(DWORD), HANDLE], ctypes.c_int),
        (k32.SetEndOfFile, [HANDLE], ctypes.c_int),
        (k32.LocalFree, [HANDLE], HANDLE),
        (k32.GetCurrentProcess, [], HANDLE),
        (ntdll.NtCreateFile, [ctypes.POINTER(HANDLE), DWORD, ctypes.POINTER(OBJECT_ATTRIBUTES),
                             ctypes.POINTER(IO_STATUS_BLOCK), HANDLE, DWORD, DWORD, DWORD, DWORD,
                             HANDLE, DWORD], ctypes.c_int32),
        (ntdll.NtSetInformationFile, [HANDLE, ctypes.POINTER(IO_STATUS_BLOCK),
                                      HANDLE, DWORD, ctypes.c_int], ctypes.c_int32),
        (ntdll.RtlNtStatusToDosError, [DWORD], DWORD),
        (ntdll.NtQueryInformationFile, [HANDLE, ctypes.POINTER(IO_STATUS_BLOCK),
                                        HANDLE, DWORD, ctypes.c_int], ctypes.c_int32),
        (ntdll.NtSetSecurityObject, [HANDLE, DWORD, HANDLE], ctypes.c_int32),
        (ntdll.NtQueryDirectoryFile, [HANDLE, HANDLE, HANDLE, HANDLE,
                                     ctypes.POINTER(IO_STATUS_BLOCK), HANDLE, DWORD,
                                     ctypes.c_int, BOOLEAN, HANDLE, BOOLEAN], ctypes.c_int32),
        (advapi.GetSecurityInfo, [HANDLE, ctypes.c_int, DWORD, ctypes.POINTER(HANDLE),
                                  ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE),
                                  ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE)], DWORD),
        (advapi.GetSecurityDescriptorControl, [HANDLE, ctypes.POINTER(USHORT),
                                                ctypes.POINTER(DWORD)], ctypes.c_int),
        (advapi.IsValidSid, [HANDLE], ctypes.c_int),
        (advapi.IsValidAcl, [HANDLE], ctypes.c_int),
        (advapi.GetLengthSid, [HANDLE], DWORD),
        (advapi.GetSecurityDescriptorLength, [HANDLE], DWORD),
        (advapi.SetSecurityInfo, [HANDLE, ctypes.c_int, DWORD, HANDLE, HANDLE,
                                  HANDLE, HANDLE], DWORD),
        (advapi.OpenProcessToken, [HANDLE, DWORD, ctypes.POINTER(HANDLE)], ctypes.c_int),
        (advapi.GetTokenInformation, [HANDLE, ctypes.c_int, HANDLE, DWORD,
                                      ctypes.POINTER(DWORD)], ctypes.c_int),
        (advapi.ConvertSidToStringSidW, [HANDLE, ctypes.POINTER(HANDLE)], ctypes.c_int),
        (advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW,
         [HANDLE, DWORD, ctypes.POINTER(HANDLE), ctypes.POINTER(DWORD)], ctypes.c_int),
        (advapi.GetSecurityDescriptorDacl,
         [HANDLE, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(HANDLE),
          ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
    )
    for function, args, result in prototypes:
        function.argtypes = args
        function.restype = result
    return _WindowsOps(k32, ntdll, last_error=ctypes.get_last_error, advapi=advapi)


class WindowsHandles:
    """Public native entrypoint. Keep instances and held handles within one run."""

    def __init__(self) -> None:
        self._ops = _native_ops()

    def private_security(self) -> SecurityParts:
        """Observe the exact protected current-user-only creation policy."""
        return self._ops._private_security()

    def list_children(self, directory: HeldHandle, *, max_entries: int | None = None,
                      max_name_bytes: int | None = None) -> tuple[str, ...]:
        if max_entries is None and max_name_bytes is None:
            return self._ops.list_children(directory)
        return self._ops.list_children(directory, max_entries=max_entries,
                                       max_name_bytes=max_name_bytes)

    def open_root(self, path: str | os.PathLike[str], *, for_publish: bool = False) -> HeldHandle:
        return self._ops.open_root(path, for_publish=for_publish)

    def open_child(self, parent: HeldHandle, name: str, *, kind: str,
                   for_rename: bool = False, create: bool = False,
                   for_lock: bool = False, for_write: bool = False,
                   for_publish: bool = False, for_delete: bool = False,
                   for_security_copy: bool = False,
                   for_metadata_restore: bool = False,
                   pin_for_read: bool = False) -> HeldHandle:
        return self._ops.open_child(parent, name, kind=kind, for_rename=for_rename,
                                    create=create, for_lock=for_lock, for_write=for_write,
                                    for_publish=for_publish, for_delete=for_delete,
                                    for_security_copy=for_security_copy,
                                    for_metadata_restore=for_metadata_restore,
                                    pin_for_read=pin_for_read)

    def restore_rename_metadata(self, handle: HeldHandle, *, creation_time: int,
                                attributes: int) -> None:
        self._ops.restore_rename_metadata(handle, creation_time=creation_time,
                                          attributes=attributes)

    def rename_no_replace(self, source: HeldHandle, destination_parent: HeldHandle,
                          destination_name: str) -> None:
        self._ops.rename_no_replace(source, destination_parent, destination_name)

    def replace_report(self, source: HeldHandle, destination_parent: HeldHandle,
                       destination_name: str) -> None:
        self._ops.replace_report(source, destination_parent, destination_name)

    def replace_private_checkpoint(self, source: HeldHandle, parent: HeldHandle) -> None:
        self._ops.replace_private_checkpoint(source, parent)

    def copy_report_security(self, source: HeldHandle, destination: HeldHandle) -> None:
        self._ops.copy_report_security(source, destination)

    def copy_staged_file_security(self, source: HeldHandle, destination: HeldHandle) -> None:
        self._ops.copy_staged_file_security(source, destination)

    def create_report_child(self, parent: HeldHandle, name: str, *, kind: str) -> HeldHandle:
        return self._ops.create_report_child(parent, name, kind=kind)

    def copy_protected_security(self, source: HeldHandle, destination: HeldHandle) -> None:
        self._ops.copy_protected_security(source, destination)

    def copy_supported_file_attributes(self, source: HeldHandle, destination: HeldHandle,
                                       *, expected_attributes: int) -> None:
        self._ops.copy_supported_file_attributes(source, destination,
                                                 expected_attributes=expected_attributes)

    def create_directory_from_template(self, parent: HeldHandle, name: str,
                                       template: HeldHandle) -> HeldHandle:
        return self._ops.create_directory_from_template(parent, name, template)

    def create_file_from_template(self, parent: HeldHandle, name: str,
                                  template: HeldHandle) -> HeldHandle:
        return self._ops.create_file_from_template(parent, name, template)

    def create_private_directory(self, parent: HeldHandle, name: str) -> HeldHandle:
        return self._ops.create_private(parent, name, kind="directory")

    def create_private_file(self, parent: HeldHandle, name: str) -> HeldHandle:
        return self._ops.create_private(parent, name, kind="file")

    def delete_exact(self, parent: HeldHandle, name: str, target: HeldHandle) -> None:
        self._ops.delete_exact(parent, name, target)
