"""Native private storage primitives for repository-intelligence integration.

This component does not enroll an RI scope, authorize activation or implement
RIT recovery. Callers must journal ownership before using destructive methods.
All child operations are relative to held, no-reparse directory handles. The
failure model is application-process interruption, not power-loss durability.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import ntpath
import re
import struct
from typing import Any, Iterator

from .windows_handles import WindowsHandles, WindowsHandleError, validate_component, validate_root_path

IDENTITY_SCHEMA = 'naos.repository_intelligence.windows_object_identity.v1'
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096


class RIStorageConflict(ValueError):
    """Native identity, private policy or expected content no longer matches."""


def _relative(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or '\\' in value:
        raise RIStorageConflict('Storage paths must be nonempty relative POSIX paths')
    return tuple(validate_component(part) for part in value.split('/'))


def _security_digest(security: Any) -> str:
    digest = hashlib.sha256(b'naos.ri.private-security.v1\0')
    digest.update(bytes([bool(security.protected)]))
    for field in (security.owner_sid, security.group_sid, security.dacl):
        digest.update(struct.pack('<I', len(field)))
        digest.update(field)
    return digest.hexdigest()


@dataclass(frozen=True)
class NativeIdentity:
    """A Windows object witness, deliberately distinct from POSIX inode fields.

    Directory timestamps change as owned children are added or removed. Content
    and child-inventory expectations are separate from this stable object ID.
    """
    volume_serial_hex: str
    file_id_hex: str
    kind: str
    security_sha256: str

    def record(self) -> dict[str, str]:
        result = {'schema': IDENTITY_SCHEMA, 'volume_serial_hex': self.volume_serial_hex,
                  'file_id_hex': self.file_id_hex, 'kind': self.kind,
                  'security_sha256': self.security_sha256}
        self.from_record(result)
        return result

    @classmethod
    def from_record(cls, value: Any) -> NativeIdentity:
        if not isinstance(value, dict) or set(value) != {
                'schema', 'volume_serial_hex', 'file_id_hex', 'kind', 'security_sha256'}:
            raise RIStorageConflict('Malformed Windows RI identity')
        if (value['schema'] != IDENTITY_SCHEMA or not isinstance(value['kind'], str)
                or value['kind'] not in {'file', 'directory'}):
            raise RIStorageConflict('Wrong Windows RI identity contract')
        for key, width in [('volume_serial_hex', 16), ('file_id_hex', 32), ('security_sha256', 64)]:
            if not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{'+str(width)+'}', value[key]):
                raise RIStorageConflict('Malformed Windows RI identity encoding')
        return cls(value['volume_serial_hex'], value['file_id_hex'], value['kind'], value['security_sha256'])


class WindowsRIStorage:
    """Pin a project root and operate only on private descendants.

    The project root may have adopter-owned ACLs; every traversed descendant
    must have the exact current-user private policy. No implicit directory
    creation, adoption of existing files or overwrite fallback is permitted.
    """
    def __init__(self, project_root: str, *, handles: Any = None):
        self.handles = handles if handles is not None else WindowsHandles()
        absolute = validate_root_path(project_root)
        self.project_root = absolute
        drive, tail = ntpath.splitdrive(absolute)
        parts = tuple(validate_component(p) for p in tail.split('\\') if p)
        if not parts:
            raise RIStorageConflict('A drive root cannot be an RI project root')
        self._stack = ExitStack()
        self._closed = False
        try:
            self._private_security = _security_digest(self.handles.private_security())
            current = self._stack.enter_context(self.handles.open_root(drive+'\\'))
            for index, part in enumerate(parts):
                final = index == len(parts)-1
                current = self._stack.enter_context(self.handles.open_child(
                    current, part, kind='directory', for_publish=final, pin_for_read=not final))
            self.root = current
            self.root_identity = current.info().identity
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stack.close()

    def __enter__(self) -> WindowsRIStorage:
        if self._closed:
            raise RIStorageConflict('Closed RI storage')
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def _identity(self, handle: Any) -> NativeIdentity:
        info = handle.info()
        security = handle.security()
        digest = _security_digest(security)
        if not security.protected or digest != self._private_security:
            raise RIStorageConflict('RI object does not have the exact private security policy')
        if info.reparse_tag or (not info.directory and info.links != 1):
            raise RIStorageConflict('RI object is a reparse point or multiply linked file')
        result = NativeIdentity(f'{info.volume:016x}', info.file_id.hex(),
                                'directory' if info.directory else 'file', digest)
        result.record()
        return result

    def _expect(self, handle: Any, expected: NativeIdentity) -> None:
        if not isinstance(expected, NativeIdentity):
            raise RIStorageConflict('A native Windows RI identity is required')
        expected.record()
        if self._identity(handle) != expected:
            raise RIStorageConflict('RI native object identity changed; preserve the current object')

    @contextmanager
    def _parent(self, relative: str) -> Iterator[tuple[Any, str]]:
        parts = _relative(relative)
        if self._closed or self.root.info().identity != self.root_identity:
            raise RIStorageConflict('RI project root is closed or changed')
        with ExitStack() as stack:
            parent = self.root
            for part in parts[:-1]:
                parent = stack.enter_context(self.handles.open_child(
                    parent, part, kind='directory', for_publish=True))
                self._identity(parent)
            yield parent, parts[-1]

    def create_directory(self, relative: str) -> NativeIdentity:
        with self._parent(relative) as (parent, name):
            with self.handles.create_private_directory(parent, name) as child:
                return self._identity(child)

    def write_new(self, relative: str, data: bytes) -> NativeIdentity:
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise RIStorageConflict('RI file payload is invalid or exceeds the bound')
        with self._parent(relative) as (parent, name):
            with self.handles.create_private_file(parent, name) as child:
                identity = self._identity(child)
                child.write_all(data)
                child.flush()
                self._expect(child, identity)
                return identity

    def _read(self, child: Any, limit: int) -> tuple[bytes, NativeIdentity]:
        if type(limit) is not int or not 0 <= limit <= MAX_FILE_BYTES:
            raise RIStorageConflict('Invalid RI read bound')
        identity = self._identity(child)
        before = child.info()
        if before.directory or before.size < 0 or before.size > limit:
            raise RIStorageConflict('RI file exceeds its read bound')
        child.seek(0)
        pieces = []
        remaining = before.size + 1
        while remaining:
            block = child.read(min(remaining, 64 * 1024))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
        data = b''.join(pieces)
        if len(data) != before.size or child.info() != before or self._identity(child) != identity:
            raise RIStorageConflict('RI file changed while reading')
        return data, identity

    def read_file(self, relative: str, *, limit: int = MAX_FILE_BYTES) -> tuple[bytes, NativeIdentity]:
        with self._parent(relative) as (parent, name):
            with self.handles.open_child(parent, name, kind='file', pin_for_read=True) as child:
                return self._read(child, limit)

    def directory_identity(self, relative: str) -> NativeIdentity:
        with self._parent(relative) as (parent, name):
            with self.handles.open_child(parent, name, kind='directory', pin_for_read=True) as child:
                return self._identity(child)

    @property
    def private_security_sha256(self) -> str:
        return self._private_security

    def identity_if_present(self, relative: str, *, kind: str) -> NativeIdentity | None:
        """Only native missing-name results mean absence; unsafe paths refuse."""
        if kind not in {'file', 'directory'}:
            raise RIStorageConflict('Invalid RI object kind')
        try:
            with self._parent(relative) as (parent, name):
                with self.handles.open_child(parent, name, kind=kind, pin_for_read=True) as child:
                    return self._identity(child)
        except WindowsHandleError as exc:
            if exc.operation == 'NtCreateFile' and exc.ntstatus == 0xC0000034:
                return None
            raise

    @contextmanager
    def pin_directories(self, expected: dict[str, NativeIdentity]) -> Iterator[None]:
        """Deny ancestor replacement throughout an identity-bound operation."""
        with ExitStack() as stack:
            for relative, identity in expected.items():
                parent, name = stack.enter_context(self._parent(relative))
                child = stack.enter_context(self.handles.open_child(
                    parent, name, kind='directory', pin_for_read=True))
                self._expect(child, identity)
            yield

    @contextmanager
    def pin_files(self, expected_sha256: dict[str, str]) -> Iterator[None]:
        """Validate private leaf bytes and deny writes/deletion until exit."""
        with ExitStack() as stack:
            for relative, digest in expected_sha256.items():
                if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                    raise RIStorageConflict('Invalid pinned RI file digest')
                parent, name = stack.enter_context(self._parent(relative))
                child = stack.enter_context(self.handles.open_child(
                    parent, name, kind='file', pin_for_read=True))
                data, _identity = self._read(child, MAX_FILE_BYTES)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise RIStorageConflict('Pinned RI bundle content changed')
            yield

    def children(self, relative: str) -> tuple[str, ...]:
        with self._parent(relative) as (parent, name):
            with self.handles.open_child(parent, name, kind='directory', pin_for_read=True) as child:
                self._identity(child)
                return self.handles.list_children(child, max_entries=MAX_DIRECTORY_ENTRIES,
                                                  max_name_bytes=MAX_DIRECTORY_ENTRIES * 510)

    def publish_no_replace(self, source: str, destination: str, expected: NativeIdentity,
                           *, content_sha256: str | None = None) -> NativeIdentity:
        if not isinstance(expected, NativeIdentity):
            raise RIStorageConflict('Native identity required before publication')
        expected.record()
        if expected.kind == 'file' and (not isinstance(content_sha256, str)
                or not re.fullmatch('[0-9a-f]{64}', content_sha256)):
            raise RIStorageConflict('File publication requires expected content digest')
        if expected.kind == 'directory' and content_sha256 is not None:
            raise RIStorageConflict('Directory publication requires separate caller inventory validation')
        with self._parent(source) as (src_parent, src_name), self._parent(destination) as (dst_parent, dst_name):
            # Windows permits a no-replace rename to the same object (including
            # case-only aliases). That is not publication into an absent slot.
            # Only an exact native missing-leaf result establishes absence.
            try:
                with self.handles.open_child(dst_parent, dst_name, kind=expected.kind):
                    raise RIStorageConflict('RI publication destination already exists')
            except WindowsHandleError as exc:
                if exc.operation != 'NtCreateFile' or exc.ntstatus != 0xC0000034:
                    raise
            with self.handles.open_child(src_parent, src_name, kind=expected.kind, for_rename=True) as child:
                self._expect(child, expected)
                if expected.kind == 'file':
                    data, _ = self._read(child, MAX_FILE_BYTES)
                    if hashlib.sha256(data).hexdigest() != content_sha256:
                        raise RIStorageConflict('RI publication content changed; preserve source')
                if dst_parent.info().volume != child.info().volume:
                    raise RIStorageConflict('RI publication cannot cross volumes')
                self.handles.rename_no_replace(child, dst_parent, dst_name)
                self._expect(child, expected)
        return expected

    def remove_file(self, relative: str, expected: NativeIdentity, *, content_sha256: str) -> None:
        if not isinstance(content_sha256, str) or not re.fullmatch('[0-9a-f]{64}', content_sha256):
            raise RIStorageConflict('Cleanup requires the exact expected content digest')
        with self._parent(relative) as (parent, name):
            with self.handles.open_child(parent, name, kind='file', for_delete=True) as child:
                self._expect(child, expected)
                data, _ = self._read(child, MAX_FILE_BYTES)
                if hashlib.sha256(data).hexdigest() != content_sha256:
                    raise RIStorageConflict('RI cleanup content changed; preserve the file')
                self.handles.delete_exact(parent, name, child)

    def remove_empty_directory(self, relative: str, expected: NativeIdentity) -> None:
        with self._parent(relative) as (parent, name):
            with self.handles.open_child(parent, name, kind='directory', for_delete=True) as child:
                self._expect(child, expected)
                if self.handles.list_children(child, max_entries=MAX_DIRECTORY_ENTRIES,
                                               max_name_bytes=MAX_DIRECTORY_ENTRIES * 510):
                    raise RIStorageConflict('RI cleanup directory is not empty; preserve its contents')
                self.handles.delete_exact(parent, name, child)

    @contextmanager
    def lock(self, relative: str, expected: NativeIdentity) -> Iterator[Any]:
        """Lock an explicitly created, identity-bound file; never create on read."""
        with self._parent(relative) as (parent, name):
            with self.handles.open_child(parent, name, kind='file', for_lock=True) as child:
                self._expect(child, expected)
                child.lock_exclusive(nonblocking=True)
                try:
                    yield child
                finally:
                    child.unlock()
