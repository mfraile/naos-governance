"""Read-only Windows held-handle adapter for portable provenance replay.

Directory ancestors remain pinned throughout replay. File handles are closed
after bounded reads and every dependency is reopened for a final consistency
pass. This detects substitutions observed during the call, but is not an atomic
snapshot of all files at one instant and confers no ownership or write rights.
"""

from __future__ import annotations

import hashlib
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

from .portable_provenance import (
    MAX_CUMULATIVE_READ_BYTES,
    PortableProvenanceError,
    ValidatedPortableSnapshot,
    control_path_limit,
    load_portable_snapshot,
)
from .windows_handles import (
    MAX_IO_CHUNK,
    SUPPORTED_DIRECTORY_ATTRIBUTES,
    SUPPORTED_FILE_ATTRIBUTES,
    UnsafeWindowsPath,
    WindowsHandleError,
    WindowsHandles,
)
from .windows_observation import _parts


MAX_ROOT_COMPONENTS = 128
MAX_DEPENDENCIES = 100_000
MAX_DIRECTORY_ENTRIES = 20_000
MAX_ENUMERATED_ENTRIES = 100_000
MAX_ENUMERATED_NAME_BYTES = 16 * 1024 * 1024
_MISSING = 0xC0000034


def _refuse(message: str) -> None:
    raise PortableProvenanceError(message)


def _security_identity(handle: Any) -> tuple[bytes, bytes, bytes, bool, bytes]:
    """Retain compact exact-value digests, not up to 128 KiB per descriptor."""
    security = handle.security()
    return (
        hashlib.sha256(security.owner_sid).digest(),
        hashlib.sha256(security.group_sid).digest(),
        hashlib.sha256(security.dacl).digest(),
        bool(security.protected),
        hashlib.sha256(security.descriptor).digest(),
    )


def _info(handle: Any, *, directory: bool) -> Any:
    info = handle.info()
    allowed = SUPPORTED_DIRECTORY_ATTRIBUTES if directory else SUPPORTED_FILE_ATTRIBUTES
    if (
        info.directory is not directory
        or info.attributes & ~allowed
        or info.reparse_tag
        or (not directory and (info.links != 1 or info.size < 0))
    ):
        _refuse("Unsupported portable control object metadata")
    return info


@dataclass(frozen=True)
class _Observation:
    parent: tuple[str, ...]
    name: str
    info: Any
    security: tuple[bytes, bytes, bytes, bool, bytes]
    sha256: bytes


class _HeldReader:
    def __init__(self, handles: Any, project_root: str, stack: ExitStack):
        drive, root_parts = _parts(project_root)
        if len(root_parts) > MAX_ROOT_COMPONENTS:
            _refuse("Portable project root has too many ancestors")
        self.handles = handles
        self.project_root = project_root
        self.stack = stack
        self.directories: dict[tuple[str, ...], Any] = {}
        self.directory_baselines: dict[tuple[str, ...], tuple[Any, tuple[bytes, bytes, bytes, bool, bytes]]] = {}
        self.directory_names: dict[tuple[str, ...], frozenset[str]] = {}
        self.checked_names: dict[tuple[str, ...], set[str]] = {}
        self.enumerated_entries = 0
        self.enumerated_name_bytes = 0
        self.dependencies: dict[str, _Observation] = {}
        self.read_bytes = 0
        self.final_bytes = 0

        root = stack.enter_context(handles.open_root(drive))
        self.directories[()] = root
        self.directory_baselines[()] = (_info(root, directory=True), _security_identity(root))
        parent: tuple[str, ...] = ()
        for component in root_parts:
            parent = self._directory(parent, component)
        self.project_parts = parent

    def _names(self, parent: tuple[str, ...]) -> frozenset[str]:
        names = self.handles.list_children(
            self.directories[parent],
            max_entries=min(MAX_DIRECTORY_ENTRIES, MAX_ENUMERATED_ENTRIES - self.enumerated_entries),
            max_name_bytes=MAX_ENUMERATED_NAME_BYTES - self.enumerated_name_bytes,
        )
        name_bytes = sum(len(name.encode("utf-16-le")) for name in names if isinstance(name, str))
        if (
            not isinstance(names, tuple)
            or len(names) > MAX_DIRECTORY_ENTRIES
            or len(names) > MAX_ENUMERATED_ENTRIES - self.enumerated_entries
            or name_bytes > MAX_ENUMERATED_NAME_BYTES - self.enumerated_name_bytes
            or any(not isinstance(name, str) for name in names)
            or len({name.casefold() for name in names}) != len(names)
        ):
            _refuse("Unsupported portable control directory enumeration")
        self.enumerated_entries += len(names)
        self.enumerated_name_bytes += name_bytes
        return frozenset(names)

    def _check_spelling(self, parent: tuple[str, ...], name: str) -> None:
        if parent not in self.directory_names:
            self.directory_names[parent] = self._names(parent)
        if name not in self.directory_names[parent]:
            _refuse("Portable control path spelling is absent")
        self.checked_names.setdefault(parent, set()).add(name)

    def _directory(self, parent: tuple[str, ...], name: str, *, exact: bool = False) -> tuple[str, ...]:
        key = parent + (name,)
        if exact:
            self._check_spelling(parent, name)
        if key not in self.directories:
            held = self.stack.enter_context(
                self.handles.open_child(self.directories[parent], name, kind="directory", pin_for_read=True)
            )
            self.directories[key] = held
            self.directory_baselines[key] = (_info(held, directory=True), _security_identity(held))
        return key

    def _parent(self, components: tuple[str, ...]) -> tuple[str, ...]:
        parent = self.project_parts
        for component in components[:-1]:
            parent = self._directory(parent, component, exact=True)
        return parent

    def _read_leaf(
        self, parent: tuple[str, ...], name: str, maximum: int, *, final: bool,
    ) -> tuple[Any, tuple[bytes, bytes, bytes, bool, bytes], bytes]:
        with self.handles.open_child(
            self.directories[parent], name, kind="file", pin_for_read=True
        ) as leaf:
            before = _info(leaf, directory=False)
            security = _security_identity(leaf)
            budget = self.final_bytes if final else self.read_bytes
            if before.size > maximum or before.size > MAX_CUMULATIVE_READ_BYTES - budget:
                _refuse("Portable control object exceeds native read budget")
            if leaf.seek(0) != 0:
                _refuse("Portable control object seek did not reach start")
            digest = hashlib.sha256()
            result = bytearray() if not final else None
            remaining = before.size
            while remaining:
                request = min(remaining, MAX_IO_CHUNK)
                block = leaf.read(request)
                if not isinstance(block, bytes) or not 0 < len(block) <= request:
                    _refuse("Portable control object read was short or invalid")
                digest.update(block)
                if result is not None:
                    result.extend(block)
                remaining -= len(block)
            if leaf.read(1) != b"":
                _refuse("Portable control object grew during read")
            if _info(leaf, directory=False) != before or _security_identity(leaf) != security:
                _refuse("Portable control object changed during read")
            if final:
                self.final_bytes += before.size
            else:
                self.read_bytes += before.size
            return before, security, digest.digest() if final else bytes(result)

    def read(self, relative: str) -> bytes | None:
        maximum = control_path_limit(relative)  # Exact slash whitelist before native conversion.
        if relative not in self.dependencies and len(self.dependencies) >= MAX_DEPENDENCIES:
            _refuse("Portable control dependency count exceeded")
        components = tuple(relative.split("/"))
        try:
            parent = self._parent(components)
            self._check_spelling(parent, components[-1])
            info, security, raw = self._read_leaf(parent, components[-1], maximum, final=False)
        except WindowsHandleError as exc:
            if exc.operation == "NtCreateFile" and exc.ntstatus == _MISSING:
                return None
            raise
        prior = self.dependencies.get(relative)
        digest = hashlib.sha256(raw).digest()
        if prior is not None and (prior.info != info or prior.security != security or prior.sha256 != digest):
            _refuse("Portable control dependency changed between reads")
        if prior is None:
            self.dependencies[relative] = _Observation(parent, components[-1], info, security, digest)
        return raw

    def _revalidate_directories(self) -> None:
        # Held directory pins remain live. Reopen each name through its held
        # parent as well, so a surviving old handle cannot mask namespace drift.
        for key, held in self.directories.items():
            baseline = self.directory_baselines[key]
            if (_info(held, directory=True), _security_identity(held)) != baseline:
                _refuse("Portable control ancestor changed during replay")
            if key:
                reopened = self.handles.open_child(
                    self.directories[key[:-1]], key[-1], kind="directory", pin_for_read=True
                )
            else:
                drive, _ = _parts(self.project_root)
                reopened = self.handles.open_root(drive)
            with reopened:
                if (_info(reopened, directory=True), _security_identity(reopened)) != baseline:
                    _refuse("Portable control ancestor namespace changed")

    def revalidate(self) -> None:
        self._revalidate_directories()
        for relative, prior in self.dependencies.items():
            maximum = control_path_limit(relative)
            info, security, digest = self._read_leaf(prior.parent, prior.name, maximum, final=True)
            if (info, security, digest) != (prior.info, prior.security, prior.sha256):
                _refuse("Portable control dependency changed before return")
        self._revalidate_directories()
        for parent, expected in self.checked_names.items():
            if not expected.issubset(self._names(parent)):
                _refuse("Portable control path spelling changed before return")


def read_portable_snapshot(project_root: str, *, handles: Any = None) -> ValidatedPortableSnapshot:
    """Validate portable history through read-only, no-follow Windows handles.

    Without injected handles this requires supported native CPython on Windows.
    The return is an internally consistent observation, not a simultaneous
    filesystem snapshot or approval of ownership, authorship, or mutation.
    """
    try:
        active_handles = WindowsHandles() if handles is None else handles
        with ExitStack() as stack:
            reader = _HeldReader(active_handles, project_root, stack)
            snapshot = load_portable_snapshot(reader)
            reader.revalidate()
            return snapshot
    except PortableProvenanceError:
        raise
    except (WindowsHandleError, UnsafeWindowsPath, OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        raise PortableProvenanceError(f"Windows portable read refused: {exc}") from exc
