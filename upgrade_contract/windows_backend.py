"""Held-handle Windows adapter for the recoverable three-slot exchange protocol.

This is a component, not an activated transaction backend: namespace crash
durability needs a documented, verified Windows filesystem-specific barrier.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import ntpath
import struct
from typing import Mapping, Any

from .windows_exchange import ExchangeConflict, LeafIdentity
from .windows_handles import (UnsafeWindowsPath, WindowsHandleError, WindowsHandles,
                              validate_component, validate_root_path)


_MISSING_LEAF = 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND, one relative component
_CHUNK = 1024 * 1024


class NamespaceDurabilityUnavailable(RuntimeError):
    """No documented, verified namespace flush primitive is configured."""


@dataclass(frozen=True)
class _Slot:
    parent: Any
    parent_identity: tuple[int, bytes]
    name: str


def _split_leaf(path: str) -> tuple[str, tuple[str, ...], str]:
    value = validate_root_path(path)
    drive, tail = ntpath.splitdrive(value)
    parts = tuple(validate_component(x) for x in tail.split("\\") if x)
    if not parts or tail.endswith("\\"):
        raise UnsafeWindowsPath("Exchange slot must name one file")
    return drive.upper() + "\\", parts[:-1], parts[-1]


def _metadata_digest(info: Any, security: Any) -> str:
    """Stable-across-rename metadata; ChangeTime is intentionally excluded.

    A rename may update Windows ChangeTime. Content, creation/last-write time,
    attributes, owner, group, protected DACL and exact DACL remain checked.
    """
    digest = hashlib.sha256(b"naos.windows.leaf.metadata.v1\0")
    digest.update(struct.pack("<qqI?", info.created_time, info.modified_time,
                              info.attributes, security.protected))
    for value in (security.owner_sid, security.group_sid, security.dacl):
        digest.update(struct.pack("<I", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _observe_pinned(handle: Any) -> LeafIdentity:
    before = handle.info()
    if before.directory or before.links != 1 or before.size < 0 or len(before.file_id) != 16:
        raise UnsafeWindowsPath("Exchange leaf must be one regular, single-link file")
    security_before = handle.security()
    handle.seek(0)
    content = hashlib.sha256()
    count = 0
    while True:
        block = handle.read(_CHUNK)
        if not block:
            break
        count += len(block)
        if count > before.size:
            raise ExchangeConflict("Exchange leaf grew during observation")
        content.update(block)
    after = handle.info()
    security_after = handle.security()
    if count != before.size or after != before or security_after != security_before:
        raise ExchangeConflict("Exchange leaf changed during observation")
    observed = LeafIdentity(before.volume, before.file_id, before.size,
                            content.hexdigest(), _metadata_digest(before, security_before))
    observed.validate()
    return observed


class WindowsExchangeBackend:
    """Own directory pins for opaque slot keys mapped to absolute file paths.

    The only path-based open is an ordinary drive root. All subsequent opens
    are one-component, no-follow opens relative to held parents. This object
    must live inside the coordinator's transaction lock and be closed after it.
    """

    def __init__(self, handles: Any, slot_paths: Mapping[str, str]):
        if not slot_paths or any(not isinstance(k, str) or not k for k in slot_paths):
            raise ValueError("Exchange requires nonempty slot keys")
        parsed = {key: _split_leaf(path) for key, path in slot_paths.items()}
        physical = list(parsed.values())
        if len(set(physical)) != len(physical):
            raise ValueError("Exchange slots resolve to duplicate names")
        self._handles = handles
        self._stack = ExitStack()
        self._closed = False
        self._slots: dict[str, _Slot] = {}
        try:
            # Cache exact spellings only. Unicode casefold is not filesystem
            # identity (e.g. Straße versus Strasse). If different spellings
            # address one object, native sharing checks may refuse the second
            # pin; they must never silently route it to another directory.
            parent_keys = {(root, parents)
                           for root, parents, _ in parsed.values()}
            directories: dict[tuple[str, tuple[str, ...]], Any] = {}
            for root, parents, _ in parsed.values():
                root_key = (root, ())
                if root_key not in directories:
                    directories[root_key] = self._stack.enter_context(handles.open_root(
                        root, for_publish=root_key in parent_keys))
                current = directories[root_key]
                prefix: tuple[str, ...] = ()
                for component in parents:
                    prefix += (component,)
                    key = (root, prefix)
                    if key not in directories:
                        directories[key] = self._stack.enter_context(handles.open_child(
                            current, component, kind="directory",
                            for_publish=key in parent_keys,
                            pin_for_read=key not in parent_keys))
                    current = directories[key]
            for key, (root, parents, leaf) in parsed.items():
                parent = directories[(root, parents)]
                info = parent.info()
                if not info.directory:
                    raise UnsafeWindowsPath("Exchange slot parent is not a directory")
                self._slots[key] = _Slot(parent, info.identity, leaf)
            if len({slot.parent_identity[0] for slot in self._slots.values()}) != 1:
                raise UnsafeWindowsPath("Exchange slot parents must be on one volume")
        except BaseException:
            self.close()
            raise

    @classmethod
    def native(cls, slot_paths: Mapping[str, str]) -> WindowsExchangeBackend:
        """Production constructor; WindowsHandles checks the actual runtime."""
        return cls(WindowsHandles(), slot_paths)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stack.close()

    def __enter__(self) -> WindowsExchangeBackend:
        if self._closed:
            raise ValueError("Closed Windows exchange backend")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _slot(self, key: str) -> _Slot:
        if self._closed:
            raise ValueError("Closed Windows exchange backend")
        try:
            slot = self._slots[key]
        except KeyError:
            raise ValueError("Unknown exchange slot key") from None
        info = slot.parent.info()
        if not info.directory or info.identity != slot.parent_identity:
            raise ExchangeConflict("Exchange parent identity changed")
        return slot

    def observe(self, slot: str) -> LeafIdentity | None:
        bound = self._slot(slot)
        try:
            opened = self._handles.open_child(bound.parent, bound.name,
                                              kind="file", pin_for_read=True)
        except WindowsHandleError as exc:
            if exc.operation == "NtCreateFile" and exc.ntstatus == _MISSING_LEAF:
                return None
            raise
        with opened:
            result = _observe_pinned(opened)
        self._slot(slot)
        return result

    def move_exact(self, source: str, destination: str, expected: LeafIdentity) -> None:
        expected.validate()
        if source == destination:
            raise ValueError("Source and destination slots must differ")
        source_slot, destination_slot = self._slot(source), self._slot(destination)
        if source_slot.parent_identity[0] != destination_slot.parent_identity[0]:
            raise ExchangeConflict("Cross-volume exchange is forbidden")
        if self.observe(destination) is not None:
            raise ExchangeConflict("Exchange destination already exists")
        with self._handles.open_child(source_slot.parent, source_slot.name,
                                      kind="file", for_rename=True) as held:
            actual = _observe_pinned(held)
            if actual != expected:
                raise ExchangeConflict("Exchange source identity does not match intent")
            self._slot(source)
            self._slot(destination)
            self._handles.rename_no_replace(held, destination_slot.parent,
                                            destination_slot.name)
        # The native no-replace rename is the collision arbiter. Any error above
        # remains visible; no destination is unlinked or overwritten.
        if self.observe(source) is not None or self.observe(destination) != expected:
            raise ExchangeConflict("Exchange move outcome is ambiguous; recover from journal")

    def preflight_durability(self) -> None:
        """Fail before intent or rename until a supported namespace barrier exists."""
        self._slot(next(iter(self._slots)))
        raise NamespaceDurabilityUnavailable(
            "No documented Windows directory namespace durability barrier is established; "
            "FlushFileBuffers on a file or volume is not proof of durable rename")

    def flush(self) -> None:
        """Never report durable progress without the same preflight guarantee."""
        self.preflight_durability()
