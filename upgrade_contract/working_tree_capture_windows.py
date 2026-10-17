"""Bounded read-only Windows working-tree capture; no local lifecycle authority.

Pins directories, hashes selected leaves twice, and reopens every observed name.
This detects observed changes during capture; it is not an atomic snapshot or a
substitute for native revalidation during a later plan/publication window.
"""

from __future__ import annotations

import hashlib
from contextlib import ExitStack
from typing import Any

from .local_binding import (
    CONTROL_DIRECTORIES,
    _native_chain,
    absent_witness,
    project_windows_witness,
)
from .working_tree_capture import (
    MAX_DIRECTORY_ENTRIES,
    MAX_DIRECTORY_NAME_BYTES,
    MAX_LEAF_BYTES,
    MAX_READ_BYTES,
    WorkingTreeCapture,
    WorkingTreeCaptureError,
    ancestor_paths,
    build_capture,
    managed_paths,
)
from .windows_handles import MAX_IO_CHUNK, WindowsHandleError, WindowsHandles
from .windows_observation import _parts

# Includes one transient reopened directory/file in addition to the pinned set.
MAX_HELD_HANDLES = 4096
_MISSING = 0xC0000034


def _fail(message: str) -> None:
    raise WorkingTreeCaptureError(message)


def _missing(exc: WindowsHandleError) -> bool:
    return exc.operation == "NtCreateFile" and exc.ntstatus == _MISSING


class _Capture:
    def __init__(self, handles: Any, root: str, stack: ExitStack):
        self.handles, self.stack, self.root = handles, stack, root
        self.drive, parts = _parts(root)
        self.project = parts
        self.directories: dict[tuple[str, ...], Any] = {}
        self.baselines: dict[tuple[str, ...], tuple[Any, dict[str, Any]]] = {}
        self.absent_directories: set[tuple[str, ...]] = set()
        self.names: dict[tuple[str, ...], dict[str, str]] = {}
        self.checked: dict[tuple[str, ...], dict[str, bool]] = {}
        self.enumerated_entries = self.enumerated_name_bytes = 0
        self.initial_bytes = self.final_bytes = 0
        self.files: dict[str, tuple[tuple[str, ...], Any, dict[str, Any], str]] = {}
        self._room()
        self._pin((), handles.open_root(self.drive))
        for index, name in enumerate(parts):
            parent = parts[:index]
            self._room()
            self._pin(
                parts[: index + 1],
                handles.open_child(
                    self.directories[parent],
                    name,
                    kind="directory",
                    pin_for_read=True,
                ),
            )

    def _room(self) -> None:
        if len(self.directories) + 1 >= MAX_HELD_HANDLES:
            _fail("Windows capture handle budget exceeded")

    @staticmethod
    def _observe(handle: Any, *, directory: bool) -> tuple[Any, dict[str, Any]]:
        info = handle.info()
        if info.directory is not directory:
            _fail("Windows capture object has wrong kind")
        # Opens use the native supported-metadata guard (reparse, EAs, streams,
        # link count); projection independently validates identity/protections.
        return info, project_windows_witness(info, handle.security())

    def _pin(self, key: tuple[str, ...], handle: Any) -> None:
        held = self.stack.enter_context(handle)
        self.baselines[key] = self._observe(held, directory=True)
        self.directories[key] = held

    def _names(self, parent: tuple[str, ...]) -> dict[str, str]:
        entries_left = MAX_DIRECTORY_ENTRIES - self.enumerated_entries
        bytes_left = MAX_DIRECTORY_NAME_BYTES - self.enumerated_name_bytes
        names = self.handles.list_children(
            self.directories[parent],
            max_entries=entries_left,
            max_name_bytes=bytes_left,
        )
        if type(names) is not tuple or len(names) > entries_left:
            _fail("Windows capture directory entry budget exceeded")
        folded: set[str] = set()
        for name in names:
            if type(name) is not str or not name or "/" in name or "\\" in name:
                _fail("Invalid Windows directory enumeration")
            # Bound encoding even with injected enumeration implementations.
            if len(name) > bytes_left // 2:
                _fail("Windows capture directory name budget exceeded")
            size = len(name.encode("utf-16-le"))
            if size > bytes_left or name.casefold() in folded:
                _fail("Windows capture directory aliases or name budget exceeded")
            bytes_left -= size
            folded.add(name.casefold())
        self.enumerated_entries += len(names)
        self.enumerated_name_bytes = MAX_DIRECTORY_NAME_BYTES - bytes_left
        return {name.casefold(): name for name in names}

    @staticmethod
    def _present(names: dict[str, str], name: str) -> bool:
        actual = names.get(name.casefold())
        if actual is not None and actual != name:
            _fail("Windows capture path has nonexact spelling")
        return actual is not None

    def _check_name(self, parent: tuple[str, ...], name: str) -> bool:
        if parent not in self.names:
            self.names[parent] = self._names(parent)
        present = self._present(self.names[parent], name)
        self.checked.setdefault(parent, {})[name] = present
        return present

    def _verify_absent(self, parent: tuple[str, ...], name: str, *, kind: str) -> None:
        try:
            opened = self.handles.open_child(
                self.directories[parent],
                name,
                kind=kind,
                pin_for_read=True,
            )
        except WindowsHandleError as exc:
            if _missing(exc):
                return
            raise
        with opened:
            _fail("Windows capture absent path appeared")

    def directory(self, relative: str) -> tuple[str, ...] | None:
        key = self.project
        for name in relative.split("/"):
            parent, key = key, key + (name,)
            if key in self.directories:
                continue
            if key in self.absent_directories or parent in self.absent_directories:
                self.absent_directories.add(key)
                continue
            if not self._check_name(parent, name):
                self._verify_absent(parent, name, kind="directory")
                self.absent_directories.add(key)
                continue
            self._room()
            self._pin(
                key,
                self.handles.open_child(
                    self.directories[parent],
                    name,
                    kind="directory",
                    pin_for_read=True,
                ),
            )
        return key if key in self.directories else None

    def _read(
        self, parent: tuple[str, ...], name: str, *, final: bool
    ) -> tuple[Any, dict[str, Any], str]:
        with self.handles.open_child(
            self.directories[parent],
            name,
            kind="file",
            pin_for_read=True,
        ) as leaf:
            before, witness = self._observe(leaf, directory=False)
            used = self.final_bytes if final else self.initial_bytes
            if before.size > MAX_LEAF_BYTES or before.size > MAX_READ_BYTES - used:
                _fail("Windows capture file read budget exceeded")
            if leaf.seek(0) != 0:
                _fail("Windows capture file seek failed")
            digest = hashlib.sha256()
            remaining = before.size
            while remaining:
                requested = min(remaining, MAX_IO_CHUNK)
                data = leaf.read(requested)
                if type(data) is not bytes or not 0 < len(data) <= requested:
                    _fail("Windows capture premature EOF or invalid read")
                digest.update(data)
                remaining -= len(data)
            if leaf.read(1) != b"":
                _fail("Windows capture file grew")
            if self._observe(leaf, directory=False) != (before, witness):
                _fail("Windows capture file changed while reading")
            if final:
                self.final_bytes += before.size
            else:
                self.initial_bytes += before.size
            return before, witness, digest.hexdigest()

    def leaf(self, relative: str) -> dict[str, Any]:
        parts = relative.split("/")
        parent = (
            self.directory("/".join(parts[:-1])) if len(parts) > 1 else self.project
        )
        if parent is not None and self._check_name(parent, parts[-1]):
            info, witness, digest = self._read(parent, parts[-1], final=False)
            self.files[relative] = parent, info, witness, digest
            return {
                "path": relative,
                "metadata": witness,
                "content": {"sha256": digest, "size_decimal": str(info.size)},
            }
        if parent is not None:
            self._verify_absent(parent, parts[-1], kind="file")
        return {
            "path": relative,
            "metadata": absent_witness("Windows", "file"),
            "content": None,
        }

    def directory_witness(self, relative: str) -> dict[str, Any]:
        key = self.directory(relative)
        return (
            self.baselines[key][1]
            if key is not None
            else absent_witness("Windows", "directory")
        )

    def _revalidate_directories(self) -> None:
        for key, held in self.directories.items():
            expected = self.baselines[key]
            if self._observe(held, directory=True) != expected:
                _fail("Windows capture held directory changed")
            opened = (
                self.handles.open_child(
                    self.directories[key[:-1]],
                    key[-1],
                    kind="directory",
                    pin_for_read=True,
                )
                if key
                else self.handles.open_root(self.drive)
            )
            with opened:
                if self._observe(opened, directory=True) != expected:
                    _fail("Windows capture directory namespace changed")

    def revalidate(self) -> None:
        self._revalidate_directories()
        for relative, (parent, info, witness, digest) in self.files.items():
            if self._read(parent, relative.split("/")[-1], final=True) != (
                info,
                witness,
                digest,
            ):
                _fail("Windows capture leaf changed before return")
        for parent, checks in self.checked.items():
            names = self._names(parent)
            for name, expected_present in checks.items():
                if self._present(names, name) != expected_present:
                    _fail("Windows capture presence or spelling changed")
                if not expected_present:
                    # An absent selected file or directory must still be absent;
                    # native wrong-kind errors also refuse newly appeared files.
                    self._verify_absent(parent, name, kind="directory")
        self._revalidate_directories()


def _initial_capture(
    reader: _Capture, project_root: str, selected: tuple[str, ...],
    ancestors: tuple[str, ...],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Observe selected witnesses while the caller keeps pinned handles live."""
    root_paths = _native_chain(project_root, "Windows")
    native = {
        "platform": "Windows",
        "root_path": project_root,
        "root_chain": [
            {
                "path": path,
                "witness": reader.baselines[reader.project[:index]][1],
            }
            for index, path in enumerate(root_paths)
        ],
        "managed_ancestors": [
            {"path": path, "witness": reader.directory_witness(path)}
            for path in ancestors
        ],
        "control_directories": [
            {"path": path, "witness": reader.directory_witness(path)}
            for path in CONTROL_DIRECTORIES
        ],
    }
    leaves = [reader.leaf(path) for path in selected]
    return native, leaves


def capture_working_tree(
    project_root: str, paths: tuple[str, ...], *, handles: Any = None
) -> WorkingTreeCapture:
    """Capture selected filesystem evidence only, without journal/binding claims."""
    selected = managed_paths(
        paths
    )  # Always precedes constructing/calling native handles.
    try:
        ancestors = ancestor_paths(selected)
        active = WindowsHandles() if handles is None else handles
        with ExitStack() as stack:
            reader = _Capture(active, project_root, stack)
            native, leaves = _initial_capture(reader, project_root, selected, ancestors)
            reader.revalidate()
            return build_capture(native, leaves)
    except WorkingTreeCaptureError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        AttributeError,
        OverflowError,
    ) as exc:
        raise WorkingTreeCaptureError(
            f"Windows working-tree capture refused: {exc}"
        ) from exc
