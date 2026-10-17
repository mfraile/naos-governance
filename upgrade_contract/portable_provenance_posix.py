"""Contained, read-only POSIX adapter for portable managed-content history.

This pins the project-root ancestry, opens each control component without
following links, and revalidates every read dependency before returning.
It is an inspection boundary, not a local binding or mutation authority.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .portable_provenance import (
    MAX_CUMULATIVE_READ_BYTES,
    PortableProvenanceError,
    ValidatedPortableSnapshot,
    control_path_limit,
    load_portable_snapshot,
)
from .security import (
    ContentPathError,
    _DescriptorMetadataChanged,
    observe_created_directory_metadata_fd,
    observe_created_file_metadata_fd,
)


MAX_ROOT_COMPONENTS = 64
MAX_DEPENDENCIES = 50000
MAX_DIRECTORY_NAMES = 100000
MAX_DIRECTORY_NAME_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024


class PortableProvenanceUnsupportedEnvironment(PortableProvenanceError):
    """The required POSIX no-follow or metadata primitives are unavailable."""


@dataclass(frozen=True)
class _Witness:
    stat_fields: tuple[int, ...]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class _Leaf:
    witness: _Witness
    sha256: str
    size: int


def _require_environment() -> None:
    if (os.name != "posix" or sys.platform not in {"darwin", "linux"}
            or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks
            or os.scandir not in os.supports_fd):
        raise PortableProvenanceUnsupportedEnvironment(
            "Portable POSIX inspection requires native no-follow dir_fd and metadata support"
        )


def _stat_fields(value: os.stat_result, *, leaf: bool) -> tuple[int, ...]:
    common = (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, int(getattr(value, "st_flags", 0)),
    )
    if leaf:
        return (*common, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    return common


class _PortableMetadataChanged(PortableProvenanceError):
    def __init__(self, before, after, label):
        super().__init__(f"Native metadata changed during observation: {label}")
        self.before = before
        self.after = after


def _witness(fd: int, *, leaf: bool, label: str) -> _Witness:
    before = os.fstat(fd)
    safe_type = ((stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
                 if leaf else stat.S_ISDIR(before.st_mode))
    if not safe_type:
        raise PortableProvenanceError(f"Unsafe portable {'file' if leaf else 'directory'}: {label}")
    try:
        metadata = (observe_created_file_metadata_fd(fd) if leaf
                    else observe_created_directory_metadata_fd(fd))
    except ContentPathError as exc:
        raise PortableProvenanceError(f"Unsupported native metadata at {label}: {exc}") from exc
    after = os.fstat(fd)
    if _stat_fields(before, leaf=leaf) != _stat_fields(after, leaf=leaf):
        raise _PortableMetadataChanged(before, after, label)
    return _Witness(_stat_fields(after, leaf=leaf), metadata)


def _same_namespace(parent_fd: int, name: str, opened: _Witness, *, leaf: bool, label: str) -> None:
    live = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (_stat_fields(live, leaf=leaf) != opened.stat_fields
            or (stat.S_ISREG(live.st_mode) if leaf else stat.S_ISDIR(live.st_mode)) is False):
        raise PortableProvenanceError(f"Portable namespace or metadata changed: {label}")


def _same_root_ancestor_stat(before: tuple[int, ...], after: tuple[int, ...]) -> bool:
    # Only linked directories are eligible; nlink is not an identity/protection.
    return (len(before) == len(after) == 7
            and stat.S_ISDIR(before[2]) and stat.S_ISDIR(after[2])
            and before[3] > 0 and after[3] > 0
            and before[:3] == after[:3] and before[4:] == after[4:])


def _same_root_ancestor(expected: _Witness, fresh: _Witness) -> bool:
    return (_same_root_ancestor_stat(expected.stat_fields, fresh.stat_fields)
            and expected.metadata == fresh.metadata)


def _root_ancestor_witness(fd: int, *, label: str) -> _Witness:
    """Retry only bounded link-count churn; return a complete strict witness.

    Linux keeps its ctime guard around native metadata inventory. A failed
    sample is retried only when its typed evidence includes a link-count
    change and no other stat change except accompanying ctime. Other metadata
    failures and observed protection/identity changes are never retried.
    """
    first = None
    for attempt in range(3):
        try:
            fresh = _witness(fd, leaf=False, label=label)
        except PortableProvenanceError as exc:
            if isinstance(exc, _PortableMetadataChanged):
                before, after = exc.before, exc.after
            elif isinstance(exc.__cause__, _DescriptorMetadataChanged):
                cause = exc.__cause__
                fields = set(cause.changed_fields)
                if 'st_nlink' not in fields or fields - {'st_nlink', 'st_ctime_ns'}:
                    raise
                before, after = cause.before, cause.after
            else:
                raise
            left, right = _stat_fields(before, leaf=False), _stat_fields(after, leaf=False)
            if (left[3] == right[3] or not _same_root_ancestor_stat(left, right)
                    or (first is not None and not _same_root_ancestor_stat(first, right))
                    or attempt == 2):
                raise
            if first is None:
                first = left
        else:
            if first is not None and not _same_root_ancestor_stat(first, fresh.stat_fields):
                raise PortableProvenanceError(f"Project-root ancestor changed during retry: {label}")
            return fresh
    raise AssertionError("Unreachable ancestor observation state")


def _same_root_ancestor_namespace(parent_fd: int, name: str,
                                  opened: _Witness, *, label: str) -> None:
    live = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not _same_root_ancestor_stat(opened.stat_fields, _stat_fields(live, leaf=False)):
        raise PortableProvenanceError(f"Portable namespace or metadata changed: {label}")


class _ContainedReader:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._stack = ExitStack()
        self._root_chain: list[tuple[int, str, int, _Witness]] = []
        self._slash_fd: int | None = None
        self._slash_witness: _Witness | None = None
        self._root_fd: int | None = None
        self._directories: dict[str, _Witness] = {}
        self._directory_names: dict[str, tuple[tuple[int, int], set[str]]] = {}
        self._name_count = 0
        self._name_bytes = 0
        self._dependencies: dict[str, _Leaf] = {}
        self._read_bytes = 0
        self._revalidation_bytes = 0

    def __enter__(self) -> _ContainedReader:
        _require_environment()
        raw = os.fspath(self.project_root)
        if not isinstance(raw, str) or not raw or ".." in Path(raw).parts:
            raise PortableProvenanceError("Project root has an unsafe path spelling")
        absolute = os.path.abspath(raw)
        parts = [part for part in absolute.split(os.sep) if part]
        if len(parts) > MAX_ROOT_COMPONENTS:
            raise PortableProvenanceError("Project-root ancestor depth exceeds limit")
        try:
            current = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._stack.callback(os.close, current)
            root_witness = _root_ancestor_witness(current, label=os.sep)
            self._slash_fd = current
            self._slash_witness = root_witness
            if not _same_root_ancestor_stat(root_witness.stat_fields,
                    _stat_fields(os.stat(os.sep, follow_symlinks=False), leaf=False)):
                raise PortableProvenanceError("Filesystem root changed while opened")
            for index, part in enumerate(parts):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=current)
                self._stack.callback(os.close, child)
                label = os.sep + os.sep.join(parts[:index + 1])
                witness = _root_ancestor_witness(child, label=label)
                _same_root_ancestor_namespace(current, part, witness, label=label)
                self._root_chain.append((current, part, child, witness))
                current = child
            self._root_fd = current
            self._check_root()
            return self
        except BaseException:
            self._stack.close()
            raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._stack.close()

    def _check_root(self) -> None:
        if self._slash_fd is None or self._slash_witness is None:
            raise PortableProvenanceError("Filesystem root witness is absent")
        slash = _root_ancestor_witness(self._slash_fd, label=os.sep)
        if (not _same_root_ancestor(self._slash_witness, slash)
                or not _same_root_ancestor_stat(slash.stat_fields,
                    _stat_fields(os.stat(os.sep, follow_symlinks=False), leaf=False))):
            raise PortableProvenanceError("Filesystem root changed")
        for parent, part, child, expected in self._root_chain:
            live = _root_ancestor_witness(child, label=f"root ancestor {part}")
            if not _same_root_ancestor(expected, live):
                raise PortableProvenanceError(f"Project-root ancestor metadata changed: {part}")
            _same_root_ancestor_namespace(parent, part, live, label=f"root ancestor {part}")

    def _exact_child(self, parent_fd: int, parent_label: str, name: str) -> bool:
        """Reject case/Unicode aliases while caching one bounded directory list."""
        current = os.fstat(parent_fd)
        times = (current.st_mtime_ns, current.st_ctime_ns)
        cached = self._directory_names.get(parent_label)
        if cached is None:
            names: set[str] = set()
            with os.scandir(parent_fd) as listing:
                for item in listing:
                    self._name_count += 1
                    self._name_bytes += len(os.fsencode(item.name))
                    if (self._name_count > MAX_DIRECTORY_NAMES
                            or self._name_bytes > MAX_DIRECTORY_NAME_BYTES):
                        raise PortableProvenanceError(
                            "Portable native directory inventory exceeds limit"
                        )
                    names.add(item.name)
            after = os.fstat(parent_fd)
            if (after.st_mtime_ns, after.st_ctime_ns) != times:
                raise PortableProvenanceError(f"Portable directory changed while listed: {parent_label}")
            cached = (times, names)
            self._directory_names[parent_label] = cached
        elif cached[0] != times:
            raise PortableProvenanceError(f"Portable directory namespace changed: {parent_label}")
        if name in cached[1]:
            return True
        if any(existing.casefold() == name.casefold() for existing in cached[1]):
            raise PortableProvenanceError(f"Portable path has absent or aliased spelling: {parent_label}/{name}")
        return False

    def _capture(self, relative: str, *, collect: bool) -> bytes | _Leaf | None:
        limit = control_path_limit(relative)
        if self._root_fd is None:
            raise PortableProvenanceError("Portable root reader is not open")
        self._check_root()
        parts = relative.split("/")
        with ExitStack() as opened:
            parent = self._root_fd
            opened_dirs: list[tuple[int, str, int, _Witness]] = []
            for index, part in enumerate(parts[:-1]):
                label = "/".join(parts[:index + 1])
                if not self._exact_child(parent, "/".join(parts[:index]), part):
                    raise PortableProvenanceError(f"Missing portable control directory: {label}")
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
                opened.callback(os.close, child)
                witness = _witness(child, leaf=False, label=label)
                _same_namespace(parent, part, witness, leaf=False, label=label)
                prior = self._directories.setdefault(label, witness)
                if witness != prior:
                    raise PortableProvenanceError(f"Portable control directory changed: {label}")
                opened_dirs.append((parent, part, child, witness))
                parent = child
            if not self._exact_child(parent, "/".join(parts[:-1]), parts[-1]):
                return None
            try:
                leaf_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=parent)
            except FileNotFoundError:
                return None
            opened.callback(os.close, leaf_fd)
            before = _witness(leaf_fd, leaf=True, label=relative)
            _same_namespace(parent, parts[-1], before, leaf=True, label=relative)
            size = before.stat_fields[-3]
            if size > limit:
                raise PortableProvenanceError(f"Portable record exceeds byte limit: {relative}")
            if collect and size > MAX_CUMULATIVE_READ_BYTES - self._read_bytes:
                raise PortableProvenanceError("Portable native cumulative read limit exceeded")
            if not collect:
                expected = self._dependencies.get(relative)
                if expected is None or before != expected.witness or size != expected.size:
                    raise PortableProvenanceError(f"Portable dependency changed after read: {relative}")
                if size > MAX_CUMULATIVE_READ_BYTES - self._revalidation_bytes:
                    raise PortableProvenanceError("Portable native revalidation-byte limit exceeded")
            data = bytearray() if collect else None
            digest = hashlib.sha256()
            count = 0
            while True:
                chunk = os.read(leaf_fd, min(READ_CHUNK_BYTES, limit + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > limit:
                    raise PortableProvenanceError(f"Portable record grew beyond byte limit: {relative}")
                digest.update(chunk)
                if data is not None:
                    data.extend(chunk)
            after = _witness(leaf_fd, leaf=True, label=relative)
            if count != size or after != before:
                raise PortableProvenanceError(f"Portable file changed during read: {relative}")
            _same_namespace(parent, parts[-1], before, leaf=True, label=relative)
            for ancestor, name, descriptor, expected in reversed(opened_dirs):
                if _witness(descriptor, leaf=False, label=name) != expected:
                    raise PortableProvenanceError(f"Portable directory changed during read: {relative}")
                _same_namespace(ancestor, name, expected, leaf=False, label=name)
            self._check_root()
            observed = _Leaf(before, digest.hexdigest(), count)
            if data is None:
                self._revalidation_bytes += count
                return observed
            self._read_bytes += count
            if relative in self._dependencies and self._dependencies[relative] != observed:
                raise PortableProvenanceError(f"Portable dependency changed between reads: {relative}")
            if relative not in self._dependencies and len(self._dependencies) >= MAX_DEPENDENCIES:
                raise PortableProvenanceError("Portable dependency inventory exceeds limit")
            self._dependencies[relative] = observed
            return bytes(data)

    def read(self, relative: str) -> bytes | None:
        value = self._capture(relative, collect=True)
        if value is not None and not isinstance(value, bytes):
            raise PortableProvenanceError("Internal portable read type mismatch")
        return value

    def revalidate(self) -> None:
        self._check_root()
        for relative, expected in self._dependencies.items():
            observed = self._capture(relative, collect=False)
            if observed != expected:
                raise PortableProvenanceError(f"Portable dependency changed after read: {relative}")
        self._check_root()


def read_portable_snapshot(project_root: Path) -> ValidatedPortableSnapshot:
    """Read and revalidate one portable head without writing local state."""
    try:
        with _ContainedReader(project_root) as reader:
            snapshot = load_portable_snapshot(reader)
            reader.revalidate()
            return snapshot
    except (PortableProvenanceError, PortableProvenanceUnsupportedEnvironment):
        raise
    except ContentPathError as exc:
        raise PortableProvenanceError(f"Unsupported portable native metadata: {exc}") from exc
    except OSError as exc:
        raise PortableProvenanceError(f"Portable native read failed: {exc}") from exc
