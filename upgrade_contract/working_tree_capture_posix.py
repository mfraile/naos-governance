"""Read-only, bounded POSIX evidence for a selected managed working tree.

This observes native topology and exact leaf bytes. It grants no ownership,
quiescence, journal validity, or permission to mutate the observed tree.
"""

from __future__ import annotations

import hashlib
import os
import sys
import unicodedata
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import local_binding as binding
from .portable_provenance import PortableProvenanceError
from .portable_provenance_posix import (
    _require_environment,
    _same_namespace,
    _same_root_ancestor,
    _same_root_ancestor_stat,
    _same_root_ancestor_namespace,
    _root_ancestor_witness,
    _stat_fields,
    _witness,
)
from .security import ContentPathError, _native_metadata_binding_scope
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


READ_CHUNK_BYTES = 1024 * 1024
MAX_ROOT_COMPONENTS = 64


class WorkingTreeCaptureUnsupportedEnvironment(WorkingTreeCaptureError):
    """Required no-follow POSIX observations are unavailable."""


class _Reader:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.stack = ExitStack()
        self.root_fd: int | None = None
        self.chain: list[tuple[str, int, str, int, Any]] = []
        self.directories: dict[str, Any] = {}
        self.scans: dict[str, tuple[tuple[int, int], frozenset[str]]] = {}
        # Exact spellings derived once from each bounded, immutable name scan.
        self.scan_aliases: dict[str, dict[str, str | None]] = {}
        self.name_count = 0
        self.name_bytes = 0
        self.read_bytes = 0
        self.final_bytes = 0
        self.root_path = ""
        self.platform = "Darwin" if sys.platform == "darwin" else "Linux"

    def __enter__(self) -> _Reader:
        try:
            _require_environment()
        except PortableProvenanceError as exc:
            raise WorkingTreeCaptureUnsupportedEnvironment(str(exc)) from exc
        raw = os.fspath(self.project_root)
        if (type(raw) is not str or not raw or len(raw) > 16 * 1024
                or ".." in Path(raw).parts):
            raise WorkingTreeCaptureError("Unsafe project-root spelling")
        self.root_path = os.path.abspath(raw)
        parts = [p for p in self.root_path.split("/") if p]
        if len(parts) > MAX_ROOT_COMPONENTS:
            raise WorkingTreeCaptureError("Project-root ancestry exceeds limit")
        try:
            # Reuse owner-bound ABI setup only; every native witness stays fresh.
            self.stack.enter_context(_native_metadata_binding_scope())
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.stack.callback(os.close, parent)
            slash = _root_ancestor_witness(parent, label="/")
            if not _same_root_ancestor_stat(slash.stat_fields,
                    _stat_fields(os.stat("/", follow_symlinks=False), leaf=False)):
                raise WorkingTreeCaptureError("Filesystem root changed")
            self.chain.append(("/", -1, "", parent, slash))
            for index, part in enumerate(parts):
                self._root_exact(parent, "/" + "/".join(parts[:index]), part)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
                self.stack.callback(os.close, child)
                label = "/" + "/".join(parts[:index + 1])
                witness = _root_ancestor_witness(child, label=label)
                _same_root_ancestor_namespace(parent, part, witness, label=label)
                self.chain.append((label, parent, part, child, witness))
                parent = child
            self.root_fd = parent
            self._check_root()
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *_args: Any) -> None:
        self.stack.close()

    def _check_root(self) -> None:
        for label, parent, name, fd, expected in self.chain:
            fresh = _root_ancestor_witness(fd, label=label)
            if not _same_root_ancestor(expected, fresh):
                raise WorkingTreeCaptureError(f"Project-root ancestor changed: {label}")
            if parent == -1:
                if not _same_root_ancestor_stat(fresh.stat_fields,
                        _stat_fields(os.stat("/", follow_symlinks=False), leaf=False)):
                    raise WorkingTreeCaptureError("Filesystem root changed")
            else:
                _same_root_ancestor_namespace(parent, name, fresh, label=label)

    def _check_root_custody(self) -> None:
        """Check held ancestry across mutation without freezing sibling counts.

        Directory link counts can change when an unrelated sibling is created.
        Fresh witnesses still require positive links and stable observations;
        identities, protections and exact no-follow spellings remain mandatory.
        Managed directory inventories and leaves retain their strict checks.
        """
        counters = self.name_count, self.name_bytes
        self.name_count = self.name_bytes = 0
        try:
            for label, parent, name, fd, expected in self.chain:
                fresh = _root_ancestor_witness(fd, label=label)
                if not _same_root_ancestor(expected, fresh):
                    raise WorkingTreeCaptureError(
                        f"Project-root ancestor identity or protection changed: {label}")
                if parent == -1:
                    if not _same_root_ancestor_stat(fresh.stat_fields,
                            _stat_fields(os.stat("/", follow_symlinks=False), leaf=False)):
                        raise WorkingTreeCaptureError("Filesystem root changed")
                else:
                    self._root_exact(parent, str(Path(label).parent), name)
                    _same_root_ancestor_namespace(parent, name, fresh, label=label)
        finally:
            self.name_count, self.name_bytes = counters

    def _root_exact(self, parent: int, label: str, name: str) -> None:
        """Check lexical root ancestry without resolving case or link aliases."""
        for _ in range(3):
            before = os.fstat(parent)
            matches: list[str] = []
            with os.scandir(parent) as entries:
                for item in entries:
                    # Retries spend the same aggregate capture budget.
                    self.name_count += 1
                    self.name_bytes += len(os.fsencode(item.name))
                    if (self.name_count > MAX_DIRECTORY_ENTRIES
                            or self.name_bytes > MAX_DIRECTORY_NAME_BYTES):
                        raise WorkingTreeCaptureError("Root ancestry inventory exceeds budget")
                    if unicodedata.normalize("NFC", item.name).casefold() == name.casefold():
                        matches.append(item.name)
            after = os.fstat(parent)
            # An alias or missing exact spelling is never made acceptable by
            # a later stable retry.
            if matches != [name]:
                raise WorkingTreeCaptureError(f"Root ancestor has aliased spelling: {label}/{name}")
            if ((before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_mtime_ns, after.st_ctime_ns)):
                continue
            return
        raise WorkingTreeCaptureError(f"Root ancestor namespace changed: {label}")

    def _scan(self, fd: int, label: str, *, final: bool = False) -> frozenset[str]:
        before = os.fstat(fd)
        times = (before.st_mtime_ns, before.st_ctime_ns)
        if not final and label in self.scans:
            cached_times, names = self.scans[label]
            if cached_times != times:
                raise WorkingTreeCaptureError(f"Directory namespace changed: {label}")
            return names
        names: set[str] = set()
        with os.scandir(fd) as entries:
            for item in entries:
                self.name_count += 1
                self.name_bytes += len(os.fsencode(item.name))
                if (self.name_count > MAX_DIRECTORY_ENTRIES
                        or self.name_bytes > MAX_DIRECTORY_NAME_BYTES):
                    raise WorkingTreeCaptureError("Directory inventory exceeds capture budget")
                names.add(item.name)
        after = os.fstat(fd)
        if (after.st_mtime_ns, after.st_ctime_ns) != times:
            raise WorkingTreeCaptureError(f"Directory changed while enumerated: {label}")
        result = frozenset(names)
        if final:
            if self.scans[label] != (times, result):
                raise WorkingTreeCaptureError(f"Directory namespace changed: {label}")
        else:
            aliases: dict[str, str | None] = {}
            for name in result:
                folded = unicodedata.normalize("NFC", name).casefold()
                aliases[folded] = None if folded in aliases else name
            self.scan_aliases[label] = aliases
            self.scans[label] = (times, result)
        return result

    def _exists(self, fd: int, label: str, name: str) -> bool:
        names = self._scan(fd, label)
        alias = self.scan_aliases[label].get(name.casefold(), name)
        if alias != name:
            raise WorkingTreeCaptureError(f"Aliased native path: {label}/{name}")
        return name in names

    def _walk(self, relative: str, stack: ExitStack) -> int | None:
        if self.root_fd is None:
            raise WorkingTreeCaptureError("Reader is closed")
        parent = self.root_fd
        prefix = ""
        opened: list[tuple[int, str, int, Any, str]] = []
        for part in relative.split("/") if relative else ():
            if not self._exists(parent, prefix, part):
                stack.callback(self._check_walk, tuple(opened))
                return None
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            stack.callback(os.close, child)
            label = part if not prefix else prefix + "/" + part
            witness = _witness(child, leaf=False, label=label)
            _same_namespace(parent, part, witness, leaf=False, label=label)
            prior = self.directories.setdefault(label, witness)
            if witness != prior:
                raise WorkingTreeCaptureError(f"Managed or control directory changed: {label}")
            opened.append((parent, part, child, witness, label))
            parent, prefix = child, label
        stack.callback(self._check_walk, tuple(opened))
        return parent

    def _check_walk(self, opened: tuple[tuple[int, str, int, Any, str], ...]) -> None:
        for parent, name, child, expected, label in opened:
            if _witness(child, leaf=False, label=label) != expected:
                raise WorkingTreeCaptureError(f"Opened directory changed: {label}")
            _same_namespace(parent, name, expected, leaf=False, label=label)

    def directory(self, relative: str) -> dict[str, Any]:
        self._check_root()
        with ExitStack() as stack:
            fd = self._walk(relative, stack)
            result = (binding.absent_witness(self.platform, "directory") if fd is None
                      else binding.project_posix_witness(
                          _witness(fd, leaf=False, label=relative).metadata))
        self._check_root()
        return result

    def leaf(self, relative: str, *, final: bool = False) -> dict[str, Any]:
        self._check_root()
        parent_path, _, name = relative.rpartition("/")
        with ExitStack() as stack:
            parent = self._walk(parent_path, stack)
            if parent is None or not self._exists(parent, parent_path, name):
                result = {"path": relative,
                          "metadata": binding.absent_witness(self.platform, "file"),
                          "content": None}
            else:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
                stack.callback(os.close, fd)
                before = _witness(fd, leaf=True, label=relative)
                _same_namespace(parent, name, before, leaf=True, label=relative)
                size = before.stat_fields[-3]
                used = self.final_bytes if final else self.read_bytes
                if size > MAX_LEAF_BYTES or size > MAX_READ_BYTES - used:
                    raise WorkingTreeCaptureError(f"Managed leaf exceeds read budget: {relative}")
                digest = hashlib.sha256()
                count = 0
                while True:
                    data = os.read(fd, min(READ_CHUNK_BYTES, MAX_LEAF_BYTES - count + 1))
                    if not data:
                        break
                    count += len(data)
                    if count > MAX_LEAF_BYTES or count > MAX_READ_BYTES - used:
                        raise WorkingTreeCaptureError(f"Managed leaf exceeds read budget: {relative}")
                    digest.update(data)
                if final:
                    self.final_bytes += count
                else:
                    self.read_bytes += count
                after = _witness(fd, leaf=True, label=relative)
                if before != after or count != size:
                    raise WorkingTreeCaptureError(f"Managed leaf changed during read: {relative}")
                _same_namespace(parent, name, before, leaf=True, label=relative)
                result = {"path": relative,
                          "metadata": binding.project_posix_witness(before.metadata),
                          "content": {"sha256": digest.hexdigest(),
                                      "size_decimal": str(count)}}
        self._check_root()
        return result

    def _final_revalidate(self, native: dict[str, Any], leaves: list[dict[str, Any]]) -> None:
        self._check_root()
        for item in native["control_directories"] + native["managed_ancestors"]:
            if self.directory(item["path"]) != item["witness"]:
                raise WorkingTreeCaptureError(f"Native directory changed: {item['path']}")
        for item in leaves:
            if self.leaf(item["path"], final=True) != item:
                raise WorkingTreeCaptureError(f"Managed leaf changed: {item['path']}")
        # Re-enumerate each observed parent once, including absence witnesses.
        self.name_count = 0
        self.name_bytes = 0
        for path in sorted(self.scans, key=lambda p: (p.count("/"), p)):
            with ExitStack() as stack:
                fd = self._walk(path, stack)
                if fd is None:
                    raise WorkingTreeCaptureError(f"Observed directory disappeared: {path}")
                self._scan(fd, path, final=True)
        for label, parent, name, _, _ in self.chain[1:]:
            self._root_exact(parent, str(Path(label).parent), name)
        # Leaf rehashing itself can change an unrelated control/ancestor's
        # protection metadata. Check the complete directory witness set again
        # after all leaf reads and namespace enumeration have finished.
        for item in native["control_directories"] + native["managed_ancestors"]:
            if self.directory(item["path"]) != item["witness"]:
                raise WorkingTreeCaptureError(f"Native directory changed: {item['path']}")
        self._check_root()


def _initial_capture(
    reader: _Reader, selected: tuple[str, ...], ancestors: tuple[str, ...],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Observe a selected tree while the caller keeps ``reader`` open."""
    native = {
        "platform": reader.platform,
        "root_path": reader.root_path,
        "root_chain": [
            {"path": path, "witness": binding.project_posix_witness(witness.metadata)}
            for path, _, _, _, witness in reader.chain
        ],
        "control_directories": [
            {"path": path, "witness": reader.directory(path)}
            for path in binding.CONTROL_DIRECTORIES
        ],
        "managed_ancestors": [
            {"path": path, "witness": reader.directory(path)}
            for path in ancestors
        ],
    }
    leaves = [reader.leaf(path) for path in selected]
    return native, leaves


def capture_working_tree(project_root: Path, paths: tuple[str, ...]) -> WorkingTreeCapture:
    """Capture selected native witnesses and exact bytes, then revalidate them.

    Each read pass is capped at 256 MiB and each leaf at 64 MiB. The result is
    observational evidence, not an atomic all-file snapshot or an apply lock.
    """
    selected = managed_paths(paths)  # Must precede any native filesystem access.
    ancestors = ancestor_paths(selected)
    try:
        with _Reader(project_root) as reader:
            native, leaves = _initial_capture(reader, selected, ancestors)
            reader._final_revalidate(native, leaves)
            return build_capture(native, leaves)
    except WorkingTreeCaptureError:
        raise
    except (PortableProvenanceError, ContentPathError, binding.LocalBindingError,
            OSError, ValueError, TypeError) as exc:
        raise WorkingTreeCaptureError(f"Unsafe POSIX working-tree capture: {exc}") from exc
