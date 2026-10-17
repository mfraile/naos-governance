"""Private Windows preview I/O addresses; never public native root authority.

Only the owning temporary allocator creates these addresses in production.
Ordinary identities and extended-length Python I/O spellings stay distinct.
"""
from __future__ import annotations

from dataclasses import dataclass
import ntpath
import os
from pathlib import Path
import shutil
import tempfile

from .windows_handles import validate_component, validate_root_path


@dataclass(frozen=True)
class PrivatePreviewAddress:
    ordinary_root: str
    io_root: str

    def __post_init__(self) -> None:
        ordinary = validate_root_path(self.ordinary_root)
        if self.io_root != "\\\\?\\" + ordinary:
            raise ValueError("Private preview address has mismatched I/O and ordinary roots")

    @classmethod
    def _for_owned_directory(cls, ordinary_root: str) -> PrivatePreviewAddress:
        ordinary = validate_root_path(ordinary_root)
        return cls(ordinary, "\\\\?\\" + ordinary)

    def require_root(self, path: Path, *, io: bool = False) -> None:
        expected = self.io_root if io else self.ordinary_root
        if str(path) != expected:
            raise ValueError("Private preview root does not match its owning address")

    def resolved_ordinary_root(self, resolved: Path) -> Path:
        # Exact root equivalence only; a resolved reparse/ancestor redirection is
        # refused instead of stripping a namespace prefix from arbitrary paths.
        if ntpath.normcase(str(resolved)) not in {
            ntpath.normcase(self.ordinary_root), ntpath.normcase(self.io_root)
        }:
            raise ValueError("Private preview root resolved outside its owning address")
        return Path(self.ordinary_root)

    def ordinary_source(self, relative: Path, source: Path) -> str:
        name = relative.as_posix()
        if name.startswith("/") or "\\" in name or not name or name == ".":
            raise ValueError("Private preview source requires a normalized relative path")
        components = name.split("/")
        for component in components:
            validate_component(component)
        expected = ntpath.join(self.io_root, *components)
        if str(source) != expected:
            raise ValueError("Private preview source is outside its exact declared address")
        return ntpath.join(self.ordinary_root, *components)


class WindowsPrivateTemporaryPreview:
    """Own one private temporary directory and its exact preview child."""

    def __init__(self, *, parent: Path, prefix: str):
        validate_component(prefix)
        parent_name = validate_root_path(str(parent))
        parent_io = "\\\\?\\" + parent_name
        allocated = tempfile.mkdtemp(prefix=prefix, dir=parent_io)
        if ntpath.dirname(allocated) != parent_io:
            raise ValueError(
                "Private temporary allocator returned an unexpected parent; "
                "unvalidated returned path was preserved: " + str(allocated)
            )
        leaf = validate_component(ntpath.basename(allocated))
        self.name = ntpath.join(parent_name, leaf)
        self._io_root = allocated
        try:
            self.preview_address = PrivatePreviewAddress._for_owned_directory(
                ntpath.join(self.name, "preview")
            )
        except (OSError, RuntimeError, ValueError) as operation_error:
            try:
                shutil.rmtree(self._io_root)
            except (OSError, RuntimeError, ValueError) as cleanup_error:
                raise RuntimeError(
                    f"Private preview allocation failed: {operation_error}; "
                    f"owned staging cleanup also failed: {cleanup_error}"
                ) from operation_error
            raise
        self._cleaned = False

    def cleanup(self) -> None:
        if self._cleaned:
            return
        try:
            shutil.rmtree(self._io_root)
        except FileNotFoundError:
            # A descendant can disappear while rmtree aborts traversal. Only
            # absence of this exact owned root proves cleanup is complete.
            try:
                os.lstat(self._io_root)
            except FileNotFoundError:
                pass
            else:
                raise
        self._cleaned = True


def create_temporary_preview(*, parent: Path, prefix: str):
    if os.name == "nt":
        return WindowsPrivateTemporaryPreview(parent=parent, prefix=prefix)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=parent)
