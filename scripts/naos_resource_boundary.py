"""Bound selected kit resources separately from untrusted project inputs."""
from __future__ import annotations

import stat
from pathlib import Path

from naos_policy import kit_root


def _regular_reference(path: Path, root: Path, *, missing_ok: bool = False) -> str | None:
    if '..' in path.parts:
        raise ValueError(f'Resource path contains traversal: {path}')
    base = root.absolute()
    candidate = path.absolute()
    try:
        relative = candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f'Resource must remain beneath its selected root: {path}') from exc
    if not relative.parts:
        raise ValueError('Resource must be a regular file')
    cursor = base
    for index, part in enumerate(relative.parts):
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if missing_ok:
                return None
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError(f'Resource must not use symlink or reparse components: {path}')
        if index < len(relative.parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError(f'Resource ancestor is not a directory: {path}')
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError(f'Resource is not a regular file: {path}')
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError(f'Resource escaped its selected root: {path}') from exc
    return relative.as_posix()


def resource_reference(path: Path, root: Path, *, kit_relative: str | None = None) -> str:
    """Only a caller-named exact kit resource can cross the project boundary.

    Callers must omit kit_relative for explicit adopter inputs. This is resource
    selection and static topology validation, not a concurrent-filesystem sandbox.
    """
    if path.absolute().is_relative_to(root.absolute()):
        try:
            result = _regular_reference(path, root)
        except ValueError as exc:
            raise ValueError(f'Input must be a regular non-linked file inside the project root: {path}; {exc}') from exc
    else:
        if kit_relative is None:
            raise ValueError(f'Project input must remain inside the project root: {path}')
        expected = kit_root() / kit_relative
        if path.absolute() != expected.absolute():
            raise ValueError(f'Path is not the selected kit resource: {path}')
        result = _regular_reference(path, kit_root())
        result = 'kit://' + str(result)
    assert result is not None
    return result


def select_resource(root: Path, project_path: Path, kit_relative: str) -> Path:
    """Prefer a valid project resource; fallback only when it is absent."""
    if _regular_reference(project_path, root, missing_ok=True) is not None:
        return project_path
    selected = kit_root() / kit_relative
    resource_reference(selected, root, kit_relative=kit_relative)
    return selected
