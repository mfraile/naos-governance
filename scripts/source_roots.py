#!/usr/bin/env python3
"""Shared source-root resolution for brownfield NAOS adopters."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

DEFAULT_SOURCE_ROOT_NAMES = ("src", "app", "apps", "packages", "lib")


def split_source_root(value: str | None) -> list[Path]:
    """Parse a comma-separated source-root value into paths."""
    return [Path(item.strip()) for item in (value or "").split(",") if item.strip()]


def resolve_source_roots(
    root: Path | None = None,
    src_root: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    fallback: bool = True,
    absolute: bool = False,
) -> list[Path]:
    """Return explicit or inferred source roots.

    Explicit ``SRC_ROOT`` values are returned even when they do not exist, so
    callers can report exactly what was configured. Without an explicit value,
    common brownfield roots are inferred when present.
    """
    base = root or Path.cwd()
    source_value = src_root
    if source_value is None:
        source_value = (env or os.environ).get("SRC_ROOT")

    if source_value:
        roots = split_source_root(source_value)
    else:
        roots = [
            Path(name)
            for name in DEFAULT_SOURCE_ROOT_NAMES
            if (base / name).is_dir()
        ]
        if not roots and fallback:
            roots = [Path("src")]

    if absolute:
        return [path if path.is_absolute() else base / path for path in roots]
    return roots


def existing_source_roots(
    root: Path | None = None,
    src_root: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    absolute: bool = False,
) -> list[Path]:
    """Return configured source roots that currently exist."""
    base = root or Path.cwd()
    roots = resolve_source_roots(base, src_root, env=env, absolute=absolute)
    existing: list[Path] = []
    for path in roots:
        candidate = path if path.is_absolute() else base / path
        if candidate.exists():
            existing.append(path)
    return existing


def source_roots_display(roots: list[Path]) -> str:
    """Render source roots for human-readable messages."""
    return ", ".join(str(root) for root in roots) if roots else "none"
