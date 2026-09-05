"""Shared validator context helpers."""

from __future__ import annotations

import os
from pathlib import Path


def is_kit_repository(root: Path | None = None) -> bool:
    """Return True when running from the NAOS kit source, not an adopter project."""

    root = root or Path.cwd()
    naos_root = Path(os.getenv("NAOS_ROOT", "naos"))
    return (
        (root / "pyproject.toml").is_file()
        and (root / "naos_init.py").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / naos_root / "TASK_REGISTRY.yaml").is_file()
    )


def print_kit_skip(validator_name: str, reason: str) -> None:
    print(f"{validator_name}: SKIP")
    print(f"  - kit repo context: {reason}")
