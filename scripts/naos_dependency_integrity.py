#!/usr/bin/env python3
"""Detect Python imports that are not stdlib, first-party, declared, or allowlisted."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_hygiene_common import check_dependency_integrity, run_report_command


FALLBACK_RULES = {
    "scan_roots": ["src", "app", "tests"],
    "exclude_dirs": ["dev", "dist", "build", "__pycache__"],
    "exclude_globs": [],
    "allowed_imports": [],
}


def main(argv: list[str] | None = None) -> int:
    return run_report_command(
        argv=argv,
        description="Detect undeclared or unresolved Python imports without network calls.",
        rules_filename="dependency_integrity_rules.yaml",
        report_key="dependency_integrity_report",
        schema="naos.dependency_integrity.v1",
        fallback_rules=FALLBACK_RULES,
        builder=check_dependency_integrity,
        summary_label="Dependency Integrity",
    )


if __name__ == "__main__":
    sys.exit(main())
