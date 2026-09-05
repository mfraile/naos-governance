#!/usr/bin/env python3
"""Detect test functions with missing or trivial assertion evidence."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_hygiene_common import check_test_quality_hygiene, run_report_command


FALLBACK_RULES = {
    "scan_roots": ["tests"],
    "exclude_dirs": ["dev", "dist", "build", "__pycache__"],
    "exclude_globs": [],
}


def main(argv: list[str] | None = None) -> int:
    return run_report_command(
        argv=argv,
        description="Detect Python tests with missing or trivial assertion evidence.",
        rules_filename="test_quality_hygiene_rules.yaml",
        report_key="test_quality_hygiene_report",
        schema="naos.test_quality_hygiene.v1",
        fallback_rules=FALLBACK_RULES,
        builder=check_test_quality_hygiene,
        summary_label="Test Quality Hygiene",
    )


if __name__ == "__main__":
    sys.exit(main())
