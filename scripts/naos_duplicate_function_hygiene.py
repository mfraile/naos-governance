#!/usr/bin/env python3
"""Detect normalized duplicate Python function bodies without model/runtime calls."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_hygiene_common import check_duplicate_function_hygiene, run_report_command


FALLBACK_RULES = {
    "scan_roots": ["src", "app", "tests"],
    "exclude_dirs": ["dev", "dist", "build", "__pycache__"],
    "exclude_globs": [],
    "min_normalized_dump_length": 240,
    "allowed_hashes": [],
}


def main(argv: list[str] | None = None) -> int:
    return run_report_command(
        argv=argv,
        description="Detect normalized duplicate Python function bodies.",
        rules_filename="duplicate_function_hygiene_rules.yaml",
        report_key="duplicate_function_hygiene_report",
        schema="naos.duplicate_function_hygiene.v1",
        fallback_rules=FALLBACK_RULES,
        builder=check_duplicate_function_hygiene,
        summary_label="Duplicate Function Hygiene",
    )


if __name__ == "__main__":
    sys.exit(main())
