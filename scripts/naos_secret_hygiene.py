#!/usr/bin/env python3
"""Detect obvious secret-like patterns and high-entropy literals locally."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_hygiene_common import check_secret_hygiene, run_report_command


FALLBACK_RULES = {
    "scan_roots": ["src", "app", "tests", ".github"],
    "suffixes": [".py", ".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".cfg", ".md", ".txt"],
    "exclude_dirs": ["dev", "dist", "build", "__pycache__"],
    "exclude_globs": [],
    "entropy_min_length": 20,
    "entropy_threshold": 4.0,
    "allowed_values": [],
}


def main(argv: list[str] | None = None) -> int:
    return run_report_command(
        argv=argv,
        description="Detect obvious secret-like patterns and high-entropy literals.",
        rules_filename="secret_hygiene_rules.yaml",
        report_key="secret_hygiene_report",
        schema="naos.secret_hygiene.v1",
        fallback_rules=FALLBACK_RULES,
        builder=check_secret_hygiene,
        summary_label="Secret Hygiene",
    )


if __name__ == "__main__":
    sys.exit(main())
