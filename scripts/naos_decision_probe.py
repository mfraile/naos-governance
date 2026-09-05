#!/usr/bin/env python3
"""Decision probe reporter for NAOS adoption."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_adoption_common import main_for


def main(argv: list[str] | None = None) -> int:
    return main_for("decision_probe", argv)


if __name__ == "__main__":
    sys.exit(main())
