#!/usr/bin/env python3
"""
generate_release_notes.py — Append task status changes to naos/RELEASE_NOTES.md.

NAOS Portable Governance Kit
Usage: python scripts/workflows/generate_release_notes.py
Env:   NAOS_ROOT   (default: naos)  — root of the governance directory
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))

EXEC_FILE = Path("specs/10-execution.md")
REL_NOTES = NAOS_ROOT / "RELEASE_NOTES.md"
CACHE = NAOS_ROOT / ".release_cache.json"


def parse_matrix() -> dict[str, str]:
    if not EXEC_FILE.exists():
        return {}
    text = EXEC_FILE.read_text(encoding="utf-8")
    m = re.search(r"<!-- BEGIN TASK_MATRIX -->([\s\S]*?)<!-- END TASK_MATRIX -->", text)
    if not m:
        return {}
    statuses: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if not line.strip().startswith("|"):
            continue
        parts = [p.strip() for p in line.strip().strip("|").split("|")]
        if len(parts) < 10 or parts[0] == "ID":
            continue
        statuses[parts[0]] = parts[5]
    return statuses


def load_prev() -> dict[str, str]:
    if not CACHE.exists():
        return {}
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_current(cur: dict[str, str]) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(cur, indent=2), encoding="utf-8")


def main() -> int:
    cur = parse_matrix()
    prev = load_prev()
    changes = []
    for tid, status in cur.items():
        old = prev.get(tid)
        if old and old != status:
            changes.append(f"- {tid}: {old} -> {status}")
        elif not old:
            changes.append(f"- {tid}: (new) {status}")
    if changes:
        stamp = datetime.now(UTC).strftime("%Y-%m-%d")
        REL_NOTES.parent.mkdir(parents=True, exist_ok=True)
        rel = REL_NOTES.read_text(encoding="utf-8") if REL_NOTES.exists() else ""
        rel += f"\n## {stamp}\n" + "\n".join(changes) + "\n"
        REL_NOTES.write_text(rel, encoding="utf-8")
    save_current(cur)
    print(f"Release notes updated with {len(changes)} changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
