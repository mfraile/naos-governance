#!/usr/bin/env python3
"""
generate_backlog.py — Generate naos/BACKLOG.md from specs/10-execution.md Task Matrix.

NAOS Portable Governance Kit
Usage: python scripts/workflows/generate_backlog.py
Env:   NAOS_ROOT   (default: naos)  — root of the governance directory
"""

from __future__ import annotations

import os
import re
from pathlib import Path

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))

EXEC_FILE = Path("specs/10-execution.md")
BACKLOG_FILE = NAOS_ROOT / "BACKLOG.md"


def parse_tasks() -> list[dict[str, str]]:
    if not EXEC_FILE.exists():
        return []
    text = EXEC_FILE.read_text(encoding="utf-8")
    m = re.search(r"<!-- BEGIN TASK_MATRIX -->([\s\S]*?)<!-- END TASK_MATRIX -->", text)
    if not m:
        return []
    tasks: list[dict[str, str]] = []
    for line in m.group(1).splitlines():
        raw = line.strip()
        if not raw.startswith("|"):
            continue
        parts = [p.strip() for p in raw.strip().strip("|").split("|")]
        # Skip header/separator
        if not parts or parts[0] in ("ID", "----") or parts[0].startswith("-"):
            continue
        if len(parts) < 10:
            continue
        phase_token = parts[2]
        if not phase_token.isdigit():
            mphase = re.match(r"(\d+)", phase_token)
            if not mphase:
                continue
            phase_token = mphase.group(1)
        tasks.append(
            {
                "id": parts[0],
                "title": parts[1],
                "phase": phase_token,
                "type": parts[3],
                "req": parts[4],
                "status": parts[5],
                "acceptance": parts[9],
            }
        )
    return tasks


def rank(tasks: list[dict[str, str]]) -> list[dict[str, str]]:
    order = {"in progress": 0, "planned": 1, "done": 2}
    return sorted(
        tasks,
        key=lambda t: (order.get(t["status"].lower(), 9), int(t["phase"]), t["id"]),
    )


def render(tasks: list[dict[str, str]]) -> str:
    rows = [
        "| Rank | Task ID | Requirement | Title | Phase | Status | Type | Acceptance |",
        "|------|---------|------------|-------|------:|--------|------|------------|",
    ]
    ranked = rank(tasks)
    for i, t in enumerate(ranked, start=1):
        rows.append(
            f"| {i} | {t['id']} | {t['req']} | {t['title']} | {t['phase']} | {t['status']} | {t['type']} | {t['acceptance']} |"
        )
    return "\n".join(rows)


def main() -> int:
    tasks = parse_tasks()
    backlog_md = (
        BACKLOG_FILE.read_text(encoding="utf-8") if BACKLOG_FILE.exists() else ""
    )
    block = render(tasks)
    new_md = re.sub(
        r"<!-- BEGIN BACKLOG -->[\s\S]*?<!-- END BACKLOG -->",
        f"<!-- BEGIN BACKLOG -->\n{block}\n<!-- END BACKLOG -->",
        backlog_md,
    )
    BACKLOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    BACKLOG_FILE.write_text(new_md, encoding="utf-8")
    print(f"Updated backlog with {len(tasks)} tasks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
