#!/usr/bin/env python3
"""
metrics_snapshot.py — Generate a governance metrics snapshot from TASK_REGISTRY.yaml.

NAOS Portable Governance Kit
Usage: python scripts/workflows/metrics_snapshot.py [--output-json PATH] [--trend-md PATH]
Env:   NAOS_ROOT   (default: naos)  — root of the governance directory

Writes a JSON snapshot to naos/metrics/snapshot_YYYYMMDD_HHMMSS.json and
a timestamped copy to the --output-json path (default: metrics_snapshot.json).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_task_lifecycle import is_task_delivered, normalize_task_states  # noqa: E402

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))

try:
    import yaml

    _YAML_OK = True
except ImportError:
    _YAML_OK = False


def collect_snapshot() -> Dict[str, Any]:
    """Collect a governance metrics snapshot from TASK_REGISTRY.yaml."""
    snap: Dict[str, Any] = {
        "generated_at": int(time.time()),
        "version": "1.0.0",
        "tasks_total": 0,
        "tasks_done": 0,
        "tasks_in_progress": 0,
        "tasks_planned": 0,
        "tasks_deferred": 0,
        "tasks_unsupported_legacy_status": 0,
        "completion_pct": 0.0,
        "requirements_total": 0,
        "requirements_delivered": 0,
        "requirements_pct": 0.0,
    }

    registry_path = NAOS_ROOT / "TASK_REGISTRY.yaml"
    if not registry_path.exists() or not _YAML_OK:
        return snap

    try:
        data = yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return snap

    tasks = data.get("tasks", [])
    by_status: Dict[str, int] = {}
    for t in tasks:
        s = str(t.get("status", "planned")).lower()
        by_status[s] = by_status.get(s, 0) + 1

    done = sum(1 for task in tasks if is_task_delivered(task))
    in_progress = by_status.get("in_progress", 0)
    planned = by_status.get("planned", 0) + by_status.get("ready", 0)
    deferred = by_status.get("deferred", 0)
    unsupported = sum(
        1
        for task in tasks
        if normalize_task_states(task).get("compatibility_status") == "unsupported"
    )
    total = len(tasks)

    snap.update(
        {
            "tasks_total": total,
            "tasks_done": done,
            "tasks_in_progress": in_progress,
            "tasks_planned": planned,
            "tasks_deferred": deferred,
            "tasks_unsupported_legacy_status": unsupported,
            "completion_pct": round(done / total * 100, 1) if total else 0.0,
        }
    )

    # Requirement-level aggregation
    req_tasks: Dict[str, list[dict[str, Any]]] = {}
    for t in tasks:
        req = str(t.get("requirement", "unknown")).split(" (")[0].split(",")[0].strip()
        req_tasks.setdefault(req, []).append(t)

    def req_delivered(requirement_tasks: list[dict[str, Any]]) -> bool:
        return bool(requirement_tasks) and all(is_task_delivered(task) for task in requirement_tasks)

    reqs_total = len(req_tasks)
    reqs_done = sum(1 for s in req_tasks.values() if req_delivered(s))
    snap.update(
        {
            "requirements_total": reqs_total,
            "requirements_delivered": reqs_done,
            "requirements_pct": round(reqs_done / reqs_total * 100, 1)
            if reqs_total
            else 0.0,
        }
    )

    return snap


def _load_prev_snapshot(prev_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if not prev_path:
        return None
    try:
        if prev_path.exists():
            return json.loads(prev_path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


NUMERIC_KEYS = (
    "tasks_total",
    "tasks_done",
    "tasks_in_progress",
    "tasks_unsupported_legacy_status",
    "completion_pct",
    "requirements_total",
    "requirements_delivered",
    "requirements_pct",
)


def compute_trend(
    curr: Dict[str, Any], prev: Optional[Dict[str, Any]]
) -> Dict[str, Dict[str, Optional[float]]]:
    trend: Dict[str, Dict[str, Optional[float]]] = {}
    for k in NUMERIC_KEYS:
        c = curr.get(k)
        p = (prev or {}).get(k) if prev else None
        delta: Optional[float] = None
        pct: Optional[float] = None
        if isinstance(c, (int, float)) and isinstance(p, (int, float)):
            delta = c - p
            try:
                denom = p if abs(p) > 1e-9 else None
                pct = ((c - p) / denom * 100.0) if denom is not None else None
            except Exception:
                pct = None
        trend[k] = {
            "current": float(c) if isinstance(c, (int, float)) else None,
            "previous": float(p) if isinstance(p, (int, float)) else None,
            "delta": delta,
            "pct": pct,
        }
    return trend


def render_trend_md(trend: Dict[str, Dict[str, Optional[float]]]) -> str:
    def arrow(d: Optional[float]) -> str:
        if d is None:
            return ""
        return "▲" if d > 0 else ("▼" if d < 0 else "=")

    lines = [
        "# Governance Metrics Snapshot Trend",
        "",
        "Key | Current | Previous | Δ | % | Trend",
        "--- | ---: | ---: | ---: | ---: | :--:",
    ]
    for k, v in trend.items():
        cur = v["current"]
        prev = v["previous"]
        d = v["delta"]
        pct_v = v["pct"]
        lines.append(
            f"{k} | {cur if cur is not None else '-'} | {prev if prev is not None else '-'} | "
            f"{d if d is not None else '-'} | {round(pct_v, 2) if pct_v is not None else '-'} | {arrow(d)}"
        )
    return "\n".join(lines) + "\n"


def _auto_prev_in_dir(out_dir: Path) -> Optional[Path]:
    if not out_dir.exists():
        return None
    candidates = sorted(out_dir.glob("snapshot_*.json"))
    return candidates[-1] if candidates else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate governance metrics snapshot from TASK_REGISTRY"
    )
    parser.add_argument(
        "--output-json",
        default="metrics_snapshot.json",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--trend-md", default=None, help="Optional Trend Markdown output path"
    )
    parser.add_argument(
        "--prev", default=None, help="Path to previous snapshot JSON to diff against"
    )
    parser.add_argument(
        "--out-dir",
        default=str(NAOS_ROOT / "metrics" / "snapshots"),
        help="Directory to store timestamped snapshots",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    prev_path = Path(args.prev) if args.prev else _auto_prev_in_dir(out_dir)
    prev = _load_prev_snapshot(prev_path)

    curr = collect_snapshot()
    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime(curr["generated_at"]))
    stamped_path = out_dir / f"snapshot_{ts}.json"
    stamped_path.write_text(json.dumps(curr, indent=2))

    latest_path = Path(args.output_json)
    latest_path.write_text(json.dumps(curr, indent=2))

    trend = compute_trend(curr, prev)
    if args.trend_md:
        Path(args.trend_md).write_text(render_trend_md(trend))

    print(f"Wrote snapshot to {stamped_path}")
    print(
        f"  tasks: {curr['tasks_done']}/{curr['tasks_total']} ({curr['completion_pct']}%)"
    )
    print(
        f"  requirements: {curr['requirements_delivered']}/{curr['requirements_total']} ({curr['requirements_pct']}%)"
    )
    if prev_path:
        print(f"  compared against: {prev_path}")
    if args.trend_md:
        print(f"  trend markdown: {args.trend_md}")


if __name__ == "__main__":
    main()
