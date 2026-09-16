#!/usr/bin/env python3
"""
generate_naos_dashboard.py - Generate a consolidated PM dashboard (naos/DASHBOARD.md).

SOURCES:
    - NAOS_ROOT/TASK_REGISTRY.yaml — canonical tasks and statuses
    - specs/03-requirements.md — FR/NFR definitions and statuses
    - NAOS_ROOT/RELEASE_NOTES.md — recent entries
    - NAOS_ROOT/PROJECT_STATUS.md — risks, blockers, ADR-lite decisions
    - NAOS_ROOT/TRACEABILITY_MATRIX.md — traceability metrics (if generated)
    - NAOS_ROOT/TASK_PROGRESS_HISTORY.csv — completion trend (appended each run)
    - NAOS_ROOT/completed/GOV-*.md — governance sprint cards (optional)
    - NAOS_ROOT/reports/conformance_latest.json — autoresearch conformance results (optional)
    - NAOS_ROOT/reports/eval_log.jsonl — AI output eval pass rates (optional)

OUTPUT:
    - NAOS_ROOT/DASHBOARD.md

SECTIONS GENERATED:
    1. Executive Summary (narrative + key metrics table)
    2. Timeline (Gantt chart)
    3. Task Progress (canonical list with badges)
    4. Requirement Coverage (FR/NFR summary)
    5. Traceability Health (from TRACEABILITY_MATRIX.md if available)
    6. Governance Sprint History (from naos/completed/ if available)
    7. Risks (from PROJECT_STATUS.md Risk Register)
    8. Recent Releases
    9. Decisions
    10. AI Quality (conformance + eval pass rates — rendered only when data present)
    11. Quick Actions
    12. Next Steps

USAGE:
    python scripts/workflows/generate_naos_dashboard.py

ENVIRONMENT:
    NAOS_ROOT  — path to the naos/ governance folder (default: "naos")
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

# Module-level team filter — set by main() before render_dashboard() is called.
# None = no filter (all tasks). Backward-compatible: default behaviour unchanged.
_TEAM_FILTER: str | None = None

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    dashboard_output_path,
    default_naos_root,
    evidence_pack_output_path,
    exit_code_for_summary,
    external_reference_status,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    test_map_output_path,
    write_report,
)
from naos_self_check import self_check_finding_occurrences  # noqa: E402
from naos_systemic_impact import (  # noqa: E402
    build_actionable_presentation,
    finding_occurrence,
    presentation_lines,
    systemic_finding_occurrences,
)
from naos_task_lifecycle import (  # noqa: E402
    is_task_delivered,
    normalize_task_states,
    task_terminal_state,
)
from naos_validate_task_registry import (  # noqa: E402
    TeamConfigValidationError,
    require_valid_team_config,
)
from source_roots import existing_source_roots  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

REGISTRY_FILE = NAOS_ROOT / "TASK_REGISTRY.yaml"
EXEC_FILE = Path("specs/10-execution.md")
REQ_FILE = Path("specs/03-requirements.md")
PROJECT_STATUS_FILE = NAOS_ROOT / "PROJECT_STATUS.md"
COVERAGE_BASELINE_FILE = NAOS_ROOT / "metrics/test_coverage.json"

REL_NOTES = NAOS_ROOT / "RELEASE_NOTES.md"
OUT_FILE = NAOS_ROOT / "DASHBOARD.md"
TREND_FILE = NAOS_ROOT / "TASK_PROGRESS_HISTORY.csv"
TRACEABILITY_FILE = NAOS_ROOT / "TRACEABILITY_MATRIX.md"
DOCS_INDEX = Path("docs/DOCS_INDEX.md")
RULES_FILE = Path(".ai/RULES.md")
GOV_COMPLETED_DIR = NAOS_ROOT / "completed"
CONFORMANCE_FILE = NAOS_ROOT / "reports" / "conformance_latest.json"
EVAL_LOG_FILE = NAOS_ROOT / "reports" / "eval_log.jsonl"

REQ_STATUS_RE = re.compile(r"^\*\*Status\*\*:\s*(.+)$", re.M)
REQ_HEADER_RE = re.compile(r"^###\s+(FR|NFR)-(\d{3}):\s*(.+)$", re.M)


def configure_naos_root(naos_root: str | Path) -> None:
    """Update generated-project path globals for the selected NAOS root."""
    global NAOS_ROOT
    global REGISTRY_FILE
    global PROJECT_STATUS_FILE
    global COVERAGE_BASELINE_FILE
    global REL_NOTES
    global OUT_FILE
    global TREND_FILE
    global TRACEABILITY_FILE
    global GOV_COMPLETED_DIR
    global CONFORMANCE_FILE
    global EVAL_LOG_FILE

    NAOS_ROOT = Path(naos_root)
    REGISTRY_FILE = NAOS_ROOT / "TASK_REGISTRY.yaml"
    PROJECT_STATUS_FILE = NAOS_ROOT / "PROJECT_STATUS.md"
    COVERAGE_BASELINE_FILE = NAOS_ROOT / "metrics/test_coverage.json"
    REL_NOTES = NAOS_ROOT / "RELEASE_NOTES.md"
    OUT_FILE = NAOS_ROOT / "DASHBOARD.md"
    TREND_FILE = NAOS_ROOT / "TASK_PROGRESS_HISTORY.csv"
    TRACEABILITY_FILE = NAOS_ROOT / "TRACEABILITY_MATRIX.md"
    GOV_COMPLETED_DIR = NAOS_ROOT / "completed"
    CONFORMANCE_FILE = NAOS_ROOT / "reports" / "conformance_latest.json"
    EVAL_LOG_FILE = NAOS_ROOT / "reports" / "eval_log.jsonl"


def _read_pytest_coverage() -> tuple[float, float]:
    """Read test coverage percentage and target.

    Source priority:
      1. .coverage SQLite DB  (live — most recent test run)
      2. naos/metrics/test_coverage.json  (committed — last known measurement)
      3. 0.0  (no data available)

    Returns (coverage_pct, target_pct).
    """
    target = 60.0

    baseline_pct = 0.0
    if COVERAGE_BASELINE_FILE.exists():
        try:
            data = json.loads(COVERAGE_BASELINE_FILE.read_text(encoding="utf-8"))
            baseline_pct = float(data.get("coverage_pct", 0))
            target = float(data.get("target", target))
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    live_pct = _read_live_coverage()
    if live_pct is not None:
        return live_pct, target

    return baseline_pct, target


def _read_live_coverage() -> float | None:
    """Read actual coverage from the .coverage database if present."""
    coverage_db = Path(".coverage")
    if not coverage_db.exists():
        return None

    try:
        result = subprocess.run(
            ["coverage", "report", "--format=total"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return float(result.stdout.strip())
    except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
        pass

    try:
        result = subprocess.run(
            ["coverage", "report"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            for line in reversed(result.stdout.splitlines()):
                m = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", line)
                if m:
                    return float(m.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def _phase_num(task: dict) -> float:
    """Convert task phase string to float for comparison."""
    try:
        return float(task.get("phase", "999"))
    except (ValueError, TypeError):
        return 999.0


def parse_task_matrix() -> list[dict]:
    """Parse tasks from TASK_REGISTRY.yaml.

    When _TEAM_FILTER is set (via --team CLI flag), only tasks in scope for
    that team are returned. Requires team_config.enabled=true in the registry.
    When disabled or unset, all tasks are returned for backward compatibility.
    """
    if not REGISTRY_FILE.exists() or yaml is None:
        return []

    data = yaml.safe_load(REGISTRY_FILE.read_text(encoding="utf-8"))
    raw_tasks = data.get("tasks", [])

    # Apply the team filter when requested.
    if _TEAM_FILTER:
        raw_tasks = _filter_raw_tasks_by_team(raw_tasks, _TEAM_FILTER, data)

    status_map = {
        "implemented": "Implemented",
        "verified": "Verified",
        "in_progress": "In Progress",
        "planned": "Planned",
        "deferred": "Deferred",
        "absorbed": "Absorbed",
        "done": "Implemented",
    }

    tasks = []
    for t in raw_tasks:
        raw_status = str(t.get("status", "planned")).split("#")[0].strip().lower()
        states = normalize_task_states(t)
        if is_task_delivered(t):
            display_status = "Verified"
        elif states.get("compatibility_status") == "unsupported":
            display_status = f"Unsupported Legacy Status ({states['legacy_status']})"
        elif states["lifecycle_state"] == "implementation_complete":
            display_status = "Implementation Complete"
        else:
            display_status = status_map.get(raw_status, raw_status.title())

        raw_deps = t.get("dependencies", [])
        dep_ids = []
        if isinstance(raw_deps, list):
            for d in raw_deps:
                m = re.match(r"((?:T|GOV)-\d{3,4}[A-Z]?(?:-\w+)?)", str(d))
                if m:
                    dep_ids.append(m.group(1))
        elif isinstance(raw_deps, str):
            dep_ids = re.findall(r"(?:T|GOV)-\d{3,4}[A-Z]?(?:-\w+)?", raw_deps)

        estimate_days = t.get("estimate_days", 2)
        tasks.append(
            {
                "id": t.get("id", ""),
                "title": t.get("title", ""),
                "phase": str(t.get("phase", "")),
                "type": "Implementation",
                "req": t.get("requirement", ""),
                "status": display_status,
                "target": t.get("target_end", ""),
                "completion_date": t.get("completion_date", ""),
                "planned_hours": estimate_days * 8,
                "priority": t.get("priority", "P2"),
                "estimate_days": estimate_days,
                "dependencies": dep_ids,
                "lifecycle_state": states["lifecycle_state"],
                "delivery_state": states["delivery_state"],
                "verification_state": states["verification_state"],
                "compatibility_status": states.get("compatibility_status"),
                "legacy_status": states.get("legacy_status"),
                "human_review_required": states.get("compatibility_status") == "unsupported",
            }
        )

    def phase_sort_key(task):
        try:
            return float(task["phase"])
        except (ValueError, TypeError):
            return 999.0

    tasks.sort(key=lambda t: (phase_sort_key(t), t["id"]))
    return tasks


def _filter_raw_tasks_by_team(
    raw_tasks: list[dict], team_id: str, registry: dict
) -> list[dict]:
    """Filter raw task dicts to those in scope for the given team.

    Mirrors filter_tasks_by_team() in sync_from_registry.py.
    Returns all tasks unchanged if team_config.enabled == False or team not found
    with zero blast radius.
    """
    team_config = require_valid_team_config(registry)
    if not team_config["enabled"]:
        print(
            f"ℹ️  team_config.enabled=false — returning all tasks (ignoring --team {team_id})"
        )
        return raw_tasks

    teams = team_config["teams"]
    team = next((t for t in teams if t.get("id") == team_id), None)
    if team is None:
        print(f"⚠️  Team '{team_id}' not found in team_config — returning all tasks")
        return raw_tasks

    scope = set(team.get("scope", []))
    if not scope:
        print(f"ℹ️  Team '{team_id}' has empty scope — returning all tasks")
        return raw_tasks

    assignment_mode = team_config["assignment_mode"]
    if assignment_mode == "task_scope":
        filtered = [t for t in raw_tasks if t.get("id") in scope]
    elif assignment_mode == "phase_scope":
        filtered = [t for t in raw_tasks if str(t.get("phase", "")) in scope]
    elif assignment_mode == "module_scope":
        filtered = [t for t in raw_tasks if t.get("owner", "") in scope]
    else:  # pragma: no cover - require_valid_team_config closes this state.
        raise TeamConfigValidationError(
            f"Invalid team_config: unsupported assignment_mode {assignment_mode!r}"
        )

    print(
        f"👥 Team filter: '{team_id}' → {len(filtered)} of {len(raw_tasks)} tasks in scope"
    )
    return filtered


def parse_authoritative_counts(specs_path: Path) -> dict:
    """Parse FR/NFR status counts from specs/03-requirements.md."""
    if not specs_path.exists():
        return {
            "fr": (0, 0, 0, 0),
            "nfr": (0, 0, 0, 0),
            "all": (0, 0, 0, 0),
            "fr_complete": [],
            "fr_in_progress": [],
            "fr_planned": [],
            "nfr_complete": [],
            "nfr_in_progress": [],
            "nfr_planned": [],
        }
    text = specs_path.read_text(encoding="utf-8")
    fr_complete, fr_in_progress, fr_planned = [], [], []
    nfr_complete, nfr_in_progress, nfr_planned = [], [], []

    fr_pattern = re.compile(
        r"^## (FR-[A-Z0-9-]+):[\s\S]*?^\*\*Status\*\*:\s*([^\n]+)", re.M
    )
    nfr_pattern = re.compile(r"^## (NFR-\d+):[\s\S]*?^\*\*Status\*\*:\s*([^\n]+)", re.M)

    for rid, status in fr_pattern.findall(text):
        s = status.lower()
        if "verif" in s or "implement" in s or "complete" in s:
            fr_complete.append(rid)
        elif "progress" in s:
            fr_in_progress.append(rid)
        else:
            fr_planned.append(rid)

    for rid, status in nfr_pattern.findall(text):
        s = status.lower()
        if "progress" in s:
            nfr_in_progress.append(rid)
        elif "verif" in s or "implement" in s or "complete" in s:
            nfr_complete.append(rid)
        else:
            nfr_planned.append(rid)

    return {
        "fr": (
            len(fr_complete) + len(fr_in_progress) + len(fr_planned),
            len(fr_complete),
            len(fr_in_progress),
            len(fr_planned),
        ),
        "nfr": (
            len(nfr_complete) + len(nfr_in_progress) + len(nfr_planned),
            len(nfr_complete),
            len(nfr_in_progress),
            len(nfr_planned),
        ),
        "all": (
            len(fr_complete)
            + len(fr_in_progress)
            + len(fr_planned)
            + len(nfr_complete)
            + len(nfr_in_progress)
            + len(nfr_planned),
            len(fr_complete) + len(nfr_complete),
            len(fr_in_progress) + len(nfr_in_progress),
            len(fr_planned) + len(nfr_planned),
        ),
        "fr_complete": fr_complete,
        "fr_in_progress": fr_in_progress,
        "fr_planned": fr_planned,
        "nfr_complete": nfr_complete,
        "nfr_in_progress": nfr_in_progress,
        "nfr_planned": nfr_planned,
    }


def load_registry_metrics() -> dict | None:
    """Dynamically compute task counts from TASK_REGISTRY.yaml."""
    if not REGISTRY_FILE.exists() or yaml is None:
        return None
    try:
        data = yaml.safe_load(REGISTRY_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    tasks = data.get("tasks", [])
    if not tasks:
        return None
    done = sum(1 for task in tasks if is_task_delivered(task))
    total = len(tasks)
    pct = round(done / total * 100, 1) if total else 0.0
    return {"total": total, "done": done, "pct": pct}


def parse_governance_status() -> dict:
    """Check governance compliance."""
    stats = {"rules_defined": False, "docs_indexed": False, "pre_commit_hook": False}

    if RULES_FILE.exists():
        stats["rules_defined"] = True

    if DOCS_INDEX.exists():
        text = DOCS_INDEX.read_text(encoding="utf-8")
        if len(text.splitlines()) > 5:
            stats["docs_indexed"] = True

    if Path(".githooks/pre-commit").exists():
        stats["pre_commit_hook"] = True

    return stats


def parse_conformance_metrics() -> dict | None:
    """Read naos/reports/conformance_latest.json. Returns None if absent."""
    if not CONFORMANCE_FILE.exists():
        return None
    try:
        return json.loads(CONFORMANCE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def parse_eval_metrics() -> list[dict]:
    """Read naos/reports/eval_log.jsonl — latest entry per feature."""
    if not EVAL_LOG_FILE.exists():
        return []
    entries: dict[str, dict] = {}
    try:
        for line in EVAL_LOG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            feature = entry.get("feature", "unknown")
            # Keep the latest entry per feature (last line wins)
            entries[feature] = entry
    except Exception:
        return []
    return list(entries.values())


def parse_recent_release_notes(limit: int = 5) -> list[str]:
    """Read last entries from RELEASE_NOTES.md."""
    if not REL_NOTES.exists():
        return []
    text = REL_NOTES.read_text(encoding="utf-8")
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("-"):
            continue
        if line.startswith("- ----"):
            continue
        entries.append(line)
    return entries[-limit:]


def parse_risks() -> list[dict]:
    """Parse risks from PROJECT_STATUS.md Risk Register."""
    if not PROJECT_STATUS_FILE.exists():
        return []

    text = PROJECT_STATUS_FILE.read_text(encoding="utf-8")

    m = re.search(
        r"## ⚠️ Risk Register \(Active\)[\s\S]*?\n\s*\|[^\n]+\n\s*\|[-\s|]+\n((?:\|[^\n]+\n)+)",
        text,
    )
    if not m:
        return []

    rows = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"\|\s*-{2,}\s*\|", line):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 7 or cols[0] == "ID":
            continue
        rows.append(
            {
                "id": cols[0].strip("*"),
                "risk": cols[1],
                "score": cols[4],
                "status": cols[5],
                "mitigation": cols[6] if len(cols) > 6 else "",
            }
        )

    return rows


def parse_dependencies() -> list[tuple[str, str]]:
    """Parse dependencies from specs/10-execution.md DEP_GRAPH section."""
    if not EXEC_FILE.exists():
        return []
    text = EXEC_FILE.read_text(encoding="utf-8")
    m = re.search(r"<!-- BEGIN DEP_GRAPH -->([\s\S]*?)<!-- END DEP_GRAPH -->", text)
    if not m:
        return []
    deps: list[tuple[str, str]] = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"\|\s*-{2,}\s*\|", line):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if cols[0] == "Task" or len(cols) < 3:
            continue
        task = cols[0]
        depends = cols[1]
        if task and depends:
            deps.append((task, depends))
    return deps


def infer_logical_dependencies(tasks: list[dict]) -> list[tuple[str, str]]:
    """Extract logical task dependencies from registry data."""
    deps = []
    task_ids = {t["id"] for t in tasks}

    for t in tasks:
        for dep_id in t.get("dependencies", []):
            if dep_id in task_ids:
                deps.append((t["id"], dep_id))

    return deps


def remove_cycles(
    deps: list[tuple[str, str]], tasks: list[dict]
) -> list[tuple[str, str]]:
    """Remove circular dependencies using Kahn's algorithm with edge pruning."""
    from collections import deque

    graph: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = defaultdict(int)
    all_tasks = {t["id"] for t in tasks}

    for t in tasks:
        if t["id"] not in in_degree:
            in_degree[t["id"]] = 0

    for task, depends_on in deps:
        if task in all_tasks and depends_on in all_tasks:
            graph[depends_on].append(task)
            in_degree[task] += 1
            if depends_on not in in_degree:
                in_degree[depends_on] = 0

    queue = deque([node for node in in_degree if in_degree[node] == 0])
    topo_order = []
    temp_in_degree = dict(in_degree)

    while queue:
        node = queue.popleft()
        topo_order.append(node)
        for neighbor in graph[node]:
            temp_in_degree[neighbor] -= 1
            if temp_in_degree[neighbor] == 0:
                queue.append(neighbor)

    if len(topo_order) < len(in_degree):
        valid_edges = []
        topo_pos = {t: i for i, t in enumerate(topo_order)}

        for task, depends_on in deps:
            if task in topo_pos and depends_on in topo_pos:
                if topo_pos[depends_on] < topo_pos[task]:
                    valid_edges.append((task, depends_on))

        return valid_edges

    return [(task, dep) for task, dep in deps if task in all_tasks and dep in all_tasks]


def parse_traceability_metrics() -> dict:
    """Parse enhanced traceability matrix for coverage metrics."""
    if not TRACEABILITY_FILE.exists():
        return {}

    text = TRACEABILITY_FILE.read_text(encoding="utf-8")
    metrics = {}

    m = re.search(r"- \*\*Total Code Files\*\*:\s*(\d+)", text)
    if m:
        metrics["total_files"] = int(m.group(1))

    m = re.search(r"- \*\*Files with Requirements\*\*:\s*(\d+)\s*\(([0-9.]+)%\)", text)
    if m:
        metrics["files_with_reqs"] = int(m.group(1))
        metrics["files_coverage_pct"] = float(m.group(2))

    m = re.search(r"- \*\*Total Linkages\*\*:\s*(\d+)", text)
    if m:
        metrics["total_linkages"] = int(m.group(1))

    m = re.search(
        r"- \*\*Requirements Traced\*\*:\s*(\d+)/(\d+)\s*\(([0-9.]+)%\)", text
    )
    if m:
        metrics["reqs_traced"] = int(m.group(1))
        metrics["reqs_total"] = int(m.group(2))
        metrics["reqs_traced_pct"] = float(m.group(3))

    m = re.search(r"- \*\*Spec ID Tags Extracted\*\*:\s*(\d+)", text)
    if m:
        metrics["spec_tags"] = int(m.group(1))

    unimplemented = text.count("⚠️ Not Implemented")
    metrics["unimplemented_reqs"] = unimplemented

    pain_tags = len(re.findall(r"\{#PAIN-[\d\.]+\}", text))
    sol_tags = len(re.findall(r"\{#SOL-[\d\.]+\}", text))
    arch_tags = len(re.findall(r"\{#ARCH-[\d\.]+\}", text))
    api_tags = len(re.findall(r"\{#API-[\d\.]+\}", text))

    metrics["tag_breakdown"] = {
        "pain": pain_tags,
        "solutions": sol_tags,
        "architecture": arch_tags,
        "api": api_tags,
    }

    return metrics


def check_source_freshness() -> list[dict]:
    """Check if critical source files are up-to-date relative to code changes."""
    sources = [
        {"path": EXEC_FILE, "name": "Execution Spec", "critical": True},
        {"path": PROJECT_STATUS_FILE, "name": "Project Status", "critical": True},
        {"path": TRACEABILITY_FILE, "name": "Traceability Matrix", "critical": False},
        {"path": REL_NOTES, "name": "Release Notes", "critical": False},
        {"path": REGISTRY_FILE, "name": "Task Registry", "critical": True},
        {"path": REQ_FILE, "name": "Requirements Spec", "critical": True},
    ]

    # Get latest code modification time from explicit or inferred source roots.
    src_paths = existing_source_roots(Path.cwd())
    latest_code_mtime = 0.0
    try:
        for src_path in src_paths:
            if src_path.exists():
                for p in src_path.rglob("*"):
                    if (
                        p.is_file()
                        and "__pycache__" not in p.parts
                        and not p.name.startswith(".")
                    ):
                        mtime = p.stat().st_mtime
                        latest_code_mtime = max(latest_code_mtime, mtime)
    except Exception:
        pass

    if latest_code_mtime == 0:
        return []

    alerts = []
    now = datetime.now(UTC).timestamp()

    for src in sources:
        p = src["path"]
        if not p.exists():
            alerts.append(
                {
                    "file": src["name"],
                    "status": "❌ Missing",
                    "msg": f"File {p} not found",
                }
            )
            continue

        mtime = p.stat().st_mtime
        age_hours = (now - mtime) / 3600
        code_gap_hours = (latest_code_mtime - mtime) / 3600

        if code_gap_hours > 24 and src["critical"]:
            alerts.append(
                {
                    "file": src["name"],
                    "status": "⚠️ Stale",
                    "msg": f"Code updated {int(code_gap_hours)}h after spec. Review needed.",
                }
            )
        else:
            alerts.append(
                {
                    "file": src["name"],
                    "status": "✅ Fresh",
                    "msg": f"Updated {int(age_hours)}h ago",
                }
            )

    return alerts


def parse_governance_sprints() -> list[dict]:
    """Parse completed governance sprint cards from naos/completed/GOV-*.md."""
    if not GOV_COMPLETED_DIR.exists():
        return []

    sprints = []
    gov_files = sorted(GOV_COMPLETED_DIR.glob("GOV-*.md"))

    for fpath in gov_files:
        text = fpath.read_text(encoding="utf-8")
        record: dict = {"file": fpath.name}

        title_m = re.search(r"^# .+?:\s*(GOV-\d+)\s*[-–—]\s*(.+)$", text, re.M)
        if title_m:
            record["id"] = title_m.group(1)
            record["title"] = title_m.group(2).strip()
        else:
            id_m = re.search(r"(GOV-\d+)", fpath.stem)
            record["id"] = id_m.group(1) if id_m else fpath.stem
            record["title"] = fpath.stem.replace("_", " ").title()

        table_m = re.search(
            r"## Quick Reference[\s\S]*?\|[^\n]+\n\|[-\s|]+\n((?:\|[^\n]+\n)+)",
            text,
        )
        if table_m:
            for row in table_m.group(1).splitlines():
                row = row.strip()
                if not row.startswith("|"):
                    continue
                cols = [c.strip().strip("*") for c in row.strip("|").split("|")]
                if len(cols) < 2:
                    continue
                field = cols[0].lower()
                value = cols[1]
                if field in ("id", "task id"):
                    record["id"] = value
                elif field == "type":
                    record["type"] = value
                elif field == "category":
                    record["category"] = value
                elif field == "created":
                    record["created"] = value

        ps_m = re.search(r"## Problem Statement\s*\n\s*\n(.+?)(?:\n\n|\n#)", text, re.S)
        if ps_m:
            brief = ps_m.group(1).strip().split("\n")[0][:120]
            if len(ps_m.group(1).strip().split("\n")[0]) > 120:
                brief += "…"
            record["brief"] = brief

        sprints.append(record)

    return sprints


def parse_decisions() -> list[dict]:
    """Parse recent decisions from PROJECT_STATUS.md ADR-lite section."""
    if not PROJECT_STATUS_FILE.exists():
        return []
    text = PROJECT_STATUS_FILE.read_text(encoding="utf-8")

    m = re.search(
        r"## 📝 Recent Decisions \(ADR-lite\)[\s\S]*?\n\s*\|[^\n]+\n\s*\|[-\s|]+\n((?:\|[^\n]+\n)+)",
        text,
    )
    if not m:
        return []

    rows = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"\|\s*-{2,}\s*\|", line):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 5 or cols[0] == "Date":
            continue
        rows.append(
            {
                "id": cols[1],
                "date": cols[0],
                "title": cols[2],
                "decision": cols[3],
                "cons": cols[4],
            }
        )
    return rows


def parse_trend_history() -> list[float]:
    """Parse real done_percent history from TASK_PROGRESS_HISTORY.csv."""
    if not TREND_FILE.exists():
        return []
    values: list[float] = []
    for line in TREND_FILE.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("timestamp"):
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        try:
            values.append(float(parts[1]))
        except ValueError:
            continue
    return values if len(values) >= 2 else []


def render_trend_sparkline(values: list[float]) -> str:
    """Render a Unicode block sparkline for trend data."""
    if not values:
        return "(Insufficient history for trend)"
    blocks = "▁▂▃▄▅▆▇█"
    min_v = min(values)
    max_v = max(values)
    span = max(max_v - min_v, 1e-9)
    chars = []
    for v in values:
        idx = int((v - min_v) / span * (len(blocks) - 1))
        chars.append(blocks[idx])
    return "Trend: " + "".join(chars) + f" (latest {values[-1]:.1f}%)"


def parse_blockers() -> list[str]:
    """Parse blockers from PROJECT_STATUS.md Critical Blockers section."""
    if not PROJECT_STATUS_FILE.exists():
        return []
    text = PROJECT_STATUS_FILE.read_text(encoding="utf-8")

    m = re.search(
        r"## 🛑 Critical Blockers & Constraints[\s\S]*?\n\s*\|[^\n]+\n\s*\|[-\s|]+\n((?:\|[^\n]+\n)+)",
        text,
    )
    if not m:
        return []

    blockers = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"\|\s*-{2,}\s*\|", line):
            continue
        cols = [c.strip().strip("*") for c in line.strip("|").split("|")]
        if len(cols) < 5 or cols[0] == "ID":
            continue
        status = cols[3]
        if "ACTIVE" in status.upper() or "🔴" in status:
            blockers.append(f"⛔ **{cols[0]}**: {cols[1]} — {cols[4]}")
    return blockers


def scan_ghost_features(reqs: dict) -> list[str]:
    """Scan codebase for 'Implements: FR-XXX' where FR-XXX is Planned."""
    ghosts = []
    try:
        seen_frs: set[str] = set()
        for src_root in existing_source_roots(Path.cwd()):
            for py_file in src_root.rglob("*.py"):
                if "__pycache__" in py_file.parts:
                    continue
                text = py_file.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"Implements: (FR-\d{3}(-\w+)?)", text):
                    fr_id = m.group(1)
                    if fr_id in seen_frs:
                        continue
                    seen_frs.add(fr_id)

                    if fr_id in reqs:
                        status = reqs[fr_id]["status"]
                        if status in ["Planned", "Phase 6", "🔴 PHASE 6"]:
                            ghosts.append(
                                f"👻 **Ghost Feature**: Code implements `{fr_id}` but status is '{status}'. Update `specs/10-execution.md`!"
                            )
    except Exception as e:
        print(f"Error scanning for ghosts: {e}")

    return list(set(ghosts))


def read_json_artifact(path: Path | None, label: str, missing_status: str = "missing") -> dict[str, Any]:
    if path is None:
        return {
            "label": label,
            "path": None,
            "exists": False,
            "status": "not_configured",
            "data": None,
        }
    if not path.exists():
        return {
            "label": label,
            "path": str(path),
            "exists": False,
            "status": missing_status,
            "data": None,
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "label": label,
            "path": str(path),
            "exists": True,
            "status": "parse_error",
            "error": str(exc),
            "data": None,
        }
    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "status": "present",
        "report_status": data.get("status") if isinstance(data, dict) else None,
        "data": data,
    }


def yaml_mapping(path: Path) -> dict[str, Any] | None:
    if yaml is None or not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def find_capabilities_dir(root: Path, explicit: str | None = None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            root / "capabilities",
            Path(__file__).resolve().parents[2] / "capabilities",
        ]
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def load_capability_contracts(root: Path, profile: str, explicit_dir: str | None = None) -> dict[str, Any]:
    capabilities_dir = find_capabilities_dir(root, explicit_dir)
    capabilities: list[dict[str, Any]] = []
    if capabilities_dir is None:
        return {
            "status": "not_configured",
            "source": None,
            "total": 0,
            "experimental": 0,
            "capabilities": [],
        }

    for path in sorted(capabilities_dir.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        data = yaml_mapping(path)
        if not data:
            continue
        profile_policy = data.get("profiles", {}).get(profile, {}) if isinstance(data.get("profiles"), dict) else {}
        status = str(data.get("status") or "unknown")
        current_maturity = data.get("current_maturity") or profile_policy.get("current_maturity") or data.get("default_maturity")
        capabilities.append(
            {
                "id": data.get("id") or path.stem,
                "name": data.get("name") or path.stem.replace("_", " ").title(),
                "status": status,
                "default_maturity": data.get("default_maturity"),
                "current_maturity": current_maturity,
                "minimum_profile": data.get("minimum_profile"),
                "profile_applicability": profile_policy or {"status": "not_configured"},
                "target_maturity": profile_policy.get("target_maturity"),
                "enforcement": profile_policy.get("enforcement") or data.get("enforcement_default"),
                "experimental": status == "experimental",
                "requires_project_readiness": bool(data.get("requires_project_readiness")),
            }
        )

    return {
        "status": "present" if capabilities else "not_configured",
        "source": str(capabilities_dir),
        "total": len(capabilities),
        "experimental": sum(1 for item in capabilities if item["experimental"]),
        "capabilities": capabilities,
    }


def summarize_claims(artifact: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    findings = data.get("findings") or []
    claims = data.get("claims") or []
    external_status = external_reference_status(policy)
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "claim_count": data.get("claim_count", len(claims) if isinstance(claims, list) else 0),
        "claim_status_counts": dict(Counter(str(claim.get("status", "unknown")) for claim in claims if isinstance(claim, dict))),
        "finding_status_counts": dict(Counter(str(finding.get("status", "unknown")) for finding in findings if isinstance(finding, dict))),
        "overclaim_findings": sum(1 for finding in findings if isinstance(finding, dict) and finding.get("status") == "overclaim"),
        "external_references_unverified": sum(
            1 for finding in findings if isinstance(finding, dict) and finding.get("status") == external_status
        ),
        "revalidation_indicators": sum(
            1
            for finding in findings
            if isinstance(finding, dict)
            and finding.get("status")
            in {"expired", "needs_revalidation", "missing_revalidation_triggers", "invalid_revalidation_trigger"}
        ),
    }


def summarize_self_check(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "checks": [
            {
                "id": check.get("id"),
                "status": check.get("status"),
                "returncode": check.get("returncode"),
            }
            for check in data.get("checks", [])
            if isinstance(check, dict)
        ],
    }


def summarize_capability_maturity_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    capabilities = data.get("capabilities") or []
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": data.get("semantics") or {
            "promotion": "NAOS evaluates maturity readiness; it does not automatically promote, certify, or approve maturity."
        },
        "capabilities": [
            {
                "capability_id": item.get("capability_id"),
                "enabled": item.get("enabled"),
                "current_maturity": item.get("current_maturity"),
                "target_maturity": item.get("target_maturity"),
                "evaluated_status": item.get("evaluated_status"),
                "ready_for_promotion": item.get("ready_for_promotion"),
                "human_approval_required": item.get("human_approval_required"),
                "promotion_recorded": item.get("promotion_recorded"),
                "missing_evidence": item.get("missing_evidence") or [],
                "stale_evidence": item.get("stale_evidence") or [],
                "waivers": item.get("waivers") or [],
                "required_next_actions": item.get("required_next_actions") or [],
            }
            for item in capabilities
            if isinstance(item, dict)
        ],
        "limitations": data.get("limitations") or [],
    }


def summarize_systemic_impact_review(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    families = data.get("artifact_families") or []
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": data.get("semantics") or {
            "report": "NAOS evaluates configured artifact-family review obligations; it does not prove perfect coherence."
        },
        "artifact_families": [
            {
                "family_id": item.get("family_id"),
                "enabled": item.get("enabled"),
                "configured": item.get("configured"),
                "files_found": item.get("files_found") or [],
                "missing_expected": item.get("missing_expected") or [],
                "related_families": item.get("related_families") or [],
                "review_obligations": item.get("review_obligations") or [],
                "evaluated_status": item.get("evaluated_status"),
                "human_review_required": item.get("human_review_required"),
                "limitations": item.get("limitations") or [],
            }
            for item in families
            if isinstance(item, dict)
        ],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
    }


def summarize_module_header_traceability(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": data.get("semantics") or {
            "report": "NAOS evaluates canonical module-header traceability; it does not prove code correctness."
        },
        "scanned_files": [
            {
                "path": item.get("path"),
                "status": item.get("status"),
                "missing_sections": item.get("missing_sections") or [],
                "module_path": item.get("module_path"),
                "human_review_required": item.get("human_review_required"),
            }
            for item in data.get("scanned_files", [])
            if isinstance(item, dict)
        ],
        "legacy_headers": data.get("legacy_headers") or [],
        "missing_headers": data.get("missing_headers") or [],
        "stale_headers": data.get("stale_headers") or [],
        "duplicate_headers": data.get("duplicate_headers") or [],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_spec_cascade_coherence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": data.get("semantics") or {
            "report": "NAOS evaluates deterministic spec-cascade coherence; it does not prove code correctness or complete traceability."
        },
        "findings": data.get("findings") or [],
        "orphan_headers": data.get("orphan_headers") or [],
        "overloaded_frs": data.get("overloaded_frs") or [],
        "stale_statuses": data.get("stale_statuses") or [],
        "uncovered_requirements": data.get("uncovered_requirements") or [],
        "untraced_sources": data.get("untraced_sources") or [],
        "unresolved_source_references": data.get("unresolved_source_references") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_spec_pack_contract(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": {
            "report": (
                "NAOS evaluates deterministic spec-pack template contract conformance, "
                "profile applicability, and deterministic reference resolution; "
                "it does not prove specification quality, approval, implementation, "
                "complete traceability, or compliance."
            )
        },
        "mode": data.get("mode"),
        "specs_root": data.get("specs_root"),
        "manifest": data.get("manifest"),
        "files": data.get("files") or [],
        "traceability_codes": data.get("traceability_codes") or [],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_spec_pack_materialization(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": {
            "report": (
                "NAOS copies or previews missing profile-required spec-pack template files. "
                "It does not fill, approve, validate, implement, test, certify, or prove specifications."
            )
        },
        "dry_run": data.get("dry_run"),
        "force": data.get("force"),
        "source_specs_root": data.get("source_specs_root"),
        "target_specs_root": data.get("target_specs_root"),
        "files": data.get("files") or [],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_spec_assembly_worksheet(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": {
            "report": (
                "NAOS maps adoption evidence and candidate requirements to manifest-declared specs for review. "
                "It does not promote candidates, fill specs, approve requirements, or prove complete traceability."
            )
        },
        "specs_root": data.get("specs_root"),
        "manifest": data.get("manifest"),
        "specs": data.get("specs") or [],
        "candidate_mappings": data.get("candidate_mappings") or [],
        "gap_mappings": data.get("gap_mappings") or [],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_control_plane_review(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": data.get("semantics") or {
            "report": "NAOS evaluates structured governance-surface review and research-routing items; it does not prove completeness."
        },
        "governance_surface_review": data.get("governance_surface_review") or {},
        "research_routing": data.get("research_routing") or {},
        "routing_decisions": [
            {
                "id": item.get("id"),
                "source_type": item.get("source_type"),
                "source_ref": item.get("source_ref"),
                "summary": item.get("summary"),
                "target_surfaces": item.get("target_surfaces") or [],
                "status": item.get("status"),
                "human_review_required": item.get("human_review_required"),
                "known_gap_ref": item.get("known_gap_ref"),
                "residual_risk_ref": item.get("residual_risk_ref"),
                "waiver_ref": item.get("waiver_ref"),
                "required_next_actions": item.get("required_next_actions") or [],
            }
            for item in data.get("routing_decisions", [])
            if isinstance(item, dict)
        ],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "waivers": data.get("waivers") or [],
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_setup_recommendations(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantics": data.get("catalog", {}).get("semantics") or {
            "recommendation": "NAOS recommends setup modules and next actions; it does not automatically enable, approve, or certify them."
        },
        "detected_signals": data.get("detected_signals") or {},
        "profile_guidance": data.get("profile_guidance") or {},
        "configured_modules": data.get("configured_modules") or [],
        "recommended_modules": data.get("recommended_modules") or [],
        "optional_modules": data.get("optional_modules") or [],
        "deferred_modules": data.get("deferred_modules") or [],
        "not_configured_modules": data.get("not_configured_modules") or [],
        "warnings": data.get("warnings") or [],
        "next_actions": data.get("next_actions") or [],
        "limitations": data.get("limitations") or [],
        "human_review_required": bool(data.get("human_review_required")),
    }


def summarize_governance_bypass_posture(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    scans = data.get("scans") if isinstance(data.get("scans"), dict) else {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "hook": scans.get("hook") or {},
        "ci": scans.get("ci") or {},
        "bypass_commit_messages": scans.get("bypass_commit_messages") or [],
        "tier": scans.get("tier") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Governance-bypass posture reports local indicators only. It is not bypass prevention, CI proof, PR approval, certification, or proof of compliance.",
    }


def summarize_external_evidence_ingest(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    scans = data.get("scans") if isinstance(data.get("scans"), dict) else {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": summary,
        "source": scans.get("source"),
        "resolved_source": scans.get("resolved_source"),
        "runs": scans.get("runs") or [],
        "verification_status": summary.get("verification_status") or scans.get("verification_default") or "unverified",
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "External evidence ingest summarizes local SARIF as unverified review evidence. It is not finding verification, approval, attestation, certification, or proof of compliance.",
    }


def summarize_roadmap(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    findings = data.get("findings") or []
    status_counts = Counter(str(item.get("status", "unknown")) for item in findings if isinstance(item, dict))
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "counts": data.get("counts") or {},
        "implemented_without_evidence": status_counts.get("implemented_without_evidence", 0),
        "unmapped_ids": status_counts.get("unmapped_id", 0),
        "referenced_ids_not_in_roadmap": status_counts.get("referenced_id_not_in_roadmap", 0),
        "status_counts": dict(status_counts),
    }


def summarize_function_index(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "index": data.get("index") or {"exists": False},
        "semantic_quality_snapshot": data.get("semantic_quality_snapshot") or {"status": "not_configured"},
        "summary": data.get("summary") or {},
        "limitations": data.get("limitations") or [],
    }


def summarize_evidence_attestation(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "artifact_manifest": [
            {
                "path": item.get("path"),
                "status": item.get("status"),
                "artifact_group": item.get("artifact_group"),
                "digest": item.get("digest"),
                "freshness": item.get("freshness") or {},
            }
            for item in data.get("artifact_manifest", [])
            if isinstance(item, dict)
        ],
        "missing_artifacts": data.get("missing_artifacts") or [],
        "stale_artifacts": data.get("stale_artifacts") or [],
        "uncovered_artifacts": data.get("uncovered_artifacts") or [],
        "reviewer_attestations": data.get("reviewer_attestations") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "waivers": data.get("waivers") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "recommended_next_commands": data.get("recommended_next_commands") or [],
        "next_actions": data.get("next_actions") or [],
        "advisory_non_deterministic_boundary": data.get("advisory_non_deterministic_boundary") or {},
    }


def summarize_evidence_conflicts(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "conflict_count": data.get("conflict_count", 0),
        "conflict_type_counts": data.get("conflict_type_counts") or {},
        "separation_of_duties_warnings": data.get("separation_of_duties_warnings") or [],
        "stale_attestations": data.get("stale_attestations") or [],
        "missing_reviewer_metadata": data.get("missing_reviewer_metadata") or [],
        "missing_operator_attribution": data.get("missing_operator_attribution") or [],
        "duplicate_attestations": data.get("duplicate_attestations") or [],
        "unrouted_conflicts": data.get("unrouted_conflicts") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Evidence conflict detection flags deterministic review conflicts and metadata gaps; it does not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance.",
    }


def summarize_evidence_verification(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    raw_presence = data.get("signature_entries_present")
    legacy_signed = data.get("signed")
    signature_entries_present = (
        raw_presence
        if isinstance(raw_presence, bool)
        else legacy_signed if isinstance(legacy_signed, bool) else False
    )
    raw_validation_claim = data.get("signature_validation_performed")
    signature_validation_claim_rejected = (
        raw_validation_claim is not None and raw_validation_claim is not False
    )
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "tamper_evident": bool(data.get("tamper_evident")),
        "signed": legacy_signed is True,
        "signature_entries_present": signature_entries_present,
        "signature_validation_performed": False,
        "signature_validation_claim_rejected": signature_validation_claim_rejected,
        "artifacts_checked": data.get("artifacts_checked", 0),
        "artifacts_declared": data.get("artifacts_declared"),
        "input_validation": data.get("input_validation", "unknown"),
        "digest_validation": data.get("digest_validation", "unknown"),
        "manifest_root_validation": data.get("manifest_root_validation", "unknown"),
        "scope_status": data.get("scope_status", "unknown"),
        "required_coverage": data.get("required_coverage") or {"status": "unknown", "missing_count": 0},
        "attestation_status": data.get("attestation_status"),
        "attestation_human_review_required": data.get("attestation_human_review_required"),
        "identity_binding": data.get("identity_binding") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Evidence verification recomputes local artifact digests and the manifest root, then reports tamper-evidence, signature-entry presence, and best-effort Git HEAD metadata. It does not validate third-party signatures, authenticate identities, sign for NAOS, approve work, provide non-repudiation, certify controls, or prove compliance.",
    }


def summarize_task_claims(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") if isinstance(artifact, dict) else {}
    if not isinstance(data, dict):
        data = {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "status": data.get("status") or artifact.get("status"),
        "summary": summary,
        "claim_count": data.get("claim_count", 0),
        "active_claim_count": data.get("active_claim_count", 0),
        "released_claim_count": data.get("released_claim_count", 0),
        "expired_claim_count": data.get("expired_claim_count", 0),
        "stale_claim_count": data.get("stale_claim_count", 0),
        "conflicting_claim_count": data.get("conflicting_claim_count", 0),
        "unknown_operator_claims": data.get("unknown_operator_claims") or [],
        "missing_session_claims": data.get("missing_session_claims") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "findings": data.get("findings") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Task claims coordinate work only; they do not authorize work, approve tasks, prove ownership, prove separation of duties, mark completion, or resolve evidence conflicts.",
    }


def summarize_memory_context_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "memory_readiness": data.get("memory_readiness") or {},
        "provider_posture": data.get("provider_posture") or {},
        "mcp_tool_access": data.get("mcp_tool_access") or {},
        "project_identity": data.get("project_identity") or {},
        "platform_access_matrix": data.get("platform_access_matrix") or [],
        "memory_authorization": data.get("memory_authorization") or {},
        "fallback_readiness": data.get("fallback_readiness") or {},
        "context_pack_readiness": data.get("context_pack_readiness") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_memory_provider_access(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "provider_declared": bool(data.get("provider_declared")),
        "provider_recommended": bool(data.get("provider_recommended")),
        "provider_name": data.get("provider_name"),
        "provider_name_source": data.get("provider_name_source"),
        "provider_configured": bool(data.get("provider_configured")),
        "provider_access_verified": bool(data.get("provider_access_verified")),
        "provider_access_method": data.get("provider_access_method"),
        "provider_binary_detected": bool(data.get("provider_binary_detected")),
        "provider_data_dir_source": data.get("provider_data_dir_source"),
        "provider_data_dir_exists": bool(data.get("provider_data_dir_exists")),
        "provider_database_exists": bool(data.get("provider_database_exists")),
        "mcp_access_verified": bool(data.get("mcp_access_verified")),
        "project_identity": data.get("project_identity") or {},
        "mcp_config_files_detected": data.get("mcp_config_files_detected") or [],
        "mcp_servers_declared": data.get("mcp_servers_declared") or [],
        "ci_memory_access": data.get("ci_memory_access") or {},
        "fallback_when_unavailable": data.get("fallback_when_unavailable") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_memory_use_policy(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "state_counts": data.get("state_counts") or {},
        "review_status_counts": data.get("review_status_counts") or {},
        "instruction_grade_items": data.get("instruction_grade_items") or [],
        "supporting_context_items": data.get("supporting_context_items") or [],
        "review_pending_items": data.get("review_pending_items") or [],
        "unsafe_instruction_grade_claims": data.get("unsafe_instruction_grade_claims") or [],
        "unsafe_supporting_context_claims": data.get("unsafe_supporting_context_claims") or [],
        "memory_access_prerequisites": data.get("memory_access_prerequisites") or {},
        "policy_item_access_posture": data.get("policy_item_access_posture") or [],
        "recall_trace_readiness": data.get("recall_trace_readiness") or {},
        "audit_event_readiness": data.get("audit_event_readiness") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_learning_loop_review(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "status_counts": data.get("status_counts") or {},
        "type_counts": data.get("type_counts") or {},
        "retrieval_policy_counts": data.get("retrieval_policy_counts") or {},
        "active_learning_records": data.get("active_learning_records") or [],
        "high_authority_active_records": data.get("high_authority_active_records") or [],
        "inactive_learning_records": data.get("inactive_learning_records") or [],
        "redacted_learning_records": data.get("redacted_learning_records") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_failure_mode_observations(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "enabled": bool(data.get("enabled")),
        "failure_mode_observations_declared": bool(data.get("failure_mode_observations_declared")),
        "summary": data.get("summary") or {},
        "mode_observation_counts": data.get("mode_observation_counts") or {},
        "family_observation_counts": data.get("family_observation_counts") or {},
        "source_report_counts": data.get("source_report_counts") or {},
        "observation_reason_code_counts": data.get("observation_reason_code_counts") or {},
        "severity_counts": data.get("severity_counts") or {},
        "related_gate_counts": data.get("related_gate_counts") or {},
        "mapping_basis_counts": data.get("mapping_basis_counts") or {},
        "review_opportunities": data.get("review_opportunities") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": (
            "Failure-mode observations are review statistics derived from local reports. "
            "They are not numeric risk score authority, automatic learning, approval, "
            "blocking, MCP/memory activation, provider/model routing, release authority, "
            "or compliance proof."
        ),
    }


def summarize_adapter_coherence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "rules_source": data.get("rules_source"),
        "propagation_state_source": data.get("propagation_state_source"),
        "profile_posture": data.get("profile_posture") or {},
        "canonical_plugin": data.get("canonical_plugin") or {},
        "canonical_plugins": data.get("canonical_plugins") or [],
        "adapter_surfaces": data.get("adapter_surfaces") or [],
        "project_local_adapters": data.get("project_local_adapters") or [],
        "propagation_links": data.get("propagation_links") or [],
        "propagation_reviews": data.get("propagation_reviews") or [],
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_task_context_pack(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "task_id": data.get("task_id"),
        "summary": data.get("summary") or {},
        "source_artifacts_missing": data.get("source_artifacts_missing") or [],
        "source_artifact_freshness": data.get("source_artifact_freshness") or {},
        "memory_context": data.get("memory_context") or {},
        "commands_to_run": data.get("commands_to_run") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool((data.get("human_review_boundary") or {}).get("required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_native_lifecycle_report(artifact: dict[str, Any], boundary: str) -> dict[str, Any]:
    data = artifact.get("data") or {}
    report = {
        "status": artifact.get("report_status") or artifact.get("status"),
        "task_id": data.get("task_id"),
        "action": data.get("action"),
        "lifecycle_state": data.get("lifecycle_state"),
        "delivery_state": data.get("delivery_state"),
        "requested_verification_state": data.get("requested_verification_state"),
        "effective_verification_state": data.get("effective_verification_state"),
        "verification_prerequisites_met": data.get("verification_prerequisites_met"),
        "completion_verification": data.get("completion_verification") or {},
        "summary": data.get("summary") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "review_reasons": data.get("review_reasons") or [],
        "review_posture_source": data.get("review_posture_source"),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": boundary,
    }
    for review_key in ("canonical_task_review", "traceability_review"):
        if isinstance(data.get(review_key), dict):
            report[review_key] = data[review_key]
    return report


def summarize_local_context_index(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "sqlite_artifact": data.get("sqlite_artifact") or {},
        "sqlite_write_coordination": data.get("sqlite_write_coordination") or {},
        "fts_available": bool(data.get("fts_available")),
        "artifact_type_counts": data.get("artifact_type_counts") or {},
        "authority_level_counts": data.get("authority_level_counts") or {},
        "query_modes_supported": data.get("query_modes_supported") or {},
        "future_semantic_layer": data.get("future_semantic_layer") or {},
        "future_graph_layer": data.get("future_graph_layer") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_sqlite_write_coordination(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "target_db_path": data.get("target_db_path"),
        "lock_acquired": bool(data.get("lock_acquired")),
        "atomic_replace_used": bool(data.get("atomic_replace_used")),
        "tables_verified": data.get("tables_verified") or [],
        "target_db_hash": data.get("target_db_hash"),
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_local_context_query(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "query": data.get("query") or {},
        "query_mode_used": data.get("query_mode_used") or [],
        "result_count": data.get("result_count", 0),
        "source_artifacts": data.get("source_artifacts") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_semantic_candidate_layer(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "semantic_runtime_enabled": bool(data.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool(data.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool(data.get("embeddings_enabled")),
        "extension_loading_allowed": bool(data.get("extension_loading_allowed")),
        "external_embedding_calls_allowed": bool(data.get("external_embedding_calls_allowed")),
        "cloud_embedding_allowed": bool(data.get("cloud_embedding_allowed")),
        "candidate_only_policy": data.get("candidate_only_policy") or {},
        "semantic_query_posture": data.get("semantic_query_posture") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_graph_context_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "graph_runtime_enabled": bool(data.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool(data.get("explicit_link_traversal_only", True)),
        "global_graph_scan_allowed": bool(data.get("global_graph_scan_allowed")),
        "graph_database_allowed": bool(data.get("graph_database_allowed")),
        "networkx_enabled": bool(data.get("networkx_enabled")),
        "graphml_enabled": bool(data.get("graphml_enabled")),
        "graph_algorithms_enabled": bool(data.get("graph_algorithms_enabled")),
        "traversal_limits": data.get("traversal_limits") or {},
        "source_authority_policy": data.get("source_authority_policy") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_graph_context_query(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "query": data.get("query") or {},
        "query_mode_used": data.get("query_mode_used") or [],
        "traversal_depth_used": data.get("traversal_depth_used"),
        "result_count": data.get("result_count", 0),
        "source_artifacts": data.get("source_artifacts") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_session_lifecycle(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "mode": data.get("mode"),
        "task_id": data.get("task_id"),
        "summary": data.get("summary") or {},
        "freshness_summary": data.get("freshness_summary") or {},
        "context_posture": data.get("context_posture") or {},
        "memory_posture": data.get("memory_posture") or {},
        "memory_candidate_proposals": data.get("memory_candidate_proposals") or [],
        "recommended_commands": data.get("recommended_commands") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_session_identity(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "session_id": data.get("session_id"),
        "session_report_root": data.get("session_report_root"),
        "sessions_index_path": data.get("sessions_index_path"),
        "latest_report_compatibility": data.get("latest_report_compatibility") or {},
        "session_aware_reports": data.get("session_aware_reports") or [],
        "latest_only_reports": data.get("latest_only_reports") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_operator_attribution(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "operator_id": data.get("operator_id"),
        "operator_source": data.get("operator_source"),
        "operator_attribution_status": data.get("operator_attribution_status"),
        "session_id": data.get("session_id"),
        "privacy_posture": data.get("privacy_posture") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_audit_log(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "event_count": data.get("event_count", 0),
        "event_type_counts": data.get("event_type_counts") or {},
        "invalid_event_count": data.get("invalid_event_count", 0),
        "missing_session_id_events": data.get("missing_session_id_events") or [],
        "missing_operator_id_events": data.get("missing_operator_id_events") or [],
        "audit_logged_sources": data.get("audit_logged_sources") or [],
        "audit_pending_sources": data.get("audit_pending_sources") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_agent_trace_validation(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "event_count": data.get("event_count", 0),
        "valid_event_count": data.get("valid_event_count", 0),
        "invalid_event_count": data.get("invalid_event_count", 0),
        "lifecycle_phase_counts": data.get("lifecycle_phase_counts") or {},
        "action_type_counts": data.get("action_type_counts") or {},
        "forbidden_payload_findings": data.get("forbidden_payload_findings") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_harness_trace_import(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "mode": data.get("mode"),
        "source_format": data.get("source_format"),
        "source_present": bool(data.get("source_present")),
        "write_events": bool(data.get("write_events")),
        "events_written": bool(data.get("events_written")),
        "raw_record_count": data.get("raw_record_count", 0),
        "imported_event_count": data.get("imported_event_count", 0),
        "rejected_record_count": data.get("rejected_record_count", 0),
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_static_grader(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "dimension_summary": data.get("dimension_summary") or {},
        "cost_posture": data.get("cost_posture") or {},
        "budget_posture": data.get("budget_posture") or {},
        "not_evaluated_dimensions": data.get("not_evaluated_dimensions") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_ai_surface_health(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "ai_surface_health_posture": data.get("ai_surface_health_posture") or "missing",
        "context_budget_posture": data.get("context_budget_posture") or "missing",
        "summary": data.get("summary") or {},
        "baseline": data.get("baseline") or {},
        "largest_families": sorted(
            [
                {
                    "id": item.get("id"),
                    "estimated_tokens": item.get("estimated_tokens"),
                    "file_count": item.get("file_count"),
                }
                for item in data.get("families") or []
                if isinstance(item, dict)
            ],
            key=lambda item: int(item.get("estimated_tokens") or 0),
            reverse=True,
        )[:5],
        "combined_scenarios": data.get("combined_scenarios") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_grader_assessment(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "mode": data.get("mode"),
        "summary": data.get("summary") or {},
        "drift": data.get("drift") or {},
        "cost_budget_posture": data.get("cost_budget_posture") or {},
        "cadence_posture": data.get("cadence_posture") or {},
        "llm_readiness": data.get("llm_readiness") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_llm_grader_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "runtime_enabled": bool(data.get("runtime_enabled")),
        "provider_allowed": bool(data.get("provider_allowed")),
        "external_api_allowed": bool(data.get("external_api_allowed")),
        "model_dependency_allowed": bool(data.get("model_dependency_allowed")),
        "api_keys_allowed": bool(data.get("api_keys_allowed")),
        "cost_posture": data.get("cost_posture") or {},
        "data_exposure_posture": data.get("data_exposure_posture") or {},
        "bias_variance_posture": data.get("bias_variance_posture") or {},
        "advisory_boundary": data.get("advisory_boundary") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_behavioral_governance_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "baseline_state_present": bool(data.get("baseline_state_present")),
        "readiness_inputs": data.get("readiness_inputs") or [],
        "impacter_review": data.get("impacter_review") or {},
        "cost_posture": data.get("cost_posture") or {},
        "runtime_posture": data.get("runtime_posture") or {},
        "advisory_boundary": data.get("advisory_boundary") or {},
        "recommended_next_commands": data.get("recommended_next_commands") or [],
        "next_actions": data.get("next_actions") or [],
        "advisory_non_deterministic_boundary": data.get("advisory_non_deterministic_boundary") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_plan_coherence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "implementation_readiness": data.get("implementation_readiness") or {},
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "Plan coherence reviews active task claims, task registry dependencies, module-header task linkage, and versioned implementation-readiness inputs as deterministic coordination evidence. It does not authorize work, sequence execution, resolve conflicts, prove ownership, prove completion, approve implementation, close tasks, merge, or release.",
    }


def summarize_ai_code_provenance(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "manifest": data.get("manifest") or {},
        "supporting_evidence": data.get("supporting_evidence") or [],
        "ai_artifact_evidence": data.get("ai_artifact_evidence") or {},
        "missing_evidence": data.get("missing_evidence") or [],
        "unresolved_questions": data.get("unresolved_questions") or [],
        "authority_boundary": data.get("authority_boundary") or {},
        "runtime_posture": data.get("runtime_posture") or {},
        "cost_posture": data.get("cost_posture") or {},
        "recommended_next_commands": data.get("recommended_next_commands") or [],
        "next_actions": data.get("next_actions") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_compliance_posture(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "manifest": data.get("manifest") or {},
        "supporting_evidence": data.get("supporting_evidence") or [],
        "supporting_report_statuses": data.get("supporting_report_statuses") or {},
        "missing_evidence": data.get("missing_evidence") or [],
        "unresolved_questions": data.get("unresolved_questions") or [],
        "authority_boundary": data.get("authority_boundary") or {},
        "runtime_posture": data.get("runtime_posture") or {},
        "cost_posture": data.get("cost_posture") or {},
        "recommended_next_commands": data.get("recommended_next_commands") or [],
        "next_actions": data.get("next_actions") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_policy_overrides(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "override_summary": data.get("override_summary") or {},
        "team_operator_map": data.get("team_operator_map") or {},
        "overlay_scope": data.get("overlay_scope") or {},
        "overlay_scopes": data.get("overlay_scopes") or [],
        "applied_overlay_scopes": data.get("applied_overlay_scopes") or [],
        "team_ids": data.get("team_ids") or [],
        "operator_overlay_id": data.get("operator_overlay_id"),
        "protected_invariant_violations": data.get("protected_invariant_violations") or [],
        "conflicts": data.get("conflicts") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_pr_governance(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "ci_provider": data.get("ci_provider"),
        "event_name": data.get("event_name"),
        "branch": data.get("branch"),
        "base_ref": data.get("base_ref"),
        "head_ref": data.get("head_ref"),
        "pull_request_number": data.get("pull_request_number"),
        "team_id": data.get("team_id"),
        "team_resolution_source": data.get("team_resolution_source"),
        "reports_generated": data.get("reports_generated") or [],
        "artifact_paths": data.get("artifact_paths") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_pr_risk_classification(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    contributor = data.get("contributor") if isinstance(data.get("contributor"), dict) else {}
    git = data.get("git") if isinstance(data.get("git"), dict) else {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": summary,
        "contributor": {
            "trust": contributor.get("trust"),
            "source": contributor.get("source"),
            "fork": contributor.get("fork"),
        },
        "git": {
            "branch": git.get("branch"),
            "base_ref": git.get("base_ref"),
            "head_ref": git.get("head_ref"),
            "diff_source": (git.get("diff_metadata") or {}).get("diff_source"),
        },
        "changed_files": len(data.get("changed_files") or []),
        "risk_files": summary.get("risk_files", 0),
        "total_findings": summary.get("total_findings", 0),
        "category_counts": summary.get("category_counts") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "rule": "PR risk classification is deterministic path/diff metadata review evidence only. It is not PR approval, malware analysis, sandbox execution, security proof, compliance proof, or release authorization.",
    }


def summarize_agentic_workflow(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "workflow_config_valid": bool(data.get("workflow_config_valid")),
        "missing_artifacts": data.get("missing_artifacts") or [],
        "sections": data.get("sections") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_pre_implementation_alignment(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "mode": data.get("mode"),
        "alignment_valid": bool(data.get("alignment_valid")),
        "question_coverage": data.get("question_coverage") or {},
        "missing_required_questions": data.get("missing_required_questions") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_calibration_shadow(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "calibration_config_valid": bool(data.get("calibration_config_valid")),
        "drift_count": int(data.get("drift_count") or 0),
        "reports_missing": data.get("reports_missing") or [],
        "unexpected_changes": data.get("unexpected_changes") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_evidence_classification(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "policy_valid": bool(data.get("policy_valid")),
        "findings_scanned": int(data.get("findings_scanned") or 0),
        "classification_counts": data.get("classification_counts") or {},
        "missing_classification": data.get("missing_classification") or [],
        "unknown_findings": data.get("unknown_findings") or [],
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_cross_harness_review_readiness(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "config_valid": bool(data.get("config_valid")),
        "declared_harness_count": int(data.get("declared_harness_count") or 0),
        "readiness_score": int(data.get("readiness_score") or 0),
        "requirements_missing": data.get("requirements_missing") or [],
        "requirements_deferred": data.get("requirements_deferred") or [],
        "runtime_execution_enabled": bool(data.get("runtime_execution_enabled")),
        "provider_api_allowed": bool(data.get("provider_api_allowed")),
        "dsse_readiness": data.get("dsse_readiness") or {},
        "findings": data.get("findings") or [],
        "human_review_required": bool(data.get("human_review_required")),
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
    }


def summarize_professional_adoption(artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    keys = [
        "adoption_summary",
        "preflight",
        "intake",
        "install_plan",
        "existing_resource_inventory",
        "ai_artifact_inventory",
        "ai_artifact_reconciliation",
        "memory_resource_inventory",
        "memory_resource_reconciliation",
        "mcp_resource_inventory",
        "brownfield_baseline",
        "candidate_requirements",
        "traceability_gap_register",
        "install_decision_record",
        "context_challenge",
        "repo_context_challenge",
        "plan_challenge",
        "decision_probe",
        "planning_gate_review",
    ]
    statuses: dict[str, Any] = {}
    present = 0
    review_required = 0
    for key in keys:
        artifact = artifacts.get(key, {})
        data = artifact.get("data") or {}
        statuses[key] = artifact.get("report_status") or artifact.get("status")
        present += 1 if artifact.get("exists") else 0
        review_required += 1 if data.get("human_review_required") else 0
    return {
        "status": "present" if present else "missing",
        "reports_expected": len(keys),
        "reports_present": present,
        "reports_review_required": review_required,
        "report_statuses": statuses,
        "human_review_required": bool(review_required),
    }


def summarize_deterministic_hygiene(artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    keys = [
        "duplicate_function_hygiene",
        "secret_hygiene",
        "test_quality_hygiene",
        "dependency_integrity",
        "package_reality",
        "api_symbol_reality",
    ]
    statuses: dict[str, Any] = {}
    summaries: dict[str, Any] = {}
    present = 0
    total_findings = 0
    for key in keys:
        artifact = artifacts.get(key, {})
        data = artifact.get("data") or {}
        statuses[key] = artifact.get("report_status") or artifact.get("status")
        summaries[key] = data.get("summary") or {}
        present += 1 if artifact.get("exists") else 0
        total_findings += int((data.get("summary") or {}).get("total_findings") or 0)
    return {
        "status": "present" if present else "missing",
        "reports_expected": len(keys),
        "reports_present": present,
        "total_findings": total_findings,
        "report_statuses": statuses,
        "summaries": summaries,
        "human_review_required": bool(total_findings),
        "rule": "Deterministic hygiene reports are review evidence only and do not prove semantic correctness, secret-free code, behavioral correctness, API behavior, package safety, approval, or compliance.",
    }


def summarize_test_evidence(map_artifact: dict[str, Any], health_artifact: dict[str, Any]) -> dict[str, Any]:
    map_data = map_artifact.get("data") or {}
    health_data = health_artifact.get("data") or {}
    return {
        "map_status": map_artifact.get("report_status") or map_artifact.get("status"),
        "health_status": health_artifact.get("report_status") or health_artifact.get("status"),
        "map_summary": map_data.get("summary") or {},
        "health_summary": health_data.get("summary") or {},
        "global_coverage_evidence": map_data.get("global_coverage_evidence") or [],
        "coverage_supports_source_default": map_data.get("coverage_supports_source_default", "unknown"),
        "limitations": list(
            dict.fromkeys((map_data.get("limitations") or []) + (health_data.get("limitations") or []))
        ),
    }


def summarize_ac_completion_evidence(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    completions = data.get("completions") if isinstance(data.get("completions"), list) else []
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "configured": bool(data.get("configured")),
        "summary": data.get("summary") or {},
        "repository_bindings": [
            {
                "record_id": item.get("record_id"),
                "ac_id": item.get("ac_id"),
                "record_state": item.get("record_state"),
                "repository_binding": item.get("repository_binding") or {},
            }
            for item in completions
            if isinstance(item, dict) and (item.get("repository_binding") or {}).get("requested")
        ],
        "supersession": [
            {
                "record_id": item.get("record_id"),
                "ac_id": item.get("ac_id"),
                "record_state": item.get("record_state"),
                "supersedes": item.get("supersedes"),
                "superseded_by": item.get("superseded_by"),
                "correction_reason": item.get("correction_reason"),
            }
            for item in completions
            if isinstance(item, dict) and (item.get("supersedes") or item.get("superseded_by"))
        ],
        "findings": data.get("findings") or [],
        "known_gaps": data.get("known_gaps") or [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": data.get("human_review_required", True),
    }


def summarize_evidence_pack(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    summary = data.get("summary") or {}
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": summary,
        "known_gaps": data.get("known_gaps") or [],
        "residual_risks": data.get("residual_risks") or [],
        "exceptions_waivers": data.get("exceptions_waivers") or [],
        "external_references": data.get("external_references") or [],
        "semantics": data.get("semantics") or {},
    }


def summarize_gatekeepers(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    gates = data.get("gates") or []
    return {
        "status": artifact.get("report_status") or artifact.get("status"),
        "summary": data.get("summary") or {},
        "gates": [
            {
                "id": gate.get("id"),
                "name": gate.get("name"),
                "status": gate.get("status"),
                "severity": gate.get("severity"),
                "missing_inputs": gate.get("missing_inputs") or [],
                "missing_evidence": gate.get("missing_evidence") or [],
                "experimental": bool(gate.get("experimental")),
            }
            for gate in gates
            if isinstance(gate, dict)
        ],
    }


def missing_report_findings(
    artifacts: dict[str, dict[str, Any]],
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    for key, artifact in artifacts.items():
        if artifact.get("status") in {"missing", "parse_error"}:
            findings.append(
                {
                    "id": key,
                    "severity": severity,
                    "status": artifact["status"],
                    "message": f"Dashboard input is not available: {artifact.get('path')}",
                }
            )
    return findings


def build_dashboard_summary(
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    args: argparse.Namespace,
    presentation_inputs: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    default_paths = {
        "claims_validation": report_default_path(root, naos_root, policy, "claims_report"),
        "self_check": report_default_path(root, naos_root, policy, "self_check_report"),
        "capability_maturity": report_default_path(root, naos_root, policy, "capability_maturity_report"),
        "systemic_impact": report_default_path(root, naos_root, policy, "systemic_impact_report"),
        "module_header_traceability": report_default_path(root, naos_root, policy, "module_header_traceability_report"),
        "spec_pack_contract": report_default_path(root, naos_root, policy, "spec_pack_contract_report"),
        "spec_pack_materialization": report_default_path(root, naos_root, policy, "spec_pack_materialization_report"),
        "spec_assembly_worksheet": report_default_path(root, naos_root, policy, "spec_assembly_worksheet_report"),
        "spec_cascade_coherence": report_default_path(root, naos_root, policy, "spec_cascade_report"),
        "control_plane_review": report_default_path(root, naos_root, policy, "control_plane_review_report"),
        "setup_recommendations": report_default_path(root, naos_root, policy, "setup_recommendations_report"),
        "governance_bypass_posture": report_default_path(root, naos_root, policy, "governance_bypass_posture_report"),
        "external_evidence_ingest": report_default_path(root, naos_root, policy, "external_evidence_ingest_report"),
        "evidence_attestation": report_default_path(root, naos_root, policy, "evidence_attestation_report"),
        "evidence_verification": report_default_path(root, naos_root, policy, "evidence_verification_report"),
        "evidence_conflicts": report_default_path(root, naos_root, policy, "evidence_conflict_detection_report"),
        "task_claims": report_default_path(root, naos_root, policy, "task_claim_report"),
        "memory_context_readiness": report_default_path(root, naos_root, policy, "memory_context_readiness_report"),
        "memory_provider_access": report_default_path(root, naos_root, policy, "memory_provider_access_report"),
        "memory_use_policy": report_default_path(root, naos_root, policy, "memory_use_policy_report"),
        "learning_loop_review": report_default_path(root, naos_root, policy, "learning_loop_review_report"),
        "failure_mode_observations": report_default_path(root, naos_root, policy, "failure_mode_observations_report"),
        "adapter_coherence": report_default_path(root, naos_root, policy, "adapter_coherence_report"),
        "task_context_pack": report_default_path(root, naos_root, policy, "task_context_pack_report"),
        "task_lifecycle": report_default_path(root, naos_root, policy, "task_lifecycle_report"),
        "research_record": report_default_path(root, naos_root, policy, "research_record_report"),
        "composed_traceability": report_default_path(root, naos_root, policy, "composed_traceability_report"),
        "local_context_index": report_default_path(root, naos_root, policy, "local_context_index_report"),
        "sqlite_write_coordination": report_default_path(root, naos_root, policy, "sqlite_write_coordination_report"),
        "local_context_query": report_default_path(root, naos_root, policy, "local_context_query_report"),
        "semantic_candidate_layer": report_default_path(root, naos_root, policy, "semantic_candidate_layer_report"),
        "graph_context_readiness": report_default_path(root, naos_root, policy, "graph_context_readiness_report"),
        "graph_context_query": report_default_path(root, naos_root, policy, "graph_context_query_report"),
        "session_identity": report_default_path(root, naos_root, policy, "session_identity_report"),
        "operator_attribution": report_default_path(root, naos_root, policy, "operator_attribution_report"),
        "session_lifecycle": report_default_path(root, naos_root, policy, "session_lifecycle_report"),
        "audit_log": report_default_path(root, naos_root, policy, "audit_log_summary_report"),
        "agent_trace_validation": report_default_path(root, naos_root, policy, "agent_trace_validation_report"),
        "harness_trace_import": report_default_path(root, naos_root, policy, "harness_trace_import_report"),
        "ai_surface_health": report_default_path(root, naos_root, policy, "ai_surface_context_budget_report"),
        "static_grader": report_default_path(root, naos_root, policy, "static_grader_report"),
        "grader_assessment": report_default_path(root, naos_root, policy, "grader_assessment_report"),
        "llm_grader_readiness": report_default_path(root, naos_root, policy, "llm_grader_readiness_report"),
        "behavioral_governance_readiness": report_default_path(root, naos_root, policy, "behavioral_governance_readiness_report"),
        "policy_overrides": report_default_path(root, naos_root, policy, "policy_override_merge_report"),
        "plan_coherence": report_default_path(root, naos_root, policy, "plan_coherence_report"),
        "pr_risk_classification": report_default_path(root, naos_root, policy, "pr_risk_classification_report"),
        "pr_governance": report_default_path(root, naos_root, policy, "pr_governance_summary_report"),
        "agentic_workflow": report_default_path(root, naos_root, policy, "agentic_workflow_review_report"),
        "pre_implementation_alignment": report_default_path(root, naos_root, policy, "pre_implementation_alignment_review_report"),
        "calibration_shadow": report_default_path(root, naos_root, policy, "calibration_shadow_report"),
        "evidence_classification": report_default_path(root, naos_root, policy, "evidence_classification_report"),
        "cross_harness_review_readiness": report_default_path(root, naos_root, policy, "cross_harness_review_readiness_report"),
        "adoption_summary": report_default_path(root, naos_root, policy, "adoption_summary_report"),
        "preflight": report_default_path(root, naos_root, policy, "preflight_report"),
        "intake": report_default_path(root, naos_root, policy, "intake_report"),
        "install_plan": report_default_path(root, naos_root, policy, "install_plan_report"),
        "existing_resource_inventory": report_default_path(root, naos_root, policy, "existing_resource_inventory_report"),
        "ai_artifact_inventory": report_default_path(root, naos_root, policy, "ai_artifact_inventory_report"),
        "ai_artifact_reconciliation": report_default_path(root, naos_root, policy, "ai_artifact_reconciliation_report"),
        "ai_code_provenance": report_default_path(root, naos_root, policy, "ai_code_provenance_report"),
        "compliance_posture": report_default_path(root, naos_root, policy, "compliance_posture_report"),
        "memory_resource_inventory": report_default_path(root, naos_root, policy, "memory_resource_inventory_report"),
        "memory_resource_reconciliation": report_default_path(root, naos_root, policy, "memory_resource_reconciliation_report"),
        "mcp_resource_inventory": report_default_path(root, naos_root, policy, "mcp_resource_inventory_report"),
        "brownfield_baseline": report_default_path(root, naos_root, policy, "brownfield_baseline_report"),
        "candidate_requirements": report_default_path(root, naos_root, policy, "candidate_requirements_report"),
        "traceability_gap_register": report_default_path(root, naos_root, policy, "traceability_gap_register_report"),
        "install_decision_record": report_default_path(root, naos_root, policy, "install_decision_record_report"),
        "context_challenge": report_default_path(root, naos_root, policy, "context_challenge_report"),
        "repo_context_challenge": report_default_path(root, naos_root, policy, "repo_context_challenge_report"),
        "plan_challenge": report_default_path(root, naos_root, policy, "plan_challenge_report"),
        "decision_probe": report_default_path(root, naos_root, policy, "decision_probe_report"),
        "planning_gate_review": report_default_path(root, naos_root, policy, "planning_gate_review_report"),
        "roadmap_crosswalk": report_default_path(root, naos_root, policy, "roadmap_report"),
        "function_index": report_default_path(root, naos_root, policy, "function_index_report"),
        "duplicate_function_hygiene": report_default_path(root, naos_root, policy, "duplicate_function_hygiene_report"),
        "secret_hygiene": report_default_path(root, naos_root, policy, "secret_hygiene_report"),
        "test_quality_hygiene": report_default_path(root, naos_root, policy, "test_quality_hygiene_report"),
        "dependency_integrity": report_default_path(root, naos_root, policy, "dependency_integrity_report"),
        "package_reality": report_default_path(root, naos_root, policy, "package_reality_report"),
        "api_symbol_reality": report_default_path(root, naos_root, policy, "api_symbol_reality_report"),
        "ac_completion_evidence": report_default_path(root, naos_root, policy, "ac_completion_evidence_report"),
        "gate_status": report_default_path(root, naos_root, policy, "gate_status_report"),
        "gate_evaluation": report_default_path(root, naos_root, policy, "gate_evaluation_report"),
        "test_evidence_map": test_map_output_path(root, naos_root, policy)
        or root / naos_root / str(policy.get("paths", {}).get("source_to_test_map") or "test_evidence/source_to_test_map.json"),
        "test_evidence_health": report_default_path(root, naos_root, policy, "test_evidence_report"),
        "evidence_pack": evidence_pack_output_path(root, naos_root, policy)
        or root / naos_root / str(policy.get("paths", {}).get("evidence_dir") or "evidence")
        / str(policy.get("paths", {}).get("evidence_pack_report") or "evidence_pack.json"),
    }
    explicit_paths = {
        "claims_validation": args.claims_report,
        "self_check": args.self_check_report,
        "capability_maturity": args.capability_maturity_report,
        "systemic_impact": args.systemic_impact_report,
        "module_header_traceability": args.module_header_report,
        "spec_pack_contract": args.spec_pack_contract_report,
        "spec_pack_materialization": args.spec_pack_materialization_report,
        "spec_assembly_worksheet": args.spec_assembly_worksheet_report,
        "spec_cascade_coherence": args.spec_cascade_report,
        "control_plane_review": args.control_plane_review_report,
        "setup_recommendations": args.setup_recommendations_report,
        "governance_bypass_posture": args.governance_bypass_posture_report,
        "external_evidence_ingest": args.external_evidence_ingest_report,
        "evidence_attestation": args.evidence_attestation_report,
        "evidence_verification": args.evidence_verification_report,
        "evidence_conflicts": args.evidence_conflict_detection_report,
        "task_claims": args.task_claim_report,
        "memory_context_readiness": args.memory_context_readiness_report,
        "memory_provider_access": args.memory_provider_access_report,
        "memory_use_policy": args.memory_use_policy_report,
        "learning_loop_review": args.learning_loop_review_report,
        "failure_mode_observations": args.failure_mode_observations_report,
        "adapter_coherence": args.adapter_coherence_report,
        "task_context_pack": args.task_context_pack_report,
        "task_lifecycle": args.task_lifecycle_report,
        "research_record": args.research_record_report,
        "composed_traceability": args.composed_traceability_report,
        "local_context_index": args.local_context_index_report,
        "sqlite_write_coordination": args.sqlite_write_coordination_report,
        "local_context_query": args.local_context_query_report,
        "semantic_candidate_layer": args.semantic_candidate_layer_report,
        "graph_context_readiness": args.graph_context_readiness_report,
        "graph_context_query": args.graph_context_query_report,
        "session_identity": args.session_identity_report,
        "operator_attribution": args.operator_attribution_report,
        "session_lifecycle": args.session_lifecycle_report,
        "audit_log": args.audit_log_summary_report,
        "agent_trace_validation": args.agent_trace_validation_report,
        "harness_trace_import": args.harness_trace_import_report,
        "ai_surface_health": args.ai_surface_context_budget_report,
        "static_grader": args.static_grader_report,
        "grader_assessment": args.grader_assessment_report,
        "llm_grader_readiness": args.llm_grader_readiness_report,
        "behavioral_governance_readiness": args.behavioral_governance_readiness_report,
        "policy_overrides": args.policy_override_merge_report,
        "plan_coherence": args.plan_coherence_report,
        "pr_risk_classification": args.pr_risk_classification_report,
        "pr_governance": args.pr_governance_summary_report,
        "agentic_workflow": args.agentic_workflow_review_report,
        "pre_implementation_alignment": args.pre_implementation_alignment_review_report,
        "calibration_shadow": args.calibration_shadow_report,
        "evidence_classification": args.evidence_classification_report,
        "cross_harness_review_readiness": args.cross_harness_review_readiness_report,
        "adoption_summary": args.adoption_summary_report,
        "preflight": args.preflight_report,
        "intake": args.intake_report,
        "install_plan": args.install_plan_report,
        "existing_resource_inventory": args.existing_resource_inventory_report,
        "ai_artifact_inventory": args.ai_artifact_inventory_report,
        "ai_artifact_reconciliation": args.ai_artifact_reconciliation_report,
        "ai_code_provenance": args.ai_code_provenance_report,
        "compliance_posture": args.compliance_posture_report,
        "memory_resource_inventory": args.memory_resource_inventory_report,
        "memory_resource_reconciliation": args.memory_resource_reconciliation_report,
        "mcp_resource_inventory": args.mcp_resource_inventory_report,
        "brownfield_baseline": args.brownfield_baseline_report,
        "candidate_requirements": args.candidate_requirements_report,
        "traceability_gap_register": args.traceability_gap_register_report,
        "install_decision_record": args.install_decision_record_report,
        "context_challenge": args.context_challenge_report,
        "repo_context_challenge": args.repo_context_challenge_report,
        "plan_challenge": args.plan_challenge_report,
        "decision_probe": args.decision_probe_report,
        "planning_gate_review": args.planning_gate_review_report,
        "roadmap_crosswalk": args.roadmap_report,
        "function_index": args.function_index_report,
        "duplicate_function_hygiene": args.duplicate_function_hygiene_report,
        "secret_hygiene": args.secret_hygiene_report,
        "test_quality_hygiene": args.test_quality_hygiene_report,
        "dependency_integrity": args.dependency_integrity_report,
        "package_reality": args.package_reality_report,
        "api_symbol_reality": args.api_symbol_reality_report,
        "ac_completion_evidence": args.ac_completion_evidence_report,
        "gate_status": args.gate_status_report,
        "gate_evaluation": args.gate_evaluation_report,
        "test_evidence_map": args.test_map,
        "test_evidence_health": args.test_evidence_report,
        "evidence_pack": args.evidence_pack,
    }
    artifacts = {
        key: read_json_artifact(Path(explicit_paths[key]) if explicit_paths[key] else default_path, label=key)
        for key, default_path in default_paths.items()
    }
    if presentation_inputs is not None:
        for key in ("self_check", "systemic_impact"):
            data = artifacts[key].get("data") or {}
            presentation_inputs[key] = data if isinstance(data, dict) else {}
    findings = missing_report_findings(artifacts, root, naos_root, profile, policy)
    summary_counts = finding_counts(findings)
    policy_meta = policy.get("_meta", {})
    capability_summary = load_capability_contracts(root, profile, args.capabilities_dir)
    capability_maturity_readiness = summarize_capability_maturity_readiness(artifacts["capability_maturity"])
    systemic_impact_review = summarize_systemic_impact_review(artifacts["systemic_impact"])
    module_header_traceability = summarize_module_header_traceability(artifacts["module_header_traceability"])
    spec_pack_contract = summarize_spec_pack_contract(artifacts["spec_pack_contract"])
    spec_pack_materialization = summarize_spec_pack_materialization(artifacts["spec_pack_materialization"])
    spec_assembly_worksheet = summarize_spec_assembly_worksheet(artifacts["spec_assembly_worksheet"])
    spec_cascade_coherence = summarize_spec_cascade_coherence(artifacts["spec_cascade_coherence"])
    control_plane_review = summarize_control_plane_review(artifacts["control_plane_review"])
    setup_recommendations = summarize_setup_recommendations(artifacts["setup_recommendations"])
    governance_bypass_posture = summarize_governance_bypass_posture(artifacts["governance_bypass_posture"])
    external_evidence_ingest = summarize_external_evidence_ingest(artifacts["external_evidence_ingest"])
    evidence_attestation = summarize_evidence_attestation(artifacts["evidence_attestation"])
    evidence_verification = summarize_evidence_verification(artifacts["evidence_verification"])
    evidence_conflicts = summarize_evidence_conflicts(artifacts["evidence_conflicts"])
    task_claims = summarize_task_claims(artifacts["task_claims"])
    memory_context_readiness = summarize_memory_context_readiness(artifacts["memory_context_readiness"])
    memory_provider_access = summarize_memory_provider_access(artifacts["memory_provider_access"])
    memory_use_policy = summarize_memory_use_policy(artifacts["memory_use_policy"])
    learning_loop_review = summarize_learning_loop_review(artifacts["learning_loop_review"])
    failure_mode_observations = summarize_failure_mode_observations(artifacts["failure_mode_observations"])
    adapter_coherence = summarize_adapter_coherence(artifacts["adapter_coherence"])
    task_context_pack = summarize_task_context_pack(artifacts["task_context_pack"])
    task_lifecycle = summarize_native_lifecycle_report(
        artifacts["task_lifecycle"],
        "Native completion records repository state; it is not merge, release, or evidence-admission authority.",
    )
    research_record = summarize_native_lifecycle_report(
        artifacts["research_record"],
        "Validated research remains candidate-only until a separate attributable transition.",
    )
    composed_traceability = summarize_native_lifecycle_report(
        artifacts["composed_traceability"],
        "Relationship presence is structural evidence and does not prove semantic correctness.",
    )
    local_context_index = summarize_local_context_index(artifacts["local_context_index"])
    sqlite_write_coordination = summarize_sqlite_write_coordination(artifacts["sqlite_write_coordination"])
    local_context_query = summarize_local_context_query(artifacts["local_context_query"])
    semantic_candidate_layer = summarize_semantic_candidate_layer(artifacts["semantic_candidate_layer"])
    graph_context_readiness = summarize_graph_context_readiness(artifacts["graph_context_readiness"])
    graph_context_query = summarize_graph_context_query(artifacts["graph_context_query"])
    session_identity = summarize_session_identity(artifacts["session_identity"])
    operator_attribution = summarize_operator_attribution(artifacts["operator_attribution"])
    session_lifecycle = summarize_session_lifecycle(artifacts["session_lifecycle"])
    audit_log = summarize_audit_log(artifacts["audit_log"])
    agent_trace_validation = summarize_agent_trace_validation(artifacts["agent_trace_validation"])
    harness_trace_import = summarize_harness_trace_import(artifacts["harness_trace_import"])
    ai_surface_health = summarize_ai_surface_health(artifacts["ai_surface_health"])
    static_grader = summarize_static_grader(artifacts["static_grader"])
    grader_assessment = summarize_grader_assessment(artifacts["grader_assessment"])
    llm_grader_readiness = summarize_llm_grader_readiness(artifacts["llm_grader_readiness"])
    behavioral_readiness = summarize_behavioral_governance_readiness(artifacts["behavioral_governance_readiness"])
    policy_overrides = summarize_policy_overrides(artifacts["policy_overrides"])
    plan_coherence = summarize_plan_coherence(artifacts["plan_coherence"])
    pr_risk_classification = summarize_pr_risk_classification(artifacts["pr_risk_classification"])
    pr_governance = summarize_pr_governance(artifacts["pr_governance"])
    agentic_workflow = summarize_agentic_workflow(artifacts["agentic_workflow"])
    pre_implementation_alignment = summarize_pre_implementation_alignment(artifacts["pre_implementation_alignment"])
    calibration_shadow = summarize_calibration_shadow(artifacts["calibration_shadow"])
    evidence_classification = summarize_evidence_classification(artifacts["evidence_classification"])
    cross_harness_review_readiness = summarize_cross_harness_review_readiness(artifacts["cross_harness_review_readiness"])
    ai_code_provenance = summarize_ai_code_provenance(artifacts["ai_code_provenance"])
    compliance_posture = summarize_compliance_posture(artifacts["compliance_posture"])
    professional_adoption = summarize_professional_adoption(artifacts)
    deterministic_hygiene = summarize_deterministic_hygiene(artifacts)
    ac_completion_evidence = summarize_ac_completion_evidence(artifacts["ac_completion_evidence"])
    capability_summary["readiness_report"] = capability_maturity_readiness
    evidence_pack = summarize_evidence_pack(artifacts["evidence_pack"])
    exceptions = evidence_pack["exceptions_waivers"]
    return {
        "schema": "naos.dashboard_summary.v1",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "profile": profile,
        "status": status_from_counts(summary_counts),
        "naos_root": naos_root,
        "policy": {
            "version": policy.get("version"),
            "source": policy_meta.get("source"),
            "path": policy_meta.get("path"),
            "profile_severity": severity_for_profile(profile, policy),
        },
        "inputs": artifacts,
        "capability_maturity": capability_summary,
        "capability_maturity_readiness": capability_maturity_readiness,
        "systemic_impact_review": systemic_impact_review,
        "module_header_traceability": module_header_traceability,
        "spec_pack_contract": spec_pack_contract,
        "spec_pack_materialization": spec_pack_materialization,
        "spec_assembly_worksheet": spec_assembly_worksheet,
        "spec_cascade_coherence": spec_cascade_coherence,
        "control_plane_review": control_plane_review,
        "setup_recommendations": setup_recommendations,
        "governance_bypass_posture": governance_bypass_posture,
        "external_evidence_ingest": external_evidence_ingest,
        "evidence_attestation": evidence_attestation,
        "evidence_verification": evidence_verification,
        "evidence_conflicts": evidence_conflicts,
        "task_claims": task_claims,
        "memory_context_readiness": memory_context_readiness,
        "memory_provider_access": memory_provider_access,
        "memory_use_policy": memory_use_policy,
        "learning_loop_review": learning_loop_review,
        "failure_mode_observations": failure_mode_observations,
        "adapter_coherence": adapter_coherence,
        "task_context_pack": task_context_pack,
        "task_lifecycle": task_lifecycle,
        "research_record": research_record,
        "composed_traceability": composed_traceability,
        "local_context_index": local_context_index,
        "sqlite_write_coordination": sqlite_write_coordination,
        "local_context_query": local_context_query,
        "semantic_candidate_layer": semantic_candidate_layer,
        "graph_context_readiness": graph_context_readiness,
        "graph_context_query": graph_context_query,
        "session_identity": session_identity,
        "operator_attribution": operator_attribution,
        "session_lifecycle": session_lifecycle,
        "audit_log": audit_log,
        "agent_trace_validation": agent_trace_validation,
        "harness_trace_import": harness_trace_import,
        "ai_surface_health": ai_surface_health,
        "static_grader": static_grader,
        "grader_assessment": grader_assessment,
        "llm_grader_readiness": llm_grader_readiness,
        "behavioral_governance_readiness": behavioral_readiness,
        "policy_overrides": policy_overrides,
        "plan_coherence": plan_coherence,
        "pr_risk_classification": pr_risk_classification,
        "pr_governance": pr_governance,
        "agentic_workflow": agentic_workflow,
        "pre_implementation_alignment": pre_implementation_alignment,
        "calibration_shadow": calibration_shadow,
        "evidence_classification": evidence_classification,
        "cross_harness_review_readiness": cross_harness_review_readiness,
        "ai_code_provenance": ai_code_provenance,
        "compliance_posture": compliance_posture,
        "professional_adoption": professional_adoption,
        "deterministic_hygiene": deterministic_hygiene,
        "ac_completion_evidence": ac_completion_evidence,
        "gatekeeper_readiness": summarize_gatekeepers(artifacts["gate_status"]),
        "claims_validation": summarize_claims(artifacts["claims_validation"], policy),
        "self_conformance": summarize_self_check(artifacts["self_check"]),
        "roadmap_crosswalk": summarize_roadmap(artifacts["roadmap_crosswalk"]),
        "function_index_health": summarize_function_index(artifacts["function_index"]),
        "test_evidence_health": summarize_test_evidence(artifacts["test_evidence_map"], artifacts["test_evidence_health"]),
        "evidence_pack": evidence_pack,
        "exceptions_waivers": {
            "status": "advisory" if exceptions else "not_configured",
            "count": len(exceptions),
            "items": exceptions,
            "risk_treatment": "Waived risk remains visible and is not converted to pass.",
        },
        "advanced_capability_readiness": {
            "status": "experimental" if capability_summary["experimental"] else "not_configured",
            "capabilities": [item for item in capability_summary["capabilities"] if item.get("experimental")],
            "default_rule": "Experimental capabilities remain scaffolded/advisory unless project policy explicitly changes them.",
        },
        "summary": {
            **summary_counts,
            "missing_inputs": sum(1 for artifact in artifacts.values() if artifact.get("status") == "missing"),
            "not_configured_inputs": sum(1 for artifact in artifacts.values() if artifact.get("status") == "not_configured"),
            "present_inputs": sum(1 for artifact in artifacts.values() if artifact.get("status") == "present"),
            "capabilities": capability_summary["total"],
            "experimental_capabilities": capability_summary["experimental"],
            "maturity_ready": capability_maturity_readiness["summary"].get("ready", 0),
            "maturity_blocked": capability_maturity_readiness["summary"].get("blocked", 0),
            "maturity_human_approval_required": capability_maturity_readiness["summary"].get("human_approval_required", 0),
            "systemic_review_required": systemic_impact_review["summary"].get("review_required", 0),
            "systemic_not_configured": systemic_impact_review["summary"].get("not_configured", 0),
            "systemic_human_review_required": systemic_impact_review["summary"].get("human_review_required", 0),
            "module_header_missing": module_header_traceability["summary"].get("missing_headers", 0),
            "module_header_legacy": module_header_traceability["summary"].get("legacy_headers", 0),
            "module_header_human_review_required": module_header_traceability["summary"].get("human_review_required", 0),
            "spec_pack_contract_total_findings": spec_pack_contract["summary"].get("total_findings", 0),
            "spec_pack_contract_files_missing": spec_pack_contract["summary"].get("files_missing", 0),
            "spec_pack_contract_files_not_applicable": spec_pack_contract["summary"].get("files_not_applicable", 0),
            "spec_pack_contract_placeholder_findings": spec_pack_contract["summary"].get("placeholder_findings", 0),
            "spec_pack_contract_traceability_reference_findings": spec_pack_contract["summary"].get(
                "traceability_reference_findings", 0
            ),
            "spec_pack_contract_human_review_required": spec_pack_contract.get("human_review_required", False),
            "spec_pack_contract_spec_files_missing": spec_pack_contract["summary"].get("spec_files_missing", 0),
            "spec_pack_contract_support_files_missing": spec_pack_contract["summary"].get("support_files_missing", 0),
            "spec_pack_materialization_copied": spec_pack_materialization["summary"].get("copied", 0),
            "spec_pack_materialization_skipped_existing": spec_pack_materialization["summary"].get("skipped_existing", 0),
            "spec_pack_materialization_missing_source": spec_pack_materialization["summary"].get("missing_source", 0),
            **(
                {
                    "spec_pack_materialization_total_findings": spec_pack_materialization["summary"].get(
                        "total_findings", 0
                    )
                }
                if "total_findings" in spec_pack_materialization["summary"]
                else {}
            ),
            **(
                {
                    "spec_pack_materialization_invalid_manifest": spec_pack_materialization["summary"].get(
                        "invalid_manifest", 0
                    )
                }
                if "invalid_manifest" in spec_pack_materialization["summary"]
                else {}
            ),
            **(
                {
                    "spec_pack_materialization_unsafe_paths": spec_pack_materialization["summary"].get(
                        "unsafe_paths", 0
                    )
                }
                if "unsafe_paths" in spec_pack_materialization["summary"]
                else {}
            ),
            **(
                {
                    "spec_pack_materialization_apply_refused": spec_pack_materialization["summary"].get(
                        "apply_refused", False
                    )
                }
                if "apply_refused" in spec_pack_materialization["summary"]
                else {}
            ),
            **(
                {
                    "spec_pack_materialization_report_write_failed": spec_pack_materialization["summary"].get(
                        "report_write_failed", 0
                    )
                }
                if "report_write_failed" in spec_pack_materialization["summary"]
                else {}
            ),
            **(
                {
                    "spec_pack_materialization_copy_cleanup_failed": spec_pack_materialization["summary"].get(
                        "copy_cleanup_failed", 0
                    )
                }
                if "copy_cleanup_failed" in spec_pack_materialization["summary"]
                else {}
            ),
            "spec_pack_materialization_human_review_required": spec_pack_materialization.get("human_review_required", False),
            "spec_assembly_required_spec_files_missing": spec_assembly_worksheet["summary"].get(
                "required_spec_files_missing", 0
            ),
            "spec_assembly_candidate_requirements": spec_assembly_worksheet["summary"].get("candidate_requirements", 0),
            "spec_assembly_non_applicability_decisions_needed": spec_assembly_worksheet["summary"].get(
                "non_applicability_decisions_needed", 0
            ),
            "spec_assembly_human_review_required": spec_assembly_worksheet.get("human_review_required", False),
            "spec_cascade_total_findings": spec_cascade_coherence["summary"].get("total_findings", 0),
            "spec_cascade_uncovered_requirements": spec_cascade_coherence["summary"].get("uncovered_requirements", 0),
            "spec_cascade_untraced_sources": spec_cascade_coherence["summary"].get("untraced_sources", 0),
            "spec_cascade_human_review_required": spec_cascade_coherence.get("human_review_required", False),
            "ac_completion_configured": ac_completion_evidence["summary"].get("configured", False),
            "ac_completion_claimed_complete": ac_completion_evidence["summary"].get("claimed_complete", 0),
            "ac_completion_satisfied": ac_completion_evidence["summary"].get("satisfied_completions", 0),
            "ac_completion_unsatisfied": ac_completion_evidence["summary"].get("unsatisfied_completions", 0),
            "ac_completion_repository_bound": ac_completion_evidence["summary"].get(
                "repository_bound_completions", 0
            ),
            "ac_completion_subject_operands_checked": ac_completion_evidence["summary"].get(
                "subject_operands_checked", 0
            ),
            "ac_completion_superseded_records": ac_completion_evidence["summary"].get(
                "superseded_completion_records", 0
            ),
            "control_plane_missing_routing": control_plane_review["summary"].get("missing_routing", 0),
            "control_plane_review_required": control_plane_review["summary"].get("review_required", 0),
            "control_plane_human_review_required": control_plane_review["summary"].get("human_review_required", 0),
            "setup_recommended_modules": setup_recommendations["summary"].get("recommended", 0),
            "setup_optional_modules": setup_recommendations["summary"].get("optional", 0),
            "setup_deferred_modules": (
                setup_recommendations["summary"].get("defer", 0)
                + setup_recommendations["summary"].get("readiness_only", 0)
                + setup_recommendations["summary"].get("experimental", 0)
            ),
            "setup_human_review_required": setup_recommendations["summary"].get("human_review_required", 0),
            "governance_bypass_findings": governance_bypass_posture["summary"].get("total_findings", 0),
            "governance_bypass_human_review_required": governance_bypass_posture.get("human_review_required", False),
            "external_evidence_results": external_evidence_ingest["summary"].get("results", 0),
            "external_evidence_verification_status": external_evidence_ingest.get("verification_status"),
            "external_evidence_human_review_required": external_evidence_ingest.get("human_review_required", False),
            "evidence_attestation_artifacts_hashed": evidence_attestation["summary"].get("artifacts_hashed", 0),
            "evidence_attestation_missing": evidence_attestation["summary"].get("missing_artifacts", 0),
            "evidence_attestation_uncovered": evidence_attestation["summary"].get("uncovered_artifacts", 0),
            "evidence_attestation_reviewer_attestations": evidence_attestation["summary"].get("reviewer_attestations", 0),
            "evidence_attestation_human_review_required": evidence_attestation["summary"].get("human_review_required", 0),
            "evidence_verification_status": evidence_verification.get("status"),
            "evidence_verification_tamper_evident": evidence_verification.get("tamper_evident", False),
            "evidence_verification_signed": evidence_verification.get("signed", False),
            "evidence_verification_signature_entries_present": evidence_verification.get(
                "signature_entries_present", False
            ),
            "evidence_verification_signature_validation_performed": evidence_verification.get(
                "signature_validation_performed", False
            ),
            "evidence_verification_signature_validation_claim_rejected": evidence_verification.get(
                "signature_validation_claim_rejected", False
            ),
            "evidence_verification_human_review_required": evidence_verification.get("human_review_required", False),
            "evidence_conflict_detection_status": evidence_conflicts.get("status"),
            "evidence_conflict_detection_conflicts": evidence_conflicts.get("conflict_count", 0),
            "evidence_conflict_detection_human_review_required": evidence_conflicts.get("human_review_required", False),
            "task_claims_status": task_claims.get("status"),
            "task_claims_active": task_claims.get("active_claim_count", 0),
            "task_claims_conflicting": task_claims.get("conflicting_claim_count", 0),
            "task_claims_human_review_required": task_claims.get("human_review_required", False),
            "memory_context_platforms": memory_context_readiness["summary"].get("platforms", 0),
            "memory_context_declared_memory_platforms": memory_context_readiness["summary"].get("platforms_with_declared_memory", 0),
            "memory_context_human_review_required": memory_context_readiness["summary"].get("human_review_required", 0),
            "memory_provider_access_status": memory_provider_access.get("status"),
            "memory_provider_access_verified": memory_provider_access.get("provider_access_verified", False),
            "memory_provider_mcp_access_verified": memory_provider_access.get("mcp_access_verified", False),
            "memory_use_policy_status": memory_use_policy.get("status"),
            "memory_use_policy_review_items": memory_use_policy["summary"].get("memory_review_items", 0),
            "memory_use_policy_instruction_grade": memory_use_policy["summary"].get("instruction_grade_items", 0),
            "memory_use_policy_human_review_required": memory_use_policy.get("human_review_required", False),
            "learning_loop_review_status": learning_loop_review.get("status"),
            "learning_loop_records": learning_loop_review["summary"].get("learning_records", 0),
            "learning_loop_active_records": learning_loop_review["summary"].get("active_records", 0),
            "learning_loop_high_authority_active": learning_loop_review["summary"].get("high_authority_active_records", 0),
            "learning_loop_human_review_required": learning_loop_review.get("human_review_required", False),
            "failure_mode_observations_status": failure_mode_observations.get("status"),
            "failure_mode_observations_declared": failure_mode_observations.get("failure_mode_observations_declared", False),
            "failure_mode_observations": failure_mode_observations["summary"].get("observations", 0),
            "failure_mode_modes_with_observations": failure_mode_observations["summary"].get("modes_with_observations", 0),
            "failure_mode_unmapped_observations": failure_mode_observations["summary"].get("unmapped_observations", 0),
            "failure_mode_high_severity_observations": failure_mode_observations["summary"].get("high_severity_observations", 0),
            "failure_mode_observations_human_review_required": failure_mode_observations.get("human_review_required", False),
            "adapter_coherence_status": adapter_coherence.get("status"),
            "adapter_coherence_plugin_skills_present": adapter_coherence["summary"].get("plugin_skills_present", 0),
            "adapter_coherence_plugin_skills_expected": adapter_coherence["summary"].get("plugin_skills_expected", 0),
            "adapter_coherence_surfaces_present": adapter_coherence["summary"].get("adapter_surfaces_present", 0),
            "adapter_coherence_surfaces_expected": adapter_coherence["summary"].get("adapter_surfaces_expected", 0),
            "adapter_coherence_human_review_required": adapter_coherence.get("human_review_required", False),
            "task_context_pack_missing_sources": len(task_context_pack.get("source_artifacts_missing") or []),
            "task_context_pack_human_review_required": task_context_pack.get("human_review_required", False),
            "local_context_index_artifacts": local_context_index["summary"].get("indexed_artifacts", 0),
            "local_context_index_chunks": local_context_index["summary"].get("chunks", 0),
            "local_context_index_fts_available": local_context_index.get("fts_available", False),
            "local_context_index_human_review_required": local_context_index.get("human_review_required", False),
            "local_context_query_results": local_context_query.get("result_count", 0),
            "local_context_query_human_review_required": local_context_query.get("human_review_required", False),
            "semantic_candidate_layer_status": semantic_candidate_layer.get("status"),
            "semantic_candidate_layer_human_review_required": semantic_candidate_layer.get("human_review_required", False),
            "graph_context_readiness_status": graph_context_readiness.get("status"),
            "graph_context_readiness_human_review_required": graph_context_readiness.get("human_review_required", False),
            "graph_context_query_results": graph_context_query.get("result_count", 0),
            "graph_context_query_human_review_required": graph_context_query.get("human_review_required", False),
            "session_identity_status": session_identity.get("status"),
            "session_identity_session_id": session_identity.get("session_id"),
            "session_identity_human_review_required": session_identity.get("human_review_required", False),
            "session_lifecycle_mode": session_lifecycle.get("mode"),
            "session_lifecycle_task_id": session_lifecycle.get("task_id"),
            "session_lifecycle_status": session_lifecycle.get("status"),
            "session_lifecycle_memory_candidate_proposals": len(session_lifecycle.get("memory_candidate_proposals") or []),
            "session_lifecycle_human_review_required": session_lifecycle.get("human_review_required", False),
            "audit_log_status": audit_log.get("status"),
            "audit_log_event_count": audit_log.get("event_count", 0),
            "audit_log_invalid_events": audit_log.get("invalid_event_count", 0),
            "audit_log_human_review_required": audit_log.get("human_review_required", False),
            "agent_trace_validation_status": agent_trace_validation.get("status"),
            "agent_trace_validation_events": agent_trace_validation.get("event_count", 0),
            "agent_trace_validation_invalid_events": agent_trace_validation.get("invalid_event_count", 0),
            "agent_trace_validation_human_review_required": agent_trace_validation.get("human_review_required", False),
            "harness_trace_import_status": harness_trace_import.get("status"),
            "harness_trace_import_imported_events": harness_trace_import.get("imported_event_count", 0),
            "harness_trace_import_rejected_records": harness_trace_import.get("rejected_record_count", 0),
            "harness_trace_import_events_written": harness_trace_import.get("events_written", False),
            "harness_trace_import_human_review_required": harness_trace_import.get("human_review_required", False),
            "static_grader_status": static_grader.get("status"),
            "static_grader_findings": (static_grader.get("summary") or {}).get("total_findings", 0),
            "static_grader_cost_usd": (static_grader.get("cost_posture") or {}).get("cost_usd", 0.0),
            "static_grader_human_review_required": static_grader.get("human_review_required", False),
            "grader_assessment_status": grader_assessment.get("status"),
            "grader_assessment_mode": grader_assessment.get("mode"),
            "grader_assessment_findings": (grader_assessment.get("summary") or {}).get("total_findings", 0),
            "grader_assessment_cost_usd": (grader_assessment.get("cost_budget_posture") or {}).get("cost_usd", 0.0),
            "grader_assessment_human_review_required": grader_assessment.get("human_review_required", False),
            "llm_grader_readiness_status": llm_grader_readiness.get("status"),
            "llm_grader_readiness_runtime_enabled": llm_grader_readiness.get("runtime_enabled", False),
            "llm_grader_readiness_cost_usd": (llm_grader_readiness.get("cost_posture") or {}).get("cost_usd", 0.0),
            "llm_grader_readiness_human_review_required": llm_grader_readiness.get("human_review_required", False),
            "behavioral_governance_readiness_status": behavioral_readiness.get("status"),
            "behavioral_governance_readiness_baseline_present": behavioral_readiness.get("baseline_state_present", False),
            "behavioral_governance_readiness_impacters": (behavioral_readiness.get("summary") or {}).get("total_impacters", 0),
            "behavioral_governance_readiness_cost_usd": (behavioral_readiness.get("cost_posture") or {}).get("cost_usd", 0.0),
            "behavioral_governance_readiness_human_review_required": behavioral_readiness.get("human_review_required", False),
            "plan_coherence_status": plan_coherence.get("status"),
            "plan_coherence_findings": (plan_coherence.get("summary") or {}).get("total_findings", 0),
            "plan_coherence_active_claims": (plan_coherence.get("summary") or {}).get("active_claims", 0),
            "plan_coherence_human_review_required": plan_coherence.get("human_review_required", False),
            "ai_code_provenance_status": ai_code_provenance.get("status"),
            "ai_code_provenance_manifest_present": (ai_code_provenance.get("manifest") or {}).get("present", False),
            "ai_code_provenance_declarations": (ai_code_provenance.get("summary") or {}).get("declarations", 0),
            "ai_code_provenance_missing_evidence": (ai_code_provenance.get("summary") or {}).get("missing_evidence", 0),
            "ai_code_provenance_human_review_required": ai_code_provenance.get("human_review_required", False),
            "compliance_posture_status": compliance_posture.get("status"),
            "compliance_posture_manifest_present": (compliance_posture.get("manifest") or {}).get("present", False),
            "compliance_posture_declared_contexts": (compliance_posture.get("summary") or {}).get("declared_contexts", 0),
            "compliance_posture_missing_evidence": (compliance_posture.get("summary") or {}).get("missing_evidence", 0),
            "compliance_posture_human_review_required": compliance_posture.get("human_review_required", False),
            "policy_overrides_status": policy_overrides.get("status"),
            "policy_overrides_applied_paths": (policy_overrides.get("summary") or {}).get("applied_paths", 0),
            "policy_overrides_protected_invariant_violations": len(policy_overrides.get("protected_invariant_violations") or []),
            "policy_overrides_human_review_required": policy_overrides.get("human_review_required", False),
            "pr_risk_classification_status": pr_risk_classification.get("status"),
            "pr_risk_classification_risk_files": pr_risk_classification.get("risk_files", 0),
            "pr_risk_classification_findings": pr_risk_classification.get("total_findings", 0),
            "pr_risk_classification_human_review_required": pr_risk_classification.get("human_review_required", False),
            "pr_governance_status": pr_governance.get("status"),
            "pr_governance_reports_present": (pr_governance.get("summary") or {}).get("reports_present", 0),
            "pr_governance_findings": (pr_governance.get("summary") or {}).get("findings", 0),
            "pr_governance_human_review_required": pr_governance.get("human_review_required", False),
            "agentic_workflow_status": agentic_workflow.get("status"),
            "agentic_workflow_sections_enabled": (agentic_workflow.get("summary") or {}).get("sections_enabled", 0),
            "agentic_workflow_human_review_required": agentic_workflow.get("human_review_required", False),
            "pre_implementation_alignment_status": pre_implementation_alignment.get("status"),
            "pre_implementation_alignment_missing_required": len(pre_implementation_alignment.get("missing_required_questions") or []),
            "pre_implementation_alignment_human_review_required": pre_implementation_alignment.get("human_review_required", False),
            "calibration_shadow_status": calibration_shadow.get("status"),
            "calibration_shadow_drift_count": calibration_shadow.get("drift_count", 0),
            "calibration_shadow_human_review_required": calibration_shadow.get("human_review_required", False),
            "evidence_classification_status": evidence_classification.get("status"),
            "evidence_classification_missing": len(evidence_classification.get("missing_classification") or []),
            "evidence_classification_human_review_required": evidence_classification.get("human_review_required", False),
            "cross_harness_review_readiness_status": cross_harness_review_readiness.get("status"),
            "cross_harness_review_readiness_score": cross_harness_review_readiness.get("readiness_score", 0),
            "cross_harness_review_readiness_human_review_required": cross_harness_review_readiness.get("human_review_required", False),
            "deterministic_hygiene_reports_present": deterministic_hygiene.get("reports_present", 0),
            "deterministic_hygiene_findings": deterministic_hygiene.get("total_findings", 0),
            "deterministic_hygiene_human_review_required": deterministic_hygiene.get("human_review_required", False),
            "evidence_pack_present": artifacts["evidence_pack"].get("status") == "present",
        },
        "findings": findings,
        "limitations": [
            "Dashboard summarizes file-first evidence that exists at generation time.",
            "Missing reports are shown as missing or not configured, not pass.",
            "Dashboard evidence supports governance traceability and review; it does not prove legal or regulatory compliance.",
            "Dashboard evidence does not prove runtime safety or complete test coverage.",
            "Adapter coherence evidence is static and file-first; it does not prove live plugin installation, mutate tool caches, call MCP, write memory, or propagate changes automatically.",
            "PR risk classification reports are path/diff metadata review signals; they do not approve pull requests, execute sandboxes, prove security, or authorize release.",
            "PR governance summaries package PR-time CI review evidence; they do not approve pull requests, authorize deployment or release, prove compliance, satisfy separation of duties, or resolve evidence conflicts.",
            "Plan coherence reports are deterministic coordination review evidence; they do not authorize work, sequence execution, resolve conflicts, or approve plans.",
            "Evidence verification reports local digest comparison, signature-entry presence, and best-effort Git HEAD metadata; it does not validate third-party signatures, authenticate identities, or sign artifacts for NAOS.",
        ],
    }


def _table_cell(value: Any) -> str:
    if value is None or value == "":
        return "—"
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def dashboard_finding_occurrences(
    dashboard_summary: dict[str, Any],
    presentation_inputs: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[Any]]:
    """Collect independent dashboard, self-check, and systemic inventories."""
    native = [
        finding_occurrence(
            source="dashboard-native",
            identity=f"dashboard-native/finding[{index}]",
            order=index,
            finding=item,
            family_label="dashboard-native",
        )
        for index, item in enumerate(dashboard_summary.get("findings") or [])
        if isinstance(item, dict)
    ]
    self_report = presentation_inputs.get("self_check") or {}
    systemic_report = presentation_inputs.get("systemic_impact") or {}
    limitations = [
        *(dashboard_summary.get("limitations") or []),
        *(self_report.get("limitations") or []),
        *(systemic_report.get("limitations") or []),
    ]
    return (
        [
            *native,
            *self_check_finding_occurrences(self_report),
            *systemic_finding_occurrences(systemic_report),
        ],
        limitations,
    )


def render_dashboard_finding_presentation(presentation: dict[str, Any] | None) -> list[str]:
    """Render the bounded/default or complete expanded finding inventory."""
    if not presentation:
        return []
    heading = "All NAOS Finding Occurrences" if presentation["show_all"] else "Actionable Findings"
    lines = [
        f"## {heading}",
        "",
        (
            "> Dashboard-native, self-check, and systemic-impact sources are "
            "reported independently. Similar rows are not deduplicated across reports."
        ),
        "",
        f"**{presentation['summary']}**",
    ]
    if presentation["rows"]:
        lines.append("")
        lines.extend(f"- {row['text']}" for row in presentation["rows"])
    if presentation["show_all"] and presentation["limitations"]:
        lines.extend(["", "### Report Limitations", ""])
        lines.extend(f"- {item}" for item in presentation["limitations"])
    lines.append("")
    return lines


def _evidence_pack_item_text(value: Any) -> str:
    if isinstance(value, dict):
        identifier = value.get("id")
        description = value.get("description") or value.get("message") or value.get("status") or ""
        if identifier and description:
            return _table_cell(f"{identifier}: {description}")
        return _table_cell(description or identifier or value)
    return _table_cell(value)


def _first_recommended_command(items: list[Any], fallback: str) -> str:
    for item in items:
        if isinstance(item, dict) and item.get("command"):
            return str(item["command"])
    return fallback


def _review_cell(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return _table_cell(value)


def render_reader_index() -> list[str]:
    return [
        "## Reader Index",
        "",
        "| Reader need | Start here |",
        "|-------------|------------|",
        "| What needs action? | [Quick Actions](#quick-actions) and [Next Steps](#next-steps) |",
        "| What is ready? | [Control Plane Status Matrix](#control-plane-status-matrix) |",
        "| What requires human review? | [Control Plane Status Matrix](#control-plane-status-matrix), [Gatekeeper Readiness](#gatekeeper-readiness), and [Plan Coherence](#plan-coherence) |",
        "| What evidence supports this? | [Evidence Integrity & Reviewer Attestation](#evidence-integrity--reviewer-attestation), [Evidence Verification](#evidence-verification), [Evidence Conflict Detection](#evidence-conflict-detection), and [Evidence Pack Gaps And Residual Risk](#evidence-pack-gaps-and-residual-risk) |",
        "| What is explicitly not claimed? | [NAOS Control-Plane Health](#naos-control-plane-health), [LLMGrader Readiness](#llmgrader-readiness), and [Behavioral Governance Readiness](#behavioral-governance-readiness) |",
        "",
    ]


def render_control_plane_status_matrix(control_plane: dict[str, Any]) -> list[str]:
    systemic = control_plane.get("systemic_impact_review") or {}
    systemic_summary = systemic.get("summary") or {}
    control_review = control_plane.get("control_plane_review") or {}
    control_review_summary = control_review.get("summary") or {}
    evidence_attestation = control_plane.get("evidence_attestation") or {}
    evidence_attestation_summary = evidence_attestation.get("summary") or {}
    evidence_verification = control_plane.get("evidence_verification") or {}
    evidence_conflicts = control_plane.get("evidence_conflicts") or {}
    plan_coherence = control_plane.get("plan_coherence") or {}
    plan_coherence_summary = plan_coherence.get("summary") or {}
    failure_mode_observations = control_plane.get("failure_mode_observations") or {}
    failure_mode_summary = failure_mode_observations.get("summary") or {}
    gatekeeper = control_plane.get("gatekeeper_readiness") or {}
    gatekeeper_gates = gatekeeper.get("gates") or []
    static_grader = control_plane.get("static_grader") or {}
    static_summary = static_grader.get("summary") or {}
    llm_readiness = control_plane.get("llm_grader_readiness") or {}
    behavioral = control_plane.get("behavioral_governance_readiness") or {}
    behavioral_summary = behavioral.get("summary") or {}
    behavioral_command = _first_recommended_command(
        behavioral.get("recommended_next_commands") or [],
        "naos behavioral-readiness --profile <profile>",
    )
    ai_code_provenance = control_plane.get("ai_code_provenance") or {}
    ai_code_summary = ai_code_provenance.get("summary") or {}
    ai_code_manifest = ai_code_provenance.get("manifest") or {}
    ai_code_command = _first_recommended_command(
        ai_code_provenance.get("recommended_next_commands") or [],
        "naos ai-code-provenance --profile <profile>",
    )
    compliance_posture = control_plane.get("compliance_posture") or {}
    compliance_summary = compliance_posture.get("summary") or {}
    compliance_manifest = compliance_posture.get("manifest") or {}
    compliance_command = _first_recommended_command(
        compliance_posture.get("recommended_next_commands") or [],
        "naos compliance-posture --profile <profile>",
    )
    evidence_pack = control_plane.get("evidence_pack") or {}
    evidence_pack_summary = evidence_pack.get("summary") or {}
    spec_pack = control_plane.get("spec_pack_contract") or {}
    spec_pack_summary = spec_pack.get("summary") or {}
    spec_materialization = control_plane.get("spec_pack_materialization") or {}
    spec_materialization_summary = spec_materialization.get("summary") or {}
    spec_worksheet = control_plane.get("spec_assembly_worksheet") or {}
    spec_worksheet_summary = spec_worksheet.get("summary") or {}
    ac_completion = control_plane.get("ac_completion_evidence") or {}
    ac_completion_summary = ac_completion.get("summary") or {}

    rows = [
        (
            "Gatekeeper readiness",
            gatekeeper.get("status"),
            "see gates",
            f"{len(gatekeeper_gates)} gates reported",
            "naos gate-status --profile <profile>",
        ),
        (
            "Behavioral Governance Readiness",
            behavioral.get("status"),
            behavioral.get("human_review_required"),
            f"baseline: {_table_cell(behavioral.get('baseline_state_present'))}; impacters: {_table_cell(behavioral_summary.get('total_impacters'))}",
            behavioral_command,
        ),
        (
            "AI Code Provenance",
            ai_code_provenance.get("status"),
            ai_code_provenance.get("human_review_required"),
            f"manifest: {_table_cell(ai_code_manifest.get('present'))}; declarations: {_table_cell(ai_code_summary.get('declarations'))}; missing evidence: {_table_cell(ai_code_summary.get('missing_evidence'))}",
            ai_code_command,
        ),
        (
            "Compliance Posture",
            compliance_posture.get("status"),
            compliance_posture.get("human_review_required"),
            f"manifest: {_table_cell(compliance_manifest.get('present'))}; declared contexts: {_table_cell(compliance_summary.get('declared_contexts'))}; missing evidence: {_table_cell(compliance_summary.get('missing_evidence'))}",
            compliance_command,
        ),
        (
            "LLMGrader readiness",
            llm_readiness.get("status"),
            llm_readiness.get("human_review_required"),
            f"runtime: {_table_cell(llm_readiness.get('runtime_enabled'))}; provider allowed: {_table_cell(llm_readiness.get('provider_allowed'))}",
            "naos llm-grader-readiness --profile <profile>",
        ),
        (
            "StaticGrader",
            static_grader.get("status"),
            static_grader.get("human_review_required"),
            f"findings: {_table_cell(static_summary.get('total_findings'))}; dimensions: {_table_cell(static_summary.get('dimensions'))}",
            "naos static-grader --profile <profile>",
        ),
        (
            "Spec-pack contract",
            spec_pack.get("status"),
            spec_pack.get("human_review_required"),
            f"spec missing: {_table_cell(spec_pack_summary.get('spec_files_missing'))}; support missing: {_table_cell(spec_pack_summary.get('support_files_missing'))}; not applicable: {_table_cell(spec_pack_summary.get('files_not_applicable'))}; unresolved refs: {_table_cell(spec_pack_summary.get('traceability_reference_findings'))}; findings: {_table_cell(spec_pack_summary.get('total_findings'))}",
            "naos spec-pack-contract --profile <profile>",
        ),
        (
            "Spec-pack materialization",
            spec_materialization.get("status"),
            spec_materialization.get("human_review_required"),
            f"copied: {_table_cell(spec_materialization_summary.get('copied'))}; would copy: {_table_cell(spec_materialization_summary.get('would_copy'))}; skipped: {_table_cell(spec_materialization_summary.get('skipped_existing'))}; missing source: {_table_cell(spec_materialization_summary.get('missing_source'))}",
            "naos spec-pack-materialize . --profile <profile> --dry-run",
        ),
        (
            "Spec assembly worksheet",
            spec_worksheet.get("status"),
            spec_worksheet.get("human_review_required"),
            f"missing specs: {_table_cell(spec_worksheet_summary.get('required_spec_files_missing'))}; candidates: {_table_cell(spec_worksheet_summary.get('candidate_requirements'))}; applicability decisions: {_table_cell(spec_worksheet_summary.get('non_applicability_decisions_needed'))}",
            "naos spec-assembly-worksheet . --profile <profile>",
        ),
        (
            "AC completion evidence",
            ac_completion.get("status"),
            ac_completion.get("human_review_required"),
            f"configured: {_table_cell(ac_completion_summary.get('configured'))}; claimed: {_table_cell(ac_completion_summary.get('claimed_complete'))}; unsatisfied: {_table_cell(ac_completion_summary.get('unsatisfied_completions'))}",
            "naos ac-completion-evidence --profile <profile>",
        ),
        (
            "Evidence attestation",
            evidence_attestation.get("status"),
            evidence_attestation.get("human_review_required"),
            f"hashed: {_table_cell(evidence_attestation_summary.get('artifacts_hashed'))}; missing: {_table_cell(evidence_attestation_summary.get('missing_artifacts'))}",
            "naos evidence-attestation --profile <profile>",
        ),
        (
            "Evidence verification",
            evidence_verification.get("status"),
            evidence_verification.get("human_review_required"),
            f"tamper-evident: {_table_cell(evidence_verification.get('tamper_evident'))}; signature entries: {_table_cell(evidence_verification.get('signature_entries_present'))}; envelope signature validated by NAOS: {_table_cell(evidence_verification.get('signature_validation_performed'))}; invalid validation claim rejected: {_table_cell(evidence_verification.get('signature_validation_claim_rejected'))}",
            "naos evidence-verify --profile <profile>",
        ),
        (
            "Evidence conflicts",
            evidence_conflicts.get("status"),
            evidence_conflicts.get("human_review_required"),
            f"conflicts: {_table_cell(evidence_conflicts.get('conflict_count'))}; unrouted: {_table_cell(len(evidence_conflicts.get('unrouted_conflicts') or []))}",
            "naos evidence-conflicts --profile <profile>",
        ),
        (
            "Plan coherence",
            plan_coherence.get("status"),
            plan_coherence.get("human_review_required"),
            f"active claims: {_table_cell(plan_coherence_summary.get('active_claims'))}; findings: {_table_cell(plan_coherence_summary.get('total_findings'))}",
            "naos plan-coherence --profile <profile>",
        ),
        (
            "Failure-mode observations",
            failure_mode_observations.get("status"),
            failure_mode_observations.get("human_review_required"),
            f"observations: {_table_cell(failure_mode_summary.get('observations'))}; modes: {_table_cell(failure_mode_summary.get('modes_with_observations'))}; unmapped: {_table_cell(failure_mode_summary.get('unmapped_observations'))}",
            "naos failure-mode-observations --profile <profile>",
        ),
        (
            "Systemic impact review",
            systemic.get("status"),
            systemic_summary.get("human_review_required"),
            f"configured: {_table_cell(systemic_summary.get('configured'))}; review required: {_table_cell(systemic_summary.get('review_required'))}",
            "naos systemic-impact --profile <profile>",
        ),
        (
            "Control-plane review routing",
            control_review.get("status"),
            control_review.get("human_review_required"),
            f"missing routing: {_table_cell(control_review_summary.get('missing_routing'))}; review required: {_table_cell(control_review_summary.get('review_required'))}",
            "naos control-plane-review --profile <profile>",
        ),
        (
            "Evidence pack",
            evidence_pack.get("status"),
            "review if gaps",
            f"present: {_table_cell(evidence_pack_summary.get('present_artifacts'))}; missing: {_table_cell(evidence_pack_summary.get('missing_artifacts'))}; stale: {_table_cell(evidence_pack_summary.get('stale_artifacts'))}",
            "naos evidence-pack --profile <profile>",
        ),
    ]

    lines = [
        "### Control Plane Status Matrix",
        "",
        "| Area | Status | Human review | Main signal | Next command |",
        "|------|--------|--------------|-------------|--------------|",
    ]
    for area, status, review, signal, command in rows:
        review_value = review
        if status in {"missing", "not_configured"} and review is False:
            review_value = None
        lines.append(
            f"| {_table_cell(area)} | {_table_cell(status)} | {_review_cell(review_value)} | {_table_cell(signal)} | `{_table_cell(command)}` |"
        )
    return lines


def render_behavioral_readiness_flow() -> list[str]:
    return [
        "",
        "#### Behavioral Governance Readiness Flow",
        "",
        "```mermaid",
        "flowchart LR",
        "    D[\"Deterministic evidence<br/>conformance, StaticGrader, reports\"] --> R[\"Readiness classification<br/>review input only\"]",
        "    R --> H[\"Human baseline decision<br/>create or maintain outside this command\"]",
        "    H -. \"optional advisory only; non-authoritative; not executed here\" .-> A[\"Non-deterministic readiness<br/>LLM posture, no provider call\"]",
        "```",
    ]


def render_testing_metrics(
    control_plane: dict[str, Any] | None,
    traceability: dict[str, Any] | None,
) -> list[str]:
    pytest_coverage, pytest_target = _read_pytest_coverage()
    coverage_source = "live .coverage or baseline" if pytest_coverage else "not_configured"
    if pytest_coverage >= pytest_target:
        coverage_status = "on_target"
    elif pytest_coverage and pytest_coverage >= pytest_target * 0.85:
        coverage_status = "near_target"
    elif pytest_coverage:
        coverage_status = "below_target"
    else:
        coverage_status = "not_configured"

    test_evidence = (control_plane or {}).get("test_evidence_health") or {}
    test_summary = test_evidence.get("map_summary") or {}
    ac_completion = (control_plane or {}).get("ac_completion_evidence") or {}
    ac_completion_summary = ac_completion.get("summary") or {}
    evidence_type_counts = test_summary.get("evidence_type_counts") or {}
    evidence_type_value = (
        ", ".join(f"{key}: {value}" for key, value in sorted(evidence_type_counts.items()))
        if evidence_type_counts
        else "—"
    )
    mapped_sources = test_summary.get("mapped_sources")
    total_sources = test_summary.get("sources")
    unmapped_sources = test_summary.get("unmapped_sources")
    source_map_value = (
        f"{_table_cell(mapped_sources)}/{_table_cell(total_sources)}"
        if mapped_sources is not None or total_sources is not None
        else "—"
    )
    unmapped_value = _table_cell(unmapped_sources)
    test_quality = ((control_plane or {}).get("deterministic_hygiene") or {})
    test_quality_status = (test_quality.get("report_statuses") or {}).get("test_quality_hygiene")
    test_quality_summary = (test_quality.get("summaries") or {}).get("test_quality_hygiene") or {}
    package_reality_status = (test_quality.get("report_statuses") or {}).get("package_reality")
    package_reality_summary = (test_quality.get("summaries") or {}).get("package_reality") or {}
    api_symbol_status = (test_quality.get("report_statuses") or {}).get("api_symbol_reality")
    api_symbol_summary = (test_quality.get("summaries") or {}).get("api_symbol_reality") or {}
    traceability_value = "—"
    traceability_status = "not_configured"
    if traceability:
        traced = traceability.get("reqs_traced", 0)
        total = traceability.get("reqs_total", 0)
        traced_pct = traceability.get("reqs_traced_pct", 0)
        traceability_value = f"{traced}/{total} ({traced_pct:.1f}%)"
        traceability_status = "present"

    return [
        "",
        "## Testing Metrics",
        "",
        "| Metric | Value | Status | Source |",
        "|--------|-------|--------|--------|",
        f"| Pytest coverage | {pytest_coverage:.1f}% / target {pytest_target:.0f}% | {_table_cell(coverage_status)} | {_table_cell(coverage_source)} |",
        f"| Source-to-test map | {source_map_value} mapped sources | {_table_cell(test_evidence.get('health_status'))} | `naos/test_evidence/source_to_test_map.json` |",
        f"| Unmapped sources | {unmapped_value} | {_table_cell(test_evidence.get('health_status'))} | `naos/test_evidence/source_to_test_map.json` |",
        f"| Evidence type counts | {_table_cell(evidence_type_value)} | {_table_cell(test_evidence.get('map_status'))} | `naos/test_evidence/source_to_test_map.json` |",
        f"| Coverage support default | {_table_cell(test_evidence.get('coverage_supports_source_default'))} | {_table_cell(test_evidence.get('health_status'))} | `naos/reports/test_evidence_health.json` |",
        f"| AC completion evidence | claimed {_table_cell(ac_completion_summary.get('claimed_complete'))}; satisfied {_table_cell(ac_completion_summary.get('satisfied_completions'))}; unsatisfied {_table_cell(ac_completion_summary.get('unsatisfied_completions'))}; repository-bound {_table_cell(ac_completion_summary.get('repository_bound_completions'))}; subject operands {_table_cell(ac_completion_summary.get('subject_operands_checked'))}; superseded records {_table_cell(ac_completion_summary.get('superseded_completion_records'))} | {_table_cell(ac_completion.get('status'))} | `naos/reports/ac_completion_evidence.json` |",
        f"| Test functions scanned | {_table_cell(test_quality_summary.get('test_functions_scanned'))} | {_table_cell(test_quality_status)} | `naos/reports/test_quality_hygiene.json` |",
        f"| Missing assertions | {_table_cell(test_quality_summary.get('missing_assertions'))} | {_table_cell(test_quality_status)} | `naos/reports/test_quality_hygiene.json` |",
        f"| Trivial assertions | {_table_cell(test_quality_summary.get('trivial_assertions'))} | {_table_cell(test_quality_status)} | `naos/reports/test_quality_hygiene.json` |",
        f"| Test parse errors | {_table_cell(test_quality_summary.get('parse_errors'))} | {_table_cell(test_quality_status)} | `naos/reports/test_quality_hygiene.json` |",
        f"| Package-reality findings | {_table_cell(package_reality_summary.get('total_findings'))} | {_table_cell(package_reality_status)} | `naos/reports/package_reality.json` |",
        f"| Package-reality registry mode | {_table_cell(package_reality_summary.get('registry_mode'))} | {_table_cell(package_reality_status)} | `naos/reports/package_reality.json` |",
        f"| Package-reality SBOM PyPI components | {_table_cell(package_reality_summary.get('sbom_pypi_components'))} | {_table_cell(package_reality_status)} | `naos/reports/package_reality.json` |",
        f"| Package-reality provenance packages | {_table_cell(package_reality_summary.get('provenance_packages'))} | {_table_cell(package_reality_status)} | `naos/reports/package_reality.json` |",
        f"| Package-reality expected hashes | {_table_cell(package_reality_summary.get('provenance_expected_hashes'))} | {_table_cell(package_reality_status)} | `naos/reports/package_reality.json` |",
        f"| API-symbol reality | verified {_table_cell(api_symbol_summary.get('verified_symbols'))}; unverified {_table_cell(api_symbol_summary.get('unverified_symbols'))}; configured {_table_cell(api_symbol_summary.get('configured'))} | {_table_cell(api_symbol_status)} | `naos/reports/api_symbol_reality.json` |",
        f"| Requirements traced | {traceability_value} | {_table_cell(traceability_status)} | `naos/TRACEABILITY_MATRIX.md` |",
    ]


def render_governance_context_detail_rows(control_plane: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    bypass = control_plane.get("governance_bypass_posture") or {}
    bypass_summary = bypass.get("summary") or {}
    bypass_hook = bypass.get("hook") or {}
    bypass_ci = bypass.get("ci") or {}
    lines.append(
        f"| Governance bypass posture | {_table_cell(bypass.get('status'))} | hook present: {_table_cell(bypass_hook.get('pre_commit_hook_present'))}; NAOS CI: {_table_cell(bypass_ci.get('naos_ci_present'))}; bypass markers: {_table_cell(bypass_summary.get('bypass_marker_findings'))}; human review: {_table_cell(bypass.get('human_review_required'))} |"
    )
    external_evidence = control_plane.get("external_evidence_ingest") or {}
    external_summary = external_evidence.get("summary") or {}
    lines.append(
        f"| External evidence ingest | {_table_cell(external_evidence.get('status'))} | source present: {_table_cell(external_summary.get('source_present'))}; results: {_table_cell(external_summary.get('results'))}; verification: {_table_cell(external_evidence.get('verification_status'))}; human review: {_table_cell(external_evidence.get('human_review_required'))} |"
    )
    policy_overrides = control_plane.get("policy_overrides") or {}
    policy_override_summary = policy_overrides.get("override_summary") or policy_overrides.get("summary") or {}
    applied_overlay_scopes = policy_overrides.get("applied_overlay_scopes") or []
    lines.append(
        f"| Policy overrides | {_table_cell(policy_overrides.get('status'))} | files: {_table_cell(policy_override_summary.get('override_files'))}; applied paths: {_table_cell(policy_override_summary.get('applied_paths'))}; scopes: {_table_cell(', '.join(applied_overlay_scopes) if applied_overlay_scopes else 'none')}; protected violations: {_table_cell(len(policy_overrides.get('protected_invariant_violations') or []))}; human review: {_table_cell(policy_overrides.get('human_review_required'))} |"
    )
    pr_risk = control_plane.get("pr_risk_classification") or {}
    pr_risk_summary = pr_risk.get("summary") or {}
    pr_contributor = pr_risk.get("contributor") or {}
    lines.append(
        f"| PR risk classification | {_table_cell(pr_risk.get('status'))} | changed files: {_table_cell(pr_risk.get('changed_files'))}; risk files: {_table_cell(pr_risk_summary.get('risk_files'))}; findings: {_table_cell(pr_risk_summary.get('total_findings'))}; contributor trust: {_table_cell(pr_contributor.get('trust'))}; human review: {_table_cell(pr_risk.get('human_review_required'))} |"
    )
    pr_governance = control_plane.get("pr_governance") or {}
    pr_governance_summary = pr_governance.get("summary") or {}
    lines.append(
        f"| PR governance CI | {_table_cell(pr_governance.get('status'))} | provider: {_table_cell(pr_governance.get('ci_provider'))}; PR: {_table_cell(pr_governance.get('pull_request_number'))}; team: {_table_cell(pr_governance.get('team_id'))}; reports: {_table_cell(pr_governance_summary.get('reports_present'))}/{_table_cell(pr_governance_summary.get('reports_expected'))}; human review: {_table_cell(pr_governance.get('human_review_required'))} |"
    )
    agentic_workflow = control_plane.get("agentic_workflow") or {}
    agentic_summary = agentic_workflow.get("summary") or {}
    lines.append(
        f"| Agentic workflow | {_table_cell(agentic_workflow.get('status'))} | config valid: {_table_cell(agentic_workflow.get('workflow_config_valid'))}; sections enabled: {_table_cell(agentic_summary.get('sections_enabled'))}; missing artifacts: {_table_cell(len(agentic_workflow.get('missing_artifacts') or []))}; human review: {_table_cell(agentic_workflow.get('human_review_required'))} |"
    )
    alignment = control_plane.get("pre_implementation_alignment") or {}
    coverage = alignment.get("question_coverage") or {}
    lines.append(
        f"| Pre-Implementation Alignment | {_table_cell(alignment.get('status'))} | mode: {_table_cell(alignment.get('mode'))}; answered: {_table_cell(coverage.get('answered_questions'))}/{_table_cell(coverage.get('total_questions'))}; missing required: {_table_cell(len(alignment.get('missing_required_questions') or []))}; human review: {_table_cell(alignment.get('human_review_required'))} |"
    )
    attestation_summary = control_plane["evidence_attestation"]["summary"]
    lines.append(
        f"| Evidence attestation | {_table_cell(control_plane['evidence_attestation']['status'])} | hashed: {_table_cell(attestation_summary.get('artifacts_hashed'))}; missing: {_table_cell(attestation_summary.get('missing_artifacts'))}; reviewer metadata: {_table_cell(attestation_summary.get('reviewer_attestations'))} |"
    )
    evidence_verification = control_plane.get("evidence_verification") or {}
    lines.append(
        f"| Evidence verification | {_table_cell(evidence_verification.get('status'))} | tamper-evident: {_table_cell(evidence_verification.get('tamper_evident'))}; signature entries: {_table_cell(evidence_verification.get('signature_entries_present'))}; envelope signature validated by NAOS: {_table_cell(evidence_verification.get('signature_validation_performed'))}; invalid validation claim rejected: {_table_cell(evidence_verification.get('signature_validation_claim_rejected'))}; checked: {_table_cell(evidence_verification.get('artifacts_checked'))}; human review: {_table_cell(evidence_verification.get('human_review_required'))} |"
    )
    evidence_conflicts = control_plane.get("evidence_conflicts") or {}
    lines.append(
        f"| Evidence conflicts | {_table_cell(evidence_conflicts.get('status'))} | conflicts: {_table_cell(evidence_conflicts.get('conflict_count'))}; unrouted: {_table_cell(len(evidence_conflicts.get('unrouted_conflicts') or []))}; human review: {_table_cell(evidence_conflicts.get('human_review_required'))} |"
    )
    memory_summary = control_plane["memory_context_readiness"]["summary"]
    lines.append(
        f"| Memory/context readiness | {_table_cell(control_plane['memory_context_readiness']['status'])} | platforms: {_table_cell(memory_summary.get('platforms'))}; declared memory: {_table_cell(memory_summary.get('platforms_with_declared_memory'))}; human review: {_table_cell(memory_summary.get('human_review_required'))} |"
    )
    memory_access = control_plane["memory_provider_access"]
    lines.append(
        f"| Memory provider access | {_table_cell(memory_access.get('status'))} | provider: {_table_cell(memory_access.get('provider_name'))}; configured: {_table_cell(memory_access.get('provider_configured'))}; provider access verified: {_table_cell(memory_access.get('provider_access_verified'))}; MCP access verified: {_table_cell(memory_access.get('mcp_access_verified'))} |"
    )
    memory_use = control_plane["memory_use_policy"]
    memory_use_summary = memory_use.get("summary") or {}
    lines.append(
        f"| Memory use policy | {_table_cell(memory_use.get('status'))} | review items: {_table_cell(memory_use_summary.get('memory_review_items'))}; instruction-grade: {_table_cell(memory_use_summary.get('instruction_grade_items'))}; unsafe instruction claims: {_table_cell(memory_use_summary.get('unsafe_instruction_grade_claims'))}; human review: {_table_cell(memory_use.get('human_review_required'))} |"
    )
    learning_loop = control_plane["learning_loop_review"]
    learning_summary = learning_loop.get("summary") or {}
    lines.append(
        f"| Governed learning lifecycle | {_table_cell(learning_loop.get('status'))} | records: {_table_cell(learning_summary.get('learning_records'))}; active: {_table_cell(learning_summary.get('active_records'))}; high-authority active: {_table_cell(learning_summary.get('high_authority_active_records'))}; human review: {_table_cell(learning_loop.get('human_review_required'))} |"
    )
    failure_mode_observations = control_plane.get("failure_mode_observations") or {}
    failure_mode_summary = failure_mode_observations.get("summary") or {}
    lines.append(
        f"| Failure-mode observations | {_table_cell(failure_mode_observations.get('status'))} | declared: {_table_cell(failure_mode_observations.get('failure_mode_observations_declared'))}; observations: {_table_cell(failure_mode_summary.get('observations'))}; modes: {_table_cell(failure_mode_summary.get('modes_with_observations'))}; unmapped: {_table_cell(failure_mode_summary.get('unmapped_observations'))}; human review: {_table_cell(failure_mode_observations.get('human_review_required'))} |"
    )
    adapter_coherence = control_plane.get("adapter_coherence") or {}
    adapter_summary = adapter_coherence.get("summary") or {}
    lines.append(
        f"| Adapter coherence | {_table_cell(adapter_coherence.get('status'))} | plugins: {_table_cell(adapter_summary.get('plugins_present'))}/{_table_cell(adapter_summary.get('plugins_expected'))}; plugin skills: {_table_cell(adapter_summary.get('plugin_skills_present'))}/{_table_cell(adapter_summary.get('plugin_skills_expected'))}; propagation: {_table_cell(adapter_summary.get('propagation_links_reviewed'))}/{_table_cell(adapter_summary.get('propagation_links_expected'))} reviewed, {_table_cell(adapter_summary.get('propagation_links_stale'))} stale; surfaces: {_table_cell(adapter_summary.get('adapter_surfaces_present'))}/{_table_cell(adapter_summary.get('adapter_surfaces_expected'))}; project adapters: {_table_cell(adapter_summary.get('project_local_adapters_present'))}; human review: {_table_cell(adapter_coherence.get('human_review_required'))} |"
    )
    task_context = control_plane["task_context_pack"]
    task_context_summary = task_context.get("summary") or {}
    lines.append(
        f"| Task context pack | {_table_cell(task_context.get('status'))} | task: {_table_cell(task_context.get('task_id'))}; sources: {_table_cell(task_context_summary.get('source_artifacts_used'))}; missing: {_table_cell(len(task_context.get('source_artifacts_missing') or []))}; human review: {_table_cell(task_context.get('human_review_required'))} |"
    )
    task_lifecycle = control_plane.get("task_lifecycle") or {}
    lines.append(
        f"| Native task lifecycle | {_table_cell(task_lifecycle.get('status'))} | action: {_table_cell(task_lifecycle.get('action'))}; task: {_table_cell(task_lifecycle.get('task_id'))}; delivery: {_table_cell(task_lifecycle.get('delivery_state'))}; requested verification: {_table_cell(task_lifecycle.get('requested_verification_state'))}; effective verification: {_table_cell(task_lifecycle.get('effective_verification_state'))}; prerequisites met: {_table_cell(task_lifecycle.get('verification_prerequisites_met'))}; human review: {_table_cell(task_lifecycle.get('human_review_required'))}; review reasons: {_table_cell(task_lifecycle.get('review_reasons'))}; review posture source: {_table_cell(task_lifecycle.get('review_posture_source'))} |"
    )
    research_record = control_plane.get("research_record") or {}
    lines.append(
        f"| Structured research record | {_table_cell(research_record.get('status'))} | candidate-only; findings: {_table_cell(len(research_record.get('findings') or []))}; human review: {_table_cell(research_record.get('human_review_required'))} |"
    )
    composed_traceability = control_plane.get("composed_traceability") or {}
    composed_summary = composed_traceability.get("summary") or {}
    canonical_review = composed_traceability.get("canonical_task_review") or {}
    traceability_review = composed_traceability.get("traceability_review") or {}
    lines.append(
        f"| Composed traceability | {_table_cell(composed_traceability.get('status'))} | chains: {_table_cell(composed_summary.get('complete_chains'))}/{_table_cell(composed_summary.get('tasks'))}; findings: {_table_cell(len(composed_traceability.get('findings') or []))}; canonical task review: {_table_cell(canonical_review.get('human_review_required'))}; traceability review: {_table_cell(traceability_review.get('human_review_required'))}; aggregate human review: {_table_cell(composed_traceability.get('human_review_required'))} |"
    )
    local_index = control_plane["local_context_index"]
    local_index_summary = local_index.get("summary") or {}
    lines.append(
        f"| Local context index | {_table_cell(local_index.get('status'))} | artifacts: {_table_cell(local_index_summary.get('indexed_artifacts'))}; chunks: {_table_cell(local_index_summary.get('chunks'))}; FTS: {_table_cell(local_index.get('fts_available'))}; human review: {_table_cell(local_index.get('human_review_required'))} |"
    )
    local_query = control_plane["local_context_query"]
    lines.append(
        f"| Local context query | {_table_cell(local_query.get('status'))} | results: {_table_cell(local_query.get('result_count'))}; modes: {_table_cell(', '.join(local_query.get('query_mode_used') or []))}; human review: {_table_cell(local_query.get('human_review_required'))} |"
    )
    semantic_layer = control_plane["semantic_candidate_layer"]
    semantic_summary = semantic_layer.get("summary") or {}
    lines.append(
        f"| Semantic candidate readiness | {_table_cell(semantic_layer.get('status'))} | runtime: {_table_cell(semantic_layer.get('semantic_runtime_enabled'))}; sqlite-vec: {_table_cell(semantic_layer.get('sqlite_vec_enabled'))}; embeddings: {_table_cell(semantic_layer.get('embeddings_enabled'))}; human review: {_table_cell(semantic_summary.get('human_review_required'))} |"
    )
    graph_query = control_plane["graph_context_query"]
    lines.append(
        f"| Graph context query | {_table_cell(graph_query.get('status'))} | results: {_table_cell(graph_query.get('result_count'))}; depth: {_table_cell(graph_query.get('traversal_depth_used'))}; modes: {_table_cell(', '.join(graph_query.get('query_mode_used') or []))}; human review: {_table_cell(graph_query.get('human_review_required'))} |"
    )
    session_identity = control_plane.get("session_identity") or {}
    lines.append(
        f"| Session identity | {_table_cell(session_identity.get('status'))} | session: {_table_cell(session_identity.get('session_id'))}; report root: {_table_cell(session_identity.get('session_report_root'))}; latest compatibility: {_table_cell(bool(session_identity.get('latest_report_compatibility')))}; human review: {_table_cell(session_identity.get('human_review_required'))} |"
    )
    operator_attribution = control_plane.get("operator_attribution") or {}
    lines.append(
        f"| Operator attribution | {_table_cell(operator_attribution.get('status'))} | source: {_table_cell(operator_attribution.get('operator_source'))}; attribution: {_table_cell(operator_attribution.get('operator_attribution_status'))}; session: {_table_cell(operator_attribution.get('session_id'))}; human review: {_table_cell(operator_attribution.get('human_review_required'))} |"
    )
    task_claims = control_plane.get("task_claims") or {}
    lines.append(
        f"| Task claims | {_table_cell(task_claims.get('status'))} | active: {_table_cell(task_claims.get('active_claim_count'))}; released: {_table_cell(task_claims.get('released_claim_count'))}; conflicts: {_table_cell(task_claims.get('conflicting_claim_count'))}; human review: {_table_cell(task_claims.get('human_review_required'))} |"
    )
    plan_coherence = control_plane.get("plan_coherence") or {}
    plan_coherence_summary = plan_coherence.get("summary") or {}
    lines.append(
        f"| Plan coherence | {_table_cell(plan_coherence.get('status'))} | active claims: {_table_cell(plan_coherence_summary.get('active_claims'))}; registry tasks: {_table_cell(plan_coherence_summary.get('registry_tasks'))}; linked tasks: {_table_cell(plan_coherence_summary.get('tasks_with_file_linkage'))}; findings: {_table_cell(plan_coherence_summary.get('total_findings'))}; human review: {_table_cell(plan_coherence.get('human_review_required'))} |"
    )
    session_lifecycle = control_plane["session_lifecycle"]
    session_summary = session_lifecycle.get("summary") or {}
    lines.append(
        f"| Session lifecycle | {_table_cell(session_lifecycle.get('status'))} | mode: {_table_cell(session_lifecycle.get('mode'))}; task: {_table_cell(session_lifecycle.get('task_id'))}; proposals: {_table_cell(len(session_lifecycle.get('memory_candidate_proposals') or []))}; stale inputs: {_table_cell(session_summary.get('stale_inputs'))}; human review: {_table_cell(session_lifecycle.get('human_review_required'))} |"
    )
    return lines


def render_control_plane_dashboard(control_plane: dict[str, Any] | None) -> list[str]:
    if not control_plane:
        return []

    lines = [
        "\n## NAOS Control-Plane Health",
        "",
        "> NAOS ships a portable, file-first capability-contract framework for SDLC governance. It does not ship runtime governance, behavioral grading, or compliance certification. Projects activate and mature capabilities progressively through profiles, readiness gates, and evidence.",
        "",
    ]
    lines.extend(render_control_plane_status_matrix(control_plane))
    lines.extend(
        [
            "",
            "<details>",
            "<summary>Detailed control-plane panel signals</summary>",
            "",
            "| Panel | Status | Signal |",
            "|-------|--------|--------|",
        ]
    )
    lines.append(
        f"| Capability maturity | {_table_cell(control_plane['capability_maturity']['status'])} | {control_plane['capability_maturity']['total']} contracts, readiness report: {_table_cell(control_plane['capability_maturity_readiness']['status'])} |"
    )
    systemic_summary = control_plane["systemic_impact_review"]["summary"]
    lines.append(
        f"| Systemic impact review | {_table_cell(control_plane['systemic_impact_review']['status'])} | configured: {_table_cell(systemic_summary.get('configured'))}; review required: {_table_cell(systemic_summary.get('review_required'))}; not configured: {_table_cell(systemic_summary.get('not_configured'))} |"
    )
    module_summary = control_plane["module_header_traceability"]["summary"]
    lines.append(
        f"| Module header traceability | {_table_cell(control_plane['module_header_traceability']['status'])} | scanned: {_table_cell(module_summary.get('scanned_files'))}; missing: {_table_cell(module_summary.get('missing_headers'))}; legacy: {_table_cell(module_summary.get('legacy_headers'))} |"
    )
    spec_pack_summary = control_plane["spec_pack_contract"]["summary"]
    lines.append(
        f"| Spec-pack contract | {_table_cell(control_plane['spec_pack_contract']['status'])} | spec files: {_table_cell(spec_pack_summary.get('spec_files_present'))}/{_table_cell(spec_pack_summary.get('spec_files_expected'))}; support files: {_table_cell(spec_pack_summary.get('support_files_present'))}/{_table_cell(spec_pack_summary.get('support_files_expected'))}; not applicable: {_table_cell(spec_pack_summary.get('files_not_applicable'))}; unresolved refs: {_table_cell(spec_pack_summary.get('traceability_reference_findings'))}; findings: {_table_cell(spec_pack_summary.get('total_findings'))} |"
    )
    spec_materialization_summary = control_plane["spec_pack_materialization"]["summary"]
    spec_materialization_signal = (
        f"copied: {_table_cell(spec_materialization_summary.get('copied'))}; "
        f"would copy: {_table_cell(spec_materialization_summary.get('would_copy'))}; "
        f"skipped existing: {_table_cell(spec_materialization_summary.get('skipped_existing'))}; "
        f"missing source: {_table_cell(spec_materialization_summary.get('missing_source'))}"
    )
    optional_materialization_signals = [
        ("invalid manifest", "invalid_manifest"),
        ("unsafe paths", "unsafe_paths"),
        ("copy cleanup failed", "copy_cleanup_failed"),
        ("report write failed", "report_write_failed"),
        ("findings", "total_findings"),
    ]
    for label, key in optional_materialization_signals:
        if key in spec_materialization_summary:
            spec_materialization_signal += f"; {label}: {_table_cell(spec_materialization_summary.get(key))}"
    lines.append(
        f"| Spec-pack materialization | {_table_cell(control_plane['spec_pack_materialization']['status'])} | {spec_materialization_signal} |"
    )
    spec_worksheet_summary = control_plane["spec_assembly_worksheet"]["summary"]
    lines.append(
        f"| Spec assembly worksheet | {_table_cell(control_plane['spec_assembly_worksheet']['status'])} | missing spec files: {_table_cell(spec_worksheet_summary.get('required_spec_files_missing'))}; candidates: {_table_cell(spec_worksheet_summary.get('candidate_requirements'))}; gap mappings: {_table_cell(spec_worksheet_summary.get('traceability_gaps'))}; applicability decisions: {_table_cell(spec_worksheet_summary.get('non_applicability_decisions_needed'))} |"
    )
    spec_cascade_summary = control_plane["spec_cascade_coherence"]["summary"]
    lines.append(
        f"| Spec cascade coherence | {_table_cell(control_plane['spec_cascade_coherence']['status'])} | findings: {_table_cell(spec_cascade_summary.get('total_findings'))}; uncovered: {_table_cell(spec_cascade_summary.get('uncovered_requirements'))}; untraced source: {_table_cell(spec_cascade_summary.get('untraced_sources'))}; unresolved refs: {_table_cell(spec_cascade_summary.get('unresolved_source_references'))} |"
    )
    control_review_summary = control_plane["control_plane_review"]["summary"]
    lines.append(
        f"| Control-plane review routing | {_table_cell(control_plane['control_plane_review']['status'])} | routed: {_table_cell(control_review_summary.get('routed'))}; missing routing: {_table_cell(control_review_summary.get('missing_routing'))}; review required: {_table_cell(control_review_summary.get('review_required'))} |"
    )
    setup_summary = control_plane["setup_recommendations"]["summary"]
    setup_deferred = (
        (setup_summary.get("defer") or 0)
        + (setup_summary.get("readiness_only") or 0)
        + (setup_summary.get("experimental") or 0)
    )
    lines.append(
        f"| Setup recommendations | {_table_cell(control_plane['setup_recommendations']['status'])} | configured: {_table_cell(setup_summary.get('configured'))}; recommended: {_table_cell(setup_summary.get('recommended'))}; optional: {_table_cell(setup_summary.get('optional'))}; deferred/readiness-only: {_table_cell(setup_deferred)} |"
    )
    lines.extend(render_governance_context_detail_rows(control_plane))
    audit_log = control_plane.get("audit_log") or {}
    lines.append(
        f"| Audit log | {_table_cell(audit_log.get('status'))} | events: {_table_cell(audit_log.get('event_count'))}; invalid: {_table_cell(audit_log.get('invalid_event_count'))}; missing session ids: {_table_cell(len(audit_log.get('missing_session_id_events') or []))}; human review: {_table_cell(audit_log.get('human_review_required'))} |"
    )
    agent_trace_validation = control_plane.get("agent_trace_validation") or {}
    agent_trace_summary = agent_trace_validation.get("summary") or {}
    lines.append(
        f"| Agent trace validation | {_table_cell(agent_trace_validation.get('status'))} | events: {_table_cell(agent_trace_validation.get('event_count'))}; action receipts: {_table_cell(agent_trace_summary.get('action_receipt_events'))}; invalid: {_table_cell(agent_trace_validation.get('invalid_event_count'))}; payload findings: {_table_cell(len(agent_trace_validation.get('forbidden_payload_findings') or []))}; human review: {_table_cell(agent_trace_validation.get('human_review_required'))} |"
    )
    ai_surface = control_plane.get("ai_surface_health") or {}
    ai_surface_summary = ai_surface.get("summary") or {}
    lines.append(
        f"| AI-surface health | {_table_cell(ai_surface.get('ai_surface_health_posture') or ai_surface.get('status'))} | tokens: {_table_cell(ai_surface_summary.get('total_estimated_tokens'))}; files: {_table_cell(ai_surface_summary.get('total_files'))}; findings: {_table_cell(ai_surface_summary.get('total_findings'))}; human review: {_table_cell(ai_surface.get('human_review_required'))} |"
    )
    static_grader = control_plane.get("static_grader") or {}
    static_summary = static_grader.get("summary") or {}
    static_cost = static_grader.get("cost_posture") or {}
    lines.append(
        f"| StaticGrader | {_table_cell(static_grader.get('status'))} | findings: {_table_cell(static_summary.get('total_findings'))}; dimensions: {_table_cell(static_summary.get('dimensions'))}; cost_usd: {_table_cell(static_cost.get('cost_usd'))}; human review: {_table_cell(static_grader.get('human_review_required'))} |"
    )
    llm_readiness = control_plane.get("llm_grader_readiness") or {}
    llm_cost = llm_readiness.get("cost_posture") or {}
    lines.append(
        f"| LLMGrader readiness | {_table_cell(llm_readiness.get('status'))} | runtime: {_table_cell(llm_readiness.get('runtime_enabled'))}; provider allowed: {_table_cell(llm_readiness.get('provider_allowed'))}; cost_usd: {_table_cell(llm_cost.get('cost_usd'))}; human review: {_table_cell(llm_readiness.get('human_review_required'))} |"
    )
    behavioral_readiness = control_plane.get("behavioral_governance_readiness") or {}
    behavioral_summary = behavioral_readiness.get("summary") or {}
    behavioral_cost = behavioral_readiness.get("cost_posture") or {}
    lines.append(
        f"| Behavioral Governance Readiness | {_table_cell(behavioral_readiness.get('status'))} | baseline: {_table_cell(behavioral_readiness.get('baseline_state_present'))}; impacters: {_table_cell(behavioral_summary.get('total_impacters'))}; cost_usd: {_table_cell(behavioral_cost.get('cost_usd'))}; human review: {_table_cell(behavioral_readiness.get('human_review_required'))} |"
    )
    ai_code_provenance = control_plane.get("ai_code_provenance") or {}
    ai_code_summary = ai_code_provenance.get("summary") or {}
    ai_code_manifest = ai_code_provenance.get("manifest") or {}
    ai_code_cost = ai_code_provenance.get("cost_posture") or {}
    lines.append(
        f"| AI Code Provenance | {_table_cell(ai_code_provenance.get('status'))} | manifest: {_table_cell(ai_code_manifest.get('present'))}; declarations: {_table_cell(ai_code_summary.get('declarations'))}; missing evidence: {_table_cell(ai_code_summary.get('missing_evidence'))}; cost_usd: {_table_cell(ai_code_cost.get('cost_usd'))}; human review: {_table_cell(ai_code_provenance.get('human_review_required'))} |"
    )
    compliance_posture = control_plane.get("compliance_posture") or {}
    compliance_summary = compliance_posture.get("summary") or {}
    compliance_manifest = compliance_posture.get("manifest") or {}
    compliance_cost = compliance_posture.get("cost_posture") or {}
    lines.append(
        f"| Compliance Posture | {_table_cell(compliance_posture.get('status'))} | manifest: {_table_cell(compliance_manifest.get('present'))}; declared contexts: {_table_cell(compliance_summary.get('declared_contexts'))}; missing evidence: {_table_cell(compliance_summary.get('missing_evidence'))}; cost_usd: {_table_cell(compliance_cost.get('cost_usd'))}; human review: {_table_cell(compliance_posture.get('human_review_required'))} |"
    )
    lines.append(
        f"| Gatekeeper readiness | {_table_cell(control_plane['gatekeeper_readiness']['status'])} | {len(control_plane['gatekeeper_readiness']['gates'])} gates reported |"
    )
    lines.append(
        f"| Claims validation | {_table_cell(control_plane['claims_validation']['status'])} | {control_plane['claims_validation']['overclaim_findings']} overclaim findings, {control_plane['claims_validation']['external_references_unverified']} unverified external references |"
    )
    lines.append(
        f"| Self-conformance | {_table_cell(control_plane['self_conformance']['status'])} | {len(control_plane['self_conformance']['checks'])} checks aggregated |"
    )
    lines.append(
        f"| Roadmap/crosswalk | {_table_cell(control_plane['roadmap_crosswalk']['status'])} | {control_plane['roadmap_crosswalk']['implemented_without_evidence']} implemented-without-evidence findings |"
    )
    lines.append(
        f"| Function index | {_table_cell(control_plane['function_index_health']['status'])} | index exists: {_table_cell(control_plane['function_index_health']['index'].get('exists'))}; semantic snapshot: {_table_cell(control_plane['function_index_health']['semantic_quality_snapshot'].get('status'))} |"
    )
    test_summary = control_plane["test_evidence_health"]["map_summary"]
    lines.append(
        f"| Test evidence | {_table_cell(control_plane['test_evidence_health']['health_status'])} | mapped sources: {_table_cell(test_summary.get('mapped_sources'))}/{_table_cell(test_summary.get('sources'))}; coverage support: {_table_cell(control_plane['test_evidence_health']['coverage_supports_source_default'])} |"
    )
    ac_completion = control_plane.get("ac_completion_evidence") or {}
    ac_summary = ac_completion.get("summary") or {}
    lines.append(
        f"| AC completion evidence | {_table_cell(ac_completion.get('status'))} | configured: {_table_cell(ac_summary.get('configured'))}; claimed: {_table_cell(ac_summary.get('claimed_complete'))}; satisfied: {_table_cell(ac_summary.get('satisfied_completions'))}; unsatisfied: {_table_cell(ac_summary.get('unsatisfied_completions'))}; evidence-present only, not correctness proof |"
    )
    evidence_summary = control_plane["evidence_pack"]["summary"]
    lines.append(
        f"| Evidence pack | {_table_cell(control_plane['evidence_pack']['status'])} | present artifacts: {_table_cell(evidence_summary.get('present_artifacts'))}; missing: {_table_cell(evidence_summary.get('missing_artifacts'))}; stale: {_table_cell(evidence_summary.get('stale_artifacts'))} |"
    )
    lines.append(
        f"| Exceptions / waivers | {_table_cell('advisory' if control_plane['exceptions_waivers']['count'] else 'not_configured')} | {control_plane['exceptions_waivers']['count']} recorded; waived risk is not hidden as pass |"
    )
    lines.append(
        f"| Advanced capability readiness | {_table_cell(control_plane['advanced_capability_readiness']['status'])} | {len(control_plane['advanced_capability_readiness']['capabilities'])} scaffolded/advisory track(s) |"
    )
    lines.extend(["", "</details>"])

    capabilities = control_plane["capability_maturity"]["capabilities"]
    if capabilities:
        lines.extend(
            [
                "",
                "### Capability Maturity Summary",
                "",
                "| Capability | Name | Status | Default | Current | Profile | Enforcement |",
                "|------------|------|--------|---------|---------|---------|-------------|",
            ]
        )
        for cap in capabilities:
            status = f"{cap['status']}{' / experimental' if cap.get('experimental') else ''}"
            lines.append(
                f"| {_table_cell(cap['id'])} | {_table_cell(cap['name'])} | {_table_cell(status)} | {_table_cell(cap.get('default_maturity'))} | {_table_cell(cap.get('current_maturity'))} | {_table_cell(cap.get('target_maturity'))} | {_table_cell(cap.get('enforcement'))} |"
            )

    readiness = control_plane.get("capability_maturity_readiness") or {}
    readiness_caps = readiness.get("capabilities") or []
    if readiness_caps:
        lines.extend(
            [
                "",
                "### Capability Maturity Readiness",
                "",
                "> NAOS evaluates maturity readiness. It does not automatically promote, certify, or approve maturity. Final maturity decisions remain project governance decisions.",
                "",
                "| Capability | Enabled | Current | Target | Readiness | Ready For Review | Human Approval | Missing/Stale Evidence |",
                "|------------|---------|---------|--------|-----------|------------------|----------------|------------------------|",
            ]
        )
        for cap in readiness_caps:
            missing = (cap.get("missing_evidence") or []) + (cap.get("stale_evidence") or [])
            lines.append(
                f"| {_table_cell(cap.get('capability_id'))} | {_table_cell(cap.get('enabled'))} | {_table_cell(cap.get('current_maturity'))} | {_table_cell(cap.get('target_maturity'))} | {_table_cell(cap.get('evaluated_status'))} | {_table_cell(cap.get('ready_for_promotion'))} | {_table_cell(cap.get('human_approval_required'))} | {_table_cell(', '.join(missing) if missing else '—')} |"
            )
    elif readiness:
        lines.extend(
            [
                "",
                "### Capability Maturity Readiness",
                "",
                f"Status: `{_table_cell(readiness.get('status'))}`. Generate `naos/reports/capability_maturity.json` with `naos capability-maturity` or `make -f Makefile.naos naos-capability-maturity` to populate this section.",
            ]
        )

    systemic = control_plane.get("systemic_impact_review") or {}
    systemic_families = systemic.get("artifact_families") or []
    if systemic_families:
        lines.extend(
            [
                "",
                "### Systemic Impact & Coherence Review",
                "",
                "> NAOS evaluates configured artifact-family review obligations. It does not prove perfect coherence, complete impact analysis, or certification.",
                "",
                "| Family | Configured | Status | Human Review | Missing Expected | Review Obligations |",
                "|--------|------------|--------|--------------|------------------|--------------------|",
            ]
        )
        for family in systemic_families[:30]:
            obligations = [
                str(item.get("target_family_id"))
                for item in family.get("review_obligations") or []
                if isinstance(item, dict) and item.get("target_status") != "ready"
            ]
            lines.append(
                f"| {_table_cell(family.get('family_id'))} | {_table_cell(family.get('configured'))} | {_table_cell(family.get('evaluated_status'))} | {_table_cell(family.get('human_review_required'))} | {_table_cell(', '.join(family.get('missing_expected') or []) if family.get('missing_expected') else '—')} | {_table_cell(', '.join(obligations) if obligations else '—')} |"
            )
    elif systemic:
        lines.extend(
            [
                "",
                "### Systemic Impact & Coherence Review",
                "",
                f"Status: `{_table_cell(systemic.get('status'))}`. Generate `naos/reports/systemic_impact_review.json` with `naos systemic-impact` or `make -f Makefile.naos naos-systemic-impact` to populate this section.",
            ]
        )

    module_headers = control_plane.get("module_header_traceability") or {}
    module_files = module_headers.get("scanned_files") or []
    if module_files:
        lines.extend(
            [
                "",
                "### Module Header Traceability",
                "",
                "> NAOS evaluates canonical source-module header evidence. It does not prove complete source traceability or code correctness.",
                "",
                "| Source File | Status | Module Path | Missing Sections | Human Review |",
                "|-------------|--------|-------------|------------------|--------------|",
            ]
        )
        for item in module_files[:30]:
            lines.append(
                f"| {_table_cell(item.get('path'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('module_path'))} | {_table_cell(', '.join(item.get('missing_sections') or []) if item.get('missing_sections') else '—')} | {_table_cell(item.get('human_review_required'))} |"
            )
        summary = module_headers.get("summary") or {}
        lines.extend(
            [
                "",
                f"Missing headers: `{_table_cell(summary.get('missing_headers'))}`; legacy headers: `{_table_cell(summary.get('legacy_headers'))}`; stale paths: `{_table_cell(summary.get('stale_headers'))}`; duplicate headers: `{_table_cell(summary.get('duplicate_headers'))}`.",
            ]
        )
    elif module_headers:
        lines.extend(
            [
                "",
                "### Module Header Traceability",
                "",
                f"Status: `{_table_cell(module_headers.get('status'))}`. Generate `naos/reports/module_header_traceability.json` with `naos module-headers` or `make -f Makefile.naos naos-module-headers` to populate this section.",
            ]
        )

    spec_pack = control_plane.get("spec_pack_contract") or {}
    spec_pack_files = spec_pack.get("files") or []
    spec_pack_findings = spec_pack.get("findings") or []
    if spec_pack_files or spec_pack_findings:
        lines.extend(
            [
                "",
                "### Spec-Pack Contract",
                "",
                "> NAOS evaluates deterministic template contract conformance, profile applicability, and reference resolution. It does not prove spec quality, approval, implementation, complete traceability, certification, or compliance.",
                "",
                "| Spec File | Applicability | Required | Present | Required Profiles |",
                "|-----------|---------------|----------|---------|-------------------|",
            ]
        )
        for item in spec_pack_files[:30]:
            lines.append(
                f"| {_table_cell(item.get('path'))} | {_table_cell(item.get('applicability'))} | {_table_cell(item.get('required'))} | {_table_cell(item.get('present'))} | {_table_cell(', '.join(item.get('required_profiles') or []))} |"
            )
        traceability_codes = spec_pack.get("traceability_codes") or []
        if traceability_codes:
            lines.extend(
                [
                    "",
                    "| Code | Applicability | Definitions | References | Unresolved |",
                    "|------|---------------|-------------|------------|------------|",
                ]
            )
            for item in traceability_codes[:30]:
                lines.append(
                    f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('applicability'))} | {_table_cell(item.get('definitions_count'))} | {_table_cell(item.get('references_count'))} | {_table_cell(item.get('unresolved_references_count'))} |"
                )
        if spec_pack_findings:
            lines.extend(
                [
                    "",
                    "| Finding | Status | Severity | Path | Human Review |",
                    "|---------|--------|----------|------|--------------|",
                ]
            )
            for item in spec_pack_findings[:30]:
                lines.append(
                    f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('severity'))} | {_table_cell(item.get('path') or '—')} | {_table_cell(item.get('human_review_required'))} |"
                )
        summary = spec_pack.get("summary") or {}
        lines.extend(
            [
                "",
                f"Mode: `{_table_cell(spec_pack.get('mode'))}`; manifest: `{_table_cell(spec_pack.get('manifest'))}`; spec files: `{_table_cell(summary.get('spec_files_present'))}/{_table_cell(summary.get('spec_files_expected'))}`; support files: `{_table_cell(summary.get('support_files_present'))}/{_table_cell(summary.get('support_files_expected'))}`; not applicable by profile: `{_table_cell(summary.get('files_not_applicable'))}`; unresolved references: `{_table_cell(summary.get('traceability_reference_findings'))}`; placeholders: `{_table_cell(summary.get('placeholder_findings'))}`.",
            ]
        )
    elif spec_pack:
        lines.extend(
            [
                "",
                "### Spec-Pack Contract",
                "",
                f"Status: `{_table_cell(spec_pack.get('status'))}`. Generate `naos/reports/spec_pack_contract.json` with `naos spec-pack-contract` or `make -f Makefile.naos naos-spec-pack-contract` to populate this section.",
            ]
        )

    materialization = control_plane.get("spec_pack_materialization") or {}
    materialization_files = materialization.get("files") or []
    materialization_findings = materialization.get("findings") or []
    if materialization_files or materialization_findings:
        summary = materialization.get("summary") or {}
        materialization_detail = (
            f"Dry run: `{_table_cell(materialization.get('dry_run'))}`; "
            f"force: `{_table_cell(materialization.get('force'))}`; "
            f"copied: `{_table_cell(summary.get('copied'))}`; "
            f"would copy: `{_table_cell(summary.get('would_copy'))}`; "
            f"skipped existing: `{_table_cell(summary.get('skipped_existing'))}`; "
            f"missing source: `{_table_cell(summary.get('missing_source'))}`."
        )
        enhanced_materialization = any(
            key in summary
            for key in (
                "invalid_manifest",
                "unsafe_paths",
                "copy_cleanup_failed",
                "report_write_failed",
                "apply_refused",
            )
        ) or bool(materialization_findings)
        if enhanced_materialization:
            materialization_detail = (
                f"Status: `{_table_cell(materialization.get('status'))}`; "
                + materialization_detail[:-1]
                + f"; invalid manifest: `{_table_cell(summary.get('invalid_manifest'))}`; "
                f"unsafe paths: `{_table_cell(summary.get('unsafe_paths'))}`; "
                f"copy cleanup failed: `{_table_cell(summary.get('copy_cleanup_failed'))}`; "
                f"report write failed: `{_table_cell(summary.get('report_write_failed'))}`; "
                f"findings: `{_table_cell(summary.get('total_findings'))}`; "
                f"apply refused: `{_table_cell(summary.get('apply_refused'))}`."
            )
        lines.extend(
            [
                "",
                "### Spec-Pack Materialization",
                "",
                "> NAOS copies or previews missing profile-required template files. It does not fill, approve, validate, implement, test, certify, or prove specifications.",
                "",
                materialization_detail,
                "",
                "| File | Kind | Action | Existed Before |",
                "|------|------|--------|----------------|",
            ]
        )
        for item in materialization_files[:30]:
            lines.append(
                f"| {_table_cell(item.get('path'))} | {_table_cell(item.get('kind'))} | {_table_cell(item.get('action'))} | {_table_cell(item.get('existed_before'))} |"
            )
        if materialization_findings:
            lines.extend(
                [
                    "",
                    "| Finding | Status | Severity | Path | Message |",
                    "|---------|--------|----------|------|---------|",
                ]
            )
            for item in materialization_findings[:30]:
                lines.append(
                    f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('severity'))} | {_table_cell(item.get('path') or '—')} | {_table_cell(item.get('message'))} |"
                )
    elif materialization:
        lines.extend(
            [
                "",
                "### Spec-Pack Materialization",
                "",
                f"Status: `{_table_cell(materialization.get('status'))}`. Generate `naos/reports/spec_pack_materialization.json` with `naos spec-pack-materialize . --dry-run` or `make -f Makefile.naos naos-spec-pack-materialize` to populate this section.",
            ]
        )

    worksheet = control_plane.get("spec_assembly_worksheet") or {}
    worksheet_specs = worksheet.get("specs") or []
    worksheet_findings = worksheet.get("findings") or []
    if worksheet_specs or worksheet_findings:
        summary = worksheet.get("summary") or {}
        lines.extend(
            [
                "",
                "### Spec Assembly Worksheet",
                "",
                "> NAOS maps adoption evidence and candidate requirements to manifest-declared specs for human review. It does not promote candidates, fill specs, approve requirements, or prove complete traceability.",
                "",
                f"Missing spec files: `{_table_cell(summary.get('required_spec_files_missing'))}`; candidate mappings: `{_table_cell(summary.get('candidate_requirements'))}`; gap mappings: `{_table_cell(summary.get('traceability_gaps'))}`; applicability decisions needed: `{_table_cell(summary.get('non_applicability_decisions_needed'))}`.",
                "",
                "| Spec | Present | State | Candidates | Gaps |",
                "|------|---------|-------|------------|------|",
            ]
        )
        for item in worksheet_specs[:30]:
            lines.append(
                f"| {_table_cell(item.get('filename'))} | {_table_cell(item.get('present'))} | {_table_cell(item.get('assembly_state'))} | {_table_cell(item.get('mapped_candidate_count'))} | {_table_cell(item.get('mapped_gap_count'))} |"
            )
    elif worksheet:
        lines.extend(
            [
                "",
                "### Spec Assembly Worksheet",
                "",
                f"Status: `{_table_cell(worksheet.get('status'))}`. Generate `naos/reports/spec_assembly_worksheet.json` with `naos spec-assembly-worksheet .` or `make -f Makefile.naos naos-spec-assembly-worksheet` to populate this section.",
            ]
        )

    ac_completion = control_plane.get("ac_completion_evidence") or {}
    ac_completion_summary = ac_completion.get("summary") or {}
    if ac_completion:
        lines.extend(
            [
                "",
                "### AC Completion Evidence",
                "",
                "> NAOS checks declared AC/SCEN completion evidence presence. It does not prove AC correctness, implementation correctness, complete coverage, approval, certification, compliance, or hallucination prevention.",
                "",
                f"Configured: `{_table_cell(ac_completion_summary.get('configured'))}`; claimed complete: `{_table_cell(ac_completion_summary.get('claimed_complete'))}`; satisfied: `{_table_cell(ac_completion_summary.get('satisfied_completions'))}`; unsatisfied: `{_table_cell(ac_completion_summary.get('unsatisfied_completions'))}`.",
            ]
        )
        findings = ac_completion.get("findings") or []
        if findings:
            lines.extend(
                [
                    "",
                    "| Finding | Status | Severity | AC/SCEN | Path |",
                    "|---------|--------|----------|---------|------|",
                ]
            )
            for item in findings[:30]:
                lines.append(
                    f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('severity'))} | {_table_cell(item.get('ac_id') or '—')} | {_table_cell(item.get('path') or '—')} |"
                )
        known_gaps = ac_completion.get("known_gaps") or []
        if known_gaps:
            lines.extend(["", "Known gaps:"])
            for gap in known_gaps[:10]:
                lines.append(f"- {_table_cell(gap)}")

    spec_cascade = control_plane.get("spec_cascade_coherence") or {}
    spec_findings = spec_cascade.get("findings") or []
    if spec_findings:
        lines.extend(
            [
                "",
                "### Spec Cascade Coherence",
                "",
                "> NAOS evaluates deterministic spec-to-task-to-source cascade evidence. It does not prove code correctness, runtime behavior, complete traceability, approval, certification, or compliance.",
                "",
                "| Finding | Status | Severity | Requirement | Path | Human Review |",
                "|---------|--------|----------|-------------|------|--------------|",
            ]
        )
        for item in spec_findings[:30]:
            lines.append(
                f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('severity'))} | {_table_cell(item.get('requirement_id') or '—')} | {_table_cell(item.get('path') or '—')} | {_table_cell(item.get('human_review_required'))} |"
            )
        summary = spec_cascade.get("summary") or {}
        lines.extend(
            [
                "",
                f"Orphan headers: `{_table_cell(summary.get('orphan_headers'))}`; uncovered requirements: `{_table_cell(summary.get('uncovered_requirements'))}`; untraced source: `{_table_cell(summary.get('untraced_sources'))}`; unresolved source refs: `{_table_cell(summary.get('unresolved_source_references'))}`; stale statuses: `{_table_cell(summary.get('stale_statuses'))}`.",
            ]
        )
    elif spec_cascade:
        lines.extend(
            [
                "",
                "### Spec Cascade Coherence",
                "",
                f"Status: `{_table_cell(spec_cascade.get('status'))}`. Generate `naos/reports/spec_cascade_coherence.json` with `naos spec-cascade` or `make -f Makefile.naos naos-spec-cascade` to populate this section.",
            ]
        )

    control_review = control_plane.get("control_plane_review") or {}
    routing_decisions = control_review.get("routing_decisions") or []
    if routing_decisions:
        lines.extend(
            [
                "",
                "### Control-Plane Review & Research Routing",
                "",
                "> NAOS evaluates structured governance-surface review and research-routing items. It does not prove complete research coverage, complete routing, governance correctness, or compliance.",
                "",
                "| Item | Source Type | Status | Human Review | Target Surfaces | Known Gap / Risk / Waiver |",
                "|------|-------------|--------|--------------|-----------------|---------------------------|",
            ]
        )
        for item in routing_decisions[:30]:
            refs = ", ".join(
                str(ref)
                for ref in [item.get("known_gap_ref"), item.get("residual_risk_ref"), item.get("waiver_ref")]
                if ref
            )
            lines.append(
                f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('source_type'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('human_review_required'))} | {_table_cell(', '.join(item.get('target_surfaces') or []) if item.get('target_surfaces') else '—')} | {_table_cell(refs if refs else '—')} |"
            )
        summary = control_review.get("summary") or {}
        lines.extend(
            [
                "",
                f"Missing routing: `{_table_cell(summary.get('missing_routing'))}`; review required: `{_table_cell(summary.get('review_required'))}`; known gaps: `{_table_cell(summary.get('known_gaps'))}`; residual risks: `{_table_cell(summary.get('residual_risks'))}`; waivers: `{_table_cell(summary.get('waivers'))}`.",
            ]
        )
    elif control_review:
        lines.extend(
            [
                "",
                "### Control-Plane Review & Research Routing",
                "",
                f"Status: `{_table_cell(control_review.get('status'))}`. Generate `naos/reports/control_plane_review.json` with `naos control-plane-review` or `make -f Makefile.naos naos-control-plane-review` to populate this section.",
            ]
        )

    setup_recommendations = control_plane.get("setup_recommendations") or {}
    setup_modules = setup_recommendations.get("recommended_modules") or []
    configured_modules = setup_recommendations.get("configured_modules") or []
    if setup_modules:
        lines.extend(
            [
                "",
                "### Setup Recommendations",
                "",
                "> NAOS recommends setup modules and next actions. It does not automatically enable modules, approve maturity, certify compliance, or guarantee project readiness.",
                "",
                "| Module | Recommendation | Benefit | Warning | Human Review Boundary |",
                "|--------|----------------|---------|---------|-----------------------|",
            ]
        )
        for item in setup_modules[:30]:
            lines.append(
                f"| {_table_cell(item.get('name'))} | {_table_cell(item.get('recommendation'))} | {_table_cell(item.get('benefit'))} | {_table_cell(item.get('warning') or '—')} | {_table_cell(item.get('human_review_boundary'))} |"
            )
        optional_count = len(setup_recommendations.get("optional_modules") or [])
        deferred_count = len(setup_recommendations.get("deferred_modules") or [])
        configured_count = len(configured_modules)
        profile_guidance = setup_recommendations.get("profile_guidance") or {}
        lines.extend(
            [
                "",
                f"Configured modules: `{_table_cell(configured_count)}`; optional modules: `{_table_cell(optional_count)}`; deferred/readiness-only modules: `{_table_cell(deferred_count)}`; human review required: `{_table_cell(setup_recommendations.get('human_review_required'))}`.",
                f"Profile guidance: `{_table_cell(profile_guidance.get('recommended_action'))}`; recommended profile: `{_table_cell(profile_guidance.get('recommended_profile'))}`; automatic upgrade: `{_table_cell(profile_guidance.get('automatic_upgrade'))}`.",
            ]
        )
    elif configured_modules:
        lines.extend(
            [
                "",
                "### Setup Recommendations",
                "",
                "> NAOS setup modules can be configured without implying maturity approval, certification, or compliance.",
                "",
                f"Configured modules: `{_table_cell(len(configured_modules))}`. No currently recommended installable modules are pending in the setup recommendation report.",
            ]
        )
    elif setup_recommendations:
        lines.extend(
            [
                "",
                "### Setup Recommendations",
                "",
                f"Status: `{_table_cell(setup_recommendations.get('status'))}`. Generate `naos/reports/setup_recommendations.json` with `naos setup-recommendations` or `make -f Makefile.naos naos-setup-recommendations` to populate this section.",
            ]
        )

    bypass = control_plane.get("governance_bypass_posture") or {}
    if bypass:
        bypass_findings = bypass.get("findings") or []
        lines.extend(
            [
                "",
                "### Governance Bypass Posture",
                "",
                "> NAOS reports local hook, CI, commit-message, and tier/profile posture. It does not prevent bypasses, prove CI ran, approve PRs, certify controls, or prove compliance.",
                "",
            ]
        )
        if bypass_findings:
            lines.extend(
                [
                    "| Finding | Status | Severity | Message |",
                    "|---------|--------|----------|---------|",
                ]
            )
            for item in bypass_findings[:30]:
                lines.append(
                    f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('severity'))} | {_table_cell(item.get('message'))} |"
                )
        else:
            hook = bypass.get("hook") or {}
            ci = bypass.get("ci") or {}
            lines.append(
                f"Status: `{_table_cell(bypass.get('status'))}`; hook present: `{_table_cell(hook.get('pre_commit_hook_present'))}`; NAOS CI detected: `{_table_cell(ci.get('naos_ci_present'))}`."
            )

    external_evidence = control_plane.get("external_evidence_ingest") or {}
    if external_evidence:
        external_summary = external_evidence.get("summary") or {}
        lines.extend(
            [
                "",
                "### External Evidence Ingest",
                "",
                "> NAOS ingests local SARIF 2.1.0 as unverified review evidence. It does not run scanners, verify findings, approve releases, attest evidence, certify controls, or prove compliance.",
                "",
                f"Status: `{_table_cell(external_evidence.get('status'))}`; source present: `{_table_cell(external_summary.get('source_present'))}`; results: `{_table_cell(external_summary.get('results'))}`; verification: `{_table_cell(external_evidence.get('verification_status'))}`.",
            ]
        )
        top_paths = external_summary.get("top_affected_paths") or []
        if top_paths:
            lines.extend(
                [
                    "",
                    "| Affected Path | Results |",
                    "|---------------|---------|",
                ]
            )
            for item in top_paths[:15]:
                lines.append(f"| {_table_cell(item.get('path'))} | {_table_cell(item.get('count'))} |")

    evidence_attestation = control_plane.get("evidence_attestation") or {}
    attested_artifacts = evidence_attestation.get("artifact_manifest") or []
    if attested_artifacts:
        lines.extend(
            [
                "",
                "### Evidence Integrity & Reviewer Attestation",
                "",
                "> NAOS records local SHA-256 digests and reviewer metadata. It does not implement cryptographic signing, signature verification, tamper-proof storage, legal approval, regulatory approval, compliance approval, or guaranteed integrity.",
                "",
                "| Artifact | Status | Group | Digest | Freshness |",
                "|----------|--------|-------|--------|-----------|",
            ]
        )
        for item in attested_artifacts[:30]:
            digest = str(item.get("digest") or "")
            short_digest = f"{digest[:12]}..." if len(digest) > 12 else digest
            freshness = item.get("freshness") or {}
            lines.append(
                f"| {_table_cell(item.get('path'))} | {_table_cell(item.get('status'))} | {_table_cell(item.get('artifact_group'))} | {_table_cell(short_digest or '—')} | {_table_cell(freshness.get('status'))} |"
            )
        summary = evidence_attestation.get("summary") or {}
        lines.extend(
            [
                "",
                f"Missing artifacts: `{_table_cell(summary.get('missing_artifacts'))}`; uncovered artifacts: `{_table_cell(summary.get('uncovered_artifacts'))}`; stale artifacts: `{_table_cell(summary.get('stale_artifacts'))}`; reviewer metadata entries: `{_table_cell(summary.get('reviewer_attestations'))}`; human review required: `{_table_cell(evidence_attestation.get('human_review_required'))}`.",
            ]
        )
        if evidence_attestation.get("known_gaps") or evidence_attestation.get("residual_risks") or evidence_attestation.get("waivers"):
            lines.append("")
            lines.append(
                f"Known gaps: `{_table_cell(len(evidence_attestation.get('known_gaps') or []))}`; residual risks: `{_table_cell(len(evidence_attestation.get('residual_risks') or []))}`; waivers: `{_table_cell(len(evidence_attestation.get('waivers') or []))}`."
            )
    elif evidence_attestation:
        lines.extend(
            [
                "",
                "### Evidence Integrity & Reviewer Attestation",
                "",
                f"Status: `{_table_cell(evidence_attestation.get('status'))}`. Generate `naos/reports/evidence_attestation.json` with `naos evidence-attestation` or `make -f Makefile.naos naos-evidence-attestation` to populate this section.",
            ]
        )

    evidence_verification = control_plane.get("evidence_verification") or {}
    if evidence_verification:
        identity = evidence_verification.get("identity_binding") or {}
        verification_summary = evidence_verification.get("summary") or {}
        lines.extend(
            [
                "",
                "### Evidence Verification",
                "",
                "> Evidence verification recomputes local artifact digests and the manifest root, then reports tamper-evidence, signature-entry presence, and best-effort Git HEAD metadata. It does not validate third-party signatures, authenticate identities, sign artifacts for NAOS, approve work, provide non-repudiation, certify controls, or prove compliance.",
                "",
                f"Status: `{_table_cell(evidence_verification.get('status'))}`; tamper-evident: `{_table_cell(evidence_verification.get('tamper_evident'))}`; signature entries present: `{_table_cell(evidence_verification.get('signature_entries_present'))}`; envelope signature validated by NAOS: `{_table_cell(evidence_verification.get('signature_validation_performed'))}`; invalid validation claim rejected: `{_table_cell(evidence_verification.get('signature_validation_claim_rejected'))}`; artifacts checked: `{_table_cell(evidence_verification.get('artifacts_checked'))}`; digest result: `{_table_cell(evidence_verification.get('digest_validation'))}`; root result: `{_table_cell(evidence_verification.get('manifest_root_validation'))}`; scope: `{_table_cell(evidence_verification.get('scope_status'))}`; required coverage: `{_table_cell((evidence_verification.get('required_coverage') or {}).get('status'))}`; findings: `{_table_cell(verification_summary.get('total_findings'))}`; human review required: `{_table_cell(evidence_verification.get('human_review_required'))}`.",
                "",
                f"Git HEAD metadata (not identity authentication): signature status `{_table_cell(identity.get('signature_status'))}`; signer `{_table_cell(identity.get('signer'))}`; commit `{_table_cell(identity.get('commit'))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Evidence Verification",
                "",
                "Status: `not_configured`. Generate `naos/reports/evidence_verification.json` with `naos evidence-verify` or `make -f Makefile.naos naos-evidence-verify` after evidence attestation exists.",
            ]
        )

    evidence_conflicts = control_plane.get("evidence_conflicts") or {}
    if evidence_conflicts:
        conflict_summary = evidence_conflicts.get("summary") or {}
        lines.extend(
            [
                "",
                "### Evidence Conflict Detection",
                "",
                "> Evidence conflict detection flags deterministic review conflicts and metadata gaps. It does not resolve conflicts, adjudicate which evidence is correct, prove separation of duties, approve work, lock tasks, prove compliance, or replace reviewer judgment.",
                "",
                f"Status: `{_table_cell(evidence_conflicts.get('status'))}`; conflicts: `{_table_cell(evidence_conflicts.get('conflict_count'))}`; stale attestations: `{_table_cell(len(evidence_conflicts.get('stale_attestations') or []))}`; duplicate attestations: `{_table_cell(len(evidence_conflicts.get('duplicate_attestations') or []))}`; unrouted conflicts: `{_table_cell(len(evidence_conflicts.get('unrouted_conflicts') or []))}`; human review required: `{_table_cell(evidence_conflicts.get('human_review_required'))}`.",
                "",
                f"Missing reviewer metadata: `{_table_cell(conflict_summary.get('missing_reviewer_metadata'))}`; missing operator attribution: `{_table_cell(conflict_summary.get('missing_operator_attribution'))}`; separation-of-duties warnings: `{_table_cell(len(evidence_conflicts.get('separation_of_duties_warnings') or []))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Evidence Conflict Detection",
                "",
                "Status: `not_configured`. Generate `naos/reports/evidence_conflict_detection.json` with `naos evidence-conflicts` or `make -f Makefile.naos naos-evidence-conflicts` to populate this section.",
            ]
        )

    memory_readiness = control_plane.get("memory_context_readiness") or {}
    platform_rows = memory_readiness.get("platform_access_matrix") or []
    if platform_rows:
        lines.extend(
            [
                "",
                "### AI Context Continuity & Memory Governance Readiness",
                "",
                "> NAOS evaluates memory/context readiness as advisory recall, authorization posture, and fallback readiness. Memory is not evidence, approval, source of truth, or hallucination prevention.",
                "",
                "| Platform | Declared Memory | MCP Configured | Read | Write | Fallback |",
                "|----------|-----------------|----------------|------|-------|----------|",
            ]
        )
        for item in platform_rows[:30]:
            lines.append(
                f"| {_table_cell(item.get('name') or item.get('id'))} | {_table_cell(item.get('memory_access_declared'))} | {_table_cell(item.get('observed_project_mcp_configured') or item.get('mcp_configured'))} | {_table_cell(item.get('read_access'))} | {_table_cell(item.get('write_access'))} | {_table_cell(item.get('fallback_when_unavailable'))} |"
            )
        provider = memory_readiness.get("provider_posture") or {}
        project_identity = memory_readiness.get("project_identity") or {}
        fallback = memory_readiness.get("fallback_readiness") or {}
        context_pack = memory_readiness.get("context_pack_readiness") or {}
        lines.extend(
            [
                "",
                f"Provider: `{_table_cell(provider.get('configured_provider') or provider.get('recommended_provider'))}`; memory state: `{_table_cell(provider.get('memory_config_state'))}`; project identity: `{_table_cell(project_identity.get('status'))}` (provider-verified: `{_table_cell(project_identity.get('project_identity_verified'))}`); fallback: `{_table_cell(fallback.get('status'))}`; context-pack readiness: `{_table_cell(context_pack.get('status'))}`; human review required: `{_table_cell(memory_readiness.get('human_review_required'))}`.",
            ]
        )
        findings = memory_readiness.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Stale or conflicting memory must be routed through human review and control-plane review.")
    elif memory_readiness:
        lines.extend(
            [
                "",
                "### AI Context Continuity & Memory Governance Readiness",
                "",
                f"Status: `{_table_cell(memory_readiness.get('status'))}`. Generate `naos/reports/memory_context_readiness.json` with `naos memory-readiness` or `make -f Makefile.naos naos-memory-readiness` to populate this section.",
            ]
        )

    memory_access = control_plane.get("memory_provider_access") or {}
    if memory_access:
        ci_access = memory_access.get("ci_memory_access") or {}
        project_identity = memory_access.get("project_identity") or {}
        lines.extend(
            [
                "",
                "### Memory Provider / MCP Access Verification",
                "",
                "> NAOS verifies declared/configured memory access posture from safe local metadata only. Configured providers and MCP config files do not prove usable access; memory access is not evidence, approval, source of truth, or hallucination prevention.",
                "",
                f"Status: `{_table_cell(memory_access.get('status'))}`; provider: `{_table_cell(memory_access.get('provider_name'))}` (source: `{_table_cell(memory_access.get('provider_name_source'))}`, explicitly declared: `{_table_cell(memory_access.get('provider_declared'))}`, recommended: `{_table_cell(memory_access.get('provider_recommended'))}`); configured: `{_table_cell(memory_access.get('provider_configured'))}`; provider access verified: `{_table_cell(memory_access.get('provider_access_verified'))}`; MCP access verified: `{_table_cell(memory_access.get('mcp_access_verified'))}`; project identity: `{_table_cell(project_identity.get('status'))}` (provider-verified: `{_table_cell(project_identity.get('project_identity_verified'))}`); provider binary detected: `{_table_cell(memory_access.get('provider_binary_detected'))}`; human review required: `{_table_cell(memory_access.get('human_review_required'))}`.",
                "",
                f"Engram data source: `{_table_cell(memory_access.get('provider_data_dir_source'))}`; data directory exists: `{_table_cell(memory_access.get('provider_data_dir_exists'))}`; derived database exists: `{_table_cell(memory_access.get('provider_database_exists'))}`; MCP config files detected: `{_table_cell(len(memory_access.get('mcp_config_files_detected') or []))}`; MCP servers declared: `{_table_cell(len(memory_access.get('mcp_servers_declared') or []))}`; CI read/write/admin access: `{_table_cell(ci_access.get('read_access'))}` / `{_table_cell(ci_access.get('write_access'))}` / `{_table_cell(ci_access.get('admin_access'))}`.",
            ]
        )
        findings = memory_access.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Access overclaims, unverified MCP, write-boundary, cloud/sync, or private-memory risks should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Memory Provider / MCP Access Verification",
                "",
                "Status: `not_configured`. Generate `naos/reports/memory_provider_access.json` with `naos memory-access` or `make -f Makefile.naos naos-memory-access` to populate this section.",
            ]
        )

    memory_use = control_plane.get("memory_use_policy") or {}
    if memory_use:
        summary = memory_use.get("summary") or {}
        recall = memory_use.get("recall_trace_readiness") or {}
        audit = memory_use.get("audit_event_readiness") or {}
        lines.extend(
            [
                "",
                "### Memory Use Policy / Recall Trace / Audit Events",
                "",
                "> NAOS evaluates manual memory-review metadata only. Unreviewed memory is advisory; instruction-grade memory requires explicit approval, provenance, scope, reviewer, timestamp, and freshness/expiry. Recall traces are usage records, audit events are records, and neither is proof or approval.",
                "",
                f"Status: `{_table_cell(memory_use.get('status'))}`; review items: `{_table_cell(summary.get('memory_review_items'))}`; instruction-grade items: `{_table_cell(summary.get('instruction_grade_items'))}`; supporting-context items: `{_table_cell(summary.get('supporting_context_items'))}`; unsafe instruction-grade claims: `{_table_cell(summary.get('unsafe_instruction_grade_claims'))}`; human review required: `{_table_cell(memory_use.get('human_review_required'))}`.",
                "",
                f"Recall trace runtime enabled: `{_table_cell(recall.get('runtime_trace_execution_enabled'))}`; audit-event runtime capture enabled: `{_table_cell(audit.get('runtime_event_capture_enabled'))}`. No automatic memory write-back, private payload reads, or cloud memory are enabled by this report.",
            ]
        )
        findings = memory_use.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Unsafe instruction-grade claims, stale/superseded memory use, recall-trace overclaims, or audit-event approval confusion should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Memory Use Policy / Recall Trace / Audit Events",
                "",
                "Status: `not_configured`. Generate `naos/reports/memory_use_policy.json` with `naos memory-use-policy` or `make -f Makefile.naos naos-memory-use-policy` to populate this section.",
            ]
        )

    learning_loop = control_plane.get("learning_loop_review") or {}
    if learning_loop:
        summary = learning_loop.get("summary") or {}
        lines.extend(
            [
                "",
                "### Governed Learning Lifecycle",
                "",
                "> NAOS evaluates candidate, active, and historical learning metadata. Candidate learning is proposal-only; active learning requires reviewed metadata; inactive learning must not be current guidance.",
                "",
                f"Status: `{_table_cell(learning_loop.get('status'))}`; records: `{_table_cell(summary.get('learning_records'))}`; active: `{_table_cell(summary.get('active_records'))}`; high-authority active: `{_table_cell(summary.get('high_authority_active_records'))}`; redacted: `{_table_cell(summary.get('redacted_records'))}`; human review required: `{_table_cell(learning_loop.get('human_review_required'))}`.",
            ]
        )
        findings = learning_loop.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Active-learning, stale-learning, promotion-review, redaction, or authority-overclaim findings should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Governed Learning Lifecycle",
                "",
                "Status: `not_configured`. Generate `naos/reports/learning_loop_review.json` with `naos learning-loop-review` or `make -f Makefile.naos naos-learning-loop-review` to populate this section.",
            ]
        )

    failure_mode_observations = control_plane.get("failure_mode_observations") or {}
    if failure_mode_observations:
        summary = failure_mode_observations.get("summary") or {}
        mode_counts = failure_mode_observations.get("mode_observation_counts") or {}
        top_modes = sorted(mode_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))[:5]
        mode_text = ", ".join(f"{mode}: {count}" for mode, count in top_modes) if top_modes else "none"
        lines.extend(
            [
                "",
                "### Failure-Mode Observations",
                "",
                "> NAOS aggregates local report findings into canonical failure-mode counts for review. Counts are statistics for human learning-loop, autoresearch, and remediation scoping; they are not numeric risk score authority, automatic learning, approval, blocking, runtime orchestration, MCP/memory activation, provider/model routing, release authority, or compliance proof.",
                "",
                f"Status: `{_table_cell(failure_mode_observations.get('status'))}`; declared: `{_table_cell(failure_mode_observations.get('failure_mode_observations_declared'))}`; observations: `{_table_cell(summary.get('observations'))}`; modes with observations: `{_table_cell(summary.get('modes_with_observations'))}`; unmapped: `{_table_cell(summary.get('unmapped_observations'))}`; high severity: `{_table_cell(summary.get('high_severity_observations'))}`; human review required: `{_table_cell(failure_mode_observations.get('human_review_required'))}`.",
                "",
                f"Top observed modes: `{_table_cell(mode_text)}`.",
            ]
        )
        findings = failure_mode_observations.get("findings") or []
        if findings:
            lines.append("")
            lines.append(
                f"Findings visible: `{_table_cell(len(findings))}`. Unmapped observations, high-severity source findings, runtime/provider/memory authority attempts, or source review conflicts should be routed through human review."
            )
    else:
        lines.extend(
            [
                "",
                "### Failure-Mode Observations",
                "",
                "Status: `not_configured`. Generate `naos/reports/failure_mode_observations.json` with `naos failure-mode-observations` or `make -f Makefile.naos naos-failure-mode-observations` to populate this section.",
            ]
        )

    adapter_coherence = control_plane.get("adapter_coherence") or {}
    if adapter_coherence:
        summary = adapter_coherence.get("summary") or {}
        canonical = adapter_coherence.get("canonical_plugin") or {}
        canonical_plugins = adapter_coherence.get("canonical_plugins") or []
        plugin_labels = []
        for plugin in canonical_plugins:
            name = plugin.get("manifest_name") or plugin.get("name") or plugin.get("id")
            version = plugin.get("manifest_version")
            plugin_labels.append(f"{name} {version}" if version else str(name))
        plugin_summary = ", ".join(plugin_labels) or str(canonical.get("manifest_name") or "n/a")
        lines.extend(
            [
                "",
                "### Adapter Coherence",
                "",
                "> Adapter coherence is deterministic, local, and file-first. It reviews repo-versioned Codex/Claude plugin source and optional tool/IDE adapter guidance; it does not prove live installation, mutate Codex caches or Claude settings, activate hooks, call MCP, write memory, or auto-propagate changes.",
                "",
                f"Status: `{_table_cell(adapter_coherence.get('status'))}`; plugins: `{_table_cell(summary.get('plugins_present'))}/{_table_cell(summary.get('plugins_expected'))}` `{_table_cell(plugin_summary)}`; skills: `{_table_cell(summary.get('plugin_skills_present'))}/{_table_cell(summary.get('plugin_skills_expected'))}`; references: `{_table_cell(summary.get('plugin_references_present'))}/{_table_cell(summary.get('plugin_references_expected'))}`; adapter surfaces: `{_table_cell(summary.get('adapter_surfaces_present'))}/{_table_cell(summary.get('adapter_surfaces_expected'))}`; propagation reviewed: `{_table_cell(summary.get('propagation_links_reviewed'))}/{_table_cell(summary.get('propagation_links_expected'))}`; stale: `{_table_cell(summary.get('propagation_links_stale'))}`; unreviewed: `{_table_cell(summary.get('propagation_links_unreviewed'))}`; project-local adapters: `{_table_cell(summary.get('project_local_adapters_present'))}`; human review required: `{_table_cell(adapter_coherence.get('human_review_required'))}`.",
            ]
        )
        findings = adapter_coherence.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Plugin-source, adapter-surface, propagation, or boundary findings should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Adapter Coherence",
                "",
                "Status: `not_configured`. Generate `naos/reports/adapter_coherence.json` with `naos adapter-coherence` or `make -f Makefile.naos naos-adapter-coherence` to populate this section.",
            ]
        )

    task_context = control_plane.get("task_context_pack") or {}
    if task_context:
        task_summary = task_context.get("summary") or {}
        freshness = task_context.get("source_artifact_freshness") or {}
        memory_context = task_context.get("memory_context") or {}
        lines.extend(
            [
                "",
                "### Task Context Pack",
                "",
                "> Task context packs are derived, bounded, non-authoritative context for one task. Repo evidence and current task constraints outrank the pack; memory inside the pack is advisory only.",
                "",
                f"Task: `{_table_cell(task_context.get('task_id'))}`; status: `{_table_cell(task_context.get('status'))}`; source artifacts used: `{_table_cell(task_summary.get('source_artifacts_used'))}`; missing sources: `{_table_cell(len(task_context.get('source_artifacts_missing') or []))}`; stale sources: `{_table_cell(freshness.get('stale'))}`; memory posture: `{_table_cell(memory_context.get('status'))}`; human review required: `{_table_cell(task_context.get('human_review_required'))}`.",
            ]
        )
        commands = task_context.get("commands_to_run") or []
        if commands:
            lines.append("")
            lines.append("Commands:")
            for command in commands[:6]:
                lines.append(f"- `{_table_cell(command)}`")
        findings = task_context.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Stale, missing, or conflicting context should be routed through control-plane review where disposition is needed.")
    else:
        lines.extend(
            [
                "",
                "### Task Context Pack",
                "",
                "Status: `not_configured`. Generate `naos/reports/task_context_pack.json` with `naos task-context --task T-XXX` or `make -f Makefile.naos naos-task-context TASK=T-XXX` to populate this section.",
            ]
        )

    local_index = control_plane.get("local_context_index") or {}
    if local_index:
        index_summary = local_index.get("summary") or {}
        sqlite_artifact = local_index.get("sqlite_artifact") or {}
        sqlite_coordination = control_plane.get("sqlite_write_coordination") or local_index.get("sqlite_write_coordination") or {}
        query_modes = local_index.get("query_modes_supported") or {}
        lines.extend(
            [
                "",
                "### Local Context Index",
                "",
                "> The local context index is generated, derived, and cache-like. It provides bounded retrieval candidates; repository evidence and deterministic NAOS reports remain authoritative.",
                "",
                f"Status: `{_table_cell(local_index.get('status'))}`; indexed artifacts: `{_table_cell(index_summary.get('indexed_artifacts'))}`; chunks: `{_table_cell(index_summary.get('chunks'))}`; SQLite: `{_table_cell(sqlite_artifact.get('status'))}`; FTS available: `{_table_cell(local_index.get('fts_available'))}`; human review required: `{_table_cell(local_index.get('human_review_required'))}`.",
                "",
                f"Query modes: path lookup `{_table_cell(query_modes.get('exact_path_lookup'))}`, metadata filtering `{_table_cell(query_modes.get('metadata_filtering'))}`, FTS keyword search `{_table_cell(query_modes.get('fts_keyword_search'))}`, semantic/vector retrieval `{_table_cell(query_modes.get('semantic_candidate_retrieval'))}`, graph traversal `{_table_cell(query_modes.get('graph_traversal'))}`.",
                "",
                "The v1 index does not use sqlite-vec, embeddings, NetworkX, GraphML, Engram, MCP, private memory payloads, or automatic context injection.",
                "",
                f"SQLite write coordination: status `{_table_cell(sqlite_coordination.get('status'))}`; local lock acquired `{_table_cell(sqlite_coordination.get('lock_acquired'))}`; atomic replace `{_table_cell(sqlite_coordination.get('atomic_replace_used'))}`. This protects local index file integrity only; it is not task locking, evidence conflict detection, append-only audit logging, distributed locking, or full multi-user completion.",
            ]
        )
        findings = local_index.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Sensitive indexing, stale index, authority-confusion, or context-bloat concerns should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Local Context Index",
                "",
                "Status: `not_configured`. Generate `naos/reports/local_context_index.json` with `naos context-index` or `make -f Makefile.naos naos-context-index` to populate this section.",
            ]
        )

    local_query = control_plane.get("local_context_query") or {}
    if local_query:
        query = local_query.get("query") or {}
        lines.extend(
            [
                "",
                "### Local Context Query",
                "",
                "> Local context query results are bounded candidate references, not answers. Source artifacts remain authoritative.",
                "",
                f"Status: `{_table_cell(local_query.get('status'))}`; query id: `{_table_cell(query.get('query_id'))}`; results: `{_table_cell(local_query.get('result_count'))}`; modes used: `{_table_cell(', '.join(local_query.get('query_mode_used') or []))}`; human review required: `{_table_cell(local_query.get('human_review_required'))}`.",
            ]
        )
        findings = local_query.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Stale, sensitive, or authority-confusion query concerns should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Local Context Query",
                "",
                "Status: `not_configured`. Generate `naos/reports/local_context_query.json` with `naos context-query --query \"...\"` or `make -f Makefile.naos naos-context-query QUERY=\"...\"` to populate this section.",
            ]
        )

    semantic_layer = control_plane.get("semantic_candidate_layer") or {}
    if semantic_layer:
        lines.extend(
            [
                "",
                "### Semantic Candidate Layer Readiness",
                "",
                "> Semantic candidate readiness is configuration/reporting only. Semantic candidates are not answers or source artifacts; exact/path/metadata/FTS query remains the deterministic baseline.",
                "",
                f"Status: `{_table_cell(semantic_layer.get('status'))}`; runtime enabled: `{_table_cell(semantic_layer.get('semantic_runtime_enabled'))}`; sqlite-vec enabled: `{_table_cell(semantic_layer.get('sqlite_vec_enabled'))}`; embeddings enabled: `{_table_cell(semantic_layer.get('embeddings_enabled'))}`; extension loading allowed: `{_table_cell(semantic_layer.get('extension_loading_allowed'))}`; human review required: `{_table_cell(semantic_layer.get('human_review_required'))}`.",
                "",
                "The readiness layer does not install providers or models, call Engram/MCP, search memory payloads, enable cloud embedding, or run semantic/vector search.",
            ]
        )
        findings = semantic_layer.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Semantic overtrust, runtime enablement, stale embedding, sensitive embedding, extension-loading, external embedding, or global-scan concerns should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Semantic Candidate Layer Readiness",
                "",
                "Status: `not_configured`. Generate `naos/reports/semantic_candidate_layer.json` with `naos semantic-candidates` or `make -f Makefile.naos naos-semantic-candidates` to populate this section.",
            ]
        )

    graph_context = control_plane.get("graph_context_readiness") or {}
    if graph_context:
        limits = graph_context.get("traversal_limits") or {}
        lines.extend(
            [
                "",
                "### Graph Context Readiness",
                "",
                "> Graph context readiness is configuration/reporting only. Graph links are candidate relationships and navigation aids, not truth; explicit source artifacts remain authoritative.",
                "",
                f"Status: `{_table_cell(graph_context.get('status'))}`; runtime enabled: `{_table_cell(graph_context.get('graph_runtime_enabled'))}`; explicit-link-only: `{_table_cell(graph_context.get('explicit_link_traversal_only'))}`; global scans allowed: `{_table_cell(graph_context.get('global_graph_scan_allowed'))}`; NetworkX enabled: `{_table_cell(graph_context.get('networkx_enabled'))}`; GraphML enabled: `{_table_cell(graph_context.get('graphml_enabled'))}`; human review required: `{_table_cell(graph_context.get('human_review_required'))}`.",
                "",
                f"Traversal limits: max hops `{_table_cell(limits.get('max_hops'))}`, max seed nodes `{_table_cell(limits.get('max_seed_nodes'))}`, max edges returned `{_table_cell(limits.get('max_edges_returned'))}`.",
                "",
                "The readiness layer does not install graph databases, run graph algorithms, call Engram/MCP, graph memory payloads, or perform automatic context injection.",
            ]
        )
        findings = graph_context.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Graph overtrust, stale links, sensitive links, global scans, runtime enablement, or graph-bloat concerns should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Graph Context Readiness",
                "",
                "Status: `not_configured`. Generate `naos/reports/graph_context_readiness.json` with `naos graph-context` or `make -f Makefile.naos naos-graph-context` to populate this section.",
            ]
        )

    graph_query = control_plane.get("graph_context_query") or {}
    if graph_query:
        query = graph_query.get("query") or {}
        lines.extend(
            [
                "",
                "### Graph Context Query",
                "",
                "> Graph context query results are bounded relationship candidates, not truth. Explicit source artifacts remain authoritative.",
                "",
                f"Status: `{_table_cell(graph_query.get('status'))}`; query id: `{_table_cell(query.get('query_id'))}`; results: `{_table_cell(graph_query.get('result_count'))}`; depth used: `{_table_cell(graph_query.get('traversal_depth_used'))}`; modes used: `{_table_cell(', '.join(graph_query.get('query_mode_used') or []))}`; human review required: `{_table_cell(graph_query.get('human_review_required'))}`.",
                "",
                "The query UX uses explicit indexed/report links only. It does not run graph databases, NetworkX, GraphML, graph algorithms, semantic graph ranking, Engram, MCP, or memory-payload traversal.",
            ]
        )
        findings = graph_query.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Stale, sensitive, authority-confusion, traversal-limit, or graph-query bloat concerns should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Graph Context Query",
                "",
                "Status: `not_configured`. Generate `naos/reports/graph_context_query.json` with `naos graph-query --task T-XXX` or `make -f Makefile.naos naos-graph-query TASK=T-XXX` to populate this section.",
            ]
        )

    session_identity = control_plane.get("session_identity") or {}
    if session_identity:
        lines.extend(
            [
                "",
                "### Session Identity",
                "",
                "> Session identity isolates report roots; it is not task locking, operator attribution, audit logging, evidence conflict detection, approval, or source authority.",
                "",
                f"Status: `{_table_cell(session_identity.get('status'))}`; session id: `{_table_cell(session_identity.get('session_id'))}`; report root: `{_table_cell(session_identity.get('session_report_root'))}`; latest compatibility: `{_table_cell(bool(session_identity.get('latest_report_compatibility')))}; human review required: `{_table_cell(session_identity.get('human_review_required'))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Session Identity",
                "",
                "Status: `not_configured`. Generate `naos/reports/session_identity.json` with `naos session-id` or `make -f Makefile.naos naos-session-id` to populate this section.",
            ]
        )

    operator_attribution = control_plane.get("operator_attribution") or {}
    if operator_attribution:
        lines.extend(
            [
                "",
                "### Operator Attribution",
                "",
                "> Operator attribution records local identity signals for who initiated a run; it is not authentication, authorization, task ownership, task locking, separation-of-duties evidence, non-repudiation, approval, or an audit log.",
                "",
                f"Status: `{_table_cell(operator_attribution.get('status'))}`; source: `{_table_cell(operator_attribution.get('operator_source'))}`; attribution status: `{_table_cell(operator_attribution.get('operator_attribution_status'))}`; session id: `{_table_cell(operator_attribution.get('session_id'))}`; human review required: `{_table_cell(operator_attribution.get('human_review_required'))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Operator Attribution",
                "",
                "Status: `not_configured`. Generate `naos/reports/operator_attribution.json` with `naos operator-attribution` or `make -f Makefile.naos naos-operator-attribution` to populate this section.",
            ]
        )

    task_claims = control_plane.get("task_claims") or {}
    if task_claims:
        lines.extend(
            [
                "",
                "### Task Claims",
                "",
                "> Task claims coordinate work across sessions/operators. They are not authorization, approval, task ownership proof, separation-of-duties evidence, task completion, evidence conflict resolution, exclusive access, compliance proof, or source authority.",
                "",
                f"Status: `{_table_cell(task_claims.get('status'))}`; active: `{_table_cell(task_claims.get('active_claim_count'))}`; released: `{_table_cell(task_claims.get('released_claim_count'))}`; expired: `{_table_cell(task_claims.get('expired_claim_count'))}`; stale: `{_table_cell(task_claims.get('stale_claim_count'))}`; conflicting: `{_table_cell(task_claims.get('conflicting_claim_count'))}`; human review required: `{_table_cell(task_claims.get('human_review_required'))}`.",
            ]
        )
        if task_claims.get("conflicting_claim_count"):
            lines.append("")
            lines.append("Conflicting task claims require human review. NAOS records the coordination metadata and does not decide who may work.")
    else:
        lines.extend(
            [
                "",
                "### Task Claims",
                "",
                "Status: `not_configured`. Generate `naos/reports/task_claim_report.json` with `naos task-claims` or `make -f Makefile.naos naos-task-claims`; claim work with `make -f Makefile.naos naos-task-claim TASK=T-XXX`.",
            ]
        )

    session_lifecycle = control_plane.get("session_lifecycle") or {}
    if session_lifecycle:
        session_summary = session_lifecycle.get("summary") or {}
        lines.extend(
            [
                "",
                "### Session Lifecycle",
                "",
                "> Session lifecycle reports coordinate start, checkpoint, and end posture. They are review checklists, not proof, approval, task completion, evidence authority, automatic context injection, or memory write-back.",
                "",
                f"Status: `{_table_cell(session_lifecycle.get('status'))}`; mode: `{_table_cell(session_lifecycle.get('mode'))}`; task: `{_table_cell(session_lifecycle.get('task_id'))}`; reports present: `{_table_cell(session_summary.get('reports_present'))}`; reports missing: `{_table_cell(session_summary.get('reports_missing'))}`; stale inputs: `{_table_cell(session_summary.get('stale_inputs'))}`; memory candidate proposals: `{_table_cell(len(session_lifecycle.get('memory_candidate_proposals') or []))}`; human review required: `{_table_cell(session_lifecycle.get('human_review_required'))}`.",
                "",
                "Memory candidates in lifecycle output are proposal_only and not_written. Durable memory actions require configured, authorized, verified, memory-use-policy-permitted access and human approval.",
            ]
        )
        findings = session_lifecycle.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Stale session context, checkpoint gaps, and memory-candidate overclaims should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Session Lifecycle",
                "",
                "Status: `not_configured`. Generate `naos/reports/session_lifecycle.json` with `naos session-start --task T-XXX` or `make -f Makefile.naos naos-session-start TASK=T-XXX` to populate this section.",
            ]
        )

    audit_log = control_plane.get("audit_log") or {}
    if audit_log:
        audit_summary = audit_log.get("summary") or {}
        lines.extend(
            [
                "",
                "### Append-Only Audit Log",
                "",
                "> Audit log events record what happened over time. They are not approval, non-repudiation, cryptographic signing, tamper-proof storage, evidence conflict detection, task locking, compliance proof, or source of truth.",
                "",
                f"Status: `{_table_cell(audit_log.get('status'))}`; events: `{_table_cell(audit_log.get('event_count'))}`; invalid events: `{_table_cell(audit_log.get('invalid_event_count'))}`; missing session ids: `{_table_cell(len(audit_log.get('missing_session_id_events') or []))}`; missing operator ids: `{_table_cell(len(audit_log.get('missing_operator_id_events') or []))}`; human review required: `{_table_cell(audit_log.get('human_review_required'))}`.",
                "",
                f"Event files: `{_table_cell(audit_summary.get('event_files'))}`; logged sources: `{_table_cell(len(audit_log.get('audit_logged_sources') or []))}`; pending sources: `{_table_cell(len(audit_log.get('audit_pending_sources') or []))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Append-Only Audit Log",
                "",
                "Status: `not_configured`. Generate `naos/reports/audit_log_summary.json` with `naos audit-log` or `make -f Makefile.naos naos-audit-log` to populate this section.",
            ]
        )

    agent_traces = control_plane.get("agent_trace_validation") or {}
    if agent_traces:
        trace_summary = agent_traces.get("summary") or {}
        lines.extend(
            [
                "",
                "### Agent Trace Validation",
                "",
                "> Agent trace events are declared records for future StaticGrader, audit, drift, and assessment flows. They are not proof, approval, evidence authority, memory writes, runtime capture, legal/compliance/regulatory assurance, or behavioral safety evidence.",
                "",
                f"Status: `{_table_cell(agent_traces.get('status'))}`; events: `{_table_cell(agent_traces.get('event_count'))}`; action receipts: `{_table_cell(trace_summary.get('action_receipt_events'))}`; valid: `{_table_cell(agent_traces.get('valid_event_count'))}`; invalid: `{_table_cell(agent_traces.get('invalid_event_count'))}`; payload findings: `{_table_cell(len(agent_traces.get('forbidden_payload_findings') or []))}`; human review required: `{_table_cell(agent_traces.get('human_review_required'))}`.",
                "",
                f"Findings: `{_table_cell(trace_summary.get('total_findings'))}`; advisory: `{_table_cell(trace_summary.get('advisory'))}`; warnings: `{_table_cell(trace_summary.get('warnings'))}`; required: `{_table_cell(trace_summary.get('required'))}`; blocking: `{_table_cell(trace_summary.get('blocking'))}`.",
            ]
        )
        findings = agent_traces.get("findings") or []
        if findings:
            lines.append("")
            lines.append("Trace schema gaps, unsafe payload indicators, and trace-as-authority wording should be routed through control-plane review before any future grading use.")
    else:
        lines.extend(
            [
                "",
                "### Agent Trace Validation",
                "",
                "Status: `not_configured`. Generate `naos/reports/agent_trace_validation.json` with `naos agent-traces` or `make -f Makefile.naos naos-agent-traces` to populate this section.",
            ]
        )

    harness_import = control_plane.get("harness_trace_import") or {}
    if harness_import:
        import_summary = harness_import.get("summary") or {}
        lines.extend(
            [
                "",
                "### Harness Trace Import",
                "",
                "> Harness trace import normalizes explicit local JSONL/NDJSON records into declared trace events. It does not execute harnesses, capture runtime events, call providers, write memory, approve work, or prove behavior.",
                "",
                f"Status: `{_table_cell(harness_import.get('status'))}`; mode: `{_table_cell(harness_import.get('mode'))}`; imported: `{_table_cell(harness_import.get('imported_event_count'))}`; rejected: `{_table_cell(harness_import.get('rejected_record_count'))}`; written: `{_table_cell(harness_import.get('events_written'))}`; human review required: `{_table_cell(harness_import.get('human_review_required'))}`.",
                "",
                f"Findings: `{_table_cell(import_summary.get('total_findings'))}`; advisory: `{_table_cell(import_summary.get('advisory'))}`; warnings: `{_table_cell(import_summary.get('warnings'))}`; required: `{_table_cell(import_summary.get('required'))}`; blocking: `{_table_cell(import_summary.get('blocking'))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Harness Trace Import",
                "",
                "Status: `not_configured`. Generate `naos/reports/harness_trace_import.json` with `naos harness-trace-import --source <repo-local.jsonl>` or `make -f Makefile.naos naos-harness-trace-import HARNESS_TRACE_SOURCE=<repo-local.jsonl>` to populate this section.",
            ]
        )

    ai_surface = control_plane.get("ai_surface_health") or {}
    if ai_surface:
        ai_surface_summary = ai_surface.get("summary") or {}
        baseline = ai_surface.get("baseline") or {}
        lines.extend(
            [
                "",
                "### AI-Surface Health",
                "",
                "> AI-surface health is deterministic context-budget and coherence evidence. It helps interpret baseline reliability but does not prevent hallucinations, score behavior, approve work, certify compliance, or auto-tune thresholds.",
                "",
                f"Status: `{_table_cell(ai_surface.get('status'))}`; posture: `{_table_cell(ai_surface.get('ai_surface_health_posture'))}`; estimated tokens: `{_table_cell(ai_surface_summary.get('total_estimated_tokens'))}`; files: `{_table_cell(ai_surface_summary.get('total_files'))}`; findings: `{_table_cell(ai_surface_summary.get('total_findings'))}`; baseline: `{_table_cell(baseline.get('status'))}`; human review required: `{_table_cell(ai_surface.get('human_review_required'))}`.",
            ]
        )
        largest = ai_surface.get("largest_families") or []
        if largest:
            lines.extend(["", "| Family | Estimated Tokens | Files |", "|--------|------------------|-------|"])
            for item in largest:
                lines.append(f"| {_table_cell(item.get('id'))} | {_table_cell(item.get('estimated_tokens'))} | {_table_cell(item.get('file_count'))} |")
    else:
        lines.extend(
            [
                "",
                "### AI-Surface Health",
                "",
                "Status: `not_configured`. Generate `naos/reports/ai_surface_context_budget.json` with `naos ai-surface-budget` or `make -f Makefile.naos naos-ai-surface-budget` to populate this section.",
            ]
        )

    static_grader = control_plane.get("static_grader") or {}
    if static_grader:
        grader_summary = static_grader.get("summary") or {}
        cost_posture = static_grader.get("cost_posture") or {}
        lines.extend(
            [
                "",
                "### StaticGrader",
                "",
                "> StaticGrader is deterministic and structural only. It does not call models, providers, APIs, Engram, MCP, or memory tools, and it does not prove behavioral safety, semantic correctness, runtime behavior, approval, maturity promotion, or legal/regulatory posture.",
                "",
                f"Status: `{_table_cell(static_grader.get('status'))}`; findings: `{_table_cell(grader_summary.get('total_findings'))}`; dimensions: `{_table_cell(grader_summary.get('dimensions'))}`; not evaluated: `{_table_cell(grader_summary.get('not_evaluated_dimensions'))}`; cost_usd: `{_table_cell(cost_posture.get('cost_usd'))}`; human review required: `{_table_cell(static_grader.get('human_review_required'))}`.",
            ]
        )
        findings = static_grader.get("findings") or []
        if findings:
            lines.append("")
            lines.append("StaticGrader findings should be reviewed as deterministic structural signals; unsupported behavioral dimensions remain readiness-only.")
    else:
        lines.extend(
            [
                "",
                "### StaticGrader",
                "",
                "Status: `not_configured`. Generate `naos/reports/static_grader_report.json` with `naos static-grader` or `make -f Makefile.naos naos-static-grader` to populate this section.",
            ]
        )

    grader_assessment = control_plane.get("grader_assessment") or {}
    if grader_assessment:
        assessment_summary = grader_assessment.get("summary") or {}
        assessment_cost = grader_assessment.get("cost_budget_posture") or {}
        drift = grader_assessment.get("drift") or {}
        lines.extend(
            [
                "",
                "### Grader Assessment",
                "",
                "> Audit/drift/assess modes are deterministic review inputs. They do not approve audits, certify compliance, infer semantic drift, call LLMs/models/providers, or promote maturity.",
                "",
                f"Status: `{_table_cell(grader_assessment.get('status'))}`; mode: `{_table_cell(grader_assessment.get('mode'))}`; findings: `{_table_cell(assessment_summary.get('total_findings'))}`; changed dimensions: `{_table_cell(len(drift.get('changed_dimensions') or []))}`; cost_usd: `{_table_cell(assessment_cost.get('cost_usd'))}`; human review required: `{_table_cell(grader_assessment.get('human_review_required'))}`.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "### Grader Assessment",
                "",
                "Status: `not_configured`. Generate `naos/reports/grader_assessment.json` with `naos grader-assessment --mode audit` or `make -f Makefile.naos naos-grader-assessment MODE=audit` to populate this section.",
            ]
        )

    llm_readiness = control_plane.get("llm_grader_readiness") or {}
    if llm_readiness:
        readiness_summary = llm_readiness.get("summary") or {}
        readiness_cost = llm_readiness.get("cost_posture") or {}
        advisory_boundary = llm_readiness.get("advisory_boundary") or {}
        lines.extend(
            [
                "",
                "### LLMGrader Readiness",
                "",
                "> LLMGrader readiness is governance posture only. Runtime grading is disabled by default; future use may be useful as an advisory second opinion, but it cannot approve, certify, prove compliance, promote maturity, replace StaticGrader, or replace human review.",
                "",
                f"Status: `{_table_cell(llm_readiness.get('status'))}`; runtime enabled: `{_table_cell(llm_readiness.get('runtime_enabled'))}`; provider allowed: `{_table_cell(llm_readiness.get('provider_allowed'))}`; external API allowed: `{_table_cell(llm_readiness.get('external_api_allowed'))}`; model dependency allowed: `{_table_cell(llm_readiness.get('model_dependency_allowed'))}`; cost_usd: `{_table_cell(readiness_cost.get('cost_usd'))}`; human review required: `{_table_cell(llm_readiness.get('human_review_required'))}`.",
                "",
                f"Advisory only: `{_table_cell(advisory_boundary.get('advisory_only'))}`; can approve: `{_table_cell(advisory_boundary.get('can_approve'))}`; can certify: `{_table_cell(advisory_boundary.get('can_certify'))}`; can promote without human: `{_table_cell(advisory_boundary.get('can_promote_without_human'))}`.",
                "",
                "Future enablement requires budget controls, provider/model and prompt/rubric metadata, data exposure review, bias and variance limitations, residual-risk review, and human approval.",
            ]
        )
        if readiness_summary.get("total_findings"):
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(readiness_summary.get('total_findings'))}`. Runtime-enablement, cost, provider, data-exposure, or advisory-boundary findings should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### LLMGrader Readiness",
                "",
                "Status: `not_configured`. Generate `naos/reports/llm_grader_readiness.json` with `naos llm-grader-readiness` or `make -f Makefile.naos naos-llm-grader-readiness` to populate this section.",
            ]
        )

    behavioral_readiness = control_plane.get("behavioral_governance_readiness") or {}
    if behavioral_readiness:
        behavioral_summary = behavioral_readiness.get("summary") or {}
        behavioral_cost = behavioral_readiness.get("cost_posture") or {}
        impacter_counts = ((behavioral_readiness.get("impacter_review") or {}).get("impacter_counts") or {})
        recommended_commands = behavioral_readiness.get("recommended_next_commands") or []
        next_actions = behavioral_readiness.get("next_actions") or []
        advisory_nd = behavioral_readiness.get("advisory_non_deterministic_boundary") or {}
        lines.extend(
            [
                "",
                "### Behavioral Governance Readiness",
                "",
                "> Behavioral Governance Readiness is deterministic review posture only. It does not run behavioral grading, call models/providers/APIs, create baselines, infer semantic drift, approve, certify, prove compliance, publish, authorize releases, promote maturity, or replace human review.",
                "",
                f"Status: `{_table_cell(behavioral_readiness.get('status'))}`; baseline present: `{_table_cell(behavioral_readiness.get('baseline_state_present'))}`; impacters: `{_table_cell(behavioral_summary.get('total_impacters'))}`; high: `{_table_cell(impacter_counts.get('high'))}`; medium: `{_table_cell(impacter_counts.get('medium'))}`; low: `{_table_cell(impacter_counts.get('low'))}`; cost_usd: `{_table_cell(behavioral_cost.get('cost_usd'))}`; human review required: `{_table_cell(behavioral_readiness.get('human_review_required'))}`.",
                "",
                "Use this section before first behavioral baseline work or after governance/CI/config evidence changes. Treat findings as review input only.",
            ]
        )
        lines.extend(render_behavioral_readiness_flow())
        if recommended_commands:
            lines.extend(["", "Recommended explicit commands:"])
            for item in recommended_commands[:5]:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- `{_table_cell(item.get('command'))}` — lane: `{_table_cell(item.get('lane'))}`; auto-run allowed: `{_table_cell(item.get('auto_run_allowed'))}`."
                )
        if next_actions:
            lines.extend(["", "Next actions:"])
            for action in next_actions[:4]:
                lines.append(f"- {_table_cell(action)}")
        if advisory_nd:
            lines.append("")
            lines.append(
                f"Advisory non-deterministic boundary: readiness command `{_table_cell(advisory_nd.get('current_readiness_command'))}`; model-backed evaluator available: `{_table_cell(advisory_nd.get('model_backed_evaluator_available'))}`; auto-trigger allowed: `{_table_cell(advisory_nd.get('auto_trigger_allowed'))}`."
            )
        if behavioral_summary.get("total_findings"):
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(behavioral_summary.get('total_findings'))}`. Missing deterministic prerequisites, unsafe LLM readiness posture, or baseline impacters should be routed through control-plane review.")
    else:
        lines.extend(
            [
                "",
                "### Behavioral Governance Readiness",
                "",
                "Status: `not_configured`. Generate `naos/reports/behavioral_governance_readiness.json` with `naos behavioral-readiness` or `make -f Makefile.naos naos-behavioral-readiness` to populate this section.",
            ]
        )

    plan_coherence = control_plane.get("plan_coherence") or {}
    if plan_coherence:
        plan_summary = plan_coherence.get("summary") or {}
        implementation_readiness = plan_coherence.get("implementation_readiness") or {}
        task_coverage = implementation_readiness.get("task_coverage") or {}
        planning_decision = implementation_readiness.get("decision") or {}
        lines.extend(
            [
                "",
                "### Plan Coherence",
                "",
                "> Plan coherence reviews active task claims, task registry dependencies, module-header task linkage, and optional diff-base implementation-scope path evidence as deterministic coordination evidence. It does not authorize work, sequence execution, resolve conflicts, prove ownership, prove completion, prove semantic drift, or approve a plan.",
                "",
                f"Status: `{_table_cell(plan_coherence.get('status'))}`; implementation readiness: `{_table_cell(implementation_readiness.get('status'))}`; task coverage complete: `{_table_cell(task_coverage.get('complete'))}`; planning decision: `{_table_cell(planning_decision.get('status'))}`; active claims: `{_table_cell(plan_summary.get('active_claims'))}`; registry tasks: `{_table_cell(plan_summary.get('registry_tasks'))}`; linked tasks: `{_table_cell(plan_summary.get('tasks_with_file_linkage'))}`; changed files: `{_table_cell(plan_summary.get('changed_files'))}`; unplanned changed: `{_table_cell(plan_summary.get('unplanned_changed_files'))}`; out-of-scope changed: `{_table_cell(plan_summary.get('out_of_scope_changed_files'))}`; findings: `{_table_cell(plan_summary.get('total_findings'))}`; human review required: `{_table_cell(plan_coherence.get('human_review_required'))}`.",
            ]
        )
        if plan_coherence.get("findings"):
            lines.extend(["", "Plan coherence findings:"])
            for item in (plan_coherence.get("findings") or [])[:5]:
                if not isinstance(item, dict):
                    continue
                lines.append(f"- `{_table_cell(item.get('status'))}` — {_table_cell(item.get('message'))}")
    else:
        lines.extend(
            [
                "",
                "### Plan Coherence",
                "",
                "Status: `not_configured`. Generate `naos/reports/plan_coherence.json` with `naos plan-coherence` or `make -f Makefile.naos naos-plan-coherence` when task claims or task registry coordination need review.",
            ]
        )

    ai_code_provenance = control_plane.get("ai_code_provenance") or {}
    if ai_code_provenance:
        ai_code_summary = ai_code_provenance.get("summary") or {}
        ai_code_manifest = ai_code_provenance.get("manifest") or {}
        ai_code_artifacts = ai_code_provenance.get("ai_artifact_evidence") or {}
        ai_code_runtime = ai_code_provenance.get("runtime_posture") or {}
        recommended_commands = ai_code_provenance.get("recommended_next_commands") or []
        next_actions = ai_code_provenance.get("next_actions") or []
        lines.extend(
            [
                "",
                "### AI Code Provenance",
                "",
                "> AI Code Provenance packages local declarations and AI artifact evidence for human review. It does not provide legal opinions, authorship or ownership proof, infringement clearance, proof of copyright compliance, AI-output detection, line-level attribution, signing, publication authority, release authority, approval, certification, or proof of compliance.",
                "",
                f"Status: `{_table_cell(ai_code_provenance.get('status'))}`; manifest present: `{_table_cell(ai_code_manifest.get('present'))}`; declarations: `{_table_cell(ai_code_summary.get('declarations'))}`; missing evidence: `{_table_cell(ai_code_summary.get('missing_evidence'))}`; unresolved questions: `{_table_cell(ai_code_summary.get('unresolved_questions'))}`; review artifacts: `{_table_cell(ai_code_artifacts.get('review_artifacts'))}`; review decisions: `{_table_cell(ai_code_artifacts.get('review_decisions'))}`; human review required: `{_table_cell(ai_code_provenance.get('human_review_required'))}`.",
                "",
                f"Runtime posture: model/provider/API calls `{_table_cell(ai_code_runtime.get('model_provider_api_calls'))}`; credential reads `{_table_cell(ai_code_runtime.get('credential_reads'))}`; private prompt capture `{_table_cell(ai_code_runtime.get('private_prompt_capture'))}`; signing/notarization `{_table_cell(ai_code_runtime.get('signing_or_notarization'))}`.",
            ]
        )
        if recommended_commands:
            lines.extend(["", "Recommended explicit commands:"])
            for item in recommended_commands[:5]:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- `{_table_cell(item.get('command'))}` — auto-run allowed: `{_table_cell(item.get('auto_run_allowed'))}`."
                )
        if next_actions:
            lines.extend(["", "Next actions:"])
            for action in next_actions[:4]:
                lines.append(f"- {_table_cell(action)}")
        if ai_code_summary.get("total_findings"):
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(ai_code_summary.get('total_findings'))}`. Missing declarations, unresolved questions, AI artifact review items, or ownership-limit warnings should be routed through human review.")
    else:
        lines.extend(
            [
                "",
                "### AI Code Provenance",
                "",
                "Status: `not_configured`. Generate `naos/reports/ai_code_provenance.json` with `naos ai-code-provenance` or `make -f Makefile.naos naos-ai-code-provenance` to populate this section.",
            ]
        )

    compliance_posture = control_plane.get("compliance_posture") or {}
    if compliance_posture:
        compliance_summary = compliance_posture.get("summary") or {}
        compliance_manifest = compliance_posture.get("manifest") or {}
        compliance_runtime = compliance_posture.get("runtime_posture") or {}
        recommended_commands = compliance_posture.get("recommended_next_commands") or []
        next_actions = compliance_posture.get("next_actions") or []
        lines.extend(
            [
                "",
                "### Compliance Posture",
                "",
                "> Compliance Posture packages adopter-declared regulated-context metadata and evidence references for human review. It does not provide legal advice, regulatory applicability decisions, compliance pass/fail, certification, conformity assessment, audit opinions, approval, signing, release authority, publication authority, or proof of compliance.",
                "",
                f"Status: `{_table_cell(compliance_posture.get('status'))}`; manifest present: `{_table_cell(compliance_manifest.get('present'))}`; declared contexts: `{_table_cell(compliance_summary.get('declared_contexts'))}`; no regulated context asserted: `{_table_cell(compliance_summary.get('no_regulated_context_asserted'))}`; missing evidence: `{_table_cell(compliance_summary.get('missing_evidence'))}`; unresolved questions: `{_table_cell(compliance_summary.get('unresolved_questions'))}`; human review required: `{_table_cell(compliance_posture.get('human_review_required'))}`.",
                "",
                f"Runtime posture: model/provider/API calls `{_table_cell(compliance_runtime.get('model_provider_api_calls'))}`; network calls `{_table_cell(compliance_runtime.get('network_calls'))}`; legal research calls `{_table_cell(compliance_runtime.get('legal_research_calls'))}`; signing/notarization `{_table_cell(compliance_runtime.get('signing_or_notarization'))}`.",
            ]
        )
        if recommended_commands:
            lines.extend(["", "Recommended explicit commands:"])
            for item in recommended_commands[:5]:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- `{_table_cell(item.get('command'))}` — auto-run allowed: `{_table_cell(item.get('auto_run_allowed'))}`."
                )
        if next_actions:
            lines.extend(["", "Next actions:"])
            for action in next_actions[:4]:
                lines.append(f"- {_table_cell(action)}")
        if compliance_summary.get("total_findings"):
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(compliance_summary.get('total_findings'))}`. Missing declarations, missing evidence, or unresolved regulated-context questions should be routed through human review.")
    else:
        lines.extend(
            [
                "",
                "### Compliance Posture",
                "",
                "Status: `not_configured`. Generate `naos/reports/compliance_posture.json` with `naos compliance-posture` or `make -f Makefile.naos naos-compliance-posture` only when adopter-declared compliance posture evidence is needed.",
            ]
        )

    policy_overrides = control_plane.get("policy_overrides") or {}
    if policy_overrides:
        override_summary = policy_overrides.get("override_summary") or policy_overrides.get("summary") or {}
        lines.extend(
            [
                "",
                "### Policy Overrides",
                "",
                "> Static policy overrides are YAML-only customization aids. Team/operator scopes are configuration metadata only. They cannot weaken ADR-0010: Control-Plane Advisory Boundaries, turn advisory findings into authority, authenticate or authorize operators, enable plugin/runtime behavior, configure gatekeeper severity per team, or approve policy changes.",
                "",
                f"Status: `{_table_cell(policy_overrides.get('status'))}`; files: `{_table_cell(override_summary.get('override_files'))}`; applied paths: `{_table_cell(override_summary.get('applied_paths'))}`; applied scopes: `{_table_cell(', '.join(policy_overrides.get('applied_overlay_scopes') or []) or 'none')}`; protected invariant violations: `{_table_cell(len(policy_overrides.get('protected_invariant_violations') or []))}`; human review required: `{_table_cell(policy_overrides.get('human_review_required'))}`.",
            ]
        )
        findings = policy_overrides.get("findings") or []
        if findings:
            lines.append("")
            lines.append(f"Findings visible: `{_table_cell(len(findings))}`. Unknown paths and protected invariant attempts should be reviewed before relying on an effective policy.")
    else:
        lines.extend(
            [
                "",
                "### Policy Overrides",
                "",
        "Status: `not_configured`. Generate `naos/reports/policy_override_merge.json` with `naos policy-overrides --dry-run` or `make -f Makefile.naos naos-policy-overrides` to populate this section.",
            ]
        )

    agentic_workflow = control_plane.get("agentic_workflow") or {}
    alignment = control_plane.get("pre_implementation_alignment") or {}
    calibration = control_plane.get("calibration_shadow") or {}
    evidence_classification = control_plane.get("evidence_classification") or {}
    cross_harness = control_plane.get("cross_harness_review_readiness") or {}
    professional_adoption = control_plane.get("professional_adoption") or {}
    lines.extend(
        [
            "",
            "### Professional Adoption Engine",
            "",
            "> Adoption reports connect preflight, intake, inventories, install plan, challenges, baselines, and decision records. They are review evidence only; they do not silently overwrite files, enable providers, write memory, approve work, or prove legal or regulatory compliance.",
            "",
            f"Status: `{_table_cell(professional_adoption.get('status'))}`; reports present: `{_table_cell(professional_adoption.get('reports_present'))}` of `{_table_cell(professional_adoption.get('reports_expected'))}`; review-required reports: `{_table_cell(professional_adoption.get('reports_review_required'))}`.",
            "",
            "Run `make -f Makefile.naos naos-adopt MODE=greenfield` or `make -f Makefile.naos naos-adopt MODE=brownfield` to refresh this evidence set.",
            "",
            "### Governed Agentic Coding Workflow",
            "",
            "> These reports review declared file-first operating controls and alignment artifacts. They do not inspect chat history, approve design or implementation, prove requirements completeness, or replace human review.",
            "",
            f"Workflow status: `{_table_cell(agentic_workflow.get('status'))}`; config valid: `{_table_cell(agentic_workflow.get('workflow_config_valid'))}`; missing artifacts: `{_table_cell(len(agentic_workflow.get('missing_artifacts') or []))}`.",
            f"Pre-Implementation Alignment status: `{_table_cell(alignment.get('status'))}`; mode: `{_table_cell(alignment.get('mode'))}`; missing required questions: `{_table_cell(len(alignment.get('missing_required_questions') or []))}`.",
            "",
            "Run `make -f Makefile.naos naos-agentic-workflow-review` and `make -f Makefile.naos naos-pre-implementation-alignment-review` to refresh these reports.",
            "",
            "### Calibration and Evidence Classification",
            "",
            "> These reports improve deterministic review discipline. They do not calibrate models, prove truth, approve work, resolve issues, certify outcomes, or prove compliance.",
            "",
            f"Calibration shadow status: `{_table_cell(calibration.get('status'))}`; drift items: `{_table_cell(calibration.get('drift_count'))}`; missing reports: `{_table_cell(len(calibration.get('reports_missing') or []))}`.",
            f"Evidence classification status: `{_table_cell(evidence_classification.get('status'))}`; findings scanned: `{_table_cell(evidence_classification.get('findings_scanned'))}`; missing classifications: `{_table_cell(len(evidence_classification.get('missing_classification') or []))}`.",
            "",
            "Run `make -f Makefile.naos naos-calibration-shadow` and `make -f Makefile.naos naos-evidence-classification` to refresh these reports.",
            "",
            "### Cross-Harness Review Readiness",
            "",
            "> This report is readiness-only. It does not execute harnesses, sign artifacts, verify signatures, custody keys, create attestations, approve work, certify outcomes, or prove compliance.",
            "",
            f"Readiness status: `{_table_cell(cross_harness.get('status'))}`; declared harnesses: `{_table_cell(cross_harness.get('declared_harness_count'))}`; score: `{_table_cell(cross_harness.get('readiness_score'))}`; missing requirements: `{_table_cell(len(cross_harness.get('requirements_missing') or []))}`.",
            "",
            "Run `make -f Makefile.naos naos-cross-harness-review-readiness` to refresh this readiness report.",
        ]
    )

    gates = control_plane["gatekeeper_readiness"]["gates"]
    if gates:
        lines.extend(
            [
                "",
                "### Gatekeeper Readiness",
                "",
                "| Gate | Status | Severity | Missing Evidence |",
                "|------|--------|----------|------------------|",
            ]
        )
        for gate in gates:
            missing = gate.get("missing_evidence") or gate.get("missing_inputs") or []
            lines.append(
                f"| {_table_cell(gate.get('id'))} {_table_cell(gate.get('name'))} | {_table_cell(gate.get('status'))} | {_table_cell(gate.get('severity'))} | {_table_cell(', '.join(missing) if missing else '—')} |"
            )

    advanced = control_plane["advanced_capability_readiness"]["capabilities"]
    if advanced:
        lines.extend(
            [
                "",
                "### Advanced Capability Readiness",
                "",
                "| Capability | Status | Maturity | Enforcement | Note |",
                "|------------|--------|----------|-------------|------|",
            ]
        )
        for cap in advanced:
            lines.append(
                f"| {_table_cell(cap['id'])} | experimental | {_table_cell(cap.get('current_maturity'))} | {_table_cell(cap.get('enforcement'))} | scaffolded/advisory unless project policy changes it |"
            )

    known_gaps = control_plane["evidence_pack"]["known_gaps"] or []
    residual_risks = control_plane["evidence_pack"]["residual_risks"] or []
    if known_gaps or residual_risks:
        lines.append("\n### Evidence Pack Gaps And Residual Risk")
        lines.append(f"- Known gaps: `{len(known_gaps)}`.")
        lines.append(f"- Residual risks: `{len(residual_risks)}`.")
        for gap in known_gaps[:3]:
            lines.append(f"- Known gap: {_evidence_pack_item_text(gap)}")
        for risk in residual_risks[:3]:
            lines.append(f"- Residual risk: {_evidence_pack_item_text(risk)}")
        if len(known_gaps) > 3 or len(residual_risks) > 3:
            lines.extend(
                [
                    "",
                    "<details>",
                    "<summary>Additional evidence-pack gaps and residual risks</summary>",
                    "",
                ]
            )
            for gap in known_gaps[3:10]:
                lines.append(f"- Known gap: {_evidence_pack_item_text(gap)}")
            for risk in residual_risks[3:10]:
                lines.append(f"- Residual risk: {_evidence_pack_item_text(risk)}")
            lines.extend(["", "</details>"])

    lines.append(
        "\n> This dashboard does not prove legal/regulatory compliance, runtime safety, or complete test coverage."
    )
    return lines


def render_dashboard(
    control_plane: dict[str, Any] | None = None,
    finding_presentation: dict[str, Any] | None = None,
) -> str:
    tasks = parse_task_matrix()
    auth_counts = parse_authoritative_counts(REQ_FILE)
    reqs: dict[str, dict] = {}
    for rid in auth_counts["fr_complete"]:
        reqs[rid] = {"title": "", "status": "Implemented"}
    for rid in auth_counts["fr_in_progress"]:
        reqs[rid] = {"title": "", "status": "In Progress"}
    for rid in auth_counts["fr_planned"]:
        reqs[rid] = {"title": "", "status": "Planned"}
    for rid in auth_counts["nfr_complete"]:
        reqs[rid] = {"title": "", "status": "Implemented"}
    for rid in auth_counts["nfr_in_progress"]:
        reqs[rid] = {"title": "", "status": "In Progress"}
    for rid in auth_counts["nfr_planned"]:
        reqs[rid] = {"title": "", "status": "Planned"}
    req_stats = {
        "fr": auth_counts["fr"],
        "nfr": auth_counts["nfr"],
        "all": auth_counts["all"],
    }

    fr_t, fr_i, fr_p, fr_pl = req_stats["fr"]
    nfr_t, nfr_i, nfr_p, nfr_pl = req_stats["nfr"]

    governance = parse_governance_status()
    conformance = parse_conformance_metrics()
    evals = parse_eval_metrics()
    traceability = parse_traceability_metrics()
    risks = parse_risks()
    parse_dependencies()
    logical_deps = infer_logical_dependencies(tasks)
    releases = parse_recent_release_notes(limit=8)
    decisions = parse_decisions()
    trend = parse_trend_history()
    blockers = parse_blockers()
    gov_sprints = parse_governance_sprints()
    current_date = datetime.now(UTC).strftime("%Y-%m-%d")

    # Persist progress history once per run
    total_reqs_hist = fr_t + nfr_t
    done_reqs_hist = fr_i + nfr_i
    in_prog_reqs_hist = fr_p + nfr_p

    if total_reqs_hist > 0:
        history_file = NAOS_ROOT / "TASK_PROGRESS_HISTORY.csv"
        pct_hist = done_reqs_hist / total_reqs_hist * 100
        if not history_file.exists():
            history_file.write_text("timestamp,done_percent,done,in_progress,total\n")
        ts = datetime.now(UTC).isoformat()
        today_str = ts[:10]
        write_row = True
        try:
            existing = history_file.read_text().strip().splitlines()
            if len(existing) > 1 and existing[-1].startswith(today_str):
                write_row = False
        except Exception:
            pass
        if write_row:
            with history_file.open("a") as hf:
                hf.write(
                    f"{ts},{pct_hist:.2f},{done_reqs_hist},{in_prog_reqs_hist},{total_reqs_hist}\n"
                )

    # Build Gantt chart with logical dependencies
    acyclic_deps = remove_cycles(logical_deps, tasks)

    gantt_lines = [
        "```mermaid",
        "gantt",
        "    dateFormat  YYYY-MM-DD",
        "    title Delivery Timeline (with Dependencies)",
        "    axisFormat  %m-%d",
        "    todayMarker stroke-width:2px,stroke:#ff0000,opacity:0.75",
    ]

    today = datetime.now(UTC).date()

    predecessors: dict[str, list[str]] = defaultdict(list)
    for task, depends_on in acyclic_deps:
        predecessors[task].append(depends_on)

    task_ends: dict[str, date] = {}
    task_starts: dict[str, date] = {}

    def calculate_task_schedule(task_id: str, tasks_dict: dict) -> tuple[date, date]:
        if task_id in task_ends:
            return task_starts[task_id], task_ends[task_id]

        t = tasks_dict.get(task_id)
        if not t:
            return today, today

        target = t.get("target", "")
        planned = t.get("planned_hours", 16)
        dur_days = max(1, int(round(planned / 8.0)))

        if task_terminal_state(t):
            completion = t.get("completion_date", "")
            if completion:
                try:
                    if isinstance(completion, date):
                        end = completion
                    else:
                        end = datetime.strptime(str(completion), "%Y-%m-%d").date()  # noqa: DTZ007
                    start = end - timedelta(days=dur_days)
                except (ValueError, TypeError):
                    start = today - timedelta(days=dur_days)
                    end = today
            else:
                start = today - timedelta(days=dur_days)
                end = today
        elif predecessors[task_id]:
            max_pred_end = today
            for pred in predecessors[task_id]:
                _, pred_end = calculate_task_schedule(pred, tasks_dict)
                max_pred_end = max(max_pred_end, pred_end)
            start = max_pred_end + timedelta(days=1)
            end = start + timedelta(days=dur_days)
        elif target:
            try:
                tdate = datetime.strptime(target, "%Y-%m-%d").date()  # noqa: DTZ007
                if tdate > today:
                    end = tdate
                    start = end - timedelta(days=dur_days)
                else:
                    start = today
                    end = start + timedelta(days=dur_days)
            except Exception:
                start = today
                end = start + timedelta(days=dur_days)
        else:
            start = today
            end = start + timedelta(days=dur_days)

        task_starts[task_id] = start
        task_ends[task_id] = end
        return start, end

    tasks_dict = {t["id"]: t for t in tasks}

    for t in tasks:
        calculate_task_schedule(t["id"], tasks_dict)

    last_phase = None
    for t in tasks:
        s = t["status"].lower()
        if is_task_delivered(t):
            status_flag = "done"
        elif "progress" in s:
            status_flag = "active"
        else:
            status_flag = ""
        phase = t["phase"]
        if phase != last_phase:
            gantt_lines.append(f"    section Phase {phase}")
            last_phase = phase

        prefix = f"{status_flag} " if status_flag else ""
        start = task_starts[t["id"]]
        dur_days = (task_ends[t["id"]] - start).days

        clean_title = (
            t["title"]
            .replace(",", " ")
            .replace(":", " ")
            .replace("**", "")
            .replace("(", "")
            .replace(")", "")
            .strip()
        )

        if predecessors[t["id"]]:
            pred_id = predecessors[t["id"]][0]
            gantt_lines.append(
                f"    {prefix}{t['id']} : {clean_title}, after {pred_id}, {dur_days}d"
            )
        else:
            gantt_lines.append(
                f"    {prefix}{t['id']} : {clean_title}, {start.isoformat()}, {dur_days}d"
            )

    if acyclic_deps:
        gantt_lines.append("    %% Dependencies (acyclic):")
        for a, b in acyclic_deps:
            gantt_lines.append(f"    %% {a} after {b}")

    gantt_lines.append("```")

    # === BUILD DASHBOARD ===
    lines = [
        "<!-- ⚠️ AUTO-GENERATED FILE — DO NOT EDIT MANUALLY. Regenerate with: make -f Makefile.naos gov-refresh -->",
        "",
        "# Project Dashboard",
        "",
        f"**Date**: {current_date}",
        "",
    ]
    lines.extend(render_reader_index())
    lines.extend(render_dashboard_finding_presentation(finding_presentation))

    lines.append("## 📊 Executive Summary")
    lines.append("")

    total_reqs = fr_t + nfr_t
    implemented_reqs = fr_i + nfr_i
    in_progress_reqs = fr_p + nfr_p
    planned_reqs = fr_pl + nfr_pl
    overall_pct = (implemented_reqs / total_reqs * 100) if total_reqs else 0.0

    phase_1_5_tasks = [t for t in tasks if _phase_num(t) < 6]
    phase_1_5_done = len(
        [t for t in phase_1_5_tasks if is_task_delivered(t)]
    )
    phase_1_5_total = len(phase_1_5_tasks)
    phase_1_5_pct = (phase_1_5_done / phase_1_5_total * 100) if phase_1_5_total else 0.0
    phase_6_plus_tasks = [t for t in tasks if _phase_num(t) >= 6]
    phase_6_plus_done = len(
        [t for t in phase_6_plus_tasks if is_task_delivered(t)]
    )
    phase_6_plus_total = len(phase_6_plus_tasks)
    active_risks = len(
        [r for r in risks if "🟡" in r.get("status", "") or "🔥" in r.get("status", "")]
    )
    registry_metrics = load_registry_metrics()

    if overall_pct >= 75:
        trajectory = "excellent progress"
    elif overall_pct >= 50:
        trajectory = "strong progress"
    else:
        trajectory = "steady progress"

    if active_risks == 0:
        risk_status = "No active risks"
    elif active_risks <= 2:
        risk_status = f"{active_risks} risk(s) monitored with mitigation"
    else:
        risk_status = f"{active_risks} active risks requiring attention"

    if in_progress_reqs > 0:
        next_steps_text = f"Complete {in_progress_reqs} in-progress requirement(s)"
    elif planned_reqs > 0:
        next_steps_text = f"Begin {planned_reqs} planned requirement(s)"
    else:
        next_steps_text = "All requirements delivered — focus on next phase"

    lines.append(f"- **Where are we?** → {overall_pct:.1f}% complete, {trajectory}")
    lines.append(f"- **What's at risk?** → {risk_status}")
    lines.append(f"- **What's next?** → {next_steps_text}")
    lines.append(
        f"- **Phases 6+ ready** → {phase_6_plus_total} tasks ({phase_6_plus_done} done)"
    )
    lines.append("")

    # Narrative summary
    if overall_pct >= 75:
        health = "**excellent shape**"
        trajectory_desc = "on track to exceed targets"
    elif overall_pct >= 50:
        health = "**strong progress**"
        trajectory_desc = "on track for scheduled completion"
    elif overall_pct >= 25:
        health = "**steady progress**"
        trajectory_desc = "requires focused execution to meet targets"
    else:
        health = "**early stages**"
        trajectory_desc = "building momentum"

    narrative = (
        f"The project is in {health} with **{overall_pct:.1f}% of requirements delivered** "
        f"({implemented_reqs}/{total_reqs}), {trajectory_desc}."
    )
    if active_risks == 0:
        narrative += " **No active high-priority risks.**"
    elif active_risks <= 2:
        narrative += f" **{active_risks} active risk(s)** monitored."
    lines.append(narrative)
    lines.append("")

    # Key Metrics table
    lines.append("### Key Metrics")
    lines.append("")
    lines.append(
        f"**Overall Project Completion**: {implemented_reqs}/{total_reqs} requirements ({overall_pct:.1f}%)"
    )
    lines.append("")
    lines.append("| Metric | Value | Status |")
    lines.append("|--------|-------|--------|")
    lines.append(
        f"| **Requirements Delivered** | {implemented_reqs}/{total_reqs} ({overall_pct:.1f}%) | {'🟢 On Track' if overall_pct >= 50 else '🟡 Behind'} |"
    )
    lines.append(
        f"| **Functional (FR)** | {fr_i}/{fr_t} ({(fr_i / fr_t * 100) if fr_t else 0:.1f}%) | {'✅ Complete' if fr_i == fr_t else f'🔵 {fr_p} in progress'} |"
    )
    lines.append(
        f"| **Non-Functional (NFR)** | {nfr_i}/{nfr_t} ({(nfr_i / nfr_t * 100) if nfr_t else 0:.1f}%) | {'✅ Complete' if nfr_i == nfr_t else f'🔵 {nfr_p} in progress'} |"
    )
    if registry_metrics:
        lines.append(
            f"| **Tasks** | {registry_metrics['done']}/{registry_metrics['total']} tasks ({registry_metrics['pct']:.1f}%) | {'🟢 On Track' if registry_metrics['pct'] >= 50 else '🟡 Behind'} |"
        )

    gov_ok = (
        governance["rules_defined"]
        and governance["docs_indexed"]
        and governance["pre_commit_hook"]
    )
    gov_status = "🟢 Configured" if gov_ok else "🔴 Gaps"
    lines.append(
        f"| **Governance Health** | Rules: {'✅' if governance['rules_defined'] else '❌'}, Index: {'✅' if governance['docs_indexed'] else '❌'}, Hooks: {'✅' if governance['pre_commit_hook'] else '❌'} | {gov_status} |"
    )
    if conformance is not None:
        oc = conformance.get("overall_conformance")
        run_date = conformance.get("run_date", "—")
        oc_pct = f"{oc * 100:.1f}%" if oc is not None else "—"
        oc_status = "🟢 Passing" if (oc or 0) >= 0.8 else ("🟡 Partial" if (oc or 0) >= 0.5 else "🔴 Low")
        lines.append(
            f"| **AI Conformance** | {oc_pct} static checks ({run_date}) | {oc_status} |"
        )

    freshness = check_source_freshness()
    if freshness:
        lines.append(
            f"| **Data Freshness** | {len([f for f in freshness if '✅' in f['status']])}/{len(freshness)} sources current | {'🟢 Sync' if all('✅' in f['status'] for f in freshness) else '🟡 Lagging'} |"
        )

    # Ghost features
    ghosts = scan_ghost_features(reqs)
    if ghosts:
        lines.append("")
        lines.append("### 🚨 Governance Alerts")
        for ghost in ghosts:
            lines.append(f"- {ghost}")

    if freshness and any("⚠️" in f["status"] or "❌" in f["status"] for f in freshness):
        lines.append("")
        lines.append("### ⚠️ Data Source Warnings")
        for f in freshness:
            if "✅" not in f["status"]:
                lines.append(f"- **{f['file']}**: {f['status']} - {f['msg']}")

    lines.append(
        f"| **Phase 1-5 Progress** | {phase_1_5_done}/{phase_1_5_total} tasks ({phase_1_5_pct:.1f}%) | {'✅ Complete' if phase_1_5_done == phase_1_5_total else '🔵 In Progress'} |"
    )
    phase_6_pct = (
        (phase_6_plus_done / phase_6_plus_total * 100) if phase_6_plus_total else 0.0
    )
    lines.append(
        f"| **Phase 6+ Progress** | {phase_6_plus_done}/{phase_6_plus_total} tasks ({phase_6_pct:.1f}%) | {'✅ Complete' if phase_6_plus_done == phase_6_plus_total else ('🔵 In Progress' if phase_6_plus_done > 0 else '⚪ Planned')} |"
    )
    lines.append(
        f"| **Active Risks** | {active_risks} risks | {'🟢 Low' if active_risks <= 2 else '🟡 Monitor'} |"
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    # === TIMELINE ===
    lines.append("## Timeline")
    lines.extend(gantt_lines)

    lines.append("\n## Task Progress (canonical)")
    lines.append("| ID | Title | Phase | Status | Badge | Target End | Late |")
    lines.append("|----|-------|------|--------|-------|------------|------|")

    def badge(task: dict) -> str:
        s = task["status"].lower()
        states = normalize_task_states(task)
        if is_task_delivered(task):
            return "✅"
        if states["lifecycle_state"] == "implementation_complete":
            return "🟠"
        if states.get("compatibility_status") == "unsupported":
            return "⚠️"
        if "progress" in s:
            return "🔵"
        if s == "planned":
            return "🟡"
        if s == "deferred":
            return "⏸️"
        if s == "absorbed":
            return "🔀"
        if s == "blocked":
            return "⛔"
        return ""

    for t in tasks:
        target = t.get("target", "")
        late = ""
        overdue_days = ""
        if target:
            try:
                tdate = datetime.strptime(target, "%Y-%m-%d").date()  # noqa: DTZ007
                if today > tdate and not is_task_delivered(t) and not task_terminal_state(t):
                    days = (today - tdate).days
                    late = "🚨" if days >= 7 else "⚠️"
                    overdue_days = f"{days}d" if days > 0 else ""
            except Exception:
                pass
        late_cell = f"{late} {overdue_days}".strip()
        lines.append(
            f"| {t['id']} | {t['title']} | {t['phase']} | {t['status']} | {badge(t)} | {target} | {late_cell} |"
        )

    if trend:
        lines.append("\n### Completion Trend (requirements done %)")
        lines.append(render_trend_sparkline(trend))

    lines.append("\n## Requirement Coverage")
    lines.append("| Type | Total | Implemented | In Progress | Planned |")
    lines.append("|------|-------|-------------|------------|---------|")
    lines.append(f"| FR | {fr_t} | {fr_i} | {fr_p} | {fr_pl} |")
    lines.append(f"| NFR | {nfr_t} | {nfr_i} | {nfr_p} | {nfr_pl} |")
    all_t, all_i, all_p, all_pl = req_stats["all"]
    lines.append(f"| All | {all_t} | {all_i} | {all_p} | {all_pl} |")
    lines.extend(render_testing_metrics(control_plane, traceability))

    # === TRACEABILITY HEALTH ===
    if traceability:
        lines.append("\n## Traceability Health & Coverage Metrics")
        lines.append(
            "> **Note**: *Spec Linkage Coverage* measures files with `Implements: FR-XXX` headers. "
            "*Test Coverage* measures code executed by tests. These are different metrics."
        )
        lines.append("")
        lines.append("| Metric | Value | Status |")
        lines.append("|--------|-------|--------|")

        traced = traceability.get("reqs_traced", 0)
        total_reqs_t = traceability.get("reqs_total", 0)
        traced_pct = traceability.get("reqs_traced_pct", 0)
        status = (
            "🟢 Good"
            if traced_pct >= 75
            else ("🟡 Fair" if traced_pct >= 50 else "🔴 Needs Work")
        )
        lines.append(
            f"| Requirements Traced | {traced}/{total_reqs_t} ({traced_pct:.1f}%) | {status} |"
        )

        files_with_reqs = traceability.get("files_with_reqs", 0)
        total_files = traceability.get("total_files", 0)
        coverage_pct = traceability.get("files_coverage_pct", 0)
        status = (
            "🟢 Excellent"
            if coverage_pct >= 90
            else ("🟡 Good" if coverage_pct >= 75 else "🔴 Low")
        )
        lines.append(
            f"| Spec Linkage Coverage | {files_with_reqs}/{total_files} ({coverage_pct:.1f}%) | {status} |"
        )

        pytest_coverage, pytest_target = _read_pytest_coverage()
        pytest_status = (
            "🟢 On Target"
            if pytest_coverage >= pytest_target
            else (
                "🟡 Near Target"
                if pytest_coverage >= pytest_target * 0.85
                else "🟠 Below Target"
            )
        )
        lines.append(
            f"| Test Coverage (pytest) | {pytest_coverage:.1f}% | {pytest_status} (target: {pytest_target:.0f}%) |"
        )

        linkages = traceability.get("total_linkages", 0)
        linkage_target = total_files if total_files else 1
        linkage_pct = (linkages / linkage_target * 100) if linkage_target else 0
        status = (
            "🟢 Complete"
            if linkage_pct >= 100
            else ("🟡 In Progress" if linkage_pct >= 10 else "🔴 Minimal")
        )
        lines.append(
            f"| Total Linkages | {linkages} / {linkage_target} ({linkage_pct:.1f}%) | {status} |"
        )

        unimpl = traceability.get("unimplemented_reqs", 0)
        impl_pct = ((total_reqs_t - unimpl) / total_reqs_t * 100) if total_reqs_t else 0
        status = (
            "🟢 Ready"
            if impl_pct >= 90
            else ("🟡 In Progress" if impl_pct >= 50 else "🔴 Early Stage")
        )
        lines.append(
            f"| Implementation Gap | {unimpl} not implemented ({impl_pct:.1f}% done) | {status} |"
        )

        spec_tags = traceability.get("spec_tags", 0)
        lines.append(f"| Spec ID Tags | {spec_tags} tags indexed | ✅ Enabled |")

    # === GOVERNANCE SPRINT HISTORY ===
    if gov_sprints:
        lines.append("\n## Governance Sprint History")
        lines.append("")

        dates = [s.get("created", "") for s in gov_sprints if s.get("created")]
        categories: set[str] = set()
        for s in gov_sprints:
            cat = s.get("category", "")
            if cat:
                for part in cat.split("/"):
                    categories.add(part.strip())

        date_range = ""
        if dates:
            date_range = f" ({min(dates)} → {max(dates)})"

        lines.append(f"**{len(gov_sprints)} governance sprints completed**{date_range}")
        if categories:
            lines.append(f"Categories: {', '.join(sorted(categories)[:8])}")
        lines.append("")

        lines.append("| ID | Title | Category | Brief | Created |")
        lines.append("|----|-------|----------|-------|---------|")
        for s in gov_sprints:
            sid = s.get("id", "")
            title = s.get("title", "")
            cat = s.get("category", "—")
            brief = s.get("brief", "—")
            created = s.get("created", "—")
            lines.append(f"| {sid} | {title} | {cat} | {brief} | {created} |")

    # === AI QUALITY (conformance + evals — rendered only when data present) ===
    if conformance is not None or evals:
        lines.append("\n## AI Quality")

        if conformance is not None:
            run_date = conformance.get("run_date", "—")
            mode = conformance.get("mode", "conformance")
            lines.append(f"\n### Conformance ({mode} — {run_date})")

            sc = conformance.get("structural_checks", {})
            fc = conformance.get("frontmatter_checks", {})
            bc = conformance.get("battery_checks", {})
            oc = conformance.get("overall_conformance")

            def _pct(score: float | None) -> str:
                return f"{score * 100:.1f}%" if score is not None else "—"

            lines.append("| Check | Passed | Score |")
            lines.append("|-------|-------:|------:|")
            lines.append(
                f"| Structural | {sc.get('passed', '—')}/{sc.get('total', '—')} | {_pct(sc.get('score'))} |"
            )
            if fc:
                lines.append(
                    f"| Frontmatter | {fc.get('passed', '—')}/{fc.get('total', '—')} | {_pct(fc.get('score'))} |"
                )
            lines.append(
                f"| Battery | {bc.get('passed', '—')}/{bc.get('total', '—')} | {_pct(bc.get('score'))} |"
            )
            lines.append(f"| **Overall** | — | **{_pct(oc)}** |")

            dims = conformance.get("dimensions", {})
            scored = {k: v for k, v in dims.items() if v is not None}
            if scored:
                lines.append("\n#### Behavioral Dimensions (project-configured evaluator)")
                lines.append("| Dimension | Score |")
                lines.append("|-----------|------:|")
                _dim_labels = {
                    "D1_rule_compliance": "D1 Rule Compliance",
                    "D2_agent_instructions": "D2 Agent Instructions",
                    "D3_scoped_instructions": "D3 Scoped Instructions",
                    "D4_prompt_templates": "D4 Prompt Templates",
                    "D5_efficiency": "D5 Efficiency",
                    "D6_portability": "D6 Portability",
                    "D7_session_hygiene": "D7 Session Hygiene",
                    "D8_ai_output_quality": "D8 AI Output Quality",
                }
                for key, label in _dim_labels.items():
                    val = dims.get(key)
                    cell = f"{val * 100:.1f}%" if val is not None else "— (not run)"
                    flag = " ⚠️" if val is not None and val < 0.5 else ""
                    lines.append(f"| {label} | {cell}{flag} |")
            else:
                lines.append(
                    "\n> Behavioral dimensions (D1-D8) require a future/project-configured behavioral governance evaluator. Deterministic `--conformance` is available now and uses no LLM or API key."
                )

        if evals:
            lines.append("\n### Eval Pass Rates (latest per feature)")
            lines.append("| Feature | Pass Rate | Cases | Date |")
            lines.append("|---------|----------:|------:|------|")
            for e in sorted(evals, key=lambda x: x.get("feature", "")):
                feature = e.get("feature", "—")
                pass_rate = e.get("pass_rate")
                cases = e.get("cases", "—")
                run_date = e.get("date", "—")
                rate_str = f"{pass_rate * 100:.0f}%" if pass_rate is not None else "—"
                flag = " ⚠️" if pass_rate is not None and pass_rate < 0.8 else ""
                lines.append(f"| {feature} | {rate_str}{flag} | {cases} | {run_date} |")

    lines.extend(render_control_plane_dashboard(control_plane))

    if risks:
        lines.append("\n## Risks (heatmap)")
        lines.append("| ID | Risk | Score | Level | Mitigation |")
        lines.append("|----|------|-------|-------|------------|")

        def level(score: str) -> str:
            try:
                s = int(score)
            except Exception:
                return ""
            if s >= 15:
                return "🔥 High"
            if s >= 8:
                return "⚠️ Medium"
            return "✅ Low"

        for r in risks:
            lvl = level(r["score"])
            lines.append(
                f"| {r['id']} | {r['risk']} | {r['score']} | {lvl} | {r['mitigation']} |"
            )

    if releases:
        lines.append("\n## Recent Releases (latest changes)")
        for rel in releases:
            lines.append(rel)

    if decisions:
        lines.append("\n## Decisions (recent)")
        lines.append("| ID | Date | Title | Decision | Impact |")
        lines.append("|----|------|-------|----------|--------|")
        for d in decisions[:5]:
            lines.append(
                f"| {d['id']} | {d['date']} | {d['title']} | {d['decision']} | {d['cons']} |"
            )

    if blockers:
        lines.append("\n## Blockers")
        for b in blockers:
            lines.append(f"- {b}")

    lines.append("\n## Quick Actions")
    lines.append("")
    lines.append("| Action | Command | When to Use |")
    lines.append("|--------|---------|-------------|")
    lines.append(
        "| Refresh dashboard | `make -f Makefile.naos gov-refresh` | After any task/status change |"
    )
    if conformance is None:
        lines.append(
            "| Run conformance check | `make -f Makefile.naos naos-conformance` | First run or after kit changes |"
        )
    lines.append("| Run tests | `make test` | Before committing code |")
    lines.append("| Full governance | `make -f Makefile.naos gov-full` | Before PRs / milestone gates |")
    if traceability and traceability.get("unimplemented_reqs", 0) > 0:
        gaps = traceability["unimplemented_reqs"]
        lines.append(
            f"| Fix traceability gaps ({gaps}) | `grep '⚠️ Not Implemented' naos/TRACEABILITY_MATRIX.md` | Improve coverage |"
        )
    if active_risks > 0:
        lines.append(
            f"| Review risks ({active_risks}) | `grep '🔥\\|⚠️' naos/DASHBOARD.md` | Mitigate active risks |"
        )
    if blockers:
        lines.append(
            f"| Resolve blockers ({len(blockers)}) | `grep '🛑' naos/PROJECT_STATUS.md` | Unblock progress |"
        )
    planned_tasks = [t for t in tasks if t["status"].lower() == "planned"]
    if planned_tasks:
        lines.append(
            f"| View planned tasks ({len(planned_tasks)}) | `grep 'status: planned' naos/TASK_REGISTRY.yaml` | Plan next sprint |"
        )

    lines.append("\n## Next Steps")
    next_items = []

    in_progress_tasks = [t for t in tasks if t["status"].lower() == "in progress"]
    if in_progress_tasks:
        task_list = ", ".join(f"{t['id']}" for t in in_progress_tasks[:5])
        suffix = (
            f" (+{len(in_progress_tasks) - 5} more)"
            if len(in_progress_tasks) > 5
            else ""
        )
        next_items.append(
            f"🔵 **Complete in-progress tasks** ({len(in_progress_tasks)}): {task_list}{suffix}"
        )

    if blockers:
        next_items.append(
            f"⛔ **Resolve {len(blockers)} blocker(s)** before continuing"
        )

    p0_planned = [t for t in planned_tasks if t.get("priority") == "P0"]
    p1_planned = [t for t in planned_tasks if t.get("priority") == "P1"]
    if p0_planned:
        task_list = ", ".join(f"{t['id']}" for t in p0_planned[:5])
        next_items.append(f"🔴 **Start P0 tasks** ({len(p0_planned)}): {task_list}")
    if p1_planned:
        task_list = ", ".join(f"{t['id']}" for t in p1_planned[:5])
        suffix = f" (+{len(p1_planned) - 5} more)" if len(p1_planned) > 5 else ""
        next_items.append(
            f"🟡 **Queue P1 tasks** ({len(p1_planned)}): {task_list}{suffix}"
        )

    if active_risks > 0:
        next_items.append(
            f"⚠️ **Monitor {active_risks} active risk(s)** — review mitigation plans"
        )

    if not gov_ok:
        missing = []
        if not governance["rules_defined"]:
            missing.append("RULES.md")
        if not governance["docs_indexed"]:
            missing.append("DOCS_INDEX")
        if not governance["pre_commit_hook"]:
            missing.append("pre-commit hook")
        next_items.append(f"🔧 **Fix governance gaps**: {', '.join(missing)}")

    if traceability and traceability.get("unimplemented_reqs", 0) > 0:
        next_items.append(
            f"📊 **Close {traceability['unimplemented_reqs']} traceability gap(s)** — add code-to-requirement links"
        )

    if not next_items:
        next_items.append("✅ **All clear** — no immediate action items")

    for item in next_items:
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate NAOS governance dashboard (naos/DASHBOARD.md)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Filter by team (requires team_config.enabled=true in TASK_REGISTRY.yaml):\n"
            "  python generate_naos_dashboard.py --team backend"
        ),
    )
    parser.add_argument("--profile", help="NAOS profile: quickstart, lite, standard, or assured.")
    parser.add_argument("--naos-root", default=os.getenv("NAOS_ROOT"), help="Generated project NAOS root. Default comes from policy.")
    parser.add_argument("--policy", help="Explicit NAOS policy YAML path.")
    parser.add_argument("--output", help="Optional Markdown dashboard output path.")
    parser.add_argument("--json-output", help="Optional machine-readable dashboard summary output path.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable dashboard summary JSON.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every human-readable finding occurrence; JSON is always complete.",
    )
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit-code behavior.")
    parser.add_argument("--claims-report")
    parser.add_argument("--self-check-report")
    parser.add_argument("--capability-maturity-report")
    parser.add_argument("--systemic-impact-report")
    parser.add_argument("--module-header-report")
    parser.add_argument("--spec-pack-contract-report")
    parser.add_argument("--spec-pack-materialization-report")
    parser.add_argument("--spec-assembly-worksheet-report")
    parser.add_argument("--spec-cascade-report")
    parser.add_argument("--control-plane-review-report")
    parser.add_argument("--setup-recommendations-report")
    parser.add_argument("--governance-bypass-posture-report")
    parser.add_argument("--external-evidence-ingest-report")
    parser.add_argument("--evidence-attestation-report")
    parser.add_argument("--evidence-verification-report")
    parser.add_argument("--evidence-conflict-detection-report")
    parser.add_argument("--task-claim-report")
    parser.add_argument("--memory-context-readiness-report")
    parser.add_argument("--memory-provider-access-report")
    parser.add_argument("--memory-use-policy-report")
    parser.add_argument("--learning-loop-review-report")
    parser.add_argument("--failure-mode-observations-report")
    parser.add_argument("--adapter-coherence-report")
    parser.add_argument("--task-context-pack-report")
    parser.add_argument("--task-lifecycle-report")
    parser.add_argument("--research-record-report")
    parser.add_argument("--composed-traceability-report")
    parser.add_argument("--local-context-index-report")
    parser.add_argument("--sqlite-write-coordination-report")
    parser.add_argument("--local-context-query-report")
    parser.add_argument("--semantic-candidate-layer-report")
    parser.add_argument("--graph-context-readiness-report")
    parser.add_argument("--graph-context-query-report")
    parser.add_argument("--session-identity-report")
    parser.add_argument("--operator-attribution-report")
    parser.add_argument("--session-lifecycle-report")
    parser.add_argument("--audit-log-summary-report")
    parser.add_argument("--agent-trace-validation-report")
    parser.add_argument("--harness-trace-import-report")
    parser.add_argument("--ai-surface-context-budget-report")
    parser.add_argument("--static-grader-report")
    parser.add_argument("--grader-assessment-report")
    parser.add_argument("--llm-grader-readiness-report")
    parser.add_argument("--behavioral-governance-readiness-report")
    parser.add_argument("--policy-override-merge-report")
    parser.add_argument("--plan-coherence-report")
    parser.add_argument("--pr-risk-classification-report")
    parser.add_argument("--pr-governance-summary-report")
    parser.add_argument("--agentic-workflow-review-report")
    parser.add_argument("--pre-implementation-alignment-review-report")
    parser.add_argument("--calibration-shadow-report")
    parser.add_argument("--evidence-classification-report")
    parser.add_argument("--cross-harness-review-readiness-report")
    parser.add_argument("--adoption-summary-report")
    parser.add_argument("--preflight-report")
    parser.add_argument("--intake-report")
    parser.add_argument("--install-plan-report")
    parser.add_argument("--existing-resource-inventory-report")
    parser.add_argument("--ai-artifact-inventory-report")
    parser.add_argument("--ai-artifact-reconciliation-report")
    parser.add_argument("--ai-code-provenance-report")
    parser.add_argument("--compliance-posture-report")
    parser.add_argument("--memory-resource-inventory-report")
    parser.add_argument("--memory-resource-reconciliation-report")
    parser.add_argument("--mcp-resource-inventory-report")
    parser.add_argument("--brownfield-baseline-report")
    parser.add_argument("--candidate-requirements-report")
    parser.add_argument("--traceability-gap-register-report")
    parser.add_argument("--install-decision-record-report")
    parser.add_argument("--context-challenge-report")
    parser.add_argument("--repo-context-challenge-report")
    parser.add_argument("--plan-challenge-report")
    parser.add_argument("--decision-probe-report")
    parser.add_argument("--planning-gate-review-report")
    parser.add_argument("--roadmap-report")
    parser.add_argument("--function-index-report")
    parser.add_argument("--duplicate-function-hygiene-report")
    parser.add_argument("--secret-hygiene-report")
    parser.add_argument("--test-quality-hygiene-report")
    parser.add_argument("--dependency-integrity-report")
    parser.add_argument("--package-reality-report")
    parser.add_argument("--api-symbol-reality-report")
    parser.add_argument("--ac-completion-evidence-report")
    parser.add_argument("--gate-status-report")
    parser.add_argument("--gate-evaluation-report")
    parser.add_argument("--test-map")
    parser.add_argument("--test-evidence-report")
    parser.add_argument("--evidence-pack")
    parser.add_argument("--capabilities-dir")
    parser.add_argument(
        "--team",
        default=None,
        metavar="TEAM_ID",
        help=(
            "Filter dashboard to tasks in scope for this team. "
            "Requires team_config.enabled=true in TASK_REGISTRY.yaml. "
            "Example: --team backend"
        ),
    )
    args = parser.parse_args()
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    configure_naos_root(naos_root)
    profile = normalize_profile(args.profile, policy)

    global _TEAM_FILTER
    _TEAM_FILTER = args.team
    if _TEAM_FILTER:
        print(f"Dashboard team filter: {_TEAM_FILTER}", file=sys.stderr if args.json else sys.stdout)

    presentation_inputs: dict[str, dict[str, Any]] = {}
    try:
        dashboard_summary = build_dashboard_summary(
            root,
            profile,
            naos_root,
            policy,
            args,
            presentation_inputs=presentation_inputs,
        )
    except TeamConfigValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    occurrences, limitations = dashboard_finding_occurrences(
        dashboard_summary,
        presentation_inputs,
    )
    finding_presentation = build_actionable_presentation(
        occurrences,
        expansion_command="naos dashboard --all",
        show_all=args.all,
        limitations=limitations,
    )
    markdown = render_dashboard(dashboard_summary, finding_presentation)
    if not args.json:
        print("NAOS dashboard findings:")
        for line in presentation_lines(finding_presentation):
            print(line)

    output_path = Path(args.output) if args.output else dashboard_output_path(root, naos_root, policy)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
        print(f"Wrote {output_path}", file=sys.stderr if args.json else sys.stdout)
    else:
        print(
            "Dashboard generated; no Markdown output written because no adopter NAOS root was detected.",
            file=sys.stderr if args.json else sys.stdout,
        )

    summary_path = Path(args.json_output) if args.json_output else report_output_path(root, naos_root, policy, "dashboard_summary_report")
    write_report(summary_path, dashboard_summary)
    if summary_path:
        print(f"Wrote {summary_path}", file=sys.stderr if args.json else sys.stdout)

    if args.json:
        print(json.dumps(dashboard_summary, indent=2, sort_keys=True))

    return exit_code_for_summary(profile, dashboard_summary["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
