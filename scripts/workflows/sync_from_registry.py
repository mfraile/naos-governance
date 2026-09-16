#!/usr/bin/env python3
"""
sync_from_registry.py - THE MASTER SYNC COMMAND

PURPOSE:
    Regenerates ALL derived PM files from the two authoritative sources:
    1. specs/03-requirements.md (FR/NFR definitions)
    2. NAOS_ROOT/TASK_REGISTRY.yaml (all tasks)

DERIVED FILES UPDATED:
    - NAOS_ROOT/BACKLOG.md (task queue)
    - NAOS_ROOT/DASHBOARD.md (metrics dashboard — header rows only)
    - NAOS_ROOT/PROJECT_STATUS.md (stale sections only — manual journal preserved)
    - specs/10-execution.md (Task Matrix section only)

USAGE:
    python scripts/workflows/sync_from_registry.py

    # Or with specific targets
    python scripts/workflows/sync_from_registry.py --backlog
    python scripts/workflows/sync_from_registry.py --dashboard
    python scripts/workflows/sync_from_registry.py --execution
    python scripts/workflows/sync_from_registry.py --project-status

    # Filter by team (requires team_config.enabled=true in TASK_REGISTRY.yaml)
    python scripts/workflows/sync_from_registry.py --team backend

THIS IS THE ONLY COMMAND YOU NEED TO RUN.
After editing TASK_REGISTRY.yaml, run this and everything stays in sync.

ENVIRONMENT:
    NAOS_ROOT  — path to the naos/ governance folder (default: "naos")

[ADAPT] PHASE_META: Replace the generic phase names with your project's actual
milestone names and target dates before using this script.
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_task_lifecycle import is_task_delivered, normalize_task_states, validate_task_artifact_identity  # noqa: E402
from naos_validate_task_registry import (  # noqa: E402
    TeamConfigValidationError,
    require_valid_team_config,
)

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML>=6.0")
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────
REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"
REQUIREMENTS_PATH = Path("specs/03-requirements.md")
BACKLOG_PATH = NAOS_ROOT / "BACKLOG.md"
DASHBOARD_PATH = NAOS_ROOT / "DASHBOARD.md"
EXECUTION_PATH = Path("specs/10-execution.md")
PROJECT_STATUS_PATH = NAOS_ROOT / "PROJECT_STATUS.md"

# ── [ADAPT] Phase metadata for milestone gates ──────────────────────────
# Replace these with your project's actual phase names, target dates, and criteria.
# Add or remove phases as needed. Keys are integer phase numbers.
PHASE_META: Dict[int, Dict[str, str]] = {
    1: {
        "name": "Phase 1",
        "date": "TBD",
        "criteria": "Phase 1 acceptance criteria",
    },
    2: {
        "name": "Phase 2",
        "date": "TBD",
        "criteria": "Phase 2 acceptance criteria",
    },
    3: {
        "name": "Phase 3",
        "date": "TBD",
        "criteria": "Phase 3 acceptance criteria",
    },
    4: {
        "name": "Phase 4",
        "date": "TBD",
        "criteria": "Phase 4 acceptance criteria",
    },
    5: {
        "name": "Phase 5",
        "date": "TBD",
        "criteria": "Phase 5 acceptance criteria",
    },
}


@dataclass
class Task:
    id: str
    title: str
    requirement: str
    phase: int
    priority: str
    status: str
    estimate_days: float
    owner: str
    acceptance: str
    description: str
    progress_percent: Optional[int] = None
    lifecycle_state: Optional[str] = None
    delivery_state: Optional[str] = None
    verification_state: Optional[str] = None

    def state_record(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "lifecycle_state": self.lifecycle_state,
            "delivery_state": self.delivery_state,
            "verification_state": self.verification_state,
        }


def load_registry() -> Dict[str, Any]:
    """Load the canonical task registry."""
    if not REGISTRY_PATH.exists():
        print(f"❌ FATAL: {REGISTRY_PATH} not found!")
        sys.exit(2)

    with open(REGISTRY_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_tasks(registry: Dict) -> List[Task]:
    """Extract all tasks from registry."""
    tasks = []
    for t in registry.get("tasks", []):
        tasks.append(
            Task(
                id=t["id"],
                title=t["title"],
                requirement=t["requirement"],
                phase=t["phase"],
                priority=t["priority"],
                status=t["status"],
                estimate_days=t.get("estimate_days", 0),
                owner=t.get("owner", "Engineering"),
                acceptance=t.get("acceptance", ""),
                description=t.get("description", ""),
                progress_percent=t.get("progress_percent"),
                lifecycle_state=t.get("lifecycle_state"),
                delivery_state=t.get("delivery_state"),
                verification_state=t.get("verification_state"),
            )
        )
    return tasks


def filter_tasks_by_team(tasks: List[Task], team_id: str, registry: Dict) -> List[Task]:
    """Filter tasks to only those in scope for a specific team.

    Reads team_config from registry (if present). If team_id is not found or
    team_config.enabled is false, returns all tasks unchanged (zero blast radius).

    Requires in TASK_REGISTRY.yaml:
        team_config:
          enabled: true
          assignment_mode: task_scope   # or phase_scope or module_scope
          teams:
            - id: backend
              scope: [T-001, T-002, T-003]
    """
    team_config = require_valid_team_config(registry)
    if not team_config["enabled"]:
        print(
            f"ℹ️  team_config.enabled=false — returning all tasks (ignoring --team {team_id})"
        )
        return tasks

    teams = team_config["teams"]
    team = next((t for t in teams if t.get("id") == team_id), None)
    if team is None:
        print(f"⚠️  Team '{team_id}' not found in team_config — returning all tasks")
        return tasks

    scope = set(team.get("scope", []))
    if not scope:
        print(f"ℹ️  Team '{team_id}' has empty scope — returning all tasks")
        return tasks

    assignment_mode = team_config["assignment_mode"]
    if assignment_mode == "task_scope":
        filtered = [t for t in tasks if t.id in scope]
    elif assignment_mode == "phase_scope":
        # scope contains phase numbers as strings ("1", "2", etc.)
        phase_ints = {int(s) for s in scope if str(s).isdigit()}
        filtered = [t for t in tasks if t.phase in phase_ints]
    elif assignment_mode == "module_scope":
        # scope contains module/owner names
        filtered = [t for t in tasks if t.owner in scope]
    else:  # pragma: no cover - require_valid_team_config closes this state.
        raise TeamConfigValidationError(
            f"Invalid team_config: unsupported assignment_mode {assignment_mode!r}"
        )

    print(
        f"👥 Team filter: '{team_id}' → {len(filtered)} of {len(tasks)} tasks in scope"
    )
    return filtered


def get_metrics(registry: Dict) -> Dict[str, Any]:
    """Compute metrics dynamically from tasks list."""
    tasks = registry.get("tasks", [])

    tasks_done = sum(1 for task in tasks if is_task_delivered(task))
    total_tasks = len(tasks)
    percent_complete = (
        round((tasks_done / total_tasks * 100), 1) if total_tasks > 0 else 0
    )

    return {
        "completion_metrics": {
            "tasks_done": tasks_done,
            "tasks_total": total_tasks,
            "percent_complete": percent_complete,
        },
        "total_tasks": total_tasks,
        "tasks_total": total_tasks,
    }


def sync_backlog(tasks: List[Task], metrics: Dict) -> None:
    """Regenerate BACKLOG.md from registry."""
    print("📝 Syncing BACKLOG.md...")

    # Group tasks by status
    in_progress = [t for t in tasks if t.status == "in_progress"]
    ready = [t for t in tasks if t.status == "ready"]
    planned = [t for t in tasks if t.status == "planned"]

    def sort_key(t: Task):
        priority_order = {"P0": 0, "P1": 1, "P2": 2}
        return (priority_order.get(t.priority, 9), t.id)

    in_progress.sort(key=sort_key)
    ready.sort(key=sort_key)
    planned.sort(key=sort_key)

    content = f"""<!-- ⚠️ AUTO-GENERATED FILE — DO NOT EDIT MANUALLY. Regenerate with: make -f Makefile.naos gov-refresh -->

# Project Backlog

**Auto-generated from**: `{REGISTRY_PATH}`
**Last Sync**: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M")}
**DO NOT EDIT MANUALLY** - Edit TASK_REGISTRY.yaml and run `sync_from_registry.py`

---

## 📊 Summary

| Status | Count |
|--------|-------|
| 🔵 In Progress | {len(in_progress)} |
| 🟢 Ready | {len(ready)} |
| ⚪ Planned | {len(planned)} |
| **Total Active** | **{len(in_progress) + len(ready) + len(planned)}** |

---

## 🔵 In Progress

| ID | Title | Requirement | Priority | Est (days) | Progress |
|----|-------|-------------|----------|------------|----------|
"""

    for t in in_progress:
        progress = f"{t.progress_percent}%" if t.progress_percent else "—"
        content += f"| **{t.id}** | {t.title} | {t.requirement} | {t.priority} | {t.estimate_days} | {progress} |\n"

    content += """
---

## 🟢 Ready (Next Up)

| ID | Title | Requirement | Priority | Est (days) |
|----|-------|-------------|----------|------------|
"""

    for t in ready:
        content += f"| **{t.id}** | {t.title} | {t.requirement} | {t.priority} | {t.estimate_days} |\n"

    content += """
---

## ⚪ Planned (Backlog)

| ID | Title | Requirement | Priority | Est (days) |
|----|-------|-------------|----------|------------|
"""

    for t in planned:
        content += f"| **{t.id}** | {t.title} | {t.requirement} | {t.priority} | {t.estimate_days} |\n"

    content += """
---

## 🔗 References

- **Authoritative Source**: `naos/TASK_REGISTRY.yaml`
- **Requirement Definitions**: `specs/03-requirements.md`
- **Task Details**: `specs/10-execution.md`

---

*This file is auto-generated. To update:*
```bash
python scripts/workflows/sync_from_registry.py --backlog
```
"""

    cleaned = "\n".join(line.rstrip() for line in content.splitlines()) + "\n"
    BACKLOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    BACKLOG_PATH.write_text(cleaned, encoding="utf-8")
    print(
        f"   ✅ Written {len(in_progress) + len(ready) + len(planned)} tasks to BACKLOG.md"
    )


def sync_execution_task_matrix(tasks: List[Task]) -> None:
    """Update Task Matrix section in specs/10-execution.md."""
    print("📐 Syncing specs/10-execution.md Task Matrix...")

    if not EXECUTION_PATH.exists():
        print("   ⚠️ specs/10-execution.md not found, skipping")
        return

    text = EXECUTION_PATH.read_text(encoding="utf-8")

    start_marker = "<!-- BEGIN TASK_MATRIX -->"
    end_marker = "<!-- END TASK_MATRIX -->"

    start_idx = text.find(start_marker)
    end_idx = text.find(end_marker)

    if start_idx == -1 or end_idx == -1:
        print("   ⚠️ Task Matrix markers not found in 10-execution.md")
        return

    sorted_tasks = sorted(tasks, key=lambda t: (t.phase, t.id))

    matrix = f"""{start_marker}
| ID | Title | Phase | Type | FR/NFR | Status | Owner | Target End | Acceptance |
|----|-------|------:|------|--------|--------|-------|------------|------------|
"""

    for t in sorted_tasks:
        task_type = "nfr" if t.requirement.startswith("NFR") else "feature"
        status_display = t.status.replace("_", " ").title()
        if status_display in ("Implemented", "Verified"):
            status_display = "Done"

        meta = PHASE_META.get(int(t.phase), {"date": "TBD"})
        target_end = meta.get("date", "TBD")

        matrix += f"| {t.id} | {t.title} | {t.phase} | {task_type} | {t.requirement} | {status_display} | {t.owner[:3]} | {target_end} | {t.acceptance} |\n"

    matrix += f"{end_marker}"

    new_text = text[:start_idx] + matrix + text[end_idx + len(end_marker) :]

    EXECUTION_PATH.write_text(new_text, encoding="utf-8")
    print(f"   ✅ Updated Task Matrix with {len(tasks)} tasks")


def sync_dashboard_metrics(tasks: List[Task], metrics: Dict) -> None:
    """Update key metrics in DASHBOARD.md."""
    print("📊 Syncing DASHBOARD.md metrics...")

    if not DASHBOARD_PATH.exists():
        print("   ⚠️ DASHBOARD.md not found, skipping")
        return

    text = DASHBOARD_PATH.read_text(encoding="utf-8")

    completion = metrics.get("completion_metrics", {})
    tasks_done = completion.get("tasks_done", 0)
    tasks_total = completion.get("tasks_total", 0)
    percent = completion.get("percent_complete", 0)

    text = re.sub(
        r"(\d+)\s*/\s*(\d+)\s*tasks",
        f"{tasks_done}/{tasks_total} tasks",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"(\d+/\d+ tasks)\s*\(\d+(?:\.\d+)?%\)",
        rf"\1 ({percent}%)",
        text,
    )

    text = re.sub(
        r"Task Completion[:\s]*\d+(?:\.\d+)?\s*%",
        f"Task Completion: {percent}%",
        text,
        flags=re.IGNORECASE,
    )

    DASHBOARD_PATH.write_text(text, encoding="utf-8")
    print(f"   ✅ Updated metrics: {tasks_done}/{tasks_total} ({percent}%)")


def _replace_between_markers(
    text: str, begin_tag: str, end_tag: str, new_content: str
) -> str:
    """Replace content between <!-- BEGIN tag --> and <!-- END tag --> markers."""
    begin = f"<!-- BEGIN {begin_tag} -->"
    end = f"<!-- END {end_tag} -->"
    start_idx = text.find(begin)
    end_idx = text.find(end)
    if start_idx == -1 or end_idx == -1:
        print(f"   ⚠️ Markers {begin_tag} not found, skipping")
        return text
    return (
        text[:start_idx]
        + begin
        + "\n"
        + new_content
        + "\n"
        + end
        + text[end_idx + len(end) :]
    )


def _phase_key(phase) -> float:
    """Convert phase to a sortable float (e.g. '8.5' -> 8.5, 8 -> 8.0)."""
    try:
        return float(phase)
    except (TypeError, ValueError):
        return 99.0


def _phase_status(tasks_in_phase: List[Task]) -> str:
    """Determine phase status from its tasks."""
    states = [normalize_task_states(task.state_record()) for task in tasks_in_phase]
    if any(state.get("compatibility_status") == "unsupported" for state in states):
        return "⚠️ REVIEW REQUIRED"
    if states and all(
        state["lifecycle_state"] in {"deferred", "cancelled", "absorbed", "superseded"}
        for state in states
    ):
        return "⏭️ SKIPPED"
    if tasks_in_phase and all(is_task_delivered(task.state_record()) for task in tasks_in_phase):
        return "✅ DONE"
    if any(state["lifecycle_state"] == "active" for state in states):
        return "🔵 IN PROGRESS"
    if any(is_task_delivered(task.state_record()) for task in tasks_in_phase) or any(
        state["lifecycle_state"] == "implementation_complete" for state in states
    ):
        return "🟡 PARTIAL"
    return "⚪ PLANNED"


def _group_tasks_by_major_phase(tasks: List[Task]) -> Dict[int, List[Task]]:
    """Group tasks by major phase number (int part of phase)."""
    groups: Dict[int, List[Task]] = defaultdict(list)
    for t in tasks:
        major = int(_phase_key(t.phase))
        groups[major].append(t)
    return groups


def _requirement_status(requirement_tasks: List[Task]) -> str:
    """Determine requirement status from canonical task states."""
    states = [normalize_task_states(task.state_record()) for task in requirement_tasks]
    if any(state.get("compatibility_status") == "unsupported" for state in states):
        return "⚠️ REVIEW REQUIRED"
    if states and all(
        state["lifecycle_state"] in {"deferred", "cancelled", "absorbed", "superseded"}
        for state in states
    ):
        return "⏭️ DEFERRED"
    if requirement_tasks and all(is_task_delivered(task.state_record()) for task in requirement_tasks):
        return "✅ DONE"
    if any(state["lifecycle_state"] == "active" for state in states):
        return "🔵 IN PROGRESS"
    if any(is_task_delivered(task.state_record()) for task in requirement_tasks) or any(
        state["lifecycle_state"] == "implementation_complete" for state in states
    ):
        return "🟡 PARTIAL"
    return "⚪ PLANNED"


def sync_project_status(tasks: List[Task], metrics: Dict) -> None:
    """Update stale sections in PROJECT_STATUS.md using marker-based replacement.

    Only sections between <!-- BEGIN SYNC_xxx --> and <!-- END SYNC_xxx -->
    markers are touched. Manual journal sections are preserved.
    """
    print("📄 Syncing PROJECT_STATUS.md (stale sections only)...")

    if not PROJECT_STATUS_PATH.exists():
        print("   ⚠️ PROJECT_STATUS.md not found, skipping")
        return

    text = PROJECT_STATUS_PATH.read_text(encoding="utf-8")
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")

    completion = metrics.get("completion_metrics", {})
    tasks_done = completion.get("tasks_done", 0)
    tasks_total = completion.get("tasks_total", 0)
    percent = completion.get("percent_complete", 0)

    # --- 1. Executive Summary Metrics ---
    req_tasks: Dict[str, List[Task]] = defaultdict(list)
    for t in tasks:
        req_key = t.requirement.split(" (")[0].split(",")[0].strip()
        req_tasks[req_key].append(t)

    reqs_total = len(req_tasks)
    reqs_done = sum(
        1
        for statuses in req_tasks.values()
        if _requirement_status(statuses) == "✅ DONE"
    )
    reqs_pct = round(reqs_done / reqs_total * 100, 1) if reqs_total else 0

    planned_count = sum(1 for t in tasks if t.status.lower() in ("planned", "ready"))

    exec_metrics = f"""**Phase Status**: 🚀 IMPLEMENTATION PHASE
**Overall Progress**: {reqs_done}/{reqs_total} requirements delivered ({reqs_pct}%) - from TASK_REGISTRY.yaml
**Task Progress**: {tasks_done}/{tasks_total} tasks implemented ({percent}%)
**Schedule Health**: {"🟢 ON TRACK" if planned_count < tasks_total * 0.3 else "🟡 AT RISK"}
**Auto-synced**: {now} (from TASK_REGISTRY.yaml)"""

    text = _replace_between_markers(
        text, "SYNC_EXEC_METRICS", "SYNC_EXEC_METRICS", exec_metrics
    )
    print("   ✅ Executive Summary metrics updated")

    # --- 2. Milestone Gates ---
    phase_groups = _group_tasks_by_major_phase(tasks)

    gate_lines = [
        "## 🎯 Milestone Gates",
        "",
        f"**Auto-synced**: {now}",
        "",
        "| Phase | Name | Target Date | Tasks | Done | Status |",
        "|------:|------|-------------|------:|-----:|--------|",
    ]
    for major_phase in sorted(phase_groups.keys()):
        meta = PHASE_META.get(
            major_phase,
            {"name": f"Phase {major_phase}", "date": "TBD", "criteria": "TBD"},
        )
        phase_tasks = phase_groups[major_phase]
        done_ct = sum(1 for t in phase_tasks if is_task_delivered(t.state_record()))
        total_ct = len(phase_tasks)
        status = _phase_status(phase_tasks)
        gate_lines.append(
            f"| {major_phase} | {meta['name']} | {meta['date']} | {total_ct} | {done_ct} | {status} |"
        )

    text = _replace_between_markers(
        text, "SYNC_MILESTONE_GATES", "SYNC_MILESTONE_GATES", "\n".join(gate_lines)
    )
    print(f"   ✅ Milestone Gates updated ({len(phase_groups)} phases)")

    # --- 3. Work Breakdown (by Requirement) ---
    wb_lines = [
        "## 📋 Work Breakdown (by Requirement)",
        "",
        f"**Auto-synced**: {now} (from TASK_REGISTRY.yaml)",
        "",
        "| Requirement | Tasks | Done | Status | Sample Tasks |",
        "|-------------|------:|-----:|--------|-------------|",
    ]

    for req_id in sorted(req_tasks.keys()):
        statuses = req_tasks[req_id]
        total = len(statuses)
        done = sum(1 for task in statuses if is_task_delivered(task.state_record()))
        status = _requirement_status(statuses)
        sample_ids = [
            t.id
            for t in tasks
            if t.requirement.split(" (")[0].split(",")[0].strip() == req_id
        ][:3]
        sample = ", ".join(sample_ids)
        wb_lines.append(f"| {req_id} | {total} | {done} | {status} | {sample} |")

    wb_lines.append("")
    wb_lines.append(
        f"**TOTAL**: {reqs_total} requirements, {tasks_total} tasks, {tasks_done} done ({percent}%)"
    )

    text = _replace_between_markers(
        text, "SYNC_WORK_BREAKDOWN", "SYNC_WORK_BREAKDOWN", "\n".join(wb_lines)
    )
    print(f"   ✅ Work Breakdown updated ({reqs_total} requirements)")

    # --- 4. Metrics Summary ---
    fr_reqs = {r: s for r, s in req_tasks.items() if r.startswith("FR")}
    nfr_reqs = {r: s for r, s in req_tasks.items() if r.startswith("NFR")}
    fr_done = sum(
        1
        for s in fr_reqs.values()
        if _requirement_status(s) == "✅ DONE"
    )
    nfr_done = sum(
        1
        for s in nfr_reqs.values()
        if _requirement_status(s) == "✅ DONE"
    )
    fr_progress = sum(
        1 for s in fr_reqs.values() if _requirement_status(s) == "🔵 IN PROGRESS"
    )
    nfr_progress = sum(
        1 for s in nfr_reqs.values() if _requirement_status(s) == "🔵 IN PROGRESS"
    )
    fr_planned = len(fr_reqs) - fr_done - fr_progress
    nfr_planned = len(nfr_reqs) - nfr_done - nfr_progress

    total_est_hours = sum(t.estimate_days * 8 for t in tasks)
    done_est_hours = sum(
        t.estimate_days * 8 for t in tasks if is_task_delivered(t.state_record())
    )
    remaining_hours = total_est_hours - done_est_hours

    metrics_lines = [
        "## 📈 Metrics Summary",
        "",
        f"**Auto-synced**: {now}",
        "",
        "### Overall Progress",
        "",
        "| Metric | Value | Target | Health |",
        "|--------|-------|--------|--------|",
        f"| **Requirements Delivered** | {reqs_done}/{reqs_total} ({reqs_pct}%) | 100% | {'🟢 ON TRACK' if reqs_pct > 70 else '🟡 AT RISK'} |",
        f"| **Tasks Implemented** | {tasks_done}/{tasks_total} ({percent}%) | 100% | {'🟢 ON TRACK' if percent > 70 else '🟡 AT RISK'} |",
    ]

    for major_phase in sorted(phase_groups.keys()):
        pts = phase_groups[major_phase]
        done_ct = sum(1 for t in pts if is_task_delivered(t.state_record()))
        if done_ct < len(pts):
            pct = round(done_ct / len(pts) * 100) if pts else 0
            meta = PHASE_META.get(major_phase, {"name": f"Phase {major_phase}"})
            metrics_lines.append(
                f"| **Phase {major_phase} ({meta['name']})** | {done_ct}/{len(pts)} ({pct}%) | 100% | {'🟢' if pct > 80 else '🟡' if pct > 50 else '🔴'} |"
            )

    metrics_lines.extend(
        [
            "",
            "### Requirements Coverage",
            "",
            "| Type | Total | Done | In Progress | Planned | % Complete |",
            "|------|------:|-----:|------------:|--------:|-----------:|",
            f"| **FR** | {len(fr_reqs)} | {fr_done} | {fr_progress} | {fr_planned} | {round(fr_done / len(fr_reqs) * 100, 1) if fr_reqs else 0}% |",
            f"| **NFR** | {len(nfr_reqs)} | {nfr_done} | {nfr_progress} | {nfr_planned} | {round(nfr_done / len(nfr_reqs) * 100, 1) if nfr_reqs else 0}% |",
            f"| **All** | {reqs_total} | {reqs_done} | {fr_progress + nfr_progress} | {fr_planned + nfr_planned} | {reqs_pct}% |",
            "",
            "### Velocity & Burndown",
            "",
            "| Metric | Estimate | Done | Remaining |",
            "|--------|----------|------|-----------|",
            f"| **Hours (total)** | {total_est_hours:.0f}h | {done_est_hours:.0f}h | {remaining_hours:.0f}h |",
            f"| **Tasks** | {tasks_total} | {tasks_done} | {tasks_total - tasks_done} |",
            f"| **Requirements** | {reqs_total} | {reqs_done} | {reqs_total - reqs_done} |",
        ]
    )

    text = _replace_between_markers(
        text, "SYNC_METRICS_SUMMARY", "SYNC_METRICS_SUMMARY", "\n".join(metrics_lines)
    )
    print("   ✅ Metrics Summary updated")

    # --- 5. Budget Summary ---
    budget_total_days = sum(t.estimate_days for t in tasks)
    budget_total_hours = budget_total_days * 8
    budget_done_hours = sum(
        t.estimate_days * 8 for t in tasks if is_task_delivered(t.state_record())
    )

    budget_lines = [
        "## 💰 Budget Summary (All Phases)",
        "",
        f"**Auto-synced**: {now}",
        f"**Total Estimate**: {budget_total_hours:.0f} hours ({budget_total_days:.0f} days) across {tasks_total} tasks",
        f"**Completed**: {budget_done_hours:.0f}h ({round(budget_done_hours / budget_total_hours * 100, 1) if budget_total_hours else 0}%)",
        f"**Remaining**: {budget_total_hours - budget_done_hours:.0f}h",
        "",
        "### Budget by Phase",
        "",
        "| Phase | Name | Tasks | Est (hours) | Done (hours) | Remaining |",
        "|------:|------|------:|------------:|-------------:|----------:|",
    ]

    for major_phase in sorted(phase_groups.keys()):
        meta = PHASE_META.get(major_phase, {"name": f"Phase {major_phase}"})
        pts = phase_groups[major_phase]
        est = sum(t.estimate_days * 8 for t in pts)
        done_h = sum(
            t.estimate_days * 8 for t in pts if is_task_delivered(t.state_record())
        )
        budget_lines.append(
            f"| {major_phase} | {meta['name']} | {len(pts)} | {est:.0f}h | {done_h:.0f}h | {est - done_h:.0f}h |"
        )

    budget_lines.extend(
        [
            f"| **TOTAL** | | **{tasks_total}** | **{budget_total_hours:.0f}h** | **{budget_done_hours:.0f}h** | **{budget_total_hours - budget_done_hours:.0f}h** |",
            "",
            "### Planned Tasks by Priority",
            "",
            "| Priority | Planned | Ready | In Progress | Total Pending |",
            "|----------|--------:|------:|------------:|--------------:|",
        ]
    )

    for prio in ["P0", "P1", "P2"]:
        p_tasks = [
            t
            for t in tasks
            if t.priority == prio
            and not is_task_delivered(t.state_record())
            and t.status.lower() not in ("deferred", "absorbed")
        ]
        planned_p = sum(1 for t in p_tasks if t.status.lower() == "planned")
        ready_p = sum(1 for t in p_tasks if t.status.lower() == "ready")
        ip_p = sum(1 for t in p_tasks if t.status.lower() == "in_progress")
        if p_tasks:
            budget_lines.append(
                f"| {prio} | {planned_p} | {ready_p} | {ip_p} | {len(p_tasks)} |"
            )

    text = _replace_between_markers(
        text, "SYNC_BUDGET", "SYNC_BUDGET", "\n".join(budget_lines)
    )
    print("   ✅ Budget updated")

    # --- Write file ---
    cleaned = "\n".join(line.rstrip() for line in text.splitlines()) + "\n"
    PROJECT_STATUS_PATH.write_text(cleaned, encoding="utf-8")
    print(f"   ✅ PROJECT_STATUS.md written ({len(cleaned)} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync all PM files from TASK_REGISTRY.yaml"
    )
    parser.add_argument("--backlog", action="store_true", help="Sync only BACKLOG.md")
    parser.add_argument(
        "--dashboard", action="store_true", help="Sync only DASHBOARD.md"
    )
    parser.add_argument(
        "--execution", action="store_true", help="Sync only specs/10-execution.md"
    )
    parser.add_argument(
        "--project-status",
        action="store_true",
        help="Sync only PROJECT_STATUS.md stale sections",
    )
    parser.add_argument(
        "--team",
        metavar="TEAM_ID",
        default=None,
        help=(
            "Filter output to tasks in scope for a specific team "
            "(requires team_config.enabled=true in TASK_REGISTRY.yaml). "
            "Example: --team backend"
        ),
    )
    args = parser.parse_args()

    sync_all = not (
        args.backlog or args.dashboard or args.execution or args.project_status
    )

    print("=" * 60)
    print("🔄 SYNC FROM REGISTRY")
    print("=" * 60)
    print(f"   Source: {REGISTRY_PATH}")
    if args.team:
        print(f"   Team filter: {args.team}")
    print("=" * 60)

    registry = load_registry()
    try:
        validate_task_artifact_identity(Path.cwd(), str(NAOS_ROOT), registry)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    tasks = get_tasks(registry)
    metrics = get_metrics(registry)

    print(f"\n📋 Loaded {len(tasks)} tasks from registry\n")

    # Apply team filter if requested (zero blast radius — loads flat list first)
    if args.team:
        try:
            tasks = filter_tasks_by_team(tasks, args.team, registry)
        except TeamConfigValidationError as exc:
            print(f"❌ {exc}", file=sys.stderr)
            sys.exit(2)

    if sync_all or args.backlog:
        sync_backlog(tasks, metrics)

    if sync_all or args.execution:
        sync_execution_task_matrix(tasks)

    if sync_all or args.dashboard:
        sync_dashboard_metrics(tasks, metrics)

    if sync_all or args.project_status:
        sync_project_status(tasks, metrics)

    print("\n" + "=" * 60)
    print("✅ SYNC COMPLETE")
    print("=" * 60)
    print("\nNext: Run validators to confirm coherence:")
    print("  python scripts/workflows/validate_task_coherence.py")


if __name__ == "__main__":
    main()
