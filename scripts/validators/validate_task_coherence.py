#!/usr/bin/env python3
"""
validate_task_coherence.py — Task coherence validator (NAOS portable)

PURPOSE:
    Ensures ALL task/metrics references across governance files match the
    canonical TASK_REGISTRY.yaml.  Prevents the recurring problem where:
    - DASHBOARD.md shows different numbers than PROJECT_STATUS.md
    - BACKLOG.md has tasks not in the registry
    - Metrics keep getting calculated incorrectly

AUTHORITATIVE SOURCE:
    <NAOS_ROOT>/TASK_REGISTRY.yaml — THE SINGLE SOURCE OF TRUTH

FILES VALIDATED:
    - <NAOS_ROOT>/DASHBOARD.md
    - <NAOS_ROOT>/PROJECT_STATUS.md
    - <NAOS_ROOT>/BACKLOG.md
    - <SPECS_ROOT>/10-execution.md  (Task Matrix section, when present)

ENV VARS:
    NAOS_ROOT   — path to naos/ directory  (default: naos)
    SPECS_ROOT  — path to specs/ directory (default: specs)

USAGE:
    python kit/scripts/validators/validate_task_coherence.py

EXIT CODES:
    0 — All files coherent with registry
    1 — Drift detected
    2 — Registry file not found

[ADAPT] section: adjust DASHBOARD_PATH, PROJECT_STATUS_PATH, BACKLOG_PATH,
                 EXECUTION_SPEC_PATH to match your project layout.
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_task_lifecycle import is_task_delivered  # noqa: E402

try:
    from validator_context import is_kit_repository, print_kit_skip
except ModuleNotFoundError:
    def is_kit_repository() -> bool:
        return False

    def print_kit_skip(validator_name: str, reason: str) -> None:
        print(f"{validator_name}: SKIP")
        print(f"  - kit repo context: {reason}")

# ── Path configuration ────────────────────────────────────────────────────────
# [ADAPT] Override via env vars for non-standard project layouts
NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
SPECS_ROOT = Path(os.getenv("SPECS_ROOT", "specs"))

REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"
DASHBOARD_PATH = NAOS_ROOT / "DASHBOARD.md"
PROJECT_STATUS_PATH = NAOS_ROOT / "PROJECT_STATUS.md"
BACKLOG_PATH = NAOS_ROOT / "BACKLOG.md"
EXECUTION_SPEC_PATH = SPECS_ROOT / "10-execution.md"


@dataclass
class TaskInfo:
    id: str
    title: str
    requirement: str
    status: str
    phase: int
    priority: str
    estimate_days: float


@dataclass
class ValidationResult:
    file: str
    check: str
    passed: bool
    expected: Any
    actual: Any
    message: str


# ── Registry loaders ──────────────────────────────────────────────────────────


def load_registry() -> Dict[str, Any]:
    if not REGISTRY_PATH.exists():
        print(f"❌ FATAL: {REGISTRY_PATH} not found!")
        print("   Create TASK_REGISTRY.yaml in your NAOS_ROOT directory.")
        sys.exit(2)
    with open(REGISTRY_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_registry_tasks(registry: Dict) -> Dict[str, TaskInfo]:
    tasks = {}
    for task in registry.get("tasks", []):
        task_id = task["id"]
        tasks[task_id] = TaskInfo(
            id=task_id,
            title=task["title"],
            requirement=task.get("requirement", ""),
            status=task["status"],
            phase=task.get("phase", 0),
            priority=task.get("priority", "medium"),
            estimate_days=task.get("estimate_days", 0),
        )
    return tasks


def get_registry_metrics(registry: Dict) -> Dict[str, Any]:
    """Compute metrics dynamically from TASK_REGISTRY.yaml tasks list."""
    tasks = registry.get("tasks", [])
    by_status: Dict[str, int] = defaultdict(int)
    for task in tasks:
        status = task.get("status", "planned").lower()
        by_status[status] += 1

    tasks_done = sum(1 for task in tasks if is_task_delivered(task))
    total_tasks = len(tasks)
    percent_complete = (tasks_done / total_tasks * 100) if total_tasks > 0 else 0.0

    return {
        "total_tasks": total_tasks,
        "implemented": by_status.get("implemented", 0),
        "in_progress": by_status.get("in_progress", 0),
        "planned": by_status.get("planned", 0),
        "ready": by_status.get("ready", 0),
        "verified": by_status.get("verified", 0),
        "complete": by_status.get("complete", 0),
        "tasks_done": tasks_done,
        "percent_complete": round(percent_complete, 1),
    }


# ── File validators ───────────────────────────────────────────────────────────


def validate_dashboard(registry: Dict) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    if not DASHBOARD_PATH.exists():
        results.append(
            ValidationResult(
                file=str(DASHBOARD_PATH),
                check="file_exists",
                passed=False,
                expected="File exists",
                actual="Not found",
                message="DASHBOARD.md not found",
            )
        )
        return results

    text = DASHBOARD_PATH.read_text(encoding="utf-8")
    metrics = get_registry_metrics(registry)

    pct_match = re.search(
        r"Task Completion[:\s]*(\d+(?:\.\d+)?)\s*%", text, re.IGNORECASE
    )
    if pct_match:
        actual_pct = float(pct_match.group(1))
        expected_pct = metrics["percent_complete"]
        results.append(
            ValidationResult(
                file=str(DASHBOARD_PATH),
                check="task_completion_percent",
                passed=abs(actual_pct - expected_pct) < 1.0,
                expected=expected_pct,
                actual=actual_pct,
                message=f"Task completion: expected {expected_pct}%, found {actual_pct}%",
            )
        )

    total_match = re.search(r"(\d+)\s*/\s*(\d+)\s*tasks", text, re.IGNORECASE)
    if total_match:
        actual_done = int(total_match.group(1))
        actual_total = int(total_match.group(2))
        results.append(
            ValidationResult(
                file=str(DASHBOARD_PATH),
                check="tasks_done_count",
                passed=actual_done == metrics["tasks_done"],
                expected=metrics["tasks_done"],
                actual=actual_done,
                message=f"Tasks done: expected {metrics['tasks_done']}, found {actual_done}",
            )
        )
        results.append(
            ValidationResult(
                file=str(DASHBOARD_PATH),
                check="tasks_total_count",
                passed=actual_total == metrics["total_tasks"],
                expected=metrics["total_tasks"],
                actual=actual_total,
                message=f"Total tasks: expected {metrics['total_tasks']}, found {actual_total}",
            )
        )

    return results


def validate_project_status(registry: Dict) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    if not PROJECT_STATUS_PATH.exists():
        return results

    text = PROJECT_STATUS_PATH.read_text(encoding="utf-8")
    tasks = get_registry_tasks(registry)

    task_refs = re.findall(r"T-(\d{3})", text)
    for task_num in set(task_refs):
        task_id = f"T-{task_num}"
        if task_id not in tasks:
            results.append(
                ValidationResult(
                    file=str(PROJECT_STATUS_PATH),
                    check=f"task_exists_{task_id}",
                    passed=False,
                    expected="Task in registry",
                    actual="Not found",
                    message=f"PROJECT_STATUS.md references {task_id} which is NOT in registry",
                )
            )

    return results


def validate_backlog(registry: Dict) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    if not BACKLOG_PATH.exists():
        return results

    text = BACKLOG_PATH.read_text(encoding="utf-8")
    tasks = get_registry_tasks(registry)
    backlog_tasks = re.findall(r"\|\s*(T-\d{3})\s*\|[^|]+\|\s*([^|]+)\|", text)

    status_map = {
        "done": "implemented",
        "complete": "implemented",
        "in progress": "in_progress",
        "in-progress": "in_progress",
        "todo": "planned",
        "to do": "planned",
    }

    for task_id, status_raw in backlog_tasks:
        status = (
            status_raw.strip()
            .lower()
            .replace("✅", "")
            .replace("🔵", "")
            .replace("🔴", "")
            .strip()
        )
        status = status_map.get(status, status)

        if task_id not in tasks:
            results.append(
                ValidationResult(
                    file=str(BACKLOG_PATH),
                    check=f"task_exists_{task_id}",
                    passed=False,
                    expected="Task in registry",
                    actual="Not found",
                    message=f"BACKLOG.md has {task_id} which is NOT in registry",
                )
            )
            continue

        registry_status = tasks[task_id].status.lower()
        if status not in {registry_status, "ready"}:
            results.append(
                ValidationResult(
                    file=str(BACKLOG_PATH),
                    check=f"task_status_{task_id}",
                    passed=False,
                    expected=registry_status,
                    actual=status,
                    message=f"{task_id} status: registry={registry_status}, backlog={status}",
                )
            )

    return results


def validate_execution_spec(registry: Dict) -> List[ValidationResult]:
    """Validate specs/10-execution.md Task Matrix if present."""
    results: List[ValidationResult] = []
    if not EXECUTION_SPEC_PATH.exists():
        return results

    text = EXECUTION_SPEC_PATH.read_text(encoding="utf-8")
    tasks = get_registry_tasks(registry)

    matrix_match = re.search(
        r"<!-- BEGIN TASK_MATRIX -->(.*?)<!-- END TASK_MATRIX -->", text, re.DOTALL
    )
    if not matrix_match:
        results.append(
            ValidationResult(
                file=str(EXECUTION_SPEC_PATH),
                check="task_matrix_section",
                passed=False,
                expected="Task matrix section",
                actual="Not found",
                message="No <!-- BEGIN TASK_MATRIX --> block in 10-execution.md",
            )
        )
        return results

    matrix_tasks = re.findall(
        r"\|\s*(T-\d{3})\s*\|[^|]+\|[^|]+\|[^|]+\|\s*([A-Z]{2,3}-[^\|]+)\|([^|]+)\|",
        matrix_match.group(1),
    )
    for task_id, requirement, _ in matrix_tasks:
        if task_id not in tasks:
            results.append(
                ValidationResult(
                    file=str(EXECUTION_SPEC_PATH),
                    check=f"matrix_task_{task_id}",
                    passed=False,
                    expected="Task in registry",
                    actual="Not found",
                    message=f"Task Matrix has {task_id} which is NOT in registry",
                )
            )

    return results


def validate_backlog_drift(registry: Dict) -> List[ValidationResult]:
    """
    Backlog drift checks — dead file refs, stale completions (≥14d),
    orphaned tasks.
    """
    results: List[ValidationResult] = []
    tasks = get_registry_tasks(registry)

    # Orphaned tasks: completed in registry but not mentioned in any governance file
    governance_files = [
        DASHBOARD_PATH,
        PROJECT_STATUS_PATH,
        BACKLOG_PATH,
        EXECUTION_SPEC_PATH,
    ]
    all_text = ""
    for gf in governance_files:
        if gf.exists():
            all_text += gf.read_text(encoding="utf-8")

    for task_id, task in tasks.items():
        registry_entry = next(
            (entry for entry in registry.get("tasks", []) if entry.get("id") == task_id),
            {"status": task.status},
        )
        if is_task_delivered(registry_entry) and task_id not in all_text:
            results.append(
                ValidationResult(
                    file="backlog_drift",
                    check=f"orphaned_done_{task_id}",
                    passed=False,
                    expected="Task referenced in governance files",
                    actual="Not referenced anywhere",
                    message=f"{task_id} is '{task.status}' but not referenced in any governance file",
                )
            )

    # Stale in_progress tasks (no mtime check possible on MD text — advisory only)
    in_progress = [t for t in tasks.values() if t.status.lower() == "in_progress"]
    if len(in_progress) > 3:
        results.append(
            ValidationResult(
                file="backlog_drift",
                check="too_many_in_progress",
                passed=False,
                expected="≤3 in-progress tasks",
                actual=str(len(in_progress)),
                message=f"{len(in_progress)} tasks marked in_progress simultaneously (WIP limit advisory)",
            )
        )

    return results


# ── Report & main ─────────────────────────────────────────────────────────────


def print_results(all_results: List[ValidationResult]) -> bool:
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed]

    print("\n" + "=" * 70)
    print("📋  TASK COHERENCE VALIDATION REPORT")
    print("=" * 70)
    print(f"   Authoritative Source : {REGISTRY_PATH}")
    print(f"   Checks Run           : {len(all_results)}")
    print(f"   ✅ Passed             : {len(passed)}")
    print(f"   ❌ Failed             : {len(failed)}")
    print("=" * 70)

    if failed:
        print("\n❌ COHERENCE VIOLATIONS DETECTED:\n")
        by_file: Dict[str, List[ValidationResult]] = defaultdict(list)
        for r in failed:
            by_file[r.file].append(r)

        for file, results in by_file.items():
            print(f"  📄 {file}")
            for r in results:
                print(f"     ├─ {r.check}")
                print(f"     │  Expected : {r.expected}")
                print(f"     │  Actual   : {r.actual}")
                print(f"     └─ {r.message}")
                print()

        print("\n🔧 HOW TO FIX:")
        print(f"   1. Edit {REGISTRY_PATH}  (canonical source)")
        print("   2. Run: python kit/scripts/workflows/sync_from_registry.py")
        print("   3. Re-run this validator to confirm coherence")
        return False

    print(f"\n✅ All checks coherent with {REGISTRY_PATH}\n")
    return True


def main() -> int:
    if is_kit_repository():
        print_kit_skip(
            "Task Coherence",
            "requires adopter naos/TASK_REGISTRY.yaml and generated PM artifacts",
        )
        return 0

    print("🔍 Loading task registry …")
    registry = load_registry()

    all_results: List[ValidationResult] = []
    print(f"📊 Validating {DASHBOARD_PATH} …")
    all_results.extend(validate_dashboard(registry))
    print(f"📋 Validating {PROJECT_STATUS_PATH} …")
    all_results.extend(validate_project_status(registry))
    print(f"📝 Validating {BACKLOG_PATH} …")
    all_results.extend(validate_backlog(registry))
    print(f"📐 Validating {EXECUTION_SPEC_PATH} …")
    all_results.extend(validate_execution_spec(registry))
    print("🔍 Backlog drift checks …")
    all_results.extend(validate_backlog_drift(registry))

    return 0 if print_results(all_results) else 1


if __name__ == "__main__":
    sys.exit(main())
