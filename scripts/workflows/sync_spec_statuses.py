#!/usr/bin/env python3
"""
sync_spec_statuses.py - Cascade task statuses from TASK_REGISTRY into spec files.

PURPOSE:
    Derives requirement-level statuses from TASK_REGISTRY.yaml task statuses
    and updates the ``**Status**:`` lines in specs/03-requirements.md and the
    task tables in specs/10-execution.md (sections outside the marker-synced
    Task Matrix).

DATA FLOW:
    TASK_REGISTRY.yaml  (authoritative task statuses)
        ↓  aggregate per requirement
    specs/03-requirements.md  ``**Status**:`` lines  (derived requirement status)
    specs/10-execution.md     §4.1 summary table + §5 traceability matrix

DERIVATION RULES:
    For each requirement R, collect every task T where T.requirement == R:
    - ALL tasks completed + delivered + verified → R = "Implemented"/"Verified"
    - Legacy implemented means implementation-complete, not delivered
    - Absorbed/deferred/cancelled/superseded tasks are not delivered
    - ANY task in_progress                        → R = "In Progress"
    - ALL tasks planned                           → R = "Planned"
    - ALL tasks deferred                          → R = "Deferred"
    - Mixed planned + done (none in_progress)     → R = "In Progress"
    - No tasks found                              → R unchanged (keep manual)

PRESERVES:
    - ✅ **COMPLETE** annotations with dates — never downgraded
    - Verified status on NFRs — never downgraded
    - Manual/architectural statuses in specs 04/05/06

USAGE:
    python scripts/workflows/sync_spec_statuses.py
    python scripts/workflows/sync_spec_statuses.py --dry-run
    python scripts/workflows/sync_spec_statuses.py --requirements-only
    python scripts/workflows/sync_spec_statuses.py --execution-only

ENVIRONMENT:
    NAOS_ROOT  — path to the naos/ governance folder (default: "naos")
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

# Shared requirement-header parser (single source of truth across cascade scripts)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spec_header  # noqa: E402
from naos_task_lifecycle import is_task_delivered, normalize_task_states, validate_task_artifact_identity  # noqa: E402

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML>=6.0")
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────
REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"
REQUIREMENTS_PATH = Path("specs/03-requirements.md")
EXECUTION_PATH = Path("specs/10-execution.md")

# ── Status classification ──────────────────────────────────────────────
IN_PROGRESS_STATUSES = frozenset({"in_progress"})
PLANNED_STATUSES = frozenset({"planned", "proposed"})
DEFERRED_STATUSES = frozenset({"deferred"})

# Patterns that indicate a "complete" annotation that should never be downgraded
COMPLETE_PATTERN = re.compile(
    r"✅.*COMPLETE|✅.*ALL.*CRITERIA.*MET|✅.*ALL.*P0.*CRITERIA|^Complete$",
    re.IGNORECASE,
)


# ── Data loading ───────────────────────────────────────────────────────


def load_registry() -> List[dict]:
    """Load tasks from TASK_REGISTRY.yaml."""
    if not REGISTRY_PATH.exists():
        print(f"   ⚠️ {REGISTRY_PATH} not found")
        return []
    data = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
    return data.get("tasks", [])


def build_requirement_status_map(tasks: List[dict]) -> Dict[str, str]:
    """Derive requirement-level status from task statuses.

    Returns mapping {requirement_id: derived_status}.
    """
    # Group tasks by canonical requirement ID
    req_tasks: Dict[str, List[dict]] = defaultdict(list)
    for t in tasks:
        raw_req = str(t.get("requirement", "")).strip()
        if not raw_req:
            continue
        # Normalize: strip parenthetical suffixes like "FR-002 (Confidence System)"
        canonical = re.match(r"((?:FR|NFR)-[\w-]+)", raw_req)
        if canonical:
            req_id = canonical.group(1)
            req_tasks[req_id].append(t)

    result: Dict[str, str] = {}
    for req_id, requirement_tasks in req_tasks.items():
        statuses = [
            str(t.get("status", "planned")).split("#")[0].strip().lower()
            for t in requirement_tasks
        ]
        status_set = set(statuses)

        # Delivered only when every task satisfies the canonical three-state contract.
        if requirement_tasks and all(is_task_delivered(task) for task in requirement_tasks):
            if req_id.startswith("NFR"):
                result[req_id] = "Verified"
            else:
                result[req_id] = "Implemented"

        # Any in progress → In Progress
        elif status_set & IN_PROGRESS_STATUSES:
            result[req_id] = "In Progress"

        # All planned
        elif status_set <= PLANNED_STATUSES:
            result[req_id] = "Planned"

        # All deferred
        elif status_set <= DEFERRED_STATUSES:
            result[req_id] = "Deferred"

        # Mix of done + planned/deferred (no in_progress) → In Progress
        elif any(is_task_delivered(task) for task in requirement_tasks):
            result[req_id] = "In Progress"

        else:
            result[req_id] = "Planned"

    return result


def build_task_status_map(tasks: List[dict]) -> Dict[str, str]:
    """Build mapping {task_id: display_status}."""
    status_display = {
        "implemented": "Implemented",
        "verified": "Verified",
        "done": "Done",
        "absorbed": "Absorbed",
        "in_progress": "In Progress",
        "planned": "Planned",
        "deferred": "Deferred",
    }
    result: Dict[str, str] = {}
    for t in tasks:
        tid = t.get("id", "")
        raw = str(t.get("status", "planned")).split("#")[0].strip().lower()
        states = normalize_task_states(t)
        if is_task_delivered(t):
            result[tid] = "Verified"
        elif states.get("compatibility_status") == "unsupported":
            result[tid] = f"Unsupported Legacy Status ({states['legacy_status']})"
        elif states["lifecycle_state"] == "implementation_complete":
            result[tid] = "Implementation Complete"
        else:
            result[tid] = status_display.get(raw, raw.title())
    return result


# ── specs/03-requirements.md sync ─────────────────────────────────────


def sync_requirements_spec(
    req_status_map: Dict[str, str], dry_run: bool = False
) -> int:
    """Update **Status**: lines in specs/03-requirements.md.

    Returns count of lines changed.
    """
    print("📋 Syncing specs/03-requirements.md requirement statuses...")

    if not REQUIREMENTS_PATH.exists():
        print(f"   ⚠️ {REQUIREMENTS_PATH} not found, skipping")
        return 0

    text = REQUIREMENTS_PATH.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    current_req: Optional[str] = None
    changes = 0

    # Requirement section headers (H2 or H3) — shared, tolerant pattern
    header_re = spec_header.REQ_HEADER_RE

    for i, line in enumerate(lines):
        # Track which requirement section we're in
        header_match = header_re.match(line)
        if header_match:
            current_req = header_match.group(1)
            continue

        # Process **Status**: lines within a known requirement section
        if current_req and line.startswith("**Status**:"):
            existing_status = line.split(":", 1)[1].strip()

            # NEVER downgrade a ✅ COMPLETE annotation
            if COMPLETE_PATTERN.search(existing_status):
                current_req = None
                continue

            # NEVER downgrade Verified NFRs
            if current_req.startswith("NFR") and "Verified" in existing_status:
                current_req = None
                continue

            # Look up derived status
            derived = req_status_map.get(current_req)
            if derived is None:
                # No tasks found for this requirement — leave unchanged
                current_req = None
                continue

            # Build new status line
            new_status_line = f"**Status**: {derived}\n"

            if new_status_line != line:
                old_display = existing_status.strip()
                print(f"   {current_req}: '{old_display}' → '{derived}'")
                lines[i] = new_status_line
                changes += 1

            current_req = None

    if changes and not dry_run:
        REQUIREMENTS_PATH.write_text("".join(lines), encoding="utf-8")
        print(f"   ✅ Updated {changes} requirement statuses")
    elif changes:
        print(f"   🔍 Would update {changes} requirement statuses (dry-run)")
    else:
        print("   ✅ All requirement statuses already in sync")

    return changes


# ── specs/10-execution.md sync ────────────────────────────────────────


def sync_execution_task_tables(
    task_status_map: Dict[str, str], dry_run: bool = False
) -> int:
    """Update task status columns in specs/10-execution.md tables outside markers.

    Targets:
    - §4.1 "NEW Tasks" summary table (| T-xxx | ... | Status |)
    - §5 Traceability Matrix (| T-xxx | ... | Status |)
    """
    print("📐 Syncing specs/10-execution.md task tables...")

    if not EXECUTION_PATH.exists():
        print(f"   ⚠️ {EXECUTION_PATH} not found, skipping")
        return 0

    text = EXECUTION_PATH.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    # Marker boundaries — skip lines between markers (already synced)
    marker_start = "<!-- BEGIN TASK_MATRIX -->"
    marker_end = "<!-- END TASK_MATRIX -->"
    in_marker = False

    changes = 0

    # Parse table rows with task IDs
    # Formats:
    #   §4.1: | T-019 | Title | Req | Prio | Est | Status |     (6 cols, status is last)
    #   §5:   | T-019 | Req | Arch | API | Accept | Status |    (6 cols, status is last)
    task_row_re = re.compile(r"^\|\s*\*{0,2}(T-\d{3})\*{0,2}\s*\|")

    for i, line in enumerate(lines):
        # Track marker boundaries
        if marker_start in line:
            in_marker = True
            continue
        if marker_end in line:
            in_marker = False
            continue
        if in_marker:
            continue

        match = task_row_re.match(line)
        if not match:
            continue

        task_id = match.group(1)
        new_status = task_status_map.get(task_id)
        if new_status is None:
            continue

        # Split the row into cells
        cells = line.split("|")
        if len(cells) < 3:
            continue

        # Find the status cell (last non-empty cell before trailing |)
        last_data_idx = len(cells) - 2  # Skip trailing empty after last |
        if last_data_idx < 1:
            continue

        old_status_cell = cells[last_data_idx].strip()
        # Clean old status for comparison (remove bold markers)
        old_clean = old_status_cell.replace("**", "").strip()

        # Skip special entries like [RESERVED] or '-'
        if old_clean in ("-", "", "[RESERVED]"):
            continue

        # Determine display format — done statuses get bold
        if new_status in ("Implemented", "Verified", "Done"):
            new_display = f"**{new_status}**"
            # For traceability matrix (§5), use simpler "Done" label
            if "Traceability" in "".join(lines[max(0, i - 30) : i]):
                new_display = "Done" if new_status != "Planned" else "Planned"
        elif new_status == "In Progress":
            new_display = f"**{new_status}**"
        else:
            new_display = new_status

        # Only count a change if the normalized status differs
        old_normalized = old_clean.lower().replace("in progress", "in_progress")
        new_normalized = new_status.lower().replace("in progress", "in_progress")

        # Map "Done" ↔ "Implemented" as equivalent
        if old_normalized in ("done", "implemented") and new_normalized in (
            "done",
            "implemented",
        ):
            continue

        # Special: skip if old has percentage (e.g., "In Progress (10%)")
        # — keep detailed manually-annotated statuses
        if re.search(r"\(\d+%\)", old_clean):
            continue

        # Special: skip "Ready" status (manual annotation in original spec)
        if old_normalized == "ready":
            continue

        if old_normalized != new_normalized:
            # Preserve cell padding
            pad = " " if cells[last_data_idx].startswith(" ") else ""
            cells[last_data_idx] = f"{pad}{new_display} "
            new_line = "|".join(cells)
            if new_line != line:
                print(f"   {task_id}: '{old_clean}' → '{new_status}'")
                lines[i] = new_line
                changes += 1

    if changes and not dry_run:
        EXECUTION_PATH.write_text("".join(lines), encoding="utf-8")
        print(f"   ✅ Updated {changes} task statuses in execution spec")
    elif changes:
        print(f"   🔍 Would update {changes} task statuses (dry-run)")
    else:
        print("   ✅ All task statuses in execution spec already in sync")

    return changes


# ── Main ───────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cascade task statuses from TASK_REGISTRY into spec files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing files",
    )
    parser.add_argument(
        "--requirements-only",
        action="store_true",
        help="Only sync specs/03-requirements.md",
    )
    parser.add_argument(
        "--execution-only",
        action="store_true",
        help="Only sync specs/10-execution.md",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    sync_all = not args.requirements_only and not args.execution_only

    # Load registry
    tasks = load_registry()
    try:
        validate_task_artifact_identity(Path.cwd(), str(NAOS_ROOT), {"tasks": tasks})
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not tasks:
        print("❌ No tasks loaded from registry")
        return 1

    if args.verbose:
        print(f"   Loaded {len(tasks)} tasks from {REGISTRY_PATH}")

    # Build status maps
    req_status_map = build_requirement_status_map(tasks)
    task_status_map = build_task_status_map(tasks)

    if args.verbose:
        print(f"   Derived statuses for {len(req_status_map)} requirements")
        for req, status in sorted(req_status_map.items()):
            print(f"     {req}: {status}")

    total_changes = 0

    # Sync specs/03-requirements.md
    if sync_all or args.requirements_only:
        total_changes += sync_requirements_spec(req_status_map, dry_run=args.dry_run)

    # Sync specs/10-execution.md
    if sync_all or args.execution_only:
        total_changes += sync_execution_task_tables(
            task_status_map, dry_run=args.dry_run
        )

    if total_changes:
        print(f"\n📊 Total: {total_changes} status updates applied")
    else:
        print("\n✅ All spec statuses in sync with TASK_REGISTRY.yaml")

    return 0


if __name__ == "__main__":
    sys.exit(main())
