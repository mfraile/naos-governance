#!/usr/bin/env python3
"""
validate_traceability_headers.py — Spec-Kit header validator (NAOS portable)

Validates that Python source files contain the NAOS Spec-Kit traceability
header (Implements, Task, Specs, Rationale) and that task statuses in
TASK_REGISTRY.yaml match code reality.

Phase 1 — Header presence in every non-exempt .py file under SRC_ROOT and SCRIPTS_ROOT
Phase 2 — Task status coherence: implemented tasks should have code; planned tasks shouldn't

ENV VARS:
    NAOS_ROOT    — naos/ directory      (default: naos)
    SRC_ROOT     — source directory or comma-separated roots
                   (default: infer src, app, apps, packages, lib when present)
    SCRIPTS_ROOT — scripts directory    (default: scripts)

USAGE:
    python kit/scripts/validators/validate_traceability_headers.py

EXIT CODES:
    0 — All headers present and task statuses coherent
    1 — Violations found
    2 — TASK_REGISTRY.yaml missing

[ADAPT] Adjust EXEMPT set for files that intentionally lack headers
        (generated files, stubs, __init__.py, etc.)
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from source_roots import (  # noqa: E402
    existing_source_roots,
    resolve_source_roots,
    source_roots_display,
)

try:
    from validator_context import is_kit_repository, print_kit_skip
except ModuleNotFoundError:
    def is_kit_repository() -> bool:
        return False

    def print_kit_skip(validator_name: str, reason: str) -> None:
        print(f"{validator_name}: SKIP")
        print(f"  - kit repo context: {reason}")

# ── Path configuration ────────────────────────────────────────────────────────
NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))
SRC_ROOTS = resolve_source_roots(Path.cwd())
SCRIPTS_ROOT = Path(os.getenv("SCRIPTS_ROOT", "scripts"))

REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"

# [ADAPT] Files that are exempt from header requirements
EXEMPT = {"__init__.py"}

HEADER_RE = re.compile(r"Implements\s*:?\s*(?:FR|NFR)-(?:\d{3}|[A-Z]{2,4})", re.I)
TASK_RE = re.compile(r"Task:\s*(T-\d+|GOV-\d+|[A-Z0-9]+-\d+)", re.I)
TASK_REGISTRY_RE = re.compile(r"^T-\d+$")
SPECS_RE = re.compile(r"Specs:\s*.+\.md", re.I)
RATIONALE_RE = re.compile(r"Rationale:\s*.+", re.I)


# ── Phase 2: task-status coherence ───────────────────────────────────────────


def validate_task_status_coherence(
    task_files: Dict[str, List[str]], verbose: bool = False
) -> Tuple[int, List[str]]:
    if not REGISTRY_PATH.exists():
        return 2, [f"❌ TASK_REGISTRY not found: {REGISTRY_PATH}"]

    try:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            registry = yaml.safe_load(f)
    except Exception as e:
        return 2, [f"❌ Failed to load TASK_REGISTRY: {e}"]

    violations: List[str] = []
    tasks_dict = {t["id"]: t for t in registry.get("tasks", [])}

    implemented_statuses = {
        "Done",
        "Implemented",
        "Complete",
        "Completed",
        "Verified",
        "verified",
    }
    planned_statuses = {"Planned", "Todo", "Not Started", "Pending"}

    for task_id, task in tasks_dict.items():
        status = task.get("status", "")
        has_code = task_id in task_files

        if status in implemented_statuses and not has_code:
            violations.append(
                f"❌ {task_id}: Status='{status}' but NO CODE FILES found"
            )
        elif status in planned_statuses and has_code:
            violations.append(
                f"⚠️  {task_id}: Status='{status}' but HAS {len(task_files[task_id])} code file(s)"
            )

    orphaned = set(task_files.keys()) - set(tasks_dict.keys())
    for task_id in sorted(orphaned):
        violations.append(
            f"⚠️  {task_id}: NOT IN REGISTRY but has {len(task_files[task_id])} code file(s)"
        )

    if verbose and violations:
        print("\n=== PHASE 2: Task Status Coherence ===")
        for v in violations:
            print(v)

    return (1 if violations else 0), violations


# ── Phase 1: header validation ────────────────────────────────────────────────


def main() -> int:
    if is_kit_repository():
        print_kit_skip(
            "Traceability Headers",
            "requires adopter traceability headers and task registry",
        )
        return 0

    missing: List[Tuple[str, List[str]]] = []
    task_files: Dict[str, List[str]] = defaultdict(list)

    roots = existing_source_roots(Path.cwd()) + [SCRIPTS_ROOT]
    for root in roots:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            if py.name in EXEMPT:
                continue
            text = py.read_text(encoding="utf-8", errors="ignore")
            if "# AUTO-GENERATED" in text:
                continue

            has_req = bool(HEADER_RE.search(text))
            has_specs = bool(SPECS_RE.search(text))
            has_rationale = bool(RATIONALE_RE.search(text))
            task_match = TASK_RE.search(text)
            has_task = bool(task_match)

            # Reject T-AUTO placeholders
            if re.search(r"^Task:\s*T-AUTO-", text, re.I | re.M):
                has_task = False
            elif task_match:
                task_id = task_match.group(1)
                if TASK_REGISTRY_RE.match(task_id):
                    task_files[task_id].append(str(py))

            if not (has_req and has_task and has_specs and has_rationale):
                missing_fields = [
                    f
                    for f, present in [
                        ("Implements", has_req),
                        ("Task", has_task),
                        ("Specs", has_specs),
                        ("Rationale", has_rationale),
                    ]
                    if not present
                ]
                missing.append((str(py), missing_fields))

    if missing:
        print(
            "✗ Missing Spec-Kit headers (Implements / Task / Specs / Rationale required):"
        )
        for p, fields in missing[:200]:
            print(f"  - {p}")
            print(f"    Missing: {', '.join(fields)}")
        if len(missing) > 200:
            print(f"  … {len(missing) - 200} more")
        return 1

    print(
        f"✓ All modules in {source_roots_display(SRC_ROOTS)} and {SCRIPTS_ROOT} have complete Spec-Kit headers"
    )

    # Phase 2
    if task_files:
        exit_code, violations = validate_task_status_coherence(task_files, verbose=True)
        if exit_code == 0:
            print(
                f"✓ Task statuses coherent ({len(task_files)} tasks, "
                f"{sum(len(v) for v in task_files.values())} files)"
            )
        elif exit_code == 2:
            print("\n".join(violations))
            print("⚠️  Skipping Phase 2 (registry unavailable)")
        else:
            print(f"\n❌ {len(violations)} task status coherence issue(s)")
            return 1
    else:
        print(
            f"⚠️  No task IDs found in {source_roots_display(SRC_ROOTS)}/{SCRIPTS_ROOT} (Phase 2 skipped)"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
