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
    From the initialized adopter root, run its generated validator:
    python scripts/validators/validate_traceability_headers.py
    For a relocated scaffold, set SCRIPTS_ROOT=naos_tools in the environment
    and run python naos_tools/validators/validate_traceability_headers.py.
    The kit-source validator has no generated content commitments; running it
    over an adopter assesses copied tooling as ordinary Python source.

EXIT CODES:
    0 — All headers present and task statuses coherent
    1 — Violations found
    2 — TASK_REGISTRY.yaml missing

[ADAPT] Adjust EXEMPT set for files that intentionally lack headers
        (generated files, stubs, __init__.py, etc.)
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from naos_console import configure_console_output  # noqa: E402
from naos_task_lifecycle import (  # noqa: E402
    DELIVERY_STATES, LIFECYCLE_STATES, VERIFICATION_STATES,
    normalize_task_id, normalize_task_states,
)
from spec_header import fr_tokens  # noqa: E402
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
# Generated content identity is anchored to this selected executable validator.
# No marker or adopter-writable manifest supplies an exclusion.
# BEGIN NAOS COPIED TOOL CONTENT
COPIED_TOOL_CONTENT = {}
# END NAOS COPIED TOOL CONTENT

HEADER_RE = re.compile(r"Implements\s*:[ \t]*([^\r\n]+)", re.I)
TASK_RE = re.compile(r"Task:[ \t]*([^\r\n]+)", re.I)
SPECS_RE = re.compile(r"Specs:\s*.+\.md", re.I)
RATIONALE_RE = re.compile(r"Rationale:\s*.+", re.I)


def _contained_regular_tool(py: Path, relative: Path | None) -> bool:
    """Select ordinary contained tool files; this is not a native race fence."""
    if relative is None or relative.parts[0] not in {"scripts", "naos_tools"}:
        return False
    cursor = Path.cwd()
    try:
        for index, component in enumerate(relative.parts):
            cursor = cursor / component
            metadata = cursor.lstat()
            if (stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                return False
            if index == len(relative.parts) - 1:
                return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            if not stat.S_ISDIR(metadata.st_mode):
                return False
    except OSError:
        return False
    return False


def _tool_exclusion(py: Path, relative: Path | None, raw: bytes) -> str | None:
    if not _contained_regular_tool(py, relative):
        return None
    # The operator already selected this executable control. Its own table
    # cannot hash itself; no other file receives this invocation exclusion.
    if (relative.parts[1:] == ("validators", "validate_traceability_headers.py")
            and os.path.realpath(py) == os.path.realpath(__file__)):
        return "selected validator control"
    if not isinstance(COPIED_TOOL_CONTENT, dict):
        return None
    row = COPIED_TOOL_CONTENT.get(relative.as_posix())
    if (isinstance(row, dict) and set(row) == {"sha256", "size_decimal"}
            and row["size_decimal"] == str(len(raw))
            and row["sha256"] == hashlib.sha256(raw).hexdigest()):
        return "exact generated tool content"
    return None


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
        return 1, [f"❌ Failed to load TASK_REGISTRY: {e}"]

    violations: List[str] = []
    if not isinstance(registry, dict) or not isinstance(registry.get("tasks"), list):
        return 1, ["❌ Malformed TASK_REGISTRY: expected a mapping with a tasks list"]

    tasks_dict = {}
    for index, task in enumerate(registry["tasks"]):
        if not isinstance(task, dict):
            violations.append(f"❌ Registry task {index + 1}: expected a task mapping")
            continue
        try:
            task_id = normalize_task_id(task.get("id"))
        except ValueError as exc:
            violations.append(f"❌ Registry task {index + 1}: {exc}")
            continue
        if task_id in tasks_dict:
            violations.append(f"❌ {task_id}: duplicate registry task ID")
            continue
        tasks_dict[task_id] = task
        states = normalize_task_states(task)
        malformed = []
        for field, allowed in (
            ("lifecycle_state", LIFECYCLE_STATES),
            ("delivery_state", DELIVERY_STATES),
            ("verification_state", VERIFICATION_STATES),
        ):
            if field in task and (
                not isinstance(task[field], str)
                or task[field].strip().lower() not in allowed
            ):
                malformed.append(field)
        if "status" in task and task["status"] is not None and not isinstance(task["status"], str):
            malformed.append("status")
        if malformed or states["compatibility_status"] == "unsupported":
            violations.append(
                f"❌ {task_id}: unsupported or malformed registry state "
                f"({', '.join(malformed) or repr(task.get('status'))})"
            )
            continue
        has_code = task_id in task_files
        requires_code = (
            states["lifecycle_state"] in {"implementation_complete", "completed"}
            or states["delivery_state"] == "delivered"
        )
        if requires_code and not has_code:
            violations.append(
                f"❌ {task_id}: lifecycle={states['lifecycle_state']!r}, "
                f"delivery={states['delivery_state']!r} but NO CODE FILES found"
            )
        if states["lifecycle_state"] == "planned" and has_code:
            violations.append(
                f"⚠️  {task_id}: lifecycle='planned' but HAS {len(task_files[task_id])} code file(s)"
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
    configure_console_output()
    if is_kit_repository():
        print_kit_skip(
            "Traceability Headers",
            "requires adopter traceability headers and task registry",
        )
        return 0

    missing: List[Tuple[str, List[str]]] = []
    task_files: Dict[str, List[str]] = defaultdict(list)

    invalid_tasks: List[str] = []
    copied_tool_exclusions: List[Tuple[str, str]] = []
    evaluated_files = 0
    roots = existing_source_roots(Path.cwd()) + [SCRIPTS_ROOT]
    for root in roots:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            if py.name in EXEMPT:
                continue
            raw = py.read_bytes()
            text = raw.decode("utf-8", errors="ignore")
            try:
                relative = Path(os.path.abspath(py)).relative_to(Path(os.path.abspath(Path.cwd())))
            except ValueError:
                relative = None
            display = (relative.as_posix() if relative is not None else
                       "[external-source:" + hashlib.sha256(os.fsencode(os.path.abspath(py))).hexdigest() + "]")
            exclusion = _tool_exclusion(py, relative, raw)
            if exclusion is not None:
                copied_tool_exclusions.append((relative.as_posix(), exclusion))
                continue
            evaluated_files += 1
            requirement_match = HEADER_RE.search(text)
            has_req = bool(requirement_match and fr_tokens(requirement_match.group(1)))
            has_specs = bool(SPECS_RE.search(text))
            has_rationale = bool(RATIONALE_RE.search(text))
            task_match = TASK_RE.search(text)
            has_task = False
            if task_match:
                try:
                    task_id = normalize_task_id(task_match.group(1))
                except ValueError as exc:
                    invalid_tasks.append(f"❌ {display}: {exc}; update the Task header to the exact registry ID")
                else:
                    has_task = True
                    task_files[task_id].append(display)

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
                missing.append((display, missing_fields))

    print(f"Python-only evaluation: {evaluated_files} non-exempt .py file(s); non-Python sources are not evaluated")

    print(f"NOT_ASSESSED: {len(copied_tool_exclusions)} tool-content/control exclusion(s); selected-validator trust boundary, not authenticated provenance")
    for path, basis in copied_tool_exclusions:
        print(f"  - NOT_ASSESSED {basis}: {path}")
    for diagnostic in invalid_tasks:
        print(diagnostic)
    if missing:
        print(
            "✗ Missing Spec-Kit headers (Implements / Task / Specs / Rationale required):"
        )
        for p, fields in missing[:200]:
            print(f"  - {p}")
            print(f"    Missing: {', '.join(fields)}")
        if len(missing) > 200:
            print(f"  … {len(missing) - 200} more")
    elif evaluated_files:
        print(
            f"✓ Evaluated Python files in {source_roots_display(SRC_ROOTS)} and {SCRIPTS_ROOT} have complete Spec-Kit headers"
        )

    # Run even when there are no task headers: implemented tasks may lack code.
    exit_code, violations = validate_task_status_coherence(task_files)
    if exit_code == 2:
        print("\n".join(violations))
        return 2
    if exit_code:
        print("\n".join(violations))
        print(f"\n❌ {len(violations)} task status coherence issue(s)")
        return 1
    print(
        f"✓ Task statuses coherent ({len(task_files)} tasks, "
        f"{sum(len(v) for v in task_files.values())} files)"
    )
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
