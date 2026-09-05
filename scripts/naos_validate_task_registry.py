"""
Validate naos/TASK_REGISTRY.yaml entries against JSON Schema.

Portable governance script — path-parameterized via NAOS_ROOT env var.
NAOS_ROOT defaults to 'naos/'; override for non-standard layouts.

Usage:
    python scripts/naos_validate_task_registry.py
    NAOS_ROOT=pm python scripts/naos_validate_task_registry.py

Schema lookup order:
    1. $REGISTRY_SCHEMA env var (absolute or project-relative path)
    2. $NAOS_ROOT/schemas/task_registry_schema.json
    3. If neither exists and jsonschema is installed: YAML syntax check only

Exits 0 on valid registry, 1 on validation errors, 2 on missing jsonschema
when a schema file is explicitly requested via env var.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path

import yaml

_HAS_JSONSCHEMA = False
try:
    from jsonschema import ValidationError, validate  # type: ignore[import]

    _HAS_JSONSCHEMA = True
except ImportError:
    pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NAOS_ROOT = PROJECT_ROOT / os.getenv("NAOS_ROOT", "naos")
REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"
TEAM_ASSIGNMENT_MODES = ("task_scope", "phase_scope", "module_scope")


class TeamConfigValidationError(ValueError):
    """Raised when a consumer cannot safely use an invalid team configuration."""


def load_registry_document(path: Path) -> object:
    """Load the complete registry so top-level controls are not discarded."""

    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def registry_tasks(data: object, path: Path) -> list[dict]:
    """Extract task entries while retaining the separately validated document."""

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "tasks" in data and isinstance(data["tasks"], list):
        return data["tasks"]
    print(f"ERROR: Unexpected TASK_REGISTRY structure in {path}", file=sys.stderr)
    sys.exit(1)


def is_kit_source_root(root: Path) -> bool:
    """Return True when running inside the NAOS kit source tree."""
    return (
        (root / "pyproject.toml").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / "naos" / "TASK_REGISTRY.yaml").exists()
    )

# Schema: explicit env var → naos/schemas/task_registry_schema.json → None
_schema_env = os.getenv("REGISTRY_SCHEMA")
if _schema_env:
    _schema_candidate = Path(_schema_env)
    if not _schema_candidate.is_absolute():
        _schema_candidate = PROJECT_ROOT / _schema_candidate
    SCHEMA_PATH: Path | None = _schema_candidate
else:
    _default_schema = NAOS_ROOT / "schemas" / "task_registry_schema.json"
    SCHEMA_PATH = _default_schema if _default_schema.exists() else None


def load_registry(path: Path) -> list[dict]:
    """Load all task entries from TASK_REGISTRY.yaml."""
    return registry_tasks(load_registry_document(path), path)


def validate_team_config(registry: object) -> dict[str, object]:
    """Return one normalized validation result for every registry consumer."""

    raw = registry.get("team_config") if isinstance(registry, dict) else None
    if raw is None:
        return {
            "valid": True,
            "enabled": False,
            "assignment_mode": "task_scope",
            "teams": [],
            "errors": [],
        }

    errors: list[str] = []
    if not isinstance(raw, dict):
        return {
            "valid": False,
            "enabled": False,
            "assignment_mode": "task_scope",
            "teams": [],
            "errors": ["team_config must be a mapping/object"],
        }

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        errors.append("team_config.enabled must be true or false")
        enabled = False

    assignment_mode = raw.get("assignment_mode", "task_scope")
    if assignment_mode not in TEAM_ASSIGNMENT_MODES:
        errors.append(
            "team_config.assignment_mode must be one of: "
            + ", ".join(TEAM_ASSIGNMENT_MODES)
        )
        assignment_mode = "task_scope"

    raw_teams = raw.get("teams", [])
    if not isinstance(raw_teams, list):
        errors.append("team_config.teams must be a list")
        raw_teams = []

    teams: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for index, team in enumerate(raw_teams, start=1):
        label = f"team_config.teams[{index}]"
        if not isinstance(team, dict):
            errors.append(f"{label} must be a mapping/object")
            continue
        team_id = team.get("id")
        if not isinstance(team_id, str) or not team_id.strip():
            errors.append(f"{label}.id must be a non-empty string")
            continue
        team_id = team_id.strip()
        if team_id in seen_ids:
            errors.append(f"duplicate team_config team id: {team_id}")
        seen_ids.add(team_id)
        scope = team.get("scope", [])
        if not isinstance(scope, list) or any(
            not isinstance(item, (str, int)) or not str(item).strip()
            for item in scope
        ):
            errors.append(f"{label}.scope must be a list of non-empty strings or integers")
            scope = []
        teams.append({**team, "id": team_id, "scope": [str(item) for item in scope]})

    return {
        "valid": not errors,
        "enabled": enabled,
        "assignment_mode": assignment_mode,
        "teams": teams,
        "errors": errors,
    }


def require_valid_team_config(registry: object) -> dict[str, object]:
    """Return normalized team configuration or reject with one stable message."""

    result = validate_team_config(registry)
    if not result["valid"]:
        raise TeamConfigValidationError(
            "Invalid team_config: " + "; ".join(str(item) for item in result["errors"])
        )
    return result


def load_schema(path: Path) -> dict:
    """Load JSON Schema from file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalise_entry(entry: dict) -> dict:
    """Normalise YAML-loaded types before schema validation.

    Converts datetime.date/datetime objects to ISO strings so jsonschema
    can validate the 'pattern' constraint on completion_date.
    """
    normalised = {}
    for k, v in entry.items():
        if isinstance(v, (datetime.date, datetime.datetime)):
            normalised[k] = v.isoformat()
        else:
            normalised[k] = v
    return normalised


def validate_registry(tasks: list[dict], schema: dict) -> list[tuple[str, str]]:
    """Validate each task entry. Returns list of (task_id, error_message) tuples."""
    if not _HAS_JSONSCHEMA:
        print(
            "WARNING: jsonschema not installed — skipping schema validation.\n"
            "Run: pip install jsonschema  to enable full validation.",
            file=sys.stderr,
        )
        return []

    errors = []
    for task in tasks:
        task_id = task.get("id", "<unknown>")
        try:
            validate(instance=normalise_entry(task), schema=schema)
        except ValidationError as exc:
            errors.append((task_id, exc.message))
    return errors


def validate_task_semantics(tasks: list[dict]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Validate dependency and parallelism semantics not expressible in basic YAML.

    Returns (errors, warnings). Errors are objective invalidity; warnings are
    quality signals that should not block existing downstream projects.
    """
    errors: list[tuple[str, str]] = []
    warnings: list[tuple[str, str]] = []
    task_ids: dict[str, int] = {}

    for index, task in enumerate(tasks, start=1):
        label = f"<entry {index}>"
        if not isinstance(task, dict):
            errors.append((label, "task entry must be a mapping/object"))
            continue

        task_id = task.get("id")
        if isinstance(task_id, str) and task_id.strip():
            label = task_id.strip()
            if label in task_ids:
                first_index = task_ids[label]
                errors.append((label, f"duplicate task id (first seen at entry {first_index})"))
            else:
                task_ids[label] = index

        if "parallelizable" in task and not isinstance(task.get("parallelizable"), bool):
            errors.append((label, "parallelizable must be true or false when present"))

    graph: dict[str, list[str]] = {task_id: [] for task_id in task_ids}

    for index, task in enumerate(tasks, start=1):
        if not isinstance(task, dict):
            continue
        task_id_value = task.get("id")
        task_id = task_id_value.strip() if isinstance(task_id_value, str) else f"<entry {index}>"
        dependencies = task.get("dependencies", [])

        if dependencies is None:
            dependencies = []
        if not isinstance(dependencies, list):
            errors.append((task_id, "dependencies must be a list of task ids when present"))
            continue

        valid_dependencies: list[str] = []
        for dependency in dependencies:
            if not isinstance(dependency, str) or not dependency.strip():
                errors.append((task_id, "dependencies entries must be non-empty task id strings"))
                continue
            dependency_id = dependency.strip()
            if dependency_id == task_id:
                errors.append((task_id, "task cannot depend on itself"))
                continue
            if dependency_id not in task_ids:
                errors.append((task_id, f"dependency not found: {dependency_id}"))
                continue
            valid_dependencies.append(dependency_id)

        if task_id in graph:
            graph[task_id] = valid_dependencies

        if task.get("parallelizable") is True:
            for field in ("owner", "requirement", "phase"):
                if task.get(field) in (None, ""):
                    warnings.append((task_id, f"parallelizable task should declare {field}"))
            description = task.get("description")
            if not isinstance(description, str) or len(description.strip()) < 40:
                warnings.append((task_id, "parallelizable task should include a specific description"))

    errors.extend(find_dependency_cycles(graph))
    return errors, warnings


def find_dependency_cycles(graph: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Return dependency-cycle errors for a task dependency graph."""
    errors: list[tuple[str, str]] = []
    state: dict[str, str] = {}
    stack: list[str] = []

    def visit(task_id: str) -> None:
        state[task_id] = "visiting"
        stack.append(task_id)
        for dependency_id in graph.get(task_id, []):
            dependency_state = state.get(dependency_id)
            if dependency_state == "visiting":
                cycle_start = stack.index(dependency_id)
                cycle = stack[cycle_start:] + [dependency_id]
                errors.append((task_id, f"dependency cycle detected: {' -> '.join(cycle)}"))
            elif dependency_state != "done":
                visit(dependency_id)
        stack.pop()
        state[task_id] = "done"

    for task_id in graph:
        if state.get(task_id) is None:
            visit(task_id)
    return errors


def print_semantic_warnings(warnings: list[tuple[str, str]]) -> None:
    """Print non-blocking semantic warnings."""
    if not warnings:
        return
    print(f"[WARN] TASK_REGISTRY semantic warning(s) — {len(warnings)} item(s):")
    for task_id, message in warnings:
        print(f"  - {task_id}: {message}")


def syntax_check_only(tasks: list[dict]) -> None:
    """Basic YAML-level sanity checks when no schema is available."""
    missing_id = [t for t in tasks if not t.get("id")]
    missing_title = [t for t in tasks if not t.get("title")]
    issues = []
    if missing_id:
        issues.append(f"  {len(missing_id)} task(s) missing 'id' field")
    if missing_title:
        issues.append(f"  {len(missing_title)} task(s) missing 'title' field")
    if issues:
        print("[WARN] Basic sanity issues found:")
        for issue in issues:
            print(issue)
    else:
        print(
            f"[OK] YAML syntax valid — {len(tasks)} entries loaded "
            f"(no schema available for full validation)"
        )


def main() -> None:
    if not REGISTRY_PATH.exists():
        if os.getenv("NAOS_ROOT") is None and is_kit_source_root(PROJECT_ROOT):
            print(
                "SKIP: TASK_REGISTRY validation applies to initialized NAOS-governed projects, "
                "not the NAOS kit source tree."
            )
            print("      Run this from a project created with `naos init`, or set NAOS_ROOT explicitly.")
            sys.exit(0)
        print(f"ERROR: TASK_REGISTRY not found: {REGISTRY_PATH}", file=sys.stderr)
        sys.exit(1)

    registry = load_registry_document(REGISTRY_PATH)
    tasks = registry_tasks(registry, REGISTRY_PATH)
    semantic_errors, semantic_warnings = validate_task_semantics(tasks)
    team_config_result = validate_team_config(registry)
    semantic_errors.extend(
        ("team_config", str(message))
        for message in team_config_result["errors"]
    )

    # No schema available — run syntax-only check
    if SCHEMA_PATH is None:
        syntax_check_only(tasks)
        print_semantic_warnings(semantic_warnings)
        if semantic_errors:
            print(
                f"[FAIL] TASK_REGISTRY semantic validation failed — {len(semantic_errors)} issue(s):\n"
            )
            for task_id, message in semantic_errors:
                print(f"  ❌  {task_id}: {message}")
            print()
            print("Fix the offending entries in TASK_REGISTRY.yaml, then retry.")
            sys.exit(1)
        sys.exit(0)

    if not SCHEMA_PATH.exists():
        if _schema_env:
            # User explicitly requested a schema that doesn't exist
            print(f"ERROR: Schema not found: {SCHEMA_PATH}", file=sys.stderr)
            sys.exit(2)
        else:
            # Default schema path doesn't exist yet — syntax check only
            syntax_check_only(tasks)
            sys.exit(0)

    if not _HAS_JSONSCHEMA:
        print(
            "ERROR: jsonschema package not installed but schema file is present.\n"
            "Run: pip install jsonschema",
            file=sys.stderr,
        )
        sys.exit(2)

    schema = load_schema(SCHEMA_PATH)
    errors = validate_registry(tasks, schema) + semantic_errors
    print_semantic_warnings(semantic_warnings)

    if errors:
        print(
            f"[FAIL] TASK_REGISTRY validation failed — {len(errors)} invalid entry(s):\n"
        )
        for task_id, message in errors:
            print(f"  ❌  {task_id}: {message}")
        print()
        print("Fix the offending entries in TASK_REGISTRY.yaml, then retry.")
        sys.exit(1)
    else:
        print(
            f"[OK] TASK_REGISTRY valid — {len(tasks)} entries passed schema validation."
        )


if __name__ == "__main__":
    main()
