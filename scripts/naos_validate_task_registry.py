"""
Validate naos/TASK_REGISTRY.yaml entries against JSON Schema.

Portable governance script — path-parameterized via NAOS_ROOT env var.
NAOS_ROOT defaults to 'naos/'; override for non-standard layouts.

Usage:
    python scripts/naos_validate_task_registry.py
    NAOS_ROOT=pm python scripts/naos_validate_task_registry.py

Schema lookup order:
    1. $REGISTRY_SCHEMA env var (per-entry schema; absolute or project-relative)
    2. $NAOS_ROOT/schemas/task_registry_schema.json (legacy per-entry schema)
    3. schemas/naos/task_registry.schema.json (shipped whole-document schema)

Exits 0 on valid registry, 1 on invalid registry, 2 on missing or invalid
schema or validation dependency.
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
    from jsonschema import validators  # type: ignore[import]

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

# Historical overrides validate each task; the shipped schema validates the document.
_schema_env = os.getenv("REGISTRY_SCHEMA")
if _schema_env:
    _schema_candidate = Path(_schema_env)
    if not _schema_candidate.is_absolute():
        _schema_candidate = PROJECT_ROOT / _schema_candidate
    SCHEMA_PATH = _schema_candidate
    SCHEMA_SCOPE = "entry"
else:
    _legacy_schema = NAOS_ROOT / "schemas" / "task_registry_schema.json"
    if _legacy_schema.exists():
        SCHEMA_PATH = _legacy_schema
        SCHEMA_SCOPE = "entry"
    else:
        SCHEMA_PATH = PROJECT_ROOT / "schemas" / "naos" / "task_registry.schema.json"
        SCHEMA_SCOPE = "document"


def load_registry(path: Path) -> list[dict]:
    """Load all task entries from TASK_REGISTRY.yaml."""
    return registry_tasks(load_registry_document(path), path)


def _team_scope_value(value: object) -> bool:
    """JSON Schema integer includes integral numeric values, but not booleans."""
    return (
        isinstance(value, str) and bool(value.strip())
        or type(value) is int
        or type(value) is float and value.is_integer()
    )


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

    # Mirror the shipped structural schema without requiring jsonschema in
    # dashboard/backlog consumers. The schema/consumer parity test guards drift.
    for field in sorted(set(raw) - {"enabled", "assignment_mode", "teams"}, key=str):
        errors.append(f"team_config has unknown field: {field}")
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
        for field in sorted(set(team) - {"id", "label", "members", "scope"}, key=str):
            errors.append(f"{label} has unknown field: {field}")
        if "label" in team and not isinstance(team["label"], str):
            errors.append(f"{label}.label must be a string")
        if "members" in team and (
            not isinstance(team["members"], list)
            or any(not isinstance(member, str) for member in team["members"])
        ):
            errors.append(f"{label}.members must be a list of strings")
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
            not _team_scope_value(item)
            for item in scope
        ):
            errors.append(f"{label}.scope must be a list of non-empty strings or integers")
            scope = []
        teams.append({**team, "id": team_id, "scope": [str(int(item)) if type(item) is float else str(item) for item in scope]})

    if enabled and not errors:
        tasks = registry.get("tasks", [])
        if not isinstance(tasks, list) or any(not isinstance(task, dict) for task in tasks):
            errors.append("team_config scope validation requires a tasks list of objects")
        else:
            field = {"task_scope": "id", "phase_scope": "phase", "module_scope": "owner"}[assignment_mode]
            available = {str(task[field]) for task in tasks if type(task.get(field)) in (str, int)}
            for team in teams:
                for entry in team["scope"]:
                    if entry not in available:
                        errors.append(f"team_config team {team['id']} scope reference not found for {assignment_mode}: {entry}")

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


def _reject_nonlocal_references(value: object) -> None:
    """Keep validation local even when a supplied schema contains references."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                not isinstance(item, str) or not item.startswith("#")
            ):
                raise ValueError(f"nonlocal JSON Schema reference is not supported: {item!r}")
            _reject_nonlocal_references(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonlocal_references(item)


def _validator_for_schema(schema: dict):
    """Check schema validity once before validating any registry content."""
    if not _HAS_JSONSCHEMA:
        raise RuntimeError("jsonschema package not installed")
    if not isinstance(schema, dict):
        raise ValueError("JSON Schema must be an object")
    _reject_nonlocal_references(schema)
    validator_class = validators.validator_for(schema)
    validator_class.check_schema(schema)
    return validator_class(schema)


def _normalise_dates(value: object) -> object:
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _normalise_dates(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise_dates(item) for item in value]
    return value


def validate_registry(tasks: list[dict], schema: dict) -> list[tuple[str, str]]:
    """Validate each task entry. Returns list of (task_id, error_message) tuples."""
    validator = _validator_for_schema(schema)
    errors = []
    for index, task in enumerate(tasks, start=1):
        task_id = task.get("id", f"<entry {index}>") if isinstance(task, dict) else f"<entry {index}>"
        for exc in validator.iter_errors(_normalise_dates(task)):
            errors.append((str(task_id), exc.message))
    return errors


def validate_registry_document(registry: object, schema: dict) -> list[tuple[str, str]]:
    """Validate the complete supported registry shape with the shipped schema."""
    from naos_task_lifecycle import (  # Imported only for the shipped default.
        DELIVERY_STATES,
        LEGACY_STATUS_COMPATIBILITY,
        LIFECYCLE_STATES,
        VERIFICATION_STATES,
        normalize_task_id,
    )

    validator = _validator_for_schema(schema)
    document = _normalise_dates(registry)
    tasks = document if isinstance(document, list) else document.get("tasks") if isinstance(document, dict) else None
    if isinstance(tasks, list):
        normalized_tasks = []
        vocabularies = {
            "status": LEGACY_STATUS_COMPATIBILITY,
            "lifecycle_state": LIFECYCLE_STATES,
            "delivery_state": DELIVERY_STATES,
            "verification_state": VERIFICATION_STATES,
        }
        for task in tasks:
            if not isinstance(task, dict):
                normalized_tasks.append(task)
                continue
            normalized = dict(task)
            task_id = task.get("id")
            if isinstance(task_id, str):
                try:
                    normalized["id"] = normalize_task_id(task_id)
                except ValueError:
                    pass  # Keep unsupported input for the schema to reject.
            for field, vocabulary in vocabularies.items():
                raw = task.get(field)
                if isinstance(raw, str):
                    candidate = raw.strip().lower()
                    if candidate in vocabulary:
                        normalized[field] = candidate
            normalized_tasks.append(normalized)
        if isinstance(document, list):
            document = normalized_tasks
        else:
            document = {**document, "tasks": normalized_tasks}
    return [
        ("TASK_REGISTRY", exc.message)
        for exc in validator.iter_errors(document)
    ]


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


def main() -> None:
    from naos_console import configure_console_output

    configure_console_output()
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

    try:
        registry = load_registry_document(REGISTRY_PATH)
    except (OSError, yaml.YAMLError) as exc:
        print(f"ERROR: Cannot load TASK_REGISTRY: {exc}", file=sys.stderr)
        sys.exit(1)
    tasks = registry_tasks(registry, REGISTRY_PATH)

    if not SCHEMA_PATH.is_file():
        print(f"ERROR: Schema not found: {SCHEMA_PATH}", file=sys.stderr)
        sys.exit(2)
    if not _HAS_JSONSCHEMA:
        print("ERROR: jsonschema package not installed; cannot validate TASK_REGISTRY", file=sys.stderr)
        sys.exit(2)
    try:
        schema = load_schema(SCHEMA_PATH)
        if SCHEMA_SCOPE == "document":
            schema_errors = validate_registry_document(registry, schema)
        else:
            schema_errors = validate_registry(tasks, schema)
    except Exception as exc:
        print(f"ERROR: Invalid or unusable schema {SCHEMA_PATH}: {exc}", file=sys.stderr)
        sys.exit(2)
    if any(not isinstance(task, dict) for task in tasks):
        print("[FAIL] TASK_REGISTRY task entries must be mappings/objects")
        for task_id, message in schema_errors:
            print(f"  ❌  {task_id}: {message}")
        sys.exit(1)

    from naos_task_lifecycle import validate_task_artifact_identity

    try:
        validate_task_artifact_identity(PROJECT_ROOT, str(NAOS_ROOT), {"tasks": tasks})
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    semantic_errors, semantic_warnings = validate_task_semantics(tasks)
    team_config_result = validate_team_config(registry)
    semantic_errors.extend(
        ("team_config", str(message))
        for message in team_config_result["errors"]
    )

    errors = schema_errors + semantic_errors
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
