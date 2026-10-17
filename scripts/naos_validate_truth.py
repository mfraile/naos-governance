#!/usr/bin/env python3
"""Check four truth-table task metrics against the parsed task registry.

Usage: python scripts/naos_validate_truth.py [--verbose] [--fix]
Env: NAOS_ROOT (default: naos), relative to this script's project root or absolute.

This read-only check covers Tasks Total, Tasks Complete, Tasks %, and Phases.
Requirement, specification, test, and review-date claims are outside its scope.
Exit 0 only when the four task rows match; exit 1 for missing or contradictory
inputs; exit 2 for an unsupported --fix request.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any

import yaml

from naos_task_lifecycle import is_task_delivered, normalize_task_id, normalize_task_states


PROJECT_ROOT = Path(__file__).resolve().parent.parent
NAOS_ROOT = PROJECT_ROOT / os.getenv("NAOS_ROOT", "naos")
TRUTH_RELATIVE = "governance/GOVERNANCE_TRUTH_TABLE.md"
REGISTRY_RELATIVE = "TASK_REGISTRY.yaml"
CHECKED_ROWS = ("Tasks Total", "Tasks Complete", "Tasks %", "Phases")
UNCHECKED_SCOPE = (
    "requirement metrics (not checked by this command)",
    "specification metrics (not checked by this command)",
    "test metrics (not derived here)",
    "Date (review date not authenticated)",
    "other governance documents (not compared here)",
)
_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_PERCENT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?%\Z")


def is_kit_source_root(root: Path) -> bool:
    """Keep the source-tree skip explicit when no adopter root was selected."""
    return (
        (root / "pyproject.toml").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / REGISTRY_RELATIVE).is_file()
        and not (root / "naos" / REGISTRY_RELATIVE).exists()
    )


@dataclass
class ValidationResult:
    source: str
    metric: str
    expected: Any
    actual: Any
    passed: bool
    message: str = ""


@dataclass
class ValidationReport:
    results: list[ValidationResult] = field(default_factory=list)
    checked_rows: list[str] = field(default_factory=list)
    not_checked_rows: list[str] = field(default_factory=list)
    table_status: str = "unavailable"
    registry_status: str = "unavailable"

    def error(self, source: str, metric: str, message: str, actual: Any = None) -> None:
        if isinstance(actual, float) and not math.isfinite(actual):
            actual = repr(actual)
        elif not isinstance(actual, (str, int, float, bool, type(None))):
            actual = repr(actual)[:200]
        self.results.append(ValidationResult(source, metric, "valid", actual, False, message))

    @property
    def failures(self) -> list[ValidationResult]:
        return [result for result in self.results if not result.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "task_metrics_matched" if not self.failures and len(self.checked_rows) == 4 else "fail",
            "scope": "task metrics only; no whole-governance truth claim",
            "table_status": self.table_status,
            "registry_status": self.registry_status,
            "checked_rows": self.checked_rows,
            "not_checked_rows": self.not_checked_rows,
            "not_checked": list(UNCHECKED_SCOPE),
            "checks_run": len(self.results),
            "checks_passed": sum(result.passed for result in self.results),
            "checks_failed": len(self.failures),
            "failures": [
                {
                    "source": result.source,
                    "metric": result.metric,
                    "expected": result.expected,
                    "actual": result.actual,
                    "message": result.message,
                }
                for result in self.failures
            ],
        }


def _table_rows(path: Path, report: ValidationReport) -> dict[str, int | float] | None:
    source = f"naos/{TRUTH_RELATIVE}"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        report.error(source, "table.available", f"Cannot read UTF-8 truth table: {exc}")
        return None
    report.table_status = "invalid"
    headings = [index for index, line in enumerate(lines) if re.fullmatch(
        r"##\s+Canonical Metrics\s*", line, flags=re.IGNORECASE,
    )]
    if len(headings) != 1:
        report.error(source, "table.section", "Expected exactly one ## Canonical Metrics section", len(headings))
        return None
    start = headings[0] + 1
    end = next((index for index in range(start, len(lines)) if re.match(r"##\s+", lines[index])), len(lines))
    seen: dict[str, str] = {}
    observed: set[str] = set()
    for line in lines[start:end]:
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        label = cells[0].strip("* ") if cells else ""
        if label not in CHECKED_ROWS:
            if label and label != "Metric" and not re.fullmatch(r"[-: ]+", label) and label not in report.not_checked_rows:
                report.not_checked_rows.append(label)
            continue
        if label in observed:
            report.error(source, f"table.{label}", "Duplicate required metric row", label)
            continue
        observed.add(label)
        if len(cells) != 4 or not line.rstrip().endswith("|"):
            report.error(source, f"table.{label}", "Required row needs Metric, Value, Source, Methodology cells", line)
            continue
        seen[label] = cells[1]
    for label in CHECKED_ROWS:
        if label not in seen:
            report.error(source, f"table.{label}", "Required metric row is missing")
    if report.failures:
        report.table_status = "invalid"
        return None
    parsed: dict[str, int | float] = {}
    for label, value in seen.items():
        if label == "Tasks %":
            if not _PERCENT.fullmatch(value):
                report.error(source, f"table.{label}", "Expected a nonnegative numeric percentage", value)
            else:
                number = Decimal(value[:-1])
                if number > 100:
                    report.error(source, f"table.{label}", "Percentage cannot exceed 100%", value)
                else:
                    parsed[label] = float(number)
        elif not _INTEGER.fullmatch(value):
            report.error(source, f"table.{label}", "Expected a nonnegative integer", value)
        else:
            try:
                parsed[label] = int(value)
            except ValueError:
                report.error(source, f"table.{label}", "Integer value is too large to parse", value[:200])
    report.table_status = "invalid" if report.failures else "valid"
    return parsed if not report.failures else None


def _phase_key(value: Any) -> tuple[str, str]:
    """Treat numeric strings and numbers as one phase value; retain named phases."""
    if isinstance(value, bool) or value is None or not isinstance(value, (str, int, float)):
        raise ValueError("phase must be a nonempty scalar value")
    text = str(value).strip()
    if not text:
        raise ValueError("phase must be a nonempty scalar value")
    try:
        numeric = Decimal(text)
    except InvalidOperation:
        return ("name", text)
    if not numeric.is_finite():
        raise ValueError("phase must be finite")
    return ("number", str(numeric.normalize()))


def _registry_metrics(path: Path, report: ValidationReport) -> dict[str, int | float] | None:
    source = f"naos/{REGISTRY_RELATIVE}"
    prior_failures = len(report.failures)
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        report.error(source, "registry.available", f"Cannot read valid UTF-8 YAML registry: {exc}")
        return None
    except (UnicodeError, yaml.YAMLError, ValueError) as exc:
        report.registry_status = "invalid"
        report.error(source, "registry.structure", f"Registry is not valid UTF-8 YAML: {exc}")
        return None
    report.registry_status = "invalid"
    if isinstance(document, dict):
        tasks = document.get("tasks")
        declared = document.get("total_tasks")
        declared_present = "total_tasks" in document
    elif isinstance(document, list):
        tasks, declared = document, None
        declared_present = False
    else:
        report.error(source, "registry.structure", "Registry must be a tasks mapping or legacy task list")
        return None
    if not isinstance(tasks, list):
        report.error(source, "registry.tasks", "Registry tasks must be a list")
        return None
    if declared_present and (
        isinstance(declared, bool) or not isinstance(declared, int) or declared < 0
    ):
        report.error(source, "registry.total_tasks", "Declared total_tasks must be a nonnegative integer", declared)
    if declared is not None and isinstance(declared, int) and not isinstance(declared, bool) and declared != len(tasks):
        report.error(source, "registry.total_tasks", "Declared total_tasks conflicts with parsed task-list length", declared)
    phases: set[tuple[str, str]] = set()
    identifiers: set[str] = set()
    delivered = 0
    for index, task in enumerate(tasks):
        prefix = f"registry.tasks[{index}]"
        if not isinstance(task, dict):
            report.error(source, prefix, "Task must be a mapping", task)
            continue
        task_id = task.get("id")
        try:
            if not isinstance(task_id, str):
                raise ValueError("Task id must be a string")
            canonical_id = normalize_task_id(task_id)
            if canonical_id in identifiers:
                raise ValueError("Task id duplicates an existing canonical identity")
            identifiers.add(canonical_id)
        except ValueError as exc:
            report.error(source, f"{prefix}.id", str(exc), task_id)
        try:
            phases.add(_phase_key(task.get("phase")))
        except ValueError as exc:
            report.error(source, f"{prefix}.phase", str(exc), task.get("phase"))
        if "status" in task and not isinstance(task["status"], str):
            report.error(source, f"{prefix}.status", "Task status must be a string", task["status"])
        states = normalize_task_states(task)
        if not states["legacy_status_supported"]:
            report.error(source, f"{prefix}.status", "Task status is not recognized by lifecycle compatibility", task.get("status"))
        for field_name in ("lifecycle_state", "delivery_state", "verification_state"):
            if task.get(field_name) not in (None, "") and (
                not isinstance(task[field_name], str)
                or task[field_name].strip().lower() != states[field_name]
            ):
                report.error(source, f"{prefix}.{field_name}", "Task state is malformed", task[field_name])
        if is_task_delivered(task):
            delivered += 1
    if len(report.failures) != prior_failures:
        report.registry_status = "invalid"
        return None
    total = len(tasks)
    report.registry_status = "valid"
    return {
        "Tasks Total": total,
        "Tasks Complete": delivered,
        "Tasks %": round(delivered / total * 100, 1) if total else 0.0,
        "Phases": len(phases),
    }


def validate_truth(naos_root: Path) -> ValidationReport:
    report = ValidationReport()
    table = _table_rows(naos_root / TRUTH_RELATIVE, report)
    registry = _registry_metrics(naos_root / REGISTRY_RELATIVE, report)
    if table is None or registry is None:
        return report
    for label in CHECKED_ROWS:
        expected, actual = table[label], registry[label]
        report.checked_rows.append(label)
        report.results.append(ValidationResult(
            source=f"naos/{TRUTH_RELATIVE}", metric=label,
            expected=expected, actual=actual, passed=expected == actual,
            message="Table value must match parsed task registry and lifecycle semantics",
        ))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check task metric rows in the governance truth table")
    parser.add_argument("--verbose", "-v", action="store_true", help="Retained for compatibility; scoped JSON is always shown")
    parser.add_argument("--fix", action="store_true", help="Unsupported: this validator never edits files")
    args = parser.parse_args(argv)
    if args.fix:
        print("ERROR: --fix is not implemented; no file was changed.", file=sys.stderr)
        return 2
    if os.getenv("NAOS_ROOT") is None and is_kit_source_root(PROJECT_ROOT):
        print("SKIP: task metric validation applies to initialized NAOS-governed projects; set NAOS_ROOT explicitly to check an adopter.")
        return 0
    report = validate_truth(NAOS_ROOT)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=True))
    if report.failures or len(report.checked_rows) != len(CHECKED_ROWS):
        print("FAIL: task metric validation failed; other governance metrics remain unchecked.")
        return 1
    print("PASS: four task metric rows match; other governance metrics remain unchecked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
