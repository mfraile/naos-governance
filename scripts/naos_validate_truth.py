#!/usr/bin/env python3
"""
naos_validate_truth.py — Validate governance documents match canonical values.

NAOS Portable Governance Kit
Usage: python scripts/naos_validate_truth.py [--verbose] [--fix]
Env:   NAOS_ROOT   (default: naos)  — root of the governance directory

PURPOSE:
    Ensures metrics in PROJECT_STATUS.md, README.md, and TASK_REGISTRY.yaml are
    consistent with the values recorded in naos/governance/GOVERNANCE_TRUTH_TABLE.md.

CANONICAL dict:
    Seed values start at zero. After your first gov-refresh run, update these to
    match the auto-computed values from naos/PROJECT_STATUS.md and naos/DASHBOARD.md.
    Run `make -f Makefile.naos gov-refresh` first, then read the outputs to fill these in.

Exit codes:
    0 — All checks passed
    1 — Drift detected (requires manual fix)
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

# ── CANONICAL VALUES ─────────────────────────────────────────────────────────
# [ADAPT] Update these to match your project's auto-computed values after
# running `make -f Makefile.naos gov-refresh`. The scripts compute these from TASK_REGISTRY.yaml.
# See naos/governance/GOVERNANCE_TRUTH_TABLE.md for the update procedure.
CANONICAL: dict[str, Any] = {
    "requirements": {
        "total": 0,  # Unique FR/NFR requirement keys from TASK_REGISTRY
        "delivered": 0,  # Requirements with all tasks done/absorbed/deferred
        "percentage": 0.0,
    },
    "tasks": {
        "total": 0,  # Total tasks in TASK_REGISTRY.yaml
        "complete": 0,  # implemented + verified + absorbed + done
        "percentage": 0.0,
    },
    "tests": {
        "total": 0,  # Total tests passing (optional — 0 = skip check)
        "passing": 0,
    },
    "date": "YYYY-MM-DD",  # Date these values were last verified
}
# ─────────────────────────────────────────────────────────────────────────────

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
NAOS_ROOT = PROJECT_ROOT / os.getenv("NAOS_ROOT", "naos")


def is_kit_source_root(root: pathlib.Path) -> bool:
    """Return True when running inside the NAOS kit source tree."""
    return (
        (root / "pyproject.toml").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / "naos" / "TASK_REGISTRY.yaml").exists()
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

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[ValidationResult]:
        return [r for r in self.results if not r.passed]

    def to_dict(self) -> dict:
        return {
            "status": "ok" if self.passed else "fail",
            "checks_run": len(self.results),
            "checks_passed": len([r for r in self.results if r.passed]),
            "checks_failed": len(self.failures),
            "failures": [
                {
                    "source": r.source,
                    "metric": r.metric,
                    "expected": r.expected,
                    "actual": r.actual,
                    "message": r.message,
                }
                for r in self.failures
            ],
        }


def grab(
    path: str, pattern: str, group: int = 1, default: Optional[str] = None
) -> Optional[str]:
    try:
        text = PROJECT_ROOT.joinpath(path).read_text(encoding="utf-8")
        m = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        return m.group(group) if m else default
    except FileNotFoundError:
        return default


def validate_task_registry(report: ValidationReport) -> None:
    """Validate TASK_REGISTRY.yaml task count (if CANONICAL.tasks.total > 0)."""
    if CANONICAL["tasks"]["total"] == 0:
        return  # Unconfigured — skip

    registry_path = NAOS_ROOT / "TASK_REGISTRY.yaml"
    try:
        text = registry_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        report.results.append(
            ValidationResult(
                source="naos/TASK_REGISTRY.yaml",
                metric="tasks.total",
                expected=CANONICAL["tasks"]["total"],
                actual="FILE_NOT_FOUND",
                passed=False,
                message=f"{registry_path} not found",
            )
        )
        return

    # Count task entries
    task_count = len(re.findall(r"^\s*- id:", text, re.MULTILINE))

    total_match = re.search(r"total_tasks:\s*(\d+)", text)
    declared_total = int(total_match.group(1)) if total_match else task_count

    report.results.append(
        ValidationResult(
            source="naos/TASK_REGISTRY.yaml",
            metric="tasks.total",
            expected=CANONICAL["tasks"]["total"],
            actual=declared_total,
            passed=declared_total == CANONICAL["tasks"]["total"],
            message=f"TASK_REGISTRY declares {declared_total}, canonical is {CANONICAL['tasks']['total']}",
        )
    )


def validate_project_status(report: ValidationReport) -> None:
    """Validate naos/PROJECT_STATUS.md metrics (if CANONICAL values > 0)."""
    if CANONICAL["requirements"]["total"] == 0:
        return  # Unconfigured — skip

    status_path = NAOS_ROOT / "PROJECT_STATUS.md"
    try:
        text = status_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return  # File may not exist yet on fresh projects

    m = re.search(r"(\d+)/(\d+)\s*requirements", text, re.I)
    if m:
        actual_delivered = int(m.group(1))
        actual_total = int(m.group(2))
        report.results.append(
            ValidationResult(
                source="naos/PROJECT_STATUS.md",
                metric="requirements.total",
                expected=CANONICAL["requirements"]["total"],
                actual=actual_total,
                passed=actual_total == CANONICAL["requirements"]["total"],
                message=f"PROJECT_STATUS says {actual_total}, canonical is {CANONICAL['requirements']['total']}",
            )
        )
        report.results.append(
            ValidationResult(
                source="naos/PROJECT_STATUS.md",
                metric="requirements.delivered",
                expected=CANONICAL["requirements"]["delivered"],
                actual=actual_delivered,
                passed=actual_delivered == CANONICAL["requirements"]["delivered"],
                message=f"PROJECT_STATUS says {actual_delivered} delivered, canonical is {CANONICAL['requirements']['delivered']}",
            )
        )


def validate_governance_truth_table(report: ValidationReport) -> None:
    """Check that naos/governance/GOVERNANCE_TRUTH_TABLE.md exists and has content."""
    truth_path = NAOS_ROOT / "governance" / "GOVERNANCE_TRUTH_TABLE.md"
    if not truth_path.exists():
        report.results.append(
            ValidationResult(
                source="naos/governance/GOVERNANCE_TRUTH_TABLE.md",
                metric="file.exists",
                expected=True,
                actual=False,
                passed=False,
                message="GOVERNANCE_TRUTH_TABLE.md is missing — create it with canonical values",
            )
        )
        return

    text = truth_path.read_text(encoding="utf-8")
    if len(text.strip()) < 100:
        report.results.append(
            ValidationResult(
                source="naos/governance/GOVERNANCE_TRUTH_TABLE.md",
                metric="file.non_empty",
                expected="populated",
                actual=f"{len(text.strip())} chars",
                passed=False,
                message="GOVERNANCE_TRUTH_TABLE.md exists but appears empty",
            )
        )
    else:
        report.results.append(
            ValidationResult(
                source="naos/governance/GOVERNANCE_TRUTH_TABLE.md",
                metric="file.exists",
                expected=True,
                actual=True,
                passed=True,
                message="Truth table present and populated",
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate governance truth consistency"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--fix", action="store_true", help="Attempt to fix drift (not implemented)"
    )
    args = parser.parse_args()

    report = ValidationReport()

    print("🔍 Validating governance truth...")

    if os.getenv("NAOS_ROOT") is None and is_kit_source_root(PROJECT_ROOT):
        print("SKIP: governance truth validation applies to initialized NAOS-governed projects,")
        print("      not the NAOS kit source tree. Run this from a project created with")
        print("      `naos init`, or set NAOS_ROOT explicitly.")
        return 0

    print(f"   Canonical source: {NAOS_ROOT}/governance/GOVERNANCE_TRUTH_TABLE.md")
    print()

    validate_task_registry(report)
    validate_project_status(report)
    validate_governance_truth_table(report)

    if args.verbose or not report.passed:
        print(json.dumps(report.to_dict(), indent=2))

    if not report.results:
        print("ℹ️  No canonical values configured yet.")
        print(
            "   Update the CANONICAL dict in this script after running `make -f Makefile.naos gov-refresh`."
        )
        return 0

    if report.passed:
        print(f"\n✅ All {len(report.results)} governance checks passed")
        return 0

    print(f"\n❌ {len(report.failures)} governance check(s) failed:")
    for f in report.failures:
        print(f"   - {f.source}: {f.metric}")
        print(f"     Expected: {f.expected}")
        print(f"     Actual:   {f.actual}")
    print()
    print("Fix: update documents to match naos/governance/GOVERNANCE_TRUTH_TABLE.md")
    print("     Then update the CANONICAL dict in this script.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
