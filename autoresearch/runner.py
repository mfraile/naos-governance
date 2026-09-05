#!/usr/bin/env python3
"""
NAOS Deterministic Conformance Review Runner.

Implements: deterministic conformance mode only, static file-first checks.
Specification: task_battery/portable_scenarios.yaml
Rationale: The 49 portable scenarios are inert data without this runner.
           Conformance mode verifies a kit-scaffolded project has the required
           governance files. It uses no LLM, API key, behavioral grading,
           semantic inference, provider setup, or network service.

Usage:
  python runner.py --conformance [--project-root PATH] [--battery PATH] [--output PATH]
  python runner.py --audit [--project-root PATH] [--profile PROFILE] [--output PATH]
  python runner.py --drift --baseline PATH [--project-root PATH] [--profile PROFILE] [--output PATH]
  python runner.py --assess [--project-root PATH] [--profile PROFILE] [--output PATH]

Exit codes:
  0 — all checks pass
  1 — one or more checks fail
  2 — usage/IO error

Audit/drift/assess modes delegate to deterministic StaticGrader assessment
reporting only. They do not run LLMGrader, call models/APIs/providers, infer
semantic drift, approve work, certify compliance, or promote maturity.
"""
# ID: F-AUTORES | CAT: KIT | STATUS: ACTIVE

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import NamedTuple

import yaml  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_RUNNER_DIR = Path(__file__).resolve().parent
_KIT_DIR = _RUNNER_DIR.parent
for _script_dir in (_KIT_DIR / "scripts", _KIT_DIR.parent / "scripts"):
    if _script_dir.is_dir() and str(_script_dir) not in sys.path:
        sys.path.insert(0, str(_script_dir))
DEFAULT_BATTERY = (
    _RUNNER_DIR / "task_battery" / "portable_scenarios.yaml"
    if (_RUNNER_DIR / "task_battery" / "portable_scenarios.yaml").exists()
    else _KIT_DIR / "task_battery" / "portable_scenarios.yaml"
)


def is_kit_source_root(root: Path) -> bool:
    """Return True when PATH is the NAOS kit source tree, not an initialized project."""
    return (
        (root / "pyproject.toml").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / "naos" / "TASK_REGISTRY.yaml").exists()
    )

# ---------------------------------------------------------------------------
# Structural governance checks
# Every kit-scaffolded project (any tier) must have these files/dirs.
# ---------------------------------------------------------------------------
STRUCTURAL_CHECKS: list[tuple[str, str]] = [
    (".ai/RULES.md", "Governance rules (.ai/RULES.md)"),
    (".github/copilot-instructions.md", "Agent instructions (copilot-instructions.md)"),
    ("naos/TASK_REGISTRY.yaml", "Task registry (TASK_REGISTRY.yaml)"),
    ("naos/DASHBOARD.md", "Governance dashboard (run make -f Makefile.naos gov-refresh)"),
    ("specs/", "Specifications directory (specs/)"),
    (".githooks/pre-commit", "Pre-commit hook (.githooks/pre-commit)"),
]

# Context_files paths that are known ADAPT placeholders (vary per project).
# These are skipped in battery context-file checks to avoid false negatives.
ADAPT_PATHS: frozenset[str] = frozenset(
    {
        "src",
        "src/",
        "tests",
        "tests/",
        "frontend",
        "frontend/",
        "configs",
        "configs/",
        ".cursorrules",
        "configs/ai_models.yaml",
        "configs/naos_governance_profiles.yaml",
        ".github/instructions/docker-deployment.instructions.md",
        ".github/instructions/session-management.instructions.md",
        ".github/instructions/ui-design.instructions.md",
        "kit/archetypes/django-postgresql/profile.yaml",
        "requirements.txt",
        "src/api",
        "src/api/",
        ".github/agents/",
    }
)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
class CheckResult(NamedTuple):
    name: str
    passed: bool
    note: str


# ---------------------------------------------------------------------------
# Battery loading
# ---------------------------------------------------------------------------
def load_battery(battery_path: Path) -> list[dict]:
    """Parse the portable_scenarios.yaml battery. Exits on YAML error."""
    try:
        data = yaml.safe_load(battery_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"[ERROR] Failed to parse battery '{battery_path}': {exc}")
        sys.exit(2)
    except OSError as exc:
        print(f"[ERROR] Cannot read battery '{battery_path}': {exc}")
        sys.exit(2)
    if not isinstance(data, dict) or "scenarios" not in data:
        print(f"[ERROR] Battery missing 'scenarios' key: {battery_path}")
        sys.exit(2)
    return data["scenarios"]


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------
def run_structural_checks(root: Path) -> list[CheckResult]:
    """Check that required governance files / dirs are present."""
    results: list[CheckResult] = []
    for rel, description in STRUCTURAL_CHECKS:
        full = root / rel
        if rel.endswith("/"):
            passed = full.is_dir()
        else:
            passed = full.is_file()
        results.append(CheckResult(description, passed, rel))
    return results


def run_registry_validation(root: Path) -> list[CheckResult]:
    """Validate naos/TASK_REGISTRY.yaml is parseable YAML."""
    reg_path = root / "naos" / "TASK_REGISTRY.yaml"
    if not reg_path.is_file():
        return []  # already caught by structural check
    try:
        yaml.safe_load(reg_path.read_text(encoding="utf-8"))
        return [CheckResult("TASK_REGISTRY.yaml is valid YAML", True, str(reg_path))]
    except yaml.YAMLError as exc:
        return [CheckResult("TASK_REGISTRY.yaml is valid YAML", False, str(exc))]


def run_frontmatter_checks(root: Path) -> list[CheckResult]:
    """Validate generated agent, skill, and instruction frontmatter when validators are installed."""
    validators_dir = root / "scripts" / "validators"
    if not validators_dir.is_dir():
        return []

    sys.path.insert(0, str(root))
    try:
        from scripts.validators.validate_agents import default_agent_files, validate_agent_files
        from scripts.validators.validate_instructions import (
            default_instruction_files,
            validate_instruction_files,
        )
        from scripts.validators.validate_skills import default_skill_files, validate_skill_files
    except ModuleNotFoundError as exc:
        return [CheckResult("Frontmatter validators import", False, str(exc))]

    results: list[CheckResult] = []
    validator_runs = [
        ("Agent frontmatter", default_agent_files(root), validate_agent_files),
        ("Skill frontmatter", default_skill_files(root), validate_skill_files),
        ("Instruction frontmatter", default_instruction_files(root), validate_instruction_files),
    ]
    for label, files, validator in validator_runs:
        if not files:
            results.append(CheckResult(f"{label}: no applicable files", True, "no files copied for this tier"))
            continue
        validation_results = validator(files)
        for validation_result in validation_results:
            try:
                rel = validation_result.path.resolve().relative_to(root.resolve())
            except ValueError:
                rel = validation_result.path
            results.append(
                CheckResult(
                    f"{label}: {rel} [{validation_result.check}]",
                    validation_result.passed,
                    validation_result.message,
                )
            )
    return results


# ---------------------------------------------------------------------------
# Battery context-file checks
# ---------------------------------------------------------------------------
def extract_context_file_paths(scenarios: list[dict]) -> list[str]:
    """Return sorted unique non-ADAPT context_file paths from all scenarios."""
    seen: set[str] = set()
    for scenario in scenarios:
        for raw_path in scenario.get("context_files", []):
            p = str(raw_path).strip()
            # Normalise: strip trailing slash for the comparison key
            norm = p.rstrip("/")
            if norm in ADAPT_PATHS or (norm + "/") in ADAPT_PATHS:
                continue
            if not p or p.startswith("["):
                continue
            seen.add(p)
    return sorted(seen)


def run_battery_checks(root: Path, scenarios: list[dict]) -> list[CheckResult]:
    """Check that non-ADAPT context_files referenced by scenarios exist."""
    context_paths = extract_context_file_paths(scenarios)
    if not context_paths:
        return []
    results: list[CheckResult] = []
    for p in context_paths:
        full = root / p
        passed = full.exists()
        results.append(CheckResult(f"Scenario context: {p}", passed, p))
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _print_section(title: str, results: list[CheckResult]) -> None:
    if not results:
        return
    width = 62
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")
    for r in results:
        status = "✓ PASS" if r.passed else "✗ FAIL"
        print(f"  {status:8}  {r.name}")
        if not r.passed:
            print(f"            missing: {r.note}")
    print(f"{'─' * width}")


# ---------------------------------------------------------------------------
# Main conformance flow
# ---------------------------------------------------------------------------
def _write_conformance_json(
    output_path: Path,
    structural: list[CheckResult],
    frontmatter_checks: list[CheckResult],
    battery_checks: list[CheckResult],
    scenarios: list[dict],
) -> None:
    """Write conformance results as structured JSON for dashboard consumption."""
    all_results = structural + frontmatter_checks + battery_checks
    total = len(all_results)
    n_pass = sum(1 for r in all_results if r.passed)
    n_struct = len(structural)
    n_struct_pass = sum(1 for r in structural if r.passed)
    n_front = len(frontmatter_checks)
    n_front_pass = sum(1 for r in frontmatter_checks if r.passed)
    n_batt = len(battery_checks)
    n_batt_pass = sum(1 for r in battery_checks if r.passed)

    data = {
        "run_date": date.today().isoformat(),
        "mode": "conformance",
        "structural_checks": {
            "passed": n_struct_pass,
            "total": n_struct,
            "score": round(n_struct_pass / n_struct, 3) if n_struct else None,
        },
        "frontmatter_checks": {
            "passed": n_front_pass,
            "total": n_front,
            "score": round(n_front_pass / n_front, 3) if n_front else None,
            "results": [
                {"name": r.name, "passed": r.passed, "note": r.note}
                for r in frontmatter_checks
            ],
        },
        "battery_checks": {
            "passed": n_batt_pass,
            "total": n_batt,
            "score": round(n_batt_pass / n_batt, 3) if n_batt else None,
        },
        # Behavioral dimensions require a future/project-configured evaluator. null = not run.
        "dimensions": {
            "D1_rule_compliance": None,
            "D2_agent_instructions": None,
            "D3_scoped_instructions": None,
            "D4_prompt_templates": None,
            "D5_efficiency": None,
            "D6_portability": None,
            "D7_session_hygiene": None,
            "D8_ai_output_quality": None,
        },
        "overall_conformance": round(n_pass / total, 3) if total else None,
        "scenarios_run": len(scenarios),
        "cost_usd": 0.0,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  Written → {output_path}")


def run_conformance(project_root: Path, battery_path: Path, output_path: Path | None = None) -> int:
    """Run static conformance checks. Returns 0 on full pass, 1 on failures."""
    print(f"\nNAOS Conformance Check")
    print(f"  Project : {project_root}")
    print(f"  Battery : {battery_path}")

    if is_kit_source_root(project_root):
        print("  Mode    : kit source tree")
        print()
        print("  SKIP: --conformance validates initialized NAOS-governed projects.")
        print("        This directory is the NAOS kit source tree; use a project")
        print("        generated with `naos init` or pass --project-root to one.\n")
        return 0

    scenarios = load_battery(battery_path)
    print(f"  Loaded {len(scenarios)} scenarios")

    # --- checks ---
    structural = run_structural_checks(project_root)
    structural += run_registry_validation(project_root)
    frontmatter_checks = run_frontmatter_checks(project_root)
    battery_checks = run_battery_checks(project_root, scenarios)

    _print_section("Structural Governance Checks", structural)
    _print_section("Agent / Skill / Instruction Frontmatter Checks", frontmatter_checks)
    _print_section("Battery Context File Checks", battery_checks)

    all_results = structural + frontmatter_checks + battery_checks
    total = len(all_results)
    n_pass = sum(1 for r in all_results if r.passed)
    n_fail = total - n_pass

    print(f"\n  Result: {n_pass}/{total} checks passed", end="")
    if n_fail:
        print(f"  ← {n_fail} FAILED")
        print("  Fix the missing files above, then re-run --conformance.\n")
        if output_path is not None:
            _write_conformance_json(output_path, structural, frontmatter_checks, battery_checks, scenarios)
        return 1
    print("  ✓ All checks passed.\n")
    if output_path is not None:
        _write_conformance_json(output_path, structural, frontmatter_checks, battery_checks, scenarios)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="runner.py",
        description=(
            "NAOS Deterministic Conformance Review Runner — static, file-first "
            "conformance plus deterministic audit/drift/assess review inputs "
            "with no LLM or API key required"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python runner.py --conformance\n"
            "  python runner.py --conformance --project-root /path/to/project\n"
            "  python runner.py --conformance --battery custom_battery.yaml\n"
            "  python runner.py --conformance --output naos/reports/conformance_latest.json\n"
            "  python runner.py --audit --profile standard\n"
            "  python runner.py --drift --baseline naos/reports/grader_assessment_baseline.json\n"
            "  python runner.py --assess --output naos/reports/grader_assessment.json\n"
        ),
    )
    p.add_argument(
        "--conformance",
        action="store_true",
        help="Run deterministic static conformance checks (no LLM, API key, or behavioral grading required)",
    )
    p.add_argument(
        "--audit",
        action="store_true",
        help="Build deterministic StaticGrader audit review input; not audit approval or certification",
    )
    p.add_argument(
        "--drift",
        action="store_true",
        help="Compare deterministic grader reports against a declared baseline; no semantic drift inference",
    )
    p.add_argument(
        "--assess",
        action="store_true",
        help="Build posture summary from deterministic grading/readiness metadata; not certification",
    )
    p.add_argument(
        "--project-root",
        default=".",
        metavar="PATH",
        help="Project root to check (default: current directory)",
    )
    p.add_argument(
        "--battery",
        default=str(DEFAULT_BATTERY),
        metavar="PATH",
        help=f"Scenario battery YAML (default: {DEFAULT_BATTERY})",
    )
    p.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help="Write structured JSON results to PATH (e.g. naos/reports/conformance_latest.json)",
    )
    p.add_argument("--profile", default=None, help="NAOS profile for audit/drift/assess modes")
    p.add_argument("--naos-root", default=None, help="NAOS root directory for audit/drift/assess modes")
    p.add_argument("--policy", default=None, help="Policy path for audit/drift/assess modes")
    p.add_argument("--baseline", default=None, metavar="PATH", help="Baseline report path for --drift")
    p.add_argument("--trace-report", default=None, metavar="PATH", help="Trace validation report path")
    p.add_argument("--trace-file", default=None, metavar="PATH", help="Trace events YAML path")
    p.add_argument("--static-grader-report", default=None, metavar="PATH", help="StaticGrader report path")
    p.add_argument("--json", action="store_true", help="Print audit/drift/assess report JSON")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    requested_modes = [args.conformance, args.audit, args.drift, args.assess]
    if sum(1 for mode in requested_modes if mode) > 1:
        print("[ERROR] Choose exactly one mode: --conformance, --audit, --drift, or --assess")
        sys.exit(2)

    if not any(requested_modes):
        parser.print_help()
        print(
            "\nNote: audit/drift/assess are deterministic review-input modes. "
            "They use StaticGrader metadata only and do not provide audit approval, "
            "certification, semantic drift inference, LLM runtime, or compliance determination."
        )
        sys.exit(0)

    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        print(f"[ERROR] Project root not found: {project_root}")
        sys.exit(2)

    if args.audit or args.drift or args.assess:
        try:
            import naos_grader_assessment
        except ModuleNotFoundError as exc:
            print(f"[ERROR] Grader assessment script is not available: {exc}")
            sys.exit(2)
        mode = "audit" if args.audit else "drift" if args.drift else "assess"
        delegated_args = ["--mode", mode, "--project-root", str(project_root)]
        if args.profile:
            delegated_args.extend(["--profile", args.profile])
        if args.naos_root:
            delegated_args.extend(["--naos-root", args.naos_root])
        if args.policy:
            delegated_args.extend(["--policy", args.policy])
        if args.baseline:
            delegated_args.extend(["--baseline", args.baseline])
        if args.trace_report:
            delegated_args.extend(["--trace-report", args.trace_report])
        if args.trace_file:
            delegated_args.extend(["--trace-file", args.trace_file])
        if args.static_grader_report:
            delegated_args.extend(["--static-grader-report", args.static_grader_report])
        if args.output:
            delegated_args.extend(["--output", args.output])
        if args.json:
            delegated_args.append("--json")
        sys.exit(naos_grader_assessment.main(delegated_args))

    battery_path = Path(args.battery)
    output_path = Path(args.output) if args.output else None
    if not battery_path.exists():
        print(f"[ERROR] Battery file not found: {battery_path}")
        sys.exit(2)

    sys.exit(run_conformance(project_root, battery_path, output_path))


if __name__ == "__main__":
    main()
