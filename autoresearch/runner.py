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
import hashlib
import importlib.util
import json
import sys
import types
import uuid
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import NamedTuple

import yaml  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_RUNNER_DIR = Path(__file__).resolve().parent
_KIT_DIR = _RUNNER_DIR.parent
# Bind runtime code to this runner, never to the inspected project or a
# fallback ancestor. The complete path literal is remapped by brownfield init.
_RUNTIME_ROOT = _KIT_DIR.parent if _KIT_DIR.name == ".github" else _KIT_DIR
_SCRIPT_DIR = _RUNTIME_ROOT / Path("scripts/naos_console.py").parent
if _SCRIPT_DIR.is_dir() and str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
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


@contextmanager
def frontmatter_validators():
    """Load the shipped modules by path in a private, temporary namespace."""
    validators_dir = _SCRIPT_DIR / "validators"
    names = ("frontmatter_utils", "validate_agents", "validate_skills", "validate_instructions")
    paths = {name: validators_dir / f"{name}.py" for name in names}
    for path in paths.values():
        if not path.is_file() or not path.resolve().is_relative_to(_SCRIPT_DIR.resolve()):
            raise ImportError(f"Shipped validator unavailable: {path.name}")
    namespace = "_naos_conformance_validators_" + uuid.uuid4().hex
    package = types.ModuleType(namespace)
    package.__path__ = []  # All allowed siblings are loaded explicitly below.
    sys.modules[namespace] = package
    modules = {}
    try:
        for name, path in paths.items():
            qualified_name = f"{namespace}.{name}"
            spec = importlib.util.spec_from_file_location(qualified_name, path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot load shipped validator: {path.name}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[qualified_name] = module
            spec.loader.exec_module(module)
            modules[name] = module
        yield modules
    finally:
        for name in list(sys.modules):
            if name == namespace or name.startswith(namespace + "."):
                del sys.modules[name]


def run_frontmatter_checks(root: Path) -> list[CheckResult]:
    """Inspect the target using this runner's shipped frontmatter validators."""
    results: list[CheckResult] = []
    try:
        with frontmatter_validators() as modules:
            agents = modules["validate_agents"]
            skills = modules["validate_skills"]
            instructions = modules["validate_instructions"]
            validator_runs = [
                ("Agent frontmatter", agents.default_agent_files(root), agents.validate_agent_files),
                ("Skill frontmatter", skills.default_skill_files(root), skills.validate_skill_files),
                ("Instruction frontmatter", instructions.default_instruction_files(root), instructions.validate_instruction_files),
            ]
            for label, files, validator in validator_runs:
                validation_results = validator(files, root=root)
                if not files:
                    results.append(CheckResult(f"{label}: no applicable files", True, "no files copied for this tier"))
                    continue
                for validation_result in validation_results:
                    try:
                        rel = validation_result.path.resolve().relative_to(root.resolve())
                    except ValueError:
                        rel = validation_result.path
                    results.append(CheckResult(
                        f"{label}: {rel} [{validation_result.check}]",
                        validation_result.passed,
                        validation_result.message,
                    ))
    except Exception as exc:
        results.append(CheckResult("Shipped frontmatter validators", False,
                                   f"Frontmatter validation unavailable ({type(exc).__name__}): {exc}; restore the shipped runtime or correct metadata scope and retry."))
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
        warning = r.note.startswith("WARNING: ")
        status = "⚠ WARN" if warning else ("✓ PASS" if r.passed else "✗ FAIL")
        print(f"  {status:8}  {r.name}")
        if warning:
            print(f"            {r.note}")
        elif not r.passed:
            print(f"            missing: {r.note}")
    print(f"{'─' * width}")


# ---------------------------------------------------------------------------
# Main conformance flow
# ---------------------------------------------------------------------------
def _conformance_payload(
    structural: list[CheckResult],
    frontmatter_checks: list[CheckResult],
    battery_checks: list[CheckResult],
    scenarios: list[dict],
) -> dict:
    """Package the actual existing checks without changing their interpretation."""
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

    return data


def _conformance_source_binding(project_root: Path, battery_path: Path) -> dict:
    """Bind exact read inputs and source-owned validator implementation bytes.

    Existence-only checks remain existence observations, including the derived
    dashboard. They do not acquire authored-content authority through hashing.
    """
    from naos_ai_surfaces import checked_path
    root = project_root.resolve(strict=True)
    battery = battery_path.absolute()
    # Inspect aliases lexically, before resolving an operand or opening it.
    checked_path(Path(battery.anchor), battery.relative_to(Path(battery.anchor)).as_posix())
    if battery == DEFAULT_BATTERY.absolute():
        selection = {"kind": "shipped_default"}
    elif battery.is_relative_to(root):
        selection = {"kind": "project", "ref": battery.relative_to(root).as_posix()}
    else:
        selection = {"kind": "external_unqualified"}
    if battery.is_relative_to(root):
        checked_path(root, battery.relative_to(root).as_posix())
    bindings = {"battery_sha256": hashlib.sha256(battery.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    sources = {}
    # Default-file discovery resolves paths. Reject aliases in its fixed input
    # directories first, so discovery cannot hide a linked markdown operand.
    for ref in ("templates/agents", "templates/skills", "templates/instructions",
                ".github/agents", ".github/skills", ".github/instructions"):
        directory = checked_path(root, ref)
        if directory.is_dir():
            for item in directory.rglob("*"):
                checked_path(root, item.relative_to(root).as_posix())
    with frontmatter_validators() as modules:
        for name, module in modules.items():
            path = Path(module.__file__)
            sources["validator:" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for module, method in ((modules["validate_agents"], "default_agent_files"),
                               (modules["validate_skills"], "default_skill_files"),
                               (modules["validate_instructions"], "default_instruction_files")):
            for path in getattr(module, method)(root):
                ref = path.absolute().relative_to(root).as_posix()
                checked_path(root, ref)
                sources["project:" + ref] = hashlib.sha256(path.read_bytes()).hexdigest()
    for ref in ("naos/TASK_REGISTRY.yaml", "naos/ai_metadata_scope.yaml"):
        path = checked_path(root, ref)
        if path.is_file():
            sources["project:" + ref] = hashlib.sha256(path.read_bytes()).hexdigest()
    scenarios = load_battery(battery)
    presence = {}
    for ref, _ in STRUCTURAL_CHECKS:
        path = checked_path(root, ref.rstrip("/"))
        presence["structural:" + ref] = path.is_dir() if ref.endswith("/") else path.is_file()
    for ref in extract_context_file_paths(scenarios):
        path = checked_path(root, ref.rstrip("/"))
        presence["battery:" + ref] = path.exists()
    bindings.update(battery_selection=selection, source_sha256=sources, selected_path_presence=presence)
    return bindings


def build_conformance_report(project_root: Path, battery_path: Path, *, profile=None,
                             naos_root=None, policy_path=None) -> dict:
    """Reproduce the actual local deterministic checks read-only; no CLI execution."""
    from naos_policy import controlled_utc_now_text, default_naos_root, load_policy, normalize_profile
    root = project_root.resolve(strict=True)
    policy = load_policy(policy_path, naos_root, root)
    selected_root = naos_root or default_naos_root(policy)
    selected_profile = normalize_profile(profile, policy)
    before = _conformance_source_binding(root, battery_path)
    scenarios = load_battery(battery_path)
    structural = run_structural_checks(root) + run_registry_validation(root)
    frontmatter = run_frontmatter_checks(root)
    battery = run_battery_checks(root, scenarios)
    data = _conformance_payload(structural, frontmatter, battery, scenarios)
    if _conformance_source_binding(root, battery_path) != before:
        raise ValueError("Conformance inputs changed during observation")
    data.update(schema="naos.conformance_latest.v1", generated_at=controlled_utc_now_text(),
                profile=selected_profile, project_root=str(root), naos_root=selected_root,
                battery_path=str(battery_path.absolute()), source_binding=before,
                status=("pass" if structural + frontmatter + battery
                        and all(item.passed for item in structural + frontmatter + battery) else "failed"),
                human_review_required=True,
                claim_ceiling="deterministic_local_conformance_structure_only",
                not_claimed=["behavioral correctness", "operating effectiveness", "approval", "maturity promotion"])
    return data


def _write_conformance_json(output_path: Path, structural: list[CheckResult],
                            frontmatter_checks: list[CheckResult], battery_checks: list[CheckResult],
                            scenarios: list[dict], *, report: dict | None = None) -> None:
    """Keep compatibility with existing legacy fixtures; real runs pass their report."""
    data = report if report is not None else _conformance_payload(structural, frontmatter_checks, battery_checks, scenarios)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  Written → {output_path}")


def run_conformance(project_root: Path, battery_path: Path, output_path: Path | None = None,
                    *, profile=None, naos_root=None, policy_path=None) -> int:
    """Run static conformance checks. Returns 0 on full pass, 1 on failures."""
    print("\nNAOS Conformance Check")
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
    report = None
    if output_path is not None:
        try:
            report = build_conformance_report(project_root, battery_path, profile=profile,
                naos_root=naos_root, policy_path=policy_path)
            original = _conformance_payload(structural, frontmatter_checks, battery_checks, scenarios)
            if any(report[key] != value for key, value in original.items() if key != "run_date"):
                raise ValueError("Conformance checks changed before publication")
        except (OSError, ValueError, ImportError, TypeError, KeyError) as exc:
            # Preserve the existing command's observed checks/exit behavior.
            # An unbound legacy report remains unresolved for typed maturity.
            report = None
            print(f"  Source binding unavailable ({type(exc).__name__}); writing legacy observation only")
    total = len(all_results)
    n_pass = sum(1 for r in all_results if r.passed)
    n_fail = total - n_pass

    print(f"\n  Result: {n_pass}/{total} checks passed", end="")
    if n_fail:
        print(f"  ← {n_fail} FAILED")
        print("  Fix the missing files above, then re-run --conformance.\n")
        if output_path is not None:
            _write_conformance_json(output_path, structural, frontmatter_checks, battery_checks, scenarios, report=report)
        return 1
    print("  ✓ All checks passed.\n")
    if output_path is not None:
        _write_conformance_json(output_path, structural, frontmatter_checks, battery_checks, scenarios, report=report)
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
    from naos_console import configure_console_output

    configure_console_output()
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

    sys.exit(run_conformance(project_root, battery_path, output_path,
        profile=args.profile, naos_root=args.naos_root, policy_path=args.policy))


if __name__ == "__main__":
    main()
