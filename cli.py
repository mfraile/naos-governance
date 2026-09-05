#!/usr/bin/env python3
"""
NAOS CLI — Governance-as-Code for AI-assisted software development.

Entry point for the `naos` command installed via `pip install naos-governance`.
Dispatches to `naos init` (scaffolder), `naos add` (progressive enhancement),
`naos upgrade` (digest-bound profile transitions), and `naos memory` (Engram onboarding).

Also supports direct execution: `python -m naos_governance.cli`
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import inspect
import os
import shutil
import sys
from pathlib import Path
from typing import Callable


SCRIPT_COMMANDS = {
    "adopt": "scripts/naos_adopt.py",
    "preflight": "scripts/naos_preflight.py",
    "intake": "scripts/naos_intake.py",
    "install-plan": "scripts/naos_install_plan.py",
    "existing-resource-inventory": "scripts/naos_existing_resource_inventory.py",
    "ai-artifact-inventory": "scripts/naos_ai_artifact_inventory.py",
    "ai-artifact-reconcile": "scripts/naos_ai_artifact_reconcile.py",
    "ai-code-provenance": "scripts/naos_ai_code_provenance.py",
    "compliance-posture": "scripts/naos_compliance_posture.py",
    "memory-resource-inventory": "scripts/naos_memory_resource_inventory.py",
    "memory-resource-reconcile": "scripts/naos_memory_resource_reconcile.py",
    "mcp-resource-inventory": "scripts/naos_mcp_resource_inventory.py",
    "brownfield-baseline": "scripts/naos_brownfield_baseline.py",
    "requirements-reconstruct": "scripts/naos_requirements_reconstruct.py",
    "traceability-gap-register": "scripts/naos_traceability_gap_register.py",
    "install-decision-record": "scripts/naos_install_decision_record.py",
    "context-challenge": "scripts/naos_context_challenge.py",
    "repo-context-challenge": "scripts/naos_repo_context_challenge.py",
    "plan-challenge": "scripts/naos_plan_challenge.py",
    "decision-probe": "scripts/naos_decision_probe.py",
    "planning-gate-review": "scripts/naos_planning_gate_review.py",
    "claims": "scripts/naos_validate_claims.py",
    "capability-maturity": "scripts/naos_capability_maturity.py",
    "systemic-impact": "scripts/naos_systemic_impact.py",
    "module-headers": "scripts/naos_module_header_traceability.py",
    "spec-pack-contract": "scripts/naos_spec_pack_contract.py",
    "spec-pack-materialize": "scripts/naos_spec_pack_materialize.py",
    "spec-assembly-worksheet": "scripts/naos_spec_assembly_worksheet.py",
    "spec-cascade": "scripts/naos_detect_spec_drift.py",
    "control-plane-review": "scripts/naos_control_plane_review.py",
    "setup-recommendations": "scripts/naos_setup_recommendations.py",
    "governance-bypass-posture": "scripts/naos_governance_bypass_posture.py",
    "external-evidence-ingest": "scripts/naos_external_evidence_ingest.py",
    "evidence-attestation": "scripts/naos_evidence_attestation.py",
    "evidence-conflicts": "scripts/naos_evidence_conflicts.py",
    "memory-readiness": "scripts/naos_memory_context_readiness.py",
    "memory-access": "scripts/naos_memory_provider_access.py",
    "memory-use-policy": "scripts/naos_memory_use_policy.py",
    "learning-loop-review": "scripts/naos_learning_loop_review.py",
    "adapter-coherence": "scripts/naos_adapter_coherence.py",
    "task-context": "scripts/naos_task_context_pack.py",
    "task-lifecycle": "scripts/naos_task_lifecycle.py",
    "task-complete": "scripts/naos_task_lifecycle.py",
    "research-record": "scripts/naos_research_record.py",
    "composed-traceability": "scripts/naos_composed_traceability.py",
    "overlay-coexistence": "scripts/naos_overlay_coexistence.py",
    "task-claim": "scripts/naos_task_claims.py",
    "task-release": "scripts/naos_task_claims.py",
    "task-claims": "scripts/naos_task_claims.py",
    "context-index": "scripts/naos_local_context_index.py",
    "context-query": "scripts/naos_local_context_query.py",
    "repository-intelligence": "scripts/naos_repository_intelligence.py",
    "semantic-candidates": "scripts/naos_semantic_candidate_readiness.py",
    "graph-context": "scripts/naos_graph_context_readiness.py",
    "graph-query": "scripts/naos_graph_context_query.py",
    "session-id": "scripts/naos_session_identity.py",
    "operator-attribution": "scripts/naos_operator_attribution.py",
    "session-start": "scripts/naos_session_lifecycle.py",
    "session-checkpoint": "scripts/naos_session_lifecycle.py",
    "session-end": "scripts/naos_session_lifecycle.py",
    "audit-log": "scripts/naos_audit_log.py",
    "agent-traces": "scripts/naos_agent_trace_validate.py",
    "harness-trace-import": "scripts/naos_harness_trace_import.py",
    "ai-surface-budget": "scripts/naos_ai_surface_budget.py",
    "static-grader": "scripts/naos_static_grader.py",
    "grader-assessment": "scripts/naos_grader_assessment.py",
    "ai-component-inventory": "scripts/naos_ai_component_inventory.py",
    "agent-sponsor-registry": "scripts/naos_agent_sponsor_registry.py",
    "aivss-verify": "scripts/naos_aivss_arithmetic_verification.py",
    "model-policy": "scripts/naos_model_provider_policy.py",
    "agent-orchestration-plan": "scripts/naos_agent_orchestration_plan.py",
    "model-telemetry": "scripts/naos_model_telemetry_evidence.py",
    "failure-mode-posture": "scripts/naos_failure_mode_posture.py",
    "failure-mode-observations": "scripts/naos_failure_mode_observations.py",
    "opencode-config-hygiene": "scripts/naos_opencode_config_hygiene.py",
    "design-traceability": "scripts/naos_design_traceability.py",
    "ui-experience-quality": "scripts/naos_ui_experience_quality.py",
    "llm-grader-readiness": "scripts/naos_llm_grader_readiness.py",
    "behavioral-readiness": "scripts/naos_behavioral_governance_readiness.py",
    "sarif-export": "scripts/naos_sarif_export.py",
    "policy-overrides": "scripts/naos_policy_overrides.py",
    "pr-risk-classify": "scripts/naos_pr_risk_classification.py",
    "pr-governance-summary": "scripts/naos_pr_governance_summary.py",
    "agentic-workflow-review": "scripts/naos_agentic_workflow_review.py",
    "pre-implementation-alignment-review": "scripts/naos_pre_implementation_alignment_review.py",
    "calibration-shadow": "scripts/naos_calibration_shadow.py",
    "evidence-classification": "scripts/naos_evidence_classification.py",
    "cross-harness-review-readiness": "scripts/naos_cross_harness_review_readiness.py",
    "self-check": "scripts/naos_self_check.py",
    "roadmap-crosswalk": "scripts/naos_validate_roadmap_crosswalk.py",
    "function-index-health": "scripts/naos_function_index_health.py",
    "test-evidence-map": "scripts/naos_test_evidence_map.py",
    "test-evidence": "scripts/naos_validate_test_evidence.py",
    "ac-completion-evidence": "scripts/naos_ac_completion_evidence.py",
    "plan-coherence": "scripts/naos_plan_coherence.py",
    "duplicate-function-hygiene": "scripts/naos_duplicate_function_hygiene.py",
    "secret-hygiene": "scripts/naos_secret_hygiene.py",
    "test-quality-hygiene": "scripts/naos_test_quality_hygiene.py",
    "dependency-integrity": "scripts/naos_dependency_integrity.py",
    "package-reality": "scripts/naos_package_reality.py",
    "api-symbol-reality": "scripts/naos_api_symbol_reality.py",
    "secure-coding-controls": "scripts/naos_secure_coding_controls.py",
    "secure-coding-reporting": "scripts/naos_secure_coding_reporting.py",
    "evidence-pack": "scripts/naos_evidence_export.py",
    "evidence-sign": "scripts/naos_evidence_signing.py",
    "evidence-verify": "scripts/naos_evidence_signing.py",
    "dashboard": "scripts/workflows/generate_naos_dashboard.py",
    "gate-status": "scripts/naos_gate_status.py",
    "gate-evaluate": "scripts/naos_gate_evaluate.py",
}


def main() -> int:
    invoked_as = Path(sys.argv[0]).name
    if invoked_as in {"naos", "naos-governance"}:
        os.environ.setdefault("NAOS_INVOKED_CONSOLE", invoked_as)

    if len(sys.argv) < 2:
        _print_help()
        return 0

    if sys.argv[1] in ("--help", "-h"):
        if any(arg in ("--all", "all", "commands") for arg in sys.argv[2:]):
            _print_full_help()
        else:
            _print_help()
        return 0

    if sys.argv[1] in ("--version", "-V"):
        _print_version()
        return 0

    command = sys.argv[1]

    if command == "doctor":
        return _print_doctor()

    if command == "first-run":
        return _run_first_run(sys.argv[2:])

    if command == "commands" or (command == "help" and any(arg in ("--all", "all", "commands") for arg in sys.argv[2:])):
        _print_full_help()
        return 0

    if command == "help":
        _print_help()
        return 0

    # Rewrite argv so argparse in each subcommand sees the right prog name
    sys.argv = [f"naos {command}"] + sys.argv[2:]

    if command == "init":
        naos_init = _import_subcommand_module("naos_init")
        return naos_init.main()

    if command == "add":
        naos_add = _import_subcommand_module("naos_add")
        return naos_add.main()

    if command == "upgrade":
        naos_upgrade = _import_subcommand_module("naos_upgrade")
        return naos_upgrade.main()

    if command == "memory":
        naos_memory = _import_subcommand_module("naos_memory")
        return naos_memory.main()

    if command in SCRIPT_COMMANDS:
        return _run_script_command(command, SCRIPT_COMMANDS[command])

    print(f"  [ERROR] Unknown command: {command!r}")
    _print_help()
    return 1


def _import_subcommand_module(module_name: str):
    if __package__:
        return importlib.import_module(f".{module_name}", __package__)

    module_path = Path(__file__).resolve().parent / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load local subcommand module {module_name!r}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run_script_command(command: str, relative_path: str) -> int:
    """Delegate a CLI subcommand to an existing standalone NAOS script."""
    script_path = Path(__file__).resolve().parent / relative_path
    if not script_path.is_file():
        print(f"  [ERROR] Script for command {command!r} not found: {relative_path}")
        return 2

    module_name = f"_naos_cli_{command.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        print(f"  [ERROR] Could not load script for command {command!r}: {relative_path}")
        return 2
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    command_main = getattr(module, "main", None)
    if command_main is None:
        print(f"  [ERROR] Script for command {command!r} has no main()")
        return 2

    signature = inspect.signature(command_main)
    if len(signature.parameters) == 0:
        return int(command_main())
    return int(command_main(sys.argv[1:]))


def _run_nested_cli_command(command: str, args: list[str]) -> int:
    """Run an existing CLI command from another CLI command without a shell."""
    previous_argv = sys.argv[:]
    sys.argv = [f"naos {command}", *args]
    try:
        if command == "add":
            naos_add = _import_subcommand_module("naos_add")
            return int(naos_add.main())
        if command in SCRIPT_COMMANDS:
            return _run_script_command(command, SCRIPT_COMMANDS[command])
        print(f"  [ERROR] Unsupported nested command: {command!r}")
        return 2
    finally:
        sys.argv = previous_argv


def _run_first_run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="naos first-run",
        description=(
            "Run the safe NAOS first-contact route: doctor, adoption dry-run, "
            "setup recommendations, profile-baseline dry-run, evidence pack, "
            "and dashboard output."
        ),
    )
    parser.add_argument("project_path", nargs="?", default=".", help="Project root to inspect.")
    parser.add_argument(
        "--profile",
        choices=("quickstart", "lite", "standard", "assured"),
        default="standard",
        help="NAOS profile for first-run evidence (default: standard).",
    )
    parser.add_argument(
        "--mode",
        choices=("greenfield", "brownfield", "upgrade", "repair", "evaluation"),
        default="brownfield",
        help="Adoption mode for the dry-run report (default: brownfield).",
    )
    parser.add_argument(
        "--dashboard-json-output",
        default="naos/reports/dashboard_summary.json",
        help="Dashboard JSON summary output path, relative to the project by default.",
    )
    args = parser.parse_args(argv)

    project_path = Path(args.project_path).expanduser().resolve()
    if not project_path.exists():
        print(f"  [ERROR] Project path does not exist: {project_path}")
        return 2
    if not project_path.is_dir():
        print(f"  [ERROR] Project path is not a directory: {project_path}")
        return 2

    preferred = _preferred_cli_invocation()
    adoption_step: tuple[str, str, Callable[[], int]] = (
        "Adoption dry-run",
        f"{preferred} adopt . --mode {args.mode} --profile {args.profile} --dry-run --no-prompt",
        lambda: _run_nested_cli_command(
            "adopt",
            [
                ".",
                "--mode",
                args.mode,
                "--profile",
                args.profile,
                "--dry-run",
                "--no-prompt",
            ],
        ),
    )
    setup_step: tuple[str, str, Callable[[], int]] = (
        "Setup recommendations",
        f"{preferred} setup-recommendations --profile {args.profile}",
        lambda: _run_nested_cli_command(
            "setup-recommendations", ["--profile", args.profile]
        ),
    )
    steps: list[tuple[str, str, Callable[[], int]]] = [
        (
            "Doctor",
            "python -m naos_governance.cli doctor",
            _print_doctor,
        ),
    ]
    if args.mode in {"brownfield", "repair", "evaluation"}:
        steps.append(
            (
                "Repository-intelligence pre-start",
                f"{preferred} setup-recommendations --profile {args.profile} --no-write-preview",
                lambda: _run_nested_cli_command(
                    "setup-recommendations",
                    ["--profile", args.profile, "--no-write-preview"],
                ),
            )
        )
    steps.extend(
        [
            adoption_step,
            setup_step,
            (
            "Profile baseline dry-run",
            f"{preferred} add setup-module profile_baseline --profile {args.profile} --dry-run",
            lambda: _run_nested_cli_command(
                "add",
                [
                    "setup-module",
                    "profile_baseline",
                    "--profile",
                    args.profile,
                    "--dry-run",
                    "--project",
                    ".",
                ],
            ),
            ),
            (
            "Evidence pack",
            f"{preferred} evidence-pack --profile {args.profile}",
            lambda: _run_nested_cli_command("evidence-pack", ["--profile", args.profile]),
            ),
            (
            "Dashboard",
            f"{preferred} dashboard --profile {args.profile} --json-output {args.dashboard_json_output}",
            lambda: _run_nested_cli_command(
                "dashboard",
                [
                    "--profile",
                    args.profile,
                    "--json-output",
                    args.dashboard_json_output,
                ],
            ),
            ),
        ]
    )

    print("NAOS first run")
    print("")
    print(f"Project: {project_path}")
    print(f"Profile: {args.profile}")
    print(f"Mode: {args.mode}")
    print("")
    print("This route writes review reports only. It does not activate hooks,")
    print("overwrite protected files, call providers, write memory, approve maturity,")
    print("certify outcomes, prove compliance, or prove runtime safety.")

    previous_cwd = Path.cwd()
    failures: list[tuple[str, int]] = []
    try:
        os.chdir(project_path)
        for index, (title, command_text, runner) in enumerate(steps, start=1):
            print("")
            print(f"[{index}/{len(steps)}] {title}")
            print(f"  command: {command_text}")
            result = int(runner())
            print(f"  result: exit {result}")
            if result != 0:
                failures.append((title, result))
                break
    finally:
        os.chdir(previous_cwd)

    print("")
    if failures:
        guided_pause = (
            failures[0] == ("Adoption dry-run", 2)
            and args.mode in {"brownfield", "repair", "evaluation"}
        )
        if guided_pause:
            print("NAOS first-run paused before adoption reports were written.")
            print(
                "Activate and validate the recommended repository intelligence, "
                "then rerun first-run."
            )
        else:
            print("NAOS first-run stopped before completion.")
        for title, code in failures:
            print(f"- {title}: exit {code}")
        print("")
        if not guided_pause:
            print("Inspect the command output above. Fix the blocking issue, then rerun")
            print("`naos-governance first-run` or the specific failed command.")
        return failures[0][1]

    print("NAOS first-run completed.")
    print("")
    print("Generated review artifacts:")
    print("  naos/reports/adoption_summary.json")
    print("  naos/reports/setup_recommendations.json")
    print("  naos/evidence/evidence_pack.json")
    print("  naos/DASHBOARD.md")
    print(f"  {args.dashboard_json_output}")
    print("")
    print("Expected for an empty or early adopter project:")
    print("  `evidence-pack` may report `required_missing`; that means required")
    print("  evidence artifacts are not present yet, not that installation failed.")
    print("")
    print("Next review:")
    print("  1. Open naos/DASHBOARD.md.")
    print("  2. Review naos/reports/setup_recommendations.json.")
    print("  3. Apply selected setup modules only after a dry run.")
    return 0


def _print_version() -> None:
    try:
        from importlib.metadata import version

        ver = version("naos-governance")
    except Exception:
        try:
            from . import __version__

            ver = __version__
        except Exception:
            ver = "unknown"
    print(f"naos-governance {ver}")


def _detect_package_version() -> str:
    try:
        from importlib.metadata import version

        return version("naos-governance")
    except Exception:
        try:
            from . import __version__

            return __version__
        except Exception:
            return "unknown"


def _looks_like_naos_console_script(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        data = path.read_bytes()[:8192]
    except OSError:
        return False

    if b"\x00" in data:
        return False

    try:
        text = data.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return False

    expected_fragments = (
        "naos_governance.cli",
        "naos-governance",
        "from cli import main",
    )
    return any(fragment in text for fragment in expected_fragments)


def _resolved_command_status(command_name: str) -> tuple[str, str]:
    resolved = shutil.which(command_name)
    if resolved is None:
        return "missing", "not found on PATH"

    path = Path(resolved)
    if _looks_like_naos_console_script(path):
        return "ok", str(path)

    return "warning", str(path)


def _preferred_cli_invocation() -> str:
    alias_status, _alias_path = _resolved_command_status("naos-governance")
    if alias_status == "ok":
        return "naos-governance"
    naos_status, _naos_path = _resolved_command_status("naos")
    if naos_status == "ok":
        return "naos"
    return "python -m naos_governance.cli"


def _print_doctor() -> int:
    """Print a first-install diagnostic that avoids running intercepted commands."""
    module_path = Path(__file__).resolve()
    version = _detect_package_version()
    naos_status, naos_path = _resolved_command_status("naos")
    alias_status, alias_path = _resolved_command_status("naos-governance")

    status = "pass"
    if naos_status != "ok" and alias_status != "ok":
        status = "warning"

    print("NAOS doctor")
    print("")
    print(f"Status: {status}")
    print(f"Python: {sys.executable}")
    print(f"Package: naos-governance {version}")
    print(f"CLI module: {module_path}")
    print(f"Current directory: {Path.cwd()}")
    print("")
    print("Command resolution:")
    print(f"  naos: {naos_status} - {naos_path}")
    print(f"  naos-governance: {alias_status} - {alias_path}")
    print("")

    preferred = _preferred_cli_invocation()

    if status == "pass":
        print(f"Use `{preferred} --help` for the short start page.")
        print(f"Use `{preferred} commands` for the full command catalogue.")
    else:
        print("The package is importable through this Python environment, but no")
        print("PATH command clearly resolves to the installed NAOS CLI.")
        print("Use `python -m naos_governance.cli ...` until PATH is fixed, or")
        print("reinstall in the active environment so `naos-governance` is present.")
        print("If bare `naos` opens another tool, treat that as a local command")
        print("collision, not a NAOS validation failure.")

    print("")
    print("First-run examples:")
    print("  python -m naos_governance.cli doctor")
    print(f"  {preferred} first-run --profile standard --mode brownfield")
    print(f"  {preferred} first-run --profile standard --mode greenfield")
    print("")
    print("Doctor output is installation/path evidence only. It is not approval,")
    print("certification, compliance proof, secure-code proof, or runtime safety proof.")
    return 0


_HELP_INDENT = "    "
_USAGE_DESCRIPTION_COLUMN = 43
_EXAMPLE_DESCRIPTION_COLUMN = 47


_HELP_USAGE_ROWS = (
    ("naos init [project_path] [options]", "Scaffold governance files"),
    ("naos add <type> <name> [options]", "Add a governance artifact or setup module"),
    ("naos upgrade PROJECT --tier T [--dry-run] [--plan-out FILE]", "Plan a content-aware profile transition"),
    ("naos upgrade PROJECT --apply-plan FILE --expect-plan-digest SHA256", "Apply one exact immutable transition plan"),
    ("naos upgrade PROJECT --recover", "Recover managed-content transactions"),
    ("naos memory [explain|check|setup|status]", "Record/check Engram onboarding posture"),
    ("naos doctor", "Diagnose install, PATH, and command-resolution state"),
    ("naos first-run [project_path] [options]", "Run safe first-contact evidence route"),
    ("naos commands", "Show the full command catalogue"),
    ("naos adopt [project_path] [options]", "Orchestrate professional adoption evidence"),
    ("naos preflight [project_path] [options]", "Run adoption preflight checks"),
    ("naos intake [project_path] [options]", "Capture guided adoption intake"),
    ("naos install-plan [project_path] [options]", "Build reviewable install plan"),
    ("naos existing-resource-inventory [path]", "Inventory local docs/specs/tests/source"),
    ("naos ai-artifact-inventory [path]", "Inventory AI instructions/prompts/rules/hooks"),
    ("naos ai-artifact-reconcile [path]", "Record AI artifact disposition decisions"),
    ("naos ai-code-provenance [options]", "Compose review-only AI code provenance evidence"),
    ("naos compliance-posture [options]", "Compose review-only compliance posture evidence"),
    ("naos memory-resource-inventory [path]", "Inventory Engram/memory/MCP posture"),
    ("naos memory-resource-reconcile [path]", "Record memory/MCP disposition decisions"),
    ("naos mcp-resource-inventory [path]", "Inventory declared local MCP configs"),
    ("naos brownfield-baseline [path]", "Build brownfield baseline evidence"),
    ("naos requirements-reconstruct [path]", "Emit candidate requirements for review"),
    ("naos traceability-gap-register [path]", "Emit traceability gaps for review"),
    ("naos install-decision-record [path]", "Record adoption decisions and boundaries"),
    ("naos context-challenge [path]", "Challenge context before build"),
    ("naos repo-context-challenge [path]", "Challenge brownfield repository context"),
    ("naos plan-challenge [path]", "Challenge implementation/install plan"),
    ("naos decision-probe [path]", "Probe unresolved adoption decisions"),
    ("naos planning-gate-review [path]", "Review planning gate evidence"),
    ("naos claims [options]", "Validate project-local claims"),
    ("naos capability-maturity [options]", "Evaluate maturity readiness"),
    ("naos systemic-impact [options]", "Evaluate systemic impact review obligations"),
    ("naos module-headers [options]", "Evaluate canonical module-header traceability"),
    ("naos spec-pack-contract [options]", "Validate spec-pack template contract"),
    ("naos spec-pack-materialize [path]", "Copy missing profile-required spec files"),
    ("naos spec-assembly-worksheet [path]", "Map adoption evidence to specs for review"),
    ("naos spec-cascade [options]", "Evaluate spec-cascade coherence"),
    ("naos control-plane-review [options]", "Evaluate review/research routing items"),
    ("naos setup-recommendations [options]", "Recommend setup modules and next actions"),
    ("naos governance-bypass-posture [options]", "Report local hook/CI bypass posture"),
    ("naos external-evidence-ingest [options]", "Ingest local SARIF as unverified evidence"),
    ("naos evidence-attestation [options]", "Generate local digest/reviewer metadata report"),
    ("naos evidence-conflicts [options]", "Detect deterministic evidence/review conflicts"),
    ("naos memory-readiness [options]", "Evaluate memory/context governance readiness"),
    ("naos memory-access [options]", "Evaluate declared provider/MCP access posture"),
    ("naos memory-use-policy [options]", "Evaluate memory-use policy/review readiness"),
    ("naos learning-loop-review [options]", "Review governed learning lifecycle records"),
    ("naos adapter-coherence [options]", "Review Codex/plugin/adapter coherence"),
    ("naos task-context --task T-XXX [options]", "Generate bounded task context pack"),
    ("naos task-lifecycle --task T-XXX [options]", "Inspect exact active/completed task lifecycle state"),
    ("naos task-complete --task T-XXX [options]", "Record a native task completion transition"),
    ("naos research-record RECORD [options]", "Validate a structured research record without promoting its claims"),
    ("naos composed-traceability [options]", "Compose explicit task/spec/source/test/history links"),
    ("naos overlay-coexistence TARGET [options]", "Validate an isolated reversible brownfield sidecar overlay"),
    ("naos task-claim --task T-XXX [options]", "Claim task coordination metadata"),
    ("naos task-release --task T-XXX [options]", "Release task coordination metadata"),
    ("naos task-claims [options]", "Summarize task claims"),
    ("naos context-index [options]", "Build local generated context index"),
    ("naos context-query [options]", "Query local context index candidates"),
    ("naos repository-intelligence <plan|enroll|apply|validate|refresh|query|status|recover> [options]", "Manage source-bound brownfield repository intelligence"),
    ("naos semantic-candidates [options]", "Evaluate semantic candidate readiness"),
    ("naos graph-context [options]", "Evaluate graph-context readiness"),
    ("naos graph-query [options]", "Query bounded explicit graph-context links"),
    ("naos session-id [options]", "Create or reuse a session id and report namespace"),
    ("naos operator-attribution [options]", "Resolve local operator attribution for a run/session"),
    ("naos session-start --task T-XXX [options]", "Generate session-start report"),
    ("naos session-checkpoint --task T-XXX [options]", "Generate checkpoint report"),
    ("naos session-end --task T-XXX [options]", "Generate session-end report"),
    ("naos audit-log [options]", "Summarize append-only audit log events"),
    ("naos agent-traces [options]", "Validate declared agent trace events"),
    ("naos harness-trace-import --source traces.jsonl [options]", "Import local harness JSONL/NDJSON as declared trace events"),
    ("naos ai-surface-budget [options]", "Evaluate AI-surface context budget and health"),
    ("naos static-grader [options]", "Run deterministic StaticGrader structural checks"),
    ("naos grader-assessment [options]", "Build deterministic audit/drift/assess grading input"),
    ("naos ai-component-inventory [options]", "Build the declared AI component inventory"),
    ("naos agent-sponsor-registry [options]", "Validate opt-in agent sponsor declarations"),
    ("naos aivss-verify [options]", "Verify opt-in AIVSS-Agentic v0.8 arithmetic"),
    ("naos model-policy [options]", "Review model-provider declarations"),
    ("naos agent-orchestration-plan [options]", "Build a human-gated agent-work proposal"),
    ("naos model-telemetry [options]", "Review local model telemetry evidence"),
    ("naos failure-mode-posture [options]", "Review local failure-mode posture"),
    ("naos failure-mode-observations [options]", "Aggregate local report findings by failure mode"),
    ("naos opencode-config-hygiene [options]", "Review optional OpenCode config hygiene"),
    ("naos design-traceability [options]", "Review UI spec-object traceability declarations"),
    ("naos ui-experience-quality [options]", "Review UI experience quality evidence declarations"),
    ("naos llm-grader-readiness [options]", "Report readiness-only LLMGrader governance posture"),
    ("naos behavioral-readiness [options]", "Report behavioral governance baseline readiness and impacters"),
    ("naos sarif-export [options]", "Export NAOS findings to SARIF 2.1.0"),
    ("naos policy-overrides [options]", "Validate and merge static/global/team/operator policy overlays"),
    ("naos pr-risk-classify [options]", "Classify deterministic PR risk surfaces"),
    ("naos pr-governance-summary [options]", "Summarize PR-time NAOS governance evidence"),
    ("naos agentic-workflow-review [options]", "Review declared agentic coding workflow controls"),
    ("naos pre-implementation-alignment-review [options]", "Review Pre-Implementation Alignment artifact"),
    ("naos calibration-shadow [options]", "Compare deterministic reports to calibration-shadow expectations"),
    ("naos evidence-classification [options]", "Classify finding provenance for review"),
    ("naos cross-harness-review-readiness [options]", "Report future cross-harness/DSSE readiness boundaries"),
    ("naos self-check [options]", "Run control-plane self-conformance"),
    ("naos roadmap-crosswalk [options]", "Validate roadmap/recommendation crosswalk"),
    ("naos function-index-health [options]", "Report FUNCTION_INDEX health"),
    ("naos test-evidence-map [options]", "Build source-to-test evidence map"),
    ("naos test-evidence [options]", "Validate test evidence map"),
    ("naos ac-completion-evidence [options]", "Validate declared AC completion evidence"),
    ("naos plan-coherence [path]", "Review sequential/parallel task-set coherence (overlap, dependencies)"),
    ("naos duplicate-function-hygiene [options]", "Detect normalized duplicate function bodies"),
    ("naos secret-hygiene [options]", "Detect obvious secret-like local findings"),
    ("naos test-quality-hygiene [options]", "Detect tests with missing/trivial assertions"),
    ("naos dependency-integrity [options]", "Detect undeclared or unresolved imports"),
    ("naos package-reality [options]", "Review package, SBOM, provenance, hash, and opt-in registry evidence"),
    ("naos api-symbol-reality [options]", "Verify declared Python API symbols"),
    ("naos secure-coding-controls [options]", "Report bounded control/evidence routing"),
    ("naos secure-coding-reporting [options]", "Report five independent P3 dimensions"),
    ("naos evidence-pack [options]", "Export JSON evidence pack"),
    ("naos evidence-sign [options]", "Emit an optionally signable DSSE evidence envelope (no keys in kit)"),
    ("naos evidence-verify [options]", "Verify local evidence digests and report signature-entry/HEAD metadata"),
    ("naos dashboard [options]", "Generate dashboard and JSON summary"),
    ("naos gate-status [options]", "Report G0-G8 readiness"),
    ("naos gate-evaluate [options]", "Evaluate configured gates"),
    ("naos --version", "Show version"),
    ("naos --help", "Show this help"),
)


_HELP_USAGE_GROUP_COMMANDS = (
    (
        "Core setup",
        (
            "naos init [project_path] [options]",
            "naos add <type> <name> [options]",
            "naos upgrade PROJECT --tier T [--dry-run] [--plan-out FILE]",
            "naos upgrade PROJECT --apply-plan FILE --expect-plan-digest SHA256",
            "naos upgrade PROJECT --recover",
            "naos memory [explain|check|setup|status]",
            "naos doctor",
            "naos first-run [project_path] [options]",
            "naos commands",
            "naos --version",
            "naos --help",
        ),
    ),
    (
        "Adoption and brownfield discovery",
        (
            "naos adopt [project_path] [options]",
            "naos preflight [project_path] [options]",
            "naos intake [project_path] [options]",
            "naos install-plan [project_path] [options]",
            "naos existing-resource-inventory [path]",
            "naos ai-artifact-inventory [path]",
            "naos ai-artifact-reconcile [path]",
            "naos ai-code-provenance [options]",
            "naos compliance-posture [options]",
            "naos memory-resource-inventory [path]",
            "naos memory-resource-reconcile [path]",
            "naos mcp-resource-inventory [path]",
            "naos brownfield-baseline [path]",
            "naos requirements-reconstruct [path]",
            "naos traceability-gap-register [path]",
            "naos install-decision-record [path]",
            "naos overlay-coexistence TARGET [options]",
            "naos repository-intelligence <plan|enroll|apply|validate|refresh|query|status|recover> [options]",
        ),
    ),
    (
        "Planning and control review",
        (
            "naos context-challenge [path]",
            "naos repo-context-challenge [path]",
            "naos plan-challenge [path]",
            "naos decision-probe [path]",
            "naos planning-gate-review [path]",
            "naos claims [options]",
            "naos capability-maturity [options]",
            "naos systemic-impact [options]",
            "naos module-headers [options]",
            "naos spec-pack-contract [options]",
            "naos spec-pack-materialize [path]",
            "naos spec-assembly-worksheet [path]",
            "naos spec-cascade [options]",
            "naos control-plane-review [options]",
            "naos setup-recommendations [options]",
            "naos governance-bypass-posture [options]",
            "naos external-evidence-ingest [options]",
            "naos evidence-attestation [options]",
            "naos evidence-conflicts [options]",
            "naos research-record RECORD [options]",
            "naos composed-traceability [options]",
            "naos agent-orchestration-plan [options]",
        ),
    ),
    (
        "Memory, context, task, and session evidence",
        (
            "naos memory-readiness [options]",
            "naos memory-access [options]",
            "naos memory-use-policy [options]",
            "naos learning-loop-review [options]",
            "naos adapter-coherence [options]",
            "naos task-context --task T-XXX [options]",
            "naos task-lifecycle --task T-XXX [options]",
            "naos task-complete --task T-XXX [options]",
            "naos task-claim --task T-XXX [options]",
            "naos task-release --task T-XXX [options]",
            "naos task-claims [options]",
            "naos context-index [options]",
            "naos context-query [options]",
            "naos semantic-candidates [options]",
            "naos graph-context [options]",
            "naos graph-query [options]",
            "naos session-id [options]",
            "naos operator-attribution [options]",
            "naos session-start --task T-XXX [options]",
            "naos session-checkpoint --task T-XXX [options]",
            "naos session-end --task T-XXX [options]",
            "naos audit-log [options]",
            "naos agent-traces [options]",
            "naos harness-trace-import --source traces.jsonl [options]",
            "naos ai-surface-budget [options]",
        ),
    ),
    (
        "Behavioral, PR, and quality evidence",
        (
            "naos static-grader [options]",
            "naos grader-assessment [options]",
            "naos ai-component-inventory [options]",
            "naos agent-sponsor-registry [options]",
            "naos aivss-verify [options]",
            "naos model-policy [options]",
            "naos model-telemetry [options]",
            "naos failure-mode-posture [options]",
            "naos failure-mode-observations [options]",
            "naos opencode-config-hygiene [options]",
            "naos design-traceability [options]",
            "naos ui-experience-quality [options]",
            "naos llm-grader-readiness [options]",
            "naos behavioral-readiness [options]",
            "naos sarif-export [options]",
            "naos policy-overrides [options]",
            "naos pr-risk-classify [options]",
            "naos pr-governance-summary [options]",
            "naos agentic-workflow-review [options]",
            "naos pre-implementation-alignment-review [options]",
            "naos calibration-shadow [options]",
            "naos evidence-classification [options]",
            "naos cross-harness-review-readiness [options]",
            "naos self-check [options]",
            "naos roadmap-crosswalk [options]",
            "naos function-index-health [options]",
            "naos test-evidence-map [options]",
            "naos test-evidence [options]",
            "naos ac-completion-evidence [options]",
            "naos plan-coherence [path]",
            "naos duplicate-function-hygiene [options]",
            "naos secret-hygiene [options]",
            "naos test-quality-hygiene [options]",
            "naos dependency-integrity [options]",
            "naos package-reality [options]",
            "naos api-symbol-reality [options]",
        ),
    ),
    (
        "Secure coding, evidence outputs, and gates",
        (
            "naos secure-coding-controls [options]",
            "naos secure-coding-reporting [options]",
            "naos evidence-pack [options]",
            "naos evidence-sign [options]",
            "naos evidence-verify [options]",
            "naos dashboard [options]",
            "naos gate-status [options]",
            "naos gate-evaluate [options]",
        ),
    ),
)


_HELP_EXAMPLE_ROWS = (
    ("naos init . --tier quickstart --activate", "5-minute governance setup (5 rules)"),
    ("naos init . --tier lite --archetype custom --backend static_only --activate", "Specs + agents + 9 rules (~15 min)"),
    ("naos init . --tier standard --archetype custom --backend static_only --activate", "Full methodology governance (~30 min)"),
    ("naos upgrade . --tier assured --plan-out /tmp/assured-plan.json", "Create an immutable transition plan"),
    ("naos memory check", "Detect existing Engram/MCP setup"),
    ("naos memory setup --disposition configure-local", "Preview local Engram onboarding state"),
    ("python -m naos_governance.cli doctor", "Diagnose install and PATH before first run"),
    ("naos-governance doctor", "Collision-resistant console alias"),
    ("naos-governance first-run --profile standard --mode brownfield", "Run safe first-contact route"),
    ("naos adopt . --mode brownfield --profile standard --dry-run", "Preview adoption evidence without protected-file changes"),
    ("naos intake . --answers naos/intake_answers.yaml --profile standard", "Use answer-file intake mode"),
    ("naos context-challenge . --challenge-mode install --profile standard", "Challenge before build, with no edits"),
    ("naos requirements-reconstruct . --profile standard", "Create candidate FR/NFRs for review"),
    ("naos ai-code-provenance --profile standard", "Compose AI code provenance evidence for review"),
    ("naos compliance-posture --profile standard", "Compose compliance posture evidence for review"),
    ("naos claims --profile quickstart", "Advisory claims smoke check"),
    ("naos capability-maturity --profile standard", "Evaluate maturity readiness"),
    ("naos systemic-impact --profile standard", "Evaluate coherence review obligations"),
    ("naos module-headers --profile standard", "Evaluate source module-header traceability"),
    ("naos spec-pack-contract --profile standard", "Validate spec-pack template contract"),
    ("naos spec-pack-materialize . --profile standard --dry-run", "Preview missing standard spec files"),
    ("naos spec-assembly-worksheet . --profile standard", "Map adoption evidence to specs for review"),
    ("naos spec-cascade --profile standard", "Evaluate spec cascade/source traceability"),
    ("naos control-plane-review --profile standard", "Evaluate control-plane review routing"),
    ("naos setup-recommendations --profile lite", "Recommend setup modules for selected profile"),
    ("naos governance-bypass-posture --profile standard", "Report local bypass-posture evidence"),
    ("naos external-evidence-ingest --source scanner.sarif --profile standard", "Summarize local SARIF evidence"),
    ("naos evidence-attestation --profile assured", "Generate local digest/reviewer metadata"),
    ("naos evidence-conflicts --profile standard", "Detect deterministic evidence/review conflicts"),
    ("naos agentic-workflow-review --profile standard", "Review governed agentic coding workflow controls"),
    ("naos pre-implementation-alignment-review --profile standard", "Review pre-implementation alignment"),
    ("naos calibration-shadow --profile standard", "Run deterministic report drift checks"),
    ("naos evidence-classification --profile standard", "Classify finding provenance"),
    ("naos cross-harness-review-readiness --profile standard", "Report future cross-harness/DSSE readiness"),
    ("naos memory-readiness --profile standard", "Evaluate memory/context readiness"),
    ("naos memory-access --profile standard", "Evaluate declared/configured access and explicit unverified fields"),
    ("naos memory-use-policy --profile standard", "Evaluate memory-use policy/review readiness"),
    ("naos learning-loop-review --profile standard", "Review governed learning lifecycle records"),
    ("naos adapter-coherence --profile standard", "Review Codex/plugin/adapter coherence"),
    ("naos task-context --task T-001 --profile standard", "Generate bounded task context"),
    ("naos task-claim --task T-001 --profile standard", "Claim a task for coordination"),
    ("naos task-release --task T-001 --profile standard", "Release a task claim"),
    ("naos task-claims --profile standard", "Summarize task claims"),
    ("naos context-index --profile standard", "Build generated local context index"),
    ("naos context-query --query \"T-001\" --profile standard", "Query generated index candidates"),
    ("naos repository-intelligence plan . --profile standard", "Inspect and prepare a no-target-mutation activation plan"),
    ("naos repository-intelligence query . --text \"authentication flow\"", "Query a validated current intelligence generation"),
    ("naos semantic-candidates --profile standard", "Evaluate semantic/vector readiness only"),
    ("naos graph-context --profile standard", "Evaluate graph traversal readiness only"),
    ("naos graph-query --task T-001 --profile standard", "Query bounded graph candidates"),
    ("naos session-id --profile standard", "Create or reuse a session id for namespaced reports"),
    ("naos operator-attribution --profile standard", "Resolve local operator attribution"),
    ("naos session-start --task T-001 --profile standard", "Generate session-start checklist"),
    ("naos session-checkpoint --task T-001 --profile standard", "Generate checkpoint checklist"),
    ("naos session-end --task T-001 --profile standard", "Generate session-end checklist"),
    ("naos audit-log --profile standard", "Summarize append-only audit log events"),
    ("naos agent-traces --profile standard", "Validate declared agent trace events"),
    ("naos harness-trace-import --source naos/harness_traces/example.jsonl --profile standard", "Normalize local harness trace records for review"),
    ("naos ai-surface-budget --profile standard", "Evaluate AI-surface context budget and health"),
    ("naos ai-component-inventory --profile standard", "Build declared AI component inventory evidence"),
    ("naos agent-sponsor-registry --profile standard", "Validate opt-in agent sponsor declarations"),
    ("naos aivss-verify --profile standard", "Verify opt-in AIVSS-Agentic v0.8 arithmetic"),
    ("naos static-grader --profile standard", "Run deterministic structural grading"),
    ("naos duplicate-function-hygiene --profile standard", "Detect duplicate function bodies"),
    ("naos secret-hygiene --profile standard", "Detect obvious secret-like local findings"),
    ("naos test-quality-hygiene --profile standard", "Detect weak test assertion evidence"),
    ("naos dependency-integrity --profile standard", "Detect undeclared/unresolved imports"),
    ("naos package-reality --profile standard", "Review package/SBOM/provenance evidence"),
    ("naos api-symbol-reality --profile standard", "Verify declared Python API symbols"),
    ("naos ac-completion-evidence --profile standard", "Validate declared AC completion evidence"),
    ("naos secure-coding-reporting --profile standard --refresh-sources", "Generate five independent P3 dimensions"),
    ("naos model-policy --profile standard", "Review model-provider declarations"),
    ("naos agent-orchestration-plan --profile assured", "Build an opt-in proposal without dispatching agents"),
    ("naos model-telemetry --profile standard", "Review local model telemetry evidence"),
    ("naos failure-mode-posture --profile standard", "Review local failure-mode posture"),
    ("naos failure-mode-observations --profile standard", "Aggregate local report findings by failure mode"),
    ("naos opencode-config-hygiene --profile standard", "Review optional OpenCode config hygiene"),
    ("naos design-traceability --profile standard", "Review UI spec-object traceability declarations"),
    ("naos ui-experience-quality --profile standard", "Review UI experience quality evidence declarations"),
    ("naos llm-grader-readiness --profile standard", "Report readiness-only LLMGrader posture"),
    ("naos behavioral-readiness --profile standard", "Report behavioral governance baseline readiness"),
    ("naos sarif-export --profile standard", "Export deterministic findings to SARIF"),
    ("naos policy-overrides --profile standard --dry-run", "Validate static/global/team/operator YAML overlays"),
    ("naos pr-risk-classify --profile standard", "Classify deterministic PR risk surfaces"),
    ("naos pr-governance-summary --profile standard", "Summarize PR governance evidence"),
    ("naos self-check --profile standard --json", "Run JSON self-check"),
    ("naos evidence-pack --profile standard", "Export NAOS evidence pack"),
    ("naos dashboard --profile standard", "Refresh DASHBOARD.md + dashboard_summary.json"),
    ("naos add instruction database", "Add database instruction"),
    ("naos add agent naos-debug", "Add debug agent"),
    ("naos add setup-module --list", "Show guided setup modules"),
    ("naos add setup-module read_only_ci_readiness --profile lite --dry-run", ""),
    ("naos add setup-module claude_code_hooks --profile standard --dry-run", ""),
    ("naos add --list", "Show available templates"),
)


def _format_help_rows(rows: tuple[tuple[str, str], ...], description_column: int) -> str:
    formatted: list[str] = []
    continuation = " " * description_column
    for command, description in rows:
        command_text = f"{_HELP_INDENT}{command}"
        if not description:
            formatted.append(command_text)
        elif len(command_text) < description_column:
            formatted.append(f"{command_text}{' ' * (description_column - len(command_text))}{description}")
        else:
            formatted.extend((command_text, f"{continuation}{description}"))
    return "\n".join(formatted)


def _group_help_rows() -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    rows_by_command = {command: (command, description) for command, description in _HELP_USAGE_ROWS}
    used_commands: set[str] = set()
    groups: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    for title, commands in _HELP_USAGE_GROUP_COMMANDS:
        group_rows = []
        for command in commands:
            group_rows.append(rows_by_command[command])
            used_commands.add(command)
        groups.append((title, tuple(group_rows)))

    remaining_rows = tuple(row for row in _HELP_USAGE_ROWS if row[0] not in used_commands)
    if remaining_rows:
        groups.append(("Other commands", remaining_rows))
    return tuple(groups)


def _format_help_groups(description_column: int) -> str:
    formatted: list[str] = []
    for title, rows in _group_help_rows():
        if formatted:
            formatted.append("")
        formatted.append(f"{title}:")
        formatted.append(_format_help_rows(rows, description_column))
    return "\n".join(formatted)


def _print_help() -> None:
    print(
        """
NAOS — Governance-as-Code for AI-assisted software development

Start here:
    python -m naos_governance.cli doctor
    naos-governance doctor
    naos doctor

First-run project route:
    naos-governance first-run --profile standard --mode brownfield

Core commands:
    naos init [project_path] [options]     Scaffold governance files
    naos first-run [project_path] [options]
                                            Run safe first-contact evidence route
    naos adopt [project_path] [options]    Preview greenfield/brownfield adoption evidence
    naos repository-intelligence <action> Plan, enroll, apply, validate, refresh, query, status, or recover repository context
    naos setup-recommendations [options]   Recommend setup modules and next actions
    naos evidence-pack [options]           Export JSON evidence pack
    naos dashboard [options]               Generate dashboard and JSON summary

Full command catalogue:
    naos commands
    naos help --all
    naos --help --all

If bare `naos` opens another tool or prints non-NAOS help, use
`python -m naos_governance.cli ...` or `naos-governance ...` until PATH is
fixed. `naos doctor` reports the current command-resolution state.

Control-plane commands are operational helpers. They do not replace the
prompt/agent lifecycle, and they do not prove legal compliance, runtime safety,
secure code, or complete test coverage.

Documentation: https://github.com/mfraile/naos-governance
"""
    )


def _print_full_help() -> None:
    usage = _format_help_groups(_USAGE_DESCRIPTION_COLUMN)
    examples = _format_help_rows(_HELP_EXAMPLE_ROWS, _EXAMPLE_DESCRIPTION_COLUMN)
    naos_init = _import_subcommand_module("naos_init")
    audiences = {
        "quickstart": "Try NAOS with minimal surfaces",
        "lite": "Solo developers and small projects",
        "standard": "Small teams and production projects",
        "assured": "Evidence-heavy regulated/enterprise projects",
    }
    profile_rows = "\n".join(
        (
            f"    {profile:<12} {info['rules_active']} rules, "
            f"{info['rules_blocking']} blocking-posture"
        ).ljust(62)
        + audiences[profile]
        for profile, info in naos_init.PROFILES.items()
    )
    print(
        f"""
NAOS — Governance-as-Code for AI-assisted software development

Usage:
{usage}

Examples:
{examples}

Profiles:
{profile_rows}

Profile counts describe rule posture, not installed executable checks. The
generated hook and installed workflows are authoritative for automation; no
licence scanner is installed by default.

Control-plane commands are operational helpers. They do not replace the
prompt/agent lifecycle, and they do not prove legal compliance, runtime safety,
secure code, or complete test coverage.

Documentation: https://github.com/mfraile/naos-governance
Public onboarding: docs/ADOPTION_GUIDE.md, docs/AUDIT_PLAYBOOK.md,
docs/ASSURED_PROFILE_ACTIVATION.md, docs/BEHAVIORAL_AUDIT_ENABLEMENT.md
"""
    )


if __name__ == "__main__":
    sys.exit(main())
