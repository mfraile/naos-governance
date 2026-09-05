#!/usr/bin/env python3
"""Aggregate NAOS self-conformance checks into one summary JSON."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    supported_profiles,
    write_report,
)
from naos_systemic_impact import (  # noqa: E402
    build_actionable_presentation,
    finding_occurrence,
    presentation_lines,
)

CAPABILITY_REQUIRED_FIELDS = {
    "id",
    "name",
    "description",
    "status",
    "default_maturity",
    "minimum_profile",
    "profiles",
    "authority",
    "allowed_resources",
    "prohibited_resources",
    "constraints",
    "required_evidence",
    "validators",
    "gatekeepers",
    "dashboard_signals",
    "maturity_path",
    "known_limitations",
    "not_claimed",
    "related_docs",
    "related_scripts",
}
CAPABILITY_ID_RE = re.compile(r"^CAP-[A-Z0-9-]+$")
GATE_ID_RE = re.compile(r"^G[0-9]+$")
MATURITY_LEVELS = {"L0", "L1", "L2", "L3", "L4", "L5"}
PROFILE_IDS = {"quickstart", "lite", "standard", "assured"}
CAPABILITY_STATUS_VALUES = {"active", "scaffolded", "experimental", "planned", "deprecated"}
ENFORCEMENT_VALUES = {"none", "advisory", "warning", "required", "blocking", "not_applicable"}
VALIDATOR_STATUS_VALUES = {"available", "planned", "external", "manual"}
PROFILE_BEHAVIOR_REQUIRED_FIELDS = {"target_maturity", "enforcement", "notes"}
GATE_REQUIRED_FIELDS = {
    "id",
    "name",
    "purpose",
    "profile_behavior",
    "required_inputs",
    "required_evidence",
    "validators",
    "outputs",
    "severity_by_profile",
    "maturity_dependency",
    "known_limitations",
}


def check_status(findings: list[dict[str, Any]]) -> str:
    return status_from_counts(finding_counts(findings))


def first_existing_dir(paths: list[Path]) -> Path:
    for path in paths:
        if path.is_dir():
            return path
    return paths[0]


def first_existing_file(paths: list[Path]) -> Path:
    for path in paths:
        if path.is_file():
            return path
    return paths[0]


def validate_capability_contracts(root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    capabilities_dir = first_existing_dir(
        [
            root / "capabilities",
            root / naos_root / "capabilities",
            kit_root() / "capabilities",
        ]
    )
    contracts = sorted(p for p in capabilities_dir.glob("*.yaml") if not p.name.startswith("_"))
    ids: list[str] = []
    for path in contracts:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            findings.append({"id": str(path), "severity": severity, "status": "parse_error", "message": str(exc)})
            continue
        missing = sorted(CAPABILITY_REQUIRED_FIELDS - set(data))
        if missing:
            findings.append(
                {
                    "id": str(path),
                    "severity": severity,
                    "status": "missing_fields",
                    "message": f"Missing required fields: {', '.join(missing)}",
                }
            )
        findings.extend(validate_capability_contract_values(path, data, severity))
        cap_id = data.get("id")
        if cap_id:
            ids.append(str(cap_id))
        if data.get("status") == "experimental":
            if data.get("default_maturity") != "L0" or data.get("enforcement_default") != "advisory":
                findings.append(
                    {
                        "id": str(cap_id or path),
                        "severity": severity,
                        "status": "experimental_policy_mismatch",
                        "message": "Experimental capabilities must default to L0 and advisory enforcement.",
                    }
                )
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    for item in duplicates:
        findings.append({"id": item, "severity": severity, "status": "duplicate_capability_id", "message": "Duplicate capability ID."})
    return {
        "id": "capability_contract_validation",
        "status": check_status(findings),
        "capabilities_dir": str(capabilities_dir),
        "contracts": len(contracts),
        "findings": findings,
    }


def value_finding(path: Path, field: str, severity: str, message: str) -> dict[str, Any]:
    return {
        "id": str(path),
        "severity": severity,
        "status": "schema_constraint_violation",
        "field": field,
        "message": message,
    }


def validate_capability_contract_values(path: Path, data: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    cap_id = data.get("id")
    if not isinstance(cap_id, str) or not CAPABILITY_ID_RE.match(cap_id):
        findings.append(value_finding(path, "id", severity, "Capability id must match CAP-* pattern."))

    status = data.get("status")
    if status not in CAPABILITY_STATUS_VALUES:
        findings.append(value_finding(path, "status", severity, "Capability status is not one of the schema enum values."))

    default_maturity = data.get("default_maturity")
    if default_maturity not in MATURITY_LEVELS:
        findings.append(value_finding(path, "default_maturity", severity, "default_maturity must be L0-L5."))

    minimum_profile = data.get("minimum_profile")
    if minimum_profile not in PROFILE_IDS:
        findings.append(value_finding(path, "minimum_profile", severity, "minimum_profile must be quickstart, lite, standard, or assured."))

    enforcement_default = data.get("enforcement_default")
    if enforcement_default is not None and enforcement_default not in ENFORCEMENT_VALUES - {"not_applicable"}:
        findings.append(value_finding(path, "enforcement_default", severity, "enforcement_default is not a valid enforcement value."))

    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        findings.append(value_finding(path, "profiles", severity, "profiles must be a mapping."))
    else:
        missing_profiles = sorted(PROFILE_IDS - set(profiles))
        if missing_profiles:
            findings.append(value_finding(path, "profiles", severity, f"Missing profile behavior entries: {', '.join(missing_profiles)}."))
        for profile_id, behavior in profiles.items():
            if profile_id not in PROFILE_IDS:
                findings.append(value_finding(path, f"profiles.{profile_id}", severity, "Unknown profile id."))
                continue
            if not isinstance(behavior, dict):
                findings.append(value_finding(path, f"profiles.{profile_id}", severity, "Profile behavior must be a mapping."))
                continue
            missing_behavior = sorted(PROFILE_BEHAVIOR_REQUIRED_FIELDS - set(behavior))
            if missing_behavior:
                findings.append(
                    value_finding(
                        path,
                        f"profiles.{profile_id}",
                        severity,
                        f"Missing profile behavior fields: {', '.join(missing_behavior)}.",
                    )
                )
            if behavior.get("target_maturity") not in MATURITY_LEVELS:
                findings.append(value_finding(path, f"profiles.{profile_id}.target_maturity", severity, "target_maturity must be L0-L5."))
            if behavior.get("enforcement") not in ENFORCEMENT_VALUES:
                findings.append(value_finding(path, f"profiles.{profile_id}.enforcement", severity, "enforcement is not a valid enforcement value."))

    validators = data.get("validators")
    if isinstance(validators, list):
        for index, validator in enumerate(validators):
            field = f"validators[{index}]"
            if not isinstance(validator, dict):
                findings.append(value_finding(path, field, severity, "Validator entry must be a mapping."))
                continue
            if not validator.get("id"):
                findings.append(value_finding(path, f"{field}.id", severity, "Validator entry must include id."))
            if validator.get("status") not in VALIDATOR_STATUS_VALUES:
                findings.append(value_finding(path, f"{field}.status", severity, "Validator status is not a valid schema value."))
    else:
        findings.append(value_finding(path, "validators", severity, "validators must be a list."))

    gatekeepers = data.get("gatekeepers")
    if isinstance(gatekeepers, list):
        for gate_id in gatekeepers:
            if not isinstance(gate_id, str) or not GATE_ID_RE.match(gate_id):
                findings.append(value_finding(path, "gatekeepers", severity, "Gatekeeper id must match G[0-9]+."))
    else:
        findings.append(value_finding(path, "gatekeepers", severity, "gatekeepers must be a list."))

    maturity_path = data.get("maturity_path")
    if isinstance(maturity_path, dict):
        missing_levels = sorted(MATURITY_LEVELS - set(maturity_path))
        if missing_levels:
            findings.append(value_finding(path, "maturity_path", severity, f"Missing maturity levels: {', '.join(missing_levels)}."))
    else:
        findings.append(value_finding(path, "maturity_path", severity, "maturity_path must be a mapping."))

    return findings


def resolve_gatekeeper_manifest(root: Path, naos_root: str) -> Path:
    project_manifest = root / naos_root / "gatekeepers.yaml"
    if project_manifest.exists():
        return project_manifest
    return first_existing_file(
        [
            root / "templates" / "structural-seeds" / "naos" / "gatekeepers.yaml",
            kit_root() / "templates" / "structural-seeds" / "naos" / "gatekeepers.yaml",
        ]
    )


def validate_gatekeeper_manifest(root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    manifest_path = resolve_gatekeeper_manifest(root, naos_root)
    findings: list[dict[str, Any]] = []
    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {
            "id": "gatekeeper_manifest_validation",
            "status": "blocked" if profile == "assured" else "required_missing",
            "manifest": str(manifest_path),
            "findings": [{"id": str(manifest_path), "severity": severity, "status": "parse_error", "message": str(exc)}],
        }
    gates = data.get("gates") or []
    if not isinstance(gates, list):
        findings.append({"id": "gates", "severity": severity, "status": "invalid_manifest", "message": "gates must be a list."})
        gates = []
    gate_ids = [str(gate.get("id")) for gate in gates if isinstance(gate, dict) and gate.get("id")]
    expected_ids = {f"G{i}" for i in range(9)}
    missing_ids = sorted(expected_ids - set(gate_ids))
    if missing_ids:
        findings.append(
            {
                "id": "gate_ids",
                "severity": severity,
                "status": "missing_gates",
                "message": f"Missing gates: {', '.join(missing_ids)}",
            }
        )
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        missing = sorted(GATE_REQUIRED_FIELDS - set(gate))
        if missing:
            findings.append(
                {
                    "id": gate.get("id", "unknown"),
                    "severity": severity,
                    "status": "missing_fields",
                    "message": f"Missing required fields: {', '.join(missing)}",
                }
            )
    return {
        "id": "gatekeeper_manifest_validation",
        "status": check_status(findings),
        "manifest": str(manifest_path),
        "gates": len(gates),
        "findings": findings,
    }


def validate_maturity_and_profiles(root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    maturity_path = first_existing_file(
        [
            root / naos_root / "maturity_levels.yaml",
            root / "templates" / "structural-seeds" / "naos" / "maturity_levels.yaml",
            kit_root() / "templates" / "structural-seeds" / "naos" / "maturity_levels.yaml",
        ]
    )
    profile_dir = first_existing_dir(
        [
            root / ".github" / "profiles",
            root / "templates" / "profiles",
            kit_root() / "templates" / "profiles",
        ]
    )
    profile_paths = sorted(profile_dir.glob("governance-*.yaml"))
    try:
        maturity = yaml.safe_load(maturity_path.read_text(encoding="utf-8")) or {}
        level_ids = {str(level.get("id")) for level in maturity.get("levels", []) if isinstance(level, dict)}
        if level_ids != {"L0", "L1", "L2", "L3", "L4", "L5"}:
            findings.append({"id": "maturity_levels", "severity": severity, "status": "invalid_levels", "message": "Expected L0-L5 maturity levels."})
    except Exception as exc:
        findings.append({"id": str(maturity_path), "severity": severity, "status": "parse_error", "message": str(exc)})
    found_profiles: set[str] = set()
    for path in profile_paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            findings.append({"id": str(path), "severity": severity, "status": "parse_error", "message": str(exc)})
            continue
        profile_id = str(data.get("id", "")).removeprefix("governance-")
        if profile_id:
            found_profiles.add(profile_id)
        if "capabilities" not in data or "gate_policy" not in data:
            findings.append({"id": str(path), "severity": severity, "status": "missing_profile_policy", "message": "Profile lacks capabilities or gate_policy section."})
    missing_profiles = sorted(set(supported_profiles(policy)) - found_profiles)
    if missing_profiles:
        findings.append({"id": "profiles", "severity": severity, "status": "missing_profiles", "message": f"Missing profiles: {', '.join(missing_profiles)}"})
    return {
        "id": "maturity_profile_parsing",
        "status": check_status(findings),
        "maturity_path": str(maturity_path),
        "profile_dir": str(profile_dir),
        "profiles": sorted(found_profiles),
        "findings": findings,
    }


def validate_profile_rules_regeneration(
    root: Path,
    profile: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Surface exact derived RULES drift only for a kit/package layout.

    Adopter-local ``.ai/RULES.md`` is intentionally not compared with kit
    bytes. That file may contain authorized project adaptations, while the
    canonical source and all four derived profile outputs remain kit resources.
    """

    canonical_source = root / "configs" / "profile_rules_source.yaml"
    renderer = root / "naos_profile_rules.py"
    kit_outputs = root / "profiles"
    derived_outputs = [
        kit_outputs / f"governance-{tier}" / ".ai" / "RULES.md"
        for tier in ("quickstart", "lite", "standard", "assured")
    ]
    is_kit_layout = (
        canonical_source.is_file()
        or renderer.is_file()
        or ((root / "naos_init.py").is_file() and all(path.is_file() for path in derived_outputs))
    )
    if not is_kit_layout:
        return {
            "id": "profile_rules_regeneration",
            "status": "not_applicable",
            "applicability": "adopter_local_rules",
            "reason": (
                "Adopter-local .ai/RULES.md may contain authorized ADAPT changes; "
                "exact kit-output parity is not applied."
            ),
            "findings": [],
        }

    severity = severity_for_profile(profile, policy)
    missing = [
        path.relative_to(root).as_posix()
        for path in (canonical_source, renderer, *derived_outputs)
        if not path.exists()
    ]
    if missing:
        findings = [
            {
                "id": "PROFILE_RULES_KIT_INPUT_MISSING",
                "severity": severity,
                "status": "profile_rules_kit_input_missing",
                "message": f"Kit profile-RULES resources are incomplete: {', '.join(missing)}.",
            }
        ]
        return {
            "id": "profile_rules_regeneration",
            "status": check_status(findings),
            "applicability": "kit_profile_rules",
            "findings": findings,
        }

    result = subprocess.run(
        [sys.executable, str(renderer), "--check", "--root", str(root), "--json"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "status": "failed",
            "findings": [
                {
                    "profile": "all",
                    "rule_id": "PROFILE_RULES_CHECK_ERROR",
                    "message": (result.stderr or result.stdout or "No renderer output").strip(),
                }
            ],
        }
    findings = [
        {
            "id": str(item.get("rule_id") or "PROFILE_RULES_CHECK_FAILED"),
            "profile": str(item.get("profile") or "all"),
            "severity": severity,
            "status": "profile_rules_drift",
            "message": str(item.get("message") or "Profile RULES parity failed."),
            "suggested_fix": str(
                item.get("suggested_fix") or "Regenerate the derived profile RULES outputs."
            ),
        }
        for item in payload.get("findings") or []
    ]
    if result.returncode != 0 and not findings:
        findings.append(
            {
                "id": "PROFILE_RULES_CHECK_ERROR",
                "severity": severity,
                "status": "profile_rules_check_error",
                "message": f"Profile RULES renderer exited {result.returncode} without a finding.",
            }
        )
    return {
        "id": "profile_rules_regeneration",
        "status": check_status(findings),
        "applicability": "kit_profile_rules",
        "renderer_status": payload.get("status", "unknown"),
        "profiles_checked": payload.get("profiles_checked", []),
        "findings": findings,
    }


def run_json_script(
    script: str,
    args: list[str],
    profile: str,
    policy: dict[str, Any],
    naos_root: str,
    policy_path: str | None,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve().parent / script),
        "--profile",
        profile,
        "--naos-root",
        naos_root,
        "--json",
        *args,
    ]
    if policy_path:
        command.extend(["--policy", policy_path])
    result = subprocess.run(command, cwd=Path.cwd(), capture_output=True, text=True)
    payload: dict[str, Any]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "schema": f"naos.{Path(script).stem}.error",
            "status": "error",
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "id": script,
                    "severity": severity_for_profile(profile, policy),
                    "status": "script_error",
                    "message": (result.stderr or result.stdout or "No output").strip(),
                }
            ],
        }
    return {
        "id": Path(script).stem,
        "returncode": result.returncode,
        "status": payload.get("status", "unknown"),
        "summary": payload.get("summary", {}),
        "findings": payload.get("findings", []),
    }


def aggregate_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for check in checks:
        findings.extend(check.get("findings") or [])
    summary = finding_counts(findings)
    summary["checks"] = len(checks)
    status = status_from_counts(summary)
    return {"status": status, "summary": summary, "findings": findings}


def self_check_finding_occurrences(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return nested self-check findings with stable positional identities."""
    occurrences: list[dict[str, Any]] = []
    order = 0
    for check_index, check in enumerate(report.get("checks") or []):
        if not isinstance(check, dict):
            continue
        check_id = str(check.get("id") or "unknown")
        for finding_index, item in enumerate(check.get("findings") or []):
            if not isinstance(item, dict):
                continue
            occurrences.append(
                finding_occurrence(
                    source="self-check",
                    identity=(
                        f"self-check/check[{check_index}]={check_id}"
                        f"/finding[{finding_index}]"
                    ),
                    order=order,
                    finding=item,
                    family_label=f"self-check[{check_index}]:{check_id}",
                    parent_evidence=check,
                )
            )
            order += 1
    return occurrences


def build_report(
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    policy_path: str | None,
) -> dict[str, Any]:
    checks = [
        validate_capability_contracts(root, profile, naos_root, policy),
        validate_gatekeeper_manifest(root, profile, naos_root, policy),
        validate_maturity_and_profiles(root, profile, naos_root, policy),
        validate_profile_rules_regeneration(root, profile, policy),
        run_json_script("naos_setup_recommendations.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_governance_bypass_posture.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_external_evidence_ingest.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_evidence_attestation.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_memory_context_readiness.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_memory_provider_access.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_memory_use_policy.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_learning_loop_review.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_task_context_pack.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_local_context_index.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_local_context_query.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_semantic_candidate_readiness.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_graph_context_readiness.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_graph_context_query.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_session_identity.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_operator_attribution.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_session_lifecycle.py", ["--mode", "session_start"], profile, policy, naos_root, policy_path),
        run_json_script("naos_audit_log.py", ["--summary"], profile, policy, naos_root, policy_path),
        run_json_script("naos_task_claims.py", ["--action", "list"], profile, policy, naos_root, policy_path),
        run_json_script("naos_agent_trace_validate.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_ai_surface_budget.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_static_grader.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_grader_assessment.py", ["--mode", "assess"], profile, policy, naos_root, policy_path),
        run_json_script("naos_llm_grader_readiness.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_behavioral_governance_readiness.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_policy_overrides.py", ["--dry-run"], profile, policy, naos_root, policy_path),
        run_json_script("naos_pr_risk_classification.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_pr_governance_summary.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_agentic_workflow_review.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_pre_implementation_alignment_review.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_calibration_shadow.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_evidence_classification.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_cross_harness_review_readiness.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_capability_maturity.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_systemic_impact.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_module_header_traceability.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_detect_spec_drift.py", [], profile, policy, naos_root, policy_path),
        *(
            [run_json_script("naos_ai_component_inventory.py", [], profile, policy, naos_root, policy_path)]
            if profile in {"standard", "assured"}
            else []
        ),
        *(
            [run_json_script("naos_agent_sponsor_registry.py", [], profile, policy, naos_root, policy_path)]
            if (root / naos_root / str(policy.get("paths", {}).get("agent_sponsor_registry") or "agent_sponsor_registry.yaml")).is_file()
            and (Path(__file__).resolve().parent / "naos_agent_sponsor_registry.py").is_file()
            else []
        ),
        *(
            [run_json_script("naos_aivss_arithmetic_verification.py", [], profile, policy, naos_root, policy_path)]
            if (root / naos_root / str(policy.get("paths", {}).get("aivss_assessments") or "aivss_assessments.yaml")).is_file()
            and (Path(__file__).resolve().parent / "naos_aivss_arithmetic_verification.py").is_file()
            else []
        ),
        run_json_script("naos_control_plane_review.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_validate_claims.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_validate_roadmap_crosswalk.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_function_index_health.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_evidence_conflicts.py", [], profile, policy, naos_root, policy_path),
        run_json_script("naos_validate_test_evidence.py", ["--advisory"], profile, policy, naos_root, policy_path),
    ]
    aggregate = aggregate_checks(checks)
    return {
        "schema": "naos.self_check.v1",
        "profile": profile,
        "status": aggregate["status"],
        "summary": aggregate["summary"],
        "checks": checks,
        "limitations": [
            "Self-check aggregates configured file-first evidence only.",
            "Quickstart and lite do not fail hard unless strict behavior is requested.",
            "Test evidence validation runs in advisory mode unless separately configured.",
            "Exact profile-RULES parity applies to kit/package resources, not adopter-local ADAPT edits.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run NAOS self-conformance checks.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every human-readable finding occurrence; JSON is always complete.",
    )
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or str(policy.get("paths", {}).get("default_naos_root") or "naos")
    profile = normalize_profile(args.profile, policy)
    policy_path = args.policy or policy.get("_meta", {}).get("path")
    report = build_report(root, profile, naos_root, policy, policy_path)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "self_check_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS self-check: {report['status']} ({report['summary']['total_findings']} findings)")
        presentation = build_actionable_presentation(
            self_check_finding_occurrences(report),
            expansion_command="naos self-check --all",
            show_all=args.all,
            limitations=report.get("limitations") or [],
        )
        for line in presentation_lines(presentation):
            print(line)
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
