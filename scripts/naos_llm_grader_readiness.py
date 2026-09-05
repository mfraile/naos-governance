#!/usr/bin/env python3
"""Evaluate LLMGrader readiness posture without running an LLM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.llm_grader_readiness.v1"
RESIDUAL_RISKS = [
    "model_drift",
    "prompt_rubric_drift",
    "position_bias",
    "style_bias",
    "self_preference_bias",
    "provider_dependency",
    "data_exposure",
    "cost_overrun",
    "false_positive",
    "false_negative",
    "automation_bias",
    "advisory_to_authority_confusion",
    "human_review_required",
]
NOT_CLAIMED = [
    "LLMGrader runtime",
    "model/API/provider call",
    "approval",
    "certification",
    "attestation",
    "maturity promotion",
    "behavioral compliance determination",
    "source authority",
    "behavioral safety proof",
    "semantic correctness proof",
    "hallucination prevention",
]
LIMITATIONS = [
    "This report checks readiness posture only and does not grade anything with a model.",
    "Future model-based judging may incur cost, expose data, drift across versions, and produce biased or inconsistent results.",
    "StaticGrader and deterministic evidence remain primary.",
    "Human review is required before any future cost-bearing or durable conclusion.",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "llm_grader_readiness_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("llm_grader_readiness_rules") or "llm_grader_readiness_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def has_model_role(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not value.strip().startswith("[ADAPT:")


def profile_posture(rules: dict[str, Any], profile: str) -> dict[str, Any]:
    posture = as_mapping(rules.get("profile_posture")).get(profile)
    if isinstance(posture, dict):
        return posture
    defaults = {
        "quickstart": {"state": "disabled", "severity": "advisory", "human_review_required": False},
        "lite": {"state": "readiness_only", "severity": "advisory", "human_review_required": False},
        "standard": {"state": "readiness_only", "severity": "review_required", "human_review_required": True},
        "assured": {"state": "readiness_only", "severity": "review_required", "human_review_required": True},
    }
    return defaults.get(profile, {"state": "readiness_only", "severity": "advisory", "human_review_required": False})


def finding(identifier: str, severity: str, status: str, message: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "authority_layer": "readiness_only",
        "not_claimed": ["approval", "certification", "compliance determination", "maturity promotion"],
    }


def future_requested(rules: dict[str, Any]) -> bool:
    return any(
        bool_value(rules.get(key))
        for key in (
            "enabled",
            "runtime_enabled",
            "provider_allowed",
            "external_api_allowed",
            "model_dependency_allowed",
            "api_keys_allowed",
            "future_enablement_requested",
        )
    )


def severity_for(profile: str, requested: bool = False) -> str:
    if not requested:
        return "advisory"
    return {"quickstart": "warning", "lite": "warning", "standard": "required", "assured": "blocking"}.get(profile, "warning")


def build_findings(rules: dict[str, Any], profile: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    requested = future_requested(rules)
    severity = severity_for(profile, requested)

    if bool_value(rules.get("runtime_enabled")):
        findings.append(finding("llm_grader.runtime_enabled", "blocking", "blocked", "Runtime model-based grading is enabled; G42D is readiness-only."))
    if bool_value(rules.get("external_api_allowed")):
        findings.append(finding("llm_grader.external_api_allowed", "blocking", "blocked", "External API use is enabled; readiness reporting must not call external services."))
    if bool_value(rules.get("model_dependency_allowed")):
        findings.append(finding("llm_grader.model_dependency_allowed", severity, "review_required", "Model dependency is allowed; future enablement needs model/version, cost, data, and human-review controls."))
    if bool_value(rules.get("api_keys_allowed")):
        findings.append(finding("llm_grader.api_keys_allowed", "blocking", "blocked", "API key handling is enabled; readiness reporting must not read or require credentials."))

    cost_policy = as_mapping(rules.get("cost_policy"))
    future_enablement = as_mapping(rules.get("future_enablement"))
    data_policy = as_mapping(rules.get("data_exposure_policy"))
    model_policy = as_mapping(rules.get("model_policy"))
    prompt_policy = as_mapping(rules.get("prompt_rubric_policy"))
    bias_policy = as_mapping(rules.get("bias_variance_policy"))
    residual_policy = as_mapping(rules.get("residual_risk_policy"))
    baseline = as_mapping(rules.get("deterministic_baseline"))
    boundary = as_mapping(rules.get("advisory_boundary"))

    if bool_value(rules.get("provider_allowed")) and (
        not bool_value(rules.get("human_approval_required_before_cost"))
        or not bool_value(rules.get("cost_budget_required_if_enabled_later"))
        or not bool_value(rules.get("data_exposure_review_required"))
    ):
        findings.append(finding("llm_grader.provider_without_controls", severity, "review_required", "Provider allowance lacks cost, data exposure, or human approval controls."))

    if requested:
        model_role_declared = has_model_role(future_enablement.get("model_role")) or has_model_role(model_policy.get("model_role"))
        required_future = {
            "provider": future_enablement.get("provider") if not model_role_declared else "declared_by_model_role",
            "model": future_enablement.get("model") if not model_role_declared else "declared_by_model_role",
            "model_version": future_enablement.get("model_version") if not model_role_declared else "declared_by_model_role",
            "prompt_version": future_enablement.get("prompt_version"),
            "rubric_version": future_enablement.get("rubric_version"),
            "max_cost_usd": future_enablement.get("max_cost_usd") if future_enablement.get("max_cost_usd") is not None else cost_policy.get("max_cost_usd"),
            "data_exposure_level": future_enablement.get("data_exposure_level"),
            "approval_owner": future_enablement.get("approval_owner"),
            "human_review_boundary": future_enablement.get("human_review_boundary"),
        }
        for key, value in required_future.items():
            if value in (None, "", []):
                findings.append(finding(f"llm_grader.future_enablement_missing_{key}", severity, "review_required", f"Future enablement is requested but `{key}` is not declared."))
        if not future_enablement.get("residual_risks"):
            findings.append(finding("llm_grader.future_enablement_missing_residual_risks", severity, "review_required", "Future enablement is requested but residual risks are not declared."))

    if not bool_value(rules.get("cost_budget_required_if_enabled_later"), True):
        findings.append(finding("llm_grader.cost_budget_not_required", severity, "review_required", "Future model-based grading must require a cost budget."))
    if not bool_value(rules.get("human_approval_required_before_cost"), True):
        findings.append(finding("llm_grader.human_approval_before_cost_missing", severity, "review_required", "Human approval before cost must be required."))
    if not bool_value(rules.get("data_exposure_review_required"), True) or not bool_value(data_policy.get("review_required"), True):
        findings.append(finding("llm_grader.data_exposure_review_missing", severity, "review_required", "Data exposure review must be required before future model-based judging."))
    if not bool_value(model_policy.get("model_version_required_if_enabled_later"), True) or not bool_value(rules.get("model_version_required"), True):
        findings.append(finding("llm_grader.model_version_policy_missing", severity, "review_required", "Future model-based judging must record model version."))
    if not bool_value(prompt_policy.get("prompt_version_required_if_enabled_later"), True) or not bool_value(prompt_policy.get("rubric_version_required_if_enabled_later"), True):
        findings.append(finding("llm_grader.prompt_rubric_version_policy_missing", severity, "review_required", "Future model-based judging must record prompt and rubric versions."))
    if not bool_value(bias_policy.get("limitations_required"), True) or not bool_value(rules.get("bias_variance_limitations_required"), True):
        findings.append(finding("llm_grader.bias_variance_limitations_missing", severity, "review_required", "Bias and variance limitations must be documented."))
    if not bool_value(residual_policy.get("required"), True) or not bool_value(rules.get("residual_risk_required"), True):
        findings.append(finding("llm_grader.residual_risk_policy_missing", severity, "review_required", "Residual risk declaration must be required."))
    if not bool_value(rules.get("advisory_only"), True) or not bool_value(boundary.get("advisory_only"), True):
        findings.append(finding("llm_grader.advisory_boundary_missing", "blocking", "blocked", "LLMGrader readiness must remain advisory-only."))

    risky_boundary_flags = [
        ("can_promote_without_human", "can_promote_without_human"),
        ("can_approve", "can_approve"),
        ("can_certify", "can_certify"),
        ("can_prove_compliance", "can_prove_compliance"),
    ]
    for rule_key, boundary_key in risky_boundary_flags:
        if bool_value(rules.get(rule_key)) or bool_value(boundary.get(boundary_key)):
            findings.append(finding(f"llm_grader.{rule_key}", "blocking", "blocked", f"`{rule_key}` is true; advisory readiness cannot approve, certify, prove compliance, or promote maturity."))

    if not bool_value(rules.get("deterministic_baseline_required"), True) or not bool_value(baseline.get("required"), True):
        findings.append(finding("llm_grader.deterministic_baseline_missing", "blocking", "blocked", "A deterministic baseline is required before any future advisory grader can be considered."))
    if not bool_value(rules.get("static_grader_remains_primary"), True) or not bool_value(baseline.get("static_grader_remains_primary"), True):
        findings.append(finding("llm_grader.static_grader_not_primary", "blocking", "blocked", "StaticGrader must remain primary over any future advisory model-based grader."))

    return findings


def report_status(rules: dict[str, Any], profile: str, posture: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if future_requested(rules) and profile in {"standard", "assured"}:
        return "review_required"
    if any(item.get("severity") in {"required", "warning"} or item.get("status") == "review_required" for item in findings):
        return "review_required"
    if posture.get("state") == "disabled" or not bool_value(rules.get("enabled"), False):
        return "disabled" if profile == "quickstart" else "readiness_only"
    if posture.get("state") == "readiness_only" or rules.get("state") == "readiness_only":
        return "readiness_only"
    if findings:
        return "advisory"
    return "readiness_only"


def build_report(root: Path, naos_root: str, profile: str, policy: dict[str, Any], rules_path: Path) -> dict[str, Any]:
    rules = load_yaml_mapping(rules_path)
    posture = profile_posture(rules, profile)
    findings = build_findings(rules, profile)
    status = report_status(rules, profile, posture, findings)

    cost_policy = as_mapping(rules.get("cost_policy"))
    data_policy = as_mapping(rules.get("data_exposure_policy"))
    model_policy = as_mapping(rules.get("model_policy"))
    prompt_policy = as_mapping(rules.get("prompt_rubric_policy"))
    bias_policy = as_mapping(rules.get("bias_variance_policy"))
    residual_policy = as_mapping(rules.get("residual_risk_policy"))
    baseline = as_mapping(rules.get("deterministic_baseline"))
    boundary = as_mapping(rules.get("advisory_boundary"))
    future_enablement = as_mapping(rules.get("future_enablement"))
    requested = future_requested(rules)

    summary = finding_counts(findings)
    summary.update(
        {
            "future_enablement_requested": requested,
            "runtime_enabled": bool_value(rules.get("runtime_enabled")),
            "provider_allowed": bool_value(rules.get("provider_allowed")),
            "cost_usd": float(cost_policy.get("cost_usd") or 0.0),
            "advisory_only": bool_value(rules.get("advisory_only"), True),
            "static_grader_primary": bool_value(rules.get("static_grader_remains_primary"), True),
        }
    )

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(rules_path),
        "rules_hash": safe_digest(rules_path),
        "runtime_enabled": bool_value(rules.get("runtime_enabled")),
        "provider_allowed": bool_value(rules.get("provider_allowed")),
        "external_api_allowed": bool_value(rules.get("external_api_allowed")),
        "model_dependency_allowed": bool_value(rules.get("model_dependency_allowed")),
        "api_keys_allowed": bool_value(rules.get("api_keys_allowed")),
        "cost_posture": {
            "cost_usd": float(cost_policy.get("cost_usd") or 0.0),
            "cost_incurred_by_default": bool_value(rules.get("cost_incurred_by_default")),
            "external_api_required": False,
            "provider_dependency_required": False,
            "model_dependency_required": False,
            "cost_budget_required_if_enabled_later": bool_value(rules.get("cost_budget_required_if_enabled_later"), True),
            "human_approval_required_before_cost": bool_value(rules.get("human_approval_required_before_cost"), True),
            "max_cost_usd": future_enablement.get("max_cost_usd", cost_policy.get("max_cost_usd")),
            "max_runs_per_day": future_enablement.get("max_runs_per_day", cost_policy.get("max_runs_per_day")),
        },
        "data_exposure_posture": {
            "review_required": bool_value(rules.get("data_exposure_review_required"), True),
            "data_exposure_level": future_enablement.get("data_exposure_level") or data_policy.get("default_data_exposure_level"),
            "allowed_data_classes": future_enablement.get("allowed_data_classes") or data_policy.get("allowed_data_classes") or [],
            "prohibited_data_classes": future_enablement.get("prohibited_data_classes") or data_policy.get("prohibited_data_classes") or [],
            "warning": "Future model-based judging may expose data depending on provider/configuration.",
        },
        "model_posture": {
            "model_role": future_enablement.get("model_role") or model_policy.get("model_role"),
            "provider": future_enablement.get("provider"),
            "model": future_enablement.get("model"),
            "model_version": future_enablement.get("model_version"),
            "provider_required_if_enabled_later": bool_value(model_policy.get("provider_required_if_enabled_later"), True),
            "model_version_required": bool_value(rules.get("model_version_required"), True),
            "provider_allowed_by_default": bool_value(rules.get("provider_allowed")),
            "model_dependency_allowed_by_default": bool_value(rules.get("model_dependency_allowed")),
            "warning": "Future model-based judging may drift across provider/model versions.",
        },
        "prompt_rubric_posture": {
            "prompt_version": future_enablement.get("prompt_version"),
            "rubric_version": future_enablement.get("rubric_version"),
            "prompt_rubric_version_required": bool_value(rules.get("prompt_rubric_version_required"), True),
            "review_required": bool_value(prompt_policy.get("prompt_and_rubric_review_required"), True),
            "warning": "Prompt/rubric drift can change advisory outputs.",
        },
        "bias_variance_posture": {
            "limitations_required": bool_value(rules.get("bias_variance_limitations_required"), True),
            "expected_limitations": bias_policy.get("expected_limitations") or [],
            "warning": "Model-based judging may be biased, inconsistent, or falsely confident.",
        },
        "residual_risk_posture": {
            "required": bool_value(rules.get("residual_risk_required"), True),
            "declared_for_future_enablement": future_enablement.get("residual_risks") or [],
            "required_risks": residual_policy.get("required_risks") or RESIDUAL_RISKS,
        },
        "deterministic_baseline": {
            "required": bool_value(rules.get("deterministic_baseline_required"), True),
            "primary_controls": baseline.get("primary_controls") or ["StaticGrader"],
            "static_grader_remains_primary": bool_value(rules.get("static_grader_remains_primary"), True),
        },
        "static_grader_primary": bool_value(rules.get("static_grader_remains_primary"), True),
        "advisory_boundary": {
            "advisory_only": bool_value(rules.get("advisory_only"), True),
            "can_promote_without_human": bool_value(rules.get("can_promote_without_human")),
            "can_approve": bool_value(rules.get("can_approve")),
            "can_certify": bool_value(rules.get("can_certify")),
            "can_prove_compliance": bool_value(rules.get("can_prove_compliance")),
            "can_replace_deterministic_controls": bool_value(boundary.get("can_replace_deterministic_controls")),
            "can_replace_human_review": bool_value(boundary.get("can_replace_human_review")),
            "may_challenge_deterministic_controls": bool_value(boundary.get("may_challenge_deterministic_controls"), True),
        },
        "future_enablement_requirements": [
            "provider",
            "model",
            "model_version",
            "prompt_version",
            "rubric_version",
            "max_cost_usd",
            "max_runs_per_day",
            "data_exposure_level",
            "allowed_data_classes",
            "prohibited_data_classes",
            "approval_owner",
            "human_review_boundary",
            "residual_risks",
            "not_claimed",
        ],
        "findings": findings,
        "known_gaps": [
            "No model-based judging runtime is implemented.",
            "No provider, model, prompt, rubric, cost budget, or data exposure approval is configured by default.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(requested or posture.get("human_review_required") or findings),
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate LLMGrader readiness posture without running an LLM.")
    parser.add_argument("--profile", default=None, choices=["quickstart", "lite", "standard", "assured"])
    parser.add_argument("--naos-root", default=None)
    parser.add_argument("--policy", default=None)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--rules", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.project_root).resolve()
    policy = load_policy(explicit_policy=args.policy, root=root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    rules_path, _source = resolve_rules_path(root, naos_root, policy, args.rules)
    try:
        report = build_report(root, naos_root, profile, policy, rules_path)
    except FileNotFoundError:
        report = {
            "schema": REPORT_SCHEMA,
            "generated_at": utc_now_text(),
            "profile": profile,
            "status": "not_configured",
            "naos_root": naos_root,
            "project_root": str(root),
            "rules_path": str(rules_path),
            "rules_hash": None,
            "runtime_enabled": False,
            "provider_allowed": False,
            "external_api_allowed": False,
            "model_dependency_allowed": False,
            "api_keys_allowed": False,
            "cost_posture": {
                "cost_usd": 0.0,
                "cost_incurred_by_default": False,
                "external_api_required": False,
                "provider_dependency_required": False,
                "model_dependency_required": False,
                "cost_budget_required_if_enabled_later": True,
                "human_approval_required_before_cost": True,
                "max_cost_usd": None,
                "max_runs_per_day": None,
            },
            "data_exposure_posture": {},
            "model_posture": {},
            "prompt_rubric_posture": {},
            "bias_variance_posture": {},
            "residual_risk_posture": {},
            "deterministic_baseline": {"required": True, "primary_controls": ["StaticGrader"], "static_grader_remains_primary": True},
            "static_grader_primary": True,
            "advisory_boundary": {"advisory_only": True, "can_promote_without_human": False, "can_approve": False, "can_certify": False, "can_prove_compliance": False},
            "future_enablement_requirements": [],
            "findings": [finding("llm_grader.rules_missing", "advisory", "not_configured", "LLMGrader readiness rules are missing.")],
            "known_gaps": ["LLMGrader readiness rules are missing."],
            "residual_risks": RESIDUAL_RISKS,
            "limitations": LIMITATIONS,
            "not_claimed": NOT_CLAIMED,
            "human_review_required": False,
            "summary": {"total_findings": 1, "blocking": 0, "required": 0, "warnings": 0, "advisory": 1},
        }

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "llm_grader_readiness_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        target = f" -> {output}" if output else ""
        print(f"NAOS LLMGrader readiness: {report['status']} (runtime_enabled={report['runtime_enabled']}, cost_usd={report['cost_posture']['cost_usd']}){target}")
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
