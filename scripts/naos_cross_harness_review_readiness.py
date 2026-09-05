#!/usr/bin/env python3
"""Report readiness-only posture for future cross-harness review and DSSE planning."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    session_report_default_path,
    sessions_index_path,
    severity_for_profile,
    write_report_with_session,
)
from naos_schema_validation import validate_json_schema_file  # noqa: E402


SCHEMA = "naos.cross_harness_review_readiness_report.v1"
CONFIG_SCHEMA = "naos.cross_harness_review_readiness.v1"
CONFIG_SCHEMA_PATH = SCRIPT_DIR.parent / "schemas" / "naos" / "cross_harness_review_readiness.schema.json"
REQUIRED_NOT_CLAIMED = {
    "cross-harness execution",
    "DSSE signing",
    "signature verification",
    "key custody",
    "signed attestation",
    "compliance proof",
    "approval",
    "certification",
    "behavioral correctness proof",
    "human review replacement",
}
LIMITATIONS = [
    "Cross-harness review readiness is configuration and reporting only.",
    "The report does not execute harnesses, call LLMs/providers/APIs, access the network, sign artifacts, verify signatures, read keys, or create attestations.",
    "Readiness metadata does not prove independent review occurred, prove compliance, approve work, or replace human review.",
]
NOT_CLAIMED = [
    "cross-harness execution",
    "DSSE signing",
    "signature verification",
    "key custody",
    "signed attestation",
    "attestation authority",
    "non-repudiation",
    "compliance proof",
    "approval",
    "certification",
    "regulator acceptance",
    "behavioral correctness proof",
    "human review replacement",
]
RESIDUAL_RISKS = [
    "Declared harness inventories can become stale as tools and review workflows change.",
    "Adopters must separately design and operate key custody, signing, verification, and attestation authority.",
    "Future cross-harness execution can expose sensitive data if trust boundaries and artifact scope are not reviewed.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    index_path = sessions_index_path(root, naos_root, policy)
    if not index_path.exists():
        return None
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id") if isinstance(data, dict) else None
    return str(value) if value else None


def finding(item_id: str, severity: str, finding_status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": item_id,
        "severity": severity,
        "status": finding_status,
        "message": message,
        "human_review_required": True,
        **extra,
    }


def config_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("cross_harness_review_readiness") or "cross_harness_review_readiness.yaml")
    project_path = root / naos_root / filename
    if project_path.exists() or not is_kit_repository(root, naos_root):
        return project_path, "project"
    return root / "templates" / "structural-seeds" / "naos" / "cross_harness_review_readiness.yaml", "kit_template"


def load_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "cross-harness review readiness config must parse to a YAML mapping"
    return data, None


def validate_config(data: dict[str, Any] | None, parse_error: str | None, profile: str, policy: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    severity = severity_for_profile(profile, policy)
    if data is None:
        return False, [
            finding(
                "cross_harness_review_readiness.invalid_config",
                severity,
                "invalid_config",
                f"Cross-harness review readiness config could not be parsed: {parse_error}",
            )
        ]
    findings: list[dict[str, Any]] = []
    for index, error in enumerate(validate_json_schema_file(data, CONFIG_SCHEMA_PATH)):
        findings.append(
            finding(
                f"cross_harness_review_readiness.schema_validation.{index}",
                severity,
                "invalid_config",
                f"Cross-harness review readiness config failed schema validation: {error}",
            )
        )
    if data.get("schema") != CONFIG_SCHEMA:
        findings.append(finding("cross_harness_review_readiness.schema", severity, "invalid_config", "Config schema id is missing or unsupported."))
    if data.get("enabled") is not True:
        findings.append(finding("cross_harness_review_readiness.disabled", "advisory", "advisory", "Cross-harness review readiness is disabled."))
    if data.get("mode") != "readiness_only":
        findings.append(finding("cross_harness_review_readiness.mode", severity, "invalid_config", "Mode must remain readiness_only."))
    not_claimed = set(str(item) for item in data.get("not_claimed") or [])
    missing_non_claims = sorted(REQUIRED_NOT_CLAIMED - not_claimed)
    if missing_non_claims:
        findings.append(
            finding(
                "cross_harness_review_readiness.not_claimed_missing",
                severity,
                "review_required",
                "Required non-claims are missing.",
                missing=missing_non_claims,
            )
        )
    if data.get("human_review_required") is not True:
        findings.append(finding("cross_harness_review_readiness.human_review_missing", severity, "review_required", "human_review_required must be true."))
    return not any(item.get("status") == "invalid_config" for item in findings), findings


def evaluate_config(data: dict[str, Any], profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    cross = data.get("cross_harness_review") if isinstance(data.get("cross_harness_review"), dict) else {}
    dsse = data.get("dsse_readiness") if isinstance(data.get("dsse_readiness"), dict) else {}
    harnesses = data.get("declared_harnesses") if isinstance(data.get("declared_harnesses"), list) else []
    requirements = data.get("readiness_requirements") if isinstance(data.get("readiness_requirements"), list) else []
    findings: list[dict[str, Any]] = []

    unsafe_runtime_fields = [
        "runtime_execution_enabled",
        "harness_execution_allowed",
        "external_network_allowed",
    ]
    for field in unsafe_runtime_fields:
        if cross.get(field) is True:
            findings.append(
                finding(
                    f"cross_harness_review_readiness.unsafe_runtime.{field}",
                    severity,
                    "unsafe_runtime_enabled",
                    f"Readiness config enables {field}; P5 must remain readiness-only and must not execute harnesses or use external runtime.",
                    field=field,
                )
            )
    if cross.get("provider_api_allowed") is True:
        findings.append(
            finding(
                "cross_harness_review_readiness.provider_api_allowed",
                severity,
                "provider_api_enabled",
                "Readiness config allows provider/API access; P5 must not call LLMs, providers, APIs, or the network.",
            )
        )
    for field in ["signing_enabled", "signature_verification_enabled", "key_custody_configured"]:
        if dsse.get(field) is True:
            findings.append(
                finding(
                    f"cross_harness_review_readiness.dsse.{field}",
                    severity,
                    "signing_enabled_in_core",
                    f"Readiness config enables {field}; NAOS core must not sign, verify signatures, read keys, or custody keys.",
                    field=field,
                )
            )
    for index, harness in enumerate(harnesses):
        if isinstance(harness, dict) and harness.get("execution_enabled") is True:
            findings.append(
                finding(
                    f"cross_harness_review_readiness.harness_execution.{harness.get('harness_id') or index}",
                    severity,
                    "unsafe_runtime_enabled",
                    "Declared harness has execution_enabled=true; readiness metadata must not enable harness execution.",
                    harness_id=harness.get("harness_id"),
                )
            )

    requirements_missing = [
        item for item in requirements
        if isinstance(item, dict) and item.get("required") is True and str(item.get("status") or "missing") in {"missing", "review_required", "unknown"}
    ]
    requirements_deferred = [
        item for item in requirements
        if isinstance(item, dict) and str(item.get("status") or "") == "deferred"
    ]
    requirement_severity = severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"})
    for item in requirements_missing:
        findings.append(
            finding(
                f"cross_harness_review_readiness.requirement.{item.get('requirement_id')}",
                requirement_severity,
                "missing_requirements",
                "Required cross-harness/attestation readiness requirement is missing or unresolved.",
                requirement_id=item.get("requirement_id"),
            )
        )

    required_count = sum(1 for item in requirements if isinstance(item, dict) and item.get("required") is True)
    missing_count = len(requirements_missing)
    readiness_score = 100 if required_count == 0 else int(round(((required_count - missing_count) / required_count) * 100))
    return {
        "runtime_execution_enabled": bool(cross.get("runtime_execution_enabled")),
        "harness_execution_allowed": bool(cross.get("harness_execution_allowed")),
        "provider_api_allowed": bool(cross.get("provider_api_allowed")),
        "external_network_allowed": bool(cross.get("external_network_allowed")),
        "declared_harnesses": [item for item in harnesses if isinstance(item, dict)],
        "declared_harness_count": sum(1 for item in harnesses if isinstance(item, dict)),
        "dsse_readiness": dsse if isinstance(dsse, dict) else {},
        "readiness_requirements": [item for item in requirements if isinstance(item, dict)],
        "requirements_missing": requirements_missing,
        "requirements_deferred": requirements_deferred,
        "readiness_score": max(0, readiness_score),
        "findings": findings,
    }


def status_for_report(profile: str, config_present: bool, config_valid: bool, evaluated: dict[str, Any]) -> str:
    if not config_present:
        return "missing_config"
    if not config_valid:
        return "invalid_config"
    finding_statuses = {str(item.get("status")) for item in evaluated.get("findings") or []}
    if "provider_api_enabled" in finding_statuses:
        return "provider_api_enabled"
    if "signing_enabled_in_core" in finding_statuses:
        return "signing_enabled_in_core"
    if "unsafe_runtime_enabled" in finding_statuses:
        return "unsafe_runtime_enabled"
    if evaluated.get("requirements_missing"):
        return "advisory" if profile in {"quickstart", "lite"} else "missing_requirements"
    return "ready"


def empty_evaluation() -> dict[str, Any]:
    return {
        "runtime_execution_enabled": False,
        "harness_execution_allowed": False,
        "provider_api_allowed": False,
        "external_network_allowed": False,
        "declared_harnesses": [],
        "declared_harness_count": 0,
        "dsse_readiness": {},
        "readiness_requirements": [],
        "requirements_missing": [],
        "requirements_deferred": [],
        "readiness_score": 0,
        "findings": [],
    }


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, int]]:
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    generated_at = utc_now()
    path, source = config_path(root, naos_root, policy, args.input)
    config_present = path.exists()
    data: dict[str, Any] | None = None
    parse_error: str | None = None
    config_valid = False
    findings: list[dict[str, Any]] = []
    evaluated = empty_evaluation()

    if not config_present:
        findings.append(
            finding(
                "cross_harness_review_readiness.missing_config",
                severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"}),
                "missing_config",
                "Cross-harness review readiness config is missing.",
                path=str(path),
            )
        )
    else:
        data, parse_error = load_yaml(path)
        config_valid, config_findings = validate_config(data, parse_error, profile, policy)
        findings.extend(config_findings)
        if config_valid and data is not None and data.get("enabled") is True:
            evaluated = evaluate_config(data, profile, policy)
            findings.extend(evaluated["findings"])

    summary = finding_counts(findings)
    status = status_for_report(profile, config_present, config_valid, evaluated)
    session_id = latest_session_id(root, naos_root, policy)
    report = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "generated_by": build_generated_by(root, session_id=session_id, generated_at=generated_at),
        "config_path": str(path),
        "config_source": source,
        "config_present": config_present,
        "config_valid": config_valid,
        "runtime_execution_enabled": evaluated["runtime_execution_enabled"],
        "harness_execution_allowed": evaluated["harness_execution_allowed"],
        "provider_api_allowed": evaluated["provider_api_allowed"],
        "external_network_allowed": evaluated["external_network_allowed"],
        "declared_harness_count": evaluated["declared_harness_count"],
        "declared_harnesses": evaluated["declared_harnesses"],
        "dsse_readiness": evaluated["dsse_readiness"],
        "readiness_requirements": evaluated["readiness_requirements"],
        "requirements_missing": evaluated["requirements_missing"],
        "requirements_deferred": evaluated["requirements_deferred"],
        "readiness_score": evaluated["readiness_score"],
        "findings": findings,
        "known_gaps": [
            "P5 does not implement harness execution, DSSE signing, signature verification, key custody, or attestation authority.",
            "Adopters must define trust boundaries, data exposure review, signing policy, key custody, verification policy, and human review outside the core kit before future activation.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
        "summary": {
            **summary,
            "config_source": source,
            "declared_harness_count": evaluated["declared_harness_count"],
            "requirements_missing": len(evaluated["requirements_missing"]),
            "requirements_deferred": len(evaluated["requirements_deferred"]),
            "readiness_score": evaluated["readiness_score"],
            "unsafe_runtime_flags": sum(
                1 for key in ["runtime_execution_enabled", "harness_execution_allowed", "provider_api_allowed", "external_network_allowed"]
                if evaluated[key]
            ),
            "dsse_core_flags": sum(
                1 for key in ["signing_enabled", "signature_verification_enabled", "key_custody_configured"]
                if bool(evaluated["dsse_readiness"].get(key))
            ),
        },
    }
    return report, summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report readiness-only posture for future cross-harness review and DSSE-style planning.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--input", help="Explicit cross_harness_review_readiness.yaml path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, summary = build_report(args)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "cross_harness_review_readiness_report")
    session_path = None
    if report.get("session_id"):
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "cross_harness_review_readiness_report")
    write_report_with_session(latest_path, session_path, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS cross-harness review readiness: {report['status']} (score {report['readiness_score']})")
    return exit_code_for_summary(report["profile"], summary, policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
