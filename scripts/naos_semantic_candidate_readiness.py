#!/usr/bin/env python3
"""Evaluate readiness posture for a future semantic candidate layer."""

from __future__ import annotations

import argparse
import hashlib
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
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.semantic_candidate_layer.v1"


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
    return kit_root() / "templates" / "structural-seeds" / "naos" / "semantic_candidate_layer_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("semantic_candidate_layer_rules") or "semantic_candidate_layer_rules.yaml")
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
    return {"id": identifier, "severity": severity, "status": status, "message": message}


def build_findings(rules: dict[str, Any], profile: str, posture: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    severity = "blocking" if profile == "assured" else "required" if profile == "standard" else "warning"

    risky_flags = [
        ("semantic_runtime_enabled", "semantic_candidate_layer.semantic_runtime_enabled", "Semantic runtime is enabled; Group 26 is readiness-only."),
        ("sqlite_vec_enabled", "semantic_candidate_layer.sqlite_vec_enabled", "sqlite-vec is enabled; it must remain deferred/project-configured."),
        ("embeddings_enabled", "semantic_candidate_layer.embeddings_enabled", "Embeddings are enabled; no embedding runtime is implemented in core NAOS."),
        ("extension_loading_allowed", "semantic_candidate_layer.extension_loading_allowed", "SQLite extension loading is allowed; it is prohibited in core NAOS."),
        ("external_embedding_calls_allowed", "semantic_candidate_layer.external_embedding_calls_allowed", "External embedding calls are allowed; cloud/API embedding calls are prohibited by default."),
        ("cloud_embedding_allowed", "semantic_candidate_layer.cloud_embedding_allowed", "Cloud embedding is allowed; cloud defaults are prohibited."),
    ]
    for key, identifier, message in risky_flags:
        if bool_value(rules.get(key)):
            findings.append(finding(identifier, severity, "blocked", message))

    source_policy = as_mapping(rules.get("source_hash_invalidation_policy"))
    if not bool_value(source_policy.get("required")) or not bool_value(source_policy.get("stale_when_source_hash_changes")):
        findings.append(
            finding(
                "semantic_candidate_layer.source_hash_invalidation_missing",
                severity,
                "review_required",
                "Source hash invalidation policy must exist before future embeddings can be trusted as current candidates.",
            )
        )

    sensitive_policy = as_mapping(rules.get("sensitive_content_embedding_policy"))
    if bool_value(sensitive_policy.get("embed_sensitive_content_by_default")):
        findings.append(
            finding(
                "semantic_candidate_layer.sensitive_content_embedding_allowed",
                severity,
                "blocked",
                "Sensitive content embedding is enabled by default; this must remain prohibited unless explicitly reviewed.",
            )
        )
    if not bool_value(sensitive_policy.get("sensitive_embedding_attempts_become_findings"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.sensitive_content_policy_missing",
                severity,
                "review_required",
                "Sensitive-content embedding attempts must become findings.",
            )
        )

    memory_policy = as_mapping(rules.get("memory_payload_embedding_policy"))
    if bool_value(memory_policy.get("embed_private_memory_payloads")) or bool_value(memory_policy.get("read_engram_db")):
        findings.append(
            finding(
                "semantic_candidate_layer.memory_payload_embedding_allowed",
                severity,
                "blocked",
                "Private memory payloads or Engram databases are configured for embedding; memory payloads must remain excluded.",
            )
        )
    for key in ("call_engram", "call_mcp", "call_memory_tools"):
        if bool_value(memory_policy.get(key)):
            findings.append(
                finding(
                    f"semantic_candidate_layer.{key}",
                    severity,
                    "blocked",
                    f"{key} is configured; readiness reporting must not call Engram, MCP, or memory tools.",
                )
            )

    global_policy = as_mapping(rules.get("global_semantic_scan_policy"))
    if bool_value(global_policy.get("allowed")):
        findings.append(
            finding(
                "semantic_candidate_layer.global_semantic_scan_allowed",
                severity,
                "blocked",
                "Global semantic scans are allowed; future semantic search must be task-scoped or metadata-prefiltered.",
            )
        )

    candidate_policy = as_mapping(rules.get("candidate_only_policy"))
    if not bool_value(rules.get("semantic_results_are_candidates_only"), True) or not bool_value(candidate_policy.get("candidates_only"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.candidate_only_policy_missing",
                severity,
                "blocked",
                "Semantic results must remain candidate references only.",
            )
        )
    if not bool_value(rules.get("source_artifacts_remain_authoritative"), True) or not bool_value(candidate_policy.get("source_artifacts_remain_authoritative"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.source_authority_policy_missing",
                severity,
                "blocked",
                "Source artifacts and deterministic evidence must remain authoritative over future semantic candidates.",
            )
        )
    if not bool_value(rules.get("exact_fts_baseline_required"), True) or not bool_value(candidate_policy.get("exact_fts_baseline_required"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.exact_fts_baseline_missing",
                severity,
                "review_required",
                "Exact/path/metadata/FTS query modes must remain the deterministic baseline.",
            )
        )
    if not bool_value(candidate_policy.get("cannot_outrank_exact_or_source_evidence"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.semantic_outranks_source",
                severity,
                "blocked",
                "Semantic candidates are configured to outrank exact/FTS/source evidence.",
            )
        )

    review_requirements = as_mapping(rules.get("human_review_requirements"))
    if profile == "standard" and not bool_value(review_requirements.get("standard_required_if_readiness_enabled"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.standard_human_review_missing",
                "required",
                "review_required",
                "Standard profile must require human review before semantic readiness is turned into runtime enablement.",
            )
        )
    if profile == "assured" and not bool_value(review_requirements.get("assured_required_if_readiness_enabled"), True):
        findings.append(
            finding(
                "semantic_candidate_layer.assured_human_review_missing",
                "blocking",
                "blocked",
                "Assured profile must require human review before semantic readiness is turned into runtime enablement.",
            )
        )

    return findings


def report_status(rules: dict[str, Any], profile: str, posture: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if any(item.get("severity") == "required" or item.get("status") == "review_required" for item in findings):
        return "review_required"
    if not bool_value(rules.get("enabled"), True) or posture.get("state") == "disabled":
        return "disabled"
    if posture.get("severity") == "review_required":
        return "review_required"
    if posture.get("state") == "readiness_only" or rules.get("state") == "readiness_only":
        return "readiness_only"
    if findings:
        return "advisory"
    return "not_configured"


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    rules_path: Path,
    rules_source: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    posture = profile_posture(rules, profile)
    findings = build_findings(rules, profile, posture)
    status = report_status(rules, profile, posture, findings)
    summary = finding_counts(findings)
    summary.update(
        {
            "status": status,
            "profile_state": posture.get("state"),
            "semantic_runtime_enabled": bool_value(rules.get("semantic_runtime_enabled")),
            "sqlite_vec_enabled": bool_value(rules.get("sqlite_vec_enabled")),
            "embeddings_enabled": bool_value(rules.get("embeddings_enabled")),
            "extension_loading_allowed": bool_value(rules.get("extension_loading_allowed")),
            "external_embedding_calls_allowed": bool_value(rules.get("external_embedding_calls_allowed")),
            "cloud_embedding_allowed": bool_value(rules.get("cloud_embedding_allowed")),
            "human_review_required": bool_value(posture.get("human_review_required")) or any(
                item.get("severity") in {"required", "blocking"} for item in findings
            ),
        }
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(rules_path),
        "rules_source": rules_source,
        "rules_hash": safe_digest(rules_path),
        "semantic_runtime_enabled": bool_value(rules.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool_value(rules.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool_value(rules.get("embeddings_enabled")),
        "extension_loading_allowed": bool_value(rules.get("extension_loading_allowed")),
        "external_embedding_calls_allowed": bool_value(rules.get("external_embedding_calls_allowed")),
        "cloud_embedding_allowed": bool_value(rules.get("cloud_embedding_allowed")),
        "local_provider_required": bool_value(rules.get("local_provider_required_if_enabled_later"), True),
        "profile_posture": posture,
        "provider_posture": as_mapping(rules.get("provider_posture")),
        "embedding_model_policy": as_mapping(rules.get("embedding_model_policy")),
        "sqlite_vec_posture": as_mapping(rules.get("sqlite_vec_posture")),
        "extension_loading_posture": as_mapping(rules.get("extension_loading_posture")),
        "semantic_query_posture": as_mapping(rules.get("semantic_query_posture")),
        "source_hash_invalidation_policy": as_mapping(rules.get("source_hash_invalidation_policy")),
        "stale_embedding_policy": as_mapping(rules.get("stale_embedding_policy")),
        "sensitive_content_policy": as_mapping(rules.get("sensitive_content_embedding_policy")),
        "memory_policy": as_mapping(rules.get("memory_payload_embedding_policy")),
        "task_scoped_prefilter_policy": as_mapping(rules.get("task_scoped_prefilter_policy")),
        "global_scan_policy": as_mapping(rules.get("global_semantic_scan_policy")),
        "result_limit_policy": as_mapping(rules.get("result_limit_policy")),
        "ranking_explanation_policy": as_mapping(rules.get("ranking_explanation_policy")),
        "model_metadata_policy": as_mapping(rules.get("model_metadata_policy")),
        "provider_metadata_policy": as_mapping(rules.get("provider_metadata_policy")),
        "review_status_policy": as_mapping(rules.get("review_status_policy")),
        "candidate_only_policy": as_mapping(rules.get("candidate_only_policy")),
        "future_data_model": as_mapping(rules.get("future_data_model")),
        "ob1_metadata_hooks": as_mapping(rules.get("ob1_metadata_hooks")),
        "integration_points": as_mapping(rules.get("integration_points")),
        "findings": findings,
        "known_gaps": rules.get("known_gaps") or [],
        "residual_risks": rules.get("residual_risks") or [],
        "waivers": rules.get("waivers") or [],
        "limitations": rules.get("limitations") or [],
        "not_claimed": rules.get("not_claimed") or [],
        "human_review_required": bool(summary["human_review_required"]),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate semantic candidate layer readiness without enabling vector runtime.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy or naos.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--rules", help="Optional semantic_candidate_layer_rules.yaml path.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit-code behavior.")
    parser.add_argument("--json", action="store_true", help="Print JSON report. Default prints JSON for script consistency.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    rules = load_yaml_mapping(rules_path)
    report = build_report(root, naos_root, profile, policy, rules, rules_path, rules_source)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "semantic_candidate_layer_report")
    write_report(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
