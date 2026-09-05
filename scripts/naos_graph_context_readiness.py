#!/usr/bin/env python3
"""Evaluate readiness posture for future graph-context traversal guardrails."""

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


REPORT_SCHEMA = "naos.graph_context_readiness.v1"


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
    return kit_root() / "templates" / "structural-seeds" / "naos" / "graph_context_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("graph_context_rules") or "graph_context_rules.yaml")
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


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


def traversal_limits(rules: dict[str, Any]) -> dict[str, Any]:
    configured = as_mapping(rules.get("traversal_limits"))
    return {
        "max_hops": int_value(configured.get("max_hops", rules.get("max_hops")), 0),
        "max_allowed_hops": int_value(configured.get("max_allowed_hops"), 3),
        "max_seed_nodes": int_value(configured.get("max_seed_nodes", rules.get("max_seed_nodes")), 0),
        "max_allowed_seed_nodes": int_value(configured.get("max_allowed_seed_nodes"), 10),
        "max_edges_returned": int_value(configured.get("max_edges_returned", rules.get("max_edges_returned")), 0),
        "max_allowed_edges_returned": int_value(configured.get("max_allowed_edges_returned"), 100),
        "require_bounded_results": bool_value(configured.get("require_bounded_results"), True),
        "require_explicit_seed_nodes": bool_value(configured.get("require_explicit_seed_nodes"), True),
    }


def build_findings(rules: dict[str, Any], profile: str, posture: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    severity = "blocking" if profile == "assured" else "required" if profile == "standard" else "warning"

    risky_flags = [
        ("graph_runtime_enabled", "graph_context.graph_runtime_enabled", "Graph runtime is enabled; Group 27 is readiness-only."),
        ("networkx_enabled", "graph_context.networkx_enabled", "NetworkX is enabled; graph algorithms remain deferred/project-configured."),
        ("graphml_enabled", "graph_context.graphml_enabled", "GraphML export/import is enabled; graph file runtime remains deferred."),
        ("graph_database_allowed", "graph_context.graph_database_allowed", "Graph database use is allowed; core NAOS does not configure graph databases."),
        ("graph_algorithms_enabled", "graph_context.graph_algorithms_enabled", "Graph algorithms are enabled; PageRank/centrality/community detection remain deferred."),
        ("global_graph_scan_allowed", "graph_context.global_graph_scan_allowed", "Global graph scans are allowed; traversal must start from explicit bounded seeds."),
    ]
    for key, identifier, message in risky_flags:
        if bool_value(rules.get(key)):
            findings.append(finding(identifier, severity, "blocked", message))

    if not bool_value(rules.get("explicit_link_traversal_only"), True):
        findings.append(
            finding(
                "graph_context.explicit_link_traversal_only_missing",
                severity,
                "blocked",
                "Graph context must remain explicit-link traversal only until a future runtime is reviewed.",
            )
        )

    limits = traversal_limits(rules)
    limit_checks = [
        ("max_hops", "max_allowed_hops", "graph_context.max_hops_unbounded", "max_hops must be present and bounded."),
        ("max_seed_nodes", "max_allowed_seed_nodes", "graph_context.max_seed_nodes_unbounded", "max_seed_nodes must be present and bounded."),
        ("max_edges_returned", "max_allowed_edges_returned", "graph_context.max_edges_returned_unbounded", "max_edges_returned must be present and bounded."),
    ]
    for value_key, max_key, identifier, message in limit_checks:
        value = int_value(limits.get(value_key), 0)
        maximum = int_value(limits.get(max_key), 0)
        if value <= 0 or (maximum > 0 and value > maximum):
            findings.append(finding(identifier, severity, "review_required", message))
    if not bool_value(limits.get("require_explicit_seed_nodes"), True):
        findings.append(
            finding(
                "graph_context.explicit_seed_nodes_missing",
                severity,
                "review_required",
                "Future graph traversal must require explicit task/spec/artifact/query seed nodes.",
            )
        )

    source_policy = as_mapping(rules.get("source_authority_policy"))
    if not bool_value(source_policy.get("source_artifacts_remain_authoritative"), True):
        findings.append(
            finding(
                "graph_context.source_authority_missing",
                severity,
                "blocked",
                "Source artifacts must remain authoritative over graph links.",
            )
        )
    if not bool_value(source_policy.get("graph_links_are_candidates_only"), True) or not bool_value(source_policy.get("graph_links_are_not_truth"), True):
        findings.append(
            finding(
                "graph_context.candidate_link_policy_missing",
                severity,
                "blocked",
                "Graph links must remain candidate relationships and navigation aids only.",
            )
        )
    if not bool_value(source_policy.get("cannot_outrank_source_artifacts"), True):
        findings.append(
            finding(
                "graph_context.graph_links_outrank_source",
                severity,
                "blocked",
                "Graph links are configured to outrank source artifacts.",
            )
        )

    stale_policy = as_mapping(rules.get("stale_link_policy"))
    if not bool_value(stale_policy.get("required")) or not bool_value(stale_policy.get("stale_links_become_findings")):
        findings.append(
            finding(
                "graph_context.stale_link_policy_missing",
                severity,
                "review_required",
                "Stale-link policy must exist and route stale links to findings.",
            )
        )

    sensitive_policy = as_mapping(rules.get("sensitive_link_policy"))
    if not bool_value(sensitive_policy.get("required")) or not bool_value(sensitive_policy.get("sensitive_links_become_findings")):
        findings.append(
            finding(
                "graph_context.sensitive_link_policy_missing",
                severity,
                "review_required",
                "Sensitive-link policy must exist and route sensitive links to findings.",
            )
        )
    if bool_value(sensitive_policy.get("link_sensitive_content_by_default")):
        findings.append(
            finding(
                "graph_context.sensitive_links_enabled_by_default",
                severity,
                "blocked",
                "Sensitive links are enabled by default; this must remain prohibited unless explicitly reviewed.",
            )
        )

    feedback_policy = as_mapping(rules.get("generated_artifact_feedback_loop_policy"))
    if bool_value(feedback_policy.get("generated_context_packs_are_graph_sources_by_default")):
        findings.append(
            finding(
                "graph_context.generated_context_pack_feedback_loop",
                severity,
                "blocked",
                "Generated context packs are configured as graph sources by default, creating feedback-loop risk.",
            )
        )

    task_policy = as_mapping(rules.get("task_scoped_traversal_policy"))
    if not bool_value(task_policy.get("required")) or not bool_value(task_policy.get("start_from_explicit_task_spec_artifact_or_query_seed")):
        findings.append(
            finding(
                "graph_context.task_scoped_traversal_missing",
                severity,
                "review_required",
                "Future traversal must be task-scoped or seeded from explicit spec/artifact/query references.",
            )
        )

    memory_policy = as_mapping(rules.get("memory_policy"))
    if bool_value(memory_policy.get("graph_private_memory_payloads")) or bool_value(memory_policy.get("read_engram_db")):
        findings.append(
            finding(
                "graph_context.memory_payload_graphing_allowed",
                severity,
                "blocked",
                "Private memory payloads or Engram databases are configured as graph sources; this is prohibited.",
            )
        )
    for key in ("call_engram", "call_mcp", "call_memory_tools"):
        if bool_value(memory_policy.get(key)):
            findings.append(
                finding(
                    f"graph_context.{key}",
                    severity,
                    "blocked",
                    f"{key} is configured; readiness reporting must not call Engram, MCP, or memory tools.",
                )
            )

    review_requirements = as_mapping(rules.get("human_review_requirements"))
    if profile == "standard" and not bool_value(review_requirements.get("standard_required_if_readiness_enabled"), True):
        findings.append(
            finding(
                "graph_context.standard_human_review_missing",
                "required",
                "review_required",
                "Standard profile must require human review before graph readiness becomes runtime traversal.",
            )
        )
    if profile == "assured" and not bool_value(review_requirements.get("assured_required_if_readiness_enabled"), True):
        findings.append(
            finding(
                "graph_context.assured_human_review_missing",
                "blocking",
                "blocked",
                "Assured profile must require human review before graph readiness becomes runtime traversal.",
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
    limits = traversal_limits(rules)
    summary = finding_counts(findings)
    summary.update(
        {
            "status": status,
            "profile_state": posture.get("state"),
            "graph_runtime_enabled": bool_value(rules.get("graph_runtime_enabled")),
            "explicit_link_traversal_only": bool_value(rules.get("explicit_link_traversal_only"), True),
            "global_graph_scan_allowed": bool_value(rules.get("global_graph_scan_allowed")),
            "networkx_enabled": bool_value(rules.get("networkx_enabled")),
            "graphml_enabled": bool_value(rules.get("graphml_enabled")),
            "graph_algorithms_enabled": bool_value(rules.get("graph_algorithms_enabled")),
            "allowed_link_types": len(as_list(rules.get("allowed_link_types"))),
            "max_hops": limits["max_hops"],
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
        "graph_runtime_enabled": bool_value(rules.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool_value(rules.get("explicit_link_traversal_only"), True),
        "global_graph_scan_allowed": bool_value(rules.get("global_graph_scan_allowed")),
        "graph_database_allowed": bool_value(rules.get("graph_database_allowed")),
        "networkx_enabled": bool_value(rules.get("networkx_enabled")),
        "graphml_enabled": bool_value(rules.get("graphml_enabled")),
        "graph_algorithms_enabled": bool_value(rules.get("graph_algorithms_enabled")),
        "profile_posture": posture,
        "traversal_limits": limits,
        "allowed_link_types": as_list(rules.get("allowed_link_types")),
        "prohibited_link_types": as_list(rules.get("prohibited_link_types")),
        "link_family_posture": as_list(rules.get("link_family_posture")),
        "source_authority_policy": as_mapping(rules.get("source_authority_policy")),
        "stale_link_policy": as_mapping(rules.get("stale_link_policy")),
        "sensitive_link_policy": as_mapping(rules.get("sensitive_link_policy")),
        "generated_artifact_feedback_loop_policy": as_mapping(rules.get("generated_artifact_feedback_loop_policy")),
        "task_scoped_traversal_policy": as_mapping(rules.get("task_scoped_traversal_policy")),
        "local_context_index_integration": as_mapping(rules.get("local_context_index_integration")),
        "local_context_query_integration": as_mapping(rules.get("local_context_query_integration")),
        "task_context_pack_integration": as_mapping(rules.get("task_context_pack_integration")),
        "semantic_candidate_layer_integration": as_mapping(rules.get("semantic_candidate_layer_integration")),
        "memory_policy": as_mapping(rules.get("memory_policy")),
        "future_graph_runtime": as_mapping(rules.get("future_graph_runtime")),
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
    parser = argparse.ArgumentParser(description="Evaluate graph-context readiness without enabling graph runtime.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy or naos.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--rules", help="Optional graph_context_rules.yaml path.")
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
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "graph_context_readiness_report")
    write_report(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
