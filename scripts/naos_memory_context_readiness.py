#!/usr/bin/env python3
"""Generate AI context-continuity and memory-governance readiness reports."""

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
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    write_report,
)
from naos_mcp_config_registry import (  # noqa: E402
    resolve_engram_project,
    scan_mcp_configs,
    summarize_mcp_configs,
)


REPORT_SCHEMA = "naos.memory_context_readiness.v1"
ACCESS_LEVELS = {"none", "read_only", "draft_write", "approved_write", "admin_config"}
WRITE_LEVELS = {"draft_write", "approved_write", "admin_config"}
PENDING_MEMORY_STATES = {"pending_external_verification", "pending_existing_verification"}
INACTIVE_MEMORY_STATES = {"not_configured", "deferred", "unknown"}
VALID_MEMORY_CONFIG_STATES = {
    "deferred",
    "pending_external_verification",
    "pending_existing_verification",
    "configured",
    "disabled",
    "broken",
}
REQUIRED_FORBIDDEN_CATEGORIES = {
    "secrets",
    "tokens",
    "API keys",
    "passwords",
    "certificates",
    "private keys",
    "connection strings",
    "PII",
    "customer data",
    "tenant data",
    "regulated data",
    "hidden approvals",
    "governance override instructions",
    "legal/compliance conclusions as approved facts",
    "sensitive exploit details unless explicitly approved",
    "private/internal material unless explicitly approved",
}
NOT_CLAIMED = [
    "hallucination prevention",
    "memory as evidence",
    "memory as approval",
    "compliance proof",
    "architecture authority",
    "security exception",
    "legal or regulatory decision",
    "cloud memory by default",
    "automatic memory writes",
    "automatic context injection",
    "universal MCP access",
    "complete continuity",
]
def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_generated_at(value: str | None) -> str:
    if not value:
        return utc_now_text()
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_context_rules.yaml"


def default_matrix_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_authorization_matrix.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("memory_context_rules") or "memory_context_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def resolve_matrix_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("memory_authorization_matrix") or "memory_authorization_matrix.yaml")
    project_matrix = root / naos_root / filename
    if project_matrix.exists():
        return project_matrix, "project"
    return default_matrix_template(), "template"


def load_memory_config(root: Path) -> dict[str, Any]:
    candidates = [
        root / "configs" / "naos_memory.yaml",
        root / "naos" / "configs" / "naos_memory.yaml",
    ]
    for path in candidates:
        if path.is_file():
            try:
                data = load_yaml(path)
            except Exception:
                return {"_error": f"invalid YAML: {path}", "_path": str(path)}
            memory = data.get("memory", data) if isinstance(data, dict) else {}
            if isinstance(memory, dict):
                memory["_path"] = str(path)
                return memory
    return {}


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def rule_severity(root: Path, naos_root: str, profile: str, policy: dict[str, Any], rules: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    mapping = rules.get("profile_severity_behavior") if isinstance(rules.get("profile_severity_behavior"), dict) else {}
    return str(mapping.get(profile) or severity_for_profile(profile, policy) or "advisory")


def finding(
    item_id: str,
    severity: str,
    status: str,
    message: str,
    actions: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": item_id,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": actions or [],
    }
    result.update({key: value for key, value in extra.items() if value is not None})
    return result


def inspect_project_mcp_configs(root: Path) -> dict[str, Any]:
    return summarize_mcp_configs(scan_mcp_configs(root))


def evaluate_memory_config_invariants(
    memory_config: dict[str, Any],
    severity: str,
) -> list[dict[str, Any]]:
    """Report deterministic state/config contradictions before access analysis."""

    if not memory_config:
        return []
    if error := memory_config.get("_error"):
        return [
            finding(
                "memory_config_parse_error",
                severity,
                "conflict",
                str(error),
                ["Repair configs/naos_memory.yaml before claiming memory readiness."],
            )
        ]

    state = str(memory_config.get("state") or "unknown")
    if state not in VALID_MEMORY_CONFIG_STATES:
        return [
            finding(
                "memory_config_state_invalid",
                severity,
                "conflict",
                f"Memory config state is not recognized: {state}.",
                ["Use a supported setup state and rerun the read-only readiness check."],
            )
        ]

    findings: list[dict[str, Any]] = []
    enabled = memory_config.get("enabled")
    if state == "configured" and enabled is not True:
        findings.append(
            finding(
                "memory_config_state_enabled_incoherent",
                severity,
                "conflict",
                "Memory state is configured but enabled is not true.",
                ["Complete reviewed provider verification before setting configured and enabled together."],
            )
        )
    elif state != "configured" and enabled is True:
        findings.append(
            finding(
                "memory_config_state_enabled_incoherent",
                severity,
                "conflict",
                f"Memory is enabled while state is {state}; enabled true requires configured state.",
                ["Disable memory until configuration is verified, or complete the reviewed configured transition."],
            )
        )
    if state == "broken":
        findings.append(
            finding(
                "memory_config_broken",
                severity,
                "review_required",
                "Memory configuration is explicitly marked broken.",
                ["Repair or explicitly disable/defer memory before claiming readiness."],
            )
        )
    return findings


def access_is_write(value: Any) -> bool:
    return str(value or "none") in WRITE_LEVELS


def evaluate_hierarchy(rules: dict[str, Any], severity: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    hierarchy = rules.get("authoritative_source_hierarchy") if isinstance(rules.get("authoritative_source_hierarchy"), list) else []
    findings: list[dict[str, Any]] = []
    by_id = {str(item.get("id")): item for item in hierarchy if isinstance(item, dict)}
    required_ids = {
        "current_user_instruction",
        "repository_governance",
        "git_working_state",
        "deterministic_naos_evidence",
        "memory_context_packs",
        "external_references",
    }
    missing = sorted(required_ids - set(by_id))
    if missing:
        findings.append(
            finding(
                "source_of_truth_hierarchy",
                severity,
                "missing",
                f"Source-of-truth hierarchy is missing required entries: {', '.join(missing)}.",
                ["Declare the full source-of-truth hierarchy before relying on memory continuity."],
            )
        )
    memory_rank = int(by_id.get("memory_context_packs", {}).get("rank", 999)) if by_id.get("memory_context_packs") else 999
    authoritative_ranks = [
        int(by_id.get(key, {}).get("rank", 999))
        for key in [
            "current_user_instruction",
            "repository_governance",
            "git_working_state",
            "deterministic_naos_evidence",
        ]
        if key in by_id
    ]
    if authoritative_ranks and memory_rank <= max(authoritative_ranks):
        findings.append(
            finding(
                "memory_source_of_truth_rank",
                severity,
                "conflict",
                "Memory is ranked at or above repository evidence or current instructions.",
                ["Move memory/context packs below deterministic repo evidence and current user instructions."],
            )
        )
    return hierarchy, findings


def evaluate_forbidden_categories(rules: dict[str, Any], severity: str) -> tuple[list[str], list[dict[str, Any]]]:
    categories = as_list(rules.get("forbidden_memory_categories"))
    missing = sorted(REQUIRED_FORBIDDEN_CATEGORIES - set(categories))
    findings: list[dict[str, Any]] = []
    if missing:
        findings.append(
            finding(
                "forbidden_memory_categories",
                severity,
                "missing",
                f"Forbidden memory categories are incomplete: {', '.join(missing)}.",
                ["Add missing forbidden categories so memory cannot silently store sensitive or governance-authoritative data."],
            )
        )
    return categories, findings


def observed_mcp_for_platform(platform_id: str, mcp_access: dict[str, Any]) -> bool:
    return platform_id in set(as_list(mcp_access.get("observed_clients")))


def evaluate_platforms(
    matrix: dict[str, Any],
    mcp_access: dict[str, Any],
    severity: str,
    *,
    memory_active: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_platforms = matrix.get("platforms") if isinstance(matrix.get("platforms"), list) else []
    findings: list[dict[str, Any]] = []
    platform_rows: list[dict[str, Any]] = []
    for item in raw_platforms:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        platform_id = str(row.get("id") or "unknown_platform")
        declared = bool(row.get("memory_access_declared"))
        mcp_configured = bool(row.get("mcp_configured")) or observed_mcp_for_platform(platform_id, mcp_access)
        row["observed_project_mcp_configured"] = mcp_configured
        read_access = str(row.get("read_access") or "none")
        write_access = str(row.get("write_access") or "none")
        admin_access = str(row.get("admin_access") or "none")
        if read_access not in ACCESS_LEVELS or write_access not in ACCESS_LEVELS or admin_access not in ACCESS_LEVELS:
            findings.append(
                finding(
                    f"{platform_id}_access_level",
                    severity,
                    "unknown",
                    "Platform declares an unsupported memory access level.",
                    ["Use one of none, read_only, draft_write, approved_write, or admin_config."],
                    platform_id=platform_id,
                )
            )
        if memory_active and declared and bool(row.get("mcp_required")) and not mcp_configured:
            findings.append(
                finding(
                    f"{platform_id}_mcp_access",
                    severity,
                    "review_required",
                    f"{row.get('name', platform_id)} declares memory use but project MCP access is not configured or confirmed.",
                    ["Run naos memory check and update the authorization matrix or platform guidance with the confirmed MCP namespace."],
                    platform_id=platform_id,
                )
            )
        if (access_is_write(write_access) or access_is_write(admin_access)) and not bool(row.get("human_review_required_for_write")):
            findings.append(
                finding(
                    f"{platform_id}_write_review_boundary",
                    severity,
                    "review_required",
                    f"{row.get('name', platform_id)} has write/admin memory access without a human-review boundary.",
                    ["Require human review before durable memory write or admin configuration."],
                    platform_id=platform_id,
                )
            )
        if platform_id == "ci" and (declared or mcp_configured or read_access != "none" or write_access != "none" or admin_access != "none"):
            findings.append(
                finding(
                    "ci_memory_access",
                    "blocking",
                    "blocked",
                    "CI must not have memory access by default.",
                    ["Set CI read/write/admin access to none and remove MCP memory configuration from default CI."],
                    platform_id=platform_id,
                )
            )
        platform_rows.append(row)
    if not platform_rows:
        findings.append(
            finding(
                "platform_access_matrix",
                severity,
                "missing",
                "Memory authorization matrix does not declare platform/tool access.",
                ["Declare platform access posture for IDEs, CLI agents, ChatGPT/OpenAI workflows, Codex, and CI."],
            )
        )
    return platform_rows, findings


def evaluate_surfaces(matrix: dict[str, Any], severity: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_surfaces = matrix.get("surfaces") if isinstance(matrix.get("surfaces"), list) else []
    findings: list[dict[str, Any]] = []
    counts = {"none": 0, "read_only": 0, "draft_write": 0, "approved_write": 0, "admin_config": 0, "unknown": 0}
    write_without_review: list[str] = []
    rows: list[dict[str, Any]] = []
    for item in raw_surfaces:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        surface_id = str(row.get("id") or "unknown_surface")
        default_access = str(row.get("default_access") or "unknown")
        write_access = str(row.get("write_access") or "none")
        counts[default_access if default_access in counts else "unknown"] += 1
        if default_access not in ACCESS_LEVELS or write_access not in ACCESS_LEVELS:
            findings.append(
                finding(
                    f"{surface_id}_access_level",
                    severity,
                    "unknown",
                    "Surface declares an unsupported memory access level.",
                    ["Use one of none, read_only, draft_write, approved_write, or admin_config."],
                    surface_id=surface_id,
                )
            )
        if access_is_write(write_access) and not bool(row.get("human_review_required_for_write")):
            write_without_review.append(surface_id)
        rows.append(row)
    if write_without_review:
        findings.append(
            finding(
                "surface_write_review_boundary",
                severity,
                "review_required",
                f"Memory write access is configured without human review for: {', '.join(write_without_review)}.",
                ["Require human review for durable memory writes."],
            )
        )
    return {
        "status": "ready" if rows and not write_without_review else "review_required",
        "access_level_counts": counts,
        "surfaces": rows,
    }, findings


def evaluate_provider_posture(rules: dict[str, Any], memory_config: dict[str, Any], severity: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    posture = dict(rules.get("provider_posture") or {})
    findings: list[dict[str, Any]] = []
    memory_state = str(memory_config.get("state") or "unknown") if memory_config else "not_configured"
    enabled = memory_config.get("enabled") is True if memory_config else False
    provider = str(memory_config.get("provider") or posture.get("recommended_provider") or "engram")
    posture.update(
        {
            "configured_provider": provider,
            "memory_config_state": memory_state,
            "memory_config_enabled": enabled,
            "memory_config_path": memory_config.get("_path"),
        }
    )
    if posture.get("cloud_memory_allowed"):
        findings.append(
            finding(
                "cloud_memory_allowed",
                severity,
                "review_required",
                "Cloud memory is allowed in rules; default NAOS posture should be local-first and cloud-disabled.",
                ["Set cloud_memory_allowed to false unless explicit project governance approves cloud memory."],
            )
        )
    if posture.get("automatic_memory_writes_allowed"):
        findings.append(
            finding(
                "automatic_memory_writes",
                severity,
                "review_required",
                "Rules allow automatic memory writes.",
                ["Disable automatic memory writes and require authorization plus human review."],
            )
        )
    if posture.get("automatic_installation_allowed"):
        findings.append(
            finding(
                "automatic_memory_installation",
                severity,
                "review_required",
                "Rules allow automatic memory provider installation.",
                ["Keep provider installation human-initiated and explicit."],
            )
        )
    if memory_state == "configured" and not memory_config.get("mcp_namespace"):
        findings.append(
            finding(
                "configured_memory_missing_namespace",
                severity,
                "review_required",
                "Memory is marked configured but no MCP namespace is declared.",
                ["Run naos memory check and record the MCP namespace or use degraded recovery."],
            )
        )
    return posture, findings


def build_context_pack_readiness(rules: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    config = rules.get("context_pack_readiness") if isinstance(rules.get("context_pack_readiness"), dict) else {}
    findings: list[dict[str, Any]] = []
    if not config:
        findings.append(
            finding(
                "context_pack_readiness",
                "advisory",
                "not_configured",
                "Context-pack readiness policy is not configured.",
                ["Declare how future context packs should bound sources, memory references, known gaps, residual risks, and non-claims."],
            )
        )
        return {"status": "not_configured", "include_sources": [], "automatic_generation_enabled": False}, findings
    include_sources = as_list(config.get("include_sources"))
    readiness_only = bool(config.get("readiness_only", True))
    automatic = bool(config.get("automatic_generation_enabled", False))
    status = "advisory" if readiness_only else "ready"
    if automatic:
        findings.append(
            finding(
                "automatic_context_pack_generation",
                "warning",
                "review_required",
                "Automatic context-pack generation is enabled; Group 22 expects readiness-only posture.",
                ["Disable automatic context-pack generation unless a later capability implements and tests it."],
            )
        )
    return {
        "status": status,
        "readiness_only": readiness_only,
        "automatic_generation_enabled": automatic,
        "include_sources": include_sources,
        "memory_inclusion_policy": config.get("memory_inclusion_policy") or {},
        "limitations": config.get("limitations") or [],
    }, findings


def summarize_status(
    *,
    rules_enabled: bool,
    memory_state: str,
    summary: dict[str, int],
) -> str:
    if not rules_enabled:
        return "disabled"
    if summary.get("blocking", 0):
        return "blocked"
    if summary.get("required", 0) or summary.get("warnings", 0):
        return "review_required"
    if memory_state in PENDING_MEMORY_STATES:
        return "review_required"
    if summary.get("advisory", 0):
        if memory_state == "disabled":
            return "disabled"
        if memory_state in INACTIVE_MEMORY_STATES:
            return "not_configured"
        return "advisory"
    if memory_state == "disabled":
        return "disabled"
    if memory_state in INACTIVE_MEMORY_STATES:
        return "not_configured"
    return "ready"


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    matrix: dict[str, Any],
    matrix_path: Path,
    matrix_source: str,
    generated_at: str,
) -> dict[str, Any]:
    severity = rule_severity(root, naos_root, profile, policy, rules)
    memory_config = load_memory_config(root)
    mcp_access = inspect_project_mcp_configs(root)
    project_identity = resolve_engram_project(memory_config, mcp_access.get("project_config_files") or [])
    mcp_access["project_identity"] = project_identity
    rules_enabled = bool(rules.get("enabled", True))
    findings: list[dict[str, Any]] = []

    provider_posture, provider_findings = evaluate_provider_posture(rules, memory_config, severity)
    memory_state = str(provider_posture.get("memory_config_state") or "not_configured")
    memory_active = bool(provider_posture.get("memory_config_enabled")) and memory_state == "configured"
    memory_config_findings = evaluate_memory_config_invariants(memory_config, severity)
    findings.extend(memory_config_findings)
    findings.extend(provider_findings)
    if project_identity.get("status") == "conflict":
        findings.append(
            finding(
                "memory_project_identity_conflict",
                severity,
                "conflict",
                "Engram project identity declarations conflict across repository config or workspace clients.",
                ["Make all fixed project declarations agree, or use the approved per-workspace resolver and verify the result with mem_current_project; never choose a project implicitly."],
            )
        )
    elif project_identity.get("status") == "unresolved_equivalence":
        findings.append(
            finding(
                "memory_project_identity_equivalence_unresolved",
                severity,
                "review_required",
                "Engram project declarations use different identifiers, but this config-only report has no registry evidence proving whether they are aliases or different projects.",
                ["Use the approved project registry/resolver and verify mem_current_project; classify a conflict only when equivalence evidence resolves the identifiers to different canonical projects."],
            )
        )
    elif memory_active and project_identity.get("status") in {"missing", "global_only"}:
        findings.append(
            finding(
                "configured_memory_missing_project_identity",
                severity,
                "review_required",
                "Memory is configured, but no per-workspace Engram project identity is declared.",
                ["Use the approved per-workspace resolver and verify it with mem_current_project, or add agreeing per-workspace declarations; do not use a user-global fixed project."],
            )
        )
    elif memory_active and project_identity.get("status") == "declared_candidate":
        findings.append(
            finding(
                "memory_project_identity_candidate_unreconciled",
                severity,
                "review_required",
                "A per-workspace Engram project identity candidate is declared but not provider-verified.",
                ["Verify the candidate through the approved per-workspace resolver and mem_current_project; if fixed client declarations are present, require them to agree."],
            )
        )
    if memory_active:
        findings.append(
            finding(
                "configured_memory_access_unverified",
                severity,
                "review_required",
                "Memory configuration and MCP declarations do not verify usable or authorized memory access.",
                ["Run the approved provider/access verification path before claiming memory was checked or usable."],
            )
        )
    hierarchy, hierarchy_findings = evaluate_hierarchy(rules, severity)
    findings.extend(hierarchy_findings)
    forbidden_categories, category_findings = evaluate_forbidden_categories(rules, severity)
    findings.extend(category_findings)
    platform_matrix, platform_findings = evaluate_platforms(matrix, mcp_access, severity, memory_active=memory_active)
    findings.extend(platform_findings)
    authorization, auth_findings = evaluate_surfaces(matrix, severity)
    findings.extend(auth_findings)
    context_pack, context_findings = build_context_pack_readiness(rules)
    findings.extend(context_findings)

    fallback = rules.get("fallback_recovery") if isinstance(rules.get("fallback_recovery"), dict) else {}
    if not fallback or not fallback.get("degraded_recovery_allowed"):
        findings.append(
            finding(
                "fallback_recovery",
                severity,
                "missing",
                "Fallback/degraded recovery behavior is missing or disabled.",
                ["Declare degraded recovery from task cards, compact summaries, git state, repo governance files, and deterministic reports."],
            )
        )

    conflict_policy = rules.get("conflict_policy") if isinstance(rules.get("conflict_policy"), dict) else {}
    if not conflict_policy.get("repo_evidence_overrides_memory"):
        findings.append(
            finding(
                "conflict_policy",
                severity,
                "conflict",
                "Conflict policy does not clearly state that repo evidence overrides memory.",
                ["Set repo_evidence_overrides_memory to true and require human review for durable conflict resolution."],
            )
        )

    for declared in rules.get("declared_memory_findings") or []:
        if not isinstance(declared, dict):
            continue
        findings.append(
            finding(
                str(declared.get("id") or "declared_memory_finding"),
                str(declared.get("severity") or severity),
                str(declared.get("status") or "advisory"),
                str(declared.get("message") or "Declared memory/context finding."),
                as_list(declared.get("required_next_actions")),
            )
        )

    if memory_state in INACTIVE_MEMORY_STATES:
        memory_status = "not_configured"
    elif memory_state in PENDING_MEMORY_STATES:
        memory_status = "review_required"
    elif memory_state == "disabled":
        memory_status = "disabled"
    elif memory_state == "configured":
        memory_status = "review_required"
    else:
        memory_status = "advisory"

    summary = finding_counts(findings)
    summary.update(
        {
            "platforms": len(platform_matrix),
            "platforms_with_declared_memory": sum(1 for row in platform_matrix if row.get("memory_access_declared")),
            "platforms_with_observed_mcp": sum(1 for row in platform_matrix if row.get("observed_project_mcp_configured")),
            "project_identity_status": project_identity.get("status"),
            "project_identity_verified": bool(project_identity.get("project_identity_verified")),
            "surfaces": len(authorization.get("surfaces") or []),
            "forbidden_categories": len(forbidden_categories),
            "human_review_required": sum(1 for item in findings if item.get("status") in {"review_required", "conflict", "blocked"}),
        }
    )
    status = summarize_status(rules_enabled=rules_enabled, memory_state=memory_state, summary=summary)
    if memory_config_findings and status == "ready":
        status = "review_required"

    known_gaps = rules.get("known_gaps") if isinstance(rules.get("known_gaps"), list) else []
    residual_risks = rules.get("residual_risks") if isinstance(rules.get("residual_risks"), list) else []
    waivers = rules.get("waivers") if isinstance(rules.get("waivers"), list) else []

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "rules": {"path": str(rules_path), "source": rules_source},
        "authorization_matrix": {"path": str(matrix_path), "source": matrix_source},
        "memory_readiness": {
            "status": memory_status,
            "memory_config_state": memory_state,
            "memory_config_enabled": bool(provider_posture.get("memory_config_enabled")),
            "memory_config_path": provider_posture.get("memory_config_path"),
            "advisory_rule": "No memory access means degraded recovery, not automatic failure unless project policy requires it.",
        },
        "provider_posture": provider_posture,
        "mcp_tool_access": mcp_access,
        "project_identity": project_identity,
        "platform_access_matrix": platform_matrix,
        "memory_authorization": authorization,
        "source_of_truth_hierarchy": hierarchy,
        "forbidden_memory_categories": forbidden_categories,
        "allowed_memory_categories": as_list(rules.get("allowed_memory_categories")),
        "memory_scopes": rules.get("memory_scopes") if isinstance(rules.get("memory_scopes"), list) else [],
        "staleness_policy": rules.get("staleness_policy") if isinstance(rules.get("staleness_policy"), dict) else {},
        "conflict_policy": conflict_policy,
        "context_continuity": {
            "status": "ready" if fallback and context_pack.get("status") != "not_configured" else "advisory",
            "memory_role": "advisory recall, continuity aid, draft checkpoint, risk signal, and context candidate",
            "memory_must_not_be": [
                "evidence",
                "approval",
                "compliance proof",
                "architecture authority",
                "security exception",
                "legal or regulatory decision",
                "source of truth",
            ],
        },
        "context_pack_readiness": context_pack,
        "fallback_readiness": {
            "status": "ready" if fallback.get("degraded_recovery_allowed") else "missing",
            "fallback_recovery": fallback,
        },
        "findings": findings,
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "waivers": waivers,
        "limitations": dedupe(as_list(rules.get("limitations")) + as_list(matrix.get("limitations"))),
        "not_claimed": dedupe(as_list(rules.get("not_claimed")) + NOT_CLAIMED),
        "human_review_required": bool(
            summary.get("human_review_required")
            or profile in {"standard", "assured"}
            and any(row.get("write_access") in WRITE_LEVELS for row in platform_matrix)
        ),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate AI context-continuity and memory-governance readiness.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured. Default: NAOS_PROFILE or policy default.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file used for path/profile conventions.")
    parser.add_argument("--rules", help="Explicit memory_context_rules.yaml path.")
    parser.add_argument("--authorization-matrix", help="Explicit memory_authorization_matrix.yaml path.")
    parser.add_argument("--generated-at", help="Optional deterministic timestamp for tests.")
    parser.add_argument("--output", help="Optional JSON output path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit policy.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = Path.cwd()
        policy = load_policy(args.policy, args.naos_root, root)
        naos_root = args.naos_root or default_naos_root(policy)
        profile = normalize_profile(args.profile, policy)
        rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
        matrix_path, matrix_source = resolve_matrix_path(root, naos_root, policy, args.authorization_matrix)
        rules = load_yaml(rules_path)
        matrix = load_yaml(matrix_path)
        report = build_report(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            rules_path=rules_path,
            rules_source=rules_source,
            matrix=matrix,
            matrix_path=matrix_path,
            matrix_source=matrix_source,
            generated_at=parse_generated_at(args.generated_at),
        )
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "memory_context_readiness_report")
    write_report(output, report)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(f"NAOS memory readiness ({profile}): {report['status']}")
        print(
            "summary: "
            f"blocking={summary.get('blocking', 0)} "
            f"required={summary.get('required', 0)} "
            f"warnings={summary.get('warnings', 0)} "
            f"advisory={summary.get('advisory', 0)}"
        )
        print(f"report: {output or 'not written in kit repository unless --output is supplied'}")

    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
