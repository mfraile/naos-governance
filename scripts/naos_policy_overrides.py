#!/usr/bin/env python3
"""Merge static NAOS policy YAML overlays while preserving protected boundaries."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
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
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    resolve_operator_attribution,
    severity_for_profile,
    validate_operator_value,
    write_report,
)
from naos_audit_log import write_audit_event  # noqa: E402


REPORT_SCHEMA = "naos.policy_override_merge.v1"
OVERRIDE_SCHEMA = "naos.policy_override.v1"
MERGE_STRATEGY_ID = "naos_static_v1"

NOT_CLAIMED = [
    "static overlays do not execute plugins or arbitrary code",
    "team/operator overlays are static configuration overlays, not access control",
    "team/operator mapping is not identity proof, authentication, authorization, or separation-of-duties satisfaction",
    "policy overrides cannot weaken ADR-0010: Control-Plane Advisory Boundaries",
    "policy overrides cannot make advisory findings authoritative",
    "policy overrides cannot enable memory write-back, MCP, Engram, semantic/vector, graph, LLMGrader, cloud, provider, or signing runtime",
    "generated effective policy is derived and reviewable; it is not an independent source of authority",
]

LIMITATIONS = [
    "Only YAML overlays under the configured adopter-local override directory and selected team/operator subdirectories are considered.",
    "Team/operator scope is resolved from local static configuration or explicit CLI flags; no identity provider is queried.",
    "Unknown or protected override paths are reported as findings and are not applied.",
    "The v1 hook does not discover or execute Python plugins, shell commands, provider integrations, or cloud services.",
    "The merge report is a review aid; durable policy decisions remain human-owned.",
]

OVERLAY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TEAM_OPERATOR_MAP_SCHEMA = "naos.team_operator_map.v1"
ALLOWED_SCALAR_PATHS = {
    "version",
    "description",
    "profiles.default",
    "claims.external_evidence_verification_default",
    "claims.safe_context_window_chars",
    "evidence.default_staleness_days",
    "evidence.external_reference_default_status",
    "test_evidence.coverage_supports_source_default",
}

ALLOWED_MAPPING_PREFIXES = {
    "profiles.severity_by_profile",
    "profiles.exit_code",
    "claims.overclaim_patterns",
    "customization.metadata",
    "customization.dashboard_visibility",
    "customization.local_workflow",
    "customization.setup_recommendations",
}

ALLOWED_LIST_PATHS = {
    "profiles.supported",
    "claims.status_values",
    "claims.revalidation_triggers",
    "claims.safe_context_phrases",
    "claims.disclaimers",
    "paths.ignored_scan_dirs",
    "test_evidence.accepted_types",
}

ALLOWED_PATH_SCALARS = {
    "paths.reports_dir",
    "paths.dashboard_markdown",
    "paths.dashboard_summary_report",
    "paths.evidence_dir",
    "paths.evidence_pack_report",
    "paths.policy_override_merge_report",
    "paths.effective_policy",
    "paths.setup_recommendations_report",
    "paths.self_check_report",
    "paths.gate_status_report",
    "paths.gate_evaluation_report",
    "paths.sarif_report",
    "paths.sarif_export_summary_report",
}

PROTECTED_PATHS = {
    "memory_context_rules.memory_payload_reads_allowed",
    "memory_provider_access_rules.live_provider_calls_allowed",
    "memory_provider_access_rules.live_mcp_calls_allowed",
    "memory_provider_access_rules.memory_payload_reads_allowed",
    "memory_provider_access_rules.memory_writes_allowed",
    "memory_provider_access_rules.cloud_memory_allowed",
    "memory_provider_access_rules.external_sync_allowed",
    "memory_use_policy_rules.memory_write_back_policy.enabled",
    "session_lifecycle_rules.no_automatic_injection_policy.enabled",
    "semantic_candidate_layer_rules.semantic_runtime_enabled",
    "semantic_candidate_layer_rules.sqlite_vec_enabled",
    "semantic_candidate_layer_rules.embeddings_enabled",
    "graph_context_rules.graph_runtime_enabled",
    "graph_context_rules.networkx_enabled",
    "graph_context_rules.graphml_enabled",
    "graph_context_rules.graph_algorithms_enabled",
    "graph_context_rules.graph_database_allowed",
    "advisory_controls.can_promote_without_human",
    "advisory_controls.can_replace_deterministic_controls",
    "source_authority.memory_source_of_truth",
    "source_authority.context_pack_source_of_truth",
    "source_authority.graph_source_of_truth",
    "source_authority.semantic_source_of_truth",
    "runtime.plugin_execution_enabled",
    "runtime.python_plugin_execution_enabled",
    "runtime.arbitrary_code_execution_enabled",
    "runtime.mcp_runtime_enabled",
    "runtime.engram_runtime_enabled",
    "runtime.sqlite_vec_runtime_enabled",
    "runtime.networkx_runtime_enabled",
    "runtime.llmgrader_runtime_enabled",
    "runtime.cloud_memory_enabled",
    "runtime.automatic_context_injection_enabled",
    "runtime.automatic_memory_write_back_enabled",
    "runtime.naos_signing_enabled",
}

RISKY_KEY_TERMS = (
    "api_key",
    "apikey",
    "token",
    "password",
    "credential",
    "secret",
    "private_key",
    "provider_key",
    "cloud_endpoint",
    "shell_command",
    "python_plugin",
    "plugin_runtime",
)

RISKY_TRUE_TERMS = (
    "source_of_truth",
    "authoritative",
    "approval",
    "certification",
    "compliance_proof",
    "promote_without_human",
    "replace_deterministic",
    "automatic_memory_write_back",
    "memory_write_back",
    "memory_payload_reads",
    "cloud_memory",
    "external_sync",
    "mcp_runtime",
    "engram_runtime",
    "sqlite_vec_runtime",
    "networkx_runtime",
    "graph_runtime",
    "llmgrader_runtime",
    "python_plugin_execution",
    "arbitrary_code_execution",
    "automatic_context_injection",
    "naos_signing",
)

RISKY_TEXT_TERMS = (
    "advisory controls replace",
    "advisory promotes",
    "memory source of truth",
    "memory as approval",
    "memory as evidence",
    "automatic memory write-back",
    "mcp runtime enabled",
    "engram runtime enabled",
    "sqlite-vec runtime enabled",
    "networkx runtime enabled",
    "llmgrader runtime enabled",
    "cloud memory enabled",
    "api key",
    "provider credentials",
)


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


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_overlay_id(value: str | None, field_name: str) -> tuple[str | None, str | None]:
    cleaned = "" if value is None else str(value).strip()
    if not cleaned:
        return None, "missing"
    if len(cleaned) > 128:
        return None, "too_long"
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        return None, "path_like_or_traversal"
    if any(ord(ch) < 32 for ch in cleaned):
        return None, "control_character"
    if not OVERLAY_ID_PATTERN.fullmatch(cleaned):
        return None, f"invalid_{field_name}_pattern"
    return cleaned, None


def team_operator_map_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    configured = str(policy.get("paths", {}).get("team_operator_map") or "team_operator_map.yaml")
    return root / naos_root / configured


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    cleaned = str(value).strip()
    return [cleaned] if cleaned else []


def load_team_operator_map(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    validation_results: list[dict[str, Any]] = []
    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "valid": False,
            "hash": None,
            "schema": TEAM_OPERATOR_MAP_SCHEMA,
            "teams": [],
            "operators": [],
            "limitations": [
                "Team/operator mapping is optional; missing mapping means only global overlays are applied unless CLI scope flags are provided.",
            ],
            "not_claimed": ["identity proof", "authorization", "access control", "separation-of-duties satisfaction"],
            "human_review_required": True,
        }, findings, validation_results
    try:
        data = load_yaml_mapping(path)
    except Exception as exc:
        findings.append(
            finding(
                "TEAM_OPERATOR_MAP_INVALID",
                "warning",
                "invalid_team_operator_map",
                f"Team/operator map could not be parsed: {exc}",
                path=str(path),
                actions=["Fix naos/team_operator_map.yaml before relying on team/operator scoped overlays."],
            )
        )
        validation_results.append({"path": str(path), "valid": False, "errors": [str(exc)]})
        return {
            "path": str(path),
            "exists": True,
            "valid": False,
            "hash": safe_digest(path),
            "schema": TEAM_OPERATOR_MAP_SCHEMA,
            "teams": [],
            "operators": [],
            "limitations": ["Invalid team/operator map was ignored."],
            "not_claimed": ["identity proof", "authorization", "access control", "separation-of-duties satisfaction"],
            "human_review_required": True,
        }, findings, validation_results

    errors: list[str] = []
    if data.get("schema") != TEAM_OPERATOR_MAP_SCHEMA:
        errors.append(f"schema must be {TEAM_OPERATOR_MAP_SCHEMA}")
    if not isinstance(data.get("teams", []), list):
        errors.append("teams must be a list")
    if not isinstance(data.get("operators", []), list):
        errors.append("operators must be a list")

    teams: list[dict[str, Any]] = []
    operators: list[dict[str, Any]] = []
    for index, item in enumerate(data.get("teams") or []):
        if not isinstance(item, dict):
            errors.append(f"teams[{index}] must be a mapping")
            continue
        team_id, reason = validate_overlay_id(item.get("team_id"), "team_id")
        if reason:
            errors.append(f"teams[{index}].team_id invalid: {reason}")
            continue
        operator_overlay_ids: list[str] = []
        for raw_overlay_id in normalize_string_list(item.get("operator_overlay_ids")):
            overlay_id, reason = validate_overlay_id(raw_overlay_id, "operator_overlay_id")
            if reason:
                errors.append(f"teams[{index}].operator_overlay_ids entry invalid: {reason}")
            elif overlay_id:
                operator_overlay_ids.append(overlay_id)
        teams.append(
            {
                "team_id": team_id,
                "description": item.get("description"),
                "operator_overlay_ids": operator_overlay_ids,
            }
        )
    for index, item in enumerate(data.get("operators") or []):
        if not isinstance(item, dict):
            errors.append(f"operators[{index}] must be a mapping")
            continue
        operator_id, invalid, detected = validate_operator_value(item.get("operator_id"), f"team_operator_map.operators[{index}].operator_id")
        if invalid or not detected or not operator_id:
            reason = (invalid or {}).get("reason", "missing")
            errors.append(f"operators[{index}].operator_id invalid: {reason}")
            continue
        team_ids: list[str] = []
        for raw_team_id in normalize_string_list(item.get("team_ids") or item.get("team_id")):
            team_id, reason = validate_overlay_id(raw_team_id, "team_id")
            if reason:
                errors.append(f"operators[{index}].team_ids entry invalid: {reason}")
            elif team_id:
                team_ids.append(team_id)
        operator_overlay_id = None
        if item.get("operator_overlay_id") is not None:
            operator_overlay_id, reason = validate_overlay_id(item.get("operator_overlay_id"), "operator_overlay_id")
            if reason:
                errors.append(f"operators[{index}].operator_overlay_id invalid: {reason}")
                operator_overlay_id = None
        operators.append(
            {
                "operator_id": operator_id,
                "team_ids": team_ids,
                "operator_overlay_id": operator_overlay_id,
            }
        )

    valid = not errors
    validation_results.append({"path": str(path), "valid": valid, "errors": errors})
    if errors:
        findings.append(
            finding(
                "TEAM_OPERATOR_MAP_INVALID",
                "warning",
                "invalid_team_operator_map",
                f"Team/operator map validation failed: {', '.join(errors)}",
                path=str(path),
                actions=["Fix naos/team_operator_map.yaml before relying on team/operator scoped overlays."],
            )
        )
    return {
        "path": str(path),
        "exists": True,
        "valid": valid,
        "hash": safe_digest(path),
        "schema": data.get("schema"),
        "teams": teams if valid else [],
        "operators": operators if valid else [],
        "limitations": data.get("limitations") or [],
        "not_claimed": data.get("not_claimed") or [],
        "human_review_required": bool(data.get("human_review_required", True)),
    }, findings, validation_results


def resolve_overlay_scope(
    *,
    root: Path,
    explicit_operator_id: str | None,
    explicit_team_id: str | None,
    explicit_operator_overlay_id: str | None,
    team_operator_map: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    operator = resolve_operator_attribution(root)
    operator_id = operator.get("operator_id")
    operator_source = operator.get("operator_source", "unknown")
    operator_attribution_status = operator.get("operator_attribution_status", "unknown")

    if explicit_operator_id:
        operator_id, invalid, detected = validate_operator_value(explicit_operator_id, "cli_operator_id")
        operator_source = "cli"
        operator_attribution_status = "resolved" if operator_id else "invalid"
        if invalid or not detected or not operator_id:
            findings.append(
                finding(
                    "POLICY_OVERRIDE_OPERATOR_ID_INVALID",
                    "warning",
                    "invalid_operator_id",
                    "Explicit operator id was invalid and was not used for scoped overlays.",
                    actions=["Use a log-safe operator id such as team-alpha, operator.123, or marlon@example.com."],
                )
            )
            operator_id = None

    team_ids: list[str] = []
    team_id_source = "none"
    if explicit_team_id:
        team_id, reason = validate_overlay_id(explicit_team_id, "team_id")
        if reason:
            findings.append(
                finding(
                    "POLICY_OVERRIDE_TEAM_ID_INVALID",
                    "warning",
                    "invalid_team_id",
                    f"Explicit team id was invalid and ignored: {reason}.",
                    actions=["Use a filesystem-safe team overlay id such as platform-team."],
                )
            )
        elif team_id:
            team_ids.append(team_id)
            team_id_source = "cli"

    operator_overlay_id = None
    operator_overlay_source = "none"
    if explicit_operator_overlay_id:
        overlay_id, reason = validate_overlay_id(explicit_operator_overlay_id, "operator_overlay_id")
        if reason:
            findings.append(
                finding(
                    "POLICY_OVERRIDE_OPERATOR_OVERLAY_ID_INVALID",
                    "warning",
                    "invalid_operator_overlay_id",
                    f"Explicit operator overlay id was invalid and ignored: {reason}.",
                    actions=["Use a filesystem-safe operator overlay id that does not expose private identifiers."],
                )
            )
        elif overlay_id:
            operator_overlay_id = overlay_id
            operator_overlay_source = "cli"

    if team_operator_map.get("valid") and operator_id:
        for entry in team_operator_map.get("operators") or []:
            if entry.get("operator_id") == operator_id:
                if not team_ids:
                    team_ids = list(dict.fromkeys(normalize_string_list(entry.get("team_ids"))))
                    team_id_source = "team_operator_map" if team_ids else team_id_source
                if not operator_overlay_id and entry.get("operator_overlay_id"):
                    operator_overlay_id = str(entry.get("operator_overlay_id"))
                    operator_overlay_source = "team_operator_map"
                break

    if explicit_team_id and team_ids and team_operator_map.get("valid") and operator_id:
        mapped_team_ids: list[str] = []
        for entry in team_operator_map.get("operators") or []:
            if entry.get("operator_id") == operator_id:
                mapped_team_ids = normalize_string_list(entry.get("team_ids"))
                break
        if mapped_team_ids and not set(team_ids).intersection(mapped_team_ids):
            findings.append(
                finding(
                    "POLICY_OVERRIDE_TEAM_SCOPE_UNMAPPED",
                    "warning",
                    "team_scope_unmapped",
                    "Explicit team scope is not mapped to the resolved operator; scope is applied as configuration only, not authorization.",
                    actions=["Review naos/team_operator_map.yaml and confirm the intended team scope."],
                )
            )

    overlay_scope = {
        "operator_id": operator_id,
        "operator_source": operator_source,
        "operator_attribution_status": operator_attribution_status,
        "team_ids": team_ids,
        "team_id_source": team_id_source,
        "operator_overlay_id": operator_overlay_id,
        "operator_overlay_source": operator_overlay_source,
        "scope_order": ["global", "team", "operator"],
        "scope_note": "Team/operator overlays are static configuration scopes, not authentication, authorization, access control, or separation-of-duties evidence.",
    }
    return overlay_scope, findings


def dotted(parent: str, key: str) -> str:
    return f"{parent}.{key}" if parent else key


def iter_leaf_paths(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        leaves: list[tuple[str, Any]] = []
        for key in sorted(value):
            leaves.extend(iter_leaf_paths(value[key], dotted(prefix, str(key))))
        return leaves
    return [(prefix, value)]


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def finding(
    identifier: str,
    severity: str,
    status: str,
    message: str,
    *,
    path: str | None = None,
    override_file: str | None = None,
    actions: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "path": path,
        "override_file": override_file,
        "required_next_actions": actions or [],
    }
    result.update({key: value for key, value in extra.items() if value is not None})
    return result


def severity_for_override(profile: str, policy: dict[str, Any], protected: bool = False) -> str:
    if protected and profile == "assured":
        return "blocking"
    if protected and profile == "standard":
        return "required"
    if protected and profile == "lite":
        return "warning"
    return severity_for_profile(profile, policy)


def is_allowed_path(path: str, value: Any) -> tuple[bool, str]:
    if path in ALLOWED_SCALAR_PATHS or path in ALLOWED_PATH_SCALARS:
        return not isinstance(value, (dict, list)), "scalar_replace"
    if path in ALLOWED_LIST_PATHS:
        return isinstance(value, list), "list_replace"
    if any(path == prefix or path.startswith(f"{prefix}.") for prefix in ALLOWED_MAPPING_PREFIXES):
        return True, "mapping_deep_merge"
    return False, "not_allowed"


def protected_reason(path: str, value: Any) -> str | None:
    if path in PROTECTED_PATHS or any(path.startswith(f"{prefix}.") for prefix in PROTECTED_PATHS):
        return "protected policy path"

    normalized_path = path.lower().replace("-", "_")
    if any(term in normalized_path for term in RISKY_KEY_TERMS):
        return "credential, plugin, provider, command, or secret-like key"

    if isinstance(value, bool) and value and any(term in normalized_path for term in RISKY_TRUE_TERMS):
        return "protected runtime/source-authority flag set true"

    if isinstance(value, str):
        text = value.lower()
        if any(term in text for term in RISKY_TEXT_TERMS):
            return "protected authority/runtime wording"

    return None


def validate_override_schema(data: dict[str, Any], path: Path) -> list[str]:
    errors: list[str] = []
    if "version" not in data:
        errors.append("missing version")
    if "overrides" not in data:
        errors.append("missing overrides")
    elif not isinstance(data.get("overrides"), dict):
        errors.append("overrides must be a mapping")
    strategy = data.get("merge_strategy")
    if strategy is not None and strategy != MERGE_STRATEGY_ID:
        errors.append(f"unsupported merge_strategy: {strategy}")
    scope = data.get("scope")
    if scope is not None and not isinstance(scope, dict):
        errors.append("scope must be a mapping when provided")
    elif isinstance(scope, dict):
        for key in scope:
            if key not in {"scope_type", "team_id", "operator_overlay_id", "note"}:
                errors.append(f"unknown scope key: {key}")
        if scope.get("scope_type") is not None and scope.get("scope_type") not in {"global", "team", "operator"}:
            errors.append(f"unsupported scope_type: {scope.get('scope_type')}")
        if scope.get("team_id") is not None:
            _team_id, reason = validate_overlay_id(scope.get("team_id"), "team_id")
            if reason:
                errors.append(f"scope.team_id invalid: {reason}")
        if scope.get("operator_overlay_id") is not None:
            _operator_overlay_id, reason = validate_overlay_id(scope.get("operator_overlay_id"), "operator_overlay_id")
            if reason:
                errors.append(f"scope.operator_overlay_id invalid: {reason}")
    for key in data:
        if key not in {"version", "description", "metadata", "merge_strategy", "scope", "overrides"}:
            errors.append(f"unknown top-level key: {key}")
    return errors


def set_path(target: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cursor: dict[str, Any] = target
    for part in parts[:-1]:
        child = cursor.get(part)
        if not isinstance(child, dict):
            child = {}
            cursor[part] = child
        cursor = child
    cursor[parts[-1]] = copy.deepcopy(value)


def get_path(target: dict[str, Any], path: str) -> Any:
    cursor: Any = target
    for part in path.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def deep_merge_at_path(target: dict[str, Any], path: str, value: Any) -> None:
    current = get_path(target, path)
    if isinstance(current, dict) and isinstance(value, dict):
        merged = dict(current)
        for key, child in value.items():
            if isinstance(child, dict) and isinstance(merged.get(key), dict):
                merged[key] = merge_mapping(dict(merged[key]), child)
            else:
                merged[key] = copy.deepcopy(child)
        set_path(target, path, merged)
    else:
        set_path(target, path, copy.deepcopy(value))


def merge_mapping(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_mapping(dict(result[key]), value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def top_allowed_prefix(path: str) -> str:
    candidates = sorted(ALLOWED_MAPPING_PREFIXES, key=len, reverse=True)
    for prefix in candidates:
        if path == prefix or path.startswith(f"{prefix}."):
            return prefix
    return path


def apply_allowed_override(effective: dict[str, Any], path: str, value: Any, strategy: str) -> None:
    set_path(effective, path, value)


def collect_yaml_files(directory: Path, *, missing_reason: str | None = None) -> tuple[list[Path], list[dict[str, Any]], bool]:
    if not directory.exists():
        return [], ([] if missing_reason is None else [{"path": str(directory), "reason": missing_reason}]), True
    if not directory.is_dir():
        return [], [{"path": str(directory), "reason": "expected directory"}], False
    files: list[Path] = []
    ignored: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_dir():
            ignored.append({"path": str(path), "reason": "directories are not overlay files"})
            continue
        if path.suffix.lower() in {".yaml", ".yml"}:
            files.append(path)
        elif path.name != "README.md":
            ignored.append({"path": str(path), "reason": "only *.yaml overlays are read"})
    return files, ignored, False


def collect_override_files(override_dir: Path) -> tuple[list[Path], list[dict[str, Any]], bool]:
    if not override_dir.exists():
        return [], [], True
    files: list[Path] = []
    ignored: list[dict[str, Any]] = []
    for path in sorted(override_dir.iterdir(), key=lambda item: item.name):
        if path.is_dir():
            if path.name in {"teams", "operators"}:
                ignored.append({"path": str(path), "reason": "scope directory; read only when selected by team/operator map or CLI flags"})
            else:
                ignored.append({"path": str(path), "reason": "directories are ignored"})
            continue
        if path.suffix.lower() in {".yaml", ".yml"}:
            files.append(path)
        elif path.name != "README.md":
            ignored.append({"path": str(path), "reason": "only *.yaml overlays are read"})
    return files, ignored, False


def collect_selected_override_files(override_dir: Path, overlay_scope: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    global_files, ignored_files, missing_override_dir = collect_override_files(override_dir)
    scopes: list[dict[str, Any]] = [
        {
            "scope_type": "global",
            "scope_id": None,
            "directory": str(override_dir),
            "files": global_files,
            "file_count": len(global_files),
            "missing": missing_override_dir,
        }
    ]
    for team_id in overlay_scope.get("team_ids") or []:
        team_dir = override_dir / "teams" / team_id
        files, ignored, missing = collect_yaml_files(team_dir, missing_reason="selected team overlay directory is missing")
        ignored_files.extend(ignored)
        scopes.append(
            {
                "scope_type": "team",
                "scope_id": team_id,
                "directory": str(team_dir),
                "files": files,
                "file_count": len(files),
                "missing": missing,
            }
        )
    operator_overlay_id = overlay_scope.get("operator_overlay_id")
    if operator_overlay_id:
        operator_dir = override_dir / "operators" / str(operator_overlay_id)
        files, ignored, missing = collect_yaml_files(operator_dir, missing_reason="selected operator overlay directory is missing")
        ignored_files.extend(ignored)
        scopes.append(
            {
                "scope_type": "operator",
                "scope_id": operator_overlay_id,
                "directory": str(operator_dir),
                "files": files,
                "file_count": len(files),
                "missing": missing,
            }
        )
    return scopes, ignored_files, missing_override_dir


def resolution_source_alias(value: Any) -> str:
    source = str(value or "").strip()
    if source == "cli":
        return "explicit flag/env"
    if source == "team_operator_map":
        return "map"
    if source in {"none", ""}:
        return "not_configured"
    if source in {"unknown", "invalid"}:
        return "unknown"
    return source


def scoped_overlay_file_paths(records: list[dict[str, Any]], scope_type: str) -> list[str]:
    return [str(record.get("path")) for record in records if record.get("scope_type") == scope_type and record.get("path")]


def build_merge_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    override_dir: Path,
    team_operator_map_path_value: Path,
    explicit_operator_id: str | None = None,
    explicit_team_id: str | None = None,
    explicit_operator_overlay_id: str | None = None,
    write_effective_policy: bool,
    effective_policy_path: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    generated_at = utc_now_text()
    default_policy_path = policy.get("_meta", {}).get("path")
    effective = copy.deepcopy({key: value for key, value in policy.items() if key != "_meta"})
    findings: list[dict[str, Any]] = []
    schema_results: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    override_file_records: list[dict[str, Any]] = []
    overlay_scope_records: list[dict[str, Any]] = []
    applied_paths: list[str] = []
    rejected_paths: list[str] = []
    seen_paths: dict[str, str] = {}

    severity = severity_for_override(profile, policy)
    protected_severity = severity_for_override(profile, policy, protected=True)
    team_operator_map, map_findings, map_validation_results = load_team_operator_map(team_operator_map_path_value)
    findings.extend(map_findings)
    schema_results.extend(map_validation_results)
    overlay_scope, scope_findings = resolve_overlay_scope(
        root=root,
        explicit_operator_id=explicit_operator_id,
        explicit_team_id=explicit_team_id,
        explicit_operator_overlay_id=explicit_operator_overlay_id,
        team_operator_map=team_operator_map,
    )
    findings.extend(scope_findings)
    selected_scopes, ignored_files, missing_override_dir = collect_selected_override_files(override_dir, overlay_scope)
    override_files = [path for scope in selected_scopes for path in scope["files"]]

    if missing_override_dir:
        findings.append(
            finding(
                "POLICY_OVERRIDE_DIR_MISSING",
                "advisory",
                "missing_override_dir",
                "Policy override directory is missing; no adopter-local overlays were applied.",
                path=str(override_dir),
                actions=["Create naos/policy_overrides.d/ with README.md or run naos init/add setup-module to seed it."],
            )
        )

    for scope in selected_scopes:
        scope_record = {
            "scope_type": scope["scope_type"],
            "scope_id": scope["scope_id"],
            "directory": scope["directory"],
            "file_count": scope["file_count"],
            "missing": scope["missing"],
            "applied_paths": [],
            "rejected_paths": [],
        }
        overlay_scope_records.append(scope_record)
        for path in scope["files"]:
            record = {
                "path": str(path),
                "hash": safe_digest(path),
                "scope_type": scope["scope_type"],
                "scope_id": scope["scope_id"],
                "applied_paths": [],
                "rejected_paths": [],
            }
            override_file_records.append(record)
            try:
                data = load_yaml_mapping(path)
            except Exception as exc:
                message = str(exc)
                schema_results.append({"path": str(path), "valid": False, "errors": [message], "scope_type": scope["scope_type"], "scope_id": scope["scope_id"]})
                findings.append(
                    finding(
                        "POLICY_OVERRIDE_SCHEMA_INVALID",
                        protected_severity,
                        "invalid_override",
                        f"Policy override could not be parsed: {message}",
                        override_file=str(path),
                        actions=["Fix YAML syntax and ensure the file is a mapping."],
                    )
                )
                continue

            errors = validate_override_schema(data, path)
            schema_results.append({"path": str(path), "valid": not errors, "errors": errors, "scope_type": scope["scope_type"], "scope_id": scope["scope_id"]})
            if errors:
                findings.append(
                    finding(
                        "POLICY_OVERRIDE_SCHEMA_INVALID",
                        protected_severity,
                        "invalid_override",
                        f"Policy override schema validation failed: {', '.join(errors)}",
                        override_file=str(path),
                        actions=["Use version plus overrides mapping; see schemas/naos/policy_override.schema.json."],
                    )
                )
                record["rejected_paths"].append("*")
                scope_record["rejected_paths"].append("*")
                rejected_paths.append("*")
                continue

            overrides = data.get("overrides") or {}
            for leaf_path, value in iter_leaf_paths(overrides):
                if leaf_path in seen_paths:
                    conflicts.append(
                        {
                            "path": leaf_path,
                            "first_file": seen_paths[leaf_path],
                            "second_file": str(path),
                            "resolution": "later file wins by scope order then lexicographic filename if path is allowed",
                            "second_scope_type": scope["scope_type"],
                            "second_scope_id": scope["scope_id"],
                        }
                    )
                seen_paths[leaf_path] = str(path)

                reason = protected_reason(leaf_path, value)
                if reason:
                    rejected_paths.append(leaf_path)
                    record["rejected_paths"].append(leaf_path)
                    scope_record["rejected_paths"].append(leaf_path)
                    findings.append(
                        finding(
                            "POLICY_OVERRIDE_PROTECTED_INVARIANT",
                            protected_severity,
                            "protected_invariant_violation",
                            f"Override for `{leaf_path}` was rejected: {reason}.",
                            path=leaf_path,
                            override_file=str(path),
                            actions=["Remove the override or route the protected policy change through human review and a future approved capability."],
                        )
                    )
                    continue

                allowed, strategy = is_allowed_path(leaf_path, value)
                if not allowed:
                    rejected_paths.append(leaf_path)
                    record["rejected_paths"].append(leaf_path)
                    scope_record["rejected_paths"].append(leaf_path)
                    findings.append(
                        finding(
                            "POLICY_OVERRIDE_UNKNOWN_KEY",
                            severity,
                            "unknown_override_key",
                            f"Override path `{leaf_path}` is outside the v1 allowlist and was not applied.",
                            path=leaf_path,
                            override_file=str(path),
                            actions=["Use an allowed override path or propose a future schema extension."],
                        )
                    )
                    continue

                apply_allowed_override(effective, leaf_path, value, strategy)
                applied_paths.append(leaf_path)
                record["applied_paths"].append(leaf_path)
                scope_record["applied_paths"].append(leaf_path)

    if not team_operator_map.get("exists"):
        findings.append(
            finding(
                "TEAM_OPERATOR_MAP_MISSING",
                "advisory",
                "team_operator_map_missing",
                "Team/operator map is missing; only global overlays and explicitly provided CLI scopes can apply.",
                path=str(team_operator_map_path_value),
                actions=["Create naos/team_operator_map.yaml when team/operator scoped overlays are needed."],
            )
        )

    if any(scope.get("missing") for scope in overlay_scope_records if scope.get("scope_type") != "global"):
        findings.append(
            finding(
                "POLICY_OVERRIDE_SCOPE_DIR_MISSING",
                "advisory",
                "scope_directory_missing",
                "A selected team/operator overlay directory was missing; merge continued with available scopes.",
                actions=["Create the selected team/operator overlay directory or update naos/team_operator_map.yaml."],
            )
        )

    protected_invariant_violations = [
        item for item in findings if item.get("status") == "protected_invariant_violation"
    ]
    schema_invalid = any(not item.get("valid") for item in schema_results if str(item.get("path")) != str(team_operator_map_path_value))
    map_invalid = team_operator_map.get("exists") and not team_operator_map.get("valid")
    protected_invalid = bool(protected_invariant_violations)
    status_driving_findings = [
        item for item in findings
        if item.get("id") not in {"TEAM_OPERATOR_MAP_MISSING", "POLICY_OVERRIDE_DIR_MISSING"}
    ]

    if protected_invalid:
        status = "protected_invariant_violation"
    elif schema_invalid:
        status = "invalid_override"
    elif map_invalid and profile in {"standard", "assured"}:
        status = "review_required"
    elif status_driving_findings and profile in {"standard", "assured"}:
        status = "review_required"
    elif override_files:
        status = "ready"
    elif missing_override_dir:
        status = "no_overrides"
    else:
        status = "no_overrides"

    if write_effective_policy and effective_policy_path is not None and not (schema_invalid or protected_invalid):
        effective_policy_path.parent.mkdir(parents=True, exist_ok=True)
        effective_policy_path.write_text(
            "# Derived NAOS effective policy. Source is default policy plus validated static overlays.\n"
            + yaml.safe_dump(effective, sort_keys=True),
            encoding="utf-8",
        )

    counts = finding_counts(findings)
    team_ids = overlay_scope.get("team_ids") or []
    team_id = team_ids[0] if len(team_ids) == 1 else None
    global_overlay_files = scoped_overlay_file_paths(override_file_records, "global")
    team_overlay_files = scoped_overlay_file_paths(override_file_records, "team")
    operator_overlay_files = scoped_overlay_file_paths(override_file_records, "operator")
    overlay_precedence = ["default_policy", "global", "team", "operator"]
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "project_root": str(root),
        "naos_root": naos_root,
        "default_policy_path": default_policy_path,
        "override_dir": str(override_dir),
        "team_operator_map_path": str(team_operator_map_path_value),
        "team_operator_map": team_operator_map,
        "operator_id": overlay_scope.get("operator_id"),
        "operator_source": overlay_scope.get("operator_source"),
        "operator_attribution_status": overlay_scope.get("operator_attribution_status"),
        "global_overlay_files": global_overlay_files,
        "team_overlay_files": team_overlay_files,
        "operator_overlay_files": operator_overlay_files,
        "team_operator_map_present": bool(team_operator_map.get("exists")),
        "team_id": team_id,
        "team_ids": team_ids,
        "team_resolution_source": resolution_source_alias(overlay_scope.get("team_id_source")),
        "operator_overlay_id": overlay_scope.get("operator_overlay_id"),
        "operator_overlay_resolution_source": resolution_source_alias(overlay_scope.get("operator_overlay_source")),
        "overlay_precedence": overlay_precedence,
        "overlay_scope": overlay_scope,
        "overlay_scopes": overlay_scope_records,
        "applied_overlay_scopes": [
            f"{scope['scope_type']}:{scope['scope_id']}" if scope.get("scope_id") else str(scope["scope_type"])
            for scope in overlay_scope_records
            if scope.get("file_count")
        ],
        "override_files": override_file_records,
        "ignored_files": ignored_files,
        "missing_override_dir": missing_override_dir,
        "merge_strategy": {
            "id": MERGE_STRATEGY_ID,
            "file_order": "global overlays first, then selected team overlays, then selected operator overlay; lexicographic within each scope",
            "scalar": "replace for allowlisted scalar paths",
            "mapping": "deep merge for allowlisted mapping prefixes",
            "list": "replace for allowlisted list paths",
            "protected_sections": "never merged implicitly",
            "plugin_runtime": "disabled",
            "team_operator_scope": "static configuration only; not authentication, authorization, access control, or separation-of-duties approval",
        },
        "allowed_override_paths": sorted(ALLOWED_SCALAR_PATHS | ALLOWED_LIST_PATHS | ALLOWED_PATH_SCALARS | ALLOWED_MAPPING_PREFIXES),
        "protected_paths": sorted(PROTECTED_PATHS),
        "effective_policy_path": str(effective_policy_path) if write_effective_policy and effective_policy_path is not None else None,
        "override_summary": {
            "override_files": len(override_files),
            "applied_paths": len(applied_paths),
            "rejected_paths": len(rejected_paths),
            "conflicts": len(conflicts),
            "ignored_files": len(ignored_files),
            "team_overlay_count": sum(1 for scope in overlay_scope_records if scope.get("scope_type") == "team" and scope.get("file_count")),
            "operator_overlay_count": sum(1 for scope in overlay_scope_records if scope.get("scope_type") == "operator" and scope.get("file_count")),
            "selected_team_ids": overlay_scope.get("team_ids") or [],
            "selected_operator_overlay_id": overlay_scope.get("operator_overlay_id"),
            "overlay_precedence": overlay_precedence,
            "plugin_runtime_enabled": False,
            "python_plugin_execution_enabled": False,
            "arbitrary_code_execution_enabled": False,
        },
        "protected_invariant_violations": protected_invariant_violations,
        "schema_validation_results": schema_results,
        "conflicts": conflicts,
        "findings": findings,
        "known_gaps": [
            {
                "id": "POLICY_OVERRIDE_PLUGIN_RUNTIME_DEFERRED",
                "description": "Python/plugin customization is deferred pending separate security review, explicit enablement, trust model, and sandboxing posture.",
                "classification": "safe_to_defer",
            },
            {
                "id": "MULTI_TEAM_GATEKEEPER_CONFIG_DEFERRED",
                "description": "Team/operator scoped overlays do not configure gatekeeper severity per team; multi-team gatekeeper config is deferred to a later control.",
                "classification": "safe_to_defer",
            }
        ],
        "residual_risks": [
            {
                "id": "POLICY_OVERRIDE_MISCONFIGURATION_RISK",
                "description": "Allowed overlays can still create noisy or overly lenient local thresholds if reviewers do not inspect the merge report.",
                "mitigation": "Review policy_override_merge.json before relying on generated effective policy.",
            },
            {
                "id": "TEAM_OPERATOR_MAPPING_STALENESS_RISK",
                "description": "Local team/operator mappings can drift from real organizational assignments.",
                "mitigation": "Treat mapping as configuration metadata and require human review for durable governance decisions.",
            }
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(protected_invariant_violations or (profile in {"standard", "assured"} and status_driving_findings)),
        "summary": {
            **counts,
            "status": status,
            "override_files": len(override_files),
            "applied_paths": len(applied_paths),
            "rejected_paths": len(rejected_paths),
            "conflicts": len(conflicts),
            "protected_invariant_violations": len(protected_invariant_violations),
            "team_ids": overlay_scope.get("team_ids") or [],
            "operator_overlay_id": overlay_scope.get("operator_overlay_id"),
            "team_operator_map_valid": bool(team_operator_map.get("valid")),
            "schema_valid": not schema_invalid,
            "effective_policy_written": bool(write_effective_policy and effective_policy_path is not None and effective_policy_path.exists()),
        },
    }
    return report, effective


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and merge static NAOS policy YAML overlays.")
    parser.add_argument("--profile", default=None, help="NAOS profile: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=None, help="Project NAOS root directory.")
    parser.add_argument("--policy", default=None, help="Explicit default policy path.")
    parser.add_argument("--override-dir", default=None, help="Override directory (default: NAOS_ROOT/policy_overrides.d).")
    parser.add_argument("--team-operator-map", default=None, help="Team/operator map path (default: NAOS_ROOT/team_operator_map.yaml).")
    parser.add_argument("--team-id", default=None, help="Filesystem-safe team overlay id to apply as static configuration.")
    parser.add_argument("--operator-id", default=None, help="Operator id to resolve team/operator overlay scope; not authentication.")
    parser.add_argument("--operator-overlay-id", default=None, help="Filesystem-safe operator overlay id to apply as static configuration.")
    parser.add_argument("--output", default=None, help="Write merge report JSON to this path.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and report without writing an effective policy.")
    parser.add_argument("--write-effective-policy", action="store_true", help="Write derived effective policy YAML when validation passes.")
    parser.add_argument("--effective-policy-output", default=None, help="Path for derived effective policy YAML.")
    parser.add_argument("--json", action="store_true", help="Print merge report JSON.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit behavior.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    override_dir = Path(args.override_dir) if args.override_dir else root / naos_root / "policy_overrides.d"
    map_path = team_operator_map_path(root, naos_root, policy, args.team_operator_map)

    effective_policy_default = report_default_path(root, naos_root, policy, "effective_policy")
    effective_policy_path = Path(args.effective_policy_output) if args.effective_policy_output else effective_policy_default
    write_effective = bool(args.write_effective_policy and not args.dry_run)

    report, _effective = build_merge_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        override_dir=override_dir,
        team_operator_map_path_value=map_path,
        explicit_operator_id=args.operator_id,
        explicit_team_id=args.team_id,
        explicit_operator_overlay_id=args.operator_overlay_id,
        write_effective_policy=write_effective,
        effective_policy_path=effective_policy_path,
    )

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "policy_override_merge_report")
    if output is not None:
        write_report(output, report)
        audit_result = write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type="policy_override_merged",
            source_report_path=output,
            source_report=report,
            related_artifacts=[
                str(path)
                for path in [output, effective_policy_path if write_effective else None]
                if path is not None
            ],
        )
        report["audit_log_event"] = {
            "status": audit_result.get("status"),
            "event_file": audit_result.get("event_file"),
            "findings": audit_result.get("findings") or [],
        }
        write_report(output, report)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS policy overrides: {report['status']} ({profile})")
        print(f"  override files: {report['summary']['override_files']}")
        print(f"  applied paths: {report['summary']['applied_paths']}")
        print(f"  rejected paths: {report['summary']['rejected_paths']}")
        print(f"  team scopes: {', '.join(report['summary'].get('team_ids') or []) or 'none'}")
        print(f"  operator overlay: {report['summary'].get('operator_overlay_id') or 'none'}")
        if output:
            print(f"  report: {output}")
        if report["findings"]:
            for item in report["findings"]:
                print(f"  - [{item['severity']}] {item['id']}: {item['message']}")

    if is_kit_repository(root, naos_root):
        return 0
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
