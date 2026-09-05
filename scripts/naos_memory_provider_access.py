#!/usr/bin/env python3
"""Verify declared memory provider and MCP access posture without using memory tools."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
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


REPORT_SCHEMA = "naos.memory_provider_access.v1"
RECOMMENDED_PROVIDER = "engram"
ACCESS_LEVELS = {"none", "read_only", "draft_write", "approved_write", "admin_config"}
WRITE_LEVELS = {"draft_write", "approved_write", "admin_config"}
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
}
NOT_CLAIMED = [
    "memory access guaranteed",
    "MCP access guaranteed",
    "memory as evidence",
    "memory as approval",
    "source of truth",
    "authoritative truth",
    "compliance proof",
    "legal or regulatory approval",
    "hallucination prevention",
    "cloud memory by default",
    "automatic memory writes",
    "automatic memory usage",
    "provider installation",
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
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_provider_access_rules.yaml"


def default_memory_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_context_rules.yaml"


def default_matrix_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_authorization_matrix.yaml"


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_seed_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    path_key: str,
    template_path: Path,
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get(path_key) or template_path.name)
    project_path = root / naos_root / filename
    if project_path.exists():
        return project_path, "project"
    return template_path, "template"


def load_memory_config(root: Path) -> dict[str, Any]:
    candidates = [root / "configs" / "naos_memory.yaml", root / "naos" / "configs" / "naos_memory.yaml"]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = load_yaml_mapping(path)
        except Exception as exc:
            return {"_path": str(path), "_error": str(exc)}
        memory = data.get("memory", data)
        if isinstance(memory, dict):
            result = dict(memory)
            result["_path"] = str(path)
            return result
    return {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if str(item).strip()]


def dedupe_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value).strip()))


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def profile_posture(rules: dict[str, Any], profile: str) -> dict[str, Any]:
    posture = rules.get("profile_posture") if isinstance(rules.get("profile_posture"), dict) else {}
    item = posture.get(profile)
    if isinstance(item, dict):
        return item
    defaults = {
        "quickstart": {"state": "disabled", "severity": "advisory", "human_review_required_if_memory_configured": False},
        "lite": {"state": "readiness_only", "severity": "advisory", "human_review_required_if_memory_configured": False},
        "standard": {"state": "readiness_only", "severity": "review_required", "human_review_required_if_memory_configured": True},
        "assured": {"state": "readiness_only", "severity": "review_required", "human_review_required_if_memory_configured": True},
    }
    return defaults.get(profile, defaults["quickstart"])


def severity_for_rules(root: Path, naos_root: str, profile: str, policy: dict[str, Any], posture: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    configured = str(posture.get("severity") or "").strip()
    if configured == "review_required":
        return "required" if profile == "standard" else "blocking" if profile == "assured" else "warning"
    if configured in {"advisory", "warning", "required", "blocking"}:
        return configured
    return severity_for_profile(profile, policy)


def finding(identifier: str, severity: str, status: str, message: str, actions: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": actions or [],
    }
    result.update({key: value for key, value in extra.items() if value is not None})
    return result


def expand_user_path(value: Any) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return Path(os.path.expanduser(text))
    except RuntimeError:
        return None


def rel_or_abs(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def path_matches(path: Path, root: Path, patterns: list[str]) -> bool:
    text = rel_or_abs(path, root).replace(os.sep, "/")
    basename = path.name
    return any(fnmatch.fnmatch(text, pattern) or fnmatch.fnmatch(basename, pattern) for pattern in patterns)


def path_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def provider_binary_names(provider_name: str | None) -> list[str]:
    provider = (provider_name or "").strip().lower()
    if provider == "engram":
        return ["engram", "engram-mcp", "mcp-engram", "engram-mcp-wrapper"]
    if provider:
        return [provider]
    return []


def inspect_provider_binary(provider_name: str | None, allowed: bool) -> dict[str, Any]:
    names = provider_binary_names(provider_name)
    detected = []
    if allowed:
        for name in names:
            found = shutil.which(name)
            if found:
                detected.append({"name": name, "path": found})
    return {
        "check_allowed": allowed,
        "candidate_names": names,
        "detected": detected,
        "detected_any": bool(detected),
        "access_verified": False,
        "rule": "Binary presence is locally observable metadata only; it does not prove usable memory access.",
    }


def inspect_provider_storage(root: Path, memory_config: dict[str, Any], rules: dict[str, Any]) -> dict[str, Any]:
    """Inspect Engram storage metadata without reading the database.

    Engram exposes a data-directory override, not an independently configurable
    database path.  Legacy ``store_path`` values are retained as migration
    evidence only and never participate in runtime path resolution.
    """

    environment_data_dir = str(os.environ.get("ENGRAM_DATA_DIR") or "").strip()
    declared_data_dir = str(memory_config.get("data_dir") or "").strip()
    raw_effective_data_dir: str
    if environment_data_dir:
        raw_effective_data_dir = environment_data_dir
        data_dir_source = "environment"
    elif declared_data_dir:
        raw_effective_data_dir = declared_data_dir
        data_dir_source = "config"
    else:
        raw_effective_data_dir = "~/.engram"
        data_dir_source = "default"
    try:
        effective_data_dir = Path(raw_effective_data_dir).expanduser()
        path_expansion_status = "resolved"
    except RuntimeError:
        effective_data_dir = Path(raw_effective_data_dir)
        path_expansion_status = "invalid_user_home_reference"

    database_path = effective_data_dir / "engram.db"
    legacy_store_path_raw = memory_config.get("store_path")
    legacy_store_path = expand_user_path(legacy_store_path_raw)
    legacy_status = "deprecated_ambiguous_not_used" if legacy_store_path_raw else "absent"
    exclusions = string_list(rules.get("provider_data_exclusions")) or string_list(
        rules.get("provider_store_exclusions")
    )
    data_dir_check_allowed = bool_value(
        rules.get("provider_data_dir_metadata_check_allowed"),
        bool_value(rules.get("provider_store_metadata_check_allowed"), True),
    )
    database_check_allowed = bool_value(rules.get("provider_database_metadata_check_allowed"), True)
    path_metadata_safe = path_expansion_status == "resolved"
    data_dir_exists = data_dir_check_allowed and path_metadata_safe and effective_data_dir.is_dir()
    database_exists = database_check_allowed and path_metadata_safe and database_path.is_file()
    database_inside_project = path_metadata_safe and database_exists and path_inside(database_path, root)
    database_matches_exclusion = path_metadata_safe and database_exists and path_matches(
        database_path,
        root,
        exclusions,
    )
    legacy_path_exists = bool(
        legacy_store_path
        and bool_value(rules.get("provider_store_metadata_check_allowed"), True)
        and legacy_store_path.exists()
    )
    database_metadata = {
        "path": str(database_path),
        "exists": database_exists,
        "payload_read": False,
        "prohibited_as_index_or_payload_source": True,
    }
    return {
        "check_allowed": data_dir_check_allowed and database_check_allowed and path_metadata_safe,
        "data_dir_check_allowed": data_dir_check_allowed,
        "database_check_allowed": database_check_allowed,
        "declared_data_dir": declared_data_dir or None,
        "effective_data_dir": str(effective_data_dir),
        "data_dir_source": data_dir_source,
        "path_expansion_status": path_expansion_status,
        "data_dir_exists": data_dir_exists,
        "database_path": str(database_path),
        "database_exists": database_exists,
        "inside_project": path_metadata_safe and path_inside(effective_data_dir, root),
        "matches_exclusion": path_metadata_safe and path_matches(effective_data_dir, root, exclusions),
        "database_inside_project": database_inside_project,
        "database_matches_exclusion": database_matches_exclusion,
        "excluded_db_metadata": [database_metadata],
        "legacy_store_path_declared": str(legacy_store_path_raw) if legacy_store_path_raw else None,
        "legacy_store_path_expanded": str(legacy_store_path) if legacy_store_path else None,
        "legacy_store_path_exists": legacy_path_exists,
        "legacy_store_path_status": legacy_status,
        "replication_profile": str(memory_config.get("replication_profile") or "local"),
        "replication_status": (
            "local" if str(memory_config.get("replication_profile") or "local").casefold() == "local" else "unsafe_non_local"
        ),
        "payload_read": False,
        "rule": (
            "Storage checks inspect data-directory and derived database metadata only; "
            "they never read memory entries or database contents. Legacy store_path is not used."
        ),
    }


def inspect_provider_store(root: Path, memory_config: dict[str, Any], rules: dict[str, Any]) -> dict[str, Any]:
    """Compatibility alias for callers of the former store-oriented helper."""

    return inspect_provider_storage(root, memory_config, rules)


def inspect_mcp_configs(root: Path, rules: dict[str, Any]) -> dict[str, Any]:
    allowed_workspace = set(string_list(rules.get("allowed_config_locations")))
    include_user = bool_value(rules.get("user_mcp_config_metadata_check_allowed"), False)
    presence_allowed = bool_value(rules.get("mcp_config_presence_check_allowed"), True)
    scanned = scan_mcp_configs(root, include_user=include_user) if presence_allowed else []
    files = [
        row
        for row in scanned
        if row.get("scope") == "user"
        or not allowed_workspace
        or str(row.get("path")) in allowed_workspace
    ]
    summary = summarize_mcp_configs(files)
    observed_files = [item for item in files if item.get("exists")]
    engram_files = [item for item in observed_files if item.get("engram_servers")]
    engram_servers = [
        server
        for server in summary.get("servers_declared") or []
        if server.get("is_engram")
    ]
    engram_server_keys = {
        (str(server.get("config_path")), str(server.get("name")))
        for server in engram_servers
    }
    engram_tools = [
        tool
        for tool in summary.get("tools_declared") or []
        if (str(tool.get("config_path")), str(tool.get("server"))) in engram_server_keys
    ]
    other_servers = [
        server
        for server in summary.get("servers_declared") or []
        if not server.get("is_engram")
    ]
    project_identity = resolve_engram_project(memory_config=None, configs=files)
    return {
        "files": files,
        "observed_files": observed_files,
        "present_files": engram_files,
        "engram_files": engram_files,
        "servers_declared": engram_servers,
        "tools_declared": engram_tools,
        "other_servers_observed": other_servers,
        "mcp_configured": bool(engram_files),
        "scan_scope": {
            "workspace_registry_metadata": presence_allowed,
            "user_registry_metadata": presence_allowed and include_user,
            "values_reported": False,
            "descriptor_ids": [str(row.get("config_id")) for row in files],
        },
        "project_identity": project_identity,
        "mcp_access_verified": False,
        "rule": (
            "Only an actual Engram server declaration counts as MCP configured. Other server files remain "
            "sanitized inventory metadata; Group 29 does not perform live MCP introspection or report values."
        ),
    }


def surface_access_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [str(row.get("id")) for row in rows]
    return {"count": len(rows), "ids": sorted(ids)}


def evaluate_platforms(
    matrix: dict[str, Any],
    mcp: dict[str, Any],
    severity: str,
    memory_configured: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    raw_platforms = matrix.get("platforms") if isinstance(matrix.get("platforms"), list) else []
    findings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for raw in raw_platforms:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        platform_id = str(row.get("id") or "unknown_platform")
        declared = bool(row.get("memory_access_declared"))
        read_access = str(row.get("read_access") or "none")
        write_access = str(row.get("write_access") or "none")
        admin_access = str(row.get("admin_access") or "none")
        row["mcp_access_verified"] = False
        row["provider_access_verified"] = False
        row["access_claim_status"] = "configured_unverified" if memory_configured and declared else "not_active"
        row["observed_config_files"] = [item["path"] for item in mcp.get("present_files", [])]
        for field_name, access in [("read_access", read_access), ("write_access", write_access), ("admin_access", admin_access)]:
            if access not in ACCESS_LEVELS:
                findings.append(
                    finding(
                        f"{platform_id}_{field_name}",
                        severity,
                        "unknown",
                        "Platform declares an unsupported memory access level.",
                        ["Use none, read_only, draft_write, approved_write, or admin_config."],
                        platform_id=platform_id,
                    )
                )
        if memory_configured and declared and not row["mcp_access_verified"]:
            findings.append(
                finding(
                    f"{platform_id}_memory_access_unverified",
                    severity,
                    "configured_unverified",
                    f"{row.get('name', platform_id)} declares memory access, but active provider/MCP access is not verified.",
                    ["Run naos memory-access after configuring the local platform, and do not claim memory was checked until access is verified."],
                    platform_id=platform_id,
                )
            )
        if write_access != "none" and read_access == "none":
            findings.append(
                finding(
                    f"{platform_id}_write_without_read_boundary",
                    severity,
                    "review_required",
                    "Platform write access is configured while read access is none; clarify access boundaries.",
                    ["Separate read, draft-write, approved-write, and admin access in the authorization matrix."],
                    platform_id=platform_id,
                )
            )
        if (write_access in WRITE_LEVELS or admin_access in WRITE_LEVELS) and not bool(row.get("human_review_required_for_write")):
            findings.append(
                finding(
                    f"{platform_id}_write_review_boundary",
                    severity,
                    "review_required",
                    "Platform write/admin memory access lacks a human-review boundary.",
                    ["Require human review before durable memory write or admin configuration."],
                    platform_id=platform_id,
                )
            )
        if platform_id == "ci" and (declared or read_access != "none" or write_access != "none" or admin_access != "none" or row.get("mcp_configured")):
            findings.append(
                finding(
                    "ci_memory_access",
                    "blocking",
                    "blocked",
                    "CI memory access must remain none by default.",
                    ["Set CI memory access to none and remove default CI memory/MCP configuration."],
                    platform_id=platform_id,
                )
            )
        rows.append(row)
    if not rows:
        findings.append(
            finding(
                "platform_access_matrix",
                severity,
                "missing",
                "Memory authorization matrix does not declare platform access posture.",
                ["Add platform rows for IDEs, agent CLIs, local tools, ChatGPT/OpenAI workflows, and CI."],
            )
        )

    access_summary = {
        "read_only": surface_access_summary([row for row in rows if row.get("read_access") == "read_only"]),
        "draft_write": surface_access_summary([row for row in rows if row.get("write_access") == "draft_write"]),
        "approved_write": surface_access_summary([row for row in rows if row.get("write_access") == "approved_write"]),
        "admin_config": surface_access_summary([row for row in rows if row.get("admin_access") == "admin_config"]),
        "ci": next((row for row in rows if row.get("id") == "ci"), {"read_access": "none", "write_access": "none", "admin_access": "none"}),
    }
    return rows, access_summary, findings


def evaluate_surfaces(matrix: dict[str, Any], severity: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_surfaces = matrix.get("surfaces") if isinstance(matrix.get("surfaces"), list) else []
    rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    counts = {level: 0 for level in ACCESS_LEVELS}
    counts["unknown"] = 0
    for raw in raw_surfaces:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        default_access = str(row.get("default_access") or "unknown")
        write_access = str(row.get("write_access") or "none")
        counts[default_access if default_access in ACCESS_LEVELS else "unknown"] += 1
        if default_access not in ACCESS_LEVELS or write_access not in ACCESS_LEVELS:
            findings.append(
                finding(
                    f"{row.get('id', 'surface')}_access_level",
                    severity,
                    "unknown",
                    "Surface declares an unsupported memory access level.",
                    ["Use none, read_only, draft_write, approved_write, or admin_config."],
                )
            )
        if write_access in WRITE_LEVELS and not bool(row.get("human_review_required_for_write")):
            findings.append(
                finding(
                    f"{row.get('id', 'surface')}_write_review_boundary",
                    severity,
                    "review_required",
                    "Surface has write access without a human-review boundary.",
                    ["Require human review before durable memory writes."],
                )
            )
        rows.append(row)
    return {"surfaces": rows, "access_level_counts": counts}, findings


def build_findings(
    *,
    root: Path,
    provider_declared: bool,
    provider_configured: bool,
    provider_binary: dict[str, Any],
    provider_store: dict[str, Any],
    mcp: dict[str, Any],
    rules: dict[str, Any],
    memory_config: dict[str, Any],
    severity: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if memory_config.get("_error"):
        findings.append(
            finding(
                "memory_config_parse_error",
                severity,
                "parse_error",
                f"Memory config could not be parsed: {memory_config.get('_error')}",
                ["Fix configs/naos_memory.yaml before relying on memory posture."],
            )
        )
    if provider_declared and bool_value(memory_config.get("enabled")) and not provider_configured:
        findings.append(
            finding(
                "provider_declared_not_configured",
                severity,
                "declared_only",
                "A memory provider is declared, but memory is not configured for active use.",
                ["Keep fallback recovery active or complete explicit provider/MCP setup with human review."],
            )
        )
    if provider_configured:
        findings.append(
            finding(
                "provider_configured_access_unverified",
                severity,
                "configured_unverified",
                "Memory provider is configured, but usable access is not verified by Group 29 v1.",
                ["Do not claim memory was checked until provider and platform tool access are verified by an approved non-invasive method."],
            )
        )
    if mcp.get("mcp_configured"):
        findings.append(
            finding(
                "mcp_config_present_access_unverified",
                severity,
                "configured_unverified",
                "An Engram MCP server declaration was detected, but active MCP access is not verified.",
                ["Verify actual tool availability in the configured platform before claiming memory access."],
            )
        )
    if provider_store.get("path_expansion_status") != "resolved":
        findings.append(
            finding(
                "provider_data_dir_invalid_user_home_reference",
                severity,
                "review_required",
                "The selected Engram data directory contains a user-home reference that cannot be resolved safely.",
                ["Replace the path with ~/.engram or an absolute directory outside the project, then rerun memory-access."],
            )
        )
    if provider_store.get("replication_status") == "unsafe_non_local":
        findings.append(
            finding(
                "provider_replication_profile_unsafe",
                severity,
                "review_required",
                "The declared Engram replication profile is non-local and outside the maintained NAOS onboarding profile.",
                [
                    "Review the external transfer and authorization boundary explicitly; NAOS will preserve the declaration and will not normalize or configure it."
                ],
                declared_replication_profile=provider_store.get("replication_profile"),
            )
        )
    if (
        provider_store.get("inside_project")
        or provider_store.get("matches_exclusion")
        or provider_store.get("database_inside_project")
        or provider_store.get("database_matches_exclusion")
    ):
        findings.append(
            finding(
                "provider_store_prohibited_location",
                severity,
                "review_required",
                "Provider data directory or derived database resolves inside the project or matches an excluded path pattern.",
                ["Keep private Engram data and the derived database outside source control and generated context artifacts."],
            )
        )
    if any(item.get("exists") for item in provider_store.get("excluded_db_metadata") or []):
        findings.append(
            finding(
                "engram_db_detected_metadata_only",
                severity,
                "review_required",
                "A local memory database path was detected as metadata only; it must not be read, indexed, or committed.",
                ["Keep database files excluded and do not use them as context-index or evidence inputs."],
            )
        )
    if provider_store.get("legacy_store_path_declared"):
        findings.append(
            finding(
                "legacy_store_path_deprecated",
                severity,
                "review_required",
                "The memory config still declares legacy store_path; it is ambiguous and was not used as Engram storage or synchronization configuration.",
                ["Review `naos memory setup` output and migrate explicitly to data_dir; keep replication local unless separately authorized."],
            )
        )
    obsolete_fields = [
        field
        for field in ("strict_required", "last_check")
        if field in memory_config
    ]
    if obsolete_fields:
        findings.append(
            finding(
                "obsolete_memory_config_fields",
                severity,
                "review_required",
                f"Memory config contains obsolete unused fields: {', '.join(obsolete_fields)}.",
                [
                    "Run a reviewed `naos memory setup` write to remove them; use the explicit readiness --strict-memory option and keep checks read-only."
                ],
            )
        )
    if not provider_binary.get("detected_any") and provider_configured:
        findings.append(
            finding(
                "provider_binary_not_detected",
                severity,
                "configured_unverified",
                "Provider is configured but no local provider binary was detected by a safe PATH check.",
                ["Install or configure provider tooling manually if the project approves memory access, then rerun memory-access."],
            )
        )

    risky_flags = [
        ("memory_payload_reads_allowed", "memory_payload_reads_allowed", "Memory payload reads are allowed; Group 29 must not read private memory payloads."),
        ("memory_writes_allowed", "memory_writes_allowed", "Memory writes are allowed; Group 29 must not write durable memory."),
        ("cloud_memory_allowed", "cloud_memory_allowed", "Cloud memory is allowed; default NAOS posture keeps cloud memory disabled."),
        ("external_sync_allowed", "external_sync_allowed", "External sync is allowed; default NAOS posture keeps sync disabled."),
        ("live_provider_calls_allowed", "live_provider_calls_allowed", "Live provider calls are allowed; Group 29 v1 is config-only."),
        ("live_mcp_calls_allowed", "live_mcp_calls_allowed", "Live MCP calls are allowed; Group 29 v1 does not call MCP."),
    ]
    for key, identifier, message in risky_flags:
        if bool_value(rules.get(key)):
            findings.append(
                finding(
                    identifier,
                    "blocking",
                    "blocked",
                    message,
                    ["Disable this rule unless a later reviewed capability explicitly implements it."],
                )
            )

    missing_forbidden = sorted(REQUIRED_FORBIDDEN_CATEGORIES - set(string_list(rules.get("forbidden_memory_categories"))))
    if missing_forbidden:
        findings.append(
            finding(
                "forbidden_memory_categories_missing",
                severity,
                "missing",
                f"Forbidden memory categories are incomplete: {', '.join(missing_forbidden)}.",
                ["Add missing forbidden memory categories before approving memory use."],
            )
        )
    fallback = rules.get("fallback_policy") if isinstance(rules.get("fallback_policy"), dict) else {}
    if not fallback.get("required") or not fallback.get("degraded_recovery_allowed"):
        findings.append(
            finding(
                "fallback_policy_missing",
                severity,
                "missing",
                "Fallback behavior when memory is unavailable is missing or disabled.",
                ["Declare fallback to repo evidence, task/context packs, deterministic reports, and git state."],
            )
        )
    scope = str(memory_config.get("scope") or "")
    project_identity = mcp.get("project_identity") if isinstance(mcp.get("project_identity"), dict) else {}
    identity_status = str(project_identity.get("status") or "missing")
    if identity_status == "conflict":
        findings.append(
            finding(
                "cross_project_memory_scope_not_bounded",
                severity,
                "conflict",
                "Engram project identity declarations conflict; no project identity was selected.",
                ["Reconcile memory.mcp_project and any fixed workspace declarations, then verify the active project through an approved resolver or mem_current_project."],
            )
        )
    elif provider_configured and scope in {"organization", "organization_level", "shared", "user-centralized"} and identity_status in {
        "missing",
        "global_only",
        "declared_candidate",
        "unresolved_equivalence",
    }:
        findings.append(
            finding(
                "cross_project_memory_scope_not_bounded",
                severity,
                "review_required",
                "Configuration metadata cannot establish the canonical Engram project binding for this workspace.",
                [
                    "Use the optional managed registry/resolver and verify mem_current_project in the active client; fixed ENGRAM_PROJECT declarations, when present, must agree."
                ],
            )
        )
    if project_identity.get("global_fixed_project_detected"):
        findings.append(
            finding(
                "global_fixed_memory_project_detected",
                severity,
                "review_required",
                "A user-scoped fixed Engram project declaration was observed and was not used to resolve this workspace.",
                ["Prefer a dynamic approved-remote resolver, or keep a fixed project declaration scoped to exactly one workspace."],
            )
        )
    for config_file in mcp.get("files") or []:
        if config_file.get("secret_like_keys"):
            findings.append(
                finding(
                    "mcp_config_secret_like_keys",
                    severity,
                    "review_required",
                    "An MCP config declares secret-like environment key names; values were not exposed.",
                    ["Keep secrets out of committed config and use platform secret storage where needed."],
                    path=config_file.get("path"),
                )
            )
    return findings


def report_status(
    rules: dict[str, Any],
    posture: dict[str, Any],
    memory_config: dict[str, Any],
    provider_configured: bool,
    provider_access_verified: bool,
    engram_mcp_configured: bool,
    findings: list[dict[str, Any]],
) -> str:
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if any(
        item.get("id")
        in {
            "provider_data_dir_invalid_user_home_reference",
            "provider_replication_profile_unsafe",
            "provider_store_prohibited_location",
            "global_fixed_memory_project_detected",
        }
        for item in findings
    ):
        return "review_required"
    if (not bool_value(rules.get("enabled"), True)) or (
        posture.get("state") == "disabled" and not provider_configured and not engram_mcp_configured
    ):
        return "disabled"
    state = str(memory_config.get("state") or "not_configured")
    if provider_access_verified:
        return "verified"
    if provider_configured:
        return "configured_unverified"
    if engram_mcp_configured:
        return "declared_only"
    if state in {"disabled"}:
        return "disabled"
    if state in {
        "deferred",
        "pending_external_verification",
        "pending_existing_verification",
        "not_configured",
        "unknown",
    } or not memory_config:
        return "not_configured"
    if any(item.get("severity") in {"required", "warning"} or item.get("status") == "review_required" for item in findings):
        return "review_required"
    return "readiness_only"


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    memory_rules_path: Path,
    memory_rules_source: str,
    matrix: dict[str, Any],
    matrix_path: Path,
    matrix_source: str,
) -> dict[str, Any]:
    posture = profile_posture(rules, profile)
    severity = severity_for_rules(root, naos_root, profile, policy, posture)
    memory_config = load_memory_config(root)
    declared_provider = memory_config.get("provider")
    provider_declared = isinstance(declared_provider, str) and bool(declared_provider.strip())
    provider_name = declared_provider.strip() if provider_declared else RECOMMENDED_PROVIDER
    provider_recommended = provider_name.casefold() == RECOMMENDED_PROVIDER
    provider_name_source = "configuration" if provider_declared else "recommended_default"
    provider_configured = bool(memory_config.get("enabled")) and str(memory_config.get("state") or "") == "configured"
    provider_binary = inspect_provider_binary(provider_name, bool_value(rules.get("provider_binary_check_allowed"), True))
    provider_store = inspect_provider_store(root, memory_config, rules)
    mcp = inspect_mcp_configs(root, rules)
    project_identity = resolve_engram_project(memory_config, mcp.get("files") or [])
    mcp["project_identity"] = project_identity
    provider_access_verified = False
    mcp_access_verified = False

    platform_rows, access_summary, platform_findings = evaluate_platforms(matrix, mcp, severity, provider_configured)
    surface_auth, surface_findings = evaluate_surfaces(matrix, severity)
    findings = build_findings(
        root=root,
        provider_declared=provider_declared,
        provider_configured=provider_configured,
        provider_binary=provider_binary,
        provider_store=provider_store,
        mcp=mcp,
        rules=rules,
        memory_config=memory_config,
        severity=severity,
    )
    findings.extend(platform_findings)
    findings.extend(surface_findings)
    status = report_status(
        rules,
        posture,
        memory_config,
        provider_configured,
        provider_access_verified,
        bool(mcp.get("mcp_configured")),
        findings,
    )
    summary = finding_counts(findings)
    summary.update(
        {
            "status": status,
            "profile_state": posture.get("state"),
            "provider_declared": provider_declared,
            "provider_recommended": provider_recommended,
            "provider_name_source": provider_name_source,
            "provider_configured": provider_configured,
            "provider_access_verified": provider_access_verified,
            "provider_binary_detected": provider_binary.get("detected_any", False),
            "provider_data_dir_exists": bool(provider_store.get("data_dir_exists")),
            "provider_database_exists": bool(provider_store.get("database_exists")),
            "provider_replication_profile": provider_store.get("replication_profile"),
            "provider_replication_status": provider_store.get("replication_status"),
            "legacy_store_path_declared": bool(provider_store.get("legacy_store_path_declared")),
            "mcp_config_files_detected": len(mcp.get("observed_files") or []),
            "mcp_engram_config_files_detected": len(mcp.get("engram_files") or []),
            "mcp_configured": bool(mcp.get("mcp_configured")),
            "mcp_servers_declared": len(mcp.get("servers_declared") or []),
            "mcp_access_verified": mcp_access_verified,
            "project_identity_status": project_identity.get("status"),
            "project_identity_verified": bool(project_identity.get("project_identity_verified")),
            "platforms": len(platform_rows),
            "platforms_with_declared_memory": sum(1 for row in platform_rows if row.get("memory_access_declared")),
            "ci_memory_access": access_summary["ci"].get("read_access", "none"),
            "human_review_required": any(item.get("status") in {"review_required", "configured_unverified", "blocked"} for item in findings)
            or bool(posture.get("human_review_required_if_memory_configured") and provider_configured),
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
        "rules_source": rules_source,
        "rules_hash": safe_digest(rules_path),
        "memory_config_path": memory_config.get("_path"),
        "memory_rules_path": str(memory_rules_path),
        "memory_rules_source": memory_rules_source,
        "authorization_matrix_path": str(matrix_path),
        "authorization_matrix_source": matrix_source,
        "provider_declared": provider_declared,
        "provider_recommended": provider_recommended,
        "provider_name": provider_name,
        "provider_name_source": provider_name_source,
        "provider_configured": provider_configured,
        "provider_access_verified": provider_access_verified,
        "provider_access_method": "config_only_no_live_calls",
        "provider_binary_detected": bool(provider_binary.get("detected_any")),
        "provider_binary": provider_binary,
        "provider_data_dir_declared": provider_store.get("declared_data_dir"),
        "provider_data_dir_effective": provider_store.get("effective_data_dir"),
        "provider_data_dir_source": provider_store.get("data_dir_source"),
        "provider_data_dir_expansion_status": provider_store.get("path_expansion_status"),
        "provider_data_dir_exists": bool(provider_store.get("data_dir_exists")),
        "provider_database_path": provider_store.get("database_path"),
        "provider_database_exists": bool(provider_store.get("database_exists")),
        "provider_storage_payload_read": False,
        "provider_replication_profile": provider_store.get("replication_profile"),
        "provider_replication_status": provider_store.get("replication_status"),
        "provider_legacy_store_path_declared": provider_store.get("legacy_store_path_declared"),
        "provider_legacy_store_path_status": provider_store.get("legacy_store_path_status"),
        "provider_store_path_declared": provider_store.get("legacy_store_path_declared"),
        "provider_store_path_exists": bool(provider_store.get("legacy_store_path_exists")),
        "provider_store": provider_store,
        "provider_store_payload_read": False,
        "mcp_config_files_inspected": mcp.get("files") or [],
        "mcp_config_files_detected": mcp.get("observed_files") or [],
        "mcp_engram_config_files_detected": mcp.get("engram_files") or [],
        "mcp_configured": bool(mcp.get("mcp_configured")),
        "mcp_servers_declared": mcp.get("servers_declared") or [],
        "mcp_tools_declared": mcp.get("tools_declared") or [],
        "mcp_other_servers_observed": mcp.get("other_servers_observed") or [],
        "mcp_scan_scope": mcp.get("scan_scope") or {},
        "mcp_access_verified": mcp_access_verified,
        "project_identity": project_identity,
        "platform_access_matrix": platform_rows,
        "authorization_matrix": surface_auth,
        "read_access": access_summary["read_only"],
        "draft_write_access": access_summary["draft_write"],
        "approved_write_access": access_summary["approved_write"],
        "admin_config_access": access_summary["admin_config"],
        "ci_memory_access": access_summary["ci"],
        "fallback_when_unavailable": rules.get("fallback_policy") if isinstance(rules.get("fallback_policy"), dict) else {},
        "verification_scope": {
            "mode": rules.get("provider_access_verification_mode", "config_only"),
            "live_provider_calls_allowed": bool_value(rules.get("live_provider_calls_allowed")),
            "live_mcp_calls_allowed": bool_value(rules.get("live_mcp_calls_allowed")),
            "memory_payload_reads_allowed": bool_value(rules.get("memory_payload_reads_allowed")),
            "memory_writes_allowed": bool_value(rules.get("memory_writes_allowed")),
            "cloud_memory_allowed": bool_value(rules.get("cloud_memory_allowed")),
            "external_sync_allowed": bool_value(rules.get("external_sync_allowed")),
        },
        "platform_verification_expectations": rules.get("platform_verification_expectations") or [],
        "access_level_definitions": rules.get("access_levels") or [],
        "findings": findings,
        "known_gaps": rules.get("known_gaps") if isinstance(rules.get("known_gaps"), list) else [],
        "residual_risks": rules.get("residual_risks") if isinstance(rules.get("residual_risks"), list) else [],
        "waivers": rules.get("waivers") if isinstance(rules.get("waivers"), list) else [],
        "limitations": dedupe_strings(string_list(rules.get("limitations")) + string_list(matrix.get("limitations"))),
        "not_claimed": dedupe_strings(string_list(rules.get("not_claimed")) + NOT_CLAIMED),
        "human_review_required": bool(summary["human_review_required"]),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify declared memory provider and MCP access posture without using memory tools.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file used for path/profile conventions.")
    parser.add_argument("--rules", help="Explicit memory_provider_access_rules.yaml path.")
    parser.add_argument("--memory-rules", help="Explicit memory_context_rules.yaml path.")
    parser.add_argument("--authorization-matrix", help="Explicit memory_authorization_matrix.yaml path.")
    parser.add_argument("--output", help="Optional JSON report output path.")
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
        rules_path, rules_source = resolve_seed_path(
            root,
            naos_root,
            policy,
            "memory_provider_access_rules",
            default_rules_template(),
            args.rules,
        )
        memory_rules_path, memory_rules_source = resolve_seed_path(
            root,
            naos_root,
            policy,
            "memory_context_rules",
            default_memory_rules_template(),
            args.memory_rules,
        )
        matrix_path, matrix_source = resolve_seed_path(
            root,
            naos_root,
            policy,
            "memory_authorization_matrix",
            default_matrix_template(),
            args.authorization_matrix,
        )
        rules = load_yaml_mapping(rules_path)
        matrix = load_yaml_mapping(matrix_path)
        report = build_report(
            root,
            naos_root,
            profile,
            policy,
            rules,
            rules_path,
            rules_source,
            memory_rules_path,
            memory_rules_source,
            matrix,
            matrix_path,
            matrix_source,
        )
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "memory_provider_access_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(f"NAOS memory provider access ({profile}): {report['status']}")
        print(
            "summary: "
            f"provider_configured={summary.get('provider_configured')} "
            f"provider_access_verified={summary.get('provider_access_verified')} "
            f"mcp_configs_observed={summary.get('mcp_config_files_detected')} "
            f"engram_mcp_configs={summary.get('mcp_engram_config_files_detected')} "
            f"mcp_access_verified={summary.get('mcp_access_verified')} "
            f"findings={summary.get('total_findings', 0)}"
        )
        print(f"report: {output or 'not written in kit repository unless --output is supplied'}")
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
