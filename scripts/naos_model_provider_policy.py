#!/usr/bin/env python3
"""Evaluate central model-provider policy declarations without provider calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

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


REPORT_SCHEMA = "naos.model_provider_policy.v1"
ALLOWED_PROVIDER_KINDS = {
    "declarative_only",
    "cloud_api",
    "local_api",
    "managed_platform",
    "proxy",
}
DEFAULT_TOOL_BINDING_IDS = {
    "claude_code",
    "codex",
    "cursor",
    "gemini_cli",
    "github_copilot_cli",
    "opencode",
    "vscode_copilot",
    "openrouter",
    "other",
}
DEFAULT_COST_TIERS = {"low", "medium", "high", "premium", "unknown"}
ALIAS_MARKERS = ("latest", "preview", "experimental", "beta", "nightly", "unstable")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
SECRET_RE = re.compile(
    r"(?i)("
    r"sk-[A-Za-z0-9_-]{8,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"AKIA[0-9A-Z]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"api[_-]?key\s*[:=]|"
    r"bearer\s+[A-Za-z0-9._-]{12,}"
    r")"
)
SENSITIVE_FIELD_NAMES = {
    "api_key",
    "api_key_env",
    "token",
    "secret",
    "password",
    "credential",
    "credentials",
    "connection_string",
}
NOT_CLAIMED = [
    "provider call",
    "local model call",
    "cloud API call",
    "SDK dependency",
    "network probe",
    "proxy startup",
    "credential validation",
    "model quality guarantee",
    "runtime model routing",
    "IDE configuration mutation",
    "tool configuration rewrite",
    "LLMGrader runtime",
    "autoresearch provider grading",
    "behavioral scoring",
    "semantic drift inference",
    "approval",
    "certification",
    "attestation",
    "compliance proof",
    "release authority",
    "publication authority",
]
LIMITATIONS = [
    "This report validates local declarations only and does not call providers, models, APIs, proxies, local servers, MCP, or memory tools.",
    "Provider model IDs, aliases, pricing, regional availability, lifecycle status, and feature support are volatile and must be rechecked before provider-specific use.",
    "Model role declarations are review metadata; they do not prove model quality, safety, privacy, legality, or runtime behavior.",
    "Secrets must remain outside the repository; this report only detects obvious literal secret-like values in declared policy files.",
]
RESIDUAL_RISKS = [
    "provider_model_drift",
    "alias_or_preview_model_drift",
    "mixed_tool_model_drift",
    "local_cloud_capability_mismatch",
    "data_exposure",
    "cost_overrun",
    "credential_leak",
    "runtime_activation_confusion",
    "advisory_to_authority_confusion",
    "human_review_required",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def is_adapt_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith("[ADAPT:")


def is_empty_or_placeholder(value: Any) -> bool:
    if value in (None, ""):
        return True
    return is_adapt_placeholder(value)


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_policy_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "model_provider_policy.yaml"


def resolve_model_policy_path(
    root: Path,
    naos_root: str,
    governance_policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(governance_policy.get("paths", {}).get("model_provider_policy") or "model_provider_policy.yaml")
    project_policy = root / naos_root / filename
    if project_policy.exists():
        return project_policy, "project"
    return default_policy_template(), "template"


def parse_frontmatter(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(errors="replace")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    data = yaml.safe_load(text[4:end]) or {}
    return data if isinstance(data, dict) else {}


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def candidate_agent_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in (".github/agents/*.agent.md", "templates/agents/*.agent.md"):
        paths.extend(path for path in root.glob(pattern) if path.is_file())
    return sorted(dict.fromkeys(paths))


def collect_agent_role_references(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    references: list[dict[str, Any]] = []
    missing_role_metadata: list[dict[str, Any]] = []
    for path in candidate_agent_files(root):
        data = parse_frontmatter(path)
        role = data.get("naos_model_role")
        if is_empty_or_placeholder(role):
            missing_role_metadata.append(
                {
                    "source": "agent_frontmatter",
                    "path": relative_path(path, root),
                    "model": data.get("model"),
                    "missing": "naos_model_role",
                }
            )
            continue
        references.append(
            {
                "source": "agent_frontmatter",
                "role": str(role),
                "path": relative_path(path, root),
                "model": data.get("model"),
            }
        )
    return references, missing_role_metadata


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None


def collect_llm_grader_role_references(root: Path, naos_root: str) -> list[dict[str, Any]]:
    path = first_existing(
        [
            root / naos_root / "llm_grader_readiness_rules.yaml",
            kit_root() / "templates" / "structural-seeds" / "naos" / "llm_grader_readiness_rules.yaml",
        ]
    )
    if path is None:
        return []
    try:
        data = load_yaml_mapping(path)
    except Exception:
        return []
    references: list[dict[str, Any]] = []
    for container_name in ("future_enablement", "model_policy"):
        container = as_mapping(data.get(container_name))
        role = container.get("model_role")
        if not is_empty_or_placeholder(role):
            references.append(
                {
                    "source": f"llm_grader_readiness.{container_name}",
                    "role": str(role),
                    "path": relative_path(path, root),
                }
            )
    return references


def collect_autoresearch_references(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    paths = [
        root / "configs" / "naos_autoresearch.yaml",
        root / ".github" / "configs" / "naos_autoresearch.yaml",
        kit_root() / "templates" / "structural-seeds" / "configs" / "naos_autoresearch.yaml",
    ]
    path = first_existing(paths)
    if path is None:
        return [], []
    try:
        data = load_yaml_mapping(path)
    except Exception:
        return [], []
    grading = as_mapping(data.get("grading"))
    provider_grader = as_mapping(grading.get("provider_grader"))
    references: list[dict[str, Any]] = []
    role = provider_grader.get("model_role")
    if not is_empty_or_placeholder(role):
        references.append(
            {
                "source": "autoresearch.provider_grader",
                "role": str(role),
                "path": relative_path(path, root),
            }
        )

    duplicate_details: list[dict[str, Any]] = []
    provider_fields = {
        key: provider_grader.get(key)
        for key in ("provider", "model", "model_version", "api_key_env", "base_url_env")
        if not is_empty_or_placeholder(provider_grader.get(key))
    }
    if provider_fields and is_empty_or_placeholder(role):
        duplicate_details.append(
            {
                "source": "autoresearch.provider_grader",
                "path": relative_path(path, root),
                "fields": sorted(provider_fields),
            }
        )
    return references, duplicate_details


def collect_role_references(root: Path, naos_root: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    references, agent_role_gaps = collect_agent_role_references(root)
    references.extend(collect_llm_grader_role_references(root, naos_root))
    autoresearch_refs, duplicate_details = collect_autoresearch_references(root)
    references.extend(autoresearch_refs)
    return references, duplicate_details, agent_role_gaps


def finding(
    identifier: str,
    severity: str,
    status: str,
    message: str,
    *,
    role: str | None = None,
    source: str | None = None,
    related_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "authority_layer": "declaration_review",
        "human_review_required": True,
        "not_claimed": ["provider call", "runtime routing", "approval", "certification", "compliance proof"],
    }
    if role:
        result["role"] = role
    if source:
        result["source"] = source
    if related_refs:
        result["related_refs"] = related_refs
    return result


def profile_posture(policy: dict[str, Any], profile: str) -> dict[str, Any]:
    posture = as_mapping(policy.get("profile_posture")).get(profile)
    if isinstance(posture, dict):
        return posture
    defaults = {
        "quickstart": {"state": "optional", "severity": "advisory", "human_review_required": False},
        "lite": {"state": "optional", "severity": "warning", "human_review_required": False},
        "standard": {"state": "expected", "severity": "required", "human_review_required": True},
        "assured": {"state": "expected", "severity": "required", "human_review_required": True},
    }
    return defaults.get(profile, defaults["quickstart"])


def severity_from_posture(posture: dict[str, Any], default: str = "advisory") -> str:
    value = str(posture.get("severity") or default)
    return value if value in {"advisory", "warning", "required", "blocking"} else default


def alias_severity(policy: dict[str, Any], profile: str, posture: dict[str, Any]) -> str:
    alias_policy = as_mapping(policy.get("default_alias_policy")).get(profile)
    if alias_policy == "pinned_required" and profile == "assured":
        return "blocking"
    if alias_policy in {"review_required", "pinned_required"}:
        return "required"
    return severity_from_posture(posture, "advisory")


def active_role_names(roles: dict[str, Any], references: list[dict[str, Any]]) -> set[str]:
    active = {ref["role"] for ref in references if ref.get("role")}
    for name, role in roles.items():
        role_map = as_mapping(role)
        if bool_value(role_map.get("enabled")) or bool_value(role_map.get("required")):
            active.add(str(name))
    return active


def looks_like_alias(value: Any) -> bool:
    if not isinstance(value, str) or is_adapt_placeholder(value):
        return False
    lowered = value.strip().lower()
    return any(marker in lowered for marker in ALIAS_MARKERS) or lowered.endswith(":latest")


def looks_like_secret(value: Any) -> bool:
    if not isinstance(value, str) or is_adapt_placeholder(value):
        return False
    return bool(SECRET_RE.search(value))


def invalid_env_reference(value: Any) -> bool:
    if value in (None, "") or is_adapt_placeholder(value):
        return False
    if not isinstance(value, str):
        return True
    return not bool(ENV_NAME_RE.fullmatch(value.strip()))


def local_url_is_public(value: Any) -> bool:
    if not isinstance(value, str) or is_adapt_placeholder(value):
        return False
    lowered = value.strip().lower()
    if not lowered.startswith(("http://", "https://")):
        return False
    return not (
        lowered.startswith("http://localhost")
        or lowered.startswith("https://localhost")
        or lowered.startswith("http://127.0.0.1")
        or lowered.startswith("https://127.0.0.1")
        or lowered.startswith("http://[::1]")
        or lowered.startswith("https://[::1]")
    )


def declared_value(value: Any) -> bool:
    return not is_empty_or_placeholder(value)


def configured_tool_ids(model_policy: dict[str, Any]) -> set[str]:
    policy = as_mapping(model_policy.get("tool_binding_policy"))
    declared = set(string_list(policy.get("allowed_tools")))
    return declared or DEFAULT_TOOL_BINDING_IDS


def configured_cost_tiers(model_policy: dict[str, Any]) -> set[str]:
    policy = as_mapping(model_policy.get("tool_binding_policy"))
    declared = set(string_list(policy.get("allowed_cost_tiers")))
    return declared or DEFAULT_COST_TIERS


def configured_data_exposure_levels(model_policy: dict[str, Any]) -> set[str]:
    data_policy = as_mapping(model_policy.get("data_policy"))
    declared = set(string_list(data_policy.get("allowed_data_exposure_levels")))
    return declared or {"none", "repo_metadata_only", "repo_metadata_or_code", "project_configured"}


def collect_tool_model_bindings(model_policy: dict[str, Any], roles: dict[str, Any]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    allowed_tools = configured_tool_ids(model_policy)
    tools = as_mapping(model_policy.get("tool_model_bindings"))
    for tool_id, raw_tool in sorted(tools.items()):
        tool = as_mapping(raw_tool)
        tool_enabled = bool_value(tool.get("enabled"))
        tool_mutation_allowed = bool_value(tool.get("mutation_allowed"))
        role_bindings = as_mapping(tool.get("roles"))
        for role_name, raw_binding in sorted(role_bindings.items()):
            role_key = str(role_name)
            role_defaults = as_mapping(roles.get(role_key))
            binding = as_mapping(raw_binding)
            provider_kind = str(binding.get("provider_kind") or role_defaults.get("provider_kind") or "declarative_only")
            provider = binding.get("provider")
            model = binding.get("model")
            model_version = binding.get("model_version")
            reasoning_effort = binding.get("reasoning_effort")
            if is_empty_or_placeholder(reasoning_effort):
                reasoning_effort = role_defaults.get("reasoning_effort")
            model_alias = binding.get("model_alias")
            cost_tier = binding.get("cost_tier")
            data_exposure_level = binding.get("data_exposure_level")
            enabled = bool_value(binding.get("enabled"), tool_enabled)
            has_declared_route = any(
                declared_value(value)
                for value in (
                    provider,
                    model,
                    model_version,
                    reasoning_effort,
                    model_alias,
                    cost_tier,
                    data_exposure_level,
                    binding.get("api_key_env"),
                    binding.get("base_url_env"),
                    binding.get("endpoint_env"),
                    binding.get("base_url"),
                )
            )
            if not enabled and not has_declared_route:
                continue
            bindings.append(
                {
                    "source": f"tool_model_bindings.{tool_id}.roles.{role_key}",
                    "tool": str(tool_id),
                    "tool_family": str(tool.get("tool_family") or tool_id),
                    "tool_known": str(tool_id) in allowed_tools,
                    "tool_enabled": tool_enabled,
                    "enabled": enabled,
                    "role": role_key,
                    "role_declared": role_key in roles,
                    "provider_kind": provider_kind,
                    "provider": provider,
                    "provider_declared": declared_value(provider),
                    "model": model,
                    "model_declared": declared_value(model),
                    "model_version": model_version,
                    "model_version_declared": declared_value(model_version),
                    "reasoning_effort": reasoning_effort,
                    "reasoning_effort_declared": declared_value(reasoning_effort),
                    "model_alias": model_alias,
                    "alias_allowed": bool_value(binding.get("alias_allowed")),
                    "cost_tier": cost_tier,
                    "data_exposure_level": data_exposure_level,
                    "api_key_env": binding.get("api_key_env"),
                    "base_url_env": binding.get("base_url_env"),
                    "endpoint_env": binding.get("endpoint_env"),
                    "base_url": binding.get("base_url"),
                    "mutation_allowed": tool_mutation_allowed or bool_value(binding.get("mutation_allowed")),
                    "human_review_required": bool_value(
                        binding.get("human_review_required"),
                        bool_value(tool.get("human_review_required"), True),
                    ),
                    "has_rationale": declared_value(binding.get("alignment_rationale") or binding.get("rationale")),
                }
            )
    return bindings


def tool_binding_counts(model_policy: dict[str, Any], bindings: list[dict[str, Any]]) -> dict[str, int]:
    tools = as_mapping(model_policy.get("tool_model_bindings"))
    drift_roles = cross_tool_drift_roles(bindings)
    return {
        "tools_declared": len(tools),
        "role_bindings_declared": len(bindings),
        "active_role_bindings": sum(1 for item in bindings if bool_value(item.get("enabled"))),
        "unknown_tools": sum(1 for item in bindings if not bool_value(item.get("tool_known"))),
        "mutation_allowed": sum(1 for item in bindings if bool_value(item.get("mutation_allowed"))),
        "cross_tool_drift_roles": len(drift_roles),
    }


def cross_tool_drift_roles(bindings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in bindings:
        if not (bool_value(item.get("enabled")) or bool_value(item.get("provider_declared")) or bool_value(item.get("model_declared"))):
            continue
        if not bool_value(item.get("role_declared")):
            continue
        if str(item.get("provider_kind") or "") == "declarative_only" and not bool_value(item.get("model_declared")):
            continue
        grouped.setdefault(str(item.get("role")), []).append(item)

    drift: dict[str, list[dict[str, Any]]] = {}
    for role_name, items in grouped.items():
        signatures = {
            (
                str(item.get("provider_kind") or ""),
                str(item.get("provider") or ""),
                str(item.get("model") or ""),
                str(item.get("model_version") or ""),
                str(item.get("reasoning_effort") or ""),
                str(item.get("cost_tier") or ""),
                str(item.get("data_exposure_level") or ""),
            )
            for item in items
        }
        if len(signatures) > 1:
            drift[role_name] = items
    return drift


def nested_secret_hits(value: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            key_lower = str(key).lower()
            if any(part in key_lower for part in SENSITIVE_FIELD_NAMES) and looks_like_secret(child):
                hits.append(child_path)
            hits.extend(nested_secret_hits(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(nested_secret_hits(child, f"{path}[{index}]"))
    return hits


def role_summary(name: str, role: dict[str, Any], referenced: bool) -> dict[str, Any]:
    return {
        "role": name,
        "enabled": bool_value(role.get("enabled")),
        "referenced": referenced,
        "provider_kind": role.get("provider_kind"),
        "provider": role.get("provider"),
        "model_declared": not is_empty_or_placeholder(role.get("model")),
        "model_version_declared": not is_empty_or_placeholder(role.get("model_version")),
        "reasoning_effort": role.get("reasoning_effort"),
        "reasoning_effort_declared": not is_empty_or_placeholder(role.get("reasoning_effort")),
        "alias_allowed": bool_value(role.get("alias_allowed")),
        "runtime_enabled": bool_value(role.get("runtime_enabled")),
        "advisory_only": bool_value(role.get("advisory_only"), True),
        "cost_tier": role.get("cost_tier"),
        "data_exposure_level": role.get("data_exposure_level"),
        "human_review_required": bool_value(role.get("human_review_required")),
    }


def build_findings(
    model_policy: dict[str, Any],
    profile: str,
    posture: dict[str, Any],
    policy_source: str,
    roles: dict[str, Any],
    references: list[dict[str, Any]],
    duplicate_provider_details: list[dict[str, Any]],
    agent_role_gaps: list[dict[str, Any]],
    tool_bindings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    posture_severity = severity_from_posture(posture)
    tool_policy = as_mapping(model_policy.get("tool_binding_policy"))
    allowed_cost_tiers = configured_cost_tiers(model_policy)
    allowed_data_levels = configured_data_exposure_levels(model_policy)
    require_cost_tier = bool_value(tool_policy.get("require_cost_tier"), True)
    require_data_exposure = bool_value(tool_policy.get("require_data_exposure_level"), True)

    if policy_source == "template" and profile in {"standard", "assured"}:
        findings.append(
            finding(
                "model_provider.missing_project_policy",
                posture_severity,
                "review_required",
                "No project-local model_provider_policy.yaml was found; using the kit template as review guidance.",
            )
        )

    unsafe_flags = [
        ("runtime_enabled", "Runtime model/provider behavior is enabled."),
        ("provider_calls_allowed", "Provider/model calls are allowed by policy."),
        ("credentials_allowed_in_repo", "Repository credential storage is allowed by policy."),
        ("can_approve", "Policy claims approval authority."),
        ("can_certify", "Policy claims certification authority."),
        ("can_prove_compliance", "Policy claims compliance-proof authority."),
        ("can_promote_maturity", "Policy claims maturity-promotion authority."),
        ("runtime_routing_authority", "Policy claims runtime routing authority."),
        ("model_quality_authority", "Policy claims model-quality authority."),
    ]
    for key, message in unsafe_flags:
        if bool_value(model_policy.get(key)):
            findings.append(finding(f"model_provider.runtime_escalation.{key}", "blocking", "blocked", message))

    if bool_value(tool_policy.get("mutation_allowed")):
        findings.append(
            finding(
                "model_provider.tool_binding_mutation_enabled",
                "blocking",
                "blocked",
                "Tool model-binding policy allows tool or IDE configuration mutation; this candidate is declaration review only.",
            )
        )

    for secret_path in nested_secret_hits(model_policy):
        findings.append(
            finding(
                "model_provider.literal_secret",
                "blocking",
                "blocked",
                f"Literal secret-like value found at `{secret_path}`; policy may declare environment variable names only.",
                source=secret_path,
            )
        )

    role_refs: dict[str, list[dict[str, Any]]] = {}
    for ref in references:
        role_refs.setdefault(str(ref.get("role")), []).append(ref)

    for role_name, refs in sorted(role_refs.items()):
        if role_name not in roles:
            findings.append(
                finding(
                    "model_provider.missing_role",
                    posture_severity,
                    "review_required",
                    f"Model role `{role_name}` is referenced but not declared in model_provider_policy.yaml.",
                    role=role_name,
                    related_refs=refs,
                )
            )

    for gap in agent_role_gaps:
        findings.append(
            finding(
                "model_provider.agent_role_metadata_missing",
                posture_severity,
                "review_required",
                "Agent frontmatter declares a host-tool model but is missing `naos_model_role` for central policy linkage.",
                source=gap.get("path"),
                related_refs=[gap],
            )
        )

    active = active_role_names(roles, references)
    for role_name, raw_role in sorted(roles.items()):
        role = as_mapping(raw_role)
        provider_kind = str(role.get("provider_kind") or "")
        referenced = role_name in role_refs
        role_is_active = role_name in active

        if provider_kind and provider_kind not in ALLOWED_PROVIDER_KINDS:
            findings.append(
                finding(
                    "model_provider.invalid_provider_kind",
                    posture_severity,
                    "review_required",
                    f"Role `{role_name}` uses unsupported provider_kind `{provider_kind}`.",
                    role=role_name,
                )
            )

        cost_tier = role.get("cost_tier")
        if declared_value(cost_tier) and str(cost_tier) not in allowed_cost_tiers:
            findings.append(
                finding(
                    "model_provider.invalid_cost_tier",
                    posture_severity,
                    "review_required",
                    f"Role `{role_name}` uses unsupported cost_tier `{cost_tier}`.",
                    role=role_name,
                )
            )

        data_level = role.get("data_exposure_level")
        if declared_value(data_level) and str(data_level) not in allowed_data_levels:
            findings.append(
                finding(
                    "model_provider.invalid_data_exposure_level",
                    posture_severity,
                    "review_required",
                    f"Role `{role_name}` uses unsupported data_exposure_level `{data_level}`.",
                    role=role_name,
                )
            )

        if not role_is_active:
            continue

        if bool_value(role.get("runtime_enabled")) or bool_value(role.get("provider_calls_allowed")):
            findings.append(
                finding(
                    "model_provider.runtime_escalation.role",
                    "blocking",
                    "blocked",
                    f"Role `{role_name}` enables runtime/provider behavior; this slice is declaration-only.",
                    role=role_name,
                )
            )

        if not bool_value(role.get("advisory_only"), True):
            findings.append(
                finding(
                    "model_provider.advisory_boundary_missing",
                    "blocking",
                    "blocked",
                    f"Role `{role_name}` is not advisory-only.",
                    role=role_name,
                )
            )

        if provider_kind in {"cloud_api", "local_api", "managed_platform", "proxy"}:
            if is_empty_or_placeholder(role.get("provider")):
                findings.append(
                    finding(
                        "model_provider.missing_role_metadata",
                        posture_severity,
                        "review_required",
                        f"Active role `{role_name}` is missing provider.",
                        role=role_name,
                    )
                )
            if require_cost_tier and is_empty_or_placeholder(role.get("cost_tier")):
                findings.append(
                    finding(
                        "model_provider.missing_role_cost_metadata",
                        posture_severity,
                        "review_required",
                        f"Active role `{role_name}` is missing cost_tier.",
                        role=role_name,
                    )
                )
            if require_data_exposure and is_empty_or_placeholder(role.get("data_exposure_level")):
                findings.append(
                    finding(
                        "model_provider.missing_role_data_metadata",
                        posture_severity,
                        "review_required",
                        f"Active role `{role_name}` is missing data_exposure_level.",
                        role=role_name,
                    )
                )
            if is_empty_or_placeholder(role.get("model")):
                findings.append(
                    finding(
                        "model_provider.missing_role_metadata",
                        posture_severity,
                        "review_required",
                        f"Active role `{role_name}` is missing model.",
                        role=role_name,
                    )
                )

        if bool_value(role.get("alias_allowed")) or looks_like_alias(role.get("model")) or looks_like_alias(role.get("model_version")):
            findings.append(
                finding(
                    "model_provider.alias_review_required",
                    alias_severity(model_policy, profile, posture),
                    "review_required",
                    f"Role `{role_name}` allows or uses alias/latest/preview/experimental model posture.",
                    role=role_name,
                )
            )
        elif profile == "assured" and role_is_active and provider_kind in {"cloud_api", "local_api", "managed_platform", "proxy"} and is_empty_or_placeholder(role.get("model_version")):
            findings.append(
                finding(
                    "model_provider.alias_review_required",
                    "blocking",
                    "review_required",
                    f"Assured active role `{role_name}` must declare a pinned model version or equivalent digest.",
                    role=role_name,
                )
            )

        for env_field in ("api_key_env", "base_url_env", "endpoint_env"):
            if invalid_env_reference(role.get(env_field)):
                findings.append(
                    finding(
                        "model_provider.env_reference_review",
                        posture_severity,
                        "review_required",
                        f"Role `{role_name}` field `{env_field}` should contain an environment variable name, not a literal value.",
                        role=role_name,
                    )
                )

        if provider_kind == "local_api" and local_url_is_public(role.get("base_url")):
            findings.append(
                finding(
                    "model_provider.local_endpoint_exposure_review",
                    posture_severity,
                    "review_required",
                    f"Role `{role_name}` declares a non-local literal base_url for a local_api provider.",
                    role=role_name,
                )
            )

    for item in duplicate_provider_details:
        findings.append(
            finding(
                "model_provider.duplicate_provider_details",
                posture_severity,
                "review_required",
                "Future model-backed config duplicates provider/model details without referencing a central model role.",
                source=item.get("source"),
                related_refs=[item],
            )
        )

    for item in tool_bindings:
        role_name = str(item.get("role"))
        source = str(item.get("source"))
        provider_kind = str(item.get("provider_kind") or "")
        binding_active = bool_value(item.get("enabled")) or bool_value(item.get("provider_declared")) or bool_value(item.get("model_declared"))

        if not bool_value(item.get("tool_known")):
            findings.append(
                finding(
                    "model_provider.unknown_tool_binding",
                    posture_severity,
                    "review_required",
                    f"Tool binding `{item.get('tool')}` is not listed in tool_binding_policy.allowed_tools.",
                    role=role_name,
                    source=source,
                )
            )

        if bool_value(item.get("mutation_allowed")):
            findings.append(
                finding(
                    "model_provider.tool_binding_mutation_enabled",
                    "blocking",
                    "blocked",
                    f"Tool binding `{source}` allows tool or IDE configuration mutation; this candidate is declaration review only.",
                    role=role_name,
                    source=source,
                )
            )

        if not bool_value(item.get("role_declared")):
            findings.append(
                finding(
                    "model_provider.tool_binding_missing_role",
                    posture_severity,
                    "review_required",
                    f"Tool binding `{source}` references undeclared model role `{role_name}`.",
                    role=role_name,
                    source=source,
                )
            )

        if provider_kind and provider_kind not in ALLOWED_PROVIDER_KINDS:
            findings.append(
                finding(
                    "model_provider.tool_binding_invalid_provider_kind",
                    posture_severity,
                    "review_required",
                    f"Tool binding `{source}` uses unsupported provider_kind `{provider_kind}`.",
                    role=role_name,
                    source=source,
                )
            )

        if binding_active and provider_kind in {"cloud_api", "local_api", "managed_platform", "proxy"}:
            if not bool_value(item.get("provider_declared")):
                findings.append(
                    finding(
                        "model_provider.tool_binding_missing_metadata",
                        posture_severity,
                        "review_required",
                        f"Tool binding `{source}` is missing provider.",
                        role=role_name,
                        source=source,
                    )
                )
            if not bool_value(item.get("model_declared")):
                findings.append(
                    finding(
                        "model_provider.tool_binding_missing_metadata",
                        posture_severity,
                        "review_required",
                        f"Tool binding `{source}` is missing model.",
                        role=role_name,
                        source=source,
                    )
                )
            if require_cost_tier and not declared_value(item.get("cost_tier")):
                findings.append(
                    finding(
                        "model_provider.tool_binding_missing_cost_metadata",
                        posture_severity,
                        "review_required",
                        f"Tool binding `{source}` is missing cost_tier.",
                        role=role_name,
                        source=source,
                    )
                )
            if require_data_exposure and not declared_value(item.get("data_exposure_level")):
                findings.append(
                    finding(
                        "model_provider.tool_binding_missing_data_metadata",
                        posture_severity,
                        "review_required",
                        f"Tool binding `{source}` is missing data_exposure_level.",
                        role=role_name,
                        source=source,
                    )
                )

        if declared_value(item.get("cost_tier")) and str(item.get("cost_tier")) not in allowed_cost_tiers:
            findings.append(
                finding(
                    "model_provider.tool_binding_invalid_cost_tier",
                    posture_severity,
                    "review_required",
                    f"Tool binding `{source}` uses unsupported cost_tier `{item.get('cost_tier')}`.",
                    role=role_name,
                    source=source,
                )
            )

        if declared_value(item.get("data_exposure_level")) and str(item.get("data_exposure_level")) not in allowed_data_levels:
            findings.append(
                finding(
                    "model_provider.tool_binding_invalid_data_exposure_level",
                    posture_severity,
                    "review_required",
                    f"Tool binding `{source}` uses unsupported data_exposure_level `{item.get('data_exposure_level')}`.",
                    role=role_name,
                    source=source,
                )
            )

        if bool_value(item.get("alias_allowed")) or looks_like_alias(item.get("model")) or looks_like_alias(item.get("model_version")) or looks_like_alias(item.get("model_alias")):
            findings.append(
                finding(
                    "model_provider.tool_binding_alias_review_required",
                    alias_severity(model_policy, profile, posture),
                    "review_required",
                    f"Tool binding `{source}` allows or uses alias/latest/preview/experimental model posture.",
                    role=role_name,
                    source=source,
                )
            )

        for env_field in ("api_key_env", "base_url_env", "endpoint_env"):
            if invalid_env_reference(item.get(env_field)):
                findings.append(
                    finding(
                        "model_provider.tool_binding_env_reference_review",
                        posture_severity,
                        "review_required",
                        f"Tool binding `{source}` field `{env_field}` should contain an environment variable name, not a literal value.",
                        role=role_name,
                        source=source,
                    )
                )

        if provider_kind == "local_api" and local_url_is_public(item.get("base_url")):
            findings.append(
                finding(
                    "model_provider.tool_binding_local_endpoint_exposure_review",
                    posture_severity,
                    "review_required",
                    f"Tool binding `{source}` declares a non-local literal base_url for a local_api provider.",
                    role=role_name,
                    source=source,
                )
            )

    for role_name, items in sorted(cross_tool_drift_roles(tool_bindings).items()):
        if all(bool_value(item.get("has_rationale")) for item in items):
            continue
        findings.append(
            finding(
                "model_provider.cross_tool_model_drift",
                posture_severity,
                "review_required",
                f"Model role `{role_name}` has different active model/reasoning-effort/provider/cost/data declarations across tools without explicit alignment rationale.",
                role=role_name,
                related_refs=[{key: item.get(key) for key in ("tool", "source", "provider_kind", "provider", "model", "model_version", "reasoning_effort", "cost_tier", "data_exposure_level")} for item in items],
            )
        )

    return findings


def report_status(policy_source: str, profile: str, findings: list[dict[str, Any]]) -> str:
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if any(item.get("severity") == "required" for item in findings):
        return "review_required"
    if any(item.get("severity") == "warning" for item in findings):
        return "warning"
    if findings:
        return "advisory"
    if policy_source == "template" and profile in {"standard", "assured"}:
        return "not_configured"
    return "declaration_only"


def build_report(root: Path, naos_root: str, profile: str, governance_policy: dict[str, Any], policy_path: Path, policy_source: str) -> dict[str, Any]:
    model_policy = load_yaml_mapping(policy_path)
    roles = {str(key): as_mapping(value) for key, value in as_mapping(model_policy.get("roles")).items()}
    references, duplicate_provider_details, agent_role_gaps = collect_role_references(root, naos_root)
    tool_bindings = collect_tool_model_bindings(model_policy, roles)
    posture = profile_posture(model_policy, profile)
    findings = build_findings(
        model_policy,
        profile,
        posture,
        policy_source,
        roles,
        references,
        duplicate_provider_details,
        agent_role_gaps,
        tool_bindings,
    )
    summary = finding_counts(findings)
    agent_refs = [ref for ref in references if ref.get("source") == "agent_frontmatter"]
    summary.update(
        {
            "roles_declared": len(roles),
            "roles_referenced": len({ref.get("role") for ref in references if ref.get("role")}),
            "agent_role_refs": len(agent_refs),
            "agent_role_gaps": len(agent_role_gaps),
            "tool_role_bindings": len(tool_bindings),
            "active_tool_role_bindings": sum(1 for item in tool_bindings if bool_value(item.get("enabled"))),
            "runtime_enabled": bool_value(model_policy.get("runtime_enabled")),
            "provider_calls_allowed": bool_value(model_policy.get("provider_calls_allowed")),
            "credentials_allowed_in_repo": bool_value(model_policy.get("credentials_allowed_in_repo")),
        }
    )
    active = active_role_names(roles, references)
    referenced_role_names = {str(ref.get("role")) for ref in references if ref.get("role")}
    status = report_status(policy_source, profile, findings)

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "policy_path": str(policy_path),
        "policy_source": policy_source,
        "policy_hash": safe_digest(policy_path),
        "enabled": bool_value(model_policy.get("enabled"), True),
        "runtime_enabled": bool_value(model_policy.get("runtime_enabled")),
        "provider_calls_allowed": bool_value(model_policy.get("provider_calls_allowed")),
        "credentials_allowed_in_repo": bool_value(model_policy.get("credentials_allowed_in_repo")),
        "profile_posture": posture,
        "default_alias_policy": as_mapping(model_policy.get("default_alias_policy")),
        "roles": [role_summary(name, role, name in referenced_role_names) for name, role in sorted(roles.items())],
        "referenced_roles": references,
        "agent_role_coverage": {
            "agent_files": len(agent_refs) + len(agent_role_gaps),
            "agent_role_refs": len(agent_refs),
            "agent_role_gaps": len(agent_role_gaps),
            "gaps": agent_role_gaps,
        },
        "duplicate_provider_detail_refs": duplicate_provider_details,
        "tool_model_bindings": tool_bindings,
        "tool_binding_counts": tool_binding_counts(model_policy, tool_bindings),
        "provider_kind_counts": dict(Counter(str(role.get("provider_kind") or "undeclared") for role in roles.values())),
        "findings": findings,
        "known_gaps": [
            "No provider/model runtime routing is implemented by this report.",
            "No provider catalogs, pricing tables, regional availability checks, or model recommendations are maintained by this report.",
            "Agent host-tool model strings and external tool settings are not rewritten by this report; central role and tool-binding metadata is review evidence only.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings) or bool_value(posture.get("human_review_required")),
        "summary": summary,
    }


def missing_report(root: Path, naos_root: str, profile: str, policy_path: Path) -> dict[str, Any]:
    findings = [
        finding(
            "model_provider.policy_missing",
            "advisory" if profile in {"quickstart", "lite"} else "required",
            "not_configured",
            "Model-provider policy seed is missing.",
        )
    ]
    summary = finding_counts(findings)
    summary.update(
        {
            "roles_declared": 0,
            "roles_referenced": 0,
            "agent_role_refs": 0,
            "agent_role_gaps": 0,
            "tool_role_bindings": 0,
            "active_tool_role_bindings": 0,
            "runtime_enabled": False,
            "provider_calls_allowed": False,
            "credentials_allowed_in_repo": False,
        }
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": "not_configured",
        "naos_root": naos_root,
        "project_root": str(root),
        "policy_path": str(policy_path),
        "policy_source": "missing",
        "policy_hash": None,
        "enabled": False,
        "runtime_enabled": False,
        "provider_calls_allowed": False,
        "credentials_allowed_in_repo": False,
        "profile_posture": {},
        "default_alias_policy": {},
        "roles": [],
        "referenced_roles": [],
        "agent_role_coverage": {
            "agent_files": 0,
            "agent_role_refs": 0,
            "agent_role_gaps": 0,
            "gaps": [],
        },
        "duplicate_provider_detail_refs": [],
        "tool_model_bindings": [],
        "tool_binding_counts": {
            "tools_declared": 0,
            "role_bindings_declared": 0,
            "active_role_bindings": 0,
            "unknown_tools": 0,
            "mutation_allowed": 0,
            "cross_tool_drift_roles": 0,
        },
        "provider_kind_counts": {},
        "findings": findings,
        "known_gaps": ["Model-provider policy seed is missing."],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": profile in {"standard", "assured"},
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate model-provider policy declarations without provider calls.")
    parser.add_argument("--profile", default=None, choices=["quickstart", "lite", "standard", "assured"])
    parser.add_argument("--naos-root", default=None)
    parser.add_argument("--policy", default=None, help="Optional NAOS governance policy path.")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--model-policy", default=None, help="Optional explicit model_provider_policy.yaml path.")
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.project_root).resolve()
    governance_policy = load_policy(explicit_policy=args.policy, root=root)
    profile = normalize_profile(args.profile, governance_policy)
    naos_root = args.naos_root or default_naos_root(governance_policy)
    policy_path, policy_source = resolve_model_policy_path(root, naos_root, governance_policy, args.model_policy)

    try:
        report = build_report(root, naos_root, profile, governance_policy, policy_path, policy_source)
    except FileNotFoundError:
        report = missing_report(root, naos_root, profile, policy_path)

    output = Path(args.output) if args.output else report_output_path(root, naos_root, governance_policy, "model_provider_policy_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        target = f" -> {output}" if output else ""
        print(
            "NAOS model-provider policy: "
            f"{report['status']} "
            f"(runtime_enabled={report['runtime_enabled']}, "
            f"provider_calls_allowed={report['provider_calls_allowed']})"
            f"{target}"
        )
    return exit_code_for_summary(profile, report.get("summary", {}), governance_policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
