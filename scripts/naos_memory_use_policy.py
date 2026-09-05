#!/usr/bin/env python3
"""Evaluate governed memory-use policy from declared review metadata only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_now_utc,
    controlled_utc_now_text,
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

try:
    from naos_mcp_config_registry import config_descriptors  # noqa: E402
except ImportError:  # pragma: no cover - compatibility for older generated adopters
    config_descriptors = None  # type: ignore[assignment]


REPORT_SCHEMA = "naos.memory_use_policy.v1"
TRUST_STATES = {
    "raw_memory_candidate",
    "review_pending_memory",
    "rejected_memory",
    "superseded_memory",
    "supporting_context_memory",
    "instruction_grade_memory",
}
APPROVED_STATUSES = {"approved", "approved_with_limits"}
FORBIDDEN_CATEGORIES = {
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
FORBIDDEN_CATEGORY_BY_NORMALIZED = {
    value.strip().casefold(): value for value in FORBIDDEN_CATEGORIES
}
NOT_CLAIMED = [
    "memory source of truth",
    "memory as source of truth",
    "memory as evidence",
    "memory as approval",
    "legal or regulatory approval",
    "compliance proof",
    "hallucination prevention",
    "automatic memory write-back",
    "live recall trace execution",
    "runtime audit-event capture",
    "cloud memory by default",
]
USE_GRADE_MEMORY_STATES = {"supporting_context_memory", "instruction_grade_memory"}
ALLOWED_MEMORY_SCOPES = {
    "project_local",
    "cross_project",
    "organization_level",
    "shared",
    "personal_operator_preference",
}
SOURCE_REFERENCE_LOCATORS = {
    "task_card": {"task_id", "source_path", "path", "reference"},
    "task_registry": {"task_id", "source_path", "path", "reference"},
    "spec": {"source_path", "path", "reference"},
    "capability_card": {"source_path", "path", "reference", "evidence_id"},
    "module_header": {"source_path", "path", "reference"},
    "source_file": {"source_path", "path", "reference"},
    "test_evidence": {"source_path", "path", "report_path", "reference", "evidence_id"},
    "deterministic_report": {"source_path", "path", "report_path", "reference", "evidence_id"},
    "evidence_pack": {"path", "report_path", "reference", "evidence_id"},
    "dashboard": {"path", "report_path", "reference"},
    "known_gap": {"source_path", "path", "reference", "evidence_id"},
    "residual_risk": {"source_path", "path", "reference", "evidence_id"},
    "waiver": {"source_path", "path", "reference", "evidence_id"},
    "control_plane_review_item": {"source_path", "path", "reference", "evidence_id"},
}
UPSTREAM_REPORT_SPECS = {
    "memory_context_readiness": {
        "policy_key": "memory_context_readiness_report",
        "filename": "memory_context_readiness.json",
        "schema": "naos.memory_context_readiness.v1",
        "schema_file": "memory_context_readiness.schema.json",
    },
    "memory_provider_access": {
        "policy_key": "memory_provider_access_report",
        "filename": "memory_provider_access.json",
        "schema": "naos.memory_provider_access.v1",
        "schema_file": "memory_provider_access.schema.json",
    },
}


def utc_now_text() -> str:
    return controlled_utc_now_text()


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if str(item).strip()]


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return value if isinstance(value, bool) else default


def dedupe_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value).strip()))


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


def load_json_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def upstream_report_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    report_key: str,
    explicit: str | None,
) -> Path:
    if explicit:
        return Path(explicit)
    spec = UPSTREAM_REPORT_SPECS[report_key]
    configured = report_output_path(root, naos_root, policy, str(spec["policy_key"]))
    if configured is not None:
        return configured
    filename = str(policy.get("paths", {}).get(spec["policy_key"]) or spec["filename"])
    return root / naos_root / "reports" / filename


def _candidate_input_path(root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.startswith(("~", "$", "<")):
        return None
    path = Path(text)
    return path if path.is_absolute() else root / path


def _registered_config_paths(root: Path) -> list[Path]:
    if config_descriptors is None:
        relative_paths = [".vscode/mcp.json", ".cursor/mcp.json", ".mcp.json", ".ai/mcp.json", "mcp.json"]
        return [root / relative for relative in relative_paths]
    paths: list[Path] = []
    for descriptor in config_descriptors(include_user=True, include_client_policy=False):
        if descriptor.scope == "workspace":
            paths.append(root / descriptor.path)
        elif descriptor.path.startswith("~/"):
            paths.append(Path.home() / descriptor.path[2:])
    return paths


def _declared_upstream_inputs(root: Path, report: dict[str, Any]) -> list[Path]:
    candidates: list[Path] = [
        root / "configs" / "naos_memory.yaml",
        root / "naos" / "configs" / "naos_memory.yaml",
        *_registered_config_paths(root),
    ]
    for key in ("rules_path", "memory_rules_path", "authorization_matrix_path", "memory_config_path"):
        if path := _candidate_input_path(root, report.get(key)):
            candidates.append(path)
    for key in ("rules", "authorization_matrix"):
        nested = report.get(key)
        if isinstance(nested, dict) and (path := _candidate_input_path(root, nested.get("path"))):
            candidates.append(path)
    for item in as_list(report.get("mcp_config_files_detected")):
        raw_path = item.get("path") if isinstance(item, dict) else item
        if path := _candidate_input_path(root, raw_path):
            candidates.append(path)
    unique: dict[str, Path] = {}
    for candidate in candidates:
        unique[str(candidate)] = candidate
    return list(unique.values())


def inspect_upstream_report(
    *,
    root: Path,
    profile: str,
    report_key: str,
    path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = UPSTREAM_REPORT_SPECS[report_key]
    report = load_json_mapping(path)
    present = path.is_file()
    validation_reasons: list[str] = []
    if not present:
        validation_reasons.append("report_missing")
    elif not report:
        validation_reasons.append("report_not_json_mapping")

    schema_errors = 0
    schema_path = kit_root() / "schemas" / "naos" / str(spec["schema_file"])
    if report and schema_path.is_file():
        schema = load_json_mapping(schema_path)
        schema_errors = sum(1 for _ in Draft202012Validator(schema).iter_errors(report)) if schema else 1
        if schema_errors:
            validation_reasons.append("schema_invalid")
    else:
        schema_errors = 1
        if present:
            validation_reasons.append("schema_unavailable")

    schema_match = report.get("schema") == spec["schema"]
    if report and not schema_match:
        validation_reasons.append("schema_identity_mismatch")
    try:
        project_match = Path(str(report.get("project_root") or "")).resolve() == root.resolve()
    except (OSError, RuntimeError, ValueError):
        project_match = False
    if report and not project_match:
        validation_reasons.append("project_root_mismatch")
    profile_match = report.get("profile") == profile
    if report and not profile_match:
        validation_reasons.append("profile_mismatch")

    freshness_status = "not_evaluated"
    newer_inputs: list[str] = []
    if present and report and not validation_reasons:
        try:
            report_mtime = path.stat().st_mtime_ns
            for candidate in _declared_upstream_inputs(root, report):
                if candidate.is_file() and candidate.stat().st_mtime_ns > report_mtime:
                    try:
                        newer_inputs.append(str(candidate.resolve().relative_to(root.resolve())))
                    except ValueError:
                        try:
                            newer_inputs.append(f"~/{candidate.resolve().relative_to(Path.home().resolve())}")
                        except ValueError:
                            newer_inputs.append("<external-input-redacted>")
            freshness_status = "stale" if newer_inputs else "no_newer_declared_inputs_detected"
            if newer_inputs:
                validation_reasons.append("newer_declared_input_detected")
        except OSError:
            freshness_status = "unverifiable"
            validation_reasons.append("freshness_unverifiable")

    accepted = bool(report) and not validation_reasons
    summary = {
        "path": str(path),
        "present": present,
        "schema_valid": schema_errors == 0 and schema_match,
        "schema_error_count": schema_errors,
        "project_root_match": project_match,
        "profile_match": profile_match,
        "freshness_status": freshness_status,
        "newer_declared_inputs": sorted(newer_inputs),
        "accepted_for_join": accepted,
        "validation_reasons": list(dict.fromkeys(validation_reasons)),
        "reported_status": report.get("status") if report else None,
    }
    return report, summary


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_use_policy_rules.yaml"


def default_review_items_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "memory_review_items.yaml"


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


def profile_posture(rules: dict[str, Any], profile: str) -> dict[str, Any]:
    posture = as_mapping(rules.get("profile_posture"))
    item = posture.get(profile)
    if isinstance(item, dict):
        return item
    defaults = {
        "quickstart": {"state": "disabled", "severity": "advisory", "human_review_required_if_review_items_exist": False},
        "lite": {"state": "readiness_only", "severity": "advisory", "human_review_required_if_review_items_exist": False},
        "standard": {"state": "readiness_only", "severity": "review_required", "human_review_required_if_review_items_exist": True},
        "assured": {"state": "readiness_only", "severity": "review_required", "human_review_required_if_review_items_exist": True},
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


def mapping_entries(value: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entries = as_list(value)
    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for index, item in enumerate(entries):
        if isinstance(item, dict):
            valid.append(item)
        else:
            invalid.append({"index": index, "value_type": type(item).__name__})
    return valid, invalid


def load_review_items(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "memory_review_items": [],
            "recall_traces": [],
            "audit_events": [],
            "_malformed_entries": {},
            "_missing": True,
        }
    data = load_yaml_mapping(path)
    memory_review_items, malformed_items = mapping_entries(data.get("memory_review_items"))
    recall_traces, malformed_traces = mapping_entries(data.get("recall_traces"))
    audit_events, malformed_events = mapping_entries(data.get("audit_events"))
    return {
        **data,
        "memory_review_items": memory_review_items,
        "recall_traces": recall_traces,
        "audit_events": audit_events,
        "_malformed_entries": {
            key: entries
            for key, entries in {
                "memory_review_items": malformed_items,
                "recall_traces": malformed_traces,
                "audit_events": malformed_events,
            }.items()
            if entries
        },
        "_missing": False,
    }


def item_id(item: dict[str, Any], index: int) -> str:
    return str(item.get("memory_reference_id") or item.get("id") or f"memory_item_{index + 1}")


def forbidden_category_map(rules: dict[str, Any] | None = None) -> dict[str, str]:
    result = dict(FORBIDDEN_CATEGORY_BY_NORMALIZED)
    if rules is not None:
        for value in string_list(rules.get("forbidden_memory_categories")):
            stripped = value.strip()
            if stripped:
                result[stripped.casefold()] = stripped
    return result


def forbidden_category_hits(
    item: dict[str, Any],
    rules: dict[str, Any] | None = None,
) -> list[str]:
    forbidden = forbidden_category_map(rules)
    normalized = {
        value.strip().casefold()
        for value in string_list(item.get("categories"))
        + string_list(item.get("forbidden_categories"))
        if value.strip()
    }
    return sorted(
        forbidden[value]
        for value in normalized
        if value in forbidden
    )


def safe_item_summary(
    item: dict[str, Any],
    index: int,
    rules: dict[str, Any] | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    source_refs = as_list(item.get("source_references"))
    return {
        "memory_reference_id": item_id(item, index),
        "title": item.get("title"),
        "state": item.get("state"),
        "scope": item.get("scope"),
        "project_scope": item.get("project_scope"),
        "review_status": item.get("review_status"),
        "reviewer": item.get("reviewer"),
        "reviewed_at": item.get("reviewed_at"),
        "expires_at": item.get("expires_at"),
        "freshness_status": item.get("freshness_status"),
        "source_reference_count": len(source_refs),
        "has_provenance": bool(item.get("provenance")),
        "confidence": item.get("confidence"),
        "limitations_count": len(as_list(item.get("limitations"))),
        "can_use_as_context": bool_value(item.get("can_use_as_context")),
        "can_use_as_supporting_evidence": bool_value(item.get("can_use_as_supporting_evidence")),
        "can_use_as_instruction": bool_value(item.get("can_use_as_instruction")),
        "requires_user_confirmation": bool_value(item.get("requires_user_confirmation")),
        "allowed_profiles": string_list(item.get("allowed_profiles")),
        "profile_allowed": (
            profile in string_list(item.get("allowed_profiles"))
            if profile is not None and string_list(item.get("allowed_profiles"))
            else True
        ),
        "allowed_agents": string_list(item.get("allowed_agents")),
        "allowed_agents_evaluated": not bool(string_list(item.get("allowed_agents"))),
        "allowed_surfaces": string_list(item.get("allowed_surfaces")),
        "allowed_surfaces_evaluated": not bool(string_list(item.get("allowed_surfaces"))),
        "forbidden_uses": string_list(item.get("forbidden_uses")),
        "forbidden_category_hits": forbidden_category_hits(item, rules),
    }


def approved_statuses(rules: dict[str, Any]) -> set[str]:
    values = set(string_list(rules.get("approved_review_statuses")))
    return values or APPROVED_STATUSES


def has_source_refs(item: dict[str, Any], rules: dict[str, Any] | None = None) -> bool:
    raw_references = as_list(item.get("source_references"))
    references = [ref for ref in raw_references if isinstance(ref, dict)]
    if not references or len(references) != len(raw_references):
        return False
    if rules is None:
        return bool(references)
    allowed = set(string_list(as_mapping(rules.get("source_reference_policy")).get("allowed_source_types")))
    for ref in references:
        source_type = ref.get("source_type")
        if not isinstance(source_type, str) or source_type.strip() not in allowed:
            return False
        locator_fields = SOURCE_REFERENCE_LOCATORS.get(source_type.strip(), set())
        if not locator_fields or not any(
            isinstance(ref.get(field), str) and bool(ref[field].strip())
            for field in locator_fields
        ):
            return False
    return True


def has_scope(item: dict[str, Any]) -> bool:
    return str(item.get("scope") or "").strip() in ALLOWED_MEMORY_SCOPES


def parse_iso_datetime(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def current_datetime() -> datetime:
    return controlled_now_utc()


def reviewed_at_is_valid(item: dict[str, Any]) -> bool:
    reviewed = parse_iso_datetime(item.get("reviewed_at"))
    return reviewed is not None and reviewed <= current_datetime()


def has_freshness_or_expiry(item: dict[str, Any], rules: dict[str, Any]) -> bool:
    policy = as_mapping(rules.get("expiry_freshness_policy"))
    freshness = str(item.get("freshness_status") or "").strip()
    allowed = set(string_list(policy.get("allowed_freshness_statuses"))) or {"fresh", "recent"}
    if (
        freshness
        and freshness not in allowed
        and not bool_value(policy.get("stale_or_unknown_instruction_allowed"))
    ):
        return False
    expiry_text = str(item.get("expires_at") or "").strip()
    expiry = parse_iso_datetime(expiry_text)
    if expiry_text:
        if expiry is None:
            return False
        now = current_datetime()
        if "T" not in expiry_text and " " not in expiry_text:
            if expiry.date() < now.date():
                return False
        elif expiry < now:
            return False
    return freshness in allowed or expiry is not None


def provenance_is_valid(item: dict[str, Any], rules: dict[str, Any]) -> bool:
    allowed = set(string_list(as_mapping(rules.get("provenance_policy")).get("accepted_values")))
    return str(item.get("provenance") or "").strip() in allowed


def confidence_is_valid(item: dict[str, Any], rules: dict[str, Any], *, instruction: bool) -> bool:
    policy = as_mapping(rules.get("confidence_policy"))
    confidence = str(item.get("confidence") or "").strip()
    allowed = set(string_list(policy.get("allowed_values")))
    if confidence not in allowed:
        return False
    return not (instruction and confidence == "unknown" and not bool_value(policy.get("unknown_confidence_allows_instruction")))


def cross_project_scope(item: dict[str, Any]) -> bool:
    return shared_scope(item) and not str(item.get("project_scope") or "").strip()


def shared_scope(item: dict[str, Any]) -> bool:
    scope = str(item.get("scope") or "").strip()
    return scope in {"organization_level", "cross_project", "shared", "personal_operator_preference"}


def item_claims_memory_truth(item: dict[str, Any]) -> bool:
    encoded = json.dumps(item, sort_keys=True).lower()
    phrases = [
        "memory source of truth",
        "memory as source of truth",
        "memory is source of truth",
        "memory is the source of truth",
    ]
    return any(phrase in encoded for phrase in phrases) or bool(item.get("memory_is_source_of_truth"))


def evaluate_items(
    items: list[dict[str, Any]],
    rules: dict[str, Any],
    severity: str,
    profile: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    approved = approved_statuses(rules)
    summaries = [safe_item_summary(item, index, rules, profile) for index, item in enumerate(items)]
    unsafe_instruction: list[dict[str, Any]] = []
    unsafe_supporting: list[dict[str, Any]] = []

    for index, item in enumerate(items):
        memory_id = item_id(item, index)
        state = str(item.get("state") or "").strip()
        review_status = str(item.get("review_status") or "").strip()
        can_instruction = bool_value(item.get("can_use_as_instruction"))
        can_support = bool_value(item.get("can_use_as_supporting_evidence"))
        can_context = bool_value(item.get("can_use_as_context"))
        forbidden_hits = forbidden_category_hits(item, rules)
        allowed_profiles = string_list(item.get("allowed_profiles"))
        allowed_agents = string_list(item.get("allowed_agents"))
        allowed_surfaces = string_list(item.get("allowed_surfaces"))
        allowed_policy_states = set(string_list(rules.get("allowed_memory_states")))

        if state not in allowed_policy_states:
            findings.append(
                finding(
                    f"{memory_id}_state_not_allowed_by_policy",
                    "blocking",
                    "blocked",
                    "Memory item state is not enabled by allowed_memory_states.",
                    ["Use a state explicitly allowed by the reviewed memory-use policy."],
                    memory_reference_id=memory_id,
                    state=state,
                )
            )
        if not has_scope(item):
            findings.append(
                finding(
                    f"{memory_id}_scope_invalid",
                    "blocking" if state in USE_GRADE_MEMORY_STATES else severity,
                    "blocked" if state in USE_GRADE_MEMORY_STATES else "review_required",
                    "Memory item scope is missing or outside the supported scope vocabulary.",
                    ["Use an explicit supported scope; do not encode shared scope with an unrecognized spelling."],
                    memory_reference_id=memory_id,
                    declared_scope=item.get("scope"),
                )
            )

        if allowed_profiles and profile not in allowed_profiles:
            findings.append(
                finding(
                    f"{memory_id}_profile_not_allowed",
                    "blocking",
                    "blocked",
                    "Memory item is not allowed for the current NAOS profile.",
                    ["Add the reviewed profile explicitly or do not use this memory item in the current profile."],
                    memory_reference_id=memory_id,
                    current_profile=profile,
                    allowed_profiles=allowed_profiles,
                )
            )
        if allowed_agents:
            findings.append(
                finding(
                    f"{memory_id}_agent_scope_not_evaluated",
                    severity,
                    "review_required",
                    "Memory item restricts allowed agents, but this report has no active-agent identity input.",
                    ["Evaluate the declared agent restriction in an authorized runtime before using this item."],
                    memory_reference_id=memory_id,
                    allowed_agents=allowed_agents,
                )
            )
        if allowed_surfaces:
            findings.append(
                finding(
                    f"{memory_id}_surface_scope_not_evaluated",
                    severity,
                    "review_required",
                    "Memory item restricts allowed surfaces, but this report has no active-surface identity input.",
                    ["Evaluate the declared surface restriction in an authorized runtime before using this item."],
                    memory_reference_id=memory_id,
                    allowed_surfaces=allowed_surfaces,
                )
            )

        expected_use_flags = {
            str(row.get("state") or ""): {
                key: row.get(key)
                for key in (
                    "can_use_as_context",
                    "can_use_as_supporting_evidence",
                    "can_use_as_instruction",
                )
            }
            for row in as_list(rules.get("memory_trust_ladder"))
            if isinstance(row, dict) and str(row.get("state") or "")
        }.get(state)
        if expected_use_flags is not None:
            mismatched_flags = [
                key
                for key, expected in expected_use_flags.items()
                if not isinstance(expected, bool) or item.get(key) is not expected
            ]
            if mismatched_flags:
                unsafe_true = any(
                    item.get(key) is True and expected_use_flags.get(key) is False
                    for key in mismatched_flags
                )
                findings.append(
                    finding(
                        f"{memory_id}_state_use_flags_incoherent",
                        "blocking" if unsafe_true else severity,
                        "blocked" if unsafe_true else "review_required",
                        "Memory item use flags do not exactly match its declared trust-ladder state.",
                        ["Use explicit Boolean flags matching the selected memory trust-ladder state."],
                        memory_reference_id=memory_id,
                        mismatched_flags=mismatched_flags,
                        expected_flags=expected_use_flags,
                    )
                )

        if state not in TRUST_STATES:
            findings.append(
                finding(
                    f"{memory_id}_unknown_state",
                    severity,
                    "unknown",
                    "Memory review item declares an unsupported trust-ladder state.",
                    ["Use one of the allowed memory trust ladder states."],
                    memory_reference_id=memory_id,
                )
            )

        if not as_list(item.get("limitations")):
            findings.append(
                finding(
                    f"{memory_id}_limitations_missing",
                    severity,
                    "review_required",
                    "Memory review item is missing limitations.",
                    ["Add explicit limitations before relying on this memory reference."],
                    memory_reference_id=memory_id,
                )
            )

        if forbidden_hits:
            findings.append(
                finding(
                    f"{memory_id}_forbidden_category",
                    "blocking",
                    "blocked",
                    "Memory review item declares a forbidden memory category.",
                    ["Remove the item or record a human-approved exception outside default NAOS behavior."],
                    memory_reference_id=memory_id,
                    categories=forbidden_hits,
                )
            )

        if cross_project_scope(item):
            findings.append(
                finding(
                    f"{memory_id}_cross_project_scope",
                    severity,
                    "review_required",
                    "Cross-project memory requires an explicit project scope.",
                    ["Add project_scope and human review before using shared memory context."],
                    memory_reference_id=memory_id,
                )
            )

        cross_project_instruction_denied = (
            state == "instruction_grade_memory"
            and shared_scope(item)
            and not bool_value(
                as_mapping(rules.get("cross_project_memory_policy")).get(
                    "cross_project_instruction_grade_allowed_by_default"
                )
            )
        )
        if cross_project_instruction_denied:
            findings.append(
                finding(
                    f"{memory_id}_cross_project_instruction_not_allowed",
                    "blocking",
                    "blocked",
                    "Cross-project instruction-grade memory is disabled by default policy.",
                    ["Do not use the item as instruction without a separately reviewed policy exception."],
                    memory_reference_id=memory_id,
                )
            )

        if item_claims_memory_truth(item):
            findings.append(
                finding(
                    f"{memory_id}_memory_source_of_truth",
                    "blocking",
                    "blocked",
                    "Memory review item contains memory-as-source-of-truth wording.",
                    ["Rewrite the item so repository evidence remains authoritative."],
                    memory_reference_id=memory_id,
                )
            )

        if state == "rejected_memory" and (can_context or can_support or can_instruction):
            findings.append(
                finding(
                    f"{memory_id}_rejected_memory_marked_usable",
                    "blocking",
                    "blocked",
                    "Rejected memory is marked usable.",
                    ["Set all use flags to false; rejected memory may remain audit history only."],
                    memory_reference_id=memory_id,
                )
            )

        if state == "superseded_memory" and can_instruction:
            findings.append(
                finding(
                    f"{memory_id}_superseded_memory_instruction",
                    "blocking",
                    "blocked",
                    "Superseded memory is marked instruction-grade.",
                    ["Use the replacement memory reference, not the superseded item."],
                    memory_reference_id=memory_id,
                )
            )
        if state == "superseded_memory" and not as_list(item.get("superseded_by")):
            findings.append(
                finding(
                    f"{memory_id}_superseded_by_missing",
                    severity,
                    "review_required",
                    "Superseded memory does not declare superseded_by.",
                    ["Link the replacement memory reference."],
                    memory_reference_id=memory_id,
                )
            )

        if can_instruction or state == "instruction_grade_memory":
            problems: list[str] = []
            checks = [
                (state == "instruction_grade_memory", "state must be instruction_grade_memory"),
                (review_status in approved, "approved review status required"),
                (bool(str(item.get("reviewer") or "").strip()), "reviewer required"),
                (reviewed_at_is_valid(item), "valid non-future reviewed_at required"),
                (has_source_refs(item, rules), "valid source references required"),
                (provenance_is_valid(item, rules), "accepted provenance required"),
                (has_scope(item), "explicit scope required"),
                (has_freshness_or_expiry(item, rules), "valid unexpired expiry or fresh/recent status required"),
                (isinstance(item.get("requires_user_confirmation"), bool), "requires_user_confirmation must be boolean"),
                (item.get("requires_user_confirmation") is True, "human confirmation boundary required"),
                (confidence_is_valid(item, rules, instruction=True), "allowed non-unknown confidence required"),
                (bool(as_list(item.get("limitations"))), "limitations required"),
                (not allowed_profiles or profile in allowed_profiles, "current profile is not allowed"),
                (not allowed_agents, "allowed-agent restriction cannot be evaluated"),
                (not allowed_surfaces, "allowed-surface restriction cannot be evaluated"),
                (item.get("can_use_as_context") is True, "can_use_as_context must be boolean true"),
                (
                    item.get("can_use_as_supporting_evidence") is True,
                    "can_use_as_supporting_evidence must be boolean true",
                ),
                (item.get("can_use_as_instruction") is True, "can_use_as_instruction must be boolean true"),
                (not forbidden_hits, "forbidden categories are not allowed"),
                (not cross_project_instruction_denied, "cross-project instruction is not allowed by default"),
                (state not in {"raw_memory_candidate", "review_pending_memory", "rejected_memory", "superseded_memory"}, "raw/pending/rejected/superseded memory cannot be instruction-grade"),
            ]
            problems = [message for ok, message in checks if not ok]
            if problems:
                unsafe = safe_item_summary(item, index, rules, profile)
                unsafe["problems"] = problems
                unsafe_instruction.append(unsafe)
                for problem in problems:
                    suffix = problem.split(" required")[0].replace("/", "_").replace(" ", "_").replace("-", "_")
                    findings.append(
                        finding(
                            f"{memory_id}_instruction_grade_{suffix}",
                            "blocking" if state in {"rejected_memory", "superseded_memory"} or forbidden_hits else severity,
                            "blocked" if state in {"rejected_memory", "superseded_memory"} or forbidden_hits else "review_required",
                            f"Instruction-grade memory requirement failed: {problem}.",
                            ["Do not use this memory as instruction until the requirement is satisfied."],
                            memory_reference_id=memory_id,
                        )
                    )

        if can_support or state == "supporting_context_memory":
            problems = []
            allowed_states = set(string_list(as_mapping(rules.get("supporting_context_requirements")).get("allowed_states"))) or {
                "supporting_context_memory",
                "instruction_grade_memory",
            }
            checks = [
                (state in allowed_states, "state must be reviewed supporting context or instruction-grade"),
                (review_status in approved, "approved review status required"),
                (bool(str(item.get("reviewer") or "").strip()), "reviewer required"),
                (reviewed_at_is_valid(item), "valid non-future reviewed_at required"),
                (has_source_refs(item, rules), "valid source references required"),
                (provenance_is_valid(item, rules), "accepted provenance required"),
                (confidence_is_valid(item, rules, instruction=False), "allowed confidence required"),
                (bool(as_list(item.get("limitations"))), "limitations required"),
                (not allowed_profiles or profile in allowed_profiles, "current profile is not allowed"),
                (not allowed_agents, "allowed-agent restriction cannot be evaluated"),
                (not allowed_surfaces, "allowed-surface restriction cannot be evaluated"),
                (item.get("can_use_as_context") is True, "can_use_as_context must be boolean true"),
                (
                    item.get("can_use_as_supporting_evidence") is True,
                    "can_use_as_supporting_evidence must be boolean true",
                ),
                (
                    item.get("can_use_as_instruction") is (state == "instruction_grade_memory"),
                    "can_use_as_instruction must match the declared use-grade state",
                ),
                (not forbidden_hits, "forbidden categories are not allowed"),
                (not cross_project_scope(item), "explicit project scope required for shared memory"),
                (not item_claims_memory_truth(item), "memory cannot be a source of truth"),
            ]
            problems = [message for ok, message in checks if not ok]
            if problems:
                unsafe = safe_item_summary(item, index, rules, profile)
                unsafe["problems"] = problems
                unsafe_supporting.append(unsafe)
                findings.append(
                    finding(
                        f"{memory_id}_supporting_context_requirements",
                        severity,
                        "review_required",
                        "Supporting-context memory is missing required review/provenance metadata.",
                        ["Add approved review status, source references, provenance, confidence, and limitations."],
                        memory_reference_id=memory_id,
                    )
                )

    return findings, {
        "summaries": summaries,
        "unsafe_instruction_grade_claims": unsafe_instruction,
        "unsafe_supporting_context_claims": unsafe_supporting,
    }


def evaluate_rules(rules: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    private_policy = as_mapping(rules.get("private_payload_policy"))
    write_policy = as_mapping(rules.get("memory_write_back_policy"))
    cloud_policy = as_mapping(rules.get("cloud_memory_policy"))
    ci_policy = as_mapping(rules.get("ci_memory_access_policy"))
    recall_policy = as_mapping(rules.get("recall_trace_readiness_policy"))
    audit_policy = as_mapping(rules.get("audit_event_readiness_policy"))
    expiry_policy = as_mapping(rules.get("expiry_freshness_policy"))
    cross_project_policy = as_mapping(rules.get("cross_project_memory_policy"))
    instruction_requirements = as_mapping(rules.get("instruction_grade_requirements"))
    supporting_requirements = as_mapping(rules.get("supporting_context_requirements"))
    source_policy = as_mapping(rules.get("source_reference_policy"))
    boolean_rules = {
        "private_payload_policy.read_private_memory_payloads": private_policy.get("read_private_memory_payloads"),
        "private_payload_policy.read_engram_db": private_policy.get("read_engram_db"),
        "private_payload_policy.index_private_payloads": private_policy.get("index_private_payloads"),
        "memory_write_back_policy.automatic_write_back_enabled": write_policy.get("automatic_write_back_enabled"),
        "memory_write_back_policy.durable_memory_writes_enabled": write_policy.get("durable_memory_writes_enabled"),
        "cloud_memory_policy.cloud_memory_enabled": cloud_policy.get("cloud_memory_enabled"),
        "cloud_memory_policy.external_sync_enabled": cloud_policy.get("external_sync_enabled"),
        "ci_memory_access_policy.memory_read_allowed": ci_policy.get("memory_read_allowed"),
        "ci_memory_access_policy.memory_write_allowed": ci_policy.get("memory_write_allowed"),
        "ci_memory_access_policy.mcp_access_allowed": ci_policy.get("mcp_access_allowed"),
        "recall_trace_readiness_policy.runtime_trace_execution_enabled": recall_policy.get(
            "runtime_trace_execution_enabled"
        ),
        "audit_event_readiness_policy.runtime_event_capture_enabled": audit_policy.get(
            "runtime_event_capture_enabled"
        ),
        "expiry_freshness_policy.stale_or_unknown_instruction_allowed": expiry_policy.get(
            "stale_or_unknown_instruction_allowed"
        ),
        "cross_project_memory_policy.cross_project_instruction_grade_allowed_by_default": cross_project_policy.get(
            "cross_project_instruction_grade_allowed_by_default"
        ),
        "instruction_grade_requirements.repository_evidence_remains_authoritative": instruction_requirements.get(
            "repository_evidence_remains_authoritative"
        ),
        "supporting_context_requirements.cannot_override_repository_evidence": supporting_requirements.get(
            "cannot_override_repository_evidence"
        ),
        "source_reference_policy.repository_evidence_outranks_memory": source_policy.get(
            "repository_evidence_outranks_memory"
        ),
        "recall_trace_readiness_policy.not_proof_of_correctness": recall_policy.get(
            "not_proof_of_correctness"
        ),
        "audit_event_readiness_policy.audit_events_are_not_approval": audit_policy.get(
            "audit_events_are_not_approval"
        ),
        "memory_write_back_policy.draft_memory_candidates_only": write_policy.get(
            "draft_memory_candidates_only"
        ),
    }
    invalid_boolean_rules = sorted(
        path for path, value in boolean_rules.items() if not isinstance(value, bool)
    )
    if invalid_boolean_rules:
        findings.append(
            finding(
                "memory_policy_boolean_type_invalid",
                "blocking",
                "blocked",
                "Safety-sensitive memory policy toggles must be explicit YAML booleans.",
                ["Replace string or missing toggle values with explicit true/false booleans."],
                invalid_rule_paths=invalid_boolean_rules,
            )
        )
    required_true_rules = {
        path: boolean_rules[path]
        for path in (
            "instruction_grade_requirements.repository_evidence_remains_authoritative",
            "supporting_context_requirements.cannot_override_repository_evidence",
            "source_reference_policy.repository_evidence_outranks_memory",
            "recall_trace_readiness_policy.not_proof_of_correctness",
            "audit_event_readiness_policy.audit_events_are_not_approval",
            "memory_write_back_policy.draft_memory_candidates_only",
        )
    }
    disabled_authority_rules = sorted(path for path, value in required_true_rules.items() if value is not True)
    if disabled_authority_rules:
        findings.append(
            finding(
                "memory_policy_authority_invariant_disabled",
                "blocking",
                "blocked",
                "A required repository-authority, no-proof, no-approval, or draft-only invariant is disabled.",
                ["Restore every listed invariant to explicit boolean true before evaluating memory use."],
                invalid_rule_paths=disabled_authority_rules,
            )
        )
    ladder_states = {
        str(item.get("state") or "")
        for item in as_list(rules.get("memory_trust_ladder"))
        if isinstance(item, dict) and str(item.get("state") or "")
    }
    allowed_states = set(string_list(rules.get("allowed_memory_states")))
    invalid_allowed_states = sorted(allowed_states - ladder_states)
    if not allowed_states or invalid_allowed_states:
        findings.append(
            finding(
                "allowed_memory_states_invalid",
                "blocking",
                "blocked",
                "allowed_memory_states is empty or contains states absent from the trust ladder.",
                ["Declare a non-empty subset of the reviewed trust-ladder states."],
                invalid_states=invalid_allowed_states,
            )
        )
    if (
        bool_value(private_policy.get("read_private_memory_payloads"))
        or bool_value(private_policy.get("read_engram_db"))
        or bool_value(private_policy.get("index_private_payloads"))
    ):
        findings.append(finding("private_payload_reads_allowed", "blocking", "blocked", "Private memory payload reads are enabled.", ["Keep private payload and Engram database reads disabled."]))
    if bool_value(write_policy.get("automatic_write_back_enabled")) or bool_value(write_policy.get("durable_memory_writes_enabled")):
        findings.append(finding("memory_write_back_enabled", "blocking", "blocked", "Memory write-back is enabled in rules.", ["Keep write-back disabled for Group 30."]))
    if bool_value(cloud_policy.get("cloud_memory_enabled")) or bool_value(cloud_policy.get("external_sync_enabled")):
        findings.append(finding("cloud_memory_enabled", "blocking", "blocked", "Cloud memory or external sync is enabled.", ["Keep cloud memory and external sync disabled by default."]))
    if (
        str(ci_policy.get("default_access") or "none") != "none"
        or bool_value(ci_policy.get("memory_read_allowed"))
        or bool_value(ci_policy.get("memory_write_allowed"))
        or bool_value(ci_policy.get("mcp_access_allowed"))
    ):
        findings.append(finding("ci_memory_access", "blocking", "blocked", "CI memory access is not none.", ["Set CI memory access to none."]))
    if bool_value(recall_policy.get("runtime_trace_execution_enabled")):
        findings.append(finding("recall_trace_runtime_enabled", "blocking", "blocked", "Live recall trace execution is enabled.", ["Keep recall trace execution deferred."]))
    if bool_value(audit_policy.get("runtime_event_capture_enabled")):
        findings.append(finding("audit_event_runtime_capture_enabled", "blocking", "blocked", "Runtime audit-event capture is enabled.", ["Keep audit-event capture deferred."]))
    declared_forbidden = {
        value.strip().casefold()
        for value in string_list(rules.get("forbidden_memory_categories"))
        if value.strip()
    }
    missing_forbidden = sorted(
        FORBIDDEN_CATEGORY_BY_NORMALIZED[value]
        for value in set(FORBIDDEN_CATEGORY_BY_NORMALIZED) - declared_forbidden
    )
    if missing_forbidden:
        findings.append(
            finding(
                "forbidden_memory_categories_missing",
                severity,
                "missing",
                f"Forbidden memory categories are incomplete: {', '.join(missing_forbidden)}.",
                ["Add missing forbidden categories before approving memory use."],
            )
        )
    return findings


def evaluate_recall_traces(traces: list[dict[str, Any]], rules: dict[str, Any], severity: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    policy = as_mapping(rules.get("recall_trace_readiness_policy"))
    findings: list[dict[str, Any]] = []
    for index, trace in enumerate(traces):
        trace_id = str(trace.get("trace_id") or f"recall_trace_{index + 1}")
        if "treated_as_proof" in trace and not isinstance(trace.get("treated_as_proof"), bool):
            findings.append(
                finding(
                    f"{trace_id}_treated_as_proof_type_invalid",
                    "blocking",
                    "blocked",
                    "Recall trace treated_as_proof must be an explicit boolean.",
                    ["Use explicit false; strings and numeric truth values are invalid."],
                    trace_id=trace_id,
                )
            )
        if bool_value(trace.get("treated_as_proof")):
            findings.append(
                finding(
                    f"{trace_id}_treated_as_proof",
                    "blocking",
                    "blocked",
                    "Recall trace is treated as proof.",
                    ["Treat recall traces as usage records only, not correctness proof."],
                    trace_id=trace_id,
                )
            )
    return {
        "status": "readiness_only",
        "runtime_trace_execution_enabled": bool_value(policy.get("runtime_trace_execution_enabled")),
        "readiness_only": bool_value(policy.get("readiness_only"), True),
        "trace_count": len(traces),
        "required_future_fields": string_list(policy.get("required_future_fields")),
        "not_proof_of_correctness": bool_value(policy.get("not_proof_of_correctness"), True),
    }, findings


def evaluate_audit_events(events: list[dict[str, Any]], rules: dict[str, Any], severity: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    policy = as_mapping(rules.get("audit_event_readiness_policy"))
    allowed = set(string_list(policy.get("allowed_event_types")))
    findings: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for index, event in enumerate(events):
        event_id = str(event.get("event_id") or f"audit_event_{index + 1}")
        event_type = str(event.get("event_type") or "unknown")
        counts[event_type] += 1
        if "treated_as_approval" in event and not isinstance(event.get("treated_as_approval"), bool):
            findings.append(
                finding(
                    f"{event_id}_treated_as_approval_type_invalid",
                    "blocking",
                    "blocked",
                    "Audit event treated_as_approval must be an explicit boolean.",
                    ["Use explicit false; strings and numeric truth values are invalid."],
                    event_id=event_id,
                )
            )
        if allowed and event_type not in allowed:
            findings.append(
                finding(
                    f"{event_id}_unknown_event_type",
                    severity,
                    "unknown",
                    "Audit event declares an unsupported event type.",
                    ["Use an allowed memory audit event type."],
                    event_id=event_id,
                )
            )
        if bool_value(event.get("treated_as_approval")):
            findings.append(
                finding(
                    f"{event_id}_treated_as_approval",
                    "blocking",
                    "blocked",
                    "Audit event is treated as approval.",
                    ["Treat audit events as records only; approval requires explicit review metadata."],
                    event_id=event_id,
                )
            )
    return {
        "status": "readiness_only",
        "runtime_event_capture_enabled": bool_value(policy.get("runtime_event_capture_enabled")),
        "readiness_only": bool_value(policy.get("readiness_only"), True),
        "event_count": len(events),
        "allowed_event_types": sorted(allowed),
        "event_type_counts": dict(sorted(counts.items())),
        "audit_events_are_not_approval": bool_value(policy.get("audit_events_are_not_approval"), True),
    }, findings


def status_from_findings(rules: dict[str, Any], posture: dict[str, Any], item_count: int, findings: list[dict[str, Any]]) -> str:
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if not bool_value(rules.get("enabled"), True) or (posture.get("state") == "disabled" and item_count == 0):
        return "disabled"
    if any(
        item.get("severity") in {"warning", "required"}
        or item.get("status")
        in {"review_required", "conflict", "invalid", "stale", "missing", "unknown", "parse_error"}
        for item in findings
    ):
        return "review_required"
    if item_count and posture.get("human_review_required_if_review_items_exist"):
        return "review_required"
    if item_count:
        return "advisory"
    return "readiness_only"


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    review_items: dict[str, Any],
    review_items_path: Path,
    review_items_source: str,
    memory_readiness_report_path: Path,
    memory_provider_access_report_path: Path,
) -> dict[str, Any]:
    posture = profile_posture(rules, profile)
    severity = severity_for_rules(root, naos_root, profile, policy, posture)
    items = [item for item in as_list(review_items.get("memory_review_items")) if isinstance(item, dict)]
    traces = [item for item in as_list(review_items.get("recall_traces")) if isinstance(item, dict)]
    events = [item for item in as_list(review_items.get("audit_events")) if isinstance(item, dict)]

    malformed_entries = as_mapping(review_items.get("_malformed_entries"))
    malformed_findings = [
        finding(
            f"{section}_malformed_entries",
            severity,
            "review_required",
            f"{section} contains non-object entries that were refused rather than silently discarded.",
            ["Replace every entry with a schema-compatible mapping and rerun the policy report."],
            section=section,
            malformed_entries=as_list(entries),
        )
        for section, entries in sorted(malformed_entries.items())
        if as_list(entries)
    ]

    item_findings, item_eval = evaluate_items(items, rules, severity, profile)
    rule_findings = evaluate_rules(rules, severity)
    recall_readiness, recall_findings = evaluate_recall_traces(traces, rules, severity)
    audit_readiness, audit_findings = evaluate_audit_events(events, rules, severity)
    findings = [
        *rule_findings,
        *malformed_findings,
        *item_findings,
        *recall_findings,
        *audit_findings,
    ]

    readiness_report, readiness_join = inspect_upstream_report(
        root=root,
        profile=profile,
        report_key="memory_context_readiness",
        path=memory_readiness_report_path,
    )
    provider_report, provider_join = inspect_upstream_report(
        root=root,
        profile=profile,
        report_key="memory_provider_access",
        path=memory_provider_access_report_path,
    )
    use_grade_items = [item for item in items if item.get("state") in USE_GRADE_MEMORY_STATES]
    access_reasons: list[str] = []
    for label, joined in (("memory_readiness", readiness_join), ("memory_provider_access", provider_join)):
        if not joined.get("accepted_for_join"):
            access_reasons.extend(f"{label}:{reason}" for reason in joined.get("validation_reasons") or ["not_accepted"])
    if readiness_join.get("accepted_for_join"):
        readiness = as_mapping(readiness_report.get("memory_readiness"))
        if readiness.get("memory_config_state") != "configured" or not bool(readiness.get("memory_config_enabled")):
            access_reasons.append("memory_readiness:memory_not_enabled_and_configured")
    if provider_join.get("accepted_for_join"):
        if not bool(provider_report.get("provider_configured")):
            access_reasons.append("memory_provider_access:provider_not_configured")
        if not bool(provider_report.get("provider_access_verified")):
            access_reasons.append("memory_provider_access:provider_access_unverified")
        if not bool(provider_report.get("mcp_access_verified")):
            access_reasons.append("memory_provider_access:mcp_access_unverified")
        project_identity = as_mapping(provider_report.get("project_identity"))
        if not bool(project_identity.get("project_identity_verified")):
            access_reasons.append("memory_provider_access:project_identity_unverified")
    access_reasons = list(dict.fromkeys(access_reasons))
    access_verified = bool(use_grade_items) and not access_reasons

    invalid_item_ids = {
        str(item.get("memory_reference_id") or "")
        for item in item_findings
        if item.get("memory_reference_id")
    }
    policy_item_access_posture: list[dict[str, Any]] = []
    for item in use_grade_items:
        item_id = str(item.get("memory_reference_id") or item.get("id") or "unknown")
        policy_metadata_valid = item_id not in invalid_item_ids
        if not policy_metadata_valid:
            joined_status = "policy_metadata_invalid"
        elif access_verified:
            joined_status = "policy_metadata_valid_access_verified"
        else:
            joined_status = "policy_item_valid_but_access_unverified"
            findings.append(
                finding(
                    f"{item_id}_policy_item_valid_but_access_unverified",
                    severity,
                    "review_required",
                    "Memory-use policy metadata is valid, but current schema-validated readiness/provider reports do not verify configured, authorized, project-resolved access.",
                    [
                        "Generate current memory-readiness and memory-access reports for this project/profile, then complete the separately approved live-access verification path before using the item."
                    ],
                    memory_reference_id=item_id,
                    access_reasons=access_reasons,
                )
            )
        policy_item_access_posture.append(
            {
                "memory_reference_id": item_id,
                "state": item.get("state"),
                "policy_metadata_valid": policy_metadata_valid,
                "joined_status": joined_status,
                "access_reasons": [] if joined_status == "policy_metadata_invalid" else access_reasons,
            }
        )

    summaries = item_eval["summaries"]
    state_counts = dict(sorted(Counter(str(item.get("state") or "unknown") for item in items).items()))
    review_status_counts = dict(sorted(Counter(str(item.get("review_status") or "unknown") for item in items).items()))
    source_counts = Counter("with_source_references" if has_source_refs(item, rules) else "missing_source_references" for item in items)
    provenance_counts = Counter("with_provenance" if item.get("provenance") else "missing_provenance" for item in items)
    status = status_from_findings(rules, posture, len(items), findings)
    summary = finding_counts(findings)
    summary.update(
        {
            "status": status,
            "profile_state": posture.get("state"),
            "memory_review_items": len(items),
            "recall_traces": len(traces),
            "audit_events": len(events),
            "instruction_grade_items": sum(1 for item in items if item.get("state") == "instruction_grade_memory"),
            "supporting_context_items": sum(1 for item in items if item.get("state") == "supporting_context_memory"),
            "unsafe_instruction_grade_claims": len(item_eval["unsafe_instruction_grade_claims"]),
            "unsafe_supporting_context_claims": len(item_eval["unsafe_supporting_context_claims"]),
            "policy_items_requiring_access": len(use_grade_items),
            "policy_items_with_verified_access": sum(
                1 for item in policy_item_access_posture if item.get("joined_status") == "policy_metadata_valid_access_verified"
            ),
            "policy_items_valid_but_access_unverified": sum(
                1 for item in policy_item_access_posture if item.get("joined_status") == "policy_item_valid_but_access_unverified"
            ),
            "malformed_input_entries": sum(len(as_list(entries)) for entries in malformed_entries.values()),
            "human_review_required": bool(findings)
            or bool(items and posture.get("human_review_required_if_review_items_exist")),
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
        "review_items_path": str(review_items_path),
        "review_items_source": review_items_source,
        "review_items_present": bool(items or traces or events or malformed_entries),
        "malformed_input_entries": malformed_entries,
        "memory_trust_ladder": as_list(rules.get("memory_trust_ladder")),
        "state_counts": state_counts,
        "review_status_counts": review_status_counts,
        "instruction_grade_items": [item for item in summaries if item.get("state") == "instruction_grade_memory"],
        "supporting_context_items": [item for item in summaries if item.get("state") == "supporting_context_memory"],
        "review_pending_items": [item for item in summaries if item.get("state") == "review_pending_memory"],
        "rejected_items": [item for item in summaries if item.get("state") == "rejected_memory"],
        "superseded_items": [item for item in summaries if item.get("state") == "superseded_memory"],
        "unsafe_instruction_grade_claims": item_eval["unsafe_instruction_grade_claims"],
        "unsafe_supporting_context_claims": item_eval["unsafe_supporting_context_claims"],
        "memory_access_prerequisites": {
            "required_for_use_grade_items": bool(use_grade_items),
            "joined_status": "verified" if access_verified else ("unverified" if use_grade_items else "not_applicable"),
            "memory_readiness_report": readiness_join,
            "memory_provider_access_report": provider_join,
            "provider_or_mcp_calls_performed": False,
            "memory_payloads_read": False,
            "access_reasons": access_reasons if use_grade_items else [],
        },
        "policy_item_access_posture": policy_item_access_posture,
        "source_reference_summary": dict(sorted(source_counts.items())),
        "provenance_summary": dict(sorted(provenance_counts.items())),
        "recall_trace_readiness": recall_readiness,
        "audit_event_readiness": audit_readiness,
        "forbidden_category_policy": {"forbidden_memory_categories": string_list(rules.get("forbidden_memory_categories"))},
        "private_payload_policy": as_mapping(rules.get("private_payload_policy")),
        "memory_write_back_policy": as_mapping(rules.get("memory_write_back_policy")),
        "cloud_memory_policy": as_mapping(rules.get("cloud_memory_policy")),
        "ci_memory_policy": as_mapping(rules.get("ci_memory_access_policy")),
        "integration_points": as_mapping(rules.get("integration_points")),
        "findings": findings,
        "known_gaps": as_list(rules.get("known_gaps")),
        "residual_risks": as_list(rules.get("residual_risks")),
        "waivers": as_list(rules.get("waivers")),
        "limitations": dedupe_strings(string_list(rules.get("limitations"))),
        "not_claimed": dedupe_strings(string_list(rules.get("not_claimed")) + NOT_CLAIMED),
        "human_review_required": bool(summary["human_review_required"]),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate memory-use policy, review items, recall-trace readiness, and audit-event readiness.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file used for path/profile conventions.")
    parser.add_argument("--rules", help="Explicit memory_use_policy_rules.yaml path.")
    parser.add_argument("--review-items", help="Explicit memory_review_items.yaml path.")
    parser.add_argument("--memory-readiness-report", help="Explicit current memory_context_readiness.json input path.")
    parser.add_argument("--memory-access-report", help="Explicit current memory_provider_access.json input path.")
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
            "memory_use_policy_rules",
            default_rules_template(),
            args.rules,
        )
        review_items_path, review_items_source = resolve_seed_path(
            root,
            naos_root,
            policy,
            "memory_review_items",
            default_review_items_template(),
            args.review_items,
        )
        rules = load_yaml_mapping(rules_path)
        review_items = load_review_items(review_items_path)
        memory_readiness_report_path = upstream_report_path(
            root,
            naos_root,
            policy,
            "memory_context_readiness",
            args.memory_readiness_report,
        )
        memory_provider_access_report_path = upstream_report_path(
            root,
            naos_root,
            policy,
            "memory_provider_access",
            args.memory_access_report,
        )
        report = build_report(
            root,
            naos_root,
            profile,
            policy,
            rules,
            rules_path,
            rules_source,
            review_items,
            review_items_path,
            review_items_source,
            memory_readiness_report_path,
            memory_provider_access_report_path,
        )
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "memory_use_policy_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(f"NAOS memory use policy ({profile}): {report['status']}")
        print(
            "summary: "
            f"items={summary.get('memory_review_items')} "
            f"instruction_grade={summary.get('instruction_grade_items')} "
            f"unsafe_instruction={summary.get('unsafe_instruction_grade_claims')} "
            f"findings={summary.get('total_findings', 0)}"
        )
        print(f"report: {output}")
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
