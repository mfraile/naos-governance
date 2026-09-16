#!/usr/bin/env python3
"""Review local model-usage telemetry evidence without runtime calls.

This command reads repo-local declarations and explicitly declared local
telemetry files only. It does not call providers, models, APIs, gateways, MCP,
memory tools, local servers, networks, or IDE/tool configuration, and it does
not prove cost completeness, route correctness, payload safety, compliance,
approval, certification, attestation, release readiness, or publication
readiness.
"""

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
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.model_telemetry_evidence.v1"
ALLOWED_SOURCE_FORMATS = {"json", "jsonl", "yaml", "yml"}
ALLOWED_ROUTE_CLASSES = {
    "planning",
    "implementation",
    "review",
    "conformance",
    "research",
    "debug",
    "triage",
    "llm_judge",
    "autoresearch_grader",
    "low_cost",
    "balanced",
    "high_capability",
    "local_only",
    "privacy_sensitive",
    "unknown",
}
SENSITIVE_DATA_CLASSES = {
    "secret",
    "secrets",
    "credential",
    "credentials",
    "token",
    "tokens",
    "password",
    "passwords",
    "private_key",
    "private keys",
    "customer_data",
    "customer data",
    "tenant_data",
    "tenant data",
    "regulated_data",
    "regulated data",
    "private_memory_payload",
    "private memory payloads",
}
PAYLOAD_FIELD_NAMES = {
    "prompt",
    "prompt_text",
    "prompt_payload",
    "input",
    "input_text",
    "input_payload",
    "messages",
    "conversation",
    "response",
    "response_text",
    "response_payload",
    "completion",
    "completion_text",
    "output",
    "output_text",
    "output_payload",
    "raw_payload",
    "payload",
}
SECRET_FIELD_NAMES = {
    "api_key",
    "api_key_env",
    "token",
    "secret",
    "password",
    "credential",
    "credentials",
    "private_key",
    "connection_string",
}
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
AUTHORITY_FIELDS = {
    "runtime_enabled",
    "provider_calls_allowed",
    "gateway_calls_allowed",
    "mcp_allowed",
    "memory_allowed",
    "provider_api_allowed",
    "model_call_allowed",
    "tool_mutation_allowed",
    "route_enforcement_enabled",
}
REASON_ORDER = [
    "telemetry_source_unreadable",
    "sensitive_payload_capture",
    "credential_capture",
    "missing_session_link",
    "missing_task_link",
    "missing_model_role",
    "undeclared_model_role",
    "model_provider_policy_link_missing",
    "unknown_route_class",
    "sensitive_data_class_review",
    "cost_threshold_exceeded",
    "latency_threshold_exceeded",
    "stale_telemetry",
    "policy_exception_declared",
    "provider_runtime_authority_attempt",
    "model_telemetry_review_required",
]
REASON_GATES = {
    "telemetry_source_unreadable": ["G6"],
    "sensitive_payload_capture": ["G6"],
    "credential_capture": ["G6"],
    "missing_session_link": ["G2", "G6"],
    "missing_task_link": ["G2", "G6"],
    "missing_model_role": ["G2", "G6"],
    "undeclared_model_role": ["G2", "G6"],
    "model_provider_policy_link_missing": ["G2", "G6"],
    "unknown_route_class": ["G2", "G6"],
    "sensitive_data_class_review": ["G6"],
    "cost_threshold_exceeded": ["G6"],
    "latency_threshold_exceeded": ["G6"],
    "stale_telemetry": ["G6"],
    "policy_exception_declared": ["G6"],
    "provider_runtime_authority_attempt": ["G6"],
    "model_telemetry_review_required": ["G6"],
}
LIMITATIONS = [
    "Model telemetry evidence reports read local declarations and local telemetry files only.",
    "The report summarizes declared records and missing or risky evidence; it does not prove a model request occurred.",
    "Cost and latency values are adopter-supplied evidence and are not complete accounting, billing proof, or provider verification.",
    "The report does not call providers, models, APIs, gateways, MCP, memory tools, local servers, networks, hooks, browsers, or IDE/tool configuration.",
    "The report sanitizes known prompt/response/credential payload fields and reports their presence as review evidence instead of copying payload values.",
    "Findings remain local human-review evidence; they do not approve, block, certify, attest, release, publish, or prove compliance.",
]
NOT_CLAIMED = [
    "LiteLLM integration",
    "provider gateway availability",
    "provider call",
    "model call",
    "API call",
    "network access",
    "MCP activation",
    "memory activation",
    "credential validation",
    "runtime model routing",
    "route enforcement",
    "model recommendation",
    "provider catalog",
    "complete cost accounting",
    "billing proof",
    "payload safety proof",
    "route correctness proof",
    "policy compliance proof",
    "legal or regulatory assurance",
    "approval",
    "certification",
    "attestation",
    "release authority",
    "publication authority",
]
RESIDUAL_RISKS = [
    "telemetry_can_be_incomplete",
    "telemetry_can_be_stale",
    "cost_values_can_be_estimates",
    "tool_export_formats_can_drift",
    "declared_route_class_is_not_route_enforcement",
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
    return list(dict.fromkeys(str(item).strip() for item in as_list(value) if str(item).strip()))


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def number_value(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def is_adapt_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith("[ADAPT:")


def is_empty_or_placeholder(value: Any) -> bool:
    return value in (None, "") or is_adapt_placeholder(value)


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


def default_declaration_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "model_telemetry_evidence.yaml"


def resolve_declaration_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("model_telemetry_evidence") or "model_telemetry_evidence.yaml")
    project_declaration = root / naos_root / filename
    if project_declaration.exists():
        return project_declaration, "project"
    return default_declaration_template(), "template"


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError:
        return path.as_posix()


def resolve_local_ref(root: Path, ref: str | None) -> Path | None:
    if not ref or is_adapt_placeholder(ref):
        return None
    path = Path(str(ref))
    return path if path.is_absolute() else root / path


def infer_source_format(path: Path, declared: Any = None) -> str:
    if declared:
        value = str(declared).strip().lower()
        if value in ALLOWED_SOURCE_FORMATS:
            return value
    suffix = path.suffix.lower().lstrip(".")
    if suffix in ALLOWED_SOURCE_FORMATS:
        return suffix
    return "yaml"


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def finding(
    identifier: str,
    severity: str,
    status: str,
    reason_code: str,
    message: str,
    *,
    record_id: str | None = None,
    source_ref: str | None = None,
    related_refs: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "reason_code": reason_code,
        "gate": REASON_GATES.get(reason_code, ["G6"])[0],
        "related_gates": REASON_GATES.get(reason_code, ["G6"]),
        "message": message,
        "human_review_required": True,
        "not_claimed": ["runtime model routing", "cost completeness", "approval", "certification", "compliance proof"],
    }
    if record_id:
        result["record_id"] = record_id
    if source_ref:
        result["source_ref"] = source_ref
    if related_refs:
        result["related_refs"] = related_refs
    return result


def profile_posture(declaration: dict[str, Any], profile: str) -> dict[str, Any]:
    posture = as_mapping(declaration.get("profile_posture")).get(profile)
    if isinstance(posture, dict):
        return posture
    defaults = {
        "quickstart": {"state": "optional", "severity": "advisory", "human_review_required": False},
        "lite": {"state": "optional", "severity": "warning", "human_review_required": False},
        "standard": {"state": "optional", "severity": "required", "human_review_required": True},
        "assured": {"state": "optional", "severity": "required", "human_review_required": True},
    }
    return defaults.get(profile, defaults["quickstart"])


def severity_from_posture(root: Path, naos_root: str, posture: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    value = str(posture.get("severity") or "advisory")
    if value == "blocking":
        return "required"
    return value if value in {"advisory", "warning", "required"} else "advisory"


def load_records_from_source(root: Path, source: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ref = str(source.get("path") or "")
    path = resolve_local_ref(root, ref)
    source_ref = ref or "missing_source_path"
    meta = {
        "path": source_ref,
        "format": None,
        "records": 0,
        "present": bool(path and path.is_file()),
        "hash": safe_digest(path) if path else None,
        "error": None,
    }
    if path is None or not path.is_file():
        meta["error"] = "source_file_missing"
        return [], meta

    source_format = infer_source_format(path, source.get("format"))
    meta["format"] = source_format
    try:
        if source_format == "jsonl":
            records: list[dict[str, Any]] = []
            for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError(f"line {index} is not a JSON object")
                parsed["_source_ref"] = relative_path(path, root)
                parsed["_source_index"] = index
                records.append(parsed)
        elif source_format == "json":
            parsed = json.loads(path.read_text(encoding="utf-8"))
            records = records_from_parsed_source(parsed, path, root)
        else:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            records = records_from_parsed_source(parsed, path, root)
    except Exception as exc:
        meta["error"] = str(exc)
        return [], meta

    meta["records"] = len(records)
    return records, meta


def records_from_parsed_source(parsed: Any, path: Path, root: Path) -> list[dict[str, Any]]:
    if isinstance(parsed, list):
        raw_records = parsed
    elif isinstance(parsed, dict):
        raw_records = parsed.get("records") if isinstance(parsed.get("records"), list) else [parsed]
    else:
        raise ValueError("telemetry source must contain an object, array, or records array")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(raw_records, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"record {index} is not an object")
        record = dict(item)
        record["_source_ref"] = relative_path(path, root)
        record["_source_index"] = index
        records.append(record)
    return records


def load_declared_model_roles(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[set[str], list[str]]:
    # Role identity comes from the current configured declaration, never a cached
    # report whose profile/source may differ. This also honours configured paths.
    from naos_model_provider_policy import resolve_model_policy_path
    path, _source = resolve_model_policy_path(root, naos_root, policy)
    if not path.is_file():
        return set(), []
    data = load_yaml_mapping(path)
    roles = {str(role) for role in as_mapping(data.get('roles'))}
    return roles, [relative_path(path, root)]


def record_id(record: dict[str, Any], index: int) -> str:
    return str(record.get("record_id") or record.get("id") or f"record-{index}")


def payload_fields_present(record: dict[str, Any]) -> list[str]:
    return sorted(field for field in PAYLOAD_FIELD_NAMES if field in record and not is_empty_or_placeholder(record.get(field)))


def credential_fields_present(record: dict[str, Any]) -> list[str]:
    present = [field for field in SECRET_FIELD_NAMES if field in record and not is_empty_or_placeholder(record.get(field))]
    for key, value in record.items():
        if key.startswith("_"):
            continue
        if isinstance(value, str) and SECRET_RE.search(value):
            present.append(str(key))
    return sorted(set(present))


def sanitized_record(record: dict[str, Any], index: int) -> dict[str, Any]:
    cost = number_value(record.get("cost_usd") if record.get("cost_usd") is not None else record.get("estimated_cost_usd"))
    latency = number_value(record.get("latency_ms"))
    return {
        "index": index,
        "record_id": record_id(record, index),
        "source_ref": record.get("_source_ref"),
        "source_index": record.get("_source_index"),
        "timestamp": record.get("timestamp"),
        "session_id": record.get("session_id"),
        "task_id": record.get("task_id"),
        "tool": record.get("tool") or record.get("agent_or_tool"),
        "model_role": record.get("model_role") or record.get("role"),
        "provider_kind": record.get("provider_kind"),
        "provider": record.get("provider"),
        "model_ref_declared": not is_empty_or_placeholder(record.get("model") or record.get("model_ref")),
        "route_class": record.get("route_class"),
        "data_class": record.get("data_class") or record.get("data_exposure_level"),
        "cost_usd": cost,
        "latency_ms": latency,
        "input_tokens": record.get("input_tokens"),
        "output_tokens": record.get("output_tokens"),
        "total_tokens": record.get("total_tokens"),
        "policy_ref": record.get("policy_ref"),
        "action_receipt_ref": record.get("action_receipt_ref"),
        "evidence_refs": string_list(record.get("evidence_refs")),
        "policy_exception_declared": bool_value(record.get("policy_exception")) or bool(string_list(record.get("policy_exceptions"))),
        "payload_fields_present": payload_fields_present(record),
        "credential_fields_present": credential_fields_present(record),
    }


def review_records(
    *,
    root: Path,
    naos_root: str,
    declaration: dict[str, Any],
    policy: dict[str, Any],
    records: list[dict[str, Any]],
    source_metas: list[dict[str, Any]],
    severity: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    sanitized: list[dict[str, Any]] = []
    evidence_refs: list[dict[str, Any]] = []
    declared_roles, policy_refs = load_declared_model_roles(root, naos_root, policy)
    thresholds = as_mapping(declaration.get("thresholds"))
    cost_threshold = number_value(thresholds.get("cost_usd_review_threshold") or thresholds.get("max_cost_usd"))
    latency_threshold = number_value(thresholds.get("latency_ms_review_threshold") or thresholds.get("max_latency_ms"))
    stale_after_days = number_value(thresholds.get("stale_after_days"))
    require_policy_ref = bool_value(as_mapping(declaration.get("policy_linkage")).get("require_policy_ref"), True)

    for source in source_metas:
        if source.get("error"):
            findings.append(
                finding(
                    "model_telemetry.telemetry_source_unreadable",
                    severity,
                    "review_required",
                    "telemetry_source_unreadable",
                    f"Telemetry source `{source.get('path')}` could not be read: {source.get('error')}.",
                    source_ref=str(source.get("path")),
                )
            )
        elif source.get("path"):
            evidence_refs.append({"type": "telemetry_source", "path": source.get("path"), "present": source.get("present")})

    now = datetime.now(UTC)
    for index, record in enumerate(records, start=1):
        sanitized_item = sanitized_record(record, index)
        sanitized.append(sanitized_item)
        rid = str(sanitized_item["record_id"])
        source_ref = str(sanitized_item.get("source_ref") or "")
        related_refs = [ref for ref in [source_ref, *policy_refs] if ref]

        if sanitized_item["payload_fields_present"]:
            findings.append(
                finding(
                    f"model_telemetry.sensitive_payload_capture.{rid}",
                    severity,
                    "review_required",
                    "sensitive_payload_capture",
                    "Telemetry record includes prompt/response/raw payload fields; NAOS reports field presence only.",
                    record_id=rid,
                    source_ref=source_ref,
                    related_refs=related_refs,
                )
            )
        if sanitized_item["credential_fields_present"]:
            findings.append(
                finding(
                    f"model_telemetry.credential_capture.{rid}",
                    severity,
                    "review_required",
                    "credential_capture",
                    "Telemetry record includes credential-like fields or values.",
                    record_id=rid,
                    source_ref=source_ref,
                    related_refs=related_refs,
                )
            )
        if is_empty_or_placeholder(sanitized_item.get("session_id")):
            findings.append(
                finding(
                    f"model_telemetry.missing_session_link.{rid}",
                    severity,
                    "review_required",
                    "missing_session_link",
                    "Telemetry record is missing session_id linkage.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        if is_empty_or_placeholder(sanitized_item.get("task_id")):
            findings.append(
                finding(
                    f"model_telemetry.missing_task_link.{rid}",
                    severity,
                    "review_required",
                    "missing_task_link",
                    "Telemetry record is missing task_id linkage.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        model_role = sanitized_item.get("model_role")
        if is_empty_or_placeholder(model_role):
            findings.append(
                finding(
                    f"model_telemetry.missing_model_role.{rid}",
                    severity,
                    "review_required",
                    "missing_model_role",
                    "Telemetry record is missing model_role linkage.",
                    record_id=rid,
                    source_ref=source_ref,
                    related_refs=policy_refs,
                )
            )
        elif declared_roles and str(model_role) not in declared_roles:
            findings.append(
                finding(
                    f"model_telemetry.undeclared_model_role.{rid}",
                    severity,
                    "review_required",
                    "undeclared_model_role",
                    f"Telemetry record references undeclared model_role `{model_role}`.",
                    record_id=rid,
                    source_ref=source_ref,
                    related_refs=policy_refs,
                )
            )
        if require_policy_ref and is_empty_or_placeholder(sanitized_item.get("policy_ref")):
            findings.append(
                finding(
                    f"model_telemetry.model_provider_policy_link_missing.{rid}",
                    severity,
                    "review_required",
                    "model_provider_policy_link_missing",
                    "Telemetry record is missing explicit model-provider policy reference.",
                    record_id=rid,
                    source_ref=source_ref,
                    related_refs=policy_refs,
                )
            )
        route_class = str(sanitized_item.get("route_class") or "").strip()
        if route_class and route_class not in ALLOWED_ROUTE_CLASSES:
            findings.append(
                finding(
                    f"model_telemetry.unknown_route_class.{rid}",
                    severity,
                    "review_required",
                    "unknown_route_class",
                    f"Telemetry record declares unsupported route_class `{route_class}`.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        data_class = str(sanitized_item.get("data_class") or "").strip().lower()
        if data_class in SENSITIVE_DATA_CLASSES:
            findings.append(
                finding(
                    f"model_telemetry.sensitive_data_class_review.{rid}",
                    severity,
                    "review_required",
                    "sensitive_data_class_review",
                    f"Telemetry record declares sensitive data_class `{data_class}`.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        if cost_threshold is not None and sanitized_item.get("cost_usd") is not None and float(sanitized_item["cost_usd"]) > cost_threshold:
            findings.append(
                finding(
                    f"model_telemetry.cost_threshold_exceeded.{rid}",
                    severity,
                    "review_required",
                    "cost_threshold_exceeded",
                    f"Telemetry record cost exceeds configured review threshold {cost_threshold}.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        if (
            latency_threshold is not None
            and sanitized_item.get("latency_ms") is not None
            and float(sanitized_item["latency_ms"]) > latency_threshold
        ):
            findings.append(
                finding(
                    f"model_telemetry.latency_threshold_exceeded.{rid}",
                    severity,
                    "review_required",
                    "latency_threshold_exceeded",
                    f"Telemetry record latency exceeds configured review threshold {latency_threshold}.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        if stale_after_days is not None:
            timestamp = parse_timestamp(sanitized_item.get("timestamp"))
            if timestamp and (now - timestamp).days > stale_after_days:
                findings.append(
                    finding(
                        f"model_telemetry.stale_telemetry.{rid}",
                        severity,
                        "review_required",
                        "stale_telemetry",
                        f"Telemetry record is older than configured review window {int(stale_after_days)} days.",
                        record_id=rid,
                        source_ref=source_ref,
                    )
                )
        if sanitized_item["policy_exception_declared"]:
            findings.append(
                finding(
                    f"model_telemetry.policy_exception_declared.{rid}",
                    severity,
                    "review_required",
                    "policy_exception_declared",
                    "Telemetry record declares a policy exception requiring human review.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
        if any(bool_value(record.get(field)) for field in AUTHORITY_FIELDS):
            findings.append(
                finding(
                    f"model_telemetry.provider_runtime_authority_attempt.{rid}",
                    severity,
                    "review_required",
                    "provider_runtime_authority_attempt",
                    "Telemetry record attempts to declare runtime/provider/tool authority.",
                    record_id=rid,
                    source_ref=source_ref,
                )
            )
    return sanitized, evidence_refs, findings


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    declaration_path: Path,
    declaration_source: str,
) -> dict[str, Any]:
    declaration = load_yaml_mapping(declaration_path)
    posture = profile_posture(declaration, profile)
    severity = severity_from_posture(root, naos_root, posture)
    enabled = bool_value(declaration.get("enabled"))
    telemetry_declared = bool_value(declaration.get("telemetry_declared"))
    authority_attempt = [field for field in sorted(AUTHORITY_FIELDS) if bool_value(declaration.get(field))]
    findings: list[dict[str, Any]] = []
    source_metas: list[dict[str, Any]] = []
    records = [item for item in as_list(declaration.get("records")) if isinstance(item, dict)]

    if enabled and telemetry_declared:
        for source in as_list(declaration.get("telemetry_sources")):
            if not isinstance(source, dict):
                source_metas.append({"path": str(source), "present": False, "records": 0, "error": "source_entry_not_mapping"})
                continue
            source_records, meta = load_records_from_source(root, source)
            source_metas.append(meta)
            records.extend(source_records)
        if authority_attempt:
            for field in authority_attempt:
                findings.append(
                    finding(
                        f"model_telemetry.provider_runtime_authority_attempt.{field}",
                        severity,
                        "review_required",
                        "provider_runtime_authority_attempt",
                        f"Declaration enables `{field}`; this capability is local evidence review only.",
                    )
                )

    sanitized_records: list[dict[str, Any]] = []
    evidence_refs: list[dict[str, Any]] = []
    if enabled and telemetry_declared:
        sanitized_records, evidence_refs, record_findings = review_records(
            root=root,
            naos_root=naos_root,
            declaration=declaration,
            policy=policy,
            records=records,
            source_metas=source_metas,
            severity=severity,
        )
        findings.extend(record_findings)

    reason_counts = Counter(str(item.get("reason_code") or "model_telemetry_review_required") for item in findings)
    reason_code_counts = {code: reason_counts.get(code, 0) for code in REASON_ORDER}
    known_gaps = string_list(declaration.get("known_gaps"))
    if not enabled or not telemetry_declared:
        known_gaps.append("model_telemetry_evidence_not_enabled")
    if enabled and telemetry_declared and not records:
        findings.append(
            finding(
                "model_telemetry.telemetry_source_unreadable.empty",
                severity,
                "review_required",
                "telemetry_source_unreadable",
                "Telemetry is declared but no records were provided by inline entries or local source files.",
            )
        )
        reason_code_counts["telemetry_source_unreadable"] = reason_code_counts.get("telemetry_source_unreadable", 0) + 1

    summary = finding_counts(findings)
    summary.update(
        {
            "records": len(sanitized_records),
            "telemetry_sources": len(source_metas),
            "telemetry_sources_unreadable": sum(1 for item in source_metas if item.get("error")),
            "payload_field_findings": reason_code_counts["sensitive_payload_capture"],
            "credential_findings": reason_code_counts["credential_capture"],
            "cost_threshold_findings": reason_code_counts["cost_threshold_exceeded"],
            "latency_threshold_findings": reason_code_counts["latency_threshold_exceeded"],
            "runtime_authority_findings": reason_code_counts["provider_runtime_authority_attempt"],
            "provider_calls_allowed": False,
            "runtime_enabled": False,
        }
    )
    if not enabled or not telemetry_declared:
        status = "not_configured"
    elif findings:
        status = status_from_counts(summary)
    else:
        status = "pass"

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "declaration_path": str(declaration_path),
        "declaration_source": declaration_source,
        "declaration_hash": safe_digest(declaration_path),
        "enabled": enabled,
        "telemetry_declared": telemetry_declared,
        "runtime_enabled": False,
        "provider_calls_allowed": False,
        "gateway_calls_allowed": False,
        "mcp_allowed": False,
        "memory_allowed": False,
        "payload_capture_allowed": False,
        "credential_capture_allowed": False,
        "tool_mutation_allowed": False,
        "declared_authority_attempts": authority_attempt,
        "capability_maturity": {
            "current": str(declaration.get("capability_maturity") or "L1"),
            "assured_blocking_enabled": False,
            "blocking_requires_l3_plus_and_gate_wiring": True,
        },
        "profile_posture": posture,
        "thresholds": as_mapping(declaration.get("thresholds")),
        "telemetry_sources": source_metas,
        "records": sanitized_records,
        "evidence_refs": evidence_refs,
        "findings": findings,
        "reason_code_counts": reason_code_counts,
        "known_gaps": list(dict.fromkeys(known_gaps)),
        "residual_risks": list(dict.fromkeys(string_list(declaration.get("residual_risks")) + RESIDUAL_RISKS)),
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings) or bool_value(posture.get("human_review_required"), False),
        "generated_by": build_generated_by(root),
        "summary": summary,
    }


def build_expected_report(*, root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    declaration_path, declaration_source = resolve_declaration_path(root, naos_root, policy)
    return build_report(root=root, profile=profile, naos_root=naos_root, policy=policy,
                        declaration_path=declaration_path, declaration_source=declaration_source)


def validate_report(*, report: Any, root: Path, profile: str, naos_root: str, policy: dict[str, Any]) -> tuple[list[str], list[str]]:
    try:
        from naos_report_contracts import validate_current_report
    except ImportError:
        return ['consumer_unavailable'], ['Canonical report validation helper is unavailable; upgrade the installed scripts']
    return validate_current_report(
        report, schema_name='model_telemetry_evidence', source_hash_field='declaration_hash',
        expected=lambda: build_expected_report(root=root, profile=profile, naos_root=naos_root, policy=policy),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review local NAOS model telemetry evidence declarations.")
    parser.add_argument("project", nargs="?", default=".", help="Project root to evaluate.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--model-telemetry-evidence", help="Path to model_telemetry_evidence.yaml.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    declaration_path, declaration_source = resolve_declaration_path(
        root,
        naos_root,
        policy,
        args.model_telemetry_evidence,
    )
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        declaration_path=declaration_path,
        declaration_source=declaration_source,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "model_telemetry_evidence_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS model telemetry evidence: "
            f"{report['status']} "
            f"({report['summary'].get('total_findings', 0)} findings, "
            f"{report['summary'].get('records', 0)} records, "
            f"output: {output})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
