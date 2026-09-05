#!/usr/bin/env python3
"""Review governed learning lifecycle records without writing memory."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

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
    report_default_path,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.learning_loop_review.v1"

LEARNING_TYPES = {
    "fact",
    "rule",
    "failure_mode",
    "anti_pattern",
    "skill_update",
    "prompt_update",
    "workflow_update",
    "baseline_update",
    "gate_policy_update",
}
STATUSES = {
    "candidate",
    "verified",
    "active",
    "superseded",
    "deprecated",
    "archived",
    "rejected",
    "redacted",
}
ACTIVE_AUTHORITY_TYPES = {
    "skill_update",
    "prompt_update",
    "workflow_update",
    "baseline_update",
    "gate_policy_update",
}
ACTIVE_RETRIEVAL_POLICIES = {"active", "gated"}
INACTIVE_RETRIEVAL_POLICIES = {"suppressed", "archive_only"}
REDACTED_PAYLOAD_FIELDS = {
    "content",
    "payload",
    "raw_payload",
    "private_payload",
    "secret",
    "secret_value",
    "sensitive_payload",
    "memory_payload",
}
NOT_CLAIMED = [
    "self-learning model weights",
    "autonomous skill promotion",
    "automatic memory write-back",
    "automatic context injection",
    "hallucination prevention",
    "approval",
    "certification",
    "proof of compliance",
    "repo evidence replacement",
]
LIMITATIONS = [
    "This review is deterministic, local, and file-first.",
    "Learning records are governance metadata, not model memory or behavioral proof.",
    "Candidate learnings are proposal-only until reviewed and promoted by humans.",
    "Engram, MCP, provider, model, and network runtimes are not called.",
]


def utc_now_text() -> str:
    return controlled_utc_now_text()


def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(f"{raw}T00:00:00+00:00")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def now_datetime() -> datetime:
    return controlled_now_utc()


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def unique_strings(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            unique.append(value)
            seen.add(value)
    return unique


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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


def default_template(name: str) -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / name


def resolve_seed_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    path_key: str,
    template_name: str,
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    configured = str(policy.get("paths", {}).get(path_key) or template_name)
    project_path = root / naos_root / configured
    if project_path.exists():
        return project_path, "project"
    return default_template(template_name), "template"


def profile_posture(rules: dict[str, Any], profile: str) -> dict[str, Any]:
    configured = as_mapping(as_mapping(rules.get("profile_posture")).get(profile))
    if configured:
        return configured
    defaults = {
        "quickstart": {"state": "advisory", "severity": "advisory", "human_review_required_for_active_learning": False},
        "lite": {"state": "readiness_only", "severity": "warning", "human_review_required_for_active_learning": False},
        "standard": {"state": "readiness_only", "severity": "required", "human_review_required_for_active_learning": True},
        "assured": {"state": "readiness_only", "severity": "blocking", "human_review_required_for_active_learning": True},
    }
    return defaults.get(profile, defaults["quickstart"])


def severity_for_rules(root: Path, naos_root: str, profile: str, policy: dict[str, Any], posture: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    configured = str(posture.get("severity") or "").strip()
    if configured in {"advisory", "warning", "required", "blocking"}:
        return configured
    return severity_for_profile(profile, policy)


def finding(identifier: str, severity: str, status: str, message: str, actions: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": actions or [],
    }
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def load_records(path: Path, keys: list[str]) -> tuple[list[dict[str, Any]], bool, str | None]:
    if not path.exists():
        return [], False, None
    data = load_yaml_mapping(path)
    for key in keys:
        if key in data:
            records = [item for item in as_list(data.get(key)) if isinstance(item, dict)]
            return records, True, key
    records = [item for item in as_list(data.get("items")) if isinstance(item, dict)]
    return records, True, "items" if "items" in data else None


def record_id(record: dict[str, Any], source: str, index: int) -> str:
    value = record.get("id") or record.get("learning_id")
    return str(value).strip() if str(value or "").strip() else f"{source}_{index + 1}"


def source_reference_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for record in records:
        for ref in as_list(record.get("evidence_refs")):
            if isinstance(ref, dict):
                ref_type = str(ref.get("type") or "mapping")
            else:
                ref_type = "path_or_uri"
            counter[ref_type] += 1
    return dict(counter)


def local_ref_exists(root: Path, ref: Any) -> bool:
    path_value: str | None = None
    if isinstance(ref, dict):
        path_value = str(ref.get("path") or ref.get("source_path") or ref.get("ref") or "").strip()
    else:
        path_value = str(ref or "").strip()
    if not path_value:
        return False
    if path_value.startswith(("http://", "https://", "urn:", "doi:")):
        return True
    path = Path(path_value)
    if path.is_absolute() or ".." in path.parts:
        return False
    return (root / path).exists()


def promotion_review(record: dict[str, Any]) -> dict[str, Any]:
    review = as_mapping(record.get("promotion_review"))
    if review:
        return review
    return {
        "approved_by": record.get("promotion_approved_by"),
        "approved_at": record.get("promotion_approved_at"),
        "target_artifacts": record.get("target_artifacts"),
    }


def validate_record(
    *,
    record: dict[str, Any],
    record_id_value: str,
    source: str,
    root: Path,
    severity: str,
    current_time: datetime,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    status = str(record.get("status") or "").strip()
    learning_type = str(record.get("type") or "").strip()
    retrieval_policy = str(record.get("retrieval_policy") or "").strip()

    if status not in STATUSES:
        findings.append(
            finding(
                f"{record_id_value}_invalid_status",
                severity,
                "invalid_learning_record",
                f"Learning record {record_id_value} has unsupported status {status!r}.",
                ["Use one of the governed learning lifecycle statuses."],
                source=source,
            )
        )
    if learning_type not in LEARNING_TYPES:
        findings.append(
            finding(
                f"{record_id_value}_invalid_type",
                severity,
                "invalid_learning_record",
                f"Learning record {record_id_value} has unsupported type {learning_type!r}.",
                ["Use one of the governed learning lifecycle types."],
                source=source,
            )
        )

    if source == "candidates" and status not in {"candidate", "verified", "rejected"}:
        findings.append(
            finding(
                f"{record_id_value}_candidate_file_invalid_status",
                severity,
                "candidate_authority_overclaim",
                "Learning candidates may only be candidate, verified, or rejected.",
                ["Move active or historical records to the correct governed learning file."],
            )
        )
    if source == "state" and status != "active":
        findings.append(
            finding(
                f"{record_id_value}_state_file_invalid_status",
                severity,
                "active_state_invalid",
                "learning_state.yaml must contain active reviewed learnings only.",
                ["Move non-active records to candidates or history."],
            )
        )
    if source == "history" and status not in {"superseded", "deprecated", "archived", "rejected", "redacted"}:
        findings.append(
            finding(
                f"{record_id_value}_history_file_invalid_status",
                severity,
                "history_state_invalid",
                "learning_history.yaml must contain inactive historical records only.",
                ["Move candidate or active records to their governed learning file."],
            )
        )

    if status in {"candidate", "verified"} and retrieval_policy in ACTIVE_RETRIEVAL_POLICIES:
        findings.append(
            finding(
                f"{record_id_value}_candidate_active_retrieval",
                severity,
                "candidate_authority_overclaim",
                "Candidate or verified learning cannot use active retrieval policy before promotion.",
                ["Set retrieval_policy to suppressed/archive_only or promote through reviewed active learning metadata."],
            )
        )

    if status == "active":
        required_fields = [
            "scope",
            "evidence_refs",
            "source_session",
            "verified_by",
            "approved_by",
            "review_after",
            "risk",
            "retrieval_policy",
            "limitations",
        ]
        for field_name in required_fields:
            value = record.get(field_name)
            if value in (None, "", []) or (field_name in {"evidence_refs", "limitations"} and not string_list(value)):
                findings.append(
                    finding(
                        f"{record_id_value}_active_missing_{field_name}",
                        severity,
                        "active_learning_missing_metadata",
                        f"Active learning {record_id_value} is missing required field {field_name}.",
                        ["Add explicit reviewed metadata before using this learning as active guidance."],
                    )
                )
        if retrieval_policy not in ACTIVE_RETRIEVAL_POLICIES:
            findings.append(
                finding(
                    f"{record_id_value}_active_retrieval_policy",
                    severity,
                    "active_learning_not_retrievable",
                    "Active learning must declare retrieval_policy active or gated.",
                    ["Set a scoped active/gated retrieval policy or archive the record."],
                )
            )
        review_after = parse_datetime(record.get("review_after"))
        if record.get("review_after") and review_after is None:
            findings.append(
                finding(
                    f"{record_id_value}_review_after_invalid",
                    severity,
                    "invalid_review_date",
                    "Active learning review_after must be an ISO date or datetime.",
                    ["Use an ISO date such as 2026-12-31."],
                )
            )
        elif review_after and review_after < current_time:
            findings.append(
                finding(
                    f"{record_id_value}_review_after_stale",
                    severity,
                    "stale_learning",
                    "Active learning is past its review_after date.",
                    ["Review, renew, supersede, deprecate, archive, or redact the learning."],
                )
            )
        evidence_refs = as_list(record.get("evidence_refs"))
        missing_refs = [ref for ref in evidence_refs if not local_ref_exists(root, ref)]
        if missing_refs:
            findings.append(
                finding(
                    f"{record_id_value}_evidence_refs_missing",
                    severity,
                    "missing_learning_evidence",
                    "Active learning references missing or unsafe evidence paths.",
                    ["Point evidence_refs to existing repo-local artifacts or verified external references."],
                    missing_count=len(missing_refs),
                )
            )
        if learning_type in ACTIVE_AUTHORITY_TYPES:
            review = promotion_review(record)
            missing_promotion = [
                field_name
                for field_name in ("approved_by", "approved_at", "target_artifacts")
                if review.get(field_name) in (None, "", [])
            ]
            if missing_promotion:
                findings.append(
                    finding(
                        f"{record_id_value}_promotion_review_missing",
                        severity,
                        "promotion_review_missing",
                        "High-authority learning requires explicit promotion review metadata.",
                        ["Add promotion_review.approved_by, approved_at, and target_artifacts before changing skills/prompts/workflows/baselines/gates."],
                        missing_fields=missing_promotion,
                    )
                )

    if status == "superseded" and not str(record.get("replaced_by") or "").strip():
        findings.append(
            finding(
                f"{record_id_value}_superseded_replaced_by_missing",
                severity,
                "superseded_learning_missing_successor",
                "Superseded learning must identify replaced_by.",
                ["Link the superseding learning id."],
            )
        )
    if status == "deprecated" and (not str(record.get("reason") or "").strip() or not str(record.get("review_path") or "").strip()):
        findings.append(
            finding(
                f"{record_id_value}_deprecated_review_path_missing",
                severity,
                "deprecated_learning_missing_review_path",
                "Deprecated learning requires reason and review_path.",
                ["Document why it was deprecated and how reviewers should resolve it."],
            )
        )
    if status in {"archived", "rejected", "superseded", "deprecated"} and retrieval_policy not in INACTIVE_RETRIEVAL_POLICIES:
        findings.append(
            finding(
                f"{record_id_value}_inactive_retrieval_policy",
                severity,
                "inactive_learning_retrievable",
                "Inactive learning must not be retrievable as active guidance.",
                ["Set retrieval_policy to archive_only or suppressed."],
            )
        )
    if status == "redacted":
        if not str(record.get("redaction_reason") or "").strip():
            findings.append(
                finding(
                    f"{record_id_value}_redaction_reason_missing",
                    severity,
                    "redacted_learning_missing_reason",
                    "Redacted learning requires a redaction_reason.",
                    ["Keep safe audit metadata and document why payload was removed."],
                )
            )
        retained_payload_fields = [field_name for field_name in REDACTED_PAYLOAD_FIELDS if record.get(field_name) not in (None, "", [])]
        if retained_payload_fields:
            findings.append(
                finding(
                    f"{record_id_value}_redacted_payload_retained",
                    severity,
                    "redacted_learning_payload_retained",
                    "Redacted learning must not retain sensitive payload fields.",
                    ["Remove content/private payload fields and retain only safe audit metadata."],
                    retained_fields=retained_payload_fields,
                )
            )
        if retrieval_policy != "archive_only":
            findings.append(
                finding(
                    f"{record_id_value}_redacted_retrieval_policy",
                    severity,
                    "redacted_learning_retrievable",
                    "Redacted learning must be archive_only.",
                    ["Set retrieval_policy to archive_only."],
                )
            )

    return findings


def safe_record_summary(record: dict[str, Any], record_id_value: str, source: str) -> dict[str, Any]:
    return {
        "id": record_id_value,
        "source": source,
        "type": record.get("type"),
        "status": record.get("status"),
        "scope": record.get("scope"),
        "risk": record.get("risk"),
        "retrieval_policy": record.get("retrieval_policy"),
        "review_after": record.get("review_after"),
        "replaces": record.get("replaces"),
        "replaced_by": record.get("replaced_by"),
        "evidence_ref_count": len(as_list(record.get("evidence_refs"))),
        "limitations_count": len(string_list(record.get("limitations"))),
    }


def failure_mode_review_severity(severity: str) -> str:
    if severity == "blocking":
        return "required"
    return severity if severity in {"advisory", "warning", "required"} else "advisory"


def load_failure_mode_observations_review(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    severity: str,
) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "failure_mode_observations_report")
    review_severity = failure_mode_review_severity(severity)
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "report_present": False,
            "summary": {},
            "review_opportunities": {},
            "findings": [],
            "human_review_required": False,
            "automatic_learning_allowed": False,
            "candidate_write_allowed": False,
            "rule": "Failure-mode observations are visible to learning-loop review when generated; missing reports do not imply absence of failure patterns or approval.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings = [
            finding(
                "failure_mode_observations_review_input_unreadable",
                review_severity,
                "failure_mode_observations_review_input_unreadable",
                "Failure-mode observations report could not be read for learning-loop review.",
                ["Regenerate or repair naos/reports/failure_mode_observations.json before using it to scope learning review."],
                error=str(exc),
                source_path=str(path),
            )
        ]
        return {
            "status": "parse_error",
            "path": str(path),
            "report_present": True,
            "summary": {"failure_mode_observation_review_findings": len(findings)},
            "review_opportunities": {},
            "findings": findings,
            "human_review_required": True,
            "automatic_learning_allowed": False,
            "candidate_write_allowed": False,
            "rule": "Unreadable failure-mode observations require repair before learning-loop review can use them.",
        }

    summary = as_mapping(data.get("summary"))
    raw_review_opportunities = data.get("review_opportunities")
    review_opportunities = raw_review_opportunities if isinstance(raw_review_opportunities, list) else []
    mode_counts = as_mapping(data.get("mode_observation_counts"))
    recurring_from_report: dict[str, Any] = {}
    for item in review_opportunities:
        if isinstance(item, dict) and item.get("type") == "recurring_mode_observations":
            recurring_from_report = as_mapping(item.get("mode_counts"))
            break
    recurring_modes = {
        str(mode_id): int(count)
        for mode_id, count in {**mode_counts, **recurring_from_report}.items()
        if isinstance(count, int) and count > 1
    }
    unmapped_count = int(summary.get("unmapped_observations") or 0)
    high_severity_count = int(summary.get("high_severity_observations") or 0)
    source_review_count = int(summary.get("source_reports_requiring_review") or 0)
    observation_count = int(summary.get("observations") or 0)

    findings: list[dict[str, Any]] = []
    if unmapped_count:
        findings.append(
            finding(
                "failure_mode_observations_mapping_review_required",
                review_severity,
                "failure_mode_observation_mapping_review_required",
                "Failure-mode observations include unmapped findings that need human taxonomy review before learning-loop use.",
                ["Review unmapped observation reason codes and update mappings only through approved governance changes."],
                source_path=str(path),
                unmapped_observations=unmapped_count,
            )
        )
    if recurring_modes:
        findings.append(
            finding(
                "failure_mode_observations_learning_review_opportunity",
                review_severity,
                "failure_mode_observation_learning_review_opportunity",
                "Recurring failure-mode observations may justify a human-reviewed learning or autoresearch candidate.",
                ["Review recurrence evidence and decide whether to create a learning candidate or research task manually."],
                source_path=str(path),
                recurring_mode_counts=recurring_modes,
            )
        )
    if high_severity_count or source_review_count or bool(data.get("human_review_required")):
        findings.append(
            finding(
                "failure_mode_observations_human_review_required",
                review_severity,
                "failure_mode_observation_human_review_required",
                "Failure-mode observations require human review before they can inform learning-loop or autoresearch decisions.",
                ["Keep observations as review evidence; do not automatically mutate memory, prompts, skills, gates, or baselines."],
                source_path=str(path),
                high_severity_observations=high_severity_count,
                source_reports_requiring_review=source_review_count,
            )
        )

    review_summary = {
        "observations": observation_count,
        "unmapped_observations": unmapped_count,
        "high_severity_observations": high_severity_count,
        "source_reports_requiring_review": source_review_count,
        "recurring_modes": len(recurring_modes),
        "failure_mode_observation_review_findings": len(findings),
    }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "report_present": True,
        "summary": review_summary,
        "review_opportunities": review_opportunities,
        "recurring_mode_counts": recurring_modes,
        "findings": findings,
        "human_review_required": bool(findings),
        "automatic_learning_allowed": False,
        "candidate_write_allowed": False,
        "limitations": [
            "Failure-mode observations can focus learning-loop review but do not create learning records.",
            "Observation counts are review statistics, not numeric risk score authority.",
        ],
        "not_claimed": [
            "automatic learning from failure-mode observations",
            "prompt or skill mutation",
            "MCP, Engram, memory, provider, or model activation",
        ],
        "rule": "Failure-mode observations can inform human-reviewed learning-loop or autoresearch scoping only; this review does not write learning records or mutate governed artifacts.",
    }


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, int]]:
    root = Path(args.root or ".").resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    posture_rules_path, _ = resolve_seed_path(root, naos_root, policy, "learning_loop_rules", "learning_loop_rules.yaml", args.rules)
    rules = load_yaml_mapping(posture_rules_path) if posture_rules_path.exists() else {}
    posture = profile_posture(rules, profile)
    severity = severity_for_rules(root, naos_root, profile, policy, posture)
    current_time = now_datetime()

    paths = {
        "rules": posture_rules_path,
        "candidates": resolve_seed_path(root, naos_root, policy, "learning_candidates", "learning_candidates.yaml", args.candidates)[0],
        "state": resolve_seed_path(root, naos_root, policy, "learning_state", "learning_state.yaml", args.state)[0],
        "history": resolve_seed_path(root, naos_root, policy, "learning_history", "learning_history.yaml", args.history)[0],
    }

    candidates, candidates_present, candidates_key = load_records(paths["candidates"], ["learning_candidates", "candidates"])
    active, state_present, state_key = load_records(paths["state"], ["active_learnings", "learning_state", "learnings"])
    history, history_present, history_key = load_records(paths["history"], ["learning_history", "history"])

    source_records = [
        ("candidates", candidates),
        ("state", active),
        ("history", history),
    ]
    findings: list[dict[str, Any]] = []
    all_records: list[tuple[str, dict[str, Any], str]] = []
    seen_ids: dict[str, str] = {}
    duplicate_ids: list[str] = []

    for source, records in source_records:
        for index, record in enumerate(records):
            rid = record_id(record, source, index)
            all_records.append((source, record, rid))
            if rid in seen_ids:
                duplicate_ids.append(rid)
                findings.append(
                    finding(
                        f"{rid}_duplicate_learning_id",
                        severity,
                        "duplicate_learning_id",
                        "Learning ids must be unique across candidate, active, and history files.",
                        ["Rename or merge duplicate records before relying on the learning lifecycle."],
                        first_source=seen_ids[rid],
                        duplicate_source=source,
                    )
                )
            else:
                seen_ids[rid] = source

    for source, record, rid in all_records:
        findings.extend(
            validate_record(
                record=record,
                record_id_value=rid,
                source=source,
                root=root,
                severity=severity,
                current_time=current_time,
            )
        )

    failure_mode_observations_review = load_failure_mode_observations_review(root, naos_root, policy, severity)
    findings.extend(failure_mode_observations_review.get("findings") or [])

    status_counts = Counter(str(record.get("status") or "unknown") for _, record, _ in all_records)
    type_counts = Counter(str(record.get("type") or "unknown") for _, record, _ in all_records)
    retrieval_counts = Counter(str(record.get("retrieval_policy") or "unset") for _, record, _ in all_records)
    active_records = [record for source, record, _ in all_records if source == "state"]
    high_authority_active = [
        safe_record_summary(record, rid, source)
        for source, record, rid in all_records
        if source == "state" and str(record.get("type") or "") in ACTIVE_AUTHORITY_TYPES
    ]
    redacted_records = [
        safe_record_summary(record, rid, source)
        for source, record, rid in all_records
        if str(record.get("status") or "") == "redacted"
    ]
    inactive_records = [
        safe_record_summary(record, rid, source)
        for source, record, rid in all_records
        if str(record.get("status") or "") in {"superseded", "deprecated", "archived", "rejected", "redacted"}
    ]

    summary = finding_counts(findings)
    summary.update(
        {
            "learning_records": len(all_records),
            "candidate_records": len(candidates),
            "active_records": len(active),
            "history_records": len(history),
            "high_authority_active_records": len(high_authority_active),
            "redacted_records": len(redacted_records),
            "duplicate_learning_ids": len(duplicate_ids),
            "failure_mode_observation_review_findings": len(failure_mode_observations_review.get("findings") or []),
            "failure_mode_observations": int(
                (failure_mode_observations_review.get("summary") or {}).get("observations") or 0
            ),
            "failure_mode_observation_recurring_modes": int(
                (failure_mode_observations_review.get("summary") or {}).get("recurring_modes") or 0
            ),
        }
    )

    human_review_required = bool(findings) or (
        bool(active_records) and bool(posture.get("human_review_required_for_active_learning", False))
    )
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(paths["rules"]),
        "rules_hash": safe_digest(paths["rules"]),
        "candidate_path": str(paths["candidates"]),
        "candidate_hash": safe_digest(paths["candidates"]),
        "candidate_key": candidates_key,
        "candidate_present": candidates_present,
        "state_path": str(paths["state"]),
        "state_hash": safe_digest(paths["state"]),
        "state_key": state_key,
        "state_present": state_present,
        "history_path": str(paths["history"]),
        "history_hash": safe_digest(paths["history"]),
        "history_key": history_key,
        "history_present": history_present,
        "profile_posture": posture,
        "status_counts": dict(status_counts),
        "type_counts": dict(type_counts),
        "retrieval_policy_counts": dict(retrieval_counts),
        "source_reference_summary": source_reference_summary([record for _, record, _ in all_records]),
        "failure_mode_observations_review": failure_mode_observations_review,
        "active_learning_records": [safe_record_summary(record, rid, source) for source, record, rid in all_records if source == "state"],
        "high_authority_active_records": high_authority_active,
        "inactive_learning_records": inactive_records,
        "redacted_learning_records": redacted_records,
        "findings": findings,
        "known_gaps": as_list(rules.get("known_gaps")),
        "residual_risks": as_list(rules.get("residual_risks")),
        "waivers": as_list(rules.get("waivers")),
        "limitations": unique_strings(
            LIMITATIONS
            + string_list(rules.get("limitations"))
            + string_list(failure_mode_observations_review.get("limitations"))
        ),
        "not_claimed": unique_strings(
            NOT_CLAIMED
            + string_list(rules.get("not_claimed"))
            + string_list(failure_mode_observations_review.get("not_claimed"))
        ),
        "human_review_required": human_review_required,
        "summary": summary,
    }
    return report, summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review governed learning lifecycle records without memory write-back.")
    parser.add_argument("--root", default=".", help="Project root to inspect.")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--naos-root", default=None)
    parser.add_argument("--policy", default=None)
    parser.add_argument("--rules", default=None, help="Explicit learning_loop_rules.yaml path.")
    parser.add_argument("--candidates", default=None, help="Explicit learning_candidates.yaml path.")
    parser.add_argument("--state", default=None, help="Explicit learning_state.yaml path.")
    parser.add_argument("--history", default=None, help="Explicit learning_history.yaml path.")
    parser.add_argument("--output", default=None, help="Output report path. Defaults to NAOS reports dir.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    parser.add_argument("--strict", action="store_true", help="Apply strict profile exit policy.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, summary = build_report(args)
    root = Path(args.root or ".").resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "learning_loop_review_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code_for_summary(profile, summary, policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
