#!/usr/bin/env python3
"""Record deterministic task claim/release coordination metadata for NAOS."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    controlled_utc_now_text,
    default_naos_root,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    resolve_operator_attribution,
    session_report_default_path,
    sessions_index_path,
    validate_operator_value,
    write_report_with_session,
)
from naos_session_identity import record_session_report_reference  # noqa: E402

try:  # noqa: E402
    from naos_audit_log import write_audit_event
except Exception:  # pragma: no cover - audit log remains optional in quickstart
    write_audit_event = None  # type: ignore[assignment]


CLAIMS_SCHEMA = "naos.task_claims.v1"
REPORT_SCHEMA = "naos.task_claim_report.v1"
TASK_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
SAFE_FRAGMENT_RE = re.compile(r"[^A-Za-z0-9._:@+-]+")
CLAIM_STATUSES = {"active", "released", "expired", "stale", "conflicting", "unknown"}

LIMITATIONS = [
    "Task claims are coordination metadata only; they are not authorization, approval, ownership proof, task completion, or a security boundary.",
    "Claims are stored in a local YAML file and can be changed by repository writers unless external controls protect the repository.",
    "Expiration and stale detection are deterministic timestamps; they do not resolve conflicts or decide who may work.",
    "Operator attribution is local metadata only; it is not authentication, authorization, non-repudiation, or separation-of-duties evidence.",
]
NOT_CLAIMED = [
    "authorization",
    "approval",
    "task ownership proof",
    "legal ownership",
    "separation-of-duties approval",
    "task completion",
    "evidence conflict resolution",
    "exclusive access security boundary",
    "compliance proof",
    "source of truth",
    "full multi-user completion",
]
RESIDUAL_RISKS = [
    "claims_can_be_modified_by_repository_writers",
    "stale_claims_may_not_reflect_actual_work_state",
    "unknown_operator_reduces_coordination_value",
    "branch_metadata_may_be_unavailable_or_stale",
    "conflicting_claims_require_human_review",
    "human_review_required",
]


def utc_now_text() -> str:
    return controlled_utc_now_text()


def parse_timestamp(value: Any) -> datetime | None:
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


def timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_fragment(value: Any, fallback: str = "item", max_length: int = 96) -> str:
    cleaned = SAFE_FRAGMENT_RE.sub("_", str(value or "").strip())[:max_length].strip("._-")
    return cleaned or fallback


def validate_task_id(value: str | None) -> tuple[str | None, dict[str, Any] | None]:
    raw = "" if value is None else str(value)
    task_id = raw.strip()
    if not task_id:
        return None, {
            "id": "task_claim.invalid_task_id",
            "severity": "warning",
            "status": "invalid_claims",
            "message": "Task id is required for claim/release actions.",
        }
    reason = ""
    if any(ord(ch) < 32 for ch in task_id):
        reason = "control_character"
    elif len(task_id) > 128:
        reason = "too_long"
    elif "/" in task_id or "\\" in task_id or ".." in task_id:
        reason = "path_like_or_traversal"
    elif not TASK_ID_PATTERN.fullmatch(task_id):
        reason = "invalid_pattern"
    if reason:
        return None, {
            "id": "task_claim.invalid_task_id",
            "severity": "warning",
            "status": "invalid_claims",
            "message": "Task id is not filesystem/log safe.",
            "reason": reason,
            "safe_pattern": TASK_ID_PATTERN.pattern,
        }
    return task_id, None


def claim_id(now: str, task_id: str) -> str:
    return f"claim-{safe_fragment(task_id, 'task', 40)}-{safe_fragment(now, 'time', 24)}-{uuid.uuid4().hex[:12]}"


def claims_file_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    configured = str(policy.get("paths", {}).get("task_claims_file") or "task_claims.yaml")
    return root / naos_root / configured


def report_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    return report_output_path(root, naos_root, policy, "task_claim_report")


def default_ttl_hours(policy: dict[str, Any]) -> int:
    value = policy.get("task_claims", {}).get("default_ttl_hours")
    if value is None:
        value = policy.get("task_claim_default_ttl_hours")
    try:
        hours = int(value)
    except Exception:
        hours = 72
    return max(1, min(hours, 24 * 30))


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    path = sessions_index_path(root, naos_root, policy)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id")
    return str(value) if value else None


def current_branch(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    branch = result.stdout.strip()
    return branch or "unknown"


def load_claims(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    if not path.exists():
        findings.append(
            {
                "id": "task_claims.claim_file_missing",
                "severity": "advisory",
                "status": "not_configured",
                "message": "Task claims file is missing; an empty file will be created for claim/release actions.",
            }
        )
        return {"schema": CLAIMS_SCHEMA, "updated_at": None, "claims": []}, findings
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {"schema": CLAIMS_SCHEMA, "updated_at": None, "claims": []}, [
            {
                "id": "task_claims.invalid_claim_schema",
                "severity": "warning",
                "status": "invalid_claims",
                "message": f"Task claims file could not be parsed: {exc}",
            }
        ]
    if not isinstance(data, dict) or not isinstance(data.get("claims"), list):
        findings.append(
            {
                "id": "task_claims.invalid_claim_schema",
                "severity": "warning",
                "status": "invalid_claims",
                "message": "Task claims file is not a mapping with a claims list.",
            }
        )
        return {"schema": CLAIMS_SCHEMA, "updated_at": None, "claims": []}, findings
    data.setdefault("schema", CLAIMS_SCHEMA)
    data.setdefault("updated_at", None)
    data["claims"] = [item for item in data.get("claims") or [] if isinstance(item, dict)]
    return data, findings


def atomic_write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        handle.write(yaml.safe_dump(data, sort_keys=False))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def claim_status_for(claim: dict[str, Any], now: datetime, ttl_hours: int) -> str:
    status = str(claim.get("status") or "unknown")
    if status not in CLAIM_STATUSES:
        return "unknown"
    if status in {"released", "conflicting", "expired", "stale"}:
        return status
    claimed_at = parse_timestamp(claim.get("claimed_at"))
    expires_at = parse_timestamp(claim.get("expires_at"))
    if expires_at and now > expires_at:
        return "expired"
    if claimed_at and now > claimed_at + timedelta(hours=ttl_hours):
        return "stale"
    return status


def normalize_claims(claims: list[dict[str, Any]], now: datetime, ttl_hours: int, *, mutate: bool) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in claims:
        claim = dict(item)
        status = claim_status_for(claim, now, ttl_hours)
        if mutate and status != claim.get("status"):
            claim["status"] = status
        claim.setdefault("limitations", LIMITATIONS)
        claim.setdefault("not_claimed", NOT_CLAIMED)
        claim.setdefault("human_review_required", True)
        normalized.append(claim)
    return normalized


def active_claims_for_task(claims: list[dict[str, Any]], task_id: str) -> list[dict[str, Any]]:
    return [claim for claim in claims if claim.get("task_id") == task_id and claim.get("status") == "active"]


def resolve_operator(root: Path, explicit: str | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    if explicit is not None:
        operator_id, invalid, detected = validate_operator_value(explicit, "cli")
        if invalid:
            findings.append(
                {
                    "id": "task_claim.unknown_operator",
                    "severity": "warning",
                    "status": "review_required",
                    "message": "Explicit operator id is invalid and was not used.",
                    "details": invalid,
                }
            )
            return {
                "operator_id": None,
                "operator_source": "unknown",
                "operator_attribution_status": "unknown",
            }, findings
        return {
            "operator_id": operator_id if detected else None,
            "operator_source": "cli" if detected else "unknown",
            "operator_attribution_status": "resolved" if detected else "unknown",
        }, findings
    operator = resolve_operator_attribution(root)
    if not operator.get("operator_id"):
        findings.append(
            {
                "id": "task_claim.unknown_operator",
                "severity": "advisory",
                "status": "review_required",
                "message": "No operator id was resolved; set NAOS_OPERATOR_ID for stable team coordination.",
            }
        )
    return operator, findings


def generated_by_for(root: Path, session_id: str | None, generated_at: str, operator: dict[str, Any]) -> dict[str, Any]:
    generated_by = build_generated_by(root, session_id=session_id, generated_at=generated_at)
    if operator.get("operator_id") and not generated_by.get("operator_id"):
        generated_by["operator_id"] = operator.get("operator_id")
        generated_by["operator_source"] = operator.get("operator_source") or "unknown"
        generated_by["operator_attribution_status"] = operator.get("operator_attribution_status") or "resolved"
    return generated_by


def make_claim(
    *,
    root: Path,
    task_id: str,
    operator: dict[str, Any],
    session_id: str | None,
    branch: str,
    now_text: str,
    ttl_hours: int,
    status: str = "active",
    risk_tier: str | None = None,
) -> dict[str, Any]:
    claimed_at = parse_timestamp(now_text)
    if claimed_at is None:
        raise ValueError("now_text must be a valid ISO timestamp.")
    return {
        "claim_id": claim_id(now_text, task_id),
        # Advisory per-task risk routing metadata (QW1/AP5); coordination input only.
        "risk_tier": risk_tier,
        "task_id": task_id,
        "operator_id": operator.get("operator_id"),
        "operator_source": operator.get("operator_source") or "unknown",
        "session_id": session_id,
        "branch": branch,
        "claimed_at": now_text,
        "expires_at": timestamp_text(claimed_at + timedelta(hours=ttl_hours)),
        "released_at": None,
        "status": status,
        "claim_source": "naos_task_claims",
        "generated_by": generated_by_for(root, session_id, now_text, operator),
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }


def build_findings(
    *,
    action: str,
    claims: list[dict[str, Any]],
    load_findings: list[dict[str, Any]],
    operator_findings: list[dict[str, Any]],
    task_finding: dict[str, Any] | None,
    branch: str,
    session_id: str | None,
) -> list[dict[str, Any]]:
    findings = list(load_findings) + list(operator_findings)
    if task_finding is not None:
        findings.append(task_finding)
    if action in {"claim", "release"} and branch == "unknown":
        findings.append(
            {
                "id": "task_claim.missing_branch",
                "severity": "advisory",
                "status": "advisory",
                "message": "Current git branch could not be resolved locally.",
            }
        )
    if action in {"claim", "release"} and not session_id:
        findings.append(
            {
                "id": "task_claim.missing_session_id",
                "severity": "advisory",
                "status": "review_required",
                "message": "No session id is available; run naos session-id for namespaced report context.",
            }
        )
    for claim in claims:
        if claim.get("status") == "conflicting":
            findings.append(
                {
                    "id": f"task_claim.conflict_unresolved.{claim.get('claim_id')}",
                    "severity": "warning",
                    "status": "review_required",
                    "message": "Task claim conflict requires human review; no authorization or conflict resolution is implied.",
                    "task_id": claim.get("task_id"),
                }
            )
        elif claim.get("status") == "expired":
            findings.append(
                {
                    "id": f"task_claim.expired.{claim.get('claim_id')}",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": "Expired task claim detected.",
                    "task_id": claim.get("task_id"),
                }
            )
        elif claim.get("status") == "stale":
            findings.append(
                {
                    "id": f"task_claim.stale.{claim.get('claim_id')}",
                    "severity": "warning",
                    "status": "review_required",
                    "message": "Stale task claim detected.",
                    "task_id": claim.get("task_id"),
                }
            )
        if not claim.get("operator_id"):
            findings.append(
                {
                    "id": f"task_claim.unknown_operator_claim.{claim.get('claim_id')}",
                    "severity": "advisory",
                    "status": "review_required",
                    "message": "Claim is missing operator attribution.",
                    "task_id": claim.get("task_id"),
                }
            )
        if not claim.get("session_id"):
            findings.append(
                {
                    "id": f"task_claim.missing_session_claim.{claim.get('claim_id')}",
                    "severity": "advisory",
                    "status": "review_required",
                    "message": "Claim is missing session id.",
                    "task_id": claim.get("task_id"),
                }
            )
    findings.append(
        {
            "id": "task_claims.coordination_metadata_only",
            "severity": "advisory",
            "status": "advisory",
            "message": "Task claims coordinate work; they are not authorization, approval, ownership proof, task completion, or separation-of-duties evidence.",
        }
    )
    return findings


def status_for_report(action_status: str, claims: list[dict[str, Any]], findings: list[dict[str, Any]], profile: str) -> str:
    if action_status in {"claim_created", "claim_released", "invalid_claims"}:
        return action_status
    if not claims:
        return "no_claims"
    if any(claim.get("status") == "conflicting" for claim in claims):
        return "review_required" if profile in {"standard", "assured"} else "conflicts_detected"
    if any(claim.get("status") == "stale" for claim in claims) and profile in {"standard", "assured"}:
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def summarize_claims(claims: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {
        "active_claims": [claim for claim in claims if claim.get("status") == "active"],
        "released_claims": [claim for claim in claims if claim.get("status") == "released"],
        "expired_claims": [claim for claim in claims if claim.get("status") == "expired"],
        "stale_claims": [claim for claim in claims if claim.get("status") == "stale"],
        "conflicting_claims": [claim for claim in claims if claim.get("status") == "conflicting"],
        "unknown_operator_claims": [claim for claim in claims if not claim.get("operator_id")],
        "missing_session_claims": [claim for claim in claims if not claim.get("session_id")],
    }


def apply_action(
    *,
    root: Path,
    action: str,
    data: dict[str, Any],
    task_id: str | None,
    operator: dict[str, Any],
    session_id: str | None,
    branch: str,
    now_text: str,
    ttl_hours: int,
    risk_tier: str | None = None,
) -> tuple[dict[str, Any], str, list[dict[str, Any]], bool, str | None]:
    findings: list[dict[str, Any]] = []
    now = parse_timestamp(now_text)
    if now is None:
        raise ValueError("now_text must be a valid ISO timestamp.")
    claims = normalize_claims(list(data.get("claims") or []), now, ttl_hours, mutate=True)
    changed = claims != data.get("claims", [])
    audit_event_type: str | None = None
    if action == "claim" and task_id:
        active = active_claims_for_task(claims, task_id)
        same = [
            claim
            for claim in active
            if claim.get("operator_id") == operator.get("operator_id")
            and (not session_id or not claim.get("session_id") or claim.get("session_id") == session_id)
        ]
        different = [
            claim
            for claim in active
            if claim.get("operator_id") != operator.get("operator_id")
            or (session_id and claim.get("session_id") and claim.get("session_id") != session_id)
        ]
        if same:
            findings.append(
                {
                    "id": "task_claim.already_active",
                    "severity": "advisory",
                    "status": "ready",
                    "message": "Same operator/session already has an active claim for this task.",
                    "task_id": task_id,
                }
            )
            action_status = "ready"
        elif different:
            conflict_claim = make_claim(
                root=root,
                task_id=task_id,
                operator=operator,
                session_id=session_id,
                branch=branch,
                now_text=now_text,
                ttl_hours=ttl_hours,
                status="conflicting",
                risk_tier=risk_tier,
            )
            claims.append(conflict_claim)
            changed = True
            action_status = "conflicts_detected"
            audit_event_type = "task_claim_conflict_detected"
            findings.append(
                {
                    "id": "task_claim.active_claim_exists",
                    "severity": "warning",
                    "status": "review_required",
                    "message": "Another active unexpired claim exists for this task; no overwrite occurred.",
                    "task_id": task_id,
                    "existing_claim_ids": [claim.get("claim_id") for claim in different],
                }
            )
        else:
            new_claim = make_claim(
                root=root,
                task_id=task_id,
                operator=operator,
                session_id=session_id,
                branch=branch,
                now_text=now_text,
                ttl_hours=ttl_hours,
                status="active",
                risk_tier=risk_tier,
            )
            claims.append(new_claim)
            changed = True
            action_status = "claim_created"
            audit_event_type = "task_claimed"
    elif action == "release" and task_id:
        matching = [
            claim
            for claim in claims
            if claim.get("task_id") == task_id
            and claim.get("status") == "active"
            and (not operator.get("operator_id") or claim.get("operator_id") == operator.get("operator_id"))
            and (not session_id or not claim.get("session_id") or claim.get("session_id") == session_id)
        ]
        if matching:
            for claim in matching:
                claim["status"] = "released"
                claim["released_at"] = now_text
            changed = True
            action_status = "claim_released"
            audit_event_type = "task_released"
        else:
            findings.append(
                {
                    "id": "task_claim.release_no_matching_active_claim",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": "Release requested but no matching active claim was found.",
                    "task_id": task_id,
                }
            )
            action_status = "advisory"
    else:
        action_status = "ready"
    data["schema"] = CLAIMS_SCHEMA
    data["updated_at"] = now_text if changed else data.get("updated_at")
    data["claims"] = claims
    return data, action_status, findings, changed, audit_event_type


def build_report(
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    action: str,
    task_id: str | None,
    session_id: str | None,
    operator: dict[str, Any],
    branch: str,
    claims_path: Path,
    data: dict[str, Any],
    load_findings: list[dict[str, Any]],
    operator_findings: list[dict[str, Any]],
    task_finding: dict[str, Any] | None,
    action_findings: list[dict[str, Any]],
    action_status: str,
    audit_result: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    claims = list(data.get("claims") or [])
    findings = build_findings(
        action=action,
        claims=claims,
        load_findings=load_findings,
        operator_findings=operator_findings,
        task_finding=task_finding,
        branch=branch,
        session_id=session_id,
    )
    findings.extend(action_findings)
    if audit_result and audit_result.get("status") not in {"written", None}:
        findings.extend(audit_result.get("findings") or [])
    categorized = summarize_claims(claims)
    status = status_for_report(action_status, claims, findings, profile)
    if action_status in {"claim_created", "claim_released"}:
        status = action_status
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "operator_id": operator.get("operator_id"),
        "generated_by": generated_by_for(root, session_id, generated_at, operator),
        "claims_file": str(claims_path),
        "claim_count": len(claims),
        "active_claim_count": len(categorized["active_claims"]),
        "released_claim_count": len(categorized["released_claims"]),
        "expired_claim_count": len(categorized["expired_claims"]),
        "stale_claim_count": len(categorized["stale_claims"]),
        "conflicting_claim_count": len(categorized["conflicting_claims"]),
        "claims": claims,
        **categorized,
        "findings": findings,
        "known_gaps": [
            "authorization_access_control_deferred",
            "team_operator_policy_overlays_deferred",
            "separation_of_duties_approval_deferred",
            "conflict_resolution_workflow_deferred",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings or categorized["conflicting_claims"] or categorized["stale_claims"] or categorized["unknown_operator_claims"]),
        "audit_log_event": audit_result or {},
        "summary": {
            "action": action,
            "task_id": task_id,
            "status": status,
            "claim_count": len(claims),
            "active_claims": len(categorized["active_claims"]),
            "released_claims": len(categorized["released_claims"]),
            "expired_claims": len(categorized["expired_claims"]),
            "stale_claims": len(categorized["stale_claims"]),
            "conflicting_claims": len(categorized["conflicting_claims"]),
            "unknown_operator_claims": len(categorized["unknown_operator_claims"]),
            "missing_session_claims": len(categorized["missing_session_claims"]),
            "branch": branch,
            "default_ttl_hours": default_ttl_hours(policy),
            "human_review_required": bool(findings or categorized["conflicting_claims"] or categorized["stale_claims"] or categorized["unknown_operator_claims"]),
        },
    }
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record and summarize deterministic NAOS task claim/release metadata.")
    parser.add_argument("--action", choices=["claim", "release", "list"], default=None)
    parser.add_argument("--task")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--session-id")
    parser.add_argument("--operator-id")
    parser.add_argument("--branch")
    parser.add_argument("--expires-at")
    parser.add_argument("--risk-tier", choices=["low", "medium", "high"], default=None,
                        help="Optional advisory per-task risk tier (QW1/AP5); recorded as coordination metadata.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def infer_action(args: argparse.Namespace) -> str:
    if args.action:
        return args.action
    prog = Path(sys.argv[0]).name.lower()
    raw = " ".join(sys.argv[:1]).lower()
    if "task-claim" in raw or "task_claim" in prog:
        return "claim"
    if "task-release" in raw or "task_release" in prog:
        return "release"
    return "list"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    action = infer_action(args)
    generated_at = utc_now_text()
    session_id = args.session_id or latest_session_id(root, naos_root, policy)
    operator, operator_findings = resolve_operator(root, args.operator_id)
    branch = args.branch or current_branch(root)
    task_id, task_finding = validate_task_id(args.task) if action in {"claim", "release"} else (None, None)
    claims_path = claims_file_path(root, naos_root, policy)
    data, load_findings = load_claims(claims_path)

    action_findings: list[dict[str, Any]] = []
    action_status = "ready"
    changed = False
    audit_event_type: str | None = None
    if task_finding is None:
        data, action_status, action_findings, changed, audit_event_type = apply_action(
            root=root,
            action=action,
            data=data,
            task_id=task_id,
            operator=operator,
            session_id=session_id,
            branch=branch,
            now_text=generated_at,
            ttl_hours=default_ttl_hours(policy),
            risk_tier=args.risk_tier,
        )
    else:
        action_status = "invalid_claims"

    if args.expires_at and action == "claim":
        parsed = parse_timestamp(args.expires_at)
        if parsed is None:
            action_findings.append(
                {
                    "id": "task_claim.invalid_expires_at",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": "Provided expires_at timestamp could not be parsed; default TTL was used.",
                }
            )
        else:
            for claim in data.get("claims") or []:
                if claim.get("task_id") == task_id and claim.get("status") == "active" and claim.get("operator_id") == operator.get("operator_id"):
                    claim["expires_at"] = timestamp_text(parsed)
                    changed = True

    if action in {"claim", "release"} and changed and not is_kit_repository(root, naos_root):
        atomic_write_yaml(claims_path, data)

    output = report_path(root, naos_root, policy)
    session_output = None
    if session_id and output is not None and not is_kit_repository(root, naos_root):
        session_output = session_report_default_path(root, naos_root, policy, session_id, "task_claim_report")

    audit_result = None
    if audit_event_type and write_audit_event is not None:
        # Audit event points at the current report path; the report is written immediately after.
        audit_result = write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type=audit_event_type,
            source_report_path=output,
            source_report={
                "schema": REPORT_SCHEMA,
                "status": action_status,
                "profile": profile,
                "session_id": session_id,
                "operator_id": operator.get("operator_id"),
                "task_id": task_id,
                "summary": {"action": action, "task_id": task_id, "branch": branch},
                "human_review_required": True,
            },
            session_id=session_id,
            generated_by=generated_by_for(root, session_id, generated_at, operator),
            related_task_id=task_id,
            related_artifacts=[str(claims_path)],
        )

    report = build_report(
        root=root,
        naos_root=naos_root,
        policy=policy,
        profile=profile,
        action=action,
        task_id=task_id,
        session_id=session_id,
        operator=operator,
        branch=branch,
        claims_path=claims_path,
        data=data,
        load_findings=load_findings,
        operator_findings=operator_findings,
        task_finding=task_finding,
        action_findings=action_findings,
        action_status=action_status,
        audit_result=audit_result,
        generated_at=generated_at,
    )
    write_report_with_session(output, session_output, report)
    if session_output is not None and output is not None:
        record_session_report_reference(root, naos_root, policy, session_id, "task_claim_report", output, session_output)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS task claims: "
            f"{report['status']} "
            f"({report['active_claim_count']} active, "
            f"{report['conflicting_claim_count']} conflicting, "
            f"output: {output if output else 'stdout only'})"
        )
    if args.strict and report["status"] in {"review_required", "invalid_claims", "blocked"}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
