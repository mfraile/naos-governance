#!/usr/bin/env python3
"""Generate deterministic session lifecycle reports for start/checkpoint/end."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
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
    build_generated_by,
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    evidence_pack_output_path,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    session_report_default_path,
    severity_for_profile,
    write_report_with_session,
)
from naos_session_identity import (  # noqa: E402
    ensure_session_context,
    record_session_report_reference,
    validate_session_id,
)
from naos_audit_log import write_audit_event  # noqa: E402
from naos_task_lifecycle import (  # noqa: E402
    extract_task_ids,
    normalize_task_id,
    normalize_task_states,
    resolve_task_record,
)


REPORT_SCHEMA = "naos.session_lifecycle.v1"
VALID_MODES = {"session_start", "session_checkpoint", "session_end"}
NOT_CLAIMED = [
    "proof",
    "approval",
    "evidence authority",
    "task completion",
    "automatic context injection",
    "automatic memory write-back",
    "memory as evidence",
    "memory as approval",
    "memory as truth",
    "source of truth",
    "hallucination prevention",
    "cloud memory",
]
REPORT_INPUTS = {
    "task_context_pack_report": "task_context_pack",
    "local_context_index_report": "local_context_index",
    "local_context_query_report": "local_context_query",
    "graph_context_readiness_report": "graph_context_readiness",
    "graph_context_query_report": "graph_context_query",
    "semantic_candidate_layer_report": "semantic_candidate_layer",
    "memory_context_readiness_report": "memory_context_readiness",
    "memory_provider_access_report": "memory_provider_access",
    "memory_use_policy_report": "memory_use_policy",
    "systemic_impact_report": "systemic_impact",
    "control_plane_review_report": "control_plane_review",
    "ai_surface_context_budget_report": "ai_surface_context_budget",
    "gate_status_report": "gate_status",
    "gate_evaluation_report": "gate_evaluation",
    "evidence_pack_report": "evidence_pack",
    "dashboard_summary_report": "dashboard_summary",
    "setup_recommendations_report": "setup_recommendations",
    "evidence_attestation_report": "evidence_attestation",
}


def utc_now_text() -> str:
    return controlled_utc_now_text()


def now_utc() -> datetime:
    return controlled_now_utc()


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def string_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if str(item).strip()]


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def dedupe_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value).strip()))


def bounded_text(value: Any, limit: int = 500) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 18)].rstrip() + " [truncated]"


def rel_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def load_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "session_lifecycle_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("session_lifecycle_rules") or "session_lifecycle_rules.yaml")
    project_path = root / naos_root / filename
    if project_path.exists():
        return project_path, "project"
    return default_rules_template(), "template"


def mode_from_command() -> str:
    command = sys.argv[0].replace("-", "_")
    if "session_start" in command:
        return "session_start"
    if "session_checkpoint" in command:
        return "session_checkpoint"
    if "session_end" in command:
        return "session_end"
    return "session_start"


def normalize_mode(value: str | None) -> str:
    mode = (value or mode_from_command()).strip().replace("-", "_")
    if mode not in VALID_MODES:
        raise ValueError(f"Unsupported session lifecycle mode {value!r}; expected one of {', '.join(sorted(VALID_MODES))}")
    return mode


def profile_posture(rules: dict[str, Any], profile: str) -> dict[str, Any]:
    configured = as_mapping(as_mapping(rules.get("profile_posture")).get(profile))
    defaults = {
        "quickstart": {"state": "advisory", "severity": "advisory", "human_review_required_for_stale_or_missing_lifecycle_critical_context": False},
        "lite": {"state": "readiness_only", "severity": "advisory", "human_review_required_for_stale_or_missing_lifecycle_critical_context": False},
        "standard": {"state": "readiness_only", "severity": "review_required", "human_review_required_for_stale_or_missing_lifecycle_critical_context": True},
        "assured": {"state": "readiness_only", "severity": "review_required", "human_review_required_for_stale_or_missing_lifecycle_critical_context": True},
    }
    return configured or defaults[profile]


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


def task_registry_path(root: Path, naos_root: str) -> Path:
    return root / naos_root / "TASK_REGISTRY.yaml"


def load_task_registry(root: Path, naos_root: str, task_id: str | None) -> dict[str, Any]:
    path = task_registry_path(root, naos_root)
    result: dict[str, Any] = {
        "path": rel_path(path, root),
        "exists": path.is_file(),
        "task_count": 0,
        "matched_task": None,
        "status": "missing",
    }
    if not path.is_file():
        return result
    try:
        data = load_yaml_mapping(path)
    except Exception as exc:
        result.update({"status": "unreadable", "error": str(exc)})
        return result
    tasks = as_list(data.get("tasks"))
    result["task_count"] = len([task for task in tasks if isinstance(task, dict)])
    if task_id:
        for task in tasks:
            if isinstance(task, dict) and str(task.get("id") or "").upper() == task_id.upper():
                result["matched_task"] = {
                    key: task.get(key)
                    for key in [
                        "id",
                        "title",
                        "status",
                        "lifecycle_state",
                        "delivery_state",
                        "verification_state",
                        "requirement",
                        "owner",
                    ]
                    if key in task
                }
                result["task_states"] = normalize_task_states(task)
                break
    result["status"] = "matched" if result.get("matched_task") else "present"
    return result


def discover_task_id(root: Path, naos_root: str, explicit_task: str | None) -> dict[str, Any]:
    if explicit_task:
        task_id = normalize_task_id(explicit_task)
        return {"task_id": task_id, "source": "argument", "candidates": [task_id], "ambiguous": False}

    candidates: list[str] = []
    active_dir = root / naos_root / "active"
    if active_dir.is_dir():
        for path in sorted(active_dir.glob("*.md")):
            if path.name.startswith("_") or "compact" in path.stem.lower():
                continue
            candidates.extend(extract_task_ids(path.name))

    registry = task_registry_path(root, naos_root)
    if not candidates and registry.is_file():
        try:
            data = load_yaml_mapping(registry)
            for task in as_list(data.get("tasks")):
                if isinstance(task, dict) and task.get("id"):
                    candidates.append(normalize_task_id(task["id"]))
                    break
        except Exception:
            pass

    candidates = dedupe_strings(candidates)
    return {
        "task_id": candidates[0] if len(candidates) == 1 else None,
        "source": "active_task_card" if candidates else "missing",
        "candidates": candidates,
        "ambiguous": len(candidates) > 1,
    }


def file_record(root: Path, path: Path | None, freshness_days: int, now: datetime) -> dict[str, Any]:
    if path is None:
        return {"path": None, "exists": False, "status": "missing", "freshness": "missing"}
    record: dict[str, Any] = {
        "path": rel_path(path, root),
        "exists": path.exists(),
        "status": "present" if path.exists() else "missing",
        "freshness": "missing",
    }
    if not path.is_file():
        return record
    stat = path.stat()
    modified = datetime.fromtimestamp(stat.st_mtime, UTC)
    age_days = max(0, (now - modified).days)
    record.update(
        {
            "size_bytes": stat.st_size,
            "modified_time": modified.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "age_days": age_days,
            "freshness": "stale" if freshness_days >= 0 and age_days > freshness_days else "fresh",
            "digest": safe_digest(path),
        }
    )
    return record


def find_active_card(root: Path, naos_root: str, task_id: str | None) -> Path | None:
    active_dir = root / naos_root / "active"
    if not active_dir.is_dir():
        return None
    patterns = [f"{task_id}*.md"] if task_id else ["*.md"]
    for pattern in patterns:
        for path in sorted(active_dir.glob(pattern)):
            if path.name.startswith("_") or "compact" in path.stem.lower():
                continue
            return path
    return None


def find_compact(root: Path, naos_root: str, task_id: str | None) -> Path | None:
    active_dir = root / naos_root / "active"
    if not active_dir.is_dir():
        return None
    patterns = [f"{task_id}*_compact.md", f"{task_id}*compact*.md"] if task_id else ["*compact*.md"]
    for pattern in patterns:
        for path in sorted(active_dir.glob(pattern)):
            if path.is_file():
                return path
    return None


def summarize_active_card(root: Path, card_path: Path | None, freshness_days: int, now: datetime) -> dict[str, Any]:
    record = file_record(root, card_path, freshness_days, now)
    if card_path and card_path.is_file():
        text = card_path.read_text(encoding="utf-8", errors="replace")
        record["title"] = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")), None)
        record["summary"] = bounded_text(text, 800)
        record["unchecked_items"] = sum(1 for line in text.splitlines() if "- [ ]" in line)
        record["checked_items"] = sum(1 for line in text.splitlines() if "- [x]" in line.lower())
    return record


def summarize_compact(root: Path, compact_path: Path | None, freshness_days: int, now: datetime) -> dict[str, Any]:
    record = file_record(root, compact_path, freshness_days, now)
    if compact_path and compact_path.is_file():
        text = compact_path.read_text(encoding="utf-8", errors="replace")
        record["summary"] = bounded_text(text, 700)
        lower = text.lower()
        record["checkpoint_fields_present"] = {
            "what": "what" in lower,
            "why": "why" in lower,
            "files": "files" in lower,
            "remaining": "remaining" in lower or "next action" in lower,
            "gotchas": "gotchas" in lower or "critical constraints" in lower,
        }
    else:
        record["checkpoint_fields_present"] = {}
    return record


def run_git(root: Path, args: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
    except Exception as exc:
        return 2, str(exc)
    return completed.returncode, completed.stdout.strip() or completed.stderr.strip()


def git_state(root: Path) -> dict[str, Any]:
    inside_code, inside = run_git(root, ["rev-parse", "--is-inside-work-tree"])
    if inside_code != 0 or inside.strip() != "true":
        return {"available": False, "status": "not_git_worktree", "mutated": False}
    branch_code, branch = run_git(root, ["branch", "--show-current"])
    head_code, head = run_git(root, ["rev-parse", "--short", "HEAD"])
    status_code, status = run_git(root, ["status", "--short"])
    files = [line[3:] if len(line) > 3 else line for line in status.splitlines() if line.strip()] if status_code == 0 else []
    return {
        "available": True,
        "status": "dirty" if files else "clean",
        "branch": branch if branch_code == 0 else None,
        "head": head if head_code == 0 else None,
        "dirty": bool(files),
        "changed_files": files[:50],
        "changed_file_count": len(files),
        "mutated": False,
    }


def changed_file_family(path: str) -> str:
    normalized = path.strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith(("naos/reports/", "naos/sessions/", "naos/audit_log/", "naos/context_packs/")):
        return "generated_evidence"
    if normalized in {"naos/TASK_REGISTRY.yaml", "naos/task_claims.yaml", "naos/PRE_IMPLEMENTATION_ALIGNMENT.md", "naos/PLANNING_BASELINES.yaml"} or normalized.startswith("naos/active/"):
        return "planning"
    first = normalized.split("/", 1)[0]
    if first in {"tests", "test"} or normalized.startswith("test_"):
        return "tests"
    if first in {"docs", "doc"} or normalized.endswith(".md"):
        return "docs"
    if first in {"schemas", "schema"} or normalized.endswith(".schema.json"):
        return "schemas"
    if first in {"templates", "profiles", "plugins"}:
        return "templates"
    if first in {"scripts", "src", "app", "apps", "packages"}:
        return "code"
    if first == "naos":
        return "governance"
    if first in {"policies", "configs", "config"}:
        return "config"
    if first == "dev":
        return "internal_docs"
    return first or "unknown"


def active_card_declares_lane_decision(active_card: dict[str, Any]) -> bool:
    text = f"{active_card.get('summary') or ''}\n{active_card.get('title') or ''}".lower()
    return "parallel_lane_decision" in text or "parallel lane decision" in text


def report_path_for(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    if key == "evidence_pack_report":
        output = evidence_pack_output_path(root, naos_root, policy)
        return output or (root / naos_root / "evidence" / "evidence_pack.json")
    return report_default_path(root, naos_root, policy, key)


def summarize_report_input(root: Path, path: Path, freshness_days: int, now: datetime) -> dict[str, Any]:
    record = file_record(root, path, freshness_days, now)
    record["schema"] = None
    record["report_status"] = None
    record["generated_at"] = None
    record["human_review_required"] = False
    if not path.is_file():
        return record
    try:
        data = load_json_mapping(path)
    except Exception as exc:
        record.update({"status": "unreadable", "error": str(exc)})
        return record
    record.update(
        {
            "schema": data.get("schema"),
            "report_status": data.get("status"),
            "generated_at": data.get("generated_at"),
            "human_review_required": bool(data.get("human_review_required")),
            "summary": data.get("summary") if isinstance(data.get("summary"), dict) else {},
            "finding_count": len(as_list(data.get("findings"))),
        }
    )
    return record


def collect_report_inputs(root: Path, naos_root: str, policy: dict[str, Any], rules: dict[str, Any], now: datetime) -> dict[str, dict[str, Any]]:
    freshness_days = int(as_mapping(rules.get("report_freshness_policy")).get("freshness_days") or 7)
    inputs: dict[str, dict[str, Any]] = {}
    for key, label in REPORT_INPUTS.items():
        inputs[label] = summarize_report_input(root, report_path_for(root, naos_root, policy, key), freshness_days, now)
    return inputs


def expected_report_keys(rules: dict[str, Any], profile: str) -> set[str]:
    required = set(string_list(as_mapping(rules.get("required_reports_by_profile")).get(profile)))
    return {REPORT_INPUTS[key] for key in required if key in REPORT_INPUTS}


def context_posture(report_inputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    names = [
        "task_context_pack",
        "local_context_index",
        "local_context_query",
        "graph_context_readiness",
        "graph_context_query",
        "semantic_candidate_layer",
    ]
    return {name: {key: report_inputs.get(name, {}).get(key) for key in ["status", "freshness", "report_status", "human_review_required"]} for name in names}


def memory_posture(report_inputs: dict[str, dict[str, Any]], rules: dict[str, Any]) -> dict[str, Any]:
    names = ["memory_context_readiness", "memory_provider_access", "memory_use_policy"]
    fallback = as_mapping(rules.get("memory_posture_policy")).get("fallback_when_unavailable") or "Use repo evidence, task cards, compact briefs, git state, and deterministic reports."
    return {
        "reports": {name: {key: report_inputs.get(name, {}).get(key) for key in ["status", "freshness", "report_status", "human_review_required"]} for name in names},
        "fallback_when_unavailable": fallback,
        "memory_is_advisory_only": True,
        "memory_is_not_evidence": True,
        "memory_is_not_approval": True,
    }


def freshness_summary(report_inputs: dict[str, dict[str, Any]], active_card: dict[str, Any], compact: dict[str, Any]) -> dict[str, int]:
    counts = Counter(str(item.get("freshness") or "unknown") for item in report_inputs.values())
    counts[str(active_card.get("freshness") or "unknown")] += 1
    counts[str(compact.get("freshness") or "unknown")] += 1
    return dict(sorted(counts.items()))


def make_memory_candidate(mode: str, task_id: str | None, git_info: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    policy = as_mapping(rules.get("memory_candidate_proposal_policy"))
    if not bool_value(policy.get("enabled"), True):
        return []
    if mode not in set(string_list(policy.get("modes_allowed")) or ["session_checkpoint", "session_end"]):
        return []
    if not task_id:
        return []
    changed = git_info.get("changed_file_count", 0)
    summary = f"{mode.replace('_', ' ')} candidate for {task_id}; changed files visible from git metadata: {changed}."
    return [
        {
            "proposal_id": f"{mode}.{task_id}.candidate",
            "task_id": task_id,
            "source_reference": {
                "source_type": "session_lifecycle_report",
                "source_path": "naos/reports/session_lifecycle.json",
                "mode": mode,
            },
            "candidate_summary": summary,
            "proposed_state": str(policy.get("default_proposed_state") or "raw_memory_candidate"),
            "allowed_use": str(policy.get("allowed_use") or "advisory_context_candidate"),
            "requires_human_review": bool_value(policy.get("requires_human_review"), True),
            "proposal_only": True,
            "not_written": True,
            "limitations": [
                "Proposal metadata only; no memory tool was called.",
                "Repository evidence and current user instructions remain authoritative.",
                "Human review is required before any durable memory use.",
            ],
        }
    ]


def recommended_commands(mode: str, task_id: str | None, profile: str, report_inputs: dict[str, dict[str, Any]], findings: list[dict[str, Any]]) -> list[str]:
    task_arg = f" --task {task_id}" if task_id else ""
    commands = [
        f"naos memory-readiness --profile {profile}",
        f"naos memory-access --profile {profile}",
        f"naos memory-use-policy --profile {profile}",
    ]
    if task_id:
        commands.insert(0, f"naos task-context --task {task_id} --profile {profile}")
    if mode == "session_start":
        commands.extend([f"naos context-index --profile {profile}", f"naos session-start{task_arg} --profile {profile}"])
    elif mode == "session_checkpoint":
        commands.extend([f"naos context-query --task {task_id} --profile {profile}" if task_id else f"naos context-query --query \"<keywords>\" --profile {profile}", f"naos session-checkpoint{task_arg} --profile {profile}"])
    else:
        commands.extend([
            f"naos systemic-impact --profile {profile}",
            f"naos control-plane-review --profile {profile}",
            f"naos evidence-pack --profile {profile}",
            f"naos dashboard --profile {profile}",
            f"naos session-end{task_arg} --profile {profile}",
        ])
    if any(item.get("status") == "stale" for item in findings):
        commands.append(f"naos control-plane-review --profile {profile}")
    return dedupe_strings(commands)


def routing_recommendations(findings: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    routes = []
    for item in findings:
        status = str(item.get("status") or "")
        if status in {"stale", "checkpoint_gap", "review_required", "missing"} or "memory_candidate" in str(item.get("id")):
            routes.append(
                {
                    "finding_id": item.get("id"),
                    "route_to": "control_plane_review",
                    "mode": mode,
                    "reason": "Lifecycle findings should be reviewed or recorded as known gaps, residual risks, waivers, or next actions.",
                }
            )
    return routes


def evaluate_findings(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    mode: str,
    rules: dict[str, Any],
    posture: dict[str, Any],
    severity: str,
    task_id: str | None,
    task_discovery: dict[str, Any],
    task_registry: dict[str, Any],
    task_resolution: dict[str, Any],
    active_card: dict[str, Any],
    compact: dict[str, Any],
    git_info: dict[str, Any],
    report_inputs: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not bool_value(rules.get("enabled"), True):
        findings.append(finding("session_lifecycle.disabled", "advisory", "disabled", "Session lifecycle rules are disabled."))
        return findings

    if not task_id:
        findings.append(
            finding(
                "session_lifecycle.missing_task",
                severity,
                "missing_task",
                "No task id was provided or discovered for this lifecycle report.",
                ["Pass --task T-XXX or create/read an active task card before relying on lifecycle context."],
            )
        )

    if not task_registry.get("exists"):
        findings.append(
            finding(
                "session_lifecycle.missing_registry",
                severity,
                "missing_registry",
                "TASK_REGISTRY.yaml is missing.",
                ["Restore or configure the task registry before using lifecycle reports for task routing."],
            )
        )

    if task_resolution.get("status") == "task_not_found":
        findings.append(
            finding(
                "session_lifecycle.task_not_found",
                severity,
                "task_not_found",
                "The exact task id is absent from the registry, active cards, and completed history.",
                ["Check the exact registry id; do not retry with a truncated T-NNN substring."],
                task_id=task_id,
            )
        )
    elif task_resolution.get("status") == "recovery_mode_mismatch":
        findings.append(
            finding(
                "session_lifecycle.recovery_mode_mismatch",
                severity,
                "task_not_found",
                "The exact task exists but is unavailable in the selected lifecycle recovery mode.",
                ["Select --recovery-mode active, completed, or auto as appropriate."],
                task_id=task_id,
            )
        )
    elif task_resolution.get("status") == "unsupported_legacy_status":
        findings.append(
            finding(
                "session_lifecycle.unsupported_legacy_status",
                "required",
                "unsupported_legacy_status",
                (
                    f"Legacy status {task_resolution.get('legacy_status')!r} is unsupported and must be "
                    "reconciled before session recovery can treat this task as lifecycle-safe."
                ),
                ["Update the task to one recognized lifecycle status and rerun recovery."],
                task_id=task_id,
            )
        )

    if task_id and not active_card.get("exists") and task_resolution.get("record_kind") != "completed":
        findings.append(
            finding(
                "session_lifecycle.missing_task_card",
                severity,
                "missing_task_card",
                "No active task card was found for the selected task.",
                ["Create or locate the active task card before implementation."],
                task_id=task_id,
            )
        )

    if active_card.get("freshness") == "stale":
        findings.append(
            finding(
                "session_lifecycle.stale_active_card",
                severity,
                "stale",
                "Active task card appears stale by the configured freshness policy.",
                ["Review the active task card and route stale context through control-plane review if it affects decisions."],
                path=active_card.get("path"),
            )
        )

    if (
        mode in {"session_checkpoint", "session_end"}
        and not compact.get("exists")
        and task_resolution.get("record_kind") != "completed"
    ):
        findings.append(
            finding(
                "session_lifecycle.compact_missing",
                severity,
                "checkpoint_gap",
                "No compact/checkpoint brief was found for this task.",
                ["Record checkpoint information in the active compact/task card manually; this report will not write it."],
                task_id=task_id,
            )
        )
    if compact.get("freshness") == "stale":
        findings.append(
            finding(
                "session_lifecycle.stale_compact",
                severity,
                "stale",
                "Compact/checkpoint brief appears stale.",
                ["Refresh the compact manually or route the stale context through control-plane review."],
                path=compact.get("path"),
            )
        )

    if mode == "session_end" and git_info.get("dirty"):
        findings.append(
            finding(
                "session_lifecycle.session_end_dirty_worktree",
                severity,
                "end_review_required",
                "Session end has uncommitted or untracked changes.",
                ["Commit, stash, or document the dirty worktree before ending the session."],
            )
        )
    changed_file_families = sorted(
        family
        for family in {changed_file_family(path) for path in string_list(git_info.get("changed_files"))}
        if family != "generated_evidence"
    )
    if git_info.get("dirty") and len(changed_file_families) >= 3 and not active_card_declares_lane_decision(active_card):
        findings.append(
            finding(
                "session_lifecycle.parallel_lane_decision_review",
                "advisory",
                "lane_decision_review",
                "Dirty worktree spans multiple path families and no lane decision was found in the active task card.",
                [
                    "Record sequential, declared, or deferred lane posture before relying on this session context.",
                ],
                changed_file_families=changed_file_families,
                does_not_declare_lanes=True,
                does_not_activate_handoff=True,
            )
        )

    required_reports = expected_report_keys(rules, profile)
    for label in sorted(required_reports):
        record = report_inputs.get(label) or {}
        if not record.get("exists"):
            findings.append(
                finding(
                    f"session_lifecycle.{label}.missing",
                    severity,
                    "missing",
                    f"Required lifecycle input report is missing: {label}.",
                    ["Run the corresponding NAOS report command or record why it is not configured."],
                    report=label,
                )
            )
        elif record.get("freshness") == "stale":
            findings.append(
                finding(
                    f"session_lifecycle.{label}.stale",
                    severity,
                    "stale",
                    f"Required lifecycle input report appears stale: {label}.",
                    ["Rerun the report or route stale context through control-plane review."],
                    report=label,
                    path=record.get("path"),
                )
            )

    if task_discovery.get("ambiguous"):
        findings.append(
            finding(
                "session_lifecycle.ambiguous_task",
                severity,
                "review_required",
                "Multiple active task candidates were discovered.",
                ["Pass an explicit --task value before using the lifecycle report."],
                candidates=task_discovery.get("candidates"),
            )
        )

    return findings


def status_from_findings(mode: str, rules: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if not bool_value(rules.get("enabled"), True):
        return "disabled"
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    statuses = {str(item.get("status")) for item in findings}
    for status in [
        "unsupported_legacy_status",
        "task_not_found",
        "missing_task",
        "missing_registry",
        "missing_task_card",
        "checkpoint_gap",
        "stale",
    ]:
        if status in statuses:
            return "stale_context" if status == "stale" else status
    if mode == "session_end" and "end_review_required" in statuses:
        return "end_review_required"
    if any(item.get("severity") in {"required", "warning"} or item.get("status") == "review_required" for item in findings):
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    mode: str,
    rules: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    explicit_task: str | None,
    recovery_mode: str = "auto",
) -> dict[str, Any]:
    now = now_utc()
    posture = profile_posture(rules, profile)
    severity = severity_for_rules(root, naos_root, profile, policy, posture)
    card_days = int(as_mapping(rules.get("active_card_policy")).get("freshness_days") or 14)
    compact_days = int(as_mapping(rules.get("compact_checkpoint_policy")).get("compact_freshness_days") or 7)
    task_discovery = discover_task_id(root, naos_root, explicit_task)
    task_id = task_discovery.get("task_id")
    task_resolution = (
        resolve_task_record(root, naos_root, str(task_id), recovery_mode)
        if task_id
        else {
            "status": "task_not_selected",
            "task_id": None,
            "recovery_mode": recovery_mode,
            "record_kind": None,
            "selected_card_path": None,
            "lifecycle_state": "unknown",
            "delivery_state": "not_delivered",
            "verification_state": "unverified",
            "human_review_required": False,
        }
    )
    registry = load_task_registry(root, naos_root, task_id)
    selected_card_path = task_resolution.get("selected_card_path")
    selected_card = Path(str(selected_card_path)) if selected_card_path else None
    active_card = summarize_active_card(root, selected_card, card_days, now)
    active_card["record_kind"] = task_resolution.get("record_kind")
    active_card["lifecycle_state"] = task_resolution.get("lifecycle_state")
    compact = summarize_compact(root, find_compact(root, naos_root, task_id), compact_days, now)
    git_info = git_state(root) if bool_value(as_mapping(rules.get("git_state_policy")).get("inspect_git_status"), True) else {"available": False, "status": "disabled", "mutated": False}
    reports = collect_report_inputs(root, naos_root, policy, rules, now)
    findings = evaluate_findings(
        root=root,
        naos_root=naos_root,
        profile=profile,
        mode=mode,
        rules=rules,
        posture=posture,
        severity=severity,
        task_id=task_id,
        task_discovery=task_discovery,
        task_registry=registry,
        task_resolution=task_resolution,
        active_card=active_card,
        compact=compact,
        git_info=git_info,
        report_inputs=reports,
    )
    proposals = make_memory_candidate(mode, task_id, git_info, rules)
    if proposals:
        findings.append(
            finding(
                "session_lifecycle.memory_candidate_proposal",
                "advisory",
                "review_required",
                "Memory candidate proposal metadata is present and requires human review before durable use.",
                ["Review the proposal under memory-use policy; this report did not write memory."],
            )
        )
    status = status_from_findings(mode, rules, findings)
    summary = finding_counts(findings)
    summary.update(
        {
            "status": status,
            "mode": mode,
            "task_id": task_id,
            "lifecycle_state": task_resolution.get("lifecycle_state"),
            "delivery_state": task_resolution.get("delivery_state"),
            "verification_state": task_resolution.get("verification_state"),
            "reports_present": sum(1 for item in reports.values() if item.get("exists")),
            "reports_missing": sum(1 for item in reports.values() if not item.get("exists")),
            "stale_inputs": sum(1 for item in reports.values() if item.get("freshness") == "stale")
            + (1 if active_card.get("freshness") == "stale" else 0)
            + (1 if compact.get("freshness") == "stale" else 0),
            "memory_candidate_proposals": len(proposals),
            "human_review_required": bool(findings)
            and bool_value(posture.get("human_review_required_for_stale_or_missing_lifecycle_critical_context"), False),
        }
    )
    human_review_required = (
        bool(summary["human_review_required"])
        or bool(task_resolution.get("human_review_required"))
        or any(proposal.get("requires_human_review") for proposal in proposals)
    )
    commands = recommended_commands(mode, task_id, profile, reports, findings)
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "mode": mode,
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(rules_path),
        "rules_source": rules_source,
        "rules_hash": safe_digest(rules_path),
        "task_id": task_id,
        "task_discovery": task_discovery,
        "task_resolution": task_resolution,
        "task_record": active_card,
        "lifecycle_state": task_resolution.get("lifecycle_state"),
        "delivery_state": task_resolution.get("delivery_state"),
        "verification_state": task_resolution.get("verification_state"),
        "task_registry": registry,
        "active_task_card": active_card,
        "compact": compact,
        "git_state": git_info,
        "report_inputs": reports,
        "freshness_summary": freshness_summary(reports, active_card, compact),
        "context_posture": context_posture(reports),
        "memory_posture": memory_posture(reports, rules),
        "memory_candidate_proposals": proposals,
        "recommended_commands": commands,
        "routing_recommendations": routing_recommendations(findings, mode),
        "known_gaps": as_list(rules.get("known_gaps")),
        "residual_risks": as_list(rules.get("residual_risks")),
        "waivers": as_list(rules.get("waivers")),
        "findings": findings,
        "limitations": dedupe_strings(string_list(rules.get("limitations"))),
        "not_claimed": dedupe_strings(string_list(rules.get("not_claimed")) + NOT_CLAIMED),
        "human_review_required": human_review_required,
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate deterministic session lifecycle reports for start/checkpoint/end.")
    parser.add_argument("--mode", choices=sorted(VALID_MODES), help="Lifecycle mode. CLI aliases set this automatically.")
    parser.add_argument("--task", help="Task id such as T-123.")
    parser.add_argument(
        "--recovery-mode",
        choices=["auto", "active", "completed"],
        default="auto",
        help="Select active-only, completed-only, or automatic task recovery.",
    )
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy.")
    parser.add_argument("--policy", help="Optional policy file used for path/profile conventions.")
    parser.add_argument("--rules", help="Explicit session_lifecycle_rules.yaml path.")
    parser.add_argument("--session-id", help="Use an existing filesystem-safe session id.")
    parser.add_argument("--new-session", action="store_true", help="Create a new session id instead of reusing the latest active session.")
    parser.add_argument("--close-session", action="store_true", help="Mark the selected session as closed after writing the lifecycle report.")
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
        mode = normalize_mode(args.mode)
        if args.session_id:
            validate_session_id(args.session_id)
        rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
        rules = load_yaml_mapping(rules_path)
        report = build_report(
            root,
            naos_root,
            profile,
            policy,
            mode,
            rules,
            rules_path,
            rules_source,
            args.task,
            args.recovery_mode,
        )
        session_context = ensure_session_context(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            requested_session_id=args.session_id,
            new_session=args.new_session,
            close_session=args.close_session,
            task_id=report.get("task_id") or args.task,
        )
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "session_lifecycle_report")
    session_output = None
    if session_context.get("session_id") and args.output is None:
        session_output = session_report_default_path(root, naos_root, policy, str(session_context["session_id"]), "session_lifecycle_report")
        report["session_id"] = session_context["session_id"]
        report["session_root"] = rel_path(session_context["session_root"], root)
        report["session_report_root"] = rel_path(session_context["session_report_root"], root)
        report["generated_by"] = build_generated_by(root, session_id=str(session_context["session_id"]), generated_at=report.get("generated_at"))
        report["latest_report_compatibility"] = {
            "enabled": True,
            "latest_report_path": rel_path(output, root) if output else None,
            "session_report_path": rel_path(session_output, root),
        }
        report.setdefault("known_gaps", []).extend(
            [
                "operator_identity_proof_authentication_authorization_deferred",
                "task_claim_authorization_and_resolution_deferred",
                "audit_log_full_source_coverage_deferred",
                "evidence_conflict_resolution_workflow_deferred",
            ]
        )
        report.setdefault("not_claimed", []).extend(
            [
                "identity proof",
                "authentication",
                "authorization",
                "operator attribution as task ownership",
                "separation of duties satisfied",
                "non-repudiation",
                "task locking enabled",
                "complete audit-log coverage",
                "evidence conflict detection complete",
                "multi-user complete",
            ]
        )
    write_report_with_session(output, session_output, report)
    if session_context.get("session_id") and args.output is None:
        record_session_report_reference(
            root,
            naos_root,
            policy,
            str(session_context["session_id"]),
            "session_lifecycle_report",
            output,
            session_output,
        )
    if args.output is None:
        event_type = {
            "session_start": "session_started",
            "session_checkpoint": "session_checkpoint",
            "session_end": "session_ended",
        }.get(str(report.get("mode")), "report_generated")
        write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type=event_type,
            source_report_path=output,
            source_report=report,
            session_id=str(report["session_id"]) if report.get("session_id") else None,
            generated_by=report.get("generated_by"),
            related_task_id=report.get("task_id") or args.task,
            related_artifacts=[str(path) for path in [output, session_output] if path is not None],
        )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(f"NAOS session lifecycle {report['mode']} ({profile}): {report['status']}")
        print(
            "summary: "
            f"task={summary.get('task_id')} "
            f"reports_present={summary.get('reports_present')} "
            f"reports_missing={summary.get('reports_missing')} "
            f"findings={summary.get('total_findings', 0)}"
        )
        print(f"report: {output}")
    exit_code = exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)
    if report.get("status") in {
        "task_not_found",
        "recovery_mode_mismatch",
        "unsupported_legacy_status",
    }:
        return exit_code or 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
