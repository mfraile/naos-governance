#!/usr/bin/env python3
"""Report behavioral governance baseline readiness and deterministic impacters."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    safe_policy_path,
    write_report,
)


REPORT_SCHEMA = "naos.behavioral_governance_readiness.v1"
STATUS_VALUES = {
    "not_configured",
    "not_ready",
    "ready_to_baseline",
    "baseline_current",
    "baseline_stale",
    "maintenance_recommended",
    "maintenance_required",
}
DEFAULT_REQUIRED_REPORTS = [
    "conformance_latest",
    "static_grader_report",
    "grader_assessment_report",
    "llm_grader_readiness_report",
]
DEFAULT_OPTIONAL_REPORTS = [
    "ai_surface_context_budget_report",
    "agent_trace_validation_report",
    "setup_recommendations_report",
    "systemic_impact_report",
]
REPORT_KEYS = {
    "static_grader_report",
    "grader_assessment_report",
    "llm_grader_readiness_report",
    "ai_surface_context_budget_report",
    "agent_trace_validation_report",
    "setup_recommendations_report",
    "systemic_impact_report",
}
REPORT_STATUS_OK = {
    "pass",
    "ok",
    "ready",
    "advisory",
    "warning",
    "readiness_only",
    "disabled",
    "review_required",
    "baseline_current",
    "ready_to_baseline",
    "maintenance_recommended",
}
CONFORMANCE_REFRESH_FINDINGS = {
    "behavioral_readiness.missing_conformance_latest",
    "behavioral_readiness.unready_conformance_latest",
}
LLM_UNSAFE_STATUSES = {"blocked", "unsafe", "failed", "error", "parse_error"}
HIGH_IMPACT_KEYS = {
    "profile",
    "rules:behavioral_governance_readiness_rules",
    "report:llm_grader_readiness_report",
}
MEDIUM_IMPACT_PREFIXES = (
    "report:ai_surface_context_budget_report",
    "report:agent_trace_validation_report",
    "report:setup_recommendations_report",
    "report:systemic_impact_report",
    "path:.github/workflows",
    "path:.claude",
    "path:.cursor",
)
RESIDUAL_RISKS = [
    "file_fingerprint_change_without_semantic_interpretation",
    "baseline_metadata_may_be_incomplete",
    "supporting_reports_may_be_stale",
    "deterministic_readiness_is_not_behavioral_correctness",
    "future_model_judge_bias_or_variance_if_enabled_elsewhere",
    "human_review_required",
]
NOT_CLAIMED = [
    "behavioral runtime grading",
    "LLM judging",
    "model/API/provider call",
    "baseline creation",
    "N-run statistics",
    "semantic drift inference",
    "approval",
    "certification",
    "attestation",
    "publication readiness",
    "release authorization",
    "compliance proof",
    "runtime safety proof",
    "behavioral safety proof",
    "maturity promotion",
]
LIMITATIONS = [
    "This report reads local deterministic files and reports review posture only.",
    "File hashes and metadata changes do not prove semantic or behavioral drift.",
    "A current baseline means tracked evidence matches baseline metadata; it is not a behavioral pass.",
    "No baseline is created or promoted automatically.",
    "Human review decides whether first baseline work or maintenance work should proceed.",
]


def utc_now_text() -> str:
    return controlled_utc_now_text()


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def age_days(value: Any, now_text: str) -> int | None:
    timestamp = parse_time(value)
    now = parse_time(now_text)
    if timestamp is None or now is None:
        return None
    return max(0, (now - timestamp).days)


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def load_structured_mapping(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "behavioral_governance_readiness_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("behavioral_governance_readiness_rules") or "behavioral_governance_readiness_rules.yaml")
    project_rules = safe_policy_path(root / naos_root, filename, field="behavioral_governance_readiness_rules")
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def resolve_baseline_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> Path:
    if explicit:
        return Path(explicit)
    filename = str(
        policy.get("paths", {}).get("behavioral_governance_readiness_baseline_state")
        or "behavioral_baseline_state.yaml"
    )
    return safe_policy_path(root / naos_root, filename, field="behavioral_governance_readiness_baseline_state")


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_directory(path: Path, max_files: int) -> tuple[str | None, bool, int]:
    if not path.is_dir():
        return None, False, 0
    digest = hashlib.sha256()
    files = [item for item in sorted(path.rglob("*")) if item.is_file()]
    truncated = len(files) > max_files
    for item in files[:max_files]:
        rel = item.relative_to(path).as_posix()
        digest.update(rel.encode("utf-8"))
        item_hash = safe_digest(item)
        if item_hash:
            digest.update(item_hash.encode("ascii"))
    return digest.hexdigest(), truncated, len(files)


def digest_path(path: Path, max_files: int) -> tuple[str | None, dict[str, Any]]:
    if path.is_file():
        return safe_digest(path), {"type": "file", "present": True, "truncated": False, "file_count": 1}
    if path.is_dir():
        digest, truncated, count = digest_directory(path, max_files)
        return digest, {"type": "directory", "present": True, "truncated": truncated, "file_count": count}
    return None, {"type": "missing", "present": False, "truncated": False, "file_count": 0}


def conformance_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    return safe_policy_path(
        root / naos_root,
        str(policy.get("paths", {}).get("reports_dir") or "reports"),
        "conformance_latest.json",
        field="conformance_latest",
    )


def conformance_runner_path(root: Path) -> Path:
    return root / ".github" / "autoresearch" / "runner.py"


def report_path_for(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    if key == "conformance_latest":
        return conformance_path(root, naos_root, policy)
    if key in REPORT_KEYS:
        return report_default_path(root, naos_root, policy, key)
    return safe_policy_path(root / naos_root, key, field=key)


def report_status(data: dict[str, Any], key: str) -> str:
    status = data.get("status") or data.get("health_status") or data.get("readiness_status")
    if status:
        return str(status)
    if key == "conformance_latest":
        if "overall_conformance" not in data:
            return "present"
        score_value = data.get("overall_conformance")
        if isinstance(score_value, bool):
            return "parse_error"
        try:
            score = float(score_value)
        except (TypeError, ValueError):
            return "parse_error"
        return "pass" if score == 1.0 else "failed"
    return "present"


def load_json_report(path: Path, key: str) -> tuple[dict[str, Any], str]:
    if not path.exists():
        return {}, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}, "parse_error"
    if not isinstance(data, dict):
        return {}, "parse_error"
    return data, report_status(data, key)


def finding(identifier: str, severity: str, status: str, message: str, *, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": identifier,
        "severity": severity,
        "status": status,
        "message": message,
        "evidence": evidence or {},
        "human_review_required": True,
        "authority_layer": "readiness_only",
        "review_input_only": True,
        "not_claimed": ["approval", "certification", "compliance proof", "runtime grading", "baseline creation"],
    }


def profile_severity(profile: str, default: str = "advisory") -> str:
    return {"quickstart": default, "lite": default, "standard": "required", "assured": "blocking"}.get(profile, default)


def summarize_report_input(root: Path, naos_root: str, policy: dict[str, Any], key: str, required: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    path = report_path_for(root, naos_root, policy, key)
    data, status = load_json_report(path, key)
    item = {
        "id": key,
        "path": str(path),
        "present": path.exists(),
        "required": required,
        "status": status,
        "schema": data.get("schema"),
        "generated_at": data.get("generated_at") or data.get("run_date"),
        "hash": safe_digest(path),
    }
    return item, data if data else None


def llm_readiness_unsafe(data: dict[str, Any], status: str) -> list[str]:
    reasons: list[str] = []
    if status in LLM_UNSAFE_STATUSES:
        reasons.append(f"status:{status}")
    for key in ("runtime_enabled", "provider_allowed", "external_api_allowed", "model_dependency_allowed", "api_keys_allowed"):
        if bool_value(data.get(key)):
            reasons.append(key)
    cost = as_mapping(data.get("cost_posture"))
    if bool_value(cost.get("cost_incurred_by_default")) or float(cost.get("cost_usd") or 0.0) > 0.0:
        reasons.append("cost_posture")
    return reasons


def rules_report_keys(rules: dict[str, Any], key: str, defaults: list[str]) -> list[str]:
    values = as_list(rules.get(key))
    result = [str(item) for item in values if str(item).strip()]
    return result or defaults


def configured_impacter_paths(rules: dict[str, Any]) -> list[str]:
    values = [str(item) for item in as_list(rules.get("impacter_paths")) if str(item).strip()]
    if values:
        return values
    return [
        "naos/behavioral_governance_readiness_rules.yaml",
        "naos/llm_grader_readiness_rules.yaml",
        "naos/ai_surface_context_budget_rules.yaml",
        "naos/agent_trace_events.yaml",
        "configs/naos_autoresearch.yaml",
        ".github/configs/naos_autoresearch.yaml",
        ".github/autoresearch/task_battery",
        ".github/workflows",
        ".claude/settings.json",
        "AGENTS.md",
        "CLAUDE.md",
    ]


def collect_readiness_inputs(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    profile: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    data_by_key: dict[str, dict[str, Any]] = {}
    required = rules_report_keys(rules, "required_reports", DEFAULT_REQUIRED_REPORTS)
    optional = rules_report_keys(rules, "optional_reports", DEFAULT_OPTIONAL_REPORTS)

    for key in required + [item for item in optional if item not in required]:
        item, data = summarize_report_input(root, naos_root, policy, key, key in required)
        inputs.append(item)
        if data is not None:
            data_by_key[key] = data
        if key in required and not item["present"]:
            findings.append(
                finding(
                    f"behavioral_readiness.missing_{key}",
                    profile_severity(profile, "warning"),
                    "not_ready",
                    f"Required deterministic input `{key}` is missing.",
                    evidence={"path": item["path"]},
                )
            )
        elif key in required and item["status"] not in REPORT_STATUS_OK:
            findings.append(
                finding(
                    f"behavioral_readiness.unready_{key}",
                    profile_severity(profile, "warning"),
                    "not_ready",
                    f"Required deterministic input `{key}` has status `{item['status']}`.",
                    evidence={"path": item["path"], "status": item["status"]},
                )
            )

    llm_item = next((item for item in inputs if item["id"] == "llm_grader_readiness_report"), None)
    llm_data = data_by_key.get("llm_grader_readiness_report") or {}
    if llm_item and llm_item["present"]:
        unsafe = llm_readiness_unsafe(llm_data, str(llm_item["status"]))
        if unsafe:
            findings.append(
                finding(
                    "behavioral_readiness.unsafe_llm_readiness_posture",
                    "blocking",
                    "not_ready",
                    "LLMGrader Readiness input is unsafe for behavioral baseline readiness.",
                    evidence={"unsafe_reasons": unsafe, "path": llm_item["path"]},
                )
            )

    return inputs, data_by_key, findings


def collect_current_fingerprints(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules: dict[str, Any],
    inputs: list[dict[str, Any]],
    profile: str,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    fingerprints: dict[str, str] = {"profile": profile}
    metadata: list[dict[str, Any]] = []
    rules_hash = safe_digest(rules_path)
    if rules_hash:
        fingerprints["rules:behavioral_governance_readiness_rules"] = rules_hash
    for item in inputs:
        if item.get("present") and item.get("hash"):
            fingerprints[f"report:{item['id']}"] = str(item["hash"])

    max_files = int(as_mapping(rules.get("path_fingerprinting")).get("max_files_per_path") or 200)
    for rel_text in configured_impacter_paths(rules):
        rel = Path(rel_text)
        if rel.is_absolute() or ".." in rel.parts:
            metadata.append({"id": f"path:{rel_text}", "present": False, "ignored": True, "reason": "unsafe_path"})
            continue
        path = root / rel
        digest, meta = digest_path(path, max_files)
        item = {"id": f"path:{rel_text}", "path": str(path), **meta}
        metadata.append(item)
        if digest:
            fingerprints[f"path:{rel_text}"] = digest
    return fingerprints, metadata


def impact_severity(key: str) -> str:
    if key in HIGH_IMPACT_KEYS:
        return "high"
    if any(key.startswith(prefix) for prefix in MEDIUM_IMPACT_PREFIXES):
        return "medium"
    return "low"


def compare_baseline(
    baseline: dict[str, Any],
    current_fingerprints: dict[str, str],
    profile: str,
    rules: dict[str, Any],
    now_text: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    impacters: list[dict[str, Any]] = []
    baseline_fingerprints = as_mapping(baseline.get("fingerprints"))
    baseline_profile = baseline.get("profile")
    if baseline_profile and str(baseline_profile) != profile:
        impacters.append(
            {
                "id": "profile",
                "category": "profile_change",
                "severity": "high",
                "status": "changed",
                "baseline": baseline_profile,
                "current": profile,
            }
        )

    for key in sorted(set(current_fingerprints) | set(str(item) for item in baseline_fingerprints)):
        current = current_fingerprints.get(key)
        previous = baseline_fingerprints.get(key)
        if current == previous:
            continue
        severity = impact_severity(key)
        impacters.append(
            {
                "id": key,
                "category": "fingerprint_change",
                "severity": severity,
                "status": "changed" if current and previous else "missing_or_new",
                "baseline_hash": previous,
                "current_hash": current,
            }
        )

    baseline_time = baseline.get("last_behavioral_baseline_at") or baseline.get("generated_at")
    days = age_days(baseline_time, now_text)
    max_age_days = int(as_mapping(rules.get("baseline_state")).get("max_age_days") or rules.get("max_age_days") or 90)
    required_age_days = int(as_mapping(rules.get("baseline_state")).get("required_after_days") or max_age_days * 2)
    if days is None and baseline_time:
        findings.append(
            finding(
                "behavioral_readiness.baseline_timestamp_unparseable",
                "warning",
                "maintenance_recommended",
                "Baseline timestamp could not be parsed.",
                evidence={"baseline_time": baseline_time},
            )
        )
    elif days is not None and days > max_age_days:
        severity = "high" if profile == "assured" and days > required_age_days else "medium"
        impacters.append(
            {
                "id": "baseline_age",
                "category": "baseline_age",
                "severity": severity,
                "status": "stale_age",
                "age_days": days,
                "max_age_days": max_age_days,
                "required_after_days": required_age_days,
            }
        )
    return impacters, findings


def status_from_state(
    rules_source: str,
    project_rules_present: bool,
    readiness_findings: list[dict[str, Any]],
    baseline_present: bool,
    impacters: list[dict[str, Any]],
) -> str:
    if rules_source == "template" and not project_rules_present:
        return "not_configured"
    if readiness_findings:
        return "not_ready"
    if not baseline_present:
        return "ready_to_baseline"
    severities = {str(item.get("severity")) for item in impacters}
    if "high" in severities:
        return "maintenance_required"
    if "medium" in severities:
        return "maintenance_recommended"
    if "low" in severities:
        return "baseline_stale"
    return "baseline_current"


def command_item(identifier: str, command: str, lane: str, reason: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "command": command,
        "lane": lane,
        "reason": reason,
        "trigger": "explicit_user",
        "auto_run_allowed": False,
        "review_input_only": True,
    }


def conformance_refresh_needed(readiness_findings: list[dict[str, Any]]) -> bool:
    return any(str(item.get("id")) in CONFORMANCE_REFRESH_FINDINGS for item in readiness_findings)


def conformance_refresh_commands(profile: str, runner_available: bool) -> list[dict[str, Any]]:
    if runner_available:
        return [
            command_item(
                "conformance",
                "make -f Makefile.naos naos-conformance",
                "deterministic",
                "Generate or refresh the deterministic conformance_latest prerequisite.",
            )
        ]
    return [
        command_item(
            "deterministic_conformance_review_preview",
            f"naos add setup-module deterministic_conformance_review --profile {profile} --dry-run",
            "deterministic_setup_preview",
            "Preview installing the deterministic conformance runner before running naos-conformance.",
        ),
        command_item(
            "deterministic_conformance_review_install",
            f"naos add setup-module deterministic_conformance_review --profile {profile}",
            "deterministic_setup",
            "Install the deterministic conformance runner after reviewing the dry-run plan.",
        ),
        command_item(
            "conformance",
            "make -f Makefile.naos naos-conformance",
            "deterministic",
            "Generate or refresh the deterministic conformance_latest prerequisite after the runner is installed.",
        ),
    ]


def recommended_next_steps(
    status: str,
    profile: str,
    readiness_findings: list[dict[str, Any]] | None = None,
    conformance_runner_available: bool = False,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    needs_conformance_refresh = conformance_refresh_needed(readiness_findings or [])
    conformance_refresh = conformance_refresh_commands(profile, conformance_runner_available) if needs_conformance_refresh else []
    deterministic_refresh = [
        command_item(
            "self_check",
            f"naos self-check --profile {profile}",
            "deterministic",
            "Refresh deterministic control-plane posture before relying on behavioral readiness.",
        ),
        command_item(
            "static_grader",
            f"naos static-grader --profile {profile}",
            "deterministic",
            "Refresh deterministic StaticGrader structural evidence.",
        ),
        command_item(
            "grader_assessment",
            f"naos grader-assessment --profile {profile} --mode assess",
            "deterministic",
            "Package deterministic grader assessment review input.",
        ),
    ]
    llm_readiness = command_item(
        "llm_grader_readiness",
        f"naos llm-grader-readiness --profile {profile}",
        "advisory_readiness_only",
        "Check readiness posture for possible future non-deterministic review without running a model.",
    )
    rerun_readiness = command_item(
        "behavioral_readiness",
        f"naos behavioral-readiness --profile {profile}",
        "deterministic",
        "Recompute behavioral baseline readiness and deterministic impacters after prerequisites or baseline metadata change.",
    )
    control_review = command_item(
        "control_plane_review",
        f"naos control-plane-review --profile {profile}",
        "deterministic_review_routing",
        "Route readiness or impacter findings for human review.",
    )

    if status == "not_configured":
        commands = [
            command_item(
                "setup_recommendations",
                f"naos setup-recommendations --profile {profile}",
                "deterministic",
                "Confirm whether the Behavioral Governance Readiness module should be installed.",
            ),
            command_item(
                "dry_run_module_install",
                f"naos add setup-module behavioral_governance_readiness --profile {profile} --dry-run",
                "deterministic",
                "Preview installing the readiness-only rules and script before changing the adopter project.",
            ),
        ]
        actions = [
            "Decide whether this adopter project should install Behavioral Governance Readiness.",
            "If approved, install the setup module explicitly, then run deterministic prerequisites.",
        ]
    elif status == "not_ready":
        commands = [*conformance_refresh, *deterministic_refresh, llm_readiness, rerun_readiness]
        actions = [
            "Generate or repair missing deterministic prerequisite reports.",
            "Run LLMGrader Readiness only as readiness posture; do not run model-backed judging.",
            "Rerun Behavioral Governance Readiness after prerequisites are refreshed.",
        ]
        if needs_conformance_refresh and not conformance_runner_available:
            actions.insert(
                0,
                "Preview and explicitly install Deterministic Conformance Review before running naos-conformance.",
            )
    elif status == "ready_to_baseline":
        commands = [*deterministic_refresh, llm_readiness, rerun_readiness]
        actions = [
            "Project is eligible for human-reviewed first behavioral baseline work.",
            "Create baseline metadata only through an explicit human review process; this command does not create it.",
            "Use LLMGrader Readiness as advisory posture only if future non-deterministic review is being considered.",
        ]
    elif status == "baseline_current":
        commands = [rerun_readiness]
        actions = [
            "Baseline metadata matches tracked deterministic evidence.",
            "Continue periodic explicit readiness checks after governance, CI, policy, rules, AI-surface, or tooling changes.",
        ]
    elif status == "baseline_stale":
        commands = [control_review, *deterministic_refresh, llm_readiness, rerun_readiness]
        actions = [
            "Review low-impact deterministic baseline differences before relying on the prior baseline posture.",
            "Refresh supporting deterministic reports, then rerun Behavioral Governance Readiness.",
        ]
    elif status == "maintenance_recommended":
        commands = [control_review, *deterministic_refresh, llm_readiness, rerun_readiness]
        actions = [
            "Schedule human maintenance review for medium-impact or age-related deterministic baseline impacters.",
            "Do not treat the prior baseline as failed or passed until the review disposition is recorded.",
        ]
    else:
        commands = [control_review, *deterministic_refresh, llm_readiness, rerun_readiness]
        actions = [
            "Perform human review before relying on the prior behavioral baseline posture.",
            "Resolve high-impact deterministic impacters or record accepted residual risk.",
            "Do not treat readiness output as approval, certification, compliance proof, or semantic drift inference.",
        ]

    advisory_boundary = {
        "current_readiness_command": llm_readiness["command"],
        "current_readiness_command_only": True,
        "model_backed_evaluator_command": None,
        "model_backed_evaluator_available": False,
        "auto_trigger_allowed": False,
        "requires_separate_approved_design": True,
        "review_input_only": True,
    }
    return commands, actions, advisory_boundary


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    baseline_path: Path,
) -> dict[str, Any]:
    now_text = utc_now_text()
    project_rules_present = rules_source != "template"
    if not rules_path.exists():
        rules: dict[str, Any] = {}
    else:
        rules = load_yaml_mapping(rules_path)

    findings: list[dict[str, Any]] = []
    if rules_source == "template" and not project_rules_present:
        findings.append(
            finding(
                "behavioral_readiness.rules_not_installed",
                "advisory",
                "not_configured",
                "Behavioral Governance Readiness rules are not installed in the project.",
                evidence={"template_rules_path": str(rules_path)},
            )
        )

    runtime_flags = {
        "runtime_enabled": bool_value(rules.get("runtime_enabled")),
        "provider_allowed": bool_value(rules.get("provider_allowed")),
        "external_api_allowed": bool_value(rules.get("external_api_allowed")),
        "model_dependency_allowed": bool_value(rules.get("model_dependency_allowed")),
        "api_keys_allowed": bool_value(rules.get("api_keys_allowed")),
        "auto_create_baseline": bool_value(as_mapping(rules.get("baseline_state")).get("auto_create")),
    }
    for key, value in runtime_flags.items():
        if value:
            findings.append(
                finding(
                    f"behavioral_readiness.{key}",
                    "blocking",
                    "not_ready",
                    f"`{key}` is true; Behavioral Governance Readiness must remain no-cost, local-file-only, and proposal/review-only.",
                )
            )

    inputs, _input_data, input_findings = collect_readiness_inputs(root, naos_root, policy, rules, profile)
    if project_rules_present:
        findings.extend(input_findings)
    current_fingerprints, path_metadata = collect_current_fingerprints(root, naos_root, policy, rules_path, rules, inputs, profile)

    baseline_present = baseline_path.exists()
    baseline_state: dict[str, Any] = {}
    baseline_error: str | None = None
    if baseline_present:
        try:
            baseline_state = load_structured_mapping(baseline_path)
        except Exception as exc:
            baseline_error = str(exc)
            findings.append(
                finding(
                    "behavioral_readiness.baseline_parse_error",
                    "blocking",
                    "not_ready",
                    "Baseline state metadata could not be parsed.",
                    evidence={"path": str(baseline_path), "error": baseline_error},
                )
            )

    impacters: list[dict[str, Any]] = []
    baseline_findings: list[dict[str, Any]] = []
    readiness_findings = [item for item in findings if item.get("status") == "not_ready" or item.get("severity") == "blocking"]
    if baseline_present and baseline_state and not readiness_findings:
        impacters, baseline_findings = compare_baseline(baseline_state, current_fingerprints, profile, rules, now_text)
        findings.extend(baseline_findings)

    status = status_from_state(rules_source, project_rules_present, readiness_findings, baseline_present, impacters)
    if status == "baseline_stale":
        findings.append(
            finding(
                "behavioral_readiness.baseline_stale",
                "warning",
                "baseline_stale",
                "Baseline metadata differs from current deterministic fingerprints.",
                evidence={"impacters": impacters},
            )
        )
    elif status == "maintenance_recommended":
        findings.append(
            finding(
                "behavioral_readiness.maintenance_recommended",
                "warning",
                "maintenance_recommended",
                "Baseline maintenance is recommended by deterministic impacter metadata.",
                evidence={"impacters": impacters},
            )
        )
    elif status == "maintenance_required":
        findings.append(
            finding(
                "behavioral_readiness.maintenance_required",
                "blocking",
                "maintenance_required",
                "High-impact deterministic change requires human behavioral-governance review.",
                evidence={"impacters": impacters},
            )
        )

    counts = finding_counts(findings)
    severity_counts = {
        "high": sum(1 for item in impacters if item.get("severity") == "high"),
        "medium": sum(1 for item in impacters if item.get("severity") == "medium"),
        "low": sum(1 for item in impacters if item.get("severity") == "low"),
    }
    summary = {
        **counts,
        "status": status,
        "baseline_present": baseline_present,
        "total_impacters": len(impacters),
        "high_impacters": severity_counts["high"],
        "medium_impacters": severity_counts["medium"],
        "low_impacters": severity_counts["low"],
        "cost_usd": 0.0,
        "runtime_enabled": False,
        "provider_allowed": False,
        "review_input_only": True,
    }
    if status not in STATUS_VALUES:
        status = "not_ready"
    recommended_commands, next_actions, advisory_non_deterministic_boundary = recommended_next_steps(
        status,
        profile,
        readiness_findings,
        conformance_runner_path(root).is_file(),
    )

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": now_text,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(rules_path),
        "rules_source": rules_source,
        "rules_hash": safe_digest(rules_path),
        "baseline_state_path": str(baseline_path),
        "baseline_state_present": baseline_present,
        "baseline_state_error": baseline_error,
        "baseline_state": baseline_state if baseline_present else {},
        "current_fingerprints": current_fingerprints,
        "fingerprinted_paths": path_metadata,
        "readiness_inputs": inputs,
        "impacter_review": {
            "impacters": impacters,
            "impacter_counts": severity_counts,
            "method": "deterministic_file_hash_and_metadata_only",
            "semantic_drift_inference": False,
            "live_environment_probe": False,
        },
        "cost_posture": {
            "cost_usd": 0.0,
            "cost_incurred_by_default": False,
            "external_api_required": False,
            "provider_dependency_required": False,
            "model_dependency_required": False,
            "credential_read_required": False,
        },
        "runtime_posture": {
            "runtime_enabled": False,
            "provider_allowed": False,
            "external_api_allowed": False,
            "model_dependency_allowed": False,
            "api_keys_allowed": False,
            "baseline_auto_create": False,
            "scheduler_or_daemon_enabled": False,
        },
        "advisory_boundary": {
            "readiness_only": True,
            "review_input_only": True,
            "can_create_baseline": False,
            "can_approve": False,
            "can_certify": False,
            "can_prove_compliance": False,
            "can_promote_maturity": False,
            "can_replace_deterministic_controls": False,
            "can_replace_human_review": False,
        },
        "findings": findings,
        "known_gaps": [
            "No behavioral baseline is created by this command.",
            "No runtime behavioral evaluator is implemented by this capability.",
            "No model-backed judging, provider call, or N-run statistical evaluation is performed.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "recommended_next_commands": recommended_commands,
        "next_actions": next_actions,
        "advisory_non_deterministic_boundary": advisory_non_deterministic_boundary,
        "human_review_required": status != "baseline_current",
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report behavioral governance baseline readiness and deterministic impacters.")
    parser.add_argument("--profile", default=None, choices=["quickstart", "lite", "standard", "assured"])
    parser.add_argument("--naos-root", default=None)
    parser.add_argument("--policy", default=None)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--rules", default=None)
    parser.add_argument("--baseline-state", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.project_root).resolve()
    policy = load_policy(explicit_policy=args.policy, root=root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    baseline_path = resolve_baseline_path(root, naos_root, policy, args.baseline_state)
    report = build_report(root, naos_root, profile, policy, rules_path, rules_source, baseline_path)

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "behavioral_governance_readiness_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        target = f" -> {output}" if output else ""
        summary = report.get("summary") or {}
        print(
            "NAOS Behavioral Governance Readiness: "
            f"{report['status']} "
            f"(baseline_present={summary.get('baseline_present')}, impacters={summary.get('total_impacters')}, cost_usd=0.0){target}"
        )
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
