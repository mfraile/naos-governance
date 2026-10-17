#!/usr/bin/env python3
"""Report behavioral governance baseline readiness and deterministic impacters."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_ai_surfaces import DEFAULT_PATHS, INSTRUCTION_NAMES, discovered_surface_type, MCP_CONFIGURATION_PATHS, cursor_skill_path, checked_path, literal_path, load_surface_rules, scan_files  # noqa: E402

from naos_policy import (  # noqa: E402
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    load_yaml_temporal_text,
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
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
    except ValueError:
        return None


def age_days(value: Any, now_text: str) -> int | None:
    timestamp = parse_time(value)
    now = parse_time(now_text)
    if timestamp is None or now is None or timestamp > now:
        return None
    return (now - timestamp).days


def baseline_timestamp(baseline: dict[str, Any]) -> Any:
    # A present but invalid override is evidence to repair, not permission to
    # substitute an older timestamp and silently bypass freshness evaluation.
    return baseline.get("last_behavioral_baseline_at") if "last_behavioral_baseline_at" in baseline else baseline.get("generated_at")


def validate_baseline_metadata(baseline: dict[str, Any], now_text: str) -> list[str]:
    issues: list[str] = []
    if baseline.get("schema") != "naos.behavioral_baseline_state.v1":
        issues.append("unsupported_or_missing_schema")
    if baseline.get("profile") not in ("quickstart", "lite", "standard", "assured"):
        issues.append("unsupported_or_missing_profile")
    fingerprints = baseline.get("fingerprints")
    if not isinstance(fingerprints, dict) or any(
        not isinstance(key, str) or not key or not isinstance(value, str) or not value
        for key, value in fingerprints.items()
    ):
        issues.append("fingerprints_must_map_nonempty_strings_to_nonempty_strings")
    if parse_time(now_text) is None:
        issues.append("comparison_time_requires_explicit_utc_offset")
    if parse_time(baseline_timestamp(baseline)) is None:
        issues.append("baseline_time_requires_explicit_utc_offset")
    elif parse_time(now_text) is not None and age_days(baseline_timestamp(baseline), now_text) is None:
        issues.append("baseline_time_is_in_the_future")
    return issues


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
        data = load_yaml_temporal_text(path.read_text(encoding="utf-8")) or {}
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
    digest, meta = digest_path(path, max_files)
    return digest, meta["truncated"], meta["file_count"]


def digest_path(path: Path, max_files: int, root: Path | None = None) -> tuple[str | None, dict[str, Any]]:
    root = root or path.parent
    files, meta = scan_files(root, path.relative_to(root).as_posix(), max_files)
    digest = hashlib.sha256()
    try:
        for item in files:
            checked_path(root, item.relative_to(root).as_posix())
            item_hash = safe_digest(item)
            if item_hash is None:
                raise ValueError("file disappeared during fingerprinting")
            if meta["type"] == "file":
                return item_hash, meta
            digest.update(item.relative_to(path).as_posix().encode("utf-8"))
            digest.update(item_hash.encode("ascii"))
    except (OSError, ValueError) as exc:
        meta["complete"] = False
        meta["issues"].append({"path": meta["path"], "reason": str(exc)})
    # Partial fingerprints cannot serve as current baseline evidence.
    if not meta["complete"] or not meta["present"]:
        return None, meta
    return digest.hexdigest(), meta


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


def confirmed_absent_path(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


PREREQUISITE_SCHEMAS = {
    "static_grader_report": "static_grader_report.schema.json",
    "grader_assessment_report": "grader_assessment.schema.json",
    "llm_grader_readiness_report": "llm_grader_readiness.schema.json",
}


def finite_number(value: Any) -> bool:
    try:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    except OverflowError:
        return False


def conformance_contract_issues(data: dict[str, Any]) -> list[str]:
    """Check the deterministic runner's count/score contract, not behavioral grading."""
    issues: list[str] = []
    try:
        datetime.fromisoformat(data.get("run_date", "").replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        issues.append("run_date:invalid")
    if data.get("mode") != "conformance":
        issues.append("mode:invalid")
    passed = total = 0
    for key in ("structural_checks", "frontmatter_checks", "battery_checks"):
        section = data.get(key)
        if not isinstance(section, dict):
            issues.append(f"{key}:object_required")
            continue
        count, size = section.get("passed"), section.get("total")
        if type(count) is not int or type(size) is not int or not 0 <= count <= size:
            issues.append(f"{key}:invalid_counts")
            continue
        passed += count
        total += size
        expected = round(count / size, 3) if size else None
        score = section.get("score")
        if "score" not in section or (expected is None and score is not None) or (expected is not None and (not finite_number(score) or score != expected)):
            issues.append(f"{key}:inconsistent_score")
        if key == "frontmatter_checks":
            results = section.get("results")
            if not isinstance(results, list) or len(results) != size or any(
                not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or type(item.get("passed")) is not bool or not isinstance(item.get("note"), str)
                for item in results
            ):
                issues.append(f"{key}:invalid_results")
            elif sum(item["passed"] for item in results) != count:
                issues.append(f"{key}:inconsistent_results")
    score = data.get("overall_conformance")
    expected = round(passed / total, 3) if total else None
    if "overall_conformance" not in data or (expected is None and score is not None) or (expected is not None and (not finite_number(score) or score != expected)):
        issues.append("overall_conformance:inconsistent_score")
    dimensions = data.get("dimensions")
    names = ("D1_rule_compliance", "D2_agent_instructions", "D3_scoped_instructions", "D4_prompt_templates", "D5_efficiency", "D6_portability", "D7_session_hygiene", "D8_ai_output_quality")
    if not isinstance(dimensions, dict) or any(name not in dimensions or (dimensions[name] is not None and (not finite_number(dimensions[name]) or not 0 <= dimensions[name] <= 1)) for name in names):
        issues.append("dimensions:invalid")
    if type(data.get("scenarios_run")) is not int or data["scenarios_run"] < 0:
        issues.append("scenarios_run:invalid")
    if not finite_number(data.get("cost_usd")) or data["cost_usd"] < 0:
        issues.append("cost_usd:invalid")
    return issues


def prerequisite_contract_issues(data: dict[str, Any], key: str) -> list[str]:
    if key == "conformance_latest":
        return conformance_contract_issues(data)
    filename = PREREQUISITE_SCHEMAS.get(key)
    if filename is None:
        return ["report_contract:unavailable"]
    try:
        schema = json.loads((kit_root() / "schemas" / "naos" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        issues = sorted({"/".join(str(part) for part in error.absolute_path) + ":" + str(error.validator) for error in validator.iter_errors(data)})
    except Exception as exc:
        # Missing or damaged local contracts must never silently skip validation.
        return ["report_contract:unavailable:" + type(exc).__name__]
    if key == "llm_grader_readiness_report":
        cost = data.get("cost_posture")
        if isinstance(cost, dict) and not finite_number(cost.get("cost_usd")):
            issues.append("cost_posture/cost_usd:finite_number_required")
    return issues


def report_status(data: dict[str, Any], key: str) -> str:
    if key == "conformance_latest":
        if conformance_contract_issues(data):
            return "invalid_contract"
        sections = [data[name] for name in ("structural_checks", "frontmatter_checks", "battery_checks")]
        # Rounded 1.0 alone must not hide a failed check or an empty run.
        return "pass" if sum(item["total"] for item in sections) > 0 and all(item["passed"] == item["total"] for item in sections) else "failed"
    return str(data.get("status") or data.get("health_status") or data.get("readiness_status") or "present")


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
    issues = prerequisite_contract_issues(data, key) if data and (required or key in PREREQUISITE_SCHEMAS) else []
    if status not in {"missing", "parse_error"} and (issues or not data):
        status = "invalid_contract"
        issues = issues or ["report_contract:empty"]
    item = {
        "id": key,
        "path": str(path),
        "present": path.exists(),
        "required": required,
        "status": status,
        "schema": data.get("schema"),
        "generated_at": data.get("generated_at") or data.get("run_date"),
        "hash": safe_digest(path),
        "contract_issues": issues,
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


def configured_impacter_paths(rules: dict[str, Any], naos_root: str = "naos", surfaces: list[str] | None = None) -> list[str]:
    values = rules.get("impacter_paths", [])
    if not isinstance(values, list):
        raise ValueError("impacter_paths must be a list of literal relative paths")
    if values:
        return list(dict.fromkeys(literal_path(value) for value in values))
    return list(dict.fromkeys([
        f"{naos_root}/behavioral_governance_readiness_rules.yaml",
        f"{naos_root}/llm_grader_readiness_rules.yaml",
        f"{naos_root}/ai_surface_context_budget_rules.yaml",
        f"{naos_root}/agent_trace_events.yaml",
        "configs/naos_autoresearch.yaml",
        ".github/configs/naos_autoresearch.yaml",
        ".github/autoresearch/task_battery",
        ".github/workflows",
        *(DEFAULT_PATHS if surfaces is None else surfaces),
    ]))


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
            missing_finding = finding(
                f"behavioral_readiness.missing_{key}",
                profile_severity(profile, "warning"),
                "not_ready",
                f"Required deterministic input `{key}` is missing.",
                evidence={"path": item["path"]},
            )
            if item.get("path") and confirmed_absent_path(Path(item["path"])):
                missing_finding.update(
                    evidence_classification="confirmed",
                    classification_scope="selected_required_report_absent_at_readiness_check",
                    reasoning_summary="The selected required report path did not exist at this check; this does not establish why it is absent or make the readiness input optional.",
                    source_path=str(Path(__file__).resolve()),
                )
            findings.append(missing_finding)
        elif key in required and item["status"] not in REPORT_STATUS_OK:
            findings.append(
                finding(
                    f"behavioral_readiness.unready_{key}",
                    profile_severity(profile, "warning"),
                    "not_ready",
                    f"Required deterministic input `{key}` has status `{item['status']}`.",
                    evidence={"path": item["path"], "status": item["status"], "contract_issues": item["contract_issues"]},
                )
            )

    llm_item = next((item for item in inputs if item["id"] == "llm_grader_readiness_report"), None)
    llm_data = data_by_key.get("llm_grader_readiness_report") or {}
    if llm_item and llm_item["present"] and llm_item["status"] in {"invalid_contract", "parse_error"} and not llm_item["required"]:
        findings.append(finding(
            "behavioral_readiness.invalid_llm_readiness_contract", "blocking", "not_ready",
            "Present LLM readiness input cannot establish a safe posture because its contract is invalid.",
            evidence={"path": llm_item["path"], "contract_issues": llm_item["contract_issues"]},
        ))
    if llm_item and llm_item["present"] and llm_item["status"] not in {"invalid_contract", "parse_error"}:
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

    try:
        settings = rules.get("path_fingerprinting", {})
        if not isinstance(settings, dict):
            raise ValueError("path_fingerprinting must be a mapping")
        max_files = settings.get("max_files_per_path", 200)
        if type(max_files) is not int or not 1 <= max_files <= 100000:
            raise ValueError("max_files_per_path must be an integer from 1 to 100000")
        surfaces = list(DEFAULT_PATHS)
        if not rules.get("impacter_paths"):
            surface_rules = load_surface_rules(root, naos_root, policy)
            if surface_rules["invalid_config"]:
                raise ValueError("invalid inventory surface rules")
            surfaces = surface_rules["effective_patterns"]
        paths = configured_impacter_paths(rules, naos_root, surfaces)
        if not rules.get("impacter_paths"):
            discovered, discovery = scan_files(root, None, surface_rules["limits"]["max_discovery_files"])
            metadata.append({"id": "instruction_discovery", **discovery})
            paths = list(dict.fromkeys(paths + [path.relative_to(root).as_posix()
                for path in discovered if discovered_surface_type(path.relative_to(root).as_posix(), surfaces) is not None]))
    except (ValueError, TypeError) as exc:
        metadata.append({"id": "path_configuration", "present": False, "ignored": True, "complete": False, "reason": str(exc)})
        return fingerprints, metadata
    for rel_text in paths:
        path = root / rel_text
        digest, meta = digest_path(path, max_files, root)
        item = {"id": f"path:{rel_text}", "path": str(path), **meta, "host_surface": rel_text in surfaces}
        metadata.append(item)
        if digest:
            fingerprints[f"path:{rel_text}"] = digest
    return fingerprints, metadata


def impact_severity(key: str, host_paths: list[str] | None = None) -> str:
    if key in HIGH_IMPACT_KEYS:
        return "high"
    if key.startswith("path:"):
        relative = key.removeprefix("path:")
        if Path(relative).name in INSTRUCTION_NAMES or relative in MCP_CONFIGURATION_PATHS or cursor_skill_path(relative):
            return "medium"
    if any(key == "path:" + path or key.startswith("path:" + path + "/") for path in (DEFAULT_PATHS if host_paths is None else host_paths)):
        return "medium"
    if any(key.startswith(prefix) for prefix in MEDIUM_IMPACT_PREFIXES):
        return "medium"
    return "low"


def compare_baseline(
    baseline: dict[str, Any],
    current_fingerprints: dict[str, str],
    profile: str,
    rules: dict[str, Any],
    now_text: str,
    host_paths: list[str] | None = None,
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
        severity = impact_severity(key, host_paths)
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

    baseline_time = baseline_timestamp(baseline)
    days = age_days(baseline_time, now_text)
    max_age_days = int(as_mapping(rules.get("baseline_state")).get("max_age_days") or rules.get("max_age_days") or 90)
    required_age_days = int(as_mapping(rules.get("baseline_state")).get("required_after_days") or max_age_days * 2)
    if days is None:
        findings.append(
            finding(
                "behavioral_readiness.baseline_timestamp_unparseable",
                "warning",
                "maintenance_recommended",
                "Baseline age is unresolved: timestamps must have explicit UTC offsets and the baseline must not be in the future.",
                evidence={"baseline_time": baseline_time},
            )
        )
        impacters.append({"id": "baseline_age", "category": "baseline_age", "severity": "medium", "status": "unresolved_timestamp"})
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
            f"naos self-check --profile {profile} --refresh",
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
    if any(not item.get("complete", True) for item in path_metadata):
        findings.append(finding(
            "behavioral_readiness.incomplete_fingerprints", "warning", "not_ready",
            "Configured fingerprint coverage is incomplete; resolve invalid paths, read failures or truncation before baselining.",
            evidence={"incomplete_paths": [item["id"] for item in path_metadata if not item.get("complete", True)]},
        ))

    baseline_present = baseline_path.exists()
    baseline_state: dict[str, Any] = {}
    baseline_error: str | None = None
    baseline_validation: dict[str, Any] = {"status": "not_present", "issues": []}
    if baseline_present:
        try:
            baseline_state = load_structured_mapping(baseline_path)
            issues = validate_baseline_metadata(baseline_state, now_text)
            baseline_validation = {"status": "invalid" if issues else "valid", "issues": issues}
            if issues:
                findings.append(finding(
                    "behavioral_readiness.baseline_metadata_invalid", "blocking", "not_ready",
                    "Present baseline metadata is invalid; repair it through human-reviewed baseline maintenance.",
                    evidence={"path": str(baseline_path), "issues": issues},
                ))
        except Exception as exc:
            baseline_error = str(exc)
            baseline_validation = {"status": "invalid", "issues": ["baseline_parse_error"]}
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
    if baseline_validation["status"] == "valid" and not readiness_findings:
        impacters, baseline_findings = compare_baseline(baseline_state, current_fingerprints, profile, rules, now_text, [item["id"][5:] for item in path_metadata if item.get("host_surface")])
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
        "baseline_validation_status": baseline_validation["status"],
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
        "baseline_validation": baseline_validation,
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
