#!/usr/bin/env python3
"""Run deterministic calibration-shadow checks over local NAOS reports."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    session_report_default_path,
    sessions_index_path,
    severity_for_profile,
    write_report_with_session,
)
from naos_schema_validation import validate_json_schema_file  # noqa: E402


SCHEMA = "naos.calibration_shadow_report.v1"
CONFIG_SCHEMA = "naos.calibration_shadow.v1"
CONFIG_SCHEMA_PATH = SCRIPT_DIR.parent / "schemas" / "naos" / "calibration_shadow.schema.json"
LIMITATIONS = [
    "Calibration shadow checks deterministic report metadata only.",
    "It does not calibrate models, grade model behavior, inspect chat history, call providers, or call the network.",
    "A stable report shape does not prove semantic correctness, compliance, safety, evidence sufficiency, or release readiness.",
]
NOT_CLAIMED = [
    "model behavior calibration",
    "behavioral correctness proof",
    "semantic correctness proof",
    "truth proof",
    "compliance proof",
    "approval",
    "certification",
    "regulator acceptance",
    "release authorization",
    "human review replacement",
]
RESIDUAL_RISKS = [
    "Frozen expectations may become stale after legitimate report schema changes.",
    "Small representative baselines can miss drift in reports not listed by the project.",
    "Human reviewers must decide whether detected drift is expected and acceptable.",
]
ALLOWED_TOP_LEVEL = {
    "schema",
    "profile",
    "updated_at",
    "description",
    "enabled",
    "mode",
    "baseline_policy",
    "expected_reports",
    "comparison_rules",
    "not_claimed",
    "human_review_required",
}
REQUIRED_NOT_CLAIMED = {
    "model behavior calibration",
    "behavioral correctness proof",
    "semantic correctness proof",
    "compliance proof",
    "approval",
    "release authorization",
    "human review replacement",
}


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    index_path = sessions_index_path(root, naos_root, policy)
    if not index_path.exists():
        return None
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("latest_session_id") if isinstance(data, dict) else None
    return str(value) if value else None


def finding(item_id: str, severity: str, finding_status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": item_id,
        "severity": severity,
        "status": finding_status,
        "message": message,
        "human_review_required": severity in {"required", "blocking"} or finding_status in {"review_required", "drift_detected", "invalid_config"},
        **extra,
    }


def config_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("calibration_shadow") or "calibration_shadow.yaml")
    project_path = root / naos_root / filename
    if project_path.exists() or not is_kit_repository(root, naos_root):
        return project_path, "project"
    return root / "templates" / "structural-seeds" / "naos" / "calibration_shadow.yaml", "kit_template"


def load_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "calibration shadow config must parse to a YAML mapping"
    return data, None


def validate_config(data: dict[str, Any] | None, parse_error: str | None, profile: str, policy: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    severity = severity_for_profile(profile, policy)
    if data is None:
        return False, [
            finding(
                "calibration_shadow.invalid_config",
                severity,
                "invalid_config",
                f"Calibration shadow config could not be parsed: {parse_error}",
            )
        ]
    findings: list[dict[str, Any]] = []
    schema_errors = validate_json_schema_file(data, CONFIG_SCHEMA_PATH)
    for index, error in enumerate(schema_errors):
        findings.append(
            finding(
                f"calibration_shadow.schema_validation.{index}",
                severity,
                "invalid_config",
                f"Calibration shadow config failed schema validation: {error}",
            )
        )
    if data.get("schema") != CONFIG_SCHEMA:
        findings.append(finding("calibration_shadow.schema", severity, "invalid_config", "Calibration shadow schema id is missing or unsupported."))
    if set(data) - ALLOWED_TOP_LEVEL:
        findings.append(
            finding(
                "calibration_shadow.unknown_top_level_fields",
                severity,
                "invalid_config",
                "Calibration shadow config contains unsupported top-level fields.",
                fields=sorted(set(data) - ALLOWED_TOP_LEVEL),
            )
        )
    if data.get("enabled") is not True:
        findings.append(finding("calibration_shadow.disabled", "advisory", "advisory", "Calibration shadow is disabled."))
    if data.get("mode") != "deterministic_shadow":
        findings.append(finding("calibration_shadow.mode", severity, "invalid_config", "Calibration shadow mode must be deterministic_shadow."))
    if not isinstance(data.get("baseline_policy"), dict):
        findings.append(finding("calibration_shadow.baseline_policy", severity, "invalid_config", "baseline_policy must be a mapping."))
    reports = data.get("expected_reports")
    if not isinstance(reports, list):
        findings.append(finding("calibration_shadow.expected_reports", severity, "invalid_config", "expected_reports must be a list."))
    else:
        for index, report in enumerate(reports):
            if not isinstance(report, dict):
                findings.append(finding(f"calibration_shadow.expected_reports.{index}", severity, "invalid_config", "Expected report entry must be a mapping."))
                continue
            for field in ["report_id", "path", "required", "expected_schema_prefix", "expected_statuses"]:
                if field not in report:
                    findings.append(finding(f"calibration_shadow.expected_reports.{index}.{field}", severity, "invalid_config", f"Expected report is missing {field}."))
            if "expected_statuses" in report and not isinstance(report.get("expected_statuses"), list):
                findings.append(finding(f"calibration_shadow.expected_reports.{index}.expected_statuses", severity, "invalid_config", "expected_statuses must be a list."))
    rules = data.get("comparison_rules")
    if not isinstance(rules, dict):
        findings.append(finding("calibration_shadow.comparison_rules", severity, "invalid_config", "comparison_rules must be a mapping."))
    not_claimed = set(str(item) for item in data.get("not_claimed") or [])
    missing_non_claims = sorted(REQUIRED_NOT_CLAIMED - not_claimed)
    if missing_non_claims:
        findings.append(
            finding(
                "calibration_shadow.not_claimed_missing",
                severity,
                "review_required",
                "Required non-claims are missing.",
                missing=missing_non_claims,
            )
        )
    if data.get("human_review_required") is not True:
        findings.append(finding("calibration_shadow.human_review_missing", severity, "review_required", "human_review_required must be true."))
    return not any(item.get("status") == "invalid_config" for item in findings), findings


def resolve_report_path(root: Path, path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "report must parse to a JSON object"
    return data, None


def finding_ids(data: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for key in ("findings", "known_gaps", "residual_risks"):
        items = data.get(key)
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if isinstance(item, dict):
                values.add(str(item.get("id") or item.get("finding_id") or f"{key}.{index}"))
            elif isinstance(item, str):
                values.add(f"{key}.{index}")
    return sorted(values)


def source_categories(data: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for key in ("findings", "input_sources", "reports_generated", "artifact_paths"):
        items = data.get(key)
        if isinstance(items, dict):
            values.update(str(k) for k in items)
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                for field in ("source_category", "source_type", "source", "type", "report_id"):
                    if item.get(field):
                        values.add(str(item[field]))
                        break
            elif isinstance(item, str):
                values.add(item)
    return sorted(values)


def summary_counts(data: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    summary = data.get("summary")
    if isinstance(summary, dict):
        for key, value in summary.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                counts[key] = value
    for key, value in data.items():
        if key.endswith("_count") and isinstance(value, int):
            counts[key] = value
        if key in {"findings", "known_gaps", "residual_risks"} and isinstance(value, list):
            counts[f"{key}_count"] = len(value)
    return counts


def compare_list(expected: list[str] | None, actual: list[str]) -> dict[str, Any]:
    if expected is None:
        return {"status": "not_configured", "expected": [], "actual": actual, "matches": True}
    expected_set = set(str(item) for item in expected)
    actual_set = set(str(item) for item in actual)
    return {
        "status": "match" if expected_set == actual_set else "drift",
        "expected": sorted(expected_set),
        "actual": sorted(actual_set),
        "missing": sorted(expected_set - actual_set),
        "unexpected": sorted(actual_set - expected_set),
        "matches": expected_set == actual_set,
    }


def compare_counts(expected: dict[str, Any] | None, actual: dict[str, int]) -> dict[str, Any]:
    if expected is None:
        return {"status": "not_configured", "expected": {}, "actual": actual, "matches": True}
    expected_ints = {str(key): int(value) for key, value in expected.items() if isinstance(value, int)}
    mismatches = {
        key: {"expected": value, "actual": actual.get(key)}
        for key, value in expected_ints.items()
        if actual.get(key) != value
    }
    unexpected = sorted(set(actual) - set(expected_ints))
    return {
        "status": "match" if not mismatches and not unexpected else "drift",
        "expected": expected_ints,
        "actual": actual,
        "mismatches": mismatches,
        "unexpected": unexpected,
        "matches": not mismatches and not unexpected,
    }


def evaluate_reports(config: dict[str, Any], root: Path, profile: str, policy: dict[str, Any]) -> dict[str, Any]:
    rules = config.get("comparison_rules") if isinstance(config.get("comparison_rules"), dict) else {}
    baseline = config.get("baseline_policy") if isinstance(config.get("baseline_policy"), dict) else {}
    severity = severity_for_profile(profile, policy)
    allow_missing_optional = baseline.get("allow_missing_optional_reports") is not False
    reports_checked: list[dict[str, Any]] = []
    reports_missing: list[dict[str, Any]] = []
    schema_matches: list[dict[str, Any]] = []
    status_matches: list[dict[str, Any]] = []
    finding_id_matches: list[dict[str, Any]] = []
    source_category_matches: list[dict[str, Any]] = []
    summary_count_matches: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for expected in config.get("expected_reports") or []:
        if not isinstance(expected, dict):
            continue
        report_id = str(expected.get("report_id") or "unknown")
        path = resolve_report_path(root, str(expected.get("path") or ""))
        required = expected.get("required") is True
        if not path.exists():
            missing = {"report_id": report_id, "path": str(path), "required": required, "status": "missing"}
            reports_missing.append(missing)
            if required or not allow_missing_optional:
                item = {
                    "report_id": report_id,
                    "drift_type": "missing_report",
                    "path": str(path),
                    "required": required,
                    "status": "drift_detected",
                }
                drift.append(item)
                findings.append(
                    finding(
                        f"calibration_shadow.{report_id}.missing_report",
                        severity,
                        "drift_detected",
                        f"Expected calibration report is missing: {report_id}.",
                        **item,
                    )
                )
            continue

        data, error = read_json(path)
        checked = {"report_id": report_id, "path": str(path), "required": required, "parse_error": error}
        reports_checked.append(checked)
        if data is None:
            item = {"report_id": report_id, "drift_type": "parse_error", "path": str(path), "error": error, "status": "drift_detected"}
            drift.append(item)
            findings.append(
                finding(
                    f"calibration_shadow.{report_id}.parse_error",
                    severity,
                    "drift_detected",
                    f"Expected calibration report could not be parsed: {report_id}.",
                    **item,
                )
            )
            continue

        if rules.get("compare_schema") is not False:
            actual_schema = str(data.get("schema") or "")
            expected_prefix = str(expected.get("expected_schema_prefix") or "")
            result = {
                "report_id": report_id,
                "expected_schema_prefix": expected_prefix,
                "actual_schema": actual_schema,
                "matches": actual_schema.startswith(expected_prefix),
                "status": "match" if actual_schema.startswith(expected_prefix) else "drift",
            }
            schema_matches.append(result)
            if not result["matches"]:
                drift.append({**result, "drift_type": "schema_mismatch"})
                findings.append(
                    finding(
                        f"calibration_shadow.{report_id}.schema_mismatch",
                        severity,
                        "drift_detected",
                        f"Report schema no longer matches expected prefix for {report_id}.",
                        **result,
                    )
                )

        if rules.get("compare_status") is not False:
            actual_status = str(data.get("status") or "unknown")
            expected_statuses = [str(item) for item in expected.get("expected_statuses") or []]
            result = {
                "report_id": report_id,
                "expected_statuses": expected_statuses,
                "actual_status": actual_status,
                "matches": actual_status in expected_statuses,
                "status": "match" if actual_status in expected_statuses else "drift",
            }
            status_matches.append(result)
            if not result["matches"]:
                drift.append({**result, "drift_type": "status_mismatch"})
                findings.append(
                    finding(
                        f"calibration_shadow.{report_id}.status_mismatch",
                        severity,
                        "drift_detected",
                        f"Report status is outside expected statuses for {report_id}.",
                        **result,
                    )
                )

        if rules.get("compare_finding_ids") is True:
            result = compare_list(expected.get("expected_finding_ids"), finding_ids(data))
            result["report_id"] = report_id
            finding_id_matches.append(result)
            if result["status"] == "drift":
                item = {**result, "drift_type": "finding_id_mismatch"}
                drift.append(item)
                findings.append(
                    finding(
                        f"calibration_shadow.{report_id}.finding_id_mismatch",
                        severity,
                        "drift_detected",
                        f"Report finding identifiers changed for {report_id}.",
                        **item,
                    )
                )

        if rules.get("compare_source_categories") is True:
            result = compare_list(expected.get("expected_source_categories"), source_categories(data))
            result["report_id"] = report_id
            source_category_matches.append(result)
            if result["status"] == "drift":
                item = {**result, "drift_type": "source_category_mismatch"}
                drift.append(item)
                findings.append(
                    finding(
                        f"calibration_shadow.{report_id}.source_category_mismatch",
                        severity,
                        "drift_detected",
                        f"Report source categories changed for {report_id}.",
                        **item,
                    )
                )

        if rules.get("compare_summary_counts") is True:
            result = compare_counts(expected.get("expected_summary_counts"), summary_counts(data))
            result["report_id"] = report_id
            summary_count_matches.append(result)
            if result["status"] == "drift":
                item = {**result, "drift_type": "summary_count_mismatch"}
                drift.append(item)
                findings.append(
                    finding(
                        f"calibration_shadow.{report_id}.summary_count_mismatch",
                        severity,
                        "drift_detected",
                        f"Report summary counts changed for {report_id}.",
                        **item,
                    )
                )

    unexpected_changes = [item for item in drift if item.get("drift_type") in {"source_category_mismatch", "finding_id_mismatch", "summary_count_mismatch"}]
    return {
        "reports_checked": reports_checked,
        "reports_missing": reports_missing,
        "schema_matches": schema_matches,
        "status_matches": status_matches,
        "finding_id_matches": finding_id_matches,
        "source_category_matches": source_category_matches,
        "summary_count_matches": summary_count_matches,
        "calibration_drift": drift,
        "unexpected_changes": unexpected_changes,
        "findings": findings,
        "ignored_fields": [str(item) for item in rules.get("ignore_fields") or []],
    }


def status_for_report(profile: str, config_present: bool, config_valid: bool, drift_count: int, missing_required: int) -> str:
    if not config_present:
        return "missing_config"
    if not config_valid:
        return "invalid_config"
    if drift_count:
        return "drift_detected" if profile in {"quickstart", "lite"} else "review_required"
    if missing_required:
        return "missing_reports"
    return "ready"


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, int]]:
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    generated_at = utc_now()
    path, source = config_path(root, naos_root, policy, args.input)
    config_present = path.exists()
    data: dict[str, Any] | None = None
    parse_error: str | None = None
    if config_present:
        data, parse_error = load_yaml(path)
    severity = severity_for_profile(profile, policy)
    config_valid = False
    findings: list[dict[str, Any]] = []
    evaluated = {
        "reports_checked": [],
        "reports_missing": [],
        "schema_matches": [],
        "status_matches": [],
        "finding_id_matches": [],
        "source_category_matches": [],
        "summary_count_matches": [],
        "calibration_drift": [],
        "unexpected_changes": [],
        "findings": [],
        "ignored_fields": [],
    }
    if not config_present:
        findings.append(
            finding(
                "calibration_shadow.missing_config",
                severity_for_profile(profile, policy, advisory=profile in {"quickstart", "lite"}),
                "missing_config",
                "Calibration shadow config is missing.",
                path=str(path),
            )
        )
    else:
        config_valid, config_findings = validate_config(data, parse_error, profile, policy)
        findings.extend(config_findings)
        if config_valid and data is not None and data.get("enabled") is True:
            evaluated = evaluate_reports(data, root, profile, policy)
            findings.extend(evaluated["findings"])

    drift_count = len(evaluated["calibration_drift"])
    missing_required = sum(1 for item in evaluated["reports_missing"] if item.get("required"))
    summary = finding_counts(findings)
    status = status_for_report(profile, config_present, config_valid, drift_count, missing_required)
    session_id = latest_session_id(root, naos_root, policy)
    report = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "session_id": session_id,
        "generated_by": build_generated_by(root, session_id=session_id, generated_at=generated_at),
        "calibration_config_path": str(path),
        "calibration_config_source": source,
        "calibration_config_present": config_present,
        "calibration_config_valid": config_valid,
        "reports_checked": evaluated["reports_checked"],
        "reports_missing": evaluated["reports_missing"],
        "schema_matches": evaluated["schema_matches"],
        "status_matches": evaluated["status_matches"],
        "finding_id_matches": evaluated["finding_id_matches"],
        "source_category_matches": evaluated["source_category_matches"],
        "summary_count_matches": evaluated["summary_count_matches"],
        "calibration_drift": evaluated["calibration_drift"],
        "drift_count": drift_count,
        "unexpected_changes": evaluated["unexpected_changes"],
        "ignored_fields": evaluated["ignored_fields"],
        "findings": findings,
        "known_gaps": [
            "Calibration shadow covers only reports listed in naos/calibration_shadow.yaml.",
            "The default seed is intentionally small and representative.",
        ],
        "residual_risks": RESIDUAL_RISKS,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings) or True,
        "summary": {
            **summary,
            "reports_checked": len(evaluated["reports_checked"]),
            "reports_missing": len(evaluated["reports_missing"]),
            "drift_count": drift_count,
            "unexpected_changes": len(evaluated["unexpected_changes"]),
            "config_source": source,
        },
    }
    return report, summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic NAOS calibration-shadow checks.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--input", help="Explicit calibration_shadow.yaml path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, summary = build_report(args)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    latest_path = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "calibration_shadow_report")
    session_path = None
    if report.get("session_id"):
        session_path = session_report_default_path(root, naos_root, policy, str(report["session_id"]), "calibration_shadow_report")
    write_report_with_session(latest_path, session_path, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS calibration shadow: {report['status']} ({report['drift_count']} drift items)")
    return exit_code_for_summary(report["profile"], summary, policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
