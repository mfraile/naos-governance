#!/usr/bin/env python3
"""Validate local parallel-lane handoff evidence and write a namespaced report.

This is deterministic review evidence only. It does not approve work, close
tasks, merge branches, dispatch agents, prove compliance, or activate runtime,
MCP, memory, provider, model, hook, API, or network behavior.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
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
    safe_policy_path,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.parallel_lane_handoff.v1"
SAFE_FRAGMENT_RE = re.compile(r"[^A-Za-z0-9._:@+-]+")
LANE_STATUSES = {
    "complete_needs_review",
    "blocked_dependency",
    "blocked_scope_drift",
    "blocked_failed_checks",
    "abandoned",
    "superseded",
    "unknown",
}
READY_DEPENDENCY_STATES = {"", "none", "not_applicable", "ready", "unlocked", "cleared", "complete"}
HIGHER_REGULATED_CONTEXTS = {"higher_regulated", "high_regulated", "regulated_high", "high"}

LIMITATIONS = [
    "Parallel lane handoff reports are local deterministic review evidence only.",
    "Reports depend on adopter-declared lane, task, dependency, path, and test evidence.",
    "Changed-file evidence is summarized from supplied handoff data; semantic correctness and safe merge are not inferred.",
    "Assured-profile blocking is not enabled by this first implementation slice; gate wiring and maturity promotion remain separate decisions.",
]
NOT_CLAIMED = [
    "approval",
    "merge approval",
    "merge readiness proof",
    "task completion proof",
    "dependency unlocking",
    "automatic task closure",
    "automatic dispatch",
    "runtime orchestration",
    "MCP activation",
    "memory activation",
    "hook activation",
    "provider calls",
    "model calls",
    "API calls",
    "network calls",
    "legal sufficiency",
    "compliance proof",
    "certification",
    "attestation",
    "release authority",
    "publication authority",
]
RESIDUAL_RISKS = [
    "handoff_data_is_adopter_declared",
    "manual_changed_file_lists_can_be_incomplete",
    "report_does_not_detect_semantic_conflicts",
    "parallel_lane_interactions_still_require_human_review",
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


def dedupe_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def safe_fragment(value: Any, fallback: str = "unscoped", max_length: int = 96) -> str:
    cleaned = SAFE_FRAGMENT_RE.sub("_", str(value or "").strip())[:max_length].strip("._-")
    return cleaned or fallback


def normalize_path(value: Any) -> str:
    text = str(value or "").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/") if text not in {"", ".", "*"} else text


def normalize_paths(value: Any) -> list[str]:
    return dedupe_strings([normalize_path(item) for item in as_list(value) if normalize_path(item)])


def path_matches(path: str, declarations: list[str]) -> bool:
    normalized = normalize_path(path)
    for declaration in declarations:
        item = normalize_path(declaration)
        if item in {"*", "."}:
            return True
        if not item:
            continue
        prefix = item.rstrip("/")
        if normalized == prefix or normalized.startswith(f"{prefix}/"):
            return True
        if fnmatch.fnmatch(normalized, item):
            return True
    return False


def finding(
    identifier: str,
    severity: str,
    status: str,
    message: str,
    gate: str,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": status,
        "gate": gate,
        "message": message,
        "human_review_required": True,
    }
    item.update({key: value for key, value in extra.items() if value is not None})
    return item


def review_severity(profile: str, root: Path, naos_root: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    if profile == "quickstart":
        return "advisory"
    if profile == "lite":
        return "warning"
    # This first slice intentionally does not enable assured blocking.
    return "required"


def load_handoff(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not path.exists():
        return {}, [
            finding(
                "parallel_lane_handoff.input_missing",
                "advisory",
                "missing_handoff",
                f"Handoff input file does not exist: {path}",
                "G6 Evidence",
                handoff_path=str(path),
            )
        ]
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {}, [
            finding(
                "parallel_lane_handoff.input_unreadable",
                "advisory",
                "invalid_handoff",
                f"Handoff input file could not be parsed: {exc}",
                "G6 Evidence",
                handoff_path=str(path),
            )
        ]
    if not isinstance(data, dict):
        return {}, [
            finding(
                "parallel_lane_handoff.input_not_mapping",
                "advisory",
                "invalid_handoff",
                "Handoff input must be a mapping.",
                "G6 Evidence",
                handoff_path=str(path),
            )
        ]
    return data, []


def handoff_from_args(args: argparse.Namespace) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if args.parallel_lanes_declared:
        data["parallel_lanes_declared"] = True
    if args.lane_id:
        data["lane_id"] = args.lane_id
    if args.lane_status:
        data["lane_status"] = args.lane_status
    if args.task:
        data["task_id"] = args.task
    if args.fr_nfr_ref:
        data["fr_nfr_refs"] = args.fr_nfr_ref
    if args.planned_path:
        data["planned_change_paths"] = args.planned_path
    if args.out_of_scope_path:
        data["out_of_scope_paths"] = args.out_of_scope_path
    if args.changed_file:
        data["changed_files"] = args.changed_file
    if args.generated_evidence_file:
        data["generated_evidence_files"] = args.generated_evidence_file
    if args.check_passed:
        data["checks_passed"] = args.check_passed
    if args.check_failed:
        data["checks_failed"] = args.check_failed
    if args.check_unavailable:
        data["checks_unavailable"] = args.check_unavailable
    if args.check_skipped:
        data["checks_skipped"] = args.check_skipped
    if args.criticality_context:
        data["criticality_context"] = args.criticality_context
    return data


def merge_cli_overrides(data: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    merged = dict(data)
    for key, value in handoff_from_args(args).items():
        merged[key] = value
    return merged


def collect_tests(data: dict[str, Any]) -> dict[str, list[str]]:
    tests = as_mapping(data.get("tests"))
    return {
        "attempted": dedupe_strings(string_list(data.get("tests_attempted")) + string_list(data.get("checks_attempted")) + string_list(tests.get("attempted"))),
        "passed": dedupe_strings(string_list(data.get("tests_passed")) + string_list(data.get("checks_passed")) + string_list(tests.get("passed"))),
        "failed": dedupe_strings(string_list(data.get("tests_failed")) + string_list(data.get("checks_failed")) + string_list(tests.get("failed"))),
        "unavailable": dedupe_strings(string_list(data.get("tests_unavailable")) + string_list(data.get("checks_unavailable")) + string_list(tests.get("unavailable"))),
        "skipped": dedupe_strings(string_list(data.get("tests_skipped")) + string_list(data.get("checks_skipped")) + string_list(data.get("tests_not_run")) + string_list(tests.get("skipped"))),
    }


def collect_changed_files(data: dict[str, Any]) -> dict[str, list[str]]:
    code = normalize_paths(data.get("changed_code_files")) + normalize_paths(data.get("source_files"))
    tests = normalize_paths(data.get("changed_test_files")) + normalize_paths(data.get("test_files"))
    config = normalize_paths(data.get("changed_config_files")) + normalize_paths(data.get("config_files"))
    docs = normalize_paths(data.get("changed_doc_files")) + normalize_paths(data.get("documentation_files"))
    all_changed = normalize_paths(data.get("changed_files")) + code + tests + config + docs
    generated = normalize_paths(data.get("generated_evidence_files"))
    noise = normalize_paths(data.get("evidence_noise")) + normalize_paths(data.get("cache_build_noise"))
    return {
        "changed_files": dedupe_strings(all_changed),
        "changed_code_files": dedupe_strings(code),
        "changed_test_files": dedupe_strings(tests),
        "changed_config_files": dedupe_strings(config),
        "changed_doc_files": dedupe_strings(docs),
        "generated_evidence_files": dedupe_strings(generated),
        "evidence_noise": dedupe_strings(noise),
    }


def lane_report_path(root: Path, naos_root: str, policy: dict[str, Any], lane_id: str | None, output_dir: str | None = None) -> Path | None:
    if is_kit_repository(root, naos_root):
        return None
    if not (root / naos_root).is_dir():
        return None
    filename = f"{safe_fragment(lane_id)}.json"
    if output_dir:
        base = Path(output_dir)
        if not base.is_absolute():
            base = root / base
        return base / filename
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    return safe_policy_path(root / naos_root, reports_dir, "parallel_lane_handoff", filename, field="parallel_lane_handoff_report")


def build_report(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    handoff_data: dict[str, Any] | None = None,
    *,
    handoff_path: str | None = None,
    load_findings: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    capability_maturity: str = "L2",
) -> dict[str, Any]:
    data = dict(handoff_data or {})
    generated_at = generated_at or utc_now_text()
    severity = review_severity(profile, root, naos_root)
    findings: list[dict[str, Any]] = list(load_findings or [])

    parallel_lanes_declared = bool_value(data.get("parallel_lanes_declared"), False)
    lane_id = str(data.get("lane_id") or "").strip() or None
    lane_status = str(data.get("lane_status") or "unknown").strip() or "unknown"
    task_id = str(data.get("task_id") or "").strip() or None
    fr_nfr_refs = dedupe_strings(string_list(data.get("fr_nfr_refs")))
    requirement_refs = dedupe_strings(string_list(data.get("requirement_refs")))
    criticality_context = str(data.get("criticality_context") or "unspecified").strip() or "unspecified"

    dependency_state = str(data.get("dependency_state") or "").strip().lower()
    dependency_blockers = dedupe_strings(string_list(data.get("dependency_blockers")))
    unlock_evidence = dedupe_strings(string_list(data.get("unlock_evidence")))
    claim_conflicts = dedupe_strings(string_list(data.get("claim_conflicts")))
    dependency_exceptions = dedupe_strings(string_list(data.get("dependency_exceptions")) + string_list(data.get("exception_rationale")))
    scope_exceptions = dedupe_strings(string_list(data.get("scope_exceptions")) + string_list(data.get("exception_rationale")))
    alternative_evidence = dedupe_strings(string_list(data.get("alternative_evidence")))

    paths = collect_changed_files(data)
    planned_change_paths = normalize_paths(data.get("planned_change_paths"))
    out_of_scope_paths = normalize_paths(data.get("out_of_scope_paths"))
    generated_or_noise = set(paths["generated_evidence_files"] + paths["evidence_noise"])
    review_changed_files = [path for path in paths["changed_files"] if path not in generated_or_noise]
    out_of_scope_changed = [path for path in review_changed_files if path_matches(path, out_of_scope_paths)]
    unplanned_changed = [
        path
        for path in review_changed_files
        if planned_change_paths and not path_matches(path, planned_change_paths) and not path_matches(path, out_of_scope_paths)
    ]
    tests = collect_tests(data)
    report_refs = dedupe_strings(string_list(data.get("naos_reports_generated")) + string_list(data.get("generated_reports")))
    evidence_conflicts = dedupe_strings(string_list(data.get("evidence_conflicts")))
    residual_risks = dedupe_strings(RESIDUAL_RISKS + string_list(data.get("residual_risks")))
    handoff_not_claimed = dedupe_strings(string_list(data.get("not_claimed")))
    input_human_review_required = data.get("human_review_required")

    if not parallel_lanes_declared:
        known_gaps = ["parallel_lanes_not_declared"]
    else:
        known_gaps = []
        if not lane_id and not handoff_path:
            findings.append(
                finding(
                    "parallel_lane_handoff.missing_handoff",
                    severity,
                    "missing_handoff",
                    "Parallel lanes are declared but no lane handoff artifact or lane id was provided.",
                    "G6 Evidence",
                )
            )
        if not lane_id:
            findings.append(
                finding(
                    "parallel_lane_handoff.missing_lane_id",
                    severity,
                    "missing_lane_identity",
                    "Declared lane handoff is missing lane_id.",
                    "G2 Planning",
                )
            )
        if lane_status not in LANE_STATUSES:
            findings.append(
                finding(
                    "parallel_lane_handoff.invalid_lane_status",
                    severity,
                    "invalid_lane_status",
                    "Lane status is not one of the approved review statuses.",
                    "G6 Evidence",
                    lane_status=lane_status,
                    allowed_statuses=sorted(LANE_STATUSES),
                )
            )
        if not task_id and not fr_nfr_refs and not requirement_refs:
            findings.append(
                finding(
                    "parallel_lane_handoff.missing_task_reference",
                    severity,
                    "missing_task_reference",
                    "Declared lane handoff is missing task_id, FR/NFR refs, and requirement refs.",
                    "G2 Planning",
                )
            )
        if claim_conflicts:
            findings.append(
                finding(
                    "parallel_lane_handoff.claim_conflict",
                    severity,
                    "claim_conflict",
                    "Task claim conflicts are recorded for this lane.",
                    "G2 Planning",
                    claim_conflicts=claim_conflicts,
                )
            )
        dependency_unresolved = bool(dependency_blockers) or dependency_state not in READY_DEPENDENCY_STATES
        if lane_status == "complete_needs_review" and dependency_unresolved:
            findings.append(
                finding(
                    "parallel_lane_handoff.dependency_conflict",
                    severity,
                    "dependency_conflict",
                    "Lane is complete_needs_review but dependency evidence is unresolved or blocked.",
                    "G2 Planning",
                    dependency_state=dependency_state or None,
                    dependency_blockers=dependency_blockers,
                )
            )
        if lane_status == "blocked_dependency" and not dependency_blockers and not dependency_state:
            findings.append(
                finding(
                    "parallel_lane_handoff.dependency_blocker_missing",
                    severity,
                    "dependency_blocker_missing",
                    "Lane is blocked_dependency but no dependency blocker or state was recorded.",
                    "G2 Planning",
                )
            )
        if out_of_scope_changed or unplanned_changed:
            findings.append(
                finding(
                    "parallel_lane_handoff.scope_drift",
                    severity,
                    "scope_drift",
                    "Changed files fall outside declared planned paths or match out-of-scope paths.",
                    "G3 Scope",
                    unplanned_changed_files=unplanned_changed,
                    out_of_scope_changed_files=out_of_scope_changed,
                )
            )
        if lane_status == "complete_needs_review" and not review_changed_files:
            findings.append(
                finding(
                    "parallel_lane_handoff.code_evidence_missing",
                    severity,
                    "code_evidence_missing",
                    "Lane is complete_needs_review but no changed-file/code evidence was recorded.",
                    "G4 Code",
                )
            )
        has_test_evidence = bool(tests["attempted"] or tests["passed"] or tests["failed"] or tests["unavailable"] or tests["skipped"])
        if lane_status == "complete_needs_review" and not has_test_evidence:
            findings.append(
                finding(
                    "parallel_lane_handoff.test_evidence_missing",
                    severity,
                    "test_evidence_missing",
                    "Lane is complete_needs_review but no test/check evidence was recorded.",
                    "G5 Test Evidence",
                )
            )
        if tests["failed"]:
            findings.append(
                finding(
                    "parallel_lane_handoff.checks_failed",
                    severity,
                    "checks_failed",
                    "One or more lane checks failed.",
                    "G5 Test Evidence",
                    checks_failed=tests["failed"],
                )
            )
        if tests["unavailable"]:
            findings.append(
                finding(
                    "parallel_lane_handoff.checks_unavailable",
                    "advisory",
                    "checks_unavailable",
                    "One or more attempted checks were unavailable; this is distinct from a failed check.",
                    "G5 Test Evidence",
                    checks_unavailable=tests["unavailable"],
                )
            )
        if lane_status == "blocked_failed_checks" and not tests["failed"]:
            findings.append(
                finding(
                    "parallel_lane_handoff.failed_check_evidence_missing",
                    severity,
                    "failed_check_evidence_missing",
                    "Lane is blocked_failed_checks but no failed check evidence was recorded.",
                    "G5 Test Evidence",
                )
            )
        if evidence_conflicts:
            findings.append(
                finding(
                    "parallel_lane_handoff.evidence_conflict",
                    severity,
                    "evidence_conflict",
                    "The handoff records unresolved evidence conflicts.",
                    "G6 Evidence",
                    evidence_conflicts=evidence_conflicts,
                )
            )
        if input_human_review_required is not True:
            findings.append(
                finding(
                    "parallel_lane_handoff.human_review_missing",
                    severity,
                    "human_review_missing",
                    "Declared lane handoff must explicitly require human review.",
                    "G6 Evidence",
                )
            )
        if not handoff_not_claimed:
            findings.append(
                finding(
                    "parallel_lane_handoff.non_claims_missing",
                    "advisory",
                    "non_claims_missing",
                    "Lane handoff input did not include explicit non-claims.",
                    "G6 Evidence",
                )
            )
        if criticality_context.lower() in HIGHER_REGULATED_CONTEXTS and alternative_evidence and not (dependency_exceptions or scope_exceptions):
            findings.append(
                finding(
                    "parallel_lane_handoff.criticality_exception_missing",
                    severity,
                    "criticality_exception_missing",
                    "Higher-regulated assured-style evidence flexibility requires explicit exception rationale.",
                    "G2/G6",
                    criticality_context=criticality_context,
                )
            )

    summary = finding_counts(findings)
    summary.update(
        {
            "parallel_lanes_declared": 1 if parallel_lanes_declared else 0,
            "changed_files": len(paths["changed_files"]),
            "review_changed_files": len(review_changed_files),
            "generated_evidence_files": len(paths["generated_evidence_files"]),
            "evidence_noise_files": len(paths["evidence_noise"]),
            "unplanned_changed_files": len(unplanned_changed),
            "out_of_scope_changed_files": len(out_of_scope_changed),
            "checks_passed": len(tests["passed"]),
            "checks_failed": len(tests["failed"]),
            "checks_unavailable": len(tests["unavailable"]),
            "assured_blocking_enabled": 0,
        }
    )
    status = "not_applicable" if not parallel_lanes_declared and not findings else status_from_counts(summary)
    lane = {
        "lane_id": lane_id,
        "lane_status": lane_status,
        "task_id": task_id,
        "fr_nfr_refs": fr_nfr_refs,
        "requirement_refs": requirement_refs,
        "operator_id": data.get("operator_id"),
        "operator_source": data.get("operator_source"),
        "session_id": data.get("session_id"),
        "branch": data.get("branch"),
        "worktree_path": data.get("worktree_path"),
        "started_at": data.get("started_at"),
        "completed_at": data.get("completed_at"),
        "dependency_state": dependency_state or None,
        "dependency_blockers": dependency_blockers,
        "unlock_evidence": unlock_evidence,
        "claim_status": data.get("claim_status"),
        "claim_conflicts": claim_conflicts,
        "planned_change_paths": planned_change_paths,
        "out_of_scope_paths": out_of_scope_paths,
        "changed_files": paths["changed_files"],
        "review_changed_files": review_changed_files,
        "generated_evidence_files": paths["generated_evidence_files"],
        "evidence_noise": paths["evidence_noise"],
        "unplanned_changed_files": unplanned_changed,
        "out_of_scope_changed_files": out_of_scope_changed,
        "tests": tests,
        "naos_reports_generated": report_refs,
        "report_freshness": as_mapping(data.get("report_freshness")),
        "handoff_summary": data.get("handoff_summary"),
        "recommended_next_review_action": data.get("recommended_next_review_action"),
    }
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "parallel_lanes_declared": parallel_lanes_declared,
        "criticality_context": criticality_context,
        "capability_maturity": {
            "current": capability_maturity,
            "assured_blocking_enabled": False,
            "blocking_requires_l3_plus_and_gate_wiring": True,
        },
        "handoff_path": handoff_path,
        "lane": lane,
        "findings": findings,
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(parallel_lanes_declared or findings or input_human_review_required),
        "generated_by": build_generated_by(root, session_id=data.get("session_id"), generated_at=generated_at),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate local parallel-lane handoff evidence.")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--handoff", help="YAML/JSON handoff input for one lane.")
    parser.add_argument("--lane-id")
    parser.add_argument("--lane-status", choices=sorted(LANE_STATUSES))
    parser.add_argument("--task")
    parser.add_argument("--fr-nfr-ref", action="append")
    parser.add_argument("--parallel-lanes-declared", action="store_true")
    parser.add_argument("--criticality-context")
    parser.add_argument("--planned-path", action="append")
    parser.add_argument("--out-of-scope-path", action="append")
    parser.add_argument("--changed-file", action="append")
    parser.add_argument("--generated-evidence-file", action="append")
    parser.add_argument("--check-passed", action="append")
    parser.add_argument("--check-failed", action="append")
    parser.add_argument("--check-unavailable", action="append")
    parser.add_argument("--check-skipped", action="append")
    parser.add_argument("--capability-maturity", default="L2")
    parser.add_argument("--output")
    parser.add_argument("--output-dir")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)

    handoff_path = str(Path(args.handoff).resolve()) if args.handoff else None
    handoff_data: dict[str, Any] = {}
    load_findings: list[dict[str, Any]] = []
    if args.handoff:
        handoff_data, load_findings = load_handoff(Path(args.handoff).resolve())
        if not handoff_data:
            handoff_data["parallel_lanes_declared"] = True
    handoff_data = merge_cli_overrides(handoff_data, args)

    report = build_report(
        root,
        naos_root,
        policy,
        profile,
        handoff_data,
        handoff_path=handoff_path,
        load_findings=load_findings,
        capability_maturity=args.capability_maturity,
    )
    lane_id = report["lane"].get("lane_id") if isinstance(report.get("lane"), dict) else None
    output = Path(args.output) if args.output else lane_report_path(root, naos_root, policy, lane_id, args.output_dir)
    write_report(output, report)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS parallel lane handoff: "
            f"{report['status']} "
            f"(lane: {lane_id or 'unscoped'}, findings: {report['summary'].get('total_findings', 0)}, output: {destination})"
        )
        for item in report["findings"]:
            print(f"  [{item['severity']}] {item['status']}: {item['message']}")
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
