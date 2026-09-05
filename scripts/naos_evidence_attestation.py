#!/usr/bin/env python3
"""Generate local evidence integrity and reviewer attestation readiness reports."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
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
    ignored_scan_dirs,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    write_report,
)


REPORT_SCHEMA = "naos.evidence_attestation.v1"
SUPPORTED_DIGESTS = {"sha256"}
STATUS_VALUES = {
    "ready",
    "review_required",
    "missing",
    "stale",
    "uncovered",
    "advisory",
    "warning",
    "blocked",
    "not_configured",
    "disabled",
    "waived",
    "unknown",
}
NOT_CLAIMED = [
    "cryptographic signing",
    "signature verification",
    "key custody or PKI",
    "remote notarization",
    "trusted timestamping",
    "ledger storage",
    "legal e-signature semantics",
    "identity verification",
    "tamper-proof evidence",
    "certified evidence",
    "legal or regulatory approval",
    "compliance approval",
    "guaranteed integrity",
]


def utc_now_text() -> str:
    return controlled_utc_now_text()


def timestamp_text(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "evidence_attestation_rules.yaml"


def default_attestations_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "evidence_review_attestations.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("evidence_attestation_rules") or "evidence_attestation_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def resolve_attestations_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("evidence_review_attestations") or "evidence_review_attestations.yaml")
    project_attestations = root / naos_root / filename
    if project_attestations.exists():
        return project_attestations, "project"
    return default_attestations_template(), "template"


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def rule_severity(root: Path, naos_root: str, profile: str, policy: dict[str, Any], rules: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    mapping = rules.get("profile_severity_behavior") if isinstance(rules.get("profile_severity_behavior"), dict) else {}
    return str(mapping.get(profile) or severity_for_profile(profile, policy) or "advisory")


def profile_bool(mapping: Any, profile: str, default: bool = False) -> bool:
    if isinstance(mapping, dict):
        if profile in mapping:
            return bool(mapping[profile])
        if "default" in mapping:
            return bool(mapping["default"])
    if isinstance(mapping, bool):
        return mapping
    return default


def matches_any(path_text: str, patterns: list[str]) -> bool:
    normalized = path_text.replace("\\", "/").lstrip("./")
    for pattern in patterns:
        normalized_pattern = str(pattern).replace("\\", "/").lstrip("./")
        if fnmatch.fnmatch(normalized, normalized_pattern):
            return True
        if normalized_pattern.endswith("/**") and normalized.startswith(normalized_pattern[:-3].rstrip("/") + "/"):
            return True
    return False


def default_exclusions(policy: dict[str, Any]) -> list[str]:
    patterns = []
    for item in ignored_scan_dirs(policy):
        patterns.append(f"{item}/**")
        patterns.append(f"**/{item}/**")
    patterns.extend(["*.pyc", "**/*.pyc", ".DS_Store", "naos/reports/evidence_attestation.json"])
    return dedupe(patterns)


def find_matching_files(root: Path, patterns: list[str], excluded: list[str]) -> list[Path]:
    results: list[Path] = []
    for pattern in patterns:
        try:
            candidates = root.glob(pattern)
            for candidate in candidates:
                if not candidate.is_file():
                    continue
                rel = candidate.relative_to(root).as_posix()
                if matches_any(rel, excluded):
                    continue
                results.append(candidate)
        except (OSError, ValueError):
            continue
    return sorted(set(results), key=lambda path: path.relative_to(root).as_posix())


def manifest_root_digest(manifest: list[dict[str, Any]]) -> str:
    """Deterministic tamper-evidence root over the artifact manifest (keyless, default-on).

    Any edit to a covered artifact changes its digest and therefore this root. This is
    integrity/tamper-evidence only — not a signature, approval, or proof of compliance.
    """
    pairs = sorted(
        (str(item.get("path")), str(item.get("digest")))
        for item in manifest
        if item.get("digest")
    )
    canonical = json.dumps(pairs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def freshness_for(path: Path, generated_at: datetime, window_days: int | None) -> dict[str, Any]:
    modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    if window_days is None or window_days < 0:
        return {
            "status": "unknown",
            "window_days": window_days,
            "age_days": None,
        }
    age_days = max(0, (generated_at - modified).days)
    return {
        "status": "stale" if generated_at - modified > timedelta(days=window_days) else "fresh",
        "window_days": window_days,
        "age_days": age_days,
    }


def artifact_entry(
    *,
    root: Path,
    path: Path,
    group_id: str,
    generated_at: datetime,
    freshness_window_days: int | None,
) -> dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    freshness = freshness_for(path, generated_at, freshness_window_days)
    return {
        "path": rel,
        "artifact_group": group_id,
        "status": "stale" if freshness.get("status") == "stale" else "ready",
        "digest": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "modified_time": timestamp_text(datetime.fromtimestamp(path.stat().st_mtime, UTC)),
        "freshness": freshness,
    }


def missing_entry(pattern: str, group_id: str, required: bool) -> dict[str, Any]:
    return {
        "path": pattern,
        "artifact_group": group_id,
        "status": "missing",
        "required": required,
    }


def normalize_attestation(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id") or "unidentified_review"),
        "reviewer_name": str(item.get("reviewer_name") or ""),
        "reviewer_role": str(item.get("reviewer_role") or ""),
        "reviewer_contact": str(item.get("reviewer_contact") or ""),
        "review_date": str(item.get("review_date") or ""),
        "reviewed_artifacts": as_list(item.get("reviewed_artifacts")),
        "artifact_groups": as_list(item.get("artifact_groups")),
        "review_scope": str(item.get("review_scope") or ""),
        "review_outcome": str(item.get("review_outcome") or "review_required"),
        "related_waivers": as_list(item.get("related_waivers")),
        "related_known_gaps": as_list(item.get("related_known_gaps")),
        "related_residual_risks": as_list(item.get("related_residual_risks")),
        "notes": str(item.get("notes") or item.get("rationale") or ""),
        "human_review_required": bool(item.get("human_review_required", True)),
        "limitations": as_list(item.get("limitations")),
        "not_claimed": as_list(item.get("not_claimed")),
    }


def reviewed_paths(attestations: list[dict[str, Any]], manifest: list[dict[str, Any]]) -> set[str]:
    by_group: dict[str, list[str]] = {}
    for artifact in manifest:
        by_group.setdefault(str(artifact.get("artifact_group") or ""), []).append(str(artifact.get("path") or ""))
    reviewed: set[str] = set()
    for item in attestations:
        reviewed.update(as_list(item.get("reviewed_artifacts")))
        for group_id in as_list(item.get("artifact_groups")):
            reviewed.update(by_group.get(group_id, []))
    return reviewed


def make_finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    required_next_actions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": required_next_actions or [],
    }


def validate_rules(rules: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if str(rules.get("digest_algorithm") or "sha256") not in SUPPORTED_DIGESTS:
        findings.append(
            make_finding(
                finding_id="digest_algorithm",
                severity="blocking",
                status="invalid_rules",
                message="Evidence attestation only supports deterministic local SHA-256 hashing.",
                required_next_actions=["Set digest_algorithm to sha256."],
            )
        )
    groups = rules.get("artifact_groups")
    if not isinstance(groups, list):
        findings.append(
            make_finding(
                finding_id="artifact_groups",
                severity="blocking",
                status="invalid_rules",
                message="evidence_attestation_rules.yaml must define artifact_groups.",
                required_next_actions=["Add at least one artifact group or disable the rules explicitly."],
            )
        )
    return findings


def collect_artifacts(
    *,
    root: Path,
    rules: dict[str, Any],
    policy: dict[str, Any],
    generated_at: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest_by_path: dict[str, dict[str, Any]] = {}
    missing: list[dict[str, Any]] = []
    disabled_groups: list[dict[str, Any]] = []
    base_exclusions = dedupe(default_exclusions(policy) + as_list(rules.get("excluded_paths")))
    default_window = int(rules.get("default_freshness_window_days") or 30)

    for group in rules.get("artifact_groups") or []:
        if not isinstance(group, dict):
            continue
        group_id = str(group.get("id") or "unknown_group")
        if group.get("enabled") is False:
            disabled_groups.append({"artifact_group": group_id, "status": "disabled"})
            continue
        group_exclusions = dedupe(base_exclusions + as_list(group.get("excluded_paths")))
        group_window = int(group.get("freshness_window_days") or default_window)
        patterns = dedupe(
            as_list(group.get("included_paths"))
            + as_list(group.get("required_artifacts"))
            + as_list(group.get("optional_artifacts"))
        )
        matched = find_matching_files(root, patterns, group_exclusions)
        for path in matched:
            rel = path.relative_to(root).as_posix()
            manifest_by_path[rel] = artifact_entry(
                root=root,
                path=path,
                group_id=group_id,
                generated_at=generated_at,
                freshness_window_days=group_window,
            )

        for pattern in as_list(group.get("required_artifacts")):
            if not find_matching_files(root, [pattern], group_exclusions):
                missing.append(missing_entry(pattern, group_id, required=True))

    return (
        sorted(manifest_by_path.values(), key=lambda item: str(item.get("path"))),
        missing,
        disabled_groups,
    )


def status_from_findings(summary: dict[str, Any]) -> str:
    if summary.get("blocking", 0):
        return "blocked"
    if summary.get("required", 0):
        return "review_required"
    if summary.get("warning", 0):
        return "warning"
    if summary.get("missing_artifacts", 0):
        return "missing"
    if summary.get("stale_artifacts", 0):
        return "stale"
    if summary.get("uncovered_artifacts", 0):
        return "uncovered"
    if summary.get("advisory", 0):
        return "advisory"
    return "ready"


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    attestations_path: Path,
    attestations_source: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or controlled_now_utc()
    rules = load_yaml(rules_path)
    policy_meta = policy.get("_meta", {})
    if rules.get("enabled") is False:
        return {
            "schema": REPORT_SCHEMA,
            "generated_at": timestamp_text(generated_at),
            "profile": profile,
            "status": "disabled",
            "naos_root": naos_root,
            "project_root": str(root),
            "digest_algorithm": str(rules.get("digest_algorithm") or "sha256"),
            "rules": {"path": str(rules_path), "source": rules_source},
            "review_metadata": {"path": str(attestations_path), "source": attestations_source},
            "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
            "summary": {"disabled": 1, "total_findings": 0},
            "artifact_manifest": [],
            "missing_artifacts": [],
            "stale_artifacts": [],
            "reviewer_attestations": [],
            "uncovered_artifacts": [],
            "known_gaps": [],
            "residual_risks": [],
            "waivers": [],
            "human_review_required": False,
            "findings": [],
            "limitations": as_list(rules.get("limitations")),
            "not_claimed": dedupe(as_list(rules.get("not_claimed")) + NOT_CLAIMED),
        }

    severity = rule_severity(root, naos_root, profile, policy, rules)
    validation_findings = validate_rules(rules)
    attestations_data = load_yaml(attestations_path)
    attestations = [
        normalize_attestation(item)
        for item in attestations_data.get("attestations") or []
        if isinstance(item, dict)
    ]
    artifact_manifest, missing_artifacts, disabled_groups = collect_artifacts(
        root=root,
        rules=rules,
        policy=policy,
        generated_at=generated_at,
    )
    stale_artifacts = [item for item in artifact_manifest if item.get("status") == "stale"]
    reviewed = reviewed_paths(attestations, artifact_manifest)
    uncovered_artifacts = [item for item in artifact_manifest if str(item.get("path")) not in reviewed]
    known_gaps = attestations_data.get("known_gaps") or []
    residual_risks = attestations_data.get("residual_risks") or []
    waivers = attestations_data.get("waivers") or []
    requirements = rules.get("reviewer_attestation_requirements") if isinstance(rules.get("reviewer_attestation_requirements"), dict) else {}
    required_by_profile = requirements.get("required_by_profile") if isinstance(requirements.get("required_by_profile"), dict) else {}
    reviewer_required = profile_bool(required_by_profile, profile, False)
    allowed_outcomes = set(as_list(requirements.get("allowed_review_outcomes"))) or {
        "acknowledged",
        "accepted_with_gaps",
        "review_required",
        "deferred",
        "waived",
    }
    required_fields = as_list(requirements.get("required_fields"))

    findings: list[dict[str, Any]] = list(validation_findings)
    for item in missing_artifacts:
        findings.append(
            make_finding(
                finding_id=f"missing:{item['artifact_group']}:{item['path']}",
                severity=severity,
                status="missing",
                message=f"Configured evidence artifact is missing: {item['path']}",
                required_next_actions=[
                    "Generate the artifact, revise the attestation rules, or record a known gap, residual risk, or waiver."
                ],
            )
        )
    for item in stale_artifacts:
        findings.append(
            make_finding(
                finding_id=f"stale:{item['path']}",
                severity=severity,
                status="stale",
                message=f"Evidence artifact is older than the configured freshness window: {item['path']}",
                required_next_actions=["Regenerate or review the artifact, or record accepted residual risk."],
            )
        )

    missing_reviewer_fields = []
    for item in attestations:
        missing = [field for field in required_fields if not item.get(field)]
        invalid_outcome = item.get("review_outcome") not in allowed_outcomes
        if missing or invalid_outcome:
            issue = f"{item['id']}: "
            issue += f"missing fields {', '.join(missing)}" if missing else "unsupported review outcome"
            missing_reviewer_fields.append(issue)
    if missing_reviewer_fields:
        findings.append(
            make_finding(
                finding_id="reviewer_metadata_fields",
                severity=severity,
                status="missing_reviewer_metadata",
                message="One or more reviewer metadata entries are incomplete or unsupported.",
                required_next_actions=["Correct reviewer metadata fields before relying on review status."],
            )
        )
    if reviewer_required and not attestations:
        findings.append(
            make_finding(
                finding_id="reviewer_metadata_required",
                severity=severity,
                status="missing_reviewer_metadata",
                message="Reviewer metadata is expected for this profile but no reviewer attestations were recorded.",
                required_next_actions=["Add reviewer metadata or record a waiver, known gap, or residual risk."],
            )
        )
    if uncovered_artifacts and profile in {"standard", "assured"}:
        findings.append(
            make_finding(
                finding_id="uncovered_artifacts",
                severity=severity,
                status="uncovered",
                message="One or more hashed artifacts are not covered by reviewer metadata.",
                required_next_actions=["Record reviewer scope for uncovered artifacts or accept the gap explicitly."],
            )
        )
    if waivers:
        findings.append(
            make_finding(
                finding_id="waivers_visible",
                severity="advisory",
                status="waived",
                message="Waivers remain visible and do not convert evidence attestation to pass.",
                required_next_actions=["Review waiver expiry, residual risk, and owner approval."],
            )
        )
    if known_gaps:
        findings.append(
            make_finding(
                finding_id="known_gaps_visible",
                severity="advisory",
                status="review_required",
                message="Known gaps remain visible in the attestation report.",
                required_next_actions=["Review known gaps and decide next action or residual-risk treatment."],
            )
        )
    if residual_risks:
        findings.append(
            make_finding(
                finding_id="residual_risks_visible",
                severity="advisory",
                status="review_required",
                message="Residual risks remain visible in the attestation report.",
                required_next_actions=["Review residual risk acceptance and owner accountability."],
            )
        )

    summary = finding_counts(findings)
    summary.update(
        {
            "artifact_groups": len([group for group in rules.get("artifact_groups") or [] if isinstance(group, dict)]),
            "disabled_groups": len(disabled_groups),
            "artifacts_hashed": len(artifact_manifest),
            "missing_artifacts": len(missing_artifacts),
            "stale_artifacts": len(stale_artifacts),
            "uncovered_artifacts": len(uncovered_artifacts),
            "reviewer_attestations": len(attestations),
            "reviewer_metadata_required": bool(reviewer_required),
            "known_gaps": len(known_gaps),
            "residual_risks": len(residual_risks),
            "waivers": len(waivers),
        }
    )
    human_review_required = bool(
        reviewer_required
        or missing_artifacts
        or stale_artifacts
        or (uncovered_artifacts and profile in {"standard", "assured"})
        or known_gaps
        or residual_risks
        or waivers
        or any(item.get("human_review_required") for item in attestations)
    )
    summary["human_review_required"] = int(human_review_required)

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": timestamp_text(generated_at),
        "profile": profile,
        "status": status_from_findings(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "digest_algorithm": str(rules.get("digest_algorithm") or "sha256"),
        "manifest_root_digest": manifest_root_digest(artifact_manifest),
        "rules": {
            "path": str(rules_path),
            "source": rules_source,
            "semantics": rules.get("semantics") or {},
            "excluded_paths": as_list(rules.get("excluded_paths")),
        },
        "review_metadata": {
            "path": str(attestations_path),
            "source": attestations_source,
            "semantics": attestations_data.get("semantics") or {},
        },
        "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
        "summary": summary,
        "artifact_manifest": artifact_manifest,
        "missing_artifacts": missing_artifacts,
        "stale_artifacts": stale_artifacts,
        "reviewer_attestations": attestations,
        "uncovered_artifacts": uncovered_artifacts,
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "waivers": waivers,
        "human_review_required": human_review_required,
        "findings": findings,
        "limitations": dedupe(as_list(rules.get("limitations")) + as_list(attestations_data.get("limitations"))),
        "not_claimed": dedupe(as_list(rules.get("not_claimed")) + as_list(attestations_data.get("not_claimed")) + NOT_CLAIMED),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate local NAOS evidence integrity and reviewer attestation report.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="Path to evidence_attestation_rules.yaml.")
    parser.add_argument("--attestations", help="Path to evidence_review_attestations.yaml.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--generated-at", help="Override generated timestamp for deterministic tests.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    attestations_path, attestations_source = resolve_attestations_path(root, naos_root, policy, args.attestations)
    generated_at = parse_datetime(args.generated_at) if args.generated_at else None
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules_path=rules_path,
        rules_source=rules_source,
        attestations_path=attestations_path,
        attestations_source=attestations_source,
        generated_at=generated_at,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "evidence_attestation_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS evidence attestation: "
            f"{report['status']} "
            f"({report['summary'].get('artifacts_hashed', 0)} artifacts hashed, "
            f"{report['summary'].get('reviewer_attestations', 0)} reviewer metadata entries, "
            f"output: {destination})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
