#!/usr/bin/env python3
"""Report bounded secure/agentic coding control evidence routing.

The report validates the canonical register and detector-to-evidence routing,
then reports local evidence availability and freshness. It never decides that a
control is satisfied, that code is secure, or that a framework is met.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    evidence_staleness_days,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

PROFILE_ORDER = {"quickstart": 0, "lite": 1, "standard": 2, "assured": 3}
FORBIDDEN_ROUTE_KEYS = {
    "enforcement",
    "enforcement_by_profile",
    "severity_by_profile",
    "blocking",
    "blocking_by_profile",
    "approval",
    "waiver",
    "exit_code",
    "satisfied",
    "compliant",
}
NOT_CLAIMED = [
    "secure code proof",
    "control satisfaction",
    "vulnerability-free proof",
    "complete detector coverage",
    "framework conformance",
    "compliance proof",
    "approval",
    "release authorization",
    "human review replacement",
]
LIMITATIONS = [
    "Evidence availability and freshness do not establish that a control is satisfied.",
    "Most controls retain human review because deterministic coverage is partial, indirect, or absent.",
    "File modification time is a bounded freshness signal, not proof of evidence validity.",
    "Project-supplied SARIF remains unverified external evidence unless separately verified.",
]


def load_data(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def bounded_explicit_path(value: str | None, *, root: Path, kit: Path, default: Path, label: str) -> Path:
    if value is None:
        return default
    candidate = Path(value).expanduser().resolve(strict=False)
    if not (_within(candidate, root) or _within(candidate, kit)):
        raise ValueError(f"{label} must remain within the project or installed kit: {candidate}")
    return candidate


def default_sources(root: Path, naos_root: str) -> dict[str, Path]:
    kit = kit_root()
    adopter = root / naos_root
    if (adopter / "secure_coding_control_register.yaml").is_file():
        register = adopter / "secure_coding_control_register.yaml"
        routes = adopter / "secure_coding_control_evidence_routes.yaml"
        register_schema = root / "schemas/naos/secure_coding_control_register.schema.json"
        routes_schema = root / "schemas/naos/secure_coding_control_evidence_routes.schema.json"
        report_schema = root / "schemas/naos/secure_coding_controls.schema.json"
    else:
        register = kit / "configs/secure_coding_control_register.yaml"
        routes = kit / "templates/structural-seeds/naos/secure_coding_control_evidence_routes.yaml"
        register_schema = kit / "schemas/naos/secure_coding_control_register.schema.json"
        routes_schema = kit / "schemas/naos/secure_coding_control_evidence_routes.schema.json"
        report_schema = kit / "schemas/naos/secure_coding_controls.schema.json"
    return {
        "register": register,
        "routes": routes,
        "register_schema": register_schema,
        "routes_schema": routes_schema,
        "report_schema": report_schema,
    }


def schema_findings(data: Any, schema: dict[str, Any], source: str, severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.absolute_path)):
        location = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.absolute_path
        )
        findings.append(
            {
                "id": f"{source}:{location}",
                "severity": severity,
                "status": "schema_error",
                "message": error.message,
                "path": source,
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )
    return findings


def standards_snapshot(register: dict[str, Any], register_path: Path) -> dict[str, Any]:
    """Capture the canonical register's framework-version baseline."""
    standards = register.get("standards") if isinstance(register.get("standards"), dict) else {}
    normalized: dict[str, dict[str, Any]] = {}
    for key in sorted(standards):
        value = standards[key]
        if not isinstance(value, dict):
            continue
        normalized[str(key)] = {
            "name": value.get("name"),
            "version": str(value.get("version") or ""),
            "role": value.get("role"),
            "source": value.get("source"),
            "mapping_default_status": value.get("mapping_default_status"),
        }
        for field in (
            "source_release",
            "source_dataset_sha256",
            "selected_control_ids",
            "claim_posture",
            "decision_use",
            "scope",
            "non_claims",
        ):
            if field in value:
                normalized[str(key)][field] = value[field]
    return {
        "source": "canonical secure-coding control register",
        "register_path": str(register_path),
        "register_schema": register.get("schema"),
        "register_version": str(register.get("version") or ""),
        "standards": normalized,
        "human_review_required": True,
        "not_claimed": [
            "framework conformance",
            "control satisfaction",
            "compliance proof",
            "approval",
        ],
    }


def walk_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def parse_generated_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def evidence_freshness(path: Path, artifact: dict[str, Any], now: datetime, max_days: int) -> dict[str, Any]:
    generated = parse_generated_at(artifact.get("generated_at"))
    if generated is None:
        generated = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        source = "file_mtime"
    else:
        source = "generated_at"
    age_days = max(0.0, (now - generated).total_seconds() / 86400)
    return {
        "source": source,
        "observed_at": generated.isoformat().replace("+00:00", "Z"),
        "age_days": round(age_days, 3),
        "maximum_age_days": max_days,
        "state": "stale" if max_days > 0 and age_days > max_days else "fresh",
    }


def build_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    register_path: Path,
    routes_path: Path,
    register_schema_path: Path,
    routes_schema_path: Path,
    report_schema_path: Path,
    check_mode: bool,
    pr_context: bool,
    external_evidence_supplied: bool,
    generated_at: str | None,
) -> dict[str, Any]:
    now = parse_generated_at(generated_at) or datetime.now(UTC)
    generated = now.isoformat().replace("+00:00", "Z")
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []

    sources = {
        "register": str(register_path),
        "routes": str(routes_path),
        "register_schema": str(register_schema_path),
        "routes_schema": str(routes_schema_path),
        "report_schema": str(report_schema_path),
        "policy": policy.get("_meta", {}).get("path"),
    }

    loaded: dict[str, Any] = {}
    for key, path in {
        "register": register_path,
        "routes": routes_path,
        "register_schema": register_schema_path,
        "routes_schema": routes_schema_path,
        "report_schema": report_schema_path,
    }.items():
        try:
            loaded[key] = load_data(path)
        except Exception as exc:
            findings.append(
                {
                    "id": f"load:{key}",
                    "severity": severity,
                    "status": "load_error",
                    "message": str(exc),
                    "path": str(path),
                    "human_review_required": True,
                    "not_claimed": NOT_CLAIMED,
                }
            )
            loaded[key] = {}

    for key, path in {
        "register_schema": register_schema_path,
        "routes_schema": routes_schema_path,
        "report_schema": report_schema_path,
    }.items():
        if not isinstance(loaded.get(key), dict):
            findings.append(
                {
                    "id": f"schema-type:{key}",
                    "severity": severity,
                    "status": "schema_error",
                    "message": f"{key.replace('_', ' ')} must be a JSON/YAML object, not {type(loaded.get(key)).__name__}.",
                    "path": str(path),
                    "human_review_required": True,
                    "not_claimed": NOT_CLAIMED,
                }
            )
            loaded[key] = {}

    register = loaded["register"] if isinstance(loaded["register"], dict) else {}
    routes = loaded["routes"] if isinstance(loaded["routes"], dict) else {}
    if isinstance(loaded["register_schema"], dict):
        findings.extend(schema_findings(register, loaded["register_schema"], str(register_path), severity))
    if isinstance(loaded["routes_schema"], dict):
        findings.extend(schema_findings(routes, loaded["routes_schema"], str(routes_path), severity))

    forbidden = sorted(FORBIDDEN_ROUTE_KEYS.intersection(set(walk_keys(routes))))
    for key in forbidden:
        findings.append(
            {
                "id": f"route-authority:{key}",
                "severity": severity,
                "status": "forbidden_authority_field",
                "message": f"Evidence route field {key!r} would create or imply a second enforcement authority.",
                "path": str(routes_path),
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )

    catalog = register.get("detector_catalog") if isinstance(register.get("detector_catalog"), dict) else {}
    control_rows = register.get("controls") if isinstance(register.get("controls"), list) else []
    route_rows = routes.get("routes") if isinstance(routes.get("routes"), list) else []
    route_by_detector: dict[str, dict[str, Any]] = {}
    duplicate_detectors: set[str] = set()
    for row in route_rows:
        if not isinstance(row, dict) or not isinstance(row.get("detector_id"), str):
            continue
        detector_id = row["detector_id"]
        if detector_id in route_by_detector:
            duplicate_detectors.add(detector_id)
        route_by_detector[detector_id] = row
    for detector_id in sorted(duplicate_detectors):
        findings.append(
            {
                "id": f"duplicate-route:{detector_id}",
                "severity": severity,
                "status": "duplicate_detector_route",
                "message": f"Detector {detector_id} has more than one evidence route.",
                "path": str(routes_path),
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )

    missing_routes = sorted(set(catalog) - set(route_by_detector))
    unknown_routes = sorted(set(route_by_detector) - set(catalog))
    for detector_id in missing_routes:
        findings.append(
            {
                "id": f"missing-route:{detector_id}",
                "severity": severity,
                "status": "missing_detector_route",
                "message": f"Canonical detector {detector_id} has no evidence route.",
                "path": str(routes_path),
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )
    for detector_id in unknown_routes:
        findings.append(
            {
                "id": f"unknown-route:{detector_id}",
                "severity": severity,
                "status": "unknown_detector_route",
                "message": f"Evidence route references unknown detector {detector_id}.",
                "path": str(routes_path),
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )

    detector_uses = Counter()
    for control in control_rows:
        if not isinstance(control, dict):
            continue
        evaluation = control.get("evaluation") if isinstance(control.get("evaluation"), dict) else {}
        for detector_id in evaluation.get("detectors", []) if isinstance(evaluation.get("detectors"), list) else []:
            if isinstance(detector_id, str):
                detector_uses[detector_id] += 1
                if detector_id not in route_by_detector:
                    findings.append(
                        {
                            "id": f"unrouted-control-detector:{control.get('id')}:{detector_id}",
                            "severity": severity,
                            "status": "unrouted_control_detector",
                            "message": f"Control {control.get('id')} uses detector {detector_id} without a route.",
                            "path": str(register_path),
                            "human_review_required": True,
                            "not_claimed": NOT_CLAIMED,
                        }
                    )

    max_days = evidence_staleness_days(policy)
    evidence_results: list[dict[str, Any]] = []
    adopter_root = (root / naos_root).resolve(strict=False)
    for detector_id in sorted(route_by_detector):
        route = route_by_detector[detector_id]
        evidence_rel = Path(str(route.get("evidence_path", "")))
        result: dict[str, Any] = {
            "detector_id": detector_id,
            "evidence_path": str(evidence_rel),
            "evidence_kind": route.get("evidence_kind"),
            "requirement": route.get("requirement"),
            "minimum_profile": route.get("minimum_profile"),
            "applies_when": route.get("applies_when"),
            "gates": route.get("gates") or [],
            "boundary": route.get("boundary"),
            "state": "not_evaluated" if check_mode else "unknown",
            "artifact_status": None,
            "freshness": None,
        }
        try:
            evidence_path = (adopter_root / evidence_rel).resolve(strict=False)
            evidence_path.relative_to(adopter_root)
        except (ValueError, OSError):
            result["state"] = "invalid_path"
            findings.append(
                {
                    "id": f"unsafe-evidence-path:{detector_id}",
                    "severity": severity,
                    "status": "unsafe_evidence_path",
                    "message": f"Evidence path escapes NAOS root: {evidence_rel}",
                    "path": str(routes_path),
                    "human_review_required": True,
                    "not_claimed": NOT_CLAIMED,
                }
            )
            evidence_results.append(result)
            continue

        if check_mode:
            evidence_results.append(result)
            continue

        minimum = str(route.get("minimum_profile", "quickstart"))
        if PROFILE_ORDER.get(profile, -1) < PROFILE_ORDER.get(minimum, 99):
            result["state"] = "not_expected_for_profile"
            evidence_results.append(result)
            continue
        applies_when = route.get("applies_when")
        if applies_when == "pull_request" and not pr_context:
            result["state"] = "not_applicable"
            evidence_results.append(result)
            continue
        if applies_when == "external_evidence_supplied" and not external_evidence_supplied:
            result["state"] = "not_applicable"
            evidence_results.append(result)
            continue
        if not evidence_path.is_file():
            requirement = route.get("requirement")
            result["state"] = "optional_missing" if requirement == "optional" else "missing"
            if requirement != "optional":
                findings.append(
                    {
                        "id": f"missing-evidence:{detector_id}",
                        "severity": severity,
                        "status": "required_evidence_missing",
                        "message": f"Applicable evidence is missing for {detector_id}: {evidence_rel}",
                        "path": str(evidence_path),
                        "human_review_required": True,
                        "not_claimed": NOT_CLAIMED,
                    }
                )
            evidence_results.append(result)
            continue
        try:
            artifact = load_data(evidence_path)
            if not isinstance(artifact, dict):
                raise ValueError("Evidence artifact must be a JSON object")
        except Exception as exc:
            result["state"] = "parse_error"
            findings.append(
                {
                    "id": f"invalid-evidence:{detector_id}",
                    "severity": severity,
                    "status": "evidence_parse_error",
                    "message": str(exc),
                    "path": str(evidence_path),
                    "human_review_required": True,
                    "not_claimed": NOT_CLAIMED,
                }
            )
            evidence_results.append(result)
            continue
        freshness = evidence_freshness(evidence_path, artifact, now, max_days)
        result["freshness"] = freshness
        result["artifact_status"] = artifact.get("status") or artifact.get("report_status")
        result["state"] = "stale" if freshness["state"] == "stale" else "available"
        if result["state"] == "stale":
            findings.append(
                {
                    "id": f"stale-evidence:{detector_id}",
                    "severity": severity,
                    "status": "evidence_stale",
                    "message": f"Evidence for {detector_id} is {freshness['age_days']} days old; limit is {max_days}.",
                    "path": str(evidence_path),
                    "human_review_required": True,
                    "not_claimed": NOT_CLAIMED,
                }
            )
        evidence_results.append(result)

    evidence_by_detector = {item["detector_id"]: item for item in evidence_results}
    controls: list[dict[str, Any]] = []
    mapping_status_counts: Counter[str] = Counter()
    outstanding_human_review = 0
    for control in control_rows:
        if not isinstance(control, dict):
            continue
        evaluation = control.get("evaluation") if isinstance(control.get("evaluation"), dict) else {}
        detector_ids = [item for item in evaluation.get("detectors", []) if isinstance(item, str)] if isinstance(evaluation.get("detectors"), list) else []
        mapping_states: Counter[str] = Counter()
        crosswalk = control.get("crosswalk") if isinstance(control.get("crosswalk"), dict) else {}
        for mapping in crosswalk.values():
            if isinstance(mapping, dict):
                state = str(mapping.get("status") or "unknown")
                mapping_states[state] += 1
                mapping_status_counts[state] += 1
        human_review = bool(evaluation.get("human_review"))
        if human_review:
            outstanding_human_review += 1
        controls.append(
            {
                "control_id": control.get("id"),
                "plane": control.get("plane"),
                "coverage": evaluation.get("coverage"),
                "detectors": detector_ids,
                "evidence_availability": [
                    {
                        "detector_id": detector_id,
                        "state": evidence_by_detector.get(detector_id, {}).get("state", "unrouted"),
                        "freshness": evidence_by_detector.get(detector_id, {}).get("freshness"),
                    }
                    for detector_id in detector_ids
                ],
                "mapping_verification": dict(sorted(mapping_states.items())),
                "human_review": evaluation.get("human_review"),
                "human_review_required": human_review,
                "not_claimed": control.get("not_claimed") or [],
            }
        )

    states = Counter(item["state"] for item in evidence_results)
    counts = finding_counts(findings)
    summary: dict[str, Any] = {
        **counts,
        "controls": len(controls),
        "detectors": len(catalog),
        "routes": len(route_by_detector),
        "detectors_used_by_controls": len(detector_uses),
        "evidence_available": states.get("available", 0),
        "evidence_stale": states.get("stale", 0),
        "evidence_missing": states.get("missing", 0),
        "evidence_optional_missing": states.get("optional_missing", 0),
        "evidence_not_applicable": states.get("not_applicable", 0),
        "evidence_not_expected_for_profile": states.get("not_expected_for_profile", 0),
        "mapping_draft": mapping_status_counts.get("draft", 0),
        "mapping_verified": mapping_status_counts.get("verified", 0),
        "mapping_deprecated": mapping_status_counts.get("deprecated", 0),
        "outstanding_human_reviews": outstanding_human_review,
    }
    register_validation_failed = any(
        item["status"] in {"schema_error", "load_error"}
        and item.get("path") in {str(register_path), str(register_schema_path)}
        for item in findings
    )
    route_validation_failed = any(
        item["status"] in {"schema_error", "load_error", "unsafe_evidence_path"}
        and item.get("path") in {str(routes_path), str(routes_schema_path)}
        for item in findings
    )
    route_integrity_failed = bool(
        route_validation_failed
        or missing_routes
        or unknown_routes
        or duplicate_detectors
        or forbidden
    )
    report = {
        "schema": "naos.secure_coding_controls.v1",
        "generated_at": generated,
        "profile": profile,
        "status": status_from_counts(counts),
        "project_root": str(root),
        "naos_root": naos_root,
        "deterministic": True,
        "check_mode": check_mode,
        "sources": sources,
        "standards_snapshot": standards_snapshot(register, register_path),
        "summary": summary,
        "dimensions": {
            "register_schema_validity": {
                "state": "invalid" if register_validation_failed else "valid",
                "authority": "canonical requirements only",
            },
            "evidence_route_integrity": {
                "state": "invalid" if route_integrity_failed else "valid",
                "missing_routes": missing_routes,
                "unknown_routes": unknown_routes,
            },
            "evidence_availability": {"state_counts": dict(sorted(states.items()))},
            "evidence_freshness": {"maximum_age_days": max_days, "stale_routes": states.get("stale", 0)},
            "mapping_verification": {"status_counts": dict(sorted(mapping_status_counts.items()))},
            "human_review": {"outstanding_controls": outstanding_human_review},
        },
        "evidence_routes": evidence_results,
        "controls": controls,
        "findings": findings,
        "known_gaps": [
            "Controls with coverage 'none' have no deterministic detector evidence.",
            "Draft framework mappings require independent control-by-control verification.",
        ],
        "residual_risks": [
            "Available detector reports may be incomplete, false-positive, false-negative, or outside their declared scope.",
            "Human review remains required for control applicability, evidence interpretation, exceptions, and durable decisions.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }
    if isinstance(loaded.get("report_schema"), dict):
        report_schema_errors = schema_findings(report, loaded["report_schema"], str(report_schema_path), severity)
        if report_schema_errors:
            report["findings"].extend(report_schema_errors)
            counts = finding_counts(report["findings"])
            report["summary"].update(counts)
            report["status"] = status_from_counts(counts)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--naos-root")
    parser.add_argument("--profile")
    parser.add_argument("--policy")
    parser.add_argument("--register")
    parser.add_argument("--routes")
    parser.add_argument("--register-schema")
    parser.add_argument("--routes-schema")
    parser.add_argument("--report-schema")
    parser.add_argument("--check", action="store_true", help="Validate register/routes without requiring project evidence reports.")
    parser.add_argument("--pr-context", action="store_true")
    parser.add_argument("--external-evidence-supplied", action="store_true")
    parser.add_argument("--generated-at")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    defaults = default_sources(root, naos_root)
    kit = kit_root()
    try:
        paths = {
            "register": bounded_explicit_path(args.register, root=root, kit=kit, default=defaults["register"], label="register"),
            "routes": bounded_explicit_path(args.routes, root=root, kit=kit, default=defaults["routes"], label="routes"),
            "register_schema": bounded_explicit_path(args.register_schema, root=root, kit=kit, default=defaults["register_schema"], label="register schema"),
            "routes_schema": bounded_explicit_path(args.routes_schema, root=root, kit=kit, default=defaults["routes_schema"], label="routes schema"),
            "report_schema": bounded_explicit_path(args.report_schema, root=root, kit=kit, default=defaults["report_schema"], label="report schema"),
        }
        report = build_report(
            root=root,
            naos_root=naos_root,
            profile=profile,
            policy=policy,
            register_path=paths["register"],
            routes_path=paths["routes"],
            register_schema_path=paths["register_schema"],
            routes_schema_path=paths["routes_schema"],
            report_schema_path=paths["report_schema"],
            check_mode=args.check,
            pr_context=args.pr_context,
            external_evidence_supplied=args.external_evidence_supplied,
            generated_at=args.generated_at,
        )
    except Exception as exc:
        severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
        finding = {
            "id": "secure-coding-controls:load",
            "severity": severity,
            "status": "load_error",
            "message": str(exc),
            "human_review_required": True,
            "not_claimed": NOT_CLAIMED,
        }
        counts = finding_counts([finding])
        report = {
            "schema": "naos.secure_coding_controls.v1",
            "generated_at": (parse_generated_at(args.generated_at) or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
            "profile": profile,
            "status": status_from_counts(counts),
            "project_root": str(root),
            "naos_root": naos_root,
            "deterministic": True,
            "check_mode": args.check,
            "sources": {},
            "summary": counts,
            "dimensions": {},
            "evidence_routes": [],
            "controls": [],
            "findings": [finding],
            "known_gaps": [],
            "residual_risks": ["The routing report could not be built and requires human review."],
            "limitations": LIMITATIONS,
            "not_claimed": NOT_CLAIMED,
            "human_review_required": True,
        }

    output = args.output
    if output is None and not args.check:
        output = report_default_path(root, naos_root, policy, "secure_coding_controls_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"NAOS secure-coding control routing: {report['status']} "
            f"({report.get('summary', {}).get('total_findings', 0)} finding(s))"
        )
        for item in report.get("findings", []):
            print(f"- {item.get('severity')}: {item.get('status')}: {item.get('message')}")
    return exit_code_for_summary(profile, report.get("summary", {}), policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
