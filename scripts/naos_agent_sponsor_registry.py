#!/usr/bin/env python3
"""Validate an opt-in build-time agent sponsor and credential-posture registry.

The registry contains declared repository posture only. It does not identify a
person, inspect or validate a credential, authenticate or authorize an agent,
call a provider or network, or enforce runtime behavior.
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
from jsonschema import Draft202012Validator, FormatChecker

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_emit_capabilities import CapabilityEmissionError, emit_catalogue  # noqa: E402
from naos_policy import (  # noqa: E402
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    write_report,
)


REPORT_SCHEMA = "naos.agent_sponsor_registry_report.v1"
REGISTRY_SCHEMA = "naos.agent_sponsor_registry.v1"
FORMAT_ID = "agent_sponsor_registry.v1"
GENERATOR_VERSION = "1.0.0"
REASON_ORDER = [
    "registry_config_parse_error",
    "registry_config_schema_invalid",
    "credential_value_detected",
    "agent_catalogue_invalid",
    "agent_record_missing",
    "unknown_agent_record",
    "duplicate_agent_record",
    "review_timestamp_invalid",
    "review_in_future",
    "review_window_invalid",
    "review_expired",
    "credential_control_missing",
    "credential_exception_review",
    "registry_review_required",
]
NOT_CLAIMED = [
    "sponsor identity verification",
    "sponsor approval",
    "authentication",
    "authorization",
    "delegation authority",
    "separation of duties",
    "credential existence",
    "credential validation",
    "credential lifetime verification",
    "credential issuance",
    "credential rotation",
    "credential revocation",
    "runtime identity",
    "runtime enforcement",
    "SPIFFE or SPIRE integration",
    "OAuth or on-behalf-of integration",
    "mTLS integration",
    "signing",
    "attestation",
    "compliance approval",
    "release authority",
    "publication authority",
]
LIMITATIONS = [
    "The registry contains project-authored declarations; opaque references are not resolved or identity-verified.",
    "Review expiry is evaluated against the replay-controlled NAOS clock and is not credential TTL, issuance, rotation, or revocation evidence.",
    "Credential posture is categorical only; no token, key, certificate, endpoint, provider, secret manager, or runtime is inspected.",
    "Content digests detect local change but do not authenticate authors, sign artifacts, attest provenance, or prove completeness.",
    "Findings route to human review and do not approve, block, merge, release, publish, authenticate, authorize, or activate agents.",
]
KNOWN_GAPS = [
    "sponsor_references_are_not_identity_verified",
    "credential_posture_is_not_runtime_verified",
    "external_identity_and_credential_controls_are_adopter_owned",
]
RESIDUAL_RISKS = [
    "false_or_stale_project_declarations",
    "external_sponsor_mapping_drift",
    "runtime_credential_posture_drift",
    "human_review_required_for_exceptions",
]
SECRET_LIKE_RE = re.compile(
    r"(?i)("
    r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}|"
    r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{8,}|"
    r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"bearer\s+[A-Za-z0-9._-]{12,}|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|private[_-]?key)"
    r"\s*[:=]\s*[^\s#]{4,}"
    r")"
)
_RFC3339_DATETIME = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[Zz]|[+-](?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))"
)


class SponsorRegistryError(ValueError):
    """Raised when registry inputs cannot be bounded deterministically."""


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_bounded_path(path: Path, root: Path) -> str:
    if ".." in path.parts:
        raise SponsorRegistryError(
            f"Sponsor-registry input must not contain traversal components: {path}"
        )
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        lexical_relative = lexical_path.relative_to(lexical_root)
        cursor = lexical_root
        for part in lexical_relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise SponsorRegistryError(
                    f"Sponsor-registry input must not use symlink path components: {path}"
                )
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError) as exc:
        raise SponsorRegistryError(
            f"Sponsor-registry input must be a regular file inside the project root: {path}"
        ) from exc
    if not resolved.is_file():
        raise SponsorRegistryError(
            f"Sponsor-registry input must be a regular non-symlink file: {path}"
        )
    return relative.as_posix()


def bounded_artifact_state(path: Path, root: Path) -> str:
    """Classify an optional artifact without following symlink components."""

    if ".." in path.parts:
        return "unsafe"
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
    except ValueError:
        return "unsafe"
    if not relative.parts:
        return "unsafe"
    cursor = lexical_root
    for index, part in enumerate(relative.parts):
        cursor = cursor / part
        if cursor.is_symlink():
            return "unsafe"
        if not os.path.lexists(cursor):
            return "missing"
        if index < len(relative.parts) - 1 and not cursor.is_dir():
            return "unsafe"
    return "regular" if lexical_path.is_file() else "unsafe"


def preflight_bounded_output(path: Path, root: Path) -> None:
    if ".." in path.parts:
        raise SponsorRegistryError(
            f"Sponsor-registry output must not contain traversal components: {path}"
        )
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
    except ValueError as exc:
        raise SponsorRegistryError(
            f"Sponsor-registry output must remain inside the project root: {path}"
        ) from exc
    cursor = lexical_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise SponsorRegistryError(
                f"Sponsor-registry output must not use symlink path components: {path}"
            )
    if path.exists():
        relative_bounded_path(path, root)


def load_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SponsorRegistryError(f"Expected JSON object: {path}")
    return data


def registry_schema_path(root: Path) -> Path:
    project = root / "schemas" / "naos" / "agent_sponsor_registry.schema.json"
    return project if project.is_file() else kit_root() / "schemas" / "naos" / project.name


def report_schema_path(root: Path) -> Path:
    project = root / "schemas" / "naos" / "agent_sponsor_registry_report.schema.json"
    return project if project.is_file() else kit_root() / "schemas" / "naos" / project.name


def resolve_registry_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        candidate = Path(explicit).expanduser()
        return (
            candidate if candidate.is_absolute() else root / candidate
        ).absolute(), "explicit"
    filename = str(
        policy.get("paths", {}).get("agent_sponsor_registry")
        or "agent_sponsor_registry.yaml"
    )
    return root / naos_root / filename, "project" if (root / naos_root / filename).is_file() else "missing"


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    match = _RFC3339_DATETIME.fullmatch(value)
    if match is None:
        return None
    offset_hour = match.group("offset_hour")
    offset_minute = match.group("offset_minute")
    if offset_hour is not None and (
        int(offset_hour) > 23 or int(offset_minute) > 59
    ):
        return None
    normalized = value[:10] + "T" + value[11:]
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _is_valid_rfc3339_format(value: Any) -> bool:
    """Supply JSON Schema date-time semantics without optional dependencies."""
    return not isinstance(value, str) or parse_timestamp(value) is not None


def schema_error_metadata(instance: dict[str, Any], schema_path: Path) -> list[dict[str, str]]:
    schema = load_json_mapping(schema_path)
    format_checker = FormatChecker()
    format_checker.checks("date-time")(_is_valid_rfc3339_format)
    errors = sorted(
        Draft202012Validator(schema, format_checker=format_checker).iter_errors(instance),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    return [
        {
            "path": ".".join(str(part) for part in error.absolute_path) or "<root>",
            "validator": str(error.validator or "unknown"),
        }
        for error in errors
    ]


def input_record(path: Path, root: Path, role: str) -> dict[str, str]:
    return {
        "path": relative_bounded_path(path, root),
        "role": role,
        "sha256": sha256_file(path),
    }


def finding(
    reason_code: str,
    severity: str,
    message: str,
    *,
    suffix: str = "registry",
    agent_id: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": f"agent_sponsor_registry.{reason_code}.{suffix}",
        "severity": severity,
        "status": "review_required",
        "reason_code": reason_code,
        "message": message,
    }
    if agent_id:
        item["agent_id"] = agent_id
    return item


def report_digest_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in report.items()
        if key != "report_digest"
    }


def current_content_payload(report: dict[str, Any]) -> dict[str, Any]:
    """Return source-comparable content without the production timestamp."""

    return {
        key: value
        for key, value in report.items()
        if key not in {"generated_at", "report_digest"}
    }


def _safe_ref_digest(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return canonical_digest({"opaque_ref": value.strip()})


def _load_registry(path: Path) -> tuple[dict[str, Any], bool]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        return {}, False
    return (data, True) if isinstance(data, dict) else ({}, False)


def _agent_catalogue(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        catalogue = emit_catalogue(root)
    except CapabilityEmissionError as exc:
        return [], str(exc)
    agents = [
        item
        for item in catalogue.get("capabilities") or []
        if isinstance(item, dict) and item.get("type") == "agent"
    ]
    return sorted(agents, key=lambda item: str(item.get("id") or "")), None


def build_expected_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    registry: str | None = None,
) -> dict[str, Any]:
    registry_path, registry_source = resolve_registry_path(
        root, naos_root, policy, registry
    )
    if ".." in registry_path.parts:
        raise SponsorRegistryError(
            f"Sponsor-registry input must not contain traversal components: {registry_path}"
        )
    registry_state = bounded_artifact_state(registry_path, root)
    if registry_state == "unsafe":
        raise SponsorRegistryError(
            f"Sponsor-registry input must be an absent or regular non-symlink file inside the project root: {registry_path}"
        )
    configured = registry_state == "regular"
    registry_data: dict[str, Any] = {}
    parse_ok = False
    registry_sha: str | None = None
    raw_text = ""
    if configured:
        relative_bounded_path(registry_path, root)
        registry_sha = sha256_file(registry_path)
        raw_text = registry_path.read_text(encoding="utf-8", errors="replace")
        registry_data, parse_ok = _load_registry(registry_path)

    schema_path = registry_schema_path(root)
    output_schema = report_schema_path(root)
    relative_bounded_path(schema_path, root)
    relative_bounded_path(output_schema, root)
    schema_errors = (
        schema_error_metadata(registry_data, schema_path)
        if configured and parse_ok
        else []
    )
    schema_valid = configured and parse_ok and not schema_errors
    enabled = bool(registry_data.get("enabled")) if parse_ok else False
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    if configured and not parse_ok:
        findings.append(
            finding(
                "registry_config_parse_error",
                severity,
                "The sponsor registry could not be parsed as a YAML mapping.",
            )
        )
    if configured and parse_ok and schema_errors:
        findings.append(
            finding(
                "registry_config_schema_invalid",
                severity,
                f"The sponsor registry violates its strict schema in {len(schema_errors)} place(s).",
            )
        )
    if configured and SECRET_LIKE_RE.search(raw_text):
        findings.append(
            finding(
                "credential_value_detected",
                "blocking" if profile == "assured" else "required",
                "The sponsor registry contains a secret-like credential value; the value was not copied into the report.",
            )
        )

    agents, agent_error = _agent_catalogue(root)
    if agent_error:
        findings.append(
            finding(
                "agent_catalogue_invalid",
                severity,
                "Current agent declarations could not be normalized safely.",
            )
        )

    inputs: list[dict[str, str]] = []
    if configured:
        inputs.append(input_record(registry_path, root, "registry_declaration"))
    for agent in agents:
        source = root / str(agent.get("source_file") or "")
        if source.is_file():
            inputs.append(input_record(source, root, "agent_declaration"))
    for helper in (
        root / "scripts" / "naos_agent_sponsor_registry.py",
        root / "scripts" / "naos_emit_capabilities.py",
        root / "scripts" / "validators" / "frontmatter_utils.py",
    ):
        if helper.is_file():
            inputs.append(input_record(helper, root, "generator_or_normalizer"))
    inputs.sort(key=lambda item: (item["path"], item["role"]))

    records = (
        [item for item in registry_data.get("records") or [] if isinstance(item, dict)]
        if schema_valid and enabled
        else []
    )
    by_id: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_id.setdefault(str(record.get("agent_id") or ""), []).append(record)
    current_ids = {str(agent.get("id") or "") for agent in agents}
    for agent_id, matches in sorted(by_id.items()):
        if agent_id not in current_ids:
            findings.append(
                finding(
                    "unknown_agent_record",
                    severity,
                    "A sponsor record names an agent that is not in the current normalized agent set.",
                    suffix=agent_id or "blank",
                    agent_id=agent_id or None,
                )
            )
        if len(matches) > 1:
            findings.append(
                finding(
                    "duplicate_agent_record",
                    severity,
                    "A current agent has more than one sponsor record.",
                    suffix=agent_id or "blank",
                    agent_id=agent_id or None,
                )
            )

    now = controlled_now_utc()
    report_agents: list[dict[str, Any]] = []
    for agent in agents:
        agent_id = str(agent.get("id") or "")
        source_file = str(agent.get("source_file") or "")
        source_path = root / source_file
        matches = by_id.get(agent_id, [])
        record = matches[0] if len(matches) == 1 else None
        agent_findings_before = len(findings)
        if configured and enabled and schema_valid and record is None:
            findings.append(
                finding(
                    "agent_record_missing",
                    severity,
                    "A current agent has no sponsor and credential-posture declaration.",
                    suffix=agent_id,
                    agent_id=agent_id,
                )
            )
        review_expires_at: str | None = None
        sponsor_digest: str | None = None
        credential_mode: str | None = None
        record_status = "missing"
        if record is not None:
            sponsor_digest = _safe_ref_digest(record.get("sponsor_ref"))
            credential = (
                record.get("credential_posture")
                if isinstance(record.get("credential_posture"), dict)
                else {}
            )
            credential_mode = str(credential.get("mode") or "") or None
            review = record.get("review") if isinstance(record.get("review"), dict) else {}
            reviewed_at_text = review.get("reviewed_at")
            expires_at_text = review.get("expires_at")
            reviewed_at = parse_timestamp(reviewed_at_text)
            expires_at = parse_timestamp(expires_at_text)
            review_expires_at = expires_at_text if isinstance(expires_at_text, str) else None
            if reviewed_at is None or expires_at is None:
                findings.append(
                    finding(
                        "review_timestamp_invalid",
                        severity,
                        "The sponsor record review timestamps must be timezone-aware ISO-8601 values.",
                        suffix=agent_id,
                        agent_id=agent_id,
                    )
                )
            else:
                if reviewed_at > now:
                    findings.append(
                        finding(
                            "review_in_future",
                            severity,
                            "The sponsor record claims a review later than the controlled evaluation time.",
                            suffix=agent_id,
                            agent_id=agent_id,
                        )
                    )
                if expires_at <= reviewed_at:
                    findings.append(
                        finding(
                            "review_window_invalid",
                            severity,
                            "The sponsor record review expiry is not later than its reviewed-at time.",
                            suffix=agent_id,
                            agent_id=agent_id,
                        )
                    )
                elif expires_at <= now:
                    findings.append(
                        finding(
                            "review_expired",
                            severity,
                            "The sponsor record review has expired at the controlled evaluation time.",
                            suffix=agent_id,
                            agent_id=agent_id,
                        )
                    )
            if credential_mode in {
                "external_short_lived_declared",
                "external_exception_declared",
            } and (
                not credential.get("owner_ref") or not credential.get("control_ref")
            ):
                findings.append(
                    finding(
                        "credential_control_missing",
                        severity,
                        "An external credential posture lacks an opaque owner or external-control reference.",
                        suffix=agent_id,
                        agent_id=agent_id,
                    )
                )
            if credential_mode == "external_exception_declared":
                findings.append(
                    finding(
                        "credential_exception_review",
                        severity,
                        "The agent declares an external credential exception that requires human review.",
                        suffix=agent_id,
                        agent_id=agent_id,
                    )
                )
            record_status = "current"
            new_agent_findings = [
                item
                for item in findings[agent_findings_before:]
                if item.get("agent_id") == agent_id
            ]
            if any(item.get("reason_code") == "review_expired" for item in new_agent_findings):
                record_status = "expired"
            elif new_agent_findings:
                record_status = "review_required"
        if not schema_valid and configured:
            record_status = "invalid"
        report_agents.append(
            {
                "agent_id": agent_id,
                "agent_name": str(agent.get("name") or agent_id),
                "source_file": source_file,
                "source_sha256": sha256_file(source_path),
                "record_status": record_status,
                "sponsor_ref_sha256": sponsor_digest,
                "credential_posture": credential_mode,
                "review_expires_at": review_expires_at,
            }
        )

    reason_counter = Counter(str(item.get("reason_code") or "registry_review_required") for item in findings)
    reason_counts = {code: reason_counter.get(code, 0) for code in REASON_ORDER}
    summary = finding_counts(findings)
    summary.update(
        {
            "agents": len(agents),
            "records": len(records),
            "covered_agents": sum(1 for item in report_agents if item["record_status"] == "current"),
            "expired_records": reason_counts["review_expired"],
            "credential_exceptions": reason_counts["credential_exception_review"],
            "inputs": len(inputs),
        }
    )
    if not configured:
        status = "not_configured"
        findings = []
        reason_counts = {code: 0 for code in REASON_ORDER}
        summary = finding_counts(findings) | {
            "agents": len(agents),
            "records": 0,
            "covered_agents": 0,
            "expired_records": 0,
            "credential_exceptions": 0,
            "inputs": len(inputs),
        }
    else:
        status = "review_required" if findings else "pass"

    relative_registry = (
        relative_bounded_path(registry_path, root)
        if configured
        else (Path(naos_root) / registry_path.name).as_posix()
    )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "generated_at": controlled_utc_now_text(),
        "generator_version": GENERATOR_VERSION,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "configured": configured,
        "enabled": enabled if configured else False,
        "format": {
            "id": FORMAT_ID,
            "version": 1,
            "kind": "build_time_declared_posture",
        },
        "decision_supported": str(registry_data.get("decision_supported") or ""),
        "verification_status": "declared_not_verified",
        "registry": {
            "path": relative_registry,
            "source": registry_source,
            "sha256": registry_sha,
            "schema_valid": schema_valid,
            "schema_error_count": len(schema_errors),
        },
        "provenance": {
            "basis": "repo_local_declared_posture",
            "inputs": inputs,
            "input_set_digest": canonical_digest(inputs),
        },
        "agents": report_agents,
        "reason_code_counts": reason_counts,
        "report_digest": "",
        "findings": findings,
        "known_gaps": list(KNOWN_GAPS),
        "residual_risks": list(RESIDUAL_RISKS),
        "limitations": list(LIMITATIONS),
        "not_claimed": list(NOT_CLAIMED),
        "human_review_required": bool(findings),
        "summary": summary,
    }
    report["report_digest"] = canonical_digest(report_digest_payload(report))
    output_errors = schema_error_metadata(report, output_schema)
    if output_errors:
        raise SponsorRegistryError(
            f"Generated sponsor-registry report violates its schema in {len(output_errors)} place(s)."
        )
    return report


def validate_registry_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    report: dict[str, Any],
    registry: str | None = None,
) -> list[str]:
    if schema_error_metadata(report, report_schema_path(root)):
        return ["registry_report_schema_invalid"]
    try:
        expected = build_expected_report(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            registry=registry,
        )
    except (SponsorRegistryError, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError):
        return ["registry_consumer_unavailable"]
    reasons: list[str] = []
    if report.get("provenance", {}).get("input_set_digest") != expected["provenance"]["input_set_digest"]:
        reasons.append("registry_source_stale")
    stored_digest = report.get("report_digest")
    recomputed_digest = canonical_digest(report_digest_payload(report))
    if stored_digest != recomputed_digest:
        reasons.append("registry_content_mismatch")
    if canonical_digest(current_content_payload(report)) != canonical_digest(
        current_content_payload(expected)
    ):
        reasons.append("registry_content_mismatch")
    generated_at = parse_timestamp(report.get("generated_at"))
    if generated_at is None or generated_at > controlled_now_utc():
        reasons.append("registry_content_mismatch")
    if report.get("status") == "review_required" or report.get("human_review_required") is True:
        counts = report.get("reason_code_counts") if isinstance(report.get("reason_code_counts"), dict) else {}
        reasons.extend(
            code for code in REASON_ORDER if int(counts.get(code) or 0) > 0
        )
        if not any(code in REASON_ORDER for code in reasons):
            reasons.append("registry_review_required")
    return list(dict.fromkeys(reasons))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate an opt-in build-time agent sponsor registry."
    )
    parser.add_argument("--profile")
    parser.add_argument("--naos-root")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd().resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    output = (
        Path(args.output)
        if args.output
        else report_output_path(
            root, naos_root, policy, "agent_sponsor_registry_report"
        )
    )
    if not output.is_absolute():
        output = root / output
    try:
        preflight_bounded_output(output, root)
        expected = build_expected_report(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            registry=args.registry,
        )
    except (SponsorRegistryError, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"NAOS agent sponsor registry: FAIL — {exc}", file=sys.stderr)
        return 2

    if args.check:
        if not output.is_file():
            print(
                f"NAOS agent sponsor registry: FAIL — missing report: {output}",
                file=sys.stderr,
            )
            return 1
        try:
            actual = load_json_mapping(output)
            reasons = validate_registry_report(
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
                report=actual,
                registry=args.registry,
            )
        except (SponsorRegistryError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"NAOS agent sponsor registry: FAIL — {exc}", file=sys.stderr)
            return 1
        if reasons:
            print(
                f"NAOS agent sponsor registry: FAIL — {', '.join(reasons)}",
                file=sys.stderr,
            )
            return 1
        print(f"NAOS agent sponsor registry: PASS — {output} is current")
        return 0

    write_report(output, expected)
    if args.json:
        print(json.dumps(expected, indent=2, sort_keys=True))
    else:
        print(
            "NAOS agent sponsor registry: "
            f"{expected['status']} ({expected['summary']['covered_agents']}/"
            f"{expected['summary']['agents']} agents covered, output: {output})"
        )
    return exit_code_for_summary(profile, expected["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
