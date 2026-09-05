#!/usr/bin/env python3
"""Verify assessor-supplied AIVSS-Agentic v0.8 arithmetic offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    write_report,
)


INPUT_SCHEMA = "naos.aivss_assessments.v1"
REPORT_SCHEMA = "naos.aivss_arithmetic_verification_report.v1"
FORMAT_ID = "aivss_arithmetic_verification.v1"
GENERATOR_VERSION = "1.0.0"
RUBRIC_ID = "AIVSS-Agentic"
RUBRIC_VERSION = "0.8"
NORMATIVE_PDF_URL = (
    "https://aivss.owasp.org/assets/publications/"
    "AIVSS%20Scoring%20System%20For%20OWASP%20Agentic%20AI%20Core%20Security%20Risks%20v0.8.pdf"
)
NORMATIVE_PDF_SHA256 = "a2abbd215f0d7790d273c30a893a09c0dc37a6c109765eb0363c01af897fd9af"
DECISION_SUPPORTED = (
    "Whether assessor-supplied AIVSS-Agentic v0.8 arithmetic matches the pinned "
    "published formula and whether a computed High or Critical band should be "
    "shown to G2/G6 human security review."
)
FACTOR_KEYS = (
    "autonomy",
    "tools",
    "language",
    "context",
    "non_determinism",
    "opacity",
    "persistence",
    "identity",
    "multi_agent",
    "self_modification",
)
THREAT_MULTIPLIERS = {
    "unreported": Decimal("0.50"),
    "proof_of_concept": Decimal("0.97"),
    "attacked": Decimal("1.00"),
}
MITIGATION_FACTORS = {
    "strong": Decimal("0.67"),
    "partial": Decimal("0.83"),
    "no_or_weak": Decimal("1.00"),
}
REASON_ORDER = (
    "input_config_parse_error",
    "input_schema_invalid",
    "duplicate_assessment_id",
    "arithmetic_mismatch",
    "high_or_critical_review",
)
NOT_CLAIMED = [
    "risk assessment",
    "exploitability proof",
    "vulnerability discovery",
    "CVSS calculation or vector validation",
    "runtime observation",
    "mitigation proof",
    "security assurance",
    "compliance evidence",
    "certification",
    "approval",
    "automatic blocking",
    "automatic prioritization",
    "merge authority",
    "release authority",
    "risk acceptance",
    "publication authority",
]
LIMITATIONS = [
    "The verifier recalculates assessor-supplied values only; humans select the CVSS base score, factor values, threat maturity, mitigation strength, and evidence.",
    "The pinned v0.8 PDF permits a 0.0 score but defines no severity band for 0.0, so the report preserves that result as unbanded rather than inventing an OWASP band.",
    "High and Critical results create advisory G2/G6 human-review prompts only and never change a gate, approval, priority, waiver, merge, release, or risk-acceptance decision.",
    "SHA-256 pins source content and detects local drift; it does not sign, authenticate, attest, or prove provenance of the publication or assessment.",
]
KNOWN_GAPS = [
    "aivss_v0_8_zero_score_has_no_defined_severity_band",
    "subjective_assessor_inputs_are_not_independently_verified",
    "cvss_v4_vector_and_base_score_are_not_calculated_or_validated",
    "mitigation_effectiveness_is_not_observed",
]
RESIDUAL_RISKS = [
    "incorrect_or_stale_assessor_inputs",
    "automation_bias_from_numeric_scores",
    "future_rubric_version_drift",
    "human_review_required_for_high_or_critical_results_and_mismatches",
]


class AivssVerificationError(ValueError):
    """Raised when AIVSS inputs or outputs cannot be bounded safely."""


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
        raise AivssVerificationError(
            f"AIVSS input must not contain traversal components: {path}"
        )
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
        cursor = lexical_root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise AivssVerificationError(
                    f"AIVSS input must not use symlink path components: {path}"
                )
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError) as exc:
        raise AivssVerificationError(
            f"AIVSS input must be a regular file inside the project root: {path}"
        ) from exc
    if not resolved.is_file():
        raise AivssVerificationError(
            f"AIVSS input must be a regular non-symlink file: {path}"
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
        raise AivssVerificationError(
            f"AIVSS output must not contain traversal components: {path}"
        )
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
    except ValueError as exc:
        raise AivssVerificationError(
            f"AIVSS output must remain inside the project root: {path}"
        ) from exc
    cursor = lexical_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise AivssVerificationError(
                f"AIVSS output must not use symlink path components: {path}"
            )
    if path.exists():
        relative_bounded_path(path, root)


def load_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AivssVerificationError(f"Expected JSON object: {path}")
    return data


def load_yaml_mapping(path: Path) -> tuple[dict[str, Any], bool]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        return {}, False
    return (data, True) if isinstance(data, dict) else ({}, False)


def input_schema_path(root: Path) -> Path:
    project = root / "schemas" / "naos" / "aivss_assessments.schema.json"
    return project if project.is_file() else kit_root() / "schemas" / "naos" / project.name


def report_schema_path(root: Path) -> Path:
    project = root / "schemas" / "naos" / "aivss_arithmetic_verification_report.schema.json"
    return project if project.is_file() else kit_root() / "schemas" / "naos" / project.name


def schema_error_metadata(instance: Any, schema_path: Path) -> list[dict[str, str]]:
    schema = load_json_mapping(schema_path)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    return [
        {
            "path": ".".join(str(part) for part in error.absolute_path) or "<root>",
            "validator": str(error.validator or "unknown"),
        }
        for error in errors
    ]


def resolve_assessments_path(
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
        policy.get("paths", {}).get("aivss_assessments")
        or "aivss_assessments.yaml"
    )
    path = root / naos_root / filename
    return path, "project" if path.is_file() else "missing"


def input_record(path: Path, root: Path, role: str) -> dict[str, str]:
    return {
        "path": relative_bounded_path(path, root),
        "role": role,
        "sha256": sha256_file(path),
    }


def _decimal(value: Any, field: str) -> Decimal:
    if not isinstance(value, str):
        raise AivssVerificationError(f"{field} must be a decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise AivssVerificationError(f"{field} is not a finite decimal") from exc
    if not result.is_finite():
        raise AivssVerificationError(f"{field} is not a finite decimal")
    return result


def decimal_text(value: Decimal, places: int) -> str:
    quantum = Decimal(1).scaleb(-places)
    return format(value.quantize(quantum), f".{places}f")


def exact_decimal_text(value: Decimal) -> str:
    """Return a canonical finite decimal without changing its value."""

    # Decimal.normalize() applies the ambient decimal context and can silently
    # round a value that was calculated exactly in the wider local context.
    # Fixed-point formatting is value-preserving; trim only insignificant
    # trailing fractional zeroes afterwards.
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in {"", "-0"}:
        text = "0"
    return text if "." in text else f"{text}.0"


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def severity_band(score: Decimal) -> str | None:
    if score == Decimal("0.0"):
        return None
    if Decimal("0.1") <= score <= Decimal("3.9"):
        return "low"
    if Decimal("4.0") <= score <= Decimal("6.9"):
        return "medium"
    if Decimal("7.0") <= score <= Decimal("8.9"):
        return "high"
    if Decimal("9.0") <= score <= Decimal("10.0"):
        return "critical"
    raise AivssVerificationError(f"Computed AIVSS score is outside 0.0-10.0: {score}")


def calculate_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
    assessment_id = str(assessment.get("assessment_id") or "<unknown>")
    cvss = assessment.get("cvss") if isinstance(assessment.get("cvss"), dict) else {}
    base = _decimal(cvss.get("base_score"), f"{assessment_id}.cvss.base_score")
    if base < Decimal("0.0") or base > Decimal("10.0"):
        raise AivssVerificationError(
            f"{assessment_id}.cvss.base_score must be between 0.0 and 10.0"
        )
    factors = assessment.get("factors") if isinstance(assessment.get("factors"), dict) else {}
    factor_values: list[Decimal] = []
    for key in FACTOR_KEYS:
        factor = factors.get(key) if isinstance(factors.get(key), dict) else {}
        value = _decimal(factor.get("value"), f"{assessment_id}.factors.{key}.value")
        if value not in {Decimal("0.0"), Decimal("0.5"), Decimal("1.0")}:
            raise AivssVerificationError(
                f"{assessment_id}.factors.{key}.value must be 0.0, 0.5, or 1.0"
            )
        factor_values.append(value)
    threat = assessment.get("threat_maturity")
    threat = threat if isinstance(threat, dict) else {}
    threat_level = str(threat.get("level") or "")
    mitigation = assessment.get("mitigation_strength")
    mitigation = mitigation if isinstance(mitigation, dict) else {}
    mitigation_level = str(mitigation.get("level") or "")
    try:
        threat_multiplier = THREAT_MULTIPLIERS[threat_level]
        mitigation_factor = MITIGATION_FACTORS[mitigation_level]
    except KeyError as exc:
        raise AivssVerificationError(
            f"{assessment_id} uses an unsupported threat or mitigation category"
        ) from exc

    # The input schema bounds every decimal token to 64 characters. A local
    # 256-digit context therefore preserves every finite intermediate exactly;
    # only the final published score is rounded to one decimal place.
    with localcontext() as context:
        context.prec = 256
        factor_sum = sum(factor_values, Decimal("0.0"))
        risk_gap = Decimal("10.0") - base
        factor_fraction = factor_sum / Decimal("10.0")
        aars = risk_gap * factor_fraction * threat_multiplier
        raw_score = (base + aars) * mitigation_factor
        score = raw_score.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    band = severity_band(score)
    return {
        "risk_gap": exact_decimal_text(risk_gap),
        "factor_sum": exact_decimal_text(factor_sum),
        "factor_fraction": exact_decimal_text(factor_fraction),
        "threat_multiplier": exact_decimal_text(threat_multiplier),
        "mitigation_factor": exact_decimal_text(mitigation_factor),
        "aars": exact_decimal_text(aars),
        "raw_score": exact_decimal_text(raw_score),
        "score": decimal_text(score, 1),
        "severity_band": band,
        "band_defined_by_v0_8": band is not None,
    }


def arithmetic_mismatches(
    assessment: dict[str, Any], computed: dict[str, Any]
) -> list[str]:
    claimed = (
        assessment.get("claimed_result")
        if isinstance(assessment.get("claimed_result"), dict)
        else {}
    )
    mismatches: list[str] = []
    for field in ("risk_gap", "factor_sum", "aars", "raw_score", "score"):
        try:
            claimed_value = _decimal(claimed.get(field), f"claimed_result.{field}")
            computed_value = _decimal(computed.get(field), f"computed.{field}")
        except AivssVerificationError:
            mismatches.append(field)
            continue
        if claimed_value != computed_value:
            mismatches.append(field)
    if claimed.get("severity_band") != computed.get("severity_band"):
        mismatches.append("severity_band")
    return mismatches


def finding(reason_code: str, message: str, *, suffix: str = "input") -> dict[str, Any]:
    return {
        "id": f"aivss_arithmetic_verification.{reason_code}.{suffix}",
        "severity": "advisory",
        "status": "review_required",
        "reason_code": reason_code,
        "message": message,
    }


def report_digest_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "report_digest"}


def current_content_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in report.items()
        if key not in {"generated_at", "report_digest"}
    }


def build_expected_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    assessments: str | None = None,
) -> dict[str, Any]:
    assessments_path, assessments_source = resolve_assessments_path(
        root, naos_root, policy, assessments
    )
    state = bounded_artifact_state(assessments_path, root)
    if state == "unsafe":
        raise AivssVerificationError(
            "AIVSS assessments must be an absent or regular non-symlink file inside the project root"
        )
    configured = state == "regular"
    input_data: dict[str, Any] = {}
    parse_ok = False
    input_sha: str | None = None
    if configured:
        relative_bounded_path(assessments_path, root)
        input_sha = sha256_file(assessments_path)
        input_data, parse_ok = load_yaml_mapping(assessments_path)

    input_schema = input_schema_path(root)
    output_schema = report_schema_path(root)
    relative_bounded_path(input_schema, root)
    relative_bounded_path(output_schema, root)
    schema_errors = (
        schema_error_metadata(input_data, input_schema)
        if configured and parse_ok
        else []
    )
    schema_valid = configured and parse_ok and not schema_errors
    enabled = bool(input_data.get("enabled")) if parse_ok else False
    findings: list[dict[str, Any]] = []
    if configured and not parse_ok:
        findings.append(
            finding(
                "input_config_parse_error",
                "The AIVSS assessment input could not be parsed as a YAML mapping.",
            )
        )
    if configured and parse_ok and schema_errors:
        findings.append(
            finding(
                "input_schema_invalid",
                f"The AIVSS assessment input violates its strict schema in {len(schema_errors)} place(s).",
            )
        )

    inputs: list[dict[str, str]] = []
    if configured:
        inputs.append(input_record(assessments_path, root, "assessment_input"))
    for path, role in (
        (input_schema, "input_schema"),
        (output_schema, "report_schema"),
        (root / "scripts" / "naos_aivss_arithmetic_verification.py", "verifier"),
    ):
        if path.is_file():
            inputs.append(input_record(path, root, role))
    inputs.sort(key=lambda item: (item["path"], item["role"]))

    raw_assessments = (
        [item for item in input_data.get("assessments") or [] if isinstance(item, dict)]
        if schema_valid and enabled
        else []
    )
    id_counts = Counter(str(item.get("assessment_id") or "") for item in raw_assessments)
    duplicate_ids = sorted(key for key, count in id_counts.items() if key and count > 1)
    for assessment_id in duplicate_ids:
        findings.append(
            finding(
                "duplicate_assessment_id",
                "An assessment identifier is declared more than once.",
                suffix=assessment_id,
            )
        )

    results: list[dict[str, Any]] = []
    for assessment in raw_assessments:
        assessment_id = str(assessment.get("assessment_id") or "")
        if assessment_id in duplicate_ids:
            continue
        computed = calculate_assessment(assessment)
        mismatches = arithmetic_mismatches(assessment, computed)
        verification_status = "mismatch" if mismatches else "verified"
        if mismatches:
            findings.append(
                finding(
                    "arithmetic_mismatch",
                    "One or more claimed AIVSS arithmetic fields do not match the pinned v0.8 calculation.",
                    suffix=assessment_id,
                )
            )
        if computed["severity_band"] in {"high", "critical"}:
            findings.append(
                finding(
                    "high_or_critical_review",
                    "A computed High or Critical AIVSS band requires G2/G6 human security review.",
                    suffix=assessment_id,
                )
            )
        results.append(
            {
                "assessment_id": assessment_id,
                "finding_ref": str(assessment.get("finding_ref") or ""),
                "assessor_ref": str(assessment.get("assessor_ref") or ""),
                "assessed_at": str(assessment.get("assessed_at") or ""),
                "system_scope_ref": str(assessment.get("system_scope_ref") or ""),
                "cvss_version": "4.0",
                "cvss_vector": str(
                    (assessment.get("cvss") or {}).get("vector") or ""
                ),
                "cvss_base_score": str(
                    (assessment.get("cvss") or {}).get("base_score") or ""
                ),
                "verification_status": verification_status,
                "mismatch_fields": mismatches,
                "computed": computed,
                "review_prompt_required": computed["severity_band"]
                in {"high", "critical"},
                "related_gates": ["G2", "G6"]
                if computed["severity_band"] in {"high", "critical"}
                else [],
            }
        )

    reason_counter = Counter(str(item["reason_code"]) for item in findings)
    reason_counts = {code: reason_counter.get(code, 0) for code in REASON_ORDER}
    summary = finding_counts(findings)
    summary.update(
        {
            "assessments": len(raw_assessments),
            "verified": sum(
                item["verification_status"] == "verified" for item in results
            ),
            "mismatches": reason_counts["arithmetic_mismatch"],
            "high": sum(
                item["computed"]["severity_band"] == "high" for item in results
            ),
            "critical": sum(
                item["computed"]["severity_band"] == "critical"
                for item in results
            ),
            "review_prompts": reason_counts["high_or_critical_review"],
            "unbanded_zero_scores": sum(
                item["computed"]["score"] == "0.0" for item in results
            ),
            "inputs": len(inputs),
        }
    )
    if not configured:
        status = "not_configured"
    else:
        status = "review_required" if findings else "pass"

    relative_input = (
        relative_bounded_path(assessments_path, root)
        if configured
        else (Path(naos_root) / assessments_path.name).as_posix()
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
            "kind": "offline_arithmetic_verification",
        },
        "rubric": {
            "id": RUBRIC_ID,
            "version": RUBRIC_VERSION,
            "normative_pdf_url": NORMATIVE_PDF_URL,
            "normative_pdf_sha256": NORMATIVE_PDF_SHA256,
            "normative_scope": "published_v0.8_pdf_only",
        },
        "decision_supported": DECISION_SUPPORTED,
        "authority": {
            "consumer": "scripts/naos_control_plane_review.py",
            "target_gates": ["G2", "G6"],
            "prompt_bands": ["high", "critical"],
            "behavior": "human_review_prompt_only",
            "may_approve": False,
            "may_block": False,
            "may_prioritize": False,
            "may_merge": False,
            "may_release": False,
            "may_accept_risk": False,
        },
        "input": {
            "path": relative_input,
            "source": assessments_source,
            "sha256": input_sha,
            "schema_valid": schema_valid,
            "schema_error_count": len(schema_errors),
        },
        "provenance": {
            "basis": "repo_local_assessor_supplied_values",
            "inputs": inputs,
            "input_set_digest": canonical_digest(inputs),
        },
        "assessments": results,
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
        raise AivssVerificationError(
            f"Generated AIVSS report violates its schema in {len(output_errors)} place(s)"
        )
    return report


def validate_verification_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    report: dict[str, Any],
    assessments: str | None = None,
) -> list[str]:
    if schema_error_metadata(report, report_schema_path(root)):
        return ["aivss_report_schema_invalid"]
    try:
        expected = build_expected_report(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            assessments=assessments,
        )
    except (AivssVerificationError, OSError, ValueError, json.JSONDecodeError):
        return ["aivss_consumer_unavailable"]
    reasons: list[str] = []
    if report.get("provenance", {}).get("input_set_digest") != expected[
        "provenance"
    ]["input_set_digest"]:
        reasons.append("aivss_source_stale")
    stored_digest = report.get("report_digest")
    if stored_digest != canonical_digest(report_digest_payload(report)):
        reasons.append("aivss_content_mismatch")
    if canonical_digest(current_content_payload(report)) != canonical_digest(
        current_content_payload(expected)
    ):
        reasons.append("aivss_content_mismatch")
    generated_at = parse_timestamp(report.get("generated_at"))
    if generated_at is None or generated_at > controlled_now_utc():
        reasons.append("aivss_content_mismatch")
    return list(dict.fromkeys(reasons))


def report_review_reason_codes(report: dict[str, Any]) -> list[str]:
    counts = (
        report.get("reason_code_counts")
        if isinstance(report.get("reason_code_counts"), dict)
        else {}
    )
    return [code for code in REASON_ORDER if int(counts.get(code) or 0) > 0]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify assessor-supplied AIVSS-Agentic v0.8 arithmetic offline."
    )
    parser.add_argument("--profile")
    parser.add_argument("--naos-root")
    parser.add_argument("--policy")
    parser.add_argument("--assessments")
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
            root,
            naos_root,
            policy,
            "aivss_arithmetic_verification_report",
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
            assessments=args.assessments,
        )
    except (AivssVerificationError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"NAOS AIVSS arithmetic verification: FAIL — {exc}", file=sys.stderr)
        return 2

    if args.check:
        if not output.is_file():
            print(
                f"NAOS AIVSS arithmetic verification: FAIL — missing report: {output}",
                file=sys.stderr,
            )
            return 1
        try:
            actual = load_json_mapping(output)
            reasons = validate_verification_report(
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
                report=actual,
                assessments=args.assessments,
            )
        except (AivssVerificationError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"NAOS AIVSS arithmetic verification: FAIL — {exc}", file=sys.stderr)
            return 1
        if reasons:
            print(
                f"NAOS AIVSS arithmetic verification: FAIL — {', '.join(reasons)}",
                file=sys.stderr,
            )
            return 1
        print(f"NAOS AIVSS arithmetic verification: PASS — {output} is current")
        return 0

    write_report(output, expected)
    if args.json:
        print(json.dumps(expected, indent=2, sort_keys=True))
    else:
        print(
            "NAOS AIVSS arithmetic verification: "
            f"{expected['status']} ({expected['summary']['verified']}/"
            f"{expected['summary']['assessments']} arithmetic records verified, "
            f"output: {output})"
        )
    # Score bands and arithmetic mismatches are review evidence, never automatic
    # blocking. Unsafe paths or an inability to build the deterministic report
    # return 2 above; a structurally current report returns 0 even with prompts.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
