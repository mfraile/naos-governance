#!/usr/bin/env python3
"""Validate and reproduce the public regulatory claim/source matrix.

The validator is deliberately offline. It proves current document identity,
row/document coverage, declared source metadata, bounded dispositions, and
deterministic arithmetic. It does not re-fetch authority, reproduce private Git
history, or make a legal conclusion.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections import Counter
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "docs" / "REGULATORY_CLAIM_SOURCE_MATRIX.yaml"
DEFAULT_SCHEMA = ROOT / "schemas" / "naos" / "regulatory_claim_source_matrix.schema.json"
CLAIM_RE = re.compile(r"`((?:DORA|E23)-[A-Z0-9-]+)`")
DOCUMENTS = ("docs/DORA_MAPPING.md", "docs/OSFI_E23_MAPPING.md")
FRAMEWORK_SOURCE = {"DORA": "DORA", "OSFI_E23": "OSFI_E23"}
FRAMEWORK_PREFIX = {"DORA": "DORA-", "OSFI_E23": "E23-"}
FRAMEWORK_DOCUMENT = {
    "DORA": "docs/DORA_MAPPING.md",
    "OSFI_E23": "docs/OSFI_E23_MAPPING.md",
}
OFFICIAL_HOST = {"DORA": "eur-lex.europa.eu", "OSFI_E23": "www.osfi-bsif.gc.ca"}


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one mapping")
    return value


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _finding(code: str, message: str, **details: Any) -> dict[str, Any]:
    return {"code": code, "message": message, **details}


def _baseline_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in data["baseline"]["documents"]:
        path = row["path"]
        document = ROOT / path
        if not document.is_file():
            findings.append(
                _finding(
                    "baseline_document_unreadable",
                    "Current public document cannot be read from the kit checkout.",
                    path=path,
                )
            )
            continue
        actual_sha = hashlib.sha256(document.read_bytes()).hexdigest()
        if actual_sha != row["sha256"]:
            findings.append(
                _finding(
                    "baseline_sha256_mismatch",
                    "Declared current-document SHA-256 differs from public content.",
                    path=path,
                    declared=row["sha256"],
                    actual=actual_sha,
                )
            )
    return findings


def _document_claims() -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    claims: dict[str, list[str]] = {}
    findings: list[dict[str, Any]] = []
    for path in DOCUMENTS:
        text = (ROOT / path).read_text(encoding="utf-8")
        identifiers = CLAIM_RE.findall(text)
        claims[path] = identifiers
        duplicates = sorted(key for key, count in Counter(identifiers).items() if count != 1)
        if duplicates:
            findings.append(
                _finding(
                    "document_claim_id_not_unique",
                    "Each governed-document claim identifier must occur exactly once.",
                    path=path,
                    identifiers=duplicates,
                )
            )
    return claims, findings


def _rounded_percentage(numerator: Any, denominator: Any) -> str | None:
    if not isinstance(numerator, (int, float)) or not isinstance(denominator, (int, float)):
        return None
    if denominator == 0:
        return None
    value = (Decimal(str(numerator)) * Decimal("100") / Decimal(str(denominator))).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    )
    return f"{value:.0f}%"


def _numeric_findings(claim: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for row in claim["numeric_derivations"]:
        result: dict[str, Any] = {
            "name": row["name"],
            "reported_value": row["reported_value"],
            "derivation_supported": row["derivation_supported"],
            "computed_result": row["computed_result"],
        }
        if row["kind"] == "ratio_percentage":
            arithmetic = _rounded_percentage(row["numerator"], row["denominator"])
            result["arithmetic_result"] = arithmetic
            if arithmetic != row["computed_result"]:
                findings.append(
                    _finding(
                        "numeric_arithmetic_mismatch",
                        "Declared ratio arithmetic does not reproduce.",
                        claim_id=claim["id"],
                        name=row["name"],
                        expected=row["computed_result"],
                        actual=arithmetic,
                    )
                )
        if row["derivation_supported"]:
            if claim["id"] == "DORA-SOURCE-001":
                match = re.fullmatch(r"inclusive integer identifiers (\d+) through (\d+)", row["inputs"][0])
                derived_count = int(match.group(2)) - int(match.group(1)) + 1 if match else None
                expected = f"{derived_count} articles" if derived_count is not None else None
            elif claim["id"] == "DORA-STRUCTURE-001":
                derived_count = len(row["inputs"])
                expected = f"{derived_count} chapters"
            else:
                derived_count = None
                expected = None
            result["derived_count"] = derived_count
            if (
                derived_count is None
                or row["numerator"] != derived_count
                or row["denominator"] != derived_count
                or row["computed_result"] != expected
            ):
                findings.append(
                    _finding(
                        "supported_numeric_derivation_mismatch",
                        "A retained numeric claim does not reproduce from its declared inputs.",
                        claim_id=claim["id"],
                        name=row["name"],
                        derived_count=derived_count,
                    )
                )
        results.append(result)
    return findings, results


def _stable_payload_sha256(data: dict[str, Any]) -> str:
    canonical = copy.deepcopy(data)
    canonical.pop("review_template", None)
    for claim in canonical.get("claims", []):
        claim.pop("independent_review", None)
    payload = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate(
    data: dict[str, Any],
    schema: dict[str, Any],
    *,
    require_independent_pass: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    schema_errors = sorted(
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).iter_errors(data),
        key=lambda error: list(error.absolute_path),
    )
    if schema_errors:
        return [
            _finding(
                "schema_validation_failed",
                error.message,
                path=list(error.absolute_path),
            )
            for error in schema_errors
        ], {}

    findings.extend(_baseline_findings(data))
    document_claims, document_findings = _document_claims()
    findings.extend(document_findings)

    rows = data["claims"]
    row_ids = [row["id"] for row in rows]
    duplicate_rows = sorted(key for key, count in Counter(row_ids).items() if count != 1)
    if duplicate_rows:
        findings.append(
            _finding(
                "matrix_claim_id_not_unique",
                "Each matrix claim identifier must occur exactly once.",
                identifiers=duplicate_rows,
            )
        )

    expected_order = document_claims[DOCUMENTS[0]] + document_claims[DOCUMENTS[1]]
    if row_ids != expected_order:
        findings.append(
            _finding(
                "matrix_document_coverage_mismatch",
                "Matrix rows must exactly match governed-document claim identifiers and order.",
                matrix=row_ids,
                documents=expected_order,
            )
        )

    status_counts = Counter(row["status"] for row in rows)
    doc_counts = Counter(row["document_path"] for row in rows)
    if dict(status_counts) != data["inventory"]["rows_by_status"]:
        findings.append(
            _finding(
                "inventory_status_count_mismatch",
                "Declared status counts differ from matrix rows.",
                declared=data["inventory"]["rows_by_status"],
                actual=dict(status_counts),
            )
        )
    if dict(doc_counts) != data["inventory"]["rows_by_document"]:
        findings.append(
            _finding(
                "inventory_document_count_mismatch",
                "Declared document counts differ from matrix rows.",
                declared=data["inventory"]["rows_by_document"],
                actual=dict(doc_counts),
            )
        )

    numeric_results: dict[str, list[dict[str, Any]]] = {}
    review_counts: Counter[str] = Counter()
    canonical_review = data["review_template"]
    if require_independent_pass:
        receipt = canonical_review["receipt"]
        if not isinstance(receipt, str) or not receipt.strip():
            findings.append(
                _finding(
                    "independent_review_receipt_missing",
                    "Terminal validation requires a non-empty canonical independent-review receipt.",
                    scope="review_template",
                )
            )
    for row in rows:
        framework = row["framework"]
        claim_id = row["id"]
        if not claim_id.startswith(FRAMEWORK_PREFIX[framework]):
            findings.append(
                _finding(
                    "framework_prefix_mismatch",
                    "Claim identifier prefix differs from its framework.",
                    claim_id=claim_id,
                    framework=framework,
                )
            )
        if row["document_path"] != FRAMEWORK_DOCUMENT[framework]:
            findings.append(
                _finding(
                    "framework_document_mismatch",
                    "Claim row is assigned to the wrong governed document.",
                    claim_id=claim_id,
                )
            )
        expected_source = data["source_register"][FRAMEWORK_SOURCE[framework]]
        actual_source = {key: value for key, value in row["source"].items() if key != "locator"}
        if actual_source != expected_source:
            findings.append(
                _finding(
                    "row_source_register_mismatch",
                    "Row authority metadata differs from the canonical source register.",
                    claim_id=claim_id,
                )
            )
        host = urlparse(row["source"]["official_url"]).hostname
        if host != OFFICIAL_HOST[framework]:
            findings.append(
                _finding(
                    "non_primary_source_host",
                    "A substantive row does not resolve to the allowed official host.",
                    claim_id=claim_id,
                    host=host,
                )
            )
        expected_command = (
            "python3 -B scripts/validators/validate_regulatory_claim_source_matrix.py "
            f"--claim {claim_id} --json"
        )
        if row["reproduction_command"] != expected_command:
            findings.append(
                _finding(
                    "reproduction_command_mismatch",
                    "Claim reproduction command is not exact.",
                    claim_id=claim_id,
                )
            )
        if row["independent_review"] != data["review_template"]:
            findings.append(
                _finding(
                    "independent_review_template_mismatch",
                    "Row review status differs from the canonical review receipt.",
                    claim_id=claim_id,
                )
            )
        review_counts[row["independent_review"]["status"]] += 1
        if require_independent_pass and row["independent_review"]["status"] != "pass":
            findings.append(
                _finding(
                    "independent_review_not_passed",
                    "Terminal validation requires independent PASS for every row.",
                    claim_id=claim_id,
                    status=row["independent_review"]["status"],
                )
            )
        if require_independent_pass:
            receipt = row["independent_review"]["receipt"]
            if not isinstance(receipt, str) or not receipt.strip():
                findings.append(
                    _finding(
                        "independent_review_receipt_missing",
                        "Terminal validation requires a non-empty independent-review receipt for every row.",
                        claim_id=claim_id,
                    )
                )
        if row["status"] == "unsupported":
            if row["document_action"] != "withdrawn_as_result" or row["claim_effect"] != "negative_evidence":
                findings.append(
                    _finding(
                        "unsupported_disposition_mismatch",
                        "Unsupported rows must be preserved only as withdrawn negative evidence.",
                        claim_id=claim_id,
                    )
                )
            if any(item["derivation_supported"] for item in row["numeric_derivations"]):
                findings.append(
                    _finding(
                        "unsupported_numeric_marked_supported",
                        "Unsupported claims cannot contain a supported numeric derivation.",
                        claim_id=claim_id,
                    )
                )
        elif row["document_action"] == "withdrawn_as_result":
            findings.append(
                _finding(
                    "verified_claim_withdrawn",
                    "A non-unsupported claim cannot use the withdrawn-result disposition.",
                    claim_id=claim_id,
                )
            )
        numeric_findings, results = _numeric_findings(row)
        findings.extend(numeric_findings)
        numeric_results[claim_id] = results

    report = {
        "claim_count": len(rows),
        "document_claim_counts": dict(sorted(doc_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "review_counts": dict(sorted(review_counts.items())),
        "numeric_results": numeric_results,
        "stable_payload_sha256": _stable_payload_sha256(data),
    }
    return findings, report


def run(
    *,
    matrix_path: Path,
    schema_path: Path,
    claim_id: str | None,
    require_independent_pass: bool,
) -> dict[str, Any]:
    data = _load_yaml(matrix_path)
    schema = _load_json(schema_path)
    findings, summary = validate(
        data,
        schema,
        require_independent_pass=require_independent_pass,
    )
    selected: dict[str, Any] | None = None
    if claim_id is not None:
        selected_row = next((row for row in data.get("claims", []) if row.get("id") == claim_id), None)
        if selected_row is None:
            findings.append(
                _finding(
                    "unknown_claim",
                    "Requested claim identifier is absent from the matrix.",
                    claim_id=claim_id,
                )
            )
        else:
            selected = {
                "id": selected_row["id"],
                "status": selected_row["status"],
                "document_action": selected_row["document_action"],
                "document_path": selected_row["document_path"],
                "document_location": selected_row["document_location"],
                "source": selected_row["source"],
                "numeric_derivations": summary.get("numeric_results", {}).get(claim_id, []),
                "falsifier": selected_row["falsifier"],
                "independent_review": selected_row["independent_review"],
            }
    return {
        "schema": "urn:naos-governance:regulatory-claim-source-matrix-validation:v1",
        "status": "pass" if not findings else "fail",
        "finding_count": len(findings),
        "findings": findings,
        "matrix": "docs/REGULATORY_CLAIM_SOURCE_MATRIX.yaml",
        "schema_path": "schemas/naos/regulatory_claim_source_matrix.schema.json",
        "require_independent_pass": require_independent_pass,
        "summary": summary,
        "selected_claim": selected,
        "claim_boundary": "Offline current-public-document integrity and deterministic-derivation evidence only; not private-history proof, legal advice, compliance, control satisfaction, conformance, certification, or operating-effectiveness proof.",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--claim")
    parser.add_argument("--require-independent-pass", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    result = run(
        matrix_path=args.matrix.resolve(),
        schema_path=args.schema.resolve(),
        claim_id=args.claim,
        require_independent_pass=args.require_independent_pass,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "Regulatory claim/source matrix: "
            f"{result['status']} ({result['finding_count']} findings)"
        )
        for finding in result["findings"]:
            print(f"- {finding['code']}: {finding['message']}")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
