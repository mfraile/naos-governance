#!/usr/bin/env python3
"""Emit signable evidence envelopes and verify local evidence digests (RF2).

Keyless and adopter-owned (ADR-0007). NAOS emits a DSSE-style signable envelope over the
evidence manifest root and recomputes local digests and the manifest root. NAOS never holds
keys, signs, validates envelope signatures, authenticates identities, or issues certificates.
An adopter may sign the envelope with an external signer (cosign / Sigstore-keyless / KMS),
but signing is not required by the kit.

Modes:
- emit:   build a DSSE envelope (payload = manifest root + metadata; empty signatures[]
          for an adopter to fill optionally) plus best-effort Git-reported HEAD signature,
          signer, and author metadata -> evidence_envelope.json.
- verify: recompute artifact digests from disk, recompute the manifest root, compare to the
          attestation report and any supplied envelope payload; report tamper_evident,
          payload binding, signature-entry presence, and
          best-effort Git-reported HEAD metadata. No cryptographic signature validation occurs.

Non-claims: not a signature by NAOS, not approval, certification, compliance proof,
non-repudiation, or key custody.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    naos_root_path,
    report_default_path,
    safe_policy_path,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

from naos_evidence_contracts import local_evidence_subject  # noqa: E402

ENVELOPE_SCHEMA = "naos.evidence_envelope.v1"
VERIFY_SCHEMA = "naos.evidence_verification.v1"
PAYLOAD_TYPE = "application/vnd.naos.evidence+json"
LIMITATIONS = [
    "NAOS emits signable envelopes and recomputes local evidence digests; it does not sign, validate envelope signatures, hold keys, authenticate identities, or issue certificates.",
    "Tamper-evidence detects post-hoc edits to covered artifacts; it is not a signature or proof of authorship.",
    "The compatibility-named identity_binding field contains best-effort Git-reported HEAD metadata only; it is not identity authentication, authorization, or non-repudiation.",
    "The compatibility-named signed field reports only whether signature entries are present; NAOS does not validate them.",
    "Digest equality covers only declared subjects. Required coverage is reported separately from integrity and remains governed by evidence attestation.",
    "When an envelope is supplied, its decoded payload must bind the independently recomputed manifest root and artifact count; this binding does not validate its signatures. A consistent inactive v1 report with no payload is explicitly not applicable, never tamper-evident or signed.",
]
NOT_CLAIMED = [
    "signature by NAOS",
    "third-party signature validation",
    "identity authentication",
    "approval",
    "certification",
    "compliance proof",
    "non-repudiation",
    "key custody",
]

IDENTITY_CLAIM_CEILING = (
    "Best-effort local Git HEAD metadata only; NAOS applies no independent trust or "
    "acceptance policy to Git's reported commit-signature status, does not validate "
    "envelope signatures, and does not authenticate any identity."
)


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    """Read JSON without collapsing malformed input into a missing report."""
    return json.loads(path.read_text(encoding="utf-8"))


def input_finding(status: str, message: str, severity: str) -> dict[str, Any]:
    return {"id": f"evidence_signing.{status}", "severity": severity,
            "status": status, "message": message}


def load_attestation(root: Path, naos_root: str, policy: dict[str, Any],
                     severity: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    path = attestation_path(root, naos_root, policy)
    try:
        data = load_json(path)
    except FileNotFoundError:
        return None, [input_finding("missing_attestation",
            "No evidence attestation found; run `naos evidence-attestation` first.", severity)], "missing"
    except (OSError, ValueError) as exc:
        return None, [input_finding("invalid_attestation", f"Cannot read attestation JSON: {exc}", severity)], "invalid"
    schema = load_json(kit_root() / "schemas" / "naos" / "evidence_attestation.schema.json")
    errors = sorted((f"{'.'.join(map(str, error.absolute_path)) or '$'}: {error.message}"
                     for error in Draft202012Validator(schema).iter_errors(data)))
    if not errors:
        seen: set[str] = set()
        for item in data["artifact_manifest"]:
            rel = item["path"]
            if local_evidence_subject(root, rel) is None:
                errors.append(f"Artifact path must identify a local project file: {rel!r}")
            if rel in seen:
                errors.append(f"Duplicate artifact subject: {rel}")
            seen.add(rel)
    if errors:
        return None, [input_finding("invalid_attestation", "; ".join(errors), severity)], "invalid"
    return data, [], "valid"


def attestation_dimensions(att: dict[str, Any] | None, validation: str) -> dict[str, Any]:
    if att is None:
        return {"input_validation": validation, "digest_validation": "unavailable",
                "manifest_root_validation": "unavailable", "scope_status": "unknown",
                "artifacts_checked": 0, "artifacts_declared": 0, "attestation_status": None,
                "required_coverage": {"status": "unknown", "missing_count": 0},
                "attestation_human_review_required": True}
    state = att["status"]
    inactive = state in {"disabled", "not_configured"}
    count = len(att["artifact_manifest"])
    missing = len(att["missing_artifacts"])
    return {"input_validation": "valid", "digest_validation": "not_applicable" if inactive or not count else "unavailable",
            "manifest_root_validation": "not_applicable" if inactive else "not_recorded",
            "scope_status": state if inactive else "covered" if count else "empty",
            "artifacts_checked": 0, "artifacts_declared": count, "attestation_status": state,
            "required_coverage": {"status": "not_applicable" if inactive else "missing" if missing else "complete",
                                  "missing_count": missing},
            "attestation_human_review_required": att["human_review_required"]}


def coverage_findings(att: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    if att["status"] in {"disabled", "not_configured"} or not att["missing_artifacts"]:
        return []
    source_severities = [item["severity"] for item in att["findings"] if item.get("status") == "missing"]
    if source_severities:
        rank = {"none": 0, "advisory": 1, "warning": 2, "required": 3, "blocking": 4}
        severity = max(source_severities, key=lambda value: rank[value])
    return [input_finding("missing_required_coverage",
        f"Attestation declares {len(att['missing_artifacts'])} missing required artifact(s); digest equality does not establish coverage.", severity)]


def verification_status(summary: dict[str, int], dimensions: dict[str, Any]) -> str:
    status = status_from_counts(summary)
    if status != "pass":
        return status
    if dimensions["scope_status"] in {"empty", "disabled", "not_configured"}:
        return dimensions["scope_status"]
    if dimensions["manifest_root_validation"] == "not_recorded":
        return "root_unavailable"
    return status


def manifest_root_digest(pairs: list[tuple[str, str]]) -> str:
    """Mirror naos_evidence_attestation.manifest_root_digest for cross-verification."""
    canonical = json.dumps(sorted(pairs), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def attestation_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    return report_default_path(root, naos_root, policy, "evidence_attestation_report")


def envelope_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    paths = policy.get("paths") or {}
    return safe_policy_path(naos_root_path(root, naos_root),
                            paths.get("evidence_dir") or "evidence",
                            paths.get("evidence_envelope_report") or "evidence_envelope.json",
                            field="evidence_envelope_report")


def git_identity(root: Path) -> dict[str, Any]:
    """Return best-effort Git-reported HEAD metadata. Graceful, never raises."""
    unavailable = {
        "available": False,
        "signature_status": "no_git",
        "commit": None,
        "signer": None,
        "author": None,
        "signature_validation_performed_by_naos": False,
        "identity_authentication_performed": False,
        "claim_ceiling": IDENTITY_CLAIM_CEILING,
    }
    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "log",
                "-1",
                "--pretty=format:%H%x1f%G?%x1f%GS%x1f%an%x1f%ae",
            ],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return unavailable
    if out.returncode != 0 or not out.stdout.strip():
        return unavailable
    commit, gsig, signer, author_name, author_email = (
        out.stdout.split("\x1f") + ["", "", "", "", ""]
    )[:5]
    status_map = {"G": "good", "B": "bad", "U": "good_unknown_validity", "X": "expired",
                  "Y": "expired_key", "R": "revoked_key", "E": "cannot_check", "N": "unsigned"}
    return {
        "available": True,
        "commit": commit,
        "signature_status": status_map.get(gsig.strip(), "unsigned" if gsig.strip() in ("", "N") else gsig.strip()),
        "signer": signer.strip() or None,
        "author": {
            "name": author_name.strip(),
            "email": author_email.strip(),
        },
        "signature_validation_performed_by_naos": False,
        "identity_authentication_performed": False,
        "claim_ceiling": IDENTITY_CLAIM_CEILING,
    }


def collect_manifest(root: Path, attestation: dict[str, Any]) -> list[dict[str, Any]]:
    """Recompute validated subjects, retaining controlled read failures."""
    items: list[dict[str, Any]] = []
    for entry in attestation["artifact_manifest"]:
        rel = entry["path"]
        error = None
        recomputed = None
        present = False
        try:
            abs_path = local_evidence_subject(root, rel)
            if abs_path is None:
                error = "Artifact no longer identifies a local project file"
            elif abs_path.is_file():
                present = True
                recomputed = sha256_file(abs_path)
        except (OSError, ValueError) as exc:
            error = str(exc)
        items.append({"path": rel, "recorded_digest": entry["digest"],
                      "recomputed_digest": recomputed, "present": present,
                      "read_error": error,
                      "matches": recomputed is not None and recomputed == entry["digest"]})
    return items


def base_report(schema: str, profile: str, naos_root: str, root: Path, status: str,
                summary: dict[str, int], findings: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    report = {
        "schema": schema,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "summary": summary,
        "findings": findings,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }
    report.update(extra)
    return report


def strict_json(text: str) -> Any:
    """Reject ambiguous duplicate members and non-JSON numeric constants."""
    def members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        raise ValueError("Non-JSON numeric constant")

    return json.loads(text, object_pairs_hook=members, parse_constant=invalid_constant)


def verify_envelope(path: Path, *, root_digest: str | None, artifact_count: int | None,
                    severity: str, inactive_report: dict[str, Any] | None = None,
                    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"envelope_supplied": False, "envelope_payload_validation": "not_supplied",
                              "signed": False, "signature_entries_present": False}
    findings: list[dict[str, Any]] = []

    def invalid(status: str, message: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        result["envelope_payload_validation"] = "invalid"
        findings.append(input_finding(status, message, severity))
        return result, findings

    try:
        env = strict_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if not path.is_symlink():
            return result, findings
        result["envelope_supplied"] = True
        return invalid("invalid_envelope", "Supplied envelope is an unreadable symbolic link.")
    except (OSError, ValueError):
        result["envelope_supplied"] = True
        return invalid("invalid_envelope", "Cannot read unambiguous UTF-8 envelope JSON.")
    result["envelope_supplied"] = True
    if not isinstance(env, dict):
        return invalid("invalid_envelope", "Envelope input must be an object.")
    if "schema" in env:
        schema = load_json(kit_root() / "schemas" / "naos" / "evidence_envelope.schema.json")
        if any(Draft202012Validator(schema).iter_errors(env)):
            return invalid("invalid_envelope", "Envelope report does not match the supported v1 schema.")
        if "envelope" in env and env["envelope"] is None:
            if (inactive_report is not None
                    and all(env.get(key) == value for key, value in inactive_report.items())
                    and not any(key in env for key in ("payload", "payloadType", "signatures"))
                    and all(env.get(key) is False for key in (
                        "signed", "signature_entries_present", "signature_validation_performed"))):
                result["envelope_payload_validation"] = "not_applicable"
                return result, findings
            return invalid("invalid_envelope", "No-payload envelope report does not match the current inactive attestation.")
    if not any(key in env for key in ("envelope", "payload", "payloadType", "signatures")):
        return invalid("invalid_envelope", "Input does not contain an envelope or payload.")
    record = env.get("envelope") if "envelope" in env else env
    if not isinstance(record, dict):
        return invalid("invalid_envelope", "Supplied envelope must contain a payload object.")
    signatures = record.get("signatures")
    if not isinstance(signatures, list):
        return invalid("invalid_signature_container", "Envelope signatures must be an array; no signature validation is performed.")
    result.update(signed=bool(signatures), signature_entries_present=bool(signatures))
    if (set(record) != {"payloadType", "payload", "signatures"}
            or record["payloadType"] != PAYLOAD_TYPE or not isinstance(record["payload"], str)
            or not all(isinstance(signature, dict) for signature in signatures)):
        return invalid("invalid_envelope_payload", "Supplied envelope requires the supported payload type, encoded payload and signature array.")
    try:
        encoded = record["payload"]
        decoded = base64.b64decode(encoded, validate=True)
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError("Noncanonical base64")
        payload = strict_json(decoded.decode("utf-8"))
    except (ValueError, UnicodeError):
        return invalid("invalid_envelope_payload", "Envelope payload must be strict base64 containing unambiguous UTF-8 JSON.")
    payload_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["schema", "manifest_root_digest", "artifact_count", "profile", "generated_at", "naos_root"],
        "properties": {
            "schema": {"const": "naos.evidence_payload.v1"},
            "manifest_root_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$", "minLength": 64, "maxLength": 64},
            "artifact_count": {"type": "integer", "minimum": 0},
            "profile": {"enum": ["quickstart", "lite", "standard", "assured"]},
            "generated_at": {"type": "string", "minLength": 20, "maxLength": 20,
                             "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
            "naos_root": {"type": "string", "minLength": 1},
        },
    }
    if (any(Draft202012Validator(payload_schema).iter_errors(payload))
            or type(payload.get("artifact_count")) is not int):
        return invalid("invalid_envelope_payload", "Envelope payload does not match the supported typed v1 payload schema.")
    try:
        # Validate the UTC syntax emitted by utc_now_text, including calendar
        # and clock bounds, without jsonschema's optional date-time extras.
        datetime.strptime(payload["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return invalid("invalid_envelope_payload", "Envelope payload generated_at must be a valid YYYY-MM-DDTHH:MM:SSZ UTC timestamp.")
    if root_digest is None or artifact_count is None:
        result["envelope_payload_validation"] = "unavailable"
        findings.append(input_finding("envelope_binding_unavailable", "Cannot bind the supplied envelope without a complete independently checked manifest.", severity))
    elif payload["manifest_root_digest"] != root_digest or payload["artifact_count"] != artifact_count:
        result["envelope_payload_validation"] = "mismatch"
        findings.append(input_finding("envelope_payload_mismatch", "Envelope payload root or artifact count differs from the independently checked current manifest.", severity))
    else:
        result["envelope_payload_validation"] = "valid"
    return result, findings


def emit(root: Path, naos_root: str, policy: dict[str, Any], profile: str) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    att, findings, validation = load_attestation(root, naos_root, policy, severity)
    dimensions = attestation_dimensions(att, validation)
    extra: dict[str, Any] = {"envelope": None, "identity_binding": git_identity(root), "signed": False,
                            "signature_entries_present": False, "signature_validation_performed": False,
                            "adopter_signing_required": False}
    if att is not None:
        findings.extend(coverage_findings(att, severity))
        if dimensions["scope_status"] not in {"disabled", "not_configured"}:
            pairs = [(item["path"], item["digest"]) for item in att["artifact_manifest"] if item["digest"]]
            root_digest = att.get("manifest_root_digest") or manifest_root_digest(pairs)
            payload = {"schema": "naos.evidence_payload.v1", "manifest_root_digest": root_digest,
                       "artifact_count": len(pairs), "profile": profile,
                       "generated_at": utc_now_text(), "naos_root": naos_root}
            payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            extra.update(payload=payload, envelope={"payloadType": PAYLOAD_TYPE,
                         "payload": base64.b64encode(payload_json.encode("utf-8")).decode("ascii"),
                         "signatures": []})
    summary = finding_counts(findings)
    # Emission prepares a payload; it performs neither digest nor root verification.
    if dimensions["scope_status"] not in {"disabled", "not_configured"}:
        dimensions["manifest_root_validation"] = "unavailable"
    status = status_from_counts(summary)
    if status == "pass" and dimensions["scope_status"] in {"empty", "disabled", "not_configured"}:
        status = dimensions["scope_status"]
    return base_report(ENVELOPE_SCHEMA, profile, naos_root, root, status, summary, findings, **dimensions, **extra)


def verify(root: Path, naos_root: str, policy: dict[str, Any], profile: str) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    att, findings, validation = load_attestation(root, naos_root, policy, severity)
    dimensions = attestation_dimensions(att, validation)
    extra: dict[str, Any] = {"tamper_evident": False, "signed": False,
                            "signature_entries_present": False, "signature_validation_performed": False,
                            "identity_binding": git_identity(root), "recorded_root": None, "recomputed_root": None}
    checked_count = None
    if att is not None:
        findings.extend(coverage_findings(att, severity))
        if dimensions["scope_status"] not in {"disabled", "not_configured"}:
            manifest = collect_manifest(root, att)
            checked = [item for item in manifest if item["recomputed_digest"] is not None]
            dimensions["artifacts_checked"] = len(checked)
            for item in manifest:
                if item["matches"]:
                    continue
                status = ("unreadable_artifact" if item["read_error"] else "missing_artifact" if not item["present"]
                          else "digest_unavailable" if item["recorded_digest"] is None else "tamper_detected")
                finding_name = "digest_mismatch" if status == "tamper_detected" else status
                findings.append({"id": f"evidence_signing.{finding_name}.{item['path']}", "severity": severity,
                                 "status": status, "path": item["path"],
                                 "message": f"Cannot verify covered artifact ({status}): {item['path']}."})
            if manifest:
                if all(item["matches"] for item in manifest):
                    dimensions["digest_validation"] = "valid"
                elif any(item["recorded_digest"] and item["recomputed_digest"] and not item["matches"] for item in manifest):
                    dimensions["digest_validation"] = "invalid"
                else:
                    dimensions["digest_validation"] = "unavailable"
            recomputed_root = manifest_root_digest([(i["path"], i["recomputed_digest"]) for i in checked])
            if len(checked) == len(manifest):
                checked_count = len(checked)
            recorded_root = att.get("manifest_root_digest")
            root_matches = recorded_root is not None and recomputed_root == recorded_root and len(checked) == len(manifest)
            dimensions["manifest_root_validation"] = ("not_recorded" if recorded_root is None else "valid" if root_matches else "invalid")
            if recorded_root is not None and not root_matches:
                findings.append({"id": "evidence_signing.root_mismatch", "severity": severity,
                                 "status": "tamper_detected", "message": "Recomputed manifest root does not match the recorded root."})
            extra.update(tamper_evident=root_matches and all(i["matches"] for i in manifest),
                         recorded_root=recorded_root, recomputed_root=recomputed_root)
    inactive_report = None
    if dimensions["input_validation"] == "valid" and dimensions["scope_status"] in {"disabled", "not_configured"}:
        inactive_report = {
            "profile": profile, "project_root": str(root), "naos_root": naos_root,
            "status": dimensions["scope_status"],
            **{key: dimensions[key] for key in ("scope_status", "attestation_status", "input_validation",
                                               "artifacts_declared", "digest_validation", "required_coverage")},
            "artifacts_checked": 0, "manifest_root_validation": "not_applicable",
        }
    envelope_result, envelope_findings = verify_envelope(
        envelope_path(root, naos_root, policy), root_digest=extra["recomputed_root"],
        artifact_count=checked_count, severity=severity, inactive_report=inactive_report,
    )
    extra.update(envelope_result)
    findings.extend(envelope_findings)
    if envelope_result["envelope_supplied"] and envelope_result["envelope_payload_validation"] != "valid":
        extra["tamper_evident"] = False
    summary = finding_counts(findings)
    return base_report(VERIFY_SCHEMA, profile, naos_root, root, verification_status(summary, dimensions),
                       summary, findings, **dimensions, **extra)


def output_overlaps_subjects(output: Path, root: Path, naos_root: str, policy: dict[str, Any]) -> bool:
    """Do not overwrite covered evidence, including a caller-selected output."""
    try:
        att = load_json(attestation_path(root, naos_root, policy))
    except (OSError, ValueError):
        return output.resolve() == attestation_path(root, naos_root, policy).resolve()
    if output.resolve() == attestation_path(root, naos_root, policy).resolve():
        return True
    entries = att.get("artifact_manifest") if isinstance(att, dict) else None
    if not isinstance(entries, list):
        return False
    return any(isinstance(item, dict) and isinstance(item.get("path"), str)
               and (root / item["path"]).resolve() == output.resolve() for item in entries)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit signable NAOS evidence envelopes or verify local evidence digests."
    )
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--mode", choices=["emit", "verify"], default=None)
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def resolve_mode(args: argparse.Namespace) -> str:
    if args.mode:
        return args.mode
    return "verify" if "verify" in " ".join(sys.argv[:1]).lower() else "emit"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = resolve_mode(args)
    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = emit(root, naos_root, policy, profile) if mode == "emit" else verify(root, naos_root, policy, profile)

    if args.output:
        output: Path | None = Path(args.output)
    elif mode == "emit":
        output = envelope_path(root, naos_root, policy) if (root / naos_root).is_dir() and not is_kit_repository(root, naos_root) else None
    else:
        output = report_output_path(root, naos_root, policy, "evidence_verification_report")
    if output is not None and output_overlaps_subjects(output, root, naos_root, policy):
        report["findings"].append(input_finding("output_is_subject",
            "Output would overwrite the attestation or a covered subject. Configure a separate output path before the next attestation, then regenerate the attestation.", "blocking"))
        report["summary"] = finding_counts(report["findings"])
        report["status"] = "blocked"
        output = None
    write_report(output, report)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if mode == "emit":
            print(
                f"Evidence Envelope: {report['status']} "
                f"(signature_entries_present={report.get('signature_entries_present')}; "
                "external_signing=optional; adopter_signing_required=False)"
            )
        else:
            print(
                f"Evidence Verify: tamper_evident={report.get('tamper_evident')} "
                f"signature_entries_present={report.get('signature_entries_present')} "
                f"envelope_signature_validated_by_naos={report.get('signature_validation_performed')} "
                f"status={report['status']}"
            )
        for item in report["findings"]:
            print(f"    [{item['severity']}] {item['status']}: {item['message']}")
    if report["input_validation"] == "invalid" or any(i["status"] == "output_is_subject" for i in report["findings"]):
        return 1
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
