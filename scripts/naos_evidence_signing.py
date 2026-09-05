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
          attestation report; report tamper_evident pass/fail, signature-entry presence, and
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

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

ENVELOPE_SCHEMA = "naos.evidence_envelope.v1"
VERIFY_SCHEMA = "naos.evidence_verification.v1"
PAYLOAD_TYPE = "application/vnd.naos.evidence+json"
LIMITATIONS = [
    "NAOS emits signable envelopes and recomputes local evidence digests; it does not sign, validate envelope signatures, hold keys, authenticate identities, or issue certificates.",
    "Tamper-evidence detects post-hoc edits to covered artifacts; it is not a signature or proof of authorship.",
    "The compatibility-named identity_binding field contains best-effort Git-reported HEAD metadata only; it is not identity authentication, authorization, or non-repudiation.",
    "The compatibility-named signed field reports only whether signature entries are present; NAOS does not validate them.",
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


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def manifest_root_digest(pairs: list[tuple[str, str]]) -> str:
    """Mirror naos_evidence_attestation.manifest_root_digest for cross-verification."""
    canonical = json.dumps(sorted(pairs), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def attestation_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    reports_dir = str((policy.get("paths") or {}).get("reports_dir") or "reports")
    filename = str((policy.get("paths") or {}).get("evidence_attestation_report") or "evidence_attestation.json")
    return root / naos_root / reports_dir / filename


def envelope_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    evidence_dir = str((policy.get("paths") or {}).get("evidence_dir") or "evidence")
    return root / naos_root / evidence_dir / "evidence_envelope.json"


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
    """Recompute on-disk digests for the artifacts the attestation report covers."""
    items: list[dict[str, Any]] = []
    for entry in attestation.get("artifact_manifest") or []:
        rel = str(entry.get("path") or "")
        if not rel:
            continue
        abs_path = root / rel
        recomputed = sha256_file(abs_path) if abs_path.is_file() else None
        items.append({
            "path": rel,
            "recorded_digest": entry.get("digest"),
            "recomputed_digest": recomputed,
            "present": abs_path.is_file(),
            "matches": bool(recomputed and recomputed == entry.get("digest")),
        })
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


def emit(root: Path, naos_root: str, policy: dict[str, Any], profile: str) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    att = load_json(attestation_path(root, naos_root, policy))
    if not att:
        findings.append({"id": "evidence_signing.missing_attestation", "severity": severity,
                         "status": "missing_attestation",
                         "message": "No evidence_attestation report found; run `naos evidence-attestation` first to build the manifest."})
        summary = finding_counts(findings)
        return base_report(ENVELOPE_SCHEMA, profile, naos_root, root, status_from_counts(summary), summary, findings,
                           envelope=None, identity_binding=git_identity(root), signed=False,
                           signature_entries_present=False, signature_validation_performed=False,
                           adopter_signing_required=False)
    pairs = [(str(i.get("path")), str(i.get("digest"))) for i in att.get("artifact_manifest") or [] if i.get("digest")]
    root_digest = att.get("manifest_root_digest") or manifest_root_digest(pairs)
    payload = {
        "schema": "naos.evidence_payload.v1",
        "manifest_root_digest": root_digest,
        "artifact_count": len(pairs),
        "profile": profile,
        "generated_at": utc_now_text(),
        "naos_root": naos_root,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_json.encode("utf-8")).decode("ascii"),
        "signatures": [],  # optionally filled by an external signer; NAOS never signs
    }
    summary = finding_counts(findings)
    return base_report(ENVELOPE_SCHEMA, profile, naos_root, root, status_from_counts(summary), summary, findings,
                       envelope=envelope, payload=payload, identity_binding=git_identity(root), signed=False,
                       signature_entries_present=False, signature_validation_performed=False,
                       adopter_signing_required=False)


def verify(root: Path, naos_root: str, policy: dict[str, Any], profile: str) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    att = load_json(attestation_path(root, naos_root, policy))
    if not att:
        findings.append({"id": "evidence_signing.missing_attestation", "severity": severity,
                         "status": "missing_attestation",
                         "message": "No evidence_attestation report found; nothing to verify."})
        summary = finding_counts(findings)
        return base_report(VERIFY_SCHEMA, profile, naos_root, root, status_from_counts(summary), summary, findings,
                           tamper_evident=False, signed=False, signature_entries_present=False,
                           signature_validation_performed=False, identity_binding=git_identity(root))
    manifest = collect_manifest(root, att)
    mismatches = [m for m in manifest if m["present"] and not m["matches"]]
    missing = [m for m in manifest if not m["present"]]
    for m in mismatches:
        findings.append({"id": f"evidence_signing.digest_mismatch.{m['path']}", "severity": severity,
                         "status": "tamper_detected",
                         "message": f"Artifact digest mismatch (possible post-hoc edit): {m['path']}.", "path": m["path"]})
    for m in missing:
        findings.append({"id": f"evidence_signing.missing_artifact.{m['path']}", "severity": "warning",
                         "status": "missing_artifact",
                         "message": f"Covered artifact is missing on disk: {m['path']}.", "path": m["path"]})
    recomputed_pairs = [(m["path"], m["recomputed_digest"]) for m in manifest if m["recomputed_digest"]]
    recomputed_root = manifest_root_digest(recomputed_pairs)
    recorded_root = att.get("manifest_root_digest")
    tamper_evident = bool(recorded_root) and recomputed_root == recorded_root and not mismatches
    if recorded_root and recomputed_root != recorded_root:
        findings.append({"id": "evidence_signing.root_mismatch", "severity": severity, "status": "tamper_detected",
                         "message": "Recomputed manifest root does not match the recorded tamper-evidence root."})
    env = load_json(envelope_path(root, naos_root, policy))
    envelope_record = env.get("envelope")
    raw_signatures = (
        envelope_record.get("signatures")
        if isinstance(envelope_record, dict)
        else env.get("signatures")
    )
    if raw_signatures is not None and not isinstance(raw_signatures, list):
        findings.append({
            "id": "evidence_signing.invalid_signature_container",
            "severity": severity,
            "status": "invalid_signature_container",
            "message": (
                "Envelope signatures must be an array; the malformed value is ignored for "
                "signature-entry presence and no signature validation is performed."
            ),
        })
        signature_entries_present = False
    else:
        signature_entries_present = bool(raw_signatures)
    summary = finding_counts(findings)
    return base_report(VERIFY_SCHEMA, profile, naos_root, root, status_from_counts(summary), summary, findings,
                       tamper_evident=tamper_evident, recomputed_root=recomputed_root, recorded_root=recorded_root,
                       artifacts_checked=len(manifest), signed=signature_entries_present,
                       signature_entries_present=signature_entries_present, signature_validation_performed=False,
                       identity_binding=git_identity(root))


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
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
