#!/usr/bin/env python3
"""Evaluate plan coherence across sequential/parallel task sets (QW4, governed autonomy).

Deterministic review input over file-first artifacts only:
- active task claims (NAOS_ROOT/task_claims.yaml),
- TASK_REGISTRY.yaml (declared tasks, status, dependencies, parallelizable),
- module-header Tasks: linkage (which source files implement which task), and
- PLANNING_BASELINES.yaml (versioned implementation-readiness evidence).

Checks:
- parallel_overlap: two concurrently active claims (distinct operator/session) whose
  tasks implement overlapping source files; elevated when a task declares
  parallelizable: false.
- dependency_not_ready: an active claim whose task declares dependencies that are not
  yet implemented/verified/done in the registry (working ahead of prerequisites).
- claim_unknown_task: an active claim for a task id absent from TASK_REGISTRY.
- planning_baseline_*: a project plan is missing, draft, stale, structurally
  invalid, incompletely linked, or lacks an attributable owner decision.

It is review evidence only. It does not authorize work, resolve conflicts, prove
ownership, sequence execution, or approve a plan. Human review remains required.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

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

import naos_module_header_traceability as mh  # noqa: E402
import naos_pre_implementation_alignment_review as pia  # noqa: E402
import naos_spec_pack_contract as spec_pack  # noqa: E402
from naos_task_lifecycle import extract_task_ids, is_task_delivered  # noqa: E402

SCHEMA = "naos.plan_coherence.v1"
PLANNING_BASELINES_SCHEMA = "naos.planning_baselines.v1"
PLANNING_BASELINES_FILENAME = "PLANNING_BASELINES.yaml"
PLANNING_BASELINES_SCHEMA_FILENAME = "planning_baselines.schema.json"
HUMAN_DECISION_SCHEMA_FILENAME = "human_decision_record.schema.json"
PLANNING_DECISION_DIGEST_KIND = "planning_baseline_projection_sha256_v1"
TERMINAL_TASK_STATES = {"completed", "done", "verified", "deferred", "cancelled", "canceled", "absorbed", "superseded"}
PLACEHOLDER_PREFIXES = ("[ADAPT", "[FILL", "TODO", "TBD")
TASK_REGISTRY_RUNTIME_FIELDS = {
    "status",
    "lifecycle_state",
    "delivery_state",
    "verification_state",
    "claimed_by",
    "started_at",
    "delivered_at",
    "verified_at",
    "completed_at",
    "delivery_evidence",
    "verification_evidence",
    "implementation_evidence",
}
EVIDENCE_REPORT_SCHEMAS = {
    "spec_pack_contract": "spec_pack_contract.schema.json",
    "pre_implementation_alignment_review": "pre_implementation_alignment_review.schema.json",
}
LIMITATIONS = [
    "Deterministic review over declared claims, registry, module headers, planning-baseline declarations, referenced local reports, and local file digests only.",
    "Task->file linkage depends on module-header Tasks: annotations; unannotated files are invisible.",
    "Overlap is a coordination signal, not a proof of conflict or of safe parallel work.",
    "Diff-base implementation-scope evidence depends on local Git changed-file output and optional alignment path declarations.",
    "Parallel-lane opportunity review is advisory and does not declare lanes or activate handoff.",
    "A structurally attributable planning decision does not prove real-world identity, role authority, requirements quality, architecture quality, or implementation correctness.",
    "Referenced reports are digest- and schema-checked, bound to exact declared inputs, and their spec-pack/alignment prerequisites are revalidated live; independent execution and cryptographic signer identity remain outside this control.",
]
NOT_CLAIMED = [
    "work authorization",
    "conflict resolution",
    "ownership proof",
    "execution sequencing",
    "plan approval",
    "completion proof",
    "semantic drift proof",
    "lane declaration",
    "handoff requirement from suggestions",
    "requirements completeness proof",
    "design approval",
    "implementation approval",
    "task closure",
    "merge or release authority",
    "real-world role or identity proof",
]


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def finding(severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    item = {"id": f"plan_coherence.{status}", "severity": severity, "status": status, "message": message}
    item.update(extra)
    return item


def active_claims(root: Path, naos_root: str, policy: dict[str, Any]) -> list[dict[str, Any]]:
    filename = str((policy.get("paths") or {}).get("task_claims_file") or "task_claims.yaml")
    data = load_yaml(root / naos_root / filename)
    return [c for c in (data.get("claims") or []) if isinstance(c, dict) and c.get("status") == "active"]


def load_registry(root: Path, naos_root: str) -> dict[str, dict[str, Any]]:
    for candidate in (root / naos_root / "TASK_REGISTRY.yaml", root / "TASK_REGISTRY.yaml"):
        if candidate.exists():
            data = load_yaml(candidate)
            tasks = data.get("tasks") if isinstance(data.get("tasks"), list) else []
            return {str(t.get("id")): t for t in tasks if isinstance(t, dict) and t.get("id")}
    return {}


def planning_baselines_path(root: Path, naos_root: str) -> tuple[Path, str]:
    project_path = root / naos_root / PLANNING_BASELINES_FILENAME
    if project_path.exists() or not is_kit_repository(root, naos_root):
        return project_path, "project"
    return root / "templates" / "structural-seeds" / "naos" / PLANNING_BASELINES_FILENAME, "kit_template"


def schema_path(root: Path, filename: str) -> Path:
    project_schema = root / "schemas" / "naos" / filename
    if project_schema.is_file():
        return project_schema
    return SCRIPT_DIR.parent / "schemas" / "naos" / filename


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.upper().startswith(tuple(item.upper() for item in PLACEHOLDER_PREFIXES))


def relative_regular_file(root: Path, raw_path: Any) -> tuple[Path | None, str | None]:
    value = str(raw_path or "").strip()
    if not value:
        return None, "path is missing"
    candidate = Path(value)
    if candidate.is_absolute():
        return None, "absolute paths are not allowed"
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None, "path escapes the project root"
    if not resolved.is_file() or resolved.is_symlink():
        return None, "path is not a regular project file"
    return resolved, None


def declared_project_path(
    root: Path,
    raw_path: Any,
    *,
    kind: str,
) -> tuple[Path | None, str | None]:
    """Resolve a report-declared project path without allowing root escape or symlinks."""
    value = str(raw_path or "").strip()
    if not value:
        return None, "path is missing"
    root_resolved = root.resolve()
    declared = Path(value)
    if declared.is_absolute():
        lexical_relative: Path | None = None
        for base in (root, root_resolved):
            try:
                lexical_relative = declared.relative_to(base)
                break
            except ValueError:
                continue
        if lexical_relative is None:
            return None, "path escapes the project root"
    else:
        lexical_relative = declared
    if any(part in {"", ".", ".."} for part in lexical_relative.parts):
        return None, "path is not a safe project-relative path"
    cursor = root_resolved
    for part in lexical_relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return None, "symlink paths are not allowed"
    try:
        resolved = (root_resolved / lexical_relative).resolve(strict=True)
        resolved.relative_to(root_resolved)
    except FileNotFoundError:
        return None, "path does not exist"
    except ValueError:
        return None, "path escapes the project root"
    if kind == "file" and not resolved.is_file():
        return None, "path is not a regular project file"
    if kind == "directory" and not resolved.is_dir():
        return None, "path is not a project directory"
    return resolved, None


def is_utc_timestamp(value: Any) -> bool:
    text = str(value or "").strip()
    if is_placeholder(text) or not text.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def task_registry_planning_projection(document: Any) -> Any:
    """Return stable plan fields while excluding routine execution-state churn."""
    if isinstance(document, list):
        return [
            {key: value for key, value in task.items() if key not in TASK_REGISTRY_RUNTIME_FIELDS}
            if isinstance(task, dict)
            else task
            for task in document
        ]
    if not isinstance(document, dict):
        raise ValueError("TASK_REGISTRY must be a mapping or task list")
    projection = {key: value for key, value in document.items() if key != "last_updated"}
    tasks = projection.get("tasks")
    if isinstance(tasks, list):
        projection["tasks"] = [
            {key: value for key, value in task.items() if key not in TASK_REGISTRY_RUNTIME_FIELDS}
            if isinstance(task, dict)
            else task
            for task in tasks
        ]
    summary = projection.get("requirements_summary")
    if isinstance(summary, dict):
        projection["requirements_summary"] = {
            key: value for key, value in summary.items() if key != "status_breakdown"
        }
    return projection


def task_registry_planning_sha256(path: Path) -> str:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    projection = task_registry_planning_projection(document)
    payload = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def planning_baseline_decision_sha256(baseline: dict[str, Any]) -> str:
    """Bind an attributable decision to the exact versioned baseline projection."""
    payload = json.dumps(
        baseline,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def planning_digest_candidates(root: Path, profile: str, baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """Expose copyable current digests without mutating a draft ledger."""
    candidates: list[dict[str, Any]] = []
    bindings = baseline.get("source_bindings") if isinstance(baseline.get("source_bindings"), dict) else {}
    for name in ["requirements", "architecture", "task_registry", "alignment"]:
        binding = bindings.get(name) if isinstance(bindings.get(name), dict) else {}
        required = name != "architecture" or profile in {"standard", "assured"}
        item = {
            "kind": "source",
            "name": name,
            "path": str(binding.get("path") or ""),
            "digest_kind": binding.get("digest_kind"),
            "required_by_profile": required,
            "sha256": None,
            "status": "not_applicable" if not required else "unavailable",
        }
        if required:
            path, error = relative_regular_file(root, binding.get("path"))
            if path is not None and error is None:
                try:
                    item["sha256"] = task_registry_planning_sha256(path) if name == "task_registry" else file_sha256(path)
                    item["status"] = "available"
                except Exception as exc:
                    item["error"] = str(exc)
            elif error:
                item["error"] = error
        candidates.append(item)
    refs = baseline.get("evidence_refs") if isinstance(baseline.get("evidence_refs"), dict) else {}
    for name in ["spec_pack_contract", "pre_implementation_alignment_review"]:
        declaration = refs.get(name) if isinstance(refs.get(name), dict) else {}
        item = {
            "kind": "evidence",
            "name": name,
            "path": str(declaration.get("path") or ""),
            "digest_kind": declaration.get("digest_kind"),
            "required_by_profile": True,
            "sha256": None,
            "status": "unavailable",
        }
        path, error = relative_regular_file(root, declaration.get("path"))
        if path is not None and error is None:
            item["sha256"] = file_sha256(path)
            item["status"] = "available"
        elif error:
            item["error"] = error
        candidates.append(item)
    candidates.append(
        {
            "kind": "decision_subject",
            "name": "decision_subject",
            "path": str(baseline.get("decision_ref") or ""),
            "digest_kind": PLANNING_DECISION_DIGEST_KIND,
            "required_by_profile": True,
            "sha256": planning_baseline_decision_sha256(baseline),
            "status": "available",
        }
    )
    return candidates


def planning_finding(severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return finding(
        severity,
        status,
        message,
        category="implementation_readiness_baseline",
        human_review_required=True,
        **extra,
    )


def validate_planning_ledger_schema(root: Path, ledger: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    path = schema_path(root, PLANNING_BASELINES_SCHEMA_FILENAME)
    if not path.is_file():
        return [planning_finding(severity, "planning_baseline_schema_missing", f"Planning-baseline schema is missing: {path}")]
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [planning_finding(severity, "planning_baseline_schema_invalid", f"Planning-baseline schema could not be loaded: {exc}")]
    errors = sorted(Draft202012Validator(schema).iter_errors(ledger), key=lambda item: list(item.absolute_path))
    return [
        planning_finding(
            severity,
            "planning_baseline_schema_invalid",
            error.message,
            schema_path="/".join(str(item) for item in error.absolute_path),
        )
        for error in errors
    ]


def validate_baseline_lineage(baselines: list[dict[str, Any]], current_id: Any, severity: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    duplicate_ids: list[str] = []
    for baseline in baselines:
        baseline_id = str(baseline.get("baseline_id") or "")
        if baseline_id in by_id:
            duplicate_ids.append(baseline_id)
        elif baseline_id:
            by_id[baseline_id] = baseline
    if duplicate_ids:
        findings.append(planning_finding(severity, "planning_baseline_duplicate_id", "Planning baseline ids must be unique.", baseline_ids=sorted(set(duplicate_ids))))

    current = by_id.get(str(current_id or ""))
    if not current:
        findings.append(planning_finding(severity, "planning_baseline_current_missing", "current_baseline_id does not resolve to one baseline record.", current_baseline_id=current_id))
    elif current.get("state") == "superseded":
        findings.append(planning_finding(severity, "planning_baseline_current_superseded", "The current planning baseline cannot be superseded.", current_baseline_id=current_id))

    inbound: dict[str, list[str]] = {}
    edges: dict[str, str] = {}
    for baseline_id, baseline in by_id.items():
        supersedes = baseline.get("supersedes")
        if not supersedes:
            continue
        supersedes = str(supersedes)
        edges[baseline_id] = supersedes
        inbound.setdefault(supersedes, []).append(baseline_id)
        previous = by_id.get(supersedes)
        if previous is None:
            findings.append(planning_finding(severity, "planning_baseline_supersedes_missing", f"{baseline_id} supersedes an unknown baseline.", baseline_id=baseline_id, supersedes=supersedes))
            continue
        if baseline_id == supersedes:
            findings.append(planning_finding(severity, "planning_baseline_self_supersession", f"{baseline_id} cannot supersede itself.", baseline_id=baseline_id))
        if int(baseline.get("version") or 0) <= int(previous.get("version") or 0):
            findings.append(planning_finding(severity, "planning_baseline_version_not_monotonic", f"{baseline_id} must have a greater version than {supersedes}.", baseline_id=baseline_id, supersedes=supersedes))
        if baseline.get("mode") != previous.get("mode"):
            findings.append(planning_finding(severity, "planning_baseline_mode_changed", f"{baseline_id} changes the greenfield/brownfield mode of its lineage.", baseline_id=baseline_id, supersedes=supersedes))

    for baseline_id, baseline in by_id.items():
        if baseline_id == str(current_id or ""):
            continue
        if baseline.get("state") != "superseded":
            findings.append(planning_finding(severity, "planning_baseline_multiple_current", "Every non-current baseline must be marked superseded.", baseline_id=baseline_id, state=baseline.get("state")))
        if baseline_id not in inbound:
            findings.append(planning_finding(severity, "planning_baseline_superseded_without_successor", "A superseded baseline must be named by a successor record.", baseline_id=baseline_id))

    for start in edges:
        seen: set[str] = set()
        cursor = start
        while cursor in edges:
            if cursor in seen:
                findings.append(planning_finding(severity, "planning_baseline_supersession_cycle", "Planning baseline supersession contains a cycle.", baseline_id=start))
                break
            seen.add(cursor)
            cursor = edges[cursor]

    return findings, {
        "baseline_count": len(baselines),
        "current_baseline_id": current_id,
        "duplicate_ids": sorted(set(duplicate_ids)),
        "valid": not findings,
    }


def check_source_bindings(root: Path, profile: str, baseline: dict[str, Any], severity: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    stale = False
    bindings = baseline.get("source_bindings") if isinstance(baseline.get("source_bindings"), dict) else {}
    architecture_required = profile in {"standard", "assured"}
    expected_arch_applicability = "required_by_profile" if architecture_required else "not_applicable_by_profile"

    for name in ["requirements", "architecture", "task_registry", "alignment"]:
        binding = bindings.get(name) if isinstance(bindings.get(name), dict) else {}
        path_text = str(binding.get("path") or "")
        expected_digest = binding.get("sha256")
        digest_kind = binding.get("digest_kind")
        expected_digest_kind = "task_registry_planning_projection_sha256_v1" if name == "task_registry" else "file_sha256"
        applicability = binding.get("applicability") if name == "architecture" else "required_by_profile"
        required = name != "architecture" or architecture_required
        check = {
            "source": name,
            "path": path_text,
            "applicability": applicability,
            "required": required,
            "expected_sha256": expected_digest,
            "actual_sha256": None,
            "digest_kind": digest_kind,
            "status": "not_applicable" if not required else "unchecked",
        }
        if digest_kind != expected_digest_kind:
            findings.append(planning_finding(severity, "planning_baseline_digest_kind_mismatch", "Planning source uses an unsupported digest contract.", source=name, expected=expected_digest_kind, actual=digest_kind))
            check["status"] = "digest_kind_mismatch"
        if name == "architecture" and applicability != expected_arch_applicability:
            findings.append(planning_finding(severity, "planning_baseline_profile_applicability_mismatch", "Architecture applicability does not match the selected profile.", source=name, expected=expected_arch_applicability, actual=applicability))
            check["status"] = "applicability_mismatch"
        if not required:
            if expected_digest is not None:
                findings.append(planning_finding(severity, "planning_baseline_not_applicable_digest_present", "Lite must not bind or synthesize an architecture digest.", source=name, path=path_text))
                check["status"] = "unexpected_digest"
            checks.append(check)
            continue
        path, error = relative_regular_file(root, path_text)
        if error or path is None:
            findings.append(planning_finding(severity, "planning_baseline_source_missing", f"Required planning-baseline source is unavailable: {path_text} ({error}).", source=name, path=path_text))
            check["status"] = "missing"
            checks.append(check)
            continue
        try:
            actual_digest = task_registry_planning_sha256(path) if name == "task_registry" else file_sha256(path)
        except Exception as exc:
            findings.append(planning_finding(severity, "planning_baseline_source_invalid", f"Required planning-baseline source could not be normalized: {path_text} ({exc}).", source=name, path=path_text))
            check["status"] = "invalid"
            checks.append(check)
            continue
        check["actual_sha256"] = actual_digest
        if expected_digest != actual_digest:
            stale = True
            findings.append(planning_finding(severity, "planning_baseline_stale", f"Planning-baseline digest no longer matches {path_text}.", source=name, path=path_text, expected_sha256=expected_digest, actual_sha256=actual_digest))
            check["status"] = "stale"
        else:
            check["status"] = "current"
        checks.append(check)
    return findings, checks, stale


def check_evidence_refs(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    baseline: dict[str, Any],
    severity: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    stale = False
    refs = baseline.get("evidence_refs") if isinstance(baseline.get("evidence_refs"), dict) else {}
    expected_required = {
        "spec_pack_contract": True,
        "pre_implementation_alignment_review": True,
    }
    for name, should_require in expected_required.items():
        declaration = refs.get(name) if isinstance(refs.get(name), dict) else {}
        path_text = str(declaration.get("path") or "")
        expected_digest = declaration.get("sha256")
        digest_kind = declaration.get("digest_kind")
        declared_required = declaration.get("required_by_profile") is True
        check = {
            "evidence": name,
            "path": path_text,
            "required_by_profile": should_require,
            "declared_required_by_profile": declared_required,
            "status": "not_applicable" if not should_require else "unchecked",
            "report_status": None,
            "expected_sha256": expected_digest,
            "actual_sha256": None,
            "digest_kind": digest_kind,
            "source_identity_status": "unchecked",
            "live_validation_status": None,
        }
        if digest_kind != "file_sha256":
            findings.append(planning_finding(severity, "planning_baseline_evidence_digest_kind_mismatch", f"{name} uses an unsupported digest contract.", evidence=name, expected="file_sha256", actual=digest_kind))
            check["status"] = "digest_kind_mismatch"
        if declared_required != should_require:
            findings.append(planning_finding(severity, "planning_baseline_evidence_applicability_mismatch", f"{name} applicability does not match profile {profile}.", evidence=name, expected=should_require, actual=declared_required))
            check["status"] = "applicability_mismatch"
        if not should_require:
            checks.append(check)
            continue
        path, error = relative_regular_file(root, path_text)
        if error or path is None:
            findings.append(planning_finding(severity, "planning_baseline_evidence_missing", f"Required planning evidence is unavailable: {path_text} ({error}).", evidence=name, path=path_text))
            check["status"] = "missing"
            checks.append(check)
            continue
        actual_digest = file_sha256(path)
        check["actual_sha256"] = actual_digest
        digest_current = expected_digest == actual_digest
        if not digest_current:
            stale = True
            findings.append(planning_finding(severity, "planning_baseline_evidence_stale", f"Planning-evidence digest no longer matches {path_text}.", evidence=name, path=path_text, expected_sha256=expected_digest, actual_sha256=actual_digest))
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(planning_finding(severity, "planning_baseline_evidence_invalid", f"Planning evidence could not be parsed: {path_text} ({exc}).", evidence=name, path=path_text))
            check["status"] = "invalid"
            checks.append(check)
            continue
        report_schema_path = schema_path(root, EVIDENCE_REPORT_SCHEMAS[name])
        try:
            report_schema = json.loads(report_schema_path.read_text(encoding="utf-8"))
            report_schema_errors = sorted(
                Draft202012Validator(report_schema).iter_errors(report),
                key=lambda item: list(item.absolute_path),
            )
        except Exception as exc:
            report_schema_errors = [exc]
        if report_schema_errors:
            findings.append(planning_finding(severity, "planning_baseline_evidence_schema_invalid", f"{name} does not satisfy its report schema.", evidence=name, path=path_text, errors=[str(item) for item in report_schema_errors]))
            check["status"] = "invalid"
            checks.append(check)
            continue
        report_status = report.get("status")
        report_profile = report.get("profile")
        check["report_status"] = report_status
        check["report_profile"] = report_profile
        valid = report_profile == profile
        if name == "spec_pack_contract":
            valid = valid and report_status == "pass" and report.get("mode") == "filled"
            check["mode"] = report.get("mode")
            source_bindings = baseline.get("source_bindings") if isinstance(baseline.get("source_bindings"), dict) else {}
            requirements_binding = source_bindings.get("requirements") if isinstance(source_bindings.get("requirements"), dict) else {}
            architecture_binding = source_bindings.get("architecture") if isinstance(source_bindings.get("architecture"), dict) else {}
            requirements_path, requirements_error = relative_regular_file(root, requirements_binding.get("path"))
            specs_root, specs_root_error = declared_project_path(root, report.get("specs_root"), kind="directory")
            manifest_path, manifest_error = declared_project_path(root, report.get("manifest"), kind="file")
            identity_failures: list[str] = []
            if requirements_error or requirements_path is None:
                identity_failures.append("requirements_binding_unavailable")
            if specs_root_error or specs_root is None:
                identity_failures.append("report_specs_root_unavailable")
            if manifest_error or manifest_path is None:
                identity_failures.append("report_manifest_unavailable")
            if requirements_path is not None and specs_root is not None:
                if requirements_path != specs_root / "03-requirements.md":
                    identity_failures.append("requirements_not_bound_to_report_03_spec")
            if specs_root is not None and manifest_path is not None and manifest_path.parent != specs_root:
                identity_failures.append("manifest_not_bound_to_report_specs_root")
            if profile in {"standard", "assured"}:
                architecture_path, architecture_error = relative_regular_file(root, architecture_binding.get("path"))
                if architecture_error or architecture_path is None:
                    identity_failures.append("architecture_binding_unavailable")
                elif specs_root is not None and architecture_path != specs_root / "04-architecture.md":
                    identity_failures.append("architecture_not_bound_to_report_04_spec")
            if identity_failures:
                valid = False
                check["source_identity_status"] = "mismatch"
                findings.append(
                    planning_finding(
                        severity,
                        "planning_baseline_evidence_source_mismatch",
                        "Spec-pack evidence is not bound to the exact declared requirements, architecture, specs root, and manifest.",
                        evidence=name,
                        path=path_text,
                        failures=identity_failures,
                    )
                )
            else:
                check["source_identity_status"] = "matched"
                assert specs_root is not None and manifest_path is not None
                live_report = spec_pack.validate_contract(
                    root=root,
                    specs_root=specs_root,
                    manifest_path=manifest_path,
                    profile=profile,
                    policy=policy,
                    mode="filled",
                )
                check["live_validation_status"] = live_report.get("status")
                if live_report.get("status") != "pass" or live_report.get("mode") != "filled":
                    valid = False
                    findings.append(
                        planning_finding(
                            severity,
                            "planning_baseline_evidence_live_not_ready",
                            "Current spec-pack sources do not reproduce the required filled passing posture.",
                            evidence=name,
                            path=path_text,
                            live_status=live_report.get("status"),
                            live_findings=(live_report.get("findings") or [])[:10],
                        )
                    )
        elif name == "pre_implementation_alignment_review":
            valid = valid and report_status == "ready" and report.get("alignment_valid") is True
            source_bindings = baseline.get("source_bindings") if isinstance(baseline.get("source_bindings"), dict) else {}
            alignment_binding = source_bindings.get("alignment") if isinstance(source_bindings.get("alignment"), dict) else {}
            alignment_path, alignment_error = relative_regular_file(root, alignment_binding.get("path"))
            report_alignment_path, report_alignment_error = declared_project_path(root, report.get("alignment_path"), kind="file")
            if (
                alignment_error
                or alignment_path is None
                or report_alignment_error
                or report_alignment_path is None
                or alignment_path != report_alignment_path
            ):
                valid = False
                check["source_identity_status"] = "mismatch"
                findings.append(
                    planning_finding(
                        severity,
                        "planning_baseline_evidence_source_mismatch",
                        "Pre-implementation alignment evidence is not bound to the exact declared alignment artifact.",
                        evidence=name,
                        path=path_text,
                        alignment_path=alignment_binding.get("path"),
                        report_alignment_path=report.get("alignment_path"),
                    )
                )
            else:
                check["source_identity_status"] = "matched"
                live_report = pia.build_report(
                    root,
                    naos_root,
                    profile,
                    policy,
                    explicit_input=str(alignment_path),
                )
                check["live_validation_status"] = live_report.get("status")
                check["live_mode"] = live_report.get("mode")
                if live_report.get("status") != "ready" or live_report.get("mode") != baseline.get("mode"):
                    valid = False
                    findings.append(
                        planning_finding(
                            severity,
                            "planning_baseline_evidence_live_not_ready",
                            "Current pre-implementation alignment does not reproduce the required ready posture and baseline mode.",
                            evidence=name,
                            path=path_text,
                            live_status=live_report.get("status"),
                            live_mode=live_report.get("mode"),
                            baseline_mode=baseline.get("mode"),
                            live_findings=(live_report.get("findings") or [])[:10],
                        )
                    )
        else:
            valid = valid and report_status == "pass"
        if not valid:
            findings.append(planning_finding(severity, "planning_baseline_evidence_not_ready", f"{name} does not contain the required current-profile passing posture.", evidence=name, path=path_text, report_status=report_status, report_profile=report_profile))
            check["status"] = "not_ready"
        elif not digest_current:
            check["status"] = "stale"
        else:
            check["status"] = "ready"
        checks.append(check)
    return findings, checks, stale


def check_decision(root: Path, baseline: dict[str, Any], severity: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    decision_ref = baseline.get("decision_ref")
    posture: dict[str, Any] = {"path": decision_ref, "status": "missing", "decision_id": None, "decided_by": None}
    path, error = relative_regular_file(root, decision_ref)
    if error or path is None:
        findings.append(planning_finding(severity, "planning_baseline_decision_missing", f"Attributable planning-baseline decision is unavailable: {decision_ref} ({error}).", decision_ref=decision_ref))
        return findings, posture
    try:
        record = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        findings.append(planning_finding(severity, "planning_baseline_decision_invalid", f"Planning-baseline decision could not be parsed: {exc}.", decision_ref=decision_ref))
        posture["status"] = "invalid"
        return findings, posture
    decision_schema_path = schema_path(root, HUMAN_DECISION_SCHEMA_FILENAME)
    try:
        decision_schema = json.loads(decision_schema_path.read_text(encoding="utf-8"))
        schema_errors = list(Draft202012Validator(decision_schema).iter_errors(record))
    except Exception as exc:
        schema_errors = [exc]
    if schema_errors:
        findings.append(planning_finding(severity, "planning_baseline_decision_invalid", "Planning-baseline decision does not satisfy the human-decision schema.", decision_ref=decision_ref, errors=[str(item) for item in schema_errors]))
        posture["status"] = "invalid"
        return findings, posture

    baseline_id = str(baseline.get("baseline_id") or "")
    owner = str(baseline.get("owner") or "")
    subject_refs = {str(item) for item in record.get("subject_refs") or []}
    evidence_refs = {str(item) for item in record.get("evidence_refs") or []}
    declared_evidence = {
        str(item.get("path"))
        for item in (baseline.get("evidence_refs") or {}).values()
        if isinstance(item, dict) and item.get("required_by_profile") is True
    }
    declared_sources = {
        str(item.get("path"))
        for item in (baseline.get("source_bindings") or {}).values()
        if isinstance(item, dict) and item.get("sha256") is not None
    }
    failures: list[str] = []
    if is_placeholder(owner):
        failures.append("baseline_owner_missing_or_placeholder")
    if record.get("decision_type") != "planning_baseline":
        failures.append("decision_type_not_planning_baseline")
    if record.get("outcome") != "approved":
        failures.append("decision_outcome_not_approved")
    if baseline_id not in subject_refs:
        failures.append("baseline_id_not_in_subject_refs")
    if is_placeholder(record.get("decided_by")) or str(record.get("decided_by")) != owner:
        failures.append("decided_by_does_not_match_baseline_owner")
    if not is_utc_timestamp(record.get("decided_at")):
        failures.append("decided_at_not_valid_utc_timestamp")
    if is_placeholder(record.get("rationale")):
        failures.append("rationale_missing_or_placeholder")
    if is_placeholder(record.get("authority_scope")):
        failures.append("authority_scope_missing_or_placeholder")
    subject_digest = record.get("subject_digest") if isinstance(record.get("subject_digest"), dict) else {}
    expected_subject_digest = planning_baseline_decision_sha256(baseline)
    if subject_digest.get("digest_kind") != PLANNING_DECISION_DIGEST_KIND:
        failures.append("subject_digest_kind_invalid")
    if subject_digest.get("sha256") != expected_subject_digest:
        failures.append("subject_digest_does_not_match_baseline")
    missing_evidence = sorted((declared_evidence | declared_sources) - evidence_refs)
    if missing_evidence:
        failures.append("declared_planning_evidence_not_in_decision")
    if failures:
        findings.append(planning_finding(severity, "planning_baseline_decision_not_attributable", "Planning-baseline decision does not satisfy the bounded attribution contract.", decision_ref=decision_ref, failures=failures, missing_evidence_refs=missing_evidence))
        posture["status"] = "not_attributable"
    else:
        posture["status"] = "structurally_attributable"
    posture.update({
        "decision_id": record.get("decision_id"),
        "decided_by": record.get("decided_by"),
        "outcome": record.get("outcome"),
        "subject_digest_kind": subject_digest.get("digest_kind"),
        "subject_digest_sha256": subject_digest.get("sha256"),
        "expected_subject_digest_sha256": expected_subject_digest,
        "real_world_authority_proven": False,
    })
    return findings, posture


def check_task_coverage(registry: dict[str, dict[str, Any]], baseline: dict[str, Any], severity: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    relevant = {
        task_id
        for task_id, task in registry.items()
        if str(task.get("lifecycle_state") or task.get("status") or "planned").lower() not in TERMINAL_TASK_STATES
    }
    vertical = [str(item) for item in baseline.get("vertical_slices") or []]
    foundations = [item for item in baseline.get("horizontal_foundations") or [] if isinstance(item, dict)]
    horizontal = [str(item.get("task_id") or "") for item in foundations]
    declared = vertical + horizontal
    duplicates = sorted({task_id for task_id in declared if declared.count(task_id) > 1})
    unknown = sorted(set(declared) - set(registry))
    uncovered = sorted(relevant - set(declared))
    if not registry:
        findings.append(planning_finding(severity, "planning_baseline_no_delivery_tasks", "An implementation-ready baseline requires at least one declared delivery task in TASK_REGISTRY."))
    if not vertical:
        findings.append(planning_finding(severity, "planning_baseline_vertical_slice_missing", "Hybrid planning requires at least one declared vertical delivery slice before implementation readiness."))
    if duplicates:
        findings.append(planning_finding(severity, "planning_baseline_duplicate_task_coverage", "Tasks must appear exactly once across vertical slices and horizontal foundations.", task_ids=duplicates))
    if unknown:
        findings.append(planning_finding(severity, "planning_baseline_unknown_tasks", "Planning baseline references tasks absent from TASK_REGISTRY.", task_ids=unknown))
    if uncovered:
        findings.append(planning_finding(severity, "planning_baseline_uncovered_tasks", "Every non-terminal registry task must be represented by the implementation-ready plan.", task_ids=uncovered))
    vertical_set = set(vertical)
    for item in foundations:
        task_id = str(item.get("task_id") or "")
        consumer = str(item.get("consuming_vertical_slice_task_id") or "")
        if consumer not in vertical_set:
            findings.append(planning_finding(severity, "planning_baseline_foundation_consumer_missing", "A horizontal foundation must name a declared consuming vertical slice.", task_id=task_id, consuming_vertical_slice_task_id=consumer))
        if consumer == task_id:
            findings.append(planning_finding(severity, "planning_baseline_foundation_self_consumer", "A horizontal foundation cannot consume itself.", task_id=task_id))
        if is_placeholder(item.get("changed_result")):
            findings.append(planning_finding(severity, "planning_baseline_foundation_changed_result_missing", "A horizontal foundation must name the consumed result it changes.", task_id=task_id))
    return findings, {
        "registry_non_terminal_tasks": sorted(relevant),
        "vertical_slice_tasks": vertical,
        "horizontal_foundation_tasks": horizontal,
        "uncovered_tasks": uncovered,
        "unknown_tasks": unknown,
        "duplicate_tasks": duplicates,
        "complete": not findings,
    }


def implementation_readiness_review(root: Path, naos_root: str, policy: dict[str, Any], profile: str, registry: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    ledger_path, source = planning_baselines_path(root, naos_root)
    base = {
        "status": "not_applicable" if profile == "quickstart" else "not_configured",
        "profile": profile,
        "ledger_path": str(ledger_path),
        "ledger_source": source,
        "current_baseline_id": None,
        "current_baseline_version": None,
        "state": None,
        "mode": None,
        "planning_model": None,
        "architecture_applicability": "not_applicable_by_profile" if profile in {"quickstart", "lite"} else "required_by_profile",
        "source_bindings": [],
        "digest_candidates": [],
        "evidence_checks": [],
        "decision": {"status": "not_checked"},
        "task_coverage": {"complete": False},
        "lineage": {"valid": False},
        "does_not_authorize": ["implementation", "task closure", "merge", "release", "publication"],
    }
    if profile == "quickstart":
        return base, []
    if not ledger_path.is_file():
        return base, [planning_finding(severity, "planning_baseline_missing", f"Planning-baseline ledger is missing: {ledger_path}")]
    try:
        ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        base["status"] = "review_required"
        return base, [planning_finding(severity, "planning_baseline_invalid", f"Planning-baseline ledger could not be parsed: {exc}")]
    if not isinstance(ledger, dict):
        base["status"] = "review_required"
        return base, [planning_finding(severity, "planning_baseline_invalid", "Planning-baseline ledger must be a mapping.")]
    schema_findings = validate_planning_ledger_schema(root, ledger, severity)
    baselines = [item for item in ledger.get("baselines") or [] if isinstance(item, dict)]
    current_id = ledger.get("current_baseline_id")
    lineage_findings, lineage = validate_baseline_lineage(baselines, current_id, severity)
    findings = schema_findings + lineage_findings
    current = next((item for item in baselines if item.get("baseline_id") == current_id), None)
    base["current_baseline_id"] = current_id
    base["lineage"] = lineage
    if current is None:
        base["status"] = "review_required"
        return base, findings
    base.update({
        "current_baseline_version": current.get("version"),
        "state": current.get("state"),
        "mode": current.get("mode"),
        "planning_model": current.get("planning_model"),
        "digest_candidates": planning_digest_candidates(root, profile, current),
    })
    if schema_findings or lineage_findings:
        base["status"] = "review_required"
        return base, findings
    if current.get("state") in {"draft", "discovery"}:
        base["status"] = "draft_or_discovery"
        findings.append(planning_finding(severity, "planning_baseline_not_implementation_ready", "Draft and discovery planning may continue, but the current baseline is not implementation-ready.", current_baseline_id=current_id, state=current.get("state")))
        return base, findings
    if current.get("state") != "implementation_ready":
        base["status"] = "review_required"
        findings.append(planning_finding(severity, "planning_baseline_invalid_current_state", "The current baseline must be draft, discovery, or implementation_ready.", current_baseline_id=current_id, state=current.get("state")))
        return base, findings

    source_findings, source_checks, stale = check_source_bindings(root, profile, current, severity)
    evidence_findings, evidence_checks, evidence_stale = check_evidence_refs(
        root,
        naos_root,
        policy,
        profile,
        current,
        severity,
    )
    decision_findings, decision = check_decision(root, current, severity)
    coverage_findings, coverage = check_task_coverage(registry, current, severity)
    findings.extend(source_findings + evidence_findings + decision_findings + coverage_findings)
    base.update({
        "source_bindings": source_checks,
        "evidence_checks": evidence_checks,
        "decision": decision,
        "task_coverage": coverage,
        "status": "stale" if stale or evidence_stale else ("review_required" if findings else "ready"),
    })
    return base, findings


def task_to_files(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, set[str]]:
    """Map task id -> set of source files via module-header Tasks: sections."""
    mapping: dict[str, set[str]] = {}
    try:
        rules_path, _ = mh.resolve_rules_path(root, naos_root, policy)
        rules = mh.load_yaml(rules_path)
        files, _ = mh.collect_source_files(root, rules, policy)
    except Exception:
        return mapping
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except Exception:
            continue
        header_text, _ = mh.header_text_from_source(source)
        sections = mh.section_map(header_text)
        tokens = {tok for item in sections.get("Tasks", []) for tok in extract_task_ids(item)}
        rel = mh.relative_text(root, path)
        for tok in tokens:
            mapping.setdefault(tok, set()).add(rel)
    return mapping


def normalize_path_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    paths: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text:
            continue
        while text.startswith("./"):
            text = text[2:]
        paths.append(text.rstrip("/") if text not in {".", "*"} else text)
    return paths


def strip_current_dir_prefix(path: str) -> str:
    normalized = path.strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def alignment_scope_paths(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit_alignment: str | None = None,
) -> dict[str, Any]:
    path, source = pia.alignment_path(root, naos_root, policy, explicit_alignment)
    data: dict[str, Any] | None = None
    parse_error: str | None = None
    if path.exists():
        data, parse_error = pia.extract_frontmatter(path)
    questions = data.get("questions") if isinstance(data, dict) and isinstance(data.get("questions"), dict) else {}
    lane_posture = pia.parallel_lane_posture(data)
    return {
        "alignment_path": str(path),
        "alignment_source": source,
        "alignment_present": path.exists(),
        "alignment_parse_error": parse_error,
        "planned_change_paths": normalize_path_list(questions.get("planned_change_paths")),
        "out_of_scope_paths": normalize_path_list(questions.get("out_of_scope_paths")),
        "parallel_lane_opportunity": lane_posture,
    }


def git_changed_files(root: Path, diff_base: str) -> tuple[list[str], str | None]:
    try:
        tracked = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", diff_base, "--"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return [], "git executable not found"
    if tracked.returncode != 0:
        return [], tracked.stderr.strip() or f"git diff failed for diff base {diff_base}"

    try:
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return [], "git executable not found"
    untracked_files = untracked.stdout.splitlines() if untracked.returncode == 0 else []
    files = sorted({line.strip() for line in tracked.stdout.splitlines() + untracked_files if line.strip()})
    return files, None


def path_matches_declaration(path: str, declarations: list[str]) -> bool:
    normalized = strip_current_dir_prefix(path)
    for declaration in declarations:
        item = strip_current_dir_prefix(declaration)
        if not item:
            continue
        if item in {".", "*"}:
            return True
        if fnmatch.fnmatch(normalized, item):
            return True
        prefix = item.rstrip("/")
        if normalized == prefix or normalized.startswith(f"{prefix}/"):
            return True
    return False


def implementation_scope_findings(
    changed_files: list[str],
    planned_change_paths: list[str],
    out_of_scope_paths: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    findings: list[dict[str, Any]] = []
    out_of_scope_changed = [
        path for path in changed_files if path_matches_declaration(path, out_of_scope_paths)
    ]
    if out_of_scope_changed:
        findings.append(
            finding(
                "advisory",
                "implementation_out_of_scope_path",
                "Changed files match Pre-Implementation Alignment out_of_scope_paths declarations.",
                changed_files=out_of_scope_changed,
                out_of_scope_paths=out_of_scope_paths,
                human_review_required=True,
            )
        )

    unplanned_changed: list[str] = []
    if planned_change_paths:
        unplanned_changed = [
            path
            for path in changed_files
            if not path_matches_declaration(path, planned_change_paths)
            and not path_matches_declaration(path, out_of_scope_paths)
        ]
        if unplanned_changed:
            findings.append(
                finding(
                    "advisory",
                    "implementation_unplanned_path",
                    "Changed files are outside Pre-Implementation Alignment planned_change_paths declarations.",
                    changed_files=unplanned_changed,
                    planned_change_paths=planned_change_paths,
                    human_review_required=True,
                )
            )
    return findings, unplanned_changed, out_of_scope_changed


def changed_file_family(path: str) -> str:
    normalized = strip_current_dir_prefix(path)
    if normalized.startswith(("naos/reports/", "naos/sessions/", "naos/audit_log/", "naos/context_packs/")):
        return "generated_evidence"
    if normalized in {"naos/TASK_REGISTRY.yaml", "naos/task_claims.yaml", "naos/PRE_IMPLEMENTATION_ALIGNMENT.md", "naos/PLANNING_BASELINES.yaml"} or normalized.startswith("naos/active/"):
        return "planning"
    first = normalized.split("/", 1)[0]
    if first in {"tests", "test"} or normalized.startswith("test_"):
        return "tests"
    if first in {"docs", "doc"} or normalized.endswith(".md"):
        return "docs"
    if first in {"schemas", "schema"} or normalized.endswith(".schema.json"):
        return "schemas"
    if first in {"templates", "profiles", "plugins"}:
        return "templates"
    if first in {"scripts", "src", "app", "apps", "packages"}:
        return "code"
    if first == "naos":
        return "governance"
    if first in {"policies", "configs", "config"}:
        return "config"
    if first in {"dev"}:
        return "internal_docs"
    return first or "unknown"


def multi_path_lane_findings(
    changed_files: list[str],
    lane_posture: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    categories = sorted({changed_file_family(path) for path in changed_files})
    review_families = [family for family in categories if family not in {"unknown", "generated_evidence"}]
    decision = lane_posture.get("decision") if isinstance(lane_posture, dict) else None
    opportunity = lane_posture.get("opportunity") if isinstance(lane_posture, dict) else None
    should_review = len(review_families) >= 3 and decision not in {"sequential", "declared"}
    context = {
        "changed_file_families": review_families,
        "changed_file_family_count": len(review_families),
        "opportunity": opportunity,
        "decision": decision,
        "does_not_declare_lanes": True,
        "does_not_activate_handoff": True,
    }
    if not should_review:
        return [], context
    return [
        finding(
            "advisory",
            "parallel_lane_decision_review",
            "Changed files span multiple path families without an explicit sequential or declared lane decision.",
            changed_file_families=review_families,
            opportunity=opportunity,
            decision=decision,
            human_review_required=True,
        )
    ], context


def build_report(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    diff_base: str | None = None,
    alignment_input: str | None = None,
) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) else severity_for_profile(profile, policy)
    claims = active_claims(root, naos_root, policy)
    registry = load_registry(root, naos_root)
    files_by_task = task_to_files(root, naos_root, policy)
    findings: list[dict[str, Any]] = []
    implementation_readiness, planning_findings = implementation_readiness_review(
        root,
        naos_root,
        policy,
        profile,
        registry,
    )
    findings.extend(planning_findings)
    scope = alignment_scope_paths(root, naos_root, policy, alignment_input)
    changed_files: list[str] = []
    git_error: str | None = None
    parallel_lane_review = {
        "changed_file_families": [],
        "changed_file_family_count": 0,
        "opportunity": scope["parallel_lane_opportunity"].get("opportunity"),
        "decision": scope["parallel_lane_opportunity"].get("decision"),
        "does_not_declare_lanes": True,
        "does_not_activate_handoff": True,
    }

    # claim_unknown_task + dependency_not_ready
    for claim in claims:
        tid = str(claim.get("task_id"))
        task = registry.get(tid)
        if registry and task is None:
            findings.append(finding("advisory", "claim_unknown_task",
                                    f"Active claim references task {tid} not present in TASK_REGISTRY.", task_id=tid))
            continue
        if task:
            for dep in task.get("dependencies") or []:
                dep_task = registry.get(str(dep))
                dep_status = str((dep_task or {}).get("status") or "unknown")
                if not dep_task or not is_task_delivered(dep_task):
                    findings.append(finding(severity, "dependency_not_ready",
                                            f"Active claim {tid} depends on {dep} (status: {dep_status}); working ahead of prerequisites.",
                                            task_id=tid, dependency=str(dep), dependency_status=dep_status))

    # parallel_overlap across distinct operator/session claims on overlapping files
    for i in range(len(claims)):
        for j in range(i + 1, len(claims)):
            a, b = claims[i], claims[j]
            if (a.get("operator_id"), a.get("session_id")) == (b.get("operator_id"), b.get("session_id")):
                continue
            ta, tb = str(a.get("task_id")), str(b.get("task_id"))
            overlap = files_by_task.get(ta, set()) & files_by_task.get(tb, set())
            if not overlap:
                continue
            non_parallel = any(registry.get(t, {}).get("parallelizable") is False for t in (ta, tb))
            findings.append(finding(
                severity if non_parallel else "warning",
                "parallel_overlap",
                f"Tasks {ta} and {tb} are concurrently claimed and implement overlapping files "
                f"({sorted(overlap)})" + ("; a task declares parallelizable: false." if non_parallel else "."),
                task_ids=[ta, tb], overlapping_files=sorted(overlap), parallelizable_false=non_parallel,
            ))

    unplanned_changed: list[str] = []
    out_of_scope_changed: list[str] = []
    if diff_base:
        changed_files, git_error = git_changed_files(root, diff_base)
        if git_error:
            findings.append(
                finding(
                    "advisory",
                    "implementation_scope_diff_unavailable",
                    f"Changed-file comparison could not be evaluated: {git_error}",
                    diff_base=diff_base,
                    human_review_required=True,
                )
            )
        else:
            scope_findings, unplanned_changed, out_of_scope_changed = implementation_scope_findings(
                changed_files,
                scope["planned_change_paths"],
                scope["out_of_scope_paths"],
            )
            findings.extend(scope_findings)
            lane_findings, parallel_lane_review = multi_path_lane_findings(
                changed_files,
                scope["parallel_lane_opportunity"],
            )
            findings.extend(lane_findings)

    summary = finding_counts(findings)
    summary.update({
        "active_claims": len(claims),
        "registry_tasks": len(registry),
        "tasks_with_file_linkage": len(files_by_task),
        "changed_files": len(changed_files),
        "planned_change_paths": len(scope["planned_change_paths"]),
        "out_of_scope_paths": len(scope["out_of_scope_paths"]),
        "unplanned_changed_files": len(unplanned_changed),
        "out_of_scope_changed_files": len(out_of_scope_changed),
        "parallel_lane_review_findings": sum(1 for item in findings if item.get("status") == "parallel_lane_decision_review"),
        "planning_baseline_findings": len(planning_findings),
        "implementation_ready": implementation_readiness.get("status") == "ready",
    })
    known_gaps = [
        "task_file_linkage_requires_module_headers",
        "conflict_resolution_workflow_deferred",
        "planning_decision_real_world_authority_not_proven",
        "requirements_and_architecture_semantic_quality_not_proven",
    ]
    if diff_base and not scope["planned_change_paths"]:
        known_gaps.append("planned_change_paths_not_declared")
    if diff_base and scope["alignment_parse_error"]:
        known_gaps.append("pre_implementation_alignment_parse_error")
    return {
        "schema": SCHEMA,
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "diff_base": diff_base,
        "changed_files": changed_files,
        "alignment_path": scope["alignment_path"],
        "alignment_source": scope["alignment_source"],
        "alignment_present": scope["alignment_present"],
        "alignment_parse_error": scope["alignment_parse_error"],
        "planned_change_paths": scope["planned_change_paths"],
        "out_of_scope_paths": scope["out_of_scope_paths"],
        "parallel_lane_opportunity": scope["parallel_lane_opportunity"],
        "parallel_lane_review": parallel_lane_review,
        "implementation_readiness": implementation_readiness,
        "unplanned_changed_files": unplanned_changed,
        "out_of_scope_changed_files": out_of_scope_changed,
        "summary": summary,
        "findings": findings,
        "known_gaps": known_gaps,
        "residual_risks": [
            "Files without module-header Tasks: annotations are not linked and may hide real overlap.",
            "Registry dependency/parallelizable metadata is adopter-maintained and may be incomplete.",
            "Implementation-scope path declarations can be stale, incomplete, or too broad.",
            "A structurally valid owner decision is attribution evidence, not proof of real-world role authority.",
            "Structural spec and traceability reports do not prove that requirements or architecture are correct or complete.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings) or implementation_readiness.get("status") == "ready",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate task-set coherence and versioned implementation-readiness planning baselines.")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--diff-base",
        help="Optional Git ref/base for advisory changed-file comparison against PRE_IMPLEMENTATION_ALIGNMENT path declarations.",
    )
    parser.add_argument(
        "--alignment",
        help="Optional explicit PRE_IMPLEMENTATION_ALIGNMENT.md path for implementation-scope comparison.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, naos_root, policy, profile, args.diff_base, args.alignment)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "plan_coherence_report")
    write_report(output, report)
    if args.json:
        import json
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Plan Coherence: {report['status']}")
        print(f"  implementation_readiness: {report['implementation_readiness']['status']}")
        print(f"  active_claims: {report['summary']['active_claims']} | findings: {report['summary'].get('total_findings', 0)}")
        if args.diff_base:
            print(
                "  implementation_scope: "
                f"changed={report['summary']['changed_files']} | "
                f"unplanned={report['summary']['unplanned_changed_files']} | "
                f"out_of_scope={report['summary']['out_of_scope_changed_files']}"
            )
        for item in report["findings"]:
            print(f"    [{item['severity']}] {item['status']}: {item['message']}")
    return exit_code_for_summary(profile, report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
