"""Exact-current declarations for aggregate systemic review surfaces.

This checks local records and file bytes. It does not authenticate reviewers,
prove that a human performed a review, or authorize implementation/release.
"""

from __future__ import annotations

from naos_self_check_inspection import logical_path

import copy
import hashlib
import json
import math
import os
import re
import stat
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable

import yaml
from naos_policy import load_operand_yaml

from naos_ai_surfaces import checked_path
from naos_policy import finding_counts, status_from_counts
from naos_resource_boundary import resource_reference

RECORD_SCHEMA = "naos.systemic_impact_family_review.v1"
ENTRY_KEYS = {
    "source_family_id",
    "target_kind",
    "target_id",
    "obligation_sha256",
    "disposition",
    "rationale",
    "evidence_refs",
    "evidence_sha256",
    "output_evidence",
    "reviewer_id",
    "reviewed_at",
}
ENTRY_REQUIRED = {
    "source_family_id",
    "target_kind",
    "target_id",
    "obligation_sha256",
    "disposition",
    "rationale",
    "evidence_refs",
    "evidence_sha256",
    "output_evidence",
}


def _digest(value: Any) -> str:
    data = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _reference(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Expected an exact nonempty project-relative path")
    parts = PurePosixPath(value).parts
    if (
        "\\" in value
        or "\x00" in value
        or ":" in value
        or PureWindowsPath(value).drive
        or value.startswith("/")
        or not parts
        or any(x in {"..", "."} for x in parts)
        or any(x in value for x in ("\n", "\r"))
        or PurePosixPath(value).as_posix() != value
    ):
        raise ValueError("Expected a canonical project-relative POSIX path")
    return value


def _identity(info: os.stat_result, *, cross_api: bool = False) -> tuple:
    common = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
    )
    # Windows Python 3.12+ can expose creation time via lstat but change
    # time via fstat. Keep ctime in each API's before/after comparison;
    # compare their shared fields when establishing path/handle identity.
    return common if cross_api and os.name == "nt" else (*common, info.st_ctime_ns)


def _local_bytes(root: Path, reference: str) -> bytes:
    """Observe a regular local witness without accepting linked components.

    Uses the existing resource boundary. This is static file validation and
    before/after identity observation, not a concurrent-filesystem sandbox.
    O_NONBLOCK prevents an exchanged FIFO from blocking before fstat refusal.
    """
    path = root / _reference(reference)
    resource_reference(path, root)
    before = path.lstat()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        held_before = os.fstat(descriptor)
        if not stat.S_ISREG(held_before.st_mode) or _identity(
            before, cross_api=True
        ) != _identity(held_before, cross_api=True):
            raise ValueError("Witness changed or is not a regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        held_after = os.fstat(descriptor)
        resource_reference(path, root)
        after = path.lstat()
        if (
            _identity(held_before) != _identity(held_after)
            or _identity(before) != _identity(after)
            or _identity(held_after, cross_api=True) != _identity(after, cross_api=True)
        ):
            raise ValueError("Witness changed during observation")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _source_bytes(root: Path, path: Path, *, kit_relative: str | None = None) -> bytes:
    # Explicit rules/policy selections must be local. Only the exact existing
    # packaged fallback can cross the boundary; resource_reference verifies it.
    if path.absolute().is_relative_to(root.absolute()):
        return _local_bytes(
            root, path.absolute().relative_to(root.absolute()).as_posix()
        )
    resource_reference(path, root, kit_relative=kit_relative)
    before = path.stat()
    data = path.read_bytes()
    resource_reference(path, root, kit_relative=kit_relative)
    if _identity(before) != _identity(path.stat()):
        raise ValueError("Selected packaged source changed")
    return data


def _load_record(root: Path, path: Path) -> dict[str, Any]:
    relative = path.absolute().relative_to(root.absolute()).as_posix()
    data = _local_bytes(root, relative).decode("utf-8")

    value = load_operand_yaml(data, unique_string_keys=True)
    if not isinstance(value, dict):
        raise ValueError("Review record must be an object")
    return value


def _file_manifest(
    root: Path, paths: list[str], forbidden: set[str], derived_directories: set[str] | None = None
) -> list[dict[str, str]]:
    witnesses: dict[str, str] = {}
    for reference in sorted(set(paths)):
        _reference(reference)
        path = root / reference
        if reference in forbidden:
            continue
        # Check components before any operation that follows a Windows junction.
        checked_path(root, reference)
        if path.is_dir() and not path.is_symlink():
            if getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError(f"Linked source directory: {reference}")

            # Include complete membership for a directory match, refusing linked
            # members. No traversal outside the already matched source directory.
            def refuse_incomplete_walk(error):
                raise error

            for directory, directories, files in os.walk(
                path, followlinks=False, onerror=refuse_incomplete_walk
            ):
                for name in directories:
                    child = Path(directory) / name
                    if (
                        child.is_symlink()
                        or getattr(child.lstat(), "st_file_attributes", 0) & 0x400
                    ):
                        raise ValueError(
                            f"Linked source directory: {child.relative_to(root)}"
                        )
                    child_ref = child.relative_to(root).as_posix()
                    if child_ref not in (derived_directories or set()):
                        witnesses[child_ref + "/"] = "directory"
                for name in files:
                    child_ref = (Path(directory) / name).relative_to(root).as_posix()
                    if child_ref in forbidden:
                        continue
                    witnesses[child_ref] = hashlib.sha256(
                        _local_bytes(root, child_ref)
                    ).hexdigest()
            # Empty-directory membership remains material even without a leaf.
            checked_path(root, reference)
            if reference not in (derived_directories or set()):
                witnesses[reference + "/"] = "directory"
        else:
            witnesses[reference] = hashlib.sha256(
                _local_bytes(root, reference)
            ).hexdigest()
    return [{"path": key, "sha256": witnesses[key]} for key in sorted(witnesses)]


def _record_errors(
    record: dict,
    scope: dict,
    binding: dict,
    expected: dict,
    validate_entries: Callable[[list[dict]], list[dict]],
) -> list[str]:
    errors = []
    if (
        set(record) != {"schema", "scope", "binding", "reviews"}
        or record.get("schema") != RECORD_SCHEMA
    ):
        errors.append("Invalid aggregate record schema/keys")
    if record.get("scope") != scope or record.get("binding") != binding:
        errors.append("Record root/profile/rules/policy binding mismatch")
    reviews = record.get("reviews")
    if not isinstance(reviews, list):
        return errors + ["Record reviews must be an array"]
    seen = set()
    for entry in reviews:
        if not isinstance(entry, dict):
            errors.append("Review entry must be an object")
            continue
        if set(entry) - ENTRY_KEYS or ENTRY_REQUIRED - set(entry):
            errors.append("Review entry has unknown or missing fields")
        key = (
            entry.get("source_family_id"),
            entry.get("target_kind"),
            entry.get("target_id"),
        )
        if not all(isinstance(part, str) and part for part in key):
            errors.append("Review target must use nonempty string identities")
            continue
        if key in seen:
            errors.append("Duplicate aggregate review target")
        seen.add(key)
        obligation = expected.get(key)
        if obligation is None:
            errors.append("Stale or unknown aggregate review target")
        elif entry.get("obligation_sha256") != obligation["obligation_sha256"]:
            errors.append("Obligation source binding mismatch")
        legacy = {
            name: entry[name]
            for name in (
                "target_kind",
                "target_id",
                "disposition",
                "rationale",
                "evidence_refs",
            )
            if name in entry
        }
        errors += [str(item.get("message")) for item in validate_entries([legacy])]
        if entry.get("target_kind") != "review_surface":
            errors.append("Only review_surface_review obligations can be settled")
        refs = entry.get("evidence_refs")
        hashes = entry.get("evidence_sha256")
        outputs = entry.get("output_evidence")
        valid_refs = isinstance(refs, list) and all(isinstance(x, str) for x in refs)
        if not valid_refs or len(refs) != len(set(refs)):
            errors.append("Evidence references must be unique strings")
        if not isinstance(hashes, dict) or not valid_refs or set(hashes) != set(refs):
            errors.append("Every evidence reference needs exactly one SHA256")
        elif any(
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
            for value in hashes.values()
        ):
            errors.append("Evidence SHA256 must be exact lowercase digests")
        if not isinstance(outputs, list):
            errors.append("Output evidence must be an array")
    return errors


# Finite producer identifiers. Root owns any extension and its projection.
DERIVED_REPORT_KEYS = {
    "conformance_latest_report",
    "agent_sponsor_registry_report",
    "agent_trace_validation_report",
    "agentic_workflow_review_report",
    "ai_component_inventory_report",
    "ai_surface_context_budget_report",
    "aivss_arithmetic_verification_report",
    "api_symbol_reality_report",
    "audit_log_summary_report",
    "behavioral_governance_readiness_report",
    "calibration_shadow_report",
    "capability_maturity_report",
    "claims_report",
    "control_plane_review_report",
    "cross_harness_review_readiness_report",
    "dashboard_markdown",
    "dashboard_summary_report",
    "dependency_integrity_report",
    "duplicate_function_hygiene_report",
    "evidence_attestation_report",
    "evidence_classification_report",
    "evidence_conflict_detection_report",
    "evidence_pack_report",
    "external_evidence_ingest_report",
    "function_index_report",
    "gate_evaluation_report",
    "gate_status_report",
    "governance_bypass_posture_report",
    "grader_assessment_report",
    "graph_context_query_report",
    "graph_context_readiness_report",
    "learning_loop_review_report",
    "llm_grader_readiness_report",
    "local_context_index_report",
    "local_context_query_report",
    "memory_context_readiness_report",
    "memory_provider_access_report",
    "memory_use_policy_report",
    "model_provider_policy_report",
    "model_telemetry_evidence_report",
    "module_header_traceability_report",
    "opencode_config_hygiene_report",
    "operator_attribution_report",
    "package_reality_report",
    "plan_coherence_report",
    "policy_override_merge_report",
    "pr_governance_summary_report",
    "pr_risk_classification_report",
    "pre_implementation_alignment_review_report",
    "roadmap_report",
    "sarif_export_summary_report",
    "sarif_report",
    "secret_hygiene_report",
    "secure_coding_controls_report",
    "secure_coding_reference_integrity_report",
    "secure_coding_reporting_report",
    "self_check_report",
    "self_check_dependency_resolution_report",
    "semantic_candidate_layer_report",
    "session_identity_report",
    "session_lifecycle_report",
    "setup_recommendations_report",
    "spec_assembly_worksheet_report",
    "spec_cascade_report",
    "spec_pack_contract_report",
    "spec_pack_materialization_report",
    "sqlite_write_coordination_report",
    "static_grader_report",
    "systemic_impact_report",
    "task_claim_report",
    "task_context_pack_report",
    "test_evidence_report",
    "test_quality_hygiene_report",
}

RESERVED_DERIVED_REPORT_KEYS = {"ci_readiness", "self_check_dependency_inputs"}


def _resolve_review_binding(
    root,
    naos_root,
    policy,
    rules,
    rule_data,
    rules_path,
    record_path,
    template_path,
    report_path,
):
    declaration = rules.get("review_binding")
    if (not isinstance(declaration, dict)
        or not {"mode", "derived_report_keys"} <= set(declaration)
        or set(declaration) - {"mode", "derived_report_keys", "derived_runtime_outputs"}
    ):
        raise ValueError("review_binding requires mode, derived_report_keys and only supported optional fields")
    if declaration["mode"] != "declared_producer_inputs":
        raise ValueError("Unsupported review_binding mode")
    roles = declaration.get("derived_runtime_outputs", [])
    if (not isinstance(roles, list) or any(not isinstance(x, str) for x in roles)
        or len(roles) != len(set(roles)) or set(roles) - RUNTIME_OUTPUT_ROLES):
        raise ValueError("derived_runtime_outputs requires unique supported roles")
    keys = declaration["derived_report_keys"]
    if (
        not isinstance(keys, list)
        or not keys
        or any(not isinstance(x, str) for x in keys)
        or len(keys) != len(set(keys))
        or set(keys) - DERIVED_REPORT_KEYS - RESERVED_DERIVED_REPORT_KEYS
    ):
        raise ValueError(
            "derived_report_keys must be unique finite supported producer identifiers"
        )
    # Validate the exact raw rules document, not a last-key-wins projection.
    from naos_systemic_applicability import load_rule_document

    raw = load_rule_document(rule_data.decode("utf-8"))
    if raw.get("review_binding") != declaration:
        raise ValueError(
            "review_binding does not match the selected raw rules document"
        )
    from naos_policy import (
        report_output_path,
        report_default_path,
        safe_policy_path,
        naos_root_path,
        evidence_pack_output_path,
        dashboard_output_path,
    )

    paths = policy.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("Derived outputs require typed policy paths")
    reports_dir = paths.get("reports_dir")
    if not isinstance(reports_dir, str) or not reports_dir:
        raise ValueError("Derived outputs require a nonempty typed reports_dir")
    protected = [rules_path]
    selected_policy = policy.get("_meta", {}).get("path")
    if selected_policy:
        protected.append(Path(selected_policy))
    protected += [path for path in (record_path, template_path) if path is not None]
    resolved = {}
    unproduced = []
    for key in keys:
        # Validate lexical components before any producer helper resolves them.
        # In particular, Path.resolve() can hide a contained Windows junction.
        if key == "self_check_dependency_inputs":
            lexical_parts = [naos_root, "dependency_inputs", "self_check_collection.json"]
        elif key == "ci_readiness":
            lexical_parts = [naos_root, reports_dir, "ci_readiness.json"]
        else:
            defaults = {
                "evidence_pack_report": "evidence_pack.json",
                "dashboard_markdown": "DASHBOARD.md",
                "sarif_report": "naos_findings.sarif",
            }
            filename = paths.get(key, defaults.get(key, key))
            if not isinstance(filename, str) or not filename:
                raise ValueError(
                    f"Empty or untyped policy path for derived producer: {key}"
                )
            if key == "dashboard_markdown":
                lexical_parts = [naos_root, filename]
            elif key == "evidence_pack_report":
                evidence_dir = paths.get("evidence_dir", "evidence")
                if not isinstance(evidence_dir, str) or not evidence_dir:
                    raise ValueError(
                        "Derived evidence output requires a typed evidence_dir"
                    )
                lexical_parts = [naos_root, evidence_dir, filename]
            else:
                lexical_parts = [naos_root, reports_dir, filename]
        checked_path(root, "/".join(lexical_parts))
        if key == "self_check_dependency_inputs":
            path = safe_policy_path(naos_root_path(root, naos_root), "dependency_inputs",
                                    "self_check_collection.json", field="self_check_dependency_inputs")
        elif key == "ci_readiness":
            # The runner has a reserved fixed receipt; it is not a fake policy key.
            path = safe_policy_path(
                naos_root_path(root, naos_root),
                reports_dir,
                "ci_readiness.json",
                field="ci_readiness",
            )
        else:
            if key == "evidence_pack_report":
                path = evidence_pack_output_path(root, naos_root, policy)
            elif key == "dashboard_markdown":
                path = dashboard_output_path(root, naos_root, policy)
            elif key in {
                "secure_coding_controls_report",
                "secure_coding_reference_integrity_report",
                "secure_coding_reporting_report",
            }:
                path = report_default_path(root, naos_root, policy, key)
            else:
                # SARIF uses this same policy-selected reports directory and
                # filename; SAFE_FALLBACK_POLICY supplies its canonical default.
                path = report_output_path(root, naos_root, policy, key)
            if path is None:
                # This producer does not publish here (e.g. kit root). The file
                # is not excluded; any original matched bytes stay bound.
                unproduced.append(key)
                continue
        path = logical_path(root, path)
        relative = _reference(path.absolute().relative_to(root).as_posix())
        if relative in resolved:
            raise ValueError("Declared derived producer paths alias each other")
        if any(path.resolve() == item.resolve() for item in protected):
            raise ValueError(
                "Declared derived output aliases rules, policy, record or template"
            )
        if (
            report_path is not None
            and path.resolve() == report_path.resolve()
            and key != "systemic_impact_report"
        ):
            raise ValueError(
                "Only the systemic producer can name its own selected output"
            )
        resolved[relative] = key
    return resolved, unproduced


# These are producer behaviours, not additional report filename definitions.
# Each copy path is resolved through the existing session_report_default_path.
# Source: the corresponding CLI write_report_with_session calls.
SESSION_COPY_KEYS = {
    "session_identity_report", "session_lifecycle_report",
    "operator_attribution_report", "task_claim_report",
    "evidence_classification_report", "cross_harness_review_readiness_report",
    "calibration_shadow_report", "agentic_workflow_review_report",
    "pre_implementation_alignment_review_report",
    "evidence_conflict_detection_report",
}
# Exact fields emitted by build_audit_event (audit_log_event schema required fields).
# Additional authored metadata keeps the whole event as a current byte witness.
AUDIT_EVENT_OUTPUT_FIELDS = {
    'schema',
    'event_id',
    'event_type',
    'generated_at',
    'session_id',
    'operator_id',
    'operator_source',
    'generated_by',
    'profile',
    'project_root',
    'naos_root',
    'source_report',
    'source_report_hash',
    'source_report_path',
    'related_task_id',
    'related_capability_id',
    'related_gate_id',
    'related_artifacts',
    'event_payload_summary',
    'event_payload_hash',
    'authority_layer',
    'human_review_required',
    'limitations',
    'not_claimed',
    'residual_risks',
}
AUDIT_PRODUCER_EVENT_TYPES = {
    "session_identity_report": {"session_started", "report_generated"},
    "session_lifecycle_report": {"session_started", "session_checkpoint", "session_ended", "report_generated"},
    "operator_attribution_report": {"operator_attributed"},
    "task_claim_report": {"task_claimed", "task_released", "task_claim_conflict_detected"},
    "policy_override_merge_report": {"policy_override_merged"},
    "local_context_index_report": {"context_index_generated"},
    "sqlite_write_coordination_report": {"sqlite_coordination_completed"},
    "gate_status_report": {"gate_evaluated"},
    "gate_evaluation_report": {"gate_evaluated"},
}
RUNTIME_OUTPUT_ROLES = {
    "session_report_copies", "registered_audit_events",
    "local_context_index_sqlite", "session_index_report_references",
}


# Exact finite shapes emitted by build_generated_by and summarize_source_report.
# Unknown authored keys at any fixed object boundary stay raw source witnesses.
_AUDIT_TEXT = (str, type(None))
_AUDIT_TEXT_LIST = ("list", str)
_AUDIT_COUNTS = {key: int for key in
    ("blocking", "required", "warnings", "advisory", "total_findings")}
_AUDIT_GENERATED_BY = {
    **{key: _AUDIT_TEXT for key in ("operator_id", "session_id", "generated_at")},
    **{key: str for key in ("operator_source", "operator_attribution_status")},
    "limitations": _AUDIT_TEXT_LIST, "not_claimed": _AUDIT_TEXT_LIST,
}
_AUDIT_SUMMARIES = {
    "session_identity_report": [{
        "session_id": _AUDIT_TEXT, "latest_report_compatibility_enabled": bool,
        "session_aware_report_count": int, "latest_only_report_count": int,
        "index_updated": bool,
    }],
    "operator_attribution_report": [{
        "operator_resolved": bool, "operator_source": str, "session_id": _AUDIT_TEXT,
        "session_copy_written": bool, "network_lookup_performed": bool,
        "identity_provider_lookup_performed": bool,
    }],
    "session_lifecycle_report": [{
        **_AUDIT_COUNTS,
        **{key: _AUDIT_TEXT for key in ("status", "mode", "task_id",
            "lifecycle_state", "delivery_state", "verification_state")},
        **{key: int for key in ("reports_present", "reports_missing", "stale_inputs",
            "memory_candidate_proposals")}, "human_review_required": bool,
    }],
    "task_claim_report": [{"action": str, "task_id": _AUDIT_TEXT, "branch": _AUDIT_TEXT}],
    "policy_override_merge_report": [{
        **_AUDIT_COUNTS, "status": str,
        **{key: int for key in ("override_files", "applied_paths", "rejected_paths",
            "conflicts", "protected_invariant_violations")},
        "team_ids": _AUDIT_TEXT_LIST, "operator_overlay_id": _AUDIT_TEXT,
        "team_operator_map_valid": bool, "schema_valid": bool,
        "effective_policy_written": bool,
    }],
    "local_context_index_report": [{"status": str}, {
        **_AUDIT_COUNTS, "status": str,
        **{key: int for key in ("indexed_artifacts", "excluded_artifacts", "chunks",
            "links", "stale_artifacts")},
        "fts_available": bool, "sqlite_written": bool, "human_review_required": bool,
    }],
    "sqlite_write_coordination_report": [{
        "status": str, "lock_acquired": bool, "atomic_replace_used": bool,
        "tables_verified": int, "target_db_hash_present": bool,
    }, {
        "status": str, "lock_acquired": bool, "atomic_replace_used": bool,
        "tables_verified": int, "target_db_hash_present": bool,
        "lock_wait_seconds": (int, float), "wal_requested": bool, "wal_effective": bool,
    }],
}
for _audit_gate_key in ("gate_status_report", "gate_evaluation_report"):
    _AUDIT_SUMMARIES[_audit_gate_key] = [{key: int for key in
        ("ready", "blocked", "required_missing", "warning", "advisory_missing",
         "not_applicable", "total")}]


def _audit_exact_object(value, shape):
    if type(value) is not dict or set(value) != set(shape):
        return False
    for key, contract in shape.items():
        item = value[key]
        if isinstance(contract, dict):
            valid = _audit_exact_object(item, contract)
        elif isinstance(contract, tuple) and contract[0] == "list":
            valid = type(item) is list and all(type(v) is contract[1] for v in item)
        else:
            allowed = contract if isinstance(contract, tuple) else (contract,)
            valid = type(item) in allowed
            if valid and type(item) in (int, float):
                valid = item >= 0 and (type(item) is int or math.isfinite(item))
        if not valid:
            return False
    return True


def _audit_nested_output_shape(event, source_key):
    if not _audit_exact_object(event["generated_by"], _AUDIT_GENERATED_BY):
        return False
    payload = event["event_payload_summary"]
    if "redacted" in payload:
        return _audit_exact_object(payload, {
            "redacted": bool, "redaction_reason": str,
            "forbidden_payload_indicators": _AUDIT_TEXT_LIST,
            "source_report_path": _AUDIT_TEXT, "schema": _AUDIT_TEXT, "status": _AUDIT_TEXT,
        }) and payload["redacted"] is True
    shape = {
        **{key: _AUDIT_TEXT for key in ("schema", "status", "profile", "mode",
            "session_id", "operator_id", "task_id", "source_report_path")},
        "finding_count": int, "human_review_required": bool,
        # Validated against finite per-producer contracts below.
        "summary": dict,
    }
    if payload.get("schema") == "naos.policy_override_merge.v1":
        shape["policy_override_scope"] = {
            **{key: _AUDIT_TEXT_LIST for key in ("global_overlay_files", "team_overlay_files",
                "operator_overlay_files", "selected_team_ids", "applied_overlay_scopes",
                "overlay_precedence")},
            **{key: _AUDIT_TEXT for key in ("team_id", "team_resolution_source",
                "operator_overlay_id", "operator_overlay_resolution_source")},
            "protected_invariant_violation_count": int,
        }
    if payload.get("schema") == "naos.gate_status.v1":
        shape["gate_team_context"] = {
            "team_id": _AUDIT_TEXT, "team_resolution_source": _AUDIT_TEXT,
            "team_overrides_applied": int, "team_overrides_rejected": int,
            "effective_severity_summary": dict,
        }
    if not _audit_exact_object(payload, shape):
        return False
    if not any(_audit_exact_object(payload["summary"], summary)
               for summary in _AUDIT_SUMMARIES.get(source_key, [])):
        return False
    if "gate_team_context" in payload:
        severities = payload["gate_team_context"]["effective_severity_summary"]
        if any(type(key) is not str or not _audit_exact_object(item, {
            "severity": _AUDIT_TEXT, "enabled": bool, "team_override_applied": bool,
        }) for key, item in severities.items()):
            return False
    return True


def _audit_output_shape(event, source_key):
    # Current audit_log_event schema uses only these primitive field contracts.
    # No schema/framework dependency is added to Lite installation.
    nullable = {"session_id", "operator_id", "source_report", "source_report_hash",
                "source_report_path", "related_task_id", "related_capability_id", "related_gate_id"}
    objects = {"generated_by", "event_payload_summary"}
    arrays = {"related_artifacts", "limitations", "not_claimed", "residual_risks"}
    # Legacy v1 event bodies stay recognized; the public-ID extension has an
    # exact pair of producer fields whose full digest is checked separately.
    fields = AUDIT_EVENT_OUTPUT_FIELDS
    if "event_id_scheme" in event or "event_nonce" in event:
        fields = fields | {"event_id_scheme", "event_nonce"}
        from naos_audit_log import recompute_public_audit_event_id
        if recompute_public_audit_event_id(event) is None:
            return False
    strings = fields - nullable - objects - arrays - {"human_review_required"}
    return (set(event) == fields
        and all(type(event[k]) in {str, type(None)} for k in nullable)
        and all(type(event[k]) is dict for k in objects)
        and all(type(event[k]) is list and all(type(v) is str for v in event[k]) for k in arrays)
        and all(type(event[k]) is str for k in strings)
        and type(event["human_review_required"]) is bool
        and event["profile"] in {"quickstart", "lite", "standard", "assured"}
        and _audit_nested_output_shape(event, source_key))


def _runtime_review_binding(root, naos_root, policy, rules, derived, protected):
    """Resolve finite sink behaviours; never approve their contents or findings.

    Unknown paths/events/references stay byte bound. The mixed session index
    retains all fields except timestamp churn and validated producer references.
    """
    roles = set(rules["review_binding"].get("derived_runtime_outputs", []))
    if not roles:
        return {}
    from naos_policy import sessions_index_path, session_report_default_path
    from naos_session_identity import path_text, validate_inspection_index_shape

    paths = policy["paths"]
    projections = {}

    def sink_json(path):
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Duplicate runtime sink JSON key")
                result[key] = value
            return result
        data = _local_bytes(root, relative(path))
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
        if not isinstance(value, dict):
            raise ValueError("Runtime sink must be a JSON object")
        return data, value

    def relative(path):
        path = logical_path(root, path)
        ref = _reference(path.absolute().relative_to(root).as_posix())
        checked_path(root, ref)
        return ref

    def add(path, role):
        ref = relative(path)
        if ref in derived or any(path.resolve() == p.resolve() for p in protected):
            raise ValueError("Runtime derived output aliases another output or source")
        derived[ref] = role

    if roles & {"session_report_copies", "session_index_report_references"}:
        # Validate lexical policy components before helpers can resolve links.
        for key in ("sessions_root", "sessions_index"):
            value = paths.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError("Runtime session outputs require typed policy paths")
            checked_path(root, naos_root + "/" + value)
        index_path = sessions_index_path(root, naos_root, policy)
        index_ref = relative(index_path)
        if index_ref in derived or any(index_path.resolve() == p.resolve() for p in protected):
            raise ValueError("Session index aliases a derived output or protected source")
        try:
            index_data, index = sink_json(index_path)
        except FileNotFoundError:
            index = None
        if index is not None:
            validate_inspection_index_shape(index)
            ids = [r["session_id"] for r in index["sessions"]]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate session identities in review binding")
            projected = copy.deepcopy(index)
            projected.pop("generated_at")
            for record in projected["sessions"]:
                record.pop("updated_at")
                session_id = record["session_id"]
                retained = {}
                for key, value in record["latest_reports"].items():
                    if key not in SESSION_COPY_KEYS or key not in derived.values():
                        retained[key] = value
                        continue
                    session_path = session_report_default_path(
                        root, naos_root, policy, session_id, key)
                    session_ref = relative(session_path)
                    latest_ref = next(ref for ref, k in derived.items() if k == key)
                    # Unknown/custom metadata is authored evidence, not churn.
                    if (not isinstance(value, dict)
                        or set(value) != {"latest_path", "session_path", "updated_at"}
                        or value["latest_path"] != path_text(root / latest_ref, root)
                        or value["session_path"] != path_text(root / session_ref, root)
                        or not isinstance(value["updated_at"], str)):
                        retained[key] = value
                record["latest_reports"] = retained
                if "session_report_copies" in roles:
                    for key in sorted(SESSION_COPY_KEYS & set(rules["review_binding"]["derived_report_keys"])):
                        if key not in derived.values():
                            continue
                        filename = paths.get(key)
                        checked_path(root, "/".join((naos_root, paths["sessions_root"],
                            session_id, paths["reports_dir"], filename)))
                        add(session_report_default_path(root, naos_root, policy,
                            session_id, key), "session_report_copy:" + key)
            if "session_index_report_references" in roles:
                if index_ref in derived:
                    raise ValueError("Session index cannot be a whole derived output")
                projections[index_ref] = {
                    "path": index_ref,
                    "binding_kind": "session_index_durable_projection",
                    "sha256": _digest(projected),
                    "raw_sha256": hashlib.sha256(index_data).hexdigest(),
                }
    if "local_context_index_sqlite" in roles:
        value = paths.get("local_context_index_sqlite")
        if not isinstance(value, str) or not value:
            raise ValueError("SQLite review output requires an explicit typed policy path")
        checked_path(root, naos_root + "/" + value)
        # A source-role lookup is not publication by the current producer.
        # The typed logical reference was validated above; never invoke another
        # producer's owned-write resolver while evaluating systemic review.
        from naos_policy import is_kit_repository
        if not is_kit_repository(root, naos_root) and (root / naos_root).is_dir():
            add(root / naos_root / value, "local_context_index_sqlite")
    if "registered_audit_events" in roles:
        from naos_audit_log import audit_log_root_path, event_file_paths, validate_audit_event
        value = paths.get("audit_log_root")
        if not isinstance(value, str) or not value:
            raise ValueError("Audit review outputs require a typed policy root")
        checked_path(root, naos_root + "/" + value)
        audit_root = audit_log_root_path(root, naos_root, policy)
        registered_sources = dict(derived)
        for event_path in sorted(audit_root.glob("*/*.jsonl")):
            relative(event_path)
            try:
                _, event = sink_json(event_path)
                # A canonical filename plus known source endpoint identifies a
                # registered sink, never an authenticated writer or approval.
                source_path = event.get("source_report_path")
                source_ref = relative(Path(source_path)) if isinstance(source_path, str) else None
                source_key = registered_sources.get(source_ref, "").removeprefix("session_report_copy:")
                if (not _audit_output_shape(event, source_key) or validate_audit_event(event)
                    or event.get("event_type") not in AUDIT_PRODUCER_EVENT_TYPES.get(source_key, set())
                    or event.get("project_root") != str(root)
                    or event.get("naos_root") != naos_root
                    or event_path not in event_file_paths(audit_root, event)):
                    continue
            except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError):
                continue  # Malformed/unknown event bytes remain source witnesses.
            add(event_path, "registered_audit_event:" + source_key)
    return projections


def _derived_only_directories(root, derived):
    """Omit container membership only for nonempty exact derived-only trees.

    Unknown files, linked resources and any empty descendant keep the directory
    witnessed. No glob or whole sessions/audit-tree exclusion is introduced.
    """
    candidates = set()
    for reference in derived:
        path = checked_path(root, reference)
        if not path.is_file():
            continue
        for parent in PurePosixPath(reference).parents:
            if parent.as_posix() != ".":
                candidates.add(parent.as_posix())
    omitted = set()
    for reference in sorted(candidates):
        folder = checked_path(root, reference)
        pure, has_leaf = True, False
        def refuse_walk(error):
            raise error
        for directory, directories, files in os.walk(folder, followlinks=False, onerror=refuse_walk):
            if not files and not directories:
                pure = False  # Genuinely empty authored membership stays bound.
                break
            for name in directories + files:
                ref = (Path(directory) / name).relative_to(root).as_posix()
                checked_path(root, ref)
                if name in files:
                    if ref not in derived:
                        pure = False
                        break
                    has_leaf = True
            if not pure:
                break
        if pure and has_leaf:
            omitted.add(reference)
    return omitted


def _derived_observations(root, derived):
    observations = []
    for reference, key in sorted(derived.items()):
        try:
            # Check parent topology even when the expected leaf is absent.
            checked_path(root, reference)
            data = _local_bytes(root, reference)
            observation = {
                "key": key,
                "path": reference,
                "state": "present",
                "sha256": hashlib.sha256(data).hexdigest(),
                "error": None,
            }
        except FileNotFoundError:
            observation = {
                "key": key,
                "path": reference,
                "state": "missing",
                "sha256": None,
                "error": None,
            }
        except (OSError, ValueError, TypeError) as exc:
            observation = {
                "key": key,
                "path": reference,
                "state": "unreadable",
                "sha256": None,
                "error": str(exc),
            }
        observations.append(observation)
    return observations


def _review_source_paths(root, definition, forbidden, runtime_observations=frozenset()):
    patterns = definition.get("review_source_patterns")
    if patterns is None:
        return []
    from naos_systemic_applicability import validate_review_patterns

    validate_review_patterns(patterns)
    found = set()
    for pattern in patterns:
        _reference(pattern)  # Canonical spelling in addition to portable patterns.
        # Wildcard supplemental discovery retains unknown evidence while exact
        # registered runtime observations use the same declared sink boundary.
        runtime_discovery = any(char in pattern for char in "*?[")
        # Canonical report/own-sink and exact durable-sink selection still refuse.
        for reference in forbidden:
            if runtime_discovery and reference in runtime_observations:
                continue
            if PurePosixPath(reference).match(pattern) or any(
                parent.as_posix() != "." and parent.match(pattern)
                for parent in PurePosixPath(reference).parents
            ):
                raise ValueError(
                    "Explicit review_source_patterns alias a derived or own sink"
                )
        literal_parts = []
        for part in PurePosixPath(pattern).parts:
            if any(character in part for character in "*?["):
                break
            literal_parts.append(part)
        if literal_parts:
            checked_path(root, "/".join(literal_parts))
        for path in root.glob(pattern):
            relative = path.relative_to(root).as_posix()
            checked_path(root, relative)
            if relative in forbidden:
                if runtime_discovery and relative in runtime_observations:
                    continue
                raise ValueError("Explicit durable witness aliases a derived or own sink")
            overlaps = {item for item in forbidden if item.startswith(relative + "/")}
            if path.is_dir() and overlaps and not (
                runtime_discovery and overlaps <= runtime_observations
            ):
                raise ValueError("Explicit durable witness aliases a derived or own sink")
            found.add(relative)
    return sorted(found)


def _required_source_paths(root, definition, derived, own_sinks):
    """Bind durable minimum expectations even outside discovery patterns.

    Only the exact declared sinks are omitted. An unknown matching file remains
    a source, including a file which first appears after review was recorded.
    """
    from naos_systemic_applicability import validate_review_patterns

    patterns = definition.get("minimum_expected") or []
    if not patterns:
        return [], []
    validate_review_patterns(patterns)
    found = set()
    predicates = []
    for pattern in patterns:
        matches = []
        for path in root.glob(pattern):
            reference = path.relative_to(root).as_posix()
            if reference in derived or reference in own_sinks:
                continue
            checked_path(root, reference)
            found.add(reference)
            matches.append(reference)
        predicates.append({"pattern": pattern, "durable_matches": sorted(matches)})
    return sorted(found), predicates


def apply_family_review(
    report: dict,
    *,
    root: Path,
    naos_root: str,
    profile: str,
    rules: dict,
    rules_path: Path,
    rules_source: str,
    policy: dict,
    record_path: Path | None,
    template_path: Path | None,
    report_path: Path | None,
    validate_entries: Callable,
    closed_dispositions: set[str],
) -> dict:
    """Apply exact records to evaluated families; leave factual defects intact."""
    result = copy.deepcopy(report)
    root = root.resolve()
    scope = {"project_root": str(root), "naos_root": naos_root, "profile": profile}
    errors: list[str] = []
    forbidden = set()
    for path in (record_path, template_path, report_path):
        if path is not None:
            try:
                forbidden.add(path.absolute().relative_to(root).as_posix())
            except ValueError:
                # Alias /tmp may resolve to /private/tmp; no input is allowed to
                # escape the selected project through resolution.
                try:
                    forbidden.add(path.resolve().relative_to(root).as_posix())
                except ValueError:
                    pass
    rule_data = None
    try:
        rule_data = _source_bytes(
            root,
            rules_path.absolute(),
            kit_relative=(
                "templates/structural-seeds/naos/systemic_impact_rules.yaml"
                if rules_source == "template"
                else None
            ),
        )
        selected_policy = policy.get("_meta", {}).get("path")
        policy_data = None
        if selected_policy:
            policy_data = _source_bytes(
                root,
                Path(selected_policy).absolute(),
                kit_relative=(
                    "policies/default_policy.yaml"
                    if policy.get("_meta", {}).get("source") == "kit"
                    else None
                ),
            )
        binding = {
            "rules_sha256": hashlib.sha256(rule_data).hexdigest(),
            "policy_sha256": hashlib.sha256(policy_data).hexdigest()
            if policy_data is not None
            else None,
            "effective_policy_sha256": _digest(
                {k: v for k, v in policy.items() if k != "_meta"}
            ),
        }
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"Selected source binding unavailable: {exc}")
        binding = {
            "rules_sha256": None,
            "policy_sha256": None,
            "effective_policy_sha256": None,
        }
    declared_input_mode = "review_binding" in rules
    derived = {}
    source_projections = {}
    unproduced_keys = []
    declaration_errors = []
    if declared_input_mode:
        try:
            if rule_data is None:
                raise ValueError("Current rules bytes unavailable")
            derived, unproduced_keys = _resolve_review_binding(
                root,
                naos_root,
                policy,
                rules,
                rule_data,
                rules_path,
                record_path,
                template_path,
                report_path,
            )
            protected = [rules_path] + [p for p in (record_path, template_path, report_path) if p is not None]
            selected_policy = policy.get("_meta", {}).get("path")
            if selected_policy:
                protected.append(Path(selected_policy))
            source_projections = _runtime_review_binding(
                root, naos_root, policy, rules, derived, protected)
        except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError) as exc:
            declaration_errors.append(str(exc))
            errors.append(f"Invalid declared producer-input binding: {exc}")
    derived_directories = set()
    if declared_input_mode and not declaration_errors and rules["review_binding"].get("derived_runtime_outputs"):
        try:
            derived_directories = _derived_only_directories(root, derived)
        except (OSError, ValueError, TypeError) as exc:
            declaration_errors.append(str(exc))
            errors.append(f"Invalid derived directory observation: {exc}")
    derived_observations = _derived_observations(root, derived)
    raw_families = {
        x.get("family_id"): x
        for x in rules.get("artifact_families", [])
        if isinstance(x, dict)
    }
    surfaces = {
        x.get("surface_id"): x
        for x in rules.get("review_surfaces", [])
        if isinstance(x, dict)
    }
    expected = {}
    for family in result["artifact_families"]:
        family_id = family["family_id"]
        for observation in [
            x for x in result["findings"] if x.get("family_id") == family_id
        ]:
            if observation.get("status") != "review_surface_review":
                continue
            targets = observation.get("related_families") or []
            if len(targets) != 1 or targets[0] not in surfaces:
                continue
            target_id = targets[0]
            key = (family_id, "review_surface", target_id)
            try:
                definition = family.get(
                    "effective_definition", raw_families.get(family_id, {})
                )
                selected_files = family.get("files_found", [])
                source_expectations = []
                if declared_input_mode:
                    if declaration_errors:
                        raise ValueError("Invalid declared producer-input binding")
                    selected_files = list(selected_files) + _review_source_paths(
                        root, definition, forbidden | set(derived),
                        {ref for ref, key in derived.items() if key.startswith(
                            ("registered_audit_event:", "session_report_copy:"))
                         or key == "local_context_index_sqlite"},
                    )
                    required_sources, source_expectations = _required_source_paths(
                        root, definition, set(derived), forbidden
                    )
                    selected_files += required_sources
                files = _file_manifest(
                    root,
                    selected_files,
                    forbidden | set(derived) if declared_input_mode else forbidden,
                    derived_directories,
                )
                for item in files:
                    projection = source_projections.get(item["path"])
                    if projection:
                        if item["sha256"] != projection["raw_sha256"]:
                            raise ValueError("Session index changed during source observation")
                        item["sha256"] = projection["sha256"]
                        item["binding_kind"] = projection["binding_kind"]
                independent_witness = (
                    any(item["sha256"] != "directory" for item in files)
                    if declared_input_mode
                    else bool(files)
                )
                if not independent_witness:
                    raise ValueError(
                        "No independent regular source witness remains after explicit own-sink exclusion"
                    )
                source_snapshot = {
                    "scope": scope,
                    "binding": binding,
                    "source_family": family.get(
                        "effective_definition", raw_families.get(family_id)
                    ),
                    "applicability": family.get("applicability"),
                    "target_surface": surfaces[target_id],
                    "source_files": files,
                    "missing_expected": family.get("missing_expected", []),
                    "configured": family.get("configured"),
                    "stale_files": family.get("stale_files", []),
                    "enabled": family.get("enabled"),
                }
                if declared_input_mode:
                    # These are actual current observations, not review identity.
                    # Original findings remain untouched and keep their severity.
                    for field in ("missing_expected", "configured", "stale_files"):
                        source_snapshot.pop(field)
                    source_snapshot["source_expectations"] = source_expectations
                    source_snapshot["source_stale_files"] = [
                        path
                        for path in family.get("stale_files", [])
                        if path not in derived and path not in forbidden
                    ]
                    source_snapshot["review_binding"] = copy.deepcopy(
                        rules["review_binding"]
                    )
                digest = _digest(source_snapshot)
                source_error = None
            except (OSError, ValueError, TypeError) as exc:
                files, digest, source_error = [], None, str(exc)
            expected[key] = {
                "source_family_id": family_id,
                "target_kind": "review_surface",
                "target_id": target_id,
                "obligation_sha256": digest,
                "source_files": files,
                "source_error": source_error,
                "required_review_outputs": list(
                    family.get(
                        "effective_definition", raw_families.get(family_id, {})
                    ).get("required_review_outputs")
                    or []
                ),
                "disposition": "unresolved",
                "rationale": "",
                "evidence_refs": [],
                "evidence_sha256": {},
                "output_evidence": [],
            }
    record = None
    if record_path is not None:
        try:
            # Keep lexical components for regular-resource refusal, even when
            # the caller selected a linked record path.
            record = _load_record(root, record_path.absolute())
            errors += _record_errors(record, scope, binding, expected, validate_entries)
        except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError) as exc:
            errors.append(f"Aggregate review record unavailable: {exc}")
    settled = {}
    if record is not None and not errors:
        for entry in record["reviews"]:
            key = (entry["source_family_id"], entry["target_kind"], entry["target_id"])
            obligation = expected[key]
            disposition = entry["disposition"]
            if disposition not in closed_dispositions:
                obligation["disposition"] = disposition
                continue
            entry_errors = []
            if (
                not isinstance(entry.get("rationale"), str)
                or not entry["rationale"].strip()
            ):
                entry_errors.append("Closed review requires nonblank rationale")
            if disposition == "not_applicable":
                entry_errors.append(
                    "Review record cannot override applicable obligation"
                )
            if obligation["source_error"] or obligation["obligation_sha256"] is None:
                entry_errors.append("Current source witness is unavailable or cyclic")
            if (
                not isinstance(entry.get("reviewer_id"), str)
                or not entry["reviewer_id"].strip()
            ):
                entry_errors.append("Closed review requires declared human reviewer_id")
            try:
                timestamp = entry.get("reviewed_at")
                if not isinstance(timestamp, str) or not re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", timestamp
                ):
                    raise ValueError("Expected explicit UTC timestamp ending Z")
                datetime.fromisoformat(timestamp[:-1] + "+00:00")
            except (ValueError, TypeError):
                entry_errors.append(
                    "Closed review requires explicit reviewed_at UTC date-time"
                )
            try:
                for reference in entry["evidence_refs"]:
                    if (
                        reference in forbidden
                        or declared_input_mode
                        and (reference in derived or reference in source_projections)
                    ):
                        raise ValueError("Cyclic or mutable derived evidence reference")
                    if (
                        hashlib.sha256(_local_bytes(root, reference)).hexdigest()
                        != entry["evidence_sha256"][reference]
                    ):
                        raise ValueError("Evidence byte hash mismatch")
                outputs = entry["output_evidence"]
                output_map = {}
                for output in outputs:
                    if not isinstance(output, dict) or set(output) != {
                        "requirement",
                        "evidence_refs",
                    }:
                        raise ValueError(
                            "Output evidence needs exact requirement text and references"
                        )
                    requirement = output["requirement"]
                    refs = output["evidence_refs"]
                    if not isinstance(requirement, str) or requirement in output_map:
                        raise ValueError("Duplicate or invalid output requirement")
                    if (
                        not isinstance(refs, list)
                        or not refs
                        or any(x not in entry["evidence_refs"] for x in refs)
                    ):
                        raise ValueError(
                            "Output requirement has no validated local evidence mapping"
                        )
                    output_map[requirement] = refs
                if set(output_map) != set(obligation["required_review_outputs"]):
                    raise ValueError(
                        "Output evidence does not exactly cover required review output text"
                    )
            except (OSError, ValueError, TypeError, KeyError) as exc:
                entry_errors.append(str(exc))
            if entry_errors:
                obligation["record_errors"] = entry_errors
                continue
            settled[key] = copy.deepcopy(entry)
            obligation.update(copy.deepcopy(entry))
    original = copy.deepcopy(result["findings"])

    def retain(finding):
        targets = finding.get("related_families") or []
        return not (
            finding.get("status") == "review_surface_review"
            and len(targets) == 1
            and (finding.get("family_id"), "review_surface", targets[0]) in settled
        )

    result["findings"] = [x for x in result["findings"] if retain(x)]
    for family in result["artifact_families"]:
        family["findings"] = [
            x for x in result["findings"] if x.get("family_id") == family["family_id"]
        ]
        for obligation in family.get("review_obligations", []):
            key = (
                family["family_id"],
                obligation.get("target_kind"),
                obligation.get("target_family_id"),
            )
            if key in settled:
                obligation["recorded_review"] = copy.deepcopy(settled[key])
                obligation["target_status"] = "review_recorded"
        if settled and family.get("enabled") and family.get("configured"):
            remaining = [
                x
                for x in family["findings"]
                if x.get("status") not in {"disabled", "waiver_visible"}
            ]
            if not remaining:
                family["evaluated_status"] = (
                    "advisory" if family.get("waivers") else "ready"
                )
    if errors:
        result["findings"].append(
            {
                "family_id": "aggregate_review_record",
                "id": "aggregate_review_record:invalid",
                "severity": "blocking" if profile == "assured" else "required",
                "status": "review_record_invalid",
                "message": "Explicit aggregate review record/source binding is invalid.",
                "related_families": [],
                "required_next_actions": errors,
            }
        )
    counts = finding_counts(result["findings"])
    result["summary"].update(counts)
    for status in ("ready", "review_required", "blocked", "advisory", "unknown"):
        field = "advisory_status" if status == "advisory" else status
        result["summary"][field] = sum(
            x.get("evaluated_status") == status for x in result["artifact_families"]
        )
    result["status"] = status_from_counts(result["summary"])
    template = {
        "schema": RECORD_SCHEMA,
        "scope": scope,
        "binding": binding,
        "reviews": [
            {
                **{
                    k: copy.deepcopy(value)
                    for k, value in expected[key].items()
                    if k in ENTRY_REQUIRED
                },
                "disposition": "unresolved",
                "rationale": "",
                "evidence_refs": [],
                "evidence_sha256": {},
                "output_evidence": [],
            }
            for key in sorted(expected)
        ],
    }
    result["aggregate_review"] = {
        "mode": "explicit_family_review",
        "scope": scope,
        "binding": binding,
        "record_path": str(record_path) if record_path else None,
        "integrity": {"status": "invalid" if errors else "pass", "errors": errors},
        "obligations": [expected[key] for key in sorted(expected)],
        "source_witness_exclusions": [
            {
                "path": path,
                "reason": "Own selected output/record/template cannot witness its own review; all other matched files remain current byte witnesses.",
            }
            for path in sorted(forbidden)
        ],
        "recorded_reviews": [settled[key] for key in sorted(settled)],
        "original_review_findings": [x for x in original if not retain(x)],
        "template": template,
        "summary": {
            "obligations": len(expected),
            "reviewed": len(settled),
            "unresolved": len(expected) - len(settled),
        },
        "limitations": [
            "Human reviewer identity and performance of review are declared, not authenticated.",
            "Current byte binding is not semantic correctness, approval or release authority.",
            "Only review-surface obligations can be settled; factual defects remain unresolved.",
            "Own-sink exclusions do not resolve indirect report cycles; changes to other bound reports invalidate review.",
            "Local witness checks are static observations, not a concurrent-filesystem sandbox.",
        ],
    }
    if declared_input_mode:
        result["aggregate_review"]["producer_input_binding"] = {
            "mode": "declared_producer_inputs",
            "declaration": None
            if declaration_errors
            else copy.deepcopy(rules.get("review_binding")),
            "integrity": {
                "status": "invalid" if declaration_errors else "pass",
                "errors": declaration_errors,
            },
            "derived_outputs": derived_observations,
            "source_projections": list(source_projections.values()),
            "derived_directory_observations": sorted(derived_directories),
            "unproduced_keys_kept_byte_bound": unproduced_keys,
            "limitations": [
                "Derived output bytes/state do not identify a human review; original factual findings remain adverse.",
                "All unknown matched outputs and immutable copied review evidence remain exact current byte witnesses.",
                "This declaration does not approve work or satisfy the separately consumed producer reports.",
            ],
        }
    return result


def create_unresolved_template(root: Path, path: Path, aggregate_review: dict) -> None:
    """Create a new local template; never replace any existing leaf."""
    root = root.resolve()
    absolute = path.absolute()
    try:
        relative = absolute.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("Family review template must remain in the project") from exc
    _reference(relative)
    binding = aggregate_review["binding"]
    if (
        not binding.get("rules_sha256")
        or not binding.get("effective_policy_sha256")
        or any(
            obligation.get("source_error")
            for obligation in aggregate_review["obligations"]
        )
    ):
        raise ValueError(
            "Cannot publish a template with invalid current source binding"
        )
    # Caller must validate sink/source conflicts before this function. POSIX
    # reuses the existing held report-parent writer; Windows retains its static
    # component checks and exclusive leaf creation (no sandbox claim).
    parent_fd = None
    if os.name != "nt":
        from naos_policy import _open_report_parent_fd

        parent_fd, leaf = _open_report_parent_fd(absolute, strict_parent_topology=True)
    else:
        cursor = root
        for part in PurePosixPath(relative).parts[:-1]:
            cursor = cursor / part
            try:
                cursor.mkdir()
            except FileExistsError:
                pass
            info = cursor.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("Template parent is linked or not a directory")
        leaf = str(absolute)
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = (
            os.open(leaf, flags, 0o600, dir_fd=parent_fd)
            if parent_fd is not None
            else os.open(leaf, flags, 0o600)
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(
                (
                    json.dumps(
                        aggregate_review["template"], indent=2, ensure_ascii=False
                    )
                    + "\n"
                ).encode("utf-8")
            )
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
