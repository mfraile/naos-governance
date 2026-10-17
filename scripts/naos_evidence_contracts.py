"""Bounded, local classification of declared NAOS evidence references.

This module reads stored artifacts and reproduces finite trusted local-only
producer reports without invoking their CLIs. It does not authenticate a
reviewer, approve a gate, or infer current source from file modification time.
"""

from __future__ import annotations

from naos_self_check_inspection import logical_path, inspection_read_path

import fnmatch
import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import RLock
from typing import Any

import yaml

from naos_policy import (
    controlled_now_utc, enforcement_transition, exit_code_for_summary,
    kit_root, report_default_path, would_block_for_summary, load_operand_yaml, evidence_staleness_days,
)


@dataclass(frozen=True)
class ReportDescriptor:
    key: str
    output_key: str | None
    schema_file: str | None
    schema_id: str | None
    clean_statuses: tuple[str, ...]
    claim_ceiling: str
    optional_rules_key: str | None = None
    manual: bool = False
    compatible_schema_ids: tuple[str, ...] = ()


def _report(
    key: str, output_key: str, clean: tuple[str, ...], ceiling: str,
    *, rules: str | None = None,
) -> ReportDescriptor:
    return ReportDescriptor(key, output_key, f"{key}.schema.json", f"naos.{key}.v1", clean, ceiling, rules)


# Finite registry: exactly the 30 distinct JSON references shipped in
# templates/structural-seeds/naos/gatekeepers.yaml at this baseline. Missing
# canonical schema files remain explicit unsupported dependencies.
REPORT_REGISTRY: dict[str, ReportDescriptor] = {
    "advanced_readiness": ReportDescriptor("advanced_readiness", None, None, None, (), "manual_reference_availability", manual=True),
    "ai_surface_context_budget": _report("ai_surface_context_budget", "ai_surface_context_budget_report", ("pass",), "input_quality_review"),
    "behavioral_evaluation": ReportDescriptor("behavioral_evaluation", None, None, None, (), "manual_reference_availability", manual=True),
    "claims_validation": _report("claims_validation", "claims_report", ("pass",), "claim_structure_review"),
    "control_plane_review": _report("control_plane_review", "control_plane_review_report", ("pass",), "review_routing"),
    "dependency_integrity": _report("dependency_integrity", "dependency_integrity_report", ("pass",), "deterministic_selected_input_check"),
    "duplicate_function_hygiene": _report("duplicate_function_hygiene", "duplicate_function_hygiene_report", ("pass",), "deterministic_selected_input_check"),
    "evidence_attestation": _report("evidence_attestation", "evidence_attestation_report", ("ready",), "structural_digest_review"),
    "function_index_health": _report("function_index_health", "function_index_report", ("pass",), "index_health_review"),
    "graph_context_query": _report("graph_context_query", "graph_context_query_report", ("ready",), "bounded_retrieval_metadata", rules="graph_context_rules"),
    "graph_context_readiness": _report("graph_context_readiness", "graph_context_readiness_report", ("readiness_only",), "graph_readiness_metadata", rules="graph_context_rules"),
    "learning_loop_review": _report("learning_loop_review", "learning_loop_review_report", ("pass",), "learning_record_review"),
    "local_context_index": _report("local_context_index", "local_context_index_report", ("ready",), "local_index_metadata", rules="local_context_index_rules"),
    "local_context_query": _report("local_context_query", "local_context_query_report", ("ready",), "bounded_retrieval_metadata", rules="local_context_index_rules"),
    "memory_context_readiness": _report("memory_context_readiness", "memory_context_readiness_report", ("ready",), "memory_readiness_metadata", rules="memory_context_rules"),
    "memory_provider_access": _report("memory_provider_access", "memory_provider_access_report", ("verified",), "declared_provider_access", rules="memory_provider_access_rules"),
    "memory_use_policy": _report("memory_use_policy", "memory_use_policy_report", ("readiness_only",), "memory_policy_review", rules="memory_use_policy_rules"),
    "module_header_traceability": _report("module_header_traceability", "module_header_traceability_report", ("pass",), "module_header_check", rules="module_header_rules"),
    "plan_coherence": _report("plan_coherence", "plan_coherence_report", ("pass",), "plan_structure_review"),
    "roadmap_crosswalk_validation": _report("roadmap_crosswalk_validation", "roadmap_report", ("pass",), "crosswalk_review"),
    "secret_hygiene": _report("secret_hygiene", "secret_hygiene_report", ("pass",), "deterministic_selected_input_check"),
    "secure_coding_controls": _report("secure_coding_controls", "secure_coding_controls_report", ("pass",), "secure_coding_route_review"),
    "self_check": _report("self_check", "self_check_report", ("pass",), "aggregate_structural_check"),
    "semantic_candidate_layer": _report("semantic_candidate_layer", "semantic_candidate_layer_report", ("readiness_only",), "semantic_readiness_metadata", rules="semantic_candidate_layer_rules"),
    "session_lifecycle": _report("session_lifecycle", "session_lifecycle_report", ("ready",), "session_checklist_review", rules="session_lifecycle_rules"),
    "spec_cascade_coherence": _report("spec_cascade_coherence", "spec_cascade_report", ("pass",), "spec_coherence_check"),
    "systemic_impact_review": _report("systemic_impact_review", "systemic_impact_report", ("pass",), "systemic_impact_review"),
    "task_context_pack": _report("task_context_pack", "task_context_pack_report", ("ready",), "task_context_assembly", rules="task_context_pack_rules"),
    "test_evidence_health": _report("test_evidence_health", "test_evidence_report", ("pass",), "test_mapping_health"),
    "test_quality_hygiene": _report("test_quality_hygiene", "test_quality_hygiene_report", ("pass",), "deterministic_selected_input_check"),
}

# Aggregate reports are consumable only by maturity prerequisites. They must
# never enter the shipped gate requirement registry or recursive gate routing.
MATURITY_REPORT_REGISTRY: dict[str, ReportDescriptor] = {
    "gate_status": ReportDescriptor("gate_status", "gate_status_report", "gate_status.schema.json", "naos.gate_status.v1", (), "stored_gate_readiness"),
    "gate_evaluation": ReportDescriptor("gate_evaluation", "gate_evaluation_report", "gate_evaluation.schema.json", "naos.gate_status.v1", (), "stored_gate_enforcement_review"),
    "dashboard_summary": ReportDescriptor("dashboard_summary", "dashboard_summary_report", "dashboard_summary.schema.json", "naos.dashboard_summary.v1", (), "capability_signal_projection", compatible_schema_ids=("naos.dashboard_summary.v2",)),
}

# Finite producer-owned reports named by shipped capability evidence contracts.
# These are maturity/pack support only, never gate eligibility or aggregate
# prerequisite closure. Their stored outcomes do not promote capability levels.
MATURITY_SUPPORT_REPORT_REGISTRY: dict[str, ReportDescriptor] = {
    "external_evidence_ingest": ReportDescriptor("external_evidence_ingest", "external_evidence_ingest_report", "external_evidence_ingest.schema.json", "naos.external_evidence_ingest.v2", (), "unverified_local_sarif_ingest_structure_only"),
    "secure_coding_reporting": _report("secure_coding_reporting", "secure_coding_reporting_report", ("pass",), "declared_secure_coding_evidence_projection_only"),
    "conformance_latest": _report("conformance_latest", "conformance_latest_report", ("pass",), "deterministic_local_conformance_structure_only"),
    "adapter_coherence": ReportDescriptor("adapter_coherence", "adapter_coherence_report", "adapter_coherence_report.schema.json", "naos.adapter_coherence_report.v1", ("pass",), "local_adapter_coherence_inspection_only"),
    "agent_trace_validation": _report("agent_trace_validation", "agent_trace_validation_report", ("ready", "no_events"), "declared_trace_structure_only"),
    "agentic_workflow_review": _report("agentic_workflow_review", "agentic_workflow_review_report", ("ready",), "declared_agentic_workflow_structure_only"),
    "cross_harness_review_readiness": ReportDescriptor("cross_harness_review_readiness", "cross_harness_review_readiness_report", "cross_harness_review_readiness_report.schema.json", "naos.cross_harness_review_readiness_report.v1", ("ready",), "declared_cross_harness_readiness_only"),
    "grader_assessment": _report("grader_assessment", "grader_assessment_report", (), "static_grader_structural_observation_only"),
    "package_reality": _report("package_reality", "package_reality_report", ("pass",), "local_package_declaration_check_only"),
    "policy_override_merge": _report("policy_override_merge", "policy_override_merge_report", ("no_overrides", "ready"), "static_policy_merge_inspection_only"),
    "pre_implementation_alignment_review": _report("pre_implementation_alignment_review", "pre_implementation_alignment_review_report", ("ready",), "declared_pre_implementation_structure_only"),
    "static_grader_report": _report("static_grader_report", "static_grader_report", (), "static_grader_structural_observation_only"),
    "setup_recommendations": _report("setup_recommendations", "setup_recommendations_report", ("pass",), "setup_orientation_only"),
    "calibration_shadow_report": _report("calibration_shadow_report", "calibration_shadow_report", ("ready",), "deterministic_metadata_calibration_only"),
    "evidence_classification_report": _report("evidence_classification_report", "evidence_classification_report", ("ready",), "provenance_label_review_only"),
    "governance_bypass_posture": _report("governance_bypass_posture", "governance_bypass_posture_report", ("pass",), "local_bypass_posture_only"),
    "pr_risk_classification": _report("pr_risk_classification", "pr_risk_classification_report", ("pass",), "local_diff_risk_review_only"),
}

# Control-plane source observations are deliberately separate from gate and
# maturity requirements. Their optional declarations do not add gate evidence.
CONTROL_PLANE_REPORT_REGISTRY: dict[str, ReportDescriptor] = {
    "failure_mode_posture": _report("failure_mode_posture", "failure_mode_posture_report", ("pass",), "declared_posture_review", rules="failure_mode_taxonomy"),
    "failure_mode_observations": _report("failure_mode_observations", "failure_mode_observations_report", ("pass",), "declared_observation_review", rules="failure_mode_observations"),
    "opencode_config_hygiene": _report("opencode_config_hygiene", "opencode_config_hygiene_report", ("pass",), "local_config_review", rules="opencode_config_hygiene"),
    "design_traceability": _report("design_traceability", "design_traceability_report", ("pass",), "declared_design_link_review", rules="design_traceability"),
    "ui_experience_quality": _report("ui_experience_quality", "ui_experience_quality_report", ("pass",), "declared_ui_evidence_review_only", rules="ui_experience_quality"),
}

_ADVERSE_STATUSES = {
    "blocked", "failed", "invalid", "missing", "stale", "required_missing",
    "uncovered", "missing_index", "missing_routing", "missing_required_source",
    "stale_source", "stale_context", "conflict", "stop", "unapproved",
}
_NOT_RUN_STATUSES = {"disabled", "not_configured", "not_run", "unknown", "missing_task", "task_not_found"}
_ADVERSE_SEVERITIES = {"blocking", "required", "error", "critical"}
_REVIEW_SEVERITIES = {"warning", "review_required"}
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _result(reference: str) -> dict[str, Any]:
    return {
        "reference": reference, "resolved_paths": [], "report_key": None,
        "expected_schema": None, "producer_schema": None,
        "availability": "missing", "applicability": "applicable",
        "applicability_reason": "required_reference", "applicability_source": "requirement",
        "validation": "not_evaluated", "scope": "not_established",
        "freshness": "not_established", "freshness_basis": "no_current_source_check",
        "producer_outcome": "not_run", "requirement_outcome": "unresolved",
        "human_review_required": False, "claim_ceiling": "none",
        "source_findings": [], "reason_codes": [],
        "content_sha256": None,
        "generation_age": {"status": "not_enforced", "basis": "none", "timestamp": None},
    }


def _safe_parts(reference: str, *, glob_allowed: bool = True) -> tuple[str, ...] | None:
    if not isinstance(reference, str) or not reference or "\\" in reference or "\x00" in reference:
        return None
    if reference.startswith("/") or PureWindowsPath(reference).drive or ":" in reference:
        return None
    parts = PurePosixPath(reference).parts
    if not parts or any(part in {".", "..", ""} for part in parts):
        return None
    if not glob_allowed and any(any(ch in part for ch in "*?[") for part in parts):
        return None
    return parts


def evidence_subject_parts(reference: str, *, glob_allowed: bool = False) -> tuple[str, ...] | None:
    """Shared project-relative subject syntax for collection, signing and conflicts.

    References use canonical project-relative POSIX syntax on every OS; this
    does not translate filenames unsupported by the native filesystem. It does not
    change the stricter no-link policy used by stored gate-report consumers.
    """
    parts = _safe_parts(reference, glob_allowed=glob_allowed)
    if parts is None or any(part in {"", ".", ".."} for part in reference.split("/")):
        return None
    if glob_allowed and any("**" in part and part != "**" for part in parts):
        return None
    return parts


def local_evidence_subject(root: Path, reference: str) -> Path | None:
    """Resolve a snapshot subject, allowing only links contained in this project.

    Missing local subjects retain a path so verification can report their absence.
    This is a read-time containment check, not a concurrent filesystem transaction.
    """
    parts = evidence_subject_parts(reference)
    if parts is None:
        return None
    try:
        base = root.resolve(strict=True)
        candidate = base.joinpath(*parts).resolve()
        return candidate if candidate.is_relative_to(base) else None
    except (OSError, RuntimeError, ValueError):
        return None


def _safe_file(root: Path, path: Path) -> str:
    """Inspect each operand before resolution; Windows lstat exposes junctions."""
    try:
        parts = path.relative_to(root).parts
        current = root
        mode = None
        for part in parts:
            current = current / part
            info = current.lstat()
            mode = info.st_mode
            if stat.S_ISLNK(mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE:
                return "unsafe_path"
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root.resolve(strict=True)):
            return "unsafe_path"
        return "available" if mode is not None and stat.S_ISREG(mode) else "not_regular_file"
    except FileNotFoundError:
        return "missing"
    except (OSError, RuntimeError, ValueError):
        return "unreadable"


def _inspection_safe_file(root: Path, path: Path) -> str:
    from naos_self_check_inspection import inspection_validation_root
    return _safe_file(inspection_validation_root(root, path), path)


def _glob_paths(root: Path, parts: tuple[str, ...]) -> list[Path]:
    """Expand path segments without traversing a symlink or reparse directory."""
    candidates = [root]
    for part in parts:
        next_candidates: list[Path] = []
        for base in candidates:
            if _safe_file(root, base) == "unsafe_path":
                # Keep the selected unsafe branch visible; a clean sibling
                # cannot make this glob pass.
                next_candidates.append(base)
                continue
            if any(ch in part for ch in "*?["):
                if part == "**":
                    raise ValueError("recursive_glob_unsupported")
                try:
                    children = sorted(base.iterdir(), key=lambda item: item.name)
                except (OSError, ValueError):
                    continue
                next_candidates.extend(child for child in children if fnmatch.fnmatchcase(child.name, part))
            else:
                next_candidates.append(base / part)
        candidates = next_candidates
    return sorted(set(candidates), key=lambda path: path.as_posix())


def _json_value(path: Path, *, data: bytes | None = None) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value

    def reject_constant(value: str) -> Any:
        raise ValueError("nonfinite_json_number")

    return json.loads((data if data is not None else inspection_read_path(path).read_bytes()).decode("utf-8", errors="strict"),
                      object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def _descriptor_for(root: Path, reference: str, naos_root: str, policy: dict[str, Any], *, consumer: str = "gate") -> tuple[ReportDescriptor | None, bool]:
    active: list[ReportDescriptor] = []
    shipped_aliases: list[ReportDescriptor] = []
    registry = (
        REPORT_REGISTRY.values() if consumer == "gate" else
        CONTROL_PLANE_REPORT_REGISTRY.values() if consumer == "control_plane" else
        (*REPORT_REGISTRY.values(), *MATURITY_REPORT_REGISTRY.values(),
         *MATURITY_SUPPORT_REPORT_REGISTRY.values())
    )
    for descriptor in registry:
        if descriptor.manual:
            reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
            expected = f"{naos_root}/{reports_dir}/{descriptor.key}.json"
        else:
            try:
                expected = logical_path(root, report_default_path(root, naos_root, policy, descriptor.output_key or "")).relative_to(root.resolve()).as_posix()
            except (OSError, RuntimeError, ValueError):
                continue
        shipped = f"{naos_root}/reports/{descriptor.key}.json"
        if reference == expected:
            active.append(descriptor)
        if reference == shipped:
            shipped_aliases.append(descriptor)
    # A policy-selected output takes precedence over another producer's
    # historical shipped filename. Multiple active producers are ambiguous.
    if len(active) == 1:
        return active[0], True
    if active:
        return None, False
    if len(shipped_aliases) == 1:
        return shipped_aliases[0], False
    return None, False


def _local_declaration(root: Path, path: Path) -> dict[str, Any] | None:
    """Read one safe, uniquely keyed project declaration; no template fallback."""
    if _inspection_safe_file(root, path) != "available":
        return None
    try:
        config = load_operand_yaml(path.read_text(encoding="utf-8"), unique_string_keys=True)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError):
        return None
    return config if isinstance(config, dict) else None


def _optional_disabled(root: Path, naos_root: str, policy: dict[str, Any], descriptor: ReportDescriptor,
                       requirement: dict[str, Any], consumer: str = "gate") -> bool:
    if requirement.get("optional") is not True or not descriptor.optional_rules_key:
        return False
    relative = policy.get("paths", {}).get(descriptor.optional_rules_key)
    if not isinstance(relative, str) or _safe_parts(relative, glob_allowed=False) is None:
        return False
    config = _local_declaration(root, root / naos_root / relative)
    if config is None or type(config.get("enabled")) is not bool:
        return False
    if config["enabled"] is False:
        return True
    # These two producers also emit disabled from an explicit disabled memory
    # setup declaration, even when their review rules remain enabled. Mirror
    # their exact candidate order; absent, unsafe or malformed config is unknown.
    # Memory-use policy has separate rule/profile semantics and is not included.
    if descriptor.key not in {"memory_context_readiness", "memory_provider_access"}:
        return False
    for path in (root / "configs/naos_memory.yaml", root / "naos/configs/naos_memory.yaml"):
        if _inspection_safe_file(root, path) == "missing":
            continue
        declaration = _local_declaration(root, path)
        if declaration is None:
            return False
        memory = declaration.get("memory", declaration)
        return isinstance(memory, dict) and memory.get("enabled") is False and memory.get("state") == "disabled"
    return False


def _control_plane_declaration_state(root: Path, naos_root: str, policy: dict[str, Any],
                                     descriptor: ReportDescriptor) -> str:
    """Mirror the four producers' project-local enablement, without running them."""
    relative = policy.get("paths", {}).get(descriptor.optional_rules_key)
    if not isinstance(relative, str) or _safe_parts(relative, glob_allowed=False) is None:
        return "invalid"
    rules = root / naos_root / relative
    availability = _safe_file(root, rules)
    if availability == "missing":
        config = {}
        declared_enabled = False  # Each producer falls back to a disabled template.
    elif availability != "available":
        return "invalid"
    else:
        try:
            config = load_operand_yaml(rules.read_text(encoding="utf-8"), unique_string_keys=True)
        except (OSError, UnicodeError, ValueError, yaml.YAMLError):
            return "invalid"
        if not isinstance(config, dict) or type(config.get("enabled")) is not bool:
            return "invalid"
        declared_enabled = config["enabled"]
    declared_field = {
        "failure_mode_posture": "failure_mode_posture_declared",
        "failure_mode_observations": "failure_mode_observations_declared",
        "opencode_config_hygiene": "opencode_config_declared",
        "design_traceability": "object_identity_declared",
        "ui_experience_quality": "ui_quality_declared",
    }[descriptor.key]
    if declared_field in config and type(config[declared_field]) is not bool:
        return "invalid"
    if descriptor.key in {"failure_mode_observations", "opencode_config_hygiene"} and config.get(declared_field) is True:
        return "active"
    if descriptor.key == "opencode_config_hygiene" and not declared_enabled:
        # The producer reviews repo-local OpenCode surfaces even when its
        # declaration is disabled. Never follow a link or reparse point while
        # detecting selected files, even if the producer would visit it.
        surfaces = ("AGENTS.md", "opencode.json", "opencode.jsonc",
                    ".opencode/config.yaml", ".opencode/config.yml")
        found_surface = False
        for item in surfaces:
            state = _safe_file(root, root / item)
            if state == "available":
                found_surface = True
            elif state != "missing":
                return "invalid"
        for item in ("agents", "commands", "modes", "plugins", "skills", "tools", "themes"):
            selected = _safe_local_tree_has_files(root, root / ".opencode" / item)
            if selected is None:
                return "invalid"
            if selected:
                found_surface = True
        if found_surface:
            return "active"
    return "active" if declared_enabled else "inactive"


def _safe_local_tree_has_files(root: Path, directory: Path) -> bool | None:
    """Inspect an OpenCode subdirectory without traversing unsafe entries."""
    availability = _safe_file(root, directory)
    if availability == "missing":
        return False
    if availability != "not_regular_file":
        return None
    try:
        if not stat.S_ISDIR(directory.lstat().st_mode):
            return None
        stack = [directory]
        found = False
        while stack:
            for path in stack.pop().iterdir():
                state = _inspection_safe_file(root, path)
                if state == "available":
                    found = True
                elif state == "not_regular_file" and stat.S_ISDIR(path.lstat().st_mode):
                    stack.append(path)
                else:
                    return None
        return found
    except (OSError, RuntimeError, ValueError):
        return None


_SCHEMA_MEMO_MAX_BYTES = 256 * 1024


@lru_cache(maxsize=64)
def _compiled_canonical_schema(raw: bytes, validator_class: type) -> tuple[Any, Any]:
    # Cache compilation only; the caller freshly reads and checks every schema.
    schema = _json_value(Path(), data=raw)
    validator_class.check_schema(schema)
    # Keep the validator private and serialize its active report iterators.
    return validator_class(schema), RLock()


def _schema_validation(report: dict[str, Any], descriptor: ReportDescriptor) -> tuple[str, list[str]]:
    if not descriptor.schema_file:
        return "unsupported", ["missing_canonical_schema"]
    schema_path = kit_root() / "schemas" / "naos" / descriptor.schema_file
    if not schema_path.is_file():
        return "unsupported", ["missing_canonical_schema"]
    try:
        raw = schema_path.read_bytes()
        schema = _json_value(schema_path, data=raw)
        if not isinstance(schema, dict):
            return "unsupported", ["invalid_canonical_schema"]
        stack = [schema]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "$ref" and (not isinstance(value, str) or not value.startswith("#/")):
                        return "unsupported", ["nonlocal_schema_reference"]
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)
        from jsonschema import Draft202012Validator
        compile_schema = (_compiled_canonical_schema if len(raw) <= _SCHEMA_MEMO_MAX_BYTES
                          else _compiled_canonical_schema.__wrapped__)
        validator, lock = compile_schema(raw, Draft202012Validator)
        with lock:
            if any(validator.iter_errors(report)):
                return "invalid", ["schema_invalid"]
    except ImportError:
        return "unsupported", ["schema_validator_unavailable"]
    except (OSError, UnicodeError, ValueError, TypeError):
        return "unsupported", ["invalid_canonical_schema"]
    return "valid", []


def _source_findings(report: dict[str, Any], path: Path, root: Path) -> tuple[list[dict[str, str]], bool, bool]:
    findings: list[dict[str, str]] = []
    adverse = False
    review = False
    for item in report.get("findings", []) if isinstance(report.get("findings"), list) else []:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "").lower()
        if severity in _ADVERSE_SEVERITIES:
            adverse = True
        elif severity in _REVIEW_SEVERITIES:
            review = True
        finding_id = item.get("id")
        if isinstance(finding_id, str) and finding_id:
            findings.append({"reference": logical_path(root, path).relative_to(root).as_posix(), "id": finding_id})
    summary = report.get("summary")
    if isinstance(summary, dict):
        for key in ("blocking", "required", "required_missing", "errors"):
            if isinstance(summary.get(key), int) and summary[key] > 0:
                adverse = True
        for key in ("warning", "warnings", "review_required"):
            if isinstance(summary.get(key), int) and summary[key] > 0:
                review = True
    return findings, adverse, review


def _selected_scan_failed(report: dict[str, Any], *, clean_input_status: str) -> bool:
    """Inspect the selected-input contract emitted by three hygiene producers."""
    summary = report.get("summary")
    scans = report.get("scans")
    if not isinstance(summary, dict) or not isinstance(scans, dict):
        return True
    for container in (summary, scans):
        if container.get("coverage_status") != "complete":
            return True
    required_counts = ("files_selected", "files_scanned", "files_failed")
    if any(type(summary.get(key)) is not int or summary[key] < 0 for key in required_counts):
        return True
    if summary["files_selected"] != summary["files_scanned"] or summary["files_failed"] > 0:
        return True
    for key in ("parse_errors", "read_errors", "analysis_errors"):
        if key in summary and (type(summary[key]) is not int or summary[key] != 0):
            return True
    input_files = scans.get("input_files")
    if not isinstance(input_files, list) or len(input_files) != summary["files_selected"]:
        return True
    return any(not isinstance(item, dict) or item.get("status") != clean_input_status for item in input_files)


def _generation_age(result: dict[str, Any], path: Path, report: dict[str, Any] | None,
                    requirement: dict[str, Any], *, manual: bool = False) -> None:
    """Keep producer age distinct from source freshness and manual file age."""
    window = requirement.get("freshness_window_days", 0)
    if type(window) is not int or window < 0:
        result["generation_age"] = {"status": "unknown", "basis": "invalid_window", "timestamp": None}
        result["reason_codes"].append("invalid_age_window")
        result["requirement_outcome"] = "unresolved"
        return
    basis = "manual_file_mtime" if manual else "report_generated_at"
    timestamp: str | None = None
    try:
        if manual:
            instant = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            timestamp = instant.isoformat()
        else:
            timestamp = report.get("generated_at") if isinstance(report, dict) else None
            if not isinstance(timestamp, str):
                raise ValueError("missing generated_at")
            instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if instant.tzinfo is None or instant.utcoffset() is None:
                raise ValueError("timestamp has no timezone")
            instant = instant.astimezone(UTC)
        now = controlled_now_utc()
        if instant > now + timedelta(minutes=5):
            raise ValueError("future timestamp")
    except (OSError, OverflowError, ValueError, TypeError):
        result["generation_age"] = {"status": "unknown", "basis": basis, "timestamp": timestamp}
        result["reason_codes"].append("generation_age_unknown")
        result["requirement_outcome"] = "unresolved"
        return
    status = "not_enforced" if window == 0 else "stale" if now - instant > timedelta(days=window) else "within_window"
    result["generation_age"] = {"status": status, "basis": basis, "timestamp": timestamp}
    if status == "stale":
        result["reason_codes"].append("generation_age_stale")
        result["requirement_outcome"] = "unresolved"


def _maturity_aggregate_outcome(report: dict[str, Any], key: str,
                                policy: dict[str, Any], *,
                                permit_advisory_gaps: bool = False) -> tuple[bool, list[str]]:
    if key == "dashboard_summary":
        # The capability-specific projection is checked by the maturity consumer.
        return True, []
    gates = report.get("gates")
    summary = report.get("summary")
    scope = report.get("evaluation_scope")
    if not isinstance(gates, list) or not gates or not isinstance(summary, dict) or not isinstance(scope, dict):
        return False, ["gate_selection_unresolved"]
    if scope.get("status") != "evaluated" or type(scope.get("selected_count")) is not int or scope["selected_count"] != len(gates):
        return False, ["gate_selection_unresolved"]
    ids = [gate.get("id") for gate in gates if isinstance(gate, dict)]
    if len(ids) != len(gates) or any(not isinstance(item, str) or not item for item in ids) or len(set(ids)) != len(ids):
        return False, ["gate_ids_invalid"]
    statuses = ("ready", "blocked", "required_missing", "warning", "advisory_missing", "not_applicable")
    if any(type(summary.get(name)) is not int or summary[name] != sum(gate.get("status") == name for gate in gates) for name in statuses):
        return False, ["gate_summary_inconsistent"]
    if type(summary.get("total")) is not int or summary["total"] != len(gates):
        return False, ["gate_summary_inconsistent"]
    applicable = [gate for gate in gates if gate.get("status") != "not_applicable"]
    if not applicable:
        return False, ["no_applicable_gate"]
    if report.get("protected_invariant_violations"):
        return False, ["protected_invariant_violation"]
    for gate in applicable:
        # PR enforcing-readiness is a distinct projection. Keep every advisory
        # row visible and leave the default maturity/pack contract unchanged.
        if (permit_advisory_gaps and gate.get("status") == "advisory_missing"
                and gate.get("severity") in {"advisory", "none"}):
            if any(not isinstance(item, dict) or item.get("severity") in {"blocking", "required", "warning"}
                   for item in gate.get("team_override_findings", [])):
                return False, ["selected_gate_override_unresolved"]
            continue
        if gate.get("status") != "ready" or gate.get("readiness") != "ready":
            return False, ["selected_gate_unresolved"]
        if any(gate.get(name) for name in ("missing_inputs", "missing_evidence", "unresolved_evidence")):
            return False, ["selected_gate_unresolved"]
        if any(not isinstance(item, dict) or item.get("requirement_outcome") not in {"satisfied", "not_applicable"}
               for item in gate.get("evidence_results", [])):
            return False, ["selected_gate_evidence_unresolved"]
        if any(not isinstance(item, dict) or item.get("status") != "pass" for item in gate.get("semantic_evidence", [])):
            return False, ["selected_gate_semantics_unresolved"]
    if key == "gate_evaluation":
        enforcement = report.get("enforcement")
        if not isinstance(enforcement, dict) or enforcement.get("exit_code") != 0:
            return False, ["gate_enforcement_unresolved"]
        counts = enforcement.get("severity_counts")
        if not isinstance(counts, dict) or any(type(counts.get(name)) is not int for name in ("blocking", "required", "warnings", "advisory")):
            return False, ["gate_enforcement_inconsistent"]
        expected_counts = {"blocking": 0, "required": 0, "warnings": 0, "advisory": 0}
        status_severity = {"blocked": "blocking", "required_missing": "required",
                           "warning": "warnings", "advisory_missing": "advisory"}
        for gate in gates:
            severities = set()
            if gate.get("status") in status_severity:
                severities.add(status_severity[gate["status"]])
            for item in gate.get("team_override_findings") or []:
                if not isinstance(item, dict):
                    return False, ["gate_enforcement_inconsistent"]
                severity = item.get("severity")
                if severity in {"blocking", "required", "warning", "advisory"}:
                    severities.add("warnings" if severity == "warning" else severity)
            for severity in severities:
                expected_counts[severity] += 1
        if counts != expected_counts:
            return False, ["gate_enforcement_inconsistent"]
        if counts["blocking"] or counts["required"]:
            return False, ["gate_enforcement_inconsistent"]
        strict = enforcement.get("strict")
        strict_required = enforcement.get("strict_required")
        if type(strict) is not bool or type(strict_required) is not bool:
            return False, ["gate_enforcement_inconsistent"]
        profile = report.get("profile")
        preview = would_block_for_summary(profile, counts, policy)
        policy_exit = exit_code_for_summary(profile, counts, policy, strict=strict)
        blocked = bool(summary["blocked"])
        required_missing = bool(summary["required_missing"])
        expected_exit = int(blocked or (strict_required and required_missing) or policy_exit)
        expected_reason = (
            "blocked_gate" if blocked else
            "strict_required" if strict_required and required_missing else
            "policy_severity" if policy_exit else
            "transition_warning" if preview else "no_failing_selected_gate"
        )
        expected = {
            "transition": enforcement_transition(policy),
            "would_block": blocked or preview,
            "reason": expected_reason,
            "exit_code": expected_exit,
        }
        if any(enforcement.get(field) != value for field, value in expected.items()):
            return False, ["gate_enforcement_inconsistent"]
    return True, []


def _classify_one(
    root: Path, reference: str, path: Path, descriptor: ReportDescriptor | None,
    current_output: bool, profile: str, naos_root: str, policy: dict[str, Any],
    requirement: dict[str, Any], consumer: str,
) -> dict[str, Any]:
    result = _result(reference)
    result["resolved_paths"] = [logical_path(root, path).relative_to(root).as_posix()]
    from naos_self_check_inspection import inspection_input_path
    path = inspection_input_path(root, naos_root, path)
    result["availability"] = _inspection_safe_file(root, path)
    if descriptor:
        result["report_key"] = descriptor.key
        result["expected_schema"] = descriptor.schema_id
        result["claim_ceiling"] = descriptor.claim_ceiling
    elif requirement.get("type") == "manual":
        result["claim_ceiling"] = "manual_reference_availability"
    else:
        result["validation"] = "unsupported"
        result["reason_codes"].append("unregistered_report" if path.suffix == ".json" else "untyped_reference")
        return result

    if descriptor and not current_output:
        result["validation"] = "unsupported"
        result["reason_codes"].append("not_current_policy_output")
        return result
    if descriptor and consumer == "control_plane":
        declaration_state = _control_plane_declaration_state(root, naos_root, policy, descriptor)
        result["declaration_state"] = declaration_state
        optional_disabled = requirement.get("optional") is True and declaration_state == "inactive"
    else:
        optional_disabled = bool(descriptor and _optional_disabled(root, naos_root, policy, descriptor, requirement, consumer))
    if result["availability"] != "available":
        if optional_disabled and result["availability"] == "missing":
            result.update(applicability="not_applicable", applicability_reason="optional_producer_disabled",
                          applicability_source="current_local_rules", scope="not_applicable",
                          freshness="not_applicable", producer_outcome="not_applicable",
                          requirement_outcome="not_applicable")
            return result
        result["reason_codes"].append(result["availability"])
        return result
    if not path.suffix.lower() == ".json":
        if descriptor and not descriptor.manual:
            result["validation"] = "invalid"
            result["reason_codes"].append("wrong_report_format")
            return result
        try:
            content = path.read_bytes()
            result["content_sha256"] = hashlib.sha256(content).hexdigest()
            if not content:
                result["validation"] = "invalid"
                result["reason_codes"].append("empty_manual_artifact")
                return result
        except OSError:
            result["availability"] = "unreadable"
            result["reason_codes"].append("unreadable")
            return result
        result.update(validation="valid", scope="not_applicable", freshness="not_applicable",
                      freshness_basis="manual_availability_only", producer_outcome="not_run",
                      requirement_outcome="satisfied")
        _generation_age(result, path, None, requirement, manual=True)
        if requirement.get("require_current_source") is True:
            result["requirement_outcome"] = "unresolved"
            result["reason_codes"].append("current_source_not_established")
        return result
    try:
        content = path.read_bytes()
        result["content_sha256"] = hashlib.sha256(content).hexdigest()
        report = _json_value(path, data=content)
    except (OSError, UnicodeError, ValueError, TypeError):
        result["validation"] = "invalid"
        result["reason_codes"].append("invalid_json")
        return result
    if not isinstance(report, dict) or not report:
        result["validation"] = "invalid"
        result["reason_codes"].append("invalid_report_shape")
        return result
    result["producer_schema"] = report.get("schema") if isinstance(report.get("schema"), str) else None
    findings, adverse_findings, review_findings = _source_findings(report, path, root)
    result["source_findings"] = findings
    result["human_review_required"] = bool(report.get("human_review_required")) or review_findings or adverse_findings
    if descriptor and not descriptor.manual:
        if report.get("schema") not in (descriptor.schema_id, *descriptor.compatible_schema_ids):
            result["validation"] = "invalid"
            result["reason_codes"].append("schema_discriminator_mismatch")
            return result
        result["validation"], codes = _schema_validation(report, descriptor)
        result["reason_codes"].extend(codes)
        if result["validation"] != "valid":
            return result
        expected_scope = {"profile": profile, "project_root": str(root.resolve()), "naos_root": naos_root}
        promised = {key for key in expected_scope if key in report}
        if any(report[key] != expected_scope[key] for key in promised):
            result["scope"] = "mismatched"
            result["reason_codes"].append("scope_mismatch")
            return result
        result["scope"] = "matched" if promised == set(expected_scope) else "not_established"
        if result["scope"] == "not_established":
            result["reason_codes"].append("partial_scope_binding")
        if consumer in {"maturity", "maturity_support", "pack"} and descriptor.key in (MATURITY_REPORT_REGISTRY | MATURITY_SUPPORT_REPORT_REGISTRY) and result["scope"] != "matched":
            return result
        if requirement.get("task_id") is not None:
            if report.get("task_id") != requirement["task_id"]:
                result["scope"] = "mismatched"
                result["reason_codes"].append("task_scope_mismatch")
                return result
        if consumer == "maturity_support" and descriptor.key in MATURITY_REPORT_REGISTRY:
            result["producer_outcome"] = "adverse" if adverse_findings or report.get("status") in _ADVERSE_STATUSES else "unknown"
            result["reason_codes"].append("aggregate_requires_prerequisite_purpose")
            _generation_age(result, path, report, requirement)
            return result
        if consumer in {"maturity", "pack"} and descriptor.key in MATURITY_REPORT_REGISTRY:
            valid, codes = _maturity_aggregate_outcome(report, descriptor.key, policy)
            result["producer_outcome"] = "passed" if valid else "adverse"
            result["reason_codes"].extend(codes)
            _generation_age(result, path, report, requirement)
            if valid and result["generation_age"]["status"] in {"within_window", "not_enforced"}:
                result["requirement_outcome"] = "satisfied"
            if requirement.get("require_current_source") is True:
                result["requirement_outcome"] = "unresolved"
                result["reason_codes"].append("current_source_not_established")
            if descriptor.key in {"gate_status", "gate_evaluation"}:
                from naos_self_check_dependency_resolution import enforce_gate_dependency_bindings
                enforce_gate_dependency_bindings(result, report, root=root, profile=profile,
                    naos_root=naos_root, policy=policy)
            return result
        if consumer == "gate":
            requirement = {"freshness_window_days": evidence_staleness_days(policy), **requirement}
            _generation_age(result, path, report, requirement)
        status = report.get("status")
        if not isinstance(status, str):
            result["producer_outcome"] = "unknown"
            result["reason_codes"].append("unknown_status")
        elif adverse_findings or status in _ADVERSE_STATUSES:
            result["producer_outcome"] = "adverse"
            result["reason_codes"].append("adverse_producer_result")
        elif status in _NOT_RUN_STATUSES:
            result["producer_outcome"] = "not_run"
            result["reason_codes"].append("producer_not_run")
        elif status in descriptor.clean_statuses:
            result["producer_outcome"] = "review_required" if review_findings else "passed"
        elif status in {"advisory", "warning", "review_required", "readiness_only", "routed", "waived"}:
            result["producer_outcome"] = "review_required"
            result["reason_codes"].append("review_required_outcome")
        else:
            result["producer_outcome"] = "unknown"
            result["reason_codes"].append("unknown_status")
        if descriptor.key in MATURITY_SUPPORT_REPORT_REGISTRY:
            incomplete = False
            if descriptor.key == "calibration_shadow_report":
                incomplete = (report.get("calibration_config_present") is not True
                              or report.get("calibration_config_valid") is not True
                              or report.get("drift_count") != 0
                              or bool(report.get("calibration_drift"))
                              or any(item.get("required") is not False for item in report.get("reports_missing", [])))
            elif descriptor.key == "evidence_classification_report":
                incomplete = (report.get("policy_present") is not True
                              or report.get("policy_valid") is not True
                              or bool(report.get("missing_classification"))
                              or any(item.get("classification") == "unknown"
                                     or item.get("classification_source") == "inferred_candidate"
                                     or item.get("candidate_requires_review") is True
                                     for item in report.get("classified_findings", []))
                              or report.get("summary", {}).get("unknown_findings", 0) != 0
                              or any(not isinstance(item, dict) or item.get("parse_error")
                                     for item in report.get("reports_scanned", [])))
            elif descriptor.key == "pr_risk_classification":
                incomplete = report.get("classification_status") != "complete"
            elif descriptor.key == "governance_bypass_posture":
                scans = report.get("scans", {})
                incomplete = any(
                    not isinstance(scans.get(name), dict)
                    or scans[name].get(field) is not True
                    for name, field in (("hook", "inspection_complete"),
                                        ("ci", "inspection_complete"),
                                        ("bypass_commit_message_inspection", "complete"))
                )
            elif descriptor.key == "cross_harness_review_readiness":
                incomplete = (report.get("config_present") is not True
                              or report.get("config_valid") is not True
                              or bool(report.get("requirements_missing"))
                              or any(report.get(field) is not False for field in
                                     ("runtime_execution_enabled", "harness_execution_allowed", "provider_api_allowed", "external_network_allowed")))
            elif descriptor.key == "agentic_workflow_review":
                incomplete = (report.get("workflow_config_present") is not True
                              or report.get("workflow_config_valid") is not True
                              or bool(report.get("missing_artifacts")))
            elif descriptor.key == "pre_implementation_alignment_review":
                incomplete = (report.get("alignment_present") is not True
                              or report.get("alignment_valid") is not True
                              or bool(report.get("missing_required_questions")))
            elif descriptor.key == "policy_override_merge":
                incomplete = (bool(report.get("protected_invariant_violations"))
                              or bool(report.get("conflicts"))
                              or report.get("summary", {}).get("schema_valid") is not True)
            if incomplete and result["producer_outcome"] == "passed":
                result["producer_outcome"] = "review_required"
                result["reason_codes"].append("producer_contract_incomplete")
        if descriptor.key == "evidence_attestation" and any(report.get(key) for key in (
            "missing_artifacts", "stale_artifacts", "uncovered_artifacts",
        )):
            result["producer_outcome"] = "adverse"
            result["reason_codes"].append("adverse_attestation_artifacts")
        if descriptor.key == "control_plane_review" and not report.get("routing_decisions"):
            result["producer_outcome"] = "not_run"
            result["reason_codes"].append("no_route_decisions")
        if descriptor.key == "plan_coherence" and (
            not isinstance(report.get("implementation_readiness"), dict)
            or report["implementation_readiness"].get("status") != "ready"
        ):
            result["producer_outcome"] = "adverse"
            result["reason_codes"].append("implementation_readiness_unresolved")
        if descriptor.key == "function_index_health":
            index = report.get("index") or {}
            if not index.get("exists"):
                result["producer_outcome"] = "adverse"
                result["reason_codes"].append("index_not_present")
            if not isinstance(index.get("entry_count"), int) or index["entry_count"] < 1:
                result["producer_outcome"] = "adverse"
                result["reason_codes"].append("index_entries_unresolved")
            if index.get("older_than_source") is True:
                result["producer_outcome"] = "adverse"
                result["reason_codes"].append("index_older_than_source")
            semantic = report.get("semantic_quality_snapshot") or {}
            if semantic.get("status") == "present":
                if not isinstance(semantic.get("errors"), int) or semantic["errors"] > 0:
                    result["producer_outcome"] = "adverse"
                    result["reason_codes"].append("semantic_quality_errors")
                elif not isinstance(semantic.get("warnings"), int):
                    result["producer_outcome"] = "adverse"
                    result["reason_codes"].append("semantic_quality_unresolved")
                elif semantic["warnings"] > 0 and result["producer_outcome"] == "passed":
                    result["producer_outcome"] = "review_required"
                    result["reason_codes"].append("semantic_quality_warnings")
        if descriptor.key in {"dependency_integrity", "duplicate_function_hygiene", "test_quality_hygiene", "secret_hygiene"}:
            clean_input_status = "read" if descriptor.key == "secret_hygiene" else "parsed"
            if _selected_scan_failed(report, clean_input_status=clean_input_status):
                result["producer_outcome"] = "adverse"
                result["reason_codes"].append("selected_scan_inputs_failed")
        if descriptor.key == "roadmap_crosswalk_validation" and isinstance(report.get("counts"), dict) and not any(
            report["counts"].get(key) for key in ("crosswalk_entries", "roadmap_ids", "referenced_ids")
        ):
            result["producer_outcome"] = "not_run"
            result["reason_codes"].append("roadmap_sources_not_configured")
        if descriptor.key == "test_evidence_health" and isinstance(report.get("summary"), dict):
            coverage = report["summary"].get("coverage_input_status")
            tests = report["summary"].get("test_input_status")
            if coverage not in {"complete", "not_configured"} or tests != "complete":
                if result["producer_outcome"] == "passed":
                    result["producer_outcome"] = "review_required"
                result["reason_codes"].append("test_inputs_incomplete_or_unknown")
            summary = report["summary"]
            map_summary = report.get("map_summary") if isinstance(report.get("map_summary"), dict) else {}
            counters = (summary, map_summary)
            failed_count = any(source.get(key, 0) > 0 for source in counters
                               for key in ("coverage_inputs_failed", "test_inputs_failed"))
            incomplete_count = any(
                source.get(selected, 0) > source.get(completed, 0)
                for source in counters
                for selected, completed in (("coverage_inputs_selected", "coverage_inputs_parsed"),
                                            ("test_inputs_selected", "test_inputs_read"))
                if selected in source and completed in source
            )
            failed_row = any(item.get("selected") and item.get("status") not in {"parsed", "parsed_empty"}
                             for item in report.get("coverage_inputs", [])) or any(
                                 item.get("status") != "read" for item in report.get("test_inputs", []))
            if failed_count or incomplete_count or failed_row:
                result["producer_outcome"] = "adverse"
                result["reason_codes"].append("selected_inputs_failed")
        if descriptor.key == "self_check":
            checks = report.get("checks")
            if not isinstance(checks, list) or not checks:
                result["producer_outcome"] = "unknown"
                result["reason_codes"].append("self_check_scope_empty")
            elif any(not isinstance(check, dict) or check.get("returncode", 0) != 0
                     or check.get("status") not in {"pass", "ready", "not_applicable"} for check in checks):
                result["producer_outcome"] = "adverse"
                result["reason_codes"].append("subcheck_unresolved")
            if isinstance(checks, list):
                for check in checks:
                    if not isinstance(check, dict):
                        continue
                    nested, nested_adverse, nested_review = _source_findings(check, path, root)
                    check_id = str(check.get("id") or "unknown")
                    result["source_findings"].extend(
                        {**item, "id": f"{check_id}/{item['id']}"} for item in nested
                    )
                    if nested_adverse:
                        result["producer_outcome"] = "adverse"
                        result["reason_codes"].append("subcheck_adverse_findings")
                    elif nested_review and result["producer_outcome"] == "passed":
                        result["producer_outcome"] = "review_required"
                        result["reason_codes"].append("subcheck_review_findings")
                    if nested_adverse or nested_review:
                        result["human_review_required"] = True
        if (optional_disabled and result["producer_outcome"] == "not_run"
                and (status in {"disabled", "not_run"}
                     or (consumer == "control_plane" and descriptor.key in {"design_traceability", "ui_experience_quality", "failure_mode_posture", "failure_mode_observations"}
                         and status == "not_configured" and report.get("enabled") is False
                         and (descriptor.key != "design_traceability" or report.get("object_identity_declared") is False)
                         and report.get("runtime_enabled") is False
                         and report.get("human_review_required") is False))
                and result["scope"] == "matched"
                and not adverse_findings and not review_findings):
            result.update(applicability="not_applicable", applicability_reason="optional_producer_disabled",
                          applicability_source="current_local_rules", freshness="not_applicable",
                          producer_outcome="not_applicable", requirement_outcome="not_applicable")
            return result
        if consumer in {"maturity", "maturity_support", "pack"}:
            _generation_age(result, path, report, requirement)
        if requirement.get("require_current_source") is True:
            result["reason_codes"].append("current_source_not_established")
        elif result["producer_outcome"] == "passed":
            if result["generation_age"]["status"] in {"within_window", "not_enforced"}:
                result["requirement_outcome"] = "satisfied"
        if descriptor.key in {"semantic_candidate_layer", "graph_context_readiness", "local_context_index", "ai_surface_context_budget"}:
            from naos_configuration_posture_review import apply_configuration_review
            apply_configuration_review(result, report, root=root, profile=profile,
                naos_root=naos_root, policy=policy, descriptor=descriptor,
                requirement=requirement, consumer=consumer, age_check=_generation_age)
    else:
        result.update(validation="valid", scope="not_applicable", freshness="not_applicable",
                      freshness_basis="manual_availability_only", producer_outcome="not_run")
        if adverse_findings or str(report.get("status") or "").lower() in _ADVERSE_STATUSES:
            result["producer_outcome"] = "adverse"
            result["reason_codes"].append("adverse_manual_artifact")
        else:
            result["requirement_outcome"] = "satisfied"
        if consumer in {"maturity", "maturity_support", "pack"}:
            _generation_age(result, path, report, requirement, manual=True)
        if requirement.get("require_current_source") is True:
            result["requirement_outcome"] = "unresolved"
            result["reason_codes"].append("current_source_not_established")
    if descriptor and descriptor.key == "self_check":
        _apply_configuration_self_check_review(
            result, report, root=root, profile=profile, naos_root=naos_root,
            policy=policy, requirement=requirement, consumer=consumer,
        )
        from naos_self_check_dependency_resolution import apply_self_check_resolution
        apply_self_check_resolution(result, report, root=root, profile=profile,
            naos_root=naos_root, policy=policy, requirement=requirement)
    if descriptor and descriptor.key in {"gate_status", "gate_evaluation"}:
        from naos_self_check_dependency_resolution import enforce_gate_dependency_bindings
        enforce_gate_dependency_bindings(result, report, root=root, profile=profile,
            naos_root=naos_root, policy=policy)
    if descriptor and descriptor.key in {"agent_trace_validation", "static_grader_report", "grader_assessment", "external_evidence_ingest"}:
        _apply_maturity_support_primitive(result, report, root=root, profile=profile,
            naos_root=naos_root, policy=policy, descriptor=descriptor, requirement=requirement)
    if descriptor and descriptor.key == "conformance_latest":
        _apply_conformance_maturity_support(result, report, root=root, profile=profile,
            naos_root=naos_root, policy=policy, requirement=requirement)
    return result


def _qualify_generated_conformance_runner(report: dict[str, Any], expected: dict[str, Any],
                                          *, root: Path, runtime: Path) -> None:
    """Qualify fixed generated bytes without importing any adopter executable.

    Keep the reported raw hash. Only the source-owned complete tool route may
    differ from trusted runner bytes; all other replay fields stay exact.
    """
    import ast
    from naos_ai_surfaces import checked_path

    raw = runtime.read_bytes()
    trusted_hash = hashlib.sha256(raw).hexdigest()
    if trusted_hash != expected["source_binding"]["runner_sha256"]:
        raise ValueError("conformance_runner_changed_during_replay")
    observed_hash = report["source_binding"]["runner_sha256"]
    generated_ref = ".github/autoresearch/runner.py"
    generated = checked_path(root, generated_ref)
    if not generated.exists() and observed_hash == trusted_hash:
        # Canonical source-produced reports need not install a project runner.
        return
    if not generated.is_file():
        raise ValueError("conformance_generated_runner_missing")
    canonical_line = b'_SCRIPT_DIR = _RUNTIME_ROOT / Path("scripts/naos_console.py").parent'
    relocated_line = b'_SCRIPT_DIR = _RUNTIME_ROOT / Path("naos_tools/naos_console.py").parent'
    assignments = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "_SCRIPT_DIR"
                           for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("conformance_runner_route_unqualified")
    allowed = {}
    for line, route in ((canonical_line, "scripts/naos_console.py"),
                        (relocated_line, "naos_tools/naos_console.py")):
        if raw.count(line) == 1 and ast.dump(assignments[0]) == ast.dump(ast.parse(line).body[0]):
            allowed[raw] = route
            if line == canonical_line:
                allowed[raw.replace(canonical_line, relocated_line, 1)] = "naos_tools/naos_console.py"
    actual = generated.read_bytes()
    route = allowed.get(actual)
    if route is None or hashlib.sha256(actual).hexdigest() != observed_hash:
        raise ValueError("conformance_generated_runner_variant_mismatch")
    if not checked_path(root, route).is_file():
        raise ValueError("conformance_generated_tool_route_missing")
    expected["source_binding"]["runner_sha256"] = observed_hash


def _apply_conformance_maturity_support(result: dict[str, Any], report: dict[str, Any], *,
                                       root: Path, profile: str, naos_root: str,
                                       policy: dict[str, Any], requirement: dict[str, Any]) -> None:
    """Replay only trusted shipped deterministic conformance code and inputs."""
    result["requirement_outcome"] = "unresolved"
    if (requirement.get("require_current_source") is True
            or result.get("producer_outcome") != "passed"
            or result.get("scope") != "matched"
            or result.get("generation_age", {}).get("status") not in {"within_window", "not_enforced"}):
        return
    try:
        import importlib.util
        from naos_ai_surfaces import checked_path
        from naos_behavioral_governance_readiness import conformance_contract_issues, report_status
        if conformance_contract_issues(report) or report_status(report, "conformance_latest") != "pass":
            raise ValueError("conformance_count_contract")
        runtime_root = kit_root()
        # Both source and initialized layouts are fixed shipped locations.
        # No report-supplied path can select executable code.
        runtime_ref = ("autoresearch/runner.py" if (runtime_root / "autoresearch/runner.py").is_file()
                       else ".github/autoresearch/runner.py")
        runtime = checked_path(runtime_root, runtime_ref)
        spec = importlib.util.spec_from_file_location("_naos_maturity_conformance_runner", runtime)
        if spec is None or spec.loader is None:
            raise ValueError("conformance_runtime_unavailable")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        selection = report["source_binding"]["battery_selection"]
        # Current caller/configuration determines the selection first. A stored
        # default report cannot override an explicitly selected custom battery.
        ref = requirement.get("conformance_battery_ref") or (policy.get("paths") or {}).get("conformance_battery")
        if ref is not None:
            if not isinstance(ref, str) or not ref or selection != {"kind": "project", "ref": ref}:
                raise ValueError("conformance_battery_selection_unbound")
            battery = checked_path(root, ref)
        elif selection == {"kind": "shipped_default"}:
            battery = runner.DEFAULT_BATTERY
        else:
            raise ValueError("conformance_battery_selection_unbound")
        # Before replay, guard the trusted/default or caller-bound selected path.
        checked_path(Path(battery.anchor), battery.relative_to(Path(battery.anchor)).as_posix())
        expected = runner.build_conformance_report(root, battery, profile=profile, naos_root=naos_root)
        _qualify_generated_conformance_runner(report, expected, root=root, runtime=runtime)
        # Initialization copies exactly these shipped validators through
        # naos_init._copy_generated_script, adding its fixed banner. Keep the
        # emitted raw hashes, accepting only that source-owned byte variant.
        observed_sources = report["source_binding"]["source_sha256"]
        expected_sources = expected["source_binding"]["source_sha256"]
        for name in ("frontmatter_utils", "validate_agents", "validate_skills", "validate_instructions"):
            key = "validator:" + name
            if observed_sources.get(key) == expected_sources.get(key):
                continue
            validator_ref = (runner._SCRIPT_DIR / "validators" / (name + ".py")).relative_to(runtime_root).as_posix()
            raw = checked_path(runtime_root, validator_ref).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_sources.get(key):
                raise ValueError("conformance_validator_changed_during_replay")
            # Match the copier's UTF-8 universal-newline read and LF write,
            # including its existing-marker guard and shebang placement.
            text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            if "# AUTO-GENERATED" in text[:2048]:
                raise ValueError("conformance_validator_copy_variant_unavailable")
            marker = "# AUTO-GENERATED: Copied by naos init from the NAOS kit.\n"
            if text.startswith("#!"):
                first_line, _, rest = text.partition("\n")
                copied = f"{first_line}\n{marker}{rest}".encode("utf-8")
            else:
                copied = (marker + text).encode("utf-8")
            if hashlib.sha256(copied).hexdigest() != observed_sources.get(key):
                raise ValueError("conformance_validator_copy_variant_mismatch")
            expected_sources[key] = observed_sources[key]
        # These labels describe execution time/location; age and scope are
        # independently checked. Every check, result, byte binding and selection
        # must reproduce exactly. Derived existence checks bind presence only.
        ignored = {"generated_at", "run_date", "battery_path"}
        if ({key: value for key, value in report.items() if key not in ignored}
                != {key: value for key, value in expected.items() if key not in ignored}):
            raise ValueError("conformance_current_reproduction_mismatch")
    except (Exception, SystemExit):
        result["reason_codes"].append("conformance_current_contract_unresolved")
        return
    result["claim_ceiling"] = "deterministic_local_conformance_structure_only"
    result["requirement_outcome"] = "satisfied"
    result["reason_codes"].append("conformance_current_contract_satisfied")


def _apply_maturity_support_primitive(result: dict[str, Any], report: dict[str, Any], *,
                                     root: Path, profile: str, naos_root: str,
                                     policy: dict[str, Any], descriptor: ReportDescriptor,
                                     requirement: dict[str, Any]) -> None:
    """Reuse exact producer reproduction for structural maturity/pack observations.

    This preserves the raw producer outcome/findings and human-review flags.
    Unsupported behavioral dimensions are not behavioral success or approval.
    """
    identities = {"external_evidence_ingest": "naos_external_evidence_ingest",
                  "agent_trace_validation": "naos_agent_trace_validate",
                  "static_grader_report": "naos_static_grader",
                  "grader_assessment": "naos_grader_assessment"}
    result["requirement_outcome"] = "unresolved"
    if (requirement.get("require_current_source") is True
            or any(result.get(key) != value for key, value in
                   {"availability": "available", "validation": "valid", "scope": "matched"}.items())
            or result.get("generation_age", {}).get("status") not in {"within_window", "not_enforced"}):
        return
    if descriptor.key == "external_evidence_ingest":
        result["human_review_required"] = True
        result["reason_codes"].append("external_findings_unverified_evidence_adequacy_not_established")
        summary = report.get("summary", {})
        if (summary.get("source_configured") is not True
                or summary.get("source_present") is not True
                or type(summary.get("runs")) is not int or summary["runs"] < 1
                or type(summary.get("results")) is not int or summary["results"] < 1
                or len(report.get("result_records", [])) != summary["results"]):
            result["reason_codes"].append("external_ingest_supporting_source_insufficient")
            return
    check = {"id": identities[descriptor.key], "returncode": 0,
             **{key: report.get(key) for key in ("status", "summary", "findings")}}
    decision = _self_check_primitive_contract(check, root=root, profile=profile,
        naos_root=naos_root, policy=policy)
    if decision is None or decision.get("content_sha256") != result.get("content_sha256"):
        result["reason_codes"].append("maturity_support_structural_contract_unresolved")
        return
    result["requirement_outcome"] = "satisfied"
    result["claim_ceiling"] = descriptor.claim_ceiling
    result["maturity_support_primitive_contract"] = decision
    result["reason_codes"].append("maturity_support_structural_contract_satisfied")


# These producer-owned contracts apply only inside the existing self-check.
# They do not register new direct gate evidence or approve behavioral outcomes.
_SELF_CHECK_PRIMITIVES = {
    "naos_behavioral_governance_readiness": ("behavioral_governance_readiness", "behavioral_governance_readiness_report", "lite_L0_inert_inspection_only_not_baseline_readiness"),
    "naos_evidence_conflicts": ("evidence_conflict_detection", "evidence_conflict_detection_report", "supported_conflict_metadata_and_pack_parser_limit"),
    "naos_task_claims": ("task_claim_report", "task_claim_report", "declared_coordination_metadata"),
    "naos_external_evidence_ingest": ("external_evidence_ingest", "external_evidence_ingest_report", "unconfigured_external_ingest_observation"),
    "naos_policy_overrides": ("policy_override_merge", "policy_override_merge_report", "static_policy_merge_inspection"),
    "naos_ai_component_inventory": ("ai_component_inventory", "ai_component_inventory_report", "declared_component_inventory"),
    "naos_model_provider_policy": ("model_provider_policy", "model_provider_policy_report", "inert_model_declaration"),
    "naos_model_telemetry_evidence": ("model_telemetry_evidence", "model_telemetry_evidence_report", "optional_disabled_telemetry"),
    "naos_llm_grader_readiness": ("llm_grader_readiness", "llm_grader_readiness_report", "disabled_future_grader_posture"),
    "naos_agent_trace_validate": ("agent_trace_validation", "agent_trace_validation_report", "valid_empty_declared_trace"),
    "naos_static_grader": ("static_grader_report", "static_grader_report", "fixed_behavioral_coverage_limitations"),
    "naos_grader_assessment": ("grader_assessment", "grader_assessment_report", "fixed_behavioral_coverage_limitations"),
}


def _primitive_source_operand(root: Path, path: Path, *, directory: bool = False) -> None:
    """Reject aliases before resolving or opening a selected project operand."""
    if not path.is_absolute():
        path = root / path
    if ".." in logical_path(root, path).relative_to(root).parts:
        raise ValueError("primitive_source_traversal")
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or getattr(root_info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE:
        raise ValueError("primitive_source_root_alias")
    outcome = _inspection_safe_file(root, path)
    if outcome == "missing":
        return  # lstat already distinguishes missing from a dangling alias.
    if directory and outcome == "not_regular_file" and path.is_dir():
        return
    if outcome != "available" or directory:
        raise ValueError("primitive_source_unsafe")


def _primitive_preferred_source(root: Path, candidates: list[Path], kit_reference: str | None = None) -> Path | None:
    for path in candidates:
        _primitive_source_operand(root, path)
        if _inspection_safe_file(root, path) == "available":
            return path
    if kit_reference is not None:
        base = kit_root()
        path = base / kit_reference
        _primitive_source_operand(base, path)
        if _safe_file(base, path) == "available":
            return path
    return None


def _primitive_source_preflight(identity: str, root: Path, naos_root: str, policy: dict[str, Any]) -> None:
    """Preflight this finite producer's actual selectors before any rebuild reads.

    Kit fallback is an exact finite source path, not report-supplied authority.
    Inventory already applies its own bounded resource/component source guards.
    """
    paths = policy.get("paths", {})
    state = root / naos_root
    _primitive_source_operand(root, state, directory=True)
    selected_policy = policy.get("_meta", {}).get("path")
    if selected_policy:
        path = Path(selected_policy)
        if path == kit_root() / "policies/default_policy.yaml":
            _primitive_source_operand(kit_root(), path)
        else:
            _primitive_source_operand(root, path)
    def configured(key: str, fallback: str) -> Path:
        return state / str(paths.get(key) or fallback)
    if identity in {"naos_agent_trace_validate", "naos_static_grader", "naos_grader_assessment"}:
        _primitive_source_operand(root, configured("agent_trace_events", "agent_trace_events.yaml"))
    if identity == "naos_llm_grader_readiness":
        _primitive_preferred_source(root, [configured("llm_grader_readiness_rules", "llm_grader_readiness_rules.yaml")],
            "templates/structural-seeds/naos/llm_grader_readiness_rules.yaml")
    if identity in {"naos_ai_component_inventory", "naos_model_provider_policy", "naos_model_telemetry_evidence"}:
        _primitive_preferred_source(root, [configured("model_provider_policy", "model_provider_policy.yaml")],
            "templates/structural-seeds/naos/model_provider_policy.yaml")
    if identity == "naos_ai_component_inventory":
        _primitive_preferred_source(root, [configured("ai_component_inventory_rules", "ai_component_inventory_rules.yaml")],
            "templates/structural-seeds/naos/ai_component_inventory_rules.yaml")
        for pattern in ("templates/agents/*.agent.md", ".github/agents/*.agent.md", "templates/skills/*/SKILL.md",
                        ".github/skills/*/SKILL.md", ".agents/skills/*/SKILL.md", ".claude/skills/*/SKILL.md", "templates/instructions/*.instructions.md", ".github/instructions/*.instructions.md"):
            prefix = pattern.split("*", 1)[0].rstrip("/")
            _primitive_source_operand(root, root / prefix, directory=True)
            for candidate in _glob_paths(root, PurePosixPath(pattern).parts):
                _primitive_source_operand(root, candidate)
        for relative in ("naos/ai_metadata_scope.yaml", "schemas/naos/ai_component_inventory.schema.json",
                         "schemas/naos/ai_component_inventory_rules.schema.json", "scripts/naos_ai_component_inventory.py",
                         "scripts/naos_emit_capabilities.py", "scripts/validators/frontmatter_utils.py"):
            _primitive_source_operand(root, root / relative)
        # load_metadata_scope already checks every declared host path lexically,
        # including Windows reparse points, before parsing its frontmatter.
    if identity == "naos_model_provider_policy":
        for pattern in (".github/agents/*.agent.md", "templates/agents/*.agent.md"):
            directory = root / str(PurePosixPath(pattern).parent)
            _primitive_source_operand(root, directory, directory=True)
            for candidate in _glob_paths(root, PurePosixPath(pattern).parts):
                _primitive_source_operand(root, candidate)
        _primitive_preferred_source(root, [state / "llm_grader_readiness_rules.yaml"],
            "templates/structural-seeds/naos/llm_grader_readiness_rules.yaml")
        _primitive_preferred_source(root, [root / "configs/naos_autoresearch.yaml", root / ".github/configs/naos_autoresearch.yaml"],
            "templates/structural-seeds/configs/naos_autoresearch.yaml")
    if identity == "naos_model_telemetry_evidence":
        declaration = _primitive_preferred_source(root, [configured("model_telemetry_evidence", "model_telemetry_evidence.yaml")],
            "templates/structural-seeds/naos/model_telemetry_evidence.yaml")
        if declaration is not None:
            data = yaml.safe_load(declaration.read_text()) or {}
            if not isinstance(data, dict):
                raise ValueError("invalid_telemetry_declaration")
            for source in data.get("telemetry_sources", []):
                if isinstance(source, dict) and source.get("path"):
                    _primitive_source_operand(root, Path(str(source["path"])))
    if identity == "naos_evidence_conflicts":
        import naos_evidence_conflicts as producer
        import naos_audit_log as audit
        from naos_policy import evidence_pack_output_path, sessions_index_path
        yaml_paths = [configured("evidence_review_attestations", "evidence_review_attestations.yaml"),
                      configured("control_plane_review_items", "control_plane_review_items.yaml")]
        rules = _primitive_preferred_source(root, [configured("control_plane_review_rules", "control_plane_review_rules.yaml")],
            "templates/structural-seeds/naos/control_plane_review_rules.yaml")
        if rules is not None:
            yaml_paths.append(rules)
        mappings = {}
        class UniqueKeyLoader(yaml.SafeLoader):
            pass
        def unique_mapping(loader, node):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node)
                if key in result:
                    raise ValueError("duplicate_conflict_input_key")
                result[key] = loader.construct_object(value_node)
            return result
        UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
        for candidate in yaml_paths:
            # Exact kit fallback was already bounded separately above.
            if candidate != rules or candidate.is_relative_to(root):
                _primitive_source_operand(root, candidate)
            if candidate.is_file():
                data = yaml.load(candidate.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
                if not isinstance(data, dict):
                    raise ValueError("invalid_conflict_input_mapping")
                mappings[candidate] = data
        json_paths = [report_default_path(root, naos_root, policy, key) for key in
                      ("evidence_attestation_report", "audit_log_summary_report", "operator_attribution_report")]
        pack = evidence_pack_output_path(root, naos_root, policy)
        if pack is not None:
            json_paths.append(pack)
        json_paths.append(sessions_index_path(root, naos_root, policy))
        for candidate in json_paths:
            _primitive_source_operand(root, candidate)
            if candidate.is_file():
                data = _json_value(candidate)
                if not isinstance(data, dict):
                    raise ValueError("invalid_conflict_input_mapping")
                mappings[candidate] = data
        audit_root = audit.audit_log_root_path(root, naos_root, policy)
        _primitive_source_operand(root, audit_root, directory=True)
        for candidate in _glob_paths(root, (*logical_path(root, audit_root).relative_to(root).parts, "*", "*.jsonl")):
            _primitive_source_operand(root, candidate)
            if candidate.is_file():
                for line in candidate.read_bytes().splitlines():
                    event = _json_value(candidate, data=line)
                    if not isinstance(event, dict) or audit.validate_audit_event(event):
                        raise ValueError("invalid_conflict_audit_event")
        source = mappings.get(yaml_paths[0], {})
        manifest = mappings.get(json_paths[0], {})
        for data, field in ((source, "attestations"), (manifest, "reviewer_attestations"),
                            (manifest, "artifact_manifest"), (mappings.get(yaml_paths[1], {}), "items")):
            if field in data and (not isinstance(data[field], list)
                    or any(not isinstance(item, dict) for item in data[field])):
                raise ValueError("invalid_conflict_input_records")
        # Preserve the legacy scalar/list aliases and explicit identity maps,
        # but never accept find_first/as_str_list coercion of other JSON types.
        from jsonschema import Draft202012Validator
        schema_path = kit_root() / "schemas/naos/evidence_attestation.schema.json"
        _primitive_source_operand(kit_root(), schema_path)
        definitions = _json_value(schema_path)["$defs"]
        properties = dict(definitions["reviewer_attestation"]["properties"])
        for field in ("reviewed_artifacts", "artifact_groups"):
            properties[field] = {"anyOf": [properties[field], {"type": ["string", "null"]}]}
        validator = Draft202012Validator({"type": "object", "properties": properties})
        def identity(value, active=frozenset()):
            if value is None or isinstance(value, str):
                return bool(value and value.strip())
            if not isinstance(value, dict) or id(value) in active:
                raise ValueError("invalid_conflict_identity_type")
            fields = set(value).intersection({"operator_id", "id", "email", "name"})
            resolved = [identity(value[field], active | {id(value)}) for field in fields]
            if not any(resolved):
                raise ValueError("invalid_conflict_identity_mapping")
            return True
        def strings(value):
            if value is None:
                return []
            values = [value] if isinstance(value, str) else value
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                raise ValueError("invalid_conflict_string_values")
            return values
        def hashes(value):
            for digest in strings(value):
                raw = digest.strip()
                if not raw:
                    continue  # Existing as_str_list treats an empty value as absent.
                if raw.startswith("sha256:"):
                    raw = raw[7:]  # Preserve legacy notation; producer comparison is unchanged.
                if len(raw) != 64 or any(char not in "0123456789abcdef" for char in raw):
                    raise ValueError("invalid_conflict_hash_format")
        for item in source.get("attestations", []) + manifest.get("reviewer_attestations", []):
            if any(validator.iter_errors(item)):
                raise ValueError("invalid_conflict_attestation_fields")
            for field in ("operator_id", "reviewer_id", "reviewer_operator_id", "reviewer_contact", "reviewer_email",
                          "created_by_operator_id", "generated_by_operator_id", "artifact_operator_id", "created_by", "generated_by"):
                if field in item:
                    identity(item[field])
            for field in ("attestation_id", "outcome", "status", "session_id"):
                if field in item and not isinstance(item[field], str):
                    raise ValueError("invalid_conflict_attestation_scalar")
            for field in ("artifact_paths", "artifact_path", "artifact_ref", "related_tasks", "tasks", "related_capabilities", "capabilities"):
                if field in item:
                    strings(item[field])
            for field in ("artifact_hash", "artifact_digest", "digest", "expected_hash", "expected_digest", "sha256"):
                if field in item:
                    hashes(item[field])
            if "artifact_hashes" in item:
                value = item["artifact_hashes"]
                if isinstance(value, dict):
                    if any(not isinstance(key, str) for key in value):
                        raise ValueError("invalid_conflict_hash_reference")
                    for nested in value.values():
                        hashes(nested)
                else:
                    hashes(value)
        attestations, _ = producer.raw_attestations(source, manifest)
        by_path = producer.artifact_manifest_by_path(manifest)
        for item in attestations:
            for reference in producer.resolve_attestation_artifacts(item, manifest):
                parts = evidence_subject_parts(reference)
                if parts is None:
                    raise ValueError("unavailable_conflict_artifact")
                candidate = root.joinpath(*parts)
                _primitive_source_operand(root, candidate)
                if _safe_file(root, candidate) != "available":
                    raise ValueError("unavailable_conflict_artifact")
                recorded = by_path.get(reference, {}).get("digest")
                # The conflict producer compares reviewer hashes with the selected
                # collection manifest, falling back to live bytes only without a
                # digest. Later generated reports need not equal that snapshot.
                # Keep topology checks above and reject malformed selected digests.
                if recorded is not None and (not isinstance(recorded, str)
                        or len(recorded) != 64
                        or any(char not in "0123456789abcdef" for char in recorded)):
                    raise ValueError("invalid_conflict_manifest_digest")
    if identity == "naos_task_claims":
        import naos_task_claims as producer
        from naos_policy import sessions_index_path
        _primitive_source_operand(root, producer.claims_file_path(root, naos_root, policy))
        _primitive_source_operand(root, sessions_index_path(root, naos_root, policy))
    if identity == "naos_policy_overrides":
        import naos_policy_overrides as producer
        directory = state / "policy_overrides.d"
        _primitive_source_operand(root, directory, directory=True)
        map_path = producer.team_operator_map_path(root, naos_root, policy, None)
        _primitive_source_operand(root, map_path)
        team_map, _, _ = producer.load_team_operator_map(map_path)
        scope, _ = producer.resolve_overlay_scope(root=root, explicit_operator_id=None, explicit_team_id=None,
            explicit_operator_overlay_id=None, team_operator_map=team_map)
        directories = [directory] + [directory / "teams" / str(value) for value in scope.get("team_ids", [])]
        if scope.get("operator_overlay_id"):
            directories.append(directory / "operators" / str(scope["operator_overlay_id"]))
        for selected in directories:
            _primitive_source_operand(root, selected, directory=True)
            for pattern in ("*.yaml", "*.yml"):
                for candidate in _glob_paths(root, (*logical_path(root, selected).relative_to(root).parts, pattern)):
                    _primitive_source_operand(root, candidate)
    if identity in {"naos_static_grader", "naos_grader_assessment"}:
        import naos_static_grader as producer
        for key, _, _ in producer.DETERMINISTIC_INPUT_REPORTS:
            _primitive_source_operand(root, report_default_path(root, naos_root, policy, key))
    if identity == "naos_grader_assessment":
        _primitive_source_operand(root, report_default_path(root, naos_root, policy, "static_grader_report"))
        _primitive_source_operand(root, root / "naos/reports/conformance_latest.json")
        _primitive_source_operand(root, report_default_path(root, naos_root, policy, "llm_grader_readiness_report"))
        _primitive_preferred_source(root, [root / ".github/configs/naos_autoresearch.yaml", root / "configs/naos_autoresearch.yaml",
            root / "templates/structural-seeds/configs/naos_autoresearch.yaml"], "templates/structural-seeds/configs/naos_autoresearch.yaml")


def _conflict_input_observation_expected(report: dict[str, Any], current: dict[str, Any], *,
                                         root: Path, profile: str, naos_root: str,
                                         policy: dict[str, Any]) -> dict[str, Any]:
    """Retain only historical counts of currently valid scoped audit observations.

    This is not event authentication or latest-count evidence. Every other
    producer field remains exact; malformed/adverse audit state fails closed.
    """
    import copy
    import naos_audit_log as audit
    names = ["evidence_review_attestations", "evidence_attestation_report", "evidence_pack_report",
             "audit_log_summary_report", "audit_log_events", "session_index", "operator_attribution_report",
             "control_plane_review_items", "control_plane_review_rules"]
    stored, fresh = report.get("input_sources"), current.get("input_sources")
    if (not isinstance(stored, list) or not isinstance(fresh, list)
            or any(not isinstance(row, dict) for row in stored + fresh)
            or [row.get("name") for row in stored] != names
            or [row.get("name") for row in fresh] != names):
        raise ValueError("invalid_conflict_input_observation_inventory")
    result = copy.deepcopy(current)
    for old, new, output in zip(stored, fresh, result["input_sources"]):
        if old["name"] != "audit_log_events":
            if old != new:
                raise ValueError("conflict_input_observation_semantics_changed")
            continue
        if ({k: v for k, v in old.items() if k != "summary"}
                != {k: v for k, v in new.items() if k != "summary"}):
            raise ValueError("conflict_audit_inventory_semantics_changed")
        for row in (old, new):
            counts = row.get("summary")
            if (row.get("path") is not None or row.get("supported") is not True
                    or type(row.get("present")) is not bool
                    or row.get("status") != ("present" if row["present"] else "missing")
                    or row.get("schema") is not None or not isinstance(counts, dict)
                    or set(counts) != {"event_count", "event_files"}
                    or any(type(v) is not int or v < 0 for v in counts.values())
                    or row["present"] != (counts["event_files"] > 0)):
                raise ValueError("invalid_conflict_audit_count_observation")
        if any(new["summary"][key] < old["summary"][key] for key in old["summary"]):
            raise ValueError("conflict_audit_count_decreased")
        actual = audit.build_summary_report(root=root, profile=profile, naos_root=naos_root, policy=policy)
        summary = actual.get("summary", {})
        if (any(actual.get(k) != v for k, v in {"schema": "naos.audit_log_summary.v1",
                "profile": profile, "project_root": str(root), "naos_root": naos_root}.items())
                or summary.get("events") != new["summary"]["event_count"]
                or summary.get("event_files") != new["summary"]["event_files"]
                or any(type(summary.get(k)) is not int or summary[k] != 0 for k in
                       ("invalid_events", "missing_session_id_events", "missing_operator_id_events"))
                or (actual.get("status") != "ready" if new["present"] else actual.get("status") != "no_events")
                or (actual.get("findings") if new["present"] else any(f.get("id") != "audit_log.no_events" for f in actual.get("findings", [])))):
            raise ValueError("conflict_current_audit_unresolved")
        for item in actual.get("event_files", []):
            event_path = Path(item["path"])
            if _safe_file(root, event_path) != "available":
                raise ValueError("unsafe_conflict_audit_event")
            events, invalid = audit.load_event_file(event_path)
            if invalid or any(event.get("project_root") != str(root)
                    or event.get("naos_root") != naos_root or event.get("profile") != profile for event in events):
                raise ValueError("conflict_audit_event_scope_mismatch")
        output["summary"] = copy.deepcopy(old["summary"])
    return result


def _static_input_observation_expected(report: dict[str, Any], current: dict[str, Any], *, assessment: bool = False) -> dict[str, Any]:
    """Preserve exact historical timestamps of registered StaticGrader inputs.

    Only collection timestamps may differ. Every ID, path, presence flag,
    status, schema, count, health field and unknown field must reproduce.
    Raw reports remain unchanged and byte-bound by the caller.
    """
    import copy
    from naos_static_grader import DETERMINISTIC_INPUT_REPORTS
    stored_rows, current_rows = report.get("input_reports"), current.get("input_reports")
    expected_ids = (["static_grader_report", "ai_surface_context_budget_report", "agent_trace_validation_report",
                     "conformance_latest", "autoresearch_config", "llm_grader_readiness_report"] if assessment
                    else [identity for _, identity, _ in DETERMINISTIC_INPUT_REPORTS])
    if (not isinstance(stored_rows, list) or not isinstance(current_rows, list)
            or any(not isinstance(row, dict) for row in stored_rows + current_rows)
            or [row.get("id") for row in stored_rows] != expected_ids
            or [row.get("id") for row in current_rows] != expected_ids):
        raise ValueError("invalid_static_input_observation_inventory")
    result = copy.deepcopy(current)
    for stored, fresh, output in zip(stored_rows, current_rows, result["input_reports"]):
        # Assessment independently collects LLM readiness after StaticGrader.
        # Preserve every other row, including its bound StaticGrader identity.
        if assessment and stored["id"] != "llm_grader_readiness_report":
            if stored != fresh:
                raise ValueError("assessment_input_observation_semantics_changed")
            continue
        for row in (stored, fresh):
            value = row.get("generated_at")
            if value is not None:
                if not isinstance(value, str) or "T" not in value:
                    raise ValueError("invalid_static_input_observation_timestamp")
                instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if instant.tzinfo is None or instant.utcoffset() is None:
                    raise ValueError("invalid_static_input_observation_timestamp")
        if ((stored.get("generated_at") is None) != (fresh.get("generated_at") is None)
                or {key: value for key, value in stored.items() if key != "generated_at"}
                != {key: value for key, value in fresh.items() if key != "generated_at"}):
            raise ValueError("static_input_observation_semantics_changed")
        output["generated_at"] = stored.get("generated_at")
    return result


def _policy_override_audit_source_hashes(report: dict[str, Any]) -> frozenset[str]:
    """Reconstruct only the two exact source-owned report-writer byte variants.

    Policy overrides audits its first write_report before adding audit_log_event.
    The POSIX descriptor writer persists UTF-8 LF, while the portable Windows
    text writer translates LF to CRLF. Accept either exact serialization across
    hosts so a copied artifact does not acquire a host-specific interpretation.
    This never normalizes supplied bytes or changes their recorded digest.
    """
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    return frozenset(
        hashlib.sha256(payload.encode("utf-8")).hexdigest()
        for payload in (text, text.replace("\n", "\r\n"))
    )


def _lite_behavioral_inspection_shape(report: dict[str, Any], profile: str) -> bool:
    """Recognize only inert L0 inspection, never behavioral baseline readiness.

    The missing required conformance finding remains in the raw report. This
    predicate is insufficient alone: callers also bind capability scope, schema,
    canonical bytes, and full current read-only producer reproduction.
    """
    findings = report.get("findings", [])
    inputs = report.get("readiness_inputs", [])
    required = {item.get("id"): item for item in inputs if item.get("required") is True}
    runtime = report.get("runtime_posture", {})
    boundary = report.get("advisory_boundary", {})
    cost = report.get("cost_posture", {})
    return (profile == "lite" and report.get("profile") == "lite"
        and report.get("status") == "not_ready"
        and report.get("baseline_state_present") is False
        and report.get("baseline_state_error") is None
        and report.get("baseline_state") == {}
        and report.get("baseline_validation") == {"status": "not_present", "issues": []}
        and len(findings) == 1
        and findings[0].get("id") == "behavioral_readiness.missing_conformance_latest"
        and findings[0].get("severity") == "warning"
        and findings[0].get("status") == "not_ready"
        and findings[0].get("human_review_required") is True
        and findings[0].get("classification_scope") == "selected_required_report_absent_at_readiness_check"
        and set(required) == {"conformance_latest", "static_grader_report", "grader_assessment_report", "llm_grader_readiness_report"}
        and len(inputs) == len({item.get("id") for item in inputs})
        and required["conformance_latest"].get("present") is False
        and required["conformance_latest"].get("status") == "missing"
        and all(item.get("present") is True and not item.get("contract_issues")
                for key, item in required.items() if key != "conformance_latest")
        and set(runtime) == {"runtime_enabled", "provider_allowed", "external_api_allowed",
            "model_dependency_allowed", "api_keys_allowed", "baseline_auto_create", "scheduler_or_daemon_enabled"}
        and all(value is False for value in runtime.values())
        and set(boundary) == {"readiness_only", "review_input_only", "can_create_baseline", "can_approve",
            "can_certify", "can_prove_compliance", "can_promote_maturity", "can_replace_deterministic_controls", "can_replace_human_review"}
        and all(value is (key in {"readiness_only", "review_input_only"}) for key,value in boundary.items())
        and type(cost.get("cost_usd")) in {int, float} and cost.get("cost_usd") == 0.0
        and set(cost) == {"cost_usd", "cost_incurred_by_default", "external_api_required", "provider_dependency_required", "model_dependency_required", "credential_read_required"}
        and all(value is False for key,value in cost.items() if key != "cost_usd")
        and all(type(report.get("summary", {}).get(key)) is int for key in ("warnings", "total_findings", "blocking", "required", "advisory", "total_impacters"))
        and report.get("summary", {}).get("warnings") == 1
        and report.get("summary", {}).get("total_findings") == 1
        and all(report.get("summary", {}).get(key) == 0 for key in ("blocking", "required", "advisory", "total_impacters")))


def _self_check_primitive_contract(
    check: dict[str, Any], *, root: Path, profile: str, naos_root: str,
    policy: dict[str, Any],
) -> dict[str, Any] | None:
    """Require canonical scope, current read-only reproduction and finite purpose.

    No producer CLI runs here. Raw flags/findings are preserved; these decisions
    are structural observations, never authentication, review or runtime approval.
    """
    identity = check.get("id")
    if identity not in _SELF_CHECK_PRIMITIVES or check.get("returncode") != 0:
        return None
    schema_name, output_key, ceiling = _SELF_CHECK_PRIMITIVES[identity]
    try:
        path = report_default_path(root, naos_root, policy, output_key)
        if _inspection_safe_file(root, path) != "available":
            return None
        reference = logical_path(root, path).relative_to(root).as_posix()
        content = path.read_bytes()
        report = _json_value(path, data=content)
        descriptor = _report(schema_name, output_key, (), ceiling)
        if identity == "naos_external_evidence_ingest":
            descriptor = ReportDescriptor(schema_name, output_key, schema_name + ".schema.json", "naos.external_evidence_ingest.v2", (), ceiling)
        if (not isinstance(report, dict) or _schema_validation(report, descriptor)[0] != "valid"
                or any(report.get(field) != value for field, value in {
                    "profile": profile, "project_root": str(root.resolve()), "naos_root": naos_root,
                }.items())
                or any(check.get(field) != report.get(field) for field in ("status", "summary", "findings"))):
            return None
        _primitive_source_preflight(identity, root, naos_root, policy)
        from naos_report_contracts import validate_current_report
        shared = dict(root=root, profile=profile, naos_root=naos_root, policy=policy)
        informational = identity in {"naos_static_grader", "naos_grader_assessment", "naos_task_claims", "naos_external_evidence_ingest", "naos_evidence_conflicts"}
        lite_inspection = identity == "naos_behavioral_governance_readiness" and _lite_behavioral_inspection_shape(report, profile)
        if not informational and not lite_inspection and report.get("findings"):
            return None
        if not lite_inspection and any(field in report.get("summary", {}) and (type(report["summary"][field]) is not int
               or report["summary"][field] != 0) for field in ("blocking", "required", "warnings")):
            return None
        reasons = []
        purpose_metadata = {}
        if identity == "naos_behavioral_governance_readiness":
            if not lite_inspection:
                return None
            import naos_behavioral_governance_readiness as producer
            import naos_capability_maturity as maturity
            state_path = maturity.resolve_state_path(root, naos_root, policy)
            _primitive_source_operand(root, state_path)
            state = maturity.normalize_state_entries(yaml.safe_load(state_path.read_text()), state_path)
            row = state.get("CAP-BEHAVIORAL-GOVERNANCE-READINESS", {})
            if (row.get("enabled") is not True or row.get("current_maturity") != "L0"
                    or row.get("target_maturity") != "L0" or row.get("waivers")
                    or row.get("evidence_refs")):
                return None
            contracts = maturity.load_capability_contracts(root, naos_root, profile)
            contract = contracts.get("CAP-BEHAVIORAL-GOVERNANCE-READINESS", {})
            if contract.get("profiles", {}).get("lite", {}).get("target_maturity") != "L0" or contract.get("profiles", {}).get("lite", {}).get("enforcement") != "advisory":
                return None
            contract_path = Path(contract["_path"])
            _primitive_source_operand(root if contract_path.is_relative_to(root) else kit_root(), contract_path)
            for selected in (root / ".github/agents/naos-conformance.agent.md", producer.conformance_runner_path(root)):
                _primitive_source_operand(root, selected)
                if selected.exists():
                    return None
            rules_path, rules_source = producer.resolve_rules_path(root, naos_root, policy)
            baseline = producer.resolve_baseline_path(root, naos_root, policy)
            if rules_source != "project":
                return None
            _primitive_source_operand(root, rules_path)
            _primitive_source_operand(root, baseline)
            rules = producer.load_yaml_mapping(rules_path)
            seed_path = producer.default_rules_template()
            _primitive_source_operand(kit_root(), seed_path)
            seed = producer.load_yaml_mapping(seed_path)
            safety_keys = {"version", "capability_id", "enabled", "readiness_only", "review_input_only",
                "runtime_enabled", "provider_allowed", "external_api_allowed", "model_dependency_allowed",
                "api_keys_allowed", "scheduler_or_daemon_enabled", "can_create_baseline", "can_approve",
                "can_certify", "can_prove_compliance", "can_promote_maturity", "can_replace_deterministic_controls",
                "can_replace_human_review", "required_reports", "optional_reports", "status_policy", "advisory_boundary", "not_claimed"}
            if (any(json.dumps(rules.get(key), sort_keys=True) != json.dumps(seed.get(key), sort_keys=True) for key in safety_keys)
                    or rules.get("baseline_state", {}).get("auto_create") is not False
                    or policy.get("paths", {}).get("conformance_battery") is not None):
                return None
            for key in producer.rules_report_keys(rules, "required_reports", producer.DEFAULT_REQUIRED_REPORTS) + producer.rules_report_keys(rules, "optional_reports", producer.DEFAULT_OPTIONAL_REPORTS):
                _primitive_source_operand(root, producer.report_path_for(root, naos_root, policy, key))
            expected = producer.build_report(root, naos_root, profile, policy, rules_path, rules_source, baseline)
            reasons, _ = validate_current_report(report, schema_name=schema_name, source_hash_field="rules_hash", expected=lambda: expected)
            accepted = _lite_behavioral_inspection_shape(expected, profile)
            purpose_metadata.update(baseline_readiness_established=False,
                behavioral_adequacy_established=False, human_review_required=True,
                applicability="Lite enabled L0-to-L0 inspection without baseline or conformance")
        elif identity == "naos_evidence_conflicts":
            import naos_evidence_conflicts as producer
            current = _conflict_input_observation_expected(report, producer.build_report(**shared), **shared)
            reasons, _ = validate_current_report(report, schema_name=schema_name, source_hash_field="",
                expected=lambda: current)
            manifest_path = report_default_path(root, naos_root, policy, "evidence_attestation_report")
            purpose_metadata["artifact_digest_basis"] = {
                "purpose": "selected_manifest_collection_snapshot_else_live_artifact",
                "manifest_reference": logical_path(root, manifest_path).relative_to(root).as_posix(),
                "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else None,
                "latest_artifact_bytes_verified": False,
                "audit_event_count_basis": "historical_collection_observation_current_valid_scope_checked",
            }
            notices = report.get("findings", [])
            coverage_only = (len(notices) == 1
                and notices[0].get("id") == "evidence_conflicts.unsupported_source.evidence_pack_report"
                and notices[0].get("severity") == "advisory" and notices[0].get("status") == "advisory"
                and notices[0].get("classification_scope") == "parser_coverage_observation"
                and notices[0].get("evidence_classification") == "confirmed"
                and len(report.get("unsupported_sources", [])) == 1
                and report["unsupported_sources"][0].get("name") == "evidence_pack_report")
            accepted = (report.get("attestation_count", 0) > 0
                and report.get("conflict_count") == 0 and not report.get("conflict_type_counts")
                and all(not report.get(field) for field in ("conflicts", "stale_attestations", "duplicate_attestations",
                    "unrouted_conflicts", "separation_of_duties_warnings", "missing_reviewer_metadata",
                    "missing_operator_attribution", "secret_like_input_fields"))
                and ((report.get("status") == "advisory" and coverage_only)
                     or (report.get("status") == "ready" and not notices and not report.get("unsupported_sources"))))
        elif identity == "naos_external_evidence_ingest":
            import naos_external_evidence_ingest as producer
            source = report.get("scans", {}).get("source")
            if source is not None:
                if not isinstance(source, str) or not source.strip():
                    return None
                _primitive_source_operand(root, Path(source))
            selection = report.get("scans", {}).get("source_selection", {})
            replay_source = None if selection.get("basis") in {"declared_local_source", "no_source_declaration"} else source
            reasons, _ = validate_current_report(report, schema_name=schema_name, source_hash_field="",
                expected=lambda: producer.build_report(root, profile, naos_root, policy, replay_source, "sarif"))
            accepted = ((source is None and report.get("status") == "advisory"
                         and report.get("summary", {}).get("source_configured") is False
                         and report.get("summary", {}).get("source_present") is False
                         and len(report.get("findings", [])) == 1
                         and report["findings"][0].get("id") == "external_evidence_ingest.source_missing"
                         and report["findings"][0].get("severity") == "advisory"
                         and report["findings"][0].get("status") == "not_configured")
                        or (source is not None and report.get("status") == "pass" and not report.get("findings")
                            and report.get("summary", {}).get("source_configured") is True
                            and report.get("summary", {}).get("source_present") is True))
            if source is not None:
                summary = report.get("summary", {})
                assessment = report.get("assessment", {})
                findings = report.get("findings", [])
                nonempty_ingest = (report.get("status") == "advisory"
                    and summary.get("source_configured") is True and summary.get("source_present") is True
                    and type(summary.get("runs")) is int and summary["runs"] > 0
                    and type(summary.get("results")) is int and summary["results"] > 0
                    and len(report.get("result_records", [])) == summary["results"]
                    and summary.get("verification_status") == "unverified"
                    and assessment.get("source_execution_status") in {"reported_success", "unknown"}
                    and assessment.get("result_posture") == "results_reported"
                    and assessment.get("coverage_status") == "not_declared"
                    and len(findings) == 1
                    and findings[0].get("id") == "external_evidence_ingest.unverified_external_results"
                    and findings[0].get("severity") == "advisory"
                    and findings[0].get("status") == "review_required")
                accepted = accepted or nonempty_ingest
                ceiling = "unverified_local_sarif_ingest_structure_only"
        elif identity == "naos_task_claims":
            import naos_task_claims as producer
            claims_path = producer.claims_file_path(root, naos_root, policy)
            data, load_findings = producer.load_claims(claims_path)
            operator, operator_findings = producer.resolve_operator(root, None)
            session_id = producer.latest_session_id(root, naos_root, policy)
            branch = producer.current_branch(root)
            now = producer.utc_now_text()
            data, action_status, action_findings, _, _ = producer.apply_action(
                root=root, action="list", data=data, task_id=None, operator=operator, session_id=session_id,
                branch=branch, now_text=now, ttl_hours=producer.default_ttl_hours(policy))
            expected = producer.build_report(**shared, action="list", task_id=None, session_id=session_id,
                operator=operator, branch=branch, claims_path=claims_path, data=data, load_findings=load_findings,
                operator_findings=operator_findings, task_finding=None, action_findings=action_findings,
                action_status=action_status, audit_result=None, generated_at=now)
            reasons, _ = validate_current_report(report, schema_name=schema_name, source_hash_field="", expected=lambda: expected)
            accepted = (report.get("status") in {"advisory", "no_claims"}
                        and report.get("summary", {}).get("action") == "list"
                        and len(report.get("findings", [])) == 1
                        and report["findings"][0].get("id") == "task_claims.coordination_metadata_only"
                        and report["findings"][0].get("severity") == "advisory"
                        and all(report.get(field) == 0 for field in ("stale_claim_count", "conflicting_claim_count")))
        elif identity == "naos_ai_component_inventory":
            import naos_ai_component_inventory as producer
            reasons = producer.validate_inventory_report(report=report, **shared)
            accepted = report.get("status") == "current" and report.get("human_review_required") is False
        elif identity == "naos_model_provider_policy":
            import naos_model_provider_policy as producer
            reasons, _ = producer.validate_report(report=report, **shared)
            accepted = (report.get("status") == "declaration_only"
                        and report.get("runtime_enabled") is False
                        and report.get("provider_calls_allowed") is False)
        elif identity == "naos_model_telemetry_evidence":
            import naos_model_telemetry_evidence as producer
            reasons, _ = producer.validate_report(report=report, **shared)
            declaration_path, _ = producer.resolve_declaration_path(root, naos_root, policy)
            declaration = producer.load_yaml_mapping(declaration_path)
            accepted = (all(field not in declaration or declaration[field] is False for field in producer.AUTHORITY_FIELDS)
                        and ((declaration.get("enabled") is False and declaration.get("telemetry_declared") is False
                              and report.get("status") == "not_configured" and report.get("enabled") is False and report.get("telemetry_declared") is False)
                             or (declaration.get("enabled") is True and declaration.get("telemetry_declared") is True
                                 and report.get("status") == "pass" and report.get("enabled") is True and report.get("telemetry_declared") is True
                                 and report.get("summary", {}).get("records", 0) > 0))
                        and all(report.get(field) is False for field in (
                            "runtime_enabled", "provider_calls_allowed", "gateway_calls_allowed", "mcp_allowed",
                            "memory_allowed", "payload_capture_allowed", "credential_capture_allowed", "tool_mutation_allowed")))
            if report.get("status") == "pass":
                ceiling = "declared_local_telemetry_metadata"
        elif identity == "naos_llm_grader_readiness":
            import naos_llm_grader_readiness as producer
            rules_path, _ = producer.resolve_rules_path(root, naos_root, policy, None)
            reasons, _ = validate_current_report(
                report, schema_name=schema_name, source_hash_field="rules_hash",
                expected=lambda: producer.build_report(root, naos_root, profile, policy, rules_path),
            )
            rules = producer.load_yaml_mapping(rules_path)
            accepted = (report.get("status") in {"readiness_only", "disabled"}
                        and rules.get("enabled") is False and rules.get("future_enablement_requested") is False
                        and report.get("summary", {}).get("future_enablement_requested") is False
                        and all(report.get(field) is False for field in (
                            "runtime_enabled", "provider_allowed", "external_api_allowed", "model_dependency_allowed", "api_keys_allowed"))
                        and report.get("cost_posture", {}).get("cost_usd") == 0
                        and report.get("cost_posture", {}).get("cost_incurred_by_default") is False)
        elif identity == "naos_agent_trace_validate":
            import naos_agent_trace_validate as producer
            trace = root / naos_root / str(policy.get("paths", {}).get("agent_trace_events") or "agent_trace_events.yaml")
            reasons, _ = validate_current_report(
                report, schema_name=schema_name, source_hash_field="",
                expected=lambda: producer.build_report(trace_file=trace, **shared),
            )
            accepted = (report.get("trace_file_present") is True and report.get("invalid_event_count") == 0
                        and ((report.get("status") == "no_events" and report.get("event_count") == 0)
                             or (report.get("status") == "ready" and report.get("event_count", 0) > 0
                                 and report.get("valid_event_count") == report["event_count"])))
            if report.get("status") == "ready":
                ceiling = "valid_declared_trace_inspection"
        elif identity == "naos_policy_overrides":
            import naos_policy_overrides as producer
            expected, _ = producer.build_merge_report(
                **shared, override_dir=root / naos_root / "policy_overrides.d",
                team_operator_map_path_value=producer.team_operator_map_path(root, naos_root, policy, None),
                write_effective_policy=False,
                effective_policy_path=report_default_path(root, naos_root, policy, "effective_policy"),
            )
            # The CLI adds one historical observation after writing the merge.
            # Validate that exact observation, never arbitrary extra report fields.
            if "audit_log_event" in report:
                import naos_audit_log as audit
                observation = report["audit_log_event"]
                if (not isinstance(observation, dict) or set(observation) != {"status", "event_file", "findings"}
                        or observation["status"] != "written" or observation["findings"]):
                    return None
                event_path = Path(observation["event_file"])
                if _safe_file(root, event_path) != "available":
                    return None
                lines = event_path.read_bytes().splitlines()
                if len(lines) != 1:
                    return None
                event = _json_value(event_path, data=lines[0])
                pre_audit = {field: value for field, value in report.items() if field != "audit_log_event"}
                pre_audit_hashes = _policy_override_audit_source_hashes(pre_audit)
                audit_root = audit.audit_log_root_path(root, naos_root, policy)
                if (audit.validate_audit_event(event) or event_path not in audit.event_file_paths(audit_root, event)
                        or event.get("event_type") != "policy_override_merged"
                        or event.get("source_report_path") != str(path)
                        or event.get("source_report") != report["schema"]
                        or event.get("source_report_hash") not in pre_audit_hashes
                        or any(event.get(field) != report[field] for field in ("profile", "project_root", "naos_root"))
                        or event.get("event_payload_summary") != audit.summarize_source_report(report, path)
                        or event.get("event_payload_hash") != audit.hash_json(event["event_payload_summary"])):
                    return None
                expected["audit_log_event"] = observation
            reasons, _ = validate_current_report(report, schema_name=schema_name, source_hash_field="",
                                                  expected=lambda: expected)
            accepted = (report.get("status") in {"no_overrides", "ready"}
                        and report.get("effective_policy_path") is None
                        and not report.get("protected_invariant_violations") and not report.get("conflicts"))
        else:
            import naos_agent_trace_validate as trace_producer
            import naos_static_grader as static_producer
            from autoresearch.graders.static import FUTURE_BEHAVIORAL_DIMENSIONS
            trace_path = report_default_path(root, naos_root, policy, "agent_trace_validation_report")
            if _safe_file(root, trace_path) != "available":
                return None
            trace_report = _json_value(trace_path)
            trace_file = root / naos_root / str(policy.get("paths", {}).get("agent_trace_events") or "agent_trace_events.yaml")
            trace_reasons, _ = validate_current_report(
                trace_report, schema_name="agent_trace_validation", source_hash_field="",
                expected=lambda: trace_producer.build_report(trace_file=trace_file, **shared),
            )
            if trace_reasons or trace_report.get("findings"):
                return None
            if identity == "naos_static_grader":
                expected = static_producer.build_report(trace_report_path=trace_path, trace_file_path=trace_file, **shared)
                expected = _static_input_observation_expected(report, expected)
            else:
                import naos_grader_assessment as producer
                if report.get("mode") != "assess":
                    return None
                static_path = report_default_path(root, naos_root, policy, "static_grader_report")
                static_report = _json_value(static_path)
                static_expected = static_producer.build_report(trace_report_path=trace_path, trace_file_path=trace_file, **shared)
                static_expected = _static_input_observation_expected(static_report, static_expected)
                static_reasons, _ = validate_current_report(
                    static_report, schema_name="static_grader_report", source_hash_field="", expected=lambda: static_expected)
                if static_reasons:
                    return None
                expected = producer.build_report(mode="assess", static_report_path=static_path,
                    trace_report_path=trace_path, trace_file_path=trace_file, baseline_path=None, **shared)
                expected = _static_input_observation_expected(report, expected, assessment=True)
            reasons, _ = validate_current_report(report, schema_name=schema_name, source_hash_field="", expected=lambda: expected)
            purpose_metadata["input_timestamp_basis"] = "historical_collection_observation_all_semantic_fields_reproduced"
            expected_ids = {"STATICGRADER_UNSUPPORTED_" + dimension for dimension in FUTURE_BEHAVIORAL_DIMENSIONS}
            findings = report.get("findings", [])
            optional_missing = [item for item in findings if item.get("id") == "STATICGRADER_MISSING_DETERMINISTIC_REPORTS"]
            if optional_missing:
                inputs = expected.get("input_reports", []) if identity == "naos_static_grader" else static_expected.get("input_reports", [])
                missing = [item for item in inputs if item.get("present") is False]
                if (len(optional_missing) != 1 or not missing
                        or any(item.get("source_path_exists") is not False for item in missing)
                        or optional_missing[0].get("classification_scope") != "optional_report_paths_absent_at_input_collection"
                        or optional_missing[0].get("severity") != "advisory"
                        or optional_missing[0].get("status") != "missing_deterministic_input_report"):
                    return None
                findings = [item for item in findings if item.get("id") != "STATICGRADER_MISSING_DETERMINISTIC_REPORTS"]
            health = [item for item in findings if item.get("id") == "STATICGRADER_AI_SURFACE_HEALTH_REVIEW"]
            if health:
                if (len(health) != 1 or health[0].get("severity") != "advisory"
                        or health[0].get("status") != "ai_surface_health_review_required"
                        or health[0].get("evidence_classification") != "hypothesized"
                        or health[0].get("classification_scope") != "possible_baseline_interpretability_effect"
                        or health[0].get("human_review_required") is not True):
                    return None
                budget_path = report_default_path(root, naos_root, policy, "ai_surface_context_budget_report")
                budget = classify_evidence(root, logical_path(root, budget_path).relative_to(root).as_posix(),
                    profile=profile, naos_root=naos_root, policy=policy, consumer="gate")
                review = budget.get("configuration_posture_review", {})
                if (budget.get("report_key") != "ai_surface_context_budget"
                        or budget.get("requirement_outcome") != "satisfied"
                        or review.get("status") != "recorded"
                        or _safe_file(root, budget_path) != "available"
                        or hashlib.sha256(budget_path.read_bytes()).hexdigest() != budget.get("content_sha256")):
                    return None
                purpose_metadata["budget_posture_review"] = {
                    "reference": logical_path(root, budget_path).relative_to(root).as_posix(),
                    "content_sha256": budget["content_sha256"], "review": review,
                    "scope": "structural_budget_posture_only",
                    "baseline_interpretability": "hypothesized_unresolved",
                    "behavioral_adequacy_established": False, "human_review_required": True,
                }
                findings = [item for item in findings if item.get("id") != "STATICGRADER_AI_SURFACE_HEALTH_REVIEW"]
            accepted = (report.get("status") == "advisory" and len(findings) == len(expected_ids)
                        and {item.get("id") for item in findings} == expected_ids
                        and all(item.get("severity") == "advisory"
                                and item.get("status") == "unsupported_behavioral_dimension" for item in findings))
        if not accepted or reasons or path.read_bytes() != content:
            return None
        return {"check_id": identity, "report_key": schema_name, "reference": reference,
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "current_source_check": "producer_reproduction", "claim_ceiling": ceiling,
                "producer_status": report["status"],
                "producer_human_review_required": report.get("human_review_required"),
                "disposition": "structural_observation", "human_review_recorded": False,
                **purpose_metadata}
    except (ImportError, OSError, ValueError, TypeError, KeyError, UnicodeError, yaml.YAMLError):
        return None


def _apply_configuration_self_check_review(
    result: dict[str, Any], report: dict[str, Any], *, root: Path,
    profile: str, naos_root: str, policy: dict[str, Any],
    requirement: dict[str, Any], consumer: str,
) -> None:
    """Resolve exact reviewed postures and three existing optional memory contracts.

    Raw aggregate/nested evidence is unchanged. Every other unclean check,
    finding or inconsistent aggregate remains unresolved.
    """
    from naos_policy import finding_counts, status_from_counts
    supported = {
        "naos_semantic_candidate_readiness": "semantic_candidate_layer",
        "naos_graph_context_readiness": "graph_context_readiness",
        "naos_local_context_index": "local_context_index",
        "naos_ai_surface_budget": "ai_surface_context_budget",
        "naos_memory_context_readiness": "memory_context_readiness",
        "naos_memory_provider_access": "memory_provider_access",
        "naos_memory_use_policy": "memory_use_policy",
    }
    # These exact existing contracts may use only the current gate's declared
    # requirements. N/A additionally needs current local disabled configuration;
    # status strings or a parent's optional flag never establish applicability.
    optional_memory = {"memory_context_readiness", "memory_provider_access", "memory_use_policy"}
    checks = report.get("checks")
    if (consumer == "control_plane" or requirement.get("require_current_source") is True
            or result["validation"] != "valid" or result["scope"] != "matched"
            or not isinstance(checks, list) or not checks):
        return
    identities = [check.get("id") for check in checks]
    if len(identities) != len(set(identities)):
        return
    all_findings = [finding for check in checks for finding in check.get("findings", [])]
    expected_summary = {**finding_counts(all_findings), "checks": len(checks)}
    if report.get("summary") != expected_summary or report.get("status") != status_from_counts(expected_summary):
        return
    decisions = []
    descriptor_decisions = []
    primitive_decisions = []
    reviewed_budget_warnings = 0
    for check in checks:
        key = supported.get(check.get("id"))
        if key is None:
            if check.get("id") in _SELF_CHECK_PRIMITIVES:
                decision = _self_check_primitive_contract(check, root=root, profile=profile, naos_root=naos_root, policy=policy)
                if decision is None:
                    result["requirement_outcome"] = "unresolved"
                    result["producer_outcome"] = "adverse"
                    result["reason_codes"].append("self_check_primitive_contract_unresolved")
                    return
                primitive_decisions.append(decision)
                continue
            _, nested_adverse, nested_review = _source_findings(
                check, root / result["reference"], root,
            )
            nested_summary = check.get("summary", {})
            if any(
                name in nested_summary
                and (type(nested_summary[name]) is not int or nested_summary[name] != 0)
                for name in ("blocking", "required", "required_missing", "errors",
                             "warning", "warnings", "review_required", "advisory",
                             "total_findings")
            ):
                return
            if (check.get("returncode", 0) != 0
                    or check.get("status") not in {"pass", "ready", "not_applicable"}
                    or check.get("findings") or nested_adverse or nested_review):
                return
            continue
        descriptor = REPORT_REGISTRY[key]
        gate_context = requirement.get("_self_check_gate_context", {})
        declared_requirement = None
        try:
            path = report_default_path(root, naos_root, policy, descriptor.output_key)
            reference = logical_path(root, path).relative_to(root).as_posix()
            nested_requirement = requirement
            if key in optional_memory:
                # This bounded inert path covers the observed empty findings
                # contracts only; unknown/advisory or inconsistent counters
                # cannot acquire an automatic disposition through optionality.
                nested_summary = check.get("summary", {})
                if check.get("findings") or any(
                    name in nested_summary
                    and (type(nested_summary[name]) is not int or nested_summary[name] != 0)
                    for name in ("blocking", "required", "required_missing", "errors",
                                 "warning", "warnings", "review_required", "advisory",
                                 "total_findings")
                ):
                    return
                if consumer != "gate" or not isinstance(gate_context, dict):
                    return
                declarations = gate_context.get("evidence_requirements")
                if (not isinstance(declarations, dict) or reference not in declarations
                        or not isinstance(declarations[reference], dict)
                        or not isinstance(gate_context.get("gate_id"), str)):
                    return
                declared_requirement = declarations[reference]
                nested_requirement = {
                    **requirement, **declared_requirement,
                    "optional": declared_requirement.get("optional") is True,
                }
            classified = classify_evidence(
                root, reference, profile=profile, naos_root=naos_root,
                policy=policy,
                requirement=nested_requirement,
                consumer=consumer,
            )
            review = classified.get("configuration_posture_review", {})
            accepted = (classified["requirement_outcome"] in {"satisfied", "not_applicable"}
                        if key in optional_memory else
                        classified["requirement_outcome"] == "satisfied" and review.get("status") == "recorded")
            if (classified.get("report_key") != key or not accepted
                    or _inspection_safe_file(root, path) != "available"):
                return
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != classified["content_sha256"]:
                return
            current = _json_value(path, data=content)
            if (check.get("returncode") != 0 or any(
                    check.get(field) != current.get(field)
                    for field in ("status", "summary", "findings"))):
                return
            if key in optional_memory:
                # The exact original descriptor result explains satisfied/N/A;
                # it does not pretend a human review was recorded for memory.
                descriptor_decisions.append({"check_id": check["id"], "gate_id": gate_context["gate_id"],
                                             "declared_requirement": declared_requirement,
                                             "evidence_result": classified})
            else:
                if key == "ai_surface_context_budget":
                    reviewed_budget_warnings += current["summary"]["warnings"]
                decisions.append({"check_id": check["id"], "report_key": key,
                                  "reference": reference, "content_sha256": classified["content_sha256"],
                                  "review": review})
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            return
    if (not decisions and not descriptor_decisions and not primitive_decisions) or any(
            expected_summary[field] for field in ("blocking", "required")) or expected_summary["warnings"] != reviewed_budget_warnings:
        return
    _generation_age(result, root / result["reference"], report, requirement)
    if result["generation_age"]["status"] not in {"within_window", "not_enforced"}:
        return
    # This is a consumer decision, not a rewritten producer result/status.
    result["requirement_outcome"] = "satisfied"
    result["human_review_required"] = (result["human_review_required"] or bool(decisions)
                                       or any(item["producer_human_review_required"] is True for item in primitive_decisions))
    result["producer_outcome"] = "review_required" if decisions else "passed"
    result["reason_codes"] = [code for code in result["reason_codes"] if code != "subcheck_unresolved"]
    if decisions:
        result["reason_codes"].append("configuration_posture_nested_reviews_recorded")
        result["configuration_posture_review_checks"] = decisions
    if descriptor_decisions:
        result["reason_codes"].append("self_check_existing_descriptor_contracts_satisfied")
        result["self_check_descriptor_checks"] = descriptor_decisions
    if primitive_decisions:
        result["reason_codes"].append("self_check_primitive_contracts_satisfied")
        result["self_check_primitive_contracts"] = primitive_decisions


def classify_evidence(
    root: Path, reference: str, *, profile: str, naos_root: str,
    policy: dict[str, Any], requirement: dict[str, Any] | None = None,
    consumer: str = "gate",
) -> dict[str, Any]:
    """Classify one declared reference; globs require every selected candidate."""
    requirement = requirement or {}
    if consumer not in {"gate", "maturity", "maturity_support", "pack", "control_plane"}:
        raise ValueError("unsupported evidence consumer")
    result = _result(reference)
    parts = _safe_parts(reference)
    if parts is None:
        result["availability"] = "unsafe_path"
        result["reason_codes"].append("unsafe_reference")
        return result
    root = root.resolve(strict=True)
    globbed = any(any(ch in part for ch in "*?[") for part in parts)
    try:
        paths = _glob_paths(root, parts) if globbed else [root.joinpath(*parts)]
        if globbed:
            from naos_self_check_inspection import inspection_candidates
            paths = inspection_candidates(root, reference, paths)
    except (OSError, ValueError):
        result["validation"] = "unsupported"
        result["reason_codes"].append("unsupported_glob")
        return result
    if not paths:
        result["reason_codes"].append("no_glob_matches")
        return result
    candidates: list[dict[str, Any]] = []
    for path in paths:
        candidate_ref = logical_path(root, path).relative_to(root).as_posix()
        descriptor, current_output = _descriptor_for(root, candidate_ref, naos_root, policy, consumer=consumer)
        candidates.append(_classify_one(
            root, candidate_ref, path, descriptor, current_output, profile, naos_root, policy, requirement, consumer,
        ))
    if not globbed:
        return candidates[0]
    result["candidates"] = candidates
    result["resolved_paths"] = [item["reference"] for item in candidates]
    result["report_key"] = candidates[0]["report_key"] if len({c["report_key"] for c in candidates}) == 1 else None
    result["expected_schema"] = candidates[0]["expected_schema"] if len({c["expected_schema"] for c in candidates}) == 1 else None
    for dimension, adverse_order in (
        ("availability", ("unsafe_path", "unreadable", "not_regular_file", "missing", "available")),
        ("validation", ("invalid", "unsupported", "not_evaluated", "valid")),
        ("scope", ("mismatched", "not_established", "not_applicable", "matched")),
        ("producer_outcome", ("adverse", "unknown", "review_required", "not_run", "not_applicable", "passed")),
    ):
        result[dimension] = next((state for state in adverse_order if any(c[dimension] == state for c in candidates)), adverse_order[0])
    result["applicability"] = "not_applicable" if all(c["applicability"] == "not_applicable" for c in candidates) else "applicable"
    result["freshness"] = "not_applicable" if all(c["freshness"] == "not_applicable" for c in candidates) else "not_established"
    result["requirement_outcome"] = (
        "not_applicable" if all(c["requirement_outcome"] == "not_applicable" for c in candidates)
        else "satisfied" if all(c["requirement_outcome"] == "satisfied" for c in candidates)
        else "unresolved"
    )
    result["human_review_required"] = any(c["human_review_required"] for c in candidates)
    result["source_findings"] = [finding for c in candidates for finding in c["source_findings"]]
    result["reason_codes"] = sorted({code for c in candidates for code in c["reason_codes"]})
    result["claim_ceiling"] = candidates[0]["claim_ceiling"] if len({c["claim_ceiling"] for c in candidates}) == 1 else "mixed"
    result["content_sha256"] = candidates[0]["content_sha256"] if len(candidates) == 1 else None
    ages = [c["generation_age"]["status"] for c in candidates]
    result["generation_age"] = {"status": next((s for s in ("stale", "unknown", "within_window", "not_enforced") if s in ages), "unknown"), "basis": "selected_candidates", "timestamp": None}
    return result


def reproduce_control_plane_source(key: str, *, root: Path, profile: str,
                                   naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    """Reproduce exactly one trusted local-only family, without writing a sink.

    This proves current producer semantics, not visual adequacy, human approval,
    provider execution, or arbitrary evidence artifact content equivalence.
    """
    import importlib
    descriptor = CONTROL_PLANE_REPORT_REGISTRY[key]
    relative = policy.get("paths", {}).get(descriptor.optional_rules_key)
    if not isinstance(relative, str) or _safe_parts(relative, glob_allowed=False) is None:
        raise ValueError("current_source_unsafe_declaration")
    _primitive_source_operand(root, root / naos_root, directory=True)
    local = root / naos_root / relative
    _primitive_source_operand(root, local)
    producer = importlib.import_module("naos_" + key)
    resolver = producer.resolve_taxonomy_path if key == "failure_mode_posture" else producer.resolve_declaration_path
    selected, source = resolver(root, naos_root, policy)
    _primitive_source_operand(root if source == "project" else kit_root(), selected)
    if key == "opencode_config_hygiene":
        for ref in ("AGENTS.md", "opencode.json", "opencode.jsonc", ".opencode/config.yaml", ".opencode/config.yml"):
            _primitive_source_operand(root, root / ref)
        for ref in ("agents", "commands", "modes", "plugins", "skills", "tools", "themes"):
            if _safe_local_tree_has_files(root, root / ".opencode" / ref) is None:
                raise ValueError("current_source_unsafe_opencode_tree")
        _primitive_source_operand(root, report_default_path(root, naos_root, policy, "model_provider_policy_report"))
    if key == "failure_mode_observations":
        declaration = producer.load_yaml_mapping(selected)
        for entry in declaration.get("source_reports", []):
            if not isinstance(entry, dict) or entry.get("enabled") is False:
                continue
            if entry.get("path_key"):
                candidates = [report_default_path(root, naos_root, policy, entry["path_key"])]
            else:
                ref = entry.get("path")
                parts = _safe_parts(ref) if isinstance(ref, str) else None
                if parts is None:
                    raise ValueError("current_source_unsafe_observation_reference")
                candidates = _glob_paths(root, parts) if any(any(c in part for c in "*?[") for part in parts) else [root.joinpath(*parts)]
            for candidate in candidates:
                _primitive_source_operand(root, candidate)
    arguments = dict(root=root, profile=profile, naos_root=naos_root, policy=policy, collect_provenance=False)
    if key == "failure_mode_posture":
        arguments.update(taxonomy_path=selected, taxonomy_source=source)
    else:
        arguments.update(declaration_path=selected, declaration_source=source)
    if key == "failure_mode_observations":
        arguments["output_path"] = report_default_path(root, naos_root, policy, descriptor.output_key)
    return producer.build_report(**arguments)


def _control_plane_projection(report: dict[str, Any]) -> dict[str, Any]:
    """Collection time and operator attribution are preserved, not source facts.

    Raw provenance stays schema-validated and is returned to the consumer;
    changing the operator does not make unchanged deterministic inputs stale.
    """
    return {key: value for key, value in report.items() if key not in {"generated_at", "generated_by"}}


def classify_control_plane_report(
    root: Path, reference: str, *, profile: str, naos_root: str,
    policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return a classified four-family source and its exact validated bytes.

    A second read is accepted only when its digest matches the classified
    content. This keeps downstream routing bound to the artifact it assessed.
    """
    evidence = classify_evidence(root, reference, profile=profile, naos_root=naos_root,
                                 policy=policy, requirement={"optional": True},
                                 consumer="control_plane")
    descriptor = CONTROL_PLANE_REPORT_REGISTRY.get(evidence["report_key"])
    if descriptor is None:
        return evidence, None
    root = root.resolve(strict=True)
    declaration_state = _control_plane_declaration_state(root, naos_root, policy, descriptor)
    if evidence["declaration_state"] != declaration_state:
        evidence["applicability"] = "applicable"
        evidence["applicability_reason"] = "declaration_changed_during_classification"
        evidence["applicability_source"] = "current_local_rules"
        if evidence["scope"] == "not_applicable":
            evidence["scope"] = "not_established"
        if evidence["freshness"] == "not_applicable":
            evidence["freshness"] = "not_established"
        evidence["producer_outcome"] = "unknown"
        evidence["requirement_outcome"] = "unresolved"
        evidence["reason_codes"].append("declaration_changed_during_classification")
        evidence["declaration_state"] = declaration_state
        return evidence, None
    if declaration_state == "invalid":
        evidence["requirement_outcome"] = "unresolved"
        evidence["reason_codes"].append("current_source_declaration_invalid")
        return evidence, None
    if evidence["availability"] != "available" or evidence["validation"] != "valid" or evidence["scope"] != "matched":
        return evidence, None
    path = root.joinpath(*PurePosixPath(reference).parts)
    from naos_self_check_inspection import inspection_input_path
    path = inspection_input_path(root, naos_root, path)
    if _inspection_safe_file(root, path) != "available":
        evidence["validation"] = "invalid"
        evidence["requirement_outcome"] = "unresolved"
        evidence["reason_codes"].append("content_changed_after_classification")
        return evidence, None
    try:
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != evidence["content_sha256"]:
            raise ValueError("content_changed_after_classification")
        report = _json_value(path, data=content)
    except (OSError, UnicodeError, ValueError, TypeError):
        evidence["validation"] = "invalid"
        evidence["requirement_outcome"] = "unresolved"
        evidence["reason_codes"].append("content_changed_after_classification")
        return evidence, None
    if not isinstance(report, dict):
        evidence["validation"] = "invalid"
        evidence["requirement_outcome"] = "unresolved"
        evidence["reason_codes"].append("content_changed_after_classification")
        return evidence, None
    if evidence["producer_outcome"] == "passed" and (
        declaration_state != "active" or report.get("enabled") is not True
    ):
        evidence["producer_outcome"] = "unknown"
        evidence["requirement_outcome"] = "unresolved"
        evidence["reason_codes"].append("declaration_report_conflict")
    if declaration_state == "active":
        try:
            current = reproduce_control_plane_source(descriptor.key, root=root,
                profile=profile, naos_root=naos_root, policy=policy)
            if _control_plane_projection(report) != _control_plane_projection(current):
                evidence["freshness"] = "stale"
                evidence["requirement_outcome"] = "unresolved"
                evidence["reason_codes"].append("current_source_producer_mismatch")
            else:
                evidence["freshness"] = "current"
            evidence["freshness_basis"] = "actual_read_only_producer_reproduction"
            if (_inspection_safe_file(root, path) != "available"
                    or hashlib.sha256(path.read_bytes()).hexdigest() != evidence["content_sha256"]
                    or _control_plane_declaration_state(root, naos_root, policy, descriptor) != declaration_state):
                evidence["freshness"] = "not_established"
                evidence["requirement_outcome"] = "unresolved"
                evidence["reason_codes"].append("current_source_changed_during_reproduction")
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, yaml.YAMLError):
            evidence["freshness"] = "not_established"
            evidence["requirement_outcome"] = "unresolved"
            evidence["reason_codes"].append("current_source_reproduction_unavailable")
    return evidence, report
