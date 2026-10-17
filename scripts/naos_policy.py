#!/usr/bin/env python3
"""Shared file-first policy helpers for standalone NAOS validators."""

from __future__ import annotations

import json
from collections import OrderedDict
from threading import RLock
from copy import deepcopy
import os
import getpass
import unicodedata
import re
import secrets
import stat
import sys
import subprocess
import errno
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


# Only explicit operand readers opt in. Every call receives freshly read bytes
# or text. Cached graphs are private; exceptions and observations are not cached.
# Runtime code/state monkeypatches inside existing loader callables are outside
# this contract; registered constructor/resolver changes bypass memoization.
_OPERAND_YAML_MAX_INPUT_BYTES = 256 * 1024
_OPERAND_YAML_MAX_TOTAL_BYTES = 2 * 1024 * 1024
_OPERAND_YAML_MAX_ENTRIES = 128
_OPERAND_YAML_CACHE = OrderedDict()
_OPERAND_YAML_CACHE_BYTES = 0
_OPERAND_YAML_LOCK = RLock()


def _operand_yaml_loader_signature(loader):
    try:
        return (
            loader,
            tuple((base, tuple((name, id(value), value)
                              for name, value in vars(base).items()
                              if callable(value))) for base in loader.__mro__),
            tuple((key, id(value), value)
                  for key, value in loader.yaml_constructors.items()),
            tuple((key, id(value), value)
                  for key, value in loader.yaml_multi_constructors.items()),
            frozenset((key, tuple(value))
                      for key, value in loader.yaml_implicit_resolvers.items()),
            tuple(loader.yaml_path_resolvers.items()),
        )
    except (TypeError, RuntimeError):
        # Valid custom resolver shapes may not support a stable fingerprint.
        # They remain available to the ordinary parser, including at import.
        return None


_OPERAND_YAML_BASELINE = _operand_yaml_loader_signature(yaml.SafeLoader)
# Stateful third-party constructors are not known to be deterministic, even if
# already registered before this module was imported. Never memoize them.
_OPERAND_YAML_STANDARD_CONSTRUCTORS = _OPERAND_YAML_BASELINE is not None and all(
    getattr(value, "__module__", "") == "yaml.constructor"
    for value in yaml.SafeLoader.yaml_constructors.values()
) and not yaml.SafeLoader.yaml_multi_constructors and all(
    isinstance(pattern, re.Pattern)
    for resolvers in yaml.SafeLoader.yaml_implicit_resolvers.values()
    for _, pattern in resolvers
)


# Optional LibYAML acceleration is confined to exact bytes/text operands. Both
# implementations must retain their import-time code/registries and use the
# same safe constructors/resolvers. This is not a blanket equivalence claim:
# malformed accelerated parses are retried by the original pure loader so its
# exception type, marks and text remain authoritative.
_OPERAND_YAML_SAFE_CONSTRUCTORS = {
    **{f"tag:yaml.org,2002:{tag}": getattr(yaml.constructor.SafeConstructor, f"construct_yaml_{tag}")
       for tag in ("null", "bool", "int", "float", "binary", "timestamp", "omap",
                   "pairs", "set", "str", "seq", "map")},
    None: yaml.constructor.SafeConstructor.construct_undefined,
}
_OPERAND_YAML_C_LOADER = getattr(yaml, "CSafeLoader", None)
if (not isinstance(_OPERAND_YAML_C_LOADER, type)
        or _OPERAND_YAML_C_LOADER.__module__ != "yaml.cyaml"
        or _OPERAND_YAML_C_LOADER.__name__ != "CSafeLoader"):
    _OPERAND_YAML_C_LOADER = None
_OPERAND_YAML_C_BASELINE = (
    _operand_yaml_loader_signature(_OPERAND_YAML_C_LOADER)
    if _OPERAND_YAML_C_LOADER is not None else None
)


def _operand_yaml_c_compatible():
    try:
        return (
            _OPERAND_YAML_STANDARD_CONSTRUCTORS
            and yaml.SafeLoader.yaml_constructors == _OPERAND_YAML_SAFE_CONSTRUCTORS
            and _OPERAND_YAML_BASELINE is not None
            and _OPERAND_YAML_C_BASELINE is not None
            and getattr(yaml, "CSafeLoader", None) is _OPERAND_YAML_C_LOADER
            and _operand_yaml_loader_signature(yaml.SafeLoader) == _OPERAND_YAML_BASELINE
            and _operand_yaml_loader_signature(_OPERAND_YAML_C_LOADER) == _OPERAND_YAML_C_BASELINE
            and _OPERAND_YAML_C_BASELINE[2:] == _OPERAND_YAML_BASELINE[2:]
        )
    except (TypeError, RuntimeError, AttributeError):
        return False


_OPERAND_YAML_C_TEXT_OUTSIDE_SUBSET = re.compile(r"%|[^\x20-\x7e\r\n]")
_OPERAND_YAML_C_BYTES_OUTSIDE_SUBSET = re.compile(rb"%|[^\x20-\x7e\r\n]")


_OPERAND_YAML_RECURSION_LIMIT = sys.getrecursionlimit()


def _operand_yaml_c_recursion_budget():
    # A shallower caller budget can make the pure composer refuse even shallow
    # YAML. Keep that path authoritative; frame inspection is local only.
    if sys.getrecursionlimit() != _OPERAND_YAML_RECURSION_LIMIT:
        return False
    try:
        frame = sys._getframe()
        depth = 0
        while frame is not None:
            depth += 1
            frame = frame.f_back
        return _OPERAND_YAML_RECURSION_LIMIT - depth >= 768
    except Exception:
        # Audit/runtime instrumentation may refuse optional frame inspection.
        # Preserve BaseException interruption behavior; ordinary failures stay pure.
        return False
    finally:
        frame = None


def _operand_yaml_c_operand(content):
    # Pure/C acceptance differs for tabs and percent-escaped NUL tag suffixes.
    # Admit printable ASCII plus CR/LF only, without percent syntax. Unsupported
    # encodings, controls, directives and tag URI escapes keep the pure parser.
    if isinstance(content, bytes):
        if _OPERAND_YAML_C_BYTES_OUTSIDE_SUBSET.search(content) is not None:
            return False
        text = content.decode("ascii")
    elif isinstance(content, str):
        if _OPERAND_YAML_C_TEXT_OUTSIDE_SUBSET.search(content) is not None:
            return False
        text = content
    else:
        return False
    # Pure composition recurses while C composition does not. Conservative
    # lexical bounds deliberately overcount brackets inside scalars: deep or
    # ambiguous operands stay pure, rather than admitting C-only deep graphs.
    if text.count("[") + text.count("{") > 32:
        return False
    for line in text.splitlines():
        if len(line) - len(line.lstrip(" ")) > 64:
            return False
        prefix = line.lstrip(" ")
        sequences = 0
        while prefix.startswith("- "):
            sequences += 1
            if sequences > 32:
                return False
            prefix = prefix[2:].lstrip(" ")
    return True


def _operand_yaml_parse(content, pure_loader, accelerated_loader=None,
                        accelerated_baseline=None):
    if (accelerated_loader is None or accelerated_baseline is None
            or not _operand_yaml_c_recursion_budget()
            or not _operand_yaml_c_operand(content)
            or not _operand_yaml_c_compatible()
            or _operand_yaml_loader_signature(accelerated_loader) != accelerated_baseline):
        return yaml.load(content, Loader=pure_loader)
    try:
        return yaml.load(content, Loader=accelerated_loader)
    except Exception:
        # Do not propagate C-parser diagnostics or retain failed observations.
        return yaml.load(content, Loader=pure_loader)


def _operand_yaml_unique_loader(base_loader=None):
    # Recreate on uncached calls to retain the reader's current SafeLoader
    # inheritance semantics after an external constructor/resolver mutation.
    class UniqueLoader(base_loader or yaml.SafeLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or key in result:
                raise ValueError("Duplicate or nonstring review-record key")
            result[key] = loader.construct_object(value_node)
        return result

    UniqueLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping
    )
    return UniqueLoader


_OPERAND_YAML_UNIQUE_LOADER = _operand_yaml_unique_loader()
_OPERAND_YAML_UNIQUE_BASELINE = _operand_yaml_loader_signature(_OPERAND_YAML_UNIQUE_LOADER)
_OPERAND_YAML_C_UNIQUE_LOADER = (
    _operand_yaml_unique_loader(_OPERAND_YAML_C_LOADER)
    if _OPERAND_YAML_C_LOADER is not None else None
)
_OPERAND_YAML_C_UNIQUE_BASELINE = (
    _operand_yaml_loader_signature(_OPERAND_YAML_C_UNIQUE_LOADER)
    if _OPERAND_YAML_C_UNIQUE_LOADER is not None else None
)
_OPERAND_YAML_C_ENABLED_BASELINE = _operand_yaml_c_compatible()


def _operand_yaml_parse_selected(content, pure_loader, unique_string_keys):
    accelerated = (_OPERAND_YAML_C_UNIQUE_LOADER if unique_string_keys
                   else _OPERAND_YAML_C_LOADER)
    baseline = (_OPERAND_YAML_C_UNIQUE_BASELINE if unique_string_keys
                else _OPERAND_YAML_C_BASELINE)
    return _operand_yaml_parse(content, pure_loader, accelerated, baseline)



def load_operand_yaml(content: bytes | str, *, unique_string_keys: bool = False):
    """Parse exact content using the ordinary or strict review-record semantics."""
    global _OPERAND_YAML_CACHE_BYTES
    size = len(content) if isinstance(content, bytes) else len(content.encode("utf-8"))
    try:
        unchanged = (
            _OPERAND_YAML_STANDARD_CONSTRUCTORS
            and (not _OPERAND_YAML_C_ENABLED_BASELINE or (
                _operand_yaml_c_compatible()
                and (not unique_string_keys or _operand_yaml_loader_signature(
                    _OPERAND_YAML_C_UNIQUE_LOADER) == _OPERAND_YAML_C_UNIQUE_BASELINE)))
            and _operand_yaml_loader_signature(yaml.SafeLoader) == _OPERAND_YAML_BASELINE
            and (not unique_string_keys or _operand_yaml_loader_signature(
                _OPERAND_YAML_UNIQUE_LOADER
            ) == _OPERAND_YAML_UNIQUE_BASELINE)
        )
    except (TypeError, RuntimeError):
        # Concurrent registry changes also remain ordinary uncached parses.
        unchanged = False
    if (size > _OPERAND_YAML_MAX_INPUT_BYTES
            or size > _OPERAND_YAML_MAX_TOTAL_BYTES or not unchanged):
        loader = _operand_yaml_unique_loader() if unique_string_keys else yaml.SafeLoader
        return _operand_yaml_parse_selected(content, loader, unique_string_keys)
    # bytes and str are deliberately distinct exact operands; neither source
    # paths nor hashes stand in for freshly observed content.
    key = (unique_string_keys, type(content), content)
    with _OPERAND_YAML_LOCK:
        if key in _OPERAND_YAML_CACHE:
            value, _ = _OPERAND_YAML_CACHE[key]
            _OPERAND_YAML_CACHE.move_to_end(key)
            return deepcopy(value)
        loader = _OPERAND_YAML_UNIQUE_LOADER if unique_string_keys else yaml.SafeLoader
        value = _operand_yaml_parse_selected(content, loader, unique_string_keys)
        # Copy before insertion: deepcopy failures cannot leave a cached value.
        result = deepcopy(value)
        while _OPERAND_YAML_CACHE and (len(_OPERAND_YAML_CACHE) >= _OPERAND_YAML_MAX_ENTRIES
                          or _OPERAND_YAML_CACHE_BYTES + size > _OPERAND_YAML_MAX_TOTAL_BYTES):
            _, (_, removed_size) = _OPERAND_YAML_CACHE.popitem(last=False)
            _OPERAND_YAML_CACHE_BYTES -= removed_size
        _OPERAND_YAML_CACHE[key] = (value, size)
        _OPERAND_YAML_CACHE_BYTES += size
        return result


class _TemporalTextLoader(yaml.SafeLoader):
    """Opt-in loader for JSON-bound evidence; timestamps retain their text."""


_TemporalTextLoader.add_constructor(
    "tag:yaml.org,2002:timestamp", yaml.SafeLoader.construct_scalar
)


def load_yaml_temporal_text(text: str) -> Any:
    """Keep YAML dates/datetimes as strings for explicit reporter validation.

    Other SafeLoader types are unchanged. This does not alter yaml.safe_load
    or coerce malformed temporal text into a valid date.
    """
    return yaml.load(text, Loader=_TemporalTextLoader)


def normalize_boolean_settings(
    settings: dict[str, Any], paths: tuple[str, ...], *, prefix: str = "rules"
) -> tuple[dict[str, Any], list[str]]:
    """Validate present boolean leaves without granting truthiness authority.

    Absent optional keys retain consumer defaults. Present non-booleans,
    including null, become false and are returned as diagnostic paths. The
    caller must emit those diagnostics before claiming readiness. ``*`` visits
    entries of a mapping or list; input objects are never modified. This is
    opt-in leaf validation, not a replacement for a consumer's schema or
    mandatory explicit-value checks. Diagnostics do not include input values.
    """
    result = deepcopy(settings)
    invalid: set[str] = set()

    def visit(node: Any, parts: list[str], location: str) -> None:
        if parts[0] == "*":
            entries = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
            for key, value in entries:
                visit(value, parts[1:], f"{location}.{key}")
            return
        if not isinstance(node, dict) or parts[0] not in node:
            return
        key = parts[0]
        path = f"{location}.{key}"
        if len(parts) > 1:
            visit(node[key], parts[1:], path)
        elif not isinstance(node[key], bool):
            invalid.add(path)
            node[key] = False

    for path in paths:
        visit(result, path.split("."), prefix)
    return result, sorted(invalid)


def nonnegative_integer_setting(settings: Any, key: str, default: int, *, context: str) -> int:
    """Read a bounded day/count setting without truthiness or numeric coercion."""
    if not isinstance(settings, dict):
        raise ValueError(f"{context} must be a mapping")
    value = settings.get(key, default)
    if type(value) is not int or value < 0:
        raise ValueError(f"{context}.{key} must be a nonnegative integer")
    return value


def controlled_now_utc() -> datetime:
    """Return the replay-controlled UTC instant, or the live UTC clock.

    ``NAOS_FIXED_TIME`` is an explicit deterministic-test contract.  Invalid or
    timezone-naive values fail closed instead of silently falling back to the
    wall clock.
    """

    if "NAOS_FIXED_TIME" not in os.environ:
        return datetime.now(UTC)
    fixed = os.environ["NAOS_FIXED_TIME"]
    if not fixed:
        raise ValueError("NAOS_FIXED_TIME must not be empty.")
    parsed = datetime.fromisoformat(fixed.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("NAOS_FIXED_TIME must include an explicit timezone.")
    return parsed.astimezone(UTC)


def controlled_utc_now_text() -> str:
    return (
        controlled_now_utc()
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


SAFE_FALLBACK_POLICY: dict[str, Any] = {
    "version": "fallback",
    "profiles": {
        "supported": ["quickstart", "lite", "standard", "assured"],
        "default": "quickstart",
        "severity_by_profile": {
            "quickstart": "advisory",
            "lite": "warning",
            "standard": "required",
            "assured": "blocking",
        },
        "exit_code": {
            "quickstart": {"fail_on": [], "transition_fail_on": [], "strict_fail_on": ["blocking", "required"]},
            "lite": {"fail_on": ["blocking"], "transition_fail_on": [], "strict_fail_on": ["blocking", "required", "warning"]},
            "standard": {"fail_on": ["blocking", "required"], "transition_fail_on": [], "strict_fail_on": ["blocking", "required", "warning"]},
            "assured": {"fail_on": ["blocking", "required", "warning"], "transition_fail_on": ["blocking"], "strict_fail_on": ["blocking", "required", "warning"]},
        },
    },
    "enforcement_transition": "warn",
    "paths": {
        "default_naos_root": "naos",
        "reports_dir": "reports",
        "claims_report": "claims_validation.json",
        "roadmap_report": "roadmap_crosswalk_validation.json",
        "function_index_report": "function_index_health.json",
        "test_evidence_report": "test_evidence_health.json",
        "ac_completion_evidence_manifest": "ac_completion_evidence.yaml",
        "ac_completion_evidence_report": "ac_completion_evidence.json",
        "duplicate_function_hygiene_report": "duplicate_function_hygiene.json",
        "secret_hygiene_report": "secret_hygiene.json",
        "test_quality_hygiene_report": "test_quality_hygiene.json",
        "dependency_integrity_report": "dependency_integrity.json",
        "package_reality_report": "package_reality.json",
        "api_symbol_reality_manifest": "api_symbol_reality.yaml",
        "api_symbol_reality_report": "api_symbol_reality.json",
        "secure_coding_control_routes": "secure_coding_control_evidence_routes.yaml",
        "secure_coding_controls_report": "secure_coding_controls.json",
        "duplicate_function_hygiene_rules": "duplicate_function_hygiene_rules.yaml",
        "secret_hygiene_rules": "secret_hygiene_rules.yaml",
        "test_quality_hygiene_rules": "test_quality_hygiene_rules.yaml",
        "dependency_integrity_rules": "dependency_integrity_rules.yaml",
        "package_reality_rules": "package_reality_rules.yaml",
        "package_reality_provenance": "package_reality_provenance.yaml",
        "self_check_report": "self_check.json",
        "self_check_dependency_resolution_report": "self_check_dependency_resolution.json",
        "capability_maturity_report": "capability_maturity.json",
        "capability_state": "capability_state.yaml",
        "systemic_impact_report": "systemic_impact_review.json",
        "systemic_impact_rules": "systemic_impact_rules.yaml",
        "module_header_traceability_report": "module_header_traceability.json",
        "spec_pack_contract_report": "spec_pack_contract.json",
        "spec_pack_materialization_report": "spec_pack_materialization.json",
        "spec_assembly_worksheet_report": "spec_assembly_worksheet.json",
        "spec_cascade_report": "spec_cascade_coherence.json",
        "module_header_rules": "module_header_rules.yaml",
        "control_plane_review_report": "control_plane_review.json",
        "control_plane_review_rules": "control_plane_review_rules.yaml",
        "control_plane_review_items": "control_plane_review_items.yaml",
        "setup_recommendations_report": "setup_recommendations.json",
        "setup_module_catalog": "setup_module_catalog.yaml",
        "governance_bypass_posture_report": "governance_bypass_posture.json",
        "external_evidence_ingest_report": "external_evidence_ingest.json",
        "evidence_attestation_report": "evidence_attestation.json",
        "evidence_verification_report": "evidence_verification.json",
        "evidence_envelope_report": "evidence_envelope.json",
        "evidence_conflict_detection_report": "evidence_conflict_detection.json",
        "evidence_attestation_rules": "evidence_attestation_rules.yaml",
        "evidence_review_attestations": "evidence_review_attestations.yaml",
        "memory_context_readiness_report": "memory_context_readiness.json",
        "memory_context_rules": "memory_context_rules.yaml",
        "memory_authorization_matrix": "memory_authorization_matrix.yaml",
        "memory_provider_access_report": "memory_provider_access.json",
        "memory_provider_access_rules": "memory_provider_access_rules.yaml",
        "memory_use_policy_report": "memory_use_policy.json",
        "memory_use_policy_rules": "memory_use_policy_rules.yaml",
        "memory_review_items": "memory_review_items.yaml",
        "learning_loop_review_report": "learning_loop_review.json",
        "learning_loop_rules": "learning_loop_rules.yaml",
        "learning_candidates": "learning_candidates.yaml",
        "learning_state": "learning_state.yaml",
        "learning_history": "learning_history.yaml",
        "adapter_coherence_report": "adapter_coherence.json",
        "adapter_coherence_rules": "adapter_coherence_rules.yaml",
        "adapter_propagation_state": "adapter_propagation_state.yaml",
        "task_context_pack_report": "task_context_pack.json",
        "task_context_pack_rules": "task_context_pack_rules.yaml",
        "task_context_pack_markdown_dir": "context_packs",
        "task_claims_file": "task_claims.yaml",
        "task_claim_report": "task_claim_report.json",
        "local_context_index_report": "local_context_index.json",
        "local_context_index_rules": "local_context_index_rules.yaml",
        "local_context_index_sqlite": "context_index/local_context_index.sqlite",
        "local_context_index_db_lock": "context_index/local_context_index.sqlite.lock",
        "sqlite_write_coordination_report": "sqlite_write_coordination.json",
        "local_context_query_report": "local_context_query.json",
        "local_context_query_markdown_dir": "context_queries",
        "semantic_candidate_layer_report": "semantic_candidate_layer.json",
        "semantic_candidate_layer_rules": "semantic_candidate_layer_rules.yaml",
        "graph_context_readiness_report": "graph_context_readiness.json",
        "graph_context_rules": "graph_context_rules.yaml",
        "graph_context_query_report": "graph_context_query.json",
        "graph_context_query_markdown_dir": "context_queries",
        "session_lifecycle_report": "session_lifecycle.json",
        "session_lifecycle_rules": "session_lifecycle_rules.yaml",
        "sessions_root": "sessions",
        "sessions_index": "sessions_index.json",
        "session_identity_report": "session_identity.json",
        "operator_attribution_report": "operator_attribution.json",
        "audit_log_root": "audit_log",
        "audit_log_summary_report": "audit_log_summary.json",
        "agent_trace_events": "agent_trace_events.yaml",
        "agent_trace_validation_report": "agent_trace_validation.json",
        "harness_trace_import_report": "harness_trace_import.json",
        "ai_surface_context_budget_report": "ai_surface_context_budget.json",
        "ai_surface_context_budget_rules": "ai_surface_context_budget_rules.yaml",
        "ai_surface_health_baseline": "baselines/ai_surface_health_baseline.json",
        "static_grader_report": "static_grader_report.json",
        "grader_assessment_report": "grader_assessment.json",
        "model_provider_policy": "model_provider_policy.yaml",
        "model_provider_policy_report": "model_provider_policy.json",
        "ai_component_inventory_rules": "ai_component_inventory_rules.yaml",
        "ai_component_inventory_report": "ai_component_inventory.json",
        "agent_sponsor_registry": "agent_sponsor_registry.yaml",
        "agent_sponsor_registry_report": "agent_sponsor_registry.json",
        "aivss_assessments": "aivss_assessments.yaml",
        "aivss_arithmetic_verification_report": "aivss_arithmetic_verification.json",
        "model_telemetry_evidence": "model_telemetry_evidence.yaml",
        "model_telemetry_evidence_report": "model_telemetry_evidence.json",
        "failure_mode_taxonomy": "failure_mode_taxonomy.yaml",
        "failure_mode_posture_report": "failure_mode_posture.json",
        "failure_mode_observations": "failure_mode_observations.yaml",
        "failure_mode_observations_report": "failure_mode_observations.json",
        "opencode_config_hygiene": "opencode_config_hygiene.yaml",
        "opencode_config_hygiene_report": "opencode_config_hygiene.json",
        "design_traceability": "design_traceability.yaml",
        "design_traceability_report": "design_traceability.json",
        "ui_experience_quality": "ui_experience_quality.yaml",
        "ui_experience_quality_report": "ui_experience_quality.json",
        "llm_grader_readiness_rules": "llm_grader_readiness_rules.yaml",
        "llm_grader_readiness_report": "llm_grader_readiness.json",
        "behavioral_governance_readiness_rules": "behavioral_governance_readiness_rules.yaml",
        "behavioral_governance_readiness_baseline_state": "behavioral_baseline_state.yaml",
        "behavioral_governance_readiness_report": "behavioral_governance_readiness.json",
        "sarif_report": "naos_findings.sarif",
        "sarif_export_summary_report": "sarif_export.json",
        "policy_override_merge_report": "policy_override_merge.json",
        "pr_risk_classification_report": "pr_risk_classification.json",
        "plan_coherence_report": "plan_coherence.json",
        "pr_risk_rules": "pr_risk_rules.yaml",
        "pr_governance_summary_report": "pr_governance_summary.json",
        "agentic_workflow": "agentic_workflow.yaml",
        "agentic_coding_playbook": "AGENTIC_CODING_PLAYBOOK.md",
        "agentic_workflow_review_report": "agentic_workflow_review.json",
        "pre_implementation_alignment": "PRE_IMPLEMENTATION_ALIGNMENT.md",
        "pre_implementation_alignment_review_report": "pre_implementation_alignment_review.json",
        "calibration_shadow": "calibration_shadow.yaml",
        "calibration_shadow_report": "calibration_shadow_report.json",
        "evidence_classification_policy": "evidence_classification_policy.yaml",
        "evidence_classification_report": "evidence_classification_report.json",
        "cross_harness_review_readiness": "cross_harness_review_readiness.yaml",
        "cross_harness_review_readiness_report": "cross_harness_review_readiness.json",
        "adoption_summary_report": "adoption_summary.json",
        "preflight_report": "preflight_report.json",
        "intake_report": "intake_report.json",
        "install_plan_report": "install_plan.json",
        "existing_resource_inventory_report": "existing_resource_inventory.json",
        "ai_artifact_inventory_report": "ai_artifact_inventory.json",
        "ai_artifact_reconciliation_report": "ai_artifact_reconciliation.json",
        "ai_code_provenance_report": "ai_code_provenance.json",
        "compliance_posture_report": "compliance_posture.json",
        "memory_resource_inventory_report": "memory_resource_inventory.json",
        "memory_resource_reconciliation_report": "memory_resource_reconciliation.json",
        "mcp_resource_inventory_report": "mcp_resource_inventory.json",
        "brownfield_baseline_report": "brownfield_baseline.json",
        "candidate_requirements_report": "candidate_requirements.json",
        "traceability_gap_register_report": "traceability_gap_register.json",
        "install_decision_record_report": "install_decision_record.json",
        "context_challenge_report": "context_challenge_report.json",
        "repo_context_challenge_report": "repo_context_challenge_report.json",
        "plan_challenge_report": "plan_challenge_report.json",
        "decision_probe_report": "decision_probe_report.json",
        "planning_gate_review_report": "planning_gate_review_report.json",
        "intake_answers": "intake_answers.yaml",
        "install_plan_rules": "install_plan_rules.yaml",
        "existing_resource_inventory_rules": "existing_resource_inventory_rules.yaml",
        "ai_artifact_inventory_rules": "ai_artifact_inventory_rules.yaml",
        "ai_code_provenance_manifest": "ai_code_provenance.yaml",
        "compliance_posture_manifest": "compliance_posture.yaml",
        "memory_mcp_inventory_rules": "memory_mcp_inventory_rules.yaml",
        "traceability_gap_register_rules": "traceability_gap_register_rules.yaml",
        "challenge_rules": "challenge_rules.yaml",
        "install_decision_record_rules": "install_decision_record_rules.yaml",
        "effective_policy": "effective_policy.yaml",
        "team_operator_map": "team_operator_map.yaml",
        "source_to_test_map": "test_evidence/source_to_test_map.json",
        "dashboard_markdown": "DASHBOARD.md",
        "dashboard_summary_report": "dashboard_summary.json",
        "evidence_dir": "evidence",
        "evidence_pack_report": "evidence_pack.json",
        "task_path_report": "evidence/task_path.yaml",
        "context_manifest_report": "evidence/context_manifest.json",
        "validator_results_report": "validator_results.json",
        "completion_certificate_report": "evidence/completion_certificate.yaml",
        "exceptions_report": "evidence/exceptions.yaml",
        "gate_status_report": "gate_status.json",
        "gate_evaluation_report": "gate_evaluation.json",
        "task_path_template": "evidence/_TEMPLATE/task_path.yaml",
        "context_manifest_template": "evidence/_TEMPLATE/context_manifest.json",
        "validator_results_template": "evidence/_TEMPLATE/validator_results.json",
        "test_evidence_template": "evidence/_TEMPLATE/test_evidence.json",
        "completion_certificate_template": "evidence/_TEMPLATE/completion_certificate.yaml",
        "adopter_policy": "policy/default_policy.yaml",
        "ignored_scan_dirs": [".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"],
    },
    "claims": {
        "status_values": ["candidate", "supported", "unsupported", "expired", "experimental", "needs_revalidation"],
        "revalidation_triggers": [
            "model_version_change",
            "ide_agent_change",
            "profile_change",
            "validator_change",
            "repository_architecture_change",
            "dependency_change",
            "release_boundary",
            "evidence_stale",
            "project_scope_change",
        ],
        "external_evidence_verification_default": "unverified",
        "safe_context_window_chars": 120,
        "safe_context_phrases": [
            "does not claim",
            "does not prove",
            "not universal proof",
            "bounded evidence",
            "cannot guarantee",
            "must not be claimed",
            "unless evidence exists",
            "not claimed",
            "limitation",
        ],
        "disclaimers": [
            "Claim validation does not prove legal or regulatory compliance.",
            "Dogfood, pilot, reference, research, model, IDE, and toolchain results are bounded evidence only.",
            "Claims may drift as models, tools, dependencies, validators, repository architecture, profile policy, gatekeeper configuration, project scope, or evidence freshness changes.",
        ],
        "overclaim_patterns": {},
    },
    "evidence": {
        "default_staleness_days": 30,
        "external_reference_default_status": "external_reference_unverified",
    },
    "test_evidence": {
        "accepted_types": ["unit", "integration", "acceptance", "security", "coverage"],
        "coverage_supports_source_default": "unknown",
        "global_coverage_maps_sources": False,
    },
    "task_claims": {
        "default_ttl_hours": 72,
    },
    "task_claim_default_ttl_hours": 72,
}


OPERATOR_RESOLUTION_ORDER = [
    "NAOS_OPERATOR_ID",
    "git config user.email",
    "git config user.name",
    "safe OS username",
    "unknown",
]
OPERATOR_ID_MAX_LENGTH = 128
OPERATOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
OPERATOR_LIMITATIONS = [
    "Operator attribution records local identity signals only; it is not authentication, authorization, non-repudiation, task ownership, or separation-of-duties evidence.",
    "Git identity is read from repository-local git config only; effective/global Git identity is intentionally not consulted and no network identity provider is queried.",
    "Explicit NAOS_OPERATOR_ID keeps its strict ASCII grammar; local Git/OS names accept bounded Unicode letters, numbers, combining marks and spaces, while Git email also accepts bot brackets.",
    "Invalid higher-priority signals that force fallback remain review findings; unused lower-priority signals do not create invalid-identifier findings.",
    "Operator identifiers may be personal data and should be handled according to the adopter's privacy policy.",
]
OPERATOR_NOT_CLAIMED = [
    "identity proof",
    "authentication",
    "authorization",
    "task ownership",
    "task locking",
    "separation of duties",
    "non-repudiation",
    "approval",
    "source of truth",
]


def kit_root() -> Path:
    return Path(__file__).resolve().parents[1]


def validate_operator_value(value: str | None, source: str) -> tuple[str | None, dict[str, Any] | None, bool]:
    raw = "" if value is None else str(value)
    cleaned = raw.strip()
    if not cleaned:
        return None, None, False
    reason = ""
    if any(ord(ch) < 32 for ch in cleaned):
        reason = "control_character"
    elif len(cleaned) > OPERATOR_ID_MAX_LENGTH:
        reason = "too_long"
    elif "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        reason = "path_like_or_traversal"
    elif source in {"git_email", "git_name", "os_user"}:
        punctuation = " ._:@+-" + ("[]" if source == "git_email" else "")
        if not cleaned[0].isalnum() or any(
            unicodedata.category(character)[0] not in {"L", "N", "M"}
            and character not in punctuation
            for character in cleaned
        ):
            reason = "invalid_pattern"
    elif not OPERATOR_ID_PATTERN.fullmatch(cleaned):
        reason = "invalid_pattern"
    if reason:
        return None, {
            "source": source,
            "status": "invalid",
            "reason": reason,
            "value_length": len(cleaned),
            "safe_pattern": OPERATOR_ID_PATTERN.pattern,
            "max_length": OPERATOR_ID_MAX_LENGTH,
        }, True
    return cleaned, None, True


def local_git_config(root: Path, key: str) -> str | None:
    """Read repository-local identity only; global/effective identity is excluded."""
    try:
        result = subprocess.run(
            ["git", "config", "--local", "--get", key],
            cwd=root,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def resolve_operator_attribution(root: Path | None = None, env: dict[str, str] | None = None) -> dict[str, Any]:
    root = root or Path.cwd()
    env = os.environ if env is None else env
    invalid_operator_findings: list[dict[str, Any]] = []
    raw_candidates = [
        ("env", env.get("NAOS_OPERATOR_ID")),
        ("git_email", local_git_config(root, "user.email")),
        ("git_name", local_git_config(root, "user.name")),
    ]
    try:
        raw_candidates.append(("os_user", getpass.getuser()))
    except Exception:
        raw_candidates.append(("os_user", None))
    detected = {source: bool(value is not None and str(value).strip()) for source, value in raw_candidates}
    operator_source = "unknown"
    operator_id: str | None = None
    # Rejected higher-priority inputs explain a fallback. Once attribution is
    # resolved, lower-priority values are detected metadata only, not warnings.
    for source, raw in raw_candidates:
        value, invalid, _ = validate_operator_value(raw, source)
        if invalid:
            invalid_operator_findings.append(invalid)
        if value:
            operator_source = source
            operator_id = value
            break

    status = "resolved" if operator_id else "unknown"
    return {
        "operator_id": operator_id,
        "operator_source": operator_source,
        "operator_resolution_order": OPERATOR_RESOLUTION_ORDER,
        "operator_attribution_status": status,
        "git_user_email_detected": detected["git_email"],
        "git_user_name_detected": detected["git_name"],
        "env_operator_id_detected": detected["env"],
        "os_user_detected": detected["os_user"],
        "invalid_operator_findings": invalid_operator_findings,
        "operator_id_validation": {
            "safe_pattern": OPERATOR_ID_PATTERN.pattern,
            "safe_pattern_applies_to": "NAOS_OPERATOR_ID",
            "local_identity_syntax": "Unicode letters/numbers/combining marks, ASCII spaces and ._:@+-; Git email additionally permits []",
            "invalid_signal_policy": "attempted_sources_through_selected_source",
            "max_length": OPERATOR_ID_MAX_LENGTH,
            "surrounding_whitespace_normalized": True,
            "path_traversal_rejected": True,
            "slash_rejected": True,
            "backslash_rejected": True,
            "control_characters_rejected": True,
            "email_format_required": False,
        },
        "privacy_posture": {
            "operator_identifiers_are_potential_personal_data": True,
            "network_identity_lookup_performed": False,
            "provider_or_api_lookup_performed": False,
            "credentials_read": False,
            "tokens_stored": False,
            "organizational_role_inferred": False,
            "team_membership_inferred": False,
            "redaction_or_hashing": "not_implemented_in_m2",
        },
        "pii_warning": "Operator identifiers may be personal data; use NAOS_OPERATOR_ID if a project-specific pseudonymous identifier is preferred.",
        "limitations": OPERATOR_LIMITATIONS,
        "not_claimed": OPERATOR_NOT_CLAIMED,
        "human_review_required": True,
    }


def build_generated_by(
    root: Path | None = None,
    *,
    session_id: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    operator = resolve_operator_attribution(root or Path.cwd())
    return {
        "operator_id": operator.get("operator_id"),
        "operator_source": operator.get("operator_source"),
        "operator_attribution_status": operator.get("operator_attribution_status"),
        "session_id": session_id,
        "generated_at": generated_at,
        "limitations": operator.get("limitations") or [],
        "not_claimed": operator.get("not_claimed") or [],
    }


def is_kit_repository(root: Path | None = None, naos_root: str = "naos") -> bool:
    root = root or Path.cwd()
    return (
        (root / "pyproject.toml").is_file()
        and (root / "naos_init.py").is_file()
        and (root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml").is_file()
        and not (root / naos_root / "TASK_REGISTRY.yaml").exists()
    )


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Policy file must be a mapping: {path}")
    return data


def implicit_adopter_policy_path(root: Path, naos_root: str) -> Path | None:
    """Return an existing implicit policy only when its full path is safe.

    Parent traversal and absolute roots are rejected before policy lookup.
    Every existing ancestor must be a real directory and the policy leaf must
    be a real regular file. Unsafe or absent implicit policies are ignored so
    downstream commands retain their own structured unsafe-path handling
    without policy discovery reading through a symlink or special file.
    """
    relative_root = safe_policy_relative_path(naos_root, field="naos_root")
    relative_policy = safe_policy_relative_path(
        str(SAFE_FALLBACK_POLICY["paths"]["adopter_policy"]),
        field="adopter_policy",
    )
    base = root.resolve()
    candidate = base
    components = relative_root.parts + relative_policy.parts
    for index, component in enumerate(components):
        candidate = candidate / component
        try:
            metadata = os.lstat(candidate)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            return None
        is_leaf = index == len(components) - 1
        if is_leaf:
            return candidate if stat.S_ISREG(metadata.st_mode) else None
        if not stat.S_ISDIR(metadata.st_mode):
            return None
    return None


def resolve_policy_path(
    explicit_policy: str | None = None,
    naos_root: str | None = None,
    root: Path | None = None,
) -> tuple[Path | None, str]:
    root = root or Path.cwd()
    default_naos_root = naos_root or os.environ.get("NAOS_ROOT") or SAFE_FALLBACK_POLICY["paths"]["default_naos_root"]
    if explicit_policy:
        return Path(explicit_policy), "explicit"

    adopter_policy = implicit_adopter_policy_path(root, str(default_naos_root))
    if adopter_policy is not None:
        return adopter_policy, "adopter"

    kit_policy = kit_root() / "policies" / "default_policy.yaml"
    if kit_policy.exists():
        return kit_policy, "kit"

    return None, "fallback"


def load_policy(
    explicit_policy: str | None = None,
    naos_root: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    path, source = resolve_policy_path(explicit_policy, naos_root, root)
    policy = dict(SAFE_FALLBACK_POLICY)
    if path is not None:
        policy = deep_merge(policy, load_yaml_mapping(path))
    policy["_meta"] = {"source": source, "path": str(path) if path else None}
    return policy


def default_naos_root(policy: dict[str, Any]) -> str:
    return str(policy.get("paths", {}).get("default_naos_root") or "naos")


def supported_profiles(policy: dict[str, Any]) -> list[str]:
    profiles = policy.get("profiles", {}).get("supported") or SAFE_FALLBACK_POLICY["profiles"]["supported"]
    return [str(profile) for profile in profiles]


def normalize_profile(profile: str | None, policy: dict[str, Any]) -> str:
    default_profile = str(policy.get("profiles", {}).get("default") or "quickstart")
    value = (profile or os.environ.get("NAOS_PROFILE") or default_profile).strip().lower()
    if value.startswith("governance-"):
        value = value.removeprefix("governance-")
    profiles = supported_profiles(policy)
    if value not in profiles:
        raise ValueError(f"Unsupported profile {profile!r}; expected one of {', '.join(profiles)}")
    return value


def safe_policy_relative_path(value: Any, *, field: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"Policy path {field} must not be empty.")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Policy path {field} must stay relative to the NAOS root: {text}")
    if any(part in {"", "."} for part in path.parts):
        raise ValueError(f"Policy path {field} must not contain current-directory path parts: {text}")
    return path


def safe_path_under(base: Path, relative: Any, *, field: str) -> Path:
    rel = safe_policy_relative_path(relative, field=field)
    if base.is_symlink():
        raise ValueError(f"Policy path {field} refuses symlinked base: {base}")
    lexical_target = base
    for part in rel.parts:
        lexical_target = lexical_target / part
        if lexical_target.is_symlink():
            raise ValueError(f"Policy path {field} refuses symlinked component: {lexical_target}")
    base_resolved = base.resolve()
    target = (base / rel).resolve(strict=False)
    if base_resolved not in (target, *target.parents):
        raise ValueError(f"Policy path {field} escapes allowed root {base_resolved}: {relative}")
    return target


def naos_root_path(root: Path, naos_root: str) -> Path:
    """Return a project-bound NAOS root without following configured symlinks."""
    return safe_path_under(root.resolve(), naos_root, field="naos_root")


def safe_policy_path(base: Path, *segments: Any, field: str) -> Path:
    target = base
    for index, segment in enumerate(segments):
        target = safe_path_under(target, segment, field=f"{field}[{index}]")
    base_resolved = base.resolve()
    target_resolved = target.resolve(strict=False)
    if base_resolved not in (target_resolved, *target_resolved.parents):
        raise ValueError(f"Policy path {field} escapes allowed root {base_resolved}: {target}")
    return target_resolved


def severity_for_profile(profile: str, policy: dict[str, Any], advisory: bool = False) -> str:
    if advisory:
        return "advisory"
    mapping = policy.get("profiles", {}).get("severity_by_profile", {})
    return str(mapping.get(profile) or "advisory")


def resolve_report_rule_severity(
    profile: str,
    policy: dict[str, Any],
    requested: Any,
    *,
    advisory: bool = False,
    review_required: bool = False,
    preserve_lower_request: bool = False,
    allow_none: bool = False,
) -> tuple[str, dict[str, Any] | None]:
    """Apply an assured policy floor to reporter rules, independent of gate maturity.

    Kit reports remain advisory. Lower profiles retain valid requested severity;
    in particular, optional memory readiness is advisory in lite. The floor is
    relative to the selected policy, not an integrity pin or approval authority.
    Context and module-header rule schemas also allow ``none``, below advisory;
    posture reporters retain their existing request vocabulary.
    """
    if advisory:
        return "advisory", None
    if profile != "assured" and preserve_lower_request and requested:
        return str(requested), None
    configured = str(requested or "").strip()
    if review_required and configured == "review_required":
        configured = "required" if profile == "standard" else "blocking" if profile == "assured" else "warning"
    order = {"none": -1, "advisory": 0, "warning": 1, "required": 2, "blocking": 3}
    policy_severity = severity_for_profile(profile, policy)
    if configured not in order or (configured == "none" and not allow_none):
        return policy_severity, None
    if profile != "assured" or order[configured] >= order.get(policy_severity, 0):
        return configured, None
    return policy_severity, {
        "id": "severity_downgrade_attempt",
        "severity": "blocking",
        "status": "blocked",
        "message": "Assured reporter rules cannot lower the selected policy severity.",
        "requested_severity": configured,
        "policy_severity": policy_severity,
        "effective_severity": policy_severity,
        "required_next_actions": ["Review the rule severity against the selected policy; keep policy changes subject to project governance."],
    }


def finding_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "blocking": sum(1 for finding in findings if finding.get("severity") == "blocking"),
        "required": sum(1 for finding in findings if finding.get("severity") == "required"),
        "warnings": sum(1 for finding in findings if finding.get("severity") == "warning"),
        "advisory": sum(1 for finding in findings if finding.get("severity") == "advisory"),
        "total_findings": len(findings),
    }


def status_from_counts(summary: dict[str, int]) -> str:
    if summary.get("blocking", 0):
        return "blocked"
    if summary.get("required", 0):
        return "required_missing"
    if summary.get("warnings", 0):
        return "warning"
    if summary.get("advisory", 0):
        return "advisory"
    return "pass"


def _severity_counts(summary: dict[str, int]) -> dict[str, int]:
    return {
        "blocking": summary.get("blocking", 0),
        "required": summary.get("required", 0),
        "warning": summary.get("warnings", 0),
        "warnings": summary.get("warnings", 0),
        "advisory": summary.get("advisory", 0),
    }


def enforcement_transition(policy: dict[str, Any]) -> str:
    """Return the graduated-ramp transition mode: 'warn' or 'enforce'.

    'warn' keeps v1-compatible exit codes (transition_fail_on) while still
    surfacing what the enforced ramp WOULD block; 'enforce' applies fail_on.
    """
    value = str(policy.get("enforcement_transition") or "enforce").strip().lower()
    return value if value in {"warn", "enforce"} else "enforce"


def exit_code_for_summary(
    profile: str,
    summary: dict[str, int],
    policy: dict[str, Any],
    strict: bool = False,
) -> int:
    exit_policy = policy.get("profiles", {}).get("exit_code", {}).get(profile, {})
    if strict:
        fail_on = exit_policy.get("strict_fail_on", [])
    elif enforcement_transition(policy) == "warn":
        # Transition release: exit codes follow the v1-compatible baseline so
        # adopters are not unexpectedly blocked by policy updates; the enforced
        # ramp is previewed via
        # would_block_for_summary() rather than failing the build.
        fail_on = exit_policy.get("transition_fail_on", exit_policy.get("fail_on", []))
    else:
        fail_on = exit_policy.get("fail_on", [])
    severity_counts = _severity_counts(summary)
    return 1 if any(severity_counts.get(str(severity), 0) for severity in fail_on) else 0


def would_block_for_summary(
    profile: str,
    summary: dict[str, int],
    policy: dict[str, Any],
) -> bool:
    """True if the enforced (non-transition) graduated ramp would fail this profile.

    Lets reports/dashboards preview ramp impact during the 'warn' transition
    without changing exit codes. Not an approval or pass/fail authority.
    """
    exit_policy = policy.get("profiles", {}).get("exit_code", {}).get(profile, {})
    fail_on = exit_policy.get("fail_on", [])
    severity_counts = _severity_counts(summary)
    return any(severity_counts.get(str(severity), 0) for severity in fail_on)


def effective_enforcement(
    profile_enforcement: str,
    current_maturity: Any,
    target_maturity: Any,
) -> str:
    """Maturity-gated enforcement (CG2): a capability only enforces at its
    declared profile severity once it has matured to target.

    When current_maturity < target_maturity the enforcement downgrades to
    'advisory' ("never block a scaffold"). Missing/unknown maturity is treated
    as below target (downgrade), never as an escalation.

    A declared enforcement at or below 'advisory' (e.g. 'none',
    'not_applicable', 'advisory') is returned unchanged: downgrading must never
    raise a capability above its declared posture.
    """
    enforcement = str(profile_enforcement or "advisory")
    # Anything already at or below advisory cannot be downgraded further, and
    # must never be escalated up to 'advisory'.
    rank = {"not_applicable": -2, "none": -1, "advisory": 0,
            "warning": 1, "required": 2, "blocking": 3}
    if rank.get(enforcement, 0) <= rank["advisory"]:
        return enforcement
    levels = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
    current = levels.get(str(current_maturity)) if current_maturity is not None else None
    target = levels.get(str(target_maturity)) if target_maturity is not None else None
    if target is None:
        return enforcement
    if current is None or current < target:
        return "advisory"
    return enforcement


PROFILE_CONTROL_ORDER = ["quickstart", "lite", "standard", "assured"]


def escalate_profile(repo_profile: str, implied_profile: str | None) -> str:
    """Return the stricter of repo_profile and implied_profile (escalate up only).

    Used for advisory per-task risk routing: a high-risk task may imply a stricter
    review profile than the repo's, but NAOS never auto-lowers the profile and never
    enforces the escalation — it is recorded review guidance for a human, not a runtime
    action.
    """
    repo = str(repo_profile or "quickstart")
    if not implied_profile:
        return repo
    order = PROFILE_CONTROL_ORDER
    ri = order.index(repo) if repo in order else 0
    ii = order.index(str(implied_profile)) if str(implied_profile) in order else ri
    return order[max(ri, ii)]


def report_output_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    filename_key: str,
) -> Path | None:
    candidate = naos_root_path(root, naos_root)
    if candidate.is_dir() and not is_kit_repository(root, naos_root):
        reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
        filename = str(policy.get("paths", {}).get(filename_key) or filename_key)
        from naos_self_check_inspection import inspection_report_output_path
        return inspection_report_output_path(root, naos_root, safe_policy_path(candidate, reports_dir, filename, field=filename_key))
    return None


def test_map_output_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    candidate = naos_root_path(root, naos_root)
    if candidate.is_dir() and not is_kit_repository(root, naos_root):
        return safe_policy_path(
            candidate,
            str(policy.get("paths", {}).get("source_to_test_map") or "test_evidence/source_to_test_map.json"),
            field="source_to_test_map",
        )
    return None


def evidence_pack_output_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    candidate = naos_root_path(root, naos_root)
    if candidate.is_dir() and not is_kit_repository(root, naos_root):
        evidence_dir = str(policy.get("paths", {}).get("evidence_dir") or "evidence")
        filename = str(policy.get("paths", {}).get("evidence_pack_report") or "evidence_pack.json")
        return safe_policy_path(candidate, evidence_dir, filename, field="evidence_pack_report")
    return None


def dashboard_output_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    candidate = naos_root_path(root, naos_root)
    if candidate.is_dir() and not is_kit_repository(root, naos_root):
        filename = str(policy.get("paths", {}).get("dashboard_markdown") or "DASHBOARD.md")
        return safe_policy_path(candidate, filename, field="dashboard_markdown")
    return None


def evidence_default_path(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    candidate = naos_root_path(root, naos_root)
    value = str(policy.get("paths", {}).get(key) or key)
    return safe_policy_path(candidate, value, field=key)


def report_default_path(root: Path, naos_root: str, policy: dict[str, Any], filename_key: str) -> Path:
    candidate = naos_root_path(root, naos_root)
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    filename = str(policy.get("paths", {}).get(filename_key) or filename_key)
    from naos_self_check_inspection import inspection_input_path
    return inspection_input_path(root, naos_root, safe_policy_path(candidate, reports_dir, filename, field=filename_key))


def sessions_root_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    candidate = naos_root_path(root, naos_root)
    sessions_root = str(policy.get("paths", {}).get("sessions_root") or "sessions")
    return safe_policy_path(candidate, sessions_root, field="sessions_root")


def sessions_index_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    candidate = naos_root_path(root, naos_root)
    filename = str(policy.get("paths", {}).get("sessions_index") or "sessions_index.json")
    return safe_policy_path(candidate, filename, field="sessions_index")


def session_report_default_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    session_id: str,
    filename_key: str,
) -> Path:
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    filename = str(policy.get("paths", {}).get(filename_key) or filename_key)
    return safe_policy_path(
        sessions_root_path(root, naos_root, policy),
        session_id,
        reports_dir,
        filename,
        field=filename_key,
    )


def validate_report_write_path(path: Path | None) -> None:
    if path is None:
        return
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Refusing to write report through symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Refusing to replace non-regular report path: {path}")
    if metadata.st_nlink != 1:
        raise ValueError(f"Refusing to replace multiply-linked report path: {path}")


def _absolute_lexical_path(path: Path, *, resolve_parent_symlinks: bool = False) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if resolve_parent_symlinks:
        return absolute.parent.resolve(strict=False) / absolute.name
    return absolute


def _secure_windows_report_writes_supported() -> bool:
    return os.name == "nt"


def _secure_directory_fd_writes_supported() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.unlink in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
        and callable(getattr(os, "fchmod", None))
        and callable(getattr(os, "fsync", None))
    )


def _open_report_parent_fd(path: Path, *, strict_parent_topology: bool) -> tuple[int, str]:
    absolute = _absolute_lexical_path(
        path,
        resolve_parent_symlinks=not strict_parent_topology,
    )
    if not absolute.name:
        raise ValueError(f"Report output must name a file: {path}")
    parent = absolute.parent
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(parent.anchor or os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parent.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o777, dir_fd=descriptor)
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise ValueError(
                            f"Refusing symlinked or non-directory report parent: {absolute.parent}"
                        ) from exc
                    raise
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        f"Refusing symlinked or non-directory report parent: {absolute.parent}"
                    ) from exc
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor, absolute.name
    except Exception:
        os.close(descriptor)
        raise


def _report_metadata_at(parent_fd: int, filename: str, path: Path) -> os.stat_result | None:
    try:
        metadata = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Refusing to write report through symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Refusing to replace non-regular report path: {path}")
    if metadata.st_nlink != 1:
        raise ValueError(f"Refusing to replace multiply-linked report path: {path}")
    return metadata


def _write_report_with_directory_fd(
    path: Path,
    data: str,
    *,
    strict_parent_topology: bool,
) -> None:
    parent_fd, filename = _open_report_parent_fd(
        path,
        strict_parent_topology=strict_parent_topology,
    )
    temporary_name: str | None = None
    temporary_fd = -1
    try:
        existing = _report_metadata_at(parent_fd, filename, path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        last_collision: FileExistsError | None = None
        for _ in range(8):
            candidate_name = (
                f".naos-report-{os.getpid()}-{secrets.token_hex(8)}.tmp"
            )
            try:
                temporary_fd = os.open(
                    candidate_name,
                    flags,
                    0o666,
                    dir_fd=parent_fd,
                )
            except FileExistsError as exc:
                last_collision = exc
                continue
            temporary_name = candidate_name
            break
        else:
            raise FileExistsError(
                "Unable to allocate a unique same-directory report temporary file."
            ) from last_collision
        if existing is not None:
            os.fchmod(temporary_fd, stat.S_IMODE(existing.st_mode))
        with os.fdopen(temporary_fd, "w", encoding="utf-8", newline="\n") as handle:
            temporary_fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(
            temporary_name,
            filename,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = None
        try:
            os.fsync(parent_fd)
        except OSError:
            # Directory fsync is not portable across every supported filesystem.
            pass
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _validate_report_parent_components(path: Path, *, strict_parent_topology: bool) -> None:
    absolute = _absolute_lexical_path(
        path,
        resolve_parent_symlinks=not strict_parent_topology,
    )
    current = Path(absolute.anchor or os.sep)
    for component in absolute.parent.parts[1:]:
        current = current / component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(
                f"Refusing symlinked or non-directory report parent: {absolute.parent}"
            )


def _write_report_portable_fallback(
    path: Path,
    data: str,
    *,
    strict_parent_topology: bool,
) -> None:
    absolute = _absolute_lexical_path(
        path,
        resolve_parent_symlinks=not strict_parent_topology,
    )
    _validate_report_parent_components(
        absolute,
        strict_parent_topology=strict_parent_topology,
    )
    absolute.parent.mkdir(parents=True, exist_ok=True)
    _validate_report_parent_components(
        absolute,
        strict_parent_topology=strict_parent_topology,
    )
    validate_report_write_path(absolute)
    existing_mode = None
    if absolute.exists():
        existing_mode = stat.S_IMODE(absolute.stat().st_mode)
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=".naos-report-",
        suffix=".tmp",
        dir=absolute.parent,
    )
    try:
        if existing_mode is not None and hasattr(os, "fchmod"):
            os.fchmod(temporary_fd, existing_mode)
        with os.fdopen(temporary_fd, "w", encoding="utf-8", newline="\n") as handle:
            temporary_fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, absolute)
        temporary_name = ""
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def write_report(
    path: Path | None,
    report: dict[str, Any],
    *,
    strict_parent_topology: bool = False,
) -> None:
    from naos_self_check_inspection import logicalize_payload, inspection_publish_path
    logicalize_payload(report)
    if path is None:
        return
    path = inspection_publish_path(path)
    data = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if _secure_directory_fd_writes_supported():
        _write_report_with_directory_fd(
            path,
            data,
            strict_parent_topology=strict_parent_topology,
        )
    elif strict_parent_topology and _secure_windows_report_writes_supported():
        from naos_windows_report import write_strict_report

        write_strict_report(path, data)
    elif strict_parent_topology:
        raise RuntimeError(
            "Strict report-parent topology requires secure directory-descriptor writes on this platform; "
            "use --no-write-preview instead."
        )
    else:
        _write_report_portable_fallback(
            path,
            data,
            strict_parent_topology=strict_parent_topology,
        )


def write_report_with_session(
    latest_path: Path | None,
    session_path: Path | None,
    report: dict[str, Any],
    *,
    strict_parent_topology: bool = False,
) -> None:
    write_report(
        latest_path,
        report,
        strict_parent_topology=strict_parent_topology,
    )
    from naos_self_check_inspection import inspection_session_copy_active
    if session_path is not None and session_path != latest_path and not inspection_session_copy_active():
        write_report(
            session_path,
            report,
            strict_parent_topology=strict_parent_topology,
        )


def ignored_scan_dirs(policy: dict[str, Any]) -> set[str]:
    return {str(part) for part in policy.get("paths", {}).get("ignored_scan_dirs", [])}


def should_ignore_path(path: Path, policy: dict[str, Any]) -> bool:
    ignored = ignored_scan_dirs(policy)
    return any(part in ignored for part in path.parts)


def safe_context_phrases(policy: dict[str, Any]) -> list[str]:
    return [str(item).lower() for item in policy.get("claims", {}).get("safe_context_phrases", [])]


def claim_status_values(policy: dict[str, Any]) -> set[str]:
    return {str(item) for item in policy.get("claims", {}).get("status_values", [])}


def claim_revalidation_triggers(policy: dict[str, Any]) -> set[str]:
    return {str(item) for item in policy.get("claims", {}).get("revalidation_triggers", [])}


def overclaim_patterns(policy: dict[str, Any]) -> dict[str, list[str]]:
    raw = policy.get("claims", {}).get("overclaim_patterns", {})
    if not isinstance(raw, dict):
        return {}
    return {
        str(category): [str(pattern) for pattern in patterns]
        for category, patterns in raw.items()
        if isinstance(patterns, list)
    }


def test_evidence_types(policy: dict[str, Any]) -> list[str]:
    return [str(item) for item in policy.get("test_evidence", {}).get("accepted_types", [])]


def evidence_staleness_days(policy: dict[str, Any]) -> int:
    return int(policy.get("evidence", {}).get("default_staleness_days") or 0)


def external_reference_status(policy: dict[str, Any]) -> str:
    return str(policy.get("evidence", {}).get("external_reference_default_status") or "external_reference_unverified")
