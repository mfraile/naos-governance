#!/usr/bin/env python3
"""Evaluate structured control-plane review and research-routing items."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_now_utc,
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

try:  # Installed Standard/Assured adopters receive both scripts together.
    from naos_ai_component_inventory import (  # noqa: E402
        build_expected_report as build_expected_ai_component_inventory,
        relative_bounded_path as bounded_ai_component_inventory_path,
        validate_inventory_report as validate_ai_component_inventory_report,
    )
except ImportError:  # Fail closed in the reconciliation instead of crashing the control plane.
    build_expected_ai_component_inventory = None
    bounded_ai_component_inventory_path = None
    validate_ai_component_inventory_report = None

try:  # Available only after the optional sponsor-registry module is installed.
    from naos_agent_sponsor_registry import (  # noqa: E402
        build_expected_report as build_expected_agent_sponsor_registry,
        relative_bounded_path as bounded_agent_sponsor_registry_path,
        resolve_registry_path as resolve_agent_sponsor_registry_path,
        validate_registry_report as validate_agent_sponsor_registry_report,
    )
except ImportError:  # Absence is not applicable unless registry/report evidence exists.
    build_expected_agent_sponsor_registry = None
    bounded_agent_sponsor_registry_path = None
    resolve_agent_sponsor_registry_path = None
    validate_agent_sponsor_registry_report = None

try:  # Available only after the optional AIVSS arithmetic module is installed.
    from naos_aivss_arithmetic_verification import (  # noqa: E402
        build_expected_report as build_expected_aivss_verification,
        relative_bounded_path as bounded_aivss_path,
        report_review_reason_codes as aivss_report_review_reason_codes,
        resolve_assessments_path as resolve_aivss_assessments_path,
        validate_verification_report as validate_aivss_verification_report,
    )
except ImportError:  # Absence is not applicable unless input/report evidence exists.
    build_expected_aivss_verification = None
    bounded_aivss_path = None
    aivss_report_review_reason_codes = None
    resolve_aivss_assessments_path = None
    validate_aivss_verification_report = None


GOVERNANCE_SOURCE_TYPES = {
    "governance_surface_change",
    "systemic_impact_finding",
    "module_traceability_finding",
    "spec_cascade_finding",
    "maturity_readiness_finding",
    "setup_recommendation_finding",
    "evidence_attestation_finding",
    "evidence_verification_finding",
    "plan_coherence_finding",
    "parallel_lane_handoff_finding",
    "external_sarif_result_finding",
    "ai_component_inventory_finding",
    "agent_sponsor_registry_finding",
    "aivss_arithmetic_verification_finding",
    "model_provider_policy_finding",
    "model_telemetry_evidence_finding",
    "failure_mode_posture_finding",
    "failure_mode_observations_finding",
    "opencode_config_hygiene_finding",
    "design_traceability_finding",
    "ui_experience_quality_finding",
    "manual_review_item",
}
RESEARCH_SOURCE_TYPES = {"research_finding", "autoresearch_finding", "trend_review", "repo_review"}
ROUTED_DISPOSITIONS = {"routed", "accepted_gap", "accepted_risk"}
REVIEW_DISPOSITIONS = {"proposed", "needs_review", "deferred"}
PROFILE_ORDER = {"quickstart": 0, "lite": 1, "standard": 2, "assured": 3}
RISK_TIER_ORDER = {"low": 0, "medium": 1, "high": 2}
PARALLEL_LANE_SOURCE_TYPE = "parallel_lane_handoff_finding"
PARALLEL_LANE_TARGETS = ["control_plane_review", "gatekeepers", "known_gaps", "residual_risks", "next_actions"]
PARALLEL_LANE_REASON_ORDER = [
    "missing_planning_link",
    "dependency_or_claim_conflict",
    "scope_mismatch",
    "changed_file_evidence_gap",
    "test_evidence_gap",
    "evidence_conflict",
    "human_review_disposition_missing",
    "actual_pr_risk_requires_review",
    "planned_actual_risk_mismatch",
]
PARALLEL_LANE_GATES = {
    "missing_planning_link": ["G2", "G6"],
    "dependency_or_claim_conflict": ["G2"],
    "scope_mismatch": ["G3"],
    "changed_file_evidence_gap": ["G4"],
    "test_evidence_gap": ["G5"],
    "evidence_conflict": ["G6"],
    "human_review_disposition_missing": ["G6"],
    "actual_pr_risk_requires_review": ["G6"],
    "planned_actual_risk_mismatch": ["G2", "G6"],
}
PARALLEL_LANE_NOT_CLAIMED = [
    "approval",
    "merge approval",
    "task closure",
    "release authorization",
    "publication authorization",
    "legal or regulatory compliance",
    "proof of compliance",
    "certification",
    "attestation",
    "runtime orchestration",
    "agent dispatch",
    "MCP activation",
    "memory activation",
    "provider/model activation",
]
PARALLEL_LANE_LIMITATIONS = [
    "Parallel-lane reconciliation is deterministic local review routing only.",
    "HITL reason codes explain review triggers; no numeric risk score is authoritative.",
    "The route does not approve, merge, close tasks, release, publish, dispatch agents, run tests, or activate runtime integrations.",
    "Missing or low PR-risk evidence is not treated as proof that planned work is safe or complete.",
]
EXTERNAL_SARIF_SOURCE_TYPE = "external_sarif_result_finding"
EXTERNAL_SARIF_TARGETS = [
    "external_evidence_ingest",
    "external_evidence_ingest_report",
    "control_plane_review",
    "gatekeepers",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
EXTERNAL_SARIF_REASON_ORDER = [
    "external_report_schema_invalid",
    "external_report_content_mismatch",
    "external_result_review_required",
    "external_result_identity_positional",
    "external_result_vocabulary_unmapped",
    "external_result_control_link_missing",
    "external_result_control_link_unverified",
    "external_assessment_not_assessed",
    "external_assessment_unknown",
    "external_assessment_failed",
    "external_zero_results_scope_review",
    "external_coverage_not_declared",
]
EXTERNAL_SARIF_GATES = {
    "external_report_schema_invalid": ["G2", "G6"],
    "external_report_content_mismatch": ["G2", "G6"],
    "external_result_review_required": ["G6"],
    "external_result_identity_positional": ["G2", "G6"],
    "external_result_vocabulary_unmapped": ["G2", "G6"],
    "external_result_control_link_missing": ["G2", "G6"],
    "external_result_control_link_unverified": ["G6"],
    "external_assessment_not_assessed": ["G2", "G6"],
    "external_assessment_unknown": ["G2", "G6"],
    "external_assessment_failed": ["G2", "G6"],
    "external_zero_results_scope_review": ["G6"],
    "external_coverage_not_declared": ["G6"],
}
EXTERNAL_SARIF_NOT_CLAIMED = [
    "finding verification",
    "risk or severity mapping",
    "control satisfaction",
    "assessed-scope completeness",
    "vulnerability absence",
    "automatic approval or blocking",
    "automatic prioritization",
    "automatic task creation or writeback",
    "merge authority",
    "release authority",
    "risk acceptance",
    "compliance evidence",
    "certification",
    "publication authority",
]
EXTERNAL_SARIF_LIMITATIONS = [
    "External-SARIF reconciliation reads the local ingest report only and emits advisory human-review prompts.",
    "Imported message text and raw SARIF payloads are not retained in result records.",
    "Native levels and source-declared taxonomy references remain unverified and are not mapped to NAOS risk, severity, controls, or requirements authority.",
    "A repeated prompt is not a durable human disposition, waiver, task link, remediation state, or closed-loop lifecycle.",
    "Zero reported results and source execution status do not establish scanner correctness, assessed-scope completeness, or vulnerability absence.",
]
EXTERNAL_SARIF_RESULT_REQUIRED_FIELDS = {
    "external_result_id",
    "origin",
    "source_sha256",
    "run_index",
    "result_index",
    "identity_basis",
    "identity_stability",
    "source_identity_sha256",
    "tool_name",
    "tool_version",
    "native_rule_id",
    "native_level",
    "native_level_status",
    "artifact_uri",
    "source_declared_taxonomy_refs",
    "control_link_status",
    "classification",
    "verification_status",
    "review_disposition",
    "human_review_required",
    "message_retention",
}
MODEL_PROVIDER_SOURCE_TYPE = "model_provider_policy_finding"
MODEL_PROVIDER_TARGETS = [
    "model_provider_policy",
    "model_provider_policy_report",
    "llm_grader_readiness",
    "autoresearch_model_policy",
    "semantic_candidate_layer",
    "ai_surfaces",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
MODEL_PROVIDER_REASON_ORDER = [
    "missing_project_policy",
    "runtime_escalation",
    "literal_secret",
    "missing_role",
    "invalid_provider_kind",
    "alias_review_required",
    "advisory_boundary_missing",
    "duplicate_provider_details",
    "env_reference_review",
    "local_endpoint_exposure_review",
    "model_provider_review_required",
]
MODEL_PROVIDER_GATES = {
    "missing_project_policy": ["G2", "G6"],
    "runtime_escalation": ["G6"],
    "literal_secret": ["G6"],
    "missing_role": ["G2", "G6"],
    "invalid_provider_kind": ["G2", "G6"],
    "alias_review_required": ["G6"],
    "advisory_boundary_missing": ["G6"],
    "duplicate_provider_details": ["G2", "G6"],
    "env_reference_review": ["G6"],
    "local_endpoint_exposure_review": ["G6"],
    "model_provider_review_required": ["G6"],
}
MODEL_PROVIDER_NOT_CLAIMED = [
    "provider call",
    "local model call",
    "cloud API call",
    "SDK dependency",
    "network probe",
    "proxy startup",
    "credential validation",
    "model recommendation",
    "provider catalog",
    "runtime model routing",
    "LLMGrader activation",
    "autoresearch provider grading",
    "semantic evidence activation",
    "approval",
    "certification",
    "attestation",
    "legal or regulatory compliance",
    "proof of compliance",
    "release authority",
    "publication authority",
]
MODEL_PROVIDER_LIMITATIONS = [
    "Model-provider reconciliation reads the local model-provider policy report only.",
    "The route does not call providers, models, APIs, proxies, local servers, or memory tools.",
    "The route does not inspect, mutate, enable, disable, or configure MCP/Engram; memory/MCP posture remains governed by the dedicated memory commands and reports.",
    "The route does not validate credentials, recommend models, maintain provider catalogs, or route runtime calls.",
    "Reason codes are deterministic review triggers, not approval, certification, attestation, legal assurance, or compliance proof.",
]
AI_COMPONENT_INVENTORY_SOURCE_TYPE = "ai_component_inventory_finding"
AI_COMPONENT_INVENTORY_TARGETS = [
    "ai_component_inventory",
    "ai_component_inventory_report",
    "ai_surfaces",
    "model_provider_policy",
    "control_plane_review",
    "gatekeepers",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
AI_COMPONENT_INVENTORY_REASON_ORDER = [
    "inventory_report_missing",
    "inventory_report_parse_error",
    "inventory_schema_invalid",
    "inventory_source_stale",
    "inventory_content_mismatch",
    "inventory_required_fields_missing",
    "inventory_review_required",
    "inventory_consumer_unavailable",
]
AI_COMPONENT_INVENTORY_GATES = {code: ["G2", "G6"] for code in AI_COMPONENT_INVENTORY_REASON_ORDER}
AI_COMPONENT_INVENTORY_NOT_CLAIMED = [
    "CycloneDX conformance",
    "SPDX conformance",
    "software bill of materials",
    "runtime discovery",
    "inventory completeness",
    "provider or model identity verification",
    "signing",
    "attestation",
    "provenance authenticity",
    "supply-chain assurance",
    "approval",
    "certification",
    "legal or regulatory compliance",
    "release authority",
    "publication authority",
]
AI_COMPONENT_INVENTORY_LIMITATIONS = [
    "AI-component reconciliation consumes local declared-facts inventory evidence only.",
    "Content digests detect change but do not authenticate authors, attest provenance, discover runtime components, or prove completeness.",
    "G2/G6 routes require human review and do not approve, block, merge, release, publish, sign, attest, or activate providers, models, MCP, memory, or runtime systems.",
]
AGENT_SPONSOR_REGISTRY_SOURCE_TYPE = "agent_sponsor_registry_finding"
AGENT_SPONSOR_REGISTRY_TARGETS = [
    "agent_sponsor_registry",
    "agent_sponsor_registry_report",
    "ai_surfaces",
    "control_plane_review",
    "gatekeepers",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
AGENT_SPONSOR_REGISTRY_REASON_ORDER = [
    "registry_config_unsafe_path",
    "registry_config_missing",
    "registry_report_unsafe_path",
    "registry_report_missing",
    "registry_report_parse_error",
    "registry_report_schema_invalid",
    "registry_source_stale",
    "registry_content_mismatch",
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
    "registry_consumer_unavailable",
]
AGENT_SPONSOR_REGISTRY_GATES = {
    code: ["G2", "G6"] for code in AGENT_SPONSOR_REGISTRY_REASON_ORDER
}
AGENT_SPONSOR_REGISTRY_NOT_CLAIMED = [
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
    "approval",
    "certification",
    "legal or regulatory compliance",
    "release authority",
    "publication authority",
]
AGENT_SPONSOR_REGISTRY_LIMITATIONS = [
    "Sponsor-registry reconciliation consumes an optional repository-local declared-posture report only.",
    "Opaque sponsor, owner, and control references are not resolved or identity-verified.",
    "Review expiry is not credential TTL, issuance, rotation, revocation, authentication, authorization, or runtime enforcement evidence.",
    "G2/G6 routes require human review and grant no approval, blocking, merge, release, publication, agent, provider, MCP, memory, identity, or credential authority.",
]
AIVSS_SOURCE_TYPE = "aivss_arithmetic_verification_finding"
AIVSS_TARGETS = [
    "aivss_assessments",
    "aivss_arithmetic_verification_report",
    "control_plane_review",
    "gatekeepers",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
AIVSS_REASON_ORDER = [
    "aivss_input_unsafe_path",
    "aivss_input_missing",
    "aivss_report_unsafe_path",
    "aivss_report_missing",
    "aivss_report_parse_error",
    "aivss_report_schema_invalid",
    "aivss_source_stale",
    "aivss_content_mismatch",
    "input_config_parse_error",
    "input_schema_invalid",
    "duplicate_assessment_id",
    "arithmetic_mismatch",
    "high_or_critical_review",
    "aivss_consumer_unavailable",
]
AIVSS_GATES = {code: ["G2", "G6"] for code in AIVSS_REASON_ORDER}
AIVSS_NOT_CLAIMED = [
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
AIVSS_LIMITATIONS = [
    "AIVSS reconciliation consumes optional repo-local arithmetic-verification evidence only; assessors remain responsible for every subjective input.",
    "The pinned v0.8 PDF permits 0.0 but defines no band for it, so 0.0 remains explicitly unbanded and creates no score-based route.",
    "High/Critical and mismatch routes are fixed advisory G2/G6 review prompts; they never approve, block, prioritize, merge, release, accept risk, or mutate durable project state.",
]
MODEL_TELEMETRY_SOURCE_TYPE = "model_telemetry_evidence_finding"
MODEL_TELEMETRY_TARGETS = [
    "model_telemetry_evidence",
    "model_telemetry_evidence_report",
    "model_provider_policy",
    "agent_trace_validation",
    "session_lifecycle",
    "control_plane_review",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
MODEL_TELEMETRY_REASON_ORDER = [
    "telemetry_source_unreadable",
    "sensitive_payload_capture",
    "credential_capture",
    "missing_session_link",
    "missing_task_link",
    "missing_model_role",
    "undeclared_model_role",
    "model_provider_policy_link_missing",
    "unknown_route_class",
    "sensitive_data_class_review",
    "cost_threshold_exceeded",
    "latency_threshold_exceeded",
    "stale_telemetry",
    "policy_exception_declared",
    "provider_runtime_authority_attempt",
    "model_telemetry_review_required",
]
MODEL_TELEMETRY_GATES = {
    "telemetry_source_unreadable": ["G6"],
    "sensitive_payload_capture": ["G6"],
    "credential_capture": ["G6"],
    "missing_session_link": ["G2", "G6"],
    "missing_task_link": ["G2", "G6"],
    "missing_model_role": ["G2", "G6"],
    "undeclared_model_role": ["G2", "G6"],
    "model_provider_policy_link_missing": ["G2", "G6"],
    "unknown_route_class": ["G2", "G6"],
    "sensitive_data_class_review": ["G6"],
    "cost_threshold_exceeded": ["G6"],
    "latency_threshold_exceeded": ["G6"],
    "stale_telemetry": ["G6"],
    "policy_exception_declared": ["G6"],
    "provider_runtime_authority_attempt": ["G6"],
    "model_telemetry_review_required": ["G6"],
}
MODEL_TELEMETRY_NOT_CLAIMED = [
    "LiteLLM integration",
    "provider gateway availability",
    "provider call",
    "model call",
    "API call",
    "network access",
    "MCP activation",
    "memory activation",
    "credential validation",
    "runtime model routing",
    "route enforcement",
    "complete cost accounting",
    "payload safety proof",
    "route correctness proof",
    "policy compliance proof",
    "approval",
    "certification",
    "attestation",
    "legal or regulatory compliance",
    "proof of compliance",
    "release authority",
    "publication authority",
]
MODEL_TELEMETRY_LIMITATIONS = [
    "Model telemetry reconciliation reads the local model telemetry evidence report only.",
    "The route treats cost, latency, route class, session/task links, and policy exceptions as declared review evidence, not proof of runtime behavior.",
    "The route does not call providers, models, APIs, gateways, MCP, memory tools, local servers, networks, hooks, or IDE/tool configuration.",
    "Reason codes are deterministic review triggers, not route enforcement, complete cost accounting, payload safety proof, approval, certification, attestation, legal assurance, or proof of compliance.",
    "Assured-profile findings remain review evidence in this slice; blocking requires a future validated L3+ maturity control and explicit gate wiring.",
]
FAILURE_MODE_POSTURE_SOURCE_TYPE = "failure_mode_posture_finding"
FAILURE_MODE_POSTURE_TARGETS = [
    "failure_mode_posture",
    "failure_mode_posture_report",
    "behavioral_governance_readiness",
    "control_plane_review",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
FAILURE_MODE_POSTURE_REASON_ORDER = [
    "taxonomy_count_mismatch",
    "unknown_mode_id",
    "duplicate_mode_id",
    "missing_mode_record",
    "invalid_coverage_value",
    "coverage_overclaim",
    "strong_without_evidence",
    "missing_control_ref",
    "missing_evidence_ref",
    "stale_evidence_ref",
    "complementary_claimed_as_core",
    "human_review_posture_missing",
    "behavioral_readiness_duplication",
    "runtime_or_provider_authority_attempt",
    "failure_mode_posture_review_required",
]
FAILURE_MODE_POSTURE_GATES = {
    "taxonomy_count_mismatch": ["G2", "G6"],
    "unknown_mode_id": ["G2", "G6"],
    "duplicate_mode_id": ["G2", "G6"],
    "missing_mode_record": ["G2", "G6"],
    "invalid_coverage_value": ["G2", "G6"],
    "coverage_overclaim": ["G6"],
    "strong_without_evidence": ["G6"],
    "missing_control_ref": ["G2", "G6"],
    "missing_evidence_ref": ["G6"],
    "stale_evidence_ref": ["G6"],
    "complementary_claimed_as_core": ["G6"],
    "human_review_posture_missing": ["G6"],
    "behavioral_readiness_duplication": ["G6"],
    "runtime_or_provider_authority_attempt": ["G6"],
    "failure_mode_posture_review_required": ["G6"],
}
FAILURE_MODE_POSTURE_NOT_CLAIMED = [
    "hallucination prevention",
    "failure prevention",
    "fully mitigated failure modes",
    "behavioral safety proof",
    "runtime monitoring",
    "runtime orchestration",
    "provider call",
    "model call",
    "API call",
    "network access",
    "MCP activation",
    "memory activation",
    "automatic learning promotion",
    "automatic approval",
    "automatic blocking",
    "certification",
    "attestation",
    "release authority",
    "publication authority",
    "legal or regulatory compliance",
    "proof of compliance",
]
FAILURE_MODE_POSTURE_LIMITATIONS = [
    "Failure-mode posture reconciliation reads the local failure-mode posture report only.",
    "The route treats coverage, mode counts, family counts, control refs, evidence refs, gaps, and residual risks as declared review evidence, not proof that failures are prevented or fully mitigated.",
    "Mode and family statistics may inform human review, learning-loop review, or autoresearch scoping, but they are not a risk score, automatic learning authority, prompt mutation authority, provider/model route, approval, or blocking rule.",
    "The route does not call providers, models, APIs, MCP, memory tools, local servers, networks, hooks, browsers, behavioral batteries, or IDE/tool configuration.",
    "Assured-profile findings remain review evidence in this slice; blocking requires a future validated L3+ maturity control and explicit gate wiring.",
]
FAILURE_MODE_OBSERVATIONS_SOURCE_TYPE = "failure_mode_observations_finding"
FAILURE_MODE_OBSERVATIONS_TARGETS = [
    "failure_mode_observations",
    "failure_mode_observations_report",
    "failure_mode_posture",
    "learning_loop_review",
    "evidence_pack",
    "dashboard",
    "sarif_export",
    "gatekeepers",
    "systemic_impact",
    "control_plane_review",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
FAILURE_MODE_OBSERVATIONS_REASON_ORDER = [
    "required_source_missing",
    "source_report_malformed",
    "source_report_excluded",
    "unknown_mode_id",
    "unmapped_observation",
    "source_human_review_required",
    "high_severity_observation",
    "runtime_or_provider_authority_attempt",
    "failure_mode_observations_review_required",
]
FAILURE_MODE_OBSERVATIONS_GATES = {
    "required_source_missing": ["G6"],
    "source_report_malformed": ["G6"],
    "source_report_excluded": ["G6"],
    "unknown_mode_id": ["G2", "G6"],
    "unmapped_observation": ["G2", "G6"],
    "source_human_review_required": ["G6"],
    "high_severity_observation": ["G6"],
    "runtime_or_provider_authority_attempt": ["G6"],
    "failure_mode_observations_review_required": ["G6"],
}
FAILURE_MODE_OBSERVATIONS_NOT_CLAIMED = [
    "self-learning model weights",
    "autonomous skill promotion",
    "automatic memory write-back",
    "automatic context injection",
    "automatic prompt mutation",
    "automatic learning promotion",
    "provider call",
    "model call",
    "API call",
    "network access",
    "MCP activation",
    "Engram activation",
    "memory activation",
    "runtime orchestration",
    "numeric risk score authority",
    "approval",
    "automatic blocking",
    "certification",
    "attestation",
    "release authority",
    "publication authority",
    "legal or regulatory compliance",
    "proof of compliance",
]
FAILURE_MODE_OBSERVATIONS_LIMITATIONS = [
    "Failure-mode observations reconciliation reads the local failure-mode observations report only.",
    "The observations report excludes control_plane_review.json as an input; control-plane consumes it downstream to avoid cyclic evidence.",
    "Mode, family, source, reason-code, severity, gate, and mapping-basis counts are review statistics, not a numeric risk score, approval authority, or blocking rule.",
    "Observation statistics may inform human review, learning-loop review, or autoresearch scoping, but they do not write learning records, mutate prompts/skills/workflows, or promote guidance.",
    "The route does not call providers, models, APIs, MCP, Engram, memory tools, local servers, networks, hooks, browsers, behavioral batteries, or IDE/tool configuration.",
    "Assured-profile findings remain review evidence in this slice; blocking requires a future validated L3+ maturity control and explicit gate wiring.",
]
OPENCODE_CONFIG_HYGIENE_SOURCE_TYPE = "opencode_config_hygiene_finding"
OPENCODE_CONFIG_HYGIENE_TARGETS = [
    "opencode_config_hygiene",
    "opencode_config_hygiene_report",
    "model_provider_policy",
    "ai_surfaces",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
OPENCODE_CONFIG_HYGIENE_REASON_ORDER = [
    "opencode_project_config_malformed",
    "stale_opencode_yaml_config",
    "remote_instruction_review",
    "absolute_instruction_review",
    "broad_permission_review",
    "auto_approval_review",
    "mcp_enabled_review",
    "mcp_remote_review",
    "mcp_auth_review",
    "plugin_external_review",
    "plugin_local_review",
    "model_provider_policy_link_missing",
    "model_provider_drift",
    "literal_secret",
    "opencode_runtime_authority_attempt",
    "opencode_config_review_required",
]
OPENCODE_CONFIG_HYGIENE_GATES = {
    "opencode_project_config_malformed": ["G2", "G6"],
    "stale_opencode_yaml_config": ["G2", "G6"],
    "remote_instruction_review": ["G3", "G6"],
    "absolute_instruction_review": ["G3", "G6"],
    "broad_permission_review": ["G3", "G6"],
    "auto_approval_review": ["G6"],
    "mcp_enabled_review": ["G6"],
    "mcp_remote_review": ["G3", "G6"],
    "mcp_auth_review": ["G6"],
    "plugin_external_review": ["G3", "G6"],
    "plugin_local_review": ["G3", "G6"],
    "model_provider_policy_link_missing": ["G2", "G6"],
    "model_provider_drift": ["G2", "G6"],
    "literal_secret": ["G6"],
    "opencode_runtime_authority_attempt": ["G6"],
    "opencode_config_review_required": ["G2", "G6"],
}
OPENCODE_CONFIG_HYGIENE_NOT_CLAIMED = [
    "OpenCode installation",
    "OpenCode execution",
    "OpenCode plugin creation",
    "global OpenCode config inspection",
    "MCP activation",
    "memory activation",
    "provider call",
    "model call",
    "API call",
    "network access",
    "credential validation",
    "secret scanner completeness",
    "malware absence",
    "supply-chain safety proof",
    "prompt-injection prevention",
    "runtime sandboxing",
    "runtime orchestration",
    "provider route correctness",
    "model recommendation",
    "IDE/tool configuration mutation",
    "approval",
    "merge approval",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "proof of compliance",
]
OPENCODE_CONFIG_HYGIENE_LIMITATIONS = [
    "OpenCode config hygiene reconciliation reads the local OpenCode config hygiene report only.",
    "The route treats OpenCode config, MCP, plugin, permission, literal-secret, and model-provider drift findings as review evidence, not runtime or security proof.",
    "The route does not create, install, run, configure, enable, disable, or mutate OpenCode, MCP, memory, providers, models, hooks, IDE settings, global config, credentials, plugins, or runtime systems.",
    "Reason codes are deterministic review triggers, not approval, certification, attestation, legal assurance, proof of compliance, prompt-injection prevention, malware absence, or supply-chain safety proof.",
    "Blocking-style unsafe declaration findings remain local review evidence and do not grant provider, model, MCP, memory, hook, OpenCode runtime, merge, release, or publication authority.",
]
DESIGN_TRACEABILITY_SOURCE_TYPE = "design_traceability_finding"
DESIGN_TRACEABILITY_TARGETS = [
    "design_traceability",
    "design_traceability_report",
    "control_plane_review",
    "gatekeepers",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
DESIGN_TRACEABILITY_REASON_ORDER = [
    "duplicate_object_id",
    "missing_object_id",
    "missing_fr_nfr_task_link",
    "missing_screen_spec_path",
    "missing_implementation_path",
    "referenced_path_missing",
    "changed_file_evidence_gap",
    "test_evidence_gap",
    "optional_design_ref_unreviewed",
    "stale_or_conflicting_evidence",
    "human_review_disposition_missing",
    "design_traceability_review_required",
]
DESIGN_TRACEABILITY_GATES = {
    "duplicate_object_id": ["G2", "G6"],
    "missing_object_id": ["G2", "G6"],
    "missing_fr_nfr_task_link": ["G2", "G6"],
    "missing_screen_spec_path": ["G2", "G6"],
    "missing_implementation_path": ["G3", "G4"],
    "referenced_path_missing": ["G3", "G6"],
    "changed_file_evidence_gap": ["G4"],
    "test_evidence_gap": ["G5"],
    "optional_design_ref_unreviewed": ["G6"],
    "stale_or_conflicting_evidence": ["G6"],
    "human_review_disposition_missing": ["G6"],
    "design_traceability_review_required": ["G6"],
}
DESIGN_TRACEABILITY_NOT_CLAIMED = [
    "automatic code-to-design synchronization",
    "automatic design-to-code synchronization",
    "Figma availability",
    "Figma API access",
    "MCP activation",
    "html.to.design fidelity",
    "design quality proof",
    "accessibility certification",
    "privacy compliance determination",
    "brand compliance proof",
    "approval",
    "merge approval",
    "task completion proof",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "legal or regulatory compliance",
    "proof of compliance",
    "runtime orchestration",
    "provider calls",
    "model calls",
    "memory activation",
]
DESIGN_TRACEABILITY_LIMITATIONS = [
    "Design-traceability reconciliation reads the local design traceability report only.",
    "The route treats optional design references as references, not proof of design-tool state or synchronization.",
    "The route does not inspect, call, configure, enable, disable, or mutate Figma, MCP, html.to.design, browsers, providers, models, memory tools, hooks, or IDE settings.",
    "Reason codes are deterministic review triggers, not design quality proof, accessibility proof, privacy proof, brand proof, approval, certification, attestation, legal assurance, or compliance proof.",
    "Assured-profile findings remain review evidence in this slice; blocking requires a future validated L3+ maturity control and explicit gate wiring.",
]
UI_EXPERIENCE_QUALITY_SOURCE_TYPE = "ui_experience_quality_finding"
UI_EXPERIENCE_QUALITY_TARGETS = [
    "ui_experience_quality",
    "ui_experience_quality_report",
    "design_traceability",
    "model_provider_policy",
    "control_plane_review",
    "gatekeepers",
    "known_gaps",
    "residual_risks",
    "next_actions",
]
UI_EXPERIENCE_QUALITY_REASON_ORDER = [
    "missing_quality_brief",
    "stage_dependency_gap",
    "provisional_dependency_unresolved",
    "missing_object_trace",
    "data_contract_gap",
    "state_model_gap",
    "missing_token_baseline",
    "brand_token_drift",
    "typography_scale_gap",
    "spacing_rhythm_gap",
    "layout_hierarchy_unreviewed",
    "responsive_state_gap",
    "interaction_state_gap",
    "empty_error_loading_state_gap",
    "motion_reduction_gap",
    "accessibility_evidence_gap",
    "visual_regression_unreviewed",
    "screenshot_set_gap",
    "content_clarity_gap",
    "performance_perception_gap",
    "inspiration_provenance_gap",
    "external_generator_provenance_gap",
    "advisory_ai_critique_unbounded",
    "human_design_review_missing",
    "user_validation_missing",
    "mcp_or_tool_mutation_attempt",
    "ui_experience_quality_review_required",
]
UI_EXPERIENCE_QUALITY_GATES = {
    "missing_quality_brief": ["G2", "G6"],
    "stage_dependency_gap": ["G2", "G6"],
    "provisional_dependency_unresolved": ["G2", "G6"],
    "missing_object_trace": ["G2", "G6"],
    "data_contract_gap": ["G2", "G3", "G6"],
    "state_model_gap": ["G4", "G5", "G6"],
    "missing_token_baseline": ["G3", "G4", "G6"],
    "brand_token_drift": ["G3", "G4", "G6"],
    "typography_scale_gap": ["G3", "G4", "G6"],
    "spacing_rhythm_gap": ["G3", "G4", "G6"],
    "layout_hierarchy_unreviewed": ["G6"],
    "responsive_state_gap": ["G5", "G6"],
    "interaction_state_gap": ["G4", "G5", "G6"],
    "empty_error_loading_state_gap": ["G4", "G5", "G6"],
    "motion_reduction_gap": ["G5", "G6"],
    "accessibility_evidence_gap": ["G5", "G6"],
    "visual_regression_unreviewed": ["G5", "G6"],
    "screenshot_set_gap": ["G5", "G6"],
    "content_clarity_gap": ["G2", "G3", "G6"],
    "performance_perception_gap": ["G5", "G6"],
    "inspiration_provenance_gap": ["G6"],
    "external_generator_provenance_gap": ["G3", "G6"],
    "advisory_ai_critique_unbounded": ["G6"],
    "human_design_review_missing": ["G6"],
    "user_validation_missing": ["G2", "G6"],
    "mcp_or_tool_mutation_attempt": ["G3", "G6"],
    "ui_experience_quality_review_required": ["G6"],
}
UI_EXPERIENCE_QUALITY_NOT_CLAIMED = [
    "Figma MCP replacement",
    "automatic code-to-design synchronization",
    "automatic design-to-code synchronization",
    "Figma availability",
    "Figma API access",
    "MCP activation",
    "design quality proof",
    "user delight proof",
    "brand approval",
    "accessibility compliance proof",
    "privacy compliance proof",
    "legal or regulatory compliance",
    "proof of compliance",
    "approval",
    "merge approval",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "runtime orchestration",
    "provider calls",
    "model calls",
    "memory activation",
]
UI_EXPERIENCE_QUALITY_LIMITATIONS = [
    "UI experience quality reconciliation reads the local UI experience quality report only.",
    "The route treats screenshots, visual-regression refs, accessibility refs, generator refs, and AI critique refs as declared review evidence, not proof of quality.",
    "The route does not inspect, call, configure, enable, disable, or mutate Figma, MCP, Penpot, html.to.design, browsers, providers, models, memory tools, hooks, IDE settings, design tools, or runtime systems.",
    "Reason codes are deterministic review triggers, not design quality proof, user delight proof, accessibility proof, privacy proof, brand approval, certification, attestation, legal assurance, or proof of compliance.",
    "Assured-profile findings remain review evidence in this slice; blocking requires a future validated L3+ maturity control and explicit gate wiring.",
]


def utc_now_text() -> str:
    return controlled_utc_now_text()


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "control_plane_review_rules.yaml"


def default_items_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "control_plane_review_items.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("control_plane_review_rules") or "control_plane_review_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def resolve_items_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(
        policy.get("paths", {}).get("control_plane_review_items")
        or rules.get("items_file")
        or "control_plane_review_items.yaml"
    )
    project_items = root / naos_root / filename
    if project_items.exists():
        return project_items, "project"
    return default_items_template(), "template"


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def rule_severity(root: Path, naos_root: str, profile: str, policy: dict[str, Any], rules: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    mapping = rules.get("profile_severity_behavior") if isinstance(rules.get("profile_severity_behavior"), dict) else {}
    return str(mapping.get(profile) or severity_for_profile(profile, policy) or "advisory")


def parse_date(value: Any) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if not value:
        return None
    text = str(value)
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def source_is_ignored(source_ref: str, rules: dict[str, Any]) -> bool:
    normalized = source_ref.strip().lstrip("./")
    for pattern in as_list(rules.get("ignored_source_patterns")):
        if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(f"{normalized}/", pattern):
            return True
    return False


def item_human_review_required(item: dict[str, Any], rules: dict[str, Any], status: str) -> bool:
    if item.get("human_review_required") is not None:
        return bool(item.get("human_review_required"))
    source_type = str(item.get("source_type") or "")
    mapping = rules.get("human_review_required") if isinstance(rules.get("human_review_required"), dict) else {}
    return bool(mapping.get(source_type, status in {"missing_routing", "review_required", "blocked"}))


def finding(
    *,
    item_id: str,
    severity: str,
    status: str,
    message: str,
    source_type: str | None = None,
    source_ref: str | None = None,
    target_surfaces: list[str] | None = None,
    required_next_actions: list[str] | None = None,
) -> dict[str, Any]:
    result = {
        "id": item_id,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": required_next_actions or [],
    }
    if source_type:
        result["source_type"] = source_type
    if source_ref:
        result["source_ref"] = source_ref
    if target_surfaces is not None:
        result["target_surfaces"] = target_surfaces
    return result


def required_actions_for(item: dict[str, Any], status: str, expected_missing: list[str]) -> list[str]:
    if status == "missing_routing":
        targets = ", ".join(expected_missing) if expected_missing else "one or more target surfaces"
        return [f"Route this item into {targets}, or record a known gap, residual risk, waiver, or next action."]
    if status == "review_required":
        return ["Review and approve disposition, target routing, next action, waiver, or residual risk treatment."]
    if status == "waived":
        return ["Review waiver expiry and residual risk; waivers remain visible and do not convert routing to pass."]
    if status == "blocked":
        return ["Resolve blocking routing issue before treating this item as complete."]
    if status == "unknown":
        return ["Correct invalid source type, target surface, disposition, or required fields."]
    return ["Keep routing decision current when related control-plane surfaces change."]


def relative_ref(root: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError:
        return path.as_posix()


def optional_artifact_state(path: Path, root: Path) -> str:
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


def bounded_lexical_ref(root: Path, path: Path, *, unsafe_label: str) -> str:
    if ".." in path.parts:
        return unsafe_label
    try:
        return path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError:
        return unsafe_label


def report_path(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    filename = str(policy.get("paths", {}).get(key) or key)
    return root / naos_root / reports_dir / filename


def load_json_report(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    return data if isinstance(data, dict) else {}, None


def load_alignment_frontmatter(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    filename = str(policy.get("paths", {}).get("pre_implementation_alignment") or "PRE_IMPLEMENTATION_ALIGNMENT.md")
    path = root / naos_root / filename
    if not path.exists():
        return {}, None
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}, relative_ref(root, path)
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, relative_ref(root, path)
    data = yaml.safe_load(parts[1]) or {}
    return (data if isinstance(data, dict) else {}), relative_ref(root, path)


def risk_tier(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    return text if text in RISK_TIER_ORDER else None


def profile_escalates(profile: str, effective_profile: Any) -> bool:
    effective = str(effective_profile or "").strip().lower()
    if effective not in PROFILE_ORDER or profile not in PROFILE_ORDER:
        return False
    return PROFILE_ORDER[effective] > PROFILE_ORDER[profile]


def int_count(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def route_severity_for_parallel_lane(root: Path, naos_root: str, profile: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_model_provider(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    report_status: str | None,
    report_findings: list[dict[str, Any]],
) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    severities = [str(item.get("severity") or "") for item in report_findings]
    if report_status == "blocked" or "blocking" in severities:
        return "blocking"
    for severity in ("required", "warning", "advisory"):
        if severity in severities:
            return severity
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_model_telemetry(root: Path, naos_root: str, profile: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_failure_mode_posture(root: Path, naos_root: str, profile: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_failure_mode_observations(root: Path, naos_root: str, profile: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_opencode_config_hygiene(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    report_status: str | None,
    report_findings: list[dict[str, Any]],
) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    severities = [str(item.get("severity") or "") for item in report_findings]
    if report_status == "blocked" or "blocking" in severities:
        return "blocking"
    for severity in ("required", "warning", "advisory"):
        if severity in severities:
            return severity
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_design_traceability(root: Path, naos_root: str, profile: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def route_severity_for_ui_experience_quality(root: Path, naos_root: str, profile: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    return {"quickstart": "advisory", "lite": "warning", "standard": "required", "assured": "required"}.get(profile, "advisory")


def matching_task_claims(task_claim_report: dict[str, Any] | None, task_id: str | None) -> list[dict[str, Any]]:
    if not task_claim_report or not task_id:
        return []
    return [
        claim
        for claim in task_claim_report.get("claims") or []
        if isinstance(claim, dict) and str(claim.get("task_id") or "") == task_id
    ]


def planned_risk_tier(
    *,
    lane_report: dict[str, Any],
    task_claim_report: dict[str, Any] | None,
    alignment_data: dict[str, Any],
) -> tuple[str | None, str | None]:
    lane = lane_report.get("lane") if isinstance(lane_report.get("lane"), dict) else {}
    for source, value in (
        ("parallel_lane_handoff.lane.risk_tier", lane.get("risk_tier")),
        ("parallel_lane_handoff.risk_tier", lane_report.get("risk_tier")),
    ):
        tier = risk_tier(value)
        if tier:
            return tier, source
    task_id = str(lane.get("task_id") or "") or None
    for claim in matching_task_claims(task_claim_report, task_id):
        tier = risk_tier(claim.get("risk_tier"))
        if tier:
            claim_id = claim.get("claim_id") or task_id
            return tier, f"task_claim_report.claims[{claim_id}].risk_tier"
    extensions = alignment_data.get("extensions") if isinstance(alignment_data.get("extensions"), dict) else {}
    for source, value in (
        ("pre_implementation_alignment.extensions.planned_risk_tier", extensions.get("planned_risk_tier")),
        ("pre_implementation_alignment.extensions.risk_tier", extensions.get("risk_tier")),
        ("pre_implementation_alignment.risk_tier", alignment_data.get("risk_tier")),
    ):
        tier = risk_tier(value)
        if tier:
            return tier, source
    return None, None


def append_reason(reasons: set[str], code: str) -> None:
    if code in PARALLEL_LANE_REASON_ORDER:
        reasons.add(code)


def append_model_provider_reason(reasons: set[str], code: str) -> None:
    if code in MODEL_PROVIDER_REASON_ORDER:
        reasons.add(code)


def model_provider_reason_code(finding_id: Any) -> str:
    text = str(finding_id or "").strip()
    if text in {"model_provider.missing_project_policy", "model_provider.policy_missing"}:
        return "missing_project_policy"
    if text.startswith("model_provider.runtime_escalation"):
        return "runtime_escalation"
    if text == "model_provider.literal_secret":
        return "literal_secret"
    if text in {"model_provider.missing_role", "model_provider.missing_role_metadata"}:
        return "missing_role"
    if text == "model_provider.invalid_provider_kind":
        return "invalid_provider_kind"
    if text == "model_provider.alias_review_required":
        return "alias_review_required"
    if text == "model_provider.advisory_boundary_missing":
        return "advisory_boundary_missing"
    if text == "model_provider.duplicate_provider_details":
        return "duplicate_provider_details"
    if text == "model_provider.env_reference_review":
        return "env_reference_review"
    if text == "model_provider.local_endpoint_exposure_review":
        return "local_endpoint_exposure_review"
    return "model_provider_review_required"


def append_model_telemetry_reason(reasons: set[str], code: str) -> None:
    if code in MODEL_TELEMETRY_REASON_ORDER:
        reasons.add(code)


def model_telemetry_reason_code(report_finding: dict[str, Any]) -> str:
    reason_code = str(report_finding.get("reason_code") or "").strip()
    if reason_code in MODEL_TELEMETRY_REASON_ORDER:
        return reason_code
    finding_id = str(report_finding.get("id") or "").strip()
    for suffix in MODEL_TELEMETRY_REASON_ORDER:
        if finding_id == f"model_telemetry.{suffix}" or finding_id.startswith(f"model_telemetry.{suffix}."):
            return suffix
    return "model_telemetry_review_required"


def append_failure_mode_posture_reason(reasons: set[str], code: str) -> None:
    if code in FAILURE_MODE_POSTURE_REASON_ORDER:
        reasons.add(code)


def failure_mode_posture_reason_code(report_finding: dict[str, Any]) -> str:
    reason_code = str(report_finding.get("reason_code") or "").strip()
    if reason_code in FAILURE_MODE_POSTURE_REASON_ORDER:
        return reason_code
    finding_id = str(report_finding.get("id") or "").strip()
    for suffix in FAILURE_MODE_POSTURE_REASON_ORDER:
        if finding_id == f"failure_mode_posture.{suffix}" or finding_id.startswith(f"failure_mode_posture.{suffix}."):
            return suffix
    return "failure_mode_posture_review_required"


def append_failure_mode_observations_reason(reasons: set[str], code: str) -> None:
    if code in FAILURE_MODE_OBSERVATIONS_REASON_ORDER:
        reasons.add(code)


def failure_mode_observations_reason_code(report_finding: dict[str, Any]) -> str:
    reason_code = str(report_finding.get("reason_code") or "").strip()
    if reason_code in FAILURE_MODE_OBSERVATIONS_REASON_ORDER:
        return reason_code
    finding_id = str(report_finding.get("id") or "").strip()
    for suffix in FAILURE_MODE_OBSERVATIONS_REASON_ORDER:
        if finding_id == f"failure_mode_observations.{suffix}" or finding_id.startswith(
            f"failure_mode_observations.{suffix}."
        ):
            return suffix
    return "failure_mode_observations_review_required"


def append_opencode_config_hygiene_reason(reasons: set[str], code: str) -> None:
    if code in OPENCODE_CONFIG_HYGIENE_REASON_ORDER:
        reasons.add(code)


def opencode_config_hygiene_reason_code(report_finding: dict[str, Any]) -> str:
    reason_code = str(report_finding.get("reason_code") or "").strip()
    if reason_code in OPENCODE_CONFIG_HYGIENE_REASON_ORDER:
        return reason_code
    finding_id = str(report_finding.get("id") or "").strip()
    for suffix in OPENCODE_CONFIG_HYGIENE_REASON_ORDER:
        if finding_id == f"opencode_config_hygiene.{suffix}" or finding_id.startswith(
            f"opencode_config_hygiene.{suffix}."
        ):
            return suffix
    if finding_id.startswith("opencode_config_hygiene.project_config_malformed"):
        return "opencode_project_config_malformed"
    if finding_id.startswith("opencode_config_hygiene.stale_yaml_config"):
        return "stale_opencode_yaml_config"
    if finding_id.startswith("opencode_config_hygiene.runtime_authority_attempt"):
        return "opencode_runtime_authority_attempt"
    return "opencode_config_review_required"


def append_design_traceability_reason(reasons: set[str], code: str) -> None:
    if code in DESIGN_TRACEABILITY_REASON_ORDER:
        reasons.add(code)


def design_traceability_reason_code(report_finding: dict[str, Any]) -> str:
    reason_code = str(report_finding.get("reason_code") or "").strip()
    if reason_code in DESIGN_TRACEABILITY_REASON_ORDER:
        return reason_code
    finding_id = str(report_finding.get("id") or "").strip()
    for suffix in DESIGN_TRACEABILITY_REASON_ORDER:
        if finding_id == f"design_traceability.{suffix}" or finding_id.startswith(f"design_traceability.{suffix}."):
            return suffix
    if finding_id.startswith("design_traceability.referenced_path_missing"):
        return "referenced_path_missing"
    return "design_traceability_review_required"


def append_ui_experience_quality_reason(reasons: set[str], code: str) -> None:
    if code in UI_EXPERIENCE_QUALITY_REASON_ORDER:
        reasons.add(code)


def ui_experience_quality_reason_code(report_finding: dict[str, Any]) -> str:
    reason_code = str(report_finding.get("reason_code") or "").strip()
    if reason_code in UI_EXPERIENCE_QUALITY_REASON_ORDER:
        return reason_code
    finding_id = str(report_finding.get("id") or "").strip()
    for suffix in UI_EXPERIENCE_QUALITY_REASON_ORDER:
        if finding_id == f"ui_experience_quality.{suffix}" or finding_id.startswith(f"ui_experience_quality.{suffix}."):
            return suffix
    return "ui_experience_quality_review_required"


def reason_codes_for_parallel_lane(
    *,
    lane_report: dict[str, Any],
    profile: str,
    pr_risk_report: dict[str, Any] | None,
    plan_coherence_report: dict[str, Any] | None,
    task_claim_report: dict[str, Any] | None,
    alignment_data: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    lane = lane_report.get("lane") if isinstance(lane_report.get("lane"), dict) else {}
    task_id = str(lane.get("task_id") or "") or None
    findings = [item for item in lane_report.get("findings") or [] if isinstance(item, dict)]
    statuses = {str(item.get("status") or "") for item in findings}
    reasons: set[str] = set()
    refs: dict[str, list[str]] = {
        "planned_risk_refs": [],
        "actual_risk_refs": [],
        "evidence_gap_refs": [],
    }

    if not task_id or not (as_list(lane.get("fr_nfr_refs")) or as_list(lane.get("requirement_refs"))):
        append_reason(reasons, "missing_planning_link")
        refs["evidence_gap_refs"].append("parallel_lane_handoff.lane.task_or_requirement_refs")

    claim_statuses = {str(claim.get("status") or "") for claim in matching_task_claims(task_claim_report, task_id)}
    dependency_state = str(lane.get("dependency_state") or "").strip().lower()
    if (
        statuses & {"claim_conflict", "dependency_conflict", "dependency_blocker_missing"}
        or as_list(lane.get("claim_conflicts"))
        or as_list(lane.get("dependency_blockers"))
        or dependency_state in {"blocked", "unresolved", "not_ready", "pending"}
        or claim_statuses & {"conflicting", "stale", "expired"}
    ):
        append_reason(reasons, "dependency_or_claim_conflict")
        refs["evidence_gap_refs"].append("parallel_lane_handoff.lane.dependency_or_claim_state")

    plan_summary = plan_coherence_report.get("summary") if isinstance(plan_coherence_report, dict) and isinstance(plan_coherence_report.get("summary"), dict) else {}
    if (
        "scope_drift" in statuses
        or as_list(lane.get("unplanned_changed_files"))
        or as_list(lane.get("out_of_scope_changed_files"))
        or int_count(plan_summary.get("unplanned_changed_files")) > 0
        or int_count(plan_summary.get("out_of_scope_changed_files")) > 0
    ):
        append_reason(reasons, "scope_mismatch")
        refs["evidence_gap_refs"].append("parallel_lane_handoff_or_plan_coherence.scope_paths")

    if "code_evidence_missing" in statuses:
        append_reason(reasons, "changed_file_evidence_gap")
        refs["evidence_gap_refs"].append("parallel_lane_handoff.findings.code_evidence_missing")

    if statuses & {"test_evidence_missing", "checks_failed", "checks_unavailable", "failed_check_evidence_missing"}:
        append_reason(reasons, "test_evidence_gap")
        refs["evidence_gap_refs"].append("parallel_lane_handoff.findings.test_or_check_evidence")

    if "evidence_conflict" in statuses:
        append_reason(reasons, "evidence_conflict")
        refs["evidence_gap_refs"].append("parallel_lane_handoff.findings.evidence_conflict")

    if "human_review_missing" in statuses or lane_report.get("human_review_required") is not True:
        append_reason(reasons, "human_review_disposition_missing")
        refs["evidence_gap_refs"].append("parallel_lane_handoff.human_review_required")

    pr_summary = pr_risk_report.get("summary") if isinstance(pr_risk_report, dict) and isinstance(pr_risk_report.get("summary"), dict) else {}
    actual_tier = risk_tier(pr_summary.get("risk_tier"))
    effective_profile = pr_summary.get("effective_profile")
    if actual_tier == "high" or profile_escalates(profile, effective_profile):
        append_reason(reasons, "actual_pr_risk_requires_review")
        refs["actual_risk_refs"].append("pr_risk_classification.summary.risk_tier")
    planned_tier, planned_ref = planned_risk_tier(
        lane_report=lane_report,
        task_claim_report=task_claim_report,
        alignment_data=alignment_data,
    )
    if planned_tier and planned_ref:
        refs["planned_risk_refs"].append(planned_ref)
    if actual_tier:
        refs["actual_risk_refs"].append("pr_risk_classification.summary.risk_tier")
    if planned_tier and actual_tier and abs(RISK_TIER_ORDER[planned_tier] - RISK_TIER_ORDER[actual_tier]) >= 2:
        append_reason(reasons, "planned_actual_risk_mismatch")

    ordered = [code for code in PARALLEL_LANE_REASON_ORDER if code in reasons]
    details = {
        "planned_risk_tier": planned_tier,
        "actual_risk_tier": actual_tier,
        "actual_effective_profile": effective_profile,
        "planned_risk_refs": dedupe(refs["planned_risk_refs"]),
        "actual_risk_refs": dedupe(refs["actual_risk_refs"]),
        "evidence_gap_refs": dedupe(refs["evidence_gap_refs"]),
    }
    return ordered, details


def evaluate_item(
    *,
    item: dict[str, Any],
    rules: dict[str, Any],
    severity: str,
    required_fields: list[str],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    item_id = str(item.get("id") or "unidentified_item")
    source_type = str(item.get("source_type") or "")
    source_ref = str(item.get("source_ref") or "")
    target_surfaces = dedupe(as_list(item.get("target_surfaces")))
    disposition = str(item.get("disposition") or "needs_review")
    expected_mapping = rules.get("expected_routing_targets") if isinstance(rules.get("expected_routing_targets"), dict) else {}
    expected_targets = [target for target in as_list(expected_mapping.get(source_type)) if target in allowed_target_surfaces]
    missing_expected_targets = [target for target in expected_targets if target not in target_surfaces]
    invalid_targets = [target for target in target_surfaces if target not in allowed_target_surfaces]
    missing_fields = [field for field in required_fields if item.get(field) in (None, "", [])]
    today = controlled_now_utc().date()
    due_date = parse_date(item.get("due_date") or item.get("review_date"))
    stale = bool(due_date and due_date < today and disposition not in ROUTED_DISPOSITIONS | {"waived"})
    findings: list[dict[str, Any]] = []

    if source_is_ignored(source_ref, rules):
        status = "advisory"
        findings.append(
            finding(
                item_id=item_id,
                severity="advisory",
                status="advisory",
                message="Item source is in an ignored/private pattern; it remains visible but is not scanned by default.",
                source_type=source_type,
                source_ref=source_ref,
                target_surfaces=target_surfaces,
                required_next_actions=["Confirm this private/internal reference should stay out of adopter-facing routing."],
            )
        )
    elif source_type not in allowed_source_types or invalid_targets or disposition not in allowed_dispositions or missing_fields:
        status = "unknown"
        issues: list[str] = []
        if source_type not in allowed_source_types:
            issues.append(f"unsupported source_type {source_type!r}")
        if invalid_targets:
            issues.append(f"unsupported target_surfaces: {', '.join(invalid_targets)}")
        if disposition not in allowed_dispositions:
            issues.append(f"unsupported disposition {disposition!r}")
        if missing_fields:
            issues.append(f"missing required fields: {', '.join(missing_fields)}")
        findings.append(
            finding(
                item_id=item_id,
                severity=severity,
                status="invalid_item",
                message=f"Control-plane review item is invalid: {'; '.join(issues)}.",
                source_type=source_type,
                source_ref=source_ref,
                target_surfaces=target_surfaces,
                required_next_actions=["Correct the structured item before relying on routing status."],
            )
        )
    elif missing_expected_targets or not target_surfaces:
        status = "missing_routing"
        findings.append(
            finding(
                item_id=item_id,
                severity=severity,
                status="missing_routing",
                message="Structured item is missing one or more expected routing targets.",
                source_type=source_type,
                source_ref=source_ref,
                target_surfaces=target_surfaces,
                required_next_actions=required_actions_for(item, "missing_routing", missing_expected_targets),
            )
        )
    elif disposition in REVIEW_DISPOSITIONS or stale:
        status = "review_required" if not stale else "blocked"
        findings.append(
            finding(
                item_id=item_id,
                severity=severity,
                status="stale_review" if stale else "review_required",
                message="Routing item needs human review before it can be treated as routed.",
                source_type=source_type,
                source_ref=source_ref,
                target_surfaces=target_surfaces,
                required_next_actions=required_actions_for(item, status, []),
            )
        )
    elif disposition in ROUTED_DISPOSITIONS:
        status = "routed"
    elif disposition == "waived" or item.get("waiver_ref"):
        status = "waived"
    else:
        status = "review_required"

    if disposition == "waived" or item.get("waiver_ref"):
        findings.append(
            finding(
                item_id=item_id,
                severity="advisory",
                status="waiver_visible",
                message="Waiver remains visible and does not convert routing to pass.",
                source_type=source_type,
                source_ref=source_ref,
                target_surfaces=target_surfaces,
                required_next_actions=required_actions_for(item, "waived", []),
            )
        )

    human_review_required = item_human_review_required(item, rules, status)
    if status == "routed" and human_review_required and item.get("review_date") is None:
        # Routed items may still require governance review, but the missing review
        # date is advisory rather than proof that routing is absent.
        findings.append(
            finding(
                item_id=item_id,
                severity="advisory",
                status="review_required",
                message="Item is routed, but configured human-review evidence remains expected.",
                source_type=source_type,
                source_ref=source_ref,
                target_surfaces=target_surfaces,
                required_next_actions=["Record review date or reviewer decision when project governance completes disposition."],
            )
        )

    decision = {
        "id": item_id,
        "source_type": source_type,
        "source_ref": source_ref,
        "summary": str(item.get("summary") or ""),
        "source_artifact_family": item.get("source_artifact_family"),
        "target_surfaces": target_surfaces,
        "expected_target_surfaces": expected_targets,
        "missing_expected_targets": missing_expected_targets,
        "related_capabilities": as_list(item.get("related_capabilities")),
        "related_gates": as_list(item.get("related_gates")),
        "related_evidence": as_list(item.get("related_evidence")),
        "disposition": disposition,
        "owner": item.get("owner"),
        "due_date": str(item.get("due_date")) if item.get("due_date") else None,
        "review_date": str(item.get("review_date")) if item.get("review_date") else None,
        "known_gap_ref": item.get("known_gap_ref"),
        "residual_risk_ref": item.get("residual_risk_ref"),
        "waiver_ref": item.get("waiver_ref"),
        "severity": severity,
        "status": status,
        "human_review_required": human_review_required,
        "notes": item.get("notes"),
        "rationale": item.get("rationale"),
        "required_next_actions": required_actions_for(item, status, missing_expected_targets),
    }
    for passthrough_key in (
        "hitl_required",
        "hitl_reason_codes",
        "aivss_reason_codes",
        "external_sarif_reason_codes",
        "external_result_id",
        "external_source_execution_status",
        "external_result_posture",
        "external_coverage_status",
        "model_provider_reason_codes",
        "model_telemetry_reason_codes",
        "failure_mode_posture_reason_codes",
        "failure_mode_observations_reason_codes",
        "opencode_config_hygiene_reason_codes",
        "design_traceability_reason_codes",
        "ui_experience_quality_reason_codes",
        "reason_code_counts",
        "planned_risk_refs",
        "actual_risk_refs",
        "evidence_gap_refs",
        "source_report_refs",
        "not_claimed",
    ):
        if passthrough_key in item:
            decision[passthrough_key] = item.get(passthrough_key)
    return decision, findings


def section_for(items: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = {status: sum(1 for item in items if item.get("status") == status) for status in sorted({str(item.get("status")) for item in items})}
    if not items:
        status = "not_configured"
    elif status_counts.get("blocked"):
        status = "blocked"
    elif status_counts.get("missing_routing"):
        status = "missing_routing"
    elif status_counts.get("review_required"):
        status = "review_required"
    elif status_counts.get("unknown"):
        status = "unknown"
    elif status_counts.get("waived"):
        status = "waived"
    elif status_counts.get("advisory"):
        status = "advisory"
    else:
        status = "routed"
    return {
        "status": status,
        "summary": {
            "items": len(items),
            "routed": status_counts.get("routed", 0),
            "missing_routing": status_counts.get("missing_routing", 0),
            "review_required": status_counts.get("review_required", 0),
            "blocked": status_counts.get("blocked", 0),
            "waived": status_counts.get("waived", 0),
            "unknown": status_counts.get("unknown", 0),
            "human_review_required": sum(1 for item in items if item.get("human_review_required")),
        },
        "items": items,
    }


def build_disabled_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    rules: dict[str, Any],
) -> dict[str, Any]:
    policy_meta = policy.get("_meta", {})
    return {
        "schema": "naos.control_plane_review.v1",
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": "disabled",
        "naos_root": naos_root,
        "project_root": str(root),
        "rules": {"path": str(rules_path), "source": rules_source, "semantics": rules.get("semantics") or {}},
        "items": {"path": None, "source": "not_loaded"},
        "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
        "summary": {"items": 0, "disabled": 1, "total_findings": 0},
        "governance_surface_review": section_for([]),
        "research_routing": section_for([]),
        "routing_decisions": [],
        "findings": [],
        "known_gaps": [],
        "residual_risks": [],
        "waivers": [],
        "human_review_required": False,
        "limitations": as_list(rules.get("limitations")),
    }


def build_parallel_lane_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    handoff_dir = root / naos_root / reports_dir / "parallel_lane_handoff"
    pr_risk, pr_error = load_json_report(report_path(root, naos_root, policy, "pr_risk_classification_report"))
    plan_coherence, plan_error = load_json_report(report_path(root, naos_root, policy, "plan_coherence_report"))
    task_claims, task_claims_error = load_json_report(report_path(root, naos_root, policy, "task_claim_report"))
    _, alignment_review_error = load_json_report(
        report_path(root, naos_root, policy, "pre_implementation_alignment_review_report")
    )
    alignment_data, alignment_ref = load_alignment_frontmatter(root, naos_root, policy)

    optional_report_refs: list[str] = []
    load_errors = {
        "pr_risk_classification": pr_error,
        "plan_coherence": plan_error,
        "task_claim_report": task_claims_error,
        "pre_implementation_alignment_review": alignment_review_error,
    }
    for key in (
        "pr_risk_classification_report",
        "plan_coherence_report",
        "task_claim_report",
        "pre_implementation_alignment_review_report",
    ):
        path = report_path(root, naos_root, policy, key)
        if path.exists():
            optional_report_refs.append(relative_ref(root, path))
    if alignment_ref:
        optional_report_refs.append(alignment_ref)

    source_reports: list[dict[str, Any]] = []
    generated_decisions: list[dict[str, Any]] = []
    generated_findings: list[dict[str, Any]] = []
    reason_code_counts = {code: 0 for code in PARALLEL_LANE_REASON_ORDER}
    routes: list[dict[str, Any]] = []

    if not handoff_dir.is_dir():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "handoff_reports_found": 0,
                "declared_lane_reports": 0,
                "routes_generated": 0,
                "hitl_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_reports": [],
            "optional_report_refs": optional_report_refs,
            "optional_report_load_errors": {key: value for key, value in load_errors.items() if value},
            "routes": [],
            "limitations": PARALLEL_LANE_LIMITATIONS,
            "not_claimed": PARALLEL_LANE_NOT_CLAIMED,
        }

    for path in sorted(handoff_dir.glob("*.json")):
        source_ref = relative_ref(root, path)
        data, error = load_json_report(path)
        lane = data.get("lane") if isinstance(data, dict) and isinstance(data.get("lane"), dict) else {}
        declared = bool(data and data.get("parallel_lanes_declared"))
        source_reports.append(
            {
                "path": source_ref,
                "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else "missing"),
                "schema": data.get("schema") if isinstance(data, dict) else None,
                "parallel_lanes_declared": declared,
                "lane_id": lane.get("lane_id"),
                "error": error,
            }
        )
        if not data or not declared:
            continue

        reason_codes, reason_details = reason_codes_for_parallel_lane(
            lane_report=data,
            profile=profile,
            pr_risk_report=pr_risk,
            plan_coherence_report=plan_coherence,
            task_claim_report=task_claims,
            alignment_data=alignment_data,
        )
        if not reason_codes:
            continue

        lane_id = str(lane.get("lane_id") or path.stem or "unscoped")
        related_gates = dedupe([gate for code in reason_codes for gate in PARALLEL_LANE_GATES.get(code, [])])
        related_evidence = dedupe([source_ref] + optional_report_refs)
        severity = route_severity_for_parallel_lane(root, naos_root, profile)
        route_item = {
            "id": f"CPR-PARALLEL-LANE-{lane_id}",
            "source_type": PARALLEL_LANE_SOURCE_TYPE,
            "source_ref": source_ref,
            "summary": f"Parallel-lane handoff for {lane_id} requires human review: {', '.join(reason_codes)}.",
            "source_artifact_family": "parallel_lane_handoff_reconciliation",
            "target_surfaces": list(PARALLEL_LANE_TARGETS),
            "related_gates": related_gates,
            "related_evidence": related_evidence,
            "disposition": "needs_review",
            "owner": "project-governance-reviewer",
            "human_review_required": True,
            "hitl_required": True,
            "hitl_reason_codes": reason_codes,
            "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in PARALLEL_LANE_REASON_ORDER},
            "planned_risk_refs": reason_details["planned_risk_refs"],
            "actual_risk_refs": reason_details["actual_risk_refs"],
            "evidence_gap_refs": reason_details["evidence_gap_refs"],
            "source_report_refs": related_evidence,
            "not_claimed": PARALLEL_LANE_NOT_CLAIMED,
            "notes": "Generated by control-plane review from local reports; not written to control_plane_review_items.yaml.",
        }
        decision, findings = evaluate_item(
            item=route_item,
            rules=rules,
            severity=severity,
            required_fields=required_fields,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
        )
        for generated_finding in findings:
            generated_finding.update(
                {
                    "hitl_required": True,
                    "hitl_reason_codes": reason_codes,
                    "related_gates": related_gates,
                    "related_evidence": related_evidence,
                    "not_claimed": PARALLEL_LANE_NOT_CLAIMED,
                }
            )
        generated_decisions.append(decision)
        generated_findings.extend(findings)
        for code in reason_codes:
            reason_code_counts[code] += 1
        routes.append(
            {
                "id": decision["id"],
                "lane_id": lane_id,
                "status": decision["status"],
                "severity": severity,
                "hitl_required": True,
                "hitl_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": related_evidence,
                **reason_details,
            }
        )

    declared_reports = sum(1 for item in source_reports if item.get("parallel_lanes_declared"))
    hitl_required = sum(1 for item in routes if item.get("hitl_required"))
    if generated_findings:
        status = status_from_counts(finding_counts(generated_findings))
    elif declared_reports:
        status = "routed"
    else:
        status = "not_applicable"
    return generated_decisions, generated_findings, {
        "status": status,
        "summary": {
            "handoff_reports_found": len(source_reports),
            "declared_lane_reports": declared_reports,
            "routes_generated": len(generated_decisions),
            "hitl_required": hitl_required,
            "reason_code_counts": reason_code_counts,
        },
        "source_reports": source_reports,
        "optional_report_refs": optional_report_refs,
        "optional_report_load_errors": {key: value for key, value in load_errors.items() if value},
        "routes": routes,
        "limitations": PARALLEL_LANE_LIMITATIONS,
        "not_claimed": PARALLEL_LANE_NOT_CLAIMED,
    }


def build_ai_component_inventory_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "ai_component_inventory_report")
    source_ref = relative_ref(root, report)
    if report.exists() and bounded_ai_component_inventory_path is not None:
        try:
            bounded_ai_component_inventory_path(report, root)
            data, error = load_json_report(report)
        except Exception as exc:
            data, error = None, f"unsafe inventory report path: {exc}"
    elif report.exists():
        data, error = None, "AI component inventory path validator is unavailable"
    else:
        data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in AI_COMPONENT_INVENTORY_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    required_for_profile = profile in {"standard", "assured"}
    source_kit_missing_not_applicable = False
    consumer_error: str | None = None
    if build_expected_ai_component_inventory is not None:
        try:
            expected = build_expected_ai_component_inventory(
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
            )
            required_for_profile = bool(expected.get("required_for_profile"))
            source_kit_missing_not_applicable = bool(
                is_kit_repository(root, naos_root)
                and (expected.get("applicability") or {}).get("source_kit_missing_report")
                == "not_applicable"
            )
        except Exception as exc:  # Converted to bounded evidence below.
            consumer_error = str(exc)
    else:
        consumer_error = "ai component inventory consumer is unavailable"
    source_report["required_for_profile"] = required_for_profile
    if consumer_error:
        source_report["consumer_error"] = consumer_error

    if not report.exists() and (source_kit_missing_not_applicable or not required_for_profile):
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "required_for_profile": required_for_profile,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": AI_COMPONENT_INVENTORY_LIMITATIONS,
            "not_claimed": AI_COMPONENT_INVENTORY_NOT_CLAIMED,
        }

    reasons: set[str] = set()
    if not report.exists():
        reasons.add("inventory_report_missing")
    elif error:
        reasons.add("inventory_report_parse_error")
    elif not isinstance(data, dict):
        reasons.add("inventory_schema_invalid")
    elif validate_ai_component_inventory_report is None:
        reasons.add("inventory_consumer_unavailable")
    else:
        try:
            reasons.update(
                validate_ai_component_inventory_report(
                    root=root,
                    profile=profile,
                    naos_root=naos_root,
                    policy=policy,
                    report=data,
                )
            )
        except Exception as exc:  # Preserve deterministic failure as review evidence.
            source_report["consumer_error"] = str(exc)
            reasons.add("inventory_consumer_unavailable")
    if consumer_error:
        reasons.add("inventory_consumer_unavailable")
    reason_codes = [code for code in AI_COMPONENT_INVENTORY_REASON_ORDER if code in reasons]
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "required_for_profile": required_for_profile,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": AI_COMPONENT_INVENTORY_LIMITATIONS,
            "not_claimed": AI_COMPONENT_INVENTORY_NOT_CLAIMED,
        }

    related_gates = dedupe(
        [gate for code in reason_codes for gate in AI_COMPONENT_INVENTORY_GATES.get(code, [])]
    )
    severity = route_severity_for_parallel_lane(root, naos_root, profile)
    route_item = {
        "id": "CPR-AI-COMPONENT-INVENTORY",
        "source_type": AI_COMPONENT_INVENTORY_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"AI component inventory requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "ai_component_inventory_reconciliation",
        "target_surfaces": list(AI_COMPONENT_INVENTORY_TARGETS),
        "related_capabilities": ["CAP-AI-COMPONENT-INVENTORY"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "ai_component_inventory_reason_codes": reason_codes,
        "reason_code_counts": {
            code: 1 if code in reason_codes else 0 for code in AI_COMPONENT_INVENTORY_REASON_ORDER
        },
        "source_report_refs": [source_ref],
        "not_claimed": AI_COMPONENT_INVENTORY_NOT_CLAIMED,
        "notes": "Generated from local declared-facts inventory evidence; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "ai_component_inventory_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": AI_COMPONENT_INVENTORY_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "ai_component_inventory_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": source_report.get("status"),
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": report.exists(),
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "required_for_profile": required_for_profile,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": AI_COMPONENT_INVENTORY_LIMITATIONS,
        "not_claimed": AI_COMPONENT_INVENTORY_NOT_CLAIMED,
    }


def build_agent_sponsor_registry_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "agent_sponsor_registry_report")
    source_ref = bounded_lexical_ref(
        root,
        report,
        unsafe_label="<unsafe-agent-sponsor-registry-report-path>",
    )
    registry_filename = str(
        policy.get("paths", {}).get("agent_sponsor_registry")
        or "agent_sponsor_registry.yaml"
    )
    registry_path = root / naos_root / registry_filename
    if resolve_agent_sponsor_registry_path is not None:
        try:
            registry_path, _registry_source = resolve_agent_sponsor_registry_path(
                root, naos_root, policy
            )
        except Exception:
            registry_path = root / naos_root / registry_filename
    registry_state = optional_artifact_state(registry_path, root)
    report_state = optional_artifact_state(report, root)
    configured = registry_state == "regular"
    report_present = report_state == "regular"
    reason_code_counts = {
        code: 0 for code in AGENT_SPONSOR_REGISTRY_REASON_ORDER
    }

    if registry_state == "missing" and report_state == "missing":
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "configured": False,
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
                "registry_artifact_state": registry_state,
                "report_artifact_state": report_state,
            },
            "source_report": {
                "path": source_ref,
                "present": False,
                "status": None,
                "schema": None,
                "error": None,
            },
            "source_report_refs": [],
            "routes": [],
            "limitations": AGENT_SPONSOR_REGISTRY_LIMITATIONS,
            "not_claimed": AGENT_SPONSOR_REGISTRY_NOT_CLAIMED,
        }

    consumer_error: str | None = None
    if (
        registry_state != "unsafe"
        and build_expected_agent_sponsor_registry is not None
    ):
        try:
            build_expected_agent_sponsor_registry(
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
            )
        except Exception as exc:
            consumer_error = str(exc)
    elif registry_state != "unsafe":
        consumer_error = "agent sponsor registry consumer is unavailable"

    if report_state == "unsafe":
        data, error = None, "unsafe sponsor-registry report path"
    elif report_present and bounded_agent_sponsor_registry_path is not None:
        try:
            bounded_agent_sponsor_registry_path(report, root)
            data, error = load_json_report(report)
        except Exception:
            data, error = None, "unsafe sponsor-registry report path"
    elif report_present:
        data, error = None, "sponsor-registry path validator is unavailable"
    else:
        data, error = load_json_report(report)
    source_report = {
        "path": source_ref,
        "present": report_present,
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
        "configured": configured,
        "registry_artifact_state": registry_state,
        "report_artifact_state": report_state,
    }
    if consumer_error:
        source_report["consumer_error"] = consumer_error

    reasons: set[str] = set()
    if registry_state == "unsafe":
        reasons.add("registry_config_unsafe_path")
    elif not configured:
        reasons.add("registry_config_missing")
    if report_state == "unsafe":
        reasons.add("registry_report_unsafe_path")
    elif not report_present:
        reasons.add("registry_report_missing")
    elif error:
        reasons.add("registry_report_parse_error")
    elif not isinstance(data, dict):
        reasons.add("registry_report_schema_invalid")
    elif validate_agent_sponsor_registry_report is None:
        reasons.add("registry_consumer_unavailable")
    else:
        try:
            reasons.update(
                validate_agent_sponsor_registry_report(
                    root=root,
                    profile=profile,
                    naos_root=naos_root,
                    policy=policy,
                    report=data,
                )
            )
        except Exception:
            reasons.add("registry_consumer_unavailable")
    if consumer_error:
        reasons.add("registry_consumer_unavailable")
    reason_codes = [
        code for code in AGENT_SPONSOR_REGISTRY_REASON_ORDER if code in reasons
    ]
    report_findings = (
        [item for item in data.get("findings") or [] if isinstance(item, dict)]
        if isinstance(data, dict)
        else []
    )

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "configured": configured,
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
                "registry_artifact_state": registry_state,
                "report_artifact_state": report_state,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": AGENT_SPONSOR_REGISTRY_LIMITATIONS,
            "not_claimed": AGENT_SPONSOR_REGISTRY_NOT_CLAIMED,
        }

    related_gates = dedupe(
        [
            gate
            for code in reason_codes
            for gate in AGENT_SPONSOR_REGISTRY_GATES.get(code, [])
        ]
    )
    severity = route_severity_for_parallel_lane(root, naos_root, profile)
    route_item = {
        "id": "CPR-AGENT-SPONSOR-REGISTRY",
        "source_type": AGENT_SPONSOR_REGISTRY_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": (
            "Agent sponsor registry requires human review: "
            + ", ".join(reason_codes)
            + "."
        ),
        "source_artifact_family": "agent_sponsor_registry_reconciliation",
        "target_surfaces": list(AGENT_SPONSOR_REGISTRY_TARGETS),
        "related_capabilities": [
            "CAP-AGENT-SPONSOR-REGISTRY",
            "CAP-AI-COMPONENT-INVENTORY",
        ],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "agent_sponsor_registry_reason_codes": reason_codes,
        "reason_code_counts": {
            code: 1 if code in reason_codes else 0
            for code in AGENT_SPONSOR_REGISTRY_REASON_ORDER
        },
        "source_report_refs": [source_ref],
        "not_claimed": AGENT_SPONSOR_REGISTRY_NOT_CLAIMED,
        "notes": "Generated from optional local declared-posture evidence; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "agent_sponsor_registry_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": AGENT_SPONSOR_REGISTRY_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "agent_sponsor_registry_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": source_report.get("status"),
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "configured": configured,
            "report_present": report_present,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
            "registry_artifact_state": registry_state,
            "report_artifact_state": report_state,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": AGENT_SPONSOR_REGISTRY_LIMITATIONS,
        "not_claimed": AGENT_SPONSOR_REGISTRY_NOT_CLAIMED,
    }


def build_aivss_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    input_filename = str(
        policy.get("paths", {}).get("aivss_assessments")
        or "aivss_assessments.yaml"
    )
    input_path = root / naos_root / input_filename
    if resolve_aivss_assessments_path is not None:
        try:
            input_path, _input_source = resolve_aivss_assessments_path(
                root, naos_root, policy
            )
        except Exception:
            input_path = root / naos_root / input_filename
    report = report_path(
        root,
        naos_root,
        policy,
        "aivss_arithmetic_verification_report",
    )
    input_state = optional_artifact_state(input_path, root)
    report_state = optional_artifact_state(report, root)
    configured = input_state == "regular"
    report_present = report_state == "regular"
    source_ref = bounded_lexical_ref(
        root,
        report,
        unsafe_label="<unsafe-aivss-verification-report-path>",
    )
    reason_code_counts = {code: 0 for code in AIVSS_REASON_ORDER}

    def findings_seen(data: Any) -> int:
        if not isinstance(data, dict):
            return 0
        entries = data.get("findings")
        return len(entries) if isinstance(entries, list) else 0

    if input_state == "missing" and report_state == "missing":
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "configured": False,
                "report_present": False,
                "findings_seen": 0,
                "assessments_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "input_artifact_state": input_state,
                "report_artifact_state": report_state,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": {
                "path": source_ref,
                "present": False,
                "status": None,
                "schema": None,
                "error": None,
            },
            "source_report_refs": [],
            "routes": [],
            "limitations": AIVSS_LIMITATIONS,
            "not_claimed": AIVSS_NOT_CLAIMED,
        }

    consumer_error: str | None = None
    if input_state != "unsafe" and build_expected_aivss_verification is not None:
        try:
            build_expected_aivss_verification(
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
            )
        except Exception as exc:
            consumer_error = str(exc)
    elif input_state != "unsafe":
        consumer_error = "AIVSS arithmetic-verification consumer is unavailable"

    if report_state == "unsafe":
        data, error = None, "unsafe AIVSS verification report path"
    elif report_present and bounded_aivss_path is not None:
        try:
            bounded_aivss_path(report, root)
            data, error = load_json_report(report)
        except Exception:
            data, error = None, "unsafe AIVSS verification report path"
    elif report_present:
        data, error = None, "AIVSS report path validator is unavailable"
    else:
        data, error = load_json_report(report)
    source_report = {
        "path": source_ref,
        "present": report_present,
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
        "configured": configured,
        "input_artifact_state": input_state,
        "report_artifact_state": report_state,
    }
    if consumer_error:
        source_report["consumer_error"] = consumer_error

    reasons: set[str] = set()
    if input_state == "unsafe":
        reasons.add("aivss_input_unsafe_path")
    elif not configured:
        reasons.add("aivss_input_missing")
    if report_state == "unsafe":
        reasons.add("aivss_report_unsafe_path")
    elif not report_present:
        reasons.add("aivss_report_missing")
    elif error:
        reasons.add("aivss_report_parse_error")
    elif not isinstance(data, dict):
        reasons.add("aivss_report_schema_invalid")
    elif validate_aivss_verification_report is None:
        reasons.add("aivss_consumer_unavailable")
    else:
        try:
            reasons.update(
                validate_aivss_verification_report(
                    root=root,
                    profile=profile,
                    naos_root=naos_root,
                    policy=policy,
                    report=data,
                )
            )
            if aivss_report_review_reason_codes is not None:
                reasons.update(aivss_report_review_reason_codes(data))
        except Exception:
            reasons.add("aivss_consumer_unavailable")
    if consumer_error:
        reasons.add("aivss_consumer_unavailable")
    reason_codes = [code for code in AIVSS_REASON_ORDER if code in reasons]
    report_assessments = (
        [item for item in data.get("assessments") or [] if isinstance(item, dict)]
        if isinstance(data, dict)
        else []
    )

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "configured": configured,
                "report_present": report_present,
                "findings_seen": findings_seen(data),
                "assessments_seen": len(report_assessments),
                "routes_generated": 0,
                "human_review_required": 0,
                "input_artifact_state": input_state,
                "report_artifact_state": report_state,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": AIVSS_LIMITATIONS,
            "not_claimed": AIVSS_NOT_CLAIMED,
        }

    related_gates = dedupe(
        [gate for code in reason_codes for gate in AIVSS_GATES.get(code, [])]
    )
    route_item = {
        "id": "CPR-AIVSS-ARITHMETIC-VERIFICATION",
        "source_type": AIVSS_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": (
            "AIVSS arithmetic verification requires G2/G6 human security review: "
            + ", ".join(reason_codes)
            + "."
        ),
        "source_artifact_family": "aivss_arithmetic_verification_reconciliation",
        "target_surfaces": list(AIVSS_TARGETS),
        "related_capabilities": ["CAP-AIVSS-ARITHMETIC-VERIFICATION"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-security-reviewer",
        "human_review_required": True,
        "aivss_reason_codes": reason_codes,
        "reason_code_counts": {
            code: 1 if code in reason_codes else 0 for code in AIVSS_REASON_ORDER
        },
        "source_report_refs": [source_ref],
        "not_claimed": AIVSS_NOT_CLAIMED,
        "notes": "Generated from optional local arithmetic-verification evidence; fixed advisory routing only and not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity="advisory",
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "aivss_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": AIVSS_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": "advisory",
        "human_review_required": True,
        "aivss_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": source_report.get("status"),
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": "review_required",
        "summary": {
            "configured": configured,
            "report_present": report_present,
            "findings_seen": findings_seen(data),
            "assessments_seen": len(report_assessments),
            "routes_generated": 1,
            "human_review_required": 1,
            "input_artifact_state": input_state,
            "report_artifact_state": report_state,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": AIVSS_LIMITATIONS,
        "not_claimed": AIVSS_NOT_CLAIMED,
    }


def is_sha256_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def external_result_id_for(source_sha256: str, run_index: int, result_index: int) -> str:
    payload = json.dumps(
        {
            "source_sha256": source_sha256,
            "run_index": run_index,
            "result_index": result_index,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sarif-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_external_sarif_report(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    schema_errors: list[str] = []
    content_errors: list[str] = []
    if data.get("schema") != "naos.external_evidence_ingest.v2":
        schema_errors.append("schema must be naos.external_evidence_ingest.v2")
    summary = data.get("summary")
    assessment = data.get("assessment")
    records = data.get("result_records")
    if not isinstance(summary, dict):
        schema_errors.append("summary must be an object")
    if not isinstance(assessment, dict):
        schema_errors.append("assessment must be an object")
    if not isinstance(records, list):
        schema_errors.append("result_records must be an array")
    if schema_errors:
        return schema_errors, content_errors

    expected_assessment_fields = {
        "source_execution_status",
        "result_posture",
        "coverage_status",
        "human_review_required",
    }
    if set(assessment) != expected_assessment_fields:
        schema_errors.append("assessment fields do not match the v2 contract")
    if assessment.get("source_execution_status") not in {
        "not_configured",
        "source_missing",
        "parse_error",
        "not_assessed",
        "unknown",
        "reported_success",
        "reported_failure",
    }:
        schema_errors.append("assessment source_execution_status is invalid")
    if assessment.get("result_posture") not in {
        "not_assessed",
        "unknown",
        "zero_results_reported",
        "results_reported",
    }:
        schema_errors.append("assessment result_posture is invalid")
    if assessment.get("coverage_status") != "not_declared":
        schema_errors.append("assessment coverage_status is invalid")
    if not isinstance(assessment.get("human_review_required"), bool):
        schema_errors.append("assessment human_review_required must be boolean")
    source_configured = summary.get("source_configured")
    if not isinstance(source_configured, bool):
        schema_errors.append("summary source_configured must be boolean")
    elif source_configured is False:
        if records:
            content_errors.append("unconfigured source must not contain result records")
        if assessment.get("source_execution_status") != "not_configured":
            content_errors.append("unconfigured source has an inconsistent execution status")
        if assessment.get("result_posture") != "not_assessed":
            content_errors.append("unconfigured source has an inconsistent result posture")
        if assessment.get("human_review_required") is not False:
            content_errors.append("unconfigured source must not require assessment review")
    elif assessment.get("source_execution_status") == "not_configured":
        content_errors.append("configured source cannot use not_configured execution status")

    seen_ids: set[str] = set()
    seen_positions: set[tuple[int, int]] = set()
    summary_source_sha256 = summary.get("source_sha256")
    for record_index, record in enumerate(records):
        prefix = f"result_records[{record_index}]"
        if not isinstance(record, dict):
            schema_errors.append(f"{prefix} must be an object")
            continue
        if set(record) != EXTERNAL_SARIF_RESULT_REQUIRED_FIELDS:
            schema_errors.append(f"{prefix} fields do not match the v2 contract")
            continue
        run_index = record.get("run_index")
        result_index = record.get("result_index")
        source_sha256 = record.get("source_sha256")
        external_result_id = record.get("external_result_id")
        if type(run_index) is not int or run_index < 0 or type(result_index) is not int or result_index < 0:
            schema_errors.append(f"{prefix} indexes must be non-negative integers")
            continue
        if not is_sha256_hex(source_sha256):
            schema_errors.append(f"{prefix} source_sha256 is invalid")
            continue
        if not isinstance(external_result_id, str) or not external_result_id.startswith("sarif-") or not is_sha256_hex(external_result_id[6:]):
            schema_errors.append(f"{prefix} external_result_id is invalid")
            continue
        if record.get("origin") != "external_unverified":
            schema_errors.append(f"{prefix} origin is invalid")
        identity_basis = record.get("identity_basis")
        identity_stability = record.get("identity_stability")
        if identity_basis not in {"guid", "partial_fingerprints", "position"}:
            schema_errors.append(f"{prefix} identity_basis is invalid")
        if identity_stability not in {"source_declared", "exact_artifact_position"}:
            schema_errors.append(f"{prefix} identity_stability is invalid")
        source_identity_sha256 = record.get("source_identity_sha256")
        if source_identity_sha256 is not None and not is_sha256_hex(source_identity_sha256):
            schema_errors.append(f"{prefix} source_identity_sha256 is invalid")
        if not all(isinstance(record.get(field), str) and record.get(field) for field in ("tool_name", "tool_version", "native_rule_id", "native_level")):
            schema_errors.append(f"{prefix} tool, rule, and native level fields must be non-empty strings")
        if record.get("native_level_status") not in {"recognized_native", "unmapped"}:
            schema_errors.append(f"{prefix} native_level_status is invalid")
        if record.get("artifact_uri") is not None and not isinstance(record.get("artifact_uri"), str):
            schema_errors.append(f"{prefix} artifact_uri is invalid")
        taxonomy_refs = record.get("source_declared_taxonomy_refs")
        if (
            not isinstance(taxonomy_refs, list)
            or any(
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
                for value in taxonomy_refs
            )
            or len(taxonomy_refs) != len(set(taxonomy_refs))
        ):
            schema_errors.append(f"{prefix} source_declared_taxonomy_refs is invalid")
            taxonomy_refs = []
        if record.get("control_link_status") not in {"missing", "source_declared_unverified"}:
            schema_errors.append(f"{prefix} control_link_status is invalid")
        if (
            record.get("classification") != "unknown"
            or record.get("verification_status") != "unverified"
            or record.get("review_disposition") != "needs_review"
            or record.get("human_review_required") is not True
            or record.get("message_retention") != "omitted"
        ):
            schema_errors.append(f"{prefix} review boundary fields are invalid")

        expected_id = external_result_id_for(source_sha256, run_index, result_index)
        if external_result_id != expected_id:
            content_errors.append(f"{prefix} external_result_id does not match source digest and ordinals")
        if external_result_id in seen_ids or (run_index, result_index) in seen_positions:
            content_errors.append(f"{prefix} duplicates an imported result identity")
        seen_ids.add(external_result_id)
        seen_positions.add((run_index, result_index))
        if source_sha256 != summary_source_sha256:
            content_errors.append(f"{prefix} source digest differs from the report summary")
        if identity_basis == "position":
            if identity_stability != "exact_artifact_position" or source_identity_sha256 is not None:
                content_errors.append(
                    f"{prefix} positional identity must use exact-artifact-position stability without a source identity digest"
                )
        elif identity_basis in {"guid", "partial_fingerprints"}:
            if identity_stability != "source_declared" or source_identity_sha256 is None:
                content_errors.append(
                    f"{prefix} source-declared identity must use source-declared stability with a source identity digest"
                )
        expected_control_link = "source_declared_unverified" if taxonomy_refs else "missing"
        if record.get("control_link_status") != expected_control_link:
            content_errors.append(f"{prefix} control-link posture disagrees with source taxonomy references")
        expected_native_status = "recognized_native" if record.get("native_level") in {"none", "note", "warning", "error"} else "unmapped"
        if record.get("native_level_status") != expected_native_status:
            content_errors.append(f"{prefix} native-level posture is inconsistent")

    if type(summary.get("results")) is not int or summary.get("results") < 0:
        schema_errors.append("summary results must be a non-negative integer")
    elif summary.get("results") != len(records):
        content_errors.append("summary result count differs from result_records")
    if records and assessment.get("result_posture") != "results_reported":
        content_errors.append("assessment result_posture does not reflect imported results")
    if not records and assessment.get("result_posture") == "results_reported":
        content_errors.append("assessment reports results without result_records")
    if assessment.get("result_posture") == "zero_results_reported" and assessment.get("source_execution_status") != "reported_success":
        content_errors.append("zero-results posture lacks a successful source execution declaration")
    return schema_errors, content_errors


def external_assessment_reason_codes(assessment: dict[str, Any]) -> set[str]:
    reasons: set[str] = set()
    execution_status = assessment.get("source_execution_status")
    result_posture = assessment.get("result_posture")
    if execution_status == "not_assessed" or result_posture == "not_assessed":
        reasons.add("external_assessment_not_assessed")
    elif execution_status == "reported_failure":
        reasons.add("external_assessment_failed")
    elif execution_status != "reported_success" or result_posture == "unknown":
        reasons.add("external_assessment_unknown")
    if result_posture == "zero_results_reported":
        reasons.add("external_zero_results_scope_review")
    if assessment.get("coverage_status") == "not_declared":
        reasons.add("external_coverage_not_declared")
    return reasons


def build_external_sarif_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "external_evidence_ingest_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in EXTERNAL_SARIF_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    empty_summary = {
        "report_present": report.exists(),
        "findings_seen": 0,
        "results_seen": 0,
        "routes_generated": 0,
        "human_review_required": 0,
        "reason_code_counts": reason_code_counts,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": empty_summary,
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": EXTERNAL_SARIF_LIMITATIONS,
            "not_claimed": EXTERNAL_SARIF_NOT_CLAIMED,
        }

    summary = data.get("summary") if isinstance(data, dict) and isinstance(data.get("summary"), dict) else {}
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []
    records = data.get("result_records") if isinstance(data, dict) and isinstance(data.get("result_records"), list) else []
    assessment = data.get("assessment") if isinstance(data, dict) and isinstance(data.get("assessment"), dict) else {}
    schema_errors: list[str] = []
    content_errors: list[str] = []
    if error or not isinstance(data, dict):
        schema_errors.append(error or "report root must be an object")
    else:
        schema_errors, content_errors = validate_external_sarif_report(data)
    source_report.update(
        {
            "source_configured": summary.get("source_configured"),
            "validation_errors": schema_errors + content_errors,
            "assessment": assessment,
        }
    )
    if (
        not schema_errors
        and not content_errors
        and summary.get("source_configured") is False
    ):
        return [], [], {
            "status": "not_applicable",
            "summary": empty_summary,
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": EXTERNAL_SARIF_LIMITATIONS,
            "not_claimed": EXTERNAL_SARIF_NOT_CLAIMED,
        }

    decisions: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []

    def add_route(route_id: str, reason_codes: list[str], external_result_id: str | None = None) -> None:
        related_gates = dedupe(
            [gate for code in reason_codes for gate in EXTERNAL_SARIF_GATES.get(code, [])]
        )
        scope = f"external result {external_result_id}" if external_result_id else "external SARIF assessment"
        route_item = {
            "id": route_id,
            "source_type": EXTERNAL_SARIF_SOURCE_TYPE,
            "source_ref": source_ref,
            "summary": f"{scope} requires human review: {', '.join(reason_codes)}.",
            "source_artifact_family": "external_sarif_result_reconciliation",
            "target_surfaces": list(EXTERNAL_SARIF_TARGETS),
            "related_capabilities": ["CAP-EXTERNAL-EVIDENCE-INGEST"],
            "related_gates": related_gates,
            "related_evidence": [source_ref],
            "disposition": "needs_review",
            "owner": "project-governance-reviewer",
            "human_review_required": True,
            "external_sarif_reason_codes": reason_codes,
            "external_result_id": external_result_id,
            "external_source_execution_status": assessment.get("source_execution_status"),
            "external_result_posture": assessment.get("result_posture"),
            "external_coverage_status": assessment.get("coverage_status"),
            "reason_code_counts": {
                code: 1 if code in reason_codes else 0 for code in EXTERNAL_SARIF_REASON_ORDER
            },
            "source_report_refs": [source_ref],
            "not_claimed": EXTERNAL_SARIF_NOT_CLAIMED,
            "notes": "Generated from the local external-evidence ingest report; not written to control_plane_review_items.yaml and not a durable disposition.",
        }
        decision, route_findings = evaluate_item(
            item=route_item,
            rules=rules,
            severity="advisory",
            required_fields=required_fields,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
        )
        for generated_finding in route_findings:
            generated_finding.update(
                {
                    "external_sarif_reason_codes": reason_codes,
                    "external_result_id": external_result_id,
                    "related_gates": related_gates,
                    "related_evidence": [source_ref],
                    "not_claimed": EXTERNAL_SARIF_NOT_CLAIMED,
                }
            )
        decisions.append(decision)
        findings.extend(route_findings)
        for code in reason_codes:
            reason_code_counts[code] += 1
        routes.append(
            {
                "id": decision["id"],
                "status": decision["status"],
                "severity": "advisory",
                "human_review_required": True,
                "external_sarif_reason_codes": reason_codes,
                "external_result_id": external_result_id,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "source_report_refs": [source_ref],
            }
        )

    if schema_errors or content_errors:
        reasons = []
        if schema_errors:
            reasons.append("external_report_schema_invalid")
        if content_errors:
            reasons.append("external_report_content_mismatch")
        add_route("CPR-EXTERNAL-SARIF-REPORT", reasons)
    elif records:
        assessment_reasons = external_assessment_reason_codes(assessment)
        for record in records:
            reasons = {"external_result_review_required", *assessment_reasons}
            if record.get("identity_stability") == "exact_artifact_position":
                reasons.add("external_result_identity_positional")
            if record.get("native_level_status") == "unmapped":
                reasons.add("external_result_vocabulary_unmapped")
            if record.get("control_link_status") == "missing":
                reasons.add("external_result_control_link_missing")
            elif record.get("control_link_status") == "source_declared_unverified":
                reasons.add("external_result_control_link_unverified")
            ordered_reasons = [code for code in EXTERNAL_SARIF_REASON_ORDER if code in reasons]
            external_result_id = str(record["external_result_id"])
            add_route(
                "CPR-EXTERNAL-SARIF-" + external_result_id.removeprefix("sarif-").upper(),
                ordered_reasons,
                external_result_id,
            )
    else:
        reasons = external_assessment_reason_codes(assessment)
        ordered_reasons = [code for code in EXTERNAL_SARIF_REASON_ORDER if code in reasons]
        if ordered_reasons:
            add_route("CPR-EXTERNAL-SARIF-ASSESSMENT", ordered_reasons)

    return decisions, findings, {
        "status": "review_required" if decisions else "pass",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "results_seen": len(records),
            "routes_generated": len(decisions),
            "human_review_required": len(decisions),
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": routes,
        "limitations": EXTERNAL_SARIF_LIMITATIONS,
        "not_claimed": EXTERNAL_SARIF_NOT_CLAIMED,
    }


def build_model_provider_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "model_provider_policy_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in MODEL_PROVIDER_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": MODEL_PROVIDER_LIMITATIONS,
            "not_claimed": MODEL_PROVIDER_NOT_CLAIMED,
        }

    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_model_provider_reason(reasons, model_provider_reason_code(report_finding.get("id")))
    if error or report_status in {"review_required", "blocked", "warning", "advisory", "not_configured"}:
        append_model_provider_reason(reasons, "model_provider_review_required")
    reason_codes = [code for code in MODEL_PROVIDER_REASON_ORDER if code in reasons]

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": MODEL_PROVIDER_LIMITATIONS,
            "not_claimed": MODEL_PROVIDER_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in MODEL_PROVIDER_GATES.get(code, [])])
    severity = route_severity_for_model_provider(
        root=root,
        naos_root=naos_root,
        profile=profile,
        report_status=report_status,
        report_findings=report_findings,
    )
    route_item = {
        "id": "CPR-MODEL-PROVIDER-POLICY",
        "source_type": MODEL_PROVIDER_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"Model-provider policy report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "model_provider_policy_reconciliation",
        "target_surfaces": list(MODEL_PROVIDER_TARGETS),
        "related_capabilities": ["CAP-MODEL-PROVIDER-POLICY"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "model_provider_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in MODEL_PROVIDER_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": MODEL_PROVIDER_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local model-provider policy report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "model_provider_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": MODEL_PROVIDER_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "model_provider_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": MODEL_PROVIDER_LIMITATIONS,
        "not_claimed": MODEL_PROVIDER_NOT_CLAIMED,
    }


def build_model_telemetry_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "model_telemetry_evidence_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in MODEL_TELEMETRY_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": MODEL_TELEMETRY_LIMITATIONS,
            "not_claimed": MODEL_TELEMETRY_NOT_CLAIMED,
        }

    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_model_telemetry_reason(reasons, model_telemetry_reason_code(report_finding))
    if error:
        append_model_telemetry_reason(reasons, "telemetry_source_unreadable")
    elif report_findings and report_status in {"advisory", "warning", "required_missing", "blocked", "unknown"}:
        append_model_telemetry_reason(reasons, "model_telemetry_review_required")
    reason_codes = [code for code in MODEL_TELEMETRY_REASON_ORDER if code in reasons]

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": MODEL_TELEMETRY_LIMITATIONS,
            "not_claimed": MODEL_TELEMETRY_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in MODEL_TELEMETRY_GATES.get(code, [])])
    severity = route_severity_for_model_telemetry(root, naos_root, profile)
    route_item = {
        "id": "CPR-MODEL-TELEMETRY-EVIDENCE",
        "source_type": MODEL_TELEMETRY_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"Model telemetry evidence report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "model_telemetry_evidence_reconciliation",
        "target_surfaces": list(MODEL_TELEMETRY_TARGETS),
        "related_capabilities": ["CAP-MODEL-TELEMETRY-EVIDENCE", "CAP-MODEL-PROVIDER-POLICY"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "model_telemetry_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in MODEL_TELEMETRY_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": MODEL_TELEMETRY_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local model telemetry evidence report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "model_telemetry_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": MODEL_TELEMETRY_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "model_telemetry_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": MODEL_TELEMETRY_LIMITATIONS,
        "not_claimed": MODEL_TELEMETRY_NOT_CLAIMED,
    }


def build_failure_mode_posture_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "failure_mode_posture_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in FAILURE_MODE_POSTURE_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
                "mode_finding_counts": {},
                "family_finding_counts": {},
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": FAILURE_MODE_POSTURE_LIMITATIONS,
            "not_claimed": FAILURE_MODE_POSTURE_NOT_CLAIMED,
        }

    report_data = data if isinstance(data, dict) else {}
    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in report_data.get("findings") or [] if isinstance(item, dict)]
    summary = report_data.get("summary") if isinstance(report_data.get("summary"), dict) else {}
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_failure_mode_posture_reason(reasons, failure_mode_posture_reason_code(report_finding))
    if error:
        append_failure_mode_posture_reason(reasons, "failure_mode_posture_review_required")
    elif report_findings and report_status in {"advisory", "warning", "required_missing", "blocked", "unknown"}:
        append_failure_mode_posture_reason(reasons, "failure_mode_posture_review_required")
    reason_codes = [code for code in FAILURE_MODE_POSTURE_REASON_ORDER if code in reasons]

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
                "mode_finding_counts": summary.get("mode_finding_counts") or report_data.get("mode_finding_counts") or {},
                "family_finding_counts": summary.get("family_finding_counts") or report_data.get("family_finding_counts") or {},
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": FAILURE_MODE_POSTURE_LIMITATIONS,
            "not_claimed": FAILURE_MODE_POSTURE_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in FAILURE_MODE_POSTURE_GATES.get(code, [])])
    severity = route_severity_for_failure_mode_posture(root, naos_root, profile)
    route_item = {
        "id": "CPR-FAILURE-MODE-POSTURE",
        "source_type": FAILURE_MODE_POSTURE_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"Failure-mode posture report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "failure_mode_posture_reconciliation",
        "target_surfaces": list(FAILURE_MODE_POSTURE_TARGETS),
        "related_capabilities": ["CAP-FAILURE-MODE-POSTURE", "CAP-BEHAVIORAL-GOVERNANCE-READINESS"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "failure_mode_posture_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in FAILURE_MODE_POSTURE_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": FAILURE_MODE_POSTURE_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local failure-mode posture report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "failure_mode_posture_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": FAILURE_MODE_POSTURE_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "failure_mode_posture_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
        "mode_finding_counts": summary.get("mode_finding_counts") or report_data.get("mode_finding_counts") or {},
        "family_finding_counts": summary.get("family_finding_counts") or report_data.get("family_finding_counts") or {},
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
            "mode_finding_counts": route["mode_finding_counts"],
            "family_finding_counts": route["family_finding_counts"],
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": FAILURE_MODE_POSTURE_LIMITATIONS,
        "not_claimed": FAILURE_MODE_POSTURE_NOT_CLAIMED,
    }


def build_failure_mode_observations_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "failure_mode_observations_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in FAILURE_MODE_OBSERVATIONS_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    empty_summary = {
        "report_present": report.exists(),
        "findings_seen": 0,
        "observations_seen": 0,
        "routes_generated": 0,
        "human_review_required": 0,
        "reason_code_counts": reason_code_counts,
        "mode_observation_counts": {},
        "family_observation_counts": {},
        "source_report_counts": {},
        "observation_reason_code_counts": {},
        "mapping_basis_counts": {},
        "unmapped_observations": 0,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": empty_summary | {"report_present": False},
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": FAILURE_MODE_OBSERVATIONS_LIMITATIONS,
            "not_claimed": FAILURE_MODE_OBSERVATIONS_NOT_CLAIMED,
        }

    report_data = data if isinstance(data, dict) else {}
    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in report_data.get("findings") or [] if isinstance(item, dict)]
    observations = [item for item in report_data.get("observations") or [] if isinstance(item, dict)]
    summary = report_data.get("summary") if isinstance(report_data.get("summary"), dict) else {}
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_failure_mode_observations_reason(reasons, failure_mode_observations_reason_code(report_finding))
    if error:
        append_failure_mode_observations_reason(reasons, "source_report_malformed")
    elif report_findings and report_status in {"advisory", "warning", "required_missing", "blocked", "unknown"}:
        append_failure_mode_observations_reason(reasons, "failure_mode_observations_review_required")
    reason_codes = [code for code in FAILURE_MODE_OBSERVATIONS_REASON_ORDER if code in reasons]

    observation_summary = {
        "report_present": True,
        "findings_seen": len(report_findings),
        "observations_seen": len(observations),
        "routes_generated": 0,
        "human_review_required": 0,
        "reason_code_counts": reason_code_counts,
        "mode_observation_counts": summary.get("mode_observation_counts") or report_data.get("mode_observation_counts") or {},
        "family_observation_counts": summary.get("family_observation_counts") or report_data.get("family_observation_counts") or {},
        "source_report_counts": summary.get("source_report_counts") or report_data.get("source_report_counts") or {},
        "observation_reason_code_counts": summary.get("observation_reason_code_counts")
        or report_data.get("observation_reason_code_counts")
        or {},
        "mapping_basis_counts": summary.get("mapping_basis_counts") or report_data.get("mapping_basis_counts") or {},
        "unmapped_observations": summary.get("unmapped_observations", 0),
    }
    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": observation_summary,
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": FAILURE_MODE_OBSERVATIONS_LIMITATIONS,
            "not_claimed": FAILURE_MODE_OBSERVATIONS_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in FAILURE_MODE_OBSERVATIONS_GATES.get(code, [])])
    severity = route_severity_for_failure_mode_observations(root, naos_root, profile)
    route_item = {
        "id": "CPR-FAILURE-MODE-OBSERVATIONS",
        "source_type": FAILURE_MODE_OBSERVATIONS_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"Failure-mode observations report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "failure_mode_observations_reconciliation",
        "target_surfaces": list(FAILURE_MODE_OBSERVATIONS_TARGETS),
        "related_capabilities": [
            "CAP-FAILURE-MODE-OBSERVATIONS",
            "CAP-FAILURE-MODE-POSTURE",
            "CAP-GOVERNED-LEARNING-LIFECYCLE",
        ],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "failure_mode_observations_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in FAILURE_MODE_OBSERVATIONS_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": FAILURE_MODE_OBSERVATIONS_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local failure-mode observations report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "failure_mode_observations_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": FAILURE_MODE_OBSERVATIONS_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "failure_mode_observations_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
        "mode_observation_counts": observation_summary["mode_observation_counts"],
        "family_observation_counts": observation_summary["family_observation_counts"],
        "source_report_counts": observation_summary["source_report_counts"],
        "observation_reason_code_counts": observation_summary["observation_reason_code_counts"],
        "mapping_basis_counts": observation_summary["mapping_basis_counts"],
        "unmapped_observations": observation_summary["unmapped_observations"],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": observation_summary
        | {
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": FAILURE_MODE_OBSERVATIONS_LIMITATIONS,
        "not_claimed": FAILURE_MODE_OBSERVATIONS_NOT_CLAIMED,
    }


def build_opencode_config_hygiene_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "opencode_config_hygiene_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in OPENCODE_CONFIG_HYGIENE_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": OPENCODE_CONFIG_HYGIENE_LIMITATIONS,
            "not_claimed": OPENCODE_CONFIG_HYGIENE_NOT_CLAIMED,
        }

    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_opencode_config_hygiene_reason(reasons, opencode_config_hygiene_reason_code(report_finding))
    if error:
        append_opencode_config_hygiene_reason(reasons, "opencode_project_config_malformed")
    elif report_findings and report_status in {"advisory", "warning", "required_missing", "blocked", "unknown"}:
        append_opencode_config_hygiene_reason(reasons, "opencode_config_review_required")
    reason_codes = [code for code in OPENCODE_CONFIG_HYGIENE_REASON_ORDER if code in reasons]

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": OPENCODE_CONFIG_HYGIENE_LIMITATIONS,
            "not_claimed": OPENCODE_CONFIG_HYGIENE_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in OPENCODE_CONFIG_HYGIENE_GATES.get(code, [])])
    severity = route_severity_for_opencode_config_hygiene(
        root=root,
        naos_root=naos_root,
        profile=profile,
        report_status=report_status,
        report_findings=report_findings,
    )
    route_item = {
        "id": "CPR-OPENCODE-CONFIG-HYGIENE",
        "source_type": OPENCODE_CONFIG_HYGIENE_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"OpenCode config hygiene report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "opencode_config_hygiene_reconciliation",
        "target_surfaces": list(OPENCODE_CONFIG_HYGIENE_TARGETS),
        "related_capabilities": ["CAP-OPENCODE-CONFIG-HYGIENE", "CAP-MODEL-PROVIDER-POLICY"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "opencode_config_hygiene_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in OPENCODE_CONFIG_HYGIENE_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": OPENCODE_CONFIG_HYGIENE_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local OpenCode config hygiene report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "opencode_config_hygiene_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": OPENCODE_CONFIG_HYGIENE_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "opencode_config_hygiene_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": OPENCODE_CONFIG_HYGIENE_LIMITATIONS,
        "not_claimed": OPENCODE_CONFIG_HYGIENE_NOT_CLAIMED,
    }


def build_design_traceability_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "design_traceability_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in DESIGN_TRACEABILITY_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": DESIGN_TRACEABILITY_LIMITATIONS,
            "not_claimed": DESIGN_TRACEABILITY_NOT_CLAIMED,
        }

    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_design_traceability_reason(reasons, design_traceability_reason_code(report_finding))
    if error:
        append_design_traceability_reason(reasons, "stale_or_conflicting_evidence")
    elif report_findings and report_status in {"advisory", "warning", "required_missing", "blocked", "unknown"}:
        append_design_traceability_reason(reasons, "design_traceability_review_required")
    reason_codes = [code for code in DESIGN_TRACEABILITY_REASON_ORDER if code in reasons]

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": DESIGN_TRACEABILITY_LIMITATIONS,
            "not_claimed": DESIGN_TRACEABILITY_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in DESIGN_TRACEABILITY_GATES.get(code, [])])
    severity = route_severity_for_design_traceability(root, naos_root, profile)
    route_item = {
        "id": "CPR-DESIGN-TRACEABILITY",
        "source_type": DESIGN_TRACEABILITY_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"Design traceability report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "design_traceability_reconciliation",
        "target_surfaces": list(DESIGN_TRACEABILITY_TARGETS),
        "related_capabilities": ["CAP-DESIGN-TRACEABILITY"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "design_traceability_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in DESIGN_TRACEABILITY_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": DESIGN_TRACEABILITY_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local design traceability report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "design_traceability_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": DESIGN_TRACEABILITY_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "design_traceability_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": DESIGN_TRACEABILITY_LIMITATIONS,
        "not_claimed": DESIGN_TRACEABILITY_NOT_CLAIMED,
    }


def build_ui_experience_quality_reconciliation(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    allowed_source_types: set[str],
    allowed_target_surfaces: set[str],
    allowed_dispositions: set[str],
    required_fields: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report = report_path(root, naos_root, policy, "ui_experience_quality_report")
    source_ref = relative_ref(root, report)
    data, error = load_json_report(report)
    reason_code_counts = {code: 0 for code in UI_EXPERIENCE_QUALITY_REASON_ORDER}
    source_report = {
        "path": source_ref,
        "present": report.exists(),
        "status": data.get("status") if isinstance(data, dict) else ("parse_error" if error else None),
        "schema": data.get("schema") if isinstance(data, dict) else None,
        "error": error,
    }
    if not report.exists():
        return [], [], {
            "status": "not_applicable",
            "summary": {
                "report_present": False,
                "findings_seen": 0,
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [],
            "routes": [],
            "limitations": UI_EXPERIENCE_QUALITY_LIMITATIONS,
            "not_claimed": UI_EXPERIENCE_QUALITY_NOT_CLAIMED,
        }

    report_status = str(data.get("status") or "") if isinstance(data, dict) else "parse_error"
    report_findings = [item for item in data.get("findings") or [] if isinstance(item, dict)] if isinstance(data, dict) else []
    reasons: set[str] = set()
    for report_finding in report_findings:
        append_ui_experience_quality_reason(reasons, ui_experience_quality_reason_code(report_finding))
    if error:
        append_ui_experience_quality_reason(reasons, "ui_experience_quality_review_required")
    elif report_findings and report_status in {"advisory", "warning", "required_missing", "blocked", "unknown"}:
        append_ui_experience_quality_reason(reasons, "ui_experience_quality_review_required")
    reason_codes = [code for code in UI_EXPERIENCE_QUALITY_REASON_ORDER if code in reasons]

    if not reason_codes:
        return [], [], {
            "status": "pass",
            "summary": {
                "report_present": True,
                "findings_seen": len(report_findings),
                "routes_generated": 0,
                "human_review_required": 0,
                "reason_code_counts": reason_code_counts,
            },
            "source_report": source_report,
            "source_report_refs": [source_ref],
            "routes": [],
            "limitations": UI_EXPERIENCE_QUALITY_LIMITATIONS,
            "not_claimed": UI_EXPERIENCE_QUALITY_NOT_CLAIMED,
        }

    related_gates = dedupe([gate for code in reason_codes for gate in UI_EXPERIENCE_QUALITY_GATES.get(code, [])])
    severity = route_severity_for_ui_experience_quality(root, naos_root, profile)
    route_item = {
        "id": "CPR-UI-EXPERIENCE-QUALITY",
        "source_type": UI_EXPERIENCE_QUALITY_SOURCE_TYPE,
        "source_ref": source_ref,
        "summary": f"UI experience quality report requires human review: {', '.join(reason_codes)}.",
        "source_artifact_family": "ui_experience_quality_reconciliation",
        "target_surfaces": list(UI_EXPERIENCE_QUALITY_TARGETS),
        "related_capabilities": ["CAP-UI-EXPERIENCE-QUALITY"],
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "disposition": "needs_review",
        "owner": "project-governance-reviewer",
        "human_review_required": True,
        "ui_experience_quality_reason_codes": reason_codes,
        "reason_code_counts": {code: 1 if code in reason_codes else 0 for code in UI_EXPERIENCE_QUALITY_REASON_ORDER},
        "source_report_refs": [source_ref],
        "not_claimed": UI_EXPERIENCE_QUALITY_NOT_CLAIMED,
        "notes": "Generated by control-plane review from the local UI experience quality report; not written to control_plane_review_items.yaml.",
    }
    decision, findings = evaluate_item(
        item=route_item,
        rules=rules,
        severity=severity,
        required_fields=required_fields,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
    )
    for generated_finding in findings:
        generated_finding.update(
            {
                "ui_experience_quality_reason_codes": reason_codes,
                "related_gates": related_gates,
                "related_evidence": [source_ref],
                "not_claimed": UI_EXPERIENCE_QUALITY_NOT_CLAIMED,
            }
        )
    for code in reason_codes:
        reason_code_counts[code] += 1
    route = {
        "id": decision["id"],
        "status": decision["status"],
        "severity": severity,
        "human_review_required": True,
        "ui_experience_quality_reason_codes": reason_codes,
        "related_gates": related_gates,
        "related_evidence": [source_ref],
        "report_status": report_status,
        "source_report_refs": [source_ref],
    }
    return [decision], findings, {
        "status": status_from_counts(finding_counts(findings)) if findings else "review_required",
        "summary": {
            "report_present": True,
            "findings_seen": len(report_findings),
            "routes_generated": 1,
            "human_review_required": 1,
            "reason_code_counts": reason_code_counts,
        },
        "source_report": source_report,
        "source_report_refs": [source_ref],
        "routes": [route],
        "limitations": UI_EXPERIENCE_QUALITY_LIMITATIONS,
        "not_claimed": UI_EXPERIENCE_QUALITY_NOT_CLAIMED,
    }


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    items_path: Path | None = None,
    items_source: str | None = None,
) -> dict[str, Any]:
    rules = load_yaml(rules_path)
    if rules.get("enabled") is False:
        return build_disabled_report(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules_path=rules_path,
            rules_source=rules_source,
            rules=rules,
        )
    if items_path is None:
        items_path, items_source = resolve_items_path(root, naos_root, policy, rules)
    items_source = items_source or "unknown"
    items_data = load_yaml(items_path)

    severity = rule_severity(root, naos_root, profile, policy, rules)
    required_fields = as_list(rules.get("required_item_fields"))
    allowed_source_types = set(as_list(rules.get("source_types")))
    allowed_target_surfaces = set(as_list(rules.get("target_surfaces")))
    allowed_dispositions = set(as_list(rules.get("allowed_dispositions")))
    raw_items = [item for item in items_data.get("items") or [] if isinstance(item, dict)]

    routing_decisions: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for item in raw_items:
        decision, item_findings = evaluate_item(
            item=item,
            rules=rules,
            severity=severity,
            required_fields=required_fields,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
        )
        routing_decisions.append(decision)
        findings.extend(item_findings)

    parallel_decisions, parallel_findings, parallel_reconciliation = build_parallel_lane_reconciliation(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules=rules,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
        required_fields=required_fields,
    )
    routing_decisions.extend(parallel_decisions)
    findings.extend(parallel_findings)

    external_sarif_decisions, external_sarif_findings, external_sarif_reconciliation = (
        build_external_sarif_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(external_sarif_decisions)
    findings.extend(external_sarif_findings)

    ai_inventory_decisions, ai_inventory_findings, ai_inventory_reconciliation = (
        build_ai_component_inventory_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(ai_inventory_decisions)
    findings.extend(ai_inventory_findings)

    sponsor_registry_decisions, sponsor_registry_findings, sponsor_registry_reconciliation = (
        build_agent_sponsor_registry_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(sponsor_registry_decisions)
    findings.extend(sponsor_registry_findings)

    aivss_decisions, aivss_findings, aivss_reconciliation = (
        build_aivss_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(aivss_decisions)
    findings.extend(aivss_findings)

    model_provider_decisions, model_provider_findings, model_provider_reconciliation = build_model_provider_reconciliation(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules=rules,
        allowed_source_types=allowed_source_types,
        allowed_target_surfaces=allowed_target_surfaces,
        allowed_dispositions=allowed_dispositions,
        required_fields=required_fields,
    )
    routing_decisions.extend(model_provider_decisions)
    findings.extend(model_provider_findings)

    model_telemetry_decisions, model_telemetry_findings, model_telemetry_reconciliation = (
        build_model_telemetry_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(model_telemetry_decisions)
    findings.extend(model_telemetry_findings)

    failure_mode_posture_decisions, failure_mode_posture_findings, failure_mode_posture_reconciliation = (
        build_failure_mode_posture_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(failure_mode_posture_decisions)
    findings.extend(failure_mode_posture_findings)

    failure_mode_observations_decisions, failure_mode_observations_findings, failure_mode_observations_reconciliation = (
        build_failure_mode_observations_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(failure_mode_observations_decisions)
    findings.extend(failure_mode_observations_findings)

    opencode_config_hygiene_decisions, opencode_config_hygiene_findings, opencode_config_hygiene_reconciliation = (
        build_opencode_config_hygiene_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(opencode_config_hygiene_decisions)
    findings.extend(opencode_config_hygiene_findings)

    design_traceability_decisions, design_traceability_findings, design_traceability_reconciliation = (
        build_design_traceability_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(design_traceability_decisions)
    findings.extend(design_traceability_findings)

    ui_experience_quality_decisions, ui_experience_quality_findings, ui_experience_quality_reconciliation = (
        build_ui_experience_quality_reconciliation(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=rules,
            allowed_source_types=allowed_source_types,
            allowed_target_surfaces=allowed_target_surfaces,
            allowed_dispositions=allowed_dispositions,
            required_fields=required_fields,
        )
    )
    routing_decisions.extend(ui_experience_quality_decisions)
    findings.extend(ui_experience_quality_findings)

    if (
        not raw_items
        and not parallel_decisions
        and not external_sarif_decisions
        and not ai_inventory_decisions
        and not sponsor_registry_decisions
        and not aivss_decisions
        and not model_provider_decisions
        and not model_telemetry_decisions
        and not failure_mode_posture_decisions
        and not failure_mode_observations_decisions
        and not opencode_config_hygiene_decisions
        and not design_traceability_decisions
        and not ui_experience_quality_decisions
    ):
        findings.append(
            finding(
                item_id="control_plane_review_items",
                severity=severity,
                status="not_configured",
                message="No structured control-plane review or research-routing items are declared.",
                required_next_actions=[
                    "Add items when governance-surface changes or actionable research findings need routing, or keep this as an explicit quickstart gap."
                ],
            )
        )

    governance_items = [item for item in routing_decisions if item.get("source_type") in GOVERNANCE_SOURCE_TYPES]
    research_items = [item for item in routing_decisions if item.get("source_type") in RESEARCH_SOURCE_TYPES]
    governance_section = section_for(governance_items)
    research_section = section_for(research_items)
    summary = finding_counts(findings)
    status_counts = {status: sum(1 for item in routing_decisions if item.get("status") == status) for status in sorted({str(item.get("status")) for item in routing_decisions})}
    known_gaps = [entry for entry in items_data.get("known_gaps") or [] if isinstance(entry, dict)]
    residual_risks = [entry for entry in items_data.get("residual_risks") or [] if isinstance(entry, dict)]
    waivers = [entry for entry in items_data.get("waivers") or [] if isinstance(entry, dict)]
    referenced_gap_ids = {str(item.get("known_gap_ref")) for item in routing_decisions if item.get("known_gap_ref")}
    referenced_risk_ids = {str(item.get("residual_risk_ref")) for item in routing_decisions if item.get("residual_risk_ref")}
    referenced_waiver_ids = {str(item.get("waiver_ref")) for item in routing_decisions if item.get("waiver_ref")}
    known_gaps.extend({"id": gap_id, "source": "routing_item_reference"} for gap_id in sorted(referenced_gap_ids))
    residual_risks.extend({"id": risk_id, "source": "routing_item_reference"} for risk_id in sorted(referenced_risk_ids))
    waivers.extend({"id": waiver_id, "source": "routing_item_reference"} for waiver_id in sorted(referenced_waiver_ids))
    summary.update(
        {
            "items": len(routing_decisions),
            "governance_surface_items": len(governance_items),
            "research_routing_items": len(research_items),
            "routed": status_counts.get("routed", 0),
            "missing_routing": status_counts.get("missing_routing", 0),
            "review_required": status_counts.get("review_required", 0),
            "blocked": status_counts.get("blocked", 0),
            "advisory_status": status_counts.get("advisory", 0),
            "not_configured": 1
            if not raw_items
            and not parallel_decisions
            and not external_sarif_decisions
            and not ai_inventory_decisions
            and not sponsor_registry_decisions
            and not aivss_decisions
            and not model_provider_decisions
            and not model_telemetry_decisions
            and not failure_mode_posture_decisions
            and not failure_mode_observations_decisions
            and not opencode_config_hygiene_decisions
            and not design_traceability_decisions
            and not ui_experience_quality_decisions
            else status_counts.get("not_configured", 0),
            "disabled": status_counts.get("disabled", 0),
            "waived": status_counts.get("waived", 0),
            "unknown": status_counts.get("unknown", 0),
            "known_gaps": len(known_gaps),
            "residual_risks": len(residual_risks),
            "waivers": len(waivers),
            "human_review_required": sum(1 for item in routing_decisions if item.get("human_review_required")),
            "parallel_lane_handoff_routes": len(parallel_decisions),
            "parallel_lane_handoff_hitl_required": parallel_reconciliation["summary"]["hitl_required"],
            "external_sarif_result_routes": len(external_sarif_decisions),
            "external_sarif_result_human_review_required": external_sarif_reconciliation["summary"][
                "human_review_required"
            ],
            "ai_component_inventory_routes": len(ai_inventory_decisions),
            "ai_component_inventory_human_review_required": ai_inventory_reconciliation["summary"][
                "human_review_required"
            ],
            "agent_sponsor_registry_routes": len(sponsor_registry_decisions),
            "agent_sponsor_registry_human_review_required": sponsor_registry_reconciliation["summary"][
                "human_review_required"
            ],
            "aivss_arithmetic_verification_routes": len(aivss_decisions),
            "aivss_arithmetic_verification_human_review_required": aivss_reconciliation[
                "summary"
            ]["human_review_required"],
            "model_provider_policy_routes": len(model_provider_decisions),
            "model_provider_policy_human_review_required": model_provider_reconciliation["summary"]["human_review_required"],
            "model_telemetry_evidence_routes": len(model_telemetry_decisions),
            "model_telemetry_evidence_human_review_required": model_telemetry_reconciliation["summary"][
                "human_review_required"
            ],
            "failure_mode_posture_routes": len(failure_mode_posture_decisions),
            "failure_mode_posture_human_review_required": failure_mode_posture_reconciliation["summary"][
                "human_review_required"
            ],
            "failure_mode_observations_routes": len(failure_mode_observations_decisions),
            "failure_mode_observations_human_review_required": failure_mode_observations_reconciliation["summary"][
                "human_review_required"
            ],
            "opencode_config_hygiene_routes": len(opencode_config_hygiene_decisions),
            "opencode_config_hygiene_human_review_required": opencode_config_hygiene_reconciliation["summary"][
                "human_review_required"
            ],
            "design_traceability_routes": len(design_traceability_decisions),
            "design_traceability_human_review_required": design_traceability_reconciliation["summary"][
                "human_review_required"
            ],
            "ui_experience_quality_routes": len(ui_experience_quality_decisions),
            "ui_experience_quality_human_review_required": ui_experience_quality_reconciliation["summary"][
                "human_review_required"
            ],
        }
    )
    policy_meta = policy.get("_meta", {})
    return {
        "schema": "naos.control_plane_review.v1",
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary) if routing_decisions else "not_configured",
        "naos_root": naos_root,
        "project_root": str(root),
        "rules": {
            "path": str(rules_path),
            "source": rules_source,
            "semantics": rules.get("semantics") or {},
            "ignored_source_patterns": as_list(rules.get("ignored_source_patterns")),
        },
        "items": {
            "path": str(items_path),
            "source": items_source,
            "structured_items": len(raw_items),
        },
        "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
        "semantics": {
            "review_items": "Structured declarations of governance-surface changes or actionable findings; not proof by themselves.",
            "report": "NAOS evaluates routing status and missing review obligations.",
            "governance_decision": "Humans approve disposition, remediation, waiver, residual-risk treatment, and next action.",
            "not_claimed": "This report does not prove research completeness, routing completeness, governance correctness, or compliance.",
            "parallel_lane_handoff_reconciliation": "Generated route evidence from local handoff and planning/risk reports; not approval, merge readiness, task closure, or runtime orchestration.",
            "external_sarif_result_reconciliation": "Generated advisory route evidence from local unverified SARIF ingest records; not finding verification, risk/severity mapping, control satisfaction, assessed-scope completeness, durable disposition, automatic task creation, approval, blocking, release, or publication authority.",
            "ai_component_inventory_reconciliation": "Generated route evidence from the local custom declared-facts inventory; not CycloneDX/SPDX conformance, runtime discovery, completeness, signing, attestation, supply-chain assurance, approval, or certification.",
            "agent_sponsor_registry_reconciliation": "Generated route evidence from an optional local declared-posture registry; not sponsor identity, approval, authentication, authorization, credential validation, runtime enforcement, signing, attestation, release, or publication authority.",
            "aivss_arithmetic_verification_reconciliation": "Generated advisory route evidence from optional local AIVSS-Agentic v0.8 arithmetic verification; not risk assessment, exploitability proof, vulnerability discovery, CVSS validation, runtime observation, mitigation proof, security assurance, compliance evidence, certification, approval, blocking, prioritization, merge, release, risk acceptance, or publication authority.",
            "model_provider_policy_reconciliation": "Generated route evidence from the local model-provider policy report; not provider access, model recommendation, runtime routing, MCP/Engram configuration, approval, or certification.",
            "model_telemetry_evidence_reconciliation": "Generated route evidence from the local model telemetry evidence report; not provider access, model calls, route enforcement, complete cost accounting, MCP/memory activation, approval, or certification.",
            "failure_mode_posture_reconciliation": "Generated route evidence from the local failure-mode posture report; not failure prevention, behavioral safety proof, automatic learning, runtime orchestration, MCP/memory activation, provider/model routing, approval, or certification.",
            "failure_mode_observations_reconciliation": "Generated route evidence from the local failure-mode observations report; not numeric risk scoring, automatic learning, prompt mutation, runtime orchestration, MCP/Engram/memory activation, provider/model routing, approval, or certification.",
            "opencode_config_hygiene_reconciliation": "Generated route evidence from the local OpenCode config hygiene report; not OpenCode execution, MCP/memory/provider/model activation, credential validation, approval, certification, or compliance proof.",
            "design_traceability_reconciliation": "Generated route evidence from the local design traceability report; not design-tool sync, design quality proof, runtime orchestration, MCP activation, approval, or certification.",
            "ui_experience_quality_reconciliation": "Generated route evidence from the local UI experience quality report; not design quality proof, accessibility proof, brand approval, runtime orchestration, MCP activation, approval, or certification.",
        },
        "summary": summary,
        "governance_surface_review": governance_section,
        "research_routing": research_section,
        "parallel_lane_handoff_reconciliation": parallel_reconciliation,
        "external_sarif_result_reconciliation": external_sarif_reconciliation,
        "ai_component_inventory_reconciliation": ai_inventory_reconciliation,
        "agent_sponsor_registry_reconciliation": sponsor_registry_reconciliation,
        "aivss_arithmetic_verification_reconciliation": aivss_reconciliation,
        "model_provider_policy_reconciliation": model_provider_reconciliation,
        "model_telemetry_evidence_reconciliation": model_telemetry_reconciliation,
        "failure_mode_posture_reconciliation": failure_mode_posture_reconciliation,
        "failure_mode_observations_reconciliation": failure_mode_observations_reconciliation,
        "opencode_config_hygiene_reconciliation": opencode_config_hygiene_reconciliation,
        "design_traceability_reconciliation": design_traceability_reconciliation,
        "ui_experience_quality_reconciliation": ui_experience_quality_reconciliation,
        "routing_decisions": routing_decisions,
        "findings": findings,
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "waivers": waivers,
        "human_review_required": bool(
            summary["human_review_required"]
            or summary["review_required"]
            or summary["missing_routing"]
            or summary["parallel_lane_handoff_hitl_required"]
            or summary["external_sarif_result_human_review_required"]
            or summary["ai_component_inventory_human_review_required"]
            or summary["agent_sponsor_registry_human_review_required"]
            or summary["aivss_arithmetic_verification_human_review_required"]
            or summary["model_provider_policy_human_review_required"]
            or summary["model_telemetry_evidence_human_review_required"]
            or summary["failure_mode_posture_human_review_required"]
            or summary["failure_mode_observations_human_review_required"]
            or summary["opencode_config_hygiene_human_review_required"]
            or summary["design_traceability_human_review_required"]
            or summary["ui_experience_quality_human_review_required"]
        ),
        "limitations": as_list(rules.get("limitations"))
        + [
            "The evaluator is deterministic and file-first.",
            "It does not perform web research, behavioral grading, LLM inference, semantic inference, or automatic remediation.",
            "It does not scan private/internal dev content by default for adopter-facing behavior.",
            "Routed status requires structured item disposition and target surfaces; report existence alone is not proof.",
            "Parallel-lane reconciliation emits review reason codes only; it does not approve, block, merge, release, dispatch agents, or activate MCP, memory, providers, hooks, models, or runtime orchestration.",
            "External-SARIF reconciliation emits repeatable advisory human-review prompts only; it does not verify findings, map risk/severity or controls, prove assessed scope or vulnerability absence, persist human disposition, create tasks/writeback, approve, block, prioritize, merge, release, accept risk, certify, publish, or prove compliance.",
            "AI-component inventory reconciliation emits review reason codes only; it does not prove runtime discovery, inventory completeness, provider/model identity, CycloneDX/SPDX conformance, signing, attestation, supply-chain assurance, approval, certification, compliance, release, or publication authority.",
            "Agent-sponsor registry reconciliation emits review reason codes only; it does not verify a sponsor, authenticate or authorize an agent, validate credential existence or lifetime, enforce runtime behavior, approve, certify, attest, release, or publish.",
            "AIVSS arithmetic reconciliation emits fixed advisory G2/G6 review prompts only; it does not select or validate subjective inputs, calculate CVSS, assess risk or exploitability, discover vulnerabilities, observe runtime behavior, prove mitigations or security, approve, block, prioritize, merge, release, accept risk, certify, attest, publish, or prove compliance.",
            "Model-provider reconciliation emits review reason codes only; it does not call providers, validate credentials, recommend models, route runtime calls, inspect or mutate MCP/Engram configuration, or activate LLMGrader, autoresearch, semantic, provider, model, or memory runtime.",
            "Model telemetry reconciliation emits review reason codes only; it does not call providers, models, APIs, gateways, MCP, memory tools, networks, hooks, or IDE/tool configuration, and it does not prove complete cost accounting, payload safety, route correctness, approval, certification, or compliance.",
            "Failure-mode posture reconciliation emits review reason codes and mode/family statistics only; it does not prevent hallucinations or failures, run behavioral batteries, mutate learning or prompts, call providers/models, activate MCP or memory, approve work, block gates, certify, attest, release, publish, or prove compliance.",
            "Failure-mode observations reconciliation emits review reason codes and observation statistics only; it does not create or promote learning, mutate prompts/skills/workflows, use numeric risk scores as authority, call providers/models, activate MCP/Engram/memory, approve work, block gates, certify, attest, release, publish, or prove compliance.",
            "OpenCode config hygiene reconciliation emits review reason codes only; it does not create, install, run, configure, enable, disable, or mutate OpenCode, MCP, memory, providers, models, hooks, IDE settings, global config, credentials, plugins, or runtime systems.",
            "Design-traceability reconciliation emits review reason codes only; it does not inspect or mutate Figma, MCP, html.to.design, browsers, IDE settings, providers, models, memory tools, or runtime systems, and it does not prove design quality, accessibility, privacy, brand, approval, certification, or compliance.",
            "UI experience quality reconciliation emits review reason codes only; it does not inspect or mutate Figma, MCP, Penpot, html.to.design, browsers, IDE settings, providers, models, memory tools, design tools, or runtime systems, and it does not prove design quality, accessibility, privacy, brand, delight, approval, certification, or compliance.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate NAOS control-plane review and research-routing items.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="Path to control_plane_review_rules.yaml.")
    parser.add_argument("--items", help="Path to control_plane_review_items.yaml.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    rules = load_yaml(rules_path)
    items_path, items_source = resolve_items_path(root, naos_root, policy, rules, args.items)
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules_path=rules_path,
        rules_source=rules_source,
        items_path=items_path,
        items_source=items_source,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "control_plane_review_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS control-plane review: "
            f"{report['status']} "
            f"({report['summary'].get('routed', 0)} routed, "
            f"{report['summary'].get('missing_routing', 0)} missing routing, "
            f"{report['summary'].get('review_required', 0)} review required, "
            f"output: {destination})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
