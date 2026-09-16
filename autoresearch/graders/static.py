"""Deterministic StaticGrader reference implementation for NAOS."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "naos.static_grader_report.v1"

SUPPORTED_DIMENSIONS = [
    "D1_structural_conformance",
    "D4_scenario_or_evidence_coverage",
    "trace_schema_conformance",
    "source_reference_coverage",
    "task_spec_capability_linkage",
    "evidence_reference_presence",
    "forbidden_payload_absence",
    "non_claim_boundary_presence",
]

FUTURE_BEHAVIORAL_DIMENSIONS = [
    "D2_agent_role_behavior",
    "D3_instruction_following_behavior",
    "D5_efficiency_or_cost_behavior",
    "D6_portability_behavior",
    "D7_session_hygiene_behavior",
    "D8_ai_output_quality_behavior",
]

ZERO_COST_POLICY = {
    "cost_incurred_by_default": False,
    "cost_usd": 0.0,
    "external_api_required": False,
    "provider_dependency_required": False,
    "model_dependency_required": False,
    "cost_budget_required_if_enabled_later": True,
    "human_approval_required_before_cost": True,
}

RESIDUAL_RISKS = [
    "static_checks_do_not_prove_behavior",
    "ai_surface_health_degradation_can_reduce_baseline_interpretability",
    "trace_events_are_declared_records",
    "missing_trace_events_reduce_coverage",
    "stale_reports_may_mislead",
    "deterministic_structure_does_not_prove_semantic_correctness",
    "human_review_required",
]

LIMITATIONS = [
    "StaticGrader evaluates deterministic structure and declared trace metadata only.",
    "StaticGrader does not execute commands listed in trace events.",
    "StaticGrader does not call Engram, MCP, memory tools, models, providers, or external APIs.",
    "StaticGrader does not evaluate semantic behavior, fairness, alignment, robustness, safety, explainability, accountability, or compliance.",
]

NOT_CLAIMED = [
    "behavioral safety proof",
    "legal/compliance/regulatory proof",
    "semantic correctness proof",
    "hallucination prevention",
    "approval",
    "maturity promotion by itself",
    "runtime behavior proof",
    "LLMGrader runtime",
    "provider or API dependency",
    "memory write",
]


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def severity_for_profile(profile: str, advisory: bool = False) -> str:
    if advisory:
        return "advisory"
    return {
        "quickstart": "advisory",
        "lite": "warning",
        "standard": "required",
        "assured": "blocking",
    }.get(profile, "advisory")


def finding_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "blocking": sum(1 for finding in findings if finding.get("severity") == "blocking"),
        "required": sum(1 for finding in findings if finding.get("severity") == "required"),
        "warnings": sum(1 for finding in findings if finding.get("severity") == "warning"),
        "advisory": sum(1 for finding in findings if finding.get("severity") == "advisory"),
        "total_findings": len(findings),
    }


def compact_finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    dimension_id: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    finding = {"id": finding_id, "severity": severity, "status": status, "message": message}
    if dimension_id:
        finding["dimension_id"] = dimension_id
    if source:
        finding["source"] = source
    return finding


def dimension(
    *,
    dimension_id: str,
    name: str,
    status: str,
    passed: bool | None,
    findings: list[dict[str, Any]],
    input_sources: list[str],
    limitations: list[str] | None = None,
    not_claimed: list[str] | None = None,
    human_review_required: bool | None = None,
) -> dict[str, Any]:
    score: float | None
    if passed is True:
        score = 1.0
    elif passed is False:
        score = 0.0
    else:
        score = None
    return {
        "dimension_id": dimension_id,
        "name": name,
        "status": status,
        "score": score,
        "passed": passed,
        "findings": findings,
        "input_sources": input_sources,
        "limitations": limitations or ["Deterministic structural dimension only."],
        "not_claimed": not_claimed or ["semantic behavior", "runtime behavior proof", "approval"],
        "human_review_required": bool(findings) if human_review_required is None else human_review_required,
    }


def statuses_from_trace(trace_report: dict[str, Any] | None) -> set[str]:
    if not trace_report:
        return set()
    return {str(item.get("status")) for item in trace_report.get("findings") or [] if isinstance(item, dict)}


def trace_report_findings(trace_report: dict[str, Any] | None, *statuses: str) -> list[dict[str, Any]]:
    if not trace_report:
        return []
    wanted = set(statuses)
    return [
        item
        for item in trace_report.get("findings") or []
        if isinstance(item, dict) and (not wanted or str(item.get("status")) in wanted)
    ]


def ai_surface_health_from_inputs(input_reports: list[dict[str, Any]]) -> dict[str, Any]:
    for item in input_reports:
        if item.get("id") == "ai_surface_context_budget":
            status = str(item.get("status") or "missing")
            posture = str(item.get("ai_surface_health_posture") or item.get("context_budget_posture") or status)
            present = bool(item.get("present"))
            return {
                "source_report_path": item.get("path"),
                "source_report_present": present,
                "status": status,
                "ai_surface_health_posture": posture if present else "missing",
                "context_budget_posture": posture if present else "missing",
                "findings_count": int(item.get("findings_count") or 0),
                "authority_layer": "deterministic_input_quality",
                "can_change_behavioral_scores": False,
                "human_review_required": present and posture in {"warning", "degraded", "blocked", "required_missing"},
                "not_claimed": ["behavioral score", "hallucination prevention", "approval"],
            }
    return {
        "source_report_path": None,
        "source_report_present": False,
        "status": "missing",
        "ai_surface_health_posture": "missing",
        "context_budget_posture": "missing",
        "findings_count": 0,
        "authority_layer": "deterministic_input_quality",
        "can_change_behavioral_scores": False,
        "human_review_required": False,
        "not_claimed": ["behavioral score", "hallucination prevention", "approval"],
    }


def status_from_findings(profile: str, findings: list[dict[str, Any]], no_inputs: bool) -> str:
    if no_inputs:
        return "advisory" if profile in {"quickstart", "lite"} else "review_required"
    if any(item.get("severity") == "blocking" for item in findings):
        return "blocked"
    if any(item.get("severity") == "required" for item in findings):
        return "review_required"
    if any(item.get("severity") == "warning" for item in findings):
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def summarize_dimensions(dimensions: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(item.get("status") or "unknown") for item in dimensions)
    return dict(sorted(counter.items()))


class StaticGrader:
    """Deterministic structural grader for declared NAOS trace evidence."""

    name = "StaticGrader"
    version = "1.0.0"
    supported_dimensions = SUPPORTED_DIMENSIONS
    deterministic = True
    advisory = False
    required_inputs = ["agent_trace_validation_report or agent_trace_events"]
    forbidden_inputs = [
        "LLMGrader runtime",
        "model calls",
        "external APIs",
        "provider credentials",
        "Engram calls",
        "MCP calls",
        "memory tools",
        "private memory payloads",
        "command execution from trace events",
    ]
    cost_policy = ZERO_COST_POLICY

    def grade(
        self,
        *,
        root: Path,
        profile: str,
        naos_root: str,
        policy: dict[str, Any],
        trace_report: dict[str, Any] | None,
        trace_events: list[dict[str, Any]],
        input_reports: list[dict[str, Any]],
        trace_report_path: Path | None,
        trace_file_path: Path | None,
    ) -> dict[str, Any]:
        # Direct library callers receive the same canonical structural check as
        # the CLI. A supplied report cannot conceal malformed current events.
        try:
            from scripts.naos_agent_trace_validate import validate_schema_shape
        except ImportError:
            from naos_agent_trace_validate import validate_schema_shape
        declared_event_count = len(trace_events)
        current_schema_errors = [validate_schema_shape(event) for event in trace_events]
        current_invalid_count = sum(bool(errors) for errors in current_schema_errors)
        trace_events = [event for event in trace_events if isinstance(event, dict)]
        del policy
        trace_source = str(trace_report_path) if trace_report else str(trace_file_path) if trace_file_path else "not_configured"
        no_trace_inputs = trace_report is None and declared_event_count == 0
        findings: list[dict[str, Any]] = []
        dimensions: list[dict[str, Any]] = []
        severity = severity_for_profile(profile)
        advisory_severity = severity_for_profile(profile, advisory=True)

        if no_trace_inputs:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_TRACE_INPUT",
                    severity=advisory_severity if profile in {"quickstart", "lite"} else severity,
                    status="missing_trace_input",
                    message="No agent trace validation report or trace event file is available; StaticGrader remains limited to readiness posture.",
                    dimension_id="D1_structural_conformance",
                    source=trace_source,
                )
            )

        trace_status = str(trace_report.get("status")) if trace_report else "not_configured"
        invalid_event_count = max(current_invalid_count, int(trace_report.get("invalid_event_count") or 0) if trace_report else 0)
        if "invalid_trace_file" in statuses_from_trace(trace_report):
            invalid_event_count = max(1, invalid_event_count)
        event_count = max(declared_event_count, int(trace_report.get("event_count") or 0) if trace_report else 0)
        trace_statuses = statuses_from_trace(trace_report)
        ai_surface_health = ai_surface_health_from_inputs(input_reports)

        if invalid_event_count:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_INVALID_TRACE_EVENTS",
                    severity=severity,
                    status="invalid_trace_events",
                    message="Agent trace validation reported invalid trace events.",
                    dimension_id="trace_schema_conformance",
                    source=trace_source,
                )
            )

        forbidden_payload_findings = trace_report.get("forbidden_payload_findings") if trace_report else []
        if forbidden_payload_findings:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_FORBIDDEN_PAYLOAD",
                    severity=severity,
                    status="forbidden_payload_findings",
                    message="Agent trace validation found forbidden/private payload indicators.",
                    dimension_id="forbidden_payload_absence",
                    source=trace_source,
                )
            )

        receipt_findings = [item for item in (trace_report or {}).get("findings", [])
                            if str(item.get("status", "")).startswith("action_receipt_")]
        approval_findings = sorted({str(item.get("status")) for item in receipt_findings})
        if approval_findings:
            receipt_severity = next((level for level in ("blocking", "required", "warning", "advisory")
                                     if any(item.get("severity") == level for item in receipt_findings)), severity)
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_ACTION_RECEIPT_REVIEW",
                    severity=receipt_severity,
                    status="action_receipt_review_required",
                    message="Declared action receipt requires review: " + ", ".join(approval_findings),
                    dimension_id="non_claim_boundary_presence",
                    source=trace_source,
                )
            )

        if "missing_source_references" in trace_statuses:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_SOURCE_REFERENCES",
                    severity=severity,
                    status="missing_source_references",
                    message="Trace events declare outputs without source references or source hashes.",
                    dimension_id="source_reference_coverage",
                    source=trace_source,
                )
            )

        overclaim_statuses = sorted(status for status in trace_statuses if status.startswith("trace_claims_"))
        if overclaim_statuses:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_TRACE_OVERCLAIM",
                    severity=severity,
                    status="trace_event_overclaim",
                    message="Trace validation reported trace authority/proof overclaim wording.",
                    dimension_id="non_claim_boundary_presence",
                    source=trace_source,
                )
            )

        if {"missing_limitations", "missing_not_claimed"} & trace_statuses:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_NON_CLAIM_BOUNDARY",
                    severity=severity,
                    status="missing_limitations_or_not_claimed",
                    message="Trace events must declare limitations and non-claims before grading reliance.",
                    dimension_id="non_claim_boundary_presence",
                    source=trace_source,
                )
            )

        if any(event.get("human_review_required") is not True for event in trace_events):
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_HUMAN_REVIEW_BOUNDARY",
                    severity=severity,
                    status="missing_human_review_boundary",
                    message="One or more trace events do not explicitly require human review.",
                    dimension_id="non_claim_boundary_presence",
                    source=str(trace_file_path) if trace_file_path else trace_source,
                )
            )

        if event_count and not any(event.get("task_id") or event.get("referenced_tasks") for event in trace_events):
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_TASK_LINKAGE",
                    severity=severity,
                    status="missing_task_spec_capability_linkage",
                    message="Trace events do not declare task references.",
                    dimension_id="task_spec_capability_linkage",
                    source=str(trace_file_path) if trace_file_path else trace_source,
                )
            )
        if event_count and not any(event.get("referenced_specs") for event in trace_events):
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_SPEC_LINKAGE",
                    severity=advisory_severity,
                    status="missing_task_spec_capability_linkage",
                    message="Trace events do not declare spec references; semantic/spec adequacy is not inferred.",
                    dimension_id="task_spec_capability_linkage",
                    source=str(trace_file_path) if trace_file_path else trace_source,
                )
            )
        if event_count and not any(event.get("referenced_capabilities") for event in trace_events):
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_CAPABILITY_LINKAGE",
                    severity=advisory_severity,
                    status="missing_task_spec_capability_linkage",
                    message="Trace events do not declare capability references; capability linkage coverage remains limited.",
                    dimension_id="task_spec_capability_linkage",
                    source=str(trace_file_path) if trace_file_path else trace_source,
                )
            )
        if event_count and not any(event.get("evidence_refs") or event.get("reports_generated") for event in trace_events):
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_EVIDENCE_REFERENCES",
                    severity=severity,
                    status="missing_evidence_references",
                    message="Trace events do not declare evidence references or generated reports.",
                    dimension_id="evidence_reference_presence",
                    source=str(trace_file_path) if trace_file_path else trace_source,
                )
            )

        missing_optional_reports = [item["id"] for item in input_reports if not item.get("present")]
        if missing_optional_reports:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_MISSING_DETERMINISTIC_REPORTS",
                    severity=advisory_severity,
                    status="missing_deterministic_input_report",
                    message="Some optional deterministic input reports are missing; coverage remains partial.",
                    source=";".join(missing_optional_reports),
                )
            )
        if ai_surface_health.get("source_report_present") and ai_surface_health.get("ai_surface_health_posture") in {"warning", "degraded"}:
            findings.append(
                compact_finding(
                    finding_id="STATICGRADER_AI_SURFACE_HEALTH_REVIEW",
                    severity=advisory_severity,
                    status="ai_surface_health_review_required",
                    message="AI-surface context-budget posture may reduce baseline interpretability; behavioral dimensions remain not evaluated.",
                    source=str(ai_surface_health.get("source_report_path")),
                )
            )

        unsupported_findings = []
        for dimension_id in FUTURE_BEHAVIORAL_DIMENSIONS:
            unsupported_findings.append(
                compact_finding(
                    finding_id=f"STATICGRADER_UNSUPPORTED_{dimension_id}",
                    severity=advisory_severity,
                    status="unsupported_behavioral_dimension",
                    message=f"{dimension_id} is not evaluated by StaticGrader v1; it remains future/advisory/readiness-only.",
                    dimension_id=dimension_id,
                )
            )
        findings.extend(unsupported_findings)

        dimensions.append(
            dimension(
                dimension_id="D1_structural_conformance",
                name="Structural Conformance",
                status="not_evaluated" if no_trace_inputs else "failed" if invalid_event_count else "pass" if trace_report and trace_status in {"ready", "no_events", "not_configured"} else "review_required",
                passed=None if no_trace_inputs else not bool(invalid_event_count),
                findings=[item for item in findings if item.get("dimension_id") == "D1_structural_conformance"],
                input_sources=[trace_source],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="D4_scenario_or_evidence_coverage",
                name="Scenario Or Evidence Coverage",
                status="not_evaluated" if not event_count else "pass" if any(event.get("evidence_refs") or event.get("reports_generated") for event in trace_events) else "review_required",
                passed=None if not event_count else any(event.get("evidence_refs") or event.get("reports_generated") for event in trace_events),
                findings=[item for item in findings if item.get("dimension_id") == "evidence_reference_presence"],
                input_sources=[str(trace_file_path) if trace_file_path else trace_source],
                not_claimed=["scenario completeness", "behavioral coverage", "approval"],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="trace_schema_conformance",
                name="Trace Schema Conformance",
                status="failed" if invalid_event_count else "not_evaluated" if trace_report is None and not trace_events else "pass",
                passed=False if invalid_event_count else None if trace_report is None and not trace_events else True,
                findings=[item for item in findings if item.get("dimension_id") == "trace_schema_conformance"],
                input_sources=[trace_source],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="source_reference_coverage",
                name="Source Reference Coverage",
                status="not_evaluated" if trace_report is None else "pass" if "missing_source_references" not in trace_statuses else "review_required",
                passed=None if trace_report is None else "missing_source_references" not in trace_statuses,
                findings=[item for item in findings if item.get("dimension_id") == "source_reference_coverage"],
                input_sources=[trace_source],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="task_spec_capability_linkage",
                name="Task/Spec/Capability Linkage",
                status="not_evaluated" if not event_count else "pass" if not [item for item in findings if item.get("dimension_id") == "task_spec_capability_linkage" and item.get("severity") != "advisory"] else "review_required",
                passed=None if not event_count else not [item for item in findings if item.get("dimension_id") == "task_spec_capability_linkage" and item.get("severity") != "advisory"],
                findings=[item for item in findings if item.get("dimension_id") == "task_spec_capability_linkage"],
                input_sources=[str(trace_file_path) if trace_file_path else trace_source],
                limitations=["Checks declared linkage presence only, not semantic adequacy."],
                not_claimed=["semantic correctness", "complete traceability", "approval"],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="evidence_reference_presence",
                name="Evidence Reference Presence",
                status="not_evaluated" if not event_count else "pass" if not [item for item in findings if item.get("dimension_id") == "evidence_reference_presence"] else "review_required",
                passed=None if not event_count else not [item for item in findings if item.get("dimension_id") == "evidence_reference_presence"],
                findings=[item for item in findings if item.get("dimension_id") == "evidence_reference_presence"],
                input_sources=[str(trace_file_path) if trace_file_path else trace_source],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="forbidden_payload_absence",
                name="Forbidden Payload Absence",
                status="not_evaluated" if trace_report is None else "pass" if not forbidden_payload_findings else "failed",
                passed=None if trace_report is None else not bool(forbidden_payload_findings),
                findings=[item for item in findings if item.get("dimension_id") == "forbidden_payload_absence"],
                input_sources=[trace_source],
                limitations=["Pattern checks are lightweight safety checks, not a full secret scanner."],
            )
        )
        dimensions.append(
            dimension(
                dimension_id="non_claim_boundary_presence",
                name="Non-Claim Boundary Presence",
                status="not_evaluated" if not event_count and trace_report is None else "pass" if not [item for item in findings if item.get("dimension_id") == "non_claim_boundary_presence"] else "review_required",
                passed=None if not event_count and trace_report is None else not [item for item in findings if item.get("dimension_id") == "non_claim_boundary_presence"],
                findings=[item for item in findings if item.get("dimension_id") == "non_claim_boundary_presence"],
                input_sources=[trace_source, str(trace_file_path) if trace_file_path else ""],
            )
        )

        not_evaluated_dimensions = [
            {
                "dimension_id": item.get("dimension_id"),
                "name": item.get("dimension_id", "").replace("_", " ").title(),
                "status": "readiness_only",
                "reason": "Behavioral/semantic grading is outside StaticGrader v1 and remains future/advisory/readiness-only.",
                "findings": [finding for finding in unsupported_findings if finding.get("dimension_id") == item.get("dimension_id")],
                "not_claimed": ["behavioral safety proof", "semantic correctness proof", "compliance/legal/regulatory proof"],
                "human_review_required": True,
            }
            for item in unsupported_findings
        ]

        summary = finding_counts(findings)
        summary["review_status_counts"] = dict(sorted(Counter(str(event.get("review_status") or "not_reviewed") for event in trace_events).items()))
        status = status_from_findings(profile, findings, no_trace_inputs)
        deterministic_results = dimensions

        return {
            "schema": REPORT_SCHEMA,
            "generated_at": utc_now_text(),
            "profile": profile,
            "status": status,
            "naos_root": naos_root,
            "project_root": str(root),
            "grader": self.name,
            "grader_version": self.version,
            "deterministic": self.deterministic,
            "advisory": self.advisory,
            "cost_posture": dict(self.cost_policy),
            "budget_posture": dict(self.cost_policy),
            "ai_surface_health_posture": ai_surface_health,
            "input_reports": input_reports,
            "input_trace_file": str(trace_file_path) if trace_file_path else None,
            "dimensions": dimensions,
            "dimension_summary": summarize_dimensions(dimensions + not_evaluated_dimensions),
            "deterministic_results": deterministic_results,
            "advisory_results": [],
            "not_evaluated_dimensions": not_evaluated_dimensions,
            "findings": findings,
            "known_gaps": [
                "Deterministic grader assessment can package StaticGrader output for audit/drift/assess review input.",
                "LLMGrader runtime and provider-backed assessment remain disabled and unimplemented.",
            ],
            "residual_risks": RESIDUAL_RISKS,
            "limitations": LIMITATIONS,
            "not_claimed": NOT_CLAIMED,
            "human_review_required": bool(findings or event_count),
            "summary": {
                **summary,
                "events": event_count,
                "valid_events": int(trace_report.get("valid_event_count") or 0) if trace_report else 0,
                "invalid_events": invalid_event_count,
                "dimensions": len(dimensions),
                "not_evaluated_dimensions": len(not_evaluated_dimensions),
                "cost_usd": 0.0,
                "ai_surface_health_posture": ai_surface_health.get("ai_surface_health_posture"),
            },
        }
