#!/usr/bin/env python3
"""Compose explicit NAOS task, spec, source, test, and completion links.

This reporter consumes deterministic file-first artifacts. It does not infer
semantic links, run a graph database, or claim coverage sufficiency.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    test_map_output_path,
    write_report,
)
from naos_task_lifecycle import (  # noqa: E402
    is_task_delivered,
    load_completed_history,
    load_registry,
    normalize_task_id,
    normalize_task_states,
    task_review_posture,
)


REPORT_SCHEMA = "naos.composed_traceability.v1"
TRACEABILITY_REVIEW_SOURCE = "composed_traceability"
AGGREGATE_REVIEW_SOURCE = "composed_traceability_aggregate"
REQ_RE = re.compile(r"(?<![A-Z0-9-])(?:FR|NFR)-[A-Z0-9-]+(?![A-Z0-9-])")


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def normalized_path(root: Path, value: Any) -> str:
    if str(value or "").startswith("naos_root:"):
        return str(value)
    path = Path(str(value or ""))
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def history_reference_path(root: Path, naos_root: str, reference: str) -> Path | None:
    value, _, _ = str(reference or "").partition("#")
    if value.startswith("naos_root:"):
        relative = Path(value.removeprefix("naos_root:"))
        base = Path(naos_root)
        base = base if base.is_absolute() else root / base
    else:
        relative = Path(value)
        base = root
    if relative.is_absolute() or ".." in relative.parts:
        return None
    resolved = (base.resolve(strict=False) / relative).resolve(strict=False)
    try:
        resolved.relative_to(base.resolve(strict=False))
    except ValueError:
        return None
    return resolved


def requirement_refs(entry: dict[str, Any]) -> list[str]:
    values = entry.get("requirements") or entry.get("requirement") or []
    text = " ".join(str(item) for item in values) if isinstance(values, list) else str(values)
    return list(dict.fromkeys(REQ_RE.findall(text.upper())))


def completion_record_for(history: dict[str, Any], task_id: str) -> dict[str, Any] | None:
    for record in history.get("records") or []:
        if not isinstance(record, dict):
            continue
        try:
            if normalize_task_id(record.get("task_id")) == task_id:
                return record
        except ValueError:
            continue
    return None


def traceability_review_reason(finding: dict[str, Any]) -> str:
    finding_id = str(finding.get("id") or "composed_traceability.unknown")
    reason = finding_id.removeprefix("composed_traceability.")
    raw_task_id = finding.get("task_id")
    if raw_task_id and reason != "invalid_task_id":
        try:
            task_id = normalize_task_id(raw_task_id)
        except ValueError:
            task_id = None
        if task_id:
            return f"traceability:{task_id}:{reason}"
    return f"traceability:{reason}"


def load_decision_record(root: Path, naos_root: str, reference: str) -> dict[str, Any] | None:
    path = history_reference_path(root, naos_root, reference)
    if path is None or not path.is_file():
        return None
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def attributable_decision(
    record: dict[str, Any] | None,
    *,
    task_id: str,
    evidence_refs: set[str],
    root: Path | None = None,
    naos_root: str = "naos",
) -> bool:
    if not record or record.get("schema") != "naos.human_decision_record.v1":
        return False
    if task_id not in {str(item).upper() for item in record.get("subject_refs") or []}:
        return False
    record_evidence = {str(item) for item in record.get("evidence_refs") or []}
    if root is not None:
        supplied_identities = {
            str(path.resolve(strict=False))
            for reference in evidence_refs
            for path in [history_reference_path(root, naos_root, reference)]
            if path is not None and path.is_file()
        }
        record_identities = {
            str(path.resolve(strict=False))
            for reference in record_evidence
            for path in [history_reference_path(root, naos_root, reference)]
            if path is not None and path.is_file()
        }
        evidence_linked = bool(supplied_identities.intersection(record_identities))
    else:
        evidence_linked = bool(evidence_refs.intersection(record_evidence))
    return bool(
        str(record.get("decided_by") or "").strip()
        and str(record.get("decided_at") or "").strip()
        and record.get("outcome") in {"approved", "rejected", "deferred"}
        and evidence_linked
    )


def build_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    module_header_report_path: Path,
    test_map_path: Path,
    ac_report_path: Path,
) -> dict[str, Any]:
    registry, registry_path = load_registry(root, naos_root)
    history, history_path = load_completed_history(root, naos_root)
    module_report = load_json(module_header_report_path)
    test_report = load_json(test_map_path)
    ac_report = load_json(ac_report_path)

    source_by_task: dict[str, list[dict[str, Any]]] = {}
    if module_report:
        for source in module_report.get("scanned_files") or []:
            if not isinstance(source, dict):
                continue
            for raw_task_id in source.get("task_ids") or []:
                try:
                    task_id = normalize_task_id(raw_task_id)
                except ValueError:
                    continue
                source_by_task.setdefault(task_id, []).append(source)

    tests_by_source: dict[str, dict[str, Any]] = {}
    if test_report:
        for mapping in test_report.get("mappings") or []:
            if not isinstance(mapping, dict):
                continue
            source_path = normalized_path(root, mapping.get("source"))
            tests_by_source[source_path] = mapping

    chains: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for entry in registry.get("tasks") or []:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        try:
            task_id = normalize_task_id(entry.get("id"))
        except ValueError as exc:
            findings.append({"id": "composed_traceability.invalid_task_id", "task_id": entry.get("id"), "message": str(exc)})
            continue
        states = normalize_task_states(entry)
        if states.get("compatibility_status") == "unsupported":
            findings.append(
                {
                    "id": "composed_traceability.unsupported_legacy_status",
                    "task_id": task_id,
                    "status": "unsupported_legacy_status",
                    "message": (
                        f"Legacy status {states.get('legacy_status')!r} is unsupported and cannot be "
                        "credited as a normal lifecycle state."
                    ),
                }
            )
        source_links: list[dict[str, Any]] = []
        for source in source_by_task.get(task_id, []):
            source_path = normalized_path(root, source.get("path"))
            test_mapping = tests_by_source.get(source_path) or {}
            source_links.append(
                {
                    "path": source_path,
                    "spec_refs": list(source.get("spec_refs") or []),
                    "requirement_ids": list(source.get("requirement_ids") or []),
                    "tests": [normalized_path(root, item.get("path")) for item in test_mapping.get("tests") or [] if isinstance(item, dict)],
                    "test_verification": [
                        {
                            "path": normalized_path(root, item.get("path")),
                            "state": item.get("verification_state") or item.get("status") or ("verified" if item.get("executed") is True else "structurally_declared"),
                        }
                        for item in test_mapping.get("tests") or []
                        if isinstance(item, dict)
                    ],
                    "coverage_supports_source": test_mapping.get("coverage_supports_source", "unknown"),
                    "mapped": bool(test_mapping.get("mapped")),
                }
            )
        completed = completion_record_for(history, task_id)
        canonical_review = task_review_posture(
            states,
            completion_record=completed,
            resolution_status=(
                "unsupported_legacy_status"
                if states.get("compatibility_status") == "unsupported"
                else None
            ),
        )
        delivered = is_task_delivered(entry)
        task_requirements = requirement_refs(entry)
        completion_required = states["lifecycle_state"] == "completed" or delivered
        mapped_test_refs = {
            normalized_path(root, test_ref)
            for source_link in source_links
            for test_ref in source_link["tests"]
        }
        history_test_refs = {
            normalized_path(root, test_ref)
            for test_ref in (completed or {}).get("test_references") or []
        }
        evidence_refs = [
            normalized_path(root, evidence_ref)
            for evidence_ref in (completed or {}).get("evidence_references") or []
        ]
        decision_refs = [
            normalized_path(root, decision_ref)
            for decision_ref in (completed or {}).get("decision_references") or []
        ]
        decision_records = [
            {
                "reference": decision_ref,
                "record": load_decision_record(root, naos_root, decision_ref),
            }
            for decision_ref in decision_refs
        ]
        attributable_records = [
            item
            for item in decision_records
            if attributable_decision(
                item["record"],
                task_id=task_id,
                evidence_refs=set(evidence_refs),
                root=root,
                naos_root=naos_root,
            )
        ]
        admitted_records = [
            item
            for item in attributable_records
            if item["record"].get("decision_type") == "evidence_admission"
            and item["record"].get("outcome") == "approved"
        ]
        source_paths_verified = bool(source_links) and all((root / link["path"]).is_file() for link in source_links)
        test_entries = [item for link in source_links for item in link["test_verification"]]
        tests_structurally_present = bool(test_entries) and all((root / item["path"]).is_file() for item in test_entries)
        tests_verified = tests_structurally_present and all(
            str(item["state"]).lower() in {"verified", "passed", "pass"} for item in test_entries
        )
        completion_links = {
            "mapped_test_references": sorted(mapped_test_refs),
            "completed_test_references": sorted(history_test_refs),
            "evidence_references": evidence_refs,
            "decision_references": decision_refs,
            "decision_records": decision_records,
        }
        link_checks = {
            "task_to_requirement": bool(task_requirements),
            "task_to_source": bool(source_links),
            "source_to_test": bool(source_links) and all(link["mapped"] and link["tests"] for link in source_links),
            "delivered_task_to_completion_history": bool(completed) if completion_required else None,
            "test_to_evidence": (
                bool(completed)
                and bool(mapped_test_refs & history_test_refs)
                and bool(evidence_refs)
            ) if completion_required else None,
            "evidence_to_decision": (
                bool(completed)
                and bool(evidence_refs)
                and bool(attributable_records)
            ) if completion_required else None,
        }
        relationship_states = {
            name: ("not_applicable" if value is None else "present" if value is True else "missing")
            for name, value in link_checks.items()
        }
        if link_checks["source_to_test"] is False and source_links:
            relationship_states["source_to_test"] = "unresolved"
        if link_checks["test_to_evidence"] is False and completed and (mapped_test_refs or history_test_refs or evidence_refs):
            relationship_states["test_to_evidence"] = "unresolved"
        if link_checks["evidence_to_decision"] is False and decision_refs:
            relationship_states["evidence_to_decision"] = "unresolved"
        qualifications = {
            "structurally_declared": all(value is True for value in link_checks.values() if value is not None),
            "source_verification": "source_verified" if source_paths_verified else ("unresolved" if source_links else "missing"),
            "test_verification": "test_verified" if tests_verified else ("structurally_declared" if tests_structurally_present else "missing"),
            "evidence_admission": "admitted" if admitted_records else ("candidate_only" if evidence_refs else "missing"),
            "attributable_decision": "recorded" if attributable_records else ("unresolved" if decision_refs else "missing"),
            "semantic_correctness_claimed": False,
        }
        if not qualifications["structurally_declared"]:
            qualification_level = "gaps_present"
        elif (
            qualifications["source_verification"] == "source_verified"
            and qualifications["test_verification"] == "test_verified"
            and qualifications["evidence_admission"] == "admitted"
            and qualifications["attributable_decision"] == "recorded"
        ):
            qualification_level = "admitted_attributable_chain"
        else:
            qualification_level = "structural_only"
        complete = all(value is True for value in link_checks.values() if value is not None)
        chains.append(
            {
                "task_id": task_id,
                "title": entry.get("title"),
                "lifecycle_state": states["lifecycle_state"],
                "delivery_state": states["delivery_state"],
                "verification_state": states["verification_state"],
                "requirement_refs": task_requirements,
                "source_links": source_links,
                "completed_history": completed,
                "completion_links": completion_links,
                "link_checks": link_checks,
                "relationship_states": relationship_states,
                "qualifications": qualifications,
                "qualification_level": qualification_level,
                "composed_chain_status": "complete" if complete else "gap",
                "canonical_task_review": canonical_review,
            }
        )
        for link_name, value in link_checks.items():
            if value is False:
                findings.append(
                    {
                        "id": f"composed_traceability.{link_name}",
                        "task_id": task_id,
                        "status": "gap",
                        "message": f"Explicit composed traceability link is missing: {link_name}.",
                    }
                )

    input_status = {
        "task_registry": {"path": str(registry_path), "status": "present" if registry_path.is_file() else "missing"},
        "completed_history": {"path": str(history_path), "status": "present" if history_path.is_file() else "missing"},
        "module_header_traceability": {"path": str(module_header_report_path), "status": "present" if module_report else "missing_or_invalid"},
        "source_to_test_map": {"path": str(test_map_path), "status": "present" if test_report else "missing_or_invalid"},
        "ac_completion_evidence": {"path": str(ac_report_path), "status": "present" if ac_report else "missing_or_invalid"},
    }
    missing_input_names = [name for name, item in input_status.items() if item["status"] != "present"]
    missing_inputs = len(missing_input_names)
    complete_chains = sum(1 for chain in chains if chain["composed_chain_status"] == "complete")
    tasks_requiring_review = [
        {
            "task_id": chain["task_id"],
            "review_reasons": list(chain["canonical_task_review"]["review_reasons"]),
        }
        for chain in chains
        if chain["canonical_task_review"]["human_review_required"]
    ]
    canonical_task_review = {
        "human_review_required": bool(tasks_requiring_review),
        "tasks_requiring_review": tasks_requiring_review,
        "review_posture_source": "canonical_task_lifecycle",
    }
    traceability_review_reasons = list(
        dict.fromkeys(
            [traceability_review_reason(finding) for finding in findings]
            + [f"traceability:missing_input:{name}" for name in missing_input_names]
        )
    )
    traceability_review = {
        "human_review_required": bool(traceability_review_reasons),
        "review_reasons": traceability_review_reasons,
        "finding_ids": list(dict.fromkeys(str(finding.get("id")) for finding in findings)),
        "missing_inputs": missing_input_names,
        "review_posture_source": TRACEABILITY_REVIEW_SOURCE,
    }
    aggregate_review_reasons = list(
        dict.fromkeys(
            [
                f"task:{item['task_id']}:{reason}"
                for item in tasks_requiring_review
                for reason in item["review_reasons"]
            ]
            + traceability_review_reasons
        )
    )
    human_review_required = bool(
        canonical_task_review["human_review_required"]
        or traceability_review["human_review_required"]
    )
    status = "not_configured" if not chains else ("pass" if not findings and not missing_inputs else "mapped_with_gaps")
    return {
        "schema": REPORT_SCHEMA,
        "profile": profile,
        "status": status,
        "project_root": str(root),
        "naos_root": naos_root,
        "inputs": input_status,
        "summary": {
            "tasks": len(chains),
            "complete_chains": complete_chains,
            "chains_with_gaps": len(chains) - complete_chains,
            "missing_inputs": missing_inputs,
            "total_findings": len(findings),
            "advisory": len(findings),
            "warning": 0,
            "required": 0,
            "blocking": 0,
            "canonical_tasks_requiring_review": len(tasks_requiring_review),
            "traceability_findings_requiring_review": len(findings),
            "human_review_required": human_review_required,
        },
        "chains": chains,
        "findings": findings,
        "ac_completion_summary": (ac_report or {}).get("summary"),
        "canonical_task_review": canonical_task_review,
        "traceability_review": traceability_review,
        "human_review_required": human_review_required,
        "review_reasons": aggregate_review_reasons,
        "review_posture_source": AGGREGATE_REVIEW_SOURCE,
        "limitations": [
            "Only explicit task ids, requirement ids, module-header refs, test-map refs, and co-recorded completion-history test/evidence/decision refs are composed.",
            "Missing reports remain gaps; no semantic or probabilistic link is inferred.",
            "Mapped links do not prove correctness, test sufficiency, AC satisfaction, or complete traceability.",
        ],
        "not_claimed": [
            "semantic graph or vector retrieval",
            "implementation correctness",
            "test sufficiency or effectiveness",
            "merge, release, or evidence-admission authority",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compose explicit NAOS traceability links.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--module-header-report", type=Path)
    parser.add_argument("--test-map", type=Path)
    parser.add_argument("--ac-report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    module_path = args.module_header_report or report_default_path(root, naos_root, policy, "module_header_traceability_report")
    test_path = args.test_map or test_map_output_path(root, naos_root, policy) or (root / naos_root / "test_evidence" / "source_to_test_map.json")
    ac_path = args.ac_report or report_default_path(root, naos_root, policy, "ac_completion_evidence_report")
    report = build_report(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        module_header_report_path=module_path,
        test_map_path=test_path,
        ac_report_path=ac_path,
    )
    output = args.output or report_output_path(root, naos_root, policy, "composed_traceability_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS composed traceability ({profile}): {report['status']}")
        print(f"chains: {report['summary']['complete_chains']}/{report['summary']['tasks']}")
        print(f"report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
