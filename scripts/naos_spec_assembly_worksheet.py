#!/usr/bin/env python3
"""Build a review-only worksheet for assembling brownfield evidence into specs.

The worksheet consumes existing NAOS adoption evidence, candidate requirements,
and traceability-gap reports, then maps available information to manifest-
declared spec files. It is deliberately non-mutating: candidates remain review
items and are not promoted into authoritative requirements.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from naos_policy import (  # noqa: E402
    default_naos_root,
    finding_counts,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

SCHEMA_ID = "naos.spec_assembly_worksheet.v1"
MANIFEST_SCHEMA_ID = "naos.spec_pack_manifest.v1"
DEFAULT_MANIFEST_NAME = "spec_manifest.yaml"
LIMITATIONS = [
    "The worksheet maps available evidence to manifest-declared spec files for human review.",
    "It does not write, fill, approve, or promote specification content.",
    "Heuristic target mapping is deterministic review evidence, not semantic proof.",
]
NOT_CLAIMED = [
    "approved requirements",
    "complete specifications",
    "correct architecture",
    "implemented behavior",
    "passing tests",
    "traceability proof",
    "standard readiness",
]


def path_text(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML file must be a mapping: {path}")
    return data


def load_json_if_present(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"status": "not_configured", "path": "", "data": {}}
    if not path.is_file():
        return {"status": "missing", "path": str(path), "data": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "unreadable", "path": str(path), "error": str(exc), "data": {}}
    if not isinstance(data, dict):
        return {"status": "invalid", "path": str(path), "data": {}}
    return {"status": "present", "path": str(path), "data": data}


def is_spec_file(filename: str) -> bool:
    return filename.endswith(".md") and len(filename) >= 3 and filename[:2].isdigit() and filename[2] == "-"


def default_manifest_candidates(root: Path) -> list[Path]:
    return [
        root / "specs" / DEFAULT_MANIFEST_NAME,
        root / "naos" / "spec_templates" / "spec-kit" / "specs" / DEFAULT_MANIFEST_NAME,
        root / "templates" / "spec-kit" / "specs" / DEFAULT_MANIFEST_NAME,
        Path(__file__).resolve().parents[1] / "templates" / "spec-kit" / "specs" / DEFAULT_MANIFEST_NAME,
    ]


def find_manifest(root: Path, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit)
        return path if path.is_absolute() else root / path
    for candidate in default_manifest_candidates(root):
        if candidate.is_file():
            return candidate
    return root / "specs" / DEFAULT_MANIFEST_NAME


def resolve_profile_manifest(profile: str, manifest: dict[str, Any]) -> list[str]:
    profiles = manifest.get("profiles") or {}
    block = profiles.get(profile) or {}
    seen: set[str] = set()
    while isinstance(block, dict) and block.get("inherits") and str(block["inherits"]) not in seen:
        inherited = str(block["inherits"])
        seen.add(inherited)
        parent = profiles.get(inherited) or {}
        required = block.get("required_files")
        if required:
            return [str(item) for item in required]
        block = parent
    return [str(item) for item in (block.get("required_files") or [])]


def report_path(root: Path, naos_root: str, policy: dict[str, Any], key: str) -> Path:
    return report_output_path(root, naos_root, policy, key)


def flatten_candidate_requirements(data: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for key in ("requirements", "candidate_requirements", "candidates", "items"):
        value = data.get(key)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))
    if not candidates and isinstance(data.get("summary"), dict):
        nested = data["summary"].get("candidate_requirements")
        if isinstance(nested, list):
            candidates.extend(item for item in nested if isinstance(item, dict))
    return candidates


def flatten_traceability_gaps(data: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for key in ("gaps", "traceability_gaps", "items", "findings"):
        value = data.get(key)
        if isinstance(value, list):
            gaps.extend(item for item in value if isinstance(item, dict))
    return gaps


def evidence_text(item: dict[str, Any]) -> str:
    values: list[str] = []
    for key in (
        "id",
        "candidate_id",
        "requirement_id",
        "type",
        "kind",
        "title",
        "name",
        "description",
        "text",
        "source",
        "source_path",
        "evidence",
        "target",
    ):
        value = item.get(key)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(part) for part in value)
        elif isinstance(value, dict):
            values.extend(str(part) for part in value.values())
    return " ".join(values).lower()


def target_spec_for_candidate(candidate: dict[str, Any]) -> str:
    text = evidence_text(candidate)
    kind = str(candidate.get("type") or candidate.get("kind") or "").upper()
    if "api" in text or "endpoint" in text or "http" in text:
        return "05-api.md"
    if "acceptance" in text or "scenario" in text or "test" in text or "ac-" in text:
        return "06-acceptance.md"
    if "cost" in text or "pricing" in text or "budget" in text:
        return "07-cost-analysis.md"
    if "market" in text or "customer" in text or "competitor" in text:
        return "08-market-analysis.md"
    if "integration" in text or "vendor" in text or "external" in text or "contract" in text:
        return "09-integration-contract.md"
    if "architecture" in text or "component" in text or "service" in text or "arch-" in text:
        return "04-architecture.md"
    if kind in {"FR", "NFR", "REQUIREMENT", "CANDIDATE_REQUIREMENT"}:
        return "03-requirements.md"
    return "03-requirements.md"


def target_spec_for_gap(gap: dict[str, Any]) -> str:
    text = evidence_text(gap)
    if "api" in text or "endpoint" in text:
        return "05-api.md"
    if "acceptance" in text or "scenario" in text or "test" in text:
        return "06-acceptance.md"
    if "cost" in text:
        return "07-cost-analysis.md"
    if "market" in text:
        return "08-market-analysis.md"
    if "integration" in text:
        return "09-integration-contract.md"
    if "architecture" in text or "arch-" in text:
        return "04-architecture.md"
    return "03-requirements.md"


def item_id(item: dict[str, Any], prefix: str, index: int) -> str:
    for key in ("id", "candidate_id", "requirement_id", "gap_id"):
        value = item.get(key)
        if value:
            return str(value)
    return f"{prefix}-{index:03d}"


def finding(
    *,
    profile: str,
    policy: dict[str, Any],
    status: str,
    category: str,
    message: str,
    path: str = "",
    advisory: bool = True,
    expected: Any = None,
    actual: Any = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": f"spec_assembly_worksheet.{status}.{path or category}",
        "severity": severity_for_profile(profile, policy, advisory=advisory),
        "status": status,
        "category": category,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        "required_next_actions": [
            "Review the mapped evidence before copying content into specs.",
            "Run spec-pack-contract after files are materialized and edited.",
        ],
    }
    if path:
        item["path"] = path
    if expected is not None:
        item["expected"] = expected
    if actual is not None:
        item["actual"] = actual
    return item


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    root = Path(args.project_root).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    specs_root = Path(args.specs_root or "specs")
    if not specs_root.is_absolute():
        specs_root = root / specs_root
    manifest_path = find_manifest(root, args.manifest).resolve()
    manifest: dict[str, Any] = {}
    required_files: list[str] = []
    findings: list[dict[str, Any]] = []

    try:
        manifest = load_yaml(manifest_path)
        if manifest.get("schema") != MANIFEST_SCHEMA_ID:
            findings.append(
                finding(
                    profile=profile,
                    policy=policy,
                    status="invalid_manifest",
                    category="manifest_contract",
                    message=f"Manifest schema must be {MANIFEST_SCHEMA_ID}.",
                    path=path_text(manifest_path, root),
                    advisory=False,
                    expected=MANIFEST_SCHEMA_ID,
                    actual=manifest.get("schema"),
                )
            )
        required_files = resolve_profile_manifest(profile, manifest)
    except Exception as exc:
        findings.append(
            finding(
                profile=profile,
                policy=policy,
                status="manifest_load_error",
                category="manifest_contract",
                message=f"Unable to load spec manifest: {exc}",
                path=path_text(manifest_path, root),
                advisory=False,
            )
        )

    evidence_inputs = {
        "existing_resource_inventory": load_json_if_present(
            report_path(root, naos_root, policy, "existing_resource_inventory_report")
        ),
        "candidate_requirements": load_json_if_present(
            report_path(root, naos_root, policy, "candidate_requirements_report")
        ),
        "traceability_gap_register": load_json_if_present(
            report_path(root, naos_root, policy, "traceability_gap_register_report")
        ),
        "brownfield_baseline": load_json_if_present(report_path(root, naos_root, policy, "brownfield_baseline_report")),
    }
    candidates = flatten_candidate_requirements(evidence_inputs["candidate_requirements"]["data"])
    gaps = flatten_traceability_gaps(evidence_inputs["traceability_gap_register"]["data"])

    candidate_rows: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates, start=1):
        candidate_rows.append(
            {
                "id": item_id(candidate, "candidate", index),
                "target_spec": target_spec_for_candidate(candidate),
                "source_type": "candidate_requirement",
                "source": candidate.get("source") or candidate.get("source_path") or "",
                "title": candidate.get("title") or candidate.get("name") or candidate.get("description") or "",
                "candidate_type": candidate.get("type") or candidate.get("kind") or "",
                "review_state": candidate.get("review_state") or "requires_human_review",
                "promoted_to_authority": False,
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )

    gap_rows: list[dict[str, Any]] = []
    for index, gap in enumerate(gaps, start=1):
        gap_rows.append(
            {
                "id": item_id(gap, "gap", index),
                "target_spec": target_spec_for_gap(gap),
                "source_type": "traceability_gap",
                "source": gap.get("source") or gap.get("source_path") or "",
                "title": gap.get("title") or gap.get("description") or gap.get("message") or "",
                "review_state": gap.get("review_state") or "requires_human_review",
                "promoted_to_authority": False,
                "human_review_required": True,
                "not_claimed": NOT_CLAIMED,
            }
        )

    spec_rows: list[dict[str, Any]] = []
    required_specs = [item for item in required_files if is_spec_file(item)]
    for rel_path in required_specs:
        target = specs_root / rel_path
        mapped_candidates = [item for item in candidate_rows if item["target_spec"] == rel_path]
        mapped_gaps = [item for item in gap_rows if item["target_spec"] == rel_path]
        present = target.is_file()
        if not present:
            assembly_state = "missing_spec_file"
            findings.append(
                finding(
                    profile=profile,
                    policy=policy,
                    status="missing_spec_file",
                    category="spec_pack_structure",
                    message=f"Manifest-required spec file is absent from the project specs root: {rel_path}",
                    path=path_text(target, root),
                    advisory=False,
                    expected=rel_path,
                )
            )
        elif mapped_candidates or mapped_gaps:
            assembly_state = "candidate_evidence_available"
        elif rel_path in {"05-api.md", "06-acceptance.md", "07-cost-analysis.md", "08-market-analysis.md", "09-integration-contract.md"}:
            assembly_state = "non_applicability_decision_needed"
            findings.append(
                finding(
                    profile=profile,
                    policy=policy,
                    status="non_applicability_decision_needed",
                    category="spec_applicability_review",
                    message=f"No mapped evidence was found for {rel_path}; record why it is not applicable or add content.",
                    path=path_text(target, root),
                    expected="reviewed applicability decision when no evidence exists",
                )
            )
        else:
            assembly_state = "ready_to_review"
        spec_rows.append(
            {
                "path": path_text(target, root),
                "filename": rel_path,
                "present": present,
                "required_by_profile": True,
                "assembly_state": assembly_state,
                "mapped_candidate_count": len(mapped_candidates),
                "mapped_gap_count": len(mapped_gaps),
                "mapped_candidate_ids": [item["id"] for item in mapped_candidates],
                "mapped_gap_ids": [item["id"] for item in mapped_gaps],
                "human_review_required": True,
            }
        )

    counts = finding_counts(findings)
    summary = {
        **counts,
        "required_spec_files": len(required_specs),
        "required_spec_files_present": sum(1 for item in spec_rows if item["present"]),
        "required_spec_files_missing": sum(1 for item in spec_rows if not item["present"]),
        "candidate_requirements": len(candidate_rows),
        "traceability_gaps": len(gap_rows),
        "specs_with_candidate_evidence": sum(
            1 for item in spec_rows if item["mapped_candidate_count"] or item["mapped_gap_count"]
        ),
        "non_applicability_decisions_needed": sum(
            1 for item in spec_rows if item["assembly_state"] == "non_applicability_decision_needed"
        ),
    }
    report = {
        "schema": SCHEMA_ID,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "profile": profile,
        "status": status_from_counts(summary),
        "project_root": str(root),
        "naos_root": naos_root,
        "specs_root": path_text(specs_root, root),
        "manifest": path_text(manifest_path, root),
        "deterministic": True,
        "summary": summary,
        "evidence_inputs": {
            key: {"status": value["status"], "path": path_text(Path(value["path"]), root)}
            for key, value in evidence_inputs.items()
        },
        "specs": spec_rows,
        "candidate_mappings": candidate_rows,
        "gap_mappings": gap_rows,
        "findings": findings,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": True,
    }
    return report, policy


def format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# NAOS Spec Assembly Worksheet",
        "",
        f"- Profile: `{report['profile']}`",
        f"- Status: `{report['status']}`",
        f"- Manifest: `{report['manifest']}`",
        f"- Required spec files present: `{report['summary']['required_spec_files_present']}/{report['summary']['required_spec_files']}`",
        f"- Candidate mappings: `{report['summary']['candidate_requirements']}`",
        f"- Traceability-gap mappings: `{report['summary']['traceability_gaps']}`",
        "",
        "This worksheet is review evidence only. It does not promote candidates into authoritative specs.",
        "",
        "## Spec Rows",
        "",
        "| Spec | Present | State | Candidates | Gaps |",
        "| --- | --- | --- | ---: | ---: |",
    ]
    for row in report["specs"]:
        lines.append(
            f"| `{row['filename']}` | `{row['present']}` | `{row['assembly_state']}` | "
            f"`{row['mapped_candidate_count']}` | `{row['mapped_gap_count']}` |"
        )
    if report["findings"]:
        lines.extend(["", "## Findings", ""])
        for item in report["findings"]:
            path = f" `{item.get('path')}`" if item.get("path") else ""
            lines.append(f"- `{item['severity']}` `{item['status']}`{path}: {item['message']}")
    lines.extend(["", "## Non-Claims", ""])
    lines.extend(f"- {item}" for item in report["not_claimed"])
    return "\n".join(lines) + "\n"


def format_text_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "NAOS Spec Assembly Worksheet",
        "=" * 40,
        f"Profile: {report['profile']}",
        f"Status: {report['status']}",
        f"Specs root: {report['specs_root']}",
        "",
        "Summary:",
        f"  Required spec files: {summary['required_spec_files']}",
        f"  Present:             {summary['required_spec_files_present']}",
        f"  Missing:             {summary['required_spec_files_missing']}",
        f"  Candidate mappings:  {summary['candidate_requirements']}",
        f"  Gap mappings:        {summary['traceability_gaps']}",
        f"  Applicability decisions needed: {summary['non_applicability_decisions_needed']}",
        f"  Findings:            {summary['total_findings']}",
    ]
    if report["findings"]:
        lines.extend(["", "Findings:"])
        for item in report["findings"]:
            location = f" ({item.get('path')})" if item.get("path") else ""
            lines.append(f"  - [{item['severity']}] {item['status']}{location}: {item['message']}")
    lines.extend(["", "Non-claims:"])
    lines.extend(f"  - {item}" for item in report["not_claimed"])
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a review-only spec assembly worksheet from adoption evidence.")
    parser.add_argument("project_root", nargs="?", default=".", help="Project root to inspect.")
    parser.add_argument("--profile", help="Governance profile (quickstart/lite/standard/assured).")
    parser.add_argument("--specs-root", default=os.environ.get("SPECS_ROOT") or "specs", help="Project specs root.")
    parser.add_argument("--manifest", help="Optional explicit spec_manifest.yaml path.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="NAOS governance root.")
    parser.add_argument("--policy", help="Optional policy YAML path.")
    parser.add_argument("--output", help="Optional JSON output report path.")
    parser.add_argument("--write-markdown", action="store_true", help="Also write a Markdown worksheet.")
    parser.add_argument("--markdown-output", help="Optional Markdown worksheet output path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, policy = build_report(args)
    root = Path(args.project_root).resolve()
    output = Path(args.output) if args.output else report_output_path(root, report["naos_root"], policy, "spec_assembly_worksheet_report")
    write_report(output, report)
    if args.write_markdown:
        markdown_output = (
            Path(args.markdown_output)
            if args.markdown_output
            else output.with_name(output.stem.replace("_worksheet", "_worksheet") + ".md")
        )
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(format_markdown(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(format_text_report(report))
        print(f"report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
