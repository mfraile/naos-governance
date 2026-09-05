#!/usr/bin/env python3
"""Validate roadmap and recommendation crosswalk evidence."""

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
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    should_ignore_path,
    status_from_counts,
    write_report,
)

IMPLEMENTED_STATES = {"implemented", "shipped", "done", "complete", "completed"}
VALID_STATES = IMPLEMENTED_STATES | {"planned", "gated", "rejected", "deferred", "experimental"}
ID_PATTERN = re.compile(r"\b(?:REC|GOV|WI|Q|S|T|FR|NFR|REQ)-[A-Z0-9][A-Z0-9_.-]*\b")


def collect_ids_from_text(path: Path) -> set[str]:
    if not path.exists() or not path.is_file():
        return set()
    return set(ID_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace")))


def collect_ids(paths: list[str], policy: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for raw in paths:
        path = Path(raw)
        if should_ignore_path(path, policy):
            continue
        if path.is_file():
            ids.update(collect_ids_from_text(path))
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if (
                    candidate.suffix.lower() in {".md", ".yaml", ".yml", ".json"}
                    and not should_ignore_path(candidate, policy)
                ):
                    ids.update(collect_ids_from_text(candidate))
    return ids


def load_crosswalk(path: Path | None) -> tuple[list[dict[str, Any]], str | None]:
    if path is None or not path.exists():
        return [], None
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    elif path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        return parse_markdown_crosswalk(path), str(path)

    entries: list[dict[str, Any]] = []
    if isinstance(data, list):
        entries = [entry for entry in data if isinstance(entry, dict)]
    elif isinstance(data, dict):
        for key in ("items", "recommendations", "roadmap", "crosswalk"):
            value = data.get(key)
            if isinstance(value, list):
                entries.extend(entry for entry in value if isinstance(entry, dict))
        for key, value in data.items():
            if isinstance(value, dict) and ID_PATTERN.fullmatch(str(key)):
                entry = {"id": str(key)}
                entry.update(value)
                entries.append(entry)
    return entries, str(path)


def parse_markdown_crosswalk(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ids = ID_PATTERN.findall(line)
        if not ids:
            continue
        state = ""
        for candidate in VALID_STATES:
            if re.search(rf"\b{re.escape(candidate)}\b", line, re.IGNORECASE):
                state = candidate
                break
        entries.append({"id": ids[0], "status": state or "candidate", "line": line.strip()})
    return entries


def find_default_crosswalk(root: Path, naos_root: str) -> Path | None:
    candidates = [
        root / naos_root / "roadmap_crosswalk.yaml",
        root / naos_root / "roadmap_crosswalk.yml",
        root / naos_root / "roadmap_crosswalk.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    intake = root / "dev" / "assessment_intake"
    if intake.exists():
        matches = sorted(intake.glob("*CROSSWALK*"))
        if matches:
            return matches[0]
    return None


def evidence_exists(root: Path, evidence: Any) -> bool:
    if isinstance(evidence, str):
        return (root / evidence).exists() or Path(evidence).exists()
    if isinstance(evidence, list):
        return any(evidence_exists(root, item) for item in evidence)
    if isinstance(evidence, dict):
        ref = evidence.get("path") or evidence.get("file") or evidence.get("url")
        if not ref:
            return False
        if str(ref).startswith(("http://", "https://")):
            return evidence.get("verified") is True
        return evidence_exists(root, str(ref))
    return False


def validate(
    root: Path,
    profile: str,
    crosswalk_entries: list[dict[str, Any]],
    crosswalk_file: str | None,
    roadmap_ids: set[str],
    referenced_ids: set[str],
    policy: dict[str, Any],
    naos_root: str,
) -> dict[str, Any]:
    severity = "advisory" if is_kit_repository(root, naos_root) and not crosswalk_entries else severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    mapped_ids = {str(entry.get("id")) for entry in crosswalk_entries if entry.get("id")}

    if not crosswalk_entries and not roadmap_ids and not referenced_ids:
        findings.append(
            {
                "id": "ROADMAP-NOT-CONFIGURED",
                "severity": severity,
                "status": "not_configured",
                "message": "No roadmap/crosswalk sources configured.",
            }
        )

    for entry in crosswalk_entries:
        item_id = str(entry.get("id") or "unknown")
        state = str(entry.get("status") or entry.get("state") or "candidate").lower()
        if state not in VALID_STATES and state != "candidate":
            findings.append(
                {
                    "id": item_id,
                    "severity": "warning",
                    "status": "invalid_state",
                    "message": f"Unknown crosswalk status: {state}",
                }
            )
        if state in IMPLEMENTED_STATES and not evidence_exists(root, entry.get("evidence")):
            findings.append(
                {
                    "id": item_id,
                    "severity": severity,
                    "status": "implemented_without_evidence",
                    "message": "Item is marked implemented/shipped without existing evidence.",
                }
            )

    missing_from_roadmap = sorted(referenced_ids - roadmap_ids) if roadmap_ids else []
    for item_id in missing_from_roadmap:
        findings.append(
            {
                "id": item_id,
                "severity": severity,
                "status": "referenced_id_not_in_roadmap",
                "message": "Referenced ID is not present in configured roadmap sources.",
            }
        )

    unmapped = sorted((roadmap_ids | referenced_ids) - mapped_ids) if mapped_ids else []
    for item_id in unmapped:
        findings.append(
            {
                "id": item_id,
                "severity": "warning" if profile in {"quickstart", "lite"} else severity,
                "status": "unmapped_id",
                "message": "Roadmap/recommendation ID is not mapped in the configured crosswalk.",
            }
        )

    summary = finding_counts(findings)
    status = status_from_counts(summary)

    return {
        "schema": "naos.roadmap_crosswalk_validation.v1",
        "profile": profile,
        "status": status,
        "crosswalk_file": crosswalk_file,
        "summary": summary,
        "counts": {
            "crosswalk_entries": len(crosswalk_entries),
            "roadmap_ids": len(roadmap_ids),
            "referenced_ids": len(referenced_ids),
        },
        "findings": findings,
        "limitations": [
            "Validation applies only to configured roadmap and crosswalk sources.",
            "Implemented or shipped status requires local evidence references.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate NAOS roadmap/crosswalk evidence.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--crosswalk-file")
    parser.add_argument("--roadmap-file", action="append", default=[])
    parser.add_argument("--scan-path", action="append", default=[])
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or str(policy.get("paths", {}).get("default_naos_root") or "naos")
    profile = normalize_profile(args.profile, policy)
    crosswalk_path = Path(args.crosswalk_file) if args.crosswalk_file else find_default_crosswalk(root, naos_root)
    entries, crosswalk_file = load_crosswalk(crosswalk_path)
    roadmap_ids = collect_ids(args.roadmap_file, policy)
    referenced_ids = collect_ids(args.scan_path, policy)
    report = validate(root, profile, entries, crosswalk_file, roadmap_ids, referenced_ids, policy, naos_root)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "roadmap_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS roadmap/crosswalk validation: {report['status']} ({report['summary']['total_findings']} findings)")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
