#!/usr/bin/env python3
"""Validate NAOS spec-pack template contract conformance.

This deterministic checker validates file names, required sections, anchor
patterns, and sync markers declared in ``spec_manifest.yaml``. Filled mode also
reports unresolved ``[ADAPT]`` placeholders. The report is structural review
evidence only; it does not approve specs or prove requirement completeness,
implementation, testing, evidence, certification, or compliance.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)
import spec_header  # noqa: E402

SCHEMA_ID = "naos.spec_pack_contract.v1"
MANIFEST_SCHEMA_ID = "naos.spec_pack_manifest.v1"
DEFAULT_TEMPLATE_SPECS_ROOT = Path("templates/spec-kit/specs")
DEFAULT_PROJECT_SPECS_ROOT = Path("specs")
DEFAULT_MANIFEST_NAME = "spec_manifest.yaml"
PLACEHOLDER_RE = re.compile(r"\[(?:ADAPT|TODO|TBD)(?:[:\]\s])", re.IGNORECASE)

LIMITATIONS = [
    "Spec-pack contract validation is deterministic structural review evidence only.",
    "It does not verify requirement correctness, implementation coverage, test behavior, runtime behavior, approval, certification, or compliance.",
    "Filled mode reports unresolved placeholders but still requires human review for durable acceptance.",
]
NOT_CLAIMED = [
    "approved specifications",
    "complete requirements",
    "correct architecture",
    "implemented behavior",
    "passing tests",
    "evidence-backed acceptance",
    "compliance proof",
]


def path_text(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def default_specs_root(root: Path) -> Path:
    if (root / DEFAULT_PROJECT_SPECS_ROOT).is_dir():
        return DEFAULT_PROJECT_SPECS_ROOT
    return DEFAULT_TEMPLATE_SPECS_ROOT


def is_spec_file(filename: str) -> bool:
    return filename.endswith(".md") and len(filename) >= 3 and filename[:2].isdigit() and filename[2] == "-"


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML file must be a mapping: {path}")
    return data


def normalize_token(value: str) -> str:
    token = str(value).strip()
    token = token.strip("`.,;:()[]{}")
    if token.startswith("#"):
        token = token[1:]
    return token.upper()


def is_placeholder_token(value: str) -> bool:
    token = normalize_token(value)
    return "XXX" in token or token.endswith(("-N", ".N", "-M", ".M"))


def profile_applies(profile: str, required_profiles: list[Any] | None) -> bool:
    return profile in {str(item) for item in required_profiles or []}


def extract_pattern_tokens(text: str, patterns: list[Any]) -> set[str]:
    tokens: set[str] = set()
    for pattern_rule in patterns or []:
        pattern = str(pattern_rule if isinstance(pattern_rule, str) else pattern_rule.get("pattern") or "")
        if not pattern:
            continue
        flags = compile_flags(pattern_rule.get("flags") if isinstance(pattern_rule, dict) else None)
        try:
            compiled = re.compile(pattern, flags)
        except re.error:
            continue
        for match in compiled.finditer(text):
            if match.groups():
                raw = match.group(1)
            else:
                raw = match.group(0)
            token = normalize_token(raw)
            if token and not is_placeholder_token(token):
                tokens.add(token)
    return tokens


def task_registry_candidates(root: Path, policy: dict[str, Any]) -> list[Path]:
    naos_root = Path(str(default_naos_root(policy)))
    candidates = [root / naos_root / "TASK_REGISTRY.yaml"]
    candidates.append(root / "TASK_REGISTRY.yaml")
    candidates.append(root / "templates" / "structural-seeds" / "naos" / "TASK_REGISTRY.yaml")
    return candidates


def load_task_ids(root: Path, policy: dict[str, Any]) -> tuple[set[str], str | None]:
    for candidate in task_registry_candidates(root, policy):
        if not candidate.is_file():
            continue
        try:
            data = load_yaml(candidate)
        except Exception:
            return set(), str(candidate)
        tasks = data.get("tasks", data)
        ids: set[str] = set()
        if isinstance(tasks, list):
            for item in tasks:
                if isinstance(item, dict) and item.get("id"):
                    ids.add(normalize_token(str(item["id"])))
        elif isinstance(tasks, dict):
            for key, item in tasks.items():
                if isinstance(item, dict):
                    ids.add(normalize_token(str(item.get("id") or key)))
        return ids, str(candidate)
    return set(), None


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


def compile_flags(values: list[str] | None) -> int:
    flags = 0
    for value in values or []:
        normalized = str(value).lower()
        if normalized == "multiline":
            flags |= re.MULTILINE
        elif normalized == "dotall":
            flags |= re.DOTALL
        elif normalized == "ignorecase":
            flags |= re.IGNORECASE
    return flags


def collect_traceability_definitions(
    *,
    root: Path,
    specs_root: Path,
    code_rule: dict[str, Any],
    required_set: set[str],
    policy: dict[str, Any],
) -> tuple[set[str], str | None]:
    source = str(code_rule.get("definition_source") or "patterns")
    if source == "task_registry":
        return load_task_ids(root, policy)

    definitions: set[str] = set()
    for rel_path in [str(item) for item in code_rule.get("defined_in") or []]:
        if rel_path not in required_set:
            continue
        path = specs_root / rel_path
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if source == "requirement_headers":
            definitions.update(spec_header.canonical_frs(text))
        else:
            definitions.update(extract_pattern_tokens(text, code_rule.get("definition_patterns") or []))
    return definitions, None


def collect_traceability_references(
    *,
    specs_root: Path,
    code_rule: dict[str, Any],
    required_set: set[str],
) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    patterns = code_rule.get("reference_patterns") or []
    if not patterns:
        return references
    for rel_path in [str(item) for item in code_rule.get("reference_files") or []]:
        if rel_path not in required_set:
            continue
        path = specs_root / rel_path
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        tokens = extract_pattern_tokens(text, patterns)
        for token in sorted(tokens):
            references.append({"path": rel_path, "token": token})
    return references


def finding(
    *,
    profile: str,
    policy: dict[str, Any],
    status: str,
    category: str,
    message: str,
    path: str = "",
    rule_id: str = "",
    expected: Any = None,
    actual: Any = None,
    advisory: bool = False,
) -> dict[str, Any]:
    item = {
        "id": f"spec_pack_contract.{status}.{rule_id or path or 'manifest'}",
        "severity": severity_for_profile(profile, policy, advisory=advisory),
        "status": status,
        "category": category,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
    }
    if path:
        item["path"] = path
    if rule_id:
        item["rule_id"] = rule_id
    if expected is not None:
        item["expected"] = expected
    if actual is not None:
        item["actual"] = actual
    item["required_next_actions"] = [
        "Restore the manifest-declared spec-pack structure or record a reviewed exception.",
        "Re-run spec-pack contract validation after remediation.",
    ]
    return item


def validate_manifest_shape(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != MANIFEST_SCHEMA_ID:
        errors.append(f"schema must be {MANIFEST_SCHEMA_ID}")
    if not isinstance(manifest.get("profiles"), dict):
        errors.append("profiles must be a mapping")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        errors.append("files must be a non-empty list")
    else:
        for index, spec in enumerate(files):
            if not isinstance(spec, dict):
                errors.append(f"files[{index}] must be a mapping")
                continue
            for key in ("id", "path", "title", "required_profiles"):
                if key not in spec:
                    errors.append(f"files[{index}] missing {key}")
    return errors


def validate_contract(
    *,
    root: Path,
    specs_root: Path,
    manifest_path: Path,
    profile: str,
    policy: dict[str, Any],
    mode: str,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    traceability_codes: list[dict[str, Any]] = []
    expected_files: list[str] = []
    manifest: dict[str, Any] = {}
    manifest_limitations = LIMITATIONS
    manifest_not_claimed = NOT_CLAIMED

    if profile == "quickstart" and not manifest_path.exists():
        summary = {
            **finding_counts([]),
            "files_expected": 0,
            "files_present": 0,
            "files_missing": 0,
            "contract_files_expected": 0,
            "contract_files_present": 0,
            "contract_files_missing": 0,
            "spec_files_expected": 0,
            "spec_files_present": 0,
            "spec_files_missing": 0,
            "support_files_expected": 0,
            "support_files_present": 0,
            "support_files_missing": 0,
            "files_not_applicable": 0,
            "files_not_applicable_present": 0,
            "files_not_applicable_missing": 0,
            "section_findings": 0,
            "pattern_findings": 0,
            "marker_findings": 0,
            "placeholder_findings": 0,
            "traceability_codes_required": 0,
            "traceability_codes_not_applicable": 0,
            "traceability_reference_findings": 0,
        }
        return {
            "schema": SCHEMA_ID,
            "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "profile": profile,
            "status": status_from_counts(summary),
            "mode": mode,
            "project_root": str(root),
            "naos_root": str(default_naos_root(policy)),
            "specs_root": path_text(specs_root, root),
            "manifest": path_text(manifest_path, root),
            "deterministic": True,
            "summary": summary,
            "findings": [],
            "files": [],
            "traceability_codes": [],
            "limitations": manifest_limitations
            + ["Quickstart does not require spec-pack files unless the project adds specs and a manifest."],
            "not_claimed": manifest_not_claimed,
            "human_review_required": True,
        }

    try:
        manifest = load_yaml(manifest_path)
        manifest_limitations = [str(item) for item in manifest.get("limitations") or LIMITATIONS]
        manifest_not_claimed = [str(item) for item in manifest.get("not_claimed") or NOT_CLAIMED]
        shape_errors = validate_manifest_shape(manifest)
        for index, error in enumerate(shape_errors, start=1):
            findings.append(
                finding(
                    profile=profile,
                    policy=policy,
                    status="invalid_manifest",
                    category="manifest_contract",
                    message=error,
                    path=path_text(manifest_path, root),
                    rule_id=f"manifest_shape_{index}",
                )
            )
    except Exception as exc:
        findings.append(
            finding(
                profile=profile,
                policy=policy,
                status="manifest_load_error",
                category="manifest_contract",
                message=f"Unable to load spec manifest: {exc}",
                path=path_text(manifest_path, root),
                rule_id="manifest_load",
            )
        )

    if manifest and not any(item["status"] in {"manifest_load_error", "invalid_manifest"} for item in findings):
        expected_files = resolve_profile_manifest(profile, manifest)
        required_set = set(expected_files)
        file_rules = [item for item in manifest.get("files") or [] if isinstance(item, dict)]
        file_rule_by_path = {str(item.get("path") or ""): item for item in file_rules}
        for expected in expected_files:
            path = specs_root / expected
            present = path.is_file()
            rule = file_rule_by_path.get(expected) or {}
            files.append(
                {
                    "path": path_text(path, root),
                    "filename": expected,
                    "kind": "spec" if is_spec_file(expected) else "support",
                    "required": True,
                    "present": present,
                    "applicability": "required_by_profile",
                    "title": rule.get("title"),
                    "required_profiles": rule.get("required_profiles") or [profile],
                }
            )
            if not present:
                findings.append(
                    finding(
                        profile=profile,
                        policy=policy,
                        status="missing_file",
                        category="file_manifest",
                        message=f"Required spec-pack file is missing: {expected}",
                        path=path_text(path, root),
                        rule_id=expected,
                        expected=expected,
                    )
                )

        for spec in file_rules:
            rel_path = str(spec.get("path") or "")
            if rel_path and rel_path not in required_set:
                path = specs_root / rel_path
                files.append(
                    {
                        "path": path_text(path, root),
                        "filename": rel_path,
                        "kind": "spec" if is_spec_file(rel_path) else "support",
                        "required": False,
                        "present": path.is_file(),
                        "applicability": "not_applicable_by_profile",
                        "title": spec.get("title"),
                        "required_profiles": spec.get("required_profiles") or [],
                    }
                )

        for spec in file_rules:
            rel_path = str(spec.get("path") or "")
            if rel_path not in required_set:
                continue
            path = specs_root / rel_path
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")

            for section in spec.get("required_sections") or []:
                if str(section) not in text:
                    findings.append(
                        finding(
                            profile=profile,
                            policy=policy,
                            status="missing_section",
                            category="section_contract",
                            message=f"{rel_path} is missing required section text: {section}",
                            path=path_text(path, root),
                            rule_id=f"{rel_path}:section:{section}",
                            expected=section,
                        )
                    )

            for marker in spec.get("required_markers") or []:
                if str(marker) not in text:
                    findings.append(
                        finding(
                            profile=profile,
                            policy=policy,
                            status="missing_marker",
                            category="sync_marker_contract",
                            message=f"{rel_path} is missing required sync marker: {marker}",
                            path=path_text(path, root),
                            rule_id=f"{rel_path}:marker:{marker}",
                            expected=marker,
                        )
                    )

            for pattern_rule in spec.get("required_patterns") or []:
                pattern = str(pattern_rule.get("pattern") or "")
                rule_id = str(pattern_rule.get("id") or pattern)
                try:
                    compiled = re.compile(pattern, compile_flags(pattern_rule.get("flags")))
                except re.error as exc:
                    findings.append(
                        finding(
                            profile=profile,
                            policy=policy,
                            status="regex_error",
                            category="manifest_contract",
                            message=f"Invalid regex for {rel_path}: {exc}",
                            path=path_text(manifest_path, root),
                            rule_id=f"{rel_path}:pattern:{rule_id}",
                            expected=pattern,
                        )
                    )
                    continue
                if not compiled.search(text):
                    findings.append(
                        finding(
                            profile=profile,
                            policy=policy,
                            status="missing_pattern",
                            category="anchor_contract",
                            message=f"{rel_path} does not satisfy required pattern {rule_id}.",
                            path=path_text(path, root),
                            rule_id=f"{rel_path}:pattern:{rule_id}",
                            expected=pattern,
                        )
                    )

            if mode == "filled":
                placeholders = sorted(set(match.group(0) for match in PLACEHOLDER_RE.finditer(text)))
                if placeholders:
                    findings.append(
                        finding(
                            profile=profile,
                            policy=policy,
                            status="placeholder_unresolved",
                            category="filled_spec_contract",
                            message=f"{rel_path} still contains unresolved draft placeholders.",
                            path=path_text(path, root),
                            rule_id=f"{rel_path}:placeholders",
                            expected="No [ADAPT]/TODO/TBD placeholders in filled mode",
                            actual=placeholders,
                        )
                    )

        for code_rule in manifest.get("traceability_codes") or []:
            if not isinstance(code_rule, dict):
                continue
            code_id = str(code_rule.get("id") or "UNKNOWN")
            applies = profile_applies(profile, code_rule.get("required_profiles"))
            code_entry: dict[str, Any] = {
                "id": code_id,
                "required": applies,
                "applicability": "required_by_profile" if applies else "not_applicable_by_profile",
                "defined_in": [str(item) for item in code_rule.get("defined_in") or []],
                "reference_files": [str(item) for item in code_rule.get("reference_files") or []],
                "definition_source": str(code_rule.get("definition_source") or "patterns"),
                "definitions_count": 0,
                "references_count": 0,
                "unresolved_references_count": 0,
            }
            if not applies:
                traceability_codes.append(code_entry)
                continue

            definitions, definition_source_path = collect_traceability_definitions(
                root=root,
                specs_root=specs_root,
                code_rule=code_rule,
                required_set=required_set,
                policy=policy,
            )
            references = collect_traceability_references(
                specs_root=specs_root,
                code_rule=code_rule,
                required_set=required_set,
            )
            code_entry["definitions_count"] = len(definitions)
            code_entry["references_count"] = len(references)
            code_entry["definitions_sample"] = sorted(definitions)[:20]
            if definition_source_path:
                code_entry["definition_source_path"] = path_text(Path(definition_source_path), root)

            if references and not definitions and code_rule.get("definition_source") == "task_registry" and not definition_source_path:
                findings.append(
                    finding(
                        profile=profile,
                        policy=policy,
                        status="missing_reference_source",
                        category="traceability_reference",
                        message="Task references are present but no TASK_REGISTRY.yaml source was found.",
                        rule_id=f"{code_id}:task_registry",
                        expected="TASK_REGISTRY.yaml defining referenced task IDs",
                        actual=sorted({item["token"] for item in references}),
                    )
                )
                code_entry["unresolved_references_count"] = len(references)
                traceability_codes.append(code_entry)
                continue

            unresolved = [item for item in references if item["token"] not in definitions]
            code_entry["unresolved_references_count"] = len(unresolved)
            for item in unresolved:
                findings.append(
                    finding(
                        profile=profile,
                        policy=policy,
                        status="unresolved_reference",
                        category="traceability_reference",
                        message=f"{item['path']} references {item['token']} but no {code_id} definition was found in applicable source artifacts.",
                        path=path_text(specs_root / item["path"], root),
                        rule_id=f"{code_id}:{item['path']}:{item['token']}",
                        expected=sorted(definitions),
                        actual=item["token"],
                    )
                )
            traceability_codes.append(code_entry)

    counts = finding_counts(findings)
    required_files = [item for item in files if item["required"]]
    spec_required_files = [item for item in required_files if item.get("kind") == "spec"]
    support_required_files = [item for item in required_files if item.get("kind") == "support"]
    summary = {
        **counts,
        "files_expected": len(expected_files),
        "files_present": sum(1 for item in required_files if item["present"]),
        "files_missing": sum(1 for item in required_files if not item["present"]),
        "contract_files_expected": len(expected_files),
        "contract_files_present": sum(1 for item in required_files if item["present"]),
        "contract_files_missing": sum(1 for item in required_files if not item["present"]),
        "spec_files_expected": len(spec_required_files),
        "spec_files_present": sum(1 for item in spec_required_files if item["present"]),
        "spec_files_missing": sum(1 for item in spec_required_files if not item["present"]),
        "support_files_expected": len(support_required_files),
        "support_files_present": sum(1 for item in support_required_files if item["present"]),
        "support_files_missing": sum(1 for item in support_required_files if not item["present"]),
        "files_not_applicable": sum(1 for item in files if item.get("applicability") == "not_applicable_by_profile"),
        "files_not_applicable_present": sum(
            1 for item in files if item.get("applicability") == "not_applicable_by_profile" and item["present"]
        ),
        "files_not_applicable_missing": sum(
            1 for item in files if item.get("applicability") == "not_applicable_by_profile" and not item["present"]
        ),
        "section_findings": sum(1 for item in findings if item["status"] == "missing_section"),
        "pattern_findings": sum(1 for item in findings if item["status"] == "missing_pattern"),
        "marker_findings": sum(1 for item in findings if item["status"] == "missing_marker"),
        "placeholder_findings": sum(1 for item in findings if item["status"] == "placeholder_unresolved"),
        "traceability_codes_required": sum(1 for item in traceability_codes if item.get("required")),
        "traceability_codes_not_applicable": sum(
            1 for item in traceability_codes if item.get("applicability") == "not_applicable_by_profile"
        ),
        "traceability_reference_findings": sum(
            1 for item in findings if item["status"] in {"unresolved_reference", "missing_reference_source"}
        ),
    }

    return {
        "schema": SCHEMA_ID,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "profile": profile,
        "status": status_from_counts(summary),
        "mode": mode,
        "project_root": str(root),
        "naos_root": str(default_naos_root(policy)),
        "specs_root": path_text(specs_root, root),
        "manifest": path_text(manifest_path, root),
        "deterministic": True,
        "summary": summary,
        "findings": findings,
        "files": files,
        "traceability_codes": traceability_codes,
        "limitations": manifest_limitations,
        "not_claimed": manifest_not_claimed,
        "human_review_required": True,
    }


def format_text_report(report: dict[str, Any]) -> str:
    lines = [
        "NAOS Spec-Pack Contract Validation",
        "=" * 40,
        f"Profile: {report['profile']}",
        f"Mode: {report['mode']}",
        f"Status: {report['status']}",
        f"Specs root: {report['specs_root']}",
        f"Manifest: {report['manifest']}",
        "",
        "Summary:",
        f"  Contract files expected: {report['summary'].get('contract_files_expected', report['summary']['files_expected'])}",
        f"  Contract files present:  {report['summary'].get('contract_files_present', report['summary']['files_present'])}",
        f"  Spec files expected:     {report['summary'].get('spec_files_expected', 0)}",
        f"  Spec files present:      {report['summary'].get('spec_files_present', 0)}",
        f"  Support files expected:  {report['summary'].get('support_files_expected', 0)}",
        f"  Support files present:   {report['summary'].get('support_files_present', 0)}",
        f"  Files not applicable by profile: {report['summary'].get('files_not_applicable', 0)}",
        f"  Traceability reference findings: {report['summary'].get('traceability_reference_findings', 0)}",
        f"  Findings:       {report['summary']['total_findings']}",
    ]
    if report["findings"]:
        lines.extend(["", "Findings:"])
        for item in report["findings"]:
            location = f" ({item.get('path')})" if item.get("path") else ""
            lines.append(f"  - [{item['severity']}] {item['status']}{location}: {item['message']}")
    else:
        lines.extend(["", "No spec-pack contract findings."])
    lines.extend(["", "Non-claims:"])
    lines.extend(f"  - {item}" for item in report["not_claimed"])
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate deterministic NAOS spec-pack contract conformance.")
    parser.add_argument("--profile", help="Governance profile (quickstart/lite/standard/assured).")
    parser.add_argument("--mode", choices=["structural", "filled"], default="structural", help="Validation mode (default: structural).")
    parser.add_argument("--specs-root", default=os.environ.get("SPECS_ROOT"), help="Specs root (default: specs/ when present, otherwise templates/spec-kit/specs).")
    parser.add_argument("--manifest", help="Spec manifest path (default: <specs-root>/spec_manifest.yaml).")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Path to NAOS governance root (default from policy/env).")
    parser.add_argument("--policy", help="Optional explicit policy file.")
    parser.add_argument("--output", help="Optional output report path.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit behavior.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    specs_root = Path(args.specs_root) if args.specs_root else default_specs_root(root)
    manifest_path = Path(args.manifest) if args.manifest else specs_root / DEFAULT_MANIFEST_NAME
    if not specs_root.is_absolute():
        specs_root = root / specs_root
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path

    report = validate_contract(
        root=root,
        specs_root=specs_root,
        manifest_path=manifest_path,
        profile=profile,
        policy=policy,
        mode=args.mode,
    )
    report["naos_root"] = naos_root
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "spec_pack_contract_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(format_text_report(report))
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
