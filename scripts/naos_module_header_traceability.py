#!/usr/bin/env python3
"""Evaluate canonical NAOS module headers and source traceability evidence."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    ignored_scan_dirs,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)
from naos_task_lifecycle import extract_task_ids  # noqa: E402
from source_roots import DEFAULT_SOURCE_ROOT_NAMES, resolve_source_roots  # noqa: E402


SECTION_LABELS = ["Module", "Purpose", "Implements", "Tasks", "Specs", "Rationale", "Design notes"]
REQ_TOKEN_RE = re.compile(r"\b(?:FR|NFR)-[A-Z0-9-]+\b")
LEGACY_TASK_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9-])(?:GOV|P[0-9]+)-[A-Z0-9-]+(?![A-Za-z0-9-])")
SPEC_REF_RE = re.compile(r"\bspecs/[A-Za-z0-9_.\-/]+\.md(?:#[A-Za-z0-9_.\-]+)?\b")
SECTION_RE = re.compile(r"^(Module|Purpose|Implements|Tasks|Specs|Rationale|Design notes):\s*(.*)$", re.I)
LEGACY_TASK_RE = re.compile(r"^Task:\s*(.+)$", re.I | re.M)


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "module_header_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("module_header_rules") or "module_header_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def relative_text(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def normalize_path_text(value: str) -> str:
    return value.strip().strip("`'\"").replace("\\", "/").lstrip("./")


def rule_severity(root: Path, naos_root: str, profile: str, policy: dict[str, Any], rules: dict[str, Any]) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    mapping = rules.get("profile_severity_behavior") if isinstance(rules.get("profile_severity_behavior"), dict) else {}
    return str(mapping.get(profile) or severity_for_profile(profile, policy) or "advisory")


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            continue
    return compiled


def pattern_matches_any(value: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def is_excluded(path: Path, root: Path, rules: dict[str, Any], policy: dict[str, Any]) -> str | None:
    rel = relative_text(root, path)
    parts = set(path.parts)
    for ignored in ignored_scan_dirs(policy):
        if ignored in parts:
            return f"policy ignored dir: {ignored}"
    for pattern in as_list(rules.get("exclude_patterns")):
        if fnmatch.fnmatch(rel, pattern) or path.match(pattern):
            return f"rule exclude pattern: {pattern}"
    return None


def effective_include_patterns(root: Path, rules: dict[str, Any]) -> tuple[list[str], list[str]]:
    configured = as_list(rules.get("include_patterns"))
    source_roots = [normalize_path_text(str(path)).rstrip("/") for path in resolve_source_roots(root)]
    default_root_patterns = {f"{name}/**/*.py" for name in DEFAULT_SOURCE_ROOT_NAMES}
    should_expand = any(normalize_path_text(pattern) in default_root_patterns for pattern in configured)
    if not should_expand:
        return configured, source_roots

    effective = list(configured)
    seen = {normalize_path_text(pattern) for pattern in effective}
    for source_root in source_roots:
        if not source_root:
            continue
        pattern = f"{source_root}/**/*.py"
        if pattern not in seen:
            effective.append(pattern)
            seen.add(pattern)
    return effective, source_roots


def collect_source_files(
    root: Path,
    rules: dict[str, Any],
    policy: dict[str, Any],
    include_patterns: list[str] | None = None,
) -> tuple[list[Path], list[dict[str, Any]]]:
    files: dict[str, Path] = {}
    excluded: list[dict[str, Any]] = []
    if include_patterns is None:
        include_patterns, _ = effective_include_patterns(root, rules)
    for pattern in include_patterns:
        try:
            matches = root.glob(pattern)
        except (OSError, ValueError):
            continue
        for match in matches:
            if not match.is_file():
                continue
            if match.suffix != ".py":
                continue
            reason = is_excluded(match, root, rules, policy)
            if reason:
                excluded.append({"path": relative_text(root, match), "reason": reason})
                continue
            files[relative_text(root, match)] = match
    return [files[key] for key in sorted(files)], sorted(excluded, key=lambda item: item["path"])


def header_text_from_source(source: str) -> tuple[str, str]:
    lines = source.splitlines()
    header_area = "\n".join(lines[:120])
    try:
        tree = ast.parse(source)
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
        ):
            value = getattr(tree.body[0].value, "value", None)
            if isinstance(value, str):
                end = getattr(tree.body[0], "end_lineno", None) or 120
                return value, "\n".join(lines[: max(end + 5, min(120, len(lines)))])
    except SyntaxError:
        pass

    comment_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if comment_lines:
                comment_lines.append("")
            continue
        if stripped.startswith("#!"):
            continue
        if re.match(r"#.*coding[:=]", stripped):
            continue
        if stripped.startswith("#"):
            comment_lines.append(stripped.lstrip("#").strip())
            continue
        break
    return "\n".join(comment_lines), header_area


def section_map(header_text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in header_text.splitlines():
        line = raw_line.rstrip()
        match = SECTION_RE.match(line.strip())
        if match:
            label = next((item for item in SECTION_LABELS if item.lower() == match.group(1).lower()), match.group(1))
            current = label
            sections.setdefault(label, [])
            inline = match.group(2).strip()
            if inline:
                sections[label].append(inline)
            continue
        if current:
            stripped = line.strip()
            if stripped:
                sections[current].append(stripped[2:].strip() if stripped.startswith("- ") else stripped)
    return sections


def extract_ids(sections: dict[str, list[str]]) -> tuple[list[str], list[str], list[str]]:
    reqs = sorted(set(token for item in sections.get("Implements", []) for token in REQ_TOKEN_RE.findall(item)))
    task_text = "\n".join(sections.get("Tasks", []))
    tasks = sorted(set(extract_task_ids(task_text)) | set(LEGACY_TASK_TOKEN_RE.findall(task_text)))
    specs = sorted(set(token for item in sections.get("Specs", []) for token in SPEC_REF_RE.findall(item)))
    return reqs, tasks, specs


def load_requirement_ids(root: Path, rules: dict[str, Any]) -> set[str]:
    config = rules.get("cross_checks", {}).get("requirements", {}) if isinstance(rules.get("cross_checks"), dict) else {}
    if config.get("enabled") is False:
        return set()
    ids: set[str] = set()
    for spec in as_list(config.get("spec_paths") or ["specs/03-requirements.md"]):
        path = root / spec
        if path.is_file():
            ids.update(REQ_TOKEN_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return ids


def load_task_ids(root: Path, rules: dict[str, Any]) -> set[str]:
    config = rules.get("cross_checks", {}).get("tasks", {}) if isinstance(rules.get("cross_checks"), dict) else {}
    if config.get("enabled") is False:
        return set()
    ids: set[str] = set()
    for registry in as_list(config.get("registry_paths") or ["naos/TASK_REGISTRY.yaml", "TASK_REGISTRY.yaml"]):
        path = root / registry
        if not path.is_file():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        tasks = data.get("tasks", data) if isinstance(data, dict) else []
        if isinstance(tasks, dict):
            ids.update(str(key) for key in tasks)
        elif isinstance(tasks, list):
            for task in tasks:
                if isinstance(task, dict) and task.get("id"):
                    ids.add(str(task["id"]))
    return ids


def finding(
    *,
    path: str,
    severity: str,
    status: str,
    message: str,
    required_next_actions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"{path}:{status}",
        "path": path,
        "severity": severity,
        "status": status,
        "message": message,
        "required_next_actions": required_next_actions or [],
    }


def status_for_file(file_findings: list[dict[str, Any]]) -> str:
    priority = ["blocked", "missing", "duplicate", "stale", "legacy", "warning", "advisory", "unknown"]
    statuses = {str(item.get("status")) for item in file_findings}
    if "missing_required_section" in statuses or "unknown_reference" in statuses:
        statuses.add("missing")
    for status in priority:
        if status in statuses:
            return status
    return "ready"


def evaluate_file(
    path: Path,
    *,
    root: Path,
    rules: dict[str, Any],
    severity: str,
    requirement_ids: set[str],
    task_ids: set[str],
    req_patterns: list[re.Pattern[str]],
    task_patterns: list[re.Pattern[str]],
    spec_patterns: list[re.Pattern[str]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rel = relative_text(root, path)
    source = path.read_text(encoding="utf-8", errors="ignore")
    header_text, header_area = header_text_from_source(source)
    sections = section_map(header_text)
    required_sections = as_list(rules.get("required_sections")) or ["Module", "Purpose", "Implements", "Tasks", "Specs", "Rationale"]
    sections_present = sorted([section for section in required_sections + as_list(rules.get("optional_sections")) if section in sections])
    missing_sections = [section for section in required_sections if section not in sections]
    reqs, tasks, specs = extract_ids(sections)
    module_entries = sections.get("Module") or []
    module_path = normalize_path_text(module_entries[0]) if module_entries else None
    module_occurrences = len(re.findall(r"(?im)^\s*Module:\s*", header_area))
    legacy_task = bool(LEGACY_TASK_RE.search(header_area)) and "Tasks" not in sections
    inline_legacy = any(
        bool(re.match(rf"(?im)^\s*{label}:\s+\S", header_text))
        for label in ["Implements", "Tasks", "Specs", "Rationale"]
    )

    file_findings: list[dict[str, Any]] = []
    if "Module" not in sections:
        file_findings.append(
            finding(
                path=rel,
                severity=severity,
                status="missing",
                message="Canonical Module section is missing.",
                required_next_actions=["Add one canonical NAOS module header or configure an explicit exemption."],
            )
        )
    if missing_sections:
        file_findings.append(
            finding(
                path=rel,
                severity=severity,
                status="missing_required_section",
                message=f"Missing required module-header sections: {', '.join(missing_sections)}.",
                required_next_actions=["Update the existing module header with the missing canonical sections."],
            )
        )
    if rules.get("duplicate_header_behavior", {}).get("enabled", True) and module_occurrences > 1:
        file_findings.append(
            finding(
                path=rel,
                severity=severity,
                status="duplicate",
                message="Multiple Module headers were found in the top-of-file header area.",
                required_next_actions=["Merge duplicate/stale metadata into one canonical module header."],
            )
        )
    if rules.get("stale_module_path_behavior", {}).get("enabled", True) and module_path and module_path != normalize_path_text(rel):
        file_findings.append(
            finding(
                path=rel,
                severity=severity,
                status="stale",
                message=f"Module path '{module_path}' does not match file path '{rel}'.",
                required_next_actions=["Review whether the file moved and update the existing Module line if appropriate."],
            )
        )
    if rules.get("legacy_header_handling", {}).get("enabled", True) and (legacy_task or inline_legacy):
        file_findings.append(
            finding(
                path=rel,
                severity=severity,
                status="legacy",
                message="Legacy inline or singular Task-style traceability header was detected.",
                required_next_actions=["Convert legacy traceability metadata to the canonical plural block format when the file is next touched."],
            )
        )

    for req_id in reqs:
        if not pattern_matches_any(req_id, req_patterns):
            file_findings.append(finding(path=rel, severity=severity, status="unknown", message=f"Requirement id has unexpected format: {req_id}."))
        elif requirement_ids and req_id not in requirement_ids:
            file_findings.append(finding(path=rel, severity=severity, status="unknown_reference", message=f"Requirement id is not present in configured requirement specs: {req_id}."))
    for task_id in tasks:
        if not pattern_matches_any(task_id, task_patterns):
            file_findings.append(finding(path=rel, severity=severity, status="unknown", message=f"Task id has unexpected format: {task_id}."))
        elif task_ids and task_id not in task_ids:
            file_findings.append(finding(path=rel, severity=severity, status="unknown_reference", message=f"Task id is not present in configured task registries: {task_id}."))
    specs_config = rules.get("cross_checks", {}).get("specs", {}) if isinstance(rules.get("cross_checks"), dict) else {}
    if specs_config.get("enabled") is not False:
        for spec_ref in specs:
            if not pattern_matches_any(spec_ref, spec_patterns):
                file_findings.append(finding(path=rel, severity=severity, status="unknown", message=f"Spec reference has unexpected format: {spec_ref}."))
                continue
            spec_path = root / spec_ref.split("#", 1)[0]
            if not spec_path.exists():
                file_findings.append(finding(path=rel, severity=severity, status="unknown_reference", message=f"Spec reference path does not exist: {spec_ref}."))

    scanned = {
        "path": rel,
        "status": status_for_file(file_findings),
        "module_path": module_path,
        "sections_present": sections_present,
        "missing_sections": missing_sections,
        "requirement_ids": reqs,
        "task_ids": tasks,
        "spec_refs": specs,
        "human_review_required": any(item["status"] in {"missing", "missing_required_section", "duplicate", "stale"} for item in file_findings),
    }
    return scanned, file_findings


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
) -> dict[str, Any]:
    rules = load_yaml(rules_path)
    severity = rule_severity(root, naos_root, profile, policy, rules)
    policy_meta = policy.get("_meta", {})
    if rules.get("enabled") is False:
        return {
            "schema": "naos.module_header_traceability.v1",
            "generated_at": utc_now_text(),
            "profile": profile,
            "status": "disabled",
            "naos_root": naos_root,
            "project_root": str(root),
            "rules": {"path": str(rules_path), "source": rules_source, "semantics": rules.get("semantics") or {}},
            "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
            "summary": {"scanned_files": 0, "excluded_files": 0, "total_findings": 0, "disabled": 1},
            "scanned_files": [],
            "excluded_files": [],
            "findings": [],
            "legacy_headers": [],
            "missing_headers": [],
            "stale_headers": [],
            "duplicate_headers": [],
            "limitations": as_list(rules.get("limitations")),
            "human_review_required": False,
        }

    include_patterns, source_roots = effective_include_patterns(root, rules)
    source_files, excluded_files = collect_source_files(root, rules, policy, include_patterns)
    req_patterns = compile_patterns(as_list(rules.get("allowed_requirement_id_patterns")) or [r"^(FR|NFR)-[A-Z0-9-]+$"])
    task_patterns = compile_patterns(
        as_list(rules.get("allowed_task_id_patterns"))
        or [r"^((?:[A-Z0-9]+-)*T-[0-9]{3,}|GOV-[A-Z0-9-]+|P[0-9]+-[A-Z0-9-]+)$"]
    )
    spec_patterns = compile_patterns(as_list(rules.get("allowed_spec_reference_patterns")) or [r"^specs/[A-Za-z0-9_.\-/]+\.md(#[A-Za-z0-9_.\-]+)?$"])
    requirement_ids = load_requirement_ids(root, rules)
    task_ids = load_task_ids(root, rules)

    scanned_files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not source_files:
        findings.append(
            finding(
                path=".",
                severity=severity,
                status="not_configured",
                message="No Python source files matched configured module-header include patterns.",
                required_next_actions=["Configure include patterns, add source files, disable the capability, or record why it is not applicable."],
            )
        )
    for path in source_files:
        scanned, file_findings = evaluate_file(
            path,
            root=root,
            rules=rules,
            severity=severity,
            requirement_ids=requirement_ids,
            task_ids=task_ids,
            req_patterns=req_patterns,
            task_patterns=task_patterns,
            spec_patterns=spec_patterns,
        )
        scanned_files.append(scanned)
        findings.extend(file_findings)

    summary = finding_counts(findings)
    status_paths = {
        status: {item["path"] for item in findings if item.get("status") == status}
        for status in {"legacy", "stale", "duplicate", "missing", "missing_required_section"}
    }
    summary.update(
        {
            "scanned_files": len(scanned_files),
            "excluded_files": len(excluded_files),
            "ready_files": sum(1 for item in scanned_files if item.get("status") == "ready"),
            "missing_headers": len(status_paths["missing"] | status_paths["missing_required_section"]),
            "legacy_headers": len(status_paths["legacy"]),
            "stale_headers": len(status_paths["stale"]),
            "duplicate_headers": len(status_paths["duplicate"]),
            "not_configured": sum(1 for item in findings if item.get("status") == "not_configured"),
            "human_review_required": sum(1 for item in scanned_files if item.get("human_review_required")),
        }
    )
    paths_by_status = {
        status: {item["path"] for item in findings if item.get("status") == status}
        for status in {"legacy", "stale", "duplicate", "missing", "missing_required_section"}
    }
    legacy_headers = [item for item in scanned_files if item.get("path") in paths_by_status["legacy"]]
    missing_headers = [
        item
        for item in scanned_files
        if item.get("path") in paths_by_status["missing"]
        or item.get("path") in paths_by_status["missing_required_section"]
        or item.get("missing_sections")
    ]
    stale_headers = [item for item in scanned_files if item.get("path") in paths_by_status["stale"]]
    duplicate_headers = [item for item in scanned_files if item.get("path") in paths_by_status["duplicate"]]
    human_review_required = bool(summary["human_review_required"] or duplicate_headers or stale_headers)
    return {
        "schema": "naos.module_header_traceability.v1",
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": status_from_counts(summary),
        "naos_root": naos_root,
        "project_root": str(root),
        "rules": {
            "path": str(rules_path),
            "source": rules_source,
            "semantics": rules.get("semantics") or {},
            "include_patterns": as_list(rules.get("include_patterns")),
            "effective_include_patterns": include_patterns,
            "source_roots": source_roots,
            "exclude_patterns": as_list(rules.get("exclude_patterns")),
        },
        "policy": {"version": policy.get("version"), "source": policy_meta.get("source"), "path": policy_meta.get("path")},
        "semantics": {
            "rules": "Project configuration for source-module header traceability; not proof by itself.",
            "report": "NAOS evaluates canonical module-header traceability evidence.",
            "not_claimed": "This report does not prove complete source traceability, source correctness, or design correctness.",
        },
        "summary": summary,
        "scanned_files": scanned_files,
        "excluded_files": excluded_files,
        "findings": findings,
        "legacy_headers": legacy_headers,
        "missing_headers": missing_headers,
        "stale_headers": stale_headers,
        "duplicate_headers": duplicate_headers,
        "limitations": as_list(rules.get("limitations"))
        + [
            "The validator is deterministic and file-first.",
            "It does not auto-fix source files.",
            "It does not prove complete source traceability or code correctness.",
        ],
        "human_review_required": human_review_required,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate canonical NAOS module-header traceability.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="Path to module_header_rules.yaml.")
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
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules_path=rules_path,
        rules_source=rules_source,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "module_header_traceability_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS module-header traceability: "
            f"{report['status']} "
            f"({report['summary'].get('scanned_files', 0)} scanned, "
            f"{report['summary'].get('missing_headers', 0)} missing, "
            f"{report['summary'].get('legacy_headers', 0)} legacy, "
            f"output: {destination})"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
