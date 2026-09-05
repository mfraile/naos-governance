#!/usr/bin/env python3
"""Shared deterministic hygiene checks for NAOS local validators."""

from __future__ import annotations

import ast
import argparse
import copy
import hashlib
import json
import math
import os
import re
import sys
import tomllib
from collections import defaultdict
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
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


NON_CLAIMS = [
    "semantic correctness proof",
    "behavioral correctness proof",
    "secure-code proof",
    "secret-free repository proof",
    "package supply-chain safety proof",
    "runtime safety proof",
    "requirements completeness proof",
    "compliance proof",
    "certification",
    "approval",
    "hallucination prevention",
    "human review replacement",
]

LIMITATIONS = [
    "Checks are deterministic, local, and file-first.",
    "Findings are review evidence only and require human triage.",
    "Generated or project-specific patterns may require adopter-owned allowlists.",
    "These checks do not replace specialized security, SCA, coverage, or semantic-review tooling.",
]

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "htmlcov",
    ".tox",
    "dev",
}

PYTHON_ROOTS = ["src", "app", "tests"]
SECRET_ROOTS = ["src", "app", "tests", ".github"]
SECRET_SUFFIXES = [".py", ".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".cfg", ".md", ".txt"]

KNOWN_IMPORT_MAP = {
    "pyyaml": "yaml",
    "python-dotenv": "dotenv",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "opencv-python": "cv2",
    "scikit-learn": "sklearn",
    "pytest": "pytest",
    "jsonschema": "jsonschema",
}

SECRET_REGEXES = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private_key_header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|credential)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
        ),
    ),
]

PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "example",
    "example-token",
    "example_secret",
    "placeholder",
    "replace-me",
    "todo",
    "your-api-key",
    "your_token_here",
}


def utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def default_rules_path(root: Path, naos_root: str, filename: str) -> Path | None:
    project_rules = root / naos_root / filename
    if project_rules.exists() and not is_kit_repository(root, naos_root):
        return project_rules
    template_rules = Path(__file__).resolve().parents[1] / "templates" / "structural-seeds" / "naos" / filename
    return template_rules if template_rules.exists() else None


def merge_rules(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_rules(merged[key], value)
        else:
            merged[key] = value
    return merged


def rules_for(root: Path, naos_root: str, explicit: str | None, filename: str, fallback: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    path = Path(explicit) if explicit else default_rules_path(root, naos_root, filename)
    rules = merge_rules(fallback, load_yaml(path))
    return rules, str(path) if path else None


def normalized_list(value: Any, fallback: list[str]) -> list[str]:
    if value is None:
        return list(fallback)
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    cleaned = str(value).strip()
    return [cleaned] if cleaned else list(fallback)


def is_excluded(path: Path, root: Path, exclude_dirs: set[str], exclude_globs: list[str]) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    if any(part in exclude_dirs for part in rel.parts):
        return True
    return any(rel.match(pattern) for pattern in exclude_globs)


def collect_files(
    root: Path,
    rules: dict[str, Any],
    *,
    roots_fallback: list[str],
    suffixes: set[str],
) -> list[Path]:
    scan_roots = normalized_list(rules.get("scan_roots"), roots_fallback)
    exclude_dirs = DEFAULT_EXCLUDE_DIRS | {str(item) for item in rules.get("exclude_dirs") or []}
    exclude_globs = normalized_list(rules.get("exclude_globs"), [])
    files: list[Path] = []
    for raw in scan_roots:
        candidate = root / raw
        if not candidate.exists():
            continue
        if candidate.is_file():
            if candidate.suffix in suffixes and not is_excluded(candidate, root, exclude_dirs, exclude_globs):
                files.append(candidate)
            continue
        for path in sorted(candidate.rglob("*")):
            if path.is_file() and path.suffix in suffixes and not is_excluded(path, root, exclude_dirs, exclude_globs):
                files.append(path)
    return sorted(set(files))


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    path: str | None = None,
    line: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "not_claimed": NON_CLAIMS,
    }
    if path is not None:
        item["path"] = path
    if line is not None:
        item["line"] = line
    if extra:
        item.update(extra)
    return item


def build_base_report(
    *,
    schema: str,
    profile: str,
    root: Path,
    naos_root: str,
    rules_path: str | None,
    findings: list[dict[str, Any]],
    summary_extra: dict[str, Any],
    scans: dict[str, Any],
) -> dict[str, Any]:
    counts = finding_counts(findings)
    status = status_from_counts(counts)
    summary = {**counts, **summary_extra}
    return {
        "schema": schema,
        "generated_at": utc_timestamp(),
        "profile": profile,
        "status": status,
        "project_root": str(root),
        "naos_root": naos_root,
        "rules_path": rules_path,
        "deterministic": True,
        "cost_posture": {
            "cost_incurred_by_default": False,
            "cost_usd": 0.0,
            "external_api_required": False,
            "provider_dependency_required": False,
            "model_dependency_required": False,
            "human_approval_required_before_cost": True,
        },
        "summary": summary,
        "scans": scans,
        "findings": findings,
        "waivers": [],
        "known_gaps": [],
        "residual_risks": [
            "deterministic_hygiene_checks_are_not_semantic_review",
            "allowlists_require_human_review",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NON_CLAIMS,
        "human_review_required": bool(findings),
    }


def run_report_command(
    *,
    argv: list[str] | None,
    description: str,
    rules_filename: str,
    report_key: str,
    schema: str,
    fallback_rules: dict[str, Any],
    builder: Any,
    summary_label: str,
) -> int:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help=f"Optional explicit {rules_filename} path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    severity = severity_for_profile(profile, policy)
    rules, rules_path = rules_for(root, naos_root, args.rules, rules_filename, fallback_rules)
    report = builder(root=root, profile=profile, naos_root=naos_root, rules=rules, rules_path=rules_path, severity=severity)
    if report.get("schema") != schema:
        report["schema"] = schema
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, report_key)
    if output is not None:
        write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"NAOS {summary_label}: {report['status']} "
            f"({report['summary'].get('total_findings', 0)} findings) -> {output}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


class _NormalizedFunction(ast.NodeTransformer):
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:  # noqa: N802
        node.name = "_function"
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:  # noqa: N802
        node.name = "_function"
        self.generic_visit(node)
        return node


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        if isinstance(body[0].value.value, str):
            return body[1:]
    return body


def check_duplicate_function_hygiene(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    files = collect_files(root, rules, roots_fallback=PYTHON_ROOTS, suffixes={".py"})
    min_dump_length = int(rules.get("min_normalized_dump_length") or 240)
    allowed_hashes = {str(item) for item in rules.get("allowed_hashes") or []}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    parse_errors = 0
    functions_scanned = 0
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            parse_errors += 1
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = _strip_docstring(list(node.body))
            if not body:
                continue
            clone = copy.deepcopy(node)
            clone.name = "_function"
            clone.body = body
            clone.decorator_list = []
            clone.returns = None
            normalized = _NormalizedFunction().visit(clone)
            dump = ast.dump(normalized, include_attributes=False)
            if len(dump) < min_dump_length:
                continue
            digest = hashlib.sha256(dump.encode("utf-8")).hexdigest()
            functions_scanned += 1
            groups[digest].append(
                {
                    "path": relpath(path, root),
                    "line": int(getattr(node, "lineno", 0) or 0),
                    "function": node.name,
                    "hash": digest,
                }
            )
    findings: list[dict[str, Any]] = []
    duplicate_groups = []
    for digest, members in sorted(groups.items()):
        paths = {member["path"] for member in members}
        if len(members) < 2 or len(paths) < 2 or digest in allowed_hashes:
            continue
        duplicate_groups.append({"hash": digest, "members": members})
        first = members[0]
        findings.append(
            finding(
                finding_id=f"duplicate_function_hygiene.{digest[:12]}",
                severity=severity,
                status="duplicate_function_body",
                message="Normalized function body appears in multiple files and requires duplicate-triage review.",
                path=first["path"],
                line=first["line"],
                extra={"duplicate_group": members, "confidence": "exact_normalized_ast"},
            )
        )
    if not files:
        findings.append(
            finding(
                finding_id="duplicate_function_hygiene.not_configured",
                severity="advisory",
                status="not_configured",
                message="No configured Python source/test roots were found for duplicate-function hygiene.",
            )
        )
    return build_base_report(
        schema="naos.duplicate_function_hygiene.v1",
        profile=profile,
        root=root,
        naos_root=naos_root,
        rules_path=rules_path,
        findings=findings,
        summary_extra={
            "files_scanned": len(files),
            "functions_scanned": functions_scanned,
            "duplicate_groups": len(duplicate_groups),
            "parse_errors": parse_errors,
        },
        scans={"duplicate_groups": duplicate_groups},
    )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _line_allowed(line: str) -> bool:
    return "naos: allow-secret" in line


def _candidate_secret_value(text: str) -> str:
    stripped = text.strip().strip("'\"")
    return stripped.lower()


def check_secret_hygiene(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    suffixes = {str(item) for item in rules.get("suffixes") or SECRET_SUFFIXES}
    files = collect_files(root, rules, roots_fallback=SECRET_ROOTS, suffixes=suffixes)
    entropy_min_length = int(rules.get("entropy_min_length") or 20)
    entropy_threshold = float(rules.get("entropy_threshold") or 4.0)
    allowed_values = {_candidate_secret_value(str(item)) for item in rules.get("allowed_values") or []}
    findings: list[dict[str, Any]] = []
    regex_matches = 0
    entropy_matches = 0
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            if _line_allowed(line):
                continue
            for rule_id, pattern in SECRET_REGEXES:
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(2) if rule_id == "assigned_secret" and len(match.groups()) >= 2 else match.group(0)
                normalized = _candidate_secret_value(value)
                if normalized in PLACEHOLDER_VALUES or normalized in allowed_values:
                    continue
                regex_matches += 1
                findings.append(
                    finding(
                        finding_id=f"secret_hygiene.{rule_id}.{relpath(path, root)}.{line_no}",
                        severity=severity,
                        status="secret_like_pattern",
                        message=f"Secret-like pattern '{rule_id}' found in local file; rotate if real and record a reviewed waiver if fixture-only.",
                        path=relpath(path, root),
                        line=line_no,
                        extra={"pattern_id": rule_id},
                    )
                )
            for literal in re.findall(r"['\"]([^'\"]{%d,})['\"]" % entropy_min_length, line):
                normalized = _candidate_secret_value(literal)
                if normalized in allowed_values or normalized in PLACEHOLDER_VALUES:
                    continue
                if not (re.search(r"[A-Za-z]", literal) and re.search(r"[0-9]", literal)):
                    continue
                entropy = shannon_entropy(literal)
                if entropy < entropy_threshold:
                    continue
                entropy_matches += 1
                findings.append(
                    finding(
                        finding_id=f"secret_hygiene.high_entropy.{relpath(path, root)}.{line_no}",
                        severity=severity,
                        status="high_entropy_literal",
                        message="High-entropy literal found in local file; review as possible credential or token.",
                        path=relpath(path, root),
                        line=line_no,
                        extra={"entropy": round(entropy, 3), "min_length": entropy_min_length},
                    )
                )
    if not files:
        findings.append(
            finding(
                finding_id="secret_hygiene.not_configured",
                severity="advisory",
                status="not_configured",
                message="No configured files were found for secret hygiene scanning.",
            )
        )
    return build_base_report(
        schema="naos.secret_hygiene.v1",
        profile=profile,
        root=root,
        naos_root=naos_root,
        rules_path=rules_path,
        findings=findings,
        summary_extra={
            "files_scanned": len(files),
            "regex_matches": regex_matches,
            "entropy_matches": entropy_matches,
        },
        scans={"suffixes": sorted(suffixes), "entropy_threshold": entropy_threshold},
    )


ASSERT_CALLS = {
    "assertEqual",
    "assertEquals",
    "assertNotEqual",
    "assertTrue",
    "assertFalse",
    "assertIs",
    "assertIsNot",
    "assertIn",
    "assertNotIn",
    "assertRaises",
    "assertRegex",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
    "fail",
    "raises",
}


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _has_assertion(node: ast.AST) -> tuple[bool, bool]:
    has_assert = False
    trivial = False
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            has_assert = True
            if isinstance(child.test, ast.Constant) and child.test.value in {True, 1, "true"}:
                trivial = True
        elif isinstance(child, ast.Raise):
            has_assert = True
        elif isinstance(child, ast.Call):
            name = _call_name(child.func)
            if name in ASSERT_CALLS or (name and name.startswith("assert")):
                has_assert = True
        elif isinstance(child, ast.With):
            for item in child.items:
                context = item.context_expr
                if isinstance(context, ast.Call) and _call_name(context.func) == "raises":
                    has_assert = True
    return has_assert, trivial


def check_test_quality_hygiene(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    files = collect_files(root, rules, roots_fallback=["tests"], suffixes={".py"})
    findings: list[dict[str, Any]] = []
    tests_scanned = 0
    missing_assertions = 0
    trivial_assertions = 0
    parse_errors = 0
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            parse_errors += 1
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                tests_scanned += 1
                has_assertion, trivial = _has_assertion(node)
                if not has_assertion:
                    missing_assertions += 1
                    findings.append(
                        finding(
                            finding_id=f"test_quality_hygiene.missing_assertion.{relpath(path, root)}.{node.lineno}",
                            severity=severity,
                            status="missing_assertion",
                            message="Test function has no assertion, expected exception, or recognized assertion call.",
                            path=relpath(path, root),
                            line=int(node.lineno),
                        )
                    )
                elif trivial:
                    trivial_assertions += 1
                    findings.append(
                        finding(
                            finding_id=f"test_quality_hygiene.trivial_assertion.{relpath(path, root)}.{node.lineno}",
                            severity="advisory",
                            status="trivial_assertion",
                            message="Test function contains a trivial assertion and requires review for meaningful evidence.",
                            path=relpath(path, root),
                            line=int(node.lineno),
                        )
                    )
    if not files:
        findings.append(
            finding(
                finding_id="test_quality_hygiene.not_configured",
                severity="advisory",
                status="not_configured",
                message="No configured Python test roots were found for test-quality hygiene.",
            )
        )
    return build_base_report(
        schema="naos.test_quality_hygiene.v1",
        profile=profile,
        root=root,
        naos_root=naos_root,
        rules_path=rules_path,
        findings=findings,
        summary_extra={
            "files_scanned": len(files),
            "test_functions_scanned": tests_scanned,
            "missing_assertions": missing_assertions,
            "trivial_assertions": trivial_assertions,
            "parse_errors": parse_errors,
        },
        scans={"assertion_model": "ast_assert_raise_assertion_calls_pytest_raises"},
    )


def _stdlib_modules() -> set[str]:
    modules = set(getattr(sys, "stdlib_module_names", set()))
    modules.update({"typing", "pathlib", "dataclasses", "__future__"})
    return modules


def _import_names(path: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((alias.name.split(".")[0], int(node.lineno)))
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imports.append((node.module.split(".")[0], int(node.lineno)))
    return imports


def _parse_requirement_name(line: str) -> str | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#") or cleaned.startswith(("-", "git+", "http://", "https://")):
        return None
    cleaned = re.split(r"[<>=!~;\[]", cleaned, maxsplit=1)[0].strip()
    return cleaned or None


def declared_dependency_imports(root: Path) -> set[str]:
    names: set[str] = set()
    for req in [root / "requirements.txt", *sorted(root.glob("requirements/*.txt"))]:
        if not req.exists():
            continue
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            name = _parse_requirement_name(line)
            if name:
                names.add(name.lower().replace("-", "_"))
                mapped = KNOWN_IMPORT_MAP.get(name.lower())
                if mapped:
                    names.add(mapped)
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        project = data.get("project") if isinstance(data, dict) else {}
        deps = project.get("dependencies") if isinstance(project, dict) else []
        optional = project.get("optional-dependencies") if isinstance(project, dict) else {}
        all_deps = list(deps or [])
        if isinstance(optional, dict):
            for value in optional.values():
                if isinstance(value, list):
                    all_deps.extend(value)
        poetry_deps = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}) if isinstance(data, dict) else {}
        if isinstance(poetry_deps, dict):
            all_deps.extend(poetry_deps.keys())
        for dep in all_deps:
            name = _parse_requirement_name(str(dep))
            if name and name.lower() != "python":
                normalized = name.lower().replace("-", "_")
                names.add(normalized)
                mapped = KNOWN_IMPORT_MAP.get(name.lower())
                if mapped:
                    names.add(mapped)
    return names


def first_party_modules(root: Path, files: list[Path]) -> set[str]:
    names: set[str] = set()
    for path in files:
        names.add(path.stem)
        parts = path.relative_to(root).parts
        if parts:
            names.add(parts[0])
    for base in [root / "src", root / "app"]:
        if not base.exists():
            continue
        for child in base.iterdir():
            if child.is_dir() and (child / "__init__.py").exists():
                names.add(child.name)
            elif child.suffix == ".py":
                names.add(child.stem)
    return names


def check_dependency_integrity(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    files = collect_files(root, rules, roots_fallback=PYTHON_ROOTS, suffixes={".py"})
    stdlib = _stdlib_modules()
    declared = declared_dependency_imports(root)
    first_party = first_party_modules(root, files)
    allowed = {str(item) for item in rules.get("allowed_imports") or []}
    findings: list[dict[str, Any]] = []
    imports_scanned = 0
    unresolved = 0
    for path in files:
        for name, line in _import_names(path):
            imports_scanned += 1
            if name in stdlib or name in first_party or name in declared or name in allowed:
                continue
            unresolved += 1
            findings.append(
                finding(
                    finding_id=f"dependency_integrity.undeclared_import.{relpath(path, root)}.{line}.{name}",
                    severity=severity,
                    status="undeclared_or_unresolved_import",
                    message=f"Import '{name}' is not stdlib, first-party, declared dependency, or allowlisted.",
                    path=relpath(path, root),
                    line=line,
                    extra={"import_name": name, "source_basis": "python_ast_import"},
                )
            )
    if not files:
        findings.append(
            finding(
                finding_id="dependency_integrity.not_configured",
                severity="advisory",
                status="not_configured",
                message="No configured Python source/test roots were found for dependency integrity.",
            )
        )
    return build_base_report(
        schema="naos.dependency_integrity.v1",
        profile=profile,
        root=root,
        naos_root=naos_root,
        rules_path=rules_path,
        findings=findings,
        summary_extra={
            "files_scanned": len(files),
            "imports_scanned": imports_scanned,
            "undeclared_or_unresolved_imports": unresolved,
            "declared_dependency_imports": len(declared),
            "first_party_modules": len(first_party),
        },
        scans={
            "declared_dependency_imports": sorted(declared),
            "first_party_modules": sorted(first_party),
            "allowed_imports": sorted(allowed),
        },
    )
