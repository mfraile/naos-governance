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
import stat
import sys
import tomllib
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
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

from naos_secret_patterns import (SECRET_SCAN_ROOTS, SECRET_SCAN_SUFFIXES,  # noqa: E402
                                  is_secret_scan_file, iter_secret_content_matches)  # noqa: E402
from naos_secret_public_literals import (PublicVocabularyError, load_public_literals,
                                        public_audit_ids, selected_public_audit_literals, selected_public_reference_literals,
                                        selected_public_derived_report_ids,
                                        public_secret_finding_ids, selected_public_secret_finding_literals,
                                        selected_public_producer_witness_literals,
                                        selected_public_claim_context, public_claim_label_spans, public_git_comparison_spans)  # noqa: E402


from naos_secret_managed_operands import _ScannerProofBudget, inventory_operand_spans
from source_roots import INFERRED_ADOPTER_ROOTS, inferred_adopter_python_files, native_adopter_root_aliases, is_native_python_package_marker, declared_package_roots, declared_package_selects


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
SECRET_ROOTS = SECRET_SCAN_ROOTS
SECRET_SUFFIXES = SECRET_SCAN_SUFFIXES

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
    include_dotenv: bool = False,
    include_symlink_leaves: bool = False,
    default_exclude_dirs: set[str] | None = None,
    selection_inventory: dict[Path, str] | None = None,
) -> list[Path]:
    scan_roots = normalized_list(rules.get("scan_roots"), roots_fallback)
    defaults = DEFAULT_EXCLUDE_DIRS if default_exclude_dirs is None else default_exclude_dirs
    exclude_dirs = defaults | {str(item) for item in rules.get("exclude_dirs") or []}
    exclude_globs = normalized_list(rules.get("exclude_globs"), [])
    files: list[Path] = []
    def select(path: Path) -> None:
        status = ("excluded" if is_excluded(path, root, exclude_dirs, exclude_globs)
                  else "selected" if _scan_suffix(path, suffixes, include_dotenv)
                  else "unselected_suffix")
        if selection_inventory is not None:
            selection_inventory[path] = status
        if status == "selected":
            files.append(path)
    for raw in scan_roots:
        candidate = root / raw
        if not candidate.exists() and not (include_symlink_leaves and candidate.is_symlink()):
            continue
        if candidate.is_file() or (include_symlink_leaves and candidate.is_symlink()
                                   and not candidate.is_dir()):
            select(candidate)
            continue
        for path in sorted(candidate.rglob("*")):
            if path.is_file() or (include_symlink_leaves and path.is_symlink()):
                select(path)
    return sorted(set(files))


_HYGIENE_MAX_ENTRIES = 50_000
_HYGIENE_MAX_DEPTH = 64


def _hygiene_selector(root: Path, raw: str) -> Path | None:
    """Reject Windows anchored forms on every host before touching the filesystem."""
    ref, windows = Path(raw), PureWindowsPath(raw)
    if (ref.is_absolute() or windows.drive or windows.root
            or ".." in ref.parts or ".." in windows.parts):
        return None
    candidate = root / ref
    return candidate if candidate.is_relative_to(root) else None


def _hygiene_roots(rules: dict[str, Any], fallback: list[str]):
    value = rules.get("scan_roots")
    truncated = isinstance(value, list) and len(value) > _HYGIENE_MAX_ENTRIES
    # Slice before normalization: repeated selectors cannot create unbounded work.
    if isinstance(value, list):
        value = value[:_HYGIENE_MAX_ENTRIES]
    return normalized_list(value, fallback), truncated


def _hygiene_scope(root: Path, rules: dict[str, Any], roots: list[str],
                   suffixes: set[str], *, secret: bool = False):
    """Bound unique discovered entries and depth, including immediate root accounting."""
    root = root.absolute()
    excluded = (DEFAULT_EXCLUDE_DIRS - {"dev"} if secret else DEFAULT_EXCLUDE_DIRS) | set(rules.get("exclude_dirs") or [])
    globs = normalized_list(rules.get("exclude_globs"), [])
    if secret and not rules.get("scan_roots"):
        excluded.add("dev")
    files, inventory, issues = set(), {}, []
    scheduled, visited, excluded_kinds = set(), set(), {}

    def issue(path, status):
        issues.append({"path": relpath(path, root), "status": status})

    def reserve(path):
        if path in scheduled:
            return True
        if len(scheduled) >= _HYGIENE_MAX_ENTRIES:
            issue(root, "entry_limit")
            return False
        scheduled.add(path)
        return True

    def walk(candidate, recursive):
        if not reserve(candidate):
            return
        pending = [candidate]
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            # Lexical containment precedes every metadata/read operation.
            if not path.is_relative_to(root):
                issue(path, "outside_root")
                continue
            if len(path.relative_to(root).parts) > _HYGIENE_MAX_DEPTH:
                issue(path, "depth_limit")
                continue
            try:
                # Check ancestors from root outward: never stat through a link.
                ancestry = [n for n in reversed([path, *path.parents]) if n.is_relative_to(root)]
                linked, excluded_ancestor = None, False
                for ancestor in ancestry:
                    metadata = ancestor.lstat()
                    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                        linked = ancestor
                        break
                    if ancestor != path and is_excluded(ancestor, root, excluded, globs):
                        excluded_ancestor = True
                        break
                if excluded_ancestor:
                    inventory[path] = "excluded"
                    continue
                if linked is not None and is_excluded(path, root, excluded, globs):
                    inventory[path] = "excluded"
                    continue
                if linked is not None:
                    if secret and linked == path and _scan_suffix(path, suffixes, True):
                        inventory[path] = "selected"
                        files.add(path)  # lstat refusal by scanner, without target read
                    else:
                        issue(path, "symlink")
                        inventory[path] = "unassessed_link"
                    continue
                mode = path.lstat().st_mode
                if is_excluded(path, root, excluded, globs):
                    inventory[path] = "excluded"
                    excluded_kinds[path] = "directory" if stat.S_ISDIR(mode) else "file"
                    continue  # Never enumerate excluded descendants.
                if stat.S_ISDIR(mode):
                    inventory[path] = "directory"
                    if not recursive and path != root:
                        continue
                    children = []
                    # Consume at most the entry budget plus one refusal witness;
                    # do not materialize an unbounded directory before sorting.
                    with os.scandir(path) as entries:
                        for entry in entries:
                            child = path / entry.name
                            if not reserve(child):
                                break
                            children.append(child)
                    pending.extend(reversed(sorted(children)))
                elif stat.S_ISREG(mode):
                    selected = _scan_suffix(path, suffixes, secret)
                    inventory[path] = "selected" if selected else "unselected_suffix"
                    if selected:
                        files.add(path)
                else:
                    issue(path, "nonregular")
            except FileNotFoundError:
                issue(path, "missing_root" if path == candidate else "discovery_error")
            except OSError:
                issue(path, "discovery_error")

    # Duplicate and overlapping roots share both work accounting and visited entries.
    selected_roots = set()
    selectors, truncated = _hygiene_roots(rules, roots)
    if truncated:
        issue(root, "selector_limit")
    for raw in selectors:
        if raw in selected_roots:
            continue
        selected_roots.add(raw)
        candidate = _hygiene_selector(root, raw)
        if candidate is None:
            issues.append({"path": str(raw), "status": "outside_root"})
        else:
            walk(candidate, True)
    if secret:
        walk(root, False)  # Root entry accounting shares the same finite budget.
    return sorted(files), inventory, list({(row["path"], row["status"]): row for row in issues}.values()), excluded_kinds


def _scope_findings(issues, name, severity):
    return [finding(finding_id=f"{name}.discovery.{row['status']}.{hashlib.sha256(row['path'].encode()).hexdigest()[:16]}", severity="advisory" if row["status"] == "missing_root" else severity,
                    status=row["status"], path=row["path"],
                    message="Configured scan discovery was not assessed; no linked or outside-root content was read.")
            for i, row in enumerate(issues)]


def _scan_suffix(path: Path, suffixes: set[str], include_dotenv: bool = False) -> bool:
    return is_secret_scan_file(path, suffixes) if include_dotenv else path.suffix in suffixes


def relpath(path: Path, root: Path) -> str:
    """Render report paths consistently without rewriting POSIX filename characters."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


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


def assign_secret_finding_ids(findings: list[dict[str, Any]]) -> None:
    """Report-local labels in final array order; never credential/provenance IDs."""
    for ordinal, item in enumerate(findings, start=1):
        item["id"] = f"SH-{ordinal}"
        item["id_scheme"] = "report_ordinal_v1"


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
    known_gaps: list[str] | None = None,
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
        "known_gaps": known_gaps or [],
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
    pass_policy: bool = False,
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
    selected_kwargs = {"policy": policy} if pass_policy else {}
    report = builder(root=root, profile=profile, naos_root=naos_root, rules=rules, rules_path=rules_path, severity=severity, **selected_kwargs)
    if report.get("schema") != schema:
        report["schema"] = schema
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, report_key)
    if output is not None:
        write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        input_detail = ""
        if "coverage_status" in summary:
            input_detail = (
                f"; scan inputs: {summary['coverage_status']}; selected {summary['files_selected']}, "
                f"scanned {summary['files_scanned']}, failed {summary['files_failed']}"
            )
        print(
            f"NAOS {summary_label}: {report['status']} "
            f"({summary.get('total_findings', 0)} findings{input_detail}) -> {output}"
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


class _AlphaFunction(ast.NodeTransformer):
    """Bounded lexical binding normalization; never execute project code.

    Attributes, literals, imports, globals, defaults and annotations retain their
    spelling. Nested function/class/lambda scopes and dynamic local inspection
    are deliberately unassessed by this supplementary advisory tier.
    """
    def __init__(self, node):
        self.scopes = [{}]
        self.serial = 0
        excluded = set()
        for child in ast.walk(node):
            if isinstance(child, (ast.Global, ast.Nonlocal)):
                excluded.update(child.names)
            elif isinstance(child, ast.Import):
                excluded.update(alias.asname or alias.name.split(".")[0] for alias in child.names)
            elif isinstance(child, ast.ImportFrom):
                excluded.update(alias.asname or alias.name for alias in child.names)
        self.excluded = excluded
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg: arguments.append(node.args.vararg)
        if node.args.kwarg: arguments.append(node.args.kwarg)
        for arg in arguments:
            self.bind(arg.arg)
        # A comprehension owns its targets; do not leak them into function scope.
        pending = list(reversed(node.body))
        while pending:
            child = pending.pop()
            if isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                self.bind(child.id)
            elif isinstance(child, ast.ExceptHandler) and child.name:
                self.bind(child.name)
            pending.extend(reversed(list(ast.iter_child_nodes(child))))

    def bind(self, name):
        if name not in self.excluded and name not in self.scopes[-1]:
            # These cannot collide with any identifier accepted by Python syntax.
            self.scopes[-1][name] = "$naos_local_" + str(self.serial) + "$"
            self.serial += 1

    def mapped(self, name):
        return next((scope[name] for scope in reversed(self.scopes) if name in scope), name)

    def visit_Name(self, node):
        node.id = self.mapped(node.id)
        return node

    def visit_ExceptHandler(self, node):
        if node.name: node.name = self.mapped(node.name)
        return self.generic_visit(node)

    def visit_comprehension_scope(self, node):
        self.scopes.append({})
        try:
            for index, generator in enumerate(node.generators):
                if index == 0:
                    inner = self.scopes.pop()
                    generator.iter = self.visit(generator.iter)
                    self.scopes.append(inner)
                else:
                    generator.iter = self.visit(generator.iter)
                for target in ast.walk(generator.target):
                    if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store): self.bind(target.id)
                generator.target = self.visit(generator.target)
                generator.ifs = [self.visit(value) for value in generator.ifs]
            for field in ("elt", "key", "value"):
                if hasattr(node, field): setattr(node, field, self.visit(getattr(node, field)))
            return node
        finally:
            self.scopes.pop()

    visit_ListComp = visit_comprehension_scope
    visit_SetComp = visit_comprehension_scope
    visit_DictComp = visit_comprehension_scope
    visit_GeneratorExp = visit_comprehension_scope


def _alpha_normalized_dump(node):
    unsupported = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                   ast.NamedExpr, ast.Match)
    for statement in node.body:
        for child in ast.walk(statement):
            if isinstance(child, unsupported): return None
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in {"eval", "exec", "locals", "globals", "vars", "dir"}:
                return None
    clone = copy.deepcopy(node)
    normalizer = _AlphaFunction(clone)
    clone.name = "_function"
    clone.decorator_list = []
    # Return annotations stay significant only in this supplementary tier.
    # Defaults and annotations evaluate outside function-local scope.
    for arg in [*clone.args.posonlyargs, *clone.args.args, *clone.args.kwonlyargs,
                *([clone.args.vararg] if clone.args.vararg else []),
                *([clone.args.kwarg] if clone.args.kwarg else [])]:
        arg.arg = normalizer.mapped(arg.arg)
    clone.body = [normalizer.visit(statement) for statement in _strip_docstring(clone.body)]
    return ast.dump(clone, include_attributes=False)


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        if isinstance(body[0].value.value, str):
            return body[1:]
    return body


def _parse_python_inputs(files: list[Path], root: Path, control: str, severity: str) -> tuple[list[tuple[Path, ast.AST]], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    """Account for every selected input; Python itself interprets encoding cookies."""
    parsed: list[tuple[Path, ast.AST]] = []
    findings: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    for path in files:
        relative = relpath(path, root)
        try:
            tree = ast.parse(path.read_bytes(), filename=relative)
        except (SyntaxError, OSError, RecursionError) as exc:
            status = "read_error" if isinstance(exc, OSError) else "parse_error"
            line = max(1, exc.lineno or 1) if isinstance(exc, SyntaxError) else None
            if isinstance(exc, SyntaxError):
                reason = exc.msg
            elif isinstance(exc, OSError):
                reason = exc.strerror or type(exc).__name__
            else:
                reason = "Python parser recursion limit exceeded"
            findings.append(finding(
                finding_id=f"{control}.{status}.{relative}", severity=severity, status=status,
                message=f"Selected Python input could not be analyzed: {reason}.",
                path=relative, line=line,
            ))
            inputs.append({"path": relative, "status": status})
        else:
            parsed.append((path, tree))
            inputs.append({"path": relative, "status": "parsed"})
    summary = {
        "files_selected": len(files),
        "files_scanned": len(parsed),
        "files_failed": len(findings),
        "parse_errors": sum(item["status"] == "parse_error" for item in inputs),
        "read_errors": sum(item["status"] == "read_error" for item in inputs),
        "coverage_status": "incomplete" if findings else ("complete" if files else "not_configured"),
    }
    return parsed, findings, summary, inputs


def inferred_python_scope(root: Path, rules: dict[str, Any]):
    """Bounded metadata inventory; infer adopter layouts, never tool ownership."""
    audit = dict(rules, scan_roots=["."])
    audit["exclude_dirs"] = list(set(rules.get("exclude_dirs") or []) | {".naos"})
    discovered, inventory, issues, _ = _hygiene_scope(root, audit, ["."], {".py"})
    inferred, declaration_issues = inferred_adopter_python_files(root, inventory=inventory)
    return inferred, inventory, issues + declaration_issues


def _python_scan_scope(root: Path, rules: dict[str, Any], name: str, severity: str):
    inferred, inventory, issues = inferred_python_scope(root, rules)
    aliases = native_adopter_root_aliases(root, (path.relative_to(root).parts[0] for path in inventory if path != root))
    value = rules.get("scan_roots", "inferred")
    if value == "inferred":
        files = inferred
    else:
        selectors, truncated = _hygiene_roots(rules, PYTHON_ROOTS)
        roots = [_hygiene_selector(root, raw) for raw in selectors]
        for index, selected in enumerate(roots):
            if selected is None:continue
            parts = selected.relative_to(root).parts
            if not parts or selected in inventory:continue
            canonical = native_adopter_root_aliases(root, [parts[0]]).get(parts[0])
            physical = next((name for name, known in aliases.items() if known == canonical), None)
            if physical is not None:roots[index] = root / physical / Path(*parts[1:])
        selector_states = []
        for raw, selected in zip(selectors, roots):
            if selected is None:
                issues.append({"path": raw, "status": "outside_root"})
                selector_states.append({"path": raw, "status": "outside_root"})
            elif selected not in inventory:
                # Do not probe through absent/pruned/unassessed ancestors. A
                # promised Python file must not disappear from coverage, even
                # when bounded metadata cannot prove whether it is absent.
                status = "unassessed_selected_file" if selected.suffix == ".py" else "missing_root"
                issues.append({"path": raw, "status": status})
                selector_states.append({"path": raw, "status": status})
            else:
                selector_states.append({"path": raw, "status": inventory[selected]})
        if truncated:issues.append({"path": ".", "status": "selector_limit"})
        files = sorted(path for path, state in inventory.items() if state == "selected" and
                       any(selected is not None and (path == selected or path.is_relative_to(selected)) for selected in roots))
    omitted = sorted(set(inferred) - set(files))
    findings = _scope_findings(issues, name, severity)
    if omitted:
        findings.append(finding(finding_id=name + ".omitted_python_inputs", severity=severity,
                                status="omitted_python_inputs", message="Configured selection omits inferred adopter Python inputs; applicability requires review."))
    non_python = sorted(relpath(path, root) for path, state in inventory.items()
                        if state == "unselected_suffix" and path.suffix.lower() in {".ts", ".tsx", ".js", ".java", ".kt", ".go", ".cs", ".rb", ".php", ".rs", ".c", ".cpp"}
                        and (len(path.relative_to(root).parts) == 1 or path.relative_to(root).parts[0] in aliases))
    if not files and non_python:
        findings.append(finding(finding_id=name + ".unsupported_language", severity=severity,
                                status="unsupported_language", message="No selected Python input; detected adopter source languages are not analyzed by this Python AST control."))
    scope = {"native_root_aliases": aliases, "scope_basis": "inferred_adopter_layout" if value == "inferred" else "explicit_selection",
             "selector_states": [] if value == "inferred" else selector_states,
             "analysis_language": "python_ast_only", "omitted_python_inputs": [relpath(path, root) for path in omitted],
             "unsupported_language_files": non_python, "discovery_issues": issues,
             "scope_limit": "Common source roots, top-level Python packages and flat Python files only; unknown layouts/languages remain unassessed. Metadata discovery shares a 50000-entry/64-depth no-follow budget; excluded/vendor/private descendants are pruned. Generated scripts are not inferred merely from their directory name."}
    return files, findings, scope


def _python_scope_summary(summary, scope):
    summary["omitted_python_files"] = len(scope["omitted_python_inputs"])
    summary["discovery_errors"] = sum(row["status"] != "missing_root" for row in scope["discovery_issues"])
    if summary["omitted_python_files"] or summary["discovery_errors"]:
        summary["coverage_status"] = "incomplete"


def check_duplicate_function_hygiene(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    files, discovery_findings, scope = _python_scan_scope(root, rules, "duplicate_function_hygiene", severity)
    min_dump_length = int(rules.get("min_normalized_dump_length") or 240)
    allowed_hashes = {str(item) for item in rules.get("allowed_hashes") or []}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    renamed_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    allowed_renamed = {str(item) for item in rules.get("allowed_renamed_hashes") or []}
    alpha_unassessed = []
    parsed, findings, input_summary, inputs = _parse_python_inputs(files, root, "duplicate_function_hygiene", severity)
    findings.extend(discovery_findings)
    _python_scope_summary(input_summary, scope)
    input_summary["analysis_errors"] = 0
    inputs_by_path = {item["path"]: item for item in inputs}
    functions_scanned = 0
    for path, tree in parsed:
        relative = relpath(path, root)
        members = []
        alpha_members = []
        unassessed = []
        try:
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
                members.append({
                    "path": relative,
                    "line": int(getattr(node, "lineno", 0) or 0),
                    "function": node.name,
                    "hash": digest,
                })
                if rules.get("renamed_identifier_review", True):
                    alpha_dump = _alpha_normalized_dump(node)
                    if alpha_dump is None:
                        unassessed.append({"path": relative, "line": node.lineno, "function": node.name})
                    elif digest not in allowed_hashes:
                        alpha_digest = hashlib.sha256(alpha_dump.encode("utf-8")).hexdigest()
                        alpha_members.append((alpha_digest, dict(members[-1])))
        except RecursionError:
            findings.append(finding(
                finding_id=f"duplicate_function_hygiene.analysis_error.{relative}",
                severity=severity, status="analysis_error", path=relative,
                message="Selected Python input exceeded the recursion limit during duplicate analysis.",
            ))
            inputs_by_path[relative]["status"] = "analysis_error"
            input_summary["files_scanned"] -= 1
            input_summary["files_failed"] += 1
            input_summary["analysis_errors"] += 1
            input_summary["coverage_status"] = "incomplete"
            continue
        # Publish this file's members only after its whole analysis succeeds.
        functions_scanned += len(members)
        for member in members:
            groups[member["hash"]].append(member)
        alpha_unassessed.extend(unassessed)
        for alpha_digest, member in alpha_members:
            renamed_groups[alpha_digest].append(member)
    duplicate_groups = []
    for digest, members in sorted(groups.items()):
        if len(members) < 2 or digest in allowed_hashes:
            continue
        duplicate_groups.append({"hash": digest, "members": members})
        first = members[0]
        findings.append(
            finding(
                finding_id=f"duplicate_function_hygiene.{digest[:12]}",
                severity=severity,
                status="duplicate_function_body",
                message="Normalized function body appears at multiple locations and requires duplicate-triage review.",
                path=first["path"],
                line=first["line"],
                extra={"duplicate_group": members, "confidence": "exact_normalized_ast"},
            )
        )
    renamed_duplicate_groups = []
    for digest, members in sorted(renamed_groups.items()):
        # Exact-only groups retain their established hashes/tier and are not repeated.
        if len({member["hash"] for member in members}) < 2 or digest in allowed_renamed:
            continue
        renamed_duplicate_groups.append({"hash": digest, "members": members})
        first = members[0]
        findings.append(finding(
            finding_id=f"duplicate_function_hygiene.renamed.{digest[:12]}",
            severity="advisory", status="renamed_identifier_duplicate",
            message="Function structure matches after bounded local-binding renaming; review possible duplication. This is not semantic equivalence.",
            path=first["path"], line=first["line"],
            extra={"duplicate_group": members, "confidence": "renamed_identifier_ast", "renamed_hash": digest},
        ))
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
            **input_summary,
            "functions_scanned": functions_scanned,
            "duplicate_groups": len(duplicate_groups),
            "renamed_identifier_groups": len(renamed_duplicate_groups),
            "alpha_unassessed_functions": len(alpha_unassessed),
        },
        scans={**scope, "normalization_model": "exact_plus_bounded_lexical_local_binding_review", "renamed_identifier_groups": renamed_duplicate_groups, "alpha_unassessed_functions": alpha_unassessed, "duplicate_groups": duplicate_groups, "coverage_status": input_summary["coverage_status"], "input_files": inputs},
        known_gaps=[
            "Renamed-identifier matches are advisory; parameter names may be public keyword APIs. No behavioral or semantic equivalence is established.",
            "Nested definitions, lambdas, assignment expressions, pattern matching and direct dynamic local inspection are unassessed by the renamed tier; exact comparison remains available.",
            *[f"Unanalyzed Python input: {item['path']} ({item['status']})." for item in inputs if item["status"] != "parsed"],
        ],
    )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _line_allowed(line: str) -> bool:
    """The first unquoted trailing comment must contain only the existing marker."""
    quote: str | None = None
    index = 0
    while index < len(line):
        character = line[index]
        if character == "\\":
            index += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
        elif character in "\"'`":
            quote = character
        elif character == "#":
            return line[index + 1:].strip() == "naos: allow-secret"
        elif line.startswith("//", index):
            return line[index + 2:].strip() == "naos: allow-secret"
        index += 1
    return False


def _candidate_secret_value(text: str) -> str:
    stripped = text.strip().strip("'\"")
    return stripped.lower()


QUOTED_SECRET_LITERAL = re.compile(r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"")
BARE_ENV_REFERENCE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{\{\s*(?:env|secrets)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}")
DOTENV_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[^\s#'\"]+)\s*(?:#.*)?$")
SECRET_NAME_END = re.compile(r"(?i)(?:^|_)(?:password|passwd|pwd|secret|token|api_?key|credential)$")


def _secret_placeholder(value: str) -> bool:
    """Exact placeholder/reference forms only; defaults and mixed values are real candidates."""
    return bool(re.fullmatch(r"\[(?:ADAPT|FILL):[^\]\r\n]*\]", value)
                or BARE_ENV_REFERENCE.fullmatch(value))


def _local_document_reference(literal: str, line: str, column: int, end_column: int,
                              lines: list[str], line_index: int) -> bool:
    """Recognize safe relative document paths only in YAML reference fields."""
    if not re.fullmatch(r"(?:docs|specs)/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:md|rst|adoc)(?:#[A-Za-z0-9_-]+)?", literal):
        return False
    if not re.fullmatch(r"\s*(?:#.*)?", line[end_column:]):
        return False
    prefix = line[:column]
    reference_key = r"(?:ref|[A-Za-z_][A-Za-z0-9_]*_refs?)"
    if re.fullmatch(r"\s*(?:-\s*)?" + reference_key + r"\s*:\s*", prefix):
        return True
    if not re.fullmatch(r"\s*-\s*", prefix):
        return False
    indent = len(line) - len(line.lstrip())
    for index in range(line_index - 1, -1, -1):
        previous = lines[index]
        if not previous.strip() or previous.lstrip().startswith("#"):
            continue
        if len(previous) - len(previous.lstrip()) >= indent:
            continue
        return bool(re.fullmatch(r"\s*" + reference_key + r"\s*:\s*(?:#.*)?", previous))
    return False


_ROOT_INSTRUCTION_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "GEMINI.md"})


def _instruction_file_witness(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _instruction_alias_snapshot(path: Path, root: Path, selected: set[Path]):
    """Observe a direct root alias without resolving or reading its contents.

    This is reporting only, not ownership or host-invocation authority.
    Endpoint witnesses detect observed changes, not continuous namespace custody.
    """
    if path.parent != root or path.name not in _ROOT_INSTRUCTION_NAMES:
        raise ValueError("unsupported_instruction_alias")
    parent = root.lstat()
    link = path.lstat()
    reparse = getattr(link, "st_file_attributes", 0) & 0x400
    if (not stat.S_ISDIR(parent.st_mode)
            or getattr(parent, "st_file_attributes", 0) & 0x400
            or not stat.S_ISLNK(link.st_mode)
            or (os.name == "nt" and (not reparse or getattr(link, "st_reparse_tag", 0)
                                    != getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C)))
            or (os.name != "nt" and reparse)):
        raise ValueError("unsafe_instruction_alias")
    raw = os.readlink(path)
    # Exact one-component spelling: no traversal, absolute path or link chain.
    if raw not in _ROOT_INSTRUCTION_NAMES or raw == path.name:
        raise ValueError("unsupported_instruction_target")
    target = root / raw
    if target not in selected:
        raise ValueError("unselected_instruction_target")
    metadata = target.lstat()
    if (not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & 0x400):
        raise ValueError("unsafe_instruction_target")
    # Directory entry timestamps may change independently; object metadata may not.
    return target, (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid,
                    parent.st_gid), _instruction_file_witness(link), raw, _instruction_file_witness(metadata)


def check_secret_hygiene(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    suffixes = {str(item) for item in rules.get("suffixes") or SECRET_SUFFIXES}
    inventory: dict[Path, str] = {}
    files, inventory, discovery, excluded_kinds = _hygiene_scope(root, rules, ["."], suffixes, secret=True)
    entropy_min_length = int(rules.get("entropy_min_length") or 20)
    entropy_threshold = float(rules.get("entropy_threshold") or 4.0)
    allowed_values = {_candidate_secret_value(str(item)) for item in rules.get("allowed_values") or []}
    entropy_allowed_values = {str(item) for item in rules.get("entropy_allowed_values") or []}
    findings: list[dict[str, Any]] = _scope_findings(discovery, "secret_hygiene", severity)
    try:
        public_literals, public_vocabulary = load_public_literals(root=root, naos_root=naos_root)
    except PublicVocabularyError as error:
        public_literals = set()
        public_vocabulary = {"status": "invalid", "reason": str(error)}
        findings.append(finding(finding_id="secret_hygiene.public_vocabulary_invalid",
                                severity="blocking", status="public_vocabulary_invalid",
                                message="Shipped public-literal declaration is missing or invalid; entropy exceptions were not applied."))
    include_root = rules.get("include_root_files", True)
    if not isinstance(include_root, bool):
        findings.append(finding(finding_id="secret_hygiene.invalid_root_selection", severity=severity,
                                status="invalid_configuration", message="include_root_files must be a boolean; immediate root files were conservatively included."))
        include_root = True
    excluded = (DEFAULT_EXCLUDE_DIRS - {"dev"}) | {str(item) for item in rules.get("exclude_dirs") or []}
    globs = normalized_list(rules.get("exclude_globs"), [])
    scan_roots, _ = _hygiene_roots(rules, ["."])
    explicit = {_hygiene_selector(root, raw) for raw in scan_roots}
    explicit.discard(None)
    root_entries = []
    immediate_entries = sorted(path for path in inventory if path.parent == root)
    for path in immediate_entries:
        is_directory = inventory[path] == "directory" or excluded_kinds.get(path) == "directory"
        selected_directory = any(Path(raw) == Path(".") or Path(raw) == Path(path.name) for raw in scan_roots)
        contains_selected_root = any(Path(raw).parts and Path(raw).parts[0] == path.name for raw in scan_roots)
        status = ("excluded" if is_excluded(path, root, excluded, globs)
                  else "selected_root" if is_directory and selected_directory
                  else "contains_selected_root" if is_directory and contains_selected_root
                  else "unselected_directory" if is_directory
                  else "selected" if (path in files and (include_root or path in explicit)) or (include_root and _scan_suffix(path, suffixes, True))
                  else "unselected_file")
        root_entries.append({"path": relpath(path, root), "kind": "directory" if is_directory else "file_or_symlink", "status": status})
        if not is_directory:
            inventory[path] = status
            if status == "selected":
                files.append(path)
    files = sorted(set(files))
    if not include_root:
        files = [path for path in files if path.parent != root or path in explicit]
    managed_proof = _ScannerProofBudget(root)
    if public_vocabulary["status"] == "valid":
        public_literals.update(selected_public_audit_literals(files, root=root, naos_root=naos_root))
        public_literals.update(selected_public_reference_literals(files, root=root, naos_root=naos_root))
        public_literals.update(selected_public_derived_report_ids(files, root=root, naos_root=naos_root))
        public_literals.update(selected_public_secret_finding_literals(files, root=root))
        public_literals.update(selected_public_producer_witness_literals(files, root=root, naos_root=naos_root, context=managed_proof))
    claim_context = selected_public_claim_context(files, root=root, naos_root=naos_root, policy=policy) if public_vocabulary['status'] == 'valid' else None
    waivers: list[dict[str, Any]] = []
    instruction_aliases = []
    scanned_instruction_metadata = {}
    selected_files = set(files)
    inputs: list[dict[str, Any]] = []
    regex_matches = 0
    entropy_matches = 0
    public_literal_matches = 0
    inventory_operand_matches = 0
    inventory_operand_diagnostics = []
    for path in files:
        relative = relpath(path, root)
        try:
            leaf_metadata = path.lstat()
            mode = leaf_metadata.st_mode
        except OSError:
            leaf_metadata = None
            mode = None
        if mode is None or not stat.S_ISREG(mode) or getattr(leaf_metadata, "st_file_attributes", 0) & 0x400:
            if mode is not None and stat.S_ISLNK(mode):
                try:
                    snapshot = _instruction_alias_snapshot(path, root, selected_files)
                except (OSError, ValueError):
                    pass  # Preserve the existing profile-severity refusal.
                else:
                    instruction_aliases.append((path, snapshot))
                    continue  # Never open the alias or follow its target.
            status = "symlink" if mode is not None and stat.S_ISLNK(mode) else "read_error"
            inputs.append({"path": relative, "status": status})
            findings.append(finding(finding_id=f"secret_hygiene.{status}.{relative}",
                                    severity=severity, status=status, path=relative,
                                    message="Selected file is not a regular readable file; secret scan coverage is incomplete."))
            continue
        try:
            instruction_before = path.lstat() if path.parent == root and path.name in _ROOT_INSTRUCTION_NAMES else None
            scanned_raw = path.read_bytes()
            instruction_after = path.lstat() if instruction_before is not None else None
            if instruction_before is not None and _instruction_file_witness(instruction_before) == _instruction_file_witness(instruction_after):
                scanned_instruction_metadata[path] = _instruction_file_witness(instruction_after)
            file_text = scanned_raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            lines = file_text.splitlines()
        except (OSError, UnicodeError) as error:
            status = "decode_error" if isinstance(error, UnicodeError) else "read_error"
            inputs.append({"path": relpath(path, root), "status": status})
            findings.append(finding(finding_id=f"secret_hygiene.{status}.{relpath(path, root)}",
                                    severity=severity, status=status, path=relpath(path, root),
                                    message="Selected file could not be read as UTF-8; secret scan coverage is incomplete."))
            continue
        inputs.append({"path": relpath(path, root), "status": "read",
                       "sha256": hashlib.sha256(scanned_raw).hexdigest(), "size_bytes": len(scanned_raw)})
        public_event_ids = public_audit_ids(file_text) if public_vocabulary["status"] == "valid" and path.suffix.lower() in {".json", ".jsonl"} else set()
        if public_vocabulary["status"] == "valid" and path.suffix.lower() in {".json", ".jsonl"}:
            public_event_ids.update(public_secret_finding_ids(file_text))
        operand_spans = set()
        if path.suffix.lower() == ".json":
            operand_spans, operand_diagnostic = inventory_operand_spans(file_text, relative, root, naos_root, managed_proof)
            if operand_diagnostic["status"] != "not_applicable":
                inventory_operand_diagnostics.append({"path": relative, **operand_diagnostic})
        claim_spans = public_claim_label_spans(file_text, relative, root=root, naos_root=naos_root, context=claim_context) if path.suffix.lower() == '.json' else set()
        comparison_spans = public_git_comparison_spans(file_text, relative, root=root, naos_root=naos_root, selected=files, policy=policy, context=managed_proof) if public_vocabulary['status'] == 'valid' and path.suffix.lower() == '.json' else set()
        line_offset = 0
        line_offsets = []
        for raw_line in file_text.splitlines(keepends=True):
            line_offsets.append(line_offset)
            line_offset += len(raw_line)
        for line_no, line in enumerate(lines, start=1):
            line_findings_start = len(findings)
            assigned_spans: set[tuple[int, int]] = set()
            content = line.encode("utf-8")
            for pattern_id, match, value_group in iter_secret_content_matches(content):
                rule_id = "assigned_secret" if value_group else pattern_id
                value = match.group(value_group or 0).decode("utf-8")
                normalized = _candidate_secret_value(value)
                if normalized in PLACEHOLDER_VALUES or normalized in allowed_values:
                    continue
                if value_group and _secret_placeholder(value):
                    continue
                if value_group:
                    byte_start, byte_end = match.span(value_group)
                    span = (len(content[:byte_start].decode("utf-8")), len(content[:byte_end].decode("utf-8")))
                    if span in assigned_spans:
                        continue
                    assigned_spans.add(span)
                column = len(content[:match.start()].decode("utf-8")) + 1
                regex_matches += 1
                findings.append(finding(
                    finding_id=f"secret_hygiene.{rule_id}.{relpath(path, root)}.{line_no}.{column}",
                    severity=severity, status="secret_like_pattern",
                    message=f"Secret-like pattern '{rule_id}' found in local file; rotate if real and record a reviewed waiver if fixture-only.",
                    path=relpath(path, root), line=line_no,
                    extra={"pattern_id": rule_id, "column": column},
                ))
            if path.name.lower() == ".env" or path.name.lower().startswith(".env.") or path.suffix.lower() == ".env":
                assignment = DOTENV_ASSIGNMENT.fullmatch(line)
                if assignment and SECRET_NAME_END.search(assignment.group(1)):
                    value = assignment.group(2)
                    value_span = assignment.span(2)
                    quoted = QUOTED_SECRET_LITERAL.fullmatch(value)
                    if quoted:
                        value = quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
                        value_span = (value_span[0] + 1, value_span[1] - 1)
                    if (value_span not in assigned_spans and len(value) >= 8
                            and _candidate_secret_value(value) not in allowed_values | PLACEHOLDER_VALUES
                            and not _secret_placeholder(value)):
                        column = assignment.start(2) + 1
                        regex_matches += 1
                        findings.append(finding(
                            finding_id=f"secret_hygiene.assigned_secret.{relpath(path, root)}.{line_no}.{column}",
                            severity=severity, status="secret_like_pattern", path=relpath(path, root), line=line_no,
                            message="Secret-like dotenv assignment found; review without copying its value into evidence.",
                            extra={"pattern_id": "assigned_secret", "column": column},
                        ))
            for match in QUOTED_SECRET_LITERAL.finditer(line):
                literal = match.group(1) if match.group(1) is not None else match.group(2)
                if len(literal) < entropy_min_length or any(character.isspace() for character in literal):
                    continue
                normalized = _candidate_secret_value(literal)
                if (line_offsets[line_no - 1] + match.start(), line_offsets[line_no - 1] + match.end()) in operand_spans:
                    inventory_operand_matches += 1
                    continue
                if (line_offsets[line_no - 1] + match.start(), line_offsets[line_no - 1] + match.end()) in claim_spans | comparison_spans:
                    public_literal_matches += 1
                    continue
                if literal in public_literals or literal in public_event_ids:
                    public_literal_matches += 1
                    continue
                if literal in entropy_allowed_values or normalized in allowed_values or normalized in PLACEHOLDER_VALUES or _secret_placeholder(literal):
                    continue
                literal_span = (match.start() + 1, match.end() - 1)
                if (literal_span not in assigned_spans
                        and _local_document_reference(literal, line, match.start(), match.end(), lines, line_no - 1)):
                    continue
                if not (re.search(r"[A-Za-z]", literal) and re.search(r"[0-9]", literal)):
                    continue
                entropy = shannon_entropy(literal)
                if entropy < entropy_threshold:
                    continue
                entropy_matches += 1
                findings.append(
                    finding(
                        finding_id=f"secret_hygiene.high_entropy.{relpath(path, root)}.{line_no}.{match.start() + 1}",
                        severity=severity,
                        status="high_entropy_literal",
                        message="High-entropy literal found in local file; review as possible credential or token.",
                        path=relpath(path, root),
                        line=line_no,
                        extra={"entropy": round(entropy, 3), "min_length": entropy_min_length, "column": match.start() + 1},
                    )
                )
            if _line_allowed(line):
                suppressed = [item for item in findings[line_findings_start:]
                              if item.get("pattern_id") == "assigned_secret" or item["status"] == "high_entropy_literal"]
                rule_counts: dict[str, int] = {}
                for item in suppressed:
                    rule_id = item.get("pattern_id", "high_entropy")
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                    if rule_id == "high_entropy":
                        entropy_matches -= 1
                    else:
                        regex_matches -= 1
                findings[line_findings_start:] = [item for item in findings[line_findings_start:] if item not in suppressed]
                waivers.append({"path": relative, "line": line_no, "rule_counts": rule_counts,
                                "suppressed_findings": len(suppressed), "human_review_required": True,
                                "scope": ["assigned_secret", "high_entropy"]})
                findings.append(finding(finding_id=f"secret_hygiene.inline_waiver.{relative}.{line_no}",
                                        severity="advisory", status="inline_waiver", path=relative, line=line_no,
                                        message="Trailing allow-secret comment waives assignment/entropy checks only; human review required.",
                                        extra={"suppressed_findings": len(suppressed), "rule_counts": rule_counts}))
    if not files:
        findings.append(
            finding(
                finding_id="secret_hygiene.not_configured",
                severity="advisory",
                status="not_configured",
                message="No configured files were found for secret hygiene scanning.",
            )
        )
    for alias, before in instruction_aliases:
        try:
            after = _instruction_alias_snapshot(alias, root, selected_files)
            target = before[0]
            metadata = scanned_instruction_metadata.get(target)
            target_row = next((row for row in inputs if row["path"] == relpath(target, root)
                               and row["status"] == "read"), None)
            if before != after or metadata is None or metadata != _instruction_file_witness(target.lstat()) or target_row is None:
                raise ValueError("unstable_or_unread_instruction_target")
        except (OSError, ValueError):
            inputs.append({"path": relpath(alias, root), "status": "symlink"})
            findings.append(finding(finding_id=f"secret_hygiene.symlink.{relpath(alias, root)}",
                                    severity=severity, status="symlink", path=relpath(alias, root),
                                    message="Instruction alias could not be linked to a stable selected scanned target."))
        else:
            inputs.append({"path": relpath(alias, root), "status": "symlink_to_scanned_target",
                           "target": relpath(target, root), "sha256": target_row["sha256"],
                           "size_bytes": target_row["size_bytes"]})
            findings.append(finding(finding_id=f"secret_hygiene.instruction_alias.{relpath(alias, root)}",
                                    severity="advisory", status="symlink_to_scanned_target", path=relpath(alias, root),
                                    message="Direct instruction alias refers to an already scanned selected root file; alias was not opened."))
    failed = sum(item["status"] not in {"read", "symlink_to_scanned_target"} for item in inputs)
    coverage = "incomplete" if failed or any(row["status"] != "missing_root" for row in discovery) else ("complete" if files else "not_configured")
    # Control-record allowances stay provisional until every cached proof input
    # survives the terminal observation. Refusal returns no report to the writer.
    managed_proof.finish_scanner_batch()
    assign_secret_finding_ids(findings)
    report = build_base_report(
        schema="naos.secret_hygiene.v1",
        profile=profile,
        root=root,
        naos_root=naos_root,
        rules_path=rules_path,
        findings=findings,
        summary_extra={
            "files_selected": len(files),
            "discovery_errors": sum(row["status"] != "missing_root" for row in discovery),
            "unassessed_suffix_files": sum(state == "unselected_suffix" for state in inventory.values()),
            "files_scanned": sum(item["status"] == "read" for item in inputs),
            "instruction_aliases": sum(item["status"] == "symlink_to_scanned_target" for item in inputs),
            "files_failed": failed,
            "coverage_status": coverage,
            "regex_matches": regex_matches,
            "entropy_matches": entropy_matches,
            "public_literal_matches": public_literal_matches,
            "inventory_operand_matches": inventory_operand_matches,
            "inline_waivers": len(waivers),
            "suppressed_findings": sum(item["suppressed_findings"] for item in waivers),
            "discovered_unselected_files": sum(status.startswith("unselected") for status in inventory.values()),
            "discovered_excluded_files": sum(kind == "file" for kind in excluded_kinds.values()),
            "discovered_excluded_directories": sum(kind == "directory" for kind in excluded_kinds.values()),
            "unselected_root_directories": sum(item["status"] == "unselected_directory" for item in root_entries),
            "excluded_root_directories": sum(item["kind"] == "directory" and item["status"] == "excluded" for item in root_entries),
        },
        scans={"suffixes": sorted(suffixes), "entropy_threshold": entropy_threshold,
               "include_root_files": include_root, "coverage_status": coverage, "input_files": inputs,
               "public_literals": public_vocabulary,
               "inventory_operand_proofs": inventory_operand_diagnostics,
               "entropy_scope": "Paired quoted literals without whitespace, containing letters and digits; punctuation is retained. Exact digest-bound public declarations and exact operands under observed project/executing-kit roots are excluded from entropy only. Validated public audit event IDs and content-addressed secret finding IDs are recomputed from exact producer objects; finding-body fields remain scanned. Safe relative document paths in YAML reference fields/lists retain their bounded exception. Exact independently linked managed operands and their diagnostic path echoes are excluded only at typed scalar quote coordinates after full independent proof. Proof-only reads use a separate 32MiB cache and do not improve coverage. Exact resolved Git comparison arguments are excluded only at the two schema-bound PR-risk diff_args quote coordinates in policy-selected reports or exact current hash-bound PR-family evidence carriers; this proves label consistency, not ownership, approval or evidence truth. Assignment/provider checks remain active; unknown values remain blocking by profile.",
               "scan_roots": scan_roots,
               "root_selection": [{"path": raw, "status": "outside_root" if _hygiene_selector(root, raw) is None
                                   else "excluded" if inventory.get(_hygiene_selector(root, raw)) == "excluded"
                                   else "present" if _hygiene_selector(root, raw) in inventory
                                   else "absent_optional" if any(row["path"] == relpath(_hygiene_selector(root, raw), root) and row["status"] == "missing_root" for row in discovery)
                                   else "unassessed"} for raw in scan_roots],
               "root_entries": root_entries,
               "scope_inventory": [{"path": relpath(path, root), "status": status} for path, status in sorted(inventory.items())],
               "coverage_basis": "selected_files_only",
               "excluded_directories": sorted(relpath(path, root) for path, kind in excluded_kinds.items() if kind == "directory"), "discovery_issues": discovery, "unassessed_suffix_files": sorted(relpath(path, root) for path, state in inventory.items() if state == "unselected_suffix"),
               "discovery_scope": "At most 50000 unique discovered entries (including roots and immediate root accounting), with depth at most 64 relative to project root; duplicate/overlapping roots share the budget. Exhaustion is incomplete, and the selected subset on exhaustion is filesystem enumeration order. Configured roots default to project root; excluded directories are pruned and links are never followed. Unselected/excluded file counts cover discovered leaves only; unselected directories are counted as entries, without reading their descendants. Complete means selected regular files were read and supported instruction aliases have stable already-scanned targets, never whole-repository coverage; absent optional roots are not scan errors."},
        known_gaps=[*[f"Unassessed discovery: {row['path']} ({row['status']})." for row in discovery], f"Unassessed suffix files: {sum(state == 'unselected_suffix' for state in inventory.values())}; excluded directory descendants were not enumerated.", *[f"Unanalyzed secret-scan input: {item['path']} ({item['status']})." for item in inputs if item["status"] not in {"read", "symlink_to_scanned_target"}], "Exact enrollment-label recomputation is entropy hygiene only; it does not prove ownership, authorization, valid enrollment, or authenticity.", *(["Public-literal declaration invalid; no declaration/context exceptions applied."] if public_vocabulary["status"] != "valid" else [])],
    )

    report["waivers"] = waivers
    return report


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


def _constant_truth(node: ast.AST, remaining: int = 64) -> bool | None:
    """Recognize bounded literal truth; never execute project expressions."""
    if remaining <= 0:
        return None
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _constant_truth(node.operand, remaining - 1)
        return None if value is None else not value
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = node.left, node.comparators[0]
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
            # AST constants are builtins; no user-defined comparisons are called.
            if isinstance(node.ops[0], ast.Eq):
                return left.value == right.value
            if isinstance(node.ops[0], ast.NotEq):
                return left.value != right.value
    if isinstance(node, ast.BoolOp):
        values = [_constant_truth(value, remaining - 1) for value in node.values]
        if isinstance(node.op, ast.Or) and True in values:
            return True
        if isinstance(node.op, ast.And) and False in values:
            return False
        if all(value is not None for value in values):
            return all(values) if isinstance(node.op, ast.And) else any(values)
    return None


def _qualified_name(node: ast.AST) -> str:
    segments: list[str] = []
    while isinstance(node, ast.Attribute):
        segments.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    segments.append(node.id)
    return ".".join(reversed(segments))


def _assertion_syntax(node):
    if isinstance(node, ast.Assert):
        return True, _constant_truth(node.test) is True
    if isinstance(node, ast.Raise) and node.exc is not None:
        raised = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        return _qualified_name(raised) in {"AssertionError", "builtins.AssertionError"}, False
    if isinstance(node, ast.Call):
        name, qualified = _call_name(node.func), _qualified_name(node.func)
        recognized = bool(name and name.startswith("assert") and (name in ASSERT_CALLS or name.startswith("assert_") or len(name) > 6 and name[6].isupper())) or qualified in {"raises", "fail", "pytest.raises", "pytest.fail", "self.fail"}
        trivial = False
        if recognized and node.args:
            if name == "assertTrue": trivial = _constant_truth(node.args[0]) is True
            elif name == "assertFalse": trivial = _constant_truth(node.args[0]) is False
            elif name in {"assertEqual", "assertEquals", "assertNotEqual"} and len(node.args) >= 2 and all(isinstance(arg, ast.Constant) for arg in node.args[:2]):
                equal = node.args[0].value == node.args[1].value
                trivial = equal if name != "assertNotEqual" else not equal
        return recognized, trivial
    return False, False


def _statement_flow(node, remaining=64):
    """Bounded exits for literal branches; unknown flow retains fallthrough."""
    if remaining <= 0:
        return {"fallthrough", "unknown"}
    if isinstance(node, ast.Return): return {"return"}
    if isinstance(node, ast.Raise): return {"raise"}
    if isinstance(node, (ast.Break, ast.Continue)): return {"loop_exit"}
    if isinstance(node, ast.Assert) and _constant_truth(node.test) is False: return {"raise"}
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        qualified = _qualified_name(node.value.func)
        if qualified in {"pytest.fail", "self.fail"}: return {"raise"}
        if qualified in {"pytest.skip", "pytest.xfail", "self.skipTest"}: return {"skip"}
    if isinstance(node, ast.If):
        truth = _constant_truth(node.test)
        left = _suite_flow(node.body, remaining - 1)
        right = _suite_flow(node.orelse, remaining - 1)
        return left if truth is True else right if truth is False else left | right
    # Complex control flow is not treated as guaranteed failure or termination.
    if isinstance(node, (ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
        return {"fallthrough", "unknown"}
    return {"fallthrough"}


def _suite_flow(statements, remaining=64):
    outcomes = {"fallthrough"}
    for statement in statements:
        if "fallthrough" not in outcomes: break
        outcomes = (outcomes - {"fallthrough"}) | _statement_flow(statement, remaining)
    return outcomes


def _catches_assertion(handler):
    caught = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return handler.type is None or any(_qualified_name(item) in {
        "AssertionError", "Exception", "BaseException", "builtins.AssertionError",
        "builtins.Exception", "builtins.BaseException",
    } for item in caught)


def _test_structure(node: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.AST | None = None) -> dict[str, Any]:
    """Potential effective assertion evidence, bounded by visible syntax only.

    This is not an execution count, reachability proof or intent assessment.
    Unresolved conditional paths remain potentially live; known ineffective
    assertions cannot make the evidence predicate true.
    """
    result = {"has_assertion": False, "assertion_syntax": False, "trivial": False,
              "dead": False, "swallowed": False, "early_return": False,
              "effective_assertions": 0, "skip_markers": []}
    decorator_names = {
        "pytest.mark.skip", "pytest.mark.skipif", "pytest.mark.xfail",
        "unittest.skip", "unittest.skipIf", "unittest.skipUnless", "unittest.expectedFailure",
    }
    for decorator in node.decorator_list:
        name = _qualified_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
        if name in decorator_names:
            result["skip_markers"].append({"name": name, "line": decorator.lineno, "kind": "decorator"})
    if tree is not None:
        result["skip_markers"].extend(_inherited_skip_markers(tree, node))
    disables_evidence = bool(result["skip_markers"])

    def suite(statements, dead=False, suppressed=False):
        rows = []
        for statement in statements:
            rows.append((statement, dead, suppressed))
            if "fallthrough" not in _statement_flow(statement): dead = True
        return rows

    pending = list(reversed(suite(node.body)))
    while pending:
        child, dead, suppressed = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        assertion, trivial = _assertion_syntax(child)
        if assertion:
            result["assertion_syntax"] = True
            result["dead"] |= dead
            result["trivial"] |= trivial
            if not dead and not suppressed and not trivial:
                result["effective_assertions"] += 1
        if isinstance(child, ast.Return) and not dead and not result["effective_assertions"]:
            result["early_return"] = True
        if isinstance(child, ast.Call):
            qualified = _qualified_name(child.func)
            if qualified in {"pytest.skip", "pytest.xfail", "self.skipTest"}:
                result["skip_markers"].append({"name": qualified, "line": child.lineno, "kind": "call"})
                disables_evidence |= not dead
        if isinstance(child, ast.If):
            truth = _constant_truth(child.test)
            pending.extend(reversed([(child.test, dead, suppressed),
                *suite(child.body, dead or truth is False, suppressed),
                *suite(child.orelse, dead or truth is True, suppressed)]))
            continue
        if isinstance(child, ast.While) and _constant_truth(child.test) is False:
            pending.extend(reversed([(child.test, dead, suppressed),
                *suite(child.body, True, suppressed), *suite(child.orelse, dead, suppressed)]))
            continue
        if isinstance(child, (ast.For, ast.AsyncFor, ast.While)):
            iterable = getattr(child, "iter", None)
            empty = isinstance(iterable, (ast.List, ast.Tuple, ast.Set)) and not iterable.elts
            pending.extend(reversed(suite(child.body, dead or empty, suppressed)))
            pending.extend(reversed(suite(child.orelse, dead, suppressed)))
            continue
        if isinstance(child, (ast.Try, ast.TryStar)):
            handler_loses_failure = any(
                _catches_assertion(handler) and _suite_flow(handler.body) != {"raise"}
                for handler in child.handlers)
            finally_loses_failure = "return" in _suite_flow(child.finalbody)
            body_assertion = _suite_assertion_present(child.body)
            other_assertion = (_suite_assertion_present(child.orelse)
                               or any(_suite_assertion_present(handler.body) for handler in child.handlers))
            result["swallowed"] |= (handler_loses_failure and body_assertion
                                    or finally_loses_failure and (body_assertion or other_assertion))
            # A returning finally overrides failures from every preceding suite.
            # Ordinary except handlers can only swallow failures from try.body.
            pending.extend(reversed(suite(child.body, dead, suppressed or handler_loses_failure or finally_loses_failure)))
            pending.extend(reversed(suite(child.orelse, dead, suppressed or finally_loses_failure)))
            pending.extend(reversed(suite(child.finalbody, dead, suppressed)))
            for handler in child.handlers:
                pending.extend(reversed(suite(handler.body, dead, suppressed or finally_loses_failure)))
            continue
        if isinstance(child, (ast.With, ast.AsyncWith)):
            suppresses = any(isinstance(item.context_expr, ast.Call)
                and _qualified_name(item.context_expr.func) == "contextlib.suppress"
                and any(_qualified_name(arg) in {"AssertionError", "Exception", "BaseException",
                                                   "builtins.AssertionError", "builtins.Exception", "builtins.BaseException"}
                        for arg in item.context_expr.args) for item in child.items)
            if suppresses and _suite_assertion_present(child.body): result["swallowed"] = True
            pending.extend(reversed(suite(child.body, dead, suppressed or suppresses)))
            for item in reversed(child.items): pending.append((item.context_expr, dead, suppressed))
            continue
        pending.extend((descendant, dead, suppressed or trivial) for descendant in reversed(list(ast.iter_child_nodes(child))))
    result["has_assertion"] = bool(result["effective_assertions"]) and not disables_evidence
    return result


def _suite_assertion_present(statements):
    pending = list(statements)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if _assertion_syntax(child)[0]: return True
        pending.extend(ast.iter_child_nodes(child))
    return False


def _inherited_skip_markers(tree, target):
    markers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(child is target for child in node.body):
            for decorator in node.decorator_list:
                name = _qualified_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
                if name in {"pytest.mark.skip", "pytest.mark.skipif", "pytest.mark.xfail", "unittest.skip", "unittest.skipIf", "unittest.skipUnless"}:
                    markers.append({"name": name, "line": decorator.lineno, "kind": "class_decorator"})
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
            values = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
            for value in values:
                name = _qualified_name(value.func if isinstance(value, ast.Call) else value)
                if name in {"pytest.mark.skip", "pytest.mark.skipif", "pytest.mark.xfail"}:
                    markers.append({"name": name, "line": node.lineno, "kind": "module_pytestmark"})
    return markers


def _has_assertion(node: ast.AST, tree: ast.AST | None = None) -> tuple[bool, bool]:
    """One predicate shared with the internal battery POC; no runtime proof."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False, False
    structure = _test_structure(node, tree)
    return structure["has_assertion"], structure["trivial"]


_NON_PYTHON_TEST_GLOBS = [
    "*.test.js", "*.test.jsx", "*.test.ts", "*.test.tsx",
    "*.spec.js", "*.spec.jsx", "*.spec.ts", "*.spec.tsx",
    "test_*.js", "test_*.ts", "*Test.java", "*Tests.java", "*Test.cs", "*Tests.cs",
]
_NON_PYTHON_TEST_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".java", ".cs"}
_TEST_MARKER_MAX_BYTES = 2 * 1024 * 1024


def _non_python_disable_markers(text, suffix):
    # Mask common comments and strings first; marker-looking prose is not code.
    quoted = r"//[^\n]*|/\*[\s\S]*?\*/|@\"(?:\"\"|[^\"])*\"|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"
    masked = re.sub(quoted, lambda match: "".join("\n" if char == "\n" else " " for char in match.group()), text)
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        pattern = r"\b(?:it|test|describe)\s*\.\s*(?:skip|todo)\b|\b(?:xit|xtest|xdescribe)\s*\("
    elif suffix == ".java":
        pattern = r"@(?:org\.junit\.jupiter\.api\.)?Disabled\b|@(?:org\.junit\.)?Ignore\b"
    else:
        pattern = r"\[\s*(?:(?:NUnit\.Framework|Microsoft\.VisualStudio\.TestTools\.UnitTesting)\.)?Ignore(?:Attribute)?\b|\bSkip\s*="
    return [{"line": masked.count("\n", 0, match.start()) + 1, "marker": match.group().strip()}
            for match in re.finditer(pattern, masked)]


def _scan_non_python_test_markers(root, scope, rules):
    globs = normalized_list(rules.get("non_python_test_globs"), _NON_PYTHON_TEST_GLOBS)
    rows, observations = [], []
    from fnmatch import fnmatchcase
    for path, state in sorted(scope.items()):
        if state != "unselected_suffix" or path.suffix.lower() not in _NON_PYTHON_TEST_SUFFIXES:
            continue
        relative = relpath(path, root)
        if not any(fnmatchcase(relative, pattern) or fnmatchcase(path.name, pattern) for pattern in globs):
            continue
        try:
            with path.open("rb") as stream: raw = stream.read(_TEST_MARKER_MAX_BYTES + 1)
            if len(raw) > _TEST_MARKER_MAX_BYTES:
                rows.append({"path": relative, "status": "size_limit"})
                continue
            text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
        except (OSError, UnicodeError):
            rows.append({"path": relative, "status": "read_error"})
            continue
        rows.append({"path": relative, "status": "marker_scanned"})
        for marker in _non_python_disable_markers(text, path.suffix.lower()):
            observations.append(finding(
                finding_id=f"test_quality_hygiene.non_python_disable.{relative}.{marker['line']}",
                severity="advisory", status="non_python_disable_marker", path=relative, line=marker["line"],
                message="Configured non-Python test file contains disable-marker syntax; review context and approval. Assertions and execution remain unassessed.",
                extra={"marker": marker["marker"], "evidence_basis": "bounded_lexical_disable_marker", "authorization_status": "not_assessed"},
            ))
    return globs, rows, observations


def check_test_quality_hygiene(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    files, scope, discovery, _ = _hygiene_scope(root, rules, ["tests"], {".py"})
    parsed, findings, input_summary, inputs = _parse_python_inputs(files, root, "test_quality_hygiene", severity)
    findings.extend(_scope_findings(discovery, "test_quality_hygiene", severity))
    if any(row["status"] != "missing_root" for row in discovery):
        input_summary["coverage_status"] = "incomplete"
    unassessed = sorted(relpath(path, root) for path, state in scope.items() if state == "unselected_suffix")
    if unassessed:
        input_summary["coverage_status"] = "incomplete"
    marker_globs, marker_inputs, marker_findings = _scan_non_python_test_markers(root, scope, rules)
    findings.extend(marker_findings)
    for row in marker_inputs:
        if row["status"] != "marker_scanned":
            findings.append(finding(finding_id=f"test_quality_hygiene.marker_{row['status']}.{row['path']}",
                severity="advisory", status="non_python_marker_unassessed", path=row["path"],
                message="Configured non-Python marker input could not be fully read; marker coverage is incomplete."))
    for name in unassessed:
        findings.append(finding(finding_id=f"test_quality_hygiene.unassessed.{name}", severity="advisory", status="unassessed_test_language", path=name, message="Non-Python file in a configured test root has no supported static detector; whether it is a test, its assertion quality and execution are unassessed."))
    tests_scanned = 0
    missing_assertions = 0
    trivial_assertions = 0
    skipped_tests = 0
    dead_assertions = 0
    swallowed_assertions = 0
    early_returns = 0
    tests_without_effective_assertion = 0
    tests_with_effective_assertion = 0
    for path, tree in parsed:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                tests_scanned += 1
                structure = _test_structure(node, tree)
                has_assertion = structure["has_assertion"]
                tests_with_effective_assertion += int(has_assertion)
                tests_without_effective_assertion += int(not has_assertion)
                trivial = structure["trivial"]
                for status, observed, message in (
                    ("skipped_test", bool(structure["skip_markers"]), "Test declares skip/xfail syntax; review its rationale and approval separately. This does not establish whether it executes or is newly weakened."),
                    ("dead_assertion", structure["dead"], "Assertion is in a literal-disabled branch or after a recognized unconditional exit; review its evidence value."),
                    ("early_return", structure["early_return"], "Test has a potentially live return before any observed effective assertion; review the path. Conditional returns may be legitimate."),
                    ("swallowed_assertion", structure["swallowed"], "Assertion syntax is inside a possibly suppressing handler/context or a returning finally; review exception handling. Runtime behavior is not established."),
                ):
                    if observed:
                        skipped_tests += int(status == "skipped_test")
                        dead_assertions += int(status == "dead_assertion")
                        swallowed_assertions += int(status == "swallowed_assertion")
                        early_returns += int(status == "early_return")
                        findings.append(finding(
                            finding_id=f"test_quality_hygiene.{status}.{relpath(path, root)}.{node.lineno}",
                            severity="advisory", status=status, message=message,
                            path=relpath(path, root), line=int(node.lineno),
                            extra={"evidence_basis": "python_ast_structure", "authorization_status": "not_assessed", "skip_markers": structure["skip_markers"]} if status == "skipped_test" else {"evidence_basis": "python_ast_structure"},
                        ))
                if not has_assertion and structure["assertion_syntax"]:
                    findings.append(finding(
                        finding_id=f"test_quality_hygiene.no_effective_assertion.{relpath(path, root)}.{node.lineno}",
                        severity="advisory", status="no_effective_assertion",
                        message="Visible assertion syntax is skipped, trivial, dead or caught; it cannot establish effective assertion evidence. Review remains required.",
                        path=relpath(path, root), line=int(node.lineno),
                        extra={"evidence_basis": "bounded_python_ast_evidence"},
                    ))
                if not structure["assertion_syntax"]:
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
            **input_summary,
            "test_functions_scanned": tests_scanned,
            "missing_assertions": missing_assertions,
            "trivial_assertions": trivial_assertions,
            "skipped_tests": skipped_tests,
            "dead_assertions": dead_assertions,
            "swallowed_assertions": swallowed_assertions, "early_returns": early_returns,
            "tests_with_effective_assertion": tests_with_effective_assertion,
            "tests_without_effective_assertion": tests_without_effective_assertion,
            "non_python_disable_markers": len(marker_findings),
            "unassessed_test_files": len(unassessed),
            "discovery_errors": sum(row["status"] != "missing_root" for row in discovery),
        },
        scans={"assertion_model": "bounded_python_ast_effective_assertion", "scope_basis": "explicit_configured_test_roots", "effective_scan_roots": normalized_list(rules.get("scan_roots"), ["tests"]), "non_python_marker_globs": marker_globs, "non_python_marker_inputs": marker_inputs, "non_python_assertion_coverage": "unassessed", "authorization_model": "not_assessed_compare_pr_diff_and_human_approval", "coverage_status": input_summary["coverage_status"], "input_files": inputs, "unassessed_test_files": unassessed, "discovery_issues": discovery},
        known_gaps=[
            *[f"Unassessed test file: {name}." for name in unassessed],
            *[f"Unassessed discovery: {row['path']} ({row['status']})." for row in discovery],
            "Non-Python support is configured JS/TS/Java/C# disable-marker syntax only, using UTF-8 and a 2 MiB per-file bound; assertion quality, aliases, computed properties, regex literals, C# raw strings and template interpolation are unassessed. A marker-free file is not useful test evidence.",
            "Python function-local structural observations only; no runtime reachability, alias resolution, dynamically inherited skips or arbitrary expression evaluation, or language-independent no-tampering assurance.",
            "Literal truth recognition is bounded to 64 AST levels; unrecognized expressions are not evaluated.",
            "Skip/xfail declarations may be legitimate; authorization and newly weakened contracts require baseline diff and explicit human review.",
            *[f"Unanalyzed Python input: {item['path']} ({item['status']})." for item in inputs if item["status"] != "parsed"],
        ],
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
    aliases = native_adopter_root_aliases(root, (path.relative_to(root).parts[0] for path in files if len(path.relative_to(root).parts) > 1))
    for path in files:
        names.add(path.stem)
        parts = path.relative_to(root).parts
        if parts:
            names.add(parts[0])
    for path in files:
        parts = path.relative_to(root).parts
        if len(parts) > 1 and aliases.get(parts[0]) in {"src", "app"}:
            names.add(Path(parts[1]).stem)
        elif (len(parts) == 3 and is_native_python_package_marker(path)
              and parts[0] in aliases):
            # A concrete immediate package declaration under a supported
            # source root, not arbitrary directory/module-resolution inference.
            names.add(parts[1])
    declarations, _ = declared_package_roots(root)
    for row in declarations:
        selected = [path for path in files if declared_package_selects(root, path, row)]
        if not selected:continue
        if row["name"]:names.add(row["name"].split(".")[0])
        if row["namespace"]:
            depth = len(row["root"].relative_to(root).parts)
            for path in selected:
                relative = path.relative_to(root).parts[depth:]
                if relative:names.add(Path(relative[0]).stem)
    return names


def check_dependency_integrity(*, root: Path, profile: str, naos_root: str, rules: dict[str, Any], rules_path: str | None, severity: str) -> dict[str, Any]:
    files, discovery_findings, scope = _python_scan_scope(root, rules, "dependency_integrity", severity)
    parsed, findings, input_summary, inputs = _parse_python_inputs(files, root, "dependency_integrity", severity)
    findings.extend(discovery_findings)
    _python_scope_summary(input_summary, scope)
    stdlib = _stdlib_modules()
    declared = declared_dependency_imports(root)
    first_party = first_party_modules(root, files)
    allowed = {str(item) for item in rules.get("allowed_imports") or []}
    imports_scanned = 0
    unresolved = 0
    for path, tree in parsed:
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend((alias.name.split(".")[0], int(node.lineno)) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imports.append((node.module.split(".")[0], int(node.lineno)))
        for name, line in imports:
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
            **input_summary,
            "imports_scanned": imports_scanned,
            "undeclared_or_unresolved_imports": unresolved,
            "declared_dependency_imports": len(declared),
            "first_party_modules": len(first_party),
        },
        scans={
            **scope, "coverage_status": input_summary["coverage_status"], "input_files": inputs,
            "declared_dependency_imports": sorted(declared),
            "first_party_modules": sorted(first_party),
            "allowed_imports": sorted(allowed),
        },
    )
