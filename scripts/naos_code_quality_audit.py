#!/usr/bin/env python3
"""
Code Quality Audit Script.

Portable governance script — path-parameterized via NAOS_ROOT / SRC_ROOT env vars.

Identifies functions and methods exceeding the 60-line threshold, detects
duplicate function names, validates spec alignment headers, enforces architecture
boundary rules, and generates the FUNCTION_INDEX.yaml cognitive map.

Usage:
    python scripts/naos_code_quality_audit.py
    python scripts/naos_code_quality_audit.py --threshold 50
    python scripts/naos_code_quality_audit.py --report json
    python scripts/naos_code_quality_audit.py --generate-index
    python scripts/naos_code_quality_audit.py --check-duplicates
    python scripts/naos_code_quality_audit.py --check-boundaries
    python scripts/naos_code_quality_audit.py --check-spec-alignment
    python scripts/naos_code_quality_audit.py --check-arch-ownership
    python scripts/naos_code_quality_audit.py --rotate-warnings-log

Environment variables:
    NAOS_ROOT   Path to the naos/ governance directory (default: naos)
    SRC_ROOT    Path to the source directory (default: src)
"""

import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Path constants — all parameterized via environment variables
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
TOOL_ROOT = Path(__file__).resolve().parent
NAOS_ROOT = PROJECT_ROOT / os.getenv("NAOS_ROOT", "naos")
SRC_ROOT_VAL = os.getenv("SRC_ROOT", "src")
SRC_DIR = PROJECT_ROOT / SRC_ROOT_VAL
_SRC_PKG_PREFIX = SRC_ROOT_VAL + "."

DEFAULT_THRESHOLD = 60
EXCLUDE_PATTERNS = ["__pycache__", ".pyc", "migrations"]

INDEX_OUTPUT = NAOS_ROOT / "inventory" / "FUNCTION_INDEX.yaml"
ALLOWLIST_PATH = PROJECT_ROOT / "configs" / "naos_duplicate_allowlist.yaml"
SIMILARITY_INDEX_PATH = NAOS_ROOT / "inventory" / "FUNCTION_SIMILARITY_INDEX.json"
SEMANTIC_WARNINGS_LOG = NAOS_ROOT / "inventory" / "SEMANTIC_WARNINGS_LOG.csv"
THRESHOLDS_CONFIG_PATH = PROJECT_ROOT / "configs" / "thresholds.yaml"
SEMANTIC_ALLOWLIST_PATH = PROJECT_ROOT / "configs" / "naos_semantic_allowlist.yaml"
BOUNDARIES_CONFIG = PROJECT_ROOT / "configs" / "naos_architecture_boundaries.yaml"
REQUIREMENTS_SPEC = PROJECT_ROOT / "specs" / "03-requirements.md"
TASK_REGISTRY = NAOS_ROOT / "TASK_REGISTRY.yaml"

# Regex — consistent with generate_traceability_matrix.py
_REQ_HEADER_RE = re.compile(r"^## ((?:FR|NFR)-[A-Z0-9]+(?:-ENHANCED)?):", re.MULTILINE)
_IMPLEMENTS_RE = re.compile(r"Implements:\s*([^\n]+)")
_TASK_HEADER_RE = re.compile(r"Task:\s*(T-[\w-]+|GOV-\d+|P2-[\w-]+)")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FunctionInfo:
    """Information about a function or method."""

    file_path: str
    function_name: str
    class_name: Optional[str]
    line_start: int
    line_end: int
    line_count: int
    docstring_lines: int
    code_lines: int


@dataclass
class AuditReport:
    """Complete audit report."""

    threshold: int
    total_functions: int
    violations: int
    compliance_rate: float
    functions_over_threshold: List[FunctionInfo]
    summary_by_file: Dict[str, int]
    priority_refactor_list: List[FunctionInfo]


# ---------------------------------------------------------------------------
# Line-length audit
# ---------------------------------------------------------------------------


def count_function_lines(node: ast.FunctionDef) -> tuple[int, int]:
    """Count lines in a function, separating docstring from code."""
    total_lines = node.end_lineno - node.lineno + 1
    docstring_lines = 0

    if (
        node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, (ast.Str, ast.Constant))
    ):
        doc_node = node.body[0]
        if hasattr(doc_node, "end_lineno") and hasattr(doc_node, "lineno"):
            docstring_lines = doc_node.end_lineno - doc_node.lineno + 1

    return total_lines, docstring_lines


def analyze_file(file_path: Path, threshold: int) -> List[FunctionInfo]:
    """Analyze a Python file for long functions."""
    long_functions = []

    try:
        with open(file_path, encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"⚠️  Skipping {file_path}: {e}", file=sys.stderr)
        return []

    rel_path = str(file_path.relative_to(PROJECT_ROOT))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            total_lines, docstring_lines = count_function_lines(node)
            code_lines = total_lines - docstring_lines

            class_name = None
            for parent in ast.walk(tree):
                if isinstance(parent, ast.ClassDef):
                    for child in ast.iter_child_nodes(parent):
                        if child is node:
                            class_name = parent.name
                            break

            if code_lines > threshold:
                long_functions.append(
                    FunctionInfo(
                        file_path=rel_path,
                        function_name=node.name,
                        class_name=class_name,
                        line_start=node.lineno,
                        line_end=node.end_lineno,
                        line_count=total_lines,
                        docstring_lines=docstring_lines,
                        code_lines=code_lines,
                    )
                )

    return long_functions


def run_audit(threshold: int = DEFAULT_THRESHOLD) -> AuditReport:
    """Run the complete code quality audit."""
    all_long_functions = []
    total_functions = 0
    summary_by_file: Dict[str, int] = {}

    for py_file in SRC_DIR.rglob("*.py"):
        if any(pattern in str(py_file) for pattern in EXCLUDE_PATTERNS):
            continue

        try:
            with open(py_file, encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total_functions += 1
        except (SyntaxError, UnicodeDecodeError):
            continue

        long_functions = analyze_file(py_file, threshold)
        if long_functions:
            rel_path = str(py_file.relative_to(PROJECT_ROOT))
            summary_by_file[rel_path] = len(long_functions)
            all_long_functions.extend(long_functions)

    priority_list = sorted(all_long_functions, key=lambda x: x.code_lines, reverse=True)

    compliance_rate = (
        (total_functions - len(all_long_functions)) / total_functions * 100
        if total_functions > 0
        else 100.0
    )

    return AuditReport(
        threshold=threshold,
        total_functions=total_functions,
        violations=len(all_long_functions),
        compliance_rate=round(compliance_rate, 2),
        functions_over_threshold=all_long_functions,
        summary_by_file=summary_by_file,
        priority_refactor_list=priority_list[:15],
    )


def print_report(report: AuditReport, format: str = "text") -> None:
    """Print the audit report."""
    if format == "json":
        print(
            json.dumps(
                {
                    "threshold": report.threshold,
                    "total_functions": report.total_functions,
                    "violations": report.violations,
                    "compliance_rate": report.compliance_rate,
                    "priority_refactor_list": [
                        asdict(f) for f in report.priority_refactor_list
                    ],
                    "summary_by_file": report.summary_by_file,
                },
                indent=2,
            )
        )
        return

    print("=" * 80)
    print("CODE QUALITY AUDIT REPORT")
    print("=" * 80)
    print("\n📊 Summary:")
    print(f"   Threshold: {report.threshold} lines (code only, excluding docstrings)")
    print(f"   Total Functions: {report.total_functions}")
    print(f"   Violations: {report.violations}")
    print(f"   Compliance Rate: {report.compliance_rate}%")

    if report.violations == 0:
        print("\n✅ No functions exceed the threshold. Code quality target MET!")
        return

    print(
        f"\n🔴 Top {len(report.priority_refactor_list)} Functions to Refactor "
        f"(by code lines):"
    )
    print("-" * 80)
    print(f"{'#':<3} {'Lines':>6} {'File':<40} {'Function':<30}")
    print("-" * 80)

    for i, func in enumerate(report.priority_refactor_list, 1):
        func_name = (
            f"{func.class_name}.{func.function_name}"
            if func.class_name
            else func.function_name
        )
        short_path = func.file_path.replace(f"{SRC_ROOT_VAL}/", "")
        if len(short_path) > 38:
            short_path = "..." + short_path[-35:]
        if len(func_name) > 28:
            func_name = func_name[:25] + "..."
        print(f"{i:<3} {func.code_lines:>6} {short_path:<40} {func_name:<30}")

    print("\n📁 Files with Most Violations:")
    print("-" * 50)
    sorted_files = sorted(
        report.summary_by_file.items(), key=lambda x: x[1], reverse=True
    )
    for file_path, count in sorted_files[:10]:
        short_path = file_path.replace(f"{SRC_ROOT_VAL}/", "")
        print(f"   {count:>3} violations: {short_path}")

    print("\n💡 Refactoring Recommendations:")
    print("   1. Start with the top-priority functions (highest line count)")
    print("   2. Extract logical blocks into helper functions")
    print("   3. Use composition over large monolithic functions")
    print("   4. Add type hints during refactoring")
    print("   5. Write unit tests for each extracted function")
    print("=" * 80)


# ---------------------------------------------------------------------------
# Function Index Generation ("External Hippocampus")
# ---------------------------------------------------------------------------


@dataclass
class IndexEntry:
    """A function/class entry for the Function Index."""

    name: str
    kind: str
    line: int
    signature: str
    docstring_summary: str
    is_public: bool


def _get_docstring_summary(node: ast.AST) -> str:
    """Extract first line of docstring from a function/class node."""
    if (
        node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, (ast.Constant,))
        and isinstance(node.body[0].value.value, str)
    ):
        first_line = node.body[0].value.value.strip().split("\n")[0].strip()
        if len(first_line) > 100:
            return first_line[:97] + "..."
        return first_line
    return ""


def _get_signature(node: ast.FunctionDef) -> str:
    """Extract function signature as a compact string — name and arg names only."""
    args = []
    all_args = node.args.args + node.args.posonlyargs + node.args.kwonlyargs
    for arg in all_args:
        if arg.arg in ("self", "cls"):
            continue
        args.append(arg.arg)

    ret = ""
    if node.returns:
        try:
            ret_str = ast.unparse(node.returns)
            ret_str = ret_str.replace("Optional[", "?").rstrip("]")
            if len(ret_str) > 30:
                ret_str = ret_str[:27] + "..."
            ret = f" → {ret_str}"
        except Exception:
            pass

    params = ", ".join(args)
    if len(params) > 50:
        params = params[:47] + "..."
    return f"({params}){ret}"


def _build_index_for_file(file_path: Path) -> dict[str, Any]:
    """Build Function Index entries for a single Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return {}

    TAG_PATTERN = re.compile(r"^(Implements|Module|Task|Specs|Rationale|ID):")

    purpose = ""
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, (ast.Constant,))
        and isinstance(tree.body[0].value.value, str)
    ):
        doc_lines = tree.body[0].value.value.strip().split("\n")
        first_line = doc_lines[0].strip()
        if TAG_PATTERN.match(first_line):
            non_tag_lines = [
                ln.strip()
                for ln in doc_lines[1:]
                if ln.strip() and not TAG_PATTERN.match(ln.strip())
            ]
            if non_tag_lines:
                purpose = non_tag_lines[0]
            else:
                purpose = f"[TAG ONLY] {first_line}"
        else:
            purpose = first_line
        if len(purpose) > 120:
            purpose = purpose[:117] + "..."

    public_entries: list[str] = []
    classes: list[str] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            sig = _get_signature(node)
            doc_summary = _get_docstring_summary(node)
            entry = f"{node.name}{sig}"
            if doc_summary:
                if len(doc_summary) > 80:
                    doc_summary = doc_summary[:77] + "..."
                entry = f"{entry}  # {doc_summary}"
            public_entries.append(entry)

        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            methods: list[str] = []
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not child.name.startswith("_"):
                        methods.append(child.name)
            if methods:
                classes.append(f"{node.name} [{', '.join(methods)}]")
            else:
                classes.append(node.name)

    result: dict[str, Any] = {}
    if purpose:
        result["purpose"] = purpose
    if public_entries:
        result["public"] = public_entries
    if classes:
        result["classes"] = classes

    return result


def _build_import_graph() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Build import graph from all src/*.py files.

    Returns:
        (imports_graph, imported_by_graph) where:
        - imports_graph[module] = set of modules it imports
        - imported_by_graph[module] = set of modules that import it
    """
    imports_graph: dict[str, set[str]] = defaultdict(set)
    imported_by: dict[str, set[str]] = defaultdict(set)

    py_files = sorted(SRC_DIR.rglob("*.py"))
    for py_file in py_files:
        if any(pattern in str(py_file) for pattern in EXCLUDE_PATTERNS):
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        rel_path = str(py_file.relative_to(PROJECT_ROOT))
        module_path = rel_path.replace("/", ".").replace(".py", "")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(_SRC_PKG_PREFIX):
                        imports_graph[module_path].add(alias.name)
                        imported_by[alias.name].add(module_path)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith(_SRC_PKG_PREFIX):
                    imports_graph[module_path].add(node.module)
                    imported_by[node.module].add(module_path)

    return dict(imports_graph), dict(imported_by)


def _inject_used_by(index: dict[str, Any], imported_by: dict[str, set[str]]) -> None:
    """Inject used_by metadata into the function index.

    For each module in the index, adds a used_by field listing modules that
    import it. Truncates to top-5 importers to stay within token budget.
    """
    MAX_USED_BY = 5

    def _walk(node: dict[str, Any], module_prefix: str = f"{_SRC_PKG_PREFIX}") -> None:
        for key, value in node.items():
            if not isinstance(value, dict):
                continue
            is_leaf = any(k in value for k in ("public", "classes", "purpose"))
            if is_leaf:
                full_module = f"{module_prefix}{key}"
                importers = imported_by.get(full_module, set())
                if importers:
                    short = sorted(m.replace(_SRC_PKG_PREFIX, "", 1) for m in importers)
                    if len(short) > MAX_USED_BY:
                        short = short[:MAX_USED_BY] + [
                            f"+{len(short) - MAX_USED_BY} more"
                        ]
                    value["used_by"] = short
            else:
                _walk(value, f"{module_prefix}{key}.")

    _walk(index)


def _inject_anomaly_markers(index: dict[str, Any]) -> None:
    """Inject DUP markers into the function index.

    Runs duplicate detection internally and scans for duplication patterns.
    Modifies the index dict in-place by appending markers to public entries.
    """
    dup_report = check_duplicates(staged_only=False, report_format="silent")
    dup_names: dict[str, list[str]] = {}
    for item in dup_report.errors + dup_report.warnings:
        name = item["name"]
        files = [loc["file"] for loc in item["locations"]]
        dup_names[name] = files

    def _walk(node: dict[str, Any], current_path: str = "") -> None:
        for key, value in node.items():
            if not isinstance(value, dict):
                continue
            if "public" in value and isinstance(value["public"], list):
                module_file = (
                    f"{SRC_ROOT_VAL}/{current_path}{key}.py"
                    if current_path
                    else f"{SRC_ROOT_VAL}/{key}.py"
                )
                new_public = []
                for entry in value["public"]:
                    func_name = entry.split("(")[0].strip()
                    markers = []
                    if func_name in dup_names:
                        other_files = [
                            f for f in dup_names[func_name] if f != module_file
                        ]
                        if other_files:
                            markers.append(f"DUP: also in {other_files[0]}")
                    if markers:
                        base = entry.split("  # DUP:")[0].split("  # DEPRECATED")[0]
                        entry = f"{base}  # {'; '.join(markers)}"
                    new_public.append(entry)
                value["public"] = new_public
            _walk(value, f"{current_path}{key}/")

    _walk(index)


def generate_function_index(output_path: Path | None = None) -> dict[str, Any]:
    """Generate FUNCTION_INDEX.yaml — compact codebase cognitive map.

    The 'External Hippocampus' — a persistent, structured index that compensates
    for AI context window limitations.
    """
    output_path = output_path or INDEX_OUTPUT
    index: dict[str, Any] = {}

    py_files = sorted(SRC_DIR.rglob("*.py"))
    for py_file in py_files:
        if any(pattern in str(py_file) for pattern in EXCLUDE_PATTERNS):
            continue
        if py_file.name == "__init__.py":
            continue

        rel = py_file.relative_to(PROJECT_ROOT)
        file_index = _build_index_for_file(py_file)
        if not file_index:
            continue

        parts = list(rel.parts)
        if parts[0] == SRC_ROOT_VAL:
            parts = parts[1:]
        parts[-1] = parts[-1].replace(".py", "")

        current = index
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            elif not isinstance(current[part], dict):
                current[part] = {"_self": current[part]}
            current = current[part]
        current[parts[-1]] = file_index

    _, imported_by = _build_import_graph()
    _inject_used_by(index, imported_by)
    _inject_anomaly_markers(index)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    from datetime import datetime

    header = (
        f"# FUNCTION_INDEX.yaml — Codebase cognitive map\n"
        f"# Auto-generated via: python scripts/naos_code_quality_audit.py --generate-index\n"
        f"# Last refresh: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"#\n"
        f"# PURPOSE: Compact AI-readable map of all public functions/classes in {SRC_ROOT_VAL}/.\n"
        f"# Serves as 'external hippocampus' — persistent memory across AI sessions.\n"
        f"# Read this BEFORE creating new functions to avoid duplication.\n"
        f"\n"
    )

    yaml_content = yaml.dump(
        index,
        default_flow_style=False,
        sort_keys=False,
        width=120,
        allow_unicode=True,
    )

    output_path.write_text(header + yaml_content, encoding="utf-8")

    total_modules = sum(
        1
        for _ in SRC_DIR.rglob("*.py")
        if "__pycache__" not in str(_) and _.name != "__init__.py"
    )
    token_estimate = len(yaml_content.split())
    print(f"✅ Function Index generated: {output_path}")
    print(f"   Modules scanned: {total_modules}")
    print(f"   Approximate size: {len(yaml_content)} chars (~{token_estimate} tokens)")

    return index


# ---------------------------------------------------------------------------
# Duplicate Function Detection
# ---------------------------------------------------------------------------


@dataclass
class DuplicateReport:
    """Report of duplicate function names found across src/."""

    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    allowlisted: list[str] = field(default_factory=list)


def _load_allowlist() -> dict[str, list[str]]:
    """Load duplicate allowlist from configs/naos_duplicate_allowlist.yaml."""
    if not ALLOWLIST_PATH.exists():
        return {}
    try:
        with open(ALLOWLIST_PATH) as f:
            data = yaml.safe_load(f) or {}
        return data.get("allowed_duplicates", {})
    except Exception:
        return {}


def _get_package(file_path: str) -> str:
    """Extract package from relative file path."""
    parts = Path(file_path).parts[:-1]
    return ".".join(parts)


def check_duplicates(
    staged_only: bool = False,
    report_format: str = "text",
) -> DuplicateReport:
    """Scan src/ for duplicate function names.

    - Same name in SAME package → ERROR
    - Same name in DIFFERENT packages → WARNING (may be intentional)
    - Allowlisted names in configs/naos_duplicate_allowlist.yaml are skipped.
    """
    allowlist = _load_allowlist()

    MIN_NAME_LENGTH = 4

    SKIP_NAMES = {
        "__init__",
        "__str__",
        "__repr__",
        "__eq__",
        "__hash__",
        "__lt__",
        "__gt__",
        "__le__",
        "__ge__",
        "__ne__",
        "__len__",
        "__iter__",
        "__next__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__contains__",
        "__enter__",
        "__exit__",
        "__call__",
        "__bool__",
        "__getattr__",
        "__setattr__",
        "setup",
        "teardown",
        "setUp",
        "tearDown",
        "to_dict",
        "from_dict",
        "to_json",
        "from_json",
        "model_post_init",
    }

    py_files = sorted(SRC_DIR.rglob("*.py"))

    staged_files: set[str] = set()
    if staged_only:
        import subprocess

        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        staged_files = {
            f.strip()
            for f in result.stdout.strip().split("\n")
            if f.strip().endswith(".py") and f.strip().startswith(SRC_ROOT_VAL + "/")
        }

    func_index: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for py_file in py_files:
        if any(pattern in str(py_file) for pattern in EXCLUDE_PATTERNS):
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        rel_path = str(py_file.relative_to(PROJECT_ROOT))

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in SKIP_NAMES or node.name.startswith("test_"):
                    continue
                if len(node.name) <= MIN_NAME_LENGTH:
                    continue
                func_index[node.name].append(
                    {
                        "file": rel_path,
                        "line": node.lineno,
                        "args": len(node.args.args),
                        "is_method": False,
                        "class": None,
                    }
                )
            elif isinstance(node, ast.ClassDef):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if child.name in SKIP_NAMES or child.name.startswith("_"):
                            continue
                        if len(child.name) <= MIN_NAME_LENGTH:
                            continue
                        func_index[child.name].append(
                            {
                                "file": rel_path,
                                "line": child.lineno,
                                "args": len(child.args.args) - 1,
                                "is_method": True,
                                "class": node.name,
                            }
                        )

    report = DuplicateReport()

    for name, entries in func_index.items():
        if len(entries) < 2:
            continue

        if staged_only and staged_files:
            if not any(e["file"] in staged_files for e in entries):
                continue

        allowed_files = set(allowlist.get(name, []))
        if allowed_files:
            filtered = [e for e in entries if e["file"] not in allowed_files]
            if len(filtered) == 0:
                report.allowlisted.append(name)
                continue
            if len(filtered) == 1:
                report.warnings.append(
                    {
                        "name": name,
                        "severity": "WARNING",
                        "reason": (
                            f"New copy of allowlisted function in {filtered[0]['file']}"
                        ),
                        "locations": [
                            {"file": filtered[0]["file"], "line": filtered[0]["line"]}
                        ],
                    }
                )
                continue
            entries = filtered

        by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in entries:
            by_package[_get_package(entry["file"])].append(entry)

        for pkg, pkg_entries in by_package.items():
            if len(pkg_entries) > 1:
                classes = {e["class"] for e in pkg_entries if e["class"]}
                non_methods = [e for e in pkg_entries if not e["is_method"]]
                if len(classes) > 1 and not non_methods:
                    continue
                report.errors.append(
                    {
                        "name": name,
                        "severity": "ERROR",
                        "reason": f"Same function name in same package ({pkg})",
                        "locations": [
                            {
                                "file": e["file"],
                                "line": e["line"],
                                "class": e.get("class"),
                            }
                            for e in pkg_entries
                        ],
                    }
                )

        if len(by_package) > 1:
            top_level = [e for e in entries if not e["is_method"]]
            if len(top_level) > 1:
                packages = list(by_package.keys())
                report.warnings.append(
                    {
                        "name": name,
                        "severity": "WARNING",
                        "reason": (
                            f"Same function name across packages: {', '.join(packages)}"
                        ),
                        "locations": [
                            {"file": e["file"], "line": e["line"]} for e in top_level
                        ],
                    }
                )

    if report_format in ("silent", "json"):
        return report
    else:
        if report.errors:
            print(f"\n🔴 DUPLICATE ERRORS ({len(report.errors)}):")
            print("-" * 70)
            for err in report.errors:
                print(f"  {err['name']}(): {err['reason']}")
                for loc in err["locations"]:
                    cls = f" ({loc['class']})" if loc.get("class") else ""
                    print(f"    → {loc['file']}:{loc['line']}{cls}")
        if report.warnings:
            print(f"\n🟡 DUPLICATE WARNINGS ({len(report.warnings)}):")
            print("-" * 70)
            for warn in report.warnings:
                print(f"  {warn['name']}(): {warn['reason']}")
                for loc in warn["locations"]:
                    print(f"    → {loc['file']}:{loc['line']}")
        if report.allowlisted:
            print(
                f"\n⚪ Allowlisted ({len(report.allowlisted)}): "
                f"{', '.join(report.allowlisted)}"
            )
        if not report.errors and not report.warnings:
            print("✅ No duplicate functions detected.")

    return report


# ---------------------------------------------------------------------------
# Semantic Duplicate Detection (graduated)
# ---------------------------------------------------------------------------

_DEFAULT_ERROR_THRESHOLD = 0.85
_DEFAULT_WARNING_COSINE = 0.75
_DEFAULT_WARNING_JACCARD = 0.6
_DEFAULT_SAME_PACKAGE_REQUIRED = True

_WARNINGS_LOG_CAP = 2000
_WARNINGS_LOG_KEEP = 1000


def _load_semantic_thresholds() -> dict:
    """Load semantic duplicate thresholds from configs/thresholds.yaml."""
    defaults = {
        "error_threshold": _DEFAULT_ERROR_THRESHOLD,
        "warning_threshold_cosine": _DEFAULT_WARNING_COSINE,
        "warning_threshold_jaccard": _DEFAULT_WARNING_JACCARD,
        "same_package_required": _DEFAULT_SAME_PACKAGE_REQUIRED,
    }
    if not THRESHOLDS_CONFIG_PATH.exists():
        return defaults
    try:
        with open(THRESHOLDS_CONFIG_PATH, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        sd = cfg.get("semantic_duplicate", {})
        if not sd:
            return defaults
        return {
            "error_threshold": float(
                sd.get("error_threshold", defaults["error_threshold"])
            ),
            "warning_threshold_cosine": float(
                sd.get("warning_threshold_cosine", defaults["warning_threshold_cosine"])
            ),
            "warning_threshold_jaccard": float(
                sd.get(
                    "warning_threshold_jaccard", defaults["warning_threshold_jaccard"]
                )
            ),
            "same_package_required": bool(
                sd.get("same_package_required", defaults["same_package_required"])
            ),
        }
    except (yaml.YAMLError, OSError, ValueError):
        return defaults


def _load_semantic_allowlist() -> set[tuple[str, str]]:
    """Load semantic allowlist pairs from configs/naos_semantic_allowlist.yaml."""
    if not SEMANTIC_ALLOWLIST_PATH.exists():
        return set()
    try:
        with open(SEMANTIC_ALLOWLIST_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        pairs: set[tuple[str, str]] = set()
        for entry in data.get("semantic_allowlist", []):
            pair_list = entry.get("pair", [])
            if len(pair_list) == 2:
                pairs.add(tuple(sorted(pair_list)))
        return pairs
    except (yaml.YAMLError, OSError):
        return set()


def _tokenize_name(text: str) -> set[str]:
    """Split function name on _ and camelCase boundaries, lowercase."""
    if not text:
        return set()
    text = re.sub(r"([a-z])([A-Z])", r"\1_\2", text)
    tokens = re.split(r"[^a-zA-Z0-9]+", text.lower())
    return {t for t in tokens if t and len(t) > 1}


def _cosine_sim(vec_a: list[float], vec_b: list[float]) -> float:
    """Cosine similarity — pure Python (no numpy dependency for pre-commit)."""
    dot = sum(x * y for x, y in zip(vec_a, vec_b))
    norm_a = sum(x * x for x in vec_a) ** 0.5
    norm_b = sum(x * x for x in vec_b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _jaccard_sim(a: set, b: set) -> float:
    """Jaccard similarity: |intersection| / |union|."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def rotate_semantic_warnings_log(log_path: Path | None = None) -> bool:
    """Rotate SEMANTIC_WARNINGS_LOG.csv when it exceeds the 2000-row cap.

    Archives the oldest (N - 1000) rows to SEMANTIC_WARNINGS_ARCHIVE_YYYYMM.csv
    and truncates the main log to the 1000 most recent rows.
    Returns True if rotation was performed, False otherwise.
    """
    from datetime import datetime

    csv_path = log_path or SEMANTIC_WARNINGS_LOG
    if not csv_path.exists():
        return False

    lines = csv_path.read_text(encoding="utf-8").splitlines(keepends=True)
    if not lines:
        return False

    header = lines[0]
    data_rows = lines[1:]

    if len(data_rows) <= _WARNINGS_LOG_CAP:
        return False

    rows_to_archive = data_rows[: len(data_rows) - _WARNINGS_LOG_KEEP]
    rows_to_keep = data_rows[len(data_rows) - _WARNINGS_LOG_KEEP :]

    archive_name = f"SEMANTIC_WARNINGS_ARCHIVE_{datetime.now(UTC).strftime('%Y%m')}.csv"
    archive_path = csv_path.parent / archive_name
    archive_exists = archive_path.exists()
    with open(archive_path, "a", encoding="utf-8") as f:
        if not archive_exists:
            f.write(header)
        f.writelines(rows_to_archive)

    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.writelines(rows_to_keep)

    archived_count = len(rows_to_archive)
    print(
        f"[rotate_semantic_warnings_log] Archived {archived_count} rows to "
        f"{archive_path.name}. Log truncated to {len(rows_to_keep)} rows.",
        file=sys.stderr,
    )
    return True


def _log_semantic_warning(
    new_func: str, matched_func: str, score: float, method: str
) -> None:
    """Append semantic warning to CSV log for ongoing monitoring."""
    from datetime import datetime

    csv_path = SEMANTIC_WARNINGS_LOG
    write_header = not csv_path.exists()
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "a", encoding="utf-8") as f:
        if write_header:
            f.write("timestamp,new_function,matched_function,score,method\n")
        ts = datetime.now(UTC).isoformat()
        f.write(f"{ts},{new_func},{matched_func},{score:.4f},{method}\n")
    rotate_semantic_warnings_log(csv_path)


def check_semantic_duplicates(
    staged_only: bool = False,
    report: DuplicateReport | None = None,
) -> DuplicateReport:
    """Check staged functions against pre-computed similarity index.

    WARNING tier: non-blocking for semantic near-matches.
    ERROR tier: blocking for high-confidence same-package matches.
    Uses pre-computed vectors — no runtime model inference.
    Thresholds loaded from configs/thresholds.yaml (semantic_duplicate section).
    """
    if report is None:
        report = DuplicateReport()

    thresholds = _load_semantic_thresholds()
    error_threshold = thresholds["error_threshold"]
    warning_cosine = thresholds["warning_threshold_cosine"]
    warning_jaccard = thresholds["warning_threshold_jaccard"]
    same_package_required = thresholds["same_package_required"]

    allowlist = _load_semantic_allowlist()

    exact_name_allowlisted: set[str] = set()
    if ALLOWLIST_PATH.exists():
        try:
            with open(ALLOWLIST_PATH, encoding="utf-8") as f:
                al_data = yaml.safe_load(f) or {}
            for name in (al_data.get("allowed_duplicates") or {}).keys():
                exact_name_allowlisted.add(name)
        except (yaml.YAMLError, OSError):
            pass

    if not SIMILARITY_INDEX_PATH.exists():
        return report

    import time

    index_mtime = SIMILARITY_INDEX_PATH.stat().st_mtime
    age_hours = (time.time() - index_mtime) / 3600
    if age_hours > 24:
        print(
            f"⚠️  FUNCTION_SIMILARITY_INDEX.json is {age_hours:.0f}h old "
            f"(>24h). Run 'make -f Makefile.naos gov-refresh' to rebuild.",
            file=sys.stderr,
        )

    try:
        with open(SIMILARITY_INDEX_PATH, encoding="utf-8") as f:
            sim_data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return report

    entries = sim_data.get("entries", {})
    meta = sim_data.get("_meta", {})
    has_embeddings = meta.get("has_embeddings", False)

    if not entries:
        return report

    import subprocess

    staged_files: set[str] = set()
    if staged_only:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        staged_files = {
            f.strip()
            for f in result.stdout.strip().split("\n")
            if f.strip().endswith(".py") and f.strip().startswith(SRC_ROOT_VAL + "/")
        }
        if not staged_files:
            return report
    else:
        staged_files = {
            str(p.relative_to(PROJECT_ROOT))
            for p in SRC_DIR.rglob("*.py")
            if not any(pat in str(p) for pat in EXCLUDE_PATTERNS)
        }

    staged_funcs: list[dict[str, Any]] = []
    for rel_path in staged_files:
        abs_path = PROJECT_ROOT / rel_path
        if not abs_path.exists():
            continue
        try:
            source = abs_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(abs_path))
        except (SyntaxError, UnicodeDecodeError):
            continue

        parts = rel_path.replace("\\", "/").split("/")
        if len(parts) >= 3 and parts[0] == SRC_ROOT_VAL:
            pkg = parts[1]
            mod = Path(parts[-1]).stem
        else:
            continue

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_") or node.name.startswith("test_"):
                    continue
                if len(node.name) <= 4:
                    continue
                key = f"{pkg}.{mod}.{node.name}"
                staged_funcs.append(
                    {
                        "key": key,
                        "name": node.name,
                        "file": rel_path,
                        "line": node.lineno,
                        "tokens": _tokenize_name(node.name),
                    }
                )

    seen_pairs: set[tuple[str, str]] = set()
    for func in staged_funcs:
        for idx_key, idx_entry in entries.items():
            if idx_key == func["key"]:
                continue
            if idx_entry.get("module", "") == func["file"]:
                continue

            pair = tuple(sorted([func["key"], idx_key]))
            if pair in seen_pairs:
                continue

            score = 0.0
            method = "none"

            if has_embeddings and "embedding" in idx_entry:
                if func["key"] in entries and "embedding" in entries[func["key"]]:
                    score = _cosine_sim(
                        entries[func["key"]]["embedding"], idx_entry["embedding"]
                    )
                    method = "cosine"

            if method == "none":
                idx_tokens = set(idx_entry.get("tokens", [])) | set(
                    idx_entry.get("doc_tokens", [])
                )
                func_tokens = func["tokens"]
                if func_tokens and idx_tokens:
                    score = _jaccard_sim(func_tokens, idx_tokens)
                    method = "jaccard"

            threshold = warning_cosine if method == "cosine" else warning_jaccard
            if score >= threshold:
                seen_pairs.add(pair)

                severity = "WARNING"
                is_same_pkg = func["key"].split(".")[0] == idx_key.split(".")[0]
                is_in_allowlist = pair in allowlist

                func_name = func["key"].rsplit(".", 1)[-1]
                idx_name = idx_key.rsplit(".", 1)[-1]
                is_exact_allowlisted = (
                    func_name in exact_name_allowlisted
                    and idx_name in exact_name_allowlisted
                )

                if (
                    method == "cosine"
                    and score >= error_threshold
                    and (is_same_pkg or not same_package_required)
                    and not is_in_allowlist
                    and not is_exact_allowlisted
                ):
                    severity = "ERROR"

                reason_prefix = (
                    f"Semantic near-match ({method} {score:.2f}): "
                    f"{func['key']} ↔ {idx_key}"
                )
                if is_in_allowlist and method == "cosine" and score >= error_threshold:
                    reason_prefix += " [allowlisted → WARNING]"
                elif (
                    is_exact_allowlisted
                    and method == "cosine"
                    and score >= error_threshold
                ):
                    reason_prefix += " [exact-name allowlisted → WARNING]"

                match_entry = {
                    "name": func["name"],
                    "severity": severity,
                    "reason": reason_prefix,
                    "locations": [
                        {"file": func["file"], "line": func["line"]},
                        {"file": idx_entry.get("module", "?"), "line": 0},
                    ],
                }

                if severity == "ERROR":
                    report.errors.append(match_entry)
                else:
                    report.warnings.append(match_entry)

                _log_semantic_warning(func["key"], idx_key, score, method)

    return report


# ---------------------------------------------------------------------------
# Architecture Boundary Enforcement
# ---------------------------------------------------------------------------


@dataclass
class BoundaryViolation:
    """A single architecture boundary violation."""

    importer_file: str
    imported_module: str
    rule_reason: str
    severity: str
    line: int


def check_boundaries(staged_only: bool = False) -> list[BoundaryViolation]:
    """Check for forbidden import patterns per configs/naos_architecture_boundaries.yaml."""
    if not BOUNDARIES_CONFIG.exists():
        print(f"⚠️  Boundaries config not found: {BOUNDARIES_CONFIG}", file=sys.stderr)
        return []

    with open(BOUNDARIES_CONFIG) as f:
        config = yaml.safe_load(f) or {}

    rules = config.get("forbidden_imports", [])
    if not rules:
        print("✅ No boundary rules defined.")
        return []

    import fnmatch

    imports_graph, _ = _build_import_graph()

    staged_files: set[str] = set()
    if staged_only:
        import subprocess

        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        staged_files = {
            f.strip()
            for f in result.stdout.strip().split("\n")
            if f.strip().endswith(".py") and f.strip().startswith(SRC_ROOT_VAL + "/")
        }

    violations: list[BoundaryViolation] = []

    for module_path, imported_modules in imports_graph.items():
        file_path = module_path.replace(".", "/") + ".py"

        if staged_only and staged_files and file_path not in staged_files:
            continue

        for imported in imported_modules:
            imported_file = imported.replace(".", "/") + ".py"
            imported_dir = imported.replace(".", "/")

            for rule in rules:
                from_pattern = rule["from"]
                to_pattern = rule["to"]

                if not fnmatch.fnmatch(file_path, from_pattern):
                    continue

                if fnmatch.fnmatch(imported_file, to_pattern) or fnmatch.fnmatch(
                    imported_dir, to_pattern
                ):
                    violations.append(
                        BoundaryViolation(
                            importer_file=file_path,
                            imported_module=imported,
                            rule_reason=rule["reason"],
                            severity=rule.get("severity", "ERROR"),
                            line=0,
                        )
                    )

    errors = [v for v in violations if v.severity == "ERROR"]
    warnings = [v for v in violations if v.severity == "WARNING"]

    if errors:
        print(f"\n🔴 BOUNDARY ERRORS ({len(errors)}):")
        print("-" * 70)
        for v in errors:
            print(f"  {v.importer_file} → {v.imported_module}")
            print(f"    Reason: {v.rule_reason}")
    if warnings:
        print(f"\n🟡 BOUNDARY WARNINGS ({len(warnings)}):")
        print("-" * 70)
        for v in warnings:
            print(f"  {v.importer_file} → {v.imported_module}")
            print(f"    Reason: {v.rule_reason}")
    if not errors and not warnings:
        print("✅ No architecture boundary violations detected.")

    return violations


# ---------------------------------------------------------------------------
# ARCH Ownership Validation
# ---------------------------------------------------------------------------

_ARCH_REF_RE = re.compile(r"ARCH-(\d+(?:\.\d+)?)")


@dataclass
class ArchOwnershipResult:
    """Result of ARCH ownership validation."""

    warnings: list[dict[str, str]] = field(default_factory=list)
    files_checked: int = 0
    files_with_arch: int = 0
    files_missing_arch: int = 0


def _parse_arch_refs_from_file(file_path: Path) -> list[str]:
    """Parse ARCH-N references from a Python file's module header area."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    lines = source.split("\n")
    header_area = "\n".join(lines[:60])

    try:
        tree = ast.parse(source, filename=str(file_path))
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)
        ):
            doc_end = tree.body[0].end_lineno or 60
            if doc_end > 60:
                header_area = "\n".join(lines[:doc_end])
    except (SyntaxError, ValueError):
        pass

    refs: list[str] = []
    seen: set[str] = set()
    for match in _ARCH_REF_RE.finditer(header_area):
        arch_id = f"ARCH-{match.group(1)}"
        if arch_id not in seen:
            seen.add(arch_id)
            refs.append(arch_id)
    return refs


def check_arch_ownership(staged_only: bool = False) -> ArchOwnershipResult:
    """Validate that source files within ARCH component module globs
    have the correct ARCH-N reference in their module header.

    WARNING tier only (graduation path: WARNING → ERROR).
    """
    import fnmatch

    result = ArchOwnershipResult()

    if not BOUNDARIES_CONFIG.exists():
        print(f"⚠️  Boundaries config not found: {BOUNDARIES_CONFIG}", file=sys.stderr)
        return result

    with open(BOUNDARIES_CONFIG) as f:
        config = yaml.safe_load(f) or {}

    arch_components = config.get("arch_components", {})
    if not arch_components:
        print("✅ No ARCH components defined in naos_architecture_boundaries.yaml.")
        return result

    if staged_only:
        import subprocess

        git_result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        files_to_check = [
            PROJECT_ROOT / f.strip()
            for f in git_result.stdout.strip().split("\n")
            if f.strip().endswith(".py") and f.strip().startswith(SRC_ROOT_VAL + "/")
        ]
    else:
        files_to_check = sorted(SRC_DIR.rglob("*.py"))

    files_to_check = [
        f for f in files_to_check if "__pycache__" not in str(f) and f.exists()
    ]

    for file_path in files_to_check:
        rel_path = str(file_path.relative_to(PROJECT_ROOT))

        owning_archs: list[str] = []
        for arch_id, arch_data in arch_components.items():
            modules = arch_data.get("affected_modules", [])
            for pattern in modules:
                if fnmatch.fnmatch(rel_path, pattern):
                    owning_archs.append(arch_id)
                    break

        if not owning_archs:
            continue

        result.files_checked += 1

        file_arch_refs = _parse_arch_refs_from_file(file_path)

        if file_arch_refs:
            result.files_with_arch += 1
        else:
            result.files_missing_arch += 1
            result.warnings.append(
                {
                    "file": rel_path,
                    "expected_arch": ", ".join(sorted(owning_archs)),
                    "reason": (
                        f"File in scope of {', '.join(sorted(owning_archs))} "
                        f"but has no ARCH-N reference in module header"
                    ),
                }
            )

    if result.warnings:
        print(
            f"\n🟡 ARCH OWNERSHIP WARNINGS ({len(result.warnings)}) — "
            f"{result.files_checked} files checked, "
            f"{result.files_with_arch} have ARCH refs, "
            f"{result.files_missing_arch} missing:"
        )
        print("-" * 70)
        for w in result.warnings[:20]:
            print(f"  {w['file']}")
            print(f"    Expected: {w['expected_arch']}")
        if len(result.warnings) > 20:
            print(f"  ... and {len(result.warnings) - 20} more")
    else:
        print(
            f"✅ ARCH ownership validated: {result.files_checked} files checked, "
            f"{result.files_with_arch} have ARCH refs."
        )

    return result


# ---------------------------------------------------------------------------
# Spec Alignment Validation
# ---------------------------------------------------------------------------


def _load_canonical_frs() -> set[str]:
    """Load all FR/NFR IDs from specs/03-requirements.md."""
    if not REQUIREMENTS_SPEC.exists():
        print(
            f"  ⚠️  {REQUIREMENTS_SPEC} not found, skipping FR validation",
            file=sys.stderr,
        )
        return set()
    text = REQUIREMENTS_SPEC.read_text(encoding="utf-8")
    return set(_REQ_HEADER_RE.findall(text))


def _load_canonical_tasks() -> set[str]:
    """Load all task IDs from TASK_REGISTRY.yaml."""
    if not TASK_REGISTRY.exists():
        print(
            f"  ⚠️  {TASK_REGISTRY} not found, skipping task validation",
            file=sys.stderr,
        )
        return set()
    with open(TASK_REGISTRY, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    tasks = set()
    for task in data.get("tasks", []):
        tid = task.get("id", "")
        if tid:
            tasks.add(tid)
        for sub in task.get("subtasks", []):
            if isinstance(sub, dict):
                for key in sub:
                    if isinstance(key, str) and re.match(r"T-\d+", key):
                        tasks.add(key)
                sub_id = sub.get("id", "")
                if sub_id and isinstance(sub_id, str) and re.match(r"T-\d+", sub_id):
                    tasks.add(sub_id)
            elif isinstance(sub, str):
                m = re.match(r"(T-\d+-\w+)", sub)
                if m:
                    tasks.add(m.group(1))
    return tasks


def _parse_implements_from_file(file_path: Path) -> list[str]:
    """Parse FR/NFR IDs from Implements: headers in a Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    lines = source.split("\n")
    header_area = "\n".join(lines[:60])

    try:
        tree = ast.parse(source, filename=str(file_path))
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)
        ):
            doc_end = tree.body[0].end_lineno or 60
            if doc_end > 60:
                header_area = "\n".join(lines[:doc_end])
    except (SyntaxError, ValueError):
        pass

    frs: list[str] = []
    seen: set[str] = set()
    for match in _IMPLEMENTS_RE.finditer(header_area):
        line = match.group(1)
        for token in re.findall(r"(?:FR|NFR)-[A-Z0-9]+(?:-ENHANCED)?", line):
            if "XXX" in token:
                continue
            if token not in seen:
                seen.add(token)
                frs.append(token)
    return frs


def _parse_tasks_from_file(file_path: Path) -> list[str]:
    """Parse Task IDs from Task: headers in a Python file."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    lines = source.split("\n")
    header_area = "\n".join(lines[:60])

    try:
        tree = ast.parse(source, filename=str(file_path))
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)
        ):
            doc_end = tree.body[0].end_lineno or 60
            if doc_end > 60:
                header_area = "\n".join(lines[:doc_end])
    except (SyntaxError, ValueError):
        pass

    tasks: list[str] = []
    seen: set[str] = set()
    for match in _TASK_HEADER_RE.finditer(header_area):
        tid = match.group(1)
        if "XXX" in tid:
            continue
        if tid not in seen:
            seen.add(tid)
            tasks.append(tid)
    return tasks


@dataclass
class SpecAlignmentReport:
    """Report of spec alignment validation."""

    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    files_checked: int = 0


def check_spec_alignment(staged_only: bool = False) -> SpecAlignmentReport:
    """Validate Implements: FR-XXX and Task: T-XXX headers against canonical sources.

    - Nonexistent FR → ERROR
    - Nonexistent Task → WARNING
    - FR with no source reference → WARNING (orphan detection)
    """
    canonical_frs = _load_canonical_frs()
    canonical_tasks = _load_canonical_tasks()

    report = SpecAlignmentReport()

    if staged_only:
        import subprocess

        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        py_files = [
            PROJECT_ROOT / f.strip()
            for f in result.stdout.strip().split("\n")
            if f.strip().endswith(".py")
        ]
    else:
        py_files = sorted(SRC_DIR.rglob("*.py"))
        script_roots = [PROJECT_ROOT / "scripts", TOOL_ROOT]
        seen_script_roots: set[Path] = set()
        for scripts_dir in script_roots:
            resolved = scripts_dir.resolve()
            if resolved in seen_script_roots or not scripts_dir.exists():
                continue
            seen_script_roots.add(resolved)
            py_files.extend(sorted(scripts_dir.rglob("*.py")))

    for py_file in py_files:
        if any(pattern in str(py_file) for pattern in EXCLUDE_PATTERNS):
            continue
        if not py_file.exists():
            continue

        report.files_checked += 1
        rel_path = str(py_file.relative_to(PROJECT_ROOT))

        frs = _parse_implements_from_file(py_file)
        for fr_id in frs:
            if canonical_frs and fr_id not in canonical_frs:
                report.errors.append(
                    {
                        "file": rel_path,
                        "ref": fr_id,
                        "type": "FR",
                        "severity": "ERROR",
                        "reason": (
                            f"Implements: {fr_id} — not found in "
                            f"specs/03-requirements.md"
                        ),
                    }
                )

        tasks = _parse_tasks_from_file(py_file)
        for tid in tasks:
            if tid.startswith("GOV-"):
                continue
            if canonical_tasks and tid not in canonical_tasks:
                report.warnings.append(
                    {
                        "file": rel_path,
                        "ref": tid,
                        "type": "Task",
                        "severity": "WARNING",
                        "reason": (f"Task: {tid} — not found in TASK_REGISTRY.yaml"),
                    }
                )

    if not staged_only:
        all_referenced_frs: set[str] = set()
        for py_file in py_files:
            if any(pattern in str(py_file) for pattern in EXCLUDE_PATTERNS):
                continue
            if not py_file.exists():
                continue
            frs = _parse_implements_from_file(py_file)
            all_referenced_frs.update(frs)

        for fr_id in canonical_frs:
            if fr_id not in all_referenced_frs:
                report.warnings.append(
                    {
                        "file": "specs/03-requirements.md",
                        "ref": fr_id,
                        "type": "Orphan",
                        "severity": "WARNING",
                        "reason": (
                            f"Orphan: {fr_id} in specs/03 but no source files "
                            f"reference it"
                        ),
                    }
                )

    if report.errors:
        print(f"\n🔴 SPEC ALIGNMENT ERRORS ({len(report.errors)}):")
        print("-" * 70)
        for err in report.errors:
            print(f"  {err['file']}: {err['reason']}")
    if report.warnings:
        print(f"\n🟡 SPEC ALIGNMENT WARNINGS ({len(report.warnings)}):")
        print("-" * 70)
        for warn in report.warnings:
            print(f"  {warn['file']}: {warn['reason']}")
    if not report.errors and not report.warnings:
        print(f"✅ Spec alignment OK ({report.files_checked} files checked)")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Code Quality Audit — line-length, duplicates, spec alignment, boundaries"
    )
    parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Line count threshold (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--report",
        "-r",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--generate-index",
        action="store_true",
        help="Generate FUNCTION_INDEX.yaml (external hippocampus)",
    )
    parser.add_argument(
        "--check-duplicates",
        action="store_true",
        help="Check for duplicate function names across src/",
    )
    parser.add_argument(
        "--staged-only",
        action="store_true",
        help="Only check git-staged files (for pre-commit use)",
    )
    parser.add_argument(
        "--check-boundaries",
        action="store_true",
        help="Check for architecture boundary violations",
    )
    parser.add_argument(
        "--check-spec-alignment",
        action="store_true",
        help="Validate Implements: FR-XXX and Task: T-XXX headers against specs",
    )
    parser.add_argument(
        "--check-arch-ownership",
        action="store_true",
        help="Validate ARCH-N refs in module headers (WARNING tier)",
    )
    parser.add_argument(
        "--rotate-warnings-log",
        action="store_true",
        help="Rotate SEMANTIC_WARNINGS_LOG.csv when >2000 rows",
    )
    args = parser.parse_args()

    if args.generate_index:
        generate_function_index()
        sys.exit(0)

    if args.check_duplicates:
        report = check_duplicates(
            staged_only=args.staged_only,
            report_format=args.report,
        )
        check_semantic_duplicates(
            staged_only=args.staged_only,
            report=report,
        )
        if args.report == "json":
            semantic_errors = [
                e for e in report.errors if "Semantic near-match" in e.get("reason", "")
            ]
            semantic_warnings = [
                w
                for w in report.warnings
                if "Semantic near-match" in w.get("reason", "")
            ]
            exact_errors = [
                e
                for e in report.errors
                if "Semantic near-match" not in e.get("reason", "")
            ]
            exact_warnings = [
                w
                for w in report.warnings
                if "Semantic near-match" not in w.get("reason", "")
            ]
            print(
                json.dumps(
                    {
                        "errors": report.errors,
                        "warnings": report.warnings,
                        "allowlisted": report.allowlisted,
                        "error_count": len(report.errors),
                        "warning_count": len(report.warnings),
                        "semantic_quality": {
                            "semantic_errors": len(semantic_errors),
                            "semantic_warnings": len(semantic_warnings),
                            "exact_errors": len(exact_errors),
                            "exact_warnings": len(exact_warnings),
                            "health_status": (
                                "clean" if not semantic_errors else "needs_attention"
                            ),
                        },
                    },
                    indent=2,
                )
            )
            sys.exit(1 if report.errors else 0)
        if args.report != "json":
            semantic_errors = [
                e for e in report.errors if "Semantic near-match" in e.get("reason", "")
            ]
            if semantic_errors:
                print(f"\n🔴 SEMANTIC DUPLICATES — ERROR ({len(semantic_errors)}):")
                print("-" * 70)
                for e in semantic_errors:
                    print(f"  {e['reason']}")
                    for loc in e.get("locations", []):
                        if loc.get("line"):
                            print(f"    → {loc['file']}:{loc['line']}")
                        else:
                            print(f"    → {loc['file']}")
                print(
                    "\n  To suppress: add pair to configs/naos_semantic_allowlist.yaml"
                )
                print(
                    "  To disable ERROR tier: set "
                    "semantic_duplicate.error_threshold: 1.0 "
                    "in configs/thresholds.yaml"
                )

            semantic_warns = [
                w
                for w in report.warnings
                if "Semantic near-match" in w.get("reason", "")
            ]
            if semantic_warns:
                print(f"\n🔵 SEMANTIC NEAR-MATCHES ({len(semantic_warns)}):")
                print("-" * 70)
                for w in semantic_warns:
                    print(f"  {w['reason']}")
                    for loc in w.get("locations", []):
                        if loc.get("line"):
                            print(f"    → {loc['file']}:{loc['line']}")
                        else:
                            print(f"    → {loc['file']}")
        sys.exit(1 if report.errors else 0)

    if args.check_boundaries:
        violations = check_boundaries(staged_only=args.staged_only)
        errors = [v for v in violations if v.severity == "ERROR"]
        sys.exit(1 if errors else 0)

    if args.check_spec_alignment:
        report = check_spec_alignment(staged_only=args.staged_only)
        sys.exit(1 if report.errors else 0)

    if args.check_arch_ownership:
        check_arch_ownership(staged_only=args.staged_only)
        sys.exit(0)

    if args.rotate_warnings_log:
        rotate_semantic_warnings_log()
        sys.exit(0)

    # Default: line-length audit
    print(f"🔍 Running Code Quality Audit (threshold: {args.threshold} lines)...\n")
    report = run_audit(args.threshold)
    print_report(report, args.report)

    sys.exit(0 if report.violations == 0 else 1)


if __name__ == "__main__":
    main()
