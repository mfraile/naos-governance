#!/usr/bin/env python3
"""Verify declared Python API symbols from local source without importing targets."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
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


SCHEMA = "naos.api_symbol_reality.v1"
MANIFEST_SCHEMA = "naos.api_symbol_reality_manifest.v1"
SOURCE_TYPES = {"source_path", "installed_distribution"}
SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
NOT_CLAIMED = [
    "API semantic correctness proof",
    "runtime behavior proof",
    "option compatibility proof",
    "endpoint behavior proof",
    "package safety proof",
    "malware detection",
    "vulnerability scanning",
    "supply-chain assurance",
    "approval",
    "certification",
    "proof of compliance",
    "hallucination prevention",
]
LIMITATIONS = [
    "V1 checks explicitly declared Python symbols only.",
    "V1 reads local Python source files and installed distribution file metadata; it does not import or execute target modules.",
    "Dynamic exports, compiled extensions, plugin registration, monkeypatching, and runtime-generated attributes may require human review or a project-specific source path.",
    "Symbol existence does not prove semantic behavior, option compatibility, endpoint behavior, package safety, or implementation correctness.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_manifest_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    configured = ((policy.get("paths") or {}).get("api_symbol_reality_manifest") or "api_symbol_reality.yaml")
    return root / naos_root / configured


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def finding(finding_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
        **extra,
    }


def load_manifest(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return {}, "manifest root must be a mapping"
    return data, None


def source_candidates_for_module(base: Path, module: str) -> list[Path]:
    parts = module.split(".")
    module_path = Path(*parts)
    if base.is_file():
        return [base]
    return [base / f"{module_path}.py", base / module_path / "__init__.py"]


def distribution_source_for_module(package: str, module: str) -> tuple[Path | None, str | None]:
    try:
        dist = importlib_metadata.distribution(package)
    except importlib_metadata.PackageNotFoundError:
        return None, "distribution_not_installed"
    except Exception as exc:
        return None, f"distribution_lookup_error: {exc}"

    files = dist.files
    if files is None:
        return None, "not_verifiable"
    module_rel = module.replace(".", "/")
    candidate_rels = {f"{module_rel}.py", f"{module_rel}/__init__.py"}
    for dist_file in files:
        rel = str(dist_file).replace("\\", "/")
        if rel in candidate_rels:
            located = Path(dist.locate_file(dist_file))
            return located if located.is_file() else None, None
    return None, "module_source_not_found"


def direct_names_in_body(body: list[ast.stmt]) -> dict[str, ast.AST]:
    names: dict[str, ast.AST] = {}
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.setdefault(stmt.name, stmt)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                for name in assignment_target_names(target):
                    names.setdefault(name, stmt)
        elif isinstance(stmt, ast.AnnAssign):
            for name in assignment_target_names(stmt.target):
                names.setdefault(name, stmt)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                exported = alias.asname or alias.name.split(".")[0]
                if exported != "*":
                    names.setdefault(exported, stmt)
    return names


def assignment_target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for item in target.elts:
            names.extend(assignment_target_names(item))
        return names
    return []


def lookup_symbol(body: list[ast.stmt], parts: list[str]) -> tuple[bool, int | None, str | None]:
    if not parts:
        return False, None, "empty_symbol"
    names = direct_names_in_body(body)
    node = names.get(parts[0])
    if node is None:
        return False, None, "symbol_not_found"
    if len(parts) == 1:
        return True, getattr(node, "lineno", None), None
    if isinstance(node, ast.ClassDef):
        return lookup_symbol(node.body, parts[1:])
    return False, getattr(node, "lineno", None), "nested_symbol_not_static"


def inspect_source(path: Path, symbol: str) -> tuple[bool, int | None, str | None]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError as exc:
        return False, exc.lineno, f"source_parse_error: {exc.msg}"
    except Exception as exc:
        return False, None, f"source_read_error: {exc}"
    return lookup_symbol(tree.body, symbol.split("."))


def normalize_entries(manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    symbols = manifest.get("symbols")
    if symbols is None:
        return [], None
    if not isinstance(symbols, list):
        return [], "symbols must be a list"
    return [item if isinstance(item, dict) else {"invalid_entry": item} for item in symbols], None


def resolve_source(entry: dict[str, Any], root: Path) -> tuple[Path | None, str, str | None]:
    source_type = str(entry.get("source_type") or ("source_path" if entry.get("source_path") else "installed_distribution"))
    module = str(entry.get("module") or "")
    if source_type == "source_path":
        raw_path = entry.get("source_path")
        if not raw_path:
            return None, source_type, "source_path_missing"
        source_root = Path(str(raw_path))
        if not source_root.is_absolute():
            source_root = root / source_root
        if not is_within(source_root, root):
            return None, source_type, "source_path_outside_project"
        for candidate in source_candidates_for_module(source_root, module):
            if candidate.is_file():
                return candidate.resolve(), source_type, None
        return None, source_type, "module_source_not_found"
    if source_type == "installed_distribution":
        package = str(entry.get("package") or "")
        if not package:
            return None, source_type, "package_missing"
        source_path, error = distribution_source_for_module(package, module)
        return source_path, source_type, error
    return None, source_type, "unsupported_source_type"


def validate_entry(entry: dict[str, Any], index: int, severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    entry_id = str(entry.get("id") or f"entry_{index}")
    for field in ("id", "module", "symbol"):
        if not entry.get(field):
            findings.append(
                finding(
                    f"api_symbol_reality.manifest_missing_field.{entry_id}.{field}",
                    severity,
                    "manifest_entry_missing_field",
                    f"API symbol manifest entry '{entry_id}' is missing required field '{field}'.",
                    entry_id=entry_id,
                    field=field,
                )
            )
    symbol = str(entry.get("symbol") or "")
    if symbol and not SYMBOL_RE.match(symbol):
        findings.append(
            finding(
                f"api_symbol_reality.invalid_symbol.{entry_id}",
                severity,
                "invalid_symbol",
                f"API symbol manifest entry '{entry_id}' has an unsupported symbol path '{symbol}'.",
                entry_id=entry_id,
                symbol=symbol,
            )
        )
    source_type = str(entry.get("source_type") or ("source_path" if entry.get("source_path") else "installed_distribution"))
    if source_type not in SOURCE_TYPES:
        findings.append(
            finding(
                f"api_symbol_reality.unsupported_source_type.{entry_id}",
                severity,
                "unsupported_source_type",
                f"API symbol manifest entry '{entry_id}' uses unsupported source_type '{source_type}'.",
                entry_id=entry_id,
                source_type=source_type,
            )
        )
    return findings


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    manifest_path: Path,
) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings: list[dict[str, Any]] = []
    manifest, manifest_error = load_manifest(manifest_path)
    manifest_present = manifest_path.exists()
    entries: list[dict[str, Any]] = []
    configured = False
    checked_symbols: list[dict[str, Any]] = []

    if manifest_error:
        findings.append(
            finding(
                "api_symbol_reality.manifest_invalid",
                severity,
                "manifest_invalid",
                f"API symbol reality manifest could not be loaded: {manifest_error}",
                manifest_path=relative(manifest_path, root),
            )
        )
        configured = True
    elif manifest is not None:
        entries, entries_error = normalize_entries(manifest)
        if entries_error:
            findings.append(
                finding(
                    "api_symbol_reality.manifest_symbols_invalid",
                    severity,
                    "manifest_symbols_invalid",
                    f"API symbol reality manifest is invalid: {entries_error}.",
                    manifest_path=relative(manifest_path, root),
                )
            )
        configured = bool(entries)

    for index, entry in enumerate(entries, start=1):
        entry_id = str(entry.get("id") or f"entry_{index}")
        entry_findings = validate_entry(entry, index, severity)
        findings.extend(entry_findings)
        if entry_findings:
            checked_symbols.append(
                {
                    "id": entry_id,
                    "package": entry.get("package"),
                    "module": entry.get("module"),
                    "symbol": entry.get("symbol"),
                    "status": "invalid",
                    "source_type": entry.get("source_type"),
                    "source_path": entry.get("source_path"),
                    "import_executed": False,
                }
            )
            continue

        source_path, source_type, source_error = resolve_source(entry, root)
        module = str(entry.get("module") or "")
        symbol = str(entry.get("symbol") or "")
        base_record = {
            "id": entry_id,
            "package": entry.get("package"),
            "module": module,
            "symbol": symbol,
            "source_type": source_type,
            "source_path": str(source_path) if source_path and not is_within(source_path, root) else (relative(source_path, root) if source_path else entry.get("source_path")),
            "import_executed": False,
            "inspection": "python_ast_source_inspection",
        }
        if source_error or source_path is None:
            status = str(source_error or "source_unavailable")
            finding_severity = severity_for_profile(profile, policy, advisory=status == "not_verifiable")
            if status == "not_verifiable":
                message = (
                    f"Installation metadata for '{entry.get('package')}' does not include a file inventory, so API symbol "
                    f"'{module}.{symbol}' cannot be verified without importing the target. This is not a defect signal; "
                    "use distribution RECORD metadata or declare a source_path for deterministic static verification."
                )
            else:
                message = f"API symbol '{module}.{symbol}' could not be verified: {status}."
            findings.append(
                finding(
                    f"api_symbol_reality.{status}.{entry_id}",
                    finding_severity,
                    status,
                    message,
                    entry_id=entry_id,
                    package=entry.get("package"),
                    module=module,
                    symbol=symbol,
                    source_type=source_type,
                    source_path=entry.get("source_path"),
                )
            )
            checked_symbols.append({**base_record, "status": "unverified", "reason": status})
            continue

        exists, line, reason = inspect_source(source_path, symbol)
        if exists:
            checked_symbols.append({**base_record, "status": "verified", "line": line})
            continue
        status = str(reason or "symbol_not_found")
        findings.append(
            finding(
                f"api_symbol_reality.{status}.{entry_id}",
                severity,
                status,
                f"API symbol '{module}.{symbol}' was not found by static AST inspection.",
                entry_id=entry_id,
                package=entry.get("package"),
                module=module,
                symbol=symbol,
                source_type=source_type,
                source_path=base_record["source_path"],
                line=line,
            )
        )
        checked_symbols.append({**base_record, "status": "unverified", "reason": status, "line": line})

    summary = finding_counts(findings)
    summary.update(
        {
            "configured": configured,
            "manifest_present": manifest_present,
            "declared_symbols": len(entries),
            "checked_symbols": len(checked_symbols),
            "verified_symbols": sum(1 for item in checked_symbols if item.get("status") == "verified"),
            "unverified_symbols": sum(1 for item in checked_symbols if item.get("status") == "unverified"),
            "invalid_entries": sum(1 for item in checked_symbols if item.get("status") == "invalid"),
            "imports_executed": 0,
            "network_used": False,
        }
    )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "profile": profile,
        "status": status_from_counts(summary),
        "configured": configured,
        "project_root": str(root),
        "naos_root": naos_root,
        "manifest_path": str(manifest_path),
        "manifest_present": manifest_present,
        "deterministic": True,
        "imports_executed": False,
        "network_used": False,
        "cost_posture": {
            "cost_incurred_by_default": False,
            "cost_usd": 0.0,
            "external_api_required": False,
            "provider_dependency_required": False,
            "model_dependency_required": False,
            "human_approval_required_before_cost": True,
        },
        "summary": summary,
        "symbols": checked_symbols,
        "findings": findings,
        "known_gaps": [
            "Compiled extension modules, dynamic exports, monkeypatching, plugin registration, and runtime-generated attributes require human review or external evidence.",
            "V1 checks Python source symbols only and does not verify JavaScript, TypeScript, OpenAPI, REST, GraphQL, or SDK endpoint behavior.",
        ],
        "residual_risks": [
            "A symbol can exist and still behave differently from generated code assumptions.",
            "Installed distribution inspection depends on the local environment matching the project's intended dependency resolution.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify explicitly declared Python API symbols without importing target modules.")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--manifest", help="Optional explicit api_symbol_reality.yaml manifest path.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_path).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    if args.manifest:
        raw_manifest_path = Path(args.manifest)
        manifest_path = raw_manifest_path if raw_manifest_path.is_absolute() else root / raw_manifest_path
        manifest_path = manifest_path.resolve()
    else:
        manifest_path = default_manifest_path(root, naos_root, policy)
    report = build_report(root=root, profile=profile, naos_root=naos_root, policy=policy, manifest_path=manifest_path)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "api_symbol_reality_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"NAOS API symbol reality: {report['status']} "
            f"({report['summary'].get('total_findings', 0)} findings, "
            f"configured={report['configured']}, imports_executed={report['imports_executed']}) -> {output}"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
