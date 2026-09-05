#!/usr/bin/env python3
"""Report NAOS function-index presence, freshness, and evidence limitations."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    controlled_now_utc,
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
from source_roots import resolve_source_roots  # noqa: E402


def newest_source_mtime(source_roots: list[Path], policy: dict[str, Any]) -> float | None:
    mtimes: list[float] = []
    for root in source_roots:
        if root.is_file():
            mtimes.append(root.stat().st_mtime)
        elif root.is_dir() and not should_ignore_path(root, policy):
            for path in root.rglob("*.py"):
                if not should_ignore_path(path, policy):
                    mtimes.append(path.stat().st_mtime)
    return max(mtimes) if mtimes else None


def count_index_entries(index_path: Path) -> int | None:
    try:
        data = yaml.safe_load(index_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("functions", "entries", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
        return len(data)
    return None


def load_semantic_snapshot(paths: list[Path]) -> dict[str, Any] | None:
    for path in paths:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return {"parse_error": str(path)}
    return None


def validate(
    root: Path,
    profile: str,
    index_path: Path,
    source_roots: list[Path],
    max_age_days: int,
    semantic_snapshot_paths: list[Path],
    policy: dict[str, Any],
    naos_root: str,
) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    if is_kit_repository(root, naos_root) and not index_path.exists():
        severity = "advisory"
    findings: list[dict[str, Any]] = []
    now = controlled_now_utc().timestamp()

    index_exists = index_path.exists()
    index_mtime = index_path.stat().st_mtime if index_exists else None
    source_mtime = newest_source_mtime(source_roots, policy)
    entry_count = count_index_entries(index_path) if index_exists else None

    if not index_exists:
        findings.append(
            {
                "id": "FUNCTION-INDEX-MISSING",
                "severity": severity,
                "status": "missing_index",
                "message": f"Function index not found: {index_path}",
            }
        )
    elif entry_count == 0:
        findings.append(
            {
                "id": "FUNCTION-INDEX-EMPTY",
                "severity": severity,
                "status": "empty_index",
                "message": "Function index exists but contains no entries.",
            }
        )

    if index_mtime and source_mtime and index_mtime < source_mtime:
        findings.append(
            {
                "id": "FUNCTION-INDEX-STALE-SOURCE",
                "severity": severity,
                "status": "stale_index",
                "message": "Function index is older than at least one configured source file.",
            }
        )

    if index_mtime:
        age_days = (now - index_mtime) / 86400
        if age_days > max_age_days:
            findings.append(
                {
                    "id": "FUNCTION-INDEX-STALE-AGE",
                    "severity": severity,
                    "status": "stale_index",
                    "message": f"Function index is older than {max_age_days} days.",
                }
            )
    else:
        age_days = None

    snapshot = load_semantic_snapshot(semantic_snapshot_paths)
    duplicate_summary: dict[str, Any] = {"status": "not_configured"}
    if isinstance(snapshot, dict):
        errors = snapshot.get("errors") or []
        warnings = snapshot.get("warnings") or []
        duplicate_summary = {
            "status": "present",
            "errors": len(errors) if isinstance(errors, list) else None,
            "warnings": len(warnings) if isinstance(warnings, list) else None,
        }
        if duplicate_summary["errors"]:
            findings.append(
                {
                    "id": "SEMANTIC-QUALITY-ERRORS",
                    "severity": severity,
                    "status": "semantic_quality_errors",
                    "message": "Semantic quality snapshot contains errors.",
                }
            )

    summary = finding_counts(findings)
    status = status_from_counts(summary)

    return {
        "schema": "naos.function_index_health.v1",
        "profile": profile,
        "status": status,
        "index": {
            "path": str(index_path),
            "exists": index_exists,
            "entry_count": entry_count,
            "age_days": round(age_days, 2) if age_days is not None else None,
            "older_than_source": bool(index_mtime and source_mtime and index_mtime < source_mtime),
        },
        "semantic_quality_snapshot": duplicate_summary,
        "summary": summary,
        "findings": findings,
        "limitations": [
            "Function-index health reports available evidence only.",
            "It does not claim absence of duplicate or equivalent functions.",
            "Semantic duplicate detection depends on configured project tooling.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report NAOS function-index health.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--index")
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--semantic-snapshot", action="append", default=[])
    parser.add_argument("--max-age-days", type=int)
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
    max_age_days = args.max_age_days if args.max_age_days is not None else int(
        policy.get("evidence", {}).get("default_staleness_days") or 30
    )
    index_path = Path(args.index) if args.index else root / naos_root / "inventory" / "FUNCTION_INDEX.yaml"
    source_roots = [
        Path(path)
        for path in (args.source_root or [str(path) for path in resolve_source_roots(root)])
    ]
    semantic_paths = [Path(path) for path in args.semantic_snapshot] or [
        root / "reports" / "semantic_quality_snapshot.json",
        root / naos_root / "reports" / "semantic_quality_snapshot.json",
    ]
    report = validate(root, profile, index_path, source_roots, max_age_days, semantic_paths, policy, naos_root)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "function_index_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"NAOS function-index health: {report['status']} ({report['summary']['total_findings']} findings)")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
