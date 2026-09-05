#!/usr/bin/env python3
"""Map source files to available test and coverage evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    load_policy,
    normalize_profile,
    should_ignore_path,
    test_evidence_types,
    test_map_output_path,
    write_report,
)
from source_roots import resolve_source_roots  # noqa: E402


def collect_sources(paths: list[str], policy: dict[str, Any]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file() and path.suffix == ".py":
            files.append(path)
        elif path.is_dir() and not should_ignore_path(path, policy):
            for candidate in sorted(path.rglob("*.py")):
                if not should_ignore_path(candidate, policy) and candidate.name != "__init__.py":
                    files.append(candidate)
    return sorted(set(files))


def collect_tests(paths: list[str], policy: dict[str, Any]) -> list[Path]:
    tests: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file() and path.suffix == ".py":
            tests.append(path)
        elif path.is_dir() and not should_ignore_path(path, policy):
            for candidate in sorted(path.rglob("*.py")):
                if not should_ignore_path(candidate, policy):
                    tests.append(candidate)
    return sorted(set(tests))


def classify_test(path: Path) -> str:
    lowered = "/".join(path.parts).lower()
    if "security" in lowered:
        return "security"
    if "acceptance" in lowered or "e2e" in lowered:
        return "acceptance"
    if "integration" in lowered:
        return "integration"
    return "unit"


def detect_coverage(root: Path, explicit_paths: list[str]) -> list[str]:
    candidates = [Path(path) for path in explicit_paths]
    candidates.extend(
        [
            root / "coverage.xml",
            root / "coverage.json",
            root / ".coverage",
            root / "htmlcov",
            root / "reports" / "coverage.xml",
            root / "reports" / "coverage.json",
        ]
    )
    return [str(path) for path in candidates if path.exists()]


def parse_coverage_sources(root: Path, coverage_paths: list[str]) -> set[str] | None:
    referenced: set[str] = set()
    parsed_any = False
    for raw in coverage_paths:
        path = Path(raw)
        if not path.exists() or path.is_dir():
            continue
        if path.suffix.lower() == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            files = data.get("files") if isinstance(data, dict) else None
            if isinstance(files, dict):
                parsed_any = True
                referenced.update(str(item) for item in files)
        elif path.suffix.lower() == ".xml":
            try:
                tree = ET.parse(path)
            except Exception:
                continue
            for class_node in tree.findall(".//class"):
                filename = class_node.attrib.get("filename")
                if filename:
                    parsed_any = True
                    referenced.add(filename)
    if not parsed_any:
        return None
    normalized = set(referenced)
    for item in list(referenced):
        normalized.add(str((root / item).resolve()))
    return normalized


def possible_module_names(source: Path) -> set[str]:
    stem = source.stem
    names = {stem, f"test_{stem}", f"{stem}_test"}
    parts = list(source.with_suffix("").parts)
    if parts:
        names.add(".".join(parts))
        if "src" in parts:
            names.add(".".join(parts[parts.index("src") + 1 :]))
    return {name for name in names if name}


def test_matches_source(test: Path, source: Path, test_text_cache: dict[Path, str]) -> bool:
    source_stem = source.stem.lower()
    test_name = test.stem.lower()
    if test_name in {f"test_{source_stem}", f"{source_stem}_test"}:
        return True
    if source_stem in test_name and test_name.startswith("test"):
        return True
    text = test_text_cache.setdefault(
        test,
        test.read_text(encoding="utf-8", errors="replace") if test.exists() else "",
    )
    return any(name in text for name in possible_module_names(source))


def build_map(
    root: Path,
    profile: str,
    source_roots: list[str],
    test_roots: list[str],
    coverage_paths: list[str],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = policy or load_policy(root=root)
    sources = collect_sources(source_roots, policy)
    tests = collect_tests(test_roots, policy)
    coverage = detect_coverage(root, coverage_paths)
    coverage_sources = parse_coverage_sources(root, coverage)
    test_text_cache: dict[Path, str] = {}
    mappings: list[dict[str, Any]] = []
    type_counts = {test_type: 0 for test_type in test_evidence_types(policy)}

    for source in sources:
        matched = []
        matched_types = set()
        for test in tests:
            if test_matches_source(test, source, test_text_cache):
                test_type = classify_test(test)
                matched.append({"path": str(test), "type": test_type})
                matched_types.add(test_type)
        coverage_supports_source = str(policy.get("test_evidence", {}).get("coverage_supports_source_default") or "unknown")
        source_refs = {str(source), str(source.resolve())}
        if coverage_sources is not None and source_refs & coverage_sources:
            coverage_supports_source = "yes"
            matched_types.add("coverage")
        elif coverage_sources is not None:
            coverage_supports_source = "no"
        for test_type in matched_types:
            type_counts[test_type] += 1
        mappings.append(
            {
                "source": str(source),
                "tests": matched,
                "global_coverage_evidence": coverage,
                "coverage_supports_source": coverage_supports_source,
                "mapped": bool(matched or coverage_supports_source == "yes"),
                "evidence_types": sorted(matched_types),
            }
        )

    unmapped = [item["source"] for item in mappings if not item["mapped"]]
    status = "not_configured" if not sources else ("pass" if not unmapped else "mapped_with_gaps")
    return {
        "schema": "naos.test_evidence_map.v1",
        "profile": profile,
        "status": status,
        "source_roots": source_roots,
        "test_roots": test_roots,
        "global_coverage_evidence": coverage,
        "coverage_supports_source_default": policy.get("test_evidence", {}).get("coverage_supports_source_default", "unknown"),
        "summary": {
            "sources": len(sources),
            "tests": len(tests),
            "mapped_sources": len(sources) - len(unmapped),
            "unmapped_sources": len(unmapped),
            "evidence_type_counts": type_counts,
        },
        "mappings": mappings,
        "limitations": [
            "Mapping uses file names, paths, and simple import text heuristics.",
            "Mapped tests do not prove sufficiency or complete behavioral coverage.",
            "Global coverage evidence does not map every source unless parsed coverage references that source.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Map source files to test evidence.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--test-root", action="append", default=[])
    parser.add_argument("--coverage", action="append", default=[])
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or str(policy.get("paths", {}).get("default_naos_root") or "naos")
    profile = normalize_profile(args.profile, policy)
    source_roots = args.source_root or [str(path) for path in resolve_source_roots(root)]
    test_roots = args.test_root or ["tests"]
    report = build_map(root, profile, source_roots, test_roots, args.coverage, policy)
    output = Path(args.output) if args.output else test_map_output_path(root, naos_root, policy)
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            "NAOS test evidence map: "
            f"{report['status']} ({report['summary']['mapped_sources']}/{report['summary']['sources']} mapped)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
