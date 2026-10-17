#!/usr/bin/env python3
"""Map source files to available test and coverage evidence."""

from __future__ import annotations

import argparse
import ast
import json
import os
import stat
import sys
import tokenize
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


COVERAGE_INPUT_FAILURES = {"missing", "unreadable", "parse_error", "invalid_structure", "unsupported_format"}


def coverage_input_inventory(root: Path, explicit_paths: list[str]) -> list[dict[str, Any]]:
    """Keep declared inputs, including missing ones; discover optional companions."""
    candidates = [(raw, "explicit") for raw in explicit_paths]
    candidates.extend((raw, "discovered") for raw in (
        "coverage.xml", "coverage.json", ".coverage", "htmlcov", "reports/coverage.xml", "reports/coverage.json",
    ))
    inputs: list[dict[str, Any]] = []
    seen: set[str] = set()
    absolute_root = root if root.is_absolute() else Path.cwd() / root
    for raw, origin in candidates:
        # Preserve '..': collapsing it before symlink traversal can select a different file.
        path = absolute_root / raw
        key = str(path)
        if key in seen:
            continue
        if origin == "discovered":
            try:
                path.stat()
            except FileNotFoundError:
                continue
            except OSError:
                pass  # Preserve unreadable discovered inputs for the parser diagnostic.
        seen.add(key)
        inputs.append({"path": str(path), "origin": origin,
                       "selected": origin == "explicit" or path.suffix.lower() in {".json", ".xml"}})
    return inputs


def detect_coverage(root: Path, explicit_paths: list[str]) -> list[str]:
    return [item["path"] for item in coverage_input_inventory(root, explicit_paths)]


def parse_coverage_inputs(root: Path, inputs: list[dict[str, Any]]) -> tuple[set[str] | None, list[dict[str, Any]]]:
    referenced: set[str] = set()
    outcomes: list[dict[str, Any]] = []
    for item in inputs:
        outcome = dict(item)
        path = Path(item["path"])
        refs: set[str] = set()
        try:
            if not item["selected"]:
                outcome.update(status="unsupported_format", message="Auxiliary coverage artifact is inventoried but not parsed.")
            else:
                mode = path.stat().st_mode
                if not stat.S_ISREG(mode) or path.suffix.lower() not in {".json", ".xml"}:
                    outcome.update(status="unsupported_format", message="Selected coverage input must be an XML or JSON file.")
                else:
                    content = path.read_bytes()
                    if path.suffix.lower() == ".json":
                        data = json.loads(content.decode("utf-8-sig"))
                        files = data.get("files") if isinstance(data, dict) else None
                        if not isinstance(files, dict) or any(
                            not isinstance(name, str) or not name.strip() or not isinstance(record, dict)
                            for name, record in files.items()
                        ):
                            raise ValueError("Coverage JSON requires a files object with nonempty names and object records.")
                        refs.update(files)
                    else:
                        tree = ET.fromstring(content)
                        if tree.tag.rsplit("}", 1)[-1] != "coverage":
                            raise ValueError("Coverage XML requires a coverage root element.")
                        for node in tree.iter():
                            if node.tag.rsplit("}", 1)[-1] == "class":
                                name = node.attrib.get("filename", "")
                                if not name.strip():
                                    raise ValueError("Coverage XML class requires a nonempty filename.")
                                refs.add(name)
                    # NUL is structurally unusable on every platform, even where
                    # native non-strict resolve happens to tolerate it. Keep this
                    # shared lexical boundary after parsing and before source resolution.
                    if any("\0" in name for name in refs):
                        raise ValueError("Coverage input contains a NUL in a source path.")
                    try:
                        normalized = {str((root / name).resolve()) for name in refs}
                    except (OSError, ValueError, RuntimeError) as exc:
                        raise ValueError("Coverage input contains an unusable source path.") from exc
                    outcome.update(status="parsed" if refs else "parsed_empty", source_references=len(refs))
                    referenced.update(refs)
                    referenced.update(normalized)
        except FileNotFoundError:
            outcome.update(status="missing", message="Selected coverage input does not exist.")
        except OSError as exc:
            outcome.update(status="unreadable", message=f"Coverage input could not be read: {exc.strerror or type(exc).__name__}.")
        except (UnicodeError, json.JSONDecodeError, ET.ParseError, LookupError, RecursionError) as exc:
            outcome.update(status="parse_error", message=f"Coverage input could not be parsed ({type(exc).__name__}).")
        except ValueError as exc:
            outcome.update(status="invalid_structure", message=str(exc))
        outcomes.append(outcome)
    if not referenced:
        return None, outcomes
    return referenced, outcomes


def parse_coverage_sources(root: Path, coverage_paths: list[str]) -> set[str] | None:
    """Compatibility helper; report builders must retain the per-input outcomes."""
    inputs = [{"path": str(root / raw), "origin": "explicit", "selected": True} for raw in coverage_paths]
    return parse_coverage_inputs(root, inputs)[0]


def source_module_index(root: Path, sources: list[Path], source_roots: list[Path]) -> dict[str, set[Path]]:
    """Index exact dotted paths; duplicate names remain ambiguous."""
    index: dict[str, set[Path]] = {}
    if not sources or not source_roots:
        return index
    project_root = root.resolve(strict=False)
    for source in sources:
        resolved_source = source.resolve(strict=False)
        for configured_root in source_roots:
            resolved_root = configured_root.resolve(strict=False)
            if not resolved_source.is_relative_to(resolved_root):
                continue
            if configured_root.is_file():
                module_parts = (source.stem,)
                module_search_base = resolved_root.parent
            else:
                relative = resolved_source.relative_to(resolved_root)
                module_parts = relative.parts[:-1] if source.name == "__init__.py" else relative.with_suffix("").parts
                module_search_base = resolved_root
            if not module_parts or not all(part.isidentifier() for part in module_parts):
                continue
            names = {".".join(module_parts)}
            if module_search_base.is_relative_to(project_root):
                root_parts = module_search_base.relative_to(project_root).parts
                if root_parts and all(part.isidentifier() for part in root_parts):
                    names.add(".".join((*root_parts, *module_parts)))
            for name in names:
                index.setdefault(name, set()).add(source)
    return index


def test_package_parts(test: Path) -> tuple[str, ...]:
    """Use only an unbroken explicit package chain for relative imports."""
    parts: list[str] = []
    parent = test.parent
    while (parent / "__init__.py").is_file() and parent.name.isidentifier():
        parts.insert(0, parent.name)
        parent = parent.parent
    return tuple(parts)


def declared_source_imports(test: Path, tree: ast.AST, module_index: dict[str, set[Path]]) -> set[Path]:
    """Resolve AST import declarations without importing or executing tests."""
    linked: set[Path] = set()
    package_parts = test_package_parts(test)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                matches = module_index.get(alias.name, set())
                if len(matches) == 1:
                    linked.update(matches)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if not package_parts or node.level > len(package_parts):
                    continue
                prefix = package_parts[: len(package_parts) - node.level + 1]
                base = ".".join((*prefix, *(node.module.split(".") if node.module else ())))
            else:
                base = node.module or ""
            if not base:
                continue
            for alias in node.names:
                child = f"{base}.{alias.name}" if alias.name != "*" else ""
                child_matches = module_index.get(child, set()) if child else set()
                base_matches = module_index.get(base, set())
                # A module and same-named child can make `from` ambiguous to
                # a static reader; do not silently select either source.
                matches = child_matches if child_matches and not base_matches else base_matches if not child_matches else set()
                if len(matches) == 1:
                    linked.update(matches)
    return linked


def test_matches_source(
    test: Path,
    source: Path,
    test_text_cache: dict[Path, str],
    module_index: dict[str, set[Path]] | None = None,
) -> bool:
    """Compatibility bool API; only a unique AST import can match."""
    text = test_text_cache.get(test)
    if text is None:
        return False
    try:
        tree = ast.parse(text, filename=str(test))
    except (SyntaxError, ValueError, RecursionError):
        return False
    index = module_index if module_index is not None else source_module_index(source.parent, [source], [source.parent])
    return source in declared_source_imports(test, tree, index)


def build_map(
    root: Path,
    profile: str,
    source_roots: list[str],
    test_roots: list[str],
    coverage_paths: list[str],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = policy or load_policy(root=root)
    configured_source_roots = [path if path.is_absolute() else root / path for path in map(Path, source_roots)]
    configured_test_roots = [path if path.is_absolute() else root / path for path in map(Path, test_roots)]
    sources = collect_sources([str(path) for path in configured_source_roots], policy)
    tests = collect_tests([str(path) for path in configured_test_roots], policy)
    module_index = source_module_index(root, sources, configured_source_roots)
    inventory = coverage_input_inventory(root, coverage_paths)
    coverage_sources, coverage_inputs = parse_coverage_inputs(root, inventory)
    coverage = [item["path"] for item in coverage_inputs]
    selected = [item for item in coverage_inputs if item["selected"]]
    failures = [item for item in selected if item["status"] in COVERAGE_INPUT_FAILURES]
    input_summary = {
        "coverage_input_status": "incomplete" if failures else ("complete" if selected else "not_configured"),
        "coverage_inputs_selected": len(selected),
        "coverage_inputs_parsed": sum(item["status"] in {"parsed", "parsed_empty"} for item in selected),
        "coverage_inputs_failed": len(failures),
        "coverage_inputs_unsupported": sum(item["status"] == "unsupported_format" for item in coverage_inputs),
    }
    test_text_cache: dict[Path, str] = {}
    test_import_links: dict[Path, set[Path]] = {}
    test_inputs: list[dict[str, Any]] = []
    for test in tests:
        try:
            with tokenize.open(test) as handle:
                text = handle.read()
            test_text_cache[test] = text
        except OSError:
            test_inputs.append({"path": str(test), "status": "unreadable",
                                "message": "Discovered test file could not be read."})
            continue
        except (SyntaxError, UnicodeError, LookupError):
            test_inputs.append({"path": str(test), "status": "parse_error", "failure_kind": "decode_error",
                                "message": "Discovered test file could not be decoded as Python source."})
            continue
        try:
            tree = ast.parse(text, filename=str(test))
        except (SyntaxError, ValueError, RecursionError):
            test_inputs.append({"path": str(test), "status": "parse_error", "failure_kind": "syntax_error",
                                "message": "Discovered test file has invalid Python syntax."})
            continue
        test_import_links[test] = declared_source_imports(test, tree, module_index)
        test_inputs.append({"path": str(test), "status": "read"})
    test_failures = [item for item in test_inputs if item["status"] in {"unreadable", "parse_error"}]
    input_summary.update({
        "test_input_status": "incomplete" if test_failures else ("complete" if tests else "not_configured"),
        "test_inputs_selected": len(tests),
        "test_inputs_read": len(test_text_cache),
        "test_inputs_failed": len(test_failures),
    })
    mappings: list[dict[str, Any]] = []
    type_counts = {test_type: 0 for test_type in test_evidence_types(policy)}

    for source in sources:
        matched = []
        candidates = []
        matched_types = set()
        for test, links in test_import_links.items():
            test_type = classify_test(test)
            if source in links:
                matched.append({"path": str(test), "type": test_type, "association": "declared_import"})
                matched_types.add(test_type)
            elif test.stem.lower() in {f"test_{source.stem.lower()}", f"{source.stem.lower()}_test"}:
                candidates.append({"path": str(test), "type": test_type, "association": "weak_heuristic"})
        coverage_supports_source = str(policy.get("test_evidence", {}).get("coverage_supports_source_default") or "unknown")
        source_refs = {str(source), str(source.resolve())}
        if coverage_sources is not None and source_refs & coverage_sources:
            coverage_supports_source = "yes"
            matched_types.add("coverage")
        elif coverage_sources is not None and not failures:
            coverage_supports_source = "no"
        elif failures:
            coverage_supports_source = "unknown"
        for test_type in matched_types:
            type_counts[test_type] += 1
        mappings.append(
            {
                "source": str(source),
                "tests": matched,
                "candidate_tests": candidates,
                "global_coverage_evidence": coverage,
                "coverage_supports_source": coverage_supports_source,
                "mapped": bool(matched or coverage_supports_source == "yes"),
                "evidence_types": sorted(matched_types),
            }
        )

    unmapped = [item["source"] for item in mappings if not item["mapped"]]
    status = "not_configured" if not sources else ("pass" if not unmapped and not failures and not test_failures else "mapped_with_gaps")
    return {
        "schema": "naos.test_evidence_map.v1",
        "profile": profile,
        "status": status,
        "source_roots": source_roots,
        "test_roots": test_roots,
        "global_coverage_evidence": coverage,
        "coverage_inputs": coverage_inputs,
        "test_inputs": test_inputs,
        "known_gaps": [f"{item['path']}: {item['status']}" for item in [*failures, *test_failures]],
        "coverage_supports_source_default": policy.get("test_evidence", {}).get("coverage_supports_source_default", "unknown"),
        "summary": {
            **input_summary,
            "sources": len(sources),
            "tests": len(tests),
            "mapped_sources": len(sources) - len(unmapped),
            "unmapped_sources": len(unmapped),
            "evidence_type_counts": type_counts,
        },
        "mappings": mappings,
        "limitations": [
            "Mapped test links are static AST import declarations, not test execution or coverage proof.",
            "Filename-only candidates are weak heuristics and do not count as mapped evidence.",
            "Ambiguous module names across source roots and unresolved relative imports do not map.",
            "Mapped tests do not prove sufficiency or complete behavioral coverage.",
            "Coverage input completeness applies only to selected files, not exercised lines or behavioral coverage.",
            "Test input completeness applies only to discovered files, not configured-root discovery or test execution.",
            "Automatically discovered binary/HTML coverage artifacts are inventoried, not parsed.",
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
            f"{report['status']} ({report['summary']['mapped_sources']}/{report['summary']['sources']} mapped; "
            f"test inputs: {report['summary']['test_input_status']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
