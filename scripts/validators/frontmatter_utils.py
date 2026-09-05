#!/usr/bin/env python3
"""Shared helpers for NAOS Markdown frontmatter validators."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml  # type: ignore[import-untyped]


@dataclass(frozen=True)
class FrontmatterDocument:
    path: Path
    data: dict[str, Any]
    body: str
    error: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    path: Path
    check: str
    passed: bool
    message: str


def parse_frontmatter(path: Path) -> FrontmatterDocument:
    """Parse the top YAML frontmatter block from a Markdown file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return FrontmatterDocument(path=path, data={}, body="", error=f"cannot read file: {exc}")

    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return FrontmatterDocument(path=path, data={}, body=text, error="missing top YAML frontmatter block")

    end_index: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_index = index
            break
    if end_index is None:
        return FrontmatterDocument(path=path, data={}, body=text, error="unterminated YAML frontmatter block")

    raw_frontmatter = "\n".join(lines[1:end_index])
    body = "\n".join(lines[end_index + 1 :])
    try:
        parsed = yaml.safe_load(raw_frontmatter) if raw_frontmatter.strip() else {}
    except yaml.YAMLError as exc:
        return FrontmatterDocument(path=path, data={}, body=body, error=f"invalid YAML frontmatter: {exc}")
    if not isinstance(parsed, dict):
        return FrontmatterDocument(path=path, data={}, body=body, error="frontmatter must be a YAML mapping")
    return FrontmatterDocument(path=path, data=parsed, body=body)


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(is_non_empty_string(item) for item in value)


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def candidate_files(root: Path, kit_pattern: str, generated_pattern: str) -> list[Path]:
    """Return kit-template files when present, otherwise generated-project files."""
    kit_files = sorted(root.glob(kit_pattern))
    if kit_files:
        return [path for path in kit_files if path.is_file()]
    return sorted(path for path in root.glob(generated_pattern) if path.is_file())


def collect_markdown_targets(inputs: Iterable[str], default_files: list[Path]) -> list[Path]:
    """Resolve CLI roots/files into Markdown files; use defaults when no inputs are given."""
    raw_inputs = list(inputs)
    if not raw_inputs:
        return default_files

    targets: list[Path] = []
    for raw in raw_inputs:
        path = Path(raw).resolve()
        if path.is_file():
            targets.append(path)
        elif path.is_dir():
            targets.extend(sorted(child for child in path.rglob("*.md") if child.is_file()))
    return targets


def print_results(title: str, root: Path, results: list[ValidationResult]) -> int:
    failures = [result for result in results if not result.passed]
    if failures:
        print(f"{title}: FAIL")
        for result in failures:
            rel = display_path(result.path, root)
            print(f"  - {rel}: {result.check}: {result.message}")
        return 1

    print(f"{title}: PASS — {len(results)} checks")
    return 0


def build_root_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional files or directories to validate. Defaults to known NAOS template/generated locations.",
    )
    parser.add_argument(
        "--root",
        default=".",
        metavar="PATH",
        help="Repository or generated project root used for default discovery and relative output.",
    )
    return parser
