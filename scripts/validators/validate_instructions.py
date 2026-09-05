#!/usr/bin/env python3
"""Validate NAOS instruction Markdown frontmatter."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from frontmatter_utils import (  # type: ignore[import-not-found]
        ValidationResult,
        build_root_parser,
        candidate_files,
        collect_markdown_targets,
        is_non_empty_string,
        parse_frontmatter,
        print_results,
    )
else:  # pragma: no cover - package import path
    from .frontmatter_utils import (
        ValidationResult,
        build_root_parser,
        candidate_files,
        collect_markdown_targets,
        is_non_empty_string,
        parse_frontmatter,
        print_results,
    )


def default_instruction_files(root: Path) -> list[Path]:
    return candidate_files(root, "templates/instructions/*.instructions.md", ".github/instructions/*.instructions.md")


def apply_to_is_well_formed(value: Any) -> bool:
    if is_non_empty_string(value):
        return True
    if isinstance(value, list) and value:
        return all(is_non_empty_string(item) for item in value)
    return False


def validate_instruction_file(path: Path) -> list[ValidationResult]:
    document = parse_frontmatter(path)
    if document.error:
        return [ValidationResult(path, "frontmatter", False, document.error)]

    return [
        ValidationResult(
            path,
            "applyTo",
            apply_to_is_well_formed(document.data.get("applyTo")),
            "required field 'applyTo' must be a non-empty string or non-empty list of strings",
        )
    ]


def validate_instruction_files(paths: list[Path]) -> list[ValidationResult]:
    instruction_files = [path for path in paths if path.name.endswith(".instructions.md")]
    results: list[ValidationResult] = []
    for path in instruction_files:
        results.extend(validate_instruction_file(path))
    return results


def main() -> int:
    parser = build_root_parser("Validate NAOS *.instructions.md frontmatter")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    targets = collect_markdown_targets(args.paths, default_instruction_files(root))
    results = validate_instruction_files(targets)
    return print_results("Instruction Frontmatter", root, results)


if __name__ == "__main__":
    sys.exit(main())
