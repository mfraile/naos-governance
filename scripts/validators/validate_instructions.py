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
        load_metadata_scope,
        MetadataScopeError,
        METADATA_SCOPE_PATH,
        scoped_frontmatter_results,
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
        load_metadata_scope,
        MetadataScopeError,
        METADATA_SCOPE_PATH,
        scoped_frontmatter_results,
        collect_markdown_targets,
        is_non_empty_string,
        parse_frontmatter,
        print_results,
    )


def default_instruction_files(root: Path) -> list[Path]:
    scope = load_metadata_scope(root)
    files = candidate_files(root, "templates/instructions/*.instructions.md", ".github/instructions/*.instructions.md")

    return sorted({p.resolve(): p for p in files + [p for p, k in scope.items() if k == 'instruction']}.values(), key=lambda p: p.as_posix())


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


def validate_instruction_files(paths: list[Path], *, root: Path | None = None) -> list[ValidationResult]:
    files = [path for path in paths if path.name.endswith(".instructions.md")]
    return scoped_frontmatter_results(files, root, "instruction", validate_instruction_file)


def main() -> int:
    parser = build_root_parser("Validate NAOS *.instructions.md frontmatter")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        targets = collect_markdown_targets(args.paths, default_instruction_files(root))
        results = validate_instruction_files(targets, root=root)
    except MetadataScopeError as exc:
        results = [ValidationResult(root / METADATA_SCOPE_PATH, "metadata-scope", False, str(exc))]
    return print_results("Instruction Frontmatter", root, results)


if __name__ == "__main__":
    sys.exit(main())
