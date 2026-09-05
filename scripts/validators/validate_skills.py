#!/usr/bin/env python3
"""Validate NAOS skill Markdown frontmatter and invocation guidance."""

from __future__ import annotations

import re
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


WHEN_TO_INVOKE_HEADING = re.compile(
    r"^#{2,6}\s+(?:When\s+to\s+(?:Use|Invoke)(?:\b|\s)|Invocation\b)",
    flags=re.IGNORECASE | re.MULTILINE,
)


def default_skill_files(root: Path) -> list[Path]:
    return candidate_files(root, "templates/skills/*/SKILL.md", ".github/skills/*/SKILL.md")


def parameters_are_well_formed(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    for entry in value:
        if not isinstance(entry, dict):
            return False
        if not is_non_empty_string(entry.get("name")):
            return False
        if not is_non_empty_string(entry.get("description")):
            return False
    return True


def validate_skill_file(path: Path) -> list[ValidationResult]:
    document = parse_frontmatter(path)
    if document.error:
        return [ValidationResult(path, "frontmatter", False, document.error)]

    return [
        ValidationResult(
            path,
            "parameters",
            parameters_are_well_formed(document.data.get("parameters")),
            "required field 'parameters' must be a list of mappings with non-empty name and description",
        ),
        ValidationResult(
            path,
            "when-to-invoke",
            bool(WHEN_TO_INVOKE_HEADING.search(document.body)),
            "body must include a heading such as '## When to Use' or '## When to Invoke'",
        ),
    ]


def validate_skill_files(paths: list[Path]) -> list[ValidationResult]:
    skill_files = [path for path in paths if path.name == "SKILL.md"]
    results: list[ValidationResult] = []
    for path in skill_files:
        results.extend(validate_skill_file(path))
    return results


def main() -> int:
    parser = build_root_parser("Validate NAOS SKILL.md frontmatter")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    targets = collect_markdown_targets(args.paths, default_skill_files(root))
    results = validate_skill_files(targets)
    return print_results("Skill Frontmatter", root, results)


if __name__ == "__main__":
    sys.exit(main())
