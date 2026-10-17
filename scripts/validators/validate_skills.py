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
        metadata_host_paths,
        MetadataScopeError,
        METADATA_SCOPE_PATH,
        scoped_frontmatter_results,
        collect_markdown_targets,
        is_non_empty_string,
        parse_frontmatter,
        skill_authoring_metadata,
        print_results,
    )
else:  # pragma: no cover - package import path
    from .frontmatter_utils import (
        ValidationResult,
        build_root_parser,
        candidate_files,
        metadata_host_paths,
        MetadataScopeError,
        METADATA_SCOPE_PATH,
        scoped_frontmatter_results,
        collect_markdown_targets,
        is_non_empty_string,
        parse_frontmatter,
        skill_authoring_metadata,
        print_results,
    )


SKILL_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


WHEN_TO_INVOKE_HEADING = re.compile(
    r"^#{2,6}\s+(?:When\s+to\s+(?:Use|Invoke)(?:\b|\s)|Invocation\b)",
    flags=re.IGNORECASE | re.MULTILINE,
)


def default_skill_files(root: Path) -> list[Path]:
    scope = metadata_host_paths(root)
    files = candidate_files(root, "templates/skills/*/SKILL.md", ".github/skills/*/SKILL.md")

    return sorted({p.resolve(): p for p in files + [p for p, k in scope.items() if k == 'skill']}.values(), key=lambda p: p.as_posix())


def collect_skill_targets(inputs: list[str], default_files: list[Path]) -> list[Path]:
    if not inputs:
        return default_files
    targets = []
    for raw in inputs:
        path = Path(raw).absolute()
        if path.is_file() or path.is_symlink():
            targets.append(path)
        elif path.is_dir():
            targets.extend(sorted(path.rglob("SKILL.md")))
    return targets



def validate_skill_file(path: Path) -> list[ValidationResult]:
    document = parse_frontmatter(path)
    if document.error:
        return [ValidationResult(path, "frontmatter", False, document.error)]

    try:
        skill_authoring_metadata(document.data)
        declaration_error = None
    except ValueError as exc:
        declaration_error = str(exc)

    name = document.data.get("name")
    description = document.data.get("description")
    return [
        ValidationResult(
            path,
            "name",
            isinstance(name, str)
            and 1 <= len(name) <= 64
            and SKILL_NAME.fullmatch(name) is not None
            and name == path.parent.name,
            "required field 'name' must match the parent directory exactly and use 1-64 lowercase ASCII letters/digits with single internal hyphens",
        ),
        ValidationResult(
            path,
            "description",
            is_non_empty_string(description) and len(description) <= 1024,
            "required field 'description' must be a non-empty string of at most 1024 characters",
        ),
        ValidationResult(
            path,
            "parameters",
            declaration_error is None,
            declaration_error or "portable frontmatter and optional namespaced NAOS inputs are well formed",
        ),
        ValidationResult(
            path,
            "when-to-invoke",
            bool(WHEN_TO_INVOKE_HEADING.search(document.body)),
            "body must include a heading such as '## When to Use' or '## When to Invoke'",
        ),
    ]


def validate_skill_files(paths: list[Path], *, root: Path | None = None) -> list[ValidationResult]:
    files = [path for path in paths if path.name == "SKILL.md"]
    return scoped_frontmatter_results(files, root, "skill", validate_skill_file)


def main() -> int:
    parser = build_root_parser("Validate NAOS SKILL.md frontmatter")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        targets = collect_skill_targets(args.paths, default_skill_files(root))
        results = validate_skill_files(targets, root=root)
    except MetadataScopeError as exc:
        results = [ValidationResult(root / METADATA_SCOPE_PATH, "metadata-scope", False, str(exc))]
    return print_results("Skill Frontmatter", root, results)


if __name__ == "__main__":
    sys.exit(main())
