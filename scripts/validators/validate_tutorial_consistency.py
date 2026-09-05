#!/usr/bin/env python3
"""
validate_tutorial_consistency.py — NAOS tutorial freshness checks

Checks that public tutorials stay aligned with public docs, profile metadata,
and the current public/internal documentation boundary.

This is intentionally lightweight and deterministic. It does not attempt to
prove tutorials are semantically perfect; it catches the drift that usually
appears after repo structure, profile, or public-surface changes.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote

TRUSTED_ROOT = Path(__file__).resolve().parents[2]


FORBIDDEN_PUBLIC_REFS = [
    "docs/THREAT_MODEL.md",
    "../THREAT_MODEL.md",
    "docs/MULTI_TEAM_DESIGN.md",
    "../MULTI_TEAM_DESIGN.md",
    "dev/",
    "../dev/",
]

LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def load_profiles(root: Path) -> dict[str, dict[str, Any]]:
    naos_init = TRUSTED_ROOT / "naos_init.py"
    if not naos_init.exists():
        return {}
    spec = importlib.util.spec_from_file_location("naos_init_for_validation", naos_init)
    if spec is None or spec.loader is None:
        return {}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profiles = getattr(module, "PROFILES", {})
    return profiles if isinstance(profiles, dict) else {}


def markdown_links(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [target.strip() for target in LINK_RE.findall(text)]


def check_tutorial_links(root: Path, tutorial_files: list[Path]) -> list[str]:
    issues: list[str] = []
    for path in tutorial_files:
        for target in markdown_links(path):
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            target_path = target.split("#", 1)[0]
            if not target_path:
                continue
            resolved = (path.parent / unquote(target_path)).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                continue
            if not resolved.exists():
                issues.append(f"{path.relative_to(root)}: broken tutorial link -> {target}")
    return issues


def check_tutorial_index(root: Path, tutorial_dir: Path, tutorial_files: list[Path]) -> list[str]:
    issues: list[str] = []
    index = tutorial_dir / "README.md"
    if not index.exists():
        return ["docs/tutorials/README.md missing"]

    index_text = index.read_text(encoding="utf-8", errors="ignore")
    for path in tutorial_files:
        if path.name == "README.md":
            continue
        if path.name not in index_text:
            issues.append(f"{path.relative_to(root)} not listed in docs/tutorials/README.md")
    return issues


def check_public_boundary(root: Path, tutorial_files: list[Path]) -> list[str]:
    issues: list[str] = []
    public_files = tutorial_files + [root / "docs" / "INDEX.md", root / "README.md", root / "ROADMAP.md"]
    for path in public_files:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for forbidden in FORBIDDEN_PUBLIC_REFS:
            if forbidden in text:
                issues.append(f"{path.relative_to(root)} references internalized path: {forbidden}")
    return issues


def extract_profile_table_row(text: str, label: str) -> dict[str, int]:
    row_re = re.compile(rf"^\| \*\*{re.escape(label)}\*\* \| (?P<body>.+)\|$", re.MULTILINE)
    match = row_re.search(text)
    if not match:
        return {}
    values = [cell.strip().strip("`*") for cell in match.group("body").split("|")]
    result: dict[str, int] = {}
    profile_order = ["quickstart", "lite", "standard", "assured"]
    for profile, value in zip(profile_order, values):
        value_match = re.search(r"\d+", value)
        if value_match:
            result[profile] = int(value_match.group(0))
    return result


def check_profile_facts(root: Path) -> list[str]:
    issues: list[str] = []
    profiles = load_profiles(root)
    chooser = root / "docs" / "tutorials" / "WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md"
    if not profiles or not chooser.exists():
        return issues

    text = chooser.read_text(encoding="utf-8", errors="ignore")
    rules = extract_profile_table_row(text, "Rules")
    blocking = extract_profile_table_row(text, "Blocking-posture rules")

    for profile, metadata in profiles.items():
        expected_rules = int(metadata.get("rules_active", -1))
        expected_blocking = int(metadata.get("rules_blocking", -1))
        if rules.get(profile) != expected_rules:
            issues.append(
                "docs/tutorials/WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md: "
                f"{profile} rules shows {rules.get(profile)!r}, expected {expected_rules}"
            )
        if blocking.get(profile) != expected_blocking:
            issues.append(
                "docs/tutorials/WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md: "
                f"{profile} blocking posture shows {blocking.get(profile)!r}, expected {expected_blocking}"
            )
    return issues


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
    tutorial_dir = root / "docs" / "tutorials"
    if not tutorial_dir.exists():
        print("Tutorial Consistency: SKIP — docs/tutorials not present")
        return 0

    tutorial_files = sorted(tutorial_dir.glob("*.md"))
    issues: list[str] = []
    issues.extend(check_tutorial_links(root, tutorial_files))
    issues.extend(check_tutorial_index(root, tutorial_dir, tutorial_files))
    issues.extend(check_public_boundary(root, tutorial_files))
    issues.extend(check_profile_facts(root))

    if issues:
        print("Tutorial Consistency: FAIL")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    print(f"Tutorial Consistency: PASS — {len(tutorial_files)} tutorial files checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
