#!/usr/bin/env python3
"""
validate_docs_consistency.py — NAOS public/generated documentation checks

Keeps high-value documentation surfaces aligned with the repository structure:
installation manual, maintenance playbook, lifecycle catalog, public docs index,
generated-project DOCS_INDEX, and NAOS_QUICK_REFERENCE.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from tempfile import TemporaryDirectory
from pathlib import Path
from urllib.parse import unquote

TRUSTED_ROOT = Path(__file__).resolve().parents[2]


ROOT_PUBLIC_DOCS = [
    "README.md",
    "INSTALLATION_MANUAL.md",
    "MAINTENANCE_PLAYBOOK.md",
    "NAOS_CATALOG.md",
    "ROADMAP.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
]

DOCS_PUBLIC_DOCS = [
    "docs/AUDIT_PLAYBOOK.md",
    "docs/ASSURED_PROFILE_ACTIVATION.md",
    "docs/BEHAVIORAL_AUDIT_ENABLEMENT.md",
    "docs/COMPLIANCE_MAPPING.md",
    "docs/GLOSSARY.md",
    "docs/INDEX.md",
    "docs/NAOS_THREAT_MODEL.md",
]

GENERATED_DOCS_INDEX_REQUIRED = [
    "README.md",
    "QUICK_START.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/DOCS_INDEX.md",
    "docs/DEPRECATION_LIST.md",
    "docs/exploration/",
    "naos/NAOS_QUICK_REFERENCE.md",
    "naos/PROJECT_STATUS.md",
    "naos/DASHBOARD.md",
    "naos/BACKLOG.md",
    "naos/TASK_REGISTRY.yaml",
    "naos/TRACEABILITY_MATRIX.md",
    "naos/RELEASE_NOTES.md",
    "naos/governance/GOVERNANCE_TRUTH_TABLE.md",
    "naos/inventory/FUNCTION_INDEX.yaml",
    "naos/inventory/MASTER_INVENTORY.md",
]

FORBIDDEN_PUBLIC_REFS = [
    "docs/THREAT_MODEL.md",
    "../THREAT_MODEL.md",
    "docs/MULTI_TEAM_DESIGN.md",
    "../MULTI_TEAM_DESIGN.md",
]

LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def markdown_links(path: Path) -> list[str]:
    return [target.strip() for target in LINK_RE.findall(text(path))]


def local_link_files(root: Path) -> list[Path]:
    files = [root / p for p in [*ROOT_PUBLIC_DOCS, *DOCS_PUBLIC_DOCS]]
    files.extend(sorted((root / "docs" / "decisions").glob("*.md")))
    files.extend(sorted((root / "docs" / "tutorials").glob("*.md")))
    files.extend(
        [
            root / "templates" / "structural-seeds" / "docs" / "DOCS_INDEX.md",
            root / "templates" / "structural-seeds" / "naos" / "NAOS_QUICK_REFERENCE.md",
        ]
    )
    return files


def check_exists(root: Path) -> list[str]:
    issues: list[str] = []
    required = [*ROOT_PUBLIC_DOCS, *DOCS_PUBLIC_DOCS]
    for item in required:
        if not (root / item).exists():
            issues.append(f"missing required public doc: {item}")

    generated_required = [
        "templates/structural-seeds/docs/DOCS_INDEX.md",
        "templates/structural-seeds/naos/NAOS_QUICK_REFERENCE.md",
        "templates/structural-seeds/NAOS_QUICKSTART.md",
        "templates/agents/AGENTS.md",
    ]
    for item in generated_required:
        if not (root / item).exists():
            issues.append(f"missing required generated-doc template: {item}")
    return issues


def check_local_links(root: Path) -> list[str]:
    issues: list[str] = []
    for path in local_link_files(root):
        if not path.exists():
            continue
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
                issues.append(f"{rel(path, root)}: broken local link -> {target}")
    return issues


def check_public_boundary(root: Path) -> list[str]:
    issues: list[str] = []
    files = [root / p for p in [*ROOT_PUBLIC_DOCS, *DOCS_PUBLIC_DOCS]]
    files.extend((root / "docs" / "tutorials").glob("*.md"))
    for path in files:
        if not path.exists():
            continue
        content = text(path)
        for forbidden in FORBIDDEN_PUBLIC_REFS:
            if forbidden in content:
                issues.append(f"{rel(path, root)} references internalized path: {forbidden}")
    return issues


def check_public_index(root: Path) -> list[str]:
    index = root / "docs" / "INDEX.md"
    if not index.exists():
        return []
    content = text(index)
    issues: list[str] = []
    for item in ROOT_PUBLIC_DOCS:
        if item == "README.md":
            token = "../README.md"
        else:
            token = f"../{item}"
        if token not in content:
            issues.append(f"docs/INDEX.md does not list public root doc: {item}")
    for item in DOCS_PUBLIC_DOCS:
        if item == "docs/INDEX.md":
            continue
        token = item.replace("docs/", "")
        if token not in content:
            issues.append(f"docs/INDEX.md does not list public docs file: {item}")
    return issues


def source_inventory(root: Path, folder: str, pattern: str) -> list[str]:
    base = root / folder
    if not base.exists():
        return []
    return sorted(path.name for path in base.glob(pattern) if path.is_file())


def skill_inventory(root: Path) -> list[str]:
    base = root / "templates" / "skills"
    if not base.exists():
        return []
    return sorted(path.parent.name for path in base.glob("*/SKILL.md"))


def check_catalog_inventory(root: Path) -> list[str]:
    catalog = root / "NAOS_CATALOG.md"
    if not catalog.exists():
        return []
    content = text(catalog)
    issues: list[str] = []

    prompt_sources = source_inventory(root, "templates/prompts", "*.prompt.md")
    expected_prompt_heading = f"## 3. All Prompts ({len(prompt_sources)})"
    if expected_prompt_heading not in content:
        issues.append(
            "NAOS_CATALOG.md prompt heading does not match source inventory: "
            f"{expected_prompt_heading}"
        )
    for filename in prompt_sources:
        if filename not in content:
            issues.append(f"NAOS_CATALOG.md missing prompt source: {filename}")
    for filename in source_inventory(root, "templates/agents", "*.agent.md"):
        if filename not in content:
            issues.append(f"NAOS_CATALOG.md missing agent source: {filename}")
    for skill in skill_inventory(root):
        if f"`{skill}`" not in content:
            issues.append(f"NAOS_CATALOG.md missing skill: {skill}")
    return issues


def check_generated_docs_index(root: Path) -> list[str]:
    index = root / "templates" / "structural-seeds" / "docs" / "DOCS_INDEX.md"
    if not index.exists():
        return []
    content = text(index)
    issues: list[str] = []
    for item in GENERATED_DOCS_INDEX_REQUIRED:
        if item not in content:
            issues.append(f"templates/structural-seeds/docs/DOCS_INDEX.md missing generated doc: {item}")
    return issues


def check_naos_quick_reference_control_plane(root: Path) -> list[str]:
    quick_ref = root / "templates" / "structural-seeds" / "naos" / "NAOS_QUICK_REFERENCE.md"
    if not quick_ref.exists():
        return []
    content = text(quick_ref)
    required_tokens = [
        "file-first governance control plane",
        "capability contracts",
        "central policy",
        "validators",
        "gates",
        "evidence pack",
        "dashboard",
        "Preventive",
        "Detective",
        "Remediation",
        "Control-Plane Self-Review",
        "Spec 04 Linkage Rule",
        "Research / Autoresearch Feedback",
        "Canonical Module Header",
        "Optional Semantic / Similarity Layer",
        "does not prove legal or regulatory compliance",
    ]
    stale_tokens = [
        "PM System Quick Reference",
        "Two-Layer Governance Control Model",
        "7 agent definitions",
        "18 SKILL.md files",
        "17 scoped instruction files",
        "16 prompt files",
        "semantic duplicate detection is core",
        "semantic duplicate detection is default",
    ]
    issues: list[str] = []
    for token in required_tokens:
        if token not in content:
            issues.append(f"NAOS_QUICK_REFERENCE.md missing control-plane token: {token}")
    lower_content = content.lower()
    for token in stale_tokens:
        if token.lower() in lower_content:
            issues.append(f"NAOS_QUICK_REFERENCE.md still contains stale token: {token}")
    return issues


def load_naos_init(root: Path):
    module_path = TRUSTED_ROOT / "naos_init.py"
    if not module_path.exists():
        return None
    spec = importlib.util.spec_from_file_location("naos_init_for_docs_check", module_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def scaffold_counts(root: Path) -> dict[str, dict[str, int]]:
    naos_init = load_naos_init(root)
    if naos_init is None:
        return {}

    counts: dict[str, dict[str, int]] = {}
    for tier in ["quickstart", "lite", "standard", "assured"]:
        with TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            preview = project / ".naos-preview"
            generated = naos_init.scaffold_files(
                project,
                tier,
                "custom",
                "static_only",
                preview,
                naos_init._empty_signals(),
            )
        counts[tier] = {
            "rules": int(naos_init.PROFILES[tier]["rules_active"]),
            "blocking": int(naos_init.PROFILES[tier]["rules_blocking"]),
            "specs": sum(
                1
                for item in generated
                if item.startswith("specs/")
                and item.endswith(".md")
                and not item.endswith("/README.md")
            ),
            "agents": sum(
                1
                for item in generated
                if item.startswith(".github/agents/") and item.endswith(".agent.md")
            ),
        }
    return counts


def check_quickstart_tier_table(root: Path) -> list[str]:
    quickstart = root / "templates" / "structural-seeds" / "NAOS_QUICKSTART.md"
    if not quickstart.exists():
        return []
    content = text(quickstart)
    counts = scaffold_counts(root)
    if not counts:
        return []

    rows = {
        "Rules": [counts[tier]["rules"] for tier in counts],
        "Blocking posture": [counts[tier]["blocking"] for tier in counts],
        "Specs": [counts[tier]["specs"] for tier in counts],
        "Agents": [counts[tier]["agents"] for tier in counts],
    }
    issues: list[str] = []
    for label, values in rows.items():
        display_values = ["-" if value == 0 else str(value) for value in values]
        expected = f"| **{label}** | {' | '.join(display_values)} |"
        if expected not in content:
            issues.append(
                "templates/structural-seeds/NAOS_QUICKSTART.md tier table "
                f"does not match scaffolded {label.lower()} counts: {expected}"
            )
    return issues


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
    issues: list[str] = []
    issues.extend(check_exists(root))
    issues.extend(check_local_links(root))
    issues.extend(check_public_boundary(root))
    issues.extend(check_public_index(root))
    issues.extend(check_catalog_inventory(root))
    issues.extend(check_generated_docs_index(root))
    issues.extend(check_naos_quick_reference_control_plane(root))
    issues.extend(check_quickstart_tier_table(root))

    if issues:
        print("Docs Consistency: FAIL")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    print("Docs Consistency: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
