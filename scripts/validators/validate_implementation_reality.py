#!/usr/bin/env python3
"""
validate_implementation_reality.py - NAOS implementation-backed docs checks

Verifies that high-value documentation references are backed by shipped source
artifacts: prompt commands, agents, Make targets, scripts, and template files.
This complements docs consistency checks, which verify coherence and links.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


DOC_FILES = [
    "README.md",
    "INSTALLATION_MANUAL.md",
    "MAINTENANCE_PLAYBOOK.md",
    "NAOS_CATALOG.md",
    "docs/COMPLIANCE_MAPPING.md",
    "docs/INDEX.md",
    "templates/agents/AGENTS.md",
    "templates/structural-seeds/CONTRIBUTING.md",
    "templates/structural-seeds/NAOS_QUICKSTART.md",
    "templates/structural-seeds/QUICK_START.md",
    "templates/structural-seeds/docs/DOCS_INDEX.md",
    "templates/structural-seeds/docs/DEPRECATION_LIST.md",
    "templates/structural-seeds/naos/NAOS_QUICK_REFERENCE.md",
]

SLASH_COMMAND_RE = re.compile(r"(?<![\w/])/(naos-[A-Za-z0-9_-]+)\b")
AGENT_RE = re.compile(r"(?<![\w@])@(naos-[A-Za-z0-9_-]+)\b")
MAKE_TARGET_RE = re.compile(r"\bmake\s+([A-Za-z0-9_-]+)\b")
MAKEFILE_TARGET_RE = re.compile(r"\bmake\s+-f\s+Makefile\.naos\s+([A-Za-z0-9_-]+)\b")
SCRIPT_RE = re.compile(
    r"(?<![\w/])((?:scripts|\.github/autoresearch)/[A-Za-z0-9_./-]+\.py)\b"
)
TEMPLATE_RE = re.compile(
    r"\b([A-Za-z0-9_.-]+\.(?:prompt\.md|agent\.md|instructions\.md))\b"
)
MAKE_NON_TARGETS = {"-C", "-f", "targets", "target"}
MAKE_BARE_TARGET_PREFIXES = ("gov-", "naos-", "validate-")
MAKE_BARE_TARGETS = {"function-index", "drift-check", "semantic-audit"}
SURFACE_DOC_GLOBS = [
    "*.md",
    "docs/**/*.md",
    "plugins/**/*.md",
    "profiles/**/*.md",
    "schemas/**/*.md",
    "templates/**/*.md",
]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def surface_doc_files(root: Path) -> list[str]:
    """Return public/generated documentation surfaces where concrete paths matter."""
    files: set[str] = set()
    for pattern in SURFACE_DOC_GLOBS:
        for path in root.glob(pattern):
            if path.is_file():
                files.add(path.relative_to(root).as_posix())
    return sorted(files)


def documented_tokens(
    root: Path,
    pattern: re.Pattern[str],
    files: list[str] | None = None,
) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for relative in files or DOC_FILES:
        path = root / relative
        if not path.exists():
            continue
        for line_number, line in enumerate(read(path).splitlines(), start=1):
            for token in pattern.findall(line):
                found.setdefault(token, set()).add(f"{relative}:{line_number}")
    return found


def documented_make_targets(root: Path, files: list[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for relative in files:
        path = root / relative
        if not path.exists():
            continue
        for line_number, line in enumerate(read(path).splitlines(), start=1):
            location = f"{relative}:{line_number}"
            for target in MAKEFILE_TARGET_RE.findall(line):
                found.setdefault(target, set()).add(location)
            for target in MAKE_TARGET_RE.findall(line):
                if target in MAKE_NON_TARGETS or target.startswith("-"):
                    continue
                if not (
                    target.startswith(MAKE_BARE_TARGET_PREFIXES)
                    or target in MAKE_BARE_TARGETS
                ):
                    continue
                found.setdefault(target, set()).add(location)
    return found


def prompt_commands(root: Path) -> set[str]:
    prompts = root / "templates" / "prompts"
    if not prompts.exists():
        return set()
    return {
        path.name.removesuffix(".prompt.md") for path in prompts.glob("*.prompt.md")
    }


def agent_names(root: Path) -> set[str]:
    agents = root / "templates" / "agents"
    if not agents.exists():
        return set()
    return {
        path.name.removesuffix(".agent.md")
        for pattern in ("*.agent.md", "optional/*.agent.md")
        for path in agents.glob(pattern)
    }


def make_targets(root: Path) -> set[str]:
    makefile = root / "templates" / "Makefile.naos"
    if not makefile.exists():
        return set()
    return set(re.findall(r"^([A-Za-z0-9_-]+):", read(makefile), flags=re.MULTILINE))


def cli_commands(root: Path) -> set[str]:
    cli = root / "cli.py"
    if not cli.exists():
        return set()
    return set(re.findall(r'if command == "([A-Za-z0-9_-]+)"', read(cli)))


def template_exists(root: Path, filename: str) -> bool:
    if filename.endswith(".prompt.md"):
        return (root / "templates" / "prompts" / filename).exists()
    if filename.endswith(".agent.md"):
        return any(
            candidate.exists()
            for candidate in (
                root / "templates" / "agents" / filename,
                root / "templates" / "agents" / "optional" / filename,
            )
        )
    if filename.endswith(".instructions.md"):
        return (root / "templates" / "instructions" / filename).exists()
    return False


def shipped_script_exists(root: Path, script: str) -> bool:
    path = Path(script)
    if (root / path).exists():
        return True
    if script.startswith(".github/autoresearch/"):
        generated_relative = path.relative_to(".github/autoresearch")
        return (root / "autoresearch" / generated_relative).exists()
    return False


def check_documented_backing(root: Path) -> list[str]:
    issues: list[str] = []
    prompts = prompt_commands(root)
    agents = agent_names(root)
    targets = make_targets(root)
    surface_docs = surface_doc_files(root)

    for command, locations in sorted(documented_tokens(root, SLASH_COMMAND_RE).items()):
        if command not in prompts:
            where = ", ".join(sorted(locations))
            issues.append(
                f"documented slash command /{command} has no templates/prompts/{command}.prompt.md ({where})"
            )

    for agent, locations in sorted(documented_tokens(root, AGENT_RE).items()):
        if agent not in agents:
            where = ", ".join(sorted(locations))
            issues.append(
                f"documented agent @{agent} has no templates/agents/{agent}.agent.md ({where})"
            )

    for target, locations in sorted(
        documented_make_targets(root, surface_docs).items()
    ):
        if target not in targets:
            where = ", ".join(sorted(locations))
            issues.append(
                f"documented make target 'make {target}' has no templates/Makefile.naos target ({where})"
            )

    for script, locations in sorted(
        documented_tokens(root, SCRIPT_RE, surface_docs).items()
    ):
        if not shipped_script_exists(root, script):
            where = ", ".join(sorted(locations))
            issues.append(
                f"documented script {script} is not shipped in the kit ({where})"
            )

    for filename, locations in sorted(documented_tokens(root, TEMPLATE_RE).items()):
        if not template_exists(root, filename):
            where = ", ".join(sorted(locations))
            issues.append(
                f"documented template {filename} is not shipped in templates/ ({where})"
            )

    return issues


def check_implemented_documented(root: Path) -> list[str]:
    """High-signal inverse checks for inventories that should be public."""
    issues: list[str] = []
    catalog = root / "NAOS_CATALOG.md"
    catalog_text = read(catalog) if catalog.exists() else ""

    for command in sorted(prompt_commands(root)):
        if command not in catalog_text:
            issues.append(
                f"implemented prompt {command}.prompt.md is missing from NAOS_CATALOG.md"
            )
    for agent in sorted(agent_names(root)):
        if agent not in catalog_text:
            issues.append(
                f"implemented agent {agent}.agent.md is missing from NAOS_CATALOG.md"
            )

    agents_index = root / "templates" / "agents" / "AGENTS.md"
    agents_index_text = read(agents_index) if agents_index.exists() else ""
    for agent in sorted(agent_names(root)):
        if f"@{agent}" not in agents_index_text:
            issues.append(
                f"implemented agent {agent}.agent.md is missing from templates/agents/AGENTS.md"
            )

    skills_dir = root / "templates" / "skills"
    if skills_dir.exists():
        for skill_file in sorted(skills_dir.glob("*/SKILL.md")):
            skill = skill_file.parent.name
            if f"`{skill}`" not in catalog_text:
                issues.append(
                    f"implemented skill {skill}/SKILL.md is missing from NAOS_CATALOG.md"
                )

    public_cli_docs = "\n".join(
        read(root / doc) for doc in DOC_FILES if (root / doc).exists()
    )
    for command in sorted(cli_commands(root)):
        if f"naos {command}" not in public_cli_docs:
            issues.append(
                f"implemented CLI command 'naos {command}' is not documented in checked docs"
            )

    return issues


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
    issues: list[str] = []
    issues.extend(check_documented_backing(root))
    issues.extend(check_implemented_documented(root))

    if issues:
        print("Implementation Reality: FAIL")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    print("Implementation Reality: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
