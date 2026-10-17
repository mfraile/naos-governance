"""Shared literal AI surface selection and bounded, local-only inspection.

Topology checks reject static symlinks/reparse points. This advisory inspection
is not a concurrent-filesystem sandbox and never authorizes mutation.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml

DEFAULT_SURFACES = (
    ("claude_context", "CLAUDE.md"),
    ("agents_context", "AGENTS.md"),
    ("agents_override_context", "AGENTS.override.md"),
    ("copilot_instructions", ".github/copilot-instructions.md"),
    ("github_agents", ".github/agents"),
    ("github_prompts", ".github/prompts"),
    ("github_skills", ".github/skills"),
    ("github_instructions", ".github/instructions"),
    ("cursor_rules", ".cursor/rules"),
    ("cursor_skills", ".cursor/skills"),
    ("cursor_mcp_configuration", ".cursor/mcp.json"),
    ("vscode_mcp_configuration", ".vscode/mcp.json"),
    ("workspace_mcp_configuration", ".mcp.json"),
    ("claude_hooks", ".claude/settings.json"),
    ("gemini_context", "GEMINI.md"),
    ("shared_rules", ".ai/RULES.md"),
    ("claude_skills", ".claude/skills"),
    ("portable_skills", ".agents/skills"),
    ("claude_agents", ".claude/agents"),
    ("claude_commands", ".claude/commands"),
    ("claude_local_settings", ".claude/settings.local.json"),
    ("claude_local_context", "CLAUDE.local.md"),
    ("github_hooks", ".github/hooks"),
    ("cursor_hooks", ".cursor/hooks.json"),
    ("cursor_legacy_rules", ".cursorrules"),
    ("gemini_settings", ".gemini/settings.json"),
    ("codex_configuration", ".codex"),
    ("spec_kit", ".specify"),
    ("bmad", ".bmad"),
    ("gsd", ".gsd"),
)
DEFAULT_PATHS = [path for _, path in DEFAULT_SURFACES]
INSTRUCTION_NAMES = {"AGENTS.md": "agents_context", "AGENTS.override.md": "agents_override_context",
                     "CLAUDE.md": "claude_context", "CLAUDE.local.md": "claude_local_context"}
MCP_CONFIGURATION_PATHS = {
    ".cursor/mcp.json": "cursor_mcp_configuration",
    ".vscode/mcp.json": "vscode_mcp_configuration",
    ".mcp.json": "workspace_mcp_configuration",
}


def cursor_skill_path(relative: str) -> bool:
    """Classify a literal SKILL.md beneath a project or nested Cursor skill root."""
    parts = PurePosixPath(relative).parts
    return (len(parts) >= 4 and parts[-1] == "SKILL.md"
            and any(parts[index:index + 2] == (".cursor", "skills")
                    for index in range(len(parts) - 3)))


def is_host_surface(relative: str) -> bool:
    """Recognize declared host obligations from the shared project families.

    Classification does not discover or claim host loading. Required contract
    files in these families must exist; default inventory roots stay optional.
    """
    path = PurePosixPath(relative)
    roots = {PurePosixPath(value).parts[0] for value in DEFAULT_PATHS if value.startswith(".")}
    return (relative in DEFAULT_PATHS or path.name in INSTRUCTION_NAMES or cursor_skill_path(relative)
            or (bool(path.parts) and path.parts[0] in roots))


def discovered_surface_type(relative: str, effective_patterns: list[str]) -> str | None:
    """Share bounded filename selection; Cursor discovery honors its enabled root.

    The caller supplies files from scan_files, never a glob or host-global root.
    Existing named instruction discovery is retained. Removing .cursor/skills
    from custom patterns disables the additional nested Cursor skill discovery.
    """
    instruction = INSTRUCTION_NAMES.get(PurePosixPath(relative).name)
    if instruction:
        return instruction
    if ".cursor/skills" in effective_patterns and cursor_skill_path(relative):
        return "cursor_skills"
    return None


IGNORED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".naos-preview",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
DEFAULT_LIMITS = {"max_files_per_path": 50, "max_discovery_files": 5000}
MAX_ENTRIES = 100000


def literal_path(value: Any) -> str:
    """Use the same forward-slash, project-relative grammar on every OS."""
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("expected nonempty literal relative path")
    parts = value.split("/")
    if (
        PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).anchor
        or any(c in value for c in "\\:*?[]")
        or any(p in {"", ".", ".."} or p.endswith((" ", ".")) for p in parts)
    ):
        raise ValueError("unsupported literal relative path")
    return value


def checked_path(root: Path, relative: str) -> Path:
    relative = literal_path(relative)
    cursor = root
    for part in relative.split("/"):
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("symlink_or_reparse_path")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("non_regular_path")
    return cursor


def load_surface_rules(
    root: Path, naos_root: str, policy: dict[str, Any]
) -> dict[str, Any]:
    artifacts = policy.get("artifacts") or {}
    result: dict[str, Any] = {
        "rules_source": "defaults",
        "rules_path": None,
        "effective_patterns": list(DEFAULT_PATHS),
        "limits": dict(DEFAULT_LIMITS),
        "issues": [],
        "invalid_config": False,
    }
    try:
        if not isinstance(artifacts, dict):
            raise ValueError("invalid artifacts configuration")
        filename = (
            artifacts.get("ai_artifact_inventory_rules")
            or "ai_artifact_inventory_rules.yaml"
        )
        relative = literal_path(naos_root) + "/" + literal_path(filename)
        result["rules_path"] = relative
        path = checked_path(root, relative)
        if not path.exists():
            return result
        result["rules_source"] = "project"
        with path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        if not isinstance(document, dict):
            raise ValueError("inventory rules must be a mapping")
        patterns = document.get("artifact_patterns", DEFAULT_PATHS)
        if not isinstance(patterns, list) or len(patterns) > 1000:
            raise ValueError(
                "artifact_patterns must be a list of at most 1000 literal paths"
            )
        result["effective_patterns"] = list(
            dict.fromkeys(literal_path(p) for p in patterns)
        )
        limits = document.get("scan_limits", {})
        if not isinstance(limits, dict) or set(limits) - set(DEFAULT_LIMITS):
            raise ValueError("invalid scan_limits")
        for key, value in limits.items():
            if type(value) is not int or not 1 <= value <= MAX_ENTRIES:
                raise ValueError("scan limits must be integers from 1 to 100000")
            result["limits"][key] = value
    except (OSError, ValueError, TypeError, UnicodeError, yaml.YAMLError) as exc:
        result.update(invalid_config=True, effective_patterns=[])
        result["issues"].append({"path": result["rules_path"], "reason": str(exc)})
    return result


def scan_files(
    root: Path, relative: str | None, max_files: int, *,
    ignored_parts: set[str] | frozenset[str] = frozenset(),
) -> tuple[list[Path], dict[str, Any]]:
    """Sorted depth-first file selection, bounded by files and visited entries.

    file_count is selected files, not an invented total when truncated. Missing
    optional surfaces are complete; unreadable, linked or truncated ones are not.
    """
    meta: dict[str, Any] = {
        "path": relative or ".",
        "present": False,
        "type": "missing",
        "file_count": 0,
        "truncated": False,
        "complete": True,
        "issues": [],
    }
    files: list[Path] = []
    excluded = IGNORED_PARTS | ignored_parts
    visited = 0

    def issue(path: Path, reason: str) -> None:
        meta["issues"].append(
            {"path": path.relative_to(root).as_posix(), "reason": reason}
        )
        meta["complete"] = False

    def walk(path: Path) -> None:
        nonlocal visited
        if meta["truncated"]:
            return
        visited += 1
        if visited > MAX_ENTRIES:
            meta.update(truncated=True, complete=False)
            return
        try:
            if path != root:
                checked_path(root, path.relative_to(root).as_posix())
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                if len(files) >= max_files:
                    meta.update(truncated=True, complete=False)
                else:
                    files.append(path)
            elif stat.S_ISDIR(info.st_mode):
                entries = []
                with os.scandir(path) as iterator:
                    for entry in iterator:
                        if len(entries) >= MAX_ENTRIES - visited:
                            meta.update(truncated=True, complete=False)
                            return
                        entries.append(entry.name)
                for name in sorted(entries):
                    if name not in excluded:
                        walk(path / name)
                    if meta["truncated"]:
                        break
            else:
                issue(path, "non_regular_path")
        except (OSError, ValueError) as exc:
            issue(path, str(exc))

    try:
        path = checked_path(root, relative) if relative is not None else root
        if not path.exists():
            return files, meta
        meta.update(present=True, type="directory" if path.is_dir() else "file")
        walk(path)
    except (OSError, ValueError) as exc:
        meta.update(complete=False, ignored=True)
        meta["issues"].append({"path": relative, "reason": str(exc)})
    meta["file_count"] = len(files)
    return files, meta
