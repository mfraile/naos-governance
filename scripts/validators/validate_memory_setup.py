#!/usr/bin/env python3
"""Validate NAOS memory onboarding consistency.

Default mode is advisory: it warns about deferred or incomplete Engram setup without
blocking projects that intentionally run in degraded recovery mode. Use --strict to
turn warnings into failures.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - PyYAML is a package dependency
    yaml = None  # type: ignore[assignment]

MEMORY_RE = re.compile(r"\b(mem_context|mem_search|mem_save|mem_session_summary|get_observation)\b")


def _load_memory_config(root: Path) -> dict:
    path = root / "configs" / "naos_memory.yaml"
    if not path.is_file() or yaml is None:
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {"_error": "invalid YAML"}
    return data if isinstance(data, dict) else {}


def _memory_reference_files(root: Path) -> list[Path]:
    patterns = [
        ".github/agents/*.agent.md",
        ".github/prompts/*.prompt.md",
        ".github/skills/*/SKILL.md",
        ".github/instructions/*.instructions.md",
        "templates/agents/*.agent.md",
        "templates/prompts/*.prompt.md",
        "templates/skills/*/SKILL.md",
        "templates/instructions/*.instructions.md",
    ]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(path for path in root.glob(pattern) if path.is_file())
    return sorted(set(files))


def _inside_project(path: Path, root: Path) -> bool:
    try:
        candidate = path.expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NAOS memory onboarding consistency")
    parser.add_argument("--root", default=".", help="Repository or generated project root")
    parser.add_argument("--strict", action="store_true", help="Fail when memory warnings are present")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    config = _load_memory_config(root)
    warnings: list[str] = []

    if config.get("_error"):
        warnings.append("configs/naos_memory.yaml exists but is invalid YAML")
        memory: dict = {}
    else:
        memory = config.get("memory", config) if config else {}

    referenced = []
    for path in _memory_reference_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if MEMORY_RE.search(text):
            referenced.append(path)

    if referenced and not memory:
        warnings.append("memory-aware templates exist but configs/naos_memory.yaml is missing")

    state = str(memory.get("state", "unknown")) if memory else "unknown"
    scope = str(memory.get("scope", "unknown")) if memory else "unknown"
    namespace = memory.get("mcp_namespace") if memory else None
    data_dir_raw = memory.get("data_dir") if memory else None
    legacy_store_path = memory.get("store_path") if memory else None
    replication_profile = str(memory.get("replication_profile") or "local") if memory else "local"
    valid_states = {
        "deferred",
        "pending_external_verification",
        "pending_existing_verification",
        "disabled",
        "configured",
        "broken",
    }

    if memory and state not in valid_states:
        warnings.append(f"memory state {state!r} is unsupported; use a current setup disposition")
    non_enabled_states = {
        "deferred",
        "pending_external_verification",
        "pending_existing_verification",
        "disabled",
    }
    if state in non_enabled_states and memory.get("enabled"):
        warnings.append(f"memory state {state} cannot set enabled=true before external verification")
    if state == "broken":
        warnings.append("memory state is broken; repair or explicitly defer/disable memory before claiming readiness")
    if state == "configured" and memory.get("enabled") is not True:
        warnings.append("memory state configured requires enabled=true")
    if memory.get("enabled") is True and state != "configured":
        warnings.append(f"memory enabled=true is incoherent with state {state}")

    if referenced and state in {
        "unknown",
        "deferred",
        "pending_external_verification",
        "pending_existing_verification",
        "disabled",
        "broken",
    }:
        warnings.append(f"memory-aware templates reference mem_* tools while memory state is {state}; degraded recovery must be documented")
    if referenced and state == "configured" and not namespace:
        warnings.append("memory state is configured but mcp_namespace is not set; agent tool allowlists may not expose Engram")
    obsolete_fields = [field for field in ("strict_required", "last_check") if field in memory]
    if obsolete_fields:
        warnings.append(f"obsolete unused memory fields are present: {', '.join(obsolete_fields)}")
    if legacy_store_path is not None:
        warnings.append("legacy store_path is ignored; declare data_dir and remove store_path only through a reviewed migration")
    data_dir_path: Path | None = None
    if data_dir_raw:
        try:
            data_dir_path = Path(str(data_dir_raw)).expanduser()
        except RuntimeError:
            warnings.append("memory data_dir contains a user-home reference that cannot be expanded safely")
    if data_dir_path is not None and data_dir_path.suffix.lower() in {".db", ".sqlite"}:
        warnings.append("memory data_dir points to a database file; declare the directory containing engram.db")
    if data_dir_path is not None and _inside_project(data_dir_path, root):
        warnings.append("Engram data_dir is inside the project repo; keep the live database external, normally under ~/.engram")
    if (
        data_dir_path is not None
        and (data_dir_path / "engram.db").is_file()
        and _inside_project(data_dir_path / "engram.db", root)
        and not _inside_project(data_dir_path, root)
    ):
        warnings.append(
            "Engram database resolves inside the project repo through the configured data_dir; keep the live database external"
        )
    if replication_profile.casefold() != "local":
        warnings.append("memory replication_profile is non-local and unsafe without explicit review; NAOS will not normalize or configure it")
    if scope == "project-local":
        warnings.append("legacy project-local scope does not configure Engram storage; use project identity over the external per-user data directory")

    if warnings:
        label = "FAIL" if args.strict else "WARN"
        print(f"Memory setup: {label}")
        for warning in warnings:
            print(f"  - {warning}")
        return 1 if args.strict else 0

    print("Memory setup: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
