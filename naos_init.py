#!/usr/bin/env python3
"""
naos init — NAOS Portable Governance Kit Scaffolder
Mode A: Detection  — naos init .    (analyse existing project)
Mode B: Greenfield — naos init --new (scaffold specs for a brand-new project)

Security model:
 - No network calls during scaffolding (air-gap compatible)
 - Files are generated into a preview directory first
 - Activation requires explicit --activate flag
 - No auto-modification of .gitignore or .git/hooks without consent
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Callable, NoReturn

import yaml

try:
    from .scripts.validators.frontmatter_utils import skill_authoring_metadata
    from .scripts.naos_console import configure_console_output
    from .naos_profile_rules import load_profile_rules_source
    from .upgrade_contract.canonical import canonical_sha256
    from .upgrade_contract.planner import (
        build_create_only_plan,
        load_source_policy_snapshot,
        regular_file_observation,
        require_supported_source_metadata,
        revalidate_create_only_plan,
    )
    from .upgrade_contract.provenance import (
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_LOCK_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        ProvenanceError,
        begin_greenfield_root,
        build_greenfield_root_intent,
        commit_managed_content_enrollment,
        managed_content_creator_identity,
        finalize_greenfield_root,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from .upgrade_contract.security import source_metadata_contract
    from .upgrade_contract.private_preview import PrivatePreviewAddress, create_temporary_preview
    from .upgrade_contract.source_origins import SourceOrigins
    from .upgrade_contract.source_modes import SourceModeError, mode_row
    from .upgrade_contract.generated_recipes import (
        MAX_INPUTS, MAX_INPUT_BYTES, MAX_TOTAL_INPUT_BYTES, OverlayInputObserver,
        bounded_canonical_input,
    )
    from .upgrade_contract.windows_provenance import ValidatedWindowsProvenance
    from .upgrade_contract.transaction import (
        TransactionPrimitiveError,
        apply_create_only_plan,
        current_managed_content_paths,
        managed_content_sources_current,
        recover_create_only_transactions,
    )
    from .scripts.naos_emit_capabilities import (
        default_agent_files,
        default_skill_files,
        default_instruction_files,
        emit_catalogue,
        render_catalogue,
        write_catalogue,
    )
except ImportError:  # Direct checkout execution: python naos_init.py ...
    _KIT_IMPORT_ROOT = Path(__file__).resolve().parent
    if str(_KIT_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_KIT_IMPORT_ROOT))
    from scripts.validators.frontmatter_utils import skill_authoring_metadata
    from scripts.naos_console import configure_console_output
    from naos_profile_rules import load_profile_rules_source
    from upgrade_contract.canonical import canonical_sha256  # type: ignore[no-redef]
    from upgrade_contract.planner import (  # type: ignore[no-redef]
        build_create_only_plan,
        load_source_policy_snapshot,
        regular_file_observation,
        require_supported_source_metadata,
        revalidate_create_only_plan,
    )
    from upgrade_contract.provenance import (  # type: ignore[no-redef]
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_LOCK_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        ProvenanceError,
        begin_greenfield_root,
        build_greenfield_root_intent,
        commit_managed_content_enrollment,
        managed_content_creator_identity,
        finalize_greenfield_root,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from upgrade_contract.security import (  # type: ignore[no-redef]
        source_metadata_contract,
    )
    from upgrade_contract.private_preview import PrivatePreviewAddress, create_temporary_preview
    from upgrade_contract.source_origins import SourceOrigins  # type: ignore[no-redef]
    from upgrade_contract.source_modes import SourceModeError, mode_row  # type: ignore[no-redef]
    from upgrade_contract.generated_recipes import (  # type: ignore[no-redef]
        MAX_INPUTS, MAX_INPUT_BYTES, MAX_TOTAL_INPUT_BYTES, OverlayInputObserver,
        bounded_canonical_input,
    )
    from upgrade_contract.windows_provenance import ValidatedWindowsProvenance  # type: ignore[no-redef]
    from upgrade_contract.transaction import (  # type: ignore[no-redef]
        TransactionPrimitiveError,
        apply_create_only_plan,
        current_managed_content_paths,
        managed_content_sources_current,
        recover_create_only_transactions,
    )
    from scripts.naos_emit_capabilities import (  # type: ignore[no-redef]
        default_agent_files,
        default_skill_files,
        default_instruction_files,
        emit_catalogue,
        render_catalogue,
        write_catalogue,
    )

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

KIT_DIR = Path(__file__).parent
TEMPLATES_DIR = KIT_DIR / "templates"
ARCHETYPES_DIR = KIT_DIR / "archetypes"
POLICIES_DIR = KIT_DIR / "policies"
CAPABILITIES_DIR = KIT_DIR / "capabilities"
PROFILE_SURFACE_CONTRACT_PATH = KIT_DIR / "configs" / "profile_generated_surface_contract.json"
PROFILE_RULES_SOURCE_PATH = KIT_DIR / "configs" / "profile_rules_source.yaml"
UPGRADE_SOURCE_POLICY_PATH = KIT_DIR / "configs" / "upgrade_source_policy.yaml"

GENERATED_CACHE_DIR_NAMES = {"__pycache__"}
GENERATED_CACHE_FILE_SUFFIXES = {".pyc", ".pyo"}
GENERATED_CACHE_FILE_NAMES = {".DS_Store"}
BROWNFIELD_TOOL_ROOT = "naos_tools"
BROWNFIELD_RUFF_BOUNDARY = (
    "# Keep NAOS-generated Python under this reserved root outside adopter Ruff discovery.\n"
    "# Activation refuses this boundary when pre-existing Python is present here.\n"
    'exclude = ["**"]\n'
    "force-exclude = true\n"
)


def load_profile_surface_contract(tier: str) -> dict[str, Any]:
    """Load the machine-checkable generated-surface contract for one profile."""

    data = json.loads(PROFILE_SURFACE_CONTRACT_PATH.read_text(encoding="utf-8"))
    if data.get("schema") != "naos.profile_generated_surface_contract.v1":
        raise ValueError("Unsupported profile generated-surface contract")
    profiles = data.get("profiles") or {}
    if tier not in profiles:
        raise ValueError(f"Profile generated-surface contract is missing {tier!r}")
    return profiles[tier]


def validated_profile_rules_path(tier: str) -> Path:
    """Return a derived kit RULES artifact only after canonical parity proof."""

    contract = load_profile_rules_source(PROFILE_RULES_SOURCE_PATH, claim_root=KIT_DIR)
    entry = contract["profiles"][tier]
    profile_rules = KIT_DIR / entry["output_path"]
    if not profile_rules.is_file():
        raise ValueError(f"Derived profile RULES file is missing: {entry['output_path']}")
    expected = str(entry["content"]).encode("utf-8")
    if profile_rules.read_bytes() != expected:
        raise ValueError(
            f"Derived profile RULES drift detected for {tier}; "
            "run python3 -B naos_profile_rules.py --check and review before regeneration"
        )
    return profile_rules


def _persist_generated_policy_profile(policy_path: Path, tier: str) -> None:
    """Set the generated adopter policy default without changing the kit policy."""

    marker = "  default: quickstart"
    content = policy_path.read_text(encoding="utf-8")
    if content.count(marker) != 1:
        raise ValueError(
            "Generated policy must contain exactly one canonical profiles.default marker"
        )
    policy_path.write_text(
        content.replace(marker, f"  default: {tier}", 1),
        encoding="utf-8",
        newline="\n",
    )


def _preferred_installed_init_command() -> list[str]:
    """Return the clearest activation command for the current environment."""
    invoked_console = os.environ.get("NAOS_INVOKED_CONSOLE")
    if invoked_console == "naos-governance":
        return ["naos-governance", "init"]
    if invoked_console == "naos":
        return ["naos", "init"]
    if shutil.which("naos-governance"):
        return ["naos-governance", "init"]
    if shutil.which("naos"):
        return ["naos", "init"]
    return [sys.executable, str(Path(__file__).resolve())]


def _format_activation_command(parts: list[object], *, windows: bool | None = None) -> str:
    """Render one argv for PowerShell on Windows or a POSIX shell elsewhere."""
    use_powershell = os.name == "nt" if windows is None else windows
    if use_powershell:
        # Windows PowerShell 5.1 reserializes native argv incorrectly for empty
        # strings, embedded quotes and spaced paths ending in a backslash.
        # Supply the CRT command line directly, without another shell parse.
        executable, *arguments = (str(part) for part in parts)
        def quote(value: str) -> str:
            # PowerShell treats typographic apostrophes as delimiters too.
            return "'" + "".join(char * 2 if char in "'‘’‚‛" else char
                                 for char in value) + "'"

        return (
            "& { $naosStart = New-Object System.Diagnostics.ProcessStartInfo; "
            f"$naosStart.FileName = {quote(executable)}; "
            f"$naosStart.Arguments = {quote(subprocess.list2cmdline(arguments))}; "
            "$naosStart.UseShellExecute = $false; "
            "$naosStart.WorkingDirectory = $PWD.ProviderPath; "
            "$naosProcess = [System.Diagnostics.Process]::Start($naosStart); "
            "try { $naosProcess.WaitForExit(); "
            "$global:LASTEXITCODE = $naosProcess.ExitCode } "
            "finally { $naosProcess.Dispose() } }"
        )
    return shlex.join(str(part) for part in parts)


def _preferred_installed_naos_command() -> str:
    """Return the preferred visible NAOS command name for follow-up guidance."""
    invoked_console = os.environ.get("NAOS_INVOKED_CONSOLE")
    if invoked_console in {"naos-governance", "naos"}:
        return invoked_console
    if shutil.which("naos-governance"):
        return "naos-governance"
    if shutil.which("naos"):
        return "naos"
    return "naos"

PROFILES: dict[str, dict[str, Any]] = {
    "quickstart": {
        "rules_active": 5,
        "rules_blocking": 3,
        "overhead": "project-dependent; measure in the adopter repository",
        "ai_review": "Rule guidance + core pre-commit checks",
        "description": "Minimal guardrails for bounded evaluation and low-friction use.",
        "consequences": [
            "Rule 1 and Rule 2 have specific generated-hook checks",
            "Rule 10 requires source verification and project approval (blocking posture)",
            "No licence scanner or licence workflow is installed by default",
            "Anti-duplication guidance (Rule 11 — advisory)",
            "No required specs; one thin read-only research agent; bounded methodology surfaces",
        ],
        "upgrade_path": "Stay on quickstart unless the project purpose requires Lite's real-project workflow surfaces.",
    },
    "lite": {
        "rules_active": 9,
        "rules_blocking": 3,
        "overhead": "project-dependent; measure in the adopter repository",
        "ai_review": "Optional advisory only",
        "description": "Minimal rules, low friction. Good for solo devs and early-stage projects.",
        "consequences": [
            "Rule 1 and Rule 2 have specific generated-hook checks",
            "Rule 10 requires source verification and project approval (blocking posture)",
            "No licence scanner or licence workflow is installed by default",
            "No deep analysis enforcement (advisory only)",
            "No pre-commit rejection for drift",
        ],
        "upgrade_path": "Stay on Lite unless the project purpose requires Standard's broader evidence surfaces.",
    },
    "standard": {
        "rules_active": 19,
        "rules_blocking": 13,
        "overhead": "project-dependent; measure in the adopter repository",
        "ai_review": "Configurable AI policy (static, local, API, or IDE agent)",
        "description": "Balanced rules + configured review posture. Recommended for small teams and production projects.",
        "consequences": [
            "Broader blocking/required posture; executable checks remain source-specific",
            "Rule 10 requires approval but no licence scanner is installed by default",
            "Generated readiness CI surfaces bounded findings for review",
            "No automatic maturity, security, or compliance outcome",
        ],
        "upgrade_path": "Stay on Standard unless the project purpose requires Assured's stronger configured evidence posture.",
    },
    "assured": {
        "rules_active": 19,
        "rules_blocking": 19,
        "overhead": "project-dependent; measure in the adopter repository",
        "ai_review": "Strongest configured review posture + 4 human-review gates",
        "description": "Evidence-heavy profile. Blocking where configured, with explicit human-review gates.",
        "consequences": [
            "All active rules use blocking posture; only installed consumers can enforce",
            "Rule 10 requires sign-off but no licence scanner is installed by default",
            "Four rules require explicit human review where configured",
            "Evidence trail depends on generated reports and adopter-maintained records",
            "Review cadence remains adopter-owned and configured",
        ],
        "upgrade_path": "Select Assured only while its evidence and review purpose applies; profile choice is not a maturity rank.",
    },
}

ARCHETYPES: dict[str, dict[str, Any]] = {
    "django-postgresql": {
        "label": "Django + PostgreSQL",
        "language": "python",
        "framework": "django",
    },
    "nextjs-supabase": {
        "label": "Next.js + Supabase",
        "language": "typescript",
        "framework": "nextjs",
    },
    "go-grpc": {"label": "Go + gRPC + Kafka", "language": "go", "framework": "grpc"},
    "springboot-kafka": {
        "label": "Spring Boot + Kafka",
        "language": "java",
        "framework": "springboot",
    },
    "fastapi-generic": {
        "label": "FastAPI (generic)",
        "language": "python",
        "framework": "fastapi",
    },
    "custom": {"label": "Custom / Other", "language": None, "framework": None},
}

BACKENDS = {
    "1": {
        "key": "static_only",
        "label": "Static-only (guaranteed, no LLM or provider keys) ← recommended",
    },
    "2": {"key": "disabled", "label": "Disable AI semantic review (structural governance only)"},
    "3": {
        "key": "local_ollama",
        "label": "Local Ollama/GPU scaffold (user provides local runtime)",
    },
    "4": {"key": "api_provider", "label": "API provider scaffold (user provides env var/key)"},
    "5": {"key": "ide_agent", "label": "IDE-agent/manual review scaffold"},
}

MEMORY_CHOICES = ("later", "check", "centralized", "local", "disabled")
MEMORY_CHOICE_CONFIGS: dict[str, dict[str, str | bool]] = {
    "later": {
        "enabled": False,
        "state": "deferred",
        "disposition": "defer",
        "scope": "none",
    },
    "check": {
        "enabled": False,
        "state": "pending_existing_verification",
        "disposition": "use-existing",
        "scope": "user-centralized",
    },
    "centralized": {
        "enabled": False,
        "state": "pending_external_verification",
        "disposition": "configure-local",
        "scope": "user-centralized",
    },
    "local": {
        "enabled": False,
        "state": "pending_external_verification",
        "disposition": "configure-local",
        "scope": "user-centralized",
    },
    "disabled": {
        "enabled": False,
        "state": "disabled",
        "disposition": "decline",
        "scope": "none",
    },
}

LEGACY_BACKEND_ALIASES = {
    "auto": "static_only",
    "ollama": "local_ollama",
    "agent": "ide_agent",
}

# ─── SIGNAL → INSTRUCTION MAPPING ────────────────────────────────────────────
# Maps signal key → instruction filename(s) conditionally included when signal detected.
# Used by scaffold_files() to go beyond tier-based selection.

SIGNAL_INSTRUCTION_MAP: dict[str, list[str]] = {
    "has_sql_db": ["database.instructions.md"],
    "has_api": ["api-endpoints.instructions.md"],
    "has_containerisation": ["docker-deployment.instructions.md"],
    "has_llm": ["ai-pipeline.instructions.md"],
    "has_event_bus": ["event-bus.instructions.md"],
    "has_auth": ["security.instructions.md"],
    "has_graph_db": ["graph-database.instructions.md"],
    "is_node": ["frontend.instructions.md"],
}


def _signal_triggered_instructions(signals: dict) -> set[str]:
    """Return set of instruction filenames triggered by detected signals."""
    triggered: set[str] = set()
    for signal_key, instruction_files in SIGNAL_INSTRUCTION_MAP.items():
        if signals.get(signal_key):
            triggered.update(instruction_files)
    return triggered


def _make_template_context(
    project_path: Path,
    signals: dict,
    tier: str,
    archetype: str | None,
) -> dict[str, str]:
    """
    Build substitution context for instruction-triple templates from detected signals.
    Returns a dict compatible with string.Template.safe_substitute().
    Fallback values preserve [ADAPT: ...] guidance when signals are not detected.
    """
    ctx: dict[str, str] = {}

    # Project identity
    name = project_path.resolve().name
    ctx["signal_project_name"] = name if name not in (".", "") else "My Project"
    ctx["signal_profile"] = f"governance-{tier}"

    # Language
    lang_parts: list[str] = []
    if signals.get("is_python"):
        lang_parts.append("Python")
    if signals.get("is_node"):
        lang_parts.append("TypeScript/JavaScript")
    if signals.get("is_go"):
        lang_parts.append("Go")
    if signals.get("is_java"):
        lang_parts.append("Java")
    ctx["signal_language"] = (
        ", ".join(lang_parts)
        if lang_parts
        else "[ADAPT: Python / TypeScript / Go / Java / ...]"
    )

    # Framework
    frameworks = signals.get("web_frameworks") or []
    ctx["signal_framework"] = (
        ", ".join(frameworks)
        if frameworks
        else "[ADAPT: FastAPI / Django / Next.js / Spring Boot / ...]"
    )

    # Tech-stack table rows
    ctx["signal_backend_stack"] = (
        ", ".join(frameworks) if frameworks else "[ADAPT: framework, version]"
    )
    dbs = signals.get("database_engines") or []
    ctx["signal_database_stack"] = (
        ", ".join(dbs) if dbs else "[ADAPT: engine, version or N/A]"
    )
    ctx["signal_queue_stack"] = (
        "Kafka / Redis (detected)" if signals.get("has_event_bus") else "N/A"
    )
    llm_providers = signals.get("llm_providers") or []
    if llm_providers:
        ctx["signal_llm_stack"] = ", ".join(llm_providers)
    elif signals.get("has_llm"):
        ctx["signal_llm_stack"] = "LLM (provider detected)"
    else:
        ctx["signal_llm_stack"] = "N/A"

    # Build / test / run commands for CLAUDE.md
    if signals.get("is_python"):
        ctx["signal_install_cmd"] = (
            "pip install -r requirements.txt"
            "  # or: conda activate <env> / python -m venv .venv && pip install -r requirements.txt"
        )
        ctx["signal_test_cmd"] = "pytest -q tests/unit tests/acceptance"
        ctx["signal_run_cmd"] = (
            "uvicorn src.main:app --reload  # [ADAPT: adjust to your app entrypoint]"
        )
        if signals.get("has_alembic"):
            ctx["signal_migrate_cmd"] = "alembic upgrade head  # apply pending migrations"
        elif signals.get("has_sql_migrations"):
            ctx["signal_migrate_cmd"] = (
                "[ADAPT: run the project migration runner for detected SQL files, "
                "for example migrations/*.sql]"
            )
        elif signals.get("has_sql_db"):
            ctx["signal_migrate_cmd"] = (
                "[ADAPT: migration command for the detected SQL database]"
            )
        else:
            ctx["signal_migrate_cmd"] = "# No SQL migrations detected"
    elif signals.get("is_node"):
        ctx["signal_install_cmd"] = "npm install"
        ctx["signal_test_cmd"] = "npm test"
        ctx["signal_run_cmd"] = "npm run dev"
        ctx["signal_migrate_cmd"] = "# [ADAPT: migration command if applicable]"
    elif signals.get("is_go"):
        ctx["signal_install_cmd"] = "go mod download"
        ctx["signal_test_cmd"] = "go test ./..."
        ctx["signal_run_cmd"] = "go run main.go  # [ADAPT: adjust entrypoint]"
        ctx["signal_migrate_cmd"] = "# [ADAPT: migration command if applicable]"
    elif signals.get("is_java"):
        ctx["signal_install_cmd"] = "mvn install  # or: gradle build"
        ctx["signal_test_cmd"] = "mvn test  # or: gradle test"
        ctx["signal_run_cmd"] = "mvn spring-boot:run  # [ADAPT: adjust]"
        ctx["signal_migrate_cmd"] = "# [ADAPT: migration command if applicable]"
    else:
        ctx["signal_install_cmd"] = (
            "[ADAPT: install command, e.g., pip install -r requirements.txt]"
        )
        ctx["signal_test_cmd"] = "[ADAPT: test command, e.g., pytest -q tests/]"
        ctx["signal_run_cmd"] = "[ADAPT: dev server command]"
        ctx["signal_migrate_cmd"] = "[ADAPT: migration command if applicable]"

    return ctx


def _populate_templates(preview_dir: Path, ctx: dict[str, str]) -> None:
    """
    Apply signal-based auto-population to instruction-triple template files.
    Unknown signal placeholders receive ADAPT fallbacks; other $xxx markers remain intact.
    Files modified in-place within preview_dir.
    """
    from string import Template

    target_files = (".github/project-context.md", "CLAUDE.md",
                    ".github/copilot-instructions.md")
    for tpl_name in target_files:
        tpl_path = preview_dir / tpl_name
        if not tpl_path.exists():
            continue
        content = tpl_path.read_text(encoding="utf-8", errors="replace")
        populated = Template(content).safe_substitute(ctx)
        populated = re.sub(
            r"\$(?:\{(signal_[A-Za-z0-9_]+)\}|(signal_[A-Za-z0-9_]+))",
            lambda match: "[ADAPT: " + (match.group(1) or match.group(2)) + "]",
            populated,
        )
        tpl_path.write_text(populated, encoding="utf-8", newline="\n")



def _provisional_archetype_context(content: str, archetype: str, tier: str) -> str:
    """Render a preset as proposals, never as evidence of the adopter's stack.

    Selection origin is not preserved by managed replay. Apply identical
    semantics to explicit and inferred selections instead of inventing a
    confirmation flag. Fenced examples remain literal, under ADAPT guidance.
    """
    def proposal(value: str) -> str:
        if "[ADAPT:" in value:
            # Preserve existing adaptation blocks, including partial values.
            return value if value.startswith("[ADAPT:") else "Proposed " + value
        return "[ADAPT: proposed " + value + "]"

    def table_separator(line: str) -> bool:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        return line.strip().startswith("|") and all(
            re.fullmatch(r":?-{3,}:?", cell) for cell in cells
        )

    rendered = [
        "# Project Context", "",
        "## NAOS Configuration Choices", "",
        f"- NAOS profile: governance-{tier}",
        f"- Selected archetype: {archetype}", "",
        "These are scaffolder configuration choices, not verified architecture.", "",
        "## Proposed Archetype Guidance", "",
    ]
    lines = content.splitlines()
    in_fence = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_fence:
                rendered.extend(["[ADAPT: Proposed preset example; confirm or replace before use.]", ""])
            in_fence = not in_fence
            rendered.append(line)
        elif in_fence or not stripped or stripped == "---":
            rendered.append(line)
        elif stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped[level:].strip()
            # Keep the original relative hierarchy below the guidance section.
            rendered.append("#" * min(level + 2, 6) + " " + proposal(title))
        elif stripped.startswith("|"):
            next_line = lines[index + 1] if index + 1 < len(lines) else ""
            if table_separator(line) or table_separator(next_line):
                rendered.append(line)
            else:
                cells = [cell.strip() for cell in stripped.strip("|").split("|")]
                rendered.append("| " + " | ".join(
                    [cells[0], *(proposal(cell) for cell in cells[1:])]
                ) + " |")
        else:
            # Leave Markdown containers outside the adaptation marker.
            match = re.match(r"^(\s*(?:>\s*)*(?:(?:[-+*]|\d+[.)])\s+)?)(.*)$", line)
            prefix, value = match.groups()
            field = re.match(r"(\*\*[^*]+\*\*:\s*)(.*)", value)
            if field:
                rendered.append(prefix + field.group(1) + proposal(field.group(2)))
            else:
                rendered.append(prefix + proposal(value))
    return "\n".join(rendered) + "\n"


def _copy_generated_script(
    src: Path, dest: Path, *, source_origins: SourceOrigins | None = None,
    copied_tool_outputs: set[Path] | None = None,
) -> None:
    if source_origins is None:
        shutil.copy2(src, dest)
    else:
        source_origins.copy2(src, dest)
    if dest.suffix != ".py":
        return
    if copied_tool_outputs is not None:
        copied_tool_outputs.add(dest)

    text = dest.read_text(encoding="utf-8")
    if "# AUTO-GENERATED" in text[:2048]:
        return

    marker = "# AUTO-GENERATED: Copied by naos init from the NAOS kit.\n"
    if text.startswith("#!"):
        first_line, _, rest = text.partition("\n")
        dest.write_text(f"{first_line}\n{marker}{rest}", encoding="utf-8", newline="\n")
    else:
        dest.write_text(f"{marker}{text}", encoding="utf-8", newline="\n")


def _finalize_copied_tool_content(
    preview_dir: Path, copied_tool_outputs: set[Path],
    *, source_origins: SourceOrigins | None = None,
) -> None:
    """Commit only writer-known final copy outputs in the selected validator.

    No existing adopter tree, marker, or external manifest is consulted. The
    control trusts the generator/validator; hashes establish content identity.
    """
    validator_paths = [path for path in copied_tool_outputs if (
        path.relative_to(preview_dir).parts[0] in {"scripts", "naos_tools"}
        and path.relative_to(preview_dir).parts[1:]
        == ("validators", "validate_traceability_headers.py"))]
    if not validator_paths:
        return
    if len(validator_paths) != 1 or len(copied_tool_outputs) > MAX_INPUTS - 1:
        raise SourceModeError("Copied-tool content inventory is ambiguous or oversized")
    validator = validator_paths[0]
    destination = validator.relative_to(preview_dir).as_posix()
    inputs: list[tuple[str, bytes]] = []
    content: dict[str, dict[str, str]] = {}
    remaining = MAX_TOTAL_INPUT_BYTES
    for path in sorted(copied_tool_outputs):
        relative = path.relative_to(preview_dir)
        if (relative.parts[0] not in {"scripts", "naos_tools"}
                or relative.suffix != ".py"):
            raise SourceModeError("Copied-tool content output is outside its role")
        cursor = preview_dir
        for part in relative.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink() or not cursor.is_dir():
                raise SourceModeError("Linked or invalid copied-tool ancestor")
        raw = SourceOrigins._bounded_bytes(path, remaining=min(MAX_INPUT_BYTES, remaining))
        remaining -= len(raw)
        inputs.append(("generated/" + relative.as_posix(), raw))
        if path != validator:
            content[relative.as_posix()] = {
                "sha256": hashlib.sha256(raw).hexdigest(), "size_decimal": str(len(raw)),
            }
    raw_validator = dict(inputs)["generated/" + destination]
    begin = "# BEGIN NAOS COPIED TOOL CONTENT\n"
    end = "# END NAOS COPIED TOOL CONTENT"
    template = raw_validator.decode("utf-8")
    if template.count(begin) != 1 or template.count(end) != 1:
        raise SourceModeError("Copied validator has no unique tool-content slot")
    start = template.index(begin) + len(begin)
    finish = template.index(end)
    if finish <= start or template[start:finish] != "COPIED_TOOL_CONTENT = {}\n":
        raise SourceModeError("Copied validator tool-content slot was already materialized")
    rendered = (template[:start] + "COPIED_TOOL_CONTENT = "
                + json.dumps(content, sort_keys=True, indent=4) + "\n" + template[finish:])
    if source_origins is not None:
        source_origins.record_copied_tool_content(destination, sorted(inputs))
    validator.write_text(rendered, encoding="utf-8", newline="\n")


def _is_generated_cache_artifact(rel: Path) -> bool:
    if any(part in GENERATED_CACHE_DIR_NAMES for part in rel.parts):
        return True
    if rel.name in GENERATED_CACHE_FILE_NAMES:
        return True
    return rel.suffix in GENERATED_CACHE_FILE_SUFFIXES


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_same_or_descendant_by_identity(child: Path, parent: Path) -> bool:
    """Compare existing path components by filesystem identity.

    This supplements lexical containment on case-insensitive filesystems, where
    differently cased spellings of the same directory do not compare equal.
    Any identity-check failure is unsafe for selecting external staging.
    """

    try:
        parent.stat()
    except FileNotFoundError:
        # No object identity exists yet. Lexical containment remains controlling.
        return False
    except OSError:
        return True

    for candidate in (child, *child.parents):
        try:
            if candidate.samefile(parent):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _safe_generated_relpath(value: str | Path) -> Path:
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts or rel == Path("."):
        raise ValueError(f"Generated preview path is unsafe: {value}")
    return rel


class ExistingPreviewRefusal(ValueError):
    """A pre-existing preview was preserved before generation or activation."""


class UnsupportedPreviewLocation(ValueError):
    """A persistent preview path inside the target is not the canonical root."""


class ActivationFailure(RuntimeError):
    """Activation began and the target may therefore be partially changed."""


class ActivationPreflightRefusal(ValueError):
    """Activation was refused before any activation destination was changed."""


def prepare_preview_dir(
    preview_dir: Path, project_path: Path, *,
    private_preview_address: PrivatePreviewAddress | None = None,
) -> None:
    io_preview = preview_dir
    if private_preview_address is not None:
        private_preview_address.require_root(preview_dir)
        io_preview = Path(private_preview_address.io_root)
    try:
        preview_metadata = io_preview.lstat()
    except FileNotFoundError:
        preview_metadata = None
    if preview_metadata is not None and io_preview.is_symlink():
        raise ExistingPreviewRefusal(
            "Preview path is an existing symbolic link; refusing to replace content "
            f"without provenance: {preview_dir}"
        )

    preview_resolved = io_preview.resolve(strict=False)
    if private_preview_address is not None:
        preview_resolved = private_preview_address.resolved_ordinary_root(preview_resolved)
    project_resolved = project_path.resolve(strict=False)
    if preview_resolved == project_resolved or _is_within(project_resolved, preview_resolved):
        raise UnsupportedPreviewLocation(
            f"Preview directory must not be the project root or contain it: {preview_dir}"
        )
    preview_is_inside_project = _is_within(
        preview_resolved,
        project_resolved,
    ) or _is_same_or_descendant_by_identity(
        io_preview if private_preview_address is not None else preview_resolved,
        project_resolved,
    )
    canonical_in_project_preview = (
        preview_resolved == project_resolved / ".naos-preview"
    )
    if not canonical_in_project_preview and preview_resolved.name == ".naos-preview":
        try:
            canonical_in_project_preview = preview_resolved.parent.samefile(
                project_resolved
            )
        except OSError:
            pass
    if preview_is_inside_project and not canonical_in_project_preview:
        raise UnsupportedPreviewLocation(
            "A persistent preview inside the target must be the direct "
            f"{project_resolved / '.naos-preview'} path; use an absent path outside "
            "the target for any other preview name."
        )
    if preview_metadata is not None:
        raise ExistingPreviewRefusal(
            "Preview directory already exists; refusing to replace content without "
            f"provenance: {preview_dir}"
        )
    try:
        io_preview.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise ExistingPreviewRefusal(
            "Preview path appeared before creation; refusing to replace content "
            f"without provenance: {preview_dir}"
        ) from exc


def _select_external_temp_root(project_path: Path) -> Path | None:
    """Return an existing temporary root that is outside the adopter project."""

    project_resolved = project_path.resolve(strict=False)
    configured_temp = next(
        (os.environ[name] for name in ("TMPDIR", "TEMP", "TMP") if os.environ.get(name)),
        None,
    )
    if configured_temp is not None:
        candidates = [Path(configured_temp)]
    elif os.name == "nt":
        candidates = [
            Path(value) / suffix
            for name, suffix in (
                ("LOCALAPPDATA", "Temp"),
                ("USERPROFILE", "AppData/Local/Temp"),
                ("SystemRoot", "Temp"),
            )
            if (value := os.environ.get(name))
        ]
    else:
        candidates = [Path("/tmp"), Path("/var/tmp"), Path("/usr/tmp")]

    for candidate in candidates:
        try:
            resolved_candidate = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if not resolved_candidate.is_dir():
            continue
        if resolved_candidate == project_resolved or _is_within(
            resolved_candidate,
            project_resolved,
        ) or _is_same_or_descendant_by_identity(
            resolved_candidate,
            project_resolved,
        ):
            continue
        return resolved_candidate
    return None


def _no_bytecode_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


_BROWNFIELD_INIT_USAGE_SCOPES = ("brownfield_adoption",)
_BROWNFIELD_GENERATION_BINDING_FIELDS = (
    "generation_id",
    "generation_content_sha256",
    "manifest_file_sha256",
    "manifest_sha256",
    "validation_receipt_file_sha256",
    "validation_receipt_sha256",
    "activation_receipt_file_sha256",
    "activation_receipt_sha256",
    "effective_source_sha256",
    "transaction_id",
    "profile",
    "purpose",
    "component_mode",
)


def _brownfield_repository_intelligence_guidance(
    project_path: Path,
    *,
    tier: str,
) -> dict[str, Any]:
    scripts_dir = KIT_DIR / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from naos_setup_recommendations import (  # type: ignore[import-not-found]
            build_repository_intelligence_guidance,
        )
    except ImportError as exc:
        raise RuntimeError(
            "repository-intelligence pre-start runtime is unavailable"
        ) from exc
    return build_repository_intelligence_guidance(
        project_path,
        "naos",
        tier,
        required_usage_scopes=_BROWNFIELD_INIT_USAGE_SCOPES,
    )


def _brownfield_generation_binding(guidance: dict[str, Any]) -> dict[str, Any] | None:
    if guidance.get("lifecycle_status") != "validated_current":
        return None
    active_context = guidance.get("active_context")
    generation = (
        active_context.get("generation")
        if isinstance(active_context, dict)
        and isinstance(active_context.get("generation"), dict)
        else None
    )
    if generation is None:
        raise RuntimeError(
            "validated repository-intelligence guidance lacks generation metadata"
        )
    binding = {
        field: generation.get(field)
        for field in _BROWNFIELD_GENERATION_BINDING_FIELDS
    }
    if any(value in {None, ""} for value in binding.values()):
        raise RuntimeError(
            "validated repository-intelligence guidance has an incomplete binding"
        )
    return binding


def _brownfield_prestart_binding(guidance: dict[str, Any]) -> dict[str, Any] | None:
    generation = _brownfield_generation_binding(guidance)
    if generation is not None:
        return {
            "binding_type": "validated_generation",
            "generation": generation,
        }
    if guidance.get("lifecycle_status") != "not_applicable":
        return None
    decision = {
        "binding_type": "not_applicable_plan",
        "plan_id": guidance.get("plan_id"),
        "plan_sha256": guidance.get("plan_sha256"),
        "effective_source_sha256": guidance.get("effective_source_sha256"),
        "selected_profile": guidance.get("selected_profile"),
        "purpose": guidance.get("purpose"),
        "component_mode": guidance.get("component_mode"),
        "rules_sha256": guidance.get("rules_sha256"),
        "plan_status": guidance.get("plan_status"),
        "recommendation": guidance.get("recommendation"),
        "required_usage_scopes": guidance.get("required_usage_scopes") or [],
        "coverage": guidance.get("coverage") or {},
        "profile_gate": guidance.get("profile_gate") or {},
        "finding_ids": guidance.get("finding_ids") or [],
    }
    if any(
        decision.get(field) in {None, ""}
        for field in (
            "plan_id",
            "plan_sha256",
            "effective_source_sha256",
            "selected_profile",
            "purpose",
            "component_mode",
            "rules_sha256",
            "plan_status",
            "recommendation",
        )
    ):
        raise RuntimeError(
            "not-applicable repository-intelligence guidance has an incomplete decision binding"
        )
    return {
        **decision,
        "decision_sha256": canonical_sha256(decision),
    }


def _revalidate_brownfield_init_prestart(
    args: argparse.Namespace,
    project_path: Path,
    *,
    tier: str,
) -> None:
    opening = getattr(args, "_brownfield_repository_intelligence", None)
    if not isinstance(opening, dict):
        return
    closing = _brownfield_repository_intelligence_guidance(project_path, tier=tier)
    if not closing.get("continuation_allowed"):
        action = str(
            (closing.get("installation") or {}).get("next_action")
            or "resolve repository-intelligence pre-start requirements"
        )
        if closing.get("error"):
            action += " Reason: " + str(closing["error"])
        raise ActivationPreflightRefusal(
            "repository intelligence changed before activation; " + action
        )
    opening_binding = _brownfield_prestart_binding(opening)
    closing_binding = _brownfield_prestart_binding(closing)
    if opening_binding != closing_binding:
        raise ActivationPreflightRefusal(
            "repository-intelligence lifecycle or immutable generation binding changed before activation"
        )


def _windows_cli():
    """Select native Windows before entering POSIX provenance or FFI paths."""
    if sys.platform != "win32":
        return None
    try:
        from .upgrade_contract import windows_cli
    except ImportError:
        from upgrade_contract import windows_cli
    return windows_cli


def _validated_current_managed_paths(project_path: Path) -> set[str]:
    """Return only provenance-validated, byte/metadata-current managed paths."""

    windows = _windows_cli()
    if windows is not None:
        return windows.current_paths(project_path)
    root = project_path.resolve(strict=True)
    scope = inspect_managed_content_scope(root)
    manifest_path = root / MANAGED_CONTENT_MANIFEST_RELATIVE
    if scope.status != "valid":
        if manifest_path.exists():
            raise ActivationPreflightRefusal(
                "managed-content state exists without valid provenance"
            )
        return set()
    if (
        not scope.project_id
        or not scope.scope_integrity
        or not scope.source_policy_sha256
    ):
        raise ActivationPreflightRefusal(
            "managed-content provenance binding is incomplete"
        )
    return current_managed_content_paths(
        root,
        manifest_path=manifest_path,
        bases_root=root / MANAGED_CONTENT_BASES_RELATIVE,
        receipts_root=root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
        project_id=scope.project_id,
        scope_integrity_sha3_512=scope.scope_integrity,
        source_policy_sha256=scope.source_policy_sha256,
    )


def _route_managed_init_transition(
    args: argparse.Namespace,
    project_path: Path,
    *,
    requested_profile: str,
) -> int | None:
    """Route managed-project transitions to the immutable upgrade planner.

    Returning ``None`` leaves initial brownfield onboarding or an ordinary
    same-profile preview with the existing init workflow. A managed activation
    is always plan-only; init must never recreate or replace an owned leaf.
    """

    try:
        from .upgrade_contract.v3_recovery import has_v3_control, _present
        from .upgrade_contract.joint_capture import capture_portable_working_tree
        from .upgrade_contract.rebind_store_inspection import ROOT as v3_store_root
    except ImportError:
        from upgrade_contract.v3_recovery import has_v3_control, _present
        from upgrade_contract.joint_capture import capture_portable_working_tree
        from upgrade_contract.rebind_store_inspection import ROOT as v3_store_root
    portable_v3 = has_v3_control(project_path)
    if portable_v3:
        # Validate portable history/current capture before reading any legacy
        # enrollment. Presence alone grants no receiving-checkout authority.
        pair = capture_portable_working_tree(project_path)
        previous_inputs = pair.portable.inputs
        if not _present(project_path, v3_store_root):
            requirement = (
                "explicit preserved-history migration; legacy storage exists"
                if _present(project_path, ".naos/upgrade-v1")
                else "explicit receiving rebind; local storage is absent"
            )
            print(
                "NOT_APPLIED: portable v3 history requires " + requirement +
                " before managed init review. The project was preserved.",
                file=sys.stderr,
            )
            return 3
    else:
        windows = _windows_cli()
        if windows is not None:
            snapshot = windows.inspect(project_path)
            if snapshot is None or snapshot.previous_inputs is None:
                return None
            previous_inputs = snapshot.previous_inputs
        else:
            inspection = inspect_managed_content_manifest(project_path)
            if not inspection.apply_eligible or inspection.snapshot is None:
                return None
            previous_inputs = inspection.snapshot.get("previous_inputs")
    if not isinstance(previous_inputs, dict):
        raise ActivationPreflightRefusal(
            "managed-content provenance has no preserved initialization inputs"
        )
    previous_profile = previous_inputs.get("profile")
    if not (
        portable_v3
        or args.activate
        or args.dry_run
        or previous_profile != requested_profile
    ):
        return None
    if args.preview_dir is not None:
        print(
            "NOT_APPLIED: managed init transitions use an external immutable "
            "upgrade plan; --preview-dir is not applicable. Use `naos upgrade "
            "PROJECT --tier T --plan-out EXTERNAL_FILE`.",
            file=sys.stderr,
        )
        return 2

    supplied = {
        "archetype": args.archetype,
        "backend": (
            LEGACY_BACKEND_ALIASES.get(args.backend, args.backend)
            if args.backend is not None
            else None
        ),
        "memory_choice": args.memory,
    }
    conflicts = sorted(
        key
        for key, value in supplied.items()
        if value is not None and previous_inputs.get(key) != value
    )
    if conflicts:
        print(
            "NOT_APPLIED: managed init transitions preserve provenance-bound "
            "profile-independent choices; conflicting overrides: "
            + ", ".join(conflicts),
            file=sys.stderr,
        )
        return 2

    if args.activate:
        print(
            "  PLAN_ONLY: direct `naos init --activate` cannot mutate an already "
            "managed project. Persist this transition with `naos upgrade PROJECT "
            "--tier T --plan-out EXTERNAL_FILE`, then apply that exact file with "
            "`naos upgrade PROJECT --apply-plan FILE --expect-plan-digest SHA256`.",
            file=sys.stderr,
        )
    try:
        try:
            from . import naos_upgrade as upgrade_module
        except ImportError:
            import naos_upgrade as upgrade_module  # type: ignore[no-redef]
        status = upgrade_module.plan_profile_transition(
            project_path,
            requested_profile=requested_profile,
            summary_only=True,
        )
        # A successful plan does not fulfill an explicit activation request.
        # Preserve planner failures and the success status of ordinary previews.
        return 3 if args.activate and status == 0 else status
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            f"NOT_APPLIED: managed init transition planning failed: {exc}",
            file=sys.stderr,
        )
        if portable_v3:
            print(
                "For a moved/copied project, inspect with `naos upgrade PROJECT "
                "--inspect-receiving-store`; explicit receiving rebind is required "
                "before managed changes. Do not delete existing local or legacy "
                "history.",
                file=sys.stderr,
            )
        return 3


# ─── DETECTION ────────────────────────────────────────────────────────────────


def _iter_detection_paths(
    project_path: Path,
    pattern: str = "*",
    *,
    excluded_paths: set[str] | None = None,
):
    """Yield project paths without entering the operation-owned preview root."""

    ignored_directories = {".git", "node_modules", ".venv", "venv", "__pycache__"}
    first_level = True
    for current_root, directory_names, file_names in os.walk(
        project_path,
        topdown=True,
        followlinks=False,
    ):
        directory_names[:] = sorted(
            name for name in directory_names if name not in ignored_directories
        )
        file_names.sort()
        if first_level:
            directory_names[:] = [
                name
                for name in directory_names
                if name not in {".naos-preview", ".naos"}
            ]
            first_level = False
        current = Path(current_root)
        for name in (*directory_names, *file_names):
            path = current / name
            relative_text = path.relative_to(project_path).as_posix()
            if relative_text in (excluded_paths or set()):
                continue
            if path.match(pattern):
                yield path


def detect_signals(
    project_path: Path,
    *,
    excluded_paths: set[str] | None = None,
) -> dict[str, Any]:
    """Detect tech stack signals from existing project directory tree."""
    signals: dict[str, Any] = {
        "is_python": False,
        "is_node": False,
        "is_go": False,
        "is_java": False,
        "has_api": False,
        "has_sql_db": False,
        "has_alembic": False,
        "has_sql_migrations": False,
        "has_vector_store": False,
        "has_llm": False,
        "has_event_bus": False,
        "has_auth": False,
        "has_graph_db": False,
        "has_multi_tenancy": False,
        "has_containerisation": False,
        "has_ci_cd": False,
        "web_frameworks": [],
        "database_engines": [],
        "llm_providers": [],
        "detected_archetype": None,
    }

    if not project_path.is_dir():
        return signals

    excluded = excluded_paths or set()
    files = list(_iter_detection_paths(project_path, excluded_paths=excluded))
    file_names = {f.name for f in files if f.is_file()}
    rel_paths = {str(f.relative_to(project_path)) for f in files if f.is_file()}

    # Language detection
    py_files = [f for f in files if f.suffix == ".py"]
    ts_files = [f for f in files if f.suffix in (".ts", ".tsx")]
    go_files = [f for f in files if f.suffix == ".go"]
    java_files = [f for f in files if f.suffix == ".java"]

    signals["is_python"] = len(py_files) > 5
    signals["is_node"] = len(ts_files) > 3 or "package.json" in file_names
    signals["is_go"] = len(go_files) > 2 or "go.mod" in file_names
    signals["is_java"] = (
        len(java_files) > 2 or "pom.xml" in file_names or "build.gradle" in file_names
    )

    # Framework detection
    if _file_contains(project_path, "requirements.txt", "fastapi", excluded) or _file_contains(
        project_path, "pyproject.toml", "fastapi", excluded
    ):
        signals["web_frameworks"].append("fastapi")
        signals["has_api"] = True
    if _file_contains(project_path, "requirements.txt", "django", excluded) or _file_contains(
        project_path, "pyproject.toml", "django", excluded
    ):
        signals["web_frameworks"].append("django")
        signals["has_api"] = True
    if "next.config" in " ".join(file_names):
        signals["web_frameworks"].append("nextjs")
        signals["has_api"] = True
    if "go.mod" in file_names and any("grpc" in str(f) for f in rel_paths):
        signals["web_frameworks"].append("grpc")
        signals["has_api"] = True
    if "pom.xml" in file_names or "build.gradle" in file_names:
        signals["web_frameworks"].append("spring")
        signals["has_api"] = True

    # DB detection
    for req_file in ["requirements.txt", "pyproject.toml", "package.json"]:
        if _file_contains(project_path, req_file, "postgres", excluded) or _file_contains(
            project_path, req_file, "psycopg", excluded
        ):
            signals["has_sql_db"] = True
            signals["database_engines"].append("postgresql")
        if _file_contains(project_path, req_file, "supabase", excluded):
            signals["database_engines"].append("supabase")
            signals["has_sql_db"] = True
        if (
            _file_contains(project_path, req_file, "chroma", excluded)
            or _file_contains(project_path, req_file, "qdrant", excluded)
            or _file_contains(project_path, req_file, "pinecone", excluded)
        ):
            signals["has_vector_store"] = True
    if "alembic.ini" in file_names or (project_path / "alembic").is_dir():
        signals["has_alembic"] = True
        signals["has_sql_db"] = True
    if _has_sql_migration_files(project_path, excluded_paths=excluded):
        signals["has_sql_migrations"] = True
        signals["has_sql_db"] = True

    # LLM detection
    for req_file in ["requirements.txt", "pyproject.toml", "package.json"]:
        if _file_contains(project_path, req_file, "anthropic", excluded):
            signals["has_llm"] = True
            signals["llm_providers"].append("anthropic")
        if _file_contains(project_path, req_file, "openai", excluded):
            signals["has_llm"] = True
            signals["llm_providers"].append("openai")
        if _file_contains(project_path, req_file, "langchain", excluded) or _file_contains(
            project_path, req_file, "llamaindex", excluded
        ):
            signals["has_llm"] = True

    # Event bus detection
    for req_file in ["requirements.txt", "pyproject.toml", "pom.xml", "go.mod"]:
        if (
            _file_contains(project_path, req_file, "kafka", excluded)
            or _file_contains(project_path, req_file, "redis", excluded)
            or _file_contains(project_path, req_file, "celery", excluded)
        ):
            signals["has_event_bus"] = True

    # Auth detection
    for req_file in ["requirements.txt", "pyproject.toml", "package.json"]:
        if _file_contains(project_path, req_file, "jwt", excluded) or _file_contains(
            project_path, req_file, "auth", excluded
        ):
            signals["has_auth"] = True

    # CI/CD
    if _directory_has_unmanaged_files(
        project_path,
        project_path / ".github" / "workflows",
        excluded,
    ) or (
        (project_path / ".gitlab-ci.yml").exists()
        and ".gitlab-ci.yml" not in excluded
    ):
        signals["has_ci_cd"] = True

    # Docker
    if (
        (project_path / "docker-compose.yml").exists()
        and "docker-compose.yml" not in excluded
    ) or (
        (project_path / "Dockerfile").exists()
        and "Dockerfile" not in excluded
    ):
        signals["has_containerisation"] = True

    # Graph DB
    for req_file in ["requirements.txt", "pyproject.toml"]:
        if (
            _file_contains(project_path, req_file, "neo4j", excluded)
            or _file_contains(project_path, req_file, "arango", excluded)
            or _file_contains(project_path, req_file, "dgraph", excluded)
        ):
            signals["has_graph_db"] = True

    # Multi-tenancy heuristic
    if _grep_recursive(
        project_path,
        "tenant_id",
        ["*.py", "*.ts", "*.java", "*.go"],
        excluded_paths=excluded,
        candidate_paths=files,
    ):
        signals["has_multi_tenancy"] = True

    # Best-match archetype
    signals["detected_archetype"] = _match_archetype(signals)

    return signals


def _file_contains(
    project_path: Path,
    filename: str,
    keyword: str,
    excluded_paths: set[str] | None = None,
) -> bool:
    if filename in (excluded_paths or set()):
        return False
    target = project_path / filename
    if target.exists():
        try:
            return keyword.lower() in target.read_text(errors="replace").lower()
        except Exception:
            pass
    return False


def _grep_recursive(
    project_path: Path,
    pattern: str,
    globs: list[str],
    *,
    excluded_paths: set[str] | None = None,
    candidate_paths: list[Path] | None = None,
) -> bool:
    """Check if pattern appears in any file matching globs (capped at 200 files)."""
    paths = candidate_paths if candidate_paths is not None else list(
        _iter_detection_paths(project_path, excluded_paths=excluded_paths)
    )
    checked = 0
    for glob in globs:
        for f in paths:
            if not f.match(glob):
                continue
            try:
                if pattern in f.read_text(errors="replace"):
                    return True
            except Exception:
                pass
            checked += 1
            if checked >= 200:
                return False
    return False


def _has_sql_migration_files(
    project_path: Path,
    *,
    excluded_paths: set[str] | None = None,
) -> bool:
    """Detect common SQL migration layouts without assuming the migration runner."""
    migration_dirs = [
        project_path / "migrations",
        project_path / "db" / "migrations",
        project_path / "database" / "migrations",
        project_path / "sql" / "migrations",
    ]
    for migration_dir in migration_dirs:
        if not migration_dir.is_dir():
            continue
        try:
            if any(
                path.is_file()
                and path.relative_to(project_path).as_posix()
                not in (excluded_paths or set())
                for path in migration_dir.rglob("*.sql")
            ):
                return True
        except OSError:
            continue
    return False


def _directory_has_unmanaged_files(
    project_path: Path,
    directory: Path,
    excluded_paths: set[str],
    observer: OverlayInputObserver | None = None,
) -> bool:
    if observer is not None:
        relative = directory.relative_to(project_path).as_posix()
        state = observer.directory_state(directory)
        if state != "directory":
            observer.decision("namespace/" + relative, {"state": state})
            return False
        return observer.unmanaged_witness(directory, excluded_paths)
    if not directory.is_dir() or directory.is_symlink():
        return False
    try:
        return any(
            path.is_file()
            and path.relative_to(project_path).as_posix() not in excluded_paths
            for path in directory.rglob("*")
        )
    except OSError:
        return False


def _match_archetype(signals: dict) -> str | None:
    """Return the best-matching archetype key given detected signals."""
    if (
        "django" in signals["web_frameworks"]
        and "postgresql" in signals["database_engines"]
    ):
        return "django-postgresql"
    if "nextjs" in signals["web_frameworks"]:
        return "nextjs-supabase"
    if "grpc" in signals["web_frameworks"] and signals["is_go"]:
        return "go-grpc"
    if "spring" in signals["web_frameworks"] and signals["has_event_bus"]:
        return "springboot-kafka"
    if "fastapi" in signals["web_frameworks"]:
        return "fastapi-generic"
    return None


# ─── DISPLAY ──────────────────────────────────────────────────────────────────


def print_banner() -> None:
    print("\n" + "=" * 60)
    print("  NAOS — AI Governance Scaffolder")
    print("  Portable Governance Kit")
    print("=" * 60 + "\n")


def print_profile_comparison() -> None:
    """Display the four-profile posture comparison table."""
    print("\n  NAOS Governance Profiles\n")
    print(
        f"  {'Profile':<12} {'Rules':<8} {'Blocking posture':<18} {'Overhead':<30} {'AI Review'}"
    )
    print("  " + "─" * 88)
    for tier, info in PROFILES.items():
        print(
            f"  {tier:<12} {info['rules_active']:<8} {info['rules_blocking']:<18} "
            f"{info['overhead']:<30} {info['ai_review']}"
        )
    print("  Counts describe rule posture, not the number of installed executable checks.")
    print("  The generated hook and installed workflows are authoritative for automation.")
    print()
    for tier, info in PROFILES.items():
        print(f"  [{tier}] {info['description']}")
        for c in info["consequences"]:
            print(f"    + {c}")
        print(f"    → {info['upgrade_path']}")
        print()


# ─── SCAFFOLDING ──────────────────────────────────────────────────────────────


def _apply_memory_choice_to_preview(
    preview_dir: Path,
    generated: list[str],
    memory_choice: str | None,
    source_origins: SourceOrigins | None = None,
) -> None:
    """Record onboarding intent without installing or configuring a provider."""

    if memory_choice is None:
        return
    selected = MEMORY_CHOICE_CONFIGS[memory_choice]
    relative = Path("configs") / "naos_memory.yaml"
    destination = preview_dir / relative
    if not destination.is_file():
        source = TEMPLATES_DIR / "structural-seeds" / relative
        if not source.is_file():
            raise FileNotFoundError(f"memory configuration seed is missing: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source_origins is None:
            shutil.copy2(source, destination)
        else:
            source_origins.copy2(source, destination)
        if relative.as_posix() not in generated:
            generated.append(relative.as_posix())

    content = destination.read_text(encoding="utf-8")
    for key, value in selected.items():
        rendered = str(value).lower() if isinstance(value, bool) else value
        content, replacements = re.subn(
            rf"^  {re.escape(key)}:.*$",
            f"  {key}: {rendered}",
            content,
            count=1,
            flags=re.MULTILINE,
        )
        if replacements != 1:
            raise ValueError(f"memory configuration seed is missing memory.{key}")
    destination.write_text(content, encoding="utf-8", newline="\n")


def _apply_planning_baseline_profile(preview_dir: Path, tier: str) -> None:
    """Render the profile-specific architecture applicability into the adopter seed."""

    destination = preview_dir / "naos" / "PLANNING_BASELINES.yaml"
    if not destination.is_file():
        return
    document = yaml.safe_load(destination.read_text(encoding="utf-8")) or {}
    baselines = document.get("baselines") if isinstance(document, dict) else None
    if not isinstance(baselines, list):
        raise ValueError("planning-baseline seed is missing baselines")
    applicability = "not_applicable_by_profile" if tier == "lite" else "required_by_profile"
    for baseline in baselines:
        if not isinstance(baseline, dict):
            continue
        bindings = baseline.get("source_bindings")
        architecture = bindings.get("architecture") if isinstance(bindings, dict) else None
        if not isinstance(architecture, dict):
            raise ValueError("planning-baseline seed is missing source_bindings.architecture")
        architecture["applicability"] = applicability
        architecture["sha256"] = None
    destination.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8", newline="\n")


def _apply_ai_component_inventory_profile(preview_dir: Path, tier: str) -> None:
    """Render the inventory capability state to match its generated profile surface."""

    destination = preview_dir / "naos" / "capability_state.yaml"
    if not destination.is_file():
        return
    document = yaml.safe_load(destination.read_text(encoding="utf-8")) or {}
    capabilities = document.get("capabilities") if isinstance(document, dict) else None
    if not isinstance(capabilities, list):
        raise ValueError("capability-state seed is missing capabilities")
    matches = [
        entry
        for entry in capabilities
        if isinstance(entry, dict)
        and entry.get("capability_id") == "CAP-AI-COMPONENT-INVENTORY"
    ]
    if len(matches) != 1:
        raise ValueError(
            "capability-state seed must declare CAP-AI-COMPONENT-INVENTORY exactly once"
        )
    entry = matches[0]
    required = tier in {"standard", "assured"}
    entry["enabled"] = required
    entry["current_maturity"] = "L1" if required else "L0"
    entry["target_maturity"] = "L1" if required else "L0"
    destination.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8", newline="\n")


def _copy_new_generated_seed(
    source: Path, destination: Path, *, source_origins: SourceOrigins | None = None,
) -> None:
    """Copy a seed into a new private preview path with generation-time age.

    The caller owns the preview directory. Refuse existing destinations, keep
    copy2 metadata, and change only mtime: archive/source age is not the age of
    the newly generated adopter configuration. Never use this on adopter files.
    """
    with destination.open("xb"):
        pass
    if source_origins is None:
        shutil.copy2(source, destination)
    else:
        source_origins.copy2(source, destination)
    copied = destination.stat()
    os.utime(destination, ns=(copied.st_atime_ns, time.time_ns()))


def _project_generated_gate_inputs(preview_dir: Path, generated: list[str]) -> None:
    """Project only installed gate inputs; missing inputs remain obligations."""
    inventory = {_safe_generated_relpath(value).as_posix() for value in generated}
    aliases = (("task_battery/", ".github/autoresearch/task_battery/"),
               ("capabilities/", "naos/capabilities/"))

    def project_input(value: str) -> str:
        for old, new in aliases:
            if not value.startswith(old):
                continue
            relative = _safe_generated_relpath(value).as_posix()
            candidate = new + relative.removeprefix(old.rstrip("/")).lstrip("/")
            if value.endswith("/"):
                candidate = candidate.rstrip("/") + "/"
                descendants = [path for path in inventory if path.startswith(candidate)]
                if not descendants:
                    return value
                if not all((preview_dir / path).is_file() for path in descendants):
                    raise ValueError(f"Generated gate dependency is missing: {candidate}")
            elif candidate not in inventory:
                return value
            elif not (preview_dir / candidate).is_file():
                raise ValueError(f"Generated gate dependency is missing: {candidate}")
            return candidate
        return value

    for relative in ("naos/gatekeepers.yaml", "scripts/workflows/gatekeepers.baseline.yaml"):
        if relative not in inventory:
            continue
        path = preview_dir / relative
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for gate in document["gates"]:
            if "required_inputs" in gate:
                gate["required_inputs"] = [project_input(value) for value in gate["required_inputs"]]
        path.write_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True),
                        encoding="utf-8", newline="\n")


def _project_generated_capability_references(preview_dir: Path, generated: list[str]) -> None:
    """Project kit references using the exact generated inventory, not host files."""
    inventory = {_safe_generated_relpath(value).as_posix() for value in generated}
    aliases = (
        ("templates/structural-seeds/", ""),
        ("templates/agents/", ".github/agents/"),
        ("templates/skills/", ".github/skills/"),
        ("templates/instructions/", ".github/instructions/"),
        ("templates/prompts/", ".github/prompts/"),
        ("templates/host-guidance/", ".github/naos-guidance/"),
        ("templates/workflows/", ".github/workflows/"),
        ("autoresearch/", ".github/autoresearch/"),
        ("task_battery/", ".github/autoresearch/task_battery/"),
        ("capabilities/", "naos/capabilities/"),
    )
    future_prefixes = ("naos/reports/", ".naos/", "naos/context_index/", "naos/context_queries/",
                       "naos/evidence/", "naos/test_evidence/", "naos/active/")

    def project_reference(value: str, *, evidence: bool = False) -> str:
        parts = value.split(maxsplit=1)
        if not parts or value.startswith(("https://", "http://", "kit://")):
            return value
        reference = parts[0]
        # Evidence prose is an obligation, not a claim that an input exists.
        if evidence and "/" not in reference:
            return value
        relative = _safe_generated_relpath(reference).as_posix()
        if evidence and (reference.startswith(future_prefixes) or " when approved" in value):
            return value
        candidates = [relative]
        candidates.extend(new + relative.removeprefix(old) for old, new in aliases if relative.startswith(old))
        if relative in {"templates/agents/AGENTS.md", ".github/agents/AGENTS.md"}:
            candidates.insert(0, ".github/NAOS_AGENTS.md")
        if relative == "templates/Makefile.naos":
            candidates.append("Makefile.naos")
        if relative == "policies/default_policy.yaml":
            candidates.append("naos/policy/default_policy.yaml")
        for candidate in candidates:
            if candidate in inventory:
                if not (preview_dir / candidate).is_file():
                    raise ValueError(f"Generated capability dependency is missing: {candidate}")
                return candidate + (" " + parts[1] if len(parts) > 1 else "")
        if evidence and relative.startswith(("naos/", "specs/")):
            # An optional project's missing configuration is still required
            # project evidence; its kit seed cannot satisfy that obligation.
            return value
        sources = [relative]
        # Reverse installed aliases only to actual kit sources. Missing optional
        # examples remain upstream references, never claims of installed files.
        sources.extend(old + relative.removeprefix(new) for old, new in aliases
                       if new and relative.startswith(new))
        if relative.startswith("naos/workflows/examples/"):
            sources.append("templates/workflows/" + relative.removeprefix("naos/workflows/examples/"))
        if relative in {".github/NAOS_AGENTS.md", ".github/agents/AGENTS.md"}:
            sources.append("templates/agents/AGENTS.md")
        if relative.startswith("naos/"):
            sources.append("templates/structural-seeds/" + relative)
        for source in sources:
            path = KIT_DIR / source
            if path.is_file() and path.resolve().is_relative_to(KIT_DIR.resolve()):
                return "kit://" + source + (" " + parts[1] if len(parts) > 1 else "")
        raise ValueError(f"Capability dependency is neither generated nor present in the kit: {reference}")

    for relative in sorted(inventory):
        if not relative.startswith("naos/capabilities/") or not relative.endswith(".yaml") or Path(relative).name.startswith("_"):
            continue
        path = preview_dir / relative
        card = yaml.safe_load(path.read_text(encoding="utf-8"))
        for field in ("related_docs", "related_scripts", "related_schemas", "required_evidence"):
            if field in card:
                card[field] = [project_reference(value, evidence=field == "required_evidence") for value in card[field]]
        for validator in card.get("validators", []):
            if validator.get("script"):
                validator["script"] = project_reference(validator["script"])
                if validator["script"].startswith("kit://") and validator.get("status") == "available":
                    validator["status"] = "external"
                    validator["notes"] = (validator.get("notes", "") + " Kit dependency; not installed or verified runnable in this generated project.").strip()
        card.setdefault("known_limitations", []).append(
            "kit:// references require the separately acquired NAOS kit; they are not local files, runnable commands or satisfied evidence. Required evidence remains an obligation, not proof of availability."
        )
        path.write_text(yaml.safe_dump(card, sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n")


    catalog_relative = "naos/setup_module_catalog.yaml"
    if catalog_relative in inventory:
        catalog_path = preview_dir / catalog_relative
        catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
        for module in catalog["modules"]:
            declarations = [module, *(module.get("profile_overrides") or {}).values()]
            for declaration in declarations:
                if "related_docs" in declaration:
                    declaration["related_docs"] = [project_reference(value)
                                                   for value in declaration["related_docs"]]
        catalog["semantics"]["related_docs_scope"] = (
            "Local related_docs identify files in this generated inventory. kit:// references "
            "identify separately acquired NAOS kit material; they are not installed files, "
            "runnable commands, or verified evidence. Catalogue bodies are on-demand configuration, "
            "not a claim about host startup context."
        )
        catalog_path.write_text(yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True),
                                encoding="utf-8", newline="\n")



def _manual_instruction_inputs(body: str) -> str:
    """Project authoring variables into explicit human-supplied input templates.

    No host-specific expansion or implicit value/default is asserted. Unknown
    names become declared manual inputs; malformed authoring tokens fail before
    any derived adapter is published.
    """
    pattern = re.compile(r"\{\{input:([A-Za-z_][A-Za-z0-9_-]{0,63})\}\}|\$\{input:([A-Za-z_][A-Za-z0-9_-]{0,63})\}")
    names = sorted({match.group(1) or match.group(2) for match in pattern.finditer(body)})
    remainder = pattern.sub("", body)
    if "{{input:" in remainder or "${input:" in remainder:
        raise ValueError("Malformed host authoring input token")
    if not names:
        return body
    body = pattern.sub(lambda match: "[MANUAL_INPUT:" + (match.group(1) or match.group(2)) + "]", body)
    lines = []
    fence: str | None = None
    for line in body.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            fence = None if fence else stripped[:3]
        elif fence and "[MANUAL_INPUT:" in line and re.match(r"\s*(?:python\d*|conda run|bash|sh|grep|naos|make)\s", line):
            line = "# Manual input template; fill and review before execution: " + line.lstrip()
        lines.append(line)
    contract = ["", "## Manual input contract", "",
        "Obtain these values from the human/request before following the template.",
        "MANUAL_INPUT markers are not host-expanded variables, defaults, validated values or execution approval.",
        "Missing required task context stops the dependent step; do not invent a value.", "",
        "| Input | Source |", "| --- | --- |"]
    contract += ["| " + name + " | Human/request; confirm value and applicability before use |" for name in names]
    return "".join(lines) + "\n" + "\n".join(contract) + "\n"


def _project_instruction_links(
    body: str, *, document_path: str, output_document_path: str,
    inventory: set[str], tier: str, kit_reference_paths: frozenset[str] = frozenset(),
) -> str:
    """Resolve named NAOS Markdown resources from the source document location.

    Relative links in a portable body must address the output document location;
    source/kit absence becomes a manual obligation, never an invented local link.
    This is pure inventory projection, with no filesystem/network access.
    """
    import posixpath
    source_parent = posixpath.dirname(document_path)
    output_parent = posixpath.dirname(output_document_path)
    def project(match: re.Match[str]) -> str:
        label, operand = match.group(1), match.group(2)
        if operand.startswith("#") or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", operand):
            return match.group(0)
        target, separator, fragment = operand.partition("#")
        canonical = posixpath.normpath(posixpath.join(source_parent, target))
        output_canonical = posixpath.normpath(posixpath.join(output_parent, target))
        if canonical not in inventory and output_canonical in inventory:
            canonical = output_canonical
        elif canonical not in inventory and target in inventory:
            canonical = target
        # Only explicitly selected copied-doc references become upstream kit
        # URIs; arbitrary missing local links retain their original obligation.
        if canonical in kit_reference_paths and canonical not in inventory:
            return "[" + label + "](kit://" + canonical + (separator + fragment if separator else "") + ")"
        named_instruction = (target.endswith((".instructions.md", ".prompt.md"))
            or canonical.startswith((".github/instructions/", ".github/prompts/", ".github/skills/", ".github/naos-guidance/")))
        if not named_instruction:
            return match.group(0)
        if canonical.startswith("../") or canonical == ".." or canonical.startswith("/"):
            raise ValueError("Instruction link escapes generated project")
        if canonical not in inventory:
            return (label + f" (not installed in {tier}; obtain required guidance or perform the applicable "
                    "review manually with project source, tests and human review; no local file loaded)")
        # Skill support trees are copied intact beside both SKILL.md routes.
        if (document_path.startswith(".github/skills/")
                and canonical.startswith(source_parent + "/")):
            canonical = posixpath.join(output_parent, canonical[len(source_parent) + 1:])
        relative = posixpath.relpath(canonical, output_parent or ".")
        return "[" + label + "](" + relative + (separator + fragment if separator else "") + ")"
    return re.sub(r"(?<!!)\[([^]\n]+)\]\(([^)\s]+)\)", project, body)


def _project_host_route_body(body: str, *, portable: bool, inventory: set[str],
                             skill_names: set[str], tier: str,
                             portable_routes: set[str] | None = None,
                             unavailable_make_targets: set[str] | None = None,
                             document_path: str | None = None,
                             output_document_path: str | None = None) -> str:
    """Pure projection; no filesystem writes or agent permission translation."""
    body = _manual_instruction_inputs(body)
    body = body.replace("$naos_checkpoint_protocol", (
        "Quickstart is research-only and does not enforce cognitive checkpoints or Rule 26. "
        "Preserve source evidence and a manual research/handoff record; request a reviewed profile transition before lifecycle implementation. "
        "For context pressure, absent caller/host telemetry remains UNKNOWN; keep a local compact or task-card record when useful."
        if tier == "quickstart" else
        "At phase transitions, non-obvious discoveries, five consecutive tool calls and handoff, "
        "record the selected profile's cognitive checkpoint under Rule 26. For context pressure use only "
        "caller/host-supplied telemetry; absent telemetry is UNKNOWN, not FRESH."
    ))
    if tier == "quickstart":
        body = body.replace("Anything outside this matrix defaults to **Standard / MODERATE** and triggers a Rule 26 checkpoint.",
            "Anything outside this matrix requires a manual research record; Quickstart does not enforce Rule 26 or activate Standard controls.")
        body = body.replace("Unlisted tasks default to **Standard / MODERATE / no specialised skill** and trigger Rule 26.",
            "Unlisted tasks require manual research review; Quickstart does not enforce Rule 26 or activate Standard controls.")
        body = body.replace("Anything outside this matrix requires a Rule 26 checkpoint and human review of the current profile.",
            "Anything outside this matrix requires manual source/evidence review; Quickstart does not enforce Rule 26.")
        body = body.replace("**Override rule.** Disagreement with the matched row REQUIRES a Rule 26 T2 checkpoint justifying the divergence.",
            "**Quickstart recommendation review.** Explain any divergence in the manual research record; no Rule 26 enforcement or profile activation is implied.")
    def available_reference(path: str) -> bool:
        if path in inventory:
            return True
        if document_path and not path.startswith((".github/", ".agents/", "naos/")):
            return (Path(document_path).parent / path).as_posix() in inventory
        return False
    installed_skills = {Path(p).parent.name for p in inventory
                        if p.startswith(".github/skills/") and p.endswith("/SKILL.md")}
    # Kit authoring paths must refer to their generated project locations
    # before selection checks decide whether a manual fallback is needed.
    body = re.sub(
        r"(?<![A-Za-z0-9_./-])templates/skills/([a-z0-9-]+)/SKILL\.md",
        r".github/skills/\1/SKILL.md", body,
    )
    body = body.replace(".github/agents/AGENTS.md", ".github/NAOS_AGENTS.md")
    aliases = {
        "templates/instruction-triple/copilot-instructions.md": ".github/copilot-instructions.md",
        "templates/instruction-triple/project-context.md": ".github/project-context.md",
        "templates/instruction-triple/CLAUDE.md": "CLAUDE.md",
        "templates/agents/": ".github/agents/",
        "templates/prompts/": ".github/prompts/",
        "templates/instructions/": ".github/instructions/",
        "templates/profiles/": ".github/profiles/",
        "templates/spec-kit/specs/": "naos/spec_templates/spec-kit/specs/",
        "templates/structural-seeds/": "",
        "task_battery/portable_scenarios.yaml": ".github/autoresearch/task_battery/portable_scenarios.yaml",
    }
    # Unknown authoring resources stay explicit kit dependencies; do not pretend
    # optional integration templates or documentation are installed or runnable.
    authoring_path = r"(?<![A-Za-z0-9_./:-])(?:templates/[A-Za-z0-9_./*-]+|kit/[A-Za-z0-9_./*-]+|task_battery/portable_scenarios\.yaml)"
    def authoring_reference(match: re.Match[str]) -> str:
        path = match.group(0).rstrip(".")
        suffix = match.group(0)[len(path):]
        for source, destination in aliases.items():
            if path == source or source.endswith("/") and path.startswith(source):
                candidate = destination + path[len(source):]
                if candidate in inventory or candidate.endswith("/") and any(p.startswith(candidate) for p in inventory):
                    return candidate + suffix
        return "kit://" + path.removeprefix("kit/") + suffix
    body = re.sub(authoring_path, authoring_reference, body)
    if document_path is not None:
        body = _project_instruction_links(
            body, document_path=document_path,
            output_document_path=output_document_path or document_path,
            inventory=inventory, tier=tier,
        )
    # Unavailable profile dependencies become explicit manual obligations.
    # Native @agent syntax is never promised by a portable adapter.
    def agent(match: re.Match[str]) -> str:
        name = match.group(0).lstrip("@")
        path = f".github/agents/{name}.agent.md"
        if path in inventory:
            return f"manual {name} role (read {path}; human-authorized handoff)" if portable else match.group(0)
        return f"human {name.removeprefix('naos-')} review (agent not installed in {tier}; no dispatch)"
    body = re.sub(r"@naos-[a-z0-9-]+", agent, body)
    # Exact references to named skills, including extension-skill names,
    # are checked against selection rather than assumed installed.
    for name in sorted(skill_names, key=len, reverse=True):
        token = f"`{name}`"
        if token not in body:
            continue
        if name in installed_skills:
            route = f".agents/skills/naos-portable-{name}/SKILL.md"
            if portable and portable_routes is not None and route not in portable_routes:
                replacement = f"read `.github/skills/{name}/SKILL.md` manually (portable adapter absent; human review, no dispatch)"
            else:
                replacement = f"`naos-portable-{name}`" if portable else token
        else:
            fallback = (
                "read `.github/skills/systemic-wiring/SKILL.md` and perform the affected-surface review"
                if name == "systemic-capability-wiring" and "systemic-wiring" in installed_skills
                else "perform the described check manually with source, tests and human review"
            )
            replacement = f"{name} guidance (not installed in {tier}; {fallback})"
        body = body.replace(token, replacement)
    reference_pattern = (
        r"(?<![A-Za-z0-9_./:-])(?:scripts/[A-Za-z0-9_./-]+\.py|"
        r"\.github/(?:NAOS_AGENTS\.md|skills/[a-z0-9-]+/SKILL\.md|agents/[a-z0-9-]+\.agent\.md|"
        r"instructions/[a-z0-9-]+\.instructions\.md|prompts/[A-Za-z0-9_-]+(?:\.prompt)?\.md|"
        r"autoresearch/[A-Za-z0-9_./-]+\.py))"
    )
    def inline_command(match: re.Match[str]) -> str:
        command = match.group(1)
        missing = [path for path in re.findall(reference_pattern, command) if not available_reference(path)]
        make_match = re.match(r"make -f Makefile\.naos ([a-zA-Z0-9_.-]+)", command)
        if make_match and make_match.group(1) in (unavailable_make_targets or set()):
            missing.append("Makefile.naos target " + make_match.group(1))
        if missing and re.match(r"(?:python\d*|conda run|bash|sh|make -f Makefile\.naos)\s", command):
            return "manual check (" + ", ".join(
                path + f" [not installed in {tier}; source/tests and human review]"
                for path in missing) + ")"
        return match.group(0)
    body = re.sub(r"`([^`\n]+)`", inline_command, body)
    lines = []
    for line in body.splitlines(keepends=True):
        missing = [path for path in re.findall(reference_pattern, line) if not available_reference(path)]
        make_match = re.match(r"\s*make -f Makefile\.naos ([a-zA-Z0-9_.-]+)", line)
        if make_match and make_match.group(1) in (unavailable_make_targets or set()):
            missing.append("Makefile.naos target " + make_match.group(1))
        if missing and re.match(r"\s*(?:python\d*|conda run|bash|sh|make -f Makefile\.naos)\s", line):
            # Never publish a runnable-looking command to an absent script.
            line = "# Profile fallback: " + ", ".join(missing) + f" not installed in {tier}; perform the described check manually and request human review.\n"
        lines.append(line)
    body = "".join(lines)
    def path_reference(match: re.Match[str]) -> str:
        path = match.group(0)
        if available_reference(path) or match.string[match.end():].startswith(f" [not installed in {tier};"):
            return path
        return f"{path} [not installed in {tier}; use the protocol in this file and human review]"
    body = re.sub(reference_pattern, path_reference, body)
    def workflow(match: re.Match[str]) -> str:
        command = match.group(1)
        candidates = [f".github/prompts/{command}.prompt.md", f".github/prompts/{command}.md"]
        found = next((path for path in candidates if path in inventory), None)
        if found is None:
            return f"{command} workflow (not installed in {tier}; use manual goal/context review)"
        if not portable:
            return match.group(0)
        base = command.removeprefix("naos-")
        base = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
        route = f".agents/skills/naos-workflow-{base}/SKILL.md"
        if portable_routes is not None and route not in portable_routes:
            return f"read `{found}` manually (portable adapter absent; human review, no dispatch)"
        return f"naos-workflow-{base}"
    body = re.sub(r"(?<![A-Za-z0-9_.-])/(naos-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])", workflow, body)
    return body


def _render_selected_host_route(
    relative: str, original_bytes: bytes, adapter_templates: dict[str, bytes],
    *, inventory: set[str], skill_names: set[str], tier: str,
    portable_routes: set[str] | None = None,
    unavailable_make_targets: set[str] | None = None,
) -> tuple[str, dict[str, bytes]]:
    """Render only one selected skill/prompt; callers own custody and publication."""
    is_skill = relative.startswith(".github/skills/") and relative.endswith("/SKILL.md")
    is_prompt = relative.startswith(".github/prompts/") and relative.endswith(".md")
    if not (is_skill or is_prompt):
        raise ValueError("Selected host route requires a skill or prompt")
    base = Path(relative).parent.name if is_skill else Path(relative).name.removesuffix(".prompt.md").removesuffix(".md").removeprefix("naos-")
    base = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
    name = ("naos-portable-" if is_skill else "naos-workflow-") + base
    if len(name) > 64:
        raise ValueError("Portable adapter name exceeds host name contract")
    destination = f".agents/skills/{name}/SKILL.md"
    # Normalize only the parsing view; provenance/copy inputs retain raw bytes.
    original = original_bytes.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    metadata: dict[str, Any] = {}
    body = original
    if original.startswith("---\n"):
        frontmatter, body = original[4:].split("\n---", 1)
        metadata = yaml.safe_load(frontmatter) or {}
    description = str(metadata.get("description") or f"Manually follow the NAOS {base} workflow for the selected profile.")
    if len(description) > 1024:
        raise ValueError("Portable adapter description exceeds host description contract")
    if is_skill:
        parameters, authoring_base = skill_authoring_metadata(metadata)
    else:
        parameters, authoring_base = metadata.get("parameters", []), metadata.get("extends")
    if not isinstance(parameters, list) or any(not isinstance(row, dict)
            or not isinstance(row.get("name"), str) or not row["name"].strip()
            or not isinstance(row.get("description"), str) or not row["description"].strip()
            for row in parameters):
        raise ValueError("Portable adapter requires well-formed authoring inputs")
    if len({row["name"] for row in parameters}) != len(parameters):
        raise ValueError("Portable adapter requires unique authoring input names")
    if parameters:
        def cell(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        lines = ["", "## Authoring inputs (manual)", "",
                 "Review these inputs with the human before following this workflow. This table",
                 "is procedural guidance, not a host-enforced schema or execution authorization.", "",
                 "| Input | Description | Required | Default |", "| --- | --- | --- | --- |"]
        for row in parameters:
            lines.append("| " + " | ".join([cell(row["name"]), cell(row["description"]),
                cell(json.dumps(row["required"]) if "required" in row else "not specified"),
                cell(json.dumps(row["default"], ensure_ascii=False) if "default" in row else "not specified")]) + " |")
        body += "\n".join(lines) + "\n"
    if authoring_base:
        body += ("\n## Authoring base (manual)\n\nRead the declared base guidance "
                 + json.dumps(authoring_base, ensure_ascii=False)
                 + ". If that base is unavailable, stop and ask for it. Do not infer inheritance, "
                   "agent permissions or execution approval from this reference.\n")
    body = _project_host_route_body(body, portable=True, inventory=inventory, skill_names=skill_names, tier=tier,
                                    portable_routes=portable_routes,
                                    unavailable_make_targets=unavailable_make_targets,
                                    document_path=relative, output_document_path=destination)
    outputs = {}
    for kind, dest, target, adapter_body in (
        ("portable-skill", destination, relative, body),
        ("claude-command", f".claude/commands/{name}.md", destination, ""),
    ):
        text = adapter_templates[kind].decode("utf-8")
        for token, value in {
            "$adapter_name": name, "$adapter_description": json.dumps(description, ensure_ascii=False),
            "$adapter_profile": tier, "$adapter_source": target, "$adapter_body": adapter_body,
        }.items():
            text = text.replace(token, value)
        outputs[dest] = text.encode("utf-8")
    return name, outputs


def _unavailable_project_make_targets(text: str, inventory: set[str]) -> set[str]:
    """Find declared targets whose unconditional local script inputs are absent.

    This is availability projection, not Make evaluation or proof that a target
    passes. File-guarded optional scripts retain their existing skip behavior.
    """
    targets: dict[str, tuple[set[str], list[str]]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+):([^=].*)?$", line)
        if match:
            current = match.group(1)
            dependencies = set((match.group(2) or "").split("#", 1)[0].split())
            targets[current] = (dependencies, [])
        elif current is not None and line.startswith("\t"):
            if not line.lstrip().startswith("#"):
                targets[current][1].append(line)
        elif line and not line.startswith(("#", " ")):
            current = None
    unavailable: set[str] = set()
    for name, (_, lines) in targets.items():
        required: set[str] = set()
        guards: list[set[str]] = []
        # Recognize only the shipped positive file-test guard shape. Unknown
        # conditions confer no availability guarantee. Guard scope applies to
        # occurrences in that true branch, never to the whole Make target.
        controls = re.compile(
            r"\bif\s+\[\s+-f\s+scripts/[A-Za-z0-9_./-]+\.py\s+\]"
            r"(?:\s*&&\s*\[[^\]\n]+\])*\s*;\s*then\b|\bif\b|\belse\b|\bfi\b"
        )
        def inspect(chunk: str) -> None:
            protected = set().union(*guards) if guards else set()
            required.update(path for path in re.findall(r"scripts/[A-Za-z0-9_./-]+\.py", chunk)
                            if path not in protected)
        for line in lines:
            start = 0
            for match in controls.finditer(line):
                inspect(line[start:match.start()])
                token = match.group(0)
                if token.startswith("if"):
                    guards.append(set(re.findall(r"-f\s+(scripts/[A-Za-z0-9_./-]+\.py)", token))
                                  if token != "if" else set())
                elif token == "else" and guards:
                    guards[-1] = set()
                elif token == "fi" and guards:
                    guards.pop()
                start = match.end()
            inspect(line[start:])
        if required - inventory:
            unavailable.add(name)
    previous: set[str] = set()
    while previous != unavailable:
        previous = set(unavailable)
        unavailable.update(name for name, (dependencies, _) in targets.items()
                           if dependencies & unavailable)
    return unavailable


def _generate_host_routes(
    preview_dir: Path, generated: list[str], tier: str,
    *, source_origins: SourceOrigins | None = None,
) -> None:
    """Project manual portable routes from the actual selected inventory.

    Original host files remain available. Distinct names avoid same-name skill
    discovery overlap; agent permissions are never translated between hosts.
    All mutations here are to private generated previews, before activation.
    """
    inventory = set(generated)
    skill_names = {p.name for p in (TEMPLATES_DIR / "skills").iterdir() if p.is_dir()}
    skill_catalogue_input = json.dumps(sorted(skill_names), separators=(",", ":")).encode("utf-8")
    installed_skills = {
        Path(relative).parent.name for relative in inventory
        if relative.startswith(".github/skills/") and relative.endswith("/SKILL.md")
    }

    makefile = preview_dir / "Makefile.naos"
    unavailable_make_targets = _unavailable_project_make_targets(
        makefile.read_text(encoding="utf-8") if makefile.is_file() else "", inventory,
    )

    def project_body(body: str, *, portable: bool, document_path: str | None = None) -> str:
        projected = _project_host_route_body(body, portable=portable, inventory=inventory,
                                            skill_names=skill_names, tier=tier,
                                            unavailable_make_targets=unavailable_make_targets,
                                            document_path=document_path)
        # These exact renderer-owned summaries retain their canonical KIT
        # attribution/coverage. Profile fallbacks apply to operational guidance
        # outside them, as in the brownfield layout adapter below.
        section_id = {
            ".github/naos-guidance/security-reference.md": "secure-coding-controls",
            ".github/naos-guidance/cursor-security.md": "secure-coding-controls",
            ".github/instructions/ai-pipeline.instructions.md": "agentic-coding-controls",
        }.get(document_path)
        if section_id is not None:
            begin = f"<!-- BEGIN NAOS GENERATED: {section_id} -->"
            end = f"<!-- END NAOS GENERATED: {section_id} -->"
            if any(text.count(marker) != 1 for text in (body, projected) for marker in (begin, end)):
                raise ValueError(f"Canonical control summary markers invalid: {document_path}")
            start, finish = body.index(begin), body.index(end) + len(end)
            projected_start, projected_finish = projected.index(begin), projected.index(end) + len(end)
            if finish <= start or projected_finish <= projected_start:
                raise ValueError(f"Canonical control summary marker order invalid: {document_path}")
            upstream_notice = (
                "> Upstream KIT provenance only: source/register/renderer paths in the "
                "canonical summary are upstream references, not claims that those files "
                "are installed or runnable in this project. This attribution does not "
                "authorize a command; use only the selected inventory and approved workflow.\n\n"
            )
            prefix = projected[:projected_start]
            if not prefix.endswith(upstream_notice):
                prefix += upstream_notice
            projected = prefix + body[start:finish] + projected[projected_finish:]
        return projected

    # Repair legacy skill/prompt profile references too, without altering their native
    # metadata or tool contracts. Header/body split prevents frontmatter edits.
    for relative in sorted(inventory):
        if not (
            relative.startswith(".github/skills/") and relative.endswith("/SKILL.md")
            or relative.startswith(".github/prompts/")
            or relative in {"CLAUDE.md", "AGENTS.md", ".github/copilot-instructions.md", ".github/project-context.md", ".github/NAOS_AGENTS.md"}
            or relative.startswith(".github/agents/") and relative.endswith(".agent.md")
            or relative.startswith(".github/instructions/") and relative.endswith(".md")
            or relative.startswith(".cursor/rules/") and relative.endswith(".mdc")
            or relative.startswith(".github/naos-guidance/") and relative.endswith(".md")
        ):
            continue
        path = preview_dir / relative
        text = path.read_text(encoding="utf-8")
        if text.startswith("---\n"):
            head, body = text[4:].split("\n---", 1)
            path.write_text("---\n" + head + "\n---" + project_body(body, portable=False, document_path=relative), encoding="utf-8", newline="\n")
        else:
            path.write_text(project_body(text, portable=False, document_path=relative), encoding="utf-8", newline="\n")

    routes: list[tuple[str, str]] = []
    selected = [p for p in sorted(inventory) if (
        p.startswith(".github/skills/") and p.endswith("/SKILL.md")
    ) or p.startswith(".github/prompts/")]
    for relative in selected:
        is_skill = relative.startswith(".github/skills/")
        base = Path(relative).parent.name if is_skill else Path(relative).name.removesuffix(".prompt.md").removesuffix(".md").removeprefix("naos-")
        base = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
        name = ("naos-portable-" if is_skill else "naos-workflow-") + base
        if len(name) > 64:
            raise ValueError("Portable adapter name exceeds host name contract")
        destination = f".agents/skills/{name}/SKILL.md"
        if destination in set(generated):
            raise ValueError("Portable adapter destination collision")
        source = TEMPLATES_DIR / ("skills" if is_skill else "prompts")
        source = source / (Path(relative).parent.name + "/SKILL.md" if is_skill else Path(relative).name)
        if is_skill and (source.parent / "agents" / "openai.yaml").exists():
            raise ValueError(
                "Portable adapter Codex policy collides with skill support: "
                + source.relative_to(TEMPLATES_DIR).as_posix()
            )
        original_bytes = source.read_bytes()
        # Parsed text uses universal newlines; original_bytes remains the recipe input.
        original = original_bytes.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        metadata: dict[str, Any] = {}
        body = original
        if original.startswith("---\n"):
            frontmatter, body = original[4:].split("\n---", 1)
            metadata = yaml.safe_load(frontmatter) or {}
        description = str(metadata.get("description") or f"Manually follow the NAOS {base} workflow for the selected profile.")
        if len(description) > 1024:
            raise ValueError("Portable adapter description exceeds host description contract")
        body = project_body(body, portable=True, document_path=relative)
        # Capture once: the exact rendered wrappers are validated and recorded.
        adapter_templates = {kind: (TEMPLATES_DIR / "host-adapters" / f"{kind}.md").read_bytes()
                             for kind in ("portable-skill", "claude-command")}
        if source_origins is not None:
            for kind, template_bytes in adapter_templates.items():
                dest = destination if kind == "portable-skill" else f".claude/commands/{name}.md"
                for kit_source, data in ((TEMPLATES_DIR / "host-adapters" / f"{kind}.md", template_bytes),
                                         (source, original_bytes)):
                    mode_row(source_origins.declaration, source=kit_source.relative_to(KIT_DIR).as_posix(),
                             source_bytes=data, destination=dest, output_bytes=data)
        _route_name, rendered_routes = _render_selected_host_route(
            relative, original_bytes, adapter_templates,
            inventory=inventory, skill_names=skill_names, tier=tier,
            unavailable_make_targets=unavailable_make_targets,
        )
        assert _route_name == name
        # Inputs originate in reviewed source, not rendered mutable preview.
        # Include the inventory: dependency projection is an explicit input.
        inventory_input = json.dumps(sorted(inventory), separators=(",", ":")).encode("utf-8")
        for kind, dest, target, adapter_body in (
            ("portable-skill", destination, relative, body),
            ("claude-command", f".claude/commands/{name}.md", destination, ""),
        ):
            template = TEMPLATES_DIR / "host-adapters" / f"{kind}.md"
            template_bytes = adapter_templates[kind]
            if source_origins is not None:
                # Named kit templates/guidance are reviewed sources, not arbitrary
                # observed host inputs. Validate the same bytes we render/capture.
                for kit_source, data in ((template, template_bytes), (source, original_bytes)):
                    mode_row(
                        source_origins.declaration,
                        source=kit_source.relative_to(KIT_DIR).as_posix(),
                        source_bytes=data, destination=dest, output_bytes=data,
                    )
                source_origins.record_recipe(
                    "host_adapter", dest,
                    sorted([
                        ("kit/" + template.relative_to(KIT_DIR).as_posix(), template_bytes),
                        ("kit/" + source.relative_to(KIT_DIR).as_posix(), original_bytes),
                        ("generated/selected_inventory.json", inventory_input),
                        ("generated/known_skill_names.json", skill_catalogue_input),
                        ("generated/project_makefile.txt", makefile.read_bytes()),
                    ]),
                    {"profile": tier, "name": name, "kind": kind},
                )
            text = rendered_routes[dest].decode("utf-8")
            path = preview_dir / dest
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            generated.append(dest)
        policy_source = TEMPLATES_DIR / "host-adapters" / "openai.yaml"
        policy_destination = Path(destination).parent / "agents" / "openai.yaml"
        policy_target = preview_dir / policy_destination
        policy_target.parent.mkdir(parents=True, exist_ok=True)
        if source_origins is not None:
            source_origins.copy2(policy_source, policy_target)
        else:
            shutil.copy2(policy_source, policy_target)
        generated.append(policy_destination.as_posix())
        if is_skill:
            # Preserve the complete relative support tree and inventory every
            # leaf. Skills can reference scripts/resources beside SKILL.md.
            for support in sorted(source.parent.rglob("*")):
                if (not support.is_file() or support == source or support.name == ".DS_Store"
                        or support.suffix in {".pyc", ".pyo"} or "__pycache__" in support.parts):
                    continue
                dest = Path(destination).parent / support.relative_to(source.parent)
                target = preview_dir / dest
                target.parent.mkdir(parents=True, exist_ok=True)
                if source_origins is not None:
                    source_origins.copy2(support, target)
                else:
                    shutil.copy2(support, target)
                generated.append(dest.as_posix())
        routes.append((name, destination))

    lines = ["## Selected profile availability", ""]
    if tier == "quickstart":
        lines += ["Quickstart installs research guidance at `.github/agents/naos-research.agent.md`.",
                  "Design/task-start/task-complete workflows, skills and lifecycle scripts are not",
                  "installed. Use a manual goal, source inspection and human review; use `naos doctor`",
                  "for diagnostics. Move to Lite or higher through a reviewed profile transition", "before using lifecycle automation."]
    else:
        lines += ["Design -> task-start -> authorized implementation -> task-complete -> human review.",
                  "Use these generated routes or read their files explicitly; no route grants execution approval.", ""]
        lines += [f"- `{name}`: `{path}`" for name, path in routes]
        lines += ["", "Use `Makefile.naos` targets only when their scripts are installed. Missing skill/agent",
                  "references are marked with a manual fallback in generated guidance."]
    availability = ("Selected profile: " + tier + ". Read root AGENTS.md for the exact generated routes. "
        "A missing tool never waives a selected-profile rule: perform the source/test review manually "
        "or stop the dependent work and obtain the required tool/evidence. "
        "kit:// references identify separately acquired kit resources, not local files or runnable commands. "
        "Profile presets describe other possible installations; they do not activate components.\n\n")
    for relative in ("CLAUDE.md", ".github/copilot-instructions.md"):
        path = preview_dir / relative
        path.write_text(availability + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    lines += ["", "A missing tool does not waive governance duties. Review source/tests manually or stop dependent work until required evidence is available.",
              "kit:// references are separately acquired kit resources, not project-local files or runnable commands.",
              "Reference profile presets and context_phases are manual planning guidance; no runtime context injection is implemented."]
    router = preview_dir / "AGENTS.md"
    text = router.read_text(encoding="utf-8").replace("$naos_profile", tier).replace("$naos_routes", "\n".join(lines))
    router.write_text(text, encoding="utf-8", newline="\n")


def scaffold_files(
    project_path: Path,
    tier: str,
    archetype: str | None,
    backend: str,
    preview_dir: Path,
    signals: dict | None = None,
    memory_choice: str | None = None,
    emit_progress: bool = True,
    source_origins: SourceOrigins | None = None,
    copied_tool_outputs: set[Path] | None = None,
    _defer_traceability_content: bool = False,
) -> list[str]:
    """
    Generate governance files into preview_dir.
    Returns forward-slash relative paths of files generated on every OS.

    Security: writes ONLY to preview_dir — never modifies project_path directly.
    Activation (copy to project_path) requires separate --activate call.
    """
    generated: list[str] = []
    if copied_tool_outputs is None:
        copied_tool_outputs = set()
    copy_source = source_origins.copy2 if source_origins is not None else shutil.copy2
    surface_contract = load_profile_surface_contract(tier)
    required_surfaces = set(surface_contract.get("required_surfaces") or [])
    preview_dir.mkdir(parents=True, exist_ok=True)

    # 1. Instruction Triple
    triple_src = TEMPLATES_DIR / "instruction-triple"
    if triple_src.is_dir():
        for tpl in triple_src.iterdir():
            if tpl.is_file():
                if tpl.name in {"copilot-instructions.md", "project-context.md"}:
                    dest = preview_dir / ".github" / tpl.name
                else:
                    dest = preview_dir / tpl.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                copy_source(tpl, dest)
                generated.append(dest.relative_to(preview_dir).as_posix())

    # 1b. Auto-populate instruction-triple templates from detected signals.
    template_ctx = _make_template_context(
        project_path=project_path,
        signals=signals or _empty_signals(),
        tier=tier,
        archetype=archetype,
    )
    _populate_templates(preview_dir, template_ctx)

    # Detailed protocols are required on demand, not unconditional host imports.
    # Keep the complete reviewed text available rather than deleting governance
    # duties to reduce always-loaded host entrypoints.
    guidance_src = TEMPLATES_DIR / "host-guidance"
    if guidance_src.is_dir():
        for guidance in sorted(guidance_src.glob("*.md")):
            if tier == "quickstart" and guidance.name.startswith("cursor-"):
                continue
            destination = preview_dir / ".github" / "naos-guidance" / guidance.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy_source(guidance, destination)
            generated.append(destination.relative_to(preview_dir).as_posix())
            # CLAUDE reference retains the same project fact substitutions as the
            # compact entrypoint; other $tokens remain literal authoring guidance.
            if guidance.name == "claude-reference.md":
                from string import Template
                destination.write_text(Template(destination.read_text(encoding="utf-8")).safe_substitute(template_ctx),
                                       encoding="utf-8", newline="\n")

    # 2. Rules Chain
    rules_src = TEMPLATES_DIR / "rules-chain"
    if rules_src.is_dir():
        for tpl in rules_src.rglob("*"):
            if tpl.is_file():
                rel = tpl.relative_to(rules_src)
                dest = preview_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                copy_source(tpl, dest)
                generated.append(rel.as_posix())

    # 3. RULES.md from selected profile
    profile_rules = validated_profile_rules_path(tier)
    dest = preview_dir / ".ai" / "RULES.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    copy_source(profile_rules, dest)
    generated.append(".ai/RULES.md")

    # 4. Cursor rules (lite+ only — skip for quickstart)
    cursor_src = TEMPLATES_DIR / "cursor-rules"
    if cursor_src.is_dir() and tier != "quickstart":
        cursor_dest = preview_dir / ".cursor" / "rules"
        cursor_dest.mkdir(parents=True, exist_ok=True)
        for mdc in cursor_src.iterdir():
            if mdc.is_file():
                copy_source(mdc, cursor_dest / mdc.name)
                generated.append(f".cursor/rules/{mdc.name}")

    # 5. Makefile.naos
    makefile_src = TEMPLATES_DIR / "Makefile.naos"
    if makefile_src.exists():
        copy_source(makefile_src, preview_dir / "Makefile.naos")
        generated.append("Makefile.naos")

    # 5a. Profile generated-surface contract (all profiles, including quickstart).
    if PROFILE_SURFACE_CONTRACT_PATH.is_file():
        contract_dest = preview_dir / "naos" / "profile_generated_surface_contract.json"
        contract_dest.parent.mkdir(parents=True, exist_ok=True)
        copy_source(PROFILE_SURFACE_CONTRACT_PATH, contract_dest)
        generated.append("naos/profile_generated_surface_contract.json")
    if tier == "quickstart":
        for contract_schema_src in [
            KIT_DIR / "schemas" / "naos" / "profile_generated_surface_contract.schema.json",
            KIT_DIR / "schemas" / "naos" / "research_record.schema.json",
            KIT_DIR / "schemas" / "naos" / "research_record_validation.schema.json",
            KIT_DIR / "schemas" / "naos" / "overlay_compatibility.schema.json",
        ]:
            if contract_schema_src.is_file():
                contract_schema_dest = preview_dir / "schemas" / "naos" / contract_schema_src.name
                contract_schema_dest.parent.mkdir(parents=True, exist_ok=True)
                copy_source(contract_schema_src, contract_schema_dest)
                generated.append(f"schemas/naos/{contract_schema_src.name}")

    # 6. Structural seeds (quickstart: selected seeds; lite+: all except the
    # installed/kit repository-intelligence runtime seed). Repository
    # intelligence writes its own source-bound rules snapshot into the
    # project-local active generation; duplicating the operational seed in
    # every scaffold would add a second, potentially stale control source.
    seeds_src = TEMPLATES_DIR / "structural-seeds"
    if seeds_src.is_dir():
        for seed in seeds_src.rglob("*"):
            if seed.is_file():
                rel = seed.relative_to(seeds_src)
                if rel == Path("naos/repository_intelligence_rules.yaml"):
                    continue
                quickstart_seed_names = {
                    "NAOS_QUICKSTART.md",
                    "NAOS_QUICK_REFERENCE.md",
                    "AGENTIC_CODING_PLAYBOOK.md",
                    "PRE_IMPLEMENTATION_ALIGNMENT.md",
                    "agentic_workflow.yaml",
                    "calibration_shadow.yaml",
                    "evidence_classification_policy.yaml",
                    "cross_harness_review_readiness.yaml",
                    "duplicate_function_hygiene_rules.yaml",
                    "secret_hygiene_rules.yaml",
                    "test_quality_hygiene_rules.yaml",
                    "dependency_integrity_rules.yaml",
                    "package_reality_rules.yaml",
                    "package_reality_provenance.yaml",
                    "api_symbol_reality.yaml",
                    "ac_completion_evidence.yaml",
                    "pr_risk_rules.yaml",
                    "intake_answers.yaml",
                    "install_plan_rules.yaml",
                    "existing_resource_inventory_rules.yaml",
                    "ai_artifact_inventory_rules.yaml",
                    "ai_code_provenance.yaml",
                    "compliance_posture.yaml",
                    "memory_mcp_inventory_rules.yaml",
                    "traceability_gap_register_rules.yaml",
                    "challenge_rules.yaml",
                    "install_decision_record_rules.yaml",
                    "capability_state.yaml",
                    "systemic_impact_rules.yaml",
                    "module_header_rules.yaml",
                    "control_plane_review_rules.yaml",
                    "control_plane_review_items.yaml",
                    "setup_module_catalog.yaml",
                    "team_operator_map.yaml",
                    "evidence_attestation_rules.yaml",
                    "evidence_review_attestations.yaml",
                    "memory_context_rules.yaml",
                    "memory_authorization_matrix.yaml",
                    "memory_provider_access_rules.yaml",
                    "memory_use_policy_rules.yaml",
                    "memory_review_items.yaml",
                    "task_context_pack_rules.yaml",
                    "local_context_index_rules.yaml",
                    "semantic_candidate_layer_rules.yaml",
                    "graph_context_rules.yaml",
                    "session_lifecycle_rules.yaml",
                    "agent_trace_events.yaml",
                    "ai_surface_context_budget_rules.yaml",
                    "model_provider_policy.yaml",
                    "model_telemetry_evidence.yaml",
                    "failure_mode_taxonomy.yaml",
                    "failure_mode_observations.yaml",
                    "opencode_config_hygiene.yaml",
                    "design_traceability.yaml",
                    "ui_experience_quality.yaml",
                    "llm_grader_readiness_rules.yaml",
                    "behavioral_governance_readiness_rules.yaml",
                    "learning_loop_rules.yaml",
                    "learning_candidates.yaml",
                    "learning_state.yaml",
                    "learning_history.yaml",
                    "research_record_contract.yaml",
                    "RECORD_TEMPLATE.yaml",
                }
                quickstart_seed_paths = {
                    Path("naos/policy_overrides.d/README.md"),
                }
                if tier == "quickstart" and rel.name not in quickstart_seed_names and rel not in quickstart_seed_paths:
                    continue
                if tier == "lite" and rel.name == "ai_component_inventory_rules.yaml":
                    continue
                dest = preview_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                _copy_new_generated_seed(seed, dest, source_origins=source_origins)
                generated.append(rel.as_posix())

    _apply_memory_choice_to_preview(
        preview_dir, generated, memory_choice, source_origins=source_origins,
    )
    _apply_planning_baseline_profile(preview_dir, tier)
    _apply_ai_component_inventory_profile(preview_dir, tier)

    # 6a. Control-plane policy and capability contracts (lite+).
    # These are adopter-local seeds for the portable kit's file-first validators;
    # quickstart remains low-friction and advisory without copying the full model.
    if tier != "quickstart":
        policy_src = POLICIES_DIR / "default_policy.yaml"
        if policy_src.is_file():
            dest = preview_dir / "naos" / "policy" / "default_policy.yaml"
            dest.parent.mkdir(parents=True, exist_ok=True)
            copy_source(policy_src, dest)
            _persist_generated_policy_profile(dest, tier)
            generated.append("naos/policy/default_policy.yaml")

        register_src = KIT_DIR / "configs" / "secure_coding_control_register.yaml"
        if register_src.is_file():
            dest = preview_dir / "naos" / "secure_coding_control_register.yaml"
            dest.parent.mkdir(parents=True, exist_ok=True)
            _copy_new_generated_seed(register_src, dest, source_origins=source_origins)
            generated.append("naos/secure_coding_control_register.yaml")

        if CAPABILITIES_DIR.is_dir():
            cap_dest = preview_dir / "naos" / "capabilities"
            cap_dest.mkdir(parents=True, exist_ok=True)
            for cap_file in sorted(CAPABILITIES_DIR.glob("*.yaml")):
                if tier == "lite" and cap_file.name == "ai_component_inventory.yaml":
                    continue
                copy_source(cap_file, cap_dest / cap_file.name)
                generated.append(f"naos/capabilities/{cap_file.name}")

        schema_src = KIT_DIR / "schemas" / "naos"
        adopter_schema_names = {
            "task_claims.schema.json",
            "task_claim_report.schema.json",
            "conformance_latest.schema.json",
            "capability.schema.json",
            "capability_maturity.schema.json",
            "static_grader_report.schema.json",
            "grader_assessment.schema.json",
            "llm_grader_readiness.schema.json",
            "calibration_shadow.schema.json",
            "calibration_shadow_report.schema.json",
            "evidence_classification_policy.schema.json",
            "evidence_classification_report.schema.json",
            "gate_status.schema.json",
            "gate_evaluation.schema.json",
            "gatekeeper.schema.json",
            "gate_input_error.schema.json",
            "agent_trace_event.schema.json",
            "agent_trace_validation.schema.json",
            "external_evidence_ingest.schema.json",
            "external_evidence_source.schema.json",
            "evidence_attestation.schema.json",
            "evidence_envelope.schema.json",
            "evidence_verification.schema.json",
            "claims_validation.schema.json",
            "control_plane_review.schema.json",
            "setup_module_catalog.schema.json",
            "setup_recommendations.schema.json",
            "function_index_health.schema.json",
            "graph_context_query.schema.json",
            "graph_context_readiness.schema.json",
            "learning_loop_review.schema.json",
            "local_context_index.schema.json",
            "local_context_query.schema.json",
            "memory_context_readiness.schema.json",
            "memory_provider_access.schema.json",
            "memory_use_policy.schema.json",
            "module_header_traceability.schema.json",
            "roadmap_crosswalk_validation.schema.json",
            "self_check.schema.json",
            "self_check_dependency_resolution.schema.json",
            "semantic_candidate_layer.schema.json",
            "session_lifecycle.schema.json",
            "spec_cascade_coherence.schema.json",
            "systemic_impact_review.schema.json",
            "systemic_impact_rules.schema.json",
            "systemic_impact_changed_path_review.schema.json",
            "systemic_impact_family_review.schema.json",
            "configuration_posture_review.schema.json",
            "pr_governance_summary.schema.json",
            "policy_override.schema.json",
            "policy_override_merge.schema.json",
            "adapter_coherence_report.schema.json",
            "task_context_pack.schema.json",
            "task_context_revalidation.schema.json",
            "test_evidence_health.schema.json",
            "task_registry.schema.json",
            "capability_maturity_report.schema.json",
            "evidence_pack.schema.json",
            "report_source_reference.schema.json",
            "capability_maturity_collection_witness.schema.json",
            "dashboard_summary.schema.json",
            "ai_surface_context_budget.schema.json",
            "ai_surface_profile_footprint_baseline.schema.json",
            "cross_harness_review_readiness.schema.json",
            "cross_harness_review_readiness_report.schema.json",
            "duplicate_function_hygiene.schema.json",
            "secret_hygiene.schema.json",
            "secret_public_literals.schema.json",
            "test_quality_hygiene.schema.json",
            "dependency_integrity.schema.json",
            "package_reality.schema.json",
            "package_reality_provenance.schema.json",
            "api_symbol_reality_manifest.schema.json",
            "api_symbol_reality.schema.json",
            "ac_completion_evidence_manifest.schema.json",
            "ac_completion_evidence.schema.json",
            "pr_risk_classification.schema.json",
            "ai_component_inventory_rules.schema.json",
            "ai_component_inventory.schema.json",
            "model_provider_policy.schema.json",
            "model_telemetry_evidence.schema.json",
            "failure_mode_posture.schema.json",
            "failure_mode_observations.schema.json",
            "opencode_config_hygiene.schema.json",
            "design_traceability.schema.json",
            "ui_experience_quality.schema.json",
            "secure_coding_control_register.schema.json",
            "secure_coding_control_evidence_routes.schema.json",
            "secure_coding_controls.schema.json",
            "adoption_summary.schema.json",
            "preflight_report.schema.json",
            "intake_report.schema.json",
            "install_plan.schema.json",
            "existing_resource_inventory.schema.json",
            "ai_artifact_inventory.schema.json",
            "ai_artifact_reconciliation.schema.json",
            "ai_code_provenance.schema.json",
            "compliance_posture.schema.json",
            "memory_resource_inventory.schema.json",
            "memory_resource_reconciliation.schema.json",
            "mcp_resource_inventory.schema.json",
            "brownfield_baseline.schema.json",
            "candidate_requirements.schema.json",
            "traceability_gap_register.schema.json",
            "install_decision_record.schema.json",
            "parallel_lane_handoff.schema.json",
            "context_challenge_report.schema.json",
            "repo_context_challenge_report.schema.json",
            "plan_challenge_report.schema.json",
            "decision_probe_report.schema.json",
            "planning_gate_review_report.schema.json",
            "spec_pack_manifest.schema.json",
            "spec_pack_contract.schema.json",
            "pre_implementation_alignment_review.schema.json",
            "plan_coherence.schema.json",
            "spec_pack_materialization.schema.json",
            "spec_assembly_worksheet.schema.json",
            "task_lifecycle_contract.schema.json",
            "completed_task_history.schema.json",
            "task_lifecycle.schema.json",
            "research_record.schema.json",
            "research_record_validation.schema.json",
            "composed_traceability.schema.json",
            "overlay_compatibility.schema.json",
            "human_decision_record.schema.json",
            "planning_baselines.schema.json",
            "governed_debug_escalation.schema.json",
        }
        if schema_src.is_dir():
            schema_dest = preview_dir / "schemas" / "naos"
            schema_dest.mkdir(parents=True, exist_ok=True)
            for schema_file in sorted(schema_src.glob("*.json")):
                if schema_file.name not in adopter_schema_names:
                    continue
                if tier == "lite" and schema_file.name.startswith("ai_component_inventory"):
                    continue
                copy_source(schema_file, schema_dest / schema_file.name)
                generated.append(f"schemas/naos/{schema_file.name}")
        team_schema_src = KIT_DIR / "schemas" / "team_config.schema.yaml"
        if team_schema_src.is_file():
            team_schema_dest = preview_dir / "schemas" / team_schema_src.name
            team_schema_dest.parent.mkdir(parents=True, exist_ok=True)
            copy_source(team_schema_src, team_schema_dest)
            generated.append(f"schemas/{team_schema_src.name}")

    # 6b. Public evidence docs used by admissibility-pack (all tiers)
    evidence_docs = {
        "ADMISSIBILITY.md",
        "TOOL_NEUTRAL_USAGE.md",
        "TASK_CONTEXT_INTEGRITY.md",
        "HOST_CONTEXT_BUDGET.md",
        "CLAIMS_AND_LIMITATIONS.md",
        "CONFIGURATION_POSTURE_REVIEW.md",
        "decisions/ADR-0010-control-plane-advisory-boundaries.md",
        "COMPLIANCE_MAPPING.md",
        "DORA_MAPPING.md",
        "ENGRAM_SETUP.md",
        "OSFI_E23_MAPPING.md",
    }
    docs_src = KIT_DIR / "docs"
    if docs_src.is_dir():
        for doc_name in sorted(evidence_docs):
            doc_src = docs_src / doc_name
            if not doc_src.is_file():
                continue
            dest = preview_dir / "docs" / doc_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            copy_source(doc_src, dest)
            generated.append(f"docs/{doc_name}")

    # Copied public evidence docs retain their kit-only references explicitly;
    # do not ship broken local links or imply the canonical kit register exists
    # in an adopter. All other local links remain unchanged and validated.
    evidence_doc_kit_references = {
        "docs/COMPLIANCE_MAPPING.md": frozenset({
            "KNOWN_LIMITATIONS.md",
            "configs/secure_coding_control_register.yaml",
            "configs/secure_coding_control_register.sample.yaml",
            "configs/secure_coding_control_render_manifest.yaml",
            "docs/decisions/ADR-0012-secure-and-agentic-coding-control-register.md",
            "docs/SECURE_CODING_CONTROL_MODEL.md",
        }),
        "docs/decisions/ADR-0010-control-plane-advisory-boundaries.md": frozenset({
            "docs/CONTROL_PLANE.md", "docs/BEHAVIORAL_AUDIT_ENABLEMENT.md",
        }),
    }
    for relative, upstream in evidence_doc_kit_references.items():
        if relative not in generated:
            continue
        for resource in upstream:
            if not (KIT_DIR / resource).is_file():
                raise ValueError(f"Declared upstream evidence-doc source is missing: {resource}")
        path = preview_dir / relative
        original = path.read_text(encoding="utf-8")
        projected = _project_instruction_links(original, document_path=relative,
            output_document_path=relative, inventory=set(generated), tier=tier,
            kit_reference_paths=upstream)
        if projected != original:
            projected += ("\n> Upstream kit resources: `kit://` links identify separately acquired NAOS kit "
                "sources, not installed project files, runnable commands or satisfied evidence. "
                "Obtain the named source for the applicable review; project-local obligations remain in force.\n")
            path.write_text(projected, encoding="utf-8", newline="\n")

    # 7. Archetype-specific project-context.md (override generic template — lite+ only)
    if archetype and archetype != "custom" and tier != "quickstart":
        archetype_ctx = ARCHETYPES_DIR / archetype / "project-context.md"
        if archetype_ctx.exists():
            dest = preview_dir / ".github" / "project-context.md"
            dest.parent.mkdir(parents=True, exist_ok=True)
            copy_source(archetype_ctx, dest)
            dest.write_text(
                _provisional_archetype_context(dest.read_text(encoding="utf-8"), archetype, tier),
                encoding="utf-8", newline="\n",
            )
            # generated[] entries must be real preview-relative paths (activate() resolves
            # and copies them); the archetype annotation is logged, not embedded in the path.
            generated.append(".github/project-context.md")
            if emit_progress:
                print(
                    "  [archetype] .github/project-context.md from archetype: "
                    + archetype
                )

    # 8a. Spec-kit templates (tier-conditional):
    #     quickstart → none  |  lite → manifest + 01,02,03 + README  |  standard/assured → all
    spec_src = TEMPLATES_DIR / "spec-kit" / "specs"
    if spec_src.is_dir() and tier != "quickstart":
        specs_dest = preview_dir / "specs"
        specs_dest.mkdir(parents=True, exist_ok=True)
        lite_specs = {
            "README.md",
            "spec_manifest.yaml",
            "01-problem.md",
            "02-solution.md",
            "03-requirements.md",
        }
        for spec_file in sorted(spec_src.iterdir()):
            if not spec_file.is_file():
                continue
            if tier == "lite" and spec_file.name not in lite_specs:
                continue
            copy_source(spec_file, specs_dest / spec_file.name)
            generated.append(f"specs/{spec_file.name}")
        template_specs_dest = preview_dir / "naos" / "spec_templates" / "spec-kit" / "specs"
        template_specs_dest.mkdir(parents=True, exist_ok=True)
        for spec_file in sorted(spec_src.iterdir()):
            if not spec_file.is_file():
                continue
            copy_source(spec_file, template_specs_dest / spec_file.name)
            generated.append(f"naos/spec_templates/spec-kit/specs/{spec_file.name}")

    # 8b. Agent surface templates (profile contract):
    #     quickstart → thin research-only handoff | lite → bounded lifecycle set | standard/assured → all
    agents_src = TEMPLATES_DIR / "agents"
    if agents_src.is_dir():
        agents_dest = preview_dir / ".github" / "agents"
        agents_dest.mkdir(parents=True, exist_ok=True)
        lite_agents = {
            "AGENTS.md",
            "_HANDOFF_TEMPLATE.yaml",
            "naos-plan.agent.md",
            "naos-implement.agent.md",
        }
        contract_agents = {
            Path(path).name
            for path in required_surfaces
            if path.startswith(".github/agents/")
        }
        for agent_file in sorted(agents_src.iterdir()):
            if not agent_file.is_file():
                continue
            if tier == "quickstart" and agent_file.name not in contract_agents:
                continue
            if tier == "lite" and agent_file.name not in (lite_agents | contract_agents):
                continue
            # A Markdown index in .github/agents is parsed as a custom agent by
            # supported hosts. Keep role documentation outside that discovery root.
            destination = (preview_dir / ".github" / "NAOS_AGENTS.md"
                           if agent_file.name == "AGENTS.md" else agents_dest / agent_file.name)
            copy_source(agent_file, destination)
            generated.append(destination.relative_to(preview_dir).as_posix())

    # 8c. Agent surface prompts (profile contract):
    #     quickstart → none | lite → bounded lifecycle set | standard/assured → all
    prompts_src = TEMPLATES_DIR / "prompts"
    if prompts_src.is_dir() and tier != "quickstart":
        prompts_dest = preview_dir / ".github" / "prompts"
        prompts_dest.mkdir(parents=True, exist_ok=True)
        lite_prompts = {
            "naos-task-start.prompt.md",
            "naos-d-commit.prompt.md",
            "naos-add-feature.prompt.md",
            "naos-GOVERNANCE_BOOTSTRAP.prompt.md",
            "naos-t-test-failure.prompt.md",
            "pre_implementation_alignment.md",
        }
        contract_prompts = {
            Path(path).name
            for path in required_surfaces
            if path.startswith(".github/prompts/")
        }
        for prompt_file in sorted(prompts_src.iterdir()):
            if not prompt_file.is_file():
                continue
            if tier == "lite" and prompt_file.name not in (lite_prompts | contract_prompts):
                continue
            copy_source(prompt_file, prompts_dest / prompt_file.name)
            generated.append(f".github/prompts/{prompt_file.name}")

    # 8d. Agent surface skills (tier-conditional):
    #     quickstart -> none | lite -> core skills | standard -> core + delivery/review skills | assured -> all
    skills_src = TEMPLATES_DIR / "skills"
    if skills_src.is_dir() and tier != "quickstart":
        skills_dest = preview_dir / ".github" / "skills"
        skills_dest.mkdir(parents=True, exist_ok=True)
        lite_skills = {
            "cognitive-checkpoint",
            "debug",
            "gov-refresh",
            "cookbook-governance",
            "cookbook-observability",
            "cookbook-evals",
        }
        standard_skills = lite_skills | {
            "function-discovery",
            "spec-extract",
            "ai-surface-health-review",
            "governed-coding-execution",
            "governed-learning-lifecycle",
            "cookbook-python",
            "cookbook-configs",
            "cookbook-tests",
            "cookbook-frontend",
            "systemic-wiring",
        }
        for skill_dir in sorted(skills_src.iterdir()):
            if not skill_dir.is_dir():
                continue
            if tier == "lite" and skill_dir.name not in lite_skills:
                continue
            if tier == "standard" and skill_dir.name not in standard_skills:
                continue
            dest_skill = skills_dest / skill_dir.name
            if dest_skill.exists():
                shutil.rmtree(dest_skill)
            if source_origins is not None:
                for skill_file in skill_dir.rglob("*"):
                    if (not skill_file.is_file() or ".DS_Store" == skill_file.name
                            or skill_file.suffix in {".pyc", ".pyo"}
                            or "__pycache__" in skill_file.parts):
                        continue
                    destination = dest_skill / skill_file.relative_to(skill_dir)
                    source_origins.record(
                        skill_file, destination.relative_to(preview_dir).as_posix(),
                    )
            shutil.copytree(
                skill_dir,
                dest_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".DS_Store"),
            )
            generated.extend(
                leaf.relative_to(preview_dir).as_posix()
                for leaf in sorted(dest_skill.rglob("*")) if leaf.is_file()
            )

    # 8e. Agent surface instructions (tier + signal conditional):
    #     quickstart → function-discovery only (hero anti-duplication instruction)
    #     Base set is tier-conditional (lite/standard/assured).
    #     PLUS: when signals dict is provided, signal-triggered instructions are
    #     added dynamically (e.g., has_sql_db → database.instructions.md).
    #     assured tier: always includes all instructions (exhaustive coverage).
    #     Signal-only additions require the signal; absent signals add no file.
    instructions_src = TEMPLATES_DIR / "instructions"
    if instructions_src.is_dir():
        instructions_dest = preview_dir / ".github" / "instructions"
        instructions_dest.mkdir(parents=True, exist_ok=True)
        quickstart_instructions = {
            "function-discovery.instructions.md",
        }
        lite_instructions = {
            "governance.instructions.md",
            "security.instructions.md",
            "tests.instructions.md",
        }
        standard_instructions = lite_instructions | {
            "python-backend.instructions.md",
            "api-endpoints.instructions.md",
            "configs.instructions.md",
            "frontend.instructions.md",
            "context-pressure.instructions.md",
        }
        # Signal-triggered additions (added on top of tier base when signals present)
        signal_additions: set[str] = set()
        if signals:
            signal_additions = _signal_triggered_instructions(signals)

        for instr_file in sorted(instructions_src.iterdir()):
            if not instr_file.is_file():
                continue
            if tier == "assured":
                pass  # include all instructions regardless of signals
            elif tier == "standard":
                if (
                    instr_file.name not in standard_instructions
                    and instr_file.name not in signal_additions
                ):
                    continue
            elif tier == "quickstart":
                if instr_file.name not in quickstart_instructions:
                    continue
            else:  # lite
                if (
                    instr_file.name not in lite_instructions
                    and instr_file.name not in signal_additions
                ):
                    continue
            copy_source(instr_file, instructions_dest / instr_file.name)
            generated.append(f".github/instructions/{instr_file.name}")

    # 8f. CI workflow templates (tier-conditional):
    #     quickstart → none  |  lite/standard/assured → public-safe NAOS readiness CI
    # Older app-specific workflow templates remain available for manual adoption, but
    # are not copied by default because they may require services, write permissions,
    # artifact upload, or project-specific commands.
    workflows_src = TEMPLATES_DIR / "workflows"
    if workflows_src.is_dir() and tier != "quickstart":
        workflows_dest = preview_dir / ".github" / "workflows"
        workflows_dest.mkdir(parents=True, exist_ok=True)
        default_workflows = {"naos-control-plane-ci.yml"}
        for wf_file in sorted(workflows_src.iterdir()):
            if not wf_file.is_file():
                continue
            if wf_file.name not in default_workflows:
                continue
            dest = workflows_dest / wf_file.name
            copy_source(wf_file, dest)
            if wf_file.name == "naos-control-plane-ci.yml":
                content = dest.read_text(encoding="utf-8")
                content = re.sub(
                    r"NAOS_PROFILE: lite",
                    f"NAOS_PROFILE: {tier}",
                    content,
                )
                dest.write_text(content, encoding="utf-8", newline="\n")
            generated.append(f".github/workflows/{wf_file.name}")

    # Distribute the reviewed PR example as inert guidance, never as active CI.
    if workflows_src.is_dir() and tier != "quickstart":
        pr_example = workflows_src / "naos-pr-governance.yml.example"
        if pr_example.is_file():
            example_rel = "naos/workflows/examples/naos-pr-governance.yml.example"
            example_dest = preview_dir / example_rel
            example_dest.parent.mkdir(parents=True, exist_ok=True)
            copy_source(pr_example, example_dest)
            generated.append(example_rel)

    # 8g. Autoresearch runner (Standard/Assured only — not Lite)
    #     Copies kit/autoresearch/ → .github/autoresearch/
    #     and kit/task_battery/   → .github/autoresearch/task_battery/
    if tier in ("standard", "assured"):
        autores_src = KIT_DIR / "autoresearch"
        autores_dest = preview_dir / ".github" / "autoresearch"
        if autores_src.is_dir():
            autores_dest.mkdir(parents=True, exist_ok=True)
            for ar_file in autores_src.rglob("*"):
                if not ar_file.is_file():
                    continue
                rel = ar_file.relative_to(autores_src)
                if any(part == "__pycache__" for part in rel.parts):
                    continue
                dest = autores_dest / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                copy_source(ar_file, dest)
                generated.append(f".github/autoresearch/{rel.as_posix()}")
        battery_src = KIT_DIR / "task_battery"
        battery_dest = autores_dest / "task_battery"
        if battery_src.is_dir():
            battery_dest.mkdir(parents=True, exist_ok=True)
            for bat_file in battery_src.iterdir():
                if bat_file.is_file() and bat_file.name != "d4_grader_scenarios.yaml":
                    copy_source(bat_file, battery_dest / bat_file.name)
                    generated.append(
                        f".github/autoresearch/task_battery/{bat_file.name}"
                    )
    elif tier == "lite":
        graders_src = KIT_DIR / "autoresearch" / "graders"
        graders_dest = preview_dir / ".github" / "autoresearch" / "graders"
        init_src = KIT_DIR / "autoresearch" / "__init__.py"
        init_dest = preview_dir / ".github" / "autoresearch" / "__init__.py"
        if graders_src.is_dir() and init_src.is_file():
            init_dest.parent.mkdir(parents=True, exist_ok=True)
            copy_source(init_src, init_dest)
            generated.append(".github/autoresearch/__init__.py")
            graders_dest.mkdir(parents=True, exist_ok=True)
            for grader_file in graders_src.rglob("*"):
                if not grader_file.is_file():
                    continue
                rel = grader_file.relative_to(graders_src)
                if any(part == "__pycache__" for part in rel.parts):
                    continue
                dest = graders_dest / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                copy_source(grader_file, dest)
                generated.append(f".github/autoresearch/graders/{rel.as_posix()}")

    # 8h. Instincts + profiles (tier-conditional):
    #     quickstart → no reference profiles  |  lite+ → every reference profile preset + schema
    instincts_src = TEMPLATES_DIR / "instincts"
    profiles_src = TEMPLATES_DIR / "profiles"
    if profiles_src.is_dir() and tier != "quickstart":
        profiles_dest = preview_dir / ".github" / "profiles"
        profiles_dest.mkdir(parents=True, exist_ok=True)
        for pf_file in sorted(profiles_src.iterdir()):
            if pf_file.is_file():
                copy_source(pf_file, profiles_dest / pf_file.name)
                generated.append(f".github/profiles/{pf_file.name}")
    if instincts_src.is_dir() and tier in ("standard", "assured"):
        instincts_dest = preview_dir / ".github" / "instincts"
        instincts_dest.mkdir(parents=True, exist_ok=True)
        for ins_file in sorted(instincts_src.iterdir()):
            if not ins_file.is_file():
                continue
            # Standard tier: schema only (no INS-*.yaml seed files)
            if tier == "standard" and ins_file.name.startswith("INS-"):
                continue
            copy_source(ins_file, instincts_dest / ins_file.name)
            generated.append(f".github/instincts/{ins_file.name}")

    # 9a. Patch AI policy in naos_ai_precommit.yaml
    precommit_yaml = preview_dir / "configs" / "naos_ai_precommit.yaml"
    if precommit_yaml.exists():
        content = precommit_yaml.read_text(encoding="utf-8")
        content = re.sub(
            r"enabled:.*# NAOS_INIT_PATCH",
            f"enabled: {str(backend != 'disabled').lower()}  # NAOS_INIT_PATCH",
            content,
        )
        content = re.sub(
            r"mode:.*# NAOS_INIT_PATCH",
            f"mode: {backend}  # NAOS_INIT_PATCH",
            content,
        )
        content = re.sub(
            r"preferred_backend:.*",
            f"preferred_backend: {backend}",
            content,
        )
        precommit_yaml.write_text(content, encoding="utf-8", newline="\n")

    # 9b. Patch NAOS_TIER default in pre-commit hook to match selected tier
    precommit_hook = preview_dir / ".githooks" / "pre-commit"
    if precommit_hook.exists():
        content = precommit_hook.read_text(encoding="utf-8")
        content = re.sub(
            r'NAOS_TIER="\$\{NAOS_TIER:-lite\}"',
            f'NAOS_TIER="${{NAOS_TIER:-{tier}}}"',
            content,
        )
        precommit_hook.write_text(content, encoding="utf-8", newline="\n")

    # The standalone P3 wrapper has its own default, independent of Makefile.naos.
    reporting_makefile = preview_dir / "Makefile.naos.secure-coding-reporting"
    if reporting_makefile.is_file():
        content = reporting_makefile.read_text(encoding="utf-8")
        content = re.sub(r"(?m)^NAOS_PROFILE \?= lite$", f"NAOS_PROFILE ?= {tier}", content)
        reporting_makefile.write_text(content, encoding="utf-8", newline="\n")

    # 9c. Patch Makefile.naos default profile to match selected tier
    makefile = preview_dir / "Makefile.naos"
    if makefile.exists():
        content = makefile.read_text(encoding="utf-8")
        content = re.sub(
            r"NAOS_PROFILE \?= quickstart",
            f"NAOS_PROFILE ?= {tier}",
            content,
        )
        content = re.sub(
            r"# NAOS_PROFILE: quickstart \| lite \| standard \| assured \(default: quickstart\)",
            f"# NAOS_PROFILE: quickstart | lite | standard | assured (default: {tier}; override with env)",
            content,
        )
        if tier == "quickstart":
            command_contract = surface_contract.get("commands") or {}
            unavailable_targets = []
            for command in ("design", "task-start"):
                alternative = command_contract[command]["alternative"]
                unavailable_targets.append(
                    f"{command}: ## Not applicable in quickstart; use the supported alternative\n"
                    f"\t@echo \"NAOS command applicability: not_applicable (profile=quickstart command={command})\"\n"
                    f"\t@echo \"Supported alternative: {alternative}\"\n\n"
                )
            content = re.sub(
                r"(?m)^\.PHONY: ",
                ".PHONY: design task-start ",
                content,
                count=1,
            )
            content = re.sub(
                r"(?m)(?=^gov-refresh:)",
                "".join(unavailable_targets),
                content,
                count=1,
            )
            refresh_alternative = command_contract["gov-refresh"]["alternative"]
            readiness_alternative = command_contract["naos-readiness"]["alternative"]
            content = re.sub(
                r"gov-refresh:.*?(?=\ngov-full:)",
                "gov-refresh: ## Not applicable in quickstart; use the supported diagnostic alternative\n"
                "\t@echo \"NAOS command applicability: not_applicable (profile=quickstart command=gov-refresh)\"\n"
                f"\t@echo \"Supported alternative: {refresh_alternative}\"\n\n",
                content,
                flags=re.DOTALL,
            )
            content = re.sub(
                r"naos-readiness:.*?(?=\ndrift-check:)",
                "naos-readiness: ## Not applicable in quickstart; use the supported diagnostic alternative\n"
                "\t@echo \"NAOS command applicability: not_applicable (profile=quickstart command=naos-readiness)\"\n"
                f"\t@echo \"Supported alternative: {readiness_alternative}\"\n\n",
                content,
                flags=re.DOTALL,
            )
        makefile.write_text(content, encoding="utf-8", newline="\n")

    # 10. Automation scripts (tier-conditional)
    #     quickstart → none  |  lite → 5 core scripts  |  standard/assured → all
    scripts_src = KIT_DIR / "scripts"
    if scripts_src.is_dir() and tier != "quickstart":
        # Core scripts always go to scripts/ (non-workflow)
        lite_scripts = {
            "naos_governance_audit.py",
            "naos_code_quality_audit.py",
            "architecture_boundaries.py",
            "naos_adapter_coherence.py",
            "naos_validate_truth.py",
            "naos_validate_task_registry.py",
            "naos_readiness.py",
            "naos_ai_precommit.py",
            "naos_policy.py",
            "source_roots.py",
            "naos_console.py",
            "spec_header.py",
            "naos_schema_validation.py",
            "naos_adoption_common.py",
            "naos_ai_surfaces.py",
            "naos_windows_report.py",
            "naos_hygiene_common.py",
            "naos_secret_public_literals.py",
            "naos_secret_managed_operands.py",
            "naos_secret_ri_windows_operands.py",
            "naos_secret_public_literals.json",
            "naos_adopt.py",
            "naos_preflight.py",
            "naos_intake.py",
            "naos_install_plan.py",
            "naos_existing_resource_inventory.py",
            "naos_ai_artifact_inventory.py",
            "naos_ai_artifact_reconcile.py",
            "naos_ai_code_provenance.py",
            "naos_compliance_posture.py",
            "naos_memory_resource_inventory.py",
            "naos_memory_resource_reconcile.py",
            "naos_mcp_resource_inventory.py",
            "naos_brownfield_baseline.py",
            "naos_requirements_reconstruct.py",
            "naos_traceability_gap_register.py",
            "naos_install_decision_record.py",
            "naos_context_challenge.py",
            "naos_repo_context_challenge.py",
            "naos_plan_challenge.py",
            "naos_decision_probe.py",
            "naos_planning_gate_review.py",
            "naos_validate_claims.py",
            "naos_capability_maturity.py",
            "naos_systemic_impact.py",
            "naos_systemic_applicability.py",
            "naos_systemic_family_review.py",
            "naos_configuration_posture_review.py",
            "naos_module_header_traceability.py",
            "naos_spec_pack_contract.py",
            "naos_spec_pack_materialize.py",
            "naos_spec_assembly_worksheet.py",
            "naos_control_plane_review.py",
            "naos_setup_recommendations.py",
            "naos_evidence_attestation.py",
            "naos_evidence_conflicts.py",
            "naos_memory_context_readiness.py",
            "naos_mcp_config_registry.py",
            "naos_memory_provider_access.py",
            "naos_memory_use_policy.py",
            "naos_task_context_pack.py",
            "naos_task_context_integrity.py",
            "naos_task_lifecycle.py",
            "naos_research_record.py",
            "naos_composed_traceability.py",
            "naos_task_claims.py",
            "naos_secret_patterns.py",
            "naos_local_context_index.py",
            "naos_local_context_query.py",
            "naos_semantic_candidate_readiness.py",
            "naos_graph_context_readiness.py",
            "naos_graph_context_query.py",
            "naos_session_identity.py",
            "naos_operator_attribution.py",
            "naos_session_lifecycle.py",
            "naos_audit_log.py",
            "naos_agent_trace_validate.py",
            "naos_ai_surface_budget.py",
            "naos_validate_instruction_budget.py",
            "naos_static_grader.py",
            "naos_grader_assessment.py",
            "naos_model_provider_policy.py",
            "naos_model_telemetry_evidence.py",
            "naos_failure_mode_posture.py",
            "naos_failure_mode_observations.py",
            "naos_opencode_config_hygiene.py",
            "naos_design_traceability.py",
            "naos_ui_experience_quality.py",
            "naos_llm_grader_readiness.py",
            "naos_behavioral_governance_readiness.py",
            "naos_policy_overrides.py",
            "naos_pr_risk_classification.py",
            "naos_self_check.py",
            "naos_agentic_workflow_review.py",
            "naos_pre_implementation_alignment_review.py",
            "naos_plan_coherence.py",
            "naos_calibration_shadow.py",
            "naos_evidence_classification.py",
            "naos_cross_harness_review_readiness.py",
            "naos_duplicate_function_hygiene.py",
            "naos_secret_hygiene.py",
            "naos_test_quality_hygiene.py",
            "naos_dependency_integrity.py",
            "naos_package_reality.py",
            "naos_api_symbol_reality.py",
            "naos_secure_coding_controls.py",
            "naos_validate_roadmap_crosswalk.py",
            "naos_function_index_health.py",
            "naos_test_evidence_map.py",
            "naos_validate_test_evidence.py",
            "naos_ac_completion_evidence.py",
            "naos_evidence_export.py",
            "naos_sarif_export.py",
            "naos_gate_status.py",
            "naos_gate_evaluate.py",
            "naos_pr_governance_summary.py",
        }
        # Workflow scripts (in workflows/ subdir)
        lite_workflows = {
            "sync_from_registry.py",
            "generate_naos_dashboard.py",
            "generate_backlog.py",
            "metrics_snapshot.py",
            "make_admissibility_pack.py",
        }
        # Shared source-bound report checks are required by copied Lite consumers.
        lite_scripts.add("naos_report_contracts.py")
        lite_scripts.add("naos_evidence_contracts.py")
        lite_scripts.add("naos_report_composition.py")
        lite_scripts.add("naos_self_check_dependency_resolution.py")
        lite_scripts.add("naos_self_check_inspection.py")
        # Canonical full self-check producers must be present before inspection
        # derives their owned report sinks from their installed source.
        lite_scripts.update({
            "naos_governance_bypass_posture.py",
            "naos_external_evidence_ingest.py",
            "naos_learning_loop_review.py",
            "naos_detect_spec_drift.py",
        })
        # configuration_posture_review -> systemic_family_review imports this
        # shared boundary helper in generated Lite projects as well.
        lite_scripts.add("naos_resource_boundary.py")

        for script_file in scripts_src.iterdir():
            if not script_file.is_file():
                continue
            # These runtimes remain installed/package or source-kit commands.
            # Their opt-in assets are project-local, but the executables are not
            # copied into every adopter repository by default.
            if script_file.name in {
                "naos_repository_intelligence.py",
                "naos_repository_intelligence_windows.py",
                "naos_agent_orchestration_plan.py",
                "naos_agent_sponsor_registry.py",
                "naos_aivss_arithmetic_verification.py",
                "naos_public_export.py",
                "generate_naos_secret_public_literals.py",
                "naos_ci_readiness.py",
            }:
                continue
            if tier == "lite" and script_file.name not in lite_scripts:
                continue
            dest = preview_dir / "scripts" / script_file.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            _copy_generated_script(script_file, dest, source_origins=source_origins, copied_tool_outputs=copied_tool_outputs)
            generated.append(f"scripts/{script_file.name}")

        native_report_source = KIT_DIR / "upgrade_contract" / "windows_handles.py"
        native_report_dest = preview_dir / "scripts" / "naos_windows_handles.py"
        _copy_generated_script(native_report_source, native_report_dest, source_origins=source_origins, copied_tool_outputs=copied_tool_outputs)
        generated.append("scripts/naos_windows_handles.py")

        # Trace atomic publication needs the exact supported POSIX observations.
        for metadata_name in ("security.py", "linux_primitives.py"):
            metadata_source = KIT_DIR / "upgrade_contract" / metadata_name
            metadata_dest = preview_dir / "scripts" / "naos_posix_metadata" / metadata_name
            metadata_dest.parent.mkdir(parents=True, exist_ok=True)
            _copy_generated_script(metadata_source, metadata_dest, source_origins=source_origins, copied_tool_outputs=copied_tool_outputs)
            generated.append(f"scripts/naos_posix_metadata/{metadata_name}")

        workflows_src = scripts_src / "workflows"
        if workflows_src.is_dir():
            for wf_file in workflows_src.iterdir():
                if not wf_file.is_file():
                    continue
                if tier == "lite" and wf_file.name not in lite_workflows:
                    continue
                dest = preview_dir / "scripts" / "workflows" / wf_file.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                _copy_generated_script(wf_file, dest, source_origins=source_origins, copied_tool_outputs=copied_tool_outputs)
                generated.append(f"scripts/workflows/{wf_file.name}")
                if wf_file.name == "generate_naos_dashboard.py":
                    # The copied dashboard must retain the shipped gate floor
                    # without depending on the kit's templates directory.
                    baseline = dest.with_name("gatekeepers.baseline.yaml")
                    copy_source(
                        TEMPLATES_DIR / "structural-seeds/naos/gatekeepers.yaml",
                        baseline,
                    )
                    generated.append("scripts/workflows/gatekeepers.baseline.yaml")
                    # Keep inert declaration comparisons available when the
                    # adopter's dashboard is moved without the kit templates.
                    for declaration in ("ai_code_provenance", "compliance_posture"):
                        baseline_name = f"{declaration}.baseline.yaml"
                        copy_source(
                            TEMPLATES_DIR / f"structural-seeds/naos/{declaration}.yaml",
                            dest.with_name(baseline_name),
                        )
                        generated.append(f"scripts/workflows/{baseline_name}")

        # Lite's adapter reviewer needs only the shared context helper/package;
        # executable maintainer validators remain Standard/Assured only.
        validators_src = scripts_src / "validators"
        if validators_src.is_dir() and tier in ("lite", "standard", "assured"):
            validator_files = (
                [validators_src / "__init__.py", validators_src / "validator_context.py"]
                if tier == "lite" else validators_src.rglob("*")
            )
            for val_file in validator_files:
                if not val_file.is_file():
                    continue
                rel = val_file.relative_to(validators_src)
                if any(part == "__pycache__" for part in rel.parts):
                    continue
                # This validates kit-level public regulatory documentation and
                # remains in the kit/package; the matrix is intentionally not
                # copied into generated adopter repositories.
                if rel == Path("validate_regulatory_claim_source_matrix.py"):
                    continue
                dest = preview_dir / "scripts" / "validators" / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                _copy_generated_script(val_file, dest, source_origins=source_origins, copied_tool_outputs=copied_tool_outputs)
                generated.append(f"scripts/validators/{rel.as_posix()}")

    _generate_host_routes(preview_dir, generated, tier, source_origins=source_origins)

    capability_emitter = preview_dir / "scripts" / "naos_emit_capabilities.py"
    if tier == "lite" or (tier in ("standard", "assured") and capability_emitter.is_file()):
        if source_origins is not None:
            catalogue_sources = sorted({
                *default_agent_files(preview_dir),
                *default_skill_files(preview_dir),
                *default_instruction_files(preview_dir),
            })
            source_origins.record_recipe(
                "catalogue", "configs/naos_ai_surface_catalogue.yaml",
                SourceOrigins.capture_file_inputs(
                    catalogue_sources, preview_dir, namespace="generated",
                ),
                {"profile": tier},
            )
        catalogue = emit_catalogue(preview_dir)
        write_catalogue(
            preview_dir / "configs" / "naos_ai_surface_catalogue.yaml",
            render_catalogue(catalogue),
        )
        generated.append("configs/naos_ai_surface_catalogue.yaml")

    _project_generated_capability_references(preview_dir, generated)
    _project_generated_gate_inputs(preview_dir, generated)
    if not _defer_traceability_content:
        _finalize_copied_tool_content(
            preview_dir, copied_tool_outputs, source_origins=source_origins,
        )
    return generated


def _guard_activation_destination(
    project_root: Path,
    rel: Path,
    *,
    reject_multiply_linked_file: bool,
) -> tuple[Path, tuple[int, int, int, int] | dict[str, str] | None]:
    """Validate one target path without following project descendants."""

    destination = project_root / rel
    windows = _windows_cli()
    if windows is not None:
        return destination, windows.activation_destination_identity(project_root, rel)
    current = project_root
    for part in rel.parts[:-1]:
        current /= part
        try:
            current_state = current.lstat()
        except FileNotFoundError:
            continue
        current_rel = current.relative_to(project_root)
        if stat.S_ISLNK(current_state.st_mode):
            raise ValueError(
                f"destination ancestor is a symbolic link: {current_rel}"
            )
        if not stat.S_ISDIR(current_state.st_mode):
            raise ValueError(
                f"destination ancestor is not a directory: {current_rel}"
            )

    try:
        leaf_state = destination.lstat()
    except FileNotFoundError:
        return destination, None
    if stat.S_ISLNK(leaf_state.st_mode):
        raise ValueError(
            f"destination leaf is a symbolic link: {rel}"
        )
    if not stat.S_ISREG(leaf_state.st_mode):
        raise ValueError(
            f"destination leaf is not a regular file: {rel}"
        )
    if reject_multiply_linked_file and leaf_state.st_nlink != 1:
        raise ValueError(
            f"destination overwrite leaf has multiple hard links: {rel}"
        )
    identity = (
        leaf_state.st_dev,
        leaf_state.st_ino,
        leaf_state.st_mode,
        leaf_state.st_nlink,
    )
    return destination, identity


def _greenfield_root_intent(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    request_inputs: dict[str, Any],
) -> dict[str, Any]:
    inventory: list[dict[str, Any]] = []
    for relative, source in sorted(
        sources,
        key=lambda item: item[0].as_posix(),
    ):
        identity, observed_metadata = regular_file_observation(source)
        metadata = source_metadata_contract(observed_metadata)
        require_supported_source_metadata(source, metadata)
        inventory.append(
            {
                "path": relative.as_posix(),
                "source": {
                    "kind": identity.kind,
                    "mode": identity.mode,
                    "size": identity.size,
                    "sha256": identity.sha256,
                },
                "source_metadata": metadata,
            }
        )
    policy_snapshot = load_source_policy_snapshot(UPGRADE_SOURCE_POLICY_PATH)
    return build_greenfield_root_intent(
        project_root,
        operation="naos-init",
        inputs=request_inputs,
        source_policy_sha256=policy_snapshot.sha256,
        source_inventory=inventory,
    )


def _require_greenfield_intent_plan_binding(
    intent: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    plan_sources = [
        {
            "path": item["path"],
            "source": item["source"],
            "source_metadata": item["source_metadata"],
        }
        for item in plan.get("paths") or []
    ]
    if (
        plan.get("operation") != intent.get("operation")
        or plan.get("inputs") != intent.get("inputs")
        or plan.get("source_policy_sha256")
        != intent.get("source_policy_sha256")
        or plan_sources != intent.get("sources")
    ):
        raise ActivationPreflightRefusal(
            "greenfield root intent and managed-content plan differ"
        )


def _emit_unmanaged_collision_review(
    *, plan_sha256: str, blocked_rows: list[dict[str, Any]],
) -> None:
    """Describe manual decisions; this diagnostic never grants apply authority."""
    def review_kind(row: dict[str, Any]) -> str:
        ordinary_collision = (
            row["action"] == "UNMANAGED_COLLISION_PRESERVE"
            and row.get("current") == "file"
        ) or (
            row["action"] == "REFUSE_UNENROLLED_COLLISION"
            and (row.get("before") or {}).get("presence") == "present"
        )
        return "external_content_comparison" if ordinary_collision else "blocking_control_review"

    review = {
        "schema": "naos.init.manual_collision_review.v1",
        "plan_sha256": plan_sha256,
        "apply_authorized": False,
        "activation_status": "refused_project_preserved",
        "blocked_paths": [
            {
                "path": row["path"].replace("\\", "/"),
                "plan_path": row["path"],
                "plan_action": row["action"],
                "generated_source": row["source"],
                "disposition": "unresolved_manual_review",
                "review_kind": review_kind(row),
                "manual_merge_authorized": False,
                "required_action": (
                    "Preserve the existing destination. Compare content only in "
                    "an external review workspace; record a decision to keep, "
                    "draft a merge externally, or defer. Check path type, links "
                    "and permissions before any separately authorized integration. "
                    "This diagnostic grants no destination write or ownership."
                    if review_kind(row) == "external_content_comparison" else
                    "Preserve the destination and resolve the reported blocking "
                    "control through its existing refusal/recovery procedure. "
                    "This row is not a content-merge candidate and grants no "
                    "destination write or ownership."
                ),
            }
            for row in sorted(blocked_rows, key=lambda item: item["path"])
        ],
        "next_action": (
            "Generate an external review preview with the same profile/options "
            "and without --activate. Resolve each listed path through the "
            "adopter's reviewed manual integration process. Direct init remains "
            "create-only: existing destinations still block init after a manual "
            "merge. This diagnostic does not clear collisions, authorize an "
            "init retry, or constitute an upgrade apply plan."
        ),
    }
    print("  BEGIN NAOS MANUAL COLLISION REVIEW")
    print(json.dumps(review, indent=2, sort_keys=True, ensure_ascii=True))
    print("  END NAOS MANUAL COLLISION REVIEW")


def _activate_managed_content(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    request_inputs: dict[str, Any],
    dry_run: bool,
    greenfield: bool,
    preapply_revalidator: Callable[[], None] | None = None,
    fixed_checks: list[dict[str, Any]] | None = None,
    private_preview_address: PrivatePreviewAddress | None = None,
) -> list[str]:
    windows = _windows_cli()
    if windows is not None:
        if private_preview_address is not None:
            return windows.activate(
                project_root, sources, request_inputs=request_inputs, dry_run=dry_run,
                greenfield=greenfield, checks=fixed_checks,
                preapply_revalidator=preapply_revalidator,
                private_preview_address=private_preview_address,
            )
        return windows.activate(
            project_root, sources, request_inputs=request_inputs, dry_run=dry_run,
            greenfield=greenfield, checks=fixed_checks,
            preapply_revalidator=preapply_revalidator,
        )
    intent = (
        _greenfield_root_intent(
            project_root,
            sources,
            request_inputs=request_inputs,
        )
        if greenfield
        else None
    )
    session = None
    scope = None
    try:
        project_metadata = os.lstat(project_root)
    except FileNotFoundError:
        if dry_run:
            print(
                "  PLAN_ONLY: the explicit greenfield target is absent. A "
                "target-bound transaction plan will be created only during "
                "the separate activation invocation."
            )
            for relative, _source in sources:
                print(f"  [DRY-RUN] Would create: {relative}")
            return [relative.as_posix() for relative, _source in sources]
        if not greenfield or intent is None:
            raise ActivationPreflightRefusal(
                "managed-content project root must already exist"
            )
        try:
            session = begin_greenfield_root(
                project_root,
                intent=intent,
                allow_create=True,
            )
        except ProvenanceError as exc:
            raise ActivationFailure(
                f"greenfield root publication or recovery failed: {exc}"
            ) from exc
        if session is None:  # pragma: no cover - absent creation cannot return None.
            raise ActivationFailure("greenfield root publication returned no authority")
        project_root = session.project_root
    else:
        if stat.S_ISLNK(project_metadata.st_mode) or not stat.S_ISDIR(
            project_metadata.st_mode
        ):
            raise ActivationPreflightRefusal(
                "managed-content project root is not a safe directory"
            )
        scope = inspect_managed_content_scope(project_root)
        if greenfield:
            assert intent is not None
            try:
                session = begin_greenfield_root(
                    project_root,
                    intent=intent,
                    allow_create=False,
                    allow_existing_without_control=scope.status == "valid",
                )
            except ProvenanceError as exc:
                raise ActivationPreflightRefusal(str(exc)) from exc

    try:
        if scope is None:
            scope = inspect_managed_content_scope(project_root)
        if session is not None and session.state == "cleanup_pending" and scope.status != "valid":
            raise ActivationPreflightRefusal(
                "greenfield root cleanup is pending but no valid managed receipt "
                "can authorize it"
            )
        if scope.status == "valid":
            if (
                not scope.project_id
                or not scope.scope_integrity
                or not scope.source_policy_sha256
            ):
                raise ActivationPreflightRefusal(
                    "managed-content provenance binding is incomplete"
                )
            if not dry_run:
                recovery_outcomes = recover_create_only_transactions(
                    project_root,
                    project_id=scope.project_id,
                    scope_integrity_sha3_512=scope.scope_integrity,
                    scope_source_policy_sha256=scope.source_policy_sha256,
                    transaction_root=project_root
                    / MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
                    lock_path=project_root / MANAGED_CONTENT_LOCK_RELATIVE,
                    manifest_path=project_root / MANAGED_CONTENT_MANIFEST_RELATIVE,
                    bases_root=project_root / MANAGED_CONTENT_BASES_RELATIVE,
                    receipts_root=project_root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
                )
                unresolved = [
                    item
                    for item in recovery_outcomes
                    if item.status in {"recovery_required", "rollback_incomplete"}
                ]
                if unresolved:
                    details = "; ".join(
                        f"{item.transaction_id}: {item.detail or item.status}"
                        for item in unresolved
                    )
                    raise ActivationPreflightRefusal(
                        "managed-content recovery preserved conflicting state; "
                        + details
                    )
                for item in recovery_outcomes:
                    print(
                        "  [RECOVERED] Managed-content transaction "
                        f"{item.transaction_id}: {item.status}"
                    )
            is_current, transaction_id = managed_content_sources_current(
                project_root,
                manifest_path=project_root / MANAGED_CONTENT_MANIFEST_RELATIVE,
                bases_root=project_root / MANAGED_CONTENT_BASES_RELATIVE,
                receipts_root=project_root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                sources=sources,
                operation="naos-init",
                inputs=request_inputs,
                require_exact_operation_inventory=True,
            )
            if is_current:
                if session is not None and not dry_run:
                    finalize_greenfield_root(
                        session,
                        exact_operation_current=True,
                    )
                print(
                    "  [ALREADY_APPLIED] Managed scaffold content and provenance "
                    f"are current (transaction {transaction_id})."
                )
                return [relative.as_posix() for relative, _source in sources]
        if session is not None and session.state == "cleanup_pending":
            raise ActivationPreflightRefusal(
                "greenfield cleanup marker is absent but the exact managed "
                "operation is not current"
            )
        plan = build_create_only_plan(
            project_root,
            sources,
            source_policy_path=UPGRADE_SOURCE_POLICY_PATH,
            operation="naos-init",
            inputs=request_inputs,
            expected_source_policy_sha256=(
                scope.source_policy_sha256
                if scope.status == "valid"
                else None
            ),
        )
        if session is not None:
            assert intent is not None
            _require_greenfield_intent_plan_binding(intent, plan)
        print(f"  Managed-content plan SHA-256: {plan['plan_sha256']}")
        if plan.get("status") != "ready_create_only":
            if not greenfield and scope.status in {
                "owner_enrollment_required", "enrollment_required",
            }:
                _emit_unmanaged_collision_review(
                    plan_sha256=plan["plan_sha256"],
                    blocked_rows=[
                        item for item in plan["paths"]
                        if not item["action"].startswith("CREATE_")
                    ],
                )
            collisions = [
                str(item["path"])
                for item in plan["paths"]
                if item.get("current") != "absent"
            ]
            preview = ", ".join(collisions[:10])
            if len(collisions) > 10:
                preview += f", and {len(collisions) - 10} more"
            if dry_run:
                print(
                    "  [PLAN-BLOCKED] Existing unmanaged destinations would "
                    "cause whole-operation apply refusal: "
                    + preview
                )
                return []
            if scope.status == "valid":
                raise ActivationPreflightRefusal(
                    "the requested profile, options, or exact generated inventory "
                    "differs from the current provenance-bound scaffold. Direct init "
                    "activation cannot apply a managed transition, so the whole project "
                    "was preserved. Persist an external plan with `naos upgrade PROJECT "
                    "--tier T --plan-out FILE`, review it, then apply only that exact plan "
                    "with `naos upgrade PROJECT --apply-plan FILE "
                    f"--expect-plan-digest SHA256`: {preview}"
                )
            raise ActivationPreflightRefusal(
                "existing generated destinations lack validated managed-content "
                "provenance; the whole activation was preserved and refused: "
                f"{preview}"
            )
        if dry_run:
            for item in plan["paths"]:
                print(f"  [DRY-RUN] Would create: {item['path']}")
            return [str(item["path"]) for item in plan["paths"]]
        if preapply_revalidator is not None:
            preapply_revalidator()
        if scope.status in {"owner_enrollment_required", "enrollment_required"}:
            if greenfield and (
                session is None or session.state != "published"
            ):
                raise ActivationPreflightRefusal(
                    "greenfield ownership enrollment lacks exact root-init authority"
                )
            scope = commit_managed_content_enrollment(
                project_root,
                authorization_digest=str(plan["plan_sha256"]),
                source_policy_sha256=str(plan["source_policy_sha256"]),
                creator_identity=(
                    managed_content_creator_identity(KIT_DIR)
                    if scope.status == "owner_enrollment_required" else None
                ),
            )
        if scope.status != "valid":
            raise ActivationPreflightRefusal(
                scope.refusal or "managed-content provenance is unavailable"
            )
        if (
            not scope.project_id
            or not scope.scope_integrity
            or not scope.source_policy_sha256
        ):
            raise ActivationPreflightRefusal(
                "managed-content provenance binding is incomplete"
            )
        revalidate_create_only_plan(
            project_root,
            sources,
            source_policy_path=UPGRADE_SOURCE_POLICY_PATH,
            plan=plan,
        )
        outcome = apply_create_only_plan(
            project_root,
            plan=plan,
            sources=sources,
            project_id=scope.project_id,
            scope_integrity_sha3_512=scope.scope_integrity,
            scope_source_policy_sha256=scope.source_policy_sha256,
            transaction_root=project_root / MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
            lock_path=project_root / MANAGED_CONTENT_LOCK_RELATIVE,
            manifest_path=project_root / MANAGED_CONTENT_MANIFEST_RELATIVE,
            bases_root=project_root / MANAGED_CONTENT_BASES_RELATIVE,
            receipts_root=project_root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
        )
        if outcome.status not in {"committed", "already_applied"}:
            raise ActivationFailure(
                f"managed-content transaction {outcome.status}: "
                f"{outcome.detail or 'inspect its durable journal'}"
            )
        if session is not None:
            exact_current, _exact_transaction_id = managed_content_sources_current(
                project_root,
                manifest_path=project_root / MANAGED_CONTENT_MANIFEST_RELATIVE,
                bases_root=project_root / MANAGED_CONTENT_BASES_RELATIVE,
                receipts_root=project_root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
                project_id=scope.project_id,
                scope_integrity_sha3_512=scope.scope_integrity,
                source_policy_sha256=scope.source_policy_sha256,
                sources=sources,
                operation="naos-init",
                inputs=request_inputs,
                require_exact_operation_inventory=True,
            )
            finalize_greenfield_root(
                session,
                exact_operation_current=exact_current,
            )
        for item in plan["paths"]:
            print(f"  [CREATED] {item['path']}")
        print(
            "  [RECEIPT] Managed-content transaction "
            f"{outcome.transaction_id}: {outcome.receipt_path}"
        )
        return [str(item["path"]) for item in plan["paths"]]
    except ActivationFailure:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        if session is not None:
            raise ActivationFailure(
                "greenfield root initialization is durably pending; the target "
                "or its operation-owned envelope may exist, so inspect or retry "
                f"the exact request for recovery: {exc}"
            ) from exc
        raise
    finally:
        if session is not None:
            session.close()


def activate(
    preview_dir: Path,
    project_path: Path,
    dry_run: bool = False,
    force: bool = False,
    generated_files: list[str] | None = None,
    managed_content: bool = True,
    managed_inputs: dict[str, Any] | None = None,
    greenfield: bool = False,
    preapply_revalidator: Callable[[], None] | None = None,
    fixed_checks: list[dict[str, Any]] | None = None,
    private_preview_address: PrivatePreviewAddress | None = None,
) -> list[str]:
    """Activate generated files only through the managed create-only path."""
    if private_preview_address is not None:
        private_preview_address.require_root(preview_dir, io=True)
    if generated_files is None:
        rels = [src.relative_to(preview_dir) for src in preview_dir.rglob("*") if src.is_file() and not src.is_symlink()]
    else:
        rels = [_safe_generated_relpath(item) for item in generated_files]
    if _windows_cli() is not None:
        project_root = Path(os.path.abspath(os.fspath(project_path.expanduser())))
    elif greenfield:
        lexical_root = Path(os.path.abspath(os.fspath(project_path)))
        project_root = lexical_root.parent.resolve(strict=True) / lexical_root.name
    else:
        project_root = project_path.resolve(strict=False)
    activation_plan: list[
        tuple[Path, Path, Path, tuple[int, int, int, int] | dict[str, str] | None]
    ] = []
    for rel in sorted(set(rels), key=lambda item: str(item)):
        if _is_generated_cache_artifact(rel):
            continue
        src = preview_dir / rel
        if src.is_symlink() or not src.is_file():
            raise ActivationPreflightRefusal(
                f"preview file is missing, non-regular, or a symbolic link: {rel}"
            )
        try:
            dest, destination_identity = _guard_activation_destination(
                project_root,
                rel,
                reject_multiply_linked_file=force,
            )
        except (OSError, ValueError) as exc:
            raise ActivationPreflightRefusal(str(exc)) from exc
        activation_plan.append((rel, src, dest, destination_identity))

    if not managed_content:
        raise ActivationPreflightRefusal(
            "legacy file-copy activation is unavailable; managed create-only "
            "provenance is required"
        )
    sources = [
        (rel, src)
        for rel, src, _dest, _identity in activation_plan
    ]
    return _activate_managed_content(
        project_root,
        sources,
        request_inputs=dict(managed_inputs or {}),
        dry_run=dry_run,
        greenfield=greenfield,
        preapply_revalidator=preapply_revalidator,
        fixed_checks=fixed_checks,
        **({"private_preview_address": private_preview_address}
           if private_preview_address is not None else {}),
    )


def _generated_python_collection_root(relative: str) -> str:
    """Return the narrow generated root for one scaffold Python file."""

    parts = Path(relative).parts
    if len(parts) >= 2 and parts[:2] == (".github", "autoresearch"):
        return ".github/autoresearch"
    return parts[0] if parts else ""


def _ruff_root_scan_consumers(
    project_path: Path,
    excluded_paths: set[str],
    observer: OverlayInputObserver | None = None,
) -> list[dict[str, Any]]:
    """Find observable recursive Ruff commands in bounded host automation files."""

    candidates = [
        project_path / "Makefile",
        project_path / "makefile",
        project_path / "GNUmakefile",
        project_path / "tox.ini",
        project_path / "noxfile.py",
    ]
    workflow_root = project_path / ".github" / "workflows"
    workflow_state = (observer.directory_state(workflow_root)
                      if observer is not None else None)
    if workflow_state == "directory" or (observer is None and workflow_root.is_dir()):
        if observer is None:
            candidates.extend(sorted(workflow_root.glob("*.yml")))
            candidates.extend(sorted(workflow_root.glob("*.yaml")))
        else:
            candidates.extend(observer.matching_paths("workflow_yml", workflow_root,
                                                      suffix=".yml"))
            candidates.extend(observer.matching_paths("workflow_yaml", workflow_root,
                                                      suffix=".yaml"))
    elif observer is not None:
        observer.decision("workflow_namespace", {"state": workflow_state})

    consumers: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for candidate_index, path in enumerate(candidates):
        if observer is not None:
            relative = path.relative_to(project_path).as_posix()
            data = observer.file(path, purpose=f"ruff_scan/{candidate_index}",
                                 excluded=relative in excluded_paths)
            if data is None:
                continue
            path_stat = path.stat()
            identity = (path_stat.st_dev, path_stat.st_ino)
            if identity in seen:
                observer.decision("ruff_dedup/" + relative, {"state": "duplicate"})
                continue
            seen.add(identity)
            lines = data.decode("utf-8", errors="replace").splitlines()
        else:
            if not path.is_file() or path.is_symlink():
                continue
            path_stat = path.stat()
            identity = (path_stat.st_dev, path_stat.st_ino)
            if identity in seen:
                continue
            seen.add(identity)
            relative = path.relative_to(project_path).as_posix()
            if relative in excluded_paths or path_stat.st_size > 2_000_000:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
        for line_number, line in enumerate(lines, start=1):
            command = line.strip()
            ruff_match = re.search(r"(?<![\w.-])ruff\b(?P<tail>.*)", command)
            if ruff_match is None:
                continue
            if not re.search(
                r"(?:^|\s)(?:check|format)(?:\s|$)",
                ruff_match.group("tail"),
            ):
                continue
            if not re.search(r"(?:^|\s)\.(?:\s|$)", command):
                continue
            bypasses_nested_config = bool(
                re.search(r"(?:^|\s)--(?:config|isolated)(?:\s|=|$)", command)
            )
            consumers.append(
                {
                    "path": relative,
                    "line": line_number,
                    "command": command,
                    "bypasses_nested_config": bypasses_nested_config,
                }
            )
            if observer is not None and len(consumers) > MAX_INPUTS:
                raise SourceModeError("Overlay Ruff consumer count exceeds bound")
    return consumers


def build_overlay_compatibility_report(
    project_path: Path,
    preview_dir: Path,
    generated_files: list[str],
    *,
    excluded_paths: set[str] | None = None,
    layout_adapter: dict[str, Any] | None = None,
    host_lint_boundary: dict[str, Any] | None = None,
    observer: OverlayInputObserver | None = None,
) -> dict[str, Any]:
    """Detect deterministic host collection overlap before activation.

    This intentionally reports only observable path/glob consumption. It does
    not guess whether host tests are semantically compatible with NAOS code.
    """

    project_path = project_path.resolve(strict=False)
    excluded = excluded_paths or set()
    if observer is not None and (len(generated_files) > MAX_INPUTS
                                 or len(excluded) > MAX_INPUTS):
        raise SourceModeError("Overlay selected path count exceeds bound")
    generated_python = sorted(
        str(_safe_generated_relpath(item))
        for item in generated_files
        if str(item).endswith(".py")
    )
    prospective_setup_python: list[str] = []
    setup_catalog = preview_dir / "naos/setup_module_catalog.yaml"
    setup_bytes = (observer.file(setup_catalog, root="preview", purpose="setup_catalog")
                   if observer is not None else None)
    if (setup_bytes is not None if observer is not None
            else setup_catalog.is_file() and not setup_catalog.is_symlink()):
        catalog = yaml.safe_load(setup_bytes.decode("utf-8") if observer is not None
                                 else setup_catalog.read_text(encoding="utf-8")) or {}
        if observer is not None and (type(catalog) is not dict
                                     or type(catalog.get("modules")) not in {list, type(None)}
                                     or len(catalog.get("modules") or []) > MAX_INPUTS):
            raise SourceModeError("Overlay setup catalogue exceeds observation bound")
        for module in catalog.get("modules") or []:
            if not isinstance(module, dict):
                continue
            if observer is not None and (type(module.get("install_actions"))
                                         not in {list, type(None)}
                                         or len(module.get("install_actions") or []) > MAX_INPUTS):
                raise SourceModeError("Overlay setup actions exceed observation bound")
            for action in module.get("install_actions") or []:
                if not isinstance(action, dict):
                    continue
                destination = str(action.get("destination") or "")
                if destination.endswith(".py"):
                    if observer is not None and len(prospective_setup_python) >= MAX_INPUTS:
                        raise SourceModeError("Overlay setup Python paths exceed bound")
                    prospective_setup_python.append(
                        str(_safe_generated_relpath(destination))
                    )
    prospective_setup_python = sorted(set(prospective_setup_python))
    roots = sorted(
        {
            _generated_python_collection_root(item)
            for item in [*generated_python, *prospective_setup_python]
            if _generated_python_collection_root(item)
        }
    )
    findings: list[dict[str, Any]] = []

    ruff_consumers = _ruff_root_scan_consumers(project_path, excluded, observer)
    ruff_boundary_roots = {
        root
        for consumer in ruff_consumers
        if not consumer["bypasses_nested_config"]
        for root in roots
    }
    for consumer in ruff_consumers:
        bypasses_nested_config = bool(consumer["bypasses_nested_config"])
        findings.append(
            {
                "kind": "lint_glob",
                "severity": "blocking" if bypasses_nested_config else "advisory",
                "generated_roots": roots,
                "consumer": consumer["path"],
                "evidence": {
                    "line": consumer["line"],
                    "command": consumer["command"],
                },
                "mitigation": (
                    "unsupported_explicit_ruff_configuration"
                    if bypasses_nested_config
                    else "nested_managed_ruff_boundaries"
                ),
            }
        )

    config_text = ""
    for name in ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", ".coveragerc"):
        if name in excluded:
            if observer is not None:
                observer.decision("config/" + name, {"state": "excluded"})
            continue
        path = project_path / name
        if observer is not None:
            data = observer.file(path, purpose="config")
            if data is not None:
                config_text += f"\n# {name}\n{data.decode('utf-8', errors='replace')}"
        elif path.is_file() and path.stat().st_size <= 2_000_000:
            config_text += f"\n# {name}\n{path.read_text(encoding='utf-8', errors='replace')}"

    testpaths: set[str] = set()
    match = re.search(r"testpaths\s*=\s*\[([^\]]*)\]", config_text, re.IGNORECASE | re.DOTALL)
    if match:
        testpaths.update(re.findall(r"[\"']([^\"']+)[\"']", match.group(1)))
    for generated_path in generated_python:
        if any(
            generated_path == testpath.rstrip("/")
            or generated_path.startswith(f"{testpath.rstrip('/')}/")
            for testpath in testpaths
        ):
            findings.append(
                {
                    "kind": "test_discovery",
                    "severity": "blocking",
                    "generated_path": generated_path,
                    "consumer": "configured pytest testpaths",
                    "evidence": sorted(testpaths),
                }
            )

    tests_dir = project_path / "tests"
    test_state = observer.directory_state(tests_dir) if observer is not None else None
    test_files = (
        sorted(
            path
            for path in tests_dir.rglob("*.py")
            if path.relative_to(project_path).as_posix() not in excluded
        )
        if tests_dir.is_dir() and observer is None
        else []
    )
    if observer is not None:
        test_files = (observer.matching_paths("test_python_namespace", tests_dir,
                                              suffix=".py", recursive=True)
                      if test_state == "directory" else [])
        if test_state != "directory":
            observer.decision("test_python_namespace",
                              {"state": test_state})
    for test_index, test_file in enumerate(test_files):
        try:
            if observer is not None:
                relative = test_file.relative_to(project_path).as_posix()
                data = observer.file(test_file, purpose=f"test_scan/{test_index}",
                                     excluded=relative in excluded)
                if data is None:
                    continue
                text = data.decode("utf-8", errors="replace")
            else:
                if test_file.stat().st_size > 2_000_000:
                    continue
                text = test_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        recursively_scans_python = bool(
            re.search(r"\.(?:rglob|glob)\(\s*[\"'][^\"']*\.py[\"']\s*\)", text)
        )
        if not recursively_scans_python:
            continue
        for root in roots:
            root_ref = re.compile(
                rf"(?:Path\(\s*[\"']{re.escape(root)}[\"']\s*\)|/\s*[\"']{re.escape(root)}[\"'])"
            )
            if root_ref.search(text):
                findings.append(
                    {
                        "kind": "static_scan",
                        "severity": "blocking",
                        "generated_root": root,
                        "consumer": str(test_file.relative_to(project_path)),
                        "evidence": f"recursive Python scan includes generated {root}/ paths",
                    }
                )

    for root in roots:
        if _directory_has_unmanaged_files(
            project_path,
            project_path / root,
            excluded,
            observer,
        ):
            prospective_setup_overlap = root == "scripts" and any(
                Path(item).parts and Path(item).parts[0] == root
                for item in prospective_setup_python
            )
            lint_boundary_overlap = root in ruff_boundary_roots
            findings.append(
                {
                    "kind": "path_namespace_overlap",
                    "severity": (
                        "blocking"
                        if prospective_setup_overlap or lint_boundary_overlap
                        else "advisory"
                    ),
                    "generated_root": root,
                    "consumer": root,
                    "evidence": (
                        "host-owned scripts namespace overlaps future setup-module destinations"
                        if prospective_setup_overlap
                        else "pre-existing Python collection cannot receive a whole-root Ruff discovery boundary"
                        if lint_boundary_overlap
                        else "host directory already exists"
                    ),
                }
            )

    blocking = [item for item in findings if item["severity"] == "blocking"]
    categories = {
        name: {
            "status": "detected" if any(item["kind"] == name for item in findings) else "not_detected",
            "finding_count": sum(1 for item in findings if item["kind"] == name),
        }
        for name in (
            "test_discovery",
            "static_scan",
            "lint_glob",
            "package_discovery",
            "import_resolution",
            "coverage_collection",
            "path_namespace_overlap",
        )
    }
    return {
        "schema": "naos.overlay_compatibility.v1",
        "status": "blocking_collision" if blocking else "compatible_by_detected_paths",
        "project_root": str(project_path),
        "preview_root": str(preview_dir.resolve(strict=False)),
        "generated_python_paths": generated_python,
        "prospective_setup_python_paths": prospective_setup_python,
        "categories": categories,
        "findings": findings,
        "activation_allowed": not blocking,
        "blocked_before_activation": bool(blocking),
        "layout_adapter": layout_adapter
        or {
            "status": "not_required",
            "from_root": None,
            "to_root": None,
            "reason_findings": [],
        },
        "host_lint_boundary": host_lint_boundary
        or {
            "status": "not_required",
            "engine": "ruff",
            "config_paths": [],
            "generated_roots": [],
            "managed_nested_configuration_created": False,
            "preexisting_adopter_ruff_files_modified": False,
            "preexisting_adopter_python_hidden": False,
        },
        "isolation_route": {
            "strategy": "external_sidecar_preview",
            "command": "naos init <project> --preview-dir <outside-project-path> without --activate",
            "review_required_before_any_later_activation": True,
            "reversible": True,
        },
        "human_review_required": bool(findings),
        "limitations": [
            "Detection covers unmanaged namespace overlap with prospective setup destinations, explicit configured testpaths, recursive Python scans that name generated top-level roots, and literal repository-root Ruff commands in bounded host automation files.",
            "Nested Ruff boundaries cover discovered recursive Ruff file discovery only; explicit files, --config, --isolated, aliases, wrappers, and other lint engines require separate evidence or refusal.",
            "Absence of a detected collision is not proof that every host lint, package, import, or coverage rule is compatible.",
        ],
        "not_claimed": [
            "semantic compatibility",
            "complete host tooling discovery",
            "test effectiveness",
            "merge or release approval",
        ],
    }


def _apply_brownfield_script_layout_adapter(
    project_path: Path,
    preview_dir: Path,
    generated_files: list[str],
    report: dict[str, Any],
    *,
    current_managed_paths: set[str],
) -> tuple[list[str], dict[str, Any] | None]:
    """Move NAOS tools away from a host-owned ``scripts/`` collection.

    The adapter runs only for a blocking ``scripts/`` namespace finding, which
    includes an unmanaged host namespace that overlaps prospective setup Python
    destinations or an observed blocking consumer. The dedicated destination
    namespace must be absent in the preview. In the adopter it may either be
    absent or contain only paths from the validated managed-content manifest;
    this permits later profile transitions to reproduce the same adapter
    without inferring ownership. Adopter command references are rewritten
    before the managed-content plan is built; canonical kit provenance keeps
    its own source namespace.
    """

    blocking = [
        item
        for item in report.get("findings") or []
        if item.get("severity") == "blocking"
    ]
    script_findings = [
        item
        for item in blocking
        if item.get("generated_root") == "scripts"
        or str(item.get("generated_path") or "").startswith("scripts/")
    ]
    if not script_findings:
        return generated_files, None

    source_root = preview_dir / "scripts"
    target_root = preview_dir / BROWNFIELD_TOOL_ROOT
    adopter_target = project_path / BROWNFIELD_TOOL_ROOT
    adopter_target_exists = adopter_target.exists() or adopter_target.is_symlink()
    managed_adopter_target = False
    if adopter_target_exists and adopter_target.is_dir() and not adopter_target.is_symlink():
        managed_destination_paths = {
            path
            for path in current_managed_paths
            if path.startswith(f"{BROWNFIELD_TOOL_ROOT}/")
        }
        try:
            managed_adopter_target = bool(managed_destination_paths) and all(
                not path.is_symlink()
                and (
                    path.is_dir()
                    or (
                        path.is_file()
                        and path.relative_to(project_path).as_posix()
                        in current_managed_paths
                    )
                )
                for path in adopter_target.rglob("*")
            )
        except (OSError, ValueError):
            managed_adopter_target = False
    if (
        (source_root.exists() and not source_root.is_dir())
        or target_root.exists()
        or (adopter_target_exists and not managed_adopter_target)
    ):
        return generated_files, None

    mappings = {
        relative: f"{BROWNFIELD_TOOL_ROOT}/{relative.removeprefix('scripts/')}"
        for relative in generated_files
        if relative.startswith("scripts/")
    }
    if source_root.is_dir():
        source_root.rename(target_root)
    rewritten = [mappings.get(relative, relative) for relative in generated_files]
    ordered_mappings = sorted(
        mappings.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    # These declarations resolve canonical plugin provenance against kit_root(),
    # independently of the adopter's generated tool destinations.
    kit_relative_adapter_declarations = {
        "naos/adapter_coherence_rules.yaml",
        "naos/adapter_propagation_state.yaml",
    }
    # These renderer-owned blocks describe canonical kit controls. Operational
    # references outside the blocks still follow the adopter's tool layout.
    kit_generated_sections = {
        ".github/naos-guidance/security-reference.md": "secure-coding-controls",
        ".github/instructions/ai-pipeline.instructions.md": "agentic-coding-controls",
        ".github/naos-guidance/cursor-security.md": "secure-coding-controls",
    }
    reference_rewrite_count = 0
    for relative in rewritten:
        if relative in kit_relative_adapter_declarations:
            continue
        path = preview_dir / _safe_generated_relpath(relative)
        if not path.is_file() or path.is_symlink():
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        updated = original
        for old, new in ordered_mappings:
            updated = updated.replace(old, new)
        section_id = kit_generated_sections.get(relative)
        if section_id is not None:
            begin = f"<!-- BEGIN NAOS GENERATED: {section_id} -->"
            end = f"<!-- END NAOS GENERATED: {section_id} -->"
            if original.count(begin) == original.count(end) == 1:
                start = original.index(begin)
                finish = original.index(end)
                if finish > start and updated.count(begin) == updated.count(end) == 1:
                    updated_start = updated.index(begin)
                    updated_finish = updated.index(end)
                    if updated_finish > updated_start:
                        updated = (
                            updated[:updated_start]
                            + original[start:finish + len(end)]
                            + updated[updated_finish + len(end):]
                        )
        if relative in {
            "Makefile.naos",
            ".githooks/pre-commit",
            ".github/workflows/naos-control-plane-ci.yml",
            "naos/setup_module_catalog.yaml",
        }:
            updated = updated.replace("scripts/", f"{BROWNFIELD_TOOL_ROOT}/")
        if updated != original:
            path.write_text(updated, encoding="utf-8", newline="\n")
            reference_rewrite_count += 1

    if not mappings and reference_rewrite_count == 0:
        return generated_files, None

    return rewritten, {
        "status": "applied",
        "from_root": "scripts",
        "to_root": BROWNFIELD_TOOL_ROOT,
        "reason_findings": script_findings,
        "rewritten_path_count": len(mappings),
        "rewritten_reference_file_count": reference_rewrite_count,
        "prospective_setup_destinations_adapted": True,
    }


def _apply_brownfield_ruff_boundaries(
    preview_dir: Path,
    generated_files: list[str],
    report: dict[str, Any],
    source_origins: SourceOrigins | None = None,
) -> tuple[list[str], dict[str, Any] | None]:
    """Fence generated Python from a detected conventional Ruff root scan."""

    lint_findings = [
        item
        for item in report.get("findings") or []
        if item.get("kind") == "lint_glob"
    ]
    if not lint_findings or any(
        item.get("severity") == "blocking"
        for item in report.get("findings") or []
    ):
        return generated_files, None

    generated_roots = sorted(
        {
            str(root)
            for item in lint_findings
            for root in item.get("generated_roots") or []
            if str(root)
        }
    )
    rewritten = list(generated_files)
    config_paths: list[str] = []
    for root in generated_roots:
        config_rel = _safe_generated_relpath(f"{root}/.ruff.toml").as_posix()
        config_path = preview_dir / config_rel
        config_path.parent.mkdir(parents=True, exist_ok=True)
        if config_path.exists() and (
            config_path.is_symlink()
            or not config_path.is_file()
            or config_path.read_text(encoding="utf-8")
            != BROWNFIELD_RUFF_BOUNDARY
        ):
            raise ActivationPreflightRefusal(
                f"generated Ruff boundary conflicts with preview content: {config_rel}"
            )
        if source_origins is not None:
            source_origins.record_recipe(
                "ruff_boundary", config_rel,
                [
                    ("decision/generated_roots", bounded_canonical_input(generated_roots)),
                    ("decision/lint_findings", bounded_canonical_input(lint_findings)),
                    ("source/boundary_literal", BROWNFIELD_RUFF_BOUNDARY.encode("utf-8")),
                ],
                {"root": root},
            )
        config_path.write_text(BROWNFIELD_RUFF_BOUNDARY, encoding="utf-8", newline="\n")
        if config_rel not in rewritten:
            rewritten.append(config_rel)
        config_paths.append(config_rel)

    return rewritten, {
        "status": "applied",
        "engine": "ruff",
        "config_paths": config_paths,
        "generated_roots": generated_roots,
        "scope": "generated_python_roots_verified_without_preexisting_python",
        "managed_nested_configuration_created": True,
        "preexisting_adopter_ruff_files_modified": False,
        "preexisting_adopter_python_hidden": False,
        "reason_findings": lint_findings,
        "unsupported_invocations": [
            "explicit generated Python file paths",
            "--config",
            "--isolated",
            "unobserved aliases or wrappers",
            "non-Ruff lint engines",
        ],
    }


def warn_generated_freshness_after_activation(
    skipped: list[str],
    *,
    force: bool = False,
    dry_run: bool = False,
) -> None:
    """Print warning-only freshness guidance for skipped generated PM files."""
    if force or dry_run:
        return
    watched = {
        "naos/DASHBOARD.md",
        "naos/PROJECT_STATUS.md",
        "naos/BACKLOG.md",
        "naos/TRACEABILITY_MATRIX.md",
        "specs/10-execution.md",
    }
    affected = sorted(path for path in skipped if path in watched)
    if not affected:
        return
    print("")
    print("  [WARN] Existing generated governance files were preserved:")
    for path in affected:
        print(f"    - {path}")
    print("  They may be stale after activation. Review the files, then run:")
    print("    make -f Makefile.naos gov-refresh")
    print("  NAOS did not overwrite them automatically.")


# ─── WIZARD ───────────────────────────────────────────────────────────────────


def _empty_signals() -> dict[str, Any]:
    """
    Returns an all-false signals dict for greenfield (--new) mode.
    Tech-stack signals are left blank — the user fills specs first via /naos-design,
    and may re-run `naos init .` later once code exists for detection.
    Schema mirrors detect_signals() so the same template pipeline is reused.
    """
    return {
        "is_python": False,
        "is_node": False,
        "is_go": False,
        "is_java": False,
        "has_api": False,
        "has_sql_db": False,
        "has_alembic": False,
        "has_sql_migrations": False,
        "has_vector_store": False,
        "has_llm": False,
        "has_event_bus": False,
        "has_auth": False,
        "has_graph_db": False,
        "has_multi_tenancy": False,
        "has_containerisation": False,
        "has_ci_cd": False,
        "web_frameworks": [],
        "database_engines": [],
        "llm_providers": [],
        "detected_archetype": None,
    }


def _exit_non_interactive_prompt(selection: str, required_flags: str) -> NoReturn:
    print(
        "\n  [ERROR] naos init cannot prompt for "
        f"{selection} because stdin is non-interactive.",
        file=sys.stderr,
    )
    print(f"  Re-run with explicit flags: {required_flags}.", file=sys.stderr)
    print(
        "  Example: naos init . --tier standard --archetype custom --backend static_only --activate",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _wizard_input(prompt: str, selection: str, required_flags: str) -> str:
    if not sys.stdin.isatty():
        _exit_non_interactive_prompt(selection, required_flags)
    try:
        return input(prompt)
    except EOFError:
        _exit_non_interactive_prompt(selection, required_flags)
    except KeyboardInterrupt:
        print("\n  [ERROR] naos init cancelled by user.", file=sys.stderr)
        raise SystemExit(130)


def wizard_tier() -> str:
    print_profile_comparison()
    while True:
        choice = (
            _wizard_input(
                "  Select profile tier [quickstart/lite/standard/assured]: ",
                "profile tier",
                "--tier <quickstart|lite|standard|assured>",
            )
            .strip()
            .lower()
        )
        if choice in PROFILES:
            return choice
        print(f"  Invalid choice: {choice!r}. Choose: quickstart, lite, standard, or assured")


def wizard_archetype() -> str:
    print("\n  Available archetypes:\n")
    keys = list(ARCHETYPES.keys())
    for i, k in enumerate(keys, 1):
        print(f"  [{i}] {ARCHETYPES[k]['label']}")
    print()
    while True:
        choice = _wizard_input(
            f"  Select archetype [1-{len(keys)}]: ",
            "archetype",
            "--archetype <archetype> --backend <backend>",
        ).strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                return keys[idx]
        except ValueError:
            pass
        print(f"  Invalid choice. Enter a number between 1 and {len(keys)}")


def wizard_backend() -> str:
    print("\n  Optional AI review policy:\n")
    for num, info in BACKENDS.items():
        print(f"  [{num}] {info['label']}")
    print()
    while True:
        choice = (
            _wizard_input(
                "  Select AI policy [1-5, default=1]: ",
                "AI review policy",
                "--backend <disabled|static_only|local_ollama|api_provider|ide_agent>",
            )
            .strip()
            or "1"
        )
        if choice in BACKENDS:
            return BACKENDS[choice]["key"]
        print("  Invalid choice. Enter a number between 1 and 5")


def print_memory_onboarding(
    tier: str,
    memory_choice: str | None,
    config_outcome: str = "preview",
) -> None:
    """Print tier-aware Engram onboarding guidance without installing anything."""
    if tier == "quickstart" and memory_choice is None:
        print("\n  Optional memory setup: run `naos memory-readiness`, `naos memory-access`, or `naos memory explain` when you outgrow quickstart.")
        return

    choice = memory_choice or "later"
    disposition = {
        "check": "use-existing",
        "centralized": "configure-local",
        "local": "configure-local",
        "disabled": "decline",
        "later": "defer",
    }[choice]

    def print_config_record(record: str) -> None:
        if config_outcome == "preserved":
            return
        prefix = {
            "activated": "Activated config records",
            "dry_run": "Dry-run activation would record",
            "preview": "Preview config records",
        }.get(config_outcome, "Preview config records")
        print(f"  {prefix} {record}.")

    print("\n  Optional memory setup — AI context continuity and Engram")
    print("  Recommended storage: local-first Engram data via ENGRAM_DATA_DIR when set; otherwise ~/.engram.")
    print("  Why: can support mem_context, mem_search, mem_save, compact recovery, and cross-project learning after access is configured, authorized, verified, and permitted by memory-use policy.")
    print("  Privacy: keep provider data outside project repos. NAOS does not install Engram, configure clients, or configure Git/network synchronization.")
    print("  Governance: memory is advisory recall, not evidence or approval; run `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy` to review readiness, declared/configured access posture with explicit unverified fields, and governed use.")
    print("  Existing Engram install? Run `naos memory check` to connect NAOS to it before creating anything new.")

    if config_outcome == "preserved":
        print("  Existing configs/naos_memory.yaml was preserved unchanged; the requested memory choice was not applied.")
        print(
            "  After review, record that choice explicitly with "
            f"`naos memory setup --disposition {disposition} --write`."
        )

    if choice == "check":
        print(f"  {'Requested' if config_outcome == 'preserved' else 'Selected'}: check the existing setup after activation with `naos memory check`.")
        print_config_record("use-existing / pending_existing_verification / enabled false")
        print("  `naos memory check` is read-only; it does not install, configure, or enable a provider.")
    elif choice == "centralized":
        print(f"  {'Requested' if config_outcome == 'preserved' else 'Selected'} legacy choice: centralized.")
        print_config_record("configure-local / pending_external_verification / enabled false")
        print("  No provider, client, Git, network, or synchronization configuration was performed. After separate setup, run `naos memory check`.")
    elif choice == "local":
        print(f"  {'Requested' if config_outcome == 'preserved' else 'Selected'} legacy choice: local. Provider data defaults to ~/.engram, not the project repository.")
        print_config_record("configure-local / pending_external_verification / enabled false")
        print("  No provider or client configuration was performed. After separate setup, run `naos memory check`.")
    elif choice == "disabled":
        print("  WARNING: NAOS memory integration is disabled.")
        print("  Standard/Assured workflows will use degraded recovery only: task cards, compact files, git state, and repo governance files.")
        print_config_record("decline / disabled / enabled false")
    else:
        if tier in ("standard", "assured"):
            print("  WARNING: memory setup is deferred. This is supported, but not recommended for Standard/Assured workflows.")
        else:
            print("  Memory setup deferred. You can enable it later with `naos memory setup`.")
        print_config_record("defer / deferred / enabled false")
        print("  Consequence: mem_* calls may be unavailable until Engram/MCP is configured.")


# ─── MAIN ─────────────────────────────────────────────────────────────────────


_LF_TEXT_SUFFIXES = frozenset({
    ".csv", ".json", ".md", ".mdc", ".mmd", ".naos", ".py",
    ".sh", ".toml", ".txt", ".yaml", ".yml",
})
_LF_TEXT_NAMES = frozenset({
    ".githooks/pre-commit", ".gitignore", "Makefile.naos.secure-coding-reporting",
    "naos/workflows/examples/naos-pr-governance.yml.example",
})


def _git_attributes_exact_pattern(relative: str) -> str:
    """Quote one root-relative literal path for Git attributes wildmatch."""
    if any(ord(character) < 32 or ord(character) == 127 for character in relative):
        raise ValueError(f"Generated Git attributes path has a control character: {relative!r}")
    literal = "/" + "".join(
        "\\" + character if character in "*?[]\\" else character
        for character in relative
    )
    return json.dumps(literal, ensure_ascii=False)


def _generated_lf_text_paths(
    preview_dir: Path,
    generated: list[str],
    recipe_inputs: list[tuple[str, bytes]] | None = None,
) -> tuple[list[str], list[dict[str, str]]]:
    covered: list[str] = []
    omitted: list[dict[str, str]] = []
    if recipe_inputs is not None and len(generated) > MAX_INPUTS:
        raise SourceModeError("LF recipe input count exceeds bound")
    remaining = MAX_TOTAL_INPUT_BYTES
    for relative in sorted(set(generated)):
        rel = _safe_generated_relpath(relative)
        source = preview_dir / rel
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"Generated LF source is not a regular file: {relative}")
        if recipe_inputs is None:
            data = source.read_bytes()
        else:
            data = SourceOrigins._bounded_bytes(
                source, remaining=min(MAX_INPUT_BYTES, remaining),
            )
            remaining -= len(data)
            recipe_inputs.append((f"generated/{relative}", data))
        if b"\x00" in data:
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if b"\r" in data:
            omitted.append({"path": relative, "reason": "source_contains_cr"})
        elif rel.suffix.lower() in _LF_TEXT_SUFFIXES or relative in _LF_TEXT_NAMES:
            covered.append(rel.as_posix())
        else:
            omitted.append({"path": relative, "reason": "text_type_not_allowlisted"})
    return covered, omitted


def _add_generated_gitignore(
    project_path: Path,
    preview_dir: Path,
    generated: list[str],
    *,
    greenfield: bool,
    current_managed_paths: set[str],
    source_origins: SourceOrigins | None = None,
) -> None:
    """Preview a source-bound seed; never replace an unmanaged adopter ignore."""
    if not greenfield and ".gitignore" not in current_managed_paths:
        try:
            os.lstat(project_path / ".gitignore")
        except FileNotFoundError:
            pass
        else:
            return
    destination = preview_dir / ".gitignore"
    if destination.exists() or destination.is_symlink():
        raise ValueError("Generated Git ignore conflicts with preview content")
    source = TEMPLATES_DIR / "git" / "gitignore"
    copy_source = source_origins.copy2 if source_origins is not None else shutil.copy2
    copy_source(source, destination)
    generated.append(".gitignore")


def _add_generated_lf_policy(
    project_path: Path,
    preview_dir: Path,
    generated: list[str],
    *,
    greenfield: bool,
    current_managed_paths: set[str],
    source_origins: SourceOrigins | None = None,
) -> dict[str, Any]:
    """Create only a source-bound policy; never edit adopter attributes."""
    recipe_inputs: list[tuple[str, bytes]] | None = [] if source_origins is not None else None
    # Recipe identifiers are portable POSIX paths, even when the scaffold
    # inventory was assembled from native Windows Path values.
    canonical_generated = [_safe_generated_relpath(item).as_posix() for item in generated]
    covered, omitted = _generated_lf_text_paths(preview_dir, canonical_generated, recipe_inputs)
    destination = project_path / ".gitattributes"
    attributes_state = "not_checked" if greenfield else "absent"
    if greenfield:
        # Exact --new retries must regenerate the first operation's inventory.
        # The parent-bound greenfield intent/managed receipt authenticate it.
        include = True
    else:
        try:
            os.lstat(destination)
        except FileNotFoundError:
            include = True
        else:
            attributes_state = "present"
            include = ".gitattributes" in current_managed_paths
    if not include:
        return {
            "status": "preserved_unmanaged",
            "text_paths": covered,
            "omitted_text_paths": omitted,
        }
    lines = [
        "# NAOS-generated policy for the exact generated text inventory.",
        "# Review with the adopter's other Git attributes before committing.",
    ]
    # Completion history may predate canonical digests. Preserve future direct
    # Markdown archives, including raw CRLF history, without overriding LF rules
    # for the exact generated scaffold inventory (such as completed/_TEMPLATE).
    completed_directories = sorted({
        _safe_generated_relpath(relative).parent.as_posix()
        for relative in canonical_generated
        if _safe_generated_relpath(relative).name == "_TEMPLATE.md"
        and _safe_generated_relpath(relative).parent.name == "completed"
        and (_safe_generated_relpath(relative).parent.parent / "TASK_REGISTRY.yaml").as_posix()
        in canonical_generated
    })
    lines.append("# Direct completed-card archives retain their recorded bytes.")
    lines.extend(
        json.dumps(json.loads(_git_attributes_exact_pattern(directory)) + "/*.md", ensure_ascii=False)
        + " -text -filter -ident -working-tree-encoding"
        for directory in completed_directories
    )
    lines.extend(
        f"{_git_attributes_exact_pattern(relative)} text eol=lf"
        for relative in sorted({*covered, ".gitattributes"})
    )
    lines.extend([
        "# Portable provenance records and bases retain their exact recorded bytes.",
        '"/.naos/managed-content/v3/**" -text -filter -ident -working-tree-encoding',
    ])
    policy_path = preview_dir / ".gitattributes"
    if policy_path.exists() or policy_path.is_symlink():
        raise ValueError("Generated LF policy conflicts with preview content")
    if source_origins is not None:
        assert recipe_inputs is not None
        source_origins.record_recipe(
            "lf_policy", ".gitattributes",
            sorted([*recipe_inputs,
                    ("decision/allowlist", bounded_canonical_input({
                        "suffixes": sorted(_LF_TEXT_SUFFIXES),
                        "names": sorted(_LF_TEXT_NAMES),
                    })),
                    ("decision/generated_paths", bounded_canonical_input(sorted(set(canonical_generated)))),
                    ("decision/text_paths", bounded_canonical_input(covered)),
                    ("decision/omitted", bounded_canonical_input(omitted)),
                    ("decision/completed_archive_directories", bounded_canonical_input(completed_directories))]),
            {"greenfield": greenfield, "attributes_state": attributes_state,
             "attributes_managed": ".gitattributes" in current_managed_paths},
        )
    policy_path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    generated.append(".gitattributes")
    return {
        "status": "generated",
        "text_paths": covered,
        "omitted_text_paths": omitted,
    }


def inspect_effective_lf_attributes(
    project_path: Path,
    text_paths: list[str],
    *,
    cached: bool = False,
    portable_only: bool = False,
) -> dict[str, Any]:
    """Inspect LF rules; portable mode excludes machine-local attribute policy.

    Portable inspection requires the index and conservatively refuses any
    info/attributes entry. Only child flags/environment change, never policy.
    """
    if portable_only and not cached:
        return {"status": "unverified_portable_git_attributes", "gaps": [], "tracked": None}
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() not in {
            "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
            "GIT_PAGER", "GIT_FLUSH",
        }
        and not key.upper().startswith(("GIT_TRACE", "GIT_REDIRECT_"))
    }
    command_prefix = ["git"]
    if portable_only:
        # --cached alone still consults global/system/info attributes. Empty
        # core.attributesFile suppresses the global default; NOSYSTEM excludes
        # system attributes. Neither changes adopter configuration.
        command_prefix.extend(["-c", "core.attributesFile="])
        environment["GIT_ATTR_NOSYSTEM"] = "1"
    try:
        top = subprocess.run(
            [*command_prefix, "rev-parse", "--show-toplevel"], cwd=project_path,
            env=environment, capture_output=True, check=False, timeout=5,
        )
        if top.returncode or Path(os.fsdecode(top.stdout.rstrip(b"\r\n"))).resolve() != project_path.resolve():
            return {"status": "unverified_git_root", "gaps": [], "tracked": None}
        paths = sorted(set(text_paths))
        if not paths:
            return {"status": "verified", "gaps": [], "tracked": None}
        info_attributes = None
        if portable_only:
            # Ask Git for its actual path: linked worktrees can use the common
            # directory's info/attributes, rather than <worktree>/.git/info.
            local = subprocess.run(
                [*command_prefix, "rev-parse", "--git-path", "info/attributes"],
                cwd=project_path, env=environment, capture_output=True,
                check=False, timeout=5,
            )
            raw_path = local.stdout.rstrip(b"\r\n")
            if local.returncode or not raw_path or b"\n" in raw_path or b"\r" in raw_path or b"\x00" in raw_path:
                return {"status": "unverified_local_git_attributes", "gaps": [], "tracked": None}
            info_attributes = Path(os.fsdecode(raw_path))
            if not info_attributes.is_absolute():
                info_attributes = project_path / info_attributes
            try:
                # Conservative refusal includes empty files, directories and
                # dangling links; a linked info parent also remains unknown.
                if stat.S_ISLNK(info_attributes.parent.lstat().st_mode):
                    return {"status": "unverified_local_git_attributes", "gaps": [], "tracked": None}
                info_attributes.lstat()
            except FileNotFoundError:
                pass
            else:
                return {"status": "unverified_local_git_attributes", "gaps": [], "tracked": None}
        result = subprocess.run(
            [*command_prefix, "check-attr", *(["--cached"] if cached else []),
             "-z", "--stdin", "text", "eol"],
            cwd=project_path, env=environment, capture_output=True,
            input=b"\x00".join(os.fsencode(path) for path in paths) + b"\x00",
            check=False, timeout=10,
        )
        if result.returncode:
            return {"status": "unverified_git_attributes", "gaps": [], "tracked": None}
        fields = result.stdout.split(b"\x00")
        if not fields or fields[-1] != b"" or (len(fields) - 1) != 6 * len(paths):
            return {"status": "unverified_git_attributes", "gaps": [], "tracked": None}
        observed: dict[str, dict[str, str]] = {}
        for index in range(0, len(fields) - 1, 3):
            relative = os.fsdecode(fields[index])
            attribute = os.fsdecode(fields[index + 1])
            value = os.fsdecode(fields[index + 2])
            if (
                relative not in paths
                or attribute not in {"text", "eol"}
                or attribute in observed.get(relative, {})
            ):
                return {"status": "unverified_git_attributes", "gaps": [], "tracked": None}
            observed.setdefault(relative, {})[attribute] = value
        gaps = [
            relative for relative in paths
            if observed.get(relative) != {"text": "set", "eol": "lf"}
        ]
        if info_attributes is not None:
            try:
                info_attributes.lstat()
            except FileNotFoundError:
                pass
            else:
                # A new local override cannot be accepted during inspection.
                return {"status": "unverified_local_git_attributes", "gaps": [], "tracked": None}
        tracked = subprocess.run(
            [*command_prefix, "ls-files", "--error-unmatch", "--", ".gitattributes"],
            cwd=project_path, env=environment, capture_output=True,
            check=False, timeout=5,
        ).returncode == 0
        return {"status": "verified", "gaps": gaps, "tracked": tracked}
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return {"status": "unverified_git_attributes", "gaps": [], "tracked": None}


def _require_unmanaged_lf_policy(project_path: Path, policy: dict[str, Any]) -> None:
    """Refuse unsafe brownfield publication without editing adopter policy.

    Preview bytes and managed provenance remain unchanged. A human must review
    and stage/commit a compatible adopter policy before managed activation.
    """
    if policy.get("status") != "preserved_unmanaged":
        return
    paths = list(policy.get("text_paths") or [])
    effective = inspect_effective_lf_attributes(project_path, paths)
    staged = inspect_effective_lf_attributes(project_path, paths, cached=True)
    portable = inspect_effective_lf_attributes(project_path, paths, cached=True, portable_only=True)
    if any(
        item.get("status") != "verified"
        or item.get("gaps")
        or item.get("tracked") is not True
        for item in (effective, staged, portable)
    ):
        details = "working tree: " + "; ".join(lf_policy_diagnostic_lines(policy, effective))
        details += "; index: " + "; ".join(lf_policy_diagnostic_lines(policy, staged))
        details += "; portable index (" + str(portable.get("status")) + "): "
        details += "; ".join(lf_policy_diagnostic_lines(policy, portable))
        raise ActivationPreflightRefusal(
            "LF_POLICY_UNMANAGED_REFUSED: adopter .gitattributes must be "
            "tracked and Git must select text/eol=lf in the working tree "
            "and portable index for every generated text "
            "path before managed activation or profile transition. Review "
            "the external preview and the effective Git attributes; amend "
            "and stage the adopter policy explicitly, then rerun. Existing "
            "repository-local info/attributes requires explicit review; "
            "its presence cannot certify portable policy. " + details
        )


def lf_policy_diagnostic_lines(
    policy: dict[str, Any],
    effective: dict[str, Any] | None = None,
) -> list[str]:
    """Keep LF limitations visible without changing any plan/evidence schema."""
    lines: list[str] = []
    if policy.get("status") == "preserved_unmanaged":
        lines.append(
            "LF_POLICY_UNMANAGED_ATTRIBUTES: existing adopter .gitattributes "
            "was preserved; NAOS LF policy was not installed."
        )
    omitted = policy.get("omitted_text_paths") or []
    if omitted:
        lines.append(
            "LF_POLICY_SOURCE_GAPS: generated text paths were not pinned: "
            + ", ".join(str(item.get("path")) for item in omitted[:10])
            + (f" (and {len(omitted) - 10} more)" if len(omitted) > 10 else "")
        )
    if effective is None:
        return lines
    if effective.get("status") != "verified":
        lines.append(
            "LF_POLICY_GIT_UNVERIFIED: effective attributes could not be "
            "verified at the adopter Git root."
        )
        return lines
    gaps = effective.get("gaps") or []
    if gaps:
        lines.append(
            "LF_POLICY_EFFECTIVE_GAPS: Git does not select text/eol=lf for: "
            + ", ".join(str(path) for path in gaps[:10])
            + (f" (and {len(gaps) - 10} more)" if len(gaps) > 10 else "")
        )
    if effective.get("tracked") is False:
        lines.append(
            "LF_POLICY_UNTRACKED: the root .gitattributes is not tracked; "
            "a future clone is not protected until it is committed."
        )
    return lines


def _generate_scaffold_preview(
    *,
    project_path: Path,
    preview_dir: Path,
    signals: dict[str, Any] | None,
    tier: str,
    archetype: str,
    backend: str,
    memory_choice: str | None,
    current_managed_paths: set[str],
    existing_destination: bool,
    apply_brownfield_layout_adapter: bool,
    ephemeral_preview: bool,
    emit_progress: bool,
    collect_source_modes: bool = False,
    private_preview_address: PrivatePreviewAddress | None = None,
) -> dict[str, Any]:
    """Generate one deterministic preview using the canonical init pipeline."""

    if private_preview_address is not None and not ephemeral_preview:
        raise ValueError("Private preview addressing requires an owned ephemeral preview")
    prepare_preview_dir(preview_dir, project_path, **(
        {"private_preview_address": private_preview_address}
        if private_preview_address is not None else {}
    ))
    if private_preview_address is not None:
        preview_dir = Path(private_preview_address.io_root)
    source_origins = (
        SourceOrigins.from_kit(KIT_DIR, output_root=preview_dir)
        if collect_source_modes else None
    )
    copied_tool_outputs: set[Path] = set()
    generated = scaffold_files(
        project_path=project_path,
        tier=tier,
        archetype=archetype,
        backend=backend,
        preview_dir=preview_dir,
        signals=signals,
        memory_choice=memory_choice,
        emit_progress=emit_progress,
        source_origins=source_origins,
        copied_tool_outputs=copied_tool_outputs,
        _defer_traceability_content=True,
    )
    # Native Path strings use backslashes on Windows. Overlay and adapter
    # comparisons consume portable root-relative identifiers.
    generated = [_safe_generated_relpath(item).as_posix() for item in generated]
    overlay_compatibility: dict[str, Any] | None = None
    layout_adapter: dict[str, Any] | None = None
    host_lint_boundary: dict[str, Any] | None = None
    if existing_destination:
        overlay_compatibility = build_overlay_compatibility_report(
            project_path,
            preview_dir,
            generated,
            excluded_paths=current_managed_paths,
        )
        if apply_brownfield_layout_adapter:
            generated, layout_adapter = _apply_brownfield_script_layout_adapter(
                project_path,
                preview_dir,
                generated,
                overlay_compatibility,
                current_managed_paths=current_managed_paths,
            )
            if layout_adapter is not None:
                copied_tool_outputs = {
                    preview_dir / BROWNFIELD_TOOL_ROOT / path.relative_to(preview_dir / "scripts")
                    for path in copied_tool_outputs
                }
                if source_origins is not None:
                    source_origins.rename_prefix("scripts", BROWNFIELD_TOOL_ROOT)
            overlay_compatibility = build_overlay_compatibility_report(
                project_path,
                preview_dir,
                generated,
                excluded_paths=current_managed_paths,
                layout_adapter=layout_adapter,
            )
        generated, host_lint_boundary = _apply_brownfield_ruff_boundaries(
            preview_dir,
            generated,
            overlay_compatibility,
            source_origins=source_origins,
        )
        overlay_observer = (OverlayInputObserver(project_path.resolve(strict=False), preview_dir)
                            if source_origins is not None else None)
        overlay_compatibility = build_overlay_compatibility_report(
            project_path,
            preview_dir,
            generated,
            excluded_paths=current_managed_paths,
            layout_adapter=layout_adapter,
            host_lint_boundary=host_lint_boundary,
            observer=overlay_observer,
        )
        if overlay_observer is not None:
            overlay_observer.decision("stage/generated_paths", sorted(generated))
            overlay_observer.decision("stage/excluded_paths", sorted(current_managed_paths))
            overlay_observer.decision("stage/layout_adapter", layout_adapter)
            overlay_observer.decision("stage/lint_boundary", host_lint_boundary)
            overlay_observer.decision("stage/ephemeral_preview", ephemeral_preview)
            overlay_observer.decision("stage/render_context", {
                "project_root": str(project_path.resolve(strict=False)),
                "preview_root": ("external_ephemeral_preview" if ephemeral_preview
                                 else str(preview_dir.resolve(strict=False))),
            })
            source_origins.record_recipe(
                "overlay_report", "naos/overlay_compatibility.json",
                sorted(overlay_observer.inputs), {"ephemeral_preview": ephemeral_preview},
            )
        if ephemeral_preview:
            overlay_compatibility["preview_root"] = "external_ephemeral_preview"
        overlay_report_path = preview_dir / "naos" / "overlay_compatibility.json"
        overlay_report_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_report_path.write_text(
            json.dumps(overlay_compatibility, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        overlay_report_rel = "naos/overlay_compatibility.json"
        if overlay_report_rel not in generated:
            generated.append(overlay_report_rel)

    _finalize_copied_tool_content(
        preview_dir, copied_tool_outputs, source_origins=source_origins,
    )
    _add_generated_gitignore(
        project_path, preview_dir, generated,
        greenfield=not existing_destination,
        current_managed_paths=current_managed_paths,
        source_origins=source_origins,
    )
    lf_policy = _add_generated_lf_policy(
        project_path,
        preview_dir,
        generated,
        greenfield=not existing_destination,
        current_managed_paths=current_managed_paths,
        source_origins=source_origins,
    )

    generated_files = tuple(
        sorted(
            {
                _safe_generated_relpath(item).as_posix()
                for item in generated
                if not _is_generated_cache_artifact(_safe_generated_relpath(item))
            }
        )
    )
    for relative_text in generated_files:
        source = preview_dir / relative_text
        if source.is_symlink() or not source.is_file():
            raise ValueError(
                "generated preview inventory contains a non-regular entry: "
                + relative_text
            )
    generated_contract_path = (
        preview_dir / "naos" / "profile_generated_surface_contract.json"
    )
    try:
        generated_contract = json.loads(
            generated_contract_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            "generated profile contract is missing or invalid"
        ) from exc
    if (
        not isinstance(generated_contract, dict)
        or generated_contract.get("schema")
        != "naos.profile_generated_surface_contract.v1"
        or not isinstance(generated_contract.get("profiles"), dict)
        or not isinstance(generated_contract["profiles"].get(tier), dict)
    ):
        raise ValueError("generated profile contract has an unsupported shape")
    profile_contract = generated_contract["profiles"][tier]
    required_surfaces = {
        _safe_generated_relpath(item).as_posix()
        for item in profile_contract.get("required_surfaces") or []
    }
    missing_surfaces = sorted(required_surfaces - set(generated_files))
    if missing_surfaces:
        raise ValueError(
            "generated profile contract is incomplete: "
            + ", ".join(missing_surfaces)
        )
    result = {
        "generated_files": generated_files,
        "sources": tuple(
            (Path(relative_text), preview_dir / relative_text)
            for relative_text in generated_files
        ),
        "overlay_compatibility": overlay_compatibility,
        "layout_adapter": layout_adapter,
        "host_lint_boundary": host_lint_boundary,
        "lf_policy": lf_policy,
        "profile_contract_sha256": canonical_sha256(profile_contract),
    }
    if source_origins is not None:
        result["source_mode_inventory"] = source_origins.inventory(
            [(relative, preview_dir / relative) for relative in generated_files]
        )
    return result


def regenerate_managed_init_preview(
    project_root: Path,
    preview_root: Path,
    *,
    manifest_snapshot: dict[str, Any] | ValidatedWindowsProvenance,
    requested_profile: str,
    collect_source_modes: bool = False,
    _profile_capture=None,
) -> dict[str, Any]:
    """Regenerate exact managed init sources without writing the adopter project."""

    root = (_canonical_init_target(project_root, must_exist=True)
            if _windows_cli() is not None else project_root.resolve(strict=True))
    if requested_profile not in PROFILES:
        raise ValueError(f"unsupported requested profile: {requested_profile}")
    try:
        from .upgrade_contract.portable_provenance import ValidatedPortableSnapshot
    except ImportError:
        from upgrade_contract.portable_provenance import ValidatedPortableSnapshot
    if _profile_capture is not None and type(manifest_snapshot) is not ValidatedPortableSnapshot:
        raise ValueError('Owned profile capture requires portable v3 history')
    if type(manifest_snapshot) is ValidatedPortableSnapshot:
        previous_inputs = manifest_snapshot.inputs
        # Shared setup/init reader validates actual current bytes and native
        # metadata; replay ownership alone never excludes adopter changes.
        try:
            from .upgrade_contract.v3_public_profile import (
                current_managed_paths as inspect_current_managed_paths, _ProfilePreviewCapture)
        except ImportError:
            from upgrade_contract.v3_public_profile import (
                current_managed_paths as inspect_current_managed_paths, _ProfilePreviewCapture)
        if _profile_capture is None:
            current_managed_paths = inspect_current_managed_paths(
                root, expected_portable=manifest_snapshot,
            )
        elif type(_profile_capture) is _ProfilePreviewCapture:
            current_managed_paths = _profile_capture.current_paths(root, manifest_snapshot)
        else:
            raise ValueError('Exact internally owned profile capture required')
    elif isinstance(manifest_snapshot, ValidatedWindowsProvenance):
        preserved = manifest_snapshot.previous_inputs
        if preserved is None:
            raise ValueError("Windows enrollment has no committed initialization request")
        previous_inputs = preserved
        current_managed_paths = {path.replace('\\', '/') for path in manifest_snapshot.entries}
    elif (
        not isinstance(manifest_snapshot, dict)
        or manifest_snapshot.get("schema")
        != "naos.upgrade.managed_content_manifest_snapshot.v2"
        or not isinstance(manifest_snapshot.get("previous_inputs"), dict)
        or not isinstance(manifest_snapshot.get("entries"), list)
    ):
        raise ValueError("managed preview requires a validated manifest snapshot")
    else:
        previous_inputs = dict(manifest_snapshot["previous_inputs"])
        current_managed_paths = {
            str(entry["path"])
            for entry in manifest_snapshot["entries"]
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        if len(current_managed_paths) != len(manifest_snapshot["entries"]):
            raise ValueError("managed preview path inventory is invalid")
    mode = previous_inputs.get("mode")
    archetype = previous_inputs.get("archetype")
    backend = previous_inputs.get("backend")
    memory_choice = previous_inputs.get("memory_choice")
    if mode not in {"greenfield", "brownfield"}:
        raise ValueError("managed preview has an unsupported initialization mode")
    if not isinstance(archetype, str) or archetype not in ARCHETYPES:
        raise ValueError("managed preview has no supported preserved archetype")
    if not isinstance(backend, str) or backend not in {
        "disabled",
        "static_only",
        "local_ollama",
        "api_provider",
        "ide_agent",
    }:
        raise ValueError("managed preview has no supported preserved backend")
    if memory_choice == "not_selected":
        rendered_memory_choice = None
    elif isinstance(memory_choice, str) and memory_choice in MEMORY_CHOICES:
        rendered_memory_choice = memory_choice
    else:
        raise ValueError("managed preview has no supported preserved memory choice")
    if mode == "brownfield" and not isinstance(
        previous_inputs.get("repository_intelligence"),
        dict,
    ):
        raise ValueError(
            "brownfield managed preview has no repository-intelligence binding"
        )
    signals = detect_signals(root, excluded_paths=current_managed_paths)
    generated = _generate_scaffold_preview(
        project_path=root,
        preview_dir=preview_root,
        signals=signals,
        tier=requested_profile,
        archetype=archetype,
        backend=backend,
        memory_choice=rendered_memory_choice,
        current_managed_paths=current_managed_paths,
        existing_destination=True,
        apply_brownfield_layout_adapter=mode == "brownfield",
        ephemeral_preview=True,
        emit_progress=False,
        collect_source_modes=collect_source_modes,
    )
    # Shared POSIX/Windows profile regeneration refuses before a ready plan;
    # it does not change the generated inventory or approval/check schemas.
    _require_unmanaged_lf_policy(root, generated["lf_policy"])
    effective_inputs = {**previous_inputs, "profile": requested_profile}
    overlay = generated["overlay_compatibility"]
    if not isinstance(overlay, dict):
        raise ValueError("managed preview lacks overlay-compatibility evidence")
    checks = [
        {
            "check_id": "generated_profile_contract",
            "status": "passed",
            "evidence_sha256": generated["profile_contract_sha256"],
        },
        {
            "check_id": "overlay_compatibility",
            "status": "passed" if overlay.get("activation_allowed") else "blocking",
            "evidence_sha256": canonical_sha256(overlay),
        },
    ]
    return {
        **generated,
        "signals": signals,
        "effective_inputs": effective_inputs,
        "checks": checks,
    }


def _run_scaffold_session(
    *,
    args: argparse.Namespace,
    project_path: Path | None,
    signals: dict[str, Any] | None,
    tier: str,
    archetype: str,
    backend: str,
    preview_dir: Path,
    ephemeral_preview: bool = False,
    private_preview_address: PrivatePreviewAddress | None = None,
) -> int:
    """Generate one preview and optionally activate it."""

    print(f"\n  Generating files to: {preview_dir}")
    preview = _generate_scaffold_preview(
        project_path=project_path or Path("."),
        preview_dir=preview_dir,
        signals=signals,
        tier=tier,
        archetype=archetype,
        backend=backend,
        memory_choice=args.memory,
        current_managed_paths=set(
            getattr(args, "_current_managed_paths", set())
        ),
        existing_destination=not args.new and project_path is not None,
        apply_brownfield_layout_adapter=not args.new and project_path is not None,
        ephemeral_preview=ephemeral_preview,
        **({"private_preview_address": private_preview_address}
           if private_preview_address is not None else {}),
        emit_progress=True,
    )
    if private_preview_address is not None:
        preview_dir = Path(private_preview_address.io_root)
    generated = list(preview["generated_files"])
    overlay_compatibility = preview["overlay_compatibility"]
    layout_adapter = preview["layout_adapter"]
    host_lint_boundary = preview["host_lint_boundary"]
    lf_policy = preview["lf_policy"]
    if layout_adapter is not None:
        print(
            "  Applied brownfield tool-layout adapter: "
            f"scripts/ -> {BROWNFIELD_TOOL_ROOT}/"
        )
    if host_lint_boundary is not None:
        print(
            "  Applied managed Ruff discovery markers to generated Python "
            "roots; no pre-existing adopter Ruff file was modified."
        )
    for line in lf_policy_diagnostic_lines(lf_policy):
        print("  " + line)

    print(f"\n  Generated {len(generated)} files:")
    for item in generated[:20]:
        print(f"    {item}")
    if len(generated) > 20:
        print(f"    ... and {len(generated) - 20} more")

    # Dry-run signal + template report.
    if args.dry_run and signals:
        triggered = _signal_triggered_instructions(signals)
        print("\n  ── Signal-Conditional Report (--dry-run) ──")
        print("  Detected signals:")
        bool_signals = [key for key, value in signals.items() if isinstance(value, bool) and value]
        for signal in bool_signals:
            print(f"    ✓ {signal}")
        extra_signals = {
            key: value
            for key, value in signals.items()
            if not isinstance(value, bool) and value and key != "detected_archetype"
        }
        for key, value in extra_signals.items():
            print(f"    ✓ {key}: {value}")
        print()
        if triggered:
            print("  Signal-triggered instructions included:")
            for instruction in sorted(triggered):
                print(f"    + {instruction}")
        else:
            print("  No signal-triggered instructions (only tier base set)")
        print()
        ctx = _make_template_context(
            project_path=project_path or Path("."),
            signals=signals,
            tier=tier,
            archetype=archetype,
        )
        auto_fields = {key: value for key, value in ctx.items() if not value.startswith("[ADAPT:")}
        if auto_fields:
            print("  Auto-populated template fields:")
            for key, value in auto_fields.items():
                print(f"    {key}: {value[:60]}{'...' if len(value) > 60 else ''}")
        print()

    # Activation
    memory_config_outcome = "preview"
    if args.activate:
        dest = project_path or Path(".")
        intelligence_guidance = getattr(
            args,
            "_brownfield_repository_intelligence",
            None,
        )
        if not args.new:
            if not args.dry_run:
                _require_unmanaged_lf_policy(dest, lf_policy)
            _revalidate_brownfield_init_prestart(
                args,
                dest.resolve(strict=False),
                tier=tier,
            )
        print(
            f"\n  {'[DRY-RUN] ' if args.dry_run else ''}Activating to: {dest.resolve()}"
        )
        print(
            "  Existing destinations cause whole-operation refusal; "
            "adopter files are never overwritten."
        )
        if overlay_compatibility and not overlay_compatibility["activation_allowed"]:
            print("  [BLOCKED] HOST COLLECTION COLLISION detected before activation.")
            for finding in overlay_compatibility["findings"]:
                if finding.get("severity") == "blocking":
                    generated_scope = (
                        finding.get("generated_root")
                        or finding.get("generated_path")
                        or ", ".join(finding.get("generated_roots") or [])
                        or "generated Python"
                    )
                    print(
                        f"    - {finding.get('kind')}: {finding.get('consumer')} "
                        f"consumes generated {generated_scope}"
                    )
            if ephemeral_preview:
                print("  The temporary overlay report will be removed when this command exits.")
            else:
                print(f"  Review: {preview_dir / 'naos' / 'overlay_compatibility.json'}")
                print("  Reversible route: generate to an external --preview-dir and do not use --activate.")
            return 3
        before_existing = {
            rel
            for rel in generated
            if (dest / _safe_generated_relpath(rel)).exists()
        }
        managed_inputs: dict[str, Any] = {
            "mode": "greenfield" if args.new else "brownfield",
            "profile": tier,
            "archetype": archetype,
            "backend": backend,
            "memory_choice": args.memory or "not_selected",
        }
        if not args.new:
            prestart_binding = _brownfield_prestart_binding(
                intelligence_guidance
            )
            lifecycle_status = str(
                intelligence_guidance.get("lifecycle_status") or "blocked"
            )
            if prestart_binding is None:
                raise ActivationPreflightRefusal(
                    "brownfield activation requires either a validated-current "
                    "repository-intelligence generation binding or an explicit "
                    "not-applicable determination"
                )
            managed_inputs["repository_intelligence"] = {
                "lifecycle_status": lifecycle_status,
                "recommendation": str(
                    intelligence_guidance.get("recommendation") or ""
                ),
                "binding": prestart_binding,
            }
            if overlay_compatibility is None:
                raise ActivationPreflightRefusal(
                    "brownfield activation lacks a frozen overlay-compatibility decision"
                )
            frozen_managed_paths = set(
                getattr(args, "_current_managed_paths", set())
            )
            frozen_overlay_sha256 = canonical_sha256(overlay_compatibility)

            def revalidate_brownfield_activation_inputs() -> None:
                _require_unmanaged_lf_policy(dest, lf_policy)
                _revalidate_brownfield_init_prestart(
                    args,
                    dest.resolve(strict=False),
                    tier=tier,
                )
                closing_managed_paths = _validated_current_managed_paths(dest)
                if closing_managed_paths != frozen_managed_paths:
                    raise ActivationPreflightRefusal(
                        "managed-content inventory changed before activation"
                    )
                closing_overlay = build_overlay_compatibility_report(
                    dest,
                    preview_dir,
                    generated,
                    excluded_paths=closing_managed_paths,
                    layout_adapter=layout_adapter,
                    host_lint_boundary=host_lint_boundary,
                )
                if ephemeral_preview:
                    closing_overlay["preview_root"] = (
                        "external_ephemeral_preview"
                    )
                if canonical_sha256(closing_overlay) != frozen_overlay_sha256:
                    raise ActivationPreflightRefusal(
                        "host collection, namespace, or layout-adapter evidence "
                        "changed before managed activation"
                    )

            activation_preapply_revalidator = (
                revalidate_brownfield_activation_inputs
            )
        else:
            activation_preapply_revalidator = None
        fixed_checks = [{
            "check_id": "generated_profile_contract", "status": "passed",
            "evidence_sha256": preview["profile_contract_sha256"],
        }]
        if not args.new:
            fixed_checks.append({
                "check_id": "overlay_compatibility", "status": "passed",
                "evidence_sha256": canonical_sha256(overlay_compatibility),
            })
        try:
            activated = activate(
                preview_dir,
                dest,
                dry_run=args.dry_run,
                force=args.force,
                generated_files=generated,
                managed_content=True,
                managed_inputs=managed_inputs,
                greenfield=args.new,
                preapply_revalidator=activation_preapply_revalidator,
                fixed_checks=fixed_checks,
                **({"private_preview_address": private_preview_address}
                   if private_preview_address is not None else {}),
            )
            skipped = sorted(before_existing - set(activated))
            warn_generated_freshness_after_activation(
                skipped,
                force=args.force,
                dry_run=args.dry_run,
            )
            memory_config_rel = "configs/naos_memory.yaml"
            if memory_config_rel in activated:
                memory_config_outcome = "dry_run" if args.dry_run else "activated"
            elif memory_config_rel in before_existing:
                memory_config_outcome = "preserved"
            if not args.dry_run:
                effective_paths = list(lf_policy["text_paths"])
                if lf_policy["status"] == "generated":
                    effective_paths.append(".gitattributes")
                effective = inspect_effective_lf_attributes(dest, effective_paths)
                for line in lf_policy_diagnostic_lines(lf_policy, effective):
                    print("  " + line)
            print_memory_onboarding(tier, args.memory, memory_config_outcome)
        except ActivationPreflightRefusal:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            if args.dry_run:
                raise
            raise ActivationFailure(str(exc)) from exc
        return 0
    else:
        if args.dry_run:
            print("\n  PLAN_ONLY: generated install set evaluated in a temporary preview.")
            print("  The temporary preview will be removed when this command exits.")
            print("  To keep a reviewable preview, rerun without --dry-run and choose a new --preview-dir.")
        else:
            print(f"\n  ✅ Files generated in: {preview_dir}")
            print("  Review them, then run:")
        preferred_naos = _preferred_installed_naos_command()
        activation_cmd = _preferred_installed_init_command()
        if args.new:
            activation_cmd.append(project_path or Path("<new-project-path>"))
            activation_cmd.append("--new")
        else:
            activation_cmd.append(project_path or ".")
        activation_cmd.extend(["--tier", tier])
        activation_cmd.extend(["--archetype", archetype, "--backend", backend])
        if args.memory is not None:
            activation_cmd.extend(["--memory", args.memory])
        activation_cmd.append("--activate")
        if os.name == "nt":
            print("  PowerShell activation command:")
        print("    " + _format_activation_command(activation_cmd))
        print()
        print("  Next steps after activation:")
        print("    1. Edit .github/project-context.md — fill ALL [ADAPT] sections")
        if args.new:
            if tier == "quickstart":
                print(
                    f"    2. Quickstart has no required spec pack; run {preferred_naos} setup-recommendations --profile quickstart before adding specs."
                )
            elif tier == "lite":
                print(
                    "    2. Run /naos-design in your AI assistant to fill profile-required specs/01 → specs/03."
                )
                print(f"       Then run {preferred_naos} spec-pack-contract --profile lite.")
                print(f"       Before planning or coding, run {preferred_naos} spec-pack-contract --profile lite --mode filled.")
                print("       Specs drive technology choices — not the other way around.")
            else:
                print(
                    "    2. Run /naos-design in your AI assistant to fill all profile-required specs/01 → specs/10."
                )
                print(
                    "       For specs 05-09, record project-domain non-applicability inside the file instead of deleting it."
                )
                print(f"       Then run {preferred_naos} spec-pack-contract --profile {tier}.")
                print(
                    f"       Before planning or coding, run {preferred_naos} spec-pack-contract --profile {tier} --mode filled."
                )
                print("       Specs drive technology choices — not the other way around.")
            print("    3. Review Git hook integration:")
            for guidance_line in hook_activation_guidance(project_path or Path.cwd()):
                print("       " + guidance_line)
            print("    4. make -f Makefile.naos naos-readiness  # reports scaffolded or missing prerequisites")
            if backend not in ("disabled", "static_only"):
                print("    5. python scripts/naos_ai_precommit.py --check-config")
                print("    6. make -f Makefile.naos gov-refresh")
            else:
                print("    5. make -f Makefile.naos gov-refresh")
        else:
            print("    2. Review Git hook integration:")
            for guidance_line in hook_activation_guidance(project_path or Path.cwd()):
                print("       " + guidance_line)
            print("    3. make -f Makefile.naos naos-readiness")
            if backend not in ("disabled", "static_only"):
                print("    4. python scripts/naos_ai_precommit.py --check-config")
                print("    5. make -f Makefile.naos gov-refresh")
                conformance_step = 6
            else:
                print("    4. make -f Makefile.naos gov-refresh")
                conformance_step = 5
            print(
                f"    {conformance_step}. make -f Makefile.naos naos-conformance  # static fit check after readiness"
            )

    print_memory_onboarding(tier, args.memory, memory_config_outcome)

    return 0


def hook_activation_guidance(root: Path) -> list[str]:
    """Inspect target Git context without changing hook files or configuration."""
    boundary = "Init generates/copies the hook only; it does not make it executable, configure Git, or execute it."
    # Keep real effective Git config (including HOME/GIT_CONFIG_*), but do not
    # let inherited trace/redirection selectors write outside the target.
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR",
                                          "GIT_INDEX_FILE", "GIT_PAGER", "GIT_FLUSH"}
                   and not key.upper().startswith(("GIT_TRACE", "GIT_REDIRECT_"))}

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *arguments], cwd=root, env=environment,
                              text=True, capture_output=True, check=False, timeout=5)

    try:
        top = git("rev-parse", "--show-toplevel")
        if top.returncode:
            return [boundary, "Target is not a confirmed Git worktree; review hook setup after establishing its Git repository."]
        top_root = Path(top.stdout.strip()).resolve()
        hooks = git("config", "--get", "core.hooksPath")
        if hooks.returncode not in {0, 1}:
            return [boundary, "Effective core.hooksPath could not be read; preserve existing hook integration and inspect Git configuration."]
        description = "Effective core.hooksPath: " + (json.dumps(hooks.stdout.rstrip("\n")) if hooks.returncode == 0 else "unset")
        if top_root != root.resolve():
            return [boundary, "Nested target in Git worktree " + json.dumps(str(top_root)) + ". " + description,
                    "The enclosing repository owns hook configuration; review integration there. No target-relative setup command is offered."]
        if hooks.returncode == 0:
            return [boundary, description + ". Preserve this configuration; review integration with its owner before making a change."]
        worktrees = git("worktree", "list", "--porcelain")
        if worktrees.returncode or sum(line.startswith("worktree ") for line in worktrees.stdout.splitlines()) != 1:
            return [boundary, description + ". Worktree configuration is shared or could not be established; review repository/worktree scope before hook integration."]
        hooks_dir = git("rev-parse", "--git-path", "hooks")
        if hooks_dir.returncode:
            return [boundary, "Default Git hook directory could not be established; preserve existing integration."]
        directory = Path(hooks_dir.stdout.strip())
        if not directory.is_absolute():
            directory = root / directory
        if directory.exists() and any(not item.name.endswith(".sample") for item in directory.iterdir()):
            return [boundary, description + ". Existing default hook entries require reviewed integration; no replacement command is offered."]
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return [boundary, "Git hook context could not be inspected; preserve existing integration and review Git configuration manually."]
    return [boundary, description + ". After activation, review .githooks/pre-commit and recheck Git context before explicitly opting in from this worktree root in a POSIX shell:",
            "chmod +x .githooks/pre-commit && git config --local core.hooksPath .githooks",
            "On Git for Windows, use its bundled Bash and set NAOS_PYTHON to the absolute path of the selected native Python executable (use forward slashes, including when the path contains spaces). This native workflow requires no WSL or global Git configuration change.",
            "Configuration alone does not prove the hook has executed."]


def _canonical_init_target(
    supplied: Path,
    *,
    must_exist: bool,
    allow_existing_resume: bool = False,
) -> Path:
    """Bind an operator-selected target without following its final component."""

    windows = _windows_cli()
    if windows is not None:
        return windows.canonical_target(
            supplied, must_exist=must_exist, allow_existing_resume=allow_existing_resume,
        )
    lexical = Path(os.path.abspath(os.fspath(supplied.expanduser())))
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"project target parent must be an existing directory: {lexical.parent}"
        ) from exc
    parent_metadata = os.lstat(parent)
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        raise ValueError(f"project target parent is unsafe: {parent}")
    target = parent / lexical.name
    try:
        metadata = os.lstat(target)
    except FileNotFoundError:
        if must_exist:
            raise ValueError(
                f"brownfield project target must be an existing directory: {target}"
            )
        return target
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"project target must not be a symbolic link: {target}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"project target must be a directory: {target}")
    if not must_exist:
        if not allow_existing_resume:
            raise ValueError(
                "greenfield project target must be absent; use brownfield mode for an "
                f"existing directory: {target}"
            )
        # This is only an untrusted resume candidate.  Exact parent-bound root
        # intent or validated managed provenance is required inside activate().
        return target
    return target


def main() -> int:
    configure_console_output()
    parser = argparse.ArgumentParser(
        description="NAOS init — Portable Governance Scaffolder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          naos init . --tier quickstart       Generate the bounded Quickstart profile
          naos init .                         Detect project at current dir, run wizard
          naos init . --tier standard --archetype custom --backend static_only
                                               Skip prompts, use standard static-only profile
          naos init . --tier assured --archetype custom --backend static_only
                                               Strongest evidence profile; read docs/ASSURED_PROFILE_ACTIVATION.md
          naos init ./new-project --new       Greenfield preview for an explicit absent target
          naos init . --activate              Generate + activate (copy to project)
          naos init . --activate --dry-run    Preview what would be activated
          naos init ./new-project --new --activate
                                               Create a new project transactionally

        After activation:
          naos setup-recommendations --profile <profile>
          naos add setup-module --list
          naos add setup-module <module_id> --profile <profile> --dry-run
        """),
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        type=Path,
        default=None,
        help="Path to existing project (detection mode). Omit for --new.",
    )
    parser.add_argument(
        "--new",
        action="store_true",
        help="Greenfield mode — scaffold profile-required specs for a new project",
    )
    parser.add_argument(
        "--tier",
        choices=["quickstart", "lite", "standard", "assured"],
        help="Skip tier selection prompt",
    )
    parser.add_argument(
        "--archetype",
        choices=list(ARCHETYPES.keys()),
        help="Skip archetype selection prompt",
    )
    parser.add_argument(
        "--backend",
        choices=[
            "disabled",
            "static_only",
            "local_ollama",
            "api_provider",
            "ide_agent",
            "auto",
            "ollama",
            "agent",
        ],
        default=None,
        help="Optional AI review policy (default: static_only). Legacy: auto/ollama/agent.",
    )
    parser.add_argument(
        "--activate",
        action="store_true",
        help="Copy generated files to project directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview from an external temporary tree without changing project files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Legacy option; refused because blanket overwrite cannot prove ownership",
    )
    parser.add_argument(
        "--preview-dir",
        type=Path,
        default=None,
        help=(
            "Absent persistent preview path: target/.naos-preview or outside the "
            "target; incompatible with --dry-run"
        ),
    )
    parser.add_argument(
        "--memory",
        choices=MEMORY_CHOICES,
        default=None,
        help="Memory onboarding choice: later, check, centralized, local, or disabled. No binaries or remotes are installed.",
    )

    args = parser.parse_args()
    if args.dry_run and args.preview_dir is not None:
        print(
            "NOT_APPLIED: --dry-run and --preview-dir are incompatible; "
            "omit --preview-dir, or omit --dry-run to keep a reviewable preview.",
            file=sys.stderr,
        )
        return 2

    # Determine project path
    project_path = args.project_path
    if project_path is None and not args.new:
        # Default to current directory if neither arg given
        project_path = Path(".")
    if args.force:
        print(
            "NOT_APPLIED: legacy blanket --force is refused. It cannot establish "
            "ownership of existing content and is incompatible with greenfield creation.",
            file=sys.stderr,
        )
        return 2
    if args.new and args.activate and project_path is None:
        print(
            "NOT_APPLIED: greenfield activation requires an explicit absent project "
            "path; for example, naos init ./new-project --new --activate.",
            file=sys.stderr,
        )
        return 2
    try:
        if project_path is not None:
            project_path = _canonical_init_target(
                project_path,
                must_exist=not args.new,
                allow_existing_resume=args.new and args.activate,
            )
    except (OSError, ValueError) as exc:
        print(f"NOT_APPLIED: {exc}", file=sys.stderr)
        return 2

    print_banner()

    # Managed v3 must route before legacy provenance, scan exclusions, or fresh
    # scaffold generation, including an attempted --new resume.
    classification_path = project_path if project_path is not None else Path.cwd()
    if classification_path.is_dir():
        try:
            try:
                from .upgrade_contract.v3_recovery import has_v3_control
            except ImportError:
                from upgrade_contract.v3_recovery import has_v3_control
            if has_v3_control(classification_path):
                if args.new:
                    print("NOT_APPLIED: --new cannot enroll an existing managed v3 project; "
                          "use managed init review without --new.", file=sys.stderr)
                    return 2
                return _route_managed_init_transition(
                    args, classification_path, requested_profile=args.tier or wizard_tier(),
                )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"NOT_APPLIED: managed v3 init review requires validated completed "
                  f"same-root history; explicit rebind or recovery may be required: {exc}",
                  file=sys.stderr)
            return 3

    # Detection mode: analyse existing project
    signals: dict | None = None
    detected_archetype = None
    current_managed_paths: set[str] = set()
    if args.new:
        # Greenfield mode — scaffold profile-required specs; tech stack unknown until /naos-design
        print("  Mode: Greenfield (--new)")
        print("  Scaffolding profile-required specs and governance structure.")
        print()
        print("  Next step: confirm the profile, then follow the profile-specific design instructions after generation.")
        print("  Where specs are present, they drive technology choices — not the other way around.")
        print()
        signals = _empty_signals()
        detected_archetype = None
    elif project_path:
        print(f"  Analysing project: {project_path.resolve()}")
        try:
            current_managed_paths = _validated_current_managed_paths(project_path)
        except (OSError, ProvenanceError, TransactionPrimitiveError, ValueError) as exc:
            print(
                "NOT_APPLIED: managed-content state is invalid or incomplete; "
                f"the project was preserved: {exc}",
                file=sys.stderr,
            )
            return 4
        setattr(args, "_current_managed_paths", current_managed_paths)
        signals = detect_signals(
            project_path,
            excluded_paths=current_managed_paths,
        )
        detected_archetype = signals.get("detected_archetype")
        if detected_archetype:
            lang = ARCHETYPES.get(detected_archetype, {}).get(
                "label", detected_archetype
            )
            print(f"  Candidate archetype from repository signals: {lang}")
        else:
            print("  Could not auto-detect archetype — you'll be asked to select one")

    # Tier selection
    tier = args.tier
    if not tier:
        tier = wizard_tier()
    else:
        print(f"  Profile tier: {tier}")
        print(f"  {PROFILES[tier]['description']}\n")

    if not args.new and project_path is not None:
        try:
            routed = _route_managed_init_transition(
                args,
                project_path,
                requested_profile=tier,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                f"NOT_APPLIED: managed init transition preflight failed: {exc}",
                file=sys.stderr,
            )
            return 3
        if routed is not None:
            return routed

    # Archetype selection (quickstart skips — no archetype-specific overrides)
    if tier == "quickstart":
        archetype = args.archetype or detected_archetype or "custom"
        backend = LEGACY_BACKEND_ALIASES.get(
            args.backend or "disabled", args.backend or "disabled"
        )
        print(f"  Archetype: {archetype} (quickstart — no archetype-specific files)")
        if backend == "disabled":
            print("  AI review policy: disabled (quickstart uses structural governance only)")
        else:
            print(
                "  AI review policy: disabled in quickstart; retained transition "
                f"choice: {backend} (not activated by this profile)"
            )
    else:
        archetype = args.archetype or detected_archetype
        if not archetype:
            archetype = wizard_archetype()
        else:
            label = ARCHETYPES.get(archetype, {}).get("label", archetype)
            print(f"  Archetype: {label}")

        # Backend selection
        backend = LEGACY_BACKEND_ALIASES.get(args.backend, args.backend)
        if backend is None:
            backend = wizard_backend()
        print(f"  AI review policy: {backend}")

    project_root = project_path or Path.cwd().resolve(strict=True)
    if args.activate and not args.new and project_root.is_dir():
        try:
            intelligence_guidance = _brownfield_repository_intelligence_guidance(
                project_root,
                tier=tier,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                f"NOT_APPLIED: repository-intelligence pre-start failed: {exc}",
                file=sys.stderr,
            )
            return 4
        lifecycle_status = str(
            intelligence_guidance.get("lifecycle_status") or "blocked"
        )
        recommendation = str(
            intelligence_guidance.get("recommendation") or "blocked_prerequisite"
        )
        print(
            "  Repository intelligence pre-start: "
            f"{lifecycle_status} ({recommendation})"
        )
        if not intelligence_guidance.get("continuation_allowed"):
            next_action = str(
                (intelligence_guidance.get("installation") or {}).get(
                    "next_action"
                )
                or "Resolve repository-intelligence pre-start requirements."
            )
            print(f"NOT_APPLIED: {next_action}", file=sys.stderr)
            return 4
        setattr(args, "_brownfield_repository_intelligence", intelligence_guidance)

    session_kwargs = {
        "args": args,
        "project_path": project_path,
        "signals": signals,
        "tier": tier,
        "archetype": archetype,
        "backend": backend,
    }

    use_ephemeral_preview = args.dry_run or (
        args.activate and args.preview_dir is None
    )
    if use_ephemeral_preview:
        temp_root = _select_external_temp_root(project_root)
        if temp_root is None:
            print(
                "NOT_APPLIED: no existing external temporary preview root is available; "
                "set TMPDIR to a directory outside the project and retry.",
                file=sys.stderr,
            )
            return 3
        if args.dry_run:
            print("  PLAN_ONLY: using an external temporary preview; project files will not be changed.")
        else:
            print("  Using external temporary staging; any persistent review preview is left unchanged.")
        result: int | None = None
        operation_error: OSError | RuntimeError | ValueError | None = None
        cleanup_error: OSError | RuntimeError | ValueError | None = None
        try:
            temporary_preview = create_temporary_preview(
                prefix="naos-init-preview-",
                parent=temp_root,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            operation_error = exc
            temporary_preview = None
        if temporary_preview is not None:
            try:
                result = _run_scaffold_session(
                    **session_kwargs,
                    preview_dir=Path(temporary_preview.name) / "preview",
                    ephemeral_preview=True,
                    **({"private_preview_address": temporary_preview.preview_address}
                       if hasattr(temporary_preview, "preview_address") else {}),
                )
            except (ActivationFailure, OSError, RuntimeError, ValueError) as exc:
                operation_error = exc
            finally:
                try:
                    temporary_preview.cleanup()
                except (OSError, RuntimeError, ValueError) as exc:
                    cleanup_error = exc

        if isinstance(operation_error, ActivationPreflightRefusal):
            cleanup_detail = (
                f" Temporary staging cleanup also failed: {cleanup_error}."
                if cleanup_error is not None
                else ""
            )
            print(
                "NOT_APPLIED: activation preflight refused before target mutation; "
                f"the target is unchanged: {operation_error}.{cleanup_detail}",
                file=sys.stderr,
            )
            return 3
        if isinstance(operation_error, ActivationFailure):
            cleanup_detail = (
                f" Temporary staging cleanup also failed: {cleanup_error}."
                if cleanup_error is not None
                else ""
            )
            print(
                "ACTIVATION_FAILED: the target may be partially changed; inspect the "
                f"command output and project before retrying: {operation_error}."
                f"{cleanup_detail}",
                file=sys.stderr,
            )
            return 3
        if operation_error is not None:
            cleanup_detail = (
                f" Temporary staging cleanup also failed: {cleanup_error}."
                if cleanup_error is not None
                else ""
            )
            if args.dry_run:
                print(
                    "NOT_APPLIED: temporary staging failed; project files are unchanged: "
                    f"{operation_error}.{cleanup_detail}",
                    file=sys.stderr,
                )
            else:
                print(
                    "NOT_APPLIED: activation staging failed before target mutation; "
                    f"the target is unchanged: {operation_error}.{cleanup_detail}",
                    file=sys.stderr,
                )
            return 3
        if cleanup_error is not None:
            if args.dry_run or result != 0:
                print(
                    "NOT_APPLIED: the target is unchanged, but temporary staging cleanup "
                    f"failed: {cleanup_error}",
                    file=sys.stderr,
                )
            else:
                print(
                    "CLEANUP_FAILED: activation completed, but temporary staging could "
                    f"not be removed; inspect the target and temporary root: {cleanup_error}",
                    file=sys.stderr,
                )
            return 3
        if args.dry_run:
            print("  PLAN_ONLY: temporary preview removed; project files were not changed.")
        else:
            print("  Temporary activation staging removed; persistent review previews were not changed.")
        return result

    if args.preview_dir is not None:
        preview_dir = args.preview_dir
    elif project_path:
        preview_dir = project_path / ".naos-preview"
    else:
        preview_dir = Path(".naos-preview")
    try:
        return _run_scaffold_session(
            **session_kwargs,
            preview_dir=preview_dir,
        )
    except ExistingPreviewRefusal as exc:
        print(
            "NOT_APPLIED: the existing preview was preserved; choose a new absent "
            f"--preview-dir: {exc}",
            file=sys.stderr,
        )
        return 3
    except UnsupportedPreviewLocation as exc:
        print(
            f"NOT_APPLIED: unsupported persistent preview location; target unchanged: {exc}",
            file=sys.stderr,
        )
        return 3
    except ActivationPreflightRefusal as exc:
        print(
            "NOT_APPLIED: activation preflight refused before any activation "
            "destination was changed. The persistent preview remains available "
            "at its requested path and may be inside the target; review it before "
            f"retrying: {exc}",
            file=sys.stderr,
        )
        return 3
    except ActivationFailure as exc:
        print(
            "ACTIVATION_FAILED: the target may be partially changed; inspect the "
            f"command output, project, and persistent preview before retrying: {exc}",
            file=sys.stderr,
        )
        return 3
    except (OSError, RuntimeError, ValueError) as exc:
        if args.activate:
            print(
                "PREVIEW_FAILED: activation did not begin and no activation destination "
                "was changed; the persistent preview may be partial and may be inside "
                "the target, so inspect it and remove it only if you own it, or choose "
                f"a new absent path: {exc}",
                file=sys.stderr,
            )
        else:
            print(
                "PREVIEW_FAILED: the persistent preview may be partial; inspect and "
                f"remove it, or choose a new path, before retrying: {exc}",
                file=sys.stderr,
            )
        return 3


if __name__ == "__main__":
    sys.exit(main())
