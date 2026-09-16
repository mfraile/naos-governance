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
import json
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Callable, NoReturn

import yaml

try:
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
        finalize_greenfield_root,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from .upgrade_contract.security import source_metadata_contract
    from .upgrade_contract.transaction import (
        TransactionPrimitiveError,
        apply_create_only_plan,
        current_managed_content_paths,
        managed_content_sources_current,
        recover_create_only_transactions,
    )
    from .scripts.naos_emit_capabilities import (
        emit_catalogue,
        render_catalogue,
        write_catalogue,
    )
except ImportError:  # Direct checkout execution: python naos_init.py ...
    _KIT_IMPORT_ROOT = Path(__file__).resolve().parent
    if str(_KIT_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_KIT_IMPORT_ROOT))
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
        finalize_greenfield_root,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from upgrade_contract.security import (  # type: ignore[no-redef]
        source_metadata_contract,
    )
    from upgrade_contract.transaction import (  # type: ignore[no-redef]
        TransactionPrimitiveError,
        apply_create_only_plan,
        current_managed_content_paths,
        managed_content_sources_current,
        recover_create_only_transactions,
    )
    from scripts.naos_emit_capabilities import (  # type: ignore[no-redef]
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
    return [sys.executable, Path(__file__).name]


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
    Uses string.Template.safe_substitute() — unknown $xxx markers are left intact.
    Files modified in-place within preview_dir.
    """
    from string import Template

    target_files = ("project-context.md", "CLAUDE.md", "copilot-instructions.md")
    for tpl_name in target_files:
        tpl_path = preview_dir / tpl_name
        if not tpl_path.exists():
            continue
        content = tpl_path.read_text(errors="replace")
        populated = Template(content).safe_substitute(ctx)
        tpl_path.write_text(populated)


def _copy_generated_script(src: Path, dest: Path) -> None:
    shutil.copy2(src, dest)
    if dest.suffix != ".py":
        return

    text = dest.read_text(encoding="utf-8")
    if "# AUTO-GENERATED" in text[:2048]:
        return

    marker = "# AUTO-GENERATED: Copied by naos init from the NAOS kit.\n"
    if text.startswith("#!"):
        first_line, _, rest = text.partition("\n")
        dest.write_text(f"{first_line}\n{marker}{rest}", encoding="utf-8")
    else:
        dest.write_text(f"{marker}{text}", encoding="utf-8")


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


def prepare_preview_dir(preview_dir: Path, project_path: Path) -> None:
    try:
        preview_metadata = preview_dir.lstat()
    except FileNotFoundError:
        preview_metadata = None
    if preview_metadata is not None and preview_dir.is_symlink():
        raise ExistingPreviewRefusal(
            "Preview path is an existing symbolic link; refusing to replace content "
            f"without provenance: {preview_dir}"
        )

    preview_resolved = preview_dir.resolve(strict=False)
    project_resolved = project_path.resolve(strict=False)
    if preview_resolved == project_resolved or _is_within(project_resolved, preview_resolved):
        raise UnsupportedPreviewLocation(
            f"Preview directory must not be the project root or contain it: {preview_dir}"
        )
    preview_is_inside_project = _is_within(
        preview_resolved,
        project_resolved,
    ) or _is_same_or_descendant_by_identity(
        preview_resolved,
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
        preview_dir.mkdir(parents=True, exist_ok=False)
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
        raise ActivationPreflightRefusal(
            "repository intelligence changed before activation; " + action
        )
    opening_binding = _brownfield_prestart_binding(opening)
    closing_binding = _brownfield_prestart_binding(closing)
    if opening_binding != closing_binding:
        raise ActivationPreflightRefusal(
            "repository-intelligence lifecycle or immutable generation binding changed before activation"
        )


def _validated_current_managed_paths(project_path: Path) -> set[str]:
    """Return only provenance-validated, byte/metadata-current managed paths."""

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
        args.activate
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
        return upgrade_module.plan_profile_transition(
            project_path,
            requested_profile=requested_profile,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            f"NOT_APPLIED: managed init transition planning failed: {exc}",
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

    first_level = True
    for current_root, directory_names, file_names in os.walk(
        project_path,
        topdown=True,
        followlinks=False,
    ):
        directory_names.sort()
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
) -> bool:
    """Check if pattern appears in any file matching globs (capped at 200 files)."""
    checked = 0
    for glob in globs:
        for f in _iter_detection_paths(
            project_path,
            glob,
            excluded_paths=excluded_paths,
        ):
            if ".git" in str(f) or "venv" in str(f) or "node_modules" in str(f):
                continue
            try:
                if pattern in f.read_text(errors="replace"):
                    return True
            except Exception:
                pass
            checked += 1
            if checked > 200:
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
) -> bool:
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
        shutil.copy2(source, destination)
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
    destination.write_text(content, encoding="utf-8")


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
    destination.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


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
    destination.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def scaffold_files(
    project_path: Path,
    tier: str,
    archetype: str | None,
    backend: str,
    preview_dir: Path,
    signals: dict | None = None,
    memory_choice: str | None = None,
    emit_progress: bool = True,
) -> list[str]:
    """
    Generate governance files into preview_dir.
    Returns list of files generated.

    Security: writes ONLY to preview_dir — never modifies project_path directly.
    Activation (copy to project_path) requires separate --activate call.
    """
    generated: list[str] = []
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
                shutil.copy2(tpl, dest)
                generated.append(str(dest.relative_to(preview_dir)))

    # 1b. Auto-populate instruction-triple templates from detected signals.
    if signals:
        template_ctx = _make_template_context(
            project_path=project_path,
            signals=signals,
            tier=tier,
            archetype=archetype,
        )
        _populate_templates(preview_dir, template_ctx)

    # 2. Rules Chain
    rules_src = TEMPLATES_DIR / "rules-chain"
    if rules_src.is_dir():
        for tpl in rules_src.rglob("*"):
            if tpl.is_file():
                rel = tpl.relative_to(rules_src)
                dest = preview_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tpl, dest)
                generated.append(str(rel))

    # 3. RULES.md from selected profile
    profile_rules = validated_profile_rules_path(tier)
    dest = preview_dir / ".ai" / "RULES.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(profile_rules, dest)
    generated.append(".ai/RULES.md")

    # 4. Cursor rules (lite+ only — skip for quickstart)
    cursor_src = TEMPLATES_DIR / "cursor-rules"
    if cursor_src.is_dir() and tier != "quickstart":
        cursor_dest = preview_dir / ".cursor" / "rules"
        cursor_dest.mkdir(parents=True, exist_ok=True)
        for mdc in cursor_src.iterdir():
            if mdc.is_file():
                shutil.copy2(mdc, cursor_dest / mdc.name)
                generated.append(f".cursor/rules/{mdc.name}")

    # 5. Makefile.naos
    makefile_src = TEMPLATES_DIR / "Makefile.naos"
    if makefile_src.exists():
        shutil.copy2(makefile_src, preview_dir / "Makefile.naos")
        generated.append("Makefile.naos")

    # 5a. Profile generated-surface contract (all profiles, including quickstart).
    if PROFILE_SURFACE_CONTRACT_PATH.is_file():
        contract_dest = preview_dir / "naos" / "profile_generated_surface_contract.json"
        contract_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROFILE_SURFACE_CONTRACT_PATH, contract_dest)
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
                shutil.copy2(contract_schema_src, contract_schema_dest)
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
                shutil.copy2(seed, dest)
                generated.append(str(rel))

    _apply_memory_choice_to_preview(preview_dir, generated, memory_choice)
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
            shutil.copy2(policy_src, dest)
            _persist_generated_policy_profile(dest, tier)
            generated.append("naos/policy/default_policy.yaml")

        register_src = KIT_DIR / "configs" / "secure_coding_control_register.yaml"
        if register_src.is_file():
            dest = preview_dir / "naos" / "secure_coding_control_register.yaml"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(register_src, dest)
            generated.append("naos/secure_coding_control_register.yaml")

        if CAPABILITIES_DIR.is_dir():
            cap_dest = preview_dir / "naos" / "capabilities"
            cap_dest.mkdir(parents=True, exist_ok=True)
            for cap_file in sorted(CAPABILITIES_DIR.glob("*.yaml")):
                if tier == "lite" and cap_file.name == "ai_component_inventory.yaml":
                    continue
                shutil.copy2(cap_file, cap_dest / cap_file.name)
                generated.append(f"naos/capabilities/{cap_file.name}")

        schema_src = KIT_DIR / "schemas" / "naos"
        adopter_schema_names = {
            "calibration_shadow.schema.json",
            "calibration_shadow_report.schema.json",
            "evidence_classification_policy.schema.json",
            "evidence_classification_report.schema.json",
            "gate_status.schema.json",
            "gate_evaluation.schema.json",
            "gatekeeper.schema.json",
            "gate_input_error.schema.json",
            "agent_trace_event.schema.json",
            "evidence_attestation.schema.json",
            "evidence_envelope.schema.json",
            "evidence_verification.schema.json",
            "claims_validation.schema.json",
            "capability_maturity_report.schema.json",
            "evidence_pack.schema.json",
            "dashboard_summary.schema.json",
            "ai_surface_context_budget.schema.json",
            "ai_surface_profile_footprint_baseline.schema.json",
            "cross_harness_review_readiness.schema.json",
            "cross_harness_review_readiness_report.schema.json",
            "duplicate_function_hygiene.schema.json",
            "secret_hygiene.schema.json",
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
                shutil.copy2(schema_file, schema_dest / schema_file.name)
                generated.append(f"schemas/naos/{schema_file.name}")

    # 6b. Public evidence docs used by admissibility-pack (all tiers)
    evidence_docs = {
        "ADMISSIBILITY.md",
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
            shutil.copy2(doc_src, dest)
            generated.append(f"docs/{doc_name}")

    # 7. Archetype-specific project-context.md (override generic template — lite+ only)
    if archetype and archetype != "custom" and tier != "quickstart":
        archetype_ctx = ARCHETYPES_DIR / archetype / "project-context.md"
        if archetype_ctx.exists():
            dest = preview_dir / ".github" / "project-context.md"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archetype_ctx, dest)
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
            shutil.copy2(spec_file, specs_dest / spec_file.name)
            generated.append(f"specs/{spec_file.name}")
        template_specs_dest = preview_dir / "naos" / "spec_templates" / "spec-kit" / "specs"
        template_specs_dest.mkdir(parents=True, exist_ok=True)
        for spec_file in sorted(spec_src.iterdir()):
            if not spec_file.is_file():
                continue
            shutil.copy2(spec_file, template_specs_dest / spec_file.name)
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
            shutil.copy2(agent_file, agents_dest / agent_file.name)
            generated.append(f".github/agents/{agent_file.name}")

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
            shutil.copy2(prompt_file, prompts_dest / prompt_file.name)
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
            shutil.copytree(
                skill_dir,
                dest_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".DS_Store"),
            )
            generated.append(f".github/skills/{skill_dir.name}/SKILL.md")

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
            shutil.copy2(instr_file, instructions_dest / instr_file.name)
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
            shutil.copy2(wf_file, dest)
            if wf_file.name == "naos-control-plane-ci.yml":
                content = dest.read_text(encoding="utf-8")
                content = re.sub(
                    r"NAOS_PROFILE: lite",
                    f"NAOS_PROFILE: {tier}",
                    content,
                )
                dest.write_text(content, encoding="utf-8")
            generated.append(f".github/workflows/{wf_file.name}")

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
                shutil.copy2(ar_file, dest)
                generated.append(f".github/autoresearch/{rel}")
        battery_src = KIT_DIR / "task_battery"
        battery_dest = autores_dest / "task_battery"
        if battery_src.is_dir():
            battery_dest.mkdir(parents=True, exist_ok=True)
            for bat_file in battery_src.iterdir():
                if bat_file.is_file() and bat_file.name != "d4_grader_scenarios.yaml":
                    shutil.copy2(bat_file, battery_dest / bat_file.name)
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
            shutil.copy2(init_src, init_dest)
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
                shutil.copy2(grader_file, dest)
                generated.append(f".github/autoresearch/graders/{rel}")

    # 8h. Instincts + profiles (tier-conditional):
    #     quickstart → no reference profiles  |  lite+ → every reference profile preset + schema
    instincts_src = TEMPLATES_DIR / "instincts"
    profiles_src = TEMPLATES_DIR / "profiles"
    if profiles_src.is_dir() and tier != "quickstart":
        profiles_dest = preview_dir / ".github" / "profiles"
        profiles_dest.mkdir(parents=True, exist_ok=True)
        for pf_file in sorted(profiles_src.iterdir()):
            if pf_file.is_file():
                shutil.copy2(pf_file, profiles_dest / pf_file.name)
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
            shutil.copy2(ins_file, instincts_dest / ins_file.name)
            generated.append(f".github/instincts/{ins_file.name}")

    # 9a. Patch AI policy in naos_ai_precommit.yaml
    precommit_yaml = preview_dir / "configs" / "naos_ai_precommit.yaml"
    if precommit_yaml.exists():
        content = precommit_yaml.read_text()
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
        precommit_yaml.write_text(content)

    # 9b. Patch NAOS_TIER default in pre-commit hook to match selected tier
    precommit_hook = preview_dir / ".githooks" / "pre-commit"
    if precommit_hook.exists():
        content = precommit_hook.read_text()
        content = re.sub(
            r'NAOS_TIER="\$\{NAOS_TIER:-lite\}"',
            f'NAOS_TIER="${{NAOS_TIER:-{tier}}}"',
            content,
        )
        precommit_hook.write_text(content)

    # 9c. Patch Makefile.naos default profile to match selected tier
    makefile = preview_dir / "Makefile.naos"
    if makefile.exists():
        content = makefile.read_text()
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
        makefile.write_text(content)

    # 10. Automation scripts (tier-conditional)
    #     quickstart → none  |  lite → 5 core scripts  |  standard/assured → all
    scripts_src = KIT_DIR / "scripts"
    if scripts_src.is_dir() and tier != "quickstart":
        # Core scripts always go to scripts/ (non-workflow)
        lite_scripts = {
            "naos_validate_truth.py",
            "naos_validate_task_registry.py",
            "naos_readiness.py",
            "naos_ai_precommit.py",
            "naos_policy.py",
            "source_roots.py",
            "spec_header.py",
            "naos_schema_validation.py",
            "naos_adoption_common.py",
            "naos_hygiene_common.py",
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
            "naos_task_lifecycle.py",
            "naos_research_record.py",
            "naos_composed_traceability.py",
            "naos_task_claims.py",
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

        for script_file in scripts_src.iterdir():
            if not script_file.is_file():
                continue
            # These runtimes remain installed/package or source-kit commands.
            # Their opt-in assets are project-local, but the executables are not
            # copied into every adopter repository by default.
            if script_file.name in {
                "naos_repository_intelligence.py",
                "naos_agent_orchestration_plan.py",
                "naos_agent_sponsor_registry.py",
                "naos_aivss_arithmetic_verification.py",
                "naos_public_export.py",
            }:
                continue
            if tier == "lite" and script_file.name not in lite_scripts:
                continue
            dest = preview_dir / "scripts" / script_file.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            _copy_generated_script(script_file, dest)
            generated.append(f"scripts/{script_file.name}")

        workflows_src = scripts_src / "workflows"
        if workflows_src.is_dir():
            for wf_file in workflows_src.iterdir():
                if not wf_file.is_file():
                    continue
                if tier == "lite" and wf_file.name not in lite_workflows:
                    continue
                dest = preview_dir / "scripts" / "workflows" / wf_file.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                _copy_generated_script(wf_file, dest)
                generated.append(f"scripts/workflows/{wf_file.name}")

        # Validators (standard/assured only).
        validators_src = scripts_src / "validators"
        if validators_src.is_dir() and tier in ("standard", "assured"):
            for val_file in validators_src.rglob("*"):
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
                _copy_generated_script(val_file, dest)
                generated.append(f"scripts/validators/{rel}")

    capability_emitter = preview_dir / "scripts" / "naos_emit_capabilities.py"
    if tier in ("standard", "assured") and capability_emitter.is_file():
        catalogue = emit_catalogue(preview_dir)
        write_catalogue(
            preview_dir / "configs" / "naos_ai_surface_catalogue.yaml",
            render_catalogue(catalogue),
        )
        generated.append("configs/naos_ai_surface_catalogue.yaml")

    return generated


def _guard_activation_destination(
    project_root: Path,
    rel: Path,
    *,
    reject_multiply_linked_file: bool,
) -> tuple[Path, tuple[int, int, int, int] | None]:
    """Validate one target path without following project descendants."""

    destination = project_root / rel
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


def _activate_managed_content(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    request_inputs: dict[str, Any],
    dry_run: bool,
    greenfield: bool,
    preapply_revalidator: Callable[[], None] | None = None,
) -> list[str]:
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
) -> list[str]:
    """Activate generated files only through the managed create-only path."""
    if generated_files is None:
        rels = [src.relative_to(preview_dir) for src in preview_dir.rglob("*") if src.is_file() and not src.is_symlink()]
    else:
        rels = [_safe_generated_relpath(item) for item in generated_files]
    if greenfield:
        lexical_root = Path(os.path.abspath(os.fspath(project_path)))
        project_root = lexical_root.parent.resolve(strict=True) / lexical_root.name
    else:
        project_root = project_path.resolve(strict=False)
    activation_plan: list[
        tuple[Path, Path, Path, tuple[int, int, int, int] | None]
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
    if workflow_root.is_dir():
        candidates.extend(sorted(workflow_root.glob("*.yml")))
        candidates.extend(sorted(workflow_root.glob("*.yaml")))

    consumers: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for path in candidates:
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
    return consumers


def build_overlay_compatibility_report(
    project_path: Path,
    preview_dir: Path,
    generated_files: list[str],
    *,
    excluded_paths: set[str] | None = None,
    layout_adapter: dict[str, Any] | None = None,
    host_lint_boundary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Detect deterministic host collection overlap before activation.

    This intentionally reports only observable path/glob consumption. It does
    not guess whether host tests are semantically compatible with NAOS code.
    """

    project_path = project_path.resolve(strict=False)
    excluded = excluded_paths or set()
    generated_python = sorted(
        str(_safe_generated_relpath(item))
        for item in generated_files
        if str(item).endswith(".py")
    )
    prospective_setup_python: list[str] = []
    setup_catalog = preview_dir / "naos/setup_module_catalog.yaml"
    if setup_catalog.is_file() and not setup_catalog.is_symlink():
        catalog = yaml.safe_load(setup_catalog.read_text(encoding="utf-8")) or {}
        for module in catalog.get("modules") or []:
            if not isinstance(module, dict):
                continue
            for action in module.get("install_actions") or []:
                if not isinstance(action, dict):
                    continue
                destination = str(action.get("destination") or "")
                if destination.endswith(".py"):
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

    ruff_consumers = _ruff_root_scan_consumers(project_path, excluded)
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
            continue
        path = project_path / name
        if path.is_file() and path.stat().st_size <= 2_000_000:
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
    test_files = (
        sorted(
            path
            for path in tests_dir.rglob("*.py")
            if path.relative_to(project_path).as_posix() not in excluded
        )
        if tests_dir.is_dir()
        else []
    )
    for test_file in test_files:
        try:
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
    without inferring ownership. Every exact generated path reference is
    rewritten before the managed-content plan is built.
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
    reference_rewrite_count = 0
    for relative in rewritten:
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
        if relative in {
            "Makefile.naos",
            ".githooks/pre-commit",
            ".github/workflows/naos-control-plane-ci.yml",
            "naos/setup_module_catalog.yaml",
        }:
            updated = updated.replace("scripts/", f"{BROWNFIELD_TOOL_ROOT}/")
        if updated != original:
            path.write_text(updated, encoding="utf-8")
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
        config_path.write_text(BROWNFIELD_RUFF_BOUNDARY, encoding="utf-8")
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
) -> dict[str, Any]:
    """Generate one deterministic preview using the canonical init pipeline."""

    prepare_preview_dir(preview_dir, project_path)
    generated = scaffold_files(
        project_path=project_path,
        tier=tier,
        archetype=archetype,
        backend=backend,
        preview_dir=preview_dir,
        signals=signals,
        memory_choice=memory_choice,
        emit_progress=emit_progress,
    )
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
        )
        overlay_compatibility = build_overlay_compatibility_report(
            project_path,
            preview_dir,
            generated,
            excluded_paths=current_managed_paths,
            layout_adapter=layout_adapter,
            host_lint_boundary=host_lint_boundary,
        )
        if ephemeral_preview:
            overlay_compatibility["preview_root"] = "external_ephemeral_preview"
        overlay_report_path = preview_dir / "naos" / "overlay_compatibility.json"
        overlay_report_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_report_path.write_text(
            json.dumps(overlay_compatibility, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        overlay_report_rel = "naos/overlay_compatibility.json"
        if overlay_report_rel not in generated:
            generated.append(overlay_report_rel)

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
    return {
        "generated_files": generated_files,
        "sources": tuple(
            (Path(relative_text), preview_dir / relative_text)
            for relative_text in generated_files
        ),
        "overlay_compatibility": overlay_compatibility,
        "layout_adapter": layout_adapter,
        "host_lint_boundary": host_lint_boundary,
        "profile_contract_sha256": canonical_sha256(profile_contract),
    }


def regenerate_managed_init_preview(
    project_root: Path,
    preview_root: Path,
    *,
    manifest_snapshot: dict[str, Any],
    requested_profile: str,
) -> dict[str, Any]:
    """Regenerate exact managed init sources without writing the adopter project."""

    root = project_root.resolve(strict=True)
    if requested_profile not in PROFILES:
        raise ValueError(f"unsupported requested profile: {requested_profile}")
    if (
        not isinstance(manifest_snapshot, dict)
        or manifest_snapshot.get("schema")
        != "naos.upgrade.managed_content_manifest_snapshot.v2"
        or not isinstance(manifest_snapshot.get("previous_inputs"), dict)
        or not isinstance(manifest_snapshot.get("entries"), list)
    ):
        raise ValueError("managed preview requires a validated manifest snapshot")
    previous_inputs = dict(manifest_snapshot["previous_inputs"])
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
    current_managed_paths = {
        str(entry["path"])
        for entry in manifest_snapshot["entries"]
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    if len(current_managed_paths) != len(manifest_snapshot["entries"]):
        raise ValueError("managed preview path inventory is invalid")
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
    )
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
        emit_progress=True,
    )
    generated = list(preview["generated_files"])
    overlay_compatibility = preview["overlay_compatibility"]
    layout_adapter = preview["layout_adapter"]
    host_lint_boundary = preview["host_lint_boundary"]
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
        print("    " + " ".join(shlex.quote(str(part)) for part in activation_cmd))
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
            print(
                "    3. chmod +x .githooks/pre-commit && git config core.hooksPath .githooks"
            )
            print("    4. make -f Makefile.naos naos-readiness  # reports scaffolded or missing prerequisites")
            if backend not in ("disabled", "static_only"):
                print("    5. python scripts/naos_ai_precommit.py --check-config")
                print("    6. make -f Makefile.naos gov-refresh")
            else:
                print("    5. make -f Makefile.naos gov-refresh")
        else:
            print(
                "    2. chmod +x .githooks/pre-commit && git config core.hooksPath .githooks"
            )
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


def _canonical_init_target(
    supplied: Path,
    *,
    must_exist: bool,
    allow_existing_resume: bool = False,
) -> Path:
    """Bind an operator-selected target without following its final component."""

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
            print(f"  Detected archetype: {lang}")
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
            temporary_preview = tempfile.TemporaryDirectory(
                prefix="naos-init-preview-",
                dir=temp_root,
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
