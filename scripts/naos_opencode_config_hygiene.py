#!/usr/bin/env python3
"""Review optional repo-local OpenCode configuration hygiene.

This command is deterministic local review evidence only. It does not create
OpenCode files, inspect global user configuration, run OpenCode, activate MCP
or memory tools, call providers or models, validate credentials, mutate IDE or
tool settings, approve work, certify outcomes, or prove compliance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    status_from_counts,
    write_report,
)


REPORT_SCHEMA = "naos.opencode_config_hygiene.v1"
TEXT_FILE_SUFFIXES = {".json", ".jsonc", ".md", ".markdown", ".txt", ".yaml", ".yml", ".toml", ".js", ".ts"}
MAX_TEXT_BYTES = 512 * 1024
OPENCODE_SUBDIRS = ("agents", "commands", "modes", "plugins", "skills", "tools", "themes")
AUTHORITY_FIELDS = {
    "runtime_enabled",
    "opencode_execution_allowed",
    "mcp_allowed",
    "provider_calls_allowed",
    "model_calls_allowed",
    "memory_allowed",
    "hook_activation_allowed",
    "tool_mutation_allowed",
}
REASON_ORDER = [
    "opencode_project_config_malformed",
    "stale_opencode_yaml_config",
    "remote_instruction_review",
    "absolute_instruction_review",
    "broad_permission_review",
    "auto_approval_review",
    "mcp_enabled_review",
    "mcp_remote_review",
    "mcp_auth_review",
    "plugin_external_review",
    "plugin_local_review",
    "model_provider_policy_link_missing",
    "model_provider_drift",
    "literal_secret",
    "opencode_runtime_authority_attempt",
    "opencode_config_review_required",
]
REASON_GATES = {
    "opencode_project_config_malformed": ["G2", "G6"],
    "stale_opencode_yaml_config": ["G2", "G6"],
    "remote_instruction_review": ["G3", "G6"],
    "absolute_instruction_review": ["G3", "G6"],
    "broad_permission_review": ["G3", "G6"],
    "auto_approval_review": ["G6"],
    "mcp_enabled_review": ["G6"],
    "mcp_remote_review": ["G3", "G6"],
    "mcp_auth_review": ["G6"],
    "plugin_external_review": ["G3", "G6"],
    "plugin_local_review": ["G3", "G6"],
    "model_provider_policy_link_missing": ["G2", "G6"],
    "model_provider_drift": ["G2", "G6"],
    "literal_secret": ["G6"],
    "opencode_runtime_authority_attempt": ["G6"],
    "opencode_config_review_required": ["G2", "G6"],
}
SECRET_RE = re.compile(
    r"(?i)("
    r"sk-[A-Za-z0-9_-]{8,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"AKIA[0-9A-Z]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"api[_-]?key\s*[:=]|"
    r"bearer\s+[A-Za-z0-9._-]{12,}|"
    r"authorization\s*[:=]\s*[A-Za-z0-9._ -]{12,}"
    r")"
)
LOCAL_MODEL_PROVIDER_REF = "naos/reports/model_provider_policy.json"
LIMITATIONS = [
    "OpenCode config hygiene reports evaluate repo-local declarations and files only.",
    "The report does not create, install, run, or configure OpenCode.",
    "The report does not inspect global user OpenCode configuration, IDE settings, credentials, private memory payloads, or external services.",
    "JSONC parsing is intentionally limited to comment and trailing-comma tolerant local configuration review.",
    "Finding presence is review evidence only; it is not approval, certification, proof of compliance, runtime supervision, or security proof.",
]
NOT_CLAIMED = [
    "OpenCode installation",
    "OpenCode execution",
    "OpenCode plugin creation",
    "global OpenCode config inspection",
    "MCP activation",
    "memory activation",
    "provider call",
    "model call",
    "API call",
    "network access",
    "credential validation",
    "secret scanner completeness",
    "malware absence",
    "supply-chain safety proof",
    "prompt-injection prevention",
    "runtime sandboxing",
    "runtime orchestration",
    "provider route correctness",
    "model recommendation",
    "IDE/tool configuration mutation",
    "approval",
    "merge approval",
    "release authority",
    "publication authority",
    "certification",
    "attestation",
    "proof of compliance",
]
RESIDUAL_RISKS = [
    "opencode_config_drift",
    "instruction_surface_drift",
    "mcp_configuration_confusion",
    "provider_model_drift",
    "literal_secret_false_negative",
    "optional_integration_authority_confusion",
    "human_review_required",
]


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return list(dict.fromkeys(str(item).strip() for item in as_list(value) if str(item).strip()))


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def is_adapt_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip().startswith("[ADAPT:")


def safe_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def default_declaration_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "opencode_config_hygiene.yaml"


def resolve_declaration_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("opencode_config_hygiene") or "opencode_config_hygiene.yaml")
    project_declaration = root / naos_root / filename
    if project_declaration.exists():
        return project_declaration, "project"
    return default_declaration_template(), "template"


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve(strict=False).relative_to(root.resolve()))
    except ValueError:
        return str(path)


def review_severity(profile: str, root: Path, naos_root: str) -> str:
    if is_kit_repository(root, naos_root):
        return "advisory"
    if profile == "quickstart":
        return "advisory"
    if profile == "lite":
        return "warning"
    return "required"


def unsafe_severity(base: str, reason_code: str) -> str:
    if reason_code in {"literal_secret", "opencode_runtime_authority_attempt"}:
        return "blocking"
    return base


def finding(
    identifier: str,
    severity: str,
    reason_code: str,
    message: str,
    path: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": identifier,
        "severity": severity,
        "status": reason_code,
        "reason_code": reason_code,
        "related_gates": REASON_GATES.get(reason_code, ["G6"]),
        "gate": ", ".join(REASON_GATES.get(reason_code, ["G6"])),
        "message": message,
        "human_review_required": True,
    }
    if path:
        item["path"] = path
    item.update({key: value for key, value in extra.items() if value is not None})
    return item


def strip_jsonc(text: str) -> str:
    output: list[str] = []
    in_string = False
    quote = ""
    escape = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in {"'", '"'}:
            in_string = True
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            output.append("\n")
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(text) and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index += 2
            continue
        output.append(char)
        index += 1
    cleaned = "".join(output)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def load_json_or_jsonc(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(strip_jsonc(text) if path.suffix == ".jsonc" else text)
    except Exception as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "OpenCode project config must be a JSON object."
    return data, None


def text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_FILE_SUFFIXES or path.name in {"AGENTS.md"}


def safe_read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES or not text_file(path):
            return None, None
        return path.read_text(encoding="utf-8", errors="replace"), None
    except Exception as exc:
        return None, str(exc)


def discover_opencode_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for relative in ("AGENTS.md", "opencode.json", "opencode.jsonc", ".opencode/config.yaml", ".opencode/config.yml"):
        path = root / relative
        if path.is_file():
            paths.append(path)
    opencode_dir = root / ".opencode"
    for dirname in OPENCODE_SUBDIRS:
        directory = opencode_dir / dirname
        if directory.is_dir():
            paths.extend(path for path in sorted(directory.rglob("*")) if path.is_file())
    return sorted(dict.fromkeys(paths))


def inspectable_file_summary(path: Path, root: Path) -> dict[str, Any]:
    text, error = safe_read_text(path)
    return {
        "path": relative_path(path, root),
        "kind": "project_config" if path.name in {"opencode.json", "opencode.jsonc"} else "opencode_surface",
        "sha256": safe_digest(path),
        "text_inspected": text is not None,
        "read_error": error,
        "size_bytes": path.stat().st_size if path.exists() else None,
    }


def walk_values(value: Any, path: str = "") -> list[tuple[str, Any]]:
    items = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            items.extend(walk_values(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            items.extend(walk_values(child, f"{path}[{index}]"))
    return items


def refs_from_config(config: dict[str, Any], names: set[str]) -> list[str]:
    refs: list[str] = []
    for path, value in walk_values(config):
        key = path.split(".")[-1].split("[")[0].lower()
        if key in names:
            refs.extend(string_list(value))
    return refs


def collect_model_provider_report_refs(report: dict[str, Any] | None) -> tuple[set[str], set[str]]:
    providers: set[str] = set()
    models: set[str] = set()
    if not isinstance(report, dict):
        return providers, models
    for path, value in walk_values(report):
        key = path.split(".")[-1].split("[")[0].lower()
        if key == "provider" and isinstance(value, str) and value.strip():
            providers.add(value.strip())
        if key == "model" and isinstance(value, str) and value.strip():
            models.add(value.strip())
    return providers, models


def load_model_provider_report(root: Path, naos_root: str, policy: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    reports_dir = str(policy.get("paths", {}).get("reports_dir") or "reports")
    filename = str(policy.get("paths", {}).get("model_provider_policy_report") or "model_provider_policy.json")
    path = root / naos_root / reports_dir / filename
    if not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    return data if isinstance(data, dict) else {}, None


def text_model_provider_refs(path: Path) -> tuple[list[str], list[str]]:
    text, _ = safe_read_text(path)
    if not text:
        return [], []
    providers: list[str] = []
    models: list[str] = []
    for match in re.finditer(r"(?im)^\s*(provider|model)\s*[:=]\s*[\"']?([A-Za-z0-9_./:@+-]+)", text):
        if match.group(1).lower() == "provider":
            providers.append(match.group(2))
        else:
            models.append(match.group(2))
    return providers, models


def has_remote_ref(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def has_absolute_ref(value: str) -> bool:
    return Path(value).is_absolute()


def is_external_plugin_ref(value: str) -> bool:
    text = value.strip()
    return bool(
        text.startswith(("http://", "https://", "github:", "npm:", "jsr:"))
        or text.startswith("@")
        or re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", text)
    )


def config_mcp_entries(config: dict[str, Any]) -> list[tuple[str, Any]]:
    return [(path, value) for path, value in walk_values(config) if path.split(".")[-1].split("[")[0].lower() == "mcp"]


def config_plugin_refs(config: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for path, value in walk_values(config):
        key = path.split(".")[-1].split("[")[0].lower()
        if key in {"plugin", "plugins"}:
            refs.extend(string_list(value))
    return refs


def permission_review_needed(config: dict[str, Any]) -> tuple[bool, bool]:
    broad = False
    auto_approval = False
    for path, value in walk_values(config):
        key = path.split(".")[-1].split("[")[0].lower()
        text = str(value).strip().lower()
        if key in {"permission", "permissions"} and (
            text in {"allow", "always", "all", "true"} or value == "*" or "*" in as_list(value)
        ):
            broad = True
        if key in {"approval", "approvals", "auto_approval", "autoapprove", "auto_approve"} and text in {
            "auto",
            "allow",
            "always",
            "true",
        }:
            auto_approval = True
        if key == "mode" and text == "auto":
            auto_approval = True
    return broad, auto_approval


def mcp_remote_or_auth(value: Any) -> tuple[bool, bool, bool]:
    enabled = bool(value)
    remote = False
    auth = False
    for path, child in walk_values(value):
        key = path.split(".")[-1].split("[")[0].lower()
        text = str(child).strip().lower()
        if key == "enabled" and text in {"false", "0", "no", "off"}:
            enabled = False
        if key in {"url", "endpoint"} and has_remote_ref(text):
            remote = True
        if key in {"type", "transport"} and text in {"remote", "http", "sse"}:
            remote = True
        if key in {"headers", "header", "oauth", "token", "authorization", "api_key", "apikey"}:
            auth = True
    return enabled, remote, auth


def authority_attempts(declaration: dict[str, Any], configs: list[dict[str, Any]]) -> list[str]:
    attempts: list[str] = []
    for field in sorted(AUTHORITY_FIELDS):
        if bool_value(declaration.get(field), default=False):
            attempts.append(f"declaration.{field}")
    for config_index, config in enumerate(configs):
        for path, value in walk_values(config):
            key = path.split(".")[-1].split("[")[0]
            if key in AUTHORITY_FIELDS and bool_value(value, default=False):
                attempts.append(f"project_config[{config_index}].{path}")
    return attempts


def has_literal_secret(path: Path) -> bool:
    text, _ = safe_read_text(path)
    return bool(text and SECRET_RE.search(text))


def reason_code_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("reason_code")) for item in findings)
    return {code: counts.get(code, 0) for code in REASON_ORDER}


def build_report(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    declaration_path: Path,
    declaration_source: str,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    declaration = load_yaml_mapping(declaration_path)
    enabled = bool_value(declaration.get("enabled"), default=False)
    declared = bool_value(declaration.get("opencode_config_declared"), default=False)
    base_severity = review_severity(profile, root, naos_root)
    findings: list[dict[str, Any]] = []

    files = discover_opencode_files(root)
    config_paths = [path for path in files if path.name in {"opencode.json", "opencode.jsonc"}]
    config_reports: list[dict[str, Any]] = []
    configs: list[dict[str, Any]] = []
    for path in config_paths:
        data, error = load_json_or_jsonc(path)
        config_reports.append(
            {
                "path": relative_path(path, root),
                "parsed": data is not None,
                "error": error,
                "sha256": safe_digest(path),
            }
        )
        if error:
            findings.append(
                finding(
                    "opencode_config_hygiene.project_config_malformed",
                    unsafe_severity(base_severity, "opencode_project_config_malformed"),
                    "opencode_project_config_malformed",
                    "OpenCode project configuration could not be parsed as local JSON/JSONC.",
                    path=relative_path(path, root),
                    parse_error=error,
                )
            )
        elif data is not None:
            configs.append(data)

    stale_yaml = [path for path in files if relative_path(path, root) in {".opencode/config.yaml", ".opencode/config.yml"}]
    for path in stale_yaml:
        findings.append(
            finding(
                "opencode_config_hygiene.stale_yaml_config",
                unsafe_severity(base_severity, "stale_opencode_yaml_config"),
                "stale_opencode_yaml_config",
                "Stale .opencode/config YAML configuration path is present; current baseline expects project opencode.json/jsonc plus .opencode/ subdirectories.",
                path=relative_path(path, root),
            )
        )

    if files and not enabled:
        findings.append(
            finding(
                "opencode_config_hygiene.config_review_required",
                unsafe_severity(base_severity, "opencode_config_review_required"),
                "opencode_config_review_required",
                "Repo-local OpenCode surfaces exist but NAOS OpenCode hygiene review is not enabled in the project declaration.",
                evidence_refs=[relative_path(path, root) for path in files],
            )
        )

    if not files and enabled:
        findings.append(
            finding(
                "opencode_config_hygiene.config_review_required",
                unsafe_severity(base_severity, "opencode_config_review_required"),
                "opencode_config_review_required",
                "NAOS OpenCode hygiene review is enabled but no repo-local OpenCode project surfaces were found.",
            )
        )

    instruction_refs: list[str] = []
    for config in configs:
        instruction_refs.extend(refs_from_config(config, {"instruction", "instructions", "agent", "agents"}))
    if any(has_remote_ref(ref) for ref in instruction_refs) and not bool_value(declaration.get("allow_remote_instructions")):
        findings.append(
            finding(
                "opencode_config_hygiene.remote_instruction_review",
                unsafe_severity(base_severity, "remote_instruction_review"),
                "remote_instruction_review",
                "OpenCode configuration references remote instruction material that needs human review.",
                instruction_refs=[ref for ref in instruction_refs if has_remote_ref(ref)],
            )
        )
    if any(has_absolute_ref(ref) for ref in instruction_refs) and not bool_value(declaration.get("allow_absolute_instruction_refs")):
        findings.append(
            finding(
                "opencode_config_hygiene.absolute_instruction_review",
                unsafe_severity(base_severity, "absolute_instruction_review"),
                "absolute_instruction_review",
                "OpenCode configuration references absolute local instruction paths that need human review.",
                instruction_refs=[ref for ref in instruction_refs if has_absolute_ref(ref)],
            )
        )

    for config in configs:
        broad, auto_approval = permission_review_needed(config)
        if broad and not bool_value(declaration.get("allow_broad_permissions")):
            findings.append(
                finding(
                    "opencode_config_hygiene.broad_permission_review",
                    unsafe_severity(base_severity, "broad_permission_review"),
                    "broad_permission_review",
                    "OpenCode configuration appears to grant broad permissions and needs human review.",
                )
            )
        if auto_approval and not bool_value(declaration.get("allow_auto_approval")):
            findings.append(
                finding(
                    "opencode_config_hygiene.auto_approval_review",
                    unsafe_severity(base_severity, "auto_approval_review"),
                    "auto_approval_review",
                    "OpenCode configuration appears to enable auto or always-approve posture and needs human review.",
                )
            )

    for config in configs:
        for mcp_path, mcp_value in config_mcp_entries(config):
            mcp_enabled, mcp_remote, mcp_auth = mcp_remote_or_auth(mcp_value)
            if mcp_enabled and not bool_value(declaration.get("allow_enabled_mcp")):
                findings.append(
                    finding(
                        "opencode_config_hygiene.mcp_enabled_review",
                        unsafe_severity(base_severity, "mcp_enabled_review"),
                        "mcp_enabled_review",
                        "OpenCode MCP configuration is declared and needs human review before any use.",
                        config_path=mcp_path,
                    )
                )
            if mcp_remote and not bool_value(declaration.get("allow_remote_mcp")):
                findings.append(
                    finding(
                        "opencode_config_hygiene.mcp_remote_review",
                        unsafe_severity(base_severity, "mcp_remote_review"),
                        "mcp_remote_review",
                        "OpenCode MCP configuration references a remote transport or URL and needs human review.",
                        config_path=mcp_path,
                    )
                )
            if mcp_auth and not bool_value(declaration.get("allow_mcp_auth")):
                findings.append(
                    finding(
                        "opencode_config_hygiene.mcp_auth_review",
                        unsafe_severity(base_severity, "mcp_auth_review"),
                        "mcp_auth_review",
                        "OpenCode MCP configuration references authentication material or headers and needs human review.",
                        config_path=mcp_path,
                    )
                )

    plugin_refs = [ref for config in configs for ref in config_plugin_refs(config)]
    external_plugin_refs = [ref for ref in plugin_refs if is_external_plugin_ref(ref)]
    if external_plugin_refs and not bool_value(declaration.get("allow_external_plugins")):
        findings.append(
            finding(
                "opencode_config_hygiene.plugin_external_review",
                unsafe_severity(base_severity, "plugin_external_review"),
                "plugin_external_review",
                "OpenCode plugin references include external package or remote identifiers that need human review.",
                plugin_refs=external_plugin_refs,
            )
        )
    local_plugin_files = [path for path in files if ".opencode/plugins/" in relative_path(path, root)]
    if local_plugin_files and not bool_value(declaration.get("allow_local_plugins_without_review")):
        findings.append(
            finding(
                "opencode_config_hygiene.plugin_local_review",
                unsafe_severity(base_severity, "plugin_local_review"),
                "plugin_local_review",
                "Repo-local OpenCode plugin files exist and need review as operational code.",
                plugin_refs=[relative_path(path, root) for path in local_plugin_files],
            )
        )

    secret_paths = [path for path in files if has_literal_secret(path)]
    for path in secret_paths:
        findings.append(
            finding(
                "opencode_config_hygiene.literal_secret",
                unsafe_severity(base_severity, "literal_secret"),
                "literal_secret",
                "OpenCode-related local file contains an obvious literal secret-like value.",
                path=relative_path(path, root),
            )
        )

    attempts = authority_attempts(declaration, configs)
    if attempts:
        findings.append(
            finding(
                "opencode_config_hygiene.runtime_authority_attempt",
                unsafe_severity(base_severity, "opencode_runtime_authority_attempt"),
                "opencode_runtime_authority_attempt",
                "OpenCode hygiene declarations attempted to enable runtime, MCP, memory, provider/model, hook, or tool-mutation authority.",
                authority_refs=attempts,
            )
        )

    config_providers: set[str] = set()
    config_models: set[str] = set()
    for config in configs:
        config_providers.update(refs_from_config(config, {"provider"}))
        config_models.update(refs_from_config(config, {"model"}))
    for path in files:
        providers, models = text_model_provider_refs(path)
        config_providers.update(providers)
        config_models.update(models)
    model_provider_report, model_provider_error = load_model_provider_report(root, naos_root, policy)
    if (config_providers or config_models) and not model_provider_report:
        findings.append(
            finding(
                "opencode_config_hygiene.model_provider_policy_link_missing",
                unsafe_severity(base_severity, "model_provider_policy_link_missing"),
                "model_provider_policy_link_missing",
                "OpenCode model/provider declarations exist without a local model-provider policy report.",
                provider_refs=sorted(config_providers),
                model_refs=sorted(config_models),
            )
        )
    elif model_provider_report:
        known_providers, known_models = collect_model_provider_report_refs(model_provider_report)
        unknown_providers = sorted(ref for ref in config_providers if ref not in known_providers)
        unknown_models = sorted(ref for ref in config_models if ref not in known_models)
        if unknown_providers or unknown_models or model_provider_error:
            findings.append(
                finding(
                    "opencode_config_hygiene.model_provider_drift",
                    unsafe_severity(base_severity, "model_provider_drift"),
                    "model_provider_drift",
                    "OpenCode model/provider declarations do not match the local model-provider policy report.",
                    unknown_providers=unknown_providers,
                    unknown_models=unknown_models,
                    model_provider_report_error=model_provider_error,
                )
            )

    summary = finding_counts(findings)
    summary.update(
        {
            "opencode_files": len(files),
            "project_config_files": len(config_paths),
            "project_config_parse_errors": sum(1 for item in config_reports if item.get("error")),
            "local_plugin_files": len(local_plugin_files),
            "model_provider_policy_report_present": bool(model_provider_report),
            "runtime_authority_findings": sum(
                1 for item in findings if item.get("reason_code") == "opencode_runtime_authority_attempt"
            ),
        }
    )
    if not files and not enabled and not declared and not findings:
        status = "not_configured"
        human_review_required = False
    elif findings:
        status = status_from_counts(summary)
        human_review_required = True
    else:
        status = "pass"
        human_review_required = False

    known_gaps = string_list(declaration.get("known_gaps"))
    if not enabled:
        known_gaps = list(dict.fromkeys(known_gaps + ["opencode_config_hygiene_not_enabled"]))
    residual_risks = list(dict.fromkeys(string_list(declaration.get("residual_risks")) + (RESIDUAL_RISKS if enabled else [])))
    not_claimed = list(dict.fromkeys(string_list(declaration.get("not_claimed")) + NOT_CLAIMED))

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "deterministic": True,
        "declaration_path": relative_path(declaration_path, root),
        "declaration_source": declaration_source,
        "declaration_hash": safe_digest(declaration_path),
        "enabled": enabled,
        "opencode_config_declared": declared,
        "runtime_enabled": False,
        "opencode_execution_allowed": False,
        "mcp_allowed": False,
        "provider_calls_allowed": False,
        "model_calls_allowed": False,
        "memory_allowed": False,
        "hook_activation_allowed": False,
        "tool_mutation_allowed": False,
        "profile_posture": as_mapping(declaration.get("profile_posture")),
        "config_files": config_reports,
        "opencode_surfaces": [inspectable_file_summary(path, root) for path in files],
        "model_provider_policy_report_ref": LOCAL_MODEL_PROVIDER_REF if model_provider_report else None,
        "findings": findings,
        "reason_code_counts": reason_code_counts(findings),
        "known_gaps": known_gaps,
        "residual_risks": residual_risks,
        "limitations": LIMITATIONS,
        "not_claimed": not_claimed,
        "human_review_required": human_review_required,
        "generated_by": build_generated_by(root, generated_at=generated_at),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review optional repo-local OpenCode configuration hygiene.")
    parser.add_argument("project", nargs="?", default=".", help="Project root to inspect.")
    parser.add_argument("--profile", default=None, help="NAOS profile.")
    parser.add_argument("--naos-root", default=None, help="NAOS root directory.")
    parser.add_argument("--policy", default=None, help="Optional policy file.")
    parser.add_argument("--opencode-config-hygiene", default=None, help="Explicit OpenCode hygiene YAML declaration.")
    parser.add_argument("--output", default=None, help="Output report path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    parser.add_argument("--strict", action="store_true", help="Use strict exit-code behavior.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project).resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    profile = normalize_profile(args.profile, policy)
    naos_root = args.naos_root or default_naos_root(policy)
    declaration_path, declaration_source = resolve_declaration_path(
        root,
        naos_root,
        policy,
        explicit=args.opencode_config_hygiene,
    )
    report = build_report(
        root=root,
        naos_root=naos_root,
        profile=profile,
        policy=policy,
        declaration_path=declaration_path,
        declaration_source=declaration_source,
    )

    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "opencode_config_hygiene_report")
    write_report(output, report)
    if args.json or output is None:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS OpenCode config hygiene: {report['status']} ({report['summary']['total_findings']} findings, output: {output})")
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
