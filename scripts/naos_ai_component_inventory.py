#!/usr/bin/env python3
"""Build and validate a deterministic inventory of declared NAOS AI components."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_emit_capabilities import (  # noqa: E402
    CapabilityEmissionError,
    default_agent_files,
    default_instruction_files,
    default_skill_files,
    emit_catalogue,
)
from naos_policy import (  # noqa: E402
    controlled_utc_now_text,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    kit_root,
    load_policy,
    normalize_profile,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.ai_component_inventory.v1"
RULES_SCHEMA = "naos.ai_component_inventory_rules.v1"
FORMAT_ID = "ai_component_inventory.v1"
GENERATOR_VERSION = "1.0.0"
NOT_CLAIMED = [
    "CycloneDX conformance",
    "SPDX conformance",
    "software bill of materials",
    "runtime discovery",
    "inventory completeness",
    "provider availability",
    "model identity verification",
    "signing",
    "attestation",
    "provenance authenticity",
    "supply-chain assurance",
    "security approval",
    "compliance approval",
    "release authority",
    "publication authority",
]
LIMITATIONS = [
    "The inventory contains declared repository facts only; it does not discover runtime components or call providers, models, MCP servers, memory tools, or networks.",
    "Content digests detect change but do not authenticate authors, sign artifacts, attest provenance, or prove completeness.",
    "Model and tool declarations are configuration metadata, not evidence that a client or provider uses them at runtime.",
]
RESIDUAL_RISKS = [
    "undeclared_runtime_components",
    "declaration_runtime_drift",
    "unverified_model_or_provider_identity",
    "human_review_required_for_missing_or_stale_inventory",
]
SECRET_LIKE_RE = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|bearer\s+[A-Za-z0-9._-]{12,}|"
    r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|credential|"
    r"authorization)\b\s*[:=]\s*\S+)"
)
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)^(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|"
    r"credential|authorization|private[_-]?key)$"
)


class InventoryError(ValueError):
    """Raised when declared inventory inputs cannot be bounded deterministically."""


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise InventoryError(f"Expected YAML mapping: {path}")
    return data


def load_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise InventoryError(f"Expected JSON object: {path}")
    return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def relative_bounded_path(path: Path, root: Path) -> str:
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        lexical_relative = lexical_path.relative_to(lexical_root)
        cursor = lexical_root
        for part in lexical_relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise InventoryError(
                    f"Inventory input must not use symlink path components: {path}"
                )
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError) as exc:
        raise InventoryError(f"Inventory input must be a regular file inside the project root: {path}") from exc
    if not resolved.is_file():
        raise InventoryError(f"Inventory input must be a regular non-symlink file: {path}")
    return relative.as_posix()


def preflight_bounded_output(path: Path, root: Path) -> None:
    lexical_root = root.absolute()
    lexical_path = path.absolute()
    try:
        lexical_relative = lexical_path.relative_to(lexical_root)
    except ValueError as exc:
        raise InventoryError(
            f"Inventory output must remain inside the project root: {path}"
        ) from exc
    cursor = lexical_root
    for part in lexical_relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise InventoryError(
                f"Inventory output must not use symlink path components: {path}"
            )
    if path.exists():
        relative_bounded_path(path, root)


def slug(value: str) -> str:
    return "-".join(part for part in "".join(char if char.isalnum() else " " for char in value).upper().split())


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "ai_component_inventory_rules.yaml"


def default_model_policy_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "model_provider_policy.yaml"


def resolve_rules_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        candidate = Path(explicit).expanduser()
        return (candidate if candidate.is_absolute() else root / candidate).absolute(), "explicit"
    filename = str(policy.get("paths", {}).get("ai_component_inventory_rules") or "ai_component_inventory_rules.yaml")
    project_path = root / naos_root / filename
    if project_path.is_file():
        return project_path, "project"
    return default_rules_template(), "template"


def resolve_model_policy_path(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    explicit: str | None = None,
) -> tuple[Path, str]:
    if explicit:
        candidate = Path(explicit).expanduser()
        return (candidate if candidate.is_absolute() else root / candidate).absolute(), "explicit"
    filename = str(policy.get("paths", {}).get("model_provider_policy") or "model_provider_policy.yaml")
    project_path = root / naos_root / filename
    if project_path.is_file():
        return project_path, "project"
    return default_model_policy_template(), "template"


def inventory_schema_path(root: Path) -> Path:
    project_schema = root / "schemas" / "naos" / "ai_component_inventory.schema.json"
    return project_schema if project_schema.is_file() else kit_root() / "schemas" / "naos" / project_schema.name


def rules_schema_path(root: Path) -> Path:
    project_schema = root / "schemas" / "naos" / "ai_component_inventory_rules.schema.json"
    return project_schema if project_schema.is_file() else kit_root() / "schemas" / "naos" / project_schema.name


def schema_errors(instance: dict[str, Any], schema_path: Path) -> list[str]:
    schema = load_json_mapping(schema_path)
    return sorted(error.message for error in Draft202012Validator(schema).iter_errors(instance))


def input_record(path: Path, root: Path, role: str) -> dict[str, str]:
    return {
        "path": relative_bounded_path(path, root),
        "role": role,
        "sha256": sha256_file(path),
    }


def sanitize_declared_value(value: Any, *, field_name: str | None = None) -> tuple[Any, int]:
    if field_name is not None and SENSITIVE_FIELD_RE.fullmatch(field_name):
        if value not in (None, "", [], {}):
            return "[REDACTED_SENSITIVE_FIELD]", 1
        return value, 0
    if isinstance(value, str):
        if SECRET_LIKE_RE.search(value):
            return "[REDACTED_SECRET_LIKE_VALUE]", 1
        return value, 0
    if isinstance(value, list):
        sanitized: list[Any] = []
        redactions = 0
        for item in value:
            clean, count = sanitize_declared_value(item)
            sanitized.append(clean)
            redactions += count
        return sanitized, redactions
    if isinstance(value, dict):
        sanitized_mapping: dict[str, Any] = {}
        redactions = 0
        named_sensitive_parameter = SENSITIVE_FIELD_RE.fullmatch(
            str(value.get("name") or "")
        ) is not None
        for key, item in value.items():
            key_text = str(key)
            sensitive_field = key_text
            if named_sensitive_parameter and key_text in {"default", "value", "example"}:
                sensitive_field = "secret"
            clean, count = sanitize_declared_value(item, field_name=sensitive_field)
            sanitized_mapping[str(key)] = clean
            redactions += count
        return sanitized_mapping, redactions
    return value, 0


def component_from_surface(surface: dict[str, Any], root: Path) -> tuple[dict[str, Any], Path]:
    source_text = str(surface.get("source_file") or "")
    source = root / source_text
    source_ref = relative_bounded_path(source, root)
    raw_declarations = {
        key: surface[key]
        for key in ("model", "naos_model_role", "tools", "parameters", "apply_to", "related_rules")
        if key in surface
    }
    declarations, redactions = sanitize_declared_value(raw_declarations)
    return (
        {
            "component_id": str(surface.get("id") or ""),
            "component_type": str(surface.get("type") or ""),
            "name": str(surface.get("name") or ""),
            "status": str(surface.get("status") or "unknown"),
            "source_file": source_ref,
            "source_sha256": sha256_file(source),
            "declarations": declarations,
            "redactions": redactions,
        },
        source,
    )


def model_components(policy_data: dict[str, Any], policy_path: Path, root: Path) -> list[dict[str, Any]]:
    policy_ref = relative_bounded_path(policy_path, root)
    policy_digest = sha256_file(policy_path)
    components: list[dict[str, Any]] = []
    roles = policy_data.get("roles") if isinstance(policy_data.get("roles"), dict) else {}
    for role, raw in sorted(roles.items()):
        declaration = raw if isinstance(raw, dict) else {}
        declarations, redactions = sanitize_declared_value(
            {
                key: declaration.get(key)
                for key in (
                    "enabled",
                    "provider_kind",
                    "provider",
                    "model",
                    "model_version",
                    "reasoning_effort",
                    "cost_tier",
                    "data_exposure_level",
                    "advisory_only",
                    "runtime_enabled",
                    "provider_calls_allowed",
                    "human_review_required",
                )
            }
        )
        components.append(
            {
                "component_id": f"MODEL-ROLE-{slug(str(role))}",
                "component_type": "model_role",
                "name": str(role),
                "status": "active" if declaration.get("enabled") is True else "declared_disabled",
                "source_file": policy_ref,
                "source_sha256": policy_digest,
                "declarations": declarations,
                "redactions": redactions,
            }
        )
    bindings = policy_data.get("tool_model_bindings") if isinstance(policy_data.get("tool_model_bindings"), dict) else {}
    for tool, raw in sorted(bindings.items()):
        declaration = raw if isinstance(raw, dict) else {}
        role_bindings = declaration.get("roles") if isinstance(declaration.get("roles"), dict) else {}
        tool_declarations, tool_redactions = sanitize_declared_value(
            {
                "enabled": bool(declaration.get("enabled")),
                "tool_family": declaration.get("tool_family"),
                "config_owner": declaration.get("config_owner"),
                "mutation_allowed": bool(declaration.get("mutation_allowed")),
                "human_review_required": bool(declaration.get("human_review_required")),
                "roles": sorted(str(item) for item in role_bindings),
            }
        )
        components.append(
            {
                "component_id": f"AI-TOOL-{slug(str(tool))}",
                "component_type": "ai_tool",
                "name": str(tool),
                "status": "active" if declaration.get("enabled") is True else "declared_disabled",
                "source_file": policy_ref,
                "source_sha256": policy_digest,
                "declarations": tool_declarations,
                "redactions": tool_redactions,
            }
        )
        for role, binding in sorted(role_bindings.items()):
            detail = binding if isinstance(binding, dict) else {}
            binding_declarations, binding_redactions = sanitize_declared_value(
                {
                    key: detail.get(key)
                    for key in (
                        "provider_kind",
                        "provider",
                        "model",
                        "model_version",
                        "reasoning_effort",
                        "cost_tier",
                        "data_exposure_level",
                    )
                }
                | {"role": str(role), "tool": str(tool)}
            )
            components.append(
                {
                    "component_id": f"AI-TOOL-BINDING-{slug(str(tool))}-{slug(str(role))}",
                    "component_type": "tool_model_binding",
                    "name": f"{tool}:{role}",
                    "status": "active" if declaration.get("enabled") is True else "declared_disabled",
                    "source_file": policy_ref,
                    "source_sha256": policy_digest,
                    "declarations": binding_declarations,
                    "redactions": binding_redactions,
                }
            )
    return components


def component_findings(
    components: list[dict[str, Any]],
    profile: str,
    rules: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    required_component_fields = [str(item) for item in rules.get("required_component_fields") or []]
    allowed_component_types = {str(item) for item in rules.get("allowed_component_types") or []}
    active_required = [
        str(item) for item in rules.get("active_model_or_binding_required_declarations") or []
    ]
    identifiers = [str(item.get("component_id") or "") for item in components]
    for component_id, count in sorted(Counter(identifiers).items()):
        if not component_id or count > 1:
            findings.append(
                {
                    "id": "ai_component_inventory.duplicate_or_missing_id",
                    "severity": "required" if profile in {"standard", "assured"} else "warning",
                    "status": "review_required",
                    "component_id": component_id or None,
                    "message": "Every declared component must have one unique non-empty identifier.",
                }
            )
    for component in components:
        missing_component_fields = [
            field for field in required_component_fields if component.get(field) in (None, "")
        ]
        if missing_component_fields:
            findings.append(
                {
                    "id": "ai_component_inventory.component_declaration_incomplete",
                    "severity": "required" if profile in {"standard", "assured"} else "warning",
                    "status": "review_required",
                    "component_id": component.get("component_id"),
                    "missing_fields": missing_component_fields,
                    "message": "A declared component is missing required inventory fields.",
                }
            )
        if str(component.get("component_type") or "") not in allowed_component_types:
            findings.append(
                {
                    "id": "ai_component_inventory.component_type_not_allowed",
                    "severity": "required" if profile in {"standard", "assured"} else "warning",
                    "status": "review_required",
                    "component_id": component.get("component_id"),
                    "message": "A declared component type is outside the bounded custom inventory contract.",
                }
            )
        declarations = component.get("declarations") if isinstance(component.get("declarations"), dict) else {}
        if int(component.get("redactions") or 0) > 0:
            findings.append(
                {
                    "id": "ai_component_inventory.secret_like_value_redacted",
                    "severity": "required" if profile in {"standard", "assured"} else "warning",
                    "status": "review_required",
                    "component_id": component.get("component_id"),
                    "message": "One or more secret-like declaration values were redacted from the inventory output.",
                }
            )
        if component.get("status") != "active":
            continue
        if component.get("component_type") in {"model_role", "tool_model_binding"}:
            missing = [field for field in active_required if declarations.get(field) in (None, "")]
            if missing:
                findings.append(
                    {
                        "id": "ai_component_inventory.active_declaration_incomplete",
                        "severity": "required" if profile in {"standard", "assured"} else "warning",
                        "status": "review_required",
                        "component_id": component.get("component_id"),
                        "missing_fields": missing,
                        "message": "An active model or tool binding is missing required declared facts.",
                    }
                )
    return findings


def digest_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {
        key: report[key]
        for key in (
            "schema",
            "profile",
            "required_for_profile",
            "format",
            "decision_supported",
            "review_owner",
            "lifecycle",
            "rules",
            "model_policy",
            "applicability",
            "field_sources",
            "provenance",
            "components",
            "component_counts",
            "findings",
            "known_gaps",
            "residual_risks",
            "limitations",
            "not_claimed",
            "human_review_required",
            "summary",
        )
    }


def build_inventory_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    model_policy_path: Path,
    model_policy_source: str,
) -> dict[str, Any]:
    relative_bounded_path(rules_path, root)
    relative_bounded_path(model_policy_path, root)
    rules_schema = rules_schema_path(root)
    report_schema = inventory_schema_path(root)
    relative_bounded_path(rules_schema, root)
    relative_bounded_path(report_schema, root)
    for candidate in (
        default_agent_files(root)
        + default_skill_files(root)
        + default_instruction_files(root)
    ):
        relative_bounded_path(candidate, root)
    rules = load_yaml_mapping(rules_path)
    if rules.get("schema") != RULES_SCHEMA:
        raise InventoryError(f"Unsupported inventory rules schema: {rules.get('schema')!r}")
    rule_errors = schema_errors(rules, rules_schema)
    if rule_errors:
        raise InventoryError("Invalid inventory rules: " + "; ".join(rule_errors))
    model_policy = load_yaml_mapping(model_policy_path)
    try:
        catalogue = emit_catalogue(root)
    except CapabilityEmissionError as exc:
        raise InventoryError(str(exc)) from exc

    components: list[dict[str, Any]] = []
    source_paths: list[Path] = []
    for surface in catalogue.get("capabilities") or []:
        if not isinstance(surface, dict):
            raise InventoryError("AI surface catalogue emitted a non-mapping component")
        component, source = component_from_surface(surface, root)
        components.append(component)
        source_paths.append(source)
    components.extend(model_components(model_policy, model_policy_path, root))
    components.sort(key=lambda item: (str(item.get("component_id")), str(item.get("source_file"))))

    inputs = [input_record(rules_path, root, "inventory_rules"), input_record(model_policy_path, root, "model_policy")]
    for path in sorted(set(source_paths), key=lambda item: relative_bounded_path(item, root)):
        inputs.append(input_record(path, root, "ai_surface_declaration"))
    for helper in (
        root / "scripts" / "naos_ai_component_inventory.py",
        root / "scripts" / "naos_emit_capabilities.py",
        root / "scripts" / "validators" / "frontmatter_utils.py",
    ):
        if helper.is_file():
            inputs.append(input_record(helper, root, "generator_or_normalizer"))
    inputs.sort(key=lambda item: (item["path"], item["role"]))

    profile_rules = rules.get("profiles") if isinstance(rules.get("profiles"), dict) else {}
    posture = profile_rules.get(profile) if isinstance(profile_rules.get(profile), dict) else {}
    required_for_profile = bool(posture.get("required"))
    findings = component_findings(components, profile, rules)
    human_review_required = bool(findings)
    status = "review_required" if findings else "current"
    component_counts = dict(sorted(Counter(str(item["component_type"]) for item in components).items()))
    summary = finding_counts(findings)
    summary.update(
        {
            "components": len(components),
            "component_types": len(component_counts),
            "inputs": len(inputs),
            "required_for_profile": required_for_profile,
        }
    )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "generated_at": controlled_utc_now_text(),
        "generator_version": GENERATOR_VERSION,
        "profile": profile,
        "status": status,
        "required_for_profile": required_for_profile,
        "project_root": str(root),
        "naos_root": naos_root,
        "format": {
            "id": FORMAT_ID,
            "version": 1,
            "kind": "custom_declared_facts_inventory",
            "standard_conformance": None,
        },
        "decision_supported": str(rules.get("decision_supported") or ""),
        "review_owner": str(rules.get("review_owner") or "project-governance-reviewer"),
        "lifecycle": rules.get("lifecycle") or {},
        "rules": {
            "path": relative_bounded_path(rules_path, root),
            "source": rules_source,
            "sha256": sha256_file(rules_path),
        },
        "model_policy": {
            "path": relative_bounded_path(model_policy_path, root),
            "source": model_policy_source,
            "sha256": sha256_file(model_policy_path),
        },
        "applicability": rules.get("applicability") or {},
        "field_sources": rules.get("field_sources") or {},
        "provenance": {
            "basis": "repo_local_declared_facts",
            "inputs": inputs,
            "input_set_digest": canonical_digest(inputs),
        },
        "components": components,
        "component_counts": component_counts,
        "inventory_digest": "",
        "findings": findings,
        "known_gaps": ["runtime_component_discovery_not_performed", "external_standard_export_not_implemented"],
        "residual_risks": list(RESIDUAL_RISKS),
        "limitations": list(LIMITATIONS),
        "not_claimed": list(NOT_CLAIMED),
        "human_review_required": human_review_required,
        "summary": summary,
    }
    report["inventory_digest"] = canonical_digest(digest_payload(report))
    errors = schema_errors(report, report_schema)
    if errors:
        raise InventoryError("Generated inventory violates its schema: " + "; ".join(errors))
    return report


def build_expected_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    rules: str | None = None,
    model_policy: str | None = None,
) -> dict[str, Any]:
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, rules)
    model_path, model_source = resolve_model_policy_path(root, naos_root, policy, model_policy)
    return build_inventory_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        rules_path=rules_path,
        rules_source=rules_source,
        model_policy_path=model_path,
        model_policy_source=model_source,
    )


def validate_inventory_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    report: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if schema_errors(report, inventory_schema_path(root)):
        reasons.append("inventory_schema_invalid")
        return reasons
    try:
        expected = build_expected_report(root=root, profile=profile, naos_root=naos_root, policy=policy)
    except (InventoryError, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError):
        return ["inventory_consumer_unavailable"]
    if report.get("provenance", {}).get("input_set_digest") != expected["provenance"]["input_set_digest"]:
        reasons.append("inventory_source_stale")
    stored_inventory_digest = report.get("inventory_digest")
    recomputed_inventory_digest = canonical_digest(digest_payload(report))
    if (
        stored_inventory_digest != recomputed_inventory_digest
        or recomputed_inventory_digest != expected["inventory_digest"]
    ):
        reasons.append("inventory_content_mismatch")
    if report.get("status") == "review_required" or report.get("human_review_required") is True:
        finding_ids = {
            str(item.get("id") or "")
            for item in report.get("findings") or []
            if isinstance(item, dict)
        }
        incomplete_ids = {
            "ai_component_inventory.duplicate_or_missing_id",
            "ai_component_inventory.component_declaration_incomplete",
            "ai_component_inventory.active_declaration_incomplete",
        }
        reasons.append(
            "inventory_required_fields_missing"
            if finding_ids & incomplete_ids
            else "inventory_review_required"
        )
    return list(dict.fromkeys(reasons))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a deterministic inventory of declared NAOS AI components.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root")
    parser.add_argument("--policy")
    parser.add_argument("--rules")
    parser.add_argument("--model-policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd().resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "ai_component_inventory_report")
    if not output.is_absolute():
        output = root / output
    try:
        preflight_bounded_output(output, root)
    except InventoryError as exc:
        print(f"NAOS AI component inventory: FAIL — {exc}", file=sys.stderr)
        return 2
    try:
        expected = build_expected_report(
            root=root,
            profile=profile,
            naos_root=naos_root,
            policy=policy,
            rules=args.rules,
            model_policy=args.model_policy,
        )
    except (InventoryError, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"NAOS AI component inventory: FAIL — {exc}", file=sys.stderr)
        return 2

    if args.check:
        if not output.is_file():
            print(f"NAOS AI component inventory: FAIL — missing report: {output}", file=sys.stderr)
            return 1
        try:
            actual = load_json_mapping(output)
            reasons = validate_inventory_report(
                root=root,
                profile=profile,
                naos_root=naos_root,
                policy=policy,
                report=actual,
            )
        except (InventoryError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"NAOS AI component inventory: FAIL — {exc}", file=sys.stderr)
            return 1
        if reasons:
            print(f"NAOS AI component inventory: FAIL — {', '.join(reasons)}", file=sys.stderr)
            return 1
        print(f"NAOS AI component inventory: PASS — {output} is current")
        return 0

    write_report(output, expected)
    if args.json:
        print(json.dumps(expected, indent=2, sort_keys=True))
    else:
        print(
            "NAOS AI component inventory: "
            f"{expected['status']} ({expected['summary']['components']} components, output: {output})"
        )
    return exit_code_for_summary(profile, expected["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
