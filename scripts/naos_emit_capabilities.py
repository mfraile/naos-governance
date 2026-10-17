#!/usr/bin/env python3
"""Emit the NAOS AI tool-surface catalogue from frontmatter."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent / "validators"))
    from frontmatter_utils import (  # type: ignore[import-not-found]
        candidate_files,
        metadata_host_paths,
        MetadataScopeError,
        host_declaration,
        METADATA_SCOPE_PATH as METADATA_SCOPE_PATH,
        display_path,
        is_non_empty_string,
        is_non_empty_string_list,
        model_selector_is_valid,
        parse_frontmatter,
        skill_authoring_metadata,
    )
else:  # pragma: no cover - package import path
    from .validators.frontmatter_utils import (
        candidate_files,
        metadata_host_paths,
        MetadataScopeError,
        host_declaration,
        METADATA_SCOPE_PATH as METADATA_SCOPE_PATH,
        display_path,
        is_non_empty_string,
        is_non_empty_string_list,
        model_selector_is_valid,
        parse_frontmatter,
        skill_authoring_metadata,
    )


SCHEMA_VERSION = "0.1.0"
CATALOGUE_VERSION = "0.1.0"
GENERATED_BY = "scripts/naos_emit_capabilities.py"
DEFAULT_OUTPUT = Path("configs/naos_ai_surface_catalogue.yaml")
RULE_RE = re.compile(r"\bRule\s+([0-9]+)\b")


class CapabilityEmissionError(Exception):
    """Raised when source metadata cannot be emitted safely."""


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value.strip()).strip("-")
    return slug.upper()


def friendly_name_from_slug(slug: str) -> str:
    return slug.replace("-", " ").strip().title()


def first_heading(body: str) -> str | None:
    for line in body.splitlines():
        match = re.match(r"^#\s+(.+?)\s*$", line)
        if match:
            return re.sub(r"[*_`]+", "", match.group(1)).strip()
    return None


def related_rules(body: str) -> list[str]:
    return [f"Rule {number}" for number in sorted(set(RULE_RE.findall(body)), key=int)]


def normalize_parameters(value: Any, path: Path) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CapabilityEmissionError(f"{path}: skill parameters must be a list")
    try:
        parameters, _ = skill_authoring_metadata({"metadata": {
            "naos-parameters": json.dumps(value, allow_nan=False)}})
    except (ValueError, TypeError, RecursionError) as exc:
        raise CapabilityEmissionError(f"{path}: malformed skill parameters: {exc}") from exc
    # Preserve JSON values and extension fields. Defaults and lists are
    # declarations, not executable inputs.
    return [{**entry, "name": entry["name"].strip(),
             "description": entry["description"].strip()} for entry in parameters]


def normalize_apply_to(value: Any, path: Path) -> str | list[str]:
    if is_non_empty_string(value):
        return value.strip()
    if isinstance(value, list) and value and all(is_non_empty_string(item) for item in value):
        return [item.strip() for item in value]
    raise CapabilityEmissionError(f"{path}: instruction applyTo must be a non-empty string or list")


def agent_slug(path: Path) -> str:
    stem = path.name.removesuffix(".agent.md")
    return stem.removeprefix("naos-")


def instruction_slug(path: Path) -> str:
    return path.name.removesuffix(".instructions.md")


def base_capability(capability_id: str, name: str, description: str, kind: str, path: Path, root: Path) -> dict[str, Any]:
    # The catalogue is a portable data record, not a native-shell display.
    # Keep source references identical when the same tree is generated on NTFS.
    try:
        source_file = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        source_file = path.as_posix()
    return {
        "id": capability_id,
        "name": name,
        "description": description,
        "type": kind,
        "source_file": source_file,
        "status": "active",
        "schema_version": SCHEMA_VERSION,
    }


def emit_agent(path: Path, root: Path) -> dict[str, Any]:
    document = parse_frontmatter(path)
    if document.error:
        raise CapabilityEmissionError(f"{path}: {document.error}")
    if not model_selector_is_valid(document.data):
        raise CapabilityEmissionError(
            f"{path}: invalid explicit agent model selector; omit for host selection "
            "or supply a non-empty host-supported scalar/list without ADAPT placeholders"
        )
    if not is_non_empty_string_list(document.data.get("tools")):
        raise CapabilityEmissionError(f"{path}: agent tools must be a non-empty list of strings")

    slug = agent_slug(path)
    name = document.data.get("name") if is_non_empty_string(document.data.get("name")) else f"@naos-{slug}"
    description = document.data.get("description") if is_non_empty_string(document.data.get("description")) else f"NAOS {friendly_name_from_slug(slug)} agent."
    capability = base_capability(f"CAP-A-{slugify(slug)}", name.strip(), description.strip(), "agent", path, root)
    # These describe repository declarations, never observed host selection.
    if "model" not in document.data:
        capability["model"] = None
        capability["model_selection"] = "host_default_unspecified"
    else:
        value = document.data["model"]
        capability["model"] = ([item.strip() for item in value]
                               if isinstance(value, list) else value.strip())
        capability["model_selection"] = "explicit_declaration"
    if is_non_empty_string(document.data.get("naos_model_role")):
        capability["naos_model_role"] = document.data["naos_model_role"].strip()
    capability["tools"] = [item.strip() for item in document.data["tools"]]
    rules = related_rules(document.body)
    if rules:
        capability["related_rules"] = rules
    return capability


def emit_skill(path: Path, root: Path) -> dict[str, Any]:
    document = parse_frontmatter(path)
    if document.error:
        raise CapabilityEmissionError(f"{path}: {document.error}")
    if not is_non_empty_string(document.data.get("name")):
        raise CapabilityEmissionError(f"{path}: skill name must be a non-empty string")
    if not is_non_empty_string(document.data.get("description")):
        raise CapabilityEmissionError(f"{path}: skill description must be a non-empty string")

    name = document.data["name"].strip()
    capability = base_capability(
        f"CAP-S-{slugify(name)}",
        name,
        document.data["description"].strip(),
        "skill",
        path,
        root,
    )
    try:
        parameters, base = skill_authoring_metadata(document.data)
    except ValueError as exc:
        raise CapabilityEmissionError(f"{path}: {exc}") from exc
    capability["parameters"] = normalize_parameters(parameters, path)
    if base is not None:
        capability["authoring_base"] = base
    rules = related_rules(document.body)
    if rules:
        capability["related_rules"] = rules
    return capability


def emit_instruction(path: Path, root: Path) -> dict[str, Any]:
    document = parse_frontmatter(path)
    if document.error:
        raise CapabilityEmissionError(f"{path}: {document.error}")
    apply_to = normalize_apply_to(document.data.get("applyTo"), path)
    slug = instruction_slug(path)
    heading = first_heading(document.body)
    name = heading if heading else friendly_name_from_slug(slug)
    description = f"Scoped instruction for files matching {apply_to!r}."
    capability = base_capability(f"CAP-I-{slugify(slug)}", name, description, "instruction", path, root)
    capability["apply_to"] = apply_to
    rules = related_rules(document.body)
    if rules:
        capability["related_rules"] = rules
    return capability


def default_agent_files(root: Path) -> list[Path]:
    return candidate_files(root, "templates/agents/*.agent.md", ".github/agents/*.agent.md")


def default_skill_files(root: Path) -> list[Path]:
    scope = metadata_host_paths(root)
    files = candidate_files(root, "templates/skills/*/SKILL.md", ".github/skills/*/SKILL.md")
    return sorted({p.resolve(): p for p in files + [p for p, kind in scope.items() if kind == "skill"]}.values(),
                  key=lambda path: path.as_posix())


def default_instruction_files(root: Path) -> list[Path]:
    return candidate_files(root, "templates/instructions/*.instructions.md", ".github/instructions/*.instructions.md")


def emit_catalogue(root: Path) -> dict[str, Any]:
    try:
        scope = metadata_host_paths(root)
        host_records = [host_declaration(path, root, kind) for path, kind in sorted(scope.items(), key=lambda item: item[0].relative_to(root.resolve()).as_posix())]
    except MetadataScopeError as exc:
        raise CapabilityEmissionError(str(exc)) from exc
    capabilities: list[dict[str, Any]] = []
    for path in default_agent_files(root):
        if path.resolve() not in scope:
            capabilities.append(emit_agent(path, root))
    for path in default_skill_files(root):
        if path.resolve() not in scope:
            capabilities.append(emit_skill(path, root))
    for path in default_instruction_files(root):
        if path.resolve() not in scope:
            capabilities.append(emit_instruction(path, root))

    by_id: dict[str, Path] = {}
    for capability in capabilities:
        capability_id = capability["id"]
        source = root / capability["source_file"]
        if capability_id in by_id:
            raise CapabilityEmissionError(
                f"duplicate capability id {capability_id}: {by_id[capability_id]} and {source}"
            )
        by_id[capability_id] = source

    capabilities.sort(key=lambda item: item["id"])
    catalogue = {
        "catalogue_version": CATALOGUE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_by": GENERATED_BY,
        "catalogue_kind": "ai_tool_surface_catalogue",
        "description": (
            "NAOS AI tool-surface catalogue emitted from agent, skill, and instruction "
            "frontmatter. This is distinct from control-plane capability contracts in "
            "capabilities/*.yaml."
        ),
        "capabilities": capabilities,
    }
    if scope:
        catalogue["host_declarations"] = host_records
    return catalogue


def render_catalogue(catalogue: dict[str, Any]) -> str:
    text = yaml.safe_dump(catalogue, sort_keys=False, allow_unicode=True, width=1000)
    return (
        f"# AUTO-GENERATED by {GENERATED_BY}. Do not edit by hand; run make -f Makefile.naos gov-refresh.\n"
        "# This is the AI tool-surface catalogue, not the control-plane capability-contract set.\n"
        f"{text}"
    )


def write_catalogue(output: Path, content: str) -> bool:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = content.encode("utf-8")
    existing = output.read_bytes() if output.exists() else None
    if existing == encoded:
        return False
    output.write_bytes(encoded)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit NAOS AI tool-surface catalogue")
    parser.add_argument("--root", default=".", metavar="PATH", help="Kit or generated project root")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        metavar="PATH",
        help="Output YAML file, relative to --root unless absolute",
    )
    parser.add_argument("--check", action="store_true", help="Verify output is current without writing")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output

    try:
        content = render_catalogue(emit_catalogue(root))
    except CapabilityEmissionError as exc:
        print(f"AI surface catalogue emission: FAIL\n  - {exc}")
        return 1

    if args.check:
        if not output.exists():
            print(f"AI surface catalogue emission: FAIL\n  - missing output: {display_path(output, root)}")
            return 1
        existing = output.read_text(encoding="utf-8")
        if existing != content:
            print(f"AI surface catalogue emission: FAIL\n  - stale output: {display_path(output, root)}")
            return 1
        print(f"AI surface catalogue emission: PASS — {display_path(output, root)} is current")
        return 0

    changed = write_catalogue(output, content)
    status = "updated" if changed else "current"
    print(f"AI surface catalogue emission: PASS — {display_path(output, root)} {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
