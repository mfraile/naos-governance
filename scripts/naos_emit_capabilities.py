#!/usr/bin/env python3
"""Emit the NAOS AI tool-surface catalogue from frontmatter."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent / "validators"))
    from frontmatter_utils import (  # type: ignore[import-not-found]
        candidate_files,
        display_path,
        is_non_empty_string,
        is_non_empty_string_list,
        parse_frontmatter,
    )
else:  # pragma: no cover - package import path
    from .validators.frontmatter_utils import (
        candidate_files,
        display_path,
        is_non_empty_string,
        is_non_empty_string_list,
        parse_frontmatter,
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

    parameters: list[dict[str, Any]] = []
    for index, entry in enumerate(value, start=1):
        if not isinstance(entry, dict):
            raise CapabilityEmissionError(f"{path}: parameter {index} must be a mapping")
        if not is_non_empty_string(entry.get("name")):
            raise CapabilityEmissionError(f"{path}: parameter {index} is missing name")
        if not is_non_empty_string(entry.get("description")):
            raise CapabilityEmissionError(f"{path}: parameter {index} is missing description")
        normalized = {
            "name": entry["name"].strip(),
            "description": entry["description"].strip(),
        }
        if "required" in entry:
            normalized["required"] = bool(entry["required"])
        if "default" in entry:
            normalized["default"] = str(entry["default"])
        parameters.append(normalized)
    return parameters


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
    return {
        "id": capability_id,
        "name": name,
        "description": description,
        "type": kind,
        "source_file": display_path(path, root),
        "status": "active",
        "schema_version": SCHEMA_VERSION,
    }


def emit_agent(path: Path, root: Path) -> dict[str, Any]:
    document = parse_frontmatter(path)
    if document.error:
        raise CapabilityEmissionError(f"{path}: {document.error}")
    if not is_non_empty_string(document.data.get("model")):
        raise CapabilityEmissionError(f"{path}: agent model must be a non-empty string")
    if not is_non_empty_string_list(document.data.get("tools")):
        raise CapabilityEmissionError(f"{path}: agent tools must be a non-empty list of strings")

    slug = agent_slug(path)
    name = document.data.get("name") if is_non_empty_string(document.data.get("name")) else f"@naos-{slug}"
    description = document.data.get("description") if is_non_empty_string(document.data.get("description")) else f"NAOS {friendly_name_from_slug(slug)} agent."
    capability = base_capability(f"CAP-A-{slugify(slug)}", name.strip(), description.strip(), "agent", path, root)
    capability["model"] = document.data["model"].strip()
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
    capability["parameters"] = normalize_parameters(document.data.get("parameters"), path)
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
    return candidate_files(root, "templates/skills/*/SKILL.md", ".github/skills/*/SKILL.md")


def default_instruction_files(root: Path) -> list[Path]:
    return candidate_files(root, "templates/instructions/*.instructions.md", ".github/instructions/*.instructions.md")


def emit_catalogue(root: Path) -> dict[str, Any]:
    capabilities: list[dict[str, Any]] = []
    for path in default_agent_files(root):
        capabilities.append(emit_agent(path, root))
    for path in default_skill_files(root):
        capabilities.append(emit_skill(path, root))
    for path in default_instruction_files(root):
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
    return {
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


def render_catalogue(catalogue: dict[str, Any]) -> str:
    text = yaml.safe_dump(catalogue, sort_keys=False, allow_unicode=True, width=1000)
    return (
        f"# AUTO-GENERATED by {GENERATED_BY}. Do not edit by hand; run make -f Makefile.naos gov-refresh.\n"
        "# This is the AI tool-surface catalogue, not the control-plane capability-contract set.\n"
        f"{text}"
    )


def write_catalogue(output: Path, content: str) -> bool:
    output.parent.mkdir(parents=True, exist_ok=True)
    existing = output.read_text(encoding="utf-8") if output.exists() else None
    if existing == content:
        return False
    output.write_text(content, encoding="utf-8")
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
