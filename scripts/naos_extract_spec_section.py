#!/usr/bin/env python3
"""
Spec Section Extraction Tool.

Portable governance script — path-parameterized via NAOS_ROOT env var.
Extracts task-relevant spec sections into context-window-sized chunks (≤5 KB)
for agent consumption.

Usage:
    python scripts/naos_extract_spec_section.py --fr FR-023
    python scripts/naos_extract_spec_section.py --arch ARCH-5
    python scripts/naos_extract_spec_section.py --api "/api/v1/events"
    python scripts/naos_extract_spec_section.py --list-requirements

Environment variables:
    NAOS_ROOT   Path to the naos/ governance directory (default: naos)
"""

import argparse
import os
import re
from pathlib import Path

import yaml

# Regex for FR/NFR heading detection
_REQ_HEADER_RE = re.compile(r"^## ((?:FR|NFR)-[A-Z0-9]+(?:-ENHANCED)?):", re.MULTILINE)

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
NAOS_ROOT = PROJECT_ROOT / os.getenv("NAOS_ROOT", "naos")
REQUIREMENTS_SPEC = PROJECT_ROOT / "specs" / "03-requirements.md"
ARCHITECTURE_SPEC = PROJECT_ROOT / "specs" / "04-architecture.md"
API_SPEC = PROJECT_ROOT / "specs" / "05-api.md"
BOUNDARIES_CONFIG = PROJECT_ROOT / "configs" / "naos_architecture_boundaries.yaml"

MAX_OUTPUT_BYTES = 5 * 1024  # 5 KB limit


def _truncate(
    text: str, max_bytes: int = MAX_OUTPUT_BYTES, source_ref: str = ""
) -> str:
    """Truncate text to max_bytes with a pointer to the full source."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    last_newline = truncated.rfind("\n")
    if last_newline > 0:
        truncated = truncated[:last_newline]
    if source_ref:
        truncated += f"\n\n[... truncated — see {source_ref} for full content]"
    return truncated


def extract_fr(fr_id: str) -> str:
    """Extract a requirement section from specs/03-requirements.md.

    Finds the ## FR-XXX: heading and extracts everything until the next ## heading.
    """
    if not REQUIREMENTS_SPEC.exists():
        return f"ERROR: {REQUIREMENTS_SPEC} not found"

    text = REQUIREMENTS_SPEC.read_text(encoding="utf-8")
    lines = text.split("\n")

    pattern = re.compile(rf"^## {re.escape(fr_id)}:", re.IGNORECASE)
    start_line = None
    for i, line in enumerate(lines):
        if pattern.match(line):
            start_line = i
            break

    if start_line is None:
        available = _REQ_HEADER_RE.findall(text)
        return (
            f"ERROR: {fr_id} not found in {REQUIREMENTS_SPEC}\n"
            f"Available: {', '.join(available[:20])}"
        )

    end_line = len(lines)
    for i in range(start_line + 1, len(lines)):
        if lines[i].startswith("## "):
            end_line = i
            break

    section = "\n".join(lines[start_line:end_line]).strip()
    source_ref = f"{REQUIREMENTS_SPEC} lines {start_line + 1}-{end_line}"
    return _truncate(section, source_ref=source_ref)


def extract_arch(arch_id: str) -> str:
    """Extract ARCH component constraints from naos_architecture_boundaries.yaml.

    Falls back to searching specs/04-architecture.md if not in YAML.
    """
    if not arch_id.startswith("ARCH-"):
        arch_id = f"ARCH-{arch_id}"

    result_parts: list[str] = []

    # 1. Check naos_architecture_boundaries.yaml for machine-readable constraints
    if BOUNDARIES_CONFIG.exists():
        with open(BOUNDARIES_CONFIG, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        components = config.get("arch_components", {})
        if arch_id in components:
            comp = components[arch_id]
            result_parts.append(f"# {arch_id}: {comp.get('description', '')}")
            result_parts.append("")
            if comp.get("affected_modules"):
                result_parts.append("## Affected Modules")
                for mod in comp["affected_modules"]:
                    result_parts.append(f"- `{mod}`")
                result_parts.append("")
            if comp.get("constraints"):
                result_parts.append("## Constraints")
                for c in comp["constraints"]:
                    result_parts.append(f"- {c}")
                result_parts.append("")
            if comp.get("spec_ref"):
                result_parts.append(f"**Spec reference**: {comp['spec_ref']}")
                result_parts.append("")

    # 2. Also extract from specs/04-architecture.md
    if ARCHITECTURE_SPEC.exists():
        text = ARCHITECTURE_SPEC.read_text(encoding="utf-8")
        lines = text.split("\n")

        pattern = re.compile(rf"^##+ .*{re.escape(arch_id)}", re.IGNORECASE)
        start_line = None
        for i, line in enumerate(lines):
            if pattern.match(line):
                start_line = i
                break

        if start_line is not None:
            heading_level = len(lines[start_line]) - len(lines[start_line].lstrip("#"))
            end_line = min(start_line + 80, len(lines))
            for i in range(start_line + 1, min(start_line + 200, len(lines))):
                if lines[i].startswith("#"):
                    current_level = len(lines[i]) - len(lines[i].lstrip("#"))
                    if current_level <= heading_level:
                        end_line = i
                        break

            spec_section = "\n".join(lines[start_line:end_line]).strip()
            result_parts.append("## Spec Excerpt")
            result_parts.append(
                f"_From specs/04-architecture.md lines {start_line + 1}-{end_line}_"
            )
            result_parts.append("")
            result_parts.append(spec_section)

    if not result_parts:
        return f"ERROR: {arch_id} not found in boundaries config or architecture spec"

    output = "\n".join(result_parts)
    return _truncate(output, source_ref=f"specs/04-architecture.md ({arch_id})")


def extract_api(endpoint: str) -> str:
    """Extract API spec section for a given endpoint from specs/05-api.md."""
    if not API_SPEC.exists():
        return f"ERROR: {API_SPEC} not found"

    text = API_SPEC.read_text(encoding="utf-8")
    lines = text.split("\n")

    escaped = re.escape(endpoint)
    pattern = re.compile(rf"{escaped}", re.IGNORECASE)

    start_line = None
    for i, line in enumerate(lines):
        if pattern.search(line):
            for j in range(i, max(i - 10, 0), -1):
                if lines[j].startswith("#"):
                    start_line = j
                    break
            if start_line is None:
                start_line = max(0, i - 3)
            break

    if start_line is None:
        return f"ERROR: Endpoint '{endpoint}' not found in {API_SPEC}"

    heading_level = 0
    if lines[start_line].startswith("#"):
        heading_level = len(lines[start_line]) - len(lines[start_line].lstrip("#"))

    end_line = min(start_line + 80, len(lines))
    if heading_level > 0:
        for i in range(start_line + 1, min(start_line + 200, len(lines))):
            if lines[i].startswith("#"):
                current_level = len(lines[i]) - len(lines[i].lstrip("#"))
                if current_level <= heading_level:
                    end_line = i
                    break

    section = "\n".join(lines[start_line:end_line]).strip()
    source_ref = f"{API_SPEC} lines {start_line + 1}-{end_line}"
    return _truncate(section, source_ref=source_ref)


def list_requirements() -> str:
    """List all FR/NFR IDs from specs/03-requirements.md."""
    if not REQUIREMENTS_SPEC.exists():
        return f"ERROR: {REQUIREMENTS_SPEC} not found"

    text = REQUIREMENTS_SPEC.read_text(encoding="utf-8")
    ids = _REQ_HEADER_RE.findall(text)
    frs = sorted(
        [r for r in ids if r.startswith("FR-")],
        key=lambda x: (0, int(x[3:])) if x[3:].isdigit() else (1, x),
    )
    nfrs = sorted(
        [r for r in ids if r.startswith("NFR-")],
        key=lambda x: (0, int(x[4:])) if x[4:].isdigit() else (1, x),
    )
    return f"FRs ({len(frs)}): {', '.join(frs)}\nNFRs ({len(nfrs)}): {', '.join(nfrs)}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract spec sections for agent context",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scripts/naos_extract_spec_section.py --fr FR-023
  python scripts/naos_extract_spec_section.py --arch ARCH-5
  python scripts/naos_extract_spec_section.py --api "/api/v1/events"
  python scripts/naos_extract_spec_section.py --list-requirements""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fr", help="Extract FR/NFR section (e.g., FR-023, NFR-001)")
    group.add_argument(
        "--arch", help="Extract ARCH component constraints (e.g., ARCH-5)"
    )
    group.add_argument(
        "--api", help="Extract API spec for endpoint (e.g., /api/v1/events)"
    )
    group.add_argument(
        "--list-requirements", action="store_true", help="List all FR/NFR IDs"
    )

    args = parser.parse_args()

    if args.fr:
        print(extract_fr(args.fr))
    elif args.arch:
        print(extract_arch(args.arch))
    elif args.api:
        print(extract_api(args.api))
    elif args.list_requirements:
        print(list_requirements())


if __name__ == "__main__":
    main()
