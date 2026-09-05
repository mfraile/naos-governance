#!/usr/bin/env python3
"""
generate_traceability_matrix.py - Generate enhanced bidirectional traceability matrix.

Generates naos/TRACEABILITY_MATRIX.md linking spec requirements to code files.

SECTIONS GENERATED:
    1. Executive Summary — stats (files scanned, linkages, requirements traced)
    2. Code → Requirements — forward traceability table
    3. Requirements → Code — reverse traceability table
    4. Spec ID Tags Index — {#PAIN}, {#FR}, {#SOL}, {#ARCH}, {#API} tags
    5. Architecture → Code — ARCH component ownership (if arch boundaries YAML exists)
    6. Next Steps — guidance for improving traceability

READS FROM:
    - NAOS_ROOT/TASK_REGISTRY.yaml (optional — for future extension)
    - specs/*.md — ID tag extraction
    - specs/03-requirements.md — requirement list (dynamic parse)
    - SRC_ROOT/**/*.py — code headers (Implements, Task, References, Upstream)
    - configs/naos_architecture_boundaries.yaml — ARCH component map (optional)

WRITES TO:
    - NAOS_ROOT/TRACEABILITY_MATRIX.md

ENVIRONMENT:
    NAOS_ROOT  — path to the naos/ governance folder (default: "naos")
    SRC_ROOT   — path to the source code root
                 (default: infer src, app, apps, packages, lib when present)
                 Set to "." to scan the entire project, or a comma-separated list
                 like "src,lib" to scan multiple directories.

USAGE:
    python scripts/workflows/generate_traceability_matrix.py
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Tuple

NAOS_ROOT = Path(os.getenv("NAOS_ROOT", "naos"))

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

OUT = NAOS_ROOT / "TRACEABILITY_MATRIX.md"

# Code header patterns
HEADER_RE = re.compile(r"Implements:\s*([^\n]+)")
TASK_RE = re.compile(r"Task:\s*([^\n]+)")
REFERENCES_RE = re.compile(r"References:\s*([^\n]+)")  # Future: {#ARCH-3.2}
UPSTREAM_RE = re.compile(r"Upstream:\s*([^\n]+)")  # Future: {#PAIN-2.1}

# Spec ID tag patterns
PAIN_TAG_RE = re.compile(r"\{#PAIN-(\d+\.\d+)\}")  # {#PAIN-1.1}
FR_TAG_RE = re.compile(r"\{#FR-(\d{3})-(\d{3})\}")  # {#FR-001-001}
NFR_TAG_RE = re.compile(r"\{#NFR-(\d{3})-(\d{3})\}")  # {#NFR-001-001}
SOL_TAG_RE = re.compile(r"\{#SOL-(\d+\.\d+)\}")  # {#SOL-1.1}
ARCH_TAG_RE = re.compile(r"\{#ARCH-(\d+\.?\d*)\}")  # {#ARCH-3.2} or {#ARCH-1}
API_TAG_RE = re.compile(r"\{#API-(\d+\.?\d*)\}")  # {#API-2.1} or {#API-1}

# Requirement header regex — shared, tolerant of H2/H3 (single source of truth)
import sys  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spec_header  # noqa: E402
from source_roots import resolve_source_roots  # noqa: E402

_REQ_HEADER_RE = spec_header.REQ_HEADER_RE

# ── SRC_ROOT: support inferred, single path, or comma-separated list ─────────
SRC_ROOTS = resolve_source_roots(Path.cwd())

REQUIREMENTS_SPEC = Path("specs/03-requirements.md")

# Spec files to scan for ID tags
SPEC_FILES = [
    Path("specs/01-problem.md"),
    Path("specs/02-solution.md"),
    Path("specs/03-requirements.md"),
    Path("specs/04-architecture.md"),
    Path("specs/05-api.md"),
    Path("specs/06-acceptance.md"),
    Path("specs/07-cost-analysis.md"),
    Path("specs/08-market-positioning.md"),
    Path("specs/09-integration-contract.md"),
    Path("specs/10-execution.md"),
]


def _parse_all_requirements() -> list[str]:
    """Parse ALL requirement IDs from specs/03-requirements.md dynamically.

    Matches: FR-001, FR-REG, NFR-001, etc.
    Returns sorted list of requirement IDs.
    """
    if not REQUIREMENTS_SPEC.exists():
        print(f"  ⚠️ {REQUIREMENTS_SPEC} not found, using empty requirement list")
        return []
    text = REQUIREMENTS_SPEC.read_text(encoding="utf-8")
    ids = _REQ_HEADER_RE.findall(text)
    # Sort: numeric FRs first (by number), then named FRs, then NFRs
    frs = sorted(
        [r for r in ids if r.startswith("FR-")],
        key=lambda x: (0, int(x[3:])) if x[3:].isdigit() else (1, x),
    )
    nfrs = sorted(
        [r for r in ids if r.startswith("NFR-")],
        key=lambda x: (0, int(x[4:])) if x[4:].isdigit() else (1, x),
    )
    return frs + nfrs


# Dynamically parsed from specs — no hardcoded lists
ALL_REQUIREMENTS = _parse_all_requirements()


def extract_spec_tags() -> Dict[str, Dict[str, List[str]]]:
    """Extract all ID tags from spec files.

    Returns: {
        "PAIN": {"1.1": ["specs/01-problem.md"], ...},
        "FR": {"001-001": ["specs/03-requirements.md"], ...},
        "SOL": {"1.1": ["specs/02-solution.md"], ...},
        "ARCH": {"3.2": ["specs/04-architecture.md"], ...},
        "API": {"2.1": ["specs/05-api.md"], ...}
    }
    """
    tags: Dict[str, Dict[str, List[str]]] = {
        "PAIN": defaultdict(list),
        "FR": defaultdict(list),
        "NFR": defaultdict(list),
        "SOL": defaultdict(list),
        "ARCH": defaultdict(list),
        "API": defaultdict(list),
    }

    for spec_file in SPEC_FILES:
        if not spec_file.exists():
            continue

        text = spec_file.read_text(encoding="utf-8", errors="ignore")

        for match in PAIN_TAG_RE.finditer(text):
            tags["PAIN"][match.group(1)].append(str(spec_file))
        for match in FR_TAG_RE.finditer(text):
            tag_id = f"{match.group(1)}-{match.group(2)}"
            tags["FR"][tag_id].append(str(spec_file))
        for match in NFR_TAG_RE.finditer(text):
            tag_id = f"{match.group(1)}-{match.group(2)}"
            tags["NFR"][tag_id].append(str(spec_file))
        for match in SOL_TAG_RE.finditer(text):
            tags["SOL"][match.group(1)].append(str(spec_file))
        for match in ARCH_TAG_RE.finditer(text):
            tags["ARCH"][match.group(1)].append(str(spec_file))
        for match in API_TAG_RE.finditer(text):
            tags["API"][match.group(1)].append(str(spec_file))

    # Deduplicate file lists
    for tag_type in tags:
        for tag_id in tags[tag_type]:
            tags[tag_type][tag_id] = sorted(set(tags[tag_type][tag_id]))

    return tags


def parse_code_files() -> List[Tuple[str, List[str], str, List[str], List[str]]]:
    """Parse all Python files in SRC_ROOTS for header information.

    Returns: [(file_path, requirements, tasks, references, upstream), ...]
    """
    rows = []
    # Preserve host source under scripts/ while also scanning the generated
    # NAOS tool namespace used by the brownfield layout adapter.
    extra_roots = [Path("scripts"), Path("naos_tools")]
    all_roots = list(SRC_ROOTS) + [r for r in extra_roots if r not in SRC_ROOTS]

    for root in all_roots:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            if py.name == "__init__.py":
                continue

            text = py.read_text(encoding="utf-8", errors="ignore")
            reqs = []
            tasks = []
            refs = []
            upstream = []

            # Implements: FR-001, FR-002 (Description)
            m1 = HEADER_RE.search(text)
            if m1:
                raw_reqs = m1.group(1).split(",")
                for req in raw_reqs:
                    req_match = re.search(
                        r"((?:FR|NFR)-[A-Z0-9]+(?:-ENHANCED)?)", req.strip()
                    )
                    if req_match:
                        reqs.append(req_match.group(1))

            # Task: T-001, T-002
            m2 = TASK_RE.search(text)
            if m2:
                tasks = [t.strip() for t in m2.group(1).split(",")]

            # References: {#ARCH-3.2}, {#API-2.1} (future support)
            m3 = REFERENCES_RE.search(text)
            if m3:
                refs = re.findall(r"\{#[A-Z]+-[\d\.]+\}", m3.group(1))

            # Upstream: {#PAIN-2.1}, {#SOL-3.1} (future support)
            m4 = UPSTREAM_RE.search(text)
            if m4:
                upstream = re.findall(r"\{#[A-Z]+-[\d\.]+\}", m4.group(1))

            rows.append((str(py), reqs, tasks, refs, upstream))

    return rows


def build_requirement_index(
    code_rows: List[Tuple[str, List[str], str, List[str], List[str]]],
) -> Dict[str, List[str]]:
    """Build reverse index: Requirement → [Files].

    Returns: {"FR-001": ["src/file1.py", "src/file2.py"], ...}
    """
    req_index: Dict[str, List[str]] = defaultdict(list)
    for file_path, reqs, _, _, _ in code_rows:
        for req in reqs:
            req_index[req].append(file_path)
    return req_index


# ---------------------------------------------------------------------------
# ARCH → Code mapping (optional — requires configs/naos_architecture_boundaries.yaml)
# ---------------------------------------------------------------------------

ARCH_BOUNDARIES_YAML = Path("configs/naos_architecture_boundaries.yaml")
_ARCH_CODE_RE = re.compile(r"ARCH-(\d+(?:\.\d+)?)")


def _collect_src_py_files() -> list[str]:
    """Return relative paths for all *.py files in SRC_ROOTS (excluding __init__.py)."""
    paths = []
    for root in SRC_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*.py"):
            if p.name != "__init__.py":
                paths.append(str(p))
    return sorted(paths)


def build_arch_code_index() -> tuple[
    dict[str, dict], dict[str, list[str]], dict[str, list[str]]
]:
    """Build ARCH → Code mapping using naos_architecture_boundaries.yaml.

    Returns:
        arch_components: {id: {description, affected_modules, ...}}
        arch_to_files: {ARCH-N: [files matched by globs]}
        arch_refs_in_code: {ARCH-N: [files with ARCH-N in header]}
    """
    if not ARCH_BOUNDARIES_YAML.exists() or yaml is None:
        return {}, {}, {}

    with open(ARCH_BOUNDARIES_YAML, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    components = data.get("arch_components", {})
    all_py = _collect_src_py_files()

    # 1) Glob-based: which files are "owned" by each ARCH component
    arch_to_files: dict[str, list[str]] = {}
    for arch_id, info in components.items():
        globs = info.get("affected_modules", [])
        matched = []
        for py in all_py:
            if any(fnmatch(py, g) for g in globs):
                matched.append(py)
        arch_to_files[arch_id] = matched

    # 2) Header-based: which files explicitly reference ARCH-N
    arch_refs_in_code: dict[str, list[str]] = defaultdict(list)
    for py in all_py:
        try:
            text = Path(py).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Only check first ~60 lines (header area)
        header = "\n".join(text.splitlines()[:60])
        for m in _ARCH_CODE_RE.finditer(header):
            arch_refs_in_code[f"ARCH-{m.group(1)}"].append(py)

    return components, arch_to_files, dict(arch_refs_in_code)


def render_enhanced_matrix(
    code_rows: List[Tuple[str, List[str], str, List[str], List[str]]],
    spec_tags: Dict[str, Dict[str, List[str]]],
    req_index: Dict[str, List[str]],
    arch_components: dict[str, dict] | None = None,
    arch_to_files: dict[str, list[str]] | None = None,
    arch_refs_in_code: dict[str, list[str]] | None = None,
) -> str:
    """Render enhanced traceability matrix with multiple sections."""
    generated_date = datetime.now(UTC).date().isoformat()

    frs_in_scope = [r for r in ALL_REQUIREMENTS if r.startswith("FR-")]
    nfrs_in_scope = [r for r in ALL_REQUIREMENTS if r.startswith("NFR-")]
    req_summary = f"{len(ALL_REQUIREMENTS)} ({len(frs_in_scope)} FRs + {len(nfrs_in_scope)} NFRs — parsed from specs)"

    lines = [
        "<!-- ⚠️ AUTO-GENERATED FILE — DO NOT EDIT MANUALLY. Regenerate with: make -f Makefile.naos gov-refresh -->",
        "",
        "# Enhanced Traceability Matrix",
        "",
        "**Version**: 3.0.0 (Dynamic Requirement Parsing)",
        f"**Generated**: {generated_date}",
        f"**Requirements**: {req_summary}",
        "**ID Tagging System**: ✅ Enabled",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Calculate statistics
    total_files = len(code_rows)
    if total_files == 0:
        lines.extend(["_No code files found in SRC_ROOT. Set SRC_ROOT env var._", ""])
        return "\n".join(lines)

    files_with_reqs = sum(1 for _, reqs, _, _, _ in code_rows if reqs)
    total_linkages = sum(len(reqs) for _, reqs, _, _, _ in code_rows)
    reqs_with_code = len([req for req in ALL_REQUIREMENTS if req in req_index])
    reqs_total = len(ALL_REQUIREMENTS) or 1  # avoid division by zero

    lines.extend(
        [
            f"- **Total Code Files**: {total_files}",
            f"- **Files with Requirements**: {files_with_reqs} ({files_with_reqs / total_files * 100:.1f}%)",
            f"- **Total Linkages**: {total_linkages}",
            f"- **Requirements Traced**: {reqs_with_code}/{len(ALL_REQUIREMENTS)} ({reqs_with_code / reqs_total * 100:.1f}%)",
            f"- **Spec ID Tags Extracted**: {sum(len(tags) for tags in spec_tags.values())}",
            "",
            "---",
            "",
            "## 1. Code → Requirements (Forward Traceability)",
            "",
            "| File | Requirements | Tasks | References (Future) | Upstream (Future) |",
            "|------|--------------|-------|---------------------|-------------------|",
        ]
    )

    for file_path, reqs, tasks, refs, upstream in sorted(code_rows, key=lambda x: x[0]):
        reqs_str = ", ".join(reqs) if reqs else "-"
        tasks_str = ", ".join(tasks) if tasks else "-"
        refs_str = ", ".join(refs) if refs else "-"
        upstream_str = ", ".join(upstream) if upstream else "-"
        lines.append(
            f"| {file_path} | {reqs_str} | {tasks_str} | {refs_str} | {upstream_str} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 2. Requirements → Code (Reverse Traceability)",
            "",
            "| Requirement | Status | Files Implementing | Count |",
            "|-------------|--------|--------------------|-------|",
        ]
    )

    for req in ALL_REQUIREMENTS:
        files = req_index.get(req, [])
        status = "✅ Traced" if files else "⚠️ Not Implemented"
        files_str = "<br>".join(files[:3])
        if len(files) > 3:
            files_str += f"<br>_...and {len(files) - 3} more_"
        if not files:
            files_str = "-"
        lines.append(f"| {req} | {status} | {files_str} | {len(files)} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 3. Spec ID Tags Index (Bidirectional Links)",
            "",
            "### Pain Points ({#PAIN-X.X})",
            "",
            "| Tag | Spec Files |",
            "|-----|------------|",
        ]
    )

    for tag_id in sorted(spec_tags["PAIN"].keys()):
        files = spec_tags["PAIN"][tag_id]
        lines.append(f"| {{#PAIN-{tag_id}}} | {', '.join(files)} |")

    lines.extend(
        [
            "",
            "### Functional Requirements ({#FR-XXX-XXX})",
            "",
            "| Tag | Spec Files |",
            "|-----|------------|",
        ]
    )

    for tag_id in sorted(spec_tags["FR"].keys()):
        files = spec_tags["FR"][tag_id]
        lines.append(f"| {{#FR-{tag_id}}} | {', '.join(files)} |")

    lines.extend(
        [
            "",
            "### Solutions ({#SOL-X.X})",
            "",
            "| Tag | Spec Files |",
            "|-----|------------|",
        ]
    )

    for tag_id in sorted(spec_tags["SOL"].keys()):
        files = spec_tags["SOL"][tag_id]
        lines.append(f"| {{#SOL-{tag_id}}} | {', '.join(files)} |")

    lines.extend(
        [
            "",
            "### Architecture Components ({#ARCH-X.X})",
            "",
            "| Tag | Spec Files |",
            "|-----|------------|",
        ]
    )

    for tag_id in sorted(
        spec_tags["ARCH"].keys(),
        key=lambda x: float(x) if x.replace(".", "", 1).isdigit() else 9999,
    ):
        files = spec_tags["ARCH"][tag_id]
        lines.append(f"| {{#ARCH-{tag_id}}} | {', '.join(files)} |")

    lines.extend(
        [
            "",
            "### API Endpoints ({#API-X.X})",
            "",
            "| Tag | Spec Files |",
            "|-----|------------|",
        ]
    )

    for tag_id in sorted(
        spec_tags["API"].keys(),
        key=lambda x: float(x) if x.replace(".", "", 1).isdigit() else 9999,
    ):
        files = spec_tags["API"][tag_id]
        lines.append(f"| {{#API-{tag_id}}} | {', '.join(files)} |")

    lines.extend(["", "---", ""])

    # ---- Section 4: ARCH → Code ----
    if arch_components and arch_to_files is not None:
        _arch_refs = arch_refs_in_code or {}
        total_arch = len(arch_components)
        arch_with_code = sum(1 for flist in arch_to_files.values() if flist)
        arch_with_refs = sum(
            1 for aid in arch_components if aid in _arch_refs and _arch_refs[aid]
        )
        pct_code = arch_with_code / total_arch * 100 if total_arch else 0
        pct_refs = arch_with_refs / total_arch * 100 if total_arch else 0

        lines.extend(
            [
                "## 4. Architecture → Code (ARCH Ownership)",
                "",
                f"- **ARCH Components Mapped**: {total_arch}",
                f"- **With Matching Source Files**: {arch_with_code}/{total_arch} ({pct_code:.1f}%)",
                f"- **With Explicit ARCH-N Refs in Code**: {arch_with_refs}/{total_arch} ({pct_refs:.1f}%)",
                "",
                "| ARCH ID | Description | Matched Files | Files w/ ARCH Ref | Coverage |",
                "|---------|-------------|:-------------:|:-----------------:|:--------:|",
            ]
        )

        def _sort_arch(aid: str) -> int:
            m = re.search(r"(\d+)", aid)
            return int(m.group(1)) if m else 0

        for arch_id in sorted(arch_components.keys(), key=_sort_arch):
            info = arch_components[arch_id]
            desc = info.get("description", "-")[:60]
            matched = arch_to_files.get(arch_id, [])
            refs = _arch_refs.get(arch_id, [])
            if matched:
                cov = "✅" if refs else "⚠️ No refs"
            else:
                cov = "❌ No files"
            lines.append(
                f"| {arch_id} | {desc} | {len(matched)} | {len(refs)} | {cov} |"
            )

        lines.extend(["", "---", ""])
    else:
        lines.extend(
            [
                "## 4. Architecture → Code (ARCH Ownership)",
                "",
                "_Architecture boundaries YAML not found — section skipped._",
                "_Create `configs/naos_architecture_boundaries.yaml` to enable this section._",
                "",
                "---",
                "",
            ]
        )

    # ---- Section 5: Next Steps ----
    lines.extend(
        [
            "## 5. Next Steps: Enhanced Code Headers",
            "",
            "**Current State**: Code files use basic headers (Implements, Task)",
            "",
            "**Target State**: Add References and Upstream fields for full bidirectional traceability:",
            "",
            "```python",
            '"""',
            "Implements: FR-001 (Core Feature), FR-016 (Multi-Tenant)",
            "Task: T-001, T-019",
            "References: {#ARCH-3.2} (Discovery Engine), {#API-2.1} (API endpoint)",
            "Upstream: {#PAIN-2.1} (Problem), {#SOL-3.1} (Solution)",
            "Specs: specs/03-requirements.md, specs/04-architecture.md",
            "Rationale: Core service with multi-tenant isolation",
            '"""',
            "```",
            "",
            "**Benefits**:",
            "- Full traceability chain: Pain → Requirement → Solution → Architecture → API → Code",
            "- Bidirectional links enable impact analysis (change propagation)",
            "- Enhanced PM governance metrics (TRACEABILITY_MATRIX.md becomes source of truth)",
            "",
        ]
    )

    return "\n".join(lines)


def main() -> int:
    print("Extracting spec ID tags...")
    spec_tags = extract_spec_tags()

    print("Parsing code files...")
    code_rows = parse_code_files()

    print("Building requirement index...")
    req_index = build_requirement_index(code_rows)

    print("Building ARCH → Code index...")
    arch_components, arch_to_files, arch_refs_in_code = build_arch_code_index()
    if arch_components:
        print(f"   - {len(arch_components)} ARCH components loaded")

    print("Rendering enhanced matrix...")
    content = render_enhanced_matrix(
        code_rows,
        spec_tags,
        req_index,
        arch_components=arch_components,
        arch_to_files=arch_to_files,
        arch_refs_in_code=arch_refs_in_code,
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(content, encoding="utf-8")
    print(f"\n✅ Wrote {OUT}")
    print(f"   - {len(code_rows)} code files analyzed")
    print(f"   - {sum(len(reqs) for _, reqs, _, _, _ in code_rows)} total linkages")
    print(
        f"   - {sum(len(tags) for tags in spec_tags.values())} spec ID tags extracted"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
