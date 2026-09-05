#!/usr/bin/env python3
"""
Spec-Code Drift Detection Tool.

Portable governance script — path-parameterized via NAOS_ROOT / SRC_ROOT env vars.

Compares 'Implements: FR-XXX' headers in source files against TASK_REGISTRY.yaml
and specs/03-requirements.md to detect spec-code drift.

Detections:
    1. Orphan headers — 'Implements: FR-XXX' in source but FR-XXX not in specs
    2. Overloaded FRs — Single FR referenced by >N files (catch-all pollution)
    3. Stale status — Spec says IMPLEMENTED but registry still has planned tasks
    4. Uncovered requirements — FR/NFR in spec with no source implementation header
    5. Untraced source — source files with no Implements:/FR reference
    6. Unresolved source references — FR/NFR/AC/SCEN ids in source text that
       are not defined in specs

Usage:
    python scripts/naos_detect_spec_drift.py
    python scripts/naos_detect_spec_drift.py --overload-threshold 15
    python scripts/naos_detect_spec_drift.py --json
    python scripts/naos_detect_spec_drift.py --profile standard --strict --json

Environment variables:
    NAOS_ROOT   Path to the naos/ governance directory (default: naos)
    SRC_ROOT    Path to source directory or comma-separated source directories
                (default: infer src, app, apps, packages, lib when present)
    SPECS_ROOT  Path to the specs directory (default: specs)
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path.cwd()
NAOS_ROOT = PROJECT_ROOT / os.getenv("NAOS_ROOT", "naos")
SPECS_ROOT = PROJECT_ROOT / os.getenv("SPECS_ROOT", "specs")
SCRIPT_SCAN_DIRS = [PROJECT_ROOT / "scripts", PROJECT_ROOT / "naos_tools"]
REQUIREMENTS_SPEC = SPECS_ROOT / "03-requirements.md"
TASK_REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"

EXCLUDE_PATTERNS = ["__pycache__", ".pyc", "migrations", "alembic"]

# Shared helpers (single source of truth across cascade scripts)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_roots import resolve_source_roots  # noqa: E402


SRC_DIRS = resolve_source_roots(PROJECT_ROOT, os.getenv("SRC_ROOT"), absolute=True)
SRC_DIR = SRC_DIRS[0] if SRC_DIRS else PROJECT_ROOT / "src"

# Shared requirement-header parser (single source of truth across cascade scripts)
import spec_header  # noqa: E402
from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

_REQ_HEADER_RE = spec_header.REQ_HEADER_RE
_IMPLEMENTS_RE = spec_header.IMPLEMENTS_RE
_FR_TOKEN_RE = spec_header.FR_TOKEN_RE
_AC_SCEN_TOKEN_RE = re.compile(
    r"\b((?:AC|SCEN)-[A-Z0-9][A-Z0-9_.-]*)\b",
    re.IGNORECASE,
)

DEFAULT_OVERLOAD_THRESHOLD = 20


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DriftReport:
    """Structured drift detection report."""

    orphan_headers: list[dict[str, Any]] = field(default_factory=list)
    overloaded_frs: list[dict[str, Any]] = field(default_factory=list)
    stale_statuses: list[dict[str, Any]] = field(default_factory=list)
    uncovered_requirements: list[str] = field(default_factory=list)
    untraced_sources: list[str] = field(default_factory=list)
    unresolved_source_references: list[dict[str, Any]] = field(default_factory=list)
    files_scanned: int = 0
    frs_in_spec: int = 0
    frs_in_source: int = 0
    ac_scen_in_spec: int = 0

    @property
    def total_issues(self) -> int:
        return (
            len(self.orphan_headers)
            + len(self.overloaded_frs)
            + len(self.stale_statuses)
            + len(self.uncovered_requirements)
            + len(self.untraced_sources)
            + len(self.unresolved_source_references)
        )


def configure_paths(
    root: Path,
    naos_root: str,
    src_root: str | None,
    specs_root: str,
) -> None:
    """Set project paths for script execution in a kit or generated adopter."""
    global PROJECT_ROOT, NAOS_ROOT, SRC_DIRS, SRC_DIR, SPECS_ROOT, SCRIPT_SCAN_DIRS
    global REQUIREMENTS_SPEC, TASK_REGISTRY_PATH
    PROJECT_ROOT = root
    NAOS_ROOT = PROJECT_ROOT / naos_root
    SRC_DIRS = resolve_source_roots(PROJECT_ROOT, src_root, absolute=True)
    SRC_DIR = SRC_DIRS[0] if SRC_DIRS else PROJECT_ROOT / "src"
    SPECS_ROOT = PROJECT_ROOT / specs_root
    SCRIPT_SCAN_DIRS = [PROJECT_ROOT / "scripts", PROJECT_ROOT / "naos_tools"]
    REQUIREMENTS_SPEC = SPECS_ROOT / "03-requirements.md"
    TASK_REGISTRY_PATH = NAOS_ROOT / "TASK_REGISTRY.yaml"


def source_dirs_label() -> str:
    return ", ".join(path_display(path) for path in SRC_DIRS)


def path_display(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def load_canonical_frs() -> set[str]:
    """Load all FR/NFR IDs defined in specs/03-requirements.md."""
    if not REQUIREMENTS_SPEC.exists():
        print(f"WARNING: {REQUIREMENTS_SPEC} not found", file=sys.stderr)
        return set()
    text = REQUIREMENTS_SPEC.read_text(encoding="utf-8")
    return spec_header.canonical_frs(text)


def load_spec_statuses() -> dict[str, str]:
    """Load FR/NFR → status mapping from specs/03-requirements.md."""
    if not REQUIREMENTS_SPEC.exists():
        return {}
    text = REQUIREMENTS_SPEC.read_text(encoding="utf-8")
    return spec_header.spec_statuses(text)


def load_defined_ac_scen_ids() -> set[str]:
    """Load AC/SCEN ids defined anywhere under specs/.

    Gate 10c keeps the test-only AC/SCEN check. This source-level scan reuses
    the same deterministic idea, but treats missing AC/SCEN definitions as a
    no-op to avoid blocking early projects before acceptance ids exist.
    """
    defined: set[str] = set()
    if not SPECS_ROOT.exists():
        return defined
    for md in sorted(SPECS_ROOT.rglob("*.md")):
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        defined.update(match.upper() for match in _AC_SCEN_TOKEN_RE.findall(text))
    return defined


# ---------------------------------------------------------------------------
# TASK_REGISTRY parsing
# ---------------------------------------------------------------------------


def load_task_registry() -> dict[str, dict[str, Any]]:
    """Load TASK_REGISTRY.yaml and return task_id → task dict mapping."""
    if not TASK_REGISTRY_PATH.exists():
        print(f"WARNING: {TASK_REGISTRY_PATH} not found", file=sys.stderr)
        return {}
    try:
        import yaml
    except ImportError:
        print(
            "WARNING: PyYAML not installed, skipping registry checks", file=sys.stderr
        )
        return {}
    with open(TASK_REGISTRY_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    tasks = data.get("tasks", data)
    if isinstance(tasks, list):
        return {t.get("id", f"unknown-{i}"): t for i, t in enumerate(tasks)}
    if isinstance(tasks, dict):
        return tasks
    return {}


def get_requirement_task_statuses(
    registry: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Map FR/NFR → list of task statuses from the registry."""
    fr_tasks: dict[str, list[str]] = defaultdict(list)
    for task_id, task in registry.items():
        req = task.get("requirement", "")
        status = task.get("status", "unknown")
        if req:
            for fr_id in _FR_TOKEN_RE.findall(req):
                fr_tasks[fr_id].append(status)
    return dict(fr_tasks)


# ---------------------------------------------------------------------------
# Source scanning
# ---------------------------------------------------------------------------


def _get_header_area(source: str) -> str:
    """Extract the header area (first 60 lines, extended for long docstrings)."""
    lines = source.split("\n")
    header_end = 60
    try:
        tree = ast.parse(source)
        if tree.body and isinstance(tree.body[0], ast.Expr) and ast.get_docstring(tree) is not None:
            doc_end = getattr(tree.body[0], "end_lineno", None) or 60
            if doc_end > header_end:
                header_end = doc_end + 5
    except SyntaxError:
        pass
    return "\n".join(lines[:header_end])


def scan_source_files() -> dict[str, list[str]]:
    """Scan configured source roots and scripts/ for Implements: headers.

    Returns FR/NFR → list of file paths mapping.
    """
    fr_files: dict[str, list[str]] = defaultdict(list)

    roots = [*SRC_DIRS, *SCRIPT_SCAN_DIRS]
    for root in roots:
        if not root.exists():
            continue
        for py_file in sorted(root.rglob("*.py")):
            if py_file.name == "__init__.py":
                continue
            if any(pat in str(py_file) for pat in EXCLUDE_PATTERNS):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            header_area = _get_header_area(source)
            for match in _IMPLEMENTS_RE.finditer(header_area):
                line = match.group(1)
                for token in _FR_TOKEN_RE.findall(line):
                    token = token.upper()
                    if "XXX" in token:
                        continue
                    rel_path = str(py_file.relative_to(PROJECT_ROOT))
                    fr_files[token].append(rel_path)

    return dict(fr_files)


def scan_untraced_sources() -> list[str]:
    """Return app source files that carry no Implements:/FR reference at all.

    These are silently invisible to traceability and orphan detection — the
    cascade depends on header discipline, so surfacing untraced source closes
    that hole and makes the profile policy decide severity/exit behavior.
    """
    untraced: list[str] = []
    for root in SRC_DIRS:
        if not root.exists():
            continue
        for py_file in sorted(root.rglob("*.py")):
            if py_file.name == "__init__.py":
                continue
            if any(pat in str(py_file) for pat in EXCLUDE_PATTERNS):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            header_area = _get_header_area(source)
            if not _IMPLEMENTS_RE.search(header_area) and not spec_header.FR_TOKEN_RE.search(
                header_area
            ):
                untraced.append(str(py_file.relative_to(PROJECT_ROOT)))
    return untraced


def iter_project_source_files() -> list[Path]:
    """Return configured application source files for free-text reference checks."""
    files: list[Path] = []
    for root in SRC_DIRS:
        if not root.exists():
            continue
        for py_file in sorted(root.rglob("*.py")):
            if py_file.name == "__init__.py":
                continue
            if any(pat in str(py_file) for pat in EXCLUDE_PATTERNS):
                continue
            files.append(py_file)
    return files


def scan_unresolved_source_references(
    canonical_frs: set[str],
    defined_ac_scen: set[str],
) -> list[dict[str, Any]]:
    """Find FR/NFR/AC/SCEN ids in application source that are not spec-defined.

    This scans configured app source roots only. NAOS governance scripts can contain
    examples, regexes, and external-control ids that are not adopter app
    requirements; scanning them as free-text source would create false positives.
    """
    findings: list[dict[str, Any]] = []
    check_frs = bool(canonical_frs)
    check_ac_scen = bool(defined_ac_scen)
    if not (check_frs or check_ac_scen):
        return findings

    for py_file in iter_project_source_files():
        try:
            lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel_path = str(py_file.relative_to(PROJECT_ROOT))
        for line_number, line in enumerate(lines, start=1):
            is_implements_line = _IMPLEMENTS_RE.search(line) is not None
            if check_frs and not is_implements_line:
                for token in _FR_TOKEN_RE.findall(line):
                    reference_id = token.upper()
                    if "XXX" in reference_id:
                        continue
                    if reference_id not in canonical_frs:
                        findings.append(
                            {
                                "reference_id": reference_id,
                                "reference_type": "FR/NFR",
                                "file": rel_path,
                                "line": line_number,
                                "issue": (
                                    f"{reference_id} appears in source text but is not defined "
                                    "in specs/03-requirements.md"
                                ),
                            }
                        )
            if check_ac_scen:
                for token in _AC_SCEN_TOKEN_RE.findall(line):
                    reference_id = token.upper()
                    if "XXX" in reference_id:
                        continue
                    if reference_id not in defined_ac_scen:
                        findings.append(
                            {
                                "reference_id": reference_id,
                                "reference_type": "AC/SCEN",
                                "file": rel_path,
                                "line": line_number,
                                "issue": (
                                    f"{reference_id} appears in source text but is not defined "
                                    "under specs/"
                                ),
                            }
                        )
    return findings


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------


def detect_drift(overload_threshold: int = DEFAULT_OVERLOAD_THRESHOLD) -> DriftReport:
    """Run all drift detections and return a structured report."""
    report = DriftReport()

    canonical_frs = load_canonical_frs()
    defined_ac_scen = load_defined_ac_scen_ids()
    spec_statuses = load_spec_statuses()
    registry = load_task_registry()
    fr_task_statuses = get_requirement_task_statuses(registry)
    fr_files = scan_source_files()

    report.frs_in_spec = len(canonical_frs)
    report.frs_in_source = len(fr_files)
    report.ac_scen_in_spec = len(defined_ac_scen)

    file_count = 0
    for root in [*SRC_DIRS, *SCRIPT_SCAN_DIRS]:
        if root.exists():
            for py in root.rglob("*.py"):
                if py.name != "__init__.py" and not any(
                    p in str(py) for p in EXCLUDE_PATTERNS
                ):
                    file_count += 1
    report.files_scanned = file_count

    # --- Detection 4 (RF-C6): Uncovered requirements (spec → no code) ---
    # The reverse of orphan detection: an FR defined in the spec with no
    # implementing Implements: header anywhere in source.
    report.uncovered_requirements = sorted(canonical_frs - set(fr_files.keys()))

    # --- Detection 5 (RF-C5): Untraced source (code → no FR header) ---
    report.untraced_sources = scan_untraced_sources()

    # --- Detection 6: Unresolved source-level FR/NFR/AC/SCEN references ---
    report.unresolved_source_references = scan_unresolved_source_references(
        canonical_frs,
        defined_ac_scen,
    )

    # --- Detection 1: Orphan headers ---
    for fr_id, files in sorted(fr_files.items()):
        if fr_id not in canonical_frs:
            report.orphan_headers.append(
                {
                    "fr_id": fr_id,
                    "files": files,
                    "count": len(files),
                    "issue": (
                        f"{fr_id} referenced in {len(files)} file(s) "
                        f"but not defined in specs/03-requirements.md"
                    ),
                }
            )

    # --- Detection 2: Overloaded FRs ---
    for fr_id, files in sorted(fr_files.items()):
        if len(files) > overload_threshold:
            report.overloaded_frs.append(
                {
                    "fr_id": fr_id,
                    "file_count": len(files),
                    "threshold": overload_threshold,
                    "files": files,
                    "issue": (
                        f"{fr_id} referenced by {len(files)} files "
                        f"(threshold: {overload_threshold}) — possible catch-all pollution"
                    ),
                }
            )

    # --- Detection 3: Stale status ---
    complete_markers = {"COMPLETE", "IMPLEMENTED", "DELIVERED"}
    planned_markers = {"planned", "in-progress", "blocked"}
    for fr_id, status_text in sorted(spec_statuses.items()):
        status_upper = status_text.upper()
        is_spec_complete = any(m in status_upper for m in complete_markers)
        if is_spec_complete and fr_id in fr_task_statuses:
            task_statuses = fr_task_statuses[fr_id]
            stale = [s for s in task_statuses if s in planned_markers]
            if stale:
                report.stale_statuses.append(
                    {
                        "fr_id": fr_id,
                        "spec_status": status_text,
                        "task_statuses": task_statuses,
                        "stale_count": len(stale),
                        "issue": (
                            f"{fr_id} spec says '{status_text}' but "
                            f"{len(stale)} task(s) still {', '.join(stale)}"
                        ),
                    }
                )

    return report


# ---------------------------------------------------------------------------
# Structured report
# ---------------------------------------------------------------------------


NOT_CLAIMED = [
    "Spec-cascade coherence findings are not approval.",
    "Spec-cascade coherence findings are not proof of code correctness.",
    "Spec-cascade coherence findings are not proof of complete traceability.",
    "Spec-cascade coherence findings are not compliance proof.",
    "Human review remains required for durable decisions, waivers, and acceptance.",
]

LIMITATIONS = [
    "Detection is regex/file-first and depends on project-maintained Implements:/FR references.",
    "The report detects structural traceability gaps; it does not execute code or verify behavior.",
    "Untraced source detection is limited to configured Python source roots.",
    "Source-level free-text reference validation is limited to configured app source roots; scripts/ Implements: header handling remains separate.",
    "AC/SCEN source-reference validation is skipped when no AC/SCEN ids are defined under specs/.",
    "Generated reports are bounded review evidence and do not replace maintainer/adopter judgment.",
]


def make_finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    category: str,
    message: str,
    path: str | None = None,
    requirement_id: str | None = None,
    files: list[str] | None = None,
    required_next_actions: list[str] | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "category": category,
        "message": message,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
    }
    if path:
        finding["path"] = path
    if requirement_id:
        finding["requirement_id"] = requirement_id
    if files:
        finding["files"] = files
    if required_next_actions:
        finding["required_next_actions"] = required_next_actions
    return finding


def structured_findings(report: DriftReport, severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in report.orphan_headers:
        fr_id = str(item.get("fr_id"))
        findings.append(
            make_finding(
                finding_id=f"spec_cascade.orphan_header.{fr_id}",
                severity=severity,
                status="orphan_header",
                category="code_to_spec_drift",
                requirement_id=fr_id,
                files=list(item.get("files") or []),
                message=str(item.get("issue") or f"{fr_id} is referenced in source but missing from specs."),
                required_next_actions=[
                    "Define the requirement in specs/03-requirements.md or remove the stale source reference.",
                    "Run the spec cascade check again after updating the spec or source header.",
                ],
            )
        )
    for item in report.overloaded_frs:
        fr_id = str(item.get("fr_id"))
        findings.append(
            make_finding(
                finding_id=f"spec_cascade.overloaded_requirement.{fr_id}",
                severity=severity,
                status="overloaded_requirement",
                category="traceability_quality",
                requirement_id=fr_id,
                files=list(item.get("files") or []),
                message=str(item.get("issue") or f"{fr_id} is referenced by too many files."),
                required_next_actions=[
                    "Review whether the requirement is a catch-all and split it into smaller requirements if needed.",
                    "Confirm all linked modules genuinely implement the same requirement.",
                ],
            )
        )
    for item in report.stale_statuses:
        fr_id = str(item.get("fr_id"))
        findings.append(
            make_finding(
                finding_id=f"spec_cascade.stale_status.{fr_id}",
                severity=severity,
                status="stale_status",
                category="task_to_spec_status_drift",
                requirement_id=fr_id,
                message=str(item.get("issue") or f"{fr_id} status is stale."),
                required_next_actions=[
                    "Update TASK_REGISTRY.yaml task status or re-run sync_spec_statuses.py.",
                    "Confirm the spec status reflects task evidence before treating the requirement as implemented.",
                ],
            )
        )
    for fr_id in report.uncovered_requirements:
        findings.append(
            make_finding(
                finding_id=f"spec_cascade.uncovered_requirement.{fr_id}",
                severity=severity,
                status="uncovered_requirement",
                category="spec_to_code_gap",
                requirement_id=fr_id,
                message=f"{fr_id} is defined in specs/03-requirements.md but has no matching Implements: header in source.",
                required_next_actions=[
                    "Add implementation evidence with an Implements: header or mark the requirement as deferred with review context.",
                    "Run validate_specs.py and the spec cascade check after remediation.",
                ],
            )
        )
    for path in report.untraced_sources:
        finding_id = path.replace("/", ".").replace("\\", ".")
        findings.append(
            make_finding(
                finding_id=f"spec_cascade.untraced_source.{finding_id}",
                severity=severity,
                status="untraced_source",
                category="source_to_spec_gap",
                path=path,
                message=f"{path} has no Implements:/FR reference and is invisible to requirement traceability.",
                required_next_actions=[
                    "Add a canonical Implements: header or explicitly exclude the file from the traceability policy.",
                    "Confirm the source file is not orphan implementation work.",
                ],
            )
        )
    for item in report.unresolved_source_references:
        reference_id = str(item.get("reference_id"))
        path = str(item.get("file"))
        line = item.get("line")
        reference_type = str(item.get("reference_type") or "reference")
        finding_suffix = f"{path}.{line}.{reference_id}".replace("/", ".").replace("\\", ".")
        findings.append(
            make_finding(
                finding_id=f"spec_cascade.unresolved_source_reference.{finding_suffix}",
                severity=severity,
                status="unresolved_source_reference",
                category="source_to_spec_reference_gap",
                path=path,
                requirement_id=reference_id,
                message=str(item.get("issue") or f"{reference_id} is referenced in source but not defined in specs."),
                required_next_actions=[
                    f"Define {reference_id} in the appropriate spec or remove the stale {reference_type} source reference.",
                    "Run the spec cascade check again after remediation.",
                ],
            )
        )
    return findings


def build_report(
    drift: DriftReport,
    *,
    profile: str,
    naos_root: str,
    src_root: str | None,
    specs_root: str,
    policy: dict[str, Any],
    overload_threshold: int,
) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    findings = structured_findings(drift, severity)
    summary = finding_counts(findings)
    summary.update(
        {
            "files_scanned": drift.files_scanned,
            "frs_in_spec": drift.frs_in_spec,
            "frs_in_source": drift.frs_in_source,
            "ac_scen_in_spec": drift.ac_scen_in_spec,
            "total_issues": drift.total_issues,
            "orphan_headers": len(drift.orphan_headers),
            "overloaded_frs": len(drift.overloaded_frs),
            "stale_statuses": len(drift.stale_statuses),
            "uncovered_requirements": len(drift.uncovered_requirements),
            "untraced_sources": len(drift.untraced_sources),
            "unresolved_source_references": len(drift.unresolved_source_references),
        }
    )
    return {
        "schema": "naos.spec_cascade_coherence.v1",
        "generated_at": utc_timestamp(),
        "profile": profile,
        "status": status_from_counts(summary),
        "project_root": str(PROJECT_ROOT),
        "naos_root": naos_root,
        "src_root": src_root or source_dirs_label(),
        "source_roots": [path_display(path) for path in SRC_DIRS],
        "specs_root": specs_root,
        "requirements_spec": str(REQUIREMENTS_SPEC),
        "task_registry": str(TASK_REGISTRY_PATH),
        "deterministic": True,
        "overload_threshold": overload_threshold,
        "summary": summary,
        "findings": findings,
        "orphan_headers": drift.orphan_headers,
        "overloaded_frs": drift.overloaded_frs,
        "stale_statuses": drift.stale_statuses,
        "uncovered_requirements": drift.uncovered_requirements,
        "untraced_sources": drift.untraced_sources,
        "unresolved_source_references": drift.unresolved_source_references,
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings),
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_text_report(report: DriftReport) -> str:
    """Format report as human-readable text."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("  SPEC-CODE DRIFT DETECTION REPORT")
    lines.append("=" * 72)
    lines.append(f"  Files scanned:       {report.files_scanned}")
    lines.append(f"  FRs in spec:         {report.frs_in_spec}")
    lines.append(f"  FRs in source:       {report.frs_in_source}")
    lines.append(f"  AC/SCEN in spec:     {report.ac_scen_in_spec}")
    lines.append(f"  Total issues found:  {report.total_issues}")
    lines.append("=" * 72)
    lines.append("")

    lines.append(f"[1] ORPHAN HEADERS ({len(report.orphan_headers)} found)")
    lines.append(
        "    FR/NFR referenced in code but NOT defined in specs/03-requirements.md"
    )
    lines.append("-" * 72)
    if report.orphan_headers:
        for item in report.orphan_headers:
            lines.append(f"  {item['fr_id']} ({item['count']} file(s)):")
            for f in item["files"]:
                lines.append(f"    - {f}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"[2] OVERLOADED FRs ({len(report.overloaded_frs)} found)")
    lines.append(
        f"    Single FR referenced by >{DEFAULT_OVERLOAD_THRESHOLD} files "
        f"(catch-all pollution)"
    )
    lines.append("-" * 72)
    if report.overloaded_frs:
        for item in report.overloaded_frs:
            lines.append(
                f"  {item['fr_id']}: {item['file_count']} files "
                f"(threshold: {item['threshold']})"
            )
            for f in item["files"][:5]:
                lines.append(f"    - {f}")
            if len(item["files"]) > 5:
                lines.append(f"    ... and {len(item['files']) - 5} more")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"[3] STALE STATUSES ({len(report.stale_statuses)} found)")
    lines.append(
        "    Spec says COMPLETE but TASK_REGISTRY has planned/in-progress tasks"
    )
    lines.append("-" * 72)
    if report.stale_statuses:
        for item in report.stale_statuses:
            lines.append(f"  {item['fr_id']}:")
            lines.append(f"    Spec:  {item['spec_status']}")
            lines.append(f"    Tasks: {', '.join(item['task_statuses'])}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(
        f"[4] UNCOVERED REQUIREMENTS ({len(report.uncovered_requirements)} found, advisory)"
    )
    lines.append("    FR/NFR defined in specs/03-requirements.md but NOT implemented in code")
    lines.append("-" * 72)
    if report.uncovered_requirements:
        for fr_id in report.uncovered_requirements:
            lines.append(f"  - {fr_id}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(
        f"[5] UNTRACED SOURCE ({len(report.untraced_sources)} found, advisory)"
    )
    lines.append("    Source files with no Implements:/FR reference (invisible to traceability)")
    lines.append("-" * 72)
    if report.untraced_sources:
        for f in report.untraced_sources[:20]:
            lines.append(f"    - {f}")
        if len(report.untraced_sources) > 20:
            lines.append(f"    ... and {len(report.untraced_sources) - 20} more")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(
        f"[6] UNRESOLVED SOURCE REFERENCES ({len(report.unresolved_source_references)} found, advisory)"
    )
    lines.append("    FR/NFR/AC/SCEN ids in source text that are not defined in specs")
    lines.append("-" * 72)
    if report.unresolved_source_references:
        for item in report.unresolved_source_references[:20]:
            lines.append(
                f"    - {item['file']}:{item['line']} {item['reference_id']}"
            )
        if len(report.unresolved_source_references) > 20:
            lines.append(
                f"    ... and {len(report.unresolved_source_references) - 20} more"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("=" * 72)
    if report.total_issues == 0:
        lines.append("  ✅ No spec-code drift detected")
    else:
        lines.append(f"  ⚠️  {report.total_issues} issue(s) require attention")
    lines.append("=" * 72)

    return "\n".join(lines)


def format_json_report(report: dict[str, Any]) -> str:
    """Format report as JSON."""
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Detect spec-cascade drift: orphan headers, uncovered requirements, unresolved source references, untraced source, overloads, and stale statuses"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python scripts/naos_detect_spec_drift.py
  python scripts/naos_detect_spec_drift.py --overload-threshold 15
  python scripts/naos_detect_spec_drift.py --json
  python scripts/naos_detect_spec_drift.py --profile standard --strict --json
""",
    )
    parser.add_argument(
        "--overload-threshold",
        type=int,
        default=DEFAULT_OVERLOAD_THRESHOLD,
        help=(
            f"Max files per FR before flagging as overloaded "
            f"(default: {DEFAULT_OVERLOAD_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON instead of text",
    )
    parser.add_argument("--profile", help="Governance profile (quickstart/lite/standard/assured).")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Path to NAOS governance root (default from policy/env).")
    parser.add_argument(
        "--src-root",
        default=os.environ.get("SRC_ROOT"),
        help=(
            "Path to source root, comma-separated roots supported "
            "(default: infer src, app, apps, packages, lib when present)."
        ),
    )
    parser.add_argument("--specs-root", default=os.environ.get("SPECS_ROOT", "specs"), help="Path to specs root (default: specs).")
    parser.add_argument("--policy", help="Optional explicit policy file.")
    parser.add_argument("--output", help="Optional output report path.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit behavior.")
    args = parser.parse_args(argv)

    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    configure_paths(root, naos_root, args.src_root, args.specs_root)

    drift = detect_drift(overload_threshold=args.overload_threshold)
    report = build_report(
        drift,
        profile=profile,
        naos_root=naos_root,
        src_root=args.src_root,
        specs_root=args.specs_root,
        policy=policy,
        overload_threshold=args.overload_threshold,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "spec_cascade_report")
    write_report(output, report)

    if args.json:
        print(format_json_report(report))
    else:
        print(format_text_report(drift))

    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
