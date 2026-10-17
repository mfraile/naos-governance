#!/usr/bin/env python3
"""
spec_header.py — single source of truth for requirement-header parsing.

The NAOS spec-cascade scripts (validate_specs, naos_detect_spec_drift,
sync_spec_statuses, generate_traceability_matrix) MUST agree on how an
``FR-XXX`` / ``NFR-XXX`` requirement header is recognized in
``specs/03-requirements.md``. Historically they did not: some matched ``## FR-``
(H2) and one matched ``### FR-`` (H3), and the shipped template uses H3 while an
internal demo used H2. That made the scripts mutually exclusive — whichever
format a project used, part of the cascade went silently blind.

This module fixes that by exposing one tolerant, canonical set of patterns.
Requirement headers are accepted at **H2 or H3** (``##`` or ``###``), with
numeric or named IDs (``FR-001``, ``FR-REG``, ``NFR-001-ENHANCED``),
case-insensitively. IDs are normalized to upper-case.

Import from any cascade script:

    import spec_header   # scripts/ is added to sys.path by the caller
    frs = spec_header.canonical_frs(text)
"""

from __future__ import annotations

import re

# Requirement section header at H2 or H3: "## FR-001:" or "### NFR-001-ENHANCED:"
REQ_HEADER_RE = re.compile(
    r"^#{2,3}\s+((?:FR|NFR)-[A-Z0-9][\w-]*):",
    re.MULTILINE | re.IGNORECASE,
)

# Preserve this historical pattern for callers that may import it. It must
# not be used to parse statuses: it can cross into a later requirement block.
REQ_STATUS_RE = re.compile(
    r"^#{2,3}\s+((?:FR|NFR)-[A-Z0-9][\w-]*):[^\n]*\n"
    r"(?:.*?\n)*?"
    r"\*\*Status\*\*:\s*(.+)",
    re.MULTILINE | re.IGNORECASE,
)
_STATUS_LINE_RE = re.compile(r"^\*\*Status\*\*:[ \t]*(.*)$", re.IGNORECASE)
_HEADING_RE = re.compile(r"^#{1,3}\s+")

# Code header line that names implemented FR/NFR tokens.
IMPLEMENTS_RE = re.compile(r"Implements:\s*([^\n]+)")

# A bare FR/NFR token inside free text (e.g. a code header or a task requirement).
FR_TOKEN_RE = re.compile(r"(?<![\w.-])(?:FR|NFR)-[A-Z0-9][\w-]*(?![\w-])", re.IGNORECASE)

# Existing tolerant completion-evidence grammar, shared with test references.
AC_SCEN_RE = re.compile(r"\b((?:AC|SCEN)-[A-Z0-9][A-Z0-9_.-]*)\b", re.IGNORECASE)


def canonical_frs(text: str) -> set[str]:
    """Return the set of FR/NFR IDs defined as requirement headers (upper-cased)."""
    return {m.group(1).upper() for m in REQ_HEADER_RE.finditer(text)}


def spec_statuses(text: str) -> dict[str, str]:
    """Return {FR_ID: status_text} parsed from requirement headers + **Status**: lines."""
    return {
        rid: status
        for rid, status in requirement_statuses(text).items()
        if status
    }


def requirement_statuses(text: str) -> dict[str, str | None]:
    """Return every declared requirement, including absent or empty statuses."""
    statuses: dict[str, str | None] = {}
    current: str | None = None
    for line in text.splitlines():
        header = REQ_HEADER_RE.match(line)
        if header:
            current = header.group(1).upper()
            statuses[current] = None
            continue
        if _HEADING_RE.match(line):
            current = None
            continue
        if current is not None:
            status_match = _STATUS_LINE_RE.match(line)
            if status_match:
                statuses[current] = status_match.group(1).strip() or None
                current = None
    return statuses


def classify_requirement_status(status: str | None) -> str:
    """Classify a declared status without treating substrings as completion."""
    if not status:
        return "unresolved"
    value = re.sub(r"<!--.*?-->", "", status).strip()
    value = re.sub(r"^✅\s*", "", value).strip().strip("*").strip().casefold()
    value = " ".join(value.split())
    if value in {"implemented", "verified", "complete", "completed", "done"}:
        return "complete"
    if value in {"in progress", "in-progress"}:
        return "in_progress"
    if value in {"planned", "draft", "not started"}:
        return "planned"
    if value == "documentation only":
        return "documentation_only"
    return "unresolved"


def fr_tokens(text: str) -> set[str]:
    """Return all FR/NFR tokens appearing in free text (upper-cased)."""
    return {t.upper() for t in FR_TOKEN_RE.findall(text)}


def _markdown_lines(text: str) -> list[str]:
    """Mask fenced examples while retaining line positions for section selection."""
    lines = text.splitlines()
    fence: tuple[str, int] | None = None
    visible = []
    for line in lines:
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence:
            visible.append("")
            if (marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= fence[1]
                    and not line[marker.end():].strip()):
                fence = None
        elif marker:
            fence = (marker.group(1)[0], len(marker.group(1)))
            visible.append("")
        else:
            visible.append(line)
    return visible


def _section_text(text: str, visible: list[str], start: int) -> str:
    lines = text.splitlines()
    heading = re.match(r"^(#{1,6})\s+", visible[start])
    if not heading:
        return lines[start].strip()
    end = len(lines)
    for i in range(start + 1, len(lines)):
        following = re.match(r"^(#{1,6})\s+", visible[i])
        if following and len(following.group(1)) <= len(heading.group(1)):
            end = i
            break
    return "\n".join(lines[start:end]).strip()


def section_for_anchor(text: str, anchor: str) -> str:
    """Select one explicit anchor, requirement ID or simple heading slug.

    Missing or ambiguous anchors refuse; never substitute the file's opening.
    """
    visible = _markdown_lines(text)
    matches = []
    for i, line in enumerate(visible):
        identifiers = re.findall(r"\{#([^}\s]+)\}", line)
        heading = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            title = re.sub(r"\s*\{#[^}]+\}", "", heading.group(1))
            identifiers.append(re.sub(r"\s+", "-", re.sub(r"[^\w\s-]", "", title).strip()).casefold())
            requirement = re.match(r"^((?:FR|NFR)-[A-Z0-9][\w-]*)(?=[:\s]|$)", title, re.IGNORECASE)
            if requirement:
                identifiers.append(requirement.group(1))
        if anchor.casefold() in {value.casefold() for value in identifiers}:
            matches.append(i)
    if len(matches) != 1:
        raise ValueError(f"Spec anchor {anchor!r} is {'missing' if not matches else 'ambiguous'}")
    return _section_text(text, visible, matches[0])


def architecture_component_sections(text: str) -> dict[str, list[str]]:
    """Component headings and definitions in Components; section anchors are not IDs."""
    visible = _markdown_lines(text)
    result: dict[str, list[str]] = {}
    components_level = None
    for i, line in enumerate(visible):
        heading = re.match(r"^(#{1,6})\s+(.+)", line)
        if heading:
            level, title = len(heading.group(1)), heading.group(2)
            if components_level is not None and level <= components_level:
                components_level = None
            if re.match(r"Components(?:\s|\{|$)", title, re.IGNORECASE):
                components_level = level
            component = re.match(r"(ARCH-[0-9]+)(?![\w-])", title, re.IGNORECASE)
        elif components_level is not None:
            component = re.match(r"^\s*(?:\|\s*)?(ARCH-[0-9]+)(?![\w-])", line, re.IGNORECASE)
        else:
            component = None
        if component:
            result.setdefault(component.group(1).upper(), []).append(_section_text(text, visible, i))
    return result
