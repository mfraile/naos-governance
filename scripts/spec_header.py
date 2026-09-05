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

# A requirement header followed (anywhere in its block) by a **Status**: line.
REQ_STATUS_RE = re.compile(
    r"^#{2,3}\s+((?:FR|NFR)-[A-Z0-9][\w-]*):[^\n]*\n"
    r"(?:.*?\n)*?"
    r"\*\*Status\*\*:\s*(.+)",
    re.MULTILINE | re.IGNORECASE,
)

# Code header line that names implemented FR/NFR tokens.
IMPLEMENTS_RE = re.compile(r"Implements:\s*([^\n]+)")

# A bare FR/NFR token inside free text (e.g. a code header or a task requirement).
FR_TOKEN_RE = re.compile(r"(?:FR|NFR)-[A-Z0-9][\w-]*", re.IGNORECASE)


def canonical_frs(text: str) -> set[str]:
    """Return the set of FR/NFR IDs defined as requirement headers (upper-cased)."""
    return {m.group(1).upper() for m in REQ_HEADER_RE.finditer(text)}


def spec_statuses(text: str) -> dict[str, str]:
    """Return {FR_ID: status_text} parsed from requirement headers + **Status**: lines."""
    return {
        m.group(1).upper(): m.group(2).strip()
        for m in REQ_STATUS_RE.finditer(text)
    }


def fr_tokens(text: str) -> set[str]:
    """Return all FR/NFR tokens appearing in free text (upper-cased)."""
    return {t.upper() for t in FR_TOKEN_RE.findall(text)}
