"""Bounded projection of P3 dimensions into existing generated artifacts."""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
from typing import Any

from .model import DIMENSION_KEYS, load_object

MARKER_ID = "secure-coding-multidimensional-reporting"
BEGIN_MARKER = f"<!-- BEGIN NAOS GENERATED: {MARKER_ID} -->"
END_MARKER = f"<!-- END NAOS GENERATED: {MARKER_ID} -->"
PROJECTION_KEY = "secure_coding_reporting"
ERROR_STATES = {"parse_error", "marker_error", "unsafe_target"}


def payload(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": report.get("schema"),
        "generated_at": report.get("generated_at"),
        "status": report.get("status"),
        "sources": report.get("sources") or {},
        "standards_snapshot": report.get("standards_snapshot") or {},
        "dimensions": report.get("dimensions") or {},
        "dimension_keys": (report.get("summary") or {}).get("dimension_keys") or [],
        "human_review_required": True,
        "limitations": report.get("limitations") or [],
        "not_claimed": report.get("not_claimed") or [],
    }


def safe_write_text(path: Path, text: str) -> None:
    """Replace an existing generated artifact without following a symlink."""
    if path.is_symlink():
        raise ValueError(f"Refusing to project through symlink: {path}")
    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Refusing to project through symlink: {path}") from exc
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def prepare_json(path: Path, report: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {"path": str(path), "state": "not_configured", "updated": False}, None
    if path.is_symlink() or not path.is_file():
        return {"path": str(path), "state": "unsafe_target", "updated": False}, None
    try:
        value = load_object(path)
    except Exception as exc:
        return {
            "path": str(path),
            "state": "parse_error",
            "updated": False,
            "message": str(exc),
        }, None
    value[PROJECTION_KEY] = payload(report)
    return {
        "path": str(path),
        "state": "ready",
        "updated": False,
    }, json.dumps(value, indent=2, sort_keys=True) + "\n"


def markdown_block(report: dict[str, Any]) -> str:
    dimensions = report.get("dimensions") or {}
    labels = {
        "register_validity": "Register validity",
        "reference_integrity": "Reference integrity",
        "detector_evidence": "Detector evidence availability/freshness",
        "mapping_verification": "Mapping verification",
        "human_review": "Human review",
    }
    lines = [
        BEGIN_MARKER,
        "### Secure-Coding Multidimensional Reporting",
        "",
        "> This panel presents five independent, source-backed dimensions. It does not calculate a blended or composite security score and does not establish control satisfaction, secure code, framework conformance, approval, or release authorization.",
        "",
        "| Dimension | State | Source |",
        "| --- | --- | --- |",
    ]
    for key in DIMENSION_KEYS:
        item = dimensions.get(key) if isinstance(dimensions.get(key), dict) else {}
        state = str(item.get("state") or "unknown").replace("|", "\\|")
        source = (
            str(item.get("source") or "not available")
            .replace("|", "\\|")
            .replace("\n", " ")
        )
        lines.append(f"| {labels[key]} | `{state}` | {source} |")
    lines.extend(["", "Human review required: `True`.", END_MARKER])
    return "\n".join(lines)


def prepare_markdown(path: Path, report: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {"path": str(path), "state": "not_configured", "updated": False}, None
    if path.is_symlink() or not path.is_file():
        return {"path": str(path), "state": "unsafe_target", "updated": False}, None
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return {
            "path": str(path),
            "state": "parse_error",
            "updated": False,
            "message": str(exc),
        }, None
    block = markdown_block(report)
    if BEGIN_MARKER in text or END_MARKER in text:
        if text.count(BEGIN_MARKER) != 1 or text.count(END_MARKER) != 1:
            return {"path": str(path), "state": "marker_error", "updated": False}, None
        start = text.index(BEGIN_MARKER)
        end = text.index(END_MARKER, start) + len(END_MARKER)
        updated = text[:start] + block + text[end:]
    else:
        separator = (
            ""
            if not text or text.endswith("\n\n")
            else ("\n" if text.endswith("\n") else "\n\n")
        )
        updated = text + separator + block + "\n"
    return {"path": str(path), "state": "ready", "updated": False}, updated


def project(
    *,
    report: dict[str, Any],
    dashboard_summary: Path,
    dashboard_markdown: Path,
    evidence_pack: Path,
) -> dict[str, Any]:
    """Preflight every configured target before mutating any target."""
    plans = {
        "dashboard_summary": prepare_json(dashboard_summary, report),
        "dashboard_markdown": prepare_markdown(dashboard_markdown, report),
        "evidence_pack": prepare_json(evidence_pack, report),
    }
    results = {key: value[0] for key, value in plans.items()}
    if any(result["state"] in ERROR_STATES for result in results.values()):
        for key, (_, content) in plans.items():
            if content is not None:
                results[key] = {
                    **results[key],
                    "state": "aborted",
                    "message": "Projection aborted because another configured target failed preflight.",
                }
        return results

    for key, (result, content) in plans.items():
        if content is None:
            continue
        path = Path(result["path"])
        safe_write_text(path, content)
        results[key] = {**result, "state": "projected", "updated": True}
    return results
