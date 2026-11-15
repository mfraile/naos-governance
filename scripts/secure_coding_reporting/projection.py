"""Bounded projection of P3 dimensions into existing generated artifacts."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

from naos_self_check_inspection import inspection_publish_path
from naos_trace_atomic_write import publish_trace, read_trace_source

from .model import DIMENSION_KEYS

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


def safe_write_text(path: Path, text: str, *, original: bytes | None = None) -> None:
    """Publish an existing artifact against its captured, non-linked preimage."""
    physical = inspection_publish_path(path)
    if original is None:
        with read_trace_source(physical) as source:
            if source is None:
                raise FileNotFoundError(f"Projection target is absent: {path}")
            original = source.read()
    publish_trace(physical, text.replace("\n", os.linesep).encode("utf-8"), original,
                  strict_parent_topology=True, create_parents=False)


def _read_existing(path: Path) -> bytes | None:
    with read_trace_source(inspection_publish_path(path)) as source:
        return None if source is None else source.read()


def _text(original: bytes) -> str:
    # Match Path.read_text's UTF-8 and universal-newline behavior.
    with io.TextIOWrapper(io.BytesIO(original), encoding="utf-8") as stream:
        return stream.read()


def prepare_json(path: Path, report: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    result, content, _original = _prepare(path, report, markdown=False)
    return result, content


def _json_text(path: Path, text: str, report: dict[str, Any]) -> str:
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    value[PROJECTION_KEY] = payload(report)
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


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
    result, content, _original = _prepare(path, report, markdown=True)
    return result, content


def _markdown_text(text: str, report: dict[str, Any]) -> str | None:
    block = markdown_block(report)
    if BEGIN_MARKER in text or END_MARKER in text:
        if text.count(BEGIN_MARKER) != 1 or text.count(END_MARKER) != 1:
            return None
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
    return updated


def _prepare(path: Path, report: dict[str, Any], *, markdown: bool
             ) -> tuple[dict[str, Any], str | None, bytes | None]:
    result = {"path": str(path), "state": "ready", "updated": False}
    try:
        original = _read_existing(path)
    except ValueError as exc:
        return {**result, "state": "unsafe_target", "message": str(exc)}, None, None
    except OSError as exc:
        return {**result, "state": "parse_error", "message": str(exc)}, None, None
    if original is None:
        return {**result, "state": "not_configured"}, None, None
    try:
        text = _text(original)
        content = _markdown_text(text, report) if markdown else _json_text(path, text, report)
    except Exception as exc:
        return {**result, "state": "parse_error", "message": str(exc)}, None, None
    if content is None:
        return {**result, "state": "marker_error"}, None, None
    return result, content, original


def project(
    *,
    report: dict[str, Any],
    dashboard_summary: Path,
    dashboard_markdown: Path,
    evidence_pack: Path,
) -> dict[str, Any]:
    """Preflight every configured target before mutating any target."""
    plans = {
        "dashboard_summary": _prepare(dashboard_summary, report, markdown=False),
        "dashboard_markdown": _prepare(dashboard_markdown, report, markdown=True),
        "evidence_pack": _prepare(evidence_pack, report, markdown=False),
    }
    results = {key: value[0] for key, value in plans.items()}
    if any(result["state"] in ERROR_STATES for result in results.values()):
        for key, (_, content, _original) in plans.items():
            if content is not None:
                results[key] = {
                    **results[key],
                    "state": "aborted",
                    "message": "Projection aborted because another configured target failed preflight.",
                }
        return results

    for key, (result, content, original) in plans.items():
        if content is None:
            continue
        path = Path(result["path"])
        safe_write_text(path, content, original=original)
        results[key] = {**result, "state": "projected", "updated": True}
    return results
