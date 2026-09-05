#!/usr/bin/env python3
"""Query the generated NAOS local context index as bounded candidate references."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    write_report,
)


REPORT_SCHEMA = "naos.local_context_query.v1"
FTS_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")
MAX_LIMIT = 50
DEFAULT_LIMIT = 10


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def bounded_text(value: Any, limit: int = 500) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 18)].rstrip() + " [truncated]"


def parse_json_text(value: Any, fallback: Any = None) -> Any:
    if not isinstance(value, str):
        return value if value is not None else fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback if fallback is not None else value


def fts_query_terms(raw: str, max_chars: int = 120) -> tuple[str, ...]:
    tokens = FTS_TOKEN_RE.findall((raw or "")[:max_chars])
    filtered = [token for token in tokens if token.upper() not in {"AND", "OR", "NOT", "NEAR"}]
    return tuple(filtered[:20])


def literalize_fts_terms(terms: tuple[str, ...]) -> str:
    return " AND ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def sanitize_fts_query(raw: str, max_chars: int = 120) -> str:
    return literalize_fts_terms(fts_query_terms(raw, max_chars))


def read_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_semantic_candidate_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "semantic_candidate_layer_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "semantic_runtime_enabled": False,
            "rule": "Semantic candidate readiness is optional reporting; context query remains exact/path/metadata/FTS-first.",
        }
    try:
        data = read_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "semantic_runtime_enabled": False, "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "semantic_runtime_enabled": bool(data.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool(data.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool(data.get("embeddings_enabled")),
        "candidate_only_policy": data.get("candidate_only_policy") or {},
        "summary": data.get("summary") or {},
        "rule": "Semantic readiness does not turn query results into answers or source artifacts.",
    }


def load_graph_context_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "graph_context_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "graph_runtime_enabled": False,
            "rule": "Graph context readiness is optional reporting; query artifact links remain explicit candidate references.",
        }
    try:
        data = read_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "graph_runtime_enabled": False, "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "graph_runtime_enabled": bool(data.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool(data.get("explicit_link_traversal_only", True)),
        "global_graph_scan_allowed": bool(data.get("global_graph_scan_allowed")),
        "traversal_limits": data.get("traversal_limits") or {},
        "summary": data.get("summary") or {},
        "rule": "Graph readiness does not turn query links into truth or source artifacts.",
    }


def load_memory_provider_access(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_provider_access_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "provider_access_verified": False,
            "mcp_access_verified": False,
            "rule": "Run naos memory-access to inspect memory provider/MCP access posture; context query never searches private memory payloads.",
        }
    try:
        data = read_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "provider_access_verified": False, "mcp_access_verified": False, "error": str(exc)}
    project_identity = data.get("project_identity") if isinstance(data.get("project_identity"), dict) else {}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "provider_configured": bool(data.get("provider_configured")),
        "provider_access_verified": bool(data.get("provider_access_verified")),
        "mcp_access_verified": bool(data.get("mcp_access_verified")),
        "project_identity": {
            "status": project_identity.get("status"),
            "project_identity_verified": bool(project_identity.get("project_identity_verified")),
            "global_fixed_project_detected": bool(project_identity.get("global_fixed_project_detected")),
        },
        "summary": data.get("summary") or {},
        "rule": "Memory access posture is advisory metadata only; query results remain generated index candidates, not memory answers.",
    }


def load_memory_use_policy(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_use_policy_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Run naos memory-use-policy to inspect memory review/use posture; context query never searches or promotes memory payloads.",
        }
    try:
        data = read_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "error": str(exc)}
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "summary": data.get("summary") or {},
        "instruction_grade_items": len(data.get("instruction_grade_items") or []),
        "unsafe_instruction_grade_claims": len(data.get("unsafe_instruction_grade_claims") or []),
        "memory_access_prerequisites": data.get("memory_access_prerequisites") or {},
        "policy_item_access_posture": data.get("policy_item_access_posture") or [],
        "rule": "Memory-use posture is advisory metadata only; query results remain candidates, not instruction-grade memory or approval, and access-unverified policy items remain explicitly unverified.",
    }


def safe_path(path: str | None) -> Path | None:
    if not path:
        return None
    try:
        return Path(path)
    except Exception:
        return None


def local_context_query_markdown_dir(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    if is_kit_repository(root, naos_root) or not (root / naos_root).is_dir():
        return None
    value = str(policy.get("paths", {}).get("local_context_query_markdown_dir") or "context_queries")
    return root / naos_root / value


def local_context_index_paths(
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    index_report_arg: str | None,
    sqlite_arg: str | None,
) -> tuple[Path, Path | None]:
    index_report = Path(index_report_arg) if index_report_arg else report_default_path(root, naos_root, policy, "local_context_index_report")
    sqlite_path = Path(sqlite_arg) if sqlite_arg else None
    if sqlite_path is None and index_report.exists():
        try:
            report = read_json_mapping(index_report)
            sqlite_value = ((report.get("sqlite_artifact") or {}).get("path") or "")
            sqlite_path = safe_path(sqlite_value)
        except Exception:
            sqlite_path = None
    if sqlite_path is None:
        configured = str(policy.get("paths", {}).get("local_context_index_sqlite") or "context_index/local_context_index.sqlite")
        sqlite_path = root / naos_root / configured
    return index_report, sqlite_path


def rows_as_dicts(connection: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    return [dict(row) for row in connection.execute(query, params).fetchall()]


def load_index_from_sqlite(sqlite_path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(sqlite_path)
    try:
        artifacts = rows_as_dicts(connection, "SELECT * FROM artifacts ORDER BY path, artifact_id")
        chunks = rows_as_dicts(connection, "SELECT * FROM artifact_chunks ORDER BY path, chunk_id")
        links = rows_as_dicts(connection, "SELECT * FROM artifact_links ORDER BY source_path, link_type, reference_id")
        tables = {
            row["name"]
            for row in rows_as_dicts(connection, "SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')")
        }
    finally:
        connection.close()
    for artifact in artifacts:
        artifact["profile_scope"] = parse_json_text(artifact.get("profile_scope"), artifact.get("profile_scope"))
        artifact["limitations"] = parse_json_text(artifact.get("limitations"), [])
    for chunk in chunks:
        for key in ["limitations", "related_task_ids", "related_spec_refs", "related_capabilities", "related_code_symbols", "related_tests"]:
            chunk[key] = parse_json_text(chunk.get(key), [])
    return {
        "source": "sqlite",
        "artifacts": artifacts,
        "chunks": chunks,
        "links": links,
        "fts_available": "artifact_chunks_fts" in tables,
        "tables": sorted(tables),
    }


def load_index_from_report(index_report: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "report",
        "artifacts": index_report.get("indexed_artifacts") or [],
        "chunks": index_report.get("artifact_chunks") or [],
        "links": index_report.get("artifact_links") or [],
        "fts_available": False,
        "tables": [],
    }


def chunk_map(chunks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for chunk in chunks:
        grouped[str(chunk.get("artifact_id"))].append(chunk)
    return grouped


def artifact_by_id(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("artifact_id")): item for item in artifacts}


def filters_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "artifact_type": args.artifact_type,
        "authority_level": args.authority_level,
        "freshness_status": args.freshness,
        "profile_scope": args.profile_scope,
        "report_status": args.report_status,
    }


def artifact_matches_filters(artifact: dict[str, Any], filters: dict[str, Any], chunks: list[dict[str, Any]]) -> bool:
    if filters.get("artifact_type") and artifact.get("artifact_type") != filters["artifact_type"]:
        return False
    if filters.get("authority_level") and artifact.get("authority_level") != filters["authority_level"]:
        return False
    if filters.get("freshness_status") and artifact.get("freshness_status") != filters["freshness_status"]:
        return False
    profile_scope = filters.get("profile_scope")
    if profile_scope:
        scope = artifact.get("profile_scope")
        if isinstance(scope, list):
            if profile_scope not in [str(item) for item in scope]:
                return False
        elif str(scope) not in {profile_scope, "all"}:
            return False
    report_status = filters.get("report_status")
    if report_status:
        if artifact.get("artifact_type") != "deterministic_report":
            return False
        text = " ".join(str(chunk.get("bounded_excerpt") or chunk.get("text_summary") or "") for chunk in chunks)
        if f'"status": "{report_status}"' not in text and f'"status":"{report_status}"' not in text:
            return False
    return True


def first_chunk_for_artifact(chunks_by_artifact: dict[str, list[dict[str, Any]]], artifact_id: str) -> dict[str, Any]:
    values = chunks_by_artifact.get(artifact_id) or []
    return values[0] if values else {}


def result_record(
    artifact: dict[str, Any],
    chunk: dict[str, Any],
    mode: str,
    reason: str,
    ordinal: int,
) -> dict[str, Any]:
    return {
        "result_id": f"Q{ordinal:04d}",
        "query_mode": mode,
        "match_reason": reason,
        "artifact_id": artifact.get("artifact_id"),
        "chunk_id": chunk.get("chunk_id"),
        "path": artifact.get("path") or chunk.get("path"),
        "artifact_type": artifact.get("artifact_type"),
        "authority_level": artifact.get("authority_level"),
        "source_hash": artifact.get("source_hash"),
        "modified_at": artifact.get("modified_at"),
        "indexed_at": artifact.get("indexed_at"),
        "freshness_status": artifact.get("freshness_status"),
        "profile_scope": artifact.get("profile_scope"),
        "section_heading": chunk.get("section_heading"),
        "bounded_excerpt": bounded_text(chunk.get("bounded_excerpt") or chunk.get("text_summary") or "", 700),
        "provenance": artifact.get("provenance") or chunk.get("provenance"),
        "scope": artifact.get("scope") or chunk.get("scope"),
        "use_policy": artifact.get("use_policy") or chunk.get("use_policy") or "candidate_reference_only",
        "review_status": artifact.get("review_status") or chunk.get("review_status"),
        "source_reference": artifact.get("source_reference") or chunk.get("source_reference"),
        "confidence": chunk.get("confidence") or artifact.get("confidence"),
        "recall_trace_readiness": chunk.get("recall_trace_readiness") or artifact.get("recall_trace_readiness"),
        "audit_event_readiness": chunk.get("audit_event_readiness") or artifact.get("audit_event_readiness"),
        "related_task_ids": chunk.get("related_task_ids") or [],
        "related_spec_refs": chunk.get("related_spec_refs") or [],
        "related_capabilities": chunk.get("related_capabilities") or [],
        "limitations": list(
            dict.fromkeys((artifact.get("limitations") or []) + (chunk.get("limitations") or []) + ["candidate reference only"])
        ),
    }


def add_artifact_result(
    results: list[dict[str, Any]],
    seen: set[tuple[str, str | None, str]],
    artifact: dict[str, Any],
    chunk: dict[str, Any],
    mode: str,
    reason: str,
) -> None:
    key = (str(artifact.get("artifact_id")), str(chunk.get("chunk_id") or ""), mode)
    if key in seen:
        return
    seen.add(key)
    results.append(result_record(artifact, chunk, mode, reason, len(results) + 1))


def requested_modes(args: argparse.Namespace) -> list[str]:
    modes: list[str] = []
    if args.path:
        modes.append("exact_path_lookup")
    if args.artifact_id:
        modes.append("artifact_id_lookup")
    if args.task:
        modes.append("task_id_lookup")
    if args.spec:
        modes.append("spec_ref_lookup")
    if args.capability:
        modes.append("capability_lookup")
    if args.report_status:
        modes.append("report_status_lookup")
    if args.query:
        modes.append("fts_keyword_search")
    if any([args.artifact_type, args.authority_level, args.freshness, args.profile_scope]):
        modes.append("metadata_filtering")
    return modes


def query_index(
    *,
    args: argparse.Namespace,
    index_data: dict[str, Any],
    index_report: dict[str, Any],
    sqlite_path: Path | None,
    limit: int,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    artifacts = index_data["artifacts"]
    chunks = index_data["chunks"]
    links = index_data["links"]
    by_id = artifact_by_id(artifacts)
    chunks_by_artifact = chunk_map(chunks)
    filters = filters_from_args(args)
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str]] = set()
    used_modes: list[str] = []
    findings: list[dict[str, Any]] = []

    def candidate_artifacts() -> list[dict[str, Any]]:
        return [
            artifact
            for artifact in artifacts
            if artifact_matches_filters(artifact, filters, chunks_by_artifact.get(str(artifact.get("artifact_id")), []))
        ]

    if args.path:
        used_modes.append("exact_path_lookup")
        normalized = args.path.strip().lstrip("./")
        for artifact in candidate_artifacts():
            if str(artifact.get("path")) == normalized:
                add_artifact_result(results, seen, artifact, first_chunk_for_artifact(chunks_by_artifact, str(artifact.get("artifact_id"))), "exact_path_lookup", "path matched exactly")

    if args.artifact_id:
        used_modes.append("artifact_id_lookup")
        artifact = by_id.get(args.artifact_id)
        if artifact and artifact_matches_filters(artifact, filters, chunks_by_artifact.get(args.artifact_id, [])):
            add_artifact_result(results, seen, artifact, first_chunk_for_artifact(chunks_by_artifact, args.artifact_id), "artifact_id_lookup", "artifact id matched exactly")

    link_modes = [
        ("task_id_lookup", "task_ref", args.task.upper() if args.task else None),
        ("spec_ref_lookup", "spec_ref", args.spec),
        ("capability_lookup", "capability_ref", args.capability.upper() if args.capability else None),
    ]
    for mode, link_type, reference_id in link_modes:
        if not reference_id:
            continue
        used_modes.append(mode)
        paths = {
            str(link.get("source_path"))
            for link in links
            if str(link.get("link_type")) == link_type and str(link.get("reference_id")).upper() == str(reference_id).upper()
        }
        for artifact in candidate_artifacts():
            if str(artifact.get("path")) in paths:
                add_artifact_result(results, seen, artifact, first_chunk_for_artifact(chunks_by_artifact, str(artifact.get("artifact_id"))), mode, f"explicit {link_type} matched {reference_id}")

    if args.report_status:
        used_modes.append("report_status_lookup")
        for artifact in candidate_artifacts():
            add_artifact_result(results, seen, artifact, first_chunk_for_artifact(chunks_by_artifact, str(artifact.get("artifact_id"))), "report_status_lookup", f"deterministic report status matched {args.report_status}")

    if any([args.artifact_type, args.authority_level, args.freshness, args.profile_scope]) and not any([args.path, args.artifact_id, args.task, args.spec, args.capability, args.query, args.report_status]):
        used_modes.append("metadata_filtering")
        for artifact in candidate_artifacts():
            add_artifact_result(results, seen, artifact, first_chunk_for_artifact(chunks_by_artifact, str(artifact.get("artifact_id"))), "metadata_filtering", "artifact metadata matched filters")

    if args.query:
        sanitized = sanitize_fts_query(args.query, int(((index_report.get("fts_query_sanitization") or {}).get("max_query_chars") or 120)))
        if not sanitized:
            findings.append(
                {
                    "id": "local_context_query.empty_sanitized_query",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": "The query was empty after sanitization; no FTS lookup was attempted.",
                }
            )
        elif index_data.get("source") == "sqlite" and index_data.get("fts_available"):
            used_modes.append("fts_keyword_search")
            try:
                if sqlite_path is None:
                    raise FileNotFoundError("SQLite path was not resolved")
                with sqlite3.connect(sqlite_path) as connection:
                    connection.row_factory = sqlite3.Row
                    rows = [
                        dict(row)
                        for row in connection.execute(
                            """
                            SELECT c.*
                            FROM artifact_chunks_fts f
                            JOIN artifact_chunks c ON f.chunk_id = c.chunk_id
                            WHERE artifact_chunks_fts MATCH ?
                            ORDER BY c.path, c.chunk_id
                            LIMIT ?
                            """,
                            (sanitized, limit),
                        ).fetchall()
                    ]
                for row in rows:
                    for key in ["limitations", "related_task_ids", "related_spec_refs", "related_capabilities", "related_code_symbols", "related_tests"]:
                        row[key] = parse_json_text(row.get(key), [])
                    artifact = by_id.get(str(row.get("artifact_id")))
                    if artifact and artifact_matches_filters(artifact, filters, [row]):
                        add_artifact_result(results, seen, artifact, row, "fts_keyword_search", "sanitized FTS keyword match")
            except Exception as exc:
                used_modes.append("metadata_text_fallback")
                findings.append(
                    {
                        "id": "local_context_query.fts_fallback",
                        "severity": "advisory",
                        "status": "advisory",
                        "message": f"FTS query failed; used bounded text fallback. {exc}",
                    }
                )
        else:
            used_modes.append("metadata_text_fallback")
            findings.append(
                {
                    "id": "local_context_query.fts_unavailable",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": "FTS5 is unavailable; used bounded text fallback over indexed chunks.",
                }
            )
        if "metadata_text_fallback" in used_modes:
            terms = [term.lower() for term in fts_query_terms(args.query, int(((index_report.get("fts_query_sanitization") or {}).get("max_query_chars") or 120)))]
            for chunk in chunks:
                text = f"{chunk.get('bounded_excerpt') or ''} {chunk.get('text_summary') or ''}".lower()
                if terms and all(term in text for term in terms):
                    artifact = by_id.get(str(chunk.get("artifact_id")))
                    if artifact and artifact_matches_filters(artifact, filters, [chunk]):
                        add_artifact_result(results, seen, artifact, chunk, "metadata_text_fallback", "sanitized keyword fallback match")

    return results[:limit], list(dict.fromkeys(used_modes)), findings


def status_from_findings(findings: list[dict[str, Any]], *, has_query: bool, index_available: bool) -> str:
    if not has_query or not index_available:
        return "not_configured"
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if findings:
        return "advisory"
    return "ready"


def markdown_for_report(report: dict[str, Any]) -> str:
    lines = [
        f"# Local Context Query: {report['query'].get('query_id')}",
        "",
        "_Derived, bounded, non-authoritative query results. Candidates are not answers; repository evidence remains authoritative._",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Profile: `{report.get('profile')}`",
        f"- Query modes used: `{', '.join(report.get('query_mode_used') or []) or 'none'}`",
        f"- Results: `{report.get('result_count')}`",
        f"- FTS available: `{report.get('fts_available')}`",
        "",
        "## Authority Boundary",
        "",
        "Use these results as candidate references only. Check the source path, source hash, freshness, authority level, and current repository state before acting.",
        "",
        "## Results",
    ]
    if not report.get("results"):
        lines.extend(["", "No candidate results matched the query."])
    for result in report.get("results") or []:
        lines.extend(
            [
                "",
                f"### {result.get('result_id')} `{result.get('path')}`",
                "",
                f"- Mode: `{result.get('query_mode')}`",
                f"- Artifact: `{result.get('artifact_id')}` / chunk `{result.get('chunk_id')}`",
                f"- Type: `{result.get('artifact_type')}`",
                f"- Authority: `{result.get('authority_level')}`",
                f"- Freshness: `{result.get('freshness_status')}`",
                f"- Source hash: `{result.get('source_hash')}`",
                f"- Reason: {result.get('match_reason')}",
                "",
                "```text",
                str(result.get("bounded_excerpt") or ""),
                "```",
            ]
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    for limitation in report.get("limitations") or []:
        lines.append(f"- {limitation}")
    lines.extend(["", "## Not Claimed", ""])
    for claim in report.get("not_claimed") or []:
        lines.append(f"- {claim}")
    return "\n".join(lines).rstrip() + "\n"


def write_markdown_if_requested(root: Path, naos_root: str, policy: dict[str, Any], report: dict[str, Any], args: argparse.Namespace) -> str | None:
    if not args.write_markdown:
        return None
    output = Path(args.markdown_output) if args.markdown_output else None
    if output is None:
        directory = local_context_query_markdown_dir(root, naos_root, policy)
        if directory is None:
            return None
        output = directory / f"{report['query']['query_id']}.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown_for_report(report), encoding="utf-8")
    return str(output)


def build_report(root: Path, naos_root: str, profile: str, policy: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    generated_at = utc_now_text()
    limit = min(max(int(args.limit or DEFAULT_LIMIT), 1), MAX_LIMIT)
    index_report_path, sqlite_path = local_context_index_paths(root, naos_root, policy, args.index_report, args.sqlite)
    index_report: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    index_available = index_report_path.exists()
    if index_available:
        try:
            index_report = read_json_mapping(index_report_path)
        except Exception as exc:
            index_available = False
            findings.append(
                {
                    "id": "local_context_query.index_report_parse_error",
                    "severity": "advisory",
                    "status": "parse_error",
                    "message": f"Local context index report could not be parsed: {exc}",
                }
            )
    else:
        findings.append(
            {
                "id": "local_context_query.index_missing",
                "severity": "advisory",
                "status": "not_configured",
                "message": "Run naos context-index before querying local context candidates.",
            }
        )

    query_payload = {
        "query_id": hashlib.sha256(
            json.dumps(
                {
                    "query": args.query,
                    "path": args.path,
                    "artifact_id": args.artifact_id,
                    "task": args.task,
                    "spec": args.spec,
                    "capability": args.capability,
                    "filters": filters_from_args(args),
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:12],
        "text": args.query,
        "path": args.path,
        "artifact_id": args.artifact_id,
        "task": args.task,
        "spec": args.spec,
        "capability": args.capability,
    }
    modes_requested = requested_modes(args)
    has_query = bool(modes_requested)

    index_data = {"source": "none", "artifacts": [], "chunks": [], "links": [], "fts_available": False, "tables": []}
    sqlite_available = False
    if index_available and sqlite_path and sqlite_path.exists():
        try:
            index_data = load_index_from_sqlite(sqlite_path)
            sqlite_available = True
        except Exception as exc:
            findings.append(
                {
                    "id": "local_context_query.sqlite_unavailable",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": f"SQLite index could not be read; falling back to JSON report candidates. {exc}",
                }
            )
    if index_available and not sqlite_available:
        index_data = load_index_from_report(index_report)

    query_findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    modes_used: list[str] = []
    if has_query and index_available:
        results, modes_used, query_findings = query_index(args=args, index_data=index_data, index_report=index_report, sqlite_path=sqlite_path, limit=limit)
        findings.extend(query_findings)
        if not results:
            findings.append(
                {
                    "id": "local_context_query.no_results",
                    "severity": "advisory",
                    "status": "advisory",
                    "message": "No bounded candidate references matched the query.",
                }
            )
    elif not has_query:
        findings.append(
            {
                "id": "local_context_query.no_query",
                "severity": "advisory",
                "status": "not_configured",
                "message": "No query mode was supplied; use --query, --path, --artifact-id, --task, --spec, --capability, or metadata filters.",
            }
        )

    source_artifacts = [
        {
            "path": result.get("path"),
            "artifact_id": result.get("artifact_id"),
            "source_hash": result.get("source_hash"),
            "freshness_status": result.get("freshness_status"),
            "authority_level": result.get("authority_level"),
        }
        for result in results
    ]
    summary = finding_counts(findings)
    summary.update(
        {
            "results": len(results),
            "modes_requested": len(modes_requested),
            "modes_used": len(modes_used),
            "sqlite_available": sqlite_available,
            "fts_available": bool(index_data.get("fts_available")),
        }
    )
    status = status_from_findings(findings, has_query=has_query, index_available=index_available)
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "query": query_payload,
        "query_mode_requested": modes_requested,
        "query_mode_used": modes_used,
        "source_index": {
            "report_path": str(index_report_path),
            "report_status": index_report.get("status"),
            "report_hash": index_report.get("rules_hash"),
            "index_generated_at": index_report.get("generated_at"),
            "index_role": "generated derived cache-like retrieval substrate; not authoritative evidence",
        },
        "memory_provider_access": load_memory_provider_access(root, naos_root, policy),
        "memory_use_policy": load_memory_use_policy(root, naos_root, policy),
        "semantic_candidate_layer_readiness": load_semantic_candidate_readiness(root, naos_root, policy),
        "graph_context_readiness": load_graph_context_readiness(root, naos_root, policy),
        "sqlite_artifact": {
            "path": str(sqlite_path) if sqlite_path else None,
            "available": sqlite_available,
            "tables": index_data.get("tables") or [],
            "role": "read-only generated candidate index for this query report",
        },
        "fts_available": bool(index_data.get("fts_available")),
        "fts_query_sanitization": {
            "enabled": True,
            "query_original": args.query,
            "query_sanitized": sanitize_fts_query(args.query or "", int(((index_report.get("fts_query_sanitization") or {}).get("max_query_chars") or 120))),
            "no_raw_llm_match_queries": True,
            "fallback_when_unavailable": "metadata_text_fallback",
        },
        "filters": filters_from_args(args),
        "results": results,
        "result_count": len(results),
        "bounded_result_limit": limit,
        "source_artifacts": source_artifacts,
        "findings": findings,
        "known_gaps": [
            {"id": "LCQ-KG-001", "summary": "Semantic/vector, graph, MCP, and memory-payload query modes are intentionally out of scope."}
        ],
        "residual_risks": [
            {"id": "LCQ-RR-001", "summary": "Keyword and metadata queries can miss relevant artifacts or surface stale candidates."}
        ],
        "limitations": [
            "Query results are candidate references, not answers.",
            "The local context index is generated, derived, cache-like, and non-authoritative.",
            "Repository evidence and deterministic NAOS reports remain authoritative for review.",
            "FTS uses sanitized keyword search over bounded chunks when available; fallback search is simple bounded text matching.",
            "Memory-readiness metadata may be queried only as indexed report metadata; private memory payloads are not searched.",
        ],
        "not_claimed": [
            "source of truth",
            "authoritative truth",
            "answers",
            "hallucination prevention",
            "semantic retrieval",
            "semantic relevance scoring",
            "sqlite-vec",
            "embeddings",
            "vector similarity",
            "graph algorithms",
            "NetworkX",
            "GraphML",
            "MCP access",
            "Engram access",
            "memory payload search",
            "automatic context injection",
            "durable memory write-back",
        ],
        "human_review_required": any(item.get("severity") in {"required", "blocking"} or item.get("status") == "review_required" for item in findings),
        "summary": summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query the generated local NAOS context index.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy or naos.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--index-report", help="Optional local_context_index.json path.")
    parser.add_argument("--sqlite", help="Optional local_context_index.sqlite path.")
    parser.add_argument("--output", help="Optional JSON query report output path.")
    parser.add_argument("--query", help="Sanitized FTS/keyword query over bounded chunks.")
    parser.add_argument("--path", help="Exact indexed source path lookup.")
    parser.add_argument("--artifact-id", help="Exact indexed artifact id lookup.")
    parser.add_argument("--task", help="Task id lookup through explicit indexed links, e.g. T-123.")
    parser.add_argument("--spec", help="Spec reference lookup through explicit indexed links.")
    parser.add_argument("--capability", help="Capability id lookup through explicit indexed links.")
    parser.add_argument("--artifact-type", help="Filter by indexed artifact_type.")
    parser.add_argument("--authority-level", help="Filter by authority_level.")
    parser.add_argument("--freshness", help="Filter by freshness_status.")
    parser.add_argument("--profile-scope", help="Filter by profile_scope.")
    parser.add_argument("--report-status", help="Filter deterministic report summaries by status.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"Maximum results, capped at {MAX_LIMIT}.")
    parser.add_argument("--write-markdown", action="store_true", help="Write derived non-authoritative Markdown query results.")
    parser.add_argument("--markdown-output", help="Optional Markdown output path.")
    parser.add_argument("--json", action="store_true", help="Print JSON report. Default prints a short summary.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit-code behavior.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, naos_root, profile, policy, args)
    markdown_path = write_markdown_if_requested(root, naos_root, policy, report, args)
    if markdown_path:
        report["markdown_output"] = markdown_path
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "local_context_query_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(
            "NAOS local context query: "
            f"status={report['status']} results={report['result_count']} "
            f"modes={','.join(report['query_mode_used']) or 'none'} output={destination}"
        )
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
