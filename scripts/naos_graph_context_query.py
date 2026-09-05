#!/usr/bin/env python3
"""Query explicit NAOS graph-context links as bounded relationship candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

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


REPORT_SCHEMA = "naos.graph_context_query.v1"
DEFAULT_LIMIT = 25
MAX_LIMIT = 50
DEFAULT_DEPTH = 1
MAX_DEPTH = 2
SENSITIVE_TERMS = (
    "secret",
    "token",
    "password",
    "credential",
    "private_key",
    "private-key",
    "customer",
    "tenant",
    ".env",
    "engram.db",
)
RAW_LINK_TO_FAMILY = {
    "task_ref": "local_index_artifact_link",
    "spec_ref": "local_index_artifact_link",
    "capability_ref": "local_index_artifact_link",
}


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def kit_root() -> Path:
    return Path(__file__).resolve().parents[1]


def template_rules_path() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "graph_context_rules.yaml"


def bounded_text(value: Any, limit: int = 700) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 18)].rstrip() + " [truncated]"


def read_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def parse_json_text(value: Any, fallback: Any = None) -> Any:
    if not isinstance(value, str):
        return value if value is not None else fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback if fallback is not None else value


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def load_graph_rules(root: Path, naos_root: str, policy: dict[str, Any], rules_arg: str | None) -> tuple[dict[str, Any], Path, str]:
    candidates: list[tuple[Path, str]] = []
    if rules_arg:
        candidates.append((Path(rules_arg), "argument"))
    configured = str(policy.get("paths", {}).get("graph_context_rules") or "graph_context_rules.yaml")
    candidates.append((root / naos_root / configured, "project"))
    candidates.append((template_rules_path(), "template"))
    for path, source in candidates:
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return data if isinstance(data, dict) else {}, path, source
    return {}, template_rules_path(), "missing"


def local_context_query_markdown_dir(root: Path, naos_root: str, policy: dict[str, Any]) -> Path | None:
    if is_kit_repository(root, naos_root) or not (root / naos_root).is_dir():
        return None
    value = str(policy.get("paths", {}).get("graph_context_query_markdown_dir") or policy.get("paths", {}).get("local_context_query_markdown_dir") or "context_queries")
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
            sqlite_path = Path(sqlite_value) if sqlite_value else None
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
    return {"source": "sqlite", "artifacts": artifacts, "chunks": chunks, "links": links, "tables": sorted(tables)}


def load_index_from_report(index_report: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "report",
        "artifacts": index_report.get("indexed_artifacts") or [],
        "chunks": index_report.get("artifact_chunks") or [],
        "links": index_report.get("artifact_links") or [],
        "tables": [],
    }


def load_optional_report(root: Path, naos_root: str, policy: dict[str, Any], path_key: str, label: str) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, path_key)
    if not path.exists():
        return {"status": "not_configured", "path": str(path), "label": label}
    try:
        data = read_json_mapping(path)
    except Exception as exc:
        return {"status": "parse_error", "path": str(path), "label": label, "error": str(exc)}
    return {"status": data.get("status", "present"), "path": str(path), "label": label, "summary": data.get("summary") or {}, "data": data}


def artifact_by_id(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("artifact_id")): item for item in artifacts if item.get("artifact_id")}


def artifact_by_path(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("path")): item for item in artifacts if item.get("path")}


def reference_node_id(link_type: str, reference_id: str) -> str:
    reference_id = reference_id.strip().rstrip(".,);]")
    if link_type == "task_ref":
        return f"task:{reference_id.upper()}"
    if link_type == "spec_ref":
        return f"spec:{reference_id}"
    if link_type == "capability_ref":
        return f"capability:{reference_id.upper()}"
    return f"reference:{link_type}:{reference_id}"


def node_record(node_id: str, artifacts_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if node_id.startswith("artifact:"):
        artifact = artifacts_by_id.get(node_id.split(":", 1)[1]) or {}
        return {
            "node_id": node_id,
            "node_type": "artifact",
            "artifact_id": artifact.get("artifact_id"),
            "path": artifact.get("path"),
            "artifact_type": artifact.get("artifact_type"),
            "authority_level": artifact.get("authority_level"),
            "source_hash": artifact.get("source_hash"),
            "freshness_status": artifact.get("freshness_status"),
            "provenance": artifact.get("provenance"),
            "confidence": artifact.get("confidence"),
        }
    if node_id.startswith("task:"):
        return {"node_id": node_id, "node_type": "task", "reference_id": node_id.split(":", 1)[1]}
    if node_id.startswith("spec:"):
        return {"node_id": node_id, "node_type": "spec", "reference_id": node_id.split(":", 1)[1]}
    if node_id.startswith("capability:"):
        return {"node_id": node_id, "node_type": "capability", "reference_id": node_id.split(":", 1)[1]}
    return {"node_id": node_id, "node_type": node_id.split(":", 1)[0], "reference_id": node_id.split(":", 1)[-1]}


def is_sensitive_link(*values: Any) -> bool:
    text = " ".join(str(value or "").lower() for value in values)
    return any(term in text for term in SENSITIVE_TERMS)


def build_edges(
    artifacts: list[dict[str, Any]],
    links: list[dict[str, Any]],
    local_query: dict[str, Any],
    task_context: dict[str, Any],
) -> list[dict[str, Any]]:
    by_path = artifact_by_path(artifacts)
    edges: list[dict[str, Any]] = []
    for link in links:
        source_path = str(link.get("source_path") or "")
        artifact = by_path.get(source_path)
        if not artifact:
            continue
        raw_type = str(link.get("link_type") or "")
        reference_id = str(link.get("reference_id") or "")
        if not reference_id:
            continue
        edges.append(
            {
                "edge_id": f"E{len(edges) + 1:04d}",
                "source_node": f"artifact:{artifact.get('artifact_id')}",
                "target_node": reference_node_id(raw_type, reference_id),
                "link_type": raw_type,
                "relationship_family": RAW_LINK_TO_FAMILY.get(raw_type, "local_index_artifact_link"),
                "source_path": source_path,
                "target_path": None,
                "reference_id": reference_id,
                "provenance": "local_context_index.artifact_links",
                "confidence": "explicit_indexed_reference",
                "review_status": "unreviewed_candidate",
            }
        )
    query_data = as_mapping(local_query.get("data"))
    for item in as_list(query_data.get("source_artifacts")):
        path = str(as_mapping(item).get("path") or "")
        artifact = by_path.get(path)
        if not artifact:
            continue
        edges.append(
            {
                "edge_id": f"E{len(edges) + 1:04d}",
                "source_node": "context_query:current",
                "target_node": f"artifact:{artifact.get('artifact_id')}",
                "link_type": "context_query_to_artifact",
                "relationship_family": "context_query_to_artifact",
                "source_path": str(query_data.get("source_index", {}).get("report_path") or local_query.get("path")),
                "target_path": path,
                "reference_id": str(artifact.get("artifact_id")),
                "provenance": "local_context_query.source_artifacts",
                "confidence": "declared_report_reference",
                "review_status": "unreviewed_candidate",
            }
        )
    task_data = as_mapping(task_context.get("data"))
    for item in as_list(task_data.get("source_artifacts")):
        path = str(as_mapping(item).get("path") or "")
        artifact = by_path.get(path)
        if not artifact:
            continue
        edges.append(
            {
                "edge_id": f"E{len(edges) + 1:04d}",
                "source_node": "task_context_pack:current",
                "target_node": f"artifact:{artifact.get('artifact_id')}",
                "link_type": "task_context_pack_to_source_artifact",
                "relationship_family": "task_context_pack_to_source_artifact",
                "source_path": str(task_context.get("path")),
                "target_path": path,
                "reference_id": str(artifact.get("artifact_id")),
                "provenance": "task_context_pack.source_artifacts",
                "confidence": "declared_report_reference",
                "review_status": "unreviewed_candidate",
            }
        )
    return edges


def seed_nodes_from_args(args: argparse.Namespace, artifacts_by_id: dict[str, dict[str, Any]], artifacts_by_path: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    seeds: list[dict[str, Any]] = []
    modes: list[str] = []
    if args.artifact_id:
        modes.append("artifact_seed")
        seeds.append({"node_id": f"artifact:{args.artifact_id}", "seed_type": "artifact_id", "seed_value": args.artifact_id})
    if args.path:
        modes.append("path_seed")
        normalized = args.path.strip().lstrip("./")
        artifact = artifacts_by_path.get(normalized)
        seeds.append(
            {
                "node_id": f"artifact:{artifact.get('artifact_id')}" if artifact else f"path:{normalized}",
                "seed_type": "path",
                "seed_value": normalized,
            }
        )
    if args.task:
        modes.append("task_seed")
        seeds.append({"node_id": f"task:{args.task.upper()}", "seed_type": "task", "seed_value": args.task.upper()})
    if args.spec:
        modes.append("spec_seed")
        spec_value = args.spec.strip()
        normalized_spec = spec_value.rstrip(".,);]")
        seeds.append({"node_id": f"spec:{normalized_spec}", "seed_type": "spec", "seed_value": spec_value})
        if "#" in normalized_spec:
            fragment = normalized_spec.split("#", 1)[1]
            seeds.append({"node_id": f"spec:{fragment}", "seed_type": "spec", "seed_value": spec_value})
    if args.capability:
        modes.append("capability_seed")
        seeds.append({"node_id": f"capability:{args.capability.upper()}", "seed_type": "capability", "seed_value": args.capability.upper()})
    if args.context_query_result:
        modes.append("context_query_result_seed")
        seeds.append({"node_id": "context_query:current", "seed_type": "context_query_result", "seed_value": "current"})
    if args.task_context_pack:
        modes.append("task_context_pack_seed")
        seeds.append({"node_id": "task_context_pack:current", "seed_type": "task_context_pack", "seed_value": "current"})
    return seeds, modes


def edge_allowed(edge: dict[str, Any], allowed: set[str], prohibited: set[str], requested_link_type: str | None) -> bool:
    raw_type = str(edge.get("link_type") or "")
    family = str(edge.get("relationship_family") or "")
    if requested_link_type and requested_link_type not in {raw_type, family}:
        return False
    if raw_type in prohibited or family in prohibited:
        return False
    return family in allowed or raw_type in allowed


def build_adjacency(edges: list[dict[str, Any]]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for edge in edges:
        source = str(edge.get("source_node"))
        target = str(edge.get("target_node"))
        adjacency[source].append((target, edge))
        adjacency[target].append((source, edge))
    for node in adjacency:
        adjacency[node].sort(key=lambda item: (str(item[1].get("relationship_family")), str(item[1].get("link_type")), item[0]))
    return adjacency


def result_from_path(
    *,
    result_id: int,
    seed: dict[str, Any],
    node_path: list[str],
    edge_path: list[dict[str, Any]],
    artifacts_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    last_edge = edge_path[-1]
    source_node = node_record(str(last_edge.get("source_node")), artifacts_by_id)
    target_node = node_record(str(last_edge.get("target_node")), artifacts_by_id)
    source_artifact = source_node if source_node.get("node_type") == "artifact" else {}
    target_artifact = target_node if target_node.get("node_type") == "artifact" else {}
    not_claimed = [
        "truth",
        "source of truth",
        "implementation correctness proof",
        "graph runtime output",
    ]
    return {
        "result_id": f"GQ{result_id:04d}",
        "rank": result_id,
        "query_mode": seed.get("seed_type"),
        "seed_node": seed,
        "traversal_depth": len(edge_path),
        "depth": len(edge_path),
        "relationship_path": [node_record(node_id, artifacts_by_id) for node_id in node_path],
        "edge_path": [
            {
                "edge_id": edge.get("edge_id"),
                "link_type": edge.get("link_type"),
                "relationship_family": edge.get("relationship_family"),
                "source_node": edge.get("source_node"),
                "target_node": edge.get("target_node"),
                "provenance": edge.get("provenance"),
            }
            for edge in edge_path
        ],
        "link_type": last_edge.get("link_type"),
        "relationship_family": last_edge.get("relationship_family"),
        "reference_id": last_edge.get("reference_id"),
        "source_artifact_id": source_artifact.get("artifact_id"),
        "source_path": source_artifact.get("path") or last_edge.get("source_path"),
        "source_artifact_type": source_artifact.get("artifact_type"),
        "target_artifact_id": target_artifact.get("artifact_id"),
        "target_path": target_artifact.get("path") or last_edge.get("target_path"),
        "target_artifact_type": target_artifact.get("artifact_type"),
        "source": source_node,
        "target": target_node,
        "source_hash": source_artifact.get("source_hash"),
        "target_hash": target_artifact.get("source_hash"),
        "source_freshness_status": source_artifact.get("freshness_status"),
        "target_freshness_status": target_artifact.get("freshness_status"),
        "source_authority_level": source_artifact.get("authority_level"),
        "target_authority_level": target_artifact.get("authority_level"),
        "provenance": last_edge.get("provenance"),
        "confidence": last_edge.get("confidence") or "explicit_candidate_link",
        "review_status": last_edge.get("review_status") or "unreviewed_candidate",
        "limitations": [
            "relationship candidate only",
            "not source of truth",
            "check explicit source artifacts before acting",
        ],
        "not_claimed": not_claimed,
    }


def traverse(
    seeds: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    artifacts_by_id: dict[str, dict[str, Any]],
    *,
    depth: int,
    limit: int,
) -> list[dict[str, Any]]:
    adjacency = build_adjacency(edges)
    results: list[dict[str, Any]] = []
    seen_results: set[tuple[str, tuple[str, ...]]] = set()
    for seed in seeds:
        start = str(seed.get("node_id"))
        queue: deque[tuple[str, list[str], list[dict[str, Any]]]] = deque([(start, [start], [])])
        visited: set[tuple[str, int]] = {(start, 0)}
        while queue and len(results) < limit:
            node, node_path, edge_path = queue.popleft()
            if len(edge_path) >= depth:
                continue
            for next_node, edge in adjacency.get(node, []):
                next_depth = len(edge_path) + 1
                visit_key = (next_node, next_depth)
                if visit_key in visited:
                    continue
                next_nodes = node_path + [next_node]
                next_edges = edge_path + [edge]
                result_key = (str(edge.get("edge_id")), tuple(next_nodes))
                if result_key not in seen_results:
                    seen_results.add(result_key)
                    results.append(
                        result_from_path(
                            result_id=len(results) + 1,
                            seed=seed,
                            node_path=next_nodes,
                            edge_path=next_edges,
                            artifacts_by_id=artifacts_by_id,
                        )
                    )
                    if len(results) >= limit:
                        break
                visited.add(visit_key)
                queue.append((next_node, next_nodes, next_edges))
    return results


def finding(identifier: str, severity: str, status: str, message: str, *, path: str | None = None) -> dict[str, Any]:
    data = {"id": identifier, "severity": severity, "status": status, "message": message}
    if path:
        data["path"] = path
    return data


def status_from_findings(findings: list[dict[str, Any]], *, has_query: bool, index_available: bool) -> str:
    if not has_query:
        return "not_configured"
    if not index_available:
        return "missing_index"
    if any(item.get("severity") == "blocking" or item.get("status") == "blocked" for item in findings):
        return "blocked"
    if any(item.get("severity") in {"required", "review_required"} or item.get("status") == "review_required" for item in findings):
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def query_id_payload(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "artifact_id": args.artifact_id,
        "path": args.path,
        "task": args.task,
        "spec": args.spec,
        "capability": args.capability,
        "context_query_result": bool(args.context_query_result),
        "task_context_pack": bool(args.task_context_pack),
        "depth": args.depth,
        "link_type": args.link_type,
        "limit": args.limit,
    }


def write_markdown_if_requested(root: Path, naos_root: str, policy: dict[str, Any], report: dict[str, Any], args: argparse.Namespace) -> str | None:
    if not args.write_markdown:
        return None
    if args.markdown_output:
        path = Path(args.markdown_output)
    else:
        directory = local_context_query_markdown_dir(root, naos_root, policy)
        if directory is None:
            return None
        path = directory / f"graph_{report['query']['query_id']}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Graph Context Query: {report['query']['query_id']}",
        "",
        "> Derived, bounded, non-authoritative relationship candidates. Graph links are not truth; explicit source artifacts remain authoritative.",
        "",
        f"- Status: `{report['status']}`",
        f"- Profile: `{report['profile']}`",
        f"- Traversal depth used: `{report['traversal_depth_used']}`",
        f"- Results: `{report['result_count']}`",
        "",
        "## Seeds",
    ]
    for seed in report.get("seed_nodes") or []:
        lines.append(f"- `{seed.get('node_id')}` ({seed.get('seed_type')}: {seed.get('seed_value')})")
    lines.extend(["", "## Candidate Relationships"])
    for result in (report.get("results") or [])[:20]:
        lines.extend(
            [
                f"### {result.get('result_id')}: {result.get('relationship_family')} / {result.get('link_type')}",
                f"- Depth: `{result.get('traversal_depth')}`",
                f"- Source path: `{result.get('source_path')}`",
                f"- Target path: `{result.get('target_path')}`",
                f"- Source hash: `{result.get('source_hash')}`",
                f"- Target hash: `{result.get('target_hash')}`",
                f"- Freshness: `{result.get('source_freshness_status')}` -> `{result.get('target_freshness_status')}`",
                f"- Authority: `{result.get('source_authority_level')}` -> `{result.get('target_authority_level')}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Limitations",
            "- Graph query results are relationship candidates, not answers.",
            "- Source artifacts remain authoritative.",
            "- No NetworkX, GraphML, graph database, graph algorithms, semantic ranking, MCP, Engram, or memory payload traversal is used.",
            "- No hallucination-prevention guarantee is claimed.",
            "",
            "## Not Claimed",
        ]
    )
    for item in report.get("not_claimed") or []:
        lines.append(f"- {item}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return str(path)


def build_report(root: Path, naos_root: str, profile: str, policy: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    generated_at = utc_now_text()
    rules, rules_path, rules_source = load_graph_rules(root, naos_root, policy, args.rules)
    limits = as_mapping(rules.get("traversal_limits"))
    max_hops = min(int(limits.get("max_hops") or rules.get("max_hops") or DEFAULT_DEPTH), int(limits.get("max_allowed_hops") or MAX_DEPTH), MAX_DEPTH)
    max_seed_nodes = int(limits.get("max_seed_nodes") or rules.get("max_seed_nodes") or 5)
    max_edges_returned = min(int(limits.get("max_edges_returned") or rules.get("max_edges_returned") or DEFAULT_LIMIT), int(limits.get("max_allowed_edges_returned") or MAX_LIMIT), MAX_LIMIT)
    requested_depth = max(1, int(args.depth or DEFAULT_DEPTH))
    depth = min(requested_depth, max_hops)
    limit = min(max(1, int(args.limit or DEFAULT_LIMIT)), max_edges_returned)
    allowed = {str(item) for item in as_list(rules.get("allowed_link_types"))}
    prohibited = {str(item) for item in as_list(rules.get("prohibited_link_types"))}

    index_report_path, sqlite_path = local_context_index_paths(root, naos_root, policy, args.index_report, args.sqlite)
    index_report: dict[str, Any] = {}
    index_available = False
    sqlite_available = False
    findings: list[dict[str, Any]] = []
    if index_report_path.exists():
        try:
            index_report = read_json_mapping(index_report_path)
            index_available = True
        except Exception as exc:
            findings.append(finding("graph_context_query.index_report_parse_error", "advisory", "parse_error", f"Local context index report could not be parsed: {exc}", path=str(index_report_path)))
    else:
        findings.append(finding("graph_context_query.index_missing", "advisory", "not_configured", "Run naos context-index before querying graph context candidates.", path=str(index_report_path)))

    index_data = {"source": "none", "artifacts": [], "chunks": [], "links": [], "tables": []}
    if index_available and sqlite_path and sqlite_path.exists():
        try:
            index_data = load_index_from_sqlite(sqlite_path)
            sqlite_available = True
        except Exception as exc:
            findings.append(finding("graph_context_query.sqlite_unavailable", "advisory", "advisory", f"SQLite index could not be read; falling back to JSON report links. {exc}", path=str(sqlite_path)))
    if index_available and not sqlite_available:
        index_data = load_index_from_report(index_report)

    graph_readiness = load_optional_report(root, naos_root, policy, "graph_context_readiness_report", "graph_context_readiness")
    graph_data = as_mapping(graph_readiness.get("data"))
    if graph_readiness.get("status") == "not_configured":
        findings.append(finding("graph_context_query.graph_readiness_missing", "advisory", "not_configured", "Run naos graph-context before relying on graph-query posture.", path=str(graph_readiness.get("path"))))
    if bool(graph_data.get("graph_runtime_enabled")) or bool(graph_data.get("global_graph_scan_allowed")):
        findings.append(finding("graph_context_query.graph_readiness_unsafe", "required", "review_required", "Graph readiness report indicates unsafe runtime/global traversal flags; do not treat query results as approved traversal."))

    local_query = load_optional_report(root, naos_root, policy, "local_context_query_report", "local_context_query")
    task_context = load_optional_report(root, naos_root, policy, "task_context_pack_report", "task_context_pack")
    memory_access = load_optional_report(root, naos_root, policy, "memory_provider_access_report", "memory_provider_access")
    memory_use = load_optional_report(root, naos_root, policy, "memory_use_policy_report", "memory_use_policy")
    semantic = load_optional_report(root, naos_root, policy, "semantic_candidate_layer_report", "semantic_candidate_layer")

    artifacts = as_list(index_data.get("artifacts"))
    artifacts_by_id = artifact_by_id(artifacts)
    artifacts_by_path = artifact_by_path(artifacts)
    raw_edges = build_edges(artifacts, as_list(index_data.get("links")), local_query, task_context)
    filtered_edges: list[dict[str, Any]] = []
    for edge in raw_edges:
        if not edge_allowed(edge, allowed, prohibited, args.link_type):
            if args.link_type or str(edge.get("relationship_family")) in prohibited or str(edge.get("link_type")) in prohibited:
                findings.append(finding("graph_context_query.prohibited_or_disallowed_link", "advisory", "advisory", f"Skipped disallowed link type {edge.get('relationship_family')} / {edge.get('link_type')}."))
            continue
        filtered_edges.append(edge)

    seeds, modes_requested = seed_nodes_from_args(args, artifacts_by_id, artifacts_by_path)
    if len(seeds) > max_seed_nodes:
        findings.append(finding("graph_context_query.seed_limit_exceeded", "required", "review_required", f"Requested {len(seeds)} seed nodes; max_seed_nodes is {max_seed_nodes}."))
        seeds = seeds[:max_seed_nodes]
    if requested_depth > depth:
        findings.append(finding("graph_context_query.depth_clamped", "advisory", "advisory", f"Requested depth {requested_depth} was clamped to {depth}."))
    for seed in seeds:
        if seed["node_id"].startswith("path:"):
            findings.append(finding("graph_context_query.seed_path_missing", "advisory", "missing", f"Seed path was not found in the generated local context index: {seed['seed_value']}"))

    has_query = bool(modes_requested)
    if not has_query:
        findings.append(finding("graph_context_query.no_seed", "advisory", "not_configured", "Supply --artifact-id, --path, --task, --spec, --capability, --context-query-result, or --task-context-pack."))

    results = traverse(seeds, filtered_edges, artifacts_by_id, depth=depth, limit=limit) if has_query and index_available else []
    if has_query and index_available and not results:
        findings.append(finding("graph_context_query.no_results", "advisory", "advisory", "No bounded explicit relationship candidates matched the seed."))
    for result in results:
        if is_sensitive_link(result.get("source_path"), result.get("target_path"), result.get("reference_id")):
            findings.append(
                finding(
                    "graph_context_query.sensitive_link_candidate",
                    "required",
                    "review_required",
                    "A returned graph-query relationship candidate is sensitive-looking and requires human review.",
                    path=str(result.get("source_path") or result.get("target_path") or ""),
                )
            )
        if result.get("source_freshness_status") == "stale" or result.get("target_freshness_status") == "stale":
            findings.append(finding("graph_context_query.stale_link_candidate", "advisory", "stale", "A graph-query result references a stale source artifact.", path=str(result.get("source_path") or result.get("target_path") or "")))

    query = query_id_payload(args)
    query_id = hashlib.sha256(json.dumps(query, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    source_artifacts = []
    seen_source_paths: set[str] = set()
    for result in results:
        for side in ["source", "target"]:
            node = as_mapping(result.get(side))
            path = node.get("path")
            if path and path not in seen_source_paths:
                seen_source_paths.add(str(path))
                source_artifacts.append(
                    {
                        "path": path,
                        "artifact_id": node.get("artifact_id"),
                        "source_hash": node.get("source_hash"),
                        "freshness_status": node.get("freshness_status"),
                        "authority_level": node.get("authority_level"),
                    }
                )

    authority_summary: dict[str, int] = {}
    freshness_summary: dict[str, int] = {}
    for result in results:
        for key in ["source_authority_level", "target_authority_level"]:
            value = str(result.get(key) or "unknown")
            authority_summary[value] = authority_summary.get(value, 0) + 1
        for key in ["source_freshness_status", "target_freshness_status"]:
            value = str(result.get(key) or "unknown")
            freshness_summary[value] = freshness_summary.get(value, 0) + 1

    modes_used = sorted({str(result.get("query_mode")) for result in results if result.get("query_mode")})
    seed_values = [seed.get("seed_value") for seed in seeds]
    seed_types = [seed.get("seed_type") for seed in seeds]
    primary_seed = None if not seed_values else seed_values[0] if len(seed_values) == 1 else seed_values
    primary_seed_type = None if not seed_types else seed_types[0] if len(seed_types) == 1 else seed_types
    truncated = len(results) >= limit and len(filtered_edges) > len(results)
    summary = finding_counts(findings)
    summary.update(
        {
            "results": len(results),
            "seed_nodes": len(seeds),
            "edges_available": len(filtered_edges),
            "depth_used": depth,
            "limit": limit,
            "sqlite_available": sqlite_available,
            "truncated": truncated,
        }
    )
    human_review_required = (
        profile in {"standard", "assured"} and bool(results)
    ) or any(item.get("severity") in {"required", "blocking"} or item.get("status") == "review_required" for item in findings)
    memory_access_context = {key: value for key, value in memory_access.items() if key != "data"}
    memory_access_data = as_mapping(memory_access.get("data"))
    project_identity = as_mapping(memory_access_data.get("project_identity"))
    memory_access_context.update(
        {
            "provider_configured": bool(memory_access_data.get("provider_configured")),
            "provider_access_verified": bool(memory_access_data.get("provider_access_verified")),
            "mcp_access_verified": bool(memory_access_data.get("mcp_access_verified")),
            "project_identity": {
                "status": project_identity.get("status"),
                "project_identity_verified": bool(project_identity.get("project_identity_verified")),
                "global_fixed_project_detected": bool(project_identity.get("global_fixed_project_detected")),
            },
        }
    )
    memory_use_context = {key: value for key, value in memory_use.items() if key != "data"}
    memory_use_data = as_mapping(memory_use.get("data"))
    memory_use_context.update(
        {
            "memory_access_prerequisites": memory_use_data.get("memory_access_prerequisites") or {},
            "policy_item_access_posture": memory_use_data.get("policy_item_access_posture") or [],
        }
    )
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status_from_findings(findings, has_query=has_query, index_available=index_available),
        "naos_root": naos_root,
        "project_root": str(root),
        "graph_readiness_report_path": str(graph_readiness.get("path") or ""),
        "local_context_index_report_path": str(index_report_path),
        "local_context_query_report_path": str(local_query.get("path") or ""),
        "query": {"query_id": query_id, **query},
        "seed": primary_seed,
        "seed_type": primary_seed_type,
        "query_mode_requested": modes_requested,
        "query_mode_used": modes_used,
        "depth_requested": requested_depth,
        "depth_used": depth,
        "traversal_depth_requested": requested_depth,
        "traversal_depth_used": depth,
        "limit": limit,
        "link_type_filter": args.link_type,
        "traversal_limits": {
            "max_hops": max_hops,
            "max_seed_nodes": max_seed_nodes,
            "max_edges_returned": max_edges_returned,
            "explicit_seed_required": True,
            "global_traversal_allowed": False,
        },
        "allowed_link_types": sorted(allowed),
        "prohibited_link_types": sorted(prohibited),
        "seed_nodes": seeds,
        "results": results,
        "result_count": len(results),
        "truncated": truncated,
        "bounded_result_limit": limit,
        "authority_summary": dict(sorted(authority_summary.items())),
        "freshness_summary": dict(sorted(freshness_summary.items())),
        "source_artifacts": source_artifacts,
        "source_index": {
            "report_path": str(index_report_path),
            "report_status": index_report.get("status"),
            "index_generated_at": index_report.get("generated_at"),
            "index_role": "generated explicit-link source; not authoritative evidence",
        },
        "sqlite_artifact": {"path": str(sqlite_path) if sqlite_path else None, "available": sqlite_available, "tables": index_data.get("tables") or []},
        "sqlite_artifact_exists": bool(sqlite_path and sqlite_path.exists()),
        "graph_context_readiness": {key: value for key, value in graph_readiness.items() if key != "data"},
        "local_context_query_context": {key: value for key, value in local_query.items() if key != "data"},
        "memory_provider_access": memory_access_context,
        "memory_use_policy": memory_use_context,
        "task_context_pack_context": {key: value for key, value in task_context.items() if key != "data"},
        "semantic_candidate_layer_readiness": {key: value for key, value in semantic.items() if key != "data"},
        "memory_policy": as_mapping(rules.get("memory_policy")) | {
            "memory_payload_traversal": False,
            "memory_references_metadata_only": True,
        },
        "findings": findings,
        "known_gaps": [
            {"id": "GCQ-KG-001", "summary": "Graph query uses explicit indexed/report links only; richer module/test/finding links depend on upstream deterministic reports."},
            {"id": "GCQ-KG-002", "summary": "No graph runtime, graph algorithm, graph database, semantic ranking, MCP, Engram, or memory-payload traversal is implemented."},
        ],
        "residual_risks": [
            {"id": "GCQ-RR-001", "summary": "Explicit links can be stale, incomplete, or weak; source artifacts must be checked directly."},
            {"id": "GCQ-RR-002", "summary": "Two-hop traversal can surface context candidates that are related but not relevant to the active task."},
        ],
        "waivers": [],
        "limitations": [
            "Graph query results are relationship candidates, not truth.",
            "Explicit source artifacts and repository evidence remain authoritative.",
            "Traversal is bounded to explicit indexed/report links and configured hop/edge limits.",
            "No NetworkX, GraphML, graph database, graph algorithms, semantic graph ranking, MCP, Engram, or memory payload traversal is used.",
            "No hallucination-prevention guarantee is claimed.",
        ],
        "not_claimed": [
            "source of truth",
            "authoritative truth",
            "implementation correctness proof",
            "complete graph coverage",
            "global graph scan",
            "graph runtime",
            "graph database",
            "NetworkX",
            "GraphML",
            "graph algorithms",
            "PageRank",
            "centrality",
            "community detection",
            "semantic graph ranking",
            "sqlite-vec",
            "embeddings",
            "MCP access",
            "Engram access",
            "memory payload traversal",
            "automatic context injection",
            "durable memory write-back",
            "hallucination prevention",
        ],
        "human_review_required": human_review_required,
        "summary": summary,
    }
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query bounded explicit graph-context relationship candidates.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy or naos.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--rules", help="Optional graph_context_rules.yaml path.")
    parser.add_argument("--index-report", help="Optional local_context_index.json path.")
    parser.add_argument("--sqlite", help="Optional local_context_index.sqlite path.")
    parser.add_argument("--output", help="Optional JSON query report output path.")
    parser.add_argument("--artifact-id", help="Seed traversal from an indexed artifact id.")
    parser.add_argument("--path", help="Seed traversal from an indexed source path.")
    parser.add_argument("--task", help="Seed traversal from a task id, e.g. T-123.")
    parser.add_argument("--spec", help="Seed traversal from a spec reference.")
    parser.add_argument("--capability", help="Seed traversal from a capability id.")
    parser.add_argument("--context-query-result", action="store_true", help="Seed traversal from the latest local context query source-artifact references.")
    parser.add_argument("--task-context-pack", action="store_true", help="Seed traversal from the latest task context pack source-artifact references.")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help=f"Traversal depth, capped at {MAX_DEPTH} and graph_context_rules.yaml limits.")
    parser.add_argument("--link-type", help="Optional raw link type or relationship family filter.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"Maximum relationship results, capped at {MAX_LIMIT} and graph_context_rules.yaml limits.")
    parser.add_argument("--write-markdown", action="store_true", help="Write derived non-authoritative Markdown graph query results.")
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
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "graph_context_query_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS graph context query: "
            f"status={report['status']} results={report['result_count']} "
            f"depth={report['traversal_depth_used']} output={output}"
        )
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
