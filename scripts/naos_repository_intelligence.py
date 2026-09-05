#!/usr/bin/env python3
"""Plan, activate, validate, refresh, and query brownfield repository intelligence.

The capability writes only operation-owned ``.naos/upgrade-v1`` state.
Repository source remains read-only and authoritative.  Plans bind the effective source
inventory, selected rules, runtime tuple, component versions, and ongoing-use
scope before a separate digest-confirmed apply publishes one active generation.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from collections import Counter, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator, ValidationError

SCRIPT_DIR = Path(__file__).resolve().parent
KIT_DIR = SCRIPT_DIR.parent
for import_root in (SCRIPT_DIR, KIT_DIR):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

try:  # Installed package or source-checkout shim.
    from naos_governance.upgrade_contract.canonical import (
        CanonicalizationError,
        CanonicalizationUnavailable,
        canonical_sha256,
        loads_strict_json,
    )
    from naos_governance.upgrade_contract.provenance import (
        CONTEXT_RELATIVE,
        LOCK_RELATIVE,
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        TRANSACTIONS_RELATIVE,
        ProvenanceError,
        ScopeInspection,
        build_enrollment_objects,
        commit_enrollment,
        inspect_managed_content_scope,
        inspect_scope,
    )
    from naos_governance.upgrade_contract.transaction import (
        StableFileLock,
        TransactionPrimitiveError,
        current_managed_content_paths,
        fsync_directory,
        lock_observation as observe_stable_lock,
        rename_no_replace,
    )
except ImportError:  # Generated standalone adopter surface.
    from upgrade_contract.canonical import (  # type: ignore[no-redef]
        CanonicalizationError,
        CanonicalizationUnavailable,
        canonical_sha256,
        loads_strict_json,
    )
    from upgrade_contract.provenance import (  # type: ignore[no-redef]
        CONTEXT_RELATIVE,
        LOCK_RELATIVE,
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        TRANSACTIONS_RELATIVE,
        ProvenanceError,
        ScopeInspection,
        build_enrollment_objects,
        commit_enrollment,
        inspect_managed_content_scope,
        inspect_scope,
    )
    from upgrade_contract.transaction import (  # type: ignore[no-redef]
        StableFileLock,
        TransactionPrimitiveError,
        current_managed_content_paths,
        fsync_directory,
        lock_observation as observe_stable_lock,
        rename_no_replace,
    )

import naos_local_context_index as local_context_index_module  # noqa: E402
from naos_local_context_index import (  # noqa: E402
    build_artifact_records,
    load_yaml_mapping,
    populate_sqlite_database,
    safe_digest,
    sanitize_fts_query,
    secure_regular_file_bytes,
    secure_regular_file_snapshot,
)
from naos_policy import (  # noqa: E402
    default_naos_root,
    kit_root,
    load_policy,
    normalize_profile,
    safe_path_under,
    write_report,
)


PLAN_SCHEMA = "naos.repository_intelligence.plan.v1"
PLAN_BUNDLE_SCHEMA = "naos.repository_intelligence.plan_bundle.v1"
MANIFEST_SCHEMA = "naos.repository_intelligence.manifest.v1"
RECEIPT_SCHEMA = "naos.repository_intelligence.validation_receipt.v1"
ACTIVATION_RECEIPT_SCHEMA = "naos.repository_intelligence.activation_receipt.v1"
ACTIVE_SCHEMA = "naos.repository_intelligence.active.v1"
APPLY_RESULT_SCHEMA = "naos.repository_intelligence.apply_result.v1"
QUERY_SCHEMA = "naos.repository_intelligence.query.v1"
CONTEXT_SCHEMA = "naos.repository_intelligence_context.v1"
INVENTORY_SCHEMA = "naos.repository_intelligence.inventory.v1"
JOURNAL_SCHEMA = "naos.repository_intelligence.transaction_journal.v1"
ENROLLMENT_RESULT_SCHEMA = "naos.repository_intelligence.enrollment_result.v1"
STATUS_SCHEMA = "naos.repository_intelligence.status.v1"
RECOVERY_RESULT_SCHEMA = "naos.repository_intelligence.recovery_result.v1"
CAPABILITY_ID = "CAP-LOCAL-CONTEXT-INDEX"
RFC8785_VERSION = "0.1.4"
NETWORKX_VERSION = "3.6.1"
SUPPORTED_PYTHON_MINORS = {(3, 11), (3, 12), (3, 13)}
SUPPORTED_SYSTEM = "Darwin"
SUPPORTED_MACHINES = {"arm64", "aarch64"}
COMPONENT_MODES = ("auto", "baseline", "graph")
REVIEWER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:/+\-]{1,127}$")
TRANSACTION_ID_RE = re.compile(r"^RIT-[0-9a-f]{24}$")
MAX_GRAPHML_BYTES = 32 * 1024 * 1024
MAX_GRAPHML_NODES = 20_000
MAX_GRAPHML_EDGES = 50_000
PURPOSE_QUESTIONS = {
    "brownfield-onboarding": [
        "Which current source, tests, specifications, migrations, and documentation are explicitly connected?",
        "Which multi-hop source relationships can improve requirements reconstruction and traceability review?",
    ],
    "ongoing-change-impact": [
        "Which explicitly linked source, test, specification, and documentation artifacts may be affected by a bounded change?",
    ],
    "task-context": [
        "Which source-bound artifacts form the smallest relevant context around a task, path, specification, or capability seed?",
    ],
}
SOURCE_SUFFIXES = {
    ".bash",
    ".cjs",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
}
JS_IMPORT_RE = re.compile(
    r"(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)[\"']([^\"']+)[\"']"
)
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s#]+)(?:#[^)\s]+)?\)")
PATH_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.(?:py|js|jsx|ts|tsx|md|yaml|yml|json|toml|sql|go|rs|java|kt|cs|rb|php|sh))(?![A-Za-z0-9_.-])"
)
class RepositoryIntelligenceError(RuntimeError):
    """Expected fail-closed product error."""


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


SCHEMA_FILES = {
    PLAN_SCHEMA: "repository_intelligence_plan.schema.json",
    MANIFEST_SCHEMA: "repository_intelligence_manifest.schema.json",
    RECEIPT_SCHEMA: "repository_intelligence_validation.schema.json",
    ACTIVATION_RECEIPT_SCHEMA: "repository_intelligence_activation_receipt.schema.json",
    ACTIVE_SCHEMA: "repository_intelligence_active.schema.json",
    APPLY_RESULT_SCHEMA: "repository_intelligence_apply_result.schema.json",
    QUERY_SCHEMA: "repository_intelligence_query.schema.json",
    CONTEXT_SCHEMA: "repository_intelligence_context.schema.json",
    INVENTORY_SCHEMA: "repository_intelligence_inventory.schema.json",
    JOURNAL_SCHEMA: "repository_intelligence_transaction_journal.schema.json",
    ENROLLMENT_RESULT_SCHEMA: "repository_intelligence_enrollment_result.schema.json",
    STATUS_SCHEMA: "repository_intelligence_status.schema.json",
    RECOVERY_RESULT_SCHEMA: "repository_intelligence_recovery_result.schema.json",
}

GENERATED_SCRIPT_MARKER = b"# AUTO-GENERATED: Copied by naos init from the NAOS kit.\n"


def _schema_path(filename: str) -> Path:
    path = kit_root() / "schemas" / "naos" / filename
    if not path.is_file():
        raise RepositoryIntelligenceError(f"Required repository-intelligence schema is unavailable: {path}")
    return path


def _validate_schema(instance: dict[str, Any], schema_name: str) -> None:
    filename = SCHEMA_FILES.get(schema_name)
    if not filename:
        raise RepositoryIntelligenceError(f"No validator is registered for schema {schema_name!r}.")
    try:
        schema = loads_strict_json(secure_regular_file_bytes(_schema_path(filename)))
        Draft202012Validator(schema).validate(instance)
    except (ValidationError, CanonicalizationError, OSError, ValueError) as exc:
        raise RepositoryIntelligenceError(
            f"Repository-intelligence object failed {schema_name} validation: {exc}"
        ) from exc


def _implementation_source_sha256(path: Path) -> str:
    """Hash executable source while ignoring only init's exact provenance marker."""

    source = secure_regular_file_bytes(path)
    if source.startswith(b"#!"):
        first_newline = source.find(b"\n")
        marker_start = first_newline + 1
        if first_newline >= 0 and source.startswith(
            GENERATED_SCRIPT_MARKER,
            marker_start,
        ):
            source = source[:marker_start] + source[
                marker_start + len(GENERATED_SCRIPT_MARKER) :
            ]
    elif source.startswith(GENERATED_SCRIPT_MARKER):
        source = source[len(GENERATED_SCRIPT_MARKER) :]
    return sha256_bytes(source)


def _implementation_identity() -> dict[str, Any]:
    engine_path = Path(__file__).resolve()
    index_path = Path(local_context_index_module.__file__).resolve()
    canonical_module = sys.modules[canonical_sha256.__module__]
    canonical_path = Path(str(canonical_module.__file__)).resolve()
    return {
        "contract_version": 1,
        "engine_sha256": _implementation_source_sha256(engine_path),
        "local_context_index_sha256": _implementation_source_sha256(index_path),
        "canonical_adapter_sha256": _implementation_source_sha256(canonical_path),
        "graphml_writer": "networkx.write_graphml_xml",
        "sqlite_serializer": "python_stdlib_sqlite3",
    }


def _validate_rules(rules: dict[str, Any]) -> None:
    try:
        schema = loads_strict_json(
            secure_regular_file_bytes(_schema_path("repository_intelligence_rules.schema.json"))
        )
        Draft202012Validator(schema).validate(rules)
    except (ValidationError, CanonicalizationError, OSError, ValueError) as exc:
        raise RepositoryIntelligenceError(f"Repository-intelligence rules are invalid: {exc}") from exc


def default_rules_path() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "repository_intelligence_rules.yaml"


def _safe_existing_project_file(root: Path, relative: str, *, field: str) -> Path | None:
    try:
        path = safe_path_under(root, relative, field=field)
    except ValueError:
        return None
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return None
    return path


def resolve_rules_path(root: Path, naos_root: str, explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = root / path
        try:
            metadata = os.lstat(path)
        except OSError as exc:
            raise RepositoryIntelligenceError(f"Repository-intelligence rules are unavailable: {path}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RepositoryIntelligenceError(f"Refusing unsafe repository-intelligence rules file: {path}")
        return path, "explicit"
    project_rules = _safe_existing_project_file(
        root,
        f"{naos_root}/repository_intelligence_rules.yaml",
        field="repository_intelligence_rules",
    )
    if project_rules is not None:
        return project_rules, "project"
    return default_rules_path(), "template"


def validate_project_root(value: str | Path) -> Path:
    lexical = Path(value).expanduser()
    absolute = Path(os.path.abspath(os.fspath(lexical)))
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise RepositoryIntelligenceError(f"Project root is unavailable: {absolute}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RepositoryIntelligenceError(f"Project root must be a real directory, not a symlink: {absolute}")
    return absolute.resolve(strict=True)


def probe_fts5() -> dict[str, Any]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE VIRTUAL TABLE fts_probe USING fts5(value)")
        connection.execute("INSERT INTO fts_probe(value) VALUES (?)", ("naos brownfield probe",))
        matched = connection.execute(
            "SELECT count(*) FROM fts_probe WHERE fts_probe MATCH ?", ("brownfield",)
        ).fetchone()
        ready = bool(matched and int(matched[0]) == 1)
        return {
            "status": "ready" if ready else "failed",
            "sqlite_version": sqlite3.sqlite_version,
            "fts5_available": ready,
            "probe": "create_insert_match",
        }
    except sqlite3.Error as exc:
        return {
            "status": "unavailable",
            "sqlite_version": sqlite3.sqlite_version,
            "fts5_available": False,
            "probe": "create_insert_match",
            "error": str(exc),
        }
    finally:
        connection.close()


def runtime_probe() -> dict[str, Any]:
    system = platform.system()
    machine = platform.machine().lower()
    python_minor = (sys.version_info.major, sys.version_info.minor)
    implementation = platform.python_implementation()
    supported = (
        system == SUPPORTED_SYSTEM
        and machine in SUPPORTED_MACHINES
        and python_minor in SUPPORTED_PYTHON_MINORS
        and implementation == "CPython"
    )
    rfc_version = package_version("rfc8785")
    networkx_version = package_version("networkx")
    networkx_imported_version: str | None = None
    networkx_module_sha256: str | None = None
    networkx_writer_available = False
    try:
        import networkx as nx

        networkx_imported_version = str(nx.__version__)
        networkx_writer_available = callable(getattr(nx, "write_graphml_xml", None))
        module_path = Path(str(nx.__file__)).resolve()
        networkx_module_sha256 = sha256_bytes(secure_regular_file_bytes(module_path))
    except (ImportError, OSError, ValueError):
        pass
    networkx_ready = (
        networkx_version == NETWORKX_VERSION
        and networkx_imported_version == NETWORKX_VERSION
        and networkx_writer_available
        and networkx_module_sha256 is not None
    )
    return {
        "platform": {
            "system": system,
            "machine": machine,
            "python": platform.python_version(),
            "implementation": implementation,
            "supported_for_apply": supported,
            "supported_tuple": "macos_arm64_cpython_3_11_to_3_13_binary_wheels",
        },
        "rfc8785": {
            "required_version": RFC8785_VERSION,
            "installed_version": rfc_version,
            "status": "ready" if rfc_version == RFC8785_VERSION else "prerequisite_missing",
        },
        "networkx": {
            "required_version": NETWORKX_VERSION,
            "installed_version": networkx_version,
            "imported_version": networkx_imported_version,
            "module_sha256": networkx_module_sha256,
            "writer": "networkx.write_graphml_xml",
            "writer_available": networkx_writer_available,
            "status": "ready" if networkx_ready else "prerequisite_missing",
            "install_extra": "naos-governance[repository-intelligence]",
        },
        "sqlite_fts": probe_fts5(),
        "sqlite_vec": {
            "status": "workload_not_defined",
            "runtime_probed": False,
            "reason": "No frozen retrieval workload or deterministic vector producer is configured.",
        },
    }


def maturity_evidence(root: Path, naos_root: str) -> dict[str, Any]:
    state_path = _safe_existing_project_file(
        root,
        f"{naos_root}/capability_state.yaml",
        field="capability_state",
    )
    if state_path is None:
        return {
            "capability_id": CAPABILITY_ID,
            "declared_level": "L0",
            "status": "unconfigured",
            "source": "brownfield_default",
            "authorization_effect": "none",
        }
    try:
        state = load_yaml_mapping(state_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return {
            "capability_id": CAPABILITY_ID,
            "declared_level": "L0",
            "status": "invalid",
            "source": "project_capability_state",
            "path": str(state_path),
            "error": str(exc),
            "authorization_effect": "none",
        }
    entries = state.get("capabilities")
    if not isinstance(entries, list):
        return {
            "capability_id": CAPABILITY_ID,
            "declared_level": "L0",
            "status": "invalid",
            "source": "project_capability_state",
            "path": str(state_path),
            "error": "capabilities must be a list",
            "authorization_effect": "none",
        }
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict) and str(item.get("capability_id") or "") == CAPABILITY_ID
        ),
        None,
    )
    if entry is None:
        return {
            "capability_id": CAPABILITY_ID,
            "declared_level": "L0",
            "status": "unconfigured",
            "source": "project_capability_state",
            "path": str(state_path),
            "authorization_effect": "none",
        }
    level = str(entry.get("current_maturity") or "")
    if level not in {"L0", "L1", "L2", "L3", "L4", "L5"}:
        return {
            "capability_id": CAPABILITY_ID,
            "declared_level": "L0",
            "status": "invalid",
            "source": "project_capability_state",
            "path": str(state_path),
            "error": f"unsupported current_maturity: {level or 'missing'}",
            "authorization_effect": "none",
        }
    return {
        "capability_id": CAPABILITY_ID,
        "declared_level": level,
        "status": "declared_unverified",
        "source": "project_capability_state",
        "path": str(state_path),
        "authorization_effect": "none",
    }


def _artifact_inventory(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        [
            {
                "artifact_id": str(item.get("artifact_id") or ""),
                "path": str(item.get("path") or ""),
                "family_id": str(item.get("family_id") or ""),
                "artifact_type": str(item.get("artifact_type") or ""),
                "authority_level": str(item.get("authority_level") or ""),
                "source_sha256": item.get("source_hash"),
                "size_bytes": int(item.get("size_bytes") or 0),
            }
            for item in artifacts
        ],
        key=lambda item: (item["path"], item["artifact_id"]),
    )


def _coverage_binding(
    inventory: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    *,
    observed_relationships: int,
    relationships_truncated: bool,
) -> dict[str, Any]:
    """Bind retained source plus every exclusion that makes coverage incomplete."""

    incomplete_reasons = {
        "max_artifacts_exceeded",
        *local_context_index_module.UNSAFE_SOURCE_TOPOLOGY_REASONS,
    }
    incomplete_exclusions = sorted(
        (
            {
                str(key): value
                for key, value in item.items()
                if key in {"path", "reason", "max_artifacts", "matched_family"}
            }
            for item in excluded
            if str(item.get("reason") or "") in incomplete_reasons
        ),
        key=lambda item: (
            str(item.get("path") or ""),
            str(item.get("reason") or ""),
            str(item.get("matched_family") or ""),
        ),
    )
    return {
        "source_inventory": inventory,
        "incomplete_exclusions": incomplete_exclusions,
        "observed_relationships": observed_relationships,
        "relationships_truncated": relationships_truncated,
    }


def _sqlite_rows_binding(rows: Iterable[Iterable[Any]]) -> dict[str, Any]:
    normalized_rows = sorted(
        ([*row] for row in rows),
        key=lambda row: str(row[0]) if row else "",
    )
    identifiers = [str(row[0] or "") if row else "" for row in normalized_rows]
    if any(not identifier for identifier in identifiers) or len(identifiers) != len(set(identifiers)):
        raise RepositoryIntelligenceError(
            "Repository-intelligence SQLite identities are missing or duplicated."
        )
    return {
        "count": len(identifiers),
        "ids_sha256": canonical_sha256(identifiers),
        "rows_sha256": canonical_sha256(normalized_rows),
    }


def _sqlite_content_binding(
    artifacts: list[dict[str, Any]],
    chunks: list[dict[str, Any]],
    links: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "artifacts": _sqlite_rows_binding(
            (
                item.get("artifact_id"),
                item.get("path"),
                item.get("artifact_type"),
                item.get("authority_level"),
                json.dumps(item.get("profile_scope"), sort_keys=True),
                item.get("source_hash"),
                item.get("modified_at"),
                item.get("indexed_at"),
                item.get("freshness_status"),
                item.get("provenance"),
                item.get("include_policy"),
                item.get("exclusion_reason"),
                item.get("scope"),
                item.get("use_policy"),
                item.get("review_status"),
                item.get("source_reference"),
                item.get("confidence"),
                json.dumps(item.get("limitations") or [], sort_keys=True),
                item.get("recall_trace_readiness"),
                item.get("audit_event_readiness"),
            )
            for item in artifacts
        ),
        "artifact_chunks": _sqlite_rows_binding(
            (
                item.get("chunk_id"),
                item.get("artifact_id"),
                item.get("path"),
                item.get("section_heading"),
                item.get("chunk_kind"),
                item.get("text_summary"),
                item.get("bounded_excerpt"),
                item.get("start_line"),
                item.get("end_line"),
                item.get("char_count"),
                item.get("confidence"),
                json.dumps(item.get("limitations") or [], sort_keys=True),
                item.get("scope"),
                item.get("use_policy"),
                item.get("review_status"),
                item.get("source_reference"),
                item.get("recall_trace_readiness"),
                item.get("audit_event_readiness"),
                json.dumps(item.get("related_task_ids") or [], sort_keys=True),
                json.dumps(item.get("related_spec_refs") or [], sort_keys=True),
                json.dumps(item.get("related_capabilities") or [], sort_keys=True),
                json.dumps(item.get("related_code_symbols") or [], sort_keys=True),
                json.dumps(item.get("related_tests") or [], sort_keys=True),
            )
            for item in chunks
        ),
        "artifact_links": _sqlite_rows_binding(
            (
                item.get("link_id"),
                item.get("source_path"),
                item.get("link_type"),
                item.get("reference_id"),
            )
            for item in links
        ),
        "repository_relationships": _sqlite_rows_binding(
            (
                item.get("relationship_id"),
                item.get("source_node"),
                item.get("target_node"),
                item.get("relationship_type"),
                item.get("source_path"),
                item.get("target_path"),
                item.get("source_sha256"),
                item.get("target_sha256"),
                item.get("evidence_sha256"),
                item.get("evidence_line"),
                item.get("reference_id"),
                item.get("provenance"),
                item.get("confidence"),
                1,
            )
            for item in relationships
        ),
    }


def _stable_generation_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stable: list[dict[str, Any]] = []
    for source in artifacts:
        item = dict(source)
        item["modified_at"] = None
        item["indexed_at"] = None
        item["freshness_status"] = "content_hash_bound"
        item.pop("age_days", None)
        item.pop("_source_bytes", None)
        stable.append(item)
    return stable


def _secret_content_reason(data: bytes) -> str | None:
    return local_context_index_module.secret_content_reason(data)


def _exclude_secret_content(
    root: Path,
    artifacts: list[dict[str, Any]],
    chunks: list[dict[str, Any]],
    links: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rejected_ids: set[str] = set()
    rejected_paths: set[str] = set()
    retained: list[dict[str, Any]] = []
    for artifact in artifacts:
        path_text = str(artifact.get("path") or "")
        data = artifact.get("_source_bytes")
        if not isinstance(data, bytes):
            retained.append(artifact)
            continue
        reason = _secret_content_reason(data)
        if reason is None:
            retained.append(artifact)
            continue
        rejected_ids.add(str(artifact.get("artifact_id") or ""))
        rejected_paths.add(path_text)
        excluded.append(
            {
                "path": path_text,
                "reason": "secret_like_content_excluded",
                "pattern_id": reason,
                "matched_family": artifact.get("family_id"),
            }
        )
    if not rejected_ids:
        return artifacts, chunks, links, excluded
    return (
        retained,
        [item for item in chunks if str(item.get("artifact_id") or "") not in rejected_ids],
        [item for item in links if str(item.get("source_path") or "") not in rejected_paths],
        sorted(excluded, key=lambda item: str(item.get("path") or "")),
    )


def _known_path_resolution(
    source_path: str,
    reference: str,
    known_paths: set[str],
    *,
    python_module: bool = False,
    suffixes: tuple[str, ...] | None = None,
) -> str | None:
    reference = reference.strip().split("#", 1)[0].split("?", 1)[0]
    if not reference or reference.startswith(("http://", "https://", "mailto:", "#")):
        return None
    source_parent = Path(source_path).parent
    candidates: list[str] = []
    if python_module:
        module_path = reference.replace(".", "/")
        candidates.extend([f"{module_path}.py", f"{module_path}/__init__.py"])
        suffix_matches = sorted(
            path
            for path in known_paths
            if path.endswith(f"/{module_path}.py") or path.endswith(f"/{module_path}/__init__.py")
        )
        candidates.extend(suffix_matches)
    else:
        relative = (source_parent / reference).as_posix()
        candidates.append(relative)
        if Path(relative).suffix == "":
            candidate_suffixes = suffixes or (
                ".py",
                ".js",
                ".jsx",
                ".ts",
                ".tsx",
                ".mjs",
                ".cjs",
                ".md",
                ".json",
                ".yaml",
                ".yml",
                ".sql",
            )
            for suffix in candidate_suffixes:
                candidates.append(f"{relative}{suffix}")
            for suffix in candidate_suffixes:
                if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                    continue
                candidates.append(f"{relative}/index{suffix}")
    matches: list[str] = []
    for candidate in candidates:
        parts: list[str] = []
        escaped_root = False
        for part in Path(candidate).as_posix().lstrip("/").split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if not parts:
                    escaped_root = True
                    break
                parts.pop()
                continue
            parts.append(part)
        if escaped_root:
            continue
        normalized = "/".join(parts)
        if normalized in known_paths:
            matches.append(normalized)
    unique = sorted(set(matches))
    return unique[0] if len(unique) == 1 else None


def _python_import_references(path: str, text: str, known_paths: set[str]) -> list[tuple[str, str, int | None]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    references: list[tuple[str, str, int | None]] = []
    parent_parts = list(Path(path).parent.parts)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = _known_path_resolution(path, alias.name, known_paths, python_module=True)
                if target:
                    references.append((target, "python_import", getattr(node, "lineno", None)))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            target: str | None = None
            if node.level:
                keep = max(0, len(parent_parts) - max(0, node.level - 1))
                relative_parts = parent_parts[:keep] + ([*module.split(".")] if module else [])
                relative_module = "/".join(part for part in relative_parts if part)
                target = _known_path_resolution(path, f"/{relative_module}", known_paths)
                if target is None:
                    candidates = [f"{relative_module}.py", f"{relative_module}/__init__.py"]
                    target = next((item for item in candidates if item in known_paths), None)
            elif module:
                target = _known_path_resolution(path, module, known_paths, python_module=True)
            if target:
                references.append((target, "python_import", getattr(node, "lineno", None)))
    return references


def _text_references(path: str, text: str, known_paths: set[str]) -> list[tuple[str, str, int | None]]:
    references: list[tuple[str, str, int | None]] = []
    suffix = Path(path).suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        for match in JS_IMPORT_RE.finditer(text):
            raw = match.group(1)
            if not raw.startswith("."):
                continue
            target = _known_path_resolution(
                path,
                raw,
                known_paths,
                suffixes=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
            )
            if target:
                references.append((target, "javascript_import", text.count("\n", 0, match.start()) + 1))
    if suffix == ".md":
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = _known_path_resolution(path, match.group(1), known_paths)
            if target:
                references.append((target, "markdown_link", text.count("\n", 0, match.start()) + 1))
    for match in PATH_REFERENCE_RE.finditer(text):
        raw = match.group(1)
        target = raw if raw in known_paths else _known_path_resolution(path, raw, known_paths)
        if target:
            references.append((target, "explicit_path_reference", text.count("\n", 0, match.start()) + 1))
    return references


def build_relationships(
    root: Path,
    artifacts: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_path = {str(item.get("path")): item for item in artifacts if item.get("path")}
    known_paths = set(by_path)
    candidates: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for path, artifact in sorted(by_path.items()):
        source_bytes = artifact.get("_source_bytes")
        if not isinstance(source_bytes, bytes):
            findings.append(
                {
                    "id": "repository_intelligence.missing_source_snapshot",
                    "severity": "blocking",
                    "status": "blocked",
                    "path": path,
                    "message": "The coherent source snapshot is unavailable for relationship extraction.",
                }
            )
            continue
        data = source_bytes
        observed_hash = sha256_bytes(data)
        if observed_hash != artifact.get("source_hash"):
            findings.append(
                {
                    "id": "repository_intelligence.source_changed_during_inventory",
                    "severity": "blocking",
                    "status": "stale",
                    "path": path,
                    "message": "Source content changed while repository intelligence was being inspected.",
                }
            )
            continue
        text = data.decode("utf-8", errors="replace")
        references: list[tuple[str, str, int | None]] = []
        if Path(path).suffix.lower() == ".py":
            references.extend(_python_import_references(path, text, known_paths))
        references.extend(_text_references(path, text, known_paths))
        for target_path, relationship_type, line in references:
            if target_path == path:
                continue
            target = by_path[target_path]
            candidates.append(
                {
                    "source_node": f"artifact:{artifact.get('artifact_id')}",
                    "target_node": f"artifact:{target.get('artifact_id')}",
                    "relationship_type": relationship_type,
                    "source_path": path,
                    "target_path": target_path,
                    "source_sha256": artifact.get("source_hash"),
                    "target_sha256": target.get("source_hash"),
                    "evidence_sha256": artifact.get("source_hash"),
                    "evidence_line": line,
                    "provenance": "current_repository_source",
                    "confidence": "explicit_source_reference",
                    "candidate_only": True,
                }
            )
    for link in links:
        source_path = str(link.get("source_path") or "")
        artifact = by_path.get(source_path)
        reference_id = str(link.get("reference_id") or "").strip()
        link_type = str(link.get("link_type") or "")
        if not artifact or not reference_id:
            continue
        prefix = {
            "task_ref": "task",
            "spec_ref": "spec",
            "capability_ref": "capability",
        }.get(link_type, "reference")
        candidates.append(
            {
                "source_node": f"artifact:{artifact.get('artifact_id')}",
                "target_node": f"{prefix}:{reference_id}",
                "relationship_type": link_type,
                "source_path": source_path,
                "target_path": None,
                "source_sha256": artifact.get("source_hash"),
                "target_sha256": None,
                "evidence_sha256": artifact.get("source_hash"),
                "evidence_line": None,
                "reference_id": reference_id,
                "provenance": "current_repository_source",
                "confidence": "explicit_source_reference",
                "candidate_only": True,
            }
        )
    relationship_priority = {
        "python_import": 0,
        "javascript_import": 1,
        "markdown_link": 2,
        "explicit_path_reference": 3,
        "task_ref": 4,
        "spec_ref": 4,
        "capability_ref": 4,
    }
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in candidates:
        key = (
            item.get("source_node"),
            item.get("target_node"),
            item.get("source_path"),
            item.get("target_path"),
            item.get("evidence_line"),
            item.get("reference_id"),
        )
        current = unique.get(key)
        if current is None or relationship_priority.get(
            str(item.get("relationship_type")), 99
        ) < relationship_priority.get(str(current.get("relationship_type")), 99):
            unique[key] = item
    relationships = []
    for key in sorted(unique, key=lambda item: tuple(str(part or "") for part in item)):
        selected = unique[key]
        identity = json.dumps(
            (*key, selected.get("relationship_type")),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        relationships.append(
            {
                "relationship_id": f"R-{hashlib.sha256(identity).hexdigest()[:16]}",
                **selected,
            }
        )
    return relationships, findings


def _source_nodes(artifacts: list[dict[str, Any]], relationships: list[dict[str, Any]]) -> list[dict[str, Any]]:
    nodes: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        node_id = f"artifact:{artifact.get('artifact_id')}"
        nodes[node_id] = {
            "node_id": node_id,
            "node_type": "artifact",
            "path": artifact.get("path"),
            "artifact_type": artifact.get("artifact_type"),
            "family_id": artifact.get("family_id"),
            "authority_level": artifact.get("authority_level"),
            "source_sha256": artifact.get("source_hash"),
        }
    for relationship in relationships:
        for key in ("source_node", "target_node"):
            node_id = str(relationship.get(key) or "")
            if not node_id or node_id in nodes:
                continue
            prefix, _, reference = node_id.partition(":")
            nodes[node_id] = {
                "node_id": node_id,
                "node_type": prefix or "reference",
                "reference_id": reference,
            }
    return [nodes[key] for key in sorted(nodes)]


def evaluate_graph_utility(
    artifacts: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    relationship_questions: list[str],
) -> dict[str, Any]:
    """Require a real multi-hop, cross-family case before recommending graph use."""

    artifact_by_node = {
        f"artifact:{item.get('artifact_id')}": item
        for item in artifacts
        if item.get("artifact_id")
    }
    adjacency: dict[str, set[str]] = {node: set() for node in artifact_by_node}
    artifact_edges = 0
    for relationship in relationships:
        source = str(relationship.get("source_node") or "")
        target = str(relationship.get("target_node") or "")
        if source not in artifact_by_node or target not in artifact_by_node:
            continue
        adjacency[source].add(target)
        adjacency[target].add(source)
        artifact_edges += 1
    qualifying_path: list[str] | None = None
    for source in sorted(adjacency):
        for middle in sorted(adjacency[source]):
            for target in sorted(adjacency[middle] - {source}):
                if target in adjacency[source]:
                    continue
                families = {
                    str(artifact_by_node[node].get("family_id") or "")
                    for node in (source, middle, target)
                }
                if len({family for family in families if family}) >= 2:
                    qualifying_path = [source, middle, target]
                    break
            if qualifying_path:
                break
        if qualifying_path:
            break
    return {
        "status": "multi_hop_cross_family" if qualifying_path else "no_incremental_multi_hop_case",
        "artifact_edges": artifact_edges,
        "qualifying_path": qualifying_path,
        "minimum_path_edges": 2,
        "minimum_artifacts": 3,
        "minimum_artifact_families": 2,
        "adds_beyond_direct_lookup": bool(qualifying_path),
        "enables_candidate_beyond_exact_or_single_link_lookup": bool(qualifying_path),
        "effectiveness_over_sqlite_fts": "untested",
        "relationship_questions": relationship_questions,
        "recommendation_boundary": "eligibility_hypothesis_not_effectiveness_proof",
    }


def inspect_repository(
    root: Path,
    *,
    profile: str,
    naos_root: str,
    rules_path: Path,
    rules_source: str,
    component_mode: str = "auto",
    purpose: str = "brownfield-onboarding",
    allowed_inflight_transaction_id: str | None = None,
) -> dict[str, Any]:
    rules = load_yaml_mapping(rules_path)
    _validate_rules(rules)
    if not rules.get("enabled", True):
        raise RepositoryIntelligenceError("Repository-intelligence rules are disabled.")
    if component_mode not in COMPONENT_MODES:
        raise RepositoryIntelligenceError(f"Unsupported component mode: {component_mode!r}.")
    if purpose not in PURPOSE_QUESTIONS:
        raise RepositoryIntelligenceError(f"Unsupported repository-intelligence purpose: {purpose!r}.")
    generated_at = utc_now_text()
    managed_scope = inspect_managed_content_scope(root)
    managed_manifest_path = root / MANAGED_CONTENT_MANIFEST_RELATIVE
    if managed_scope.status == "valid":
        if (
            not managed_scope.project_id
            or not managed_scope.scope_integrity
            or not managed_scope.source_policy_sha256
        ):
            raise RepositoryIntelligenceError(
                "Managed-content provenance binding is incomplete."
            )
        managed_paths = current_managed_content_paths(
            root,
            manifest_path=managed_manifest_path,
            bases_root=root / MANAGED_CONTENT_BASES_RELATIVE,
            receipts_root=root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
            project_id=managed_scope.project_id,
            scope_integrity_sha3_512=managed_scope.scope_integrity,
            source_policy_sha256=managed_scope.source_policy_sha256,
        )
    elif managed_manifest_path.exists():
        raise RepositoryIntelligenceError(
            "Managed-content state exists without valid provenance; repository "
            "intelligence will not use it as an exclusion authority."
        )
    else:
        managed_paths = set()
    managed_exclusions = {
        path: {
            "reason": "current_managed_content_excluded",
            "pattern_id": "managed_content_manifest_current_base",
        }
        for path in managed_paths
    }
    artifacts, chunks, links, excluded = build_artifact_records(
        root,
        rules,
        generated_at,
        include_source_bytes=True,
        preexcluded_paths=managed_exclusions,
    )
    excluded_paths = {str(item.get("path") or "") for item in excluded}
    excluded.extend(
        {
            "path": path,
            "reason": "current_managed_content_excluded",
            "pattern_id": "managed_content_manifest_current_base",
            "matched_family": None,
        }
        for path in sorted(managed_paths)
        if path not in excluded_paths
    )
    artifacts, chunks, links, excluded = _exclude_secret_content(
        root, artifacts, chunks, links, excluded
    )
    relationships, relationship_findings = build_relationships(root, artifacts, links)
    artifacts = _stable_generation_artifacts(artifacts)
    max_relationships = int((rules.get("chunking") or {}).get("max_relationships") or 20_000)
    observed_relationships = len(relationships)
    relationships_truncated = len(relationships) > max_relationships
    if relationships_truncated:
        relationship_findings.append(
            {
                "id": "repository_intelligence.relationship_limit_exceeded",
                "severity": "blocking",
                "status": "blocked",
                "message": f"Relationship count exceeds the configured limit of {max_relationships}.",
                "observed_relationships": len(relationships),
            }
        )
        relationships = relationships[:max_relationships]
    inventory = _artifact_inventory(artifacts)
    family_counts = Counter(item.get("family_id") for item in inventory)
    runtime = runtime_probe()
    maturity = maturity_evidence(root, naos_root)
    unsafe_sources = [item for item in inventory if not item.get("source_sha256")]
    artifact_limit_truncated = any(
        item.get("reason") == "max_artifacts_exceeded" for item in excluded
    )
    unsafe_topology_exclusions = [
        item
        for item in excluded
        if item.get("reason")
        in local_context_index_module.UNSAFE_SOURCE_TOPOLOGY_REASONS
    ]
    inventory_truncated = artifact_limit_truncated or bool(unsafe_topology_exclusions)
    candidate = len(inventory) >= 2 and len([key for key, value in family_counts.items() if key and value]) >= 2
    graph_utility = evaluate_graph_utility(
        artifacts,
        relationships,
        PURPOSE_QUESTIONS[purpose],
    )
    graph_applicable = candidate and bool(graph_utility["adds_beyond_direct_lookup"])
    graph_runtime_ready = runtime["networkx"]["status"] == "ready"
    graph_selected = bool(
        graph_applicable
        and (
            component_mode == "graph"
            or (component_mode == "auto" and graph_runtime_ready)
        )
    )
    components = {
        "sqlite_fts": {
            "status": (
                "ready"
                if candidate and runtime["sqlite_fts"]["fts5_available"]
                else ("not_applicable" if not candidate else "prerequisite_missing")
            ),
            "engine": "python_stdlib_sqlite3_fts5",
            "version": sqlite3.sqlite_version,
            "applicability_basis": "executed_inventory_and_fts5_probe",
        },
        "networkx_graphml": {
            "status": (
                "not_applicable"
                if not graph_applicable
                else (
                    runtime["networkx"]["status"]
                    if graph_selected
                    else (
                        "available_not_selected"
                        if component_mode == "baseline"
                        else "available_prerequisite_missing"
                    )
                )
            ),
            "engine": "networkx_graphml",
            "version": runtime["networkx"]["installed_version"],
            "required_version": NETWORKX_VERSION,
            "applicability_basis": "explicit_source_bound_relationships",
            "relationship_count": len(relationships),
            "utility_evidence": graph_utility,
            "selected": graph_selected,
            "effectiveness_over_sqlite_fts": "untested",
        },
        "sqlite_vec": {
            "status": "workload_not_defined",
            "engine": "sqlite_vec",
            "version": None,
            "applicability_basis": "frozen_workload_and_vector_producer_required",
        },
    }
    findings = [*relationship_findings]
    context_path = _context_index_root(root, naos_root)
    scope_inspection = inspect_scope(
        root,
        governed_root=context_path.relative_to(root).as_posix(),
    )
    if scope_inspection.activation_eligible and context_path.exists():
        try:
            _assert_context_entries(context_path)
            inactive_owned = (
                not (context_path / "active.json").exists()
                and _inactive_context_is_operation_owned(
                    root,
                    context_path,
                    root / TRANSACTIONS_RELATIVE,
                    allowed_inflight_transaction_id=allowed_inflight_transaction_id,
                )
            )
            if not (context_path / "active.json").exists() and not inactive_owned:
                raise RepositoryIntelligenceError(
                    "The generated context root has no valid active or transaction provenance chain."
                )
        except (OSError, RepositoryIntelligenceError) as exc:
            findings.append(
                {
                    "id": "repository_intelligence.unproven_generated_root",
                    "severity": "blocking",
                    "status": "refused",
                    "message": str(exc),
                }
            )
    if maturity["status"] == "invalid":
        findings.append(
            {
                "id": "repository_intelligence.invalid_maturity_declaration",
                "severity": "blocking",
                "status": "invalid_metadata",
                "message": (
                    "The repository-intelligence capability maturity declaration is invalid; "
                    "repair it to an explicit L0-L5 value before enrollment or activation."
                ),
                "error": maturity.get("error"),
            }
        )
    if not candidate:
        findings.append(
            {
                "id": "repository_intelligence.insufficient_cross_surface_inventory",
                "severity": "advisory",
                "status": "not_applicable",
                "message": "Fewer than two artifact families were found; repository-intelligence activation is not recommended.",
            }
        )
    if candidate and not runtime["sqlite_fts"]["fts5_available"]:
        findings.append(
            {
                "id": "repository_intelligence.fts5_unavailable",
                "severity": "blocking",
                "status": "prerequisite_missing",
                "message": "The executed SQLite FTS5 probe failed; activation is unavailable.",
            }
        )
    if graph_applicable and runtime["networkx"]["status"] != "ready":
        findings.append(
            {
                "id": "repository_intelligence.networkx_prerequisite_missing",
                "severity": "blocking" if component_mode == "graph" else "advisory",
                "status": "prerequisite_missing",
                "message": "Explicit relationships exist, but exact NetworkX 3.6.1 is not installed.",
                "next_action": "Install NAOS with the repository-intelligence optional extra, then prepare a graph-mode plan; baseline mode remains available.",
            }
        )
    if component_mode == "graph" and not graph_applicable:
        findings.append(
            {
                "id": "repository_intelligence.graph_not_applicable",
                "severity": "blocking",
                "status": "not_applicable",
                "message": "Graph mode was requested but executed inspection found no qualifying multi-hop cross-family relationship case.",
            }
        )
    if not runtime["platform"]["supported_for_apply"]:
        findings.append(
            {
                "id": "repository_intelligence.unsupported_platform_tuple",
                "severity": "blocking",
                "status": "unsupported_metadata",
                "message": "Apply is enabled only for the executed macOS ARM64 CPython 3.11-3.13 tuple.",
            }
        )
    if runtime["rfc8785"]["status"] != "ready":
        findings.append(
            {
                "id": "repository_intelligence.rfc8785_prerequisite_missing",
                "severity": "blocking",
                "status": "prerequisite_missing",
                "message": "Exact RFC 8785 canonicalization support is unavailable.",
            }
        )
    if unsafe_sources:
        findings.append(
            {
                "id": "repository_intelligence.unhashed_source",
                "severity": "blocking",
                "status": "blocked",
                "message": "At least one inventoried source could not be content-bound.",
                "paths": [item["path"] for item in unsafe_sources[:20]],
            }
        )
    if unsafe_topology_exclusions:
        findings.append(
            {
                "id": "repository_intelligence.unsafe_in_scope_source",
                "severity": "blocking",
                "status": "blocked",
                "message": (
                    "At least one in-scope source has unsafe filesystem topology; "
                    "it was not read and activation is refused."
                ),
                "sources": [
                    {"path": item.get("path"), "reason": item.get("reason")}
                    for item in unsafe_topology_exclusions[:20]
                ],
            }
        )
    if artifact_limit_truncated:
        findings.append(
            {
                "id": "repository_intelligence.inventory_limit_exceeded",
                "severity": "blocking",
                "status": "blocked",
                "message": "The configured artifact limit prevented a complete inventory; raise the explicit limit and prepare a new plan.",
                "excluded_count": sum(
                    1 for item in excluded if item.get("reason") == "max_artifacts_exceeded"
                ),
            }
        )
    coverage_binding = _coverage_binding(
        inventory,
        excluded,
        observed_relationships=observed_relationships,
        relationships_truncated=relationships_truncated,
    )
    return {
        "generated_at": generated_at,
        "project_root": str(root),
        "profile": profile,
        "purpose": purpose,
        "component_mode": component_mode,
        "naos_root": naos_root,
        "rules": {
            "path": str(rules_path),
            "source": rules_source,
            "sha256": safe_digest(rules_path),
        },
        "runtime": runtime,
        "maturity": maturity,
        "inventory": inventory,
        "effective_source_sha256": canonical_sha256(coverage_binding),
        "coverage_binding": coverage_binding,
        "artifacts": artifacts,
        "chunks": chunks,
        "links": links,
        "relationships": relationships,
        "graph_utility": graph_utility,
        "nodes": _source_nodes(artifacts, relationships),
        "excluded_artifacts": excluded,
        "family_counts": dict(sorted((str(key), value) for key, value in family_counts.items() if key)),
        "repository_intelligence_candidate": candidate,
        "graph_applicable": graph_applicable,
        "graph_selected": graph_selected,
        "relationships_truncated": relationships_truncated,
        "inventory_truncated": inventory_truncated,
        "components": components,
        "findings": findings,
    }


def _profile_gate(profile: str) -> dict[str, Any]:
    named_review = profile in {"standard", "assured"}
    return {
        "profile": profile,
        "digest_confirmation_required": True,
        "named_review_required": named_review,
        "reviewer_identity_is_attribution_not_authentication": True,
        "maturity_does_not_authorize_component_selection": True,
    }


def _blocking_finding_ids(inspection: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(item.get("id") or "repository_intelligence.unknown_blocker")
            for item in inspection.get("findings") or []
            if isinstance(item, dict) and item.get("severity") == "blocking"
        }
    )


def _assert_current_inspection_complete(
    inspection: dict[str, Any],
    *,
    phase: str,
) -> None:
    blockers = _blocking_finding_ids(inspection)
    if (
        blockers
        or inspection.get("inventory_truncated")
        or inspection.get("relationships_truncated")
    ):
        labels = ", ".join(blockers) if blockers else "truncated_coverage"
        raise RepositoryIntelligenceError(
            f"Repository inspection became blocking during {phase}: {labels}; prepare a new plan."
        )


def _plan_digest_payload(plan: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(plan)
    for field in ("created_at", "plan_id", "plan_sha256", "plan_file"):
        payload.pop(field, None)
    bundle = payload.get("bundle")
    if isinstance(bundle, dict):
        bundle.pop("path", None)
    return payload


def _bundle_digest_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(bundle)
    payload.pop("path", None)
    payload.pop("bundle_sha256", None)
    return payload


def _make_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise RepositoryIntelligenceError(f"Refusing existing plan-bundle path: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkdir(path, 0o700)


def _private_file(path: Path) -> None:
    os.chmod(path, 0o600)
    _fsync_file(path)


def _build_plan_bundle(
    root: Path,
    inspection: dict[str, Any],
    *,
    profile: str,
    purpose: str,
    component_mode: str,
    rules_path: Path,
    bundle_dir: Path,
    provenance_gate: dict[str, Any],
) -> dict[str, Any]:
    _make_private_directory(bundle_dir)
    try:
        graph_model = {
            "directed": True,
            "multigraph": True,
            "nodes": inspection["nodes"],
            "relationships": inspection["relationships"],
        }
        graph_model_sha256 = canonical_sha256(graph_model)
        implementation = _implementation_identity()
        content_identity_control = {
            "capability_id": CAPABILITY_ID,
            "project_root": str(root),
            "profile": profile,
            "purpose": purpose,
            "component_mode": component_mode,
            "effective_source_sha256": inspection["effective_source_sha256"],
            "rules": inspection["rules"],
            "runtime": inspection["runtime"],
            "implementation": implementation,
            "provenance_gate": provenance_gate,
            "components": inspection["components"],
            "graph_model_sha256": graph_model_sha256,
            "ongoing_use_scope": list(load_yaml_mapping(rules_path).get("ongoing_use_scope") or []),
        }
        generation_content_sha256 = canonical_sha256(content_identity_control)
        generation_id = f"RI-{generation_content_sha256[:24]}"
        sqlite_content_binding = _sqlite_content_binding(
            inspection["artifacts"],
            inspection["chunks"],
            inspection["links"],
            inspection["relationships"],
        )
        inventory_report = {
            "schema": INVENTORY_SCHEMA,
            "status": "staged",
            "project_root": str(root),
            "generation_id": generation_id,
            "effective_source_sha256": inspection["effective_source_sha256"],
            "source_inventory": inspection["inventory"],
            "artifacts": inspection["artifacts"],
            "relationships": inspection["relationships"],
            "sqlite_content_binding": sqlite_content_binding,
            "excluded_artifacts": inspection["excluded_artifacts"],
            "components": inspection["components"],
            "ongoing_use_scope": content_identity_control["ongoing_use_scope"],
            "candidate_only": True,
            "limitations": list(load_yaml_mapping(rules_path).get("limitations") or []),
            "not_claimed": list(load_yaml_mapping(rules_path).get("not_claimed") or []),
        }
        inventory_path = bundle_dir / "inventory.json"
        _write_json(inventory_path, inventory_report)
        _private_file(inventory_path)
        rules_snapshot_path = bundle_dir / "repository_intelligence_rules.yaml"
        _write_new_bytes(rules_snapshot_path, secure_regular_file_bytes(rules_path))

        sqlite_validation: dict[str, Any]
        sqlite_path: Path | None = None
        candidate = bool(inspection["repository_intelligence_candidate"])
        fts_ready = bool(inspection["runtime"]["sqlite_fts"]["fts5_available"])
        if candidate and fts_ready:
            sqlite_path = bundle_dir / "local_context_index.sqlite"
            provisional = {
                "generated_at": "content_bound_generation",
                "profile": profile,
                "rules_hash": inspection["rules"].get("sha256"),
                "status": "validated",
                "limitations": inventory_report["limitations"],
            }
            fts_available, sqlite_findings = populate_sqlite_database(
                sqlite_path,
                provisional,
                inspection["artifacts"],
                inspection["chunks"],
                inspection["links"],
            )
            if not fts_available or any(item.get("severity") == "blocking" for item in sqlite_findings):
                raise RepositoryIntelligenceError("SQLite/FTS plan bundle did not validate.")
            _populate_relationship_tables(
                sqlite_path,
                inspection["relationships"],
                {
                    "effective_source_sha256": inspection["effective_source_sha256"],
                    "generation_content_sha256": generation_content_sha256,
                    "graph_model_sha256": graph_model_sha256,
                    "ongoing_use_scope": content_identity_control["ongoing_use_scope"],
                    "sqlite_content_binding": sqlite_content_binding,
                },
            )
            _private_file(sqlite_path)
            sqlite_validation = _validate_sqlite(
                sqlite_path,
                inspection["effective_source_sha256"],
                sqlite_content_binding,
            )
        else:
            sqlite_validation = {
                "status": "not_applicable" if not candidate else "prerequisite_missing",
                "source_binding_validated": False,
            }

        graph_validation: dict[str, Any]
        graph_path: Path | None = None
        if inspection["graph_selected"]:
            graph_path = bundle_dir / "context.graphml"
            graph_validation = _write_graphml(
                graph_path,
                inspection["nodes"],
                inspection["relationships"],
                source_sha256=inspection["effective_source_sha256"],
                model_sha256=graph_model_sha256,
            )
        else:
            graph_validation = {
                "status": "not_selected" if inspection["graph_applicable"] else "not_applicable",
                "reason": (
                    "Graph was not selected for this plan."
                    if inspection["graph_applicable"]
                    else "No qualifying multi-hop cross-family relationship case was detected."
                ),
            }

        repeat = inspect_repository(
            root,
            profile=profile,
            naos_root=str(inspection["naos_root"]),
            rules_path=rules_path,
            rules_source=str(inspection["rules"].get("source") or "unknown"),
            component_mode=component_mode,
            purpose=purpose,
        )
        if repeat["effective_source_sha256"] != inspection["effective_source_sha256"]:
            raise RepositoryIntelligenceError("Repository source changed while the plan bundle was built.")
        repeat_model = {
            "directed": True,
            "multigraph": True,
            "nodes": repeat["nodes"],
            "relationships": repeat["relationships"],
        }
        if canonical_sha256(repeat_model) != graph_model_sha256:
            raise RepositoryIntelligenceError("Repository relationships changed while the plan bundle was built.")

        validation_control = {
            "generation_id": generation_id,
            "generation_content_sha256": generation_content_sha256,
            "effective_source_sha256": inspection["effective_source_sha256"],
            "profile": profile,
            "purpose": purpose,
            "component_mode": component_mode,
            "runtime": inspection["runtime"],
            "implementation": implementation,
            "provenance_gate": provenance_gate,
            "sqlite_fts": sqlite_validation,
            "networkx_graphml": graph_validation,
            "source_revalidated_after_generation": True,
            "candidate_only": True,
        }
        provenance_valid = provenance_gate.get("status") == "valid"
        validation_receipt = {
            "schema": RECEIPT_SCHEMA,
            "status": (
                "validated_generation"
                if sqlite_path is not None and provenance_valid
                else "diagnostic_generation"
            ),
            "receipt_sha256": canonical_sha256(validation_control),
            "control": validation_control,
            "not_claimed": ["source authority", "reviewer authentication", "complete graph coverage"],
        }
        validation_path = bundle_dir / "validation_receipt.json"
        _write_json(validation_path, validation_receipt)
        _private_file(validation_path)

        content_paths = [inventory_path, rules_snapshot_path, validation_path]
        if sqlite_path is not None:
            content_paths.append(sqlite_path)
        if graph_path is not None:
            content_paths.append(graph_path)
        content_files = sorted((_file_record(path) for path in content_paths), key=lambda item: item["path"])
        manifest_control = {
            "generation_id": generation_id,
            "generation_content_sha256": generation_content_sha256,
            "project_root": str(root),
            "effective_source_sha256": inspection["effective_source_sha256"],
            "graph_model_sha256": graph_model_sha256,
            "profile": profile,
            "purpose": purpose,
            "component_mode": component_mode,
            "rules": inspection["rules"],
            "rules_snapshot": "repository_intelligence_rules.yaml",
            "runtime": inspection["runtime"],
            "implementation": implementation,
            "provenance_gate": provenance_gate,
            "components": inspection["components"],
            "coverage": {
                "indexed_artifacts": len(inspection["inventory"]),
                "excluded_artifacts": len(inspection["excluded_artifacts"]),
                "artifact_families": inspection["family_counts"],
                "explicit_relationships": len(inspection["relationships"]),
                "graph_nodes": len(inspection["nodes"]),
                "truncated": bool(
                    inspection["relationships_truncated"] or inspection["inventory_truncated"]
                ),
            },
            "ongoing_use_scope": content_identity_control["ongoing_use_scope"],
            "files": content_files,
            "validation_receipt_sha256": validation_receipt["receipt_sha256"],
            "candidate_only": True,
        }
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "status": "validated" if sqlite_path is not None and provenance_valid else "diagnostic_only",
            "manifest_sha256": canonical_sha256(manifest_control),
            "control": manifest_control,
            "limitations": inventory_report["limitations"],
            "not_claimed": inventory_report["not_claimed"],
        }
        manifest_path = bundle_dir / "manifest.json"
        _write_json(manifest_path, manifest)
        _private_file(manifest_path)
        _fsync_directory(bundle_dir)

        bundle_files = sorted(
            (_file_record(path) for path in [*content_paths, manifest_path]),
            key=lambda item: item["path"],
        )
        bundle = {
            "schema": PLAN_BUNDLE_SCHEMA,
            "path": str(bundle_dir),
            "generation_id": generation_id,
            "generation_content_sha256": generation_content_sha256,
            "files": bundle_files,
            "validation": {
                "status": manifest["status"],
                "sqlite_fts": sqlite_validation,
                "networkx_graphml": graph_validation,
                "source_revalidated": True,
                "exact_bytes_ready_for_activation": sqlite_path is not None and provenance_valid,
                "provenance_valid": provenance_valid,
            },
            "generated_state_only": True,
        }
        bundle["bundle_sha256"] = canonical_sha256(_bundle_digest_payload(bundle))
        return bundle
    except Exception:
        if bundle_dir.exists() and bundle_dir.is_dir() and not bundle_dir.is_symlink():
            shutil.rmtree(bundle_dir)
        raise


def build_plan(
    root: Path,
    *,
    profile: str,
    naos_root: str,
    rules_path: Path,
    rules_source: str,
    purpose: str = "brownfield-onboarding",
    component_mode: str = "auto",
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    inspection = inspect_repository(
        root,
        profile=profile,
        naos_root=naos_root,
        rules_path=rules_path,
        rules_source=rules_source,
        component_mode=component_mode,
        purpose=purpose,
    )
    runtime = inspection["runtime"]
    components = inspection["components"]
    blocking = [item for item in inspection["findings"] if item.get("severity") == "blocking"]
    context_path = _context_index_root(root, naos_root)
    governed_root = context_path.relative_to(root).as_posix()
    scope_inspection = inspect_scope(root, governed_root=governed_root)
    provenance_gate = scope_inspection.plan_gate()
    if (
        not inspection["repository_intelligence_candidate"]
        and scope_inspection.status
        in {"enrollment_required", "scope_enrollment_required"}
    ):
        # A diagnostic not-applicable decision authorizes no enrollment or
        # mutation.  Do not let a one-use enrollment UUID make that decision
        # non-deterministic; a later applicable plan will allocate its own
        # exact enrollment identity.
        provenance_gate = {
            **provenance_gate,
            "enrollment_project_id": None,
        }
    apply_allowed = bool(
        inspection["repository_intelligence_candidate"]
        and not blocking
        and scope_inspection.activation_eligible
    )
    graph_model = {
        "directed": True,
        "multigraph": True,
        "nodes": inspection["nodes"],
        "relationships": inspection["relationships"],
    }
    if bundle_dir is None:
        bundle_dir = Path(tempfile.mkdtemp(prefix="naos-repository-intelligence-bundle-parent-")).resolve() / "bundle"
    else:
        bundle_dir = bundle_dir.expanduser().resolve(strict=False)
    bundle = _build_plan_bundle(
        root,
        inspection,
        profile=profile,
        purpose=purpose,
        component_mode=component_mode,
        rules_path=rules_path,
        bundle_dir=bundle_dir,
        provenance_gate=provenance_gate,
    )
    implementation = _implementation_identity()
    control = {
        "capability_id": CAPABILITY_ID,
        "project_root": str(root),
        "profile": profile,
        "purpose": purpose,
        "component_mode": component_mode,
        "relationship_questions": PURPOSE_QUESTIONS[purpose],
        "naos_root": naos_root,
        "effective_source_sha256": inspection["effective_source_sha256"],
        "source_inventory": inspection["inventory"],
        "rules": inspection["rules"],
        "runtime": runtime,
        "implementation": implementation,
        "provenance_gate": provenance_gate,
        "maturity": inspection["maturity"],
        "components": components,
        "graph_model_sha256": canonical_sha256(graph_model),
        "generation_id": bundle["generation_id"],
        "generation_content_sha256": bundle["generation_content_sha256"],
        "bundle_sha256": bundle["bundle_sha256"],
        "coverage": {
            "indexed_artifacts": len(inspection["inventory"]),
            "excluded_artifacts": len(inspection["excluded_artifacts"]),
            "artifact_families": inspection["family_counts"],
            "explicit_relationships": len(inspection["relationships"]),
            "graph_nodes": len(inspection["nodes"]),
            "truncated": bool(
                inspection["relationships_truncated"] or inspection["inventory_truncated"]
            ),
        },
        "ongoing_use_scope": list(
            (load_yaml_mapping(rules_path).get("ongoing_use_scope") or [])
        ),
        "profile_gate": _profile_gate(profile),
        "apply_allowed": apply_allowed,
        "generation_layout": {
            "root": f"{CONTEXT_RELATIVE.as_posix()}/generations",
            "sqlite": "local_context_index.sqlite",
            "graphml": "context.graphml" if inspection["graph_selected"] else None,
            "inventory": "inventory.json",
            "manifest": "manifest.json",
            "validation_receipt": "validation_receipt.json",
            "active_pointer": f"{CONTEXT_RELATIVE.as_posix()}/active.json",
        },
        "invalidated_by": [
            "source_inventory_change",
            "rules_change",
            "profile_change",
            "runtime_tuple_change",
            "component_version_change",
            "implementation_change",
            "ongoing_use_scope_change",
        ],
        "not_claimed": [
            "source authority",
            "complete dependency graph",
            "semantic truth",
            "automatic requirements approval",
            "automatic maturity promotion",
            "sqlite-vec effectiveness",
        ],
    }
    if apply_allowed:
        status = "confirmation_required"
    elif not inspection["repository_intelligence_candidate"]:
        status = "not_applicable"
    elif scope_inspection.status in {"enrollment_required", "scope_enrollment_required"} and not blocking:
        status = "enrollment_required"
    else:
        status = "blocked_prerequisite"
    findings = list(inspection["findings"])
    if (
        inspection["repository_intelligence_candidate"]
        and scope_inspection.status
        in {"enrollment_required", "scope_enrollment_required"}
    ):
        findings.append(
            {
                "id": "repository_intelligence.provenance_enrollment_required",
                "severity": "action_required",
                "status": scope_inspection.status,
                "message": "The absent generated namespace requires a separate digest-confirmed capability enrollment before apply.",
                "next_action": "Run repository-intelligence enroll with this exact plan digest, then prepare a new activation plan.",
            }
        )
    elif scope_inspection.status == "refused":
        findings.append(
            {
                "id": "repository_intelligence.provenance_refused",
                "severity": "blocking",
                "status": "refuse_provenance",
                "message": scope_inspection.refusal or "Capability provenance is invalid.",
            }
        )
    plan = {
        "schema": PLAN_SCHEMA,
        "created_at": inspection["generated_at"],
        "status": status,
        "control": control,
        "bundle": bundle,
        "findings": findings,
        "effectiveness_hypothesis": {
            "status": "untested",
            "comparison_required": True,
            "success_requires_effectiveness_not_generation": True,
            "measures": [
                "source-confirmed incremental discoveries",
                "false and unsupported relationship rate",
                "missed relationship rate",
                "verification effort",
                "determinism",
                "runtime and storage cost",
            ],
        },
        "limitations": load_yaml_mapping(rules_path).get("limitations") or [],
        "not_claimed": control["not_claimed"],
        "human_review_required": True,
    }
    digest = canonical_sha256(_plan_digest_payload(plan))
    plan["plan_id"] = f"RI-{digest[:16]}"
    plan["plan_sha256"] = digest
    return plan


def _strict_json_file(path: Path) -> dict[str, Any]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RepositoryIntelligenceError(f"JSON control file is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RepositoryIntelligenceError(f"Refusing unsafe JSON control file: {path}")
    try:
        data = loads_strict_json(secure_regular_file_bytes(path))
    except (CanonicalizationError, OSError, ValueError) as exc:
        raise RepositoryIntelligenceError(f"Invalid JSON control file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RepositoryIntelligenceError(f"JSON control file must contain an object: {path}")
    return data


def _strict_bundle_directory(root: Path, bundle: dict[str, Any]) -> Path:
    raw = str(bundle.get("path") or "")
    if not raw:
        raise RepositoryIntelligenceError("Plan bundle path is missing.")
    path = Path(raw).expanduser()
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RepositoryIntelligenceError(f"Plan bundle is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RepositoryIntelligenceError(f"Refusing unsafe plan-bundle directory: {path}")
    resolved = path.resolve(strict=True)
    if resolved == root or root in resolved.parents:
        raise RepositoryIntelligenceError("Plan bundle must remain outside the target repository.")
    return resolved


def _validate_plan_bundle(
    root: Path,
    plan: dict[str, Any],
    *,
    require_activation: bool,
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    bundle = plan.get("bundle")
    control = plan.get("control")
    if not isinstance(bundle, dict) or not isinstance(control, dict):
        raise RepositoryIntelligenceError("Plan bundle or control object is missing.")
    if bundle.get("schema") != PLAN_BUNDLE_SCHEMA:
        raise RepositoryIntelligenceError("Unsupported repository-intelligence plan-bundle schema.")
    if canonical_sha256(_bundle_digest_payload(bundle)) != bundle.get("bundle_sha256"):
        raise RepositoryIntelligenceError("Plan-bundle digest is invalid.")
    for field in ("generation_id", "generation_content_sha256", "bundle_sha256"):
        if bundle.get(field) != control.get(field):
            raise RepositoryIntelligenceError(f"Plan bundle {field} does not match plan control.")
    if bundle.get("generated_state_only") is not True:
        raise RepositoryIntelligenceError("Plan bundle is not limited to generated state.")
    validation = bundle.get("validation")
    if not isinstance(validation, dict) or validation.get("source_revalidated") is not True:
        raise RepositoryIntelligenceError("Plan bundle did not complete generation validation.")
    if require_activation and (
        validation.get("exact_bytes_ready_for_activation") is not True
        or validation.get("status") != "validated"
        or validation.get("provenance_valid") is not True
    ):
        raise RepositoryIntelligenceError("Plan bundle is diagnostic-only and cannot be applied.")

    bundle_dir = _strict_bundle_directory(root, bundle)
    records = bundle.get("files")
    if not isinstance(records, list):
        raise RepositoryIntelligenceError("Plan bundle file inventory is missing.")
    _validate_file_records(bundle_dir, records)
    record_names = [str(item.get("path") or "") for item in records if isinstance(item, dict)]
    if len(record_names) != len(records) or len(record_names) != len(set(record_names)):
        raise RepositoryIntelligenceError("Plan bundle contains invalid or duplicate file records.")
    actual_names = sorted(
        child.name
        for child in bundle_dir.iterdir()
        if child.is_file() and not child.is_symlink()
    )
    if actual_names != sorted(record_names):
        raise RepositoryIntelligenceError("Plan bundle contains unrecorded or missing files.")

    manifest_path = bundle_dir / "manifest.json"
    manifest = _strict_json_file(manifest_path)
    _validate_schema(manifest, MANIFEST_SCHEMA)
    manifest_control = manifest.get("control")
    if not isinstance(manifest_control, dict):
        raise RepositoryIntelligenceError("Plan-bundle manifest control is missing.")
    if canonical_sha256(manifest_control) != manifest.get("manifest_sha256"):
        raise RepositoryIntelligenceError("Plan-bundle manifest digest is invalid.")
    for field in (
        "generation_id",
        "generation_content_sha256",
        "project_root",
        "effective_source_sha256",
        "graph_model_sha256",
        "profile",
        "purpose",
        "component_mode",
        "runtime",
        "implementation",
        "provenance_gate",
        "components",
        "ongoing_use_scope",
    ):
        if manifest_control.get(field) != control.get(field):
            raise RepositoryIntelligenceError(f"Plan-bundle manifest {field} does not match plan control.")
    manifest_records = manifest_control.get("files")
    if not isinstance(manifest_records, list):
        raise RepositoryIntelligenceError("Plan-bundle manifest file inventory is missing.")
    expected_manifest_records = sorted(
        (item for item in records if item.get("path") != "manifest.json"),
        key=lambda item: str(item.get("path") or ""),
    )
    if manifest_records != expected_manifest_records:
        raise RepositoryIntelligenceError("Plan-bundle and manifest file inventories disagree.")

    receipt = _strict_json_file(bundle_dir / "validation_receipt.json")
    _validate_schema(receipt, RECEIPT_SCHEMA)
    receipt_control = receipt.get("control")
    if not isinstance(receipt_control, dict) or canonical_sha256(receipt_control) != receipt.get("receipt_sha256"):
        raise RepositoryIntelligenceError("Plan-bundle validation receipt digest is invalid.")
    expected_receipt_status = "validated_generation" if manifest.get("status") == "validated" else "diagnostic_generation"
    if receipt.get("status") != expected_receipt_status:
        raise RepositoryIntelligenceError("Plan-bundle validation receipt is not eligible for activation.")
    if receipt.get("receipt_sha256") != manifest_control.get("validation_receipt_sha256"):
        raise RepositoryIntelligenceError("Plan-bundle validation receipt is not bound by its manifest.")
    for field in (
        "generation_id",
        "generation_content_sha256",
        "effective_source_sha256",
        "profile",
        "purpose",
        "component_mode",
        "runtime",
        "implementation",
        "provenance_gate",
    ):
        if receipt_control.get(field) != control.get(field):
            raise RepositoryIntelligenceError(f"Plan-bundle receipt {field} does not match plan control.")

    inventory = _strict_json_file(bundle_dir / "inventory.json")
    _validate_schema(inventory, INVENTORY_SCHEMA)
    if inventory.get("generation_id") != control.get("generation_id"):
        raise RepositoryIntelligenceError("Plan-bundle inventory generation identity is invalid.")
    rules_bytes = secure_regular_file_bytes(bundle_dir / "repository_intelligence_rules.yaml")
    if sha256_bytes(rules_bytes) != control.get("rules", {}).get("sha256"):
        raise RepositoryIntelligenceError("Plan-bundle rules snapshot digest is invalid.")
    rules = yaml.safe_load(rules_bytes)
    if not isinstance(rules, dict):
        raise RepositoryIntelligenceError("Plan-bundle rules snapshot must contain a mapping.")
    _validate_rules(rules)
    content_binding = inventory.get("sqlite_content_binding")
    if not isinstance(content_binding, dict):
        raise RepositoryIntelligenceError("Plan-bundle SQLite content binding is missing.")
    _validate_sqlite(
        bundle_dir / "local_context_index.sqlite",
        str(control.get("effective_source_sha256") or ""),
        content_binding,
    )
    graph_name = control.get("generation_layout", {}).get("graphml")
    if graph_name:
        _validate_graphml_file(
            bundle_dir / str(graph_name),
            expected_source_sha256=str(control.get("effective_source_sha256") or ""),
            expected_model_sha256=str(control.get("graph_model_sha256") or ""),
        )
    elif (bundle_dir / "context.graphml").exists():
        raise RepositoryIntelligenceError("Plan bundle contains GraphML that was not selected by the plan.")
    return bundle, bundle_dir, manifest


def _verify_plan_integrity(
    plan: dict[str, Any],
    confirmed_digest: str,
    *,
    require_activation_bundle: bool,
) -> dict[str, Any]:
    if plan.get("schema") != PLAN_SCHEMA:
        raise RepositoryIntelligenceError("Unsupported repository-intelligence plan schema.")
    _validate_schema(plan, PLAN_SCHEMA)
    control = plan.get("control")
    if not isinstance(control, dict):
        raise RepositoryIntelligenceError("Plan control object is missing.")
    observed = canonical_sha256(_plan_digest_payload(plan))
    declared = str(plan.get("plan_sha256") or "")
    if observed != declared:
        raise RepositoryIntelligenceError("Plan content digest is invalid.")
    if plan.get("plan_id") != f"RI-{declared[:16]}":
        raise RepositoryIntelligenceError("Plan identity does not match its content digest.")
    if confirmed_digest != declared:
        raise RepositoryIntelligenceError("Confirmation digest does not match the plan digest.")
    profile = str(control.get("profile") or "")
    if profile not in {"quickstart", "lite", "standard", "assured"}:
        raise RepositoryIntelligenceError("Plan profile is unsupported.")
    if control.get("profile_gate") != _profile_gate(profile):
        raise RepositoryIntelligenceError("Plan profile gate is not the canonical gate for its profile.")
    _validate_plan_bundle(
        Path(str(control.get("project_root") or "")).resolve(strict=False),
        plan,
        require_activation=require_activation_bundle,
    )
    return control


def verify_plan(plan: dict[str, Any], confirmed_digest: str) -> dict[str, Any]:
    control = _verify_plan_integrity(plan, confirmed_digest, require_activation_bundle=True)
    provenance_gate = control.get("provenance_gate")
    if not isinstance(provenance_gate, dict) or provenance_gate.get("status") != "valid":
        raise RepositoryIntelligenceError("This plan lacks valid capability provenance.")
    if plan.get("status") != "confirmation_required" or control.get("apply_allowed") is not True:
        raise RepositoryIntelligenceError("This plan is not eligible for apply.")
    if any(item.get("severity") == "blocking" for item in plan.get("findings") or [] if isinstance(item, dict)):
        raise RepositoryIntelligenceError("This plan contains a blocking finding and cannot be applied.")
    return control


def verify_enrollment_plan(plan: dict[str, Any], confirmed_digest: str) -> dict[str, Any]:
    control = _verify_plan_integrity(plan, confirmed_digest, require_activation_bundle=False)
    provenance_gate = control.get("provenance_gate")
    if not isinstance(provenance_gate, dict) or provenance_gate.get("status") not in {
        "enrollment_required",
        "scope_enrollment_required",
    }:
        raise RepositoryIntelligenceError("This plan is not eligible for capability enrollment.")
    if plan.get("status") != "enrollment_required" or control.get("apply_allowed") is not False:
        raise RepositoryIntelligenceError("Enrollment plan state is invalid.")
    return control


def _require_reviewer(profile: str, reviewer_id: str | None) -> str | None:
    required = _profile_gate(profile)["named_review_required"]
    if required and not reviewer_id:
        raise RepositoryIntelligenceError(f"Profile {profile} requires --reviewer-id attribution.")
    if reviewer_id is not None and not REVIEWER_ID_RE.fullmatch(reviewer_id):
        raise RepositoryIntelligenceError("Reviewer identity has an unsupported format.")
    return reviewer_id


def enroll_capability_scope(
    root: Path,
    plan: dict[str, Any],
    *,
    confirmed_digest: str,
    reviewer_id: str | None,
    requested_profile: str | None = None,
    requested_naos_root: str | None = None,
) -> dict[str, Any]:
    control = verify_enrollment_plan(plan, confirmed_digest)
    if str(control.get("project_root")) != str(root):
        raise RepositoryIntelligenceError("Enrollment plan project root does not match the requested project.")
    profile = str(control.get("profile") or "")
    if requested_profile is not None and requested_profile != profile:
        raise RepositoryIntelligenceError("CLI profile does not match the enrollment plan profile.")
    reviewer_id = _require_reviewer(profile, reviewer_id)
    naos_root = str(control.get("naos_root") or "naos")
    if requested_naos_root is not None and requested_naos_root != naos_root:
        raise RepositoryIntelligenceError("CLI NAOS root does not match the enrollment plan.")
    governed_root = _context_index_root(root, naos_root).relative_to(root).as_posix()
    current = inspect_scope(root, governed_root=governed_root)
    planned_gate = control.get("provenance_gate")
    if not isinstance(planned_gate, dict):
        raise RepositoryIntelligenceError("Enrollment provenance gate is missing.")
    current_gate = current.plan_gate()
    stable_gate_fields = set(current_gate) - {"enrollment_project_id"}
    if any(current_gate.get(field) != planned_gate.get(field) for field in stable_gate_fields):
        raise RepositoryIntelligenceError("Capability provenance changed after planning; prepare a new plan.")
    current = ScopeInspection(
        status=current.status,
        project_id=current.project_id,
        owner_integrity=current.owner_integrity,
        scope_integrity=current.scope_integrity,
        governed_root=current.governed_root,
        enrollment_project_id=str(planned_gate.get("enrollment_project_id") or "") or None,
        refusal=current.refusal,
    )

    _bundle, bundle_dir, _manifest = _validate_plan_bundle(
        root,
        plan,
        require_activation=False,
    )
    rules_path = bundle_dir / "repository_intelligence_rules.yaml"
    rules_source = "plan_bundle_snapshot"
    inspection = inspect_repository(
        root,
        profile=profile,
        naos_root=naos_root,
        rules_path=rules_path,
        rules_source=rules_source,
        component_mode=str(control.get("component_mode") or "auto"),
        purpose=str(control.get("purpose") or "brownfield-onboarding"),
    )
    _assert_current_inspection_complete(inspection, phase="enrollment revalidation")
    planned_rules = control.get("rules") if isinstance(control.get("rules"), dict) else {}
    if inspection["rules"].get("sha256") != planned_rules.get("sha256"):
        raise RepositoryIntelligenceError(
            "Enrollment prerequisite rules changed after planning; prepare a new plan."
        )
    for field, observed in (
        ("effective_source_sha256", inspection["effective_source_sha256"]),
        ("runtime", inspection["runtime"]),
        ("components", inspection["components"]),
        ("implementation", _implementation_identity()),
    ):
        if control.get(field) != observed:
            raise RepositoryIntelligenceError(
                f"Enrollment prerequisite {field} changed after planning; prepare a new plan."
            )
    owner, scope = build_enrollment_objects(
        current,
        plan_sha256=confirmed_digest,
        source_manifest_sha256=str(control.get("implementation", {}).get("engine_sha256") or ""),
        kit_version=package_version("naos-governance") or "source-checkout",
        source_commit=None,
    )
    enrolled = commit_enrollment(root, current, owner=owner, scope=scope)
    result = {
        "schema": "naos.repository_intelligence.enrollment_result.v1",
        "status": "enrolled",
        "project_root": str(root),
        "project_id": enrolled.project_id,
        "owner_path": ".naos/upgrade-v1/OWNER.json",
        "owner_integrity_sha3_512": enrolled.owner_integrity,
        "scope_path": ".naos/upgrade-v1/provenance/scopes/repository-intelligence.json",
        "scope_integrity_sha3_512": enrolled.scope_integrity,
        "governed_root": governed_root,
        "authorization_plan_sha256": confirmed_digest,
        "reviewer": {
            "required": _profile_gate(profile)["named_review_required"],
            "reviewer_id": reviewer_id,
            "identity_status": "declared_attribution" if reviewer_id else "not_required",
            "authentication_status": "not_claimed",
        },
        "next_action": "Prepare a new plan; only that post-enrollment plan can become apply-eligible.",
        "ownership_inference_used": False,
        "source_artifacts_modified": [],
    }
    _validate_schema(result, ENROLLMENT_RESULT_SCHEMA)
    return result


def _context_index_root(root: Path, naos_root: str) -> Path:
    try:
        return safe_path_under(
            root,
            CONTEXT_RELATIVE.as_posix(),
            field="repository_intelligence_context_index",
        )
    except ValueError as exc:
        raise RepositoryIntelligenceError(str(exc)) from exc


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)


def _acquire_lock(lock_path: Path, plan_sha256: str) -> StableFileLock:
    try:
        return StableFileLock(
            lock_path,
            {
                "plan_sha256": plan_sha256,
                "metadata_is_authority": False,
            },
        ).acquire()
    except TransactionPrimitiveError as exc:
        raise RepositoryIntelligenceError(str(exc)) from exc


def _release_lock(lock: StableFileLock) -> None:
    lock.release()


def _populate_relationship_tables(path: Path, relationships: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    connection = sqlite3.connect(path)
    try:
        with connection:
            connection.execute(
                """
                CREATE TABLE repository_relationships (
                    relationship_id TEXT PRIMARY KEY,
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    source_path TEXT,
                    target_path TEXT,
                    source_sha256 TEXT,
                    target_sha256 TEXT,
                    evidence_sha256 TEXT,
                    evidence_line INTEGER,
                    reference_id TEXT,
                    provenance TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    candidate_only INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE repository_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            for relationship in relationships:
                connection.execute(
                    "INSERT INTO repository_relationships VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        relationship.get("relationship_id"),
                        relationship.get("source_node"),
                        relationship.get("target_node"),
                        relationship.get("relationship_type"),
                        relationship.get("source_path"),
                        relationship.get("target_path"),
                        relationship.get("source_sha256"),
                        relationship.get("target_sha256"),
                        relationship.get("evidence_sha256"),
                        relationship.get("evidence_line"),
                        relationship.get("reference_id"),
                        relationship.get("provenance"),
                        relationship.get("confidence"),
                        1,
                    ),
                )
            for key, value in sorted(metadata.items()):
                connection.execute(
                    "INSERT INTO repository_metadata VALUES (?, ?)",
                    (key, json.dumps(value, sort_keys=True)),
                )
    finally:
        connection.close()


def _graph_scalar(value: Any) -> str | int | float | bool:
    if isinstance(value, (str, int, float, bool)):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _graph_projection(graph: Any) -> dict[str, Any]:
    graph_attributes = {
        str(key): value
        for key, value in sorted(graph.graph.items())
        if not (key in {"node_default", "edge_default"} and value == {})
    }
    return {
        "directed": bool(graph.is_directed()),
        "multigraph": bool(graph.is_multigraph()),
        "graph": graph_attributes,
        "nodes": [
            {
                "node_id": str(node_id),
                "attributes": {str(key): value for key, value in sorted(attributes.items())},
            }
            for node_id, attributes in sorted(graph.nodes(data=True), key=lambda item: str(item[0]))
        ],
        "edges": [
            {
                "source": str(source),
                "target": str(target),
                "edge_id": str(key),
                "attributes": {str(name): value for name, value in sorted(attributes.items())},
            }
            for source, target, key, attributes in sorted(
                graph.edges(keys=True, data=True),
                key=lambda item: (str(item[0]), str(item[1]), str(item[2])),
            )
        ],
    }


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_graphml(
    path: Path,
    nodes: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    *,
    source_sha256: str,
    model_sha256: str,
) -> dict[str, Any]:
    try:
        import networkx as nx
    except ImportError as exc:
        raise RepositoryIntelligenceError("Exact NetworkX runtime is unavailable.") from exc
    if package_version("networkx") != NETWORKX_VERSION:
        raise RepositoryIntelligenceError(f"NetworkX {NETWORKX_VERSION} is required for GraphML activation.")
    graph = nx.MultiDiGraph()
    graph.graph.update(
        {
            "source_tree_sha256": source_sha256,
            "canonical_model_sha256": model_sha256,
            "candidate_only": True,
        }
    )
    for node in sorted(nodes, key=lambda item: str(item.get("node_id") or "")):
        node_id = str(node.get("node_id") or "")
        attributes = {
            key: _graph_scalar(value)
            for key, value in sorted(node.items())
            if key != "node_id" and value is not None
        }
        graph.add_node(node_id, **attributes)
    for relationship in sorted(relationships, key=lambda item: str(item.get("relationship_id") or "")):
        attributes = {
            key: _graph_scalar(value)
            for key, value in sorted(relationship.items())
            if key not in {"source_node", "target_node"} and value is not None
        }
        graph.add_edge(
            str(relationship["source_node"]),
            str(relationship["target_node"]),
            key=str(relationship["relationship_id"]),
            **attributes,
        )
    if graph.number_of_nodes() > MAX_GRAPHML_NODES or graph.number_of_edges() > MAX_GRAPHML_EDGES:
        raise RepositoryIntelligenceError(
            f"GraphML model exceeds limits: nodes={graph.number_of_nodes()}, edges={graph.number_of_edges()}."
        )
    nx.write_graphml_xml(
        graph,
        path,
        encoding="utf-8",
        prettyprint=True,
        infer_numeric_types=True,
        named_key_ids=False,
        edge_id_from_attribute="relationship_id",
    )
    os.chmod(path, 0o600)
    _fsync_file(path)
    repeat_path = path.with_name(f".{path.name}.determinism-probe")
    try:
        nx.write_graphml_xml(
            graph,
            repeat_path,
            encoding="utf-8",
            prettyprint=True,
            infer_numeric_types=True,
            named_key_ids=False,
            edge_id_from_attribute="relationship_id",
        )
        first = secure_regular_file_bytes(path)
        second = secure_regular_file_bytes(repeat_path)
        if first != second:
            raise RepositoryIntelligenceError("GraphML serialization was not byte-deterministic across repeat writes.")
        upper = first.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise RepositoryIntelligenceError("Generated GraphML contains a prohibited DTD or entity declaration.")
        if len(first) > MAX_GRAPHML_BYTES:
            raise RepositoryIntelligenceError(
                f"Generated GraphML exceeds the {MAX_GRAPHML_BYTES}-byte limit."
            )
        key_ids = re.findall(rb"<key\s+[^>]*id=\"([^\"]+)\"", first)
        if len(key_ids) != len(set(key_ids)):
            raise RepositoryIntelligenceError("Generated GraphML contains duplicate global key identifiers.")
    finally:
        try:
            repeat_path.unlink()
        except FileNotFoundError:
            pass
    loaded = nx.read_graphml(io.BytesIO(first), force_multigraph=True)
    if _graph_projection(loaded) != _graph_projection(graph):
        raise RepositoryIntelligenceError("Generated GraphML failed full semantic round-trip validation.")
    return {
        "status": "validated",
        "networkx_version": package_version("networkx"),
        "writer": "networkx.write_graphml_xml",
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "bytes": len(first),
        "global_key_ids_unique": True,
        "byte_deterministic_repeat": True,
        "semantic_round_trip_validated": True,
    }


def _validate_graphml_file(
    path: Path,
    *,
    expected_source_sha256: str,
    expected_model_sha256: str,
) -> dict[str, Any]:
    try:
        import networkx as nx
    except ImportError as exc:
        raise RepositoryIntelligenceError("Exact NetworkX runtime is unavailable.") from exc
    if package_version("networkx") != NETWORKX_VERSION:
        raise RepositoryIntelligenceError(f"NetworkX {NETWORKX_VERSION} is required for GraphML validation.")
    data = secure_regular_file_bytes(path)
    if len(data) > MAX_GRAPHML_BYTES:
        raise RepositoryIntelligenceError(f"GraphML exceeds the {MAX_GRAPHML_BYTES}-byte limit.")
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise RepositoryIntelligenceError("GraphML contains a prohibited DTD or entity declaration.")
    key_ids = re.findall(rb"<key\s+[^>]*id=\"([^\"]+)\"", data)
    if len(key_ids) != len(set(key_ids)):
        raise RepositoryIntelligenceError("GraphML contains duplicate global key identifiers.")
    try:
        graph = nx.read_graphml(io.BytesIO(data), force_multigraph=True)
    except Exception as exc:
        raise RepositoryIntelligenceError(f"GraphML parse validation failed: {exc}") from exc
    if not graph.is_directed() or not graph.is_multigraph():
        raise RepositoryIntelligenceError("GraphML must encode a directed multigraph.")
    if graph.number_of_nodes() > MAX_GRAPHML_NODES or graph.number_of_edges() > MAX_GRAPHML_EDGES:
        raise RepositoryIntelligenceError("GraphML model exceeds the supported validation limits.")
    if str(graph.graph.get("source_tree_sha256") or "") != expected_source_sha256:
        raise RepositoryIntelligenceError("GraphML source-tree binding is invalid.")
    if str(graph.graph.get("canonical_model_sha256") or "") != expected_model_sha256:
        raise RepositoryIntelligenceError("GraphML model binding is invalid.")
    for source, target, edge_id, attributes in graph.edges(keys=True, data=True):
        if str(attributes.get("relationship_id") or edge_id) != str(edge_id):
            raise RepositoryIntelligenceError(
                f"GraphML relationship identity is inconsistent: {source!r} -> {target!r}."
            )
        if not str(attributes.get("evidence_sha256") or ""):
            raise RepositoryIntelligenceError(f"GraphML edge lacks source-bound evidence: {edge_id!r}.")
    return {
        "status": "validated",
        "networkx_version": NETWORKX_VERSION,
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "bytes": len(data),
        "source_binding_validated": True,
        "model_binding_validated": True,
        "global_key_ids_unique": True,
    }


def _validate_sqlite(
    path: Path,
    expected_source_sha256: str,
    expected_content_binding: dict[str, Any],
) -> dict[str, Any]:
    try:
        uri = path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    except OSError as exc:
        raise RepositoryIntelligenceError(f"SQLite generation is unavailable: {path}") from exc
    connection = sqlite3.connect(uri, uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")
        }
        required = {
            "artifacts",
            "artifact_chunks",
            "artifact_chunks_fts",
            "artifact_links",
            "index_runs",
            "repository_metadata",
            "repository_relationships",
        }
        missing = sorted(required - tables)
        if not integrity or integrity[0] != "ok" or missing:
            raise RepositoryIntelligenceError(
                f"SQLite generation validation failed: integrity={integrity}, missing={missing}"
            )
        source_row = connection.execute(
            "SELECT value FROM repository_metadata WHERE key = ?", ("effective_source_sha256",)
        ).fetchone()
        binding_row = connection.execute(
            "SELECT value FROM repository_metadata WHERE key = ?", ("sqlite_content_binding",)
        ).fetchone()
        try:
            source_value = json.loads(str(source_row[0])) if source_row else None
            metadata_binding = json.loads(str(binding_row[0])) if binding_row else None
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RepositoryIntelligenceError(
                "SQLite repository metadata is not valid JSON."
            ) from exc
        actual_content_binding = {
            "artifacts": _sqlite_rows_binding(
                connection.execute("SELECT * FROM artifacts ORDER BY artifact_id")
            ),
            "artifact_chunks": _sqlite_rows_binding(
                connection.execute("SELECT * FROM artifact_chunks ORDER BY chunk_id")
            ),
            "artifact_links": _sqlite_rows_binding(
                connection.execute("SELECT * FROM artifact_links ORDER BY link_id")
            ),
            "repository_relationships": _sqlite_rows_binding(
                connection.execute(
                    "SELECT * FROM repository_relationships ORDER BY relationship_id"
                )
            ),
        }
        fts_binding = _sqlite_rows_binding(
            connection.execute(
                """
                SELECT chunk_id, artifact_id, path, section_heading, text_summary, bounded_excerpt
                FROM artifact_chunks_fts
                ORDER BY chunk_id
                """
            )
        )
        expected_fts_binding = _sqlite_rows_binding(
            connection.execute(
                """
                SELECT chunk_id, artifact_id, path, section_heading, text_summary, bounded_excerpt
                FROM artifact_chunks
                ORDER BY chunk_id
                """
            )
        )
        index_runs = connection.execute(
            "SELECT run_id, artifact_count, chunk_count FROM index_runs ORDER BY run_id"
        ).fetchall()
        orphan_chunks = int(
            connection.execute(
                """
                SELECT count(*)
                FROM artifact_chunks AS chunk
                LEFT JOIN artifacts AS artifact ON artifact.artifact_id = chunk.artifact_id
                WHERE artifact.artifact_id IS NULL OR artifact.path != chunk.path
                """
            ).fetchone()[0]
        )
        orphan_links = int(
            connection.execute(
                """
                SELECT count(*)
                FROM artifact_links AS link
                LEFT JOIN artifacts AS artifact ON artifact.path = link.source_path
                WHERE artifact.artifact_id IS NULL
                """
            ).fetchone()[0]
        )
        orphan_relationship_paths = int(
            connection.execute(
                """
                SELECT count(*)
                FROM repository_relationships AS relationship
                LEFT JOIN artifacts AS source_artifact
                  ON source_artifact.path = relationship.source_path
                LEFT JOIN artifacts AS target_artifact
                  ON target_artifact.path = relationship.target_path
                WHERE (relationship.source_path IS NOT NULL AND source_artifact.artifact_id IS NULL)
                   OR (relationship.target_path IS NOT NULL AND target_artifact.artifact_id IS NULL)
                """
            ).fetchone()[0]
        )
        fts_probe = connection.execute(
            "SELECT count(*) FROM artifact_chunks_fts WHERE artifact_chunks_fts MATCH ?", ("naos",)
        ).fetchone()
        expected_run = [
            (
                "current",
                expected_content_binding.get("artifacts", {}).get("count"),
                expected_content_binding.get("artifact_chunks", {}).get("count"),
            )
        ]
        if (
            source_value != expected_source_sha256
            or metadata_binding != expected_content_binding
            or actual_content_binding != expected_content_binding
            or fts_binding != expected_fts_binding
            or index_runs != expected_run
            or orphan_chunks
            or orphan_links
            or orphan_relationship_paths
        ):
            raise RepositoryIntelligenceError(
                "SQLite generation content binding failed: "
                f"source_match={source_value == expected_source_sha256}, "
                f"metadata_match={metadata_binding == expected_content_binding}, "
                f"identity_match={actual_content_binding == expected_content_binding}, "
                f"fts_content_match={fts_binding == expected_fts_binding}, "
                f"index_counts_match={index_runs == expected_run}, "
                f"orphan_chunks={orphan_chunks}, orphan_links={orphan_links}, "
                f"orphan_relationship_paths={orphan_relationship_paths}"
            )
        return {
            "status": "validated",
            "integrity_check": "ok",
            "required_tables": sorted(required),
            "fts_query_executed": True,
            "fts_probe_matches": int(fts_probe[0]) if fts_probe else 0,
            "source_binding_validated": True,
            "content_identity_binding": actual_content_binding,
            "relational_consistency_validated": True,
        }
    finally:
        connection.close()


def _file_record(path: Path) -> dict[str, Any]:
    data = secure_regular_file_bytes(path)
    return {"path": path.name, "sha256": sha256_bytes(data), "size_bytes": len(data)}


def _write_json(path: Path, report: dict[str, Any]) -> None:
    write_report(path, report, strict_parent_topology=True)


def _json_report_bytes(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_new_bytes(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _current_active_pointer(context_root: Path) -> dict[str, Any] | None:
    path = context_root / "active.json"
    if not path.exists():
        return None
    data = _strict_json_file(path)
    if data.get("schema") != ACTIVE_SCHEMA:
        raise RepositoryIntelligenceError(
            "Existing context-index active.json is foreign or incompatible; refusing replacement."
        )
    return data


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    parent = path.parent
    temporary = parent / f".{path.name}.pending"
    if temporary.exists() or temporary.is_symlink():
        metadata = os.lstat(temporary)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RepositoryIntelligenceError(
                f"Unsafe pending atomic-write file is preserved and refused: {temporary}"
            )
        temporary.unlink()
        _fsync_directory(parent)
    _write_new_bytes(temporary, data)
    try:
        os.replace(temporary, path)
        _fsync_directory(parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_promoted_generation(
    root: Path,
    generation_dir: Path,
    *,
    control: dict[str, Any],
    bundle: dict[str, Any],
) -> dict[str, Any]:
    records = bundle.get("files")
    if not isinstance(records, list):
        raise RepositoryIntelligenceError("Generation file inventory is missing.")
    _validate_file_records(generation_dir, records)
    actual = sorted(child.name for child in generation_dir.iterdir())
    expected = sorted(str(item.get("path") or "") for item in records)
    if actual != expected:
        raise RepositoryIntelligenceError("Promoted generation has missing or unrecorded entries.")
    for child in generation_dir.iterdir():
        metadata = os.lstat(child)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RepositoryIntelligenceError(f"Promoted generation contains an unsafe entry: {child}")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RepositoryIntelligenceError(f"Promoted generation file mode is not 0600: {child}")
    manifest = _strict_json_file(generation_dir / "manifest.json")
    _validate_schema(manifest, MANIFEST_SCHEMA)
    manifest_control = manifest.get("control")
    if not isinstance(manifest_control, dict) or canonical_sha256(manifest_control) != manifest.get("manifest_sha256"):
        raise RepositoryIntelligenceError("Promoted manifest digest is invalid.")
    if manifest.get("status") != "validated":
        raise RepositoryIntelligenceError("Promoted manifest is diagnostic-only.")
    for field in (
        "generation_id",
        "generation_content_sha256",
        "project_root",
        "effective_source_sha256",
        "graph_model_sha256",
        "profile",
        "purpose",
        "component_mode",
        "runtime",
        "implementation",
        "provenance_gate",
        "components",
        "ongoing_use_scope",
    ):
        if manifest_control.get(field) != control.get(field):
            raise RepositoryIntelligenceError(f"Promoted manifest {field} binding is invalid.")
    receipt = _strict_json_file(generation_dir / "validation_receipt.json")
    _validate_schema(receipt, RECEIPT_SCHEMA)
    receipt_control = receipt.get("control")
    if (
        receipt.get("status") != "validated_generation"
        or not isinstance(receipt_control, dict)
        or canonical_sha256(receipt_control) != receipt.get("receipt_sha256")
        or receipt.get("receipt_sha256") != manifest_control.get("validation_receipt_sha256")
    ):
        raise RepositoryIntelligenceError("Promoted generation validation receipt is invalid.")
    inventory = _strict_json_file(generation_dir / "inventory.json")
    _validate_schema(inventory, INVENTORY_SCHEMA)
    content_binding = inventory.get("sqlite_content_binding")
    if not isinstance(content_binding, dict):
        raise RepositoryIntelligenceError("Promoted SQLite content binding is missing.")
    sqlite_validation = _validate_sqlite(
        generation_dir / "local_context_index.sqlite",
        str(control.get("effective_source_sha256") or ""),
        content_binding,
    )
    graph_validation: dict[str, Any]
    if control.get("generation_layout", {}).get("graphml"):
        graph_validation = _validate_graphml_file(
            generation_dir / "context.graphml",
            expected_source_sha256=str(control.get("effective_source_sha256") or ""),
            expected_model_sha256=str(control.get("graph_model_sha256") or ""),
        )
    else:
        graph_validation = {"status": "not_selected"}
    return {
        "status": "validated_generation",
        "manifest": manifest,
        "validation_receipt": receipt,
        "sqlite_fts": sqlite_validation,
        "networkx_graphml": graph_validation,
    }


def _staging_pending_name(name: str) -> str:
    return f".{name}.pending"


def _copy_exact_bundle(bundle_dir: Path, staging_dir: Path, records: list[dict[str, Any]]) -> None:
    os.mkdir(staging_dir, 0o700)
    os.chmod(staging_dir, 0o700)
    _fsync_directory(staging_dir)
    _fsync_directory(staging_dir.parent)
    for record in sorted(records, key=lambda item: str(item.get("path") or "")):
        name = str(record.get("path") or "")
        data = secure_regular_file_bytes(bundle_dir / name)
        if sha256_bytes(data) != record.get("sha256") or len(data) != record.get("size_bytes"):
            raise RepositoryIntelligenceError(f"Plan-bundle file changed during promotion: {name}")
        destination = staging_dir / name
        pending = staging_dir / _staging_pending_name(name)
        _write_new_bytes(pending, data)
        rename_no_replace(pending, destination)
        _fsync_directory(staging_dir)


def _exact_file_record_map(records: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise RepositoryIntelligenceError("Transaction staging-file inventory is missing.")
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise RepositoryIntelligenceError("Transaction staging-file record is invalid.")
        name = str(record.get("path") or "")
        if not name or Path(name).name != name or name in result:
            raise RepositoryIntelligenceError(
                f"Transaction staging-file path is invalid: {name!r}"
            )
        digest = record.get("sha256")
        size = record.get("size_bytes")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RepositoryIntelligenceError(
                f"Transaction staging-file digest is invalid: {name!r}"
            )
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RepositoryIntelligenceError(
                f"Transaction staging-file size is invalid: {name!r}"
            )
        result[name] = {"path": name, "sha256": digest, "size_bytes": size}
    return result


def _operation_directory_conflicts(
    path: Path,
    records: Any,
    *,
    allow_pending: bool,
    require_complete: bool = False,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> list[str]:
    expected = _exact_file_record_map(records)
    try:
        root_metadata = os.lstat(path)
    except FileNotFoundError:
        return []
    conflicts: list[str] = []
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        return [str(path)]
    if expected_device is not None and root_metadata.st_dev != expected_device:
        conflicts.append(f"{path}:device")
    if expected_inode is not None and root_metadata.st_ino != expected_inode:
        conflicts.append(f"{path}:inode")
    pending_names = {
        _staging_pending_name(name): name for name in expected
    } if allow_pending else {}
    observed_complete: set[str] = set()
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        metadata = os.lstat(child)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            conflicts.append(str(child))
            continue
        record = expected.get(child.name)
        if record is not None:
            try:
                data = secure_regular_file_bytes(child)
            except (OSError, RepositoryIntelligenceError):
                conflicts.append(str(child))
                continue
            if len(data) != record["size_bytes"] or sha256_bytes(data) != record["sha256"]:
                conflicts.append(str(child))
            else:
                observed_complete.add(child.name)
            continue
        if child.name in pending_names:
            continue
        conflicts.append(str(child))
    if require_complete:
        conflicts.extend(
            f"{path}/{name}:missing"
            for name in sorted(set(expected) - observed_complete)
        )
    return conflicts


def _remove_owned_staging(
    staging_path: Path,
    records: Any,
    *,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> None:
    if not staging_path.exists() and not staging_path.is_symlink():
        return
    conflicts = _operation_directory_conflicts(
        staging_path,
        records,
        allow_pending=True,
        expected_device=expected_device,
        expected_inode=expected_inode,
    )
    if conflicts:
        raise RepositoryIntelligenceError(
            "Rollback conflict preserved in transaction staging: " + ", ".join(conflicts)
        )
    for child in sorted(staging_path.iterdir(), key=lambda item: item.name):
        child.unlink()
    staging_path.rmdir()
    _fsync_directory(staging_path.parent)


def _journal_digest_payload(journal: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(journal)
    payload.pop("journal_sha256", None)
    return payload


def _write_journal(path: Path, journal: dict[str, Any], *, state: str, error: str | None = None) -> dict[str, Any]:
    updated = copy.deepcopy(journal)
    updated["state"] = state
    updated["updated_at"] = utc_now_text()
    updated["last_error"] = error
    updated["journal_sha256"] = canonical_sha256(_journal_digest_payload(updated))
    _validate_schema(updated, JOURNAL_SCHEMA)
    _atomic_write_bytes(path, _json_report_bytes(updated))
    return updated


def _load_journal(path: Path) -> dict[str, Any]:
    journal = _strict_json_file(path)
    if journal.get("schema") != "naos.repository_intelligence.transaction_journal.v1":
        raise RepositoryIntelligenceError(f"Unsupported transaction journal: {path}")
    if canonical_sha256(_journal_digest_payload(journal)) != journal.get("journal_sha256"):
        raise RepositoryIntelligenceError(f"Transaction journal digest is invalid: {path}")
    _validate_schema(journal, JOURNAL_SCHEMA)
    return journal


def _preparing_transaction_name(transaction_id: str) -> str:
    if not TRANSACTION_ID_RE.fullmatch(transaction_id):
        raise RepositoryIntelligenceError(f"Invalid transaction identity: {transaction_id!r}")
    return f".{transaction_id}.preparing"


def _transaction_id_from_preparing_name(name: str) -> str | None:
    prefix = "."
    suffix = ".preparing"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return None
    transaction_id = name[len(prefix) : -len(suffix)]
    return transaction_id if TRANSACTION_ID_RE.fullmatch(transaction_id) else None


def _prepare_transaction_directory(
    transactions_root: Path,
    transaction_dir: Path,
    journal: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    """Publish a recoverable PREPARED journal without an unowned mkdir gap."""

    transaction_id = str(journal.get("transaction_id") or "")
    if transaction_dir.name != transaction_id or not TRANSACTION_ID_RE.fullmatch(transaction_id):
        raise RepositoryIntelligenceError("Transaction directory does not match its journal identity.")
    preparing_dir = transactions_root / _preparing_transaction_name(transaction_id)
    if transaction_dir.exists() or transaction_dir.is_symlink():
        raise RepositoryIntelligenceError(f"Transaction already exists: {transaction_id}")
    if preparing_dir.exists() or preparing_dir.is_symlink():
        raise RepositoryIntelligenceError(
            f"Transaction preparation already exists: {transaction_id}. Run status/recovery before retrying."
        )
    os.mkdir(preparing_dir, 0o700)
    _fsync_directory(transactions_root)
    prepared = _write_journal(
        preparing_dir / "journal.json",
        journal,
        state="PREPARED",
    )
    rename_no_replace(preparing_dir, transaction_dir)
    _fsync_directory(transactions_root)
    return transaction_dir / "journal.json", prepared


def _normalize_preparing_transactions(transactions_root: Path) -> list[dict[str, Any]]:
    """Recover only exact operation-owned preparation directories."""

    normalized: list[dict[str, Any]] = []
    if not transactions_root.exists():
        return normalized
    for child in sorted(transactions_root.iterdir(), key=lambda item: item.name):
        transaction_id = _transaction_id_from_preparing_name(child.name)
        if transaction_id is None:
            continue
        metadata = os.lstat(child)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RepositoryIntelligenceError(
                f"Unsafe transaction preparation entry is preserved and refused: {child}"
            )
        journal_pending = child / ".journal.json.pending"
        if journal_pending.exists() or journal_pending.is_symlink():
            pending_metadata = os.lstat(journal_pending)
            if (
                stat.S_ISLNK(pending_metadata.st_mode)
                or not stat.S_ISREG(pending_metadata.st_mode)
                or pending_metadata.st_nlink != 1
                or stat.S_IMODE(pending_metadata.st_mode) != 0o600
            ):
                raise RepositoryIntelligenceError(
                    f"Unsafe pending journal is preserved and refused: {journal_pending}"
                )
            journal_pending.unlink()
            _fsync_directory(child)
        entries = sorted(item.name for item in child.iterdir())
        if not entries:
            child.rmdir()
            _fsync_directory(transactions_root)
            normalized.append(
                {
                    "transaction_id": transaction_id,
                    "state": "PREPARATION_DISCARDED",
                    "journal_path": None,
                    "unreferenced_generation_preserved": False,
                }
            )
            continue
        if entries != ["journal.json"]:
            raise RepositoryIntelligenceError(
                f"Unknown transaction preparation contents are preserved and refused: {child}"
            )
        journal = _load_journal(child / "journal.json")
        if journal.get("transaction_id") != transaction_id:
            raise RepositoryIntelligenceError(
                f"Transaction preparation identity mismatch is preserved and refused: {child}"
            )
        transaction_dir = transactions_root / transaction_id
        if transaction_dir.exists() or transaction_dir.is_symlink():
            raise RepositoryIntelligenceError(
                f"Transaction preparation collides with an existing transaction: {transaction_id}"
            )
        rename_no_replace(child, transaction_dir)
        _fsync_directory(transactions_root)
    return normalized


def _unresolved_journals(transactions_root: Path) -> list[tuple[Path, dict[str, Any]]]:
    if not transactions_root.exists():
        return []
    unresolved: list[tuple[Path, dict[str, Any]]] = []
    for child in sorted(transactions_root.iterdir(), key=lambda item: item.name):
        if child.is_symlink() or not child.is_dir():
            raise RepositoryIntelligenceError(f"Unknown transaction entry: {child}")
        if _transaction_id_from_preparing_name(child.name) is not None:
            raise RepositoryIntelligenceError(
                f"Interrupted transaction preparation requires recovery: {child.name}"
            )
        if not TRANSACTION_ID_RE.fullmatch(child.name):
            raise RepositoryIntelligenceError(f"Unknown transaction entry: {child}")
        journal_path = child / "journal.json"
        journal = _load_journal(journal_path)
        if journal.get("transaction_id") != child.name:
            raise RepositoryIntelligenceError(f"Transaction directory identity mismatch: {child}")
        if journal.get("state") not in {"COMMITTED", "ROLLED_BACK"}:
            unresolved.append((journal_path, journal))
    return unresolved


def _generation_reuse_authorized(
    transactions_root: Path,
    *,
    generation_id: str,
    generation_content_sha256: str,
    final_path: str,
    exclude_transaction_id: str,
) -> bool:
    for child in sorted(transactions_root.iterdir(), key=lambda item: item.name):
        if child.name == exclude_transaction_id or not TRANSACTION_ID_RE.fullmatch(child.name):
            continue
        try:
            journal = _load_journal(child / "journal.json")
        except (RepositoryIntelligenceError, OSError, ValueError):
            continue
        if (
            journal.get("state") in {"COMMITTED", "ROLLED_BACK"}
            and journal.get("generation_id") == generation_id
            and journal.get("generation_content_sha256") == generation_content_sha256
            and journal.get("final_path") == final_path
            and journal.get("generation_published") is True
            and isinstance(journal.get("completed_action_index"), int)
            and journal.get("completed_action_index") >= 1
        ):
            return True
    return False


def _inactive_context_is_operation_owned(
    root: Path,
    context_root: Path,
    transactions_root: Path,
    *,
    allowed_inflight_transaction_id: str | None = None,
) -> bool:
    _assert_context_entries(context_root)
    if (context_root / "active.json").exists():
        return False
    generations_root = context_root / "generations"
    if not generations_root.exists() or generations_root.is_symlink():
        return False
    generations = sorted(generations_root.iterdir(), key=lambda item: item.name)
    if not generations:
        return False
    for generation in generations:
        if not re.fullmatch(r"RI-[0-9a-f]{24}", generation.name):
            return False
        relative = generation.relative_to(root).as_posix()
        authorized = False
        for transaction in sorted(transactions_root.iterdir(), key=lambda item: item.name):
            if not TRANSACTION_ID_RE.fullmatch(transaction.name):
                continue
            try:
                journal = _load_journal(transaction / "journal.json")
            except (RepositoryIntelligenceError, OSError, ValueError):
                continue
            state_is_owned = journal.get("state") in {"COMMITTED", "ROLLED_BACK"} or (
                transaction.name == allowed_inflight_transaction_id
                and journal.get("state") in {"APPLYING", "VALIDATING"}
            )
            if not (
                state_is_owned
                and journal.get("generation_id") == generation.name
                and journal.get("final_path") == relative
                and journal.get("generation_published") is True
                and isinstance(journal.get("completed_action_index"), int)
                and journal.get("completed_action_index") >= 1
            ):
                continue
            conflicts = _operation_directory_conflicts(
                generation,
                journal.get("staging_files"),
                allow_pending=False,
                require_complete=True,
                expected_device=journal.get("staging_device"),
                expected_inode=journal.get("staging_inode"),
            )
            if not conflicts:
                authorized = True
                break
        if not authorized:
            return False
    return True


def _reconcile_generation_publication(
    root: Path,
    journal: dict[str, Any],
) -> dict[str, Any]:
    """Resolve the only indeterminate publication window by inode identity."""

    final_path = safe_path_under(
        root,
        str(journal.get("final_path") or ""),
        field="repository_intelligence_generation_publication",
    )
    exists = final_path.exists() or final_path.is_symlink()
    published = journal.get("generation_published") is True
    device = journal.get("staging_device")
    inode = journal.get("staging_inode")
    if not exists:
        if published:
            raise RepositoryIntelligenceError(
                f"Published generation disappeared and rollback preserved state: {final_path}"
            )
        return journal
    if not isinstance(device, int) or isinstance(device, bool) or not isinstance(inode, int) or isinstance(inode, bool):
        if published:
            raise RepositoryIntelligenceError(
                f"Published generation lacks its journaled filesystem identity: {final_path}"
            )
        return journal
    conflicts = _operation_directory_conflicts(
        final_path,
        journal.get("staging_files"),
        allow_pending=False,
        require_complete=True,
        expected_device=device,
        expected_inode=inode,
    )
    if conflicts:
        raise RepositoryIntelligenceError(
            "Generation publication conflict was preserved: " + ", ".join(conflicts)
        )
    updated = copy.deepcopy(journal)
    updated["generation_published"] = True
    updated["completed_action_index"] = max(
        1, int(updated.get("completed_action_index") or 0)
    )
    return updated


def _remove_active_pending(root: Path, context_root: Path, journal: dict[str, Any]) -> None:
    expected = context_root / ".active.json.pending"
    pending = safe_path_under(
        root,
        str(journal.get("active_pending_path") or ""),
        field="repository_intelligence_active_pending",
    )
    if pending != expected:
        raise RepositoryIntelligenceError(
            "Transaction active-pointer pending path is invalid."
        )
    try:
        metadata = os.lstat(pending)
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RepositoryIntelligenceError(
            f"Active-pointer rollback conflict was preserved: {pending}"
        )
    pending.unlink()
    _fsync_directory(pending.parent)


def _reconcile_initial_context_publication(
    root: Path,
    context_root: Path,
    journal: dict[str, Any],
) -> dict[str, Any]:
    if journal.get("initial_context_absent") is not True:
        return journal
    prepared = safe_path_under(
        root,
        str(journal.get("context_staging_path") or ""),
        field="repository_intelligence_context_staging",
    )
    expected_prepared = (
        root
        / TRANSACTIONS_RELATIVE
        / str(journal.get("transaction_id") or "")
        / "context"
    )
    if prepared != expected_prepared:
        raise RepositoryIntelligenceError("Transaction context-staging path is invalid.")
    prepared_exists = prepared.exists() or prepared.is_symlink()
    context_exists = context_root.exists() or context_root.is_symlink()
    if prepared_exists and context_exists:
        raise RepositoryIntelligenceError(
            "Both prepared and published context roots exist; rollback preserved both."
        )
    device = journal.get("context_staging_device")
    inode = journal.get("context_staging_inode")
    candidate = context_root if context_exists else prepared if prepared_exists else None
    if candidate is None:
        if journal.get("context_published") is True:
            raise RepositoryIntelligenceError(
                "Journaled context publication disappeared; rollback preserved state."
            )
        return journal
    metadata = os.lstat(candidate)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or not isinstance(device, int)
        or isinstance(device, bool)
        or not isinstance(inode, int)
        or isinstance(inode, bool)
        or metadata.st_dev != device
        or metadata.st_ino != inode
    ):
        raise RepositoryIntelligenceError(
            f"Context publication identity conflict was preserved: {candidate}"
        )
    entries = sorted(child.name for child in candidate.iterdir())
    if entries != ["generations"]:
        raise RepositoryIntelligenceError(
            f"Context publication contents conflict was preserved: {candidate}"
        )
    generations = candidate / "generations"
    generations_metadata = os.lstat(generations)
    if (
        stat.S_ISLNK(generations_metadata.st_mode)
        or not stat.S_ISDIR(generations_metadata.st_mode)
        or stat.S_IMODE(generations_metadata.st_mode) != 0o700
    ):
        raise RepositoryIntelligenceError(
            f"Context generations directory conflict was preserved: {generations}"
        )
    generation_entries = sorted(generations.iterdir(), key=lambda item: item.name)
    expected_generation = str(journal.get("generation_id") or "")
    if generation_entries:
        if len(generation_entries) != 1 or generation_entries[0].name != expected_generation:
            raise RepositoryIntelligenceError(
                f"Context generation conflict was preserved: {generations}"
            )
        conflicts = _operation_directory_conflicts(
            generation_entries[0],
            journal.get("staging_files"),
            allow_pending=False,
            require_complete=True,
            expected_device=journal.get("staging_device"),
            expected_inode=journal.get("staging_inode"),
        )
        if conflicts:
            raise RepositoryIntelligenceError(
                "Context generation conflict was preserved: " + ", ".join(conflicts)
            )
    if context_exists:
        if not generation_entries:
            raise RepositoryIntelligenceError(
                "Published context root has no journaled generation."
            )
        updated = copy.deepcopy(journal)
        updated["context_published"] = True
        updated["generation_published"] = True
        updated["completed_action_index"] = max(
            1, int(updated.get("completed_action_index") or 0)
        )
        return updated
    if generation_entries:
        _remove_owned_staging(
            generation_entries[0],
            journal.get("staging_files"),
            expected_device=journal.get("staging_device"),
            expected_inode=journal.get("staging_inode"),
        )
    generations.rmdir()
    prepared.rmdir()
    _fsync_directory(prepared.parent)
    return journal


def _cleanup_failed_transaction_state(
    root: Path,
    context_root: Path,
    journal: dict[str, Any],
) -> dict[str, Any]:
    _remove_active_pending(root, context_root, journal)
    updated = _reconcile_initial_context_publication(root, context_root, journal)
    if updated.get("initial_context_absent") is not True:
        updated = _reconcile_generation_publication(root, updated)
    staging_path = safe_path_under(
        root,
        str(updated.get("staging_path") or ""),
        field="repository_intelligence_rollback_staging",
    )
    _remove_owned_staging(
        staging_path,
        updated.get("staging_files"),
        expected_device=updated.get("staging_device"),
        expected_inode=updated.get("staging_inode"),
    )
    return updated


def _active_file_state(active_path: Path) -> tuple[dict[str, Any] | None, bytes | None, str | None]:
    if not active_path.exists():
        return None, None, None
    data = secure_regular_file_bytes(active_path)
    active = loads_strict_json(data)
    if not isinstance(active, dict) or active.get("schema") != ACTIVE_SCHEMA:
        raise RepositoryIntelligenceError("Existing active pointer is foreign or invalid.")
    return active, data, sha256_bytes(data)


def _restore_active_pointer(
    active_path: Path,
    *,
    active_before_bytes: bytes | None,
    active_before_file_sha256: str | None,
    proposed_active_sha256: str,
    proposed_active_file_sha256: str | None,
) -> None:
    if active_path.exists():
        live_bytes = secure_regular_file_bytes(active_path)
        live_file_sha256 = sha256_bytes(live_bytes)
        if active_before_file_sha256 and live_file_sha256 == active_before_file_sha256:
            return
        if (
            proposed_active_file_sha256 is None
            or live_file_sha256 != proposed_active_file_sha256
        ):
            raise RepositoryIntelligenceError(
                "Active pointer changed unexpectedly; rollback requires recovery and preserved the live pointer."
            )
        live = loads_strict_json(live_bytes)
        if (
            not isinstance(live, dict)
            or live.get("active_sha256") != proposed_active_sha256
        ):
            raise RepositoryIntelligenceError(
                "Active pointer semantic identity changed unexpectedly; rollback preserved the live pointer."
            )
        if active_before_bytes is None:
            active_path.unlink()
            _fsync_directory(active_path.parent)
        else:
            _atomic_write_bytes(active_path, active_before_bytes)
    elif active_before_bytes is not None:
        _atomic_write_bytes(active_path, active_before_bytes)


def _assert_context_entries(context_root: Path) -> None:
    try:
        root_metadata = os.lstat(context_root)
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RepositoryIntelligenceError(
            f"Generated context root is unsafe or has unsupported metadata: {context_root}"
        )
    allowed = {"generations", "active.json"}
    unknown = sorted(child.name for child in context_root.iterdir() if child.name not in allowed)
    if unknown:
        raise RepositoryIntelligenceError(
            f"Foreign repository-intelligence entries are preserved and refused: {unknown}"
        )
    for child in context_root.iterdir():
        metadata = os.lstat(child)
        if child.name == "generations":
            valid = (
                not stat.S_ISLNK(metadata.st_mode)
                and stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o700
            )
        else:
            valid = (
                not stat.S_ISLNK(metadata.st_mode)
                and stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
            )
        if not valid:
            raise RepositoryIntelligenceError(
                f"Generated context entry has unsupported metadata: {child}"
            )


def apply_plan(
    root: Path,
    plan: dict[str, Any],
    *,
    confirmed_digest: str,
    reviewer_id: str | None,
    rules_override: str | None = None,
    requested_profile: str | None = None,
    requested_naos_root: str | None = None,
) -> dict[str, Any]:
    if rules_override is not None:
        raise RepositoryIntelligenceError("Apply does not accept a rules override; rules are bound by the plan.")
    control = verify_plan(plan, confirmed_digest)
    if str(control.get("project_root")) != str(root):
        raise RepositoryIntelligenceError("Plan project root does not match the requested project.")
    profile = str(control.get("profile") or "")
    if requested_profile is not None and requested_profile != profile:
        raise RepositoryIntelligenceError("CLI profile does not match the apply plan profile.")
    reviewer_id = _require_reviewer(profile, reviewer_id)
    naos_root = str(control.get("naos_root") or "naos")
    if requested_naos_root is not None and requested_naos_root != naos_root:
        raise RepositoryIntelligenceError("CLI NAOS root does not match the apply plan.")
    context_root = _context_index_root(root, naos_root)
    governed_root = context_root.relative_to(root).as_posix()
    scope = inspect_scope(root, governed_root=governed_root)
    if scope.plan_gate() != control.get("provenance_gate") or not scope.activation_eligible:
        raise RepositoryIntelligenceError("Capability provenance changed after planning; prepare a new plan.")

    bundle, bundle_dir, _bundle_manifest = _validate_plan_bundle(
        root,
        plan,
        require_activation=True,
    )
    rules_identity = control.get("rules") if isinstance(control.get("rules"), dict) else {}
    rules_path = bundle_dir / "repository_intelligence_rules.yaml"
    rules_source = "plan_bundle_snapshot"
    inspection = inspect_repository(
        root,
        profile=profile,
        naos_root=naos_root,
        rules_path=rules_path,
        rules_source=rules_source,
        component_mode=str(control.get("component_mode") or "auto"),
        purpose=str(control.get("purpose") or "brownfield-onboarding"),
    )
    _assert_current_inspection_complete(inspection, phase="pre-apply revalidation")
    if inspection["rules"].get("sha256") != rules_identity.get("sha256"):
        raise RepositoryIntelligenceError("rules changed after planning; prepare a new plan.")
    comparisons = {
        "effective_source_sha256": inspection["effective_source_sha256"],
        "runtime": inspection["runtime"],
        "components": inspection["components"],
        "implementation": _implementation_identity(),
    }
    for field, observed in comparisons.items():
        if control.get(field) != observed:
            raise RepositoryIntelligenceError(f"{field} changed after planning; prepare a new plan.")
    graph_model = {
        "directed": True,
        "multigraph": True,
        "nodes": inspection["nodes"],
        "relationships": inspection["relationships"],
    }
    if canonical_sha256(graph_model) != control.get("graph_model_sha256"):
        raise RepositoryIntelligenceError("Relationship model changed after planning; prepare a new plan.")
    generations_root = context_root / "generations"
    transactions_root = root / TRANSACTIONS_RELATIVE
    lock_path = root / LOCK_RELATIVE
    lock = _acquire_lock(lock_path, confirmed_digest)
    journal: dict[str, Any] | None = None
    journal_path: Path | None = None
    staging_dir: Path | None = None
    proposed_pointer: dict[str, Any] | None = None
    try:
        locked_scope = inspect_scope(root, governed_root=governed_root)
        if locked_scope.plan_gate() != control.get("provenance_gate") or not locked_scope.activation_eligible:
            raise RepositoryIntelligenceError(
                "Capability provenance changed before the transaction lock was acquired."
            )
        transactions_metadata = os.lstat(transactions_root)
        if (
            stat.S_ISLNK(transactions_metadata.st_mode)
            or not stat.S_ISDIR(transactions_metadata.st_mode)
            or stat.S_IMODE(transactions_metadata.st_mode) != 0o700
        ):
            raise RepositoryIntelligenceError(
                f"Repository-intelligence transaction root is unsafe: {transactions_root}"
            )
        unresolved = _unresolved_journals(transactions_root)
        if unresolved:
            raise RepositoryIntelligenceError(
                f"Unresolved transaction {unresolved[0][1].get('transaction_id')} requires recovery before apply."
            )
        active_path = context_root / "active.json"
        try:
            os.lstat(context_root)
        except FileNotFoundError:
            context_kind = "absent"
        else:
            context_kind = "present"
        if context_kind == "absent":
            active_before = None
            active_before_bytes = None
            active_before_file_sha256 = None
        else:
            _assert_context_entries(context_root)
            if not active_path.exists():
                if not _inactive_context_is_operation_owned(
                    root, context_root, transactions_root
                ):
                    raise RepositoryIntelligenceError(
                        "The governed root appeared after enrollment without a valid active chain; ownership was refused."
                    )
                active_before = None
                active_before_bytes = None
                active_before_file_sha256 = None
            else:
                prior_validation = validate_active_generation(
                    root,
                    naos_root=naos_root,
                    require_current_source=False,
                )
                if prior_validation.get("status") != "validated":
                    raise RepositoryIntelligenceError(
                        "Existing active state is not a valid rollback base."
                    )
                active_before, active_before_bytes, active_before_file_sha256 = _active_file_state(active_path)
        if (
            isinstance(active_before, dict)
            and active_before.get("control", {}).get("plan_sha256") == confirmed_digest
            and active_before.get("control", {}).get("bundle_sha256") == bundle.get("bundle_sha256")
        ):
            validation = validate_active_generation(root, naos_root=naos_root, require_current_source=True)
            if validation.get("status") != "validated_current":
                raise RepositoryIntelligenceError("Existing same-plan activation is not current.")
            result = {
                "schema": APPLY_RESULT_SCHEMA,
                "status": "already_active",
                "transaction_id": active_before.get("control", {}).get("transaction_id"),
                "generation_id": control.get("generation_id"),
                "generation_content_sha256": control.get("generation_content_sha256"),
                "plan_sha256": confirmed_digest,
                "bundle_sha256": bundle.get("bundle_sha256"),
                "active_pointer": str(active_path.relative_to(root)),
                "active_sha256": active_before.get("active_sha256"),
                "manifest": active_before.get("control", {}).get("manifest_path"),
                "manifest_sha256": active_before.get("control", {}).get("manifest_sha256"),
                "activation_receipt": active_before.get("control", {}).get("activation_receipt_path"),
                "activation_receipt_sha256": active_before.get("control", {}).get("activation_receipt_sha256"),
                "validation": validation,
                "idempotent_reuse": True,
                "previous_generation_id": active_before.get("control", {}).get("previous_generation_id"),
                "source_artifacts_modified": [],
                "generated_state_only": True,
                "exact_bundle_bytes_promoted": True,
            }
            _validate_schema(result, APPLY_RESULT_SCHEMA)
            return result

        transaction_seed = {
            "plan_sha256": confirmed_digest,
            "bundle_sha256": bundle.get("bundle_sha256"),
            "active_before_file_sha256": active_before_file_sha256,
        }
        attempt = 0
        while True:
            transaction_id = f"RIT-{canonical_sha256({**transaction_seed, 'attempt': attempt})[:24]}"
            transaction_dir = transactions_root / transaction_id
            preparing_dir = transactions_root / _preparing_transaction_name(transaction_id)
            if (
                not transaction_dir.exists()
                and not transaction_dir.is_symlink()
                and not preparing_dir.exists()
                and not preparing_dir.is_symlink()
            ):
                break
            attempt += 1
            if attempt > 10_000:
                raise RepositoryIntelligenceError("No unused bounded transaction identity is available.")
        generation_id = str(control.get("generation_id") or "")
        final_dir = generations_root / generation_id
        staging_dir = transaction_dir / "staging"
        records = bundle.get("files")
        if not isinstance(records, list):
            raise RepositoryIntelligenceError("Plan-bundle file inventory is missing.")
        context_staging_dir = transaction_dir / "context"
        journal = {
            "schema": "naos.repository_intelligence.transaction_journal.v1",
            "transaction_id": transaction_id,
            "state": "PREPARED",
            "created_at": utc_now_text(),
            "updated_at": utc_now_text(),
            "plan_sha256": confirmed_digest,
            "bundle_sha256": bundle.get("bundle_sha256"),
            "generation_id": generation_id,
            "generation_content_sha256": control.get("generation_content_sha256"),
            "staging_path": str(staging_dir.relative_to(root)),
            "staging_files": records,
            "staging_device": None,
            "staging_inode": None,
            "context_staging_path": str(context_staging_dir.relative_to(root)),
            "context_staging_device": None,
            "context_staging_inode": None,
            "context_published": False,
            "final_path": str(final_dir.relative_to(root)),
            "generation_published": False,
            "initial_context_absent": context_kind == "absent",
            "active_path": str(active_path.relative_to(root)),
            "active_pending_path": str(
                active_path.with_name(f".{active_path.name}.pending").relative_to(root)
            ),
            "active_before": active_before,
            "active_before_bytes_hex": active_before_bytes.hex() if active_before_bytes is not None else None,
            "active_before_file_sha256": active_before_file_sha256,
            "proposed_active_sha256": None,
            "proposed_active_file_sha256": None,
            "actions": ["copy_exact_bundle", "publish_generation", "write_activation_receipt", "publish_active_pointer", "validate_current"],
            "completed_action_index": -1,
            "last_error": None,
        }
        journal_path, journal = _prepare_transaction_directory(
            transactions_root,
            transaction_dir,
            journal,
        )

        reused_existing = final_dir.exists()
        if reused_existing:
            if not _generation_reuse_authorized(
                transactions_root,
                generation_id=generation_id,
                generation_content_sha256=str(
                    control.get("generation_content_sha256") or ""
                ),
                final_path=str(final_dir.relative_to(root)),
                exclude_transaction_id=transaction_id,
            ):
                raise RepositoryIntelligenceError(
                    "An unreferenced generation appeared without prior operation provenance; it was preserved and refused."
                )
            _validate_promoted_generation(root, final_dir, control=control, bundle=bundle)
        else:
            journal = _write_journal(journal_path, journal, state="APPLYING")
            _copy_exact_bundle(bundle_dir, staging_dir, records)
            _validate_promoted_generation(root, staging_dir, control=control, bundle=bundle)
            staging_metadata = os.lstat(staging_dir)
            journal["staging_device"] = staging_metadata.st_dev
            journal["staging_inode"] = staging_metadata.st_ino
            journal["completed_action_index"] = 0
            journal = _write_journal(journal_path, journal, state="APPLYING")

        if not reused_existing:
            if context_kind == "absent":
                os.mkdir(context_staging_dir, 0o700)
                os.chmod(context_staging_dir, 0o700)
                os.mkdir(context_staging_dir / "generations", 0o700)
                os.chmod(context_staging_dir / "generations", 0o700)
                _fsync_directory(context_staging_dir / "generations")
                _fsync_directory(context_staging_dir)
                _fsync_directory(transaction_dir)
                context_metadata = os.lstat(context_staging_dir)
                journal["context_staging_device"] = context_metadata.st_dev
                journal["context_staging_inode"] = context_metadata.st_ino
                journal = _write_journal(journal_path, journal, state="APPLYING")
                rename_no_replace(
                    staging_dir,
                    context_staging_dir / "generations" / generation_id,
                )
                staging_dir = None
                _fsync_directory(context_staging_dir / "generations")
                try:
                    rename_no_replace(context_staging_dir, context_root)
                except FileExistsError as exc:
                    raise RepositoryIntelligenceError(
                        "Generated context root appeared during atomic publication; it was preserved and refused."
                    ) from exc
                _fsync_directory(context_root.parent)
                journal["context_published"] = True
            else:
                _assert_context_entries(context_root)
                try:
                    rename_no_replace(staging_dir, final_dir)
                except FileExistsError as exc:
                    raise RepositoryIntelligenceError(
                        "Generation destination appeared during atomic publication; it was preserved and refused."
                    ) from exc
                staging_dir = None
                _fsync_directory(generations_root)
            journal["generation_published"] = True
        journal["completed_action_index"] = 1
        journal = _write_journal(journal_path, journal, state="APPLYING")
        promoted = _validate_promoted_generation(root, final_dir, control=control, bundle=bundle)

        repeat = inspect_repository(
            root,
            profile=profile,
            naos_root=naos_root,
            rules_path=rules_path,
            rules_source=rules_source,
            component_mode=str(control.get("component_mode") or "auto"),
            purpose=str(control.get("purpose") or "brownfield-onboarding"),
            allowed_inflight_transaction_id=transaction_id,
        )
        _assert_current_inspection_complete(
            repeat,
            phase="pre-publication revalidation",
        )
        if repeat["effective_source_sha256"] != control.get("effective_source_sha256"):
            raise RepositoryIntelligenceError("Repository source changed before publication; activation was not published.")
        if inspect_scope(root, governed_root=governed_root).plan_gate() != control.get("provenance_gate"):
            raise RepositoryIntelligenceError("Capability provenance changed before publication.")

        manifest = promoted["manifest"]
        manifest_path = final_dir / "manifest.json"
        validation_receipt_path = final_dir / "validation_receipt.json"
        previous_generation_id = (
            active_before.get("control", {}).get("generation_id")
            if isinstance(active_before, dict)
            else None
        )
        reviewer = {
            "required": _profile_gate(profile)["named_review_required"],
            "reviewer_id": reviewer_id,
            "identity_status": "declared_attribution" if reviewer_id else "not_required",
            "authentication_status": "not_claimed",
        }
        activation_control = {
            "transaction_id": transaction_id,
            "plan_sha256": confirmed_digest,
            "bundle_sha256": bundle.get("bundle_sha256"),
            "generation_id": generation_id,
            "generation_content_sha256": control.get("generation_content_sha256"),
            "manifest_file_sha256": sha256_bytes(secure_regular_file_bytes(manifest_path)),
            "manifest_sha256": manifest.get("manifest_sha256"),
            "validation_receipt_file_sha256": sha256_bytes(secure_regular_file_bytes(validation_receipt_path)),
            "validation_receipt_sha256": promoted["validation_receipt"].get("receipt_sha256"),
            "provenance_project_id": scope.project_id,
            "provenance_owner_sha3_512": scope.owner_integrity,
            "provenance_scope_sha3_512": scope.scope_integrity,
            "profile": profile,
            "reviewer": reviewer,
            "preapply_revalidation": True,
            "postcopy_validation": True,
            "previous_generation_id": previous_generation_id,
            "active_pointer_publication": "pending",
        }
        activation_receipt = {
            "schema": ACTIVATION_RECEIPT_SCHEMA,
            "status": "authorized_for_publication",
            "recorded_at": utc_now_text(),
            "receipt_sha256": canonical_sha256(activation_control),
            "control": activation_control,
            "not_claimed": ["reviewer authentication", "source authority", "filesystem-wide atomic visibility"],
        }
        _validate_schema(activation_receipt, ACTIVATION_RECEIPT_SCHEMA)
        activation_receipt_path = transaction_dir / "receipt.json"
        _write_new_bytes(
            activation_receipt_path,
            _json_report_bytes(activation_receipt),
        )
        _fsync_directory(transaction_dir)
        journal["completed_action_index"] = 2
        journal = _write_journal(journal_path, journal, state="VALIDATING")

        pointer_control = {
            "transaction_id": transaction_id,
            "generation_id": generation_id,
            "generation_content_sha256": control.get("generation_content_sha256"),
            "manifest_path": str(manifest_path.relative_to(root)),
            "manifest_file_sha256": activation_control["manifest_file_sha256"],
            "manifest_sha256": manifest.get("manifest_sha256"),
            "validation_receipt_path": str(validation_receipt_path.relative_to(root)),
            "validation_receipt_file_sha256": activation_control["validation_receipt_file_sha256"],
            "validation_receipt_sha256": activation_control["validation_receipt_sha256"],
            "activation_receipt_path": str(activation_receipt_path.relative_to(root)),
            "activation_receipt_file_sha256": sha256_bytes(secure_regular_file_bytes(activation_receipt_path)),
            "activation_receipt_sha256": activation_receipt["receipt_sha256"],
            "plan_sha256": confirmed_digest,
            "bundle_sha256": bundle.get("bundle_sha256"),
            "effective_source_sha256": control.get("effective_source_sha256"),
            "profile": profile,
            "purpose": control.get("purpose"),
            "component_mode": control.get("component_mode"),
            "provenance_project_id": scope.project_id,
            "provenance_owner_sha3_512": scope.owner_integrity,
            "provenance_scope_sha3_512": scope.scope_integrity,
            "ongoing_use_scope": control.get("ongoing_use_scope") or [],
            "previous_generation_id": previous_generation_id,
        }
        proposed_pointer = {
            "schema": ACTIVE_SCHEMA,
            "status": "validated_active",
            "active_sha256": canonical_sha256(pointer_control),
            "control": pointer_control,
            "source_artifacts_remain_authoritative": True,
            "human_review_required": True,
        }
        _validate_schema(proposed_pointer, ACTIVE_SCHEMA)
        proposed_pointer_bytes = _json_report_bytes(proposed_pointer)
        journal["proposed_active_sha256"] = proposed_pointer["active_sha256"]
        journal["proposed_active_file_sha256"] = sha256_bytes(proposed_pointer_bytes)
        journal = _write_journal(journal_path, journal, state="VALIDATING")
        _atomic_write_bytes(active_path, proposed_pointer_bytes)
        journal["completed_action_index"] = 3
        journal = _write_journal(journal_path, journal, state="VALIDATING")
        validation = validate_active_generation(
            root,
            naos_root=naos_root,
            require_current_source=True,
            allow_validating_transaction_id=transaction_id,
        )
        if validation.get("status") != "validated_current":
            raise RepositoryIntelligenceError(
                f"Post-publication validation failed with status={validation.get('status')}."
            )
        journal["completed_action_index"] = 4
        journal = _write_journal(journal_path, journal, state="COMMITTED")
        validation = validate_active_generation(root, naos_root=naos_root, require_current_source=True)
        result = {
            "schema": APPLY_RESULT_SCHEMA,
            "status": "validated_active",
            "transaction_id": transaction_id,
            "generation_id": generation_id,
            "generation_content_sha256": control.get("generation_content_sha256"),
            "plan_sha256": confirmed_digest,
            "bundle_sha256": bundle.get("bundle_sha256"),
            "active_pointer": str(active_path.relative_to(root)),
            "active_sha256": proposed_pointer["active_sha256"],
            "manifest": str(manifest_path.relative_to(root)),
            "manifest_sha256": manifest.get("manifest_sha256"),
            "activation_receipt": str(activation_receipt_path.relative_to(root)),
            "activation_receipt_sha256": activation_receipt["receipt_sha256"],
            "validation": validation,
            "idempotent_reuse": reused_existing,
            "previous_generation_id": previous_generation_id,
            "source_artifacts_modified": [],
            "generated_state_only": True,
            "exact_bundle_bytes_promoted": True,
        }
        _validate_schema(result, APPLY_RESULT_SCHEMA)
        return result
    except Exception as exc:
        if journal is not None and journal_path is not None:
            try:
                if proposed_pointer is not None:
                    before_hex = journal.get("active_before_bytes_hex")
                    before_bytes = bytes.fromhex(before_hex) if isinstance(before_hex, str) else None
                    _restore_active_pointer(
                        context_root / "active.json",
                        active_before_bytes=before_bytes,
                        active_before_file_sha256=journal.get("active_before_file_sha256"),
                        proposed_active_sha256=str(proposed_pointer.get("active_sha256") or ""),
                        proposed_active_file_sha256=journal.get(
                            "proposed_active_file_sha256"
                        ),
                    )
                journal = _cleanup_failed_transaction_state(
                    root, context_root, journal
                )
                journal = _write_journal(journal_path, journal, state="ROLLED_BACK", error=str(exc))
            except Exception as rollback_exc:
                try:
                    _write_journal(
                        journal_path,
                        journal,
                        state="ROLLBACK_INCOMPLETE",
                        error=f"apply={exc}; rollback={rollback_exc}",
                    )
                except Exception as journal_exc:
                    raise RepositoryIntelligenceError(
                        "Apply rollback failed and its terminal journal could not be persisted: "
                        f"apply={exc}; rollback={rollback_exc}; journal={journal_exc}"
                    ) from exc
                raise RepositoryIntelligenceError(
                    f"Apply failed and rollback requires recovery: apply={exc}; rollback={rollback_exc}"
                ) from exc
        raise
    finally:
        _release_lock(lock)


def _lock_observation(lock_path: Path) -> dict[str, Any]:
    return observe_stable_lock(lock_path)


def repository_intelligence_status(root: Path, *, naos_root: str) -> dict[str, Any]:
    context_root = _context_index_root(root, naos_root)
    governed_root = context_root.relative_to(root).as_posix()
    scope = inspect_scope(root, governed_root=governed_root)
    transactions_root = root / TRANSACTIONS_RELATIVE
    transaction_reports: list[dict[str, Any]] = []
    unresolved_count = 0
    if transactions_root.exists():
        try:
            for child in sorted(transactions_root.iterdir(), key=lambda item: item.name):
                preparing_transaction_id = _transaction_id_from_preparing_name(child.name)
                if preparing_transaction_id is not None:
                    unresolved_count += 1
                    child_metadata = os.lstat(child)
                    safe_directory = bool(
                        stat.S_ISDIR(child_metadata.st_mode)
                        and not stat.S_ISLNK(child_metadata.st_mode)
                    )
                    journal_path = child / "journal.json"
                    transaction_reports.append(
                        {
                            "transaction_id": preparing_transaction_id,
                            "state": (
                                "PREPARATION_INCOMPLETE"
                                if safe_directory
                                else "INVALID"
                            ),
                            "journal_path": (
                                str(journal_path.relative_to(root))
                                if safe_directory and journal_path.exists()
                                else None
                            ),
                        }
                    )
                    continue
                journal_path = child / "journal.json"
                try:
                    journal = _load_journal(journal_path)
                    state = str(journal.get("state") or "")
                    if state not in {"COMMITTED", "ROLLED_BACK"}:
                        unresolved_count += 1
                    transaction_reports.append(
                        {
                            "transaction_id": journal.get("transaction_id"),
                            "state": state,
                            "journal_path": str(journal_path.relative_to(root)),
                            "generation_id": journal.get("generation_id"),
                            "last_error": journal.get("last_error"),
                        }
                    )
                except (RepositoryIntelligenceError, OSError, ValueError) as exc:
                    unresolved_count += 1
                    transaction_reports.append(
                        {
                            "transaction_id": child.name,
                            "state": "INVALID",
                            "journal_path": str(journal_path.relative_to(root)),
                            "error": str(exc),
                        }
                    )
        except OSError as exc:
            unresolved_count += 1
            transaction_reports.append({"state": "INVALID", "error": str(exc)})
    active_status: dict[str, Any]
    if unresolved_count:
        active_status = {
            "status": "not_validated_while_recovery_required",
            "active_pointer_present": (context_root / "active.json").exists(),
        }
    else:
        try:
            active_status = validate_active_generation(root, naos_root=naos_root, require_current_source=True)
        except (RepositoryIntelligenceError, ProvenanceError, OSError, ValueError) as exc:
            active_status = {"status": "invalid", "error": str(exc)}
    overall = "recovery_required" if unresolved_count else str(active_status.get("status") or "invalid")
    result = {
        "schema": "naos.repository_intelligence.status.v1",
        "status": overall,
        "project_root": str(root),
        "provenance": scope.plan_gate(),
        "lock": _lock_observation(root / LOCK_RELATIVE),
        "transactions": transaction_reports,
        "unresolved_transaction_count": unresolved_count,
        "active": active_status,
        "source_artifacts_modified": [],
    }
    _validate_schema(result, STATUS_SCHEMA)
    return result


def recover_repository_intelligence(root: Path, *, naos_root: str) -> dict[str, Any]:
    context_root = _context_index_root(root, naos_root)
    governed_root = context_root.relative_to(root).as_posix()
    scope = inspect_scope(root, governed_root=governed_root)
    if not scope.activation_eligible:
        raise RepositoryIntelligenceError(f"Recovery requires valid capability provenance: {scope.refusal}")
    lock_path = root / LOCK_RELATIVE
    lock = _acquire_lock(lock_path, "recovery")
    recovered: list[dict[str, Any]] = []
    try:
        transactions_root = root / TRANSACTIONS_RELATIVE
        recovered.extend(_normalize_preparing_transactions(transactions_root))
        unresolved = _unresolved_journals(transactions_root)
        incomplete = False
        for journal_path, journal in unresolved:
            transaction_id = str(journal.get("transaction_id") or "")
            staging_expected = (
                journal_path.parent / "staging"
            ).relative_to(root).as_posix()
            if journal.get("staging_path") != staging_expected:
                raise RepositoryIntelligenceError(
                    f"Transaction {transaction_id} has an invalid staging path; recovery refused."
                )
            active_expected = f"{governed_root}/active.json"
            if journal.get("active_path") != active_expected:
                raise RepositoryIntelligenceError(
                    f"Transaction {transaction_id} has an invalid active path; recovery refused."
                )
            try:
                proposed = journal.get("proposed_active_sha256")
                active_before_hex = journal.get("active_before_bytes_hex")
                active_before_bytes = (
                    bytes.fromhex(active_before_hex) if isinstance(active_before_hex, str) else None
                )
                if active_before_bytes is not None and sha256_bytes(active_before_bytes) != journal.get(
                    "active_before_file_sha256"
                ):
                    raise RepositoryIntelligenceError(
                        f"Transaction {transaction_id} prior-pointer evidence is invalid."
                    )
                active_path = context_root / "active.json"
                if isinstance(proposed, str):
                    _restore_active_pointer(
                        active_path,
                        active_before_bytes=active_before_bytes,
                        active_before_file_sha256=journal.get("active_before_file_sha256"),
                        proposed_active_sha256=proposed,
                        proposed_active_file_sha256=journal.get(
                            "proposed_active_file_sha256"
                        ),
                    )
                else:
                    live_bytes = secure_regular_file_bytes(active_path) if active_path.exists() else None
                    live_digest = sha256_bytes(live_bytes) if live_bytes is not None else None
                    if live_digest != journal.get("active_before_file_sha256"):
                        raise RepositoryIntelligenceError(
                            f"Transaction {transaction_id} active pointer changed before publication."
                        )
                journal = _cleanup_failed_transaction_state(
                    root, context_root, journal
                )
                journal = _write_journal(
                    journal_path,
                    journal,
                    state="ROLLED_BACK",
                    error=journal.get("last_error") or "Recovered by restoring the prior active-pointer state.",
                )
            except Exception as recovery_exc:
                incomplete = True
                journal = _write_journal(
                    journal_path,
                    journal,
                    state="ROLLBACK_INCOMPLETE",
                    error=str(recovery_exc),
                )
            recovered.append(
                {
                    "transaction_id": transaction_id,
                    "state": journal.get("state"),
                    "journal_path": str(journal_path.relative_to(root)),
                    "unreferenced_generation_preserved": bool(
                        safe_path_under(
                            root,
                            str(journal.get("final_path") or ""),
                            field="repository_intelligence_recovery_generation",
                        ).exists()
                    ),
                }
            )
        result = {
            "schema": "naos.repository_intelligence.recovery_result.v1",
            "status": (
                "recovery_incomplete"
                if incomplete
                else "recovered"
                if recovered
                else "nothing_to_recover"
            ),
            "project_root": str(root),
            "recovered_transactions": recovered,
            "source_artifacts_modified": [],
        }
        _validate_schema(result, RECOVERY_RESULT_SCHEMA)
        return result
    finally:
        _release_lock(lock)


def _validate_file_records(generation_dir: Path, records: Iterable[dict[str, Any]]) -> None:
    allowed = {
        "inventory.json",
        "repository_intelligence_rules.yaml",
        "local_context_index.sqlite",
        "context.graphml",
        "validation_receipt.json",
        "manifest.json",
        "activation_receipt.json",
    }
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise RepositoryIntelligenceError("Generation file record must be an object.")
        name = str(record.get("path") or "")
        if name not in allowed or Path(name).name != name or name in seen:
            raise RepositoryIntelligenceError(f"Generation contains an invalid file record: {name!r}")
        seen.add(name)
        path = generation_dir / name
        observed = _file_record(path)
        if observed.get("sha256") != record.get("sha256") or observed.get("size_bytes") != record.get("size_bytes"):
            raise RepositoryIntelligenceError(f"Generation file integrity mismatch: {path}")


def validate_active_generation(
    root: Path,
    *,
    naos_root: str,
    require_current_source: bool,
    allow_validating_transaction_id: str | None = None,
) -> dict[str, Any]:
    context_root = _context_index_root(root, naos_root)
    active_path = context_root / "active.json"
    if not active_path.exists():
        report = {"schema": CONTEXT_SCHEMA, "status": "not_configured", "project_root": str(root)}
        _validate_schema(report, CONTEXT_SCHEMA)
        return report
    active = _strict_json_file(active_path)
    _validate_schema(active, ACTIVE_SCHEMA)
    pointer_control = active.get("control")
    if not isinstance(pointer_control, dict) or canonical_sha256(pointer_control) != active.get("active_sha256"):
        raise RepositoryIntelligenceError("Active pointer digest is invalid.")

    governed_root = context_root.relative_to(root).as_posix()
    scope = inspect_scope(root, governed_root=governed_root)
    if not scope.activation_eligible:
        raise RepositoryIntelligenceError(f"Active generation lacks valid capability provenance: {scope.refusal}")
    provenance_expected = {
        "provenance_project_id": scope.project_id,
        "provenance_owner_sha3_512": scope.owner_integrity,
        "provenance_scope_sha3_512": scope.scope_integrity,
    }
    for field, expected in provenance_expected.items():
        if pointer_control.get(field) != expected:
            raise RepositoryIntelligenceError(f"Active pointer {field} binding is invalid.")

    generation_id = str(pointer_control.get("generation_id") or "")
    if not re.fullmatch(r"RI-[0-9a-f]{24}", generation_id):
        raise RepositoryIntelligenceError("Active generation identity is invalid.")
    generation_dir = context_root / "generations" / generation_id
    expected_manifest_path = generation_dir / "manifest.json"
    manifest_relative = str(pointer_control.get("manifest_path") or "")
    manifest_path = safe_path_under(root, manifest_relative, field="repository_intelligence_manifest")
    if manifest_path != expected_manifest_path:
        raise RepositoryIntelligenceError("Active manifest path does not match its generation identity.")
    manifest_file = secure_regular_file_bytes(manifest_path)
    if sha256_bytes(manifest_file) != pointer_control.get("manifest_file_sha256"):
        raise RepositoryIntelligenceError("Active manifest file digest is invalid.")
    manifest = loads_strict_json(manifest_file)
    if not isinstance(manifest, dict):
        raise RepositoryIntelligenceError("Active manifest schema is invalid.")
    _validate_schema(manifest, MANIFEST_SCHEMA)
    manifest_control = manifest.get("control")
    if not isinstance(manifest_control, dict) or canonical_sha256(manifest_control) != manifest.get("manifest_sha256"):
        raise RepositoryIntelligenceError("Active manifest control digest is invalid.")
    for field in (
        "generation_id",
        "generation_content_sha256",
        "effective_source_sha256",
        "profile",
        "purpose",
        "component_mode",
    ):
        if manifest_control.get(field) != pointer_control.get(field):
            raise RepositoryIntelligenceError(f"Active manifest {field} binding is invalid.")
    if manifest.get("manifest_sha256") != pointer_control.get("manifest_sha256"):
        raise RepositoryIntelligenceError("Active manifest content digest is not pointer-bound.")
    if manifest_control.get("project_root") != str(root):
        raise RepositoryIntelligenceError("Active manifest project root is invalid.")
    if manifest_control.get("runtime") != runtime_probe():
        raise RepositoryIntelligenceError("Active generation runtime tuple or exact component identity changed.")
    if manifest_control.get("implementation") != _implementation_identity():
        raise RepositoryIntelligenceError("Active generation implementation identity changed.")
    expected_gate = scope.plan_gate()
    if manifest_control.get("provenance_gate") != expected_gate:
        raise RepositoryIntelligenceError("Active manifest provenance binding is invalid.")

    manifest_records = manifest_control.get("files")
    if not isinstance(manifest_records, list):
        raise RepositoryIntelligenceError("Active manifest file inventory is missing.")
    _validate_file_records(generation_dir, manifest_records)
    actual_names = sorted(child.name for child in generation_dir.iterdir())
    expected_names = sorted(["manifest.json", *(str(item.get("path") or "") for item in manifest_records)])
    if actual_names != expected_names:
        raise RepositoryIntelligenceError("Active generation contains missing or unrecorded entries.")
    for child in generation_dir.iterdir():
        metadata = os.lstat(child)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RepositoryIntelligenceError(f"Active generation contains an unsafe entry: {child}")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RepositoryIntelligenceError(f"Active generation file mode is not 0600: {child}")

    validation_receipt_path = generation_dir / "validation_receipt.json"
    if str(validation_receipt_path.relative_to(root)) != pointer_control.get("validation_receipt_path"):
        raise RepositoryIntelligenceError("Active validation-receipt path is invalid.")
    validation_receipt_bytes = secure_regular_file_bytes(validation_receipt_path)
    if sha256_bytes(validation_receipt_bytes) != pointer_control.get("validation_receipt_file_sha256"):
        raise RepositoryIntelligenceError("Active validation-receipt file digest is invalid.")
    validation_receipt = loads_strict_json(validation_receipt_bytes)
    if not isinstance(validation_receipt, dict):
        raise RepositoryIntelligenceError("Active validation receipt must contain an object.")
    _validate_schema(validation_receipt, RECEIPT_SCHEMA)
    validation_control = validation_receipt.get("control")
    if (
        validation_receipt.get("status") != "validated_generation"
        or not isinstance(validation_control, dict)
        or canonical_sha256(validation_control) != validation_receipt.get("receipt_sha256")
        or validation_receipt.get("receipt_sha256") != pointer_control.get("validation_receipt_sha256")
        or validation_receipt.get("receipt_sha256") != manifest_control.get("validation_receipt_sha256")
    ):
        raise RepositoryIntelligenceError("Active validation receipt is invalid.")

    transaction_id = str(pointer_control.get("transaction_id") or "")
    transaction_dir = root / TRANSACTIONS_RELATIVE / transaction_id
    expected_activation_path = transaction_dir / "receipt.json"
    activation_relative = str(pointer_control.get("activation_receipt_path") or "")
    activation_path = safe_path_under(root, activation_relative, field="repository_intelligence_activation_receipt")
    if activation_path != expected_activation_path:
        raise RepositoryIntelligenceError("Active activation-receipt path is invalid.")
    activation_bytes = secure_regular_file_bytes(activation_path)
    if sha256_bytes(activation_bytes) != pointer_control.get("activation_receipt_file_sha256"):
        raise RepositoryIntelligenceError("Active activation-receipt file digest is invalid.")
    activation = loads_strict_json(activation_bytes)
    if not isinstance(activation, dict):
        raise RepositoryIntelligenceError("Active activation receipt must contain an object.")
    _validate_schema(activation, ACTIVATION_RECEIPT_SCHEMA)
    activation_control = activation.get("control")
    if (
        not isinstance(activation_control, dict)
        or canonical_sha256(activation_control) != activation.get("receipt_sha256")
        or activation.get("receipt_sha256") != pointer_control.get("activation_receipt_sha256")
    ):
        raise RepositoryIntelligenceError("Active activation receipt digest is invalid.")
    activation_bindings = {
        "transaction_id": transaction_id,
        "plan_sha256": pointer_control.get("plan_sha256"),
        "bundle_sha256": pointer_control.get("bundle_sha256"),
        "generation_id": generation_id,
        "generation_content_sha256": pointer_control.get("generation_content_sha256"),
        "manifest_file_sha256": pointer_control.get("manifest_file_sha256"),
        "manifest_sha256": pointer_control.get("manifest_sha256"),
        "validation_receipt_file_sha256": pointer_control.get("validation_receipt_file_sha256"),
        "validation_receipt_sha256": pointer_control.get("validation_receipt_sha256"),
        "provenance_project_id": scope.project_id,
        "provenance_owner_sha3_512": scope.owner_integrity,
        "provenance_scope_sha3_512": scope.scope_integrity,
        "profile": pointer_control.get("profile"),
        "previous_generation_id": pointer_control.get("previous_generation_id"),
    }
    for field, expected in activation_bindings.items():
        if activation_control.get(field) != expected:
            raise RepositoryIntelligenceError(f"Activation receipt {field} binding is invalid.")
    journal = _load_journal(transaction_dir / "journal.json")
    journal_state = str(journal.get("state") or "")
    validating_allowed = (
        allow_validating_transaction_id == transaction_id and journal_state == "VALIDATING"
    )
    if journal_state != "COMMITTED" and not validating_allowed:
        raise RepositoryIntelligenceError(
            f"Active pointer references a non-committed transaction: {journal.get('state')}."
        )
    for field in ("transaction_id", "plan_sha256", "bundle_sha256", "generation_id", "generation_content_sha256"):
        if journal.get(field) != (
            pointer_control.get(field) if field != "transaction_id" else transaction_id
        ):
            raise RepositoryIntelligenceError(f"Committed journal {field} binding is invalid.")

    inventory = _strict_json_file(generation_dir / "inventory.json")
    _validate_schema(inventory, INVENTORY_SCHEMA)
    content_binding = inventory.get("sqlite_content_binding")
    if not isinstance(content_binding, dict):
        raise RepositoryIntelligenceError("Active SQLite content binding is missing.")
    sqlite_validation = _validate_sqlite(
        generation_dir / "local_context_index.sqlite",
        str(manifest_control.get("effective_source_sha256") or ""),
        content_binding,
    )
    graph_selected = bool(
        (manifest_control.get("components") or {}).get("networkx_graphml", {}).get("selected")
    )
    if graph_selected:
        graph_validation = _validate_graphml_file(
            generation_dir / "context.graphml",
            expected_source_sha256=str(manifest_control.get("effective_source_sha256") or ""),
            expected_model_sha256=str(manifest_control.get("graph_model_sha256") or ""),
        )
    else:
        if (generation_dir / "context.graphml").exists():
            raise RepositoryIntelligenceError("Unselected GraphML is present in the active generation.")
        graph_validation = {"status": "not_selected"}
    source_status = "not_checked"
    if require_current_source:
        rules_path = generation_dir / str(
            manifest_control.get("rules_snapshot") or "repository_intelligence_rules.yaml"
        )
        rules_source = "generation_snapshot"
        inspection = inspect_repository(
            root,
            profile=str(manifest_control.get("profile") or "quickstart"),
            naos_root=naos_root,
            rules_path=rules_path,
            rules_source=rules_source,
            component_mode=str(manifest_control.get("component_mode") or "auto"),
            purpose=str(manifest_control.get("purpose") or "brownfield-onboarding"),
        )
        current_blockers = _blocking_finding_ids(inspection)
        if (
            inspection["effective_source_sha256"]
            != manifest_control.get("effective_source_sha256")
            or current_blockers
            or inspection.get("inventory_truncated")
            or inspection.get("relationships_truncated")
        ):
            blocker_suffix = (
                f" Current blocking findings: {', '.join(current_blockers)}."
                if current_blockers
                else ""
            )
            report = {
                "schema": CONTEXT_SCHEMA,
                "status": "stale",
                "project_root": str(root),
                "generation_id": manifest_control.get("generation_id"),
                "effective_source_sha256": manifest_control.get("effective_source_sha256"),
                "current_source_sha256": inspection["effective_source_sha256"],
                "candidate_references": [],
                "finding": (
                    "Active repository intelligence is stale or its current source coverage is "
                    f"incomplete; prepare and confirm a refresh plan.{blocker_suffix}"
                ),
            }
            _validate_schema(report, CONTEXT_SCHEMA)
            return report
        graph_model = {
            "directed": True,
            "multigraph": True,
            "nodes": inspection["nodes"],
            "relationships": inspection["relationships"],
        }
        if canonical_sha256(graph_model) != manifest_control.get("graph_model_sha256"):
            raise RepositoryIntelligenceError("Current source relationship model does not match the active generation.")
        source_status = "current"
    report = {
        "schema": CONTEXT_SCHEMA,
        "status": "validated_current" if source_status == "current" else "validated",
        "project_root": str(root),
        "generation": {
            "generation_id": manifest_control.get("generation_id"),
            "generation_content_sha256": manifest_control.get("generation_content_sha256"),
            "manifest_path": str(manifest_path.relative_to(root)),
            "manifest_file_sha256": pointer_control.get("manifest_file_sha256"),
            "manifest_sha256": manifest.get("manifest_sha256"),
            "validation_receipt_path": str((generation_dir / "validation_receipt.json").relative_to(root)),
            "validation_receipt_file_sha256": pointer_control.get(
                "validation_receipt_file_sha256"
            ),
            "validation_receipt_sha256": manifest_control.get("validation_receipt_sha256"),
            "activation_receipt_path": str(activation_path.relative_to(root)),
            "activation_receipt_file_sha256": pointer_control.get(
                "activation_receipt_file_sha256"
            ),
            "activation_receipt_sha256": activation.get("receipt_sha256"),
            "transaction_id": transaction_id,
            "plan_sha256": pointer_control.get("plan_sha256"),
            "bundle_sha256": pointer_control.get("bundle_sha256"),
            "profile": manifest_control.get("profile"),
            "purpose": manifest_control.get("purpose"),
            "component_mode": manifest_control.get("component_mode"),
            "validation_status": "passed",
            "effective_source_sha256": manifest_control.get("effective_source_sha256"),
            "source_status": source_status,
        },
        "usage_scope": manifest_control.get("ongoing_use_scope") or [],
        "components": manifest_control.get("components") or {},
        "coverage": manifest_control.get("coverage") or {},
        "sqlite_validation": sqlite_validation,
        "networkx_graphml_validation": graph_validation,
        "provenance_validation": {
            "status": "valid",
            "project_id": scope.project_id,
            "owner_integrity_sha3_512": scope.owner_integrity,
            "scope_integrity_sha3_512": scope.scope_integrity,
        },
        "transaction": {"transaction_id": transaction_id, "state": journal.get("state")},
        "candidate_reference_count": len(inventory.get("source_inventory") or []),
        "candidate_only": True,
        "source_artifacts_remain_authoritative": True,
        "limitations": manifest.get("limitations") or [],
        "not_claimed": manifest.get("not_claimed") or [],
    }
    _validate_schema(report, CONTEXT_SCHEMA)
    return report


def _active_generation_paths(root: Path, naos_root: str) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    context = validate_active_generation(root, naos_root=naos_root, require_current_source=True)
    if context.get("status") != "validated_current":
        raise RepositoryIntelligenceError(
            f"A validated current repository-intelligence generation is required; status={context.get('status')}."
        )
    manifest_path = root / str(context["generation"]["manifest_path"])
    manifest = _strict_json_file(manifest_path)
    return context, manifest_path.parent, manifest


ACTIVE_GENERATION_BINDING_FIELDS = (
    "generation_id",
    "generation_content_sha256",
    "manifest_file_sha256",
    "manifest_sha256",
    "validation_receipt_file_sha256",
    "validation_receipt_sha256",
    "activation_receipt_file_sha256",
    "activation_receipt_sha256",
    "effective_source_sha256",
    "transaction_id",
    "profile",
    "purpose",
    "component_mode",
)


def repository_intelligence_binding(context: dict[str, Any]) -> dict[str, Any]:
    """Return the complete immutable binding for a validated active generation."""

    if context.get("status") != "validated_current":
        raise RepositoryIntelligenceError(
            "A validated current repository-intelligence context is required to create a consumer binding."
        )
    generation = context.get("generation")
    if not isinstance(generation, dict):
        raise RepositoryIntelligenceError("Validated repository intelligence lacks generation metadata.")
    binding = {field: generation.get(field) for field in ACTIVE_GENERATION_BINDING_FIELDS}
    if any(value in {None, ""} for value in binding.values()):
        raise RepositoryIntelligenceError("Validated repository intelligence has an incomplete generation binding.")
    return binding


def assert_repository_intelligence_binding_unchanged(
    opening: dict[str, Any],
    closing: dict[str, Any],
) -> None:
    """Refuse consumption when any immutable active-generation binding changed."""

    for field in ACTIVE_GENERATION_BINDING_FIELDS:
        if opening.get(field) != closing.get(field):
            raise RepositoryIntelligenceError(
                f"Active repository-intelligence binding changed during consumption: {field}."
            )


def read_active_repository_intelligence_snapshot(
    root: Path,
    *,
    naos_root: str,
    required_usage_scopes: list[str] | tuple[str, ...] = (),
    evidence_paths: list[str] | tuple[str, ...] = (),
    families: list[str] | tuple[str, ...] = (),
    retrieval_queries: list[str] | tuple[str, ...] = (),
    limit: int = 500,
) -> dict[str, Any]:
    """Read a bounded, source-revalidated snapshot for deterministic consumers.

    The active generation remains candidate navigation evidence. Current repository
    source remains authoritative, and this function never writes to the target.
    """

    if limit < 1 or limit > 2_000:
        raise RepositoryIntelligenceError("Repository-intelligence snapshot limit must be between 1 and 2000.")
    normalized_queries = list(
        dict.fromkeys(
            str(item).strip()[:120]
            for item in retrieval_queries
            if str(item).strip()
        )
    )
    if len(normalized_queries) > 12:
        raise RepositoryIntelligenceError(
            "Repository-intelligence onboarding retrieval accepts at most 12 queries."
        )
    status_report = repository_intelligence_status(root, naos_root=naos_root)
    if status_report.get("status") != "validated_current":
        raise RepositoryIntelligenceError(
            "A validated current repository-intelligence generation is required; "
            f"status={status_report.get('status')}."
        )
    context, generation_dir, _manifest = _active_generation_paths(root, naos_root)
    opening_binding = repository_intelligence_binding(context)
    authorized_scopes = {
        str(item) for item in (context.get("usage_scope") or []) if str(item).strip()
    }
    required_scopes = sorted({str(item) for item in required_usage_scopes if str(item).strip()})
    missing_scopes = sorted(set(required_scopes) - authorized_scopes)
    if missing_scopes:
        raise RepositoryIntelligenceError(
            "Active repository intelligence is not authorized for required usage scopes: "
            + ", ".join(missing_scopes)
        )

    inventory = _strict_json_file(generation_dir / "inventory.json")
    _validate_schema(inventory, INVENTORY_SCHEMA)
    normalized_paths = {
        Path(str(item).removeprefix("./")).as_posix()
        for item in evidence_paths
        if str(item).strip()
    }
    selected_families = {str(item) for item in families if str(item).strip()}
    source_inventory = inventory.get("source_inventory") or []
    selected_sources: list[dict[str, Any]] = []
    for record in source_inventory:
        if not isinstance(record, dict):
            raise RepositoryIntelligenceError("Active repository intelligence contains an invalid source record.")
        relative = str(record.get("path") or "")
        if normalized_paths and relative not in normalized_paths:
            continue
        if selected_families and str(record.get("family_id") or "") not in selected_families:
            continue
        selected_sources.append(dict(record))
        if len(selected_sources) >= limit:
            break

    candidates = [
        {
            "lane": "validated_inventory",
            "source_path": str(item.get("path") or ""),
            "source_sha256": item.get("source_sha256"),
            "source_kind": item.get("artifact_type"),
            "family_id": item.get("family_id"),
            "authority_level": item.get("authority_level"),
            "retrieval": {
                "match_reason": "validated_active_inventory",
                "score_type": None,
                "score": None,
            },
            "candidate_only": True,
            "human_review_required": True,
        }
        for item in selected_sources
    ]
    selected_paths = {str(item.get("source_path") or "") for item in candidates}
    relationships = [
        dict(item)
        for item in (inventory.get("relationships") or [])
        if isinstance(item, dict)
        and (
            not selected_paths
            or str(item.get("source_path") or "") in selected_paths
            or str(item.get("target_path") or "") in selected_paths
        )
    ][:limit]
    exclusions = [
        dict(item)
        for item in (inventory.get("excluded_artifacts") or [])
        if isinstance(item, dict)
    ][:limit]
    retrieval = _bounded_onboarding_retrieval(
        generation_dir,
        _manifest,
        normalized_queries,
        source_inventory,
        limit=min(limit, 100),
    )
    retrieval_candidates = retrieval["candidates"]
    source_revalidation = _revalidate_candidate_sources(
        root,
        [*candidates, *retrieval_candidates],
    )

    closing_context = validate_active_generation(
        root,
        naos_root=naos_root,
        require_current_source=True,
    )
    closing_binding = repository_intelligence_binding(closing_context)
    assert_repository_intelligence_binding_unchanged(opening_binding, closing_binding)
    return {
        "status": "validated_current_snapshot",
        "opening_generation": opening_binding,
        "closing_generation": closing_binding,
        "binding_unchanged": True,
        "required_usage_scopes": required_scopes,
        "authorized_usage_scopes": sorted(authorized_scopes),
        "usage_scope_satisfied": True,
        "components": context.get("components") or {},
        "coverage": context.get("coverage") or {},
        "candidates": candidates,
        "retrieval_candidates": retrieval_candidates,
        "retrieval": retrieval["summary"],
        "relationships": relationships,
        "excluded_artifacts": exclusions,
        "source_revalidation": source_revalidation,
        "candidate_only": True,
        "source_artifacts_remain_authoritative": True,
        "limitations": context.get("limitations") or [],
        "not_claimed": context.get("not_claimed") or [],
    }


def _fts_candidates(connection: sqlite3.Connection, query: str, limit: int) -> list[dict[str, Any]]:
    sanitized = sanitize_fts_query(query)
    if not sanitized:
        return []
    try:
        rows = connection.execute(
            """
            SELECT f.path, a.source_hash, a.artifact_type, a.authority_level,
                   f.section_heading, bm25(artifact_chunks_fts) AS score
            FROM artifact_chunks_fts AS f
            JOIN artifacts AS a ON a.artifact_id = f.artifact_id
            WHERE artifact_chunks_fts MATCH ?
            ORDER BY score, f.path, f.chunk_id
            LIMIT ?
            """,
            (sanitized, limit),
        ).fetchall()
    except sqlite3.Error as exc:
        raise RepositoryIntelligenceError(f"Bounded literal FTS query failed: {exc}") from exc
    return [
        {
            "lane": "fts",
            "source_path": row[0],
            "source_sha256": row[1],
            "source_kind": row[2],
            "authority_level": row[3],
            "section_heading": row[4],
            "retrieval": {"match_reason": "fts5_keyword_match", "score_type": "bm25", "score": row[5]},
            "candidate_only": True,
            "human_review_required": True,
        }
        for row in rows
    ]


def _exact_candidate(connection: sqlite3.Connection, path: str) -> list[dict[str, Any]]:
    row = connection.execute(
        "SELECT path, source_hash, artifact_type, authority_level FROM artifacts WHERE path = ?",
        (path.removeprefix("./"),),
    ).fetchone()
    if not row:
        return []
    return [
        {
            "lane": "exact",
            "source_path": row[0],
            "source_sha256": row[1],
            "source_kind": row[2],
            "authority_level": row[3],
            "retrieval": {"match_reason": "exact_path", "score_type": None, "score": None},
            "candidate_only": True,
            "human_review_required": True,
        }
    ]


def _reference_candidates(
    connection: sqlite3.Connection,
    *,
    task: str | None,
    spec: str | None,
    capability: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    selectors: list[tuple[str, str]] = []
    if task:
        selectors.append(("task_ref", task.upper()))
    if spec:
        selectors.append(("spec_ref", spec.removeprefix("./")))
    if capability:
        selectors.append(("capability_ref", capability.upper()))
    if not selectors:
        return []
    clauses = " OR ".join("(r.relationship_type = ? AND r.reference_id = ?)" for _ in selectors)
    parameters: list[Any] = []
    for relationship_type, reference_id in selectors:
        parameters.extend((relationship_type, reference_id))
    parameters.append(limit)
    rows = connection.execute(
        f"""
        SELECT r.relationship_id, r.relationship_type, r.reference_id,
               r.source_path, r.source_sha256, r.evidence_sha256, r.evidence_line,
               r.provenance, r.confidence,
               a.artifact_type, a.authority_level
        FROM repository_relationships AS r
        JOIN artifacts AS a ON a.path = r.source_path
        WHERE {clauses}
        ORDER BY r.relationship_type, r.reference_id, r.source_path, r.relationship_id
        LIMIT ?
        """,
        tuple(parameters),
    ).fetchall()
    return [
        {
            "lane": "reference",
            "source_path": row[3],
            "source_sha256": row[4],
            "source_kind": row[9],
            "authority_level": row[10],
            "retrieval": {
                "match_reason": "sqlite_explicit_source_reference",
                "score_type": None,
                "score": None,
                "relationship_id": row[0],
                "relationship_type": row[1],
                "reference_id": row[2],
                "evidence_sha256": row[5],
                "evidence_line": row[6],
                "provenance": row[7],
                "confidence": row[8],
            },
            "candidate_only": True,
            "human_review_required": True,
        }
        for row in rows
    ]


def _load_validated_graph(
    generation_dir: Path,
    manifest: dict[str, Any],
    connection: sqlite3.Connection,
) -> Any | None:
    manifest_control = manifest.get("control") if isinstance(manifest.get("control"), dict) else {}
    selected = bool((manifest_control.get("components") or {}).get("networkx_graphml", {}).get("selected"))
    graph_path = generation_dir / "context.graphml"
    if not selected:
        if graph_path.exists():
            raise RepositoryIntelligenceError("Active generation contains unselected GraphML.")
        return None
    _validate_graphml_file(
        graph_path,
        expected_source_sha256=str(manifest_control.get("effective_source_sha256") or ""),
        expected_model_sha256=str(manifest_control.get("graph_model_sha256") or ""),
    )
    try:
        import networkx as nx
    except ImportError as exc:
        raise RepositoryIntelligenceError("NetworkX is required to query selected GraphML.") from exc
    graph = nx.read_graphml(io.BytesIO(secure_regular_file_bytes(graph_path)), force_multigraph=True)
    database_edges = {
        str(row[0]): {
            "source_node": row[1],
            "target_node": row[2],
            "relationship_type": row[3],
            "source_path": row[4] or "",
            "target_path": row[5] or "",
            "source_sha256": row[6] or "",
            "target_sha256": row[7] or "",
            "evidence_sha256": row[8] or "",
            "evidence_line": row[9] if row[9] is not None else "",
            "reference_id": row[10] or "",
            "provenance": row[11],
            "confidence": row[12],
            "candidate_only": True,
        }
        for row in connection.execute(
            """
            SELECT relationship_id, source_node, target_node, relationship_type,
                   source_path, target_path, source_sha256, target_sha256,
                   evidence_sha256, evidence_line, reference_id, provenance,
                   confidence
            FROM repository_relationships
            ORDER BY relationship_id
            """
        )
    }
    graph_edges: dict[str, dict[str, Any]] = {}
    for source, target, edge_id, attributes in graph.edges(keys=True, data=True):
        relationship_id = str(attributes.get("relationship_id") or edge_id)
        if relationship_id in graph_edges:
            raise RepositoryIntelligenceError(f"GraphML contains duplicate relationship ID: {relationship_id}")
        graph_edges[relationship_id] = {
            "source_node": str(source),
            "target_node": str(target),
            "relationship_type": attributes.get("relationship_type"),
            "source_path": attributes.get("source_path") or "",
            "target_path": attributes.get("target_path") or "",
            "source_sha256": attributes.get("source_sha256") or "",
            "target_sha256": attributes.get("target_sha256") or "",
            "evidence_sha256": attributes.get("evidence_sha256") or "",
            "evidence_line": attributes.get("evidence_line") if attributes.get("evidence_line") not in {None, ""} else "",
            "reference_id": attributes.get("reference_id") or "",
            "provenance": attributes.get("provenance"),
            "confidence": attributes.get("confidence"),
            "candidate_only": attributes.get("candidate_only") is True,
        }
    if graph_edges != database_edges:
        raise RepositoryIntelligenceError("GraphML relationships do not match the source-bound SQLite relationship inventory.")
    artifact_nodes = {
        f"artifact:{row[0]}": (row[1], row[2], row[3], row[4])
        for row in connection.execute(
            "SELECT artifact_id, path, source_hash, artifact_type, authority_level FROM artifacts"
        )
    }
    for node_id, (path, source_hash, artifact_type, authority_level) in artifact_nodes.items():
        if node_id not in graph:
            raise RepositoryIntelligenceError(f"GraphML is missing artifact node: {node_id}")
        attributes = graph.nodes[node_id]
        if (
            attributes.get("path") != path
            or attributes.get("source_sha256") != source_hash
            or attributes.get("artifact_type") != artifact_type
            or attributes.get("authority_level") != authority_level
        ):
            raise RepositoryIntelligenceError(f"GraphML artifact node does not match SQLite: {node_id}")
    allowed_reference_nodes = {
        str(item["target_node"])
        for item in database_edges.values()
        if not str(item["target_node"]).startswith("artifact:")
    }
    if set(graph.nodes) != set(artifact_nodes) | allowed_reference_nodes:
        raise RepositoryIntelligenceError("GraphML contains missing or unrecorded nodes.")
    return graph


def _graph_candidates(
    graph: Any | None,
    *,
    path: str | None,
    task: str | None,
    spec: str | None,
    capability: str | None,
    depth: int,
    limit: int,
) -> list[dict[str, Any]]:
    if graph is None:
        return []
    seeds_supplied = sum(value is not None for value in (path, task, spec, capability))
    if seeds_supplied > 1:
        raise RepositoryIntelligenceError("Graph navigation accepts exactly one of --path, --task, --spec, or --capability.")
    seed: str | None = None
    if path:
        normalized = path.removeprefix("./")
        seed = next((str(node) for node, data in graph.nodes(data=True) if data.get("path") == normalized), None)
    elif task:
        seed = f"task:{task.upper()}"
    elif spec:
        seed = f"spec:{spec}"
    elif capability:
        seed = f"capability:{capability.upper()}"
    if seed is None or seed not in graph:
        return []
    adjacency: dict[str, list[tuple[str, str, str, str, dict[str, Any]]]] = {}
    for observed_source, observed_target, edge_id, attributes in graph.edges(keys=True, data=True):
        relationship_id = str(attributes.get("relationship_id") or edge_id)
        adjacency.setdefault(str(observed_source), []).append(
            (str(observed_target), relationship_id, "forward", str(observed_source), dict(attributes))
        )
        adjacency.setdefault(str(observed_target), []).append(
            (str(observed_source), relationship_id, "reverse", str(observed_source), dict(attributes))
        )
    for node in adjacency:
        adjacency[node].sort(key=lambda item: (item[0], item[1], item[2]))
    queue: deque[tuple[str, list[str], list[dict[str, Any]]]] = deque([(seed, [seed], [])])
    seen_distance = {seed: 0}
    candidates: list[dict[str, Any]] = []
    while queue and len(candidates) < limit:
        node_id, node_path, edge_path = queue.popleft()
        distance = len(edge_path)
        if node_id != seed and str(node_id).startswith("artifact:"):
            data = graph.nodes[node_id]
            source_path = data.get("path") or None
            source_sha256 = data.get("source_sha256") or None
            if not source_path or not source_sha256:
                raise RepositoryIntelligenceError(
                    f"GraphML artifact node lacks its own source identity: {node_id}"
                )
            candidates.append(
                {
                    "lane": "graph",
                    "node_id": str(node_id),
                    "source_path": source_path,
                    "source_sha256": source_sha256,
                    "source_kind": data.get("artifact_type") or data.get("node_type"),
                    "authority_level": data.get("authority_level") or None,
                    "retrieval": {
                        "match_reason": "bounded_networkx_navigation",
                        "score_type": "hop_distance",
                        "score": distance,
                        "direction_policy": "bidirectional_navigation_over_directed_observations",
                        "seed_node": seed,
                        "node_path": node_path,
                        "edge_path": edge_path,
                    },
                    "candidate_only": True,
                    "human_review_required": True,
                }
            )
        if distance >= depth:
            continue
        for neighbor, relationship_id, direction, observed_source, attributes in adjacency.get(node_id, []):
            next_distance = distance + 1
            if neighbor in seen_distance and seen_distance[neighbor] <= next_distance:
                continue
            seen_distance[neighbor] = next_distance
            observed_target = str(attributes.get("target_node") or "")
            if not observed_target:
                observed_target = neighbor if direction == "forward" else node_id
            step = {
                "ordinal": next_distance,
                "relationship_id": relationship_id,
                "relationship_type": attributes.get("relationship_type"),
                "traversal_from": node_id,
                "traversal_to": neighbor,
                "observed_source_node": observed_source,
                "observed_target_node": observed_target,
                "traversal_direction": direction,
                "evidence": {
                    "path": attributes.get("source_path") or None,
                    "sha256": attributes.get("evidence_sha256") or None,
                    "line": attributes.get("evidence_line") or None,
                    "target_path": attributes.get("target_path") or None,
                    "reference_id": attributes.get("reference_id") or None,
                    "provenance": attributes.get("provenance"),
                    "confidence": attributes.get("confidence"),
                },
            }
            queue.append((neighbor, [*node_path, neighbor], [*edge_path, step]))
    return candidates


def _bounded_onboarding_retrieval(
    generation_dir: Path,
    manifest: dict[str, Any],
    queries: list[str],
    source_inventory: list[dict[str, Any]],
    *,
    limit: int,
) -> dict[str, Any]:
    """Return deterministic FTS seeds plus supported two-hop graph additions."""

    if not queries:
        return {
            "candidates": [],
            "summary": {
                "status": "not_requested",
                "queries": [],
                "fts_candidate_count": 0,
                "graph_candidate_count": 0,
                "graph_results_consumed": False,
                "ranking_effect": "none",
            },
        }
    sqlite_path = generation_dir / "local_context_index.sqlite"
    connection = sqlite3.connect(
        sqlite_path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1",
        uri=True,
    )
    try:
        ranked_fts: list[dict[str, Any]] = []
        seen_fts_paths: set[str] = set()
        per_query_limit = max(1, min(20, limit))
        for query_index, query in enumerate(queries):
            for item in _fts_candidates(connection, query, per_query_limit):
                path = str(item.get("source_path") or "")
                if not path or path in seen_fts_paths:
                    continue
                seen_fts_paths.add(path)
                candidate = dict(item)
                candidate["retrieval"] = {
                    **dict(item.get("retrieval") or {}),
                    "query": query,
                    "query_ordinal": query_index,
                }
                ranked_fts.append(candidate)
                if len(ranked_fts) >= limit:
                    break
            if len(ranked_fts) >= limit:
                break

        graph_model = _load_validated_graph(generation_dir, manifest, connection)
        family_by_path = {
            str(item.get("path") or ""): str(item.get("family_id") or "")
            for item in source_inventory
            if isinstance(item, dict) and item.get("path")
        }
        inventory_by_path = {
            str(item.get("path") or ""): item
            for item in source_inventory
            if isinstance(item, dict) and item.get("path")
        }
        for candidate in ranked_fts:
            source_record = inventory_by_path.get(
                str(candidate.get("source_path") or ""), {}
            )
            candidate["family_id"] = source_record.get("family_id")
        graph_additions: list[dict[str, Any]] = []
        seen_graph_paths = set(seen_fts_paths)
        for seed_rank, seed in enumerate(ranked_fts):
            seed_path = str(seed.get("source_path") or "")
            navigated = _graph_candidates(
                graph_model,
                path=seed_path,
                task=None,
                spec=None,
                capability=None,
                depth=2,
                limit=limit,
            )
            for item in navigated:
                path = str(item.get("source_path") or "")
                retrieval = item.get("retrieval")
                edge_path = (
                    retrieval.get("edge_path")
                    if isinstance(retrieval, dict)
                    and isinstance(retrieval.get("edge_path"), list)
                    else []
                )
                if (
                    not path
                    or path in seen_graph_paths
                    or len(edge_path) != 2
                    or any(
                        not isinstance(step, dict)
                        or not isinstance(step.get("evidence"), dict)
                        or not step["evidence"].get("path")
                        or not step["evidence"].get("sha256")
                        for step in edge_path
                    )
                ):
                    continue
                families = {
                    family_by_path.get(seed_path, ""),
                    family_by_path.get(path, ""),
                }
                if len({family for family in families if family}) < 2:
                    continue
                candidate = dict(item)
                candidate["family_id"] = family_by_path.get(path)
                candidate["retrieval"] = {
                    **dict(retrieval),
                    "seed_rank": seed_rank,
                    "seed_query": (seed.get("retrieval") or {}).get("query"),
                    "cross_family": True,
                }
                graph_additions.append(candidate)
                seen_graph_paths.add(path)
                if len(ranked_fts) + len(graph_additions) >= limit:
                    break
            if len(ranked_fts) + len(graph_additions) >= limit:
                break
    finally:
        connection.close()
    candidates = [*ranked_fts, *graph_additions]
    return {
        "candidates": candidates,
        "summary": {
            "status": "candidates_found" if candidates else "no_candidates",
            "queries": queries,
            "fts_candidate_count": len(ranked_fts),
            "graph_candidate_count": len(graph_additions),
            "graph_results_consumed": bool(graph_additions),
            "graph_depth": 2,
            "graph_cross_family_required": True,
            "ranking_effect": "review_priority_only",
            "authority_effect": "none",
            "effectiveness_over_sqlite_fts": "untested",
        },
    }


def _revalidate_candidate_sources(root: Path, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    expected: dict[str, str] = {}
    for candidate in candidates:
        path = candidate.get("source_path")
        digest = candidate.get("source_sha256")
        if not isinstance(path, str) or not path or not isinstance(digest, str) or not digest:
            raise RepositoryIntelligenceError("Candidate lacks a source path or source digest.")
        previous = expected.setdefault(path, digest)
        if previous != digest:
            raise RepositoryIntelligenceError(f"Candidate source has conflicting digests: {path}")
        retrieval = candidate.get("retrieval")
        if isinstance(retrieval, dict):
            for step in retrieval.get("edge_path") or []:
                if not isinstance(step, dict):
                    raise RepositoryIntelligenceError("Graph evidence path contains an invalid step.")
                evidence = step.get("evidence")
                if not isinstance(evidence, dict):
                    raise RepositoryIntelligenceError("Graph evidence step lacks evidence metadata.")
                evidence_path = evidence.get("path")
                evidence_digest = evidence.get("sha256")
                if isinstance(evidence_path, str) and evidence_path:
                    if not isinstance(evidence_digest, str) or not evidence_digest:
                        raise RepositoryIntelligenceError("Graph evidence path lacks a source digest.")
                    prior = expected.setdefault(evidence_path, evidence_digest)
                    if prior != evidence_digest:
                        raise RepositoryIntelligenceError(
                            f"Graph evidence has conflicting source digests: {evidence_path}"
                        )
    checked: list[dict[str, Any]] = []
    for relative, digest in sorted(expected.items()):
        try:
            path = safe_path_under(root, relative, field="repository_intelligence_candidate_source")
            data, _metadata = secure_regular_file_snapshot(path, max_bytes=2_000_000)
        except (OSError, ValueError) as exc:
            raise RepositoryIntelligenceError(f"Candidate source is unavailable or unsafe: {relative}") from exc
        observed = sha256_bytes(data)
        if observed != digest:
            raise RepositoryIntelligenceError(f"Candidate source changed after indexing: {relative}")
        checked.append({"path": relative, "sha256": observed})
    for candidate in candidates:
        candidate["source_revalidated"] = True
    return {
        "status": "current_sources_confirmed",
        "checked_path_count": len(checked),
        "checked_paths": checked,
    }


def query_active_generation(
    root: Path,
    *,
    naos_root: str,
    text: str | None,
    path: str | None,
    task: str | None,
    spec: str | None,
    capability: str | None,
    depth: int,
    limit: int,
) -> dict[str, Any]:
    context, generation_dir, manifest = _active_generation_paths(root, naos_root)
    sqlite_path = generation_dir / "local_context_index.sqlite"
    connection = sqlite3.connect(sqlite_path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        exact = _exact_candidate(connection, path) if path else []
        fts = _fts_candidates(connection, text, limit) if text else []
        reference = _reference_candidates(
            connection,
            task=task,
            spec=spec,
            capability=capability,
            limit=limit,
        )
        graph_model = _load_validated_graph(generation_dir, manifest, connection)
        graph = _graph_candidates(
            graph_model,
            path=path,
            task=task,
            spec=spec,
            capability=capability,
            depth=depth,
            limit=limit,
        )
    finally:
        connection.close()
    candidates = [*exact, *reference, *fts, *graph]
    source_revalidation = _revalidate_candidate_sources(root, candidates)
    closing_context = validate_active_generation(root, naos_root=naos_root, require_current_source=True)
    opening_generation = context.get("generation") if isinstance(context.get("generation"), dict) else {}
    closing_generation = (
        closing_context.get("generation")
        if isinstance(closing_context.get("generation"), dict)
        else {}
    )
    for field in (
        "generation_id",
        "generation_content_sha256",
        "manifest_file_sha256",
        "manifest_sha256",
        "validation_receipt_file_sha256",
        "validation_receipt_sha256",
        "activation_receipt_file_sha256",
        "activation_receipt_sha256",
        "effective_source_sha256",
        "transaction_id",
        "profile",
        "purpose",
        "component_mode",
    ):
        if opening_generation.get(field) != closing_generation.get(field):
            raise RepositoryIntelligenceError("Active repository-intelligence binding changed during query.")
    report = {
        "schema": QUERY_SCHEMA,
        "generated_at": utc_now_text(),
        "status": "candidates_found" if candidates else "no_candidates",
        "project_root": str(root),
        "generation": context.get("generation"),
        "query": {
            "text": text,
            "path": path,
            "task": task,
            "spec": spec,
            "capability": capability,
            "depth": depth,
            "limit": limit,
        },
        "lanes": {
            "exact": exact,
            "reference": reference,
            "fts": fts,
            "graph": graph,
            "semantic": [],
        },
        "summary": {
            "exact_candidates": len(exact),
            "reference_candidates": len(reference),
            "fts_candidates": len(fts),
            "graph_candidates": len(graph),
            "semantic_candidates": 0,
            "total_candidates": len(candidates),
        },
        "source_revalidation": source_revalidation,
        "limitations": [
            "Candidates must be verified against current repository source.",
            "Graph distance and FTS rank are retrieval metadata, not truth or confidence.",
            "Missing results do not establish absence.",
        ],
        "not_claimed": ["answer generation", "source authority", "complete recall", "semantic relevance proof"],
        "human_review_required": True,
    }
    _validate_schema(report, QUERY_SCHEMA)
    return report


def default_plan_output(plan: dict[str, Any]) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="naos-repository-intelligence-plan-"))
    return directory / f"{plan['plan_id']}.json"


def _external_output_path(root: Path, value: str | None, default: Path | None = None) -> Path | None:
    if value is None and default is None:
        return None
    output = Path(value).expanduser() if value is not None else default
    assert output is not None
    if not output.is_absolute():
        output = Path.cwd() / output
    output = output.resolve(strict=False)
    if output == root or root in output.parents:
        raise RepositoryIntelligenceError("Repository-intelligence output must remain outside the target repository.")
    return output


def _write_immutable_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    _write_new_bytes(path, data)
    os.chmod(path, 0o600)
    _fsync_directory(path.parent)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan, activate, validate, refresh, and query reusable brownfield repository intelligence."
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    def common(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("project_path", nargs="?", default=".")
        subparser.add_argument("--profile", choices=("quickstart", "lite", "standard", "assured"))
        subparser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
        subparser.add_argument("--policy")

    plan_parser = subparsers.add_parser("plan", help="Inspect source and create an immutable, no-target-mutation plan.")
    common(plan_parser)
    plan_parser.add_argument("--rules")
    plan_parser.add_argument("--output", help="Plan output path; defaults to a unique OS temporary directory.")
    plan_parser.add_argument("--purpose", choices=tuple(PURPOSE_QUESTIONS), default="brownfield-onboarding")
    plan_parser.add_argument("--component-mode", choices=COMPONENT_MODES, default="auto")

    apply_parser = subparsers.add_parser("apply", help="Apply one exact digest-confirmed plan as generated state.")
    common(apply_parser)
    apply_parser.add_argument("--plan", required=True)
    apply_parser.add_argument("--confirm-plan-sha256", required=True)
    apply_parser.add_argument("--reviewer-id")
    apply_parser.add_argument("--output")

    enroll_parser = subparsers.add_parser(
        "enroll",
        help="Establish capability-scoped provenance for an absent generated namespace.",
    )
    common(enroll_parser)
    enroll_parser.add_argument("--plan", required=True)
    enroll_parser.add_argument("--confirm-plan-sha256", required=True)
    enroll_parser.add_argument("--reviewer-id")
    enroll_parser.add_argument("--output")

    validate_parser = subparsers.add_parser("validate", help="Validate the active generation and source binding.")
    common(validate_parser)
    validate_parser.add_argument("--allow-stale-source", action="store_true")
    validate_parser.add_argument("--output")

    status_parser = subparsers.add_parser("status", help="Report provenance, lock, transaction, and active-generation state.")
    common(status_parser)
    status_parser.add_argument("--output")

    recover_parser = subparsers.add_parser("recover", help="Recover interrupted repository-intelligence publication.")
    common(recover_parser)
    recover_parser.add_argument("--output")

    refresh_parser = subparsers.add_parser("refresh", help="Prepare a new source-bound plan for the current repository.")
    common(refresh_parser)
    refresh_parser.add_argument("--rules")
    refresh_parser.add_argument("--output")
    refresh_parser.add_argument("--purpose", choices=tuple(PURPOSE_QUESTIONS), default="ongoing-change-impact")
    refresh_parser.add_argument("--component-mode", choices=COMPONENT_MODES, default="auto")

    query_parser = subparsers.add_parser("query", help="Query exact, FTS, and bounded graph candidate lanes.")
    common(query_parser)
    query_parser.add_argument("--text")
    query_parser.add_argument("--path")
    query_parser.add_argument("--task")
    query_parser.add_argument("--spec")
    query_parser.add_argument("--capability")
    query_parser.add_argument("--depth", type=int, default=2)
    query_parser.add_argument("--limit", type=int, default=25)
    query_parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = validate_project_root(args.project_path)
        policy = load_policy(args.policy, args.naos_root, root)
        naos_root = args.naos_root or default_naos_root(policy)
        profile = normalize_profile(args.profile, policy)
        if args.operation in {"plan", "refresh"}:
            rules_path, rules_source = resolve_rules_path(root, naos_root, args.rules)
            report = build_plan(
                root,
                profile=profile,
                naos_root=naos_root,
                rules_path=rules_path,
                rules_source=rules_source,
                purpose=args.purpose,
                component_mode=args.component_mode,
            )
            output = _external_output_path(root, args.output, default_plan_output(report))
            assert output is not None
            report["plan_file"] = str(output)
            _validate_schema(report, PLAN_SCHEMA)
            _write_immutable_json(output, report)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["status"] in {"confirmation_required", "enrollment_required", "not_applicable"} else 2
        if args.operation == "apply":
            plan = _strict_json_file(Path(args.plan).expanduser())
            report = apply_plan(
                root,
                plan,
                confirmed_digest=args.confirm_plan_sha256,
                reviewer_id=args.reviewer_id,
                rules_override=None,
                requested_profile=profile,
                requested_naos_root=naos_root,
            )
        elif args.operation == "enroll":
            plan = _strict_json_file(Path(args.plan).expanduser())
            report = enroll_capability_scope(
                root,
                plan,
                confirmed_digest=args.confirm_plan_sha256,
                reviewer_id=args.reviewer_id,
                requested_profile=profile,
                requested_naos_root=naos_root,
            )
        elif args.operation == "validate":
            report = validate_active_generation(
                root,
                naos_root=naos_root,
                require_current_source=not args.allow_stale_source,
            )
        elif args.operation == "status":
            report = repository_intelligence_status(root, naos_root=naos_root)
        elif args.operation == "recover":
            report = recover_repository_intelligence(root, naos_root=naos_root)
        else:
            if not any((args.text, args.path, args.task, args.spec, args.capability)):
                raise RepositoryIntelligenceError("Query requires --text, --path, --task, --spec, or --capability.")
            depth = min(max(1, args.depth), 3)
            limit = min(max(1, args.limit), 100)
            report = query_active_generation(
                root,
                naos_root=naos_root,
                text=args.text,
                path=args.path,
                task=args.task,
                spec=args.spec,
                capability=args.capability,
                depth=depth,
                limit=limit,
            )
        if args.output:
            output = _external_output_path(root, args.output)
            assert output is not None
            _write_immutable_json(output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report.get("status") not in {
            "blocked",
            "stale",
            "not_configured",
            "recovery_required",
            "invalid",
        } else 2
    except (
        RepositoryIntelligenceError,
        ProvenanceError,
        CanonicalizationError,
        CanonicalizationUnavailable,
        ValueError,
        OSError,
    ) as exc:
        print(f"Repository intelligence refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
