#!/usr/bin/env python3
"""Build a deterministic, local, non-authoritative NAOS context index."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    build_generated_by,
    default_naos_root,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    kit_root,
    load_policy,
    normalize_profile,
    report_default_path,
    report_output_path,
    safe_policy_path,
    sessions_index_path,
    severity_for_profile,
    write_report,
)
from naos_audit_log import write_audit_event  # noqa: E402


REPORT_SCHEMA = "naos.local_context_index.v1"
SQLITE_COORDINATION_SCHEMA = "naos.sqlite_write_coordination.v1"
SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_LOCK_TIMEOUT_SECONDS = 10.0
SQLITE_STALE_LOCK_SECONDS = 300.0
SQLITE_REQUIRED_TABLES = ["index_runs", "artifacts", "artifact_chunks", "artifact_links", "report_summaries"]
SENSITIVE_NAME_RE = re.compile(r"(?i)(secret|token|credential|password|api[_-]?key|private[_-]?key)")
SECRET_CONTENT_PATTERNS = (
    ("aws_access_key_id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), None),
    ("openai_style_key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"), None),
    (
        "private_key_header",
        re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        None,
    ),
    (
        "assigned_secret_quoted",
        re.compile(
            rb'''(?ix)\b["']?(?:password|passwd|pwd|secret|token|api[_-]?key|credential)["']?\s*[:=]\s*(?P<quote>["'])(?P<value>[^"'\r\n]{8,})(?P=quote)'''
        ),
        "value",
    ),
    (
        "assigned_secret_unquoted",
        re.compile(
            rb'''(?im)^[ \t]*(?:-[ \t]*)?["']?(?:password|passwd|pwd|secret|token|api[_-]?key|credential)["']?[ \t]*[:=][ \t]*(?P<value>[A-Za-z0-9_./+@:-]{8,})[ \t]*(?=[#,}\]\r\n]|$)'''
        ),
        "value",
    ),
)
PLACEHOLDER_SECRET_VALUES = {
    b"changeme",
    b"change-me",
    b"example",
    b"example-token",
    b"example_secret",
    b"placeholder",
    b"replace-me",
    b"todo",
    b"your-api-key",
    b"your_token_here",
}
TASK_ID_RE = re.compile(r"\bT-\d{3,}\b", re.IGNORECASE)
SPEC_REF_RE = re.compile(r"(specs/[A-Za-z0-9_./-]+\.md(?:#[A-Za-z0-9_.:-]+)?)")
CAPABILITY_RE = re.compile(r"\bCAP-[A-Za-z0-9_-]+\b", re.IGNORECASE)
FTS_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")
SAFE_TEMP_FRAGMENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")
TEXT_SUFFIXES = {
    ".bash",
    ".cfg",
    ".cjs",
    ".cs",
    ".csv",
    ".go",
    ".gradle",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".md",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def utc_now_text() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def timestamp_text(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping: {path}")
    return data


def load_json_mapping(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def default_rules_template() -> Path:
    return kit_root() / "templates" / "structural-seeds" / "naos" / "local_context_index_rules.yaml"


def resolve_rules_path(root: Path, naos_root: str, policy: dict[str, Any], explicit: str | None = None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit), "explicit"
    filename = str(policy.get("paths", {}).get("local_context_index_rules") or "local_context_index_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists():
        return project_rules, "project"
    return default_rules_template(), "template"


def secure_regular_file_snapshot(
    path: Path,
    *,
    max_bytes: int | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read one coherent regular-file snapshot without following a leaf symlink."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"Refusing non-regular index source: {path}")
        if before.st_nlink != 1:
            raise ValueError(f"Refusing multiply-linked index source: {path}")
        if max_bytes is not None and before.st_size > max_bytes:
            raise ValueError(
                f"Refusing oversized index source ({before.st_size} > {max_bytes} bytes): {path}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read()
            after = os.fstat(handle.fileno())
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise ValueError(f"Index source changed during its content snapshot: {path}")
        if len(data) != before.st_size:
            raise ValueError(f"Index source size changed during its content snapshot: {path}")
        return data, before
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def secure_regular_file_bytes(path: Path) -> bytes:
    """Read one regular, single-link file without following a leaf symlink."""

    return secure_regular_file_snapshot(path)[0]


def safe_digest(path: Path) -> str | None:
    try:
        data = secure_regular_file_bytes(path)
    except (FileNotFoundError, OSError, ValueError):
        return None
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def finding(finding_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        **extra,
    }


def latest_session_id(root: Path, naos_root: str, policy: dict[str, Any]) -> str | None:
    path = sessions_index_path(root, naos_root, policy)
    if not path.exists():
        return None
    try:
        data = load_json_mapping(path)
    except Exception:
        return None
    value = data.get("latest_session_id")
    return str(value) if value else None


def sqlite_lock_path(root: Path, naos_root: str, policy: dict[str, Any], target_db_path: Path) -> Path:
    configured = policy.get("paths", {}).get("local_context_index_db_lock")
    if configured:
        return root / naos_root / str(configured)
    return target_db_path.with_name(f"{target_db_path.name}.lock")


def temp_db_path(target_db_path: Path, session_id: str | None) -> Path:
    seed = session_id or uuid.uuid4().hex
    safe_fragment = SAFE_TEMP_FRAGMENT_RE.sub("_", seed)[:64].strip("._-") or "session"
    return target_db_path.with_name(f"{target_db_path.name}.tmp.{os.getpid()}.{safe_fragment}.{uuid.uuid4().hex[:8]}")


def parse_lock_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(str(value))
    except Exception:
        return None


def read_lock_metadata(lock_path: Path) -> dict[str, Any]:
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    return data if isinstance(data, dict) else {}


def lock_age_seconds(lock_path: Path, now_text: str) -> float | None:
    metadata = read_lock_metadata(lock_path)
    acquired_at = parse_lock_timestamp(metadata.get("acquired_at"))
    now = parse_timestamp(now_text)
    if acquired_at is not None:
        return max(0.0, (now - acquired_at).total_seconds())
    try:
        modified_at = datetime.fromtimestamp(lock_path.stat().st_mtime, UTC)
    except OSError:
        return None
    return max(0.0, (now - modified_at).total_seconds())


def acquire_sqlite_lock(
    lock_path: Path,
    *,
    target_db_path: Path,
    session_id: str | None,
    generated_by: dict[str, Any],
    generated_at: str,
    timeout_seconds: float = SQLITE_LOCK_TIMEOUT_SECONDS,
    stale_after_seconds: float = SQLITE_STALE_LOCK_SECONDS,
    retry_interval_seconds: float = 0.1,
) -> tuple[int | None, dict[str, Any]]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    stale_detected = False
    stale_action = "not_applicable"
    findings: list[dict[str, Any]] = []
    metadata = {
        "pid": os.getpid(),
        "session_id": session_id,
        "operator_id": generated_by.get("operator_id"),
        "operator_source": generated_by.get("operator_source"),
        "operator_attribution_status": generated_by.get("operator_attribution_status"),
        "acquired_at": generated_at,
        "target_db_path": str(target_db_path),
    }
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8"))
            os.fsync(fd)
            waited = time.monotonic() - start
            return fd, {
                "lock_acquired": True,
                "lock_wait_seconds": round(waited, 3),
                "stale_lock_detected": stale_detected,
                "stale_lock_action": stale_action,
                "findings": findings,
            }
        except FileExistsError:
            age = lock_age_seconds(lock_path, generated_at)
            if age is not None and age > stale_after_seconds:
                stale_detected = True
                try:
                    lock_path.unlink()
                    stale_action = "removed"
                    findings.append(
                        finding(
                            "sqlite_write_coordination.stale_lock_detected",
                            "advisory",
                            "stale_lock_detected",
                            "A stale SQLite index lock file was detected and removed before retrying.",
                            path=str(lock_path),
                            age_seconds=round(age, 3),
                        )
                    )
                    continue
                except OSError as exc:
                    stale_action = "not_removed"
                    waited = time.monotonic() - start
                    findings.append(
                        finding(
                            "sqlite_write_coordination.stale_lock_not_removed",
                            "warning",
                            "stale_lock_detected",
                            f"A stale SQLite index lock file was detected but could not be removed: {exc}",
                            path=str(lock_path),
                            age_seconds=round(age, 3),
                        )
                    )
                    return None, {
                        "lock_acquired": False,
                        "lock_wait_seconds": round(waited, 3),
                        "stale_lock_detected": stale_detected,
                        "stale_lock_action": stale_action,
                        "findings": findings,
                    }
            if time.monotonic() - start >= timeout_seconds:
                waited = time.monotonic() - start
                findings.append(
                    finding(
                        "sqlite_write_coordination.lock_timeout",
                        "warning",
                        "lock_timeout",
                        "Timed out waiting for the local SQLite index lock; the existing index was left unchanged.",
                        path=str(lock_path),
                    )
                )
                return None, {
                    "lock_acquired": False,
                    "lock_wait_seconds": round(waited, 3),
                    "stale_lock_detected": stale_detected,
                    "stale_lock_action": stale_action,
                    "findings": findings,
                }
            time.sleep(retry_interval_seconds)


def release_sqlite_lock(fd: int | None, lock_path: Path) -> dict[str, Any] | None:
    if fd is None:
        return None
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        lock_path.unlink()
        return {"action": "lock_released", "path": str(lock_path), "status": "removed"}
    except FileNotFoundError:
        return {"action": "lock_released", "path": str(lock_path), "status": "already_absent"}
    except OSError as exc:
        return {"action": "lock_release_failed", "path": str(lock_path), "status": "failed", "error": str(exc)}


def verify_sqlite_tables(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')").fetchall()
    finally:
        connection.close()
    return sorted(str(row[0]) for row in rows)


def sqlite_coordination_report_base(
    *,
    root: Path,
    naos_root: str,
    profile: str,
    generated_at: str,
    target_db_path: Path | None,
    lock_path: Path | None,
    session_id: str | None,
    generated_by: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": SQLITE_COORDINATION_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": "not_configured",
        "naos_root": naos_root,
        "project_root": str(root),
        "target_db_path": str(target_db_path) if target_db_path else None,
        "lock_path": str(lock_path) if lock_path else None,
        "lock_acquired": False,
        "lock_wait_seconds": 0.0,
        "lock_timeout_seconds": env_float("NAOS_SQLITE_LOCK_TIMEOUT_SECONDS", SQLITE_LOCK_TIMEOUT_SECONDS),
        "stale_lock_detected": False,
        "stale_lock_action": "not_applicable",
        "temp_db_path": None,
        "atomic_replace_used": False,
        "busy_timeout_ms": SQLITE_BUSY_TIMEOUT_MS,
        "wal_requested": False,
        "wal_effective": False,
        "wal_checkpointed": False,
        "sqlite_version": sqlite3.sqlite_version,
        "session_id": session_id,
        "operator_id": generated_by.get("operator_id"),
        "generated_by": generated_by,
        "tables_verified": [],
        "target_db_hash": None,
        "cleanup_actions": [],
        "findings": [],
        "known_gaps": [
            "SQLite write coordination is local file-system coordination only.",
            "Logical evidence conflicts, task locks, append-only audit logs, and team policy overlays are deferred to later multi-user groups.",
        ],
        "residual_risks": [
            "local_filesystem_semantics_may_vary",
            "network_filesystem_safety_not_verified",
            "last_writer_may_still_win_at_logical_level",
            "coordination_protects_file_integrity_not_governance_correctness",
            "human_review_required",
        ],
        "limitations": [
            "Uses a stdlib lock file and atomic same-directory replace for local generated SQLite index writes.",
            "WAL is not requested because the database is built offline in a unique temp file, closed, verified, and atomically replaced.",
            "This report is infrastructure posture; it is not task locking, evidence conflict detection, append-only audit logging, or full multi-user completion.",
        ],
        "not_claimed": [
            "distributed locking",
            "network filesystem safety",
            "task locking",
            "evidence conflict detection",
            "append-only audit log",
            "full multi-user completion",
            "compliance proof",
            "source of truth",
        ],
        "human_review_required": True,
        "summary": {
            "status": "not_configured",
            "lock_acquired": False,
            "atomic_replace_used": False,
            "tables_verified": 0,
            "target_db_hash_present": False,
        },
    }


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def load_semantic_candidate_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "semantic_candidate_layer_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "semantic_runtime_enabled": False,
            "sqlite_vec_enabled": False,
            "embeddings_enabled": False,
            "rule": "Run naos semantic-candidates to inspect future semantic candidate posture; the local index remains exact/FTS-first.",
        }
    try:
        data = load_json_mapping(path)
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "semantic_runtime_enabled": False,
            "sqlite_vec_enabled": False,
            "embeddings_enabled": False,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "semantic_runtime_enabled": bool(data.get("semantic_runtime_enabled")),
        "sqlite_vec_enabled": bool(data.get("sqlite_vec_enabled")),
        "embeddings_enabled": bool(data.get("embeddings_enabled")),
        "candidate_only_policy": data.get("candidate_only_policy") or {},
        "summary": data.get("summary") or {},
        "rule": "Semantic readiness is reporting-only; it does not enable vector runtime or change source authority.",
    }


def load_graph_context_readiness(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "graph_context_readiness_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "graph_runtime_enabled": False,
            "explicit_link_traversal_only": True,
            "rule": "Run naos graph-context to inspect future graph traversal posture; the local index exposes explicit links only.",
        }
    try:
        data = load_json_mapping(path)
    except Exception as exc:
        return {
            "status": "parse_error",
            "path": str(path),
            "graph_runtime_enabled": False,
            "explicit_link_traversal_only": True,
            "error": str(exc),
        }
    return {
        "status": data.get("status", "present"),
        "path": str(path),
        "graph_runtime_enabled": bool(data.get("graph_runtime_enabled")),
        "explicit_link_traversal_only": bool(data.get("explicit_link_traversal_only", True)),
        "global_graph_scan_allowed": bool(data.get("global_graph_scan_allowed")),
        "traversal_limits": data.get("traversal_limits") or {},
        "summary": data.get("summary") or {},
        "rule": "Graph context readiness is reporting-only; explicit index links remain candidate relationships, not authority.",
    }


def load_memory_provider_access(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_provider_access_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "provider_access_verified": False,
            "mcp_access_verified": False,
            "rule": "Run naos memory-access to inspect declared/configured memory access posture; the local index never indexes private memory payloads.",
        }
    try:
        data = load_json_mapping(path)
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
        "rule": "Memory access posture is metadata only; private memory payloads and provider databases remain excluded from indexing.",
    }


def load_memory_use_policy(root: Path, naos_root: str, policy: dict[str, Any]) -> dict[str, Any]:
    path = report_default_path(root, naos_root, policy, "memory_use_policy_report")
    if not path.exists():
        return {
            "status": "not_configured",
            "path": str(path),
            "rule": "Run naos memory-use-policy to inspect memory review/use posture; the local index never indexes private memory payloads.",
        }
    try:
        data = load_json_mapping(path)
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
        "rule": "Memory-use posture is metadata only; index candidates do not become instruction-grade memory, approval, or source authority, and access-unverified policy items remain explicitly unverified.",
    }


def rel_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if str(item).strip()]


def bounded_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 18)].rstrip() + " [truncated]"


def fts_query_terms(raw: str, max_chars: int = 120) -> tuple[str, ...]:
    tokens = FTS_TOKEN_RE.findall((raw or "")[:max_chars])
    filtered = [token for token in tokens if token.upper() not in {"AND", "OR", "NOT", "NEAR"}]
    return tuple(filtered[:20])


def literalize_fts_terms(terms: Iterable[str]) -> str:
    return " AND ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def sanitize_fts_query(raw: str, max_chars: int = 120) -> str:
    return literalize_fts_terms(fts_query_terms(raw, max_chars))


def match_any(path_text: str, patterns: list[str]) -> bool:
    normalized = path_text.replace(os.sep, "/")
    return any(fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(f"/{normalized}", pattern) for pattern in patterns)


def is_sensitive_path(path_text: str) -> bool:
    parts = Path(path_text).parts
    basename = parts[-1] if parts else path_text
    if basename in {".env"} or basename.startswith(".env."):
        return True
    if basename in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "engram.db"}:
        return True
    if Path(basename).suffix.lower() in {".pem", ".key", ".crt", ".p12", ".pfx", ".db", ".sqlite"}:
        return True
    return bool(SENSITIVE_NAME_RE.search(path_text))


UNSAFE_SOURCE_TOPOLOGY_REASONS = frozenset(
    {
        "unsafe_source_outside_root",
        "unsafe_source_root",
        "unsafe_source_unreadable",
        "unsafe_source_symlink",
        "unsafe_source_non_directory_ancestor",
        "unsafe_source_non_regular",
        "unsafe_source_hardlink",
    }
)


def lexical_path_under(root: Path, path: Path) -> tuple[str, bool]:
    """Return a lexical relative path without resolving a candidate symlink."""

    root_absolute = Path(os.path.abspath(os.fspath(root)))
    path_absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError:
        return Path(os.path.relpath(path_absolute, root_absolute)).as_posix(), False
    return relative.as_posix(), True


def should_exclude(relative_path: str, rules: dict[str, Any]) -> tuple[bool, str | None]:
    rel = relative_path.replace(os.sep, "/")
    if rel in {"naos/reports/local_context_index.json", "naos/reports/sqlite_write_coordination.json"}:
        return True, "generated_index_report_feedback_loop"
    patterns = string_list(rules.get("exclude_patterns")) + string_list(rules.get("default_exclusions"))
    if match_any(rel, patterns):
        return True, "default_exclusion"
    if is_sensitive_path(rel):
        return True, "sensitive_name_or_extension"
    return False, None


def secret_content_reason(data: bytes) -> str | None:
    """Return the first non-placeholder secret-content classification."""

    for pattern_id, pattern, value_group in SECRET_CONTENT_PATTERNS:
        for match in pattern.finditer(data):
            if value_group is not None:
                value = match.group(value_group).strip().lower()
                if value in PLACEHOLDER_SECRET_VALUES:
                    continue
            return pattern_id
    return None


def source_topology_refusal(root: Path, path: Path) -> str | None:
    """Classify unsafe source topology without opening or following the leaf."""

    root_absolute = Path(os.path.abspath(os.fspath(root)))
    path_absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError:
        return "unsafe_source_outside_root"
    try:
        root_metadata = os.lstat(root_absolute)
    except OSError:
        return "unsafe_source_unreadable"
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        return "unsafe_source_root"
    current = root_absolute
    for index, component in enumerate(relative.parts):
        current = current / component
        try:
            metadata = os.lstat(current)
        except OSError:
            return "unsafe_source_unreadable"
        is_leaf = index == len(relative.parts) - 1
        if stat.S_ISLNK(metadata.st_mode):
            return "unsafe_source_symlink"
        if is_leaf:
            if not stat.S_ISREG(metadata.st_mode):
                return "unsafe_source_non_regular"
            if metadata.st_nlink != 1:
                return "unsafe_source_hardlink"
            return None
        if not stat.S_ISDIR(metadata.st_mode):
            return "unsafe_source_non_directory_ancestor"
    return "unsafe_source_non_regular"


def iter_pattern_matches(root: Path, pattern: str) -> list[Path]:
    if pattern.startswith("/"):
        pattern = pattern.lstrip("/")
    try:
        paths = sorted(root.glob(pattern))
    except ValueError:
        return []
    return paths


def collect_candidates(root: Path, rules: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    max_file_bytes = int((rules.get("chunking") or {}).get("max_file_bytes") or 2_000_000)
    families = [item for item in rules.get("artifact_families", []) if isinstance(item, dict)]
    candidates: dict[str, dict[str, Any]] = {}
    excluded: dict[str, dict[str, Any]] = {}

    for family in families:
        for pattern in string_list(family.get("include_patterns")):
            for path in iter_pattern_matches(root, pattern):
                rel, root_bounded = lexical_path_under(root, path)
                if not root_bounded:
                    excluded.setdefault(
                        rel,
                        {
                            "path": rel,
                            "reason": "unsafe_source_outside_root",
                            "matched_family": family.get("id"),
                        },
                    )
                    continue
                excluded_flag, reason = should_exclude(rel, rules)
                if excluded_flag:
                    if reason == "generated_index_report_feedback_loop":
                        continue
                    excluded.setdefault(
                        rel,
                        {
                            "path": rel,
                            "reason": reason,
                            "matched_family": family.get("id"),
                        },
                    )
                    continue
                topology_refusal = source_topology_refusal(root, path)
                if topology_refusal:
                    excluded.setdefault(
                        rel,
                        {
                            "path": rel,
                            "reason": topology_refusal,
                            "matched_family": family.get("id"),
                        },
                    )
                    continue
                try:
                    size_bytes = os.lstat(path).st_size
                except OSError:
                    size_bytes = max_file_bytes + 1
                if size_bytes > max_file_bytes:
                    excluded.setdefault(
                        rel,
                        {
                            "path": rel,
                            "reason": "max_file_bytes_exceeded",
                            "size_bytes": size_bytes,
                            "max_file_bytes": max_file_bytes,
                            "matched_family": family.get("id"),
                        },
                    )
                    continue
                if rel in candidates:
                    continue
                candidates[rel] = {"path": path, "family": family}
    return [candidates[key] for key in sorted(candidates)], [excluded[key] for key in sorted(excluded)]


def summarize_markdown(text: str, max_chars: int, max_chunks: int) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    current_heading = "document"
    current_lines: list[str] = []
    start_line = 1
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#"):
            if current_lines:
                chunks.append(
                    {
                        "section_heading": current_heading,
                        "text": "\n".join(current_lines).strip(),
                        "start_line": start_line,
                        "end_line": line_no - 1,
                    }
                )
            current_heading = line.strip("# ").strip() or "section"
            current_lines = [line]
            start_line = line_no
        else:
            current_lines.append(line)
    if current_lines:
        chunks.append(
            {
                "section_heading": current_heading,
                "text": "\n".join(current_lines).strip(),
                "start_line": start_line,
                "end_line": len(text.splitlines()) or 1,
            }
        )
    return [
        {
            **item,
            "text": bounded_text(item["text"], max_chars),
            "chunk_kind": "markdown_summary",
        }
        for item in chunks
        if item.get("text")
    ][:max_chunks]


def summarize_mapping(data: dict[str, Any], max_chars: int, max_chunks: int, kind: str) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    if kind == "json_summary" and any(key in data for key in ("schema", "status", "summary", "findings")):
        summary = {
            "schema": data.get("schema"),
            "status": data.get("status"),
            "summary": data.get("summary") or {},
            "findings_count": len(data.get("findings") or []),
            "known_gaps_count": len(data.get("known_gaps") or []),
            "residual_risks_count": len(data.get("residual_risks") or []),
            "human_review_required": data.get("human_review_required"),
        }
        chunks.append({"section_heading": "report_summary", "text": json.dumps(summary, sort_keys=True), "chunk_kind": kind})
    else:
        top_keys = list(data.keys())[:20]
        summary = {"top_level_keys": top_keys}
        for key in top_keys[:8]:
            value = data.get(key)
            if isinstance(value, (str, int, float, bool)) or value is None:
                summary[key] = value
            elif isinstance(value, list):
                summary[key] = {"items": len(value)}
            elif isinstance(value, dict):
                summary[key] = {"keys": list(value.keys())[:8]}
        chunks.append({"section_heading": "structured_summary", "text": json.dumps(summary, sort_keys=True), "chunk_kind": kind})
    return [
        {
            **item,
            "text": bounded_text(item["text"], max_chars),
            "start_line": None,
            "end_line": None,
        }
        for item in chunks[:max_chunks]
    ]


def summarize_python(text: str, max_chars: int, max_chunks: int) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [
            {
                "section_heading": "python_parse_error",
                "text": "Python file could not be parsed; source body was not indexed.",
                "chunk_kind": "python_symbol_summary",
                "start_line": None,
                "end_line": None,
            }
        ]
    module_doc = ast.get_docstring(tree) or ""
    symbols: list[dict[str, Any]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append(
                {
                    "name": node.name,
                    "kind": node.__class__.__name__,
                    "line": getattr(node, "lineno", None),
                    "doc": bounded_text(ast.get_docstring(node) or "", 160),
                }
            )
    summary = {
        "module_doc": bounded_text(module_doc, 240),
        "symbols": symbols[:30],
        "note": "Source body is not indexed by default; this is a bounded symbol/header summary.",
    }
    return [
        {
            "section_heading": "python_symbol_summary",
            "text": bounded_text(json.dumps(summary, sort_keys=True), max_chars),
            "chunk_kind": "python_symbol_summary",
            "start_line": 1,
            "end_line": None,
        }
    ][:max_chunks]


def summarize_bounded_text(text: str, max_chars: int, max_chunks: int) -> list[dict[str, Any]]:
    """Split text into deterministic bounded line blocks for candidate retrieval."""

    chunks: list[dict[str, Any]] = []
    current: list[str] = []
    current_chars = 0
    start_line = 1
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        line_cost = len(line) + 1
        if current and current_chars + line_cost > max_chars:
            chunks.append(
                {
                    "section_heading": f"lines_{start_line}_{line_no - 1}",
                    "text": "\n".join(current),
                    "chunk_kind": "bounded_text",
                    "start_line": start_line,
                    "end_line": line_no - 1,
                }
            )
            if len(chunks) >= max_chunks:
                break
            current = []
            current_chars = 0
            start_line = line_no
        current.append(line)
        current_chars += line_cost
    if current and len(chunks) < max_chunks:
        chunks.append(
            {
                "section_heading": f"lines_{start_line}_{len(lines) or 1}",
                "text": bounded_text("\n".join(current), max_chars),
                "chunk_kind": "bounded_text",
                "start_line": start_line,
                "end_line": len(lines) or 1,
            }
        )
    return [item for item in chunks if item.get("text")]


def chunks_for_artifact_bytes(
    path: Path,
    data: bytes,
    family: dict[str, Any],
    rules: dict[str, Any],
) -> list[dict[str, Any]]:
    chunking = rules.get("chunking") or {}
    max_chars = int(chunking.get("max_chars_per_chunk") or 1200)
    max_chunks = int(family.get("max_chunks_per_artifact") or chunking.get("max_chunks_per_artifact") or 8)
    kind = str(family.get("chunk_kind") or "")
    suffix = path.suffix.lower()
    if suffix not in TEXT_SUFFIXES and kind not in {
        "bounded_text",
        "markdown_summary",
        "json_summary",
        "yaml_summary",
        "python_symbol_summary",
    }:
        return []
    text = data.decode("utf-8", errors="replace")
    if suffix == ".md" or kind == "markdown_summary":
        return summarize_markdown(text, max_chars, max_chunks)
    if kind == "python_symbol_summary" or (suffix == ".py" and not kind):
        return summarize_python(text, max_chars, max_chunks)
    if suffix == ".json" or kind == "json_summary":
        try:
            return summarize_mapping(json.loads(text), max_chars, max_chunks, "json_summary")
        except Exception:
            return [{"section_heading": "json_parse_error", "text": "JSON parse failed.", "chunk_kind": "json_summary"}]
    if suffix in {".yaml", ".yml"} or kind == "yaml_summary":
        try:
            data = yaml.safe_load(text) or {}
            return summarize_mapping(data if isinstance(data, dict) else {"items": data}, max_chars, max_chunks, "yaml_summary")
        except Exception:
            return [{"section_heading": "yaml_parse_error", "text": "YAML parse failed.", "chunk_kind": "yaml_summary"}]
    return summarize_bounded_text(text, max_chars, max_chunks)


def chunks_for_artifact(path: Path, family: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    max_file_bytes = int((rules.get("chunking") or {}).get("max_file_bytes") or 2_000_000)
    data, _metadata = secure_regular_file_snapshot(path, max_bytes=max_file_bytes)
    return chunks_for_artifact_bytes(path, data, family, rules)


def link_records(path_text: str, chunk_text: str) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for task_id in sorted({match.upper() for match in TASK_ID_RE.findall(chunk_text)}):
        links.append({"source_path": path_text, "link_type": "task_ref", "reference_id": task_id})
    for spec_ref in sorted(set(SPEC_REF_RE.findall(chunk_text))):
        links.append({"source_path": path_text, "link_type": "spec_ref", "reference_id": spec_ref})
    for cap_ref in sorted({match.upper() for match in CAPABILITY_RE.findall(chunk_text)}):
        links.append({"source_path": path_text, "link_type": "capability_ref", "reference_id": cap_ref})
    return links


def build_artifact_records(
    root: Path,
    rules: dict[str, Any],
    generated_at: str,
    *,
    include_source_bytes: bool = False,
    preexcluded_paths: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    now = parse_timestamp(generated_at)
    freshness_days = int((rules.get("freshness_policy") or {}).get("default_freshness_window_days") or 30)
    candidates, excluded = collect_candidates(root, rules)
    artifacts: list[dict[str, Any]] = []
    chunks: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    preexcluded_paths = preexcluded_paths or {}
    max_artifacts = int((rules.get("chunking") or {}).get("max_artifacts") or 500)
    max_file_bytes = int((rules.get("chunking") or {}).get("max_file_bytes") or 2_000_000)
    for candidate in candidates:
        path = Path(candidate["path"])
        family = candidate["family"]
        path_text = rel_path(path, root).replace(os.sep, "/")
        preexcluded = preexcluded_paths.get(path_text)
        if preexcluded is not None:
            excluded.append(
                {
                    "path": path_text,
                    "matched_family": family.get("id"),
                    **preexcluded,
                }
            )
            continue
        if len(artifacts) >= max_artifacts:
            excluded.append(
                {
                    "path": path_text,
                    "reason": "max_artifacts_exceeded",
                    "max_artifacts": max_artifacts,
                    "matched_family": family.get("id"),
                }
            )
            continue
        data, metadata = secure_regular_file_snapshot(path, max_bytes=max_file_bytes)
        secret_reason = secret_content_reason(data)
        if secret_reason is not None:
            excluded.append(
                {
                    "path": path_text,
                    "reason": "secret_like_content_excluded",
                    "pattern_id": secret_reason,
                    "matched_family": family.get("id"),
                }
            )
            continue
        modified = datetime.fromtimestamp(metadata.st_mtime, UTC)
        age_days = max(0, (now.date() - modified.date()).days)
        source_hash = hashlib.sha256(data).hexdigest()
        identity = f"{family.get('id') or 'artifact'}\0{path_text}".encode("utf-8")
        artifact_id = f"A-{hashlib.sha256(identity).hexdigest()[:16]}"
        artifact = {
            "artifact_id": artifact_id,
            "path": path_text,
            "artifact_type": family.get("artifact_type") or family.get("id"),
            "family_id": family.get("id"),
            "authority_level": family.get("authority_level") or "repository_governance",
            "profile_scope": family.get("profile_scope") or "all",
            "source_hash": source_hash,
            "size_bytes": metadata.st_size,
            "modified_at": timestamp_text(modified),
            "indexed_at": generated_at,
            "freshness_status": "stale" if freshness_days >= 0 and age_days > freshness_days else "fresh",
            "age_days": age_days,
            "provenance": "repo_file",
            "include_policy": family.get("include_policy") or "bounded_summary",
            "exclusion_reason": None,
            "scope": family.get("scope") or "project_local",
            "use_policy": "candidate_reference_only",
            "review_status": "unreviewed_candidate",
            "source_reference": path_text,
            "confidence": "declared_artifact",
            "limitations": ["bounded summary only", "not authority"],
            "recall_trace_readiness": "metadata_available",
            "audit_event_readiness": "index_run_recorded",
        }
        if include_source_bytes:
            artifact["_source_bytes"] = data
        artifact_chunks = chunks_for_artifact_bytes(path, data, family, rules)
        for chunk_index, item in enumerate(artifact_chunks, start=1):
            chunk_id = f"{artifact_id}-C{chunk_index:03d}"
            chunk_text = str(item.get("text") or "")
            chunk_record = {
                "chunk_id": chunk_id,
                "artifact_id": artifact_id,
                "path": path_text,
                "section_heading": item.get("section_heading") or "summary",
                "chunk_kind": item.get("chunk_kind") or family.get("chunk_kind") or "summary",
                "text_summary": bounded_text(chunk_text, 500),
                "bounded_excerpt": bounded_text(chunk_text, int((rules.get("chunking") or {}).get("max_chars_per_chunk") or 1200)),
                "start_line": item.get("start_line"),
                "end_line": item.get("end_line"),
                "char_count": len(chunk_text),
                "confidence": "bounded_candidate",
                "limitations": ["candidate retrieval only"],
                "scope": artifact["scope"],
                "use_policy": "candidate_reference_only",
                "review_status": "unreviewed_candidate",
                "source_reference": path_text,
                "recall_trace_readiness": "metadata_available",
                "audit_event_readiness": "index_run_recorded",
                "related_task_ids": sorted({link["reference_id"] for link in link_records(path_text, chunk_text) if link["link_type"] == "task_ref"}),
                "related_spec_refs": sorted({link["reference_id"] for link in link_records(path_text, chunk_text) if link["link_type"] == "spec_ref"}),
                "related_capabilities": sorted({link["reference_id"] for link in link_records(path_text, chunk_text) if link["link_type"] == "capability_ref"}),
                "related_code_symbols": [],
                "related_tests": [],
            }
            chunks.append(chunk_record)
            links.extend(link_records(path_text, chunk_text))
        artifact["chunk_count"] = len(artifact_chunks)
        artifacts.append(artifact)
    deduped_links = []
    seen_links: set[tuple[str, str, str]] = set()
    for link in links:
        key = (str(link.get("source_path")), str(link.get("link_type")), str(link.get("reference_id")))
        if key not in seen_links:
            seen_links.add(key)
            link_identity = "\0".join(key).encode("utf-8")
            deduped_links.append(
                {
                    **link,
                    "link_id": f"L-{hashlib.sha256(link_identity).hexdigest()[:16]}",
                }
            )
    return artifacts, chunks, deduped_links, excluded


def populate_sqlite_database(path: Path, report: dict[str, Any], artifacts: list[dict[str, Any]], chunks: list[dict[str, Any]], links: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    fts_available = False
    try:
        with connection:
            connection.execute(
                """
                CREATE TABLE index_runs (
                    run_id TEXT PRIMARY KEY,
                    generated_at TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    rules_hash TEXT,
                    status TEXT NOT NULL,
                    artifact_count INTEGER NOT NULL,
                    chunk_count INTEGER NOT NULL,
                    limitations TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    artifact_type TEXT,
                    authority_level TEXT,
                    profile_scope TEXT,
                    source_hash TEXT,
                    modified_at TEXT,
                    indexed_at TEXT,
                    freshness_status TEXT,
                    provenance TEXT,
                    include_policy TEXT,
                    exclusion_reason TEXT,
                    scope TEXT,
                    use_policy TEXT,
                    review_status TEXT,
                    source_reference TEXT,
                    confidence TEXT,
                    limitations TEXT,
                    recall_trace_readiness TEXT,
                    audit_event_readiness TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE artifact_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    section_heading TEXT,
                    chunk_kind TEXT,
                    text_summary TEXT,
                    bounded_excerpt TEXT,
                    start_line INTEGER,
                    end_line INTEGER,
                    char_count INTEGER,
                    confidence TEXT,
                    limitations TEXT,
                    scope TEXT,
                    use_policy TEXT,
                    review_status TEXT,
                    source_reference TEXT,
                    recall_trace_readiness TEXT,
                    audit_event_readiness TEXT,
                    related_task_ids TEXT,
                    related_spec_refs TEXT,
                    related_capabilities TEXT,
                    related_code_symbols TEXT,
                    related_tests TEXT,
                    FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE artifact_links (
                    link_id TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    link_type TEXT NOT NULL,
                    reference_id TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE report_summaries (
                    path TEXT PRIMARY KEY,
                    status TEXT,
                    summary_json TEXT,
                    human_review_required INTEGER
                )
                """
            )
            try:
                connection.execute(
                    """
                    CREATE VIRTUAL TABLE artifact_chunks_fts USING fts5(
                        chunk_id UNINDEXED,
                        artifact_id UNINDEXED,
                        path UNINDEXED,
                        section_heading,
                        text_summary,
                        bounded_excerpt
                    )
                    """
                )
                fts_available = True
            except sqlite3.OperationalError as exc:
                findings.append(
                    {
                        "id": "local_context_index.fts_unavailable",
                        "severity": "advisory",
                        "status": "advisory",
                        "message": f"SQLite FTS5 is unavailable; metadata/path lookup remains available. {exc}",
                    }
                )
            connection.execute(
                "INSERT INTO index_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "current",
                    report["generated_at"],
                    report["profile"],
                    report.get("rules_hash"),
                    report["status"],
                    len(artifacts),
                    len(chunks),
                    json.dumps(report.get("limitations") or [], sort_keys=True),
                ),
            )
            for artifact in artifacts:
                connection.execute(
                    """
                    INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact.get("artifact_id"),
                        artifact.get("path"),
                        artifact.get("artifact_type"),
                        artifact.get("authority_level"),
                        json.dumps(artifact.get("profile_scope"), sort_keys=True),
                        artifact.get("source_hash"),
                        artifact.get("modified_at"),
                        artifact.get("indexed_at"),
                        artifact.get("freshness_status"),
                        artifact.get("provenance"),
                        artifact.get("include_policy"),
                        artifact.get("exclusion_reason"),
                        artifact.get("scope"),
                        artifact.get("use_policy"),
                        artifact.get("review_status"),
                        artifact.get("source_reference"),
                        artifact.get("confidence"),
                        json.dumps(artifact.get("limitations") or [], sort_keys=True),
                        artifact.get("recall_trace_readiness"),
                        artifact.get("audit_event_readiness"),
                    ),
                )
                if artifact.get("artifact_type") == "deterministic_report":
                    connection.execute(
                        "INSERT OR REPLACE INTO report_summaries VALUES (?, ?, ?, ?)",
                        (
                            artifact.get("path"),
                            artifact.get("freshness_status"),
                            json.dumps({"source_hash": artifact.get("source_hash")}, sort_keys=True),
                            0,
                        ),
                    )
            for chunk in chunks:
                connection.execute(
                    """
                    INSERT INTO artifact_chunks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chunk.get("chunk_id"),
                        chunk.get("artifact_id"),
                        chunk.get("path"),
                        chunk.get("section_heading"),
                        chunk.get("chunk_kind"),
                        chunk.get("text_summary"),
                        chunk.get("bounded_excerpt"),
                        chunk.get("start_line"),
                        chunk.get("end_line"),
                        chunk.get("char_count"),
                        chunk.get("confidence"),
                        json.dumps(chunk.get("limitations") or [], sort_keys=True),
                        chunk.get("scope"),
                        chunk.get("use_policy"),
                        chunk.get("review_status"),
                        chunk.get("source_reference"),
                        chunk.get("recall_trace_readiness"),
                        chunk.get("audit_event_readiness"),
                        json.dumps(chunk.get("related_task_ids") or [], sort_keys=True),
                        json.dumps(chunk.get("related_spec_refs") or [], sort_keys=True),
                        json.dumps(chunk.get("related_capabilities") or [], sort_keys=True),
                        json.dumps(chunk.get("related_code_symbols") or [], sort_keys=True),
                        json.dumps(chunk.get("related_tests") or [], sort_keys=True),
                    ),
                )
                if fts_available:
                    connection.execute(
                        "INSERT INTO artifact_chunks_fts VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            chunk.get("chunk_id"),
                            chunk.get("artifact_id"),
                            chunk.get("path"),
                            chunk.get("section_heading"),
                            chunk.get("text_summary"),
                            chunk.get("bounded_excerpt"),
                        ),
                    )
            for link in links:
                connection.execute(
                    "INSERT INTO artifact_links VALUES (?, ?, ?, ?)",
                    (link.get("link_id"), link.get("source_path"), link.get("link_type"), link.get("reference_id")),
                )
    finally:
        connection.close()
    return fts_available, findings


def create_sqlite_artifact(
    path: Path,
    report: dict[str, Any],
    artifacts: list[dict[str, Any]],
    chunks: list[dict[str, Any]],
    links: list[dict[str, Any]],
    *,
    root: Path,
    naos_root: str,
    policy: dict[str, Any],
    profile: str,
    generated_at: str,
    session_id: str | None,
    generated_by: dict[str, Any],
) -> tuple[dict[str, Any], bool, list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if path.exists() and path.is_symlink():
        raise ValueError(f"Refusing to write SQLite artifact through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = sqlite_lock_path(root, naos_root, policy, path)
    temp_path = temp_db_path(path, session_id)
    coordination = sqlite_coordination_report_base(
        root=root,
        naos_root=naos_root,
        profile=profile,
        generated_at=generated_at,
        target_db_path=path,
        lock_path=lock_path,
        session_id=session_id,
        generated_by=generated_by,
    )
    coordination["temp_db_path"] = str(temp_path)
    coordination["findings"].append(
        finding(
            "sqlite_write_coordination.distributed_lock_not_provided",
            "advisory",
            "advisory",
            "SQLite coordination uses a local lock file only; distributed or network-filesystem locking is not claimed.",
        )
    )
    if not session_id:
        coordination["findings"].append(
            finding(
                "sqlite_write_coordination.session_metadata_unavailable",
                "advisory",
                "advisory",
                "No session_id was available for the SQLite coordination report; file integrity coordination still runs.",
            )
        )
    if not generated_by.get("operator_id"):
        coordination["findings"].append(
            finding(
                "sqlite_write_coordination.operator_metadata_unavailable",
                "advisory",
                "advisory",
                "No resolved operator_id was available for the SQLite coordination report; operator attribution is not required in quickstart.",
            )
        )
    lock_fd: int | None = None
    fts_available = False
    try:
        lock_fd, lock_result = acquire_sqlite_lock(
            lock_path,
            target_db_path=path,
            session_id=session_id,
            generated_by=generated_by,
            generated_at=generated_at,
            timeout_seconds=env_float("NAOS_SQLITE_LOCK_TIMEOUT_SECONDS", SQLITE_LOCK_TIMEOUT_SECONDS),
            stale_after_seconds=env_float("NAOS_SQLITE_STALE_LOCK_SECONDS", SQLITE_STALE_LOCK_SECONDS),
        )
        coordination["lock_acquired"] = bool(lock_result.get("lock_acquired"))
        coordination["lock_wait_seconds"] = lock_result.get("lock_wait_seconds", 0.0)
        coordination["stale_lock_detected"] = bool(lock_result.get("stale_lock_detected"))
        coordination["stale_lock_action"] = lock_result.get("stale_lock_action") or "not_applicable"
        coordination["findings"].extend(lock_result.get("findings") or [])
        if lock_fd is None:
            coordination["status"] = "lock_timeout" if any(item.get("status") == "lock_timeout" for item in coordination["findings"]) else "blocked"
            coordination["summary"] = {
                "status": coordination["status"],
                "lock_acquired": False,
                "atomic_replace_used": False,
                "tables_verified": 0,
                "target_db_hash_present": False,
            }
            artifact = {
                "enabled": True,
                "status": "not_written",
                "path": str(path),
                "role": "SQLite artifact was not replaced because the local write lock was unavailable.",
            }
            return artifact, False, coordination["findings"], coordination

        if temp_path.exists():
            temp_path.unlink()
            coordination["cleanup_actions"].append({"action": "preexisting_temp_removed", "path": str(temp_path), "status": "removed"})

        try:
            fts_available, populate_findings = populate_sqlite_database(temp_path, report, artifacts, chunks, links)
        except Exception as exc:
            coordination["status"] = "validation_failed"
            coordination["findings"].append(
                finding(
                    "sqlite_write_coordination.db_build_failed",
                    "blocking",
                    "validation_failed",
                    f"The generated temp SQLite index could not be built; the existing target DB was left unchanged. {exc}",
                    path=str(temp_path),
                )
            )
            if temp_path.exists():
                try:
                    temp_path.unlink()
                    coordination["cleanup_actions"].append({"action": "failed_build_temp_removed", "path": str(temp_path), "status": "removed"})
                except OSError as cleanup_exc:
                    coordination["cleanup_actions"].append(
                        {"action": "failed_build_temp_cleanup", "path": str(temp_path), "status": "failed", "error": str(cleanup_exc)}
                    )
            artifact = {
                "enabled": True,
                "status": "not_written",
                "path": str(path),
                "role": "SQLite artifact was not replaced because temp DB build failed.",
            }
            coordination["summary"] = {
                "status": coordination["status"],
                "lock_acquired": True,
                "atomic_replace_used": False,
                "tables_verified": 0,
                "target_db_hash_present": bool(safe_digest(path)),
            }
            return artifact, False, coordination["findings"], coordination
        findings.extend(populate_findings)
        coordination["findings"].extend(populate_findings)
        tables = verify_sqlite_tables(temp_path)
        missing_tables = [table for table in SQLITE_REQUIRED_TABLES if table not in tables]
        coordination["tables_verified"] = tables
        if missing_tables:
            coordination["status"] = "validation_failed"
            coordination["findings"].append(
                finding(
                    "sqlite_write_coordination.db_validation_failed",
                    "blocking",
                    "validation_failed",
                    "The generated temp SQLite index did not include all required tables; the existing target DB was left unchanged.",
                    missing_tables=missing_tables,
                    path=str(temp_path),
                )
            )
            if temp_path.exists():
                temp_path.unlink()
                coordination["cleanup_actions"].append({"action": "invalid_temp_removed", "path": str(temp_path), "status": "removed"})
            artifact = {
                "enabled": True,
                "status": "not_written",
                "path": str(path),
                "role": "SQLite artifact was not replaced because temp DB validation failed.",
            }
            coordination["summary"] = {
                "status": coordination["status"],
                "lock_acquired": True,
                "atomic_replace_used": False,
                "tables_verified": len(tables),
                "target_db_hash_present": False,
            }
            return artifact, fts_available, coordination["findings"], coordination

        try:
            os.replace(temp_path, path)
            coordination["atomic_replace_used"] = True
            coordination["cleanup_actions"].append({"action": "atomic_replace", "source": str(temp_path), "target": str(path), "status": "completed"})
        except OSError as exc:
            coordination["status"] = "replace_failed"
            coordination["findings"].append(
                finding(
                    "sqlite_write_coordination.atomic_replace_failed",
                    "blocking",
                    "replace_failed",
                    f"Atomic replacement of the SQLite index failed: {exc}",
                    path=str(path),
                )
            )
            if temp_path.exists():
                try:
                    temp_path.unlink()
                    coordination["cleanup_actions"].append({"action": "failed_replace_temp_removed", "path": str(temp_path), "status": "removed"})
                except OSError as cleanup_exc:
                    coordination["cleanup_actions"].append(
                        {"action": "failed_replace_temp_cleanup", "path": str(temp_path), "status": "failed", "error": str(cleanup_exc)}
                    )
                    coordination["findings"].append(
                        finding(
                            "sqlite_write_coordination.temp_cleanup_failed",
                            "warning",
                            "advisory",
                            f"Temp DB cleanup failed after replace failure: {cleanup_exc}",
                            path=str(temp_path),
                        )
                    )
            artifact = {
                "enabled": True,
                "status": "not_written",
                "path": str(path),
                "role": "SQLite artifact was not replaced because atomic replace failed.",
            }
            coordination["summary"] = {
                "status": coordination["status"],
                "lock_acquired": True,
                "atomic_replace_used": False,
                "tables_verified": len(tables),
                "target_db_hash_present": False,
            }
            return artifact, fts_available, coordination["findings"], coordination
    finally:
        release_action = release_sqlite_lock(lock_fd, lock_path)
        if release_action:
            coordination["cleanup_actions"].append(release_action)
            if release_action.get("status") == "failed":
                coordination["findings"].append(
                    finding(
                        "sqlite_write_coordination.lock_release_failed",
                        "warning",
                        "advisory",
                        "The local SQLite index lock could not be removed after the write attempt.",
                        path=str(lock_path),
                    )
                )
        if temp_path.exists() and coordination.get("atomic_replace_used") is not True:
            try:
                temp_path.unlink()
                coordination["cleanup_actions"].append({"action": "leftover_temp_removed", "path": str(temp_path), "status": "removed"})
            except OSError as exc:
                coordination["cleanup_actions"].append({"action": "leftover_temp_cleanup", "path": str(temp_path), "status": "failed", "error": str(exc)})
                coordination["findings"].append(
                    finding(
                        "sqlite_write_coordination.temp_cleanup_failed",
                        "warning",
                        "advisory",
                        f"Temp DB cleanup failed: {exc}",
                        path=str(temp_path),
                    )
                )

    stat = path.stat()
    target_hash = safe_digest(path)
    coordination["target_db_hash"] = target_hash
    if not coordination.get("status") or coordination["status"] == "not_configured":
        coordination["status"] = "advisory" if coordination["findings"] else "ready"
    if coordination.get("stale_lock_detected") and coordination.get("status") == "ready":
        coordination["status"] = "stale_lock_detected"
    coordination["summary"] = {
        "status": coordination["status"],
        "lock_acquired": bool(coordination.get("lock_acquired")),
        "lock_wait_seconds": coordination.get("lock_wait_seconds", 0.0),
        "atomic_replace_used": bool(coordination.get("atomic_replace_used")),
        "tables_verified": len(coordination.get("tables_verified") or []),
        "target_db_hash_present": bool(target_hash),
        "wal_requested": False,
        "wal_effective": False,
    }
    artifact = {
        "enabled": True,
        "status": "written",
        "path": str(path),
        "size_bytes": stat.st_size,
        "tables": ["index_runs", "artifacts", "artifact_chunks", "artifact_links", "report_summaries"],
        "fts_table": "artifact_chunks_fts" if fts_available else None,
        "rebuild_mode": "full_deterministic_rebuild",
        "role": "generated derived cache-like retrieval substrate; not authoritative evidence",
    }
    if fts_available:
        artifact["tables"].append("artifact_chunks_fts")
    return artifact, fts_available, coordination["findings"], coordination


def sqlite_output_path(root: Path, naos_root: str, policy: dict[str, Any], rules: dict[str, Any], explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    if is_kit_repository(root, naos_root) or not (root / naos_root).is_dir():
        return None
    configured = policy.get("paths", {}).get("local_context_index_sqlite")
    if configured:
        return safe_policy_path(root / naos_root, str(configured), field="local_context_index_sqlite")
    rules_path = str((rules.get("sqlite_artifact") or {}).get("path") or "context_index/local_context_index.sqlite")
    return safe_policy_path(root / naos_root, rules_path, field="local_context_index.sqlite_artifact.path")


def build_findings(
    *,
    rules: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
    indexed_artifacts: list[dict[str, Any]],
    excluded_artifacts: list[dict[str, Any]],
    fts_available: bool,
    sqlite_written: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    severity = severity_for_profile(profile, policy)
    if not indexed_artifacts:
        findings.append(
            {
                "id": "local_context_index.no_indexed_artifacts",
                "severity": "advisory" if profile in {"quickstart", "lite"} else severity,
                "status": "not_configured",
                "message": "No indexable artifacts were found under the configured include patterns.",
            }
        )
    if not sqlite_written and (rules.get("sqlite_artifact") or {}).get("enabled", True):
        findings.append(
            {
                "id": "local_context_index.sqlite_not_written",
                "severity": "advisory",
                "status": "advisory",
                "message": "SQLite artifact was not written because this is the kit repository, NAOS_ROOT is missing, or --no-sqlite was used.",
            }
        )
    if (rules.get("fts") or {}).get("enabled", True) and not fts_available:
        findings.append(
            {
                "id": "local_context_index.fts_unavailable_or_skipped",
                "severity": "advisory",
                "status": "advisory",
                "message": "FTS5 is unavailable or SQLite output was skipped; path and metadata lookup remain the v1 fallback.",
            }
        )
    if (rules.get("future_semantic_vector_layer") or {}).get("extension_loading_allowed") is not False:
        findings.append(
            {
                "id": "local_context_index.semantic_extension_policy_unclear",
                "severity": severity,
                "status": "review_required",
                "message": "Future semantic/vector layer policy must keep SQLite extension loading disabled in v1.",
            }
        )
    if any(item.get("reason") == "sensitive_name_or_extension" for item in excluded_artifacts):
        findings.append(
            {
                "id": "local_context_index.sensitive_paths_excluded",
                "severity": "advisory",
                "status": "advisory",
                "message": "Sensitive-looking paths were excluded and remain visible for review.",
            }
        )
    if any(item.get("reason") == "secret_like_content_excluded" for item in excluded_artifacts):
        findings.append(
            {
                "id": "local_context_index.secret_content_excluded",
                "severity": severity,
                "status": "review_required",
                "message": "Artifacts containing non-placeholder secret-like values were excluded before chunking or SQLite publication.",
            }
        )
    unsafe_sources = [
        item
        for item in excluded_artifacts
        if item.get("reason") in UNSAFE_SOURCE_TOPOLOGY_REASONS
    ]
    if unsafe_sources:
        findings.append(
            {
                "id": "local_context_index.unsafe_in_scope_source",
                "severity": "blocking",
                "status": "blocked",
                "message": "At least one in-scope source has unsafe filesystem topology and was not read.",
                "sources": [
                    {"path": item.get("path"), "reason": item.get("reason")}
                    for item in unsafe_sources[:20]
                ],
            }
        )
    return findings


def report_status(findings: list[dict[str, Any]], rules_enabled: bool) -> str:
    if not rules_enabled:
        return "disabled"
    severities = {str(item.get("severity")) for item in findings}
    statuses = {str(item.get("status")) for item in findings}
    if "blocking" in severities or "blocked" in statuses:
        return "blocked"
    if "required" in severities or "review_required" in statuses:
        return "review_required"
    if findings:
        return "advisory"
    return "ready"


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    policy: dict[str, Any],
    rules: dict[str, Any],
    rules_path: Path,
    rules_source: str,
    *,
    no_sqlite: bool = False,
    sqlite_output: str | None = None,
) -> dict[str, Any]:
    generated_at = utc_now_text()
    rules_hash = safe_digest(rules_path)
    session_id = latest_session_id(root, naos_root, policy)
    generated_by = build_generated_by(root, session_id=session_id, generated_at=generated_at)
    if not rules.get("enabled", True):
        return {
            "schema": REPORT_SCHEMA,
            "generated_at": generated_at,
            "profile": profile,
            "status": "disabled",
            "naos_root": naos_root,
            "project_root": str(root),
            "rules_path": str(rules_path),
            "rules_source": rules_source,
            "rules_hash": rules_hash,
            "sqlite_artifact": {"enabled": False, "status": "disabled", "path": None},
            "sqlite_write_coordination": sqlite_coordination_report_base(
                root=root,
                naos_root=naos_root,
                profile=profile,
                generated_at=generated_at,
                target_db_path=None,
                lock_path=None,
                session_id=session_id,
                generated_by=generated_by,
            ),
            "sqlite_version": sqlite3.sqlite_version,
            "fts_available": False,
            "fts_query_sanitization": {"enabled": False},
            "source_families": [],
            "indexed_artifacts": [],
            "excluded_artifacts": [],
            "artifact_type_counts": {},
            "authority_level_counts": {},
            "chunk_counts": {"artifacts": 0, "chunks": 0},
            "link_counts": {"links": 0},
            "freshness_summary": {},
            "memory_policy": rules.get("memory_indexing_policy") or {},
            "memory_provider_access": load_memory_provider_access(root, naos_root, policy),
            "memory_use_policy": load_memory_use_policy(root, naos_root, policy),
            "future_semantic_layer": rules.get("future_semantic_vector_layer") or {},
            "semantic_candidate_layer_readiness": load_semantic_candidate_readiness(root, naos_root, policy),
            "future_graph_layer": rules.get("future_graph_layer") or {},
            "graph_context_readiness": load_graph_context_readiness(root, naos_root, policy),
            "query_modes_supported": {},
            "task_context_pack_integration": {},
            "findings": [],
            "known_gaps": rules.get("known_gaps") or [],
            "residual_risks": rules.get("residual_risks") or [],
            "limitations": rules.get("limitations") or [],
            "not_claimed": rules.get("not_claimed") or [],
            "human_review_required": False,
            "summary": {"status": "disabled"},
        }

    artifacts, chunks, links, excluded = build_artifact_records(root, rules, generated_at)
    artifact_counts = Counter(str(item.get("artifact_type")) for item in artifacts)
    authority_counts = Counter(str(item.get("authority_level")) for item in artifacts)
    freshness_counts = Counter(str(item.get("freshness_status")) for item in artifacts)
    families = []
    for family in rules.get("artifact_families") or []:
        if not isinstance(family, dict):
            continue
        family_id = str(family.get("id"))
        families.append(
            {
                "id": family_id,
                "name": family.get("name"),
                "artifact_type": family.get("artifact_type"),
                "authority_level": family.get("authority_level"),
                "indexed_artifacts": sum(1 for item in artifacts if item.get("family_id") == family_id),
                "include_policy": family.get("include_policy"),
            }
        )

    sqlite_path = None if no_sqlite or not (rules.get("sqlite_artifact") or {}).get("enabled", True) else sqlite_output_path(root, naos_root, policy, rules, sqlite_output)
    sqlite_artifact: dict[str, Any]
    fts_available = False
    sqlite_findings: list[dict[str, Any]] = []
    provisional_report = {
        "generated_at": generated_at,
        "profile": profile,
        "status": "ready",
        "rules_hash": rules_hash,
        "limitations": rules.get("limitations") or [],
    }
    if sqlite_path is not None:
        sqlite_artifact, fts_available, sqlite_findings, sqlite_coordination = create_sqlite_artifact(
            sqlite_path,
            provisional_report,
            artifacts,
            chunks,
            links,
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            generated_at=generated_at,
            session_id=session_id,
            generated_by=generated_by,
        )
    else:
        sqlite_artifact = {
            "enabled": bool((rules.get("sqlite_artifact") or {}).get("enabled", True)) and not no_sqlite,
            "status": "not_written",
            "path": None,
            "role": "SQLite artifact skipped; JSON report remains available.",
        }
        sqlite_coordination = sqlite_coordination_report_base(
            root=root,
            naos_root=naos_root,
            profile=profile,
            generated_at=generated_at,
            target_db_path=None,
            lock_path=None,
            session_id=session_id,
            generated_by=generated_by,
        )
        sqlite_coordination["status"] = "not_configured"
        sqlite_coordination["summary"]["status"] = "not_configured"

    findings = build_findings(
        rules=rules,
        profile=profile,
        policy=policy,
        indexed_artifacts=artifacts,
        excluded_artifacts=excluded,
        fts_available=fts_available,
        sqlite_written=sqlite_artifact.get("status") == "written",
    )
    findings.extend(sqlite_findings)
    counts = finding_counts(findings)
    status = report_status(findings, True)
    human_review_required = any(item.get("severity") in {"required", "blocking"} or item.get("status") == "review_required" for item in findings)
    fts_policy = rules.get("fts") or {}
    query_sanitization = fts_policy.get("query_sanitization") or {}
    max_query_chars = int(query_sanitization.get("max_query_chars") or 120)
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": status,
        "naos_root": naos_root,
        "project_root": str(root),
        "rules_path": str(rules_path),
        "rules_source": rules_source,
        "rules_hash": rules_hash,
        "sqlite_artifact": sqlite_artifact,
        "sqlite_write_coordination": sqlite_coordination,
        "sqlite_version": sqlite3.sqlite_version,
        "fts_available": fts_available,
        "fts_query_sanitization": {
            "enabled": bool(query_sanitization.get("enabled", True)),
            "max_query_chars": max_query_chars,
            "allowed_token_pattern": query_sanitization.get("allowed_token_pattern"),
            "no_raw_llm_match_queries": bool(query_sanitization.get("no_raw_llm_match_queries", True)),
            "example": sanitize_fts_query('status:ready OR "secret" NEAR report', max_query_chars),
        },
        "source_families": families,
        "indexed_artifacts": artifacts,
        "excluded_artifacts": excluded,
        "artifact_chunks": chunks[:200],
        "artifact_links": links[:200],
        "artifact_type_counts": dict(sorted(artifact_counts.items())),
        "authority_level_counts": dict(sorted(authority_counts.items())),
        "chunk_counts": {
            "artifacts": len(artifacts),
            "chunks": len(chunks),
            "chunks_with_task_refs": sum(1 for chunk in chunks if chunk.get("related_task_ids")),
            "chunks_with_spec_refs": sum(1 for chunk in chunks if chunk.get("related_spec_refs")),
        },
        "link_counts": {
            "links": len(links),
            "task_refs": sum(1 for item in links if item.get("link_type") == "task_ref"),
            "spec_refs": sum(1 for item in links if item.get("link_type") == "spec_ref"),
            "capability_refs": sum(1 for item in links if item.get("link_type") == "capability_ref"),
        },
        "freshness_summary": dict(sorted(freshness_counts.items())),
        "memory_policy": rules.get("memory_indexing_policy") or {},
        "memory_provider_access": load_memory_provider_access(root, naos_root, policy),
        "memory_use_policy": load_memory_use_policy(root, naos_root, policy),
        "future_semantic_layer": rules.get("future_semantic_vector_layer") or {},
        "semantic_candidate_layer_readiness": load_semantic_candidate_readiness(root, naos_root, policy),
        "future_graph_layer": rules.get("future_graph_layer") or {},
        "graph_context_readiness": load_graph_context_readiness(root, naos_root, policy),
        "query_modes_supported": {
            "exact_path_lookup": True,
            "metadata_filtering": True,
            "fts_keyword_search": fts_available,
            "relationship_link_lookup": True,
            "semantic_candidate_retrieval": False,
            "vector_search": False,
            "graph_traversal": False,
            "rule": "Index results are bounded candidates only; source artifacts must still be checked directly.",
        },
        "task_context_pack_integration": {
            "status": "ready" if artifacts else "advisory",
            "report_path": str(report_default_path(root, naos_root, policy, "local_context_index_report")),
            "usage": "Task context packs may reference index summaries/candidates without treating them as authority.",
            "source_artifacts_remain_authoritative": True,
            "memory_remains_advisory": True,
        },
        "findings": findings,
        "known_gaps": rules.get("known_gaps") or [],
        "residual_risks": rules.get("residual_risks") or [],
        "limitations": rules.get("limitations") or [],
        "not_claimed": rules.get("not_claimed") or [],
        "human_review_required": human_review_required,
        "summary": {
            "status": status,
            "indexed_artifacts": len(artifacts),
            "excluded_artifacts": len(excluded),
            "chunks": len(chunks),
            "links": len(links),
            "fts_available": fts_available,
            "sqlite_written": sqlite_artifact.get("status") == "written",
            "stale_artifacts": freshness_counts.get("stale", 0),
            "human_review_required": human_review_required,
            **counts,
        },
    }
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a deterministic local NAOS context index.")
    parser.add_argument("--profile", help="Profile name: quickstart, lite, standard, assured.")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"), help="Generated project NAOS root. Default from policy or naos.")
    parser.add_argument("--policy", help="Optional policy file.")
    parser.add_argument("--rules", help="Optional local_context_index_rules.yaml path.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--sqlite-output", help="Optional SQLite artifact output path.")
    parser.add_argument("--no-sqlite", action="store_true", help="Emit JSON report only; do not write the SQLite artifact.")
    parser.add_argument("--rebuild", action="store_true", help="Accepted for ergonomics; v1 always performs a deterministic full rebuild.")
    parser.add_argument("--strict", action="store_true", help="Use strict profile exit-code behavior.")
    parser.add_argument("--json", action="store_true", help="Print JSON report. Default is JSON for script consistency.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path, rules_source = resolve_rules_path(root, naos_root, policy, args.rules)
    rules = load_yaml_mapping(rules_path)
    report = build_report(
        root,
        naos_root,
        profile,
        policy,
        rules,
        rules_path,
        rules_source,
        no_sqlite=args.no_sqlite,
        sqlite_output=args.sqlite_output,
    )
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "local_context_index_report")
    write_report(output, report)
    coordination = report.get("sqlite_write_coordination")
    coordination_path = report_output_path(root, naos_root, policy, "sqlite_write_coordination_report")
    if isinstance(coordination, dict):
        write_report(coordination_path, coordination)
    if args.output is None:
        write_audit_event(
            root=root,
            naos_root=naos_root,
            policy=policy,
            profile=profile,
            event_type="context_index_generated",
            source_report_path=output,
            source_report=report,
            session_id=report.get("sqlite_write_coordination", {}).get("session_id") if isinstance(report.get("sqlite_write_coordination"), dict) else None,
            generated_by=report.get("sqlite_write_coordination", {}).get("generated_by") if isinstance(report.get("sqlite_write_coordination"), dict) else None,
            related_artifacts=[str(path) for path in [output, coordination_path] if path is not None],
        )
        if isinstance(coordination, dict):
            write_audit_event(
                root=root,
                naos_root=naos_root,
                policy=policy,
                profile=profile,
                event_type="sqlite_coordination_completed",
                source_report_path=coordination_path,
                source_report=coordination,
                session_id=coordination.get("session_id"),
                generated_by=coordination.get("generated_by"),
                related_artifacts=[str(path) for path in [coordination_path] if path is not None],
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code_for_summary(profile, report.get("summary", {}), policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
