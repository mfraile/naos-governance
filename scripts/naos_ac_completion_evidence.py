#!/usr/bin/env python3
"""Validate declared AC/SCEN completion evidence without inferring completion."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

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

SCHEMA = "naos.ac_completion_evidence.v1"
MANIFEST_SCHEMA = "naos.ac_completion_evidence_manifest.v1"
AC_SCEN_RE = re.compile(r"\b((?:AC|SCEN)-[A-Z0-9][A-Z0-9_.-]*)\b", re.IGNORECASE)
EVIDENCE_TYPES = {"test_report", "validator_report", "command_output", "manual_review"}
DETERMINISTIC_EVIDENCE_TYPES = EVIDENCE_TYPES - {"manual_review"}
CLAIMED_COMPLETE = "claimed_complete"
KNOWN_STATUSES = {CLAIMED_COMPLETE, "not_claimed", "deferred", "review_only"}
RECORD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
OID_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
PATH_LIKE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
SUPPORTED_SUBJECT_MODES = {"040000", "100644", "100755"}
SHELL_CONTROL_CHARS = frozenset(";&|<>()")


def utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def default_manifest_path(root: Path, naos_root: str, policy: dict[str, Any]) -> Path:
    manifest_name = str(policy.get("paths", {}).get("ac_completion_evidence_manifest") or "ac_completion_evidence.yaml")
    return root / naos_root / manifest_name


def load_manifest(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.is_file():
        return {}, None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return {}, str(exc)
    if not isinstance(data, dict):
        return {}, "Manifest root must be a mapping."
    return data, None


def is_placeholder_id(token: str) -> bool:
    upper = token.upper()
    return "XXX" in upper or upper in {"SCEN-N.M", "AC-N.M"}


def collect_defined_ac_scen(specs_root: Path) -> set[str]:
    defined: set[str] = set()
    if not specs_root.is_dir():
        return defined
    for md in sorted(specs_root.rglob("*.md")):
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in AC_SCEN_RE.findall(text):
            token = match.upper()
            if not is_placeholder_id(token):
                defined.add(token)
    return defined


def rel_display(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def resolve_in_repo(root: Path, raw_path: Any) -> tuple[Path | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "Evidence item is missing a path."
    candidate = Path(raw_path.strip())
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return candidate, "Evidence path must stay inside the project root."
    return resolved, None


def make_finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    ac_id: str | None = None,
    path: str | None = None,
    record_id: str | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": True,
        "not_claimed": [
            "AC completion correctness",
            "complete test coverage",
            "implementation correctness",
            "semantic quality",
            "approval",
        ],
    }
    if ac_id:
        finding["ac_id"] = ac_id
    if path:
        finding["path"] = path
    if record_id:
        finding["record_id"] = record_id
    return finding


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(
            args=["git", "-C", str(root), *args],
            returncode=127,
            stdout="",
            stderr=str(exc),
        )


def git_oid(root: Path, expression: str) -> str | None:
    result = run_git(root, "rev-parse", "--verify", "--end-of-options", expression)
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and OID_RE.fullmatch(value) else None


def repository_binding_status(
    *,
    root: Path,
    binding: Any,
    ac_id: str,
    severity: str,
    record_id: str | None,
) -> tuple[bool, bool, list[dict[str, Any]], dict[str, Any]]:
    if binding is None:
        return False, False, [], {
            "requested": False,
            "status": "not_requested",
            "validation_scope": "git_object_database",
        }

    findings: list[dict[str, Any]] = []
    normalized: dict[str, Any] = {
        "requested": True,
        "status": "invalid",
        "validation_scope": "git_object_database",
        "base_commit": None,
        "base_tree": None,
        "subject_commit": None,
        "subject_tree": None,
        "head_commit": None,
        "subject_reachable_from_head": False,
        "subject_is_head": False,
        "worktree_clean_at_validation": None,
    }
    if not isinstance(binding, dict):
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:invalid_repository_binding",
                severity=severity,
                status="invalid_repository_binding",
                message="repository_binding must be a mapping.",
                ac_id=ac_id,
                record_id=record_id,
            )
        )
        return True, False, findings, normalized

    required_fields = ("base_commit", "subject_commit", "subject_tree")
    declared: dict[str, str] = {}
    for field in required_fields:
        raw = binding.get(field)
        value = str(raw or "").strip().lower()
        declared[field] = value
        normalized[field] = value or None
        if not value:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:repository_binding_missing_{field}",
                    severity=severity,
                    status="repository_binding_missing_field",
                    message=f"repository_binding requires {field}.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )
        elif not OID_RE.fullmatch(value):
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:repository_binding_invalid_{field}",
                    severity=severity,
                    status="repository_binding_oid_not_canonical",
                    message=f"{field} must be a full 40- or 64-character hexadecimal Git object id.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )

    top_level = run_git(root, "rev-parse", "--show-toplevel")
    try:
        actual_root = Path(top_level.stdout.strip()).resolve()
    except (OSError, ValueError):
        actual_root = Path()
    if top_level.returncode != 0 or actual_root != root.resolve():
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:repository_binding_git_unavailable",
                severity=severity,
                status="repository_binding_git_unavailable",
                message="The project root is not the exact root of an available Git worktree.",
                ac_id=ac_id,
                record_id=record_id,
            )
        )
        return True, False, findings, normalized

    base_commit = (
        git_oid(root, f"{declared['base_commit']}^{{commit}}")
        if OID_RE.fullmatch(declared["base_commit"])
        else None
    )
    subject_commit = (
        git_oid(root, f"{declared['subject_commit']}^{{commit}}")
        if OID_RE.fullmatch(declared["subject_commit"])
        else None
    )
    if declared["base_commit"] and base_commit != declared["base_commit"]:
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:repository_binding_base_unresolved",
                severity=severity,
                status="repository_binding_commit_unresolved",
                message="base_commit does not resolve exactly to a commit in the project repository.",
                ac_id=ac_id,
                record_id=record_id,
            )
        )
    if declared["subject_commit"] and subject_commit != declared["subject_commit"]:
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:repository_binding_subject_unresolved",
                severity=severity,
                status="repository_binding_commit_unresolved",
                message="subject_commit does not resolve exactly to a commit in the project repository.",
                ac_id=ac_id,
                record_id=record_id,
            )
        )

    if base_commit and subject_commit:
        normalized["base_commit"] = base_commit
        normalized["subject_commit"] = subject_commit
        base_tree = git_oid(root, f"{base_commit}^{{tree}}")
        subject_tree = git_oid(root, f"{subject_commit}^{{tree}}")
        normalized["base_tree"] = base_tree
        normalized["subject_tree"] = subject_tree
        if base_commit == subject_commit:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:repository_binding_same_commit",
                    severity=severity,
                    status="repository_binding_base_not_before_subject",
                    message="base_commit and subject_commit must identify different commits.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )
        ancestry = run_git(root, "merge-base", "--is-ancestor", base_commit, subject_commit)
        if ancestry.returncode != 0:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:repository_binding_base_not_ancestor",
                    severity=severity,
                    status="repository_binding_base_not_ancestor",
                    message="base_commit must be an ancestor of subject_commit.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )
        if subject_tree != declared["subject_tree"]:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:repository_binding_subject_tree_mismatch",
                    severity=severity,
                    status="repository_binding_subject_tree_mismatch",
                    message="subject_tree does not match the tree of subject_commit.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )

        head_commit = git_oid(root, "HEAD^{commit}")
        normalized["head_commit"] = head_commit
        if head_commit:
            normalized["subject_is_head"] = head_commit == subject_commit
            reachable = run_git(root, "merge-base", "--is-ancestor", subject_commit, head_commit).returncode == 0
            normalized["subject_reachable_from_head"] = reachable
            if not reachable:
                findings.append(
                    make_finding(
                        finding_id=f"{ac_id}:repository_binding_subject_not_reachable",
                        severity=severity,
                        status="repository_binding_subject_not_reachable",
                        message="subject_commit is not reachable from the current checkout HEAD.",
                        ac_id=ac_id,
                        record_id=record_id,
                    )
                )
        else:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:repository_binding_head_unavailable",
                    severity=severity,
                    status="repository_binding_head_unavailable",
                    message="The current checkout has no resolvable HEAD commit.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )

    worktree = run_git(root, "status", "--porcelain", "--untracked-files=all")
    if worktree.returncode == 0:
        normalized["worktree_clean_at_validation"] = not bool(worktree.stdout)

    valid = not findings
    normalized["status"] = "ready" if valid else "invalid"
    return True, valid, findings, normalized


def normalized_subject_path(raw: str) -> tuple[str | None, str | None]:
    value = raw.strip()
    if "::" in value:
        value = value.split("::", 1)[0]
    if re.search(r":\d+(?::\d+)?$", value):
        value = re.sub(r":\d+(?::\d+)?$", "", value)
    value = value.replace("\\", "/")
    if value == ".":
        return ".", None
    if any(marker in value for marker in ("\x00", "\r", "\n")):
        return None, "Subject-tree operands must not contain control characters."
    if not value or value.startswith("/") or re.match(r"^[A-Za-z]:/", value):
        return None, "Subject-tree operands must be repository-relative paths."
    if any(char in value for char in "*?["):
        return None, "Subject-tree operands must be exact paths, not globs."
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        return None, "Subject-tree operands must not contain empty, current-directory, or parent-directory segments."
    path = PurePosixPath(value)
    return path.as_posix(), None


def path_shaped_candidate(raw: str) -> bool:
    normalized = raw.replace("\\", "/")
    suffix = PurePosixPath(normalized).suffix.lower()
    return raw in {".", ".."} or "/" in raw or "\\" in raw or suffix in PATH_LIKE_SUFFIXES


def supported_colon_path_token(raw: str) -> bool:
    if "::" in raw:
        base, selector = raw.split("::", 1)
        return bool(selector) and path_shaped_candidate(base)
    line_selector = re.fullmatch(r"(.+):\d+(?::\d+)?", raw)
    return bool(line_selector and path_shaped_candidate(line_selector.group(1)))


def command_path_operands(command: Any) -> tuple[list[str], str | None]:
    if not isinstance(command, str) or not command.strip():
        return [], None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in command):
        return [], (
            "C0 and DEL control characters are not supported for subject-tree operand verification."
        )
    if "://" in command:
        return [], "URL-bearing command operands are not supported for subject-tree operand verification."
    if "@" in command:
        return [], "Response-file command operands are not supported for subject-tree operand verification."
    if any(
        marker in command
        for marker in (
            "\x00",
            "\r",
            "\n",
            "`",
            "$",
            "~",
            "{",
            "}",
            "#",
            "(",
            ")",
            "*",
            "?",
            "[",
            "]",
            "!",
        )
    ):
        return [], (
            "Dynamic, expansion-bearing, comment-bearing, grouped, or multi-line shell commands "
            "are not supported for subject-tree operand verification."
        )
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as exc:
        return [], f"Command operands could not be parsed deterministically: {exc}"
    if any(token and set(token) <= SHELL_CONTROL_CHARS for token in tokens):
        return [], "Compound shell commands are not supported for subject-tree operand verification."
    if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\+)?=.*", token) for token in tokens):
        return [], "Environment-assignment command prefixes are not supported for subject-tree operand verification."

    operands: list[str] = []
    for token in tokens:
        if not token:
            continue
        if token.startswith("-"):
            attached_value = token.split("=", 1)[1] if "=" in token else token.lstrip("-")
            if ":" in attached_value and not supported_colon_path_token(attached_value):
                return [], (
                    "Colon-bearing command-option values outside supported path selectors are not "
                    "supported for subject-tree operand verification."
                )
            candidate = attached_value.split("::", 1)[0]
            candidate = re.sub(r":\d+(?::\d+)?$", "", candidate)
            if path_shaped_candidate(candidate):
                return [], (
                    "Path-shaped values attached to command options are not supported for "
                    "subject-tree operand verification."
                )
            continue
        if ":" in token and not supported_colon_path_token(token):
            return [], (
                "Colon-bearing command operands outside supported path selectors are not supported "
                "for subject-tree operand verification."
            )
        candidate = token.split("::", 1)[0]
        candidate = re.sub(r":\d+(?::\d+)?$", "", candidate)
        if path_shaped_candidate(candidate):
            operands.append(token)
    return list(dict.fromkeys(operands)), None


def subject_path_receipt(root: Path, subject_tree: str, raw_path: str) -> tuple[dict[str, Any], str | None]:
    normalized, error = normalized_subject_path(raw_path)
    receipt: dict[str, Any] = {
        "operand": raw_path,
        "path": normalized,
        "status": "invalid" if error else "missing",
        "mode": None,
        "object_type": None,
        "object_id": None,
    }
    if error:
        return receipt, error
    if normalized == ".":
        receipt.update({"status": "ready", "mode": "040000", "object_type": "tree", "object_id": subject_tree})
        return receipt, None

    result = run_git(root, "ls-tree", "-z", subject_tree, "--", normalized or "")
    if result.returncode != 0:
        return receipt, "Git could not inspect the declared subject-tree operand."
    entries = [entry for entry in result.stdout.split("\x00") if entry]
    match = None
    for entry in entries:
        metadata, separator, path_text = entry.partition("\t")
        if separator and path_text == normalized:
            match = metadata.split()
            break
    if not match or len(match) != 3:
        return receipt, "Path-shaped command operand does not exist in subject_tree."
    mode, object_type, object_id = match
    receipt.update({"mode": mode, "object_type": object_type, "object_id": object_id})
    if mode not in SUPPORTED_SUBJECT_MODES:
        receipt["status"] = "unsupported_type"
        return receipt, "Subject-tree operand is a symlink, gitlink, or other unsupported object mode."
    receipt["status"] = "ready"
    return receipt, None


def evidence_status(
    *,
    root: Path,
    evidence: dict[str, Any],
    ac_id: str,
    severity: str,
    freshness_days: int | None,
    now: datetime,
    record_id: str | None,
    repository_binding_requested: bool,
    repository_binding_valid: bool,
    subject_tree: str | None,
) -> tuple[bool, list[dict[str, Any]], dict[str, Any]]:
    evidence_type = str(evidence.get("type") or "").strip()
    outcome = str(evidence.get("outcome") or "").strip().lower()
    raw_path = evidence.get("path")
    display_path = raw_path if isinstance(raw_path, str) else None
    normalized: dict[str, Any] = {
        "type": evidence_type,
        "path": display_path,
        "command": evidence.get("command"),
        "outcome": outcome,
        "generated_at": evidence.get("generated_at"),
        "notes": evidence.get("notes"),
        "satisfies_deterministic_completion": False,
        "subject_operand_validation": {
            "status": "not_requested",
            "operands": [],
        },
    }
    findings: list[dict[str, Any]] = []

    if evidence_type not in EVIDENCE_TYPES:
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:unsupported_evidence_type",
                severity=severity,
                status="unsupported_evidence_type",
                message=f"Evidence type {evidence_type!r} is not supported.",
                ac_id=ac_id,
                path=display_path,
                record_id=record_id,
            )
        )
        return False, findings, normalized

    if evidence_type == "manual_review":
        normalized["review_only"] = True
        return False, findings, normalized

    if not isinstance(evidence.get("command"), str) or not evidence.get("command", "").strip():
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:missing_evidence_command",
                severity=severity,
                status="missing_evidence_command",
                message="Deterministic evidence must include the command or validator that produced it.",
                ac_id=ac_id,
                path=display_path,
                record_id=record_id,
            )
        )

    if outcome != "pass":
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:evidence_not_passing",
                severity=severity,
                status="evidence_not_passing",
                message="Claimed-complete AC evidence must have outcome: pass.",
                ac_id=ac_id,
                path=display_path,
                record_id=record_id,
            )
        )

    resolved, path_error = resolve_in_repo(root, raw_path)
    if path_error:
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:invalid_evidence_path",
                severity=severity,
                status="invalid_evidence_path",
                message=path_error,
                ac_id=ac_id,
                path=display_path,
                record_id=record_id,
            )
        )
    elif resolved is not None and not resolved.is_file():
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:missing_evidence_path",
                severity=severity,
                status="missing_evidence_path",
                message="Declared evidence path does not exist.",
                ac_id=ac_id,
                path=rel_display(root, resolved),
                record_id=record_id,
            )
        )
    elif resolved is not None:
        normalized["path"] = rel_display(root, resolved)

    generated_at = parse_timestamp(evidence.get("generated_at"))
    if evidence.get("generated_at") and generated_at is None:
        findings.append(
            make_finding(
                finding_id=f"{ac_id}:invalid_evidence_timestamp",
                severity="advisory",
                status="invalid_evidence_timestamp",
                message="Evidence generated_at timestamp is not parseable.",
                ac_id=ac_id,
                path=display_path,
                record_id=record_id,
            )
        )
    if freshness_days is not None and generated_at is not None:
        age_limit = now - timedelta(days=freshness_days)
        if generated_at < age_limit:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:stale_evidence",
                    severity="advisory",
                    status="stale_evidence",
                    message=f"Evidence is older than configured freshness window ({freshness_days} days).",
                    ac_id=ac_id,
                    path=display_path,
                    record_id=record_id,
                )
            )

    operand_validation_ok = True
    if repository_binding_requested:
        if not repository_binding_valid or not subject_tree:
            operand_validation_ok = False
            normalized["subject_operand_validation"] = {
                "status": "blocked_by_repository_binding",
                "operands": [],
            }
        else:
            operands, parse_error = command_path_operands(evidence.get("command"))
            receipts: list[dict[str, Any]] = []
            if parse_error:
                operand_validation_ok = False
                findings.append(
                    make_finding(
                        finding_id=f"{ac_id}:command_operand_parse_error",
                        severity=severity,
                        status="command_operand_parse_error",
                        message=parse_error,
                        ac_id=ac_id,
                        record_id=record_id,
                    )
                )
            for operand in operands:
                receipt, operand_error = subject_path_receipt(root, subject_tree, operand)
                receipts.append(receipt)
                if operand_error:
                    operand_validation_ok = False
                    findings.append(
                        make_finding(
                            finding_id=f"{ac_id}:subject_operand:{len(receipts)}",
                            severity=severity,
                            status="subject_operand_invalid",
                            message=operand_error,
                            ac_id=ac_id,
                            path=receipt.get("path") or operand,
                            record_id=record_id,
                        )
                    )
            if not parse_error and not receipts:
                operand_validation_ok = False
                findings.append(
                    make_finding(
                        finding_id=f"{ac_id}:subject_operand_not_identified",
                        severity=severity,
                        status="subject_operand_not_identified",
                        message=(
                            "Repository-bound deterministic evidence must expose at least one "
                            "conservatively recognized path operand for subject-tree verification."
                        ),
                        ac_id=ac_id,
                        record_id=record_id,
                    )
                )
            normalized["subject_operand_validation"] = {
                "status": "ready" if operand_validation_ok else "invalid",
                "operands": receipts,
            }

    satisfied = evidence_type in DETERMINISTIC_EVIDENCE_TYPES and outcome == "pass" and not any(
        item["status"] in {"missing_evidence_command", "invalid_evidence_path", "missing_evidence_path"}
        for item in findings
    ) and operand_validation_ok
    normalized["satisfies_deterministic_completion"] = satisfied
    return satisfied, findings, normalized


def build_report(
    *,
    root: Path,
    profile: str,
    naos_root: str,
    policy: dict[str, Any],
    manifest_path: Path,
    specs_root: Path,
    advisory: bool = False,
    freshness_days: int | None = None,
) -> dict[str, Any]:
    generated_at = utc_timestamp()
    now = parse_timestamp(generated_at) or datetime.now(UTC)
    severity = severity_for_profile(profile, policy, advisory)
    manifest, manifest_error = load_manifest(manifest_path)
    defined_ids = collect_defined_ac_scen(specs_root)
    findings: list[dict[str, Any]] = []
    completions: list[dict[str, Any]] = []

    if manifest_error:
        findings.append(
            make_finding(
                finding_id="manifest_parse_error",
                severity=severity,
                status="manifest_parse_error",
                message=f"AC completion manifest could not be parsed: {manifest_error}",
                path=str(manifest_path),
            )
        )
    if manifest and manifest.get("schema") not in {MANIFEST_SCHEMA, None}:
        findings.append(
            make_finding(
                finding_id="manifest_schema_mismatch",
                severity=severity,
                status="manifest_schema_mismatch",
                message=f"Manifest schema must be {MANIFEST_SCHEMA}.",
                path=str(manifest_path),
            )
        )

    raw_completions = manifest.get("completions") if isinstance(manifest, dict) else None
    if raw_completions is None:
        raw_completions = []
    if not isinstance(raw_completions, list):
        findings.append(
            make_finding(
                finding_id="manifest_completions_not_list",
                severity=severity,
                status="manifest_completions_not_list",
                message="Manifest completions must be a list.",
                path=str(manifest_path),
            )
        )
        raw_completions = []

    configured = bool(manifest_path.is_file() and raw_completions)
    if raw_completions and not defined_ids:
        findings.append(
            make_finding(
                finding_id="specs_no_ac_scen_definitions",
                severity=severity,
                status="specs_no_ac_scen_definitions",
                message="Completion claims exist but no AC/SCEN identifiers were parsed from specs.",
                path=str(specs_root),
            )
        )

    completion_metadata: dict[int, dict[str, Any]] = {}
    seen_record_ids: dict[str, dict[str, Any]] = {}
    superseded_by: dict[str, str] = {}
    for index, raw_completion in enumerate(raw_completions, start=1):
        if not isinstance(raw_completion, dict):
            continue
        ac_id = str(raw_completion.get("ac_id") or "").strip().upper()
        raw_record_id = raw_completion.get("record_id")
        record_id = str(raw_record_id or "").strip() or None
        raw_supersedes = raw_completion.get("supersedes")
        supersedes = str(raw_supersedes).strip() if isinstance(raw_supersedes, str) else None
        correction_reason = raw_completion.get("correction_reason")
        record_id_valid = bool(record_id and RECORD_ID_RE.fullmatch(record_id))
        relation_valid = True

        if record_id and not record_id_valid:
            findings.append(
                make_finding(
                    finding_id=f"completion_{index}:invalid_record_id",
                    severity=severity,
                    status="invalid_record_id",
                    message="record_id must use 1-128 letters, digits, dots, underscores, colons, or hyphens.",
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )
        elif record_id and record_id in seen_record_ids:
            record_id_valid = False
            findings.append(
                make_finding(
                    finding_id=f"completion_{index}:duplicate_record_id",
                    severity=severity,
                    status="duplicate_record_id",
                    message="record_id values must be unique within the completion manifest.",
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )

        if raw_supersedes is not None:
            if (
                not isinstance(raw_supersedes, str)
                or not supersedes
                or not RECORD_ID_RE.fullmatch(supersedes)
            ):
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:invalid_supersedes",
                        severity=severity,
                        status="invalid_supersedes",
                        message="supersedes must be null or a valid non-empty record_id string.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
        if supersedes:
            target = seen_record_ids.get(supersedes)
            if not record_id_valid:
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:supersession_record_id_required",
                        severity=severity,
                        status="supersession_record_id_required",
                        message="A superseding completion record requires its own valid record_id.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
            if supersedes == record_id:
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:self_supersession",
                        severity=severity,
                        status="self_supersession",
                        message="A completion record cannot supersede itself.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
            elif target is None:
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:supersession_target_missing",
                        severity=severity,
                        status="supersession_target_missing",
                        message="supersedes must reference an earlier record_id in the same manifest.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
            elif target.get("ac_id") != ac_id:
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:supersession_ac_mismatch",
                        severity=severity,
                        status="supersession_ac_mismatch",
                        message="A superseding completion record must use the same ac_id as its predecessor.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
            elif supersedes in superseded_by:
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:supersession_target_already_replaced",
                        severity=severity,
                        status="supersession_target_already_replaced",
                        message="A completion record may have only one direct superseding successor.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
            if not isinstance(correction_reason, str) or not correction_reason.strip():
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:supersession_reason_missing",
                        severity=severity,
                        status="supersession_reason_missing",
                        message="A superseding completion record must state correction_reason.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
            if not isinstance(raw_completion.get("evidence"), list) or not raw_completion.get("evidence"):
                relation_valid = False
                findings.append(
                    make_finding(
                        finding_id=f"completion_{index}:supersession_evidence_missing",
                        severity=severity,
                        status="supersession_evidence_missing",
                        message="A superseding completion record must carry its own evidence.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )

        metadata = {
            "ac_id": ac_id,
            "record_id": record_id if record_id_valid else None,
            "supersedes": supersedes,
            "correction_reason": correction_reason,
            "valid_supersession": bool(supersedes and relation_valid),
        }
        completion_metadata[index] = metadata
        if record_id_valid and record_id:
            seen_record_ids[record_id] = metadata
        if supersedes and relation_valid and record_id:
            superseded_by[supersedes] = record_id

    for metadata in completion_metadata.values():
        record_id = metadata.get("record_id")
        successor = superseded_by.get(record_id) if record_id else None
        metadata["superseded_by"] = successor
        metadata["record_state"] = "superseded" if successor else "current"

    for index, raw_completion in enumerate(raw_completions, start=1):
        if not isinstance(raw_completion, dict):
            findings.append(
                make_finding(
                    finding_id=f"completion_{index}:invalid_completion_entry",
                    severity=severity,
                    status="invalid_completion_entry",
                    message="Completion entry must be a mapping.",
                )
            )
            continue
        raw_ac_id = raw_completion.get("ac_id")
        ac_id = str(raw_ac_id or "").strip().upper()
        metadata = completion_metadata.get(index, {})
        record_id = metadata.get("record_id")
        record_state = str(metadata.get("record_state") or "current")
        record_severity = "advisory" if record_state == "superseded" else severity
        status = str(raw_completion.get("status") or CLAIMED_COMPLETE).strip().lower()
        evidence_items = raw_completion.get("evidence") or []
        if not ac_id:
            findings.append(
                make_finding(
                    finding_id=f"completion_{index}:missing_ac_id",
                    severity=record_severity,
                    status="missing_ac_id",
                    message="Completion entry is missing ac_id.",
                    record_id=record_id,
                )
            )
        elif defined_ids and ac_id not in defined_ids:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id}:unknown_ac_id",
                    severity=record_severity,
                    status="unknown_ac_id",
                    message=f"{ac_id} is not defined under specs/.",
                    ac_id=ac_id,
                    record_id=record_id,
                )
            )
        if status not in KNOWN_STATUSES:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id or index}:unknown_completion_status",
                    severity=record_severity,
                    status="unknown_completion_status",
                    message=f"Completion status {status!r} is not supported.",
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )
        if not isinstance(evidence_items, list):
            findings.append(
                make_finding(
                    finding_id=f"{ac_id or index}:evidence_not_list",
                    severity=record_severity,
                    status="evidence_not_list",
                    message="Completion evidence must be a list.",
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )
            evidence_items = []

        binding_requested, binding_valid, binding_findings, normalized_binding = repository_binding_status(
            root=root,
            binding=raw_completion.get("repository_binding"),
            ac_id=ac_id or f"completion_{index}",
            severity=record_severity,
            record_id=record_id,
        )
        findings.extend(binding_findings)
        if status == CLAIMED_COMPLETE and not binding_requested:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id or index}:repository_binding_not_requested",
                    severity="advisory",
                    status="repository_binding_not_requested",
                    message=(
                        "Claimed-complete evidence is not bound to explicit base/subject commits and "
                        "a verified subject tree; legacy structural evidence remains review-only."
                    ),
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )

        normalized_evidence: list[dict[str, Any]] = []
        deterministic_satisfied = False
        for evidence in evidence_items:
            if not isinstance(evidence, dict):
                findings.append(
                    make_finding(
                        finding_id=f"{ac_id or index}:invalid_evidence_entry",
                        severity=record_severity,
                        status="invalid_evidence_entry",
                        message="Evidence entry must be a mapping.",
                        ac_id=ac_id or None,
                        record_id=record_id,
                    )
                )
                continue
            satisfied, evidence_findings, normalized = evidence_status(
                root=root,
                evidence=evidence,
                ac_id=ac_id or f"completion_{index}",
                severity=record_severity,
                freshness_days=freshness_days,
                now=now,
                record_id=record_id,
                repository_binding_requested=binding_requested,
                repository_binding_valid=binding_valid,
                subject_tree=normalized_binding.get("subject_tree"),
            )
            deterministic_satisfied = deterministic_satisfied or satisfied
            findings.extend(evidence_findings)
            normalized_evidence.append(normalized)

        if status == CLAIMED_COMPLETE and not evidence_items:
            findings.append(
                make_finding(
                    finding_id=f"{ac_id or index}:missing_completion_evidence",
                    severity=record_severity,
                    status="missing_completion_evidence",
                    message="Claimed-complete AC/SCEN has no evidence items.",
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )
        if status == CLAIMED_COMPLETE and evidence_items and not deterministic_satisfied:
            evidence_types = {
                str(item.get("type") or "").strip()
                for item in evidence_items
                if isinstance(item, dict)
            }
            finding_status = "manual_review_only" if evidence_types == {"manual_review"} else "completion_not_satisfied"
            findings.append(
                make_finding(
                    finding_id=f"{ac_id or index}:{finding_status}",
                    severity=record_severity,
                    status=finding_status,
                    message="Claimed-complete AC/SCEN lacks passing deterministic evidence.",
                    ac_id=ac_id or None,
                    record_id=record_id,
                )
            )

        completions.append(
            {
                "record_id": record_id,
                "record_state": record_state,
                "supersedes": metadata.get("supersedes"),
                "superseded_by": metadata.get("superseded_by"),
                "correction_reason": metadata.get("correction_reason"),
                "ac_id": ac_id,
                "status": status,
                "source_ref": raw_completion.get("source_ref"),
                "repository_binding": normalized_binding,
                "evidence": normalized_evidence,
                "deterministic_completion_evidence_present": deterministic_satisfied,
            }
        )

    superseded_record_ids = set(superseded_by)
    for finding in findings:
        if finding.get("record_id") in superseded_record_ids:
            finding["severity"] = "advisory"

    counts = finding_counts(findings)
    current_records = [item for item in completions if item.get("record_state") == "current"]
    superseded_records = [item for item in completions if item.get("record_state") == "superseded"]
    claimed = [item for item in current_records if item.get("status") == CLAIMED_COMPLETE]
    satisfied_count = sum(1 for item in claimed if item.get("deterministic_completion_evidence_present"))
    repository_bound = [
        item
        for item in current_records
        if (item.get("repository_binding") or {}).get("status") == "ready"
    ]
    subject_operands_checked = sum(
        len((evidence.get("subject_operand_validation") or {}).get("operands") or [])
        for item in current_records
        for evidence in item.get("evidence") or []
    )
    summary = {
        **counts,
        "configured": bool(configured),
        "defined_ac_scen_ids": len(defined_ids),
        "completions_declared": len(completions),
        "current_completion_records": len(current_records),
        "superseded_completion_records": len(superseded_records),
        "claimed_complete": len(claimed),
        "satisfied_completions": satisfied_count,
        "unsatisfied_completions": max(len(claimed) - satisfied_count, 0),
        "repository_bound_completions": len(repository_bound),
        "subject_operands_checked": subject_operands_checked,
        "evidence_items": sum(len(item.get("evidence") or []) for item in completions),
        "deterministic_evidence_items": sum(
            1
            for item in completions
            for evidence in item.get("evidence") or []
            if evidence.get("type") in DETERMINISTIC_EVIDENCE_TYPES
        ),
    }
    known_gaps: list[str] = []
    if not manifest_path.is_file() or not raw_completions:
        known_gaps.append("AC completion manifest is missing or empty; no completion evidence was assessed.")
    if raw_completions and not defined_ids:
        known_gaps.append("No AC/SCEN identifiers were parsed from specs; completion id validation is limited.")
    if any(
        item.get("status") == CLAIMED_COMPLETE
        and (item.get("repository_binding") or {}).get("status") == "not_requested"
        for item in current_records
    ):
        known_gaps.append(
            "One or more current claimed-complete records use legacy unbound evidence; "
            "no subject-tree operand verification was performed."
        )
    report_status = status_from_counts(summary)
    if not configured:
        report_status = "not_configured"

    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "profile": profile,
        "status": report_status,
        "configured": bool(configured),
        "project_root": str(root),
        "naos_root": naos_root,
        "specs_root": str(specs_root),
        "manifest_path": str(manifest_path),
        "deterministic": True,
        "summary": summary,
        "findings": findings,
        "completions": completions,
        "known_gaps": known_gaps,
        "limitations": [
            "This report validates declared AC/SCEN completion evidence only.",
            "Missing or empty manifests are non-blocking and are not completion proof.",
            "Evidence paths and outcomes are checked structurally; command output is not re-executed.",
            "Optional repository binding validates declared Git objects and conservative path-shaped "
            "command operands against subject_tree; it does not prove the command ran against that tree.",
            "Compound or grouped shell commands, bang/history-negation forms, comments, environment "
            "assignments, shell expansions, globs, path-shaped values attached to options, direct "
            "@file-style response syntax, URI/URL-bearing or otherwise unsupported colon forms, C0/DEL "
            "controls, module-style operands, generated output operands, symlink targets, and submodule "
            "contents are outside the bounded subject-operand grammar.",
            "Supersession preserves predecessor records and derives current versus superseded review "
            "posture inside one manifest; it is not deletion, revocation, approval, or release authority.",
            "Freshness is advisory unless explicitly configured.",
        ],
        "not_claimed": [
            "AC correctness",
            "complete test coverage",
            "implementation correctness",
            "semantic quality",
            "requirements approval",
            "hallucination prevention",
            "independent or clean execution proof",
            "cryptographic signing or signer identity",
            "non-repudiation",
            "certification",
            "compliance proof",
        ],
        "human_review_required": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate declared AC/SCEN completion evidence.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--manifest", help="Completion manifest path. Default: NAOS_ROOT/ac_completion_evidence.yaml")
    parser.add_argument("--specs-root", default=os.environ.get("SPECS_ROOT", "specs"))
    parser.add_argument("--freshness-days", type=int, default=None, help="Optional advisory freshness window.")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--advisory", action="store_true", help="Force advisory findings regardless of profile.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    manifest_path = Path(args.manifest) if args.manifest else default_manifest_path(root, naos_root, policy)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    specs_root = Path(args.specs_root)
    if not specs_root.is_absolute():
        specs_root = root / specs_root
    report = build_report(
        root=root,
        profile=profile,
        naos_root=naos_root,
        policy=policy,
        manifest_path=manifest_path,
        specs_root=specs_root,
        advisory=args.advisory,
        freshness_days=args.freshness_days,
    )
    output = (
        Path(args.output)
        if args.output
        else report_output_path(root, naos_root, policy, "ac_completion_evidence_report")
    )
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        configured_note = "configured" if report["configured"] else "not configured; no completion proof"
        print(
            "NAOS AC completion evidence: "
            f"{report['status']} ({configured_note}, {report['summary']['total_findings']} findings)"
        )
    return exit_code_for_summary(profile, report["summary"], policy, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
