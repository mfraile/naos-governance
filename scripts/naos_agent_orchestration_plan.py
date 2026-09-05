#!/usr/bin/env python3
"""Build one deterministic, human-gated agent-work proposal without dispatching it."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import naos_plan_coherence as plan_coherence  # noqa: E402
from naos_policy import (  # noqa: E402
    default_naos_root,
    load_policy,
    normalize_profile,
)
from naos_task_lifecycle import (  # noqa: E402
    is_task_delivered,
    normalize_task_id,
    normalize_task_states,
)


REPORT_SCHEMA = "naos.agent_orchestration_plan.v1"
DIGEST_KIND = "agent_orchestration_plan_sha256_v1"
ALLOWED_CLIENTS = (
    "codex",
    "claude_code",
    "cursor",
    "github_copilot_cli",
    "opencode",
)
CLIENT_TOOL_IDS = {client: client for client in ALLOWED_CLIENTS}
EXPECTED_CLIENT_CONTRACTS = {
    "codex": {
        "supported": True,
        "configuration_path": ".codex/agents/{agent_name}.toml",
        "model_field": "model",
        "reasoning_effort_field": "model_reasoning_effort",
    },
    "claude_code": {
        "supported": True,
        "configuration_path": ".claude/agents/{agent_name}.md",
        "model_field": "model",
        "reasoning_effort_field": "effort",
    },
    "cursor": {
        "supported": False,
        "configuration_path": ".cursor/cli.json",
        "model_field": None,
        "reasoning_effort_field": None,
    },
    "github_copilot_cli": {
        "supported": True,
        "configuration_path": ".github/agents/{agent_name}.agent.md",
        "model_field": "model",
        "reasoning_effort_field": "reasoningEffort",
    },
    "opencode": {
        "supported": True,
        "configuration_path": "opencode.json",
        "model_field": "agent.{agent_name}.model",
        "reasoning_effort_field": "agent.{agent_name}.reasoningEffort",
    },
}
PRIORITIES = ("P0", "P1", "P2", "P3")
REGULAR_GIT_MODES = {"100644", "100755"}
REQUIRED_DECISION_NONCLAIMS = {
    "automatic client launch",
    "client configuration mutation",
    "provider or model call",
    "task state mutation",
    "task completion or closure",
    "claim mutation",
    "automatic approval",
    "merge",
    "push",
    "release",
    "publication",
    "worktree creation",
    "hook installation",
    "memory write",
    "signer identity proof",
    "independent execution proof",
}
LIMITATIONS = [
    "Client projections describe dated configuration contracts; they do not prove that any client honored a model or reasoning-effort declaration.",
    "The report is a local proposal and human-decision check. It does not launch clients, materialize client configuration, or mutate task state.",
    "A later wave is conditional on recomputing current task, claim, repository, planning, model-policy, and decision evidence.",
    "Signer identity and independent clean-execution proof are outside this bounded implementation.",
]
NOT_CLAIMED = sorted(REQUIRED_DECISION_NONCLAIMS)


class ContractError(ValueError):
    """A deterministic input contract is invalid."""


class PreconditionError(RuntimeError):
    """Current repository or planning state cannot support a proposal."""


def utc_now() -> datetime:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        value = fixed.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return datetime.now(UTC)


def utc_now_text() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    normalized = text.casefold()
    return (
        plan_coherence.is_placeholder(text)
        or normalized in {"replace-me", "example", "run-example-001"}
        or normalized.startswith("replace-")
    )


def require_utc_timestamp(value: Any, *, field: str) -> datetime:
    text = str(value or "").strip()
    if is_placeholder(text) or not text.endswith("Z"):
        raise ContractError(f"{field} must be one non-placeholder UTC timestamp ending in Z.")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError(f"{field} must be a valid UTC timestamp.") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ContractError(f"{field} must be a valid UTC timestamp.")
    return parsed.astimezone(UTC)


def finding(finding_id: str, severity: str, message: str, **context: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "status": "blocked" if severity == "blocking" else "review_required",
        "message": message,
    }
    item.update(context)
    return item


def empty_report(root: Path, naos_root: str, profile: str) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now_text(),
        "profile": profile,
        "status": "not_configured",
        "project_root": str(root),
        "naos_root": naos_root,
        "configured": False,
        "active": False,
        "proposal_only": True,
        "repository": {},
        "client_contracts": {},
        "client_projections": [],
        "waves": [],
        "subject": None,
        "decision": {
            "present": False,
            "validated": False,
            "outcome": None,
            "automatic_dispatch_authorized": False,
        },
        "findings": [],
        "authority": {
            "client_launch": False,
            "client_configuration_write": False,
            "provider_or_model_call": False,
            "task_state_write": False,
            "task_completion": False,
            "claim_write": False,
            "automatic_approval": False,
            "merge": False,
            "push": False,
            "release": False,
            "publication": False,
            "worktree_creation": False,
            "hook_installation": False,
            "memory_write": False,
        },
        "limitations": list(LIMITATIONS),
        "not_claimed": list(NOT_CLAIMED),
        "summary": {
            "lanes": 0,
            "waves": 0,
            "affected_files": 0,
            "affected_bytes": 0,
            "human_review_required": True,
            "automatic_dispatch_authorized": False,
        },
    }


def finish(report: dict[str, Any], status: str, *findings: dict[str, Any]) -> tuple[dict[str, Any], int]:
    report["status"] = status
    report["findings"].extend(findings)
    success = status in {"not_applicable", "not_configured", "inactive", "human_dispatch_required"}
    return report, 0 if success else 1


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ContractError(f"Cannot read YAML mapping {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError(f"Expected a YAML mapping: {path}")
    return data


def load_json_mapping(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"Cannot read JSON mapping {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError(f"Expected a JSON mapping: {path}")
    return data


def safe_relative_path(raw: Any, *, field: str) -> str:
    value = str(raw or "").strip()
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or ".." in candidate.parts
        or any(part in {"", "."} for part in candidate.parts)
        or candidate.parts[0] == ".git"
        or any(ord(character) < 32 for character in value)
    ):
        raise ContractError(f"{field} must be one safe repository-relative path: {value!r}")
    return candidate.as_posix()


def project_path(root: Path, raw: Any, *, field: str, must_exist: bool = True) -> Path:
    relative = safe_relative_path(raw, field=field)
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ContractError(f"{field} refuses symlinked path component: {relative}")
    target = (root / relative).resolve(strict=False)
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ContractError(f"{field} escapes the project root: {relative}") from exc
    if must_exist and not target.is_file():
        raise ContractError(f"{field} is not a regular project file: {relative}")
    return target


def schema_path(root: Path, filename: str) -> Path:
    adopter = root / "schemas" / "naos" / filename
    if adopter.is_file():
        return adopter
    source_kit = SCRIPT_DIR.parent / "schemas" / "naos" / filename
    if source_kit.is_file():
        return source_kit
    raise ContractError(f"Required schema is missing: schemas/naos/{filename}")


def validate_document(document: dict[str, Any], schema: dict[str, Any], *, label: str) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    if not errors:
        return
    rendered: list[str] = []
    for error in errors[:12]:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        rendered.append(f"{location}: {error.message}")
    raise ContractError(f"{label} schema validation failed: {'; '.join(rendered)}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(root: Path, *args: str, check: bool = True) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise PreconditionError(f"git {' '.join(args)} failed: {message or completed.returncode}")
    return completed.stdout


def git_text(root: Path, *args: str) -> str:
    return run_git(root, *args).decode("utf-8", errors="strict").strip()


def git_path(root: Path, name: str) -> Path:
    raw = git_text(root, "rev-parse", "--git-path", name)
    candidate = Path(raw)
    return candidate if candidate.is_absolute() else (root / candidate).resolve(strict=False)


def operation_in_progress(root: Path) -> list[str]:
    active: list[str] = []
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG", "rebase-merge", "rebase-apply"):
        if git_path(root, name).exists():
            active.append(name)
    return active


def repository_snapshot(root: Path, expected_branch: str | None = None) -> dict[str, Any]:
    exact_root = Path(git_text(root, "rev-parse", "--show-toplevel")).resolve()
    if exact_root != root.resolve():
        raise PreconditionError(f"Project root is not the exact Git worktree root: {root}")
    branch = git_text(root, "symbolic-ref", "--quiet", "--short", "HEAD")
    if not branch:
        raise PreconditionError("Detached HEAD is not eligible for an orchestration proposal.")
    if expected_branch and branch != expected_branch:
        raise PreconditionError(f"Expected branch {expected_branch!r}, observed {branch!r}.")
    operations = operation_in_progress(root)
    if operations:
        raise PreconditionError(f"Git operation state is active: {', '.join(operations)}")
    status = run_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status:
        raise PreconditionError("The worktree/index is not clean; commit or remove the exact in-scope change before planning.")
    snapshot = {
        "root": str(exact_root),
        "branch": branch,
        "head": git_text(root, "rev-parse", "HEAD"),
        "git_dir": str(Path(git_text(root, "rev-parse", "--absolute-git-dir")).resolve()),
        "common_dir": str(Path(git_text(root, "rev-parse", "--git-common-dir")).resolve()),
        "object_format": git_text(root, "rev-parse", "--show-object-format"),
        "index": run_git(root, "ls-files", "--stage", "-z"),
        "flags": run_git(root, "ls-files", "-v", "-z"),
        "status": status,
    }
    masked = masked_index_paths(snapshot)
    if masked:
        raise PreconditionError(
            "The Git index contains skip-worktree or assume-unchanged paths; "
            f"exact planning refuses hidden worktree state: {', '.join(sorted(masked)[:12])}"
        )
    return snapshot


def snapshot_identity(snapshot: dict[str, Any]) -> tuple[Any, ...]:
    return (
        snapshot["root"],
        snapshot["branch"],
        snapshot["head"],
        snapshot["git_dir"],
        snapshot["common_dir"],
        snapshot["object_format"],
        snapshot["index"],
        snapshot["flags"],
        snapshot["status"],
    )


def parse_index(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for record in snapshot["index"].split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, oid, stage = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8", errors="surrogateescape")
        except (ValueError, UnicodeError) as exc:
            raise PreconditionError("Git index contains an unparseable entry.") from exc
        if stage != "0":
            raise PreconditionError(f"Git index contains an unmerged entry: {path}")
        if any(ord(character) < 32 for character in path):
            raise PreconditionError(f"Git index path contains a control character: {path!r}")
        entries.append({"mode": mode, "oid": oid, "path": path})
    return entries


def masked_index_paths(snapshot: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for record in snapshot["flags"].split(b"\0"):
        if len(record) < 3:
            continue
        marker = chr(record[0])
        path = record[2:].decode("utf-8", errors="surrogateescape")
        if marker == "S" or marker.islower():
            paths.add(path)
    return paths


def path_matches(path: str, pattern: str) -> bool:
    """Match one Git path without allowing ``*`` or ``?`` to cross ``/``."""
    path_parts = tuple(path.split("/"))
    pattern_parts = tuple(pattern.split("/"))
    memo: dict[tuple[int, int], bool] = {}

    def matches(path_index: int, pattern_index: int) -> bool:
        key = (path_index, pattern_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = matches(path_index, pattern_index + 1) or (
                path_index < len(path_parts)
                and matches(path_index + 1, pattern_index)
            )
        else:
            result = (
                path_index < len(path_parts)
                and fnmatch.fnmatchcase(
                    path_parts[path_index], pattern_parts[pattern_index]
                )
                and matches(path_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return matches(0, 0)


def normalized_patterns(values: Any, *, field: str) -> list[str]:
    patterns = [safe_relative_path(item, field=field) for item in as_list(values)]
    if len(patterns) != len(set(patterns)):
        raise ContractError(f"{field} contains duplicate path patterns.")
    return patterns


def pattern_prefix(pattern: str) -> str:
    prefix = pattern
    for marker in ("*", "?", "["):
        prefix = prefix.split(marker, 1)[0]
    return prefix.rstrip("/")


def patterns_may_overlap(left: list[str], right: list[str]) -> bool:
    for first in left:
        for second in right:
            if first == second:
                return True
            first_prefix = pattern_prefix(first)
            second_prefix = pattern_prefix(second)
            if not first_prefix or not second_prefix:
                return True
            first_has_glob = any(marker in first for marker in ("*", "?", "["))
            second_has_glob = any(marker in second for marker in ("*", "?", "["))
            if not first_has_glob and not second_has_glob:
                continue
            if (
                first_prefix.startswith(second_prefix)
                or second_prefix.startswith(first_prefix)
                or path_matches(first_prefix, second)
                or path_matches(second_prefix, first)
            ):
                return True
    return False


def selected_index_projection(
    root: Path,
    snapshot: dict[str, Any],
    lanes: list[dict[str, Any]],
    decision_ref: str,
    max_files: int,
    max_bytes: int,
) -> tuple[list[dict[str, Any]], int, dict[str, int], dict[str, list[str]]]:
    lane_scopes: list[dict[str, Any]] = []
    for lane in lanes:
        lane_scopes.append(
            {
                "lane_id": str(lane.get("lane_id")),
                "permitted": normalized_patterns(
                    lane.get("permitted_paths"),
                    field=f"{lane.get('lane_id')}.permitted_paths",
                ),
                "excluded": normalized_patterns(
                    lane.get("excluded_paths"),
                    field=f"{lane.get('lane_id')}.excluded_paths",
                ),
            }
        )
    selected: list[dict[str, Any]] = []
    selected_paths_by_lane: dict[str, set[str]] = {
        scope["lane_id"]: set() for scope in lane_scopes
    }
    folded: dict[str, str] = {}
    total_bytes = 0
    for item in parse_index(snapshot):
        path = str(item["path"])
        if path_matches(path, decision_ref):
            continue
        matching_lanes = [
            scope["lane_id"]
            for scope in lane_scopes
            if any(path_matches(path, pattern) for pattern in scope["permitted"])
            and not any(
                path_matches(path, pattern) for pattern in scope["excluded"]
            )
        ]
        if not matching_lanes:
            continue
        for lane_id in matching_lanes:
            selected_paths_by_lane[lane_id].add(path)
        previous = folded.setdefault(path.casefold(), path)
        if previous != path:
            raise PreconditionError(f"Selected paths collide under case folding: {previous}, {path}")
        if item["mode"] not in REGULAR_GIT_MODES:
            raise PreconditionError(f"Selected path is not a regular tracked file: {path} ({item['mode']})")
        blob = run_git(root, "cat-file", "blob", str(item["oid"]))
        total_bytes += len(blob)
        selected.append(
            {
                "mode": item["mode"],
                "path": path,
                "blob_sha256": hashlib.sha256(blob).hexdigest(),
                "bytes": len(blob),
            }
        )
    selected.sort(key=lambda item: item["path"])
    if len(selected) > max_files:
        raise PreconditionError(f"Selected projection exceeds max_affected_files ({len(selected)} > {max_files}).")
    if total_bytes > max_bytes:
        raise PreconditionError(f"Selected projection exceeds max_affected_bytes ({total_bytes} > {max_bytes}).")
    empty_lanes = sorted(
        lane_id for lane_id, paths in selected_paths_by_lane.items() if not paths
    )
    if empty_lanes:
        raise PreconditionError(
            "Every lane must match at least one regular tracked file after exclusions; "
            f"empty lanes: {', '.join(empty_lanes)}"
        )
    sorted_paths_by_lane = {
        lane_id: sorted(paths)
        for lane_id, paths in sorted(selected_paths_by_lane.items())
    }
    selected_by_lane = {
        lane_id: len(paths) for lane_id, paths in sorted_paths_by_lane.items()
    }
    return selected, total_bytes, selected_by_lane, sorted_paths_by_lane


def stable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): stable_value(child)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
            if str(key) not in {"generated_at", "observed_at"}
        }
    if isinstance(value, list):
        return [stable_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(stable_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def contract_age_days(raw: Any) -> int:
    try:
        checked = date.fromisoformat(str(raw))
    except ValueError as exc:
        raise ContractError(f"Invalid client source_checked_at date: {raw!r}") from exc
    return (utc_now().date() - checked).days


def validate_client_contracts(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    contracts = as_mapping(policy.get("client_contracts"))
    max_age = int(policy.get("client_contract_max_age_days") or 0)
    if tuple(sorted(contracts)) != tuple(sorted(ALLOWED_CLIENTS)):
        raise ContractError("client_contracts must contain exactly Codex, Claude Code, Cursor, GitHub Copilot CLI, and OpenCode.")
    result: dict[str, dict[str, Any]] = {}
    for client in ALLOWED_CLIENTS:
        contract = as_mapping(contracts.get(client))
        expected = EXPECTED_CLIENT_CONTRACTS[client]
        mismatches = [
            key
            for key, expected_value in expected.items()
            if contract.get(key) != expected_value
        ]
        if mismatches:
            raise ContractError(
                f"Client contract {client} does not match the reviewed projection fields: "
                + ", ".join(mismatches)
            )
        configuration_path = str(contract.get("configuration_path") or "")
        remaining_path = configuration_path.replace("{agent_name}", "")
        if configuration_path.count("{agent_name}") > 1 or any(
            marker in remaining_path for marker in ("{", "}")
        ):
            raise ContractError(
                f"Client contract {client} contains an unsupported path placeholder."
            )
        safe_relative_path(
            configuration_path.replace("{agent_name}", "agent"),
            field=f"client_contracts.{client}.configuration_path",
        )
        age = contract_age_days(contract.get("source_checked_at"))
        if age < 0:
            raise ContractError(f"Client contract {client} has a future source_checked_at date.")
        if age > max_age:
            raise ContractError(f"Client contract {client} is stale ({age} days > {max_age}).")
        result[client] = {
            **contract,
            "age_days": age,
            "runtime_verified": False,
            "configuration_written": False,
        }
    return result


def load_registry(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    raw = load_yaml_mapping(path)
    tasks: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(as_list(raw.get("tasks"))):
        if not isinstance(item, dict):
            raise ContractError(f"task_registry.tasks[{index}] must be a mapping.")
        task_id = normalize_task_id(item.get("id"))
        if task_id in tasks:
            raise ContractError(f"Duplicate task id in registry: {task_id}")
        tasks[task_id] = item
    if not tasks:
        raise ContractError("The selected task registry contains no tasks.")
    return tasks, raw


def canonical_task_registry_path(root: Path, naos_root: str) -> Path:
    safe_naos_root = safe_relative_path(naos_root, field="naos_root")
    for relative in (
        f"{safe_naos_root}/TASK_REGISTRY.yaml",
        "TASK_REGISTRY.yaml",
    ):
        candidate = root / relative
        if candidate.exists():
            return project_path(
                root,
                relative,
                field="canonical_task_registry",
            )
    raise PreconditionError("The canonical TASK_REGISTRY.yaml is missing.")


def validate_unique_required_outputs(lanes: list[dict[str, Any]]) -> None:
    owners: dict[str, tuple[str, str]] = {}
    for lane in lanes:
        lane_id = str(lane.get("lane_id") or "<unknown>")
        for raw_output in as_list(lane.get("required_outputs")):
            output = safe_relative_path(
                raw_output,
                field=f"{lane_id}.required_outputs",
            )
            folded = output.casefold()
            previous = owners.get(folded)
            if previous is not None:
                previous_lane, previous_output = previous
                raise ContractError(
                    "Required handoff outputs must be globally unique under case folding: "
                    f"{previous_lane}/{previous_output}, {lane_id}/{output}"
                )
            owners[folded] = (lane_id, output)


def validate_selected_tasks(
    lanes: list[dict[str, Any]],
    registry: dict[str, dict[str, Any]],
    claims: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    lane_ids: set[str] = set()
    claimed = {normalize_task_id(item.get("task_id")) for item in claims if item.get("task_id")}
    for lane in lanes:
        lane_id = str(lane.get("lane_id"))
        if lane_id in lane_ids:
            raise ContractError(f"Duplicate lane id: {lane_id}")
        lane_ids.add(lane_id)
        task_id = normalize_task_id(lane.get("task_id"))
        if task_id in selected:
            raise ContractError(f"A task may appear in only one lane: {task_id}")
        task = registry.get(task_id)
        if task is None:
            raise PreconditionError(f"Selected task is not present in TASK_REGISTRY: {task_id}")
        states = normalize_task_states(task)
        if (
            states["lifecycle_state"] != "planned"
            or states["delivery_state"] != "not_started"
            or states["verification_state"] != "unverified"
        ):
            raise PreconditionError(
                f"Selected task {task_id} is not planned/not_started/unverified: "
                f"{states['lifecycle_state']}/{states['delivery_state']}/{states['verification_state']}"
            )
        priority = str(task.get("priority") or "")
        if priority not in PRIORITIES:
            raise ContractError(f"Selected task {task_id} has invalid priority: {priority!r}")
        phase = task.get("phase")
        if isinstance(phase, bool) or not isinstance(phase, int) or phase < 0:
            raise ContractError(f"Selected task {task_id} has invalid phase: {phase!r}")
        if task_id in claimed:
            raise PreconditionError(f"Selected task already has an active claim: {task_id}")
        selected[task_id] = {"task": task, "lane": lane}
    return selected


def selected_dependencies(
    selected: dict[str, dict[str, Any]],
    registry: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    dependencies: dict[str, set[str]] = {}
    for task_id, item in selected.items():
        current: set[str] = set()
        raw_dependencies = item["task"].get("dependencies", [])
        if raw_dependencies is None:
            raw_dependencies = []
        if not isinstance(raw_dependencies, list):
            raise ContractError(
                f"Task {task_id} dependencies must be an array, not {type(raw_dependencies).__name__}."
            )
        for raw_dependency in raw_dependencies:
            dependency = normalize_task_id(raw_dependency)
            if dependency == task_id:
                raise ContractError(f"Task {task_id} cannot depend on itself.")
            dependency_task = registry.get(dependency)
            if dependency_task is None:
                raise PreconditionError(f"Task {task_id} has an unknown dependency: {dependency}")
            if is_task_delivered(dependency_task):
                continue
            if dependency not in selected:
                raise PreconditionError(f"Task {task_id} has an undelivered dependency outside the selected lanes: {dependency}")
            current.add(dependency)
        dependencies[task_id] = current
    return dependencies


def task_sort_key(task_id: str, selected: dict[str, dict[str, Any]]) -> tuple[Any, ...]:
    item = selected[task_id]
    task = item["task"]
    lane = item["lane"]
    return (PRIORITIES.index(str(task.get("priority"))), int(task.get("phase")), task_id, str(lane.get("lane_id")))


def build_waves(
    selected: dict[str, dict[str, Any]],
    dependencies: dict[str, set[str]],
    selected_paths_by_lane: dict[str, list[str]],
    max_parallel: int,
) -> list[dict[str, Any]]:
    pending = set(selected)
    completed: set[str] = set()
    waves: list[dict[str, Any]] = []
    while pending:
        ready = sorted(
            (task_id for task_id in pending if dependencies[task_id] <= completed),
            key=lambda task_id: task_sort_key(task_id, selected),
        )
        if not ready:
            raise PreconditionError(f"Selected tasks contain a dependency cycle: {', '.join(sorted(pending))}")
        first = ready[0]
        wave_tasks = [first]
        first_parallel = selected[first]["task"].get("parallelizable") is True
        if first_parallel:
            for candidate in ready[1:]:
                if len(wave_tasks) >= max_parallel:
                    break
                if selected[candidate]["task"].get("parallelizable") is not True:
                    continue
                candidate_lane_id = str(
                    selected[candidate]["lane"].get("lane_id")
                )
                candidate_paths = normalized_patterns(
                    selected[candidate]["lane"].get("permitted_paths"),
                    field=f"{selected[candidate]['lane'].get('lane_id')}.permitted_paths",
                )
                if any(
                    set(selected_paths_by_lane.get(candidate_lane_id, []))
                    & set(
                        selected_paths_by_lane.get(
                            str(selected[chosen]["lane"].get("lane_id")), []
                        )
                    )
                    or patterns_may_overlap(
                        candidate_paths,
                        normalized_patterns(
                            selected[chosen]["lane"].get("permitted_paths"),
                            field=f"{selected[chosen]['lane'].get('lane_id')}.permitted_paths",
                        ),
                    )
                    for chosen in wave_tasks
                ):
                    continue
                wave_tasks.append(candidate)
        wave_number = len(waves) + 1
        waves.append(
            {
                "wave": wave_number,
                "conditional": wave_number > 1,
                "must_recompute_before_dispatch": True,
                "lanes": [
                    {
                        "lane_id": selected[task_id]["lane"]["lane_id"],
                        "task_id": task_id,
                        "objective": selected[task_id]["lane"]["objective"],
                        "read_only": selected[task_id]["lane"]["read_only"],
                        "client": selected[task_id]["lane"]["client"],
                        "role": selected[task_id]["lane"]["role"],
                        "agent_name": selected[task_id]["lane"]["agent_name"],
                        "priority": selected[task_id]["task"]["priority"],
                        "phase": selected[task_id]["task"]["phase"],
                        "parallelizable": selected[task_id]["task"].get("parallelizable") is True,
                        "depends_on_selected": sorted(dependencies[task_id]),
                        "permitted_paths": normalized_patterns(
                            selected[task_id]["lane"].get("permitted_paths"),
                            field=f"{selected[task_id]['lane'].get('lane_id')}.permitted_paths",
                        ),
                        "excluded_paths": normalized_patterns(
                            selected[task_id]["lane"].get("excluded_paths"),
                            field=f"{selected[task_id]['lane'].get('lane_id')}.excluded_paths",
                        ),
                        "required_outputs": list(
                            selected[task_id]["lane"].get("required_outputs") or []
                        ),
                    }
                    for task_id in wave_tasks
                ],
            }
        )
        pending.difference_update(wave_tasks)
        completed.update(wave_tasks)
    return waves


def nonempty_declaration(value: Any) -> bool:
    return isinstance(value, str) and not is_placeholder(value)


def client_projection(
    lane: dict[str, Any],
    model_policy: dict[str, Any],
    contracts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    client = str(lane.get("client"))
    role_name = str(lane.get("role"))
    agent_name = str(lane.get("agent_name"))
    contract = contracts[client]
    if not contract.get("supported"):
        raise ContractError(f"Selected client {client} has no supported repository-local model-and-effort projection contract.")
    roles = as_mapping(model_policy.get("roles"))
    role = as_mapping(roles.get(role_name))
    if not role:
        raise ContractError(f"Selected lane references an undeclared model role: {role_name}")
    if role.get("enabled") is not True:
        raise ContractError(
            f"Selected model role must be explicitly enabled: {role_name}"
        )
    tool = as_mapping(as_mapping(model_policy.get("tool_model_bindings")).get(CLIENT_TOOL_IDS[client]))
    binding = as_mapping(as_mapping(tool.get("roles")).get(role_name))
    if not tool or not binding or tool.get("enabled") is not True or binding.get("enabled") is not True:
        raise ContractError(f"Selected client/role binding must be explicitly enabled: {client}/{role_name}")
    if tool.get("mutation_allowed") is not False or binding.get("mutation_allowed") is not False:
        raise ContractError(f"Selected client/role binding allows configuration mutation: {client}/{role_name}")
    if role.get("runtime_enabled") is not False or role.get("provider_calls_allowed") is not False:
        raise ContractError(f"Selected model role does not explicitly disable runtime/provider behavior: {role_name}")
    for field in ("model", "reasoning_effort"):
        if field in binding and not nonempty_declaration(binding.get(field)):
            raise ContractError(
                f"Selected client/role binding has an invalid explicit {field}: {client}/{role_name}"
            )
    model = binding["model"] if "model" in binding else role.get("model")
    effort = (
        binding["reasoning_effort"]
        if "reasoning_effort" in binding
        else role.get("reasoning_effort")
    )
    if not nonempty_declaration(model):
        raise ContractError(f"Selected client/role binding has no exact model: {client}/{role_name}")
    if not nonempty_declaration(effort):
        raise ContractError(f"Selected client/role binding has no exact reasoning_effort: {client}/{role_name}")
    configuration_path = str(contract["configuration_path"]).replace("{agent_name}", agent_name)
    return {
        "lane_id": lane["lane_id"],
        "task_id": normalize_task_id(lane["task_id"]),
        "client": client,
        "role": role_name,
        "agent_name": agent_name,
        "configuration_path": configuration_path,
        "model_field": str(contract["model_field"]).replace(
            "{agent_name}", agent_name
        ),
        "reasoning_effort_field": str(
            contract["reasoning_effort_field"]
        ).replace("{agent_name}", agent_name),
        "model": str(model),
        "reasoning_effort": str(effort),
        "configuration_written": False,
        "effective_runtime_verified": False,
        "provider_or_model_called": False,
        "limitations": list(as_list(contract.get("limitations"))),
    }


def validate_model_policy(model_policy: dict[str, Any]) -> None:
    if model_policy.get("enabled") is not True:
        raise ContractError("Model policy must be explicitly enabled for the selected proposal.")
    unsafe = {
        "runtime_enabled": model_policy.get("runtime_enabled"),
        "provider_calls_allowed": model_policy.get("provider_calls_allowed"),
        "credentials_allowed_in_repo": model_policy.get("credentials_allowed_in_repo"),
        "runtime_routing_authority": model_policy.get("runtime_routing_authority"),
        "can_approve": model_policy.get("can_approve"),
        "can_certify": model_policy.get("can_certify"),
        "can_prove_compliance": model_policy.get("can_prove_compliance"),
        "can_promote_maturity": model_policy.get("can_promote_maturity"),
        "model_quality_authority": model_policy.get("model_quality_authority"),
    }
    unsafe_values = sorted(key for key, value in unsafe.items() if value is not False)
    if unsafe_values:
        raise ContractError(
            "Model policy must explicitly disable declaration-only authority fields: "
            + ", ".join(unsafe_values)
        )
    tool_policy = as_mapping(model_policy.get("tool_binding_policy"))
    if tool_policy.get("mutation_allowed") is not False:
        raise ContractError("Model policy must explicitly disable tool-binding mutation.")


def expected_subject_refs(request: dict[str, Any], lanes: list[dict[str, Any]]) -> list[str]:
    return [
        f"project:{request['project_id']}",
        f"run:{request['run_id']}",
        *sorted(f"lane:{lane['lane_id']}" for lane in lanes),
        *sorted(f"task:{normalize_task_id(lane['task_id'])}" for lane in lanes),
    ]


def decision_status(
    root: Path,
    request: dict[str, Any],
    subject: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    decision_ref = str(request["decision_ref"])
    decision_path = project_path(root, decision_ref, field="decision_ref", must_exist=False)
    if not decision_path.exists():
        return "decision_required", {
            "present": False,
            "validated": False,
            "outcome": None,
            "decision_ref": decision_ref,
            "required_decision_id": f"DECISION-{request['run_id']}",
            "required_subject_refs": subject["subject_refs"],
            "required_subject_digest": {"digest_kind": DIGEST_KIND, "sha256": subject["sha256"]},
            "automatic_dispatch_authorized": False,
        }
    if not run_git(root, "ls-files", "--error-unmatch", "--", decision_ref, check=False):
        raise PreconditionError("The orchestration decision must be a tracked file in the clean worktree.")
    decision = load_yaml_mapping(decision_path)
    validate_document(
        decision,
        load_json_mapping(schema_path(root, "human_decision_record.schema.json")),
        label="human decision",
    )
    expected_id = f"DECISION-{request['run_id']}"
    errors: list[str] = []
    if decision.get("decision_id") != expected_id:
        errors.append(f"decision_id must be {expected_id}")
    if decision.get("decision_type") != "agent_orchestration_plan":
        errors.append("decision_type must be agent_orchestration_plan")
    if decision.get("subject_refs") != subject["subject_refs"]:
        errors.append("subject_refs do not exactly match the proposal subject")
    if is_placeholder(decision.get("decided_by")) or decision.get("decided_by") != request.get("requested_by"):
        errors.append("decided_by must exactly match requested_by")
    try:
        requested_at = require_utc_timestamp(
            request.get("requested_at"), field="requested_at"
        )
        decided_at = require_utc_timestamp(
            decision.get("decided_at"), field="decided_at"
        )
    except ContractError as exc:
        errors.append(str(exc))
    else:
        if decided_at < requested_at:
            errors.append("decided_at cannot precede requested_at")
        if decided_at > utc_now():
            errors.append("decided_at cannot be in the future")
    if is_placeholder(decision.get("rationale")):
        errors.append("rationale must be substantive and non-placeholder")
    if is_placeholder(decision.get("authority_scope")):
        errors.append("authority_scope must be substantive and non-placeholder")
    digest = as_mapping(decision.get("subject_digest"))
    if digest.get("digest_kind") != DIGEST_KIND or digest.get("sha256") != subject["sha256"]:
        errors.append("subject_digest does not exactly match the proposal")
    if decision.get("real_world_authority_proven") is not False:
        errors.append("real_world_authority_proven must be false")
    missing_nonclaims = REQUIRED_DECISION_NONCLAIMS - {str(item) for item in as_list(decision.get("not_claimed"))}
    if missing_nonclaims:
        errors.append(f"not_claimed is missing: {', '.join(sorted(missing_nonclaims))}")
    if errors:
        raise ContractError("Invalid orchestration decision: " + "; ".join(errors))
    outcome = str(decision.get("outcome"))
    status = {
        "approved": "human_dispatch_required",
        "rejected": "decision_rejected",
        "deferred": "decision_deferred",
    }[outcome]
    return status, {
        "present": True,
        "validated": True,
        "outcome": outcome,
        "decision_ref": decision_ref,
        "decision_id": expected_id,
        "decided_by": decision.get("decided_by"),
        "decided_at": decision.get("decided_at"),
        "real_world_authority_proven": False,
        "automatic_dispatch_authorized": False,
    }


def build_report(
    root: Path,
    naos_root: str,
    profile: str,
    governance_policy: dict[str, Any],
    orchestration_policy_path: Path,
    request_path: Path,
) -> tuple[dict[str, Any], int]:
    report = empty_report(root, naos_root, profile)
    if profile != "assured":
        return finish(
            report,
            "not_applicable",
            finding("agent_orchestration.profile", "advisory", "Agent orchestration proposals are Assured-only."),
        )
    if not orchestration_policy_path.exists() or not request_path.exists():
        return finish(
            report,
            "not_configured",
            finding("agent_orchestration.not_configured", "advisory", "Install the confirmed agent_orchestration_plan setup module first."),
        )

    try:
        policy_path = project_path(root, orchestration_policy_path.relative_to(root), field="orchestration_policy")
        exact_request_path = project_path(root, request_path.relative_to(root), field="orchestration_request")
        orchestration_policy = load_yaml_mapping(policy_path)
        request = load_yaml_mapping(exact_request_path)
        validate_document(
            orchestration_policy,
            load_json_mapping(schema_path(root, "agent_orchestration_policy.schema.json")),
            label="agent orchestration policy",
        )
        validate_document(
            request,
            load_json_mapping(schema_path(root, "agent_orchestration_request.schema.json")),
            label="agent orchestration request",
        )
        report["configured"] = True
        report["client_contracts"] = validate_client_contracts(orchestration_policy)
        report["authority"] = as_mapping(orchestration_policy.get("authority"))
        report["not_claimed"] = sorted({*NOT_CLAIMED, *[str(item) for item in as_list(orchestration_policy.get("required_nonclaims"))]})
        if orchestration_policy.get("enabled") is not True or request.get("enabled") is not True:
            return finish(
                report,
                "inactive",
                finding("agent_orchestration.inactive", "advisory", "Policy and request must both be explicitly enabled for one run."),
            )
        report["active"] = True

        run_id = str(request["run_id"])
        for field in ("run_id", "project_id", "requested_by"):
            if is_placeholder(request.get(field)):
                raise ContractError(f"{field} must be replaced with one attributable value.")
        requested_at = require_utc_timestamp(
            request.get("requested_at"), field="requested_at"
        )
        if requested_at > utc_now():
            raise ContractError("requested_at cannot be in the future.")
        lanes = [as_mapping(item) for item in as_list(request.get("lanes"))]
        if not lanes:
            raise ContractError("An enabled orchestration request must select at least one lane.")
        for lane in lanes:
            lane_id = str(lane.get("lane_id") or "<unknown>")
            for field in ("objective", "agent_name"):
                if is_placeholder(lane.get(field)):
                    raise ContractError(
                        f"{lane_id}.{field} must be replaced with one exact value."
                    )
        validate_unique_required_outputs(lanes)
        expected_decision_ref = f"naos/human_decisions/DECISION-{run_id}.yaml"
        if request.get("decision_ref") != expected_decision_ref:
            raise ContractError(f"decision_ref must be exactly {expected_decision_ref}")
        policy_max = int(orchestration_policy["max_parallel"])
        request_max = int(request["max_parallel"])
        if request_max > policy_max:
            raise ContractError(f"Request max_parallel exceeds policy ({request_max} > {policy_max}).")

        first_snapshot = repository_snapshot(root, str(request["expected_branch"]))
        report["repository"] = {
            "root": first_snapshot["root"],
            "branch": first_snapshot["branch"],
            "head_observed_not_digest_bound": first_snapshot["head"],
            "object_format": first_snapshot["object_format"],
            "clean": True,
            "snapshot_raced": False,
        }

        model_policy_path = project_path(root, request["model_policy_ref"], field="model_policy_ref")
        expected_model_policy_path = project_path(
            root,
            f"{safe_relative_path(naos_root, field='naos_root')}/model_provider_policy.yaml",
            field="canonical_model_policy",
        )
        if model_policy_path != expected_model_policy_path:
            raise PreconditionError(
                "model_policy_ref must resolve to the canonical project-local model policy."
            )
        task_registry_path = project_path(root, request["task_registry_ref"], field="task_registry_ref")
        if task_registry_path != canonical_task_registry_path(root, naos_root):
            raise PreconditionError(
                "task_registry_ref must resolve to the same canonical registry used by live planning."
            )
        model_policy = load_yaml_mapping(model_policy_path)
        validate_model_policy(model_policy)
        registry, registry_raw = load_registry(task_registry_path)

        live_plan = plan_coherence.build_report(root, naos_root, governance_policy, profile)
        readiness = as_mapping(live_plan.get("implementation_readiness"))
        if readiness.get("status") != "ready":
            raise PreconditionError(
                f"Live planning readiness must be ready; observed {readiness.get('status') or 'missing'}."
            )
        claims = plan_coherence.active_claims(root, naos_root, governance_policy)
        selected = validate_selected_tasks(lanes, registry, claims)
        dependencies = selected_dependencies(selected, registry)
        affected, affected_bytes, affected_by_lane, selected_paths_by_lane = selected_index_projection(
            root,
            first_snapshot,
            lanes,
            expected_decision_ref,
            int(orchestration_policy["max_affected_files"]),
            int(orchestration_policy["max_affected_bytes"]),
        )
        waves = build_waves(
            selected,
            dependencies,
            selected_paths_by_lane,
            request_max,
        )
        projections = [
            client_projection(lane, model_policy, report["client_contracts"])
            for lane in sorted(lanes, key=lambda item: str(item.get("lane_id")))
        ]

        subject_refs = expected_subject_refs(request, lanes)
        digest_payload = {
            "digest_kind": DIGEST_KIND,
            "policy_file_sha256": file_sha256(policy_path),
            "request_file_sha256": file_sha256(exact_request_path),
            "model_policy_file_sha256": file_sha256(model_policy_path),
            "task_registry_file_sha256": file_sha256(task_registry_path),
            "planning_readiness": stable_value(readiness),
            "request": stable_value(request),
            "waves": stable_value(waves),
            "client_projections": stable_value(projections),
            "affected_index_entries": affected,
            "repository_identity": {
                "root": first_snapshot["root"],
                "git_dir": first_snapshot["git_dir"],
                "common_dir": first_snapshot["common_dir"],
                "branch": first_snapshot["branch"],
                "object_format": first_snapshot["object_format"],
            },
            "subject_refs": subject_refs,
            "registry_projection": stable_value(registry_raw),
        }
        subject = {
            "digest_kind": DIGEST_KIND,
            "sha256": canonical_sha256(digest_payload),
            "subject_refs": subject_refs,
            "affected_files": len(affected),
            "affected_bytes": affected_bytes,
            "affected_files_by_lane": affected_by_lane,
            "affected_index_entries": affected,
            "head_excluded_to_avoid_self_referential_decision_commit": True,
            "decision_ref_excluded_from_affected_projection": expected_decision_ref,
        }

        try:
            second_snapshot = repository_snapshot(
                root, str(request["expected_branch"])
            )
        except PreconditionError as exc:
            report["repository"]["snapshot_raced"] = True
            report["repository"]["clean"] = False
            raise PreconditionError(
                "Repository state changed while the proposal digest was being computed."
            ) from exc
        if snapshot_identity(first_snapshot) != snapshot_identity(second_snapshot):
            report["repository"]["snapshot_raced"] = True
            raise PreconditionError("Repository state changed while the proposal digest was being computed.")

        report["waves"] = waves
        report["client_projections"] = projections
        report["subject"] = subject
        report["summary"].update(
            {
                "lanes": len(lanes),
                "waves": len(waves),
                "affected_files": len(affected),
                "affected_bytes": affected_bytes,
            }
        )
        status, decision = decision_status(root, request, subject)
        report["decision"] = decision
        try:
            final_snapshot = repository_snapshot(
                root, str(request["expected_branch"])
            )
        except PreconditionError as exc:
            report["repository"]["snapshot_raced"] = True
            report["repository"]["clean"] = False
            raise PreconditionError(
                "Repository state changed while the human decision was being validated."
            ) from exc
        if snapshot_identity(first_snapshot) != snapshot_identity(final_snapshot):
            report["repository"]["snapshot_raced"] = True
            raise PreconditionError(
                "Repository state changed while the human decision was being validated."
            )
        if status == "human_dispatch_required":
            report["findings"] = [
                finding(
                    "agent_orchestration.human_dispatch_required",
                    "advisory",
                    "The exact owner decision is valid; any actual client invocation remains a separate manual human action.",
                )
            ]
            return finish(report, status)
        if status == "decision_required":
            return finish(
                report,
                status,
                finding("agent_orchestration.decision_required", "blocking", "The exact digest-bound human decision is absent."),
            )
        return finish(
            report,
            status,
            finding(
                f"agent_orchestration.{status}",
                "blocking",
                f"The exact human decision outcome is {decision.get('outcome')}; no dispatch is allowed.",
            ),
        )
    except ContractError as exc:
        return finish(report, "invalid_contract", finding("agent_orchestration.invalid_contract", "blocking", str(exc)))
    except (PreconditionError, ValueError) as exc:
        return finish(report, "precondition_failed", finding("agent_orchestration.precondition_failed", "blocking", str(exc)))


def validate_report(root: Path, report: dict[str, Any]) -> None:
    validate_document(
        report,
        load_json_mapping(schema_path(root, "agent_orchestration_plan.schema.json")),
        label="agent orchestration plan report",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic Assured-only agent-work proposal. The command does not launch clients, "
            "write client configuration, change tasks, approve results, merge, push, release, or publish."
        )
    )
    parser.add_argument("--root", default=".", help="Exact Git worktree root (default: current directory).")
    parser.add_argument("--naos-root", default=None, help="NAOS governance directory (default from policy).")
    parser.add_argument("--profile", default=None, help="NAOS profile; only assured is applicable.")
    parser.add_argument("--policy", default=None, help="Optional governance policy path.")
    parser.add_argument(
        "--orchestration-policy",
        default=None,
        help="Agent orchestration policy path (default: <naos-root>/agent_orchestration_policy.yaml).",
    )
    parser.add_argument(
        "--request",
        default=None,
        help="Per-run orchestration request path (default: <naos-root>/agent_orchestration_request.yaml).",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    governance_policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(governance_policy)
    try:
        profile = normalize_profile(args.profile, governance_policy)
    except ValueError as exc:
        report = empty_report(root, str(naos_root), "quickstart")
        report, code = finish(report, "invalid_contract", finding("agent_orchestration.profile", "blocking", str(exc)))
    else:
        default_root = root / str(naos_root)
        orchestration_policy_path = Path(args.orchestration_policy).resolve() if args.orchestration_policy else default_root / "agent_orchestration_policy.yaml"
        request_path = Path(args.request).resolve() if args.request else default_root / "agent_orchestration_request.yaml"
        report, code = build_report(
            root,
            str(naos_root),
            profile,
            governance_policy,
            orchestration_policy_path,
            request_path,
        )

    try:
        validate_report(root, report)
    except (ContractError, RuntimeError, OSError) as exc:
        report["status"] = "invalid_contract"
        report["findings"].append(finding("agent_orchestration.output", "blocking", str(exc)))
        code = 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
