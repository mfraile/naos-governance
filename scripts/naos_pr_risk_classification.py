#!/usr/bin/env python3
"""Classify pull-request risk from deterministic local diff metadata."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from naos_policy import (  # noqa: E402
    default_naos_root,
    escalate_profile,
    exit_code_for_summary,
    finding_counts,
    is_kit_repository,
    load_policy,
    normalize_profile,
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)

# Per-task risk routing (QW1/AP5): default tier mapping (adopter-overridable via
# pr_risk_rules.yaml `risk_tier_map`). Advisory, escalate-up-only; never enforced here.
DEFAULT_RISK_TIER_MAP = {
    "high": {"categories": ["secret_like", "prompt_injection", "protected_path"], "implies_profile": "assured"},
    "medium": {"categories": ["dependency", "workflow", "ai_surface"], "implies_profile": "standard"},
}


def derive_risk_tier(category_counts: dict[str, int], rules: dict[str, Any] | None = None) -> tuple[str, str | None]:
    """Map pr-risk category presence to a risk tier and the profile it implies.

    Returns (risk_tier, implied_profile). 'low' implies no escalation (None). This is
    deterministic, advisory review input — not approval, enforcement, or runtime action.
    """
    tier_map = (rules or {}).get("risk_tier_map") if isinstance(rules, dict) else None
    tier_map = tier_map if isinstance(tier_map, dict) and tier_map else DEFAULT_RISK_TIER_MAP
    present = {cat for cat, count in (category_counts or {}).items() if count}
    for tier in ("high", "medium"):
        spec = tier_map.get(tier) or {}
        if present.intersection(set(spec.get("categories") or [])):
            return tier, spec.get("implies_profile")
    return "low", None


SCHEMA = "naos.pr_risk_classification.v1"
NOT_CLAIMED = [
    "PR approval",
    "security proof",
    "malware analysis",
    "sandbox execution",
    "prompt-injection prevention",
    "legal or regulatory compliance",
    "proof of compliance",
    "certification",
    "release authorization",
    "deployment authorization",
    "DSSE signing",
    "signature verification",
    "key custody",
    "proof of execution",
    "human review replacement",
]
LIMITATIONS = [
    "Classification is deterministic and local; it reviews path and diff metadata only.",
    "The classifier does not execute changed code, install dependencies, run sandboxes, call providers, or call the network.",
    "Pattern findings are review signals and can be false positives or false negatives.",
    "Contributor trust metadata from CI or environment variables is governance metadata, not authentication or authorization.",
    "Human review remains required for protected path, dependency, workflow, prompt, secret-like, and governance-surface decisions.",
]
DEFAULT_RULES = {
    "trusted_authors": [],
    "protected_path_patterns": [
        ".github/**",
        ".githooks/**",
        ".claude/hooks/**",
        ".claude/settings.json",
        ".codex/config.toml",
        ".vscode/mcp.json",
        ".cursor/mcp.json",
        ".mcp.json",
        ".ai/mcp.json",
        "mcp.json",
        ".agents/mcp_config.json",
        ".kilo/kilo.jsonc",
        "opencode.json",
        "policies/**",
        "schemas/**",
        "capabilities/**",
        "templates/**",
        "scripts/validators/**",
        "naos/**",
    ],
    "test_contract_path_patterns": ["tests/**", "test/**", "**/tests/**", "**/test/**", "test_*.py", "**/test_*.py", "*_test.py", "**/*_test.py"],
    "workflow_path_patterns": [".github/workflows/**", "templates/workflows/**"],
    "dependency_path_patterns": [
        "pyproject.toml",
        "requirements*.txt",
        "requirements/**",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
    ],
    "ai_surface_path_patterns": [
        "CLAUDE.md",
        "AGENTS.md",
        "**/AGENTS.md",
        "GEMINI.md",
        "**/GEMINI.md",
        ".github/copilot-instructions.md",
        ".github/agents/**",
        ".github/prompts/**",
        ".github/skills/**",
        ".github/instructions/**",
        ".cursor/rules/**",
        "templates/agents/**",
        "templates/prompts/**",
        "templates/skills/**",
        "templates/instructions/**",
        "templates/instruction-triple/**",
    ],
    "governance_path_patterns": [
        "capabilities/**",
        "policies/**",
        "schemas/**",
        "templates/structural-seeds/naos/**",
        "docs/decisions/**",
        "docs/CLAIMS_AND_LIMITATIONS.md",
        "docs/NAOS_THREAT_MODEL.md",
    ],
    "prompt_injection_patterns": [
        "(?i)ignore (all )?(previous|prior) instructions",
        "(?i)disregard (all )?(previous|prior) instructions",
        "(?i)system prompt",
        "(?i)developer message",
        "(?i)return status: ?passed",
        "(?i)do not tell",
    ],
    "secret_like_patterns": [
        "\\bAKIA[0-9A-Z]{16}\\b",
        "\\bsk-[A-Za-z0-9_-]{20,}\\b",
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "(?i)\\b(password|passwd|pwd|secret|token|api[_-]?key|credential)\\b\\s*[:=]\\s*['\\\"][^'\\\"]{8,}['\\\"]",
    ],
    "max_diff_lines_scanned": 4000,
}


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_readonly_git_diff(root: Path, args: list[str], **options: Any) -> subprocess.CompletedProcess:
    """Let Git filter stat-only differences using a disposable index copy."""
    located = subprocess.run(
        ["git", "--no-optional-locks", "rev-parse", "--git-path", "index"],
        cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if located.returncode != 0:
        raise RuntimeError("Cannot locate Git index: " + located.stderr.decode("utf-8", errors="replace").strip())
    name = os.fsdecode(located.stdout).removesuffix("\n")
    if os.name == "nt":
        name = name.removesuffix("\r")
    if not name or "\x00" in name:
        raise RuntimeError("Git returned an invalid index path")
    index = Path(name)
    if not index.is_absolute():
        index = root / index
    try:
        temp_root = Path(tempfile.gettempdir()).resolve()
        if temp_root.is_relative_to(root.resolve()) or temp_root.is_relative_to(index.parent.resolve()):
            raise RuntimeError("Read-only Git diff requires temporary storage outside the project and index directory")
        scratch = tempfile.TemporaryDirectory(prefix="naos-git-diff-", dir=temp_root)
    except OSError as exc:
        raise RuntimeError(f"Cannot prepare private Git index: {exc}") from exc
    with scratch as temporary:
        private_index = Path(temporary) / "index"
        try:
            raw = index.read_bytes()
        except FileNotFoundError:
            pass  # Preserve an actually absent index as absent, not an empty file.
        else:
            with private_index.open("xb") as stream:
                stream.write(raw)
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(private_index)
        # Keep Git's content filter; any refresh writes only the disposable
        # index. Disable new split-index publication in repository metadata.
        return subprocess.run(
            ["git", "--no-optional-locks", "-c", "core.splitIndex=false", *args],
            cwd=root, env=environment, **options,
        )


def run_git(root: Path, args: list[str]) -> tuple[int, str, str]:
    try:
        options = dict(text=True, encoding="utf-8", errors="surrogateescape",
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if args and args[0] == "diff":
            result = _run_readonly_git_diff(root, args, **options)
        else:
            result = subprocess.run(["git", "--no-optional-locks", *args], cwd=root, **options)
    except FileNotFoundError:
        return 127, "", "git not found"
    except (OSError, RuntimeError) as exc:
        return 1, "", f"Read-only Git observation unavailable: {exc}"
    return result.returncode, result.stdout, result.stderr


def load_yaml(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def default_rules_path(root: Path, naos_root: str, explicit: str | None, policy: dict[str, Any]) -> Path | None:
    if explicit:
        return Path(explicit)
    filename = str(policy.get("paths", {}).get("pr_risk_rules") or "pr_risk_rules.yaml")
    project_rules = root / naos_root / filename
    if project_rules.exists() and not is_kit_repository(root, naos_root):
        return project_rules
    template = Path(__file__).resolve().parents[1] / "templates" / "structural-seeds" / "naos" / filename
    return template if template.exists() else None


def merge_rules(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_rules(merged[key], value)
        else:
            merged[key] = value
    return merged


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    cleaned = str(value).strip()
    return [cleaned] if cleaned else []


def patterns_for(rules: dict[str, Any], key: str) -> list[str]:
    return as_list(rules.get(key))


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) or path == pattern.rstrip("/") for pattern in patterns)


def compile_patterns(patterns: list[str]) -> list[tuple[str, re.Pattern[str]]]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        try:
            compiled.append((pattern, re.compile(pattern)))
        except re.error:
            continue
    return compiled


def current_branch(root: Path) -> str | None:
    code, out, _ = run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    return out.strip() if code == 0 and out.strip() else None


def current_commit(root: Path) -> str | None:
    code, out, _ = run_git(root, ["rev-parse", "HEAD"])
    return out.strip() if code == 0 and out.strip() else None


def validate_diff_ref(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    ref = value.strip()
    if not ref:
        return None
    if ref.startswith("-") or any(ch.isspace() or ord(ch) < 32 for ch in ref):
        raise ValueError(f"{label} is not a safe git ref")
    if ".." in ref or ref.endswith(".") or "@{" in ref or "\\" in ref:
        raise ValueError(f"{label} is not a safe git ref")
    return ref


def infer_diff_args(base_ref: str | None, head_ref: str | None) -> tuple[list[str], str]:
    base_ref = validate_diff_ref(base_ref, label="base_ref")
    head_ref = validate_diff_ref(head_ref, label="head_ref")
    if base_ref and head_ref:
        return [f"{base_ref}...{head_ref}"], "explicit_base_head"
    if base_ref:
        return [f"{base_ref}...HEAD"], "explicit_base_to_head"
    if head_ref:
        raise ValueError("head_ref requires base_ref for a PR comparison")
    return ["HEAD"], "working_tree_vs_head"


def resolve_diff_comparison(root: Path, base_ref: str | None, head_ref: str | None) -> dict[str, Any]:
    """Freeze each requested comparison endpoint to a commit before diff reads."""
    try:
        _, source = infer_diff_args(base_ref, head_ref)
        base = validate_diff_ref(base_ref, label="base_ref")
        head = validate_diff_ref(head_ref, label="head_ref")
    except ValueError as exc:
        return {"diff_source": "invalid_comparison", "diff_args": [], "git_status": "unavailable", "error": str(exc)}
    refs = [("base_ref", base), ("head_ref", head or "HEAD")] if base else [("head_ref", "HEAD")]
    resolved: dict[str, str] = {}
    for label, ref in refs:
        code, out, err = run_git(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
        commit = out.strip()
        if code != 0 or not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
            return {
                "diff_source": source,
                "diff_args": [],
                "git_status": "unavailable",
                "git_exit_code": code,
                "error": f"{label} does not resolve to a commit: {sanitized_git_error(err, root)}",
            }
        resolved[label] = commit
    diff_args = (
        [f"{resolved['base_ref']}...{resolved['head_ref']}"]
        if base else [resolved["head_ref"]]
    )
    return {"diff_source": source, "diff_args": diff_args, "git_status": "available", "resolved_commits": resolved}


def untracked_files(root: Path, metadata: dict[str, Any] | None = None) -> list[dict[str, str]]:
    code, out, err = run_git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if code != 0:
        if metadata is not None:
            metadata.update({
                "untracked_git_status": "unavailable",
                "untracked_git_exit_code": code,
                "untracked_error": sanitized_git_error(err, root),
            })
        return []
    if metadata is not None:
        metadata["untracked_git_status"] = "available"
    files: list[dict[str, str]] = []
    for record in out.split("\0"):
        if not record.startswith("?? "):
            continue
        path = record[3:]
        if path:
            files.append({"status": "??", "path": path})
    return files


def sanitized_git_error(error: str, root: Path) -> str:
    """Keep useful Git context without exposing local roots or control characters."""
    message = error.strip().replace(str(root), "<project>").replace(str(Path.home()), "<home>")
    message = re.sub(r"(?i)(://[^\s/:@]+:)[^\s@]+@", r"\1<redacted>@", message)
    return "".join(ch if ch.isprintable() or ch == "\n" else "?" for ch in message)[:500] or "git command failed"


def parse_name_status_z(output: str) -> list[dict[str, str]]:
    if not output:
        return []
    if not output.endswith("\0"):
        raise ValueError("git name-status output was not NUL terminated")
    fields = output[:-1].split("\0")
    files: list[dict[str, str]] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if not re.fullmatch(r"[A-Z?][0-9]*", status):
            raise ValueError("git name-status output had an invalid status")
        path_count = 2 if status.startswith(("R", "C")) else 1
        if index + path_count > len(fields):
            raise ValueError("git name-status output was truncated")
        for path in fields[index : index + path_count]:
            if not path:
                raise ValueError("git name-status output had an empty path")
            files.append({"status": status, "path": path})
        index += path_count
    return files


def changed_files(
    root: Path, base_ref: str | None, head_ref: str | None, comparison: dict[str, Any] | None = None
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    metadata = dict(comparison if comparison is not None else resolve_diff_comparison(root, base_ref, head_ref))
    if metadata["git_status"] != "available":
        return [], metadata
    diff_args, source = metadata["diff_args"], metadata["diff_source"]
    code, out, err = run_git(root, ["diff", "--name-status", "-z", "--no-ext-diff", *diff_args])
    if code != 0:
        metadata.update({"git_status": "unavailable", "git_exit_code": code, "error": sanitized_git_error(err, root)})
        return [], metadata
    try:
        files = parse_name_status_z(out)
    except ValueError as exc:
        metadata.update({"git_status": "unavailable", "error": str(exc)})
        return [], metadata
    if source == "working_tree_vs_head":
        existing = {item["path"] for item in files}
        untracked = [item for item in untracked_files(root, metadata) if item["path"] not in existing]
        if untracked:
            files.extend(untracked)
            metadata["untracked_files_included"] = len(untracked)
    return files, metadata


def untracked_added_lines(root: Path, limit: int, already_scanned: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lines: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"untracked_files_scanned": 0, "untracked_lines_scanned": 0}
    remaining = max(0, limit - already_scanned)
    if remaining == 0:
        metadata["truncated"] = True
        return lines, metadata
    for item in untracked_files(root, metadata):
        if remaining <= 0:
            metadata["truncated"] = True
            break
        path = item["path"]
        full_path = root / path
        if not full_path.is_file():
            continue
        try:
            text = full_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            metadata.setdefault("binary_or_non_utf8_skipped", []).append(path)
            continue
        except OSError:
            metadata.setdefault("unreadable_skipped", []).append(path)
            continue
        metadata["untracked_files_scanned"] += 1
        for line_number, text_line in enumerate(text.splitlines(), start=1):
            if remaining <= 0:
                metadata["truncated"] = True
                break
            lines.append({"path": path, "line": line_number, "text": text_line})
            remaining -= 1
            metadata["untracked_lines_scanned"] += 1
    return lines, metadata


def added_diff_lines(
    root: Path, base_ref: str | None, head_ref: str | None, limit: int, comparison: dict[str, Any] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    metadata = dict(comparison if comparison is not None else resolve_diff_comparison(root, base_ref, head_ref))
    if metadata["git_status"] != "available":
        return [], metadata
    diff_args, source = metadata["diff_args"], metadata["diff_source"]
    code, out, err = run_git(root, ["diff", "--unified=0", "--no-ext-diff", *diff_args])
    if code != 0:
        metadata.update({"git_status": "unavailable", "git_exit_code": code, "error": sanitized_git_error(err, root)})
        return [], metadata
    results: list[dict[str, Any]] = []
    current_path: str | None = None
    current_line = 0
    scanned = 0
    for line in out.splitlines():
        if scanned >= limit:
            metadata["truncated"] = True
            break
        if line.startswith("+++ b/"):
            current_path = line[6:]
            current_line = 0
            continue
        if line.startswith("+++ "):
            current_path = None
            if line != "+++ /dev/null":
                metadata["unparsed_added_file_headers"] = metadata.get("unparsed_added_file_headers", 0) + 1
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            current_line = int(match.group(1)) if match else 0
            continue
        if current_path and line.startswith("+") and not line.startswith("+++"):
            scanned += 1
            results.append({"path": current_path, "line": current_line or None, "text": line[1:]})
            current_line += 1
        elif current_path and not line.startswith("-"):
            current_line += 1 if current_line else 0
    metadata["lines_scanned"] = scanned
    if source == "working_tree_vs_head":
        untracked_lines, untracked_metadata = untracked_added_lines(root, limit, scanned)
        results.extend(untracked_lines)
        metadata["untracked"] = untracked_metadata
    return results, metadata


def classify_contributor(rules: dict[str, Any]) -> dict[str, Any]:
    actor = (
        os.environ.get("GITHUB_ACTOR")
        or os.environ.get("NAOS_PR_AUTHOR")
        or os.environ.get("PR_AUTHOR")
    )
    trusted = set(as_list(rules.get("trusted_authors")) + as_list(os.environ.get("NAOS_TRUSTED_CONTRIBUTORS")))
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    fork = os.environ.get("GITHUB_HEAD_REPO_FORK", "").strip().lower() in {"1", "true", "yes"}
    if actor and actor in trusted:
        trust = "trusted"
        reason = "actor matched configured trusted author list"
    elif actor:
        trust = "untrusted" if event_name == "pull_request" or fork else "unknown"
        reason = "actor present but not in configured trusted author list"
    else:
        trust = "local_preview"
        reason = "no PR author metadata detected"
    return {
        "actor": actor,
        "trust": trust,
        "event_name": event_name,
        "fork": fork,
        "source": "github_actions_env" if os.environ.get("GITHUB_ACTIONS") else "local_env",
        "reason": reason,
        "not_claimed": [
            "authentication",
            "authorization",
            "team membership proof",
            "identity proof",
        ],
    }


def finding(
    *,
    finding_id: str,
    severity: str,
    status: str,
    message: str,
    path: str | None = None,
    line: int | None = None,
    category: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "category": category,
        "human_review_required": True,
        "not_claimed": NOT_CLAIMED,
    }
    if path:
        item["path"] = path
    if line:
        item["line"] = line
    if details:
        item.update(details)
    return item


def classify_file(path: str, rules: dict[str, Any], severity: str) -> tuple[list[str], list[dict[str, Any]]]:
    categories: list[str] = []
    findings: list[dict[str, Any]] = []
    checks = [
        ("protected_path", "protected_path_patterns", "pr_risk.protected_path", "Changed file touches a protected governance or CI path."),
        ("test_contract", "test_contract_path_patterns", "pr_risk.test_contract_change", "Changed test file requires comparison with the retained baseline, specification and human approval before assertion weakening, skip/xfail, retry or timeout changes; this signal does not prove tampering."),
        ("workflow", "workflow_path_patterns", "pr_risk.workflow_change", "Changed file touches workflow configuration."),
        ("dependency", "dependency_path_patterns", "pr_risk.dependency_change", "Changed file touches dependency manifests or lockfiles."),
        ("ai_surface", "ai_surface_path_patterns", "pr_risk.ai_surface_change", "Changed file touches AI instruction, prompt, agent, skill, or rule surfaces."),
        ("governance_surface", "governance_path_patterns", "pr_risk.governance_surface_change", "Changed file touches NAOS governance surfaces."),
    ]
    for category, key, finding_id, message in checks:
        if matches_any(path, patterns_for(rules, key)):
            categories.append(category)
            findings.append(
                finding(
                    finding_id=finding_id,
                    severity=severity,
                    status="review_required",
                    message=message,
                    path=path,
                    category=category,
                    details={"matched_rule_group": key},
                )
            )
    return categories, findings


def classify_diff_lines(lines: list[dict[str, Any]], rules: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    prompt_patterns = compile_patterns(patterns_for(rules, "prompt_injection_patterns"))
    secret_patterns = compile_patterns(patterns_for(rules, "secret_like_patterns"))
    for line in lines:
        text = str(line.get("text") or "")
        path = str(line.get("path") or "")
        line_number = line.get("line") if isinstance(line.get("line"), int) else None
        for pattern_id, pattern in prompt_patterns:
            if pattern.search(text):
                findings.append(
                    finding(
                        finding_id="pr_risk.prompt_injection_text",
                        severity=severity,
                        status="review_required",
                        message="Changed line resembles prompt-injection or reviewer-manipulation text.",
                        path=path,
                        line=line_number,
                        category="prompt_injection",
                        details={"pattern_id": pattern_id, "raw_text_redacted": True},
                    )
                )
                break
        for pattern_id, pattern in secret_patterns:
            if pattern.search(text):
                findings.append(
                    finding(
                        finding_id="pr_risk.secret_like_added_line",
                        severity=severity,
                        status="review_required",
                        message="Changed line resembles secret-like material; raw value is not included in the report.",
                        path=path,
                        line=line_number,
                        category="secret_like",
                        details={"pattern_id": pattern_id, "raw_text_redacted": True},
                    )
                )
                break
    return findings


def diff_evidence_complete(metadata: dict[str, Any]) -> bool:
    untracked = metadata.get("untracked") or {}
    return (
        metadata["git_status"] == "available"
        and metadata.get("untracked_git_status") != "unavailable"
        and not metadata.get("truncated")
        and not metadata.get("unparsed_added_file_headers")
        and untracked.get("untracked_git_status") != "unavailable"
        and not untracked.get("truncated")
        and not untracked.get("unreadable_skipped")
        and not untracked.get("binary_or_non_utf8_skipped")
    )


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.project_path or ".").resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    rules_path = default_rules_path(root, naos_root, args.rules, policy)
    rules = merge_rules(DEFAULT_RULES, load_yaml(rules_path))
    severity = severity_for_profile(profile, policy)
    comparison = resolve_diff_comparison(root, args.base_ref, args.head_ref)
    files, diff_metadata = changed_files(root, args.base_ref, args.head_ref, comparison)
    diff_lines, diff_line_metadata = added_diff_lines(
        root,
        args.base_ref,
        args.head_ref,
        int(rules.get("max_diff_lines_scanned") or DEFAULT_RULES["max_diff_lines_scanned"]),
        comparison,
    )

    findings: list[dict[str, Any]] = []
    diff_available = diff_evidence_complete(diff_metadata) and diff_evidence_complete(diff_line_metadata)
    if not diff_available:
        findings.append(
            finding(
                finding_id="pr_risk.diff_unavailable",
                severity=severity,
                status="unavailable",
                message="PR risk classification is inconclusive because required Git diff evidence is unavailable or incomplete.",
                category="diff_unavailable",
                details={
                    "name_status_available": diff_evidence_complete(diff_metadata),
                    "added_lines_available": diff_evidence_complete(diff_line_metadata),
                },
            )
        )
    changed: list[dict[str, Any]] = []
    for item in files:
        path = item["path"]
        categories, file_findings = classify_file(path, rules, severity)
        changed.append({"path": path, "status": item["status"], "risk_categories": categories})
        findings.extend(file_findings)
    findings.extend(classify_diff_lines(diff_lines, rules, severity))

    contributor = classify_contributor(rules)
    if contributor["trust"] in {"untrusted", "unknown"} and files:
        findings.append(
            finding(
                finding_id="pr_risk.untrusted_or_unknown_contributor",
                severity=severity,
                status="review_required",
                message="Contributor trust posture is untrusted or unknown; review risky surfaces before relying on PR evidence.",
                category="contributor_trust",
                details={"trust": contributor["trust"], "actor": contributor.get("actor")},
            )
        )

    summary = finding_counts(findings)
    category_counts: dict[str, int] = {}
    for item in findings:
        category = str(item.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
    risk_tier, risk_implied_profile = derive_risk_tier(category_counts, rules) if diff_available else ("unknown", None)
    summary.update(
        {
            "changed_files": len(changed),
            "risk_files": sum(1 for item in changed if item.get("risk_categories")),
            "category_counts": category_counts,
            "risk_tier": risk_tier,
            "risk_implied_profile": risk_implied_profile,
            # Advisory escalate-up-only effective profile; recorded review guidance, not enforced.
            "effective_profile": escalate_profile(profile, risk_implied_profile),
        }
    )

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "profile": profile,
        "status": status_from_counts(summary),
        "classification_status": "complete" if diff_available else "inconclusive",
        "project_root": str(root),
        "naos_root": naos_root,
        "rules_path": str(rules_path) if rules_path else None,
        "deterministic": True,
        "cost_posture": {
            "cost_incurred_by_default": False,
            "cost_usd": 0.0,
            "external_api_required": False,
            "provider_dependency_required": False,
            "model_dependency_required": False,
            "human_approval_required_before_cost": True,
        },
        "git": {
            "branch": current_branch(root),
            "commit_sha": current_commit(root),
            "base_ref": args.base_ref,
            "head_ref": args.head_ref,
            "diff_metadata": diff_metadata,
            "diff_line_metadata": diff_line_metadata,
        },
        "contributor": contributor,
        "changed_files": changed,
        "summary": summary,
        "findings": findings,
        "known_gaps": [
            "sandbox_execution_not_implemented",
            "clean_room_attestation_not_implemented",
            "contributor_identity_not_authenticated_by_naos",
        ],
        "residual_risks": [
            "Path and pattern checks can miss malicious behavior hidden in apparently low-risk files.",
            "Diff metadata can be incomplete outside CI or when base/head refs are unavailable.",
            "Repository owners must decide how to treat findings in branch protection and review policy.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classify pull-request risk from deterministic local diff metadata.")
    parser.add_argument("project_path", nargs="?", default=".", help="Project repository path. Default: current directory.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--rules", help="Optional pr_risk_rules.yaml path.")
    parser.add_argument("--base-ref", default=os.environ.get("GITHUB_BASE_REF") or os.environ.get("NAOS_PR_BASE_REF"))
    parser.add_argument("--head-ref", default=os.environ.get("GITHUB_HEAD_REF") or os.environ.get("NAOS_PR_HEAD_REF"))
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = build_report(args)
    except ValueError as exc:
        print(f"NAOS PR risk classification error: {exc}", file=sys.stderr)
        return 2
    root = Path(args.project_path or ".").resolve()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "pr_risk_classification_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "NAOS PR risk classification: "
            f"{report['status']} "
            f"({report['summary']['risk_files']}/{report['summary']['changed_files']} risky files, "
            f"{report['summary']['total_findings']} findings, "
            f"output: {output if output else 'stdout only'})"
        )
    return exit_code_for_summary(report["profile"], report["summary"], policy, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
