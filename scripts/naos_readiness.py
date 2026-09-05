#!/usr/bin/env python3
"""NAOS readiness checker.

Reports whether a repo is ready for the next lifecycle capability. It is
deliberately conservative: moment-zero scaffold may pass while baseline or task
work remains blocked until specs, ADAPT markers, and task/AC anchors exist.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - PyYAML is a package dependency
    yaml = None  # type: ignore[assignment]

from naos_mcp_config_registry import (  # noqa: E402
    resolve_engram_project,
    scan_mcp_configs,
    summarize_mcp_configs,
)


REQUIRED_SPECS = [
    "01-problem.md",
    "02-solution.md",
    "03-requirements.md",
    "04-architecture.md",
]
VALID_MEMORY_STATES = {
    "deferred",
    "pending_external_verification",
    "pending_existing_verification",
    "configured",
    "disabled",
    "broken",
}
MCP_NAMESPACE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]{0,63}(?:/(?:\*|[A-Za-z][A-Za-z0-9_-]{0,63}))?$"
)
MCP_NAMESPACE_SENSITIVE_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|bearer|connection[_-]?string|password|secret|token|^(?:sk[-_]|ghp_|glpat-|xox))"
)


def _has_unresolved_markers(text: str) -> bool:
    return bool(re.search(r"\[(?:ADAPT|FILL):[^\]]+\]|\{\{carry:[^}]+\}\}", text))


def _status(ok: bool, label: str, detail: str = "") -> None:
    prefix = "PASS" if ok else "BLOCK"
    line = f"[{prefix}] {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def _check_specs(root: Path, strict_markers: bool) -> bool:
    specs_root = root / "specs"
    ok = True
    for name in REQUIRED_SPECS:
        path = specs_root / name
        if not path.is_file():
            _status(False, f"spec required: specs/{name}", "missing")
            ok = False
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        enough = len(text.strip()) >= 250
        unresolved = _has_unresolved_markers(text)
        _status(enough, f"spec has content: specs/{name}")
        if not enough:
            ok = False
        if strict_markers:
            _status(not unresolved, f"spec placeholders resolved: specs/{name}")
            if unresolved:
                ok = False
        elif unresolved:
            print(f"[WARN] spec placeholders remain: specs/{name}")
    return ok


def _extract_fr_ids(text: str) -> set[str]:
    return set(re.findall(r"\bFR-\d+(?:-\d+)?\b", text))


def _check_task_registry(root: Path) -> bool:
    registry = root / "naos" / "TASK_REGISTRY.yaml"
    if not registry.is_file():
        _status(False, "task registry", "naos/TASK_REGISTRY.yaml missing")
        return False
    if yaml is None:
        _status(False, "task registry YAML", "PyYAML unavailable")
        return False
    try:
        data = yaml.safe_load(registry.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        _status(False, "task registry YAML", str(exc))
        return False

    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    _status(isinstance(tasks, list), "task registry structure")
    if not isinstance(tasks, list):
        return False

    req_file = root / "specs" / "03-requirements.md"
    fr_ids = _extract_fr_ids(req_file.read_text(encoding="utf-8", errors="ignore")) if req_file.is_file() else set()
    ok = True
    for task in tasks:
        if not isinstance(task, dict):
            continue
        task_id = str(task.get("id", "<missing>"))
        requirement = str(task.get("requirement", "")).strip()
        if not requirement or requirement.upper() in {"TBD", "TODO", "NONE"}:
            print(f"[WARN] task {task_id} has no concrete requirement anchor")
            continue
        if fr_ids and requirement not in fr_ids:
            _status(False, f"task {task_id} requirement exists", requirement)
            ok = False
    if ok:
        _status(True, "task requirements cross-reference specs/03")
    return ok


def _check_ai_config(root: Path) -> bool:
    path = root / "configs" / "naos_ai_precommit.yaml"
    if not path.is_file():
        print("[WARN] AI review config not present; static governance can still run")
        return True
    if yaml is None:
        _status(False, "AI config YAML", "PyYAML unavailable")
        return False
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        _status(False, "AI config YAML", str(exc))
        return False
    mode = str(data.get("ai_review", {}).get("mode", data.get("mode", "static_only")))
    valid = {"disabled", "static_only", "local_ollama", "api_provider", "ide_agent", "advisory", "blocking"}
    _status(mode in valid, "AI policy mode", mode)
    return mode in valid


def _memory_data_dir_issue(value: object, root: Path) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "data_dir must be a non-empty absolute path or start with '~/'."
    supplied = value.strip()
    if any(character in supplied for character in ("\x00", "\n", "\r")):
        return "data_dir must be a single-line path."
    try:
        expanded = Path(supplied).expanduser()
    except RuntimeError:
        return "data_dir user-home expansion failed."
    if not expanded.is_absolute():
        return "data_dir must be absolute or start with '~/'."
    if expanded.name == "engram.db" or expanded.suffix.casefold() in {".db", ".sqlite"}:
        return "data_dir must name the directory containing engram.db, not a database file."
    try:
        expanded.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return "data_dir must remain outside the project repository."


def _memory_namespace_issue(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "configured memory requires a declared MCP namespace."
    namespace = value.strip()
    if not MCP_NAMESPACE_PATTERN.fullmatch(namespace) or MCP_NAMESPACE_SENSITIVE_PATTERN.search(namespace):
        return "MCP namespace must be a non-sensitive tool name such as 'engram' or 'engram/*'."
    return None


def _report_memory_issue(issue: str, *, strict: bool) -> None:
    if strict:
        _status(False, "strict memory readiness", issue)
    else:
        print(f"[WARN] memory config — {issue}")


def _check_memory_config(root: Path, strict: bool) -> bool:
    path = root / "configs" / "naos_memory.yaml"
    if not path.is_file():
        message = "configs/naos_memory.yaml missing; run naos memory check/setup"
        if strict:
            _status(False, "memory config", message)
            return False
        print(f"[WARN] memory config — {message}")
        return True
    if yaml is None:
        _status(False, "memory config YAML", "PyYAML unavailable")
        return False
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        _status(False, "memory config YAML", str(exc))
        return False
    memory = data.get("memory", data) if isinstance(data, dict) else {}
    if not isinstance(memory, dict):
        _status(False, "memory config structure", "memory must be a YAML mapping")
        return False
    state = str(memory.get("state", "unknown")) if isinstance(memory, dict) else "unknown"
    valid_state = state in VALID_MEMORY_STATES
    _status(valid_state, "memory state", state)
    if not valid_state:
        return False

    enabled = memory.get("enabled")
    if state == "configured" and enabled is not True:
        _status(
            False,
            "memory state/enabled invariant",
            "state configured requires enabled: true",
        )
        return False
    if state != "configured" and enabled is True:
        _status(
            False,
            "memory state/enabled invariant",
            f"enabled: true requires state configured, not {state}",
        )
        return False
    if state == "broken":
        _status(False, "memory state", "broken configuration requires repair")
        return False

    if state != "configured":
        message = "memory-aware workflows use degraded recovery until Engram/MCP is configured"
        if strict:
            _status(False, "strict memory readiness", message)
            return False
        print(f"[WARN] {message}")
        return True

    issues: list[str] = []
    if str(memory.get("replication_profile") or "").strip() != "local":
        issues.append("replication_profile must be local; NAOS does not configure Git or cloud replication.")
    if data_dir_issue := _memory_data_dir_issue(memory.get("data_dir"), root):
        issues.append(data_dir_issue)
    if namespace_issue := _memory_namespace_issue(memory.get("mcp_namespace")):
        issues.append(namespace_issue)

    mcp_rows = scan_mcp_configs(root)
    mcp_summary = summarize_mcp_configs(mcp_rows)
    identity = resolve_engram_project(memory, mcp_rows)
    if not mcp_summary.get("mcp_configured"):
        issues.append("no workspace Engram MCP server declaration was found; configuration presence is not access.")
    identity_status = identity.get("status")
    dynamic_assertion = bool(
        identity_status == "declared_candidate"
        and str(memory.get("mcp_project") or "").strip()
        and mcp_summary.get("mcp_configured")
    )
    if identity_status != "declared_consistent" and not dynamic_assertion:
        issues.append(
            "project identity is unresolved "
            f"({identity_status}); require an explicit repository project assertion, "
            "agreeing workspace declarations, or registry equivalence evidence."
        )

    for issue in issues:
        _report_memory_issue(issue, strict=strict)
    if not issues:
        print(
            "[REVIEW] memory configuration assertion is coherent, but project identity "
            "and MCP access remain externally unverified; use the approved provider/access "
            "check before claiming live memory usability."
        )
    return not (strict and issues)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check NAOS lifecycle readiness")
    parser.add_argument("--project-root", default=".", help="Project root to inspect")
    parser.add_argument(
        "--target",
        choices=["phase2", "baseline", "drift"],
        default="baseline",
        help="Capability readiness target",
    )
    parser.add_argument(
        "--allow-adapt",
        action="store_true",
        help="Warn on unresolved [ADAPT]/[FILL] markers instead of blocking",
    )
    parser.add_argument(
        "--strict-memory",
        action="store_true",
        help=(
            "Block unless repository Engram configuration is coherent; this does not "
            "verify live project identity or MCP access"
        ),
    )
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    if not root.is_dir():
        print(f"[ERROR] Project root not found: {root}")
        return 2

    print(f"NAOS readiness check: target={args.target} project={root}")
    strict = not args.allow_adapt
    ok = _check_specs(root, strict)
    if args.target in {"phase2", "baseline", "drift"}:
        ok = _check_task_registry(root) and ok
    if args.target in {"baseline", "drift"}:
        ok = _check_ai_config(root) and ok
        ok = _check_memory_config(root, args.strict_memory) and ok
    if args.target == "drift":
        baseline = root / "naos" / "reports" / "conformance_latest.json"
        _status(baseline.is_file(), "previous baseline exists", str(baseline))
        ok = baseline.is_file() and ok

    print("READY" if ok else "NOT READY")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
