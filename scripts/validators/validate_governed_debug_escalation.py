#!/usr/bin/env python3
"""Validate the opt-in NAOS implementation-to-debug escalation boundary.

This validator inspects local configuration, capability state, and installed
agent manifests. It never invokes an agent and never treats file posture as
proof that host-side delegation occurred.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


CAPABILITY_ID = "CAP-GOVERNED-DEBUG-ESCALATION"
PROFILE_MINIMUM = {"standard": "L2", "assured": "L3"}
MATURITY_RANK = {f"L{level}": level for level in range(6)}
PARENT_NAME = "naos-implement-with-debug"
CHILD_NAME = "naos-debug"
AGENT_TOOL_NAMES = {"agent", "agent/runSubagent"}
EXPECTED_AGENT_BODY_SHA256 = {
    PARENT_NAME: "a3319b4e9a09093ba04f843d647ffaa59f25efdd4aac765d1ed1dd68f6a05aa6",
    CHILD_NAME: "0457782e852c48bf4c0e5f34726d8eb09b8da1b7c16ab7b7e27831e62521646d",
}


def _finding(rule_id: str, path: Path, message: str) -> dict[str, str]:
    return {"rule_id": rule_id, "path": str(path), "message": message}


def _load_yaml(path: Path, findings: list[dict[str, str]]) -> dict[str, Any] | None:
    if not path.is_file():
        findings.append(_finding("missing_file", path, "required file is missing"))
        return None
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        findings.append(_finding("invalid_yaml", path, str(exc)))
        return None
    if not isinstance(value, dict):
        findings.append(_finding("invalid_shape", path, "expected a YAML mapping"))
        return None
    return value


def _load_json(path: Path, findings: list[dict[str, str]]) -> dict[str, Any] | None:
    if not path.is_file():
        findings.append(_finding("missing_file", path, "required file is missing"))
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(_finding("invalid_json", path, str(exc)))
        return None
    if not isinstance(value, dict):
        findings.append(_finding("invalid_shape", path, "expected a JSON object"))
        return None
    return value


def _load_agent(
    path: Path, findings: list[dict[str, str]]
) -> tuple[dict[str, Any] | None, str]:
    if not path.is_file():
        findings.append(_finding("missing_agent", path, "required agent is missing"))
        return None, ""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(_finding("unreadable_agent", path, str(exc)))
        return None, ""
    parts = text.split("---", 2)
    if len(parts) != 3:
        findings.append(
            _finding("invalid_frontmatter", path, "YAML frontmatter is missing")
        )
        return None, text
    try:
        metadata = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        findings.append(_finding("invalid_frontmatter", path, str(exc)))
        return None, parts[2]
    if not isinstance(metadata, dict):
        findings.append(
            _finding("invalid_frontmatter", path, "frontmatter must be a mapping")
        )
        return None, parts[2]
    return metadata, parts[2]


def _normalized_agent_body(body: str) -> str:
    """Normalize line endings and trailing whitespace without changing words."""
    return "\n".join(line.rstrip() for line in body.strip().splitlines())


def _agent_body_sha256(body: str) -> str:
    return hashlib.sha256(_normalized_agent_body(body).encode("utf-8")).hexdigest()


_RFC3339_DATETIME = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[Zz]|[+-](?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))"
)


def _is_valid_rfc3339_datetime(value: Any) -> bool:
    """Validate a timezone-qualified RFC 3339 date-time without optional deps."""
    if not isinstance(value, str):
        return False
    match = _RFC3339_DATETIME.fullmatch(value)
    if match is None:
        return False
    offset_hour = match.group("offset_hour")
    offset_minute = match.group("offset_minute")
    if offset_hour is not None and (
        int(offset_hour) > 23 or int(offset_minute) > 59
    ):
        return False
    normalized = value[:10] + "T" + value[11:]
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _validate_config(
    root: Path, profile: str, findings: list[dict[str, str]]
) -> dict[str, Any] | None:
    config_path = root / "naos" / "governed_debug_escalation.yaml"
    schema_path = root / "schemas" / "naos" / "governed_debug_escalation.schema.json"
    config = _load_yaml(config_path, findings)
    schema = _load_json(schema_path, findings)
    if config is None or schema is None:
        return config

    # JSON Schema format checks are annotations unless an optional checker is
    # installed. Validate date-times explicitly below so clean installs and
    # maintainer environments enforce the same activation boundary.
    validator = Draft202012Validator(schema)
    for error in sorted(
        validator.iter_errors(config), key=lambda item: list(item.path)
    ):
        location = ".".join(str(part) for part in error.path) or "<root>"
        findings.append(
            _finding(
                "config_schema",
                config_path,
                f"{location}: {error.message}",
            )
        )

    if config.get("enabled") is not True:
        findings.append(
            _finding("config_disabled", config_path, "enabled must be true")
        )
    if config.get("profile") != profile:
        findings.append(
            _finding(
                "profile_mismatch",
                config_path,
                f"configured profile must be {profile}",
            )
        )
    host = config.get("host")
    if isinstance(host, dict):
        if host.get("capability_acknowledged") is not True:
            findings.append(
                _finding(
                    "host_not_acknowledged",
                    config_path,
                    "host capability acknowledgement must be true",
                )
            )
        contract_reviewed_at = host.get("contract_reviewed_at")
        if not contract_reviewed_at:
            findings.append(
                _finding(
                    "host_contract_not_reviewed",
                    config_path,
                    "host contract review timestamp is required",
                )
            )
        elif not _is_valid_rfc3339_datetime(contract_reviewed_at):
            findings.append(
                _finding(
                    "host_contract_review_invalid",
                    config_path,
                    "host.contract_reviewed_at is not valid as an RFC 3339 date-time",
                )
            )
    approval = config.get("human_approval")
    if isinstance(approval, dict):
        if approval.get("approved") is not True:
            findings.append(
                _finding(
                    "approval_missing",
                    config_path,
                    "named human approval must be true",
                )
            )
        approver = str(approval.get("approved_by") or "").strip()
        if not approver or approver == "@unassigned":
            findings.append(
                _finding(
                    "unnamed_approver",
                    config_path,
                    "human approval must identify a named approver",
                )
            )
        approved_at = approval.get("approved_at")
        if not approved_at:
            findings.append(
                _finding(
                    "approval_timestamp_missing",
                    config_path,
                    "human approval timestamp is required",
                )
            )
        elif not _is_valid_rfc3339_datetime(approved_at):
            findings.append(
                _finding(
                    "approval_timestamp_invalid",
                    config_path,
                    "human_approval.approved_at is not valid as an RFC 3339 date-time",
                )
            )
    return config


def _validate_capability_state(
    root: Path, profile: str, findings: list[dict[str, str]]
) -> None:
    state_path = root / "naos" / "capability_state.yaml"
    state = _load_yaml(state_path, findings)
    if state is None:
        return
    entries = state.get("capabilities")
    if not isinstance(entries, list):
        findings.append(
            _finding("invalid_state", state_path, "capabilities must be a list")
        )
        return
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict) and item.get("capability_id") == CAPABILITY_ID
        ),
        None,
    )
    if entry is None:
        findings.append(
            _finding("missing_capability", state_path, f"missing {CAPABILITY_ID}")
        )
        return
    if entry.get("enabled") is not True:
        findings.append(
            _finding(
                "capability_disabled",
                state_path,
                f"{CAPABILITY_ID} must be explicitly enabled",
            )
        )
    minimum = PROFILE_MINIMUM[profile]
    maturity = str(entry.get("current_maturity") or "")
    if MATURITY_RANK.get(maturity, -1) < MATURITY_RANK[minimum]:
        findings.append(
            _finding(
                "insufficient_maturity",
                state_path,
                f"{profile} requires {minimum} or higher; current maturity is {maturity or 'missing'}",
            )
        )
    reviewer = str(entry.get("accountable_reviewer") or "").strip()
    if not reviewer or reviewer == "@unassigned":
        findings.append(
            _finding(
                "unnamed_reviewer",
                state_path,
                "accountable_reviewer must identify a named reviewer",
            )
        )


def _validate_project_profile(
    root: Path, profile: str, findings: list[dict[str, str]]
) -> None:
    policy_path = root / "naos" / "policy" / "default_policy.yaml"
    policy = _load_yaml(policy_path, findings)
    if policy is None:
        return
    profiles = policy.get("profiles")
    declared = profiles.get("default") if isinstance(profiles, dict) else None
    if declared != profile:
        findings.append(
            _finding(
                "project_profile_mismatch",
                policy_path,
                f"project policy profile is {declared or 'missing'}, not {profile}",
            )
        )


def _tools(metadata: dict[str, Any]) -> list[str]:
    value = metadata.get("tools")
    return [str(item) for item in value] if isinstance(value, list) else []


def _validate_agents(root: Path, findings: list[dict[str, str]]) -> None:
    agents_dir = root / ".github" / "agents"
    parent_path = agents_dir / "naos-implement-with-debug.agent.md"
    child_path = agents_dir / "naos-debug.agent.md"
    default_path = agents_dir / "naos-implement.agent.md"
    parent, parent_body = _load_agent(parent_path, findings)
    child, child_body = _load_agent(child_path, findings)
    default, _default_body = _load_agent(default_path, findings)

    if parent is not None:
        parent_tools = _tools(parent)
        if _agent_body_sha256(parent_body) != EXPECTED_AGENT_BODY_SHA256[PARENT_NAME]:
            findings.append(
                _finding(
                    "parent_instruction_integrity",
                    parent_path,
                    "parent instructions differ from the canonical bounded escalation protocol; repair explicitly before activation",
                )
            )
        if parent.get("name") != PARENT_NAME:
            findings.append(
                _finding("parent_name", parent_path, f"name must be {PARENT_NAME}")
            )
        if parent.get("target") != "vscode":
            findings.append(
                _finding("parent_target", parent_path, "target must be vscode")
            )
        if parent.get("disable-model-invocation") is not True:
            findings.append(
                _finding(
                    "parent_invocation_posture",
                    parent_path,
                    "the top-level parent must not be available as a child",
                )
            )
        if "agent" not in parent_tools or "agent/runSubagent" in parent_tools:
            findings.append(
                _finding(
                    "parent_tool",
                    parent_path,
                    "parent must expose only the current agent tool spelling",
                )
            )
        if parent.get("agents") != [CHILD_NAME]:
            findings.append(
                _finding(
                    "child_allowlist",
                    parent_path,
                    f"agents must be exactly [{CHILD_NAME}]",
                )
            )

    if child is not None:
        child_tools = _tools(child)
        normalized_child_body = " ".join(child_body.split())
        if _agent_body_sha256(child_body) != EXPECTED_AGENT_BODY_SHA256[CHILD_NAME]:
            findings.append(
                _finding(
                    "child_instruction_integrity",
                    child_path,
                    "debug-child instructions differ from the canonical no-write/no-recursion protocol; repair explicitly before activation",
                )
            )
        if child.get("name") != CHILD_NAME:
            findings.append(
                _finding("child_name", child_path, f"name must be {CHILD_NAME}")
            )
        if child.get("disable-model-invocation") is not True:
            findings.append(
                _finding(
                    "child_invocation_posture",
                    child_path,
                    "disable-model-invocation must be true",
                )
            )
        if AGENT_TOOL_NAMES.intersection(child_tools):
            findings.append(
                _finding("child_recursion", child_path, "child must have no agent tool")
            )
        if any(tool.startswith("edit/") or tool == "edit" for tool in child_tools):
            findings.append(
                _finding("child_write", child_path, "child must have no edit tool")
            )
        if (
            "no direct edit/create or agent-invocation tools"
            not in normalized_child_body
        ):
            findings.append(
                _finding(
                    "child_instruction",
                    child_path,
                    "child instructions must state the no-direct-edit and no-recursion boundary",
                )
            )
        if "not a filesystem security boundary" not in normalized_child_body:
            findings.append(
                _finding(
                    "child_terminal_boundary",
                    child_path,
                    "child instructions must state that terminal access is not filesystem isolation",
                )
            )

    if default is not None and AGENT_TOOL_NAMES.intersection(_tools(default)):
        findings.append(
            _finding(
                "default_delegation",
                default_path,
                "the default implementation agent must remain human-mediated",
            )
        )


def build_report(root: Path, profile: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    if profile not in PROFILE_MINIMUM:
        findings.append(
            _finding(
                "unsupported_profile",
                root,
                "activation is available only for standard or assured",
            )
        )
    else:
        _validate_config(root, profile, findings)
        _validate_project_profile(root, profile, findings)
        _validate_capability_state(root, profile, findings)
        _validate_agents(root, findings)

    eligible = not findings
    return {
        "status": "pass" if eligible else "fail",
        "profile": profile,
        "activation_eligible": eligible,
        "findings": findings,
        "invocation_attempted": False,
        "invocation_performed": False,
        "semantics": {
            "result": "local activation eligibility only",
            "not_claimed": "host invocation, child compliance, diagnosis correctness, or approval",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate opt-in NAOS implementation-to-debug escalation"
    )
    parser.add_argument("--root", default=".", help="Generated project root")
    parser.add_argument(
        "--profile",
        required=True,
        choices=["quickstart", "lite", "standard", "assured"],
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = build_report(root, args.profile)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "Governed debug escalation: "
            f"{report['status'].upper()} — profile={args.profile}; "
            f"findings={len(report['findings'])}"
        )
        for finding in report["findings"]:
            print(f"  - {finding['rule_id']}: {finding['path']}: {finding['message']}")
        print("  Invocation attempted: false")
        print("  Invocation performed: false")
    return 0 if report["activation_eligible"] else 1


if __name__ == "__main__":
    sys.exit(main())
