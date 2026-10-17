#!/usr/bin/env python3
"""Report local governance-bypass posture without claiming bypass prevention."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
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
    report_output_path,
    severity_for_profile,
    status_from_counts,
    write_report,
)


SCHEMA = "naos.governance_bypass_posture.v1"
NOT_CLAIMED = [
    "bypass prevention",
    "tamper-proof hook enforcement",
    "authentication",
    "authorization",
    "non-repudiation",
    "PR approval",
    "security proof",
    "proof of compliance",
    "certification",
    "release authorization",
]
LIMITATIONS = [
    "This report reads local git configuration, local workflow files, and local commit messages only.",
    "Git hooks can be bypassed with --no-verify or core.hooksPath changes; NAOS reports posture but does not prevent those actions.",
    "Commit-message searches can miss bypasses because git does not record --no-verify by default.",
    "CI workflow presence is configuration evidence only; it does not prove that CI ran or passed for a specific PR.",
    "Human review remains required for bypass disposition, compensating controls, and branch protection decisions.",
]


def utc_now() -> str:
    fixed = os.environ.get("NAOS_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_git(root: Path, args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "FileNotFoundError"
    except OSError:
        return 126, "", "OSError"
    return result.returncode, result.stdout, result.stderr


def git_failure_class(code: int, error: str) -> str:
    if code == 127 and error == "FileNotFoundError":
        return "file_not_found"
    if code == 126 and error == "OSError":
        return "os_error"
    return "git_query_failed"


def cost_posture() -> dict[str, Any]:
    return {
        "cost_incurred_by_default": False,
        "cost_usd": 0.0,
        "external_api_required": False,
        "provider_dependency_required": False,
        "model_dependency_required": False,
        "human_approval_required_before_cost": False,
    }


def finding(finding_id: str, severity: str, status: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "status": status,
        "message": message,
        "human_review_required": severity in {"blocking", "required", "warning"} or status != "not_configured",
        "not_claimed": NOT_CLAIMED,
        **extra,
    }


def local_hook_posture(root: Path) -> dict[str, Any]:
    code, out, error = run_git(root, ["config", "--local", "--get", "core.hooksPath"])
    if code == 0:
        configured = out.strip()
        inspection_status = "configured" if configured else "unset"
    elif code == 1 and not out and not error:
        configured = ""
        inspection_status = "unset"
    else:
        configured = ""
        inspection_status = "read_error"
    expected = ".githooks"
    hook_file = root / expected / "pre-commit"
    posture = {
        "configured_hooks_path": configured or None,
        "expected_hooks_path": expected,
        "configured_matches_expected": configured == expected,
        "pre_commit_hook_present": hook_file.is_file(),
        "pre_commit_hook_path": str(hook_file),
        "inspection_status": inspection_status,
        "inspection_complete": inspection_status != "read_error",
        "git_exit_code": code,
    }
    if inspection_status == "read_error":
        posture["error_class"] = (
            "unexpected_query_output" if code == 1 else git_failure_class(code, error)
        )
    return posture


class _CILoader(yaml.SafeLoader):
    """Keep YAML `on` literal; reject duplicate declarations rather than guessing."""

    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node: Any, deep: bool = False) -> dict:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate CI declaration")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


_CILoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF")
)


def _declared_command(script: Any) -> bool:
    """Recognize direct command prefixes only, never text embedded in shell programs."""
    if _unsupported_script(script):
        return False
    script = re.sub(r"\\\r?\n", " ", script)
    lines = [line.strip() for line in script.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    for line in lines:
        words = _shell_words(line)
        words = [word.removeprefix("./") for word in words]
        # Help/version and make no-execution modes are not governance declarations.
        if any(word in {"--help", "-h", "--version", "--dry-run", "--just-print", "--recon", "-n", "-q", "--question", "-t", "--touch"} for word in words):
            continue
        if words[:2] == ["naos", "gate-evaluate"]:
            return True
        if len(words) >= 4 and words[:3] == ["make", "-f", "Makefile.naos"]:
            if any(word.startswith("-") for word in words[4:]):
                continue
            if words[3] in {"validate-all", "naos-gate-evaluate"}:
                return True
        if words and words[0] in {"python", "python3", "python3.11", "python3.12", "python3.13", "python.exe"}:
            if words[1:3] == ["cli.py", "gate-evaluate"]:
                return True
            if words[1:3] == ["-m", "naos_governance.scripts.naos_ci_readiness"]:
                return True
    return False


def _shell_words(line: str) -> list[str]:
    lexer = shlex.shlex(line.replace("\\", "/"), posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def _unsupported_script(script: Any) -> bool:
    if not isinstance(script, str):
        return True
    controls = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "exit", "return", "function", "{", "}"}
    lines = [line.strip() for line in re.sub(r"\\\r?\n", " ", script).splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    direct = {"python", "python3", "python3.11", "python3.12", "python3.13", "python.exe", "make", "naos"}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.split()[0] in controls or line.endswith("{") or line.endswith("()"):
            return True
        if any(token in line for token in ("`", "$(")):
            return True
        try:
            words = _shell_words(line)
        except ValueError:
            return True
        if any(word and all(character in ";&|<>" for character in word) for word in words):
            return True
        if words and (words[0] in {"bash", "sh", "pwsh", "powershell", "cmd"}
                      or (len(lines) > 1 and words[0] not in direct)):
            return True
    return False


def _unsupported_executable_form(script: Any) -> bool:
    """Unknown launchers/wrappers may invoke governance; do not infer their absence."""
    if _unsupported_script(script):
        return True
    for line in re.sub(r"\\\r?\n", " ", script).splitlines():
        words = _shell_words(line)
        if not words:
            continue
        words = [word.removeprefix("./") for word in words]
        if words[0] in {"echo", "printf", "true", "false", ":"}:
            continue
        if _declared_command(line):
            continue
        launchers = {"python", "python3", "python3.11", "python3.12", "python3.13", "python.exe", "make", "naos"}
        no_op = {"--help", "-h", "--version", "--dry-run", "--just-print", "--recon", "-n", "-q", "--question", "-t", "--touch"}
        if words[0] in launchers and any(word in no_op for word in words):
            operational = " ".join(shlex.quote(word) for word in words if word not in no_op)
            if _declared_command(operational):
                continue
        return True
    return False


def _github_declaration(data: dict) -> tuple[str, str]:
    trigger = data.get("on")
    events = [trigger] if isinstance(trigger, str) else trigger
    if not isinstance(events, (dict, list)):
        return "unknown", "unsupported_trigger"
    if not any(event in events for event in ("push", "pull_request")):
        return "not_detected", "no_supported_automatic_trigger"
    if isinstance(events, dict) and any(
        events[event] is not None and not isinstance(events[event], dict)
        for event in ("push", "pull_request") if event in events
    ):
        return "unknown", "unsupported_trigger_configuration"
    if isinstance(events, dict):
        allowed = {"push": {"branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore"},
                   "pull_request": {"branches", "branches-ignore", "paths", "paths-ignore", "types"}}
        for event in ("push", "pull_request"):
            config = events.get(event)
            if isinstance(config, dict) and (set(config) - allowed[event] or any(
                not isinstance(value, list) or any(not isinstance(item, str) for item in value)
                for value in config.values()
            )):
                return "unknown", "unsupported_trigger_filters"
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return "unknown", "unsupported_jobs"
    unknown = False
    for job in jobs.values():
        if not isinstance(job, dict):
            unknown = True
            continue
        if job.get("if") is False:
            continue
        if "if" in job or "uses" in job or "runs-on" not in job or "strategy" in job:
            unknown = True
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            unknown = True
            continue
        for step in steps:
            if not isinstance(step, dict):
                unknown = True
                continue
            if step.get("if") is False:
                continue
            if "if" in step:
                unknown = True
                continue
            if _declared_command(step.get("run")):
                return "present", "supported_automatic_command_declaration"
            if "uses" in step or ("run" in step and _unsupported_executable_form(step["run"])):
                unknown = True
    return ("unknown", "unsupported_job_or_step") if unknown else ("not_detected", "no_supported_command")


def _gitlab_sources(data: dict, default: set[str]) -> set[str] | None:
    if any(key in data for key in ("only", "except", "extends")):
        return None
    when = data.get("when", "on_success")
    if when in {"manual", "never"}:
        return set()
    if when not in {"on_success", "always"}:
        return None
    if "rules" not in data:
        return default
    rules = data["rules"]
    if not isinstance(rules, list):
        return None
    remaining = {"push", "merge_request_event"}
    selected: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"if", "when"}:
            return None
        if "if" in rule:
            match = re.fullmatch(r'\$CI_PIPELINE_SOURCE\s*==\s*([\"\x27])(push|merge_request_event|schedule|web)\1', str(rule["if"]))
            if not match:
                return None
            sources = {match[2]} & remaining
        else:
            sources = remaining.copy()
        rule_when = rule.get("when", when)
        if rule_when not in {"on_success", "always", "manual", "never"}:
            return None
        if rule_when not in {"manual", "never"}:
            selected.update(sources)
        remaining.difference_update(sources)
    return selected


def _gitlab_declaration(data: dict) -> tuple[str, str]:
    # External includes and inherited defaults require provider expansion; do not guess.
    if any(key in data for key in ("include", "default")):
        return "unknown", "external_or_inherited_configuration"
    workflow = data.get("workflow", {})
    if not isinstance(workflow, dict):
        return "unknown", "unsupported_workflow"
    sources = _gitlab_sources(workflow, {"push", "merge_request_event"})
    if sources is None:
        return "unknown", "unsupported_workflow_rules"
    unknown = any(key in data for key in ("before_script", "after_script"))
    reserved = {"workflow", "stages", "variables", "image", "services", "before_script", "after_script", "cache"}
    for name, job in data.items():
        if not isinstance(name, str) or name.startswith(".") or name in reserved:
            continue
        if not isinstance(job, dict):
            unknown = True
            continue
        job_sources = _gitlab_sources(job, {"push"})
        if job_sources is None or "trigger" in job:
            unknown = True
            continue
        if not (job_sources & sources):
            continue
        if any(key in job for key in ("before_script", "after_script", "run", "hooks")):
            unknown = True
        scripts = job.get("script", [])
        scripts = [scripts] if isinstance(scripts, str) else scripts
        if not isinstance(scripts, list) or any(not isinstance(script, str) for script in scripts):
            unknown = True
            continue
        if any(_unsupported_executable_form(script) for script in scripts):
            unknown = True
            continue
        if any(_declared_command(script) for script in scripts):
            return "present", "supported_automatic_command_declaration"
    return ("unknown", "unsupported_job") if unknown else ("not_detected", "no_supported_automatic_command")


def ci_posture(root: Path) -> dict[str, Any]:
    workflow_dir = root / ".github" / "workflows"
    files = [(path, "github") for path in workflow_dir.glob("*") if path.suffix in {".yml", ".yaml"}]
    files += [(root / name, provider) for name, provider in (
        (".gitlab-ci.yml", "gitlab"), ("azure-pipelines.yml", "azure"),
        ("azure-pipelines.yaml", "azure"), ("Jenkinsfile", "jenkins"),
    ) if (root / name).exists() or (root / name).is_symlink()]
    records = []
    for path, provider in sorted(files, key=lambda item: item[0].relative_to(root).as_posix()):
        status, reason = "unknown", "unsupported_provider"
        if provider in {"github", "gitlab"}:
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError("nonregular declaration")
                data = yaml.load(path.read_bytes(), Loader=_CILoader)
                if not isinstance(data, dict):
                    raise ValueError("nonmapping declaration")
                status, reason = (_github_declaration(data) if provider == "github" else _gitlab_declaration(data))
            except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError, RecursionError):
                reason = "unreadable_or_invalid_yaml"
        records.append({"path": path.relative_to(root).as_posix(), "provider": provider, "status": status, "reason": reason})
    present = [record["path"] for record in records if record["status"] == "present"]
    complete = all(record["status"] != "unknown" for record in records)
    providers = sorted({record["provider"] for record in records})
    return {
        "workflow_dir_present": workflow_dir.is_dir(),
        "workflow_files": [record["path"] for record in records],
        "naos_workflow_files": present,
        "naos_ci_present": bool(present),
        "ci_provider": providers[0] if len(providers) == 1 else ("multiple" if providers else "none"),
        "declaration_status": "present" if present else ("not_detected" if complete else "unknown"),
        "inspection_complete": complete,
        "declarations": records,
        "execution_verified": False,
        "enforcement_verified": False,
    }


def bypass_commit_messages(root: Path, days: int) -> tuple[list[dict[str, str]], dict[str, Any]]:
    code, out, error = run_git(
        root,
        ["log", f"--since={days} days ago", "--max-count=200", "--pretty=format:%H%x09%s", "--all"],
    )
    if code != 0:
        return [], {"status": "read_error", "complete": False,
                    "git_exit_code": code, "error_class": git_failure_class(code, error)}
    matches: list[dict[str, str]] = []
    needles = ("no-verify", "skip-hook", "skip hook", "bypass hook", "bypass pre-commit")
    for line in out.splitlines():
        commit, _, subject = line.partition("\t")
        if any(needle in subject.lower() for needle in needles):
            matches.append({"commit": commit, "subject": subject})
    return matches, {"status": "complete", "complete": True, "git_exit_code": code}


def tier_posture(profile: str) -> dict[str, Any]:
    tier = (os.environ.get("NAOS_TIER") or "").strip().lower()
    return {
        "profile": profile,
        "naos_tier_env": tier or None,
        "tier_env_present": bool(tier),
        "tier_matches_profile": not tier or tier == profile,
    }


def build_report(root: Path, profile: str, naos_root: str, policy: dict[str, Any], days: int) -> dict[str, Any]:
    severity = severity_for_profile(profile, policy)
    hook = local_hook_posture(root)
    ci = ci_posture(root)
    bypass_messages, bypass_inspection = bypass_commit_messages(root, days)
    tier = tier_posture(profile)
    findings: list[dict[str, Any]] = []
    inspection_severity = "warning" if profile in {"standard", "assured"} else "advisory"

    if hook["inspection_status"] == "read_error":
        findings.append(finding(
            "governance_bypass.hooks_path_inspection_failed", inspection_severity,
            "read_error", "Local core.hooksPath could not be inspected; hook configuration is unknown.",
            git_exit_code=hook["git_exit_code"], error_class=hook["error_class"],
        ))
    if not bypass_inspection["complete"]:
        findings.append(finding(
            "governance_bypass.commit_message_inspection_failed", inspection_severity,
            "read_error", "Local commit messages could not be inspected; bypass markers are unknown.",
            git_exit_code=bypass_inspection["git_exit_code"],
            error_class=bypass_inspection["error_class"],
        ))

    if not is_kit_repository(root, naos_root):
        if not hook["pre_commit_hook_present"]:
            findings.append(finding("governance_bypass.pre_commit_missing", severity, "missing", "Generated pre-commit hook is missing.", path=hook["pre_commit_hook_path"]))
        if hook["configured_hooks_path"] and not hook["configured_matches_expected"]:
            findings.append(finding("governance_bypass.hooks_path_mismatch", severity, "review_required", "Local core.hooksPath does not point at .githooks.", configured_hooks_path=hook["configured_hooks_path"]))
        if hook["inspection_status"] == "unset":
            findings.append(finding("governance_bypass.hooks_path_unset", inspection_severity, "review_required", "Local core.hooksPath is not set; generated hooks may not run."))

    if not ci["inspection_complete"]:
        findings.append(finding(
            "governance_bypass.ci_declaration_inspection_unknown", inspection_severity,
            "unknown", "Some local CI declarations use unsupported syntax or could not be read; review them explicitly.",
        ))
    if profile in {"standard", "assured"} and ci["declaration_status"] == "not_detected":
        findings.append(finding("governance_bypass.naos_ci_not_detected", severity, "review_required", "No supported automatic GitHub/GitLab declaration of a NAOS governance command was detected."))

    for item in bypass_messages:
        findings.append(
            finding(
                "governance_bypass.commit_message_bypass_marker",
                severity,
                "review_required",
                "Recent commit message contains a hook-bypass marker.",
                commit=item["commit"],
                subject=item["subject"],
            )
        )

    if tier["tier_env_present"] and not tier["tier_matches_profile"]:
        findings.append(finding("governance_bypass.naos_tier_profile_mismatch", severity, "review_required", "NAOS_TIER environment value differs from the selected profile.", tier=tier["naos_tier_env"], profile=profile))

    summary = finding_counts(findings)
    summary.update(
        {
            "hook_findings": sum(1 for item in findings if item["id"].startswith("governance_bypass.hooks") or item["id"].startswith("governance_bypass.pre_commit")),
            "ci_findings": sum(1 for item in findings if "ci" in item["id"]),
            "bypass_marker_findings": len(bypass_messages),
            "tier_findings": sum(1 for item in findings if "tier" in item["id"]),
        }
    )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "profile": profile,
        "status": status_from_counts(summary),
        "project_root": str(root),
        "naos_root": naos_root,
        "deterministic": True,
        "cost_posture": cost_posture(),
        "summary": summary,
        "scans": {
            "hook": hook,
            "ci": ci,
            "bypass_commit_message_window_days": days,
            "bypass_commit_messages": bypass_messages,
            "bypass_commit_message_inspection": bypass_inspection,
            "tier": tier,
        },
        "findings": findings,
        "waivers": [],
        "known_gaps": [
            "Local git hooks remain bypassable by design; CI and branch protection are adopter-managed compensating controls."
        ],
        "residual_risks": [
            "A bypass can occur without a commit-message marker.",
            "A configured workflow can be disabled, skipped, or fail outside this local report's view.",
        ],
        "limitations": LIMITATIONS,
        "not_claimed": NOT_CLAIMED,
        "human_review_required": bool(findings),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report local NAOS governance-bypass posture.")
    parser.add_argument("--profile")
    parser.add_argument("--naos-root", default=os.environ.get("NAOS_ROOT"))
    parser.add_argument("--policy")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--since-days", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path.cwd()
    policy = load_policy(args.policy, args.naos_root, root)
    naos_root = args.naos_root or default_naos_root(policy)
    profile = normalize_profile(args.profile, policy)
    report = build_report(root, profile, naos_root, policy, max(args.since_days, 1))
    output = Path(args.output) if args.output else report_output_path(root, naos_root, policy, "governance_bypass_posture_report")
    write_report(output, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        destination = str(output) if output else "stdout only"
        print(f"NAOS governance bypass posture: {report['status']} (findings: {report['summary']['total_findings']}, output: {destination})")
    return exit_code_for_summary(profile, report["summary"], policy, args.strict and not is_kit_repository(root, naos_root))


if __name__ == "__main__":
    raise SystemExit(main())
