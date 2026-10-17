#!/usr/bin/env python3
"""Advisory Claude Code hook dispatcher for an explicitly installed NAOS CLI.

The hook payload is intentionally unused. No model input or tool arguments are
parsed, logged, passed to a shell, or forwarded to NAOS.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

TIMEOUT_SECONDS = 15
EVENTS = {
    "session-start",
    "pre-tool-edit",
    "pre-tool-bash",
    "post-tool-write",
    "pre-compact",
    "session-end",
    "stop",
}


def warn(message: str) -> None:
    print(f"NAOS Claude hook: {message}", file=sys.stderr)


def _commands(event: str, profile: str, environ: dict[str, str]) -> list[list[str]]:
    common = ["--profile", profile]
    task = environ.get("NAOS_TASK_ID") or environ.get("TASK") or ""
    team = environ.get("NAOS_TEAM_ID") or environ.get("TEAM_ID") or ""
    if event == "stop":
        warn("legacy Stop is per-response; skipped session-end writes. Use SessionEnd for the end review or run it manually.")
        return []
    if event == "session-start":
        return [["session-id", *common], ["operator-attribution", *common]]
    if event == "pre-tool-edit":
        return [["task-claims", "--action", "list", *common]]
    if event == "pre-tool-bash":
        project = Path(environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        naos_root = environ.get("NAOS_ROOT") or "naos"
        output_path = Path(naos_root) / "reports" / "gate_status.json"
        output = ["--output", str(output_path)] if (project / naos_root).is_dir() else []
        return [["gate-status", *common, "--naos-root", naos_root, *(["--team-id", team] if team else []), *output]]
    if event == "post-tool-write":
        return [["self-check", *common]]
    if event in {"pre-compact", "session-end"}:
        if not task:
            warn("NAOS_TASK_ID/TASK not set; skipped session lifecycle review. Record it manually if needed.")
            return []
        command = "session-checkpoint" if event == "pre-compact" else "session-end"
        return [[command, "--task", task, *common]]
    raise ValueError(f"unsupported event: {event}")


def main(argv: list[str] | None = None, *, environ: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", choices=sorted(EVENTS), required=True)
    parser.add_argument("--profile", choices=["quickstart", "lite", "standard", "assured"])
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code:
            warn("invalid hook configuration; skipped advisory review.")
        return 0
    env = dict(os.environ if environ is None else environ)
    profile = args.profile or env.get("NAOS_PROFILE") or "standard"
    if profile not in {"quickstart", "lite", "standard", "assured"}:
        warn(f"invalid NAOS_PROFILE {profile!r}; skipped review.")
        return 0

    project_dir = env.get("CLAUDE_PROJECT_DIR")
    if project_dir and not Path(project_dir).is_dir():
        warn("CLAUDE_PROJECT_DIR is unavailable; skipped review.")
        return 0
    cwd = project_dir or os.getcwd()  # POSIX compatibility wrappers may be run manually from the project.
    for command in _commands(args.event, profile, env):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "naos_governance", *command],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            warn(f"{command[0]} unavailable or timed out ({type(exc).__name__}); review manually.")
            continue
        if result.returncode != 0:
            warn(f"{command[0]} returned nonzero status (exit {result.returncode}); check the NAOS installation and review manually.")
        else:
            warn(f"{command[0]} ran; review its local NAOS report before acting.")
    warn("hook output is advisory; it does not approve, certify, deploy, release, or write memory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
