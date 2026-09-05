#!/usr/bin/env python3
"""Validate a reversible NAOS overlay against a brownfield repository.

The target is read-only. Generation occurs in an isolated temporary directory;
the report records collisions and verifies the Git-visible target snapshot is
unchanged before any optional report is written outside the target.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


KIT_ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "naos.overlay_coexistence.v1"


def run_git(target: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=target,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def git_visible_paths(target: Path) -> list[Path]:
    result = run_git(target, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if result.returncode != 0:
        raise ValueError(result.stderr.decode("utf-8", errors="replace").strip() or "git ls-files failed")
    return [target / raw.decode("utf-8", errors="surrogateescape") for raw in result.stdout.split(b"\0") if raw]


def target_snapshot(target: Path) -> dict[str, Any]:
    records: list[str] = []
    for path in sorted(git_visible_paths(target), key=lambda item: item.as_posix()):
        relative = path.relative_to(target).as_posix()
        if path.is_symlink():
            records.append(f"L\0{relative}\0{os.readlink(path)}")
        elif path.is_file():
            payload = path.read_bytes()
            records.append(f"F\0{relative}\0{len(payload)}\0{hashlib.sha256(payload).hexdigest()}")
        else:
            records.append(f"M\0{relative}")
    payload = "\n".join(records).encode("utf-8", errors="surrogateescape")
    status = run_git(target, "status", "--porcelain=v2", "--branch", "--untracked-files=all")
    return {
        "algorithm": "sha256",
        "scope": "git_tracked_and_nonignored_untracked_files",
        "digest": hashlib.sha256(payload).hexdigest(),
        "file_count": len(records),
        "git_status_sha256": hashlib.sha256(status.stdout).hexdigest(),
    }


def tree_snapshot(target: Path) -> dict[str, Any]:
    """Hash a disposable materialization without requiring its Git metadata."""

    records: list[str] = []
    for path in sorted(target.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(target).as_posix()
        if path.is_symlink():
            records.append(f"L\0{relative}\0{os.readlink(path)}")
        elif path.is_file():
            payload = path.read_bytes()
            records.append(f"F\0{relative}\0{len(payload)}\0{hashlib.sha256(payload).hexdigest()}")
    payload = "\n".join(records).encode("utf-8", errors="surrogateescape")
    return {
        "algorithm": "sha256",
        "scope": "all_materialized_files",
        "digest": hashlib.sha256(payload).hexdigest(),
        "file_count": len(records),
    }


def git_head(target: Path) -> str | None:
    result = run_git(target, "rev-parse", "HEAD")
    return result.stdout.decode().strip() if result.returncode == 0 else None


def resolve_commit(target: Path, commit: str) -> str | None:
    result = run_git(target, "rev-parse", f"{commit}^{{commit}}")
    return result.stdout.decode().strip() if result.returncode == 0 else None


def materialize_commit(target: Path, commit: str, destination: Path) -> str:
    resolved = resolve_commit(target, commit)
    if resolved != commit:
        raise ValueError(f"Expected commit {commit} is not available as that exact Git object (resolved={resolved!r}).")
    archive = run_git(target, "archive", "--format=tar", commit)
    if archive.returncode != 0:
        raise ValueError(archive.stderr.decode("utf-8", errors="replace").strip() or "git archive failed")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
        tar.extractall(destination, filter="data")
    return resolved


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def run_verification(command: list[str], cwd: Path) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return {
        "argv": command,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def build_report(
    target: Path,
    profile: str,
    expected_commit: str | None,
    verification_command: list[str] | None = None,
) -> dict[str, Any]:
    target = target.resolve(strict=True)
    before = target_snapshot(target)
    head = git_head(target)
    with tempfile.TemporaryDirectory(prefix="naos-overlay-") as temp_dir:
        temp_root = Path(temp_dir)
        validation_target = temp_root / "target-at-commit"
        requested_commit = expected_commit or head
        if not requested_commit:
            raise ValueError("The target does not expose a Git commit to materialize.")
        validated_commit = materialize_commit(target, requested_commit, validation_target)
        source_materialization = "git_archive"
        baseline_verification = run_verification(verification_command, validation_target) if verification_command else None
        overlay = temp_root / "overlay"
        disposable_before_activation = tree_snapshot(validation_target)
        result = subprocess.run(
            [
                sys.executable,
                str(KIT_ROOT / "naos_init.py"),
                str(validation_target),
                "--tier",
                profile,
                "--archetype",
                "custom",
                "--backend",
                "static_only",
                "--memory",
                "disabled",
                "--activate",
                "--preview-dir",
                str(overlay),
            ],
            cwd=KIT_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        disposable_after_activation = tree_snapshot(validation_target)
        compatibility_path = overlay / "naos" / "overlay_compatibility.json"
        compatibility = (
            json.loads(compatibility_path.read_text(encoding="utf-8"))
            if compatibility_path.is_file()
            else None
        )
        activation_blocked = bool(
            result.returncode == 3
            and compatibility
            and compatibility.get("status") == "blocking_collision"
            and compatibility.get("blocked_before_activation") is True
        )
        disposable_activation_performed = result.returncode == 0
        activation_safe = bool(
            (activation_blocked and disposable_before_activation == disposable_after_activation)
            or disposable_activation_performed
        )
        generated = sorted(path.relative_to(overlay).as_posix() for path in overlay.rglob("*") if path.is_file()) if overlay.exists() else []
        collisions = [path for path in generated if (validation_target / path).exists()]
        additions = [path for path in generated if path not in collisions]
        overlay_digest = hashlib.sha256(
            "\n".join(
                f"{path}\0{hashlib.sha256((overlay / path).read_bytes()).hexdigest()}" for path in generated
            ).encode("utf-8")
        ).hexdigest()
        post_overlay_verification = run_verification(verification_command, validation_target) if verification_command else None
    after = target_snapshot(target)
    unchanged = before == after
    commit_match = expected_commit is None or validated_commit == expected_commit
    verification_passed = bool(
        verification_command is None
        or (
            baseline_verification
            and post_overlay_verification
            and baseline_verification["exit_code"] == 0
            and post_overlay_verification["exit_code"] == 0
        )
    )
    status = "pass" if activation_safe and unchanged and commit_match and verification_passed else "failed"
    findings: list[dict[str, Any]] = []
    if result.returncode not in {0, 3} or (result.returncode == 3 and not activation_blocked):
        findings.append({"id": "overlay.generation_failed", "message": result.stderr.strip() or result.stdout.strip()})
    if activation_blocked and disposable_before_activation != disposable_after_activation:
        findings.append({"id": "overlay.block_was_not_pre_activation", "message": "Disposable host changed despite a blocking preflight result."})
    if not unchanged:
        findings.append({"id": "overlay.target_mutated", "message": "Git-visible target snapshot changed during overlay generation."})
    if not commit_match:
        findings.append({"id": "overlay.commit_mismatch", "message": f"Expected {expected_commit}, observed {head}."})
    if not verification_passed:
        findings.append({"id": "overlay.verification_failed", "message": "Baseline or sidecar-overlay verification command failed."})
    return {
        "schema": REPORT_SCHEMA,
        "status": status,
        "target": str(target),
        "profile": profile,
        "expected_commit": expected_commit,
        "observed_commit": head,
        "validated_commit": validated_commit,
        "commit_match": commit_match,
        "target_snapshot_before": before,
        "target_snapshot_after": after,
        "target_unchanged": unchanged,
        "compatibility_preflight": compatibility,
        "activation_outcome": "blocked_before_activation" if activation_blocked else ("activated_in_disposable_checkout" if disposable_activation_performed else "failed"),
        "disposable_target_snapshot_before_activation": disposable_before_activation,
        "disposable_target_snapshot_after_activation": disposable_after_activation,
        "disposable_target_unchanged_when_blocked": disposable_before_activation == disposable_after_activation if activation_blocked else None,
        "overlay": {
            "generated_files": len(generated),
            "digest": {"algorithm": "sha256", "value": overlay_digest},
            "collisions": collisions,
            "additions": additions,
            "isolated_temporary_directory": True,
            "removed_after_validation": True,
            "target_activation_performed": False,
            "disposable_activation_performed": disposable_activation_performed,
            "blocked_before_activation": activation_blocked,
            "source_materialization": source_materialization,
        },
        "verification": {
            "command_configured": verification_command is not None,
            "baseline": baseline_verification,
            "with_isolated_sidecar_overlay": post_overlay_verification,
            "passed": verification_passed,
        },
        "findings": findings,
        "human_review_required": bool((compatibility or {}).get("human_review_required") or collisions or findings),
        "limitations": [
            "The mutation check covers Git-tracked and non-ignored untracked files, not ignored caches.",
            "Host collection detection is structural and may not discover every custom lint, package, import, or coverage rule.",
            "A blocking result establishes prevention of the tested incompatible activation path; it does not establish installed compatibility.",
            "This run validates bounded coexistence and reversibility, not product behavior or human usability.",
        ],
        "not_claimed": [
            "target-repository modification or installation",
            "merge, release, or evidence-admission approval",
            "behavioral effectiveness",
            "full matched E2E qualification",
        ],
        "summary": {
            "status": status,
            "generated_files": len(generated),
            "collisions": len(collisions),
            "additions": len(additions),
            "target_unchanged": unchanged,
            "commit_match": commit_match,
            "verification_passed": verification_passed,
            "activation_blocked": activation_blocked,
            "disposable_activation_performed": disposable_activation_performed,
            "total_findings": len(findings),
            "advisory": len(collisions),
            "warning": 0,
            "required": len(findings),
            "blocking": 0,
            "human_review_required": bool((compatibility or {}).get("human_review_required") or collisions or findings),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate isolated NAOS overlay coexistence without target mutation.")
    parser.add_argument("target", type=Path)
    parser.add_argument("--profile", choices=["quickstart", "lite", "standard", "assured"], default="standard")
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verification-command", help="Optional no-shell command run at the pinned snapshot before and while the sidecar overlay exists.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    target = args.target.resolve(strict=True)
    if args.output and is_within(args.output, target):
        print("ERROR: --output must be outside the read-only target repository", file=sys.stderr)
        return 2
    try:
        verification_command = shlex.split(args.verification_command) if args.verification_command else None
        report = build_report(target, args.profile, args.expected_commit, verification_command)
    except Exception as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "target": str(target),
            "profile": args.profile,
            "expected_commit": args.expected_commit,
            "observed_commit": git_head(target),
            "commit_match": False,
            "target_unchanged": None,
            "findings": [{"id": "overlay.validation_error", "message": str(exc)}],
            "human_review_required": True,
            "limitations": ["Overlay coexistence validation did not complete."],
            "not_claimed": ["target-repository modification or installation"],
            "summary": {"status": "failed", "total_findings": 1, "advisory": 0, "warning": 0, "required": 1, "blocking": 0, "human_review_required": True},
        }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json or not args.output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"NAOS overlay coexistence: {report['status']}")
        print(f"target unchanged: {report.get('target_unchanged')}")
        print(f"report: {args.output}")
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
