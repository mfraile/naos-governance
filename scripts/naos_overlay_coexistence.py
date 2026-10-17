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


class OverlayRefusal(ValueError):
    """A refused operation, without claiming installed compatibility."""

    def __init__(self, finding_id: str, message: str, evidence: dict[str, Any] | None = None):
        super().__init__(message)
        self.finding_id = finding_id
        self.evidence = evidence or {}


def operation_environment() -> dict[str, str]:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1",
               PYTHONIOENCODING="utf-8", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    # Cwd must select each repository, not inherited alternate Git state.
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_CONFIG_PARAMETERS", "GIT_NAMESPACE"):
        env.pop(key, None)
    for key in list(env):
        if key == "GIT_CONFIG_COUNT" or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            env.pop(key)
    return env


def run_git(target: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=target,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=operation_environment(),
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
    if status.returncode:
        raise ValueError(status.stderr.decode("utf-8", errors="replace"))
    index_result = run_git(target, "rev-parse", "--git-path", "index")
    refs = run_git(target, "for-each-ref", "--format=%(refname) %(objectname) %(symref)")
    if index_result.returncode or refs.returncode:
        raise ValueError("Cannot observe target Git index and references")
    index = Path(os.fsdecode(index_result.stdout.rstrip(b"\r\n")))
    if not index.is_absolute():
        index = target / index
    return {
        "algorithm": "sha256",
        "scope": "git_tracked_and_nonignored_untracked_files_plus_index_and_refs",
        "git_index_sha256": hashlib.sha256(index.read_bytes()).hexdigest() if index.exists() else None,
        "git_refs_sha256": hashlib.sha256(refs.stdout).hexdigest(),
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
    try:
        with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
            tar.extractall(destination, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise OverlayRefusal("overlay.archive_refused", f"Pinned archive cannot be safely materialized: {exc}") from exc
    return resolved


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def protected_directories(target: Path) -> list[Path]:
    directories = [target]
    for option in ("--absolute-git-dir", "--git-common-dir"):
        result = run_git(target, "rev-parse", option)
        if result.returncode:
            raise OverlayRefusal("overlay.git_state_unavailable", "Cannot resolve protected Git metadata")
        directory = Path(os.fsdecode(result.stdout.rstrip(b"\r\n")))
        if not directory.is_absolute():
            directory = target / directory
        directories.append(directory.resolve())
    return directories


def report_output_allowed(path: Path, target: Path) -> bool:
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_nlink != 1)):
        return False
    return not any(is_within(path, directory) for directory in protected_directories(target))


def temporary_parent(target: Path) -> Path:
    protected = protected_directories(target)
    # Reject configured protected locations before tempfile can probe them.
    configured = [tempfile.tempdir, *(os.environ.get(k) for k in ("TMPDIR", "TEMP", "TMP"))]
    for value in configured:
        if value and any(is_within(Path(os.fsdecode(value)), directory) for directory in protected):
            raise OverlayRefusal("overlay.temporary_location_refused", "Temporary storage must be outside target and Git metadata")
    parent = Path(tempfile.gettempdir()).resolve()
    if any(is_within(parent, directory) for directory in protected):
        raise OverlayRefusal("overlay.temporary_location_refused", "Temporary storage must be outside target and Git metadata")
    return parent


def run_verification(command: list[str], cwd: Path) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=operation_environment(),
    )
    return {
        "argv": command,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def prepare_disposable_lifecycle(target: Path, profile: str, workspace: Path) -> list[dict[str, Any]]:
    """Enroll only this temporary root using actual digest-confirmed producers."""
    steps: list[dict[str, Any]] = []

    def refusal(message: str) -> OverlayRefusal:
        return OverlayRefusal("overlay.prerequisite_refused", message,
                              {"disposable_prerequisites": {"repository_intelligence": steps}})

    if (target / ".naos/upgrade-v1").exists():
        raise OverlayRefusal("overlay.prerequisite_refused",
                             "Archived managed state cannot authorize a fresh disposable root. "
                             "Use a supported receiving/migration workflow; overlay validation does not rebind it.")
    empty_template = workspace / "empty-git-template"
    empty_template.mkdir()
    for args in (("init", "--quiet", "--template=" + str(empty_template)), ("add", "--all", "--force")):
        result = run_git(target, *args)
        if result.returncode:
            raise refusal(result.stderr.decode("utf-8", errors="replace"))

    def ri(operation: str, *args: str) -> dict[str, Any]:
        command = [sys.executable, "-B", str(KIT_ROOT / "scripts/naos_repository_intelligence.py"),
                   operation, str(target), "--profile", profile, *args]
        result = run_verification(command, KIT_ROOT)
        try:
            report = json.loads(result["stdout"])
        except ValueError as exc:
            steps.append({"operation": operation, **result, "status": "invalid_output"})
            raise refusal(f"Repository intelligence {operation} failed: {result['stderr']}") from exc
        steps.append({"operation": operation, "exit_code": result["exit_code"],
                      "status": report.get("status"), "plan_sha256": report.get("plan_sha256")})
        if result["exit_code"]:
            raise refusal(f"Repository intelligence {operation} refused: " + json.dumps(report))
        return report

    for operation, expected, accepted in (
        ("enroll", "enrollment_required", {"enrolled", "enrolled_without_activation"}),
        ("apply", "confirmation_required", {"validated_active"}),
    ):
        plan_path = workspace / (operation + "-plan.json")
        plan = ri("plan", "--component-mode", "baseline", "--output", str(plan_path))
        if plan.get("status") == "not_applicable":
            return steps  # The initializer independently revalidates this determination.
        if plan.get("status") != expected or not isinstance(plan.get("plan_sha256"), str):
            raise refusal("Unexpected disposable lifecycle plan: " + json.dumps(plan))
        result = ri(operation, "--plan", str(plan_path), "--confirm-plan-sha256", plan["plan_sha256"],
                    "--reviewer-id", "disposable-overlay-validation")
        if result.get("status") not in accepted:
            raise refusal("Disposable lifecycle operation did not complete")
    if ri("validate").get("status") != "validated_current":
        raise refusal("Disposable repository intelligence is not current")
    return steps


def build_report(
    target: Path,
    profile: str,
    expected_commit: str | None,
    verification_command: list[str] | None = None,
) -> dict[str, Any]:
    target = target.resolve(strict=True)
    before = target_snapshot(target)
    head = git_head(target)
    with tempfile.TemporaryDirectory(prefix="naos-overlay-", dir=temporary_parent(target)) as temp_dir:
        temp_root = Path(temp_dir)
        validation_target = temp_root / "target-at-commit"
        requested_commit = expected_commit or head
        if not requested_commit:
            raise ValueError("The target does not expose a Git commit to materialize.")
        validated_commit = materialize_commit(target, requested_commit, validation_target)
        source_materialization = "git_archive"
        original_paths = {path.relative_to(validation_target).as_posix() for path in validation_target.rglob("*")}
        baseline_verification = run_verification(verification_command, validation_target) if verification_command else None
        overlay = temp_root / "overlay"
        try:
            lifecycle_steps = prepare_disposable_lifecycle(validation_target, profile, temp_root)
        except OverlayRefusal as exc:
            exc.evidence["verification"] = {"command_configured": verification_command is not None,
                                            "baseline": baseline_verification,
                                            "with_isolated_sidecar_overlay": None, "passed": False}
            raise
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
            encoding="utf-8",
            errors="replace",
            env=operation_environment(),
            stdin=subprocess.DEVNULL,
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
        collisions = [path for path in generated if path in original_paths]
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
        "disposable_prerequisites": {"git_state": "synthetic_index_of_archived_files_without_original_history",
                                    "repository_intelligence": lifecycle_steps},
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
            "The mutation check covers Git-visible files plus index bytes and references, not ignored caches or an atomic filesystem snapshot.",
            "Optional verification commands run with caller privileges in a temporary cwd; this is not a security sandbox.",
            "The disposable Git index is synthetic; the original commit identity is recorded separately.",
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
    verification = parser.add_mutually_exclusive_group()
    verification.add_argument("--verification-command", help="Legacy POSIX-quoted no-shell command; use --verification-argv for native Windows paths.")
    verification.add_argument("--verification-argv", help="JSON array of exact no-shell command arguments, portable across all operating systems.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    target = args.target.resolve(strict=True)
    if args.output and not report_output_allowed(args.output, target):
        print("ERROR: --output must be outside the read-only target and its Git metadata, without file aliases", file=sys.stderr)
        return 2
    before = None
    try:
        verification_command = (json.loads(args.verification_argv) if args.verification_argv is not None
                                else shlex.split(args.verification_command) if args.verification_command else None)
        if verification_command is not None and (not isinstance(verification_command, list)
                or not verification_command or any(not isinstance(arg, str) or "\0" in arg for arg in verification_command)
                or not verification_command[0]):
            raise OverlayRefusal("overlay.invalid_verification_argv", "Verification argv must be a nonempty JSON array of strings with an executable first argument")
        before = target_snapshot(target)
        report = build_report(target, args.profile, args.expected_commit, verification_command)
    except Exception as exc:
        try:
            after = target_snapshot(target) if before is not None else None
        except (OSError, ValueError):
            after = None
        report = {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "target": str(target),
            "profile": args.profile,
            "expected_commit": args.expected_commit,
            "observed_commit": git_head(target),
            "commit_match": False,
            "target_unchanged": before == after if before is not None and after is not None else None,
            "findings": [{"id": getattr(exc, "finding_id", "overlay.validation_error"), "message": str(exc)}],
            "human_review_required": True,
            "limitations": ["Overlay coexistence validation did not complete."],
            "not_claimed": ["target-repository modification or installation"],
            "summary": {"status": "failed", "total_findings": 1, "advisory": 0, "warning": 0, "required": 1, "blocking": 0, "human_review_required": True},
        }
        if isinstance(exc, OverlayRefusal):
            report.update(exc.evidence)
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
