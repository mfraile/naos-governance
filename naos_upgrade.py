#!/usr/bin/env python3
"""Deterministic content-aware planning, apply, and recovery for NAOS."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

try:
    from . import naos_init
    from .upgrade_contract.canonical import canonical_bytes, loads_strict_json
    from .upgrade_contract.planner import (
        ContentPlanningError,
        build_content_aware_plan,
        load_source_policy_snapshot,
        revalidate_content_aware_plan,
        validate_content_aware_plan,
    )
    from .upgrade_contract.provenance import (
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_LOCK_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from .upgrade_contract import transaction
except ImportError:  # Direct checkout execution through ``python cli.py``.
    _KIT_IMPORT_ROOT = Path(__file__).resolve().parent
    if str(_KIT_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_KIT_IMPORT_ROOT))
    import naos_init  # type: ignore[no-redef]
    from upgrade_contract.canonical import (  # type: ignore[no-redef]
        canonical_bytes,
        loads_strict_json,
    )
    from upgrade_contract.planner import (  # type: ignore[no-redef]
        ContentPlanningError,
        build_content_aware_plan,
        load_source_policy_snapshot,
        revalidate_content_aware_plan,
        validate_content_aware_plan,
    )
    from upgrade_contract.provenance import (  # type: ignore[no-redef]
        MANAGED_CONTENT_BASES_RELATIVE,
        MANAGED_CONTENT_LOCK_RELATIVE,
        MANAGED_CONTENT_MANIFEST_RELATIVE,
        MANAGED_CONTENT_RECEIPTS_RELATIVE,
        MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        inspect_managed_content_manifest,
        inspect_managed_content_scope,
    )
    from upgrade_contract import transaction  # type: ignore[no-redef]


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PLAN_BYTES = 64 * 1024 * 1024
UPGRADE_OPERATION = "naos-upgrade-profile-transition"
UPGRADE_CHECK_IDS = {
    "generated_profile_contract",
    "overlay_compatibility",
}


class UpgradeCliError(ValueError):
    """A controlled pre-mutation upgrade refusal."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "NAOS upgrade — create an immutable content-aware plan, apply one "
            "exact digest-bound plan, or recover managed transactions"
        )
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        type=Path,
        default=Path("."),
        help="Existing managed project (default: current directory)",
    )
    parser.add_argument(
        "--tier",
        choices=["quickstart", "lite", "standard", "assured"],
        help="Requested profile for planning; required in planning mode",
    )
    parser.add_argument(
        "--plan-out",
        type=Path,
        help="Atomically create this absent plan file outside the adopter project",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Exact synonym for default plan-only behavior",
    )
    parser.add_argument(
        "--apply-plan",
        type=Path,
        help="Apply this exact external canonical plan; never replans",
    )
    parser.add_argument(
        "--expect-plan-digest",
        help="Required SHA-256 digest for --apply-plan",
    )
    parser.add_argument(
        "--recover",
        action="store_true",
        help="Recover supported managed-content transactions",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Legacy blanket replacement option; always refused",
    )
    parser.add_argument("--archetype", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--backend", default=None, help=argparse.SUPPRESS)
    return parser


def _selected_mode(args: argparse.Namespace) -> str:
    if args.force:
        raise UpgradeCliError(
            "legacy blanket --force is permanently refused; there is no "
            "break-glass replacement route"
        )
    if args.archetype is not None or args.backend is not None:
        raise UpgradeCliError(
            "upgrade preserves provenance-bound archetype and backend choices; "
            "command-line overrides are refused"
        )
    if args.recover:
        if any(
            value is not None
            for value in (
                args.tier,
                args.plan_out,
                args.apply_plan,
                args.expect_plan_digest,
            )
        ) or args.dry_run:
            raise UpgradeCliError(
                "--recover cannot be combined with planning or apply options"
            )
        return "recover"
    if args.apply_plan is not None or args.expect_plan_digest is not None:
        if args.apply_plan is None or args.expect_plan_digest is None:
            raise UpgradeCliError(
                "--apply-plan and --expect-plan-digest are required together"
            )
        if args.tier is not None or args.plan_out is not None or args.dry_run:
            raise UpgradeCliError(
                "digest-bound apply cannot be combined with --tier, --plan-out, "
                "or --dry-run"
            )
        if SHA256_RE.fullmatch(args.expect_plan_digest) is None:
            raise UpgradeCliError("--expect-plan-digest must be lowercase SHA-256")
        return "apply"
    if args.tier is None:
        raise UpgradeCliError("planning requires --tier")
    return "plan"


def _canonical_project_path(supplied: Path) -> Path:
    try:
        return naos_init._canonical_init_target(
            supplied,
            must_exist=True,
        ).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise UpgradeCliError(
            "upgrade requires an existing non-symlink project directory; "
            "use `naos init` for a new destination: " + str(exc)
        ) from exc


def _external_plan_path(
    project_root: Path,
    supplied: Path,
    *,
    must_exist: bool,
) -> Path:
    lexical = Path(os.path.abspath(os.fspath(supplied.expanduser())))
    if not lexical.name or lexical.name in {".", ".."}:
        raise UpgradeCliError("external plan path has no valid file name")
    try:
        parent = lexical.parent.resolve(strict=True)
        parent_state = os.lstat(parent)
    except OSError as exc:
        raise UpgradeCliError(
            "external plan parent must be an existing directory: " + str(exc)
        ) from exc
    if not stat.S_ISDIR(parent_state.st_mode) or stat.S_ISLNK(parent_state.st_mode):
        raise UpgradeCliError("external plan parent is not a safe directory")
    if (
        parent == project_root
        or project_root in parent.parents
        or naos_init._is_same_or_descendant_by_identity(parent, project_root)
    ):
        raise UpgradeCliError("plan files must remain outside the adopter project")
    result = parent / lexical.name
    try:
        state = os.lstat(result)
    except FileNotFoundError:
        state = None
    except OSError as exc:
        raise UpgradeCliError("external plan path is unsafe: " + str(exc)) from exc
    if must_exist:
        if state is None:
            raise UpgradeCliError("apply plan does not exist")
        if (
            stat.S_ISLNK(state.st_mode)
            or not stat.S_ISREG(state.st_mode)
            or state.st_nlink != 1
        ):
            raise UpgradeCliError(
                "apply plan must be one regular, non-symlink, singly-linked file"
            )
    elif state is not None:
        raise UpgradeCliError(
            "plan output already exists and was preserved; choose an absent path"
        )
    return result


def _publish_external_plan(path: Path, payload: bytes) -> None:
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary_name = f".{path.name}.naos-plan-{uuid.uuid4().hex}.pending"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing canonical plan")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        transaction.rename_no_replace_at(
            parent_fd,
            temporary_name,
            parent_fd,
            path.name,
        )
        os.fsync(parent_fd)
    except FileExistsError as exc:
        raise UpgradeCliError(
            "plan output appeared concurrently and was preserved"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _read_external_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > MAX_PLAN_BYTES
        ):
            raise UpgradeCliError("apply plan file identity or size is unsupported")
        chunks: list[bytes] = []
        remaining = MAX_PLAN_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if len(raw) > MAX_PLAN_BYTES:
            raise UpgradeCliError("apply plan exceeds the supported size")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise UpgradeCliError("apply plan changed while it was read")
    finally:
        os.close(descriptor)
    value = loads_strict_json(raw)
    if not isinstance(value, dict):
        raise UpgradeCliError("apply plan must be a JSON object")
    canonical = canonical_bytes(value)
    if raw != canonical:
        raise UpgradeCliError(
            "apply plan is not the exact RFC 8785 canonical byte representation"
        )
    return value, raw


def _transaction_arguments(project_root: Path, binding: object) -> dict[str, Any]:
    project_id = getattr(binding, "project_id", None)
    scope_integrity = getattr(binding, "scope_integrity", None)
    source_policy_sha256 = getattr(binding, "source_policy_sha256", None)
    if not all(
        isinstance(value, str) and value
        for value in (project_id, scope_integrity, source_policy_sha256)
    ):
        raise UpgradeCliError("managed-content provenance binding is incomplete")
    return {
        "project_id": project_id,
        "scope_integrity_sha3_512": scope_integrity,
        "scope_source_policy_sha256": source_policy_sha256,
        "transaction_root": project_root / MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
        "lock_path": project_root / MANAGED_CONTENT_LOCK_RELATIVE,
        "manifest_path": project_root / MANAGED_CONTENT_MANIFEST_RELATIVE,
        "bases_root": project_root / MANAGED_CONTENT_BASES_RELATIVE,
        "receipts_root": project_root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
    }


def _preview_checks(preview: dict[str, Any]) -> list[dict[str, str]]:
    overlay = preview.get("overlay_compatibility")
    if not isinstance(overlay, dict):
        raise UpgradeCliError("upgrade preview lacks overlay-compatibility evidence")
    profile_digest = preview.get("profile_contract_sha256")
    if not isinstance(profile_digest, str) or SHA256_RE.fullmatch(profile_digest) is None:
        raise UpgradeCliError("upgrade preview lacks generated-profile evidence")
    return [
        {
            "check_id": "generated_profile_contract",
            "status": "passed",
            "evidence_sha256": profile_digest,
        },
        {
            "check_id": "overlay_compatibility",
            "status": "passed" if overlay.get("activation_allowed") else "blocking",
            "evidence_sha256": naos_init.canonical_sha256(overlay),
        },
    ]


def _diagnostic_preview(
    project_root: Path,
    preview_root: Path,
    *,
    requested_profile: str,
) -> dict[str, Any]:
    signals = naos_init.detect_signals(project_root, excluded_paths=set())
    preview = naos_init._generate_scaffold_preview(
        project_path=project_root,
        preview_dir=preview_root,
        signals=signals,
        tier=requested_profile,
        archetype="custom",
        backend="static_only",
        memory_choice=None,
        current_managed_paths=set(),
        existing_destination=True,
        apply_brownfield_layout_adapter=True,
        ephemeral_preview=True,
        emit_progress=False,
    )
    return {
        **preview,
        "signals": signals,
        "effective_inputs": {"profile": requested_profile},
        "checks": _preview_checks(preview),
    }


def _external_temp_root(project_root: Path) -> Path:
    temp_root = naos_init._select_external_temp_root(project_root)
    if temp_root is None:
        raise UpgradeCliError(
            "no existing external temporary root is available; set TMPDIR to a "
            "directory outside the adopter project"
        )
    return temp_root


def _plan_command(
    project_root: Path,
    *,
    requested_profile: str,
    plan_out: Path | None,
) -> int:
    inspection = inspect_managed_content_manifest(project_root)
    with tempfile.TemporaryDirectory(
        prefix="naos-upgrade-plan-",
        dir=_external_temp_root(project_root),
    ) as temporary:
        preview_root = Path(temporary) / "preview"
        if inspection.apply_eligible and inspection.snapshot is not None:
            preview = naos_init.regenerate_managed_init_preview(
                project_root,
                preview_root,
                manifest_snapshot=inspection.snapshot,
                requested_profile=requested_profile,
            )
            manifest_snapshot = inspection.snapshot
            provenance_refusal = None
        else:
            preview = _diagnostic_preview(
                project_root,
                preview_root,
                requested_profile=requested_profile,
            )
            manifest_snapshot = None
            provenance_refusal = inspection.refusal or (
                "Existing project has no valid managed-content provenance; "
                "ownership inference is forbidden."
            )
        plan = build_content_aware_plan(
            project_root,
            list(preview["sources"]),
            source_policy_path=naos_init.UPGRADE_SOURCE_POLICY_PATH,
            operation=UPGRADE_OPERATION,
            inputs={"profile": requested_profile},
            manifest_snapshot=manifest_snapshot,
            provenance_refusal=provenance_refusal,
            fixed_checks=list(preview["checks"]),
        )
        if inspection.apply_eligible and (
            plan["profile"]["effective_inputs"] != preview["effective_inputs"]
        ):
            raise UpgradeCliError(
                "regenerated profile-independent inputs differ from provenance"
            )
        payload = canonical_bytes(plan)
    if plan_out is not None:
        external = _external_plan_path(
            project_root,
            plan_out,
            must_exist=False,
        )
        _publish_external_plan(external, payload)
    sys.stdout.write(payload.decode("utf-8") + "\n")
    return 3 if plan["status"] == "diagnostic_only" else 0


def plan_profile_transition(
    project_root: Path,
    *,
    requested_profile: str,
    plan_out: Path | None = None,
) -> int:
    """Public in-process entry point for consumers that must use upgrade planning."""

    return _plan_command(
        _canonical_project_path(project_root),
        requested_profile=requested_profile,
        plan_out=plan_out,
    )


def publish_external_content_plan(
    project_root: Path,
    plan_path: Path,
    plan: dict[str, Any],
) -> Path:
    """Publish one validated canonical plan outside the adopter project."""

    root = _canonical_project_path(project_root)
    validate_content_aware_plan(plan, project_root=root)
    external = _external_plan_path(root, plan_path, must_exist=False)
    _publish_external_plan(external, canonical_bytes(plan))
    return external


def _require_upgrade_checks(plan: dict[str, Any]) -> None:
    checks = plan.get("checks")
    if (
        not isinstance(checks, list)
        or {
            str(check.get("check_id"))
            for check in checks
            if isinstance(check, dict)
        }
        != UPGRADE_CHECK_IDS
        or any(check.get("status") != "passed" for check in checks)
    ):
        raise UpgradeCliError(
            "digest-bound apply requires passed generated-profile and overlay checks"
        )


def _require_add_checks(plan: dict[str, Any]) -> None:
    checks = plan.get("checks")
    if (
        not isinstance(checks, list)
        or len(checks) != 1
        or checks[0].get("check_id") != "managed_request_source_authority"
        or checks[0].get("status") != "passed"
        or not isinstance(checks[0].get("evidence_sha256"), str)
        or SHA256_RE.fullmatch(str(checks[0]["evidence_sha256"])) is None
    ):
        raise UpgradeCliError(
            "digest-bound add/setup apply requires exact source-authority evidence"
        )


def _apply_regenerated_plan(
    project_root: Path,
    *,
    plan: dict[str, Any],
    inspection: object,
    sources: list[tuple[Path, Path]],
    checks: list[dict[str, str]],
) -> object:
    transaction_arguments = _transaction_arguments(project_root, inspection)
    revalidate_content_aware_plan(
        project_root,
        sources,
        source_policy_path=naos_init.UPGRADE_SOURCE_POLICY_PATH,
        plan=plan,
        manifest_snapshot=getattr(inspection, "snapshot", None),
        provenance_refusal=getattr(inspection, "refusal", None),
        fixed_checks=checks,
    )
    return transaction.apply_content_aware_plan(
        project_root,
        plan=plan,
        sources=sources,
        **transaction_arguments,
    )


def _emit_apply_outcome(
    outcome: object,
    expected_digest: str,
    *,
    status_override: str | None = None,
    detail_override: str | None = None,
) -> int:
    status = status_override or str(getattr(outcome, "status", "unknown"))
    print(
        json.dumps(
            {
                "status": status,
                "transaction_id": getattr(outcome, "transaction_id", None),
                "receipt_path": getattr(outcome, "receipt_path", None),
                "plan_sha256": expected_digest,
                "detail": (
                    detail_override
                    if detail_override is not None
                    else getattr(outcome, "detail", None)
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if status in {"committed", "already_applied"} else 3


def _apply_command(
    project_root: Path,
    *,
    plan_path: Path,
    expected_digest: str,
) -> int:
    external = _external_plan_path(project_root, plan_path, must_exist=True)
    plan, _raw = _read_external_plan(external)
    validate_content_aware_plan(plan, project_root=project_root)
    if plan.get("plan_sha256") != expected_digest:
        raise UpgradeCliError(
            "supplied digest does not equal the embedded canonical plan digest"
        )
    operation = str(plan.get("operation") or "")
    is_profile_transition = operation == UPGRADE_OPERATION
    is_add_request = operation.startswith("naos-add-artifact:") or operation.startswith(
        "naos-add-setup-module:"
    )
    if not is_profile_transition and not is_add_request:
        raise UpgradeCliError(
            "apply plan was not created by a supported NAOS content consumer"
        )
    if plan.get("status") != "ready":
        raise UpgradeCliError(
            "apply refuses a plan that is not mutation-ready: "
            + str(plan.get("status"))
        )
    if is_profile_transition:
        _require_upgrade_checks(plan)
    else:
        _require_add_checks(plan)
    active_policy = (plan.get("source_policy") or {}).get("active") or {}
    provenance_policy = (plan.get("source_policy") or {}).get("provenance") or {}
    load_source_policy_snapshot(
        naos_init.UPGRADE_SOURCE_POLICY_PATH,
        expected_sha256=str(active_policy.get("binding_sha256") or ""),
    )
    load_source_policy_snapshot(
        naos_init.UPGRADE_SOURCE_POLICY_PATH,
        expected_sha256=str(provenance_policy.get("binding_sha256") or ""),
    )
    inspection = inspect_managed_content_manifest(project_root)
    if not inspection.apply_eligible or inspection.snapshot is None:
        raise UpgradeCliError(
            "apply requires currently valid managed-content provenance: "
            + str(inspection.refusal or inspection.status)
        )
    prior = transaction.inspect_content_aware_plan_application(
        project_root,
        plan=plan,
        **_transaction_arguments(project_root, inspection),
    )
    if prior is not None:
        return _emit_apply_outcome(prior, expected_digest)
    requested_profile = str((plan.get("profile") or {}).get("requested") or "")
    if is_profile_transition:
        with tempfile.TemporaryDirectory(
            prefix="naos-upgrade-apply-",
            dir=_external_temp_root(project_root),
            ignore_cleanup_errors=True,
        ) as temporary:
            preview = naos_init.regenerate_managed_init_preview(
                project_root,
                Path(temporary) / "preview",
                manifest_snapshot=inspection.snapshot,
                requested_profile=requested_profile,
            )
            if preview["effective_inputs"] != plan["profile"]["effective_inputs"]:
                raise UpgradeCliError(
                    "profile-independent inputs changed during source regeneration"
                )
            if preview["checks"] != plan["checks"]:
                raise UpgradeCliError(
                    "fixed generated-profile or overlay evidence changed after planning"
                )
            outcome = _apply_regenerated_plan(
                project_root,
                plan=plan,
                inspection=inspection,
                sources=list(preview["sources"]),
                checks=list(preview["checks"]),
            )
    else:
        try:
            from . import naos_add as add_module
        except ImportError:
            import naos_add as add_module  # type: ignore[no-redef]
        with add_module.regenerate_managed_request(project_root, plan) as regenerated:
            if regenerated["checks"] != plan["checks"]:
                raise UpgradeCliError(
                    "fixed add/setup source evidence changed after planning"
                )
            previous_inputs = inspection.snapshot.get("previous_inputs")
            if plan["profile"]["effective_inputs"] != previous_inputs:
                raise UpgradeCliError(
                    "add/setup plan changed provenance-bound profile inputs"
                )
            outcome = _apply_regenerated_plan(
                project_root,
                plan=plan,
                inspection=inspection,
                sources=list(regenerated["sources"]),
                checks=list(regenerated["checks"]),
            )
    if outcome.status not in {"committed", "already_applied"}:
        return _emit_apply_outcome(outcome, expected_digest)
    try:
        closing = inspect_managed_content_manifest(project_root)
    except Exception as exc:
        return _emit_apply_outcome(
            outcome,
            expected_digest,
            status_override="post_apply_validation_failed",
            detail_override=(
                "the transaction committed, but closing manifest/receipt "
                f"validation failed: {exc}"
            ),
        )
    if closing.status != "valid_v2" or closing.snapshot is None:
        return _emit_apply_outcome(
            outcome,
            expected_digest,
            status_override="post_apply_validation_failed",
            detail_override=(
                "the transaction committed, but closing manifest/receipt "
                f"validation reported {closing.status}: {closing.refusal or ''}"
            ),
        )
    return _emit_apply_outcome(outcome, expected_digest)


def _recover_command(project_root: Path) -> int:
    scope = inspect_managed_content_scope(project_root)
    if scope.status != "valid":
        raise UpgradeCliError(
            "recovery requires a valid operation-owned scope: "
            + str(scope.refusal or scope.status)
        )
    outcomes = transaction.recover_managed_content_transactions(
        project_root,
        **_transaction_arguments(project_root, scope),
    )
    payload = [
        {
            "status": outcome.status,
            "transaction_id": outcome.transaction_id,
            "receipt_path": outcome.receipt_path,
            "detail": outcome.detail,
        }
        for outcome in outcomes
    ]
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    unresolved = {
        "recovery_required",
        "rollback_incomplete",
        "blocked_collision",
    }
    return 3 if any(item["status"] in unresolved for item in payload) else 0


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    try:
        mode = _selected_mode(args)
        project_root = _canonical_project_path(args.project_path)
        if mode == "plan":
            return _plan_command(
                project_root,
                requested_profile=str(args.tier),
                plan_out=args.plan_out,
            )
        if mode == "apply":
            return _apply_command(
                project_root,
                plan_path=args.apply_plan,
                expected_digest=args.expect_plan_digest,
            )
        return _recover_command(project_root)
    except (OSError, RuntimeError, ValueError, ContentPlanningError) as exc:
        print(f"NOT_APPLIED: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
