#!/usr/bin/env python3
"""Deterministic content-aware planning, apply, and recovery for NAOS."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

try:
    from . import naos_init
    from .upgrade_contract.plan_stdout import emit_canonical_plan
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
    from upgrade_contract.plan_stdout import emit_canonical_plan
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
        help="Required SHA-256 digest for --apply-plan or explicit approved recovery",
    )
    parser.add_argument(
        "--recover",
        action="store_true",
        help="Recover supported managed-content transactions",
    )
    parser.add_argument(
        "--inspect-provenance",
        action="store_true",
        help="Read and validate portable v3 history without granting mutation authority",
    )
    parser.add_argument('--plan-hook-activation', action='store_true',
        help='Review exact existing POSIX owned-hook activation; never configures or executes Git')
    parser.add_argument('--hook-mode-octal', help='Exact observed full activation mode, four octal digits')
    parser.add_argument("--plan-migration", action="store_true",
        help="Review explicit legacy history migration using independently selected inputs")
    parser.add_argument("--migration-inputs", type=Path,
        help="External canonical migration inputs and original policy/mode file paths")
    parser.add_argument(
        "--plan-rebind", action="store_true",
        help="Review explicit receiving enrollment with absent local and legacy storage",
    )
    parser.add_argument("--expected-owner-sha256", help="Independently selected portable owner SHA-256 for rebind planning")
    parser.add_argument("--expected-head-sha256", help="Independently selected portable head SHA-256 for rebind planning")
    parser.add_argument("--binding-id", help="Explicit new 32-character lowercase hexadecimal receiving binding ID")
    parser.add_argument('--inspect-receiving-store',action='store_true',help='Review completed populated receiving evidence without mutation')
    parser.add_argument('--plan-receive-store',action='store_true',help='Review explicit in-place receiving of a completed populated store')
    parser.add_argument('--expected-store-inventory-sha256',help='Independently selected complete old receiving evidence inventory SHA-256')
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
    if args.plan_hook_activation:
        if (args.plan_migration or args.migration_inputs is not None or args.plan_rebind
                or args.inspect_provenance or args.recover or args.dry_run
                or args.inspect_receiving_store or args.plan_receive_store
                or any(v is not None for v in (args.tier, args.apply_plan, args.expect_plan_digest,
                    args.binding_id, args.expected_store_inventory_sha256))):
            raise UpgradeCliError('Hook activation planning requires its exclusive option set')
        if (args.hook_mode_octal is None or re.fullmatch(r'[0-7]{4}', args.hook_mode_octal) is None
                or any(v is None or SHA256_RE.fullmatch(v) is None for v in
                    (args.expected_owner_sha256, args.expected_head_sha256))):
            raise UpgradeCliError('Hook activation requires exact mode and independent owner/head digests')
        return 'plan_hook_activation'
    if args.hook_mode_octal is not None:
        raise UpgradeCliError('Hook mode selection requires --plan-hook-activation')
    inspect_receiving=getattr(args,'inspect_receiving_store',False)
    plan_receiving=getattr(args,'plan_receive_store',False)
    inventory_digest=getattr(args,'expected_store_inventory_sha256',None)
    if inspect_receiving or plan_receiving:
        if (inspect_receiving and plan_receiving or args.plan_migration or args.migration_inputs is not None
                or args.plan_rebind or args.inspect_provenance or args.recover or args.dry_run
                or any(v is not None for v in (args.tier,args.apply_plan,args.expect_plan_digest))):
            raise UpgradeCliError('Receiving inspection/planning requires its exact exclusive option set')
        if inspect_receiving:
            if any(v is not None for v in (args.plan_out,args.expected_owner_sha256,args.expected_head_sha256,args.binding_id,inventory_digest)):
                raise UpgradeCliError('Receiving inspection accepts no planning authority inputs')
            return 'inspect_receiving'
        if any(v is None or SHA256_RE.fullmatch(v) is None for v in
               (args.expected_owner_sha256,args.expected_head_sha256,inventory_digest)):
            raise UpgradeCliError('Receiving plan requires independent owner/head/store inventory SHA-256')
        if args.binding_id is None or re.fullmatch(r'[0-9a-f]{32}',args.binding_id) is None:
            raise UpgradeCliError('Receiving plan requires a fresh explicit binding ID')
        return 'plan_receiving'
    if inventory_digest is not None:
        raise UpgradeCliError('Store inventory expectation requires --plan-receive-store')
    if args.plan_migration:
        if (args.migration_inputs is None or args.plan_rebind or args.inspect_provenance
                or args.recover or args.dry_run or any(value is not None for value in
                (args.tier, args.apply_plan, args.expect_plan_digest,
                 args.expected_owner_sha256, args.expected_head_sha256, args.binding_id))):
            raise UpgradeCliError("--plan-migration requires --migration-inputs and only optional --plan-out")
        return "plan_migration"
    if args.migration_inputs is not None:
        if (args.apply_plan is None or args.expect_plan_digest is None or args.plan_rebind
                or args.inspect_provenance or args.dry_run or args.tier is not None
                or args.plan_out is not None or any(value is not None for value in
                (args.expected_owner_sha256, args.expected_head_sha256, args.binding_id))):
            raise UpgradeCliError("--migration-inputs requires exact migration plan apply or recovery")
        if SHA256_RE.fullmatch(args.expect_plan_digest) is None:
            raise UpgradeCliError("--expect-plan-digest must be lowercase SHA-256")
        return "recover_migration" if args.recover else "apply_migration"
    rebind_values = (args.expected_owner_sha256, args.expected_head_sha256, args.binding_id)
    if args.plan_rebind:
        if (args.inspect_provenance or args.recover or args.dry_run
                or any(value is not None for value in (args.tier, args.apply_plan, args.expect_plan_digest))):
            raise UpgradeCliError("--plan-rebind cannot be combined with profile planning, apply or recovery")
        if any(value is None for value in rebind_values):
            raise UpgradeCliError("--plan-rebind requires --expected-owner-sha256, --expected-head-sha256 and --binding-id")
        if any(SHA256_RE.fullmatch(value) is None for value in rebind_values[:2]):
            raise UpgradeCliError("rebind owner/head expectations must be lowercase SHA-256")
        if re.fullmatch(r"[0-9a-f]{32}", args.binding_id) is None:
            raise UpgradeCliError("--binding-id must be 32 lowercase hexadecimal characters")
        return "plan_rebind"
    if any(value is not None for value in rebind_values):
        raise UpgradeCliError("owner/head/binding options require --plan-rebind")
    if args.inspect_provenance:
        if args.recover or args.dry_run or any(
            value is not None
            for value in (args.tier, args.plan_out, args.apply_plan, args.expect_plan_digest)
        ):
            raise UpgradeCliError(
                "--inspect-provenance cannot be combined with planning, apply or recovery options"
            )
        return "inspect"
    if args.recover:
        if args.apply_plan is not None:
            if (args.expect_plan_digest is None or SHA256_RE.fullmatch(args.expect_plan_digest) is None
                    or args.tier is not None or args.plan_out is not None or args.dry_run):
                raise UpgradeCliError('External receiving recovery requires exact plan and digest only')
            return 'recover_receiving'
        if any(
            value is not None
            for value in (
                args.tier,
                args.plan_out,
                args.apply_plan,
            )
        ) or args.dry_run:
            raise UpgradeCliError(
                "--recover cannot be combined with planning or apply options"
            )
        if args.expect_plan_digest is not None:
            if SHA256_RE.fullmatch(args.expect_plan_digest) is None:
                raise UpgradeCliError("--expect-plan-digest must be lowercase SHA-256")
            return "recover_rebind"
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
        target = naos_init._canonical_init_target(
            supplied,
            must_exist=True,
        )
        return target if naos_init._windows_cli() is not None else target.resolve(strict=True)
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


def _check_external_plan_parent(path: Path, parent_fd: int) -> None:
    opened = os.fstat(parent_fd)
    live = os.stat(path.parent, follow_symlinks=False)
    if not stat.S_ISDIR(live.st_mode) or (
        opened.st_dev, opened.st_ino
    ) != (live.st_dev, live.st_ino):
        raise UpgradeCliError("external plan parent changed during publication")


def _check_external_plan_entry(
    parent_fd: int, name: str, descriptor: int, owned: os.stat_result,
    payload: bytes,
) -> None:
    before = os.fstat(descriptor)
    live = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(live.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or (live.st_dev, live.st_ino) != (owned.st_dev, owned.st_ino)
        or (before.st_dev, before.st_ino) != (owned.st_dev, owned.st_ino)
        or before.st_nlink != 1 or live.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or stat.S_IMODE(live.st_mode) != 0o600
        or (before.st_uid, before.st_gid) != (owned.st_uid, owned.st_gid)
        or before.st_size != len(payload)
    ):
        raise UpgradeCliError("external plan file identity changed during publication")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = len(payload) + 1
    while remaining:
        block = os.read(descriptor, min(1024 * 1024, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    after = os.fstat(descriptor)
    if b"".join(chunks) != payload or (
        before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise UpgradeCliError("external plan bytes changed during publication")
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
        raise UpgradeCliError("external plan name changed during publication")


def _publish_external_plan(path: Path, payload: bytes) -> None:
    if platform.system() not in {"Darwin", "Linux"}:
        raise UpgradeCliError(
            "External plan publication requires a macOS or Linux descriptor adapter."
        )
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
        _check_external_plan_parent(path, parent_fd)
        descriptor = os.open(
            temporary_name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        owned = os.fstat(descriptor)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing canonical plan")
            view = view[written:]
        os.fsync(descriptor)
        _check_external_plan_entry(parent_fd, temporary_name, descriptor, owned, payload)
        _check_external_plan_parent(path, parent_fd)
        transaction.rename_no_replace_at(
            parent_fd,
            temporary_name,
            parent_fd,
            path.name,
        )
        os.fsync(parent_fd)
        _check_external_plan_entry(parent_fd, path.name, descriptor, owned, payload)
        _check_external_plan_parent(path, parent_fd)
    except FileExistsError as exc:
        raise UpgradeCliError(
            "plan publication path collision; existing entries were preserved; "
            f"inspect any retained pending entry at {path.parent / temporary_name}"
        ) from exc
    except (OSError, UpgradeCliError, transaction.TransactionPrimitiveError) as exc:
        raise UpgradeCliError(
            f"external plan publication refused: {exc}; "
            f"inspect retained entries, if present, at {path.parent / temporary_name} "
            f"and {path}; no cleanup was attempted"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # Name-based cleanup cannot atomically establish ownership. Preserve
        # uncertain entries on failure; successful rename consumes our name.
        os.close(parent_fd)


def _read_external_bytes(path: Path, *, limit: int | None = None) -> bytes:
    limit = MAX_PLAN_BYTES if limit is None else limit
    if not 0 < limit <= MAX_PLAN_BYTES:
        raise UpgradeCliError("unsupported external file read limit")
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
            or before.st_size > limit
        ):
            raise UpgradeCliError("apply plan file identity or size is unsupported")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if len(raw) > limit:
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
    return raw


def _read_external_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_external_bytes(path)
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


def _emit_lf_preview_diagnostics(
    project_root: Path,
    preview: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    """Report attribute limits on stderr; stdout remains the exact plan JSON."""
    policy = preview.get("lf_policy")
    if not isinstance(policy, dict):
        return
    for line in naos_init.lf_policy_diagnostic_lines(policy):
        print(line, file=sys.stderr)
    rows = plan.get("paths") or plan.get("rows") or []
    row = next(
        (item for item in rows if item.get("path") == ".gitattributes"),
        None,
    )
    action = row.get("action") if isinstance(row, dict) else None
    if action in {"CREATE_NEW_UPSTREAM", "UPDATE_FROM_UPSTREAM"}:
        print(
            "LF_POLICY_PENDING_APPLY: effective Git attributes for the "
            "proposed generated policy require post-apply verification.",
            file=sys.stderr,
        )
        return
    effective_paths = list(policy.get("text_paths") or [])
    if policy.get("status") == "generated":
        effective_paths.append(".gitattributes")
    effective = naos_init.inspect_effective_lf_attributes(
        project_root, effective_paths,
    )
    for line in naos_init.lf_policy_diagnostic_lines(
        {"status": "checked", "omitted_text_paths": []}, effective,
    ):
        print(line, file=sys.stderr)


def _emit_lf_current_diagnostics(project_root: Path, policy: dict[str, Any]) -> None:
    """Report current attribute limits without changing a reviewed operation."""
    if not isinstance(policy, dict):
        return
    effective_paths = list(policy.get("text_paths") or [])
    if policy.get("status") == "generated":
        effective_paths.append(".gitattributes")
    effective = naos_init.inspect_effective_lf_attributes(project_root, effective_paths)
    for line in naos_init.lf_policy_diagnostic_lines(policy, effective):
        print(line, file=sys.stderr)


def _emit_managed_init_summary(*, requested_profile: str, status: str, plan_saved: bool = False) -> None:
    """Emit a bounded routing summary, never a replacement approval artifact."""
    if requested_profile not in {"quickstart", "lite", "standard", "assured"}:
        raise ValueError("Unsupported managed-init summary profile")
    if status not in {"plan_only", "no_changes", "diagnostic_only"}:
        raise ValueError("Unsupported managed-init summary status")
    print(json.dumps({
        "status": status,
        "requested_profile": requested_profile,
        "mutation_authorized": False,
        "plan_saved": plan_saved,
        "next_action": "Persist and review an external upgrade plan before digest-bound apply.",
    }, sort_keys=True, separators=(",", ":")))


def _plan_command(
    project_root: Path,
    *,
    requested_profile: str,
    plan_out: Path | None,
    summary_only: bool = False,
) -> int:
    summary_options = {"summary_only": True} if summary_only else {}
    if _v3_recovery_api().has_v3_control(project_root):
        return _v3_public_profile_api().plan_command(project_root, requested_profile=requested_profile,
                            plan_out=plan_out, cli=sys.modules[__name__], **summary_options)
    windows = naos_init._windows_cli()
    if windows is not None:
        return windows.plan_upgrade(project_root, requested_profile=requested_profile,
                                    plan_out=plan_out, **summary_options)
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
        _emit_lf_preview_diagnostics(project_root, preview, plan)
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
    if summary_only:
        _emit_managed_init_summary(requested_profile=requested_profile,
            status="diagnostic_only" if plan["status"] == "diagnostic_only" else "plan_only",
            plan_saved=plan_out is not None)
    else:
        emit_canonical_plan(payload)
    return 3 if plan["status"] == "diagnostic_only" else 0


def plan_profile_transition(
    project_root: Path,
    *,
    requested_profile: str,
    plan_out: Path | None = None,
    summary_only: bool = False,
) -> int:
    """Public in-process entry point for consumers that must use upgrade planning."""

    return _plan_command(
        _canonical_project_path(project_root),
        requested_profile=requested_profile,
        plan_out=plan_out,
        **({"summary_only": True} if summary_only else {}),
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
        or len(checks) != len(UPGRADE_CHECK_IDS)
        or any(not isinstance(check, dict) for check in checks)
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
        or not isinstance(checks[0], dict)
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
    public_rebind = _public_rebind_api()
    body, raw = public_rebind.read_external_plan(project_root, plan_path, cli=sys.modules[__name__])
    if body.get('schema') == _public_foreign_store_api().PLAN_SCHEMA:
        return _public_foreign_store_api().approved_command(project_root,raw=raw,expected_digest=expected_digest)
    if body.get("schema") in _public_migration_api().PLAN_SCHEMAS:
        raise UpgradeCliError("Exact migration plan requires --migration-inputs")
    if body.get("schema") == public_rebind.PLAN_SCHEMA:
        return public_rebind.apply_command(project_root, raw=raw, expected_digest=expected_digest,
                                           cli=sys.modules[__name__])
    if _v3_recovery_api().has_v3_control(project_root):
        return _v3_public_profile_api().apply_command(project_root, plan_path=plan_path,
                             expected_digest=expected_digest, cli=sys.modules[__name__])
    windows = naos_init._windows_cli()
    if windows is not None:
        return windows.apply_upgrade(project_root, plan_path=plan_path,
                                     expected_digest=expected_digest)
    plan, _raw = body, raw
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
    if is_profile_transition:
        policy = preview.get("lf_policy")
        _emit_lf_current_diagnostics(project_root, policy)
    return _emit_apply_outcome(outcome, expected_digest)


def _public_foreign_store_api():
    try:
        from .upgrade_contract import public_foreign_store
    except ImportError:
        from upgrade_contract import public_foreign_store
    return public_foreign_store


def _public_migration_api():
    try:
        from .upgrade_contract import public_migration
    except ImportError:
        from upgrade_contract import public_migration
    return public_migration


def _public_rebind_api():
    try:
        from .upgrade_contract import public_rebind
    except ImportError:
        from upgrade_contract import public_rebind
    return public_rebind


def _v3_public_profile_api():
    try:
        from .upgrade_contract import v3_public_profile
    except ImportError:
        from upgrade_contract import v3_public_profile
    return v3_public_profile


def _v3_recovery_api():
    try:
        from .upgrade_contract import v3_recovery
    except ImportError:
        from upgrade_contract import v3_recovery
    return v3_recovery


def _recover_command(project_root: Path) -> int:
    portable_recovery = _v3_recovery_api()
    if portable_recovery.has_v3_control(project_root):
        outcome = portable_recovery.recover_active_j2(project_root)
        print(json.dumps([outcome], sort_keys=True, separators=(",", ":")))
        return 0
    windows = naos_init._windows_cli()
    if windows is not None:
        return windows.recover(project_root)
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


def _inspect_provenance_command(project_root: Path) -> int:
    """Inspect portable consistency only; local ownership and mutation are separate."""
    if platform.system() == "Windows":
        try:
            from .upgrade_contract.portable_provenance_windows import read_portable_snapshot
        except ImportError:
            from upgrade_contract.portable_provenance_windows import read_portable_snapshot
        snapshot = read_portable_snapshot(str(project_root))
    elif platform.system() in {"Darwin", "Linux"}:
        try:
            from .upgrade_contract.portable_provenance_posix import read_portable_snapshot
        except ImportError:
            from upgrade_contract.portable_provenance_posix import read_portable_snapshot
        snapshot = read_portable_snapshot(project_root)
    else:
        raise UpgradeCliError("Portable provenance inspection requires macOS, Linux or Windows")
    print(json.dumps({
        "schema": "naos.upgrade.portable_inspection.v1",
        "status": "history_internally_consistent",
        "project_id": snapshot.project_id,
        "owner_sha256": snapshot.owner_sha256,
        "manifest_sha256": snapshot.manifest_sha256,
        "head_receipt_sha256": snapshot.head_receipt_sha256,
        "entry_count": len(snapshot.entries),
        "inputs": snapshot.inputs,
        "local_binding_status": "not_assessed",
        "working_tree_status": "not_assessed",
        "mutation_eligible": False,
        "authority": "Self-hashes establish internal consistency, not authorship or checkout ownership.",
    }, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    try:
        mode = _selected_mode(args)
        if mode == "inspect":
            # Native readers validate the supplied ancestor chain. Do not first
            # resolve symlinks and thereby erase the path that must be checked.
            return _inspect_provenance_command(args.project_path.expanduser().absolute())
        project_root = _canonical_project_path(args.project_path)
        if mode == 'plan_hook_activation':
            try:
                from .upgrade_contract import hook_activation
            except ImportError:
                from upgrade_contract import hook_activation
            return hook_activation.plan_command(project_root,
                approved_mode_octal=args.hook_mode_octal,
                expected_owner_sha256=args.expected_owner_sha256,
                expected_head_sha256=args.expected_head_sha256,
                plan_out=args.plan_out, cli=sys.modules[__name__])
        if mode == 'inspect_receiving':
            return _public_foreign_store_api().inspect_command(project_root)
        if mode == 'plan_receiving':
            return _public_foreign_store_api().plan_command(project_root,
                expected_owner_sha256=args.expected_owner_sha256,expected_head_sha256=args.expected_head_sha256,
                expected_inventory_sha256=args.expected_store_inventory_sha256,binding_id=args.binding_id,
                plan_out=args.plan_out,cli=sys.modules[__name__])
        if mode == 'recover_receiving':
            body,raw=_public_rebind_api().read_external_plan(project_root,args.apply_plan,cli=sys.modules[__name__])
            if body.get('schema')!=_public_foreign_store_api().PLAN_SCHEMA:
                raise UpgradeCliError('External receiving recovery refuses a different plan schema')
            return _public_foreign_store_api().approved_command(project_root,raw=raw,
                expected_digest=args.expect_plan_digest,recover=True)
        if mode == "plan_migration":
            return _public_migration_api().plan_command(project_root,
                inputs_path=args.migration_inputs, plan_out=args.plan_out, cli=sys.modules[__name__])
        if mode in {"apply_migration", "recover_migration"}:
            return _public_migration_api().approved_command(project_root,
                inputs_path=args.migration_inputs, plan_path=args.apply_plan,
                expected_digest=args.expect_plan_digest, recover=mode == "recover_migration",
                cli=sys.modules[__name__])
        if mode == "plan_rebind":
            return _public_rebind_api().plan_command(
                project_root, expected_owner_sha256=args.expected_owner_sha256,
                expected_head_sha256=args.expected_head_sha256, binding_id=args.binding_id,
                plan_out=args.plan_out, cli=sys.modules[__name__])
        if mode == "recover_rebind":
            return _public_rebind_api().recover_command(
                project_root, expected_digest=args.expect_plan_digest)
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
        prefix = "PROVENANCE_REFUSED" if args.inspect_provenance else "NOT_APPLIED"
        print(f"{prefix}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
