"""Explicit public adapter for the qualified absent-store receiving lifecycle.

Approval comes from the caller's selected raw plan digest. Persisted records
never grant approval, and existing storage never falls through to enrollment.
The adapter adds no native filesystem primitives or renderer dependencies.
"""
from __future__ import annotations

import hashlib
import json
import sys

from .plan_stdout import emit_canonical_plan
from .canonical import canonical_bytes
from . import joint_capture, rebind_records as records
from . import rebind_planning as planning, rebind_preparation as preparation
from . import rebind_candidate as candidate, rebind_publication as publication
from . import rebind_checkpoint as checkpoint, rebind_rollback as rollback
from . import rebind_store_inspection as inspection

PLAN_SCHEMA = records.PLAN_SCHEMA


def read_external_plan(root, path, *, cli):
    windows = cli.naos_init._windows_cli()
    if windows is not None:
        body = windows.read_external_plan(root, path)
        return body, canonical_bytes(body)
    return cli._read_external_plan(cli._external_plan_path(root, path, must_exist=True))


def plan_command(root, *, expected_owner_sha256, expected_head_sha256,
                 binding_id, plan_out, cli):
    plan = planning.plan_absent_store_rebind(
        root, expected_owner_sha256=expected_owner_sha256,
        expected_head_sha256=expected_head_sha256, binding_id=binding_id)
    if plan_out is not None:
        windows = cli.naos_init._windows_cli()
        if windows is not None:
            windows.publish_external_plan(root, plan_out, plan.body)
        else:
            cli._publish_external_plan(
                cli._external_plan_path(root, plan_out, must_exist=False), plan.raw)
    emit_canonical_plan(plan.raw)
    print("PLAN_ONLY: explicit receiving rebind; raw plan SHA-256 " + plan.sha256,
          file=sys.stderr)
    return 0


def _emit(result):
    print(json.dumps({
        "status": result.recovery_action, "phase": result.phase,
        "transaction_id": records.JOURNAL_ID, "plan_sha256": result.plan_sha256,
        "portable_head_sha256": result.portable_head_sha256,
        "binding_sha256": result.binding_sha256,
        "changed_working_paths": list(result.changed_working_paths),
    }, sort_keys=True, separators=(",", ":")))
    return 0


def apply_command(root, *, raw, expected_digest, cli):
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("Exact raw approved receiving plan digest differs")
    captured = joint_capture.capture_portable_working_tree(root)
    plan = records.load_rebind_plan(raw, captured.portable)
    # Classify refusal before the mutation attempt; preparation repeats this
    # qualification and rechecks native witnesses around recorded transitions.
    preparation._preflight(root, plan, expected_digest, None)
    # Preparation performs its own native absence/capture revalidation. An
    # existing or interrupted store requires explicit persisted-record recovery.
    try:
        preparation.prepare_absent_store_rebind(root, plan=plan,
                                                expected_plan_sha256=expected_digest)
        candidate.stage_prepared_rebind(root, expected_plan_sha256=expected_digest)
        publication.publish_prepared_rebind(root, expected_plan_sha256=expected_digest)
        result = checkpoint.complete_published_rebind(root, expected_plan_sha256=expected_digest)
    except (OSError, RuntimeError, ValueError) as exc:
        # Preparation may have created partial records; retain them unchanged.
        print(json.dumps({"status": "recovery_required", "plan_sha256": expected_digest,
            "detail": "Receiving apply refused or interrupted; inspect preserved state with "
                      "--recover --expect-plan-digest " + expected_digest + ": " + str(exc)},
            sort_keys=True, separators=(",", ":")))
        return 3
    return _emit(result)


def recover_command(root, *, expected_digest):
    # Inspection binds the explicit external approval to complete native saved
    # plan/intent/progress. A self-declared on-disk digest is never selected.
    result = inspection.inspect_absent_store_rebind(root, expected_plan_sha256=expected_digest)
    if result.recovery_action in {"complete", "rolled_back"}:
        return _emit(result)
    if result.recovery_action not in {"forward_completion_required", "rollback_required"}:
        raise ValueError("Unsupported receiving rebind recovery state")
    try:
        if result.recovery_action == "forward_completion_required":
            result = checkpoint.complete_published_rebind(root, expected_plan_sha256=expected_digest)
        else:
            result = rollback.rollback_prepublication_rebind(root, expected_plan_sha256=expected_digest)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "recovery_required", "plan_sha256": expected_digest,
            "detail": "Receiving recovery mutation was attempted; preserve state and retry "
                      "--recover --expect-plan-digest " + expected_digest + ": " + str(exc)},
            sort_keys=True, separators=(",", ":")))
        return 3
    return _emit(result)
