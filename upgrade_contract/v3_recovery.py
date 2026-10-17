"""Public recovery dispatch for the explicitly replay-bound J1-to-J2 variant.

Namespace detection grants no authority. Every operation reopens and validates
the private records and native ownership under its existing lock.
"""
from __future__ import annotations

from pathlib import Path
import stat

from . import portable_provenance as portable
from . import rebind_store_inspection as store


def _present(root: Path, relative: str) -> bool:
    """Observe a fixed namespace without following ancestor links or reparses."""
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            observed = current.lstat()
        except FileNotFoundError:
            return False
        # A malformed final object is present and belongs to the refusing v3
        # reader. A malformed ancestor must not conceal a v3 namespace.
        if index < len(parts) - 1 and (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or getattr(observed, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError("Unsupported ancestor of managed v3 control storage")
    return True


def has_v3_control(project_root: Path | str) -> bool:
    """Absence routing hint only; present/torn/foreign v3 never routes to v1."""
    root = Path(project_root)
    return _present(root, store.ROOT) or _present(root, portable.ROOT)


def recover_active_j2(project_root: Path | str) -> dict:
    """Rollback before the head boundary; finish forward after it.

An existing checkpoint supplies its own recorded outcome. Missing or malformed
private replay data refuses; recovery never rerenders using the current kit.
"""
    from . import v3_durable_replay as replay
    from . import v3_j2_registration as registration
    from . import v3_publication_stage as staging
    from . import v3_j2_publication as publication
    from . import v3_j2_checkpoint as checkpoint

    root = Path(project_root)
    recovered = replay.load_active_j2(root)
    from .v3_operation_context import for_plan
    context = for_plan(recovered.plan)
    arguments = {
        "plan": recovered.plan,
        "expected_plan_sha256": recovered.plan.sha256,
        "plan_evidence": recovered.evidence,
        "program": recovered.program,
        "expected_program_sha256": recovered.program.sha256,
    }
    if not _present(root, context.checkpoint.CHECKPOINT):
        if not _present(root, context.staging.PUBLICATION):
            registration.register_j2_rebind_successor(
                root,
                plan=recovered.plan,
                expected_plan_sha256=recovered.plan.sha256,
                plan_evidence=recovered.evidence,
            )
            staging.stage_j2_publication(root, **arguments)
        if not _present(root, context.publication.DIRECTORY_COMMITMENT):
            publication.prepare_j2_directories(root, **arguments)
        inspected = publication.inspect_j2_destinations(root, **arguments)
        publication.publish_j2_destinations(
            root, rollback=not inspected.head_installed, **arguments
        )
    result = checkpoint.complete_j2_checkpoint(root, **arguments)
    if not result.complete:
        raise ValueError("Managed v3 recovery did not complete its checkpoint")
    return {
        "status": result.outcome,
        "transaction_id": recovered.program.body["journal_id"],
        "receipt_path": None,
        "detail": "Validated private replay and native terminal checkpoint",
    }
