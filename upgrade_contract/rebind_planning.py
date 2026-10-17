"""Native read-only planning for the existing absent-store rebind contract.

A returned plan binds portable history and current managed bytes to this checkout;
it is not local enrollment, ownership proof, a lock, or permission to mutate.
Both native readers stay open through legacy absence observation and plan
construction, and revalidate before the plan can escape to its caller.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import joint_capture as joint
from . import local_binding as binding
from . import rebind_records as records
from .canonical import canonical_bytes
from .portable_provenance import PortableProvenanceError
from .working_tree_capture import WorkingTreeCaptureError

LEGACY_ROOT = '.naos/upgrade-v1'


class RebindPlanningError(ValueError):
    """The current native checkout cannot support this rebind plan."""


def plan_absent_store_rebind(
    project_root: Path | str, *, expected_owner_sha256: str,
    expected_head_sha256: str, binding_id: str, handles: Any = None,
) -> records.ValidatedRebindPlan:
    """Observe, construct and revalidate an explicit checkout-bound rebind plan.

    The caller supplies independently selected expected history digests and a
    new binding ID. This does not authenticate those digests. Existing local or
    legacy state refuses this variant; no directory, record or lock is created.
    Adopter edits/deletions remain captured exactly, never rewritten to a base.
    Explicit ``handles`` selects the injectable Windows reader on any host.
    """
    try:
        # Refuse malformed public inputs before native I/O.
        binding._hex(expected_owner_sha256, binding.HEX64, 'expected portable owner')
        binding._hex(expected_head_sha256, binding.HEX64, 'expected portable head')
        binding._hex(binding_id, binding.BINDING_ID, 'new binding ID')
        windows = handles is not None or os.name == 'nt'
        held_context = (joint._held_windows(str(project_root), (), handles) if windows
                        else joint._held_posix(Path(project_root), ()))
        with held_context as held:
            capture = held.result.working_tree
            reader = held.working_reader
            witness = (reader.directory_witness(LEGACY_ROOT) if windows
                       else reader.directory(LEGACY_ROOT))
            if witness['presence'] != 'absent':
                raise RebindPlanningError('Legacy control state exists; explicit migration is required')
            legacy = records.load_absent_legacy(canonical_bytes({
                'schema': records.LEGACY_SCHEMA,
                'path': LEGACY_ROOT,
                'parent_witness': capture.body['native']['control_directories'][0]['witness'],
                'witness': witness,
            }), capture)
            plan = records.build_rebind_plan(
                held.result, expected_owner_sha256=expected_owner_sha256,
                expected_head_sha256=expected_head_sha256, binding_id=binding_id,
                legacy_absence=legacy,
            )
        # Exiting the context rechecks history, leaves and observed namespaces.
        return plan
    except RebindPlanningError:
        raise
    except (PortableProvenanceError, WorkingTreeCaptureError, joint.JointCaptureError,
            OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        raise RebindPlanningError(f'Native absent-store rebind planning refused: {exc}') from exc
