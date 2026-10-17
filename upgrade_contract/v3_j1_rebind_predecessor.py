"""Held, read-only J1 absent-store-rebind predecessor inspection for a J2 plan.

This deliberately supports one terminal variant. No journal creation or state
replacement occurs here. Other J1 variants and any J2+ history refuse.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from . import joint_capture as joint
from . import local_binding as lb, local_store as ls, portable_provenance as pp
from . import rebind_records as rebind
from . import rebind_store_inspection as ris
from . import v3_operation_custody as custody_api
from . import v3_operation_records as op

ROOT = ris.ROOT
JOURNAL = ROOT + '/journals/J00000001'
PROGRESS = JOURNAL + '/progress'
STATE = ROOT + '/state.json'
BINDING = ROOT + '/binding.json'
TERMINAL = JOURNAL + '/terminal.json'
PLAN = JOURNAL + '/plan.json'
INTENT = JOURNAL + '/intent.json'
MAX_PROGRESS = 10


class J1PredecessorError(ValueError):
    pass


def _fail(message):
    raise J1PredecessorError(message)


@dataclass(frozen=True)
class J1RebindPredecessor:
    approved_next_plan_sha256: str
    prior_history_sha256: str
    prior_intent_sha256: str
    prior_binding_sha256: str
    prior_store_sha256: str
    portable_head_sha256: str
    captured_working_sha256: str
    journal_ids: tuple[str, ...] = ('J00000001',)
    mutation_authorized: bool = False


def _semantic_j1(raw: dict[str, bytes], portable):
    """Validate every immutable J1 record and terminal checkpoint semantics."""
    if type(raw) is not dict or type(portable) is not pp.ValidatedPortableSnapshot:
        _fail('Exact J1 bytes and validated portable replay required')
    fixed = {PLAN, INTENT, TERMINAL, STATE, BINDING}
    progress_paths = sorted(path for path in raw if path.startswith(PROGRESS + '/'))
    if (not 1 <= len(progress_paths) <= MAX_PROGRESS or
            progress_paths != [PROGRESS + f'/{index:08d}.json' for index in range(len(progress_paths))] or
            set(raw) != fixed | set(progress_paths)):
        _fail('Missing, extra or reordered J1 immutable history')
    plan = rebind.load_rebind_plan(raw[PLAN], portable)
    intent = rebind.load_rebind_intent(raw[INTENT], plan, portable,
                                       approved_plan_sha256=plan.sha256)
    if intent.body['variant'] != rebind.VARIANT:
        _fail('Unsupported J1 terminal variant')
    progress = tuple(rebind.load_rebind_progress(raw[path], intent, plan, portable)
                     for path in progress_paths)
    history = rebind.validate_progress_history(progress, intent, plan, portable)
    if progress[-1].body['phase'] != 'finalized':
        _fail('J1 is not a completed bound rebind')
    state = ls.load_local_store(raw[STATE])
    terminal = ls.load_local_terminal(raw[TERMINAL])
    binding = lb.load_local_binding(raw[BINDING])
    rebind.validate_checkpoint_records(state, terminal, binding, history,
                                       intent, plan, portable)
    if (terminal.body['outcome'] != 'committed' or
            state.body['active_journal_id'] is not None or
            state.body['archives'] or
            binding.body['portable_head_sha256'] != portable.manifest_sha256):
        _fail('J1 terminal is not a quiescent bound rebind')
    return plan, intent, history, state, binding


def _exact_names(native):
    if native.children(ROOT) != {'scope.lock', 'journals', 'state.json', 'binding.json'}:
        _fail('Local root has missing, pending or foreign records')
    if native.children(ROOT + '/journals') != {'J00000001'}:
        _fail('This inspector supports exact J1 predecessor history only')
    if native.children(JOURNAL) != {'plan.json', 'intent.json', 'progress', 'terminal.json'}:
        _fail('J1 has missing, pending or foreign records')
    names = native.children(PROGRESS)
    if (not 1 <= len(names) <= MAX_PROGRESS or
            names != {f'{index:08d}.json' for index in range(len(names))}):
        _fail('J1 progress history is incomplete or aliased')
    return tuple(PROGRESS + '/' + name for name in sorted(names))


def _read_complete(native, progress_paths):
    paths = (PLAN, INTENT, *progress_paths, TERMINAL, STATE, BINDING)
    return {path: native.read(path) for path in paths}


def inspect_j1_rebind_predecessor(project_root: Path | str, *,
                                   next_plan: op.ValidatedOperationPlan,
                                   expected_plan_sha256: str,
                                   plan_evidence: dict[str, Any], handles=None) -> J1RebindPredecessor:
    """Prove an exact completed J1 rebind under the same lock as a J2 plan read.

    Historical bytes/terminal semantics are validated independently of current
    working leaves, which may contain adopter edits. The current joint capture,
    supplied portable bytes and predecessor file witnesses must still match the
    explicitly approved next plan. Return detached facts, not a mutation token.
    """
    try:
        lb._hex(expected_plan_sha256, lb.HEX64, 'next approved plan digest')
        if type(next_plan) is not op.ValidatedOperationPlan or next_plan.sha256 != expected_plan_sha256:
            _fail('Explicit next plan digest differs')
        op._verified_plan(next_plan, plan_evidence)
        for path in plan_evidence['portable_files']:
            pp.control_path_limit(path)
        extras = tuple(sorted(plan_evidence['requested']))
        windows = handles is not None or os.name == 'nt'
        with custody_api._held_operation_store(project_root,
                journal_ids=('J00000001',), handles=handles) as custody:
            context = (joint._held_windows(str(project_root), extras, handles) if windows
                       else joint._held_posix(Path(project_root), extras))
            with context as held:
                # Custody's POSIX wrapper pins only fixed directories; its
                # underlying contained reader supplies complete enumeration.
                # Reuse the same held lock and pins without treating that
                # wrapper's ordered JID argument as history proof.
                local_reader = custody.reader if windows else custody.reader.reader
                native = ris._NativeStore(SimpleNamespace(working_reader=local_reader), windows)
                native.lock_handle = custody.lock_handle
                native.lock_witness = custody.lock_witness
                progress_paths = _exact_names(native)
                raw = _read_complete(native, progress_paths)
                plan, intent, history, state, binding = _semantic_j1(raw, held.result.portable)
                if native.observations[BINDING]['metadata'] != history.records[-1].body['publication_witness']:
                    _fail('Current binding differs from the witnessed J1 publication')
                if (native.lock_witness != intent.body['storage_witnesses']['lock'] or
                        native.directory(JOURNAL) != intent.body['storage_witnesses']['journal']):
                    _fail('J1 native lock or journal witness differs from immutable intent')
                legacy = (held.working_reader.directory_witness('.naos/upgrade-v1') if windows
                          else held.working_reader.directory('.naos/upgrade-v1'))
                if legacy['presence'] != 'absent':
                    _fail('Legacy control state appeared after rebind')
                if (raw[STATE] != plan_evidence['predecessor_store'].raw or
                        raw[BINDING] != plan_evidence['predecessor_binding'].raw or
                        held.result.working_tree != plan_evidence['capture']):
                    _fail('Current checkpoint or working capture differs from next plan')
                witnesses = plan_evidence['predecessor_record_witnesses']
                if (native.observations[STATE]['metadata'] != witnesses['state'] or
                        native.observations[BINDING]['metadata'] != witnesses['binding']):
                    _fail('Predecessor record native identity differs from approved plan')
                supplied = plan_evidence['portable_files']
                if type(supplied) is not dict or any(type(path) is not str or type(data) is not bytes
                                                     for path, data in supplied.items()):
                    _fail('Exact supplied portable bytes required')
                for path, expected in supplied.items():
                    if held.portable_reader.read(path) != expected:
                        _fail('Portable native bytes differ from next plan replay')
                if (binding.sha256 != next_plan.body['prior_binding_sha256'] or
                        state.sha256 != next_plan.body['prior_store_sha256']):
                    _fail('J1 checkpoint differs from approved next plan')
                # Re-open every immutable record, rather than trusting this
                # reader's cache, and compare both bytes and native identities.
                fresh = ris._NativeStore(SimpleNamespace(working_reader=local_reader), windows)
                for path, expected in raw.items():
                    if fresh.read(path) != expected or fresh.observations[path] != native.observations[path]:
                        _fail('Immutable J1 record changed or was substituted')
                for directory in (ROOT, ROOT + '/journals', JOURNAL, PROGRESS):
                    native.children(directory, final=True)
                custody.check_lock()
                held.portable_reader.revalidate()
                return J1RebindPredecessor(expected_plan_sha256, history.sha256,
                    intent.sha256, binding.sha256, state.sha256,
                    held.result.portable.manifest_sha256, held.result.working_tree.sha256)
    except J1PredecessorError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError, RecursionError) as exc:
        raise J1PredecessorError(f'J1 predecessor inspection refused: {exc}') from exc
