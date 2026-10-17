"""Structural terminal-journal proof for an approved POSIX legacy archive.

The caller supplies a complete selected-scope path inventory from a later
native capture. This module cannot establish its completeness or custody.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import legacy_migration_records as migration
from . import legacy_posix_replay as replay
from . import planner, transaction, windows_provenance
from .canonical import loads_strict_json

_SCOPE = '.naos/upgrade-v1/managed-content/'
_SCOPE_ROOT = _SCOPE[:-1]
_TRANSACTIONS = _SCOPE + 'transactions/'
_TRANSACTIONS_ROOT = _TRANSACTIONS[:-1]
_RECEIPTS = _SCOPE + 'state/receipts/'
_LOCK = _SCOPE + 'lock'
_EMPTY_TERMINAL_DIRECTORIES = {
    _SCOPE_ROOT, _SCOPE + 'state', _SCOPE + 'state/bases',
    _SCOPE + 'state/receipts', _TRANSACTIONS_ROOT,
}
_MAX_JOURNALS = 256
_MAX_JOURNAL_BYTES = 64 * 1024 * 1024
_MAX_RECORD = 16 * 1024 * 1024


class LegacyPosixTerminalError(ValueError):
    """Archived terminal journal evidence is incomplete or inconsistent."""


@dataclass(frozen=True)
class TerminalTransaction:
    transaction_id: str
    state: str
    version: str
    journal_path: str


@dataclass(frozen=True)
class LegacyPosixTerminal:
    replay: replay.LegacyPosixReplay
    transactions: tuple[TerminalTransaction, ...]
    checked_paths: tuple[str, ...]
    native_custody_proven: bool = False
    quiescence_proven: bool = False
    mutation_authorized: bool = False


def _inventory(directory_paths: object, archive: dict[str, bytes]) -> tuple[str, ...]:
    if (type(directory_paths) not in (tuple, list) or not directory_paths
            or len(directory_paths) > 1024):
        raise LegacyPosixTerminalError('Complete bounded selected-scope path inventory is required')
    paths = tuple(directory_paths)
    if (any(type(path) is not str for path in paths)
            or paths != tuple(sorted(set(paths))) or _SCOPE_ROOT not in paths):
        raise LegacyPosixTerminalError('Selected-scope directories must be unique, sorted and include scope root')
    for path in paths:
        if path != _SCOPE_ROOT:
            migration._path(path, migration.POSIX_MANAGED_V1)
        if path != _SCOPE_ROOT and not path.startswith(_SCOPE):
            raise LegacyPosixTerminalError('Inventory path is outside selected scope')
    directories = set(paths)
    if directories & set(archive):
        raise LegacyPosixTerminalError('A source path is both a directory and archived file')
    # Capture returns directory keys only. Require every archived scope leaf's
    # ancestry, including the scope root, in that independently supplied set.
    ancestors = {_SCOPE_ROOT}
    for leaf in archive:
        if not leaf.startswith(_SCOPE):
            continue
        parent = leaf.rpartition('/')[0]
        while parent.startswith(_SCOPE_ROOT):
            ancestors.add(parent)
            if parent not in directories:
                raise LegacyPosixTerminalError('Archived leaf lacks a captured directory ancestor')
            if parent == _SCOPE_ROOT:
                break
            parent = parent.rpartition('/')[0]
    if directories - ancestors - _EMPTY_TERMINAL_DIRECTORIES:
        raise LegacyPosixTerminalError('Unknown selected-scope directory residue')
    return paths


def validate_posix_terminal_archive(archive_bytes, lineage, *, directory_paths,
                                    **replay_args) -> LegacyPosixTerminal:
    """Replay committed source, then verify all selected terminal journals.

    `directory_paths` is an externally captured, complete directory-only set.
    Archived bytes provide the file paths. This function does
    not observe the filesystem and grants no mutation authority.
    """
    try:
        if type(archive_bytes) is not dict:
            raise LegacyPosixTerminalError('Exact archived byte dictionary is required')
        archive = dict(archive_bytes)
        proven = replay.replay_posix_archive(archive, lineage, **replay_args)
        paths = _inventory(directory_paths, archive)
        manifest_path = migration._ANCHORS[migration.POSIX_MANAGED_V1]['head']
        manifest = loads_strict_json(archive[manifest_path])
        references = {ref['transaction_id']: ref['plan'] for ref in manifest['transactions']}
        source_raw = replay_args['source_policy_raw']
        policy_value = windows_provenance.strict_policy_load(source_raw)
        enrolled_digest = manifest['source_policy_sha256']
        policies = {}
        policy_work = 0

        def policy_for(digest):
            nonlocal policy_work
            migration._digest(digest, 'journal source policy')
            if digest not in policies:
                policy_work += len(source_raw)
                if policy_work > replay.MAX_POLICY_WORK_BYTES:
                    raise LegacyPosixTerminalError('Historical journal policy replay exceeds byte budget')
                policies[digest] = planner._source_policy_snapshot_from_value(
                    policy_value, source_raw, expected_sha256=digest)
            return policies[digest]

        def validate_plan(plan):
            if type(plan) is not dict or replay._root_text(plan) != proven.historical_root:
                raise LegacyPosixTerminalError('Journal historical root binding differs')
            schema = plan.get('schema')
            if schema in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
                if plan.get('status') != 'ready_create_only' or plan.get('source_policy_sha256') != enrolled_digest:
                    raise LegacyPosixTerminalError('Journal create-only status or policy differs')
                policy_for(enrolled_digest)
                planner._validate_create_only_plan_record(plan, root_binding=proven.historical_root)
            elif schema in planner.CONTENT_AWARE_PLAN_SCHEMAS:
                if plan.get('status') != 'ready':
                    raise LegacyPosixTerminalError('Journal content-aware plan is not ready')
                planner._validate_content_aware_plan_record(plan, root_binding=proven.historical_root)
                bindings = plan['source_policy']
                if bindings['provenance']['binding_sha256'] != enrolled_digest:
                    raise LegacyPosixTerminalError('Journal provenance policy differs')
                for role in ('active', 'provenance'):
                    binding = bindings[role]
                    selected = policy_for(binding['binding_sha256'])
                    if (binding['snapshot_id'] != selected.snapshot_id
                            or binding['snapshot_sha256'] != selected.snapshot_sha256):
                        raise LegacyPosixTerminalError('Journal policy snapshot differs')
            else:
                raise LegacyPosixTerminalError('Unsupported journal plan schema')

        tx_paths = [path for path in paths if path == _TRANSACTIONS_ROOT or path.startswith(_TRANSACTIONS)]
        transaction_leaves = [path for path in archive if path.startswith(_TRANSACTIONS)]
        journal_paths = [path for path in transaction_leaves if path.endswith('/journal.json')]
        if len(journal_paths) > _MAX_JOURNALS:
            raise LegacyPosixTerminalError('Terminal journal count exceeds budget')
        total = 0
        checked = set()
        terminals = []
        for path in sorted(journal_paths):
            parts = path[len(_TRANSACTIONS):].split('/')
            if (len(parts) != 2 or parts[1] != 'journal.json'
                    or transaction.TRANSACTION_ID_RE.fullmatch(parts[0]) is None):
                raise LegacyPosixTerminalError('Unknown or preparing transaction inventory')
            txid = parts[0]
            raw = archive[path]
            total += len(raw)
            if type(raw) is not bytes or len(raw) > _MAX_RECORD or total > _MAX_JOURNAL_BYTES:
                raise LegacyPosixTerminalError('Terminal journal byte budget exceeded')
            journal = loads_strict_json(raw)
            if type(journal) is not dict or journal.get('transaction_id') != txid:
                raise LegacyPosixTerminalError('Transaction directory and journal differ')
            schema = journal.get('schema')
            if schema == 'naos.upgrade.create_only_transaction.v1':
                plan = transaction._validate_journal_record(journal, validate_plan=validate_plan)
                version = 'v1'
            elif schema == 'naos.upgrade.content_transaction.v2':
                plan = transaction._validate_journal_v2_record(journal, validate_plan=validate_plan)
                version = 'v2'
            elif schema == transaction._COMPACT_JOURNAL_SCHEMA:
                sidecar_path = _TRANSACTIONS + txid + '/' + transaction._COMPACT_PLAN_NAME
                plan_raw = archive.get(sidecar_path)
                if type(plan_raw) is not bytes or len(plan_raw) > _MAX_RECORD:
                    raise LegacyPosixTerminalError('Compact plan sidecar missing or over budget')
                total += len(plan_raw)
                if total > _MAX_JOURNAL_BYTES:
                    raise LegacyPosixTerminalError('Terminal journal byte budget exceeded')
                plan = transaction._validate_compact_journal_record(
                    journal, plan_raw, validate_plan=validate_plan)
                version = 'compact_v1'
                checked.add(sidecar_path)
            else:
                raise LegacyPosixTerminalError('Unsupported terminal journal schema')
            state = journal['state']
            if state not in ('COMMITTED', 'ROLLED_BACK'):
                raise LegacyPosixTerminalError('Unfinished transaction journal requires recovery')
            if state == 'COMMITTED':
                if references.get(txid) != plan:
                    raise LegacyPosixTerminalError('Committed journal plan differs from manifest')
            elif txid in references or _RECEIPTS + txid + '.json' in archive:
                raise LegacyPosixTerminalError('Rolled-back journal has conflicting commit evidence')
            terminals.append(TerminalTransaction(txid, state, version, path))
            checked.add(path)
        if set(transaction_leaves) - checked:
            raise LegacyPosixTerminalError('Unknown or unreferenced transaction leaf residue')
        allowed_dirs = {_TRANSACTIONS_ROOT} | {_TRANSACTIONS + item.transaction_id for item in terminals}
        if set(tx_paths) != allowed_dirs:
            raise LegacyPosixTerminalError('Unknown transaction directory residue')
        if {item.transaction_id for item in terminals if item.state == 'COMMITTED'} != set(references):
            raise LegacyPosixTerminalError('Committed journal coverage differs from manifest')
        if not terminals:
            raise LegacyPosixTerminalError('No terminal journals')
        if archive.get(_LOCK) != b'':
            raise LegacyPosixTerminalError('Legacy scope lock bytes differ')
        known_leaves = set(proven.actually_read_source_paths) | checked | {_LOCK}
        if set(archive) - known_leaves:
            raise LegacyPosixTerminalError('Unknown or pending archived control leaf residue')
        return LegacyPosixTerminal(proven, tuple(terminals), tuple(sorted(checked)))
    except LegacyPosixTerminalError:
        raise
    except (replay.LegacyPosixReplayError, migration.LegacyMigrationRecordError,
            transaction.TransactionPrimitiveError, planner.ContentPlanningError,
            windows_provenance.WindowsProvenanceError, TypeError, KeyError, ValueError,
            AttributeError, OverflowError, RecursionError) as exc:
        raise LegacyPosixTerminalError(f'Legacy POSIX terminal validation refused: {exc}') from exc
