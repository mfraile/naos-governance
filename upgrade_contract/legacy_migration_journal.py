"""Initial migration journal records; no namespace transition is authorized here.

A complete prepared record binds actually created private storage to an approved
plan. Staging, original-pointer retention and publication need further witnessed
records; byte equality alone never establishes ownership for cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import legacy_migration_plan_records as plans
from . import local_binding as lb
from . import portable_provenance as pp
from . import rebind_records as rebind
from .canonical import canonical_bytes
from .working_tree_capture import WorkingTreeCapture, build_capture

INTENT_SCHEMA = 'naos.upgrade.legacy_migration_intent.v1'
PROGRESS_SCHEMA = 'naos.upgrade.legacy_migration_progress.v1'
JOURNAL_ID = 'J00000001'
_INTENT_KEYS = {'schema', 'journal_id', 'plan_sha256', 'approved_plan_sha256',
                'failure_model', 'prepared_capture', 'storage_witnesses', 'legacy_lock'}


class MigrationJournalError(ValueError):
    """The initial private journal is incomplete, foreign or unsupported."""


@dataclass(frozen=True)
class MigrationIntent:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, 'migration intent')


def _plan(plan, projection_files, lineage, expected):
    if (type(plan) is not plans.ValidatedMigrationPlan or plan.sha256 != expected
            or plans.load_migration_plan(plan.raw, projection_files, lineage) != plan):
        raise MigrationJournalError('Exact approved migration plan is required')
    return plan.body


def _prepared(body, planned):
    lb._fields(body, {'schema', 'native', 'leaves'}, 'prepared migration capture')
    checked = build_capture(body['native'], body['leaves'])
    if canonical_bytes(checked.body) != canonical_bytes(body):
        raise MigrationJournalError('Prepared migration capture differs')
    # Shared shape-only check: unchanged roots/managed leaves, and newly present
    # planned local controls. It performs no absent-legacy or enrollment check.
    rebind._validate_prepared(planned['initial_capture'], checked.body)
    return checked


def _storage(witnesses, prepared, legacy_lock):
    lb._fields(witnesses, {'lock', 'journal', 'progress'}, 'migration storage witnesses')
    native = prepared.body['native']
    platform = native['platform']
    selected = [row['witness'] for row in native['control_directories'][1:]]
    for name, kind in (('lock', 'file'), ('journal', 'directory'), ('progress', 'directory')):
        lb._validate_witness(witnesses[name], platform, kind)
        selected.append(witnesses[name])
    owner = legacy_lock['witness']
    volume = 'volume_serial_hex' if platform == 'Windows' else 'device_decimal'
    identities = set()
    for w in selected:
        if w['presence'] != 'present' or w[volume] != owner[volume]:
            raise MigrationJournalError('Prepared private storage absent or on another volume')
        identity = (w[volume], w['file_id_hex'] if platform == 'Windows' else w['inode_decimal'])
        if identity in identities:
            raise MigrationJournalError('Prepared storage identities alias')
        identities.add(identity)
        if platform == 'Windows':
            security = w['security']
            if not security['dacl_protected'] or any(
                    security[key] != owner['security'][key]
                    for key in ('owner_sid_sha256', 'group_sid_sha256', 'dacl_sha256')):
                raise MigrationJournalError('Prepared Windows storage is not privately owned')
        elif (w['mode_octal'] != ('0600' if w['kind'] == 'file' else '0700')
              or w['acl_entries'] or any(w[k] != owner[k] for k in ('uid_decimal', 'gid_decimal'))):
            raise MigrationJournalError('Prepared POSIX storage is not privately owned')


def load_migration_intent(raw, plan, projection_files, lineage, *, approved_plan_sha256):
    try:
        planned = _plan(plan, projection_files, lineage, approved_plan_sha256)
        if type(raw) is not bytes or len(raw) > lb.MAX_RECORD_BYTES:
            raise MigrationJournalError('Missing or oversized migration intent')
        body = pp._load_json(raw, 'migration intent')
        lb._bounded_input(body)
        lb._fields(body, _INTENT_KEYS, 'migration intent')
        if (body['schema'] != INTENT_SCHEMA or body['journal_id'] != JOURNAL_ID
                or body['plan_sha256'] != plan.sha256 or body['approved_plan_sha256'] != plan.sha256
                or body['failure_model'] != 'application_interruption_v1'
                or canonical_bytes(body['legacy_lock']) != canonical_bytes(planned['legacy_lock'])
                or canonical_bytes(body) != raw):
            raise MigrationJournalError('Migration intent differs from approved plan or lock')
        prepared = _prepared(body['prepared_capture'], planned)
        _storage(body['storage_witnesses'], prepared, body['legacy_lock'])
        return MigrationIntent(raw, hashlib.sha256(raw).hexdigest())
    except MigrationJournalError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        raise MigrationJournalError(f'Migration intent refused: {exc}') from exc


def build_migration_intent(plan, projection_files, lineage, prepared_capture, *,
                           approved_plan_sha256, storage_witnesses, legacy_lock):
    if (type(prepared_capture) is not WorkingTreeCapture
            or type(prepared_capture.raw) is not bytes or len(prepared_capture.raw) > lb.MAX_RECORD_BYTES
            or hashlib.sha256(prepared_capture.raw).hexdigest() != prepared_capture.sha256):
        raise MigrationJournalError('Typed exact prepared capture required')
    body = {'schema': INTENT_SCHEMA, 'journal_id': JOURNAL_ID, 'plan_sha256': plan.sha256,
            'approved_plan_sha256': approved_plan_sha256, 'failure_model': 'application_interruption_v1',
            'prepared_capture': prepared_capture.body, 'storage_witnesses': storage_witnesses,
            'legacy_lock': legacy_lock}
    lb._bounded_input(body)
    return load_migration_intent(canonical_bytes(body), plan, projection_files, lineage,
                                 approved_plan_sha256=approved_plan_sha256)


def initial_progress(intent):
    """Deterministic initial checkpoint; cannot stand in for later transitions."""
    if (type(intent) is not MigrationIntent or type(intent.raw) is not bytes
            or len(intent.raw) > lb.MAX_RECORD_BYTES
            or hashlib.sha256(intent.raw).hexdigest() != intent.sha256):
        raise MigrationJournalError('Exact typed intent required')
    return canonical_bytes({'schema': PROGRESS_SCHEMA, 'journal_id': JOURNAL_ID,
                            'intent_sha256': intent.sha256, 'sequence': 0,
                            'previous_sha256': None, 'phase': 'prepared'})
