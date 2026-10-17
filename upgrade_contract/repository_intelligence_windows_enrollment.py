"""RI-only native enrollment component; public lifecycle integration is pending.

One immutable record carries both owner and scope, avoiding split publication.
Hashes are consistency checks, not authentication. The public caller must still
validate its source/rules/profile/reviewer contract before invoking this API.
Neither this record nor managed-content enrollment authorizes RI activation.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import ExitStack
import hashlib
from pathlib import Path
import re
import sys
from typing import Any
import uuid

from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .repository_intelligence_windows import NativeIdentity, RIStorageConflict, WindowsRIStorage

PLAN_SCHEMA = 'naos.repository_intelligence.windows_enrollment_plan.v1'
SCOPE_SCHEMA = 'naos.repository_intelligence.windows_enrollment.v1'
RECORD_PATH = '.naos/upgrade-v1/windows-repository-intelligence.json'
GOVERNED_ROOT = '.naos/upgrade-v1/state/repository-intelligence'
PARENTS = ('.naos', '.naos/upgrade-v1')
MAX_RECORD_BYTES = 64 * 1024


def _hex(value: Any, width: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(width)+'}', value) is not None


def _implementation() -> dict[str, str]:
    base = Path(__file__).parent
    return {name: hashlib.sha256((base/name).read_bytes()).hexdigest() for name in (
        'canonical.py', 'windows_handles.py', 'repository_intelligence_windows.py',
        'repository_intelligence_windows_enrollment.py')}


def _project_id(root: dict[str, str]) -> str:
    return 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'naos:windows:ri:'+canonical_sha256(root)))


def _validate_plan(plan: Any) -> str:
    if not isinstance(plan, dict) or set(plan) != {
        'schema', 'owner_kind', 'capability_id', 'scope_id', 'project_id', 'root_identity',
        'record_path', 'governed_root', 'initial_governed_root_state', 'ownership_inference',
        'activation_authorized', 'private_security_sha256', 'parents', 'implementation',
        'python_minor', 'source_authorization_sha256'}:
        raise RIStorageConflict('Malformed native RI enrollment plan')
    constants = {'schema': PLAN_SCHEMA, 'owner_kind': 'naos_windows_repository_intelligence',
                 'capability_id': 'CAP-LOCAL-CONTEXT-INDEX', 'scope_id': 'repository-intelligence',
                 'record_path': RECORD_PATH, 'governed_root': GOVERNED_ROOT,
                 'initial_governed_root_state': 'absent', 'ownership_inference': 'forbidden'}
    if any(plan[k] != v for k, v in constants.items()) or plan['activation_authorized'] is not False:
        raise RIStorageConflict('Wrong native RI enrollment contract')
    root = plan['root_identity']
    if (not isinstance(root, dict) or set(root) != {'volume_serial_hex', 'file_id_hex'}
            or not _hex(root['volume_serial_hex'], 16) or not _hex(root['file_id_hex'], 32)
            or plan['project_id'] != _project_id(root)):
        raise RIStorageConflict('Invalid native RI project binding')
    if not _hex(plan['private_security_sha256']) or not _hex(plan['source_authorization_sha256']):
        raise RIStorageConflict('Invalid native RI authorization binding')
    parents = plan['parents']
    if not isinstance(parents, dict) or set(parents) != set(PARENTS):
        raise RIStorageConflict('Invalid native RI parent observations')
    missing = False
    for path in PARENTS:
        if parents[path] is None:
            missing = True
        else:
            identity = NativeIdentity.from_record(parents[path])
            if missing or identity.kind != 'directory' or identity.security_sha256 != plan['private_security_sha256']:
                raise RIStorageConflict('Inconsistent native RI parent observations')
    implementation = plan['implementation']
    if (not isinstance(implementation, dict) or set(implementation) != {
            'canonical.py', 'windows_handles.py', 'repository_intelligence_windows.py',
            'repository_intelligence_windows_enrollment.py'}
            or any(not _hex(v) for v in implementation.values())
            or plan['python_minor'] not in ['3.11', '3.12', '3.13']):
        raise RIStorageConflict('Invalid native RI implementation binding')
    return canonical_sha256(plan)


def _record(plan: dict[str, Any], parents: dict[str, Any]) -> bytes:
    digest = _validate_plan(plan)
    if not isinstance(parents, dict) or set(parents) != set(PARENTS):
        raise RIStorageConflict('Invalid published native RI parent bindings')
    for path, value in parents.items():
        identity = NativeIdentity.from_record(value)
        if (identity.kind != 'directory' or identity.security_sha256 != plan['private_security_sha256']
                or (plan['parents'][path] is not None and plan['parents'][path] != value)):
            raise RIStorageConflict('Published native RI parent differs from its authorization')
    body = {'schema': SCOPE_SCHEMA, 'plan': plan, 'plan_sha256': digest, 'parents': parents}
    return canonical_bytes({**body, 'record_sha256': canonical_sha256(body)})


def _decode(raw: bytes) -> dict[str, Any]:
    try:
        value = loads_strict_json(raw)
        if (not isinstance(value, dict) or set(value) != {'schema', 'plan', 'plan_sha256', 'parents', 'record_sha256'}
                or value['schema'] != SCOPE_SCHEMA or _validate_plan(value['plan']) != value['plan_sha256']
                or _record(value['plan'], value['parents']) != raw):
            raise RIStorageConflict('Invalid native RI enrollment record')
        return value
    except (ValueError, TypeError, KeyError) as exc:
        raise RIStorageConflict('Invalid native RI enrollment record') from exc


@dataclass(frozen=True)
class WindowsRIScopeInspection:
    project_id: str
    enrollment_plan_sha256: str
    record_sha256: str
    record_identity: NativeIdentity

    @property
    def status(self) -> str:
        return 'enrolled_without_activation'

    @property
    def activation_eligible(self) -> bool:
        return False


class WindowsRIEnrollment:
    """Exclusive enrollment on an explicitly confirmed native component plan.

    Interrupted pending files are preserved, never adopted on matching bytes.
    A fresh plan may be required after partial parent creation. Completed exact
    retries are idempotent; recovery of incomplete publication is not claimed.
    """
    def __init__(self, storage: WindowsRIStorage):
        self.storage = storage

    def _root(self) -> dict[str, str]:
        info = self.storage.root.info()
        if info.identity != self.storage.root_identity:
            raise RIStorageConflict('Native RI project root changed')
        return {'volume_serial_hex': f'{info.volume:016x}', 'file_id_hex': info.file_id.hex()}

    def _parents(self) -> dict[str, Any]:
        result = {}
        for path in PARENTS:
            identity = self.storage.identity_if_present(path, kind='directory')
            result[path] = identity.record() if identity else None
        return result

    def _require_absent_generated_root(self) -> None:
        if self.storage.identity_if_present(GOVERNED_ROOT, kind='directory') is not None:
            raise RIStorageConflict('Existing generated root is not owned by an enrollment record')

    def inspect(self) -> WindowsRIScopeInspection | None:
        result = self._inspect_record()
        if result is not None:
            self._require_absent_generated_root()
        return result

    def _inspect_record(self) -> WindowsRIScopeInspection | None:
        """Validate enrollment only; lifecycle callers must prove generated ownership.

        This private entry point does not make an existing generated root owned
        or activation eligible. The public inspection retains that refusal.
        """
        if self.storage.identity_if_present(RECORD_PATH, kind='file') is None:
            return None
        raw, identity = self.storage.read_file(RECORD_PATH, limit=MAX_RECORD_BYTES)
        record = _decode(raw)
        plan = record['plan']
        if (plan['root_identity'] != self._root()
                or plan['private_security_sha256'] != self.storage.private_security_sha256):
            raise RIStorageConflict('Native RI enrollment belongs to a different root or security policy')
        if self._parents() != record['parents']:
            raise RIStorageConflict('Native RI enrolled parent identity changed')
        bindings = {path: NativeIdentity.from_record(value) for path, value in record['parents'].items()}
        with self.storage.pin_directories(bindings):
            if self.storage.read_file(RECORD_PATH, limit=MAX_RECORD_BYTES) != (raw, identity):
                raise RIStorageConflict('Native RI enrollment changed during inspection')
            return WindowsRIScopeInspection(plan['project_id'], canonical_sha256(plan),
                                            hashlib.sha256(raw).hexdigest(), identity)

    def plan(self, *, source_authorization_sha256: str) -> dict[str, Any]:
        if self.inspect() is not None:
            raise RIStorageConflict('Native RI scope is already enrolled')
        self._require_absent_generated_root()
        root = self._root()
        result = {'schema': PLAN_SCHEMA, 'owner_kind': 'naos_windows_repository_intelligence',
                  'capability_id': 'CAP-LOCAL-CONTEXT-INDEX', 'scope_id': 'repository-intelligence',
                  'project_id': _project_id(root), 'root_identity': root,
                  'record_path': RECORD_PATH, 'governed_root': GOVERNED_ROOT,
                  'initial_governed_root_state': 'absent', 'ownership_inference': 'forbidden',
                  'activation_authorized': False, 'private_security_sha256': self.storage.private_security_sha256,
                  'parents': self._parents(), 'implementation': _implementation(),
                  'python_minor': f'{sys.version_info.major}.{sys.version_info.minor}',
                  'source_authorization_sha256': source_authorization_sha256}
        _validate_plan(result)
        return result

    def commit(self, plan: dict[str, Any], *, confirmed_digest: str) -> WindowsRIScopeInspection:
        # Canonical roundtrip makes the caller-owned object immutable to this operation.
        plan = loads_strict_json(canonical_bytes(plan))
        digest = _validate_plan(plan)
        if digest != confirmed_digest:
            raise RIStorageConflict('Explicit native RI enrollment digest does not match')
        if (plan['root_identity'] != self._root()
                or plan['private_security_sha256'] != self.storage.private_security_sha256
                or plan['implementation'] != _implementation()
                or plan['python_minor'] != f'{sys.version_info.major}.{sys.version_info.minor}'):
            raise RIStorageConflict('Native RI enrollment prerequisites changed')
        enrolled = self.inspect()
        if enrolled is not None:
            raw, identity = self.storage.read_file(RECORD_PATH, limit=MAX_RECORD_BYTES)
            if (_decode(raw)['plan'] != plan or identity != enrolled.record_identity
                    or hashlib.sha256(raw).hexdigest() != enrolled.record_sha256):
                raise RIStorageConflict('Existing native RI enrollment differs from the confirmed plan')
            return enrolled
        self._require_absent_generated_root()
        if self._parents() != plan['parents']:
            raise RIStorageConflict('Native RI parents changed after planning; prepare a new plan')
        parents = dict(plan['parents'])
        with ExitStack() as pins:
            for path in PARENTS:
                if parents[path] is None:
                    parents[path] = self.storage.create_directory(path).record()
                # Pin each ancestor before creating/traversing its child, not
                # just before the final file rename.
                pins.enter_context(self.storage.pin_directories(
                    {path: NativeIdentity.from_record(parents[path])}))
            data = _record(plan, parents)
            pending = RECORD_PATH + '.pending-' + digest
            # Exclusive creation returns the identity for this invocation. A prior
            # process's pending file, even with equal bytes, is preserved/refused.
            identity = self.storage.write_new(pending, data)
            self._require_absent_generated_root()
            self.storage.publish_no_replace(pending, RECORD_PATH, identity,
                                           content_sha256=hashlib.sha256(data).hexdigest())
            enrolled = self.inspect()
            if enrolled is None or enrolled.record_identity != identity:
                raise RIStorageConflict('Native RI enrollment publication could not be verified')
            return enrolled
