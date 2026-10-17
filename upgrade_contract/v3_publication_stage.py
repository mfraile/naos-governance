"""Private J2 publication payload staging; no destination move or terminal claim."""
from __future__ import annotations

from . import v3_operation_context as operation_context

from contextlib import ExitStack
from dataclasses import dataclass
import base64
import ctypes
import sys
import hashlib
import os
from pathlib import Path
from typing import Any

from . import local_binding as lb
from . import portable_provenance as pp, rebind_checkpoint as checkpoint
from .canonical import canonical_bytes
from . import v3_j2_registration as reg
from . import v3_operation_program as programs

PUBLICATION = reg.J2 + '/publication'
STAGES = PUBLICATION + '/stages'
RETAINED = PUBLICATION + '/retained'
PROGRAM = PUBLICATION + '/program.json'
TARGETS = PUBLICATION + '/targets.json'
COMMITMENT = PUBLICATION + '/commitment.json'
SCHEMA = 'naos.upgrade.v3_publication_stage.v1'
MAX_BYTES = pp.MAX_CUMULATIVE_READ_BYTES


class PublicationStageError(ValueError):
    pass


def _fail(message):
    raise PublicationStageError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _record(body):
    lb._bounded_input(body)
    raw = canonical_bytes(body)
    if len(raw) > lb.MAX_RECORD_BYTES:
        _fail('Private staging record exceeds bound')
    return raw


def _native_directory(reader, path, windows):
    return reader.directory_witness(path) if windows else reader.directory(path)


def _observe_public(reader, program, evidence, windows):
    """Inspect all public targets/reuse and public parent directories, including absences."""
    _ctx = operation_context.for_program(program)
    body = program.body
    pub_prefix = _ctx.registration.J2 + '/publication/'
    directories = []
    for item in body['required_directories']:
        path = item['path']
        if path == _ctx.registration.J2 or path.startswith(pub_prefix) or path in (_ctx.staging.PUBLICATION,):
            continue
        observed = _native_directory(reader, path, windows)
        captured = item['captured_witness']
        if captured is not None and observed != captured:
            _fail('Approved public parent native observation changed')
        directories.append({'path': path, 'witness': observed})
    expected = {x['destination']: x for x in body['publications']}
    leaves = []
    for path in sorted(set(expected) | {x['path'] for x in body['reused_portable_evidence']}):
        observed = reader.leaf(path)
        slot = expected.get(path)
        if slot is not None:
            before = slot['before']
            if before is None:
                if observed['content'] is not None:
                    _fail('New publication target appeared')
            elif observed['content'] != {k: before[k] for k in ('sha256', 'size_decimal')}:
                _fail('Existing publication target content changed')
            witness = slot['before_native_witness']
            if witness is not None and observed['metadata'] != witness:
                _fail('Approved working target native identity changed')
        else:
            reuse = next(x for x in body['reused_portable_evidence'] if x['path'] == path)
            if observed['content'] != {k: reuse['content'][k] for k in ('sha256', 'size_decimal')}:
                _fail('Reused portable evidence changed')
        leaves.append(observed)
    return {'directories': directories, 'leaves': leaves}


def _reobserve_public(root, custody, program, evidence, expected):
    with reg._fresh_native(root, custody, custody.windows) as native:
        actual = _observe_public(native.reader, program, evidence, custody.windows)
        if actual != expected:
            _fail('Public target/parent native evidence changed before staging')


def _posix_xattrs(source, source_witness):
    if sys.platform == 'darwin':
        # Darwin's Python os module does not expose descriptor xattr APIs.
        # The existing transaction path supplies the descriptor-only copy.
        return None
    expected = {x['name_base64']: (x['size_decimal'], x['sha256'])
                for x in source_witness['xattrs']}
    actual = {}
    for name in os.listxattr(source):
        name_bytes = os.fsencode(name)
        encoded = base64.b64encode(name_bytes).decode('ascii')
        value = os.getxattr(source, name)
        actual[encoded] = (str(len(value)), _sha(value), name, value)
    if {key: value[:2] for key, value in actual.items()} != expected:
        _fail('Working replacement xattrs changed')
    return actual


def _write_payload_posix(custody, slot, raw, before_raw):
    from .portable_provenance_posix import _same_namespace, _witness
    stage = slot['stage']
    policy = slot['stage_native_policy']
    with checkpoint._parent(custody, stage) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            remaining = memoryview(raw)
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0:
                    _fail('Short publication payload write')
                remaining = remaining[count:]
            if policy['kind'] == 'posix_working_replace':
                source_path = slot['destination']
                source_parent, _, source_name = source_path.rpartition('/')
                with ExitStack() as stack:
                    parent_fd = custody.reader.reader._walk(source_parent, stack)
                    source = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=parent_fd)
                    stack.callback(os.close, source)
                    observed = _witness(source, leaf=True, label=source_path)
                    if lb.project_posix_witness(observed.metadata) != policy['source_witness']:
                        _fail('Working replacement source native identity changed')
                    _same_namespace(parent_fd, source_name, observed, leaf=True, label=source_path)
                    os.lseek(source, 0, os.SEEK_SET)
                    checkpoint._check_bytes(lambda n: os.read(source, n), before_raw)
                    attrs = _posix_xattrs(source, policy['source_witness'])
                    if attrs is None:
                        libc = ctypes.CDLL(None, use_errno=True)
                        fcopyfile = libc.fcopyfile
                        fcopyfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
                        fcopyfile.restype = ctypes.c_int
                        if fcopyfile(source, fd, None, 0x00000004) != 0:  # COPYFILE_XATTR
                            _fail('Darwin descriptor xattr copy failed')
                    else:
                        for _, (_, _, xname, xvalue) in attrs.items():
                            os.setxattr(fd, xname, xvalue)
                    if lb.project_posix_witness(_witness(source, leaf=True, label=source_path).metadata) != policy['source_witness']:
                        _fail('Working replacement source metadata changed during copy')
                os.fchown(fd, int(policy['uid_decimal']), int(policy['gid_decimal']))
            os.fchmod(fd, int(policy['mode_octal'], 8))
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            checkpoint._check_bytes(lambda n: os.read(fd, n), raw)
            observed = _witness(fd, leaf=True, label=stage)
            _same_namespace(parent, name, observed, leaf=True, label=stage)
            projected = lb.project_posix_witness(observed.metadata)
            if projected['mode_octal'] != policy['mode_octal']:
                _fail('Payload stage mode differs from intended final mode')
            if policy['kind'] == 'posix_working_replace' and (
                    projected['uid_decimal'] != policy['uid_decimal'] or
                    projected['gid_decimal'] != policy['gid_decimal'] or
                    projected['xattrs'] != policy['source_witness']['xattrs']):
                _fail('Payload replacement metadata differs from source policy')
        finally:
            os.close(fd)
        os.fsync(parent)
    return projected


def _write_payload_windows(custody, slot, raw, before_raw):
    stage = slot['stage']
    policy = slot['stage_native_policy']
    with checkpoint._parent(custody, stage) as (parent, name):
        handles = custody.reader.handles
        with handles.create_private_file(parent, name) as created:
            if policy['kind'] == 'windows_working_replace':
                source_path = slot['destination']
                source_parent, _, source_name = source_path.rpartition('/')
                key = custody.reader.directory(source_parent)
                with handles.open_child(custody.reader.directories[key], source_name,
                                        kind='file', pin_for_read=True) as source:
                    info = source.info()
                    if lb.project_windows_witness(info, source.security()) != policy['source_witness']:
                        _fail('Windows replacement source native identity changed')
                    source.seek(0)
                    checkpoint._check_bytes(source.read, before_raw)
                    source.seek(0)
                    handles.copy_staged_file_security(source, created)
                    created.write_all(raw)
                    handles.copy_supported_file_attributes(
                        source, created, expected_attributes=info.attributes)
                    if lb.project_windows_witness(source.info(), source.security()) != policy['source_witness']:
                        _fail('Windows replacement source changed during stage')
            else:
                created.write_all(raw)
            created.flush()
            witness = lb.project_windows_witness(created.info(), created.security())
    # Bind the created object while held; the subsequent read must match after close.
    return witness


def _write_payload(custody, slot, raw, before_raw):
    if type(raw) is not bytes or len(raw) > pp.MAX_BASE_BYTES:
        _fail('Invalid stage payload bytes')
    if custody.windows:
        witness = _write_payload_windows(custody, slot, raw, before_raw)
    else:
        witness = _write_payload_posix(custody, slot, raw, before_raw)
    return {'path': slot['stage'], 'metadata': witness,
            'content': {'sha256': _sha(raw), 'size_decimal': str(len(raw))}}


def _stage_names(native, expected_count, *, final=False):
    _ctx = operation_context.from_custody(native)
    if type(expected_count) is not int or not 1 <= expected_count <= programs.MAX_SLOTS:
        _fail('Stage slot count exceeds approved program bound')
    native.directory(_ctx.staging.STAGES)
    if native.windows:
        key = native.reader.directory(_ctx.staging.STAGES)
        names = frozenset(native.reader._names(key).values())
    else:
        with ExitStack() as stack:
            fd = native.reader._walk(_ctx.staging.STAGES, stack)
            names = native.reader._scan(fd, _ctx.staging.STAGES, final=final)
    if len(names) > programs.MAX_SLOTS or names != {f'{i:08d}' for i in range(1, expected_count + 1)}:
        _fail('Partial, extra or aliased stage payload inventory')


def _stage_observations(root, custody, program):
    with reg._fresh_native(root, custody, custody.windows) as native:
        result = []
        for slot in program.body['publications']:
            path = slot['stage']
            item = native.reader.leaf(path)
            if item['content'] != {k: slot['after'][k] for k in ('sha256', 'size_decimal')}:
                _fail('Staged publication payload bytes differ')
            policy = slot['stage_native_policy']
            if policy['kind'].startswith('posix_') and item['metadata']['mode_octal'] != policy['mode_octal']:
                _fail('Staged publication payload mode differs')
            if policy['kind'] == 'posix_working_replace' and (
                    item['metadata']['uid_decimal'] != policy['uid_decimal'] or
                    item['metadata']['gid_decimal'] != policy['gid_decimal'] or
                    item['metadata']['xattrs'] != policy['source_witness']['xattrs']):
                _fail('Staged replacement metadata differs')
            if policy['kind'] == 'windows_working_replace' and (
                    item['metadata']['security'] != policy['source_witness']['security'] or
                    item['metadata']['attributes_hex'] != policy['source_witness']['attributes_hex']):
                _fail('Staged Windows replacement security/attributes differ')
            result.append(item)
        return result


def _sealed_snapshot(root, custody, program, public, intent, registered, *, committed):
    """Observe the fixed staging namespace; payloads retain their own role policy."""
    _ctx = operation_context.for_program(program)
    with reg._fresh_native(root, custody, custody.windows) as native:
        names = {'program.json', 'targets.json', 'stages', 'retained'}
        if committed:
            names.add('commitment.json')
        reg._names(native, _ctx.staging.PUBLICATION, names)
        reg._names(native, _ctx.staging.RETAINED, set())
        _stage_names(native, len(program.body['publications']))
        directories = {path: native.directory(path)
                       for path in (_ctx.staging.PUBLICATION, _ctx.staging.STAGES, _ctx.staging.RETAINED)}
        target_raw = _record(public)
        if native.read(_ctx.staging.PROGRAM) != program.raw or native.read(_ctx.staging.TARGETS) != target_raw:
            _fail('Persisted publication program/targets differ')
        records = {path: native.observations[path] for path in (_ctx.staging.PROGRAM, _ctx.staging.TARGETS)}
        stages = _stage_observations(root, custody, program)
        body = {'schema': SCHEMA, 'program_sha256': program.sha256,
                'intent_sha256': intent.sha256,
                'registered_state_sha256': registered.sha256,
                'target_observations_sha256': _sha(target_raw),
                'storage_witnesses': directories, 'record_witnesses': records,
                'stages': stages}
        raw = _record(body)
        if committed and native.read(_ctx.staging.COMMITMENT) != raw:
            _fail('Stage commitment or native stage identity differs')
        observations = dict(native.observations)
        _stage_names(native, len(stages), final=True)
        native.children(_ctx.staging.PUBLICATION, final=True)
        native.children(_ctx.staging.RETAINED, final=True)
    return body, observations


def _verify_sealed(root, custody, program, public, intent, registered, expected=None,
                   *, commit_witness=None):
    _ctx = operation_context.for_program(program)
    first, observations = _sealed_snapshot(
        root, custody, program, public, intent, registered, committed=True)
    if expected is not None and first != expected:
        _fail('Created staging evidence changed before final verification')
    if commit_witness is not None and observations[_ctx.staging.COMMITMENT]['metadata'] != commit_witness:
        _fail('New commitment object was substituted before final verification')
    second, reread = _sealed_snapshot(
        root, custody, program, public, intent, registered, committed=True)
    if second != first or reread != observations:
        _fail('Private staging evidence changed during final revalidation')
    return first


@dataclass(frozen=True)
class PublicationStages:
    program_sha256: str
    commitment_sha256: str
    stage_count: int
    mutation_authorized: bool = False


def stage_j2_publication(project_root: Path | str, *, plan, expected_plan_sha256,
                         plan_evidence: dict[str, Any], program, expected_program_sha256,
                         handles=None) -> PublicationStages:
    """Stage exact payloads, or recognize one fully committed private stage set."""
    _ctx = operation_context.for_plan(plan)
    try:
        if type(program) is not programs.ValidatedPublicationProgram or program.sha256 != expected_program_sha256:
            _fail('Exact approved publication program digest required')
        programs.load_publication_program(program.raw, plan, plan_evidence)
        reg.operation._verified_plan(plan, plan_evidence)
        if plan.sha256 != expected_plan_sha256 or program.body['journal_id'] != _ctx.journal_id:
            _fail('Exact registered J2 plan required')
        root = Path(project_root)
        windows = handles is not None or os.name == 'nt'
        with ExitStack() as pins:
            with operation_context.held_store(root, journal_ids=_ctx.prior_journal_ids, handles=handles, context=_ctx) as custody:
                with reg._source_capture(root, custody, plan_evidence, windows, state_source=_ctx.registration.BACKUP) as held:
                    native = reg._native(custody, windows)
                    # Inventory through a separate read lane: the bridge must own
                    # the mutation-custody pin, including on Windows.
                    with reg._fresh_native(root, custody, windows) as inventory:
                        has_publication = 'publication' in inventory.children(_ctx.registration.J2)
                    phase, intent, registered, prior_state, commitment, repairs = reg._inspect_bridge(
                        root, plan, plan_evidence, custody, native, held, pins,
                        publication_child=has_publication)
                    if phase != 'registered' or repairs:
                        _fail('Publication staging requires exact registered J2 state')
                    baseline = reg._private_baseline(native, phase=phase,
                        old_state_raw=prior_state.raw, registered_raw=registered.raw,
                        publication_child=has_publication)
                    public = _observe_public(held.working_reader, program, plan_evidence, windows)
                    for path in plan_evidence['portable_files']:
                        if held.portable_reader.read(path) != plan_evidence['portable_files'][path]:
                            _fail('Prior portable byte evidence changed')
                reg._revalidate_private(root, custody, baseline, phase='registered')
                _reobserve_public(root, custody, program, plan_evidence, public)
                if has_publication:
                    body = _verify_sealed(root, custody, program, public, intent, registered)
                    reg._revalidate_private(root, custody, baseline, phase='registered')
                    _reobserve_public(root, custody, program, plan_evidence, public)
                    _verify_sealed(root, custody, program, public, intent, registered, body)
                    return PublicationStages(program.sha256, _sha(_record(body)), len(body['stages']))
                # Every read-only lane above has closed with final validation.
                created_directories = {
                    path: reg._pin_directory(custody, path, create=True, pins=pins)
                    for path in (_ctx.staging.PUBLICATION, _ctx.staging.STAGES, _ctx.staging.RETAINED)
                }
                baseline['publication_child'] = True
                created_records = {
                    _ctx.staging.PROGRAM: checkpoint._write_new(custody, _ctx.staging.PROGRAM, program.raw),
                    _ctx.staging.TARGETS: checkpoint._write_new(custody, _ctx.staging.TARGETS, _record(public)),
                }
                payloads = program.publication_bytes
                total = 0
                created_stages = []
                for slot in program.body['publications']:
                    data = payloads[slot['destination']]
                    total += len(data)
                    if total > MAX_BYTES:
                        _fail('Staging cumulative byte limit exceeded')
                    before = (plan_evidence['current_bytes'].get(slot['destination'])
                              if slot['role'].startswith('working_') else
                              plan_evidence['portable_files'].get(slot['destination']))
                    created_stages.append(_write_payload(custody, slot, data, before))
                body, _observations = _sealed_snapshot(
                    root, custody, program, public, intent, registered, committed=False)
                if (body['storage_witnesses'] != created_directories or
                        body['stages'] != created_stages or any(
                        body['record_witnesses'][path]['metadata'] != witness
                        for path, witness in created_records.items())):
                    _fail('New directory, payload or preparation record was substituted before commitment')
                raw = _record(body)
                commit_witness = checkpoint._write_new(custody, _ctx.staging.COMMITMENT, raw)
                reg._revalidate_private(root, custody, baseline, phase='registered')
                _reobserve_public(root, custody, program, plan_evidence, public)
                _verify_sealed(root, custody, program, public, intent, registered,
                               body, commit_witness=commit_witness)
                return PublicationStages(program.sha256, _sha(raw), len(created_stages))
    except PublicationStageError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError) as exc:
        raise PublicationStageError(f'J2 publication staging refused: {exc}') from exc
