"""Protected, bounded exact-byte replay evidence for active J2 recovery.

No mutation authority: the consumer must still run the existing same-lock native
registration/publication/checkpoint inspectors. Private evidence is not portable.
"""
from __future__ import annotations

from . import v3_operation_context as operation_context

from contextlib import ExitStack
from dataclasses import dataclass
from functools import wraps
import hashlib
from pathlib import Path
from types import SimpleNamespace

from . import local_binding as lb, local_store as ls, portable_provenance as pp
from . import rebind_store_inspection as ris
from . import v3_operation_records as records, v3_operation_program as programs
from .canonical import canonical_bytes
from .working_tree_capture import build_capture

J2 = ris.ROOT + '/journals/J00000002'
ROOT = J2 + '/replay'
BLOBS = ROOT + '/blobs'
INDEX = ROOT + '/index.json'
COMMITMENT = ROOT + '/commitment.json'
SCHEMA = 'naos.upgrade.v3_private_replay.v1'
PUBLIC_SCHEMA = 'naos.upgrade.v3_private_replay.v2'
SELECTED_SCHEMA = 'naos.upgrade.v3_private_replay.v3'
COMMIT_SCHEMA = 'naos.upgrade.v3_private_replay_commitment.v1'
MAX_BYTES = pp.MAX_CUMULATIVE_READ_BYTES
MAX_BLOBS = pp.MAX_TOTAL_SELECTED_PATHS * 3 + pp.MAX_TOTAL_CHANGES + 10_000


class DurableReplayError(ValueError):
    pass


def _fail(message):
    raise DurableReplayError(message)


def _closed(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except DurableReplayError:
            raise
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError,
                OverflowError, RecursionError) as exc:
            raise DurableReplayError(f'Private replay refused: {exc}') from exc
    return call


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _encode(body):
    lb._bounded_input(body)
    raw = canonical_bytes(body)
    if len(raw) > lb.MAX_RECORD_BYTES:
        _fail('Replay record exceeds byte budget')
    return raw


def _parse(raw):
    if type(raw) is not bytes or len(raw) > lb.MAX_RECORD_BYTES:
        _fail('Replay record exceeds byte budget')
    body = pp._load_json(raw, 'private replay')
    if _encode(body) != raw:
        _fail('Noncanonical private replay record')
    return body


@_closed
def build_bundle(plan, evidence):
    """Return canonical index and exact deduplicated bytes after original replay."""
    _ctx = operation_context.for_plan(plan)
    p = records._verified_plan(plan, evidence)
    if p['next_journal_id'] != _ctx.journal_id:
        _fail('Only active J2 replay is supported')
    blobs, total = {}, 0
    def reference(raw):
        nonlocal total
        if raw is None:
            return None
        if type(raw) is not bytes or len(raw) > pp.MAX_BASE_BYTES:
            _fail('Replay blob exceeds leaf byte budget')
        total += len(raw)
        if total > MAX_BYTES:
            _fail('Replay logical input budget exceeded')
        digest = _sha(raw)
        if digest in blobs and blobs[digest] != raw:
            _fail('Replay digest collision')
        blobs[digest] = raw
        return {'sha256': digest, 'size_decimal': str(len(raw))}
    body = {'schema': SCHEMA, 'journal_id': p['next_journal_id'],
            'plan_sha256': plan.sha256,
            'portable': {path: reference(raw) for path, raw in sorted(evidence['portable_files'].items())},
            'current': {path: reference(raw) for path, raw in sorted(evidence['current_bytes'].items())},
            'requested': {path: {'source': reference(item['source']),
                                'output': reference(item['output']),
                                'executable': item['executable']}
                          for path, item in sorted(evidence['requested'].items())},
            'inputs': evidence['inputs'], 'source_policy': reference(canonical_bytes(evidence['source_policy']))}
    if 'public_review' in evidence:
        body['schema'] = PUBLIC_SCHEMA
        body['public_review'] = evidence['public_review']
    if 'selection' in evidence:
        body['schema'] = SELECTED_SCHEMA
        body['selection'] = evidence['selection']
    index_raw = _encode(body)
    _storage_budget(index_raw, blobs)
    return index_raw, blobs


def _storage_budget(index_raw, blobs):
    # The fixed reader counts records as well as payloads. Reserve the complete
    # existing commitment record ceiling before any new namespace is created.
    # This deliberately narrows logical-valid plans by up to 16 MiB; it never
    # enlarges the 256 MiB physical read budget or the generic record reader.
    physical = len(index_raw) + sum(len(raw) for raw in blobs.values())
    if physical + lb.MAX_RECORD_BYTES > MAX_BYTES:
        _fail('Replay physical read budget reservation exceeded')


@_closed
def decode_bundle(index_raw, blobs, plan_raw, binding_raw, state_raw):
    """Decode exact bytes into existing typed validators; no new plan validator."""
    _ctx = operation_context.for_journal(records._parsed(plan_raw, 'operation plan')['next_journal_id'])
    body = _parse(index_raw)
    if type(body) is not dict or set(body) != {'schema', 'journal_id', 'plan_sha256',
            'portable', 'current', 'requested', 'inputs', 'source_policy'} | ({'public_review'} if body.get('schema') in (PUBLIC_SCHEMA, SELECTED_SCHEMA) else set()) | ({'selection'} if body.get('schema') == SELECTED_SCHEMA else set()):
        _fail('Malformed replay index')
    if body['schema'] not in (SCHEMA, PUBLIC_SCHEMA, SELECTED_SCHEMA) or body['journal_id'] != _ctx.journal_id or body['plan_sha256'] != _sha(plan_raw):
        _fail('Replay index differs from approved plan')
    if type(blobs) is not dict:
        _fail('Malformed replay blobs')
    plan = records.ValidatedOperationPlan(plan_raw, _sha(plan_raw))
    p = plan.body
    total, used = 0, set()
    def resolve(ref):
        nonlocal total
        if ref is None:
            return None
        if type(ref) is not dict or set(ref) != {'sha256', 'size_decimal'}:
            _fail('Malformed replay blob reference')
        digest = ref['sha256']
        lb._hex(digest, lb.HEX64, 'replay blob digest')
        raw = blobs.get(digest)
        if type(raw) is not bytes or len(raw) > pp.MAX_BASE_BYTES or ref != {'sha256': _sha(raw), 'size_decimal': str(len(raw))}:
            _fail('Missing or mismatched replay bytes')
        total += len(raw)
        if total > MAX_BYTES:
            _fail('Replay logical input budget exceeded')
        used.add(digest)
        return raw
    for name in ('portable', 'current', 'requested'):
        if type(body[name]) is not dict or len(body[name]) > pp.MAX_TOTAL_SELECTED_PATHS + pp.MAX_TOTAL_CHANGES + 10_000:
            _fail('Malformed replay path inventory')
    portable = {path: resolve(ref) for path, ref in body['portable'].items()}
    if any(raw is None for raw in portable.values()):
        _fail('Portable replay bytes may not be absent')
    current = {path: resolve(ref) for path, ref in body['current'].items()}
    requested = {}
    for path, item in body['requested'].items():
        if type(item) is not dict or set(item) != {'source', 'output', 'executable'}:
            _fail('Malformed requested replay map')
        requested[path] = {'source': resolve(item['source']), 'output': resolve(item['output']),
                           'executable': item['executable']}
    capture = build_capture(p['initial_capture']['native'], p['initial_capture']['leaves'])
    evidence = {'portable_files': portable, 'current_bytes': current, 'requested': requested,
                'capture': capture, 'predecessor_binding': lb.load_local_binding(binding_raw),
                'predecessor_store': ls.load_local_store(state_raw),
                'journal_ids': tuple(x['id'] for x in p['prior_journals']['entries']),
                'predecessor_record_witnesses': p['predecessor_record_witnesses'],
                'operation': p['operation'], 'inputs': body['inputs'],
                'source_policy_id': p['source_policy_id'], 'source_policy': pp._load_json(resolve(body['source_policy']), 'replayed policy')}
    if body['schema'] in (PUBLIC_SCHEMA, SELECTED_SCHEMA):
        evidence['public_review'] = body['public_review']
    if body['schema'] == SELECTED_SCHEMA:
        evidence['selection'] = body['selection']
    if used != set(blobs):
        _fail('Unknown or unreferenced replay blob')
    _storage_budget(index_raw, blobs)
    # Publication-program construction immediately verifies this exact plan
    # against the same decoded evidence before using either one.  Keep that
    # verification once, inside the operation that consumes its result.
    try:
        program = programs.build_publication_program(plan, evidence)
    except programs.PublicationProgramError as exc:
        # That builder owns the sole plan verification.  Preserve this codec's
        # existing operation-record refusal for malformed replay evidence.
        if isinstance(exc.__cause__, records.OperationRecordError):
            raise records.OperationRecordError(str(exc.__cause__)) from exc
        raise
    return plan, evidence, program


class _ReplayStore(ris._NativeStore):
    """Bounded private blob read role; ordinary record ceilings remain unchanged."""
    def children(self, relative, *, final=False):
        _ctx = operation_context.from_custody(self)
        if relative != _ctx.replay.BLOBS:
            return super().children(relative, final=final)
        self.directory(relative)
        if self.windows:
            key = self.reader.directory(relative)
            names = frozenset(self.reader._names(key).values())
        else:
            with ExitStack() as stack:
                fd = self.reader._walk(relative, stack)
                names = self.reader._scan(fd, relative, final=final)
        if len(names) > MAX_BLOBS:
            _fail('Replay blob inventory exceeds bound')
        for name in names:
            if not name.endswith('.bin'):
                _fail('Unknown replay blob filename')
            lb._hex(name[:-4], lb.HEX64, 'replay blob filename')
        if final and names != self.inventories.get(relative):
            _fail('Replay blob inventory changed during inspection')
        self.inventories.setdefault(relative, names)
        return names

    def read_blob(self, relative):
        _ctx = operation_context.from_custody(self)
        name = relative.removeprefix(_ctx.replay.BLOBS + '/')
        if relative != _ctx.replay.BLOBS + '/' + name or not name.endswith('.bin'):
            _fail('Replay blob is outside fixed namespace')
        lb._hex(name[:-4], lb.HEX64, 'replay blob name')
        self._blob_role = True
        try:
            return self.read(relative)
        finally:
            self._blob_role = False

    def _budget(self, size):
        if getattr(self, '_blob_role', False):
            if not 0 <= size <= pp.MAX_BASE_BYTES or size > MAX_BYTES - self.total_bytes:
                _fail('Replay physical read budget exceeded')
        else:
            if not 0 <= size <= lb.MAX_RECORD_BYTES or size > MAX_BYTES - self.total_bytes:
                _fail('Replay record or cumulative read budget exceeded')


def _reader(native, context=None):
    reader = _ReplayStore(SimpleNamespace(working_reader=native.reader), native.windows)
    reader.operation_context = context or operation_context.from_custody(native)
    reader.lock_handle, reader.lock_witness = native.lock_handle, native.lock_witness
    return reader


def snapshot(native, *, expected=None, context=None):
    """Read and bind exact namespace/protections, bytes and creation observations."""
    _ctx = context or operation_context.from_custody(native)
    n = _reader(native, _ctx)
    if n.children(_ctx.replay.ROOT) != {'index.json', 'blobs', 'commitment.json'}:
        _fail('Partial or unknown replay inventory')
    index_raw = n.read(_ctx.replay.INDEX)
    index = _parse(index_raw)
    commit_raw = n.read(_ctx.replay.COMMITMENT)
    commit = _parse(commit_raw)
    if type(commit) is not dict or set(commit) != {'schema', 'plan_sha256', 'directories', 'files'} or commit['schema'] != COMMIT_SCHEMA:
        _fail('Malformed replay commitment')
    if commit['plan_sha256'] != index.get('plan_sha256') or set(commit['directories']) != {_ctx.replay.ROOT, _ctx.replay.BLOBS}:
        _fail('Replay directory/plan commitment differs')
    for path, witness in commit['directories'].items():
        current = n.directory(path)
        if not lb._metadata_comparison(
                current, witness, 'Windows' if n.windows else n.reader.platform):
            _fail('Replay directory identity changed')
    if type(commit['files']) is not dict or _ctx.replay.INDEX not in commit['files']:
        _fail('Malformed replay file commitment')
    names = n.children(_ctx.replay.BLOBS)
    if len(names) > MAX_BLOBS:
        _fail('Replay blob count exceeds bound')
    if set(commit['files']) != {_ctx.replay.INDEX} | {_ctx.replay.BLOBS + '/' + name for name in names}:
        _fail('Replay committed file inventory differs')
    blobs = {}
    for name in sorted(names):
        path = _ctx.replay.BLOBS + '/' + name
        raw = n.read_blob(path)
        if name != _sha(raw) + '.bin':
            _fail('Replay blob name differs from bytes')
        blobs[name[:-4]] = raw
    for path, observation in commit['files'].items():
        if n.observations[path] != observation:
            _fail('Replay creation identity or bytes changed')
    binding = n.observations[_ctx.replay.COMMITMENT]
    if expected is not None and binding != expected:
        _fail('Registration-bound replay commitment changed')
    second = _reader(native, _ctx)
    for path, observation in n.observations.items():
        raw = second.read_blob(path) if path.startswith(_ctx.replay.BLOBS + '/') else second.read(path)
        if raw != n.raw[path] or second.observations[path] != observation:
            _fail('Replay evidence changed during final revalidation')
    for path in (_ctx.replay.ROOT, _ctx.replay.BLOBS):
        n.children(path, final=True)
    return index_raw, blobs, binding


def prepare(root, custody, plan, evidence, pins):
    _ctx = operation_context.for_plan(plan)
    from . import v3_j2_registration as reg, rebind_checkpoint as checkpoint
    index_raw, blobs = build_bundle(plan, evidence)
    directories = {path: reg._pin_directory(custody, path, create=True, pins=pins)
                   for path in (_ctx.replay.ROOT, _ctx.replay.BLOBS)}
    created = {}
    for path, raw in [(_ctx.replay.BLOBS + '/' + digest + '.bin', raw) for digest, raw in sorted(blobs.items())] + [(_ctx.replay.INDEX, index_raw)]:
        created[path] = checkpoint._write_new(custody, path, raw, max_bytes=pp.MAX_BASE_BYTES if path != _ctx.replay.INDEX else lb.MAX_RECORD_BYTES)
    with reg._fresh_native(root, custody, custody.windows) as native:
        n = _reader(native)
        if n.children(_ctx.replay.ROOT) != {'index.json', 'blobs'} or n.children(_ctx.replay.BLOBS) != {digest + '.bin' for digest in blobs}:
            _fail('Replay preparation inventory changed')
        for path, witness in directories.items():
            current = n.directory(path)
            if not lb._metadata_comparison(
                    current, witness, 'Windows' if n.windows else n.reader.platform):
                _fail('Created replay directory changed')
        for path, witness in created.items():
            raw = n.read(_ctx.replay.INDEX) if path == _ctx.replay.INDEX else n.read_blob(path)
            expected_raw = index_raw if path == _ctx.replay.INDEX else blobs[path.rsplit('/', 1)[1][:-4]]
            if raw != expected_raw or n.observations[path]['metadata'] != witness:
                _fail('Created replay record changed before commitment')
        commit_raw = _encode({'schema': COMMIT_SCHEMA, 'plan_sha256': plan.sha256,
                              'directories': directories, 'files': dict(n.observations)})
    witness = checkpoint._write_new(custody, _ctx.replay.COMMITMENT, commit_raw)
    with reg._fresh_native(root, custody, custody.windows) as native:
        _index, _blobs, binding = snapshot(native)
        if binding['metadata'] != witness or binding['content']['sha256'] != _sha(commit_raw):
            _fail('Created replay commitment changed')
    return binding


def validate(native, binding, plan, evidence):
    index, blobs, _binding = snapshot(native, expected=binding)
    loaded, recovered, program = decode_bundle(index, blobs, plan.raw,
        evidence['predecessor_binding'].raw, evidence['predecessor_store'].raw)
    if loaded != plan or recovered != evidence:
        _fail('Durable replay evidence differs from caller evidence')
    return program


@dataclass(frozen=True)
class ActiveReplay:
    plan: records.ValidatedOperationPlan
    evidence: dict
    program: programs.ValidatedPublicationProgram


@_closed
def load_active_j2(project_root, *, handles=None, context=None):
    """Read-only fresh-process decoder; native mutation consumers revalidate.

    This loader does not classify public recovery policy or authorize a move.
    """
    _ctx = context or operation_context.probe(project_root, handles=handles)
    from . import v3_j2_registration as reg
    root = Path(project_root)
    with operation_context.held_store(root, journal_ids=_ctx.journal_ids, handles=handles, context=_ctx) as custody:
        with reg._fresh_native(root, custody, custody.windows) as native:
            commit = _parse(native.read(_ctx.registration.COMMITMENT))
            if commit.get('schema') != _ctx.registration.REPLAY_SCHEMA or 'replay_binding' not in commit:
                _fail('Registration has no durable replay variant')
            index, blobs, _binding = snapshot(native, expected=commit['replay_binding'])
            plan, evidence, program = decode_bundle(index, blobs, native.read(_ctx.registration.PLAN),
                native.read(_ctx.registration.PRIOR_BINDING), native.read(_ctx.registration.PRIOR_STATE))
            if commit['plan_sha256'] != plan.sha256:
                _fail('Replay differs from registered plan')
            return ActiveReplay(plan, evidence, program)
