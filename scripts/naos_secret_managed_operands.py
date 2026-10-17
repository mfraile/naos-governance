"""Bounded pure constructor proofs for exact inventory scalar occurrences.

Hash links establish local consistency, never authenticity, ownership or safety.
There is no upgrade_contract/native import and no native host dispatch.
"""
from __future__ import annotations
import hashlib
import json
import math
import ntpath
import os
import re
import stat
import uuid
from importlib import metadata as importlib_metadata
from pathlib import Path, PureWindowsPath
from typing import Any
class CanonicalizationError(ValueError):
    """Raised when a value cannot enter the canonical control boundary."""

class CanonicalizationUnavailable(RuntimeError):
    """Raised when the exact selected RFC 8785 implementation is unavailable."""

def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785/JCS bytes using the exact maintained dependency."""
    try:
        import rfc8785
    except ImportError as exc:
        raise CanonicalizationUnavailable('RFC 8785 support is unavailable; install the declared rfc8785==0.1.4 dependency.') from exc
    try:
        distribution = importlib_metadata.distribution('rfc8785')
    except importlib_metadata.PackageNotFoundError as exc:
        raise CanonicalizationUnavailable('RFC 8785 support is unavailable; install the declared rfc8785==0.1.4 dependency.') from exc
    if distribution.version != '0.1.4':
        raise CanonicalizationUnavailable('RFC 8785 support requires the exact declared rfc8785==0.1.4 dependency.')
    module_file = getattr(rfc8785, '__file__', None)
    distribution_files = distribution.files
    if not isinstance(module_file, str) or distribution_files is None:
        raise CanonicalizationUnavailable('RFC 8785 support could not bind the imported module to rfc8785==0.1.4.')
    try:
        expected_module_files = {Path(distribution.locate_file(path)).resolve(strict=True) for path in distribution_files if path.parts and path.parts[0] == 'rfc8785' and (path.suffix == '.py')}
        imported_module_file = Path(module_file).resolve(strict=True)
    except OSError as exc:
        raise CanonicalizationUnavailable('RFC 8785 support could not bind the imported module to rfc8785==0.1.4.') from exc
    if imported_module_file not in expected_module_files:
        raise CanonicalizationUnavailable('RFC 8785 support refused an imported module outside the rfc8785==0.1.4 distribution.')
    try:
        return bytes(rfc8785.dumps(value))
    except Exception as exc:
        raise CanonicalizationError(f'Value is not valid RFC 8785 input: {exc}') from exc

def canonical_sha256(value: Any) -> str:
    """Return the lowercase SHA-256 digest of RFC 8785 canonical bytes."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

def canonical_sha3_512(value: Any) -> str:
    """Return the lowercase SHA3-512 digest of RFC 8785 canonical bytes."""
    return hashlib.sha3_512(canonical_bytes(value)).hexdigest()

_PUBLIC_LINK_FIELDS = ('previous_projection_sha256', 'result_projection_sha256', 'introduced_policy_sha256', 'mode_inventory_sha256', 'source_policy_snapshot_sha256', 'previous_receipt_sha256', 'owner_sha256', 'archive_sha256', 'plan_sha256', 'policy_sha256', 'receipt_sha256', 'scope_integrity_sha3_512')

_SUPPORTED_SCHEMAS = ('naos.secret_hygiene.v1', 'naos.evidence_pack.v1', 'naos.evidence_pack.v2', 'naos.dashboard_summary.v1', 'naos.dashboard_summary.v2', 'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2', 'naos.upgrade.content_aware_plan.v1', 'naos.upgrade.content_aware_plan.v2', 'naos.upgrade.managed_content_manifest.v1', 'naos.upgrade.managed_content_manifest.v2', 'naos.upgrade.managed_content_scope.v1', 'naos.upgrade.create_only_transaction.v1', 'naos.upgrade.content_transaction.v2', 'naos.upgrade.content_transaction.compact.v1', 'naos.upgrade.managed_content_receipt.v1', 'naos.upgrade.managed_content_receipt.v2', 'naos.upgrade.portable_owner.v3', 'naos.upgrade.portable_manifest.v3', 'naos.upgrade.portable_receipt.v3', 'naos.upgrade.source_mode_inventory.v1', 'naos.upgrade.windows_root_enrollment.v1', 'naos.upgrade.windows_owner_enrollment.v1', 'naos.upgrade.windows_content_manifest.v1', 'naos.upgrade.windows_content_receipt.v1', 'naos.upgrade.windows_content_base.v1', 'naos.upgrade.windows_operation_plan.v1', 'naos.upgrade.windows_operation_plan.v2', 'naos.upgrade.windows_operation.v1', 'naos.upgrade.windows_operation.v2', 'naos.upgrade.windows_runtime_plan.v1', 'naos.upgrade.windows_runtime_plan.v2', 'naos.upgrade.windows_runtime_directories.v1')

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_PROOF_BYTES = 32 * 1024 * 1024
MAX_IDENTITIES = 16384
MAX_REPRESENTATIONS = 65536
MAX_METADATA_NODES = 50000
MAX_DEPTH = 64
_MANAGED_ROOT = '.naos/upgrade-v1/managed-content'
_METADATA_ARRAYS = {'input_files', 'scope_inventory', 'unassessed_suffix_files'}
_DIAGNOSTIC_ARRAY = 'inventory_operand_proofs'
_REPORT_PREFIXES = ((), ('artifacts', 'secret_hygiene_report', 'data'),
                    ('inputs', 'secret_hygiene', 'data'),
                    ('inputs', 'evidence_pack', 'data', 'artifacts', 'secret_hygiene_report', 'data'))
_JSON_PRIMITIVE = re.compile(r'(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)')


class OperandRefusal(ValueError):
    """No coordinate admission follows a failed parse or proof."""


def _control_coordinate(path, coordinates):
    # Only the bounded array index wildcard may match; object keys stay literal.
    return any(len(path) == len(coordinate) and all(
        type(actual) is int if expected is None else actual == expected
        for actual, expected in zip(path, coordinate)) for coordinate in coordinates)


def _control_record(relative):
    """Select exact producer file roles, never a label prefix in arbitrary text."""
    if relative in {'.naos/upgrade-v1/OWNER.json', _MANAGED_ROOT + '/scope.json'}:
        return _MANAGED_ROOT, frozenset()
    if relative == _MANAGED_ROOT + '/state/manifest.json':
        return _MANAGED_ROOT, frozenset({('last_transaction_id',),
            ('transactions', None, 'transaction_id'),
            ('entries', None, 'introduced_by_transaction'),
            ('entries', None, 'last_mutated_by_transaction')})
    if re.fullmatch(re.escape(_MANAGED_ROOT) + r'/(?:state/receipts/MC-[0-9a-f]{16}-[0-9a-f]{8}\.json|transactions/MC-[0-9a-f]{16}-[0-9a-f]{8}/journal\.json)', relative):
        return _MANAGED_ROOT, frozenset({('transaction_id',)})
    if re.fullmatch(re.escape(_MANAGED_ROOT) + r'/transactions/MC-[0-9a-f]{16}-[0-9a-f]{8}/plan\.json', relative):
        return _MANAGED_ROOT, frozenset()
    if relative in {_WINDOWS_ROOT + '/root.json', _WINDOWS_ROOT + '/owner.json'}:
        return _WINDOWS_ROOT, frozenset()
    if re.fullmatch(re.escape(_WINDOWS_ROOT) + r'/transactions/WOP-[0-9a-f]{16}/directories\.json', relative):
        return _WINDOWS_ROOT, frozenset()
    if relative == _WINDOWS_ROOT + '/manifest.json':
        return _WINDOWS_ROOT, frozenset({('body', 'receipts', None, 'transaction_id')})
    if re.fullmatch(re.escape(_WINDOWS_ROOT) + r'/(?:receipts/WMC-[0-9a-f]{16}\.json|bases/[0-9a-f]{64}\.json)', relative):
        return _WINDOWS_ROOT, frozenset({('body', 'transaction_id')})
    if re.fullmatch(re.escape(_WINDOWS_ROOT) + r'/transactions/WOP-[0-9a-f]{16}/plan\.json', relative):
        return _WINDOWS_ROOT, frozenset({('body', 'operation_id'),
            ('body', 'plan', 'operation_id'), ('body', 'plan', 'transaction_id')})
    if re.fullmatch(re.escape(_WINDOWS_ROOT) + r'/transactions/WOP-[0-9a-f]{16}/intent\.json', relative):
        return _WINDOWS_ROOT, frozenset({('body', 'operation_id')})
    return None, frozenset()


def _ensure_control_family(context, family):
    prove = _legacy_operands if family == _MANAGED_ROOT else _windows_operands
    if family not in context.operands and family not in context.reason:
        try:
            context.operands[family] = prove(context)
            context.evidence[family] = {"kind": family, "input_sha256": {
                name: hashlib.sha256(row[0]).hexdigest() for name, row in context.cache.items()
                if name.startswith(family + "/")}}
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError) as exc:
            context.reason[family] = type(exc).__name__


def _control_id_spans(text, relative, parser, family, context):
    _ensure_control_family(context, family)
    if family in context.reason:
        raise OperandRefusal('control_chain')
    manifest_path = family + ('/state/manifest.json' if family == _MANAGED_ROOT else '/manifest.json')
    if (relative != manifest_path and relative not in context.operands[family]
            and relative not in context.constructor_coordinates.get(family, {})):
        raise OperandRefusal('control_record_membership')
    # Parsed scanner content must be the exact bytes consumed by the proof.
    if text.encode('utf-8') != context.read(relative):
        raise OperandRefusal('control_record_bytes')
    manifest = context.object(manifest_path)
    if family == _MANAGED_ROOT:
        labels = {row['transaction_id'] for row in manifest['transactions']}
    else:
        labels = {row['transaction_id'] for row in manifest['body']['receipts']}
        labels.update('WOP-' + label[4:] for label in tuple(labels))
    context.admission_checkpoint()
    return {(start, end) for coordinate, (start, end, value) in parser.strings.items()
            if (_control_coordinate(coordinate, parser.control_coordinates) and value in labels)
            or (coordinate in parser.exact_control_coordinates
                and value == context.constructor_coordinates.get(family, {}).get(relative, {}).get(coordinate))}


class _OffsetJSON:
    """Validate all JSON; count inventory nodes and optional exact control slots.

    Coordinates are character intervals INCLUDING the original double quotes.
    The entropy scanner must compare its entire quoted match with this interval.
    """
    def __init__(self, text, control_coordinates=frozenset(), exact_control_coordinates=frozenset()):
        if type(text) is not str or len(text.encode('utf-8')) > MAX_DOCUMENT_BYTES:
            raise OperandRefusal('document_bytes')
        self.text = text
        self.index = 0
        self.nodes = 0
        self.strings = {}
        self.control_coordinates = control_coordinates
        self.exact_control_coordinates = frozenset(exact_control_coordinates)
        self.decoder = json.JSONDecoder()

    def whitespace(self):
        while self.index < len(self.text) and self.text[self.index] in ' \t\r\n':
            self.index += 1

    def value(self, path=(), depth=0):
        self.whitespace()
        if self.index >= len(self.text):
            raise OperandRefusal('truncated')
        targeted = any(path[:len(prefix)] == prefix and len(path) >= len(prefix) + 2
                       and path[len(prefix)] == 'scans' and path[len(prefix) + 1] in _METADATA_ARRAYS | {_DIAGNOSTIC_ARRAY}
                       for prefix in _REPORT_PREFIXES)
        targeted = targeted or path in self.exact_control_coordinates or _control_coordinate(path, self.control_coordinates)
        if targeted:
            self.nodes += 1
            if self.nodes > MAX_METADATA_NODES:
                raise OperandRefusal('metadata_nodes')
        char = self.text[self.index]
        if char in '{[':
            depth += 1
            if depth > MAX_DEPTH:
                raise OperandRefusal('depth')
            self.index += 1
            self.whitespace()
            result = {} if char == '{' else []
            close = '}' if char == '{' else ']'
            if self.index < len(self.text) and self.text[self.index] == close:
                self.index += 1
                return result
            while True:
                self.whitespace()
                if char == '{':
                    if self.index >= len(self.text) or self.text[self.index] != '"':
                        raise OperandRefusal('object_key')
                    key_start = self.index
                    key, end = self.decoder.raw_decode(self.text, self.index)
                    if key in result:
                        raise OperandRefusal('duplicate_key')
                    # Object keys are separate from value coordinates. Only an
                    # independently proved exact key gets a quote interval.
                    key_coordinate = (*path, ('object_key', key))
                    if key_coordinate in self.exact_control_coordinates:
                        self.nodes += 1
                        if self.nodes > MAX_METADATA_NODES:
                            raise OperandRefusal('metadata_nodes')
                        self.strings[key_coordinate] = (key_start, end, key)
                    self.index = end
                    self.whitespace()
                    if self.index >= len(self.text) or self.text[self.index] != ':':
                        raise OperandRefusal('colon')
                    self.index += 1
                    result[key] = self.value((*path, key), depth)
                else:
                    result.append(self.value((*path, len(result)), depth))
                self.whitespace()
                if self.index >= len(self.text):
                    raise OperandRefusal('truncated')
                token = self.text[self.index]
                self.index += 1
                if token == close:
                    return result
                if token != ',':
                    raise OperandRefusal('delimiter')
        start = self.index
        if char == '"':
            result, self.index = self.decoder.raw_decode(self.text, start)
            if targeted:
                self.strings[path] = (start, self.index, result)
            return result
        token = _JSON_PRIMITIVE.match(self.text, start)
        if token is None:
            raise OperandRefusal('primitive')
        self.index += len(token[0])
        result = json.loads(token[0])
        if type(result) is float and not math.isfinite(result):
            raise OperandRefusal('nonfinite')
        return result

    def parse(self):
        value = self.value()
        self.whitespace()
        if self.index != len(self.text):
            raise OperandRefusal('trailing')
        return value


def _strict_object(raw):
    parser = _OffsetJSON(raw.decode('utf-8', errors='strict'))
    value = parser.parse()
    if type(value) is not dict:
        raise OperandRefusal('not_object')
    return value


def _safe_component_path(value):
    return (type(value) is str and bool(value) and not PureWindowsPath(value).drive
            and not value.startswith('/') and '\\' not in value and ':' not in value
            and all(p not in {'', '.', '..'} for p in value.split('/'))
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _snapshot(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns,
            getattr(metadata, 'st_file_attributes', 0))


def _windows_birthtime(metadata):
    # Windows exposes a creation clock separately from the descriptor's
    # change clock in Python 3.12+. Never discard the raw descriptor snapshot.
    return (getattr(metadata, 'st_birthtime_ns', None)
            if hasattr(metadata, 'st_file_attributes') else None)


def _descriptor_matches_path(before, opened):
    expected, observed = _snapshot(before), _snapshot(opened)
    birthtime = _windows_birthtime(before)
    if type(birthtime) is int:
        if _windows_birthtime(opened) != birthtime:
            return False
        # Only align clocks when the path explicitly reports creation time.
        # Device/inode, mode, size, mtime and all attributes stay exact.
        if before.st_ctime_ns == birthtime:
            observed = observed[:5] + (birthtime,) + observed[6:]
    return expected == observed


def _descriptor_snapshot(metadata):
    return _snapshot(metadata), _windows_birthtime(metadata)


def _no_link(metadata):
    return not (stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, 'st_file_attributes', 0) & 0x400)


def _ancestor_snapshot(metadata):
    # Directory entries may change without replacing this observed parent.
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
            getattr(metadata, 'st_uid', None), getattr(metadata, 'st_gid', None),
            getattr(metadata, 'st_file_attributes', 0))


def _ancestor_observations(parents):
    observations = []
    for parent in parents:
        metadata = parent.lstat()
        if not _no_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise OperandRefusal('unsafe_ancestor')
        observations.append((parent, _ancestor_snapshot(metadata)))
    return observations


class ProofBudget:
    """One scan's NEW managed proof domain; older collectors retain their caps.

    Observed sizes are reserved before unbuffered reads and remain charged
    after refusal. Stable cached files are re-observed and reused uncharged.
    Reads do not count as selected-file coverage. Ancestor object identity and
    stat-visible security properties are re-observed; directory entry changes
    are allowed. Links and Windows reparse points are refused. These endpoint
    observations do not establish continuous namespace custody.
    """
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.bytes_read = 0
        self.cache = {}
        self.operands = {}
        self.reason = {}
        self.evidence = {}
        self.constructor_coordinates = {}

    def read(self, relative):
        if not _safe_component_path(relative):
            raise OperandRefusal('unsafe_operand')
        path = self.root.joinpath(*relative.split('/'))
        parents = list(reversed(path.parents))
        observations = _ancestor_observations(parents)
        before = path.lstat()
        if not _no_link(before) or not stat.S_ISREG(before.st_mode):
            raise OperandRefusal('unsafe_file')
        if before.st_size > MAX_DOCUMENT_BYTES:
            raise OperandRefusal('document_bytes')
        cached = self.cache.get(relative)
        if cached is not None:
            raw, identity, ancestors, descriptor_identity = cached
            if _snapshot(before) != identity or observations != ancestors:
                raise OperandRefusal('cached_substitution')
            if type(_windows_birthtime(before)) is int:
                descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
                try:
                    opened = os.fstat(descriptor)
                    if (not _descriptor_matches_path(before, opened)
                            or _descriptor_snapshot(opened) != descriptor_identity):
                        raise OperandRefusal('cached_substitution')
                finally:
                    os.close(descriptor)
                if (_snapshot(path.lstat()) != identity
                        or _ancestor_observations(parents) != ancestors):
                    raise OperandRefusal('cached_substitution')
            return raw
        allocation = getattr(self, 'shared_budget', self)
        if allocation.bytes_read + before.st_size > MAX_PROOF_BYTES:
            raise OperandRefusal('proof_bytes')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(descriptor)
            descriptor_identity = _descriptor_snapshot(opened)
            if not _descriptor_matches_path(before, opened):
                raise OperandRefusal('substitution')
            # Reserve the maximum bytes this attempt may consume. Never refund
            # refusal, short read or I/O failure; unstable bytes are never cached.
            allocation.bytes_read += before.st_size
            if allocation is not self:
                self.bytes_read += before.st_size
            with os.fdopen(descriptor, 'rb', buffering=0, closefd=False) as stream:
                raw = stream.read(before.st_size)
            if len(raw) != before.st_size or _descriptor_snapshot(os.fstat(descriptor)) != descriptor_identity:
                raise OperandRefusal('unstable_read')
        finally:
            os.close(descriptor)
        if _snapshot(path.lstat()) != _snapshot(before):
            raise OperandRefusal('substitution')
        if _ancestor_observations(parents) != observations:
            raise OperandRefusal('ancestor_substitution')
        self.cache[relative] = (raw, _snapshot(before), observations, descriptor_identity)
        return raw

    def entries(self, relative):
        """Bounded saved-chain namespace membership, rechecked at admission."""
        if not _safe_component_path(relative): raise OperandRefusal('unsafe_directory')
        path = self.root.joinpath(*relative.split('/'))
        ancestors = _ancestor_observations(list(reversed(path.parents)))
        before = path.lstat()
        if not _no_link(before) or not stat.S_ISDIR(before.st_mode): raise OperandRefusal('unsafe_directory')
        names = []; name_bytes = 0
        with os.scandir(path) as directory:
            for child in directory:
                name_bytes += len(child.name.encode('utf-8'))
                if len(names) >= MAX_IDENTITIES or name_bytes > MAX_DOCUMENT_BYTES:
                    raise OperandRefusal('directory_entries')
                names.append(child.name)
        names = tuple(sorted(names))
        if _ancestor_snapshot(path.lstat()) != _ancestor_snapshot(before) or _ancestor_observations(list(reversed(path.parents))) != ancestors:
            raise OperandRefusal('directory_substitution')
        observed = (names, _ancestor_snapshot(before), ancestors)
        if not hasattr(self, 'directory_cache'): self.directory_cache = {}
        if relative in self.directory_cache and self.directory_cache[relative] != observed:
            raise OperandRefusal('directory_membership_changed')
        self.directory_cache[relative] = observed
        return names

    def object(self, relative):
        return _strict_object(self.read(relative))

    def verify_cached(self):
        for relative in getattr(self, 'directory_cache', {}):
            self.entries(relative)
        if hasattr(self, 'schema_context'):
            self.schema_context.verify_cached()
        for relative in self.cache:
            self.read(relative)

    def admission_checkpoint(self):
        """Direct helper callers verify the entire proof before admitting a span."""
        self.verify_cached()


class _ScannerProofBudget(ProofBudget):
    """Provisional control spans, committed only by one scan's final checkpoint.

    Constructor checkpoints and each read retain their existing observations.
    Only control-record admission sweeps are deferred. A cached read refusal is
    sticky even if a caller catches it and later restores the observed object.
    """
    def __init__(self, root):
        super().__init__(root)
        self._invalidated = False

    def read(self, relative):
        if self._invalidated:
            raise OperandRefusal('scan_proof_invalidated')
        try:
            return super().read(relative)
        except (OSError, OperandRefusal):
            if type(relative) is str and relative in self.cache:
                self._invalidated = True
            raise

    def entries(self, relative):
        if self._invalidated: raise OperandRefusal('scan_proof_invalidated')
        try:
            return super().entries(relative)
        except (OSError, OperandRefusal):
            if relative in getattr(self, 'directory_cache', {}): self._invalidated = True
            raise

    def admission_checkpoint(self):
        if self._invalidated:
            raise OperandRefusal('scan_proof_invalidated')

    def finish_scanner_batch(self):
        """Refuse before returning a report; expose no provisional allowances."""
        try:
            self.verify_cached()
        except (OSError, OperandRefusal):
            self._invalidated = True
            raise OperandRefusal('scan_proof_invalidated') from None



def _proved_inventory_directories(context, operands, root):
    """Proper native parents of linked, byte-proved operands only.

    Each parent was checked as a non-link, non-reparse directory by read(),
    and verify_cached() rechecks its object identity/security before admission.
    Ordinary directory existence and a report's claimed status grant nothing.
    The scanner's terminal checkpoint retains the same endpoint observations.
    """
    root = Path(root).absolute()
    result = set()
    for relative in operands:
        cached = context.cache.get(relative)
        if cached is None:
            continue  # A saved directory label alone supplies no native witness.
        for parent, _identity in cached[2]:
            if parent != root and parent.is_relative_to(root):
                value = parent.relative_to(root).as_posix()
                if _safe_component_path(value) and relative.startswith(value + '/'):
                    result.add(value)
                    if len(result) > MAX_IDENTITIES:
                        raise OperandRefusal('inventory_directory_identities')
    return result


def inventory_operand_spans(text, relative_report_path, root, naos_root, proof_context):
    """Return exact quote intervals at proven inventory or raw control-ID positions.

    The schema selects coordinates only. Membership requires independently
    linked producer records and actual raw base content. Legacy-v1/v2, Windows-v1 operation records and portable-v3 new-enrollment
    receipt chains use independent pure constructor proofs. Legacy-authority
    portable variants remain unsupported and receive no allowance.
    """
    diagnostic = {'status': 'not_applicable', 'matches': 0, 'proof_bytes': proof_context.bytes_read}
    try:
        if not _safe_component_path(relative_report_path) or not _safe_component_path(naos_root):
            return set(), diagnostic
        if _ri_record(relative_report_path):
            expected = _ri_constructor_coordinates(proof_context).get(relative_report_path, {})
            parser = _OffsetJSON(text, exact_control_coordinates=expected)
            parser.parse()
            if not expected or text.encode('utf-8') != proof_context.read(relative_report_path):
                raise OperandRefusal('ri_control_record')
            proof_context.admission_checkpoint()
            spans = {(start,end) for coordinate,(start,end,value) in parser.strings.items()
                     if value == expected.get(coordinate)}
            diagnostic.update(status='proved',matches=len(spans),proof_bytes=proof_context.bytes_read)
            return spans, diagnostic
        family, coordinates = _control_record(relative_report_path)
        parser = _OffsetJSON(text, coordinates)
        if family == _MANAGED_ROOT:
            parser.exact_control_coordinates = frozenset(
                _legacy_constructor_coordinates(proof_context).get(relative_report_path, {}))
        if family == _WINDOWS_ROOT:
            parser.exact_control_coordinates = frozenset(
                _windows_constructor_coordinates(proof_context).get(relative_report_path, {}))
        report = parser.parse()
        if family is not None:
            spans = _control_id_spans(text, relative_report_path, parser, family, proof_context)
            diagnostic.update(status='proved', matches=len(spans), proof_bytes=proof_context.bytes_read)
            return spans, diagnostic
        def bound(value, schema):
            return (type(value) is dict and value.get('schema') == schema
                    and value.get('project_root') == str(Path(root).absolute())
                    and value.get('naos_root') == naos_root)
        def at(value, prefix):
            for key in prefix:
                if type(value) is not dict:
                    return None
                value = value.get(key)
            return value
        prefixes = []
        if bound(report, 'naos.secret_hygiene.v1'):
            prefixes = [()]
        elif bound(report, 'naos.evidence_pack.v1'):
            prefixes = [_REPORT_PREFIXES[1]]
        elif bound(report, 'naos.dashboard_summary.v1'):
            prefixes = [_REPORT_PREFIXES[2]]
            if bound(at(report, ('inputs', 'evidence_pack', 'data')), 'naos.evidence_pack.v1'):
                prefixes.append(_REPORT_PREFIXES[3])
        candidates = []
        directory_candidates = []
        for prefix in prefixes:
            inner = at(report, prefix)
            if not bound(inner, 'naos.secret_hygiene.v1'):
                continue
            scans = inner.get('scans')
            if type(scans) is not dict:
                raise OperandRefusal('scans_shape')
            for key in _METADATA_ARRAYS:
                rows = scans.get(key, [])
                if type(rows) is not list:
                    raise OperandRefusal('inventory_shape')
                for index, row in enumerate(rows):
                    if key == 'unassessed_suffix_files':
                        if type(row) is not str:
                            raise OperandRefusal('inventory_shape')
                        coordinate = (*prefix, 'scans', key, index)
                    else:
                        statuses = ({'read', 'read_error', 'decode_error', 'symlink'} if key == 'input_files'
                                    else {'selected', 'unselected_suffix', 'unselected_file', 'excluded', 'symlink', 'read_error', 'directory'})
                        if (type(row) is not dict
                                or type(row.get('path')) is not str or type(row.get('status')) is not str
                                or row['status'] not in statuses):
                            raise OperandRefusal('inventory_shape')
                        if set(row) == {'path', 'status'}:
                            pass  # Legacy read rows and non-read inventory observations.
                        elif (key == 'input_files' and row['status'] == 'read'
                              and set(row) == {'path', 'status', 'sha256', 'size_bytes'}):
                            _hex(row['sha256'])
                            if type(row['size_bytes']) is not int or row['size_bytes'] < 0:
                                raise OperandRefusal('inventory_shape')
                        else:
                            raise OperandRefusal('inventory_shape')
                        coordinate = (*prefix, 'scans', key, index, 'path')
                    token = parser.strings.get(coordinate)
                    if token is not None and (token[2] == _RI_WINDOWS_RUNTIME or any(token[2].startswith(r + '/') for r in (_MANAGED_ROOT, _WINDOWS_ROOT, _PORTABLE_ROOT, _RI_ROOT, _RI_TRANSACTIONS, _RI_WINDOWS_RUNTIME))):
                        candidates.append(token)
                        if key == 'scope_inventory' and row['status'] == 'directory':
                            directory_candidates.append(token)
            # Producer proof diagnostics are coverage metadata, not proof authority.
            # Refused, partial and malformed rows cannot grant an allowance or
            # change the independent treatment of older inventory arrays.
            rows = scans.get(_DIAGNOSTIC_ARRAY, [])
            if type(rows) is list:
                for index, row in enumerate(rows):
                    if (type(row) is not dict
                            or set(row) != {'path', 'status', 'matches', 'proof_bytes'}
                            or row['status'] != 'proved'
                            or not _safe_component_path(row['path'])
                            or type(row['matches']) is not int
                            or not 0 <= row['matches'] <= MAX_REPRESENTATIONS
                            or type(row['proof_bytes']) is not int
                            or not 0 <= row['proof_bytes'] <= MAX_PROOF_BYTES):
                        continue
                    coordinate = (*prefix, 'scans', _DIAGNOSTIC_ARRAY, index, 'path')
                    token = parser.strings.get(coordinate)
                    if token is not None and (token[2] == _RI_WINDOWS_RUNTIME or any(token[2].startswith(r + '/') for r in (_MANAGED_ROOT, _WINDOWS_ROOT, _PORTABLE_ROOT, _RI_ROOT, _RI_TRANSACTIONS, _RI_WINDOWS_RUNTIME))):
                        candidates.append(token)
        if not candidates:
            return set(), diagnostic
        operands = set()
        refusals = []
        for family, prove in ((_MANAGED_ROOT, _legacy_operands), (_WINDOWS_ROOT, _windows_operands), (_PORTABLE_ROOT, _portable_operands)):
            if not any(token[2].startswith(family + '/') for token in candidates):
                continue
            if family not in proof_context.operands and family not in proof_context.reason:
                try:
                    proof_context.operands[family] = prove(proof_context)
                    proof_context.evidence[family] = {"kind": family, "input_sha256": {relative: hashlib.sha256(row[0]).hexdigest() for relative, row in proof_context.cache.items() if relative.startswith(family + "/")}}
                except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError) as exc:
                    proof_context.reason[family] = type(exc).__name__
            if family in proof_context.reason:
                refusals.append({'family':family, 'reason':proof_context.reason[family]})
            else:
                operands.update(proof_context.operands[family])
                if family == _WINDOWS_ROOT:
                    operands.update(_windows_new_enrollment_carrier_operands(proof_context))
        if any(token[2] == _RI_WINDOWS_RUNTIME or token[2].startswith(r + '/') for token in candidates for r in (_RI_ROOT, _RI_TRANSACTIONS, _RI_WINDOWS_RUNTIME)):
            if _ri_constructor_coordinates(proof_context):
                operands.update(proof_context.operands[_RI_ROOT])
            else:
                refusals.append({'family':_RI_ROOT, 'reason':'constructor_refused'})
        proof_context.verify_cached()
        spans = {(start, end) for start, end, value in candidates if value in operands}
        if directory_candidates:
            directories = _proved_inventory_directories(proof_context, operands, root)
            spans.update((start, end) for start, end, value in directory_candidates
                         if value in directories)
        diagnostic.update(status='proved' if not refusals else 'partial_refusal', matches=len(spans), proof_bytes=proof_context.bytes_read)
        if refusals:
            diagnostic['refusals'] = refusals
        return spans, diagnostic
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError) as exc:
        diagnostic.update(status='refused', reason=type(exc).__name__, proof_bytes=proof_context.bytes_read)
        return set(), diagnostic


def _shape(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise OperandRefusal('shape')
    return value


def _hex(value, length=64):
    if type(value) is not str or re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is None:
        raise OperandRefusal('digest')
    return value


def _integrity(value, algorithm='sha256'):
    integrity = _shape(value.get('integrity'), 'algorithm canonicalization scope value')
    digest = (canonical_sha256 if algorithm == 'sha256' else canonical_sha3_512)(
        {k: v for k, v in value.items() if k != 'integrity'})
    if integrity != dict(algorithm=algorithm, canonicalization='rfc8785', scope='object_without_integrity', value=digest):
        raise OperandRefusal('integrity')
    return digest


def _same(value, expected):
    if any(value.get(k) != v or type(value.get(k)) is not type(v) for k, v in expected.items()):
        raise OperandRefusal('link')


def _list(value):
    if type(value) is not list or len(value) > MAX_IDENTITIES:
        raise OperandRefusal('inventory')
    return value


def _identity(value):
    _shape(value, 'kind mode size sha256')
    if (value['kind'] != 'file' or type(value['mode']) is not int or not 0 <= value['mode'] <= 0o7777
            or type(value['size']) is not int or value['size'] < 0):
        raise OperandRefusal('identity')
    _hex(value['sha256'])
    return value


def _raw_base(context, relative, digest, size):
    _hex(digest)
    if type(size) is not int or size < 0:
        raise OperandRefusal('base_size')
    raw = context.read(relative)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise OperandRefusal('base_preimage')
    return relative


def _legacy_operands(context):
    scope = _shape(context.object(_MANAGED_ROOT + '/scope.json'),
                   'schema canonicalization project_id owner_integrity_sha3_512 scope_id capability_id policy enrollment integrity')
    _same(scope, dict(schema='naos.upgrade.managed_content_scope.v1', canonicalization='rfc8785',
                      scope_id='managed-content', capability_id='CAP-CONTENT-AWARE-UPGRADE'))
    if type(scope['project_id']) is not str or not scope['project_id']:
        raise OperandRefusal('project')
    _hex(scope['owner_integrity_sha3_512'], 128)
    enrollment = _shape(scope['enrollment'], 'authorization_sha256 source_policy_sha256')
    _hex(enrollment['authorization_sha256']); _hex(enrollment['source_policy_sha256'])
    scope_digest = _integrity(scope, 'sha3-512')
    policy = {'ownership_inference': 'forbidden', 'existing_without_valid_base': 'preserve_and_refuse',
              'manifest_path': _MANAGED_ROOT + '/state/manifest.json', 'base_store': _MANAGED_ROOT + '/state/bases',
              'receipt_root': _MANAGED_ROOT + '/state/receipts', 'transaction_root': _MANAGED_ROOT + '/transactions',
              'lock_path': _MANAGED_ROOT + '/lock', 'allowed_initial_mutation': 'absent_regular_files_only',
              'existing_content_replacement': 'refused_without_reviewed_contract'}
    if scope['policy'] != policy:
        raise OperandRefusal('scope_policy')
    manifest = context.object(_MANAGED_ROOT + '/state/manifest.json')
    v2 = manifest.get('schema') == 'naos.upgrade.managed_content_manifest.v2'
    _shape(manifest, 'schema project_id scope_integrity_sha3_512 source_policy_sha256 previous_integrity_sha256 last_transaction_id last_plan_sha256 entries transactions integrity' + (' minimum_recovery_naos_version' if v2 else ''))
    _same(manifest, dict(schema='naos.upgrade.managed_content_manifest.' + ('v2' if v2 else 'v1'),
                         project_id=scope['project_id'], scope_integrity_sha3_512=scope_digest,
                         source_policy_sha256=enrollment['source_policy_sha256']))
    if v2: _same(manifest, {'minimum_recovery_naos_version': '1.1.0'})
    _integrity(manifest)
    if manifest['previous_integrity_sha256'] is not None: _hex(manifest['previous_integrity_sha256'])
    transactions = _list(manifest['transactions']); entries = _list(manifest['entries'])
    if not transactions or not entries: raise OperandRefusal('empty')
    by_id = {}; result = set(); bases_by_tid = {}
    for t in transactions:
        _shape(t, 'transaction_id plan receipt_sha256')
        tid = t['transaction_id']; plan = t['plan']; _hex(t['receipt_sha256'])
        if type(tid) is not str or re.fullmatch(r'MC-[0-9a-f]{16}-[0-9a-f]{8}', tid) is None or tid in by_id:
            raise OperandRefusal('transaction_id')
        schema = plan.get('schema') if type(plan) is dict else None
        content = schema in {'naos.upgrade.content_aware_plan.v1', 'naos.upgrade.content_aware_plan.v2'}
        if content:
            keys = 'schema operation status project profile request_inputs creation_identity source_policy manifest paths ownership_inference planning_mutated_target apply_requires_separate_digest_bound_invocation plan_sha256'
            if schema.endswith('.v2'): keys += ' selected_paths operation_inputs checks'
            elif 'checks' in plan: keys += ' checks'
            _shape(plan, keys)
            _shape(plan['project'], 'root_binding project_id scope_integrity_sha3_512')
            _same(plan['project'], dict(root_binding=str(context.root), project_id=scope['project_id'], scope_integrity_sha3_512=scope_digest))
            provenance = plan['source_policy'].get('provenance')
            if type(provenance) is not dict or provenance.get('binding_sha256') != enrollment['source_policy_sha256']:
                raise OperandRefusal('plan_policy')
        else:
            if schema not in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
                raise OperandRefusal('plan_schema')
            _shape(plan, 'schema operation status project_root_binding source_policy_sha256 creation_identity inputs paths replacement_allowed ownership_inference plan_sha256' + (' preconditions' if schema.endswith('.v2') else ''))
            _same(plan, dict(project_root_binding=str(context.root), source_policy_sha256=enrollment['source_policy_sha256'], replacement_allowed=False))
        if type(plan['operation']) is not str or not plan['operation'] or plan['status'] != ('ready' if content else 'ready_create_only'):
            raise OperandRefusal('plan_control')
        if content:
            _same(plan, {'planning_mutated_target':False, 'apply_requires_separate_digest_bound_invocation':True})
        digest = canonical_sha256({k: v for k, v in plan.items() if k != 'plan_sha256'})
        _same(plan, dict(plan_sha256=digest, ownership_inference='forbidden'))
        if tid[3:19] != digest[:16]: raise OperandRefusal('transaction_prefix')
        planned = {}; identities = []
        for item in _list(plan['paths']):
            keys = ('path base before after base_metadata before_metadata after_metadata content_state ownership source_policy preservation action mutation metadata_status ancestor_identities' if content else
                    'path source source_metadata base current content_state ownership creation_policy source_policy_rule action ancestor_identities')
            _shape(item, keys)
            if not _safe_component_path(item['path']) or item['path'] in planned: raise OperandRefusal('plan_path')
            planned[item['path']] = item
            if not content: identities.append(_identity(item['source']))
            elif type(item['mutation']) is dict and item['mutation'].get('eligible') is True:
                after = item['after']
                if type(after) is not dict or after.get('presence') != 'present': raise OperandRefusal('after')
                identities.append(_identity({k: after[k] for k in ('kind','mode','size','sha256')}))
        journal_path = _MANAGED_ROOT + '/transactions/' + tid + '/journal.json'
        receipt_path = _MANAGED_ROOT + '/state/receipts/' + tid + '.json'
        journal = context.object(journal_path); receipt = context.object(receipt_path)
        compact = content and journal.get('schema') == 'naos.upgrade.content_transaction.compact.v1'
        sidecar_path = journal_path.rsplit('/', 1)[0] + '/plan.json'
        if compact:
            _shape(journal, 'schema minimum_recovery_naos_version transaction_id plan_ref state applied_actions created_directories pending_action detail integrity')
            _same(journal, dict(transaction_id=tid, state='COMMITTED'))
            _integrity(journal)
            reference = _shape(journal['plan_ref'], 'name sha256 size')
            _same(reference, {'name':'plan.json'}); _hex(reference['sha256'])
            raw_plan = context.read(sidecar_path)
            if (type(reference['size']) is not int or reference['size'] != len(raw_plan)
                    or hashlib.sha256(raw_plan).hexdigest() != reference['sha256']
                    or canonical_bytes(plan) + b'\n' != raw_plan):
                raise OperandRefusal('compact_plan_binding')
        else:
            _shape(journal, ('schema minimum_recovery_naos_version transaction_id plan state applied_actions created_directories pending_action detail integrity' if content else
                             'schema transaction_id plan state applied_paths applied_identities created_directories pending_action detail integrity'))
            _same(journal, dict(schema='naos.upgrade.content_transaction.v2' if content else 'naos.upgrade.create_only_transaction.v1', transaction_id=tid, plan=plan, state='COMMITTED'))
            _integrity(journal)
        _shape(receipt, ('schema minimum_recovery_naos_version project_id scope_integrity_sha3_512 source_policy_sha256 transaction_id plan_sha256 status actions replacement_performed integrity' if content else
                         'schema project_id scope_integrity_sha3_512 source_policy_sha256 transaction_id plan_sha256 status paths created_metadata replacement_performed integrity'))
        _same(receipt, dict(schema='naos.upgrade.managed_content_receipt.' + ('v2' if content else 'v1'), project_id=scope['project_id'], scope_integrity_sha3_512=scope_digest, source_policy_sha256=enrollment['source_policy_sha256'], transaction_id=tid, plan_sha256=digest, status='COMMITTED'))
        if content:
            _same(receipt, dict(minimum_recovery_naos_version='1.1.0')); _same(journal, dict(minimum_recovery_naos_version='1.1.0'))
            mutations = [i for i in planned.values() if type(i['mutation']) is dict and i['mutation'].get('eligible') is True]
            actions = _list(receipt['actions'])
            if len(actions) != len(mutations): raise OperandRefusal('receipt_actions')
            for a, item in zip(actions, mutations):
                _shape(a, 'path kind before after before_metadata after_metadata installed_metadata backup_metadata base_blob publication_adapter')
                _same(a, {k:item[k] for k in ('path','before','after','before_metadata','after_metadata')})
                _same(a, {'kind':item['mutation']['kind'], 'base_blob':{'path':item['after']['sha256'], 'sha256':item['after']['sha256']}})
        else:
            _same(receipt, {'paths': plan['paths'], 'replacement_performed':False})
        _integrity(receipt)
        if canonical_sha256(receipt) != t['receipt_sha256']: raise OperandRefusal('receipt_hash')
        bases_by_tid[tid] = {i['sha256']:i for i in identities}; by_id[tid] = t
        # Each exact transaction operand is backed by the independent committed chain.
        result.update({journal_path, receipt_path, _MANAGED_ROOT + '/transactions/' + tid})
        if compact: result.add(sidecar_path)
        for i in identities:
            result.add(_raw_base(context, _MANAGED_ROOT + '/state/bases/' + i['sha256'], i['sha256'], i['size']))
    _same(manifest, {'last_transaction_id':transactions[-1]['transaction_id'], 'last_plan_sha256':transactions[-1]['plan']['plan_sha256']})
    seen = set()
    for e in entries:
        _shape(e, 'path ownership creation_policy base source_metadata base_blob created_metadata introduced_by_transaction receipt_sha256' + (' last_mutated_by_transaction' if v2 else ''))
        if not _safe_component_path(e['path']) or e['path'] in seen: raise OperandRefusal('entry_path')
        seen.add(e['path']); i = _identity(e['base']); tid = e.get('last_mutated_by_transaction', e['introduced_by_transaction'])
        if (e['introduced_by_transaction'] not in by_id or tid not in by_id or i != bases_by_tid[tid].get(i['sha256'])
                or e['receipt_sha256'] != by_id[tid]['receipt_sha256']
                or e['base_blob'] != {'path':i['sha256'], 'sha256':i['sha256']}): raise OperandRefusal('entry_link')
    if len(result) > MAX_IDENTITIES: raise OperandRefusal('identities')
    context.verify_cached()
    return result


def _legacy_owner(context):
    owner_path = '.naos/upgrade-v1/OWNER.json'
    owner = _shape(context.object(owner_path),
        'schema canonicalization project_id control_root owner_kind created_by enrollment_authorization integrity')
    _same(owner, dict(schema='naos.upgrade.control_root_owner.v1', canonicalization='rfc8785',
        control_root='.naos/upgrade-v1', owner_kind='naos_operation_control_root'))
    creator = _shape(owner['created_by'], 'kit_id kit_version source_commit source_manifest_sha256')
    _same(creator, {'kit_id':'naos-governance'})
    if type(creator['kit_version']) is not str or not creator['kit_version']:
        raise OperandRefusal('owner_creator')
    _hex(creator['source_manifest_sha256'])
    commit = creator['source_commit']
    if commit is not None and (type(commit) is not str or re.fullmatch(r'[0-9a-f]{40}', commit) is None):
        raise OperandRefusal('owner_commit')
    authorization = _shape(owner['enrollment_authorization'], 'plan_sha256 review_receipt_sha256')
    _hex(authorization['plan_sha256'])
    if authorization['review_receipt_sha256'] is not None:
        _hex(authorization['review_receipt_sha256'])
    project = owner['project_id']
    if type(project) is not str or project != 'urn:uuid:' + str(uuid.UUID(project.removeprefix('urn:uuid:'))):
        raise OperandRefusal('owner_project')
    owner_digest = _integrity(owner, 'sha3-512')
    return owner, owner_digest


def _legacy_constructor_coordinates(context):
    """Exact linked owner project labels, never UUID shape or body membership.

    The existing committed constructor proves the root-bound plans and raw
    bases. OWNER validation adds its canonical public UUID and scope link.
    This establishes local consistency, not producer authenticity or ownership.
    An absent/unsupported owner leaves older transaction-ID proofs unchanged.
    """
    if _MANAGED_ROOT in context.constructor_coordinates:
        return context.constructor_coordinates[_MANAGED_ROOT]
    result = {}
    try:
        _ensure_control_family(context, _MANAGED_ROOT)
        if _MANAGED_ROOT in context.reason:
            raise OperandRefusal('control_chain')
        owner_path = '.naos/upgrade-v1/OWNER.json'
        owner, owner_digest = _legacy_owner(context)
        project = owner['project_id']
        scope_path = _MANAGED_ROOT + '/scope.json'
        scope = context.object(scope_path)
        _same(scope, {'project_id':project, 'owner_integrity_sha3_512':owner_digest})
        manifest_path = _MANAGED_ROOT + '/state/manifest.json'
        manifest = context.object(manifest_path)
        result = {path:{('project_id',):project} for path in (owner_path, scope_path, manifest_path)}
        for transaction in manifest['transactions']:
            receipt = _MANAGED_ROOT + '/state/receipts/' + transaction['transaction_id'] + '.json'
            result[receipt] = {('project_id',):project}
            if transaction['plan']['schema'].startswith('naos.upgrade.content_aware_plan.'):
                journal = _MANAGED_ROOT + '/transactions/' + transaction['transaction_id'] + '/journal.json'
                if context.object(journal).get('schema') == 'naos.upgrade.content_transaction.compact.v1':
                    result[journal.rsplit('/', 1)[0] + '/plan.json'] = {('project','project_id'):project}
                else:
                    result[journal] = {('plan','project','project_id'):project}
        for relative, coordinates in _legacy_ri_binding_coordinates(context, manifest).items():
            result.setdefault(relative, {}).update(coordinates)
        context.verify_cached()
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        result = {}
    context.constructor_coordinates[_MANAGED_ROOT] = result
    return result


_RI_ROOT = '.naos/upgrade-v1/state/repository-intelligence'
_RI_WINDOWS_RUNTIME = '.naos/upgrade-v1/windows-ri-runtime'
_RI_TRANSACTIONS = '.naos/upgrade-v1/transactions/repository-intelligence'
_RI_SCOPE = '.naos/upgrade-v1/provenance/scopes/repository-intelligence.json'
_RI_WINDOWS_BOOTSTRAP = '.naos/upgrade-v1/windows-ri-runtime.json'
_RI_WINDOWS_ACTIVE_SCHEMA = 'naos.repository_intelligence.windows_active.v1'
_RI_SCOPE_SCHEMA = 'naos.upgrade.capability_scope.v1'
_RI_LOCK = '.naos/upgrade-v1/locks/repository-intelligence.lock'
_RI_SUPPORTED_TUPLES = (
    ('Darwin', 'arm64', 'macos_arm64_cpython_3_11_to_3_13_binary_wheels'),
    ('Darwin', 'aarch64', 'macos_arm64_cpython_3_11_to_3_13_binary_wheels'),
    ('Linux', 'x86_64', 'linux_x86_64_cpython_3_11_to_3_13_binary_wheels'),
    ('Linux', 'aarch64', 'linux_aarch64_cpython_3_11_to_3_13_binary_wheels'),
)
_RI_SCHEMAS = {'repository_intelligence_active': '8118d030a7664d546cf3aa13e2e5bf8870c254c769a34d276671e3853830ed40', 'repository_intelligence_manifest': '48b2d48beb051c0b7a9fa2109e503388d906d04be10f4ad800e305ba63fa274a', 'repository_intelligence_validation': 'fbd89f17ed0fef16f26d5921d3b96d1b3cb6a6d755fd3493b5bacfa83b580a9f', 'repository_intelligence_activation_receipt': 'a5c4767077ece941fef0325c5b95ebc5708beb58216b0379adb0ad1a68f4df36', 'repository_intelligence_transaction_journal': '8a50790e91fb53b4b2bfaa07eecd79a8984ca58004fe3255e9b63659960baa4a', 'repository_intelligence_inventory': '9545e92239a7021e6e494eaf0789cc30bc9f6938a337ad02564f3187117039a6'}


def _ri_record(relative):
    return (relative == _RI_SCOPE or relative in {'.naos/upgrade-v1/windows-repository-intelligence.json', _RI_WINDOWS_BOOTSTRAP}
        or re.fullmatch(r'\.naos/upgrade-v1/windows-ri-runtime/(?:preparations|receipts)/WOP-[0-9a-f]{16}\.json',relative) is not None
        or re.fullmatch(r'\.naos/upgrade-v1/windows-ri-runtime/operations/WOP-[0-9a-f]{16}/(?:plan|intent)\.json',relative) is not None
        or relative == _RI_ROOT + '/active.json'
        or re.fullmatch(re.escape(_RI_ROOT) + r'/generations/RI-[0-9a-f]{24}/(?:manifest|validation_receipt|inventory)\.json', relative) is not None
        or re.fullmatch(re.escape(_RI_TRANSACTIONS) + r'/RIT-[0-9a-f]{24}/(?:journal|receipt)\.json', relative) is not None)


def _ri_object(context, relative, schema):
    from jsonschema import Draft202012Validator
    if not hasattr(context, 'schema_context'):
        context.schema_context = ProofBudget(Path(__file__).absolute().parents[1])
        context.schema_context.shared_budget = context
    proof = context.schema_context
    raw = proof.read('schemas/naos/' + schema + '.schema.json')
    if context.bytes_read > MAX_PROOF_BYTES or hashlib.sha256(raw).hexdigest() != _RI_SCHEMAS[schema]:
        raise OperandRefusal('ri_schema')
    value = context.object(relative)
    if next(Draft202012Validator(_strict_object(raw)).iter_errors(value), None) is not None:
        raise OperandRefusal('ri_shape')
    return value


def _ri_reference_coordinates(context, inventory):
    from naos_local_context_index import recompute_public_artifact_id, link_records
    artifacts = {}; sources = {}
    for artifact in _list(inventory['artifacts']):
        label = recompute_public_artifact_id(artifact); path = artifact.get('path')
        if label is None or path in artifacts: raise OperandRefusal('ri_artifact')
        raw = context.read(path)
        if hashlib.sha256(raw).hexdigest() != artifact.get('source_hash'): raise OperandRefusal('ri_source')
        artifacts[path] = label; sources[path] = raw.decode('utf-8', errors='strict')
    result = {}
    for index,row in enumerate(_list(inventory['relationships'])):
        source = row.get('source_path'); target = row.get('target_path'); expected_source = 'artifact:'+artifacts.get(source,'')
        if source not in artifacts or row.get('source_node') != expected_source: raise OperandRefusal('ri_relationship')
        result[('relationships',index,'source_node')] = expected_source
        if target in artifacts and row.get('target_node') == 'artifact:'+artifacts[target]:
            result[('relationships',index,'target_node')] = 'artifact:'+artifacts[target]
        elif row.get('relationship_type') in {'task_ref','spec_ref','capability_ref'}:
            link = dict(source_path=source,link_type=row['relationship_type'],reference_id=row.get('reference_id'))
            prefix = {'task_ref':'task','spec_ref':'spec','capability_ref':'capability'}[row['relationship_type']]
            expected_target = prefix+':'+str(row.get('reference_id'))
            if link not in link_records(source,sources[source]) or row.get('target_node') != expected_target: raise OperandRefusal('ri_reference')
            result[('relationships',index,'target_node')] = expected_target
    return result


def _ri_constructor_coordinates(context):
    """Saved POSIX RI control-label consistency, never native runtime authority.

    Reuse the producer schemas and exact active/manifest/receipt/journal links.
    Only fixed policy slots, linked current generation labels and independently rederived reference slots enter
    the result. Saved Windows RI v2 genesis records use a separate pure parser.
    """
    if _RI_ROOT in context.constructor_coordinates:
        return context.constructor_coordinates[_RI_ROOT]
    result = {}
    try:
        if context.object(_RI_ROOT+'/active.json').get('schema') == _RI_WINDOWS_ACTIVE_SCHEMA:
            from naos_secret_ri_windows_operands import constructor_coordinates
            return constructor_coordinates(context)
        owner, owner_digest = _legacy_owner(context)
        project = owner['project_id']
        scope = _shape(context.object(_RI_SCOPE), 'schema canonicalization project_id owner_integrity_sha3_512 scope_id capability_id governed_root policy enrollment integrity')
        _same(scope, dict(schema=_RI_SCOPE_SCHEMA, canonicalization='rfc8785',
            project_id=project, owner_integrity_sha3_512=owner_digest, scope_id='repository-intelligence',
            capability_id='CAP-LOCAL-CONTEXT-INDEX', governed_root=_RI_ROOT))
        policy = dict(initial_root_state='absent', existing_without_valid_chain='refuse', ownership_inference='forbidden',
            mutable_paths=[_RI_ROOT+'/active.json'], immutable_generation_root=_RI_ROOT+'/generations',
            transient_paths=[_RI_TRANSACTIONS+'/<transaction_id>/staging'], transaction_root=_RI_TRANSACTIONS,
            lock_path=_RI_LOCK, unknown_entries='refuse',
            generation_id_pattern='^RI-[0-9a-f]{24}$')
        if scope['policy'] != policy: raise OperandRefusal('ri_policy')
        enrollment = _shape(scope['enrollment'], 'plan_sha256 review_receipt_sha256 observed_governed_root_state')
        _same(enrollment, {'observed_governed_root_state':'absent'}); _hex(enrollment['plan_sha256'])
        if enrollment['review_receipt_sha256'] is not None: _hex(enrollment['review_receipt_sha256'])
        scope_digest = _integrity(scope, 'sha3-512')
        active_path = _RI_ROOT+'/active.json'
        active = _ri_object(context, active_path, 'repository_intelligence_active'); control = active['control']
        _same(active, {'active_sha256':canonical_sha256(control)})
        binding = dict(provenance_project_id=project, provenance_owner_sha3_512=owner_digest, provenance_scope_sha3_512=scope_digest)
        _same(control, binding)
        generation = _RI_ROOT+'/generations/'+control['generation_id']
        transaction = _RI_TRANSACTIONS+'/'+control['transaction_id']
        _same(control, dict(generation_id='RI-'+control['generation_content_sha256'][:24],
            manifest_path=generation+'/manifest.json', validation_receipt_path=generation+'/validation_receipt.json',
            activation_receipt_path=transaction+'/receipt.json'))
        loaded = {}
        for key, schema, digest_key in [('manifest','repository_intelligence_manifest','manifest_sha256'),
                ('validation_receipt','repository_intelligence_validation','receipt_sha256'),
                ('activation_receipt','repository_intelligence_activation_receipt','receipt_sha256')]:
            relative = control[key+'_path']; value = _ri_object(context, relative, schema)
            if hashlib.sha256(context.read(relative)).hexdigest() != control[key+'_file_sha256']:
                raise OperandRefusal('ri_preimage')
            _same(value, {digest_key:canonical_sha256(value['control'])})
            _same(control, {key+'_sha256':value[digest_key]})
            loaded[key] = value
        manifest = loaded['manifest']['control']; validation = loaded['validation_receipt']['control']; activation = loaded['activation_receipt']['control']
        _same(manifest, {key:control[key] for key in ('generation_id','generation_content_sha256','effective_source_sha256','profile','purpose','component_mode')})
        _same(manifest, dict(project_root=str(context.root), validation_receipt_sha256=loaded['validation_receipt']['receipt_sha256']))
        gate = dict(status='valid', project_id=project, owner_integrity_sha3_512=owner_digest,
            scope_integrity_sha3_512=scope_digest, governed_root=_RI_ROOT, ownership_inference='forbidden',
            legacy_bootstrap_allowed=False, activation_eligible=True, owner_path='.naos/upgrade-v1/OWNER.json',
            scope_path=_RI_SCOPE, refusal=None, enrollment_project_id=None)
        _same(manifest, {'provenance_gate':gate}); _same(validation, {'provenance_gate':gate})
        content_identity = {key:manifest[key] for key in ('project_root','profile','purpose','component_mode','effective_source_sha256','rules','runtime','implementation','provenance_gate','components','graph_model_sha256','ongoing_use_scope')}
        content_identity['capability_id'] = 'CAP-LOCAL-CONTEXT-INDEX'
        _same(manifest, {'generation_content_sha256':canonical_sha256(content_identity)})
        _same(validation, {key:manifest[key] for key in ('generation_id','generation_content_sha256','effective_source_sha256','profile','purpose','component_mode','runtime','implementation')})
        _same(activation, {key:control[key] for key in ('transaction_id','plan_sha256','bundle_sha256','generation_id','generation_content_sha256','manifest_file_sha256','manifest_sha256','validation_receipt_file_sha256','validation_receipt_sha256','profile','previous_generation_id')} | binding)
        journal_path = transaction+'/journal.json'; journal = _ri_object(context, journal_path, 'repository_intelligence_transaction_journal')
        _same(journal, dict(journal_sha256=canonical_sha256({k:v for k,v in journal.items() if k!='journal_sha256'}),
            state='COMMITTED', proposed_active_sha256=active['active_sha256'], proposed_active_file_sha256=hashlib.sha256(context.read(active_path)).hexdigest(),
            active_path=active_path, active_pending_path=_RI_ROOT+'/.active.json.pending', final_path=generation,
            staging_path=transaction+'/staging', context_staging_path=transaction+'/context'))
        _same(journal, {key:control[key] for key in ('transaction_id','plan_sha256','bundle_sha256','generation_id','generation_content_sha256')})
        records = {}
        for row in _list(manifest['files']):
            _shape(row, 'path sha256 size_bytes')
            if not _safe_component_path(row['path']) or '/' in row['path'] or row['path'] in records: raise OperandRefusal('ri_file')
            relative = generation+'/'+row['path']; _raw_base(context, relative, row['sha256'], row['size_bytes']); records[row['path']] = row
        if manifest['rules_snapshot'] not in records or records[manifest['rules_snapshot']]['sha256'] != manifest['rules'].get('sha256'):
            raise OperandRefusal('ri_rules_snapshot')
        expected_records = {**records, 'manifest.json':dict(path='manifest.json', sha256=control['manifest_file_sha256'], size_bytes=len(context.read(control['manifest_path'])))}
        if journal['staging_files'] != [expected_records[key] for key in sorted(expected_records)]: raise OperandRefusal('ri_file_links')
        inventory_path = generation+'/inventory.json'; inventory = _ri_object(context, inventory_path, 'repository_intelligence_inventory')
        _same(inventory, dict(project_root=str(context.root),generation_id=control['generation_id'],effective_source_sha256=control['effective_source_sha256']))
        result[_RI_SCOPE] = {('project_id',):project, ('schema',):scope['schema']}
        for key,value in policy.items():
            if type(value) is str and key.endswith(('_path','_root')): result[_RI_SCOPE][('policy',key)] = value
            elif type(value) is list:
                for index,operand in enumerate(value): result[_RI_SCOPE][('policy',key,index)] = operand
        result[active_path] = {('control',key):control[key] for key in ('manifest_path','validation_receipt_path','activation_receipt_path','provenance_project_id','transaction_id','generation_id')}
        result[transaction+'/receipt.json'] = {('control','provenance_project_id'):project, ('control','transaction_id'):control['transaction_id'], ('control','generation_id'):control['generation_id']}
        result[journal_path] = {(key,):journal[key] for key in ('active_path','active_pending_path','final_path','staging_path','context_staging_path','transaction_id','generation_id')}
        for relative in (generation+'/manifest.json',generation+'/validation_receipt.json'):
            result[relative] = {('control','provenance_gate','project_id'):project, ('control','generation_id'):control['generation_id']}
            platform = manifest['runtime']['platform']
            tuples = {(system, machine): label for system, machine, label in _RI_SUPPORTED_TUPLES}
            expected = tuples.get((platform.get('system'),platform.get('machine')))
            if (expected is not None and platform.get('supported_tuple') == expected
                    and platform.get('implementation') == 'CPython' and platform.get('supported_for_apply') is True
                    and type(platform.get('python')) is str and re.fullmatch(r'3\.1[123]\.[0-9]+', platform['python']) is not None):
                result[relative][('control','runtime','platform','supported_tuple')] = expected
        result[inventory_path] = _ri_reference_coordinates(context, inventory)
        result[inventory_path][('generation_id',)] = control['generation_id']
        context.verify_cached()
        context.operands[_RI_ROOT] = set(result) | {generation, transaction} | {generation+'/'+name for name in records}
    except (ImportError, OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        result = {}
    context.constructor_coordinates[_RI_ROOT] = result
    return result



# Exact immutable consumer binding produced by naos_init, not a label grammar.
_RI_GENERATION_BINDING_FIELDS = (
    'generation_id', 'generation_content_sha256', 'manifest_file_sha256', 'manifest_sha256',
    'validation_receipt_file_sha256', 'validation_receipt_sha256',
    'activation_receipt_file_sha256', 'activation_receipt_sha256',
    'effective_source_sha256', 'transaction_id', 'profile', 'purpose', 'component_mode',
)


def _legacy_ri_binding_coordinates(context, manifest):
    """Optional current RI binding in an independently committed MC plan.

    The caller has completed the MC proof. RI proof never calls this bridge;
    missing or mismatching RI cannot erase established MC operands. All reads
    still enter the existing shared custody checkpoint.
    """
    result = {}
    try:
        candidates = []
        for index, transaction in enumerate(manifest['transactions']):
            plan = transaction['plan']
            if plan['schema'] in {'naos.upgrade.create_only_plan.v1', 'naos.upgrade.create_only_plan.v2'}:
                input_field = 'inputs'
            elif plan['schema'] in {'naos.upgrade.content_aware_plan.v1', 'naos.upgrade.content_aware_plan.v2'}:
                journal_path = _MANAGED_ROOT + '/transactions/' + transaction['transaction_id'] + '/journal.json'
                if context.object(journal_path).get('schema') != 'naos.upgrade.content_transaction.compact.v1':
                    continue
                input_field = 'request_inputs'
            else:
                continue
            if type(plan[input_field]) is not dict:
                continue
            inputs = plan[input_field].get('repository_intelligence')
            if type(inputs) is dict and inputs.get('lifecycle_status') == 'validated_current':
                candidates.append((index, transaction, inputs, input_field))
        if not candidates:
            return result  # Unrelated MC plans need no additional RI reads.
        active_path = _RI_ROOT + '/active.json'
        proved = _ri_constructor_coordinates(context).get(active_path, {})
        transaction_id = proved.get(('control', 'transaction_id'))
        if transaction_id is None:
            return result
        active = context.object(active_path)['control']
        generation = {field: active[field] for field in _RI_GENERATION_BINDING_FIELDS}
        expected_binding = {'binding_type': 'validated_generation', 'generation': generation}
        for index, transaction, inputs, input_field in candidates:
            if inputs.get('binding') != expected_binding:
                continue
            journal = _MANAGED_ROOT + '/transactions/' + transaction['transaction_id'] + '/journal.json'
            for field in ('transaction_id', 'generation_id'):
                # Admit only labels independently proved in the current POSIX
                # active record, after the entire typed 13-field binding matches.
                label = proved.get(('control', field))
                if label is None:
                    continue
                suffix = (input_field, 'repository_intelligence', 'binding', 'generation', field)
                result.setdefault(_MANAGED_ROOT + '/state/manifest.json', {})[
                    ('transactions', index, 'plan', *suffix)] = label
                if context.object(journal).get('schema') == 'naos.upgrade.content_transaction.compact.v1':
                    result.setdefault(journal.rsplit('/', 1)[0] + '/plan.json', {})[suffix] = label
                else:
                    result.setdefault(journal, {})[('plan', *suffix)] = label
    except (ImportError, OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        result = {}
    return result


def _envelope(context, relative, schema, keys):
    if schema not in _SUPPORTED_SCHEMAS:
        raise OperandRefusal('unsupported_schema')
    raw = context.read(relative)
    value = _shape(_strict_object(raw), 'body sha256')
    body = _shape(value['body'], keys)
    _same(body, {'schema': schema})
    digest = canonical_sha256(body)
    if value['sha256'] != digest or canonical_bytes(value) != raw:
        raise OperandRefusal('record_digest')
    return body, digest


def _decimal(value):
    if (type(value) is not str or not value.isascii() or not value.isdecimal()
            or not 1 <= len(value) <= 20 or str(int(value)) != value):
        raise OperandRefusal('decimal')
    return int(value)


_PORTABLE_ROOT = '.naos/managed-content/v3'
_PORTABLE_MANIFEST_KEYS = 'schema project_id owner_sha256 previous_head_sha256 receipts entries inputs projection_sha256 head_receipt_sha256'


def _portable_operands(context):
    root = _PORTABLE_ROOT
    owner, owner_sha = _envelope(context, root + '/OWNER.json', 'naos.upgrade.portable_owner.v3',
                                 'schema project_id minimum_reader authority_kind authority_sha256')
    _same(owner, {'minimum_reader':3, 'authority_kind':'new_enrollment'})
    _hex(owner['authority_sha256'])
    if type(owner['project_id']) is not str or not owner['project_id']:
        raise OperandRefusal('portable_project')
    manifest, manifest_sha = _envelope(context, root + '/manifest.json', 'naos.upgrade.portable_manifest.v3', _PORTABLE_MANIFEST_KEYS)
    binding = {'project_id':owner['project_id'], 'owner_sha256':owner_sha}
    _same(manifest, binding)
    refs = _list(manifest['receipts']); seen = set(); result = set(); entries = {}; projections = []; previous = None
    if not refs: raise OperandRefusal('portable_empty')
    for index, ref in enumerate(refs, 1):
        _shape(ref, 'id sha256'); _hex(ref['sha256'])
        rid = f'R{index:08d}'
        if ref['id'] != rid or ref['sha256'] in seen: raise OperandRefusal('receipt_ref')
        seen.add(ref['sha256'])
        rp = root + '/receipts/' + ref['sha256'] + '.json'
        receipt, sha = _envelope(context, rp, 'naos.upgrade.portable_receipt.v3',
            'schema id project_id owner_sha256 previous_receipt_sha256 previous_projection_sha256 result_projection_sha256 operation inputs selected_paths changes policy_sha256 mode_inventory_sha256')
        _same(receipt, {**binding, 'id':rid, 'previous_receipt_sha256':previous,
                        'previous_projection_sha256':projections[-1] if projections else None})
        if sha != ref['sha256']: raise OperandRefusal('receipt_ref_digest')
        policy_sha = _hex(receipt['policy_sha256']); inventory_sha = _hex(receipt['mode_inventory_sha256'])
        pp = root + '/policies/' + policy_sha + '.json'
        raw = context.read(pp); policy = _shape(_strict_object(raw), 'snapshot_id policy')
        if canonical_bytes(policy) != raw or canonical_sha256(policy) != policy_sha: raise OperandRefusal('policy_digest')
        ip = root + '/mode-inventories/' + inventory_sha + '.json'
        inventory, actual = _envelope(context, ip, 'naos.upgrade.source_mode_inventory.v1', 'schema items')
        if actual != inventory_sha: raise OperandRefusal('inventory_digest')
        modes = {}
        for item in _list(inventory['items']):
            _shape(item, 'destination source_sha256 source_size_decimal output_sha256 output_size_decimal executable')
            if not _safe_component_path(item['destination']) or item['destination'] in modes: raise OperandRefusal('mode_path')
            _hex(item['source_sha256']); _hex(item['output_sha256']); _decimal(item['source_size_decimal']); _decimal(item['output_size_decimal'])
            if type(item['executable']) is not bool: raise OperandRefusal('mode_type')
            modes[item['destination']] = item
        selected = _list(receipt['selected_paths'])
        if any(not _safe_component_path(p) for p in selected) or selected != sorted(set(selected)): raise OperandRefusal('selected_paths')
        changed = set()
        for change in _list(receipt['changes']):
            _shape(change, 'path before after'); path = change['path']
            if not _safe_component_path(path) or path not in selected or path in changed: raise OperandRefusal('change_path')
            changed.add(path)
            if change['before'] != entries.get(path): raise OperandRefusal('before_link')
            after = _shape(change['after'], 'path content ownership creation_policy introduced_policy_sha256 introduced_by latest_base_receipt')
            _same(after, {'path':path}); _hex(after['introduced_policy_sha256'])
            content = after['content']
            if content is not None:
                _shape(content, 'kind sha256 size_decimal executable')
                if content['kind'] != 'file' or type(content['executable']) is not bool: raise OperandRefusal('content')
                digest = _hex(content['sha256']); size = _decimal(content['size_decimal'])
                mode = modes.get(path)
                if mode is None: raise OperandRefusal('mode_link')
                _same(mode, {'output_sha256':digest, 'output_size_decimal':content['size_decimal'], 'executable':content['executable']})
                result.add(_raw_base(context, root + '/bases/' + digest + '.bin', digest, size))
            entries[path] = after
        projection = canonical_sha256({'entries':[entries[p] for p in sorted(entries)], 'inputs':receipt['inputs']})
        _same(receipt, {'result_projection_sha256':projection})
        projections.append(projection); previous = sha
        result.update({rp, pp, ip})
        if len(result) > MAX_IDENTITIES: raise OperandRefusal('identities')
    _same(manifest, {'entries':[entries[p] for p in sorted(entries)], 'inputs':receipt['inputs'],
                      'projection_sha256':projections[-1], 'head_receipt_sha256':previous})
    current = manifest; heads = {manifest_sha}
    for length in range(len(refs), 0, -1):
        _same(current, {**binding, 'receipts':refs[:length], 'head_receipt_sha256':refs[length-1]['sha256'], 'projection_sha256':projections[length-1]})
        if canonical_sha256({'entries':current['entries'], 'inputs':current['inputs']}) != projections[length-1]: raise OperandRefusal('prior_projection')
        prior = current['previous_head_sha256']
        if length == 1:
            if prior is not None: raise OperandRefusal('genesis_head')
        else:
            _hex(prior)
            if prior in heads: raise OperandRefusal('head_cycle')
            heads.add(prior); mp = root + '/manifests/' + prior + '.json'
            current, actual = _envelope(context, mp, 'naos.upgrade.portable_manifest.v3', _PORTABLE_MANIFEST_KEYS)
            if actual != prior: raise OperandRefusal('prior_digest')
            result.add(mp)
            if len(result) > MAX_IDENTITIES:
                raise OperandRefusal('identities')
    if len(result) > MAX_IDENTITIES:
        raise OperandRefusal('identities')
    context.verify_cached()
    return result


_WINDOWS_ROOT = '.naos/upgrade-v1/windows-content'


def _windows_operands(context):
    root = _WINDOWS_ROOT
    enrollment, enrollment_sha = _envelope(context, root + '/root.json', 'naos.upgrade.windows_root_enrollment.v1', 'schema project_id root_identity enrollment_plan_sha256')
    owner, owner_sha = _envelope(context, root + '/owner.json', 'naos.upgrade.windows_owner_enrollment.v1', 'schema project_id root_identity root_enrollment_sha256 source_policy_snapshot_sha256 owner_kind')
    if type(enrollment['project_id']) is not str or not enrollment['project_id']:
        raise OperandRefusal('windows_project')
    binding = {'project_id':enrollment['project_id'], 'root_identity':enrollment['root_identity']}
    _same(owner, {**binding, 'root_enrollment_sha256':enrollment_sha})
    _hex(enrollment['enrollment_plan_sha256']); _hex(owner['source_policy_snapshot_sha256'])
    identity = _shape(enrollment['root_identity'], 'volume_serial_hex file_id_hex'); _hex(identity['volume_serial_hex'],16); _hex(identity['file_id_hex'],32)
    manifest, _ = _envelope(context, root + '/manifest.json', 'naos.upgrade.windows_content_manifest.v1', 'schema project_id root_identity owner_sha256 source_policy_snapshot_sha256 receipts entries last_request')
    _same(manifest, {**binding, 'owner_sha256':owner_sha})
    _hex(manifest['source_policy_snapshot_sha256'])
    seen = set(); result = set(); previous = None; current_bases = {}
    for ref in _list(manifest['receipts']):
        _shape(ref, 'transaction_id sha256'); tid = ref['transaction_id']; _hex(ref['sha256'])
        if type(tid) is not str or re.fullmatch(r'WMC-[0-9a-f]{16}',tid) is None or tid in seen: raise OperandRefusal('windows_id')
        seen.add(tid); rp = root + '/receipts/' + tid + '.json'
        receipt, sha = _envelope(context, rp, 'naos.upgrade.windows_content_receipt.v1', 'schema transaction_id project_id root_identity owner_sha256 source_policy_snapshot_sha256 previous_receipt_sha256 plan_sha256 changes request')
        _same(receipt, {**binding, 'owner_sha256':owner_sha, 'transaction_id':tid, 'previous_receipt_sha256':previous})
        if sha != ref['sha256']: raise OperandRefusal('windows_receipt_digest')
        _hex(receipt['source_policy_snapshot_sha256']); _hex(receipt['plan_sha256']); previous = sha
        operation = 'WOP-' + tid[4:]; op = root + '/transactions/' + operation
        version = context.object(op + '/plan.json').get('body', {}).get('schema')
        if version not in {'naos.upgrade.windows_operation_plan.v1','naos.upgrade.windows_operation_plan.v2'}:
            raise OperandRefusal('operation_schema')
        operation_schema = 'naos.upgrade.windows_operation.' + version.rsplit('.', 1)[1]
        plan_record, _ = _envelope(context, op + '/plan.json', version, 'schema operation_id plan plan_sha256')
        plan = _shape(plan_record['plan'], 'schema project_root project_root_identity source_policy_observation source_policy_sha256 source_policy_snapshot_sha256 expected_manifest_sha256 expected_owner_sha256 enrollment private_file_policy request checks rows operation_id transaction_id project_id status digest_sha256')
        if plan['schema'] not in {'naos.upgrade.windows_runtime_plan.v1','naos.upgrade.windows_runtime_plan.v2'}: raise OperandRefusal('windows_plan_schema')
        _same(plan, {'project_root':str(context.root), 'project_root_identity':identity, 'project_id':enrollment['project_id'], 'operation_id':operation, 'transaction_id':tid, 'status':'ready', 'source_policy_snapshot_sha256':receipt['source_policy_snapshot_sha256']})
        plan_digest = canonical_sha256({k:v for k,v in plan.items() if k != 'digest_sha256'})
        _same(plan, {'digest_sha256':plan_digest}); _same(receipt, {'plan_sha256':plan_digest})
        _same(plan_record, {'operation_id':operation, 'plan_sha256':canonical_sha256(plan)})
        intent, _ = _envelope(context, op + '/intent.json', operation_schema, 'schema failure_model operation_id plan_sha256 slot_paths publications runtime_parent_id scope_lock_id transaction_directory_id lock_id')
        _same(intent, {'operation_id':operation, 'plan_sha256':plan_record['plan_sha256'], 'failure_model':'application_crash_v1'})
        marker, _ = _envelope(context, op + '/committed.json', operation_schema, 'schema failure_model intent_sha256 direction topology')
        _same(marker, {'failure_model':'application_crash_v1', 'intent_sha256':hashlib.sha256(context.read(op+'/intent.json')).hexdigest(), 'direction':'forward', 'topology':'committed'})
        changed = set()
        for change in _list(receipt['changes']):
            if type(change) is not dict or type(change.get('path')) is not str or change['path'] in changed:
                raise OperandRefusal('windows_change_duplicate')
            changed.add(change['path'])
            _shape(change, 'path base_sha256 ownership creation_policy introduced_policy_sha256'); digest = _hex(change['base_sha256'])
            bp = root + '/bases/' + digest + '.json'
            base, actual = _envelope(context, bp, 'naos.upgrade.windows_content_base.v1', 'schema path content archive_sha256 archive_size_decimal ownership creation_policy introduced_policy_sha256 transaction_id')
            if actual != digest: raise OperandRefusal('windows_base_digest')
            _same(base, {**{k:change[k] for k in ('path','ownership','creation_policy','introduced_policy_sha256')}, 'transaction_id':tid})
            content = _shape(base['content'], 'kind size_decimal sha256 metadata_sha256'); _hex(content['sha256']); _hex(content['metadata_sha256'])
            if content['kind'] != 'file': raise OperandRefusal('windows_content')
            _same(base, {'archive_sha256':content['sha256'], 'archive_size_decimal':content['size_decimal']})
            blob = root + '/base-blobs/' + content['sha256'] + '.bin'
            result.add(_raw_base(context, blob, content['sha256'], _decimal(content['size_decimal'])))
            result.add(bp); current_bases[change['path']] = {'path':change['path'], 'base_sha256':digest, 'receipt_sha256':sha, **{k:change[k] for k in ('ownership','creation_policy','introduced_policy_sha256')}}
        result.update({rp,op,op+'/plan.json',op+'/intent.json',op+'/committed.json'})
    if manifest['entries'] != [current_bases[p] for p in sorted(current_bases)]: raise OperandRefusal('windows_entries')
    if len(result) > MAX_IDENTITIES: raise OperandRefusal('identities')
    context.verify_cached()
    return result

_WINDOWS_COMPONENT_RESERVED = re.compile(r'^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(?:\.|$)', re.I)
_WINDOWS_CREATE_ACTIONS = frozenset({'CREATE_NEW_UPSTREAM', 'CREATE_NEW_ADOPTER_OWNED',
    'CREATE_CONFIGURATION_CHOICE', 'CREATE_MANAGED_CACHE', 'CREATE_IMMUTABLE_REPORT'})


def _windows_relative_path(value):
    if (type(value) is not str or not value or PureWindowsPath(value).drive
            or value.startswith('\\') or '/' in value):
        raise OperandRefusal('windows_relative_path')
    parts = value.split('\\')
    for part in parts:
        if (not part or part in {'.', '..'} or part[-1] in ' .'
                or any(c in part for c in '/\\:\0<>"|?*')
                or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in part)
                or _WINDOWS_COMPONENT_RESERVED.match(part)
                or len(part.encode('utf-16-le')) > 510):
            raise OperandRefusal('windows_component')
    return tuple(parts)


def _windows_v2_publication_identity(value, root_identity, raw):
    _shape(value, 'volume_serial_hex file_id_hex size_bytes content_sha256 metadata_sha256 rename_metadata_v2')
    _same(value, {'volume_serial_hex':root_identity['volume_serial_hex'],
                  'size_bytes':str(len(raw)), 'content_sha256':hashlib.sha256(raw).hexdigest()})
    _hex(value['file_id_hex'],32); _hex(value['metadata_sha256'])
    if _decimal(value['size_bytes']) > (1 << 63) - 1:
        raise OperandRefusal('windows_identity_size')
    metadata = _shape(value['rename_metadata_v2'], 'created_100ns_decimal last_write_100ns_decimal attributes_hex owner_sid_sha256 group_sid_sha256 dacl_sha256 descriptor_sha256 dacl_protected')
    for name in ('created_100ns_decimal', 'last_write_100ns_decimal'):
        if not 0 < _decimal(metadata[name]) <= (1 << 63) - 1:
            raise OperandRefusal('windows_identity_time')
    if metadata['attributes_hex'] not in {'00000020','00000080'} or type(metadata['dacl_protected']) is not bool:
        raise OperandRefusal('windows_identity_metadata')
    for name in ('owner_sid_sha256','group_sid_sha256','dacl_sha256','descriptor_sha256'):
        _hex(metadata[name])
    return value['volume_serial_hex'], value['file_id_hex']


def _windows_enrollment_coordinates(context):
    """Additional labels for one exact v2 NEW-enrollment constructor only.

    This runs after the entire existing committed chain and raw archives prove.
    A refusal adds no path admission and grants no current native authority.
    """
    root = _WINDOWS_ROOT
    manifest = context.object(root + '/manifest.json')['body']
    if len(manifest['receipts']) != 1:
        raise OperandRefusal('constructor_history')
    tid = manifest['receipts'][0]['transaction_id']; operation = 'WOP-' + tid[4:]
    op = root + '/transactions/' + operation
    saved = context.object(op + '/plan.json')['body']; plan = saved['plan']
    if (saved['schema'] != 'naos.upgrade.windows_operation_plan.v2'
            or plan['schema'] != 'naos.upgrade.windows_runtime_plan.v2'
            or plan['enrollment'] is not True):
        raise OperandRefusal('constructor_variant')
    project = str(context.root)
    project_path = PureWindowsPath(project)
    if not project_path.is_absolute() or len(project_path.drive) != 2 or project_path.drive[1] != ':':
        raise OperandRefusal('constructor_root')
    root_parts = _windows_relative_path('\\'.join(project_path.parts[1:])) if len(project_path.parts) > 1 else ()
    enrollment = context.object(root + '/root.json')['body']
    _same(enrollment, {'enrollment_plan_sha256':plan['digest_sha256']})
    receipt_path = root + '/receipts/' + tid + '.json'
    receipt = context.object(receipt_path)['body']
    changes = receipt['changes']
    changed = {}
    if len(changes) > MAX_IDENTITIES:
        raise OperandRefusal('identities')
    for change in changes:
        path = change['path']; _windows_relative_path(path)
        if path.casefold() in changed:
            raise OperandRefusal('constructor_path_alias')
        changed[path.casefold()] = change
    if [r['path'] for r in changes] != sorted(r['path'] for r in changes):
        raise OperandRefusal('constructor_change_order')
    coordinates = {}; representations = 0
    def add(relative, coordinate, value):
        nonlocal representations
        representations += 1
        if representations > MAX_REPRESENTATIONS:
            raise OperandRefusal('representations')
        coordinates.setdefault(relative, {})[coordinate] = value
    rows = _list(plan['rows'])
    if (len(rows) != len(changes) or len(rows) > MAX_IDENTITIES
            or [row['path'] for row in rows] != [change['path'] for change in changes]):
        raise OperandRefusal('constructor_rows')
    evidence = {root + '/root.json', root + '/owner.json', receipt_path}
    files = []; seen = set()
    for index, row in enumerate(rows):
        _shape(row, 'action base before creation_policy intended ownership path source')
        path = row['path']; parts = _windows_relative_path(path)
        if path.casefold() in seen or row['action'] not in _WINDOWS_CREATE_ACTIONS:
            raise OperandRefusal('constructor_action')
        seen.add(path.casefold()); change = changed.get(path.casefold())
        if change is None or change['path'] != path:
            raise OperandRefusal('constructor_change')
        _same(row, {name:change[name] for name in ('ownership','creation_policy')})
        source = _shape(row['source'], 'path sha256 size_decimal')
        _same(source, {'path':path}); _hex(source['sha256']); _decimal(source['size_decimal'])
        base_path = root + '/bases/' + change['base_sha256'] + '.json'
        base = context.object(base_path)['body']; content = base['content']
        _same(content, {name:source[name] for name in ('sha256','size_decimal')})
        _same(base, {'path':path})
        _same(row['base'], {'presence':'absent','kind':None,'metadata_sha256':None,'sha256':None,'size_decimal':None})
        _shape(row['base'], 'presence kind metadata_sha256 sha256 size_decimal')
        intended = _shape(row['intended'], 'presence kind metadata_sha256 sha256 size_decimal')
        _same(intended, {'presence':'present', **content})
        before = _shape(row['before'], 'schema path presence ancestors missing_suffix')
        _same(before, {'schema':'naos.upgrade.windows_content_observation.v1','path':path,'presence':'absent'})
        ancestors = _list(before['ancestors']); suffix = _list(before['missing_suffix'])
        prefix = ('', *root_parts, *parts[:-1])
        if not len(root_parts) + 1 <= len(ancestors) <= len(prefix):
            raise OperandRefusal('constructor_absence')
        for ancestor, name in zip(ancestors,prefix):
            _shape(ancestor,'name volume_serial_hex file_id_hex')
            _same(ancestor, {'name':name,'volume_serial_hex':plan['project_root_identity']['volume_serial_hex']})
            _hex(ancestor['file_id_hex'],32)
        _same(ancestors[len(root_parts)], plan['project_root_identity'])
        remaining = parts[len(ancestors) - len(root_parts) - 1:]
        if suffix != list(remaining):
            raise OperandRefusal('constructor_missing_suffix')
        for slot,ancestor in enumerate(ancestors):
            add(op+'/plan.json', ('body','plan','rows',index,'before','ancestors',slot,'name'),ancestor['name'])
        for slot,name in enumerate(remaining):
            add(op+'/plan.json', ('body','plan','rows',index,'before','missing_suffix',slot),name)
        for coordinate in [('body','plan','rows',index,'path'),
                           ('body','plan','rows',index,'source','path'),
                           ('body','plan','rows',index,'before','path')]:
            add(op+'/plan.json',coordinate,path)
        add(base_path,('body','path'),path)
        blob = root + '/base-blobs/' + content['sha256'] + '.bin'
        raw = context.read(blob)
        files.append((path, raw, 'content', 'content-' + format(index,'06d') + '.bin'))
        evidence.update({base_path,blob})
    if seen != set(changed):
        raise OperandRefusal('constructor_rows')
    for index, change in enumerate(changes):
        add(receipt_path,('body','changes',index,'path'),change['path'])
    for index, entry in enumerate(manifest['entries']):
        add(root+'/manifest.json',('body','entries',index,'path'),entry['path'])
    for relative in sorted(evidence, key=lambda name:name.replace('/','\\')):
        if relative not in context.cache:
            raise OperandRefusal('constructor_evidence')
        index = len(files)
        files.append((relative.replace('/','\\'), context.read(relative), 'evidence',
                      'evidence-' + format(index,'06d') + '.bin'))
    files.append((root.replace('/','\\')+'\\manifest.json',context.read(root+'/manifest.json'),
                  'manifest','manifest-'+format(len(files),'06d')+'.json'))
    if len(files) > MAX_IDENTITIES:
        raise OperandRefusal('identities')
    intent = context.object(op+'/intent.json')['body']
    publications = _list(intent['publications'])
    if len(publications) != len(files):
        raise OperandRefusal('constructor_publications')
    expected_slots = {}; native_ids = set(); physical = set()
    stage_root = project.rstrip('\\') + '\\' + root.replace('/','\\') + '\\staging\\' + operation
    for index, ((path, raw, role, stage_name), publication) in enumerate(zip(files,publications)):
        _shape(publication,'role kind target staged after')
        target, staged = 'target-'+str(index), 'staged-'+str(index)
        _same(publication, {'role':role,'kind':'create','target':target,'staged':staged})
        identity = _windows_v2_publication_identity(publication['after'],plan['project_root_identity'],raw)
        if identity in native_ids:
            raise OperandRefusal('constructor_identity_alias')
        native_ids.add(identity)
        expected_slots[target] = project.rstrip('\\') + '\\' + path
        expected_slots[staged] = stage_root + '\\' + stage_name
        for key in (target,staged):
            value = expected_slots[key]
            if value.casefold() in physical:
                raise OperandRefusal('constructor_slot_alias')
            physical.add(value.casefold())
            add(op+'/intent.json',('body','slot_paths',key),value)
    if intent['slot_paths'] != expected_slots:
        raise OperandRefusal('constructor_slots')
    # Default executing-kit role only. Custom source policy paths stay scanned.
    kit = PureWindowsPath(__file__).parent.parent
    if not kit.is_absolute() or len(kit.drive) != 2 or kit.drive[1] != ':':
        raise OperandRefusal('constructor_kit')
    policy_path = '\\'.join((*kit.parts[1:],'configs','upgrade_source_policy.yaml'))
    observation = plan['source_policy_observation']
    if (type(observation) is not dict
            or observation.get('schema') != 'naos.upgrade.windows_content_observation.v1'
            or observation.get('presence') != 'present'
            or observation.get('path') != policy_path
            or observation.get('sha256') != plan['source_policy_sha256']):
        raise OperandRefusal('constructor_policy_path')
    add(op+'/plan.json',('body','plan','source_policy_observation','path'),policy_path)
    # The NEW runtime producer uses secrets.token_hex(8), independently of
    # the shared WOP/WMC suffix. Only its five exact linked scalar roles qualify.
    # This proves constructor compatibility, never randomness or authenticity.
    project_id = enrollment['project_id']
    if (re.fullmatch(r'WIN-[0-9a-f]{16}', project_id) is not None
            and plan['expected_manifest_sha256'] is None
            and plan['expected_owner_sha256'] is None):
        for relative in (root+'/root.json', root+'/owner.json',
                         root+'/manifest.json', receipt_path):
            add(relative, ('body','project_id'), project_id)
        add(op+'/plan.json', ('body','plan','project_id'), project_id)
    # Optional saved directory journal has one further generated operation label.
    # Its refusal must not erase the already proved enrollment/path coordinates.
    try:
        _same(plan, {'expected_manifest_sha256':None, 'expected_owner_sha256':None})
        relative = op+'/directories.json'
        directories, _ = _envelope(context, relative,
            'naos.upgrade.windows_runtime_directories.v1',
            'schema failure_model operation_id intent_sha256 directories')
        intent_sha = hashlib.sha256(context.read(op+'/intent.json')).hexdigest()
        _windows_saved_directory_witnesses(plan, operation, intent_sha, directories)
        if representations < MAX_REPRESENTATIONS:
            add(relative, ('body','operation_id'), operation)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError,
            RecursionError, RuntimeError):
        pass
    context.verify_cached()
    return coordinates


def _windows_constructor_coordinates(context):
    if _WINDOWS_ROOT not in context.constructor_coordinates:
        _ensure_control_family(context, _WINDOWS_ROOT)
        if _WINDOWS_ROOT in context.reason:
            return {}
        try:
            context.constructor_coordinates[_WINDOWS_ROOT] = _windows_enrollment_coordinates(context)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
            context.constructor_coordinates[_WINDOWS_ROOT] = {}
    return context.constructor_coordinates[_WINDOWS_ROOT]


def _windows_directory_identity(value):
    _shape(value, 'volume_serial_hex file_id_hex')
    _hex(value['volume_serial_hex'], 16); _hex(value['file_id_hex'], 32)
    return value


def _windows_saved_directory_scope(plan):
    """Pure saved-plan mirror of windows_runtime_directories scope/anchors.

    Agreement is tested against absent_content_parents/existing_parent_anchors;
    producer code is never imported into this separate proof domain.
    """
    mutations = _WINDOWS_CREATE_ACTIONS | {'UPDATE_FROM_UPSTREAM'}
    paths = set(); anchors = {}
    for row in _list(plan['rows']):
        if row['action'] not in mutations or row['before']['presence'] != 'absent':
            continue
        parts = _windows_relative_path(row['path'])
        if parts[0].casefold() == '.naos':
            raise OperandRefusal('directory_runtime_path')
        suffix = _list(row['before'].get('missing_suffix'))
        if not suffix or len(suffix) > len(parts) or list(parts[-len(suffix):]) != suffix:
            raise OperandRefusal('directory_saved_absence')
        for length in range(len(parts) - len(suffix) + 1, len(parts)):
            paths.add('\\'.join(parts[:length]))
        if len(suffix) < 2:
            continue
        path = '\\'.join(parts[:len(parts) - len(suffix) + 1])
        ancestors = _list(row['before'].get('ancestors'))
        if not ancestors or type(ancestors[-1]) is not dict:
            raise OperandRefusal('directory_anchor')
        parent = _windows_directory_identity({k: ancestors[-1].get(k)
            for k in ('volume_serial_hex', 'file_id_hex')})
        if path in anchors and anchors[path] != parent:
            raise OperandRefusal('directory_anchor_conflict')
        anchors[path] = parent
    if len(paths) > MAX_IDENTITIES or len({p.casefold() for p in paths}) != len(paths):
        raise OperandRefusal('directory_path_alias')
    if set(anchors) != {p for p in paths if ntpath.dirname(p) not in paths}:
        raise OperandRefusal('directory_anchors')
    return tuple(sorted(paths, key=lambda p: (p.count('\\'), p.casefold()))), anchors


def _windows_saved_directory_witnesses(plan, operation, intent_sha, body):
    """Pure mirror of DirectoryJournal._validate_body for JSON witness data.

    0x20b7 is the producer's SUPPORTED_DIRECTORY_ATTRIBUTES. This validates
    consistency of saved bytes only; it grants no native ownership authority.
    """
    expected_paths, anchors = _windows_saved_directory_scope(plan)
    root_identity = _windows_directory_identity(plan['project_root_identity'])
    _shape(body, 'schema failure_model operation_id intent_sha256 directories')
    _same(body, {'schema':'naos.upgrade.windows_runtime_directories.v1',
        'failure_model':'application_crash_v1', 'operation_id':operation,
        'intent_sha256':intent_sha})
    rows = _list(body['directories']); seen_ids = set(); seen_paths = {}
    for row in rows:
        _shape(row, 'path identity parent_identity attributes_hex comparison_metadata_sha256')
        identity = _windows_directory_identity(row['identity'])
        parent = _windows_directory_identity(row['parent_identity'])
        attributes = int(_hex(row['attributes_hex'], 8), 16)
        _hex(row['comparison_metadata_sha256'])
        parts = _windows_relative_path(row['path'])
        if parts[0].casefold() == '.naos' or not attributes & 0x10 or attributes & ~0x20b7:
            raise OperandRefusal('directory_attributes')
        key = canonical_bytes(identity); parent_path = ntpath.dirname(row['path']).casefold()
        if (key in seen_ids or row['path'].casefold() in seen_paths or identity == parent
                or identity['volume_serial_hex'] != root_identity['volume_serial_hex']
                or parent['volume_serial_hex'] != root_identity['volume_serial_hex']
                or row['path'] in anchors and parent != anchors[row['path']]
                or not parent_path and parent != root_identity
                or parent_path in seen_paths and seen_paths[parent_path] != parent):
            raise OperandRefusal('directory_identity_conflict')
        seen_ids.add(key); seen_paths[row['path'].casefold()] = identity
    if tuple(row['path'] for row in rows) != expected_paths:
        raise OperandRefusal('directory_coverage')


def _windows_new_enrollment_carrier_operands(context):
    """Exact optional carrier paths after the independent enrollment-v2 proof.

    These are typed inventory coordinates only. Raw record bodies remain
    scanned. Unsupported or refused augmentation cannot erase old operands.
    The constructor covers historical metadata even when a stage directory
    has already retired; file existence or a matching prefix is not authority.
    """
    key = _WINDOWS_ROOT + '#new_enrollment_carrier'
    if key in context.constructor_coordinates:
        return context.constructor_coordinates[key]
    result = set()
    try:
        if not _windows_constructor_coordinates(context):
            raise OperandRefusal('carrier_constructor')
        root = _WINDOWS_ROOT
        manifest = context.object(root + '/manifest.json')['body']
        if len(manifest['receipts']) != 1:
            raise OperandRefusal('carrier_history')
        tid = manifest['receipts'][0]['transaction_id']
        operation = 'WOP-' + tid[4:]; op = root + '/transactions/' + operation
        saved = context.object(op + '/plan.json')['body']; plan = saved['plan']
        if (saved['schema'] != 'naos.upgrade.windows_operation_plan.v2'
                or plan['schema'] != 'naos.upgrade.windows_runtime_plan.v2'
                or plan['enrollment'] is not True):
            raise OperandRefusal('carrier_variant')
        intent = context.object(op + '/intent.json')['body']
        intent_sha = hashlib.sha256(context.read(op + '/intent.json')).hexdigest()
        # WindowsOperation binds the two fixed lock roles and both parent
        # directory roles in this exact intent. These are consistency records,
        # not a claim that the scanner owns or can operate native handles.
        for name in ('runtime_parent_id', 'scope_lock_id', 'transaction_directory_id', 'lock_id'):
            identity = _windows_directory_identity(intent[name])
            if identity['volume_serial_hex'] != plan['project_root_identity']['volume_serial_hex']:
                raise OperandRefusal('carrier_runtime_identity')
        publications = _list(intent['publications'])
        if not publications or any(row['kind'] != 'create' for row in publications):
            raise OperandRefusal('carrier_publications')
        # A create publication has exactly one forward step. The completed
        # constructor proved every publication and slot against saved bytes.
        for step in range(1, len(publications) + 1):
            relative = op + '/forward-' + format(step, '06d') + '.json'
            marker, _ = _envelope(context, relative, 'naos.upgrade.windows_operation.v2',
                'schema failure_model intent_sha256 direction topology')
            _same(marker, {'failure_model':'application_crash_v1',
                'intent_sha256':intent_sha, 'direction':'forward',
                'topology':'step:' + str(step)})
            result.add(relative)
        # Reconstruct the producer's saved-plan directory witness contract
        # without importing its native handles/backend or consulting live absence.
        relative = op + '/directories.json'
        directories, _ = _envelope(context, relative,
            'naos.upgrade.windows_runtime_directories.v1',
            'schema failure_model operation_id intent_sha256 directories')
        _windows_saved_directory_witnesses(plan, operation, intent_sha, directories)
        result.add(relative)
        # WindowsRuntime._prepare constructs exactly these fixed children and
        # templates, and apply constructs the operation staging directory.
        result.update(root + '/' + name for name in
            ('root.json', 'owner.json', 'manifest.json', 'bases', 'base-blobs',
             'receipts', 'transactions', 'staging', 'template.file',
             'template.directory'))
        result.update({op, op + '/lock', root + '/transactions/managed-scope.lock',
                       root + '/staging/' + operation})
        if len(result | context.operands[root]) > MAX_IDENTITIES:
            raise OperandRefusal('carrier_identities')
        context.verify_cached()
    except (OSError, UnicodeError, ValueError, TypeError, KeyError,
            RecursionError, RuntimeError):
        result = set()
    context.constructor_coordinates[key] = frozenset(result)
    return context.constructor_coordinates[key]
