"""Opt-in selected-context byte comparison; no host delivery or identity assurance."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from naos_evidence_contracts import _compiled_canonical_schema, _json_value, _safe_file, evidence_subject_parts
from naos_policy import kit_root
from naos_session_identity import inspect_session_context, validate_session_id

SELECTION_SCHEMA = 'naos.task_context_selection.v1'
CHECK_SCHEMA = 'naos.task_context_revalidation.v1'
MAX_FILES = 128
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PACK_BYTES = 4 * 1024 * 1024
HEX = re.compile(r'^[0-9a-f]{64}$')
DEVICE = re.compile(r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', re.I)
NONCLAIMS = {
    'issuer': 'local_deterministic_cli',
    'observable': 'selected_bytes_at_check_time',
    'host_delivery': 'not_observed',
    'model_use': 'unknown',
    'behavioral_effectiveness': 'not_evaluated',
}
EXCLUSIONS = [
    'nonselected_files', 'generated_report_summaries', 'private_memory_payloads',
    'host_request_context', 'derived_markdown',
]


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def path_parts(reference: Any) -> tuple[str, ...] | None:
    if not isinstance(reference, str) or len(reference) > 4096:
        return None
    parts = evidence_subject_parts(reference)
    if parts is None or any(
        any(ord(ch) < 32 or ch in '<>"|:*?\\' or ord(ch) == 127 for ch in part)
        or part.endswith((' ', '.')) or DEVICE.match(part)
        for part in parts
    ):
        return None
    if any(part.lower() in {'.git', '.codex', '.engram', 'engram', 'memories'} for part in parts):
        return None
    return parts


def read_bytes(root: Path, reference: str, limit: int = MAX_FILE_BYTES) -> tuple[str, bytes | None]:
    parts = path_parts(reference)
    if parts is None:
        return 'unsafe', None
    path = root.joinpath(*parts)
    state = _safe_file(root, path)
    if state != 'available':
        return {'unsafe_path': 'unsafe', 'not_regular_file': 'unsafe'}.get(state, state), None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                return 'unsafe', None
            if before.st_size > limit:
                return 'oversized', None
            with os.fdopen(fd, 'rb', closefd=False) as handle:
                raw = handle.read(limit + 1)
            after = os.fstat(fd)
            if len(raw) > limit:
                return 'oversized', None
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
            if any(getattr(before, key) != getattr(after, key) for key in fields):
                return 'partial', None
            return 'present', raw
        finally:
            os.close(fd)
    except FileNotFoundError:
        return 'missing', None
    except OSError:
        return 'unreadable', None


def json_mapping(raw: bytes) -> dict[str, Any]:
    value = _json_value(Path('.'), data=raw)
    if not isinstance(value, dict):
        raise ValueError('mapping_required')
    return value


def selected_bytes(root: Path, reference: str, used: int) -> tuple[str, bytes | None]:
    remaining = MAX_TOTAL_BYTES - used
    if remaining <= 0:
        return 'partial', None
    limit = min(MAX_FILE_BYTES, remaining)
    state, raw = read_bytes(root, reference, limit)
    if state == 'oversized' and limit < MAX_FILE_BYTES:
        return 'partial', None
    return state, raw


def selection_validation(selection: Any) -> str:
    """Use the shipped self-contained schema; unavailable never means matched."""
    state, raw = read_bytes(kit_root().resolve(), 'schemas/naos/task_context_pack.schema.json')
    if state != 'present' or raw is None:
        return 'schema_unavailable'
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
    except ImportError:
        return 'schema_unavailable'
    try:
        schema = json_mapping(raw)['properties']['context_integrity']['properties']['selection']
        # This fragment is self-contained. Refuse external or unresolved refs.
        encoded = json.dumps(schema, allow_nan=False).encode('utf-8')
        if '"$ref"' in encoded.decode('utf-8'):
            return 'schema_unavailable'
        validator, lock = _compiled_canonical_schema(encoded, Draft202012Validator)
        with lock:
            return 'valid' if validator.is_valid(selection) else 'selection_shape_invalid'
    except (SchemaError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return 'schema_unavailable'


def project_identity(root: Path, expected: Any) -> str:
    if not isinstance(expected, str) or not expected or len(expected) > 1024:
        return 'unknown'
    # Git configuration is a local binding, never authentication. Reject secrets.
    try:
        parsed = urlsplit(expected)
        if (parsed.scheme not in {'https', 'ssh'} or not parsed.hostname
                or parsed.password or (parsed.scheme == 'https' and parsed.username)
                or parsed.query or parsed.fragment or any(ord(c) < 33 for c in expected)):
            return 'unsafe'
        top = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
                             capture_output=True, text=True, timeout=5, check=False)
        origin = subprocess.run(['git', '-C', str(root), 'config', '--get-all', 'remote.origin.url'],
                                capture_output=True, text=True, timeout=5, check=False)
        if top.returncode or Path(top.stdout.strip()).resolve() != root.resolve():
            return 'unknown'
        origins = origin.stdout.splitlines() if origin.returncode == 0 else []
        if len(origins) != 1:
            return 'unknown'
        return 'matched' if origins[0] == expected else 'scope_mismatch'
    except (OSError, ValueError, subprocess.SubprocessError):
        return 'unknown'


def association(root: Path, naos_root: str, policy: dict[str, Any], project_id: Any,
                task_id: Any, session_id: Any, profile: str) -> str:
    state = project_identity(root, project_id)
    if state != 'matched':
        return state
    if not isinstance(task_id, str) or not re.fullmatch(r'T-[A-Z0-9][A-Z0-9_.-]*', task_id):
        return 'unknown'
    try:
        validate_session_id(session_id)
        context = inspect_session_context(root, naos_root, policy, session_id)
    except (ValueError, TypeError, OSError):
        return 'unknown'
    record = context.get('record') or {}
    if context.get('status') != 'ready' or record.get('status') != 'active':
        return 'unknown'
    return 'matched' if record.get('task_id') == task_id and record.get('profile') == profile else 'scope_mismatch'


def rules_record(root: Path, path: Path) -> dict[str, Any]:
    try:
        reference = path.absolute().relative_to(root.absolute()).as_posix()
        base = root
    except ValueError:
        try:
            base = kit_root().resolve()
            reference = 'kit://' + path.absolute().relative_to(base).as_posix()
        except ValueError:
            return {'path': None, 'state': 'unsafe', 'sha256': None}
    local = reference.removeprefix('kit://')
    state, raw = read_bytes(base, local)
    return {'path': reference, 'state': state,
            'sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None}


def freeze_selection(root: Path, naos_root: str, policy: dict[str, Any], *,
                     report: dict[str, Any], project_id: str, session_id: str,
                     inputs: list[str], expected_outputs: list[str], rules_path: Path,
                     supersedes: str | None = None) -> dict[str, Any]:
    if not inputs or len(inputs) > MAX_FILES or len(set(inputs)) != len(inputs):
        raise ValueError('Select 1-128 unique context inputs.')
    if len(set(expected_outputs)) != len(expected_outputs) or not set(expected_outputs) <= set(inputs):
        raise ValueError('Expected outputs must be a unique subset of context inputs.')
    if supersedes is not None and not HEX.fullmatch(supersedes):
        raise ValueError('Superseded pack digest must be lowercase SHA256.')
    entries = []
    total = 0
    for reference in sorted(inputs):
        state, raw = selected_bytes(root, reference, total)
        total += len(raw) if raw is not None else 0
        entries.append({'path': reference, 'state': state,
                        'sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None,
                        'size_bytes': len(raw) if raw is not None else None,
                        'expected_output': reference in expected_outputs})
    binding = association(root, naos_root, policy, project_id, report.get('task_id'), session_id, report['profile'])
    selection = {
        'schema': SELECTION_SCHEMA, 'project_id': project_id, 'task_id': report.get('task_id'),
        'session_id': session_id, 'profile': report['profile'], 'naos_root': naos_root,
        'association_at_freeze': binding, 'scope': 'explicit_paths_only',
        'inputs': entries, 'rules': rules_record(root, rules_path),
        'exclusions': EXCLUSIONS, 'supersedes_pack_sha256': supersedes,
        'representation': 'raw_file_bytes_no_newline_or_case_folding',
    }
    return {'selection': selection, 'manifest_sha256': canonical_digest(selection),
            'status': outcome([binding, selection['rules']['state'] if selection['rules']['state'] != 'present' else 'matched']
                              + [entry['state'] if entry['state'] != 'present' else 'matched' for entry in entries]),
            'evidence_dimensions': dict(NONCLAIMS)}


def outcome(states: list[str]) -> str:
    if any(state not in {'matched', 'expected_changed', 'scope_mismatch', 'superseded', 'unsafe',
                         'unreadable', 'oversized', 'partial', 'missing', 'unknown', 'changed'} for state in states):
        return 'unknown'
    for state in ('scope_mismatch', 'superseded', 'unsafe', 'unreadable', 'oversized',
                  'partial', 'missing', 'unknown', 'changed'):
        if state in states:
            return state
    return 'matched'


def check_context(root: Path, naos_root: str, policy: dict[str, Any], *, path: str,
                  pack_sha256: str | None, project_id: str | None, task_id: str | None,
                  session_id: str | None, profile: str, phase: str = 'checkpoint',
                  manifest_sha256: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        'schema': CHECK_SCHEMA, 'status': 'unknown', 'phase': phase, 'path': path,
        'pack_sha256': None, 'manifest_sha256': None, 'inputs': [],
        'reason_codes': [], 'evidence_dimensions': dict(NONCLAIMS),
        'scope': 'explicit_selected_inputs_and_rules_at_check_time',
    }

    def finish(state: str, reason: str) -> dict[str, Any]:
        result['status'] = state
        result['reason_codes'].append(reason)
        return result

    state, raw = read_bytes(root, path, MAX_PACK_BYTES)
    if raw is None:
        return finish(state, 'pack_' + state)
    actual = hashlib.sha256(raw).hexdigest()
    result['pack_sha256'] = actual
    if not isinstance(pack_sha256, str) or not HEX.fullmatch(pack_sha256):
        return finish('unknown', 'expected_pack_digest_missing_or_invalid')
    if actual != pack_sha256:
        return finish('scope_mismatch', 'pack_digest_mismatch')
    try:
        pack = json_mapping(raw)
        integrity = pack.get('context_integrity')
        if integrity is None:
            return finish('unknown', 'legacy_pack_without_selection')
        selection = integrity['selection']
        shape = selection_validation(selection)
        if shape != 'valid':
            return finish('unknown', shape)
        if (pack.get('schema') != 'naos.task_context_pack.v1'
                or selection.get('schema') != SELECTION_SCHEMA):
            return finish('unknown', 'unsupported_selection_schema')
        if phase not in {'checkpoint', 'completion', 'end'}:
            return finish('unknown', 'unsupported_checkpoint')
        if selection.get('representation') != 'raw_file_bytes_no_newline_or_case_folding':
            return finish('unknown', 'unsupported_input_representation')
        digest = canonical_digest(selection)
        result['manifest_sha256'] = digest
        if digest != integrity.get('manifest_sha256') or (manifest_sha256 is not None and digest != manifest_sha256):
            return finish('scope_mismatch', 'manifest_digest_mismatch')
        expected = {'project_id': project_id, 'task_id': task_id, 'session_id': session_id,
                    'profile': profile, 'naos_root': naos_root}
        if any(value is None or value == '' for value in expected.values()):
            return finish('unknown', 'expected_association_missing')
        if any(selection.get(key) != value for key, value in expected.items()):
            return finish('scope_mismatch', 'selected_association_mismatch')
        if pack.get('task_id') != task_id or pack.get('profile') != profile or pack.get('naos_root') != naos_root:
            return finish('scope_mismatch', 'pack_association_mismatch')
        binding = association(root, naos_root, policy, project_id, task_id, session_id, profile)
        states = [binding, selection.get('association_at_freeze', 'unknown')]
        entries = selection['inputs']
        if (not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES
                or selection.get('scope') != 'explicit_paths_only'
                or selection.get('exclusions') != EXCLUSIONS):
            return finish('unknown', 'invalid_selection_shape')
        seen = set()
        total = 0
        for entry in entries:
            reference = entry['path']
            if not isinstance(reference, str) or reference in seen:
                return finish('unknown', 'duplicate_or_invalid_input')
            seen.add(reference)
            current, data = selected_bytes(root, reference, total)
            total += len(data) if data is not None else 0
            if entry.get('state') != 'present':
                current = entry.get('state') if entry.get('state') in {
                    'missing', 'unsafe', 'unreadable', 'oversized', 'partial'} else 'unknown'
            elif (not isinstance(entry.get('sha256'), str) or not HEX.fullmatch(entry['sha256'])
                  or type(entry.get('size_bytes')) is not int or type(entry.get('expected_output')) is not bool):
                current = 'unknown'
            elif current == 'present':
                current = 'matched' if hashlib.sha256(data).hexdigest() == entry['sha256'] and len(data) == entry['size_bytes'] else 'changed'
                if current == 'changed' and entry['expected_output'] and phase in {'completion', 'end'}:
                    current = 'expected_changed'
            result['inputs'].append({'path': reference, 'status': current})
            states.append(current)
        rules = selection['rules']
        reference = rules['path']
        if not isinstance(reference, str):
            states.append('unknown')
        else:
            base = kit_root().resolve() if reference.startswith('kit://') else root
            current, data = read_bytes(base, reference.removeprefix('kit://'))
            if rules.get('state') != 'present':
                current = 'unknown'
            elif current == 'present':
                current = 'matched' if hashlib.sha256(data).hexdigest() == rules.get('sha256') else 'changed'
            result['rules_status'] = current
            states.append(current)
        result['status'] = outcome(states)
        if binding != 'matched':
            result['reason_codes'].append('current_association_' + binding)
        if result['status'] != 'matched':
            result['reason_codes'].append('selection_requires_review')
        return result
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        return finish('unknown', 'malformed_pack_or_selection')


def completion_context(root: Path, naos_root: str, policy: dict[str, Any], profile: str,
                       selected: Any, binding: Any, *, selected_present: bool = False,
                       binding_present: bool = False) -> dict[str, Any]:
    if selected is None and binding is None and not selected_present and not binding_present:
        return {'status': 'unknown', 'required': False, 'reason_codes': ['legacy_context_not_selected'],
                'evidence_dimensions': dict(NONCLAIMS)}
    if not isinstance(selected, dict) or not isinstance(binding, dict):
        return {'status': 'unknown', 'required': True, 'reason_codes': ['selected_context_or_binding_missing'],
                'evidence_dimensions': dict(NONCLAIMS)}
    fields = ('pack_sha256', 'manifest_sha256', 'project_id', 'task_id', 'session_id')
    result = check_context(root, naos_root, policy, path=selected.get('path'),
                           pack_sha256=selected.get('pack_sha256'), project_id=selected.get('project_id'),
                           task_id=selected.get('task_id'), session_id=selected.get('session_id'),
                           profile=profile, phase='completion', manifest_sha256=selected.get('manifest_sha256'))
    result['required'] = True
    if any(not selected.get(field) or binding.get(field) != selected.get(field) for field in fields):
        previous_status = result['status']
        if previous_status == 'matched':
            result['status'] = 'scope_mismatch'
        result['reason_codes'].append('completion_context_join_mismatch')
        # This classifies replay only against an explicitly selected successor.
        state, raw = read_bytes(root, selected.get('path'), MAX_PACK_BYTES)
        if (previous_status == 'matched' and state == 'present' and raw is not None
                and result.get('pack_sha256') == selected.get('pack_sha256')):
            try:
                metadata = json_mapping(raw)['context_integrity']['selection']
                predecessor = metadata.get('supersedes_pack_sha256') if isinstance(metadata, dict) else None
                if predecessor and binding.get('pack_sha256') == predecessor:
                    result['status'] = 'superseded'
            except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
                pass
    return result
