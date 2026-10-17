"""Versioned local collection references. Metadata never authenticates evidence."""
from __future__ import annotations
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

_REPARSE_ATTRIBUTE = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
REFERENCE_SCHEMA = 'naos.report_source_reference.v1'
WITNESS_SCHEMA = 'naos.capability_maturity_collection_witness.v1'
PUBLICATION_MAX_BYTES = 8 * 1024 * 1024
DETAIL_MAX_BYTES = 64 * 1024 * 1024
PROOF_FIELDS = ('capability_id', 'enabled', 'current_maturity', 'target_maturity', 'evaluated_status',
                'ready_for_promotion', 'human_approval_required', 'promotion_recorded', 'missing_evidence',
                'stale_evidence', 'waivers', 'required_next_actions')
L2_FIELDS = ('reference', 'availability', 'applicability', 'applicability_reason', 'applicability_source',
             'validation', 'scope', 'producer_outcome', 'requirement_outcome', 'content_sha256',
             'generation_age', 'requirement_contract')
CANDIDATE_FIELDS = ('reference', 'content_sha256', 'availability', 'requirement_outcome')
CLASSIFICATION_BUCKETS = ('unclassified_context', 'missing_classification', 'unknown_findings', 'findings')

class CompositionError(ValueError):
    """Publication refused; no prior output may be replaced."""

def _safe_selected(root: Path, reference: str, *, allow_missing: bool = False) -> Path:
    if (not isinstance(reference, str) or not reference or '\\' in reference or ':' in reference
            or any(ord(c) < 32 for c in reference)):
        raise CompositionError('unsafe_source_reference')
    parts = reference.split('/')
    if any(p in ('', '.', '..') for p in parts) or PurePosixPath(reference).is_absolute():
        raise CompositionError('unsafe_source_reference')
    # The supplied review root defines the read boundary. Inspect its lexical
    # identity before resolution, then inspect each declared operand likewise.
    root = root.absolute()
    current = Path(root.anchor)
    for component in root.parts[1:]:
        current = current / component
        root_info = current.lstat()
        if (stat.S_ISLNK(root_info.st_mode)
                or getattr(root_info, 'st_file_attributes', 0) & _REPARSE_ATTRIBUTE
                or not stat.S_ISDIR(root_info.st_mode)):
            raise CompositionError('unsafe_source_reference')
    root = root.resolve(strict=True)
    selected = root
    leaf_info = None
    for index, component in enumerate(parts):
        selected = selected / component
        try:
            info = selected.lstat()
        except FileNotFoundError:
            leaf_info = None
            if allow_missing:continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & _REPARSE_ATTRIBUTE:
            raise CompositionError('unsafe_source_reference')
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise CompositionError('unsafe_source_reference')
        leaf_info = info
    if leaf_info is not None and not stat.S_ISREG(leaf_info.st_mode):
        raise CompositionError('not_regular_source')
    if leaf_info is not None and not os.access(selected, os.R_OK):
        raise CompositionError('unreadable_source')
    if not selected.resolve().is_relative_to(root):
        raise CompositionError('unsafe_source_reference')
    return selected

def source_reference(entry: dict[str, Any], root: Path) -> dict[str, Any]:
    data = entry.get('data')
    result = {key: value for key, value in entry.items() if key not in ('data', 'collection_sha256', 'collection_size_bytes')}
    reference = None
    detail = 'unavailable'
    reason = 'source_missing'
    if entry.get('path'):
        try:
            path = Path(entry['path'])
            if not path.is_absolute():path = root / path
            reference = path.absolute().relative_to(root.absolute()).as_posix()
            _safe_selected(root, reference, allow_missing=True)
            if entry.get('collection_sha256') is not None and entry.get('collection_size_bytes') is not None:
                detail, reason = 'source_bound', 'collected_bytes_required'
        except (ValueError, OSError):
            reference, reason = None, 'unsafe_source_reference'
    result.update(schema=REFERENCE_SCHEMA, composition_kind='source_reference',
                  source_schema=data.get('schema') if isinstance(data, dict) else None,
                  source_generated_at=data.get('generated_at') if isinstance(data, dict) else None,
                  source_reference=reference, source_sha256=entry.get('collection_sha256'),
                  source_size_bytes=entry.get('collection_size_bytes'),
                  detail_availability=detail, detail_reason=reason)
    return result

def read_collection_entry(entry: dict[str, Any], root: Path, *, max_bytes: int = DETAIL_MAX_BYTES) -> dict[str, Any]:
    """Read only the collected bytes; legacy embedded adverse payloads stay readable."""
    def unavailable(reason):return {'detail_availability': 'unavailable', 'requirement_outcome': 'unresolved', 'reason': reason, 'data': None}
    if not isinstance(entry, dict):return unavailable('invalid_collection_entry')
    if entry.get('composition_kind') is None and 'data' in entry:
        if 'schema' in entry:return unavailable('unknown_collection_version')
        return {'detail_availability': 'legacy_embedded', 'requirement_outcome': 'unresolved', 'reason': 'legacy_collection', 'data': entry['data']}
    if entry.get('schema') != REFERENCE_SCHEMA or entry.get('composition_kind') != 'source_reference':
        return unavailable('unknown_collection_version')
    if entry.get('detail_availability') != 'source_bound':return unavailable(entry.get('detail_reason', 'source_unavailable'))
    try:
        from jsonschema import Draft202012Validator
        schema_path = Path(__file__).resolve().parents[1] / 'schemas/naos/report_source_reference.schema.json'
        Draft202012Validator(json.loads(schema_path.read_text())).validate(entry)
        path = _safe_selected(root, entry['source_reference'])
        with path.open('rb') as stream:
            raw = stream.read(min(max_bytes, DETAIL_MAX_BYTES) + 1)
        if len(raw) > min(max_bytes, DETAIL_MAX_BYTES):return unavailable('oversized_source')
        if len(raw) != entry['source_size_bytes'] or hashlib.sha256(raw).hexdigest() != entry['source_sha256']:
            return unavailable('changed_source')
        if entry.get('format') == 'yaml':
            import yaml
            data = yaml.safe_load(raw)
        else:
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:raise CompositionError('duplicate_source_key')
                    value[key] = item
                return value
            def invalid_constant(value):raise CompositionError('nonfinite_source')
            data = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
        return {'detail_availability': 'available', 'requirement_outcome': 'unresolved', 'reason': 'exact_collected_bytes', 'data': data}
    except FileNotFoundError:return unavailable('missing_source')
    except CompositionError as exc:
        reason = str(exc)
        return unavailable(reason if reason in ('not_regular_source', 'unreadable_source') else 'unsafe_source_reference')
    except OSError:return unavailable('unreadable_source')
    except Exception:
        # Diagnostics carry a finite reason only; credentials from malformed input
        # must not be repeated in reader messages.
        return unavailable('malformed_source_or_reference')

def maturity_witness(entry: dict[str, Any]) -> dict[str, Any]:
    data = entry.get('data')
    witness = {'schema': WITNESS_SCHEMA, 'source_sha256': entry.get('collection_sha256'),
               'source_size_bytes': entry.get('collection_size_bytes'), 'source_schema': None,
               'source_generated_at': None, 'status': entry.get('status'),
               'profile': None, 'naos_root': None, 'project_root': None, 'state': None, 'capabilities': []}
    if isinstance(data, dict):
        for key in ('profile', 'naos_root', 'project_root', 'state', 'status'):
            witness[key] = data.get(key)
        witness['source_schema'] = data.get('schema')
        witness['source_generated_at'] = data.get('generated_at')
        rows = data.get('capabilities')
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    witness['capabilities'].append(row)
                    continue
                selected = {k:row[k] for k in PROOF_FIELDS if k in row}
                selected['evidence_results'] = []
                for item in row.get('evidence_results', []):
                    if not isinstance(item, dict) or item.get('stage') != 'L2':continue
                    fact = {'stage': 'L2', **{k:item.get(k) for k in L2_FIELDS}}
                    fact['candidates'] = [{k:c.get(k) for k in CANDIDATE_FIELDS}
                                          for c in item.get('candidates', []) if isinstance(c, dict)]
                    selected['evidence_results'].append(fact)
                witness['capabilities'].append(selected)
    return witness

def classification_projection(summary: dict[str, Any], entry: dict[str, Any], root: Path) -> dict[str, Any]:
    result = dict(summary)
    references = {}
    for bucket in CLASSIFICATION_BUCKETS:
        if bucket not in result:continue
        values = result.pop(bucket)
        if not isinstance(values, list):raise CompositionError('invalid_classification_collection')
        # Same canonicalization as naos_evidence_classification.canonical_item_bytes.
        canonical = json.dumps(values, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
        references[bucket] = {'source': source_reference(entry, root), 'json_pointer': '/' + bucket,
                              'item_count': len(values), 'canonical_sha256': hashlib.sha256(canonical).hexdigest(),
                              'canonicalization': 'json_sort_keys_ascii_compact_v1'}
    result['collection_references'] = references
    return result

def read_collection_bucket(reference: dict[str, Any], root: Path, *, max_bytes: int = DETAIL_MAX_BYTES) -> dict[str, Any]:
    """Expand a complete named inventory only after source and bucket identity checks."""
    def unavailable(reason):return {'detail_availability': 'unavailable', 'requirement_outcome': 'unresolved', 'reason': reason, 'data': None}
    if (not isinstance(reference, dict) or set(reference) != {'source', 'json_pointer', 'item_count', 'canonical_sha256', 'canonicalization'}
            or reference.get('json_pointer') not in {'/' + bucket for bucket in CLASSIFICATION_BUCKETS}
            or reference.get('canonicalization') != 'json_sort_keys_ascii_compact_v1'
            or type(reference.get('item_count')) is not int or reference['item_count'] < 0):
        return unavailable('invalid_collection_reference')
    resolved = read_collection_entry(reference['source'], root, max_bytes=max_bytes)
    if resolved['detail_availability'] != 'available':return resolved
    data = resolved['data']
    bucket = reference['json_pointer'][1:]
    values = data.get(bucket) if isinstance(data, dict) else None
    if not isinstance(values, list):return unavailable('malformed_source_collection')
    canonical = json.dumps(values, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    if len(values) != reference['item_count'] or hashlib.sha256(canonical).hexdigest() != reference['canonical_sha256']:
        return unavailable('changed_collection_identity')
    return {'detail_availability': 'available', 'requirement_outcome': 'unresolved', 'reason': 'exact_collected_bucket', 'data': values}


def collection_count(summary: dict[str, Any], bucket: str) -> int:
    references = summary.get('collection_references')
    if isinstance(references, dict) and bucket in references:
        count = references[bucket].get('item_count')
        if type(count) is not int or count < 0:raise CompositionError('invalid_collection_count')
        return count
    return len(summary.get(bucket) or [])

def compose_publication(report: dict[str, Any], root: Path) -> dict[str, Any]:
    schema = report.get('schema')
    if schema not in ('naos.evidence_pack.v1', 'naos.dashboard_summary.v1'):
        raise CompositionError('unknown_publication_version')
    field = 'artifacts' if schema == 'naos.evidence_pack.v1' else 'inputs'
    entries = report[field]
    result = dict(report)
    result['schema'] = schema[:-1] + '2'
    result[field] = {key:source_reference(entry, root) for key,entry in entries.items()}
    classification = entries.get('evidence_classification_report' if field == 'artifacts' else 'evidence_classification')
    if classification is not None:
        result['evidence_classification'] = classification_projection(report['evidence_classification'], classification, root)
    if field == 'inputs' and 'capability_maturity' in entries:
        result[field]['capability_maturity']['collection_witness'] = maturity_witness(entries['capability_maturity'])
    checked_publication_bytes(result)
    return result

def checked_publication_bytes(report: dict[str, Any]) -> bytes:
    raw = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')
    if len(raw) > PUBLICATION_MAX_BYTES:raise CompositionError('composition_publication_exceeds_8mib')
    return raw
