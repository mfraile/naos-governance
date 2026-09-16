"""Read-only validation of local producer reports against current declared inputs."""
from __future__ import annotations

import json
from typing import Any, Callable

import yaml
from jsonschema import Draft202012Validator

from naos_policy import kit_root


def validate_current_report(
    report: Any, *, schema_name: str, expected: Callable[[], dict[str, Any]],
    source_hash_field: str,
) -> tuple[list[str], list[str]]:
    """Validate v1 structure and reproduce its content; timestamps are not freshness.

    Reproduction is read-only and calls no provider or model. It includes producer
    dependencies (role references, configuration, local telemetry, and review age).
    Old reports remain readable, but only reports matching current source content
    can supply a clean review result. Attribution metadata is not authentication.
    """
    try:
        schema = json.loads((kit_root() / 'schemas' / 'naos' / (schema_name + '.schema.json')).read_text(encoding='utf-8'))
        errors = sorted(error.message for error in Draft202012Validator(schema).iter_errors(report))
    except (OSError, ValueError) as exc:
        return ['consumer_unavailable'], [f'Canonical report schema unavailable: {exc}']
    if errors:
        return ['schema_invalid'], errors
    try:
        current = expected()
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        return ['consumer_unavailable'], [f'Current producer inputs cannot be evaluated: {exc}']
    reasons: list[str] = []
    errors = []
    for field in ('profile', 'project_root', 'naos_root'):
        if report.get(field) != current.get(field):
            reasons.append('identity_mismatch')
            errors.append(f'{field} does not match the current consumer context')
    if report.get(source_hash_field) != current.get(source_hash_field):
        reasons.append('source_stale')
        errors.append(f'{source_hash_field} does not match the current declaration')
    # All producer-owned fields are compared. New or missing fields are incompatible,
    # not silently inferred. generated_by is informational local attribution only.
    volatile = {'generated_at', 'generated_by'}
    stored = {key: value for key, value in report.items() if key not in volatile}
    fresh = {key: value for key, value in current.items() if key not in volatile}
    if stored != fresh:
        reasons.append('content_mismatch')
        errors.append('Stored report content differs from current read-only producer output; regenerate the report')
    return list(dict.fromkeys(reasons)), errors
