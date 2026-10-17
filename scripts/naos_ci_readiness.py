#!/usr/bin/env python3
"""Installed readiness runner: retain command failures while collecting evidence.

Used by generated CI in a disposable checkout. This runs deterministic local
commands, preserves their existing policy/exit semantics, and never uploads.
Explicit dependency acquisition invalidates the prior owned proof once, then
invalidates the two gate sinks before production. Final dependency
evaluation retains the prior sink while computing, then requires changed output
bytes or invalidates it before another consumer. Other evidence keeps its contract.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import uuid

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from naos_policy import (  # noqa: E402
    evidence_pack_output_path, load_policy, naos_root_path, report_output_path, resolve_policy_path,
    safe_policy_path, write_report,
)
from naos_pr_governance_summary import project_gate_readiness  # noqa: E402

# CLI names/arguments are deliberately explicit; this is not a shell evaluator.
PRODUCERS = (
    ('claims',), ('setup-recommendations',), ('governance-bypass-posture',),
    ('external-evidence-ingest',), ('memory-readiness',), ('learning-loop-review',),
    ('context-index',), ('context-query',),
    ('semantic-candidates',), ('graph-context',), ('graph-query',),
    ('task-context',), ('evidence-attestation',),
    ('systemic-impact',), ('module-headers',),
    ('spec-pack-contract',), ('spec-pack-materialize', '.', '--dry-run'),
    ('spec-assembly-worksheet', '.'), ('spec-cascade',), ('model-policy',),
    ('model-telemetry',), ('roadmap-crosswalk',), ('function-index-health',),
    ('test-evidence-map',), ('test-evidence',), ('duplicate-function-hygiene',),
    ('test-quality-hygiene',), ('secret-hygiene',), ('dependency-integrity',),
    ('package-reality',), ('api-symbol-reality',), ('secure-coding-controls',),
    ('secure-coding-reporting', '--refresh-sources'), ('capability-maturity',),
    ('failure-mode-posture',), ('opencode-config-hygiene',),
    ('design-traceability',), ('ui-experience-quality',),
    ('failure-mode-observations',), ('control-plane-review',),
    ('ai-surface-budget',), ('self-check',),
)
CONSUMERS = (
    ('evidence-pack',), ('dashboard',),
    ('secure-coding-reporting', '--check', '--project'),
    ('sarif-export',), ('pr-governance-summary',),
)


def output_paths(root, naos_root, policy):
    """Reserve policy-selected report sinks, including downstream projections."""
    keys = {key for key in policy['paths'] if key.endswith('_report')}
    keys.update({'dashboard_summary_report', 'secure_coding_reporting_report'})
    outputs = {
        key: report_output_path(root, naos_root, policy, key)
        for key in keys
    }
    outputs['evidence_pack_report'] = evidence_pack_output_path(root, naos_root, policy)
    return outputs


def gate_sinks(root, naos_root, policy, policy_path=None, *, selected=None):
    """Preflight both disposable gate destinations before changing either."""
    outputs = {
        name: report_output_path(root, naos_root, policy, key)
        for name, key in (('gate-status', 'gate_status_report'),
                          ('gate-evaluate', 'gate_evaluation_report'))
    }
    if any(path is None for path in outputs.values()):
        raise ValueError('CI readiness requires an adopter project with a NAOS state directory')
    if len(set(outputs.values())) != 2:
        raise ValueError('Gate report destinations must be distinct')
    state_root = naos_root_path(root, naos_root)
    inputs = input_paths(root, state_root, policy, policy_path, naos_root)
    for name, path in outputs.items():
        if path in inputs or path.suffix != '.json' or path.parent == state_root:
            raise ValueError('Gate report destination aliases input/state or lacks a report directory')
        if (selected is None or selected == name) and path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError(f'Gate report must be a regular unlinked output: {path}')
            previous = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(previous, dict) or previous.get('schema') not in {
                'naos.gate_status.v1', 'naos.gate_input_error.v1',
            }:
                raise ValueError(f'Refusing to discard an unrecognized gate output: {path}')
    return outputs


def _checked_gate_destinations(root, naos_root, policy_path, sinks, receipt_path, *, selected):
    """Recheck current path topology and aliases before reading or invalidating output."""
    current = load_policy(policy_path, naos_root, root)
    checked = gate_sinks(root, naos_root, current, policy_path, selected=selected)
    current_outputs = output_paths(root, naos_root, current)
    others = {path for key, path in current_outputs.items()
              if key not in {'gate_status_report', 'gate_evaluation_report'}}
    state_root = naos_root_path(root, naos_root)
    if (checked != sinks or set(checked.values()) & others
            or receipt_path in others
            or receipt_path in input_paths(root, state_root, current, policy_path, naos_root)):
        raise ValueError('Gate destinations or report/input aliases changed during readiness')
    return checked[selected]


def input_paths(root, state_root, policy, policy_path, naos_root):
    selected_policy = resolve_policy_path(policy_path, naos_root, root)[0]
    inputs = {state_root / 'gatekeepers.yaml'}
    if selected_policy is not None:
        inputs.add((root / selected_policy).resolve())
    for key, value in policy['paths'].items():
        if (not key.endswith('_report') and isinstance(value, str)
                and value.endswith(('.json', '.yaml', '.yml'))):
            inputs.add((state_root / value).resolve())
    return inputs


def _invalidate_dependency_proof(root, naos_root, policy, policy_path, readiness_path, validator):
    """Discard only a recognized derived proof before explicit fresh acquisition.

    Recognition permits refreshing this output, not accepting its readiness.
    Final publication and every reader still perform full source verification.
    Like gate cleanup, this does not claim concurrent-writer serialization.
    """
    from naos_self_check_dependency_resolution import receipt_path, _json, _schema

    def checked():
        current = load_policy(policy_path, naos_root, root)
        if current != policy:
            raise ValueError('Dependency proof policy changed before acquisition')
        path = receipt_path(root, naos_root, current)
        state_root = naos_root_path(root, naos_root)
        protected = input_paths(root, state_root, current, policy_path, naos_root)
        protected.update(path for key, path in output_paths(root, naos_root, current).items()
                         if key != 'self_check_dependency_resolution_report')
        protected.update({readiness_path, validator})
        if any(path == other.resolve() or (path.exists() and other.exists() and path.samefile(other))
               for other in protected):
            raise ValueError('Dependency proof destination aliases an input, report or validator')
        if not path.exists():
            return path, None, None
        previous, digest = _json(root, path)
        _schema(previous, 'self_check_dependency_resolution.schema.json')
        if (previous.get('status') != 'resolved'
                or previous.get('project_root') != str(root.resolve())
                or previous.get('naos_root') != naos_root):
            raise ValueError('Refusing to discard an unrecognized or differently scoped dependency proof')
        # A supported profile transition may legitimately replace its old proof.
        metadata = path.stat()
        return path, digest, (metadata.st_dev, metadata.st_ino)

    path, digest, identity = checked()
    if digest is None:
        return {'status': 'no_prior_proof', 'path': str(path), 'prior_sha256': None}
    if checked() != (path, digest, identity):
        raise ValueError('Dependency proof changed before acquisition invalidation')
    path.unlink()
    return {'status': 'prior_proof_invalidated', 'path': str(path), 'prior_sha256': digest}


def _reporting_source_binding(root, profile, naos_root, policy):
    """Reproduce canonical P3 from current P1/P2 without publishing any bytes."""
    from naos_self_check_dependency_resolution import _json, _schema, _report_path
    from secure_coding_reporting.model import build_report

    keys = ('secure_coding_reference_integrity_report', 'secure_coding_controls_report',
            'secure_coding_reporting_report')
    paths = {key: _report_path(root, naos_root, policy, key) for key in keys}
    before = {key: _json(root, path)[1] for key, path in paths.items()}
    stored, _ = _json(root, paths[keys[2]])
    _schema(stored, 'secure_coding_reporting.schema.json')
    if any(stored.get(key) != value for key, value in
           {'profile': profile, 'project_root': str(root), 'naos_root': naos_root}.items()):
        raise ValueError('Canonical P3 scope mismatch')
    current = build_report(root=root, naos_root=naos_root, profile=profile, policy=policy,
        reference_path=paths[keys[0]], controls_path=paths[keys[1]],
        check_mode=stored['check_mode'], generated_at=stored['generated_at'])
    # No nested timestamps, dimensions, findings or source bindings are removed.
    # Acquisition publishes canonical P3 with empty projection metadata.
    if stored != current or stored.get('status') != 'pass':
        raise ValueError('Canonical P3 is not exactly reproducible from current P1/P2')
    after = {key: _json(root, path)[1] for key, path in paths.items()}
    if before != after:
        raise ValueError('Authoritative secure-coding evidence changed during reproduction')
    return after


def _assured_maturity_cycle(root, profile, naos_root, policy):
    """Only the existing independently checked finite maturity/G6 component."""
    from naos_self_check_dependency_resolution import _collect_maturity_obligations, _report_path
    reference = _report_path(root, naos_root, policy, 'self_check_report').relative_to(root).as_posix()
    return _collect_maturity_obligations(root, profile, naos_root, policy, reference)


def _budget_guarded_bytes(root, path):
    from naos_systemic_family_review import _local_bytes
    from naos_policy import kit_root
    path = path.absolute()
    base = root.absolute()
    if not path.is_relative_to(base):
        kit = kit_root().absolute()
        if path not in {kit / 'policies/default_policy.yaml',
                        kit / 'templates/structural-seeds/naos/ai_surface_context_budget_rules.yaml'}:
            raise ValueError('Budget input is outside its selected resource boundary')
        base = kit
    if path.lstat().st_nlink != 1:
        raise ValueError('Hardlinked budget witness')
    data = _local_bytes(base, path.relative_to(base).as_posix())
    if path.lstat().st_nlink != 1:
        raise ValueError('Hardlinked budget witness changed')
    return data


def _budget_policy_binding(root, naos_root, policy, policy_path):
    from naos_systemic_family_review import _digest
    selected, source = resolve_policy_path(policy_path, naos_root, root)
    path = (root / selected).absolute() if selected is not None else None
    before = _budget_guarded_bytes(root, path) if path else None
    current = load_policy(str(path) if path else None, naos_root, root)
    after = _budget_guarded_bytes(root, path) if path else None
    metadata = policy.get('_meta', {})
    admitted_path = (root / metadata['path']).absolute() if metadata.get('path') else None
    effective = {k: v for k, v in current.items() if k != '_meta'}
    if (before != after or effective != {k: v for k, v in policy.items() if k != '_meta'}
            or admitted_path != path or metadata.get('source') != source):
        raise ValueError('Budget invocation selected policy changed')
    return {'path': str(path) if path else None, 'source': source,
            'sha256': hashlib.sha256(before).hexdigest() if before is not None else None,
            'effective_sha256': _digest({k: v for k, v in current.items() if k != '_meta'})}


def _budget_preflight(root, naos_root, policy, policy_path, readiness_path, sinks):
    from naos_ai_surface_budget import default_rules_path, default_baseline_path, deep_merge, DEFAULT_RULES
    from naos_policy import load_operand_yaml
    from naos_systemic_family_review import _review_source_paths, _reference
    from naos_configuration_posture_review import _refuse_alias
    binding = _budget_policy_binding(root, naos_root, policy, policy_path)
    output, _ = _budget_output_digest(root, naos_root, policy)
    rules_path = default_rules_path(root, naos_root, policy)
    declared = load_operand_yaml(_budget_guarded_bytes(root, rules_path)) or {}
    if not isinstance(declared, dict):
        raise ValueError('Selected budget generating rules must be a mapping')
    rules = deep_merge(DEFAULT_RULES, declared)
    # Discover the same selected inputs as the producer, without imposing the
    # stricter warning-review estimator, thresholds or catalogue eligibility.
    patterns = []
    for family in rules.get('families') or []:
        if isinstance(family, dict):
            patterns.extend(pattern for pattern in family.get('patterns') or []
                            if isinstance(pattern, str) and pattern)
    for scenario in rules.get('combined_scenarios') or []:
        if not isinstance(scenario, dict):
            continue
        for item in scenario.get('files') or []:
            if isinstance(item, str):
                pattern = item
            elif isinstance(item, dict):
                pattern = str(item.get('path') or '')
            else:
                continue
            if pattern:
                patterns.append(pattern)
    baseline = default_baseline_path(root, naos_root, rules, policy)
    from naos_ai_surfaces import checked_path
    checked_path(root, _reference(baseline.relative_to(root).as_posix()))
    if baseline.exists():
        _budget_guarded_bytes(root, baseline)
    state = naos_root_path(root, naos_root)
    record = safe_policy_path(state, policy['paths']['evidence_review_attestations'], field='budget_review_record')
    protected = input_paths(root, state, policy, policy_path, naos_root)
    protected.update({rules_path, baseline, record, readiness_path, *sinks.values()})
    protected.update(path for key, path in output_paths(root, naos_root, policy).items()
                     if key != 'ai_surface_context_budget_report')
    if binding['path']:
        protected.add(Path(binding['path']))
    reference = output.relative_to(root).as_posix()
    measured = (_review_source_paths(root, {'review_source_patterns': sorted(set(patterns))}, {reference})
                if patterns else [])
    protected.update(root / name for name in measured)
    if record.exists() or record.is_symlink():
        document = load_operand_yaml(_budget_guarded_bytes(root, record), unique_string_keys=True)
        if not isinstance(document, dict):
            raise ValueError('Malformed selected review record')
        reviews = document.get('configuration_posture_reviews', [])
        if not isinstance(reviews, list):
            raise ValueError('Malformed selected review entries')
        for entry in reviews:
            if not isinstance(entry, dict):
                raise ValueError('Malformed selected review entry')
            snapshot = entry.get('subject_snapshot', {})
            if not isinstance(snapshot, dict) or not isinstance(entry.get('evidence_sha256', {}), dict):
                raise ValueError('Malformed selected review references')
            for name in ([snapshot['path']] if 'path' in snapshot else []) + list(entry.get('evidence_sha256', {})):
                protected.add(root / _reference(name))
    if any(output.absolute() == other.absolute() for other in protected):
        raise ValueError('Budget output aliases a protected input or output')
    if output.exists():
        _refuse_alias(output, list(protected))
    if _budget_policy_binding(root, naos_root, policy, policy_path) != binding:
        raise ValueError('Budget policy changed during preflight')
    return binding


def _budget_output_digest(root, naos_root, policy):
    """Read only the selected regular canonical output, refusing linked topology."""
    path = report_output_path(root, naos_root, policy, 'ai_surface_context_budget_report')
    if not path.absolute().is_relative_to(root.absolute()):
        raise ValueError('Budget output escapes project root')
    for ancestor in (path, *path.parents):
        if ancestor == root:
            break
        if (ancestor.is_symlink() or (ancestor.exists()
                and getattr(ancestor.lstat(), 'st_file_attributes', 0) & 0x400)):
            raise ValueError('Linked budget output topology')
    if not path.exists():
        return path, None
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or getattr(metadata, 'st_file_attributes', 0) & 0x400):
        raise ValueError('Unsafe budget output')
    return path, hashlib.sha256(_budget_guarded_bytes(root, path)).hexdigest()


def _budget_acquisition_review(record, expected_argv, root, profile, naos_root,
                               policy, prior_sha256, output_sha256, invocation_started_at, policy_path, policy_binding):
    """Existing exact warning review only; raw exit and final proof stay required."""
    from naos_evidence_contracts import classify_evidence
    from naos_policy import exit_code_for_summary
    if (record['argv'] != expected_argv or record.get('phase') != 'acquisition'
            or record['returncode'] != 1 or record['outcome'] != 'nonzero_exit'
            or not output_sha256 or output_sha256 == prior_sha256):
        raise ValueError('Budget invocation/publication is not reviewable')
    path, current_sha256 = _budget_output_digest(root, naos_root, policy)
    if current_sha256 != output_sha256:
        raise ValueError('Budget publication changed before classification')
    if _budget_policy_binding(root, naos_root, policy, policy_path) != policy_binding:
        raise ValueError('Budget policy changed after producer invocation')
    data = json.loads(_budget_guarded_bytes(root, path))
    if not isinstance(data, dict) or not isinstance(data.get('generated_at'), str) or not data['generated_at']:
        raise ValueError('Budget publication must have an object and timestamp')
    generated_at = datetime.fromisoformat(data['generated_at'].replace('Z', '+00:00'))
    started_at = datetime.fromisoformat(invocation_started_at)
    if generated_at.tzinfo is None or not started_at <= generated_at <= datetime.now(timezone.utc):
        raise ValueError('Budget output timestamp is not from this invocation')
    review_path = safe_policy_path(naos_root_path(root, naos_root),
        policy['paths']['evidence_review_attestations'], field='budget_review_record')
    review_record_sha256 = hashlib.sha256(_budget_guarded_bytes(root, review_path)).hexdigest()
    classified = classify_evidence(root, path.relative_to(root).as_posix(),
        profile=profile, naos_root=naos_root, policy=policy, consumer='gate')
    review = classified.get('configuration_posture_review', {})
    declaration = review.get('declaration', {})
    if (classified.get('report_key') != 'ai_surface_context_budget'
            or classified.get('validation') != 'valid' or classified.get('scope') != 'matched'
            or classified.get('requirement_outcome') != 'satisfied'
            or classified.get('content_sha256') != output_sha256
            or classified.get('generation_age', {}).get('status') not in {'within_window', 'not_enforced'}
            or review.get('status') != 'recorded'
            or declaration.get('review_outcome') != 'reviewed_budget_warnings_only'
            or exit_code_for_summary(profile, data.get('summary', {}), policy, False) != 1):
        raise ValueError('Exact current budget warning review is unresolved')
    if (root / review['record_reference'] != review_path
            or hashlib.sha256(_budget_guarded_bytes(root, review_path)).hexdigest() != review_record_sha256):
        raise ValueError('Budget review record changed during classification')
    if _budget_policy_binding(root, naos_root, policy, policy_path) != policy_binding:
        raise ValueError('Budget policy changed through classification')
    if _budget_output_digest(root, naos_root, policy)[1] != output_sha256:
        raise ValueError('Budget publication changed during classification')
    return {'status': 'recorded_warning_review_acquisition_only',
            'reference': path.relative_to(root).as_posix(),
            'invocation_started_at': invocation_started_at,
            'prior_sha256': prior_sha256, 'output_sha256': output_sha256,
            'review_record_reference': review['record_reference'],
            'review_record_sha256': review_record_sha256,
            'subject_sha256': declaration['binding']['subject_sha256'],
            'review_outcome': 'reviewed_budget_warnings_only',
            'raw_returncode': 1, 'raw_outcome': 'nonzero_exit',
            'final_dependency_proof_required': True}


def _acquisition_error(item, profile):
    if item['returncode'] == 0:
        return False
    if item['outcome'] == 'nonzero_exit' and item['returncode'] == 1:
        if len(item['argv']) > 2 and item['argv'][2] in (
                {'self-check', 'gate-evaluate', 'capability-maturity'}
                if profile == 'assured' else {'self-check', 'gate-evaluate'}):
            return False
        if (len(item['argv']) > 2 and item['argv'][2] == 'ai-surface-budget'
                and item.get('phase') == 'acquisition'
                and item.get('budget_review_disposition', {}).get('status') == 'recorded_warning_review_acquisition_only'):
            return False
    return True


def run_chain(root, profile, naos_root, ac_validator=None, *, policy_path=None, timeout=300,
              pr_base_ref=None, pr_head_ref=None, team_id=None,
              task=None, query=None, graph_path=None, finalize_dependencies=False):
    task = task if task is not None else os.environ.get('TASK') or os.environ.get('NAOS_TASK') or None
    query = 'governance' if query is None else query
    for name, value in (('task', task), ('query', query), ('graph-path', graph_path)):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f'Explicit {name} context must be a nonempty string')
    task_options = ['--task', task] if task is not None else []
    query_options = task_options + ['--query', query]
    graph_options = task_options + (['--path', graph_path] if graph_path is not None else [])
    self_check_options = task_options + ['--query', query] + (['--graph-path', graph_path] if graph_path is not None else [])
    pr_mode = pr_base_ref is not None or pr_head_ref is not None
    if pr_mode and not all(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value)
                           for value in (pr_base_ref, pr_head_ref)):
        raise ValueError('PR comparison requires explicit full 40-character base and head commit SHAs')
    if team_id is not None and not pr_mode:
        raise ValueError('Team metadata requires an explicit PR comparison')
    if finalize_dependencies and profile not in {'lite', 'standard', 'assured'}:
        raise ValueError('Dependency finalization supports Lite, Standard and Assured profiles')
    policy = load_policy(policy_path, naos_root, root)
    sinks = gate_sinks(root, naos_root, policy, policy_path)
    state_root = naos_root_path(root, naos_root)
    receipt_path = safe_policy_path(state_root, policy['paths']['reports_dir'],
                                    'ci_readiness.json', field='ci_readiness')
    if (receipt_path in sinks.values()
            or receipt_path in input_paths(root, state_root, policy, policy_path, naos_root)):
        raise ValueError('Readiness receipt must not alias a gate report or input')
    outputs = output_paths(root, naos_root, policy)
    reserved = {'gate_status_report', 'gate_evaluation_report'}
    other_outputs = {path for key, path in outputs.items() if key not in reserved}
    if set(sinks.values()) & other_outputs or receipt_path in other_outputs:
        raise ValueError('Gate/receipt destination aliases another report output')
    overridden = ac_validator is not None
    if overridden and not os.fspath(ac_validator).strip():
        raise ValueError('AC validator override must be a nonempty project-contained path')
    validator = (safe_policy_path(root, ac_validator, field='ac_validator') if overridden
                 else SCRIPT_DIR / 'validators' / 'validate_test_ac_references.py')
    applicable = profile in {'standard', 'assured'}
    validator_digest = None
    if applicable:
        if not stat.S_ISREG(validator.lstat().st_mode):
            raise ValueError('AC validator must be a regular file')
        canonical_validator = validator.resolve()
        if not overridden and not canonical_validator.is_relative_to(SCRIPT_DIR):
            raise ValueError('Default AC validator must remain inside the running kit')
        for destination in {*outputs.values(), receipt_path}:
            if (canonical_validator == destination.resolve()
                    or (destination.exists() and destination.samefile(validator))):
                raise ValueError('AC validator must not alias a report or readiness receipt')
        validator = canonical_validator
        validator_digest = hashlib.sha256(validator.read_bytes()).hexdigest()
    receipt = {
        'schema': 'naos.ci_readiness.v1', 'run_id': str(uuid.uuid4()),
        'started_at': datetime.now(timezone.utc).isoformat(), 'profile': profile,
        'status': 'running', 'status_dimension': ('dependency_acquisition_and_final_evaluation'
            if finalize_dependencies else 'command_execution_and_output_collection'),
        'commands': [],
        'ac_validator': {
            'authority': 'adopter_override' if overridden else 'runner_adjacent',
            'path': str(validator), 'sha256': validator_digest, 'applicable': applicable,
        },
        'gate_outputs': {name: str(path) for name, path in sinks.items()},
        'limitations': ['Local command execution is not hosted or native-platform acceptance.',
                        'Acquisition invalidates gate outputs before production. Final dependency evaluation retains the prior gate during computation and requires changed canonical output bytes; incomplete or unchanged publication is invalidated before another consumer.',
                        'Exit codes are recorded without redefining them as policy decisions; gate readiness is a separate validated source projection.',
                        'AC validator identity records selection and a pre-execution digest, not installation authenticity or protection against concurrent file replacement.'],
    }
    if finalize_dependencies:
        receipt['dependency_resolution_refresh'] = _invalidate_dependency_proof(
            root, naos_root, policy, policy_path, receipt_path, validator)
        receipt['limitations'].append(
            'Explicit fresh dependency acquisition invalidates the prior recognized proof once; '
            'failed acquisition leaves dependency readers unresolved until a new proof is verified. '
            'Dashboard JSON is retained in its report; command output contains the bounded presentation.')
    write_report(receipt_path, receipt)
    prefix = [sys.executable, str(SCRIPT_DIR.parent / 'cli.py')]
    options = ['--profile', profile, '--naos-root', naos_root]
    if policy_path:
        options += ['--policy', str(policy_path)]
    commands = []
    if applicable:
        commands.append([sys.executable, str(validator)])
    if pr_mode:
        commands += [prefix + list(command) + options for command in (
            ('session-id',), ('operator-attribution',), ('policy-overrides', '--dry-run'),
        )]
    if pr_mode:
        commands.append(prefix + ['pr-risk-classify'] + options + [
            '--base-ref', pr_base_ref, '--head-ref', pr_head_ref,
        ])
    for command in PRODUCERS:
        producer_options = list(options)
        if command[0] == 'context-query':
            producer_options += query_options
        elif command[0] == 'graph-query':
            producer_options += graph_options
        elif command[0] == 'task-context':
            producer_options += task_options
        elif command[0] == 'self-check':
            # Readiness explicitly collects persistent evidence for later gates.
            producer_options += ['--refresh'] + self_check_options
        if pr_mode and command[0] == 'self-check':
            producer_options += ['--pr-base-ref', pr_base_ref, '--pr-head-ref', pr_head_ref]
        commands.append(prefix + list(command) + producer_options)
    if pr_mode:
        commands += [prefix + [command] + options for command in ('task-claims', 'evidence-conflicts')]
    for name, path in sinks.items():
        gate_options = options + ['--output', str(path)]
        if pr_mode and team_id:
            gate_options += ['--team-id', team_id]
        if pr_mode and name == 'gate-evaluate' and profile in {'standard', 'assured'}:
            gate_options += ['--strict-required']
        commands.append(prefix + [name] + gate_options)
    commands += [prefix + list(command) + options for command in CONSUMERS]
    acquisition_count = len(commands)
    provisional_collection = set()
    proof_index = None
    reporting_binding = None
    if finalize_dependencies:
        # A fixed acquisition/finalization protocol, never retry-until-green.
        # All acquisition diagnostics remain in this receipt. Only exact cycle
        # command exits may advance to an independently verified final report.
        final_self_check = prefix + ['self-check'] + options + self_check_options
        if pr_mode:
            final_self_check += ['--pr-base-ref', pr_base_ref, '--pr-head-ref', pr_head_ref]
        commands += [prefix + ['self-check', '--capture-dependency-inputs'] + options,
                     final_self_check + ['--refresh']]
        if profile in {'lite', 'standard', 'assured'}:
            provisional_collection.add(acquisition_count + 1)
            # Full F1 owns current independent bytes. Refresh both stored gates
            # against F1 before proving G6; this is one finite collection pass.
            for name, path in sinks.items():
                gate_options = options + ['--output', str(path)]
                if pr_mode and team_id:
                    gate_options += ['--team-id', team_id]
                if name == 'gate-evaluate':
                    gate_options += ['--strict-required']
                provisional_collection.add(len(commands))
                commands.append(prefix + [name] + gate_options)
        proof_index = len(commands)
        commands.append(final_self_check + ['--finalize-dependencies'])
        for name, path in sinks.items():
            gate_options = options + ['--output', str(path)]
            if pr_mode and team_id:
                gate_options += ['--team-id', team_id]
            if name == 'gate-evaluate':
                gate_options += ['--strict-required']
            commands.append(prefix + [name] + gate_options)
        # History is an authored proof input. The acquisition dashboard records
        # it before capture; post-proof rendering must preserve its exact bytes,
        # including when this finite chain crosses a UTC date boundary.
        commands += [prefix + list(command) + options
                     + (['--no-progress-history'] if command[0] == 'dashboard' else [])
                     for command in CONSUMERS]
        receipt['limitations'].append(
            'Dependency acquisition retains raw self-check/gate evaluation diagnostics; Assured maturity diagnostics advance only after existing strict finite obligations reproduce. F1 and pre-proof gates retain raw exits; '
            'only a separately verified complete dependency proof and successful final '
            'commands can pass this explicitly selected mode.')
    gate_attempts = {name: False for name in sinks}
    for command_index, command in enumerate(commands):
        record = {'argv': command, 'returncode': None, 'outcome': 'launch_error'}
        if finalize_dependencies:
            record['phase'] = 'acquisition' if command_index < acquisition_count or command_index in provisional_collection else 'final_evaluation'
            if command_index == acquisition_count:
                independent_errors = [item for item in receipt['commands']
                                      if _acquisition_error(item, profile)]
                if independent_errors:
                    break
                if profile == 'assured':
                    try:
                        _reporting_source_binding(root, profile, naos_root, policy)
                        _assured_maturity_cycle(root, profile, naos_root, policy)
                    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                        record.update(outcome='publication_error', error=str(error))
                        receipt['commands'].append(record)
                        write_report(receipt_path, receipt)
                        break
            if profile == 'assured' and proof_index is not None and command_index == proof_index:
                try:
                    reporting_binding = _reporting_source_binding(root, profile, naos_root, policy)
                except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                    record.update(outcome='publication_error', error=str(error))
                    receipt['commands'].append(record)
                    write_report(receipt_path, receipt)
                    break
        retained_gate = None
        prior_gate_sha256 = None
        print('NAOS readiness command:', json.dumps(command), flush=True)
        if len(command) > 2 and command[2] in sinks:
            name = command[2]
            if finalize_dependencies and command_index >= acquisition_count:
                gate_attempts[name] = False
            try:
                # Earlier producers may have changed policy or replaced a sink.
                path = _checked_gate_destinations(root, naos_root, policy_path, sinks,
                                                  receipt_path, selected=name)
                if finalize_dependencies and command_index >= acquisition_count:
                    retained_gate = name
                    prior_gate_sha256 = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                    gate_attempts[name] = False
                else:
                    path.unlink(missing_ok=True)
                    gate_attempts[name] = True
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                record.update(outcome='cleanup_error', error=str(error))
                receipt['commands'].append(record)
                write_report(receipt_path, receipt)
                if finalize_dependencies and command_index >= acquisition_count:
                    break
                continue
        budget_invocation = (finalize_dependencies and command_index < acquisition_count
                             and command == prefix + ['ai-surface-budget'] + options)
        prior_budget_sha256 = None
        budget_started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        budget_policy_binding = None
        if budget_invocation:
            try:
                budget_policy_binding = _budget_preflight(root, naos_root, policy, policy_path, receipt_path, sinks)
                _, prior_budget_sha256 = _budget_output_digest(root, naos_root, policy)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                record.update(outcome='cleanup_error', error=str(error))
                receipt['commands'].append(record)
                write_report(receipt_path, receipt)
                continue
        try:
            if len(command) > 2 and command[2] == 'graph-query' and not graph_options:
                with tempfile.TemporaryDirectory(prefix='naos-context-inspection-') as directory:
                    command = command + ['--output', str(Path(directory) / 'diagnostic.json')]
                    record['argv'] = command
                    record['publication'] = {'mode': 'invocation_only_no_context',
                                             'default_receipt': 'preserved_not_validated'}
                    result = subprocess.run(command, cwd=root, timeout=timeout, check=False)
            else:
                result = subprocess.run(command, cwd=root, timeout=timeout, check=False)
            record.update(returncode=result.returncode,
                          outcome='completed' if result.returncode == 0 else 'nonzero_exit')
        except subprocess.TimeoutExpired:
            record.update(outcome='timeout')
        except OSError as error:
            record.update(error=str(error))
        if budget_invocation and record['returncode'] == 1 and record['outcome'] == 'nonzero_exit':
            try:
                _, output_sha256 = _budget_output_digest(root, naos_root, policy)
                record['budget_review_disposition'] = _budget_acquisition_review(
                    record, prefix + ['ai-surface-budget'] + options,
                    root, profile, naos_root, policy, prior_budget_sha256, output_sha256, budget_started_at, policy_path, budget_policy_binding)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                record['error'] = 'Budget acquisition review refused: ' + str(error)
        if retained_gate is not None:
            publication = {'mode': 'prior_retained_until_changed_output',
                           'prior_sha256': prior_gate_sha256, 'output_sha256': None,
                           'status': 'guarded_output_refused'}
            record['gate_publication'] = publication
            try:
                path = _checked_gate_destinations(root, naos_root, policy_path, sinks,
                                                  receipt_path, selected=retained_gate)
                output_sha256 = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                publication['output_sha256'] = output_sha256
                if record['outcome'] not in {'completed', 'nonzero_exit'}:
                    path.unlink(missing_ok=True)
                    publication['status'] = 'incomplete_invalidated'
                elif output_sha256 is None:
                    publication['status'] = 'missing_output'
                elif output_sha256 == prior_gate_sha256:
                    path.unlink(missing_ok=True)
                    publication['status'] = 'unchanged_invalidated'
                else:
                    publication['status'] = 'produced'
                    gate_attempts[retained_gate] = True
                if not gate_attempts[retained_gate] and record['outcome'] == 'completed':
                    record.update(outcome='publication_error', error='Gate command did not publish changed canonical output bytes')
            except (OSError, ValueError, TypeError, RuntimeError) as error:
                # Preserve unsafe/unrecognized/aliased paths; never delete them as stale output.
                record.update(outcome='publication_error', error=str(error))
        receipt['commands'].append(record)
        write_report(receipt_path, receipt)
        if (finalize_dependencies and command_index >= acquisition_count
                and (record['returncode'] != 0 or record['outcome'] != 'completed')
                and not (command_index in provisional_collection
                         and record['returncode'] == 1 and record['outcome'] == 'nonzero_exit')):
            break
    receipt['gate_outputs_present'] = {name: gate_attempts[name] and path.is_file() for name, path in sinks.items()}
    # Preserve the original generated workflow's output and projection checks.
    receipt['output_checks'] = {}
    for key in ('dashboard_summary_report', 'secure_coding_reporting_report', 'evidence_pack_report'):
        path = outputs[key]
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            valid = isinstance(data, dict)
            if key != 'secure_coding_reporting_report':
                valid = valid and 'secure_coding_reporting' in json.dumps(data)
            receipt['output_checks'][key] = bool(valid)
        except (OSError, ValueError):
            receipt['output_checks'][key] = False
    passed = (all(item['returncode'] == 0 for item in receipt['commands'])
              and all(receipt['gate_outputs_present'].values())
              and all(receipt['output_checks'].values()))
    receipt['status'] = 'pass' if passed else 'failed'
    receipt['gate_readiness'] = {
        label: project_gate_readiness(root, naos_root, profile, policy, label)
        for label in ('gate_status', 'gate_evaluation')
    }
    if finalize_dependencies:
        acquisition = [item for item in receipt['commands'] if item.get('phase') == 'acquisition']
        final = [item for item in receipt['commands'] if item.get('phase') == 'final_evaluation']
        receipt['acquisition_status'] = 'pass' if all(item['returncode'] == 0 for item in acquisition) else 'failed'
        passed = (len(receipt['commands']) == len(commands) and bool(final)
                  and all(item['returncode'] == 0 and item['outcome'] == 'completed' for item in final)
                  and all(receipt['gate_outputs_present'].values())
                  and all(receipt['output_checks'].values())
                  and all(item['required_readiness'] == 'ready' for item in receipt['gate_readiness'].values()))
        if profile in {'lite', 'standard', 'assured'}:
            from naos_self_check_dependency_resolution import verify_published_resolution
            try:
                if profile == 'assured':
                    receipt['output_checks']['secure_coding_source_binding'] = (
                        reporting_binding is not None and
                        _reporting_source_binding(root, profile, naos_root, policy) == reporting_binding)
                receipt['output_checks']['complete_dependency_resolution'] = (
                    verify_published_resolution(root, profile=profile, naos_root=naos_root,
                                                policy=policy).get('status') == 'resolved')
            except (OSError, ValueError, TypeError, KeyError, RuntimeError):
                if profile == 'assured':
                    receipt['output_checks']['secure_coding_source_binding'] = False
                receipt['output_checks']['complete_dependency_resolution'] = False
            passed = passed and all(receipt['output_checks'].values())
            if profile == 'assured':
                passed = passed and all(
                    item['readiness'] == 'ready' for item in receipt['gate_readiness'].values())
        receipt['status'] = 'pass' if passed else 'failed'
    receipt['finished_at'] = datetime.now(timezone.utc).isoformat()
    write_report(receipt_path, receipt)
    print(f'NAOS readiness {receipt["status"]}: {receipt_path}', flush=True)
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('lite', 'standard', 'assured'), required=True)
    parser.add_argument('--naos-root', default=os.environ.get('NAOS_ROOT', 'naos'))
    parser.add_argument('--ac-validator', default=None,
                        help='Explicit project-contained validator override; default uses the validator shipped beside this runner')
    parser.add_argument('--policy')
    parser.add_argument('--task', default=os.environ.get('TASK') or os.environ.get('NAOS_TASK') or None,
                        help='Explicit task id; defaults to TASK/NAOS_TASK')
    parser.add_argument('--query', help='Literal bounded local-context query; default governance')
    parser.add_argument('--graph-path', help='Exact indexed source path for graph-query --path')
    parser.add_argument('--pr-base-ref', help='Explicit immutable full base commit SHA for PR collection')
    parser.add_argument('--pr-head-ref', help='Explicit immutable full head commit SHA for PR collection')
    parser.add_argument('--team-id', help='Optional declared team metadata for PR gate reports; not authentication')
    parser.add_argument('--finalize-dependencies', action='store_true',
                        help='Run fixed Lite/Standard/Assured acquisition and verified final evaluation, preserving initial failures')
    args = parser.parse_args(argv)
    try:
        return run_chain(Path.cwd(), args.profile, args.naos_root, args.ac_validator,
                         policy_path=args.policy, pr_base_ref=args.pr_base_ref,
                         pr_head_ref=args.pr_head_ref, team_id=args.team_id,
                         task=args.task, query=args.query, graph_path=args.graph_path,
                         finalize_dependencies=args.finalize_dependencies)
    except (OSError, ValueError, TypeError) as error:
        print(f'NAOS readiness input/output error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
