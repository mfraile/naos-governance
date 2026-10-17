"""Pure subsequent-v3 plan, intent and registration records.

The records bind supplied bytes and validated local/native observations. They do
not grant filesystem authority or prove native completion. Checkpoint reference
reconciliation is not complete historical terminal validation; the native
inspector must independently validate every immutable journal and terminal. No terminal checkpoint
is constructed here: that needs a legal progress/executor contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import hashlib
from typing import Any

from . import local_binding as lb, local_store as ls
from . import portable_provenance as pp
from . import v3_operation_projection as projection
from .canonical import canonical_bytes
from .working_tree_capture import WorkingTreeCapture, build_capture

PLAN_SCHEMA = "naos.upgrade.v3_operation_plan.v1"
PUBLIC_PLAN_SCHEMA = "naos.upgrade.v3_operation_plan.v2"
SELECTED_PLAN_SCHEMA = "naos.upgrade.v3_operation_plan.v3"
NOOP_REVIEW_SCHEMA = "naos.upgrade.v3_profile_noop.v1"
INTENT_SCHEMA = "naos.upgrade.v3_operation_intent.v1"
MAX_RECORD_BYTES = lb.MAX_RECORD_BYTES


class OperationRecordError(ValueError):
    pass


def _closed(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except OperationRecordError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError,
                RecursionError) as exc:
            raise OperationRecordError("Invalid operation record input") from exc
    return call


def _fail(message: str) -> None:
    raise OperationRecordError(message)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _checked_bytes(raw: Any, label: str) -> bytes:
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        _fail(f"Invalid {label} bytes")
    return raw


def _record(body: dict[str, Any]) -> bytes:
    try:
        lb._bounded_input(body)
        raw = canonical_bytes(body)
        if len(raw) > MAX_RECORD_BYTES:
            _fail("Operation record exceeds byte budget")
        return raw
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise OperationRecordError("Invalid operation record") from exc


def _parsed(raw: bytes, label: str) -> dict[str, Any]:
    _checked_bytes(raw, label)
    try:
        body = pp._load_json(raw, label)
        if _record(body) != raw:
            _fail("Noncanonical operation record")
        return body
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise OperationRecordError("Malformed operation record") from exc


@dataclass(frozen=True)
class ValidatedOperationPlan:
    raw: bytes
    sha256: str

    @property
    def body(self) -> dict[str, Any]:
        return _parsed(self.raw, "operation plan")


@dataclass(frozen=True)
class ValidatedOperationIntent:
    raw: bytes
    sha256: str

    @property
    def body(self) -> dict[str, Any]:
        return _parsed(self.raw, "operation intent")


def _checked_capture(value: Any) -> dict[str, Any]:
    if type(value) is not WorkingTreeCapture or build_capture(
        value.body["native"], value.body["leaves"]
    ) != value:
        _fail("Validated complete working capture required")
    return value.body


def _checkpoint(binding: Any, state: Any, journal_ids: Any) -> tuple[dict, dict]:
    if (type(binding) is not lb.ValidatedLocalBinding or
            lb.load_local_binding(binding.raw) != binding or
            type(state) is not ls.ValidatedLocalStore or
            ls.load_local_store(state.raw) != state):
        _fail("Validated predecessor binding and store required")
    result = ls.reconcile_registration(state, binding, journal_ids)
    if result.status != "checkpoint_consistent" or result.active_journal_id is not None:
        _fail("Predecessor is not a complete inactive checkpoint")
    return binding.body, state.body


def _inventory(files: dict[str, bytes], label: str) -> list[dict[str, str]]:
    if type(files) is not dict or len(files) > pp.MAX_TOTAL_SELECTED_PATHS + pp.MAX_TOTAL_CHANGES + 10_000:
        _fail(f"Invalid {label} inventory")
    if any(type(path) is not str for path in files):
        _fail(f"Invalid {label} inventory path")
    total = 0
    result = []
    for path in sorted(files):
        raw = files[path]
        if type(path) is not str or type(raw) is not bytes or len(raw) > pp.MAX_BASE_BYTES:
            _fail(f"Invalid {label} entry")
        total += len(raw)
        if total > pp.MAX_CUMULATIVE_READ_BYTES:
            _fail(f"Oversized {label} inventory")
        result.append({"path": path, "sha256": _digest(raw),
                       "size_decimal": str(len(raw))})
    return result


def _record_witnesses(value: Any, platform: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {"binding", "state"}:
        _fail("Exact predecessor record witnesses required")
    for witness in value.values():
        lb._validate_witness(witness, platform, "file")
        if witness["presence"] != "present":
            _fail("Predecessor record witness absent")
        if platform == "Windows":
            if not witness["security"]["dacl_protected"]:
                _fail("Predecessor record security is unprotected")
        elif witness["mode_octal"] != "0600":
            _fail("Predecessor record is not private")
    return value


def _working_inputs(capture: dict, current_bytes: dict[str, bytes | None],
                    prior_observation: dict) -> dict[str, dict[str, Any]]:
    leaves = capture["leaves"]
    if type(current_bytes) is not dict or set(current_bytes) != {x["path"] for x in leaves}:
        _fail("Current byte inventory differs from complete capture")
    platform = capture["native"]["platform"]
    host = "windows" if platform == "Windows" else "posix"
    prior_native = prior_observation["native"]
    now_native = capture["native"]
    if (prior_native["platform"] != platform or prior_native["root_path"] != now_native["root_path"] or
            prior_native["root_chain"] != now_native["root_chain"] or
            prior_native["control_directories"] != now_native["control_directories"]):
        _fail("Root or local control witness changed")
    old_ancestors = {x["path"]: x["witness"] for x in prior_native["managed_ancestors"]}
    now_ancestors = {x["path"]: x["witness"] for x in now_native["managed_ancestors"]}
    if any(now_ancestors.get(path) != witness for path, witness in old_ancestors.items()):
        _fail("Historical managed ancestor witness changed")
    prior_leaves = {x["path"]: x for x in prior_observation["leaves"]}
    observations = {}
    total = 0
    for leaf in leaves:
        path = leaf["path"]
        raw = current_bytes[path]
        if raw is not None and (type(raw) is not bytes or len(raw) > pp.MAX_BASE_BYTES):
            _fail("Invalid current bytes")
        total += 0 if raw is None else len(raw)
        if total > pp.MAX_CUMULATIVE_READ_BYTES:
            _fail("Current byte budget exceeded")
        content = leaf["content"]
        if (raw is None) != (content is None):
            _fail("Current bytes and captured presence differ")
        if raw is not None and content != {"sha256": _digest(raw), "size_decimal": str(len(raw))}:
            _fail("Current bytes differ from captured content")
        witness = leaf["metadata"]
        prior = prior_leaves.get(path)
        drift = prior is not None and prior["metadata"] != witness
        # A new path's observed witness still only gives planning facts. Native
        # custody and namespace safety must be established again before writes.
        mode = (None if raw is None or host == "windows" else
                bool(int(witness["mode_octal"], 8) & 0o111))
        observations[path] = {"bytes": raw, "executable": mode,
                              "native_status": "metadata_drift" if drift else "clear"}
    return observations


def _request_source_identity(identity, metadata):
    if type(identity) is not dict or identity.get('kind') != 'file':
        _fail('Invalid artifact source identity')
    lb._hex(identity.get('sha256'), lb.HEX64, 'artifact source digest')
    if type(metadata) is not dict:
        _fail('Invalid artifact source metadata')
    if metadata.get('schema') == 'naos.windows.source_metadata.v1':
        if set(identity) != {'kind', 'size_decimal', 'sha256'} or set(metadata) != {'schema', 'attributes', 'security'}:
            _fail('Invalid Windows artifact source contract')
        lb._u64(identity['size_decimal'], 'artifact source size')
        if type(metadata['attributes']) is not int or metadata['attributes'] not in {32, 128}:
            _fail('Unsupported Windows artifact source attributes')
        security = metadata['security']
        if type(security) is not dict or set(security) != {'owner_sid_sha256', 'group_sid_sha256', 'dacl_sha256', 'dacl_protected'} or type(security['dacl_protected']) is not bool:
            _fail('Invalid Windows artifact source security')
        for key in ('owner_sid_sha256', 'group_sid_sha256', 'dacl_sha256'):
            lb._hex(security[key], lb.HEX64, 'artifact source security digest')
    else:
        from .security import validate_source_metadata_contract
        if set(identity) != {'kind', 'mode', 'size', 'sha256'} or any(type(identity[key]) is not int or identity[key] < 0 for key in ('mode', 'size')) or identity['size'] > pp.MAX_BASE_BYTES or identity['mode'] > 0o7777:
            _fail('Invalid POSIX artifact source contract')
        validate_source_metadata_contract(metadata)


def _request_actions(actions, profile):
    if type(actions) is not list or not actions or len(actions) > pp.MAX_TOTAL_SELECTED_PATHS:
        _fail('Explicit bounded setup actions required')
    required = {'type', 'source', 'destination', 'copy_mode', 'overwrite', 'profiles', 'explanation', 'post_install_next_actions'}
    for action in actions:
        if type(action) is not dict or set(action) not in (required, required | {'profile_patch'}):
            _fail('Unsupported setup action fields')
        if action['type'] not in {'copy_file', 'repair_seed', 'copy_tree'} or action['copy_mode'] != ('tree' if action['type'] == 'copy_tree' else 'file') or action['overwrite'] != 'skip':
            _fail('Unsupported setup action')
        pp._path(action['source'])
        pp._path(action['destination'])
        profiles = action['profiles']
        if type(profiles) is not list or not profiles or len(profiles) > 4 or any(type(item) is not str or item not in {'quickstart', 'lite', 'standard', 'assured'} for item in profiles) or profile not in profiles:
            _fail('Invalid selected setup action profiles')
        next_actions = action['post_install_next_actions']
        if type(action['explanation']) is not str or type(next_actions) is not list or len(next_actions) > pp.MAX_TOTAL_SELECTED_PATHS or any(type(item) is not str for item in next_actions):
            _fail('Invalid setup action instructions')
        if 'profile_patch' in action:
            patch = action['profile_patch']
            if type(patch) is not dict or not {'enabled'} <= set(patch) <= {'enabled', 'pattern', 'replacement_template'} or type(patch['enabled']) is not bool or any(type(v) is not str for k, v in patch.items() if k != 'enabled') or (patch['enabled'] and (not patch.get('pattern') or not patch.get('replacement_template'))):
                _fail('Invalid explicit setup profile patch')


def decode_public_request(value):
    if type(value) is not dict or set(value) != {'schema', 'canonical_json'} or value['schema'] != 'naos.add.review_request.v1':
        _fail('Exact canonical public request envelope required')
    encoded = value['canonical_json']
    if type(encoded) is not str or len(encoded) > MAX_RECORD_BYTES:
        _fail('Public request text exceeds limit')
    raw = encoded.encode('utf-8')
    if len(raw) > MAX_RECORD_BYTES:
        _fail('Public request bytes exceed limit')
    decoded = pp._load_json(raw, 'canonical public add/setup request')
    if canonical_bytes(decoded) != raw:
        _fail('Noncanonical public request text')
    return decoded


def _skill_host_route_review(value, profile):
    keys = {'schema', 'profile', 'inventory', 'observations', 'skill_names',
            'renderer', 'add_implementation', 'templates', 'policy'}
    if type(value) is not dict or set(value) != keys or value['schema'] != 'naos.add.skill_host_routes.v1' or value['profile'] != profile:
        _fail('Invalid progressive skill host route binding')
    for key in ['inventory', 'skill_names']:
        items = value[key]
        if type(items) is not list or len(items) > 4096 or any(type(item) is not str for item in items) or items != sorted(set(items)):
            _fail('Invalid progressive host route inventory')
        for item in items:
            pp._path(item)
            if key == 'skill_names' and '/' in item:
                _fail('Invalid progressive skill catalogue name')
    def source_contract(item):
        if type(item) is not list or len(item) != 2:
            _fail('Invalid progressive host route source contract')
        _request_source_identity(item[0], item[1])
    for key in ['renderer', 'add_implementation', 'policy']:
        source_contract(value[key])
    if type(value['templates']) is not dict or set(value['templates']) != {'portable-skill', 'claude-command'}:
        _fail('Exact progressive host templates required')
    for item in value['templates'].values():
        source_contract(item)
    observations = value['observations']
    if type(observations) is not list or len(observations) > 4096:
        _fail('Progressive reference observations exceed bound')
    paths = []
    for row in observations:
        if type(row) is not dict or type(row.get('present')) is not bool or set(row) != ({'path', 'present', 'identity', 'metadata'} if row['present'] else {'path', 'present'}):
            _fail('Invalid progressive reference observation')
        pp._path(row['path']); paths.append(row['path'])
        if row['present']:
            _request_source_identity(row['identity'], row['metadata'])
    if paths != sorted(set(paths)):
        _fail('Duplicate or unordered progressive reference observations')


def _public_request_review(value, operation, inputs):
    if type(value) is not dict or set(value) != {'request', 'checks', 'source_mode_inventory_sha256'}:
        _fail('Exact public add/setup review required')
    request = decode_public_request(value['request'])
    if type(request) is not dict or set(request) != {'operation', 'operation_inputs', 'selected_paths'} or request['operation'] != operation:
        _fail('Public add/setup request differs from operation')
    bound = request['operation_inputs']
    if type(bound) is not dict or set(bound) != {'schema', 'request_sha256', 'request'} or bound['schema'] != 'naos.add.operation_inputs.v1':
        _fail('Invalid public add/setup operation inputs')
    lb._hex(bound['request_sha256'], lb.HEX64, 'add source-authority digest')
    options = bound['request']
    if type(options) is not dict:
        _fail('Public add/setup options required')
    if operation.startswith('naos-add-artifact:'):
        kind, name = options.get('kind'), options.get('name')
        keys = {'kind', 'name', 'template'}
        if kind != 'skill':
            keys |= {'template_source', 'template_source_metadata', 'template_context_sha256'}
        elif 'host_routes' in options:
            keys.add('host_routes')
            _skill_host_route_review(options['host_routes'], inputs.get('profile'))
        if kind not in {'instruction', 'agent', 'spec', 'skill'} or type(name) is not str or not name or set(options) != keys:
            _fail('Unsupported public artifact options')
        if not operation.startswith('naos-add-artifact:' + kind + ':'):
            _fail('Public artifact kind differs')
        pp._path(operation.split(':', 2)[2])
        pp._path(options['template'])
        if kind != 'skill':
            _request_source_identity(options['template_source'], options['template_source_metadata'])
            lb._hex(options['template_context_sha256'], lb.HEX64, 'artifact context digest')
    elif operation.startswith('naos-add-setup-module:'):
        if set(options) != {'module_id', 'profile', 'catalog_sha256', 'catalog_schema_sha256', 'required_catalog_sha256', 'catalog_version', 'catalog_source', 'source_authority_sha256', 'selected_actions'}:
            _fail('Unsupported public setup options')
        if type(options['module_id']) is not str or not options['module_id'] or operation != 'naos-add-setup-module:' + options['module_id'] or options['profile'] != inputs.get('profile'):
            _fail('Public setup module/profile differs')
        for key in ('catalog_sha256', 'catalog_schema_sha256', 'required_catalog_sha256', 'source_authority_sha256'):
            lb._hex(options[key], lb.HEX64, 'setup authority digest')
        if any(type(options[key]) is not str for key in ('catalog_version', 'catalog_source')):
            _fail('Invalid setup catalogue descriptors')
        _request_actions(options['selected_actions'], options['profile'])
    else:
        _fail('Unsupported public add/setup operation')
    paths = request['selected_paths']
    if type(paths) is not list or not paths or paths != sorted(paths) or len(paths) > pp.MAX_TOTAL_SELECTED_PATHS:
        _fail('Exact public add/setup selected paths required')
    pp._unique_paths(paths)
    for path in paths:
        pp._path(path)
    lb._hex(value['source_mode_inventory_sha256'], lb.HEX64, 'add source-mode review digest')
    checks = value['checks']
    if type(checks) is not list or len(checks) != 1 or type(checks[0]) is not dict or checks[0] != {'check_id': 'managed_request_source_authority', 'status': 'passed', 'evidence_sha256': bound['request_sha256']}:
        _fail('Required public add/setup source check differs')
    return value


def _public_review(value, operation, inputs):
    if operation == "naos-hook-activate":
        from .hook_activation import validate_public_review
        validate_public_review(value)
        return value
    if type(value) is dict and 'request' in value:
        return _public_request_review(value, operation, inputs)
    if type(value) is not dict or set(value) != {'requested_profile', 'checks', 'source_mode_inventory_sha256'}:
        _fail('Exact public profile review required')
    if (operation != 'naos-upgrade-profile-transition' or
            value['requested_profile'] not in {'quickstart', 'lite', 'standard', 'assured'} or
            value['requested_profile'] != inputs.get('profile')):
        _fail('Public profile review differs from operation inputs')
    lb._hex(value['source_mode_inventory_sha256'], lb.HEX64, 'source-mode review digest')
    checks = value['checks']
    if type(checks) is not list or len(checks) != 2 or [x.get('check_id') for x in checks if type(x) is dict] != ['generated_profile_contract', 'overlay_compatibility']:
        _fail('Required public profile checks differ')
    for check in checks:
        if type(check) is not dict or set(check) != {'check_id', 'status', 'evidence_sha256'} or check['status'] != 'passed':
            _fail('Public profile check did not pass')
        lb._hex(check['evidence_sha256'], lb.HEX64, 'public check digest')
    return value


def _project_operation(portable_files, current_bytes, requested, capture,
                       predecessor_binding, predecessor_store, public_review, *,
                       operation, inputs, source_policy_id, source_policy, selection=None):
    observed = _checked_capture(capture)
    observations = _working_inputs(observed, current_bytes, predecessor_binding.body['observation'])
    activation = None
    if operation == 'naos-hook-activate':
        from .hook_activation import checked_review
        activation = checked_review(public_review, portable_files=portable_files,
            current_bytes=current_bytes, requested=requested, capture=capture,
            predecessor_binding=predecessor_binding, predecessor_store=predecessor_store)
    return projection.project_operation(portable_files, observations, requested,
        host='windows' if observed['native']['platform'] == 'Windows' else 'posix',
        operation=operation, inputs=inputs, source_policy_id=source_policy_id,
        source_policy=source_policy, selection=selection, activation=activation)

def _require_current_drift_review(rows):
    from .planner import kit_owned_drift
    paths = sorted(row["path"] for row in rows
        if kit_owned_drift(row["historical_ownership"], row["action"])
        or (row["historical_ownership"] == "kit_owned_derived"
            and row["native_status"] != "clear"
            and row["action"] not in {"PRESERVE_UNSELECTED_HISTORICAL",
                                      "PROPOSE_MODE_INTENT_UPDATE"}))
    if paths:
        _fail("GOVERNANCE_DRIFT: selected kit-owned paths require review: " + ", ".join(paths))


def _facts(portable_files: dict[str, bytes], current_bytes: dict[str, bytes | None],
           requested: dict[str, dict[str, Any]], capture: WorkingTreeCapture,
           predecessor_binding: lb.ValidatedLocalBinding,
           predecessor_store: ls.ValidatedLocalStore, journal_ids: tuple[str, ...],
           predecessor_record_witnesses: dict[str, Any], *, operation: str, inputs: dict[str, Any], source_policy_id: str,
           source_policy: dict[str, Any], public_review=None, selection=None, allow_noop=False, current_review=False, _return_projection=False):
    prior, state = _checkpoint(predecessor_binding, predecessor_store, journal_ids)
    observed = _checked_capture(capture)
    records = _record_witnesses(predecessor_record_witnesses, observed["native"]["platform"])
    if type(requested) is not dict or (selection is None and set(requested) != set(current_bytes)):
        _fail("Requested path coverage differs from captured current bytes")
    if [x["path"] for x in observed["leaves"]] != sorted(current_bytes):
        _fail("Working capture must cover complete requested selection")
    try:
        snapshot = pp.load_portable_snapshot(projection._Reader(portable_files))
    except (pp.PortableProvenanceError, TypeError, ValueError) as exc:
        raise OperationRecordError("Portable history failed replay") from exc
    if (prior["project_id"] != snapshot.project_id or prior["owner_sha256"] != snapshot.owner_sha256 or
            prior["portable_head_sha256"] != snapshot.manifest_sha256 or
            state["project_id"] != snapshot.project_id or state["owner_sha256"] != snapshot.owner_sha256 or
            [x["path"] for x in prior["observation"]["leaves"]] != sorted(snapshot.entries)):
        _fail("Predecessor binding/store differs from complete portable history")
    if len(state["journals"]["entries"]) >= lb.MAX_JOURNALS or state["generation"] >= ls.MAX_GENERATION:
        _fail("Local sequence or generation exhausted")
    _working_inputs(observed, current_bytes, prior["observation"])
    host = "windows" if observed["native"]["platform"] == "Windows" else "posix"
    result = _project_operation(portable_files, current_bytes, requested, capture,
        predecessor_binding, predecessor_store, public_review, operation=operation,
        inputs=inputs, source_policy_id=source_policy_id, source_policy=source_policy,
        selection=selection)
    if current_review:
        _require_current_drift_review(result["rows"])
    if public_review is not None and type(public_review) is dict and 'request' in public_review:
        if decode_public_request(public_review['request'])['selected_paths'] != sorted(requested):
            _fail('Public add/setup review differs from requested coverage')
    if result["status"] == "no_receipt" and allow_noop:
        if public_review is None or selection is None:
            _fail("Read-only profile review requires exact selected public evidence")
        return {"schema": NOOP_REVIEW_SCHEMA, "status": "no_changes",
                "mutation_eligible": False, "operation": operation,
                "project_id": snapshot.project_id, "owner_sha256": snapshot.owner_sha256,
                "portable_head_sha256": snapshot.manifest_sha256,
                "binding_sha256": predecessor_binding.sha256, "store_sha256": predecessor_store.sha256,
                "current_capture_sha256": _digest(canonical_bytes(observed)),
                "public_review": _public_review(public_review, operation, inputs),
                "selection": projection._selection(selection, snapshot.entries, requested, current_bytes),
                "projection_rows": result["rows"]}
    if result["status"] not in {"entry_changes", "input_only_profile_transition"}:
        _fail("No actionable portable receipt; blocked and no-op plans refuse")
    output_inventory = []
    for path in sorted(requested):
        item = requested[path]
        if type(item) is not dict or set(item) != {"source", "output", "executable"}:
            _fail("Malformed requested byte inventory")
        for name in ("source", "output"):
            raw = item[name]
            if raw is not None and type(raw) is not bytes:
                _fail("Malformed requested bytes")
        output_inventory.append({"path": path,
            "source_sha256": None if item["source"] is None else _digest(item["source"]),
            "source_size_decimal": None if item["source"] is None else str(len(item["source"])),
            "output_sha256": None if item["output"] is None else _digest(item["output"]),
            "output_size_decimal": None if item["output"] is None else str(len(item["output"])),
            "executable": item["executable"]})
    body = {"schema": PLAN_SCHEMA, "operation": operation, "host": host,
        "project_id": snapshot.project_id, "owner_sha256": snapshot.owner_sha256,
        "binding_id": prior["binding_id"], "prior_portable_head_sha256": snapshot.manifest_sha256,
        "prior_binding_sha256": predecessor_binding.sha256,
        "prior_store_sha256": predecessor_store.sha256,
        "predecessor_record_witnesses": records,
        "prior_journals": state["journals"], "prior_generation_decimal": str(state["generation"]),
        "next_journal_id": f"J{len(journal_ids) + 1:08d}",
        "next_receipt_id": result["next_receipt_id"],
        "initial_capture": observed,
        "current_inventory": _inventory({p: x for p, x in current_bytes.items() if x is not None}, "current"),
        "requested_inventory": output_inventory,
        "portable_inventory": _inventory(portable_files, "portable"),
        "prospective_overlay_inventory": _inventory(result["portable_overlay"], "overlay"),
        "source_policy_id": source_policy_id,
        "source_policy_sha256": result["source_policy_sha256"],
        "prospective_head_sha256": result["prospective_manifest_sha256"],
        "projection_status": result["status"], "projection_rows": result["rows"],
        "changes": result["changes"]}
    if public_review is not None:
        body["schema"] = PUBLIC_PLAN_SCHEMA
        body["public_review"] = _public_review(public_review, operation, inputs)
    if selection is not None:
        if public_review is None:
            _fail("Selected public plan requires complete public review")
        body["schema"] = SELECTED_PLAN_SCHEMA
        body["selection"] = projection._selection(selection, snapshot.entries, requested, current_bytes)
    return (body, result) if _return_projection else body


@dataclass(frozen=True)
class ValidatedProfileNoop:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, "read-only profile review")


@_closed
def build_profile_review(**evidence):
    """Exact current review; a no-op cannot become an actionable operation plan."""
    body = _facts(**evidence, allow_noop=True, current_review=True)
    raw = _record(body)
    if body["schema"] == NOOP_REVIEW_SCHEMA:
        return ValidatedProfileNoop(raw, _digest(raw))
    return ValidatedOperationPlan(raw, _digest(raw))


@_closed
def build_operation_plan(portable_files, current_bytes, requested, capture,
                         predecessor_binding, predecessor_store, journal_ids,
                         predecessor_record_witnesses, *,
                         operation, inputs, source_policy_id, source_policy, public_review=None, selection=None):
    body = _facts(portable_files, current_bytes, requested, capture,
        predecessor_binding, predecessor_store, journal_ids, predecessor_record_witnesses,
        operation=operation,
        inputs=inputs, source_policy_id=source_policy_id, source_policy=source_policy, public_review=public_review, selection=selection, current_review=True)
    raw = _record(body)
    return ValidatedOperationPlan(raw, _digest(raw))


@_closed
def _load_operation_plan_projection(raw, portable_files, current_bytes, requested, capture,
                        predecessor_binding, predecessor_store, journal_ids,
                        predecessor_record_witnesses, *,
                        operation, inputs, source_policy_id, source_policy, public_review=None, selection=None):
    _parsed(raw, "operation plan")
    expected, projected = _facts(portable_files, current_bytes, requested, capture,
        predecessor_binding, predecessor_store, journal_ids, predecessor_record_witnesses,
        operation=operation,
        inputs=inputs, source_policy_id=source_policy_id, source_policy=source_policy, public_review=public_review, selection=selection, _return_projection=True)
    if raw != _record(expected):
        _fail("Operation plan differs from recomputed inputs and projection")
    return ValidatedOperationPlan(raw, _digest(raw)), projected


@_closed
def load_operation_plan(raw, portable_files, current_bytes, requested, capture,
                        predecessor_binding, predecessor_store, journal_ids,
                        predecessor_record_witnesses, *,
                        operation, inputs, source_policy_id, source_policy, public_review=None, selection=None):
    plan, _projected = _load_operation_plan_projection(raw, portable_files, current_bytes,
        requested, capture, predecessor_binding, predecessor_store, journal_ids,
        predecessor_record_witnesses, operation=operation, inputs=inputs,
        source_policy_id=source_policy_id, source_policy=source_policy,
        public_review=public_review, selection=selection)
    return plan


def _verified_plan(plan: ValidatedOperationPlan, evidence: dict[str, Any], *, _return_projection=False):
    body = plan.body if type(plan) is ValidatedOperationPlan else None
    public = body is not None and body.get("schema") in {PUBLIC_PLAN_SCHEMA, SELECTED_PLAN_SCHEMA}
    selected = body is not None and body.get("schema") == SELECTED_PLAN_SCHEMA
    if type(plan) is not ValidatedOperationPlan or type(evidence) is not dict or set(evidence) != {
        "portable_files", "current_bytes", "requested", "capture", "predecessor_binding",
        "predecessor_store", "journal_ids", "predecessor_record_witnesses",
        "operation", "inputs", "source_policy_id",
        "source_policy",
    } | ({"public_review"} if public else set()) | ({"selection"} if selected else set()):
        _fail("Complete plan replay evidence required")
    loaded, projected = _load_operation_plan_projection(plan.raw, evidence["portable_files"], evidence["current_bytes"],
        evidence["requested"], evidence["capture"], evidence["predecessor_binding"],
        evidence["predecessor_store"], evidence["journal_ids"],
        evidence["predecessor_record_witnesses"],
        operation=evidence["operation"], inputs=evidence["inputs"],
        source_policy_id=evidence["source_policy_id"], source_policy=evidence["source_policy"],
        public_review=evidence.get("public_review"), selection=evidence.get("selection"))
    if loaded != plan:
        _fail("Plan differs from recomputed evidence")
    return (body, projected) if _return_projection else body


def _intent_body(plan: ValidatedOperationPlan, predecessor_binding,
                 predecessor_store, prepared_capture: WorkingTreeCapture,
                 storage_witnesses: dict[str, Any], checkpoint_record_witnesses: dict[str, Any],
                 approved_plan_sha256: str, plan_evidence: dict[str, Any]) -> dict:
    p = _verified_plan(plan, plan_evidence)
    return _intent_fields(p, plan, predecessor_binding, predecessor_store,
        prepared_capture, storage_witnesses, checkpoint_record_witnesses,
        approved_plan_sha256, plan_evidence)


def _intent_fields(p, plan, predecessor_binding, predecessor_store,
                   prepared_capture, storage_witnesses, checkpoint_record_witnesses,
                   approved_plan_sha256, plan_evidence):
    """Deterministic fields; callers in this module first verify the full plan."""
    if plan_evidence["predecessor_binding"] != predecessor_binding or plan_evidence["predecessor_store"] != predecessor_store:
        _fail("Intent predecessor differs from plan replay evidence")
    prior, state = _checkpoint(predecessor_binding, predecessor_store,
        tuple(x["id"] for x in p["prior_journals"]["entries"]))
    if approved_plan_sha256 != plan.sha256 or p["prior_binding_sha256"] != predecessor_binding.sha256 or p["prior_store_sha256"] != predecessor_store.sha256:
        _fail("Approval or predecessor checkpoint differs")
    if p["binding_id"] != prior["binding_id"] or p["prior_journals"] != state["journals"]:
        _fail("Intent predecessor linkage differs")
    prepared = _checked_capture(prepared_capture)
    if _record_witnesses(checkpoint_record_witnesses, prepared["native"]["platform"]) != p["predecessor_record_witnesses"]:
        _fail("Predecessor record native identity changed since approval")
    if prepared != p["initial_capture"]:
        _fail("Prepared capture differs from reviewed working capture")
    if type(storage_witnesses) is not dict or set(storage_witnesses) != {"lock", "journal"}:
        _fail("Incomplete new storage witnesses")
    platform = prepared["native"]["platform"]
    lb._validate_witness(storage_witnesses["lock"], platform, "file")
    lb._validate_witness(storage_witnesses["journal"], platform, "directory")
    for witness in storage_witnesses.values():
        if witness["presence"] != "present":
            _fail("New storage witness absent")
        if platform == "Windows" and not witness["security"]["dacl_protected"]:
            _fail("New storage security is unprotected")
    if platform != "Windows" and (storage_witnesses["lock"]["mode_octal"] != "0600" or
                                  storage_witnesses["journal"]["mode_octal"] != "0700"):
        _fail("New POSIX storage is not private")
    return {"schema": INTENT_SCHEMA, "journal_id": p["next_journal_id"],
        "plan_sha256": plan.sha256, "approved_plan_sha256": approved_plan_sha256,
        "predecessor_binding_sha256": predecessor_binding.sha256,
        "predecessor_store_sha256": predecessor_store.sha256,
        "project_id": p["project_id"], "owner_sha256": p["owner_sha256"],
        "binding_id": p["binding_id"], "prior_portable_head_sha256": p["prior_portable_head_sha256"],
        "prospective_head_sha256": p["prospective_head_sha256"],
        "prepared_capture": prepared, "storage_witnesses": storage_witnesses,
        "checkpoint_record_witnesses": checkpoint_record_witnesses,
        "failure_model": "application_interruption_v1"}


@_closed
def build_operation_intent(plan, predecessor_binding, predecessor_store,
                           prepared_capture, storage_witnesses, checkpoint_record_witnesses,
                           *, approved_plan_sha256, plan_evidence):
    body = _intent_body(plan, predecessor_binding, predecessor_store,
        prepared_capture, storage_witnesses, checkpoint_record_witnesses,
        approved_plan_sha256, plan_evidence)
    _require_current_drift_review(plan.body["projection_rows"])
    raw = _record(body)
    return ValidatedOperationIntent(raw, _digest(raw))


@_closed
def load_operation_intent(raw, plan, predecessor_binding, predecessor_store,
                          prepared_capture, storage_witnesses, checkpoint_record_witnesses,
                          *, approved_plan_sha256, plan_evidence):
    _parsed(raw, "operation intent")
    expected = _intent_body(plan, predecessor_binding, predecessor_store,
        prepared_capture, storage_witnesses, checkpoint_record_witnesses,
        approved_plan_sha256, plan_evidence)
    if raw != _record(expected):
        _fail("Operation intent differs from validated plan and prepared witnesses")
    return ValidatedOperationIntent(raw, _digest(raw))


@_closed
def registration_store(intent: ValidatedOperationIntent, plan: ValidatedOperationPlan,
                       predecessor_binding: lb.ValidatedLocalBinding,
                       predecessor_store: ls.ValidatedLocalStore, *, plan_evidence: dict[str, Any]) -> ls.ValidatedLocalStore:
    p = _verified_plan(plan, plan_evidence)
    if type(intent) is not ValidatedOperationIntent or _digest(intent.raw) != intent.sha256:
        _fail("Typed validated intent required")
    i = intent.body
    load_operation_intent(intent.raw, plan, predecessor_binding, predecessor_store,
        plan_evidence["capture"], i["storage_witnesses"],
        i["checkpoint_record_witnesses"],
        approved_plan_sha256=plan.sha256, plan_evidence=plan_evidence)
    return _registration_fields(i, intent, p, plan, predecessor_binding, predecessor_store)


def _registration_fields(i, intent, p, plan, predecessor_binding, predecessor_store):
    """Shared linkage and generation checks after complete intent validation."""
    prior, state = _checkpoint(predecessor_binding, predecessor_store,
        tuple(x["id"] for x in p["prior_journals"]["entries"]))
    if (i["plan_sha256"] != plan.sha256 or i["approved_plan_sha256"] != plan.sha256 or
            i["predecessor_binding_sha256"] != predecessor_binding.sha256 or
            i["predecessor_store_sha256"] != predecessor_store.sha256 or
            i["journal_id"] != p["next_journal_id"] or
            i["prior_portable_head_sha256"] != prior["portable_head_sha256"] or
            i["binding_id"] != prior["binding_id"]):
        _fail("Intent is not linked to exact predecessor and reviewed plan")
    entries = state["journals"]["entries"] + [{"id": i["journal_id"], "sha256": intent.sha256}]
    body = {**state, "generation": state["generation"] + 1,
            "journals": {"head_id": i["journal_id"], "entries": entries},
            "active_journal_id": i["journal_id"]}
    registered = ls.load_local_store(ls.encode_local_store(body))
    ls.reconcile_registration(registered, predecessor_binding,
        tuple(x["id"] for x in entries))
    return registered


def _exact_operation_input(value):
    """Detached equality key retaining exact types, including bool/int aliases.

    Used only around an invocation that still runs the deterministic validators;
    this is not a proof, digest substitute, or persistent validation cache.
    """
    kind = type(value)
    if kind in (str, bytes, int, float, bool, type(None)):
        return kind, value
    if kind in (ValidatedOperationPlan, ValidatedOperationIntent,
                lb.ValidatedLocalBinding, ls.ValidatedLocalStore, WorkingTreeCapture):
        return kind, _exact_operation_input(value.raw), _exact_operation_input(value.sha256)
    if kind is dict:
        if any(type(key) is not str for key in value):
            _fail("Exact operation input keys required")
        return kind, tuple((key, _exact_operation_input(value[key])) for key in sorted(value))
    if kind in (list, tuple):
        return kind, tuple(_exact_operation_input(item) for item in value)
    _fail("Exact operation input types required")


@_closed
def _load_intent_and_registration(raw, plan, evidence):
    """Derive both records from one fresh verification; accept no trusted proof.

    Capture-owned callers may retain these pure products only while freshly
    comparing every bound raw input. Ordinary public validators remain fresh.
    """
    before = _exact_operation_input((raw, plan, evidence))
    i = _parsed(raw, "operation intent")
    p = _verified_plan(plan, evidence)
    binding, state = evidence["predecessor_binding"], evidence["predecessor_store"]
    expected = _intent_fields(p, plan, binding, state, evidence["capture"],
        i["storage_witnesses"], evidence["predecessor_record_witnesses"],
        plan.sha256, evidence)
    if raw != _record(expected):
        _fail("Operation intent differs from validated plan and prepared witnesses")
    intent = ValidatedOperationIntent(raw, _digest(raw))
    registered = _registration_fields(i, intent, p, plan, binding, state)
    if _exact_operation_input((raw, plan, evidence)) != before:
        _fail("Operation inputs changed during combined validation")
    return intent, registered
