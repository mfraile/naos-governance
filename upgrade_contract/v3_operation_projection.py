"""Pure, provisional v3 B/C/N projection; this result grants no native authority.

The caller must separately hold and revalidate complete native custody. Portable
records and C observations must be immutable snapshots from that custody.
"""
from __future__ import annotations

import hashlib
import copy
from pathlib import Path
from typing import Any, Mapping

from . import portable_provenance as pp
from .canonical import canonical_bytes, canonical_sha256
from .planner import (
    ContentPlanningError, apply_ownership_guard, classify_content_state, classify_new_path,
)


SELECTION_SCHEMA = "naos.upgrade.v3_operation_selection.v1"
OWNERSHIP_PRESERVATION = frozenset({"PRESERVE_ADOPTER_CONTENT", "PRESERVE_ADAPTED_CONTENT",
                                  "PRESERVE_CONFIGURATION_CHOICE", "PRESERVE_EVIDENCE_REPORT"})


class ProjectionError(ValueError):
    pass


class _Reader:
    def __init__(self, files: dict[str, bytes]):
        self.files = files

    def read(self, relative: str) -> bytes | None:
        return self.files.get(relative)


class _ByteIdentity:
    def __init__(self, raw: bytes | None):
        self.presence = "absent" if raw is None else "present"
        self._key = None if raw is None else (len(raw), hashlib.sha256(raw).hexdigest())

    def comparison_key(self):
        return self._key


def _byte(value: Any, label: str) -> bytes | None:
    if value is not None and (type(value) is not bytes or len(value) > pp.MAX_BASE_BYTES):
        raise ProjectionError(f"Invalid or oversized {label} bytes")
    return value


def _observation(value: Any, host: str) -> tuple[bytes | None, bool | None, str]:
    if type(value) is not dict or set(value) != {"bytes", "executable", "native_status"}:
        raise ProjectionError("Current observation fields differ")
    raw = _byte(value["bytes"], "current")
    mode = value["executable"]
    if raw is None:
        if mode is not None:
            raise ProjectionError("Absent current leaf has executable mode")
    elif host == "posix":
        if type(mode) is not bool:
            raise ProjectionError("POSIX current executable observation is required")
    elif mode is not None:
        raise ProjectionError("Windows current executable intent is not observable")
    status = value["native_status"]
    if type(status) is not str or status not in {"clear", "metadata_drift", "unsafe"}:
        raise ProjectionError("Native status is not a supported observation")
    return raw, mode, status


def _requested(value: Any) -> tuple[bytes | None, bytes | None, bool | None]:
    if type(value) is not dict or set(value) != {"source", "output", "executable"}:
        raise ProjectionError("Requested output fields differ")
    source = _byte(value["source"], "source")
    output = _byte(value["output"], "output")
    mode = value["executable"]
    if output is None:
        if source is not None or mode is not None:
            raise ProjectionError("Absent output carries source or mode")
    elif type(source) is not bytes or type(mode) is not bool:
        raise ProjectionError("Output requires exact source bytes and executable intent")
    return source, output, mode


def _content(raw: bytes, executable: bool) -> dict[str, Any]:
    return {"kind": "file", "sha256": hashlib.sha256(raw).hexdigest(),
            "size_decimal": str(len(raw)), "executable": executable}


def _inventory(path: str, source: bytes, output: bytes, executable: bool) -> dict[str, Any]:
    return {"destination": path,
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "source_size_decimal": str(len(source)),
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_size_decimal": str(len(output)), "executable": executable}


def _selection(value, historical, requested, current):
    if (type(value) is not dict or set(value) != {"schema", "selected_paths", "carry_forward_paths"}
            or value["schema"] != SELECTION_SCHEMA):
        raise ProjectionError("Malformed operation selection")
    selected, carried = value["selected_paths"], value["carry_forward_paths"]
    if (type(selected) is not list or type(carried) is not list
            or any(type(p) is not str for p in selected + carried)
            or selected != sorted(requested) or carried != sorted(set(historical) - set(requested))
            or set(current) != set(historical) | set(requested)
            or len(current) > pp.MAX_TOTAL_SELECTED_PATHS):
        raise ProjectionError("Selection must exactly partition current capture and historical carry-forward")
    return copy.deepcopy(value)


def project_operation(
    portable_files: Mapping[str, bytes],
    current: Mapping[str, dict[str, Any]],
    requested: Mapping[str, dict[str, Any]],
    *, host: str, operation: str, inputs: dict[str, Any],
    source_policy_id: str, source_policy: dict[str, Any], selection=None, activation=None,
) -> dict[str, Any]:
    """Return detached planning facts, never an approval token or write plan.

    B and ownership come from complete portable replay. C supplies bytes and,
    only on POSIX, observed executable bits. N binds exact source/output bytes
    and explicit executable intent. Native metadata/topology is outside this API.
    """
    if type(host) is not str or host not in {"posix", "windows"} or type(portable_files) is not dict:
        raise ProjectionError("Unsupported host or portable input")
    if type(current) is not dict or type(requested) is not dict:
        raise ProjectionError("Current/requested inventory must be exact dictionaries")
    if len(requested) > pp.MAX_TOTAL_SELECTED_PATHS or (selection is None and set(current) != set(requested)):
        raise ProjectionError("Requested/current coverage differs or exceeds limit")
    if any(type(path) is not str for path in requested) or type(operation) is not str:
        raise ProjectionError("Selected paths and operation must be strings")
    files = {}
    total = 0
    for key, raw in portable_files.items():
        if type(key) is not str or type(raw) is not bytes:
            raise ProjectionError("Portable files must be exact byte records")
        total += len(raw)
        if total > pp.MAX_CUMULATIVE_READ_BYTES:
            raise ProjectionError("Portable byte budget exceeded")
        files[key] = raw
    try:
        snapshot = pp.load_portable_snapshot(_Reader(files))
    except pp.PortableProvenanceError as exc:
        raise ProjectionError("Prior portable history failed complete replay") from exc
    old_entries = snapshot.entries
    old_inputs = snapshot.inputs
    if selection is not None:
        selection = _selection(selection, old_entries, requested, current)
    try:
        next_inputs = copy.deepcopy(pp._inputs(inputs, old_inputs, operation))
        policy_sha, _ = pp.encode_policy(source_policy_id, source_policy)
    except ValueError as exc:
        raise ProjectionError("Invalid operation inputs or source policy") from exc
    next_rid = f"R{len(snapshot.manifest['receipts']) + 1:08d}"
    if pp.RECEIPT_ID.fullmatch(next_rid) is None:
        raise ProjectionError("Receipt sequence exhausted")
    prospective = copy.deepcopy(old_entries)
    changes = []
    inventories = []
    rows = []
    blocked = []
    selected = sorted(requested)
    if selection is None and not set(old_entries) <= set(selected):
        raise ProjectionError("Historical managed coverage is incomplete")
    try:
        for path in current:
            pp._path(path)
        pp._unique_paths(sorted(current))
    except pp.PortableProvenanceError as exc:
        raise ProjectionError("Selected paths are unsafe, duplicate or aliased") from exc
    historic_aliases = {path.casefold(): path for path in old_entries}
    if any(path.casefold() in historic_aliases and historic_aliases[path.casefold()] != path
           for path in selected):
        raise ProjectionError("Selected path aliases historical entry")
    selected_byte_work = 0
    if selection is not None:
        for path in selection["carry_forward_paths"]:
            c_raw, _mode, native_status = _observation(current[path], host)
            selected_byte_work += 0 if c_raw is None else len(c_raw)
            if selected_byte_work > pp.MAX_CUMULATIVE_READ_BYTES:
                raise ProjectionError("Selected byte-work budget exceeded")
            if native_status == "unsafe":
                blocked.append(path)
            rows.append({"path": path, "proposal": "NOT_SELECTED",
                         "action": "PRESERVE_UNSELECTED_HISTORICAL",
                         "historical_ownership": old_entries[path]["ownership"],
                         "native_status": native_status})
    for path in selected:
        c_raw, c_exec, native_status = _observation(current[path], host)
        if native_status == "unsafe":
            blocked.append(path)
        source, n_raw, n_exec = _requested(requested[path])
        selected_byte_work += sum(len(raw) for raw in (c_raw, source, n_raw) if raw is not None)
        if selected_byte_work > pp.MAX_CUMULATIVE_READ_BYTES:
            raise ProjectionError("Selected byte-work budget exceeded")
        prior = old_entries.get(path)
        if prior is not None and prior["content"] is None and n_raw is not None:
            raise ProjectionError("Historical tombstone cannot be reintroduced automatically")
        if prior is not None and prior["content"] is None and c_raw is None and n_raw is None:
            rows.append({"path": path, "proposal": "NOOP_REMOVED_AND_ABSENT",
                         "action": "NOOP_REMOVED_AND_ABSENT",
                         "historical_ownership": prior["ownership"],
                         "native_status": native_status})
            continue
        base = None if prior is None or prior["content"] is None else files[pp.base_path(prior["content"]["sha256"])]
        if prior is None and n_raw is None:
            raise ProjectionError("Unmanaged absent output is outside path universe")
        try:
            proposal = classify_content_state(_ByteIdentity(base), _ByteIdentity(c_raw), _ByteIdentity(n_raw))
            ownership = prior["ownership"] if prior is not None else "unmanaged"
            policy_rule = None
            if prior is None and n_raw is not None and c_raw is None:
                policy_rule = classify_new_path(Path(path), source_policy)
                ownership = policy_rule["ownership"]
            action = apply_ownership_guard(
                proposal, ownership,
                creation_policy=None if policy_rule is None else policy_rule["creation_policy"],
            )["action"]
        except ContentPlanningError as exc:
            raise ProjectionError("Content or ownership classification refused") from exc
        reconciled_activation = False
        if operation == "naos-hook-activate":
            from .hook_activation import projection_eligible
            reconciled_activation = projection_eligible(activation, path, prior, base,
                c_raw, c_exec, n_raw, n_exec, native_status, host)
        elif activation is not None:
            raise ProjectionError("Activation review is outside its exact operation")
        # Byte-only classification deliberately ignores executable intent. A
        # separate gate prevents C==B==N bytes from disguising a B/N mode change.
        b_exec = None if prior is None or prior["content"] is None else prior["content"]["executable"]
        changed_mode = b_exec is not None and n_raw is not None and n_exec != b_exec
        if changed_mode:
            if (ownership == "kit_owned_derived" and c_raw == base
                    and (host == "windows" or c_exec == b_exec)):
                action = "PROPOSE_MODE_INTENT_UPDATE"
            else:
                action = "PRESERVE_MODE_INTENT_CONFLICT"
        if host == "posix" and prior is not None and base is not None and c_raw == base and c_exec != b_exec and not reconciled_activation:
            action = "PRESERVE_CURRENT_MODE_DRIFT"
        if reconciled_activation:
            action = "PROPOSE_MODE_INTENT_UPDATE"
        if native_status != "clear" and not reconciled_activation and action in {
                "CREATE_NEW_UPSTREAM", "CREATE_NEW_ADOPTER_OWNED",
                "CREATE_CONFIGURATION_CHOICE", "CREATE_MANAGED_CACHE",
                "CREATE_IMMUTABLE_REPORT", "UPDATE_FROM_UPSTREAM",
                "PROPOSE_MODE_INTENT_UPDATE"}:
            action = "PRESERVE_METADATA_DRIFT" if native_status == "metadata_drift" else "REFUSE_UNSAFE_NATIVE_OBJECT"
        if action in {"CREATE_NEW_UPSTREAM", "CREATE_NEW_ADOPTER_OWNED",
                      "CREATE_CONFIGURATION_CHOICE", "CREATE_MANAGED_CACHE",
                      "CREATE_IMMUTABLE_REPORT", "UPDATE_FROM_UPSTREAM",
                      "PROPOSE_MODE_INTENT_UPDATE"}:
            assert n_raw is not None and source is not None and n_exec is not None
            if prior is None:
                after = {"path": path, "content": _content(n_raw, n_exec),
                         "ownership": ownership,
                         "creation_policy": policy_rule["creation_policy"],
                         "introduced_policy_sha256": policy_sha,
                         "introduced_by": next_rid, "latest_base_receipt": next_rid}
            else:
                after = copy.deepcopy(prior)
                after["content"] = _content(n_raw, n_exec)
                after["latest_base_receipt"] = next_rid
            prospective[path] = after
            changes.append({"path": path, "before": prior, "after": after})
            inventories.append(_inventory(path, source, n_raw, n_exec))
        elif (prior is None and n_raw is not None) or (
                prior is not None and prior["content"] is not None
                and n_raw is not None and _content(n_raw, n_exec) != prior["content"]):
            if not (selection is not None and prior is not None and action in OWNERSHIP_PRESERVATION and native_status == "clear"):
                blocked.append(path)
        rows.append({"path": path, "proposal": proposal, "action": action,
                     "historical_ownership": None if prior is None else prior["ownership"],
                     "native_status": native_status})
    if blocked:
        status = "blocked"
    elif changes:
        status = "entry_changes"
    elif canonical_bytes(next_inputs) != canonical_bytes(old_inputs):
        status = "input_only_profile_transition"
    else:
        status = "no_receipt"
    rows.sort(key=lambda row: row["path"])
    projected_entries = [prospective[path] for path in sorted(prospective)]
    result = {"status": status, "rows": rows, "changes": changes,
            "selected_paths": sorted(requested), "mode_inventory_items": inventories,
            "prospective_entries": projected_entries, "prospective_inputs": next_inputs,
            "prospective_projection_sha256": canonical_sha256(
                {"entries": projected_entries, "inputs": next_inputs}),
            "next_receipt_id": next_rid, "source_policy_sha256": policy_sha,
            "prior_manifest_sha256": snapshot.manifest_sha256,
            "prior_head_receipt_sha256": snapshot.head_receipt_sha256,
            "project_id": snapshot.project_id, "owner_sha256": snapshot.owner_sha256}
    if status in {"no_receipt", "blocked"}:
        result["portable_overlay"] = {}
        result["blocked_paths"] = blocked
        return result
    if status == "input_only_profile_transition" and operation != "naos-upgrade-profile-transition":
        raise ProjectionError("Only a profile transition can change inputs without an entry")
    if status == "input_only_profile_transition" and selected:
        # Input-only grammar requires empty selected coverage. A full native
        # inventory may be supplied, but selection is a receipt concept.
        receipt_selected = []
    else:
        receipt_selected = selected
    if status == "entry_changes" and len(changes) > pp.MAX_TOTAL_CHANGES:
        raise ProjectionError("Receipt change budget exceeded")
    policy_sha, policy_raw = pp.encode_policy(source_policy_id, source_policy)
    inventory_sha, inventory_raw = pp.encode_mode_inventory(inventories)
    projection_sha = result["prospective_projection_sha256"]
    receipt = {"schema": pp.RECEIPT_SCHEMA, "id": next_rid,
        "project_id": snapshot.project_id, "owner_sha256": snapshot.owner_sha256,
        "previous_receipt_sha256": snapshot.head_receipt_sha256,
        "previous_projection_sha256": snapshot.manifest["projection_sha256"],
        "result_projection_sha256": projection_sha, "operation": operation,
        "inputs": next_inputs, "selected_paths": receipt_selected,
        "changes": changes, "policy_sha256": policy_sha,
        "mode_inventory_sha256": inventory_sha}
    receipt_sha = canonical_sha256(receipt)
    manifest = {**snapshot.manifest,
        "previous_head_sha256": snapshot.manifest_sha256,
        "receipts": snapshot.manifest["receipts"] + [{"id": next_rid, "sha256": receipt_sha}],
        "entries": projected_entries, "inputs": next_inputs,
        "projection_sha256": projection_sha, "head_receipt_sha256": receipt_sha}
    overlay = {pp.prior_manifest_path(snapshot.manifest_sha256): files[pp.MANIFEST_PATH],
        pp.policy_path(policy_sha): policy_raw,
        pp.inventory_path(inventory_sha): inventory_raw,
        pp.receipt_path(receipt_sha): pp.encode_record(receipt),
        pp.MANIFEST_PATH: pp.encode_record(manifest)}
    for change in changes:
        content = change["after"]["content"]
        path = change["path"]
        overlay[pp.base_path(content["sha256"])] = requested[path]["output"]
    for path, raw in overlay.items():
        if path != pp.MANIFEST_PATH and path in files and files[path] != raw:
            raise ProjectionError("Prospective evidence collides with historical bytes")
    combined = {**files, **overlay}
    if sum(map(len, combined.values())) > pp.MAX_CUMULATIVE_READ_BYTES:
        raise ProjectionError("Prospective portable read-byte budget exceeded")
    try:
        validated = pp.load_portable_snapshot(_Reader(combined))
    except pp.PortableProvenanceError as exc:
        raise ProjectionError("Prospective portable history failed complete replay") from exc
    result["portable_overlay"] = overlay
    result["prospective_manifest_sha256"] = validated.manifest_sha256
    result["prospective_head_receipt_sha256"] = validated.head_receipt_sha256
    result["receipt_selected_paths"] = receipt_selected
    return result
