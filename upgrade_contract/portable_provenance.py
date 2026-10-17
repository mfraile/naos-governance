"""Pure portable managed-content v3 codec and complete history replay.

Records establish internal consistency only. Equal bytes, a self-hash, and a
project ID confer neither ownership of a checkout nor human authenticity.
Native readers must supply contained, stable reads; this module performs no I/O.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .planner import _validate_source_policy, classify_new_path
from .security import safe_relative_path


ROOT = ".naos/managed-content/v3"
OWNER_PATH = ROOT + "/OWNER.json"
MANIFEST_PATH = ROOT + "/manifest.json"
OWNER_SCHEMA = "naos.upgrade.portable_owner.v3"
MANIFEST_SCHEMA = "naos.upgrade.portable_manifest.v3"
RECEIPT_SCHEMA = "naos.upgrade.portable_receipt.v3"
MODE_INVENTORY_SCHEMA = "naos.upgrade.source_mode_inventory.v1"
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_BASE_BYTES = 64 * 1024 * 1024
MAX_RECEIPTS = 10000
MAX_JSON_DEPTH = 64
MAX_JSON_STRUCTURAL_TOKENS = 250000
MAX_CUMULATIVE_READ_BYTES = 256 * 1024 * 1024
MAX_TOTAL_CHANGES = 50000
MAX_TOTAL_SELECTED_PATHS = 100000
MAX_PROJECTION_ENTRY_VISITS = 250000
MAX_PREFIX_REFERENCE_VISITS = 250000
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RECEIPT_ID = re.compile(r"R[0-9]{8}\Z")
WINDOWS_RESERVED = re.compile(
    r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(?:\.|$)",
    re.I,
)
PROFILE_ORDER = ("quickstart", "lite", "standard", "assured")
INPUT_KEYS = {"mode", "profile", "archetype", "backend", "memory_choice"}
ENTRY_KEYS = {"path", "content", "ownership", "creation_policy",
              "introduced_policy_sha256", "introduced_by", "latest_base_receipt"}
CONTENT_KEYS = {"kind", "sha256", "size_decimal", "executable"}
MODE_ITEM_KEYS = {"destination", "source_sha256", "source_size_decimal",
                  "output_sha256", "output_size_decimal", "executable"}


class PortableProvenanceError(ValueError):
    """A portable record, reference, or replay invariant is invalid."""


class Reader(Protocol):
    def read(self, relative: str) -> bytes | None: ...


@dataclass(frozen=True)
class ValidatedPortableSnapshot:
    """Copy-on-access validated result, with no native mutation authority."""

    project_id: str
    owner_sha256: str
    manifest_sha256: str
    head_receipt_sha256: str
    _entries_bytes: bytes
    _inputs_bytes: bytes
    _manifest_bytes: bytes
    activated_hooks: tuple[str, ...] = ()

    @property
    def entries(self) -> dict[str, dict[str, Any]]:
        return loads_strict_json(self._entries_bytes)

    @property
    def inputs(self) -> dict[str, Any]:
        return loads_strict_json(self._inputs_bytes)

    @property
    def manifest(self) -> dict[str, Any]:
        return loads_strict_json(self._manifest_bytes)


def _fail(message: str) -> None:
    raise PortableProvenanceError(message)


def _hex(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _new_project_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _decimal(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 20 and value.isdecimal()
            and str(int(value)) == value)


def _keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(f"Invalid {label} fields")
    return value


def _path(value: Any) -> str:
    if not isinstance(value, str):
        _fail("Managed path must be text")
    try:
        if safe_relative_path(value).as_posix() != value:
            _fail("Noncanonical managed path")
    except ValueError as exc:
        raise PortableProvenanceError("Unsafe or noncanonical managed path") from exc
    for component in value.split("/"):
        if (any(character in '<>"|?*' or 0xD800 <= ord(character) <= 0xDFFF
                for character in component)
                or WINDOWS_RESERVED.match(component)
                or len(component.encode("utf-16-le")) > 510):
            _fail("Managed path is outside the common POSIX/Windows namespace")
    return value


_JSON_SYNTAX = re.compile(rb'["\\\[\]{}:,]')


def _load_json(raw: bytes, label: str) -> Any:
    """Bound syntax depth/work before strict parsing; skip ordinary byte spans."""
    depth = tokens = 0
    quoted = False
    skip_until = 0
    syntax = (((match.start(), raw[match.start()])
               for match in _JSON_SYNTAX.finditer(raw))
              if isinstance(raw, (bytes, bytearray)) else enumerate(raw))
    for position, byte in syntax:
        if quoted:
            if position < skip_until:
                continue
            if byte == 92:  # One escape consumes exactly the following byte.
                skip_until = position + 2
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            quoted = True
        elif byte in (91, 123):  # [ {
            depth += 1
            tokens += 1
        elif byte in (93, 125):  # ] }
            depth -= 1
        elif byte in (44, 58):  # , :
            tokens += 1
        if depth > MAX_JSON_DEPTH or tokens > MAX_JSON_STRUCTURAL_TOKENS:
            _fail(f"{label} exceeds JSON structural limits")
    if depth != 0 or quoted:
        _fail(f"Malformed {label} JSON structure")
    return loads_strict_json(raw)


def _unique_paths(paths: list[str]) -> None:
    folded: dict[str, str] = {}
    for path in paths:
        path = _path(path)
        alias = path.casefold()
        if alias in folded:
            _fail(f"Duplicate or case-aliased managed path: {path}")
        folded[alias] = path
    ordered = sorted(folded)
    for alias in ordered:
        # All descendants begin with this exact component boundary. Searching
        # once avoids constructing every growing prefix of a deeply nested path.
        prefix = alias + "/"
        index = bisect_left(ordered, prefix)
        if index < len(ordered) and ordered[index].startswith(prefix):
            _fail("Managed file is an ancestor of another managed path")


def _record_path(kind: str, digest: str) -> str:
    if not _hex(digest):
        _fail("Invalid record digest")
    return f"{ROOT}/{kind}/{digest}.json"


def receipt_path(digest: str) -> str:
    return _record_path("receipts", digest)


def policy_path(digest: str) -> str:
    return _record_path("policies", digest)


def inventory_path(digest: str) -> str:
    return _record_path("mode-inventories", digest)


def prior_manifest_path(digest: str) -> str:
    return _record_path("manifests", digest)


def base_path(digest: str) -> str:
    if not _hex(digest):
        _fail("Invalid base digest")
    return f"{ROOT}/bases/{digest}.bin"


def control_path_limit(relative: str) -> int:
    """Whitelist internal read paths and bound allocation before native I/O.

    This is separate from managed destination validation, which excludes .naos.
    Native readers must still enforce containment and stable file identities.
    """
    if not isinstance(relative, str):
        _fail("Portable control path must be text")
    if relative in {OWNER_PATH, MANIFEST_PATH}:
        return MAX_RECORD_BYTES
    prefix = re.escape(ROOT)
    if re.fullmatch(prefix + r"/(?:bases|legacy-blobs)/[0-9a-f]{64}\.bin", relative):
        return MAX_BASE_BYTES
    if re.fullmatch(
        prefix + r"/(?:receipts|policies|mode-inventories|manifests|legacy-authorities|legacy-lineages)/[0-9a-f]{64}\.json",
        relative,
    ):
        return MAX_RECORD_BYTES
    _fail("Unsafe or unsupported portable control path")


def encode_record(body: Mapping[str, Any]) -> bytes:
    """Encode a self-hashed canonical record; validation remains reader-specific."""
    body = dict(body)
    return canonical_bytes({"body": body, "sha256": canonical_sha256(body)})


def encode_policy(snapshot_id: str, policy: dict[str, Any]) -> tuple[str, bytes]:
    """Retain the existing source-policy snapshot digest interpretation."""
    if not isinstance(snapshot_id, str) or not snapshot_id:
        _fail("Invalid policy snapshot ID")
    try:
        _validate_source_policy(policy, snapshot_id=snapshot_id)
    except ValueError as exc:
        raise PortableProvenanceError("Invalid source-policy snapshot") from exc
    value = {"snapshot_id": snapshot_id, "policy": policy}
    return canonical_sha256(value), canonical_bytes(value)


def encode_mode_inventory(items: list[dict[str, Any]]) -> tuple[str, bytes]:
    """Bind each destination to exact source/output bytes and logical mode."""
    body = {"schema": MODE_INVENTORY_SCHEMA, "items": items}
    _mode_inventory(body)
    encoded = encode_record(body)
    return canonical_sha256(body), encoded


def _decode_record(raw: bytes | None, schema: str, keys: set[str]) -> tuple[dict[str, Any], str]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RECORD_BYTES:
        _fail(f"Missing or oversized {schema} record")
    envelope = _keys(_load_json(raw, schema), {"body", "sha256"}, schema + " envelope")
    body = _keys(envelope["body"], keys, schema)
    if (body["schema"] != schema or not _hex(envelope["sha256"])
            or canonical_bytes(envelope) != raw
            or canonical_sha256(body) != envelope["sha256"]):
        _fail(f"Invalid {schema} digest, schema or canonical bytes")
    return body, envelope["sha256"]


def _content(value: Any) -> dict[str, Any]:
    value = _keys(value, CONTENT_KEYS, "portable content")
    if (value["kind"] != "file" or not _hex(value["sha256"])
            or not _decimal(value["size_decimal"])
            or type(value["executable"]) is not bool):
        _fail("Invalid portable content identity")
    return value


def _entry(value: Any, path: str) -> dict[str, Any]:
    value = _keys(value, ENTRY_KEYS, "portable entry")
    if value["path"] != path:
        _fail("Entry path differs from its reference")
    if value["content"] is not None:
        _content(value["content"])
    if (value["ownership"] not in {"kit_owned_derived", "adopter_owned",
                                  "adopter_adapted_generated", "configuration_choice",
                                  "ephemeral_cache", "evidence_bearing_report", "unmanaged"}
            or not isinstance(value["creation_policy"], str)
            or not value["creation_policy"]
            or not _hex(value["introduced_policy_sha256"])
            or not isinstance(value["introduced_by"], str)
            or RECEIPT_ID.fullmatch(value["introduced_by"]) is None
            or not isinstance(value["latest_base_receipt"], str)
            or RECEIPT_ID.fullmatch(value["latest_base_receipt"]) is None):
        _fail("Invalid entry ownership or lineage")
    return value


def _mode_inventory(body: Any) -> dict[str, dict[str, Any]]:
    body = _keys(body, {"schema", "items"}, "mode inventory")
    if body["schema"] != MODE_INVENTORY_SCHEMA or not isinstance(body["items"], list):
        _fail("Invalid mode inventory schema/items")
    items: dict[str, dict[str, Any]] = {}
    for item in body["items"]:
        item = _keys(item, MODE_ITEM_KEYS, "mode inventory item")
        path = _path(item["destination"])
        if (not _hex(item["source_sha256"]) or not _hex(item["output_sha256"])
                or not _decimal(item["source_size_decimal"])
                or not _decimal(item["output_size_decimal"])
                or type(item["executable"]) is not bool):
            _fail("Invalid mode inventory digest, size or executable intent")
        items[path] = item
    _unique_paths([item["destination"] for item in body["items"]])
    if list(items) != sorted(items):
        _fail("Mode inventory must be sorted by destination")
    return items


def _inputs_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) not in (INPUT_KEYS, INPUT_KEYS | {"repository_intelligence"}):
        _fail("Invalid preserved initialization inputs")
    if (value["mode"] not in {"greenfield", "brownfield"}
            or value["profile"] not in PROFILE_ORDER
            or any(not isinstance(value[key], str) or not value[key]
                   for key in ("archetype", "backend", "memory_choice"))
            or (value["mode"] == "brownfield") != ("repository_intelligence" in value)
            or ("repository_intelligence" in value
                and not isinstance(value["repository_intelligence"], dict))):
        _fail("Incomplete initialization inputs")
    return value


def _inputs(value: Any, prior: dict[str, Any] | None, operation: str) -> dict[str, Any]:
    value = _inputs_shape(value)
    if prior is None:
        if operation != "naos-init":
            _fail("First receipt must be initialization")
    elif operation == "naos-upgrade-profile-transition":
        if (canonical_bytes({k: v for k, v in value.items() if k != "profile"})
                != canonical_bytes({k: v for k, v in prior.items() if k != "profile"})):
            _fail("Profile transition changed initialization choices")
    elif (operation in {"naos-init", "naos-hook-activate"} or operation.startswith("naos-add-artifact:")
          or operation.startswith("naos-add-setup-module:")):
        if canonical_bytes(value) != canonical_bytes(prior):
            _fail("Operation changed initialization choices")
    else:
        _fail("Unsupported managed operation")
    return value


def _projection(entries: dict[str, dict[str, Any]], inputs: dict[str, Any]) -> str:
    return canonical_sha256({"entries": [entries[p] for p in sorted(entries)], "inputs": inputs})


def _manifest_projection(manifest: dict[str, Any]) -> tuple[str, int]:
    items = manifest["entries"]
    if not isinstance(items, list):
        _fail("Manifest entries are not a list")
    paths: list[str] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            _fail("Invalid manifest entry")
        path = _path(item["path"])
        _entry(item, path)
        paths.append(path)
    _unique_paths(paths)
    if paths != sorted(paths):
        _fail("Manifest entries are not sorted")
    inputs = _inputs_shape(manifest["inputs"])
    return canonical_sha256({"entries": items, "inputs": inputs}), len(items)


def load_portable_snapshot(reader: Reader) -> ValidatedPortableSnapshot:
    """Validate owner, every receipt/base/policy/inventory, and manifest lineage.

    The caller must provide a native contained reader. The returned snapshot
    contains portable facts only and cannot authorize a checkout mutation.
    """
    try:
        return _load_portable_snapshot(reader)
    except PortableProvenanceError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PortableProvenanceError("Malformed portable provenance") from exc


def _load_portable_snapshot(reader: Reader) -> ValidatedPortableSnapshot:
    cumulative_read_bytes = 0
    total_changes = 0
    total_selected_paths = 0
    projection_entry_visits = 0
    prefix_reference_visits = 0
    validated_bases: dict[str, int] = {}

    def read(relative: str, *, maximum: int, declared_size: int | None = None) -> bytes | None:
        nonlocal cumulative_read_bytes
        if (declared_size is not None
                and declared_size > MAX_CUMULATIVE_READ_BYTES - cumulative_read_bytes):
            _fail("Cumulative portable read-byte budget exceeded")
        raw = reader.read(relative)
        if raw is not None:
            if not isinstance(raw, bytes) or len(raw) > maximum:
                _fail("Missing, invalid or oversized portable input")
            if len(raw) > MAX_CUMULATIVE_READ_BYTES - cumulative_read_bytes:
                _fail("Cumulative portable read-byte budget exceeded")
            cumulative_read_bytes += len(raw)
        return raw

    owner, owner_sha = _decode_record(read(OWNER_PATH, maximum=MAX_RECORD_BYTES), OWNER_SCHEMA,
        {"schema", "project_id", "minimum_reader", "authority_kind", "authority_sha256"})
    if (not _new_project_id(owner["project_id"])
            or owner["minimum_reader"] != 3
            or owner["authority_kind"] not in {"new_enrollment", "legacy_projection", "legacy_replay_projection"}
            or not _hex(owner["authority_sha256"])):
        _fail("Invalid or unsupported portable owner authority")
    legacy_seed = None
    if owner["authority_kind"] == "legacy_projection":
        from .legacy_authority import load_authority
        legacy_seed = load_authority(read, owner)
    if owner["authority_kind"] == "legacy_replay_projection":
        from .legacy_authority import load_replay_authority
        legacy_seed = load_replay_authority(read, owner)
    manifest, manifest_sha = _decode_record(read(MANIFEST_PATH, maximum=MAX_RECORD_BYTES), MANIFEST_SCHEMA,
        {"schema", "project_id", "owner_sha256", "previous_head_sha256",
         "receipts", "entries", "inputs", "projection_sha256", "head_receipt_sha256"})
    if manifest["project_id"] != owner["project_id"] or manifest["owner_sha256"] != owner_sha:
        _fail("Manifest owner differs")
    refs = manifest["receipts"]
    if not isinstance(refs, list) or not 1 <= len(refs) <= MAX_RECEIPTS:
        _fail("Invalid receipt coverage")
    entries: dict[str, dict[str, Any]] = {}
    previous_receipt: str | None = None
    inputs: dict[str, Any] | None = None
    projections: list[str] = []
    known_paths: dict[str, str] = {}
    seen_refs: set[str] = set()
    policies: dict[str, dict[str, Any]] = {}
    inventories: dict[str, dict[str, dict[str, Any]]] = {}
    for index, ref in enumerate(refs, 1):
        ref = _keys(ref, {"id", "sha256"}, "receipt reference")
        rid = f"R{index:08d}"
        if ref["id"] != rid or not _hex(ref["sha256"]) or ref["sha256"] in seen_refs:
            _fail("Duplicate, missing or out-of-order receipt reference")
        seen_refs.add(ref["sha256"])
        receipt, receipt_sha = _decode_record(read(receipt_path(ref["sha256"]), maximum=MAX_RECORD_BYTES),
            RECEIPT_SCHEMA,
            {"schema", "id", "project_id", "owner_sha256", "previous_receipt_sha256",
             "previous_projection_sha256", "result_projection_sha256", "operation",
             "inputs", "selected_paths", "changes", "policy_sha256", "mode_inventory_sha256"})
        if (receipt_sha != ref["sha256"] or receipt["id"] != rid
                or receipt["project_id"] != owner["project_id"]
                or receipt["owner_sha256"] != owner_sha
                or receipt["previous_receipt_sha256"] != previous_receipt
                or receipt["previous_projection_sha256"] != (projections[-1] if projections else None)
                or not _hex(receipt["policy_sha256"])
                or not _hex(receipt["mode_inventory_sha256"])):
            _fail("Broken receipt chain or owner binding")
        policy_digest = receipt["policy_sha256"]
        if policy_digest not in policies:
            raw = read(policy_path(policy_digest), maximum=MAX_RECORD_BYTES)
            if not isinstance(raw, bytes) or len(raw) > MAX_RECORD_BYTES:
                _fail("Missing policy snapshot")
            policy_record = _keys(_load_json(raw, "policy snapshot"), {"snapshot_id", "policy"}, "policy snapshot")
            snapshot_id = policy_record["snapshot_id"]
            if (not isinstance(snapshot_id, str) or not snapshot_id
                    or canonical_bytes(policy_record) != raw
                    or canonical_sha256(policy_record) != policy_digest):
                _fail("Invalid policy snapshot digest or canonical bytes")
            policies[policy_digest] = _validate_source_policy(policy_record["policy"], snapshot_id=snapshot_id)
        inventory_digest = receipt["mode_inventory_sha256"]
        if inventory_digest not in inventories:
            inventory, actual = _decode_record(read(inventory_path(inventory_digest), maximum=MAX_RECORD_BYTES),
                MODE_INVENTORY_SCHEMA, {"schema", "items"})
            if actual != inventory_digest:
                _fail("Mode inventory digest differs")
            inventories[inventory_digest] = _mode_inventory(inventory)
        operation = receipt["operation"]
        if index == 1:
            activated_hooks = set()
        if operation == "naos-hook-activate":
            activated_hooks.add(".githooks/pre-commit")
        if not isinstance(operation, str):
            _fail("Invalid operation")
        prior_inputs = inputs
        migration_genesis = legacy_seed is not None and index == 1
        if migration_genesis:
            expected_changes = [{"path": e["path"], "before": None, "after": e}
                                for e in legacy_seed["entries"]]
            if (operation != "naos-migrate"
                    or canonical_bytes(receipt["inputs"]) != canonical_bytes(legacy_seed["inputs"])
                    or receipt["selected_paths"] != [e["path"] for e in legacy_seed["entries"]]
                    or canonical_bytes(receipt["changes"]) != canonical_bytes(expected_changes)
                    or policy_digest != legacy_seed["genesis_policy_sha256"]
                    or inventory_digest != legacy_seed["inventory_sha256"]):
                _fail("Migration genesis differs from validated historical authority")
            inputs = _inputs_shape(receipt["inputs"])
        else:
            inputs = _inputs(receipt["inputs"], inputs, operation)
        if operation == "naos-hook-activate":
            from .hook_activation import validate_activation_receipt
            validate_activation_receipt(receipt, inventories[inventory_digest])
        selected = receipt["selected_paths"]
        changes = receipt["changes"]
        # A real profile-only transition must not invent a managed-file update.
        # It changes the replay projection through inputs, never path ownership.
        inputs_only = (index > 1 and operation == "naos-upgrade-profile-transition"
                       and prior_inputs is not None
                       and canonical_bytes(inputs) != canonical_bytes(prior_inputs)
                       and selected == [] and changes == []
                       and not inventories[inventory_digest])
        if (not isinstance(selected, list) or not isinstance(changes, list)
                or (not inputs_only and (not selected or not changes))
                or any(not isinstance(p, str) for p in selected)
                or selected != sorted(selected)):
            _fail("Malformed selected-path or change coverage")
        if len(changes) > MAX_TOTAL_CHANGES - total_changes:
            _fail("Cumulative receipt-change budget exceeded")
        total_changes += len(changes)
        if len(selected) > MAX_TOTAL_SELECTED_PATHS - total_selected_paths:
            _fail("Cumulative selected-path budget exceeded")
        total_selected_paths += len(selected)
        _unique_paths(selected)
        for path in selected:
            historic = known_paths.get(path.casefold())
            if historic is not None and historic != path:
                _fail("Selected path aliases historical managed path")
        changed_paths: list[str] = []
        for change in changes:
            change = _keys(change, {"path", "before", "after"}, "receipt change")
            path = _path(change["path"])
            changed_paths.append(path)
            alias = path.casefold()
            if alias in known_paths and known_paths[alias] != path:
                _fail("Historical path alias")
            known_paths[alias] = path
            before = entries.get(path)
            if change["before"] is not None:
                _entry(change["before"], path)
            if (None if change["before"] is None else canonical_bytes(change["before"])) != (
                    None if before is None else canonical_bytes(before)):
                _fail("Receipt before identity differs from replay")
            after = _entry(change["after"], path)
            if before is None and not migration_genesis:
                if (after["content"] is None or after["introduced_by"] != rid
                        or after["latest_base_receipt"] != rid
                        or after["introduced_policy_sha256"] != policy_digest):
                    _fail("Invalid first creation or introduction policy")
                rule = classify_new_path(Path(path), policies[policy_digest])
                if (after["ownership"] != rule["ownership"]
                        or after["creation_policy"] != rule["creation_policy"]):
                    _fail("Ownership escalation from source policy")
            elif before is not None:
                if before["ownership"] != "kit_owned_derived":
                    _fail("Update of non-kit-owned entry")
                for key in ("ownership", "creation_policy", "introduced_policy_sha256", "introduced_by"):
                    if after[key] != before[key]:
                        _fail("Historical ownership or creation policy changed")
                if (after["latest_base_receipt"] != (rid if after["content"] is not None
                                                      else before["latest_base_receipt"])):
                    _fail("Invalid latest base receipt")
            if path in activated_hooks and (after["content"] is None or after["content"]["executable"] is not True):
                _fail("Explicit hook activation intent cannot be silently removed")
            if after["content"] is not None:
                content = after["content"]
                item = inventories[inventory_digest].get(path)
                if (item is None or item["output_sha256"] != content["sha256"]
                        or item["output_size_decimal"] != content["size_decimal"]
                        or item["executable"] is not content["executable"]):
                    _fail("Source-mode inventory does not bind exact output")
                base_sha = content["sha256"]
                expected_size = int(content["size_decimal"])
                if expected_size > MAX_BASE_BYTES:
                    _fail("Historical base exceeds per-base byte limit")
                if base_sha in validated_bases:
                    if validated_bases[base_sha] != expected_size:
                        _fail("Historical base size differs for repeated digest")
                else:
                    blob = read(base_path(base_sha), maximum=MAX_BASE_BYTES,
                                declared_size=expected_size)
                    if (blob is None or len(blob) != expected_size
                            or hashlib.sha256(blob).hexdigest() != base_sha):
                        _fail("Missing or altered exact-byte historical base")
                    validated_bases[base_sha] = expected_size
            entries[path] = after
        _unique_paths(changed_paths)
        if changed_paths != sorted(changed_paths) or not set(changed_paths) <= set(selected):
            _fail("Receipt changes are not a sorted subset of selected paths")
        if len(entries) > MAX_PROJECTION_ENTRY_VISITS - projection_entry_visits:
            _fail("Cumulative projection-work budget exceeded")
        projection_entry_visits += len(entries)
        projection = _projection(entries, inputs)
        if receipt["result_projection_sha256"] != projection:
            _fail("Receipt result projection differs from replay")
        projections.append(projection)
        previous_receipt = receipt_sha
    _unique_paths(list(known_paths.values()))
    if (manifest["head_receipt_sha256"] != previous_receipt
            or manifest["projection_sha256"] != projections[-1]):
        _fail("Manifest does not match exact replay projection")
    # Every historical head is a complete, immutable prefix, one receipt per commit.
    current = manifest
    seen_heads = {manifest_sha}
    for length in range(len(refs), 0, -1):
        if length > MAX_PREFIX_REFERENCE_VISITS - prefix_reference_visits:
            _fail("Cumulative manifest-prefix budget exceeded")
        prefix_reference_visits += length
        current_refs = current["receipts"]
        if (not isinstance(current_refs, list) or len(current_refs) != length
                or any(not isinstance(ref, dict) or set(ref) != {"id", "sha256"}
                       or type(ref["id"]) is not str or type(ref["sha256"]) is not str
                       or ref["id"] != refs[position]["id"]
                       or ref["sha256"] != refs[position]["sha256"]
                       for position, ref in enumerate(current_refs))):
            _fail("Previous manifest receipt prefix differs")
        items = current["entries"]
        if not isinstance(items, list) or len(items) > MAX_PROJECTION_ENTRY_VISITS - projection_entry_visits:
            _fail("Cumulative projection-work budget exceeded")
        projection_entry_visits += len(items)
        actual_projection, _ = _manifest_projection(current)
        if (actual_projection != projections[length - 1]
                or current["projection_sha256"] != projections[length - 1]
                or current["head_receipt_sha256"] != refs[length - 1]["sha256"]
                or current["owner_sha256"] != owner_sha
                or current["project_id"] != owner["project_id"]):
            _fail("Previous manifest is not an exact history prefix")
        previous = current["previous_head_sha256"]
        if length == 1:
            if previous is not None:
                _fail("Genesis manifest has a previous head")
            break
        if not _hex(previous) or previous in seen_heads:
            _fail("Missing or cyclic previous manifest head")
        seen_heads.add(previous)
        current, actual = _decode_record(read(prior_manifest_path(previous), maximum=MAX_RECORD_BYTES),
            MANIFEST_SCHEMA,
            {"schema", "project_id", "owner_sha256", "previous_head_sha256",
             "receipts", "entries", "inputs", "projection_sha256", "head_receipt_sha256"})
        if actual != previous:
            _fail("Previous manifest digest differs")
    return ValidatedPortableSnapshot(owner["project_id"], owner_sha, manifest_sha,
        previous_receipt, canonical_bytes({p: entries[p] for p in sorted(entries)}),
        canonical_bytes(inputs), canonical_bytes(manifest), tuple(sorted(activated_hooks)))
