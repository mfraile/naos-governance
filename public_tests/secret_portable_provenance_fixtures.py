"""Pure portable provenance constructor fixtures for the public contracts.

These constructors assert no native filesystem or runtime mutation authority.
"""
import copy
import hashlib
from upgrade_contract import portable_provenance as pp
from upgrade_contract.canonical import canonical_sha256, loads_strict_json


POLICY = {
    "version": 2, "scope": "managed-content",
    "semantics": {"ownership_inference": "forbidden",
                  "unmatched_new_path": "create_once_adopter_owned",
                  "existing_without_valid_base": "preserve_and_refuse",
                  "exact_path_precedence": True,
                  "prior_manifest_ownership": "preserve_verbatim"},
    "rules": [{"id": "kit", "ownership": "kit_owned_derived",
               "creation_policy": "create", "first_components": ["scripts"]}],
    "fallback": {"id": "fallback", "ownership": "adopter_owned",
                 "creation_policy": "create_once_adopter_owned"},
}


INPUTS = {"mode": "greenfield", "profile": "standard", "archetype": "custom",
          "backend": "static_only", "memory_choice": "not_selected"}


PROJECT_ID = "123e4567-e89b-42d3-a456-426614174000"


class Reader:
    def __init__(self, files):
        self.files = files

    def read(self, relative):
        return self.files.get(relative)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def body(raw):
    return loads_strict_json(raw)["body"]


def entry(path, data, policy_sha, *, rid="R00000001", executable=False,
          ownership="kit_owned_derived", creation_policy="create"):
    return {"path": path,
            "content": {"kind": "file", "sha256": digest(data),
                        "size_decimal": str(len(data)), "executable": executable},
            "ownership": ownership, "creation_policy": creation_policy,
            "introduced_policy_sha256": policy_sha,
            "introduced_by": rid, "latest_base_receipt": rid}


def fixture(*, path="scripts/tool.py", data=b"a\r\nb\n", executable=False,
            ownership="kit_owned_derived", creation_policy="create", inputs=None):
    inputs = INPUTS if inputs is None else inputs
    files = {}
    owner = {"schema": pp.OWNER_SCHEMA, "project_id": PROJECT_ID,
             "minimum_reader": 3, "authority_kind": "new_enrollment",
             "authority_sha256": "1" * 64}
    owner_sha = canonical_sha256(owner)
    files[pp.OWNER_PATH] = pp.encode_record(owner)
    policy_sha, policy_bytes = pp.encode_policy("v2", POLICY)
    files[pp.policy_path(policy_sha)] = policy_bytes
    item = {"destination": path, "source_sha256": digest(data),
            "source_size_decimal": str(len(data)), "output_sha256": digest(data),
            "output_size_decimal": str(len(data)), "executable": executable}
    inventory_sha, inventory_bytes = pp.encode_mode_inventory([item])
    files[pp.inventory_path(inventory_sha)] = inventory_bytes
    files[pp.base_path(digest(data))] = data
    e = entry(path, data, policy_sha, executable=executable,
              ownership=ownership, creation_policy=creation_policy)
    projection = canonical_sha256({"entries": [e], "inputs": inputs})
    receipt = {"schema": pp.RECEIPT_SCHEMA, "id": "R00000001",
               "project_id": PROJECT_ID, "owner_sha256": owner_sha,
               "previous_receipt_sha256": None, "previous_projection_sha256": None,
               "result_projection_sha256": projection, "operation": "naos-init",
               "inputs": inputs, "selected_paths": [path],
               "changes": [{"path": path, "before": None, "after": e}],
               "policy_sha256": policy_sha, "mode_inventory_sha256": inventory_sha}
    receipt_sha = canonical_sha256(receipt)
    files[pp.receipt_path(receipt_sha)] = pp.encode_record(receipt)
    manifest = {"schema": pp.MANIFEST_SCHEMA, "project_id": PROJECT_ID,
                "owner_sha256": owner_sha, "previous_head_sha256": None,
                "receipts": [{"id": "R00000001", "sha256": receipt_sha}],
                "entries": [e], "inputs": inputs,
                "projection_sha256": projection, "head_receipt_sha256": receipt_sha}
    files[pp.MANIFEST_PATH] = pp.encode_record(manifest)
    return files


def two_receipt_fixture(*, path="scripts/tool.py", ownership="kit_owned_derived",
                        creation_policy="create"):
    files = fixture(path=path, ownership=ownership, creation_policy=creation_policy)
    first = body(files[pp.MANIFEST_PATH])
    first_head = canonical_sha256(first)
    files[pp.prior_manifest_path(first_head)] = files[pp.MANIFEST_PATH]
    prior = first["entries"][0]
    next_bytes = b"next exact bytes"
    next_entry = copy.deepcopy(prior)
    next_entry["content"] = {"kind": "file", "sha256": digest(next_bytes),
                             "size_decimal": str(len(next_bytes)), "executable": False}
    next_entry["latest_base_receipt"] = "R00000002"
    files[pp.base_path(digest(next_bytes))] = next_bytes
    inventory_sha, inventory = pp.encode_mode_inventory([{
        "destination": path, "source_sha256": digest(next_bytes),
        "source_size_decimal": str(len(next_bytes)),
        "output_sha256": digest(next_bytes), "output_size_decimal": str(len(next_bytes)),
        "executable": False}])
    files[pp.inventory_path(inventory_sha)] = inventory
    projection = canonical_sha256({"entries": [next_entry], "inputs": INPUTS})
    receipt = {"schema": pp.RECEIPT_SCHEMA, "id": "R00000002",
               "project_id": PROJECT_ID, "owner_sha256": first["owner_sha256"],
               "previous_receipt_sha256": first["head_receipt_sha256"],
               "previous_projection_sha256": first["projection_sha256"],
               "result_projection_sha256": projection,
               "operation": "naos-add-artifact:next", "inputs": INPUTS,
               "selected_paths": [path],
               "changes": [{"path": path, "before": prior, "after": next_entry}],
               "policy_sha256": prior["introduced_policy_sha256"],
               "mode_inventory_sha256": inventory_sha}
    second_sha = canonical_sha256(receipt)
    files[pp.receipt_path(second_sha)] = pp.encode_record(receipt)
    second = {**first, "previous_head_sha256": first_head,
              "receipts": first["receipts"] + [{"id": "R00000002", "sha256": second_sha}],
              "entries": [next_entry], "projection_sha256": projection,
              "head_receipt_sha256": second_sha}
    files[pp.MANIFEST_PATH] = pp.encode_record(second)
    return files, first_head, second_sha
