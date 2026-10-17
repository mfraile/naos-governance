#!/usr/bin/env python3
"""Build a synthetic saved-Windows RI reader fixture; never call native APIs.

All native-looking values are deterministic public test constants. This creates
linked parser inputs, not enrollment evidence or a claim that Windows ran here.
Run from the kit with rfc8785==0.1.4 installed, passing --output PATH.
"""

from __future__ import annotations
import argparse
import base64
import copy
import hashlib
import json
import ntpath
from pathlib import Path
import sqlite3
import sys
import uuid
import zlib

HERE = Path(__file__).resolve().parent
KIT = (
    Path(__file__).resolve().parents[2]
    if (Path(__file__).resolve().parents[2] / "scripts").is_dir()
    else Path.cwd()
)
sys.path.insert(0, str(KIT / "scripts"))
import naos_secret_managed_operands as m  # noqa: E402
import naos_secret_ri_windows_operands as w  # noqa: E402

ROOT = r"C:\synthetic-ri-fixture\project-abcdefghijklmnopqrstuvwxyz0123456789"
SEED = "naos-public-synthetic-windows-ri-v1:"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def public_hash(label):
    return sha((SEED + label).encode())


def plain(value):
    return m.canonical_bytes(value)


def digest(value):
    return sha(plain(value))


def envelope(body):
    return plain({"body": body, "sha256": digest(body)})


def pretty(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def build(inputs_path):
    template = json.loads(inputs_path.read_text())
    files = {p: s.encode() for p, s in template["text_files"].items()}
    manifest = copy.deepcopy(template["manifest.json"])
    control = manifest["control"]
    inventory = copy.deepcopy(template["inventory.json"])
    validation = copy.deepcopy(template["validation_receipt.json"])
    vc = validation["control"]
    root = {
        "volume_serial_hex": "0123456789abcdef",
        "file_id_hex": public_hash("root")[:32],
    }
    security = public_hash("private-security-descriptor")
    project = "urn:uuid:" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, "naos:windows:ri:" + digest(root))
    )
    op = "WOP-" + public_hash("operation")[:16]
    operation = w.RUNTIME + "/operations/" + op
    stage = w.RUNTIME + "/staging/" + op

    def native(path, kind):
        return dict(
            schema="naos.repository_intelligence.windows_object_identity.v1",
            volume_serial_hex=root["volume_serial_hex"],
            file_id_hex=public_hash("native:" + path)[:32],
            kind=kind,
            security_sha256=security,
        )

    implementation = {
        name: public_hash("implementation:" + name) for name in w.RUNTIME_IMPLEMENTATION
    }
    enrollment_implementation = {
        name: implementation[name] for name in w.ENROLLMENT_IMPLEMENTATION
    }
    ci = control["implementation"]
    ci["windows_ri_enrollment"] = enrollment_implementation
    ci["windows_ri_runtime"] = implementation
    for key in (
        "engine_sha256",
        "local_context_index_sha256",
        "canonical_adapter_sha256",
        "windows_ri_public",
    ):
        ci[key] = public_hash("implementation:" + key)
    control["project_root"] = ROOT
    control["rules"]["path"] = (
        r"Z:\synthetic-naos-kit-abcdefghijklmnopqrstuvwxyz0123456789\templates\naos\repository_intelligence_rules.yaml"
    )
    rules = template["rules_yaml"].encode()
    control["rules"]["sha256"] = sha(rules)
    control["effective_source_sha256"] = public_hash("source-policy")
    # These are deliberately declared synthetic platform values, not observations.
    control["runtime"]["platform"]["python"] = "3.11.0"
    control["runtime"]["sqlite_fts"]["sqlite_version"] = "3.0.0"
    profile = control["profile"]
    named = profile in {"standard", "assured"}
    profile_gate = dict(
        profile=profile,
        digest_confirmation_required=True,
        named_review_required=named,
        reviewer_identity_is_attribution_not_authentication=True,
        maturity_does_not_authorize_component_selection=True,
    )
    authorization_source = dict(
        project_root=ROOT,
        profile=profile,
        profile_gate=profile_gate,
        naos_root="naos",
        purpose=control["purpose"],
        component_mode=control["component_mode"],
        rules_sha256=sha(rules),
        effective_source_sha256=control["effective_source_sha256"],
        runtime=control["runtime"],
        components=control["components"],
        implementation=ci,
    )
    plan = dict(
        schema=w.ENROLLMENT_PLAN_SCHEMA,
        owner_kind="naos_windows_repository_intelligence",
        capability_id="CAP-LOCAL-CONTEXT-INDEX",
        scope_id="repository-intelligence",
        project_id=project,
        root_identity=root,
        record_path=w.ENROLLMENT,
        governed_root=m._RI_ROOT,
        initial_governed_root_state="absent",
        ownership_inference="forbidden",
        activation_authorized=False,
        private_security_sha256=security,
        parents={".naos": None, ".naos/upgrade-v1": None},
        implementation=enrollment_implementation,
        python_minor="3.11",
        source_authorization_sha256=digest(authorization_source),
    )
    enrollment = dict(
        schema=w.ENROLLMENT_SCHEMA,
        plan=plan,
        plan_sha256=digest(plan),
        parents={p: native(p, "directory") for p in plan["parents"]},
    )
    enrollment["record_sha256"] = digest(enrollment)
    files[w.ENROLLMENT] = plain(enrollment)
    binding = dict(
        record_sha256=sha(files[w.ENROLLMENT]),
        record_identity=native(w.ENROLLMENT, "file"),
        project_id=project,
        enrollment_plan_sha256=enrollment["plan_sha256"],
    )
    directories = (
        ".naos",
        ".naos/upgrade-v1",
        ".naos/upgrade-v1/state",
        *w.DIRECTORIES,
    )
    bootstrap = dict(
        schema=w.BOOTSTRAP_SCHEMA,
        enrollment=binding,
        directories={p: native(p, "directory") for p in directories},
        files={p: native(p, "file") for p in w.FILES},
    )
    files[w.BOOTSTRAP] = plain(bootstrap)
    for p in w.FILES:
        files[p] = b""
    gate = dict(
        status="valid",
        activation_eligible=True,
        backend="windows-ri-enrollment.v1",
        governed_root=m._RI_ROOT,
        record_path=w.ENROLLMENT,
        ownership_inference="forbidden",
        refusal=None,
        native_enrollment_plan=None,
        enrollment=dict(
            project_id=project,
            native_plan_sha256=enrollment["plan_sha256"],
            record_bytes_sha256=binding["record_sha256"],
            record_identity=binding["record_identity"],
        ),
    )
    control["provenance_gate"] = gate
    content = {
        k: control[k]
        for k in (
            "project_root",
            "profile",
            "purpose",
            "component_mode",
            "effective_source_sha256",
            "rules",
            "runtime",
            "implementation",
            "provenance_gate",
            "components",
            "graph_model_sha256",
            "ongoing_use_scope",
        )
    }
    content["capability_id"] = "CAP-LOCAL-CONTEXT-INDEX"
    content_sha = digest(content)
    gid = "RI-" + content_sha[:24]
    generation = m._RI_ROOT + "/generations/" + gid
    control.update(generation_id=gid, generation_content_sha256=content_sha)
    inventory.update(
        project_root=ROOT,
        generation_id=gid,
        effective_source_sha256=control["effective_source_sha256"],
    )
    for a in inventory["artifacts"]:
        a["source_hash"] = sha(files[a["path"]])
        a["size_bytes"] = len(files[a["path"]])
    for a in inventory["source_inventory"]:
        a["source_sha256"] = sha(files[a["path"]])
        a["size_bytes"] = len(files[a["path"]])
    for key in (
        "generation_id",
        "generation_content_sha256",
        "effective_source_sha256",
        "profile",
        "purpose",
        "component_mode",
        "runtime",
        "implementation",
        "provenance_gate",
    ):
        vc[key] = copy.deepcopy(control[key])
    vc["sqlite_fts"]["content_identity_binding"] = inventory["sqlite_content_binding"]
    # SQL contains only toy source/index content; old machine metadata was removed.
    db = sqlite3.connect(":memory:")
    db.executescript(template["sqlite_sql"])
    db.execute("UPDATE index_runs SET rules_hash=?", (sha(rules),))
    metadata = {
        k: control[k]
        for k in (
            "effective_source_sha256",
            "generation_content_sha256",
            "graph_model_sha256",
            "ongoing_use_scope",
        )
    }
    metadata["sqlite_content_binding"] = inventory["sqlite_content_binding"]
    db.executemany(
        "INSERT INTO repository_metadata VALUES (?,?)",
        [(k, json.dumps(v, sort_keys=True)) for k, v in sorted(metadata.items())],
    )
    db.commit()
    if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise RuntimeError("synthetic sqlite integrity")
    sqlite_raw = db.serialize()
    db.close()
    validation["receipt_sha256"] = digest(vc)
    members_raw = {
        "inventory.json": pretty(inventory),
        "local_context_index.sqlite": sqlite_raw,
        "repository_intelligence_rules.yaml": rules,
        "validation_receipt.json": pretty(validation),
    }
    control["validation_receipt_sha256"] = validation["receipt_sha256"]
    control["files"] = [
        dict(path=p, sha256=sha(b), size_bytes=len(b))
        for p, b in sorted(members_raw.items())
    ]
    manifest["manifest_sha256"] = digest(control)
    members_raw["manifest.json"] = pretty(manifest)
    for p, b in members_raw.items():
        files[generation + "/" + p] = b
    members = {p: sha(b) for p, b in sorted(members_raw.items())}
    authorization = dict(
        schema="naos.repository_intelligence.windows_authorization.v1",
        profile=profile,
        naos_root="naos",
        profile_gate=profile_gate,
        reviewer=dict(
            reviewer_id="synthetic-public-reviewer",
            required=named,
            identity_status="declared_attribution" if named else "not_required",
            authentication_status="not_claimed",
        ),
        effective_source_sha256=control["effective_source_sha256"],
        rules_sha256=sha(rules),
        manifest_sha256=manifest["manifest_sha256"],
        generation_content_sha256=content_sha,
    )
    request = dict(
        public_plan_sha256=public_hash("public-plan"),
        bundle_sha256=public_hash("bundle"),
        generation_id=gid,
        authorization=authorization,
    )
    receipt = dict(
        schema=w.ACTIVATION_RECEIPT_SCHEMA,
        operation_id=op,
        request=request,
        members=members,
        predecessor=None,
    )
    receipt_path = w.RUNTIME + "/receipts/" + op + ".json"
    files[receipt_path] = plain(receipt)
    pointer = {
        **receipt,
        "schema": w.ACTIVE_SCHEMA,
        "receipt_sha256": sha(files[receipt_path]),
    }
    active = m._RI_ROOT + "/active.json"
    files[active] = plain(pointer)
    slots = {}
    publications = []

    def publication(role, target, staged, raw):
        after = dict(
            volume_serial_hex=root["volume_serial_hex"],
            file_id_hex=public_hash("publication:" + target)[:32],
            size_bytes=str(len(raw)),
            content_sha256=sha(raw),
            metadata_sha256=public_hash("metadata:" + target),
            rename_metadata_v2=dict(
                created_100ns_decimal="125911584000000000",
                last_write_100ns_decimal="125911584000000000",
                attributes_hex="00000020",
                owner_sid_sha256=public_hash("owner-sid"),
                group_sid_sha256=public_hash("group-sid"),
                dacl_sha256=public_hash("dacl"),
                descriptor_sha256=public_hash("descriptor"),
                dacl_protected=True,
            ),
        )
        publications.append(
            dict(role=role, kind="create", target=target, staged=staged, after=after)
        )

    for i, name in enumerate(sorted(members)):
        t = "content-" + str(i)
        s = "staged-" + str(i)
        slots[t] = generation + "/" + name
        slots[s] = stage + "/" + name
        publication("content", t, s, members_raw[name])
    slots.update(
        receipt=receipt_path,
        **{
            "staged-receipt": stage + "/activation-receipt.json",
            "pointer": active,
            "staged-pointer": stage + "/active.json",
        },
    )
    publication("evidence", "receipt", "staged-receipt", files[receipt_path])
    publication("manifest", "pointer", "staged-pointer", files[active])
    preparation = dict(
        schema=w.PREPARATION_SCHEMA,
        operation_id=op,
        request=request,
        bootstrap_sha256=digest(bootstrap),
        implementation=implementation,
        predecessor=None,
        directories={p: native(p, "directory") for p in (stage, generation)},
        members=members,
        publications=publications,
        pointer_sha256=sha(files[active]),
        receipt_sha256=pointer["receipt_sha256"],
    )
    files[w.RUNTIME + "/preparations/" + op + ".json"] = plain(preparation)
    files[operation + "/plan.json"] = envelope(
        dict(
            schema="naos.upgrade.windows_operation_plan.v2",
            operation_id=op,
            plan=preparation,
            plan_sha256=digest(preparation),
        )
    )

    def id_only(n):
        return {k: n[k] for k in ("volume_serial_hex", "file_id_hex")}

    intent = dict(
        schema="naos.upgrade.windows_operation.v2",
        failure_model="application_crash_v1",
        operation_id=op,
        plan_sha256=digest(preparation),
        slot_paths={k: ntpath.join(ROOT, *p.split("/")) for k, p in slots.items()},
        publications=publications,
        runtime_parent_id=id_only(bootstrap["directories"][w.RUNTIME + "/operations"]),
        scope_lock_id=id_only(bootstrap["files"][w.RUNTIME + "/scope.lock"]),
        transaction_directory_id=id_only(native(operation, "directory")),
        lock_id=id_only(native(operation + "/lock", "file")),
    )
    files[operation + "/intent.json"] = envelope(intent)
    marker = dict(
        schema=intent["schema"],
        failure_model="application_crash_v1",
        intent_sha256=sha(files[operation + "/intent.json"]),
        direction="forward",
        topology="committed",
    )
    files[operation + "/committed.json"] = envelope(marker)
    for i in range(1, len(publications) + 1):
        files[operation + "/forward-" + f"{i:06d}" + ".json"] = envelope(
            {**marker, "topology": "step:" + str(i)}
        )
    files[operation + "/lock"] = b""
    result = dict(
        schema="naos.public_test.synthetic_windows_ri_fixture.v1",
        logical_root=ROOT,
        derived_empty_directories=[w.RUNTIME + "/directory-template", stage],
        provenance=dict(
            kind="fully_synthetic",
            generator="public_tests/fixtures/generate_ri_windows_synthetic_fixture.py",
            inputs="public_tests/fixtures/ri_windows_synthetic_inputs.json",
            inputs_sha256=sha(inputs_path.read_bytes()),
            native_values="Deterministic public constants; no device-derived IDs, security descriptors or timestamps.",
            platform_values="Declared synthetic test inputs; never observed Windows runtime evidence.",
            sqlite_generation="Logical toy SQL rebuilt with Python sqlite3; SQLite serialization can vary by library version.",
        ),
        not_claimed=[
            "native Windows execution",
            "current ownership",
            "supplier capture equivalence",
            "real reviewer authentication",
        ],
        files={
            p: dict(
                size_bytes=len(b),
                sha256=sha(b),
                zlib_base64=base64.b64encode(zlib.compress(b, 9)).decode(),
            )
            for p, b in sorted(files.items())
        },
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--inputs", type=Path, default=HERE / "ri_windows_synthetic_inputs.json"
    )
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(build(args.inputs), indent=2, sort_keys=True) + "\n"
    )
