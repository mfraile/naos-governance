"""Synthetic test histories; no captured device metadata or adopter authority.

Native legacy seeds use the real low-level writers, with two selected files and
fixture-only creator metadata. They do not assert scaffold/profile validation.
Portable seeds use the existing pure public fixture, then observe the real host
through the public rebind command. Product calls always receive ordinary paths.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace
import uuid
from unittest.mock import patch

import secret_portable_provenance_fixtures as portable_fixture
from upgrade_contract import legacy_archive_capture as archive_capture
from upgrade_contract import legacy_migration_records as migration
from upgrade_contract import portable_provenance as pp
from upgrade_contract.canonical import canonical_bytes, loads_strict_json


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def io_path(path: Path) -> Path:
    """Extended paths for owned Windows fixture I/O, never product arguments."""
    if os.name == "nt":
        return Path("\\\\?\\" + str(path.absolute()))
    return path


def cleanup_owned_temp(owner) -> None:
    if os.name == "nt":
        shutil.rmtree(io_path(Path(owner.name)))
    owner.cleanup()


def tree(root: Path) -> dict:
    root = io_path(root)
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        value = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
                 info.st_ino, info.st_mtime_ns)
        if path.is_symlink():
            value += (os.readlink(path),)
        elif path.is_file():
            value += (path.read_bytes(),)
        result[path.relative_to(root).as_posix()] = value
    return result


def preserved_tree(root: Path) -> dict:
    # Local receiver storage may be created; portable history and user files may not change.
    return {path: (value[:3] + (None,) if path in {".", ".naos"} else value)
            for path, value in tree(root).items()
            if path != ".naos/local" and not path.startswith(".naos/local/")}


def portable_seed(base: Path, kit: Path, *, hook=False):
    root = base / "project"
    root.mkdir()
    path = ".githooks/pre-commit" if hook else "scripts/tool.py"
    data = ((kit / "templates/rules-chain/.githooks/pre-commit").read_bytes()
            if hook else b"synthetic managed bytes\n")
    if hook:
        from upgrade_contract.planner import load_source_policy_snapshot
        policy = load_source_policy_snapshot(kit / "configs/upgrade_source_policy.yaml").policy
        with patch.object(portable_fixture, "POLICY", policy):
            files = portable_fixture.fixture(path=path, data=data)
    else:
        files = portable_fixture.fixture(path=path, data=data)
    snapshot = pp.load_portable_snapshot(portable_fixture.Reader(files))
    for relative, raw in {**files, path: data}.items():
        target = io_path(root / relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if os.name != "nt":
            target.chmod(0o644)
    return SimpleNamespace(root=root, snapshot=snapshot, files=files, path=path, data=data)


def native_legacy_seed(base: Path, kit: Path):
    root = base / "project"
    root.mkdir()
    contents = {"scripts/tool.py": b"VALUE = 'synthetic'\n",
                ".githooks/pre-commit": (kit / "templates/rules-chain/.githooks/pre-commit").read_bytes()}
    sources = []
    for index, (relative, raw) in enumerate(contents.items()):
        source = base / f"source-{index}"
        source.write_bytes(raw)
        if os.name != "nt":
            source.chmod(0o644)
        sources.append((Path(relative), source))
    policy_path = kit / "configs/upgrade_source_policy.yaml"
    inputs = {"mode": "greenfield", "profile": "standard", "archetype": "custom",
              "backend": "static_only", "memory_choice": "disabled"}
    if os.name == "nt":
        from upgrade_contract.windows_cli import source_pairs
        from upgrade_contract.windows_handles import WindowsHandles
        from upgrade_contract.windows_runtime import WindowsRuntime
        runtime = WindowsRuntime(WindowsHandles(), str(root), str(policy_path))
        native_sources = source_pairs(sources)
        plan = runtime.plan(native_sources, request={"operation": "naos-init", "inputs": inputs},
                            checks=[], allow_enrollment=True)
        assert plan["status"] == "ready", plan
        outcome = runtime.apply(plan, native_sources, expected_digest=plan["digest_sha256"])
        assert outcome["status"] == "committed", outcome
        source_format = migration.WINDOWS_CONTENT_V1
    else:
        from upgrade_contract import provenance, transaction
        from upgrade_contract.planner import build_create_only_plan
        plan = build_create_only_plan(root, sources, source_policy_path=policy_path,
                                      operation="naos-init", inputs=inputs)
        scope = provenance.commit_managed_content_enrollment(
            root, authorization_digest=plan["plan_sha256"],
            source_policy_sha256=plan["source_policy_sha256"],
            creator_identity={"kit_id": "naos-governance", "kit_version": "fixture-version",
                              "source_commit": None, "source_manifest_sha256": "a" * 64})
        outcome = transaction.apply_create_only_plan(
            root, plan=plan, sources=sources, project_id=scope.project_id,
            scope_integrity_sha3_512=scope.scope_integrity,
            scope_source_policy_sha256=scope.source_policy_sha256,
            transaction_root=root / provenance.MANAGED_CONTENT_TRANSACTIONS_RELATIVE,
            lock_path=root / provenance.MANAGED_CONTENT_LOCK_RELATIVE,
            manifest_path=root / provenance.MANAGED_CONTENT_MANIFEST_RELATIVE,
            bases_root=root / provenance.MANAGED_CONTENT_BASES_RELATIVE,
            receipts_root=root / provenance.MANAGED_CONTENT_RECEIPTS_RELATIVE)
        assert outcome.status == "committed", outcome
        source_format = migration.POSIX_MANAGED_V1
    with archive_capture.held_legacy_archive(root, source_format=source_format) as held:
        archive = held.archive_bytes
    anchors = migration._ANCHORS[source_format]
    expected = {f"expected_{role}_sha256": sha(archive[path]) for role, path in anchors.items()}
    owner = loads_strict_json(archive[anchors["owner"]])
    original_id = owner.get("body", owner)["project_id"]
    new_id = str(uuid.uuid4())
    lineage = migration.build_lineage(archive, source_format=source_format,
                                      original_project_id=original_id, new_project_id=new_id, **expected)
    # Explicit fixture intent from selected source bytes, never inferred from a receiving host.
    items = [{"destination": path, "source_sha256": sha(raw), "output_sha256": sha(raw),
              "source_size_decimal": str(len(raw)), "output_size_decimal": str(len(raw)),
              "executable": False} for path, raw in sorted(contents.items())]
    modes_sha, modes_raw = pp.encode_mode_inventory(items)
    policy_raw = policy_path.read_bytes()
    policy_file, mode_file = base / "policy.yaml", base / "modes.json"
    policy_file.write_bytes(policy_raw)
    mode_file.write_bytes(modes_raw)
    controls = {"schema": "naos.upgrade.legacy_migration_inputs.v2", "source_format": source_format,
                "original_project_id": original_id, "new_project_id": new_id,
                "binding_id": uuid.uuid4().hex, "approved_lineage_sha256": lineage.sha256,
                "expected_source_policy_sha256": sha(policy_raw), "expected_modes_sha256": modes_sha,
                "source_policy_file": policy_file.name, "mode_inventory_file": mode_file.name, **expected}
    inputs_file = base / "inputs.json"
    inputs_file.write_bytes(canonical_bytes(controls))
    return SimpleNamespace(root=root, archive=archive, lineage=lineage, inputs_file=inputs_file,
                           source_format=source_format, new_id=new_id, contents=contents)


def load_portable(root: Path):
    files = {path.relative_to(io_path(root)).as_posix(): path.read_bytes()
             for path in io_path(root / pp.ROOT).rglob("*") if path.is_file()}
    return pp.load_portable_snapshot(portable_fixture.Reader(files))
