"""Pure B/C/N classification and conservative managed-content source policy."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from .canonical import canonical_sha256
from .security import (
    managed_creation_identity,
    metadata_preservation_matches,
    observe_absent_leaf,
    observe_created_file_metadata_fd,
    observe_regular_file_beneath,
    safe_relative_path,
    source_metadata_contract,
    validate_managed_creation_identity,
    validate_created_metadata_identity,
    validate_source_metadata_contract,
    validate_distinct_paths,
)


Presence = Literal["present", "absent", "unknown"]
OWNERSHIP_CLASSES = {
    "kit_owned_derived",
    "adopter_owned",
    "adopter_adapted_generated",
    "configuration_choice",
    "ephemeral_cache",
    "evidence_bearing_report",
    "unmanaged",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA3_512_RE = re.compile(r"^[0-9a-f]{128}$")
LEGACY_CONTENT_AWARE_PLAN_SCHEMA = "naos.upgrade.content_aware_plan.v1"
CONTENT_AWARE_PLAN_SCHEMA = "naos.upgrade.content_aware_plan.v2"
CONTENT_AWARE_PLAN_SCHEMAS = {
    LEGACY_CONTENT_AWARE_PLAN_SCHEMA,
    CONTENT_AWARE_PLAN_SCHEMA,
}


class ContentPlanningError(ValueError):
    """Raised when content state or source policy is incomplete or ambiguous."""


@dataclass(frozen=True)
class SourcePolicySnapshot:
    snapshot_id: str
    sha256: str
    policy: dict[str, Any]
    compatibility_aliases: tuple[str, ...] = ()
    snapshot_sha256: str | None = None


@dataclass(frozen=True)
class ContentIdentity:
    presence: Presence
    kind: str | None = None
    mode: int | None = None
    size: int | None = None
    sha256: str | None = None

    def __post_init__(self) -> None:
        if self.presence not in {"present", "absent", "unknown"}:
            raise ContentPlanningError("Content identity presence is invalid.")
        if self.presence == "present":
            if (
                self.kind not in {"file", "directory", "symlink", "special"}
                or isinstance(self.mode, bool)
                or not isinstance(self.mode, int)
                or not 0 <= self.mode <= 0o777
                or isinstance(self.size, bool)
                or not isinstance(self.size, int)
                or self.size < 0
                or not isinstance(self.sha256, str)
                or SHA256_RE.fullmatch(self.sha256) is None
            ):
                raise ContentPlanningError("Present content identity is incomplete.")
        elif any(
            value is not None for value in (self.kind, self.mode, self.size, self.sha256)
        ):
            raise ContentPlanningError("Absent/unknown identity cannot carry content fields.")

    @classmethod
    def absent(cls) -> "ContentIdentity":
        return cls("absent")

    @classmethod
    def unknown(cls) -> "ContentIdentity":
        return cls("unknown")

    def comparison_key(self) -> tuple[str, int, int, str]:
        if self.presence != "present":
            raise ContentPlanningError("Only present identities can be compared.")
        assert self.kind is not None and self.mode is not None
        assert self.size is not None and self.sha256 is not None
        return self.kind, self.mode, self.size, self.sha256


def regular_file_observation(
    path: Path,
) -> tuple[ContentIdentity, dict[str, object]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        live = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (live.st_dev, live.st_ino)
        ):
            raise ContentPlanningError(
                f"Content source is not a stable unique regular file: {path}"
            )
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        metadata_identity = observe_created_file_metadata_fd(descriptor)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            int(getattr(before, "st_flags", 0)),
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            int(getattr(after, "st_flags", 0)),
        ):
            raise ContentPlanningError(f"Content source changed while read: {path}")
        return (
            ContentIdentity(
                "present",
                kind="file",
                mode=stat.S_IMODE(before.st_mode),
                size=before.st_size,
                sha256=digest.hexdigest(),
            ),
            metadata_identity,
        )
    finally:
        os.close(descriptor)


def regular_file_identity(path: Path) -> ContentIdentity:
    return regular_file_observation(path)[0]


def require_supported_source_metadata(
    path: Path,
    metadata: dict[str, object],
) -> None:
    if (
        metadata.get("flags") != 0
        or metadata.get("acl_entries") != []
        or metadata.get("uid") != os.getuid()
        or int(metadata.get("mode") or 0) & ~0o777
    ):
        raise ContentPlanningError(
            "UNSUPPORTED_METADATA: source flags, ACL, owner, or special "
            f"mode is outside the executed Darwin create-only adapter: {path}"
        )


def _same(left: ContentIdentity, right: ContentIdentity) -> bool:
    return left.comparison_key() == right.comparison_key()


def classify_content_state(
    base: ContentIdentity,
    current: ContentIdentity,
    new: ContentIdentity,
) -> str:
    """Select exactly one normative content row for a reachable B/C/N tuple."""

    if current.presence == "unknown" or new.presence == "unknown":
        raise ContentPlanningError("Current and new identities cannot be unknown.")
    if base.presence == "unknown":
        return "REFUSE_PROVENANCE"
    if base.presence == current.presence == new.presence == "absent":
        raise ContentPlanningError("B/C/N all absent is outside the path universe.")
    if base.presence == current.presence == new.presence == "present":
        bc = _same(base, current)
        bn = _same(base, new)
        cn = _same(current, new)
        if bc and bn:
            return "NOOP_UNCHANGED"
        if cn and not bc:
            return "NOOP_ALREADY_IDENTICAL"
        if bc and not bn:
            return "PROPOSE_UPDATE_FROM_UPSTREAM"
        if bn and not bc:
            return "PRESERVE_ADOPTER_MODIFICATION"
        if not bc and not bn and not cn:
            return "CONFLICT_PRESERVE"
        raise ContentPlanningError("Present B/C/N equality predicates are inconsistent.")
    tuple_key = (base.presence, current.presence, new.presence)
    # Keep comparisons inside the rows whose operands are both present.  A
    # dictionary literal would evaluate every value eagerly, including
    # comparisons for unrelated absent-state rows.
    if tuple_key == ("present", "present", "absent"):
        return (
            "RETAIN_REMOVED_UPSTREAM"
            if _same(base, current)
            else "REMOVAL_CONFLICT_PRESERVE"
        )
    if tuple_key == ("absent", "present", "present"):
        return (
            "NOOP_IDENTICAL_UNMANAGED"
            if _same(current, new)
            else "UNMANAGED_COLLISION_PRESERVE"
        )
    rows = {
        ("present", "absent", "present"): "PRESERVE_ABSENCE",
        ("present", "absent", "absent"): "NOOP_REMOVED_AND_ABSENT",
        ("absent", "absent", "present"): "PROPOSE_NEW_UPSTREAM_CREATE",
        ("absent", "present", "absent"): "UNMANAGED_RETAIN",
    }
    try:
        return rows[tuple_key]
    except KeyError as exc:
        raise ContentPlanningError(f"Unreachable B/C/N tuple: {tuple_key}") from exc


def apply_ownership_guard(
    proposal: str,
    ownership: str,
    *,
    creation_policy: str | None = None,
) -> dict[str, str]:
    """Apply the ownership guard without granting authority from equality alone."""

    if ownership not in OWNERSHIP_CLASSES:
        raise ContentPlanningError(f"Unknown ownership class: {ownership}")
    if proposal in {"NOOP_IDENTICAL_UNMANAGED", "UNMANAGED_COLLISION_PRESERVE", "UNMANAGED_RETAIN"}:
        return {"ownership": "unmanaged", "action": proposal}
    # Content state never grants or changes ownership. A separately recorded
    # adopter-adaptation decision may use adopter_adapted_generated, but byte
    # equality, difference, or absence cannot bootstrap that class.
    effective = ownership
    if proposal == "REFUSE_PROVENANCE":
        return {"ownership": effective, "action": "REFUSE_PROVENANCE"}
    if proposal == "PROPOSE_NEW_UPSTREAM_CREATE":
        allowed = {
            ("kit_owned_derived", "create"): "CREATE_NEW_UPSTREAM",
            ("adopter_owned", "create_once_adopter_owned"): "CREATE_NEW_ADOPTER_OWNED",
            ("configuration_choice", "preserved_choice"): "CREATE_CONFIGURATION_CHOICE",
            ("ephemeral_cache", "owned_cache"): "CREATE_MANAGED_CACHE",
            ("evidence_bearing_report", "immutable_new"): "CREATE_IMMUTABLE_REPORT",
        }
        action = allowed.get((effective, creation_policy))
        if action is None:
            raise ContentPlanningError(
                "New-path ownership/creation policy is not eligible for creation."
            )
        return {"ownership": effective, "action": action}
    if proposal == "PROPOSE_UPDATE_FROM_UPSTREAM":
        actions = {
            "kit_owned_derived": "UPDATE_FROM_UPSTREAM",
            "adopter_owned": "PRESERVE_ADOPTER_CONTENT",
            "adopter_adapted_generated": "PRESERVE_ADAPTED_CONTENT",
            "configuration_choice": "PRESERVE_CONFIGURATION_CHOICE",
            "ephemeral_cache": "REFUSE_CACHE_UPDATE_OUTSIDE_OWNED_ROOT",
            "evidence_bearing_report": "PRESERVE_EVIDENCE_REPORT",
            "unmanaged": "REFUSE_UNMANAGED_MUTATION",
        }
        return {"ownership": effective, "action": actions[effective]}
    if proposal in {
        "CONFLICT_PRESERVE",
        "UNMANAGED_COLLISION_PRESERVE",
        "PRESERVE_ADOPTER_MODIFICATION",
        "REMOVAL_CONFLICT_PRESERVE",
    }:
        return {"ownership": effective, "action": proposal}
    return {"ownership": effective, "action": proposal}


def _read_source_policy_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ContentPlanningError(
                "Managed-content source policy is not a unique regular file."
            )
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ContentPlanningError(
                "Managed-content source policy changed while it was read."
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_source_policy(policy: Any, *, snapshot_id: str) -> dict[str, Any]:
    if (
        not isinstance(policy, dict)
        or policy.get("version") not in {1, 2}
        or policy.get("scope") != "managed-content"
    ):
        raise ContentPlanningError(
            f"Managed-content source policy snapshot is invalid: {snapshot_id}"
        )
    semantics = policy.get("semantics")
    rules = policy.get("rules")
    fallback = policy.get("fallback")
    if (
        not isinstance(semantics, dict)
        or semantics.get("ownership_inference") != "forbidden"
        or semantics.get("unmatched_new_path") != "create_once_adopter_owned"
        or semantics.get("existing_without_valid_base")
        != "preserve_and_refuse"
        or (
            policy.get("version") == 2
            and (
                semantics.get("exact_path_precedence") is not True
                or semantics.get("prior_manifest_ownership")
                != "preserve_verbatim"
            )
        )
        or not isinstance(rules, list)
        or not rules
        or not isinstance(fallback, dict)
    ):
        raise ContentPlanningError(
            f"Managed-content source policy snapshot is incomplete: {snapshot_id}"
        )
    rule_ids: set[str] = set()
    exact_paths: set[str] = set()
    first_components: set[str] = set()
    for rule in [*rules, fallback]:
        if not isinstance(rule, dict):
            raise ContentPlanningError(
                f"Managed-content source policy rule is invalid: {snapshot_id}"
            )
        rule_id = str(rule.get("id") or "fallback")
        if rule_id in rule_ids:
            raise ContentPlanningError(
                f"Managed-content source policy rule ID is duplicated: {rule_id}"
            )
        rule_ids.add(rule_id)
        ownership = str(rule.get("ownership") or "")
        creation_policy = str(rule.get("creation_policy") or "")
        apply_ownership_guard(
            "PROPOSE_NEW_UPSTREAM_CREATE",
            ownership,
            creation_policy=creation_policy,
        )
        for field in ("exact_paths", "first_components"):
            values = rule.get(field, [])
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value for value in values
            ):
                raise ContentPlanningError(
                    f"Managed-content source policy {field} is invalid: {rule_id}"
                )
            if len(values) != len(set(values)):
                raise ContentPlanningError(
                    f"Managed-content source policy {field} is duplicated: {rule_id}"
                )
            if field == "exact_paths":
                canonical_values: set[str] = set()
                for value in values:
                    relative = safe_relative_path(value)
                    if relative.as_posix() != value:
                        raise ContentPlanningError(
                            "Managed-content source policy exact path is not canonical: "
                            + value
                        )
                    canonical_values.add(value)
                if canonical_values & exact_paths:
                    raise ContentPlanningError(
                        "Managed-content source policy exact rules overlap."
                    )
                exact_paths.update(canonical_values)
            else:
                if any("/" in value or value in {".", ".."} for value in values):
                    raise ContentPlanningError(
                        "Managed-content source policy first component is invalid."
                    )
                component_values = set(values)
                if component_values & first_components:
                    raise ContentPlanningError(
                        "Managed-content source policy component rules overlap."
                    )
                first_components.update(component_values)
    return policy


def load_source_policy_snapshot(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> SourcePolicySnapshot:
    """Resolve one immutable policy snapshot from one stable file read.

    Flat v1 policy files remain supported for transaction fixtures. The
    repository bundle binds new plans to the active snapshot's canonical
    digest, while retained aliases resolve older raw-file provenance without
    changing its recorded ownership.
    """

    raw = _read_source_policy_bytes(path)
    try:
        value = yaml.safe_load(raw.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ContentPlanningError("Managed-content source policy is invalid YAML.") from exc
    if isinstance(value, dict) and value.get("version") == 1:
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and expected_sha256 != digest:
            raise ContentPlanningError(
                "Managed-content source policy snapshot is unavailable for "
                f"recorded digest: {expected_sha256}"
            )
        policy = _validate_source_policy(value, snapshot_id="legacy-flat-v1")
        return SourcePolicySnapshot(
            "legacy-flat-v1",
            digest,
            policy,
            snapshot_sha256=digest,
        )
    if (
        not isinstance(value, dict)
        or value.get("schema") != "naos.upgrade.source_policy_bundle.v1"
        or not isinstance(value.get("active_snapshot"), str)
        or not isinstance(value.get("snapshots"), list)
    ):
        raise ContentPlanningError("Managed-content source policy bundle is invalid.")
    snapshots: list[SourcePolicySnapshot] = []
    observed_ids: set[str] = set()
    observed_bindings: set[str] = set()
    for record in value["snapshots"]:
        if not isinstance(record, dict) or set(record) != {
            "id",
            "sha256_aliases",
            "policy",
        }:
            raise ContentPlanningError(
                "Managed-content source policy snapshot record is invalid."
            )
        snapshot_id = str(record.get("id") or "")
        aliases = record.get("sha256_aliases")
        if (
            not snapshot_id
            or snapshot_id in observed_ids
            or not isinstance(aliases, list)
            or len(aliases) != len(set(aliases))
            or any(
                not isinstance(alias, str) or SHA256_RE.fullmatch(alias) is None
                for alias in aliases
            )
        ):
            raise ContentPlanningError(
                "Managed-content source policy snapshot identity is invalid."
            )
        observed_ids.add(snapshot_id)
        policy = _validate_source_policy(record.get("policy"), snapshot_id=snapshot_id)
        digest = canonical_sha256(
            {"snapshot_id": snapshot_id, "policy": policy}
        )
        bindings = {digest, *aliases}
        if bindings & observed_bindings:
            raise ContentPlanningError(
                "Managed-content source policy snapshot binding is ambiguous."
            )
        observed_bindings.update(bindings)
        snapshots.append(
            SourcePolicySnapshot(
                snapshot_id,
                digest,
                policy,
                tuple(sorted(aliases)),
                digest,
            )
        )
    if expected_sha256 is None:
        matches = [
            snapshot
            for snapshot in snapshots
            if snapshot.snapshot_id == value["active_snapshot"]
        ]
    else:
        matches = [
            snapshot
            for snapshot in snapshots
            if expected_sha256
            in {snapshot.sha256, *snapshot.compatibility_aliases}
        ]
    if len(matches) != 1:
        label = expected_sha256 or str(value["active_snapshot"])
        raise ContentPlanningError(
            "Managed-content source policy snapshot is unavailable or ambiguous: "
            + label
        )
    selected = matches[0]
    binding = expected_sha256 or selected.sha256
    return SourcePolicySnapshot(
        selected.snapshot_id,
        binding,
        selected.policy,
        selected.compatibility_aliases,
        selected.snapshot_sha256,
    )


def _load_source_policy_snapshot(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> tuple[dict[str, Any], str]:
    snapshot = load_source_policy_snapshot(
        path,
        expected_sha256=expected_sha256,
    )
    return snapshot.policy, snapshot.sha256


def load_source_policy(path: Path) -> dict[str, Any]:
    return _load_source_policy_snapshot(path)[0]


def classify_new_path(relative_path: Path, policy: dict[str, Any]) -> dict[str, str]:
    if relative_path.is_absolute() or relative_path == Path(".") or ".." in relative_path.parts:
        raise ContentPlanningError(f"Unsafe managed-content path: {relative_path}")
    exact_matches: list[dict[str, Any]] = []
    component_matches: list[dict[str, Any]] = []
    for rule in policy.get("rules") or []:
        if not isinstance(rule, dict):
            raise ContentPlanningError("Managed-content policy rule is not an object.")
        exact = {str(item) for item in (rule.get("exact_paths") or [])}
        components = {str(item) for item in (rule.get("first_components") or [])}
        if relative_path.as_posix() in exact:
            exact_matches.append(rule)
        elif relative_path.parts and relative_path.parts[0] in components:
            component_matches.append(rule)
    matches = exact_matches or component_matches
    if len(matches) > 1:
        raise ContentPlanningError(f"Ambiguous managed-content source policy: {relative_path}")
    selected = matches[0] if matches else policy.get("fallback")
    if not isinstance(selected, dict):
        raise ContentPlanningError(f"No managed-content source policy: {relative_path}")
    ownership = str(selected.get("ownership") or "")
    creation_policy = str(selected.get("creation_policy") or "")
    apply_ownership_guard(
        "PROPOSE_NEW_UPSTREAM_CREATE",
        ownership,
        creation_policy=creation_policy,
    )
    return {
        "policy_id": str(selected.get("id") or "fallback"),
        "ownership": ownership,
        "creation_policy": creation_policy,
    }


def build_create_only_plan(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    source_policy_path: Path,
    operation: str,
    inputs: dict[str, Any],
    precondition_sources: list[tuple[Path, Path]] | None = None,
    expected_source_policy_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a target-read-only plan for one absent-regular-file transaction."""

    root = project_root.resolve(strict=True)
    root_device = os.lstat(root).st_dev
    policy, source_policy_sha256 = _load_source_policy_snapshot(
        source_policy_path,
        expected_sha256=expected_source_policy_sha256,
    )
    creation_identity = managed_creation_identity()
    precondition_sources = precondition_sources or []
    relative_paths = [safe_relative_path(relative) for relative, _source in sources]
    precondition_paths = [
        safe_relative_path(relative) for relative, _source in precondition_sources
    ]
    validate_distinct_paths(relative_paths + precondition_paths)
    if len(set(relative_paths + precondition_paths)) != len(
        relative_paths + precondition_paths
    ):
        raise ContentPlanningError("Managed-content plan contains duplicate paths.")
    paths: list[dict[str, Any]] = []
    for relative, source in sorted(sources, key=lambda item: item[0].as_posix()):
        relative = safe_relative_path(relative)
        source_identity, observed_source_metadata = regular_file_observation(source)
        source_metadata = source_metadata_contract(observed_source_metadata)
        require_supported_source_metadata(source, source_metadata)
        observation = observe_absent_leaf(root, relative)
        if any(
            device != root_device
            for _path, device, _inode in observation.ancestor_identities
        ):
            raise ContentPlanningError(
                "UNSUPPORTED_METADATA: destination ancestors must share the "
                f"project-root filesystem: {relative}"
            )
        policy_result = classify_new_path(relative, policy)
        current_status = observation.status
        if current_status == "absent":
            proposal = "PROPOSE_NEW_UPSTREAM_CREATE"
            guarded = apply_ownership_guard(
                proposal,
                policy_result["ownership"],
                creation_policy=policy_result["creation_policy"],
            )
        else:
            proposal = "UNMANAGED_COLLISION_PRESERVE"
            guarded = {"ownership": "unmanaged", "action": proposal}
        paths.append(
            {
                "path": relative.as_posix(),
                "source": {
                    "kind": source_identity.kind,
                    "mode": source_identity.mode,
                    "size": source_identity.size,
                    "sha256": source_identity.sha256,
                },
                "source_metadata": source_metadata,
                "base": "verified_absent",
                "current": current_status,
                "content_state": proposal,
                "ownership": guarded["ownership"],
                "creation_policy": policy_result["creation_policy"],
                "source_policy_rule": policy_result["policy_id"],
                "action": guarded["action"],
                "ancestor_identities": [
                    {"path": path, "device": device, "inode": inode}
                    for path, device, inode in observation.ancestor_identities
                ],
            }
        )
    preconditions: list[dict[str, Any]] = []
    for relative, source in sorted(
        precondition_sources,
        key=lambda item: item[0].as_posix(),
    ):
        relative = safe_relative_path(relative)
        source_identity, observed_source_metadata = regular_file_observation(source)
        source_metadata = source_metadata_contract(observed_source_metadata)
        require_supported_source_metadata(source, source_metadata)
        expected_source = {
            "kind": source_identity.kind,
            "mode": source_identity.mode,
            "size": source_identity.size,
            "sha256": source_identity.sha256,
        }
        current_identity, observed_current_metadata, current_ancestors = (
            observe_regular_file_beneath(root, relative)
        )
        if (
            current_identity != expected_source
            or not metadata_preservation_matches(
                source_metadata,
                observed_current_metadata,
                creation_identity=creation_identity,
            )
        ):
            raise ContentPlanningError(
                "Managed-content non-mutating precondition is not an exact "
                f"source/current match: {relative}"
            )
        preconditions.append(
            {
                "path": relative.as_posix(),
                "source": expected_source,
                "source_metadata": source_metadata,
                "requirement": "PROVENANCE_CURRENT_EXACT",
                "ancestor_identities": current_ancestors,
            }
        )
    status = (
        "ready_create_only"
        if paths
        and all(str(item["action"]).startswith("CREATE_") for item in paths)
        else "blocked_collision"
    )
    control = {
        "schema": (
            "naos.upgrade.create_only_plan.v2"
            if preconditions
            else "naos.upgrade.create_only_plan.v1"
        ),
        "operation": operation,
        "status": status,
        "project_root_binding": str(root),
        "source_policy_sha256": source_policy_sha256,
        "creation_identity": creation_identity,
        "inputs": inputs,
        "paths": paths,
        "replacement_allowed": False,
        "ownership_inference": "forbidden",
    }
    if preconditions:
        control["preconditions"] = preconditions
    result = {**control, "plan_sha256": canonical_sha256(control)}
    validate_create_only_plan(result, project_root=root)
    return result


def validate_create_only_plan(
    plan: dict[str, Any],
    *,
    project_root: Path,
) -> None:
    """Validate the complete create-only plan before it can authorize mutation."""

    schema = plan.get("schema") if isinstance(plan, dict) else None
    expected_keys = {
        "schema",
        "operation",
        "status",
        "project_root_binding",
        "source_policy_sha256",
        "creation_identity",
        "inputs",
        "paths",
        "replacement_allowed",
        "ownership_inference",
        "plan_sha256",
    }
    if schema == "naos.upgrade.create_only_plan.v2":
        expected_keys.add("preconditions")
    if (
        not isinstance(plan, dict)
        or schema
        not in {
            "naos.upgrade.create_only_plan.v1",
            "naos.upgrade.create_only_plan.v2",
        }
        or set(plan) != expected_keys
    ):
        raise ContentPlanningError("Managed-content plan shape is invalid.")
    root = project_root.resolve(strict=True)
    if plan.get("status") not in {"ready_create_only", "blocked_collision"}:
        raise ContentPlanningError("Managed-content plan status is invalid.")
    if plan.get("project_root_binding") != str(root):
        raise ContentPlanningError("Managed-content plan is bound to another project root.")
    if (
        not isinstance(plan.get("operation"), str)
        or not str(plan.get("operation")).strip()
        or not isinstance(plan.get("inputs"), dict)
        or plan.get("replacement_allowed") is not False
        or plan.get("ownership_inference") != "forbidden"
        or not isinstance(plan.get("source_policy_sha256"), str)
        or SHA256_RE.fullmatch(str(plan.get("source_policy_sha256"))) is None
    ):
        raise ContentPlanningError("Managed-content plan control fields are invalid.")
    try:
        validate_managed_creation_identity(plan.get("creation_identity"))
    except ValueError as exc:
        raise ContentPlanningError(
            "Managed-content plan creation identity is invalid."
        ) from exc
    paths = plan.get("paths")
    if not isinstance(paths, list) or not paths:
        raise ContentPlanningError("Managed-content plan path inventory is empty or invalid.")
    expected_path_keys = {
        "path",
        "source",
        "source_metadata",
        "base",
        "current",
        "content_state",
        "ownership",
        "creation_policy",
        "source_policy_rule",
        "action",
        "ancestor_identities",
    }
    relative_paths: list[Path] = []
    for item in paths:
        if not isinstance(item, dict) or set(item) != expected_path_keys:
            raise ContentPlanningError("Managed-content plan path shape is invalid.")
        if not isinstance(item.get("path"), str):
            raise ContentPlanningError("Managed-content plan path is invalid.")
        relative = safe_relative_path(str(item["path"]))
        if relative.as_posix() != item["path"]:
            raise ContentPlanningError("Managed-content plan path is not canonical.")
        relative_paths.append(relative)
        source = item.get("source")
        if not isinstance(source, dict) or set(source) != {
            "kind",
            "mode",
            "size",
            "sha256",
        }:
            raise ContentPlanningError(
                f"Managed-content source identity is invalid: {relative}"
            )
        mode = source.get("mode")
        size = source.get("size")
        digest = source.get("sha256")
        if (
            source.get("kind") != "file"
            or isinstance(mode, bool)
            or not isinstance(mode, int)
            or mode < 0
            or mode > 0o7777
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise ContentPlanningError(
                f"Managed-content source identity is invalid: {relative}"
            )
        try:
            validate_source_metadata_contract(item.get("source_metadata"))
        except ValueError as exc:
            raise ContentPlanningError(
                f"Managed-content source metadata is invalid: {relative}"
            ) from exc
        if item["source_metadata"].get("mode") != mode:
            raise ContentPlanningError(
                f"Managed-content source mode/metadata differs: {relative}"
            )
        if (
            item.get("base") != "verified_absent"
            or item.get("current")
            not in {"absent", "file", "directory", "symlink", "special"}
            or not isinstance(item.get("source_policy_rule"), str)
            or not str(item.get("source_policy_rule")).strip()
        ):
            raise ContentPlanningError(
                f"Managed-content create-only state is invalid: {relative}"
            )
        if item.get("current") == "absent":
            if item.get("content_state") != "PROPOSE_NEW_UPSTREAM_CREATE":
                raise ContentPlanningError(
                    f"Managed-content create-only proposal is invalid: {relative}"
                )
            guarded = apply_ownership_guard(
                "PROPOSE_NEW_UPSTREAM_CREATE",
                str(item.get("ownership") or ""),
                creation_policy=str(item.get("creation_policy") or ""),
            )
            if item.get("action") != guarded["action"]:
                raise ContentPlanningError(
                    f"Managed-content action is not authorized by its ownership policy: {relative}"
                )
        elif (
            item.get("content_state") != "UNMANAGED_COLLISION_PRESERVE"
            or item.get("ownership") != "unmanaged"
            or item.get("action") != "UNMANAGED_COLLISION_PRESERVE"
        ):
            raise ContentPlanningError(
                f"Managed-content collision finding is invalid: {relative}"
            )
        ancestors = item.get("ancestor_identities")
        if not isinstance(ancestors, list):
            raise ContentPlanningError(
                f"Managed-content ancestor inventory is invalid: {relative}"
            )
        seen_ancestors: list[Path] = []
        for ancestor in ancestors:
            if not isinstance(ancestor, dict) or set(ancestor) != {
                "path",
                "device",
                "inode",
            }:
                raise ContentPlanningError(
                    f"Managed-content ancestor identity is invalid: {relative}"
                )
            ancestor_path = safe_relative_path(str(ancestor.get("path") or ""))
            if (
                not isinstance(ancestor.get("device"), int)
                or isinstance(ancestor.get("device"), bool)
                or not isinstance(ancestor.get("inode"), int)
                or isinstance(ancestor.get("inode"), bool)
                or ancestor.get("device", -1) < 0
                or ancestor.get("inode", -1) < 0
                or relative.parts[: len(ancestor_path.parts)] != ancestor_path.parts
                or ancestor_path == relative
            ):
                raise ContentPlanningError(
                    f"Managed-content ancestor identity is invalid: {relative}"
                )
            seen_ancestors.append(ancestor_path)
        if seen_ancestors != sorted(
            seen_ancestors, key=lambda value: len(value.parts)
        ) or len(set(seen_ancestors)) != len(seen_ancestors):
            raise ContentPlanningError(
                f"Managed-content ancestor identity order is invalid: {relative}"
            )
    validate_distinct_paths(relative_paths)
    if [path.as_posix() for path in relative_paths] != sorted(
        path.as_posix() for path in relative_paths
    ):
        raise ContentPlanningError("Managed-content plan paths are not deterministic.")
    preconditions = plan.get("preconditions", [])
    if not isinstance(preconditions, list):
        raise ContentPlanningError(
            "Managed-content non-mutating preconditions are invalid."
        )
    if schema == "naos.upgrade.create_only_plan.v2" and not preconditions:
        raise ContentPlanningError(
            "Managed-content v2 plans require at least one precondition."
        )
    expected_precondition_keys = {
        "path",
        "source",
        "source_metadata",
        "requirement",
        "ancestor_identities",
    }
    seen_preconditions: list[Path] = []
    for item in preconditions:
        if not isinstance(item, dict) or set(item) != expected_precondition_keys:
            raise ContentPlanningError(
                "Managed-content non-mutating precondition shape is invalid."
            )
        relative = safe_relative_path(str(item.get("path") or ""))
        source = item.get("source")
        if (
            relative.as_posix() != item.get("path")
            or not isinstance(source, dict)
            or set(source) != {"kind", "mode", "size", "sha256"}
            or source.get("kind") != "file"
            or isinstance(source.get("mode"), bool)
            or not isinstance(source.get("mode"), int)
            or source.get("mode", -1) < 0
            or source.get("mode", 0) > 0o7777
            or isinstance(source.get("size"), bool)
            or not isinstance(source.get("size"), int)
            or source.get("size", -1) < 0
            or not isinstance(source.get("sha256"), str)
            or SHA256_RE.fullmatch(str(source.get("sha256"))) is None
            or item.get("requirement") != "PROVENANCE_CURRENT_EXACT"
        ):
            raise ContentPlanningError(
                f"Managed-content non-mutating precondition is invalid: {relative}"
            )
        try:
            validate_source_metadata_contract(item.get("source_metadata"))
        except ValueError as exc:
            raise ContentPlanningError(
                f"Managed-content precondition metadata is invalid: {relative}"
            ) from exc
        if item["source_metadata"].get("mode") != source.get("mode"):
            raise ContentPlanningError(
                f"Managed-content precondition mode differs: {relative}"
            )
        ancestors = item.get("ancestor_identities")
        if not isinstance(ancestors, list):
            raise ContentPlanningError(
                f"Managed-content precondition ancestry is invalid: {relative}"
            )
        seen_ancestors: list[Path] = []
        for ancestor in ancestors:
            if not isinstance(ancestor, dict) or set(ancestor) != {
                "path",
                "device",
                "inode",
            }:
                raise ContentPlanningError(
                    f"Managed-content precondition ancestry is invalid: {relative}"
                )
            ancestor_path = safe_relative_path(str(ancestor.get("path") or ""))
            if (
                not isinstance(ancestor.get("device"), int)
                or isinstance(ancestor.get("device"), bool)
                or not isinstance(ancestor.get("inode"), int)
                or isinstance(ancestor.get("inode"), bool)
                or relative.parts[: len(ancestor_path.parts)] != ancestor_path.parts
                or ancestor_path == relative
            ):
                raise ContentPlanningError(
                    f"Managed-content precondition ancestry is invalid: {relative}"
                )
            seen_ancestors.append(ancestor_path)
        if seen_ancestors != sorted(
            seen_ancestors,
            key=lambda value: len(value.parts),
        ) or len(set(seen_ancestors)) != len(seen_ancestors):
            raise ContentPlanningError(
                f"Managed-content precondition ancestry order is invalid: {relative}"
            )
        seen_preconditions.append(relative)
    if (
        [path.as_posix() for path in seen_preconditions]
        != sorted(path.as_posix() for path in seen_preconditions)
        or len(set(seen_preconditions)) != len(seen_preconditions)
    ):
        raise ContentPlanningError(
            "Managed-content precondition paths are not sorted and unique."
        )
    validate_distinct_paths(relative_paths + seen_preconditions)
    expected_status = (
        "ready_create_only"
        if all(str(item["action"]).startswith("CREATE_") for item in paths)
        else "blocked_collision"
    )
    if plan.get("status") != expected_status:
        raise ContentPlanningError(
            "Managed-content plan status does not match its path findings."
        )
    expected_digest = canonical_sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    if plan.get("plan_sha256") != expected_digest:
        raise ContentPlanningError("Managed-content plan digest is invalid.")


def revalidate_create_only_plan(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    source_policy_path: Path,
    plan: dict[str, Any],
    precondition_sources: list[tuple[Path, Path]] | None = None,
) -> None:
    rebuilt = build_create_only_plan(
        project_root,
        sources,
        source_policy_path=source_policy_path,
        operation=str(plan.get("operation") or ""),
        inputs=dict(plan.get("inputs") or {}),
        precondition_sources=precondition_sources,
        expected_source_policy_sha256=str(
            plan.get("source_policy_sha256") or ""
        ),
    )
    if rebuilt != plan:
        raise ContentPlanningError("Managed-content plan or target/source state changed before apply.")


def _normalized_metadata_sha256(
    identity: ContentIdentity,
    metadata: dict[str, object] | None,
    *,
    creation_identity: dict[str, object],
    normalize_creation_identity: bool,
) -> str | None:
    if identity.presence != "present":
        return None
    if metadata is None:
        return canonical_sha256(
            {
                "status": "unsupported",
                "kind": identity.kind,
                "mode": identity.mode,
                "size": identity.size,
            }
        )
    schema = metadata.get("schema")
    if schema == "naos.metadata.darwin_source.v1":
        validate_source_metadata_contract(metadata)
        normalized = copy.deepcopy(metadata)
    elif schema == "naos.metadata.darwin_create_only.v1":
        validate_created_metadata_identity(metadata, expected_type="regular_file")
        normalized = source_metadata_contract(metadata)
    else:
        raise ContentPlanningError("Content-aware metadata schema is unsupported.")
    if normalize_creation_identity:
        normalized["uid"] = creation_identity["uid"]
        normalized["gid"] = creation_identity["gid"]
    return canonical_sha256(normalized)


def _classification_identity(
    identity: ContentIdentity,
    metadata_sha256: str | None,
) -> ContentIdentity:
    if identity.presence != "present":
        return identity
    if not isinstance(metadata_sha256, str) or SHA256_RE.fullmatch(metadata_sha256) is None:
        raise ContentPlanningError("Present classification metadata identity is invalid.")
    return ContentIdentity(
        "present",
        kind=identity.kind,
        mode=identity.mode,
        size=identity.size,
        sha256=canonical_sha256(
            {
                "content_sha256": identity.sha256,
                "metadata_sha256": metadata_sha256,
            }
        ),
    )


def _identity_value(
    identity: ContentIdentity,
    metadata_sha256: str | None,
) -> dict[str, Any]:
    if identity.presence == "present":
        if (
            not isinstance(metadata_sha256, str)
            or SHA256_RE.fullmatch(metadata_sha256) is None
        ):
            raise ContentPlanningError("Present plan metadata identity is invalid.")
    elif metadata_sha256 is not None:
        raise ContentPlanningError(
            "Absent/unknown plan identity cannot carry metadata identity."
        )
    return {
        "presence": identity.presence,
        "kind": identity.kind,
        "mode": identity.mode,
        "size": identity.size,
        "sha256": identity.sha256,
        "metadata_sha256": metadata_sha256,
    }


def _identity_from_value(
    value: Any,
    *,
    label: str,
) -> tuple[ContentIdentity, str | None]:
    if not isinstance(value, dict) or set(value) != {
        "presence",
        "kind",
        "mode",
        "size",
        "sha256",
        "metadata_sha256",
    }:
        raise ContentPlanningError(f"{label} identity shape is invalid.")
    try:
        identity = ContentIdentity(
            value["presence"],
            kind=value["kind"],
            mode=value["mode"],
            size=value["size"],
            sha256=value["sha256"],
        )
    except (TypeError, ContentPlanningError) as exc:
        raise ContentPlanningError(f"{label} identity is invalid.") from exc
    metadata_sha256 = value["metadata_sha256"]
    if identity.presence == "present":
        if (
            not isinstance(metadata_sha256, str)
            or SHA256_RE.fullmatch(metadata_sha256) is None
        ):
            raise ContentPlanningError(
                f"{label} metadata identity is invalid."
            )
    elif metadata_sha256 is not None:
        raise ContentPlanningError(
            f"{label} absent/unknown metadata identity is invalid."
        )
    return identity, metadata_sha256


def _opaque_unsupported_identity(path: Path, kind: str) -> ContentIdentity:
    metadata = os.lstat(path)
    digest = hashlib.sha256(
        f"unsupported-leaf\0{kind}\0{stat.S_IMODE(metadata.st_mode)}\0{metadata.st_size}".encode(
            "utf-8"
        )
    ).hexdigest()
    return ContentIdentity(
        "present",
        kind=kind,
        mode=stat.S_IMODE(metadata.st_mode),
        size=metadata.st_size,
        sha256=digest,
    )


def _observe_current_content(
    root: Path,
    relative: Path,
) -> tuple[
    ContentIdentity,
    dict[str, object] | None,
    list[dict[str, object]],
    str | None,
]:
    observation = observe_absent_leaf(root, relative)
    ancestors = [
        {"path": path, "device": device, "inode": inode}
        for path, device, inode in observation.ancestor_identities
    ]
    if observation.status == "absent":
        return ContentIdentity.absent(), None, ancestors, None
    if observation.status != "file":
        return (
            _opaque_unsupported_identity(root / relative, observation.status),
            None,
            ancestors,
            "UNSUPPORTED_METADATA: destination leaf is not a regular file",
        )
    identity, metadata, descriptor_ancestors = observe_regular_file_beneath(
        root,
        relative,
    )
    current = ContentIdentity(
        "present",
        kind=str(identity["kind"]),
        mode=int(identity["mode"]),
        size=int(identity["size"]),
        sha256=str(identity["sha256"]),
    )
    reason = None
    if (
        metadata.get("platform") != "Darwin"
        or metadata.get("flags") != 0
        or metadata.get("acl_entries") != []
        or metadata.get("uid") != os.getuid()
        or int(metadata.get("mode") or 0) & ~0o777
    ):
        reason = (
            "UNSUPPORTED_METADATA: current file is outside the executed "
            "Darwin regular-file tuple"
        )
    return current, metadata, descriptor_ancestors, reason


def _validate_manifest_snapshot_for_planning(value: Any) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "project_id",
        "scope_integrity_sha3_512",
        "source_policy_sha256",
        "source_manifest_integrity_sha256",
        "migration",
        "creation_identity",
        "previous_inputs",
        "entries",
        "snapshot_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ContentPlanningError("Managed-content manifest snapshot shape is invalid.")
    if (
        value.get("schema")
        != "naos.upgrade.managed_content_manifest_snapshot.v2"
        or not isinstance(value.get("project_id"), str)
        or not value.get("project_id")
        or not isinstance(value.get("scope_integrity_sha3_512"), str)
        or SHA3_512_RE.fullmatch(str(value["scope_integrity_sha3_512"])) is None
        or not isinstance(value.get("source_policy_sha256"), str)
        or SHA256_RE.fullmatch(str(value["source_policy_sha256"])) is None
        or not isinstance(value.get("source_manifest_integrity_sha256"), str)
        or SHA256_RE.fullmatch(str(value["source_manifest_integrity_sha256"]))
        is None
        or not isinstance(value.get("previous_inputs"), dict)
    ):
        raise ContentPlanningError(
            "Managed-content manifest snapshot binding is invalid."
        )
    try:
        validate_managed_creation_identity(value.get("creation_identity"))
    except ValueError as exc:
        raise ContentPlanningError(
            "Managed-content manifest creation identity is invalid."
        ) from exc
    migration = value.get("migration")
    valid_migrations = (
        {
            "source_schema": "naos.upgrade.managed_content_manifest.v1",
            "status": "normalized_v1_preserved_ownership",
            "ownership_reclassified": False,
            "persisted": False,
        },
        {
            "source_schema": "naos.upgrade.managed_content_manifest.v2",
            "status": "validated_v2_preserved_ownership",
            "ownership_reclassified": False,
            "persisted": True,
        },
    )
    if migration not in valid_migrations:
        raise ContentPlanningError(
            "Managed-content manifest migration boundary is invalid."
        )
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ContentPlanningError(
            "Managed-content manifest snapshot inventory is invalid."
        )
    observed: list[str] = []
    expected_entry_keys = {
        "path",
        "ownership",
        "creation_policy",
        "base",
        "source_metadata",
        "base_blob",
        "created_metadata",
        "introduced_by_transaction",
        "receipt_sha256",
    }
    if migration["source_schema"] == "naos.upgrade.managed_content_manifest.v2":
        expected_entry_keys.add("last_mutated_by_transaction")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise ContentPlanningError(
                "Managed-content manifest snapshot entry shape is invalid."
            )
        relative = safe_relative_path(str(entry.get("path") or ""))
        if relative.as_posix() != entry.get("path"):
            raise ContentPlanningError(
                "Managed-content manifest snapshot path is not canonical."
            )
        ownership = str(entry.get("ownership") or "")
        if ownership not in OWNERSHIP_CLASSES:
            raise ContentPlanningError(
                f"Managed-content manifest ownership is invalid: {relative}"
            )
        if migration["source_schema"] == "naos.upgrade.managed_content_manifest.v2":
            last_mutated = entry.get("last_mutated_by_transaction")
            if not isinstance(last_mutated, str) or not last_mutated:
                raise ContentPlanningError(
                    f"Managed-content manifest mutation lineage is invalid: {relative}"
                )
        base = entry.get("base")
        if not isinstance(base, dict):
            raise ContentPlanningError(
                f"Managed-content manifest base is invalid: {relative}"
            )
        identity = ContentIdentity(
            "present",
            kind=base.get("kind"),
            mode=base.get("mode"),
            size=base.get("size"),
            sha256=base.get("sha256"),
        )
        if identity.kind != "file":
            raise ContentPlanningError(
                f"Managed-content manifest base is not a file: {relative}"
            )
        try:
            validate_source_metadata_contract(entry.get("source_metadata"))
        except ValueError as exc:
            raise ContentPlanningError(
                f"Managed-content manifest source metadata is invalid: {relative}"
            ) from exc
        base_blob = entry.get("base_blob")
        if (
            not isinstance(base_blob, dict)
            or base_blob
            != {"path": identity.sha256, "sha256": identity.sha256}
        ):
            raise ContentPlanningError(
                f"Managed-content manifest base blob is invalid: {relative}"
            )
        observed.append(relative.as_posix())
    if observed != sorted(observed) or len(set(observed)) != len(observed):
        raise ContentPlanningError(
            "Managed-content manifest snapshot paths are not sorted and unique."
        )
    control = {key: item for key, item in value.items() if key != "snapshot_sha256"}
    if value.get("snapshot_sha256") != canonical_sha256(control):
        raise ContentPlanningError(
            "Managed-content manifest snapshot digest is invalid."
        )
    return value


def _policy_binding(snapshot: SourcePolicySnapshot) -> dict[str, str]:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "binding_sha256": snapshot.sha256,
        "snapshot_sha256": str(snapshot.snapshot_sha256 or snapshot.sha256),
    }


def _path_action_contract(action: str) -> tuple[str, dict[str, Any]]:
    if action.startswith("CREATE_"):
        return "create_absent", {"kind": "create", "eligible": True}
    if action == "UPDATE_FROM_UPSTREAM":
        return "replace_verified_base", {"kind": "replace", "eligible": True}
    if action.startswith("NOOP_"):
        return "unchanged", {"kind": "none", "eligible": False}
    if action in {
        "PRESERVE_ABSENCE",
        "PRESERVE_ADOPTER_MODIFICATION",
        "PRESERVE_ADOPTER_CONTENT",
        "PRESERVE_ADAPTED_CONTENT",
        "PRESERVE_CONFIGURATION_CHOICE",
        "PRESERVE_EVIDENCE_REPORT",
        "CONFLICT_PRESERVE",
        "REMOVAL_CONFLICT_PRESERVE",
        "RETAIN_REMOVED_UPSTREAM",
        "UNMANAGED_RETAIN",
        "PRESERVE_OUT_OF_SCOPE",
    }:
        return "preserve", {"kind": "none", "eligible": False}
    return "refuse", {"kind": "none", "eligible": False}


def _normalized_fixed_checks(
    value: list[dict[str, str]] | None,
) -> list[dict[str, str]]:
    checks = copy.deepcopy(value or [])
    observed_ids: list[str] = []
    for check in checks:
        if (
            not isinstance(check, dict)
            or set(check) != {"check_id", "status", "evidence_sha256"}
            or not isinstance(check.get("check_id"), str)
            or not str(check["check_id"]).strip()
            or check.get("status") not in {"passed", "blocking", "not_applicable"}
            or not isinstance(check.get("evidence_sha256"), str)
            or SHA256_RE.fullmatch(str(check["evidence_sha256"])) is None
        ):
            raise ContentPlanningError("Content-aware fixed check is invalid.")
        observed_ids.append(str(check["check_id"]))
    if len(set(observed_ids)) != len(observed_ids):
        raise ContentPlanningError("Content-aware fixed checks are duplicated.")
    return sorted(checks, key=lambda check: str(check["check_id"]))


def _content_aware_status(
    paths: list[dict[str, Any]],
    input_conflicts: list[str],
    fixed_checks: list[dict[str, str]],
) -> str:
    blocking_actions = {
        "REFUSE_PROVENANCE",
        "UNSUPPORTED_METADATA",
        "UNMANAGED_COLLISION_PRESERVE",
        "REFUSE_UNMANAGED_MUTATION",
        "REFUSE_CACHE_UPDATE_OUTSIDE_OWNED_ROOT",
    }
    if (
        input_conflicts
        or any(item["action"] in blocking_actions for item in paths)
        or any(check["status"] == "blocking" for check in fixed_checks)
    ):
        return "diagnostic_only"
    if any(bool(item["mutation"]["eligible"]) for item in paths):
        return "ready"
    return "no_changes"


def build_content_aware_plan(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    source_policy_path: Path,
    operation: str,
    inputs: dict[str, Any],
    manifest_snapshot: dict[str, Any] | None,
    provenance_refusal: str | None = None,
    fixed_checks: list[dict[str, str]] | None = None,
    selected_paths: list[Path] | None = None,
    operation_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one exhaustive target-read-only content-aware plan."""

    root = project_root.resolve(strict=True)
    root_device = os.lstat(root).st_dev
    if not isinstance(operation, str) or not operation.strip():
        raise ContentPlanningError("Content-aware operation is invalid.")
    if (
        not isinstance(inputs, dict)
        or not isinstance(inputs.get("profile"), str)
        or not str(inputs["profile"]).strip()
    ):
        raise ContentPlanningError(
            "Content-aware planning requires one requested profile."
        )
    active_policy = load_source_policy_snapshot(source_policy_path)
    validated_manifest: dict[str, Any] | None = None
    manifest_refusal = provenance_refusal
    if manifest_snapshot is None and not manifest_refusal:
        manifest_refusal = (
            "Existing project has no validated managed-content provenance; "
            "ownership inference is forbidden."
        )
    if manifest_snapshot is not None:
        try:
            validated_manifest = _validate_manifest_snapshot_for_planning(
                manifest_snapshot
            )
        except ContentPlanningError as exc:
            manifest_refusal = str(exc)
    provenance_policy: SourcePolicySnapshot | None = None
    if validated_manifest is not None:
        try:
            provenance_policy = load_source_policy_snapshot(
                source_policy_path,
                expected_sha256=str(validated_manifest["source_policy_sha256"]),
            )
        except ContentPlanningError as exc:
            manifest_refusal = str(exc)
        else:
            manifest_refusal = None

    source_by_path: dict[str, Path] = {}
    for relative, source in sources:
        canonical = safe_relative_path(relative).as_posix()
        if canonical in source_by_path:
            raise ContentPlanningError(
                f"Content-aware source path is duplicated: {canonical}"
            )
        source_by_path[canonical] = source
    manifest_by_path = {
        str(entry["path"]): entry
        for entry in (validated_manifest or {}).get("entries", [])
    }
    universe = sorted(set(source_by_path) | set(manifest_by_path))
    if not universe:
        raise ContentPlanningError("Content-aware path inventory is empty.")
    validate_distinct_paths([Path(path) for path in universe])
    selected = (
        universe
        if selected_paths is None
        else sorted(
            {
                safe_relative_path(relative).as_posix()
                for relative in selected_paths
            }
        )
    )
    if not selected or not set(selected).issubset(universe):
        raise ContentPlanningError(
            "Content-aware selected paths must be a non-empty subset of the inventory."
        )
    bound_operation_inputs = copy.deepcopy(operation_inputs or {})
    if not isinstance(bound_operation_inputs, dict):
        raise ContentPlanningError("Content-aware operation inputs are invalid.")

    previous_inputs = copy.deepcopy(
        (validated_manifest or {}).get("previous_inputs") or {}
    )
    runtime_creation_identity = managed_creation_identity()
    creation_identity = copy.deepcopy(
        (validated_manifest or {}).get("creation_identity")
        or runtime_creation_identity
    )
    try:
        validate_managed_creation_identity(creation_identity)
    except ValueError as exc:
        raise ContentPlanningError(
            "Content-aware creation identity binding is invalid."
        ) from exc
    creation_identity_mismatch = creation_identity != runtime_creation_identity
    requested_profile = str(inputs["profile"])
    input_conflicts = sorted(
        key
        for key, value in inputs.items()
        if key != "profile"
        and (key not in previous_inputs or previous_inputs.get(key) != value)
    )
    preserved_inputs = {
        key: copy.deepcopy(value)
        for key, value in sorted(previous_inputs.items())
        if key != "profile"
    }
    effective_inputs = (
        {**copy.deepcopy(previous_inputs), "profile": requested_profile}
        if previous_inputs
        else copy.deepcopy(inputs)
    )

    paths: list[dict[str, Any]] = []
    for path_text in universe:
        relative = Path(path_text)
        entry = manifest_by_path.get(path_text)
        source = source_by_path.get(path_text)
        after_metadata: dict[str, object] | None = None
        metadata_reasons: list[str] = []
        if source is None:
            after = ContentIdentity.absent()
        else:
            after, observed_source_metadata = regular_file_observation(source)
            after_metadata = source_metadata_contract(observed_source_metadata)
            try:
                require_supported_source_metadata(source, after_metadata)
            except ContentPlanningError as exc:
                metadata_reasons.append(str(exc))
        before, before_metadata, ancestors, current_reason = _observe_current_content(
            root,
            relative,
        )
        if current_reason:
            metadata_reasons.append(current_reason)
        if any(int(item["device"]) != root_device for item in ancestors):
            metadata_reasons.append(
                "UNSUPPORTED_METADATA: destination ancestors cross the project filesystem"
            )
        if creation_identity_mismatch:
            metadata_reasons.append(
                "UNSUPPORTED_METADATA: executing identity differs from the "
                "provenance-bound creation identity"
            )

        prior_ownership = str((entry or {}).get("ownership") or "unmanaged")
        creation_policy = str((entry or {}).get("creation_policy") or "")
        ownership_source = "unmanaged_diagnostic"
        policy_rule = "unresolved"
        selected_policy = active_policy
        base_metadata: dict[str, object] | None = None
        if entry is not None:
            base_metadata = copy.deepcopy(entry["source_metadata"])
            source_schema = (
                (validated_manifest or {}).get("migration") or {}
            ).get("source_schema")
            ownership_source = (
                "manifest_v2_preserved"
                if source_schema == "naos.upgrade.managed_content_manifest.v2"
                else "manifest_v1_preserved"
                if validated_manifest is not None
                else "manifest_unvalidated"
            )
            policy_rule = "manifest:" + str(entry["introduced_by_transaction"])
            selected_policy = provenance_policy or active_policy
        if validated_manifest is None or provenance_policy is None:
            base = ContentIdentity.unknown()
        else:
            if entry is None:
                base = ContentIdentity.absent()
                policy_result = classify_new_path(relative, active_policy.policy)
                prior_ownership = "unmanaged"
                creation_policy = policy_result["creation_policy"]
                ownership_source = "source_policy_new_path"
                policy_rule = policy_result["policy_id"]
                selected_policy = active_policy
            else:
                base_value = entry["base"]
                base = ContentIdentity(
                    "present",
                    kind=base_value["kind"],
                    mode=base_value["mode"],
                    size=base_value["size"],
                    sha256=base_value["sha256"],
                )
        base_metadata_sha256 = _normalized_metadata_sha256(
            base,
            base_metadata,
            creation_identity=creation_identity,
            normalize_creation_identity=True,
        )
        before_metadata_sha256 = _normalized_metadata_sha256(
            before,
            before_metadata,
            creation_identity=creation_identity,
            normalize_creation_identity=False,
        )
        after_metadata_sha256 = _normalized_metadata_sha256(
            after,
            after_metadata,
            creation_identity=creation_identity,
            normalize_creation_identity=True,
        )
        proposal = classify_content_state(
            _classification_identity(base, base_metadata_sha256),
            _classification_identity(before, before_metadata_sha256),
            _classification_identity(after, after_metadata_sha256),
        )
        if validated_manifest is None or provenance_policy is None:
            guarded = apply_ownership_guard(proposal, prior_ownership)
        else:
            guard_ownership = prior_ownership
            if entry is None and proposal == "PROPOSE_NEW_UPSTREAM_CREATE":
                guard_ownership = policy_result["ownership"]
            guarded = apply_ownership_guard(
                proposal,
                guard_ownership,
                creation_policy=creation_policy,
            )
        action = guarded["action"]
        if path_text not in selected:
            action = "PRESERVE_OUT_OF_SCOPE"
        elif metadata_reasons:
            action = "UNSUPPORTED_METADATA"
        preservation, mutation = _path_action_contract(action)
        ownership_after = str(guarded["ownership"])
        paths.append(
            {
                "path": path_text,
                "base": _identity_value(base, base_metadata_sha256),
                "before": _identity_value(before, before_metadata_sha256),
                "after": _identity_value(after, after_metadata_sha256),
                "base_metadata": base_metadata,
                "before_metadata": before_metadata,
                "after_metadata": after_metadata,
                "content_state": proposal,
                "ownership": {
                    "before": prior_ownership,
                    "after": ownership_after,
                    "source": ownership_source,
                    "creation_policy": creation_policy,
                },
                "source_policy": {
                    **_policy_binding(selected_policy),
                    "rule": policy_rule,
                },
                "preservation": preservation,
                "action": action,
                "mutation": mutation,
                "metadata_status": {
                    "status": "unsupported" if metadata_reasons else "supported",
                    "reason": "; ".join(metadata_reasons) if metadata_reasons else None,
                },
                "ancestor_identities": ancestors,
            }
        )

    normalized_checks = _normalized_fixed_checks(fixed_checks)
    status = _content_aware_status(paths, input_conflicts, normalized_checks)
    manifest_control = {
        "status": (
            (
                "valid_v2"
                if validated_manifest is not None
                and validated_manifest["migration"]["source_schema"]
                == "naos.upgrade.managed_content_manifest.v2"
                else "valid_v1_normalized"
            )
            if validated_manifest is not None and provenance_policy is not None
            else "diagnostic_only"
        ),
        "snapshot_sha256": (
            validated_manifest.get("snapshot_sha256")
            if validated_manifest is not None
            else None
        ),
        "source_schema": (
            validated_manifest["migration"]["source_schema"]
            if validated_manifest is not None
            else None
        ),
        "ownership_reclassified": False,
        "refusal": manifest_refusal,
    }
    control = {
        "schema": CONTENT_AWARE_PLAN_SCHEMA,
        "operation": operation,
        "status": status,
        "project": {
            "root_binding": str(root),
            "project_id": (
                validated_manifest.get("project_id")
                if validated_manifest is not None
                else None
            ),
            "scope_integrity_sha3_512": (
                validated_manifest.get("scope_integrity_sha3_512")
                if validated_manifest is not None
                else None
            ),
        },
        "profile": {
            "previous": previous_inputs.get("profile"),
            "requested": requested_profile,
            "preserved_inputs": preserved_inputs,
            "effective_inputs": effective_inputs,
            "input_conflicts": input_conflicts,
        },
        "request_inputs": copy.deepcopy(inputs),
        "selected_paths": selected,
        "operation_inputs": bound_operation_inputs,
        "checks": normalized_checks,
        "creation_identity": creation_identity,
        "source_policy": {
            "active": _policy_binding(active_policy),
            "provenance": (
                _policy_binding(provenance_policy)
                if provenance_policy is not None
                else None
            ),
        },
        "manifest": manifest_control,
        "paths": paths,
        "ownership_inference": "forbidden",
        "planning_mutated_target": False,
        "apply_requires_separate_digest_bound_invocation": True,
    }
    plan = {**control, "plan_sha256": canonical_sha256(control)}
    validate_content_aware_plan(plan, project_root=root)
    return plan


def validate_content_aware_plan(
    plan: dict[str, Any],
    *,
    project_root: Path,
) -> None:
    if not isinstance(plan, dict):
        raise ContentPlanningError("Content-aware plan shape is invalid.")
    legacy_base_keys = {
        "schema",
        "operation",
        "status",
        "project",
        "profile",
        "request_inputs",
        "creation_identity",
        "source_policy",
        "manifest",
        "paths",
        "ownership_inference",
        "planning_mutated_target",
        "apply_requires_separate_digest_bound_invocation",
        "plan_sha256",
    }
    if plan.get("schema") == LEGACY_CONTENT_AWARE_PLAN_SCHEMA:
        if frozenset(plan) not in {
            frozenset(legacy_base_keys),
            frozenset({*legacy_base_keys, "checks"}),
        }:
            raise ContentPlanningError("Legacy content-aware plan shape is invalid.")
        expected_legacy_digest = canonical_sha256(
            {key: value for key, value in plan.items() if key != "plan_sha256"}
        )
        if plan.get("plan_sha256") != expected_legacy_digest:
            raise ContentPlanningError("Legacy content-aware plan digest is invalid.")
        paths = plan.get("paths")
        if not isinstance(paths, list) or not paths or any(
            not isinstance(item, dict) or not isinstance(item.get("path"), str)
            for item in paths
        ):
            raise ContentPlanningError("Legacy content-aware path inventory is invalid.")
        normalized = copy.deepcopy(plan)
        normalized["schema"] = CONTENT_AWARE_PLAN_SCHEMA
        normalized.setdefault("checks", [])
        normalized["selected_paths"] = sorted(
            str(item["path"]) for item in paths
        )
        normalized["operation_inputs"] = {}
        normalized["plan_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in normalized.items()
                if key != "plan_sha256"
            }
        )
        validate_content_aware_plan(normalized, project_root=project_root)
        return
    expected_keys = {
        "schema",
        "operation",
        "status",
        "project",
        "profile",
        "request_inputs",
        "selected_paths",
        "operation_inputs",
        "checks",
        "creation_identity",
        "source_policy",
        "manifest",
        "paths",
        "ownership_inference",
        "planning_mutated_target",
        "apply_requires_separate_digest_bound_invocation",
        "plan_sha256",
    }
    if not isinstance(plan, dict) or set(plan) != expected_keys:
        raise ContentPlanningError("Content-aware plan shape is invalid.")
    if (
        plan.get("schema") != CONTENT_AWARE_PLAN_SCHEMA
        or plan.get("ownership_inference") != "forbidden"
        or plan.get("planning_mutated_target") is not False
        or plan.get("apply_requires_separate_digest_bound_invocation") is not True
        or not isinstance(plan.get("operation"), str)
        or not str(plan["operation"]).strip()
    ):
        raise ContentPlanningError("Content-aware plan control is invalid.")
    root = project_root.resolve(strict=True)
    project = plan.get("project")
    if (
        not isinstance(project, dict)
        or set(project)
        != {"root_binding", "project_id", "scope_integrity_sha3_512"}
        or project.get("root_binding") != str(root)
        or (
            project.get("project_id") is not None
            and not isinstance(project.get("project_id"), str)
        )
        or (
            project.get("scope_integrity_sha3_512") is not None
            and (
                not isinstance(project.get("scope_integrity_sha3_512"), str)
                or SHA3_512_RE.fullmatch(str(project["scope_integrity_sha3_512"]))
                is None
            )
        )
    ):
        raise ContentPlanningError("Content-aware project binding is invalid.")
    profile = plan.get("profile")
    if (
        not isinstance(profile, dict)
        or set(profile)
        != {
            "previous",
            "requested",
            "preserved_inputs",
            "effective_inputs",
            "input_conflicts",
        }
        or not isinstance(profile.get("requested"), str)
        or not isinstance(profile.get("preserved_inputs"), dict)
        or not isinstance(profile.get("effective_inputs"), dict)
        or not isinstance(profile.get("input_conflicts"), list)
        or profile.get("effective_inputs", {}).get("profile")
        != profile.get("requested")
    ):
        raise ContentPlanningError("Content-aware profile binding is invalid.")
    if not isinstance(plan.get("request_inputs"), dict):
        raise ContentPlanningError("Content-aware request inputs are invalid.")
    selected_paths = plan.get("selected_paths")
    if (
        not isinstance(selected_paths, list)
        or not selected_paths
        or any(
            not isinstance(path, str)
            for path in selected_paths
        )
        or selected_paths != sorted(set(selected_paths))
        or any(safe_relative_path(path).as_posix() != path for path in selected_paths)
    ):
        raise ContentPlanningError("Content-aware selected paths are invalid.")
    if not isinstance(plan.get("operation_inputs"), dict):
        raise ContentPlanningError("Content-aware operation inputs are invalid.")
    checks = _normalized_fixed_checks(plan.get("checks"))
    if plan.get("checks") != checks:
        raise ContentPlanningError(
            "Content-aware fixed checks are not sorted and unique."
        )
    creation_identity = plan.get("creation_identity")
    try:
        validate_managed_creation_identity(creation_identity)
    except ValueError as exc:
        raise ContentPlanningError(
            "Content-aware creation identity is invalid."
        ) from exc
    assert isinstance(creation_identity, dict)

    def validate_policy_binding(value: Any, *, nullable: bool = False) -> None:
        if nullable and value is None:
            return
        if (
            not isinstance(value, dict)
            or set(value)
            != {"snapshot_id", "binding_sha256", "snapshot_sha256"}
            or not isinstance(value.get("snapshot_id"), str)
            or not value.get("snapshot_id")
            or not isinstance(value.get("binding_sha256"), str)
            or SHA256_RE.fullmatch(str(value["binding_sha256"])) is None
            or not isinstance(value.get("snapshot_sha256"), str)
            or SHA256_RE.fullmatch(str(value["snapshot_sha256"])) is None
        ):
            raise ContentPlanningError("Content-aware policy binding is invalid.")

    policies = plan.get("source_policy")
    if not isinstance(policies, dict) or set(policies) != {"active", "provenance"}:
        raise ContentPlanningError("Content-aware policy inventory is invalid.")
    validate_policy_binding(policies["active"])
    validate_policy_binding(policies["provenance"], nullable=True)
    manifest = plan.get("manifest")
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "status",
            "snapshot_sha256",
            "source_schema",
            "ownership_reclassified",
            "refusal",
        }
        or manifest.get("status")
        not in {"valid_v1_normalized", "valid_v2", "diagnostic_only"}
        or manifest.get("ownership_reclassified") is not False
    ):
        raise ContentPlanningError("Content-aware manifest binding is invalid.")
    if manifest["status"] in {"valid_v1_normalized", "valid_v2"}:
        expected_source_schema = (
            "naos.upgrade.managed_content_manifest.v2"
            if manifest["status"] == "valid_v2"
            else "naos.upgrade.managed_content_manifest.v1"
        )
        if (
            not isinstance(manifest.get("snapshot_sha256"), str)
            or SHA256_RE.fullmatch(str(manifest["snapshot_sha256"])) is None
            or manifest.get("source_schema") != expected_source_schema
            or policies["provenance"] is None
            or manifest.get("refusal") is not None
        ):
            raise ContentPlanningError(
                "Content-aware validated manifest binding is invalid."
            )
    elif not isinstance(manifest.get("refusal"), str) or not str(
        manifest["refusal"]
    ).strip():
        raise ContentPlanningError(
            "Content-aware diagnostic manifest refusal is invalid."
        )
    paths = plan.get("paths")
    if not isinstance(paths, list) or not paths:
        raise ContentPlanningError("Content-aware path inventory is invalid.")
    expected_path_keys = {
        "path",
        "base",
        "before",
        "after",
        "base_metadata",
        "before_metadata",
        "after_metadata",
        "content_state",
        "ownership",
        "source_policy",
        "preservation",
        "action",
        "mutation",
        "metadata_status",
        "ancestor_identities",
    }
    observed_paths: list[Path] = []
    for item in paths:
        if not isinstance(item, dict) or set(item) != expected_path_keys:
            raise ContentPlanningError("Content-aware path shape is invalid.")
        relative = safe_relative_path(str(item.get("path") or ""))
        if relative.as_posix() != item.get("path"):
            raise ContentPlanningError("Content-aware path is not canonical.")
        base, base_metadata_sha256 = _identity_from_value(
            item.get("base"),
            label="base",
        )
        before, before_metadata_sha256 = _identity_from_value(
            item.get("before"),
            label="before",
        )
        after, after_metadata_sha256 = _identity_from_value(
            item.get("after"),
            label="after",
        )
        for metadata_name in ("base_metadata", "after_metadata"):
            metadata = item.get(metadata_name)
            if metadata is not None:
                try:
                    validate_source_metadata_contract(metadata)
                except ValueError as exc:
                    raise ContentPlanningError(
                        f"Content-aware {metadata_name} is invalid: {relative}"
                    ) from exc
        before_metadata = item.get("before_metadata")
        if before_metadata is not None:
            try:
                validate_created_metadata_identity(
                    before_metadata,
                    expected_type="regular_file",
                )
            except ValueError as exc:
                raise ContentPlanningError(
                    f"Content-aware before metadata is invalid: {relative}"
                ) from exc
        expected_metadata_sha256s = (
            _normalized_metadata_sha256(
                base,
                item.get("base_metadata"),
                creation_identity=creation_identity,
                normalize_creation_identity=True,
            ),
            _normalized_metadata_sha256(
                before,
                before_metadata,
                creation_identity=creation_identity,
                normalize_creation_identity=False,
            ),
            _normalized_metadata_sha256(
                after,
                item.get("after_metadata"),
                creation_identity=creation_identity,
                normalize_creation_identity=True,
            ),
        )
        if expected_metadata_sha256s != (
            base_metadata_sha256,
            before_metadata_sha256,
            after_metadata_sha256,
        ):
            raise ContentPlanningError(
                f"Content-aware metadata identity binding is invalid: {relative}"
            )
        proposal = classify_content_state(
            _classification_identity(base, base_metadata_sha256),
            _classification_identity(before, before_metadata_sha256),
            _classification_identity(after, after_metadata_sha256),
        )
        if item.get("content_state") != proposal:
            raise ContentPlanningError(
                f"Content-aware classifier binding is invalid: {relative}"
            )
        ownership = item.get("ownership")
        if (
            not isinstance(ownership, dict)
            or set(ownership)
            != {"before", "after", "source", "creation_policy"}
            or ownership.get("before") not in OWNERSHIP_CLASSES
            or ownership.get("after") not in OWNERSHIP_CLASSES
            or not isinstance(ownership.get("source"), str)
            or not isinstance(ownership.get("creation_policy"), str)
        ):
            raise ContentPlanningError(
                f"Content-aware ownership binding is invalid: {relative}"
            )
        if str(ownership["source"]).startswith("manifest") and (
            ownership["before"] != ownership["after"]
        ):
            raise ContentPlanningError(
                f"Prior ownership was reclassified: {relative}"
            )
        path_policy = item.get("source_policy")
        if not isinstance(path_policy, dict) or set(path_policy) != {
            "snapshot_id",
            "binding_sha256",
            "snapshot_sha256",
            "rule",
        }:
            raise ContentPlanningError(
                f"Content-aware path policy binding is invalid: {relative}"
            )
        validate_policy_binding(
            {key: path_policy[key] for key in path_policy if key != "rule"}
        )
        if not isinstance(path_policy.get("rule"), str) or not path_policy["rule"]:
            raise ContentPlanningError(
                f"Content-aware path policy rule is invalid: {relative}"
            )
        metadata_status = item.get("metadata_status")
        if (
            not isinstance(metadata_status, dict)
            or set(metadata_status) != {"status", "reason"}
            or metadata_status.get("status") not in {"supported", "unsupported"}
            or (
                metadata_status.get("status") == "unsupported"
                and not isinstance(metadata_status.get("reason"), str)
            )
        ):
            raise ContentPlanningError(
                f"Content-aware metadata status is invalid: {relative}"
            )
        if proposal == "REFUSE_PROVENANCE":
            guarded = apply_ownership_guard(proposal, str(ownership["before"]))
        elif proposal == "PROPOSE_NEW_UPSTREAM_CREATE":
            guarded = apply_ownership_guard(
                proposal,
                str(ownership["after"]),
                creation_policy=str(ownership["creation_policy"]),
            )
        else:
            guarded = apply_ownership_guard(
                proposal,
                str(ownership["before"]),
                creation_policy=str(ownership["creation_policy"]),
            )
        expected_action = (
            "PRESERVE_OUT_OF_SCOPE"
            if relative.as_posix() not in selected_paths
            else "UNSUPPORTED_METADATA"
            if metadata_status["status"] == "unsupported"
            else guarded["action"]
        )
        expected_preservation, expected_mutation = _path_action_contract(
            expected_action
        )
        if (
            item.get("action") != expected_action
            or item.get("preservation") != expected_preservation
            or item.get("mutation") != expected_mutation
        ):
            raise ContentPlanningError(
                f"Content-aware action binding is invalid: {relative}"
            )
        ancestors = item.get("ancestor_identities")
        if not isinstance(ancestors, list):
            raise ContentPlanningError(
                f"Content-aware ancestor inventory is invalid: {relative}"
            )
        observed_paths.append(relative)
    if (
        [path.as_posix() for path in observed_paths]
        != sorted(path.as_posix() for path in observed_paths)
        or len(set(observed_paths)) != len(observed_paths)
    ):
        raise ContentPlanningError(
            "Content-aware paths are not sorted and unique."
        )
    validate_distinct_paths(observed_paths)
    if not set(selected_paths).issubset(
        {path.as_posix() for path in observed_paths}
    ):
        raise ContentPlanningError(
            "Content-aware selected paths are outside the path inventory."
        )
    expected_status = _content_aware_status(
        paths,
        list(profile["input_conflicts"]),
        checks,
    )
    if plan.get("status") != expected_status:
        raise ContentPlanningError("Content-aware plan status is invalid.")
    expected_digest = canonical_sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    if plan.get("plan_sha256") != expected_digest:
        raise ContentPlanningError("Content-aware plan digest is invalid.")


def revalidate_content_aware_plan(
    project_root: Path,
    sources: list[tuple[Path, Path]],
    *,
    source_policy_path: Path,
    plan: dict[str, Any],
    manifest_snapshot: dict[str, Any] | None,
    provenance_refusal: str | None = None,
    fixed_checks: list[dict[str, str]] | None = None,
) -> None:
    rebuilt = build_content_aware_plan(
        project_root,
        sources,
        source_policy_path=source_policy_path,
        operation=str(plan.get("operation") or ""),
        inputs=copy.deepcopy(plan.get("request_inputs") or {}),
        manifest_snapshot=manifest_snapshot,
        provenance_refusal=provenance_refusal,
        fixed_checks=fixed_checks,
        selected_paths=[Path(path) for path in plan.get("selected_paths") or []],
        operation_inputs=copy.deepcopy(plan.get("operation_inputs") or {}),
    )
    if rebuilt != plan:
        raise ContentPlanningError(
            "Content-aware plan or target/source/provenance state changed before apply."
        )
