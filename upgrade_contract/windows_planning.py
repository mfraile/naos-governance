"""Read-only, Windows-native managed-content planning.

No existing-file mutation authority is derived from an unvalidated POSIX
manifest. Existing paths require a validated Windows base and ownership record.
Local record integrity is not cryptographic author authentication.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Mapping


from .canonical import canonical_sha256
from .planner import _validate_source_policy, apply_ownership_guard, classify_content_state, classify_new_path
from .windows_handles import UnsafeWindowsPath, WindowsHandleError, WindowsHandles
from .windows_observation import _parts, _relative_parts
from .windows_backend import _metadata_digest
from .windows_provenance import (ValidatedWindowsProvenance,
                                 load_windows_provenance, strict_policy_load,
                                 MAX_BASE_ARCHIVE_BYTES)


SCHEMA = "naos.upgrade.windows_content_plan.v1"
OBSERVATION_SCHEMA = "naos.upgrade.windows_content_observation.v1"
_MISSING_LEAF = 0xC0000034
_CHUNK = 1024 * 1024


class WindowsPlanningError(ValueError):
    """An exact Windows plan or its inputs failed validation."""


@dataclass(frozen=True)
class WindowsContentIdentity:
    presence: str
    kind: str | None = None
    size_decimal: str | None = None
    sha256: str | None = None
    metadata_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.presence not in {"present", "absent", "unknown"}:
            raise WindowsPlanningError("Invalid Windows content presence")
        fields = (self.kind, self.size_decimal, self.sha256, self.metadata_sha256)
        if self.presence == "present":
            if (self.kind != "file" or not isinstance(self.size_decimal, str)
                    or not self.size_decimal.isdecimal() or str(int(self.size_decimal)) != self.size_decimal
                    or any(not isinstance(x, str) or len(x) != 64
                           or any(c not in "0123456789abcdef" for c in x)
                           for x in (self.sha256, self.metadata_sha256))):
                raise WindowsPlanningError("Incomplete Windows file content identity")
        elif any(field is not None for field in fields):
            raise WindowsPlanningError("Absent or unknown Windows identity has content")

    def comparison_key(self) -> tuple[str, str, str, str]:
        if self.presence != "present":
            raise WindowsPlanningError("Only present content can be compared")
        return (self.kind, self.size_decimal, self.sha256, self.metadata_sha256)  # type: ignore[return-value]

    def record(self) -> dict[str, str | None]:
        return {"presence": self.presence, "kind": self.kind,
                "size_decimal": self.size_decimal, "sha256": self.sha256,
                "metadata_sha256": self.metadata_sha256}


def _content(observation: Mapping[str, Any] | None) -> WindowsContentIdentity:
    if observation is None:
        return WindowsContentIdentity("absent")
    if observation.get("schema") != OBSERVATION_SCHEMA:
        raise WindowsPlanningError("Wrong Windows observation schema")
    return WindowsContentIdentity("present", "file", observation["size_decimal"],
                                  observation["sha256"], observation["comparison_metadata_sha256"])


def _comparison_metadata_digest(info: Any, security: Any) -> str:
    """Stable source-policy metadata for B/C/N; excludes transient file times."""
    digest = hashlib.sha256(b"naos.windows.content_policy_metadata.v1\0")
    digest.update(info.attributes.to_bytes(4, "little"))
    digest.update(b"\x01" if security.protected else b"\x00")
    for value in (security.owner_sid, security.group_sid, security.dacl):
        digest.update(len(value).to_bytes(4, "little"))
        digest.update(value)
    return digest.hexdigest()


def _identity(info: Any) -> dict[str, str]:
    if len(info.file_id) != 16 or not 0 <= info.volume < 2**64:
        raise UnsafeWindowsPath("Invalid native Windows file identity")
    return {"volume_serial_hex": f"{info.volume:016x}", "file_id_hex": info.file_id.hex()}


class WindowsReadObserver:
    """Observe one leaf through pinned one-component handles, including absence."""

    def __init__(self, handles: Any):
        self.handles = handles

    @classmethod
    def native(cls) -> "WindowsReadObserver":
        return cls(WindowsHandles())

    def root_identity(self, root: str) -> dict[str, str]:
        """Bind a project root by opening the drive and each component held."""
        drive, parts = _parts(root)
        with ExitStack() as stack:
            parent = stack.enter_context(self.handles.open_root(drive))
            for component in parts:
                parent = stack.enter_context(self.handles.open_child(parent, component,
                                             kind="directory", pin_for_read=True))
            info = parent.info()
            if not info.directory:
                raise UnsafeWindowsPath("Project root is not a directory")
            return _identity(info)

    def observe(self, root: str, relative: str, *, capture_bytes: bool = False) -> tuple[dict[str, Any] | None, bytes | None]:
        drive, root_parts = _parts(root)
        leaf_parts = _relative_parts(relative)
        if not leaf_parts:
            raise UnsafeWindowsPath("Managed path requires a leaf")
        with ExitStack() as stack:
            parent = stack.enter_context(self.handles.open_root(drive))
            held = [("", parent)]
            all_dirs = root_parts + leaf_parts[:-1]
            missing_suffix: tuple[str, ...] = ()
            for index, component in enumerate(all_dirs):
                try:
                    child = self.handles.open_child(parent, component,
                                      kind="directory", pin_for_read=True)
                except WindowsHandleError as exc:
                    if (index >= len(root_parts) and exc.operation == "NtCreateFile"
                            and exc.ntstatus == _MISSING_LEAF):
                        missing_suffix = all_dirs[index:] + leaf_parts[-1:]
                        break
                    raise
                parent = stack.enter_context(child)
                held.append((component, parent))
            ancestors = []
            for name, handle in held:
                info = handle.info()
                if not info.directory:
                    raise UnsafeWindowsPath("Managed ancestor is not a directory")
                ancestors.append({"name": name, **_identity(info)})
            if missing_suffix:
                for (name, handle), expected in zip(held, ancestors):
                    info = handle.info()
                    if not info.directory or {"name": name, **_identity(info)} != expected:
                        raise UnsafeWindowsPath("Managed ancestor changed during absence check")
                return ({"schema": OBSERVATION_SCHEMA, "presence": "absent",
                         "path": relative, "ancestors": ancestors,
                         "missing_suffix": list(missing_suffix)}, None)
            try:
                leaf = stack.enter_context(self.handles.open_child(parent, leaf_parts[-1],
                                               kind="file", pin_for_read=True))
            except WindowsHandleError as exc:
                if exc.operation == "NtCreateFile" and exc.ntstatus == _MISSING_LEAF:
                    for (name, handle), expected in zip(held, ancestors):
                        info = handle.info()
                        if not info.directory or {"name": name, **_identity(info)} != expected:
                            raise UnsafeWindowsPath("Managed ancestor changed during absence check")
                    return ({"schema": OBSERVATION_SCHEMA, "presence": "absent",
                             "path": relative, "ancestors": ancestors,
                             "missing_suffix": [leaf_parts[-1]]}, None)
                raise
            before = leaf.info()
            if before.directory or before.links != 1 or before.size < 0:
                raise UnsafeWindowsPath("Managed leaf is not a single-link regular file")
            if capture_bytes and before.size > MAX_BASE_ARCHIVE_BYTES:
                raise UnsafeWindowsPath("Captured Windows source exceeds the 64 MiB limit")
            security_before = leaf.security()
            leaf.seek(0)
            digest = hashlib.sha256()
            chunks = [] if capture_bytes else None
            count = 0
            while True:
                block = leaf.read(_CHUNK)
                if not block:
                    break
                count += len(block)
                if count > before.size:
                    raise UnsafeWindowsPath("Managed leaf grew while read")
                digest.update(block)
                if chunks is not None:
                    chunks.append(block)
            after = leaf.info()
            security_after = leaf.security()
            if count != before.size or before != after or security_before != security_after:
                raise UnsafeWindowsPath("Managed leaf changed while read")
            for (name, handle), expected in zip(held, ancestors):
                info = handle.info()
                if not info.directory or {"name": name, **_identity(info)} != expected:
                    raise UnsafeWindowsPath("Managed ancestor changed while read")
            observation = {
                "schema": OBSERVATION_SCHEMA, "presence": "present", "path": relative,
                "identity": _identity(before), "ancestors": ancestors,
                "size_decimal": str(before.size), "sha256": digest.hexdigest(),
                "metadata_sha256": _metadata_digest(before, security_before),
                "comparison_metadata_sha256": _comparison_metadata_digest(before, security_before),
                "attributes": before.attributes,
                "file_times_100ns": {"created": str(before.created_time),
                                     "modified": str(before.modified_time),
                                     "changed": str(before.changed_time)},
                "security": {"owner_sid_sha256": hashlib.sha256(security_before.owner_sid).hexdigest(),
                             "group_sid_sha256": hashlib.sha256(security_before.group_sid).hexdigest(),
                             "dacl_sha256": hashlib.sha256(security_before.dacl).hexdigest(),
                             "dacl_protected": security_before.protected},
            }
            return observation, b"".join(chunks) if chunks is not None else None


def _policy(raw: bytes) -> tuple[str, str, dict[str, Any]]:
    bundle = strict_policy_load(raw)
    if (not isinstance(bundle, dict) or bundle.get("schema") != "naos.upgrade.source_policy_bundle.v1"
            or not isinstance(bundle.get("active_snapshot"), str)
            or not isinstance(bundle.get("snapshots"), list)):
        raise WindowsPlanningError("Windows planner requires versioned source policy bundle")
    seen_ids: set[str] = set()
    seen_bindings: set[str] = set()
    selected = None
    for record in bundle["snapshots"]:
        if not isinstance(record, dict) or set(record) != {"id", "sha256_aliases", "policy"}:
            raise WindowsPlanningError("Invalid source policy snapshot record")
        snapshot_id, aliases = record["id"], record["sha256_aliases"]
        if (not isinstance(snapshot_id, str) or not snapshot_id or snapshot_id in seen_ids
                or not isinstance(aliases, list) or len(aliases) != len(set(aliases))
                or any(not isinstance(x, str) or len(x) != 64 or
                       any(c not in "0123456789abcdef" for c in x) for x in aliases)):
            raise WindowsPlanningError("Invalid or duplicate source policy binding")
        seen_ids.add(snapshot_id)
        policy = _validate_source_policy(record["policy"], snapshot_id=snapshot_id)
        digest = canonical_sha256({"snapshot_id": snapshot_id, "policy": policy})
        bindings = set(aliases) | {digest}
        if bindings & seen_bindings:
            raise WindowsPlanningError("Ambiguous source policy digest binding")
        seen_bindings.update(bindings)
        if snapshot_id == bundle["active_snapshot"]:
            selected = (snapshot_id, digest, policy)
    if selected is None:
        raise WindowsPlanningError("Active source policy snapshot unavailable")
    return selected


def _logical_policy_path(relative: str) -> Path:
    # POSIX policy spells paths with '/'; Windows observations use '\'.
    parts = _relative_parts(relative)
    return Path(*parts)


def _validate_plan_digest(plan: Mapping[str, Any]) -> None:
    if plan.get("schema") != SCHEMA or not isinstance(plan.get("digest_sha256"), str):
        raise WindowsPlanningError("Wrong Windows plan schema")
    body = {key: value for key, value in plan.items() if key != "digest_sha256"}
    if canonical_sha256(body) != plan["digest_sha256"]:
        raise WindowsPlanningError("Windows plan digest mismatch")


def build_windows_plan(observer: Any, *, project_root: str, candidate_root: str,
                       policy_root: str, policy_relative: str,
                       paths: tuple[str, ...],
                       provenance_reader: Any | None = None) -> dict[str, Any]:
    """Build B/C/N from validated Windows provenance; never infer prior ownership."""
    if (any(not isinstance(p, str) for p in paths)
            or len(paths) != len(set(paths))
            or len(paths) != len({p.casefold() for p in paths})):
        raise WindowsPlanningError("Paths must be unique and nonempty")
    for path in paths:
        _relative_parts(path)
    policy_observation, raw_policy = observer.observe(policy_root, policy_relative,
                                                       capture_bytes=True)
    if policy_observation is None or policy_observation["presence"] != "present" or raw_policy is None:
        raise WindowsPlanningError("Source policy is absent")
    snapshot_id, snapshot_digest, policy = _policy(raw_policy)
    provenance: ValidatedWindowsProvenance | None = None
    if provenance_reader is not None:
        provenance = load_windows_provenance(
            provenance_reader, root_identity=observer.root_identity(project_root),
            source_policy_raw=raw_policy)
        if provenance.active_policy_sha256 != snapshot_digest:
            raise WindowsPlanningError("Active policy and provenance catalog differ")
    universe = tuple(sorted(set(paths) | (set(provenance.entries) if provenance else set())))
    if not universe:
        raise WindowsPlanningError("Empty Windows path universe")
    # Conservative refusal only: casefold is not proof of native identity.
    # Never manufacture B=absent from a different spelling of known history.
    if len(universe) != len({path.casefold() for path in universe}):
        raise WindowsPlanningError("Selected path aliases historical managed spelling")
    project_identity = provenance.root_identity if provenance else None
    root_depth = len(_parts(project_root)[1])
    entries = provenance.entries if provenance else {}
    rows = []
    for path in universe:
        current, _ = observer.observe(project_root, path)
        candidate, _ = observer.observe(candidate_root, path)
        if current is None or candidate is None:
            raise WindowsPlanningError("Observer returned no presence record")
        if any(observed.get("path") != path or observed.get("schema") != OBSERVATION_SCHEMA
               or observed.get("presence") not in {"present", "absent"}
               for observed in (current, candidate)):
            raise WindowsPlanningError("Observation is not bound to the requested path")
        if project_identity is not None:
            ancestors = current.get("ancestors")
            if (not isinstance(ancestors, list) or len(ancestors) <= root_depth
                    or not isinstance(ancestors[root_depth], dict)
                    or {key: ancestors[root_depth].get(key)
                        for key in ("volume_serial_hex", "file_id_hex")} != project_identity):
                raise WindowsPlanningError("Current observation differs from enrolled project root")
        before, after = _content(current if current["presence"] == "present" else None), _content(candidate if candidate["presence"] == "present" else None)
        entry = entries.get(path)
        if provenance is None:
            base = WindowsContentIdentity("unknown")
        elif entry is None:
            base = WindowsContentIdentity("absent")
        else:
            base = WindowsContentIdentity("present", **entry["content"])
        if base.presence == before.presence == after.presence == "absent":
            raise WindowsPlanningError("All-absent path is outside plan universe")
        proposal = classify_content_state(base, before, after)
        policy_rule = classify_new_path(_logical_policy_path(path), policy)
        conditional_new_path = None
        if provenance is None and before.presence == "absent" and after.presence == "present":
            # This is only a conditional classification: an absent file may
            # have been deliberately deleted after an earlier managed install.
            # The source policy cannot prove B=absent or grant ownership.
            conditional_new_path = apply_ownership_guard(
                "PROPOSE_NEW_UPSTREAM_CREATE", policy_rule["ownership"],
                creation_policy=policy_rule["creation_policy"])["action"]
        if provenance is None:
            action = "REFUSE_PROVENANCE"
            ownership_source = "unvalidated_windows_provenance"
            guarded_ownership = None
        else:
            ownership = entry["ownership"] if entry else policy_rule["ownership"]
            creation_policy = entry["creation_policy"] if entry else policy_rule["creation_policy"]
            guarded = apply_ownership_guard(proposal, ownership,
                                            creation_policy=creation_policy)
            action = guarded["action"]
            guarded_ownership = guarded["ownership"]
            ownership_source = "windows_manifest_preserved" if entry else "source_policy_new_path"
        if path not in paths:
            action = "PRESERVE_OUT_OF_SCOPE"
        elif (after.presence == "present" and after.size_decimal is not None
              and int(after.size_decimal) > MAX_BASE_ARCHIVE_BYTES
              and action in {"CREATE_NEW_UPSTREAM", "CREATE_NEW_ADOPTER_OWNED",
                             "CREATE_CONFIGURATION_CHOICE", "CREATE_MANAGED_CACHE",
                             "CREATE_IMMUTABLE_REPORT", "UPDATE_FROM_UPSTREAM"}):
            action = "REFUSE_UNSUPPORTED_BASE_ARCHIVE_SIZE"
        rows.append({"path": path, "base": base.record(), "before": before.record(),
                     "after": after.record(), "before_observation": current,
                     "after_observation": candidate, "content_state": proposal,
                     "action": action, "conditional_if_verified_base_absent": conditional_new_path,
                     "ownership_source": ownership_source,
                     "ownership": guarded_ownership,
                     "policy_rule": policy_rule})
    body = {"schema": SCHEMA, "project_root": project_root,
            "candidate_root": candidate_root, "policy_root": policy_root,
            "policy_relative": policy_relative, "policy_observation": policy_observation,
            "policy_raw_sha256": hashlib.sha256(raw_policy).hexdigest(),
            "policy_snapshot_id": snapshot_id, "policy_snapshot_sha256": snapshot_digest,
            "provenance_manifest_sha256": provenance.manifest_sha256 if provenance else None,
            "provenance_project_id": provenance.project_id if provenance else None,
            "project_root_identity": project_identity,
            "selected_paths": list(paths),
            "paths": rows}
    return {**body, "digest_sha256": canonical_sha256(body)}


def revalidate_windows_plan(observer: Any, plan: Mapping[str, Any], *,
                            provenance_reader: Any | None = None) -> None:
    """Refuse changed plan, policy, source, target, or held ancestor identity."""
    _validate_plan_digest(plan)
    try:
        raw_paths = tuple(plan["selected_paths"])
        rebuilt = build_windows_plan(observer, project_root=plan["project_root"],
                                     candidate_root=plan["candidate_root"],
                                     policy_root=plan["policy_root"],
                                     policy_relative=plan["policy_relative"], paths=raw_paths,
                                     provenance_reader=provenance_reader)
    except (KeyError, TypeError, ValueError) as exc:
        raise WindowsPlanningError("Windows plan cannot be revalidated") from exc
    if rebuilt != plan:
        raise WindowsPlanningError("Windows plan inputs changed")
