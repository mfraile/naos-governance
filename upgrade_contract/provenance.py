"""Explicit, capability-scoped provenance for NAOS-generated project state.

This module never infers ownership from repository content, paths, Git history,
headers, or template equality.  A previously absent namespace receives
authority only through a separate digest-confirmed enrollment operation.
"""

from __future__ import annotations

import os
import re
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - managed mutation is already unsupported.
    fcntl = None  # type: ignore[assignment]

from .canonical import (
    canonical_bytes,
    canonical_sha256,
    canonical_sha3_512,
    loads_strict_json,
)
from .security import (
    ContentPathError,
    observe_created_directory_metadata_fd,
    safe_relative_path,
    validate_created_metadata_identity,
    validate_source_metadata_contract,
)
from .transaction import (
    TransactionPrimitiveError,
    fsync_directory,
    load_managed_content_manifest_snapshot,
    rename_no_replace,
    rename_no_replace_at,
)


OWNER_SCHEMA = "naos.upgrade.control_root_owner.v1"
SCOPE_SCHEMA = "naos.upgrade.capability_scope.v1"
CANONICALIZATION = "rfc8785"
CONTROL_ROOT = Path(".naos/upgrade-v1")
STATE_PARENT_RELATIVE = CONTROL_ROOT / "state"
CONTEXT_RELATIVE = STATE_PARENT_RELATIVE / "repository-intelligence"
OWNER_RELATIVE = CONTROL_ROOT / "OWNER.json"
SCOPE_RELATIVE = CONTROL_ROOT / "provenance/scopes/repository-intelligence.json"
SCOPE_ID = "repository-intelligence"
CAPABILITY_ID = "CAP-LOCAL-CONTEXT-INDEX"
LOCK_RELATIVE = CONTROL_ROOT / "locks/repository-intelligence.lock"
CONTROL_ENROLLMENT_LOCK_RELATIVE = CONTROL_ROOT / "locks/control-root-enrollment.lock"
TRANSACTIONS_RELATIVE = CONTROL_ROOT / "transactions/repository-intelligence"
MANAGED_CONTENT_ROOT_RELATIVE = CONTROL_ROOT / "managed-content"
MANAGED_CONTENT_SCOPE_RELATIVE = MANAGED_CONTENT_ROOT_RELATIVE / "scope.json"
MANAGED_CONTENT_LOCK_RELATIVE = MANAGED_CONTENT_ROOT_RELATIVE / "lock"
MANAGED_CONTENT_TRANSACTIONS_RELATIVE = MANAGED_CONTENT_ROOT_RELATIVE / "transactions"
MANAGED_CONTENT_STATE_RELATIVE = MANAGED_CONTENT_ROOT_RELATIVE / "state"
MANAGED_CONTENT_MANIFEST_RELATIVE = MANAGED_CONTENT_STATE_RELATIVE / "manifest.json"
MANAGED_CONTENT_BASES_RELATIVE = MANAGED_CONTENT_STATE_RELATIVE / "bases"
MANAGED_CONTENT_RECEIPTS_RELATIVE = MANAGED_CONTENT_STATE_RELATIVE / "receipts"
MANAGED_CONTENT_SCOPE_SCHEMA = "naos.upgrade.managed_content_scope.v1"
GREENFIELD_INTENT_SCHEMA = "naos.init.greenfield_root_intent.v1"
GREENFIELD_ROOT_IDENTITY_SCHEMA = "naos.init.greenfield_root_identity.v1"
GREENFIELD_ROOT_MARKER_SCHEMA = "naos.init.greenfield_root_marker.v1"
GREENFIELD_ROOT_MARKER = ".naos-greenfield-intent.json"
GREENFIELD_CONTROL_PREFIX = ".naos-init-v1."
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LEGACY_MANAGED_CONTENT_RELATIVES = (
    CONTROL_ROOT / "provenance/scopes/managed-content.json",
    CONTROL_ROOT / "locks/managed-content.lock",
    CONTROL_ROOT / "transactions/managed-content",
    CONTROL_ROOT / "state/managed-content",
)


class ProvenanceError(RuntimeError):
    """Raised when capability provenance is absent, unsafe, or inconsistent."""


@dataclass(frozen=True)
class ScopeInspection:
    status: str
    project_id: str | None
    owner_integrity: str | None
    scope_integrity: str | None
    governed_root: str
    enrollment_project_id: str | None = None
    refusal: str | None = None

    @property
    def activation_eligible(self) -> bool:
        return self.status == "valid"

    def plan_gate(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "activation_eligible": self.activation_eligible,
            "project_id": self.project_id,
            "owner_path": OWNER_RELATIVE.as_posix() if self.status == "valid" else None,
            "owner_integrity_sha3_512": self.owner_integrity,
            "scope_path": SCOPE_RELATIVE.as_posix() if self.status == "valid" else None,
            "scope_integrity_sha3_512": self.scope_integrity,
            "governed_root": self.governed_root,
            "enrollment_project_id": self.enrollment_project_id,
            "legacy_bootstrap_allowed": False,
            "ownership_inference": "forbidden",
            "refusal": self.refusal,
        }


@dataclass(frozen=True)
class ManagedContentScopeInspection:
    status: str
    project_id: str | None
    owner_integrity: str | None
    scope_integrity: str | None
    refusal: str | None = None
    source_policy_sha256: str | None = None

    @property
    def activation_eligible(self) -> bool:
        return self.status == "valid"


@dataclass(frozen=True)
class ManagedContentManifestInspection:
    status: str
    project_id: str | None
    scope_integrity: str | None
    source_policy_sha256: str | None
    snapshot: dict[str, Any] | None = None
    refusal: str | None = None

    @property
    def apply_eligible(self) -> bool:
        return self.status in {"valid_v1_normalized", "valid_v2"} and self.snapshot is not None


@dataclass
class GreenfieldRootSession:
    """Descriptor-bound authority for one exact greenfield root publication."""

    project_root: Path
    parent_path: Path
    target_name: str
    control_name: str
    control_entry_name: str
    parent_descriptor: int
    control_descriptor: int
    root_descriptor: int
    lock_descriptor: int
    intent: dict[str, Any]
    marker_bytes: bytes
    root_identity: dict[str, Any]
    state: str
    cleanup_anchor_name: str | None = None
    cleanup_anchor_descriptor: int | None = None
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        lock_descriptors = {
            descriptor
            for descriptor in (
                self.lock_descriptor,
                self.cleanup_anchor_descriptor,
            )
            if descriptor is not None
        }
        if fcntl is not None:
            for descriptor in lock_descriptors:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
        descriptors = {
            self.lock_descriptor,
            self.root_descriptor,
            self.control_descriptor,
            self.parent_descriptor,
        }
        if self.cleanup_anchor_descriptor is not None:
            descriptors.add(self.cleanup_anchor_descriptor)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> "GreenfieldRootSession":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _integrity_payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    payload.pop("integrity", None)
    return payload


def _with_integrity(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["integrity"] = {
        "algorithm": "sha3-512",
        "canonicalization": CANONICALIZATION,
        "scope": "object_without_integrity",
        "value": canonical_sha3_512(result),
    }
    return result


def _validate_integrity(value: dict[str, Any], *, label: str) -> str:
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {
        "algorithm",
        "canonicalization",
        "scope",
        "value",
    }:
        raise ProvenanceError(f"{label} integrity object is missing or malformed.")
    if integrity.get("algorithm") != "sha3-512" or integrity.get("canonicalization") != CANONICALIZATION:
        raise ProvenanceError(f"{label} integrity algorithm is unsupported.")
    if integrity.get("scope") != "object_without_integrity":
        raise ProvenanceError(f"{label} integrity scope is invalid.")
    observed = canonical_sha3_512(_integrity_payload(value))
    if integrity.get("value") != observed:
        raise ProvenanceError(f"{label} integrity digest is invalid.")
    return observed


def _safe_file_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProvenanceError(f"Provenance file is unavailable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProvenanceError(f"Refusing unsafe provenance file: {path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ProvenanceError(f"Provenance file changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = loads_strict_json(_safe_file_bytes(path))
    except Exception as exc:
        if isinstance(exc, ProvenanceError):
            raise
        raise ProvenanceError(f"{label} is not strict JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ProvenanceError(f"{label} must contain an object.")
    return value


def _existing_kind(path: Path) -> str:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    return "special"


def _validate_runtime_control(root: Path) -> None:
    for relative in (
        CONTROL_ROOT,
        CONTROL_ROOT / "provenance",
        CONTROL_ROOT / "provenance/scopes",
        CONTROL_ROOT / "transactions",
        TRANSACTIONS_RELATIVE,
        CONTROL_ROOT / "locks",
        STATE_PARENT_RELATIVE,
    ):
        path = root / relative
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ProvenanceError(f"Required operation-control directory is unsafe: {path}")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ProvenanceError(f"Required operation-control directory mode is not 0700: {path}")
    for relative in (CONTROL_ENROLLMENT_LOCK_RELATIVE, LOCK_RELATIVE):
        lock_path = root / relative
        metadata = os.lstat(lock_path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ProvenanceError(f"Required operation-control lock file is unsafe: {lock_path}")


def _validate_scope_enrollment_runtime(root: Path) -> None:
    for relative in (
        CONTROL_ROOT,
        CONTROL_ROOT / "provenance",
        CONTROL_ROOT / "provenance/scopes",
        CONTROL_ROOT / "transactions",
        CONTROL_ROOT / "locks",
        STATE_PARENT_RELATIVE,
    ):
        path = root / relative
        try:
            metadata = os.lstat(path)
        except FileNotFoundError as exc:
            raise ProvenanceError(
                "Existing OWNER control root lacks the v1 shared-enrollment runtime."
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ProvenanceError(f"Shared-enrollment directory is unsafe: {path}")
    lock_path = root / CONTROL_ENROLLMENT_LOCK_RELATIVE
    try:
        metadata = os.lstat(lock_path)
    except FileNotFoundError as exc:
        raise ProvenanceError(
            "Existing OWNER control root lacks the v1 shared-enrollment lock."
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ProvenanceError(f"Shared-enrollment lock is unsafe: {lock_path}")


def _validate_owner(owner: dict[str, Any]) -> tuple[str, str]:
    required = {
        "schema",
        "canonicalization",
        "project_id",
        "control_root",
        "owner_kind",
        "created_by",
        "enrollment_authorization",
        "integrity",
    }
    if set(owner) != required or owner.get("schema") != OWNER_SCHEMA:
        raise ProvenanceError("OWNER.json has an unsupported shape or schema.")
    if owner.get("canonicalization") != CANONICALIZATION:
        raise ProvenanceError("OWNER.json canonicalization is unsupported.")
    if owner.get("control_root") != CONTROL_ROOT.as_posix():
        raise ProvenanceError("OWNER.json control root is invalid.")
    if owner.get("owner_kind") != "naos_operation_control_root":
        raise ProvenanceError("OWNER.json owner kind is invalid.")
    created_by = owner.get("created_by")
    if (
        not isinstance(created_by, dict)
        or set(created_by)
        != {"kit_id", "kit_version", "source_commit", "source_manifest_sha256"}
        or created_by.get("kit_id") != "naos-governance"
        or not isinstance(created_by.get("kit_version"), str)
        or not created_by.get("kit_version")
        or SHA256_RE.fullmatch(str(created_by.get("source_manifest_sha256") or ""))
        is None
    ):
        raise ProvenanceError("OWNER.json creator binding is invalid.")
    source_commit = created_by.get("source_commit")
    if source_commit is not None and (
        not isinstance(source_commit, str)
        or GIT_SHA_RE.fullmatch(source_commit) is None
    ):
        raise ProvenanceError("OWNER.json source commit is invalid.")
    authorization = owner.get("enrollment_authorization")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != {"plan_sha256", "review_receipt_sha256"}
        or SHA256_RE.fullmatch(str(authorization.get("plan_sha256") or "")) is None
    ):
        raise ProvenanceError("OWNER.json enrollment authorization is invalid.")
    review_receipt = authorization.get("review_receipt_sha256")
    if review_receipt is not None and (
        not isinstance(review_receipt, str)
        or SHA256_RE.fullmatch(review_receipt) is None
    ):
        raise ProvenanceError("OWNER.json review receipt binding is invalid.")
    project_id = str(owner.get("project_id") or "")
    try:
        parsed = uuid.UUID(project_id.removeprefix("urn:uuid:"))
    except ValueError as exc:
        raise ProvenanceError("OWNER.json project_id is invalid.") from exc
    if project_id != f"urn:uuid:{str(parsed)}":
        raise ProvenanceError("OWNER.json project_id is not canonical.")
    return project_id, _validate_integrity(owner, label="OWNER.json")


def _validate_scope(
    scope: dict[str, Any],
    *,
    project_id: str,
    owner_integrity: str,
    governed_root: str,
) -> str:
    required = {
        "schema",
        "canonicalization",
        "project_id",
        "owner_integrity_sha3_512",
        "scope_id",
        "capability_id",
        "governed_root",
        "policy",
        "enrollment",
        "integrity",
    }
    if set(scope) != required or scope.get("schema") != SCOPE_SCHEMA:
        raise ProvenanceError("Repository-intelligence scope has an unsupported shape or schema.")
    if scope.get("canonicalization") != CANONICALIZATION:
        raise ProvenanceError("Repository-intelligence scope canonicalization is unsupported.")
    expected = {
        "project_id": project_id,
        "owner_integrity_sha3_512": owner_integrity,
        "scope_id": SCOPE_ID,
        "capability_id": CAPABILITY_ID,
        "governed_root": governed_root,
    }
    for field, value in expected.items():
        if scope.get(field) != value:
            raise ProvenanceError(f"Repository-intelligence scope {field} is invalid.")
    policy = scope.get("policy")
    if policy != {
        "initial_root_state": "absent",
        "existing_without_valid_chain": "refuse",
        "ownership_inference": "forbidden",
        "mutable_paths": [f"{governed_root}/active.json"],
        "immutable_generation_root": f"{governed_root}/generations",
        "transient_paths": [
            f"{TRANSACTIONS_RELATIVE.as_posix()}/<transaction_id>/staging"
        ],
        "transaction_root": TRANSACTIONS_RELATIVE.as_posix(),
        "lock_path": LOCK_RELATIVE.as_posix(),
        "unknown_entries": "refuse",
        "generation_id_pattern": "^RI-[0-9a-f]{24}$",
    }:
        raise ProvenanceError("Repository-intelligence scope policy is invalid.")
    enrollment = scope.get("enrollment")
    if not isinstance(enrollment, dict) or set(enrollment) != {
        "plan_sha256",
        "review_receipt_sha256",
        "observed_governed_root_state",
    }:
        raise ProvenanceError("Repository-intelligence scope enrollment is invalid.")
    if enrollment.get("observed_governed_root_state") != "absent":
        raise ProvenanceError("Repository-intelligence scope was not enrolled over an absent root.")
    plan_sha256 = enrollment.get("plan_sha256")
    review_receipt = enrollment.get("review_receipt_sha256")
    if (
        not isinstance(plan_sha256, str)
        or SHA256_RE.fullmatch(plan_sha256) is None
        or (
            review_receipt is not None
            and (
                not isinstance(review_receipt, str)
                or SHA256_RE.fullmatch(review_receipt) is None
            )
        )
    ):
        raise ProvenanceError("Repository-intelligence scope authorization is invalid.")
    return _validate_integrity(scope, label="repository-intelligence scope")


def inspect_scope(project_root: Path, *, governed_root: str) -> ScopeInspection:
    root = project_root.resolve(strict=True)
    owner_path = root / OWNER_RELATIVE
    scope_path = root / SCOPE_RELATIVE
    target_path = root / Path(governed_root)
    owner_kind = _existing_kind(owner_path)
    scope_kind = _existing_kind(scope_path)
    target_kind = _existing_kind(target_path)

    if owner_kind == "absent" and scope_kind == "absent":
        if target_kind != "absent":
            return ScopeInspection(
                "refused",
                None,
                None,
                None,
                governed_root,
                refusal="Existing generated root has no valid provenance; ownership inference is forbidden.",
            )
        control_kind = _existing_kind(root / CONTROL_ROOT)
        if control_kind != "absent":
            return ScopeInspection(
                "refused",
                None,
                None,
                None,
                governed_root,
                refusal="Existing operation-control root has no valid OWNER.json.",
            )
        return ScopeInspection(
            "enrollment_required",
            None,
            None,
            None,
            governed_root,
            # This identifier is plan data, not ownership evidence. Derive it
            # from the exact target binding so repeated read-only plans are
            # byte-deterministic; ownership still begins only at separately
            # digest-confirmed enrollment.
            enrollment_project_id=(
                "urn:uuid:"
                + str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"naos:repository-intelligence:{root}:{governed_root}",
                    )
                )
            ),
        )
    if owner_kind != "file":
        return ScopeInspection("refused", None, None, None, governed_root, refusal="OWNER.json is absent or unsafe.")
    try:
        owner = _load_object(owner_path, label="OWNER.json")
        project_id, owner_integrity = _validate_owner(owner)
    except ProvenanceError as exc:
        return ScopeInspection("refused", None, None, None, governed_root, refusal=str(exc))
    if scope_kind == "absent" and target_kind == "absent":
        try:
            _validate_scope_enrollment_runtime(root)
        except ProvenanceError as exc:
            return ScopeInspection(
                "refused",
                project_id,
                owner_integrity,
                None,
                governed_root,
                refusal=str(exc),
            )
        return ScopeInspection(
            "scope_enrollment_required",
            project_id,
            owner_integrity,
            None,
            governed_root,
            enrollment_project_id=project_id,
        )
    if scope_kind != "file":
        return ScopeInspection("refused", project_id, owner_integrity, None, governed_root, refusal="Capability scope is absent or unsafe.")
    try:
        scope = _load_object(scope_path, label="repository-intelligence scope")
        scope_integrity = _validate_scope(
            scope,
            project_id=project_id,
            owner_integrity=owner_integrity,
            governed_root=governed_root,
        )
        _validate_runtime_control(root)
    except ProvenanceError as exc:
        return ScopeInspection("refused", project_id, owner_integrity, None, governed_root, refusal=str(exc))
    return ScopeInspection("valid", project_id, owner_integrity, scope_integrity, governed_root)


def build_enrollment_objects(
    inspection: ScopeInspection,
    *,
    plan_sha256: str,
    source_manifest_sha256: str,
    kit_version: str,
    source_commit: str | None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if inspection.status not in {"enrollment_required", "scope_enrollment_required"}:
        raise ProvenanceError(f"Scope is not eligible for enrollment: {inspection.status}.")
    project_id = inspection.enrollment_project_id
    if not project_id:
        raise ProvenanceError("Enrollment project identity is missing.")
    owner: dict[str, Any] | None = None
    owner_integrity = inspection.owner_integrity
    if inspection.status == "enrollment_required":
        owner = _with_integrity(
            {
                "schema": OWNER_SCHEMA,
                "canonicalization": CANONICALIZATION,
                "project_id": project_id,
                "control_root": CONTROL_ROOT.as_posix(),
                "owner_kind": "naos_operation_control_root",
                "created_by": {
                    "kit_id": "naos-governance",
                    "kit_version": kit_version,
                    "source_commit": source_commit,
                    "source_manifest_sha256": source_manifest_sha256,
                },
                "enrollment_authorization": {
                    "plan_sha256": plan_sha256,
                    "review_receipt_sha256": None,
                },
            }
        )
        owner_integrity = str(owner["integrity"]["value"])
    if not owner_integrity:
        raise ProvenanceError("Enrollment owner binding is missing.")
    governed_root = inspection.governed_root
    scope = _with_integrity(
        {
            "schema": SCOPE_SCHEMA,
            "canonicalization": CANONICALIZATION,
            "project_id": project_id,
            "owner_integrity_sha3_512": owner_integrity,
            "scope_id": SCOPE_ID,
            "capability_id": CAPABILITY_ID,
            "governed_root": governed_root,
            "policy": {
                "initial_root_state": "absent",
                "existing_without_valid_chain": "refuse",
                "ownership_inference": "forbidden",
                "mutable_paths": [f"{governed_root}/active.json"],
                "immutable_generation_root": f"{governed_root}/generations",
                "transient_paths": [
                    f"{TRANSACTIONS_RELATIVE.as_posix()}/<transaction_id>/staging"
                ],
                "transaction_root": TRANSACTIONS_RELATIVE.as_posix(),
                "lock_path": LOCK_RELATIVE.as_posix(),
                "unknown_entries": "refuse",
                "generation_id_pattern": "^RI-[0-9a-f]{24}$",
            },
            "enrollment": {
                "plan_sha256": plan_sha256,
                "review_receipt_sha256": None,
                "observed_governed_root_state": "absent",
            },
        }
    )
    return owner, scope


def _mkdir_exclusive(path: Path) -> None:
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    _write_exclusive_bytes(path, canonical_bytes(value) + b"\n")


def _write_exclusive_bytes(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _pending_enrollment_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.enrolling")


def _remove_pending_enrollment_file(path: Path) -> None:
    kind = _existing_kind(path)
    if kind == "absent":
        return
    if kind != "file":
        raise ProvenanceError(
            f"Unsafe enrollment pending file is preserved and refused: {path}"
        )
    metadata = os.lstat(path)
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ProvenanceError(
            f"Unsafe enrollment pending-file metadata is preserved and refused: {path}"
        )
    path.unlink()
    _fsync_dir(path.parent)


def _write_atomic_new(path: Path, data: bytes) -> None:
    """Publish new enrollment bytes without exposing a partial final file."""

    pending = _pending_enrollment_path(path)
    _remove_pending_enrollment_file(pending)
    _write_exclusive_bytes(pending, data)
    _fsync_dir(pending.parent)
    rename_no_replace(pending, path)
    _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    fsync_directory(path)


def _mkdir_durable(path: Path) -> None:
    _mkdir_exclusive(path)
    _fsync_dir(path.parent)


@contextmanager
def _stable_directory_lock(path: Path) -> Iterator[int]:
    """Serialize first-owner publication without adding an unowned lock file."""

    if fcntl is None:
        raise ProvenanceError(
            "Stable directory-lock support is unavailable for initial enrollment."
        )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProvenanceError(
            f"Initial enrollment lock directory is unavailable: {path}"
        ) from exc
    locked = False
    try:
        opened = os.fstat(descriptor)
        observed = os.lstat(path)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ProvenanceError(
                f"Initial enrollment lock directory is unsafe: {path}"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProvenanceError(
                "Another initial managed-content enrollment holds the project lock."
            ) from exc
        locked = True
        current = os.lstat(path)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ProvenanceError(
                "Initial enrollment lock directory changed while acquiring its lock."
            )
        yield descriptor
        final = os.lstat(path)
        if (
            stat.S_ISLNK(final.st_mode)
            or not stat.S_ISDIR(final.st_mode)
            or (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino)
        ):
            raise ProvenanceError(
                "Initial enrollment control ancestor changed during publication."
            )
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    if not name or name in {".", ".."} or "/" in name:
        raise ProvenanceError(f"Unsafe directory component: {name!r}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise ProvenanceError(f"Bound directory is unavailable: {name}") from exc
    try:
        opened = os.fstat(descriptor)
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ProvenanceError(f"Bound directory is unsafe: {name}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_relative_directory_at(root_descriptor: int, relative: str) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        if relative in {"", "."}:
            return descriptor
        for component in Path(relative).parts:
            child = _open_directory_at(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _bound_control_root(project_root: Path) -> Iterator[int]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_descriptor = os.open(project_root, flags)
    naos_descriptor: int | None = None
    control_descriptor: int | None = None
    try:
        opened = os.fstat(root_descriptor)
        observed = os.lstat(project_root)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ProvenanceError("Project root changed while binding provenance.")
        naos_descriptor = _open_directory_at(root_descriptor, ".naos")
        control_descriptor = _open_directory_at(
            naos_descriptor,
            CONTROL_ROOT.name,
        )
        yield control_descriptor
        current_naos = os.stat(
            ".naos",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        opened_naos = os.fstat(naos_descriptor)
        current_control = os.stat(
            CONTROL_ROOT.name,
            dir_fd=naos_descriptor,
            follow_symlinks=False,
        )
        opened_control = os.fstat(control_descriptor)
        if (
            stat.S_ISLNK(current_naos.st_mode)
            or not stat.S_ISDIR(current_naos.st_mode)
            or (current_naos.st_dev, current_naos.st_ino)
            != (opened_naos.st_dev, opened_naos.st_ino)
            or stat.S_ISLNK(current_control.st_mode)
            or not stat.S_ISDIR(current_control.st_mode)
            or (current_control.st_dev, current_control.st_ino)
            != (opened_control.st_dev, opened_control.st_ino)
        ):
            raise ProvenanceError(
                "Operation-control ancestor changed while provenance was bound."
            )
    finally:
        if control_descriptor is not None:
            os.close(control_descriptor)
        if naos_descriptor is not None:
            os.close(naos_descriptor)
        os.close(root_descriptor)


@contextmanager
def _stable_file_lock_at(
    root_descriptor: int,
    relative: str,
) -> Iterator[int]:
    if fcntl is None:
        raise ProvenanceError("Stable file-lock support is unavailable.")
    path = Path(relative)
    parent = _open_relative_directory_at(
        root_descriptor,
        Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
    )
    descriptor: int | None = None
    locked = False
    try:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path.name, flags, dir_fd=parent)
        opened = os.fstat(descriptor)
        observed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ProvenanceError(f"Bound enrollment lock is unsafe: {relative}")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProvenanceError(f"Enrollment lock is held: {relative}") from exc
        locked = True
        yield descriptor
    finally:
        if descriptor is not None:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        os.close(parent)


def _load_object_at(
    root_descriptor: int,
    relative: str,
    *,
    label: str,
) -> dict[str, Any]:
    path = Path(relative)
    parent = _open_relative_directory_at(
        root_descriptor,
        Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
    )
    try:
        raw = _read_regular_file_at(parent, path.name)
    finally:
        os.close(parent)
    try:
        value = loads_strict_json(raw)
    except Exception as exc:
        raise ProvenanceError(f"{label} is not strict JSON.") from exc
    if not isinstance(value, dict):
        raise ProvenanceError(f"{label} must contain an object.")
    return value


def _read_regular_file_at(parent_descriptor: int, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        before = os.fstat(descriptor)
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ProvenanceError(f"Bound enrollment file is unsafe: {name}")
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
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ProvenanceError(f"Bound enrollment file changed while read: {name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _relative_entry_metadata_at(
    root_descriptor: int,
    relative: str,
) -> os.stat_result | None:
    path = Path(relative)
    parent = _open_relative_directory_at(
        root_descriptor,
        Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
    )
    try:
        try:
            return os.stat(
                path.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
    finally:
        os.close(parent)


def _validate_directory_at(root_descriptor: int, relative: str) -> None:
    descriptor = _open_relative_directory_at(root_descriptor, relative)
    try:
        metadata = os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ProvenanceError(
                f"Operation-control directory mode is not 0700: {relative}"
            )
    finally:
        os.close(descriptor)


def _validate_regular_file_at(root_descriptor: int, relative: str) -> None:
    metadata = _relative_entry_metadata_at(root_descriptor, relative)
    if (
        metadata is None
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ProvenanceError(f"Operation-control file is unsafe: {relative}")


def _validate_preparation_tree_at(
    preparation_descriptor: int,
    *,
    expected_directories: set[str],
    expected_files: dict[str, bytes],
) -> None:
    root_metadata = os.fstat(preparation_descriptor)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise ProvenanceError("Enrollment preparation root is unsafe.")
    pending_files = {
        str(Path(relative).with_name(f".{Path(relative).name}.enrolling")): value
        for relative, value in expected_files.items()
    }

    def visit(directory_descriptor: int, prefix: str) -> None:
        for name in sorted(os.listdir(directory_descriptor)):
            relative = f"{prefix}/{name}" if prefix else name
            metadata = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(metadata.st_mode):
                if relative not in expected_directories or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise ProvenanceError(
                        f"Unknown or unsafe enrollment preparation directory: {relative}"
                    )
                child = _open_directory_at(directory_descriptor, name)
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
                continue
            expected = expected_files.get(relative)
            if expected is None:
                expected = pending_files.get(relative)
            if (
                expected is None
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or _read_regular_file_at(directory_descriptor, name) != expected
            ):
                raise ProvenanceError(
                    f"Unknown, unsafe, or differing enrollment preparation file: {relative}"
                )

    visit(preparation_descriptor, "")


def _remove_preparation_contents_at(directory_descriptor: int) -> None:
    for name in sorted(os.listdir(directory_descriptor)):
        before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child = _open_directory_at(directory_descriptor, name)
            try:
                _remove_preparation_contents_at(child)
            finally:
                os.close(child)
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise ProvenanceError(
                    f"Enrollment preparation directory changed during recovery: {name}"
                )
            os.rmdir(name, dir_fd=directory_descriptor)
        else:
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise ProvenanceError(
                    f"Enrollment preparation file changed during recovery: {name}"
                )
            os.unlink(name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)


def _create_directory_tree_at(
    root_descriptor: int,
    expected_directories: set[str],
) -> None:
    for relative in sorted(
        expected_directories,
        key=lambda item: (len(Path(item).parts), item),
    ):
        path = Path(relative)
        parent = _open_relative_directory_at(
            root_descriptor,
            Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
        )
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            child = _open_directory_at(parent, path.name)
            try:
                os.fchown(child, os.getuid(), os.getgid())
                os.fchmod(child, 0o700)
                os.fsync(child)
            finally:
                os.close(child)
            os.fsync(parent)
        finally:
            os.close(parent)


def _write_exclusive_bytes_at(
    root_descriptor: int,
    relative: str,
    data: bytes,
) -> None:
    path = Path(relative)
    parent = _open_relative_directory_at(
        root_descriptor,
        Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
    )
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent)
        try:
            os.fchown(descriptor, os.getuid(), os.getgid())
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(data):
                offset += os.write(descriptor, data[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def _publish_exact_file_at(
    root_descriptor: int,
    relative: str,
    data: bytes,
) -> None:
    """Idempotently publish one exact file beneath a pinned control root."""

    path = Path(relative)
    parent = _open_relative_directory_at(
        root_descriptor,
        Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
    )
    pending_name = f".{path.name}.enrolling"
    try:
        try:
            final = _read_regular_file_at(parent, path.name)
        except FileNotFoundError:
            final = None
        if final is not None:
            if final != data:
                raise ProvenanceError(
                    f"Existing enrollment file differs and was preserved: {relative}"
                )
            try:
                pending = _read_regular_file_at(parent, pending_name)
            except FileNotFoundError:
                return
            if pending != data:
                raise ProvenanceError(
                    f"Enrollment pending file differs and was preserved: {relative}"
                )
            os.unlink(pending_name, dir_fd=parent)
            os.fsync(parent)
            return
        try:
            pending = _read_regular_file_at(parent, pending_name)
        except FileNotFoundError:
            _write_exclusive_bytes_at(
                root_descriptor,
                (path.parent / pending_name).as_posix(),
                data,
            )
        else:
            if pending != data:
                raise ProvenanceError(
                    f"Enrollment pending file differs and was preserved: {relative}"
                )
        try:
            rename_no_replace_at(
                parent,
                pending_name,
                parent,
                path.name,
            )
            os.fsync(parent)
        except FileExistsError:
            final = _read_regular_file_at(parent, path.name)
            if final != data:
                raise ProvenanceError(
                    f"Enrollment destination appeared and differs: {relative}"
                )
            pending = _read_regular_file_at(parent, pending_name)
            if pending != data:
                raise ProvenanceError(
                    f"Enrollment pending file changed and was preserved: {relative}"
                )
            os.unlink(pending_name, dir_fd=parent)
            os.fsync(parent)
    finally:
        os.close(parent)


def _ensure_empty_directory_at(root_descriptor: int, relative: str) -> None:
    """Create or recover one exact empty runtime directory under a pinned root."""

    path = Path(relative)
    parent = _open_relative_directory_at(
        root_descriptor,
        Path(*path.parts[:-1]).as_posix() if len(path.parts) > 1 else ".",
    )
    child: int | None = None
    created = False
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            os.fsync(parent)
            created = True
        except FileExistsError:
            pass
        child = _open_directory_at(parent, path.name)
        if created:
            os.fchmod(child, 0o700)
        elif stat.S_IMODE(os.fstat(child).st_mode) != 0o700:
            raise ProvenanceError(
                f"Pre-scope capability directory mode is unsafe: {relative}"
            )
        if os.listdir(child):
            raise ProvenanceError(
                f"Pre-scope capability directory is not empty: {relative}"
            )
        os.fsync(child)
        os.fsync(parent)
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)


def _publish_prepared_tree_at(
    parent_descriptor: int,
    *,
    preparation_name: str,
    final_name: str,
    preparation_prefixes: tuple[str, ...],
    expected_directories: set[str],
    expected_files: dict[str, bytes],
) -> None:
    for name in sorted(os.listdir(parent_descriptor)):
        if (
            name != preparation_name
            and any(name.startswith(prefix) for prefix in preparation_prefixes)
        ):
            raise ProvenanceError(
                "A different enrollment preparation requires exact recovery first: "
                f"{name}"
            )
    try:
        final_metadata = os.stat(
            final_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        final_metadata = None
    if final_metadata is not None:
        raise ProvenanceError(f"Enrollment destination already exists: {final_name}")
    try:
        preparation = _open_directory_at(parent_descriptor, preparation_name)
    except ProvenanceError:
        try:
            os.stat(
                preparation_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            preparation = None
        else:
            raise
    if preparation is not None:
        try:
            _validate_preparation_tree_at(
                preparation,
                expected_directories=expected_directories,
                expected_files=expected_files,
            )
            _remove_preparation_contents_at(preparation)
        finally:
            os.close(preparation)
        os.rmdir(preparation_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    os.mkdir(preparation_name, 0o700, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)
    preparation = _open_directory_at(parent_descriptor, preparation_name)
    try:
        os.fchown(preparation, os.getuid(), os.getgid())
        os.fchmod(preparation, 0o700)
        _create_directory_tree_at(preparation, expected_directories)
        for relative, data in sorted(expected_files.items()):
            _write_exclusive_bytes_at(preparation, relative, data)
        for relative in sorted(
            expected_directories,
            key=lambda item: (len(Path(item).parts), item),
            reverse=True,
        ):
            directory = _open_relative_directory_at(preparation, relative)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        os.fsync(preparation)
    finally:
        os.close(preparation)
    rename_no_replace_at(
        parent_descriptor,
        preparation_name,
        parent_descriptor,
        final_name,
    )
    os.fsync(parent_descriptor)


def _greenfield_target_binding(project_root: Path) -> tuple[Path, Path, dict[str, Any]]:
    lexical = Path(os.path.abspath(os.fspath(project_root)))
    if not lexical.name or lexical.name in {".", ".."}:
        raise ProvenanceError("Greenfield target leaf is invalid.")
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as exc:
        raise ProvenanceError(
            "Greenfield target parent must be an existing directory."
        ) from exc
    parent_metadata = os.lstat(parent)
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        raise ProvenanceError("Greenfield target parent is unsafe.")
    target = parent / lexical.name
    return (
        target,
        parent,
        {
            "parent_path": str(parent),
            "parent_device": parent_metadata.st_dev,
            "parent_inode": parent_metadata.st_ino,
            "target_leaf": target.name,
        },
    )


def _validate_greenfield_source_inventory(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ProvenanceError("Greenfield source inventory is empty or invalid.")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "source",
            "source_metadata",
        }:
            raise ProvenanceError("Greenfield source inventory item is invalid.")
        try:
            relative = safe_relative_path(str(item.get("path") or ""))
            validate_source_metadata_contract(item.get("source_metadata"))
        except (ContentPathError, ValueError) as exc:
            raise ProvenanceError("Greenfield source inventory metadata is invalid.") from exc
        source = item.get("source")
        if not isinstance(source, dict) or set(source) != {
            "kind",
            "mode",
            "size",
            "sha256",
        }:
            raise ProvenanceError("Greenfield source identity is invalid.")
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
            or item["source_metadata"].get("mode") != mode
        ):
            raise ProvenanceError("Greenfield source identity is invalid.")
        normalized.append(
            {
                "path": relative.as_posix(),
                "source": dict(source),
                "source_metadata": dict(item["source_metadata"]),
            }
        )
    paths = [str(item["path"]) for item in normalized]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ProvenanceError(
            "Greenfield source inventory is not sorted and unique."
        )
    return normalized


def build_greenfield_root_intent(
    project_root: Path,
    *,
    operation: str,
    inputs: dict[str, Any],
    source_policy_sha256: str,
    source_inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an immutable parent-bound authority for initial root publication."""

    _target, _parent, target_binding = _greenfield_target_binding(project_root)
    inventory = _validate_greenfield_source_inventory(source_inventory)
    if (
        not isinstance(operation, str)
        or not operation.strip()
        or not isinstance(inputs, dict)
    ):
        raise ProvenanceError("Greenfield operation binding is invalid.")
    if SHA256_RE.fullmatch(source_policy_sha256) is None:
        raise ProvenanceError("Greenfield source-policy binding is invalid.")
    payload = {
        "schema": GREENFIELD_INTENT_SCHEMA,
        "target_binding": target_binding,
        "operation": operation,
        "inputs": inputs,
        "source_policy_sha256": source_policy_sha256,
        "sources": inventory,
    }
    result = {
        **payload,
        "request_sha256": canonical_sha256(payload),
    }
    return _with_integrity(result)


def validate_greenfield_root_intent(
    intent: dict[str, Any],
    *,
    project_root: Path,
) -> str:
    expected_keys = {
        "schema",
        "target_binding",
        "operation",
        "inputs",
        "source_policy_sha256",
        "sources",
        "request_sha256",
        "integrity",
    }
    if not isinstance(intent, dict) or set(intent) != expected_keys:
        raise ProvenanceError("Greenfield root intent shape is invalid.")
    _target, _parent, target_binding = _greenfield_target_binding(project_root)
    if (
        intent.get("schema") != GREENFIELD_INTENT_SCHEMA
        or intent.get("target_binding") != target_binding
        or not isinstance(intent.get("operation"), str)
        or not str(intent.get("operation")).strip()
        or not isinstance(intent.get("inputs"), dict)
        or not isinstance(intent.get("source_policy_sha256"), str)
        or SHA256_RE.fullmatch(str(intent.get("source_policy_sha256"))) is None
    ):
        raise ProvenanceError("Greenfield root intent binding is invalid.")
    inventory = _validate_greenfield_source_inventory(intent.get("sources"))
    payload = {
        "schema": intent["schema"],
        "target_binding": intent["target_binding"],
        "operation": intent["operation"],
        "inputs": intent["inputs"],
        "source_policy_sha256": intent["source_policy_sha256"],
        "sources": inventory,
    }
    expected_request = canonical_sha256(payload)
    if intent.get("request_sha256") != expected_request:
        raise ProvenanceError("Greenfield root request digest is invalid.")
    _validate_integrity(intent, label="greenfield root intent")
    return expected_request


def _greenfield_control_name(intent: dict[str, Any]) -> str:
    target_binding = intent.get("target_binding")
    return GREENFIELD_CONTROL_PREFIX + canonical_sha256(
        {
            "schema": "naos.init.greenfield_target_binding.v1",
            "target_binding": target_binding,
        }
    )[:24]


def _greenfield_marker_value(intent: dict[str, Any]) -> dict[str, Any]:
    return _with_integrity(
        {
            "schema": GREENFIELD_ROOT_MARKER_SCHEMA,
            "request_sha256": intent["request_sha256"],
            "target_binding": intent["target_binding"],
        }
    )


def _greenfield_root_identity_value(
    intent: dict[str, Any],
    metadata: dict[str, object],
) -> dict[str, Any]:
    try:
        validate_created_metadata_identity(metadata, expected_type="directory")
    except ContentPathError as exc:
        raise ProvenanceError("Greenfield root metadata identity is invalid.") from exc
    if (
        metadata.get("mode") != 0o755
        or metadata.get("uid") != os.getuid()
        or metadata.get("gid") != os.getgid()
    ):
        raise ProvenanceError(
            "UNSUPPORTED_METADATA: greenfield root ownership or mode is outside "
            "the executed Darwin create-only adapter."
        )
    return _with_integrity(
        {
            "schema": GREENFIELD_ROOT_IDENTITY_SCHEMA,
            "request_sha256": intent["request_sha256"],
            "metadata": metadata,
        }
    )


def _validate_greenfield_root_identity(
    value: dict[str, Any],
    *,
    intent: dict[str, Any],
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "request_sha256",
        "metadata",
        "integrity",
    }:
        raise ProvenanceError("Greenfield root identity shape is invalid.")
    if (
        value.get("schema") != GREENFIELD_ROOT_IDENTITY_SCHEMA
        or value.get("request_sha256") != intent.get("request_sha256")
        or not isinstance(value.get("metadata"), dict)
    ):
        raise ProvenanceError("Greenfield root identity binding is invalid.")
    _greenfield_root_identity_value(intent, dict(value["metadata"]))
    _validate_integrity(value, label="greenfield root identity")
    return dict(value["metadata"])


def _open_greenfield_parent(
    parent: Path,
    target_binding: dict[str, Any],
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(parent, flags)
    try:
        opened = os.fstat(descriptor)
        observed = os.lstat(parent)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (observed.st_dev, observed.st_ino)
            or opened.st_dev != target_binding.get("parent_device")
            or opened.st_ino != target_binding.get("parent_inode")
        ):
            raise ProvenanceError("Greenfield target parent binding changed.")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _acquire_greenfield_lock(control_descriptor: int) -> int:
    if fcntl is None:
        raise ProvenanceError("Stable flock support is unavailable.")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("lock", flags, dir_fd=control_descriptor)
    try:
        opened = os.fstat(descriptor)
        observed = os.stat(
            "lock",
            dir_fd=control_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino)
            != (observed.st_dev, observed.st_ino)
            or _read_regular_file_at(control_descriptor, "lock") != b""
        ):
            raise ProvenanceError("Greenfield root lock is unsafe.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProvenanceError("Another greenfield root operation holds the lock.") from exc
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _acquire_greenfield_cleanup_anchor(
    parent_descriptor: int,
    name: str,
) -> tuple[int, bytes]:
    """Open and lock the durable root-identity anchor for cleanup recovery."""

    if fcntl is None:
        raise ProvenanceError("Stable flock support is unavailable.")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        live = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.getuid()
            or opened.st_gid != os.getgid()
            or (opened.st_dev, opened.st_ino) != (live.st_dev, live.st_ino)
        ):
            raise ProvenanceError("Greenfield cleanup anchor is unsafe.")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (opened.st_dev, opened.st_ino)
            != (current.st_dev, current.st_ino)
        ):
            raise ProvenanceError(
                "Greenfield cleanup anchor changed while being acquired."
            )
        data = b"".join(chunks)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise ProvenanceError(
            "Another greenfield cleanup operation holds the anchor lock."
        ) from exc
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, data


def _load_greenfield_root_identity_at(
    control_descriptor: int,
    *,
    intent: dict[str, Any],
) -> dict[str, object]:
    raw = _read_regular_file_at(control_descriptor, "root-identity.json")
    try:
        value = loads_strict_json(raw)
    except Exception as exc:
        raise ProvenanceError("Greenfield root identity is not strict JSON.") from exc
    if not isinstance(value, dict):
        raise ProvenanceError("Greenfield root identity must be an object.")
    return _validate_greenfield_root_identity(value, intent=intent)


def _verify_greenfield_root_metadata(
    root_descriptor: int,
    expected: dict[str, object],
) -> None:
    observed = observe_created_directory_metadata_fd(root_descriptor)
    if observed != expected:
        raise ProvenanceError("Greenfield root metadata identity changed.")


def begin_greenfield_root(
    project_root: Path,
    *,
    intent: dict[str, Any],
    allow_create: bool,
    allow_existing_without_control: bool = False,
) -> GreenfieldRootSession | None:
    """Publish or resume one exact root without treating emptiness as authority."""

    request_sha256 = validate_greenfield_root_intent(
        intent,
        project_root=project_root,
    )
    target, parent, target_binding = _greenfield_target_binding(project_root)
    control_name = _greenfield_control_name(intent)
    preparation_prefix = f"{control_name}.preparing."
    preparation_name = preparation_prefix + request_sha256[:24]
    completion_prefix = f"{control_name}.completed."
    completion_name = completion_prefix + request_sha256[:24]
    cleanup_anchor_name = completion_name + ".anchor"
    marker_bytes = canonical_bytes(_greenfield_marker_value(intent)) + b"\n"
    intent_bytes = canonical_bytes(intent) + b"\n"
    parent_descriptor = _open_greenfield_parent(parent, target_binding)
    control_descriptor: int | None = None
    root_descriptor: int | None = None
    lock_descriptor: int | None = None
    cleanup_anchor_descriptor: int | None = None
    try:
        try:
            target_metadata = os.stat(
                target.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            target_metadata = None
        if target_metadata is not None and (
            stat.S_ISLNK(target_metadata.st_mode)
            or not stat.S_ISDIR(target_metadata.st_mode)
        ):
            raise ProvenanceError("Greenfield target is not a safe directory.")
        parent_entries = set(os.listdir(parent_descriptor))
        preparations = sorted(
            name for name in parent_entries if name.startswith(preparation_prefix)
        )
        completion_entries = sorted(
            name for name in parent_entries if name.startswith(completion_prefix)
        )
        control_present = control_name in parent_entries
        if control_present and (preparations or completion_entries):
            raise ProvenanceError(
                "Greenfield root has conflicting final, prepared, or completed "
                "control envelopes."
            )
        unexpected_completions = set(completion_entries) - {
            completion_name,
            cleanup_anchor_name,
        }
        if unexpected_completions:
            raise ProvenanceError(
                "A different greenfield completion envelope is preserved and "
                "requires exact recovery."
            )
        completed_present = completion_name in completion_entries
        cleanup_anchor_present = cleanup_anchor_name in completion_entries
        completion_pending = completed_present or cleanup_anchor_present
        active_control_name = completion_name if completed_present else control_name
        if not control_present:
            if target_metadata is not None:
                if preparations:
                    raise ProvenanceError(
                        "A greenfield preparation envelope remains beside an "
                        "existing target and requires exact recovery."
                    )
                root_descriptor = _open_directory_at(
                    parent_descriptor,
                    target.name,
                )
                try:
                    marker_metadata = os.stat(
                        GREENFIELD_ROOT_MARKER,
                        dir_fd=root_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    marker_metadata = None
                if marker_metadata is not None and not completion_pending:
                    raise ProvenanceError(
                        "Greenfield target marker lacks its parent-bound envelope."
                    )
                if completion_pending:
                    if marker_metadata is not None:
                        raise ProvenanceError(
                            "Greenfield completed envelope still has a live root marker."
                        )
                    os.close(root_descriptor)
                    root_descriptor = None
                    control_present = True
                elif allow_existing_without_control:
                    os.close(root_descriptor)
                    root_descriptor = None
                    os.close(parent_descriptor)
                    return None
                else:
                    raise ProvenanceError(
                        "Existing greenfield target lacks exact root-init provenance."
                    )
            elif completion_pending:
                raise ProvenanceError(
                    "Greenfield completion envelope exists without its target."
                )
            elif not allow_create:
                raise ProvenanceError("Greenfield root creation is not authorized.")
            else:
                _publish_prepared_tree_at(
                    parent_descriptor,
                    preparation_name=preparation_name,
                    final_name=control_name,
                    preparation_prefixes=(preparation_prefix,),
                    expected_directories={"staging-root"},
                    expected_files={
                        "intent.json": intent_bytes,
                        "lock": b"",
                        f"staging-root/{GREENFIELD_ROOT_MARKER}": marker_bytes,
                    },
                )
                control_present = True
        if completion_pending:
            anchor_bytes: bytes | None = None
            if cleanup_anchor_present:
                cleanup_anchor_descriptor, anchor_bytes = (
                    _acquire_greenfield_cleanup_anchor(
                        parent_descriptor,
                        cleanup_anchor_name,
                    )
                )
            identity_bytes: bytes | None = None
            if completed_present:
                control_descriptor = _open_directory_at(
                    parent_descriptor,
                    completion_name,
                )
                control_metadata = os.fstat(control_descriptor)
                if (
                    stat.S_IMODE(control_metadata.st_mode) != 0o700
                    or control_metadata.st_uid != os.getuid()
                    or control_metadata.st_gid != os.getgid()
                ):
                    raise ProvenanceError(
                        "Greenfield completion envelope metadata is unsafe."
                    )
                entries = set(os.listdir(control_descriptor))
                if not entries <= {"intent.json", "lock", "root-identity.json"}:
                    raise ProvenanceError(
                        "Greenfield completion envelope has unknown entries."
                    )
                if "intent.json" in entries and _read_regular_file_at(
                    control_descriptor,
                    "intent.json",
                ) != intent_bytes:
                    raise ProvenanceError(
                        "Greenfield completion envelope belongs to a different request."
                    )
                if "root-identity.json" in entries:
                    identity_bytes = _read_regular_file_at(
                        control_descriptor,
                        "root-identity.json",
                    )
                if identity_bytes is not None and anchor_bytes is not None:
                    raise ProvenanceError(
                        "Greenfield root identity exists both inside and outside "
                        "the completion envelope."
                    )
                if "lock" in entries:
                    lock_descriptor = _acquire_greenfield_lock(control_descriptor)
                elif cleanup_anchor_descriptor is not None:
                    lock_descriptor = cleanup_anchor_descriptor
                else:
                    raise ProvenanceError(
                        "Greenfield completion recovery has no stable lock."
                    )
            else:
                if cleanup_anchor_descriptor is None:
                    raise ProvenanceError(
                        "Greenfield completion recovery has no envelope or anchor."
                    )
                control_descriptor = os.dup(parent_descriptor)
                lock_descriptor = cleanup_anchor_descriptor
            identity_bytes = anchor_bytes if anchor_bytes is not None else identity_bytes
            if identity_bytes is None:
                raise ProvenanceError(
                    "Greenfield completion recovery has no root identity."
                )
            try:
                root_identity_value = loads_strict_json(identity_bytes)
            except Exception as exc:
                raise ProvenanceError(
                    "Greenfield completion root identity is not strict JSON."
                ) from exc
            if not isinstance(root_identity_value, dict):
                raise ProvenanceError(
                    "Greenfield completion root identity must be an object."
                )
            recorded_metadata = _validate_greenfield_root_identity(
                root_identity_value,
                intent=intent,
            )
            root_descriptor = _open_directory_at(parent_descriptor, target.name)
            _verify_greenfield_root_metadata(root_descriptor, recorded_metadata)
            live_root = os.stat(
                target.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            opened_root = os.fstat(root_descriptor)
            if (live_root.st_dev, live_root.st_ino) != (
                opened_root.st_dev,
                opened_root.st_ino,
            ):
                raise ProvenanceError("Greenfield final root binding changed.")
            return GreenfieldRootSession(
                project_root=target,
                parent_path=parent,
                target_name=target.name,
                control_name=control_name,
                control_entry_name=completion_name,
                parent_descriptor=parent_descriptor,
                control_descriptor=control_descriptor,
                root_descriptor=root_descriptor,
                lock_descriptor=lock_descriptor,
                intent=intent,
                marker_bytes=marker_bytes,
                root_identity=root_identity_value,
                state="completed_cleanup_pending",
                cleanup_anchor_name=(
                    cleanup_anchor_name if cleanup_anchor_present else None
                ),
                cleanup_anchor_descriptor=cleanup_anchor_descriptor,
            )
        control_descriptor = _open_directory_at(
            parent_descriptor,
            active_control_name,
        )
        control_metadata = os.fstat(control_descriptor)
        if (
            stat.S_IMODE(control_metadata.st_mode) != 0o700
            or control_metadata.st_uid != os.getuid()
            or control_metadata.st_gid != os.getgid()
        ):
            raise ProvenanceError("Greenfield control envelope metadata is unsafe.")
        lock_descriptor = _acquire_greenfield_lock(control_descriptor)
        if _read_regular_file_at(control_descriptor, "intent.json") != intent_bytes:
            raise ProvenanceError(
                "Greenfield control envelope belongs to a different exact request."
            )
        entries = set(os.listdir(control_descriptor))
        allowed_entries = (
            {"intent.json", "lock", "root-identity.json"}
            if completed_present
            else {
                "intent.json",
                "lock",
                "root-identity.json",
                ".root-identity.json.enrolling",
                "staging-root",
            }
        )
        if not entries <= allowed_entries or not {"intent.json", "lock"} <= entries:
            raise ProvenanceError(
                "Greenfield control envelope has missing or unknown entries."
            )
        staging_present = "staging-root" in entries
        try:
            current_target = os.stat(
                target.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            current_target = None
        if staging_present and current_target is not None:
            raise ProvenanceError(
                "Greenfield staged and final roots both exist; preserving both."
            )
        if not staging_present and current_target is None:
            raise ProvenanceError(
                "Greenfield control envelope has neither staged nor final root."
            )
        if staging_present:
            root_descriptor = _open_directory_at(
                control_descriptor,
                "staging-root",
            )
            if set(os.listdir(root_descriptor)) != {GREENFIELD_ROOT_MARKER}:
                raise ProvenanceError(
                    "Greenfield staged root contains unknown entries."
                )
            if _read_regular_file_at(
                root_descriptor,
                GREENFIELD_ROOT_MARKER,
            ) != marker_bytes:
                raise ProvenanceError("Greenfield staged-root marker differs.")
            current_mode = stat.S_IMODE(os.fstat(root_descriptor).st_mode)
            if current_mode not in {0o700, 0o755}:
                raise ProvenanceError("Greenfield staged-root mode is unsafe.")
            if current_mode == 0o700:
                os.fchmod(root_descriptor, 0o755)
                os.fsync(root_descriptor)
            root_metadata = observe_created_directory_metadata_fd(root_descriptor)
            root_identity = _greenfield_root_identity_value(intent, root_metadata)
            _publish_exact_file_at(
                control_descriptor,
                "root-identity.json",
                canonical_bytes(root_identity) + b"\n",
            )
            rename_no_replace_at(
                control_descriptor,
                "staging-root",
                parent_descriptor,
                target.name,
            )
            os.fsync(control_descriptor)
            os.fsync(parent_descriptor)
        else:
            root_descriptor = _open_directory_at(parent_descriptor, target.name)
            try:
                recorded_metadata = _load_greenfield_root_identity_at(
                    control_descriptor,
                    intent=intent,
                )
            except FileNotFoundError:
                pending_raw = _read_regular_file_at(
                    control_descriptor,
                    ".root-identity.json.enrolling",
                )
                try:
                    pending_value = loads_strict_json(pending_raw)
                except Exception as exc:
                    raise ProvenanceError(
                        "Greenfield pending root identity is invalid."
                    ) from exc
                if not isinstance(pending_value, dict):
                    raise ProvenanceError(
                        "Greenfield pending root identity must be an object."
                    )
                recorded_metadata = _validate_greenfield_root_identity(
                    pending_value,
                    intent=intent,
                )
                _verify_greenfield_root_metadata(
                    root_descriptor,
                    recorded_metadata,
                )
                _publish_exact_file_at(
                    control_descriptor,
                    "root-identity.json",
                    pending_raw,
                )
            root_identity = loads_strict_json(
                _read_regular_file_at(control_descriptor, "root-identity.json")
            )
            if not isinstance(root_identity, dict):
                raise ProvenanceError("Greenfield root identity must be an object.")
            recorded_metadata = _validate_greenfield_root_identity(
                root_identity,
                intent=intent,
            )
            _verify_greenfield_root_metadata(root_descriptor, recorded_metadata)
        live_root = os.stat(
            target.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened_root = os.fstat(root_descriptor)
        if (live_root.st_dev, live_root.st_ino) != (
            opened_root.st_dev,
            opened_root.st_ino,
        ):
            raise ProvenanceError("Greenfield final root binding changed.")
        root_identity_value = loads_strict_json(
            _read_regular_file_at(control_descriptor, "root-identity.json")
        )
        if not isinstance(root_identity_value, dict):
            raise ProvenanceError("Greenfield root identity must be an object.")
        recorded_metadata = _validate_greenfield_root_identity(
            root_identity_value,
            intent=intent,
        )
        _verify_greenfield_root_metadata(root_descriptor, recorded_metadata)
        try:
            marker_current = _read_regular_file_at(
                root_descriptor,
                GREENFIELD_ROOT_MARKER,
            )
        except FileNotFoundError:
            state = (
                "completed_cleanup_pending"
                if completed_present
                else "cleanup_pending"
            )
        else:
            if marker_current != marker_bytes:
                raise ProvenanceError("Greenfield final-root marker differs.")
            state = "published"
        return GreenfieldRootSession(
            project_root=target,
            parent_path=parent,
            target_name=target.name,
            control_name=control_name,
            control_entry_name=active_control_name,
            parent_descriptor=parent_descriptor,
            control_descriptor=control_descriptor,
            root_descriptor=root_descriptor,
            lock_descriptor=lock_descriptor,
            intent=intent,
            marker_bytes=marker_bytes,
            root_identity=root_identity_value,
            state=state,
        )
    except BaseException:
        held_locks = {
            descriptor
            for descriptor in (lock_descriptor, cleanup_anchor_descriptor)
            if descriptor is not None
        }
        for descriptor in held_locks:
            if fcntl is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
        descriptors = {
            descriptor
            for descriptor in (
                lock_descriptor,
                cleanup_anchor_descriptor,
                root_descriptor,
                control_descriptor,
                parent_descriptor,
            )
            if descriptor is not None
        }
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _unlink_exact_regular_at(
    parent_descriptor: int,
    name: str,
    expected: bytes,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        before = os.fstat(descriptor)
        live = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (live.st_dev, live.st_ino)
            or _read_regular_file_at(parent_descriptor, name) != expected
        ):
            raise ProvenanceError(
                f"Greenfield cleanup file changed and was preserved: {name}"
            )
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ProvenanceError(
                f"Greenfield cleanup file changed and was preserved: {name}"
            )
        os.unlink(name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(descriptor)


def _unlink_exact_held_regular_at(
    parent_descriptor: int,
    name: str,
    held_descriptor: int,
    expected: bytes,
) -> None:
    """Unlink only the live pathname represented by an already-held descriptor."""

    before = os.fstat(held_descriptor)
    live = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    os.lseek(held_descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        block = os.read(held_descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    after = os.fstat(held_descriptor)
    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.getuid()
        or before.st_gid != os.getgid()
        or (before.st_dev, before.st_ino) != (live.st_dev, live.st_ino)
        or (before.st_dev, before.st_ino)
        != (current.st_dev, current.st_ino)
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        or b"".join(chunks) != expected
    ):
        raise ProvenanceError(
            f"Greenfield held cleanup file changed and was preserved: {name}"
        )
    os.unlink(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def finalize_greenfield_root(
    session: GreenfieldRootSession,
    *,
    exact_operation_current: bool,
) -> None:
    """Remove transient root authority only after an exact committed receipt."""

    if not exact_operation_current:
        raise ProvenanceError(
            "Greenfield root intent cannot be finalized without an exact receipt."
        )
    if session.closed:
        raise ProvenanceError("Greenfield root session is already closed.")
    parent_opened = os.fstat(session.parent_descriptor)
    parent_live = os.lstat(session.parent_path)
    root_opened = os.fstat(session.root_descriptor)
    root_live = os.stat(
        session.target_name,
        dir_fd=session.parent_descriptor,
        follow_symlinks=False,
    )
    if (
        (parent_opened.st_dev, parent_opened.st_ino)
        != (parent_live.st_dev, parent_live.st_ino)
        or (root_opened.st_dev, root_opened.st_ino)
        != (root_live.st_dev, root_live.st_ino)
    ):
        raise ProvenanceError("Greenfield cleanup binding changed.")
    recorded_metadata = _validate_greenfield_root_identity(
        session.root_identity,
        intent=session.intent,
    )
    _verify_greenfield_root_metadata(session.root_descriptor, recorded_metadata)
    intent_bytes = canonical_bytes(session.intent) + b"\n"
    identity_bytes = canonical_bytes(session.root_identity) + b"\n"
    tombstone_name = (
        f"{session.control_name}.completed."
        f"{session.intent['request_sha256'][:24]}"
    )
    anchor_name = tombstone_name + ".anchor"
    try:
        control_live = os.stat(
            session.control_entry_name,
            dir_fd=session.parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        control_live = None
    if control_live is None:
        if (
            session.state != "completed_cleanup_pending"
            or session.cleanup_anchor_name != anchor_name
            or session.cleanup_anchor_descriptor is None
        ):
            raise ProvenanceError("Greenfield cleanup envelope disappeared.")
    else:
        control_opened = os.fstat(session.control_descriptor)
        if (
            not stat.S_ISDIR(control_live.st_mode)
            or (control_opened.st_dev, control_opened.st_ino)
            != (control_live.st_dev, control_live.st_ino)
        ):
            raise ProvenanceError("Greenfield cleanup envelope binding changed.")
        entries = set(os.listdir(session.control_descriptor))
        if session.state == "completed_cleanup_pending":
            if not entries <= {"intent.json", "lock", "root-identity.json"}:
                raise ProvenanceError(
                    "Greenfield completion cleanup has unknown entries."
                )
            if "intent.json" in entries and _read_regular_file_at(
                session.control_descriptor,
                "intent.json",
            ) != intent_bytes:
                raise ProvenanceError(
                    "Greenfield completion intent changed and was preserved."
                )
            if "lock" in entries and _read_regular_file_at(
                session.control_descriptor,
                "lock",
            ) != b"":
                raise ProvenanceError(
                    "Greenfield completion lock changed and was preserved."
                )
            if "root-identity.json" in entries and _read_regular_file_at(
                session.control_descriptor,
                "root-identity.json",
            ) != identity_bytes:
                raise ProvenanceError(
                    "Greenfield completion root identity changed and was preserved."
                )
            if (
                "root-identity.json" in entries
                and session.cleanup_anchor_name is not None
            ):
                raise ProvenanceError(
                    "Greenfield completion has duplicate root-identity authority."
                )
        elif (
            entries != {"intent.json", "lock", "root-identity.json"}
            or _read_regular_file_at(session.control_descriptor, "intent.json")
            != intent_bytes
            or _read_regular_file_at(session.control_descriptor, "lock") != b""
            or _read_regular_file_at(
                session.control_descriptor,
                "root-identity.json",
            )
            != identity_bytes
        ):
            raise ProvenanceError(
                "Greenfield control cleanup state differs and was preserved."
            )
    if session.state == "published":
        _unlink_exact_regular_at(
            session.root_descriptor,
            GREENFIELD_ROOT_MARKER,
            session.marker_bytes,
        )
        session.state = "cleanup_pending"
    elif session.state not in {
        "cleanup_pending",
        "completed_cleanup_pending",
    }:
        raise ProvenanceError("Greenfield root session state is invalid.")
    if session.state != "completed_cleanup_pending":
        rename_no_replace_at(
            session.parent_descriptor,
            session.control_entry_name,
            session.parent_descriptor,
            tombstone_name,
        )
        os.fsync(session.parent_descriptor)
        session.control_entry_name = tombstone_name
        session.state = "completed_cleanup_pending"
    elif session.control_entry_name != tombstone_name:
        raise ProvenanceError("Greenfield completion envelope binding is invalid.")

    if session.cleanup_anchor_name is None:
        rename_no_replace_at(
            session.control_descriptor,
            "root-identity.json",
            session.parent_descriptor,
            anchor_name,
        )
        os.fsync(session.control_descriptor)
        os.fsync(session.parent_descriptor)
        anchor_descriptor, anchor_bytes = _acquire_greenfield_cleanup_anchor(
            session.parent_descriptor,
            anchor_name,
        )
        if anchor_bytes != identity_bytes:
            os.close(anchor_descriptor)
            raise ProvenanceError(
                "Greenfield cleanup anchor differs from the root identity."
            )
        session.cleanup_anchor_name = anchor_name
        session.cleanup_anchor_descriptor = anchor_descriptor
    elif session.cleanup_anchor_name != anchor_name:
        raise ProvenanceError("Greenfield cleanup anchor binding is invalid.")

    try:
        os.stat(
            session.control_entry_name,
            dir_fd=session.parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        envelope_present = False
    else:
        envelope_present = True
    if envelope_present:
        remaining = set(os.listdir(session.control_descriptor))
        if not remaining <= {"intent.json", "lock"}:
            raise ProvenanceError(
                "Greenfield completion cleanup has unknown remaining entries."
            )
        if "intent.json" in remaining:
            _unlink_exact_regular_at(
                session.control_descriptor,
                "intent.json",
                intent_bytes,
            )
        if "lock" in remaining:
            _unlink_exact_regular_at(session.control_descriptor, "lock", b"")
        if os.listdir(session.control_descriptor):
            raise ProvenanceError(
                "Greenfield completion envelope is not empty after exact cleanup."
            )
        held_control = os.fstat(session.control_descriptor)
        live_control = os.stat(
            session.control_entry_name,
            dir_fd=session.parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(held_control.st_mode)
            or (held_control.st_dev, held_control.st_ino)
            != (live_control.st_dev, live_control.st_ino)
        ):
            raise ProvenanceError(
                "Greenfield completion envelope changed before removal."
            )
        os.rmdir(session.control_entry_name, dir_fd=session.parent_descriptor)
        os.fsync(session.parent_descriptor)
    if session.cleanup_anchor_descriptor is None:
        raise ProvenanceError("Greenfield cleanup anchor descriptor is unavailable.")
    _unlink_exact_held_regular_at(
        session.parent_descriptor,
        anchor_name,
        session.cleanup_anchor_descriptor,
        identity_bytes,
    )
    session.close()


def _enrollment_temp_path(root: Path, scope: dict[str, Any]) -> Path:
    enrollment = scope.get("enrollment")
    plan_sha256 = enrollment.get("plan_sha256") if isinstance(enrollment, dict) else None
    if not isinstance(plan_sha256, str) or len(plan_sha256) != 64:
        raise ProvenanceError("Enrollment scope does not contain a valid authorization digest.")
    return root / ".naos" / f"upgrade-v1.enrolling.{plan_sha256[:24]}"


def _validate_or_remove_partial_enrollment(
    path: Path,
    *,
    owner: dict[str, Any],
    scope: dict[str, Any],
) -> None:
    if _existing_kind(path) == "absent":
        return
    if _existing_kind(path) != "directory":
        raise ProvenanceError(f"Unsafe enrollment preparation is preserved and refused: {path}")
    expected_files = {
        "OWNER.json": canonical_bytes(owner) + b"\n",
        "provenance/scopes/repository-intelligence.json": canonical_bytes(scope) + b"\n",
        "locks/control-root-enrollment.lock": b"",
        "locks/repository-intelligence.lock": b"",
    }
    expected_pending = {
        _pending_enrollment_path(path / relative).relative_to(path).as_posix()
        for relative in expected_files
    }
    expected_directories = {
        "provenance",
        "provenance/scopes",
        "transactions",
        "transactions/repository-intelligence",
        "locks",
        "state",
    }
    for child in sorted(path.rglob("*"), key=lambda item: len(item.relative_to(path).parts), reverse=True):
        relative = child.relative_to(path).as_posix()
        kind = _existing_kind(child)
        if kind == "directory" and relative in expected_directories:
            continue
        if kind == "file" and relative in expected_files:
            if _safe_file_bytes(child) != expected_files[relative]:
                raise ProvenanceError(
                    f"Enrollment preparation content mismatch is preserved and refused: {child}"
                )
            continue
        if kind == "file" and relative in expected_pending:
            metadata = os.lstat(child)
            if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ProvenanceError(
                    f"Unsafe enrollment pending-file metadata is preserved and refused: {child}"
                )
            continue
        raise ProvenanceError(f"Unknown enrollment preparation entry is preserved and refused: {child}")
    for child in sorted(path.rglob("*"), key=lambda item: len(item.relative_to(path).parts), reverse=True):
        if child.is_dir():
            child.rmdir()
        else:
            child.unlink()
    path.rmdir()
    _fsync_dir(path.parent)


def commit_enrollment(
    project_root: Path,
    inspection: ScopeInspection,
    *,
    owner: dict[str, Any] | None,
    scope: dict[str, Any],
) -> ScopeInspection:
    root = project_root.resolve(strict=True)
    current = inspect_scope(root, governed_root=inspection.governed_root)
    if owner is None and current.status == "valid":
        with _bound_control_root(root) as control_descriptor:
            existing_scope = _load_object_at(
                control_descriptor,
                "provenance/scopes/repository-intelligence.json",
                label="repository-intelligence scope",
            )
            if existing_scope != scope:
                raise ProvenanceError(
                    "Completed repository-intelligence enrollment differs from the "
                    "requested scope."
                )
        return current
    if (
        current.status != inspection.status
        or current.project_id != inspection.project_id
        or current.owner_integrity != inspection.owner_integrity
        or current.scope_integrity != inspection.scope_integrity
        or current.governed_root != inspection.governed_root
        or current.refusal != inspection.refusal
    ):
        raise ProvenanceError("Provenance state changed after planning; prepare a new enrollment plan.")
    governed_path = root / inspection.governed_root
    if _existing_kind(governed_path) != "absent":
        raise ProvenanceError(
            "The governed root appeared after planning; enrollment preserved it and refused ownership."
        )
    if owner is not None:
        naos_dir = root / ".naos"
        naos_kind = _existing_kind(naos_dir)
        if naos_kind == "absent":
            try:
                _mkdir_durable(naos_dir)
            except FileExistsError:
                metadata = os.lstat(naos_dir)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ProvenanceError(
                        f"Refusing unsafe provenance directory: {naos_dir}"
                    )
        elif naos_kind != "directory":
            raise ProvenanceError(f"Refusing unsafe provenance directory: {naos_dir}")
        with _stable_directory_lock(naos_dir) as naos_descriptor:
            if inspection.governed_root != CONTEXT_RELATIVE.as_posix():
                raise ProvenanceError(
                    "Repository-intelligence governed root is outside its canonical binding."
                )
            _publish_prepared_tree_at(
                naos_descriptor,
                preparation_name=_enrollment_temp_path(root, scope).name,
                final_name=CONTROL_ROOT.name,
                preparation_prefixes=(
                    "upgrade-v1.enrolling.",
                    "upgrade-v1.managed-content-enrolling.",
                ),
                expected_directories={
                    "provenance",
                    "provenance/scopes",
                    "transactions",
                    "transactions/repository-intelligence",
                    "locks",
                    "state",
                },
                expected_files={
                    "OWNER.json": canonical_bytes(owner) + b"\n",
                    "provenance/scopes/repository-intelligence.json": canonical_bytes(scope) + b"\n",
                    "locks/control-root-enrollment.lock": b"",
                    "locks/repository-intelligence.lock": b"",
                },
            )
    else:
        if inspection.governed_root != CONTEXT_RELATIVE.as_posix():
            raise ProvenanceError(
                "Repository-intelligence governed root is outside its canonical binding."
            )
        with _bound_control_root(root) as control_descriptor:
            with _stable_file_lock_at(
                control_descriptor,
                "locks/control-root-enrollment.lock",
            ):
                owner_value = _load_object_at(
                    control_descriptor,
                    "OWNER.json",
                    label="OWNER.json",
                )
                current_project_id, current_owner_integrity = _validate_owner(
                    owner_value
                )
                if (
                    current_project_id != inspection.project_id
                    or current_owner_integrity != inspection.owner_integrity
                ):
                    raise ProvenanceError(
                        "Repository-intelligence owner binding changed during enrollment."
                    )
                state_descriptor = _open_relative_directory_at(
                    control_descriptor,
                    "state",
                )
                try:
                    try:
                        os.stat(
                            "repository-intelligence",
                            dir_fd=state_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise ProvenanceError(
                            "The governed root appeared during scope enrollment; "
                            "ownership was refused."
                        )
                finally:
                    os.close(state_descriptor)
                _ensure_empty_directory_at(
                    control_descriptor,
                    "transactions/repository-intelligence",
                )
                _publish_exact_file_at(
                    control_descriptor,
                    "locks/repository-intelligence.lock",
                    b"",
                )
                _publish_exact_file_at(
                    control_descriptor,
                    "provenance/scopes/repository-intelligence.json",
                    canonical_bytes(scope) + b"\n",
                )
    result = inspect_scope(root, governed_root=inspection.governed_root)
    if result.status != "valid":
        raise ProvenanceError(f"Enrollment did not produce valid capability provenance: {result.refusal}")
    return result


def _managed_content_scope_object(
    *,
    project_id: str,
    owner_integrity: str,
    authorization_digest: str,
    source_policy_sha256: str,
) -> dict[str, Any]:
    if (
        SHA256_RE.fullmatch(authorization_digest) is None
        or SHA256_RE.fullmatch(source_policy_sha256) is None
    ):
        raise ProvenanceError("Managed-content enrollment digests must be SHA-256 values.")
    return _with_integrity(
        {
            "schema": MANAGED_CONTENT_SCOPE_SCHEMA,
            "canonicalization": CANONICALIZATION,
            "project_id": project_id,
            "owner_integrity_sha3_512": owner_integrity,
            "scope_id": "managed-content",
            "capability_id": "CAP-CONTENT-AWARE-UPGRADE",
            "policy": {
                "ownership_inference": "forbidden",
                "existing_without_valid_base": "preserve_and_refuse",
                "manifest_path": MANAGED_CONTENT_MANIFEST_RELATIVE.as_posix(),
                "base_store": MANAGED_CONTENT_BASES_RELATIVE.as_posix(),
                "receipt_root": MANAGED_CONTENT_RECEIPTS_RELATIVE.as_posix(),
                "transaction_root": MANAGED_CONTENT_TRANSACTIONS_RELATIVE.as_posix(),
                "lock_path": MANAGED_CONTENT_LOCK_RELATIVE.as_posix(),
                "allowed_initial_mutation": "absent_regular_files_only",
                "existing_content_replacement": "refused_without_reviewed_contract",
            },
            "enrollment": {
                "authorization_sha256": authorization_digest,
                "source_policy_sha256": source_policy_sha256,
            },
        }
    )


def _validate_managed_content_scope(
    value: dict[str, Any], *, project_id: str, owner_integrity: str
) -> str:
    expected_keys = {
        "schema",
        "canonicalization",
        "project_id",
        "owner_integrity_sha3_512",
        "scope_id",
        "capability_id",
        "policy",
        "enrollment",
        "integrity",
    }
    if set(value) != expected_keys or value.get("schema") != MANAGED_CONTENT_SCOPE_SCHEMA:
        raise ProvenanceError("Managed-content scope has an unsupported shape or schema.")
    if value.get("canonicalization") != CANONICALIZATION:
        raise ProvenanceError("Managed-content scope canonicalization is unsupported.")
    if value.get("project_id") != project_id or value.get("owner_integrity_sha3_512") != owner_integrity:
        raise ProvenanceError("Managed-content scope owner binding is invalid.")
    if value.get("scope_id") != "managed-content" or value.get("capability_id") != "CAP-CONTENT-AWARE-UPGRADE":
        raise ProvenanceError("Managed-content scope identity is invalid.")
    expected_policy = {
        "ownership_inference": "forbidden",
        "existing_without_valid_base": "preserve_and_refuse",
        "manifest_path": MANAGED_CONTENT_MANIFEST_RELATIVE.as_posix(),
        "base_store": MANAGED_CONTENT_BASES_RELATIVE.as_posix(),
        "receipt_root": MANAGED_CONTENT_RECEIPTS_RELATIVE.as_posix(),
        "transaction_root": MANAGED_CONTENT_TRANSACTIONS_RELATIVE.as_posix(),
        "lock_path": MANAGED_CONTENT_LOCK_RELATIVE.as_posix(),
        "allowed_initial_mutation": "absent_regular_files_only",
        "existing_content_replacement": "refused_without_reviewed_contract",
    }
    if value.get("policy") != expected_policy:
        raise ProvenanceError("Managed-content scope policy is invalid.")
    enrollment = value.get("enrollment")
    if not isinstance(enrollment, dict) or set(enrollment) != {
        "authorization_sha256",
        "source_policy_sha256",
    }:
        raise ProvenanceError("Managed-content scope enrollment binding is invalid.")
    for field in ("authorization_sha256", "source_policy_sha256"):
        digest = enrollment.get(field)
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ProvenanceError(f"Managed-content scope {field} is invalid.")
    return _validate_integrity(value, label="managed-content scope")


def inspect_managed_content_scope(project_root: Path) -> ManagedContentScopeInspection:
    root = project_root.resolve(strict=True)
    naos_path = root / ".naos"
    naos_kind = _existing_kind(naos_path)
    if naos_kind == "absent":
        return ManagedContentScopeInspection(
            "owner_enrollment_required", None, None, None
        )
    if naos_kind != "directory":
        return ManagedContentScopeInspection(
            "refused",
            None,
            None,
            None,
            "Project .naos control ancestor is unsafe.",
        )
    control_kind = _existing_kind(root / CONTROL_ROOT)
    if control_kind == "absent":
        return ManagedContentScopeInspection(
            "owner_enrollment_required", None, None, None
        )
    if control_kind != "directory":
        return ManagedContentScopeInspection(
            "refused", None, None, None, "Operation-control root is unsafe."
        )
    project_id: str | None = None
    owner_integrity: str | None = None
    try:
        with _bound_control_root(root) as control_descriptor:
            for relative in (
                ".",
                "provenance",
                "provenance/scopes",
                "transactions",
                "locks",
                "state",
            ):
                _validate_directory_at(control_descriptor, relative)
            _validate_regular_file_at(
                control_descriptor,
                "locks/control-root-enrollment.lock",
            )
            owner_value = _load_object_at(
                control_descriptor,
                "OWNER.json",
                label="OWNER.json",
            )
            project_id, owner_integrity = _validate_owner(owner_value)
            legacy_runtime = [
                relative
                for relative in LEGACY_MANAGED_CONTENT_RELATIVES
                if _relative_entry_metadata_at(
                    control_descriptor,
                    relative.relative_to(CONTROL_ROOT).as_posix(),
                )
                is not None
            ]
            if legacy_runtime:
                raise ProvenanceError(
                    "Legacy managed-content runtime is preserved and requires exact "
                    "recovery: "
                    + ", ".join(item.as_posix() for item in legacy_runtime)
                )
            runtime_metadata = _relative_entry_metadata_at(
                control_descriptor,
                MANAGED_CONTENT_ROOT_RELATIVE.name,
            )
            if runtime_metadata is None:
                return ManagedContentScopeInspection(
                    "enrollment_required", project_id, owner_integrity, None
                )
            if (
                stat.S_ISLNK(runtime_metadata.st_mode)
                or not stat.S_ISDIR(runtime_metadata.st_mode)
                or stat.S_IMODE(runtime_metadata.st_mode) != 0o700
            ):
                raise ProvenanceError("Managed-content runtime root is unsafe.")
            preparations = [
                name
                for name in os.listdir(control_descriptor)
                if name.startswith(".managed-content.enrolling.")
            ]
            if preparations:
                raise ProvenanceError(
                    "Managed-content enrollment preparation requires exact recovery: "
                    + ", ".join(sorted(preparations))
                )
            runtime_descriptor = _open_directory_at(
                control_descriptor,
                MANAGED_CONTENT_ROOT_RELATIVE.name,
            )
            try:
                direct_entries = set(os.listdir(runtime_descriptor))
                expected_direct_entries = {
                    "scope.json",
                    "lock",
                    "transactions",
                    "state",
                }
                if direct_entries != expected_direct_entries:
                    raise ProvenanceError(
                        "Managed-content runtime has missing or unknown direct entries: "
                        f"{sorted(direct_entries ^ expected_direct_entries)}"
                    )
                for relative in (".", "transactions", "state", "state/bases", "state/receipts"):
                    _validate_directory_at(runtime_descriptor, relative)
                _validate_regular_file_at(runtime_descriptor, "lock")
                scope_value = _load_object_at(
                    runtime_descriptor,
                    "scope.json",
                    label="managed-content scope",
                )
                scope_integrity = _validate_managed_content_scope(
                    scope_value,
                    project_id=project_id,
                    owner_integrity=owner_integrity,
                )
                source_policy_sha256 = str(
                    (scope_value.get("enrollment") or {}).get(
                        "source_policy_sha256"
                    )
                    or ""
                )
                state_descriptor = _open_relative_directory_at(
                    runtime_descriptor,
                    "state",
                )
                try:
                    state_entries = set(os.listdir(state_descriptor))
                    allowed_state_entries = {"bases", "receipts", "manifest.json"}
                    pending_manifest_entries = {
                        name
                        for name in state_entries
                        if re.fullmatch(
                            r"\.manifest\.json\.MC-[0-9a-f]{16}-[0-9a-f]{8}\.pending",
                            name,
                        )
                    }
                    unknown_state_entries = state_entries - (
                        allowed_state_entries | pending_manifest_entries
                    )
                    if unknown_state_entries:
                        raise ProvenanceError(
                            "Managed-content state has unknown entries: "
                            f"{sorted(unknown_state_entries)}"
                        )
                    if "manifest.json" in state_entries:
                        _validate_regular_file_at(state_descriptor, "manifest.json")
                finally:
                    os.close(state_descriptor)
            finally:
                os.close(runtime_descriptor)
    except (OSError, ProvenanceError) as exc:
        return ManagedContentScopeInspection(
            "refused", project_id, owner_integrity, None, str(exc)
        )
    return ManagedContentScopeInspection(
        "valid",
        project_id,
        owner_integrity,
        scope_integrity,
        source_policy_sha256=source_policy_sha256,
    )


def inspect_managed_content_manifest(
    project_root: Path,
) -> ManagedContentManifestInspection:
    """Return a strict read-only manifest snapshot or a diagnostic refusal.

    Missing, legacy, or malformed provenance never acquires ownership. Existing
    v1 entries are normalized for the v2 planner only after their scope,
    introducing plan, receipt, and recoverable base all validate; their stored
    ownership is copied verbatim.
    """

    root = project_root.resolve(strict=True)
    scope = inspect_managed_content_scope(root)
    if (
        scope.status != "valid"
        or not scope.project_id
        or not scope.scope_integrity
        or not scope.source_policy_sha256
    ):
        return ManagedContentManifestInspection(
            "diagnostic_only",
            scope.project_id,
            scope.scope_integrity,
            scope.source_policy_sha256,
            refusal=scope.refusal
            or "Existing project has no complete managed-content provenance; ownership inference is forbidden.",
        )
    try:
        snapshot = load_managed_content_manifest_snapshot(
            root,
            project_id=scope.project_id,
            scope_integrity_sha3_512=scope.scope_integrity,
            source_policy_sha256=scope.source_policy_sha256,
            manifest_path=root / MANAGED_CONTENT_MANIFEST_RELATIVE,
            bases_root=root / MANAGED_CONTENT_BASES_RELATIVE,
            receipts_root=root / MANAGED_CONTENT_RECEIPTS_RELATIVE,
        )
    except (OSError, ValueError, TransactionPrimitiveError) as exc:
        return ManagedContentManifestInspection(
            "diagnostic_only",
            scope.project_id,
            scope.scope_integrity,
            scope.source_policy_sha256,
            refusal=f"Managed-content provenance is invalid and preserved: {exc}",
        )
    if snapshot is None:
        return ManagedContentManifestInspection(
            "diagnostic_only",
            scope.project_id,
            scope.scope_integrity,
            scope.source_policy_sha256,
            refusal="Managed-content scope has no validated manifest; ownership inference is forbidden.",
        )
    source_schema = (snapshot.get("migration") or {}).get("source_schema")
    return ManagedContentManifestInspection(
        (
            "valid_v2"
            if source_schema == "naos.upgrade.managed_content_manifest.v2"
            else "valid_v1_normalized"
        ),
        scope.project_id,
        scope.scope_integrity,
        scope.source_policy_sha256,
        snapshot=snapshot,
    )


def _managed_content_owner_object(
    *,
    project_id: str,
    authorization_digest: str,
    source_policy_sha256: str,
) -> dict[str, Any]:
    return _with_integrity(
        {
            "schema": OWNER_SCHEMA,
            "canonicalization": CANONICALIZATION,
            "project_id": project_id,
            "control_root": CONTROL_ROOT.as_posix(),
            "owner_kind": "naos_operation_control_root",
            "created_by": {
                "kit_id": "naos-governance",
                "kit_version": "1.0.0",
                "source_commit": None,
                "source_manifest_sha256": source_policy_sha256,
            },
            "enrollment_authorization": {
                "plan_sha256": authorization_digest,
                "review_receipt_sha256": None,
            },
        }
    )


def _managed_content_enrollment_temp_path(
    root: Path, authorization_digest: str
) -> Path:
    return root / ".naos" / (
        "upgrade-v1.managed-content-enrolling."
        f"{authorization_digest[:24]}"
    )


def _managed_content_scope_temp_path(
    root: Path,
    authorization_digest: str,
) -> Path:
    return root / CONTROL_ROOT / (
        ".managed-content.enrolling." + authorization_digest[:24]
    )


def _validate_or_remove_partial_managed_content_scope_enrollment(
    path: Path,
    *,
    scope: dict[str, Any],
) -> None:
    if _existing_kind(path) == "absent":
        return
    if _existing_kind(path) != "directory":
        raise ProvenanceError(
            "Unsafe managed-content scope preparation is preserved and refused: "
            f"{path}"
        )
    expected_files = {
        "scope.json": canonical_bytes(scope) + b"\n",
        "lock": b"",
    }
    expected_directories = {
        "transactions",
        "state",
        "state/bases",
        "state/receipts",
    }
    expected_pending = {
        _pending_enrollment_path(path / relative).relative_to(path).as_posix()
        for relative in expected_files
    }
    for child in sorted(
        path.rglob("*"),
        key=lambda item: len(item.relative_to(path).parts),
        reverse=True,
    ):
        relative = child.relative_to(path).as_posix()
        kind = _existing_kind(child)
        if kind == "directory" and relative in expected_directories:
            continue
        if kind == "file" and relative in expected_files:
            if _safe_file_bytes(child) != expected_files[relative]:
                raise ProvenanceError(
                    "Managed-content scope preparation content differs: "
                    f"{child}"
                )
            continue
        if kind == "file" and relative in expected_pending:
            metadata = os.lstat(child)
            if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ProvenanceError(
                    "Unsafe managed-content scope pending file is preserved: "
                    f"{child}"
                )
            continue
        raise ProvenanceError(
            "Unknown managed-content scope preparation entry is preserved: "
            f"{child}"
        )
    for child in sorted(
        path.rglob("*"),
        key=lambda item: len(item.relative_to(path).parts),
        reverse=True,
    ):
        if child.is_dir():
            child.rmdir()
        else:
            child.unlink()
    path.rmdir()
    _fsync_dir(path.parent)


def _publish_managed_content_scope_runtime(
    root: Path,
    *,
    control_descriptor: int,
    scope: dict[str, Any],
    authorization_digest: str,
) -> None:
    _publish_prepared_tree_at(
        control_descriptor,
        preparation_name=_managed_content_scope_temp_path(
            root,
            authorization_digest,
        ).name,
        final_name=MANAGED_CONTENT_ROOT_RELATIVE.name,
        preparation_prefixes=(".managed-content.enrolling.",),
        expected_directories={
            "transactions",
            "state",
            "state/bases",
            "state/receipts",
        },
        expected_files={
            "scope.json": canonical_bytes(scope) + b"\n",
            "lock": b"",
        },
    )


def _validate_or_remove_partial_managed_content_enrollment(
    path: Path,
    *,
    owner: dict[str, Any],
    scope: dict[str, Any],
) -> None:
    if _existing_kind(path) == "absent":
        return
    if _existing_kind(path) != "directory":
        raise ProvenanceError(
            f"Unsafe managed-content enrollment preparation is preserved and refused: {path}"
        )
    expected_files = {
        "OWNER.json": canonical_bytes(owner) + b"\n",
        "managed-content/scope.json": canonical_bytes(scope) + b"\n",
        "locks/control-root-enrollment.lock": b"",
        "managed-content/lock": b"",
    }
    expected_directories = {
        "provenance",
        "provenance/scopes",
        "transactions",
        "locks",
        "state",
        "managed-content",
        "managed-content/transactions",
        "managed-content/state",
        "managed-content/state/bases",
        "managed-content/state/receipts",
    }
    expected_pending = {
        _pending_enrollment_path(path / relative).relative_to(path).as_posix()
        for relative in expected_files
    }
    for child in sorted(
        path.rglob("*"),
        key=lambda item: len(item.relative_to(path).parts),
        reverse=True,
    ):
        relative = child.relative_to(path).as_posix()
        kind = _existing_kind(child)
        if kind == "directory" and relative in expected_directories:
            continue
        if kind == "file" and relative in expected_files:
            if _safe_file_bytes(child) != expected_files[relative]:
                raise ProvenanceError(
                    "Managed-content enrollment preparation content mismatch is "
                    f"preserved and refused: {child}"
                )
            continue
        if kind == "file" and relative in expected_pending:
            metadata = os.lstat(child)
            if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ProvenanceError(
                    "Unsafe managed-content enrollment pending file is preserved "
                    f"and refused: {child}"
                )
            continue
        raise ProvenanceError(
            f"Unknown managed-content enrollment entry is preserved and refused: {child}"
        )
    for child in sorted(
        path.rglob("*"),
        key=lambda item: len(item.relative_to(path).parts),
        reverse=True,
    ):
        if child.is_dir():
            child.rmdir()
        else:
            child.unlink()
    path.rmdir()
    _fsync_dir(path.parent)


def _commit_initial_managed_content_enrollment(
    root: Path,
    *,
    authorization_digest: str,
    source_policy_sha256: str,
) -> None:
    project_id = (
        "urn:uuid:"
        + str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"naos:managed-content:{root}:{authorization_digest}",
            )
        )
    )
    owner = _managed_content_owner_object(
        project_id=project_id,
        authorization_digest=authorization_digest,
        source_policy_sha256=source_policy_sha256,
    )
    owner_integrity = str(owner["integrity"]["value"])
    scope = _managed_content_scope_object(
        project_id=project_id,
        owner_integrity=owner_integrity,
        authorization_digest=authorization_digest,
        source_policy_sha256=source_policy_sha256,
    )
    naos_dir = root / ".naos"
    naos_kind = _existing_kind(naos_dir)
    if naos_kind == "absent":
        try:
            _mkdir_durable(naos_dir)
        except FileExistsError:
            metadata = os.lstat(naos_dir)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ProvenanceError(
                    f"Refusing unsafe provenance directory: {naos_dir}"
                )
    elif naos_kind != "directory":
        raise ProvenanceError(f"Refusing unsafe provenance directory: {naos_dir}")
    with _stable_directory_lock(naos_dir) as naos_descriptor:
        _publish_prepared_tree_at(
            naos_descriptor,
            preparation_name=_managed_content_enrollment_temp_path(
                root, authorization_digest
            ).name,
            final_name=CONTROL_ROOT.name,
            preparation_prefixes=(
                "upgrade-v1.enrolling.",
                "upgrade-v1.managed-content-enrolling.",
            ),
            expected_directories={
                "provenance",
                "provenance/scopes",
                "transactions",
                "locks",
                "state",
                "managed-content",
                "managed-content/transactions",
                "managed-content/state",
                "managed-content/state/bases",
                "managed-content/state/receipts",
            },
            expected_files={
                "OWNER.json": canonical_bytes(owner) + b"\n",
                "managed-content/scope.json": canonical_bytes(scope) + b"\n",
                "locks/control-root-enrollment.lock": b"",
                "managed-content/lock": b"",
            },
        )


def commit_managed_content_enrollment(
    project_root: Path,
    *,
    authorization_digest: str,
    source_policy_sha256: str,
) -> ManagedContentScopeInspection:
    root = project_root.resolve(strict=True)
    opening = inspect_managed_content_scope(root)
    if opening.status == "valid":
        return opening
    if opening.status == "owner_enrollment_required":
        _commit_initial_managed_content_enrollment(
            root,
            authorization_digest=authorization_digest,
            source_policy_sha256=source_policy_sha256,
        )
        result = inspect_managed_content_scope(root)
        if result.status != "valid":
            raise ProvenanceError(
                result.refusal
                or "Initial managed-content enrollment did not validate."
            )
        return result
    if opening.status != "enrollment_required" or not opening.project_id or not opening.owner_integrity:
        raise ProvenanceError(opening.refusal or "Managed-content enrollment is unavailable.")
    scope = _managed_content_scope_object(
        project_id=opening.project_id,
        owner_integrity=opening.owner_integrity,
        authorization_digest=authorization_digest,
        source_policy_sha256=source_policy_sha256,
    )
    with _bound_control_root(root) as control_descriptor:
        with _stable_file_lock_at(
            control_descriptor,
            "locks/control-root-enrollment.lock",
        ):
            owner_value = _load_object_at(
                control_descriptor,
                "OWNER.json",
                label="OWNER.json",
            )
            current_project_id, current_owner_integrity = _validate_owner(owner_value)
            if (
                current_project_id != opening.project_id
                or current_owner_integrity != opening.owner_integrity
            ):
                raise ProvenanceError(
                    "Managed-content owner binding changed during enrollment."
                )
            try:
                os.stat(
                    MANAGED_CONTENT_ROOT_RELATIVE.name,
                    dir_fd=control_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise ProvenanceError(
                    "Managed-content runtime appeared during enrollment."
                )
            _publish_managed_content_scope_runtime(
                root,
                control_descriptor=control_descriptor,
                scope=scope,
                authorization_digest=authorization_digest,
            )
    result = inspect_managed_content_scope(root)
    if result.status != "valid":
        raise ProvenanceError(
            result.refusal or "Managed-content enrollment did not validate."
        )
    return result
