"""RI-specific publication and recovery over the native v2 operation engine.

This is an internal lifecycle adapter. Its caller must revalidate the public
source/rules/profile/reviewer contract under the supplied callback. It does not
relax the public activation gate. Unknown or incompletely witnessed objects are
preserved. The failure model is application-process interruption, not power loss.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import ntpath
from pathlib import Path
import re
from typing import Any, Callable, Iterator
import uuid

from .canonical import canonical_bytes, canonical_sha256, loads_strict_json
from .repository_intelligence_windows import (
    MAX_FILE_BYTES,
    NativeIdentity,
    RIStorageConflict,
    WindowsRIStorage,
)
from .repository_intelligence_windows_enrollment import (
    GOVERNED_ROOT,
    RECORD_PATH,
    WindowsRIEnrollment,
    _decode as decode_enrollment,
)
from .windows_coordinator import _decode
from .windows_handles import validate_component
from .windows_operation import Publication, WindowsOperation, WindowsOperationSpec
from .windows_rename_identity import identity_from_record, identity_record
from .windows_restoring_backend import WindowsRestoringBackend

RUNTIME = ".naos/upgrade-v1/windows-ri-runtime"
BOOTSTRAP = ".naos/upgrade-v1/windows-ri-runtime.json"
BOOTSTRAP_SCHEMA = "naos.repository_intelligence.windows_bootstrap.v1"
PREPARATION_SCHEMA = "naos.repository_intelligence.windows_preparation.v1"
POINTER_SCHEMA = "naos.repository_intelligence.windows_active.v1"
RECEIPT_SCHEMA = "naos.repository_intelligence.windows_activation_receipt.v1"
STATE = ".naos/upgrade-v1/state"
DIRECTORIES = (
    RUNTIME,
    RUNTIME + "/operations",
    RUNTIME + "/preparations",
    RUNTIME + "/staging",
    RUNTIME + "/receipts",
    RUNTIME + "/directory-template",
    GOVERNED_ROOT,
    GOVERNED_ROOT + "/generations",
)
FILES = (RUNTIME + "/file-template", RUNTIME + "/scope.lock")
ACTIVE = GOVERNED_ROOT + "/active.json"
MAX_RECORD = 4 * 1024 * 1024


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: Any, count: int = 64) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch("[0-9a-f]{" + str(count) + "}", value) is not None
    )


def _operation_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"WOP-[0-9a-f]{16}", value):
        raise RIStorageConflict("Invalid RI operation ID")
    return value


def _implementation() -> dict[str, str]:
    base = Path(__file__).parent
    return {
        name: _sha((base / name).read_bytes())
        for name in (
            "canonical.py",
            "repository_intelligence_windows.py",
            "repository_intelligence_windows_enrollment.py",
            "repository_intelligence_windows_runtime.py",
            "windows_handles.py",
            "windows_backend.py",
            "windows_exchange.py",
            "windows_coordinator.py",
            "windows_operation.py",
            "windows_rename_identity.py",
            "windows_restoring_backend.py",
        )
    }


class WindowsRIRuntime:
    def __init__(self, storage: WindowsRIStorage):
        self.storage = storage
        self.enrollment = WindowsRIEnrollment(storage)

    def _absolute(self, relative: str) -> str:
        # Derive from the pinned root, never a path supplied by a journal.
        return ntpath.join(self.storage.project_root, *relative.split("/"))

    def _json(self, relative: str) -> tuple[dict[str, Any], bytes]:
        raw, _ = self.storage.read_file(relative, limit=MAX_RECORD)
        try:
            value = loads_strict_json(raw)
            if not isinstance(value, dict) or canonical_bytes(value) != raw:
                raise ValueError("Noncanonical object")
        except (ValueError, TypeError) as exc:
            raise RIStorageConflict("Invalid RI lifecycle record") from exc
        return value, raw

    def _publish_record(self, relative: str, value: dict[str, Any]) -> None:
        raw = canonical_bytes(value)
        pending = relative + ".pending"
        identity = self.storage.write_new(pending, raw)
        self.storage.publish_no_replace(
            pending, relative, identity, content_sha256=_sha(raw)
        )

    def _enrollment_binding(self) -> dict[str, Any]:
        inspected = self.enrollment._inspect_record()
        if inspected is None:
            raise RIStorageConflict("Native RI enrollment is required")
        return {
            "record_sha256": inspected.record_sha256,
            "record_identity": inspected.record_identity.record(),
            "project_id": inspected.project_id,
            "enrollment_plan_sha256": inspected.enrollment_plan_sha256,
        }

    def bootstrap(self, *, revalidate: Callable[[], None]) -> dict[str, Any]:
        """Create explicit ownership witnesses; never adopt a partial bootstrap."""
        if not callable(revalidate):
            raise RIStorageConflict("RI public authority revalidation is required")
        if self.storage.identity_if_present(BOOTSTRAP, kind="file") is not None:
            with self.locked() as (_lock, record):
                revalidate()
                return record
        self.enrollment.inspect()  # Existing generated root must still be absent.
        binding = self._enrollment_binding()
        for path in (RUNTIME, GOVERNED_ROOT):
            if self.storage.identity_if_present(path, kind="directory") is not None:
                raise RIStorageConflict(
                    "Unwitnessed RI bootstrap requires owner reconciliation"
                )
        if (
            self.storage.identity_if_present(BOOTSTRAP + ".pending", kind="file")
            is not None
        ):
            raise RIStorageConflict("Incomplete RI bootstrap receipt is preserved")
        revalidate()
        enrollment_raw, _ = self.storage.read_file(RECORD_PATH)
        enrolled_parents = decode_enrollment(enrollment_raw)["parents"]
        dirs: dict[str, NativeIdentity] = {
            p: NativeIdentity.from_record(v) for p, v in enrolled_parents.items()
        }
        files = {}
        with ExitStack() as stack:
            stack.enter_context(self.storage.pin_directories(dirs))
            stack.enter_context(
                self.storage.pin_files({RECORD_PATH: binding["record_sha256"]})
            )
            state = self.storage.identity_if_present(STATE, kind="directory")
            dirs[STATE] = state or self.storage.create_directory(STATE)
            stack.enter_context(self.storage.pin_directories({STATE: dirs[STATE]}))
            for path in DIRECTORIES:
                dirs[path] = self.storage.create_directory(path)
                stack.enter_context(self.storage.pin_directories({path: dirs[path]}))
            for path in FILES:
                files[path] = self.storage.write_new(path, b"").record()
            record = {
                "schema": BOOTSTRAP_SCHEMA,
                "enrollment": binding,
                "directories": {p: i.record() for p, i in dirs.items()},
                "files": files,
            }
            revalidate()
            self._publish_record(BOOTSTRAP, record)
        with self.locked() as (_lock, checked):
            return checked

    @contextmanager
    def bootstrap_pins(self) -> Iterator[dict[str, Any]]:
        """Read-only ownership proof, also usable inside an existing RI lock."""
        record, raw = self._json(BOOTSTRAP)
        if (
            set(record) != {"schema", "enrollment", "directories", "files"}
            or record["schema"] != BOOTSTRAP_SCHEMA
            or record["enrollment"] != self._enrollment_binding()
            or set(record["directories"])
            != {".naos", ".naos/upgrade-v1", STATE, *DIRECTORIES}
            or set(record["files"]) != set(FILES)
        ):
            raise RIStorageConflict("RI bootstrap ownership binding differs")
        dirs = {
            p: NativeIdentity.from_record(v) for p, v in record["directories"].items()
        }
        files = {p: NativeIdentity.from_record(v) for p, v in record["files"].items()}
        if any(i.kind != "directory" for i in dirs.values()) or any(
            i.kind != "file" for i in files.values()
        ):
            raise RIStorageConflict("RI bootstrap object kind differs")
        with ExitStack() as stack:
            stack.enter_context(self.storage.pin_directories(dirs))
            stack.enter_context(
                self.storage.pin_files(
                    {
                        BOOTSTRAP: _sha(raw),
                        RECORD_PATH: record["enrollment"]["record_sha256"],
                    }
                )
            )
            if record["enrollment"] != self._enrollment_binding():
                raise RIStorageConflict(
                    "RI enrollment changed before ownership pinning"
                )
            stack.enter_context(
                self.storage.pin_files({RUNTIME + "/file-template": _sha(b"")})
            )
            for path, identity in files.items():
                if path.endswith("/scope.lock"):
                    with self.storage._parent(path) as (parent, name):
                        with self.storage.handles.open_child(
                            parent, name, kind="file"
                        ) as child:
                            if (
                                self.storage._identity(child) != identity
                                or child.info().size != 0
                            ):
                                raise RIStorageConflict("RI scope lock changed")
                elif self.storage.read_file(path) != (b"", identity):
                    raise RIStorageConflict("RI bootstrap template changed")
            if set(self.storage.children(RUNTIME)) != {
                "operations",
                "preparations",
                "staging",
                "receipts",
                "directory-template",
                "file-template",
                "scope.lock",
            }:
                raise RIStorageConflict("Unknown RI runtime object is preserved")
            if self.storage.children(RUNTIME + "/directory-template"):
                raise RIStorageConflict("RI directory template is not empty")
            if set(self.storage.children(GOVERNED_ROOT)) - {
                "generations",
                "active.json",
            }:
                raise RIStorageConflict("Unknown RI context object is preserved")
            yield record

    @contextmanager
    def locked(self) -> Iterator[tuple[Any, dict[str, Any]]]:
        """Hold RI-specific lock and all bootstrap ancestors for the whole action."""
        with self.bootstrap_pins() as record:
            expected = NativeIdentity.from_record(
                record["files"][RUNTIME + "/scope.lock"]
            )
            with self.storage.lock(RUNTIME + "/scope.lock", expected) as lock:
                yield lock, record

    def _validate_request(self, request: Any, files: Any) -> None:
        if (
            not isinstance(request, dict)
            or set(request)
            not in (
                {"public_plan_sha256", "bundle_sha256", "generation_id"},
                {
                    "public_plan_sha256",
                    "bundle_sha256",
                    "generation_id",
                    "authorization",
                },
            )
            or (
                "authorization" in request
                and not isinstance(request["authorization"], dict)
            )
            or not _hex(request["public_plan_sha256"])
            or not _hex(request["bundle_sha256"])
            or not isinstance(request["generation_id"], str)
            or not re.fullmatch(r"RI-[0-9a-f]{24}", request["generation_id"])
            or not isinstance(files, dict)
            or not 1 <= len(files) <= 32
        ):
            raise RIStorageConflict("Invalid RI lifecycle request")
        for name, data in files.items():
            if (
                not isinstance(name, str)
                or validate_component(name) != name
                or "/" in name
                or not isinstance(data, bytes)
                or len(data) > MAX_FILE_BYTES
            ):
                raise RIStorageConflict("Invalid RI generation member")
        if len({n.casefold() for n in files}) != len(files):
            raise RIStorageConflict("Aliased RI generation members")
        if {"active.json", "activation-receipt.json", "previous-active.json"} & {
            n.casefold() for n in files
        }:
            raise RIStorageConflict("Reserved RI generation member")

    def _paths(
        self, op: str, generation: str, names: list[str], replacement: bool
    ) -> dict[str, str]:
        stage = RUNTIME + "/staging/" + op
        result = {}
        for index, name in enumerate(names):
            result["content-" + str(index)] = (
                GOVERNED_ROOT + "/generations/" + generation + "/" + name
            )
            result["staged-" + str(index)] = stage + "/" + name
        result.update(
            {
                "receipt": RUNTIME + "/receipts/" + op + ".json",
                "staged-receipt": stage + "/activation-receipt.json",
                "pointer": ACTIVE,
                "staged-pointer": stage + "/active.json",
            }
        )
        if replacement:
            result["backup"] = stage + "/previous-active.json"
        return result

    def _spec(self, record: dict[str, Any]) -> WindowsOperationSpec:
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "schema",
                "operation_id",
                "request",
                "bootstrap_sha256",
                "implementation",
                "predecessor",
                "directories",
                "members",
                "publications",
                "pointer_sha256",
                "receipt_sha256",
            }
            or record["schema"] != PREPARATION_SCHEMA
            or record["implementation"] != _implementation()
        ):
            raise RIStorageConflict("RI preparation contract or implementation differs")
        op = _operation_id(record["operation_id"])
        request = record["request"]
        members = record["members"]
        if not isinstance(members, dict) or any(not _hex(v) for v in members.values()):
            raise RIStorageConflict("Invalid RI generation hashes")
        self._validate_request(request, {k: b"" for k in members})
        if {"active.json", "activation-receipt.json", "previous-active.json"} & set(
            members
        ):
            raise RIStorageConflict(
                "RI generation member conflicts with lifecycle records"
            )
        if not all(
            _hex(record[k])
            for k in ("bootstrap_sha256", "pointer_sha256", "receipt_sha256")
        ):
            raise RIStorageConflict("Invalid RI lifecycle digest")
        pred = record["predecessor"]
        if pred is not None:
            if (
                not isinstance(pred, dict)
                or set(pred) != {"operation_id", "pointer_sha256"}
                or not _hex(pred["pointer_sha256"])
            ):
                raise RIStorageConflict("Invalid RI predecessor")
            _operation_id(pred["operation_id"])
        expected_dirs = {
            RUNTIME + "/staging/" + op,
            GOVERNED_ROOT + "/generations/" + request["generation_id"],
        }
        if set(record["directories"]) != expected_dirs:
            raise RIStorageConflict("RI preparation namespace differs")
        for v in record["directories"].values():
            if NativeIdentity.from_record(v).kind != "directory":
                raise RIStorageConflict("RI prepared directory kind differs")
        names = sorted(members)
        paths = self._paths(op, request["generation_id"], names, pred is not None)
        rows = record["publications"]
        expected = [
            ("content", "create", "content-" + str(i), "staged-" + str(i), members[n])
            for i, n in enumerate(names)
        ]
        expected += [
            (
                "evidence",
                "create",
                "receipt",
                "staged-receipt",
                record["receipt_sha256"],
            ),
            (
                "manifest",
                "replace" if pred else "create",
                "pointer",
                "staged-pointer",
                record["pointer_sha256"],
            ),
        ]
        if not isinstance(rows, list) or len(rows) != len(expected):
            raise RIStorageConflict("RI publication inventory differs")
        pubs = []
        for row, (role, kind, target, staged, digest) in zip(rows, expected):
            keys = {"role", "kind", "target", "staged", "after"} | (
                {"backup", "before"} if kind == "replace" else set()
            )
            if (
                not isinstance(row, dict)
                or set(row) != keys
                or (row["role"], row["kind"], row["target"], row["staged"])
                != (role, kind, target, staged)
            ):
                raise RIStorageConflict("RI publication routing differs")
            after = identity_from_record(row["after"])
            before = identity_from_record(row["before"]) if kind == "replace" else None
            if after.content_sha256 != digest or (
                before is not None
                and (
                    row["backup"] != "backup"
                    or before.content_sha256 != pred["pointer_sha256"]
                )
            ):
                raise RIStorageConflict("RI publication content binding differs")
            pubs.append(
                Publication(
                    role, kind, target, staged, after, row.get("backup"), before
                )
            )
        spec = WindowsOperationSpec(
            op, record, {k: self._absolute(v) for k, v in paths.items()}, tuple(pubs), 2
        )
        spec.validate()
        return spec

    @contextmanager
    def _operation(
        self, spec: WindowsOperationSpec, lock: Any
    ) -> Iterator[WindowsOperation]:
        with ExitStack() as stack:
            dirs = {
                p: NativeIdentity.from_record(v)
                for p, v in spec.plan["directories"].items()
            }
            stack.enter_context(self.storage.pin_directories(dirs))
            handles = self.storage.handles
            opened = []
            for path, kind in (
                (RUNTIME + "/operations", "directory"),
                (RUNTIME + "/directory-template", "directory"),
                (RUNTIME + "/file-template", "file"),
            ):
                parent, name = stack.enter_context(self.storage._parent(path))
                opened.append(
                    stack.enter_context(
                        handles.open_child(
                            parent,
                            name,
                            kind=kind,
                            for_publish=kind == "directory",
                            pin_for_read=kind == "file",
                        )
                    )
                )
            yield stack.enter_context(
                WindowsOperation(handles, *opened, spec, held_scope_lock=lock)
            )

    def publish(
        self,
        request: dict[str, Any],
        files: dict[str, bytes],
        *,
        revalidate: Callable[[], None],
    ) -> dict[str, Any]:
        request = loads_strict_json(canonical_bytes(request))
        files = dict(files)
        self._validate_request(request, files)
        if {"active.json", "activation-receipt.json", "previous-active.json"} & set(
            files
        ):
            raise RIStorageConflict("Reserved RI generation member")
        self.bootstrap(revalidate=revalidate)
        with self.locked() as (lock, bootstrap):
            current, history = self._history(bootstrap)
            if current is not None and current["request"] == request:
                if current["members"] != {n: _sha(b) for n, b in files.items()}:
                    raise RIStorageConflict(
                        "Completed RI request has different generation bytes"
                    )
                revalidate()
                return current
            revalidate()
            op = "WOP-" + uuid.uuid4().hex[:16]
            generation = request["generation_id"]
            stage = RUNTIME + "/staging/" + op
            dest = GOVERNED_ROOT + "/generations/" + generation
            if self.storage.identity_if_present(dest, kind="directory") is not None:
                raise RIStorageConflict(
                    "Existing generation is preserved; create a new public plan"
                )
            pred = (
                None
                if current is None
                else {
                    "operation_id": current["operation_id"],
                    "pointer_sha256": history[current["operation_id"]][
                        "pointer_sha256"
                    ],
                }
            )
            receipt = {
                "schema": RECEIPT_SCHEMA,
                "operation_id": op,
                "request": request,
                "members": {n: _sha(b) for n, b in files.items()},
                "predecessor": pred,
            }
            receipt_raw = canonical_bytes(receipt)
            pointer = {
                **receipt,
                "schema": POINTER_SCHEMA,
                "receipt_sha256": _sha(receipt_raw),
            }
            pointer_raw = canonical_bytes(pointer)
            dirs = {}
            with ExitStack() as stack:
                for path in (stage, dest):
                    identity = self.storage.create_directory(path)
                    dirs[path] = identity.record()
                    stack.enter_context(self.storage.pin_directories({path: identity}))
                for name, data in files.items():
                    self.storage.write_new(stage + "/" + name, data)
                self.storage.write_new(stage + "/activation-receipt.json", receipt_raw)
                self.storage.write_new(stage + "/active.json", pointer_raw)
                paths = self._paths(op, generation, sorted(files), pred is not None)
                pubs = []
                with WindowsRestoringBackend(
                    self.storage.handles,
                    {k: self._absolute(v) for k, v in paths.items()},
                ) as backend:
                    for index, name in enumerate(sorted(files)):
                        pubs.append(
                            Publication(
                                "content",
                                "create",
                                "content-" + str(index),
                                "staged-" + str(index),
                                backend.observe("staged-" + str(index)),
                            )
                        )
                    pubs.append(
                        Publication(
                            "evidence",
                            "create",
                            "receipt",
                            "staged-receipt",
                            backend.observe("staged-receipt"),
                        )
                    )
                    before = (
                        self._spec(history[current["operation_id"]])
                        .publications[-1]
                        .after
                        if pred
                        else None
                    )
                    if backend.observe("pointer") != before:
                        raise RIStorageConflict(
                            "RI predecessor changed after history validation"
                        )
                    pubs.append(
                        Publication(
                            "manifest",
                            "replace" if pred else "create",
                            "pointer",
                            "staged-pointer",
                            backend.observe("staged-pointer"),
                            "backup" if pred else None,
                            before,
                        )
                    )
                rows = []
                for p in pubs:
                    row = {
                        "role": p.role,
                        "kind": p.kind,
                        "target": p.target,
                        "staged": p.staged,
                        "after": identity_record(p.after),
                    }
                    if p.before is not None:
                        row.update(backup=p.backup, before=identity_record(p.before))
                    rows.append(row)
                record = {
                    "schema": PREPARATION_SCHEMA,
                    "operation_id": op,
                    "request": request,
                    "bootstrap_sha256": canonical_sha256(bootstrap),
                    "implementation": _implementation(),
                    "predecessor": pred,
                    "directories": dirs,
                    "members": receipt["members"],
                    "publications": rows,
                    "pointer_sha256": _sha(pointer_raw),
                    "receipt_sha256": _sha(receipt_raw),
                }
                spec = self._spec(record)
                self._publish_record(RUNTIME + "/preparations/" + op + ".json", record)
                revalidate()
                with self._operation(spec, lock) as operation:
                    operation.apply()
            result, _ = self._history(bootstrap)
            if result != pointer:
                raise RIStorageConflict("RI committed pointer differs")
            return result

    def _journal(self, spec: WindowsOperationSpec) -> tuple[str, dict[str, Any]]:
        base = RUNTIME + "/operations/" + spec.operation_id
        if self.storage.identity_if_present(base, kind="directory") is None:
            self._prepared_without_journal(spec)
            return "prepared_without_journal", {}
        # Validate the exact constrained spec before letting the generic engine
        # see any journal-supplied absolute path.
        plan = _decode(self.storage.read_file(base + "/plan.json", limit=MAX_RECORD)[0])
        intent_raw = self.storage.read_file(base + "/intent.json", limit=MAX_RECORD)[0]
        intent = _decode(intent_raw)
        if (
            plan
            != {
                "schema": "naos.upgrade.windows_operation_plan.v2",
                "operation_id": spec.operation_id,
                "plan": dict(spec.plan),
                "plan_sha256": canonical_sha256(dict(spec.plan)),
            }
            or set(intent)
            != {
                "schema",
                "failure_model",
                "operation_id",
                "plan_sha256",
                "slot_paths",
                "publications",
                "runtime_parent_id",
                "scope_lock_id",
                "transaction_directory_id",
                "lock_id",
            }
            or intent.get("schema") != "naos.upgrade.windows_operation.v2"
            or intent.get("failure_model") != "application_crash_v1"
            or intent.get("operation_id") != spec.operation_id
            or intent.get("plan_sha256") != plan["plan_sha256"]
            or intent.get("slot_paths") != dict(spec.slot_paths)
            or intent.get("publications") != spec.plan["publications"]
        ):
            raise RIStorageConflict(
                "RI journal differs from its constrained preparation"
            )
        for field, path, kind in (
            ("runtime_parent_id", RUNTIME + "/operations", "directory"),
            ("scope_lock_id", RUNTIME + "/scope.lock", "file"),
            ("transaction_directory_id", base, "directory"),
            ("lock_id", base + "/lock", "file"),
        ):
            if field == "scope_lock_id":
                # The caller already holds this file exclusively with write
                # access for LockFileEx. A second deny-write read pin conflicts
                # with that live handle; observe through a compatible read
                # handle while the original lock continues to deny deletion.
                with self.storage._parent(path) as (parent, name):
                    with self.storage.handles.open_child(
                        parent, name, kind="file"
                    ) as child:
                        identity = self.storage._identity(child)
            else:
                identity = self.storage.identity_if_present(path, kind=kind)
            if identity is None or intent[field] != {
                "volume_serial_hex": identity.volume_serial_hex,
                "file_id_hex": identity.file_id_hex,
            }:
                raise RIStorageConflict("RI journal native namespace identity differs")
        found = []
        for name, direction, topology, status in [
            ("committed.json", "forward", "committed", "committed"),
            ("rolled-back.json", "rollback", "prepared", "rolled_back"),
        ]:
            if self.storage.identity_if_present(base + "/" + name, kind="file") is None:
                continue
            marker = _decode(self.storage.read_file(base + "/" + name)[0])
            if marker != {
                "schema": "naos.upgrade.windows_operation.v2",
                "failure_model": "application_crash_v1",
                "intent_sha256": _sha(intent_raw),
                "direction": direction,
                "topology": topology,
            }:
                raise RIStorageConflict("RI terminal marker differs")
            found.append(status)
        if len(found) > 1:
            raise RIStorageConflict("RI journal has conflicting terminal markers")
        # Historical operations cannot be replayed against a newer pointer, but
        # their terminal marker still requires the complete bound checkpoints.
        if found:
            count = sum(p.state_count() for p in spec.publications)
            expected_names = {"lock", "plan.json", "intent.json"}
            start = count
            if found[0] == "rolled_back":
                rollback = _decode(self.storage.read_file(base + "/rollback.json")[0])
                encoded = rollback.get("start_step_decimal")
                if (
                    not isinstance(encoded, str)
                    or not encoded.isascii()
                    or not encoded.isdecimal()
                    or len(encoded) > 4
                    or str(int(encoded)) != encoded
                ):
                    raise RIStorageConflict("RI rollback start is invalid")
                start = int(encoded)
                if not 0 <= start <= count or rollback != {
                    "schema": "naos.upgrade.windows_operation.v2",
                    "failure_model": "application_crash_v1",
                    "intent_sha256": _sha(intent_raw),
                    "start_step_decimal": encoded,
                }:
                    raise RIStorageConflict("RI rollback binding differs")
                expected_names |= {"rollback.json", "rolled-back.json"}
            else:
                expected_names.add("committed.json")
            checkpoints = [
                ("forward-" + f"{i:06d}" + ".json", "forward", f"step:{i}")
                for i in range(1, start + 1)
            ]
            if found[0] == "rolled_back":
                checkpoints += [
                    ("rollback-" + f"{i:06d}" + ".json", "rollback", f"step:{i}")
                    for i in range(start)
                ]
            for name, direction, topology in checkpoints:
                expected_names.add(name)
                checkpoint = _decode(self.storage.read_file(base + "/" + name)[0])
                if checkpoint != {
                    "schema": "naos.upgrade.windows_operation.v2",
                    "failure_model": "application_crash_v1",
                    "intent_sha256": _sha(intent_raw),
                    "direction": direction,
                    "topology": topology,
                }:
                    raise RIStorageConflict("RI historical checkpoint differs")
            if set(self.storage.children(base)) != expected_names:
                raise RIStorageConflict("RI historical journal inventory differs")
        return found[0] if found else "pending", intent

    def _prepared_without_journal(self, spec: WindowsOperationSpec) -> None:
        """Prove the witnessed, unpublished topology without adopting any object."""
        dirs = {
            p: NativeIdentity.from_record(v)
            for p, v in spec.plan["directories"].items()
        }
        with self.storage.pin_directories(dirs):
            stage = RUNTIME + "/staging/" + spec.operation_id
            generation = (
                GOVERNED_ROOT + "/generations/" + spec.plan["request"]["generation_id"]
            )
            if set(self.storage.children(stage)) != set(spec.plan["members"]) | {
                "active.json",
                "activation-receipt.json",
            } or self.storage.children(generation):
                raise RIStorageConflict("RI unjournaled preparation inventory differs")
            with WindowsRestoringBackend(
                self.storage.handles, dict(spec.slot_paths)
            ) as backend:
                for publication in spec.publications:
                    if (
                        backend.observe(publication.staged) != publication.after
                        or backend.observe(publication.target) != publication.before
                        or (
                            publication.backup
                            and backend.observe(publication.backup) is not None
                        )
                    ):
                        raise RIStorageConflict(
                            "RI unjournaled preparation identity differs"
                        )

    def _records(self, bootstrap: dict[str, Any]) -> dict[str, dict[str, Any]]:
        records = {}
        for name in self.storage.children(RUNTIME + "/preparations"):
            if not name.endswith(".json"):
                raise RIStorageConflict(
                    "Incomplete or unknown RI preparation is preserved"
                )
            op = _operation_id(name[:-5])
            record, _ = self._json(RUNTIME + "/preparations/" + name)
            if record.get("operation_id") != op or record.get(
                "bootstrap_sha256"
            ) != canonical_sha256(bootstrap):
                raise RIStorageConflict("RI preparation bootstrap differs")
            self._spec(record)
            for path, value in record["directories"].items():
                if self.storage.directory_identity(path) != NativeIdentity.from_record(
                    value
                ):
                    raise RIStorageConflict("RI prepared directory identity changed")
            records[op] = record
        if set(self.storage.children(RUNTIME + "/staging")) != set(records):
            raise RIStorageConflict("Unwitnessed RI staging is preserved")
        if set(self.storage.children(RUNTIME + "/operations")) - set(records):
            raise RIStorageConflict("Unwitnessed RI operation is preserved")
        generations = {r["request"]["generation_id"] for r in records.values()}
        if set(
            self.storage.children(GOVERNED_ROOT + "/generations")
        ) != generations or len(generations) != len(records):
            raise RIStorageConflict("Unwitnessed or aliased RI generation is preserved")
        return records

    def _history(
        self, bootstrap: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
        records = self._records(bootstrap)
        directories = {
            p: NativeIdentity.from_record(v)
            for r in records.values()
            for p, v in r["directories"].items()
        }
        with self.storage.pin_directories(directories):
            return self._history_records(records)

    def _history_records(
        self, records: dict[str, dict[str, Any]]
    ) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
        committed = set()
        for op, record in records.items():
            spec = self._spec(record)
            state, _ = self._journal(spec)
            if state in {"pending", "prepared_without_journal"}:
                raise RIStorageConflict("RI operation requires explicit recovery")
            if state == "committed":
                committed.add(op)
            stage = RUNTIME + "/staging/" + op
            generation = (
                GOVERNED_ROOT + "/generations/" + record["request"]["generation_id"]
            )
            if state == "rolled_back":
                if self.storage.children(generation):
                    raise RIStorageConflict("Rolled-back RI generation is not empty")
                expected_stage = set(record["members"]) | {
                    "activation-receipt.json",
                    "active.json",
                }
                with WindowsRestoringBackend(
                    self.storage.handles, dict(spec.slot_paths)
                ) as backend:
                    for publication in spec.publications:
                        if backend.observe(publication.staged) != publication.after:
                            raise RIStorageConflict(
                                "Rolled-back RI staging identity differs"
                            )
            else:
                expected_stage = (
                    {"previous-active.json"} if record["predecessor"] else set()
                )
            if set(self.storage.children(stage)) != expected_stage:
                raise RIStorageConflict("RI staging inventory differs")
        if self.storage.identity_if_present(ACTIVE, kind="file") is None:
            if committed:
                raise RIStorageConflict("RI committed history lacks active pointer")
            if self.storage.children(RUNTIME + "/receipts"):
                raise RIStorageConflict("RI receipt inventory differs")
            return None, records
        pointer, raw = self._json(ACTIVE)
        pointer_path = ACTIVE
        successor_before = None
        current = pointer
        seen = set()
        while pointer is not None:
            op = _operation_id(pointer.get("operation_id"))
            if op not in committed or op in seen:
                raise RIStorageConflict("RI pointer is uncommitted, unknown or cyclic")
            seen.add(op)
            record = records[op]
            spec = self._spec(record)
            expected_receipt = {
                "schema": RECEIPT_SCHEMA,
                "operation_id": op,
                "request": record["request"],
                "members": record["members"],
                "predecessor": record["predecessor"],
            }
            expected_pointer = {
                **expected_receipt,
                "schema": POINTER_SCHEMA,
                "receipt_sha256": record["receipt_sha256"],
            }
            if pointer != expected_pointer or _sha(raw) != record["pointer_sha256"]:
                raise RIStorageConflict("RI pointer binding differs")
            manifest = spec.publications[-1]
            with WindowsRestoringBackend(
                self.storage.handles, {"pointer": self._absolute(pointer_path)}
            ) as backend:
                if backend.observe("pointer") != manifest.after or (
                    successor_before is not None and successor_before != manifest.after
                ):
                    raise RIStorageConflict("RI pointer native identity differs")
            receipt, receipt_raw = self._json(RUNTIME + "/receipts/" + op + ".json")
            if (
                receipt != expected_receipt
                or _sha(receipt_raw) != record["receipt_sha256"]
            ):
                raise RIStorageConflict("RI immutable activation receipt differs")
            with WindowsRestoringBackend(
                self.storage.handles, dict(spec.slot_paths)
            ) as backend:
                for p in spec.publications[:-1]:
                    if (
                        backend.observe(p.target) != p.after
                        or backend.observe(p.staged) is not None
                    ):
                        raise RIStorageConflict("RI immutable publication changed")
            generation = (
                GOVERNED_ROOT + "/generations/" + record["request"]["generation_id"]
            )
            if set(self.storage.children(generation)) != set(record["members"]):
                raise RIStorageConflict("RI generation inventory differs")
            pred = record["predecessor"]
            if pred is None:
                pointer = None
            else:
                successor_before = manifest.before
                pointer_path = RUNTIME + "/staging/" + op + "/previous-active.json"
                pointer, raw = self._json(pointer_path)
                if (
                    _sha(raw) != pred["pointer_sha256"]
                    or pointer.get("operation_id") != pred["operation_id"]
                ):
                    raise RIStorageConflict("RI predecessor chain differs")
        if seen != committed:
            raise RIStorageConflict("RI committed history is disconnected")
        if set(self.storage.children(RUNTIME + "/receipts")) != {
            op + ".json" for op in committed
        }:
            raise RIStorageConflict("RI receipt inventory differs")
        return current, records

    @contextmanager
    def active(self) -> Iterator[dict[str, Any] | None]:
        """Reader lease: keep lock, directory IDs and immutable bytes pinned."""
        with self.locked() as (_lock, bootstrap):
            current, records = self._history(bootstrap)
            if current is None:
                yield None
                return
            record = records[current["operation_id"]]
            base = GOVERNED_ROOT + "/generations/" + current["request"]["generation_id"]
            pins = {base + "/" + n: h for n, h in record["members"].items()}
            pins[ACTIVE] = record["pointer_sha256"]
            with (
                self.storage.pin_directories(
                    {
                        p: NativeIdentity.from_record(v)
                        for p, v in record["directories"].items()
                    }
                ),
                self.storage.pin_files(pins),
            ):
                # Pins deny replacement/write, but hashes alone do not establish
                # object ownership. Recheck the exact native witnesses while
                # those same files remain pinned for the caller's whole read.
                pinned_current, _ = self._history(bootstrap)
                if pinned_current != current:
                    raise RIStorageConflict("RI reader snapshot changed before pinning")
                yield current

    def recover(self, operation_id: str) -> str:
        op = _operation_id(operation_id)
        with self.locked() as (lock, bootstrap):
            records = self._records(bootstrap)
            if op not in records:
                raise RIStorageConflict("Unknown RI operation is not recoverable")
            spec = self._spec(records[op])
            state, _ = self._journal(spec)
            if state in {"committed", "rolled_back"}:
                # Validate the complete predecessor chain. A superseded pointer
                # deliberately no longer has the old operation's final topology.
                self._history(bootstrap)
                return state
            committed = set()
            for other, record in records.items():
                if other == op:
                    continue
                other_state, _ = self._journal(self._spec(record))
                if other_state in {"pending", "prepared_without_journal"}:
                    raise RIStorageConflict(
                        "Multiple pending RI operations require owner reconciliation"
                    )
                if other_state == "committed":
                    committed.add(other)
            parents = {
                records[item]["predecessor"]["operation_id"]
                for item in committed
                if records[item]["predecessor"] is not None
            }
            heads = committed - parents
            pred = spec.plan["predecessor"]
            if (
                parents - committed
                or (committed and len(heads) != 1)
                or ({pred["operation_id"]} if pred else set()) != heads
            ):
                raise RIStorageConflict(
                    "Pending RI operation is not a successor of committed history"
                )
            if state == "prepared_without_journal":
                # Validate the complete predecessor contents, not just the IDs
                # in the head calculation, before creating recovery metadata.
                self._history_records({k: v for k, v in records.items() if k != op})
                self._prepared_without_journal(spec)
            with self._operation(spec, lock) as operation:
                result = (
                    operation.initialize_rollback()
                    if state == "prepared_without_journal"
                    else operation.recover()
                )
            self._history(bootstrap)
            return result
