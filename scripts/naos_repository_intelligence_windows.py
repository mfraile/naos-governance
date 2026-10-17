"""Public RI lifecycle dispatch using native Windows ownership and reader leases.

The shared engine supplies deterministic source, profile, rules and bundle
validation. This adapter supplies native publication/recovery and a versioned
Windows context, without interpreting Windows IDs as POSIX provenance.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

CONTEXT_SCHEMA = "naos.repository_intelligence_context.v2"
APPLY_SCHEMA = "naos.repository_intelligence.apply_result.v2"
AUTH_SCHEMA = "naos.repository_intelligence.windows_authorization.v1"


class _GenerationReader:
    """Read only active leased members through existing native custody guards."""

    def __init__(self, storage, relative, members, engine):
        self.storage, self.relative, self.e = storage, relative, engine
        self.members = dict(members)

    def __call__(self, name):
        if name not in self.members or Path(name).name != name:
            raise self.e.RepositoryIntelligenceError("Unbound native generation member")
        data, _identity = self.storage.read_file(self.relative + "/" + name)
        if self.e.sha256_bytes(data) != self.members[name]:
            raise self.e.RepositoryIntelligenceError("Native generation member digest differs")
        return data

    def json(self, name):
        data = self.e.loads_strict_json(self(name))
        if not isinstance(data, dict):
            raise self.e.RepositoryIntelligenceError("Native JSON control must be an object")
        return data


class WindowsRepositoryIntelligencePublic:
    def __init__(self, root: Path, engine: Any):
        self.root, self.e = root, engine
        self.storage_type = engine.ri_windows_storage.WindowsRIStorage
        self.native = engine.ri_windows_runtime

    @contextmanager
    def _errors(self):
        try:
            yield
        except self.e.RepositoryIntelligenceError:
            raise
        except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
            raise self.e.RepositoryIntelligenceError(
                f"Native Windows RI refused: {exc}"
            ) from exc

    def _context_root(self, naos_root):
        return self.e._context_index_root(self.root, naos_root)

    def _empty(self):
        result = {
            "schema": CONTEXT_SCHEMA,
            "status": "not_configured",
            "project_root": str(self.root),
        }
        self.e._validate_schema(result, CONTEXT_SCHEMA)
        return result

    def _bootstrap_present(self, storage):
        present = (
            storage.identity_if_present(self.native.BOOTSTRAP, kind="file") is not None
        )
        if not present:
            # An enrolled namespace without a complete bootstrap never owns an
            # existing generated root or a partial runtime directory.
            enrollment = self.e.ri_windows_enrollment.WindowsRIEnrollment(storage)
            enrollment.inspect()
            enrollment._require_absent_generated_root()
            if (
                storage.identity_if_present(self.native.RUNTIME, kind="directory")
                is not None
            ):
                raise self.e.RepositoryIntelligenceError(
                    "Incomplete native RI bootstrap requires recovery/reconciliation"
                )
        return present

    def _inspect_source(self, control, rules_path, naos_root, rules_bytes=None):
        return self.e.inspect_repository(
            self.root,
            profile=control["profile"],
            naos_root=naos_root,
            rules_path=rules_path,
            rules_source="native_generation_snapshot",
            component_mode=control["component_mode"],
            purpose=control["purpose"],
            rules_bytes=rules_bytes,
        )

    def _authorize(self, control, rules_path, naos_root, storage):
        current = self.e.ri_windows_enrollment.WindowsRIEnrollment(
            storage
        )._inspect_record()
        planned = control["provenance_gate"].get("enrollment")
        if current is None or planned != {
            "project_id": current.project_id,
            "native_plan_sha256": current.enrollment_plan_sha256,
            "record_bytes_sha256": current.record_sha256,
            "record_identity": current.record_identity.record(),
        }:
            raise self.e.RepositoryIntelligenceError(
                "Native RI enrollment changed after planning"
            )
        inspection = self._inspect_source(control, rules_path, naos_root)
        self.e._assert_current_inspection_complete(
            inspection, phase="native pre-apply revalidation"
        )
        expected = {
            "effective_source_sha256": inspection["effective_source_sha256"],
            "runtime": inspection["runtime"],
            "components": inspection["components"],
            "implementation": self.e._implementation_identity(),
        }
        for key, value in expected.items():
            if control.get(key) != value:
                raise self.e.RepositoryIntelligenceError(
                    f"{key} changed after planning; prepare a new plan"
                )
        if inspection["rules"]["sha256"] != control["rules"]["sha256"]:
            raise self.e.RepositoryIntelligenceError("Rules changed after planning")
        graph = {
            "directed": True,
            "multigraph": True,
            "nodes": inspection["nodes"],
            "relationships": inspection["relationships"],
        }
        if self.e.canonical_sha256(graph) != control["graph_model_sha256"]:
            raise self.e.RepositoryIntelligenceError(
                "Relationship model changed after planning"
            )

    @contextmanager
    def _refresh_lease(self, storage, runtime, naos_root, target):
        """Retain immutable native members after releasing the active lock.

        ACTIVE is observed and compared, never held across its replacement.
        Existing storage handles deny writes/deletion; full HandleInfo and private
        security/native IDs are bound in addition to each raw member digest.
        """
        with ExitStack() as pins:
            files, directories, memberships = {}, {}, {}
            held = {}
            held_directories = {}
            cumulative_bytes = 0

            def info_value(info):
                return {key: value.hex() if isinstance(value, bytes) else
                        str(value) if type(value) is int else value
                        for key, value in asdict(info).items()}

            def read(relative, *, retain=False, account=True):
                nonlocal cumulative_bytes
                with ExitStack() as temporary:
                    parent, name = temporary.enter_context(storage._parent(relative))
                    if retain:
                        # Retain the ancestry lease too, not just a leaf handle.
                        pinned_parent, pinned_name = pins.enter_context(storage._parent(relative))
                        child = pins.enter_context(storage.handles.open_child(
                            pinned_parent, pinned_name, kind="file", pin_for_read=True))
                    else:
                        child = temporary.enter_context(storage.handles.open_child(
                            parent, name, kind="file", pin_for_read=True))
                    before = child.info()
                    raw, identity = storage._read(child, self.e.ri_windows_storage.MAX_FILE_BYTES)
                    if child.info() != before:
                        raise self.e.RepositoryIntelligenceError("Prior native metadata changed during capture")
                    if account:
                        cumulative_bytes += len(raw)
                    if cumulative_bytes > 256 * 1024 * 1024 or (retain and relative not in files and len(files) >= 4096):
                        raise self.e.RepositoryIntelligenceError("Prior native witness exceeds cumulative capture bound")
                    value = {"sha256": self.e.sha256_bytes(raw), "native_identity": {
                        "storage": identity.record(), "handle_info": info_value(before)}}
                    if retain:
                        files[relative] = value
                        held[relative] = child
                    return raw, value

            def tree(relative):
                identity = storage.directory_identity(relative)
                pins.enter_context(storage.pin_directories({relative: identity}))
                parent, name = pins.enter_context(storage._parent(relative))
                child = pins.enter_context(storage.handles.open_child(parent, name, kind="directory", pin_for_read=True))
                if storage._identity(child) != identity:
                    raise self.e.RepositoryIntelligenceError("Prior native directory changed during capture")
                directories[relative] = {"storage": identity.record(), "handle_info": info_value(child.info())}
                held_directories[relative] = child
                names = sorted(storage.children(relative))
                memberships[relative] = names
                for name in names:
                    path = relative + "/" + name
                    # History proved these three finite directories contain
                    # files only. An unexpected directory/reparse/link refuses
                    # through the existing strict file opener; no type fallback.
                    read(path, retain=True)

            with runtime.active() as current:
                if current is None:
                    witness = None
                else:
                    base = self.native.GOVERNED_ROOT + "/generations/" + current["request"]["generation_id"]
                    manifest_raw, _ = read(base + "/manifest.json", retain=True)
                    manifest = self.e.loads_strict_json(manifest_raw)
                    implementation = manifest["control"]["implementation"]
                    self.e._supported_refresh_implementation(implementation, target)
                    self._validate_bound(storage, runtime, current, naos_root, False,
                                         prior_implementation=implementation)
                    bootstrap, _raw = runtime._json(self.native.BOOTSTRAP)
                    records = runtime._records(bootstrap)
                    # active() already proved complete committed custody. Keep
                    # every original record/member/pointer backup, including
                    # rolled-back historical publications, immutable thereafter.
                    for op, record in sorted(records.items()):
                        for folder in (self.native.GOVERNED_ROOT + "/generations/" + record["request"]["generation_id"],
                                       self.native.RUNTIME + "/staging/" + op,
                                       self.native.RUNTIME + "/operations/" + op):
                            tree(folder)
                        read(self.native.RUNTIME + "/preparations/" + op + ".json", retain=True)
                    receipt_root = self.native.RUNTIME + "/receipts"
                    receipts = sorted(storage.children(receipt_root))
                    for name in receipts:
                        read(receipt_root + "/" + name, retain=True)
                    pointer_raw, pointer_value = read(self.native.ACTIVE)
                    witness = {"schema": self.e.REFRESH_BASE_SCHEMA, "backend": "windows",
                        "generation_id": current["request"]["generation_id"],
                        "operation_id": current["operation_id"],
                        "pointer": {"path": self.native.ACTIVE, **pointer_value},
                        "manifest_file_sha256": self.e.sha256_bytes(manifest_raw),
                        "manifest_sha256": manifest["manifest_sha256"],
                        "bindings": self.e._refresh_manifest_bindings(manifest["control"]),
                        "files": files, "directories": directories,
                        "memberships": {**memberships, receipt_root: receipts}}
                # Release the ACTIVE reader handle before publish (the runtime's
                # active() pins it independently until this block closes).

            def check(*, pointer=True):
                if witness is None:
                    if not pointer:
                        return
                    if storage.identity_if_present(self.native.ACTIVE, kind="file") is not None:
                        raise self.e.RepositoryIntelligenceError("Unreviewed native active pointer appeared")
                    return
                if witness["bindings"]["contract_schema_sha256"] != self.e._refresh_contract_schemas():
                    raise self.e.RepositoryIntelligenceError("Reviewed native refresh schema contracts changed")
                for relative, expected in directories.items():
                    if (storage.directory_identity(relative).record() != expected["storage"]
                            or storage._identity(held_directories[relative]).record() != expected["storage"]
                            or info_value(held_directories[relative].info()) != expected["handle_info"]):
                        raise self.e.RepositoryIntelligenceError("Pinned prior native directory changed")
                for relative, expected in files.items():
                    child = held[relative]
                    raw, identity = storage._read(child, self.e.ri_windows_storage.MAX_FILE_BYTES)
                    if (self.e.sha256_bytes(raw) != expected["sha256"]
                            or identity.record() != expected["native_identity"]["storage"]
                            or info_value(child.info()) != expected["native_identity"]["handle_info"]):
                        raise self.e.RepositoryIntelligenceError("Pinned prior native member changed")
                for relative, names in memberships.items():
                    if sorted(storage.children(relative)) != names:
                        raise self.e.RepositoryIntelligenceError("Prior immutable native membership changed")
                if pointer:
                    if sorted(storage.children(receipt_root)) != receipts:
                        raise self.e.RepositoryIntelligenceError("Prior native receipt membership changed")
                    _raw, observed = read(self.native.ACTIVE, account=False)
                    if observed != pointer_value:
                        raise self.e.RepositoryIntelligenceError("Approved prior native pointer changed")
            check()
            try:
                yield witness, check
            finally:
                check(pointer=False)

    def capture_refresh_base(self, naos_root, target):
        with self._errors(), self.storage_type(str(self.root)) as storage:
            if not self._bootstrap_present(storage):
                return None
            runtime = self.native.WindowsRIRuntime(storage)
            with self._refresh_lease(storage, runtime, naos_root, target) as (witness, _check):
                return witness

    def apply(
        self,
        plan,
        *,
        confirmed_digest,
        reviewer_id,
        rules_override=None,
        requested_profile=None,
        requested_naos_root=None,
    ):
        with self._errors(), self.e._native_bundle_pins(self.root, plan):
            if rules_override is not None:
                raise self.e.RepositoryIntelligenceError(
                    "Apply does not accept a rules override"
                )
            control = self.e.verify_plan(plan, confirmed_digest)
            if control["project_root"] != str(self.root):
                raise self.e.RepositoryIntelligenceError(
                    "Plan project root does not match requested project"
                )
            profile, naos_root = control["profile"], control["naos_root"]
            if requested_profile is not None and requested_profile != profile:
                raise self.e.RepositoryIntelligenceError(
                    "CLI profile does not match apply plan profile"
                )
            if requested_naos_root is not None and requested_naos_root != naos_root:
                raise self.e.RepositoryIntelligenceError(
                    "CLI NAOS root does not match apply plan"
                )
            self._context_root(naos_root)
            reviewer_id = self.e._require_reviewer(profile, reviewer_id)
            bundle, bundle_dir, manifest = self.e._validate_plan_bundle(
                self.root, plan, require_activation=True
            )
            gate = self.e._inspect_ri_scope(
                self.root, governed_root=self.native.GOVERNED_ROOT
            )
            if (
                not gate.activation_eligible
                or gate.plan_gate() != control["provenance_gate"]
            ):
                raise self.e.RepositoryIntelligenceError(
                    "Native RI provenance changed after planning"
                )
            authorization = {
                "schema": AUTH_SCHEMA,
                "profile": profile,
                "naos_root": naos_root,
                "profile_gate": self.e._profile_gate(profile),
                "reviewer": {
                    "reviewer_id": reviewer_id,
                    "required": self.e._profile_gate(profile)["named_review_required"],
                    "identity_status": "declared_attribution"
                    if reviewer_id
                    else "not_required",
                    "authentication_status": "not_claimed",
                },
                "effective_source_sha256": control["effective_source_sha256"],
                "rules_sha256": control["rules"]["sha256"],
                "manifest_sha256": manifest["manifest_sha256"],
                "generation_content_sha256": control["generation_content_sha256"],
            }
            self.e._validate_schema(authorization, AUTH_SCHEMA)
            request = {
                "public_plan_sha256": confirmed_digest,
                "bundle_sha256": bundle["bundle_sha256"],
                "generation_id": control["generation_id"],
                "authorization": authorization,
            }
            files = {
                row["path"]: self.e.secure_regular_file_bytes(bundle_dir / row["path"])
                for row in bundle["files"]
            }
            with self.storage_type(str(self.root)) as storage:
                runtime = self.native.WindowsRIRuntime(storage)
                return self._publish_bound(storage, runtime, control, request, files,
                                           bundle_dir, bundle, manifest, confirmed_digest, naos_root)

    def _publish_bound(self, storage, runtime, control, request, files,
                       bundle_dir, bundle, manifest, confirmed_digest, naos_root):
        with ExitStack() as refresh_pins:
            before = None
            def refresh_check():
                return None
            if self._bootstrap_present(storage):
                with runtime.active() as current:
                    if current is not None:
                        # A stale source is a valid refresh base; corrupt
                        # generated state or incompatible runtime is not.
                        before = current
                        exact_retry = current["request"] == request
                        if "refresh_base" not in control or exact_retry:
                            self._validate_bound(storage, runtime, current, naos_root, False)
                if "refresh_base" in control and not (before and before["request"] == request):
                    observed, refresh_check = refresh_pins.enter_context(
                        self._refresh_lease(storage, runtime, naos_root, control["implementation"]))
                    if observed != control["refresh_base"]:
                        raise self.e.RepositoryIntelligenceError("Approved native refresh baseline changed")
            elif "refresh_base" in control:
                if control["refresh_base"] is not None:
                    raise self.e.RepositoryIntelligenceError("Approved native refresh baseline disappeared")
                def refresh_check():
                    if storage.identity_if_present(self.native.ACTIVE, kind="file") is not None:
                        raise self.e.RepositoryIntelligenceError("Unreviewed native active pointer appeared")

            def revalidate():
                refresh_check()
                self._authorize(
                    control,
                    bundle_dir / "repository_intelligence_rules.yaml",
                    naos_root,
                    storage,
                )

            def finish(pointer, validation, *, content_noop=False):
                same = before == pointer
                generation = validation["generation"]
                result = {
                    "schema": APPLY_SCHEMA,
                    "status": "already_active" if same else "validated_active",
                    "transaction_id": pointer["operation_id"],
                    "generation_id": control["generation_id"],
                    "generation_content_sha256": control["generation_content_sha256"],
                    "plan_sha256": confirmed_digest,
                    "bundle_sha256": bundle["bundle_sha256"],
                    "active_pointer": self.native.ACTIVE,
                    "active_sha256": self.e.canonical_sha256(pointer),
                    "manifest": generation["manifest_path"],
                    "manifest_sha256": manifest["manifest_sha256"],
                    "activation_receipt": generation["activation_receipt_path"],
                    "activation_receipt_sha256": generation[
                        "activation_receipt_sha256"
                    ],
                    "validation": validation,
                    "idempotent_reuse": same,
                    "previous_generation_id": before["request"]["generation_id"]
                    if before
                    else None,
                    "source_artifacts_modified": [],
                    "generated_state_only": True,
                    "exact_bundle_bytes_promoted": True,
                }
                if content_noop:
                    result["activation_effect"] = "confirmed_existing_content_no_publication"
                    result["persisted_activation_plan_sha256"] = generation["plan_sha256"]
                self.e._validate_schema(result, APPLY_SCHEMA)
                return result

            if (control.get("refresh_base") is not None and before is not None
                    and before["request"] != request
                    and before["request"]["generation_id"] == request["generation_id"]):
                # A newly confirmed plan may describe the exact active content.
                # Decide only inside the existing full-history native reader
                # lease. Keep the original request/receipt; publish nothing.
                with runtime.active() as current:
                    if current != before:
                        raise self.e.RepositoryIntelligenceError("Active native generation changed before content acknowledgement")
                    revalidate()
                    validation = self._validate_bound(storage, runtime, current, naos_root, True)
                    if validation["status"] != "validated_current":
                        raise self.e.RepositoryIntelligenceError("Active native generation is not current")
                    if (set(current["request"]) != set(request)
                            or any(current["request"][key] != value for key, value in request.items()
                                   if key != "public_plan_sha256")
                            or current["members"] != {name: self.e.sha256_bytes(data) for name, data in files.items()}
                            or validation["generation"]["manifest_sha256"] != manifest["manifest_sha256"]):
                        raise self.e.RepositoryIntelligenceError("Active native generation differs from confirmed bundle or authorization")
                    revalidate()
                    return finish(current, validation, content_noop=True)

            revalidate()
            pointer = runtime.publish(request, files, revalidate=revalidate)
            with runtime.active() as current:
                if current != pointer:
                    raise self.e.RepositoryIntelligenceError(
                        "Active native generation changed after publication"
                    )
                validation = self._validate_bound(
                    storage, runtime, current, naos_root, True
                )
                if validation["status"] != "validated_current":
                    raise self.e.RepositoryIntelligenceError(
                        "Published native generation is not current"
                    )
            return finish(pointer, validation)

    def _validate_bound(
        self, storage, runtime, pointer, naos_root, require_current_source,
        *, prior_implementation=None, classify_identity_drift=False
    ):
        if pointer is None:
            return self._empty()
        request = pointer["request"]
        auth = request.get("authorization")
        self.e._validate_schema(auth, AUTH_SCHEMA)
        if auth["naos_root"] != naos_root or auth[
            "profile_gate"
        ] != self.e._profile_gate(auth["profile"]):
            raise self.e.RepositoryIntelligenceError(
                "Native active authorization scope differs"
            )
        self.e._require_reviewer(auth["profile"], auth["reviewer"]["reviewer_id"])
        if (
            auth["reviewer"]["required"]
            != auth["profile_gate"]["named_review_required"]
        ):
            raise self.e.RepositoryIntelligenceError(
                "Native reviewer requirement differs from profile"
            )
        base = self._context_root(naos_root) / "generations" / request["generation_id"]
        reader = _GenerationReader(
            storage, base.relative_to(self.root).as_posix(), pointer["members"], self.e
        )
        manifest = reader.json("manifest.json")
        self.e._validate_schema(manifest, self.e.MANIFEST_SCHEMA)
        control = manifest["control"]
        if (
            self.e.canonical_sha256(control) != manifest["manifest_sha256"]
            or manifest["manifest_sha256"] != auth["manifest_sha256"]
            or manifest["status"] != "validated"
        ):
            raise self.e.RepositoryIntelligenceError(
                "Native generation manifest binding differs"
            )
        if (
            control["project_root"] != str(self.root)
            or control["generation_id"] != request["generation_id"]
        ):
            raise self.e.RepositoryIntelligenceError(
                "Native generation root or identity differs; restore the bound root or use a "
                "separately qualified, explicitly approved provenance rebind before refresh"
            )
        for key in ("profile", "generation_content_sha256", "effective_source_sha256"):
            if control[key] != auth[key]:
                raise self.e.RepositoryIntelligenceError(
                    f"Native authorization {key} differs"
                )
        if control["rules"]["sha256"] != auth["rules_sha256"]:
            raise self.e.RepositoryIntelligenceError(
                "Native authorization rules differ"
            )
        identity_drift_fields = []
        if control["runtime"] != self.e.runtime_probe():
            identity_drift_fields.append("runtime")
        if control["implementation"] != self.e._implementation_identity():
            if prior_implementation is None or control["implementation"] != prior_implementation:
                identity_drift_fields.append("implementation")
            else:
                self.e._supported_refresh_implementation(prior_implementation, self.e._implementation_identity())
        # Preserve early strict refusal; only status can defer to prove stored
        # integrity before reporting an identity-drift diagnostic.
        if identity_drift_fields and (not classify_identity_drift or prior_implementation is not None):
            raise self.e.RepositoryIntelligenceError(self.e._identity_drift_finding(identity_drift_fields))
        gate = self.e._inspect_ri_scope(
            self.root, governed_root=self.native.GOVERNED_ROOT
        )
        if (
            not gate.activation_eligible
            or control["provenance_gate"] != gate.plan_gate()
        ):
            raise self.e.RepositoryIntelligenceError(
                "Native generation enrollment binding differs; a relocated root cannot bypass "
                "provenance without a separately qualified, explicitly approved rebind"
            )
        self.e._validate_file_records(base, control["files"], generation_reader=reader)
        expected = {"manifest.json", *(row["path"] for row in control["files"])}
        if expected != set(pointer["members"]):
            raise self.e.RepositoryIntelligenceError(
                "Native generation manifest inventory differs"
            )
        receipt = reader.json("validation_receipt.json")
        self.e._validate_schema(receipt, self.e.RECEIPT_SCHEMA)
        rc = receipt["control"]
        if (
            receipt["status"] != "validated_generation"
            or self.e.canonical_sha256(rc) != receipt["receipt_sha256"]
            or receipt["receipt_sha256"] != control["validation_receipt_sha256"]
        ):
            raise self.e.RepositoryIntelligenceError(
                "Native generation validation receipt differs"
            )
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
            if rc.get(key) != control.get(key):
                raise self.e.RepositoryIntelligenceError(
                    f"Native validation receipt {key} differs"
                )
        inventory = reader.json("inventory.json")
        self.e._validate_schema(inventory, self.e.INVENTORY_SCHEMA)
        if inventory["generation_id"] != request["generation_id"]:
            raise self.e.RepositoryIntelligenceError(
                "Native inventory generation differs"
            )
        rules = base / "repository_intelligence_rules.yaml"
        rules_bytes = reader("repository_intelligence_rules.yaml")
        if (
            self.e.sha256_bytes(rules_bytes)
            != auth["rules_sha256"]
        ):
            raise self.e.RepositoryIntelligenceError(
                "Native generation rules snapshot differs"
            )
        rules_mapping = self.e.yaml.safe_load(rules_bytes.decode("utf-8")) or {}
        if not isinstance(rules_mapping, dict):
            raise self.e.RepositoryIntelligenceError("Native rules must be a YAML mapping")
        self.e._validate_rules(rules_mapping)
        sqlite_validation = self.e._validate_sqlite(
            base / "local_context_index.sqlite",
            control["effective_source_sha256"],
            inventory["sqlite_content_binding"],
            generation_reader=reader,
        )
        graph_selected = bool(
            control["components"].get("networkx_graphml", {}).get("selected")
        )
        if graph_selected:
            graph_validation = self.e._validate_graphml_file(
                base / "context.graphml",
                expected_source_sha256=control["effective_source_sha256"],
                expected_model_sha256=control["graph_model_sha256"],
                data=reader("context.graphml"),
            )
        else:
            if "context.graphml" in pointer["members"]:
                raise self.e.RepositoryIntelligenceError(
                    "Unselected native GraphML is present"
                )
            graph_validation = {"status": "not_selected"}
        if require_current_source and not identity_drift_fields:
            inspection = self._inspect_source(control, rules, naos_root, rules_bytes)
            if (
                inspection["effective_source_sha256"]
                != control["effective_source_sha256"]
                or self.e._blocking_finding_ids(inspection)
                or inspection["inventory_truncated"]
                or inspection["relationships_truncated"]
            ):
                result = {
                    "schema": CONTEXT_SCHEMA,
                    "status": "stale",
                    "project_root": str(self.root),
                    "generation_id": request["generation_id"],
                    "effective_source_sha256": control["effective_source_sha256"],
                    "current_source_sha256": inspection["effective_source_sha256"],
                    "candidate_references": [],
                    "finding": "Active repository intelligence is stale or source coverage is incomplete; prepare and confirm a refresh plan.",
                }
                self.e._validate_schema(result, CONTEXT_SCHEMA)
                return result
            graph = {
                "directed": True,
                "multigraph": True,
                "nodes": inspection["nodes"],
                "relationships": inspection["relationships"],
            }
            if self.e.canonical_sha256(graph) != control["graph_model_sha256"]:
                raise self.e.RepositoryIntelligenceError(
                    "Current native source relationship model differs"
                )
        bootstrap, _ = runtime._json(self.native.BOOTSTRAP)
        _, pointer_identity = storage.read_file(self.native.ACTIVE)
        activation_relative = (
            self.native.RUNTIME + "/receipts/" + pointer["operation_id"] + ".json"
        )
        activation_bytes, _ = storage.read_file(activation_relative)
        # runtime.active() retains committed native custody through this return;
        # member/receipt/SQLite/GraphML failures must not become stale diagnostics.
        if identity_drift_fields:
            if classify_identity_drift and prior_implementation is None:
                return self.e._identity_drift_report(self.root, control, CONTEXT_SCHEMA, identity_drift_fields)
            raise self.e.RepositoryIntelligenceError(self.e._identity_drift_finding(identity_drift_fields))
        native_binding = {
            "backend": "windows-ri-runtime.v1",
            "bootstrap_sha256": self.e.canonical_sha256(bootstrap),
            "enrollment": bootstrap["enrollment"],
            "pointer_identity": pointer_identity.record(),
        }
        generation = {
            "generation_id": request["generation_id"],
            "generation_content_sha256": control["generation_content_sha256"],
            "manifest_path": (base / "manifest.json").relative_to(self.root).as_posix(),
            "manifest_file_sha256": pointer["members"]["manifest.json"],
            "manifest_sha256": manifest["manifest_sha256"],
            "validation_receipt_path": (base / "validation_receipt.json")
            .relative_to(self.root)
            .as_posix(),
            "validation_receipt_file_sha256": pointer["members"][
                "validation_receipt.json"
            ],
            "validation_receipt_sha256": receipt["receipt_sha256"],
            "activation_receipt_path": activation_relative,
            "activation_receipt_file_sha256": self.e.sha256_bytes(activation_bytes),
            "activation_receipt_sha256": pointer["receipt_sha256"],
            "transaction_id": pointer["operation_id"],
            "plan_sha256": request["public_plan_sha256"],
            "bundle_sha256": request["bundle_sha256"],
            "profile": control["profile"],
            "purpose": control["purpose"],
            "component_mode": control["component_mode"],
            "validation_status": "passed",
            "effective_source_sha256": control["effective_source_sha256"],
            "source_status": "current" if require_current_source else "not_checked",
            "native_binding": native_binding,
        }
        report = {
            "schema": CONTEXT_SCHEMA,
            "status": "validated_current" if require_current_source else "validated",
            "project_root": str(self.root),
            "generation": generation,
            "usage_scope": control["ongoing_use_scope"],
            "components": control["components"],
            "coverage": control["coverage"],
            "sqlite_validation": sqlite_validation,
            "networkx_graphml_validation": graph_validation,
            "provenance_validation": {"status": "valid", **native_binding},
            "transaction": {
                "transaction_id": pointer["operation_id"],
                "state": "COMMITTED",
            },
            "candidate_reference_count": len(inventory.get("source_inventory", [])),
            "candidate_only": True,
            "source_artifacts_remain_authoritative": True,
            "limitations": manifest.get("limitations", []),
            "not_claimed": manifest.get("not_claimed", []),
        }
        self.e._validate_schema(report, CONTEXT_SCHEMA)
        return report

    @contextmanager
    def lease(self, *, naos_root, require_current_source=True):
        with self._errors(), self.storage_type(str(self.root)) as storage:
            self._context_root(naos_root)
            if not self._bootstrap_present(storage):
                raise self.e.RepositoryIntelligenceError(
                    "A validated current native RI generation is required; status=not_configured"
                )
            runtime = self.native.WindowsRIRuntime(storage)
            with runtime.active() as pointer:
                context = self._validate_bound(
                    storage, runtime, pointer, naos_root, require_current_source
                )
                if context["status"] != (
                    "validated_current" if require_current_source else "validated"
                ):
                    raise self.e.RepositoryIntelligenceError(
                        f"A validated native RI generation is required; status={context['status']}"
                    )
                base = self.root / context["generation"]["manifest_path"]
                reader = _GenerationReader(
                    storage, base.parent.relative_to(self.root).as_posix(),
                    pointer["members"], self.e
                )
                manifest = reader.json("manifest.json")

                def closing():
                    return self._validate_bound(
                        storage, runtime, pointer, naos_root, require_current_source
                    )

                yield context, base.parent, manifest, closing, reader

    def validate(self, *, naos_root, require_current_source, classify_identity_drift=False):
        with self._errors(), self.storage_type(str(self.root)) as storage:
            self._context_root(naos_root)
            if not self._bootstrap_present(storage):
                return self._empty()
            runtime = self.native.WindowsRIRuntime(storage)
            with runtime.active() as pointer:
                return self._validate_bound(
                    storage, runtime, pointer, naos_root, require_current_source,
                    classify_identity_drift=classify_identity_drift
                )

    def _transactions(self, storage, runtime):
        with runtime.locked() as (_lock, bootstrap):
            records = runtime._records(bootstrap)
            result = []
            for op, record in sorted(records.items()):
                try:
                    state, _ = runtime._journal(runtime._spec(record))
                    error = None
                except (ValueError, OSError, RuntimeError) as exc:
                    state, error = "preparation_incomplete", str(exc)
                result.append(
                    {
                        "transaction_id": op,
                        "state": state.upper(),
                        "generation_id": record["request"]["generation_id"],
                        "journal_path": self.native.RUNTIME
                        + "/operations/"
                        + op
                        + "/intent.json",
                        "error": error,
                    }
                )
            return result

    def status(self, *, naos_root):
        self._context_root(naos_root)
        transactions = []
        active = {}
        unresolved = 0
        gate = self.e._inspect_ri_scope(
            self.root, governed_root=self.native.GOVERNED_ROOT
        ).plan_gate()
        try:
            with self.storage_type(str(self.root)) as storage:
                if self._bootstrap_present(storage):
                    runtime = self.native.WindowsRIRuntime(storage)
                    transactions = self._transactions(storage, runtime)
            unresolved = sum(
                row["state"] not in {"COMMITTED", "ROLLED_BACK"} for row in transactions
            )
            active = (
                {"status": "not_validated_while_recovery_required"}
                if unresolved
                else self.validate(naos_root=naos_root, require_current_source=True,
                    classify_identity_drift=True)
            )
        except (ValueError, OSError, RuntimeError) as exc:
            active = {"status": "invalid", "error": str(exc)}
        result = {
            "schema": self.e.STATUS_SCHEMA,
            "status": "recovery_required"
            if unresolved
            else active.get("status", "invalid"),
            "project_root": str(self.root),
            "provenance": gate,
            "lock": {
                "backend": "Windows LockFileEx",
                "held": False,
                "observation": "released_after_read",
            },
            "transactions": transactions,
            "unresolved_transaction_count": unresolved,
            "active": active,
            "source_artifacts_modified": [],
        }
        self.e._validate_schema(result, self.e.STATUS_SCHEMA)
        return result

    def recover(self, *, naos_root):
        with self._errors(), self.storage_type(str(self.root)) as storage:
            self._context_root(naos_root)
            recovered = []
            incomplete = False
            if self._bootstrap_present(storage):
                runtime = self.native.WindowsRIRuntime(storage)
                for row in self._transactions(storage, runtime):
                    if row["state"] in {"COMMITTED", "ROLLED_BACK"}:
                        continue
                    try:
                        state = runtime.recover(row["transaction_id"]).upper()
                        detail = "Explicit native prefix rollback"
                    except (ValueError, OSError, RuntimeError) as exc:
                        state = "RECOVERY_INCOMPLETE"
                        detail = str(exc)
                        incomplete = True
                    recovered.append(
                        {
                            "transaction_id": row["transaction_id"],
                            "state": state,
                            "journal_path": row["journal_path"],
                            "unreferenced_generation_preserved": True,
                            "detail": detail,
                        }
                    )
            result = {
                "schema": self.e.RECOVERY_RESULT_SCHEMA,
                "status": "recovery_incomplete"
                if incomplete
                else "recovered"
                if recovered
                else "nothing_to_recover",
                "project_root": str(self.root),
                "recovered_transactions": recovered,
                "source_artifacts_modified": [],
            }
            self.e._validate_schema(result, self.e.RECOVERY_RESULT_SCHEMA)
            return result
