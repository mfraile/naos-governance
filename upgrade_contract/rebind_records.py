"""Pure absent-store rebind records; no native execution or mutation authority.

Only absent managed-content-v3 store AND absent .naos/upgrade-v1 are supported. Existing,
foreign-complete, foreign-pending and same-binding stores refuse this variant.
Native readers must prove absence, private preparation, lock and continuity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import local_binding as lb
from . import local_store as store
from . import portable_provenance as pp
from .canonical import canonical_bytes
from .joint_capture import PortableWorkingTreeCapture
from .working_tree_capture import WorkingTreeCapture, build_capture

PLAN_SCHEMA = "naos.upgrade.rebind_absent_plan.v1"
INTENT_SCHEMA = "naos.upgrade.rebind_absent_intent.v1"
PROGRESS_SCHEMA = "naos.upgrade.rebind_absent_progress.v1"
LEGACY_SCHEMA = "naos.upgrade.absent_legacy_control.v1"
VARIANT = "absent_local_and_legacy_store"
JOURNAL_ID = "J00000001"
MAX_BYTES = lb.MAX_RECORD_BYTES
PHASES = {
    "prepared",
    "registered",
    "candidate_ready",
    "publish_pending",
    "committed",
    "finalize_pending",
    "finalized",
    "rollback_pending",
    "rolled_back",
}
EDGES = {
    "prepared": {"registered", "rollback_pending"},
    "registered": {"candidate_ready", "rollback_pending"},
    "candidate_ready": {"publish_pending", "rollback_pending"},
    "publish_pending": {"committed", "rollback_pending"},
    "committed": {"finalize_pending"},
    "finalize_pending": {"finalized"},
    "rollback_pending": {"rolled_back"},
    "finalized": set(),
    "rolled_back": set(),
}


class RebindRecordError(ValueError):
    """Malformed record, unsupported variant, or invalid pure transition."""


def _fail(message):
    raise RebindRecordError(message)


def _fields(body, keys):
    lb._fields(body, set(keys.split()), "rebind record")
    lb._bounded_input(body)


def _hash(value):
    return lb._hex(value, lb.HEX64, "rebind digest")


@dataclass(frozen=True)
class ValidatedRebindPlan:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, "rebind plan")


@dataclass(frozen=True)
class ValidatedRebindIntent:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, "rebind intent")


@dataclass(frozen=True)
class ValidatedRebindProgress:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, "rebind progress")


@dataclass(frozen=True)
class ValidatedAbsentLegacy:
    raw: bytes
    sha256: str

    @property
    def body(self):
        return pp._load_json(self.raw, "absent legacy")


def _record(raw, cls, validate):
    try:
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            _fail("Missing or oversized rebind bytes")
        body = pp._load_json(raw, "rebind record")
        validate(body)
        if canonical_bytes(body) != raw:
            _fail("Noncanonical rebind bytes")
        return cls(raw, hashlib.sha256(raw).hexdigest())
    except RebindRecordError:
        raise
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        AttributeError,
    ) as exc:
        raise RebindRecordError("Invalid rebind record") from exc


def _encoded(body):
    try:
        lb._bounded_input(body)
        raw = canonical_bytes(body)
        if len(raw) > MAX_BYTES:
            _fail("Rebind record exceeds byte budget")
        return raw
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise RebindRecordError("Cannot encode rebind record") from exc


def _capture(body):
    _fields(body, "schema native leaves")
    result = build_capture(body["native"], body["leaves"])
    if result.body != body:
        _fail("Capture schema differs")
    return result


def _checked_capture(value):
    if type(value) is not WorkingTreeCapture:
        _fail("Typed working-tree capture required")
    result = _capture(value.body)
    if result != value:
        _fail("Working capture hash/bytes differ")
    return result.body


def _portable(value):
    if type(value) is not pp.ValidatedPortableSnapshot:
        _fail("Validated portable replay required")
    # Internal coherence, not a replacement for complete replay by the reader.
    for raw in (value._manifest_bytes, value._entries_bytes, value._inputs_bytes):
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            _fail("Invalid portable snapshot bytes")
    manifest = value.manifest
    if (
        hashlib.sha256(value._manifest_bytes).hexdigest() != value.manifest_sha256
        or manifest["project_id"] != value.project_id
        or manifest["owner_sha256"] != value.owner_sha256
        or manifest["head_receipt_sha256"] != value.head_receipt_sha256
        or manifest["entries"] != list(value.entries.values())
        or manifest["inputs"] != value.inputs
    ):
        _fail("Portable snapshot fields differ")
    _hash(value.owner_sha256)
    _hash(value.manifest_sha256)
    return value


def load_absent_legacy(raw, capture):
    current = _checked_capture(capture)
    platform = current["native"]["platform"]

    def validate(body):
        _fields(body, "schema path parent_witness witness")
        if (
            body["schema"] != LEGACY_SCHEMA
            or body["path"] != ".naos/upgrade-v1"
            or body["parent_witness"]
            != current["native"]["control_directories"][0]["witness"]
            or body["witness"] != lb.absent_witness(platform, "directory")
        ):
            _fail("Legacy absence does not match captured .naos parent")

    return _record(raw, ValidatedAbsentLegacy, validate)


def _validate_plan(body, portable):
    _fields(
        body,
        "schema operation variant project_id owner_sha256 portable_head_sha256 binding_id source_store_sha256 source_binding_sha256 initial_capture legacy_absence",
    )
    snapshot = _portable(portable)
    entries = snapshot.entries
    if (
        body["schema"] != PLAN_SCHEMA
        or body["operation"] != "rebind"
        or body["variant"] != VARIANT
        or body["project_id"] != snapshot.project_id
        or body["owner_sha256"] != snapshot.owner_sha256
        or body["portable_head_sha256"] != snapshot.manifest_sha256
        or body["source_store_sha256"] is not None
        or body["source_binding_sha256"] is not None
    ):
        _fail("Unsupported store variant or changed portable binding")
    lb._hex(body["binding_id"], lb.BINDING_ID, "new binding ID")
    capture = _capture(body["initial_capture"])
    native = capture.body["native"]
    if native["control_directories"][0]["witness"]["presence"] != "present":
        _fail("Portable control ancestor must already exist")
    parent = native["control_directories"][1]["witness"]
    if parent["presence"] == "present":
        if native["platform"] == "Windows":
            if not parent["security"]["dacl_protected"]:
                _fail("Existing local parent lacks protected security")
        elif parent["mode_octal"] != "0700":
            _fail("Existing local parent is not private; do not chmod during rebind")
    if any(
        item["witness"]["presence"] != "absent"
        for item in native["control_directories"][2:]
    ):
        _fail("Existing or partially existing local storage is unsupported")
    if [x["path"] for x in capture.body["leaves"]] != sorted(entries):
        _fail("Rebind capture must cover exactly the replayed managed paths")
    for leaf in capture.body["leaves"]:
        content = entries[leaf["path"]]["content"]
        if (
            content is not None
            and leaf["content"] is not None
            and native["platform"] != "Windows"
        ):
            executable = bool(int(leaf["metadata"]["mode_octal"], 8) & 0o111)
            if executable != content["executable"]:
                _fail("Executable mismatch requires explicit mode repair")
    load_absent_legacy(_encoded(body["legacy_absence"]), capture)


def load_rebind_plan(raw, portable):
    return _record(
        raw, ValidatedRebindPlan, lambda body: _validate_plan(body, portable)
    )


def _plan(plan, portable):
    if (
        type(plan) is not ValidatedRebindPlan
        or load_rebind_plan(plan.raw, portable) != plan
    ):
        _fail("Unvalidated or forged rebind plan")
    return plan.body


def build_rebind_plan(
    pair,
    *,
    expected_owner_sha256,
    expected_head_sha256,
    binding_id,
    legacy_absence,
    variant=VARIANT,
    source_store=None,
):
    if type(pair) is not PortableWorkingTreeCapture:
        _fail("Typed joint capture required")
    if variant != VARIANT or source_store is not None:
        _fail(
            "Existing, foreign-completed, foreign-pending and same-binding rebind unsupported"
        )
    snapshot = _portable(pair.portable)
    if (
        expected_owner_sha256 != snapshot.owner_sha256
        or expected_head_sha256 != snapshot.manifest_sha256
    ):
        _fail("Expected portable owner/head differs")
    captured = _checked_capture(pair.working_tree)
    if (
        type(legacy_absence) is not ValidatedAbsentLegacy
        or load_absent_legacy(legacy_absence.raw, pair.working_tree) != legacy_absence
    ):
        _fail("Typed legacy absence observation required")
    body = {
        "schema": PLAN_SCHEMA,
        "operation": "rebind",
        "variant": variant,
        "project_id": snapshot.project_id,
        "owner_sha256": expected_owner_sha256,
        "portable_head_sha256": expected_head_sha256,
        "binding_id": binding_id,
        "source_store_sha256": None,
        "source_binding_sha256": None,
        "initial_capture": captured,
        "legacy_absence": legacy_absence.body,
    }
    return load_rebind_plan(_encoded(body), snapshot)


def _validate_prepared(before, after):
    first, last = before["native"], after["native"]
    for key in ("platform", "root_path", "root_chain", "managed_ancestors"):
        if first[key] != last[key]:
            _fail("Native root/managed ancestry changed during local preparation")
    if before["leaves"] != after["leaves"]:
        _fail("Managed bytes/metadata changed during local preparation")
    for index, (old, new) in enumerate(
        zip(first["control_directories"], last["control_directories"], strict=True)
    ):
        if index == 0:
            if old != new:
                _fail("Existing .naos identity/protection changed")
        elif old["witness"]["presence"] == "present" and old != new:
            _fail("Existing private parent witness changed")
        elif new["witness"]["presence"] != "present":
            _fail("Prepared local control directories must be present")


def load_rebind_intent(raw, plan, portable, *, approved_plan_sha256):
    planned = _plan(plan, portable)
    if approved_plan_sha256 != plan.sha256:
        _fail("Supplied approval digest does not match plan")

    def validate(body):
        _fields(
            body,
            "schema operation variant journal_id plan_sha256 approved_plan_sha256 failure_model prepared_capture storage_witnesses",
        )
        if (
            body["schema"] != INTENT_SCHEMA
            or body["operation"] != "rebind"
            or body["variant"] != VARIANT
            or body["journal_id"] != JOURNAL_ID
            or body["plan_sha256"] != plan.sha256
            or body["approved_plan_sha256"] != plan.sha256
            or body["failure_model"] != "application_interruption_v1"
        ):
            _fail("Intent differs from approved absent-store rebind")
        prepared = _capture(body["prepared_capture"])
        _validate_prepared(planned["initial_capture"], prepared.body)
        _fields(body["storage_witnesses"], "lock journal")
        platform = prepared.body["native"]["platform"]
        lb._validate_witness(body["storage_witnesses"]["lock"], platform, "file")
        lb._validate_witness(
            body["storage_witnesses"]["journal"], platform, "directory"
        )
        witnesses = [
            x["witness"] for x in prepared.body["native"]["control_directories"][1:]
        ]
        witnesses += [
            body["storage_witnesses"]["journal"],
            body["storage_witnesses"]["lock"],
        ]
        for index, witness in enumerate(witnesses):
            if witness["presence"] != "present":
                _fail("Prepared storage object absent")
            if platform != "Windows":
                if witness["mode_octal"] != (
                    "0600" if index == len(witnesses) - 1 else "0700"
                ):
                    _fail("Prepared POSIX storage is not private")
                if any(
                    witness[key] != witnesses[0][key]
                    for key in ("uid_decimal", "gid_decimal")
                ):
                    _fail("Prepared storage owner/group differ")
            else:
                if not witness["security"]["dacl_protected"]:
                    _fail("Prepared Windows storage DACL is not protected")
                if witness["security"] != witnesses[0]["security"]:
                    _fail("Prepared Windows security differs")

    return _record(raw, ValidatedRebindIntent, validate)


def build_rebind_intent(
    plan, portable, prepared_capture, *, approved_plan_sha256, storage_witnesses
):
    prepared = _checked_capture(prepared_capture)
    return load_rebind_intent(
        _encoded(
            {
                "schema": INTENT_SCHEMA,
                "operation": "rebind",
                "variant": VARIANT,
                "journal_id": JOURNAL_ID,
                "plan_sha256": plan.sha256,
                "approved_plan_sha256": approved_plan_sha256,
                "failure_model": "application_interruption_v1",
                "prepared_capture": prepared,
                "storage_witnesses": storage_witnesses,
            }
        ),
        plan,
        portable,
        approved_plan_sha256=approved_plan_sha256,
    )


def _intent(intent, plan, portable):
    if (
        type(intent) is not ValidatedRebindIntent
        or load_rebind_intent(
            intent.raw, plan, portable, approved_plan_sha256=plan.sha256
        )
        != intent
    ):
        _fail("Unvalidated or forged rebind intent")
    return intent.body


def candidate_binding(intent, plan, portable):
    body = _intent(intent, plan, portable)
    p = plan.body
    capture = body["prepared_capture"]
    observation = {
        "schema": lb.OBSERVATION_SCHEMA,
        "native": capture["native"],
        "leaves": capture["leaves"],
        "journals": {
            "head_id": JOURNAL_ID,
            "entries": [{"id": JOURNAL_ID, "sha256": intent.sha256}],
        },
        "transaction_state": "quiescent",
        "binding_id": p["binding_id"],
        "diagnostic_python_minor": None,
    }
    # A prospective postcondition record, NOT a claim of current quiescence.
    return lb.load_local_binding(
        lb.encode_local_binding(
            {
                "schema": lb.BINDING_SCHEMA,
                "project_id": p["project_id"],
                "owner_sha256": p["owner_sha256"],
                "portable_head_sha256": p["portable_head_sha256"],
                "binding_id": p["binding_id"],
                "observation": observation,
            }
        )
    )


def _progress_record(raw, intent, result, plan, portable):
    def validate(body):
        _fields(
            body,
            "schema intent_sha256 phase direction revision previous_progress_sha256 candidate_binding_sha256 publication_witness",
        )
        if (
            body["schema"] != PROGRESS_SCHEMA
            or body["intent_sha256"] != intent.sha256
            or type(body["phase"]) is not str
            or body["phase"] not in PHASES
            or body["candidate_binding_sha256"] != result.sha256
        ):
            _fail("Progress record differs from intent/candidate")
        witness = body["publication_witness"]
        if witness is not None:
            lb._validate_witness(
                witness, result.body["observation"]["native"]["platform"], "file"
            )
            if witness["presence"] != "present":
                _fail("Staged binding witness must be present")
            lock = intent.body["storage_witnesses"]["lock"]
            if result.body["observation"]["native"]["platform"] != "Windows":
                if witness["mode_octal"] != "0600" or any(
                    witness[k] != lock[k] for k in ("uid_decimal", "gid_decimal")
                ):
                    _fail("Staged binding private metadata differs")
            elif witness["security"] != lock["security"]:
                _fail("Staged binding private security differs")
        if body["phase"] in {"prepared", "registered"} and witness is not None:
            _fail("Binding candidate cannot precede registration")
        if (
            body["phase"]
            in {
                "candidate_ready",
                "publish_pending",
                "committed",
                "finalize_pending",
                "finalized",
            }
            and witness is None
        ):
            _fail("Binding publication requires exact staged native witness")
        direction = (
            "rollback"
            if body["phase"] in {"rollback_pending", "rolled_back"}
            else "forward"
        )
        if body["direction"] != direction:
            _fail("Progress direction/phase conflict")
        lb._u64(body["revision"], "progress revision")
        if int(body["revision"]) > 16:
            _fail("Progress revision exceeds bounded state machine")
        if body["phase"] == "prepared":
            if body["revision"] != "0" or body["previous_progress_sha256"] is not None:
                _fail("Initial progress must start at zero without predecessor")
        else:
            _hash(body["previous_progress_sha256"])
            if body["revision"] == "0":
                _fail("Progress predecessor requires nonzero revision")

    return _record(raw, ValidatedRebindProgress, validate)


def load_rebind_progress(raw, intent, plan, portable):
    return _progress_record(
        raw, intent, candidate_binding(intent, plan, portable), plan, portable
    )


def initial_progress(intent, plan, portable):
    return load_rebind_progress(
        _encoded(
            {
                "schema": PROGRESS_SCHEMA,
                "intent_sha256": intent.sha256,
                "phase": "prepared",
                "direction": "forward",
                "revision": "0",
                "previous_progress_sha256": None,
                "candidate_binding_sha256": candidate_binding(
                    intent, plan, portable
                ).sha256,
                "publication_witness": None,
            }
        ),
        intent,
        plan,
        portable,
    )


def advance_progress(
    previous,
    phase,
    intent,
    plan,
    portable,
    *,
    live_binding,
    current_portable_head_sha256,
    publication_witness=None,
):
    if (
        type(previous) is not ValidatedRebindProgress
        or load_rebind_progress(previous.raw, intent, plan, portable) != previous
    ):
        _fail("Unvalidated progress predecessor")
    prior = previous.body
    if type(phase) is not str or phase not in EDGES[prior["phase"]]:
        _fail("Illegal rebind phase transition")
    if current_portable_head_sha256 != plan.body["portable_head_sha256"]:
        _fail("Portable head changed during local-only rebind")
    expected = candidate_binding(intent, plan, portable)
    present = live_binding is not None
    if present:
        if (
            type(live_binding) is not lb.ValidatedLocalBinding
            or live_binding != expected
        ):
            _fail("Unknown or foreign live binding; preserve and refuse")
    forward_committed = phase in {"committed", "finalize_pending", "finalized"}
    if forward_committed != present:
        _fail(
            "Commitpoint observation requires forward finalization or precommit rollback"
        )
    if forward_committed and publication_witness != prior["publication_witness"]:
        _fail(
            "Published binding native identity/protection differs or was not observed"
        )
    witness = prior["publication_witness"]
    if phase == "candidate_ready":
        witness = publication_witness
    elif publication_witness is not None and publication_witness != witness:
        _fail("Binding publication witness changed")
    body = {
        "schema": PROGRESS_SCHEMA,
        "intent_sha256": intent.sha256,
        "phase": phase,
        "direction": "rollback"
        if phase in {"rollback_pending", "rolled_back"}
        else "forward",
        "revision": str(int(prior["revision"]) + 1),
        "previous_progress_sha256": previous.sha256,
        "candidate_binding_sha256": expected.sha256,
        "publication_witness": witness,
    }
    return load_rebind_progress(_encoded(body), intent, plan, portable)


@dataclass(frozen=True)
class ValidatedRebindHistory:
    records: tuple[ValidatedRebindProgress, ...]
    sha256: str


def validate_progress_history(records, intent, plan, portable):
    if type(records) is not tuple or not 1 <= len(records) <= 10:
        _fail("Bounded complete progress history required")
    total_bytes = 0
    for record in records:
        if type(record) is not ValidatedRebindProgress or type(record.raw) is not bytes:
            _fail("Typed progress bytes required")
        total_bytes += len(record.raw)
        if total_bytes > MAX_BYTES:
            _fail("Cumulative progress history exceeds byte budget")
    candidate = candidate_binding(intent, plan, portable)
    for index, record in enumerate(records):
        if (
            type(record) is not ValidatedRebindProgress
            or _progress_record(record.raw, intent, candidate, plan, portable) != record
        ):
            _fail("Invalid progress history record")
        body = record.body
        if body["revision"] != str(index):
            _fail("Progress history has missing revision")
        if index == 0:
            if body["phase"] != "prepared":
                _fail("Progress history lacks initial preparation")
        elif (
            body["previous_progress_sha256"] != records[index - 1].sha256
            or body["phase"] not in EDGES[records[index - 1].body["phase"]]
        ):
            _fail("Broken or illegal progress history transition")
        if (
            index
            and body["phase"] != "candidate_ready"
            and body["publication_witness"]
            != records[index - 1].body["publication_witness"]
        ):
            _fail("Binding native witness changed across progress history")
    digest = hashlib.sha256(canonical_bytes([x.sha256 for x in records])).hexdigest()
    return ValidatedRebindHistory(records, digest)


def checkpoint_records(history, intent, plan, portable):
    """Prospective checkpoint only; full legal history and native completion required."""
    if (
        type(history) is not ValidatedRebindHistory
        or validate_progress_history(history.records, intent, plan, portable) != history
    ):
        _fail("Validated complete progress history required")
    progress = history.records[-1]
    phase = progress.body["phase"]
    if phase not in {"finalized", "rolled_back"}:
        _fail("Terminal phase required")
    p = plan.body
    after = candidate_binding(intent, plan, portable) if phase == "finalized" else None
    checkpoint = store.load_local_store(
        store.encode_local_store(
            {
                "schema": store.STORE_SCHEMA,
                "generation": 1,
                "project_id": p["project_id"],
                "owner_sha256": p["owner_sha256"],
                "binding_id": p["binding_id"] if after else None,
                "binding_sha256": after.sha256 if after else None,
                "journals": {
                    "head_id": JOURNAL_ID,
                    "entries": [{"id": JOURNAL_ID, "sha256": intent.sha256}],
                },
                "active_journal_id": None,
                "archives": [],
            }
        )
    )
    marker = store.load_local_terminal(
        store.encode_local_terminal(
            {
                "schema": store.TERMINAL_SCHEMA,
                "intent_sha256": intent.sha256,
                "outcome": "committed" if after else "rolled_back",
                "progress_sha256": progress.sha256,
                "binding_after_sha256": after.sha256 if after else None,
                "portable_head_sha256": p["portable_head_sha256"],
            }
        )
    )
    return checkpoint, marker, after


@dataclass(frozen=True)
class ValidatedRebindCheckpoint:
    """Operation record consistency only; not native completion or readiness."""

    state: store.ValidatedLocalStore
    terminal: store.ValidatedLocalTerminal
    binding_after: lb.ValidatedLocalBinding | None
    history_sha256: str


def validate_checkpoint_records(
    state, terminal, binding_after, history, intent, plan, portable
):
    """Validate persisted checkpoint records against the complete approved operation.

    The generic store codec intentionally cannot infer this operation's unchanged
    portable head, especially for an unbound rollback. Exact rederivation also
    binds every checkpoint/inventory/terminal field, including result absence.
    Native completion, privacy, locks and held observations remain caller duties.
    """
    expected = checkpoint_records(history, intent, plan, portable)
    if (
        type(state) is not store.ValidatedLocalStore
        or type(terminal) is not store.ValidatedLocalTerminal
        or (
            binding_after is not None
            and type(binding_after) is not lb.ValidatedLocalBinding
        )
        or (state, terminal, binding_after) != expected
    ):
        _fail("Persisted checkpoint differs from approved rebind operation")
    store.reconcile_registration(state, binding_after, (JOURNAL_ID,))
    store.reconcile_terminal_reference(
        state,
        JOURNAL_ID,
        terminal,
        progress_sha256=history.records[-1].sha256,
        binding_after=binding_after,
    )
    return ValidatedRebindCheckpoint(state, terminal, binding_after, history.sha256)
