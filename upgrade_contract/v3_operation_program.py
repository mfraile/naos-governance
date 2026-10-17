"""Pure, byte-bound publication program for a validated subsequent-v3 plan.

A program names exact prospective files and private journal slots; it grants no
native mutation authority. Native custody must observe every unobserved target,
parent and retained slot and prove the legal platform-specific move topology.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import hashlib
from typing import Any

from . import local_binding as lb, portable_provenance as pp
from . import v3_operation_records as records
from .canonical import canonical_bytes

SCHEMA = "naos.upgrade.v3_publication_program.v1"
PRIVATE_ROOT = ".naos/local/managed-content-v3/journals"
MAX_SLOTS = pp.MAX_TOTAL_CHANGES + pp.MAX_TOTAL_SELECTED_PATHS + 16


class PublicationProgramError(ValueError):
    pass


def _fail(message: str) -> None:
    raise PublicationProgramError(message)


def _closed(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PublicationProgramError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError,
                OverflowError, RecursionError) as exc:
            raise PublicationProgramError("Invalid publication program input") from exc
    return call


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _content(raw: bytes | None, executable: bool | None = None) -> dict[str, Any] | None:
    if raw is None:
        return None
    if type(raw) is not bytes:
        _fail("File payload must be exact bytes")
    return {"sha256": _sha(raw), "size_decimal": str(len(raw)),
            "executable": executable}


def _encode(body: dict[str, Any]) -> bytes:
    lb._bounded_input(body)
    raw = canonical_bytes(body)
    if len(raw) > lb.MAX_RECORD_BYTES:
        _fail("Publication program exceeds local record byte budget")
    return raw


@dataclass(frozen=True)
class ValidatedPublicationProgram:
    raw: bytes
    sha256: str
    _payloads: tuple[tuple[str, bytes], ...]

    @property
    def body(self) -> dict[str, Any]:
        return pp._load_json(self.raw, "publication program")

    @property
    def publication_bytes(self) -> dict[str, bytes]:
        """Detached destination -> exact staged bytes, excluding reused evidence."""
        return dict(self._payloads)


def _replay(plan: records.ValidatedOperationPlan,
            evidence: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(evidence) is not dict:
        _fail("Complete exact plan evidence required")
    consumed = {}
    for name in ("portable_files", "current_bytes", "requested"):
        values = evidence.get(name)
        if type(values) is not dict:
            _fail("Complete exact byte maps required")
        if name == "requested":
            if any(type(row) is not dict for row in values.values()):
                _fail("Exact requested byte rows required")
            consumed[name] = {path: dict(row) for path, row in values.items()}
        else:
            consumed[name] = dict(values)
    captured = evidence.get("capture")
    # Use only the fresh projection produced by this exact plan/evidence check.
    # Every invocation still validates its current caller-owned inputs.
    p, result = records._verified_plan(plan, evidence, _return_projection=True)
    if (evidence.get("capture") is not captured or
            type(evidence.get("requested")) is not dict or
            any(type(row) is not dict for row in evidence["requested"].values()) or
            any(type(evidence.get(name)) is not dict or evidence[name] != before
                for name, before in consumed.items())):
        _fail("Publication evidence changed after plan validation")
    if result["status"] != p["projection_status"] or result["status"] not in {
            "entry_changes", "input_only_profile_transition"}:
        _fail("Replayed actionable projection differs from plan")
    if result["prospective_manifest_sha256"] != p["prospective_head_sha256"]:
        _fail("Prospective portable head differs from approved plan")
    return p, result


def _private_slots(journal_id: str, index: int) -> tuple[str, str]:
    # All generated paths are beneath this exact next-journal namespace.
    prefix = f"{PRIVATE_ROOT}/{journal_id}/publication"
    suffix = f"{index:08d}"
    return f"{prefix}/stages/{suffix}", f"{prefix}/retained/{suffix}"


def _parent_paths(path: str) -> tuple[str, ...]:
    pieces = path.split("/")
    return tuple("/".join(pieces[:n]) for n in range(1, len(pieces)))


def _required_directories(destinations: list[str], capture: dict[str, Any]) -> list[dict[str, Any]]:
    native = capture["native"]
    managed = {item["path"]: item["witness"] for item in native["managed_ancestors"]}
    control = {item["path"]: item["witness"] for item in native["control_directories"]}
    paths = set()
    for destination in destinations:
        for parent in _parent_paths(destination):
            paths.add(parent)
            if len(paths) > lb.MAX_ANCESTORS + len(control) + 1000:
                _fail("Publication parent directory inventory exceeds bound")
    result = []
    for path in sorted(paths, key=lambda x: (x.count("/"), x)):
        if path in managed:
            witness = managed[path]
        else:
            witness = control.get(path)
        if witness is None:
            status = "requires_native_observation"
        elif witness["presence"] == "absent":
            status = "captured_absent_requires_owned_creation"
        else:
            status = "captured_present"
        result.append({"path": path, "native_status": status,
                       "captured_witness": witness})
    return result


def _stage_native_policy(role: str, host: str, before_witness: dict | None,
                         before_mode: bool | None, after_mode: bool | None) -> dict[str, Any]:
    """Final native payload metadata while still enclosed by the private parent."""
    if role.startswith('portable_'):
        return ({'kind': 'posix_portable', 'mode_octal': '0600'}
                if host != 'windows' else {'kind': 'windows_private_portable'})
    if role == 'working_create':
        if type(after_mode) is not bool or before_witness is None or before_witness['presence'] != 'absent':
            _fail('Working create needs exact absent witness and executable intent')
        return ({'kind': 'posix_working_create',
                 'mode_octal': '0755' if after_mode else '0644'}
                if host != 'windows' else {'kind': 'windows_private_working_create'})
    if role != 'working_replace' or type(after_mode) is not bool or before_witness is None:
        _fail('Unknown native payload stage role')
    if host == 'windows':
        return {'kind': 'windows_working_replace', 'source_witness': before_witness}
    if type(before_mode) is not bool or before_witness.get('presence') != 'present':
        _fail('POSIX replacement requires exact present mode witness')
    old = int(before_witness['mode_octal'], 8)
    if old & ~0o777 or bool(old & 0o111) != before_mode:
        _fail('Special or inconsistent POSIX replacement mode')
    updated = old if after_mode == before_mode else ((old & ~0o111) | (0o111 if after_mode else 0))
    return {'kind': 'posix_working_replace', 'mode_octal': f'{updated:04o}',
            'uid_decimal': before_witness['uid_decimal'],
            'gid_decimal': before_witness['gid_decimal'],
            'source_witness': before_witness}


def _program_body(plan: records.ValidatedOperationPlan,
                  evidence: dict[str, Any]) -> tuple[dict[str, Any], tuple[tuple[str, bytes], ...]]:
    p, projected = _replay(plan, evidence)
    files = evidence["portable_files"]
    requested = evidence["requested"]
    current = evidence["current_bytes"]
    capture = evidence["capture"].body
    leaf_by_path = {item["path"]: item for item in capture["leaves"]}
    overlay = projected["portable_overlay"]
    if type(files) is not dict or type(requested) is not dict or type(current) is not dict:
        _fail("Complete exact byte maps required")
    if len(projected["changes"]) + len(overlay) > MAX_SLOTS:
        _fail("Publication slot count exceeded")
    publications = []
    payloads = []
    reused = []
    total_payload = 0

    def append(role: str, destination: str, before: bytes | None, after: bytes,
               *, before_mode: bool | None = None, after_mode: bool | None = None,
               source: bytes | None = None, before_witness: dict | None = None):
        nonlocal total_payload
        if type(after) is not bytes or len(after) > pp.MAX_BASE_BYTES:
            _fail("Invalid or oversized publication payload")
        total_payload += len(after)
        if total_payload > pp.MAX_CUMULATIVE_READ_BYTES:
            _fail("Publication byte-work budget exceeded")
        index = len(publications) + 1
        stage, retained = _private_slots(p["next_journal_id"], index)
        policy = _stage_native_policy(role, p["host"], before_witness, before_mode, after_mode)
        publications.append({"order_decimal": str(index), "role": role,
            "destination": destination, "stage": stage, "retained": retained,
            "before": _content(before, before_mode), "after": _content(after, after_mode),
            "source": _content(source), "before_native_witness": before_witness,
            "native_target_observation": "captured" if before_witness is not None else "required",
            "stage_native_policy": policy})
        payloads.append((destination, after))

    # Only projection-approved managed entry changes become working writes.
    for change in projected["changes"]:
        path = change["path"]
        before = current[path]
        after = requested[path]["output"]
        source = requested[path]["source"]
        if after is None or source is None:
            _fail("Owned change lacks exact source/output bytes")
        witness = leaf_by_path[path]["metadata"]
        role = "working_create" if before is None else "working_replace"
        before_mode = (None if before is None or p["host"] == "windows" else
                       bool(int(witness["mode_octal"], 8) & 0o111))
        append(role, path, before, after, before_mode=before_mode,
               after_mode=requested[path]["executable"], source=source,
               before_witness=witness)

    # The overlay is replay-validated. Existing identical content-addressed
    # objects are shared evidence: they get no stage, move or rollback slot.
    for path in sorted(overlay):
        if path == pp.MANIFEST_PATH:
            continue
        raw = overlay[path]
        if path in files:
            if files[path] != raw:
                _fail("Historical portable evidence collision")
            reused.append({"path": path, "content": _content(raw),
                           "native_target_observation": "required"})
        else:
            append("portable_immutable_create", path, None, raw)

    # The exact new manifest is the last file publication and forward-only
    # boundary. Its prior native identity still requires a held observation.
    append("portable_manifest_forward_only", pp.MANIFEST_PATH,
           files[pp.MANIFEST_PATH], overlay[pp.MANIFEST_PATH])
    destinations = [item["destination"] for item in publications]
    if len(destinations) != len(set(destinations)) or len(destinations) != len(set(p.casefold() for p in destinations)):
        _fail("Aliased publication destinations")
    private = [x[key] for x in publications for key in ("stage", "retained")]
    if len(private) != len(set(private)) or any(path in destinations for path in private):
        _fail("Aliased private publication slots")
    for path in destinations:
        if path.startswith(".naos/"):
            if path not in overlay:
                _fail("Unreplayed portable publication target")
        else:
            pp._path(path)
    folded = sorted(path.casefold() for path in destinations)
    if any(right.startswith(left + "/") for left, right in zip(folded, folded[1:])):
        _fail("Publication file/descendant namespace collision")
    directories = _required_directories(
        destinations + private + [item['path'] for item in reused], capture)
    body = {"schema": SCHEMA, "plan_sha256": plan.sha256,
        "project_id": p["project_id"], "owner_sha256": p["owner_sha256"],
        "binding_id": p["binding_id"], "journal_id": p["next_journal_id"],
        "prior_portable_head_sha256": p["prior_portable_head_sha256"],
        "prospective_portable_head_sha256": p["prospective_head_sha256"],
        "required_directories": directories, "publications": publications,
        "reused_portable_evidence": reused}
    return body, tuple(payloads)


@_closed
def build_publication_program(plan: records.ValidatedOperationPlan,
                              plan_evidence: dict[str, Any]) -> ValidatedPublicationProgram:
    body, payloads = _program_body(plan, plan_evidence)
    raw = _encode(body)
    return ValidatedPublicationProgram(raw, _sha(raw), payloads)


@_closed
def load_publication_program(raw: bytes, plan: records.ValidatedOperationPlan,
                             plan_evidence: dict[str, Any]) -> ValidatedPublicationProgram:
    if type(raw) is not bytes or len(raw) > lb.MAX_RECORD_BYTES:
        _fail("Invalid publication program bytes")
    parsed = pp._load_json(raw, "publication program")
    body, payloads = _program_body(plan, plan_evidence)
    expected = _encode(body)
    if raw != expected or parsed != body:
        _fail("Publication program differs from recomputed projection")
    return ValidatedPublicationProgram(raw, _sha(raw), payloads)
