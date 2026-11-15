"""Exact, digest-bound public declarations for entropy-only noise reduction.

No adopter metadata, directory role, prefix, filename existence, UUID shape,
or arbitrary source literal establishes membership in this vocabulary.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path, PurePath, PureWindowsPath
import re
import stat
import sys
import uuid
from typing import Any

CATALOG_SCHEMA = "naos.secret_public_literals.v1"
COPIED_RUNTIME_MARKER = b"# AUTO-" + b"GENERATED: Copied by naos init from the NAOS kit."
CATALOG_FILENAME = "naos_secret_public_literals.json"
CATALOG_SHA256 = "ab18b51b48687722bdf198c5631245c6ea718a7b8ba53bd3a9e40d11106da066"
MAX_CATALOG_BYTES = 1024 * 1024
MAX_ENTRIES = 16_384
MAX_GROUPS = 2048
MAX_CONTEXT_VALUES = 65_536
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = {"literal", "project_path", "kit_path"}


class PublicVocabularyError(ValueError):
    """Invalid shipped declaration: never downgrade to an implicit allowance."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PublicVocabularyError("duplicate_key")
        result[key] = value
    return result


def raw_literal_representations(value: str) -> set[str]:
    """Exact emitted JSON and Python quote contents; no arbitrary decoding."""
    return {value, json.dumps(value, ensure_ascii=True)[1:-1],
            json.dumps(value, ensure_ascii=False)[1:-1],
            value.replace("\\", "\\\\").replace("'", "\\'")}


def _relative(value: str) -> bool:
    windows = PureWindowsPath(value)
    return bool(value and not windows.drive and not windows.root and not value.startswith("/")
                and "\\" not in value and all(part not in {"", ".", ".."} for part in value.split("/")))


def _unsafe_link(metadata) -> bool:
    return bool(stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def read_catalog() -> dict[str, Any]:
    module_path = Path(__file__).absolute()
    path = module_path.parent / CATALOG_FILENAME
    try:
        for ancestor in reversed((module_path.parent, *module_path.parent.parents)):
            metadata = ancestor.lstat()
            if _unsafe_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise PublicVocabularyError("unsafe_module_location")
        module_metadata = module_path.lstat()
        if _unsafe_link(module_metadata) or not stat.S_ISREG(module_metadata.st_mode):
            raise PublicVocabularyError("unsafe_module_location")
        metadata = path.lstat()
        if _unsafe_link(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CATALOG_BYTES:
            raise PublicVocabularyError("not_regular_or_oversized")
        with path.open("rb") as stream:
            raw = stream.read(MAX_CATALOG_BYTES + 1)
        if len(raw) > MAX_CATALOG_BYTES:
            raise PublicVocabularyError("oversized")
        if hashlib.sha256(raw).hexdigest() != CATALOG_SHA256:
            raise PublicVocabularyError("digest_mismatch")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(PublicVocabularyError("nonfinite")))
        if (type(value) is not dict or set(value) != {"schema", "groups"}
                or value["schema"] != CATALOG_SCHEMA or type(value["groups"]) is not list
                or not 1 <= len(value["groups"]) <= MAX_GROUPS):
            raise PublicVocabularyError("shape")
        seen = set()
        entries = 0
        for group in value["groups"]:
            if type(group) is not dict or set(group) != {"kind", "source", "selector", "component_sha256", "values"}:
                raise PublicVocabularyError("group_shape")
            if group["kind"] not in _KINDS or not isinstance(group["source"], str) or not _relative(group["source"]):
                raise PublicVocabularyError("origin")
            if (type(group["selector"]) is not str or not 1 <= len(group["selector"]) <= 256
                    or type(group["component_sha256"]) is not str or not _SHA256.fullmatch(group["component_sha256"])
                    or type(group["values"]) is not list or not group["values"]):
                raise PublicVocabularyError("declaration")
            for item in group["values"]:
                if (type(item) is not str or not 1 <= len(item) <= 4096 or any(ord(c) < 32 for c in item)
                        or (group["kind"] != "literal" and not _relative(item))):
                    raise PublicVocabularyError("entry")
                identity = (group["kind"], item, group["source"], group["selector"])
                if identity in seen:
                    raise PublicVocabularyError("duplicate_entry")
                seen.add(identity)
                entries += 1
                if entries > MAX_ENTRIES:
                    raise PublicVocabularyError("entry_limit")
        return value
    except PublicVocabularyError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise PublicVocabularyError("unreadable_or_malformed") from None


def context_values(catalog: dict[str, Any], *, project_root: PurePath, kit_root: PurePath,
                   naos_root: str, runtime_layout: str = "kit") -> set[str]:
    """Expand only whole independently declared operands under observed roots."""
    if not _relative(naos_root):
        raise PublicVocabularyError("invalid_naos_root")
    if runtime_layout not in {"kit", "copied_project"}:
        raise PublicVocabularyError("invalid_runtime_layout")
    roots = (project_root, kit_root)
    values = set()
    def add(value):
        values.update(raw_literal_representations(value))
        if len(values) > MAX_CONTEXT_VALUES:
            raise PublicVocabularyError("context_limit")
    for root in roots:
        add(str(root))
        add(root.as_posix())
    add(CATALOG_SHA256)
    for group in catalog["groups"]:
        # The shipped catalog declares its own exact selector names as public.
        # Digest validation precedes admission; adopter selector fields do not.
        add(group["selector"])
        add(group["component_sha256"])
        for value in group["values"]:
            add(value)
            if group["kind"] == "project_path":
                relative = naos_root + value[4:] if value.startswith("naos/") else value
                add(relative)
                paths = (project_root.joinpath(*relative.split("/")),)
                add(str(paths[0].relative_to(project_root)))
            elif group["kind"] == "kit_path" and runtime_layout == "kit":
                paths = (kit_root.joinpath(*value.split("/")),)
                add(str(paths[0].relative_to(kit_root)))
            else:
                paths = ()
            for path in paths:
                add(str(path))
                add(path.as_posix())
    return values


def load_public_literals(*, root: Path, naos_root: str) -> tuple[set[str], dict[str, Any]]:
    catalog = read_catalog()
    kit_root = Path(__file__).resolve().parents[1]
    try:
        with Path(__file__).open("rb") as stream:
            copied_marker = COPIED_RUNTIME_MARKER in stream.read(2048).splitlines()
    except OSError:
        raise PublicVocabularyError("unreadable_module_location") from None
    # Existing installer marker selects the conservative copied operand set.
    # Coincident roots also avoid inventing kit-only adopter destinations.
    runtime_layout = "copied_project" if copied_marker or kit_root == root.resolve() else "kit"
    values = context_values(catalog, project_root=root.absolute(), kit_root=kit_root, naos_root=naos_root, runtime_layout=runtime_layout)
    if type(sys.executable) is str and sys.executable and Path(sys.executable).is_absolute():
        values.update(raw_literal_representations(sys.executable))
    enrollment_id, enrollment_status = public_enrollment_id(root)
    if enrollment_id is not None:
        values.update(raw_literal_representations(enrollment_id))
    return values, {"status": "valid", "schema": CATALOG_SCHEMA, "sha256": CATALOG_SHA256,
                    "declarations": sum(len(group["values"]) for group in catalog["groups"]),
                    "context_values": len(values), "kit_root_basis": "executing_module_location", "runtime_layout": runtime_layout,
                    "enrollment_uuid": enrollment_status}


def public_enrollment_id(root: Path) -> tuple[str | None, str]:
    """Recompute one public label; makes no ownership/authenticity assertion."""
    try:
        native_root = root.resolve(strict=True)
        path = native_root
        for part in (".naos", "upgrade-v1", "OWNER.json"):
            path = path / part
            metadata = path.lstat()
            mode = metadata.st_mode
            if _unsafe_link(metadata) or (part != "OWNER.json" and not stat.S_ISDIR(mode)):
                return None, "unsafe_input_not_admitted"
        if not stat.S_ISREG(mode) or path.stat().st_size > 65_536:
            return None, "unsafe_input_not_admitted"
        with path.open("rb") as stream:
            raw = stream.read(65_537)
        if len(raw) > 65_536:
            return None, "unsafe_input_not_admitted"
        owner = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        authorization = owner.get("enrollment_authorization") if isinstance(owner, dict) else None
        digest = authorization.get("plan_sha256") if isinstance(authorization, dict) else None
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            return None, "missing_or_invalid_input_not_admitted"
        expected = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"naos:managed-content:{native_root}:{digest}"))
        if type(owner.get("project_id")) is not str or owner["project_id"] != expected:
            return None, "mismatched_input_not_admitted"
        return expected, "exact_public_derivation_no_authority_claim"
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return None, "missing_or_invalid_input_not_admitted"


def public_audit_ids(text: str, *, root: Path | None = None, naos_root: str | None = None) -> set[str]:
    """Validate producer API against exact event objects; never admit ID shapes."""
    if len(text) > 8 * 1024 * 1024:
        return set()
    try:
        from naos_audit_log import recompute_public_audit_event_id, parse_timestamp, event_file_paths
        from naos_policy import SAFE_FALLBACK_POLICY
    except ImportError:
        return set()
    try:
        objects = [json.loads(text, object_pairs_hook=_unique_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))]
    except (ValueError, RecursionError):
        try:
            objects = [json.loads(line, object_pairs_hook=_unique_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite"))) for line in text.splitlines() if line.strip()]
        except (ValueError, RecursionError):
            return set()
    result = set()
    pending = [(obj, 0) for obj in objects]
    visited = 0
    while pending:
        obj, depth = pending.pop()
        visited += 1
        if visited > 50_000 or depth > 64:
            return set()
        if isinstance(obj, dict):
            expected = recompute_public_audit_event_id(obj)
            if expected is not None and obj.get("event_id") == expected:
                result.update(raw_literal_representations(expected))
                if (root is not None and naos_root is not None and _relative(naos_root)
                        and obj.get("project_root") == str(root) and obj.get("naos_root") == naos_root):
                    try:
                        timestamp = parse_timestamp(obj["generated_at"])
                        if timestamp is not None and timestamp.tzinfo is not None and timestamp.utcoffset() is not None:
                            audit_operand = SAFE_FALLBACK_POLICY["paths"]["audit_log_root"]
                            if type(audit_operand) is str and _relative(audit_operand):
                                for operand in event_file_paths(root / naos_root / audit_operand, obj):
                                    for value in (str(operand), operand.as_posix(), operand.relative_to(root).as_posix()):
                                        result.update(raw_literal_representations(value))
                    except (ValueError, OverflowError, OSError, TypeError):
                        pass
            pending.extend((value, depth + 1) for value in obj.values() if isinstance(value, (dict, list)))
        elif isinstance(obj, list):
            pending.extend((value, depth + 1) for value in obj if isinstance(value, (dict, list)))
    return result



def collect_public_audit_event_references(files: list[Path], *, root: Path, naos_root: str) -> dict[str, dict[str, Any]]:
    """Bounded context-bound public event/body/operand map from selected inputs.

    Callers must independently select their inputs and continue ordinary body
    scanning. This classification map is not an event authenticity assertion.
    """
    if len(files) > 50_000:
        return {}
    result = {}
    physical_references: set[str] = set()
    total_bytes = 0
    try:
        from naos_audit_log import recompute_public_audit_event_id, parse_timestamp, event_file_paths
        from naos_policy import SAFE_FALLBACK_POLICY
    except ImportError:
        return {}
    for path in files:
        if path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        try:
            parts = path.relative_to(root).parts
            component = root
            unsafe = False
            for part in parts:
                component /= part
                if _unsafe_link(component.lstat()):
                    unsafe = True
                    break
            metadata = path.lstat()
            if unsafe or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
                continue
            with path.open("rb") as stream:
                raw = stream.read(8 * 1024 * 1024 + 1)
            total_bytes += len(raw)
            if total_bytes > 32 * 1024 * 1024:
                return {}
            if len(raw) > 8 * 1024 * 1024:
                continue
            text = raw.decode("utf-8")
            def strict_load(value):
                return json.loads(value, object_pairs_hook=_unique_pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
            try:
                objects = [strict_load(text)]
            except (ValueError, RecursionError):
                objects = [strict_load(line) for line in text.splitlines() if line.strip()]
            pending = [(value, 0) for value in objects]
            visited = 0
            while pending:
                obj, depth = pending.pop()
                visited += 1
                if depth > 64 or visited > 50_000:
                    return {}
                if type(obj) is dict:
                    identifier = recompute_public_audit_event_id(obj)
                    if (identifier is not None and obj.get("project_root") == str(root)
                            and obj.get("naos_root") == naos_root and _relative(naos_root)):
                        timestamp = parse_timestamp(obj["generated_at"])
                        if timestamp is not None and timestamp.tzinfo is not None and timestamp.utcoffset() is not None:
                            audit_operand = SAFE_FALLBACK_POLICY["paths"]["audit_log_root"]
                            if type(audit_operand) is str and _relative(audit_operand):
                                operands = event_file_paths(root / naos_root / audit_operand, obj)
                                # A selected JSONL audit event must occupy one of
                                # its two exact names. Embedded JSON reports keep
                                # the current derived operand, as before.
                                if path.suffix.lower() == ".jsonl" and path not in operands:
                                    continue
                                if path in operands:
                                    # A wrapped repeat cannot replace an actual
                                    # selected legacy file with a nonexistent
                                    # current operand. Two selected exact files
                                    # have a stable, order-independent choice.
                                    operand = path
                                    if identifier in physical_references:
                                        operand = min(path, Path(result[identifier]["event_file"]), key=str)
                                    physical_references.add(identifier)
                                elif identifier in physical_references:
                                    continue
                                else:
                                    operand = operands[0]
                                result[identifier] = {"event": obj, "event_file": str(operand)}
                    pending.extend((value, depth + 1) for value in obj.values() if type(value) in {dict, list})
                elif type(obj) is list:
                    pending.extend((value, depth + 1) for value in obj if type(value) in {dict, list})
                if len(result) > 16_384:
                    return {}
        except (OSError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            continue
    return result


def _selected_physical_audit_event_references(files, *, root, naos_root, policy, context):
    """Physical anchors share the existing proof cache; broad JSON cannot erase them.

    Preserve the legacy embedded-event reader separately. No new path/ID shape,
    proof budget, authentication or ordinary-body exemption is introduced.
    """
    if context is None or len(files) > 50_000 or not _relative(naos_root):
        return {}
    try:
        from naos_policy import SAFE_FALLBACK_POLICY
        from naos_audit_log import recompute_public_audit_event_id, parse_timestamp, event_file_paths
        chosen = policy if policy is not None else SAFE_FALLBACK_POLICY
        if type(chosen) is not dict or type(chosen.get('paths', {})) is not dict:
            return {}
        audit_operand = chosen.get('paths', {}).get('audit_log_root', 'audit_log')
        if (audit_operand != SAFE_FALLBACK_POLICY['paths']['audit_log_root']
                or not _relative(audit_operand) or context.root != root.absolute()):
            return {}
        audit_root = root / naos_root / audit_operand
        result = {}
        for path in sorted(set(files)):
            relative = path.absolute().relative_to(root.absolute()).as_posix()
            try:
                parts = path.absolute().relative_to(audit_root.absolute()).parts
            except ValueError:
                continue
            if len(parts) != 2 or path.suffix.lower() != '.jsonl':
                continue
            raw = context.read(relative)
            if len(raw) > 8 * 1024 * 1024:
                return {}
            try:
                event = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
            except (UnicodeError, ValueError, RecursionError):
                # Bad candidate content remains scanned; it cannot replace or
                # erase independently validated neighboring event anchors.
                continue
            pending = [(event, 0)]
            visited = 0
            while pending:
                value, depth = pending.pop()
                visited += 1
                if visited > 50_000 or depth > 64:
                    return {}
                if type(value) is dict:
                    pending.extend((item, depth + 1) for item in value.values()
                                   if type(item) in {dict, list})
                elif type(value) is list:
                    pending.extend((item, depth + 1) for item in value
                                   if type(item) in {dict, list})
            identifier = recompute_public_audit_event_id(event)
            if (identifier is None or event.get('project_root') != str(root)
                    or event.get('naos_root') != naos_root):
                continue
            stamp = parse_timestamp(event['generated_at'])
            if stamp is None or stamp.tzinfo is None or stamp.utcoffset() is None:
                continue
            try:
                operands = event_file_paths(audit_root, event)
            except (OverflowError, ValueError):
                # An aware timestamp can still exceed UTC's representable
                # range. Refuse this event without erasing valid neighbors.
                continue
            if path not in operands:
                continue
            previous = result.get(identifier)
            if previous is None or str(path) < previous['event_file']:
                result[identifier] = {'event': event, 'event_file': str(path)}
            if len(result) > 16_384:
                return {}
        context.admission_checkpoint()
        return result
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, ImportError, RecursionError):
        return {}


def _audit_session_path_literals(event: dict[str, Any], *, root: Path, naos_root: str,
                                 policy: dict[str, Any] | None) -> set[str]:
    """Derive exact constructor labels; do not classify raw session IDs."""
    from naos_policy import SAFE_FALLBACK_POLICY
    from naos_session_identity import SESSION_AWARE_REPORTS, validate_session_id

    roles = {
        "naos.session_identity.v1": ("session_identity_report", {"session_started", "report_generated"}),
        "naos.session_lifecycle.v1": ("session_lifecycle_report", {
            "session_started", "session_checkpoint", "session_ended", "report_generated"}),
        "naos.operator_attribution.v1": ("operator_attribution_report", {"operator_attributed"}),
    }
    role = roles.get(event.get("source_report"))
    if role is None or role[0] not in SESSION_AWARE_REPORTS or event.get("event_type") not in role[1]:
        return set()
    session_id = event.get("session_id")
    if type(session_id) is not str:
        return set()
    try:
        validate_session_id(session_id)
    except ValueError:
        return set()
    if policy is None:
        policy = SAFE_FALLBACK_POLICY
    if type(policy) is not dict or type(policy.get("paths", {})) is not dict:
        return set()
    paths = policy.get("paths", {})
    key = role[0]
    segments = (naos_root, paths.get("sessions_root") or "sessions",
                paths.get("reports_dir") or "reports", paths.get(key) or key)
    if any(type(value) is not str or not _relative(value) for value in segments):
        return set()
    managed, sessions, reports, filename = segments
    # Lexical constructor labels only: no filesystem lookup, history rewrite,
    # source-report read or claim of native identity/producer authenticity.
    latest = root / managed / reports / filename
    session_root = root / managed / sessions / session_id
    report_root = session_root / reports
    mirror = report_root / filename
    summary = event.get("event_payload_summary")
    if (event.get("source_report_path") != str(latest)
            or event.get("related_artifacts") != [str(latest), str(mirror)]
            or type(event.get("source_report_hash")) is not str
            or not _SHA256.fullmatch(event["source_report_hash"])
            or type(summary) is not dict
            or any(summary.get(field) != value for field, value in (
                ("schema", event["source_report"]), ("session_id", session_id),
                ("source_report_path", str(latest))))):
        return set()
    result = set()
    for operand in (session_root, report_root, mirror):
        for value in (str(operand), operand.as_posix(), str(operand.relative_to(root)),
                      operand.relative_to(root).as_posix()):
            result.update(raw_literal_representations(value))
    return result


def _audit_day_directory_literals(operands: tuple[Path, ...], *, root: Path) -> set[str]:
    """Exact dated parents of already validated event operands; no new reads."""
    result = set()
    for directory in {operand.parent for operand in operands}:
        for value in (str(directory), directory.as_posix(), str(directory.relative_to(root)),
                      directory.relative_to(root).as_posix()):
            result.update(raw_literal_representations(value))
    return result


def selected_public_audit_literals(files: list[Path], *, root: Path, naos_root: str,
                                  policy: dict[str, Any] | None = None, context=None) -> set[str]:
    """Derive exact full ID/path strings; grant no ordinary scan coverage."""
    result = set()
    session_values: set[str] = set()
    session_exhausted = False
    day_values: set[str] = set()
    day_exhausted = False
    from naos_audit_log import event_file_paths
    references = collect_public_audit_event_references(files, root=root, naos_root=naos_root)
    if context is not None:
        for identifier, reference in _selected_physical_audit_event_references(
                files, root=root, naos_root=naos_root, policy=policy, context=context).items():
            references.setdefault(identifier, reference)
    for identifier, reference in references.items():
        selected = Path(reference["event_file"])
        operands = event_file_paths(selected.parent.parent, reference["event"])
        for operand in operands:
            for value in (identifier, str(operand), operand.as_posix(), operand.relative_to(root).as_posix()):
                result.update(raw_literal_representations(value))
                if len(result) > MAX_CONTEXT_VALUES:
                    return set()
        if not session_exhausted:
            session_values.update(_audit_session_path_literals(reference["event"], root=root,
                naos_root=naos_root, policy=policy))
            if len(session_values) > MAX_CONTEXT_VALUES:
                session_values.clear()
                session_exhausted = True
        if not day_exhausted:
            day_values.update(_audit_day_directory_literals(operands, root=root))
            if len(day_values) > MAX_CONTEXT_VALUES:
                day_values.clear()
                day_exhausted = True
    if not session_exhausted and len(result | session_values) <= MAX_CONTEXT_VALUES:
        result.update(session_values)
    # New day labels cannot displace the existing event/session vocabulary.
    if not day_exhausted and len(result | day_values) <= MAX_CONTEXT_VALUES:
        result.update(day_values)
    return result


# These schema bytes ship with both kit and copied scanner layouts. A replaced
# adopter schema cannot expand the public operand contract.
_REFERENCE_SCHEMAS = {'pr_risk_classification': '4c238cfdff0c214402e8435f24e825bec2ec1b21c8196bcda6270b0aa854ec4b', 'self_check': 'a8c8388efc1ea6897e96b2dccfba513f0389ff0b8fe0adde94dbf3e659364e5a', 'evidence_classification_report': '5cdb1dc62bf40054f41240b43693ee307b35dac427190d3e0f26ac19b2414e47', 'dashboard_summary': 'f853ca6db22405ed32d0552d93d1f89c7428b49ab733af5a74f496ef471318c7', 'evidence_pack': 'db950d0fd159b07312e42b3540e0c3f7ddb2d1e48b878c152b8b39fdd3b6ffbb', 'task_claim_report': '48a8d7b0f5631f7fb0069da715b9a3062103c808b436d5a75de0abc505e375fe', 'task_claims': '6c8cf8b03cf4d2dd78f11c7cf6cd59a482f6c2a704644131ba5f4f63dca8f68f', 'task_registry': 'c681ebafc2fb53af86f28332363ddab4cdcb97b9be7a236d247d37df3ae5d901', 'local_context_index': '9060ce868c254045b116917a3d4774343a607a4cfb10a1b56a3199ee9daee6f1', 'external_evidence_ingest': 'd96e6c9ebce6d9d1720ba4660cd64bc42f8652d9871b9fdeabde358599e3eefb', 'systemic_impact_family_review': 'afee3bdd6f0dd3cdfacfe64c9335acc71a9034bab50cb6e4d2f7fb7e6a2e3fb5', 'session_identity': '8a67d3e44fc6197579fe15afb8a777883ef5118ec7d67de46d28f7ea2a037513', 'session_lifecycle': '5f83f799a83efcd551fa01a976e9bf157bbb747a1dabde011cb2503b10853df0', 'operator_attribution': '44af3d532e02bc5241671ba1413d9a5606bc094555864e9a3433066c078ac649', 'session_index': '3d7a66bcf2eadbcef34d32d14039733e0aba6efc291798f6c8057708140d8869', 'systemic_impact_review': 'b44095b4033923d4a90f1a72442eb96547da99117c376d2efcc12df197181942', 'task_context_pack': '53e5d96a0f83af7b86fa07a06d41d1bbcede547d75f4bf7f3b5e14c1eee2159e', 'test_evidence_health': '6f7d0cd4aa1bdc53aae66f5b84c276b5cc8c00b2d73718ce405523e08474028f', 'gate_status': 'ae6b8779f2862697c6851ddf5d5c82565916630cc5a9af3b2be2fe849ab98fd9', 'secret_hygiene': 'f6346cf46f35be03f96629f2093cbae42dfb2b0cd27ca15930900aa72b1d7c3d'}
_TASK_PUBLIC_ID = re.compile(r"T-[0-9]{3}\Z")
_CONSTRUCTOR_REFERENCE_SCHEMA_NAMES = (
    'session_identity', 'session_lifecycle', 'operator_attribution',
    'session_index', 'systemic_impact_review',
    'task_context_pack', 'test_evidence_health', 'gate_status', 'secret_hygiene',
)


def _bounded_regular_bytes(path: Path, *, boundary: Path, limit: int) -> bytes:
    parts = path.relative_to(boundary).parts
    component = boundary
    # Native ancestors must also be ordinary directories, including junctions.
    for ancestor in reversed((boundary, *boundary.parents)):
        metadata = ancestor.lstat()
        if _unsafe_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise PublicVocabularyError("unsafe_reference_input")
    for part in parts:
        component /= part
        if _unsafe_link(component.lstat()):
            raise PublicVocabularyError("unsafe_reference_input")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        raise PublicVocabularyError("unsafe_reference_input")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise PublicVocabularyError("oversized_reference_input")
    return raw


def _reference_document(path: Path, *, root: Path, schema_name: str, raw: bytes | None = None) -> Any:
    from jsonschema import Draft202012Validator
    import yaml
    schema_root = Path(__file__).absolute().parents[1]
    schema_path = schema_root / "schemas" / "naos" / (schema_name + ".schema.json")
    schema_bytes = _bounded_regular_bytes(schema_path, boundary=schema_root, limit=131_072)
    if hashlib.sha256(schema_bytes).hexdigest() != _REFERENCE_SCHEMAS[schema_name]:
        raise PublicVocabularyError("reference_schema_digest_mismatch")
    schema = json.loads(schema_bytes.decode("utf-8"), object_pairs_hook=_unique_pairs)
    if raw is None:
        raw = _bounded_regular_bytes(path, boundary=root, limit=1024 * 1024)
    if len(raw) > 1024 * 1024:
        raise PublicVocabularyError("oversized_reference_input")
    text = raw.decode("utf-8")
    if path.suffix == ".json":
        document = json.loads(text, object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    else:
        class StrictLoader(yaml.SafeLoader):
            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise PublicVocabularyError("reference_alias")
                return super().compose_node(parent, index)
            def construct_mapping(self, node, deep=False):
                pairs = []
                for key, value in node.value:
                    pairs.append((self.construct_object(key, deep=deep), self.construct_object(value, deep=deep)))
                return _unique_pairs(pairs)
        document = yaml.load(text, Loader=StrictLoader)
    pending = [(document, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 50_000 or depth > 64:
            raise PublicVocabularyError("reference_complexity")
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise PublicVocabularyError("reference_nonstring_key")
            pending.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is float and not math.isfinite(value):
            raise PublicVocabularyError("reference_nonfinite")
    Draft202012Validator(schema).validate(document)
    return document


def selected_public_reference_literals(files: list[Path], *, root: Path, naos_root: str) -> set[str]:
    """Whole default ordinal task operands from selected canonical inputs only.

    All source IDs and bodies still undergo the ordinary scan. Only the public
    T-NNN ordinal namespace is recognized. Session IDs, namespaced task IDs,
    authored paths and arbitrary filenames establish no membership.
    """
    if not _relative(naos_root) or len(files) > 50_000:
        return set()
    selected = set(files)
    result = set()
    def add(relative):
        path = root
        for part in relative.split("/"):
            path /= part
            try:
                if _unsafe_link(path.lstat()):
                    return
            except FileNotFoundError:
                break
        path = root.joinpath(*relative.split("/"))
        for value in (relative, str(Path(relative)), str(path), path.as_posix()):
            result.update(raw_literal_representations(value))
        if len(result) > MAX_CONTEXT_VALUES:
            raise PublicVocabularyError("reference_context_limit")
    task_path = root / naos_root / "TASK_REGISTRY.yaml"
    if task_path in selected:
        try:
            document = _reference_document(task_path, root=root, schema_name="task_registry")
            tasks = document["tasks"] if type(document) is dict else document
            ids = [task["id"] for task in tasks]
            if len(ids) > 10_000 or len(set(ids)) != len(ids):
                raise PublicVocabularyError("ambiguous_task_ids")
            for identifier in ids:
                if _TASK_PUBLIC_ID.fullmatch(identifier):
                    add(naos_root + "/active/" + identifier + ".md")
                    add(naos_root + "/active/" + identifier + "_compact.md")
        except PublicVocabularyError as error:
            if str(error) == "reference_context_limit":
                return set()
        except (ImportError, OSError, ValueError, TypeError, KeyError, RecursionError):
            pass
        except Exception as error:
            # jsonschema/yaml validation exceptions are optional admission failures.
            if error.__class__.__module__.split(".")[0] not in {"jsonschema", "yaml"}:
                raise
    return result



def external_result_id_for(source_sha256: str, run_index: int, result_index: int) -> str:
    """Pure exact source-digest/ordinal label; grants no source verification."""
    if (type(source_sha256) is not str or len(source_sha256) != 64
            or any(c not in "0123456789abcdef" for c in source_sha256)
            or type(run_index) is not int or run_index < 0
            or type(result_index) is not int or result_index < 0):
        raise ValueError("Invalid external result identity inputs")
    payload = json.dumps({"source_sha256": source_sha256, "run_index": run_index,
                          "result_index": result_index}, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False)
    return "sarif-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def recompute_public_external_result_id(record: Any) -> str | None:
    """Strict stored defining fields; arbitrary neighboring values stay scanned."""
    fields = {"external_result_id", "source_sha256", "run_index", "result_index"}
    if type(record) is not dict or not fields <= record.keys():
        return None
    try:
        expected = external_result_id_for(record["source_sha256"], record["run_index"], record["result_index"])
    except (ValueError, TypeError, UnicodeError):
        return None
    return expected if type(record["external_result_id"]) is str and record["external_result_id"] == expected else None


def recompute_public_external_route_id(record: Any) -> str | None:
    identifier = recompute_public_external_result_id(record)
    return "CPR-EXTERNAL-SARIF-" + identifier[6:].upper() if identifier is not None else None


def _verified_local_chunk_labels(document: dict[str, Any], artifacts: list[dict[str, Any]]) -> set[str]:
    """Recompute only the producer's displayed global prefix, never raw labels."""
    if "artifact_chunks" not in document:
        return set()  # Legacy artifact-only reports establish no chunk membership.
    from naos_local_context_index import chunk_id_for
    chunks, counts = document["artifact_chunks"], document.get("chunk_counts")
    if type(chunks) is not list or len(chunks) > 200 or type(counts) is not dict:
        raise PublicVocabularyError("invalid_public_chunk_prefix")
    total = 0
    for artifact in artifacts:
        count = artifact.get("chunk_count")
        if (type(count) is not int or not 0 <= count <= MAX_ENTRIES
                or artifact.get("source_reference") != artifact["path"]):
            raise PublicVocabularyError("invalid_public_chunk_parent")
        total += count
    if (type(counts.get("artifacts")) is not int or counts["artifacts"] != len(artifacts)
            or type(counts.get("chunks")) is not int or counts["chunks"] != total
            or len(chunks) != min(total, 200)):
        raise PublicVocabularyError("inconsistent_public_chunk_counts")
    admitted, position = set(), 0
    for artifact in artifacts:
        for ordinal in range(1, min(artifact["chunk_count"], len(chunks) - position) + 1):
            record = chunks[position]
            identifier = chunk_id_for(artifact["artifact_id"], ordinal)
            if (type(record) is not dict or record.get("chunk_id") != identifier
                    or record.get("artifact_id") != artifact["artifact_id"]
                    or record.get("path") != artifact["path"]
                    or record.get("source_reference") != artifact["path"]
                    or identifier in admitted):
                raise PublicVocabularyError("invalid_or_duplicate_public_chunk_identity")
            admitted.add(identifier)
            position += 1
    if position != len(chunks):
        raise PublicVocabularyError("unbound_public_chunk_record")
    return admitted


def selected_public_derived_report_ids(files: list[Path], *, root: Path, naos_root: str) -> set[str]:
    """Exact producer-recomputed IDs from two selected default report operands.

    These labels assert no producer authenticity, truthful content or authority.
    Defining fields and all other report values retain ordinary body scanning.
    Custom/unselected report paths, copied IDs alone and neighboring values
    establish no membership.
    """
    if not _relative(naos_root) or len(files) > 50_000:
        return set()
    try:
        from naos_policy import SAFE_FALLBACK_POLICY
    except ImportError:
        return set()
    selected, result = set(files), set()
    contracts = (("local_context_index_report", "local_context_index", "naos.local_context_index.v1", "indexed_artifacts"),
                 ("external_evidence_ingest_report", "external_evidence_ingest", "naos.external_evidence_ingest.v2", "result_records"))
    for key, schema_name, schema_id, bucket in contracts:
        relative = SAFE_FALLBACK_POLICY["paths"]["reports_dir"] + "/" + SAFE_FALLBACK_POLICY["paths"][key]
        if not _relative(relative):
            continue
        path = root / naos_root / relative
        if path not in selected:
            continue
        try:
            document = _reference_document(path, root=root, schema_name=schema_name)
            if (type(document) is not dict or document.get("schema") != schema_id
                    or document.get("project_root") != str(root) or document.get("naos_root") != naos_root
                    or type(document.get(bucket)) is not list or len(document[bucket]) > MAX_ENTRIES):
                continue
            admitted, identities, positions = set(), set(), set()
            for record in document[bucket]:
                if schema_name == "local_context_index":
                    from naos_local_context_index import recompute_public_artifact_id
                    identifier = recompute_public_artifact_id(record)
                    aliases = (identifier, "artifact:" + identifier) if identifier is not None else ()
                else:
                    identifier = recompute_public_external_result_id(record)
                    if identifier is not None:
                        position = (record["source_sha256"], record["run_index"], record["result_index"])
                        if position in positions or record["source_sha256"] != document["summary"].get("source_sha256"):
                            raise PublicVocabularyError("ambiguous_derived_report_identity")
                        positions.add(position)
                    aliases = (identifier, recompute_public_external_route_id(record)) if identifier is not None else ()
                if identifier is None or identifier in identities:
                    raise PublicVocabularyError("invalid_or_duplicate_derived_report_identity")
                identities.add(identifier)
                for alias in aliases:
                    admitted.update(raw_literal_representations(alias))
            if schema_name == "local_context_index":
                for identifier in _verified_local_chunk_labels(document, document[bucket]):
                    admitted.update(raw_literal_representations(identifier))
            result.update(admitted)
            if len(result) > MAX_CONTEXT_VALUES:
                return set()
        except (ImportError, OSError, ValueError, TypeError, KeyError, RecursionError):
            continue
        except Exception as error:
            if error.__class__.__module__.split(".")[0] not in {"jsonschema", "yaml"}:
                raise
    return result


_SECRET_FINDING_PREFIX = "secret_hygiene.sha256."
_SECRET_FINDING_DOMAIN = b"naos.secret_finding.v1\x00"


def secret_finding_id(item: dict[str, Any]) -> str:
    """Content address of the redacted finding body, never its secret value.

    This public derivation is a label, not producer authentication. Every body
    field other than the ID participates; consumers retain the original body.
    """
    body = {key: value for key, value in item.items() if key != "id"}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":"), allow_nan=False).encode("ascii")
    return _SECRET_FINDING_PREFIX + hashlib.sha256(_SECRET_FINDING_DOMAIN + raw).hexdigest()


def _verified_secret_finding_id(item: dict[str, Any]) -> str | None:
    identifier = item.get("id")
    if (type(identifier) is not str or not identifier.startswith(_SECRET_FINDING_PREFIX)
            or not _SHA256.fullmatch(identifier[len(_SECRET_FINDING_PREFIX):])
            or any(type(item.get(key)) is not str for key in ("severity", "status", "message"))
            or type(item.get("human_review_required")) is not bool
            or type(item.get("not_claimed")) is not list
            or any(type(value) is not str for value in item["not_claimed"])):
        return None
    try:
        expected = secret_finding_id(item)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return None
    return expected if identifier == expected else None


def public_secret_finding_ids(text: str) -> set[str]:
    """Exact recomputation from bounded strict JSON, including copied bodies.

    IDs, classification references and the classifier's one fixed wrapper are
    public only when the complete underlying body establishes the digest. Raw
    paths, messages, source IDs and unknown neighboring strings remain scanned.
    """
    if len(text.encode("utf-8")) > 8 * 1024 * 1024:
        return set()
    def strict_load(value):
        return json.loads(value, object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    try:
        try:
            objects = [strict_load(text)]
        except (ValueError, RecursionError):
            objects = [strict_load(line) for line in text.splitlines() if line.strip()]
        pending = [(obj, 0) for obj in objects]
        visited = 0
        objects_to_verify = []
        while pending:
            obj, depth = pending.pop()
            visited += 1
            if visited > 50_000 or depth > 64:
                return set()
            if type(obj) is dict:
                if visited + len(pending) + len(obj) > 50_000:
                    return set()
                objects_to_verify.append(obj)
                pending.extend((value, depth + 1) for value in obj.values())
            elif type(obj) is list:
                if visited + len(pending) + len(obj) > 50_000:
                    return set()
                pending.extend((value, depth + 1) for value in obj)
        result = set()
        for obj in objects_to_verify:
            identifier = _verified_secret_finding_id(obj)
            if identifier is not None:
                result.update(raw_literal_representations(identifier))
                # Exact existing naos_evidence_classification producer at its
                # missing-classification diagnostic, not arbitrary prefixes.
                classified_id = "evidence_classification.missing." + identifier
                result.update(raw_literal_representations(classified_id))
                # Exact naos_sarif_export.build_result identity pairs. These
                # inputs contain only fixed source labels and the verified ID;
                # no arbitrary SARIF source/rule field establishes membership.
                for source_id, finding_id in (("secret_hygiene", identifier),
                        ("self_check", identifier), ("evidence_classification", classified_id)):
                    pair = json.dumps([source_id, finding_id], ensure_ascii=True, separators=(",", ":"))
                    alias = source_id + "." + finding_id + "." + hashlib.sha256(pair.encode("utf-8")).hexdigest()
                    result.update(raw_literal_representations(alias))
                if len(result) > MAX_CONTEXT_VALUES:
                    return set()
        return result
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return set()


def _classifier_ordinal_aliases(path: Path, raw: bytes, *, root: Path) -> set[str]:
    """Exact evidence-contract namespaces from one complete selected vector.

    This proves the positional label constructor, never source truth or producer
    authenticity. Original diagnostic and source bodies remain ordinary inputs.
    """
    relative = path.absolute().relative_to(root.absolute()).as_posix()
    if not relative.endswith(('/reports/evidence_classification_report.json', '/reports/self_check.json')):
        return set()
    schema_name = 'self_check' if relative.endswith('/self_check.json') else 'evidence_classification_report'
    from jsonschema import ValidationError
    try:
        document = _reference_document(path, root=root, schema_name=schema_name, raw=raw)
    except ValidationError:
        return set()
    naos_root = document.get('naos_root')
    if (type(naos_root) is not str or not _relative(naos_root)
            or relative != naos_root + '/reports/' + schema_name + '.json'
            or document.get('project_root') != str(root.absolute())
            or document.get('schema') != 'naos.' + schema_name + '.v1'
            or document.get('profile') not in {'quickstart', 'lite', 'standard', 'assured'}):
        return set()
    rows = document.get('findings')
    if schema_name == 'self_check':
        checks = [check for check in document['checks'] if check.get('id') == 'naos_evidence_classification']
        if (len(checks) != 1 or set(checks[0]) != {'id', 'returncode', 'status', 'summary', 'findings'}
                or type(checks[0]['returncode']) is not int or type(checks[0]['summary']) is not dict):
            return set()
        rows = checks[0].get('findings')
    if type(rows) is not list or len(rows) > MAX_ENTRIES:
        return set()
    aliases = set()
    for ordinal, item in enumerate(rows, start=1):
        if (type(item) is not dict
                or any(type(item.get(key)) is not str for key in ('id', 'severity', 'status', 'message'))):
            return set()
        if item['status'] != 'missing_classification':
            if item.get('id_scheme') == 'report_ordinal_v1' or item['id'].startswith('EC-'):
                return set()
            continue
        if (item['id'] != f'EC-{ordinal}' or item.get('id_scheme') != 'report_ordinal_v1'
                or item['severity'] not in {'blocking', 'required', 'advisory'}
                or item['message'] != 'Finding lacks declared provenance classification; inferred candidate requires human review.'
                or item.get('human_review_required') is not True
                or item.get('evidence_classification') != 'confirmed'
                or item.get('classification_scope') != 'classifier_diagnostic_observed_at_scan_only'
                or item.get('not_claimed') != ['source finding truth', 'issue resolution', 'human review replacement']
                or any(type(item.get(key)) is not str or not item[key] for key in
                       ('finding_id', 'source_report', 'source_bucket', 'scan_generated_at', 'source_observed_at', 'inferred_classification'))
                or any(type(item.get(key)) is not str or not _SHA256.fullmatch(item[key])
                       for key in ('source_item_sha256', 'source_report_sha256'))
                or type(item.get('source_index')) is not int or item['source_index'] < 0
                or item.get('evidence_refs') != [{'type':'generated_report', 'ref':item['source_report']}]):
            return set()
        aliases.update(raw_literal_representations('naos_evidence_classification/' + item['id']))
    return aliases


def selected_public_secret_finding_literals(files: list[Path], *, root: Path) -> set[str]:
    """Selected-corpus references to fully recomputed new finding IDs only."""
    if len(files) > 50_000:
        return set()
    total_bytes = 0
    result = set()
    for path in files:
        if path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        try:
            raw = _bounded_regular_bytes(path, boundary=root, limit=8 * 1024 * 1024)
            total_bytes += len(raw)
            if total_bytes > 32 * 1024 * 1024:
                return set()
            result.update(public_secret_finding_ids(raw.decode("utf-8")))
            try:
                result.update(_classifier_ordinal_aliases(path, raw, root=root))
            except (OSError, UnicodeError, ValueError, TypeError, RecursionError, ImportError):
                pass
            if len(result) > MAX_CONTEXT_VALUES:
                return set()
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
            continue
    return result


def selected_public_producer_witness_literals(files: list[Path], *, root: Path, naos_root: str, context=None) -> set[str]:
    """Independent bounded projection of canonical, already-selected producers.

    Generic corpus exhaustion remains a refusal. These exact source roles may
    independently prove ordinal/event references; prefixes never prove values.
    Current bytes, complete original constructors and recomputed audit filenames
    are required. Ordinary source/consumer bodies and credential checks remain.
    """
    from naos_secret_managed_operands import ProofBudget
    context = context if context is not None else ProofBudget(root)
    try:
        if context.root.absolute() != root.absolute():
            return set()
    except (AttributeError, TypeError, ValueError, OSError):
        return set()
    from naos_policy import SAFE_FALLBACK_POLICY
    audit_operand = SAFE_FALLBACK_POLICY['paths']['audit_log_root']
    if (len(files) > 50_000 or type(naos_root) is not str or not _relative(naos_root)
            or type(audit_operand) is not str or not _relative(audit_operand)):
        return set()
    canonical = {naos_root+'/reports/'+name+'.json'
                 for name in ('self_check','evidence_classification_report')}
    audit_parts = (*naos_root.split('/'), *audit_operand.split('/'))
    result = set()
    total_bytes = 0
    candidates = 0
    for path in files:
        try:
            relative = path.absolute().relative_to(root.absolute()).as_posix()
            parts = relative.split('/')
            ordinal = relative in canonical
            audit = (tuple(parts[:len(audit_parts)]) == audit_parts
                     and len(parts) == len(audit_parts)+2 and path.suffix == '.jsonl')
            if not ordinal and not audit:
                continue
            candidates += 1
            if candidates > MAX_ENTRIES:
                return set()
            raw = context.read(relative)
            total_bytes += len(raw)
            if total_bytes > 32*1024*1024:
                return set()
            values = set()
            if ordinal:
                values = _classifier_ordinal_aliases(path, raw, root=root)
            else:
                lines = [line for line in raw.decode('utf-8').splitlines() if line.strip()]
                if len(lines) != 1:
                    continue
                event = json.loads(lines[0], object_pairs_hook=_unique_pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
                if type(event) is not dict:
                    continue
                references = collect_public_audit_event_references([path], root=root, naos_root=naos_root)
                identifier = event.get('event_id')
                if len(references) != 1 or identifier not in references:
                    continue
                reference = references[identifier]
                operand = Path(reference['event_file'])
                if reference['event'] != event or operand.absolute() != path.absolute():
                    continue
                for value in (identifier, str(operand), operand.as_posix(),
                              operand.relative_to(root).as_posix()):
                    values.update(raw_literal_representations(value))
            if context.read(relative) != raw:
                return set()
            result.update(values)
            if len(result) > MAX_CONTEXT_VALUES:
                return set()
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError, ImportError):
            continue
    try:
        context.admission_checkpoint()
    except (OSError, ValueError):
        return set()
    return result


def _claim_validator(name):
    from jsonschema import Draft202012Validator
    schema_root = Path(__file__).absolute().parents[1]
    raw = _bounded_regular_bytes(schema_root / 'schemas' / 'naos' / (name + '.schema.json'),
                                 boundary=schema_root, limit=131_072)
    if hashlib.sha256(raw).hexdigest() != _REFERENCE_SCHEMAS[name]:
        raise PublicVocabularyError('reference_schema_digest_mismatch')
    return Draft202012Validator(json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs))


def _public_claim_record(record):
    """Exact producer-form defining fields; nonce shape is not recomputation."""
    from naos_task_claims import safe_fragment, validate_task_id, parse_timestamp
    if type(record) is not dict or record.get('claim_source') != 'naos_task_claims':
        raise PublicVocabularyError('claim_source')
    task, time, identifier = (record.get(key) for key in ('task_id', 'claimed_at', 'claim_id'))
    if (type(task) is not str or validate_task_id(task) != (task, None)
            or type(time) is not str or len(time) > 128 or time != time.strip()
            or any(ord(c) < 32 for c in time) or parse_timestamp(time) is None
            or type(identifier) is not str):
        raise PublicVocabularyError('claim_defining_fields')
    prefix = 'claim-' + safe_fragment(task, 'task', 40) + '-' + safe_fragment(time, 'time', 24) + '-'
    if not identifier.startswith(prefix) or re.fullmatch(r'[0-9a-f]{12}', identifier[len(prefix):]) is None:
        raise PublicVocabularyError('claim_constructor')
    return identifier, (task, time, record['claim_source'])


def selected_public_claim_context(files: list[Path], *, root: Path, naos_root: str, policy=None):
    """Selected default defining registry only; no corpus-wide ID allowance."""
    if not _relative(naos_root) or len(files) > 50_000:
        return None
    path = root / naos_root / 'task_claims.yaml'
    if path not in set(files):
        return None
    try:
        from naos_secret_managed_operands import ProofBudget
        proof = ProofBudget(root)
        document = _reference_document(path, root=root, schema_name='task_claims',
                                       raw=proof.read(naos_root + '/task_claims.yaml'))
        records = document['claims']
        if len(records) > MAX_ENTRIES:
            raise PublicVocabularyError('claim_count')
        known = {}
        for record in records:
            identifier, defining = _public_claim_record(record)
            if identifier in known:
                raise PublicVocabularyError('duplicate_claim_id')
            known[identifier] = defining
        proof.verify_cached()
        from naos_policy import SAFE_FALLBACK_POLICY, evidence_pack_output_path, report_default_path, sessions_root_path
        selected_policy = policy if policy is not None else SAFE_FALLBACK_POLICY
        carriers = {}
        for key, path in {
            'task_claim_report': report_default_path(root, naos_root, selected_policy, 'task_claim_report'),
            'dashboard_summary': report_default_path(root, naos_root, selected_policy, 'dashboard_summary_report'),
            'evidence_pack': evidence_pack_output_path(root, naos_root, selected_policy),
        }.items():
            if path is not None:
                relative = path.absolute().relative_to(root.absolute()).as_posix()
                if not _relative(relative):
                    raise PublicVocabularyError('unsafe_claim_carrier')
                carriers[key] = relative
        session_base = sessions_root_path(root, naos_root, selected_policy).relative_to(root).as_posix() + '/'
        return {'known': known, 'proof': proof, 'selected': set(files), 'carriers': carriers, 'session_base': session_base}
    except (ImportError, OSError, ValueError, TypeError, KeyError, RecursionError):
        return None
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return None


def _session_constructor_spellings(root: PurePath, naos_root: str, session_id: str,
                                   filename: str) -> tuple[set[str], set[str]]:
    latest = root / naos_root / 'reports' / filename
    mirror = root / naos_root / 'sessions' / session_id / 'reports' / filename
    def spellings(path):
        return {str(path), path.as_posix(), str(path.relative_to(root)), path.relative_to(root).as_posix()}
    return spellings(latest), spellings(mirror)


def selected_public_constructor_context(files: list[Path], *, root: Path, naos_root: str,
                                         profile: str, policy=None, context=None):
    """Fresh selected session anchors and finite shipped filename constructors.

    Hash/schema agreement establishes metadata consistency, not authenticity or
    secret safety. Raw IDs and ordinary body strings receive no new allowance.
    New proof reads share the scanner's existing 32MiB domain and final check.
    """
    if not files or len(files) > 50_000 or not _relative(naos_root):
        return None
    try:
        from naos_secret_managed_operands import ProofBudget
        from naos_policy import SAFE_FALLBACK_POLICY, report_default_path, sessions_index_path
        from naos_audit_log import summarize_source_report
        chosen = policy if policy is not None else SAFE_FALLBACK_POLICY
        paths = chosen.get('paths', {})
        if (type(paths) is not dict or any(paths.get(key, default) != default for key, default in
                                         (('reports_dir', 'reports'), ('sessions_root', 'sessions')))):
            return None
        declarations = [group for group in read_catalog()['groups'] if group['source'] == 'scripts/naos_policy.py'
                        and group['selector'] == 'session_report_default_path.literal_role_pairs']
        if len(declarations) != 1:
            return None
        roles = {}
        for pair in declarations[0]['values']:
            role, filename = pair.split(':', 1)
            if (not re.fullmatch(r'[a-z_]+', role) or not _relative(filename)
                    or '/' in filename or ':' in filename or role in roles):
                return None
            if paths.get(role, filename) == filename:
                roles[role] = filename
        selected = set(files)
        proof = context if context is not None else ProofBudget(root)
        if proof.root != root.absolute():
            return None
        source_roles = {
            'naos.session_identity.v1': ('session_identity_report', 'session_identity'),
            'naos.session_lifecycle.v1': ('session_lifecycle_report', 'session_lifecycle'),
            'naos.operator_attribution.v1': ('operator_attribution_report', 'operator_attribution'),
        }
        sessions = set()
        for reference in _selected_physical_audit_event_references(
                files, root=root, naos_root=naos_root, policy=chosen, context=proof).values():
            event = reference['event']
            source_role = source_roles.get(event.get('source_report'))
            if (Path(reference['event_file']) not in selected or source_role is None
                    or event.get('profile') != profile or source_role[0] not in roles
                    or not _audit_session_path_literals(event, root=root, naos_root=naos_root, policy=chosen)):
                continue
            latest = report_default_path(root, naos_root, chosen, source_role[0])
            mirror = root / naos_root / 'sessions' / event['session_id'] / 'reports' / roles[source_role[0]]
            if latest not in selected or mirror not in selected:
                continue
            relative = latest.absolute().relative_to(root.absolute()).as_posix()
            raw = proof.read(relative)
            if (hashlib.sha256(raw).hexdigest() != event['source_report_hash']
                    or proof.read(mirror.relative_to(root).as_posix()) != raw):
                continue
            document = _reference_document(latest, root=root, schema_name=source_role[1], raw=raw)
            if (document.get('session_id') != event['session_id'] or document.get('profile') != profile
                    or summarize_source_report(document, latest) != event['event_payload_summary']):
                continue
            sessions.add(event['session_id'])
        if not sessions:
            return None
        by_session = {session: {role: _session_constructor_spellings(root, naos_root, session, filename)
                               for role, filename in roles.items()} for session in sessions}
        labels = set().union(*(mirrors for entries in by_session.values() for _, mirrors in entries.values()))
        if len(labels) > MAX_CONTEXT_VALUES:
            return None
        carriers = {
            report_default_path(root, naos_root, chosen, 'systemic_impact_report').relative_to(root).as_posix(): 'systemic_impact_review',
            report_default_path(root, naos_root, chosen, 'dashboard_summary_report').relative_to(root).as_posix(): 'dashboard_summary',
            sessions_index_path(root, naos_root, chosen).relative_to(root).as_posix(): 'session_index',
            report_default_path(root, naos_root, chosen, 'secret_hygiene_report').relative_to(root).as_posix(): 'secret_hygiene',
        }
        if len(carriers) != 4:
            return None
        proof.admission_checkpoint()
        return {'proof': proof, 'selected': selected, 'labels': labels, 'sessions': by_session,
                'carriers': carriers, 'profile': profile}
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, ImportError, RecursionError):
        return None
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return None


def public_constructor_label_spans(text: str, relative: str, *, root: Path,
                                     naos_root: str, context) -> set[tuple[int, int]]:
    """Exact schema-bound metadata quotes; no global session-value admission."""
    if (context is None or relative not in context['carriers'] or not _relative(relative)
            or root.joinpath(*relative.split('/')) not in context['selected']):
        return set()
    try:
        from naos_secret_managed_operands import _OffsetJSON, MAX_METADATA_NODES
        from jsonschema import Draft202012Validator
        schema_name = context['carriers'][relative]
        def target(path):
            if schema_name == 'secret_hygiene':
                return (len(path) == 4 and path[0] == 'scans'
                        and path[1] in {'input_files', 'scope_inventory'}
                        and type(path[2]) is int and path[3] == 'path')
            if schema_name == 'session_index':
                return (len(path) == 5 and path[0] == 'sessions' and type(path[1]) is int
                        and path[2] == 'latest_reports' and type(path[3]) is str and path[4] == 'session_path')
            prefix = ('systemic_impact_review',) if schema_name == 'dashboard_summary' else ()
            if (len(path) == len(prefix) + 5 and path[:len(prefix)] == prefix
                    and path[len(prefix):len(prefix) + 3] == ('aggregate_review', 'producer_input_binding', 'derived_outputs')
                    and type(path[-2]) is int and path[-1] == 'path'):
                return True
            return (len(path) == len(prefix) + 4 and path[:len(prefix)] == prefix
                    and path[len(prefix)] == 'artifact_families' and type(path[-3]) is int
                    and path[-2] == 'files_found' and type(path[-1]) is int)
        class ConstructorOffsets(_OffsetJSON):
            def __init__(self, text):
                # Retain every existing decoder limit and additionally bound
                # this consumer's exact metadata coordinates.
                super().__init__(text)
                self.constructor_nodes = 0

            def value(self, path=(), depth=0):
                self.whitespace()
                start = self.index
                if target(path):
                    self.constructor_nodes += 1
                    if self.constructor_nodes > MAX_METADATA_NODES:
                        raise ValueError('constructor_metadata_nodes')
                value = super().value(path, depth)
                if target(path) and type(value) is str:
                    self.strings[path] = (start, self.index, value)
                    if len(self.strings) > MAX_METADATA_NODES:
                        raise ValueError('constructor_metadata_nodes')
                return value
        raw = context['proof'].read(relative)
        if raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n') != text:
            return set()
        parser = ConstructorOffsets(text)
        document = parser.parse()
        # Carrier bodies can exceed1MiB. Reuse the existing8MiB offset parser,
        # 50,000metadata-coordinate cap and shared32MiB proof budget; do not
        # change the older reference reader's1MiB/complexity limits.
        schema_root = Path(__file__).absolute().parents[1]
        schema_path = schema_root / 'schemas/naos' / (schema_name + '.schema.json')
        schema_raw = _bounded_regular_bytes(schema_path, boundary=schema_root, limit=131_072)
        if hashlib.sha256(schema_raw).hexdigest() != _REFERENCE_SCHEMAS[schema_name]:
            return set()
        Draft202012Validator(json.loads(schema_raw, object_pairs_hook=_unique_pairs)).validate(document)
        if schema_name != 'session_index' and (
                document.get('project_root') != str(root) or document.get('naos_root') != naos_root
                or document.get('profile') != context['profile']):
            return set()
        result = set()
        for coordinate, (start, end, value) in parser.strings.items():
            if not target(coordinate) or value not in context['labels']:
                continue
            if schema_name == 'secret_hygiene':
                row = document['scans'][coordinate[1]][coordinate[2]]
                statuses = ({'read', 'read_error', 'decode_error', 'symlink'}
                            if coordinate[1] == 'input_files' else
                            {'selected', 'unselected_suffix', 'unselected_file',
                             'excluded', 'symlink', 'read_error', 'directory'})
                if type(row) is not dict or row.get('status') not in statuses:
                    continue
                if set(row) != {'path', 'status'}:
                    if (coordinate[1] != 'input_files' or row['status'] != 'read'
                            or set(row) != {'path', 'status', 'sha256', 'size_bytes'}
                            or type(row['sha256']) is not str or not _SHA256.fullmatch(row['sha256'])
                            or type(row['size_bytes']) is not int or row['size_bytes'] < 0):
                        continue
            if schema_name == 'session_index':
                record = document['sessions'][coordinate[1]]
                pair = context['sessions'].get(record['session_id'], {}).get(coordinate[3])
                if (pair is None or record['profile'] != context['profile'] or value not in pair[1]
                        or record['latest_reports'][coordinate[3]].get('latest_path') not in pair[0]):
                    continue
            prefix = ('systemic_impact_review',) if schema_name == 'dashboard_summary' else ()
            if (len(coordinate) == len(prefix) + 5
                    and coordinate[len(prefix):len(prefix) + 3] == ('aggregate_review', 'producer_input_binding', 'derived_outputs')):
                row = document
                for part in coordinate[:-1]:
                    row = row[part]
                if not any(row.get('key') == 'session_report_copy:' + role and value in pair[1]
                           for roles in context['sessions'].values() for role, pair in roles.items()):
                    continue
            result.add((start, end))
        context['proof'].admission_checkpoint()
        return result
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, ImportError, RecursionError):
        return set()
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return set()


def public_git_comparison_spans(text: str, relative: str, *, root: Path, naos_root: str,
                                selected: list[Path], policy=None, context=None) -> set[tuple[int, int]]:
    """Exact selected PR-risk comparison quote coordinates, entropy only.

    Declared safe refs, the finite comparison mode and both frozen metadata
    tuples must agree with resolve_diff_comparison's constructor. This is label
    consistency, not commit existence, producer authenticity or evidence truth.
    """
    if not _relative(naos_root) or not _relative(relative) or len(selected) > 50_000:
        return set()
    path = root.joinpath(*relative.split('/'))
    if path not in selected:
        return set()
    try:
        from jsonschema import ValidationError
        from naos_secret_managed_operands import _OffsetJSON, ProofBudget
        from naos_policy import SAFE_FALLBACK_POLICY, report_default_path, safe_policy_path
        chosen = policy if policy is not None else SAFE_FALLBACK_POLICY
        canonical = report_default_path(root, naos_root, chosen, 'pr_risk_classification_report')
        proof = None
        raw = _bounded_regular_bytes(path, boundary=root, limit=1024 * 1024)
        if raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n') != text:
            return set()
        try:
            document = _reference_document(path, root=root, schema_name='pr_risk_classification', raw=raw)
        except ValidationError:
            return set()
        if (document.get('schema') != 'naos.pr_risk_classification.v1'
                or document.get('project_root') != str(root.absolute())
                or document.get('naos_root') != naos_root):
            return set()
        if path != canonical:
            # One policy-selected declaration establishes only carrier role and
            # current byte identity; review dispositions/obligations are not run.
            record_name = chosen.get('paths', {}).get('systemic_impact_family_review_record')
            if type(record_name) is not str or not _relative(record_name):
                return set()
            record_path = safe_policy_path(root / naos_root, record_name,
                                           field='systemic_impact_family_review_record')
            proof = context if context is not None else ProofBudget(root)
            if proof.root != root.absolute():
                return set()
            record_raw = proof.read(record_path.absolute().relative_to(root.absolute()).as_posix())
            if len(record_raw) > 1024 * 1024:
                return set()
            try:
                record = _reference_document(record_path, root=root,
                    schema_name='systemic_impact_family_review', raw=record_raw)
            except ValidationError:
                return set()
            if (record['scope']['project_root'] != str(root.absolute())
                    or record['scope']['naos_root'] != naos_root
                    or record['scope']['profile'] != document['profile']
                    or len(record['reviews']) > MAX_ENTRIES):
                return set()
            role_bound = False
            for row in record['reviews']:
                if type(row) is not dict:
                    return set()
                if row.get('source_family_id') != 'pr_risk_classification':
                    continue
                refs, hashes = row.get('evidence_refs'), row.get('evidence_sha256')
                if (type(refs) is not list or len(refs) > MAX_ENTRIES
                        or any(type(ref) is not str or not _relative(ref) for ref in refs)
                        or type(hashes) is not dict):
                    return set()
                if relative in refs and hashes.get(relative) == hashlib.sha256(raw).hexdigest():
                    role_bound = True
            if not role_bound or proof.read(relative) != raw:
                return set()
        git = document['git']
        if (not {'base_ref', 'head_ref'} <= set(git)
                or any(value is not None and type(value) is not str for value in (git['base_ref'], git['head_ref']))):
            return set()
        # These producer helpers are pure ref validation/finite mode selection;
        # resolution and all Git execution remain outside this admission path.
        from naos_pr_risk_classification import infer_diff_args, validate_diff_ref
        _, source = infer_diff_args(git['base_ref'], git['head_ref'])
        base = validate_diff_ref(git['base_ref'], label='base_ref')
        head = validate_diff_ref(git['head_ref'], label='head_ref')
        coordinates = {('git', key, 'diff_args', 0) for key in ('diff_metadata', 'diff_line_metadata')}
        resolved = None
        expected = None
        for key in ('diff_metadata', 'diff_line_metadata'):
            metadata = git.get(key)
            required = {'diff_source', 'diff_args', 'git_status', 'resolved_commits'}
            optional = ({'lines_scanned', 'truncated', 'unparsed_added_file_headers', 'untracked'}
                        if key == 'diff_line_metadata' else
                        {'untracked_files_included', 'untracked_git_status', 'untracked_git_exit_code', 'untracked_error'})
            if (type(metadata) is not dict
                    or not required <= set(metadata) or set(metadata) - required - optional
                    or metadata['diff_source'] != source or metadata['git_status'] != 'available'
                    or type(metadata['resolved_commits']) is not dict
                    or set(metadata['resolved_commits']) != ({'base_ref', 'head_ref'} if base else {'head_ref'})
                    or len({len(value) for value in metadata['resolved_commits'].values() if type(value) is str}) != 1
                    or any(type(value) is not str or re.fullmatch(r'(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', value) is None
                           for value in metadata['resolved_commits'].values())
                    or any(type(metadata[name]) is not int or metadata[name] < 0 for name in
                           ('lines_scanned', 'unparsed_added_file_headers', 'untracked_files_included') if name in metadata)
                    or ('truncated' in metadata and metadata['truncated'] is not True)
                    or ('untracked' in metadata and type(metadata['untracked']) is not dict)
                    or ('untracked_git_status' in metadata and metadata['untracked_git_status'] not in {'available', 'unavailable'})
                    or ('untracked_git_exit_code' in metadata and type(metadata['untracked_git_exit_code']) is not int)
                    or ('untracked_error' in metadata and type(metadata['untracked_error']) is not str)):
                return set()
            current = metadata['resolved_commits']
            if resolved is not None and current != resolved:
                return set()
            resolved = current
            for label, declared in (('base_ref', base), ('head_ref', head)):
                if declared and re.fullmatch(r'(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', declared):
                    if current.get(label, '').lower() != declared.lower():
                        return set()
            expected = (resolved['base_ref'] + '...' + resolved['head_ref']) if base else resolved['head_ref']
            if metadata['diff_args'] != [expected]:
                return set()
        class ComparisonOffsets(_OffsetJSON):
            def value(self, path=(), depth=0):
                self.whitespace()
                start = self.index
                value = super().value(path, depth)
                if path in coordinates and type(value) is str:
                    self.strings[path] = (start, self.index, value)
                return value
        parser = ComparisonOffsets(text)
        parser.parse()
        if proof is not None:
            proof.verify_cached()
        return {(start, end) for coordinate, (start, end, value) in parser.strings.items()
                if coordinate in coordinates and value == expected}
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, ImportError, KeyError):
        return set()


def public_claim_label_spans(text: str, relative: str, *, root: Path, naos_root: str, context) -> set[tuple[int, int]]:
    """Finite report-carrier claim_id coordinates linked to selected registry.

    All defining fields and neighboring strings retain ordinary detection. This
    proves constructor-form consistency, not random nonce origin, authenticity,
    ownership, approval or evidence verification.
    """
    if context is None or not _relative(relative) or root.joinpath(*relative.split('/')) not in context['selected']:
        return set()
    carriers = context.get('carriers', {})
    session_base = context.get('session_base', naos_root + '/sessions/')
    session_parts = relative[len(session_base):].split('/') if relative.startswith(session_base) else []
    session_carrier = (len(session_parts) == 3 and _relative(session_parts[0])
                       and ':' not in session_parts[0] and not any(ord(c) < 32 for c in session_parts[0])
                       and session_parts[1:] == ['reports', 'task_claim_report.json'])
    if relative not in set(carriers.values()) and not session_carrier:
        return set()
    try:
        observed = context['proof'].read(relative).decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')
        if observed != text:
            return set()
        from naos_secret_managed_operands import _OffsetJSON, OperandRefusal
        class ClaimOffsets(_OffsetJSON):
            def __init__(self, value):
                super().__init__(value)
                self.claim_nodes = 0
                self.claim_strings = {}
            def value(self, path=(), depth=0):
                self.claim_nodes += 1
                if self.claim_nodes > 50_000:
                    raise OperandRefusal('claim_nodes')
                self.whitespace()
                start = self.index
                result = super().value(path, depth)
                if path and path[-1] == 'claim_id' and type(result) is str:
                    self.claim_strings[path] = (start, self.index, result)
                return result
        parser = ClaimOffsets(text)
        document = parser.parse()
        def bound(value, schema):
            return (type(value) is dict and value.get('schema') == schema
                    and value.get('project_root') == str(root.absolute()) and value.get('naos_root') == naos_root)
        def at(value, prefix):
            for key in prefix:
                if type(value) is not dict:
                    return None
                value = value.get(key)
            return value
        prefixes = []
        if bound(document, 'naos.task_claim_report.v1'):
            session = document.get('session_id')
            session_path = (session_base + session + '/reports/task_claim_report.json'
                            if type(session) is str and _relative(session) and '/' not in session and ':' not in session
                            and not any(ord(c) < 32 for c in session) else None)
            if relative not in {carriers.get('task_claim_report'), session_path}:
                return set()
            prefixes = [()]
        elif relative == carriers.get('evidence_pack') and bound(document, 'naos.evidence_pack.v1'):
            _claim_validator('evidence_pack').validate(document)
            prefixes = [('artifacts', 'task_claim_report', 'data')]
        elif relative == carriers.get('dashboard_summary') and bound(document, 'naos.dashboard_summary.v1'):
            _claim_validator('dashboard_summary').validate(document)
            prefixes = [('inputs', 'task_claims', 'data')]
            inner = at(document, ('inputs', 'evidence_pack', 'data'))
            if bound(inner, 'naos.evidence_pack.v1'):
                _claim_validator('evidence_pack').validate(inner)
                prefixes.append(('inputs', 'evidence_pack', 'data', 'artifacts', 'task_claim_report', 'data'))
        report_validator = _claim_validator('task_claim_report')
        claim_schema = _claim_validator('task_claims').schema['$defs']['claim']
        from jsonschema import Draft202012Validator
        record_validator = Draft202012Validator(claim_schema)
        result = set()
        buckets = ('claims', 'active_claims', 'released_claims', 'expired_claims', 'stale_claims',
                   'conflicting_claims', 'unknown_operator_claims', 'missing_session_claims')
        for prefix in prefixes:
            report = at(document, prefix)
            if not bound(report, 'naos.task_claim_report.v1') or report.get('claims_file') != str(root / naos_root / 'task_claims.yaml'):
                continue
            report_validator.validate(report)
            if report['claim_count'] != len(report['claims']):
                raise PublicVocabularyError('claim_report_count')
            admitted = set()
            for bucket in buckets:
                rows = report[bucket]
                if len(rows) > MAX_ENTRIES:
                    raise PublicVocabularyError('claim_count')
                seen = set()
                for index, record in enumerate(rows):
                    record_validator.validate(record)
                    identifier, defining = _public_claim_record(record)
                    if identifier in seen or context['known'].get(identifier) != defining:
                        raise PublicVocabularyError('unbound_claim_reference')
                    seen.add(identifier)
                    coordinate = parser.claim_strings.get((*prefix, bucket, index, 'claim_id'))
                    if coordinate is None or coordinate[2] != identifier:
                        raise PublicVocabularyError('claim_coordinate')
                    admitted.add(coordinate[:2])
            result.update(admitted)
        context['proof'].verify_cached()
        return result
    except (ImportError, OSError, ValueError, TypeError, KeyError, RecursionError):
        return set()
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return set()


def public_family_record_path_spans(text, relative, *, root, naos_root, profile,
                                   selected, policy, context=None):
    """One exact selected-record constructor coordinate, entropy only.

    This proves local path/binding consistency, never human review or producer
    authenticity. All body strings and credential-pattern scans remain active.
    """
    if (not _relative(relative) or not _relative(naos_root)
            or len(selected) > 50_000):
        return set()
    try:
        from jsonschema import Draft202012Validator
        from naos_policy import SAFE_FALLBACK_POLICY, report_default_path, safe_policy_path
        from naos_secret_managed_operands import _OffsetJSON, ProofBudget
        chosen = policy if policy is not None else SAFE_FALLBACK_POLICY
        path = root.joinpath(*relative.split('/'))
        canonical = report_default_path(root, naos_root, chosen, 'systemic_impact_report')
        if path != canonical or path not in selected:
            return set()
        name = chosen.get('paths', {}).get('systemic_impact_family_review_record')
        if type(name) is not str or not _relative(name):
            return set()
        record_path = safe_policy_path(root / naos_root, name,
                                      field='systemic_impact_family_review_record')
        if record_path not in selected:
            return set()
        proof = context if context is not None else ProofBudget(root)
        if proof.root != root.absolute():
            return set()
        raw = proof.read(relative)
        if raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n') != text:
            return set()
        coordinate = ('aggregate_review', 'record_path')
        parser = _OffsetJSON(text, exact_control_coordinates={coordinate})
        document = parser.parse()
        schema_root = Path(__file__).absolute().parents[1]
        schema_path = schema_root / 'schemas/naos/systemic_impact_review.schema.json'
        schema_raw = _bounded_regular_bytes(schema_path, boundary=schema_root,
                                           limit=131_072)
        if hashlib.sha256(schema_raw).hexdigest() != _REFERENCE_SCHEMAS['systemic_impact_review']:
            return set()
        Draft202012Validator(json.loads(schema_raw, object_pairs_hook=_unique_pairs)).validate(document)
        expected_scope = {'project_root': str(root.absolute()),
                          'naos_root': naos_root, 'profile': profile}
        if any(document.get(k) != v for k, v in expected_scope.items()):
            return set()
        record_relative = record_path.absolute().relative_to(root.absolute()).as_posix()
        record = _reference_document(record_path, root=root,
                    schema_name='systemic_impact_family_review',
                    raw=proof.read(record_relative))
        aggregate = document.get('aggregate_review', {})
        if (record.get('scope') != expected_scope
                or aggregate.get('scope') != expected_scope
                or aggregate.get('binding') != record.get('binding')):
            return set()
        policy_path = Path(chosen.get('_meta', {}).get('path') or '')
        policy_relative = policy_path.absolute().relative_to(root.absolute()).as_posix()
        rules_name = chosen.get('paths', {}).get('systemic_impact_rules')
        if type(rules_name) is not str or not _relative(rules_name):
            return set()
        rules_path = safe_policy_path(root / naos_root, rules_name,
                                     field='systemic_impact_rules')
        rules_relative = rules_path.absolute().relative_to(root.absolute()).as_posix()
        effective = json.dumps({k: v for k, v in chosen.items() if k != '_meta'},
                               sort_keys=True, ensure_ascii=False,
                               separators=(',', ':'), allow_nan=False).encode('utf-8')
        expected_binding = {
            'policy_sha256': hashlib.sha256(proof.read(policy_relative)).hexdigest(),
            'rules_sha256': hashlib.sha256(proof.read(rules_relative)).hexdigest(),
            'effective_policy_sha256': hashlib.sha256(effective).hexdigest(),
        }
        if aggregate.get('binding') != expected_binding:
            return set()
        slot = parser.strings.get(coordinate)
        if slot is None or slot[2] != str(record_path):
            return set()
        proof.admission_checkpoint()
        return {(slot[0], slot[1])}
    except (OSError, UnicodeError, ValueError, TypeError, KeyError,
            ImportError, RecursionError):
        return set()
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return set()


def selected_scanner_consumer_paths(*, root, naos_root, policy):
    """Finite consumer roles eligible to reuse their actual selected scan read.

    This grants no literal admission. Each caller retains its source, schema,
    byte-binding and exact-coordinate proof. Ordinary files keep full scanning.
    """
    if type(policy) is not dict or type(policy.get('paths', {})) is not dict:
        return set()
    try:
        from naos_policy import report_default_path, sessions_index_path, evidence_pack_output_path, test_map_output_path
        roles = ('secret_hygiene_report', 'systemic_impact_report',
                 'dashboard_summary_report', 'session_lifecycle_report',
                 'task_context_pack_report', 'test_evidence_report',
                 'pr_risk_classification_report')
        paths = {report_default_path(root, naos_root, policy, role) for role in roles}
        paths.add(sessions_index_path(root, naos_root, policy))
        paths.update(path for path in (evidence_pack_output_path(root, naos_root, policy),
                                      test_map_output_path(root, naos_root, policy)) if path is not None)
        return {path.absolute().relative_to(root.absolute()).as_posix() for path in paths}
    except (OSError, ValueError, TypeError, KeyError):
        return set()


def _selected_metadata_bytes(text, relative, *, root, selected, context):
    """One exact selected input; share the caller's proof and endpoint checks."""
    if (context is None or context.root != root.absolute() or not _relative(relative)
            or len(selected) > 50_000):
        raise PublicVocabularyError('metadata_selection')
    selected_paths = {path.absolute() for path in selected}
    if (root / relative).absolute() not in selected_paths:
        raise PublicVocabularyError('unselected_metadata')
    raw = context.read(relative)
    if re.sub(r'\r\n?', '\n', raw.decode('utf-8')) != text:
        raise PublicVocabularyError('metadata_bytes')
    return raw, selected_paths


def _bounded_external_reference_rows(document, policy):
    """Bound work before invoking the producer's unchanged collector/deduper."""
    from naos_evidence_export import URL_RE, classify_reference, collect_external_references, dedupe_references
    pending = [(document, 0)]
    containers = references = 0
    while pending:
        value, depth = pending.pop()
        if depth > 64:
            raise PublicVocabularyError('reference_depth')
        if type(value) in {dict, list}:
            containers += 1
            if containers > 50_000:
                raise PublicVocabularyError('reference_complexity')
            if type(value) is dict:
                references += int(bool(classify_reference(value, policy)['url']))
                pending.extend((item, depth + 1) for item in value.values())
            else:
                pending.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            references += sum(1 for _ in URL_RE.finditer(value))
        if references > MAX_CONTEXT_VALUES:
            raise PublicVocabularyError('reference_count')
    return dedupe_references(collect_external_references(document, policy))


def public_gate_reference_location_spans(text, relative, *, root, naos_root,
                                        profile, selected, policy, context):
    """Exact collected navigation labels, never URL/body or review authority."""
    if (type(policy) is not dict or type(policy.get('paths', {})) is not dict
            or not _relative(naos_root)):
        return set()
    try:
        from naos_policy import evidence_pack_output_path, report_default_path
        from naos_secret_managed_operands import _OffsetJSON
        from naos_configuration_posture_review import _digest
        destination = evidence_pack_output_path(root, naos_root, policy)
        if destination is None or root / relative != destination:
            return set()
        if len(text.encode('utf-8')) > 1024 * 1024:
            return set()
        observed = _OffsetJSON(text).parse()
        scope = {'project_root': str(root.absolute()), 'naos_root': naos_root, 'profile': profile}
        if (type(observed) is not dict or observed.get('schema') != 'naos.evidence_pack.v2'
                or any(observed.get(key) != value for key, value in scope.items())
                or type(observed.get('artifacts')) is not dict):
            return set()
        raw, selected_paths = _selected_metadata_bytes(text, relative, root=root,
            selected=selected, context=context)
        pack = _reference_document(destination, root=root, schema_name='evidence_pack', raw=raw)
        if (pack.get('schema') != 'naos.evidence_pack.v2'
                or any(pack.get(key) != value for key, value in scope.items())):
            return set()
        groups = [group for group in read_catalog()['groups']
                  if group['source'] == 'scripts/naos_evidence_export.py'
                  and group['selector'] == 'collect_external_references.ai_surface_host_context.finite_locations']
        if len(groups) != 1:
            return set()
        tails = set(groups[0]['values'])
        expected = {}
        proved_reference_rows = set()
        pattern = re.compile(r'\$\.gates\[([0-9]{1,8})\]\.evidence_results\[([0-9]{1,8})\]'
            r'\.configuration_posture_review_subject\.subject\.configuration_posture(\..+)\Z')
        for role in ('gate_evaluation_report', 'gate_status_report'):
            artifact = pack.get('artifacts', {}).get(role)
            if type(artifact) is not dict:
                continue
            ref = artifact.get('source_reference')
            if not _relative(ref):
                continue
            source_path = report_default_path(root, naos_root, policy, role)
            if (source_path is None or root / ref != source_path
                    or source_path.absolute() not in selected_paths
                    or any(artifact.get(key) != value for key, value in (
                        ('schema', 'naos.report_source_reference.v1'),
                        ('composition_kind', 'source_reference'), ('source_schema', 'naos.gate_status.v1'),
                        ('detail_availability', 'source_bound'), ('status', 'present'), ('format', 'json')))):
                continue
            if (type(artifact.get('source_size_bytes')) is not int
                    or not 0 < artifact['source_size_bytes'] <= 8 * 1024 * 1024):
                continue
            source_raw = context.read(ref)
            if (len(source_raw) != artifact['source_size_bytes']
                    or hashlib.sha256(source_raw).hexdigest() != artifact.get('source_sha256')):
                continue
            source = _OffsetJSON(source_raw.decode('utf-8')).parse()
            _claim_validator('gate_status').validate(source)
            if (source.get('schema') != 'naos.gate_status.v1'
                    or any(source.get(key) != value for key, value in scope.items())):
                continue
            rows = _bounded_external_reference_rows(source, policy)
            if json.dumps(rows, sort_keys=True) != json.dumps(artifact.get('external_references'), sort_keys=True):
                continue
            for index, row in enumerate(rows):
                location = row.get('location')
                match = pattern.fullmatch(location) if type(location) is str else None
                if match is None or '$' + match[3] not in tails:
                    continue
                gate_index, evidence_index = int(match[1]), int(match[2])
                gates = source['gates']
                if gate_index >= len(gates) or evidence_index >= len(gates[gate_index]['evidence_results']):
                    continue
                evidence = gates[gate_index]['evidence_results'][evidence_index]
                envelope = evidence.get('configuration_posture_review_subject', {})
                subject = envelope.get('subject', {})
                if (evidence.get('report_key') != 'ai_surface_context_budget'
                        or envelope.get('schema') != 'naos.configuration_posture_review_subject.v1'
                        or envelope.get('report_key') != 'ai_surface_context_budget'
                        or envelope.get('scope') != scope or subject.get('scope') != scope
                        or subject.get('schema') != 'naos.configuration_posture_review.v1.subject'
                        or subject.get('report_key') != 'ai_surface_context_budget'
                        or envelope.get('binding', {}).get('subject_sha256') != _digest(subject)):
                    continue
                coordinate = ('artifacts', role, 'external_references', index, 'location')
                expected[coordinate] = location
                proved_reference_rows.add(json.dumps(row, sort_keys=True))
                if len(expected) > MAX_CONTEXT_VALUES:
                    return set()
        # The pack's summary dedupes whole collected rows from its artifacts.
        # Match a complete proved row; a location string alone is not a witness.
        for index, row in enumerate(pack.get('external_references', [])):
            if json.dumps(row, sort_keys=True) in proved_reference_rows:
                expected[('external_references', index, 'location')] = row['location']
                if len(expected) > MAX_CONTEXT_VALUES:
                    return set()
        parser = _OffsetJSON(text, exact_control_coordinates=set(expected))
        if parser.parse() != pack:
            return set()
        spans = {(start, end) for key, (start, end, value) in parser.strings.items()
                 if key in expected and value == expected[key]}
        context.admission_checkpoint()
        return spans
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, ImportError,
            RecursionError, OverflowError):
        return set()
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return set()


def public_source_test_path_projections(text, relative, *, root, naos_root,
                                        profile, selected, policy, context):
    """Project only an observed root at proved map columns; keep filename entropy."""
    if (type(policy) is not dict or type(policy.get('paths', {})) is not dict
            or type(policy.get('test_evidence', {})) is not dict or not _relative(naos_root)):
        return {}
    try:
        import ast
        from naos_policy import test_map_output_path, should_ignore_path
        from naos_secret_managed_operands import _OffsetJSON
        from naos_test_evidence_map import source_module_index, declared_source_imports, classify_test
        destination = test_map_output_path(root, naos_root, policy)
        if destination is None or root / relative != destination:
            return {}
        document = _OffsetJSON(text).parse()
        if (type(document) is not dict or document.get('schema') != 'naos.test_evidence_map.v1'
                or document.get('profile') != profile or document.get('coverage_inputs') != []
                or document.get('global_coverage_evidence') != []):
            return {}
        for field, folder in (('source_roots', 'src'), ('test_roots', 'tests')):
            values = document.get(field)
            if type(values) is not list or len(values) != 1 or type(values[0]) is not str:
                return {}
            declared_root = Path(values[0])
            if not declared_root.is_absolute():
                declared_root = root / declared_root
            if '..' in declared_root.parts or declared_root.absolute() != (root / folder).absolute():
                return {}
        _, selected_paths = _selected_metadata_bytes(text, relative, root=root,
            selected=selected, context=context)
        selected_sources = sorted(path for path in selected_paths
            if path.is_relative_to(root / 'src') and path.suffix == '.py'
            and path.name != '__init__.py' and not should_ignore_path(path, policy))
        selected_tests = sorted(path for path in selected_paths
            if path.is_relative_to(root / 'tests') and path.suffix == '.py'
            and not should_ignore_path(path, policy))
        if len(selected_sources) + len(selected_tests) > MAX_CONTEXT_VALUES:
            return {}
        mappings = document.get('mappings')
        inputs = document.get('test_inputs')
        if (type(mappings) is not list or len(mappings) != len(selected_sources)
                or type(inputs) is not list or len(inputs) != len(selected_tests)
                or any(type(row) is not dict or type(row.get('source')) is not str for row in mappings)
                or any(type(row) is not dict or type(row.get('path')) is not str for row in inputs)):
            return {}
        # Match selected objects with native path equality, while retaining the
        # producer's spelling for subsequent row checks and filename entropy.
        sources = [Path(row['source']) for row in mappings]
        tests = [Path(row['path']) for row in inputs]
        if (sources != selected_sources or tests != selected_tests
                or any(row['source'] != str(path) for row, path in zip(mappings, sources))
                or inputs != [{'path': str(path), 'status': 'read'} for path in tests]):
            return {}
        for path in sources:
            context.read(path.relative_to(root).as_posix())
        module_index = source_module_index(root, sources, [root / 'src'])
        links = {}
        for path in tests:
            tree = ast.parse(context.read(path.relative_to(root).as_posix()), filename=str(path))
            links[path] = declared_source_imports(path, tree, module_index)
        expected = {('test_inputs', i, 'path'): path for i, path in enumerate(tests)}
        coverage_default = str(policy.get('test_evidence', {}).get('coverage_supports_source_default') or 'unknown')
        for index, (source, row) in enumerate(zip(sources, mappings)):
            matched = [{'path': str(test), 'type': classify_test(test), 'association': 'declared_import'}
                       for test in tests if source in links[test]]
            candidates = [{'path': str(test), 'type': classify_test(test), 'association': 'weak_heuristic'}
                          for test in tests if source not in links[test]
                          and test.stem.lower() in {'test_' + source.stem.lower(), source.stem.lower() + '_test'}]
            produced = {'source': str(source), 'tests': matched, 'candidate_tests': candidates,
                'global_coverage_evidence': [], 'coverage_supports_source': coverage_default,
                'mapped': bool(matched or coverage_default == 'yes'),
                'evidence_types': sorted({item['type'] for item in matched})}
            if json.dumps(row, sort_keys=True) != json.dumps(produced, sort_keys=True):
                return {}
            expected[('mappings', index, 'source')] = source
            for test_index, item in enumerate(matched):
                expected[('mappings', index, 'tests', test_index, 'path')] = Path(item['path'])
        parser = _OffsetJSON(text, exact_control_coordinates=set(expected))
        if parser.parse() != document:
            return {}
        projections = {}
        for key, (start, end, value) in parser.strings.items():
            operand = expected.get(key)
            if operand is not None and value == str(operand):
                ref = operand.relative_to(root).as_posix()
                if _relative(ref):
                    projections[(start, end)] = ref
        context.admission_checkpoint()
        return projections
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, ImportError,
            RecursionError, SyntaxError, OverflowError):
        return {}


def public_operational_path_spans(text, relative, *, root, naos_root, profile,
                                  selected, policy, rules, context, session_context):
    """Source-bound task/test labels, exact metadata quotes only.

    The scanner supplies its existing ProofBudget. Native topology, selected
    coverage and final proof invalidation remain the caller's existing contract.
    This proves label consistency, never source truth or execution/review.
    """
    from naos_secret_managed_operands import _OffsetJSON
    if (context is None or type(policy) is not dict
            or not _relative(relative) or not _relative(naos_root)):
        return set()
    try:
        if context.root != root.absolute():
            return set()
        paths = policy.get('paths', {})
        if type(paths) is not dict:
            return set()
        reports = paths.get('reports_dir', 'reports')
        sessions = paths.get('sessions_root', 'sessions')
        routes = {
            'session_lifecycle': paths.get('session_lifecycle_report', 'session_lifecycle.json'),
            'task_context_pack': paths.get('task_context_pack_report', 'task_context_pack.json'),
            'test_evidence_health': paths.get('test_evidence_report', 'test_evidence_health.json'),
        }
        if not all(_relative(v) for v in (reports, sessions, *routes.values())):
            return set()
        candidates = []
        for schema_name, filename in routes.items():
            latest = '/'.join((naos_root, reports, filename))
            if relative == latest:
                candidates.append((schema_name, latest, None))
            prefix = '/'.join((naos_root, sessions)) + '/'
            if relative.startswith(prefix):
                rest = relative[len(prefix):]
                session, separator, suffix = rest.partition('/')
                if separator and suffix == reports + '/' + filename:
                    candidates.append((schema_name, latest, session))
        if len(candidates) != 1:
            return set()
        schema_name, latest, mirror_session = candidates[0]
        selected_refs = {p.absolute().relative_to(root.absolute()).as_posix() for p in selected}
        if len(selected_refs) > 50_000 or relative not in selected_refs:
            return set()
        raw = context.read(relative)
        if re.sub(r'\r\n?', '\n', raw.decode('utf-8')) != text:
            return set()
        document = _reference_document(root / relative, root=root,
                                       schema_name=schema_name, raw=raw)
        if any(document.get(k) != v for k, v in (
            ('project_root', str(root.absolute())), ('naos_root', naos_root),
            ('profile', profile), ('schema', 'naos.' + schema_name + '.v1'))):
            return set()
        if mirror_session is not None:
            if (schema_name != 'session_lifecycle' or session_context is None
                    or mirror_session not in session_context['sessions']
                    or document.get('session_id') != mirror_session
                    or latest not in selected_refs or context.read(latest) != raw):
                return set()
        # Never turn an arbitrary adopter filename into a new exception.
        # Bind the selected rule bytes and require an already explicit operand.
        from naos_policy import load_operand_yaml
        rules_ref = '/'.join((naos_root, paths.get('secret_hygiene_rules', 'secret_hygiene_rules.yaml')))
        if not _relative(rules_ref) or rules_ref not in selected_refs:
            return set()
        declared = load_operand_yaml(context.read(rules_ref).decode('utf-8'), unique_string_keys=True)
        allowed = rules.get('entropy_allowed_values', [])
        if (type(declared) is not dict or declared.get('entropy_allowed_values', []) != allowed
                or type(allowed) is not list or any(type(value) is not str for value in allowed)):
            return set()
        def permitted(ref):
            operand = root / ref
            return bool({ref, str(operand), operand.as_posix()} & set(allowed))
        coordinates = set()
        expected = set()
        if schema_name in {'session_lifecycle', 'task_context_pack'}:
            from naos_task_lifecycle import task_card_identity
            task_id = document.get('task_id')
            if type(task_id) is not str or not re.fullmatch(r'T-[0-9]{3,}', task_id):
                return set()
            registry_ref = naos_root + '/TASK_REGISTRY.yaml'
            if registry_ref not in selected_refs:
                return set()
            registry = _reference_document(root / registry_ref, root=root,
                schema_name='task_registry', raw=context.read(registry_ref))
            rows = [row for row in registry.get('tasks', []) if row.get('id') == task_id]
            if len(rows) != 1:
                return set()
            matches = []
            for ref in sorted(selected_refs):
                if (ref.startswith(naos_root + '/active/') and ref.endswith('.md')
                        and '/' not in ref[len(naos_root + '/active/'):]
                        and not ref.rsplit('/', 1)[-1].startswith('_')
                        and 'compact' not in (root / ref).stem.lower()):
                    card = context.read(ref)
                    owners, errors = task_card_identity(root / ref, card.decode('utf-8'))
                    if task_id in owners:
                        if errors or owners != {task_id}:
                            return set()
                        matches.append((ref, card))
            if len(matches) != 1:
                return set()
            ref, card = matches[0]
            if not permitted(ref):
                return set()
            operand = root / ref
            resolution = document.get('task_resolution', {})
            if (resolution.get('record_kind') != 'active'
                    or resolution.get('registry_entry') != rows[0]
                    or resolution.get('selected_card_path') != str(operand)
                    or resolution.get('active_card_path') != str(operand)):
                return set()
            expected = {str(operand), operand.as_posix(),
                        str(operand.relative_to(root)), operand.relative_to(root).as_posix()}
            coordinates |= {('task_resolution', 'active_card_path'),
                            ('task_resolution', 'selected_card_path')}
            if schema_name == 'session_lifecycle':
                for field in ('active_task_card', 'task_record'):
                    record = document.get(field, {})
                    if (record.get('digest') != hashlib.sha256(card).hexdigest()
                            or record.get('size_bytes') != len(card)
                            or record.get('record_kind') != 'active'):
                        return set()
                    coordinates.add((field, 'path'))
            else:
                if document.get('task_card', {}).get('fields', {}).get('Task ID') != task_id:
                    return set()
                coordinates.add(('task_card', 'path'))
        else:
            # Conservative default-root case. Custom CLI test roots are not
            # admitted until their selection contract can be independently bound.
            import ast
            from naos_policy import should_ignore_path
            inputs = document.get('test_inputs', [])
            refs = []
            ref_names = {}
            for ref in sorted(selected_refs):
                if (ref.startswith('tests/') and ref.endswith('.py')
                        and not should_ignore_path(root / ref, policy)):
                    ast.parse(context.read(ref))
                    refs.append(str(root / ref))
                    ref_names[str(root / ref)] = ref
            if inputs != [{'path': ref, 'status': 'read'} for ref in sorted(refs)]:
                return set()
            expected = {value for value in refs if permitted(ref_names[value])}
            coordinates |= {('test_inputs', i, 'path') for i in range(len(inputs))}
        parser = _OffsetJSON(text, exact_control_coordinates=coordinates)
        if parser.parse() != document:
            return set()
        spans = {(start, end) for key, (start, end, value) in parser.strings.items()
                 if key in coordinates and value in expected}
        context.admission_checkpoint()
        return spans
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, SyntaxError, ImportError):
        return set()
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return set()
