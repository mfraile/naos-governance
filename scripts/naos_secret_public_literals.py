"""Exact, digest-bound public declarations for entropy-only noise reduction.

No adopter metadata, directory role, prefix, filename existence, UUID shape,
or arbitrary source literal establishes membership in this vocabulary.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import re
import stat
import sys
import uuid
from typing import Any

CATALOG_SCHEMA = "naos.secret_public_literals.v1"
COPIED_RUNTIME_MARKER = b"# AUTO-" + b"GENERATED: Copied by naos init from the NAOS kit."
CATALOG_FILENAME = "naos_secret_public_literals.json"
CATALOG_SHA256 = "93c48765877746091641b9c0aa8eea24f0518659c044f35d08dda07e6139ac4f"
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


def selected_public_audit_literals(files: list[Path], *, root: Path, naos_root: str) -> set[str]:
    """Derive exact full ID/path strings; grant no ordinary scan coverage."""
    result = set()
    from naos_audit_log import event_file_paths
    for identifier, reference in collect_public_audit_event_references(files, root=root, naos_root=naos_root).items():
        selected = Path(reference["event_file"])
        for operand in event_file_paths(selected.parent.parent, reference["event"]):
            for value in (identifier, str(operand), operand.as_posix(), operand.relative_to(root).as_posix()):
                result.update(raw_literal_representations(value))
                if len(result) > MAX_CONTEXT_VALUES:
                    return set()
    return result


# These schema bytes ship with both kit and copied scanner layouts. A replaced
# adopter schema cannot expand the public operand contract.
_REFERENCE_SCHEMAS = {'pr_risk_classification': '4c238cfdff0c214402e8435f24e825bec2ec1b21c8196bcda6270b0aa854ec4b', 'self_check': 'a8c8388efc1ea6897e96b2dccfba513f0389ff0b8fe0adde94dbf3e659364e5a', 'evidence_classification_report': '5cdb1dc62bf40054f41240b43693ee307b35dac427190d3e0f26ac19b2414e47', 'dashboard_summary': 'c703a430008cc25b7257c597a009646a309e6308f64a5c88fd45fb926742ff67', 'evidence_pack': 'd51bb13207f8b566bccffaf43c5b62e36eeb1c7caab698bdde296395aa2304aa', 'task_claim_report': '48a8d7b0f5631f7fb0069da715b9a3062103c808b436d5a75de0abc505e375fe', 'task_claims': '6c8cf8b03cf4d2dd78f11c7cf6cd59a482f6c2a704644131ba5f4f63dca8f68f', 'task_registry': 'c681ebafc2fb53af86f28332363ddab4cdcb97b9be7a236d247d37df3ae5d901', 'local_context_index': '9060ce868c254045b116917a3d4774343a607a4cfb10a1b56a3199ee9daee6f1', 'external_evidence_ingest': 'd96e6c9ebce6d9d1720ba4660cd64bc42f8652d9871b9fdeabde358599e3eefb', 'systemic_impact_family_review': 'afee3bdd6f0dd3cdfacfe64c9335acc71a9034bab50cb6e4d2f7fb7e6a2e3fb5'}
_TASK_PUBLIC_ID = re.compile(r"T-[0-9]{3}\Z")


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
                or item['severity'] not in {'blocking', 'advisory'}
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
    result = set(); total_bytes = 0; candidates = 0
    for path in files:
        try:
            relative = path.absolute().relative_to(root.absolute()).as_posix()
            parts = relative.split('/')
            ordinal = relative in canonical
            audit = (tuple(parts[:len(audit_parts)]) == audit_parts
                     and len(parts) == len(audit_parts)+2 and path.suffix == '.jsonl')
            if not ordinal and not audit:continue
            candidates += 1
            if candidates > MAX_ENTRIES:return set()
            raw = context.read(relative)
            total_bytes += len(raw)
            if total_bytes > 32*1024*1024:return set()
            values = set()
            if ordinal:
                values = _classifier_ordinal_aliases(path, raw, root=root)
            else:
                lines = [line for line in raw.decode('utf-8').splitlines() if line.strip()]
                if len(lines) != 1:continue
                event = json.loads(lines[0], object_pairs_hook=_unique_pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
                if type(event) is not dict:continue
                references = collect_public_audit_event_references([path], root=root, naos_root=naos_root)
                identifier = event.get('event_id')
                if len(references) != 1 or identifier not in references:continue
                reference = references[identifier]
                operand = Path(reference['event_file'])
                if reference['event'] != event or operand.absolute() != path.absolute():continue
                for value in (identifier, str(operand), operand.as_posix(),
                              operand.relative_to(root).as_posix()):
                    values.update(raw_literal_representations(value))
            if context.read(relative) != raw:
                return set()
            result.update(values)
            if len(result) > MAX_CONTEXT_VALUES:return set()
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
                if not _relative(relative):raise PublicVocabularyError('unsafe_claim_carrier')
                carriers[key] = relative
        session_base = sessions_root_path(root, naos_root, selected_policy).relative_to(root).as_posix() + '/'
        return {'known': known, 'proof': proof, 'selected': set(files), 'carriers': carriers, 'session_base': session_base}
    except (ImportError, OSError, ValueError, TypeError, KeyError, RecursionError):
        return None
    except Exception as error:
        if error.__class__.__module__.split('.')[0] not in {'jsonschema', 'yaml'}:
            raise
        return None


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
        from naos_secret_managed_operands import _OffsetJSON, OperandRefusal, ProofBudget
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
                if type(value) is not dict:return None
                value = value.get(key)
            return value
        prefixes = []
        if bound(document, 'naos.task_claim_report.v1'):
            session = document.get('session_id')
            session_path = (session_base + session + '/reports/task_claim_report.json'
                            if type(session) is str and _relative(session) and '/' not in session and ':' not in session
                            and not any(ord(c) < 32 for c in session) else None)
            if relative not in {carriers.get('task_claim_report'), session_path}:return set()
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
            if report['claim_count'] != len(report['claims']):raise PublicVocabularyError('claim_report_count')
            admitted = set()
            for bucket in buckets:
                rows = report[bucket]
                if len(rows) > MAX_ENTRIES:raise PublicVocabularyError('claim_count')
                seen = set()
                for index, record in enumerate(rows):
                    record_validator.validate(record)
                    identifier, defining = _public_claim_record(record)
                    if identifier in seen or context['known'].get(identifier) != defining:
                        raise PublicVocabularyError('unbound_claim_reference')
                    seen.add(identifier)
                    coordinate = parser.claim_strings.get((*prefix, bucket, index, 'claim_id'))
                    if coordinate is None or coordinate[2] != identifier:raise PublicVocabularyError('claim_coordinate')
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
