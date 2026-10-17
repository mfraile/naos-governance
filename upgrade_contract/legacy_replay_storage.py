"""Versioned factored storage for large path-free replay transcripts.

Only transport changes: reconstructed bytes enter the existing full codec.
Raw byte leaves avoid base64 read inflation; metadata uses canonical fixed-size
content-addressed chunks. No original locations or replay budgets are relaxed.
"""

from __future__ import annotations

import base64
import hashlib

from . import legacy_migration_records as migration
from . import portable_provenance as pp
from .canonical import canonical_bytes

SCHEMA = "naos.upgrade.factored_legacy_replay.v1"
CHUNK_BYTES = pp.MAX_RECORD_BYTES
MAX_TRANSCRIPT_BYTES = migration.MAX_ARCHIVE_BYTES * 2
MAX_CHUNKS = (MAX_TRANSCRIPT_BYTES + CHUNK_BYTES - 1) // CHUNK_BYTES
_BODY_KEYS = {
    "schema",
    "source_format",
    "raw_lineage_commitment_sha256",
    "derived_lineage",
    "directory_paths",
    "members",
}
_CODEC_SCHEMAS = {
    migration.POSIX_MANAGED_V1: "naos.upgrade.derived_posix_replay.v1",
    migration.WINDOWS_CONTENT_V1: "naos.upgrade.derived_windows_replay.v1",
}


def _size(value, maximum, label, *, minimum=0):
    # Length before int conversion also bounds adversarial decimal work.
    if (
        type(value) is not str
        or not 1 <= len(value) <= len(str(maximum))
        or not value.isascii()
        or not value.isdigit()
        or str(int(value)) != value
        or not minimum <= int(value) <= maximum
    ):
        pp._fail("Invalid " + label + " size")
    return int(value)


ENCODING_SCHEMA = "naos.upgrade.dictionary_replay_storage.v1"
_MAGIC = b"NAOS-REPLAY-DICT1\n"
_SCALAR_BATCH_BYTES = 64 * 1024
_SCALAR_BATCH_COUNT = 256


def _u32(value):
    return value.to_bytes(4, "big")


def _pack_metadata(metadata):
    """Fixed binary grammar; canonical strings/numbers use existing RFC 8785."""
    body = pp._load_json(metadata, "factored transcript")
    if canonical_bytes(body) != metadata:
        pp._fail("Noncanonical expanded metadata input")
    strings = set()

    def gather(value):
        if type(value) is str:
            strings.add(value)
        elif type(value) is dict:
            for key, item in value.items():
                strings.add(key)
                gather(item)
        elif type(value) is list:
            for item in value:
                gather(item)

    gather(body)
    table = sorted(strings, key=lambda value: value.encode("utf-16be"))
    indices = {value: index for index, value in enumerate(table)}
    literals = [canonical_bytes(value) for value in table]
    encoded = bytearray(_MAGIC + _u32(len(table)))
    for literal in literals:
        encoded.extend(_u32(len(literal)))
        encoded.extend(literal)

    def node(value):
        if type(value) is dict:
            encoded.extend(b"o" + _u32(len(value)))
            for key in sorted(value, key=lambda text: indices[text]):
                encoded.extend(_u32(indices[key]))
                node(value[key])
        elif type(value) is list:
            encoded.extend(b"a" + _u32(len(value)))
            for item in value:
                node(item)
        elif type(value) is str:
            encoded.extend(b"s" + _u32(indices[value]))
        elif value is None:
            encoded.extend(b"n")
        elif type(value) is bool:
            encoded.extend(b"t" if value else b"f")
        elif type(value) in (int, float):
            literal = canonical_bytes(value)
            encoded.extend(b"d" + _u32(len(literal)))
            encoded.extend(literal)
        else:
            pp._fail("Unsupported dictionary primitive")

    node(body)
    if len(encoded) > MAX_TRANSCRIPT_BYTES:
        pp._fail("Encoded transcript byte budget exceeded")
    return bytes(encoded)


def _expand_metadata(encoded, *, expanded_size, expanded_sha256):
    """Validate the complete grammar and expanded work before allocation."""
    if type(encoded) is not bytes or not encoded.startswith(_MAGIC):
        pp._fail("Dictionary transcript magic differs")
    cursor = len(_MAGIC)

    def integer():
        nonlocal cursor
        if cursor + 4 > len(encoded):
            pp._fail("Truncated dictionary integer")
        value = int.from_bytes(encoded[cursor : cursor + 4], "big")
        cursor += 4
        return value

    def take(amount):
        nonlocal cursor
        if amount > expanded_size or amount > len(encoded) - cursor:
            pp._fail("Dictionary literal byte budget differs")
        value = encoded[cursor : cursor + amount]
        cursor += amount
        return value

    # A canonical array is the comma-joined canonical spelling of its scalars.
    # Bound retained parsed values; never cache dependency authority between
    # canonical_bytes calls. Large single literals keep individual validation.
    scalar_values = []
    scalar_literals = []
    scalar_bytes = 0

    def flush_scalars():
        nonlocal scalar_bytes
        if scalar_values:
            expected = b"[" + b",".join(scalar_literals) + b"]"
            if canonical_bytes(scalar_values) != expected:
                kind = "string" if type(scalar_values[0]) is str else "number"
                pp._fail("Noncanonical dictionary " + kind)
            scalar_values.clear()
            scalar_literals.clear()
            scalar_bytes = 0

    def scalar(value, literal):
        nonlocal scalar_bytes
        if (
            len(scalar_values) == _SCALAR_BATCH_COUNT
            or scalar_bytes + len(literal) > _SCALAR_BATCH_BYTES
        ):
            flush_scalars()
        if len(literal) > _SCALAR_BATCH_BYTES:
            if canonical_bytes(value) != literal:
                kind = "string" if type(value) is str else "number"
                pp._fail("Noncanonical dictionary " + kind)
        else:
            scalar_values.append(value)
            scalar_literals.append(literal)
            scalar_bytes += len(literal)

    count = integer()
    if count > pp.MAX_JSON_STRUCTURAL_TOKENS + 1:
        pp._fail("Dictionary string-table work budget exceeded")
    literals = []
    literal_total = 0
    previous = None
    for _ in range(count):
        amount = integer()
        literal_total += amount
        if literal_total > expanded_size:
            pp._fail("Dictionary string-table byte budget exceeded")
        literal = take(amount)
        value = pp._load_json(literal, "dictionary string")
        if type(value) is not str:
            pp._fail("Noncanonical dictionary string")
        scalar(value, literal)
        try:
            ordering = value.encode("utf-16be")
        except UnicodeEncodeError:
            # Preserve the maintained backend's invalid-Unicode refusal.
            flush_scalars()
            raise
        if previous is not None and ordering <= previous:
            pp._fail("Duplicate or unordered dictionary string")
        previous = ordering
        literals.append(literal)
    flush_scalars()
    tree_start = cursor
    used = set()
    tokens = nodes = 0

    def reference():
        index = integer()
        if index >= count:
            pp._fail("Dictionary reference index differs")
        used.add(index)
        return index

    def check(depth):
        nonlocal cursor, tokens, nodes
        nodes += 1
        if nodes > 2 * pp.MAX_JSON_STRUCTURAL_TOKENS + 1:
            pp._fail("Dictionary tree work budget exceeded")
        if cursor == len(encoded):
            pp._fail("Truncated dictionary tree")
        tag = encoded[cursor : cursor + 1]
        cursor += 1
        if tag in (b"o", b"a"):
            depth += 1
            amount = integer()
            tokens += (
                (2 * amount if amount else 1)
                if tag == b"o"
                else (amount if amount else 1)
            )
            if depth > pp.MAX_JSON_DEPTH or tokens > pp.MAX_JSON_STRUCTURAL_TOKENS:
                pp._fail("Expanded transcript exceeds JSON structural limits")
            total = 2 + max(0, amount - 1)
            last_key = -1
            for _ in range(amount):
                if tag == b"o":
                    key = reference()
                    if key <= last_key:
                        pp._fail("Duplicate or unordered dictionary object key")
                    last_key = key
                    total += len(literals[key]) + 1
                total += check(depth)
                if total > expanded_size:
                    pp._fail("Expanded transcript byte budget exceeded")
        elif tag == b"s":
            total = len(literals[reference()])
        elif tag in (b"n", b"t", b"f"):
            total = 5 if tag == b"f" else 4
        elif tag == b"d":
            literal = take(integer())
            value = pp._load_json(literal, "dictionary number")
            if type(value) not in (int, float):
                pp._fail("Noncanonical dictionary number")
            scalar(value, literal)
            total = len(literal)
        else:
            pp._fail("Unknown dictionary tree tag")
        if total > expanded_size:
            pp._fail("Expanded transcript byte budget exceeded")
        return total

    total = check(0)
    if cursor != len(encoded) or total != expanded_size or len(used) != count:
        pp._fail("Dictionary tree trailing bytes, size or unused strings differ")
    flush_scalars()
    # The first pass proved exact size, original depth/work, every reference,
    # primitive spelling and key uniqueness/order. Only now allocate output.
    cursor = tree_start
    output = bytearray(expanded_size)
    offset = 0

    def emit(raw):
        nonlocal offset
        output[offset : offset + len(raw)] = raw
        offset += len(raw)

    def render():
        nonlocal cursor
        tag = encoded[cursor : cursor + 1]
        cursor += 1
        if tag in (b"o", b"a"):
            amount = integer()
            emit(b"{" if tag == b"o" else b"[")
            for index in range(amount):
                if index:
                    emit(b",")
                if tag == b"o":
                    emit(literals[integer()])
                    emit(b":")
                render()
            emit(b"}" if tag == b"o" else b"]")
        elif tag == b"s":
            emit(literals[integer()])
        elif tag == b"d":
            emit(take(integer()))
        else:
            emit({b"n": b"null", b"t": b"true", b"f": b"false"}[tag])

    render()
    metadata = bytes(output)
    if (
        offset != expanded_size
        or hashlib.sha256(metadata).hexdigest() != expanded_sha256
    ):
        pp._fail("Expanded transcript commitment differs")
    return metadata


def pack(raw):
    """Factor already codec-validated bytes without changing the small codec."""
    if type(raw) is not bytes or len(raw) > MAX_TRANSCRIPT_BYTES:
        pp._fail("Derived transcript storage budget exceeded")
    body = pp._load_json(raw, "derived transcript")
    if (
        type(body) is not dict
        or set(body) != _BODY_KEYS
        or body.get("schema") != _CODEC_SCHEMAS.get(body.get("source_format"))
    ):
        pp._fail("Unsupported derived transcript storage schema")
    blobs = {}
    for member in body["members"]:
        payload = member["payload"]
        if payload.get("kind") != "bytes":
            continue
        materialized = base64.b64decode(payload["base64"], validate=True)
        digest = hashlib.sha256(materialized).hexdigest()
        if (
            digest != member["derived_materialized_sha256"]
            or str(len(materialized)) != member["derived_materialized_size_decimal"]
        ):
            pp._fail("Derived byte storage commitment differs")
        blobs[digest] = materialized
        member["payload"] = {
            "kind": "blob",
            "sha256": digest,
            "size_decimal": str(len(materialized)),
        }
    body["schema"] = SCHEMA
    metadata = canonical_bytes(body)
    if len(metadata) > MAX_TRANSCRIPT_BYTES:
        pp._fail("Factored transcript storage budget exceeded")
    encoded = _pack_metadata(metadata)
    encoding = {
        "schema": ENCODING_SCHEMA,
        "encoded_sha256": hashlib.sha256(encoded).hexdigest(),
        "encoded_size_decimal": str(len(encoded)),
    }
    chunks = []
    for index, start in enumerate(range(0, len(encoded), CHUNK_BYTES)):
        chunk = encoded[start : start + CHUNK_BYTES]
        digest = hashlib.sha256(chunk).hexdigest()
        blobs[digest] = chunk
        chunks.append(
            {
                "index_decimal": str(index),
                "sha256": digest,
                "size_decimal": str(len(chunk)),
            }
        )
    return metadata, chunks, blobs, encoding


def load(read, auth, blob_path):
    """Check the complete chunk index and all leaves before full codec replay."""
    size = _size(
        auth["transcript_size_decimal"], MAX_TRANSCRIPT_BYTES, "transcript", minimum=1
    )
    encoding = auth["transcript_encoding"]
    if (
        type(encoding) is not dict
        or set(encoding) != {"schema", "encoded_sha256", "encoded_size_decimal"}
        or encoding["schema"] != ENCODING_SCHEMA
    ):
        pp._fail("Transcript encoding schema or shape differs")
    migration._digest(encoding["encoded_sha256"], "encoded transcript")
    encoded_size = _size(
        encoding["encoded_size_decimal"],
        MAX_TRANSCRIPT_BYTES,
        "encoded transcript",
        minimum=1,
    )
    chunks = auth["transcript_chunks"]
    count = (encoded_size + CHUNK_BYTES - 1) // CHUNK_BYTES
    if (
        type(chunks) is not list
        or not 1 <= len(chunks) <= MAX_CHUNKS
        or len(chunks) != count
    ):
        pp._fail("Factored transcript chunk count differs")
    # Validate all declarations before any chunk read or allocation.
    for index, item in enumerate(chunks):
        if type(item) is not dict or set(item) != {
            "index_decimal",
            "sha256",
            "size_decimal",
        }:
            pp._fail("Factored transcript chunk index shape differs")
        if item["index_decimal"] != str(index):
            pp._fail("Factored transcript chunk order differs")
        migration._digest(item["sha256"], "transcript chunk")
        amount = _size(item["size_decimal"], CHUNK_BYTES, "chunk", minimum=1)
        if amount != min(CHUNK_BYTES, encoded_size - index * CHUNK_BYTES):
            pp._fail("Factored transcript chunk size or total differs")
    parts = []
    for item in chunks:
        raw = read(
            blob_path(item["sha256"]),
            maximum=CHUNK_BYTES,
            declared_size=int(item["size_decimal"]),
        )
        if (
            type(raw) is not bytes
            or len(raw) != int(item["size_decimal"])
            or hashlib.sha256(raw).hexdigest() != item["sha256"]
        ):
            pp._fail("Factored transcript chunk bytes differ")
        parts.append(raw)
    encoded = b"".join(parts)
    if (
        len(encoded) != encoded_size
        or hashlib.sha256(encoded).hexdigest() != encoding["encoded_sha256"]
    ):
        pp._fail("Encoded transcript total commitment differs")
    metadata = _expand_metadata(
        encoded, expanded_size=size, expanded_sha256=auth["transcript_sha256"]
    )
    body = pp._load_json(metadata, "factored transcript")
    if (
        type(body) is not dict
        or set(body) != _BODY_KEYS
        or body.get("schema") != SCHEMA
        or body.get("source_format") not in _CODEC_SCHEMAS
        or canonical_bytes(body) != metadata
    ):
        pp._fail("Factored transcript schema or canonical bytes differ")
    members = body["members"]
    if (
        type(members) is not list
        or not 1 <= len(members) <= migration.MAX_ARCHIVE_FILES
    ):
        pp._fail("Factored transcript inventory budget differs")
    wanted = {}
    materialized_total = 0
    reconstructed_size = (
        len(metadata) + len(_CODEC_SCHEMAS[body["source_format"]]) - len(SCHEMA)
    )
    empty_byte_payload_size = len(canonical_bytes({"kind": "bytes", "base64": ""}))
    paths = []
    for item in members:
        if type(item) is not dict or set(item) != {
            "path",
            "derived_materialized_sha256",
            "derived_materialized_size_decimal",
            "payload",
        }:
            pp._fail("Factored member shape differs")
        migration._path(item["path"], body["source_format"])
        paths.append(item["path"])
        migration._digest(item["derived_materialized_sha256"], "derived member")
        amount = _size(
            item["derived_materialized_size_decimal"],
            migration.MAX_ARCHIVE_FILE_BYTES,
            "derived member",
        )
        materialized_total += amount
        if materialized_total > migration.MAX_ARCHIVE_BYTES:
            pp._fail("Factored archive byte budget exceeded")
        payload = item["payload"]
        if type(payload) is not dict:
            pp._fail("Factored payload shape differs")
        if payload.get("kind") == "blob":
            if set(payload) != {"kind", "sha256", "size_decimal"}:
                pp._fail("Factored byte reference shape differs")
            migration._digest(payload["sha256"], "factored byte leaf")
            if (
                payload["sha256"] != item["derived_materialized_sha256"]
                or payload["size_decimal"] != item["derived_materialized_size_decimal"]
            ):
                pp._fail("Factored byte reference commitment differs")
            if payload["sha256"] in wanted and wanted[payload["sha256"]] != amount:
                pp._fail("Factored byte reference size differs")
            wanted[payload["sha256"]] = amount
            reconstructed_size += (
                empty_byte_payload_size
                + 4 * ((amount + 2) // 3)
                - len(canonical_bytes(payload))
            )
        elif payload.get("kind") != "record":
            pp._fail("Unsupported factored payload")
    if paths != sorted(set(paths)):
        pp._fail("Factored inventory order or duplicate differs")
    if reconstructed_size > MAX_TRANSCRIPT_BYTES:
        pp._fail("Reconstructed transcript byte budget exceeded")
    blobs = {}
    for digest, amount in wanted.items():
        raw = read(
            blob_path(digest),
            maximum=migration.MAX_ARCHIVE_FILE_BYTES,
            declared_size=amount,
        )
        if (
            type(raw) is not bytes
            or len(raw) != amount
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            pp._fail("Factored byte leaf bytes differ")
        blobs[digest] = raw
    for item in members:
        payload = item["payload"]
        if payload["kind"] == "blob":
            item["payload"] = {
                "kind": "bytes",
                "base64": base64.b64encode(blobs[payload["sha256"]]).decode("ascii"),
            }
    body["schema"] = _CODEC_SCHEMAS[body["source_format"]]
    raw = canonical_bytes(body)
    if len(raw) != reconstructed_size or len(raw) > MAX_TRANSCRIPT_BYTES:
        pp._fail("Reconstructed transcript byte budget exceeded")
    return raw
