"""RFC 8785 canonical JSON and strict JSON input handling.

The serializer is deliberately delegated to the selected maintained
``rfc8785`` package.  This module only supplies input validation and the
content-digest boundary shared by plans, manifests, receipts, and provenance.
"""

from __future__ import annotations

import hashlib
import json
import math
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Iterable


class CanonicalizationError(ValueError):
    """Raised when a value cannot enter the canonical control boundary."""


class DuplicateKeyError(CanonicalizationError):
    """Raised when a raw JSON object contains the same member name twice."""


class CanonicalizationUnavailable(RuntimeError):
    """Raised when the exact selected RFC 8785 implementation is unavailable."""


def _reject_duplicate_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"Duplicate JSON member name: {key!r}")
        value[key] = item
    return value


def _reject_nonfinite_constant(value: str) -> None:
    raise CanonicalizationError(f"Non-finite JSON number is not permitted: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CanonicalizationError(f"JSON number is outside the finite binary64 range: {value}")
    return parsed


def loads_strict_json(data: str | bytes | bytearray) -> Any:
    """Parse UTF-8 JSON while refusing duplicate keys and non-finite numbers."""

    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalizationError("Control JSON must be valid UTF-8.") from exc
    else:
        text = data
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_constant,
            parse_float=_parse_finite_float,
        )
    except DuplicateKeyError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, CanonicalizationError):
            raise
        raise CanonicalizationError(f"Invalid control JSON: {exc}") from exc


def load_strict_json(path: Path) -> Any:
    """Read and strictly parse one JSON file."""

    return loads_strict_json(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785/JCS bytes using the exact maintained dependency."""

    try:
        import rfc8785
    except ImportError as exc:
        raise CanonicalizationUnavailable(
            "RFC 8785 support is unavailable; install the declared rfc8785==0.1.4 dependency."
        ) from exc
    try:
        distribution = importlib_metadata.distribution("rfc8785")
    except importlib_metadata.PackageNotFoundError as exc:
        raise CanonicalizationUnavailable(
            "RFC 8785 support is unavailable; install the declared rfc8785==0.1.4 dependency."
        ) from exc
    if distribution.version != "0.1.4":
        raise CanonicalizationUnavailable(
            "RFC 8785 support requires the exact declared rfc8785==0.1.4 dependency."
        )
    module_file = getattr(rfc8785, "__file__", None)
    distribution_files = distribution.files
    if not isinstance(module_file, str) or distribution_files is None:
        raise CanonicalizationUnavailable(
            "RFC 8785 support could not bind the imported module to rfc8785==0.1.4."
        )
    try:
        expected_module_files = {
            Path(distribution.locate_file(path)).resolve(strict=True)
            for path in distribution_files
            if path.parts and path.parts[0] == "rfc8785" and path.suffix == ".py"
        }
        imported_module_file = Path(module_file).resolve(strict=True)
    except OSError as exc:
        raise CanonicalizationUnavailable(
            "RFC 8785 support could not bind the imported module to rfc8785==0.1.4."
        ) from exc
    if imported_module_file not in expected_module_files:
        raise CanonicalizationUnavailable(
            "RFC 8785 support refused an imported module outside the rfc8785==0.1.4 distribution."
        )
    try:
        return bytes(rfc8785.dumps(value))
    except Exception as exc:
        raise CanonicalizationError(f"Value is not valid RFC 8785 input: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """Return the lowercase SHA-256 digest of RFC 8785 canonical bytes."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def canonical_sha3_512(value: Any) -> str:
    """Return the lowercase SHA3-512 digest of RFC 8785 canonical bytes."""

    return hashlib.sha3_512(canonical_bytes(value)).hexdigest()
