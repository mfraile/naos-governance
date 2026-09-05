#!/usr/bin/env python3
"""Small JSON Schema subset validator for NAOS local config checks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def load_schema(schema_path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        data = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"schema file could not be read: {schema_path}: {exc}"]
    if not isinstance(data, dict):
        return None, [f"schema file must contain a JSON object: {schema_path}"]
    return data, []


def _format_path(path: list[str | int]) -> str:
    if not path:
        return "$"
    result = "$"
    for part in path:
        if isinstance(part, int):
            result += f"[{part}]"
        else:
            result += f".{part}"
    return result


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _resolve_ref(ref: str, root_schema: dict[str, Any]) -> dict[str, Any] | None:
    if not ref.startswith("#/"):
        return None
    current: Any = root_schema
    for part in ref[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current if isinstance(current, dict) else None


def _validate(value: Any, schema: dict[str, Any], root_schema: dict[str, Any], path: list[str | int]) -> list[str]:
    if "$ref" in schema:
        resolved = _resolve_ref(str(schema["$ref"]), root_schema)
        if resolved is None:
            return [f"{_format_path(path)}: unresolved schema reference {schema['$ref']}"]
        return _validate(value, resolved, root_schema, path)

    errors: list[str] = []

    if "const" in schema and value != schema["const"]:
        errors.append(f"{_format_path(path)}: expected constant {schema['const']!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{_format_path(path)}: value {value!r} is not one of {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None:
        types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_type_matches(value, str(item)) for item in types):
            errors.append(f"{_format_path(path)}: expected type {'/'.join(str(item) for item in types)}")
            return errors

    if isinstance(value, dict):
        required = schema.get("required") or []
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append(f"{_format_path(path + [str(key)])}: required property is missing")

        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                errors.extend(_validate(item, properties[key], root_schema, path + [str(key)]))
            elif additional is False:
                errors.append(f"{_format_path(path + [str(key)])}: additional property is not allowed")
            elif isinstance(additional, dict):
                errors.extend(_validate(item, additional, root_schema, path + [str(key)]))

    if isinstance(value, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(value) < min_items:
            errors.append(f"{_format_path(path)}: expected at least {min_items} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(_validate(item, item_schema, root_schema, path + [index]))

    if isinstance(value, str) and "pattern" in schema:
        pattern = str(schema["pattern"])
        if re.fullmatch(pattern, value) is None:
            errors.append(f"{_format_path(path)}: value {value!r} does not match pattern {pattern!r}")

    minimum = schema.get("minimum")
    if isinstance(minimum, (int, float)) and isinstance(value, (int, float)) and not isinstance(value, bool) and value < minimum:
        errors.append(f"{_format_path(path)}: value {value!r} is below minimum {minimum!r}")

    return errors


def validate_json_schema_file(data: Any, schema_path: Path) -> list[str]:
    schema, errors = load_schema(schema_path)
    if schema is None:
        return errors
    return _validate(data, schema, schema, [])
