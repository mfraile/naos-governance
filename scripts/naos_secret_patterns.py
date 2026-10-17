"""Bounded, deterministic credential-pattern checks for local evidence outputs.

This is a selected-pattern filter, not a general secret scanner. It never
examines global configuration, providers, memory stores, or network services.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator


# Finite shared file-selection contract; adopters can replace the scanner roots/suffixes.
SECRET_SCAN_ROOTS = ["src", "app", "apps", "tests", ".github", "services", "packages",
                     "config", "configs", "infra", "infrastructure", "cmd", "lib", "libs"]
SECRET_SCAN_SUFFIXES = [".py", ".yaml", ".yml", ".json", ".jsonl", ".toml", ".env", ".ini", ".cfg",
                        ".conf", ".md", ".txt", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
                        ".java", ".kt", ".kts", ".go", ".cs", ".rb", ".php", ".sh", ".bash",
                        ".ps1", ".tf", ".tfvars", ".hcl", ".properties", ".xml", ".gradle",
                        ".pem", ".key"]


def is_secret_scan_file(path: Path, suffixes: set[str] | None = None) -> bool:
    """Case-insensitive suffix/dotenv matching, plus common extensionless key files."""
    allowed = {item.lower() for item in (SECRET_SCAN_SUFFIXES if suffixes is None else suffixes)}
    name = path.name.lower()
    return (path.suffix.lower() in allowed
            or (".env" in allowed and (name == ".env" or name.startswith(".env.")))
            or (".key" in allowed and name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}))


REDACTED_CREDENTIAL = "[REDACTED:credential_like]"
PLACEHOLDER_SECRET_VALUES = {
    b"[redacted:credential_like]",
    b"changeme",
    b"change-me",
    b"example",
    b"example-token",
    b"example_secret",
    b"sk-example-token",
    b"sk-example-secret",
    b"placeholder",
    b"replace-me",
    b"todo",
    b"your-api-key",
    b"your_token_here",
}
_SECRET_FIELD = (
    rb"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
    rb"(?:secret[_-]?access[_-]?key|secret[_-]?key|password|passwd|pwd|secret|token|"
    rb"api[_-]?key|credential|private[_-]?key)"
)
_SECRET_FIELD_NAME = re.compile(rb"(?i)^" + _SECRET_FIELD + rb"$")
SECRET_CONTENT_PATTERNS = (
    ("aws_access_key_id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), None),
    ("openai_style_key", re.compile(rb"\bsk-[A-Za-z0-9_-]{8,}\b"), None),
    ("slack_style_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"), None),
    ("github_style_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"), None),
    ("bearer_token", re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._-]{12,}\b"), None),
    ("private_key_header", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), None),
    (
        "assigned_secret_quoted",
        re.compile(
            rb'''(?ix)(?<![A-Za-z0-9_])["']?'''
            + _SECRET_FIELD
            + rb'''["']?\s*[:=]\s*(?P<quote>["'])(?P<value>(?:\\[^\r\n]|(?!(?P=quote))[^\\\r\n]){8,})(?P=quote)'''
        ),
        "value",
    ),
    (
        "assigned_secret_unquoted",
        re.compile(
            rb'''(?im)^[ \t]*(?:-[ \t]*)?["']?'''
            + _SECRET_FIELD
            + rb'''["']?[ \t]*[:=][ \t]*(?P<value>[A-Za-z0-9_./+@:-]{8,})[ \t]*(?=[;#,}\]\r\n]|$)'''
        ),
        "value",
    ),
    (
        "assigned_secret_embedded",
        re.compile(
            rb'''(?im)(?<![A-Za-z0-9_])["']?'''
            + _SECRET_FIELD
            + rb'''["']?[ \t]*[:=][ \t]*(?P<value>[A-Za-z0-9_./+@:-]{8,})(?=[; \t#,}\]\r\n"']|$)'''
        ),
        "value",
    ),
)


def iter_secret_content_matches(data: bytes | str) -> Iterator[tuple[str, re.Match[bytes], str | None]]:
    """Yield ephemeral matches with byte offsets; never serialize matched values."""

    content = data.encode("utf-8") if isinstance(data, str) else data
    for pattern_id, pattern, value_group in SECRET_CONTENT_PATTERNS:
        for match in pattern.finditer(content):
            if value_group is not None and match.group(value_group).strip().lower() in PLACEHOLDER_SECRET_VALUES:
                continue
            if pattern_id == "openai_style_key" and match.group(0).lower() in PLACEHOLDER_SECRET_VALUES:
                continue
            yield pattern_id, match, value_group


def secret_content_reason(data: bytes | str) -> str | None:
    """Classify only known provider shapes and secret-named assignments."""
    for pattern_id, _, _ in iter_secret_content_matches(data):
        return pattern_id
    return None


def is_secret_field_name(name: str) -> bool:
    return _SECRET_FIELD_NAME.fullmatch(name.encode("utf-8")) is not None


def redact_sensitive_text(value: str) -> str:
    return REDACTED_CREDENTIAL if secret_content_reason(value) is not None else value


def sanitize_report_value(value: Any) -> Any:
    """Keep evidence shape while removing matched values before serialization."""

    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [sanitize_report_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_report_value(item) for item in value]
    if isinstance(value, dict):
        return {
            redact_sensitive_text(key) if isinstance(key, str) else key: sanitize_report_value(item)
            for key, item in value.items()
        }
    return value
