"""Human console output and Python-child text boundaries; not artifact encoding."""

import sys


def configure_console_output() -> None:
    """Keep the selected encoding, escaping characters it cannot represent."""
    for stream in (sys.stdout, sys.stderr):
        configure = getattr(stream, "reconfigure", None)
        if callable(configure):
            configure(errors="backslashreplace")


def decode_child_output(value: str | bytes | None) -> str:
    """Timeout output can remain bytes even when subprocess text mode is used."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="surrogateescape")
    return value or ""
