"""Emit canonical UTF-8 plan bytes independently of console text encoding."""
from __future__ import annotations

import sys


def emit_canonical_plan(raw: bytes) -> None:
    """Write the unmodified UTF-8 artifact plus one LF to the selected stdout.

    Real binary stdout bypasses locale recoding. Text-only captures such as
    StringIO retain the exact decoded Unicode text. This does not reconfigure
    global streams or change human diagnostics or saved artifact bytes.
    """
    if not isinstance(raw, bytes):
        raise TypeError("Canonical plan bytes required")
    text = raw.decode("utf-8")  # Fail before output if supplied bytes are invalid.
    stream = sys.stdout
    binary = getattr(stream, "buffer", None)
    if binary is None:
        stream.write(text + "\n")
        return
    stream.flush()  # Keep any pending text before this binary artifact.
    remaining = memoryview(raw + b"\n")
    while remaining:
        written = binary.write(remaining)
        if not isinstance(written, int) or not 0 < written <= len(remaining):
            raise OSError("Canonical plan stdout made no valid write progress")
        remaining = remaining[written:]
    binary.flush()
