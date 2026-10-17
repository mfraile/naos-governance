#!/usr/bin/env sh
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v python3 >/dev/null 2>&1; then
  python3 "$SCRIPT_DIR/dispatch.py" --event pre-compact
elif command -v python >/dev/null 2>&1; then
  python "$SCRIPT_DIR/dispatch.py" --event pre-compact
else
  printf "%s\n" "NAOS Claude hook: Python unavailable; run NAOS review manually." >&2
fi
exit 0
