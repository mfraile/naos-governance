#!/usr/bin/env sh
set -u

PROFILE="${NAOS_PROFILE:-standard}"
TASK="${NAOS_TASK_ID:-${TASK:-}}"

warn() {
  printf '%s\n' "NAOS Claude hook: $*" >&2
}

if [ "$TASK" = "" ]; then
  warn "NAOS_TASK_ID/TASK not set; skipped session-checkpoint. Record a manual checkpoint if needed."
  exit 0
fi

if ! command -v make >/dev/null 2>&1 || [ ! -f Makefile.naos ]; then
  warn "Makefile.naos is unavailable; record checkpoint for ${TASK} manually."
  exit 0
fi

make -f Makefile.naos naos-session-checkpoint TASK="$TASK" NAOS_PROFILE="$PROFILE" || warn "session-checkpoint returned a review finding."
warn "checkpoint output is review context only; no memory write-back or context injection was performed."
exit 0
