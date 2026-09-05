#!/usr/bin/env sh
set -u

PROFILE="${NAOS_PROFILE:-standard}"
TASK="${NAOS_TASK_ID:-${TASK:-}}"

warn() {
  printf '%s\n' "NAOS Claude hook: $*" >&2
}

if [ "$TASK" = "" ]; then
  warn "NAOS_TASK_ID/TASK not set; skipped session-end. Review git status and NAOS reports manually."
  exit 0
fi

if ! command -v make >/dev/null 2>&1 || [ ! -f Makefile.naos ]; then
  warn "Makefile.naos is unavailable; run session-end for ${TASK} manually when practical."
  exit 0
fi

make -f Makefile.naos naos-session-end TASK="$TASK" NAOS_PROFILE="$PROFILE" || warn "session-end returned a review finding."
warn "stop hook does not push, release, deploy, approve, or write memory."
exit 0
