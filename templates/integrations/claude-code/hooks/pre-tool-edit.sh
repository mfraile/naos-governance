#!/usr/bin/env sh
set -u

PROFILE="${NAOS_PROFILE:-standard}"

warn() {
  printf '%s\n' "NAOS Claude hook: $*" >&2
}

if ! command -v make >/dev/null 2>&1 || [ ! -f Makefile.naos ]; then
  warn "Makefile.naos is unavailable; review task claims manually before editing."
  exit 0
fi

make -f Makefile.naos naos-task-claims NAOS_PROFILE="$PROFILE" || warn "task-claims returned a review finding."
warn "task claims are coordination metadata only, not authorization, ownership proof, or approval."
exit 0
