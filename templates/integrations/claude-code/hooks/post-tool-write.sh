#!/usr/bin/env sh
set -u

PROFILE="${NAOS_PROFILE:-standard}"

warn() {
  printf '%s\n' "NAOS Claude hook: $*" >&2
}

if ! command -v make >/dev/null 2>&1 || [ ! -f Makefile.naos ]; then
  warn "Makefile.naos is unavailable; run NAOS self-check manually when practical."
  exit 0
fi

make -f Makefile.naos naos-self-check NAOS_PROFILE="$PROFILE" || warn "self-check returned a review finding."
warn "self-check does not approve work, certify compliance, or replace human review."
exit 0
