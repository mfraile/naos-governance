#!/usr/bin/env sh
set -u

PROFILE="${NAOS_PROFILE:-standard}"
TEAM_ARG=""
if [ "${TEAM_ID:-}" != "" ]; then
  TEAM_ARG="TEAM_ID=${TEAM_ID}"
fi

warn() {
  printf '%s\n' "NAOS Claude hook: $*" >&2
}

if ! command -v make >/dev/null 2>&1 || [ ! -f Makefile.naos ]; then
  warn "Makefile.naos is unavailable; skipped gate-status review."
  exit 0
fi

make -f Makefile.naos naos-gate-status NAOS_PROFILE="$PROFILE" $TEAM_ARG || warn "gate-status returned a review finding."
warn "gate status is review evidence only, not approval or deployment authorization."
exit 0
