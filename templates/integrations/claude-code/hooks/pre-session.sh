#!/usr/bin/env sh
set -u

PROFILE="${NAOS_PROFILE:-standard}"

warn() {
  printf '%s\n' "NAOS Claude hook: $*" >&2
}

run_make() {
  target="$1"
  if ! command -v make >/dev/null 2>&1; then
    warn "make is unavailable; skipped ${target}."
    return 0
  fi
  if [ ! -f Makefile.naos ]; then
    warn "Makefile.naos not found; skipped ${target}."
    return 0
  fi
  make -f Makefile.naos "$target" NAOS_PROFILE="$PROFILE" || warn "${target} returned a review finding."
}

run_make naos-session-id
run_make naos-operator-attribution
warn "session hooks are convenience checks only; no approval, context injection, or memory write-back was performed."
exit 0
