# ADR-0005: Never Auto-Promote Instincts

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: Rule and instinct lifecycle

## Context

NAOS can record observed patterns before they become durable governance rules.
Observed patterns are useful, but they can be noisy, local, stale, or
misinterpreted. Automatically promoting observations into rules would create
governance drift and could turn weak evidence into authority.

## Decision

NAOS must not auto-promote instincts, observations, or advisory findings into
durable rules. Promotion requires explicit evidence, review, and human
decision. Advisory findings may recommend review; they may not rewrite durable
governance state by themselves.

## Consequences

Positive consequences:

- Rule changes remain deliberate and reviewable.
- False positives and local patterns are less likely to become global rules.
- The kit preserves the `ADR-0010: Control-Plane Advisory Boundaries` boundary
  between advisory signals and durable decisions.

Tradeoffs:

- Useful patterns may take longer to become reusable rules.
- Maintainers and adopters must maintain evidence and review discipline.

## Related Links/Files

- [templates/instincts/schema.yaml](../../templates/instincts/schema.yaml)
- [templates/skills/instinct-observer/SKILL.md](../../templates/skills/instinct-observer/SKILL.md)
- [docs/decisions/ADR-0010-control-plane-advisory-boundaries.md](ADR-0010-control-plane-advisory-boundaries.md)
