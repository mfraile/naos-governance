# ADR-0006: Return Null for Unavailable Behavioral Dimensions

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: Deterministic conformance and behavioral/advisory dimensions

## Context

Some governance questions cannot be measured by the default deterministic kit.
Examples include behavioral quality, model attention, semantic correctness, and
runtime behavior. Filling those fields with optimistic values would make reports
look complete while hiding missing capability.

## Decision

When a behavioral or advisory dimension is not implemented for a project, NAOS
returns `null`, `not_configured`, `readiness_only`, or an equivalent explicit
status rather than inventing a score. Missing measurements must stay visible.

## Consequences

Positive consequences:

- Reports distinguish measured evidence from unavailable evidence.
- Adopters can see which future or project-configured capabilities still need
  design, evidence, and human review.
- Dashboards avoid false precision.

Tradeoffs:

- Some reports may look less complete than users expect.
- Teams must handle missing evidence instead of treating absent data as pass.

## Related Links/Files

- [docs/BEHAVIORAL_AUDIT_ENABLEMENT.md](../BEHAVIORAL_AUDIT_ENABLEMENT.md)
- [docs/CLAIMS_AND_LIMITATIONS.md](../CLAIMS_AND_LIMITATIONS.md)
- [docs/decisions/ADR-0010-control-plane-advisory-boundaries.md](ADR-0010-control-plane-advisory-boundaries.md)
