# ADR-0008: Advisory Capability Enablements Are Not Release Commitments

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: Readiness-only, advisory, and project-configured capability framing

## Context

The kit can ship schemas, prompts, reports, readiness checks, and documentation
for capabilities that still require adopter configuration or future design.
Users need to know the difference between an enabled public artifact and an
operational runtime capability.

## Decision

NAOS distinguishes kit-side enablement from adopter-side activation. A schema,
readiness report, setup recommendation, or documentation page may make a
capability visible without making it operational, authoritative, or complete.
Reports must state when a capability is readiness-only, advisory, disabled, or
project-configured.

## Consequences

Positive consequences:

- Adopters get a roadmap for maturation without being told a capability is
  active when it is not.
- Optional modules can be installed later without changing the core dependency
  direction.
- Readiness reports can identify gaps without claiming completion.

Tradeoffs:

- The public kit has more status language to read.
- Adopters must decide when to activate optional or project-configured behavior.

## Related Links/Files

- [docs/ADOPTION_GUIDE.md](../ADOPTION_GUIDE.md)
- [docs/ASSURED_PROFILE_ACTIVATION.md](../ASSURED_PROFILE_ACTIVATION.md)
- [docs/BEHAVIORAL_AUDIT_ENABLEMENT.md](../BEHAVIORAL_AUDIT_ENABLEMENT.md)
