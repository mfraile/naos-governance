# ADR-0009: Select Apache License 2.0

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: Public kit licensing posture

## Context

NAOS-Governance is intended to be usable by individual developers, teams,
enterprises, and regulated adopters without special procurement friction. The
public kit needs an OSI-approved license with clear redistribution terms and a
patent grant.

## Decision

NAOS-Governance core is published under Apache License 2.0. The core kit remains
Apache License 2.0 after v1.0.0. If commercial products or hosted services are
created in the future, they must live in separate repositories or distribution
packages under their own terms; they do not change the license posture of the
core public kit.

This ADR is architectural project documentation, not legal advice.

## Consequences

Positive consequences:

- Adopters can use the kit under a familiar enterprise-friendly open-source
  license.
- The public redistribution obligations are visible in `LICENSE` and `NOTICE`.
- Commercial services, if any, can be separated from the public kit rather than
  changing the public kit's core license.

Tradeoffs:

- Redistributors must preserve the Apache License 2.0 notices and mark modified
  files as required by the license.
- Normal use inside an adopter's own project is different from redistribution;
  adopters should review `LICENSE` and `NOTICE` for the actual terms.

## Related Links/Files

- [LICENSE](../../LICENSE)
- [NOTICE](../../NOTICE)
- [README.md](../../README.md#license)
