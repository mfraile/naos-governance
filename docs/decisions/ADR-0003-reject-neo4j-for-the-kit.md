# ADR-0003: Reject Neo4j Infrastructure for the Kit

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: Graph and infrastructure posture for the public kit

## Context

Graph databases can be valuable for some SDLC and evidence-navigation tasks.
However, requiring a graph server would add operational burden, credentials,
backups, service availability, and onboarding complexity to a kit that is meant
to be portable and file-first.

## Decision

NAOS does not require Neo4j infrastructure. The public kit may include guidance
for projects that already use graph databases, but NAOS core must not depend on
a graph server.

## Consequences

Positive consequences:

- The kit remains easy to clone, install, initialize, and run locally.
- Adopters do not inherit graph-server administration as a condition of using
  governance checks.
- Graph-related outputs can stay explicit, bounded, and reviewable.

Tradeoffs:

- Projects with large graph-query needs may need their own project-specific
  graph design.
- NAOS graph-context outputs remain candidate relationship evidence unless a
  future project explicitly implements and validates a stronger design.

## Related Links/Files

- [docs/TOOL_NEUTRAL_USAGE.md](../TOOL_NEUTRAL_USAGE.md)
- [docs/NAOS_THREAT_MODEL.md](../NAOS_THREAT_MODEL.md)
- [docs/decisions/ADR-0002-file-first-portable-architecture.md](ADR-0002-file-first-portable-architecture.md)
