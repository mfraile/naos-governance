# Public Architecture Decision Records

This directory contains the public-safe architecture decision records for
NAOS-Governance. These ADRs document load-bearing choices in the kit's public
architecture. They are intentionally shorter than maintainer-private research
notes and exclude private planning, customer-specific examples, local paths, and
unpublished release material.

Each ADR follows the same structure:

- **Status**
- **Context**
- **Decision**
- **Consequences**
- **Related links/files**

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [ADR-0001](ADR-0001-default-to-deterministic-workflows.md) | Default to deterministic workflows | Accepted |
| [ADR-0002](ADR-0002-file-first-portable-architecture.md) | File-first portable architecture | Accepted |
| [ADR-0003](ADR-0003-reject-neo4j-for-the-kit.md) | Reject Neo4j infrastructure for the kit | Accepted |
| [ADR-0004](ADR-0004-sqlite-sqlitevec-networkx-graphml-stack.md) | SQLite, sqlite-vec, NetworkX, and GraphML posture | Accepted, future/project-configured |
| [ADR-0005](ADR-0005-never-auto-promote-instincts.md) | Never auto-promote instincts | Accepted |
| [ADR-0006](ADR-0006-conformance-returns-null-for-behavioral-dimensions.md) | Return null for unavailable behavioral dimensions | Accepted |
| [ADR-0007](ADR-0007-ai-policy-defaults-to-static-only.md) | AI policy defaults to static-only | Accepted |
| [ADR-0008](ADR-0008-advisory-capability-enablements-not-release-commitments.md) | Advisory capability enablements are not release commitments | Accepted |
| [ADR-0009](ADR-0009-license-selection-apache-2.md) | Select Apache License 2.0 | Accepted |
| [ADR-0010](ADR-0010-control-plane-advisory-boundaries.md) | Control-plane advisory boundaries | Accepted |
| [ADR-0011](ADR-0011-deterministic-hygiene-controls.md) | Deterministic hygiene controls | Accepted |
| [ADR-0012](ADR-0012-secure-and-agentic-coding-control-register.md) | Secure-coding and agentic-coding control register | Accepted, corrected design baseline |

These records are review evidence for architecture and onboarding decisions.
They are not legal advice, compliance approval, runtime safety proof, or a
substitute for human review.
