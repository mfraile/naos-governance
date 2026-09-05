# ADR-0004: SQLite, sqlite-vec, NetworkX, and GraphML Posture

**Status**: Accepted, future/project-configured
**Date**: 2026-05-11
**Scope**: Structured substrate and graph/semantic candidate posture

## Context

NAOS needs room for better local evidence navigation without turning the public
kit into a server platform. SQLite, vector extensions, in-process graph
libraries, and text graph exports are plausible tools for future or
project-configured substrate work.

## Decision

The public kit preserves a file-first architecture while allowing carefully
bounded structured-substrate work. SQLite is acceptable for generated local
indexes and report metadata when writes are coordinated and outputs are treated
as generated evidence. sqlite-vec, NetworkX, and GraphML remain future or
project-configured capabilities unless explicitly enabled by a separate design.

## Consequences

Positive consequences:

- Generated local indexes can improve review ergonomics without becoming
  source-of-truth artifacts.
- Future graph or semantic candidate work has a bounded architectural direction.
- `ADR-0010: Control-Plane Advisory Boundaries` still governs the boundary:
  advisory candidates may challenge but may not replace deterministic evidence.

Tradeoffs:

- SQLite write coordination is needed when multiple local runs generate the same
  index.
- Semantic/vector and graph outputs can create overtrust if not labeled as
  advisory candidate evidence.

## Related Links/Files

- [docs/decisions/ADR-0010-control-plane-advisory-boundaries.md](ADR-0010-control-plane-advisory-boundaries.md)
- [schemas/naos/sqlite_write_coordination.schema.json](../../schemas/naos/sqlite_write_coordination.schema.json)
- [schemas/naos/semantic_candidate_layer.schema.json](../../schemas/naos/semantic_candidate_layer.schema.json)
- [schemas/naos/graph_context_readiness.schema.json](../../schemas/naos/graph_context_readiness.schema.json)
