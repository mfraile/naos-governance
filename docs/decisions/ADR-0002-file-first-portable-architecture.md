# ADR-0002: File-First Portable Architecture

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: NAOS public kit architecture and adopter portability

## Context

NAOS must work in ordinary repositories without requiring a hosted service,
database server, AI assistant, MCP server, or SaaS product. Adopters need to
inspect and version the governance artifacts that affect their projects.

## Decision

NAOS is file-first and portable. The core kit operates through Markdown, YAML,
JSON, JSON Schema, shell/Make wrappers, and Python scripts that read and write
repository-local files. Generated reports remain review evidence and can be
deleted and regenerated.

## Consequences

Positive consequences:

- Adopters can review changes in normal code review.
- The kit works in local, CI, cloud IDE, and air-gapped-ish workflows where
  Python and a filesystem are available.
- Optional integrations can call NAOS without NAOS depending on those tools.

Tradeoffs:

- File-first artifacts require explicit coordination when multiple operators
  work in the same repository.
- Advanced graph, semantic, signing, or runtime capabilities must remain
  opt-in and separately governed.

## Related Links/Files

- [docs/TOOL_NEUTRAL_USAGE.md](../TOOL_NEUTRAL_USAGE.md)
- [templates/Makefile.naos](../../templates/Makefile.naos)
- [docs/decisions/ADR-0010-control-plane-advisory-boundaries.md](ADR-0010-control-plane-advisory-boundaries.md)
