# ADR-0001: Default to Deterministic Workflows

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: NAOS workflow architecture and default control posture

## Context

AI-assisted SDLC governance can either rely primarily on model-driven agents or
on deterministic workflows. Agents are useful for ambiguous tasks, but their
behavior changes with context, model, instructions, and tool availability.
Governance evidence needs a repeatable baseline that a reviewer can rerun from
repository files.

## Decision

NAOS defaults to deterministic workflows. Validators, schemas, reports, gates,
Make targets, and CLI commands are the primary governance surface. Agents,
prompts, skills, and optional integrations may help humans operate the workflow,
but they do not replace deterministic checks or human decision boundaries.

## Consequences

Positive consequences:

- Routine governance checks are reproducible from files.
- Evidence packs and dashboards can explain what was checked and what was
  missing.
- Adopters can use NAOS without a specific AI assistant, model provider, or IDE.

Tradeoffs:

- Some tasks remain human-reviewed or require project-specific validators.
- Advisory AI findings may be useful, but they need residual-risk handling
  before they affect durable decisions.

## Related Links/Files

- [docs/CONTROL_PLANE.md](../CONTROL_PLANE.md)
- [docs/CLAIMS_AND_LIMITATIONS.md](../CLAIMS_AND_LIMITATIONS.md)
- [docs/decisions/ADR-0010-control-plane-advisory-boundaries.md](ADR-0010-control-plane-advisory-boundaries.md)
