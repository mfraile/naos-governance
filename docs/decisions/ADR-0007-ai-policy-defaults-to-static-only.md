# ADR-0007: AI Policy Defaults to Static-Only

**Status**: Accepted
**Date**: 2026-05-11
**Scope**: AI policy defaults, provider use, and runtime boundaries

## Context

Model-backed review can be useful, but it introduces provider configuration,
data exposure, cost, drift, and repeatability concerns. A governance kit should
not require secrets or model calls merely to initialize or run baseline checks.

## Decision

NAOS defaults to static-only AI policy. The baseline kit calls no model
providers, requires no provider credentials, writes no memory, and does not run
LLMGrader by default. Any provider-backed or model-backed review must be
project-configured, explicit, bounded, and subject to human review.

## Consequences

Positive consequences:

- Baseline governance works without secrets, network model calls, or provider
  procurement.
- CI and local checks are more reproducible.
- Data exposure decisions remain with adopters.

Tradeoffs:

- NAOS default checks cannot answer semantic or behavioral questions that need a
  project-approved evaluator.
- Teams that want model-backed review must configure and govern that separately.

## Related Links/Files

- [docs/BEHAVIORAL_AUDIT_ENABLEMENT.md](../BEHAVIORAL_AUDIT_ENABLEMENT.md)
- [docs/TOOL_NEUTRAL_USAGE.md](../TOOL_NEUTRAL_USAGE.md)
- [schemas/naos/llm_grader_readiness.schema.json](../../schemas/naos/llm_grader_readiness.schema.json)
