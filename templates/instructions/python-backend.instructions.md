---
applyTo: "src/**/*.py"
---

# Python Backend Guidelines

> Consult `.github/project-context.md` for project-specific conventions (schemas, modules, constraints).

## Module Header (Required)

```python
"""
Module: src/path/to/module.py

Purpose:
    Short module-level description.

Implements:
    - FR-XXX: Requirement/control name
    - NFR-XXX: Non-functional requirement/control name

Tasks:
    - T-XXX: Task title
    - T-YYY: Task title

Specs:
    - specs/03-requirements.md#fr-xxx
    - specs/04-architecture.md#architecture-section

Rationale:
    Short paragraph explaining why this module exists, why the logic belongs
    here, what boundary it owns, and how it avoids duplication or architecture
    drift.

Design notes:
    - Optional stable architectural constraints/patterns.
"""
```

Use one canonical module header per source module. Update it when module purpose
materially changes; do not create duplicate/stale docstrings with overlapping
metadata.

After adding or materially changing source modules, run or recommend
`naos module-headers` and, when specs, tasks, source headers, source spec
references, profile-required spec files, brownfield evidence, or source traceability changed,
`naos spec-pack-contract`, `naos spec-pack-materialize --dry-run`, `naos spec-assembly-worksheet`, and `naos spec-cascade` as applicable. Treat findings as traceability review evidence; do not
auto-rewrite headers across the project or treat structural traceability as
code-correctness, filled-content, candidate-promotion, or spec-quality proof without human/profile-based approval.

## Core Standards

- **Layering**: Routes → Services → DB. Full rules: `api-endpoints.instructions.md`.
- **Config**: `[ADAPT: your config import, e.g. from src.core.config import settings]` — never hard-code values from `configs/*.yaml`.
- **Errors**: Every `except` must re-raise, log WARNING+, or route to DLQ. Bare `except: pass` forbidden.
- **Datetime**: `[ADAPT: your timezone-aware datetime utility]` — never `datetime.utcnow()`.
- **Queries**: Parameterized only — no f-strings in SQL or Cypher.
- **Schema**: `[ADAPT: if your project uses a two-tier schema (global/tenant), document here]`
- **Enums**: Use your ORM's correct enum column pattern to avoid type registration errors.

## Security Quick-Reference (canonical detail: `security.instructions.md`)

- **Auth**: Every endpoint needs authentication and authorization dependencies — see `api-endpoints.instructions.md`.
- **SSRF**: Validate all user-provided URLs before any HTTP fetch — raise 422 on failure.
- **PII**: No PII in application schema, logs, or LLM prompts.
- **Errors**: Centralized error handler only — never expose raw tracebacks in API responses.

## Pre-Coding Checks

1. `python scripts/naos_function_index_query.py --package <target>` — check existing functions.
2. `python scripts/naos_function_index_query.py --similar "<description>"` — optional project-configured near-matches when available.
3. `grep -r "def function_name" src/` — verify no duplicates.
4. If changing `specs/04-architecture.md`, verify linkage to specs 01-03, task registry, traceability where present, affected capabilities, gates/evidence, known gaps, and residual risks.
5. If specs, profile-required spec files, brownfield evidence, task registry entries, source headers, source spec references, or source traceability changed, run or recommend `naos spec-pack-contract`, `naos spec-pack-materialize --dry-run`, `naos spec-assembly-worksheet`, and `naos spec-cascade` as applicable.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-python/SKILL.md` — invoke via Copilot chat when you need patterns.
