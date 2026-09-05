---
name: "naos-governed-learning"
description: "Use NAOS governed learning lifecycle from Codex when lessons might change future skills, prompts, workflows, baselines, gates, instructions, or adapter content."
parameters: []
---

# NAOS Governed Learning

## When to Use

Use this skill when a session produces a lesson, failure mode, anti-pattern,
verified fact, prompt update, skill update, workflow change, gate-policy change,
baseline change, or adapter propagation need.

## Flow

```text
capture -> verify -> consolidate -> consult -> act -> supersede/deprecate/archive/reject/redact
```

Candidate learning is proposal-only. Active learning needs reviewed evidence,
scope, verifier, approver, retrieval policy, limitations, and review metadata.

## NAOS Commands

```bash
naos failure-mode-observations --profile <profile>  # optional review input when local findings should be counted by failure mode
naos learning-loop-review --profile <profile>
naos ai-surface-budget --profile <profile>
naos systemic-impact --profile <profile>
naos adapter-coherence --profile <profile>
```

Failure-mode observations may focus human review of recurring or unmapped
patterns. They do not create learning records, mutate skills/prompts/workflows,
activate memory/MCP/provider/model runtime, or approve a learning promotion.

## Propagation Rule

Learn anywhere, approve centrally, propagate deliberately. Update canonical NAOS
artifacts first, then regenerate or review Codex, Claude Code, Cursor, VS Code,
Gemini, and MCP adapter surfaces.
