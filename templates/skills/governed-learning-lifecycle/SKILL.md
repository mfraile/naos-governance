---
name: "governed-learning-lifecycle"
description: "Review and use NAOS governed learning lifecycle controls. Invoke when capturing lessons, promoting learning into active guidance, replacing stale learning, forgetting/redacting records, or changing skills/prompts/workflows/baselines/gates based on learned evidence."
parameters: []
---

# Governed Learning Lifecycle

## When to Use

Use this skill when work produces a lesson that might affect future behavior:

- a verified fact, rule, failure mode, or anti-pattern;
- a proposed skill, prompt, workflow, baseline, or gate-policy update;
- a stale or wrong lesson that should be superseded, deprecated, archived,
  rejected, redacted, or rolled back;
- an autoresearch, session-end, audit, incident, or review finding that should
  become candidate learning.

## Core Commands

```bash
naos learning-loop-review --profile <profile>
make -f Makefile.naos naos-learning-loop-review
```

When a learning changes AI/governance surfaces, also run:

```bash
naos ai-surface-budget --profile <profile>
naos systemic-impact --profile <profile>
naos control-plane-review --profile <profile>
```

## Lifecycle

Use the governed sequence:

```text
capture -> verify -> consolidate -> consult -> act -> supersede/deprecate/archive/reject/redact
```

Candidate records live in `naos/learning_candidates.yaml`. Active reviewed
guidance lives in `naos/learning_state.yaml`. Superseded, deprecated,
archived, rejected, and redacted records live in `naos/learning_history.yaml`.

## Rules

1. Candidate learning is proposal-only. It must not be treated as active
   instruction or evidence.
2. Active learning needs scope, evidence, source session, verifier, approver,
   review date, risk, retrieval policy, and limitations.
3. High-authority learning that affects skills, prompts, workflows, baselines,
   gates, maturity, or instructions needs explicit promotion review metadata.
4. Superseded learning needs `replaced_by`. Deprecated learning needs a reason
   and review path. Redacted learning must remove private payloads and keep only
   safe audit metadata.
5. Repository evidence, current user instructions, and human decisions outrank
   learning state.

## Non-Claims

This lifecycle does not write memory, call Engram/MCP/providers/LLMs, inject
context automatically, prevent hallucinations, approve work, certify compliance,
or mutate governed artifacts automatically.
