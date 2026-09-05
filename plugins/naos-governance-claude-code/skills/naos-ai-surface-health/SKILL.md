---
name: naos-ai-surface-health
description: Review NAOS AI surface budget and context health from Claude Code. Use when CLAUDE.md, plugin skills, prompts, agents, manuals, quick references, or instructions change.
---

# NAOS AI Surface Health

Use this skill to keep Claude-facing governance surfaces bounded and coherent.

## Steps

1. Identify changed AI surfaces: `CLAUDE.md`, plugin skills, hook guidance,
   prompts, agents, instructions, manuals, quick references, and docs.
2. Recommend `naos ai-surface-budget --profile standard` for singleton health.
   When profile breadth or candidate intake changes, also recommend
   `naos ai-surface-budget --fresh-profiles --json`; add `--all` for the
   complete human occurrence view.
3. Preserve required anchors while reducing repeated always-loaded prose.
4. Route residual warnings through `naos control-plane-review` instead of
   inflating thresholds.
5. If learning drove the change, recommend `naos learning-loop-review`.

## Boundaries

AI-surface health reduces context overload and contradiction risk. It does not
prevent hallucinations, grade model behavior, auto-tune thresholds, approve
baselines, certify prompt fidelity, or replace human review. Fresh-profile mode
writes nothing unless an explicit output path is supplied.
