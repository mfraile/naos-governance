---
name: naos-governed-learning
description: Apply NAOS governed learning lifecycle from Claude Code. Use when a lesson may change future skills, prompts, workflows, baselines, gates, docs, or adapter behavior.
---

# NAOS Governed Learning

Use this skill when a Claude Code session produces a potential reusable lesson.

## Steps

1. Classify the learning as project fact, project rule, reusable method,
   adapter defect, skill improvement, or obsolete learning.
2. Keep project-sensitive facts inside the project.
3. Treat candidates as proposal-only until reviewed.
4. Optionally recommend `naos failure-mode-observations --profile standard`
   when local report findings should be counted by failure mode for review.
5. Recommend `naos learning-loop-review --profile standard`.
6. If an AI surface changes, also recommend `naos ai-surface-budget` and
   `naos adapter-coherence`.

## Replacement And Forgetting

Learning may be added, superseded, reverted, or expired. Preserve history and
review metadata instead of silently deleting prior guidance.

## Boundaries

Failure-mode observations may focus human review of recurring or unmapped
patterns, but they do not create learning records or approve promotion. Do not
write memory, mutate shared skills, alter plugin files, activate MCP/provider
runtime, or change hooks without explicit human-approved artifact edits and
follow-up checks.
