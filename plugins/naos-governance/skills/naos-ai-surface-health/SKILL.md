---
name: "naos-ai-surface-health"
description: "Review NAOS AI/governance instruction surface size, duplication, anchor coverage, and adapter loadout health from Codex."
parameters: []
---

# NAOS AI Surface Health

## When to Use

Use this skill when prompts, instructions, agents, skills, workflows, manuals,
quick references, plugin skills, or adapter guidance change.

## Review

Run:

```bash
naos ai-surface-budget --profile <profile>
naos ai-surface-budget --fresh-profiles --json
# Add --all for every human-readable occurrence.
naos adapter-coherence --profile <profile>
```

Look for oversized surfaces, duplicated rules, stale examples, conflicting
claims, missing anchors, and adapter-specific copies that no longer match the
canonical NAOS guidance. Use the fresh-profile command when profile breadth or
candidate intake changes; review findings, resident context tokens, generated
files, and generated-script-reachable commands separately for all four
profiles.

## Boundary

AI-surface budget checks do not prevent hallucinations, grade behavior, tune
thresholds, approve baselines, or prove semantic correctness. Fresh-profile
mode writes nothing unless an explicit output path is supplied.
