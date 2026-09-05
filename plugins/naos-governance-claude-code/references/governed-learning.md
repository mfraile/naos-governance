# Governed Learning Propagation

Learning starts locally and remains proposal-only until reviewed.

```text
Learn anywhere -> approve centrally -> propagate deliberately -> verify adapters
```

When a Claude Code session discovers a reusable lesson:

1. Capture it as candidate learning or a review finding.
2. Optionally run `naos failure-mode-observations --profile <profile>` when
   local report findings should be counted by failure mode for review.
3. Run `naos learning-loop-review --profile <profile>`.
4. Update canonical NAOS artifacts only after human review.
5. Run `naos ai-surface-budget --profile <profile>` if AI surfaces changed.
6. Run `naos adapter-coherence --profile <profile>` after propagation.

Project facts stay project-local. Reusable method improvements may be promoted
to shared skills, prompts, workflows, docs, or plugin skills only after review.
Failure-mode observation counts are review statistics only; they do not write
learning records, activate MCP/memory/provider/model runtime, approve
promotion, or replace repository evidence.
