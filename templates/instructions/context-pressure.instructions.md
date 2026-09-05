---
applyTo: "**"
---

# Context Pressure Guidelines

> Governs AI agent behavior when context window is under pressure.
> Applies globally to all coding sessions.
> Project-level AI-surface budget is checked separately with `naos ai-surface-budget`; this file governs live session behavior, not static baseline approval.

## Context Brackets

As the context window fills, escalating constraints apply:

| Bracket | Threshold | Behavior |
|---------|:---------:|---------|
| `FRESH` | < 25% used | Normal operation — full analysis, deep research, complete documentation |
| `MODERATE` | 25–50% used | Prefer concise outputs; avoid redundant tool calls; batch reads |
| `DEEP` | 50–75% used | Prioritize essential context only; use configured/authorized/verified memory tools or compact fallback; emit session checkpoints |
| `CRITICAL` | > 75% used | Save session state to authorized memory or compact fallback immediately; complete current atomic unit; hand off cleanly |

## Rules Per Bracket

### FRESH
- Full protocol, all tools available, no special constraints.

### MODERATE
- Skip reading files you've already read in this session.
- Prefer `grep_search` over full file reads for targeted lookups.
- Batch independent tool calls when possible.

### DEEP
- If Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, call `mem_session_summary` at the next natural checkpoint; otherwise update the active compact/task card with the same state.
- Use `strategic-compact` skill to update the session brief.
- Avoid creating new task cards or large documentation — defer to next session.
- Complete the current atomic work unit before stopping.

### CRITICAL
- **Immediately** persist all in-progress state. If Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, call `mem_session_summary`; otherwise update the active compact/task card and mark recovery as degraded.
- Update `naos/active/<TASK-ID>_compact.md` with current WI and next steps.
- Do NOT start new work items — finish or safely abandon the current one.
- Leave clear breadcrumbs: last completed step, next step, any blockers.

## Recovery After Compaction

When a compaction message appears, execute this sequence before resuming:

1. **Read compact file** — `naos/active/<TASK-ID>_compact.md` (fastest recovery)
2. **Check memory state** — run or consult `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`; if Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy, call `mem_context`; if deferred/disabled/unavailable, continue with degraded recovery
3. **Read active task card** — restore scope and acceptance criteria
4. **Search memory if available** — call `mem_search "<task-id>"` only when Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy
5. **Check `git diff --name-only`** — resume from last verified file state

**Do NOT restart completed work** — verify what was done, then continue from the last checkpoint.

## Anti-Patterns

- Never discard in-progress work when approaching context limits — checkpoint first.
- Never start a new WI when context is CRITICAL — finish or safely hand off the current one.
- Never skip the compaction recovery sequence — skipping causes scope drift.
