---
name: "strategic-compact"
description: "Invoke when starting, resuming, updating, closing, or handing off a multi-workstream task; create or maintain a five-field Strategic Compact for continuity."
parameters: []
---

# SKILL: strategic-compact
# Purpose: Create and maintain a Strategic Compact — a living 5-field session brief
#          that survives compaction, guides agent continuity, and replaces ad-hoc notes
# Invoke: at session start, after each workstream completes, before session close, after compaction

---

## What Is a Strategic Compact?

A Strategic Compact is a **1-page living document** maintained by any planning or
implementation agent across a multi-workstream task. It provides:

- **Focus anchor** — what we are doing and why, always current
- **Compaction recovery** — the first thing to read after any context reset
- **Handoff substrate** — what the next agent (or session) needs to know immediately

It replaces ad-hoc session summaries, mid-task notes in the card, and "situation in
the header" comments. It is stored in `naos/active/<TASK-ID>_compact.md`.

---

## Quick Start

1. For a multi-workstream task, check whether
   `naos/active/<TASK-ID>_compact.md` already exists.
2. Create or update the five fields: Focus, Completed, In Progress, Decisions
   Made, and Critical Constraints.
3. Keep the compact to 30 lines or fewer.
4. Use Engram only when write access is configured, authorized, verified,
   policy-permitted, and explicitly approved; otherwise keep recovery state in
   the compact or task card.

## When to Invoke This Skill

| Trigger | Action |
|---------|--------|
| Session opens on a multi-WI task | Create compact if absent; read compact if present |
| A WI is marked complete | Update compact: advance current_wi, update progress |
| A compaction event occurs | Read compact first (before task card, before memory lookup) |
| Handing off to another agent | Ensure compact is current before handoff |
| Session is closing | Update compact with final state + next steps |
| User says "continue" or "resume" | Check for compact; if present, read it; if absent, create from card |

---

## Compact Format (5 Fields)

```markdown
# Strategic Compact — <TASK-ID>
_Last updated: YYYY-MM-DD HH:MM UTC by <agent-name>_

## Focus
<1-2 sentences: what task, which WI in progress, what it achieves>

## Completed
- WI-N: <title> ✅ — <one-line summary of what was done>
- WI-M: <title> ✅ — <one-line summary>

## In Progress
- WI-X: <title> 🔄 — <current status: "created dirs", "3/5 files done", etc.>
  - Next action: <exactly what to do next>

## Decisions Made
- <decision>: <why> (avoids relitigating resolved questions)
- ...

## Critical Constraints
- <constraint 1>
- <constraint 2>
```

**Maximum size:** 30 lines. If it grows beyond 30 lines, summarize older items into a single line and link to card AC.

---

## Step-by-Step: Creating a Compact

1. Check if `naos/active/<TASK-ID>_compact.md` already exists — if yes, **update it, don't recreate**
2. Read the task card `naos/active/<TASK-ID>_*.md` to extract WI list, completed ACs, and current scope
3. Fill in the 5 fields above
4. Save to `naos/active/<TASK-ID>_compact.md`
5. If Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, call `mem_save` to record that a compact exists for this task; otherwise note the compact path in the active task card

**Template invocation:**
```bash
# Check if compact exists
ls naos/active/<TASK-ID>_compact.md 2>/dev/null && echo FOUND || echo CREATE
```

---

## Step-by-Step: Reading a Compact After Compaction

When you detect that compaction has occurred (context-reset banner, conversation summary):

1. **First** — read `naos/active/<TASK-ID>_compact.md` (faster than card, tells you exactly where to resume)
2. **Second** — check `configs/naos_memory.yaml` and `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`; if Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy, call `mem_context` for session observations
3. **Third** — call `mem_search "<task-id>"` only when Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy; otherwise continue degraded recovery from compact, task card, git state, and deterministic reports
4. **Fourth** — skim the task card's AC section to confirm checkbox state
5. **Skip**: Do NOT re-read entire card, entire RULES.md, or entire CLAUDE.md unless compact says "re-read X"

---

## Step-by-Step: Updating a Compact

After completing a WI:

1. Move the WI from "In Progress" to "Completed" with a one-line summary
2. Advance "In Progress" to the next WI + its first action
3. Update `_Last updated` line
4. Keep total lines ≤ 30

---

## What NOT to Do

- **Do NOT** create multiple compacts for the same task
- **Do NOT** let compact grow >30 lines — summarize, don't expand
- **Do NOT** duplicate the task card's full AC list in the compact
- **Do NOT** use compact to store code snippets or full diffs — that belongs in Engram when configured or in the task card when running degraded recovery
- **Do NOT** skip reading the compact when resuming — it exists precisely to prevent that

---

## Files This Skill Touches

- `naos/active/<TASK-ID>_compact.md` — the compact itself (created/updated by this skill)
- `naos/active/<TASK-ID>_*.md` — source task card (read-only during compact creation)
- Engram (`mem_save`) — record compact creation/location only when memory write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use

---

## Agents That Use This Skill

The following agents invoke `strategic-compact` as part of their protocol:
- `plan` — creates compact during planning phase
- `implement` — reads compact at session start; updates after each WI
- `review` — reads compact to verify scope before reviewing
- `debug` — reads compact to establish task context before diagnosing
- `gov-audit` — reads compact to understand what changed before auditing

**`triage`** does NOT use this skill — triage operates on fresh, uncontextualized issues.
