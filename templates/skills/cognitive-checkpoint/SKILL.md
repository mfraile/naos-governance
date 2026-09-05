---
name: "cognitive-checkpoint"
description: "Provide recovery-grade checkpoints at Rule 26 trigger points. Invoke at phase transitions, non-obvious discoveries, tool depth, context pressure, or pre-handoff."
parameters: []
---

# SKILL: cognitive-checkpoint
# Purpose: Provide a concrete template for saving recovery-grade checkpoints at
#          the 5 mandatory triggers defined in Rule 26.
# Invoke: at any T1–T5 trigger (phase transition, discovery, tool depth, context
#         pressure, or pre-handoff). Zero cost when not needed.

---

## What Is a Cognitive Checkpoint?

A cognitive checkpoint is a **structured memory save** that captures enough context
for ANY agent (including yourself after compaction) to resume exactly where you left off
without re-reading every file.

**Why it matters**: `wi9_recovery_with_both` scores 33% even with a story card AND Engram
memory — because the checkpoints lack the 5 critical fields. This skill provides the template
that makes checkpoints actually useful for recovery.

**Memory requirement**: Use Engram only when memory/MCP access and durable writes are configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use. Run or consult `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy` before assuming access. If Engram is already installed but this project is not connected, run `naos memory check`. If memory is deferred, disabled, unauthorized, unverified, disallowed by memory-use policy, or unavailable, save the same structured payload into the active compact/task card and mark the project as using degraded recovery.

---

## Quick Start

1. Identify the Rule 26 trigger (T1-T5) and active PAUL bracket.
2. Capture What, Why, Files, Remaining, and Gotchas.
3. Save to Engram only when write access is configured, authorized, verified,
   policy-permitted, and explicitly approved; otherwise write the same payload
   to the active compact or task card.
4. For declared parallel lanes, include lane id, path scope, handoff status,
   and unresolved blockers. For suggested lanes, record that no handoff is
   active unless the lane decision is declared.
5. On recovery, read the compact first, then memory only when read access is
   configured, authorized, verified, and policy-permitted.

## When to Invoke (Rule 26 — Five Triggers)

| Trigger | Signal |
|---------|--------|
| **T1 Phase transition** | You finish planning and start implementing; you finish implementing and run tests; you finish testing and commit |
| **T2 Non-obvious discovery** | You found a bug root cause, an architecture constraint not in the card, a config gotcha, or an edge case that changes your approach |
| **T3 Tool depth** | You've made ≥5 consecutive tool calls without saving a checkpoint in this session |
| **T4 Context pressure** | ≥20 messages have passed in this session without a checkpoint |
| **T5 Pre-handoff** | You are about to yield to `@naos-review`, `@naos-conformance`, `@naos-debug`, or `@naos-plan` |

### PAUL Context Brackets (Rule 26 companion)

> Every checkpoint MUST pre-declare the active PAUL bracket. Brackets are estimates of remaining context-window headroom and dictate behavioral changes. Use Copilot's status bar / Claude's `/context` to estimate.

| Bracket | Headroom remaining | Behavioral change | Trigger interplay |
|---|---|---|---|
| **FRESH** | > 75% | Normal cadence. Speculative exploration permitted. | T1–T5 fire as written. |
| **MODERATE** | 35–75% | Prefer focused tool calls; summarise verbose tool outputs before continuing. | T3 frequency raised: checkpoint every 4 tool calls. |
| **DEEP** | 25–35% | No new exploration branches. Compact memory before any new agent invocation. Pre-handoff (T5) becomes mandatory before *any* sub-task. | Force a T1 + T5 checkpoint as soon as DEEP is entered. |
| **CRITICAL** | < 25% | Save a full checkpoint, then hand off. | Normative stop; hook cannot intercept tools. |

**How to declare in a checkpoint:**
```
mem_save "<title>" "**Bracket**: DEEP\n**What**: ...\n**Why**: ...\n**Files**: ...\n**Remaining**: ...\n**Gotchas**: ..."
```

---

## Checkpoint Templates

### Full Template (T1 / T2 / T5 — phase transitions, discoveries, handoffs)

```
mem_save "<verb> <what> in <task-id>" "
**What**: <1-2 sentences: what was decided/implemented/found — outcome, not just action>
**Why**: <motivation — enough to reconstruct reasoning; not just 'per requirements'>
**Files**: <precise paths changed or read — comma-separated, not 'some files in src/'>
**Remaining**: <exact next concrete action: command to run or edit to make>
**Gotchas**: <non-obvious constraint, edge case, or surprise — 'none' if truly none>
"
```

**Example** (phase transition after implementing PID lockfile):
```
mem_save "Implemented PID lockfile in runner.py" "
**What**: Added _acquire_lock()/_release_lock() + --force flag to runner.py. PID file at
  PROJECT_ROOT/.autoresearch.pid. Stale PIDs cleaned automatically on startup.
**Why**: INS-009 — interrupted runs billed in full; concurrent runs double the cost.
**Files**: autoresearch/runner.py in kit source or generated .github/autoresearch/runner.py copy, configs/naos_autoresearch.yaml
**Remaining**: Add drift_retry_attempts and preferred_run_window_utc to autoresearch.yaml.
  Then add drift-safe Makefile target.
**Gotchas**: _acquire_lock uses logging.getLogger() directly (not module-level logger)
  because it is defined before the module-level logger assignment — works correctly.
"
```

### Quickfire Template (T3 / T4 — tool depth / context pressure)

For fast checkpoints during active tool execution chains, when a full template would
break flow. Use when you cannot identify a meaningful "why" or "gotcha":

```
mem_save "Progress checkpoint — <task-id> <phase>" "
State: <one sentence: what you just did>
Next: <exactly what to do next>
Open: <any concern or thing to watch>
"
```

---

## Recovery Protocol

After compaction or session restart, to restore state from a previous checkpoint:

1. **Read compact first** (fastest): `ls naos/active/<task-id>_compact.md && cat naos/active/<task-id>_compact.md`
2. **Search Engram for recent checkpoints** only when read access is configured, authorized, verified, and permitted by memory-use policy: `mem_search "<task-id> checkpoint"`
3. **Get full checkpoint content**: `mem_get_observation <observation-id>`
4. **Verify against task card**: Read `naos/active/<task-id>_*.md` — confirm you're not
   re-doing completed work. Cross-reference compact's "Completed" list.
5. **Resume from last known state**: Do NOT restart from beginning unless compact is absent
   and Engram returns no matches.

**Only then**: run `git diff --name-only` to see what was changed vs HEAD, then continue
from the next action listed in the checkpoint.

---

## Anti-Patterns (What Makes a Bad Checkpoint)

| Anti-pattern | Why it breaks recovery |
|---|---|
| "I implemented the PID lockfile" (no why/files/remaining) | Recovering agent re-reads all files to figure out what was done |
| Only "what" + "files" — missing "remaining" | Agent doesn't know where to continue |
| "Per the requirements" as the "why" | Too vague — cannot reconstruct which requirement, which tradeoff was made |
| Saving at end-of-session only | If compaction hits mid-session, the entire session's reasoning is lost |
| Using checkpoint as user-facing status update | Checkpoints are for agent recovery, not for the human in the chat |
| Skipping T5 pre-handoff | Receiving agent starts cold and may redo work or miss constraints |

---

## mem_save vs memory create — When to Use Which

| Checkpoint type | Tool | Why |
|---|---|---|
| Mid-task, survives compaction | `mem_save` (Engram) only when configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use | Searchable, survives context compaction |
| Cross-session reference | Approved memory write or compact/task-card fallback | Persists after session end only when authorized and human-approved |
| Critical decisions | Repo evidence plus authorized memory reference | Repository governance remains authoritative |

If neither Engram nor `/memories/` is available, write the checkpoint to the active compact/task card and include the same What / Why / Files / Remaining / Gotchas fields.
