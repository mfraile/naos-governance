# Micro Tutorial 10 — naos-d-start

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Command**: `/naos-d-start`
> **Agent**: `@naos-plan`
> **Cadence**: Daily — first thing every coding session
> **Time**: 3–5 minutes

---

## What This Command Does

`/naos-d-start` is morning governance-bootstrap guidance. When invoked, it
instructs the configured host or agent to review:

1. The governance constitution and rules
2. Your active task cards (what you were working on)
3. Session memory when configured, or degraded recovery from compact/task-card state
4. Project status and priorities

Without that review, an AI agent may begin without relevant governance context
or prior decisions that affect the current task.

---

## The Agent: `@naos-plan`

`@naos-plan` is the planning and orchestration prompt. It is instructed to use:

- Governance guidance and evidence-gap reporting; the prompt does not enforce rules
- The project spec structure and task registry
- How to recover from compaction (context loss between sessions)
- How to read and summarize active task cards
- How to set the governance context for the session

Use `@naos-plan` for:
- Session starts and ends
- Planning and priority-setting
- Governance questions
- Recovering context after a gap

---

## When to Use It

- **Every time** you start a coding session
- After a break of more than a few hours
- When resuming work after context compaction
- When switching from one project to another

---

## Step-by-Step

### Step 1: Open your AI tool

Use whichever AI assistant your team has configured (Copilot, Claude Code, Cursor, etc.).

### Step 2: Invoke the command

```
/naos-d-start
```

Or, using the agent directly:

```
@naos-plan /naos-d-start
```

### Step 3: Declare what you are working on today

The prompt is designed to ask you to declare your task; verify that your host actually presents this request:

```
Today I'm working on: [describe your task or paste the task ID, e.g., T-202]
```

### Step 4: Ask the agent to review the requested context

The prompt instructs the agent to:

1. Read `@.ai/RULES.md` — governance constitution
2. Read `@naos/governance/PROJECT_GOVERNANCE_RULES.md`
3. Read `@naos/PROJECT_STATUS.md` — current status and priorities
4. Read `@naos/TASK_REGISTRY.yaml` — all tasks (authoritative source)
5. Check `naos/active/` for your active task card
6. Run or consult `naos session-start --task <TASK-ID>` as a bounded checklist; it does not inject context automatically.
7. Check `configs/naos_memory.yaml`, `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`; when Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy, tool-specific agents may use `mem_context` as advisory recall. If memory is deferred, disabled, unverified, or unavailable, recover from the compact file, active task card, git state, repo governance files, and deterministic reports.
8. Surface any existing `parallel_lane_opportunity` or
   `parallel_lane_decision` from active cards or alignment artifacts. This is
   a planning reminder only; it does not declare lanes or activate handoff.

### Step 5: Review the agent's summary

The requested output is:

- **Pre-Task Research Summary**: what it found in context
- **Files to Update** (not create): what it plans to modify
- **Impact Validation**: what documentation will be affected
- **Priority Tasks**: top 3–4 tasks based on project status
- **Lane posture** when available: whether work is sequential, deferred, or
  explicitly declared for handoff review

Review this before writing any code.

---

## What the Prompt Instructs the Agent Not to Do

- The prompt instructs the agent not to create new summary or analysis files (Rule 1).
- The prompt instructs the agent not to create archive folders (Rule 2).
- The prompt instructs the agent to read task IDs from `TASK_REGISTRY.yaml`, not invent them.
- The prompt instructs the agent not to modify files outside the declared scope.

These are instructions, not an enforcement guarantee; review the agent output and repository diff.

---

## Common Mistakes

**❌ Skipping `/naos-d-start` and going straight to coding**

The AI agent may then start without reviewing governance context. Instructions
may not be reviewed or applied, and prior decisions may be rediscovered from
scratch.

**❌ Running `/naos-d-start` but not reading the output**

The requested context-review output may contain important information —
especially recovered memory from previous sessions or a degraded recovery
summary from compact/task-card state. Review the cited sources before relying
on it.

**❌ Using a different agent for session start**

`@naos-plan` is the designated session-start prompt. Another agent does not
follow the bootstrap sequence unless the host or operator explicitly supplies
equivalent context-review instructions.

---

## What Happens Next

After `/naos-d-start`, you are ready to begin a task.

The prompt's `next_action` footer will usually point you to
`/naos-task-start <TASK_ID>` after the requested daily context review.

If you know which task you are starting:
→ [Micro Tutorial 11: naos-task-start](./MICRO_TUTORIAL_11_NAOS_TASK_START.md)

If you are continuing work from a previous session:
- Check your active task card in `naos/active/`
- Resume with `@naos-implement` where you left off

---

## Key Governance Rules Active During This Step

| Rule | Description |
|------|-------------|
| Rule 1 | Update existing files only — no new analysis/summary files |
| Rule 2 | No archive folders |
| Rule 3 | PM status in one place: `naos/PROJECT_STATUS.md` |
| Rule 17 | Never recreate existing code without querying the function index |
