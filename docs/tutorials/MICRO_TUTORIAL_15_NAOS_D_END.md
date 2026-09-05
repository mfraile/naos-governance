# Micro Tutorial 15 — naos-d-end

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Command**: `/naos-d-end`
> **Agent**: `@naos-plan`
> **Cadence**: Daily — last action of every coding session
> **Time**: 5–10 minutes

---

## What This Command Does

`/naos-d-end` is session-close prompt guidance. It requests review of:

1. Project status is updated with today's work
2. Tomorrow's priorities are planned
3. A session memory checkpoint is saved only when memory is configured and write-authorized, with compact/task-card fallback when it is not
4. Completed-task lifecycle state, with no default archive automation
5. Governance metrics are refreshed

It complements `/naos-d-start`. Useful context is available next session only
when the requested updates are actually persisted and later read.

---

## The Agent: `@naos-plan`

`@naos-plan` carries session-open and session-close instructions. It is asked to:

- Summarize today's work with source references for operator review
- Identify the right priorities for tomorrow from the project status
- Propose authorized memory persistence or a compact/task-card fallback and report what was actually saved
- Generate the exact git commands needed to close out cleanly

---

## When to Use It

- **Every time** you end a coding session
- Before a longer break (overnight, weekend, vacation)
- When switching projects

---

## Step-by-Step

### Step 1: Confirm your work is committed

Before running `/naos-d-end`:

```bash
git status   # Should show clean or only known uncommitted work
git log --oneline -5  # Verify today's commits are there
```

### Step 2: Invoke the command

```
/naos-d-end
```

Or:

```
@naos-plan /naos-d-end

Today's work:
- Completed: T-202 user auth endpoint
- In Progress: T-205 payment integration (50% done)
- Blockers: None
```

### Step 3: Review the three mandatory output sections

The prompt requests:

**Section 1: Files Updated**
- What changed today
- Session impact summary

**Section 2: Tomorrow's Priorities**
- Priority 1 (Critical): Blockers, deadlines
- Priority 2 (High): Phase goals, active work
- Priority 3 (Normal): Planned tasks
- Context for tomorrow: decisions made today, dependencies

**Section 3: Session Closing Commands**
Commands for human review before execution:

```bash
# 1. Full governance refresh where project-specific PM artifacts are installed
make -f Makefile.naos gov-refresh

# 2. Stage status updates
git add naos/PROJECT_STATUS.md CHANGELOG.md naos/active/ naos/completed/ naos/TASK_REGISTRY.yaml

# 3. Commit
git commit -m "docs(pm): End-of-day status update 2026-03-25"

# 5. Push
git push origin [branch]
```

### Step 4: Save session memory or compact fallback

The agent should run or consult `naos session-end --task <TASK-ID>` and prepare a reviewable closeout. Memory candidates are proposal-only unless Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use. If memory is deferred, disabled, unauthorized, or unavailable, record any needed summary manually in the active compact/task card. Verify it captures:

```
## Goal: [what you worked on]
## Discoveries: [technical findings, constraints, unexpected things]
## Accomplished: [completed items with key details]
## Next Steps: [what remains for next session]
## Relevant Files: [paths touched and what changed]
```

This state can be recovered at the next session only if it was actually saved
and the next host reads it: via `mem_context` when Engram/MCP access is
configured and authorized, or via a persisted compact/task-card fallback.

### Step 5: Run the closing commands

Review and explicitly run only the authorized commands from Section 3. The
prompt itself does not execute them. The example commands may:

- Request project-specific completed-card handling; NAOS ships no default archive script
- Refresh configured governance metrics when their commands exist
- Commit a reviewed status update
- Push only with separate remote-write authority

---

## Status Update Content

The prompt asks for reviewed updates to `naos/PROJECT_STATUS.md`, where present:

- **Work Breakdown Table**: Updated FR/NFR status
- **Update History**: Today's entry with summary
- **Recent Decisions**: Any ADRs made today
- **Risk Register**: Updates if risks changed

It also requests an applicable `CHANGELOG.md` update under `[Unreleased]`:

- Added / Changed / Fixed / Removed
- Session impact metrics
- Commits pushed today

**Do not calculate these metrics manually.** The agent reads them from the authoritative sources (`specs/03-requirements.md`, `naos/TASK_REGISTRY.yaml`).

---

## Handling In-Progress Tasks

If a task is in progress but not complete:

1. Add implementation notes with today's date to the story card
2. Update progress in the card (e.g., "50% complete — auth logic done, tests remain")
3. Leave the card in `naos/active/` — do NOT archive it

If a task is complete:
- Run `/naos-task-complete T-XXX` before running `/naos-d-end`
- Verify the completion workflow's actual files; no default archive script is shipped

---

## Common Mistakes

**❌ Skipping `/naos-d-end` when you are "almost done"**

The reviewable memory or compact-file candidate is an important output. Without
verified persistence, the next session may start without this context.

**❌ Running `/naos-d-end` before committing your code**

The status update in `naos/PROJECT_STATUS.md` should reflect committed work, not in-flight changes. Commit first, then close the session.

**❌ Not reading tomorrow's priorities**

The proposed priority list should cite current project state. Review it before
closeout; prompt output alone does not prove tomorrow's priority.

---

## The Daily Rhythm — Complete Picture

```
Morning
  /naos-d-start (@naos-plan)     ← request context review and recovery

  /naos-task-start T-XXX (@naos-plan or @naos-triage)  ← request task review

  @naos-implement                 ← code, test, fix

  @naos-review                    ← verify spec alignment

  /naos-task-complete T-XXX (@naos-conformance)  ← request audit/lifecycle review

Evening
  /naos-d-end (@naos-plan)       ← request status/memory/priority closeout
```

---

## What Happens Next

After verifying the requested persistence and authorized closeout actions,
resume tomorrow with:

→ [Micro Tutorial 10: naos-d-start](./MICRO_TUTORIAL_10_NAOS_D_START.md)

The `next_action` footer should match the first safe step recorded in the session summary, usually `/naos-d-start` with the next priority already named.
