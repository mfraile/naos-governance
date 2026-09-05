# Micro Tutorial 11 — naos-task-start

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Command**: `/naos-task-start`
> **Default Agent**: `@naos-plan`
> **Alt Agent**: `@naos-triage` (when task needs shaping before planning)
> **Cadence**: Once per task, after `/naos-d-start`
> **Time**: 5–10 minutes

---

## What This Command Does

`/naos-task-start` is task-start prompt guidance. When invoked, it requests that
the configured host or agent:

1. Verify the task exists in `naos/TASK_REGISTRY.yaml`
2. Review the relevant spec sections, schemas, and existing code
3. Create or read an **active story card** in `naos/active/`
4. Record scope guardrails for review

The story card is the single source of truth for the task. Everything decided during the task — schemas to respect, code to reuse, acceptance criteria — lives in that card.

---

## The Two Agents

### `@naos-plan` — Default

Use `@naos-plan` when:
- The task is already defined in the task registry with clear acceptance criteria
- You know what needs to be built
- This is a continuation of already-specified work

`@naos-plan` is instructed to read the task registry, extract acceptance
criteria, review relevant context, and propose or update the story card. Check
the resulting files and evidence.

### `@naos-triage` — When Task Shaping Is Needed

Use `@naos-triage` when:
- The task exists in the registry but is vague or underspecified
- You are unsure what the task requires technically
- You need to decompose a large task before committing to an approach
- The task has cross-cutting concerns that need clarification before coding

`@naos-triage` provides structured shaping guidance: it requests clarifying
questions, dependency and constraint review, and a refined task proposal before
an explicit handoff to `@naos-plan`.

**Decision rule**: If you can answer "what exactly am I building and how?" in one sentence, use `@naos-plan`. If you cannot, use `@naos-triage` first.

---

## Step-by-Step (Default Path — `@naos-plan`)

### Step 1: Confirm `/naos-d-start` has run

Complete and review the `/naos-d-start` context request before starting a task.

### Step 2: Identify the task

Find the task ID in `naos/TASK_REGISTRY.yaml`:

```bash
grep -A5 "title: My Feature" naos/TASK_REGISTRY.yaml
```

### Step 3: Run the command

```
/naos-task-start T-202
```

Or using the agent directly:

```
@naos-plan /naos-task-start T-202
```

### Step 4: Ask the agent to research context

The prompt instructs the agent to:

1. Verify `T-202` exists in `naos/TASK_REGISTRY.yaml`
2. Check `naos/active/` for an existing card
3. Load related schemas and migrations
4. Query the function index for existing code related to this task
5. Identify the acceptance criteria from the registry and `specs/03-requirements.md`

### Step 5: Review the story card

Review the proposed or updated `naos/active/T-202_[short_description].md` for:

- Task metadata (ID, requirement, spec section)
- Schemas to respect
- Existing code to reuse (Rule 17: do not recreate)
- Acceptance criteria
- Parallel lane posture: `parallel_lane_opportunity`,
  `parallel_lane_decision`, reason codes, and suggested lanes where relevant
- Pre-coding checklist

**Read the entire card before writing any code.**

### Step 6: Confirm the pre-coding checklist

Before coding, verify:

- [ ] Spec section read
- [ ] Schema matches plan
- [ ] Function index queried (no duplicates)
- [ ] Acceptance criteria understood
- [ ] Scope limited — no scope creep
- [ ] Lane posture recorded: `sequential`, `deferred`, or explicitly
      `declared`
- [ ] If lanes are declared, `naos/lane_handoffs/_TEMPLATE.yaml` will be filled
      at lane completion/block/review; suggested lanes alone do not activate
      handoff

---

## Step-by-Step (Shaping Path — `@naos-triage`)

### When to use this path

```
/naos-task-start T-315
```

If the registry shows the task as: `status: defined | description: vague` — switch to triage.

### Run triage

```
@naos-triage /naos-task-start T-315
```

The triage prompt instructs the agent to:

1. Ask clarifying questions about the task scope
2. Identify technical unknowns and dependencies
3. Propose a decomposed task breakdown
4. Produce a refined task definition

### Hand off to plan

After triage produces a clear definition:

```
@naos-plan — create the story card for T-315 using the triage output above
```

---

## What a Story Card Contains

```markdown
# Active Task: T-202 - [Title]

## Quick Reference
| Field | Value |
|-------|-------|
| Task ID | T-202 |
| Requirement | FR-15 |
| Spec Section | specs/03-requirements.md L145 |
| Created | 2026-03-25 |

## Schemas to Respect
[DB tables, columns, JSON schema fields — DO NOT VIOLATE]

## Existing Code to Use
[Files and functions discovered — DO NOT RECREATE]

## Acceptance Criteria
- AC-202.1: [criterion]
- AC-202.2: [criterion]

## Pre-Coding Checklist
- [ ] Spec section read
- [ ] Schema matches plan
- [ ] Function index queried
- [ ] No duplicate planned
- [ ] Acceptance criteria understood
```

---

## Common Mistakes

**❌ Starting a task that isn't in the registry**

The task registry is the authoritative source. If the task doesn't exist there, add it before starting. Do not invent task IDs.

**❌ Skipping the story card research phase**

The research in Step 4 reduces duplicate-implementation and schema-mismatch
risk; it does not guarantee either outcome.

**❌ Using `@naos-plan` when the task is vague**

If you start coding before the acceptance criteria are clear, you will likely need to redo the work. Use `@naos-triage` to get clarity first.

---

## What Happens Next

After confirming the story card exists and is source-grounded:

→ [Micro Tutorial 12: Implement in Practice](./MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md)
