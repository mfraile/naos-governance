# Micro Tutorial 20 — Weekly Cadence

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Commands**: `/naos-w-plan` (Monday), `/naos-w-review` (Friday)
> **Agent**: `@naos-plan` (planning) / `@naos-review` (review)
> **Cadence**: Weekly rhythm — plan on Monday, review on Friday
> **Time**: 30–60 minutes per event

---

## What the Weekly Cadence Does

The daily NAOS workflow (start → task → implement → review → complete → end) keeps individual tasks on track. The weekly cadence zooms out to ask:

- Are we working on the right tasks this week?
- Are we making progress toward the right requirements?
- Are governance metrics trending correctly?
- Are there blockers or risks that need attention before they become crises?

The weekly cadence is the governance rhythm layer above individual tasks.

---

## Monday: Weekly Planning — `/naos-w-plan`

### Purpose

Set the week's direction. Choose the right tasks. Identify risks. Create a daily breakdown so each morning's `/naos-d-start` has a clear starting point.

### Agent

`@naos-plan` — same agent used for daily session starts.

### Run

```
/naos-w-plan

Week starting: 2026-03-25
Focus areas: Payment integration (FR-18), User management cleanup (FR-12)
```

### What the Agent Produces

**Week Overview**
- Week goal (one sentence)
- Focus areas (2–3 high-priority areas)
- Target completions (specific tasks/FRs to finish this week)
- Risks (blockers, dependencies)

**Daily Breakdown**

```
Monday:    Morning: T-205 payment gateway setup
           Afternoon: T-205 integration tests

Tuesday:   Morning: T-207 user management cleanup
           Afternoon: T-208 session expiry fix

Wednesday: Morning: T-209 payment webhook
           ...
```

**Required Reads**
The prompt instructs the agent to read, and the operator should verify:
- `@specs/03-requirements.md` — FR/NFR status (authoritative)
- `@naos/TASK_REGISTRY.yaml` — task status (authoritative)
- `@naos/PROJECT_STATUS.md` — current state
- `@specs/10-execution.md` — task execution matrix

### How to Use the Weekly Plan

Review the daily breakdown at the start of each daily session. It supplements `/naos-d-start` — when the daily session asks "what are you working on today?", the weekly plan answers.

Keep the weekly plan in `naos/PROJECT_STATUS.md` under the "Next 2 Weeks" section, or in a dedicated `naos/active/WEEK_2026-W13.md` note.

---

## Friday: Weekly Review — `/naos-w-review`

### Purpose

Assess governance health at the end of the week. Measure whether the week's goals were met. Identify patterns that need attention.

### Agent

`@naos-review` — same agent used for task-level reviews.

### Run

```
/naos-w-review

Week of: 2026-03-25 to 2026-03-28
```

### What the Agent Produces

**Velocity Assessment**
- Tasks completed vs. planned
- FRs advanced or delivered
- Commits pushed

**Governance Health**
- Pre-commit violations (blocked vs. bypassed)
- New unauthorized files
- Traceability gaps

**Quality Indicators**
- Test failures this week
- Bug fixes introduced (indicator of rework)
- Spec deviations found in review

**Next Week Priorities**
- Carryover tasks
- Newly surfaced risks
- Preparation for Monday's `/naos-w-plan`

---

## The Weekly Rhythm — Complete Picture

```
Monday morning
  /naos-w-plan (@naos-plan)       ← set week direction

  Monday–Friday daily sessions:
    /naos-d-start → tasks → /naos-d-end

Friday afternoon
  /naos-w-review (@naos-review)   ← assess governance health
  → inputs feed next Monday's /naos-w-plan
```

Weekly prompts may include a `next_action` footer so carryover work becomes a visible next-week planning input rather than informal memory.

---

## When to Skip the Weekly Cadence

The weekly cadence adds most value when:
- The team is making multiple commits per day
- More than one developer is active on the project
- The project is in a critical phase (pre-release, feature freeze)

For very slow-moving projects (one commit per week), the weekly cadence may be overkill. Monthly cadence (`/naos-m-review`) may be sufficient.

---

## Integration with Monthly Cadence

The weekly review feeds the monthly review. Patterns that appear in weekly reviews (e.g., consistently skipping pre-commit, persistent test failures in the same module) are the raw material for the monthly governance audit.

→ [Micro Tutorial 21: Monthly Cadence](./MICRO_TUTORIAL_21_NAOS_M_CADENCE.md)

---

## Common Mistakes

**❌ Running `/naos-w-plan` on Wednesday instead of Monday**

Weekly planning works because it sets direction *before* the work starts, not mid-week. A Wednesday plan is a post-hoc rationalization of what you already did.

**❌ Skipping `/naos-w-review` when the week was "basically fine"**

"Basically fine" weeks often contain the seeds of future problems. The review is designed to surface leading indicators before they become incidents.

**❌ Using the weekly plan as a rigid schedule**

The daily breakdown is a guide, not a contract. Tasks move, blockers appear, priorities shift. Adjust the plan as needed — but always update `naos/PROJECT_STATUS.md` when you do.
