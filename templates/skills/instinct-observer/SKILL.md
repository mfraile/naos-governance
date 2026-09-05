---
name: "instinct-observer"
description: "Record, review, and promote recurring behavioural instincts. Invoke when a pattern recurs, after compaction recovery, or after a behavioral drift signal."
parameters: []
---

# SKILL: instinct-observer
# Purpose: Record, review, and promote behavioural instincts (3-tier learning system)
# Invoke: when a behavioural pattern recurs ≥3 times, after a compaction recovery, or after a behavioral drift signal fires unexpected results

---

## Quick Start

1. Confirm this is a recurring pattern, compaction recovery signal, or drift
   signal rather than a one-off mistake.
2. Search existing instinct files before creating a new `INS-NNN.yaml`.
3. Create or update the instinct with evidence count, dates, source sessions,
   confidence, and mitigation.
4. Never promote an instinct to user memory, kit behavior, or a rule without
   explicit human sign-off.

## When to Invoke This Skill

Call `instinct-observer` when you notice ANY of the following:

- A pattern you've seen **before in this session or a prior one** appears again
- A **behavioral drift alert** fired and you're diagnosing whether it's a real regression or noise
- A **compaction** just happened and you're recovering context
- A **known anti-pattern** (from mem_context, session summary, compact file, or task card) recurs
- A **Rule in RULES.md** turns out to be insufficient and you find yourself inventing a workaround

---

## Step-by-Step: Recording an Instinct

### Step 1 — Check if instinct already exists
```bash
ls .github/instincts/INS-*.yaml
grep -r "title:" .github/instincts/INS-*.yaml | grep -i "<keyword>"
```
If a matching instinct exists: **update `evidence_count` and `last_confirmed`** (do NOT create a duplicate).

### Step 2 — Assign ID
Next ID = highest existing N + 1. If `.github/instincts/` has INS-001 through INS-003, new instinct is INS-004.

### Step 3 — Create the file
```
.github/instincts/INS-NNN.yaml
```
Use `schema.yaml` fields. Required: `id`, `title`, `tier`, `observed_pattern`, `context`, `mitigation`, `evidence_count`, `first_observed`, `last_confirmed`, `source_sessions`.

### Step 4 — Compute confidence
```
confidence = min(evidence_count / 10, 1.0)
```

### Step 5 — Persist the observation

If Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, save the observation there:

```
mem_save(
  title="Recorded instinct INS-NNN: <title>",
  type="pattern",
  content="<brief summary of what was observed and mitigation>"
)
```

If memory is deferred or disabled in `configs/naos_memory.yaml`, add the same summary to the active compact/task card and mark it as degraded recovery evidence. Do not skip persistence just because Engram is unavailable.

---

## Step-by-Step: Updating an Existing Instinct

When the same pattern recurs in a new session:

1. Read the existing `INS-NNN.yaml`
2. Increment `evidence_count` by 1
3. Update `last_confirmed` to today's date
4. Append the new session ID to `source_sessions`
5. Recalculate `confidence`
6. Check promotion gates (see below)

---

## Promotion Gates

### Tier 1 → Tier 2 (user-scoped memory)
- `evidence_count ≥ 5`
- Confirmed in ≥ 2 **independent** sessions (not the same day)
- Action: record in approved user-scoped memory, preferably local-first Engram under `ENGRAM_DATA_DIR`; replication remains local/off unless separately reviewed
- **NEVER auto-promote** — requires explicit human sign-off ("promote this instinct")

### Tier 2 → Tier 3 (NAOS kit universal)
- `evidence_count ≥ 10`
- Observed across ≥ 2 different projects
- Action: submit to NAOS portable kit repo

### Tier 1/2 → Rule
- `evidence_count ≥ 10`
- Strong consensus + testable via scenario
- Action:
  1. Append Rule N to `.ai/RULES.md` (next available number)
  2. Add scenario to `.github/autoresearch/task_battery/core_scenarios.yaml`
  3. Set `promoted_to_rule: "Rule-NN"` in the INS file
  4. Set `status: promoted` (optional field)
  - **NEVER auto-promote** — requires explicit human sign-off

---

## What NOT to Do

- **Do NOT** create an instinct for a one-off mistake (evidence_count must reach ≥3 before creating)
- **Do NOT** auto-promote to Rule without human approval
- **Do NOT** store PII, credentials, or customer data in instinct files
- **Do NOT** duplicate existing RULES.md rules — if it's already a rule, the instinct is redundant
- **Do NOT** dismiss an instinct without documenting why (`dismissed: true` + `dismissal_reason`)

---

## Quick Reference

| Situation | Action |
|-----------|--------|
| Pattern seen for 1st or 2nd time | Note in Engram via mem_save only when configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use; otherwise record in compact/task card. Do NOT create an instinct file yet |
| Pattern confirmed 3rd time | Create INS-NNN.yaml with evidence_count: 3 |
| Pattern confirmed 4th+ time | Update existing INS file (increment evidence_count) |
| evidence_count reaches 5, 2+ sessions | Propose Tier 2 promotion to user |
| evidence_count reaches 10, 2+ projects | Propose Tier 3 or Rule promotion to user |
| Behavioral drift fires ALERT | Check INS-002 first (N=1 false positive); if not, create/update instinct |
| Compaction just happened | Check INS-003; confirm 3-step recovery was followed |

---

## Files This Skill Touches

- `.github/instincts/INS-NNN.yaml` — instinct files (primary)
- `.github/instincts/schema.yaml` — format reference (read-only)
- Approved user-scoped memory, preferably local-first Engram under `ENGRAM_DATA_DIR` — Tier 2 instincts (after promotion); replication remains local/off unless separately reviewed
- `.ai/RULES.md` — when instinct graduates to Rule
- `.github/autoresearch/task_battery/core_scenarios.yaml` — when Rule needs scenario
- Engram (`mem_save`) — for every new or updated instinct only when memory write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use; otherwise use compact/task-card degraded evidence
