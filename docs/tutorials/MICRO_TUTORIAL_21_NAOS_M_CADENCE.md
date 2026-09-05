# Micro Tutorial 21 — Monthly Cadence

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Command**: `/naos-m-review`
> **Agent**: `@naos-review`
> **Cadence**: Monthly — end of each calendar month
> **Time**: 60–90 minutes

---

## What the Monthly Cadence Does

The monthly cadence is the governance health audit. It operates at a level above weekly reviews:

- Measures governance evidence and adherence over the full month
- Surfaces systemic patterns (not just individual incidents)
- Updates governance rules when lessons have been learned but not yet encoded
- Reviews evidence and gaps that may indicate whether the NAOS framework is improving

The monthly review records candidate lessons and follow-up actions. It does not prove that updates improve enforcement; later operating evidence must test that outcome.

---

## The Agent: `@naos-review`

`@naos-review` handles both task-level and governance-level reviews. For monthly reviews, it operates in aggregate mode — looking at patterns across all tasks and commits for the month.

---

## Step-by-Step

### Step 1: Run governance refresh first

Before the monthly review, ensure metrics are current:

```bash
make -f Makefile.naos gov-refresh
```

This auto-computes all derived metrics from the authoritative sources (`specs/03-requirements.md`, `naos/TASK_REGISTRY.yaml`). **Never calculate governance metrics manually** — always read from the refreshed output.

### Step 2: Invoke the command

```
/naos-m-review

Month: 2026-03
```

Or:

```
@naos-review /naos-m-review 2026-03
```

### Step 3: Review the metrics output

The agent will gather:

```bash
# Commits last 30 days
git log --oneline --since="30 days ago" | wc -l

# Pre-commit bypasses (governance concern)
git log --oneline --since="30 days ago" | grep -i "no-verify\|skip" | wc -l

# Test fix commits (quality indicator)
git log --oneline --since="30 days ago" | grep -i "fix test\|test fix" | wc -l
```

**Key metrics to review**:

| Metric | Target | Concern Threshold |
|--------|--------|------------------|
| Velocity (commits/week) | Stable or improving | >40% drop |
| Pre-commit bypass rate | 0% | >5% |
| Test fix ratio | <10% of commits | >20% |
| Governance evidence/adherence rate | Improving | Any unexplained regression |
| FR/NFR delivery rate | On plan | Behind on critical FRs |

### Step 4: Lessons Learned Audit

This is the most important part of the monthly review. For each pattern identified:

1. **Identify the pattern**: "We bypassed pre-commit 3 times this month because of the lint rule for generated files."
2. **Root cause**: "The lint rule doesn't exclude the `generated/` directory."
3. **Action**: Update the governance rule to exclude `generated/`.
4. **Encode the fix**: Update `.ai/RULES.md` or the pre-commit hook configuration.

The `naos-m-review` prompt includes a structured audit for:
- Pre-commit failures and bypass patterns
- Test failures and rework patterns
- Scope creep incidents
- Documentation debt accumulation
- Traceability gaps

### Step 5: Update governance artifacts

Based on the lessons learned audit, update:

1. **`naos/governance/PROJECT_GOVERNANCE_RULES.md`**: Add or update rules
2. **`naos/PROJECT_STATUS.md`**: Update metrics summary, risk register
3. **`CHANGELOG.md`**: Add monthly summary under `[Unreleased]`

### Step 6: Refresh and record the governance evidence posture

NAOS can report governance evidence posture through deterministic readiness
reports, the evidence pack, and the dashboard. Treat these as internal review
signals, not legal or regulatory conclusions.

```bash
naos evidence-pack --profile <profile>
naos dashboard --profile <profile> --json
```

Record the result in `naos/PROJECT_STATUS.md` under "Metrics Summary":

```markdown
## Metrics Summary (2026-03)
- Governance evidence/adherence: 82.4%
- Velocity: 47 commits (avg 11.75/week)
- Pre-commit bypass rate: 2.1% (1 bypass)
- Test fix ratio: 8.5%
```

### Step 7: Plan next month

Based on the review, produce next month's governance priorities:

- Which rules need strengthening?
- Which metrics need attention?
- Which FRs are at risk of slipping?
- What tooling improvements would help?

---

## The Governance Improvement Loop

```
Monthly Review
  │
  ├─ Metrics collected
  ├─ Lessons learned identified
  ├─ Rules updated
  └─ Next month targeted

        ↓ feeds

Weekly Reviews
  │
  └─ Weekly patterns feed monthly audit

        ↓ feeds

Daily Sessions
  │
  └─ Daily governance decisions feed weekly reviews
```

---

## Governance Evidence Metric — Context

NAOS has published an evidence/adherence baseline from one configured codebase. Treat that as bounded evidence, not a universal benchmark. The monthly review is the mechanism for improving your own project baseline over time.

The metric is not a judgment or a legal/regulatory conclusion; it is a measurement. A score below 100% means some configured governance evidence is missing, stale, waived, or not yet satisfied. The monthly review identifies the gap and drives the next improvement cycle.

**Target trajectory**: Not "reach 100% and stop", but "measure accurately, improve consistently, and be able to explain any deviation."

---

## Common Mistakes

**❌ Running the monthly review without running `make -f Makefile.naos gov-refresh` first**

Stale metrics will produce incorrect trend analysis.

**❌ Identifying lessons learned but not encoding them as rule changes**

A lesson learned that doesn't change behavior is just a note. The value is in encoding the lesson as a governance rule.

**❌ Treating an evidence regression as a crisis**

An evidence regression is information. Investigate the cause, encode the fix, and continue. NAOS is designed to improve over time, not to be perfect on day one.

---

## What Happens Next

After the monthly review:

- Updated rules are active for next month's daily workflow
- Metrics baseline is established for trend tracking
- Next month begins with a clean governance status

For the next daily session:
→ [Micro Tutorial 10: naos-d-start](./MICRO_TUTORIAL_10_NAOS_D_START.md)

For the full methodology assessment:
→ [NAOS roadmap](../../ROADMAP.md) and [advisory compliance mapping](../COMPLIANCE_MAPPING.md)
