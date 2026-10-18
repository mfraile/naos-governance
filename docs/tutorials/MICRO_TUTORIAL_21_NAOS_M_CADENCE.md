# Micro Tutorial 21 — Monthly Cadence

> _Source-reviewed against the remediated candidate · 2026-10-18. See [verification scope](./README.md#verification-scope)._

> **Command**: `/naos-m-review`
> **Agent**: `@naos-review`
> **Cadence**: Monthly — end of each calendar month
> **Time**: 60–90 minutes

> **Availability**: Standard and Assured. Lite uses manual session/cadence
> notes in its integral tutorial; Quickstart has no lifecycle prompts.

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

This refreshes configured derived PM outputs from sources such as
`specs/03-requirements.md` and `naos/TASK_REGISTRY.yaml`. It does not compute
every metric below. For each metric, retain its definition, numerator,
denominator, period and executed data source; missing inputs remain unknown.

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

Review the available outputs; missing evidence remains unknown:

```bash
# Commits last 30 days
git log --oneline --since="30 days ago" | wc -l

# Local hook posture and self-reported commit-message mentions (portable CLI)
naos governance-bypass-posture --since-days 30 --json

# Test fix commits (quality indicator)
git log --oneline --since="30 days ago" | grep -i "fix test\|test fix" | wc -l
```

The posture report searches at most 200 local commit subjects across refs in the
selected time window. Read `scans.bypass_commit_message_inspection`; a read error
is unknown, not zero. Git does not record `--no-verify` use by default, and an
innocent message can mention bypassing. Retained local/CI results can establish
that particular checks ran; they cannot reconstruct past hook invocations.

**Key metrics to review**:

| Metric | Target | Concern Threshold |
|--------|--------|------------------|
| Velocity (commits/week) | Stable or improving | >40% drop |
| Self-reported hook-bypass message mentions | Review each mention | Unexplained mention; zero is not proof hooks ran |
| Test fix ratio | <10% of commits | >20% |
| Governance evidence/adherence rate | Improving | Any unexplained regression |
| FR/NFR delivery rate | On plan | Behind on critical FRs |

### Step 4: Lessons Learned Audit

This is the most important part of the monthly review. For each pattern identified:

1. **Identify the observed pattern**: "Three commit messages mention a hook bypass; inspect retained check output and ask the authors before inferring what occurred."
2. **Test a cause**: Reproduce a retained failure; do not infer its cause from a commit message.
3. **Review a remedy**: Decide whether generated files need different lint handling while retaining applicable checks.
4. **Validate an authorized fix**: Change only the reviewed rule or configuration and preserve before/after evidence.

The `naos-m-review` prompt includes a structured audit for:
- Retained pre-commit failures and self-reported bypass-message patterns
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

Record measured results in `naos/PROJECT_STATUS.md` under "Metrics Summary".
The numbers below are illustrative, not outputs produced by the commands above:

```markdown
## Metrics Summary (2026-03)
- Governance evidence/adherence: 82.4%
- Velocity: 47 commits (avg 11.75/week)
- Self-reported hook-bypass message mentions: 1 (not an observed bypass count or rate)
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

Establish your own configured project baseline with a documented calculation
and retained inputs. An example percentage is not a measured baseline or a
universal benchmark. Later operating evidence can test whether changes help.

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

- Authorized, validated rule changes can be used in the next workflow
- Retained metric inputs support trend tracking
- Unresolved findings and missing evidence carry forward visibly

For the next daily session:
→ [Micro Tutorial 10: naos-d-start](./MICRO_TUTORIAL_10_NAOS_D_START.md)

For the full methodology assessment:
→ [NAOS roadmap](../../ROADMAP.md) and [advisory compliance mapping](../COMPLIANCE_MAPPING.md)
