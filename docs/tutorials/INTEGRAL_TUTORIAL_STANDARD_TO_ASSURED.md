# Integral Tutorial — Standard to Assured Managed Upgrade

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-08-24_

> **From profile**: `standard`
> **To profile**: `assured`
> **Effort basis**: Repository-specific; record review, remediation, apply, recovery, and validation time from the actual transition
> **Goal**: Assess a running `standard` installation, review an immutable content-aware `assured` plan, and apply that exact digest without overwriting adopter-owned content.

---

## What the Assured Target Changes

The `assured` profile differs from `standard` by strengthening evidence expectations, exception visibility, and blocking behavior where configured by profile policy.

In `standard`, missing evidence is usually reported as required and can be made strict. In `assured`, configured gates may block until evidence, remediation, or an approved waiver is present.

Additionally:

- `@naos-conformance` should run with the strictest configured project posture on task close
- security and architecture instruction surfaces become more explicit
- evidence-pack, exception, waiver, and residual-risk visibility become more important
- dashboard and validator outputs support audit/admissibility discussions without proving legal compliance

---

## Prerequisites

- Running `standard` installation (see [Integral Tutorial: Standard from Scratch](./INTEGRAL_TUTORIAL_STANDARD_FROM_SCRATCH.md))
- Team is familiar and comfortable with the `standard` workflow
- A current `standard` evidence baseline from representative project work

Do not select `assured` until its stronger evidence and review expectations fit
the project. Profiles are purpose-fit choices, not a mandatory maturity ladder.

---

## Part 1: Pre-Transition Readiness Assessment

Before previewing the target posture, assess your current governance evidence baseline.

### Step 1: Run the current governance audit

```bash
make -f Makefile.naos gov-refresh
naos claims --profile standard
naos setup-recommendations --profile standard
naos add setup-module --recommended --profile assured --dry-run
naos memory-readiness --profile standard
naos memory-access --profile standard
naos memory-use-policy --profile standard
naos context-index --profile standard
naos context-query --query "governance" --profile standard
naos semantic-candidates --profile standard
naos graph-context --profile standard
naos graph-query --task T-001 --profile standard
naos session-start --task T-001 --profile standard
naos evidence-attestation --profile standard
naos capability-maturity --profile standard
naos systemic-impact --profile standard
naos module-headers --profile standard
naos spec-pack-contract --profile standard
naos spec-pack-materialize . --profile standard --dry-run
naos spec-assembly-worksheet . --profile standard
naos spec-cascade --profile standard
naos control-plane-review --profile standard
naos self-check --profile standard
naos duplicate-function-hygiene --profile standard
naos secret-hygiene --profile standard
naos test-quality-hygiene --profile standard
naos dependency-integrity --profile standard
naos package-reality --profile standard
naos api-symbol-reality --profile standard
naos gate-status --profile standard
naos gate-evaluate --profile standard
naos evidence-pack --profile standard
naos dashboard --profile standard --json
```

Record the output. You want to know:
- Current dashboard/evidence posture
- Which checks currently produce warnings or required_missing findings
- Which non-blocking findings would become blocking under your project policy

### Step 2: Review warning and required_missing findings

Check current project policy and rules for warning-level or required-missing findings that would block in `assured`:

```bash
# Check the governance rules file for current warning-level rules
grep -A3 "blocking: false" .ai/RULES.md
```

For each warning-level rule:
- How many violations in the last 30 days?
- Are they systemic or one-off?
- Will fixing them require code changes or only workflow changes?

If any finding has a high violation rate, **fix or explicitly waive it before
considering a future transition**. If a separately reviewed transition is later
implemented and applied, unresolved findings may become immediate blocks.

### Step 3: Fix outstanding violations

For each warning-level rule with violations:

```
@naos-implement Fix violations of [rule] — list them from the latest NAOS readiness reports
```

Commit the fixes:

```bash
git commit -m "fix(governance): address pre-assured transition findings"
```

Re-run the audit and verify the warning count is at or near zero.

---

## Part 2: Plan, Review, and Apply the Managed Transition

### Step 1: Persist the immutable no-write plan

```bash
naos-governance upgrade . --tier assured --plan-out /tmp/naos-assured-plan.json
```

This command:
- generates profile-target files in an external temporary directory;
- classifies the complete managed inventory from recorded base/current/new identities;
- records each ownership, preservation, and mutation decision;
- atomically creates the absent external plan file;
- removes the temporary preview afterward; and
- writes nothing to the adopter project.

Normal planning without `--dry-run` and explicit `--dry-run` have the same
plan-only semantics. Neither invocation applies the transition. Every legacy
`--force` request is refused.

### Step 2: Review the plan and copy its exact digest

Review every preservation and mutation decision in
`/tmp/naos-assured-plan.json`. Only unchanged `kit_owned_derived` regular files
may be replaced. Adopter-owned, modified, ambiguous, unsafe, and out-of-scope
paths must remain preserved. Record the exact lowercase `plan_sha256` value.

Do not substitute `naos init --activate`: on a valid managed project it routes
to this same plan-only workflow and cannot bypass separate apply.

### Step 3: Apply only the reviewed digest

```bash
naos-governance upgrade . \
  --apply-plan /tmp/naos-assured-plan.json \
  --expect-plan-digest PLAN_DIGEST
```

Apply never replans. It reloads the immutable plan, regenerates its fixed
sources, revalidates provenance and current state, and commits eligible changes
through the managed journal and transaction service. If the process is
interrupted, run:

```bash
naos-governance upgrade . --recover
```

### Step 4: Evaluate the applied target posture

```bash
naos self-check --profile assured --json
naos setup-recommendations --profile assured --json
naos memory-readiness --profile assured --json
naos memory-access --profile assured --json
naos memory-use-policy --profile assured --json
naos task-context --task T-001 --profile assured --json
naos context-index --profile assured --json
naos context-query --query "governance" --profile assured --json
naos semantic-candidates --profile assured --json
naos graph-context --profile assured --json
naos graph-query --task T-001 --profile assured --json
naos evidence-attestation --profile assured --json
naos duplicate-function-hygiene --profile assured --json
naos secret-hygiene --profile assured --json
naos test-quality-hygiene --profile assured --json
naos dependency-integrity --profile assured --json
naos package-reality --profile assured --json
naos api-symbol-reality --profile assured --json
naos gate-status --profile assured --json
naos evidence-pack --profile assured --json
naos dashboard --profile assured --json
```

These commands evaluate the current repository using an `assured` profile
argument. They do not replace the successful upgrade receipt or prove that
project-specific governance content is complete. Continue only after the exact
transition reports an applied or already-applied result.

---

## Part 3: First Assured Session After a Successful Transition

### The generated-hook boundary

The shipped generated hook warns on a missing traceability header in both
Standard and Assured. It does not change that predicate into a profile-specific
commit rejection:

```
⚠️  WARNING: Traceability header missing in src/utils/helpers.py
    (non-blocking — commit allowed)
```

A separately configured module-header report or gate may block for Assured only
when that consumer is installed, its capability maturity and policy transition
resolve to `enforce`, and it is wired into the relevant commit or CI path.
Profile selection alone is not that wiring evidence.

### Session start

```
/naos-d-start

Today I'm working on: first session on assured profile — T-002 session expiry
```

`@naos-plan` should load the actually installed assured-profile context and
report the configured blocking posture. A command-line `--profile assured`
argument alone is not installation evidence.

### Task start

```
/naos-task-start T-002
```

The task-start guidance is the same. The generated hook's traceability-header
behavior does not differ merely because the selected profile name changed.

### Implementation

```
@naos-implement Implement JWT token expiry enforcement per AC-1.3
```

When committing:

```bash
git add src/auth/middleware.py tests/test_auth_expiry.py
git commit -m "feat(T-002): enforce JWT expiry (AC-1.3)"
```

If a separately installed and configured commit or CI gate blocks, read its
evidence and follow the adopter's approved remediation or waiver process. The
shipped hook alone emits a warning for this traceability-header case.

### Task completion

Task completion guidance in `assured` asks `@naos-conformance` to review the
configured strict posture:

```
/naos-task-complete T-002
```

`@naos-conformance` should surface completion blockers where configured, including:
- Any acceptance criterion is not verified
- Any checklist item is unchecked
- Any governance rule violation is outstanding
- TASK_REGISTRY.yaml is not updated

Fix findings, document an approved waiver, or record residual risk before the story card is archived.

---

## Part 4: Handling the Stronger Evidence Period

After a real transition, `assured` may surface findings that `standard` reported
as warnings or `required_missing`, depending on configured policy, capability
maturity, and enforcement transition. Plan for review rather than assuming a
fixed outcome.

### Common early assured blockers

**Missing traceability headers in older files**

Files written before NAOS was installed may not have traceability headers. When you touch these files in a task, add the header:

```python
# NAOS Traceability
# Task: T-XXX (retroactive)
# Requirement: [FR or "legacy code"]
```

**Documentation not updated**

`assured` mode may enforce documentation impact where configured. If you add a feature, update the CHANGELOG or document why it is not applicable.

**Test coverage gaps**

If a rule requires source-specific test evidence and you have files with no tests, the project may block. Prioritize adding tests or documenting evidence gaps for files you are actively modifying.

### How to manage the post-transition period

1. Track every new type of block in `naos/PROJECT_STATUS.md` under "Assured Transition Notes"
2. For systemic blocks (same rule hitting many files), create a dedicated cleanup task in the registry
3. Do not disable rules just to reduce friction; if a rule is inappropriate, record the rationale, waiver, or policy change

---

## Part 5: Measuring the Assured Baseline

After representative project work on `assured`:

```bash
make -f Makefile.naos gov-refresh
naos memory-readiness --profile assured
naos memory-access --profile assured
naos memory-use-policy --profile assured
naos context-index --profile assured
naos context-query --query "governance" --profile assured
naos semantic-candidates --profile assured
naos graph-context --profile assured
naos graph-query --task T-001 --profile assured
naos evidence-attestation --profile assured
naos evidence-pack --profile assured
naos dashboard --profile assured --json
```

Compare to your pre-transition baseline. Depending on project configuration,
you may see:
- Higher rule adherence (blocks caught things that warnings didn't)
- Possibly lower evidence/adherence percentage initially (findings now counted that were previously warnings)
- Improving trend as violations are resolved

Record the assured evidence baseline in `naos/PROJECT_STATUS.md`.

---

## Comparing Evidence Posture

No universal percentage trajectory applies across Quickstart, Lite, Standard,
and Assured. Profiles are purpose-fit configurations, not maturity scores. Your
actual evidence posture depends on project readiness, selected controls,
configured consumers, unresolved findings, waivers, and reviewed repository
evidence.

The path to stronger evidence maturity requires:
- Consistent use of all cadence rituals
- Zero `--no-verify` bypasses
- Active lessons-learned encoding in monthly reviews
- Traceability headers, spec-pack contract, spec-cascade coherence, and source-to-test evidence where applicable

---

## What You Would Have After a Separately Applied Transition

| Capability | Status |
|-----------|--------|
| Strongest evidence profile | Configured |
| Blocking gates | Enabled where project policy configures them |
| Conformance audit on task close | Strict where configured |
| Security/architecture instruction set | Stronger guidance |
| Evidence pack and waiver visibility | Configured where reports exist |
| Governance evidence measurement | Configured where reports exist |

---

## What to Do Next

→ [Micro Tutorial 21: Monthly Cadence](./MICRO_TUTORIAL_21_NAOS_M_CADENCE.md) — the monthly review is particularly important in `assured` mode for tracking governance evidence and residual risk.

→ [NAOS compliance mapping](../COMPLIANCE_MAPPING.md) — if you want to understand the public advisory mapping between NAOS evidence and external governance frameworks. This mapping supports review; it does not prove legal or regulatory compliance.
