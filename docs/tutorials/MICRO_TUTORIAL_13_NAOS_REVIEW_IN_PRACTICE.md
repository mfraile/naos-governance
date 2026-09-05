# Micro Tutorial 13 — Review in Practice

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-08-29_

> **Agent**: `@naos-review`
> **Cadence**: After implementation, before task completion
> **Time**: 10–20 minutes per task

---

## What This Agent Does

`@naos-review` is governance review guidance. It runs three ordered perspectives
inside one read-only role and reports each separately before synthesis.

While `@naos-implement` focuses on implementation, `@naos-review` helps assess whether the intended change was built; its output is not proof or approval.

---

## What `@naos-review` Checks

### Lens 1 — Independent Goal/Diff And Scope

Does the exact change serve the supplied goal without inheriting the
implementer's conclusion?

- Reads the active task, explicit constraints, and exact changed paths
- Maps every changed path back to the goal and flags unscoped work
- Checks applicable parallel-lane posture and, for changed UI with enabled
  evidence declarations, runs or reviews `naos design-traceability` and/or
  `naos ui-experience-quality` without treating either as design approval, UI
  quality proof, accessibility certification, brand approval, or compliance proof

### Lens 2 — Edge Cases, Coverage, And Systemic Propagation

What actual consuming paths, boundaries, negative cases, and dependent surfaces
could the change have missed?

- Checks new functions against the existing function index and source search
- Uses `naos duplicate-function-hygiene` when deterministic duplicate-body
  evidence is useful
- Traces source, configuration, schemas, tests, generated/adopter surfaces,
  documentation, and directly affected governance evidence
- Preserves uncertainty, counterarguments, falsifiers, and residual risk
- Reviews code quality, security, architecture, remediation safety, and required
  documentation without treating advisory evidence as proof

### Lens 3 — Acceptance-Criteria And Spec Evidence

Was the required resulting state actually demonstrated?

- Maps every explicit AC/spec obligation to deliverables, tests, and evidence
- Requires tests to assert material behavior or resulting state, not only AC IDs,
  bookkeeping rows, or successful commands
- Records missing evidence and conscious deferrals instead of inventing completion

The final synthesis deduplicates the three reports, places blocking findings
first, and returns an advisory recommendation. Deterministic checks and executed
evidence outrank model judgement; a named human retains merge authority.

---

## When to Use `@naos-review`

- **After `@naos-implement` completes** and before running `/naos-task-complete`
- **When you are unsure** whether the implementation is spec-aligned
- **Before a PR** — catch governance violations before they become review comments
- **When a reviewer requests changes** — use `@naos-review` to validate the fix

---

## Step-by-Step

### Step 1: Confirm implementation is complete

Before review:
- [ ] All code for the task is written
- [ ] Tests pass locally
- [ ] Pre-commit hook has passed

### Step 2: Invoke the agent

```
@naos-review Review the implementation of T-202
```

Or with explicit context:

```
@naos-review Review the implementation of T-202 against:
- AC-202.1: User authentication endpoint validates credentials
- AC-202.2: Returns 401 on invalid credentials, 200 + JWT on success
- Schema constraint: users table — no new columns added
```

### Step 3: Review the output sections

`@naos-review` produces a structured output:

**Lens 1 — Goal/Diff And Scope**
- Goal-to-path mapping, drift, and authority issues

**Lens 2 — Edge/Coverage And Propagation**
- Actual consumers, edge cases, systemic obligations, and residual risks

**Lens 3 — AC/Spec Evidence**
- AC/spec-to-result/test/evidence mapping and explicit gaps

**Synthesis**
- Deduplicated blocking findings first, approved observations, uncertainty, and
  `READY_FOR_ATTRIBUTABLE_HUMAN_MERGE_DECISION`, `NEEDS_CHANGES`, or `BLOCKED`

### Step 4: Act on the findings

For each finding:

- **✅ Satisfied**: No action needed
- **⚠️ Partial**: Discuss with the team — may be an acceptable scope decision or may require additional work
- **❌ Not satisfied**: Return to `@naos-implement` to address
- **Duplicate detected**: Use existing code; do not commit the duplicate
- **Documentation needed**: Update before running `/naos-task-complete`

### Step 5: Re-run review after fixes

If you made changes based on review findings, re-run:

```
@naos-review Re-review T-202 after the fixes above
```

---

## Accepting and Documenting the Review

Once the review is clean:

1. Record `READY_FOR_ATTRIBUTABLE_HUMAN_MERGE_DECISION` or the applicable
   `NEEDS_CHANGES`/`BLOCKED` status under "Review Notes".
2. Treat readiness as evidence for a named human decision-maker, not approval
   or authorization to merge, release, admit evidence, close an exception, or
   close the task.
3. Mark the review checklist items in the story card.
4. Record any actual human decision separately under `naos/human_decisions/`.
5. Proceed to native task completion when its lifecycle and verification
   preconditions are satisfied.

---

## Common Mistakes

**❌ Skipping review and going straight to `/naos-task-complete`**

Task completion (`@naos-conformance`) requests its own checks, but those are
coarser. `@naos-review` is detailed pre-completion review guidance, not an
enforcement gate. Skipping it may leave more findings for later review.

**❌ Using `@naos-review` to review code that isn't yours**

`@naos-review` is designed to review code against an active task's story card. Reviewing arbitrary code without a task context will produce lower-quality output.

**❌ Treating the three lenses as proof of better model behavior**

The ordered contract is deterministically present in the installed role, but
instruction presence does not prove that a model follows it or finds every
defect. Preserve missed findings, host/model limits, and human review.

**❌ Treating duplicate-intent findings as automatic rewrite approval**

Some overlap is expected and acceptable — utility functions, patterns, boilerplate. Read the evidence and recommendations carefully. Risky remediation still needs human/profile-based approval, especially for security, database, public API, or regulatory-control code.

---

## Weekly and Monthly Review

The `@naos-review` agent is also used for cadence reviews:

- `/naos-w-review` — end-of-week governance review
- `/naos-m-review` — monthly governance metrics review

See [Micro Tutorial 20: Weekly Cadence](./MICRO_TUTORIAL_20_NAOS_W_CADENCE.md) and [Micro Tutorial 21: Monthly Cadence](./MICRO_TUTORIAL_21_NAOS_M_CADENCE.md).

---

## What Happens Next

After a clean review:

→ [Micro Tutorial 14: naos-task-complete with Conformance](./MICRO_TUTORIAL_14_NAOS_TASK_COMPLETE_WITH_CONFORMANCE.md)
