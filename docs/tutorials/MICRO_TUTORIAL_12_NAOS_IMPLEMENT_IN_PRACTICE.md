# Micro Tutorial 12 — Implement in Practice

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Agent**: `@naos-implement`
> **Cadence**: Throughout every coding session, after task start
> **Time**: Variable — the bulk of your development work happens here

---

## What This Agent Does

`@naos-implement` is the hands-on development agent. Its prompt refers to the
story card created or reviewed during `/naos-task-start` and the context
requested and checked during `/naos-d-start`.

Unlike a general-purpose coding agent, `@naos-implement` carries governance-aware
instructions. It is instructed to:

- Write code that stays within the declared task scope
- Use existing functions identified in the story card (Rule 17: no duplication)
- Respect the schemas documented in the story card
- Add traceability headers to new files
- Prompt for pre-commit validation before committing

These are instruction expectations, not proof of host/model behavior. Review the
diff, tests, and repository evidence before accepting the result.

---

## When to Use `@naos-implement`

Use `@naos-implement` for:

- **Writing new code** — features, functions, classes
- **Writing tests** — unit, integration, acceptance
- **Bounded fixes** — bug fixes scoped to the current task
- **Refactoring** — within the declared scope
- **Configuration changes** — defined in the story card

Do **not** use `@naos-implement` for:
- Starting a session (use `/naos-d-start` → `@naos-plan`)
- Starting a task (use `/naos-task-start` → `@naos-plan` or `@naos-triage`)
- Reviewing work (use `@naos-review`)
- Completing a task (use `/naos-task-complete` → `@naos-conformance`)

---

## Step-by-Step

### Step 1: Confirm prerequisites

Before using `@naos-implement`:

- [x] `/naos-d-start` has run this session
- [x] `/naos-task-start T-XXX` has run and story card is open
- [x] Pre-coding checklist in story card is complete

### Step 2: Invoke the agent

```
@naos-implement [describe what you want to build]
```

Example:
```
@naos-implement Add the user authentication endpoint per AC-202.1 —
use the UserRepository from src/repositories/user_repository.py (already in story card)
```

### Step 3: Reference the story card explicitly

For important constraints, paste them into the prompt:

```
@naos-implement Implement the payment processor integration.

Constraints from story card T-205:
- Use existing PaymentGateway class in src/payments/gateway.py
- Schema: payments table — columns: id, user_id, amount, status, created_at
- Do NOT add new columns
- AC-205.1: Must validate amount > 0 before calling gateway
```

If the story card records `parallel_lane_decision: declared`, also paste the
lane boundary: lane id, task/FR/NFR refs, planned paths, out-of-scope paths,
dependencies, expected tests/checks, and handoff expectation. Suggested
postures such as `parallel_possible` or `parallel_recommended` are not active
lanes. They should be treated as planning notes until a human/project decision
records `declared`.

### Step 4: Review each implementation before accepting

Before accepting code from `@naos-implement`:

**Governance checklist**:
- [ ] Code uses existing functions (not duplicating them)
- [ ] Code respects the declared schema (no schema drift)
- [ ] New files have traceability headers
- [ ] Tests are included for new logic
- [ ] No scope creep — only what the story card defines

### Step 5: Pre-commit validation

Before committing, run the pre-commit hook:

```bash
git add [files]
# An explicitly activated Git hook runs on git commit
git commit -m "feat(T-202): implement user auth endpoint (AC-202.1)"
```

If no hook is activated, this command runs no NAOS pre-commit control. If an
activated hook rejects the commit, read the output and fix the finding before proceeding.

For complex changes, use the AI-assisted pre-commit review:
```
/naos-t-precommit
```

> **Cumulative-context monitor (v0.9.1+).** The Standard/Assured pre-commit hook reads the caller-supplied `NAOS_CONTEXT_REMAINING_PCT`. It warns at the **DEEP** PAUL bracket (<35%) and rejects that commit attempt at **CRITICAL** (<25%). The check is a no-op when the variable is unset. It does not measure remaining context or verify a checkpoint. See Rule 26 in the selected profile's `RULES.md`, the `cognitive-checkpoint` skill template, and [MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md](MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md).

> **Rule 18 budget boundary.** The ≤400L cumulative-instruction budget is documented posture, not a measured hook gate. `NAOS_CONTEXT_REMAINING_PCT` is a separate self-declared percentage and cannot prove how many instruction lines co-fired. To right-size your loadout, split monolithic instruction files into scoped `.instructions.md` files with tight `applyTo` globs (≤100L each), and prefer references over inlining.

---

## Traceability Headers

All new source files must include a traceability header under this workflow. `@naos-implement` is instructed to propose one, but host/model behavior is not guaranteed; verify or add it explicitly:

```python
# NAOS Traceability
# Task: T-202
# Requirement: FR-15
# Spec: specs/03-requirements.md L145
```

Or for other languages:

```javascript
// NAOS Traceability
// Task: T-202
// Requirement: FR-15
```

---

## Handling Test Failures During Implementation

If a test fails during implementation:

```
/naos-t-test-failure
```

This triggers the structured test failure investigation: root cause analysis, blast radius, fix plan. Do not use `@naos-implement` to blindly fix a failing test without understanding why it failed.

---

## Scope Discipline

`@naos-implement` is instructed to preserve scope, but it is not an enforcement boundary or gatekeeper. It may still act outside the card if prompted or if context is incomplete.

**Your responsibility**: keep the session scoped to the story card. If you discover work that needs to be done but is outside the current task, note it in the story card under "Discovered Work" and create a new task in the registry — do not implement it now.

For declared lanes, keep changed files inside the lane's planned paths and
record tests/checks as you go. At lane completion, block, or review handoff,
fill `naos/lane_handoffs/_TEMPLATE.yaml`, run
`python scripts/naos_parallel_lane_handoff.py --handoff naos/lane_handoffs/<lane>.yaml`,
then run `naos control-plane-review`. This produces local review evidence only;
it does not approve, merge, close, dispatch, release, certify, attest, or prove
compliance.

---

## Common Mistakes

**❌ Using `@naos-implement` without a story card**

Without the story card, the agent has no schema constraints, no list of existing code to use, and no acceptance criteria. This is the configuration most likely to produce Rule 17 violations (duplicate code).

**❌ Accepting code without reviewing the governance checklist**

The agent produces correct code most of the time. But "most of the time" is not a governance standard. Review each implementation output.

**❌ Committing without running the pre-commit hook**

The pre-commit hook is one executable layer for its implemented predicates, not an enforcement mechanism for every RULES row. Bypassing an activated hook with `--no-verify` should follow the project's explicit exception process and be recorded.

---

## What Happens Next

After implementation is complete and tests pass:

→ [Micro Tutorial 13: Review in Practice](./MICRO_TUTORIAL_13_NAOS_REVIEW_IN_PRACTICE.md)
