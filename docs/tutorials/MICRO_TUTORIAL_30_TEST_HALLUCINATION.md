# MICRO TUTORIAL 30 — Catching Test Hallucinations

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

When tests pass but verify the wrong thing — or worse, verify nothing real at all —
your green pipeline is lying to you. This micro tutorial walks through the
**test-AC reference validator** introduced in v0.9.2 (kit action A6) and the
discipline that detects declared test references for review. It does not prove test correctness or prevent every form of test hallucination.

---

## What is a "test hallucination"?

A test hallucination is a test that:

1. Looks structurally legitimate (has assertions, exercises real code paths).
2. References an Acceptance Criterion (`AC-103.2`) or Scenario (`SCEN-1.1`) **that does not exist** in `specs/06-acceptance.md`.
3. Therefore proves nothing about the spec it pretends to verify.

Most often this happens when an AI agent invents an AC ID to satisfy a
"every test must reference an AC" rule, when the developer renames an AC and
forgets to update the test, or when a test is copy-pasted from another task
without re-anchoring its references.

The validator catches all three failure modes at commit time.

NAOS also includes `naos test-quality-hygiene`, which is a separate
deterministic local report for weak test evidence such as missing assertions or
trivial assertions. Use both checks together when reviewing AI-generated tests:
AC/SCEN validation checks whether references exist, while test-quality hygiene
checks whether the test body contains meaningful assertion evidence. Neither
check proves behavioral correctness or test sufficiency.

---

## How the validator works

**Script**: `scripts/validators/validate_test_ac_references.py`

1. Walks `specs/` (configurable via `SPECS_ROOT`) and collects every `AC-X.Y` and
   `SCEN-X.Y` identifier defined in any `.md` file.
2. Walks `tests/` (configurable via `TESTS_ROOT`) — or, with `--staged`, only
   the tests staged for the current commit — and extracts every `AC-` /
   `SCEN-` identifier referenced inside test files.
3. Fails if any test reference is **not** in the defined set.

Recognised patterns:

| Convention | Example |
|---|---|
| Acceptance Criterion | `AC-103.2`, `AC-103.2.1` |
| Scenario | `SCEN-1.1`, `SCEN-S.1`, `SCEN-P.1` |

Test file globs: `test_*.py`, `*_test.py`, `*.spec.ts`, `*.test.ts`, `*.spec.js`.

---

## Pre-commit integration

In Standard and Assured profiles the validator runs as **gate 10c** of the
NAOS pre-commit hook. If a staged test references an undefined AC/SCEN, the
commit is blocked with an actionable message:

```
[FAIL] Test files reference AC/SCEN ids that are not defined in specs:
  tests/api/test_login.py: AC-777.7

Either (a) define the ids in specs/06-acceptance.md, or
       (b) remove the phantom AC/SCEN references from the tests.
```

Greenfield repos with no tests yet are unaffected — the validator silently
exits 0 when there's nothing to check.

---

## When to run it manually

```bash
# Full repo audit (CI, periodic sanity check)
python scripts/validators/validate_test_ac_references.py

# Only staged tests (what the pre-commit hook does)
python scripts/validators/validate_test_ac_references.py --staged

# Custom roots (monorepo, alternative layout)
SPECS_ROOT=apps/api/specs TESTS_ROOT=apps/api/tests \
  python scripts/validators/validate_test_ac_references.py
```

Exit codes: `0` = clean (or no-op), `1` = hallucination detected, `2` = reserved.

**No-op conditions** (silent success — never blocks a commit):

- No test files staged (or, in full mode, no test files anywhere yet).
- `specs/` directory missing entirely (greenfield repo before `naos init`).
- `specs/` exists but contains zero `AC-` / `SCEN-` identifiers (mid-onboarding,
  lite tier without `06-acceptance.md`, or template stubs only).

The gate only fires once you have **both** real tests and at least one defined
AC/SCEN id — i.e., once the discipline can actually be enforced.

---

## How to write tests that pass the validator

```python
# tests/api/test_login.py
"""
Implements: FR-101
Task: T-401
Specs: AC-101.1, AC-101.2
Rationale: Verify happy + unauthenticated paths for /login per spec.
"""

def test_login_happy_path():
    """Verifies AC-101.1: valid credentials return 200 + token."""
    ...

def test_login_unauthenticated():
    """Verifies AC-101.2: invalid credentials return 401."""
    ...
```

Both `AC-101.1` and `AC-101.2` must exist as headings (or anywhere) in
`specs/06-acceptance.md`. The validator does not parse or interpret the
referenced ACs — it only checks existence. Spec-content correctness is
out of scope (that's the job of `@naos-review`).

---

## Common mistakes

**❌ Inventing AC IDs to satisfy a rule.**
Asking the AI to "make the test reference an AC" without an actual spec is
how hallucinations enter the repo. The fix is upstream: write the AC in
`specs/06-acceptance.md` first, then write the test.

**❌ Renaming ACs without grep.**
If `AC-103.2` becomes `AC-103.2.1`, run
`grep -rE 'AC-103\.2\b' tests/` before committing the spec rename.

**❌ Copy-pasting tests across tasks.**
Always re-anchor the AC references in the new context. The validator will
catch you, but only at commit time.

**❌ Trying to bypass with `--no-verify`.**
The validator is the enforcement mechanism. `--no-verify` is reserved for
genuine emergencies and must be logged in the cognitive checkpoint.

---

## Relationship to other gates

- **Rule 16 (Spec Alignment)**: gate 9 validates that **source files** carry
  traceability headers. Gate 10c is the symmetric deterministic check for **test files**.
- **Rule 11 (Anti-Duplication)**: gate 8 (the kit's AST-based moat) is
  untouched by A6. Gate 10c only verifies AC/SCEN reference existence.
- **Rule 26 (PAUL brackets)**: if gate 10b blocks at the **CRITICAL** bracket,
  do not push through. Save a full checkpoint and yield to a fresh agent.

---

## What happens next

Once a clean commit lands, `@naos-review` and `@naos-conformance` can rely on
the assertion that every test/AC reference is real. This composes with the
D4 scenario metadata (kit action A4), which supports deterministic conformance
review today and Behavioral Governance Readiness; future behavioral evaluators
remain project-configured.

For a full picture of how the v0.9.2 changes interact, see:

- [MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md](MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md) — pre-commit overview, including the v0.9.1 cumulative-context monitor (gate 10b)
- [MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md](MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md) — dedicated guide to the `NAOS_CONTEXT_REMAINING_PCT` guard
- [templates/skills/cognitive-checkpoint/SKILL.md](../../templates/skills/cognitive-checkpoint/SKILL.md) — checkpoint template mirrored by Rule 26 PAUL bracket behavior
