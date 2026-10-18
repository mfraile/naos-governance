# MICRO TUTORIAL 30 — Catching Test Hallucinations

> _Source-reviewed against the remediated candidate · 2026-10-18. See [verification scope](./README.md#verification-scope)._

When tests pass but verify the wrong thing — or worse, verify nothing real at all —
your green pipeline is lying to you. This micro tutorial walks through the
**test-AC reference validator** introduced in v0.9.2 (kit action A6) and the
discipline that detects declared test references for review. It does not prove test correctness or prevent every form of test hallucination.

---

## What is a "test hallucination"?

A test hallucination is a test that:

1. Looks structurally legitimate (has assertions, exercises real code paths).
2. References an Acceptance Criterion (`AC-103.2`) or Scenario (`SCEN-1.1`) **that does not exist** in the Markdown files under `specs/`.
3. Therefore proves nothing about the spec it pretends to verify.

Most often this happens when an AI agent invents an AC ID to satisfy a
"every test must reference an AC" rule, when the developer renames an AC and
forgets to update the test, or when a test is copy-pasted from another task
without re-anchoring its references.

With an activated Standard/Assured hook and applicable inputs, the validator
can reject recognized references absent from the captured spec snapshot. It
cannot tell whether an existing ID describes the behavior a test should prove.

NAOS also includes `naos test-quality-hygiene`, which is a separate
deterministic local report for weak test evidence such as missing assertions or
trivial assertions. Use both checks together when reviewing AI-generated tests:
AC/SCEN validation checks whether references exist, while test-quality hygiene
checks whether the test body contains meaningful assertion evidence. Neither
check proves behavioral correctness or test sufficiency.

---

## How the validator works

**Script**: `scripts/validators/validate_test_ac_references.py`

1. Collects recognized AC/SCEN tokens anywhere in Markdown under `specs/`
   (configurable through `SPECS_ROOT` or `--specs-root`). A token in an example
   or comment counts too; collection is not semantic acceptance of a criterion.
2. Full mode reads recognized test files under `tests/` plus recognized tracked
   tests elsewhere in the repository. `--staged` captures one Git index tree:
   it checks changed indexed tests, or all indexed tests when a spec changes.
   Unstaged working-tree edits do not supply definitions for that snapshot.
3. Returns 1 when a checked reference is absent from the collected set.

Recognised examples include canonical `AC-001-1` and legacy `AC-103.2`,
`AC-103.2.1`, `SCEN-1.1`, `SCEN-S.1` and `SCEN-P.1`, case-insensitively.
Legacy dot forms are accepted by this validator; the spec-pack manifest uses
its own canonical AC definition pattern, `AC-001-1`.

Recognized test names include `test_*.py`, `*_test.py`, JS/TS
`*.spec.*` / `*.test.*` (including JSX/TSX), `*_test.go`, `*Test.java`,
`*Tests.cs` and `test_*.rb`. See the script's exact glob list for coverage.

---

## Pre-commit integration

In Standard and Assured, an explicitly activated NAOS pre-commit hook runs
the validator as **gate 10c**. If a checked indexed test references an undefined AC/SCEN, the
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

# Index snapshot; spec edits also recheck all indexed tests
python scripts/validators/validate_test_ac_references.py --staged

# Custom roots (monorepo, alternative layout)
SPECS_ROOT=apps/api/specs TESTS_ROOT=apps/api/tests \
  python scripts/validators/validate_test_ac_references.py
```

Exit codes: `0` = no violations or an onboarding/no-test no-op, `1` = unresolved
references, `2` = a requested snapshot, history or relevant content could not be
read. Inspect output and applicability as well as the exit code.

No recognized test files means no references to check. With no current AC/SCEN
tokens, initial onboarding may also skip, sometimes with an INFO/WARN message.
It is not an unconditional bypass: deleting the final previously configured
criterion causes affected references to fail. If references remain but no
current definitions do, the checker consults retained Git history; insufficient
shallow history or unreadable relevant content can return 2. Generated template
examples may already contain recognized tokens, so "template stubs only" does
not necessarily mean an empty definition set.

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

Both `AC-101.1` and `AC-101.2` must occur in a Markdown file under `specs/`.
Use genuine authored criteria rather than adding unused tokens to satisfy a regex. The validator does not parse or interpret the
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
Always re-anchor the AC references in the new context. Run the validator manually as well as through an activated hook; existing
but unrelated IDs still require semantic review.

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

Retain the command, snapshot, exit code and applicable findings for review.
A successful applicable run establishes recognized reference membership for
that checked snapshot; a no-op or an existing but unrelated ID does not prove
that tests verify the intended behavior. Review tests and actual execution
before accepting the task. In Lite use human completion review;
`@naos-conformance` is installed only by Standard/Assured.

For a full picture of how the v0.9.2 changes interact, see:

- [MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md](MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md) — pre-commit overview, including the v0.9.1 cumulative-context monitor (gate 10b)
- [MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md](MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md) — dedicated guide to the `NAOS_CONTEXT_REMAINING_PCT` guard
- [templates/skills/cognitive-checkpoint/SKILL.md](../../templates/skills/cognitive-checkpoint/SKILL.md) — checkpoint template mirrored by Rule 26 PAUL bracket behavior
