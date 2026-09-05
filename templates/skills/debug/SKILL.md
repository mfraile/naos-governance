---
name: "debug"
description: "Diagnose and fix bugs with evidence-first discipline — reproduce → localize → minimal-change fix → regression test. Invoke when a test fails, an error appears, or a regression needs investigation."
parameters:
  - name: target
    description: "Optional: describe the bug, error message, or failing test to focus the investigation"
    required: false
    default: ""
---

# Skill: Debug Agent

Invokes the `@naos-debug` agent for structured, evidence-first bug diagnosis. Purpose-built to compensate for AI's weaker long-horizon debugging capability (MIT CSAIL SWE-bench finding).

## When to Use

- A `pytest` test is failing and you need to diagnose why
- A runtime error appears in logs or terminal output
- A recent commit introduced a regression
- Before attempting any fix — to confirm root cause first

## What This Invokes

`@naos-debug` agent (`debug.agent.md`) with a 4-step protocol:

1. **Evidence Gathering** — reproduce the failure, grep related code, review recent git log. NO file modifications in this step.
2. **Hypothesis Formulation** — state root cause explicitly with evidence. Escalate to `@naos-plan` if architectural.
3. **Minimal-Change Fix** — touch ONLY the confirmed root cause file(s). Maximum 5 file changes.
4. **Regression Test** — write a test that fails before and passes after. Run full suite.

## Quick Commands

```bash
# Reproduce
pytest tests/<path> -v --tb=short

# Localize
grep -rn "ErrorKeyword" src/
git log --oneline -20 -- <affected_file>

# Validate fix
pytest -q tests/unit tests/acceptance
```

## Handoff Rules

- Root cause is architectural → escalate to `@naos-plan` with evidence
- Fix verified + regression test green → hand off to `@naos-review`

## Anti-Patterns

| Pattern | Status |
|---------|--------|
| "It's probably X" without a stack trace | **FORBIDDEN** |
| Refactoring adjacent code while fixing | **FORBIDDEN** |
| Skipping regression test | **FORBIDDEN** |
| `--no-verify` to bypass pre-commit | **FORBIDDEN** |
| >5 file changes without escalating to @naos-plan | **FORBIDDEN** |
