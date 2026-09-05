# MICRO TUTORIAL 31 - PAUL Runtime Guard

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

The PAUL runtime guard maps a caller-supplied cognitive-state declaration to a
deterministic commit-time response. An agent estimates its remaining
context-window headroom through `NAOS_CONTEXT_REMAINING_PCT`; the generated
pre-commit hook maps that unverified signal to Rule 26 PAUL brackets. It does not
measure context or observe the agent runtime.

---

## What the guard does

In Standard and Assured generated projects, pre-commit gate 10b reads:

```bash
NAOS_CONTEXT_REMAINING_PCT
```

The variable is a caller-supplied integer from 0 to 100 that estimates remaining agent context.
The hook behavior is intentionally small and deterministic:

| Signal | Result | Required response |
|---|---|---|
| Unset | No-op | Human commits are not blocked for missing agent telemetry. |
| Non-integer | Warning, then skip | Fix the agent telemetry if it should have reported a number. |
| `35` or more | Pass | Continue with normal Rule 26 checkpoint cadence. |
| `25` to `34` | DEEP warning | Compact memory before the next sub-task; save T1 + T5 checkpoints. |
| Less than `25` | CRITICAL failure | Stop, save a full Rule 26 checkpoint, and hand off via `strategic-compact`. |

The guard warns at DEEP and rejects the commit attempt at CRITICAL. That result
does not prove whether the agent is safe, whether the estimate is accurate, or
whether a recovery-grade checkpoint and handoff actually occurred.

---

## How agents should set it

Before a commit attempt, the active agent should set the variable to its current
context estimate:

```bash
NAOS_CONTEXT_REMAINING_PCT=42 git commit -m "feat: implement task"
```

If the agent is below the DEEP threshold, it should not treat the warning as
cosmetic. DEEP means the session is now narrow enough that recovery state matters
more than exploration.

```bash
NAOS_CONTEXT_REMAINING_PCT=31 git commit -m "docs: update governance note"
```

Expected response:

- Finish only the current bounded action.
- Save or refresh the Rule 26 checkpoint.
- Compact memory before starting a new sub-task.
- Avoid new exploratory branches.

At CRITICAL, the commit is blocked:

```bash
NAOS_CONTEXT_REMAINING_PCT=18 git commit -m "fix: patch drift"
```

Expected response:

1. Stop work.
2. Save a full Rule 26 checkpoint with What / Why / Files / Remaining / Gotchas.
3. Hand off via `strategic-compact` or yield to a fresh agent.
4. Resume from the saved checkpoint in a fresh context.

---

## Relationship to Rule 18 and Rule 26

- **Rule 18** sets the cumulative instruction-budget expectation. The guard does
  not count instruction lines or enforce the ≤400L expectation; it handles only
  the separately supplied percentage signal.
- **Rule 26** defines the PAUL bracket behavior. The runtime guard is the
  generated pre-commit signal that turns DEEP and CRITICAL bracket declarations
  into visible commit-time feedback.
- **The cognitive-checkpoint skill** remains the template for the actual saved
  checkpoint.

The guard does not replace human judgment. It makes a dangerous context state
harder to ignore at the moment a commit would otherwise become durable.

---

## Override policy

The hook documents a rare escape hatch:

```bash
NAOS_CONTEXT_REMAINING_PCT=100 git commit -m "docs: emergency correction"
```

Use that only when a human maintainer has decided the telemetry is stale or the
blocked commit is safer than delaying. Record the reason in the task card or
checkpoint. Do not use the override to continue agent work at CRITICAL context.

---

## Limitations

- The guard is a pre-commit check, not a runtime sandbox for every tool call.
- The guard trusts caller-supplied telemetry and cannot verify context usage,
  checkpoint persistence, or handoff completion.
- If the variable is unset, the hook does not block; this avoids breaking direct
  human commits when no agent telemetry exists.
- `git commit --no-verify` bypasses pre-commit hooks. Projects that require
  enforcement should mirror NAOS tier expectations in CI.
- Adopters must enforce the expected `NAOS_TIER` in CI if they need Standard or
  Assured behavior to be mandatory across a team.

---

## Related files

- [templates/rules-chain/.githooks/pre-commit](../../templates/rules-chain/.githooks/pre-commit) - generated hook source for gate 10b
- [templates/skills/cognitive-checkpoint/SKILL.md](../../templates/skills/cognitive-checkpoint/SKILL.md) - checkpoint template
- [docs/GLOSSARY.md](../GLOSSARY.md) - definitions for `NAOS_CONTEXT_REMAINING_PCT` and PAUL context brackets
- [SECURITY.md](../../SECURITY.md) - vulnerability and limitation boundaries for guard bypasses
