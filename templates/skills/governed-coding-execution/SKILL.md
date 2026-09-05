---
name: "governed-coding-execution"
description: "Orchestrate evidence-first implementation from bounded task context through source inspection, minimal change, tests, diff review, deterministic evidence, completion-claim verification, and human handoff. Invoke for material code, configuration, schema, workflow, security, or governance-surface changes, and before claiming implementation is complete, done, fixed, or passing."
parameters:
  - name: task
    description: "Optional task, requirement, FR/NFR/SCEN id, or work-item identifier to anchor execution."
    required: false
    default: ""
  - name: phase
    description: "Execution phase: prepare, implement, verify, or handoff."
    required: false
    default: "verify"
  - name: risk
    description: "Risk posture: auto, low, moderate, high, or critical. Raise verification effort for security, data, schema, and control-surface changes."
    required: false
    default: "auto"
---

# Skill: Governed Coding Execution

Run a coding change as a governed execution loop: bounded context ->
evidence-backed plan -> minimal change -> verification against reality ->
completion-claim review -> human handoff.

This is a thin orchestrator. It composes existing NAOS controls; it does not
replace them. Defer detailed method to `@naos-plan`, `@naos-implement`,
`@naos-review`, `@naos-conformance`, and the `function-discovery`,
`test-driven-development`, and `systemic-capability-wiring` skills — reference
them concisely instead of re-deriving their content here.

This skill is not evidence that the work was done correctly. The evidence is
repository state: the diff, the tests, the command output, the deterministic
reports, and the human review trail.

## Quick Start

1. Resolve scope, acceptance criteria, and out-of-scope boundaries.
2. Record advisory lane posture for non-trivial work: sequential, declared, or
   deferred. Suggested lanes do not activate handoff; declared lanes use
   existing handoff review evidence.
3. Inspect relevant source, schemas, tests, validators, docs, and existing
   behavior before editing.
4. Make the smallest coherent change and run focused validation.
5. Inspect the diff, complete the evidence ledger, and route human decisions
   that remain.

## When to Use

Use when implementing or materially changing code, configuration, schemas,
workflows, security/privacy behavior, or any governance surface — and always
before asserting a change is done, fixed, implemented, passing, or complete.

Do not use it for read-only questions, trivial edits with no behavior change, or
when the current brief explicitly bounds scope to something narrower.

## Evidence Hierarchy

Per ADR-0010: Control-Plane Advisory Boundaries, deterministic controls are primary; this skill is advisory and
bounded. When sources disagree, prefer: current user instruction; repository
source, schemas, tests, validators; deterministic command output from this
checkout; decision records and capability contracts; generated reports; then
docs, memory, and prior chat. Do not silently average conflicting evidence —
record the conflict and leave disputed interpretation for human review.

## Protocol

1. Prepare — establish authority and scope.
   - Resolve the active task, acceptance criteria, and out-of-scope boundary.
   - Record `parallel_lane_opportunity` and `parallel_lane_decision` in the
     task card or alignment artifact when the task is non-trivial or
     multi-scope. Use `deferred` when evidence is insufficient.
   - Treat `parallel_possible` and `parallel_recommended` as suggestions only;
     do not create agents, branches, worktrees, claims, handoff requirements,
     approval, merge, release, or compliance posture from a suggestion.
   - Inspect repository state, relevant specs, capability contracts, tests, and
     existing implementation before proposing change. Do not invent missing
     requirements; record gaps instead.
   - Run `function-discovery` before introducing new intent.
2. Implement — change minimally.
   - Follow the approved plan and make the smallest coherent change.
   - Use acceptance-linked `test-driven-development` where behavior is testable.
   - Record deviations as they occur. Stop rather than silently rewriting
     high-risk control surfaces without explicit approval.
3. Verify — reconcile against reality.
   - Inspect the actual diff and reconcile changed files against the plan and
     acceptance criteria.
   - Run focused tests, then the relevant broader tests; capture exact commands
     and their actual results. Never convert a recommended command into an
     executed one.
   - Run or recommend the applicable deterministic checks (`naos systemic-impact`
     for governed-artifact families, `naos spec-pack-contract` / `naos spec-cascade` / `naos module-headers`
     for traceability or source-reference changes, `naos control-plane-review`
     for routing, and `naos plan-coherence --diff-base <ref>` when alignment
     path declarations should be compared to changed files).
4. Review the completion claim — before saying done.
   - Produce the Completion Evidence Ledger below. Every material claim needs
     evidence or an explicit "not applicable" / "unverified". No silent omission.
5. Handoff — route, do not self-approve.
   - Route to `@naos-review` for quality, `@naos-conformance` for governance
     conformance, and a human for security, architecture, risk acceptance,
     waiver, merge, release, or deployment decisions.

## Completion Evidence Ledger

End each substantive invocation with this ledger (use "not applicable" rather
than omitting a line):

```text
Implementation status:
Scope and acceptance criteria:
Repository sources inspected:
Files changed:
Diff reviewed:
Commands executed:
Observed command results:
Tests not run:
Deterministic evidence generated:
Parallel lane posture:
Observed facts:
Reasoned inferences:
Unverified claims:
Plan deviations:
Known gaps:
Residual risks:
Rollback considerations:
Human decisions still required:
Recommended next NAOS action:
```

## Prohibited Claims

Do not:

- claim a file, function, branch, or command exists without inspecting it;
- say tests passed when they were not run, or hide failures behind a positive summary;
- treat a recommended command as an executed command;
- treat documentation or generated reports as proof of runtime behavior or approval;
- treat static validation as behavioral correctness, or absence of a finding as proof of absence;
- silently broaden scope, invent acceptance criteria, or omit untested areas;
- declare completion before reviewing the diff;
- replace deterministic controls with model judgement without explicit approval;
- manufacture objections merely to appear rigorous when no material weakness exists.

## Boundaries

This skill coordinates governed execution; it does not prove correctness,
security, or compliance, and it does not approve, certify, merge, release, or
deploy. Human review remains required for risky changes, waivers, approvals, and
maturity claims.
