---
name: "test-driven-development"
description: "Use acceptance-linked TDD discipline for behavior changes: scenario link -> failing test -> minimal implementation -> refactor -> evidence."
parameters:
  - name: requirement
    description: "Optional FR/NFR or acceptance scenario id to anchor the test-first workflow"
    required: false
    default: ""
---

# Skill: Test-Driven Development

## When to Use

Use this skill when implementing or changing behavior that can be tied to a
requirement, acceptance criterion, or `SCEN-*` scenario. It is especially useful
for new features, bug fixes with a known regression, and safety/security logic
where a passing test is part of the completion evidence.

Do not use this skill as proof that the assistant actually followed TDD. The
evidence is the repository state: the test, the implementation, the command
output, and the review trail.

## Protocol

1. Identify the requirement or scenario.
   - Prefer `specs/06-acceptance.md` `SCEN-*` links.
   - If the scenario is missing, record that gap before implementation.
2. Write or update the smallest failing test that captures the expected behavior.
   - The test name or comments should reference the relevant `FR-*`, `NFR-*`, or `SCEN-*`.
   - Run the focused test and confirm it fails for the expected reason.
3. Implement the smallest production change that makes the test pass.
   - Do not broaden scope while the red test is unresolved.
4. Refactor only after the focused test passes.
   - Re-run the focused test after refactor.
5. Run the appropriate broader test set and NAOS evidence checks.
   - Use `pytest -q` or the project-specific test command.
   - Run or recommend `naos spec-pack-contract` and `naos spec-cascade` when
     specs/source traceability or source spec references changed.
   - Run or recommend `naos module-headers` when source module headers changed.

## Evidence

Record:

- scenario or requirement id;
- failing test command and failure summary;
- passing focused test command;
- broader validation command;
- any missing scenario, missing traceability, waiver, known gap, or residual risk.

## Boundaries

- TDD is a development discipline, not a certification.
- A passing test does not prove complete behavior, security, compliance, or absence of defects.
- Missing acceptance scenarios are governance gaps; do not invent hidden acceptance criteria.
- Human review remains required for risky changes, waivers, approvals, and maturity claims.
