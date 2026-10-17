---
name: debug
description: 'Diagnose bugs with evidence-first discipline: reproduce, localize, test hypotheses and recommend a minimal fix. Implementation requires an authorized writer.'
metadata:
  naos-parameters: '[{"name":"target","description":"Optional bug, error message or failing test to investigate","required":false,"default":""}]'
---

# Skill: evidence-first diagnosis

## When to Invoke

Use this skill to investigate a bug, error message or failing test.

Follow a no-direct-edit diagnostic role. This skill does not invoke an agent.
Where installed, read `.github/agents/naos-debug.agent.md` as the diagnostic
contract; native selection requires the active host's manual invocation and
human authorization. Lite has no debug agent: follow this protocol directly.

1. Reproduce the supplied failure with project-appropriate commands. Record the
   exact symptom, expected behavior, failing test and affected source paths.
2. State competing root-cause hypotheses, evidence, confidence and falsifiers.
   Preserve failed hypotheses and missing evidence; never infer a fix from a name.
3. Recommend the smallest correction and a regression test. Do not edit files,
   invoke another agent, claim implementation or repeatedly run an unchanged
   failing command. Architectural uncertainty goes to human planning review.
4. Hand the diagnosis and proposed validation to a separately authorized writer.
   Only that writer implements and runs the relevant checks; then request human
   quality/governance review. A diagnostic report is not proof of a verified fix.

Manual role guidance, where installed: `.github/agents/naos-plan.agent.md`,
`.github/agents/naos-implement.agent.md`, `.github/agents/naos-review.agent.md`.
If any file is absent, use a human-reviewed plan, authorized writer and human
review without claiming a named agent was loaded or invoked.

Do not refactor adjacent code, omit regression evidence or bypass pre-commit.
