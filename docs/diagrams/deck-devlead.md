---
marp: true
title: NAOS-Governance Development Lead Overview
---

# Development Lead View

NAOS-Governance helps a team keep AI-assisted delivery connected to project
evidence.

Common adoption commands:

- `naos adopt --mode greenfield --dry-run`
- `naos adopt --mode brownfield --dry-run`
- `naos preflight`
- `naos intake`
- `naos install-plan`

---

# Brownfield Workflow

- `naos existing-resource-inventory`
- `naos ai-artifact-inventory`
- `naos memory-resource-inventory`
- `naos repo-context-challenge`
- `naos brownfield-baseline`
- `naos requirements-reconstruct`
- `naos traceability-gap-register`
- `naos install-decision-record`

Candidate requirements remain candidates until human review.

---

# Daily Operating Boundary

Use prompts and agents for work:

- `/naos-d-start`
- `/naos-task-start`
- `@naos-plan`
- `@naos-implement`
- `@naos-review`
- `/naos-task-complete`

Use CLI reports for evidence. Do not treat reports as approval.

When specs, tasks, source spec references, or source traceability change, include `naos spec-pack-contract` and `naos spec-cascade`
alongside module-header, test-evidence, and AC-completion evidence checks before reviewer handoff when completion is claimed.
