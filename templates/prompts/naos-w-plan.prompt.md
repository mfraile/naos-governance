# Plan Week's Work

**Version**: 2.0.0 (Governance Trinity Edition)
**Enhancement v2.0**: **REQUIRED**: Read [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md) FIRST

Plan the upcoming week's work, breaking down tasks and setting priorities.

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**Before proceeding**, read: [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md)

Compare the plan with authoritative `specs/03` and `naos/TASK_REGISTRY`.

## Context Required

### ⚠️ AUTHORITATIVE SOURCES (CRITICAL)
- `@specs/03-requirements.md` → FR/NFR status (canonical source)
- `@naos/TASK_REGISTRY.yaml` → Task status (canonical source — use for task selection)

### Core Context
- `@naos/PROJECT_STATUS.md` — Current project status
- `@specs/10-execution.md` — Task execution matrix
- `@.ai/RULES.md` — Governance rules

## Instructions

Read the context files and create a **comprehensive weekly work plan** (typically done Monday morning).

**Input Parameters**:
- {{week_starting}}: Week starting date (e.g., "2026-01-20")
- {{focus_areas}}: Key focus areas for the week

**You MUST provide these 3 sections**:

### 1. Week Overview
- **Week Goal**: One sentence describing the main objective
- **Focus Areas**: 2-3 high-priority areas
- **Target Completion**: Which tasks/FRs to complete this week
- **Risks**: Potential blockers or dependencies

### 2. Daily Breakdown
**Monday**:
- Morning: [tasks]
- Afternoon: [tasks]

**Tuesday**:
- Morning: [tasks]
- Afternoon: [tasks]

**Wednesday**:
- Morning: [tasks]
- Afternoon: [tasks]

**Thursday**:
- Morning: [tasks]
- Afternoon: [tasks]

**Friday**:
- Morning: [tasks]
- Afternoon: Weekly review + retrospective

### 3. Success Criteria
- [ ] Specific deliverable 1
- [ ] Specific deliverable 2
- [ ] Specific deliverable 3
- [ ] [ADAPT: your test coverage target, e.g., test coverage maintained ≥ X%]
- [ ] All tests passing
- [ ] Documentation updated

**Format**: Be specific with task IDs, FR/NFR references, and time estimates.

**Governance**: This plan follows all governance rules from `.ai/RULES.md`.

---

## Next Action (Advisory)

After the weekly plan is accepted, start the next daily session from the selected task and current priorities.

```yaml
next_action:
	label: "Start the first planned daily session and select the active task."
	preferred_command: "/naos-d-start"
	preferred_agent: "@naos-plan"
	reason: "The weekly plan sets priorities; daily bootstrap turns them into task-scoped work."
	constraints:
		- "Use task IDs from TASK_REGISTRY.yaml."
		- "Re-plan before implementation if blockers or dependencies changed."
```
