# Active Task: T-XXX - [Task Title]

<!--
MANDATORY: ALL AI tools must read this before coding.
This card focuses context to prevent drift.
-->

## Quick Reference

| Field | Value |
|-------|-------|
| **Task ID** | T-XXX |
| **Requirement** | FR-XXX |
| **Spec Section** | [ADAPT: specs/03-requirements.md (lines XXX-XXX)] |
| **Related Specs** | [ADAPT: list relevant spec files] |
| **Related Tasks** | T-YYY, T-ZZZ |
| **Created** | YYYY-MM-DD |
| **Owner** | [name] |

---

## Schemas to Respect (DO NOT VIOLATE)

### Database Schema
```
[ADAPT: paste the relevant table definition here]
```

### API/JSON Schema
```
[ADAPT: paste the relevant schema here, or N/A]
```

---

## Existing Code to Use (DO NOT RECREATE)

| Purpose | File | Function/Class |
|---------|------|----------------|
| [purpose] | `[ADAPT: src/services/service.py]` | `[function_name]` |

**CRITICAL**: Check `naos/inventory/FUNCTION_INDEX.yaml` before creating new functions!

---

## Acceptance Criteria

- [ ] AC1: [criterion]
- [ ] AC2: [criterion]
- [ ] AC3: [criterion]

---

## Pre-Coding Checklist

**STOP if any are unchecked:**

- [ ] Read the spec section referenced above
- [ ] Verified DB schema matches plan
- [ ] Searched for existing code that does similar work (`naos/inventory/FUNCTION_INDEX.yaml`)
- [ ] Confirmed no duplicate functionality being created

---

## Spec Alignment Checklist

- [ ] Identified all relevant FRs/NFRs from requirements spec
- [ ] Checked architecture spec for applicable constraints
- [ ] Checked API spec for conventions (if API work)
- [ ] Checked acceptance spec for test scenarios to implement

---

## Parallelization Opportunity (Advisory)

Record this before implementation, even for solo work. Suggested lanes are
review guidance only and become active only when explicitly declared.

| Field | Value |
|-------|-------|
| **Parallel Lane Opportunity** | not_applicable / sequential_recommended / parallel_possible / parallel_recommended |
| **Parallel Lane Decision** | sequential / declared / deferred |
| **Reason Codes** | [ADAPT: independent_acceptance_criteria, distinct_path_scopes, dependency_unlocked, frontend_backend_test_docs_split, high_context_load, solo_checkpoint_value, unresolved_dependency, high_scope_overlap, schema_or_api_decision_first, high_risk_tightly_controlled_work, missing_task_or_requirement_link, missing_test_strategy] |
| **Candidate Lanes** | [ADAPT: list logical/team lanes or N/A] |
| **Solo/Team Posture** | [ADAPT: logical checkpoints in one checkout / team lanes with task claims / N/A] |

Activation boundary:
- `parallel_possible` and `parallel_recommended` do not require handoff by themselves.
- Handoff evidence applies only after `Parallel Lane Decision` is `declared`.
- Git worktrees are optional physical isolation, not proof of safe parallel work.

---

## Implementation Plan

[Write the step-by-step plan here BEFORE coding]

1. [ ] Phase 1: [description]
2. [ ] Phase 2: [description]
3. [ ] Phase 3: [description]

---

## Out of Scope (Guardrails)

These are explicitly out of scope for this task:
- [list what NOT to change]
- [adjacent problems to defer]

---

## Known Risks / Gotchas

- [ADAPT: document any non-obvious constraints or edge cases]

---

## Post-Implementation Checklist

- [ ] Tests written and passing (`pytest -q`)
- [ ] Function index regenerated (`make -f Makefile.naos function-index`)
- [ ] Governance synced (`make -f Makefile.naos gov-refresh`)
- [ ] Task status updated in `naos/TASK_REGISTRY.yaml`
