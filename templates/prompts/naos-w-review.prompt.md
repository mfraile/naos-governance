# Weekly Review (Friday)

**Version**: 2.0.0 (Governance Trinity Edition)
**Enhancement v2.0**: **REQUIRED**: Read [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md) FIRST

---

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**Before proceeding**, read: [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md)

Review the week against specs, PM audit, and AI rules.

---

### ⚠️ AUTHORITATIVE SOURCES (CRITICAL)

**ALWAYS read these FIRST — they are the single source of truth:**
- `@specs/03-requirements.md` → FR/NFR status (canonical)
- `@naos/TASK_REGISTRY.yaml` → Task status (canonical)

**NEVER calculate metrics manually** — they are auto-synced from these sources.

> **⚠️ Governance metrics**: When scope changed this week, run `make -f Makefile.naos gov-refresh` FIRST, then update
> truth table to match auto-computed values. See `naos/governance/GOVERNANCE_TRUTH_TABLE.md` → Update Procedure.

Review this week's progress and update **`naos/PROJECT_STATUS.md`** "Notes & Observations":

**Weekly Reflection**:
- **Wins**: {{input:what_went_well}}
- **Challenges**: {{input:what_blocked_us}}
- **Lessons**: {{input:what_we_learned}}
- **Next Week Focus**: {{input:priorities}}

Add comprehensive entry to `naos/PROJECT_STATUS.md` following `.ai/RULES.md` Rule 3.

Also check:
- Are all completed items marked in Work Breakdown table?
- Are there unresolved blockers that need escalation?
- Do we need to update risk scores?

Include 3 mandatory response sections.

---
**Context Required**: `@.ai/RULES.md`, `@naos/PROJECT_STATUS.md`

---

## Next Action (Advisory)

Use the weekly review findings to seed next week's plan or open a focused task for unresolved blockers.

```yaml
next_action:
	label: "Convert review findings into next-week priorities."
	preferred_command: "/naos-w-plan"
	preferred_agent: "@naos-plan"
	reason: "Review findings should become planned work, not informal memory."
	constraints:
		- "Add or update TASK_REGISTRY.yaml only through the normal governance flow."
		- "Keep retrospective notes distinct from committed task status."
```
