# End of Day Status Update & Tomorrow Planning

**Purpose**: Guide end-of-day review and planning.

**Version**: 2.1.0 (Governance Trinity Edition)
**Enhancement v2.1**: **REQUIRED**: Read [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md) FIRST

---

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**BEFORE proceeding, read this context**:
- File: [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md)
- Purpose: Interconnected governance trinity (Constitution/Admin/Behavior)

Review `PROJECT_STATUS.md`; verify the diff and absence of new summaries.

---

## Today's Work Summary

**Today's Work**:
- **Completed**: {{input:what_completed}}
- **In Progress**: {{input:what_in_progress}}
- **Blockers**: {{input:any_blockers}}

## Instructions

### ⚠️ AUTHORITATIVE SOURCES (CRITICAL)

**ALWAYS read these FIRST — they are the single source of truth:**
- `@specs/03-requirements.md` → FR/NFR status (canonical)
- `@naos/TASK_REGISTRY.yaml` → Task status (canonical)

**NEVER calculate metrics manually** — they are auto-synced from these sources.

> **⚠️ Governance metrics**: When task status changes affect metrics, run `make -f Makefile.naos gov-refresh` FIRST,
> then read auto-computed values, then update truth table to match.
> See `naos/governance/GOVERNANCE_TRUTH_TABLE.md` → Update Procedure.

### PART 1: Update Status Files (Follow `.ai/RULES.md`)

1. **naos/PROJECT_STATUS.md** — Update:
   - Work Breakdown table (update FR/NFR status)
   - Update History (add today's entry with summary)
   - Recent Decisions (if any ADRs made today)
   - Risk Register (update if risks changed)

2. **CHANGELOG.md** — Add under [Unreleased]:
   - Added / Changed / Fixed / Removed
   - Session impact metrics
   - Commits pushed today

### PART 2: Validate Metrics Coherence

**Before committing status updates**, run:
```bash
python scripts/validators/validate_metrics_coherence.py --verbose
```
This checks bounded metrics coherence, not overall consistency.

### PART 3: Analyze Tomorrow's Priorities

Review `@naos/PROJECT_STATUS.md` sections:
- **Next 2 Weeks**: What's scheduled for tomorrow?
- **Risk Register**: Any ACTIVE risks blocking tomorrow?
- **Pending Activities**: What should continue?
- **Metrics Summary**: What needs attention?

Generate **Tomorrow's Recommended Priorities** (3-5 items):
- Priority 1 (🔴 CRITICAL): Blockers, deadlines
- Priority 2 (🟡 HIGH): Phase goals, active work
- Priority 3 (🟢 NORMAL): Planned tasks

Include:
- Why this is priority (link to FR/NFR or risk)
- Estimated effort
- Dependencies or prerequisites
- Success criteria

### PART 4: Handle Active Story Cards

Check `naos/active/` for any cards worked on today:

```bash
ls naos/active/
```

For each card where work was done:

1. **If task COMPLETED today**:
   - **Use the completion workflow**: `/naos-task-complete T-XXX`
   - Verify actual checkbox, note, validation, and command evidence

2. **If task IN PROGRESS**:
   - Add implementation notes with today's date
   - Update progress in the card
   - Card stays in `naos/active/`

3. **Archive posture**:
   NAOS does not ship a default generated-adopter archive script. If your project has an approved internal archival workflow, run it according to that project's documentation after all completion boxes are manually checked. Otherwise, keep task-card and registry updates explicit and human-reviewed.

### PART 5: Session Closing Commands

**Before closing**: Save a session summary to Engram only when memory is configured, write access is authorized and verified, memory-use policy permits the write, and the human-review boundary is satisfied. Otherwise write the same summary into the active compact/task card and mark recovery as degraded:
```
mem_session_summary:
  ## Goal: [what we were working on]
  ## Discoveries: [technical findings, constraints, gotchas]
  ## Accomplished: [completed items with key details]
  ## Next Steps: [what remains for next session]
  ## Relevant Files: [paths touched and what changed]
```

Run or consult `naos session-end --task <TASK-ID> --profile <profile>` before closing. It recommends reruns, evidence/dashboard refreshes, and memory candidate proposals, but does not approve work, mutate task cards, write compact files, call Engram/MCP, or write memory. If Engram is already installed but not connected, run `naos memory-readiness`, `naos memory-access`, `naos memory-use-policy`, and `naos memory check` after the session. If memory is deferred, disabled, unauthorized, unverified, disallowed by memory-use policy, or unavailable, record any needed summary manually in the active compact/task card and note that recovery is running in degraded mode.

Provide ready-to-run commands:
```bash
# 1. Archive completed story cards only if your project has an approved internal workflow
# Otherwise keep task-card and registry updates explicit and human-reviewed.

# 2. Full governance refresh (syncs all derived files + validates coherence)
make -f Makefile.naos gov-refresh

# 3. Stage status updates
git add naos/PROJECT_STATUS.md CHANGELOG.md naos/active/ naos/completed/ naos/TASK_REGISTRY.yaml

# 4. Commit
git commit -m "docs(pm): End-of-day status update {{currentDate}}"

# 5. Push
git push origin [branch]

# 6. Review today
git log --oneline --since="{{currentDate}} 00:00"
```

## Response Format (3 Mandatory Sections)

### ✅ FILES UPDATED
List files with summary of changes

### 🎯 TOMORROW'S PRIORITIES ({{nextDate}})
**Priority 1 (🔴 CRITICAL)**:
- Task name (why, effort, success criteria)

**Priority 2 (🟡 HIGH)**:
- Task name (why, effort, success criteria)

**Priority 3 (🟢 NORMAL)**:
- Task name (why, effort, success criteria)

**Context for Tomorrow**:
- What was left in-progress today
- Any decisions that affect tomorrow
- Links to relevant specs/docs

### 📦 SESSION CLOSING COMMANDS
Provide the bash commands above (ready to copy-paste)

### 🚫 WHAT I DID NOT DO
- Pre-existing issues not fixed today
- Out-of-scope items
- Future work deferred

### NEXT ACTION (ADVISORY)
Record the first task or decision for the next session in both the session summary and the footer below.

```yaml
next_action:
   label: "Resume with the recorded priority in the next session."
   preferred_command: "/naos-d-start"
   preferred_agent: "@naos-plan"
   reason: "Session state is closed; the next safe step is a fresh governance bootstrap."
   constraints:
      - "Save the session summary before ending."
      - "Do not leave uncommitted work unexplained in the handoff."
```

---
**Context Required**: `@.ai/RULES.md`, `@naos/PROJECT_STATUS.md`, `@CHANGELOG.md`, `@naos/BACKLOG.md`
