---
name: "cookbook-governance"
description: "If-then recipes for governance workflow. Invoke when scope changes, creating tasks, ending sessions, or asked to create summary/analysis files."
parameters: []
---

# Cookbook: Governance Workflow

## When to Use

Use this skill when scope changes, creating tasks, ending sessions, or asked to
create summary or analysis files.

> Extracted from `.github/instructions/governance.instructions.md`. See that file for full domain rules.

### If: Scope changes (new task, new requirement, status update)
**Then**: Run `make -f Makefile.naos gov-refresh` FIRST — never manually calculate derived metrics
**Example**:
```bash
# WRONG — manually editing naos/DASHBOARD.md or counting tasks by hand

# RIGHT
make -f Makefile.naos gov-refresh   # updates all auto-generated files
```

### If: Creating a new task
**Then**: Add it to `naos/TASK_REGISTRY.yaml` first, then create the card in `naos/active/` using `_TEMPLATE.md`
**Example**: See `naos/active/_TEMPLATE.md` — required fields: Task ID, Requirement, Spec Section, AC

### If: A session ends or a major decision is made
**Then**: Check `configs/naos_memory.yaml`, `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`. If Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, call `mem_save` to record the decision and `mem_session_summary` before signing off. If memory is deferred, disabled, unauthorized, unverified, disallowed by memory-use policy, or unavailable, write the same What / Why / Files / Remaining / Gotchas payload into the active compact/task card.
**Example**: See `docs/ENGRAM_SETUP.md` and the cognitive-checkpoint skill — use `mem_save` at phase transitions only when memory write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, and use degraded compact/task-card persistence otherwise.

### If: Asked to create a summary, analysis, or session notes file
**Then**: Update `naos/PROJECT_STATUS.md` instead — never create `SESSION_SUMMARY_*.md`, `ANALYSIS_*.md`, or `draft_*.md`
**Example**:
```bash
# WRONG
touch naos/SESSION_SUMMARY_2026-03-15.md

# RIGHT — update the journal section of the existing file
# Edit naos/PROJECT_STATUS.md — add to the journal section
```
