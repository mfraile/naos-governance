---
applyTo: "**"
---

# Session Management Guidelines

> Governs AI agent session lifecycle: start, work, checkpoint, handoff, and close.
> Inspired by ECC session hooks; adapted for NAOS governance-as-code enforcement.
> Complements: `context-pressure.instructions.md` (context brackets), cognitive-checkpoint skill (memory proposals/compact fallback), `naos session-id` report namespacing, and `naos session-start|session-checkpoint|session-end` lifecycle reports.

## Session Lifecycle

Every coding session follows five phases:

| Phase | Trigger | Required Actions |
|-------|---------|-----------------|
| **START** | New session or compaction recovery | Run/review `naos session-id` and `naos session-start --task <TASK-ID>`, read compact/task card, verify scope |
| **WORK** | Active implementation | Follow governance rules, checkpoint at triggers |
| **CHECKPOINT** | T1-T5 triggers (Rule 26) | Run/review `naos session-checkpoint --task <TASK-ID>` and record manual compact/task-card updates when appropriate |
| **HANDOFF** | Agent transition or session break | Full T5 checkpoint, update task card status |
| **CLOSE** | End of session | Run/review `naos session-end --task <TASK-ID>`, identify manual updates, check git status |

## START Phase — Session Initialization

When beginning a session (fresh or post-compaction):

1. **Check for active task**: `ls naos/active/*_compact.md` — if a compact file exists, this is a continuation
2. **Create/reuse session namespace**: `naos session-id` writes `naos/sessions_index.json` and uses `naos/sessions/<session_id>/reports/` while keeping `naos/reports/` as compatibility output
3. **Record operator attribution**: `naos operator-attribution` records local identity signals for who initiated the run/session; it is not authentication, authorization, task ownership, locking, separation-of-duties evidence, non-repudiation, or approval
4. **Summarize audit history**: `naos audit-log` records/summarizes append-only event history; it is not approval, non-repudiation, cryptographic signing, tamper-proof storage, task locking, evidence conflict detection, compliance approval, or source of truth
5. **Detect evidence conflicts**: `naos evidence-conflicts` flags deterministic evidence/review conflicts for human review; it does not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance
5. **Record task coordination when relevant**: `naos task-claim --task <TASK-ID>` or `make -f Makefile.naos naos-task-claim TASK=T-123` records local claim metadata; `naos task-release --task <TASK-ID>` releases it. Claims do not authorize work, approve tasks, prove ownership or separation of duties, mark completion, create exclusive access, resolve evidence conflicts, or prove compliance.
5. **Generate/review lifecycle posture**: `naos session-start --task <TASK-ID>` is a report/checklist, not automatic context injection
6. **Read compact file first** (fastest recovery): get last completed WI, next action, blockers
7. **Verify git state**: `git status && git diff --name-only` — understand what changed since last session
8. **Read active task card**: confirm scope and acceptance criteria haven't changed
9. **Do NOT restart completed work** — continue from where the last session left off

Session identity isolates report roots, operator attribution records local run/session identity signals, the audit log records event history over time, and evidence conflict detection flags deterministic review conflicts. M3 adds local SQLite write coordination for context-index file integrity, M4 adds audit event history, M5 adds evidence conflict detection, M6 adds task claim/release coordination metadata, M7 adds static team/operator policy overlay scopes, M8 adds team-scoped gatekeeper posture, M9 adds PR-time CI evidence templates, and P1 adds optional tool integration templates. NAOS still treats authorization-backed task locking, release approval, deployment authorization, and public-release re-audit as separate human-governed steps. Lifecycle reports never write memory, compact files, task cards, or `TASK_REGISTRY`. Memory candidates are proposal-only until explicitly approved under memory-use policy.

**Anti-pattern**: Starting a fresh analysis of the entire codebase when a compact file clearly states "Task A complete, start Task B."

## WORK Phase — Active Implementation

During active work:

- **Single-task focus**: Work on one WI at a time. Complete it or checkpoint before switching.
- **File discipline**: Update existing files (Rule 1). No `SESSION_SUMMARY_*.md`, no `draft_*.md`, no `archive/` folders.
- **Checkpoint triggers**: Save at every T1-T5 trigger (see cognitive-checkpoint skill).
- **Evidence trail**: Every decision should trace to a rule, spec reference, or explicit user request.

## CHECKPOINT Phase — Structured State Saves

Use the cognitive-checkpoint skill template. Minimum fields:

```
**What**: <outcome, not just action>
**Why**: <motivation, not just "per requirements">
**Files**: <precise paths changed>
**Remaining**: <next concrete action>
**Gotchas**: <non-obvious constraints>
```

**When to save** (Rule 26 triggers):
- T1: Phase transitions (plan -> code -> test -> commit)
- T2: Non-obvious discoveries (bugs, constraints, gotchas)
- T3: >=5 consecutive tool calls without checkpoint
- T4: >=20 messages without checkpoint
- T5: Pre-handoff to another agent

## HANDOFF Phase — Agent Transitions

Before yielding to another agent or ending a work session:

1. **Update compact file**: `naos/active/<TASK-ID>_compact.md` with current state
2. **Update task card**: Mark completed WIs, update "Context Brief" section
3. **Save T5 checkpoint**: Full template with all 5 fields
4. **Document open questions**: Anything the next agent needs to decide
5. **Record advisory next action**: If using `_HANDOFF_TEMPLATE.yaml`, fill `next_action` so the next session knows the first safe step
6. **Git state clean**: Either commit or stash — never leave dirty working tree for handoff

## CLOSE Phase — Session Wrap-Up

At end of session:

1. **Run `make -f Makefile.naos gov-status`** — verify governance files are consistent
2. **Update compact file** with session summary
3. **Verify no drift**: No unauthorized files created, no archive folders, no session summaries
4. **Leave clear next-step**: The next session (or agent) should know exactly what to do first; use `next_action` when a structured handoff is needed

## Session State Files

| File | Purpose | Created By |
|------|---------|-----------|
| `naos/active/<TASK-ID>_compact.md` | Cross-session recovery state | Agent (manual update) |
| `naos/active/<TASK-ID>_*.md` | Full task card with WI details | Agent (manual update) |
| `naos/TASK_REGISTRY.yaml` | Task status tracking | Agent (manual update) |

## Anti-Patterns

| Anti-Pattern | Why It Breaks Sessions |
|---|---|
| No compact file update at session end | Next session starts cold, wastes 10+ minutes re-reading |
| Multiple WIs in flight simultaneously | Context fragmentation, incomplete checkpoints |
| Skipping START phase recovery | Redo completed work, miss constraints |
| Creating `SESSION_SUMMARY_*.md` files | Violates Rule 1 (file proliferation) |
| Dirty git state at handoff | Next agent doesn't know what's committed vs. in-progress |
