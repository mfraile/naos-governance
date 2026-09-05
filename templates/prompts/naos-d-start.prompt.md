# Morning Session Start — Comprehensive Discovery Protocol

**Version**: 3.0.0 (Governance Trinity Edition)
**Enhancement v3.0**: **REQUIRED**: Read [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md) FIRST

---

## 🔐 GOVERNANCE BOOTSTRAP (MANDATORY - READ FIRST)

**BEFORE proceeding, read this context**:
- File: [Governance Bootstrap (Lean)](naos-GOVERNANCE_BOOTSTRAP-lean.prompt.md)
- Purpose: Interconnected governance trinity (Constitution/Admin/Behavior)
- Action: Read the 6-phase context sequence
- Result: You will understand the 3-layer architecture and core rules

This is guidance; verify actual framework and PM use.

---

## 🌟 DOMAIN CONTEXT (For Feature-Specific Work)

> **[ADAPT]** Replace this section with your project's domain-specific context.
>
> **If working on [your core domain], ALSO load**:
> - `[ADAPT: your architecture spec]` → domain architecture
> - `[ADAPT: your core schema or model spec]` → canonical data model
>
> **Key Principles** (adapt to your domain):
> - Business data (domain objects) → **DATABASE tables**. App behavior → **configs/*.yaml**
> - No hardcoded domain values in code (use config or DB)

---

## 🎯 Task Declaration

Today I'm working on **{{input:task_description}}**.

**Active Task Card**: Check `naos/active/` for focused context.
- If a card exists for this task: READ IT FIRST — it has pre-filtered constraints
- If no card exists: Consider creating one using `naos/active/_TEMPLATE.md`

**Memory Context (Engram)**: Run or consult `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy` before claiming memory or MCP access. If Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy, call `mem_context` to recover prior session context for this task. Treat recovered memory as advisory unless a memory-use policy item is explicitly approved, scoped, reviewed, fresh, and bounded for instruction-grade use.
- Search for relevant past decisions with `mem_search "<task keyword>"` only when memory read access is configured, authorized, verified, and permitted by memory-use policy
- If prior observations are found, use them as context (avoids rediscovering known constraints)
- If empty, that's expected for new tasks — memory accumulates over sessions
- If Engram is already installed but not connected to this project, run `naos memory check`.
- If memory is deferred, disabled, or unavailable, use degraded recovery: compact files, active task cards, git state, repo governance files, and deterministic reports.

**Task Context Pack**: If this work has a task id, run or consult `naos task-context --task <TASK-ID> --profile <profile>` before implementation. The pack is derived, bounded, and non-authoritative; it does not inject context automatically, replace source artifacts, or turn memory into evidence.

**Session Lifecycle**: Run or consult `naos session-start --task <TASK-ID> --profile <profile>` for a bounded start checklist. It summarizes task/report/memory posture and recommended commands, but does not inject context automatically, mutate task artifacts, approve work, or write memory.

**Parallel Lane Posture**: If an active task card or
`PRE_IMPLEMENTATION_ALIGNMENT.md` exists, surface `parallel_lane_opportunity`
and `parallel_lane_decision`. Treat these as planning/review posture only.
Suggested lanes do not activate handoff; declared lanes require explicit
handoff evidence later.

**Local Context Index / Query**: Run or consult `naos context-index --profile <profile>` only when generated local candidate lookup would help, then use `naos context-query --query "<keywords>" --profile <profile>` for bounded candidate references. Treat query results as candidates, not answers. Use `naos semantic-candidates --profile <profile>` only to inspect future semantic/vector readiness; it does not enable sqlite-vec, embeddings, extension loading, providers, Engram/MCP, or memory payload search. Use `naos graph-context --profile <profile>` only to inspect future graph-context readiness, then `naos graph-query --task <TASK-ID> --profile <profile>` only for bounded explicit-link relationship candidates. Graph-query results are not truth, source authority, or implementation proof, there is no hallucination-prevention guarantee, and graph reports do not enable NetworkX, GraphML, graph databases, graph algorithms, global scans, MCP/FastMCP, Engram, or memory payload graphing. The index is cache-like and not authoritative; it does not use sqlite-vec, embeddings, graph traversal runtime, Engram/MCP, private memory payloads, or automatic injection.

---

## 🔄 Recovering from Compaction?

If your context seems incomplete, or you're resuming after a long gap or compaction event:
1. Check memory state immediately — call `mem_context` only when Engram/MCP read access is configured, authorized, verified, and permitted by memory-use policy
2. `ls naos/active/*.md` then read the active task card — restore scope and acceptance criteria
3. `mem_search "<task-id>"` (e.g., `mem_search "T-235"`) only when read access is configured, authorized, verified, and permitted by memory-use policy — recover task-specific decisions as advisory recall
4. `git status` — see what files were modified in this session
5. Do NOT restart work that memory + git confirm was already completed

If `mem_context` or `mem_search` is unavailable, record degraded recovery and use compact files, task cards, git state, repo governance files, and deterministic reports.

---

## ✅ PHASE 4: GOVERNANCE-POSTURE REVIEW

### Before suggesting changes:

1. ✅ **Rule 1**: Update existing files only (no new analysis/summary files)
2. ✅ **Rule 2**: No archive folders (use git rm for obsolete files)
3. ✅ **Rule 3**: PM status in ONE place (`naos/PROJECT_STATUS.md`)
4. ✅ **Rule 4**: Verify impact on ALL documentation
5. ✅ **Rule 7**: If adding dependencies, follow dependency checklist
6. ✅ **Rule 8**: Inventory & Regeneration Loop completed → `make -f Makefile.naos gov-refresh`
7. ✅ **Rule 10**: Record source licence evidence/approval; no scanner is installed

**Governance Refresh Command**:
```bash
make -f Makefile.naos gov-refresh   # Syncs all derived files + validates coherence
```

### Mandatory Response Sections:

1. **📚 Pre-Task Research Summary**
2. **📄 Files Updated (Not Created)** (list all files to modify)
3. **✅ Impact Validation** (documentation impact check)
4. **🚫 What I Did NOT Do** (governance violations avoided)
5. **📋 Priority Tasks** (List top 3-4 priority tasks based on PROJECT_STATUS.md)
6. **Parallel Lane Posture** (sequential / declared / deferred where known)

---

## 🚀 Ready to Proceed?

**ONLY AFTER**:
- ✅ ALL mandatory context read (governance, specs, operations, security)
- ✅ Existing implementation audited (code, tests, configs)
- ✅ Past research reviewed (`docs/exploration/` or project decision log)
- ✅ **If network available**: do external research; **if not**, note "external research skipped (offline)"
- ✅ Approach validated against architecture AND best practices
- ✅ Governance posture/evidence gaps reviewed

---

**Context Required (Mandatory Reads)**:
```
@.ai/RULES.md
@naos/governance/PROJECT_GOVERNANCE_RULES.md
@CONTRIBUTING.md
@SECURITY.md
@naos/PROJECT_STATUS.md
@naos/TASK_REGISTRY.yaml          ← AUTHORITATIVE SOURCE FOR ALL TASKS
@specs/03-requirements.md        ← AUTHORITATIVE SOURCE FOR FR/NFR
@CHANGELOG.md
@README.md
@specs/01-problem.md
@specs/02-solution.md
@specs/04-architecture.md
[ADAPT: add your project-specific required files here]
```

**⚠️ CRITICAL — AUTHORITATIVE SOURCES**:
- **Tasks**: Get ALL task info from `naos/TASK_REGISTRY.yaml` ONLY
- **Requirements**: Get FR/NFR status from `specs/03-requirements.md` ONLY
- **Never invent task IDs** — use existing T-XXX from registry
- **After changes**: Run `make -f Makefile.naos gov-refresh`

**Research Required (Mandatory Audit)**:
```
docs/exploration/  (list all, read relevant)
```

---

## Next Action (Advisory)

After this session bootstrap is complete, choose the active task and run the task-start workflow before implementation.

```yaml
next_action:
	label: "Begin or resume the active task with a focused story-card check."
	preferred_command: "/naos-task-start <TASK_ID>"
	preferred_agent: "@naos-plan"
	reason: "Context was requested; next is task-scoped planning."
	constraints:
		- "Use the task ID from naos/TASK_REGISTRY.yaml."
		- "Do not start implementation until the active card and scope are clear."
```
