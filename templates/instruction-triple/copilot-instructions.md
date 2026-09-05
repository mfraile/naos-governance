<!-- NAOS Kit: copilot-instructions.md Template (Cluster 1 — Instruction Triple) -->
<!-- This is the PORTABLE GOVERNANCE LAYER — minimal source-project-specific content -->
<!-- Replace [ADAPT: ...] blocks. Keep the protocol/checklist content as-is. -->
# AI Coding Guidelines (NAOS Governance Layer)

> **Project-specific context**: See `.github/project-context.md` for tech stack, module map, schemas, constraints, and pipelines.
> This file contains ONLY portable governance principles.

---

## 🎯 ACTIVE TASK — READ FIRST (Prevents Context Drift)

**Before ANY coding**, check `naos/active/*.md` for current task context.
- If a card exists: READ IT FIRST — it has pre-filtered constraints, schemas, existing code to reuse
- If no card exists: Consider creating one using `naos/active/_TEMPLATE.md`

---

## 🚨 BEFORE WRITING CODE

1. **Search first**: `grep -r "keyword" src/` — Does similar functionality exist?
2. **Check schemas**: See project-context.md for DB models, JSON schemas, API types
3. **Check architecture**: `[ADAPT: path to your architecture doc]` — understand the relevant module/layer
4. **Check existing functions**: `naos/inventory/FUNCTION_INDEX.yaml` — is there a reusable function?
5. **Check related tests**: inspect existing tests and `naos/test_evidence/source_to_test_map.json` when present
6. **Check capability constraints**: read relevant `naos/capabilities/*.yaml` contracts when present
7. **Check spec architecture linkage**: if `specs/04-architecture.md` changes, verify specs 01-03, `naos/TASK_REGISTRY.yaml`, `naos/TRACEABILITY_MATRIX.md` where present, affected capabilities, gate/evidence expectations, known gaps, and residual risks
8. **Present plan** with files to modify, dependencies, evidence to update, and breaking change assessment
9. **Wait for approval** before generating code

---

## Control-Plane Operating Loop

NAOS uses preventive, detective, and remediation controls. AI tools participate in this loop; they do not replace human/profile-based approval.

When a user describes intent in natural language, first route it to an explicit
NAOS workflow: new project -> greenfield adoption; existing repo -> brownfield
adoption; daily task -> `/naos-task-start` when that prompt is installed, else explicit context; PR/release
review -> gate/evidence/dashboard; governance-surface change -> systemic impact
and control-plane review. Recommend visible CLI/Make commands and reports. Do
not silently run adoption, activate hooks, write memory, call providers, approve
work, or treat reports as authority.
When a task is created, selected, or planned, record advisory
`parallel_lane_opportunity` as `not_applicable`, `sequential_recommended`,
`parallel_possible`, or `parallel_recommended`, and record
`parallel_lane_decision` as `sequential`, `declared`, or `deferred`. Suggested
lanes do not activate handoff, dispatch agents, create branches/worktrees,
approve work, merge, release, or prove compliance.

### Preventive Controls — Before Generation

- Read active task context from `naos/active/*.md`.
- Inspect `naos/inventory/FUNCTION_INDEX.yaml` when present.
- Search source for equivalent or related functions before creating new functions.
- Inspect related tests and source-to-test mapping when present.
- Inspect specs and architecture context; architecture changes must link to problem, solution, requirements, task registry, traceability where present, capabilities, gates/evidence, known gaps, and residual risks.
- Record advisory lane opportunity for non-trivial or multi-scope tasks; solo
  developers may use lanes as logical checkpoints, and team lanes use task
  claims plus handoff only when explicitly declared.
- Prefer reuse or targeted refactor over duplicate implementation.
- If a new function is still needed, explain why existing functions are insufficient.

### Detective Controls — After Generation

Run or propose the relevant evidence checks after code changes:

```bash
make -f Makefile.naos naos-function-index-health
make -f Makefile.naos naos-module-headers
make -f Makefile.naos naos-spec-pack-contract
make -f Makefile.naos naos-spec-pack-materialize
make -f Makefile.naos naos-spec-assembly-worksheet
make -f Makefile.naos naos-spec-cascade
make -f Makefile.naos naos-test-evidence-map
make -f Makefile.naos naos-test-evidence
make -f Makefile.naos naos-ac-completion-evidence
make -f Makefile.naos naos-setup-recommendations
make -f Makefile.naos naos-memory-readiness, make -f Makefile.naos naos-memory-use-policy, make -f Makefile.naos naos-learning-loop-review, make -f Makefile.naos naos-adapter-coherence
make -f Makefile.naos naos-task-context TASK=<id>
make -f Makefile.naos naos-context-index
make -f Makefile.naos naos-context-query QUERY="..."
make -f Makefile.naos naos-graph-context
make -f Makefile.naos naos-evidence-attestation
make -f Makefile.naos naos-evidence-conflicts
make -f Makefile.naos naos-systemic-impact
make -f Makefile.naos naos-ai-surface-budget
make -f Makefile.naos naos-self-check
make -f Makefile.naos naos-gate-status
make -f Makefile.naos naos-evidence-pack
make -f Makefile.naos naos-dashboard
```

Use direct scripts if the Make targets are not installed for the selected profile.

### Remediation Controls — Human-Reviewed

- If semantic overlap or duplicate intent is suspected, produce a finding and remediation options.
- Do not silently delete, merge, or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code.
- For risky changes, propose the patch, evidence updates, and residual-risk note, then wait for explicit human/profile-based approval.
- Safe auto-generation may include evidence placeholders, function-index drafts, source-to-test map drafts, dashboard refresh, and evidence pack refresh where appropriate.

### Governance-Surface Review

When `SKILL.md`, `.agent.md`, `*.instructions.md`, prompts, workflows, specs, module headers, policies, capabilities, gatekeepers, validators, evidence semantics, dashboard semantics, or AI tool surfaces change, perform control-plane self-review.
When designing or changing a capability, feature, validator, report, prompt, agent, instruction, workflow, doc, source module, or project configuration, use the installed NAOS wiring skill under `.github/skills/` instead of duplicating long local variants. Skill availability is profile-gated: quickstart installs no project skills, lite installs a core subset, standard installs `.github/skills/systemic-wiring/SKILL.md`, and assured installs the full catalogue including `.github/skills/systemic-capability-wiring/SKILL.md`. Use `systemic-capability-wiring` when it is installed; otherwise use `systemic-wiring` plus `naos systemic-impact` / `naos control-plane-review` for the same review obligation. Do not claim a named skill was loaded if the file is not present in `.github/skills/`.
Run or recommend `naos ai-surface-budget --profile <profile>` when prompts, agents, skills, instructions, workflows, manuals, quick references, or governance docs change; it reports static context pressure, anchors, combined loadout, and baseline drift without preventing hallucinations, grading behavior, auto-tuning thresholds, or approving baseline changes.
For a full command inventory, use `naos/NAOS_QUICK_REFERENCE.md`. Keep this file as the compact always-loaded layer:
- Setup/modules/policy: `naos setup-recommendations`, `naos add setup-module MODULE_ID --dry-run`, and `naos policy-overrides --dry-run` are advisory configuration flows; they do not authenticate, authorize, activate deferred runtimes, approve work, or prove compliance.
- Memory/context/session/learning/adapters: `naos memory-readiness`, `naos memory-access`, `naos memory-use-policy`, `naos learning-loop-review`, `naos adapter-coherence`, `naos task-context`, `naos session-*`, `naos operator-attribution`, `naos audit-log`, and `naos task-claims` produce recall, learning, adapter, context, records, or coordination metadata only. They do not inject context, write memory, mutate governed artifacts, prove live plugin installation, prove identity, lock tasks, or replace human review.
- Index/semantic/graph: `naos context-index`, `naos context-query`, `naos semantic-candidates`, `naos graph-context`, and `naos graph-query` produce bounded candidates/readiness only, not answers, truth, source authority, implementation proof, hallucination prevention, provider/API calls, memory payload search, or graph-runtime enablement.
- Grading/evidence: `naos agent-traces`, `naos static-grader`, `naos grader-assessment --mode audit`, `naos model-policy`, `naos failure-mode-observations`, `naos opencode-config-hygiene`, `naos design-traceability`, `naos ui-experience-quality`, `naos llm-grader-readiness`, `naos behavioral-readiness`, `naos evidence-attestation`, `naos evidence-conflicts`, and `naos sarif-export` are deterministic/file-first or readiness-only review inputs. They do not approve, certify, attest, promote maturity, prove behavior, create baselines, call models/providers, validate credentials, recommend models, route runtime calls, run OpenCode, write learning records, activate MCP/memory, mutate design tools, or prove UI quality by default. For standard/assured projects, use concise `action_receipt` metadata for side effects, approvals, memory trust, or claim evidence; never store prompts, private data, credentials, or secrets.
- AI-surface remediation: when `ai-surface-budget` reports `warning` or `degraded`, use `.github/skills/ai-surface-health-review/SKILL.md` where installed; preserve anchors and do not hide findings by inflating thresholds.
- Governed learning: when a lesson may affect future behavior, use `.github/skills/governed-learning-lifecycle/SKILL.md` where installed; candidate learning is proposal-only and active learning requires evidence, scope, review, approval, and review/expiry metadata.
- Governed coding execution: when implementing or materially changing code, config, schema, workflow, or governance surfaces, and before claiming work done/fixed/passing, use `.github/skills/governed-coding-execution/SKILL.md` where installed; it produces an evidence-backed completion ledger and does not approve, certify, or replace human review.
Use adopter-facing names: Deterministic Conformance Review is implemented static/file-first checking; StaticGrader is deterministic structural grading over trace/report metadata; Grader Assessment is deterministic audit/drift/assess review input; LLMGrader Readiness is disabled/readiness-only governance posture for a possible future advisory second opinion; Autoresearch Readiness is routing posture; Behavioral Governance Readiness is deterministic baseline-readiness and impacter review. Do not use internal work-item labels or claim semantic behavioral grading exists in the default kit.

- Skills: review frontmatter, parameters, when-to-invoke rules, overlap, authority, and recommend update/merge/deprecate/keep/defer.
- Agents: review model/tools/frontmatter, role boundaries, handoff rules, least privilege, risky auto-fix behavior, and mapping to commands, prompts, capabilities, policy, validators, evidence, and dashboard.
- Instructions/tool surfaces: review `applyTo`, contradictions across Claude/Copilot/Cursor/.ai/AGENTS.md, claim-control wording, preventive/detective/remediation rules, and source/function-index inspection.
- Workflow prompts: review next-action routing, command/agent handoff, capability/policy/validator/gate/evidence/dashboard mapping, and human/profile-based approval for risky remediation.
- Research/autoresearch/trend-review outputs: create or update `naos/control_plane_review_items.yaml` where disposition tracking is useful, then route actionable findings into capability contracts, central policy, gatekeepers, validators, roadmap/crosswalk, task registry, known gaps, residual risks, evidence pack, dashboard, next-action recommendation, AI instruction surfaces, or specs 01-04.

This review is advisory/profile-aware unless an implemented validator or gate enforces it.

---

## 🧠 Domain Mindsets

When the conversation topic implies a specific domain, adopt that domain's judgment heuristics:

- **Security-related**: Prioritize hardening over convenience; assume adversarial input; consult `[ADAPT: your security instructions path]`.
- **Architecture-related**: Prioritize clean interfaces over build speed; verify boundary compliance. Consult `[ADAPT: your architecture doc]`.
- **Testing-related**: Prioritize coverage over speed; use project actual DB schemas and fixtures. Consult `[ADAPT: your acceptance spec]`.
- **Refactoring**: Prioritize behavior preservation over code elegance; require regression tests before and after changes; verify no function duplication.
- **Planning / PM**: Prioritize scope discipline; read active task card in `naos/active/*.md` before advising.

---

## 🔬 DEEP ANALYSIS PROTOCOL (MANDATORY — ALL TASKS)

### The 7 Non-Negotiable Principles

| # | Principle | Anti-Pattern (NEVER do this) |
|---|-----------|-----------------------------|
| 1 | **Evidence-First**: Test on real project files, not toy examples | "This library should work" without testing |
| 2 | **Exhaustive Impact Search**: `grep -r`, `find`, semantic search — find ALL affected files | Fixing 2 of 9 affected files |
| 3 | **Verify Claims at Source**: `pip show`, read LICENSE, check actual behavior | Trusting a GitHub README |
| 4 | **Multi-Alternative Evaluation**: Test 3+ options, create decision matrix | Picking the first result |
| 5 | **Fallback Chain Design**: Graceful degradation, nothing breaks during migration | Hard-swapping with no safety net |
| 6 | **Full Scope Documentation**: Task card with motivation, evidence, AC, risks | "I changed it" with no audit trail |
| 7 | **No Drift**: Stay within task scope, do not expand into adjacent problems | Fixing X while also refactoring Y |

### When to Apply

| Trigger | Minimum Principles |
|---------|--------------------|
| `ultrathink` / `think deeply` | ALL 7 — full protocol |
| `analyse` / `evaluate` | 1-4 (evidence, search, verify, compare) |
| Any library/dependency change | 1-5 (always verify license, test, design fallback) |
| Any bug investigation | 1-2 (evidence-first, find ALL occurrences) |
| Any feature implementation | 2, 5-7 (impact search, docs, no drift) |
| Any code change | At minimum #2 (exhaustive search) |

---

## 📝 Code Conventions

### Cognitive Checkpoint (NAOS Rule 26)
At phase transitions (plan→code→test→commit), non-obvious discoveries, ≥5 consecutive
tool calls without a checkpoint, and pre-handoff to another agent, persist a cognitive
checkpoint. If Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, use `mem_save`;
otherwise write the same payload to the active compact/task card. Minimum:
what + why + files + remaining + gotchas.

If Engram is already installed, verify project connection with `naos memory-readiness`
and `naos memory check`.
If memory is deferred or disabled in `configs/naos_memory.yaml`, preserve the same
checkpoint fields in the active compact/task card and state that recovery is degraded.

### Commit Format
```
feat(T-XXX): description
fix(T-XXX): description
```

### Module Header
```python
"""
Module: src/path/to/module.py

Purpose:
    Short module-level description.

Implements:
    - FR-XXX: Requirement/control name
    - NFR-XXX: Non-functional requirement/control name

Tasks:
    - T-XXX: Task title
    - T-YYY: Task title

Specs:
    - specs/03-requirements.md#fr-xxx
    - specs/04-architecture.md#architecture-section

Rationale:
    Short paragraph explaining why this module exists, why the logic belongs
    here, what boundary it owns, and how it avoids duplication or architecture
    drift.

Design notes:
    - Optional stable architectural constraints/patterns.
"""
```

Use one module header per source module. Do not create duplicate/stale module
docstrings with overlapping metadata; update the existing header when purpose or
boundaries materially change.

After adding or materially changing source modules, run or recommend
`naos module-headers` and, when specs, tasks, source headers, source spec
references, profile-required spec files, brownfield evidence, or source traceability changed,
`naos spec-pack-contract`, `naos spec-pack-materialize --dry-run`, `naos spec-assembly-worksheet`, and `naos spec-cascade` as applicable. Treat findings as traceability review evidence; do not
auto-rewrite all headers blindly or treat structural traceability as
code-correctness, filled-content, candidate-promotion, or spec-quality proof.

<!-- BEGIN SYNC_TASK_CAPABILITY_MATRIX -->
## Task-Capability Matrix

> Pick the right tool for the task. Rows are task archetypes (MIT CSAIL spectrum, greenfield → long-horizon debugging); columns are the recommended NAOS profile, the cognitive bracket to pre-declare, and the skills/agents to prefer. Preferred skills are names under `.github/skills/<skill-name>/SKILL.md` when installed for the selected profile. Anything outside this matrix defaults to **Standard / MODERATE** and triggers a Rule 26 checkpoint.

| Task archetype | Recommended profile | Recommended PAUL bracket | Preferred skills / agents |
|---|---|---|---|
| Greenfield scaffolding | `lite` or `standard` | FRESH | `cookbook-*`, `function-discovery` |
| Refactor in single bounded context | `standard` | MODERATE | `function-discovery`, `cognitive-checkpoint` |
| Bugfix with reproducible failing test | `standard` | MODERATE | `debug`, `cognitive-checkpoint` |
| Long-horizon debugging | `assured` | DEEP → CRITICAL | `debug`, `instinct-observer`, `strategic-compact` |
| Spec extraction / code archaeology | `standard` | MODERATE | `spec-extract`, `function-discovery` |
| Performance / capacity | `standard` or `assured` | DEEP | `debug`, `instinct-observer` |
| Governance refresh | `standard` | MODERATE | `gov-refresh`, `cognitive-checkpoint` |
| Multi-agent orchestration | `assured` | DEEP | `strategic-compact`, `cognitive-checkpoint` |

**Override rule.** Disagreement with the matched row REQUIRES a Rule 26 T2 checkpoint justifying the divergence.
<!-- END SYNC_TASK_CAPABILITY_MATRIX -->

<!-- BEGIN SYNC_ANTI_DUPLICATION -->
## Anti-Duplication Protocol (Rule 11)

> Before ANY function: check `naos/inventory/FUNCTION_INDEX.yaml` + `grep -r "def fn_name" src/`. After creating: `python scripts/naos_code_quality_audit.py --generate-index`.
<!-- END SYNC_ANTI_DUPLICATION -->

<!-- BEGIN SYNC_PRE_CODING_CONTEXT -->
## Pre-Coding Context Protocol (Rule 17)

> Before ANY `src/` function: (1) inspect `naos/inventory/FUNCTION_INDEX.yaml` when present (2) search source for names and domain keywords (3) use project-configured similarity only when available (4) populate "Existing Code to Use" in story card.
<!-- END SYNC_PRE_CODING_CONTEXT -->

---

## 📚 Key Reference Files

[ADAPT: Update with your project's actual file paths]

| Purpose | File |
|---------|------|
| **Project Context** | `.github/project-context.md` — tech stack, schemas, constraints |
| **Custom Agents** | `.github/agents/AGENTS.md` — agent index, model assignments |
| **Governance Rules** | `.ai/RULES.md` |
| **Active Task** | `naos/active/*.md` — READ FIRST before coding |
| **Requirements** | `[ADAPT: specs/03-requirements.md]` |
| **Task Registry** | `naos/TASK_REGISTRY.yaml` — SINGLE SOURCE OF TRUTH for tasks |
| **Function Index** | `naos/inventory/FUNCTION_INDEX.yaml` |
