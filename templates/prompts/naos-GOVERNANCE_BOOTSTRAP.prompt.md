# 🔐 GOVERNANCE BOOTSTRAP — Explicit References Only

**Purpose/Scope**: Ordered guidance for an explicit reference; no host auto-load claim.
**Version**: 1.0.0 (Kit Generic Edition)

---

## 📋 GOVERNANCE TRINITY (Cybernetic Control System)

You are part of an integrated 3-layer governance system:

### Layer 1: The Constitution (Specs) — THE TRUTH
**Location**: `specs/01-problem.md` → `specs/10-execution.md`

**Authority**: Single source of truth for requirements and execution plan.
- `specs/03-requirements.md` → FR/NFR definitions (canonical metrics source)
- `specs/10-execution.md` → Task matrix, dependencies, estimates (canonical task source)

**Your Role**: All code, tests, docs, and PM decisions must trace back to specs.

---

### Layer 2: The Administration (PM) — THE AUDIT
**Location**: `naos/PROJECT_STATUS.md`, `naos/TASK_REGISTRY.yaml`, `naos/governance/`

**Authority**: Single source of truth for project state and governance.
- `naos/PROJECT_STATUS.md` → Current phase, milestones, risks, decisions, metrics
- `naos/TASK_REGISTRY.yaml` → Canonical task definitions
- `naos/governance/PROJECT_GOVERNANCE_RULES.md` → Mandatory project rules

**Your Role**: Review these sources for drift; validators check only their coded predicates.

---

### Layer 3: The Behavior Control (AI) — THE POLICE
**Location**: `.ai/RULES.md`, `CONTRIBUTING.md`, `SECURITY.md`

**Authority**: Rules for how you operate within the Constitution and Administration.
**The Core Rules** (see `.ai/RULES.md` for full details):
1. ✅ **Update existing files, NEVER create new** (no session summaries, analyses, action plans as separate files)
2. ✅ **No archive folders ever** (git rm for deletion, history is archive)
3. ✅ **PM status in ONE place** (`naos/PROJECT_STATUS.md` atomic updates)
4. ✅ **Check impact on ALL documentation** (before any change, verify impact on root files, specs, operations, PM)
5. ✅ **Exploration folder is exploration-only** (exempt from governance, not authoritative)
6. ✅ **Refresh README Before Push** (sync README sections before pushing)
7. ✅ **Deep Analysis Protocol** (Evidence-first, exhaustive search, verify claims at source, multi-alternative evaluation, fallback chain design, full documentation, NO DRIFT)
8. ✅ **Bulk Code Migration Safety Protocol** (verify scope, distinguish code from data, AST-verify)
9. ✅ **Ultra Deep Analysis for Enhancements** (impact map, alternatives, fallback, governance update)
10. ✅ **License Compliance** (verify every dependency license)
11. ✅ **Anti-Duplication Protocol** (check FUNCTION_INDEX before creating any function)
12. ✅ **[ADAPT: project-specific data flow invariants]**
13. ✅ **Resilience Conventions** (config timeouts, exponential backoff, fail-fast, no silent swallow)

**Your Role**: Apply the rules. Hook source defines its bounded checks; never bypass an active control.

---

## 🧭 Control-Plane Addendum

NAOS uses preventive, detective, and remediation controls:

- **Preventive**: before generation, read the active task, inspect `FUNCTION_INDEX.yaml`, search source, check related tests/source-to-test mapping, and read relevant capability constraints when present.
- **Preventive**: if `specs/04-architecture.md` changes, verify linkage to specs 01-03, `naos/TASK_REGISTRY.yaml`, `naos/TRACEABILITY_MATRIX.md` where present, affected capabilities, gate/evidence expectations, known gaps, and residual risks.
- **Detective**: after generation, run or request `make -f Makefile.naos naos-function-index-health`, `make -f Makefile.naos naos-module-headers`, `make -f Makefile.naos naos-spec-pack-contract`, `make -f Makefile.naos naos-spec-cascade`, `make -f Makefile.naos naos-test-evidence-map`, `make -f Makefile.naos naos-test-evidence`, `make -f Makefile.naos naos-ac-completion-evidence` when AC/SCEN completion is claimed, `make -f Makefile.naos naos-setup-recommendations`, `make -f Makefile.naos naos-memory-readiness, make -f Makefile.naos naos-memory-use-policy`, `make -f Makefile.naos naos-task-context TASK=<id>` for active-task handoff context, `make -f Makefile.naos naos-task-claim TASK=T-123` for local task-claim coordination metadata, `make -f Makefile.naos naos-task-claims` for claim summary, `make -f Makefile.naos naos-context-index` for generated local candidate indexing, `make -f Makefile.naos naos-context-query QUERY="..."` for bounded candidate references, `make -f Makefile.naos naos-graph-context` for future graph-context readiness, `make -f Makefile.naos naos-graph-query TASK=<id>` for bounded explicit-link relationship candidates, `make -f Makefile.naos naos-evidence-attestation`, `make -f Makefile.naos naos-evidence-conflicts`, `make -f Makefile.naos naos-self-check`, `make -f Makefile.naos naos-systemic-impact`, `make -f Makefile.naos naos-control-plane-review`, `make -f Makefile.naos naos-gate-status`, `make -f Makefile.naos naos-evidence-pack`, and `make -f Makefile.naos naos-dashboard` where installed.
- **Remediation**: if duplicate intent or control drift is suspected, produce findings and options. Do not silently delete, merge, or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code without explicit approval. Safe auto-generation may include evidence placeholders, function-index drafts, source-to-test map drafts, dashboard refresh, and evidence pack refresh where appropriate.

Control-plane self-review applies when agents, skills, prompts, instructions, workflows, specs, task/source traceability, source spec references, module headers, policies, capabilities, gatekeepers, validators, evidence semantics, dashboard semantics, or AI tool surfaces change. Review/routing findings should recommend the next command, agent, prompt, remediation, waiver, or evidence update; they should not silently rewrite the governance system.
When designing or changing a capability, feature, validator, report, prompt, agent, instruction, workflow, doc, source module, or project configuration, use `templates/skills/systemic-capability-wiring/SKILL.md` as the canonical wiring checklist instead of duplicating long local variants.
For adopter setup or module-choice guidance, run or recommend `naos setup-recommendations` and explain choice, rationale, benefit, warning, consequence, and next action; use `naos add setup-module MODULE_ID --profile PROFILE --dry-run` for selected installable modules and never silently enable readiness-only/deferred modules. Before claiming memory or MCP access, run or recommend `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`; memory is advisory recall only, instruction-grade memory requires explicit approval/provenance/scope/reviewer/timestamp/freshness, recall traces are usage records, audit events are records, repo evidence outranks memory, durable writes require configured, authorized, verified, and memory-use-policy-permitted access plus human review, secrets/customer data must not be stored, and unavailable memory means degraded recovery from repo evidence/context. For active-task handoff, run or recommend `naos task-context --task <id>`; treat the pack as derived bounded context, not source artifacts, approval, automatic context injection, or memory evidence. Run or recommend `naos task-claim --task <TASK-ID>` or `make -f Makefile.naos naos-task-claim TASK=T-123` for local task-claim coordination metadata, `naos task-release --task <TASK-ID>` to release it, and `naos task-claims` to summarize; claims are not authorization, approval, ownership proof, separation-of-duties evidence, task completion, exclusive access, conflict resolution, or proof of compliance. Run or recommend `naos context-index` for generated local candidate lookup only, and `naos context-query --query "<keywords>"` for bounded candidate references; query results are candidates, not answers. Run or recommend `naos graph-context` before discussing graph traversal readiness, then `naos graph-query --task <id>` only for bounded explicit-link relationship candidates. Graph-query results are not truth, source authority, or implementation proof, and no NetworkX/GraphML/graph database/graph algorithm/global traversal runtime is enabled by default. The SQLite index is cache-like and not authoritative, with no sqlite-vec, embeddings, graph traversal runtime, Engram/MCP calls, private memory payload indexing, or automatic injection. Run or recommend `naos agent-traces` only for declared trace records; in standard/assured projects, suggest concise `action_receipt` metadata after meaningful agent actions, review checkpoints, or hallucination-sensitive claims when side effects, approval posture, memory trust, or claim-to-evidence review should be explicit. Trace events support StaticGrader/future audit flows but are not proof, approval, memory writes, runtime capture, runtime enforcement, tool-call interception, legal/compliance/regulatory assurance, hallucination prevention, or behavioral safety evidence, and must not contain prompts, private memory payloads, customer data, tenant data, credentials, or secrets. Run or recommend `naos static-grader` after trace validation when deterministic structural grading is useful; StaticGrader costs 0.0 by default, calls no model/API/provider, does not execute trace commands, and does not prove behavioral safety, semantic correctness, runtime behavior, legal/regulatory posture, approval, maturity promotion, or hallucination prevention. For evidence artifacts or reviewer metadata, run or recommend `naos evidence-attestation` and treat local digests as bounded evidence only, not signing, tamper-proof storage, or compliance approval. For spec templates or generated spec files, run or recommend `naos spec-pack-contract` and treat findings as template contract conformance evidence only, not spec quality, requirements completeness, approval, implementation, complete traceability, or proof of compliance. For specs, task registry entries, module headers, source spec references, or source traceability changes, run or recommend `naos spec-cascade` and treat findings as structural review evidence only. When AC/SCEN completion is explicitly claimed, run or recommend `naos ac-completion-evidence` and treat findings as declared evidence-presence review only, not AC correctness, complete coverage, implementation correctness, approval, certification, compliance, or hallucination prevention. For Lite+, require live `naos plan-coherence` readiness before implementation (Lite: 03; Standard/Assured: 03+04); add `--diff-base <ref>` for declared path scope. Readiness is structural evidence, not approval or release authority. For governed artifact-family changes, run or recommend `naos systemic-impact` and update related artifacts or record a known gap, residual risk, waiver, or next action. For governance-surface changes or actionable research/autoresearch findings, update `naos/control_plane_review_items.yaml` and run or recommend `naos control-plane-review`. The reports are review aids, not proof of perfect coherence, research completeness, governance correctness, complete traceability, or code correctness.
Run or recommend `naos grader-assessment --mode audit` or `make -f Makefile.naos naos-grader-assessment MODE=audit` when deterministic grading needs packaging for review. Audit mode is deterministic review input, drift mode compares deterministic reports without semantic drift inference, assess mode summarizes posture rather than certification, zero cost by default remains explicit, and there is no LLMGrader runtime, model/API/provider call, behavioral compliance determination, approval, attestation, or maturity promotion.
Run/recommend `naos model-policy`, `naos model-telemetry`, `naos failure-mode-observations`, and `naos opencode-config-hygiene` only as local review evidence; they do not call providers/models/APIs, validate credentials, route runtime, write learning records, mutate tool/OpenCode config, activate MCP/memory, approve, certify, or prove compliance. Run/recommend `naos design-traceability` and `naos ui-experience-quality` only for optional UI evidence review; they do not call design tools, MCP, browsers, providers, models, memory tools, APIs, mutate tools, approve UI, prove design quality, certify accessibility, or prove compliance.
Run or recommend `naos llm-grader-readiness` or `make -f Makefile.naos naos-llm-grader-readiness` only as readiness-only governance posture. Runtime is disabled by default, no provider/model/API dependency or credential handling is enabled, cost is 0.0 by default, StaticGrader remains primary, future advisory use may incur cost/expose data/drift/be biased, and human approval is required before any future cost-bearing design.
Run or recommend `naos behavioral-readiness` or `make -f Makefile.naos naos-behavioral-readiness` before first behavioral baseline work or after baseline-impacting governance/CI/config evidence changes. It is deterministic readiness and impacter review only: no baseline creation, behavioral grading, model/provider/API call, semantic drift inference, approval, certification, publication, release authorization, or maturity promotion.
Use adopter-facing names: Deterministic Conformance Review is implemented static/file-first checking; StaticGrader is deterministic structural grading over trace/report metadata; Grader Assessment is deterministic audit/drift/assess review input; Model Provider Policy is declaration-only model-role/provider posture review; LLMGrader Readiness is disabled/readiness-only governance posture for a possible future advisory second opinion; Autoresearch Readiness is routing posture; Behavioral Governance Readiness is deterministic baseline-readiness and impacter review. Do not use internal work-item labels or claim semantic behavioral grading exists in the default kit.

Research, autoresearch, trend-review, repo-review, and external-analysis findings should route into capability contracts, central policy, gatekeepers, validators, roadmap/crosswalk, task registry, known gaps, residual risks, evidence pack, dashboard, next-action recommendations, AI instruction surfaces, or specs 01-04 when actionable.

These commands support the existing `/naos-*` workflow and agent handoffs; they do not replace them.

---

## 🔄 Context Sequence (Load in This Order EVERY TIME)

Before executing ANY naos-* command, load this context in sequence:

### ✅ Phase 0: Active Task Context (FOCUS GATE — Read FIRST)
**Files to read**:
- `naos/active/*.md` → Current task constraints (if any card exists)

**What to internalize**:
- Active task cards contain PRE-FILTERED context for current work
- Schemas, existing code, acceptance criteria already extracted
- This is your FOCUS — don't expand beyond these constraints
- If no active card exists, consider creating one using `naos/active/_TEMPLATE.md`

**Purpose**: Prevents context drift by focusing on task-specific constraints.

---

### ✅ Phase 1: Three-Layer Architecture Awareness
**Files to read**:
- `.ai/RULES.md` → Rules, authoritative sources
- `naos/NAOS_QUICK_REFERENCE.md` → Quick reference for workflows

**What to internalize**:
- Three layers exist: Constitution (specs), Administration (pm), Behavior (ai)
- Rules are non-negotiable (Rule 7: Deep Analysis Protocol)
- Hook source defines its checks; other rules require review or another validator

---

### ✅ Phase 2: Development Process Governance
**Files to read**:
- `CONTRIBUTING.md` → SDD lifecycle, Spec-Kit methodology

**What to internalize**:
- Spec-Kit methodology: `specs/01-10` are canonical
- Spec-Driven Development: Specs first, then code, then tests
- **Regeneration gate** (MANDATORY before coding):
  ```bash
  make -f Makefile.naos gov-refresh   # Syncs all derived files, validates coherence
  ```
- Every code change requires traceability headers (FR-XXX, T-XXX comments)
- Every test must use multi-source design (specs/03, specs/06, security guidelines)

---

### ✅ Phase 3: Security & Operations
**Files to read**:
- `SECURITY.md` → Defense-in-depth, encryption, key rotation procedures

**What to internalize**:
- No secrets in code (env vars or secrets mounts only)
- OWASP Top 10 compliance required
- Zero warnings policy: deprecations fixed, not suppressed
- Configuration domain-separated (NOT monolithic), loaded from YAML/env, NOT hard-coded

#### 🔧 Configuration Governance

**❌ FORBIDDEN** — Hardcoded parameters:
```python
# [ADAPT: your language]
batch_size = 100  # Hardcoded!
api_timeout = 30  # Hardcoded!
threshold = 0.85  # Hardcoded!
```

**✅ REQUIRED** — Use central configuration:
```python
# [ADAPT: your config access pattern]
batch_size = settings.scheduler.max_queue_depth
threshold = config.thresholds.auto_approve
```

---

### ✅ Phase 4: Project Governance
**Files to read**:
- `naos/governance/PROJECT_GOVERNANCE_RULES.md` → Mandatory project rules

**What to internalize**:
- Rule #1: [ADAPT: your primary data governance rule — e.g., PII separation, multi-tenancy, schema constraints]
- The hook covers only coded predicates; project rules still require review
- All contributors must follow project governance rules
- Code review reports posture and evidence gaps

---

### ✅ Phase 5: Domain Context (Project-Specific — ADAPT)

> **[ADAPT]** Replace this section with your project's domain-specific context.
>
> Example substitutions:
> - For SaaS: "If working on tenant isolation, read `specs/04-architecture.md` → multi-tenancy section"
> - For data pipelines: "If working on ingestion, read `docs/pipeline-architecture.md`"
> - For APIs: "If working on new endpoints, read `specs/05-api.md` (OpenAPI contract)"
>
> **Suggested items**:
 > - Core domain schema — what is your canonical business object? (e.g., User, Order, Regulation, Asset)
> - Primary business rule: Is it stored in DB or YAML? (business data → DB; app settings → YAML)
> - Architecture decision records relevant to this domain

---

### ✅ Phase 6: Execute the PM Command
Continue with the caller after the requested review; this file proves no host loading.

**Include in every response**:
- Reference to authoritative sources (`specs/03`, `naos/TASK_REGISTRY`, `naos/PROJECT_STATUS`)
- No new files created (Rule 1)
- Impact validation on documentation (Rule 4)
- Rule 8 command checklist if code changes → `make -f Makefile.naos gov-refresh`
- Governance-posture and evidence-gap review

---

## 📊 Authoritative Sources (NEVER Calculate Manually)

**Read these FIRST before suggesting ANY changes**:

| Source | Purpose | Authority | Update Frequency |
|--------|---------|-----------|------------------|
| `specs/03-requirements.md` | FR/NFR definitions | CANONICAL | Changed per spec workflow |
| `specs/10-execution.md` | Task matrix, T-IDs | CANONICAL | Auto-generated from specs/03 + manual |
| `naos/TASK_REGISTRY.yaml` | Task definitions | CANONICAL | Manual updates per phase |
| `naos/PROJECT_STATUS.md` | Current phase, milestones, risks | CANONICAL | Weekly manual + session updates |
| `naos/DASHBOARD.md` | Visual status summary | 🚫 AUTO-GEN | `make -f Makefile.naos gov-refresh` |
| `naos/BACKLOG.md` | Backlog and planned items | 🚫 AUTO-GEN | `make -f Makefile.naos gov-refresh` |
| `naos/TRACEABILITY_MATRIX.md` | FR/NFR ↔ Code linkage | 🚫 AUTO-GEN | `make -f Makefile.naos gov-refresh` |
| `naos/inventory/MASTER_INVENTORY.md` | File inventory | 🚫 AUTO-GEN | `make -f Makefile.naos gov-refresh` |
| `[ADAPT: your ADR location]` | Architecture decisions | CANONICAL | Per architecture decisions |
| `[ADAPT: your domain schema]` | Core domain schema | CANONICAL | Per schema evolution |

**RULES**:
- ✅ Read `specs/03-requirements.md` for current FR/NFR count
- ✅ Read `naos/TASK_REGISTRY.yaml` for current task definitions
- ❌ Do NOT calculate metrics manually from code
- ❌ Do NOT assume old status values; always read `PROJECT_STATUS.md`
