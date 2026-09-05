<!-- NAOS Kit: CLAUDE.md Template (Cluster 1 — Instruction Triple) -->
<!-- Strip all [ADAPT: ...] blocks and replace with project content -->
<!-- This file is read automatically by Claude Code at session start -->

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Layered context**: This file is comprehensive for Claude (verbosity helps).
> For the portable governance layer, see `.github/copilot-instructions.md`.
> For project-specific context (tech stack, schemas, constraints), see `.github/project-context.md`.
> For custom agents and handoff workflows, see `.github/agents/AGENTS.md`.

> **Claude Code / Cursor users**: At session start, read `.github/copilot-instructions.md` — it contains the governance protocols (Deep Analysis Protocol, Domain Mindsets, Code Conventions) that apply to all AI coding tools.

## Project Overview

[ADAPT: 1-3 sentences describing the project purpose, domain, and key differentiator.
Keep this high-level — details go in project-context.md.]

## Build & Development Commands

```bash
# Environment setup
$signal_install_cmd

# Database (if applicable)
$signal_migrate_cmd

# Development server
$signal_run_cmd

# Testing — IMPORTANT: Read "Test Execution" section below
$signal_test_cmd

# Governance (before commits)
make -f Makefile.naos gov-refresh   # Inventory → specs → headers → dashboard (run after task/scope changes)
make -f Makefile.naos gov-full      # gov-refresh + truth validation
make -f Makefile.naos naos-self-check
make -f Makefile.naos naos-memory-readiness, make -f Makefile.naos naos-memory-use-policy, make -f Makefile.naos naos-learning-loop-review, make -f Makefile.naos naos-adapter-coherence
make -f Makefile.naos naos-task-context TASK=<id>
make -f Makefile.naos naos-context-index
make -f Makefile.naos naos-context-query QUERY="..."
make -f Makefile.naos naos-graph-context
make -f Makefile.naos naos-policy-overrides
make -f Makefile.naos naos-ai-surface-budget
make -f Makefile.naos naos-static-grader
make -f Makefile.naos naos-grader-assessment MODE=audit
make -f Makefile.naos naos-model-policy
make -f Makefile.naos naos-llm-grader-readiness
make -f Makefile.naos naos-evidence-attestation
make -f Makefile.naos naos-evidence-conflicts
make -f Makefile.naos naos-evidence-pack
make -f Makefile.naos naos-dashboard
```

## Control-Plane Discipline

Route only through installed surfaces: Quickstart research; Lite its task
lifecycle; Standard/Assured the full prompt/agent catalogue.

When a user states a goal in natural language, route it to the visible NAOS
workflow before recommending implementation: new project -> `naos adopt --mode
greenfield --dry-run`; existing repo -> `naos adopt --mode brownfield
--dry-run`; daily task -> `/naos-task-start` when installed, else explicit task context; PR/release
review -> gate/evidence/dashboard commands; governance-surface change ->
`naos systemic-impact` and `naos control-plane-review`. Recommend commands and
reports explicitly; do not silently execute adoption, activate hooks, write
memory, call providers, approve work, or treat reports as authority.

Use `naos policy-overrides --profile <profile> --dry-run` or `make -f Makefile.naos naos-policy-overrides` before relying on adopter-local overlays. Static YAML overlays support global and optional team/operator scopes selected by `naos/team_operator_map.yaml` or explicit flags. Team/operator overlays are configuration only, not authentication, authorization, access control, identity proof, or separation-of-duties satisfaction. Executable adopter plugin runtime remains deferred; the Codex and Claude Code plugin sources are optional operator adapters over project-local NAOS artifacts, not source authority. Overlays cannot weaken ADR-0010: Control-Plane Advisory Boundaries, turn advisory findings into authority, or enable memory write-back, MCP/Engram runtime, sqlite-vec, graph runtime, LLMGrader runtime, cloud memory, provider credentials, or signing by NAOS. Team gatekeeper config resolves gate severity/enabled posture from local team context; use `make -f Makefile.naos naos-gate-status TEAM_ID=platform` or `make -f Makefile.naos naos-gate-evaluate TEAM_ID=platform`. It is governance configuration, not authorization, access control, team-membership proof, approval, proof of compliance, or separation-of-duties satisfaction.

Use `naos pr-risk-classify --profile <profile>` or `make -f Makefile.naos naos-pr-risk-classify` before PR governance summary when local diff risk evidence is needed, then use `naos pr-governance-summary --profile <profile>` or `make -f Makefile.naos naos-pr-governance-summary` after PR-time gate, evidence, dashboard, evidence-conflict, task-claim, and PR-risk reports run. The workflow example at `templates/workflows/naos-pr-governance.yml.example` is not auto-installed; adopters must review and copy it explicitly. `TEAM_ID` and `NAOS_OPERATOR_ID` are governance metadata only, artifacts require sensitivity review before upload, and CI output is not PR approval, malware analysis, sandbox execution, security proof, deployment authorization, release authorization, proof of compliance, authentication, authorization, access control, separation-of-duties satisfaction, or conflict resolution.

NAOS is tool-neutral by default. Optional templates under `templates/integrations/` may help teams using Spec-Kit, Claude Code hooks, Claude Code plugin guidance, or Codex plugin guidance, but they must be copied through review-first setup modules into `naos/integrations/` and manually activated if desired. Do not treat them as core dependencies, official third-party support, plugin cache mutation, Claude settings mutation, silent context injection, memory write-back, provider/API calls, approval, certification, or proof of compliance.

Before coding, inspect task context, `FUNCTION_INDEX.yaml`, tests,
source-to-test mapping, capability constraints, and spec/architecture context.
`parallel_lane_opportunity`; `parallel_lane_decision`. If
`specs/04-architecture.md` changes, check linkage to
`specs/01-problem.md`, `specs/02-solution.md`, `specs/03-requirements.md`,
`naos/TASK_REGISTRY.yaml`, `naos/TRACEABILITY_MATRIX.md` where present, affected
capabilities, gate/evidence expectations, known gaps, and residual risks. Prefer
reuse or targeted refactor over duplication. If a new function is necessary,
justify why existing functions are insufficient.

After generation, run or propose relevant detective checks: function-index
health, module headers, spec-pack, spec-cascade, source-to-test/test-evidence,
claimed AC/SCEN evidence, claims, self-check, systemic impact, gates, evidence
pack, and dashboard. Treat remediation as a proposed patch plus
evidence update; do not silently delete, merge, or rewrite security, encryption,
authentication, authorization, database, public API, or regulatory-control code
without explicit approval.

If agents, skills, prompts, instructions, workflows, specs, task/source traceability, source spec references, module headers,
policies, capabilities, gatekeepers, validators, evidence semantics, dashboard
semantics, or AI tool surfaces change, perform control-plane self-review. Create
or update `naos/control_plane_review_items.yaml` where disposition tracking is
useful, then route actionable research/autoresearch/trend-review findings into the appropriate
capability, policy, gate, validator, roadmap/crosswalk, task, known gap,
residual risk, evidence pack, dashboard, next action, instruction surface, or
spec. This review is not fully automated unless an implemented validator/gate
exists.
For governance-surface changes, use `.github/skills/` guidance: standard has
`.github/skills/systemic-wiring/SKILL.md`; assured may have
`.github/skills/systemic-capability-wiring/SKILL.md`. Prefer
`systemic-capability-wiring` only when its file exists; otherwise use
`systemic-wiring` plus `naos systemic-impact` / `naos control-plane-review`.
Do not claim a named skill was loaded if the file is not present in `.github/skills/`.
When orienting adopters or module choices, run or recommend
`naos setup-recommendations` and explain rationale, benefit, warning,
consequence, and next action without silently enabling modules.
Before claiming memory or MCP access, run or recommend `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`;
memory is advisory recall only, instruction-grade memory requires explicit approval/provenance/scope/reviewer/timestamp/freshness, recall traces are usage records, audit events are records, repo evidence outranks memory, durable writes
require authorization and human review, secrets/customer data must not be stored,
and unavailable memory means degraded recovery from repo evidence/context.
Before treating a lesson as active guidance or using it to change skills, prompts, workflows, baselines, gates, maturity, or instructions, run or recommend `naos learning-loop-review`; candidate learning is proposal-only and active learning requires evidence, scope, review, approval, retrieval policy, and review/expiry metadata.
After plugin, integration, skill, instruction, workflow, MCP-posture, or governed-learning propagation changes, run or recommend `naos adapter-coherence`; adapter reports are static review evidence, not live plugin installation proof or adapter auto-repair.
For active-task handoff, run or recommend `naos task-context --task <id>`;
the pack is derived, bounded, and non-authoritative, memory references inside it
are advisory only, and it does not inject context automatically or approve work.
Run or recommend `naos session-id` or `make -f Makefile.naos naos-session-id`
to create/reuse a session id and namespaced report root; session-specific
reports live under `naos/sessions/<session_id>/reports/`, latest `naos/reports/`
remains compatibility output. Run or recommend `naos operator-attribution` or
`make -f Makefile.naos naos-operator-attribution` to record local operator
attribution for who initiated the run/session. Operator attribution is not
identity proof, authentication, authorization, task ownership, locking,
separation-of-duties evidence, non-repudiation, or approval. Run or recommend
`naos audit-log` or `make -f Makefile.naos naos-audit-log` to summarize
append-only audit events; audit events record what happened over time and are
not approval, non-repudiation, cryptographic signing, tamper-proof storage,
task locking, evidence conflict detection, compliance approval, or source of
truth. Run or recommend `naos evidence-conflicts` or
`make -f Makefile.naos naos-evidence-conflicts` to flag deterministic
evidence/review conflicts for human review; it does not resolve conflicts,
adjudicate evidence correctness, prove separation of duties, approve work, lock
tasks, or prove compliance. Use `naos task-claim --task <TASK-ID> --profile <profile>` or `make -f Makefile.naos naos-task-claim TASK=T-123` to record local task-claim coordination; use `naos task-release --task <TASK-ID>` or `make -f Makefile.naos naos-task-release TASK=T-123` to release it, and `naos task-claims` or `make -f Makefile.naos naos-task-claims` to summarize claims. Claims are coordination metadata only: a claim does not authorize work, approve a task, prove task ownership or separation of duties, mark completion, create exclusive access, resolve evidence conflicts, or prove compliance. Conflicts and stale claims require human review. M3 adds local SQLite write coordination through
`naos context-index`, M4 adds audit history, M5 adds evidence conflict
detection, M6 adds task claim/release coordination metadata, M7 adds static
team/operator policy overlay scopes, M8 adds team-scoped gatekeeper posture,
M9 adds PR-time CI evidence templates, and P1 adds optional tool integration templates plus adapter-coherence review; authorization-backed task locking,
release approval, deployment authorization, and public-release re-audit remain
separate human-governed steps.
For daily workflow coordination, run or recommend `naos session-start --task <id>`,
`naos session-checkpoint --task <id>`, and `naos session-end --task <id>` as
bounded lifecycle reports/checklists. They do not mutate task cards, write
compact files, approve work, inject context automatically, or write memory.
Memory candidates are proposal_only and not_written.
Run or recommend `naos context-index` only for generated local candidate lookup;
it also emits SQLite write coordination posture for local lock/temp/atomic-replace
index file integrity, not task locking, evidence conflict detection,
distributed locking, or full multi-user completion. Run or
recommend `naos context-query --query "<keywords>"` for bounded candidate
references. Query results are candidates, not answers. The index is cache-like
and not authoritative, with no sqlite-vec, embeddings, graph traversal,
Engram/MCP calls, or automatic injection.
Run or recommend `naos graph-context` before discussing graph traversal
readiness; graph links are relationship candidates, not source of truth, and no
NetworkX/GraphML/graph database/graph algorithm/global traversal runtime is
enabled by default.
Run or recommend `naos agent-traces` only when manually declared trace or
`action_receipt` records exist; trace events are records for StaticGrader/future
audit flows, not proof, approval, memory writes, runtime capture,
legal/compliance/regulatory assurance, hallucination prevention, or behavioral
safety evidence, and they must not contain secrets or private payloads.
Run or recommend `naos harness-trace-import --source <repo-local.jsonl>` only
when an explicit local harness export exists; default mode is report-only and
does not execute harnesses, capture runtime events, call providers, or write
memory.
Run/recommend `naos ai-surface-budget` after AI-surface changes; it reports
context pressure and drift only, not hallucination prevention, behavior grading,
threshold tuning, or approval.
Run/recommend `naos static-grader` after trace validation when useful. It is
zero-cost by default, calls no model/API/provider, executes no trace commands,
and proves no behavior, safety, legality, approval, maturity, or correctness.
Run/recommend `naos grader-assessment --mode audit` when deterministic grading
needs review packaging. Audit/drift/assess are deterministic summaries only;
no LLMGrader runtime, provider/model call, behavioral compliance decision,
approval, attestation, or maturity promotion.
Run/recommend `naos model-policy` for model/provider declarations only; no
calls, credentials, recommendations, routing, approval, or compliance conclusion.
Run/recommend `naos opencode-config-hygiene` only for optional repo-local
OpenCode config review; no execution, global config, MCP/memory, providers,
models, credentials, plugins, mutation, approval, or certification.
Run/recommend `naos failure-mode-observations` only for local observation
statistics over configured NAOS reports; it does not read control-plane review
as input, write learning records, call providers/models/APIs, activate
MCP/Engram/memory, approve, certify, or prove compliance.
Run/recommend `naos design-traceability`/`naos ui-experience-quality` only when
enabled; no calls, mutation, approval, certification, or compliance.
Run/recommend `naos llm-grader-readiness` as readiness only: no runtime,
providers, credentials, cost runtime, or StaticGrader/human-review replacement.
Run/recommend `naos evidence-attestation` for evidence/reviewer metadata only;
not signing, tamper-proof storage, or compliance approval.
When governed artifact families change, run or recommend `naos systemic-impact`
and update related artifacts or record a known gap, residual risk, waiver, or
next action. When governance-surface changes or actionable research/autoresearch
findings need disposition, update `naos/control_plane_review_items.yaml` and run
or recommend `naos control-plane-review`. Treat these reports as review evidence,
not proof of perfect coherence, research completeness, or governance correctness.
Use adopter-facing names: Deterministic Conformance Review is implemented
static/file-first checking; Autoresearch Readiness is routing posture;
Behavioral Governance Readiness is deterministic baseline-readiness and
impacter review. Do not use internal work-item labels or claim
semantic/model-backed behavioral grading exists in the default kit.

## Architecture

[ADAPT: describe your architecture briefly. Include:]
- The key architectural pattern (e.g., MVC, microservices, event-driven, hexagonal)
- The main data flows
- Any critical design decisions that affect how AI agents should write code

```
[ADAPT: ASCII or text diagram of your architecture if helpful]
```

### Source Structure

```
[ADAPT: key directories and their purpose]
src/
├── [module-1]/    # [purpose]
├── [module-2]/    # [purpose]
└── ...
```

## Key Constraints

### [ADAPT: Framework/Stack-Specific Rules]

[ADAPT: List the most important coding constraints for your stack. Examples:
- "Never use datetime.utcnow() — use timezone-aware alternatives"
- "Always use parameterized queries — no string formatting in SQL"
- "Never hard-code config values — use configs/*.yaml"
- "All new endpoints require auth dependency"]

### Database Rules

[ADAPT: List your database conventions. Examples:
- Schema naming conventions
- Which tables contain PII and require encryption
- Migration strategy
- Connection pool settings]

### Configuration

[ADAPT: How to access config in this project.
Example: "Load from configs/*.yaml. Access via from src.core.config import settings. Never hard-code config values in src/"]

## Code Conventions

### Commit Messages

```
feat(T-XXX): description
fix(T-XXX): description
docs: description
```

### Module Header (Python)

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

Use plural labels. Keep `Rationale` concise and module-level. Update the existing
header when purpose changes; do not create a second module header or stale
duplicate metadata docstring.

After source changes, run `naos module-headers`. If specs, profile files,
brownfield evidence, tasks, headers/references, or traceability changed, run the
applicable spec lifecycle checks: `naos spec-pack-contract`, `naos
spec-pack-materialize --dry-run`, `naos spec-assembly-worksheet`, `naos
spec-cascade`. Treat findings as review evidence; do not auto-rewrite headers or
claim correctness, filled specs, candidate promotion, or spec quality.

### Datetime & Timezone Standards

[ADAPT: Specify your project's datetime conventions. Examples:
- Python: "Use timezone-aware datetimes. Never datetime.utcnow(). Use datetime.now(UTC)."
- JavaScript: "Use date-fns with UTC. Never new Date() without timezone handling."
- Go: "Use time.UTC() consistently. Store as UTC in database."]

## Task-Capability Matrix

> Pick the right task tool. Skills live under `.github/skills/<skill-name>/SKILL.md` when installed. Unlisted tasks default to **Standard / MODERATE / no specialised skill** and trigger Rule 26.

| Task archetype | Recommended profile | Recommended PAUL bracket | Preferred skills / agents |
|---|---|---|---|
| Greenfield scaffolding (new module, new repo) | `lite` or `standard` | FRESH | `cookbook-*` (language-appropriate), `function-discovery` |
| Refactor within a single bounded context | `standard` | MODERATE | `function-discovery`, `cognitive-checkpoint` |
| Bugfix with reproducible failing test | `standard` | MODERATE | `debug`, `cognitive-checkpoint` |
| Long-horizon debugging (intermittent / multi-system) | `assured` | DEEP → CRITICAL | `debug`, `instinct-observer`, `strategic-compact` |
| Spec extraction from docs / code archaeology | `standard` | MODERATE | `spec-extract`, `function-discovery` |
| Performance / capacity work | `standard` or `assured` | DEEP | `debug`, `instinct-observer` |
| Governance refresh / drift remediation | `standard` | MODERATE | `gov-refresh`, `cognitive-checkpoint` |
| Multi-agent orchestration / handoff | `assured` | DEEP | `strategic-compact`, `cognitive-checkpoint` |

**Override rule.** If the agent disagrees with the matched row, it MUST emit a Rule 26 T2 checkpoint ("non-obvious discovery") justifying the divergence before proceeding.

## Test Execution

[ADAPT: Describe how to run tests correctly. Include:
- The exact test command(s)
- Required environment variables or setup steps
- Any known pitfalls (buffering, env vars, etc.)]

```bash
# ADAPT: Replace with your actual test commands
# Step 1: [ADAPT: activate environment]
# Step 2: [ADAPT: load env vars if needed]
# Step 3: [ADAPT: run tests]

# Examples:
pytest -q tests/unit tests/acceptance
npm test
go test ./...
```

## Key Reference Files

[ADAPT: Update this table with your project's actual files]

| Purpose | File | Editable? |
|---------|------|:---------:|
| **Active Task (READ FIRST)** | `naos/active/*.md` | ✅ Manual |
| **Requirements** | `[ADAPT: specs/03-requirements.md]` | ✅ Manual |
| **Task Registry** | `naos/TASK_REGISTRY.yaml` | ✅ Manual — SINGLE SOURCE OF TRUTH for tasks |
| **DB Models** | `[ADAPT: src/db/models.py]` | ✅ Manual |
| **Config Files** | `configs/` | ✅ Manual |
| **Dashboard** | `naos/DASHBOARD.md` | 🚫 Auto-generated (`make -f Makefile.naos gov-refresh`) |
| **Function Index** | `naos/inventory/FUNCTION_INDEX.yaml` | 🚫 Auto-generated |
