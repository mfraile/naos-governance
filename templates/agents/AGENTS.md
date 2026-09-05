# Custom Agents Index

> **Governance**: `.ai/RULES.md` Rule 18 (Agent & Skill Governance)
> **Project Context**: `.github/project-context.md`

<!-- ADAPT: Update agent names, models, roles, and files for your team. -->

## Agent Inventory

This is a superset. Quickstart installs only `@naos-research`; Lite adds plan,
implement, and review; Standard/Assured add triage, debug, and conformance.

| Agent | Model | Role | Purpose | File |
| ------- | ------- | --------- | --------- | ------ |
| `@naos-plan` | [ADAPT: model] | `planning` | Planning, analysis, task decomposition | `naos-plan.agent.md` |
| `@naos-implement` | [ADAPT: model] | `implementation` | Code generation, file editing, tests | `naos-implement.agent.md` |
| `@naos-review` | [ADAPT: model] | `review` | Code and governance-evidence review | `naos-review.agent.md` |
| `@naos-conformance` | [ADAPT: model] | `conformance` | Governance/evidence-gap review | `naos-conformance.agent.md` |
| `@naos-triage` | [ADAPT: model] | `triage` | Issue classification, priority assessment | `naos-triage.agent.md` |
| `@naos-debug` | [ADAPT: model] | `debug` | No-direct-edit diagnosis and root-cause guidance | `naos-debug.agent.md` |
| `@naos-research` | [ADAPT: model] | `research` | Read-only evidence gathering | `naos-research.agent.md` |

## Handoff Chain

Standard/Assured: triage → plan → implement → review; debug supports planning,
and conformance reports findings for a separately approved fix.

> **Cross-session handoff**: Use `.github/agents/_HANDOFF_TEMPLATE.yaml` when a session ends
> mid-task to preserve decisions, constraints, and modified files for the next session.
> Handoff files and workflow prompts may include a `next_action` hint. Treat it as
> advisory routing for the human operator, not as permission for agents to cross
> phase boundaries on their own.

---

## Workflow Patterns

**Natural-language workflow router**:

When an adopter states intent in plain language, route it to an explicit
command or prompt sequence:

| Intent | Route |
| --- | --- |
| New project | `naos adopt . --mode greenfield --profile <profile> --dry-run` |
| Existing repo | `naos adopt . --mode brownfield --profile <profile> --dry-run` |
| Daily task work | `/naos-task-start <TASK-ID>` when installed; otherwise state that context manually |
| PR/release review | `naos spec-pack-contract`, `naos spec-pack-materialize --dry-run`, `naos spec-assembly-worksheet`, `naos spec-cascade`, `naos ai-surface-budget`, `naos governance-bypass-posture`, `naos gate-evaluate`, `naos evidence-pack`, `naos dashboard` |
| Governance-surface change | `naos ai-surface-budget`, `naos systemic-impact`, and `naos control-plane-review` |

Agents recommend and explain commands. They do not silently execute adoption,
cross handoff phases, approve work, or treat reports as authority.

**Feature Implementation**:

1. `@naos-research` — Gather evidence when the task is unclear or high-risk
2. `@naos-plan` — Analyze task card, search codebase, create plan
3. `@naos-implement` — Write code following the plan
4. `@naos-review` — Verify quality, governance, security

**Bug Fix**:

1. `@naos-triage` — Classify, assess priority, create task card
2. `@naos-plan` — Root cause analysis, impact search
3. `@naos-debug` — No-direct-edit diagnosis and minimal-change guidance (complex bugs)
4. `@naos-implement` — Apply the bounded fix
5. `@naos-review` — Verify fix, check for regressions

**Governance Audit**:

1. Run installed deterministic checks; Standard/Assured may use `@naos-conformance`.
2. Route a separately approved fix through `@naos-implement`.

---

## Control-Plane Operating Rules

All agents support the control plane; they do not replace it.

**Preventive**:
- Read `naos/active/*.md` and `.github/project-context.md` before planning or implementation.
- Check `naos/inventory/FUNCTION_INDEX.yaml` and search source before creating functions.
- Inspect related tests and `naos/test_evidence/source_to_test_map.json` when present.
- Read relevant `naos/capabilities/*.yaml` contracts when present.
- For non-trivial or ambiguous implementation, use `naos/PRE_IMPLEMENTATION_ALIGNMENT.md` before code to capture slice, contract, risks, test/evidence strategy, out-of-scope paths, and review boundary.
- For task create/select/plan, record `parallel_lane_opportunity` and `parallel_lane_decision`; suggestions do not activate handoff, and declared decisions use the existing handoff route.
- UI tasks: UI evidence reports are review evidence only.
- Prefer bounded task context over long accumulated chat. Treat compacted chat summaries as advisory, not authoritative; repo files and NAOS reports remain primary evidence.
- If `specs/04-architecture.md` changes, check linkage to `specs/01-problem.md`, `specs/02-solution.md`, `specs/03-requirements.md`, `naos/TASK_REGISTRY.yaml`, `naos/TRACEABILITY_MATRIX.md` where present, affected capability contracts, gate/evidence expectations, known gaps, and residual risks.
- Prefer reuse or refactor over duplication; justify any new function that overlaps existing intent.

**Detective**:
- After implementation or governance-surface changes, run or request the relevant Make targets from `naos/NAOS_QUICK_REFERENCE.md` instead of loading the full command inventory into agent context.
- Core review chain: `naos-ai-surface-budget`, `naos-systemic-impact`, `naos-control-plane-review`, `naos-self-check`, `naos-gate-status`, `naos-evidence-pack`, and `naos-dashboard`.
- Before closing a stable governed change, pass every exact tracked path to
  `naos systemic-impact --changed-path <path>`, keep kit-source and
  adopter-generated roles separate, disposition every emitted obligation, and
  require an evidence-backed review record with `--require-resolved`. Refreeze
  and repeat if another target changes. This does not infer a Git base, edit
  artifacts, prove semantic completeness, or approve the task.
- Source/quality chain: `naos-function-index-health`, `naos-module-headers`, `naos-spec-pack-contract`, `naos-spec-pack-materialize`, `naos-spec-assembly-worksheet`, `naos-spec-cascade`, `naos-test-evidence-map`, `naos-test-evidence`, and `naos-ac-completion-evidence` when AC/SCEN completion is claimed.
- Treat AC-completion evidence as declared evidence presence only; it does not prove AC correctness, implementation correctness, complete coverage, approval, certification, or compliance.
- When `PRE_IMPLEMENTATION_ALIGNMENT.md` declares `planned_change_paths` or `out_of_scope_paths`, run or recommend `naos plan-coherence --diff-base <ref>` as advisory implementation-scope evidence only; do not treat it as plan approval, sequencing, or semantic drift proof.
- Context/session/memory/learning/adapter chain: `naos-task-context`, `naos-context-index`, `naos-context-query`, `naos-memory-readiness`, `naos-memory-access`, `naos-memory-use-policy`, `naos-learning-loop-review`, `naos-adapter-coherence`, `naos-session-*`, and `naos-operator-attribution`.
- For `naos session` lifecycle review, use the session Make/CLI targets; do not inject task context automatically.
- Grading/evidence chain: `naos-agent-traces`, `naos-harness-trace-import`, `naos-static-grader`, `naos-grader-assessment`, `naos-model-policy`, `naos-model-telemetry`, `naos-failure-mode-observations`, `naos-opencode-config-hygiene`, `naos-llm-grader-readiness`, `naos-behavioral-readiness`, `naos-evidence-attestation`, `naos-evidence-conflicts`, and `naos-sarif-export`.
- For standard/assured projects, add concise `action_receipt` metadata for side effects, approvals, memory trust, or claim evidence; run `naos-agent-traces`; never store prompts, private data, credentials, or secrets.
- Optional integration templates are convenience layers only. Preview with `naos add setup-module MODULE_ID --dry-run`; copied templates live under `naos/integrations/` and do not activate hooks, mutate plugin/IDE settings, inject context, write memory, call providers, approve work, certify, or become core dependencies.
- Treat AI-surface budget output as context-health review evidence only: it can inform baseline interpretation and drift review, but it does not prevent hallucinations, grade behavior, auto-tune thresholds, or approve baseline changes.
- Treat grader assessment as review input only: audit/drift/assess summarize deterministic posture; no LLMGrader runtime, model/API/provider call, behavioral compliance determination, approval, attestation, or maturity promotion is enabled.
- Treat LLMGrader readiness as disabled/readiness-only posture: no provider/model/API dependency, credentials, cost-bearing runtime, or replacement of StaticGrader/human approval.
- Treat model-policy/model-telemetry/failure-mode-observations/opencode-config-hygiene as local review evidence only; no provider/model/OpenCode execution, learning write, config mutation, credentials, MCP/memory activation, approval, certification, or compliance decision.
- Treat missing evidence as missing or not configured, not as pass.

**Remediation**:
- If duplicate intent, stale evidence, or control drift is suspected, produce findings and remediation options.
- Do not silently delete, merge, or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code.
- Risky remediation requires explicit human/profile-based approval and an evidence update.
Safe auto-generation may include evidence placeholders, function-index drafts, source-to-test map drafts, dashboard refresh, and evidence pack refresh where appropriate.

## Governance-Surface Review Routing

When agents, skills, prompts, instructions, workflows, specs, task/source traceability, source spec references, module headers, policies, capabilities, gatekeepers, validators, evidence semantics, dashboard semantics, or AI tool surfaces change, perform control-plane self-review before treating the change as complete.
When designing or changing a capability, feature, validator, report, prompt, agent, instruction, workflow, doc, source module, or project configuration, use `templates/skills/systemic-capability-wiring/SKILL.md` as the canonical wiring checklist instead of duplicating long local variants.
Use `templates/skills/ai-surface-health-review/SKILL.md` when the AI-surface budget report is `warning` or `degraded`, or before slimming high-authority prompts, agents, instructions, workflows, skills, or command guides.
Use `templates/skills/governed-learning-lifecycle/SKILL.md` when capturing, promoting, replacing, forgetting, or redacting lessons that may affect future behavior.
Use `templates/skills/governed-coding-execution/SKILL.md` when implementing or materially changing code, config, schema, workflow, or governance surfaces, and before claiming work done/fixed/passing; it produces an evidence-backed completion ledger and does not approve, certify, or replace human review.

Operational boundaries:
- Setup, policy overlays, team gates, optional integrations, memory/MCP, task context, sessions, operator attribution, audit logs, task claims, evidence conflicts, indexes, graph/semantic readiness, StaticGrader, grader assessment, LLMGrader readiness, and SARIF export are review or coordination evidence only.
- They do not authenticate, authorize, approve, certify, prove compliance, prove behavior, prevent hallucinations, replace human review, activate hooks, call providers, write memory, inject context automatically, or create source-of-truth authority unless a separate project policy and implemented control explicitly says so.
- Memory is advisory recall. Durable memory writes require configured, authorized, verified, policy-permitted access plus explicit human approval; secrets and customer data must not be stored.
- Learning candidates are proposal-only. Active learning requires reviewed evidence, scope, approval, retrieval policy, and review/expiry metadata; it must not mutate governed artifacts automatically.
- StaticGrader and grader assessment are deterministic/file-first review inputs. LLMGrader readiness is disabled/readiness-only by default and uses no LLM, no model, no provider/API call, and no cost-bearing runtime.
- Route unsafe instruction-grade memory, stale/conflicting context, overtrust in index/query/semantic/graph outputs, trace payload risks, policy-override protected-invariant findings, evidence conflicts, missing reviewer metadata, and write-authorization findings through `naos control-plane-review`.
Use adopter-facing names: Deterministic Conformance Review is implemented static/file-first checking; StaticGrader is deterministic structural grading over trace/report metadata; LLMGrader Readiness is disabled/readiness-only governance posture for a possible future advisory second opinion; Autoresearch Readiness is routing posture; Behavioral Governance Readiness is deterministic baseline-readiness and impacter review. Do not use internal work-item labels or claim semantic behavioral grading exists in the default kit.

- `SKILL.md` changes: review frontmatter, parameters, when-to-invoke rules, overlap with agents/prompts/instructions, authority scope, and recommend update, merge, deprecate, keep, or defer.
- `.agent.md` changes: review model/tools/frontmatter, role boundaries, handoff rules, least privilege, risky auto-fix behavior, and mapping to commands, prompts, capabilities, policy, validators, evidence, and dashboard.
- `*.instructions.md` or tool-surface changes: review `applyTo`, contradictions across Claude/Copilot/Cursor/.ai/AGENTS.md, claim-control wording, preventive/detective/remediation rules, and whether existing code plus `FUNCTION_INDEX.yaml` are inspected before new functions.
- Workflow prompt changes: review next-action routing, command/agent handoff, capability/policy/validator/gate/evidence/dashboard mapping, and whether risky remediation still requires human/profile-based approval.
- Research, autoresearch, trend-review, repo-review, or external analysis findings: create or update `naos/control_plane_review_items.yaml` where disposition tracking is useful, then route actionable items into capability contracts, central policy, gatekeepers, validators, roadmap/crosswalk, task registry, known gaps, residual risks, evidence pack, dashboard, next-action recommendation, AI instruction surfaces, or specs 01-04.

Findings should recommend the appropriate next command, agent, prompt, remediation, waiver, or evidence update. Do not silently rewrite the governance system.

## Canonical Module Header

Use one module header per source module unless the language/framework requires another convention. Do not create a second module header or stale duplicate docstring if one already exists.

```text
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
```

When adding or materially changing source modules, update the existing header
instead of adding duplicate metadata. Run or recommend `naos module-headers`
after meaningful source-module changes; treat findings as review evidence, not
as permission to rewrite all headers blindly.

---

## Model Assignment Guidelines

<!-- ADAPT: Assign models based on task complexity.
     High-reasoning (planning, review, audit) → use strongest available model
     Fast-execution (implement, triage, debug) → use faster model -->

| Capability Required | Recommended Model Tier | Agents |
| ------------------- | ----------------------- | -------- |
| Deep reasoning, compliance, architecture | Highest (e.g. Opus/o1) | plan, review, audit |
| Fast code generation, classification | Fast (e.g. Sonnet/4o) | implement, triage, debug |

---

## Tool Assignment

Each agent should receive only the tools it needs (principle of least privilege).
See individual agent files for their tool lists.

<!-- ADAPT: Review tool lists in each .agent.md file and remove tools your agents don't need. -->

Agent frontmatter is validated by static conformance. Keep every `.agent.md`
file parseable as YAML and declare both `model` and `tools`.

---

## Agent Tool And Handoff Boundary

Default agents omit `agent` and `agent/runSubagent`; their handoffs remain
human-mediated. Standard/L2 or Assured/L3 projects may separately install
`@naos-implement-with-debug` after validation and named approval. It can call
only `naos-debug`, once, after two distinct failed attempts. This proves local
eligibility, not invocation or diagnosis correctness.

Plan/Triage can edit or create records; Implement writes code; Conformance can
edit an existing truth table; Review and Research have no edit tools; Debug has
no edit or agent tool but keeps terminal/test access. Current documented VS
Code tool names are required. These are manifest/instruction limits, not a
filesystem sandbox; host approvals, permissions, and sandboxing still apply.

### MCP Servers in CLI Agents (VS Code 1.113+)

MCP config is declaration only. Run `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`, then verify tools in the active client. Never put credentials, PII, or connection strings in MCP config.

Engram uses external `ENGRAM_DATA_DIR` (default `~/.engram`) and its derived `engram.db`. Run `naos memory check` first. NAOS neither installs nor syncs Engram; `~/engram-memories`, if present, is a management toolkit, not the store.

For multiple repositories, use a registry-approved canonical identity. Dynamic adapters verify the resolver and `mem_current_project`; fixed `ENGRAM_PROJECT` is workspace-only and must agree. Never infer it from a folder or set it globally:

```json
{
     "servers": {
          "engram": {
               "type": "stdio",
               "command": "engram-mcp-wrapper",
               "args": [],
               "env": {
                    "ENGRAM_PROJECT": "<registered-canonical-project-id>"
               }
          }
     }
}
```

`vscode/memory` is not a current documented core tool and is not shipped.
Engram calls require a verified, project-specific MCP namespace in the agent
allowlist. Do not claim memory access or save durable memory until readiness,
access, use policy, namespace, and human write approval are verified.

If memory is deferred or disabled, agents must use degraded recovery: read compact files, task cards, git state, and repo governance files instead of assuming `mem_*` calls are available.

**Before adding a new MCP server, verify**:

- [ ] No credentials or connection strings in the config
- [ ] Data classification — confirm no PII flows through unapproved tools (Rule 19)
- [ ] Tool scope is least-privilege — read-only where possible

---

## Agents vs Workflows

Use this decision before reaching for an agent:

| Signal | Use | Rationale |
| -------- | ----- | ----------- |
| High variability, open-ended task | **Agent** | LLM control flow needed |
| Repeatable, deterministic steps | **Workflow** | Predictable, auditable, cheaper |
| Mixed — quality loop needed | **Evaluator-optimizer** | `@naos-implement` → `@naos-review` → repeat |

**Default to deterministic workflows** — introduce an agent only when a workflow demonstrably can't handle the variability. Agents add governance surface area; workflows don't.
