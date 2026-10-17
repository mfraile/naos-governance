# Custom Agents Index

> **Governance**: `.ai/RULES.md` Rule 18 (Agent & Skill Governance)
> **Project Context**: `.github/project-context.md`

<!-- ADAPT: Update agent names, role mappings, and files for your team. -->

## Agent Inventory

This is a superset. Quickstart installs only `@naos-research`; Lite adds plan,
implement, and review; Standard/Assured add triage, debug, and conformance.

| Agent | Role | Purpose | File |
| ------- | --------- | --------- | ------ |
| `@naos-plan` | `planning` | Planning, analysis, task decomposition | `naos-plan.agent.md` |
| `@naos-implement` | `implementation` | Code generation, file editing, tests | `naos-implement.agent.md` |
| `@naos-review` | `review` | Code and governance-evidence review | `naos-review.agent.md` |
| `@naos-conformance` | `conformance` | Governance/evidence-gap review | `naos-conformance.agent.md` |
| `@naos-triage` | `triage` | Issue classification, priority assessment | `naos-triage.agent.md` |
| `@naos-debug` | `debug` | No-direct-edit diagnosis and root-cause guidance | `naos-debug.agent.md` |
| `@naos-research` | `research` | Read-only evidence gathering | `naos-research.agent.md` |

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

**Natural-language workflow router**: Route adopter intent to an explicit command or prompt sequence:

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

Read and apply the inventory role files: `@naos-research` when unclear/high-risk →
`@naos-plan` → `@naos-implement` → `@naos-review`.

**Bug Fix**:

Read and apply the inventory role files: `@naos-triage` → `@naos-plan` →
`@naos-debug` for complex bugs → `@naos-implement` → `@naos-review`.
Debug remains no-direct-edit; Implement applies the bounded fix.

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
- If `specs/04-architecture.md` changes, read and apply the linkage checklist in `naos-plan.agent.md` (Before Planning).
- Prefer reuse or refactor over duplication; justify any new function that overlaps existing intent.

**Detective**:
- After implementation or governance-surface changes, run or request the relevant Make targets from `naos/NAOS_QUICK_REFERENCE.md` instead of loading the full command inventory into agent context.
- Core review chain: `naos-ai-surface-budget`, `naos-systemic-impact`, `naos-control-plane-review`, `naos-self-check`, `naos-gate-status`, `naos-evidence-pack`, and `naos-dashboard`.
- Before stable governed closure, read and apply `naos-implement.agent.md` (After Changes): exact tracked `naos systemic-impact --changed-path <path>` inputs, separate kit/adopter roles, every obligation disposition, evidence-backed `--require-resolved`, and refreeze/repeat after changes. No inferred Git base, artifact edits, semantic-completeness proof, or approval.
- Source/quality chain: `naos-function-index-health`, `naos-module-headers`, `naos-spec-pack-contract`, `naos-spec-pack-materialize`, `naos-spec-assembly-worksheet`, `naos-spec-cascade`, `naos-test-evidence-map`, `naos-test-evidence`, and `naos-ac-completion-evidence` when AC/SCEN completion is claimed.
- Apply the AC-completion evidence-presence/non-proof boundary in `naos-implement.agent.md` (After Changes).
- When `PRE_IMPLEMENTATION_ALIGNMENT.md` declares `planned_change_paths` or `out_of_scope_paths`, run or recommend `naos plan-coherence --diff-base <ref>` as advisory implementation-scope evidence only; do not treat it as plan approval, sequencing, or semantic drift proof.
- Context/session/memory/learning/adapter chain: `naos-task-context`, `naos-context-index`, `naos-context-query`, `naos-memory-readiness`, `naos-memory-access`, `naos-memory-use-policy`, `naos-learning-loop-review`, `naos-adapter-coherence`, `naos-session-*`, and `naos-operator-attribution`.
- For `naos session` lifecycle review, use the session Make/CLI targets; do not inject task context automatically.
- Grading/evidence chain: `naos-agent-traces`, `naos-harness-trace-import`, `naos-static-grader`, `naos-grader-assessment`, `naos-model-policy`, `naos-model-telemetry`, `naos-failure-mode-observations`, `naos-opencode-config-hygiene`, `naos-llm-grader-readiness`, `naos-behavioral-readiness`, `naos-evidence-attestation`, `naos-evidence-conflicts`, and `naos-sarif-export`.
- For standard/assured projects, add concise `action_receipt` metadata for side effects, approvals, memory trust, or claim evidence; run `naos-agent-traces`; never store prompts, private data, credentials, or secrets.
- Optional convenience integrations: preview `naos add setup-module MODULE_ID --dry-run`; copies live under `naos/integrations/`. Apply Operational boundaries below; no plugin/IDE-setting mutation or core dependencies.
- AI-surface budget: context-health/baseline/drift review only. Read `templates/skills/ai-surface-health-review/SKILL.md`; no hallucination prevention, behavior grading, threshold auto-tuning, or baseline approval.
- Grader assessment audit/drift/assess summarizes deterministic posture only; no behavioral compliance determination, attestation, or maturity promotion. Apply the Operational boundaries below to these chains: no runtime or approval authority.
- Model-policy/model-telemetry/failure-mode-observations/opencode-config-hygiene: local review evidence only; no provider/model/OpenCode execution, learning write, config mutation, credentials, MCP/memory activation, approval, certification, or compliance decision.
- Treat missing evidence as missing or not configured, not as pass.

**Remediation**:
- If duplicate intent, stale evidence, or control drift is suspected, produce findings and remediation options.
- Do not silently delete, merge, or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code.
- Risky remediation requires explicit human/profile-based approval and an evidence update.
Safe auto-generation may include evidence placeholders, function-index drafts, source-to-test map drafts, dashboard refresh, and evidence pack refresh where appropriate.

## Governance-Surface Review Routing

For governance-surface changes, perform control-plane self-review before completion.
Read and apply `templates/skills/systemic-capability-wiring/SKILL.md` for its covered change families and canonical wiring checklist, including task/source traceability, source spec references, module headers, gatekeepers, evidence/dashboard semantics, and AI tool surfaces.
Use `templates/skills/ai-surface-health-review/SKILL.md` when the AI-surface budget report is `warning` or `degraded`, or before slimming high-authority prompts, agents, instructions, workflows, skills, or command guides.
Use `templates/skills/governed-learning-lifecycle/SKILL.md` when capturing, promoting, replacing, forgetting, or redacting lessons that may affect future behavior.
Use `templates/skills/governed-coding-execution/SKILL.md` when implementing or materially changing code, config, schema, workflow, or governance surfaces, and before claiming work done/fixed/passing; it produces an evidence-backed completion ledger and does not approve, certify, or replace human review.

Operational boundaries:
- Setup, policy overlays, team gates, optional integrations, memory/MCP, task context, sessions, operator attribution, audit logs, task claims, evidence conflicts, indexes, graph/semantic readiness, StaticGrader, grader assessment, LLMGrader readiness, and SARIF export are review or coordination evidence only.
- They do not authenticate, authorize, approve, certify, prove compliance, prove behavior, prevent hallucinations, replace human review, activate hooks, call providers, write memory, inject context automatically, or create source-of-truth authority unless a separate project policy and implemented control explicitly says so.
- Memory is advisory recall. Durable memory writes require configured, authorized, verified, policy-permitted access plus explicit human approval; secrets and customer data must not be stored.
- Learning candidates are proposal-only. Active learning requires reviewed evidence, scope, approval, retrieval policy, and review/expiry metadata; it must not mutate governed artifacts automatically.
- StaticGrader and grader assessment are deterministic/file-first review inputs. LLMGrader readiness is disabled/readiness-only: no LLM, no model, no provider/API dependency or call, credentials, or cost-bearing runtime; no replacement of StaticGrader/human approval.
- Route unsafe instruction-grade memory, stale/conflicting context, overtrust in index/query/semantic/graph outputs, trace payload risks, policy-override protected-invariant findings, evidence conflicts, missing reviewer metadata, and write-authorization findings through `naos control-plane-review`.
Use adopter-facing names: Deterministic Conformance Review is implemented static/file-first checking; StaticGrader is deterministic structural grading over trace/report metadata; LLMGrader Readiness is disabled/readiness-only governance posture for a possible future advisory second opinion; Autoresearch Readiness is routing posture; Behavioral Governance Readiness is deterministic baseline-readiness and impacter review. Do not use internal work-item labels or claim semantic behavioral grading exists in the default kit.

- `SKILL.md` changes: review frontmatter, parameters, when-to-invoke rules, overlap with agents/prompts/instructions, authority scope, and recommend update, merge, deprecate, keep, or defer.
- `.agent.md` changes: review model/tools/frontmatter, role boundaries, handoff rules, least privilege, risky auto-fix behavior, and mapping to commands, prompts, capabilities, policy, validators, evidence, and dashboard.
- `*.instructions.md` or tool-surface changes: review `applyTo`, contradictions across Claude/Copilot/Cursor/.ai/AGENTS.md, claim-control wording, preventive/detective/remediation rules, and whether existing code plus `FUNCTION_INDEX.yaml` are inspected before new functions.
- Workflow prompt changes: review next-action routing, command/agent handoff, capability/policy/validator/gate/evidence/dashboard mapping, and whether risky remediation still requires human/profile-based approval.
- Research, autoresearch, trend-review, repo-review, or external analysis findings: create or update `naos/control_plane_review_items.yaml` where disposition tracking is useful, then route actionable items into capability contracts, central policy, gatekeepers, validators, roadmap/crosswalk, task registry, known gaps, residual risks, evidence pack, dashboard, next-action recommendation, AI instruction surfaces, or specs 01-04.

Findings should recommend the appropriate next command, agent, prompt, remediation, waiver, or evidence update. Do not silently rewrite the governance system.

## Canonical Module Header

One header per module unless language/framework requires otherwise.
Update on material changes; no duplicate headers or stale docstrings.

```text
Module: src/path/to/module.py
Purpose: Short module-level description.
Implements:
    - FR-XXX: Requirement
    - NFR-XXX: Control
Tasks:
    - T-XXX: Task title
Specs:
    - specs/03-requirements.md#fr-xxx
    - specs/04-architecture.md#architecture-section
Rationale: Why here, owned boundary, reuse and drift avoidance.
Design notes:
    - Optional stable constraints/patterns.
```

Run/recommend `naos module-headers`; findings are review evidence, not
permission to rewrite blindly.

---

## Model Assignment Guidelines

Shipped agents omit `model:`; the host selects it. Omission neither selects nor
approves a model/provider. Keep `naos_model_role` mapped to
`naos/model_provider_policy.yaml`. Before use, verify the actual model,
provider, availability, cost, data exposure and required human approval.
Model-policy reports inspect declarations; they cannot enforce picker choices
or authorize calls.

Adopters may add a host-supported selector: a scalar, or a prioritized list for
VS Code; GitHub documents a scalar. Explicit selection remains subject to the
project's model/provider policy and approval process.

---

## Tool Assignment

Review each `.agent.md` tool list and remove unneeded tools (least privilege).

Static conformance requires parseable YAML, `description` and `tools`.
Optional `model` must have a non-empty scalar/list shape supported by the declared
host. Unresolved ADAPT selectors fail `model` and `model-placeholder-unresolved`.
These checks prove neither availability, actual selection nor approval.

---

## Agent Tool And Handoff Boundary

Default agents omit `agent` and `agent/runSubagent`; their handoffs remain
human-mediated. Standard/L2 or Assured/L3 projects may separately install
`@naos-implement-with-debug` after validation and named approval. It can call
only `naos-debug`, once, after two distinct failed attempts. This proves local
eligibility, not invocation or diagnosis correctness.

Current VS Code Local-harness documentation states that explicitly naming a child
in `agents` overrides that child's `disable-model-invocation: true`. The optional
parent names only `naos-debug`; keep the child's flag true and all existing
activation gates. This documented exception is not a global child enablement or
proof of invocation. Other harnesses must satisfy their own current contract;
if the named allowlist or tool is unavailable, use the human-mediated fallback.
Neither the kit nor the optional agent changes recursive host settings.

The activation gate and local validator use the same deterministic tool-scope
check. They reject omitted or malformed tool lists and wildcard authority.
Agent frontmatter also refuses duplicate mapping keys, including nested keys
and overrides of merged keys, before evaluating permissions;
`tools: []` disables tools. The debug child may retain or reduce the shipped
read/search/terminal/test/todos scope. Added tools require a separately reviewed
contract update. Case-insensitive GitHub edit aliases (`Write`, `MultiEdit`,
`NotebookEdit`) and agent aliases (`Task`, `custom-agent`) are refused in the
child; the default implementation agent also refuses agent aliases. The parent
retains the exact VS Code `agent` token and exact `naos-debug` allowlist. A
server/tool suffix is not treated as a built-in alias: arbitrary MCP tools are
outside the child scope, without a claim about their behavior. Terminal/test
access still follows host approvals and sandbox; it is not a filesystem security
boundary. These are local declaration checks, not live host invocation proof.

Alias and omission semantics: [GitHub custom-agent reference](https://docs.github.com/en/copilot/reference/custom-agents-configuration).
Scoped tool and agent lists: [VS Code custom agents](https://code.visualstudio.com/docs/agent-customization/custom-agents).

Plan/Triage can edit or create records; Implement writes code; Conformance can
edit an existing truth table; Review and Research have no edit tools; Debug has
no edit or agent tool but keeps terminal/test access. Current documented VS
Code tool names are required. These are manifest/instruction limits, not a
filesystem sandbox; host approvals, permissions, and sandboxing still apply.

### MCP Servers in CLI Agents (VS Code 1.113+)

MCP config is declaration only. Run `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy`, then verify tools in the active client. Never put credentials, PII, or connection strings in MCP config.

Run `naos memory check` first. Read [Engram storage](../../docs/ENGRAM_SETUP.md#storage-model): external `ENGRAM_DATA_DIR` (default `~/.engram`), derived `engram.db`; `~/engram-memories` is toolkit, not store. NAOS neither installs nor syncs Engram.

For multiple repositories, use a registry-approved canonical identity. Dynamic adapters verify the resolver and `mem_current_project`; fixed `ENGRAM_PROJECT` is workspace-only and must agree. Never infer it from a folder or set it globally:

See [Engram workspace identity and MCP namespace](../../docs/ENGRAM_SETUP.md#workspace-project-identity)
for workspace declarations.


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
