# NAOS Control Plane

**Status**: Public overview of the implemented control-plane behavior
**Scope**: Portable NAOS kit architecture, not adopter-specific assurance

NAOS ships a portable, file-first capability-contract framework for SDLC governance. It does not ship runtime governance, semantic/model-backed behavioral grading, or compliance certification. Projects activate and mature capabilities progressively through profiles, readiness gates, and evidence.

The control plane wraps the existing NAOS operating model. It does not replace prompts, agents, skills, task cards, the function index, readiness checks, conformance checks, memory flow, or the admissibility pack. It makes those surfaces easier to describe, validate, package, and display.

Deterministic Conformance Review is implemented today as a static, file-first review of governance structure, YAML/frontmatter metadata, and task-battery references. Autoresearch Readiness is configuration and routing posture for research/review workflows. Behavioral Governance Readiness is implemented as deterministic readiness and impacter review for first baseline work or baseline maintenance; the default kit still does not grade AI behavior, run model-backed judges, produce behavioral scores, create baselines automatically, or require provider setup.

## Implemented Control-Plane Pieces

| Piece | Implemented artifact | Purpose |
| --- | --- | --- |
| Capability contracts | `capabilities/*.yaml` | Machine-readable description of each NAOS capability, limits, validators, gates, evidence, and maturity path. |
| Maturity model | `templates/structural-seeds/naos/maturity_levels.yaml` | L0-L5 progression from scaffolded to assured. |
| Capability state | `naos/capability_state.yaml` in adopter projects | Adopter declaration of enabled capabilities, current/target maturity, owners, evidence references, freshness windows, waiver policy, and project criteria. |
| Maturity readiness evaluator | `scripts/naos_capability_maturity.py` | Deterministically evaluates readiness and emits `naos/reports/capability_maturity.json`; it does not record promotion. |
| Central policy | `policies/default_policy.yaml` | Canonical profile gate severity, exit-code ramp, enforcement transition, claim lifecycle, evidence freshness, report paths, and external-reference defaults. It is not the source of RULES prose or membership. |
| Profile RULES source | `configs/profile_rules_source.yaml`, rendered by `naos_profile_rules.py` | Canonical exact document bytes, active-table membership, documented postures, headings, profile/version markers, and preserved source-path claims for the four shipped kit RULES outputs. |
| Derived profile RULES | `profiles/governance-*/.ai/RULES.md` | Byte-exact kit outputs checked against the independent profile RULES source; initialization copies the selected prevalidated output. |
| Profile presets | `templates/profiles/governance-*.yaml` | Reference presets copied into Lite+ projects. They are not the source of shipped RULES membership. |
| Gatekeepers | `templates/structural-seeds/naos/gatekeepers.yaml` | G0-G8 file-first gates over readiness, planning, code, tests, evidence, behavioral readiness, and advanced architecture readiness. |
| Validators | `scripts/naos_validate_*.py`, `scripts/naos_self_check.py`, `scripts/naos_function_index_health.py`, `scripts/naos_test_evidence_map.py` | Standalone checks that read policy and emit JSON reports. |
| Spec-cascade coherence | `scripts/naos_detect_spec_drift.py`, `schemas/naos/spec_cascade_coherence.schema.json` | Deterministically reviews requirement/task/source cascade gaps, including unresolved source spec references, and writes `naos/reports/spec_cascade_coherence.json`. |
| Native task lifecycle | `scripts/naos_task_lifecycle.py`, `naos/task_lifecycle_contract.yaml`, `naos/completed_history.yaml` | Resolves exact registry ids, inspects active or completed records, and records the implemented `active`/`implementation_complete` to `completed` transition with durable provenance. Completion is not merge, release, or evidence-admission authority. |
| Structured research records | `scripts/naos_research_record.py`, `naos/research_record_contract.yaml`, `naos/research/RECORD_TEMPLATE.yaml` | Validates profile-proportionate candidate research provenance, claim posture, contradictions, uncertainty, revision, and supersession metadata. A valid record remains candidate-only until a separate governed transition. |
| Composed traceability | `scripts/naos_composed_traceability.py`, `schemas/naos/composed_traceability.schema.json` | Composes explicit task-to-source, source-to-test, test-to-evidence, and evidence-to-decision links and distinguishes present, missing, unresolved, and not-applicable relations. It publishes canonical task-lifecycle review and traceability-quality review as separate blocks; the top-level review Boolean is their aggregate OR. Structural linkage does not prove semantic correctness. |
| Human decision records | `naos/human_decisions/_TEMPLATE.yaml`, `schemas/naos/human_decision_record.schema.json` | Keeps reviewer readiness output separate from an attributable human merge, release, evidence-admission, or exception decision. Agent review cannot create the latter. |
| Brownfield repository intelligence | Installed/kit `scripts/naos_repository_intelligence.py`, kit default `templates/structural-seeds/naos/repository_intelligence_rules.yaml`, project `.naos/upgrade-v1/state/repository-intelligence/` | Plans and activates a source-bound SQLite/FTS generation before brownfield installation; optional NetworkX/GraphML requires executed eligibility, while sqlite-vec remains inactive without a workload. The runtime and schemas are not duplicated into default generated profiles. |
| Brownfield overlay preflight | `naos/overlay_compatibility.json`, `schemas/naos/overlay_compatibility.schema.json` | Scans configured pytest paths, recursive Python scans in host tests, and literal repository-root Ruff commands in bounded host automation before activation. An observed `scripts/` consumer can trigger the bounded `naos_tools/` preview remap; conventional Ruff discovery can add managed nested markers only in generated roots proved to contain no pre-existing adopter Python. The `naos_tools/` marker is kit-owned and `.github/autoresearch/` is a create-once adopter-owned seed; no pre-existing adopter Ruff file is modified. Mixed Python roots and detected nested-config bypasses refuse. It is not proof of complete coexistence or arbitrary lint compatibility. |
| AI-surface health budget | `scripts/naos_ai_surface_budget.py`, `templates/structural-seeds/naos/ai_surface_context_budget_rules.yaml` | Measures singleton context-budget posture and, on explicit request, isolated fresh-profile finding, resident-token, generated-file, and reachable-command baselines. |
| AI code provenance review | `scripts/naos_ai_code_provenance.py`, `templates/structural-seeds/naos/ai_code_provenance.yaml` | Packages local AI-assisted code provenance declarations and AI artifact evidence into `naos/reports/ai_code_provenance.json` for human review only. |
| Compliance posture review | `scripts/naos_compliance_posture.py`, `templates/structural-seeds/naos/compliance_posture.yaml` | Packages adopter-declared regulated-context metadata and evidence references into `naos/reports/compliance_posture.json` for human review only. |
| MCP static descriptor review | `scripts/naos_mcp_config_registry.py`, `scripts/naos_adoption_common.py`, `templates/structural-seeds/naos/memory_mcp_inventory_rules.yaml` | Adds fail-closed risk-owner policy evaluation to the existing MCP inventory without live scanning. An exact match is pending activation only; remote identity, authentication, tools, and writes remain unverified and separately authorized. |
| Agent sponsor registry | `scripts/naos_agent_sponsor_registry.py`, opt-in `naos/agent_sponsor_registry.yaml`, `scripts/naos_control_plane_review.py` | Validates one current build-time sponsor/ownership/review-expiry/credential-posture declaration per normalized agent and routes missing, malformed, stale, expired, secret-bearing, orphaned, or exception states to G2/G6. Opaque references and categorical posture do not verify a person, credential, authentication, authorization, or runtime identity. |
| AIVSS arithmetic verification | `scripts/naos_aivss_arithmetic_verification.py`, opt-in `naos/aivss_assessments.yaml`, `scripts/naos_control_plane_review.py` | Recalculates assessor-supplied AIVSS-Agentic v0.8 arithmetic from a pinned PDF. High/Critical score prompts and separate arithmetic/integrity prompts route to advisory G2/G6 review without becoming gate, priority, approval, release, or risk authority. |
| Model-provider policy review | `scripts/naos_model_provider_policy.py`, `templates/structural-seeds/naos/model_provider_policy.yaml`, `scripts/naos_control_plane_review.py` | Reviews local model-role/provider declarations and optional mixed-tool model bindings, writes `naos/reports/model_provider_policy.json`, and can route report findings into control-plane human review; it does not call providers, validate credentials, recommend models, rewrite IDE/tool configuration, route runtime calls, or inspect or mutate MCP/Engram configuration. |
| Failure-mode observations | `scripts/naos_failure_mode_observations.py`, `templates/structural-seeds/naos/failure_mode_observations.yaml`, `scripts/naos_control_plane_review.py` | Aggregates configured local report findings into canonical 21-mode observation statistics, writes `naos/reports/failure_mode_observations.json`, and surfaces report findings through control-plane, dashboard, evidence-pack, SARIF, gate-status, systemic-impact, and learning-loop review consumers; it excludes `control_plane_review.json` as an input and does not create learning records, mutate prompts/skills/workflows, call providers/models, activate MCP/Engram/memory, approve, block, certify, or prove compliance. |
| OpenCode config hygiene | `scripts/naos_opencode_config_hygiene.py`, `templates/structural-seeds/naos/opencode_config_hygiene.yaml`, `scripts/naos_control_plane_review.py` | Reviews optional repo-local OpenCode config/instruction surfaces, writes `naos/reports/opencode_config_hygiene.json`, and can route report findings into control-plane human review; it does not create, install, run, or configure OpenCode, inspect global config, activate MCP or memory, call providers/models, validate credentials, create plugins, or mutate tools. |
| Design traceability review | `scripts/naos_design_traceability.py`, `templates/structural-seeds/naos/design_traceability.yaml`, `scripts/naos_control_plane_review.py` | Reviews optional local UI spec-object identity declarations, writes `naos/reports/design_traceability.json`, and can route report findings into control-plane human review; it does not call Figma, MCP, html.to.design, providers, models, memory tools, browsers, APIs, or mutate design tools. |
| UI experience quality review | `scripts/naos_ui_experience_quality.py`, `templates/structural-seeds/naos/ui_experience_quality.yaml`, `scripts/naos_control_plane_review.py` | Reviews optional local stage-aware UI quality evidence declarations, writes `naos/reports/ui_experience_quality.json`, and can route report findings into control-plane human review; it does not call Figma, MCP, Penpot, browsers, screenshot tools, providers, models, memory tools, APIs, or mutate design tools. |
| Model telemetry evidence | `scripts/naos_model_telemetry_evidence.py`, `templates/structural-seeds/naos/model_telemetry_evidence.yaml`, `scripts/naos_control_plane_review.py` | Reviews optional local model-use telemetry evidence declarations, writes `naos/reports/model_telemetry_evidence.json`, and can route findings into control-plane human review; it does not call providers, models, APIs, gateways, MCP, memory tools, networks, hooks, local servers, or IDE settings. |
| Governed learning lifecycle | `scripts/naos_learning_loop_review.py`, `templates/structural-seeds/naos/learning_loop_rules.yaml` | Reviews candidate, active, and historical learning records and writes `naos/reports/learning_loop_review.json`; it does not write memory or mutate governed artifacts. |
| Parallel lane handoff review | `scripts/naos_parallel_lane_handoff.py`, `templates/structural-seeds/naos/lane_handoffs/_TEMPLATE.yaml`, `scripts/naos_control_plane_review.py` | Validates adopter-declared lane handoff evidence and routes deterministic HITL reason codes for declared parallel lanes; it does not infer lanes from suggestions or approve/block work by itself. |
| Evidence pack | `scripts/naos_evidence_export.py` | Consolidates validator outputs, known gaps, residual risks, waivers, and policy metadata. |
| Dashboard | `scripts/workflows/generate_naos_dashboard.py` | Extends the existing Markdown dashboard and emits `dashboard_summary.json`. |
| Make/CLI wiring | `templates/Makefile.naos`, `cli.py` | Thin wrappers over the implemented scripts; lifecycle still runs through prompts and agents. |
| Systemic wiring skill | Source: `templates/skills/systemic-capability-wiring/SKILL.md`; generated projects: `.github/skills/<skill-name>/SKILL.md` where installed | Canonical AI-agent method for designing capability, feature, validator, prompt, agent, instruction, workflow, doc, and configuration changes without orphan artifacts. |
| AI-surface review skill | `templates/skills/ai-surface-health-review/SKILL.md` | Operational method for interpreting `warning`/`degraded` AI-surface budget findings, slimming loaded surfaces, preserving anchors, and avoiding threshold/baseline overreach. |

## Governed Agentic Coding Workflow

P2 adds deterministic review surfaces for AI-assisted engineering operating practice. `naos/agentic_workflow.yaml` declares context hygiene, Pre-Implementation Alignment, vertical slicing, red-green feedback, module-design guidance, human/AI work split, Kanban/DAG flow, and push/pull context discipline. `naos/PRE_IMPLEMENTATION_ALIGNMENT.md` records greenfield, brownfield, or feature-level alignment before non-trivial implementation, and `naos/AGENTIC_CODING_PLAYBOOK.md` explains the operating model for adopters.

The review commands are `naos agentic-workflow-review --profile <profile>` and `naos pre-implementation-alignment-review --profile <profile>`. They validate files and emit `naos/reports/agentic_workflow_review.json` and `naos/reports/pre_implementation_alignment_review.json`. These reports do not inspect chat history, call LLMs, prove model behavior, approve designs, prove requirements completeness, or replace human review.

## Maturity Levels

| Level | Meaning |
| --- | --- |
| L0 | Scaffolded: files, templates, schemas, or docs exist. |
| L1 | Configured: project selected profile and configured the capability. |
| L2 | Operational: capability runs and produces evidence. |
| L3 | Enforced: gatekeeper warns or blocks based on profile severity. |
| L4 | Measured: dashboard tracks maturity, exceptions, drift, and trends. |
| L5 | Assured: evidence is complete enough to support regulated or audit-style review. |

Installing NAOS does not make a project L5. The limiting factors are profile, project readiness, available evidence, gatekeeper configuration, and project-specific adoption maturity.

## Maturity Readiness Evaluation

NAOS evaluates maturity readiness. It does not automatically promote, certify, or approve maturity. Final maturity decisions remain project governance decisions.

The implemented flow is:

```text
declare -> evaluate -> report -> review -> approve -> mature
```

The adopter declares state in `naos/capability_state.yaml`. That declaration is not proof by itself. The evaluator reads that state, capability contracts, central policy, evidence references, freshness windows, gate evidence, dashboard evidence, waivers, and profile severity, then writes `naos/reports/capability_maturity.json`.

The report distinguishes `ready`, `blocked`, `advisory`, `not_configured`, `disabled`, and `unknown`. It keeps waivers visible and sets `promotion_recorded: false` because maturity movement is a human/project governance decision. For `standard` and `assured`, movement to a higher maturity requires human approval. L5 is conservative by design: the kit can identify supporting evidence and gaps, but it cannot certify L5 maturity automatically.

`naos self-check`, gate status/evaluation, evidence-pack export, and the dashboard consume the maturity readiness report when it exists. Missing reports are shown honestly as missing or not configured.

## Deterministic and Advisory Control Contract

`ADR-0010: Control-Plane Advisory Boundaries` defines the control-plane
boundary: advisory controls may challenge deterministic controls, but they may
not replace them.

Deterministic primary controls include specs, task cards, code, tests, schemas,
configs, policies, capability cards, gates, static validators, explicit links,
local context exact/path/metadata/FTS results, evidence packs, dashboards, and
reviewer attestation metadata. Advisory complementary controls include future
or project-configured semantic similarity, sqlite-vec/vector candidates,
embeddings, graph analytics, memory discrepancy detection, and LLMGrader-style
second opinions.

Advisory controls can produce candidates, warnings, discrepancy findings, and
review prompts. They cannot approve work, certify outcomes, prove compliance, promote maturity,
prove task completion, override repository evidence, or become sole pass/fail
authority. Any future advisory runtime must record residual-risk metadata,
including the deterministic baseline, model or algorithm, version, parameters,
input scope, source hashes, confidence, limitations, discrepancy with the
baseline, and human-review boundary.

## Profile Semantics

| Profile | Control-plane behavior |
| --- | --- |
| `quickstart` | Advisory evaluation scaffold. It includes the named research-agent/template route but not native task completion, design, implementation, review, or full lifecycle scripts. Inapplicable Make targets return an explicit `not_applicable` result and name `naos doctor` as the alternative. |
| `lite` | Warning-oriented light governance with native research, planning, implementation, review, design, task completion, and composed traceability surfaces. It does not reproduce Standard enforcement. |
| `standard` | Required evidence for normal SDLC work; stricter behavior can be enabled with strict flags and project policy. |
| `assured` | Blocking where configured, evidence-backed governance, exception/waiver visibility, and stronger gate expectations. |

Tier 3 and experimental capabilities such as `runtime_handoff`, `structured_substrate`, `source_test_graph`, and `digital_twin_evaluation` remain scaffolded/advisory by default unless a project policy explicitly changes them.

### Control is a 2-D lattice: profile × maturity

Control is not a single dial. Effective enforcement is the combination of two
axes:

- **Profile (breadth/severity)** — quickstart → lite → standard → assured set
  the severity and the graduated `exit_code` ramp (`fail_on` increases
  monotonically: `quickstart: []`, `lite: [blocking]`, `standard: [blocking,
  required]`, `assured: [blocking, required, warning]`).
- **Capability maturity L0–L5 (depth/readiness)** — a capability only enforces
  at its declared per-profile severity once `current_maturity ≥ target_maturity`;
  below target it downgrades to advisory ("never block a scaffold", computed by
  `naos_policy.effective_enforcement` and surfaced in the capability maturity
  report). **Gate severity is gated the same way**: a gate's effective severity is
  capped by the maturity-gated enforcement of the capabilities mapped to it via
  their `gatekeepers` linkage (downgrade-only — never raised above the declared
  profile severity), recorded as `maturity_gated`/`pre_maturity_severity` in gate
  status. A declared `current_maturity` not backed by present, fresh evidence is
  flagged as `unsupported_current_maturity` (advisory at lower profiles, blocking at
  assured); `current_maturity` is an adopter declaration, not proof.

**Scoped canonical sources.** “Profile control” is not one interchangeable
number. Current authority is split by operational meaning:

1. `policies/default_policy.yaml` is authoritative for profile gate severity,
   the `exit_code` ramp, and `enforcement_transition`. These decide gate and
   process return-code posture; the policy does not contain RULES prose or rule
   membership.
2. `configs/profile_rules_source.yaml` is authoritative for the complete shipped
   RULES presentation: exact bytes, the named active table, documented table
   postures, rule headings, profile/version markers, and preserved ADAPT/PGR
   material. `naos_profile_rules.py --check` compares that non-output input with all
   four derived `profiles/governance-*/.ai/RULES.md` files; `--write` regenerates
   them deterministically.
3. `templates/rules-chain/.githooks/pre-commit` is authoritative for actual
   commit-time checks and their implemented warning/blocking behavior. A RULES
   table row does not prove that a corresponding hook check exists.
4. `naos_init.py` selects a profile and copies its prevalidated derived RULES
   artifact. `templates/profiles/governance-*.yaml` remains reference-only and
   does not select or render shipped rule membership.

For this contract, an **active rule** is a non-ADAPT entry in the document's
named active table. A **blocking rule** is an active-table entry whose documented
default posture is explicitly BLOCKING; a conditional advisory row is recorded
separately. A **blocking pre-commit check** is executable hook logic that can
increment a violation or exit non-zero. **Gate severity** and **exit-code
posture** come from policy and maturity evaluation, not from the RULES table.
**Derived RULES presentation** means the whole UTF-8 byte stream, including
text outside the active table. **Kit-output drift** is any byte difference
between a shipped derived output and the canonical source. **Authorized adopter
adaptation** is a local project edit—including resolution of ADAPT stubs—after
initialization; kit exact-parity checks are explicitly not applicable to that
adopter-local file.

`naos_init.PROFILES.rules_blocking` is a presentation mirror of the canonical
documented BLOCKING rows: quickstart/lite/standard/assured are 3/3/13/19.
`validate_profile_control_coherence.py` checks exact equality when the canonical
kit source is present; the kit-only count invariant is not applicable in generated
adopter roots that do not carry that source. These values are not counts of
blocking hook checks, gate severity, or exit-code sets.

Note the two distinct enforcement surfaces: once an adopter explicitly activates
the **core pre-commit hook**, it runs a few commit-time checks at every configured
profile (including quickstart), while the **`naos` gate / exit-code posture** is
the graduated, maturity-gated, `warn`-by-default ramp. "Quickstart is advisory"
refers to the gate layer; an activated hook still applies its core guardrails.

**Per-task risk routing (advisory).** `naos pr-risk-classify` derives a `risk_tier`
(low/medium/high) from the change's risk categories and an `effective_profile` =
the stricter of the repo profile and the risk-implied profile (escalate-up-only;
never auto-lowered). This lets a high-risk task in a lower-profile repo be reviewed
under stricter expectations. It is recorded review guidance — surfaced in the
pr-risk summary, the handoff template, and optionally on task claims — and is **not**
an enforced gate, an exit-code change, or an instruction to trigger another agent.
The tier→profile mapping is adopter-overridable via `pr_risk_rules.yaml`.

**Plan coherence (sequential/parallel task sets).** `naos plan-coherence` reviews active
task claims against `TASK_REGISTRY.yaml` and module-header `Tasks:` linkage and reports:
concurrently-claimed tasks that implement overlapping files (elevated when a task declares
`parallelizable: false`), claims whose registry dependencies are not yet ready (working
ahead of prerequisites), and claims for tasks absent from the registry. With
`--diff-base <ref>`, it can also compare Git changed files to optional
`planned_change_paths` and `out_of_scope_paths` declarations in
`PRE_IMPLEMENTATION_ALIGNMENT.md`. It is deterministic review evidence — it
does not authorize work, resolve conflicts, sequence execution, approve a plan,
or prove semantic drift.

**Parallel lane opportunity and handoff interaction.** Task cards and
`PRE_IMPLEMENTATION_ALIGNMENT.md` can record `parallel_lane_opportunity`
(`not_applicable`, `sequential_recommended`, `parallel_possible`, or
`parallel_recommended`) and `parallel_lane_decision` (`sequential`, `declared`,
or `deferred`). The opportunity value is advisory. It helps humans decide
whether a task should stay sequential, split into solo logical checkpoints, or
use team lanes. Handoff activates only when the project records
`parallel_lane_decision: declared` and a lane handoff input records
`parallel_lanes_declared: true`. The handoff script writes local reports under
`naos/reports/parallel_lane_handoff/`; `naos control-plane-review` can then
reconcile those reports with PR-risk, plan-coherence, task-claim, and alignment
evidence. This route produces review reasons such as missing planning links,
scope mismatch, test evidence gaps, evidence conflicts, high actual PR risk, or
planned/actual risk mismatch. It is not automatic task creation, automatic lane
dispatch, worktree or branch creation, approval, blocking gate wiring, merge,
task closure, release, runtime orchestration, certification, attestation, or
proof of compliance.

**Conflict-visibility floor.** Conflicting task claims are never silently dropped at
any profile: they always surface a `warning` conflict finding and set
`human_review_required`. At quickstart/lite this is advisory and non-blocking
(status `conflicts_detected`); at standard/assured it escalates to
`review_required`. Task claims remain coordination metadata only — not
authorization, ownership, approval, or conflict resolution.

These axes must increase coherently and are guarded by
`scripts/validators/validate_profile_control_coherence.py` (monotonicity,
no declared-but-unconsumed control fields, and exact kit RULES parity).

**Enforcement transition.** The graduated ramp ships in a `warn` transition mode
(`enforcement_transition: warn` in policy): exit codes follow a v1-compatible
baseline while the ramp records what it *would* block, so existing adopters are
not unexpectedly blocked by policy updates. Projects opt into full enforcement with
`enforcement_transition: enforce`. This is review/enforcement posture, not
approval, certification, or proof of compliance.

## Kit Runs vs Adopter Runs

When these scripts run inside the NAOS kit repository, findings are calibration and dogfood signals for the portable kit itself. Some missing project evidence is intentionally reported as `advisory` because the kit repository is not an initialized adopter project and should not create a root generated-project `naos/` directory by default.

Adopter-project runs are different. In an initialized project, profile and policy decide whether missing, stale, or incomplete evidence is advisory, warning, required, or blocking. A kit-repo advisory result must not be interpreted as the maximum severity an adopter project will see.

## Control-Plane vs AI Surface Catalogue

NAOS uses two intentionally separate namespaces:

- `capabilities/*.yaml` are control-plane capability contracts. They describe maturity, profile behavior, gatekeeper expectations, evidence, validators, limitations, and non-claims.
- `configs/naos_ai_surface_catalogue.yaml` is a generated catalogue of AI tool surfaces: agents, skills, and scoped instructions emitted from frontmatter by `scripts/naos_emit_capabilities.py`.

The surface catalogue can support competence, inventory, and frontmatter review, but it is not the same thing as the control-plane capability-contract framework.

## AI-Surface Health Budget

The AI-surface budget control is a static context-health check for the instructions that shape AI behavior: profile `.ai/RULES.md` files, generated governance rules, governance instructions, agents, prompts, skills, workflows, manuals, quick references, and related control-plane documentation. Run `naos ai-surface-budget --profile <profile>` or `make -f Makefile.naos naos-ai-surface-budget` to write `naos/reports/ai_surface_context_budget.json`.

The report estimates artifact token weight, required anchor coverage, family-level posture, combined loadout pressure, and optional approved-baseline drift. Required anchors are only present when every configured phrase is found; partial matches are reported with `missing_phrases`. It is deterministic and one-way: StaticGrader, grader assessment, gate status, evidence pack, and dashboard can consume the report, but autoresearch metrics and grader outcomes do not automatically tune its thresholds or rewrite its baseline. A baseline change requires an explicit reviewed artifact update.

Maintainers can run `naos ai-surface-budget --fresh-profiles --json` to measure
isolated Quickstart, Lite, Standard, and Assured scaffolds in one controlled
run. The distinct aggregate report preserves complete finding occurrences and
separate `not_configured`, `not_applicable`, `disabled`, advisory, and
actionable states; it also records unique resident context tokens, unique
generated files, and generated-script-reachable CLI commands per profile while
keeping the installed global CLI envelope separate. Aggregate mode writes
nothing unless `--output` is supplied. Its default human view has at most 24
detail/rollup rows; `--all` exposes every occurrence, and JSON is always
complete. This mode does not change the singleton report path, shape, or
downstream consumers. The temporary self-check fixture excludes user-level
provider binaries, provider/database metadata, MCP configuration, ambient task
and CI variables, and dynamic host paths/identifiers; the report records those
isolation and normalization controls rather than treating this machine's setup
as fresh-project evidence.

The control mitigates instruction-surface overload and drift risk; it does not prevent hallucinations, prove AI behavior, grade model quality, certify prompt fidelity, approve work, or replace human review. Heavy artifacts can remain intentionally heavy when they carry real governance value, but the report makes that tradeoff visible.

## Governed Learning Lifecycle

Learning becomes self-improvement only when it can lead to reviewed action. NAOS
therefore keeps learning records split across candidates, active reviewed state,
and inactive history: `naos/learning_candidates.yaml`,
`naos/learning_state.yaml`, and `naos/learning_history.yaml`. Run
`naos learning-loop-review --profile <profile>` to write
`naos/reports/learning_loop_review.json`.
The architecture is mapped in
[`docs/diagrams/governed-learning-lifecycle-architecture.mmd`](diagrams/governed-learning-lifecycle-architecture.mmd).

The lifecycle is capture, verify, consolidate, consult, act, then supersede,
deprecate, archive, reject, redact, or roll back when the lesson is stale,
wrong, unsafe, or no longer in scope. Candidate learning is proposal-only.
Active learning requires evidence, scope, reviewer, approver, review date, risk,
retrieval policy, and limitations. Changes to skills, prompts, workflows,
baselines, gates, maturity, or instructions require explicit promotion review
metadata and should also trigger AI-surface budget, systemic-impact, and
control-plane review.

This control does not train model weights, call LLMs/providers/MCP/Engram, write
memory, inject context automatically, approve work, prove semantic truth,
prevent hallucinations, or replace repository evidence.

When posture is `warning` or `degraded`, use `templates/skills/ai-surface-health-review/SKILL.md` where installed. The remediation path is to slim repeated always-loaded prose, preserve required anchors, and route unresolved residual warnings through control-plane review. Do not make the report green by inflating thresholds or auto-approving a baseline.

## Operating Chain

The existing NAOS lifecycle stays intact:

```text
project, spec, research, prompt, agent, skill, and code changes
  -> mapped to capability contracts
  -> preventive review/routing
  -> governed by profile policy
  -> checked by implemented validators
  -> converged through gatekeepers
  -> packaged as evidence
  -> displayed in dashboard
  -> remediation / waiver / next action
  -> later activated through tool-specific AI instruction surfaces where implemented
```

Examples:

| Existing surface | Control-plane relationship |
| --- | --- |
| `/naos-design`, `/naos-task-start`, `/naos-task-complete` | Drive the human-mediated workflow that produces project evidence. |
| `@naos-plan`, `@naos-implement`, `@naos-review`, `@naos-conformance` | Agent roles remain governed by frontmatter, handoff rules, and capability constraints. |
| `TASK_REGISTRY.yaml`, active cards, `TRACEABILITY_MATRIX.md` | Provide task and traceability evidence consumed by validators, spec-pack contract, spec-cascade coherence, gates, and dashboard. |
| `FUNCTION_INDEX.yaml` | Feeds function-index health; absence or staleness is reported as evidence state, not hidden. |
| `task_context_pack.json`, `context_packs/<TASK-ID>.md` | Provide derived, bounded task context for AI handoff; source artifacts remain authoritative. |
| `session_lifecycle.json` | Provides bounded start/checkpoint/end checklists; it does not mutate task artifacts, inject context, or write memory. |
| `ai_surface_context_budget.json` | Provides deterministic AI-surface context-health, anchor, combined-loadout, and baseline-drift evidence; it does not prevent hallucinations, auto-tune thresholds, or grade behavior. |
| `static_grader_report.json` | Provides deterministic structural StaticGrader findings; it does not prove behavior, approve work, or call models/providers. |
| `model_provider_policy.json` | Records local model-role/provider and optional mixed-tool binding declaration coherence; control-plane review may route its findings for human review, but it does not call providers, validate credentials, recommend models, rewrite IDE/tool configuration, route runtime calls, inspect or mutate MCP/Engram configuration, or prove model quality. |
| `llm_grader_readiness.json` | Records readiness-only LLMGrader posture; runtime is disabled by default and future advisory use requires cost, data exposure, bias/drift, residual-risk, and human-approval controls. |
| `behavioral_governance_readiness.json` | Records deterministic first-baseline readiness, optional baseline metadata currency, and file/report impacters; it does not grade behavior, infer semantic drift, create baselines, approve work, authorize publication/release, or call models/providers. |
| `grader_assessment.json` | Provides deterministic audit/drift/assess review input; audit is not approval, drift is not semantic drift inference, and assess is not certification. |
| `naos_findings.sarif`, `sarif_export.json` | Export structured NAOS findings for SARIF consumers; the export does not approve work, certify outcomes, prove compliance, or replace evidence review. |
| `policy_override_merge.json` | Validates static YAML policy overlays; overrides cannot weaken protected invariants or enable plugin/runtime behavior. |
| `agentic_workflow_review.json`, `pre_implementation_alignment_review.json` | Review declared agentic coding workflow and Pre-Implementation Alignment artifacts; they do not inspect chat history, approve design or implementation, prove requirements completeness, or replace human review. |
| `make -f Makefile.naos admissibility-pack` | Existing zip handoff remains; the new JSON evidence pack gives a machine-readable control-plane view. |
| Engram memory or degraded compact/task-card recovery | Supports continuity evidence when configured; NAOS does not require a hosted memory service. |

The control plane is implemented through file-first artifacts and standalone scripts. Governed agentic coding workflow review is implemented through `naos/agentic_workflow.yaml`, `naos/AGENTIC_CODING_PLAYBOOK.md`, `naos/PRE_IMPLEMENTATION_ALIGNMENT.md`, `scripts/naos_agentic_workflow_review.py`, `scripts/naos_pre_implementation_alignment_review.py`, `naos/reports/agentic_workflow_review.json`, and `naos/reports/pre_implementation_alignment_review.json`; it records context hygiene, alignment, vertical-slice, feedback-loop, module-design, human/AI split, Kanban/DAG, and push/pull context posture without inspecting chat history, proving behavior, approving design or implementation, proving requirements completeness, or replacing human review. Systemic impact review is implemented as a configurable artifact-family review aid through `naos/systemic_impact_rules.yaml` and `naos/reports/systemic_impact_review.json`. Canonical module-header traceability is implemented as a deterministic source review through `naos/module_header_rules.yaml` and `naos/reports/module_header_traceability.json`. Spec-cascade coherence is implemented through `scripts/naos_detect_spec_drift.py`, `schemas/naos/spec_cascade_coherence.schema.json`, and `naos/reports/spec_cascade_coherence.json`; it reports requirement/task/source structural gaps but does not prove complete traceability, code correctness, runtime behavior, approval, certification, or compliance. Control-plane review and research routing is implemented as structured routing evidence through `naos/control_plane_review_rules.yaml`, `naos/control_plane_review_items.yaml`, and `naos/reports/control_plane_review.json`. AI context continuity and memory governance readiness is implemented through `naos/memory_context_rules.yaml`, `naos/memory_authorization_matrix.yaml`, and `naos/reports/memory_context_readiness.json`; it evaluates local-first memory posture, MCP/tool access declarations, authorization, fallback recovery, and context-pack readiness without calling memory tools or treating memory as evidence. Memory-use policy is implemented through `naos/memory_use_policy_rules.yaml`, `naos/memory_review_items.yaml`, and `naos/reports/memory_use_policy.json`; it evaluates the trust ladder, manual review metadata, instruction-grade requirements, recall-trace readiness, and audit-event readiness without reading payloads or writing memory. Task context packs are implemented through `naos/task_context_pack_rules.yaml`, `naos/reports/task_context_pack.json`, and optional derived Markdown under `naos/context_packs/`; they package bounded task context without automatic context injection or source-of-truth authority. Session identity is implemented through `scripts/naos_session_identity.py`, `naos/sessions_index.json`, `naos/reports/session_identity.json`, and `naos/sessions/<session_id>/reports/`; session ids isolate report namespaces while `naos/reports/` remains a latest-report compatibility surface. Operator attribution is implemented through `scripts/naos_operator_attribution.py`, `naos/reports/operator_attribution.json`, and session-scoped copies under `naos/sessions/<session_id>/reports/`; it records local identity signals for who initiated a run and does not prove identity, authenticate, authorize, assign task ownership, lock tasks, satisfy separation of duties, provide non-repudiation, or approve work. SQLite write coordination is implemented inside `scripts/naos_local_context_index.py` and reported through `naos/reports/sqlite_write_coordination.json`; it protects local context-index DB file integrity with a stdlib lock file, unique temp database, validation, and same-directory atomic replace, but it is local filesystem-only and not distributed locking, task locking, evidence conflict detection, governance correctness, or full multi-user completion. Append-only audit logging is implemented through `scripts/naos_audit_log.py`, `naos/audit_log/YYYY-MM-DD/*.jsonl`, and `naos/reports/audit_log_summary.json`; it records event history with one JSONL file per event and hashes/summaries by default, but it is not approval, non-repudiation, cryptographic signing, tamper-proof storage, task locking, evidence conflict detection, compliance approval, source of truth, or full multi-user completion. Evidence conflict detection is implemented through `scripts/naos_evidence_conflicts.py` and `naos/reports/evidence_conflict_detection.json`; it flags deterministic review-outcome conflicts, stale attestations, duplicate attestations, missing reviewer/operator metadata, same-operator review warnings, and unrouted conflicts for human review, but it does not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance. Task claim/release coordination is implemented through `scripts/naos_task_claims.py`, `naos/task_claims.yaml`, and `naos/reports/task_claim_report.json`; `naos task-claim --task <TASK-ID>` and `make -f Makefile.naos naos-task-claim TASK=T-123` record coordination metadata only, not authorization, approval, ownership proof, task completion, exclusive access, conflict resolution, or legal/regulatory compliance determination. Session lifecycle reports are implemented through `naos/session_lifecycle_rules.yaml` and `naos/reports/session_lifecycle.json`; `naos session-start`, `naos session-checkpoint`, and `naos session-end` coordinate task, compact, report, git, memory, evidence, dashboard, and routing posture without mutating task cards, `TASK_REGISTRY`, compact files, git state, or memory. Agent trace validation is implemented through `naos/agent_trace_events.yaml`, `scripts/naos_agent_trace_validate.py`, and `naos/reports/agent_trace_validation.json`; trace events are declared records, not runtime capture. StaticGrader is implemented through `autoresearch/graders/base.py`, `autoresearch/graders/static.py`, `scripts/naos_static_grader.py`, and `naos/reports/static_grader_report.json`; it evaluates deterministic structure only, costs 0.0 by default, and has no model/API/provider runtime. Grader assessment is implemented through `scripts/naos_grader_assessment.py`, `autoresearch/runner.py --audit|--drift|--assess`, and `naos/reports/grader_assessment.json`; audit mode is deterministic review input, drift mode compares deterministic reports and sets `no_semantic_drift_inferred: true`, and assess mode summarizes posture rather than certification. LLMGrader readiness is implemented through `naos/llm_grader_readiness_rules.yaml`, `scripts/naos_llm_grader_readiness.py`, and `naos/reports/llm_grader_readiness.json`; it is readiness-only governance posture with runtime disabled, no provider/model/API dependency, no credential handling, no default cost, explicit data exposure and bias/drift warnings, and StaticGrader remaining primary. Static customization hooks are implemented through `naos/policy_overrides.d/*.yaml`, optional `naos/policy_overrides.d/teams/<team_id>/*.yaml` and `naos/policy_overrides.d/operators/<operator_overlay_id>/*.yaml`, `naos/team_operator_map.yaml`, `scripts/naos_policy_overrides.py`, and `naos/reports/policy_override_merge.json`; they support static YAML overlays only, executable adopter plugin runtime remains deferred, and the repo-versioned Codex and Claude Code plugin sources are optional operator adapters over project-local NAOS artifacts; selected team/operator scopes are configuration metadata rather than authentication, authorization, access control, or separation-of-duties evidence, and protected invariant attempts become findings. PR-time CI integration is implemented through `templates/workflows/naos-pr-governance.yml.example`, `scripts/naos_pr_risk_classification.py`, `scripts/naos_pr_governance_summary.py`, `naos/reports/pr_risk_classification.json`, and `naos/reports/pr_governance_summary.json`; adopters must explicitly review and copy the workflow example, artifacts need sensitivity review before upload, PR risk classification is deterministic local diff metadata only, and CI evidence is not pull-request approval, malware analysis, sandbox execution, security proof, deployment authorization, release authorization, proof of compliance, authentication, authorization, or conflict resolution. Local context index readiness is implemented through `naos/local_context_index_rules.yaml`, `naos/reports/local_context_index.json`, and the generated `naos/context_index/local_context_index.sqlite`; it creates bounded SQLite/FTS candidate metadata and remains generated, cache-like, and not authoritative. Semantic candidate layer readiness is implemented through `naos/semantic_candidate_layer_rules.yaml` and `naos/reports/semantic_candidate_layer.json`; it records disabled/readiness-only posture for future semantic/vector candidates without enabling sqlite-vec, embeddings, extension loading, provider/model/API calls, Engram/MCP, or memory payload search. Graph context readiness is implemented through `naos/graph_context_rules.yaml` and `naos/reports/graph_context_readiness.json`; it records explicit-link traversal guardrails for future graph-context work without enabling NetworkX, GraphML, graph databases, graph algorithms, global traversal, MCP/FastMCP, Engram, or memory payload graphing. Evidence integrity and reviewer attestation is implemented as local digest and reviewer-metadata evidence through `naos/evidence_attestation_rules.yaml`, `naos/evidence_review_attestations.yaml`, and `naos/reports/evidence_attestation.json`. SARIF export is implemented through `naos sarif-export`, `naos/reports/naos_findings.sarif`, and `naos/reports/sarif_export.json`; it maps structured NAOS findings into SARIF 2.1.0 for code-scanning/security-tool interoperability, exports deterministic findings by default, and includes advisory findings only when explicitly requested with non-authority and human-review metadata. The routing report evaluates declared review items; it does not discover every research finding, scan private `dev/` content by default, or prove routing completeness. The memory-readiness, memory-use, session-identity, audit-log, and session-lifecycle reports do not install Engram, enable cloud memory, write memory, grant MCP access, prevent hallucinations, or make memory authoritative. Recall traces are usage records rather than proof; audit events are records rather than approvals. The task-context report does not replace source artifacts, call memory/MCP tools, or approve work. Session lifecycle reports are checklists and recommendations only: memory candidates are proposal_only and not_written, durable memory requires configured, authorized, verified, memory-use-policy-permitted access plus human approval, and session reports are not proof, approval, evidence authority, or task completion. StaticGrader, grader assessment, and LLMGrader readiness do not prove behavioral safety, semantic correctness, runtime behavior, legal/regulatory posture, approval, maturity promotion, certification, attestation, semantic drift, or hallucination prevention; unsupported behavioral dimensions remain not evaluated/readiness-only. Future LLM-as-judge use may incur cost, expose data, drift across provider/model versions, and produce biased or inconsistent review signals; it can only be advisory and must not replace deterministic controls or human review. Static YAML overlays cannot weaken ADR-0010: Control-Plane Advisory Boundaries, turn advisory findings into authority, enable memory write-back, MCP/Engram runtime, sqlite-vec, graph runtime, LLMGrader runtime, cloud memory, provider credentials, or signing by NAOS. Team/operator overlays cannot authenticate or authorize operators, prove team assignment, or satisfy separation of duties. Team gatekeeper config resolves severity/enabled posture for local team context, but it is governance configuration only: it is not authorization, access control, team-membership proof, approval, proof of compliance, or separation-of-duties satisfaction. The local context index does not use sqlite-vec, embeddings, graph traversal, NetworkX, GraphML, Engram, MCP, private memory payloads, or automatic context injection. Semantic candidates are not answers or authority. Graph links are relationship candidates, not source of truth, and there is no hallucination-prevention guarantee. The SARIF export does not create approval, certification, proof of compliance, attestation, source-of-truth authority, maturity promotion, or reviewer sign-off. The attestation and audit-log reports do not implement signing, tamper-proof storage, legal/regulatory approval, compliance approval, or guaranteed integrity.

Project-specific rules that are not represented in implemented reports are review disciplines unless a project adds an implemented validator or gate for them.

## Systemic Capability Wiring Skill

When designing or changing a capability, feature, validator, report, prompt,
agent, instruction, workflow, documentation surface, source module, or project
configuration, apply the Systemic Capability Wiring Skill:
`templates/skills/systemic-capability-wiring/SKILL.md`.

Generated adopter projects do not use `templates/skills/...` paths. They receive
profile-gated skill copies under `.github/skills/<skill-name>/SKILL.md`.
Assured/full-catalogue projects can use
`.github/skills/systemic-capability-wiring/SKILL.md`; standard projects use
`.github/skills/systemic-wiring/SKILL.md` plus `naos systemic-impact` /
`naos control-plane-review` for the same orphan-surface review obligation.

The skill is the canonical AI-agent wiring checklist. Other AI surfaces should
reference it concisely rather than duplicating long variants of the same rule.
It asks what the change declares, configures, evaluates, reports, exposes,
tests, documents, and leaves for human review. It also tells agents to watch
for prompt drift: stale examples, contradictory local rules, buried
constraints, and long instruction surfaces that reduce reliable attention.

The public summary is `docs/SYSTEMIC_CAPABILITY_WIRING.md`. The skill is a
design protocol, not a runtime gate in this group.

## Systemic Impact Review

Systemic impact review declares configurable relationships among artifact families and evaluates the current project state against those relationships. It is designed for both installation/onboarding and BAU project execution.

Use this flow:

`configure -> evaluate -> report -> review -> update -> re-evaluate`

The default rules seed covers specs, requirements, architecture, tasks, traceability, capabilities, capability state, policies, gatekeepers, validators, scripts, tests, skills, agents, instructions, prompts, workflows, rules, manuals, tutorials, quick reference, claims, evidence, dashboard, function index, module headers, research findings, known gaps, and residual risks. Projects can adapt the patterns and relationships as they mature.

Run:

```bash
naos systemic-impact --profile quickstart
make -f Makefile.naos naos-systemic-impact
```

For a stable card or bounded change, pass the exact repository-relative paths
rather than asking NAOS to infer a Git base:

```bash
naos systemic-impact --profile standard \
  --changed-path scripts/naos_systemic_impact.py \
  --changed-path tests/test_systemic_impact_review.py

naos systemic-impact --profile standard \
  --changed-path scripts/naos_systemic_impact.py \
  --changed-path tests/test_systemic_impact_review.py \
  --review-record naos/systemic-impact-review.yaml \
  --require-resolved
```

The first form emits typed review obligations and configured trigger labels.
The second is an explicit closure check: every obligation must be recorded as
updated, reviewed with no change, or not applicable, with rationale and
evidence. `update_required` and `unresolved` remain open.
The review record binds once to the complete exact `changed_paths` set and
records one decision per unique affected destination; the report retains every
contributing path and source family beneath that decision.

Rules distinguish NAOS-governance kit-source paths from portable
adopter-generated paths. Internal `dev/` history and plugin source are not
generated adopter content; project-local `naos/`, profile-selected `.github/`,
and Make surfaces are not kit-development records. No-argument current-state
review remains available. Changed-path mode does not execute Git, edit files,
prove semantic completeness, approve work, or authorize release.

The report distinguishes `ready`, `review_required`, `blocked`, `advisory`, `not_configured`, `disabled`, and `unknown`. It surfaces review obligations, affected artifact families, typed non-artifact review surfaces, missing links, stale links, and human-review requirements. It does not prove perfect coherence, complete impact analysis, automatic consistency, or certification. Spec 04 linkage is one high-value scenario inside this broader configurable graph, not the whole capability.

## Module Header Traceability

Module-header traceability evaluates whether configured Python source modules use the canonical NAOS header linking source files to requirements, tasks, specs, rationale, and design notes.

Run:

```bash
naos module-headers --profile quickstart
make -f Makefile.naos naos-module-headers
```

Generated adopter output:

```text
NAOS_ROOT/reports/module_header_traceability.json
```

The validator reports missing required sections, legacy single-line or singular `Task:` headers, stale `Module:` paths, duplicate module headers, and optional source references that cannot be checked against available specs or task registries. It never auto-fixes files and does not prove complete source traceability, design correctness, or code correctness. Brownfield projects may start with advisory findings and improve progressively through profile policy, waivers, known gaps, and human review.

## Spec-Pack Contract

Spec-pack contract validation evaluates deterministic template-structure
conformance, profile applicability, and manifest-declared reference resolution
before spec-cascade evidence is interpreted. It reads
`specs/spec_manifest.yaml` in generated projects, or
`templates/spec-kit/specs/spec_manifest.yaml` in the kit, then checks profile
required filenames, non-applicable-by-profile files, required sections, anchors,
cross-reference codes such as PAIN/SOL/FR/NFR/ARCH/API/AC/SCEN/INT/EXEC/TASK,
and sync markers such as `TASK_MATRIX`.

Run:

```bash
naos spec-pack-contract --profile quickstart
make -f Makefile.naos naos-spec-pack-contract
```

Generated adopter output:

```text
NAOS_ROOT/reports/spec_pack_contract.json
```

Default structural mode permits fresh `[ADAPT]` placeholders so greenfield
projects can start from templates without false failure. Explicit filled mode
adds unresolved-placeholder findings and should be run before treating specs as
ready for planning or coding. Standard and assured profiles require the full
ten-file spec pack; product-domain non-applicability should be recorded in the
relevant file rather than deleting it. Lite/quickstart omissions are reported as
not applicable by profile. The report separates the ten canonical spec files
from support files such as the manifest and README so aggregate counts cannot
hide missing applicable spec content. The report is deterministic review evidence only; it
does not prove specification quality, requirements completeness, approval,
implementation, test behavior, complete traceability, certification, or
compliance.

## Spec-Pack Materialization And Assembly Worksheet

Spec-pack materialization is a bounded missing-file addition and repair
surface, not a profile-transition mechanism. It reads the local canonical template source under
`naos/spec_templates/spec-kit/specs/` in generated projects, previews missing
profile-required files with `--dry-run`, and copies missing files only when the
operator runs it without `--dry-run`. Existing project files are skipped unless
`--force` is explicit. Before copying, it validates the trusted manifest schema,
full profile-inheritance graph and path inventory, then every selected required
source, destination, and path topology. It does not cross-check
`files[].required_profiles` metadata against every profile-list membership.
Invalid manifests, missing or symbolic-link sources,
out-of-project targets, and symbolic-link or non-regular destination paths
produce blocked evidence and no spec-file changes. A requested report path is
also checked for symlinked in-project ancestors, regular single-link leaf type, and basic writability
before apply. If no report path is configured, evidence is stdout-only. `--force` replaces only an existing
regular file inside the project; it does not relax these checks.

Apply is enabled only for the executed macOS/POSIX adapter tuple; every other
platform tuple, including Linux/POSIX, fails closed, while dry-run/report
evaluation remains available. Each successful leaf uses a same-directory
temporary before link or replacement.
The multi-file operation is sequential and has no rollback. A runtime filesystem,
post-install temporary cleanup, or late report-write failure can therefore occur
after the current or earlier copied leaves are in place. If an absent target was
installed before its temporary cleanup failed, it remains counted as copied and
the residue path is a blocking `copy_cleanup_failed` finding; remaining copies
stop. In the report-write case, blocked evidence is printed to stdout. That
state reports `report_write_failed > 0` while `apply_allowed` remains true and
`apply_refused` remains false because the spec-file apply completed before the
report sink failed.

Spec assembly worksheets support brownfield adoption. They read existing
adoption evidence, candidate requirements, traceability gaps, and the manifest,
then map available information to manifest-declared spec files for review.
Candidates stay unpromoted, and absent evidence for standard topics such as API,
acceptance, cost, market, or integrations becomes an applicability-review item
rather than a silent omission.

Run:

```bash
naos spec-pack-materialize . --profile quickstart --dry-run
naos spec-assembly-worksheet . --profile quickstart
make -f Makefile.naos naos-spec-pack-materialize
make -f Makefile.naos naos-spec-assembly-worksheet
```

Generated adopter outputs:

```text
NAOS_ROOT/reports/spec_pack_materialization.json
NAOS_ROOT/reports/spec_assembly_worksheet.json
```

These reports do not fill specs, promote candidate requirements, prove
applicability, approve requirements, prove design quality, or prove complete
traceability.

## Spec-Cascade Coherence

Spec-cascade coherence evaluates deterministic requirement/task/source linkage
across `specs/03-requirements.md`, AC/SCEN ids under `specs/`,
`naos/TASK_REGISTRY.yaml`, source module headers, and configured Python source
roots. When `SRC_ROOT` is not set, the current implementation infers common
brownfield roots such as `src`, `app`, `apps`, `packages`, and `lib`. It can
report unresolved source-level FR/NFR/AC/SCEN references in configured or
inferred source roots without changing Gate 10c's test-only AC/SCEN semantics.

Run:

```bash
naos spec-cascade --profile quickstart
make -f Makefile.naos naos-spec-cascade
```

Generated adopter output:

```text
NAOS_ROOT/reports/spec_cascade_coherence.json
```

The report surfaces orphan headers, stale task/requirement status links,
overloaded FRs, uncovered requirements, unresolved source spec references, and
untraced source files. It is
structural traceability evidence only: it does not execute code, prove complete
traceability, prove code correctness, prove runtime behavior, approve work,
certify outcomes, or prove compliance.

## Control-Plane Review And Research Routing

Control-plane review routing tracks structured items for governance-surface changes and actionable research/autoresearch findings. It is a routing/evidence layer, not a research engine.

Use this flow:

`declare -> evaluate -> report -> review -> approve disposition -> update`

Run:

```bash
naos control-plane-review --profile quickstart
make -f Makefile.naos naos-control-plane-review
```

Generated adopter output:

```text
NAOS_ROOT/reports/control_plane_review.json
```

The report has two sections: `governance_surface_review` and `research_routing`. Items come from `naos/control_plane_review_items.yaml` and can reference source type, source ref, target surfaces, related capabilities, gates, evidence, known gaps, residual risks, waivers, owner, dates, disposition, and next actions. The evaluator reports `routed`, `review_required`, `missing_routing`, `blocked`, `advisory`, `not_configured`, `disabled`, `waived`, and `unknown` states. It does not infer routed status merely because another report exists, and it does not auto-route or auto-fix anything.

## Evidence Integrity And Reviewer Attestation

Evidence attestation records local SHA-256 digests and reviewer metadata for configured evidence artifacts. Use this flow:

`configure -> hash -> report -> review -> record gaps/risks/waivers -> refresh evidence`

### Tamper-evidence and the keyless signing bridge

The attestation report now also records a deterministic **`manifest_root_digest`** — a single
SHA-256 over the artifact manifest. Any post-hoc edit to a covered artifact changes this root.
This tamper-evidence is **on by default** at every profile (keyless, zero-config, works for a
solo developer with no infrastructure).

For optional adopter-controlled sign-off, NAOS provides a **signable-envelope bridge**
(adopter-owned, ADR-0007 — NAOS never holds keys, signs, or validates signatures):

- `naos evidence-sign` emits a **DSSE-style signable envelope** over the manifest root
  (`payloadType`, base64 payload, empty `signatures: []`) plus best-effort Git-reported HEAD
  signature, signer, and author metadata. The compatibility-named `identity_binding` field is
  metadata only; NAOS applies no independent trust or acceptance policy to Git's reported
  status and does not authenticate an identity.
- An **adopter may sign** the envelope with an external signer — for example, a local key,
  cosign, Sigstore-keyless (OIDC) in CI, or a KMS. NAOS does not require signing or issue keys.
- `naos evidence-verify` recomputes digests from disk, recompares the manifest root (tamper
  detection), and reports signature-entry presence plus best-effort Git HEAD metadata.

This is local digest-integrity and optional signing-handoff tooling, not signature validation,
identity authentication, a signature by NAOS, approval, certification, a compliance opinion,
or non-repudiation.

Run:

```bash
naos evidence-attestation --profile quickstart
naos evidence-sign --profile quickstart
naos evidence-verify --profile quickstart
make -f Makefile.naos naos-evidence-attestation
make -f Makefile.naos naos-evidence-sign
make -f Makefile.naos naos-evidence-verify
```

Generated adopter output:

```text
NAOS_ROOT/reports/evidence_attestation.json
NAOS_ROOT/evidence/evidence_envelope.json
NAOS_ROOT/reports/evidence_verification.json
```

The report includes artifact digests, missing artifacts, stale artifacts, uncovered artifacts, reviewer attestations, known gaps, residual risks, waivers, human-review requirements, limitations, and explicit non-claims. Reviewer metadata is not a digital signature. Local digests are bounded evidence about file contents at report generation time; they are not tamper-proof storage, identity verification, legal/regulatory approval, compliance approval, or guaranteed integrity. Evidence attestation is local and repository-based: someone with repository write access can still edit evidence, reports, reviewer metadata, or manifests unless external controls such as protected branches, signed commits, external notarization, or independent archival are used. If `evidence_pack.json` is included in a hashed artifact set, reviewers should note circularity: the pack can later include the attestation report, so NAOS does not claim a stable digest for the final self-containing pack.

Evidence conflict detection reads deterministic local evidence/review inputs and writes `naos/reports/evidence_conflict_detection.json`:

```bash
naos evidence-conflicts --profile quickstart
make -f Makefile.naos naos-evidence-conflicts
```

The report flags conflicting review outcomes, reviewer disagreement, stale artifact hashes, missing reviewer/operator metadata, duplicate attestations, potential same-operator review warnings, unsupported structured sources, and unrouted conflicts. It detects review findings only; it does not resolve conflicts, adjudicate evidence correctness, prove separation of duties, approve work, lock tasks, produce an audit conclusion, or prove compliance. Absence of detected conflicts does not prove evidence is correct.

## AI Context Continuity And Memory Governance Readiness

Memory can help agents recover context, but repository evidence remains authoritative. Run:

```bash
naos memory-readiness --profile quickstart
make -f Makefile.naos naos-memory-readiness
```

The report distinguishes memory provider posture, declared MCP/tool access, platform authorization, fallback/degraded recovery, and context-pack readiness. Use `naos memory-access --profile <profile>` to write `naos/reports/memory_provider_access.json`, which verifies declared/configured access posture from safe config metadata without calling Engram, MCP, or memory tools. Use `naos memory-use-policy --profile <profile>` to write `naos/reports/memory_use_policy.json`, which evaluates manual review items, instruction-grade requirements, recall-trace readiness, and audit-event readiness. Configured providers and MCP config files do not prove usable access; agents should not claim memory was checked unless access is configured, authorized, and verified. Engram is the recommended local provider pattern, but NAOS does not install Engram, enable Engram cloud, call MCP tools, read private memories, write memory, or inject context automatically. Memory is advisory recall unless explicitly reviewed; instruction-grade memory requires approval, provenance, scope, reviewer, timestamp, source refs, and freshness/expiry. Memory is not evidence, approval, compliance conclusion, architecture authority, security exception, or legal/regulatory decision. Durable memory writes require configured, authorized, verified, and memory-use-policy-permitted access plus human review; recall traces are usage records, audit events are records, and CI has no memory access by default. If memory is unavailable, agents should fall back to task cards, compact summaries, git state, repo governance files, and deterministic NAOS reports.

## Task Context Pack

For a specific active task, run:

```bash
naos task-context --task T-001 --profile quickstart
naos task-context --task T-001 --profile standard --write-markdown
make -f Makefile.naos naos-task-context TASK=T-001
```

The JSON report is `naos/reports/task_context_pack.json`. Markdown output, when explicitly requested, is derived from JSON and written to `naos/context_packs/<TASK-ID>.md`. The pack summarizes or references the active task card, task registry, specs, relevant capability cards, policy profile, function-index posture, module-header traceability, spec-pack contract posture, spec-cascade coherence posture, source-to-test/test-evidence posture, systemic impact, control-plane review, setup recommendations, memory-readiness state, evidence attestation, gates, known gaps, residual risks, waivers, commands, and human-review boundaries. It does not include full large reports or memory dumps by default.

### Brownfield Repository Intelligence

Before activating NAOS into an existing repository, run the
`repository-intelligence` lifecycle: plan to an external path, perform the
conditional exact-digest enrollment, create a fresh exact-digest activation
plan, apply it, and validate the active generation. Planning does not mutate
the target. Apply writes only the capability-owned provenance, transaction, and
generated-intelligence namespace. Brownfield `init --activate` consumes the
validated immutable generation binding, or an executed not-applicable result,
before its separate scaffold transaction.

The baseline generation requires a host SQLite build with FTS5; activation and
query fail closed when it is unavailable. Optional NetworkX 3.6.1/GraphML is
enabled only for an executed eligible relationship
model and remains derived navigation evidence. `sqlite-vec`, embeddings, and
provider calls remain inactive without a defined workload. Profile and declared
L0–L5 maturity affect review posture but do not authorize activation or approve
maturity. The local context and graph-context commands below are separate
advisory project surfaces; they do not establish this provenance-bound
pre-onboarding lifecycle.

### Local Context Index

```bash
naos context-index --profile quickstart
make -f Makefile.naos naos-context-index
```

The JSON report is `naos/reports/local_context_index.json`. In generated adopter projects, the command also writes `naos/context_index/local_context_index.sqlite` using Python stdlib `sqlite3`, with FTS5 when the local SQLite build supports it and graceful metadata/path lookup fallback when it does not. The index stores source hashes, freshness metadata, bounded chunks/summaries, authority classification, provenance metadata, and explicit links. It is generated, derived, cache-like, and not authoritative; repository evidence and deterministic NAOS reports remain the review trail. The v1 index does not enable SQLite extension loading, sqlite-vec, embeddings, semantic scoring, graph traversal, Engram, MCP, private memory payloads, or automatic context injection.

### Local Context Query

```bash
naos context-query --query "governance" --profile quickstart
make -f Makefile.naos naos-context-query QUERY="governance"
```

The JSON report is `naos/reports/local_context_query.json`. It queries the generated local context index through deterministic modes such as exact path, artifact id, task id, spec reference, capability id, metadata filters, explicit links, and sanitized FTS keyword search when FTS is available. Results are bounded candidate references, not answers. They include source paths, hashes, freshness, authority levels, provenance, and limitations so humans and AI tools can check source artifacts directly. The query UX does not use sqlite-vec, embeddings, semantic scoring, graph algorithms, Engram, MCP, private memory payloads, automatic context injection, or durable memory write-back.

```bash
naos semantic-candidates --profile quickstart
make -f Makefile.naos naos-semantic-candidates
```

The JSON report is `naos/reports/semantic_candidate_layer.json`. It checks the future semantic/vector candidate posture before any runtime exists. Defaults keep semantic runtime, sqlite-vec, embeddings, extension loading, external/cloud embedding calls, memory payload embedding, and global semantic scans disabled. Exact/path/metadata/FTS query remains the deterministic baseline. Any future semantic candidates must show source path, hash, freshness, authority level, provider/model metadata, ranking explanation, and review status, and they remain candidates only.

```bash
naos graph-context --profile quickstart
make -f Makefile.naos naos-graph-context
```

The JSON report is `naos/reports/graph_context_readiness.json`. It checks future graph-context traversal guardrails before any graph runtime exists. Defaults keep graph runtime, NetworkX, GraphML, graph databases, graph algorithms, PageRank, centrality, community detection, global traversal, MCP/FastMCP, Engram, and memory payload graphing disabled. Graph links are relationship candidates and navigation aids, not source of truth; explicit source artifacts remain authoritative. Future traversal must start from explicit task/spec/artifact/query seed nodes and stay bounded by max hops, seed nodes, and returned edges. No hallucination-prevention guarantee is claimed.

```bash
naos graph-query --task T-001 --profile quickstart
make -f Makefile.naos naos-graph-query TASK=T-001
```

The JSON report is `naos/reports/graph_context_query.json`. It traverses existing explicit links from the generated local context index and related NAOS reports as bounded relationship candidates. Results show seed nodes, traversal depth, link paths, source/target paths, hashes, freshness, authority, provenance, and limitations. They are not truth, source authority, implementation proof, or graph-runtime output. The query UX does not use NetworkX, GraphML, graph databases, graph algorithms, semantic graph ranking, Engram, MCP, memory payload traversal, or global graph scans.

```bash
naos session-start --task T-001 --profile quickstart
naos session-checkpoint --task T-001 --profile quickstart
naos session-end --task T-001 --profile quickstart
make -f Makefile.naos naos-session-start TASK=T-001
make -f Makefile.naos naos-session-checkpoint TASK=T-001
make -f Makefile.naos naos-session-end TASK=T-001
```

The JSON report is `naos/reports/session_lifecycle.json`. It summarizes task discovery, task registry/card/compact posture, read-only git state, report freshness, context posture, memory readiness/access/use-policy posture, recommended commands, routing recommendations, and proposal-only memory candidates. It never writes task cards, `TASK_REGISTRY`, compact files, git state, or memory. Session-start does not inject context automatically; checkpoint does not write memory or compact files; session-end does not approve work or write memory. Memory candidates are `proposal_only` and `not_written`, and durable memory writes require configured, authorized, verified, memory-use-policy-permitted access plus human approval.

Task context packs use the same source hierarchy as memory readiness: current user instructions and active task constraints first, then repository governance/specs/policies/capabilities/rules/task cards, git state, deterministic NAOS reports, advisory memory/context references, and external references with provenance. Memory inside a pack is advisory readiness state only. The pack is derived and non-authoritative; it does not replace source artifacts, approve work, become evidence authority, inject context automatically, or prevent hallucinations. CI may generate or validate packs from files, but CI has no memory access by default.

## Experimental Runtime and Substrate Boundaries

`runtime_handoff`, `structured_substrate`, `source_test_graph`, and `digital_twin_evaluation` are public capability contracts for future/project-configured tracks. They preserve the design boundary that core NAOS remains deterministic, file-first, and portable.

These contracts do not ship a runtime gateway, runtime governance service, behavioral grading system, database, graph server, vector store, daemon, scheduler, or external service. PETRI-style behavioral evaluation and runtime-governance ideas are treated as inspiration or future-facing scaffold material unless a project provides implemented evidence and an explicit policy decision.

## Control-Plane Self-Review

Control-plane self-review is a file-first review and routing discipline for governance-surface changes. It is not a daemon, scheduler, runtime orchestrator, autonomous supervisor, or proof that every governance drift case is automatically detected.

Use it when any of these surfaces change:

- agents, skills, prompts, instructions, workflows, or AI tool surfaces;
- specs, module headers, task registry, traceability, or project context;
- policies, capability contracts, gatekeepers, validators, evidence semantics, or dashboard semantics.

The review should ask whether agents remain coherent, skills are correctly scoped, prompts align with capabilities and gates, instruction surfaces contradict one another, specs link problem/solution/requirements/architecture context, research findings are routed into the control plane, gates receive implemented evidence, and claims remain bounded and reviewable. Findings should recommend the next command, agent, prompt, remediation, waiver, or evidence update. They should not silently rewrite the system. When a structured item is needed, add or update `naos/control_plane_review_items.yaml` and run `naos control-plane-review`.

Profile behavior is advisory in `quickstart`, warning-oriented in `lite`, required where configured in `standard`, and blocking in `assured` only when an implemented validator or gate enforces it.

## Spec 04 Readiness Routing

When `specs/04-architecture.md` changes, reviewers and AI tools should check that architecture context is linked to the problem, solution, and requirements record before implementation proceeds.

Minimum linkage to inspect:

- `specs/01-problem.md`;
- `specs/02-solution.md`;
- `specs/03-requirements.md`;
- `specs/04-architecture.md`;
- `naos/TASK_REGISTRY.yaml`;
- `naos/TRACEABILITY_MATRIX.md` where present;
- affected capability contract where applicable;
- relevant gate/evidence expectation where applicable;
- residual risks and known gaps where applicable.

This is currently a review/routing rule in the portable AI surfaces and documentation. It must not be described as fully automated unless a project installs an implemented validator/gate for it.

## Research Feedback Loop

Research, autoresearch, trend-review, repo-review, and external analysis outputs should not remain standalone analysis when actionable. Route actionable findings into one or more of:

- capability contracts;
- central policy;
- gatekeepers;
- validators;
- roadmap/crosswalk;
- task registry;
- known gaps and residual risks;
- evidence pack and dashboard;
- next-action recommendation;
- AI instruction surfaces;
- specs 01-04 where relevant.

Examples: duplicate-function research should update function-index expectations, preventive AI instructions, known gaps, and dashboard/evidence notes where applicable. Architecture-without-requirements findings should route into spec-readiness review, gate severity, and evidence expectations. Over-strong public claims should route into claims validation, docs correction, and evidence limitations.

Use `naos/control_plane_review_items.yaml` to declare actionable research or autoresearch findings that need disposition. Run `naos control-plane-review` to report missing routing, routed items, known gaps, residual risks, waivers, and human-review requirements.

This loop is advisory/profile-aware unless an implemented validator or gate enforces it. It does not add web dependencies, background jobs, model-backed behavioral grading, behavioral autoresearch, or an external research subsystem.

## Gatekeeper Convergence

Gates are convergence points for implemented evidence. They should consume the relevant reports and identify `missing`, `not_configured`, stale, waived, residual-risk, and experimental evidence honestly. They are not merely green/pass file-existence checks, and they are not proof that every underlying behavior is safe or compliant.

Gate review should consider:

- preventive controls before generation or change;
- detective validators after generation or change;
- control-plane self-review findings for governance-surface changes;
- systemic impact/coherence review findings for configured artifact families;
- control-plane review routing for governance-surface and research findings;
- spec-readiness review for specs 01-04;
- research/autoresearch feedback routing;
- evidence-pack decisions, findings, waivers, known gaps, and residual risks;
- dashboard posture display.

Quickstart, lite, standard, and assured behavior remains controlled by profile policy. Tier 3/experimental tracks remain advisory unless project policy explicitly changes them and provides project-readiness evidence.

## Canonical Module Header

Generic NAOS examples use one canonical module-header convention. Adapt syntax to the language, but keep the labels and semantics consistent:

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

Use plural labels: `Implements`, `Tasks`, and `Specs`. Allow multiple entries when genuinely applicable. Keep `Rationale` concise and module-level; do not turn the header into a full design document. Generated code should update the existing header when module purpose materially changes, not create a second overlapping module header or stale duplicate docstring.

## Dashboard Behavior

The existing dashboard generator remains the entry point:

```bash
python scripts/workflows/generate_naos_dashboard.py --profile standard
naos dashboard --profile standard
make -f Makefile.naos naos-dashboard NAOS_PROFILE=standard
```

Generated adopter outputs:

```text
NAOS_ROOT/DASHBOARD.md
NAOS_ROOT/reports/dashboard_summary.json
```

The kit repository does not create root generated-project `naos/` state by default. In the kit repo, use `--json`, `--output`, or `--json-output` for explicit checks.

Dashboard statuses distinguish `pass`, `advisory`, `warning`, `required_missing`, `blocked`, `missing`, `not_configured`, `stale`, `experimental`, and `not_applicable` when that state appears in the underlying evidence. Missing reports are shown as missing or not configured. Waivers remain visible and do not become pass. Experimental Tier 3 tracks are labelled scaffolded/advisory unless project policy changes them.

The generated Markdown dashboard includes a reader index, compact testing metrics, a compact control-plane status matrix, and GitHub-compatible collapsed detail sections for lower-noise panel summaries. Testing metrics summarize existing deterministic inputs such as pytest coverage posture, source-to-test mapping, unmapped source counts, mapped evidence-type counts, test-evidence validation posture, declared AC/SCEN completion evidence posture, and test-quality hygiene posture. Critical status, failed or missing evidence, human-review requirements, behavioral readiness posture, testing posture, and non-claims remain visible outside collapsed details. The dashboard may include Mermaid diagrams for bounded governance/readiness flows, but this is Markdown rendering only: it is not a web dashboard, runtime UI, JavaScript feature, approval surface, or publication artifact.

## Evidence Pack Behavior

The JSON evidence pack is produced by:

```bash
python scripts/naos_evidence_export.py --profile standard
naos evidence-pack --profile standard
make -f Makefile.naos naos-evidence-pack NAOS_PROFILE=standard
```

Generated adopter output:

```text
NAOS_ROOT/evidence/evidence_pack.json
```

Inputs are validator reports under `NAOS_ROOT/reports/`, source-to-test evidence under `NAOS_ROOT/test_evidence/`, declared AC completion evidence under `NAOS_ROOT/reports/ac_completion_evidence.json`, optional task/context/certificate files under `NAOS_ROOT/evidence/`, and central policy metadata. The pack records missing inputs, known gaps, residual risks, exceptions/waivers, evidence freshness, and external references.

The AC-completion report and evidence pack preserve optional record-level Git
binding and supersession posture. A binding uses full base/subject commit ids
and the exact tree id for the subject commit. NAOS resolves those objects in the
project repository and checks conservatively recognized path-shaped command
operands against the subject tree. Comment, environment-assignment, expansion,
glob, path-valued attached-option, direct-`@file`-response, URI/URL or otherwise
unsupported colon-bearing, C0/DEL-control, bang/history-negation, grouping, and
compound-command forms are outside that bounded grammar and fail closed before
any operand receipt is accepted. A successor may reference one earlier
same-AC record; the predecessor remains visible. This is local structural review
evidence only: the command is not re-executed, checkout cleanliness is an
observation rather than execution proof, and no signing, signer identity,
non-repudiation, approval, release, or publication authority is created.

When `naos/reports/evidence_attestation.json` exists, the evidence pack includes it as an input and summarizes local digest coverage, reviewer metadata status, missing/stale/uncovered artifacts, waivers, known gaps, residual risks, and limitations. This summary is bounded evidence only; it is not cryptographic signing, certification, legal/regulatory approval, compliance approval, or tamper-proof storage.

External HTTP/HTTPS references are treated as unverified references unless explicitly marked verified in the evidence object. They can support review context; they are not verified evidence by default.

## Operational Commands

The CLI and Make targets are support surfaces for the existing operating model. They do not replace `/naos-design`, `/naos-task-start`, `@naos-plan`, `@naos-implement`, `@naos-review`, `@naos-conformance`, or `/naos-task-complete`.

| Purpose | CLI | Make |
| --- | --- | --- |
| Claims validation | `naos claims` | `make -f Makefile.naos naos-claims` |
| Self-conformance | `naos self-check` | `make -f Makefile.naos naos-self-check` |
| Roadmap/crosswalk validation | `naos roadmap-crosswalk` | `make -f Makefile.naos naos-roadmap-crosswalk` |
| Function-index health | `naos function-index-health` | `make -f Makefile.naos naos-function-index-health` |
| Setup recommendations | `naos setup-recommendations` | `make -f Makefile.naos naos-setup-recommendations` |
| Governance bypass posture | `naos governance-bypass-posture` | `make -f Makefile.naos naos-governance-bypass-posture` |
| External evidence ingest | `naos external-evidence-ingest --source scan.sarif` | `make -f Makefile.naos naos-external-evidence-ingest EXTERNAL_EVIDENCE_SOURCE=scan.sarif` |
| Memory readiness | `naos memory-readiness` | `make -f Makefile.naos naos-memory-readiness` |
| Memory provider access | `naos memory-access` | `make -f Makefile.naos naos-memory-access` |
| Memory use policy | `naos memory-use-policy` | `make -f Makefile.naos naos-memory-use-policy` |
| Task context pack | `naos task-context --task T-XXX` | `make -f Makefile.naos naos-task-context TASK=T-XXX` |
| Native task lifecycle | `naos task-lifecycle --task T-XXX` | `make -f Makefile.naos naos-task-lifecycle TASK=T-XXX` |
| Native task completion | `naos task-complete --task T-XXX --verification-state <state>` | `make -f Makefile.naos naos-task-complete TASK=T-XXX VERIFICATION_STATE=<state> TASK_COMPLETE_ARGS="..."` |
| Local context index | `naos context-index` | `make -f Makefile.naos naos-context-index` |
| Local context query | `naos context-query` | `make -f Makefile.naos naos-context-query QUERY="..."` |
| Semantic candidate readiness | `naos semantic-candidates` | `make -f Makefile.naos naos-semantic-candidates` |
| Graph context readiness | `naos graph-context` | `make -f Makefile.naos naos-graph-context` |
| Graph context query | `naos graph-query --task T-XXX` | `make -f Makefile.naos naos-graph-query TASK=T-XXX` |
| Session identity | `naos session-id` | `make -f Makefile.naos naos-session-id` |
| Operator attribution | `naos operator-attribution` | `make -f Makefile.naos naos-operator-attribution` |
| Static policy overrides | `naos policy-overrides --dry-run` | `make -f Makefile.naos naos-policy-overrides` |
| PR risk classification | `naos pr-risk-classify` | `make -f Makefile.naos naos-pr-risk-classify` |
| PR governance summary | `naos pr-governance-summary` | `make -f Makefile.naos naos-pr-governance-summary` |
| Agent trace validation | `naos agent-traces` | `make -f Makefile.naos naos-agent-traces` |
| Harness trace import | `naos harness-trace-import --source <repo-local.jsonl>` | `make -f Makefile.naos naos-harness-trace-import HARNESS_TRACE_SOURCE=<repo-local.jsonl>` |
| AI-surface health budget | `naos ai-surface-budget` | `make -f Makefile.naos naos-ai-surface-budget` |
| StaticGrader | `naos static-grader` | `make -f Makefile.naos naos-static-grader` |
| Duplicate function hygiene | `naos duplicate-function-hygiene` | `make -f Makefile.naos naos-duplicate-function-hygiene` |
| Secret hygiene | `naos secret-hygiene` | `make -f Makefile.naos naos-secret-hygiene` |
| Test quality hygiene | `naos test-quality-hygiene` | `make -f Makefile.naos naos-test-quality-hygiene` |
| Dependency integrity | `naos dependency-integrity` | `make -f Makefile.naos naos-dependency-integrity` |
| Package reality | `naos package-reality` | `make -f Makefile.naos naos-package-reality` |
| API symbol reality | `naos api-symbol-reality` | `make -f Makefile.naos naos-api-symbol-reality` |
| Grader assessment | `naos grader-assessment --mode audit` | `make -f Makefile.naos naos-grader-assessment MODE=audit` |
| Design traceability | `naos design-traceability` | `make -f Makefile.naos naos-design-traceability` |
| Model telemetry evidence | `naos model-telemetry` | `make -f Makefile.naos naos-model-telemetry` |
| OpenCode config hygiene | `naos opencode-config-hygiene` | `make -f Makefile.naos naos-opencode-config-hygiene` |
| UI experience quality | `naos ui-experience-quality` | `make -f Makefile.naos naos-ui-experience-quality` |
| LLMGrader readiness | `naos llm-grader-readiness` | `make -f Makefile.naos naos-llm-grader-readiness` |
| Behavioral Governance Readiness | `naos behavioral-readiness` | `make -f Makefile.naos naos-behavioral-readiness` |
| Evidence attestation | `naos evidence-attestation` | `make -f Makefile.naos naos-evidence-attestation` |
| Evidence signing bridge | `naos evidence-sign`, `naos evidence-verify` | `make -f Makefile.naos naos-evidence-sign`, `make -f Makefile.naos naos-evidence-verify` |
| Module-header traceability | `naos module-headers` | `make -f Makefile.naos naos-module-headers` |
| Spec-pack contract | `naos spec-pack-contract` | `make -f Makefile.naos naos-spec-pack-contract` |
| Spec-pack materialization | `naos spec-pack-materialize` | `make -f Makefile.naos naos-spec-pack-materialize` |
| Spec assembly worksheet | `naos spec-assembly-worksheet` | `make -f Makefile.naos naos-spec-assembly-worksheet` |
| Spec-cascade coherence | `naos spec-cascade` | `make -f Makefile.naos naos-spec-cascade` |
| Plan coherence review | `naos plan-coherence` | `make -f Makefile.naos naos-plan-coherence` |
| Control-plane review routing | `naos control-plane-review` | `make -f Makefile.naos naos-control-plane-review` |
| AIVSS arithmetic verification | `naos aivss-verify` | `make -f Makefile.naos naos-aivss-verify` |
| Source-to-test map | `naos test-evidence-map` | `make -f Makefile.naos naos-test-evidence-map` |
| Test evidence validation | `naos test-evidence` | `make -f Makefile.naos naos-test-evidence` |
| AC completion evidence | `naos ac-completion-evidence` | `make -f Makefile.naos naos-ac-completion-evidence` |
| Gate status/evaluation | `naos gate-status`, `naos gate-evaluate` | `make -f Makefile.naos naos-gate-status`, `make -f Makefile.naos naos-gate-evaluate` |
| Evidence pack | `naos evidence-pack` | `make -f Makefile.naos naos-evidence-pack` |
| Dashboard | `naos dashboard` | `make -f Makefile.naos naos-dashboard` |
| Professional adoption | `naos adopt --mode greenfield` | `make -f Makefile.naos naos-adopt MODE=greenfield` |
| Challenge before build | `naos context-challenge` | `make -f Makefile.naos naos-context-challenge` |

All wrappers delegate to existing scripts and central policy. Profiles preserve quickstart advisory, lite warning, standard required/strict-optional, assured blocking where configured, and Tier 3 advisory defaults.

Verified task completion is a pre-mutation exception to profile-severity
variation: every profile requires existing regular test and evidence files plus
an approved exact-task `task_delivery` decision under the project or configured
NAOS root. Invalid previews and executions are both non-zero and non-mutating.
The validator establishes structural attribution only; it does not prove
genuine review, test sufficiency, merge/release authority, or evidence admission.

The deterministic hygiene commands inspect local files only and write
schema-validated reports under `naos/reports/`. They are wired into evidence,
dashboard, SARIF, and gate visibility where generated; they do not prove
semantic correctness, secret-free code, behavioral correctness, package safety,
API behavior, vulnerability absence, supply-chain assurance, approval, certification,
compliance, or runtime safety. `naos package-reality` uses offline local review
by default; configured local SBOM/provenance/hash inputs remain review evidence
only; registry metadata checks require explicit online mode with network
consent and remain review evidence only. These signals do not prove SBOM
completeness or provenance authenticity.

`naos api-symbol-reality` reads explicit declarations from
`naos/api_symbol_reality.yaml` and writes
`naos/reports/api_symbol_reality.json`. V1 inspects repo-local Python source
paths or installed distribution Python source files by AST without importing or
executing target modules. Missing or empty manifests are not proof. It does not
prove API semantics, runtime behavior, option compatibility, endpoint behavior,
package safety, vulnerability absence, supply-chain assurance, approval,
certification, compliance, or hallucination prevention.

`naos pr-risk-classify` inspects local git diff metadata and writes
`naos/reports/pr_risk_classification.json` for protected paths, workflow or
dependency changes, AI instruction/prompt/agent surfaces, prompt-injection-like
added text, secret-like added lines, and contributor-trust posture supplied by
local/CI metadata. It is wired into evidence packs, dashboards, SARIF, gate
visibility, and PR governance summaries. It is not PR approval, not security
proof, not malware analysis, not sandbox execution, not authentication, not
authorization, not deployment/release authorization, and not proof of
compliance.

Setup recommendations are guidance for module selection. `naos setup-recommendations` reads `naos/setup_module_catalog.yaml`, reports rationale, benefit, warning, consequence, prerequisites, evidence outputs, commands, human-review boundaries, and deterministic profile guidance, and writes `naos/reports/setup_recommendations.json`. Profile guidance can recommend staying on the selected profile or considering lite, standard, or assured based on local signals; it does not automatically upgrade, approve maturity, certify outcomes, prove compliance, or guarantee readiness.

`naos governance-bypass-posture` writes `naos/reports/governance_bypass_posture.json` from local git hook configuration, `.githooks/pre-commit` presence, workflow files, recent commit-message markers, and tier/profile mismatch signals. It is wired into self-check, gate status/evaluation, maturity related evidence, evidence packs, dashboards, and SARIF deterministic export. It reports bypass posture only: it does not prevent bypasses, prove CI ran, approve PRs, authenticate operators, authorize work, certify controls, or prove compliance.

`naos external-evidence-ingest --source <scan.sarif>` writes `naos/reports/external_evidence_ingest.json` by parsing a local SARIF 2.1.0 file, summarizing tool names, result counts, native levels, rules, and affected paths, and preserving one deterministic opaque review record per imported result. The record includes source digest and ordinals, source-identity posture, tool/rule/native-level metadata, first artifact URI, and unverified source-declared taxonomy references; arbitrary result-message text and raw SARIF payloads are omitted. The report distinguishes successful execution with zero reported results from not-assessed, unknown, failed, missing, or malformed input, while keeping coverage explicitly `not_declared`. `naos control-plane-review` creates one repeatable advisory review prompt per result and an assessment prompt when no result record exists but execution/coverage still needs review. G2/G6 labels are human-review destinations only and do not change gate decisions. Without `--source`, ingest records a visible not-configured/advisory posture and control-plane reconciliation is not applicable. Imported results remain unverified external review evidence: neither native levels nor source-declared taxonomy references are mapped to NAOS risk, severity, controls, or requirements authority, and the commands do not run scanners, verify findings, prove assessed scope or vulnerability absence, persist human dispositions, create tasks/writeback, approve, block, prioritize, remediate, attest, certify, release, publish, or prove compliance.

To act on selected recommendations, use `naos add setup-module --list` and then `naos add setup-module MODULE_ID --profile PROFILE --dry-run`. The add path is catalog-driven and applies only explicit `install_actions`; it refuses readiness-only or deferred modules, does not install providers or services, and does not silently enable advanced behavior.

Agent trace validation reads declared records from `naos/agent_trace_events.yaml` and writes `naos/reports/agent_trace_validation.json`. Standard/assured projects can add optional `action_receipt` metadata to a trace event after meaningful agent actions, review checkpoints, or hallucination-sensitive claims when side effects, approval posture, permission scope, memory trust, or claim-to-evidence review should be explicit. Trace events and action receipts are records for StaticGrader and future audit flows; they are not proof, approval, evidence authority, memory writes, runtime capture, runtime enforcement, tool-call interception, legal/compliance/regulatory assurance, or behavioral safety evidence. Agent trace validation does not implement runtime capture, LLMGrader runtime, command execution, Engram/MCP calls, memory tools, provider/API dependencies, or permission enforcement, and trace records must not contain secrets, prompts, private memory payloads, customer data, or tenant data.

Harness trace import reads an explicit repo-local JSONL/NDJSON file and writes `naos/reports/harness_trace_import.json`; with `--write-events`, it appends valid normalized records to `naos/agent_trace_events.yaml` for later `naos agent-traces` validation. It does not execute harnesses, capture runtime events, activate hooks, run commands from trace records, call providers/APIs, access the network, read memory payloads, write memory, approve work, certify outcomes, or prove behavior.

AI-surface health budget reads configured AI/governance artifact families and writes `naos/reports/ai_surface_context_budget.json` in legacy singleton mode. It estimates standalone and combined context pressure, validates required anchors, compares against an explicit approved baseline when present, and surfaces degraded/warning posture to StaticGrader, grader assessment, gate status, evidence pack, and dashboard. Its opt-in `--fresh-profiles` mode measures four isolated generated profiles and has no default write. Both paths are deterministic and local-file-only: they do not call models/providers, read or write memory, prevent hallucinations, evaluate behavior, auto-tune thresholds, or approve baseline changes.

StaticGrader reads trace validation/report metadata where present and writes `naos/reports/static_grader_report.json`. It is deterministic and structural only: BaseGrader defines the small protocol, StaticGrader checks trace schema conformance, source/evidence references, task/spec/capability linkage, forbidden-payload absence, non-claim boundaries, residual risks, and zero-cost posture. It does not evaluate semantic behavior, fairness, alignment, robustness, safety, explainability, accountability, legal/regulatory posture, runtime behavior, or hallucination risk. D2/D3/D5/D6/D7/D8-style behavioral dimensions remain not evaluated/readiness-only, and humans decide any durable conclusion.

Grader assessment reads StaticGrader and trace/conformance metadata and writes `naos/reports/grader_assessment.json`. Use `naos grader-assessment --mode audit` or `make -f Makefile.naos naos-grader-assessment MODE=audit` for deterministic audit input, `--mode drift --baseline <path>` to compare deterministic report baselines without semantic drift inference, and `--mode assess` for posture summary only. It is zero cost by default, has no LLMGrader runtime, no model/API/provider calls, no behavioral compliance determination, and no certification or approval authority.

Model-provider policy reads `naos/model_provider_policy.yaml`, optional `naos_model_role` agent frontmatter, optional mixed-tool `tool_model_bindings`, and future-readiness references, then writes `naos/reports/model_provider_policy.json`. Use `naos model-policy --profile <profile>` or `make -f Makefile.naos naos-model-policy`. It validates declaration coherence for model roles, per-tool model bindings, provider kind, alias/latest/preview posture, cost/data exposure, environment-variable-name posture, cross-tool drift, and disabled runtime posture. Control-plane review may route report findings for human review. It does not call providers, start local models, validate credentials, recommend models, maintain provider catalogs, rewrite IDE/tool configuration, route runtime calls, inspect or mutate MCP/Engram configuration, approve work, certify controls, prove compliance, promote maturity, or activate LLMGrader/autoresearch/semantic behavior.

Model telemetry evidence reads `naos/model_telemetry_evidence.yaml` plus explicitly declared local YAML, JSON, or JSONL telemetry summaries, then writes `naos/reports/model_telemetry_evidence.json`. Use `naos model-telemetry --profile <profile>` or `make -f Makefile.naos naos-model-telemetry` when a project explicitly wants local model-use telemetry reviewed for session/task/model-role links, policy refs, cost/latency thresholds, payload/credential field presence, sensitive data class posture, stale records, and policy exceptions. Control-plane review may route report findings for human review. It does not call providers, models, APIs, gateways, MCP, memory tools, networks, hooks, local servers, or IDE settings; it does not validate credentials, start gateways, route runtime calls, inspect payload semantics, prove complete costs, approve work, certify controls, prove compliance, or activate model/provider runtime behavior.

Failure-mode observations read `naos/failure_mode_observations.yaml` plus configured direct local report files, then write `naos/reports/failure_mode_observations.json`. Use `naos failure-mode-observations --profile <profile>` or `make -f Makefile.naos naos-failure-mode-observations` only when a project explicitly wants local report findings counted against the canonical 21 failure modes. The report excludes `naos/reports/control_plane_review.json` as an input so control-plane can consume observations downstream without a cycle. Counts by mode, family, source report, reason code, severity, gate, and mapping basis are review statistics only. Dashboard, evidence-pack, SARIF, gate-status, systemic-impact, and learning-loop consumers surface those statistics as review evidence; they do not create or promote learning, mutate prompts/skills/workflows, run autoresearch, call providers/models, activate MCP/Engram/memory, approve work, block gates, certify controls, authorize release, or prove compliance.

OpenCode config hygiene reads `naos/opencode_config_hygiene.yaml`, project `AGENTS.md`, project `opencode.json` or `opencode.jsonc`, optional repo-local `.opencode/` subdirectories, and `naos/reports/model_provider_policy.json` when present, then writes `naos/reports/opencode_config_hygiene.json`. Use `naos opencode-config-hygiene --profile <profile>` or `make -f Makefile.naos naos-opencode-config-hygiene` only when a project explicitly wants local OpenCode config hygiene reviewed. It checks malformed local JSON/JSONC, stale `.opencode/config.yaml` paths, remote or absolute instruction refs, broad permission and auto-approval posture, MCP declarations, plugin refs, literal secret-like values, missing model-provider policy links, model/provider drift, and runtime-authority attempts. Control-plane review may route report findings for human review. It does not create, install, run, or configure OpenCode; inspect global user config; activate MCP or memory; call providers/models/APIs; validate credentials; create plugins; mutate IDE/tool settings; approve work; certify controls; prove compliance; prevent prompt injection; prove malware absence; or prove supply-chain safety.

Design traceability reads `naos/design_traceability.yaml` and writes `naos/reports/design_traceability.json`. Use `naos design-traceability --profile <profile>` or `make -f Makefile.naos naos-design-traceability` when a project explicitly wants local UI screen/component object IDs linked to FR/NFR/task refs, screen specs, implementation paths, changed-file evidence, test/check evidence, optional design references, and human-review posture. Control-plane review may route report findings for human review. It does not call or inspect Figma, MCP, html.to.design, browsers, providers, models, memory tools, APIs, networks, hooks, or IDE settings; it does not synchronize code/design, mutate design tools, prove design quality, accessibility, privacy, brand posture, implementation correctness, approval, certification, attestation, release readiness, or compliance.

UI experience quality reads `naos/ui_experience_quality.yaml` and writes `naos/reports/ui_experience_quality.json`. Use `naos ui-experience-quality --profile <profile>` or `make -f Makefile.naos naos-ui-experience-quality` when a project explicitly enables stage-aware local review of UI quality evidence. It checks declared FR/NFR/task/AC refs, open dependency posture, data/API/state refs, token/typography/spacing refs, screenshot/state refs, accessibility/performance refs, generator and advisory-AI provenance, user-validation refs, and human design-review posture. Control-plane review may route report findings for human review. It does not call or inspect Figma, MCP, Penpot, html.to.design, browsers, screenshot tools, providers, models, memory tools, APIs, networks, hooks, or IDE settings; it does not generate screenshots, run accessibility or performance tools, mutate design tools, score or prove design quality, approve UI, certify accessibility, prove privacy or brand posture, authorize release, or prove compliance.

LLMGrader readiness reads `naos/llm_grader_readiness_rules.yaml` and writes `naos/reports/llm_grader_readiness.json`. Use `naos llm-grader-readiness --profile <profile>` or `make -f Makefile.naos naos-llm-grader-readiness`. It is readiness-only in this scope: runtime is disabled by default, no provider/model/API dependency or credential handling is allowed, cost is 0.0 by default, StaticGrader remains primary, and any future advisory use requires provider/model and prompt/rubric metadata, budget controls, data exposure review, bias/variance limitations, residual-risk review, and human approval. It cannot approve, certify, prove compliance, promote maturity, or replace deterministic controls and human review.

Behavioral Governance Readiness reads `naos/behavioral_governance_readiness_rules.yaml`, deterministic supporting reports, and optional human-created `naos/behavioral_baseline_state.yaml` metadata, then writes `naos/reports/behavioral_governance_readiness.json`. Use `naos behavioral-readiness --profile <profile>` or `make -f Makefile.naos naos-behavioral-readiness`. The command reports readiness/impacter status only: `not_configured`, `not_ready`, `ready_to_baseline`, `baseline_current`, `baseline_stale`, `maintenance_recommended`, or `maintenance_required`. It does not create baselines, grade behavior, call models/providers/APIs, infer semantic drift, calculate N-run statistics, approve, certify, prove compliance, promote maturity, publish, or authorize releases.

AI Code Provenance reads optional project-local `naos/ai_code_provenance.yaml` declarations plus AI artifact inventory/reconciliation and adjacent evidence reports, then writes `naos/reports/ai_code_provenance.json`. Use `naos ai-code-provenance --profile <profile>` or `make -f Makefile.naos naos-ai-code-provenance`. It reports `not_configured`, `incomplete`, `review_ready`, or `review_required` as human-review posture only. It does not provide legal opinions, authorship proof, ownership proof, infringement clearance, proof of copyright compliance, AI-output detection, line-level attribution, signing, publication authority, release authority, approval, certification, or proof of compliance.

Compliance Posture reads optional project-local `naos/compliance_posture.yaml` declarations plus adjacent local evidence reports, then writes `naos/reports/compliance_posture.json`. Use `naos compliance-posture --profile <profile>` or `make -f Makefile.naos naos-compliance-posture`. It reports `not_configured`, `incomplete`, `review_ready`, or `review_required` as adopter-declared human-review posture only. It does not provide legal advice, legal opinions, regulatory applicability decisions, compliance pass/fail, compliance scores, certification, conformity assessment, audit opinions, operational-resilience execution, model-risk approval, signing, release authority, publication authority, or proof of compliance.

For adopter CI, use the generated `naos-control-plane-ci.yml` workflow from
lite upward. It runs the same deterministic control-plane command chain with
read-only repository permission while commands write ephemeral runner evidence;
the workflow does not upload artifacts or commit changes. Quickstart does not
install CI by default, and CI output
is still review evidence rather than maturity approval, a legal/regulatory
determination, or automatic remediation.

`semantic-audit` and similarity evidence remain optional/project-configured advisory controls. Core NAOS is deterministic, file-first, and portable; it does not require MPNet, MiniLM, `sentence-transformers`, embeddings, GPU, or any semantic model. Projects may configure an optional provider-neutral similarity layer and provide evidence for it. `sentence-transformers/all-mpnet-base-v2` is an acceptable local CPU-friendly provider example when explicitly configured by a project; it is not a baseline dependency. Similarity evidence may challenge the deterministic baseline by producing candidates or discrepancy findings, but it may not replace exact/path/metadata/FTS evidence, approve work, promote maturity, or block without deterministic support and human review.

## Professional Adoption Engine

The professional adoption engine is a control-plane intake layer for greenfield, brownfield, upgrade, repair, and evaluation adoption. It wires:

- command surface: `naos adopt`, `naos preflight`, `naos intake`, inventories, reconciliation, install plan, challenge reports, candidate requirements, traceability gaps, and decision records;
- input contracts: answer files and local rule seeds under `naos/`;
- output contracts: JSON reports under `naos/reports/` with local schemas under `schemas/naos/`;
- evidence visibility: evidence pack and dashboard summaries treat adoption reports as related review evidence;
- authority boundary: users decide profile, artifact disposition, candidate promotion, memory/MCP posture, activation, residual risk, and next action.

MCP discovery and descriptor review remain separate logical planes inside one
inventory report. Discovery emits sanitized declaration metadata and never raw
endpoint values. Descriptor review compares config/container shape, declared
field set, exact transport value, an exact endpoint-string digest, rule-basis digest, and the
canonical policy digest. The server label is recorded but never used as
identity. A valid exact Figma remote VS Code tuple can be
`allowlisted_pending_activation`; every drifted or unknown tuple fails closed
to `review_required`. Neither result performs activation, authentication,
provider/MCP calls, remote identity verification, tool enumeration, or write
authorization. Install decision records consume only the review status and
counts; they do not convert allowlisting into installation or approval.

This engine is report orchestration, not scaffold activation. The end-to-end
brownfield route first establishes repository intelligence, then runs the
separate managed create-only `init` transaction, and only then uses adoption
reports to support human adaptation of specs and tasks. Standard/Assured
activation creates specs 01–10, the task registry, dashboard seed, rules, and
provenance, but those generated seeds are not automatically project-specific.
Candidate requirements remain unpromoted until a reviewer accepts, rejects,
defers, or edits them and reruns the relevant validators and native tests.

After that first create-only installation, an already managed profile change
uses the content-aware upgrade contract. Normal invocation and `--dry-run` are
plan-only; `--plan-out` writes one absent external immutable plan, and mutation
requires a separate `--apply-plan` invocation with the exact expected digest.
The planner classifies the full provenance inventory, preserves adopter-owned
and modified content, and permits replacement only for unchanged
`kit_owned_derived` regular files. `naos init` transitions and eligible
add/setup collisions route through the same central apply and recovery service;
legacy `--force` remains refused. Mutation is limited to the executed Darwin
regular-file adapter. This control does not run arbitrary project validators or
hooks and makes no cryptographic-reviewer, hostile-validator-isolation,
network-denial, global atomicity, Windows/Linux, or extended-metadata claim.

The core rule is human challenge before build and evidence before confidence.
The current challenge commands perform a generic file-path presence check;
they do not read source or document contents, or parse or evaluate a plan,
decision record, gate state, or prior report content. Challenge reports do not
edit project files; candidate requirements remain candidates; memory, Engram,
and MCP findings remain advisory unless separately configured and reviewed.
Adoption report writes require the secure directory-descriptor path so strict
parent topology remains bound through replacement. On hosts without that
primitive, report-writing adoption fails before creating report paths;
`--no-write-preview` remains the supported no-mutation evaluation route.

## Declared AI Component Inventory

Standard and Assured adopters can run `naos ai-component-inventory --profile
<profile>` (or `make -f Makefile.naos naos-ai-component-inventory`) before
`naos control-plane-review`. The command builds the custom
`ai_component_inventory.v1` report from the existing agent, skill, and
instruction frontmatter normalizer plus `naos/model_provider_policy.yaml`.
Every input is repository-relative and content-digested; copied mtimes and
wall-clock age are not freshness authority.

The named consumer is control-plane review. For Standard and Assured profiles,
a missing, malformed, schema-invalid, source-stale, content-mismatched, or
incomplete required inventory produces one G2/G6 human-review route. A current
inventory produces no route. Quickstart and Lite do not require the report.
The source kit itself supplies the generator, schemas, rules, and consumer but
does not persist an adopter report, so a missing source-kit report is explicitly
not applicable; the required missing-report route applies to generated Standard
and Assured projects.

This is a NAOS-specific declared-facts inventory, not a CycloneDX or SPDX
profile. It does not discover runtime components, prove completeness, verify a
provider or model identity, sign, attest, authenticate provenance, establish
supply-chain assurance, approve compliance, block a gate, release, or publish.

## Optional Agent Sponsor Registry

Standard and Assured adopters may review and explicitly install
`agent_sponsor_registry` with `naos add setup-module agent_sponsor_registry
--profile <profile> --dry-run`, followed by a separate `--confirm`. It is not
part of any default generated profile. The empty seed deliberately invents no
sponsor and therefore routes every current normalized `CAP-A-*` agent until the
project supplies one schema-valid record per agent.

`naos agent-sponsor-registry` derives the current agent set from `.agent.md`
frontmatter, checks exact coverage, duplicate/orphan records, opaque sponsor and
owner references, review timestamps against `NAOS_FIXED_TIME` or the controlled
UTC clock, categorical credential posture, external-control references, and
secret-like values. Reports contain only a digest of each sponsor reference.
Agent source files, the registry, and installed generator/normalizer inputs are
content-digested; drift or report-body tampering fails closed. The report digest
also binds its schema-validated `generated_at` value, and a future timestamp is
rejected. Current-source comparison excludes that volatile timestamp after
those checks, so the unsigned digest does not authenticate a past timestamp.

The named consumer is `naos control-plane-review`. Missing, malformed, stale,
expired, secret-bearing, orphaned, duplicate, or external-exception evidence
produces one G2/G6 human-review route. A directory, broken symbolic link,
symbolic-link ancestor, traversal-bearing or out-of-root path, or other
non-regular registry/report artifact also routes; only two safely absent leaves
are not applicable. A current complete declaration produces no sponsor-registry
route. Registry review expiry is not credential expiry.
Neither a declaration nor a passing report verifies a sponsor, credential,
credential lifetime, authentication, authorization, delegation, separation of
duties, runtime identity, SPIFFE/SPIRE, OAuth/OBO, mTLS, signing, attestation,
approval, release, or publication.

## Optional AIVSS Arithmetic Verification

Standard and Assured adopters may dry-run and separately confirm the
`aivss_arithmetic_verification` setup module. It remains absent from every
default profile. `naos aivss-verify` reads assessor-supplied local declarations,
uses only the published AIVSS-Agentic v0.8 PDF pinned by URL and SHA-256,
preserves exact finite-decimal intermediate values, and applies round-half-up
only to the final one-decimal score. The upstream 0.0 result remains unbanded.

`naos control-plane-review` is the named consumer. A current High/Critical
result produces a score-review prompt; arithmetic mismatch or missing,
malformed, stale, unsafe, or content-mismatched installed evidence produces a
separate integrity-review prompt. Both use fixed advisory severity and target
G2/G6 human security review. They never approve, block, prioritize, merge,
release, accept risk, certify, attest, publish, or prove compliance.

Assessors remain responsible for the CVSS-v4 base score, all ten factor values,
threat maturity, mitigation strength, scope, and evidence references. NAOS does
not calculate or validate CVSS, verify subjective inputs, discover
vulnerabilities, assess risk or exploitability, observe runtime behavior, prove
mitigations, or provide security assurance.

## AI Tool Activation Surfaces

NAOS core controls are tool-neutral. Tool-specific instruction surfaces are optional activation layers:

| Surface | Current status |
| --- | --- |
| Claude / Claude Code | Implemented templates: `CLAUDE.md`, agents, prompts, skills, optional hooks, and a skills-only repo-versioned plugin source at `plugins/naos-governance-claude-code/`. |
| VS Code + GitHub Copilot | Implemented template: `.github/copilot-instructions.md`; generated project can also carry `.github/agents`, `.github/prompts`, `.github/instructions`. |
| Cursor | Implemented templates: `.cursor/rules/*.mdc`. |
| Continue | Implemented generic `.ai/config.yml` pattern. |
| Generic `AGENTS.md` / `.ai` | Implemented templates for agent governance and rules. |
| Codex | Repo-versioned plugin source at `plugins/naos-governance/` plus optional adopter guidance under `naos/integrations/codex-plugin/`; live installation remains explicit. |
| Gemini | Future activation surface. Generic instruction files can be adapted, but no dedicated generator is implemented yet. |

Optional integration templates are now available under `templates/integrations/` for Spec-Kit, Claude Code hooks, Claude Code plugin adapter guidance, and Codex plugin adapter guidance. They are copied only by explicit, review-first setup-module actions into adopter-local `naos/integrations/` paths. They do not activate hooks, overwrite IDE settings, mutate Codex plugin caches, mutate Claude Code plugin state, edit marketplace files, inject context, write memory, call provider APIs, approve work, certify outcomes, prove compliance, or create core dependencies.

Use `naos adapter-coherence --profile <profile>` after plugin, integration,
skill, instruction, workflow, MCP-posture, or governed-learning propagation
changes. Adapter coherence is deterministic and static; it checks
`adapter_propagation_state.yaml` for reviewed source/target hashes and flags
stale or unreviewed plugin guidance. It does not prove live Codex installation,
live Claude Code plugin installation, or repair drift automatically.

## Limits

The control plane supports governance traceability, review, audit/admissibility discussions, and residual-risk review. It does not prove legal or regulatory compliance, does not prove runtime safety, does not replace human review, and does not prove complete test coverage unless source-specific test or coverage evidence supports that narrower claim.
