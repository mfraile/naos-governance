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

Alignment files accept UTF-8 with or without a leading byte-order mark, including files authored by Windows PowerShell. YAML frontmatter must have opening and closing `---` delimiter lines; malformed or unterminated frontmatter remains an invalid input. Planning-baseline ledgers are schema-checked before lineage and digest processing: invalid version values produce `planning_baseline_schema_invalid` findings and `review_required` readiness. Use the plan-coherence command's `--strict` option when those findings must produce a nonzero exit.

New planning-baseline templates declare `text_lf_sha256_v1` for requirements,
architecture, alignment and evidence snapshots. This contract requires valid
UTF-8 and hashes bytes after replacing only CRLF pairs with LF; BOMs, lone CRs,
whitespace and all other bytes remain significant. Source checks, evidence
checks and copyable digest candidates use the declared contract. Unsupported
kinds or invalid UTF-8 under the text contract cannot produce a current digest.
Historical `file_sha256` entries still hash exact bytes, including binary;
the task registry keeps its existing stable planning projection. To adopt the
text contract for an approved record, retain the historical digest kind and
hash, create a successor baseline with a higher version and `supersedes`, and
obtain a new attributable decision bound to that successor's exact projection.
Changing the kind in an approved record invalidates its existing decision;
digest candidates do not edit a ledger or approve migration. The policy
report writers explicitly emit LF while retaining their existing atomic
replacement, permissions and topology checks.

## Maturity Levels

| Level | Meaning |
| --- | --- |
| L0 | Scaffolded: files, templates, schemas, or docs exist. |
| L1 | Configured: project selected profile and configured the capability. |
| L2 | Operational: capability runs and produces evidence. |
| L3 | Enforced: gatekeeper warns or blocks based on profile severity. |
| L4 | Measured: dashboard includes the capability's current selected signals; quantitative effectiveness and historical trends require separate evidence. |
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

L2 review requires at least one applicable supporting reference and no unresolved
required reference. Registered reports are checked for shape, scope and their
own bounded outcome. A dashboard or gate aggregate cannot substitute for L2
operational evidence. Nonempty manual material can support human review with a
`manual_reference_availability` ceiling; it is never labeled executed or
authenticated. JSON manual material needs an explicit `type: manual` in the
state entry's `evidence_requirements` map, keyed to its exact `evidence_refs`
value. A known automatic report cannot be retyped to bypass an adverse outcome.
Optional disabled evidence is inapplicable only when valid local configuration
establishes that status; it does not count as positive operational evidence.

Additional producer reports can provide typed maturity or evidence-pack
support: setup recommendations, calibration shadow, evidence classification,
governance bypass posture, PR risk classification, adapter coherence, trace
validation, agentic-workflow and pre-implementation review, cross-harness
readiness, offline package inspection, policy overrides, static grading,
secure-coding evidence projection and deterministic conformance. Conformance support reproduces the shipped local
checks against their bound inputs; behavioral dimensions remain unmeasured.
Custom batteries require an explicit current caller or policy selection.
Replay retains the producer's raw runner hash. A generated runner must match
the trusted runner bytes, allowing only the exact generator-owned tool-path
relocation from `scripts` to `naos_tools`; missing, linked or altered runner
and tool paths remain unresolved. The source-kit consumer reads the generated
runner for comparison and never executes it.
Their schema, project scope, outcome and declared age remain checked. Adverse,
incomplete and unrecognized review results remain unresolved. Schema compilation
may reuse up to 64 private validators per process, keyed by exact schema bytes
and validator class. Schemas larger than 256 KiB bypass this cache. Every request
still reads and checks the canonical schema and validates the current report;
evidence outcomes, dependency proofs and freshness decisions are not cached.
Dependency input inventory and systemic review-record readers may also reuse
private YAML parse results from the exact freshly read content. Ordinary YAML
and review records with unique string keys keep separate parsing semantics;
each caller receives an independent copy. Every request retains file reads,
byte hashes, path and identity checks, topology validation and current proof
evaluation. Reuse bypasses changed loader registrations and unsupported resolver
fingerprints. The cache retains at most 128 entries and 2 MiB of source content;
inputs larger than 256 KiB bypass it. These limits do not establish a heap-memory
bound or a native workflow performance guarantee.
Trace and static grading reuse their finite current-producer structural contracts, retaining
unsupported behavioral dimensions, hypotheses and human-review flags; these are
not behavioral success. This support does not register the reports as gate
requirements, replace aggregate prerequisites or record promotion.

L3 additionally requires both stored gate reports, consistent selected gate
rows covering the capability's declared gate links, and consistent enforcement
metadata. Warn mode remains valid when the selected evidence is resolved. L4
checks the selected adopter capability signals against their embedded maturity
source, current state and supporting-evidence digests. It does not turn a
dashboard's collection status into a maturity pass. To refresh these inputs,
generate a maturity snapshot, generate the dashboard, then evaluate maturity
again. The final review can change the displayed verdict without invalidating
its own prerequisite; changed underlying evidence requires a fresh projection.

`generation_age` and current-source freshness are separate. Automatic reports
use their timestamp and the declared age window; missing, invalid or future
timestamps remain unresolved. A zero-day window disables the age limit, not
timestamp validation. Manual files retain explicitly labeled modification-time
availability age. Touching a file does not change a failed producer outcome.
`require_current_source: true` remains unresolved for producers without a
supported source validator. Requirements for a higher target level do not
retroactively invalidate otherwise supported evidence for the current level.

Malformed or unreadable present state and selected capability inputs produce a
`naos.capability_maturity_input_error.v1` report with `status: invalid_input`
and exit code 2. This replaces a prior report at the selected writable output
and remains blocking when self-check aggregates it. The error report records
no evaluated readiness, state existence or promotion result. Validation rejects
ambiguous duplicate declarations and invalid consumed field types; absent state
and valid partial declarations retain their existing behavior. This check does
not infer whether an absent entry was previously configured.

`naos self-check`, gate status/evaluation, evidence-pack export, and the dashboard consume the maturity readiness report when it exists. Missing reports are shown honestly as missing or not configured.

`naos self-check --profile <profile>` performs a live inspection of the real project. Selected checks exchange current derived reports in a temporary workspace; inspection does not start sessions, append audit events or publish project reports, SQLite indexes or claim locks. Required missing evidence and invalid authored inputs remain findings. `--output <path>` publishes only the final self-check report.

Use `naos self-check --profile <profile> --refresh` to explicitly collect persistent derived evidence using the normal producer publication rules. CI readiness selects this collection mode for its downstream gates. Dependency capture and finalization are separate explicit writer operations; they are not inferred from an inspection result. A passing check does not approve the project or establish evidence completeness.

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

An explicit profile-control `--capabilities` path is relative to the caller's
working directory. The selected directory and capability files must resolve
inside the selected root; external selections produce
`CTRLCOH_CAPABILITIES_OUTSIDE_ROOT` before scanning or reading them. Existing
in-root directory links remain supported. This is a read-time path check, not
protection against concurrent filesystem replacement.

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
`PRE_IMPLEMENTATION_ALIGNMENT.md`. The comparison includes deleted files and both
old and new paths of detected renames, as well as untracked files. Git paths retain
literal spaces and Unicode characters. Scope findings remain advisory and require
human review. It is deterministic review evidence — it
does not authorize work, resolve conflicts, sequence execution, approve a plan,
or prove semantic drift.

Planning baselines bind exact evidence bytes. Before requesting an
implementation-ready decision, preserve the actual filled spec-pack and ready
alignment reports under a baseline-specific path such as
`naos/planning-evidence/PB-001/`, and bind those snapshots in `evidence_refs`.
The working `naos/reports/` files can then be regenerated without overwriting
reviewed evidence. G2 still checks source digests and revalidates the current
specs and alignment. Changed snapshots or source bindings require a new review;
do not automatically rewrite approved hashes to make a gate pass.

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

**Concurrent local claims.** Claim, release, and list commands share a persistent
`task_claims.yaml.lock` beside the configured claims file. Native OS locks on
macOS, Linux, and Windows serialize reading, updating, and publishing the claim
report. Do not remove the lock file while commands may be running; the OS releases
the lock when its holder exits, including after a crash. After ten seconds of
contention, the command reports `blocked` on stdout without updating shared
claims or reports (`--strict` returns exit code 1; the default remains advisory).
Unparseable YAML, invalid list structure, unsupported schemas and unsupported
claim status values are preserved and reported as `invalid_claims` for repair.
Legacy omitted fields still receive their existing defaults; this is not full
schema validation of every historical record.
This coordinates cooperating commands in one local checkout. It does not lock
separate clones, synchronize network filesystems, authenticate operators, or make
the claims, audit log, and reports one crash-atomic transaction. After an interrupted
publication, rerun `naos task-claims` to regenerate the claim report.

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

Anchor phrases apply to every profile unless the rule explicitly lists
supported `profiles`. Malformed or empty profile lists fail rather than disable
an anchor. Reports retain inapplicable anchors with `applicable_to_profile:
false`; these do not generate missing-anchor or baseline-regression findings.
Every phrase remains required for an applicable anchor. General context pressure,
checkpoint and compact guidance applies everywhere; the caller-supplied hook
signal anchor applies to Standard/Assured, where that hook check is installed.

The AI-surface budget control is a static context-health check for the instructions that shape AI behavior: profile `.ai/RULES.md` files, generated governance rules, governance instructions, agents, prompts, skills, workflows, manuals, quick references, and related control-plane documentation. Run `naos ai-surface-budget --profile <profile>` or `make -f Makefile.naos naos-ai-surface-budget` to write `naos/reports/ai_surface_context_budget.json`.

The report estimates artifact token weight, required anchor coverage, family-level posture, combined loadout pressure, and optional approved-baseline drift. Required anchors are only present when every configured phrase is found; partial matches are reported with `missing_phrases`. It is deterministic and one-way: StaticGrader, grader assessment, gate status, evidence pack, and dashboard can consume the report, but autoresearch metrics and grader outcomes do not automatically tune its thresholds or rewrite its baseline. A baseline change requires an explicit reviewed artifact update.

The legacy family and `resident_context` totals are full matched catalogue weights,
not measurements of host startup context. `combined_scenarios` are configured
synthetic bundles: GitHub instruction membership does not establish Claude-native
loading. Additive `host_context` estimates a bounded project-local Claude subset:
`CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, supported explicit relative
imports, and unscoped recursive `.claude/rules` files. Paths-conditioned rules
and skill/command bodies are listed separately. Conditional or on-demand-only
presence can therefore have a zero startup estimate. Ancestors, user settings,
activation, installed host version, prose-requested reads and actual host loading remain unobserved.

Supported imports are standalone `@relative/path` lines outside fenced code.
Missing, cyclic, oversized, changed, linked, external or unsupported inputs make
the estimate `partial`; directory discovery, content reads and import depth are
bounded. `input_sources.host_context_files` binds the successfully read files to
byte-derived hashes independently of the legacy source-file inventory. Parsing, hashes and character estimates use one capped byte read.
Post-read identity checks assume a stable project tree and do not establish a
race-proof filesystem sandbox. Numeric thresholds, baseline projections, legacy
findings and downstream posture remain unchanged.

A missing optional baseline is independent of the measured warning cause. A
fresh Lite measurement on 13 October 2026 found the full manual
`.github/agents/AGENTS.md` catalogue at 5,255 estimated tokens against its local
5,000 file threshold. Configured exceedances remain real findings; governed
content compaction and its fresh measurements are validated separately rather
than clearing findings through threshold changes. This historical measurement
did not prove oversized Claude startup context. NAOS's local CLAUDE file
thresholds of 3,500/5,500 character-estimated tokens are distinct from Claude's
[under-200-line guidance](https://code.claude.com/docs/en/memory), which is
advisory rather than a vendor hard token limit. [Skill bodies load on demand](https://code.claude.com/docs/en/skills);
full body inventories are not observed startup usage.

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

Fresh-profile children receive a temporary home directory through `HOME`,
`USERPROFILE`, `HOMEDRIVE` and `HOMEPATH` on macOS, Ubuntu and Windows.
Native Python home lookup therefore resolves inside the temporary fixture;
the parent environment remains unchanged. This environment isolation is not
an operating-system security sandbox.

Scaffold manifests use forward-slash relative paths on every OS. Fresh-profile
timestamp normalization refuses symlinks, Windows reparse points, hard-linked
files and paths outside the fixture. It uses no-follow timestamps where the
runtime supports them, otherwise a checked regular-file operation, and verifies
file identity and the resulting timestamp. The fallback is confined to the
private disposable scaffold; it does not protect against hostile concurrent
filesystem replacement. Timestamp failures remain failures.

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

For current-state family review, use a separate record from the historical
changed-path record:

```bash
naos systemic-impact --profile standard --family-review-record naos/reviews/systemic.json --family-review-template naos/reviews/systemic-template.json
```

The template is created only at a new project-local path. It contains unresolved
entries and current bindings, never automatic approval. After actual review,
save the completed declaration at the selected record path and rerun with
`--family-review-record` alone. To reuse that selection from self-check, set
`paths.systemic_impact_family_review_record: reviews/systemic.json` in the
project policy **before** acquiring the template, because policy changes
invalidate the binding.

A closed entry identifies the source family and exact review surface, declares
the reviewer and UTC review time, and supplies rationale, local evidence paths
and their SHA-256 digests. `output_evidence` maps each exact required-review
instruction to its supporting evidence references. This records a declaration;
it does not authenticate a person or establish approval or correctness.
Only the matched human-review observation can settle. Missing artifacts,
unknown targets, stale files and invalid declarations remain findings. A
record's `not_applicable` disposition cannot waive an applicable requirement.

Rules, policy, root, profile, effective family definitions, matched source
membership and bytes are checked again. Without an explicit `review_binding`
declaration, changing another matched producer report invalidates the review.
The command visibly excludes its own selected record/template and report sinks
to avoid direct self-reference.

The shipped rules use `review_binding.mode: declared_producer_inputs` with a
finite `derived_report_keys` list. Each listed output is resolved through its
producer's policy path; `ci_readiness` names the runner's fixed receipt under
the selected reports directory. Their current presence, readability and byte
hashes remain visible as `producer_input_binding.derived_outputs`. These live
outputs do not identify the human source review: otherwise a self-check report
containing that review would invalidate the review every time it was written.
All original missing/stale artifact findings and downstream gate checks remain
active. A recorded source review cannot make an adverse output satisfy a gate.

Wildcard supplemental patterns may discover registered runtime observations;
only those exact declared observations are omitted, while unknown matching bytes
remain witnessed. Exact durable-sink selection still refuses.

Unknown outputs, authored baselines and immutable review evidence remain byte
witnesses. `review_source_patterns` can add independent local inputs for a family
that otherwise contains only generated reports; `review_source_patterns_by_role`
uses the same explicit kit/adopter projection as discovery patterns. These
patterns supplement existing non-derived matches and cannot select a declared
output or the review's own sinks. At least one independent regular source is
required. Closed review evidence must use stable local records rather than a
live derived output. No declaration or review template automatically approves
anything.

The optional `derived_runtime_outputs` declaration extends this same mode to
registered session report copies, canonical audit files for registered producer
endpoints/event types, and the exact policy-selected local SQLite cache. Paths
are resolved by the existing producer helpers; unknown paths, malformed events,
unknown event fields and custom report references remain current byte witnesses.
Canonical paths describe sink roles, not authenticated writers or report truth.
Runtime findings and downstream validation stay active, and these mutable sinks
cannot be used as closed-review evidence.

The session index retains its authored session identity, creation time, status,
profile, task, operator, lists and all unknown fields. Only its generated timestamp,
per-session update timestamps and exact canonical registered report references
are omitted from the structural digest. Reference matching uses the writer's
native path spelling on each OS; alternative authored spellings remain bound.
Index witnesses explicitly carry
`binding_kind: session_index_durable_projection`; their digest hashes the retained
JSON projection rather than raw file bytes. The raw hash remains visible in
`producer_input_binding.source_projections`. Missing/invalid index structure and
duplicate identities cannot supply a valid projection. Directory membership is
omitted only for nonempty trees containing exclusively exact declared derived
files; unknown siblings and truly empty directories remain witnessed. No sessions
or audit tree is excluded wholesale. This records source wiring review only and
does not approve audit evidence, task claims, operators, index freshness, behavior,
provider use or runtime enablement.

Changing the binding declaration, policy or source invalidates prior records.
Projects retaining older rules keep their full-byte behavior until they
explicitly adopt the new declaration and review its inputs. This source-review
contract does not resolve classifier predecessor feedback or the documented
pack/attestation digest cycle, and does not establish complete workflow readiness.

New audit events retain the `naos.audit_log_event.v1` schema and add
`event_id_scheme: naos.audit_log_event.public_id.v1` and `event_nonce`, a fresh
UUID4 occurrence discriminator stored as canonical ASCII decimal text. Their
`event_id` is `audit-sha256-` followed by the full SHA-256 digest produced by the
existing sorted-key compact JSON hash helper over
`{"domain": "naos.audit_log_event.public_id.v1", "event": <stored event body>}`.
The body is the sanitized stored event excluding only `event_id`; it includes
both new fields and the separately recomputed summary hash. Repeated calls
still record distinct occurrences, and an existing filename causes a fresh
nonce and recomputed identifier. The pure
`recompute_public_audit_event_id(event)` helper returns the independently
recomputed matching identifier only for supported new event shapes; legacy
random identifiers, unknown event types, malformed fields, extra top-level
fields, wrong domains, and mismatching body or summary hashes have no public-ID
recognition. No randomness, filesystem, history inventory, or provider access
is needed to check an event. This establishes deterministic correlation only:
repository writers can construct or change an event and recompute its ID, and
the nonce and body hash do not authenticate a producer, prove event truth,
prove credential safety of other fields, or make the log tamper-proof. Existing
legacy event files remain readable without rewriting their bytes or names;
legacy random identifiers receive no new recognition. Ordinary secret checks
continue to apply to every other event value and credential assignment.

## Module Header Traceability

Module-header traceability evaluates whether configured Python source modules use the canonical NAOS header linking source files to requirements, tasks, specs, rationale, and design notes.

An enabled scan with no applicable Python modules reports advisory
`not_configured` evidence with `coverage.status: not_assessed` and requires
human review. It does not establish passing coverage for Java, TypeScript or
other languages. Python modules omitted by the configured includes and
malformed scan configuration retain the profile's finding severity, including
blocking in Assured. Explicitly disabling the capability remains a separate
`disabled` state.

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

Report `--output` paths containing a lexical `..` component are refused even
when normalization would place the report inside the project. From the project
root working directory, use a relative path without parent components, or use
a resolved absolute path contained within the project. Ancestor, symlink and
hardlink checks still apply to the selected report path.

Apply implements native macOS/Linux/Windows operations with CPython 3.11–3.13;
other runtime families fail closed. See `PLATFORM_ADAPTERS.md` for bounded
native qualification. Each successful leaf uses a same-directory temporary
before POSIX link, Windows no-clobber rename, or explicit replacement. Windows
reparse points (including junctions) are refused. Windows preserves source
read-only attributes and inherits destination-directory ACLs; `--force` does
not clear an existing destination’s read-only protection.
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

Successful worksheet generation exits 0 even when its review report is
blocked; the report does not approve adoption. `--write-markdown` uses the
configured or explicit JSON report's `.md` sibling. Where no default report
path exists, supply `--output` or `--markdown-output`; otherwise the command
returns usage error 2 without writing a report.

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

### Consuming one external result routing review

An imported result remains `classification: unknown`, `verification_status:
unverified`, `review_disposition: needs_review` and `human_review_required: true`
in the external ingest report. A project-authored item can close only its generated
**routing review obligation**. It cannot verify the finding, authenticate the
reviewer, approve implementation, accept risk, establish coverage or rewrite the
external report. No-result assessment prompts and report-wide schema/content
errors cannot be consumed by this contract.

Use the exact generated `CPR-EXTERNAL-SARIF-<UPPERCASE_RESULT_DIGEST>` item id,
`source_type: external_sarif_result_finding` and the current ingest report's
project-relative `source_ref`. Supply nonempty `owner` and `rationale`, the existing
expected `target_surfaces`, a normal routed disposition (`routed`, `accepted_gap`
or `accepted_risk`), and `review_date` matching the date of `reviewed_at`.
A waiver cannot substitute for review. The disposition describes routing only.
Add this explicit binding to the item:

```yaml
external_result_review:
  external_result_id: sarif-<current-result-digest>
  source_sha256: <current-imported-source-byte-sha256>
  report_content_sha256: <current-routing-review-content-sha256>
  reviewed_at: <timezone-aware-ISO-8601-timestamp>
  supporting_ref: reviews/external-result-routing-review.md
  supporting_sha256: <supporting-artifact-byte-sha256>
related_evidence:
  - reviews/external-result-routing-review.md
```

The reconciliation exposes the current `report_content_sha256` as
`external_sarif_result_reconciliation.source_report.routing_review_content_sha256`.
Its exact v2 scope is the parsed external ingest report with **only its top-level
`generated_at` omitted**, serialized by Python `json.dumps` with `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, encoded as UTF-8,
then SHA-256 hashed. Non-finite JSON constants leave a malformed-report route pending.
Every other field, including assessment, result records, findings, source path and
project root, remains bound. JSON whitespace/key order and timestamp-only refreshes
do not invalidate review; any other content change does. The helper is
`scripts/naos_control_plane_review.py:external_routing_review_content_sha256`.

The supporting artifact must be nonempty local regular-file evidence, listed in
`related_evidence`, with matching bytes. It must differ from the imported SARIF,
ingest report and review-items declaration (identical byte digests also fail).
The full current v2 report schema must validate through the existing local schema
validator; an unavailable schema/validator leaves review pending. Report profile,
absolute project root and NAOS root must match the current requested scope.
Project-relative canonical paths, containment and no-link guards apply; each
consumption operand is bounded to 4 MiB. The current local raw SARIF named by
`scans.resolved_source` must still match the imported `source_sha256`. Duplicate
mapping keys, duplicate matching items, malformed bindings, missing files, changed
bytes, invalid/future timestamps and timestamps older than the configured
`freshness_window_days` (default 90 days) leave routing pending. An unmatched
opt-in review declaration remains visible as an unresolved authored item.

A consumed route reports `external_review_consumption.status: consumed`,
`claim_scope: routing_review_only` and `routing_review_consumed: true`. Its routing
`human_review_required` becomes false; `external_imported_human_review_required`
remains true. Raw external reason codes, unknown/unverified classification,
execution status and undeclared coverage remain visible. This declaration and its
supporting bytes are review metadata, not authenticated human sign-off or proof
of external evidence adequacy. Absent the opt-in binding, generated routing
remains pending under the existing rules.

## Evidence Integrity And Reviewer Attestation

Evidence attestation records local SHA-256 digests and reviewer metadata for configured evidence artifacts. Use this flow:

`configure -> hash -> report -> review -> record gaps/risks/waivers -> refresh evidence`

Freshness is the age of the adopter-local file's modification time. New structural
seeds and the secure-coding control register receive generation-time modification
times in an init or upgrade preview, including when the kit comes from a
reproducible archive with epoch timestamps. This does not establish upstream
source currency, content approval or reviewer attestation. Archive timestamps
remain reproducible; existing adopter configuration and evidence are not refreshed
by generating a preview. Their configured stale-artifact checks still apply.

Attestation artifact freshness explicitly reports `basis: file_mtime` and
`source_freshness: not_established`; function-index health uses the same limit
with `freshness_basis: file_mtime`. Copying or checking out equal content may
change local age and index/source timestamp ordering. It does not prove that the
source or evidence was regenerated. Stale artifacts and an index older than
local source remain adverse in their gate contracts, and a clean age result
cannot satisfy an explicit current-source requirement. Regenerate in the
receiving checkout when ordering is unresolved. The component-specific zero
windows and rounding rules are listed in [Local producer and consumer
freshness](producer-consumer-freshness.md); they retain their existing meanings.

Each hashed artifact now carries `creator_attribution` with a `declared` or
`unknown` status. For JSON/YAML artifacts up to 1 MiB, the collector reads a
valid `generated_by.operator_id` from the same bytes used for the artifact
SHA-256 digest, using the existing local operator identifier format. The
manifest retains that producer's declared operator source when present.
Plain text, oversized artifacts, absent/invalid metadata and malformed or
duplicate mapping keys remain explicitly unknown. The full artifact is still
hashed even when metadata extraction is unavailable.

This identifies a declared producer-run operator, not an authenticated person
or the author of all underlying code. The collecting run's environment, Git
identity and operator are never substituted for an artifact creator. Matching
this declaration to reviewer metadata is an advisory self-review signal;
unknown attribution does not establish separation of duties. The manifest root
continues to hash sorted path/digest pairs, and does not authenticate metadata,
sign evidence or approve a review.

### Preparing an enforcing evidence snapshot

Before an enforcing CI run, inspect the configured required subjects and reviewer
coverage with `naos evidence-attestation --profile assured`. The default rules
require existing claims, self-check and evidence-pack reports. On a first run,
missing subjects are reported as prerequisites; generate their real reports and
retain any failures before preparing the next run. A report existing or being
hashed does not mean its governance checks passed. Record reviewer metadata only
for the scope actually reviewed; CI does not create human approval.

Self-check evaluates attestation before writing its own report, and the readiness
runner generates the evidence pack later. Attestation therefore covers the
prepared file snapshots it reads, not a guarantee about the final pack or every
later report in that run. Preserve the prior attestation with its subjects when
reproducible verification is needed. Verification after a covered subject changes
should report a digest mismatch; do not suppress that result. The runner still
collects downstream reports and preserves earlier command failures.

Prepared gate reports remain available to earlier maturity checks. During ordinary
acquisition, the runner rechecks each selected destination and removes its prior
report immediately before that gate producer runs. Cleanup refusal is retained as
a failed command; an old file cannot count as a new gate result.

The opt-in dependency-finalization phase keeps the prior gate report readable
while its replacement is evaluated, because session and PR checks consume that
report. The command must publish different bytes to the validated canonical
output. Missing output or unchanged bytes cannot establish a new result, even
with a zero exit code. An unchanged prior output is invalidated before downstream
consumption; an unsafe destination is preserved and the command fails. A newly
written adverse diagnostic remains visible without turning its failed command
into success. This phase does not infer freshness from modification time alone.

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

Evidence snapshot subjects and glob patterns use canonical project-relative
paths with forward slashes. Absolute paths, drive/UNC paths, alternate streams,
traversal, empty or dot segments, and malformed recursive globs are rejected
before collection; an invalid pattern exits 2 without replacing a prior report.
Collection, verification and conflict hashing share this path domain. Links
whose resolved target stays inside the project remain supported; links outside
it are not collected, and required excluded subjects remain missing. Verification
rechecks containment before reading each subject. These snapshot checks do not
provide concurrent filesystem transaction guarantees or translate filenames
unsupported by the receiving OS. Gate-report consumers retain their separate,
stricter no-link rule.

Attestation freshness windows are nonnegative integers. An omitted default uses
30 days; an omitted group window inherits that default. Explicit zero stays zero:
any positive elapsed time is stale, while the exact boundary is fresh. Null,
booleans, strings, fractions and negative values are invalid, including in a
disabled group's configuration. A file must match only one enabled artifact
group after exclusions. Overlap is refused with the path and group IDs rather
than allowing group order to weaken freshness or reviewer requirements. Invalid
windows and overlap exit with code 2 without replacing a prior report; that prior
report must not be treated as a successful result of the failed invocation.

Evidence conflict detection reads deterministic local evidence/review inputs and writes `naos/reports/evidence_conflict_detection.json`:

```bash
naos evidence-conflicts --profile quickstart
make -f Makefile.naos naos-evidence-conflicts
```

The report flags conflicting review outcomes, reviewer disagreement, stale artifact hashes, missing reviewer/operator metadata, duplicate attestations, potential same-operator review warnings, unsupported structured sources, and unrouted conflicts. It detects review findings only; it does not resolve conflicts, adjudicate evidence correctness, prove separation of duties, approve work, lock tasks, produce an audit conclusion, or prove compliance. Absence of detected conflicts does not prove evidence is correct.

`acknowledged` means receipt was acknowledged; it is not approval. Acknowledged,
not-reviewed and unknown records remain visible but do not constitute opposing
review verdicts. The command remains advisory, including with `--strict`.

To route a conflict, add an item to `naos/control_plane_review_items.yaml` with a
conflict source type (for example `evidence_conflict_finding`) and its exact
`conflict_id` as `source_ref`. Supply the existing required fields, owner,
disposition and targets from `control_plane_review_rules.yaml`. The same
control-plane evaluator must classify that item as routed or waived, and routing
must be enabled. Free-text mentions of a conflict type, artifact path or
attestation do not establish a route. Record gap, risk or waiver references on
the structured item. A route keeps the conflict and its findings visible; it
does not resolve them or approve the evidence.

## AI Context Continuity And Memory Governance Readiness

The installed `cognitive-checkpoint` skill contains the normative PAUL bracket
table for Lite and higher. Context-pressure instructions and profile Rule 26
reference that table: the same attributed estimate satisfies
`used = 100 - remaining`, so 60% used / 40% remaining is MODERATE and
70% used / 30% remaining is DEEP. Missing or unusable percentages are UNKNOWN,
not measured FRESH. Quickstart does not enforce cognitive checkpoints. The
Standard/Assured hook retains its caller-supplied, unset-no-op threshold checks;
it cannot measure context or verify a checkpoint. T3/T4 cadence remains declared
guidance; these source contracts do not establish cadence effectiveness or
reduced token/file churn. Shipped memory policy blocks automatic/durable
write-back enablement; checkpoint success can use the compact/task-card fallback
and never requires a memory call under that baseline.

Memory can help agents recover context, but repository evidence remains authoritative. Run:

```bash
naos memory-readiness --profile quickstart
make -f Makefile.naos naos-memory-readiness
```

The report distinguishes memory provider posture, declared MCP/tool access, platform authorization, fallback/degraded recovery, and context-pack readiness. Use `naos memory-access --profile <profile>` to write `naos/reports/memory_provider_access.json`, which verifies declared/configured access posture from safe config metadata without calling Engram, MCP, or memory tools. Use `naos memory-use-policy --profile <profile>` to write `naos/reports/memory_use_policy.json`, which evaluates manual review items, instruction-grade requirements, recall-trace readiness, and audit-event readiness. Configured providers and MCP config files do not prove usable access; agents should not claim memory was checked unless access is configured, authorized, and verified. Engram is the recommended local provider pattern, but NAOS does not install Engram, enable Engram cloud, call MCP tools, read private memories, write memory, or inject context automatically. Memory is advisory recall unless explicitly reviewed; instruction-grade memory requires approval, provenance, scope, reviewer, timestamp, source refs, and freshness/expiry. Memory is not evidence, approval, compliance conclusion, architecture authority, security exception, or legal/regulatory decision. Durable memory writes require configured, authorized, verified, and memory-use-policy-permitted access plus human review; recall traces are usage records, audit events are records, and CI has no memory access by default. If memory is unavailable, agents should fall back to task cards, compact summaries, git state, repo governance files, and deterministic NAOS reports.

MCP credential metadata retains secret-like environment/header key names and
adds bounded credential-shaped scalar field paths without reporting matched
credential values or traversing structured values. A deliberate exception retains a non-credential-
shaped `ENGRAM_PROJECT` value from an Engram server as a project identifier for
scope reconciliation. This identifier is reported in `project`/`projects` and
project declarations; it does not verify identity, access or authority. Other
environment values and matched credentials are not reported. Header key inventory
remains `absent`,
`mapping_keys_only`, or `unsupported_shape`. String-list arguments report
`string_list_options_only`: a finite credential-option spelling check recognizes
split or `--key=value` declarations, and selected credential shapes produce only
`args[index]` evidence. Other argument shapes report `unsupported_shape`; this is
not a server option grammar or complete secret scan. These fields do not verify
credentials, authentication, tool authority or usable MCP access.

The workspace registry includes Copilot `.github/mcp.json`, project Codex
`.codex/config.toml`, and Gemini `.gemini/settings.json`; optional user inventory
also includes Cursor `~/.cursor/mcp.json` and Gemini `~/.gemini/settings.json`.
Codex user inventory honors `CODEX_HOME/config.toml` only under the existing user
scan opt-in. Memory-use-policy freshness follows the selected user/managed
sources and custom Codex home rather than silently checking the default home.
The producer hashes actual selected config identities without reporting expanded
paths. The consumer compares that binding against its current selection before
mtime checks; changed or unavailable bindings require review. These digests
check source-selection consistency; they do not authenticate files or their owners.
Legacy reports
remain readable under schema v1, but need producer refresh before the new
consumer can admit their missing identity binding.
Client-policy presence checks, including Claude
`.claude/settings.local.json`, require
`client_policy_mcp_config_metadata_check_allowed: true` and do not interpret
approvals. A shared `.mcp.json` is attributed to Claude Code and Copilot CLI;
legacy `.ai/mcp.json` remains generic local metadata, without unsupported vendor
attribution. This inventories declarations, without emulating trust, discovery
precedence, inherited directory layers or runtime connection decisions.

When user inventory is selected, Claude `~/.claude.json` contributes top-level
user declarations plus only the current root's `projects[path].mcpServers` as
workspace declarations. Other projects are excluded; they never select the
workspace identity. Matching normalizes absolute path syntax, folds Windows
case and preserves POSIX case, including case-sensitive macOS volumes. Ambiguous
or malformed selected shapes require review; an inaccessible or refused selected
config is not evidence that no MCP configuration exists.

Managed file metadata is a separate default-off opt-in:
`managed_mcp_config_metadata_check_allowed: true`. It selects only the host's
Claude `managed-mcp.json` (`mcpServers`) and `managed-settings.json`
(`managedMcpServers`) in `/Library/Application Support/ClaudeCode/` on macOS,
`/etc/claude-code/` on Linux/WSL, or `C:/Program Files/ClaudeCode/` on Windows.
The registry API also permits explicit custom descriptors and synthetic managed
roots. New managed-file reads refuse linked or Windows reparse ancestors before
content inspection, using checks available across the supported Python versions.
This pre-read refusal does not claim continuous race-proof custody. User-home
ancestor handling is unchanged. User scans do not select these system files.
File declarations do not
establish effective managed precedence; MDM/plist/registry policy, managed
settings drop-ins, remote-delivered policy, in-process connectors and active
runtime inventories remain unobserved. No scan activates MCP or reads memory
payloads.

Location and shape references (checked 2026-10-16):
[Claude scopes](https://code.claude.com/docs/en/mcp),
[Claude managed MCP](https://code.claude.com/docs/en/managed-mcp),
[managed settings paths](https://code.claude.com/docs/en/managed-settings),
[Cursor](https://cursor.com/docs/mcp),
[Gemini](https://geminicli.com/docs/tools/mcp-server/),
[Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers),
[Codex config](https://learn.chatgpt.com/docs/config-file/config-advanced).
These references establish declaration locations and selected shapes, not NAOS
runtime integration or current access on any machine.

The memory-setup validator reports a non-mapping `memory` section as an advisory
warning, or a failure with `--strict`, without exposing its value. Missing or
empty configuration and valid flat or nested mappings retain their existing
behavior.

## Task Context Pack

Spec references with `#anchor` select that section before excerpt truncation; missing or ambiguous anchors are reported as invalid references. The source digest still covers the complete validated file snapshot. Identical capability cards are presented once, retaining equivalent source paths; differing cards remain visible.

For a specific active task, run:

```bash
naos task-context --task T-001 --profile quickstart
naos task-context --task T-001 --profile standard --write-markdown
make -f Makefile.naos naos-task-context TASK=T-001
```

Spec references must be portable paths beneath `specs/`. Parent traversal, absolute paths, symbolic links, Windows reparse points/junctions, hard links and non-regular files are refused with an explicit invalid-spec finding. Each accepted file is limited to 2,000,000 bytes; its bounded excerpt and evidence digest come from the same checked snapshot. Missing files remain distinct from invalid references. This is a local context reader, not a sandbox against a hostile process concurrently replacing directory ancestors.

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
query fail closed when it is unavailable. Windows native generations are read through
the held generation lease, including control/rules/GraphML bytes and a bounded
SQLite image deserialized into a query-only in-memory connection. This avoids
ordinary full-path reopens of native-owned generation members at the Windows
path-length boundary; reparse, hard-link, private-security, object-identity,
content and stability checks remain mandatory. SQLite deserialize must be
available on that host. This does not change registry or global path policy.

Generation manifests bind executable implementation hashes on every OS. An
engine source change invalidates older generations even when the macOS/Linux
file-reading behavior is unchanged. Prepare and independently review a fresh
regeneration path under the existing enrollment and digest-confirmed apply
contract; never rewrite an old identity or silently regenerate it. Existing
apply prevalidation can refuse an old base whose implementation has changed;
a successful refresh across that boundary requires separate executed proof.
This read-path correction does not authorize an identity bypass or automatic
regeneration.

 Optional NetworkX 3.6.1/GraphML is
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

`self-check --task T-123 --query "bounded context" --graph-path src/component.py`
forwards explicit context to the task pack and local/graph query producers.
It refreshes the index and queries before building the task pack. Use an actual
task and indexed source path. The readiness runner accepts the same flags and
forwards them through its later self-check, so that stage cannot silently
replace a scoped query with an unconfigured one. With no context, query
diagnostics use a temporary output and remain unresolved in the current
self-check; the previous default receipt is preserved, not validated.

For `context-query --path` and `graph-query --path`, use an indexed project-relative path. Leading dots and case are significant; a leading `./` and Windows backslash separators are accepted. Absolute, drive-relative and parent-traversal spellings do not resolve. If a POSIX literal backslash name conflicts with its separator spelling, use the exact artifact ID to disambiguate. Queries never resolve these operands through the filesystem. Module-header report paths and finding IDs use `/` on every OS.

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

Session freshness uses exact elapsed time, not rounded-down whole days. Omitted
active-card, compact and report windows default to 14, 7 and 7 days respectively;
an explicit zero marks any older file stale. Values must be nonnegative integers,
and policy sections must be mappings. Invalid settings refuse before session
creation or report publication. `age_days` remains whole-day display metadata.
These freshness rules apply equally on macOS, Ubuntu and Windows; they do not
change other components' separately documented zero-window conventions.

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

`gate-status` and `gate-evaluate` reject unreadable or malformed consumed
capability/maturity inputs with exit code 2 and a `naos.gate_input_error.v1`
report (`status: invalid_input`). A parse failure, ambiguous duplicate declaration,
or invalid present maturity/enforcement value cannot become an advisory maturity
downgrade. Diagnostics identify the input and invalid shape without quoting its
YAML values. A requested writable `--output` path receives the error report so
PR summaries, SARIF, the dashboard and evidence pack can retain the failure.
Without `--output`, these gate commands report to stdout only; callers that need
persisted evidence must provide the consumer's report path.

Required evidence is evaluated separately from required input directories.
Gate reports retain file availability, structural validation, declared scope,
bounded producer outcome and unresolved references. Malformed, unsupported or
adverse required reports cannot make a gate `ready`. A report's schema and
clean outcome establish only its declared check; stored reports do not prove
that current source was rechecked. Freshness remains `not_established` unless
a separate current-source check establishes it. G2 retains its live plan
coherence requirement.

The manifest may attach `evidence_requirements` to its existing
`required_evidence` paths. An explicit `type: manual` admits a readable local
review artifact without labeling it a producer pass. Shipped optional report
requirements use `optional: true`; only valid current local configuration can
establish that a disabled producer is inapplicable. Missing configuration or a
report's own disabled flag cannot grant that exemption. Every selected glob
match is evaluated, so a passing file cannot conceal a failed sibling.

For optional memory-readiness and memory-access evidence, explicit local memory
setup with `memory.enabled: false` and `memory.state: disabled` can establish
inactivity even when their review rules are enabled. The current local rules
must still be valid declarations. The consumer checks `configs/naos_memory.yaml`
before `naos/configs/naos_memory.yaml`; a malformed or unsafe first declaration
cannot fall through to a permissive second one. Memory-use policy remains a
separate requirement. No provider or memory-store operation is performed.

An existing optional receipt must have valid schema, fully matching scope, an
actual `disabled` or `not_run` status, and no adverse or review findings before
receiving the same exemption as an absent receipt. `unknown`, `not_configured`,
`missing_task`, partial scope, and mandatory evidence remain unresolved.

`gate-evaluate` applies the selected policy's warn/enforce transition. `--strict`
uses its strict severities; `--strict-required` retains its narrower meaning.
A blocked gate always fails. The JSON `enforcement` object records the applied
flags, exit reason and what enforced policy would block. `--gate` limits
gate-specific findings and enforcement to that selection. An Assured team
override cannot disable an enabled required/blocking base gate. Explicit owner
configuration and the existing maturity severity ceiling remain distinct.
Direct commands use `--team-id` or `NAOS_TEAM_ID`; Make may still pass its
`TEAM_ID` explicitly.

This gate boundary checks consumed fields, not full capability/state schema
conformance or the sufficiency of maturity evidence. A present state document
requires a `capabilities` list, which may be empty. Valid immature state remains
advisory, absent state retains contract defaults, and no capability directory
leaves declared gate severity unchanged. Existing omission defaults for contract
ID (filename), gate links, selected profile, enforcement, target/current/default
maturity remain supported; explicit null or invalid values are not omissions.
YAML merge overrides remain supported, but duplicate explicit keys and duplicate
capability identifiers are rejected. The gate cannot infer whether removing a
previously declared state or changing a valid declaration was authorized; that
requires a separately configured baseline/review contract. These checks neither
change the warn/enforce policy nor activate hooks or approve maturity.

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

Dashboard input applicability is strict by default: every missing configured report retains its profile-severity finding. A project can opt in through `naos/policy/default_policy.yaml` (or an explicit project policy passed with `--policy`):

```yaml
dashboard:
  applicability: selected_workflows
  selected_workflows: [professional_adoption]
```

The recognized workflow IDs are `professional_adoption`, `brownfield_adoption`, `ai_code_provenance`, and `regulated_context`. An unselected workflow only exempts an absent report from the dashboard's missing-input finding when its input belongs to that documented workflow. The JSON `input_applicability` section and Markdown table show each decision and reason. Unknown, duplicate, or malformed declarations preserve strict missing-input findings. Canonical and project gate requirements override workflow selection, including report paths remapped through policy or CLI; disabling a capability does not waive a gate. Every present report is still parsed, and malformed or unreadable reports remain findings. Producer status, findings, and human-review obligations remain visible; input availability does not establish project readiness or approval.

| Workflow ID | Eligible dashboard inputs when absent |
| --- | --- |
| `professional_adoption` | `adoption_summary`, `context_challenge`, `plan_challenge`, `decision_probe`, `planning_gate_review` |
| `brownfield_adoption` | `brownfield_baseline`, `repo_context_challenge` |
| `ai_code_provenance` | `ai_code_provenance` |
| `regulated_context` | `compliance_posture` |

Generated Lite, Standard and Assured automation carries the shipped gate baseline in `scripts/workflows/gatekeepers.baseline.yaml`, beside the dashboard script. Keep these files together when relocating automation; a custom governance root still uses its own project gate manifest in addition to the shipped requirements. A missing or malformed required baseline denies applicability exemptions. Source and installed kit commands retain the original template baseline. This copied runtime resource is editable project content, not an authentication or tamper-resistance mechanism.

The table is intentionally bounded for `selected_workflows`. An unrun static inventory, intake, install plan, install decision, and all other dashboard inputs retain missing-input findings until their own applicability is established. A standalone challenge command counts as selecting `professional_adoption` for this declaration.

For an explicit view of the project's current obligations, use:

```yaml
dashboard:
  applicability: selected_obligations
  selected_workflows: []
```

This mode requires the reports selected by the shipped and project gates, full self-check producers, enabled capability requirements at current or target L2 and above, explicit report operands, selected workflows, and authored AI-use or compliance declarations. An authored no-AI or no-regulated-context assertion still selects its report even when its list is empty. Only exact unchanged shipped declaration seeds are inert. Missing known roles with no selected obligation remain visible advisory findings; selected missing reports and present malformed or adverse inputs retain their findings. Unknown or malformed selectors, capabilities, gate manifests or declaration baselines deny advisory reclassification. Generated dashboards carry the two declaration baselines beside the gate baseline so the same selection works after relocation. These editable resources establish comparison defaults, not authenticated policy or approval.

The generated Markdown dashboard includes a reader index, compact testing metrics, a compact control-plane status matrix, and GitHub-compatible collapsed detail sections for lower-noise panel summaries. Testing metrics summarize existing deterministic inputs such as pytest coverage posture, source-to-test mapping, unmapped source counts, mapped evidence-type counts, test-evidence validation posture, declared AC/SCEN completion evidence posture, and test-quality hygiene posture. Critical status, failed or missing evidence, human-review requirements, behavioral readiness posture, testing posture, and non-claims remain visible outside collapsed details. The dashboard may include Mermaid diagrams for bounded governance/readiness flows, but this is Markdown rendering only: it is not a web dashboard, runtime UI, JavaScript feature, approval surface, or publication artifact.

### Secret-hygiene scope

Secret hygiene scans the configured roots and, by default, supported immediate
project-root files. Set `include_root_files: false` in
`naos/secret_hygiene_rules.yaml` to retain only selected roots. This does not add
recursive scanning of other root directories. Existing directory/glob exclusions
still apply. Selecting the `.env` suffix includes bare `.env` and `.env.*` files
within this scope, as well as files ending in `.env`.

The fresh secret-hygiene seed and fallback exclude `dev`, `dist`, `build` and
`__pycache__` by default, including nested directories with those names.
Existing adopter exclusions remain authoritative. Other hygiene commands
retain their own default exclusions. This does not add new scan roots.

Known key prefixes and private-key headers are independent of placeholder
handling. Credential-name assignments support quoted JSON/YAML/Python-style
values and simple quoted or unquoted dotenv assignments, including names such
as `AUTH_TOKEN`. The shared matcher also handles prefixed assignments and simple
unquoted YAML values, preserving escaped quoted literals. The shared provider
patterns include AWS, OpenAI-style, GitHub and Slack shapes and bearer tokens.
These are lexical heuristics, not complete format parsers.
Entropy review uses correctly paired quoted literals containing letters and
digits without whitespace; punctuation is retained. It excludes exact
`[ADAPT: ...]`/`[FILL: ...]` placeholders and bare `$NAME`, `${NAME}` or GitHub
`env.NAME`/`secrets.NAME` expressions. Defaults, mixed literal/reference values
and recognized credentials inside placeholders remain candidates. Secrets with
other forms, whitespace or low entropy may be missed; use dedicated scanning
where needed. Managed files are not blanket-excluded.

The seed and fallback ship with empty `entropy_allowed_values`. Exact public
identifiers, including `D3_instruction_following_behavior`, are recognized through
separate digest-bound public declarations, not an adopter-owned default allowlist.
These exact declarations skip entropy only; credential-name assignments and known
provider prefixes still run. Unknown or changed high-entropy literals remain
candidates; source paths and scan thresholds are unchanged. Additional
adopter-reviewed exceptions remain explicit; no literals are learned or added
automatically.

Repeated matches have distinct rule/path/line/column IDs and retain separate
SARIF fingerprints. Values are not copied into findings. Secret reports count
selected, successfully read and failed UTF-8 inputs separately; read/decode
failures and unsafe selected symbolic-link leaves remain findings with incomplete
input coverage. A bounded reporting-only exception recognizes a stable direct
root `AGENTS.md`, `CLAUDE.md` or `GEMINI.md` alias to another selected regular root
instruction file that was successfully scanned. The alias is not opened; its
advisory row reuses the scanned target path and digest. `files_scanned` counts
actual reads and `instruction_aliases` counts these aliases. Link text, link and
target metadata, and root identity must remain stable at terminal observation.
Windows requires the exact symbolic-link reparse tag; junctions, unknown reparse
types, outside targets, dangling, chained, unselected, unread or changed aliases
remain refused at profile severity. This exception grants no ownership or
mutation authority and does not prove continuous namespace custody. This covers
configured project text (default project root, with explicit suffix and directory exclusions), not binary/unsupported files or excluded descendants. Existing adopter `scan_roots`, suffixes, exclusions and `include_root_files` remain authoritative. Discovery refuses linked/outside-root paths and records unreadable directories as incomplete; unselected suffix files and skipped discovery remain visible. Generated default rules exclude `dev`, `dist`, `build` and `__pycache__`. Existing policy severity, strict
exits and explicitly reviewed allow values/annotations remain in effect.

### Scan input completeness

Dependency-integrity and duplicate-function checks default to `scan_roots: inferred`.
They select flat Python files, top-level Python packages and common adopter roots
(`src`, `app`, `apps`, `packages`, `services`, `lib`, `libs`, `cmd`, `tests`).
Directory aliases follow the native filesystem; distinct case-sensitive directories
stay distinct. Explicit root lists or scalar selectors remain supported. Omitting
inferred Python inputs, or selecting a Python file that cannot be assessed, leaves
coverage incomplete and produces a finding at the configured profile severity.
These controls analyze Python ASTs only; unknown layouts and other languages do
not become verified merely because selected Python files passed.

Concrete package roots declared in supported setuptools, Poetry and Hatch
`pyproject.toml` fields are also inferred. Unsafe or malformed declarations are
adverse; unsupported broad declarations remain visibly unassessed. Explicit
selectors remain available for other layouts.

The local context source/test metadata families share this inferred scope and
retain Python symbol summaries. Other supported implementation suffixes use
path, suffix, size and hash metadata, with no raw bodies or language semantics.
Repository intelligence retains private coherent snapshots for integrity checks
and skips body relationship extraction for this metadata-only family. Generated
`scripts/` bodies are not inferred solely from the directory name. Pruned vendor/private directories are recorded as
excluded directories with `descendants_enumerated: false`, rather than claiming
that every excluded leaf was visited.

Duplicate-function hygiene accounts for discovered, selected Python files. Test-quality hygiene additionally records selected-root discovery failures and non-Python files as unassessed; it does not execute or assess their assertions. Missing optional roots remain visible without manufacturing read failures. `summary.files_selected` counts selected files;
`files_scanned` counts files whose scan completed (older reports counted selections); `files_failed`,
`parse_errors` and `read_errors` expose gaps. `summary.coverage_status` and
`scans.coverage_status` describe only this input set. Per-file outcomes appear
in `scans.input_files`; failures also produce normal findings and `known_gaps`.
Discovery bounds for these two static hygiene producers are 50,000 unique entries per invocation (including selected roots and immediate root accounting), 50,000 selector occurrences, and depth 64 relative to the project root. Duplicate and overlapping roots share entry and traversal accounting. Windows drive-relative, drive-absolute, rooted and UNC selectors and parent traversal are refused lexically on every host before metadata access. Excluded directories are pruned and linked ancestors are checked from the root outward. Entry, selector or depth exhaustion emits a policy-severity discovery finding and marks coverage incomplete; the partial inventory follows filesystem enumeration order before bounded sorting and is not a complete scan. These bounds do not change profile severity, strict exit policy, or adopter-relative root selections.

Test-quality advisory signals include recognized pytest/unittest skip/xfail declarations on functions, direct classes and module `pytestmark`; assertions after an unconditional return/raise in the same suite; literal-disabled branches; and assertion syntax under handlers that may swallow AssertionError. These are bounded static review signals, not runtime reachability, malicious intent, authorization or correctness proof. Aliases, dynamic inheritance and arbitrary control-flow reasoning remain unassessed. Existing legitimate skip/xfail cases and unconditional re-raise handlers remain valid.
Python source encoding declarations are respected. Parser recursion failures are
reported as `parse_error`; duplicate normalization recursion failures are
`analysis_error`, counted separately in `summary.analysis_errors`. A file whose
duplicate analysis fails contributes no partial duplicate-group members.
Ordinary CLI summaries show the input state and selected/scanned/failed counts,
including `not_configured` when no files were selected. These diagnostics do not
bound all resource use or guarantee survival of interpreter or process failure.

The source-to-test map records `coverage_inputs` and summary counters for selected,
parsed, failed and unsupported inputs. Explicit `--coverage` paths are bound to
the project root and retained even if missing. JSON files must contain a `files`
object of named object records; XML must have a `coverage` root and nonempty
class filenames. Empty valid reports contain no per-source evidence. Discovered
binary/HTML artifacts are inventoried as unsupported auxiliary inputs; explicitly
selecting them produces a finding. XML/JSON failures remain visible alongside
valid inputs. Valid references can support `yes`; absent references remain
`unknown` when another selected input failed.

Python test associations use exact AST import declarations resolved against the
configured source roots. Comments, strings and unrelated name substrings do not
map a source. Filename-only hints remain `weak_heuristic` candidates and do not
increase mapped-source counts. Ambiguous module paths and unresolved relative
imports remain unmapped; valid source-specific coverage references can still
provide a separate mapping. Invalid Python test inputs remain visible failures.
These are static declared links, not proof that a test imported or exercised
the source at runtime.

Input completeness is not line coverage, test sufficiency or behavioral proof.
The health validator uses existing profile/advisory severity and configured
exit policy; a zero exit in warning mode is not a clean report. Legacy maps
without completeness metadata retain an explicit unknown-completeness gap.
The test-evidence CLI also shows this `unknown` input state. Its finding-severity
status can remain `pass` when no findings were recorded; that is not a statement
of complete inputs. Regenerate the map to obtain measured input completeness.
Dashboard testing metrics show input failures; evidence packs retain reports,
and SARIF exports their findings. Self-check retains its existing advisory
coverage validation and consumes the same bounded mapping results; it does not
execute the discovered tests.

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

Read the pack's dimensions separately. `assembly_status` describes whether its
required files were collected; `producer_outcome_summary` preserves the bounded
outcomes of registered report contracts. `readiness` lists unresolved sources
for stored-report review, including unsupported, malformed and adverse reports.
A complete assembly can contain failed evidence. The legacy top-level `status`
and command exit continue to summarize collection findings under the configured
profile; neither is an approval or a pass for every included control.

Each classified artifact retains its original data and a content digest, so the
classification can be checked against the bytes collected. Source finding
references are retained without copying them into a new recursive finding count.
Each named report slot is also bound to its expected producer contract; one
passing report cannot fill unrelated report slots. Invalid nested fields leave
the original report visible and mark its summary projection unresolved.
Unknown report formats remain unresolved. The pack's file-age metadata is
explicitly based on file modification time and cannot establish that a producer
checked current source. Its `readiness.source_freshness` remains
`not_established`; valid report structure is not independent verification.

Dashboards retain these separate collection and readiness dimensions. PR
summaries validate the stored gate sources and retain unresolved references,
protected policy violations and enforcement metadata. A CI receipt's `status`
describes command execution and output collection; its separate `gate_readiness`
does not become ready merely because a warn-mode command returned zero.

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

External HTTP/HTTPS URLs, URIs and identifiers remain unverified reference
context even if an evidence object declares `verified: true`. That flag alone
cannot satisfy a claim's evidence requirement. Supply a regular project-local
supporting artifact using a project-relative path with forward slashes. Absolute
paths, backslashes, parent traversal, directories and symlink/reparse components
are rejected. Local reference validation does not itself prove claim truth,
evidence sufficiency or human identity.

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

`naos external-evidence-ingest --source <scan.sarif>` writes `naos/reports/external_evidence_ingest.json` by parsing a local SARIF 2.1.0 file, summarizing tool names, result counts, native levels, rules, and affected paths, and preserving one deterministic opaque review record per imported result. The record includes source digest and ordinals, source-identity posture, tool/rule/native-level metadata, first artifact URI, and unverified source-declared taxonomy references; arbitrary result-message text and raw SARIF payloads are omitted. The report distinguishes successful execution with zero reported results from not-assessed, unknown, failed, missing, or malformed input, while keeping coverage explicitly `not_declared`. `naos control-plane-review` creates one repeatable advisory review prompt per result and an assessment prompt when no result record exists but execution/coverage still needs review. G2/G6 labels are human-review destinations only and do not change gate decisions. When `--source` is omitted, the producer reads only the project-local `NAOS_ROOT/external_evidence_source.json` declaration. Its inert default is `{"schema": "naos.external_evidence_source.v1", "source": null}`; set `source` to a canonical project-relative POSIX path such as `inputs/scan.sarif` to retain the same local source during subsequent CLI, CI and self-check runs. Explicit `--source` takes priority. Malformed, duplicate, oversized, linked or unsafe declarations fail closed; absence or null remains not configured and cannot satisfy supporting-evidence requirements. The report binds declaration bytes and SARIF bytes, and replay checks the current declaration and source. A confirmed ingestion notice establishes only local parsing, byte hash and count; imported findings remain unknown, unverified and subject to human review. Nonempty exact-source ingestion can support the bounded L2 ingestion-structure requirement, with an explicit claim ceiling; it does not establish finding adequacy or satisfy a gate directly. With no selected source, ingest records a visible not-configured/advisory posture and control-plane reconciliation is not applicable. Imported results remain unverified external review evidence: neither native levels nor source-declared taxonomy references are mapped to NAOS risk, severity, controls, or requirements authority, and the commands do not run scanners, verify findings, prove assessed scope or vulnerability absence, persist human dispositions, create tasks/writeback, approve, block, prioritize, remediate, attest, certify, release, publish, or prove compliance.

To act on selected recommendations, use `naos add setup-module --list` and then `naos add setup-module MODULE_ID --profile PROFILE --dry-run`. The add path is catalog-driven and applies only explicit `install_actions`; it refuses readiness-only or deferred modules, does not install providers or services, and does not silently enable advanced behavior.

Agent trace validation reads declared records from `naos/agent_trace_events.yaml` and writes `naos/reports/agent_trace_validation.json`. Standard/assured projects can add optional `action_receipt` metadata to a trace event after meaningful agent actions, review checkpoints, or hallucination-sensitive claims when side effects, approval posture, permission scope, memory trust, or claim-to-evidence review should be explicit. Trace events and action receipts are records for StaticGrader and future audit flows; they are not proof, approval, evidence authority, memory writes, runtime capture, runtime enforcement, tool-call interception, legal/compliance/regulatory assurance, or behavioral safety evidence. Agent trace validation does not implement runtime capture, LLMGrader runtime, command execution, Engram/MCP calls, memory tools, provider/API dependencies, or permission enforcement, and trace records must not contain secrets, prompts, private memory payloads, customer data, or tenant data.

Trace validation applies shared credential-value patterns to every scalar and
credential-shaped mapping key, including invalid records, limitations and
nonclaims. Ordinary path names such as `docs/token.md` or
`specs/approval-workflow.md` do not assert payload disclosure or approval.
Explicit credential-reference markers, dotenv/private-memory references and key
headers retain their review findings; narrative keyword findings are indicators,
not proof of a leaked credential. Known-value checks still apply to path fields.
POSIX absolute/traversal paths and Windows rooted, drive-relative, drive-absolute,
UNC and traversal paths receive the same scope decision on all hosts. Final trace
reports redact selected credential-shaped values in summaries, schema errors,
paths and mapping keys. This is bounded pattern filtering, not exhaustive secret
detection, input-file cleaning or a guarantee that traces are safe to publish.
Audit-log source summaries use the same known-value patterns in addition to
their existing conservative private-payload rules. New event metadata and
historical summary outputs are filtered before serialization; existing log
files are not rewritten. These filters do not establish complete redaction.


Harness trace import reads an explicit repo-local JSONL/NDJSON file and writes `naos/reports/harness_trace_import.json`; with `--write-events`, it appends valid normalized records to `naos/agent_trace_events.yaml` for later `naos agent-traces` validation. It does not execute harnesses, capture runtime events, activate hooks, run commands from trace records, call providers/APIs, access the network, read memory payloads, write memory, approve work, certify outcomes, or prove behavior.

AI-surface health budget reads configured AI/governance artifact families and writes `naos/reports/ai_surface_context_budget.json` in legacy singleton mode. It estimates standalone and combined context pressure, validates required anchors, compares against an explicit approved baseline when present, and surfaces degraded/warning posture to StaticGrader, grader assessment, gate status, evidence pack, and dashboard. Its opt-in `--fresh-profiles` mode measures four isolated generated profiles and has no default write. Both paths are deterministic and local-file-only: they do not call models/providers, read or write memory, prevent hallucinations, evaluate behavior, auto-tune thresholds, or approve baseline changes.

StaticGrader reads trace validation/report metadata where present and writes `naos/reports/static_grader_report.json`. It is deterministic and structural only: BaseGrader defines the small protocol, StaticGrader checks trace schema conformance, source/evidence references, task/spec/capability linkage, forbidden-payload absence, non-claim boundaries, residual risks, and zero-cost posture. It does not evaluate semantic behavior, fairness, alignment, robustness, safety, explainability, accountability, legal/regulatory posture, runtime behavior, or hallucination risk. D2/D3/D5/D6/D7/D8-style behavioral dimensions remain not evaluated/readiness-only, and humans decide any durable conclusion.

Its `ready` status requires all eight supported structural dimensions to pass and no project findings to remain. Fixed unsupported behavioral dimensions stay visible in findings, summaries and limitations, with human review still required; their presence alone does not force every report to remain advisory. Missing inputs and project findings retain their existing severity. Implementation `source_path` references are portable paths within the kit or generated project.

Grader assessment reads StaticGrader and trace/conformance metadata and writes `naos/reports/grader_assessment.json`. Use `naos grader-assessment --mode audit` or `make -f Makefile.naos naos-grader-assessment MODE=audit` for deterministic audit input, `--mode drift --baseline <path>` to compare deterministic report baselines without semantic drift inference, and `--mode assess` for posture summary only. It is zero cost by default, has no LLMGrader runtime, no model/API/provider calls, no behavioral compliance determination, and no certification or approval authority.

Model-provider policy reads `naos/model_provider_policy.yaml`, optional `naos_model_role` agent frontmatter, optional mixed-tool `tool_model_bindings`, and future-readiness references, then writes `naos/reports/model_provider_policy.json`. Use `naos model-policy --profile <profile>` or `make -f Makefile.naos naos-model-policy`. It validates declaration coherence for model roles, per-tool model bindings, provider kind, alias/latest/preview posture, cost/data exposure, environment-variable-name posture, cross-tool drift, and disabled runtime posture. Control-plane review may route report findings for human review. It does not call providers, start local models, validate credentials, recommend models, maintain provider catalogs, rewrite IDE/tool configuration, route runtime calls, inspect or mutate MCP/Engram configuration, approve work, certify controls, prove compliance, promote maturity, or activate LLMGrader/autoresearch/semantic behavior.

Model telemetry evidence reads `naos/model_telemetry_evidence.yaml` plus explicitly declared local YAML, JSON, or JSONL telemetry summaries, then writes `naos/reports/model_telemetry_evidence.json`. Use `naos model-telemetry --profile <profile>` or `make -f Makefile.naos naos-model-telemetry` when a project explicitly wants local model-use telemetry reviewed for session/task/model-role links, policy refs, cost/latency thresholds, payload/credential field presence, sensitive data class posture, stale records, and policy exceptions. Control-plane review may route report findings for human review. It does not call providers, models, APIs, gateways, MCP, memory tools, networks, hooks, local servers, or IDE settings; it does not validate credentials, start gateways, route runtime calls, inspect payload semantics, prove complete costs, approve work, certify controls, prove compliance, or activate model/provider runtime behavior.

Learning-loop review, memory-use policy and model-telemetry evidence preserve YAML
date and datetime scalars as text, including unquoted values. Their existing
temporal checks interpret dates and timezone-naive timestamps as UTC; explicit
offsets retain their meaning. Reports retain the input spelling as JSON strings.
Where required by their review rules, invalid learning review dates and memory
review/expiry dates produce findings. Invalid supplied telemetry timestamps also
produce findings, even without a freshness threshold. These inputs remain visible
rather than disappearing or causing date serialization failures. A valid memory date does not establish live memory
access. This loader is limited to these reporters; other YAML loaders and
boolean types are unchanged.


LLM-grader readiness, graph-context readiness, model-provider policy,
memory-provider access and memory-use policy require actual YAML booleans for
consumed boolean settings. Quoted `"false"`, `"no"`, null, numbers, lists and
mappings are not boolean declarations. A present malformed value produces a
`boolean_setting_invalid` finding and cannot enable optional behavior; report
summaries require review instead of silently accepting a disabled posture.
Absent optional keys retain their documented defaults. Existing mandatory
memory-policy declarations still require explicit values and retain their
blocking diagnostics. Malformed metadata-check permissions are denied before
binary, store or MCP inspection. This does not enable provider calls or turn a
valid configuration into proof of usable memory access. On Windows, named-user
home paths such as `~other-user/data` are refused as unresolved; provide an
explicit path or use the current user’s `~` home. POSIX named-user resolution
is unchanged.


For failure-mode posture, failure-mode observations, OpenCode config hygiene
and design traceability, control-plane review checks the producer's local
activation conditions before deciding whether an absent report is inapplicable.
An enabled feature with a missing report requires review. Present reports must
match their expected schema, project, profile and NAOS root; malformed,
unrelated, adverse or contradictory reports cannot become a clean result merely
because no known finding ID was found. Routing uses the same classified content
bytes and retains its evidence classification with the source reference. These
are checks of stored reports; they do not establish current-source freshness or
authenticated approval. Existing profile severity rules still govern the review
route.

Failure-mode observations read `naos/failure_mode_observations.yaml` plus configured direct local report files, then write `naos/reports/failure_mode_observations.json`. Use `naos failure-mode-observations --profile <profile>` or `make -f Makefile.naos naos-failure-mode-observations` only when a project explicitly wants local report findings counted against the canonical 21 failure modes. The report automatically excludes the configured control-plane and failure-mode observation output paths, including its explicit `--output` path, so downstream review cannot feed back into its own observations. These exclusions follow `NAOS_ROOT`, the report directory and configured filenames on macOS, Ubuntu and Windows; path and file-identity aliases are excluded too. Additional `excluded_source_report_paths` remain project-relative owner exclusions. An unrelated file with the same basename remains eligible. Project-relative references use forward slashes; literal backslashes in POSIX filenames retain their meaning. Counts by mode, family, source report, reason code, severity, gate, and mapping basis are review statistics only. Dashboard, evidence-pack, SARIF, gate-status, systemic-impact, and learning-loop consumers surface those statistics as review evidence; they do not create or promote learning, mutate prompts/skills/workflows, run autoresearch, call providers/models, activate MCP/Engram/memory, approve work, block gates, certify controls, authorize release, or prove compliance.

The disabled observations seed also declares four optional detector sources through their existing policy report keys: `api_symbol_reality_report`, `package_reality_report`, `duplicate_function_hygiene_report`, and `test_quality_hygiene_report`. When explicitly enabled, canonical detector schemas are checked before findings are consumed. Validation stays local: mutable schemas cannot retrieve external references, and invalid or unresolved schemas produce sanitized review diagnostics. Missing optional reports produce no observation; required missing reports, malformed/unsupported reports and unavailable validation remain review findings. Exact configured `status` mappings link `symbol_not_found` to F1, package typo/registry absence/undeclared documentation install signals to F2, `duplicate_function_body` to S1, `missing_assertion` to B3 and `trivial_assertion` to B4. Other statuses remain visible as unmapped observations requiring review. These bounded signals do not establish fabrication, semantic correctness, meaningful coverage, or prevention. The five taxonomy modes retain gap coverage and concrete detector control references; projects must declare their own applicable evidence. Existing observation reconciliation carries counts and source references to human review, including remapped adopter report paths, without adding approval or blocking authority.


OpenCode config hygiene reads `naos/opencode_config_hygiene.yaml`, project `AGENTS.md` when review is enabled/declared or OpenCode-specific local surfaces exist, project `opencode.json` or `opencode.jsonc`, optional repo-local `.opencode/` subdirectories, and `naos/reports/model_provider_policy.json` when present, then writes `naos/reports/opencode_config_hygiene.json`. Use `naos opencode-config-hygiene --profile <profile>` or `make -f Makefile.naos naos-opencode-config-hygiene` only when a project explicitly wants local OpenCode config hygiene reviewed. It checks malformed local JSON/JSONC, stale `.opencode/config.yaml` paths, remote or absolute instruction refs, broad permission and auto-approval posture, MCP declarations, plugin refs, literal secret-like values, missing model-provider policy links, model/provider drift, and runtime-authority attempts. A shared `AGENTS.md` alone does not opt into OpenCode review. Permission scalar, tool and input-pattern maps (including agent declarations) are human-review signals, not effective permission or precedence decisions. MCP enable status is evaluated per named server; disabled servers still receive remote/authentication declaration review. Bare key names and reviewer-authorization prose are not literal-secret evidence; value-bearing credential patterns remain blocking, with matched values omitted from findings. Project-relative report paths use forward slashes on all supported operating systems. Control-plane review may route report findings for human review. It does not create, install, run, or configure OpenCode; inspect global user config; activate MCP or memory; call providers/models/APIs; validate credentials; create plugins; mutate IDE/tool settings; approve work; certify controls; prove compliance; prevent prompt injection; prove malware absence; or prove supply-chain safety.

Design traceability reads `naos/design_traceability.yaml` and writes `naos/reports/design_traceability.json`. Use `naos design-traceability --profile <profile>` or `make -f Makefile.naos naos-design-traceability` when a project explicitly wants local UI screen/component object IDs linked to FR/NFR/task refs, screen specs, implementation paths, changed-file evidence, test/check evidence, optional design references, and human-review posture. Control-plane review may route report findings for human review. It does not call or inspect Figma, MCP, html.to.design, browsers, providers, models, memory tools, APIs, networks, hooks, or IDE settings; it does not synchronize code/design, mutate design tools, prove design quality, accessibility, privacy, brand posture, implementation correctness, approval, certification, attestation, release readiness, or compliance.

Design `changed_file_refs` and `test_evidence_refs` must be lists. A string selects
a readable, nonempty project-relative regular file using forward slashes. A mapping
`{ref: "reference context", evidence_ref: "reports/local-artifact.txt"}` pairs a
command, external URL or changed/deleted path with a retained local artifact.
Absolute paths, traversal, symlink/reparse components, directories, missing or
empty artifacts produce the existing changed-file or test-evidence gap findings.
Every declared reference is checked, including those on planned objects; a valid
sibling cannot hide an invalid entry. `verified: true` alone is insufficient.
The report retains each artifact's availability and SHA-256 of the observed bytes.
Its `pass` means local declaration and artifact availability review only: it does
not verify changed-file status, test outcome, the artifact's semantic relationship
to the object, or external state. Completion claims require the separate AC/SCEN
completion-evidence contract; human review remains responsible for relevance.

UI experience quality reads `naos/ui_experience_quality.yaml` and writes `naos/reports/ui_experience_quality.json`. Use `naos ui-experience-quality --profile <profile>` or `make -f Makefile.naos naos-ui-experience-quality` when a project explicitly enables stage-aware local review of UI quality evidence. It checks declared FR/NFR/task/AC refs, open dependency posture, data/API/state refs, token/typography/spacing refs, screenshot/state refs, accessibility/performance refs, generator and advisory-AI provenance, user-validation refs, and human design-review posture. Control-plane review may route report findings for human review. It does not call or inspect Figma, MCP, Penpot, html.to.design, browsers, screenshot tools, providers, models, memory tools, APIs, networks, hooks, or IDE settings; it does not generate screenshots, run accessibility or performance tools, mutate design tools, score or prove design quality, approve UI, certify accessibility, prove privacy or brand posture, authorize release, or prove compliance.

Each declared local UI evidence reference is checked, including nested review,
inspiration, generator and critique paths. A missing, unreadable or unsafe path
produces a finding even when other evidence is present. References must use
project-relative forward-slash paths to regular files; directories, absolute
paths, traversal and symlink/reparse components do not satisfy them. External
URLs remain labeled unverified reference context. Concept exploration still
permits omitted final-design evidence; any references actually declared must
be available. These checks do not authenticate reviewers or inspect evidence
for design quality.

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

`semantic-audit` is a deprecated compatibility command: NAOS does not implement the advertised LLM code-quality audit. It returns `SEMANTIC_AUDIT_NOT_IMPLEMENTED` with exit 2 and produces no assessment or artifact. Existing similarity evidence remains optional/project-configured advisory evidence. Core NAOS is deterministic, file-first, and portable; it does not require MPNet, MiniLM, `sentence-transformers`, embeddings, GPU, or any semantic model. Projects may configure an optional provider-neutral similarity layer and provide evidence for it. `sentence-transformers/all-mpnet-base-v2` is an acceptable local CPU-friendly provider example when explicitly configured by a project; it is not a baseline dependency. Similarity evidence may challenge the deterministic baseline by producing candidates or discrepancy findings, but it may not replace exact/path/metadata/FTS evidence, approve work, promote maturity, or block without deterministic support and human review.

## Professional Adoption Engine

AI artifact inventory reads the effective `ai_artifact_inventory_rules` policy
artifact under the selected NAOS root. `artifact_patterns` accepts literal,
forward-slash project-relative file or directory paths, not globs. Discovery also
retains the bounded prompt/rule/workflow fallback and nested `AGENTS.md`,
`CLAUDE.md` and `CLAUDE.local.md` discovery. These are path-based review candidates;
detection does not assert that a particular vendor/version loads them. `scan_limits` defaults to
50 files per selected path and 5,000 fallback files; values must be integers
between 1 and 100,000. Directory traversal also has a 100,000-entry budget.
`scan_scope` records selected paths, limits, selected file counts, issues,
truncation and completeness. Counts on truncated scans are not repository totals.
Invalid rules produce `invalid_config`; unreadable, linked or truncated scans
remain explicitly incomplete. Reconciliation scans current content using the
same rules instead of relying on a stale inventory report.

Fresh behavioral-readiness seeds leave `impacter_paths` empty to use the shared
host-surface catalogue and effective inventory paths, alongside governance inputs.
A nonempty adopter list remains a complete replacement. Existing installations
with an explicit list retain it; adopting shared defaults requires the owner to
review and empty that list. Host instruction/skill changes carry medium maintenance
impact; byte changes do not prove semantic harm or vendor loading behavior.
Fingerprints retain raw bytes across all platforms. Incomplete selected fingerprint
coverage produces `not_ready`, never `baseline_current` from a partial digest.

These inspections reject static symlink/reparse paths and require no host AI tool,
provider, Bash or Make. They are local advisory inspection, not a concurrent
filesystem sandbox. The same policy applies on macOS, Ubuntu and Windows.


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

### Plan comparison reference safety

`naos plan-coherence --diff-base <ref>` resolves one commit before running the
changed-file comparison. Branches, tags and commit IDs are accepted; option-shaped
arguments, revision ranges, missing refs and non-commit objects produce an explicit
`implementation_scope_diff_unavailable` advisory. A failed comparison is not
evidence that no files changed. The existing advisory policy is unchanged.

### Trusted report resources and project inputs

Governance-bypass posture distinguishes supported local CI declarations from
missing and unknown configurations. See [CI declaration posture](CI_DECLARATION_POSTURE.md)
for provider coverage, command recognition and limitations. Declaration presence
does not establish CI execution, successful checks or merge enforcement.

Failure-mode posture checks inspect `name`, `coverage`, `known_gaps`, `notes`,
`rationale` and `summary` prose for overclaims. Control and evidence references,
and explicit disclaimer fields, are not claims of coverage. This remains a
lexical check requiring human review; it does not interpret negation or prove
that a claim is true.

`naos agent-sponsor-registry`, `naos aivss-verify` and
`naos ai-component-inventory` prefer valid project schemas and use their exact
kit schema when the project copy is absent. The component inventory likewise
uses its named kit rules/model-policy templates when project inputs are absent.
Where recorded in provenance, external kit resources use `kit://` references
and content hashes; these references do not represent project-owned declarations.
Explicit inputs remain inside the project. Malformed project files, traversal,
links and reparse points are refused rather than replaced with fallback data.

Without an initialized NAOS directory, these commands can print a JSON report
with `--json` without writing files. `--check` requires an existing selected
report and returns a controlled missing-report failure when none is selected.

### Evidence classification labels and counts

Evidence classification keeps source declarations separate from inferred review
candidates. Severity and status do not establish provenance. A reference to the
source report provides traceability; reference presence or a `verified` flag
does not establish confirmation, and this classifier does not inspect linked
content. Explicit declared labels remain source declarations. Reasoned
deductions and hypotheses remain candidates requiring human review.

`classification_counts` retains the combined label totals for compatibility.
`declared_classification_counts` and `inferred_classification_counts` expose the
split, with `classification_count_semantics` stating
`provenance_labels_not_verified_evidence`. Export, gate, maturity and dashboard
summaries preserve these fields. Legacy reports retain their aggregate counts
with `legacy_unspecified_labels_not_verified_evidence`; consumers do not invent
a declared/inferred split. No count establishes truth, approval or resolution.
The classifier uses one loaded governance-policy snapshot for each report pass.

PR `gate_unresolved` and capability maturity `missing_evidence`, `stale_evidence`,
`unresolved_evidence` and `missing_gate_evidence` findings carry provenance for
these producers' executed local gate projections or typed evidence evaluations.
The metadata retains selected references, evaluated states and available byte
hashes. A `confirmed` label here confirms that the evaluator observed an unmet
requirement; it does not confirm source report truth, evidence adequacy,
remediation, approval, maturity promotion or completed human review. The original
severity and unresolved outcomes remain active. Missing, malformed, adverse and
unclassified external material does not become approved through this annotation.

The same distinction applies to a dashboard input that could not be loaded,
missing spec/capability links in a selected trace, an absent selected policy
overlay directory, and an empty worksheet evidence mapping. Their producers
declare the observed diagnostic and its selected references; they retain the
original severity, negative status and human-review requirement. A confirmed
absence does not establish that a missing item is unnecessary or that the
underlying project is ready. Stored reports and assessment baselines retain
their original metadata until the relevant producer is executed again.

PR gate projections distinguish `readiness` for all selected gates from
`required_readiness` for enforcing readiness. A validated `advisory_missing`
row with advisory or no enforcement severity remains visible as an advisory
PR finding; it does not independently become a required PR failure. Explicit
escalation to warning, required or blocking severity remains unresolved.
Selection counts, protected invariants and evaluation enforcement must still
agree. This PR projection does not change the stricter gate-evidence contract
used for maturity or evidence packs, and neither field records approval.

Dependency finalization is an explicit opt-in collection protocol in
`ci-readiness --finalize-dependencies`. Acquisition results are retained
separately from final evaluation; the designated initial self-check and
gate-evaluation diagnostic exits can advance to final verification. Capture
stores exact prior self-check/evidence-pack bytes under
`naos/dependency_inputs/self_check_collection.json`. A new full self-check is
then verified against current independent inputs and producer results before a
separate `self_check_dependency_resolution_report` is published. Stored gate
readers require the declared full-self-check membership and revalidate the
current proof; a stored ready flag, omitted row or relabelled row is insufficient.

The acquisition dashboard records progress history before dependency capture.
The final dashboard uses `--no-progress-history` to render the existing history
without appending to `naos/TASK_PROGRESS_HISTORY.csv`. This keeps the proof's
authored input bytes stable when a run crosses midnight UTC. Standalone
`naos dashboard` retains its usual daily history recording. History remains
byte-bound: edits after proof publication still invalidate the proof and gates.

Explicit dependency acquisition may advance one additional raw diagnostic: the
exact policy-selected `ai-surface-budget` invocation returning 1 with a current
recorded `reviewed_budget_warnings_only` declaration. The invocation must publish
changed regular canonical output bytes. Before launch, guarded reads and exact
selected-policy comparison refuse aliases to policy, rules, baseline, measured
sources, review witnesses and other outputs. The policy path, bytes and effective
values must remain unchanged through production and classification. Existing
classification must reproduce
those same bytes and exact measured review subject. Missing, unchanged, unsafe or
invalid output, unrecorded/adverse review and every other independent failure refuse.
The receipt retains raw exit 1, warnings and failed acquisition status, and records
a bounded acquisition disposition; every final command, gate and complete current
dependency proof remains required. This does not alter strict exits, thresholds,
ordinary self-check consumption, or authenticate a reviewer. Synthetic test
declarations remain test fixtures, never genuine human approval.


Before explicit fresh acquisition, the runner invalidates the previous recognized
dependency proof once, after checking its scope, schema and output isolation.
Unknown, malformed, linked or aliased files are preserved and collection refuses.
Failed acquisition leaves proof-dependent readiness unresolved; final publication
and readers still verify the complete current proof. Ordinary collection preserves
the prior proof. Dashboard commands retain the full JSON report and print their
bounded presentation rather than duplicating the JSON in the collection log.

Final collection for Lite and Standard requires the validated
`required_readiness` projection; a valid advisory gap remains visible without
becoming a required failure. Assured additionally requires all selected gates
to be ready. Earlier diagnostic gate evaluations remain recorded separately
and cannot substitute for the designated final evaluation.

This does not waive independent missing evidence or adverse findings, replace
human review, or rewrite the raw self-check. Source changes invalidate the proof.
The implementation bounds this protocol to Lite, Standard and Assured with
current maturity L0–L2 and targets through L3. Lite's enabled L0 behavioral
capability permits only a source-bound, reproduced inert inspection: the raw
`not_ready` status and missing-conformance warning remain visible. This does
not establish baseline readiness, behavioral adequacy or human approval, and
stronger behavioral declarations cannot use that inspection contract. L3 proof independently checks the selected
gates, evidence membership, scope and freshness; it does not promote maturity or
complete manual G7/G8 review. Current L3 and L4/L5 remain unsupported and fail
closed. Complete Assured workflow and installed-artifact/native qualification
remain outstanding until their executed acceptance receipts are recorded. Generated report destinations, including the selected
secure-coding reference-integrity output, are excluded from authored-source
review bindings only by their explicit producer key and exact policy path.
Adjacent authored files remain bound and report contents retain their separate
evidence checks.

### PR comparison commits and host paths

The inert `naos-pr-governance.yml.example` fetches full comparison history and
passes immutable PR base/head SHAs to `pr-risk-classify`. It retains the default
PR merge checkout for executed code; comparison endpoints do not change that
checkout. Manual workflow runs require explicit 40-character commit SHA inputs.
SHA syntax is checked before package installation; the classifier still reports
missing commits or an unavailable merge base as inconclusive, never a clean
comparison. Local use can pass `--base-ref <commit> --head-ref <commit>` after
acquiring the required history. Editing this example does not enable Actions.

Default and generated PR-risk rules classify `.claude/settings.json` and
`.codex/config.toml` as protected paths under the existing high-risk category.
Root and nested `AGENTS.md` and `GEMINI.md` are AI instruction surfaces under the
existing medium-risk category. Both rename endpoints remain visible; these are
deterministic review signals, not approval or a security guarantee.
## Readiness AC validator selection

The readiness runner uses the AC-reference validator shipped beside the running
kit by default. Generated CI does not select a project-local validator.
`--ac-validator PATH` is an explicit project-contained override. The receipt's
`ac_validator` object records `runner_adjacent` or `adopter_override`, the path,
applicability and a SHA-256 digest of the selected file before execution.
Lite records the validator as inapplicable and does not require or hash it.
A missing applicable default fails without falling back to project code.
Validator/report and receipt aliases are refused before output writes.

An override remains adopter code; a successful command does not confer the
authority of the installed default. A local digest identifies observed bytes,
not installation authenticity or protection against concurrent file replacement.
Older receipts without this object do not establish validator provenance.

### Invalid alignment input in control-plane review

Control-plane review reports unreadable UTF-8, malformed YAML, missing delimiter
lines and non-mapping alignment frontmatter as
`control_plane_review.invalid_alignment_frontmatter`, with an `unresolved`
requirement outcome and human review required. The diagnostic appears even when
no parallel lanes are declared; it does not invent a lane or bypass existing
planning and human-review gates. Repair the file and rerun alignment and
control-plane review. Severity follows the existing profile policy (advisory for
Quickstart, warning for Lite, required for Standard/Assured; advisory in the kit).
A missing optional alignment file retains its existing behavior. UTF-8 BOM and
CRLF files are accepted. CLI exit enforcement continues to follow the selected
policy; a zero exit alone does not establish resolved evidence.

### Spec-cascade language coverage

`naos spec-cascade` analyzes Python source. Non-Python files in configured app
roots (after exclusions) are listed in
`source_selection.unassessed_non_python_files`; `language_coverage: partial`
requests review even when the Python checks find no drift. This inventory does
not parse those files or establish their implementation status. Requirements
without a matching Python `Implements:` header remain visible but advisory and
unresolved when non-Python files are unassessed. Actual Python orphan, untraced
and unresolved-reference findings retain the selected profile severity.

Free-text source inference requires standalone uppercase `FR-`, `NFR-`, `AC-`
and `SCEN-` identifiers, avoiding lowercase locale/CSS tokens. Explicit
requirement headers, task links and `Implements:` declarations retain existing
case-insensitive normalization. Text reports use the profile severity instead
of hardcoded advisory labels. Python-only coverage is not proof of complete
traceability; content-read completeness remains unverified.

### Conformance validator location

The conformance runner uses the frontmatter validators shipped alongside its
own runtime, including generated `naos_tools` brownfield layouts. The project
passed with `--project-root` is the inspection target, not an import location.
Missing or unloadable shipped validators produce a failed check, even when no
applicable Markdown files exist. Successfully loaded validators may report
that no files apply to a tier. StaticGrader also loads its trace-schema helper
from its own generated runtime, including the remapped tools directory.
This location binding does not authenticate
installed bytes or make the Python interpreter a sandbox.

### Capability references in generated projects

Generated capability cards point to shipped adopter files, including remapped
`naos_tools` validators and `.github/autoresearch` assets. `kit://` identifies a
dependency in a separately acquired NAOS kit, not a filesystem path, runnable
local command or satisfied evidence. Validators omitted from the generated
profile are external dependencies, not locally available validators.

Capability-contract validation discovers kit and adopter collections, retains
duplicate-ID detection and checks local references. Use `--naos-root <directory>`
(or `NAOS_ROOT`) for another governance root. Installed CLI references remain
explicitly unverified when the adopter has no CLI source; their syntax does not
prove availability. Required project configuration stays a project obligation:
a missing optional input produces `CAPCONTRACT_PROJECT_INPUT_UNRESOLVED`; its
kit seed cannot satisfy it. Future report outputs are not required at scaffold
time. A contract-validation pass does not establish capability readiness.


### Adopter PR workflow example

Lite+ projects receive `naos/workflows/examples/naos-pr-governance.yml.example`
as inert guidance. Review artifact sensitivity, declared team metadata and the
Actions budget before manually copying it into active CI. The setup catalog does
not auto-install or enable this workflow. Configure an independently reviewed
HTTPS artifact URL and SHA256 using the same acquisition contract as readiness CI.

The example runs the installed `naos_governance.scripts.naos_ci_readiness` module
with explicit full base/head commit SHAs. Its PR mode reuses the deterministic
readiness producers and collectors, includes task/conflict and PR-risk reports,
and uses `--strict-required` for Standard/Assured gate evaluation. Commands run
as Python argument lists on supported operating systems. Failed producers remain
in `ci_readiness.json`; later collectors still run, and the chain returns failure.
The adjacent packaged CLI is used internally, so an adopter does not need the
kit's `cli.py`, build files, self-validation scripts or test suite in its checkout.
Neither local collection nor uploaded reports approve a PR, authenticate team
membership, or prove hosted Actions execution.

### SARIF export identity and delivery

SARIF results keep producer-specific rule IDs and merge identical finding copies from
that producer, including delegated self-check copies. Missing child reports do
not discard findings retained by self-check. Distinct line, region, severity,
message and occurrence fields remain distinct; producers must supply an occurrence
identifier when otherwise identical records represent separate occurrences.
Summary counts describe exported results; `export_accounting` records collected,
duplicate and excluded advisory counts. Producer labels and carried source hashes
are declared report metadata, not authenticated provenance. Rule IDs and
fingerprints change with this correction, so consumers may initially display
previous findings as new.

When there is no adopter output directory and no `--output`, the command prints
the SARIF document to stdout. With `--json`, stdout retains the summary object
and adds the document under `sarif` with `output_delivery: stdout`; an explicit
`--summary-output` saves the same complete summary. Explicit file output and
adopter-default output continue to write SARIF to the reported file path.

### Assured reporter rule severity

The learning-loop, memory-context, module-header, memory-provider-access, and
memory-use-policy reports apply the selected policy's assured severity as a
minimum for rule-level severity. A lower valid request produces a blocking
`severity_downgrade_attempt` finding, including when other checks are clean.
Kit reports remain advisory; quickstart, lite, and standard keep their configured
posture, including advisory memory readiness in lite. `review_required` retains
its profile-specific severity mapping in the memory reporters. Existing explicit
disablement handling is unchanged.

This minimum is relative to the selected policy; it does not pin policy bytes
or authenticate a policy change. Memory-use rules may restrict approval to a
subset of `approved` and `approved_with_limits`; they cannot define new approval
aliases. Missing or empty lists retain the canonical default. Malformed values
and unknown tokens produce a finding, and unknown tokens never qualify an item
as approved. Review metadata and access checks still apply; these declarations
do not authenticate a human review or establish evidence authenticity.
It is separate from the gatekeeper capability-maturity ceiling: a valid immature
capability can still lower gate enforcement to advisory. Existing assured team
protections remain independent of that ceiling. Strict and transition exit rules
continue to use the selected policy.


D05 report input integrity: an explicit `research-record --schema` selects exactly
that file. A missing or non-file explicit schema produces an invalid report and
exit status 2; only the omitted option permits the established kit fallback.
Harness trace import marks imported events `tool_declared` and `review_pending`
and does not copy imported reviewer or review timestamp claims. Existing malformed
entries are refused. Existing block event sequences retain original bytes and
comments while new records are inserted; empty `[]` seeds expand while retaining comments. Unsupported nonempty flow/aliased layouts
are refused with a finding and require explicit operator conversion. Whole-file
publication stages the complete candidate and atomically renames it into place.
Existing target write access is required before staging; POSIX UID/GID/mode and
supported xattrs are copied and verified through held descriptors. Nonempty POSIX
ACLs, unsupported flags, or unpreservable metadata refuse before original-file
mutation. Windows retains the existing supported owner/group/DACL and
NORMAL/ARCHIVE attribute checks; unsupported preservation refuses. New files
retain ordinary creation permissions under the current umask or Windows parent
security inheritance. Pre-publication write, fsync, metadata or rename failures
leave original contents intact and become findings. Before publication or cleanup,
the staging pathname must still identify the held unique regular staging file;
missing or substituted names refuse publication and preserve foreign occupants.
Publication retains a
name-refresh gap after the last preimage/metadata check; it is not a concurrent
writer compare-and-swap, writer lock, or power-loss durability guarantee.
Generated scripts include the source-bound POSIX metadata observers and existing
Windows native helpers; missing metadata support fails closed.


Producer-report reproduction is local to the current absolute project root,
profile and NAOS root. A report copied from another clone or operating system
requires local regeneration, even when declaration hashes match. Historical
reports remain readable as evidence; report presence is not current consumer
acceptance. Schema, identity, source digest and all nonvolatile producer fields
remain checked. Portable acceptance would require a separately approved
provenance contract; removing the root comparison alone is insufficient.

The standalone LLMGrader-readiness and model-provider-policy commands select
their governance root from `--naos-root`, then `NAOS_ROOT`. That selected root
is used for implicit governance-policy discovery, local rules or model-policy
declarations, and default report output. With neither set, existing policy
defaults apply. An explicit `--policy` still takes precedence over implicit
policy discovery without replacing the selected root. Explicit `--rules` and
`--model-policy` inputs also retain their existing precedence.

A missing implicit policy under the selected root retains the shared loader's
kit/fallback behavior; it does not select another adopter root's policy.
Malformed selected policy files still refuse before report publication.
These declarations do not enable a grader, provider, model call or runtime.

### Documentation, CLI coverage and adapter authority

The implementation-reality validator statically inventories explicit CLI dispatch branches and the literal `SCRIPT_COMMANDS` mapping used by the real dispatcher. It imports no CLI code. Each public command and alias needs an exact `naos <command>` token in at least one checked `DOC_FILES` document, including the generated quick-reference seed; options are not commands. Documented-to-shipped-source checks remain separate.

Adapter-coherence reports distinguish `project` host-file review from `kit` canonical plugin/propagation review through `review_scope` and `source_authority`. New reports always emit both fields. Older v1 reports without them remain parseable historical bodies and establish no inferred scope/authority. Project review does not promote inherited kit review records or waive missing selected host surfaces. Context recognition and adapter review share strict structured-contract parsing, with the exact schema-only legacy form admitted separately. Customized host lists are respected; absent structured host obligations are reported as incomplete, and legacy identity-only records declare no host obligations. Kit review retains all nine exact propagation mappings. No scope claims live plugin installation or provider/host execution.

Brownfield inventory includes root and nested `AGENTS.override.md` using the retained Codex instruction contract. Discovery, reconciliation and default fingerprints share bounded literal selection and raw-byte change detection; explicit fingerprint path overrides remain authoritative. Truncation and refused links/reparse paths stay visible. Project-local inventory additionally selects `.cursor/skills`, `.cursor/mcp.json`, `.vscode/mcp.json` and workspace-root `.mcp.json`. When `.cursor/skills` is enabled in the effective literal inventory, the existing bounded discovery also selects nested `<project>/.cursor/skills/<skill>/SKILL.md`; custom path selection and explicit fingerprint overrides remain authoritative. A declared required host file, including `AGENTS.override.md`, supported MCP files or Cursor `SKILL.md`, must exist; an optional inventory directory does not become mandatory merely by being a default. MCP entries expose path, host role and raw-byte SHA-256, with no text sampling or credential-based ownership/compatibility inference. They remain review-required; a file/hash does not establish trust, approval, connection or active MCP servers. User/global configurations and unsupported `.github/mcp.json` are outside this declared selection.

The supported locations follow official [Cursor Skills](https://cursor.com/help/customization/skills), [Cursor MCP](https://cursor.com/docs/mcp), [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration), and [Claude Code MCP](https://code.claude.com/docs/en/mcp) documentation retrieved on 2026-10-16. `.vscode/mcp.json` and `.mcp.json` have distinct host/harness formats and settings; inventory does not translate or activate them. This is bounded source-supported path coverage, not complete discovery of extension-registered/global tools, observed host loading, or native case/reparse assurance. Existing separate MCP registry/memory scanning and trust/activation policies are unchanged.
