# NAOS Tutorials

The prompt/agent rows below describe the kit-source superset. Quickstart
installs no prompts and only `@naos-research`. Lite installs its bounded prompt
set plus `@naos-plan`, `@naos-implement`, `@naos-review`, and
`@naos-research`; it does not install triage or conformance agents.
Standard/Assured install the full prompt and agent catalogue. Use a tutorial
only when every named prompt and agent exists in the generated project, or
follow the profile-specific fallback described by the integral tutorial.

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_
> **Audience**: Developers and teams adopting NAOS governance for their AI-assisted projects.
> **Goal**: Learn to use NAOS workflow commands, understand agent roles, and build sustainable governance habits.

NAOS is now documented as a file-first control plane as well as a prompt/agent workflow. For generated projects, the seeded [NAOS Quick Reference](../../templates/structural-seeds/naos/NAOS_QUICK_REFERENCE.md) is copied into `naos/NAOS_QUICK_REFERENCE.md` and summarizes profiles, capabilities, policy, validators, gates, evidence pack, dashboard, and operational wrappers. Pair it with [CONTROL_PLANE.md](../CONTROL_PLANE.md) when you need the current control-plane model.

---

## Reading Order

You do not need to read every tutorial before using NAOS. Start with the route
that matches your situation, then use the deeper tutorials only when they are
relevant to the work in front of you.

| If you are... | Read first | Then use |
| --- | --- | --- |
| Trying NAOS quickly | START_HERE + profile chooser | Quickstart integral tutorial |
| Starting a new project | Professional Adoption Engine | Greenfield path and `/naos-design` guidance |
| Adopting an existing repo | Professional Adoption Engine | Brownfield inventories, candidate requirements, traceability gaps |
| Doing daily task work | Lite: integral Lite tutorial plus Micro 11-13; Standard/Assured: Micro 10-15 | Profile-available task context, implementation, review, completion |
| Running team cadence | Standard/Assured: Micro tutorials 20-21; Lite: manual cadence in its integral tutorial | Weekly/monthly planning and review |
| Handling specialist quality risks | Micro tutorials 30-31 | Test hallucination and runtime guard topics |
| Training a team end-to-end | Integral tutorials | Profile-specific full walkthroughs |

### 1. Start Here — Orientation

| Document | Purpose |
| -------- | ------- |
| [START_HERE — Overview & Learning Path](./START_HERE_NAOS_OVERVIEW_AND_LEARNING_PATH.md) | What NAOS is, how this tutorial set works, and which path to take |
| [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md) | Decision guide: Quickstart / Lite / Standard / Assured |
| [Is NAOS Right for My Project?](./IS_NAOS_RIGHT_FOR_MY_PROJECT.md) | Fit assessment: team size, compliance needs, AI tooling |
| [Professional Adoption Engine](./PROFESSIONAL_ADOPTION_ENGINE.md) | Connected preflight, intake, inventory, challenge, baseline, and decision-record workflow |

### 2. Core Workflow Micro-Tutorials (Series 1x)

Learn each source-catalogue command and paired AI agent in isolation. The
availability column is authoritative for generated-profile routing.

| Tutorial | Command / Agent | Topic | Installed profiles |
| -------- | --------------- | ----- | ------------------ |
| [10 — naos-d-start](./MICRO_TUTORIAL_10_NAOS_D_START.md) | `/naos-d-start` → `@naos-plan` | Morning session start and governance bootstrap | Standard, Assured |
| [11 — naos-task-start](./MICRO_TUTORIAL_11_NAOS_TASK_START.md) | `/naos-task-start` → `@naos-plan`; triage alternative only where installed | Task kick-off and story card creation | Lite, Standard, Assured; triage only Standard/Assured |
| [12 — Implement in Practice](./MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md) | `@naos-implement` | Code, tests, pre-commit governance | Lite, Standard, Assured |
| [13 — Review in Practice](./MICRO_TUTORIAL_13_NAOS_REVIEW_IN_PRACTICE.md) | `@naos-review` | Spec alignment, function-index / duplicate-intent review | Lite, Standard, Assured |
| [14 — naos-task-complete with Conformance](./MICRO_TUTORIAL_14_NAOS_TASK_COMPLETE_WITH_CONFORMANCE.md) | `/naos-task-complete` → `@naos-conformance` | Governance audit, archival, metrics update | Standard, Assured; Lite uses the integral tutorial's human-review route |
| [15 — naos-d-end](./MICRO_TUTORIAL_15_NAOS_D_END.md) | `/naos-d-end` → `@naos-plan` | End-of-day wrap and session memory | Standard, Assured |

### 3. Cadence Micro-Tutorials (Series 2x)

| Tutorial | Rhythm | Topic | Installed profiles |
| -------- | ------ | ----- | ------------------ |
| [20 — Weekly Cadence](./MICRO_TUTORIAL_20_NAOS_W_CADENCE.md) | `/naos-w-plan` | Monday planning, weekly review | Standard, Assured |
| [21 — Monthly Cadence](./MICRO_TUTORIAL_21_NAOS_M_CADENCE.md) | `/naos-m-review` | Monthly governance review and metrics | Standard, Assured |

### 4. Quality Micro-Tutorials (Series 3x)

| Tutorial | Focus | Topic |
| -------- | ----- | ----- |
| [30 — Test Hallucination](./MICRO_TUTORIAL_30_TEST_HALLUCINATION.md) | Test integrity | Detecting tests that pass without proving the intended behavior |
| [31 — PAUL Runtime Guard](./MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md) | Context safety | Using `NAOS_CONTEXT_REMAINING_PCT` to warn at DEEP and block at CRITICAL |

### 5. Integral Tutorials — End-to-End Walkthroughs

| Tutorial | Profile | Scope |
| -------- | ------- | ----- |
| [Quickstart from Scratch](./INTEGRAL_TUTORIAL_QUICKSTART_FROM_SCRATCH.md) | `quickstart` | 5-minute governance from zero |
| [Lite from Scratch](./INTEGRAL_TUTORIAL_LITE_FROM_SCRATCH.md) | `lite` | Solo developer full workflow |
| [Standard from Scratch](./INTEGRAL_TUTORIAL_STANDARD_FROM_SCRATCH.md) | `standard` | Team-grade governance setup |
| [Standard → Assured Readiness and Managed Upgrade](./INTEGRAL_TUTORIAL_STANDARD_TO_ASSURED.md) | `standard` → `assured` target | Immutable planning, review, and digest-bound apply |

---

## Command/Agent Quick Reference

| Command | Default Agent | Alt Agent | When | Installed profiles |
| ------- | ------------- | --------- | ---- | ------------------ |
| `/naos-d-start` | `@naos-plan` | — | Start of a full-cadence coding session | Standard, Assured |
| `/naos-task-start` | `@naos-plan` | `@naos-triage` only where installed | Beginning a new task | Lite, Standard, Assured; triage only Standard/Assured |
| _(implementation phase)_ | `@naos-implement` | — | Coding, testing, bounded fixes | Lite, Standard, Assured |
| _(review phase)_ | `@naos-review` | — | Reviewing work before completion | Lite, Standard, Assured |
| `/naos-task-complete` | Human review in Lite; `@naos-conformance` in Standard/Assured | — | Closing a completed task | Lite, Standard, Assured |
| `/naos-d-end` | `@naos-plan` | — | End of a full-cadence coding session | Standard, Assured |

Many lifecycle prompts include an advisory `next_action` footer. Use it as a quick pointer to the next safe command or agent; it does not replace the human-mediated handoff chain.

## Control-Plane Operational Helpers

The lifecycle remains command/prompt/agent driven. CLI and Make wrappers support the lifecycle by running validators, gate checks, evidence export, and dashboard refresh.

Common CLI helpers:

```bash
naos claims --profile quickstart
naos-governance setup-recommendations --profile quickstart
naos memory-readiness --profile quickstart
naos memory-access --profile quickstart
naos memory-use-policy --profile quickstart
naos task-context --task T-001 --profile quickstart   # when an active task card exists
naos context-index --profile quickstart
naos context-query --query "governance" --profile quickstart
naos semantic-candidates --profile quickstart
naos graph-context --profile quickstart
naos graph-query --task T-001 --profile quickstart
naos session-start --task T-001 --profile quickstart
naos session-checkpoint --task T-001 --profile quickstart
naos session-end --task T-001 --profile quickstart
naos agent-traces --profile quickstart
naos static-grader --profile quickstart
naos grader-assessment --mode audit --profile quickstart
naos model-policy --profile quickstart
naos opencode-config-hygiene --profile quickstart
naos llm-grader-readiness --profile quickstart
naos evidence-attestation --profile quickstart
naos capability-maturity --profile quickstart
naos systemic-impact --profile quickstart
naos module-headers --profile quickstart
naos spec-pack-contract --profile quickstart
naos spec-pack-materialize . --profile quickstart --dry-run
naos spec-assembly-worksheet . --profile quickstart
naos spec-cascade --profile quickstart
naos control-plane-review --profile quickstart
naos self-check --profile quickstart
naos roadmap-crosswalk --profile quickstart
naos function-index-health --profile quickstart
naos test-evidence-map --profile quickstart
naos test-evidence --profile quickstart
naos duplicate-function-hygiene --profile quickstart
naos secret-hygiene --profile quickstart
naos test-quality-hygiene --profile quickstart
naos dependency-integrity --profile quickstart
naos package-reality --profile quickstart
naos api-symbol-reality --profile quickstart
naos gate-status --profile quickstart
naos gate-evaluate --profile quickstart
naos evidence-pack --profile quickstart
naos sarif-export --profile quickstart
naos policy-overrides --profile quickstart --dry-run
naos dashboard --profile quickstart --json
naos adopt . --mode greenfield --profile quickstart --no-prompt
naos context-challenge . --challenge-mode install --profile quickstart
```

After setup recommendations identify an installable module, dry-run the add path before writing files:

```bash
naos add setup-module profile_baseline --profile standard --dry-run
```

Readiness-only or deferred modules remain guidance and do not install active behavior.

Evidence attestation is local and repository-based: someone with repository write access can still edit evidence, reports, reviewer metadata, or manifests unless external controls such as protected branches, signed commits, external notarization, or independent archival are used.

Common Make helpers where installed:

```bash
make -f Makefile.naos naos-claims
make -f Makefile.naos naos-setup-recommendations
make -f Makefile.naos naos-memory-readiness
make -f Makefile.naos naos-memory-use-policy
make -f Makefile.naos naos-task-context TASK=T-001
make -f Makefile.naos naos-session-start TASK=T-001
make -f Makefile.naos naos-session-checkpoint TASK=T-001
make -f Makefile.naos naos-session-end TASK=T-001
make -f Makefile.naos naos-agent-traces
make -f Makefile.naos naos-evidence-attestation
make -f Makefile.naos naos-evidence-conflicts
make -f Makefile.naos naos-task-claim TASK=T-123
make -f Makefile.naos naos-task-release TASK=T-123
make -f Makefile.naos naos-task-claims
make -f Makefile.naos naos-capability-maturity
make -f Makefile.naos naos-systemic-impact
make -f Makefile.naos naos-module-headers
make -f Makefile.naos naos-spec-pack-contract
make -f Makefile.naos naos-spec-pack-materialize
make -f Makefile.naos naos-spec-assembly-worksheet
make -f Makefile.naos naos-spec-cascade
make -f Makefile.naos naos-control-plane-review
make -f Makefile.naos naos-self-check
make -f Makefile.naos naos-roadmap-crosswalk
make -f Makefile.naos naos-function-index-health
make -f Makefile.naos naos-test-evidence-map
make -f Makefile.naos naos-test-evidence
make -f Makefile.naos naos-ac-completion-evidence
make -f Makefile.naos naos-duplicate-function-hygiene
make -f Makefile.naos naos-secret-hygiene
make -f Makefile.naos naos-test-quality-hygiene
make -f Makefile.naos naos-dependency-integrity
make -f Makefile.naos naos-package-reality
make -f Makefile.naos naos-api-symbol-reality
make -f Makefile.naos naos-spec-pack-contract
make -f Makefile.naos naos-spec-pack-materialize
make -f Makefile.naos naos-spec-assembly-worksheet
make -f Makefile.naos naos-spec-cascade
make -f Makefile.naos naos-gate-status
make -f Makefile.naos naos-gate-evaluate
make -f Makefile.naos naos-evidence-pack
make -f Makefile.naos naos-static-grader
make -f Makefile.naos naos-grader-assessment MODE=audit
make -f Makefile.naos naos-model-policy
make -f Makefile.naos naos-llm-grader-readiness
make -f Makefile.naos naos-sarif-export
make -f Makefile.naos naos-policy-overrides
make -f Makefile.naos naos-dashboard
make -f Makefile.naos naos-adopt MODE=greenfield
make -f Makefile.naos naos-context-challenge
```

`naos policy-overrides` validates static YAML overlays under `naos/policy_overrides.d/`, including optional team/operator scopes selected by `naos/team_operator_map.yaml` or explicit flags. Team/operator overlays are static configuration only, not authentication, authorization, access control, identity proof, or separation-of-duties satisfaction. Executable adopter plugin runtime remains deferred; the repo-versioned Codex and Claude Code plugin sources are optional operator adapters over project-local NAOS artifacts, and overrides cannot weaken ADR-0010: Control-Plane Advisory Boundaries or turn advisory findings into authority. Team gatekeeper config uses `team_overrides` in `naos/gatekeepers.yaml` to resolve gate severity/enabled posture for a selected team context; use `make -f Makefile.naos naos-gate-status TEAM_ID=platform` and `make -f Makefile.naos naos-gate-evaluate TEAM_ID=platform`. It is governance configuration, not authorization, access control, team-membership proof, approval, proof of compliance, or separation-of-duties satisfaction.

For pull-request workflows, review `templates/workflows/naos-pr-governance.yml.example` before copying it into an adopter `.github/workflows/` directory. Run `naos pr-risk-classify --profile standard` or `make -f Makefile.naos naos-pr-risk-classify` before PR governance summary when local diff risk evidence is needed; it writes `naos/reports/pr_risk_classification.json`. After PR-time gate/evidence/dashboard/conflict/task-claim reports run, use `naos pr-governance-summary --profile standard` or `make -f Makefile.naos naos-pr-governance-summary` to write `naos/reports/pr_governance_summary.json`. `TEAM_ID` and `NAOS_OPERATOR_ID` are governance metadata only, not authentication or authorization; CI output is review evidence, not PR approval, not security proof, not malware analysis, not sandbox execution, not deployment authorization, not release authorization, not proof of compliance, not separation-of-duties satisfaction, and not conflict resolution. Review artifact sensitivity before enabling upload or retention.

NAOS is tool-neutral: core usage is CLI, Make targets, files, schemas, and reports. Optional templates under `templates/integrations/` can help teams using Spec-Kit, Claude Code hooks, Claude Code plugin guidance, or Codex plugin guidance, but they are not required, not official third-party support, and not activated automatically. Use `docs/TOOL_NEUTRAL_USAGE.md` before copying any integration template.

`naos agent-traces` validates manually declared records in `naos/agent_trace_events.yaml`. In standard/assured projects, use optional `action_receipt` metadata after meaningful agent actions, review checkpoints, or hallucination-sensitive claims when side effects, approval posture, memory trust, or claim-to-evidence review should be explicit. Trace events are StaticGrader/future-audit inputs only: they are not proof, approval, memory writes, runtime capture, runtime enforcement, tool-call interception, legal/compliance/regulatory assurance, hallucination prevention, or behavioral safety evidence, and they must not contain secrets, prompts, private memory payloads, customer data, or tenant data.

`naos static-grader` writes `naos/reports/static_grader_report.json` using deterministic structural checks only. It costs 0.0 by default, calls no model/API/provider, does not execute trace commands, and does not prove behavioral safety, semantic correctness, runtime behavior, legal/regulatory posture, approval, maturity promotion, or hallucination prevention.

`naos duplicate-function-hygiene`, `naos secret-hygiene`, `naos test-quality-hygiene`, `naos dependency-integrity`, `naos package-reality`, and `naos api-symbol-reality` write deterministic local hygiene reports for normalized duplicate function bodies, obvious secret-like findings, weak assertion evidence, undeclared/unresolved imports, package reality from local manifests, lock-style pins, optional docs install snippets, configured local CycloneDX SBOM/provenance/hash evidence, explicit opt-in registry metadata, and explicitly declared Python API symbols. They are review evidence only; they do not prove semantic correctness, secret-free code, behavioral correctness, API behavior, package safety, vulnerability absence, SBOM completeness, provenance authenticity, supply-chain assurance, approval, certification, compliance, or runtime safety.

`naos spec-pack-contract` writes `naos/reports/spec_pack_contract.json` as deterministic template contract conformance evidence. Use `make -f Makefile.naos naos-spec-pack-contract` before interpreting spec-cascade evidence when spec templates or generated spec files change. Default structural mode permits `[ADAPT]` placeholders; explicit filled mode reports unresolved placeholders. It does not prove specification quality, requirements completeness, approval, implementation, test behavior, complete traceability, certification, or compliance.

`naos spec-pack-materialize . --dry-run` writes `naos/reports/spec_pack_materialization.json` when the adopter report path is configured, otherwise it returns stdout-only preview evidence without changing spec files. The manifest schema/profile graph/path inventory, complete selected source/destination plan, and requested report sink must pass before an apply can copy anything; unsafe paths, missing sources, invalid manifests, and apply requests outside the executed macOS/POSIX tuple block. Removing `--dry-run` copies missing templates and skips existing regular files unless `--force` is explicit. Multi-file apply is sequential and has no rollback; a runtime filesystem, post-install cleanup, or late report-write failure can occur after the current or earlier copies. A target installed before cleanup failure remains counted as copied with a blocking residue finding, while late report failure is preserved in blocked stdout evidence. It does not fill, approve, or validate spec content.

`naos spec-assembly-worksheet .` writes `naos/reports/spec_assembly_worksheet.json` as review-only mapping from adoption evidence, candidate requirements, and traceability gaps to manifest-declared spec files. It does not promote candidates, prove applicability, or prove complete traceability.

`naos spec-cascade` writes `naos/reports/spec_cascade_coherence.json` as deterministic requirement/task/source traceability evidence. Use `make -f Makefile.naos naos-spec-cascade` in generated adopters when specs, task registry entries, source headers, source spec references, or configured/inferred source roots change. It flags structural gaps such as orphan headers, stale status links, uncovered requirements, overloaded FRs, unresolved source spec references, and untraced source; it does not prove complete traceability, code correctness, runtime behavior, approval, certification, or compliance.

`naos grader-assessment --mode audit` writes `naos/reports/grader_assessment.json` as deterministic review input. Audit mode is deterministic review input, drift mode compares deterministic reports and does not infer semantic drift, and assess mode summarizes posture rather than certification. Use `make -f Makefile.naos naos-grader-assessment MODE=audit` in generated adopters. It stays zero cost by default, has no LLMGrader runtime, calls no model/API/provider, and does not produce behavioral compliance determination, approval, attestation, or maturity promotion.

`naos model-policy` writes `naos/reports/model_provider_policy.json` as local model-role/provider declaration review. Use `make -f Makefile.naos naos-model-policy` in generated adopters. It reviews repo-local declarations, optional `naos_model_role` metadata, optional mixed-tool model bindings, alias/latest/preview posture, obvious literal secret-like values, cost/data-exposure posture, and disabled runtime posture; it does not call providers, validate credentials, rewrite IDE/tool configuration, recommend models, route runtime calls, approve work, certify controls, prove compliance, or activate LLMGrader/autoresearch/semantic behavior.

`naos model-telemetry` writes `naos/reports/model_telemetry_evidence.json` as optional local model-use telemetry evidence review. Use `make -f Makefile.naos naos-model-telemetry` only when a project explicitly has local telemetry summaries to review. It checks session/task/model-role links, model-policy refs, cost/latency thresholds, payload/credential field presence, stale records, and policy exceptions; it does not call providers, validate credentials, start gateways, route runtime calls, prove complete costs, approve work, certify controls, or prove compliance.

`naos failure-mode-observations` writes `naos/reports/failure_mode_observations.json` as optional local observation statistics across configured direct report findings. Use `make -f Makefile.naos naos-failure-mode-observations` only when a project explicitly wants findings counted against the canonical 21 failure modes. Control-plane, dashboard, evidence-pack, SARIF, gate-status, systemic-impact, and learning-loop consumers may surface those counts as review evidence. It excludes `control_plane_review.json` as an input and does not create learning records, mutate prompts/skills/workflows, call providers/models, activate MCP/Engram/memory, approve work, block gates, certify controls, or prove compliance.

`naos opencode-config-hygiene` writes `naos/reports/opencode_config_hygiene.json` as optional repo-local OpenCode config hygiene review. Use `make -f Makefile.naos naos-opencode-config-hygiene` only when a project explicitly has local OpenCode surfaces to review. It checks local config/instruction posture, MCP/plugin refs, literal secret-like values, and model-provider drift; it does not create, install, run, or configure OpenCode, inspect global config, activate MCP or memory, call providers/models, validate credentials, create plugins, mutate tools, approve work, certify controls, or prove compliance.

`naos llm-grader-readiness` writes `naos/reports/llm_grader_readiness.json` as readiness-only governance posture. Use `make -f Makefile.naos naos-llm-grader-readiness` in generated adopters. Runtime is disabled by default, no provider/model/API dependency or credential handling is enabled, cost is 0.0 by default, StaticGrader remains primary, and future advisory use requires cost budget, data exposure review, bias/drift limitations, residual-risk review, and human approval.

`naos evidence-conflicts` writes `naos/reports/evidence_conflict_detection.json` as deterministic review-risk findings. Use `make -f Makefile.naos naos-evidence-conflicts` in generated adopters. It detects conflicting review outcomes, stale attestations, missing reviewer/operator metadata, duplicate attestations, and unrouted conflicts; it does not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance.

`naos task-claim --task <TASK-ID>`, `naos task-release --task <TASK-ID>`, and `naos task-claims` write local coordination metadata to `naos/task_claims.yaml` and `naos/reports/task_claim_report.json`. Use `make -f Makefile.naos naos-task-claim TASK=T-123`, `make -f Makefile.naos naos-task-release TASK=T-123`, and `make -f Makefile.naos naos-task-claims` in generated adopters. Claims are coordination metadata only: they do not authorize work, approve tasks, prove ownership or separation of duties, mark completion, create exclusive access, resolve evidence conflicts, or prove compliance.

Quickstart uses these commands as local advisory smoke checks and does not
install CI by default. Lite is the first default CI-friendly tier; generated
lite, standard, and assured projects receive a read-only
`naos-control-plane-ci.yml` workflow for the same deterministic chain.
SARIF export is optional interoperability output for findings; it does not
approve work, certify outcomes, prove compliance, or replace review of repository evidence.

Do not treat Make as a replacement for `/naos-d-start`, `/naos-task-start`, `@naos-implement`, `@naos-review`, `@naos-conformance`, `/naos-task-complete`, or `/naos-d-end`.

---

## Navigation

- **New to NAOS?** → Start with [START_HERE](./START_HERE_NAOS_OVERVIEW_AND_LEARNING_PATH.md)
- **Choosing a profile?** → [Profile selection guide](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md)
- **Understanding the control plane?** → See [CONTROL_PLANE.md](../CONTROL_PLANE.md) and the seeded [NAOS Quick Reference](../../templates/structural-seeds/naos/NAOS_QUICK_REFERENCE.md)
- **Assessing NAOS as a toolkit?** → See [NAOS roadmap](../../ROADMAP.md) and [advisory compliance mapping](../COMPLIANCE_MAPPING.md)
- **Understanding public direction?** → See [NAOS roadmap](../../ROADMAP.md)
