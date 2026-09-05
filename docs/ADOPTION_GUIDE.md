# Adoption Guide

**Status**: Public adoption guidance for greenfield, brownfield, and non-developer intake
**Scope**: How to activate NAOS progressively without overclaiming maturity

NAOS is one portable kit. It is not a second product for regulated teams and it is not a parallel runtime framework. The same kit can start lightly and mature as the project provides configuration and evidence.

## Progressive Adoption Model

```text
install kit
  -> choose profile
  -> fill project context and intake
  -> configure capabilities
  -> declare capability state
  -> evaluate maturity readiness
  -> run validators
  -> review gate status
  -> export evidence pack
  -> refresh dashboard
  -> review and approve maturity decisions
  -> mature only the capabilities the project is ready to operate
```

NAOS evaluates maturity readiness. It does not automatically promote, certify, or approve maturity. Final maturity decisions remain project governance decisions.

The `ADR-0010: Control-Plane Advisory Boundaries` decision locks the adoption
boundary between deterministic and advisory controls. Run deterministic primary
controls first. Optional advisory controls such as semantic similarity, graph
analytics, memory discrepancy detection, or LLMGrader-style second opinions may
challenge the baseline with candidates or warnings, but they may not replace
deterministic evidence, approve work, certify compliance, promote maturity, or
update durable project state.

Use [docs/AUDIT_PLAYBOOK.md](AUDIT_PLAYBOOK.md) when preparing a deterministic
review run, [docs/NAOS_THREAT_MODEL.md](NAOS_THREAT_MODEL.md) when reviewing
SDLC evidence risks, and [docs/ASSURED_PROFILE_ACTIVATION.md](ASSURED_PROFILE_ACTIVATION.md)
before treating the `assured` profile as operational. These guides are public
review aids; they are not approvals, legal advice, runtime safety assurance, or
legal/regulatory compliance determination.

## Profile Semantics

| Profile | Default adoption posture |
| --- | --- |
| `quickstart` | Advisory, low-friction onboarding. Use it to learn the workflow. |
| `lite` | Warnings and lightweight checks. Good for solo and early team adoption. |
| `standard` | Required evidence for normal SDLC work. Strict failure behavior remains opt-in until project policy and gates are operationalized. |
| `assured` | Blocking where configured. Use when evidence-backed governance, exception approval, and reviewer handoff matter. |

Tier 3/experimental capabilities remain advisory by default unless a project explicitly changes policy and provides readiness evidence.

## Adoption Workflow Router

Use this router before choosing a long checklist. It maps natural-language
adopter intent to the explicit command/report path.

| Adopter intent | Route | Commands to start | Decision boundary |
| --- | --- | --- | --- |
| New project | Greenfield adoption | `naos adopt . --mode greenfield --profile standard --dry-run` | review install plan and decision record |
| Existing repo | Brownfield adoption | `naos adopt . --mode brownfield --profile standard --dry-run` | review inventories, conflicts, candidates, gaps |
| Declared MCP server | Static descriptor review | `naos mcp-resource-inventory . --profile <profile>` | exact risk-owner policy match is pending activation, not runtime or write authority |
| Non-developer intake | Guided intake | `naos intake . --interactive --profile <profile>` | preserve unknowns; humans answer or defer |
| Potential parallel task work | Lane opportunity review | `/naos-task-start <TASK-ID>`, `naos pre-implementation-alignment-review`, optional handoff script after declaration | suggested lanes stay advisory until `parallel_lane_decision: declared` |
| More assurance | Profile/gate/maturity | `naos capability-maturity`, `naos gate-status`, `naos gate-evaluate` | maturity movement remains project-owned |
| Governance surface changed | Systemic review | `naos systemic-impact`, `naos control-plane-review` | route findings to remediation, waiver, or known gap |
| Tool adapter changed | Adapter coherence | `naos adapter-coherence` | plugin/IDE adapter drift, boundaries, propagation hashes, and stale guidance findings |

Prompts and agents may recommend the route and command sequence. They do not
silently execute setup, activate integrations, approve maturity, or replace
human review.

MCP descriptor review is deliberately narrower than MCP scanning. It reads
sanitized repo-local declaration metadata, compares an exact static tuple and
policy digest, and reports either `allowlisted_pending_activation` or
`review_required`. The shipped Figma rule applies only to the recorded
repo-local remote VS Code workspace declaration subset. It does not read
user-global configuration, call
Figma or MCP, authenticate, enumerate tools, verify remote identity, or grant
tool or write authority. The desktop endpoint and every unknown or drifted
declaration remain review-required.

## Readiness Run

After installation, run a deterministic readiness chain before treating NAOS
outputs as current. Use the selected profile:

```bash
python -m naos_governance.cli doctor
naos-governance first-run --profile standard --mode greenfield
```

`first-run` performs doctor, adoption dry-run, setup recommendations,
profile-baseline setup-module dry-run, evidence pack, and dashboard generation.
Review dry-run adoption and setup recommendations before applying modules.
Apply selected setup modules one at a time after a dry run. `validate-all`
runs installed tier-appropriate validators and may skip checks not copied into
the selected profile. It may still report review findings that require
adaptation or waiver before the run should be treated as clean. Dry-run
adoption does not install `Makefile.naos`; run installed-project validators only
after NAOS files have been activated or materialized intentionally. If
`naos-governance` is missing but `python -m naos_governance.cli doctor` reports
the package is importable, reinstall NAOS in the active Python environment. If
bare `naos` opens another tool, use `naos-governance ...` or
`python -m naos_governance.cli ...` until command resolution is fixed. These
commands produce review evidence only; they do not approve maturity, certify
readiness, prove compliance, or prove runtime safety.

For deeper local review, run the broader chain:

```bash
naos claims --profile <profile>
naos setup-recommendations --profile <profile>
naos governance-bypass-posture --profile <profile>
naos external-evidence-ingest --profile <profile>      # add --source <scan.sarif> when available
naos memory-readiness --profile <profile>
naos memory-use-policy --profile <profile>
naos learning-loop-review --profile <profile>
naos adapter-coherence --profile <profile>
naos task-context --task <TASK-ID> --profile <profile>   # task-specific, when an active card exists
naos context-index --profile <profile>
naos context-query --query "<keywords>" --profile <profile>
naos semantic-candidates --profile <profile>
naos graph-context --profile <profile>
naos graph-query --task <TASK-ID> --profile <profile>
naos session-start --task <TASK-ID> --profile <profile>
naos session-checkpoint --task <TASK-ID> --profile <profile>
naos session-end --task <TASK-ID> --profile <profile>
naos policy-overrides --profile <profile> --dry-run
naos agentic-workflow-review --profile <profile>
naos pre-implementation-alignment-review --profile <profile>
naos calibration-shadow --profile <profile>
naos evidence-classification --profile <profile>
naos evidence-attestation --profile <profile>
naos capability-maturity --profile <profile>
naos systemic-impact --profile <profile>
naos module-headers --profile <profile>
naos spec-pack-contract --profile <profile>
naos spec-pack-materialize . --profile <profile> --dry-run
naos spec-assembly-worksheet . --profile <profile>
naos spec-cascade --profile <profile>
naos control-plane-review --profile <profile>
naos ai-surface-budget --profile <profile>
naos self-check --profile <profile>
naos roadmap-crosswalk --profile <profile>
naos function-index-health --profile <profile>
naos test-evidence-map --profile <profile>
naos test-evidence --profile <profile>
naos ac-completion-evidence --profile <profile>
naos duplicate-function-hygiene --profile <profile>
naos secret-hygiene --profile <profile>
naos test-quality-hygiene --profile <profile>
naos dependency-integrity --profile <profile>
naos package-reality --profile <profile>
naos api-symbol-reality --profile <profile>
naos gate-status --profile <profile>
naos gate-evaluate --profile <profile>
naos evidence-pack --profile <profile>
naos dashboard --profile <profile> --json-output naos/reports/dashboard_summary.json
```

Quickstart runs this as advisory local smoke. Lite is the first CI-friendly
tier and receives a low-noise `naos-control-plane-ci.yml` workflow by default.
Standard and assured use the same deterministic chain with stronger profile and
policy semantics. CI surfaces findings; humans still review disposition,
waivers, residual risks, and maturity decisions.

`task-context` is task-specific rather than a whole-project readiness command.
It derives `naos/reports/task_context_pack.json` and, with `--write-markdown`,
`naos/context_packs/<TASK-ID>.md` from active task cards, task registry entries,
specs, capability cards, deterministic reports, and memory-readiness posture.
The pack is bounded and non-authoritative: it does not replace source
artifacts, inject context automatically, treat memory as evidence, or approve
task decisions.

Parallel-lane planning is an advisory overlay on the same task lifecycle. Record
`parallel_lane_opportunity` and `parallel_lane_decision` in the active card or
`PRE_IMPLEMENTATION_ALIGNMENT.md` when a task has independent acceptance
criteria, distinct path scopes, dependency-unlocked work, or high context load.
For solo developers, lanes can be logical checkpoints rather than concurrent
execution. For teams, declared lanes should also link task claims, dependencies,
planned paths, expected checks, operator/session metadata, and human-review
posture. Suggested lanes do not activate handoff. When a project explicitly
declares lanes, fill `naos/lane_handoffs/_TEMPLATE.yaml` into a lane-specific
file, run `python scripts/naos_parallel_lane_handoff.py --profile <profile> --handoff naos/lane_handoffs/<lane>.yaml`,
then run `naos control-plane-review --profile <profile>` to reconcile local
handoff, PR-risk, plan-coherence, task-claim, and alignment evidence. The route
is review evidence only; it is not task authorization, lane dispatch, merge
approval, task closure, release approval, certification, attestation, or proof
of compliance.

## Greenfield Adoption

Use greenfield adoption when the project is new enough that NAOS can shape specs, task cards, and traceability before implementation accelerates.

Recommended path:

1. Run `naos-governance init --new --tier lite --archetype custom --backend static_only` or `naos-governance init --new --tier standard --archetype custom --backend static_only`.
2. Fill `project-context.md` and initial specs before coding.
3. Run `/naos-design` to elicit the profile-required spec pack: lite fills specs 01-03; standard and assured keep all specs 01-10 present, using explicit non-applicability rationale inside any file whose topic does not apply to the product. To compare the missing Standard spec templates, run `naos spec-pack-materialize . --profile standard --dry-run`, review the report, then remove `--dry-run` only when you intend to copy those missing files. This does not apply a Lite-to-Standard transition. Before treating the specs as ready for planning or coding, run `naos spec-pack-contract --profile <profile> --mode filled` and review unresolved placeholders.
4. Use `/naos-task-start -> @naos-plan -> @naos-implement -> @naos-review`.
5. Run validators and refresh the dashboard once evidence exists.
6. Declare initial capability state in `naos/capability_state.yaml`.
7. Run `naos setup-recommendations --profile <profile>` to generate `naos/reports/setup_recommendations.json` and review choice/rationale/benefit/warning/consequence guidance and profile guidance before enabling advanced modules. The guidance may recommend staying on the selected profile or considering lite, standard, or assured, but it never upgrades automatically. Use `naos add setup-module MODULE_ID --profile PROFILE --dry-run` for selected installable modules; readiness-only or deferred modules do not install active behavior.
8. Run `naos governance-bypass-posture --profile <profile>` to generate `naos/reports/governance_bypass_posture.json` for hook, CI, commit-message, and tier/profile bypass posture. Run `naos external-evidence-ingest --source <scan.sarif> --profile <profile>` when local SARIF scanner output should be visible as unverified external review evidence. These reports are evidence inputs only: they do not prevent bypasses, prove CI ran, verify external findings, approve PRs, attest evidence, certify controls, or prove compliance.
8. Run `naos memory-readiness --profile <profile>` for memory-governance posture, `naos memory-access --profile <profile>` before asking agents to claim memory or MCP access, `naos memory-use-policy --profile <profile>` before treating any memory reference as supporting context or instruction-grade, and `naos learning-loop-review --profile <profile>` before treating lessons as active guidance or using them to change governed artifacts. Memory is advisory recall only until reviewed: repository evidence and current user instructions remain authoritative, configured providers and MCP config files do not prove usable access, instruction-grade memory requires approval/provenance/scope/reviewer/timestamp/freshness, durable writes require configured, authorized, verified, and memory-use-policy-permitted access plus human review, learning candidates are proposal-only, active learning requires reviewed evidence/scope/approval/review metadata, cloud memory is not enabled by default, and unavailable memory means degraded recovery from task cards, compact summaries, git state, governance files, and NAOS reports.
9. Review `naos/agentic_workflow.yaml`, `naos/AGENTIC_CODING_PLAYBOOK.md`, and `naos/PRE_IMPLEMENTATION_ALIGNMENT.md` before substantial AI-assisted work. Run `naos agentic-workflow-review --profile <profile>` and `naos pre-implementation-alignment-review --profile <profile>` to surface missing workflow sections, unsafe context/approval flags, missing first vertical slice, and missing test/evidence strategy. These reports are review aids only: they do not inspect chat history, approve design or implementation, prove requirements completeness, prove compliance, or replace human review.
10. Run `naos calibration-shadow --profile <profile>` and `naos evidence-classification --profile <profile>` after representative reports exist. Calibration shadow monitors deterministic report metadata drift, not model calibration or release authorization. Evidence classification separates `confirmed`, `deduced`, `hypothesized`, and `unknown` provenance from severity; inferred categories remain review candidates, not truth proof, issue resolution, approval, or proof of compliance.
10. For active implementation work, run `naos task-context --task <TASK-ID> --profile <profile>` before handing a task to an AI tool. Use `--write-markdown` only when a bounded human/AI handoff pack is helpful.
10. Run `naos context-index --profile <profile>` when a generated local candidate index would help task-context or review workflows. The index is generated, cache-like, and not authoritative; it does not use sqlite-vec, embeddings, graph traversal, Engram, MCP, private memory payloads, or automatic context injection.
11. Run `naos context-query --query "<keywords>" --profile <profile>` when you need bounded candidate references from the generated index. Query results are candidates, not answers; check source paths, hashes, freshness, and authority levels before acting.
12. Run `naos semantic-candidates --profile <profile>` to inspect future semantic/vector readiness posture. It is disabled/readiness-only by default and does not install or enable sqlite-vec, embeddings, providers, API calls, cloud embedding, extension loading, Engram/MCP, or memory payload search.
13. Run `naos graph-context --profile <profile>` to inspect future graph-context traversal guardrails. It is disabled/readiness-only by default: graph links are relationship candidates, not source of truth, NetworkX/GraphML/graph databases/graph algorithms/global scans are deferred, memory payload graphing is prohibited, and there is no hallucination-prevention guarantee.
14. Run `naos graph-query --task <TASK-ID> --profile <profile>` after a local context index exists when bounded explicit-link relationship candidates would help. Results are not truth, source authority, or implementation proof; check source paths, hashes, freshness, and authority before acting.
15. Run `naos session-id --profile <profile>` or `make -f Makefile.naos naos-session-id` to create or reuse a session id and session report namespace. Session-specific evidence lives under `naos/sessions/<session_id>/reports/`; latest reports under `naos/reports/` remain compatibility outputs.
16. Run `naos operator-attribution --profile <profile>` or `make -f Makefile.naos naos-operator-attribution` to record local operator attribution for who initiated a run/session. Prefer `NAOS_OPERATOR_ID` for project-approved identifiers. Operator attribution may be personal data and is not identity proof, authentication, authorization, task ownership, locking, separation-of-duties evidence, non-repudiation, or approval.
17. Run `naos audit-log --profile <profile>` or `make -f Makefile.naos naos-audit-log` to summarize append-only audit event files under `naos/audit_log/YYYY-MM-DD/`. Audit events record what happened over time; they are not approval, non-repudiation, cryptographic signing, tamper-proof storage, task locking, evidence conflict detection, compliance approval, or source of truth.
17. Run `naos evidence-conflicts --profile <profile>` or `make -f Makefile.naos naos-evidence-conflicts` to flag deterministic evidence/review conflicts, stale attestations, duplicate attestations, missing reviewer/operator metadata, and unrouted conflicts. It detects review findings only; it does not resolve conflicts, adjudicate evidence correctness, prove separation of duties, approve work, lock tasks, or prove compliance.
17. Run `naos task-claim --task <TASK-ID> --profile <profile>` or `make -f Makefile.naos naos-task-claim TASK=T-123` to record local task-claim coordination, `naos task-release --task <TASK-ID>` or `make -f Makefile.naos naos-task-release TASK=T-123` to release it, and `naos task-claims --profile <profile>` or `make -f Makefile.naos naos-task-claims` to summarize active/released/stale/conflicting claims. Claims are coordination metadata only: they do not authorize work, approve tasks, prove task ownership or separation of duties, mark completion, create exclusive access, resolve evidence conflicts, or prove compliance. Conflicts and stale claims require human review.
17. Run `naos session-start --task <TASK-ID>`, `naos session-checkpoint --task <TASK-ID>`, and `naos session-end --task <TASK-ID>` to generate bounded lifecycle reports/checklists. They recommend commands and routing, but do not mutate task cards, write compact files, approve work, inject context automatically, or write memory. Memory candidates are proposal-only and require human review. M3 adds local SQLite write coordination for context-index file integrity through `naos context-index`, M4 adds event history, M5 adds evidence conflict detection, M6 adds task claim/release coordination metadata, M7 adds static team/operator policy overlay scopes, M8 adds team-scoped gatekeeper posture, and M9 adds PR-time CI evidence templates. NAOS still treats authorization-backed task locking, release approval, deployment authorization, and public-release re-audit as separate human-governed steps.
17. Run `naos policy-overrides --profile <profile> --dry-run` or `make -f Makefile.naos naos-policy-overrides` before relying on any adopter-local overlays under `naos/policy_overrides.d/`. Static YAML overlays are supported directly and through optional `teams/<team_id>/` and `operators/<operator_overlay_id>/` scopes selected by `naos/team_operator_map.yaml` or explicit flags. Team/operator overlays are configuration only, not authentication, authorization, access control, identity proof, or separation-of-duties satisfaction. For team-scoped gatekeeper posture, run `make -f Makefile.naos naos-gate-status TEAM_ID=platform` or `make -f Makefile.naos naos-gate-evaluate TEAM_ID=platform`; team gatekeeper config is governance configuration, not authorization, approval, proof of compliance, or team-membership proof. Executable adopter plugin runtime remains deferred; the repo-versioned Codex and Claude Code plugin sources are optional operator adapters over project-local NAOS artifacts. Overrides cannot weaken ADR-0010: Control-Plane Advisory Boundaries, turn advisory findings into authority, enable memory write-back, MCP/Engram runtime, sqlite-vec, graph runtime, LLMGrader runtime, cloud memory, provider credentials, or signing by NAOS.
17. Review `templates/workflows/naos-pr-governance.yml.example` before copying it into an adopter `.github/workflows/` directory. The example runs deterministic PR-time NAOS checks, supports optional `TEAM_ID` and `NAOS_OPERATOR_ID` metadata, runs `naos pr-risk-classify --profile <profile>` to write `naos/reports/pr_risk_classification.json`, and writes `naos/reports/pr_governance_summary.json` through `naos pr-governance-summary --profile <profile>` or `make -f Makefile.naos naos-pr-governance-summary`. PR risk classification flags protected paths, workflow/dependency changes, AI instruction surfaces, prompt-injection-like text, and secret-like added lines for review. CI output is review evidence only: it is not PR approval, not security proof, not malware analysis, not sandbox execution, not deployment authorization, not release authorization, not proof of compliance, not authentication, not authorization, not access control, not separation-of-duties satisfaction, and not conflict resolution. Review artifact sensitivity before enabling upload or retention.
18. Keep NAOS tool-neutral. Use `docs/TOOL_NEUTRAL_USAGE.md` and `docs/CODEX_PLUGIN_AND_MCP.md` when deciding how to pair NAOS with Claude Code, Codex, Gemini CLI, Cursor, VS Code/Copilot, cloud IDEs, or Spec-Kit. Optional integration templates can be copied with `naos add setup-module spec_kit_adapter --dry-run`, `naos add setup-module claude_code_hooks --dry-run`, `naos add setup-module claude_code_plugin_adapter --dry-run`, or `naos add setup-module codex_plugin_adapter --dry-run`; they copy templates under `naos/integrations/` only and do not activate hooks, overwrite IDE settings, mutate Codex plugin caches, mutate Claude Code plugin state, edit marketplace files, inject context, write memory, call provider APIs, or create approvals. `naos adapter-coherence` uses propagation-state hashes to flag stale plugin guidance, but it does not auto-sync installed plugin copies.
18. Run `naos agent-traces --profile <profile>` or `make -f Makefile.naos naos-agent-traces` when manually declared trace records exist in `naos/agent_trace_events.yaml`. In standard/assured projects, add the optional `action_receipt` block after meaningful agent actions, review checkpoints, or hallucination-sensitive claims when side effects, approval posture, memory trust, or claim-to-evidence review should be explicit. Trace events and action receipts are records for StaticGrader and future audit flows; they are not proof, approval, memory writes, runtime capture, runtime enforcement, tool-call interception, legal/compliance/regulatory assurance, hallucination prevention, or behavioral safety evidence, and they must not contain secrets, prompts, private memory payloads, customer data, or tenant data.
19. Run `naos ai-surface-budget --profile <profile>` or `make -f Makefile.naos naos-ai-surface-budget` when prompts, agents, skills, instructions, workflows, manuals, quick references, or governance docs change. It writes `naos/reports/ai_surface_context_budget.json` for static context pressure, anchor coverage, combined loadout, and optional approved-baseline drift. If a learned lesson drives that surface change, run `naos learning-loop-review` first or in the same evidence refresh. These reports can inform StaticGrader, grader assessment, gates, evidence, and dashboards, but they do not prevent hallucinations, grade behavior, auto-tune thresholds, auto-promote lessons, or approve baseline changes.
19. Run `naos static-grader --profile <profile>` or `make -f Makefile.naos naos-static-grader` after trace validation when deterministic structural grading is useful. StaticGrader is zero-cost by default and checks structural metadata only; it does not call models, APIs, providers, Engram, MCP, or memory tools, does not execute trace commands, and does not prove behavioral safety, semantic correctness, runtime behavior, legal/regulatory posture, approval, maturity promotion, or hallucination prevention.
19. Run `naos duplicate-function-hygiene`, `naos secret-hygiene`, `naos test-quality-hygiene`, `naos dependency-integrity`, `naos package-reality`, `naos api-symbol-reality`, and `naos pr-risk-classify` when deterministic local hygiene or PR-risk evidence is useful before gate/evidence review. These commands inspect local files and git diff metadata only by default and write `naos/reports/duplicate_function_hygiene.json`, `naos/reports/secret_hygiene.json`, `naos/reports/test_quality_hygiene.json`, `naos/reports/dependency_integrity.json`, `naos/reports/package_reality.json`, `naos/reports/api_symbol_reality.json`, and `naos/reports/pr_risk_classification.json`. `naos package-reality` checks package names, lock-style pins, optional docs install snippets, configured local CycloneDX SBOM/provenance/hash evidence, and registry metadata only when explicitly run with `--registry-mode online --allow-network`. `naos api-symbol-reality` checks explicitly declared Python API symbols by source inspection without importing target modules. They reduce obvious duplicate-body, secret-like, weak-test, undeclared-import, package-reality, declared-API-symbol, protected-path, workflow, dependency, and AI-surface risk classes; they do not prove semantic correctness, secret-free code, behavioral correctness, API behavior, package safety, vulnerability absence, SBOM completeness, provenance authenticity, supply-chain assurance, PR approval, security, certification, compliance, or runtime safety.
20. Run `naos grader-assessment --mode audit --profile <profile>` or `make -f Makefile.naos naos-grader-assessment MODE=audit` when StaticGrader output should be packaged as deterministic review input. Audit mode is deterministic review input, drift mode compares deterministic reports without semantic drift inference, assess mode summarizes posture rather than certification, zero cost by default remains explicit, and no LLMGrader runtime, model/API/provider call, behavioral compliance determination, approval, attestation, or maturity promotion is enabled.
21. Run `naos llm-grader-readiness --profile <profile>` or `make -f Makefile.naos naos-llm-grader-readiness` when future LLM-as-judge discussion needs governance posture. It is readiness-only: runtime is disabled by default, StaticGrader remains primary, no provider/model/API dependency or credential handling is enabled, cost is 0.0 by default, and future advisory use requires budget controls, data exposure review, bias/drift limitations, residual-risk review, and human approval.
21. Run `naos behavioral-readiness --profile <profile>` or `make -f Makefile.naos naos-behavioral-readiness` before first behavioral baseline work or after baseline-impacting governance/CI/config evidence changes. It writes `naos/reports/behavioral_governance_readiness.json` from deterministic local reports plus optional human-created baseline metadata. It does not create baselines, grade behavior, call models/providers/APIs, infer semantic drift, approve, certify, prove compliance, publish, authorize releases, or promote maturity.
21. Run `naos ai-code-provenance --profile <profile>` or `make -f Makefile.naos naos-ai-code-provenance` when AI-assisted code provenance evidence is needed for human review or admissibility handoff. It reads `naos/ai_code_provenance.yaml`, AI artifact inventory/reconciliation reports, and adjacent local reports, then writes `naos/reports/ai_code_provenance.json`. It does not provide legal opinions, authorship proof, ownership proof, infringement clearance, proof of copyright compliance, AI-output detection, line-level attribution, signing, approval, certification, publication authority, release authority, or proof of compliance.
21. Run `naos compliance-posture --profile <profile>` or `make -f Makefile.naos naos-compliance-posture` when adopter-declared regulated-context evidence is needed for human review or admissibility handoff. It reads `naos/compliance_posture.yaml` and adjacent local evidence reports, then writes `naos/reports/compliance_posture.json`. It does not provide legal advice, legal opinions, regulatory applicability decisions, compliance pass/fail, compliance scores, certification, conformity assessment, audit opinions, operational-resilience execution, model-risk approval, signing, approval, publication authority, release authority, or proof of compliance.
22. Run `naos evidence-attestation --profile <profile>` when local digest coverage and reviewer metadata are useful. The report is not signing, tamper-proof storage, approval, or certification. Evidence attestation is local and repository-based: someone with repository write access can still edit evidence, reports, reviewer metadata, or manifests unless external controls such as protected branches, signed commits, external notarization, or independent archival are used.
23. Run `naos capability-maturity --profile <profile>` to generate `naos/reports/capability_maturity.json`.
24. Review `naos/systemic_impact_rules.yaml` and run `naos systemic-impact --profile <profile>` to generate `naos/reports/systemic_impact_review.json`.
25. Review `naos/module_header_rules.yaml` and run `naos module-headers --profile <profile>` to generate `naos/reports/module_header_traceability.json` when source modules exist.
26. Run `naos spec-pack-contract --profile <profile>` to generate `naos/reports/spec_pack_contract.json` when spec templates or generated spec files change. It checks template contract structure only and does not prove specification quality, requirements completeness, approval, implementation, complete traceability, certification, or compliance.
27. Run `naos spec-pack-materialize . --profile <profile> --dry-run` to generate `naos/reports/spec_pack_materialization.json` when profile-required spec files may be missing. Remove `--dry-run` only after review; copied files are templates, not filled or approved specs.
28. Run `naos spec-assembly-worksheet . --profile <profile>` to generate `naos/reports/spec_assembly_worksheet.json` when brownfield evidence, candidate requirements, or traceability gaps need to be mapped into specs. The worksheet keeps candidates unpromoted and highlights missing applicability decisions; it does not prove applicability or complete traceability.
29. Run `naos spec-cascade --profile <profile>` to generate `naos/reports/spec_cascade_coherence.json` when specs, task registry entries, module headers, source spec references, or configured/inferred source roots change. If `PRE_IMPLEMENTATION_ALIGNMENT.md` declares `planned_change_paths` or `out_of_scope_paths`, run `naos plan-coherence --profile <profile> --diff-base <ref>` when changed-file scope evidence is useful; this remains advisory review evidence, not plan approval or semantic drift proof.
28. Add structured review/routing items to `naos/control_plane_review_items.yaml` when governance surfaces or actionable research findings need disposition, then run `naos control-plane-review --profile <profile>`.
29. Export an evidence pack only after validator reports have been generated.

Greenfield projects often reach L1/L2 faster because task and evidence structures are present before code accumulates.

## Brownfield Adoption

Use brownfield adoption when the project already has code, tests, docs, or delivery processes.

Before the first command, freeze a reviewable source baseline: use a clean
commit or a controlled disposable copy, record its source identity, and record
the native build and test commands that will be rerun after onboarding.

Recommended path:

1. Run `naos repository-intelligence plan . --profile <profile> --component-mode baseline --output <external-plan.json>`. Review the source-bound plan. When enrollment is required, confirm that exact digest with `repository-intelligence enroll`, create a fresh plan, apply that exact digest, and run `repository-intelligence validate`.
2. Run `naos-governance init . --tier <profile> --dry-run`, inspect the complete generated surface, and use a separate `--activate` invocation only after review. Activation is one provenance-bound create-only transaction: any unproven existing destination refuses the whole operation.
3. If an observed host test recursively consumes its own `scripts/` Python collection, review the deterministic `scripts/` to `naos_tools/` preview remap. When bounded host automation literally runs repository-root Ruff discovery, also review the managed nested `.ruff.toml` markers in generated roots proved to contain no pre-existing adopter Python. The `naos_tools/` marker is kit-owned; the `.github/autoresearch/` marker follows that seed's create-once adopter ownership, and no pre-existing adopter Ruff file is modified. Mixed Python roots and detected `--config`/`--isolated` bypass postures refuse activation. Later manual Python inside a reserved excluded root, explicit-file invocations, aliases, wrappers, and non-Ruff lint engines remain review-required. Other blocking collection collisions still refuse activation.
4. Run `naos adopt . --mode brownfield --profile <profile> --no-prompt` and inspect the inventories, baseline, candidate requirements, traceability gaps, and decision record.
5. Fill project context with verified, non-obvious constraints: the commands that actually work, frozen or fragile areas, project-specific conventions, and known pitfalls. Keep repository maps derived from source rather than copying them into long-lived agent instructions. For Standard or Assured, install the complete specs 01–10, task registry, dashboard seed, and rules, but adapt them around one bounded first change; mark the rest unknown, deferred, or not applicable instead of inventing a retrospective specification of the whole system. Candidate requirements are never promoted automatically; explicitly accept, reject, defer, or edit each relevant candidate.
6. Run function-index health, test-evidence mapping, AC-completion evidence when completion is claimed, duplicate-function hygiene, secret hygiene, test-quality hygiene, dependency-integrity, package-reality, and API-symbol reality checks in advisory mode. Human-confirm useful findings and place accepted work in `naos/TASK_REGISTRY.yaml` with explicit value, priority, and effort; findings are not tasks until that review occurs.
7. Review `naos/capability_state.yaml` and disable or mark `not_configured` capabilities that are not in scope yet. Profile and L0–L5 maturity guide review posture but do not authorize activation or approve maturity. If the project has explicitly decided to maintain a build-time sponsor declaration for every agent, Standard/Assured may dry-run and separately confirm the optional `agent_sponsor_registry` setup module. Its empty seed assigns nobody; use categorized opaque references (`role:`, `team:`, or `group:` for sponsors/owners and `control:` or `policy:` for external controls), keep names, email addresses, and all credential values outside the repository, and treat its G2/G6 output as declaration review rather than identity, authentication, authorization, credential, or runtime proof. If the project separately chooses assessor-supplied AIVSS-Agentic v0.8 arithmetic, it may dry-run and confirm `aivss_arithmetic_verification`; its output is advisory G2/G6 arithmetic/integrity review only and is not CVSS validation, risk assessment, security proof, or decision authority.
8. Review `naos/systemic_impact_rules.yaml` and adapt artifact-family patterns to existing project docs, tests, workflows, and evidence surfaces.
9. Run maturity readiness and systemic impact review; treat missing traceability and review obligations as onboarding debt, not failure.
10. Run `naos spec-assembly-worksheet . --profile <profile>` after candidate requirements and traceability gaps exist. Review missing required spec files, mapped candidate evidence, and any non-applicability decisions before treating spec coverage as current.
11. Run the generated governance validators and the project's native tests. Refresh repository intelligence after reviewed project changes so its source binding is current.
12. For an already managed project, use `naos upgrade . --tier <profile> --plan-out <external-absent-plan.json>` to create a no-target-write content-aware plan. Review its preservation decisions and digest, then use a separate `naos upgrade . --apply-plan <plan.json> --expect-plan-digest <sha256>` invocation. Use `naos upgrade . --recover` after interruption. Initial create-only brownfield installation remains a different operation, and `--force` never authorizes replacement.

Brownfield projects should expect more `missing`, `not_configured`, and `advisory` dashboard statuses during onboarding. That is honest maturity reporting, not a failed installation.

The deterministic repository-intelligence baseline requires a host SQLite
build with FTS5; activation and query fail closed when it is unavailable.
Optional NetworkX/GraphML is selected only after executed
relationship-utility evidence supports it; GraphML remains derived navigation
evidence. `sqlite-vec`, embeddings, and provider calls remain inactive without
a separately defined workload. Use the installed NAOS command or kit checkout
for this lifecycle: the default generated profile deliberately does not
duplicate its operational script, schemas, or upgrade-contract modules. The
older `context-index` and `graph-context`
commands remain separate advisory surfaces rather than substitutes for this
provenance-bound lifecycle.

## Installer and Module Polish

The preferred public path is:

```bash
pip install naos-governance
naos-governance init /path/to/project --tier quickstart --activate
cd /path/to/project
naos-governance setup-recommendations --profile quickstart
```

For source checkouts, use the actual script entry point:

```bash
python naos_init.py /path/to/project --tier quickstart --activate
```

Optional modules can be added during greenfield setup, brownfield onboarding, or
later adoption. Always dry-run setup modules first:

```bash
naos add setup-module --list
naos add setup-module profile_baseline --profile standard --dry-run
```

Remove `--dry-run` only for a genuinely absent create operation. Setup modules
create absent paths and treat provenance-current exact files as already
satisfied. For an eligible unchanged kit-owned collision, persist an external
plan with `--plan-out`, then apply that exact digest through
`naos upgrade --apply-plan`; do not treat a normal add invocation as replacement authority.
Adopter-owned or modified paths are preserved, and blanket `--force` remains
unavailable. Optional integrations remain optional.

## Non-Developer Intake

NAOS should support structured intake before AI implementation, especially where business owners, compliance owners, or product managers bring requirements to an AI-assisted engineering workflow.

For regulatory or statutory requirements such as DORA encryption controls, intake should collect:

- business objective and accountable owner;
- data classes, sensitive fields, retention, and encryption expectations;
- architecture boundaries and affected systems;
- regulatory, statutory, contractual, and internal-policy references;
- toolchain context, including AI assistants and models in use;
- required evidence and reviewer expectations;
- known gaps, assumptions, and residual risks;
- acceptance criteria and source-to-test expectations.

The professional adoption engine now provides deterministic intake and adoption
reports through `naos intake`, `naos install-plan`, `naos adopt`,
`naos context-challenge`, `naos repo-context-challenge`,
`naos requirements-reconstruct`, `naos traceability-gap-register`, and
`naos install-decision-record`. These commands support answer-file and
interactive use where appropriate, preserve unknowns instead of guessing, and
write review artifacts under `naos/reports/`.

Brownfield reconstruction remains bounded: candidate FRs and NFRs are generated
only from controlled local evidence such as existing specs, docs, source, tests,
workflows, security/privacy material, and explicit intake answers. Candidate
requirements are not final requirements, candidate NFRs do not prove security,
compliance, or runtime safety, and human review is required before any candidate
is promoted into project authority.

## Evidence Maturity

Evidence maturity is strongest when these artifacts exist and agree:

- claims validation report;
- self-check report;
- capability maturity readiness report;
- roadmap/crosswalk report;
- function-index health report;
- source-to-test map, test-evidence health report, and declared AC/SCEN completion evidence report where completion is claimed;
- AI-surface context-budget report;
- gatekeeper status/evaluation report;
- evidence pack;
- dashboard summary.

Missing evidence should be recorded as missing or not configured. Waived risk remains visible. Evidence packs support review and audit/admissibility discussions; they are not legal proof.

Capability maturity readiness is strongest when `naos/capability_state.yaml` names owners, target maturity, evidence references, freshness windows, waiver policy, and project criteria, and when `naos/reports/capability_maturity.json` shows readiness without hiding missing evidence or human-approval requirements.

Module-header traceability is strongest when `naos/module_header_rules.yaml` reflects the project source layout and `naos/reports/module_header_traceability.json` is refreshed after source modules are added or materially changed. Spec-cascade coherence is strongest when `naos/reports/spec_cascade_coherence.json` is refreshed after specs, task registry entries, source headers, source spec references, or configured/inferred source roots change. These reports support review of source-to-requirement/task/spec links; they do not prove complete traceability or code correctness.

## Governance-Surface Adoption

As teams mature beyond initial setup, treat changes to agents, skills, prompts, instructions, workflows, specs, module headers, policies, capabilities, gatekeepers, validators, evidence semantics, and dashboard semantics as governance-surface changes.

When designing or changing a capability, feature, validator, report, prompt,
agent, instruction, workflow, documentation surface, source module, or project
configuration, apply the Systemic Capability Wiring Skill at
`templates/skills/systemic-capability-wiring/SKILL.md`. It is the canonical
AI-agent checklist for connecting a change to contracts, configuration,
validation, evidence, visibility, docs, tests, and human decision boundaries.
Use `docs/SYSTEMIC_CAPABILITY_WIRING.md` as the short public method summary.
In generated adopter projects, use the profile-gated installed copy under
`.github/skills/` instead of the source-kit `templates/skills/...` path. Use
`.github/skills/systemic-capability-wiring/SKILL.md` when installed, such as in
assured/full-catalogue projects or after an explicit skill add; otherwise use
`.github/skills/systemic-wiring/SKILL.md` where installed plus
`naos systemic-impact` / `naos control-plane-review` for the same review
obligation.

Recommended review/routing:

1. Check whether the surface still maps to the intended NAOS lifecycle command, agent, prompt, capability, policy, validator, gate, evidence output, and dashboard panel.
2. If `specs/04-architecture.md` changes, review linkage to `specs/01-problem.md`, `specs/02-solution.md`, `specs/03-requirements.md`, `TASK_REGISTRY.yaml`, `TRACEABILITY_MATRIX.md` where present, affected capability contracts, relevant gate/evidence expectations, known gaps, and residual risks.
3. If research, autoresearch, trend-review, repo-review, or external analysis produces actionable findings, declare or update a structured item in `naos/control_plane_review_items.yaml`, then route it into capability contracts, central policy, gatekeepers, validators, roadmap/crosswalk, task registry, known gaps, residual risks, evidence pack, dashboard, next-action recommendation, AI instruction surfaces, or specs 01-04 as appropriate.

Use adopter-facing capability names in plans and reports: Deterministic Conformance Review is implemented static/file-first checking; StaticGrader is deterministic structural grading over declared trace/report metadata; Grader Assessment is deterministic audit/drift/assess review input; LLMGrader Readiness is disabled/readiness-only governance posture for a possible future advisory second opinion; Autoresearch Readiness is configuration and routing posture; Behavioral Governance Readiness is deterministic readiness and impacter review for first baseline work or baseline maintenance. Do not present scenario metadata, StaticGrader, grader assessment, LLMGrader readiness, Behavioral Governance Readiness, or future advisory dimensions as semantic behavioral scoring unless the project separately implements and approves an evaluator.
4. Treat findings as proposed remediation, waiver, or next-action routing. Do not silently rewrite risky security, encryption, authentication, authorization, database, public API, or regulatory-control code.

This review is advisory/profile-aware unless a project has installed an implemented validator or gate that enforces it.

When an advisory control disagrees with deterministic evidence, record a
discrepancy or residual-risk item and route it through control-plane review.
Only reviewed decisions update durable state.

Run `naos control-plane-review --profile <profile>` after adding structured review items. The report writes `naos/reports/control_plane_review.json` and shows governance-surface review and research-routing status, including missing routing, known gaps, residual risks, waivers, and human-review requirements. It does not prove research completeness or governance correctness.

## Systemic Impact Review

Group related project artifacts through `naos/systemic_impact_rules.yaml`, then run `naos systemic-impact --profile <profile>` after meaningful changes to specs, requirements, policies, gates, validators, scripts, prompts, agents, skills, instructions, workflows, docs, claims, evidence, dashboard semantics, or capability contracts.

When closing a stable bounded change, pass each exact changed path explicitly:

```bash
naos systemic-impact --profile <profile> \
  --changed-path <repo-relative-path> \
  --changed-path <another-path>
```

Review every emitted artifact-family, typed review-surface, and declared
artifact obligation. Record `updated`, `reviewed_no_change`, `not_applicable`,
`update_required`, or `unresolved` in a review-record YAML, then rerun with
`--review-record <yaml> --require-resolved`. Closed dispositions require
rationale and evidence. If resolving an obligation changes another file,
refreeze the path list and repeat.

The review record lists the complete exact `changed_paths` set once, then one
decision per unique routed destination. The report retains all contributing
paths, families, triggers, and declared links, avoiding duplicate review
decisions without hiding why a destination was selected.

The seed keeps kit-development source patterns separate from portable
adopter-generated patterns. Adopter projects do not receive NAOS internal
`dev/` history, audits, or plugin source through this feature. The command does
not infer a Git base, edit files, activate an integration, or grant approval.

The flow is:

`configure -> evaluate -> report -> review -> update -> re-evaluate`

NAOS does not automatically know every project dependency. It uses configurable artifact-family rules, typed review surfaces, semantic path routes, and declared capability links to identify review obligations, affected artifact families, missing links, stale links, `not_configured` families, disabled families, and human-review requirements. The generated `naos/reports/systemic_impact_review.json` is a review aid; it is not proof of perfect coherence, complete impact analysis, or certification.

## Professional Adoption Engine

For new or existing projects, prefer the connected adoption path before durable activation:

```bash
naos preflight . --profile standard
naos intake . --answers naos/intake_answers.yaml --profile standard
naos install-plan . --profile standard
naos context-challenge . --challenge-mode install --profile standard
naos plan-challenge . --challenge-mode implementation-plan --profile standard
naos decision-probe . --challenge-mode decision --profile standard
naos planning-gate-review . --challenge-mode gate --profile standard
naos install-decision-record . --profile standard
```

`naos adopt` orchestrates those pieces and, for brownfield/evaluation modes, adds repository-context challenge, candidate requirement reconstruction, traceability gaps, and brownfield baseline reports.

The five challenge command labels currently share one deterministic file-path
presence check. They enumerate local paths but do not read source or document
contents, or parse or evaluate a plan, decision record, gate state, or prior
report content. A present `planning_gate_review` report proves only that this
bounded posture check ran; it is not substantive gate review or approval.

```bash
naos adopt . --mode greenfield --profile standard --dry-run
naos adopt . --mode brownfield --profile standard --dry-run
```

`--dry-run` is the report-writing preview posture for `naos adopt`: it
orchestrates the deterministic adoption reports, explains the phases, writes
only declared NAOS report artifacts, and does not activate hooks, CI,
providers, memory write-back, MCP runtime, external connectors, or protected
project files. `--no-write-preview` evaluates the same phases without writing
reports or activation files. `--no-prompt` controls interaction only; it does
not change either write contract. The JSON fields `no_write_preview`,
`report_writes_performed`, and each phase's `write_status` make the distinction
mechanically visible.

The report-writing `--dry-run` path requires secure directory-descriptor writes
that bind creation and replacement to the already-open report directory. If
the host cannot provide that primitive, adoption fails before creating a report
parent or file and directs the operator to `--no-write-preview`; NAOS does not
claim equivalent strict parent-swap protection from its portable path fallback.

For greenfield work, use one explicit preview → install-set review → activation
route:

```bash
naos adopt . --mode greenfield --profile quickstart --no-write-preview
naos-governance init --new --tier quickstart --preview-dir .naos-preview
# Review the generated install set and profile_generated_surface_contract.json.
naos-governance init --new --tier quickstart --activate
```

The persistent preview destination must be absent. Inside the target, only the
direct `TARGET/.naos-preview` path is supported; other persistent preview paths
must be outside the target. The initializer preserves and refuses any
pre-existing file, directory, or symbolic link at that path.
For a target-preserving evaluation instead, use `naos init --dry-run` without
`--preview-dir`; its external temporary preview is removed on exit. Default
activation regenerates into separate external temporary staging and preserves
the review preview. It is not digest-bound to that earlier preview, so use the
same reviewed kit source and arguments and inspect the activation output.
The regenerated install set is frozen into a provenance-bound create-only plan
and applied with an exclusive lock, same-filesystem staging, durable journal,
atomic leaf publication, receipt, and restart recovery. This does not provide a
single multi-path snapshot: another reader can observe completed leaf
publications while the transaction is in progress.

Profile selection is purpose-based, not compulsory progression. Use Quickstart
for bounded evaluation, Lite for a reduced real-project workflow, Standard for
broader SDLC evidence, and Assured for the strongest configured evidence and
reviewer handoff. A different profile may be selected later if the purpose
changes; that choice is not proof of maturity.

Native lifecycle maintenance uses `naos task-lifecycle`, `naos task-complete`,
`naos research-record`, and `naos composed-traceability` where those surfaces
are installed. These are current file-first behaviors. Semantic/vector/graph
runtimes, model-backed grading, autonomous learning, and provider execution
remain future or separately project-configured candidates; readiness metadata
does not make them current runtime behavior.

Inventories separate existing resources, AI artifacts, memory/Engram posture, and MCP declarations. Reconciliation commands record `keep`, `merge`, `replace`, `quarantine`, `create`, or `review_required` decisions without silently overwriting active files. Candidate FR/NFRs use confidence classes such as `confirmed_by_existing_spec`, `supported_by_docs`, `inferred_from_code`, `inferred_from_tests`, and `hypothesized_requires_review`.

The adoption engine is review evidence. It does not approve work, choose profile authority for the user, promote candidates to requirements, write memory, activate providers, prove runtime safety, or prove legal or regulatory compliance.
