---
applyTo: "{naos/**,scripts/**}"
---

# Governance & Scripts Guidelines

> Consult `.github/project-context.md` for project-specific governance conventions.

## Key Governance Files

| File | Editable? | Purpose |
|------|:---------:|---------|
| `naos/TASK_REGISTRY.yaml` | Yes | SINGLE SOURCE OF TRUTH for tasks |
| `naos/active/*.md` | Yes | Current task cards |
| `naos/DASHBOARD.md` | No | Auto-generated (`make -f Makefile.naos gov-refresh`) |
| `naos/BACKLOG.md` | No | Auto-generated |
| `naos/TRACEABILITY_MATRIX.md` | No | Auto-generated |
| `naos/inventory/FUNCTION_INDEX.yaml` | No | Auto-generated (`code_quality_audit.py`) |
| `naos/PROJECT_STATUS.md` | Partial | SYNC blocks auto-updated, journal manual |

## File Rules

- **Update existing files** — never create `naos/SESSION_SUMMARY_*.md`, `docs/ANALYSIS_*.md`, `draft_*.md`
- **No archive folders** — use `git rm` for deletion
- **Exception**: `docs/exploration/` is exempt for exploratory work

## Scripts Conventions

- Scripts in `scripts/` are **production tools only** — configurable via CLI args and YAML.
- Never hardcode UUIDs, user IDs, or user emails in `scripts/`.
- Use `argparse` for CLI tools, load data from `configs/*.yaml`.
- Use `datetime.now(datetime.UTC)` in standalone scripts (not your project's `utc_now()` utility).

## Governance Metric Updates

- **NEVER** manually calculate derived metrics — auto-scripts compute from TASK_REGISTRY.yaml.
- **ALWAYS** run `make -f Makefile.naos gov-refresh` FIRST when scope changes.
- **THEN** read auto-computed values from `naos/PROJECT_STATUS.md` and `naos/DASHBOARD.md`.

## After Code Changes

```bash
python scripts/naos_code_quality_audit.py --generate-index  # Update FUNCTION_INDEX
make -f Makefile.naos naos-function-index-health                              # Check index presence/freshness
make -f Makefile.naos naos-module-headers                                    # Check canonical source module headers
make -f Makefile.naos naos-spec-pack-contract                                # Check spec-pack template contract conformance
make -f Makefile.naos naos-spec-pack-materialize                             # Preview missing profile-required spec files
make -f Makefile.naos naos-spec-assembly-worksheet                           # Map brownfield evidence/candidates to specs for review
make -f Makefile.naos naos-spec-cascade                                      # Check requirement/task/source cascade coherence
make -f Makefile.naos naos-test-evidence-map                                  # Map source changes to tests
make -f Makefile.naos naos-test-evidence                                      # Validate mapped evidence
make -f Makefile.naos naos-ac-completion-evidence                             # Validate declared AC/SCEN completion evidence presence
make -f Makefile.naos naos-agentic-workflow-review                            # Review governed AI-assisted workflow controls
make -f Makefile.naos naos-pre-implementation-alignment-review                # Review pre-implementation alignment artifact
make -f Makefile.naos naos-setup-recommendations                              # Orient module choices and next actions
make -f Makefile.naos naos-governance-bypass-posture                          # Report local hook/CI bypass posture
make -f Makefile.naos naos-external-evidence-ingest                           # Summarize local SARIF when configured
make -f Makefile.naos naos-memory-readiness, make -f Makefile.naos naos-memory-use-policy, make -f Makefile.naos naos-learning-loop-review  # Review memory/MCP access, fallback, and governed learning posture
make -f Makefile.naos naos-task-context TASK=<id>                            # Generate bounded task context for an active task
make -f Makefile.naos naos-context-index                                     # Build generated local context index candidates
make -f Makefile.naos naos-context-query QUERY="..."                         # Query bounded candidate references from the index
make -f Makefile.naos naos-semantic-candidates                               # Evaluate future semantic/vector readiness posture
make -f Makefile.naos naos-graph-context                                     # Evaluate future graph-context readiness posture
make -f Makefile.naos naos-graph-query TASK=<id>                             # Query bounded explicit-link relationship candidates
make -f Makefile.naos naos-ai-surface-budget                                 # Measure AI/governance instruction context health
make -f Makefile.naos naos-static-grader                                     # Run deterministic StaticGrader structural checks
make -f Makefile.naos naos-grader-assessment MODE=audit                      # Build deterministic audit/drift/assess review input
make -f Makefile.naos naos-model-policy                                      # Review model-provider declarations without provider calls
make -f Makefile.naos naos-model-telemetry                                   # Review local model telemetry evidence without provider calls
make -f Makefile.naos naos-failure-mode-observations                         # Aggregate local report findings into failure-mode observation statistics
make -f Makefile.naos naos-opencode-config-hygiene                           # Review optional OpenCode config hygiene without runtime activation
make -f Makefile.naos naos-design-traceability                               # Review optional UI object-identity declarations
make -f Makefile.naos naos-ui-experience-quality                             # Review optional UI quality evidence declarations
make -f Makefile.naos naos-llm-grader-readiness                              # Report readiness-only LLMGrader posture
make -f Makefile.naos naos-evidence-attestation                              # Generate local digest/reviewer metadata report
make -f Makefile.naos naos-evidence-conflicts                                # Detect deterministic evidence/review conflicts
make -f Makefile.naos naos-task-claim TASK=T-123                             # Record local task-claim coordination metadata
make -f Makefile.naos naos-task-release TASK=T-123                           # Release local task-claim coordination metadata
make -f Makefile.naos naos-task-claims                                       # Summarize task claims
make -f Makefile.naos naos-self-check                                         # Aggregate control-plane conformance
make -f Makefile.naos naos-systemic-impact                                    # Review configured artifact-family impacts
make -f Makefile.naos naos-control-plane-review                              # Review governance-surface/research routing items
make -f Makefile.naos naos-gate-status                                        # Review gate readiness
make -f Makefile.naos naos-evidence-pack                                      # Export consolidated evidence
make -f Makefile.naos naos-sarif-export                                       # Export structured findings to SARIF
make -f Makefile.naos naos-dashboard                                          # Refresh dashboard summary
make -f Makefile.naos gov-refresh                                             # Update all governance files
```

Treat these as detective controls. Missing evidence remains missing or not configured until a human/project owner resolves it.

Boundary summary:
- Agentic workflow, setup recommendations, bypass posture, external evidence, memory/MCP, governed learning lifecycle, task context, task claims, local indexes, semantic/graph readiness, trace validation/import, StaticGrader, grader assessment, model-provider policy, model telemetry evidence, LLMGrader readiness, SARIF export, evidence attestation/conflict reports, systemic impact, and control-plane review are review or coordination evidence only.
- They do not approve work, certify outcomes, prove compliance, authenticate, authorize, prove behavior, prove source correctness, prevent hallucinations, replace human review, activate hooks, write memory, call providers, inject context automatically, or create source-of-truth authority.
- AI-surface anchor wording is required evidence, not prose decoration: not claimed boundaries include does not prove, not approval, and not certification; source artifacts remain authoritative and repository evidence remains primary.
- Memory is advisory recall; instruction-grade use and durable writes require explicit approval/provenance/scope/reviewer/timestamp/freshness plus configured, authorized, verified, policy-permitted access.
- StaticGrader and grader assessment are deterministic/file-first review inputs. Model-provider policy is declaration review only and has no provider/model call, credential validation, model recommendation, or runtime routing authority. LLMGrader readiness is disabled/readiness-only by default and has no LLM, no model, no provider/API call, and no cost-bearing runtime.
- For AI-surface budget `warning` or `degraded` findings, use `.github/skills/ai-surface-health-review/SKILL.md` where installed, then route unresolved findings through `naos control-plane-review`.
- For lessons that may change future behavior, use `.github/skills/governed-learning-lifecycle/SKILL.md` where installed and run `naos learning-loop-review`; candidates are proposal-only and active learning requires reviewed promotion metadata.
- When implementing or materially changing code, config, schema, workflow, or governance surfaces, and before claiming work done/fixed/passing, use `.github/skills/governed-coding-execution/SKILL.md` where installed; it produces an evidence-backed completion ledger and does not approve, certify, or replace human review.

When designing or changing a capability, feature, validator, report, prompt,
agent, instruction, workflow, doc, source module, or project configuration, use
`templates/skills/systemic-capability-wiring/SKILL.md` as the canonical wiring
checklist instead of duplicating long local variants.
Run or recommend `naos ai-surface-budget` when prompts, agents, skills,
instructions, workflows, manuals, quick references, or governance docs change.
It reports static context pressure, anchors, combined loadout, and baseline
drift without preventing hallucinations, grading behavior, auto-tuning
thresholds, or approving baseline changes.
Use adopter-facing names: Deterministic Conformance Review is implemented
static/file-first checking; Autoresearch Readiness is routing posture;
Behavioral Governance Readiness is deterministic baseline-readiness and
impacter review. Do not use internal work-item labels or claim
semantic/model-backed behavioral grading exists in the default kit.

## Control-Plane Self-Review

Use this review/routing discipline when governance surfaces change. It is file-first
and profile-aware; it is not a runtime orchestrator, scheduler, daemon, autonomous
supervisor, or fully automated validator unless a project has installed one.

- `SKILL.md`: review frontmatter, parameters, when-to-invoke rules, overlap with agents/prompts/instructions, excessive authority, and recommend update/merge/deprecate/keep/defer.
- `.agent.md`: review model/tools/frontmatter, role boundaries, handoff rules, least privilege, risky auto-fix behavior, and mapping to commands, prompts, capabilities, policy, validators, evidence, and dashboard.
- `*.instructions.md` or tool surfaces: review `applyTo`, contradictions across Claude/Copilot/Cursor/.ai/AGENTS.md, claim-control wording, preventive/detective/remediation rules, and source/function-index inspection.
- Workflow prompts: review next-action routing, command/agent handoff, capability/policy/validator/gate/evidence/dashboard mapping, optional path declarations, and human/profile-based approval for risky remediation.
- Specs, module headers, and source traceability: ensure architecture and implementation context remains linked to problem, solution, requirements, tasks, traceability, capabilities, gates, evidence, known gaps, and residual risks. When source modules are added or materially changed, run or recommend `naos module-headers`; when spec templates or generated spec files changed, run or recommend `naos spec-pack-contract`; when profile-required spec files may be missing, run or recommend `naos spec-pack-materialize --dry-run`; when brownfield evidence, candidate requirements, or traceability gaps need mapping, run or recommend `naos spec-assembly-worksheet`; when specs, task registry entries, source headers, source spec references, or source traceability changed, run or recommend `naos spec-cascade`. When `PRE_IMPLEMENTATION_ALIGNMENT.md` declares `planned_change_paths` or `out_of_scope_paths`, run or recommend `naos plan-coherence --diff-base <ref>` for changed-file scope review. Treat findings as review evidence, not automatic rewrite instructions, code-correctness proof, filled-content proof, candidate promotion, spec quality proof, plan approval, or semantic drift proof.

Research, autoresearch, trend-review, repo-review, and external-analysis findings
should be declared in `naos/control_plane_review_items.yaml` when disposition
tracking is useful, then routed into capability contracts, central policy,
gatekeepers, validators, roadmap/crosswalk, task registry, known gaps, residual
risks, evidence pack, dashboard, next-action recommendations, AI instruction
surfaces, or specs 01-04 when actionable.

## Spec 04 Readiness

If `specs/04-architecture.md` is modified, check for current linkage to:

- `specs/01-problem.md`;
- `specs/02-solution.md`;
- `specs/03-requirements.md`;
- `specs/04-architecture.md`;
- `naos/TASK_REGISTRY.yaml`;
- `naos/TRACEABILITY_MATRIX.md` where present;
- affected capability contract where applicable;
- relevant gate/evidence expectation where applicable;
- residual risks and known gaps where applicable.

Quickstart is advisory, lite is warning-oriented, standard is required where
configured, and assured blocks only where an implemented validator/gate enforces it.

## Remediation Safety

- For suspected duplicate intent, produce a finding and remediation options before changing code.
- Do not silently delete, merge, or rewrite security, encryption, authentication, authorization, database, public API, or regulatory-control code.
- Risky remediation needs explicit human/profile-based approval and an evidence update.

## Task Card Conventions

- Use `naos/active/_TEMPLATE.md` for new cards.
- Product tasks → `naos/TASK_REGISTRY.yaml`; methodology → `naos/active/` cards only.
- Include: Spec Section, Existing Code to Use, Acceptance Criteria.
- Include advisory Parallelization Opportunity: `parallel_lane_opportunity`,
  `parallel_lane_decision`, reason codes, candidate lanes, and solo/team
  posture. A suggestion does not activate handoff; handoff applies only when
  lanes are explicitly declared.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-governance/SKILL.md` — invoke via Copilot chat when you need patterns.
