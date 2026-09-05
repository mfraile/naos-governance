# Glossary

NAOS-specific vocabulary, defined factually.

---

## Admissibility

The practical readiness of governance evidence to be handed to a reviewer, auditor, regulated principal, customer, or internal risk owner. In NAOS, admissibility is defined in `docs/ADMISSIBILITY.md` and grounded by public compliance mappings and generated project evidence.

## Architecture Decision Record (ADR)

A public-safe record of a load-bearing NAOS architecture decision. Public ADRs
live under `docs/decisions/` and include status, context, decision,
consequences, and related files. They are architecture rationale, not legal
advice, approval, certification, or proof of compliance.

## Allowlist (duplicate / semantic)

A YAML file listing pairs of functions or modules that look like duplicates but are intentionally distinct. Two files: `configs/naos_duplicate_allowlist.yaml` (literal-name matches) and `configs/naos_semantic_allowlist.yaml` (cosine-similarity matches). Every entry requires an `approved_by` and `date`; quarterly review is recommended.

## Archetype

A pre-populated technology-stack template. NAOS ships five: `django-postgresql`, `nextjs-supabase`, `go-grpc`, `springboot-kafka`, `fastapi-generic`. Each archetype carries a `project-context.md`, scoped instructions, profile defaults, and Makefile targets. Selecting an archetype during `naos init` auto-detects (or accepts) the project's stack and binds the matching instructions via `SIGNAL_INSTRUCTION_MAP` in `naos_init.py`.

## Assured profile

The strictest of the four governance profiles. It is intended for
evidence-heavy reviewer handoff and stronger gate posture where configured. See
`docs/ASSURED_PROFILE_ACTIVATION.md`. It is a profile name, not certification,
proof of compliance, runtime safety proof, or automatic approval.

## Behavioral Audit Enablement

Public guidance in `docs/BEHAVIORAL_AUDIT_ENABLEMENT.md` for keeping
behavioral and advisory surfaces bounded. StaticGrader remains structural and
deterministic; LLMGrader is readiness-only by default; advisory findings require
residual-risk handling and human review.

## Capability (capability card)

A bounded set of actions declared by an agent, skill, or scoped instruction, with explicit authority, constraints, and evidence requirements. The canonical capability-card schema is `schemas/naos/capability.schema.json`; capability cards live under `capabilities/*.yaml` and are validated by `scripts/validators/validate_capability_contracts.py`.

## Capability contract

A file under `capabilities/*.yaml` describing one NAOS capability, including status, default maturity, profile applicability, evidence expectations, validators, gatekeepers, dashboard signals, limitations, and claims that are explicitly not made.

## Capability maturity

The L0-L5 progression used by the control plane: scaffolded, configured, operational, enforced, measured, assured. A project can install the kit at L0 while only some capabilities progress to L1-L5.

## Control plane

The file-first layer that connects existing commands, prompts, agents, workflows, task records, validators, gatekeepers, evidence packs, and dashboard summaries. See `docs/CONTROL_PLANE.md`.

## Parallel lane opportunity

An advisory task-planning value recorded in active task cards or
`PRE_IMPLEMENTATION_ALIGNMENT.md`: `not_applicable`,
`sequential_recommended`, `parallel_possible`, or `parallel_recommended`. It is
a prompt for human/project review, not an active lane declaration and not
approval to dispatch work.

## Parallel lane decision

The human/project decision for a task's lane posture: `sequential`, `declared`,
or `deferred`. Only `declared`, paired with a lane handoff input that records
`parallel_lanes_declared: true`, activates the local handoff review route.

## Parallel lane handoff report

The deterministic local report emitted by `scripts/naos_parallel_lane_handoff.py`
under `naos/reports/parallel_lane_handoff/`. It records declared lane evidence
for review and can be reconciled by `naos control-plane-review`; it is not task
authorization, agent dispatch, merge approval, task completion proof,
certification, attestation, runtime orchestration, or proof of compliance.

## Cross-Harness Review Readiness

Readiness-only planning for future independent review across separate harnesses
or review contexts. Implemented by `naos cross-harness-review-readiness` and
documented in `docs/CROSS_HARNESS_REVIEW_READINESS.md`. It records harness
inventory, trust boundaries, evidence needs, DSSE-style planning requirements,
and adopter-owned key-custody boundaries. It is not harness execution, signing,
signature verification, attestation authority, approval, certification, or proof
of compliance.

## Agent trace validation

The deterministic review report emitted by `naos agent-traces` at
`naos/reports/agent_trace_validation.json`. It validates declared records in
`naos/agent_trace_events.yaml`, including optional `action_receipt` metadata for
side-effect class, approval posture, permission scope, claim refs, and memory
trust state. It is not runtime capture, command execution, permission
enforcement, tool-call interception, memory write-back, approval,
certification, proof of compliance, behavioral correctness proof, or
hallucination prevention.

## Harness trace import

The review-only adapter emitted by `naos harness-trace-import` at
`naos/reports/harness_trace_import.json`. It reads an explicit repo-local
JSONL/NDJSON file and normalizes compatible records into declared agent trace
event shape. With `--write-events`, it appends valid declared records to
`naos/agent_trace_events.yaml` for later `naos agent-traces` validation. It is
not runtime capture, harness execution, hook activation, provider/API use,
memory write-back, approval, certification, proof of compliance, or behavioral
correctness proof.

## API symbol reality

The deterministic review report emitted by `naos api-symbol-reality` at
`naos/reports/api_symbol_reality.json`. It checks explicitly declared Python
symbols from `naos/api_symbol_reality.yaml` using repo-local source paths or
installed-distribution Python source files. It does not import or execute target
modules and does not prove API semantics, runtime behavior, option
compatibility, endpoint behavior, package safety, approval, certification,
compliance, or hallucination prevention.

## Public audit playbook

The public runbook at `docs/AUDIT_PLAYBOOK.md` for running deterministic NAOS
checks, reading generated reports, and preparing reviewer-facing evidence. It
does not expose private audit skills and does not provide legal advice,
regulator attestation, deployment approval, or proof of compliance.

## Package reality review

The deterministic review report emitted by `naos package-reality` at
`naos/reports/package_reality.json`. It checks local Python dependency
manifests, lock-style pins, optional docs install snippets, configured local
CycloneDX SBOM/provenance/hash evidence, and registry metadata only when
explicitly run with `--registry-mode online --allow-network`. It is package
review evidence, not proof of package safety, malware absence, vulnerability
absence, SBOM completeness, provenance authenticity, supply-chain assurance,
registry trust, approval, certification, or compliance.

## Spec-pack contract

The deterministic review report emitted by `naos spec-pack-contract` at
`naos/reports/spec_pack_contract.json`. It checks profile-required spec files,
required sections, anchors, sync markers, and optional filled-mode unresolved
placeholders against `spec_manifest.yaml`. It is template contract conformance
evidence, not proof of specification quality, requirements completeness,
approval, implementation, complete traceability, certification, or compliance.

## Spec-pack materialization

The bounded setup report emitted by `naos spec-pack-materialize` at
`naos/reports/spec_pack_materialization.json`. It previews or copies missing
profile-required spec-pack template files while skipping existing project files
unless `--force` is explicit. It does not fill specs, approve specs, prove
applicability, or prove profile readiness.

## Spec assembly worksheet

The review-only report emitted by `naos spec-assembly-worksheet` at
`naos/reports/spec_assembly_worksheet.json`. It maps brownfield adoption
evidence, candidate requirements, and traceability gaps to manifest-declared
spec files. Candidate mappings stay unpromoted and require human review; the
worksheet does not prove complete traceability or approve requirements.

## Spec-cascade coherence

The deterministic review report emitted by `naos spec-cascade` at
`naos/reports/spec_cascade_coherence.json`. It checks structural linkage among
requirements, task registry entries, source headers, and configured source
roots, including unresolved source-level FR/NFR/AC/SCEN references where
spec ids exist. It is traceability evidence, not proof of complete traceability,
code correctness, runtime behavior, approval, certification, or compliance.

## AC completion evidence

The deterministic review report emitted by `naos ac-completion-evidence` at
`naos/reports/ac_completion_evidence.json`. It checks explicit
`naos/ac_completion_evidence.yaml` declarations for claimed-complete AC/SCEN
entries and their local evidence paths/outcomes. It does not prove AC
correctness, complete coverage, implementation correctness, approval,
certification, or compliance.

## Task Context Pack

A bounded, derived context artifact for one exact active or completed task. `naos task-context --task <TASK-ID>` writes `naos/reports/task_context_pack.json` and can optionally write `naos/context_packs/<TASK-ID>.md`. It references task cards or durable completed history, specs, capability cards, deterministic reports, memory-readiness posture, gaps, risks, waivers, commands, and human-review boundaries without becoming source artifacts, approval, automatic context injection, or memory evidence.

## Native task lifecycle

The versioned exact-id contract in `naos/task_lifecycle_contract.yaml`. The implemented actions are inspection and completion; completion accepts only `active` or `implementation_complete`, moves the card to `naos/completed/`, and appends `naos/completed_history.yaml`. A verified-delivery request must first validate existing test/evidence references and an approved exact-task `task_delivery` decision. Unsupported legacy statuses remain visible as unresolved and block completion. Deferred, cancelled, absorbed, and superseded are declared non-delivery metadata states, not implemented transition commands. Completion does not authorize merge, release, evidence admission, or exception closure.

## Structured research record

A profile-proportionate candidate record with stable identity, revision/supersession metadata, source provenance, claim type and posture, uncertainty, contradictions/counterevidence, outcome, traceability, and human disposition. Schema validity is necessary but does not promote the record into a requirement, decision, evidence admission, or repository authority.

## Composed traceability

A derived report that checks explicit task-to-source, source-to-test, test-to-evidence, and evidence-to-decision relationships. Link presence is structural evidence only; it does not prove that a source implements the task, a test verifies the intended behavior, evidence is admissible, or a decision is substantively correct.

## Attributable human decision

A separate schema-valid repository record naming the human decision-maker, decision type, outcome, scope, timestamp, and referenced evidence. `task_delivery` is the explicit type used to establish structural attribution for verified delivery. It does not imply merge, release, evidence-admission, or exception authority, and schema validation does not prove that the named person genuinely reviewed the work or that tests are sufficient. Agent review may report readiness for a decision, but it cannot create human authority.

## Cognitive checkpoint

A structured checkpoint under Rule 26, recorded via `mem_save` only when Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use, or into the active compact/task card when memory is deferred, disabled, unauthorized, or unavailable. Five trigger conditions (T1 phase transition / T2 non-obvious discovery / T3 ≥5 tool calls / T4 ≥20 messages / T5 pre-handoff). Payload has five typed fields: What / Why / Files / Remaining / Gotchas. The profile `RULES.md` files define the enforcement posture; `templates/skills/cognitive-checkpoint/SKILL.md` provides the checkpoint template.

## Engram

External memory MCP server (MIT-licensed, Go binary). Can persist `mem_save` calls across sessions only when write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use; supports `mem_search` and `mem_get_observation` only when access is configured, authorized, and verified. NAOS treats Engram as the recommended local provider pattern when configured by the adopter; memory remains advisory recall and not authoritative evidence.

Recommended NAOS setup is local-first Engram storage under `ENGRAM_DATA_DIR` (default `~/.engram`), with the database derived as `<data-dir>/engram.db`. NAOS does not configure replication or synchronization and reports a non-local declaration as unsafe and review-required. An `~/engram-memories` checkout, where present, is an optional management toolkit—not the live store or a Git memory-sync repository. If Engram is already installed, run `naos memory check` and connect NAOS to the existing setup instead of creating duplicate configuration. See `docs/ENGRAM_SETUP.md`.

## MCP (Model Context Protocol)

Protocol used by AI tools to expose external tools such as memory servers. NAOS memory-aware agents may require the actual Engram MCP namespace in their tool allowlist; `vscode/memory` alone should not be treated as proof that `mem_context` or `mem_save` is available. Multi-project clients must use a registry-approved canonical identity: dynamic clients verify `mem_current_project`, while a fixed `ENGRAM_PROJECT` is acceptable only for one workspace and only when it agrees with the approved remote mapping. Run `naos memory-readiness`, `naos memory-access`, and `naos memory-use-policy` to inspect declared/configured posture, explicit unverified fields, and governed use boundaries. Live provider, MCP, and project-identity verification remains a separate active-client step.

## Goal-backward verification

A mandatory ordered contract in `templates/agents/naos-review.agent.md` and
role-specific pre-completion contracts in Conformance and Debug. Review applies
and reports independent goal/diff, edge/coverage, and AC/spec-evidence lenses
separately before one deduplicated advisory synthesis. It traces changed paths and resulting-state
evidence backward to supplied criteria, preserves uncertainty and deferral, and
keeps deterministic checks and named-human authority primary. Conformance adapts
the backward trace to audited findings and pass claims; Debug adapts it to an
exact failure/reproducer, expected behavior, diagnosis, and writer-validation
handoff. Without explicit criteria, each role continues only its legitimate
bounded work, marks the mapping unavailable, and invents no requirement or
completion claim. Exact block validation proves structural conformance only;
instruction presence is not live behavioral efficacy or operating effectiveness.

## Handoff template

`templates/agents/_HANDOFF_TEMPLATE.yaml`. A structured cross-agent record carrying completed work, remaining work, files modified with rationale, decisions, test state, constraints, advisory `next_action`, and context notes. Used when a session ends mid-task.

## next_action

An advisory footer or handoff field that names the next safe command, agent target, reason, and constraints for a human operator. It is guidance, not runtime orchestration, and does not authorize agents to bypass the human-mediated handoff chain.

## Instinct

An observed behavioural pattern recorded before promotion to a formal rule. Schema in `templates/instincts/schema.yaml`. Three tiers: Tier 1 (project, `.github/instincts/`), Tier 2 (user-centralized memory, preferably local-first Engram under `ENGRAM_DATA_DIR`), Tier 3 (universal, ships with the kit). Lifecycle: hypothesis → confirmed → dismissed → promoted. Promotion gates require human review (ADR-0005).

## Lite profile

Warning-oriented profile for projects that want native research, planning,
implementation, review, design, lifecycle, and traceability surfaces without
the full Standard control posture. Setup effort is project-dependent; this
profile label is not a universal risk classification or ROI claim.

## NAOS_TIER

Environment variable controlling pre-commit hook behaviour. Values:
`quickstart`/`lite` (core section, with `lite` the default), `standard` (core plus
Standard section), and `assured` (core, Standard, and Assured sections). Numbered
section labels are not a count of executable blockers. Read by
`templates/rules-chain/.githooks/pre-commit`. Not enforced at the kit layer; CI
enforcement is the adopter's responsibility.

## NAOS_CONTEXT_REMAINING_PCT

Caller-supplied environment variable read by the Standard/Assured pre-commit
section at `pre-commit:225–241`. `<25%` rejects that commit attempt; `<35%`
warns; unset is a no-op. The hook neither measures remaining context nor
authenticates the signal's producer. See
`docs/tutorials/MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md`.

## PAUL context brackets

Four behavioural states declaring an AI agent's remaining context-window headroom. The table is promoted into profile Rule 26 text and mirrored in `templates/skills/cognitive-checkpoint/SKILL.md`:

- **FRESH** — >75% headroom. Normal cadence. Speculative exploration permitted.
- **MODERATE** — 35–75%. Prefer focused tool calls; summarise verbose outputs.
- **DEEP** — 25–35%. No new exploration; compact memory; T1+T5 checkpoints forced.
- **CRITICAL** — <25%. Stop. Save full checkpoint. Hand off via `strategic-compact`.

The PAUL guard can reject a commit attempt when the caller supplies a value below
25%. It does not measure remaining context, verify that a checkpoint or handoff
occurred, or intercept non-commit tool calls.

## Profile

One of four pre-defined governance configurations (`quickstart`, `lite`,
`standard`, `assured`). Selected during `naos init`. Determines generated
surfaces, rule/enforcement posture, and AI-review posture. Profiles are selected
by purpose rather than compulsory progression; they do not determine a universal
setup time or legal/regulatory risk class.

## Promotion gate (instincts)

A point in the instinct lifecycle requiring evidence threshold plus human review. Three gates: Tier 1→2 (`evidence_count ≥5`, ≥2 sessions, human review), Tier 2→3 (`evidence_count ≥10`, ≥2 projects, human review), to_rule (`evidence_count ≥10`, strong consensus, testable via scenario, human review). NEVER auto-promote.

## Quickstart profile

The lowest-friction profile (5 rules, 3 blocking-posture). Suitable for bounded
evaluation and minimal guardrails; actual setup effort is repository-specific.

## Readiness gate

The check that a project has the prerequisites for advanced kit features. Implemented in `scripts/naos_readiness.py`. Verifies specs/01–04 ≥250 chars, ADAPT markers resolved, AI policy valid, task registry anchors populated. The gate is the precondition for future behavioural baseline runs.

## ROM / RAM (Rule 19 memory model)

The kit's memory governance metaphor. **ROM** = governance files (`RULES.md`,
profile files, instinct schema) — *read-only* in the sense that AI agents must
not silently overwrite them. **RAM** = volatile session memory (Engram
`mem_save`, session summaries). Rule 19 declares that RAM never overwrites ROM;
the rule text is at `profiles/governance-assured/.ai/RULES.md:285–290`.

When Engram is deferred or disabled, NAOS uses degraded recovery through task cards, compact files, git state, and repo governance files.

## Rules (governance rules)

The numbered rules in `.ai/RULES.md`. Quickstart/Lite/Standard/Assured activate
5/9/19/19 rows, of which 3/3/13/19 have documented blocking posture. Posture is
not a count of installed executable checks. Rules are versioned; the full
ladder is documented in `profiles/governance-assured/.ai/RULES.md`. Adjacent
concept: *Instinct*, which is what a rule looks like before it has been promoted.

## Skill

An invocable context fragment carried by `templates/skills/<skill-name>/SKILL.md`. Skills provide focused guidance without changing the AI's mode. 25 skills ship in the current kit. From a research-paper perspective, a skill is a capability with parameters but no model binding.

## Standard profile

The full-workflow profile for projects that require stronger evidence and
traceability controls than Lite. It is a purpose choice, not a universal
maturity step, setup-time estimate, or legal/regulatory risk classification.

## Deterministic Conformance Review

The conformance review that ships in v1.0.0. It verifies governance files exist, YAML parses, generated AI-surface frontmatter is shaped correctly where validators are installed, and scenario context-file metadata is present. It is static, file-first, and uses no LLM, API key, provider setup, behavioral grading, or network service. Implemented in `autoresearch/runner.py`. Returns `null` for the 8 behavioral dimensions when no project-configured behavioral evaluator exists.

## Three-Layer Trinity

The kit's mental model for governance documents, expressed in `templates/prompts/naos-GOVERNANCE_BOOTSTRAP.prompt.md`:

- **Layer 1 — Specs (constitution)**: what the project must do.
- **Layer 2 — PM artefacts (audit)**: what the project has done.
- **Layer 3 — AI rules (police)**: how the project must do it.

Referenced by selected `/naos-*` prompts as ordered context-review guidance;
the kit installs no host-level automatic loader.

## Truth Table

`naos/governance/GOVERNANCE_TRUTH_TABLE.md`. Canonical metrics file. Other governance documents (DASHBOARD, PROJECT_STATUS, README) must match the values here. Drift between any of them and the truth table is detected by `scripts/naos_validate_truth.py`. Manipulating the truth table itself is a known evidence-integrity risk.

## Vendor cascade

Pattern from OSFI E-23 (Canada) by which standards for major banks flow down to their fintech and AI vendors. The vendor must demonstrate compliance evidence acceptable to the bank's auditors. In NAOS, generated evidence bundles and public compliance mapping are the relevant public artefacts at the vendor-cascade boundary.

## Behavioral Governance Readiness

Shipped deterministic readiness and impacter-review report for first behavioral baseline work or baseline maintenance. It plans around scenario metadata, review criteria, provider/cost considerations, known gaps, residual risks, and human approval boundaries without running a behavioral grader. It does not produce behavioral results by default. A project must separately design, approve, configure, and run any behavioral evaluator.

---

## Cross-walk to agentic-AI governance vocabulary

For readers comparing NAOS to agentic-AI governance literature, the table below describes approximate public terminology mappings. It is an explanatory bridge, not a normative standard.

| Paper term | NAOS analogue |
| --- | --- |
| Capability | Skill + agent + scoped instruction (three frontmatter shapes; capability card unifies them) |
| AI surface catalogue | Generated `configs/naos_ai_surface_catalogue.yaml` inventory emitted from current agent, skill, and instruction frontmatter. This is separate from control-plane capability contracts in `capabilities/*.yaml`. |
| Authority / constraints / evidence | Capability-card fields (`schemas/naos/capability.schema.json`) |
| Transition system T = (S, Σ, δ) | Pre-commit hook + PAUL bracket state machine (commit-time only) |
| State attributes (Alignment, Verification, ...) | PAUL bracket + cognitive checkpoint fields (What/Why/Files/Remaining/Gotchas) |
| Governance decision Δ | Human decision informed by repository evidence; a hook or validator exit code is evidence, not decision authority |
| Agent trajectory store | `mem_save` payload + handoff template + `naos_autoresearch.yaml` readiness configuration |
| External risk-tier vocabulary | No canonical one-to-one mapping to NAOS profiles; select a profile by project purpose, evidence needs, and configured controls |
| Default-deny / dual approval | Assured documents 19 blocking-posture rules and 4 human-review gates; it does not provide default-deny or dual-approval runtime enforcement by itself. |
| Orchestration drift | Future/project-configured behavioral evaluator topic; no behavioral drift operation is implemented by default |
| Existing-project change surfaces | `naos_upgrade.py` supports immutable planning, separately authorized exact-digest apply, and recovery for eligible managed changes; `naos_add.py` performs explicit bounded additions. Neither reconstructs adopter requirements or grants overwrite authority. |
| Admissibility | Evidence packaging + public compliance mapping |
| Vendor cascade (OSFI E-23) | Regulated-domain mapping + generated evidence bundles |
