# NAOS-Governance — Your AI Coding Assistant Just Created a Function That Already Exists

> Your AI assistant is excellent. It writes clean code, follows instructions, and passes tests.
> It also just duplicated a function that exists three directories away. Nobody caught it —
> not the AI, not code review, not your linter. **NAOS helps catch that — and the governance failures
> ordinary code checks usually miss.**
> For the shipped deterministic duplicate-function check, "catch" means an identifier-sensitive
> exact normalized-AST match across distinct files. Parameter or local renaming changes the
> comparison; this is not semantic-equivalence detection.

**NAOS-Governance** (*Native AI Orchestration for SDLC*) is **governance-as-code** for AI-assisted software development. Machine-readable rule posture with selected executable checks. Deterministic conformance checks, including agent/skill/instruction frontmatter validation. Function-index and duplicate-intent review surfaces. Generated traceability surfaces. Profile-aware evidence.

NAOS is tool-neutral by design: it works through repository files, commands,
hooks, schemas, reports, and human-reviewed evidence rather than through a
single assistant or IDE.

> **NAOS makes governance inspectable inside the repository.** It adds
> deterministic conformance, traceability, validators, evidence packs, and
> dashboards. Reference-project results are bounded evidence from their own
> context; your project starts with profile selection and creates its own
> evidence as specs, gates, validators, and governance artifacts mature.

---

## The Problem

AI coding assistants can accelerate implementation, but generated work still
needs repository-local governance. Static instruction files give AI agents
guidelines, but they do not enforce method, traceability, review boundaries, or
evidence production by themselves. Code review often catches violations after
they have already reached a branch or pull request. Pre-commit linters usually
check style or syntax, not methodology.

NAOS targets the gap between *"I asked the AI to follow the rules"* and
*"the repository contains reviewable evidence that the governed method was
followed."*

---

## What Is NAOS?

NAOS is not an AI coding assistant, a linter, or a code review tool. It is a
methodology encoded as executable repository artifacts.

| NAOS surface | What it provides |
| --- | --- |
| Profile-scoped hooks | Commit-time governance checks that scale from quickstart to assured profiles. |
| Traceability files and validators | Machine-checkable links among requirements, tasks, source, tests, and evidence where the adopter configures those artifacts. |
| Deterministic reports | Local JSON/Markdown review evidence for conformance, gates, dashboards, hygiene, provenance, compliance posture, and readiness. |
| Human-review boundaries | Explicit non-claims for approval, compliance, runtime safety, publication, and advisory/model-backed work. |

Optional adapter and integration surfaces exist for teams that use specific
developer tools, but those adapters are convenience layers over project-local
NAOS artifacts. They are not source authority and they are not required for the
core control plane.

### Control-Plane Principle

NAOS ships a portable, file-first capability-contract framework for SDLC governance. It does not ship runtime governance, semantic/model-backed behavioral grading, or compliance certification. Projects activate and mature capabilities progressively through profiles, readiness gates, and evidence.

The kit now includes capability contracts, a centralized policy, profile-aware gates, validators, evidence-pack export, and dashboard summary output. These wrap the existing NAOS operating model rather than replacing it:

```text
commands, prompts, agents, workflows
  -> preventive review/routing for specs, research, and governance surfaces
  -> mapped to capabilities
  -> governed by profile policy
  -> checked by validators
  -> converged through gates
  -> packaged as evidence
  -> displayed in dashboard
  -> remediation / waiver / next action
```

See [docs/CONTROL_PLANE.md](docs/CONTROL_PLANE.md), [docs/CLAIMS_AND_LIMITATIONS.md](docs/CLAIMS_AND_LIMITATIONS.md), [docs/ADOPTION_GUIDE.md](docs/ADOPTION_GUIDE.md), [docs/AUDIT_PLAYBOOK.md](docs/AUDIT_PLAYBOOK.md), and [docs/ASSURED_PROFILE_ACTIVATION.md](docs/ASSURED_PROFILE_ACTIVATION.md).

For a first-reader view of current kit scope, local review evidence, and the
human decision boundary, see the
[NAOS scope and human-decision boundary](docs/diagrams/naos-scope-and-human-decision-boundary.mmd).
The Mermaid source is explanatory documentation only; it adds no runtime or
decision authority.

Public mental model: define truth, index context, query candidates, package
task context, review evidence, and record decisions.
`ADR-0010: Control-Plane Advisory Boundaries` documents the boundary behind
that model: advisory controls may challenge deterministic controls, but they
may not replace them.

### Natural-language workflow router

Start from what you are trying to do, then run the explicit NAOS command or
Make target that records evidence. Prompts and agents can recommend the next
step, but they do not silently execute commands or approve outcomes.

| If you are trying to... | Start here | Evidence produced |
| --- | --- | --- |
| Start a new project | `naos adopt . --mode greenfield --profile standard --dry-run` | intake, install plan, challenge, decision record |
| Adopt an existing repo | `naos repository-intelligence plan . --profile standard --component-mode baseline` | source-bound plan before create-only activation and adoption reports |
| Start daily task work | `/naos-task-start <TASK-ID>` when installed; Quickstart states task ID/scope/constraints explicitly | task context, lifecycle posture, review handoff |
| Decide whether task work can use parallel lanes | Lite+: `/naos-task-start <TASK-ID>` plus `naos/PRE_IMPLEMENTATION_ALIGNMENT.md`; Quickstart: review and record the alignment file manually | advisory lane decision; Lite reviews its template manually, while Standard/Assured can produce local handoff reports |
| Review a PR or release | `naos gate-evaluate`, `naos evidence-pack`, `naos dashboard` | gate, evidence, dashboard, PR-risk reports |
| Change governance surfaces | `naos systemic-impact` and `naos control-plane-review` | routed findings, residual risks, next actions |
| Review tool adapters | `naos adapter-coherence` | Codex/Claude/plugin/IDE adapter drift and propagation findings |

For `gate-status` and `gate-evaluate`, profile resolution order is `--profile`,
then `NAOS_PROFILE`, then the generated policy default. Initialization persists
the selected `lite`, `standard`, or `assured` tier in the generated project
policy, so bare calls to those gate commands use that project tier; generated
`quickstart` projects retain the `quickstart` fallback because they do not
include the full policy.

The generated `naos/NAOS_QUICK_REFERENCE.md` is the daily router. The complete
inventory remains [NAOS_CATALOG.md](NAOS_CATALOG.md).

### After Install: Choose The Evidence Path

Use `naos setup-recommendations --profile standard` after initialization to
understand which modules to enable, defer, or keep optional. Apply selected
installable modules only with an explicit dry run first:
`naos add setup-module profile_baseline --profile standard --dry-run`.
The guidance does not automatically enable modules, approve maturity, certify
readiness, or change the selected profile.

| Review need | Start with | Boundary |
| --- | --- | --- |
| Spec-pack lifecycle | `naos spec-pack-contract`, `naos spec-pack-materialize . --dry-run`, `naos spec-assembly-worksheet .` | Checks manifest structure, previews/copies missing profile-required spec files, and maps adoption evidence for review; it does not fill, approve, or prove specs. |
| Module setup | `naos setup-recommendations`, `naos add setup-module --dry-run` | Recommends and stages explicit actions only; it does not enable deferred modules or certify readiness. |
| Memory posture | `naos memory-readiness`, `naos memory-access`, `naos memory-use-policy` | Memory remains advisory recall until reviewed and authorized; repository evidence stays authoritative. |
| MCP descriptor posture | `naos mcp-resource-inventory` | Reviews sanitized repo-local declarations against the exact risk-owner policy. A match is only `allowlisted_pending_activation`; it does not start, authenticate, call, or grant tool/write authority to an MCP server. |
| Declared AI component inventory | `naos ai-component-inventory`, then `naos control-plane-review` | Standard/Assured declared-facts inventory with content-digest freshness. Missing, invalid, stale, or incomplete required evidence routes to G2/G6 human review; it is not CycloneDX/SPDX, runtime discovery, completeness, signing, attestation, approval, release, or publication. |
| Optional agent sponsor registry | Review `naos add setup-module agent_sponsor_registry --profile <profile> --dry-run`, install separately with `--confirm`, run `naos agent-sponsor-registry`, then `naos control-plane-review` | Opt-in Standard/Assured build-time declaration that checks one current opaque sponsor/ownership/review-expiry/credential-posture record per normalized agent. Invalid, stale, expired, unsafe-path, secret-bearing, orphaned, or exception states route to G2/G6; it does not verify identity, credentials, authentication, authorization, or runtime behavior. |
| Task context | `naos task-context --task <TASK-ID>`, `naos context-index`, `naos context-query` | Context packs and query results are aids, not source truth, approval, or hallucination prevention. |
| Native task lifecycle | `naos task-lifecycle --task <TASK-ID>`, `naos task-complete --task <TASK-ID>` | Exact-ID state, durable completed history, and recovery. Verified delivery requires existing test/evidence files plus an approved exact-task `task_delivery` decision; the structural gate does not prove genuine review, authorize merge/release, or admit evidence. |
| Structured research | `naos research-record <record.yaml>` | Profile-proportionate candidate validation; never automatic requirement, decision, task, evidence, learning, or memory promotion. |
| Composed traceability | `naos composed-traceability` | Explicit task→source→test→evidence→decision relationship visibility, qualified separately from semantic correctness or evidence admission. |
| Session evidence | `naos session-id`, `naos session-start`, `naos session-checkpoint`, `naos session-end` | Session reports are checklists and namespaces; they do not mutate task cards, git state, compact files, or memory. |
| Parallel lane planning and handoff | task card / `PRE_IMPLEMENTATION_ALIGNMENT.md`; Lite reviews its installed handoff template manually; Standard/Assured may run `python scripts/naos_parallel_lane_handoff.py --handoff naos/lane_handoffs/<lane>.yaml`, then `naos control-plane-review` | Quickstart has manual alignment only. Suggestions do not activate handoff; executable report generation requires the Standard/Assured script plus explicit declared-lane fields. |
| Declared agent trace records | `naos agent-traces`, `naos harness-trace-import --source <repo-local.jsonl>` | Trace events and optional `action_receipt` metadata are declared review records only; not runtime capture, approval, permission enforcement, memory write-back, tool-call interception, or hallucination prevention. |
| Operator and coordination records | `naos operator-attribution`, `naos task-claim`, `naos task-release`, `naos task-claims` | Local coordination metadata only; not identity proof, authorization, ownership proof, or approval. |
| Evidence integrity review | `naos audit-log`, `naos evidence-attestation`, `naos evidence-sign`, `naos evidence-verify`, `naos evidence-conflicts` | Local records, digest metadata, signable-envelope output, and tamper-evidence review only; not NAOS signing, third-party signature validation, tamper-proof storage, conflict resolution, approval, non-repudiation, or proof of compliance. |
| Model-provider declarations | `naos model-policy` | Reviews repo-local model-role/provider and optional mixed-tool binding declarations; no provider calls, SDKs, credentials, IDE/tool config mutation, model recommendations, runtime routing, approval, or compliance determination. |
| Model telemetry evidence | `naos model-telemetry`, then `naos control-plane-review` when findings exist | Reviews optional repo-local model-use telemetry summaries for session/task/model-role links, policy refs, cost/latency thresholds, payload/credential field capture, and policy exceptions; no provider calls, gateways, credential validation, runtime routing, complete cost accounting, approval, or compliance determination. |
| OpenCode config hygiene | `naos opencode-config-hygiene`, then `naos control-plane-review` when findings exist | Reviews optional repo-local OpenCode config/instruction surfaces; no OpenCode execution, global config inspection, MCP/memory activation, provider/model calls, credential validation, plugin creation, approval, certification, or proof of compliance. |
| UI object identity traceability | `naos design-traceability`, then `naos control-plane-review` when findings exist | Reviews optional repo-local screen/component object IDs, FR/NFR/task links, paths, changed-file evidence, test/check evidence, and human-review posture; no Figma, MCP, html.to.design, provider/model/memory calls, design-tool mutation, sync proof, approval, or compliance determination. |
| UI experience quality evidence | `naos ui-experience-quality`, then `naos control-plane-review` when findings exist | Reviews optional repo-local stage/dependency, data/API/state, token, screenshot/state, accessibility/performance, generator-provenance, and human-review evidence; no Figma, MCP, Penpot, browser, screenshot generation, provider/model/memory calls, design-tool mutation, design-quality proof, approval, or compliance determination. |
| Static and behavioral readiness | `naos static-grader`, `naos grader-assessment`, `naos llm-grader-readiness`, `naos behavioral-readiness` | Deterministic review posture only; no model calls, runtime grading, semantic drift inference, approval, or maturity promotion. |
| Provenance and compliance handoff | `naos ai-code-provenance`, `naos compliance-posture` | Reviewer-facing packaging of declared local evidence; not legal advice, ownership proof, compliance pass/fail, certification, or release authority. |
| PR and release evidence | `naos pr-risk-classify`, `naos pr-governance-summary`, `naos plan-coherence`, `naos gate-evaluate`, `naos evidence-pack`, `naos dashboard` | Review inputs only; not work authorization, plan approval, PR approval, deployment authorization, publication authorization, or proof of compliance. |
| Optional adapters | `naos adapter-coherence`, explicit setup-module dry runs for integration templates | Convenience adapters over project-local NAOS artifacts; no hooks, memory, provider calls, plugin mutation, or settings changes are activated automatically. |

Current maintenance behavior is limited to implemented file-first commands,
schemas, generated surfaces, deterministic validators, and human-reviewed
records such as the native task lifecycle above. Semantic/vector/graph
runtimes, model-backed grading, autonomous learning, and provider execution are
future or project-configured candidates unless a separate implemented contract
explicitly says otherwise. Readiness metadata is not current runtime behavior.

Advanced candidate layers remain bounded:

- `naos semantic-candidates` reports readiness for future semantic/vector
  candidate evidence only. It does not enable embeddings, extension loading,
  provider/model/API calls, memory payload search, or semantic authority.
- `naos graph-context` and `naos graph-query` report explicit-link relationship
  candidates only. They do not enable graph runtimes, global traversal, MCP,
  Engram, private memory graphing, or answer generation.
- `naos sarif-export` exports structured NAOS findings for interoperability.
  Advisory findings require explicit inclusion and remain human-review input.
- Static policy overlays under `naos/policy_overrides.d/` cannot weaken
  `ADR-0010: Control-Plane Advisory Boundaries` or turn advisory findings into
  authority.

NAOS reports are repository-local evidence surfaces. Someone with repository
write access can still edit reports, reviewer metadata, claims, manifests, or
local evidence unless the adopter adds external controls such as protected
branches, signed commits, independent archival, or notarization.

NAOS is for developers, technical leads, platform teams, and reviewers who want
AI-assisted delivery to leave inspectable evidence. It supports governance
evidence and review; it does not prove legal or regulatory compliance,
guarantee secure code, prove runtime safety, or prove complete test coverage.

---

## Quick Start

Portable preview generation is exercised on Linux with Python 3.11. Managed
`--activate` mutation is currently supported only on Darwin ARM64 with CPython
3.11–3.13; Linux, Windows, and other unsupported tuples refuse before target
mutation. On an unsupported host, use an absent `--preview-dir` to inspect the
complete install set and activate later on a supported host.

### Option A: pip install (recommended)

```bash
pip install naos-governance
naos-governance init /path/to/your/project --tier quickstart --activate

# Install pre-commit hook
cd /path/to/your/project
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks

# Done. Starter scaffold installed. 5 rules. The hook enforces its documented
# file/path checks; Rule 10 has blocking posture but no licence scanner is installed.
```

First-run evidence route after install:

```bash
python -m naos_governance.cli doctor
naos-governance first-run --profile quickstart --mode greenfield
```

If `naos-governance` is missing but `python -m naos_governance.cli doctor`
reports the package is importable, reinstall NAOS in the active Python
environment. If bare `naos` opens another tool or prints non-NAOS help, treat
that as a local command collision and use `naos-governance ...` or
`python -m naos_governance.cli ...` until PATH is fixed.
`--no-write-preview` evaluates adoption without writing reports or activation
files. Dry-run adoption writes declared NAOS review reports but makes no
protected-file or activation changes. Full scaffold activation with
`naos-governance init --activate` is a separate, provenance-bound create-only
transaction; any unproven existing destination refuses the whole activation.

One explicit greenfield preview → install-set review → activation → adoption
route is:

```bash
PROJECT=/path/to/new-project
PREVIEW=/tmp/naos-new-project-preview
naos-governance init "$PROJECT" --new --tier quickstart --preview-dir "$PREVIEW"
# Review $PREVIEW, including naos/profile_generated_surface_contract.json.
naos-governance init "$PROJECT" --new --tier quickstart --activate
cd "$PROJECT"
naos adopt . --mode greenfield --profile quickstart --no-write-preview
```

The middle command writes only the generated install preview. Its destination
must be absent. Inside the target, only direct `TARGET/.naos-preview` is
supported; other persistent preview paths must be outside the target. `naos
init` never deletes or replaces a pre-existing preview
without provenance. Use `naos init --dry-run` without `--preview-dir` for a
target-preserving evaluation through a temporary external preview that is
removed on exit. The final command regenerates from the current kit and
arguments in separate external temporary staging, performs one durable
create-only transaction, and leaves the persistent review preview unchanged.
It does not claim digest-bound identity with that earlier preview.
Existing-repository activation first requires a validated-current
repository-intelligence generation, or an executed not-applicable result. If a
host test recursively consumes its own `scripts/` Python collection, the
generated preview is deterministically remapped to `naos_tools/` before the
transaction digest is frozen. If bounded host automation literally runs
`ruff check .` or `ruff format ... .`, NAOS also places managed nested
`.ruff.toml` discovery markers only in generated roots proved to contain no
pre-existing adopter Python. The marker under `naos_tools/` is kit-owned; the
marker under `.github/autoresearch/` follows that generated seed's create-once
adopter ownership. No pre-existing adopter Ruff file is modified. A mixed
host/generated Python root, `--config`, or `--isolated` posture refuses
activation because nested discovery cannot safely preserve that boundary.
Later manual Python placed inside a reserved excluded root is not covered by
the adopter's repository-root Ruff scan. Aliases, wrappers, explicit
generated-file arguments, and non-Ruff lint engines remain review-required.
All detected collection and lint findings are recorded in
`naos/overlay_compatibility.json`.

`first-run` performs doctor, adoption dry-run, setup recommendations,
profile-baseline setup-module dry-run, evidence pack, and dashboard generation.
Review the dry-run adoption report and setup recommendations before enabling
modules. Apply selected setup modules one at a time after a dry run. These
commands produce review evidence; they do not approve maturity, prove runtime
safety, certify outcomes, prove compliance, or guarantee secure code.

Optional control-plane smoke checks after install:

| Purpose | Commands |
| --- | --- |
| Setup posture | `naos-governance setup-recommendations --profile quickstart`, `naos self-check --profile quickstart` |
| Evidence and dashboard | `naos claims --profile quickstart`, `naos evidence-pack --profile quickstart`, `naos dashboard --profile quickstart --json-output naos/reports/dashboard_summary.json` |
| Review handoff | `naos behavioral-readiness --profile quickstart`, `naos ai-code-provenance --profile quickstart`, `naos compliance-posture --profile quickstart` |
| Hygiene checks | `naos duplicate-function-hygiene --profile quickstart`, `naos secret-hygiene --profile quickstart`, `naos test-quality-hygiene --profile quickstart`, `naos dependency-integrity --profile quickstart`, `naos package-reality --profile quickstart`, `naos api-symbol-reality --profile quickstart` |
| Optional context aids | `naos task-context --task T-001 --profile quickstart`, `naos context-index --profile quickstart`, `naos context-query --query "governance" --profile quickstart` |

Use `naos commands` or [NAOS_CATALOG.md](NAOS_CATALOG.md) for the full command
inventory.

In the kit repository itself, these commands do not create a root generated-project `naos/` directory by default. Use explicit `--output` / `--json-output` paths for source-repo checks.

For Lite, Standard, and Assured workflows, NAOS recommends Engram memory for
cross-session recovery and cognitive checkpoints. If Engram is already installed,
connect to that setup first:

```bash
naos memory check
```

Recommended new setup uses Engram's provider-managed user data directory
(`ENGRAM_DATA_DIR`, or `~/.engram` by default). The database path is derived as
`<data-dir>/engram.db`; NAOS does not configure replication or Git memory sync.
An `~/engram-memories` checkout, where present, is an optional management
toolkit—not the live store:

```bash
naos memory explain
naos memory setup --disposition configure-local --write
```

If you skip memory, NAOS still works in degraded mode using task cards, compact
files, git state, repo governance files, and deterministic reports.

### Memory, Learning, And Adapter Checks

| Review question | Command | Boundary |
| --- | --- | --- |
| Is memory configured and safe to reference? | `naos memory-readiness`, `naos memory-access`, `naos memory-use-policy` | Unreviewed memory is advisory only. Recall traces are usage records, not proof. Audit events are records, not approval. |
| Can a lesson become active guidance? | `naos learning-loop-review` | Candidate learning is proposal-only until evidence, scope, review, approval, retrieval policy, and expiry metadata exist. |
| Did adapter guidance drift? | `naos adapter-coherence` | Repo-versioned plugin sources are source authority; installed caches and marketplace copies are not. The report flags stale guidance but does not auto-sync content. |

Architecture diagrams:

- [Plugin adapter architecture](docs/diagrams/naos-plugin-adapter-architecture.mmd)
- [Governed learning lifecycle](docs/diagrams/governed-learning-lifecycle-architecture.mmd)

### Option B: git clone

```bash
git clone https://github.com/mfraile/naos-governance
cd naos-governance
python -m pip install -r requirements.txt
python naos_init.py /path/to/your/project --tier quickstart --activate
```

**Need a different purpose-fit profile for a genuinely new destination?**
Select it explicitly; profiles are not a compulsory maturity ladder:

```bash
naos-governance init /path/to/new-project --new --tier lite --archetype custom --backend static_only --activate
naos-governance init /path/to/new-project --new --tier standard --archetype custom --backend static_only --activate
naos-governance init /path/to/new-project --new --tier assured --archetype custom --backend static_only --activate
```

For an existing repository without NAOS, run the repository-intelligence
lifecycle above, preview the initial scaffold, then use the separate managed
create-only `naos init --activate` route. For an already managed project,
`naos upgrade /path/to/project --tier <tier>` and `--dry-run` both produce the
same no-target-write content-aware plan. Persist an exact plan with
`--plan-out /external/absent-plan.json`, then apply only that file in a separate
invocation with `--apply-plan` and `--expect-plan-digest`. Use `--recover` after
an interrupted managed transaction. Legacy `--force` replacement remains
permanently refused.

---

## The 4 Governance Profiles

| Profile | Rules | Blocking posture | Purpose |
| --------- | ------: | :----------------: | --------- |
| **quickstart** | 5 | 3 | Bounded evaluation and minimal guardrails |
| **lite** | 9 | 3 | Reduced-governance real-project workflow |
| **standard** | 19 | 13 | Broader SDLC evidence and team workflow |
| **assured** | 19 | 19 | Strongest configured evidence and reviewer handoff |

These profile-summary counts mirror the explicit BLOCKING rows in the canonical
`.ai/RULES.md` presentation. They are not counts of executable pre-commit checks,
policy gate severity, or exit-code sets. The exact shipped RULES documents are derived from
`configs/profile_rules_source.yaml`; policy remains authoritative only for gate
severity, exit codes, and enforcement transition. Adopter-local RULES may be
adapted after initialization and are outside the kit byte-parity check. The
generated hook contains no licence scanner, and initialization does not install
the optional `license-scan.yml` workflow.

Profiles control purpose and enforcement posture, not instant maturity or a
required progression. Quickstart is advisory and low-friction; Lite emphasizes
warnings; Standard expects broader SDLC evidence; Assured can block where
configured and evidence-backed. Experimental Tier 3 tracks remain
scaffolded/advisory unless a project explicitly changes policy and provides
readiness evidence. Setup and maintenance effort are repository-specific; NAOS
makes no default time-saving, cost-saving, or return-on-investment claim.

Enforcement follows a **graduated exit-code ramp** that increases across profiles (`quickstart` blocks nothing → `lite` fails on blocking findings → `standard` adds required → `assured` adds warnings). It ships in a **`warn`-by-default transition** (`enforcement_transition: warn` in policy): the ramp records what *would* block without changing exit codes, so adopters are not unexpectedly blocked by policy updates. Set `enforcement_transition: enforce` to apply it. Enforcement is further gated by capability maturity — a capability only enforces at its profile severity once it reaches its target maturity (below target it stays advisory, "never block a scaffold"). This is review/enforcement posture, not approval, certification, or proof of compliance.

```bash
# Choose your profile
naos-governance init . --tier lite --archetype custom --backend static_only        # minimal friction
naos-governance init . --tier standard --archetype custom --backend static_only    # recommended for most teams
naos-governance init . --tier assured --archetype custom --backend static_only     # enterprise/regulated
```

---

## Capability Snapshot

NAOS should be evaluated against its own implemented evidence surfaces, not
against claims about other tools.

| Capability area | Current NAOS posture |
| --- | --- |
| Static instruction surfaces | Generated prompts, agents, skills, and instructions with deterministic metadata checks where profile policy enables them. |
| Pre-commit enforcement | Profile-scoped hook sections that can block configured governance violations before commit. |
| Duplicate-intent review | Function-index-first review plus optional project-configured similarity evidence. |
| Behavioral governance readiness | Deterministic readiness and impacter review only; runtime behavioral evaluation remains adopter-owned and separately approved. |
| Requirements traceability | Machine-checkable requirement, task, source, and test evidence where the adopter maintains those artifacts. |
| Governance rule lifecycle | Versioned, human-reviewed promotion and remediation model for governed rules and learning. |
| Evidence metrics | Validator reports, gate status, dashboard summaries, evidence packs, and bounded truth checks. |
| Spec alignment | Profile-scoped checks for spec-pack contract structure, orphaned tasks, module headers, source traceability, and configured spec-cascade evidence. |

Deterministic conformance also validates the metadata contract for generated agents,
skills, and instructions. Standard and assured projects can emit the current
AI tool-surface inventory to `configs/naos_ai_surface_catalogue.yaml`; see
[docs/FRONTMATTER_CONFORMANCE.md](docs/FRONTMATTER_CONFORMANCE.md) for the
required `model`, `tools`, `parameters`, and `applyTo` fields.

Generated projects also include a **task-capability matrix** in `CLAUDE.md` and
`.github/copilot-instructions.md`. Use it after choosing a repo-level profile:
it maps task archetypes such as greenfield scaffolding, bounded refactors,
reproducible bugfixes, spec archaeology, and long-horizon debugging to the
recommended NAOS profile, PAUL bracket, and preferred skills or agents.

Gate 10c also detects **test hallucinations** by checking that tests cite real
acceptance-criteria or scenario ids from specs; see
[Micro Tutorial 30](docs/tutorials/MICRO_TUTORIAL_30_TEST_HALLUCINATION.md).

For regulated or audit-facing teams, NAOS now ships public evidence maps for
[OSFI E-23](docs/OSFI_E23_MAPPING.md) and [DORA](docs/DORA_MAPPING.md), plus an
[admissibility](docs/ADMISSIBILITY.md) guide that explains which NAOS artefacts
can be handed to reviewers and which legal, operational, runtime, and
third-party-risk responsibilities remain outside the kit.

### Evidence And Dashboard Outputs

| Surface | Output | Boundary |
| --- | --- | --- |
| Dashboard | `NAOS_ROOT/DASHBOARD.md`, `NAOS_ROOT/reports/dashboard_summary.json` | Shows current evidence posture, stale artifacts, waivers, and missing reports without turning them into green/pass signals. |
| Evidence pack | `NAOS_ROOT/evidence/evidence_pack.json` | Packages local evidence references for review; it is not approval or publication authority. |
| AI-surface budget | `NAOS_ROOT/reports/ai_surface_context_budget.json` | Reviews static AI/governance instruction context health; it does not prevent hallucinations, grade behavior, auto-tune thresholds, or approve baselines. |
| Declared AI component inventory | `NAOS_ROOT/reports/ai_component_inventory.json` | Records declared AI authoring/model/tool facts and content-digest freshness for G2/G6 routing; it is not a standards BOM or runtime discovery. |
| Agent sponsor registry | `NAOS_ROOT/reports/agent_sponsor_registry.json` | Records sanitized opt-in build-time sponsor/ownership/review-expiry/credential-posture completeness for G2/G6 routing; opaque refs are digested and are not identity or credential proof. |
| AIVSS arithmetic verification | `NAOS_ROOT/reports/aivss_arithmetic_verification.json` | Recalculates opt-in assessor-supplied AIVSS-Agentic v0.8 values from the pinned publication and supplies advisory G2/G6 review input; it is not a risk assessment, CVSS validation, security assurance, or decision authority. |
| Learning loop review | `NAOS_ROOT/reports/learning_loop_review.json` | Reviews governed-learning posture; it does not write memory, auto-promote lessons, or mutate AI surfaces. |
| Adapter coherence | `NAOS_ROOT/reports/adapter_coherence.json` | Reviews source/target adapter guidance; it does not prove live plugin installation, mutate caches or settings, activate hooks, call MCP, or repair drift automatically. |

Similarity or semantic evidence is an optional project-configured semantic layer. Core NAOS does not require MPNet, MiniLM, `sentence-transformers`, embeddings, GPU, or any semantic model by default. A project may explicitly enable a local provider such as `sentence-transformers/all-mpnet-base-v2` on CPU, but that remains non-core and evidence-backed.

Public NAOS positioning should be checked against its own source, validators,
reports, and documented non-claims.

---

## Measurement Posture

> **NAOS treats governance as something a repository can measure.**
> Deterministic conformance, traceability, governance truth checks, and bounded
> evidence reports are first-class outputs. Behavioral Governance Readiness is
> shipped as deterministic baseline-readiness and impacter review; behavioral
> evaluators remain future/project-configured unless an adopter separately
> implements and approves one.

The public kit intentionally does not publish private reference-codebase benchmark tables without a public formula, source path, commit/date, measurement method, scope, and limitation statement. Public NAOS ships the machinery for each adopter to generate its own evidence: first adapt specs and task governance, then run deterministic conformance and validators, then treat any provider-backed behavioral baseline as future/project-configured work outside the default kit. Public NAOS never ships API keys; any local/API/IDE-agent provider is user-supplied configuration.

---

## Supported Archetypes

The scaffolder auto-detects your stack. Pre-populated templates exist for:

| Archetype | Stack | Profile Default |
| ----------- | ------- | ---------------- |
| `django-postgresql` | Python / Django / PostgreSQL | standard |
| `nextjs-supabase` | TypeScript / Next.js / Supabase | standard |
| `go-grpc` | Go / gRPC / Kafka / sqlc | standard |
| `springboot-kafka` | Java / Spring Boot / Kafka / Flyway | assured |
| `fastapi-generic` | Python / FastAPI (any DB) | lite |

---

## What Gets Generated

Generated files vary by profile and by the selected setup options. The list
below is a tested orientation to core Standard-profile surfaces, not a complete
manifest. The generated preview directory is the exact inventory for a run;
the CLI also reports the total and the first 20 paths.

<!-- generated-core-inventory:start -->

```text
.ai/
  RULES.md              — Governance rules (profile-specific: 5, 9, or 19 active rows)
  config.yml            — Declarative tool/posture map; not an auto-load consumer

.github/
  copilot-instructions.md  — Copilot-oriented portable instruction surface; host loading must be verified
  project-context.md       — YOUR project details (fill this in)

.cursor/rules/
  naos-coding-standards.mdc
  naos-project-governance.mdc
  naos-security-standards.mdc

.githooks/
  pre-commit            — Best-effort registry sync + checks (explicit activation required)

CLAUDE.md               — Claude Code context file
CONTRIBUTING.md         — Contribution guide template
QUICK_START.md          — Setup guide template
Makefile.naos           — Governance make targets (include in your Makefile)

configs/
  naos_ai_precommit.yaml         — AI review policy config (disabled/static/local/API/IDE)
  naos_architecture_boundaries.yaml  — Module boundary rules
  naos_autoresearch.yaml         — deterministic conformance and future readiness schedules
  naos_duplicate_allowlist.yaml  — Duplication exemptions
  naos_semantic_allowlist.yaml   — Semantic audit exemptions

naos/active/_TEMPLATE.md  — Story card template
naos/evidence/_TEMPLATE/  — Evidence-pack seed templates
docs/DOCS_INDEX.md        — Documentation catalog
docs/DEPRECATION_LIST.md  — Deprecation tracking
```

<!-- generated-core-inventory:end -->

---

## Architecture

NAOS uses a 3-tier instinct model:

```text
Tier 1: Project-level (.github/instincts/)
  — Project-specific rules and patterns
  — Highest priority

Tier 2: Developer-level (user-centralized memory)
  — Cross-project personal preferences
  — Prefer local-first Engram data under ENGRAM_DATA_DIR (default ~/.engram)
  — Replication remains local/off unless separately reviewed and authorized

Tier 3: Universal (this kit — mfraile/naos-governance)
  — Portable base rules
  — Host/runtime behavior must be configured and verified in each client
```

### How AI Tools Load Context

| Tool | Config File | Auto-Load? |
| ------ | ------------- | ----------- |
| Claude Code | `CLAUDE.md` | Host-dependent; verify active-client behavior |
| GitHub Copilot | `.github/copilot-instructions.md` | Host-dependent; verify active-client behavior |
| Cursor | `.cursor/rules/*.mdc` | Host-dependent; verify active-client behavior |
| Continue.dev | `.ai/config.yml` | Host-dependent; configure and verify explicitly |
| All tools | `.ai/RULES.md` (when referenced) | Not automatic by itself |

---

## Conformance And Evaluation Battery

NAOS includes a 49-scenario battery used by Deterministic Conformance Review today and by behavioral governance readiness paths. Deterministic conformance verifies file structure, scenario references, and metadata shape without calling an LLM. Scenario files are metadata unless a behavioral evaluator is separately designed, configured, approved, and run by the adopter.

The source repository also keeps a separate internal 23-case deterministic
adversarial hygiene regression. Its versioned maintainer policy is consumed by
the existing pull-request and `main`-push unit suite and
fails closed on scenario drift, false negatives, false positives, runner/schema
errors, or a changed known-gap set. This is maintainer CI evidence only—not an
adopter behavioral evaluator, model/provider run, broad red-team assurance,
risk acceptance, approval, release, or publication authority.

| Dim | Measures | Scenarios |
| ----- | --------- | :---------: |
| 1 | Rule compliance rate | 8 |
| 2 | Agent instruction following | 8 |
| 3 | Scoped instruction adherence | 7 |
| 4 | Prompt template quality | 3 |
| 5 | Efficiency (context, memory) | 8 |
| 6 | Portability (cross-project) | 5 |
| 7 | Session & governance hygiene | 6 |
| 8 | AI output quality | 4 |

```bash
# Run deterministic conformance review from the kit source tree (no LLM, no API key)
python -m autoresearch.runner --conformance \
  --battery task_battery/portable_scenarios.yaml
```

---

## Maintenance

See [MAINTENANCE_PLAYBOOK.md](MAINTENANCE_PLAYBOOK.md) for the 6 maintenance cadences:

1. **On-demand Deterministic Conformance Review** — `python -m autoresearch.runner --conformance` in the kit source tree, or `make -f Makefile.naos naos-conformance` in a generated adopter project
2. **Behavioral evaluator cadence** — deferred/project-configured; the internal deterministic adversarial CI regression does not create an adopter behavioral evaluator or behavioral drift operation
3. **Quarterly review readiness** — planned review posture for the scenario battery, not default behavioral scoring
4. **Dependency audit** — After major pip/npm version bumps
5. **Toolchain upgrade** — After AI assistant major versions
6. **AI quality review** — deterministic conformance + project-configured eval pass rates where they exist

---

## CI Integration

GitHub Actions example:

```yaml
# .github/workflows/naos-gov.yml
on:
  schedule:
    - cron: "0 9 1-7 * 1"    # 1st Monday of each month
  push:
    paths: ["naos/TASK_REGISTRY.yaml"]

jobs:
  gov-refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt
      - run: make -f Makefile.naos gov-full
```

See [MAINTENANCE_PLAYBOOK.md](MAINTENANCE_PLAYBOOK.md) for GitLab CI and generic shell examples.

---

## Roadmap

The roadmap lives in [`ROADMAP.md`](ROADMAP.md). It describes public direction, near-term themes, longer-term constraints, and explicit non-goals. Detailed maintainer planning and research synthesis remain internal until a public-safe summary is approved. Release-level changes are tracked via git tags and GitHub Releases.

---

## Who Is This For?

### Solo Developer Quick Start

If you're a solo dev adding AI governance for the first time:

```bash
# Choose lite when you want a reduced real-project workflow
naos-governance init . --tier lite --archetype custom --backend static_only --activate

# What you get immediately:
# - RULES.md with 9 rules (host loading must be configured and verified)
# - Pre-commit hook with core hygiene checks (inspect the hook for exact behavior)
# - Story card template + TASK_REGISTRY seed
# - Governance Makefile targets (make -f Makefile.naos gov-refresh, make -f Makefile.naos gov-full)
```

Setup and per-change overhead depend on repository size, enabled controls, and
local tooling. Measure them in the adopter repository when they matter to a
decision; NAOS does not publish a universal effort or ROI value.

### Team Setup

For teams (2–10 devs) adopting governance together:

```bash
# Recommended: standard tier
naos-governance init . --tier standard --archetype custom --backend static_only --activate

# Additional steps for teams:
# 1. Fill in .github/project-context.md with your stack info
# 2. Review naos/TASK_REGISTRY.yaml conventions with the team
# 3. Set up branch protection requiring pre-commit on all PRs
# 4. Schedule monthly gov-refresh: make -f Makefile.naos gov-refresh
```

Measure setup and ongoing overhead in the adopter repository if those values
matter to a decision; the kit does not publish a universal effort or ROI value.

> For enterprise/regulated projects, see the `--tier assured` profile and
> [INSTALLATION_MANUAL.md](INSTALLATION_MANUAL.md) for sign-off workflows.

---

## Philosophy

### Why NAOS?

NAOS keeps its scope deliberately narrow:

- **Repository-measured hooks** whose runtime depends on repository size and enabled controls, and that block configured violations at commit time
- **Measurable governance evidence** — deterministic checks, validators, dashboard summaries, behavioral readiness/impacter review, and future project-configured evaluator paths show what evidence exists and what is missing
- **Profile tiers** so you can start minimal and scale up
- **Portable templates** intended for project-specific adaptation and validation

### Design Decisions

| Decision | Rationale |
| ---------- | ----------- |
| RULES.md over separate governance docs | One generated rule source can be referenced by tool-specific context; loading remains host-dependent. |
| Pre-commit as universal baseline | IDE-neutral after explicit activation; CI requires an explicitly configured equivalent invocation. |
| Claude Code hooks as enhancement | Optional — the baseline works without them |
| Tiered profiles | One-size enforcement doesn't fit solo dev AND enterprise |
| `NAOS_ROOT` env var | Supported commands use a configurable project-management root; verify support for the command being run |

---

## Strategic documents

These public documents define where the kit is going, how architecture decisions are bounded, and how adopters should run review evidence without overclaiming it.

| Document | Role |
| --- | --- |
| [`ROADMAP.md`](ROADMAP.md) | *Where the kit is going.* Public direction, themes, longer-term constraints, and explicit non-goals. |
| [`docs/decisions/README.md`](docs/decisions/README.md) | *Why the kit made public load-bearing architecture choices.* Sanitized public ADR index. |
| [`docs/AUDIT_PLAYBOOK.md`](docs/AUDIT_PLAYBOOK.md) | *How adopters run deterministic checks and package review evidence.* |
| [`docs/NAOS_THREAT_MODEL.md`](docs/NAOS_THREAT_MODEL.md) | *Which SDLC evidence risks, trust boundaries, and residual risks the kit recognizes.* |
| [`docs/ASSURED_PROFILE_ACTIVATION.md`](docs/ASSURED_PROFILE_ACTIVATION.md) | *How to activate the strictest profile without treating it as certification or approval.* |
| [`docs/BEHAVIORAL_AUDIT_ENABLEMENT.md`](docs/BEHAVIORAL_AUDIT_ENABLEMENT.md) | *How advisory and behavioral-readiness surfaces stay bounded by deterministic evidence and human review.* |
| [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md) | *Which artefacts may support which framework-control discussions.* Includes bounded EU AI Act / NIST RMF / ISO 42001 / AIUC-1 material and links to current source-qualified OSFI E-23, DORA, and jurisdictional mappings; none is a compliance determination. |
| [`docs/decisions/ADR-0010-control-plane-advisory-boundaries.md`](docs/decisions/ADR-0010-control-plane-advisory-boundaries.md) | *How deterministic controls, advisory controls, residual risk, and human decisions interact.* |
| [`docs/decisions/ADR-0011-deterministic-hygiene-controls.md`](docs/decisions/ADR-0011-deterministic-hygiene-controls.md) | *How static hygiene controls stay useful review inputs without becoming safety or compliance overclaims.* |

Private strategy notes, internal audit methodology, and unpublished release verification material remain outside the public kit unless separately sanitized and indexed.

For everything else, [`docs/INDEX.md`](docs/INDEX.md) is the navigation surface.

If you are evaluating NAOS for a regulated context, start with [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md), [`docs/AUDIT_PLAYBOOK.md`](docs/AUDIT_PLAYBOOK.md), [`docs/ASSURED_PROFILE_ACTIVATION.md`](docs/ASSURED_PROFILE_ACTIVATION.md), and [`SECURITY.md`](SECURITY.md). Public reports are review evidence, not approvals, certification, legal advice, or proof of compliance.

---

## Professional Adoption Engine

NAOS includes a file-first professional adoption engine that connects preflight, guided intake, inventories, install planning, challenge reports, brownfield baselines, candidate requirements, traceability gaps, and an install/adoption decision record.

NAOS also includes deterministic hygiene controls for duplicate function bodies, obvious secret-like local findings, weak assertion evidence, undeclared/unresolved Python imports, package reality, explicitly declared Python API symbols, and PR diff risk surfaces. `naos package-reality` writes `naos/reports/package_reality.json` from local manifests, lock-style pins, optional docs install snippets, configured local CycloneDX SBOM/provenance/hash evidence, and explicit opt-in registry metadata checks. `naos api-symbol-reality` writes `naos/reports/api_symbol_reality.json` from explicit manifest entries and local Python source inspection without importing target modules. `naos pr-risk-classify` writes `naos/reports/pr_risk_classification.json` for protected paths, workflow/dependency changes, AI instruction surfaces, prompt-injection-like text, and secret-like added lines. These checks are local review evidence only; they do not prove semantic correctness, secret-free code, behavioral correctness, API behavior, package safety, vulnerability absence, SBOM completeness, provenance authenticity, supply-chain assurance, PR approval, security, certification, compliance, or runtime safety.

Common commands:

```bash
naos repository-intelligence plan . --profile standard --component-mode baseline --output /tmp/naos-ri-enrollment.json
# Review the plan, then use its exact plan_sha256 for enroll.
naos repository-intelligence enroll . --profile standard --plan /tmp/naos-ri-enrollment.json --confirm-plan-sha256 PLAN_SHA256 --reviewer-id REVIEWER
naos repository-intelligence plan . --profile standard --component-mode baseline --output /tmp/naos-ri-activation.json
naos repository-intelligence apply . --profile standard --plan /tmp/naos-ri-activation.json --confirm-plan-sha256 PLAN_SHA256 --reviewer-id REVIEWER
naos repository-intelligence validate . --profile standard
naos-governance init . --tier standard --archetype custom --backend static_only --activate
naos preflight . --profile standard
naos intake . --answers naos/intake_answers.yaml --profile standard
naos existing-resource-inventory . --profile standard
naos ai-artifact-inventory . --profile standard
naos memory-resource-inventory . --profile standard
naos mcp-resource-inventory . --profile standard
naos install-plan . --profile standard
naos context-challenge . --challenge-mode install --profile standard
naos plan-challenge . --challenge-mode implementation-plan --profile standard
naos decision-probe . --challenge-mode decision --profile standard
naos planning-gate-review . --challenge-mode gate --profile standard
naos adopt . --mode brownfield --profile standard --no-prompt
```

`mcp-resource-inventory` performs static, metadata-only descriptor review. The
shipped policy recognizes only the exact repo-local VS Code workspace subset
of the remote Figma declaration recorded in
`naos/memory_mcp_inventory_rules.yaml`; endpoint, transport,
field-set, config-shape, or policy-digest drift requires review. The result
`allowlisted_pending_activation` is a risk-owner policy match, not proof of
Figma identity or behavior and not permission to authenticate, invoke tools,
or use Figma's write-capable operations. Other clients, the local desktop
endpoint, and all unknown declarations remain review-required by default.

The repository-intelligence baseline requires a host SQLite build with FTS5;
activation and query fail closed when that prerequisite is unavailable.
NetworkX/GraphML is an optional, separately selected component only when the
executed relationship model is eligible. `sqlite-vec`, embeddings, and provider
calls remain disabled without a defined workload. The operational
repository-intelligence runtime and its schemas stay in the installed NAOS
package or kit checkout; default project scaffolds do not duplicate those 22
files, while the immutable generation itself remains project-local under
`.naos/upgrade-v1/state/repository-intelligence/`. The adoption engine
writes deterministic reports under `naos/reports/`; those reports identify
candidate requirements and gaps but do not activate the scaffold or fill
project-specific specifications. Human review must accept, reject, or edit
those candidates before filled-spec and traceability claims are made.

---

## Contributing

For contributing to **the NAOS kit itself**, see [`CONTRIBUTING.md`](CONTRIBUTING.md) at the kit root. For the contribution guide that ships *into adopter projects* via `naos init`, see [`templates/structural-seeds/CONTRIBUTING.md`](templates/structural-seeds/CONTRIBUTING.md) — different file, different audience.

Issues, PRs, and rule contributions welcome at [github.com/mfraile/naos-governance](https://github.com/mfraile/naos-governance).

---

## Research Foundation

The NAOS methodology is grounded in three research threads:

1. **Repository-continuity metaphor** — AI coding assistants can lose track of what a repository already contains. The function index, rule posture, selected checks, and memory checkpoints provide a practical continuity layer. This is a metaphor for repository navigation and evidence continuity, not neuroscience validation.

2. **Three-Layer Defense** — Rules (documented posture) -> activated pre-commit hook (implemented predicates only) -> deterministic evidence and human review. Behavioral readiness/impacter review is deterministic; future behavioral evaluators remain project-configured.

3. **Continuous Improvement Protocol** — NAOS favors repeatable local evidence,
   visible regressions, and versioned remediation over unreviewed claims.
   Runtime behavioral evaluation and public benchmark publication remain
   project-configured or separately approved work.
   > *"We'd rather be honestly imprecise than confidently unmeasured."*

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for attribution requirements.

The original kit copyright belongs to Marlon Fraile. Third-party contributors retain copyright in their own contributions and license them to the project under Apache License 2.0 through the standard Developer Certificate of Origin process; see [CONTRIBUTING.md](CONTRIBUTING.md).

**If you redistribute the kit** (publish a fork, embed it in a derivative governance kit, or include it in a wider distribution), the Apache License §4 already requires you to retain the LICENSE, NOTICE, copyright notices, and to mark any files you change. See NOTICE for the operational checklist.

**If you use NAOS to govern your own project** (the typical case — running `naos init` against your codebase), no license obligations attach to your project's code. As a social norm, please add a README attribution:

```markdown
Governance powered by [NAOS-Governance](https://github.com/mfraile/naos-governance) by Marlon Fraile
```

Or the badge:

```markdown
[![Governance: NAOS-Governance](https://img.shields.io/badge/governance-NAOS--Governance-blue)](https://github.com/mfraile/naos-governance)
```

Attribution creates a discovery network — every project using NAOS that links back helps the community grow.

---
