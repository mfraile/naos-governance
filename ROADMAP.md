---
status: public-directional
created: 2026-05-11
last_reviewed: 2026-08-27
scope: public-roadmap
temporal_role: directional-summary
current_truth_source: mfraile/naos-governance
truth_weight: current
refresh_cadence: after public releases and major roadmap decisions
companion_documents:
  - docs/COMPLIANCE_MAPPING.md
---

# NAOS Roadmap

This public roadmap describes the direction of NAOS — Native AI Orchestration for SDLC — without exposing maintainer-private planning detail, unpublished research notes, or tactical implementation sequencing.

NAOS is currently focused on one product promise: portable, file-first governance for AI-assisted software development. Changes on the v1.x line must preserve that model.

---

## Current Focus

NAOS v1.0.0 establishes the portable governance kit:

- Profile-based governance tiers from quickstart to assured.
- Machine-checkable project artefacts such as task registries, dashboards, traceability matrices, and conformance reports.
- Static conformance over the portable scenario battery.
- AI-assistant instructions, prompts, skills, and agents that can be copied into adopter projects.
- Documentation for installation, maintenance, public compliance mapping, and adoption use.

The current control-plane line adds capability contracts, centralized policy, profile-aware gatekeepers, standalone validators, JSON evidence-pack export, and dashboard summary output. These features make the existing NAOS workflow easier to evidence; they do not make every adopter project assured by default.

The next public work concentrates on proving portability, tightening evidence quality, and making the kit easier to adopt without changing the file-first architecture.

## Control-Plane Status By Layer

| Layer | Current status |
| --- | --- |
| Capability contracts, central policy, profile presets, G0-G8 gate manifest, standalone validators, module-header traceability validator, evidence-pack export, dashboard summary, CLI/Make wrappers | Implemented now in the file-first kit. |
| Structured control-plane review and research routing | Implemented through `naos control-plane-review`, `naos research-record`, schemas, profile policy, reports, tests, and generated command surfaces. These reports route review evidence; they do not prove complete coherence, behavior, or outcomes. |
| Spec 04 linkage | Implemented as configurable spec-cascade and control-plane review evidence; no universal semantic-correctness proof or fully automatic project-specific linkage is claimed. |
| Semantic/similarity support | Optional and project-configured. Core NAOS remains deterministic and does not require MPNet, MiniLM, `sentence-transformers`, embeddings, GPU, or a semantic model. |
| Tier 3 tracks such as runtime handoff, structured substrate, source-test graph, digital-twin evaluation, and model-backed behavioural evaluation | Future/project-configured and advisory unless separately approved. |
| Codex plugin adapter | Implemented as an optional repository-owned adapter over file-first NAOS artifacts; live installation and host behavior remain separately verifiable. |
| Gemini and OpenCode plugin adapters | Future and unimplemented; current generic repository files may be configured manually where a host supports them. |

## Near-Term Themes

### Compliance Evidence

Improve the public evidence surfaces that help adopters explain NAOS-governed work to internal reviewers, auditors, and regulated customers.

Expected direction:

- Maintain the published, source-qualified OSFI E-23 and DORA mappings and their reproducible claim/source matrix.
- Clearer public assurance guidance for what NAOS evidence proves and what it does not prove, including admissibility evidence-pack limits.
- Better packaging of current project evidence for review and handoff, including the generated `make -f Makefile.naos admissibility-pack` target for eligible projects.
- Machine-readable evidence posture through `NAOS_ROOT/evidence/evidence_pack.json` and `NAOS_ROOT/reports/dashboard_summary.json`.

### Control-Plane Maturity

Make capability maturity explicit across the kit while preserving file-first adoption.

Expected direction:

- Capability contracts remain portable and adopter-neutral.
- Profiles continue to control enforcement severity.
- Gatekeepers summarize evidence without hiding missing, stale, waived, or experimental states.
- Tier 3 tracks such as runtime handoff, structured substrate, source-test graph, and digital-twin evaluation remain scaffolded/advisory unless project policy and readiness evidence activate them.

### Capability Catalogue

Make the kit's agents, skills, instructions, and scenarios easier to inventory and validate as a coherent governance system.

Expected direction:

- A generated AI surface catalogue derived from current project frontmatter. The catalogue is emitted as `configs/naos_ai_surface_catalogue.yaml` and remains distinct from control-plane capability contracts in `capabilities/`.
- Static checks that keep agent, skill, and instruction metadata complete.
- A path toward richer capability cards when the lightweight catalogue has proven useful.

### Conformance And Anti-Hallucination

Strengthen deterministic checks and readiness review before adding heavier
behavioural evaluation.

Expected direction:

- Maintain bounded test-reference validation evidence in compliance and README surfaces without claiming exhaustive hallucination prevention.
- More complete conformance output for CI and audit workflows.
- Deterministic Behavioral Governance Readiness for first-baseline and
  maintenance review, without creating baselines or grading behavior.
- Continued preference for deterministic checks first, with LLM-assisted review only where it adds value.

### Adoption Ergonomics

Reduce friction for new projects and teams adopting NAOS.

Expected direction:

- Faster `naos init` onboarding.
- Clearer generated-project documentation.
- Better upgrade and profile-activation guidance.
- Structured intake for non-developer stakeholders before AI implementation, especially where statutory or regulatory requirements need business, data, architecture, evidence, and risk context.

### AI Tool Activation Surfaces

NAOS core controls are tool-neutral. Existing templates cover Claude/Claude Code, VS Code + GitHub Copilot, Cursor, Continue/generic `.ai`, generic agent surfaces, and an optional Codex plugin adapter. Host discovery and loading remain configuration-dependent. Future work may add other tool-specific surfaces only after source and demand are revalidated.

Gemini and OpenCode remain future activation surfaces. AI tools are optional activation surfaces; the existing Codex adapter is also an optional layer, not a hard dependency or proof of live host behavior.

### Deferred Follow-Ups

Future control-plane work may include:

- More complete project-specific Spec 04 semantic-link validation beyond the current configurable evidence and routing checks.
- Broader provider-backed semantic or pre-commit integration beyond the existing disabled-by-default function-index similarity hook.
- Semantic duplicate-intent review.
- Dedicated Gemini or OpenCode activation surfaces if project demand and current host evidence justify them.
- Final traceability audit against roadmap/trends sources and dogfood implementation patterns.

These are roadmap items, not current implementation commitments.

## Longer-Term Direction

Longer-term work may introduce more structured storage, richer graph-based
traceability, and model-backed behavioural evaluation, but only after the
portable v1.0.x model has enough evidence from real projects and a separate
runtime design is approved.

Any architecture pivot must preserve the core NAOS principle: governance artefacts should remain inspectable, reviewable, and usable without requiring a central hosted service.

## Kit-Enabled Capabilities

Some capabilities cannot be fully delivered by the kit alone because they depend on each adopter project's configuration, data, risk appetite, and credentials.

Examples include:

- Model-backed behavioural audit or scoring beyond deterministic conformance
  and readiness review.
- Assured-profile activation for regulated environments.
- Evidence bundles for external review, enabled by generated admissibility-pack tooling and populated by each adopter project.

For these, the kit provides enablement infrastructure and documentation; each adopter project provides the runtime context and evidence.

## Explicit Non-Goals

NAOS is not trying to become:

- A runtime governance daemon for deployed AI agents.
- A hosted compliance platform.
- A replacement for branch protection, CI policy, or human review.
- A graph-database-first platform that requires infrastructure before adoption.
- A financial-domain application template library.

The kit governs the SDLC layer. Runtime governance for deployed agents belongs in a separate runtime-control layer.

## How Decisions Get Made

Public compliance positioning lives in [docs/COMPLIANCE_MAPPING.md](docs/COMPLIANCE_MAPPING.md). The public repository also indexes sanitized decision records, the threat model, and the audit playbook through [docs/INDEX.md](docs/INDEX.md). Maintainer-only development records remain internal unless separately sanitized and indexed.

Detailed maintainer planning remains private until a public-safe summary is ready. Public roadmap updates should describe direction, constraints, and release-level commitments rather than private research notes or implementation recipes.
