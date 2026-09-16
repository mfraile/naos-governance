# Document Index

A single page listing every public kit-shipped document with one-line scope and the question it answers. If you are new to the kit, start with `README.md` and `START_HERE_NAOS_OVERVIEW_AND_LEARNING_PATH.md`. If you are evaluating NAOS for a regulated context, start with `docs/COMPLIANCE_MAPPING.md`.

This file is mechanically maintained — every documented file is listed here exactly once, and orphaned documents will be flagged by `scripts/validators/validate_project_coherence.py`.

## Public planning surface

These public documents define what NAOS commits to ship and what evidences each compliance control. Maintainer-private research, unpublished decision records, threat analysis, audit mechanics, and adopter details stay outside the public index until explicitly approved for publication.

| Document | Role | Answer to |
| --- | --- | --- |
| [`ROADMAP.md`](../ROADMAP.md) | Public roadmap | *Where is the kit going?* Directional themes, longer-term constraints, kit-enabled capabilities, and explicit non-goals. |
| [`docs/CONTROL_PLANE.md`](CONTROL_PLANE.md) | Control-plane overview | *How do capability contracts, policy, profiles, gates, validators, evidence packs, and dashboards fit together?* |
| [`docs/SECURE_CODING_CONTROL_MODEL.md`](SECURE_CODING_CONTROL_MODEL.md) | Secure/agentic coding control model | *How are coding-time controls authored, mapped, evaluated, rendered, and kept separate from enforcement authority?* |
| [`docs/SYSTEMIC_CAPABILITY_WIRING.md`](SYSTEMIC_CAPABILITY_WIRING.md) | Systemic wiring method | *How should features, capabilities, validators, AI surfaces, docs, and project configuration be wired without becoming orphan artifacts?* |
| [`docs/CLAIMS_AND_LIMITATIONS.md`](CLAIMS_AND_LIMITATIONS.md) | Claim-control policy | *What can NAOS safely claim, and which claims require project-local evidence or revalidation?* |
| [`docs/ADOPTION_GUIDE.md`](ADOPTION_GUIDE.md) | Adoption guide | *How should greenfield, brownfield, and non-developer intake flows activate NAOS progressively?* |
| [`docs/NAOS_THREAT_MODEL.md`](NAOS_THREAT_MODEL.md) | Public threat model | *What are the main SDLC evidence risks and trust boundaries for NAOS?* |
| [`docs/AUDIT_PLAYBOOK.md`](AUDIT_PLAYBOOK.md) | Public audit playbook | *How should adopters run deterministic NAOS checks and package review evidence without overclaiming approval?* |
| [`docs/ASSURED_PROFILE_ACTIVATION.md`](ASSURED_PROFILE_ACTIVATION.md) | Assured profile activation guide | *What must be configured before using `assured` seriously, and what does it still not prove?* |
| [`docs/BEHAVIORAL_AUDIT_ENABLEMENT.md`](BEHAVIORAL_AUDIT_ENABLEMENT.md) | Behavioral/advisory enablement guide | *How do StaticGrader, LLMGrader readiness, agentic workflow review, calibration shadow, evidence classification, and advisory findings stay bounded?* |
| [`docs/CROSS_HARNESS_REVIEW_READINESS.md`](CROSS_HARNESS_REVIEW_READINESS.md) | Cross-harness/DSSE readiness guide | *What must be declared before future independent review or signing designs are safe to consider?* |
| [`docs/COMPLIANCE_MAPPING.md`](COMPLIANCE_MAPPING.md) | Compliance lens | *Which NAOS artefacts may support framework-control discussions, and which responsibilities remain outside the kit?* |
| [`docs/OSFI_E23_MAPPING.md`](OSFI_E23_MAPPING.md) | OSFI E-23 evidence lens | *Where does NAOS evidence help a vendor-cascade or model-risk conversation, and where does the regulated principal remain accountable?* |
| [`docs/DORA_MAPPING.md`](DORA_MAPPING.md) | DORA evidence lens | *Where can NAOS SDLC evidence support DORA control discussions, and which operational resilience controls remain outside NAOS?* |
| [`docs/ADMISSIBILITY.md`](ADMISSIBILITY.md) | Evidence-pack definition | *Which NAOS artefacts are ready for reviewer handoff, and what do they not prove?* |
| [`docs/FRONTMATTER_CONFORMANCE.md`](FRONTMATTER_CONFORMANCE.md) | Static conformance reference | *Which agent, skill, and instruction frontmatter fields must generated projects declare?* |
| [`docs/ENGRAM_SETUP.md`](ENGRAM_SETUP.md) | Memory setup guide | *How do I configure local/private Engram memory, or safely defer it?* |
| [`docs/TOOL_NEUTRAL_USAGE.md`](TOOL_NEUTRAL_USAGE.md) | Optional integrations guide | *How do I use NAOS with common AI-assisted SDLC tools without making them core dependencies?* |
| [`docs/CODEX_PLUGIN_AND_MCP.md`](CODEX_PLUGIN_AND_MCP.md) | Plugin/MCP adapter guide | *How do repo-versioned Codex and Claude Code plugins coexist with project-local NAOS and future MCP adapters?* |

## Visual Aids And Deck Sources

These text sources are public documentation aids. They describe the current
local-first control plane and professional adoption workflow; they are not
additional runtime capabilities and do not change command semantics.

| Document | Scope |
| --- | --- |
| [`docs/diagrams/naos-scope-and-human-decision-boundary.mmd`](diagrams/naos-scope-and-human-decision-boundary.mmd) | Mermaid source for current NAOS scope, local review evidence, and human/project-owned decisions; no runtime, compliance, certification, or automatic decision authority |
| [`docs/diagrams/systemic-control-plane.mmd`](diagrams/systemic-control-plane.mmd) | Mermaid source for the command/config/report/evidence/control-plane relationship |
| [`docs/diagrams/governed-learning-lifecycle-architecture.mmd`](diagrams/governed-learning-lifecycle-architecture.mmd) | Mermaid source for governed learning records, deterministic review, gates, AI-surface budget, and reviewed action surfaces |
| [`docs/diagrams/naos-plugin-adapter-architecture.mmd`](diagrams/naos-plugin-adapter-architecture.mmd) | Mermaid source for NAOS core, Codex and Claude Code plugin sources, project-local integrations, adapter coherence, and governed propagation |
| [`docs/diagrams/professional-adoption-engine.mmd`](diagrams/professional-adoption-engine.mmd) | Mermaid source for greenfield and brownfield adoption flow |
| [`docs/diagrams/natural-language-router-sequence.mmd`](diagrams/natural-language-router-sequence.mmd) | Mermaid sequence for natural-language intent to explicit CLI/report/human decision |
| [`docs/diagrams/greenfield-adoption-sequence.mmd`](diagrams/greenfield-adoption-sequence.mmd) | Mermaid sequence for greenfield adoption evidence flow |
| [`docs/diagrams/brownfield-adoption-sequence.mmd`](diagrams/brownfield-adoption-sequence.mmd) | Mermaid sequence for brownfield adoption evidence flow |
| [`docs/diagrams/daily-task-sequence.mmd`](diagrams/daily-task-sequence.mmd) | Mermaid sequence for daily task lifecycle handoff |
| [`docs/diagrams/pr-evidence-sequence.mmd`](diagrams/pr-evidence-sequence.mmd) | Mermaid sequence for PR/release evidence review |
| [`docs/diagrams/governance-surface-change-sequence.mmd`](diagrams/governance-surface-change-sequence.mmd) | Mermaid sequence for systemic-impact/control-plane review |
| [`docs/diagrams/evidence-boundary-lifecycle.mmd`](diagrams/evidence-boundary-lifecycle.mmd) | Mermaid source for evidence, gate, dashboard, and human-review boundaries |
| [`docs/diagrams/deck-exec.md`](diagrams/deck-exec.md) | Short executive deck source |
| [`docs/diagrams/deck-auditor.md`](diagrams/deck-auditor.md) | Short auditor/reviewer deck source |
| [`docs/diagrams/deck-devlead.md`](diagrams/deck-devlead.md) | Short development-lead deck source |

## Public decision records

| Document | Role | Answer to |
| --- | --- | --- |
| [`docs/decisions/README.md`](decisions/README.md) | ADR index | *Which public architecture decision records are available?* |
| [`docs/decisions/ADR-0001-default-to-deterministic-workflows.md`](decisions/ADR-0001-default-to-deterministic-workflows.md) | Deterministic workflow default | *Why are deterministic workflows the baseline instead of model-driven agents?* |
| [`docs/decisions/ADR-0002-file-first-portable-architecture.md`](decisions/ADR-0002-file-first-portable-architecture.md) | File-first architecture | *Why does the core kit stay portable and repository-local?* |
| [`docs/decisions/ADR-0003-reject-neo4j-for-the-kit.md`](decisions/ADR-0003-reject-neo4j-for-the-kit.md) | Graph-server rejection | *Why does the kit not require Neo4j infrastructure?* |
| [`docs/decisions/ADR-0004-sqlite-sqlitevec-networkx-graphml-stack.md`](decisions/ADR-0004-sqlite-sqlitevec-networkx-graphml-stack.md) | Structured substrate posture | *How should SQLite, vector, and graph candidate layers stay bounded?* |
| [`docs/decisions/ADR-0005-never-auto-promote-instincts.md`](decisions/ADR-0005-never-auto-promote-instincts.md) | Instinct promotion boundary | *Why do observed patterns require human review before becoming rules?* |
| [`docs/decisions/ADR-0006-conformance-returns-null-for-behavioral-dimensions.md`](decisions/ADR-0006-conformance-returns-null-for-behavioral-dimensions.md) | Unavailable behavioral dimensions | *Why does NAOS return explicit missing/null states instead of invented scores?* |
| [`docs/decisions/ADR-0007-ai-policy-defaults-to-static-only.md`](decisions/ADR-0007-ai-policy-defaults-to-static-only.md) | Static-only AI policy default | *Why does the baseline call no model/provider APIs?* |
| [`docs/decisions/ADR-0008-advisory-capability-enablements-not-release-commitments.md`](decisions/ADR-0008-advisory-capability-enablements-not-release-commitments.md) | Enablement vs activation | *Why does a readiness artifact not mean a capability is operational?* |
| [`docs/decisions/ADR-0009-license-selection-apache-2.md`](decisions/ADR-0009-license-selection-apache-2.md) | Apache 2.0 license posture | *Why is the public core kit Apache License 2.0?* |
| [`docs/decisions/ADR-0010-control-plane-advisory-boundaries.md`](decisions/ADR-0010-control-plane-advisory-boundaries.md) | Advisory-control boundary | *How do deterministic controls, advisory controls, residual risk, and human decisions interact?* |
| [`docs/decisions/ADR-0011-deterministic-hygiene-controls.md`](decisions/ADR-0011-deterministic-hygiene-controls.md) | Deterministic hygiene controls | *How should static hygiene findings remain useful without becoming overclaims?* |
| [`docs/decisions/ADR-0012-secure-and-agentic-coding-control-register.md`](decisions/ADR-0012-secure-and-agentic-coding-control-register.md) | Secure/agentic coding control register | *How are coding-time control requirements centralized without becoming a second enforcement-policy authority?* |

## Reference & onboarding

| Document | Scope |
| --- | --- |
| [`README.md`](../README.md) | Product overview, profile selection, measurement posture, philosophy |
| [`INSTALLATION_MANUAL.md`](../INSTALLATION_MANUAL.md) | Full install walkthrough across IDEs and tiers |
| [`docs/CONTRACT_REVALIDATION.md`](CONTRACT_REVALIDATION.md) | Task identity, commit snapshots, evidence validation, repeatable attestation, and existing-project migration |
| [`MAINTENANCE_PLAYBOOK.md`](../MAINTENANCE_PLAYBOOK.md) | Six maintenance cadences (on-demand conformance, monthly drift, quarterly assessment, dependency audit, toolchain upgrade, AI quality review) |
| [`NAOS_CATALOG.md`](../NAOS_CATALOG.md) | Lifecycle catalog: 16 prompts, 7 agents, 25 skills, CLI commands |
| [`docs/CONTROL_PLANE.md`](CONTROL_PLANE.md) | Capability maturity, gatekeepers G0-G8, validator/evidence/dashboard flow, and AI tool activation-surface status |
| [`docs/ADOPTION_GUIDE.md`](ADOPTION_GUIDE.md) | Progressive adoption, greenfield/brownfield guidance, non-developer intake |
| [`docs/AUDIT_PLAYBOOK.md`](AUDIT_PLAYBOOK.md) | Deterministic audit runbook and reviewer-facing evidence packaging guidance |
| [`docs/ASSURED_PROFILE_ACTIVATION.md`](ASSURED_PROFILE_ACTIVATION.md) | Assured profile prerequisites, team/operator interaction, CI posture, and human review boundaries |
| [`docs/BEHAVIORAL_AUDIT_ENABLEMENT.md`](BEHAVIORAL_AUDIT_ENABLEMENT.md) | Behavioral/advisory readiness boundaries, calibration shadow, evidence classification, and deterministic review surfaces |
| [`docs/CROSS_HARNESS_REVIEW_READINESS.md`](CROSS_HARNESS_REVIEW_READINESS.md) | Readiness-only planning for future cross-harness review, DSSE-style boundaries, adopter-owned key custody, and human review |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | For people contributing to the NAOS kit itself (distinct from the adopter template under `templates/structural-seeds/`) |
| [`docs/GLOSSARY.md`](GLOSSARY.md) | NAOS-specific terms (PAUL bracket, ROM/RAM, instinct, trinity, cognitive checkpoint, admissibility, vendor cascade) |
| [`docs/ENGRAM_SETUP.md`](ENGRAM_SETUP.md) | Engram data-directory setup, optional toolkit integration, canonical project identity, and degraded recovery |
| [`docs/TOOL_NEUTRAL_USAGE.md`](TOOL_NEUTRAL_USAGE.md) | Tool-neutral CLI/Make/report usage and optional integration templates |

## Tutorials

| Path | Scope |
| --- | --- |
| [`docs/tutorials/START_HERE_NAOS_OVERVIEW_AND_LEARNING_PATH.md`](tutorials/START_HERE_NAOS_OVERVIEW_AND_LEARNING_PATH.md) | Entry point for new readers |
| [`docs/tutorials/IS_NAOS_RIGHT_FOR_MY_PROJECT.md`](tutorials/IS_NAOS_RIGHT_FOR_MY_PROJECT.md) | Decision tree: should you adopt? |
| [`docs/tutorials/WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md`](tutorials/WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md) | Quickstart vs Lite vs Standard vs Assured |
| [`docs/tutorials/PROFESSIONAL_ADOPTION_ENGINE.md`](tutorials/PROFESSIONAL_ADOPTION_ENGINE.md) | Connected preflight, intake, inventory, challenge, baseline, and decision-record workflow |
| [`docs/tutorials/INTEGRAL_TUTORIAL_*.md`](tutorials/) | End-to-end profile walkthroughs plus a read-only transition preview |
| [`docs/tutorials/MICRO_TUTORIAL_*.md`](tutorials/) | Task-specific (~30 min each) walkthroughs of the lifecycle prompts |

## Governance & risk

| Document | Scope |
| --- | --- |
| [`docs/COMPLIANCE_MAPPING.md`](COMPLIANCE_MAPPING.md) | (see above) |
| [`docs/FRONTMATTER_CONFORMANCE.md`](FRONTMATTER_CONFORMANCE.md) | Static metadata checks for agents, skills, and instructions |
| [`SECURITY.md`](../SECURITY.md) | Supported versions, vulnerability reporting, security posture |

## Schemas and canonical control data

| Path | Scope |
| --- | --- |
| [`schemas/README.md`](../schemas/README.md) | Schema namespace guide and canonical-schema posture |
| [`configs/naos_ai_surface_catalogue.yaml`](../configs/naos_ai_surface_catalogue.yaml) | Generated AI tool-surface catalogue emitted from agent, skill, and instruction frontmatter; separate from control-plane capability contracts |
| [`configs/secure_coding_control_register.yaml`](../configs/secure_coding_control_register.yaml) | Active canonical secure/agentic coding requirements register; does not own enforcement policy or prove security |
| [`configs/secure_coding_control_register.sample.yaml`](../configs/secure_coding_control_register.sample.yaml) | Illustrative compatibility seed; not the active requirement authority |
| [`configs/secure_coding_control_render_manifest.yaml`](../configs/secure_coding_control_render_manifest.yaml) | Reviewed binding from canonical controls to bounded generated consumer sections |
| [`schemas/team_config.schema.yaml`](../schemas/team_config.schema.yaml) | Multi-team filter config (TASK_REGISTRY `team_config` block) |
| [`schemas/naos/capability.schema.json`](../schemas/naos/capability.schema.json) | Canonical capability-card schema used by the capability contract validator |
| [`schemas/naos/systemic_impact_rules.schema.json`](../schemas/naos/systemic_impact_rules.schema.json) | Artifact families, typed review surfaces, and separate kit-source/adopter-generated changed-path routes |
| [`schemas/naos/systemic_impact_review.schema.json`](../schemas/naos/systemic_impact_review.schema.json) | Current-state and optional explicit changed-path systemic-impact report contract |
| [`schemas/naos/systemic_impact_changed_path_review.schema.json`](../schemas/naos/systemic_impact_changed_path_review.schema.json) | Human-authored evidence dispositions for exact changed-path obligations; not approval or semantic-completeness proof |
| [`schemas/naos/spec_pack_manifest.schema.json`](../schemas/naos/spec_pack_manifest.schema.json) | Structural schema for the spec-pack manifest; template contract only, not spec approval |
| [`schemas/naos/spec_pack_contract.schema.json`](../schemas/naos/spec_pack_contract.schema.json) | Structured report schema for deterministic spec-pack template contract conformance |
| [`schemas/naos/spec_cascade_coherence.schema.json`](../schemas/naos/spec_cascade_coherence.schema.json) | Structured report schema for deterministic spec-cascade coherence findings |
| [`schemas/naos/ac_completion_evidence.schema.json`](../schemas/naos/ac_completion_evidence.schema.json) | Structured report schema for declared AC/SCEN completion evidence findings |
| [`schemas/naos/ac_completion_evidence_manifest.schema.json`](../schemas/naos/ac_completion_evidence_manifest.schema.json) | Manifest schema for explicit AC/SCEN completion evidence declarations |
| [`schemas/naos/package_reality.schema.json`](../schemas/naos/package_reality.schema.json) | Structured report schema for deterministic package, optional SBOM/provenance/hash, docs-snippet, and explicit opt-in registry-metadata review evidence |
| [`schemas/naos/package_reality_provenance.schema.json`](../schemas/naos/package_reality_provenance.schema.json) | Optional manifest schema for adopter-maintained package provenance evidence declarations |
| [`schemas/naos/secure_coding_control_register.schema.json`](../schemas/naos/secure_coding_control_register.schema.json) | Structural schema for both active and illustrative secure/agentic coding registers; excludes profile-enforcement authority |

## Community and project management

| Document | Scope |
| --- | --- |
| [`.github/CODEOWNERS`](../.github/CODEOWNERS) | Explicit ownership map for the kit |
| [`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/) | Issue templates: bug-report, roadmap-decision, threat-model, audit-playbook |
| [`.github/FUNDING.yml`](../.github/FUNDING.yml) | Funding configuration |
| [`LICENSE`](../LICENSE) | Apache License 2.0 terms |
| [`NOTICE`](../NOTICE) | Attribution notice |

---

## What this index is NOT

- **Not exhaustive across maintainer-private planning material.** This index covers the published kit only. Internal research, marketing, and release-planning material stays outside the public documentation surface until explicitly approved for publication.
- **Not a sitemap for generated documents.** Documents produced by `make -f Makefile.naos gov-refresh` (DASHBOARD.md, TRACEABILITY_MATRIX.md, BACKLOG.md, PROJECT_STATUS.md) are intentionally not listed — they are outputs, not inputs.
- **Not version-pinned.** Document content changes between releases; the index structure does not. If a document is missing here, that is a bug in the kit, not in your installation.
