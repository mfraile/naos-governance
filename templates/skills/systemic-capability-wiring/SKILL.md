---
name: "systemic-capability-wiring"
description: "Use when designing, changing, or reviewing capabilities, validators, AI surfaces, docs, source modules, workflows, or project configuration so NAOS changes are wired without orphan artifacts."
parameters: []
---

# Systemic Capability Wiring Skill

## Purpose

Use this skill when designing, changing, or reviewing a feature, capability,
system component, app/web/API feature, validator, report, prompt, instruction,
agent, workflow, documentation surface, or project configuration.

Core principle: a feature is not done when it works in isolation; it is done
when it is wired into the system's contracts, configuration, validation,
evidence, visibility, documentation, tests, and human decision boundaries.

This is the canonical AI-agent guidance for systemic wiring. Other prompts,
agents, instructions, rules, and workflows should reference this skill
concisely instead of copying this full checklist into many places.

## Quick Start

1. Name the change and the artifact families it touches.
2. Identify the contract, configuration, schema, validator/report, evidence,
   docs, tests, and human decision boundary.
3. Freeze the exact changed-path list and run or recommend `naos
   systemic-impact --changed-path <path>` for every governed changed file.
4. Record one evidence-backed disposition for every emitted review obligation
   and use `--review-record <yaml> --require-resolved` before closure.
5. Record non-claims, residual risks, validation evidence, and any human review
   still required.

## When to Use

Use this skill when adding or materially changing:

- capability cards;
- schemas;
- policies;
- validators or scripts;
- gates;
- evidence reports;
- dashboards;
- CLI or Make commands;
- CI or workflow behavior;
- AI prompts, instructions, agents, or skills;
- docs, manuals, tutorials, or quick references;
- project configuration;
- source code modules;
- web, app, API, or data features in adopter projects;
- security/privacy-sensitive behavior;
- maturity, evidence, traceability, or review workflows.

If the change touches AI surfaces, specs, capability contracts, policies,
validators, evidence semantics, dashboard semantics, source traceability, or
project configuration, also run or recommend `naos systemic-impact`.

## Two Perspectives

### NAOS Product-Readiness Method

Think in terms of systemic wiring across:

- capability contracts;
- schemas;
- policy;
- adopter configuration;
- maturity state;
- gates;
- evidence pack;
- dashboard;
- systemic impact review;
- spec-pack contract;
- spec-cascade coherence;
- module-header traceability;
- CLI, Make, and CI;
- docs, manuals, tutorials, and quick references;
- tests;
- human approval boundaries;
- known limitations and non-claims.

### Senior Engineering And Product Practice

Also apply standard engineering discipline:

- requirements traceability;
- specification-driven and acceptance-test-driven thinking;
- architecture decision records;
- CI and regression control;
- threat and risk thinking;
- observability and operational visibility;
- documentation-as-product;
- explicit ownership and accountability;
- human review and approval boundaries;
- safety-critical and regulated-system discipline;
- maintainability and change-impact analysis.

## Required Wiring Checklist

For every feature, capability, or system change, identify:

- user or stakeholder;
- problem solved;
- scenario or use case;
- input artifacts;
- output artifacts;
- capability contract or equivalent;
- configuration surface;
- schema or data contract;
- policy or rules;
- execution surface: CLI, API, UI, job, or workflow;
- validator, evaluator, checker, or grader;
- evidence or report produced;
- dashboard or visibility surface;
- traceability links to requirements, specs, tasks, tests, risks, and docs;
- systemic impact relationships;
- human approval boundary;
- docs, tutorial, or quick reference updates;
- tests and regression checks;
- security and privacy implications;
- failure modes;
- known limitations;
- non-claims;
- future extension path.

## NAOS Wiring Pattern

Use this canonical NAOS pattern:

```text
capability card
-> rules/config
-> schema
-> policy
-> validator/report
-> gates
-> evidence pack
-> dashboard
-> capability maturity
-> systemic impact
-> spec-pack contract where spec templates/files are involved
-> spec-cascade coherence where specs/tasks/source references or traceability are involved
-> module/source traceability where applicable
-> CLI/Make/CI
-> docs/tutorials/quick reference
-> tests
-> human decision boundary
```

The common shape is: declare, configure, evaluate, report, review, approve,
and mature. NAOS produces bounded evidence and related evidence. It does not
replace governance judgement, prevent bypasses, or prove CI ran.

Keep two artifact roles explicit throughout that flow:

- **NAOS-governance kit source**: canonical scripts, templates, plugins,
  capabilities, maintainer records, and kit tests.
- **Adopter project output**: only portable files generated or explicitly
  installed into a project, including profile-selected `naos/`, `.github/`,
  Make, and local evidence surfaces.

Review propagation between the roles where declared, but never present kit-only
history, audits, or plugin source as generated adopter content.

## Stable Changed-Path Closure

After the card diff is stable, derive its exact tracked paths from the approved
base and pass them explicitly:

```bash
naos systemic-impact \
  --profile <profile> \
  --changed-path <path> \
  --changed-path <another-path>
```

Disposition every emitted obligation as `updated`, `reviewed_no_change`,
`not_applicable`, `update_required`, or `unresolved`. Closed dispositions need
rationale and evidence. Then run the same command with
`--review-record <yaml> --require-resolved`. If another file changes, refreeze
and repeat. The report is routing and review evidence; it is not automatic Git
diff analysis, semantic-completeness proof, approval, or certification.

Bind the review record once to the complete exact changed-path set and record
one decision per unique routed destination. Do not duplicate the same decision
for every contributing path; the report preserves those path-level reasons.

## Generic App/Web/System Pattern

For adopter product work, map the change like this:

```text
feature
-> user story/requirement
-> data model/schema
-> API/UI/workflow
-> validation
-> permissions/security
-> logs/audit/evidence
-> observability/dashboard
-> tests
-> documentation
-> release/rollback considerations
-> human approval boundary where needed
```

## AI Drift And Instruction Design

AI agents can drift when:

- prompts are too long;
- instructions are duplicated across many files;
- old examples conflict with canonical rules;
- constraints are buried in the middle of large prompts;
- similar guidance is expressed differently in different surfaces;
- stale prompt fragments remain after the design changes;
- too many files are concatenated into context without prioritization.

Guidance:

- keep one canonical skill or checklist for systemic wiring;
- reference it concisely from other AI surfaces;
- put non-negotiable constraints near the top;
- structure large prompts with headings and grouped rules;
- remove stale duplicated guidance or mark it legacy;
- ask the agent to summarize active constraints before major implementation;
- run or recommend systemic-impact review when AI surfaces change;
- prefer self-intuitive file names, command names, report names, and section names.

Adding more instructions is not automatically better. Concise canonical
guidance plus clear references is usually more reliable than repeated long
text with slight local variations.

## Anti-Patterns

Reject these patterns:

- script without report;
- report without consumer;
- config without schema;
- schema without validator;
- command without docs or tests;
- validator without severity/profile behavior;
- dashboard without evidence source;
- evidence without limitations;
- maturity claim without evidence;
- declared field that no runtime code consumes (orphan declaration, e.g. a
  capability `enforcement`/`target_maturity` that is schema-valid but never
  drives behavior);
- per-profile control that is not monotonic quickstart -> lite -> standard ->
  assured (severity, enforcement, target_maturity, or exit-code ramp);
- static generated artifact (e.g. `profiles/*/RULES.md`) that drifts from its
  generator/policy;
- automatic approval without human boundary;
- project-specific assumption disguised as generic kit behavior;
- prompt or instruction change without systemic-impact review;
- feature that bypasses gates, evidence, or dashboard visibility;
- overclaiming proof, certification, or compliance from advisory evidence;
- duplicating the same long guidance across many AI surfaces;
- burying critical constraints inside long prompts;
- allowing old prompt examples to conflict with canonical guidance;
- adding new instructions without checking systemic impact;
- increasing prompt length without improving decision quality;
- implementing a feature without asking what else it affects.

## Control-Coherence Invariants

NAOS control is a 2-D lattice: **profile severity (breadth)** × **capability
maturity L0–L5 (depth)**. When you add or change a capability, profile, gate,
policy, or enforcement surface, these invariants must hold and are checked by
`scripts/validators/validate_profile_control_coherence.py`:

- **Monotonic profiles.** Control must not decrease across
  quickstart → lite → standard → assured — for `severity_by_profile`,
  per-capability `enforcement`, per-capability `target_maturity`, and the
  `exit_code` ramp (each profile's `fail_on` ⊇ the previous; `fail_on` ⊆
  `strict_fail_on`).
- **No orphan declarations.** A declared control field (e.g. capability
  `enforcement`/`target_maturity`) MUST be consumed by runtime code, not just
  schema-validated. Declared-but-unconsumed is the failure mode that let the
  control lattice look enforced while it was not.
- **Maturity gates enforcement.** Per-capability enforcement only takes effect
  once `current_maturity ≥ target_maturity`; below target it downgrades to
  advisory ("never block a scaffold"). Use `naos_policy.effective_enforcement`.
- **Generated artifacts match their generator.** Static samples such as
  `profiles/*/RULES.md` must be regenerated from the generator, never hand-drifted.
- **Run the guard.** Add `validate_profile_control_coherence.py` to CI and
  `naos self-check` whenever control surfaces change.

## Language Rules

Use these terms:

- declare;
- configure;
- evaluate;
- report;
- review;
- approve;
- mature;
- human review required;
- known limitation;
- related evidence;
- review obligation;
- bounded evidence;
- systemic impact;
- traceability;
- configuration surface;
- evidence consumer.

Avoid these terms when they overclaim:

- prove;
- certify;
- guarantee;
- automatically approve;
- complete coherence;
- universal correctness;
- no human review needed;
- full automation of governance;
- compliance proof;
- runtime safety proof;
- complete coverage proof.

## Examples

### A. Capability Maturity Readiness

`capability_state.yaml` declares adopter state.
`capability_maturity.json` evaluates readiness.
The evidence pack and dashboard expose the result.
Humans approve maturity movement.

### B. Systemic Impact Review

`systemic_impact_rules.yaml` declares artifact-family relationships.
`systemic_impact_review.json` reports review obligations.
It does not claim perfect coherence.

### C. Module-Header Traceability

`module_header_rules.yaml` declares source-traceability expectations.
`module_header_traceability.json` reports missing, legacy, or stale headers.
`spec_cascade_coherence.json` reports orphan headers, uncovered requirements,
stale status links, overloaded FRs, and untraced source when specs/tasks/source
traceability changed.
It does not claim code correctness.

### D. Generic User-Role Feature

A new user-role feature should wire requirements to data model, API/UI,
permission checks, logs/audit, tests, docs, dashboard/monitoring, and a
rollback/review path.

## Validation Checklist

At the end of a feature implementation, answer:

- What capability or feature was added or changed?
- Who uses it?
- What problem does it solve?
- What consumes it?
- What configuration surface controls it?
- What schema or contract defines it?
- What policy or rule governs it?
- What command, API, UI, or workflow runs it?
- What report or evidence does it produce?
- Where does it appear in dashboard or visibility surfaces?
- What gates or checks see it?
- What docs, tutorials, or quick references changed?
- What tests cover it?
- What does it not claim?
- What human decision remains?
- What artifact families may be impacted?
- Is this guidance canonical, or duplicated elsewhere?
- Could this instruction conflict with another AI surface?
- Is the prompt or instruction too long for reliable AI attention?
- Are critical constraints near the top?
- Does this change require systemic-impact review?

## Human Governance Boundary

This skill helps design and review coherent systems. It does not replace
product owner, architect, security, compliance, engineering, or risk approval.

## Output Expectation

Implementation reports guided by this skill should include:

- files changed;
- systemic wiring;
- tests run;
- evidence generated;
- docs updated;
- limitations;
- non-claims;
- remaining risks;
- next impacted groups.
