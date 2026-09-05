---
name: "naos-systemic-wiring"
description: "NAOS-aware extension of systemic-wiring. Adds NAOS capability, policy, validator, evidence, dashboard, spec-pack, and AI surface families plus naos CLI commands and control-coherence invariants. Requires NAOS kit installed in the project."
extends: "systemic-wiring"
parameters:
  - name: target
    description: "All targets from systemic-wiring plus NAOS-specific: capability, policy, validator, gate, evidence, dashboard, spec-pack, ai-surface, hook-template, optional-integration, or all."
    required: false
    default: "all"
  - name: depth
    description: "Check depth: quick (triage only) or standard (full wiring check)."
    required: false
    default: "standard"
  - name: profile
    description: "NAOS profile: quickstart, lite, standard, or assured."
    required: false
    default: "standard"
---

# NAOS Systemic Wiring

NAOS-aware extension of the generic `systemic-wiring` skill. Run the base
`systemic-wiring` skill first, then apply the NAOS-specific additions below.

Requires the NAOS governance kit to be installed in the project. If NAOS is
not installed, use `systemic-wiring` directly.

## When to Use

Use this skill when a change affects NAOS commands, reports, schemas, policies,
skills, prompts, workflows, instructions, agents, docs, optional integrations,
plugin source, MCP posture, project setup, generated adopter files, or
spec-pack surfaces.

Escalate to `naos-forensic-audit` when the change spans many governed families,
affects release/public-export posture, changes security or authority boundaries,
or when a previous wiring finding is being claimed as fixed.

## Base Skill

Run `systemic-wiring` with the same `target` and `depth` parameters. All four
steps, the finding format, boundaries, and escalation criteria apply. This
skill adds NAOS-specific families, orphan checks, CLI commands, and
control-coherence invariants on top.

## NAOS Context Budget

Before running, check AI surface budget:

```bash
naos ai-surface-budget --profile <profile>
```

Apply the same degraded/critical degradation rules from the base
`systemic-wiring` Context Budget section. At critical posture, run Step 1
(family identification) only and defer Step 3 CLI commands to a fresh session.

## NAOS-Specific Families

In addition to the base `systemic-wiring` families, identify whether the change
touches:

| NAOS Family | Examples |
|---|---|
| Capability contracts | `capabilities/*.yaml` enforcement, target_maturity, severity_by_profile |
| Policy | `policies/*.yaml` rules, thresholds, profile behavior |
| Validators / scripts | `scripts/validators/*.py`, deterministic checks, CLI/Make dispatch |
| Gates | `naos/gate_status.json`, `naos/gate_evaluate.json`, gate logic and consumers |
| Evidence reports | `naos/reports/*.json`, evidence pack, SARIF, capability maturity, systemic impact, control-plane review |
| Dashboard | Panels and summaries consuming evidence reports |
| Spec-pack | `templates/spec-kit/specs`, `spec_manifest.yaml`, generated `specs/`, materialization previews, assembly worksheets |
| AI surfaces | `CLAUDE.md`, plugin skills, prompts, agents, instructions, manuals, quick references |
| Hook templates | Optional Claude Code hook templates under `plugins/` or `templates/` |
| Optional integrations | Spec-Kit adapter, MCP posture, learning propagation, integration-readiness reports |
| `dev/**` boundary | Internal audit history that must not appear in public surfaces or export material |

List every affected NAOS family before proceeding.

## NAOS-Specific Orphan Checks

For each affected NAOS family, verify:

- **Capability contract change**: Is the enforcement field consumed by
  `naos_policy.effective_enforcement` or equivalent runtime code, not merely
  schema-valid? Is target maturity monotonic across profiles? Is the capability
  card validated by `validate_capability_contracts.py`?
- **Policy change**: Is the policy reflected in validator logic, schema, docs,
  tutorials, generated profile rules, and tests?
- **Validator / script change**: Does the validator have CLI/Make/CI routing,
  self-check visibility, tests, report schema, and bounded non-claims?
- **Gate change**: Is the gate consuming the right evidence report, and are
  dashboard, CI, schema, and evidence pack consumers updated?
- **Evidence report change**: Is the report schema updated and validated? Does
  the report include known gaps, residual risks, limitations, non-claims, and
  human-review posture?
- **Dashboard change**: Does every panel reference a real, currently generated
  evidence report?
- **Spec-pack change**: Does the manifest, generated project behavior,
  spec-pack contract validator, materialization dry-run, docs, tutorials,
  quick reference, and tests agree? Do not claim design quality or complete
  traceability from structural conformance.
- **AI surface change**: Is `naos ai-surface-budget` run after this change? Are
  conflicting instructions removed or consolidated? Are critical constraints
  near the top of the relevant surface? Is control-plane review routed?
- **Hook template change**: Is the hook reviewed as operational code that can
  run commands or inject context? Is it optional and manual? Does it avoid
  secrets, auto-push, auto-deploy, and silent context injection?
- **Optional integration change**: Is the integration clearly optional,
  template/manual only, and non-required?
- **`dev/**` boundary change**: Does any new or moved internal file risk
  appearing in `templates/`, generated adopters, sanitized export material, or
  public docs?

## NAOS CLI Checks

After running the base Step 3 project checks, run applicable NAOS commands:

```bash
# Systemic impact - mandatory for governed artifact family changes
naos systemic-impact --profile <profile>

# Stable-card closure - repeat --changed-path for the exact tracked change set
naos systemic-impact --profile <profile> --changed-path <path>
naos systemic-impact --profile <profile> --changed-path <path> \
  --review-record <review.yaml> --require-resolved

# Control-plane review - after plugin, integration, instruction, or AI surface changes
naos control-plane-review --profile <profile>

# Adapter coherence - after plugin, MCP posture, or learning propagation changes
naos adapter-coherence --profile <profile>

# Spec-pack structural conformance and lifecycle checks
naos spec-pack-contract --profile <profile>
naos spec-pack-materialize . --profile <profile> --dry-run
naos spec-assembly-worksheet . --profile <profile>

# Control-coherence validation
python scripts/validators/validate_profile_control_coherence.py
python scripts/validators/validate_capability_contracts.py

# Broad health check
naos self-check --profile <profile>
```

If no NAOS CLI is available, inspect the affected `capabilities/`, `policies/`,
`scripts/validators/`, `schemas/naos/`, `templates/`, and `plugins/` files
manually and surface gaps as findings.

For each stable card, run the explicit changed-path form once before closure.
Keep NAOS-governance kit sources separate from portable adopter-generated
files. Record an evidence-backed disposition for every emitted obligation;
preserve `update_required` and `unresolved` honestly. If another target is
edited, refreeze the paths and repeat. The check does not infer a Git base,
edit artifacts, prove semantic completeness, or grant approval.
Bind the review record once to the complete exact changed-path set and record
one decision per unique destination; the report retains every contributing
path, family, trigger, and declared link.

## Control-Coherence Invariants

When a capability contract, profile, gate, policy, or enforcement surface
changes, verify these invariants before closing the wiring check:

1. **Monotonic profiles** - control must not decrease across quickstart, lite,
   standard, and assured for severity, enforcement, target maturity, or exit
   code ramp.
2. **No orphan declarations** - every declared enforcement or target maturity
   field must be consumed by runtime code, not merely schema-valid.
3. **Generated artifact fidelity** - static generated files must be regenerated
   from their generator after policy changes, never hand-edited.
4. **Evidence consumer completeness** - every evidence report produced by a
   script must have at least one consumer: dashboard panel, gate entry, or
   evidence pack inclusion.

Surface any invariant violation as a blocker wiring finding.

## NAOS Escalation Additions

In addition to the base `systemic-wiring` escalation criteria, escalate to
`naos-forensic-audit` when:

| Condition | Reason |
|---|---|
| A capability contract's enforcement or target_maturity field changes | Requires control-coherence adversarial pass |
| `ADR-0010: Control-Plane Advisory Boundaries` authority boundaries are in dispute | Requires forensic-audit evidence hierarchy and false-positive hunter |
| A multi-user control surface changes | Requires adversarial ghost hunt for overclaims |
| A sanitized public export or release candidate is being reviewed | Triage is insufficient; full NAOS release audit required |
| `dev/**` content risk is detected in public surfaces | Requires Pass 3 NAOS adversarial ghost hunt |
| An optional integration is presented as required or auto-active | Requires integration leakage adversarial pass |
| A spec-pack or AI-surface catalogue drift finding is being closed | Requires confirmation against generated projects, catalogues, and adapter coherence |
| A retracted or previously disputed audit finding is being reopened | Requires retractions-ledger review and differently framed confirmation |

## Related NAOS Skills

| Skill | When to use |
|---|---|
| `systemic-wiring` | Base skill - always run first |
| `systemic-capability-wiring` | Canonical NAOS product/control-plane wiring checklist |
| `naos-forensic-audit` | Escalate when NAOS surfaces require deep adversarial review |
| `naos-forensic-review` | Lightweight evidence-backed review of a single artifact |
| `naos-control-plane-evidence` | Choose the right NAOS evidence commands for the change |
| `naos-ai-surface-health` | Review AI surface budget after AI surface changes |
| `naos-adoption-readiness` | Confirm NAOS is installed correctly before wiring checks |

## Boundary

This skill guides review and routing. It does not install plugins, activate
hooks, call providers, approve work, certify compliance, prove runtime safety,
or replace human review.
