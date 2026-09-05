# Assured Profile Activation

**Status**: Public adopter guidance
**Scope**: How to activate and interpret the `assured` profile without
overclaiming assurance

The `assured` profile is the strongest NAOS profile. It increases review and
gate expectations for projects that need evidence-heavy governance. It does not
provide certification, proof of compliance, regulator acceptance, runtime safety
proof, automatic approval, or separation-of-duties satisfaction by itself.

## What Assured Means

`assured` means:

- stricter profile policy;
- more blocking or review-required posture where configured;
- stronger evidence expectations;
- higher visibility for waivers, residual risks, missing inputs, and stale
  reports;
- stronger human-review boundaries.

It does not mean the project is mature, compliant, approved, or safe merely
because the profile is selected.

## Before Using Assured Seriously

Configure or review these adopter-specific inputs:

- `naos/capability_state.yaml`
- `naos/gatekeepers.yaml`
- `naos/systemic_impact_rules.yaml`
- `naos/control_plane_review_rules.yaml`
- `naos/control_plane_review_items.yaml`
- `naos/evidence_attestation_rules.yaml`
- `naos/evidence_review_attestations.yaml`
- `naos/team_operator_map.yaml` if team/operator overlays are used
- `naos/task_claims.yaml` if multiple operators coordinate task work
- `naos/agentic_workflow.yaml`
- `naos/PRE_IMPLEMENTATION_ALIGNMENT.md`
- project specs, task registry, traceability matrix, source/test evidence, and
  CI workflow choices

Run `naos setup-recommendations --profile assured` before treating the profile
as operational.

## Expected Evidence Inputs

Assured profile evidence is strongest when the project has:

- current capability maturity report;
- current gate status and gate evaluation reports;
- evidence pack and dashboard summary;
- source-to-test, module-header, spec-pack, and spec-cascade reports where relevant;
- evidence attestation and evidence conflict reports;
- session identity, operator attribution, audit-log summary, and task-claim
  reports for team workflows;
- policy override merge report if overlays are used;
- PR risk classification and PR governance summary if CI is configured.

Missing evidence should remain visible. Do not turn missing evidence into a
green/pass signal.

## Team and Operator Overlays

Team/operator policy overlays and multi-team gatekeeper config can change
effective policy or gate posture for a selected team context. They are static
configuration only:

- not authentication;
- not authorization;
- not access control;
- not team-membership proof;
- not separation-of-duties satisfaction.

Use explicit `TEAM_ID`/`--team-id` or a reviewed `naos/team_operator_map.yaml`
only as governance metadata.

## PR-Time CI

Adopters may copy `templates/workflows/naos-pr-governance.yml.example` into
their own workflow directory after review. CI can run assured checks and write
`naos/reports/pr_risk_classification.json` and
`naos/reports/pr_governance_summary.json`.

PR risk classification reviews local diff metadata for protected paths,
workflow/dependency changes, AI instruction surfaces, prompt-injection-like
text, and secret-like added lines. PR-time CI output is review evidence. It is
not PR approval, malware analysis, sandbox execution, security proof,
deployment authorization, release authorization, proof of compliance, or
evidence-conflict resolution.

## Human Review Boundary

Humans remain responsible for:

- profile selection;
- scope and requirements decisions;
- accepting waivers and residual risks;
- resolving evidence conflicts;
- approving releases, deployments, and exceptions;
- deciding whether evidence is sufficient for an external reviewer.

## New Versus Existing Projects

For a genuinely new destination, initialize the selected profile explicitly.
For an existing project, `naos upgrade --dry-run` is currently comparison-only:
it writes nothing to the adopter repository and does not establish ownership,
merge content, apply a profile transition, or activate enforcement. Normal
upgrade invocation and legacy `--force` fail closed with `NOT_APPLIED`.

Do not use `naos init --activate` as an existing-project upgrade substitute.
Skip-existing scaffolding may add missing files while retaining older or
adopter-owned profile content.

## Activation And Assessment Checklist

```bash
# New destination only, run from that destination:
naos-governance init --new --tier assured --archetype custom --backend static_only --activate

# Existing project: preview only; no transition is applied:
naos-governance upgrade . --tier assured --archetype custom --backend static_only --dry-run

# Target-posture assessment; these commands are not activation evidence:
naos setup-recommendations --profile assured
naos agentic-workflow-review --profile assured
naos pre-implementation-alignment-review --profile assured
naos policy-overrides --profile assured --dry-run
naos self-check --profile assured
naos gate-status --profile assured
naos gate-evaluate --profile assured
naos evidence-pack --profile assured
naos dashboard --profile assured --json
```

Use `naos add setup-module profile_baseline --profile assured --dry-run` before
copying optional modules. Remove `--dry-run` only after reviewing the proposed
files.
