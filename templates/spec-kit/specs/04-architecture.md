# 04 - Architecture

**Version**: 0.2.0
**Status**: Draft
**Upstream**: [01](01-problem.md), [02](02-solution.md), [03](03-requirements.md)
**Downstream**: [05](05-api.md), [06](06-acceptance.md), [10](10-execution.md)

## Architecture Overview {#ARCH-0}

[ADAPT: Style, deployment, stores, integrations, trust boundaries, flow]

## Decision Context {#ARCH-5}

**Project mode**: [ADAPT: greenfield | brownfield]
**Decision owner**: [ADAPT: accountable role]
**Decision scope**: [ADAPT: exact decision]
**Supported result**: [ADAPT: observable result changed]
**Inputs reviewed**: [ADAPT: specs, source/ADRs, research, unknowns]

### Material Constraints

| Constraint | Kind | Source | Pass condition | Result |
|---|---|---|---|---|
| CON-001 | [ADAPT: hard/soft] | [ADAPT: source] | [ADAPT: condition] | [ADAPT: result + rationale] |

## Components {#ARCH-10}

| Component | Purpose + FR/NFR | Technology | Owns/consumes |
|---|---|---|---|
| ARCH-1 {#arch-1} | [ADAPT: role + FR/NFR] | [ADAPT: identity/version] | [ADAPT: data/interfaces] |
| ARCH-2 {#arch-2} | [ADAPT] | [ADAPT] | [ADAPT] |

## Data Flow {#ARCH-15}

1. **ARCH-1**: [ADAPT: input/state/failure]
2. **ARCH-2**: [ADAPT: processing/output/failure]

## Architectural Decisions {#ARCH-20}

| Decision/option | Identity | Version | Source | Checked date | Constraint result | Trade-offs | Uncertainty | Counterargument | FR/NFR |
|---|---|---|---|---|---|---|---|---|---|
| ADR-001 / OPT-001 | [ADAPT: candidate] | [ADAPT: version] | [ADAPT: source] | [ADAPT: YYYY-MM-DD] | [ADAPT: CON/result] | [ADAPT: trade-offs] | [ADAPT: confidence/unknowns] | [ADAPT: strongest objection] | [ADAPT] |

**Human outcome**: [ADAPT: selected | rejected | deferred | review_required]
**Outcome rationale**: [ADAPT: human rationale/assumptions/alternative]

## Brownfield Reconciliation {#ARCH-25}

**Brownfield disposition**: [ADAPT: keep | merge | replace | quarantine | create | review_required | not_applicable — why]

| Current boundary | Disposition/target | Compatibility | Migration/coexistence | Rollback | Regression | Decommission |
|---|---|---|---|---|---|---|
| [ADAPT: boundary/N/A] | [ADAPT: disposition/target] | [ADAPT: evidence/unknown] | [ADAPT: evidence/unknown] | [ADAPT: evidence/unknown] | [ADAPT: evidence/unknown] | [ADAPT: evidence/unknown] |

## Security Model {#ARCH-30}

- **Authentication/authorization**: [ADAPT: mechanism/boundary]
- **Tenant isolation**: [ADAPT: model or N/A rationale]
- **Sensitive data/secrets**: [ADAPT: class/residency/storage/handling]

## Architecture Invariants {#ARCH-40}

1. [ADAPT: invariant]
2. [ADAPT: invariant]
3. [ADAPT: invariant]

Enforced only when a compatible validator is installed and invoked.

## Known Gaps, Residual Risks, and Non-Claims {#ARCH-50}

- **Known gaps/unknowns**: [ADAPT: missing facts/evidence]
- **Residual risks**: [ADAPT: accepted/deferred/routed]
- **Falsifier/revisit trigger**: [ADAPT: invalidating evidence/change]
- **Non-claims**: [ADAPT: no truth, completeness, suitability, approval, implementation, or release claim]
