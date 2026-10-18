# 03 - Requirements Specification

**Version**: 0.1.0
**Status**: Draft
**Upstream**: [01-problem.md](./01-problem.md), [02-solution.md](./02-solution.md)
**Downstream**: [04-architecture.md](./04-architecture.md), [05-api.md](./05-api.md), [06-acceptance.md](./06-acceptance.md), [10-execution.md](./10-execution.md)

<!-- ⚠️ Status badges in each FR are auto-updated by `make -f Makefile.naos gov-refresh`. Edit TASK_REGISTRY.yaml, not here. -->

---

## Table of Contents

### Functional Requirements

<!-- ADAPT: Replace with your FR list. Keep this index in sync with sections below. -->
1. [FR-001: ADAPT Name](#fr-001-adapt-name) — Draft
2. [FR-002: ADAPT Name](#fr-002-adapt-name) — Draft

### Non-Functional Requirements
1. [NFR-001: Performance](#nfr-001-performance) — Draft
2. [NFR-002: Security](#nfr-002-security) — Draft

---

## Constitution Gates (Pre-Implementation Validation)

<!-- ADAPT: Principles that every FR/NFR must respect. Customize for your domain.
     Example gates: Data isolation, GDPR compliance, test-first culture. -->

| # | Gate | Validation |
|---|------|------------|
| 1 | **ADAPT: Gate 1** | [ADAPT: how to verify — e.g. RLS policies, audit log, test case] |
| 2 | **ADAPT: Gate 2** | [ADAPT] |

---

## Functional Requirements

Supplied reference markers are drafting context. When provided, insert
`**Source reference**: <exact supplied value>` between the document's top-level
Status and Upstream lines, once per document rather than under each requirement.
Keep every supplied marker verbatim and visible, not only in HTML comments.
Do not invent one, turn it into an FR/NFR identity, or treat it as authorization.
If none is supplied, omit the field; do not ask for a marker.
Before completion, re-read the saved document and compare each value with the
request. Restore missing or changed supplied values; report unresolved conflicts
instead of claiming that a mismatched draft faithfully retains the input.
Preserve every existing explicit `{#...}` anchor string even when its heading
title changes; update table-of-contents labels without regenerating targets.
Compare original and saved anchors before completion; restore omissions or
renames using the original strings.

Template candidates below preserve scaffold reference forms, not established relationships.
Before retaining a candidate, verify its pre-edit field and current target definition,
and record the source and template/seed origin in the existing review evidence.
If no valid candidate exists, keep a visible `[ADAPT: mapping unresolved]` field
without invented IDs and retain the actual missing-pattern/reference findings.
A structural pass does not establish a mapping or make an unfinished draft ready.
Explicit supplied priorities override template examples; retain an established
priority when no change is supplied. A template value is not a business decision.
Conflicting priorities or ambiguous requirement identities require resolution.
Do not infer capability-to-requirement associations from numbering or order.
After editing, compare each affected Priority field, required facts and exact
examples/markers against the supplied input; preserve IDs, anchors and unrelated
content. Record mismatches in existing review evidence, not a new registry.
A template example or multi-value placeholder is not an established priority;
leave an unknown priority pending rather than silently choosing P1.

Keep each unfinished link field visibly unresolved with `[ADAPT: ...]`; hidden
HTML comments or a global footnote alone are insufficient. Do not demote a
supported relationship without an authorized correction. Remove invalid or
superseded candidates and retain the actual findings; never append unrelated
IDs for a regex, invent bindings, or create tasks/components in a spec-only edit.
Current extraction counts even unconfirmed IDs as references. Do not use unfinished
relationships to authorize planning/coding. A saved draft may support an explicitly
scoped design step to resolve them; it is not a gate pass. Complete source-backed
problem/solution mappings when known; architecture/task assignments may await
their own design/planning decisions. Reconcile those fields once decisions exist.
Record actual report status/findings/exit separately from input fidelity and
semantic completeness: exit 0 with `required_missing` is not a structural pass.
A reviewed rationale is not an implemented exception. Unknown outcomes, methods
and targets stay pending; filled checks and supported semantic decisions are
required before claiming readiness for planning/coding.

---

### FR-001: [ADAPT: Requirement Name] {#fr-001-adapt-name}

**Priority**: [ADAPT: select P0, P1 or P2 from the supplied requirement priority; no default]
**Status**: Draft  <!-- Auto-updated by gov-refresh via TASK_REGISTRY.yaml -->
**Linked Tasks**: [ADAPT: assignment unresolved]. Template candidates T-001, T-002; not established assignments.
**Linked To**: [ADAPT: mapping unresolved]. Template candidates PAIN-1.1, SOL-1.1, R-001; not established mappings.
**ARCH Components**: [ADAPT: component mapping unresolved]. Template candidates ARCH-1, ARCH-2; not established components.

#### Description

<!-- ADAPT: 2-5 sentence description of what the system must do.
     Write from the user/system perspective: "The system shall..." -->

[ADAPT: What the system must do]

#### Acceptance Criteria

| AC | Condition | Validation |
|----|-----------|------------|
| AC-001-1 | [ADAPT: Given [context] When [action] Then [outcome]] | [ADAPT: unit test / integration test / manual] |
| AC-001-2 | [ADAPT] | [ADAPT] |

#### Systemic Impacts

<!-- ADAPT: How does this FR affect other spec documents?
     Fill in after all specs are initially drafted. -->

| Spec | Impact |
|------|--------|
| 04-architecture.md | [ADAPT: e.g. Requires new service layer component] |
| 05-api.md | [ADAPT: e.g. Introduces POST /items endpoint] |
| 06-acceptance.md | [ADAPT: e.g. Drives SCEN-1.M scenarios] |
| 07-cost-analysis.md | [ADAPT: e.g. Adds $X/month infra cost] |

#### Independent Test

<!-- ADAPT: How to verify this FR in isolation, before full-system testing. -->

```bash
# ADAPT: Command to run the isolated test
pytest tests/unit/test_fr001.py -v
```

---

### FR-002: [ADAPT: Requirement Name] {#fr-002-adapt-name}

<!-- ADAPT: Duplicate the FR-001 block above for each new functional requirement.
     Recommended: keep FRs small and testable (1 FR = 1 user capability). -->

**Priority**: [ADAPT: select P0, P1 or P2 from the supplied requirement priority; no default]
**Status**: Draft
**Linked Tasks**: [ADAPT: assignment unresolved]. Template candidate T-003; not an established assignment.
**Linked To**: [ADAPT: mapping unresolved]. Template candidates PAIN-1.2, SOL-1.2; not established mappings.
**ARCH Components**: [ADAPT: component mapping unresolved]. Template candidate ARCH-2; not an established component.

#### Description

[ADAPT]

#### Acceptance Criteria

| AC | Condition | Validation |
|----|-----------|------------|
| AC-002-1 | [ADAPT] | [ADAPT] |

#### Systemic Impacts

| Spec | Impact |
|------|--------|
| 04-architecture.md | [ADAPT] |

#### Independent Test

```bash
# ADAPT
pytest tests/unit/test_fr002.py -v
```

---

<!-- ADAPT: Continue adding FR-XXX sections following the same pattern -->

---

## Non-Functional Requirements

---

### NFR-001: Performance {#nfr-001-performance}

**Status**: Draft

**Target**: [ADAPT: e.g. "API P95 latency < 200ms under 1000 req/s"]

**Acceptance Criteria**:
- [ADAPT: e.g. Load test passing at defined SLA]

---

### NFR-002: Security {#nfr-002-security}

**Status**: Draft

**Target**: [ADAPT: e.g. "OWASP Top 10 — zero critical findings"]

**Acceptance Criteria**:
- [ADAPT: e.g. Security audit passed; no PII in logs; auth on all new endpoints]

---

<!-- ADAPT: Add NFR-003 (Reliability), NFR-004 (Scalability), etc. as needed -->
