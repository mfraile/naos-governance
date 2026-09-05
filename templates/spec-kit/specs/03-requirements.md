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

---

### FR-001: [ADAPT: Requirement Name] {#fr-001-adapt-name}

**Priority**: P0 / P1 / P2  <!-- ADAPT -->
**Status**: Draft  <!-- Auto-updated by gov-refresh via TASK_REGISTRY.yaml -->
**Linked Tasks**: T-001, T-002  <!-- ADAPT: list after tasks are defined -->
**Linked To**: PAIN-1.1, SOL-1.1, R-001  <!-- ADAPT: from 01-problem.md and 02-solution.md -->
**ARCH Components**: ARCH-1, ARCH-2  <!-- ADAPT: from 04-architecture.md after architecture is drafted -->

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

**Priority**: P1
**Status**: Draft
**Linked Tasks**: T-003
**Linked To**: PAIN-1.2, SOL-1.2
**ARCH Components**: ARCH-2

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
