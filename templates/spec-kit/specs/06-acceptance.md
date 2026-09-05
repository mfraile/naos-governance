# 06 - Acceptance Criteria & Test Scenarios

**Version**: 0.1.0
**Status**: Draft
**Upstream**: [03-requirements.md](./03-requirements.md), [05-api.md](./05-api.md)

<!-- ADAPT: Gherkin-style acceptance scenarios that validate functional requirements.
     Every FR-XXX in 03-requirements.md should have at least 1 SCEN-N.M here.
     These scenarios drive automated acceptance tests in tests/acceptance/. -->

---

## Scenario Conventions

- `SCEN-N.M` — N is the FR number (1, 2...), M is the scenario number within that FR
- Each scenario has a `Requirement` pointer back to 03-requirements.md
- Scenarios use standard Gherkin: `Given / When / Then / And`

---

## FR-001 Scenarios {#scen-1}

### SCEN-1.1: [ADAPT: Happy path scenario name] {#SCEN-1.1}

**Requirement**: FR-001
**Priority**: P0

```gherkin
Scenario: [ADAPT: Short description — e.g. "User creates a new item with valid data"]
  Given [ADAPT: precondition — e.g. "an authenticated user with writer role"]
  When [ADAPT: action — e.g. "they POST /items with valid payload"]
  Then [ADAPT: outcome — e.g. "the response is 201 with the created item"]
   And [ADAPT: additional assertion — e.g. "the item is persisted in the database"]
```

---

### SCEN-1.2: [ADAPT: Error scenario name] {#SCEN-1.2}

**Requirement**: FR-001
**Priority**: P1

```gherkin
Scenario: [ADAPT: e.g. "Unauthenticated request is rejected"]
  Given [ADAPT: e.g. "a request with no Authorization header"]
  When [ADAPT: e.g. "they POST /items"]
  Then [ADAPT: e.g. "the response is 401 Unauthorized"]
```

---

## FR-002 Scenarios {#scen-2}

### SCEN-2.1: [ADAPT] {#SCEN-2.1}

**Requirement**: FR-002
**Priority**: P1

```gherkin
Scenario: [ADAPT]
  Given [ADAPT]
  When [ADAPT]
  Then [ADAPT]
```

---

<!-- ADAPT: Add SCEN-N.M blocks for each FR, covering:
     - Happy path (SCEN-N.1)
     - Boundary conditions (SCEN-N.2)
     - Error cases (SCEN-N.3)
     - Security / auth (SCEN-N.4)
     Aim for ≥2 scenarios per FR for adequate coverage. -->

---

## Multi-Tenant / Security Scenarios {#scen-security}

<!-- ADAPT: Include these scenarios if your product is multi-tenant or has strict auth requirements.
     Delete this section if not applicable. -->

### SCEN-S.1: Tenant isolation enforced {#SCEN-S.1}

**Requirement**: NFR-002 (Security)
**Priority**: P0

```gherkin
Scenario: Tenant A cannot read Tenant B's data
  Given Tenant A is authenticated
  When Tenant A requests a resource belonging to Tenant B
  Then the response is 404 (not 403 — avoid information disclosure)
```

---

## Performance Scenarios {#scen-perf}

<!-- ADAPT: Define load test acceptance criteria.
     Delete if not relevant for your project maturity. -->

### SCEN-P.1: API latency under load {#SCEN-P.1}

**Requirement**: NFR-001 (Performance)

```gherkin
Scenario: System handles target load within SLA
  Given [ADAPT: N concurrent users]
  When they send [ADAPT: request type] for [ADAPT: duration]
  Then P95 latency is below [ADAPT: Xms]
   And error rate is below [ADAPT: X%]
```
