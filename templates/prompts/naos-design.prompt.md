# /naos-design — Spec-by-Spec Design Elicitation

**Version**: 1.1.0
**Phase**: NAOS Lifecycle Phase 1 — Design (runs after `naos init --new`, before `/naos-task-start`)
**Usage**:
- `/naos-design`              → Profile-aware cascade from `spec_manifest.yaml`
- `/naos-design spec 03`      → Single spec elicitation (any spec 01-10)
- `/naos-design enhance`      → Revision mode — update a previously filled spec

**Relationships**:
- `/naos-design` ≠ `@naos-plan` — `/naos-design` is project-altitude (all specs, once); `@naos-plan` is task-altitude (one task at a time, repeatedly)
- `/naos-design` ≠ `naos-specify` — `/naos-design spec 03` orchestrates the full spec 03; `naos-specify` is surgical for one FR/NFR
- `/naos-design` PRECEDES coding — complete the profile-required specs before writing code

---

## 📥 Invocation Parameters

```
Target spec (optional): {{input:target_spec}}
```

If `target_spec` is empty → run **Full Cascade** for the profile-required specs declared in `spec_manifest.yaml`.
If `target_spec` is `enhance` → run **Revision Mode** (see bottom of this prompt).
If `target_spec` is a number (01–10) → run **Single Spec Mode** for that spec.

---

## 🗺️ NAOS Spec Map

| Spec | Title | Profile Requirement | Depends On |
|------|-------|:-------------------:|------------|
| 01 | Problem Statement | lite+ | — |
| 02 | Solution Overview | lite+ | spec 01 |
| 03 | Requirements (FR/NFR) | lite+ | spec 01, 02 |
| 04 | Architecture | standard+ | spec 03 |
| 05 | API Specification | standard+ | spec 03, 04 |
| 06 | Acceptance Criteria & Test Scenarios | standard+ | spec 03 |
| 07 | Cost Analysis | standard+ | spec 02 |
| 08 | Market Analysis | standard+ | spec 02 |
| 09 | Integration Contracts | standard+ | spec 04 |
| 10 | Execution & Delivery Plan | standard+ | spec 03, 04 |

**Profile paths**:
- quickstart: no required spec pack.
- lite: fill 01 → 02 → 03.
- standard/assured: keep and fill 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10. If a standard/assured topic is not relevant to the product, record that non-applicability inside the file while preserving the manifest-defined structure and anchors.

Before creating or revising specs, locate and read `specs/spec_manifest.yaml`
when present; otherwise read the source manifest under
`naos/spec_templates/spec-kit/specs/spec_manifest.yaml` or
`templates/spec-kit/specs/spec_manifest.yaml`. Preserve manifest-declared
filenames, sections, anchors, sync markers, and traceability codes such as
PAIN, SOL, FR/NFR, ARCH, API, AC, SCEN, COST, MKT, INT, EXEC, and TASK.

Suggested elicitation order for standard/assured is 01 → 02 → 03 → 04, then
triage 05-09 from the project facts, then complete 10. This order does not make
05-09 optional files in standard or assured profiles.

---

## 🔁 Full Cascade Mode

> Run this mode when `target_spec` is empty.

Work through each profile-required spec in order. For each spec:
1. **Tell** the user which spec you're filling and why it matters.
2. **Ask** the 3-5 elicitation questions listed below.
3. **Fill** the spec template sections based on answers.
4. **Run the quality gate** before advancing to the next spec.
5. **Carry forward** key decisions to inform questions for the next spec.

After completing spec 04 in standard/assured, triage specs 05-09 before filling
spec 10. Fill applicable content where the topic applies; otherwise write an
explicit non-applicability rationale inside the file.
After creating or revising specs, run or recommend
`naos spec-pack-contract --profile <profile>` before cascade review. If
profile-required files may be missing, use
`naos spec-pack-materialize . --profile <profile> --dry-run` and ask before
copying. If brownfield/candidate evidence exists, use
`naos spec-assembly-worksheet . --profile <profile>`. Before planning or coding,
run `--mode filled`. Standard/assured keep all ten spec files and record
non-applicability in-file. Reports are review evidence only, not proof of
quality, completeness, approval, implementation, traceability, certification, or
compliance.

---

## 📋 Spec Elicitation Playbooks

### Spec 01 — Problem Statement

**Purpose**: Define the problem space with precision. Everything downstream (solution, requirements, architecture) flows from this.

**Before asking questions**, read `specs/01-problem.md` if it exists.
Check if the file has been partially filled (look for `[ADAPT` markers not yet replaced).

**Questions**:

1. **Who suffers the problem?** Describe the primary user role and the type of organisation they work in. Be specific — not "developers" but "backend engineers at regulated financial firms with 50-500 employees."

2. **What breaks without your product?** What is the concrete failure mode or gap today? Describe what happens when the problem is NOT solved — real workflows blocked, real cost incurred, real risk materialised.

3. **What metric proves the problem exists?** Quote a statistic, survey result, or observable signal. Avoid phrases like "many organisations" — give a number.

4. **Why do existing solutions fail?** Name 2-3 existing approaches and explain exactly WHY each fails for your target user. (This carves your differentiation niche.)

5. **What is the root cause?** Not just the symptom — what structural or systemic factor creates this problem? (This informs whether a product fix is durable or band-aid.)

**Fill into**: `specs/01-problem.md` — sections: Executive Summary, Problem Statement, Target Users (if present), Evidence.

**Carry forward to spec 02**: The specific user role, the core failure mode, and the metric evidence.

**Quality Gate (01 → 02)**:
- [ ] Executive Summary is 3-5 sentences and mentions WHO, WHAT, WHY
- [ ] At least one quantitative metric is present
- [ ] At least 2 existing solutions are named and their failure mode explained
- [ ] No remaining `[ADAPT` placeholders in critical sections

---

### Spec 02 — Solution & Value Proposition

**Purpose**: Define what you are building and why users will choose it over alternatives.

**Carry-in from spec 01**: User role ({{carry:spec01_user}}), failure mode ({{carry:spec01_failure_mode}}).

**Questions**:

1. **What is the one-sentence product promise?** Complete: "For [user from spec 01], [product name] is the [category] that [key benefit] unlike [alternative], because [differentiator]."

2. **What are the 3 most critical capabilities?** Not features — capabilities. What must the product DO (at a high level) to deliver the promise? Rank by importance.

3. **What is explicitly OUT of scope (v1)?** Every product promise must have a boundary. What are you NOT building in the first version — and why?

4. **How does value flow to the user?** Describe the workflow: [user does X] → [system does Y] → [user gets Z]. This becomes the backbone of spec 03 user stories.

**Fill into**: `specs/02-solution.md` — sections: Value Proposition, Core Capabilities, Out of Scope, User Value Flow.

**Carry forward to spec 03**: The 3 core capabilities (each becomes a candidate FR cluster), the out-of-scope list (filters invalid requirements), the value flow (becomes acceptance scenario backbone).

**Quality Gate (02 → 03)**:
- [ ] Value proposition follows the [user/product/category/benefit/differentiator] structure
- [ ] 3 core capabilities listed with explicit priority ranking
- [ ] Out-of-scope list is explicit (minimum 3 items)
- [ ] Value flow is specific enough to derive testable scenarios

---

### Spec 03 — Requirements Specification

**Purpose**: Enumerate all functional and non-functional requirements. This is the contract between PM and engineering.

> **Integrated with `naos-specify`**: For each FR/NFR generated, apply the full `naos-specify` pattern (collision avoidance, priority, user story, acceptance scenarios, technical constraints).

**Carry-in from spec 02**: Core capabilities ({{carry:spec02_capabilities}}), value flow ({{carry:spec02_value_flow}}).

**Questions**:

1. **Map capabilities to FRs.** For each core capability from spec 02, ask: "What must the system DO for this capability to be delivered?" Each answer is a candidate FR. Group related actions under one FR if they form a cohesive unit.

2. **What are the P0 requirements?** A P0 means: "If this isn't working, the product cannot ship." List them first. (Typical: auth, data integrity, core business logic.)

3. **What are the critical non-functional requirements?** For each: performance target, security requirement, availability requirement, and reliability expectation. Be concrete — not "fast" but "p99 < 200ms for search queries."

4. **What can fail gracefully vs. what must never fail?** This carves your NFR-reliability and NFR-resilience requirements.

5. **What does done look like?** For the 3 most important FRs — describe a concrete scenario where a real user achieves real value. (These become acceptance scenarios in spec 06.)

**FR/NFR Generation**:

For each identified requirement, generate a full spec entry following this structure:

```markdown
## FR-XXX: [Concise Title]

**Priority**: P[0|1|2]
**Status**: 📋 SPECIFIED
**Dependencies**: [FR/NFR IDs]

### User Story
**As a** [role from spec 01]
**I want** [capability]
**So that** [outcome linked to problem from spec 01]

### Acceptance Scenarios

**Scenario 1: Happy Path**
- **Given** [precondition]
- **When** [action]
- **Then** [expected outcome]

**Scenario 2: Failure Mode**
- **Given** [precondition]
- **When** [edge case action]
- **Then** [graceful handling]
```

> **Collision check**: Before assigning IDs, run: `python scripts/naos_extract_spec_section.py --list-requirements`
> If script not available, scan `specs/03-requirements.md` for the highest existing FR/NFR number.

**Fill into**: `specs/03-requirements.md` — Table of Contents index + full FR/NFR sections.

**Carry forward to spec 04**: FR IDs by subsystem/domain (these become architecture components), P0 requirements (these become architecture constraints), NFR performance targets (become architecture decisions).

**Quality Gate (03 → 04)**:
- [ ] At least 3 FRs with full user story + 2 scenarios each
- [ ] At least 2 NFRs (performance + security minimum)
- [ ] All P0 FRs have "must never fail" failure scenarios
- [ ] Each FR traces back to a capability from spec 02
- [ ] No FR ID collisions with existing requirements

---

### Spec 04 — Architecture

**Purpose**: Make spec 03 implementable and material technology choices
reviewable by a human; this is not selection or approval.

**Carry-in from spec 03**: FR clusters ({{carry:spec03_fr_clusters}}), P0 constraints ({{carry:spec03_p0}}), NFRs ({{carry:spec03_nfr}}).

**Before questions**: Read specs 01–04 and relevant ADR, research, inventory,
source, and deployment evidence. Challenge unsupported claims; classify
`greenfield`/`brownfield` per boundary; label facts, owner constraints,
inferences, assumptions, recommendations, and unknowns. Ask only material gaps.
For unknowns, offer bounded options, a recommendation, and consequences; the
human accepts, revises, or defers.

**Questions** (group them into 3–5 conversational prompts):

1. **Decision** — owner, scope, changed result, hard constraints/preferences.
2. **Envelope** — users/load/growth, service levels, tenancy, privacy/regulation,
   AI/integrations, deployment, skills, cost, operations.
3. **Shape** — style, FR/NFR components, P0 flow/state/trust/failures, 3–5 invariants.
4. **Options** — identity/version, source/date, constraint result, trade-offs,
   uncertainty, counterargument, smallest alternative. Unknown is not pass and
   soft scores cannot offset hard conflict. Use owner-authorized `@naos-research`
   for current external facts.
5. **Transition/outcome** — Brownfield: disposition, compatibility, migration/
   coexistence, rollback/regression, decommission. Greenfield: N/A rationale.
   The human selects/rejects/defers; AI recommends only.

**Fill into**: `specs/04-architecture.md`; preserve all manifest-required fields.

**Carry forward to spec 10**: Components, choices/skills/vendor risks, and invariants/gates.

**Quality Gate (04 → 10)**:
- [ ] Components map to FRs; data flow covers the P0 journey
- [ ] Choices record identity/version, source/date, constraint result, uncertainty, human outcome, and rationale
- [ ] Unknowns/conflicts remain visible; recommendations are not approval
- [ ] Brownfield transition evidence is complete per boundary, or greenfield records N/A rationale
- [ ] At least 3 invariants; no component is responsible for everything
- [ ] Spec 04 links—or records gaps—to upstream specs, task/traceability records, capabilities, gate/evidence expectations, risks, and gaps
- [ ] Any research/autoresearch/trend-review finding that changes architecture is routed into specs, task registry, capability contracts, systemic impact review, gate/evidence expectations, known gaps, residual risks, evidence pack, dashboard, or next action as appropriate

---

### Spec 10 — Execution & Delivery Plan

**Purpose**: Translate specs 03 and 04 into a phased delivery plan with clear exit criteria.

**Carry-in from spec 04**: Component list ({{carry:spec04_components}}), technology choices ({{carry:spec04_tech}}).

**Questions**:

1. **What is the smallest viable first phase?** Which FRs from spec 03 must be working before you can get real user feedback? This is Phase 1. It should take ≤4 weeks.

2. **What is the dependency order?** Cannot authenticate until the user model exists. Cannot persist data until the schema is defined. Draw the dependency order of your FRs.

3. **What are the phase exit criteria?** For each phase, what is the observable outcome that tells you it's done? ("Phase 1 is done when: a user can [action] and [outcome] is verified.")

4. **What are the top 3 delivery risks?** For each: what could delay it, and what is the mitigation strategy?

5. **Who does what?** If you have a team, which roles own which phases (PM, backend, frontend, data, DevOps)?

**Fill into**: `specs/10-execution.md` — sections: Phase Overview, Task Matrix (seed with initial tasks), Risk Register.

**Quality Gate (spec 10 complete)**:
- [ ] At least 2 delivery phases defined with distinct exit criteria
- [ ] Each phase lists the FRs it delivers
- [ ] Top 3 risks have explicit mitigations
- [ ] Phase 1 timeline is ≤4 weeks (if longer, split it)

---

## 🔄 Profile-Conditional Specs — Applicability Triage (05-09)

After completing spec 04 in standard/assured, ask the user:

> "Specs 05-09 are profile-required in standard and assured. Based on your architecture and requirements, which ones have applicable product content, and which should record a non-applicability rationale?"

| Spec | Offer if... | What it covers |
|------|------------|----------------|
| `05-api.md` | spec 04 includes an API layer | Endpoint contracts, request/response schemas, auth |
| `06-acceptance.md` | spec 03 has testable scenarios | Test strategy, fixtures, coverage targets |
| `07-cost-analysis.md` | spec 02 mentions monetisation or SaaS | Unit economics, pricing model, cost drivers |
| `08-market-analysis.md` | this is a product (not internal tool) | TAM/SAM/SOM, competitors, positioning |
| `09-integration-contract.md` | spec 04 has external API calls | Integration schemas, versioning, vendor SLAs |

For each applicable standard/assured spec, run the same **ask → fill → quality
gate** cycle. For each non-applicable standard/assured spec, preserve the
required structure and anchors while recording why it is not applicable to this
product. Each profile-conditional spec playbook uses 3 targeted questions
derived from the already-filled core specs.

### Spec 05 — API Design (Contextual)

**Questions**:
1. For each P0 FR that involves external access: what is the HTTP method, path, request body, and response shape?
2. What authentication mechanism does every endpoint require? (Bearer token, API key, session cookie?)
3. What are the error contract standards? (Status codes, error body shape, retry-safe vs. non-retry-safe errors.)

**Quality Gate**: At least 3 endpoints documented with request/response examples; auth dependency specified on every endpoint; error contracts defined.

### Spec 06 — Acceptance Testing Strategy (Contextual)

**Questions**:
1. What are the 5 most important user journeys to cover with integration tests?
2. What is the test data strategy? (Fixtures, factories, real DB snapshots?)
3. What does "green CI" mean? What is the minimum test gate before a PR can merge?

**Quality Gate**: Test pyramid defined (unit/integration/e2e split); 5 journeys mapped to FR IDs; CI gate is explicit.

### Spec 09 — Integration Contracts (Contextual)

**Questions**:
1. List every external service your system calls. For each: name, purpose, authentication method, and SLA.
2. What happens when each external service is unavailable? (Fail-fast? Degrade gracefully? Cache last-known-good?)
3. Which integrations are P0 (the product cannot function without them)?

**Quality Gate**: Every external dependency listed with SLA and failure behaviour; P0 integrations identified; no external call left uncontracted.

---

## ✅ Post-Cascade Quality Summary

After completing all selected specs, produce a summary:

```
## Spec Design Session Complete

**Specs filled**: [list]
**Specs deferred**: [list with reason]

**Key decisions made**:
- Problem: [one-sentence from spec 01]
- Solution: [value proposition from spec 02]
- Core FRs: [FR-001, FR-002, FR-003, ...]
- Architecture: [top-level shape from spec 04]
- Delivery: [Phase 1 target and exit criteria from spec 10]

**Open questions / deferred decisions**:
- [Any section left as placeholder — with a note on when to resolve]

**Next step**: Run `/naos-task-start` to begin implementing FR-001.
Note: You can re-run `/naos-design spec XX` at any time to enhance a specific spec.
```

---

## 🔁 Revision Mode (`/naos-design enhance`)

Use this when you want to update a spec that has already been filled.

**Process**:
1. Read the target spec file.
2. Identify sections with `[ADAPT` placeholders (unfilled) vs. sections that have substantive content (filled but possibly outdated).
3. Ask the user: *"What changed that requires this update? (New requirement discovered, scope change, architecture pivot?)"*
4. Apply targeted updates to the affected sections only — do NOT re-elicit unchanged sections.
5. Re-run the quality gate for the updated spec.
6. If the change ripples downstream (e.g., spec 03 change affects spec 04), flag it: *"This change to spec 03 may affect spec 04 section [X]. Do you want to update that now?"*

---

## 📌 Design Philosophy Notes

> These are for the AI operating this prompt — not surfaced to users unless asked.

- **Specs drive tech, not vice versa.** Never suggest a technology during spec elicitation. Technology appears in spec 04, after the WHAT (spec 03) is locked.
- **Each spec has one owner**: spec 01-02 = PM altitude; spec 03-04 = tech lead altitude (but elicited collaboratively); spec 10 = delivery manager altitude.
- **Questions should cascade.** The answer to "who suffers the problem" (spec 01) should appear in the user story preamble of spec 03. Make those connections explicit.
- **Quality gates are non-negotiable.** If a gate fails, fix the spec before advancing. Don't generate fake content to pass a placeholder check.
- **[ADAPT] is a red flag, not a destination.** A spec with `[ADAPT]` markers is not filled. The goal is zero `[ADAPT]` markers in mandatory specs before coding starts.
