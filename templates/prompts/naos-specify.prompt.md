# Specify Feature — Generate FR/NFR Section

**Version**: 1.0.0
**Usage**: Transform a natural-language feature idea into a formal FR/NFR section
matching `specs/03-requirements.md` format.

---

## Feature Idea

{{input:feature_description}}

---

## Workflow

### Step 1: Collision Avoidance

Before generating, determine the next available ID:

```bash
python scripts/naos_extract_spec_section.py --list-requirements
```

- For functional requirements: use the next `FR-XXX` number
- For non-functional requirements: use the next `NFR-XXX` number
- **NEVER** reuse an existing ID

### Step 2: Classify the Requirement

Determine:
- **Type**: FR (functional) or NFR (non-functional)
- **Priority**: P0 (MUST — blocks production), P1 (SHOULD — high impact), P2 (NICE — quality enhancement)
- **System Scope**: `[ADAPT: your system scopes, e.g., CORE|PLATFORM|EXTENSION|CROSS-CUTTING]`
- **Dependencies**: Which existing FR/NFR does this depend on or affect?

### Step 3: Research Context (Rule 7 — Evidence-First)

Before writing the spec, gather evidence:

1. **Problem validation**: Why is this needed? What real data or constraint validates it?
2. **Existing coverage**: `grep -r "keyword" specs/03-requirements.md` — is this already covered?
3. **Architecture fit**: Read `specs/04-architecture.md` — which ARCH components are affected?
4. **Code impact**: `grep -r "keyword" [ADAPT: your source dir]/` — what existing code relates to this?
5. **Existing functions**: `python scripts/naos_function_index_query.py --similar "{{input:feature_description}}"` — what already exists?
6. **Control-plane routing**: if research, autoresearch, trend-review, repo-review, or external analysis produced this feature, identify which capability, policy, gate, validator, roadmap/crosswalk, task, known gap, residual risk, evidence pack, dashboard, instruction surface, or spec 01-04 update should receive the finding.

### Step 4: Generate Spec Section

Produce a complete section using this EXACT structure. Every subsection is **mandatory**.

```markdown
## [FR|NFR]-XXX: [Concise Title]

**Priority**: P[0|1|2] ([Critical|High|Enhancement])
**Status**: 📋 SPECIFIED
**System Scope**: [ADAPT: your scope tags]
**Dependencies**: [List dependent FR/NFR IDs]

### User Story (Spec-Kit Enhanced)

**As a** [specific role at a specific type of organization]
**I want** [concrete capability with measurable attributes]
**So that** [business outcome tied to a real pain point from specs/01-problem.md]

**Priority Rationale**: **P[X] ([Level])** — [Why this priority? What breaks without it?]

**Independent Test**: [One sentence describing how to verify this in isolation]

### Acceptance Scenarios (Given/When/Then)

**Scenario 1: [Happy Path Name]**
- **Given** [precondition]
- **When** [action]
- **Then** [expected outcome]
- **And** [additional outcomes]

**Scenario 2: [Edge Case / Failure Mode]**
- **Given** [precondition]
- **When** [action]
- **Then** [expected behavior]

[Add 2-4 scenarios covering: happy path, edge case, failure mode, security]

### Acceptance Criteria (Checklist)

**MUST HAVE (P0):**
- [ ] [Criterion 1 — measurable, testable]
- [ ] [Criterion 2]

**SHOULD HAVE (P1):**
- [ ] [Criterion 3]

**NICE TO HAVE (P2):**
- [ ] [Criterion 4]

### Technical Specifications

```yaml
[component_name]:
  [key technical parameters with concrete values]
  [data formats, protocols, thresholds]
  [integration points]
```

### Systemic Impacts (Coherence Analysis)

**Upstream Impacts** (How other docs influence this FR):
- **01-problem.md**: [Which pain point does this address?]
- **02-solution.md**: [Which architectural constraint applies?]

**Downstream Impacts** (How this FR influences other docs):
- **04-architecture.md**: [Schema/component changes needed]
- **05-api.md**: [New or modified endpoints]
- **06-acceptance.md**: [New acceptance scenarios to add]

**Horizontal Impacts** (Peer FRs):
- **FR-XXX**: [Dependency or interaction description]

### Traceability

**ARCH Components**: [ARCH-X, ARCH-Y from specs/04-architecture.md]

**Impacts**:
- [FR/NFR that this requirement affects]

**Related**:
- [FR/NFR with mutual dependencies]

**Enables**:
- [Downstream capabilities unlocked by this requirement]

**Blocks**:
- [What cannot proceed without this requirement]
```

### Step 5: Validate Output

Before presenting the spec section, verify:

```
□ `specs/spec_manifest.yaml` was read when present, and the generated section preserves manifest-defined requirement structure and reference codes
□ ID does not collide with existing FR/NFR (Step 1 check)
□ User Story follows As-a/I-want/So-that format with specific role
□ ≥2 BDD scenarios with Given/When/Then structure
□ AC split into MUST/SHOULD/NICE with measurable criteria
□ Technical Specs include concrete values (not vague)
□ Systemic Impacts reference real spec files (01-08)
□ Traceability maps to real PAIN, SOL, ARCH, FR/NFR, AC/SCEN, and task references where those source artifacts apply to the active profile
□ Independent Test is verifiable in isolation
□ No overlap with existing requirements (Step 3 check)
□ Follows Evidence-First principle (Rule 7) — claims backed by data
□ If architecture changes are implied, spec 04 linkage to specs 01-03, task registry, traceability, capabilities, gates/evidence, known gaps, and residual risks is recorded or explicitly missing
```

### Step 6: Suggest Next Steps

After generating the spec section, recommend:

1. **Add to `specs/03-requirements.md`** at the appropriate position (after last FR/NFR)
2. **Create task(s)** in `naos/TASK_REGISTRY.yaml` to implement the requirement
3. **Update `specs/10-execution.md`** task matrix if needed
4. **Run `naos spec-pack-contract --profile <profile>`** if spec structure or reference codes changed
5. **Run `naos spec-pack-materialize . --profile <profile> --dry-run`** if the active profile requires spec files that are missing; copy only after human review
6. **Run `naos spec-assembly-worksheet . --profile <profile>`** if brownfield adoption evidence, candidate requirements, or traceability gaps need to be mapped into specs
7. **Run `make -f Makefile.naos gov-refresh`** only when the implementing agent confirms it is installed and safe for the checkout; otherwise run the relevant bounded validators such as `naos spec-cascade`, `naos evidence-pack`, and `naos dashboard`

---

## Output Format

Present the generated spec section as a Markdown code block ready to paste into
`specs/03-requirements.md`. Include a brief summary of:
- Collision check results (which IDs were considered)
- Evidence gathered (what existing code/specs were checked)
- Recommended insertion point in `specs/03-requirements.md`

---

## Reference

- **Spec format**: `specs/03-requirements.md` (use existing requirements as exemplars)
- **ARCH components**: `specs/04-architecture.md` (ARCH-1 through ARCH-N)
- **ID collision check**: `scripts/naos_extract_spec_section.py --list-requirements`
- **Governance rules**: `.ai/RULES.md` Rule 7 (Deep Analysis), Rule 16 (Spec Alignment)
- **Anti-duplication**: `.ai/RULES.md` Rule 11, `scripts/naos_function_index_query.py`
