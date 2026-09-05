# Integral Tutorial — Standard from Scratch

> _Installation path reverified with NAOS kit v1.1.0 candidate · 2026-09-05_

> **Profile**: `standard`
> **Effort basis**: Repository-specific; record actual setup, specification, task, and validation receipts
> **Goal**: Configure a Standard-profile evidence workflow and verify its project-specific results

---

## Evidence You Should Be Able to Evaluate

- The generated `standard` profile and its documented 19-rule, 13-blocking-posture configuration
- The profile-required spec structure, with completeness determined from filled project content rather than file presence
- Task/requirement links that remain unverified until their referenced code, tests, and evidence are checked
- Function-index and duplicate-risk review where project data exists
- Static conformance, validator, dashboard, and evidence-pack outputs with preserved gaps and unknowns
- Non-publishing NAOS control-plane CI using read-only repository permission; commands may write ephemeral runner evidence
- One bounded example workflow whose actual cadence and outcomes must be recorded by the adopter

---

## Prerequisites

- Python ≥ 3.11
- An absent path for the new project; add meaningful project code after activation
- A team or solo developer committing to using NAOS consistently
- Time to review the generated install set and adapt project specifications
- An AI coding assistant

Portable preview generation is exercised on Linux with Python 3.11. Managed
`--activate` mutation is currently supported only on Darwin ARM64 with CPython
3.11–3.13; Linux, Windows, and other unsupported tuples refuse before target
mutation. On an unsupported host, review an absent external `--preview-dir`
and perform activation later on a supported host.

---

## Part 1: Installation

### Step 1: Install

```bash
PROJECT=/path/to/your/new-project
PREVIEW=/tmp/naos-standard-preview
pip install naos-governance
naos-governance init "$PROJECT" --new --tier standard --archetype custom --backend static_only --preview-dir "$PREVIEW"
# Review $PREVIEW before the supported-host activation below.
naos-governance init "$PROJECT" --new --tier standard --archetype custom --backend static_only --activate
cd "$PROJECT"
```

### Step 2: Verify the full structure

```bash
ls .ai/                          # RULES.md (19 rules)
ls .github/prompts/              # Profile-generated prompt files; verify against the generated contract
ls naos/                         # Full PM infrastructure
ls naos/governance/              # Governance truth table + rules
ls specs/                        # Full spec kit (01–10)
ls templates/                    # All NAOS template files
ls scripts/workflows/            # Workflow automation scripts
ls .github/workflows/            # naos-control-plane-ci.yml
```

### Step 3: Activate hooks and verify

```bash
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

Test the hook:
```bash
git stash  # if you have uncommitted changes
git commit --allow-empty -m "test: verify pre-commit hook"
# Should see hook output with all sections passing
```

---

## Part 2: Spec Kit Setup

The spec kit is the foundation of spec-driven development. You need at minimum:

- `specs/01-problem.md` — problem statement
- `specs/02-solution.md` — solution approach
- `specs/03-requirements.md` — FR/NFR (authoritative source for all tasks)
- `specs/04-architecture.md` — system architecture

### Option A: Use the design prompt (recommended for new projects)

```
/naos-design
```

This prompt runs a PM-quality spec elicitation session. Answer the questions — the agent fills in the spec templates.

### Option B: Fill templates manually (existing projects)

Open each spec file and fill in the `[ADAPT]` sections:

```bash
# Work through specs in order
nano specs/01-problem.md
nano specs/02-solution.md
nano specs/03-requirements.md
nano specs/04-architecture.md
```

### FR/NFR structure in `specs/03-requirements.md`

The task registry links to requirements by ID. Use this format:

```markdown
## Functional Requirements

### FR-1: User Authentication
**Status**: In Progress
**Priority**: High
**Description**: The system must authenticate users via email/password.

#### Acceptance Criteria
- AC-1.1: Valid credentials return a JWT token
- AC-1.2: Invalid credentials return 401 with non-enumeration message
- AC-1.3: Tokens expire after 24 hours
```

---

## Part 3: Task Registry Setup

Open `naos/TASK_REGISTRY.yaml` and populate it with your initial task set:

```yaml
tasks:
  - id: T-001
    title: User authentication endpoint
    status: planned
    lifecycle_state: planned
    delivery_state: not_started
    verification_state: unverified
    requirement: FR-1
    estimated_days: 2
    owner: [your name]
    description: |
      Implement JWT-based authentication endpoint.
      POST /auth/login validates credentials and returns JWT.
    acceptance_criteria:
      - id: AC-1.1
        description: Valid credentials return JWT token
      - id: AC-1.2
        description: Invalid credentials return 401 (non-enumeration message)

  - id: T-002
    title: Session expiry enforcement
    status: planned
    lifecycle_state: planned
    delivery_state: not_started
    verification_state: unverified
    requirement: FR-1
    estimated_days: 1
    dependencies: [T-001]
    description: |
      Enforce JWT expiry — reject expired tokens with 401.
```

**Important**: Never invent task IDs. Add tasks here first; then reference them by ID everywhere else.

---

## Part 4: Run the Governance Bootstrap

```bash
# Build the function index (supports deterministic function discovery and duplicate-risk review)
python scripts/naos_function_index_query.py --rebuild-index

# Run governance refresh where project-specific PM artifacts are installed
make -f Makefile.naos gov-refresh

# Run the current deterministic readiness chain
naos claims --profile standard
naos setup-recommendations --profile standard
naos add setup-module deterministic_conformance_review --profile standard --dry-run
naos memory-readiness --profile standard
naos memory-access --profile standard
naos memory-use-policy --profile standard
naos task-context --task T-001 --profile standard --write-markdown
naos task-lifecycle --task T-001 --profile standard
naos context-index --profile standard
naos context-query --query "governance" --profile standard
naos semantic-candidates --profile standard
naos graph-context --profile standard
naos graph-query --task T-001 --profile standard
naos session-start --task T-001 --profile standard
naos session-checkpoint --task T-001 --profile standard
naos session-end --task T-001 --profile standard
naos evidence-attestation --profile standard
naos capability-maturity --profile standard
naos systemic-impact --profile standard
naos module-headers --profile standard
naos spec-pack-contract --profile standard
naos spec-pack-materialize . --profile standard --dry-run
naos spec-assembly-worksheet . --profile standard
naos spec-cascade --profile standard
naos control-plane-review --profile standard
naos self-check --profile standard
naos roadmap-crosswalk --profile standard
naos function-index-health --profile standard
naos test-evidence-map --profile standard
naos test-evidence --profile standard
naos ac-completion-evidence --profile standard
naos composed-traceability --profile standard
naos duplicate-function-hygiene --profile standard
naos secret-hygiene --profile standard
naos test-quality-hygiene --profile standard
naos dependency-integrity --profile standard
naos package-reality --profile standard
naos api-symbol-reality --profile standard
naos gate-status --profile standard
naos gate-evaluate --profile standard
naos evidence-pack --profile standard
naos dashboard --profile standard --json

# Run static conformance, including frontmatter checks for agents, skills, and instructions
make -f Makefile.naos naos-conformance
```

Record the initial dashboard/evidence posture in `naos/PROJECT_STATUS.md`. This is your baseline.

If conformance reports frontmatter failures, fix the reported `.agent.md`,
`SKILL.md`, or `*.instructions.md` metadata before treating the scaffold as
ready. See [Frontmatter Conformance](../FRONTMATTER_CONFORMANCE.md).

---

## Part 5: Your First Bounded Sprint

### Monday — Weekly Planning

```
/naos-w-plan

Week starting: 2026-03-25
Focus areas: User authentication (FR-1)
```

Review the daily breakdown and set priorities.

### Day 1, Morning — Session Start

```
/naos-d-start

Today I'm working on: T-001 user authentication endpoint
```

`@naos-plan` is instructed to review the relevant governance context and report
what it actually found, including:
- 19 rules
- `specs/03-requirements.md` (FR-1 requirements)
- `naos/TASK_REGISTRY.yaml` (T-001 details)
- All three AI instruction files

### Day 1 — Task Start

```
/naos-task-start T-001
```

`@naos-plan` is instructed to perform source-grounded research:
- Read T-001 from the registry
- Query the function index and source for existing auth-related functions
- Review the `specs/03-requirements.md` FR-1 section
- Propose or update `naos/active/T-001_user-auth-endpoint.md`

**Read the entire story card before coding.**

### Day 1 — Implementation

```
@naos-implement Implement the POST /auth/login endpoint per AC-1.1 and AC-1.2.

Story card constraints:
- Use UserRepository from src/repositories/user_repository.py
- Use JWTService from src/services/jwt_service.py
- Schema: users table (id, email, password_hash, created_at) — no new columns
```

Work through the implementation iteratively. Commit when a logical unit is complete:

```bash
git add src/auth/endpoint.py tests/test_auth.py
git commit -m "feat(T-001): implement POST /auth/login with JWT (AC-1.1, AC-1.2)"
```

The blocking-posture count shown above describes policy/human review, not
hook automation. Inspect the generated hook for its exact executable checks;
it contains no licence scanner.

### Day 1 — Review

```
@naos-review Review T-001 implementation

Acceptance criteria:
- AC-1.1: Valid credentials return JWT token
- AC-1.2: Invalid credentials return 401 (non-enumeration message)
```

In `standard` profile, the review includes:
- Function-index and duplicate-intent review where evidence exists
- Full spec alignment check
- Traceability verification
- Documentation impact assessment

Address all findings.

### Day 1 — Task Completion

Update the story card manually:

```markdown
## Completion Checklist
- [x] All acceptance criteria satisfied (AC-1.1, AC-1.2)
- [x] Tests written and passing
- [x] No schema violations introduced
- [x] No duplicate code created
- [x] Traceability headers added to new files
- [x] Move this card to naos/completed/ when done

## Implementation Notes

2026-03-25 — Task completed (git commit abc1234)
           ✅ AC-1.1: Valid credentials return JWT — implemented in src/auth/endpoint.py
           ✅ AC-1.2: 401 with "Invalid email or password" — non-enumeration message
           📝 Files: src/auth/endpoint.py, src/services/jwt_service.py, tests/test_auth.py
```

Run completion:

```
/naos-task-complete T-001
```

`@naos-conformance` is instructed to review the evidence and propose the
configured lifecycle action. Verify its report and make the human-owned
archive decision. Then:

```bash
make -f Makefile.naos gov-refresh
```

### Day 1 — Session End

```
/naos-d-end

Today's work:
- Completed: T-001 user auth endpoint
- In Progress: nothing
- Blockers: none
```

Run the closing commands from the agent's output.

### Friday — Weekly Review

```
/naos-w-review

Week of: 2026-03-25 to 2026-03-28
```

---

## Part 6: Measure Your Governance Evidence

After the first sprint:

```bash
make -f Makefile.naos gov-refresh
naos spec-pack-contract --profile standard
naos spec-pack-materialize . --profile standard --dry-run
naos spec-assembly-worksheet . --profile standard
naos spec-cascade --profile standard
naos evidence-pack --profile standard
naos dashboard --profile standard --json
```

Compare the dashboard/evidence output to your initial baseline (recorded in
Step 4). Do not infer improvement from completing the tutorial: record what
changed, what stayed unknown, and whether evidence freshness or findings
actually improved.

---

## Evidence to Verify

| Capability | Required verification |
|-----------|--------|
| Documented blocking posture (13 rules) | Confirm generated rules and configured consumers; this is not an executable-check count. |
| Spec-driven development | Inspect filled project specs and unresolved markers; generated files alone are insufficient. |
| Requirements traceability (FR→Task→Code→Test) | Validate each claimed link and its referenced evidence. |
| Function-index and duplicate-risk evidence | Confirm reports exist and match current project data. |
| Behavioral Governance Readiness | Treat as readiness metadata; a project-configured evaluator is required for behavior scoring. |
| Governance dashboard and evidence metrics | Confirm current reports, gaps, stale inputs, and unknowns. |
| Daily, weekly, and monthly cadence | Record only the cadences actually performed and reviewed. |
| Assured profile | Not implied by this tutorial; evaluate separately only where purpose-fit. |

---

## What to Do Next

For enterprise or regulated environments:

→ [Integral Tutorial: Standard → Assured Readiness and Upgrade Preview](./INTEGRAL_TUTORIAL_STANDARD_TO_ASSURED.md)

For assessing NAOS as a methodology kit:

→ [NAOS roadmap](../../ROADMAP.md) and [compliance mapping](../COMPLIANCE_MAPPING.md)
