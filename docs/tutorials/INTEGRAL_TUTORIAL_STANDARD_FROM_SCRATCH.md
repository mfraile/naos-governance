# Integral Tutorial — Standard from Scratch

> _Source-reviewed against the remediated candidate · 2026-10-18. See [verification scope](./README.md#verification-scope)._

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

Native macOS ARM64/APFS, Ubuntu x86_64/ext4 and Windows 11 x86_64/NTFS
have recorded Python 3.11–3.13 installation checks and selected workflow and
recovery evidence. These are separate checks: qualification for an activation,
update or receiving operation depends on its named route and evidence, not
only the operating system. Linux aarch64 is not qualified. Before activation,
check the [platform evidence and limits](../PLATFORM_ADAPTERS.md).
Preview generation and package installation
do not qualify filesystem recovery. On unsupported hosts, review an absent
external `--preview-dir` without activating.

---

## Part 1: Installation

### Step 1: Install

```bash
PROJECT=/path/to/your/new-project
PREVIEW=/tmp/naos-standard-preview
# First complete artifact acquisition in INSTALLATION_MANUAL.md.
naos-governance init "$PROJECT" --new --tier standard --archetype custom --backend static_only --preview-dir "$PREVIEW"
# Review $PREVIEW before the supported-host activation below.
naos-governance init "$PROJECT" --new --tier standard --archetype custom --backend static_only --activate
cd "$PROJECT"
```

### Step 2: Verify the full structure

```bash
ls .ai/                          # RULES.md (19 rules)
ls .github/prompts/              # VS Code Local prompt files; verify against the generated contract
ls naos/                         # Full PM infrastructure
ls naos/governance/              # Governance truth table + rules
ls specs/                        # Full spec kit (01–10)
ls templates/                    # Profile-selected templates, not the full kit catalogue
ls scripts/workflows/            # Workflow automation scripts
ls .github/workflows/            # naos-control-plane-ci.yml
```

### Step 3: Activate hooks and verify

Create the Git repository before configuring repository-local hooks. Configure
your Git author identity if needed before making a commit.

```bash
git init
chmod +x .githooks/pre-commit
git config --local core.hooksPath .githooks
```

These are opt-in POSIX-shell commands for this new repository. On native
Windows, use Git for Windows Bash and set `NAOS_PYTHON` to the absolute path
of the selected native Python executable before committing, using forward
slashes (for example, `export NAOS_PYTHON='C:/path/to/python.exe'`). The hook
refuses a Windows commit without that explicit interpreter. This Bash syntax
is not PowerShell syntax; no WSL or global Git change is required. Preserve
any existing effective hook configuration rather than replacing it.

Test the hook:
```bash
# In an existing repository with commits, stash unrelated changes if needed.
# A newly initialized repository has no commit to stash against.
git commit --allow-empty -m "test: verify pre-commit hook"
# Inspect the actual exit code and findings; unfinished seeds may warn or fail.
# Do not bypass a failure or treat this smoke as project readiness.
```

---

## Part 2: Spec Kit Setup

Start design with the four files below. Standard installs the full 01–10 pack;
retain its manifest, sections, IDs and anchors. Before claiming implementation
readiness, fill and check the complete profile-required pack and resolve the
applicable project decisions. An initial Draft or structural pass is not that
readiness evidence:

- `specs/01-problem.md` — problem statement
- `specs/02-solution.md` — solution approach
- `specs/03-requirements.md` — FR/NFR (authoritative source for all tasks)
- `specs/04-architecture.md` — system architecture

### Option A: Use the design prompt (recommended for new projects)

In a VS Code **Local** agent session, invoke the generated prompt:

```text
/naos-design
```

VS Code **Agent Host** does not load prompt files. For that session, or when
command discovery is unavailable, read root `AGENTS.md`, then explicitly open
`.agents/skills/naos-workflow-design/SKILL.md` and ask the assistant to follow
that file for the design session. This portable file is generated for Standard;
manual reading does not depend on host skill discovery.

The design guidance elicits the project specifications. Answer the questions and
review the filled spec templates. Reading or invoking the guidance grants no
additional execution or approval authority. See
[generated project host routes](../TOOL_NEUTRAL_USAGE.md#generated-project-host-routes)
for the host compatibility limits.

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

The task registry links to requirements by ID. Adapt the existing FR-001
block in place, preserving its exact explicit anchor and other required fields.
This fragment illustrates requirement content, not a replacement for the whole
file. P1 is an example project decision, not a default. Leave unknown mappings
visibly unresolved and keep the document Draft until they are supported:

```markdown
## Functional Requirements

### FR-001: User Authentication {#fr-001-adapt-name}
**Priority**: P1
**Status**: Draft
**Linked Tasks**: [ADAPT: confirm the task assignment]
**Linked To**: [ADAPT: confirm problem and solution mappings]
**ARCH Components**: [ADAPT: confirm architecture mappings]

#### Description
The system must authenticate users via email/password.

#### Acceptance Criteria
- AC-001-1: Valid credentials return a JWT token
- AC-001-2: Invalid credentials return 401 with non-enumeration message
- AC-001-3: Tokens expire after 24 hours
```

---

## Part 3: Task Registry Setup

Adapt the existing T-001/T-002 seed entries in `naos/TASK_REGISTRY.yaml`; do
not append duplicate IDs or discard unrelated entries and top-level controls.
The fragment assumes FR-001 and the named ACs have been authored and the task
assignments reviewed. Keep estimates, owner and priority project-specific:

```yaml
tasks:
  - id: T-001
    title: User authentication endpoint
    status: planned
    lifecycle_state: planned
    delivery_state: not_started
    verification_state: unverified
    requirement: FR-001
    estimate_days: 2
    owner: "[your name]"
    description: |
      Implement JWT-based authentication endpoint.
      POST /auth/login validates credentials and returns JWT.
    acceptance_criteria:
      - id: AC-001-1
        description: Valid credentials return JWT token
      - id: AC-001-2
        description: Invalid credentials return 401 (non-enumeration message)

  - id: T-002
    title: Session expiry enforcement
    status: planned
    lifecycle_state: planned
    delivery_state: not_started
    verification_state: unverified
    requirement: FR-001
    estimate_days: 1
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

For an optional frozen selection and checkpoint/completion comparison, follow [Selected task-context integrity](../TASK_CONTEXT_INTEGRITY.md). Select relevant inputs and intended output changes explicitly; the default tutorial does not require this contract or establish host delivery.


Record the initial dashboard/evidence posture in `naos/PROJECT_STATUS.md`. This is your baseline.

If conformance reports frontmatter failures, fix the reported `.agent.md`,
`SKILL.md`, or `*.instructions.md` metadata before treating the scaffold as
ready. See [Frontmatter Conformance](../FRONTMATTER_CONFORMANCE.md).

---

## Part 5: Your First Bounded Sprint

### Monday — Weekly Planning

```
/naos-w-plan

Week starting: 2026-03-23
Focus areas: User authentication (FR-001)
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
- `specs/03-requirements.md` (FR-001 requirements)
- `naos/TASK_REGISTRY.yaml` (T-001 details)
- All three AI instruction files

### Day 1 — Task Start

```
/naos-task-start T-001
```

`@naos-plan` is instructed to perform source-grounded research:
- Read T-001 from the registry
- Query the function index and source for existing auth-related functions
- Review the `specs/03-requirements.md` FR-001 section
- Propose or update `naos/active/T-001_user-auth-endpoint.md`

**Read the entire story card before coding.**

### Day 1 — Implementation

```
@naos-implement Implement the POST /auth/login endpoint per AC-001-1 and AC-001-2.

Story card constraints:
- Use UserRepository from src/repositories/user_repository.py
- Use JWTService from src/services/jwt_service.py
- Schema: users table (id, email, password_hash, created_at) — no new columns
```

Work through the implementation iteratively. Commit when a logical unit is complete:

```bash
git add src/auth/endpoint.py tests/test_auth.py
git commit -m "feat(T-001): implement POST /auth/login with JWT (AC-001-1, AC-001-2)"
```

The blocking-posture count shown above describes policy/human review, not
hook automation. Inspect the generated hook for its exact executable checks;
it contains no licence scanner.

### Day 1 — Review

```
@naos-review Review T-001 implementation

Acceptance criteria:
- AC-001-1: Valid credentials return JWT token
- AC-001-2: Invalid credentials return 401 (non-enumeration message)
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
- [x] All acceptance criteria satisfied (AC-001-1, AC-001-2)
- [x] Tests written and passing
- [x] No schema violations introduced
- [x] No duplicate code created
- [x] Traceability headers added to new files
- [x] Move this card to naos/completed/ when done

## Implementation Notes

2026-03-25 — Task completed (git commit abc1234)
           ✅ AC-001-1: Valid credentials return JWT — implemented in src/auth/endpoint.py
           ✅ AC-001-2: 401 with "Invalid email or password" — non-enumeration message
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

Week of: 2026-03-23 to 2026-03-27
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
