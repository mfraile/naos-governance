# Integral Tutorial — Lite from Scratch

> _Installation path reverified with NAOS kit v1.1.0 candidate · 2026-09-05_

> **Profile**: `lite`
> **Effort basis**: Repository-specific; record actual install, configuration, and validation receipts
> **Goal**: Exercise the reduced Lite native workflow against one real task

---

## What You Will Have at the End

- A `lite` profile installed with 9 rules (3 blocking-posture)
- Three AI instruction files configured (Copilot, Claude Code, Cursor)
- A partial spec kit in place
- A low-noise, non-publishing NAOS control-plane CI workflow with read-only repository permission and ephemeral runner outputs
- Capability state, systemic impact, module-header, spec-pack, spec-cascade, and control-plane review posture
- A complete Lite-native task session: task-start → implement → review → task-complete, with manual opening/closing notes
- A manual weekly planning routine; the weekly prompts begin at Standard

---

## Prerequisites

- Python ≥ 3.11
- An absent path for the new project; add the project's real code after activation
- An AI coding assistant
- Enough uninterrupted time to review generated files and run the local checks

Portable preview generation is exercised on Linux with Python 3.11. Managed
`--activate` mutation is currently supported only on Darwin ARM64 with CPython
3.11–3.13; Linux, Windows, and other unsupported tuples refuse before target
mutation. On an unsupported host, review an absent external `--preview-dir`
and perform activation later on a supported host.

---

## Part 1: Installation and Configuration

### Step 1: Install NAOS with the lite profile

```bash
PROJECT=/path/to/your/new-project
PREVIEW=/tmp/naos-lite-preview
pip install naos-governance
naos-governance init "$PROJECT" --new --tier lite --archetype custom --backend static_only --preview-dir "$PREVIEW"
# Review $PREVIEW before the supported-host activation below.
naos-governance init "$PROJECT" --new --tier lite --archetype custom --backend static_only --activate
cd "$PROJECT"
```

Or from source:
```bash
PROJECT=/path/to/your/new-project
python naos_init.py "$PROJECT" --new --tier lite --archetype custom --backend static_only --activate
```

### Step 2: Verify the installed structure

```bash
ls .ai/                     # RULES.md — governance constitution
ls .github/prompts/         # All prompt files
ls .github/workflows/       # naos-control-plane-ci.yml
ls naos/                    # Project management infrastructure
ls specs/                   # Spec kit (partial)
```

Key files installed:
- `.ai/RULES.md` — governance rules (9 rules, 3 blocking-posture)
- `.github/copilot-instructions.md` — Copilot instruction set
- `CLAUDE.md` — Claude Code instruction set
- `.cursorrules` or `.cursor/rules/*.mdc` — Cursor rules
- `naos/PROJECT_STATUS.md` — project status tracker
- `naos/TASK_REGISTRY.yaml` — task registry (empty, ready to fill)
- `naos/capability_state.yaml` — adopter-local maturity state declaration
- `naos/systemic_impact_rules.yaml` — artifact-family review relationships
- `naos/module_header_rules.yaml` — source traceability expectations
- `naos/reports/spec_pack_contract.json` — generated spec-pack template contract evidence after `naos spec-pack-contract`
- `naos/reports/spec_cascade_coherence.json` — generated requirement/task/source traceability evidence after `naos spec-cascade`
- `naos/control_plane_review_items.yaml` — structured routing items for governance/research findings
- `naos/setup_module_catalog.yaml` — module-choice guidance for recommended, optional, and deferred setup tracks
- `specs/` — spec directory with template files
- `.github/workflows/naos-control-plane-ci.yml` — non-publishing readiness CI; commands write ephemeral runner evidence but do not upload or commit it

Run the deterministic readiness chain locally before relying on generated
evidence:

```bash
naos claims --profile lite
naos setup-recommendations --profile lite
naos add setup-module read_only_ci_readiness --profile lite --dry-run
naos memory-readiness --profile lite
naos memory-access --profile lite
naos memory-use-policy --profile lite
naos task-context --task T-001 --profile lite   # when an active task card exists
naos task-lifecycle --task T-001 --profile lite # exact active/completed lookup
naos context-index --profile lite
naos context-query --query "governance" --profile lite
naos semantic-candidates --profile lite
naos graph-context --profile lite
naos graph-query --task T-001 --profile lite
naos session-start --task T-001 --profile lite
naos evidence-attestation --profile lite
naos capability-maturity --profile lite
naos systemic-impact --profile lite
naos module-headers --profile lite
naos spec-pack-contract --profile lite
naos spec-pack-materialize . --profile lite --dry-run
naos spec-assembly-worksheet . --profile lite
naos spec-cascade --profile lite
naos control-plane-review --profile lite
naos self-check --profile lite
naos roadmap-crosswalk --profile lite
naos function-index-health --profile lite
naos test-evidence-map --profile lite
naos test-evidence --profile lite
naos ac-completion-evidence --profile lite
naos composed-traceability --profile lite
naos duplicate-function-hygiene --profile lite
naos secret-hygiene --profile lite
naos test-quality-hygiene --profile lite
naos dependency-integrity --profile lite
naos package-reality --profile lite
naos api-symbol-reality --profile lite
naos gate-status --profile lite
naos gate-evaluate --profile lite
naos evidence-pack --profile lite
naos dashboard --profile lite --json
```

### Step 3: Activate the pre-commit hook

```bash
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

### Step 4: Configure your AI instruction file

**For GitHub Copilot**: `.github/copilot-instructions.md` is auto-configured. Verify it loads in your IDE.

**For Claude Code**: Open `CLAUDE.md` and adapt the `[ADAPT]` sections to your project's domain.

**For Cursor**: The `.mdc` rules file is installed. Open Cursor settings and verify the rules file is detected.

### Step 5: Initialize your first spec

```bash
# Open the problem spec template
cat specs/01-problem.md
```

Fill in the `[ADAPT]` sections with a 2–3 sentence description of your project's problem statement. This is the foundation for requirements traceability.

You do not need to fill all specs before using NAOS — but `01-problem.md` and a rough `03-requirements.md` give the system something to work with.

### Step 6: Register your first task

Open `naos/TASK_REGISTRY.yaml` and add an entry for the first task you plan to work on:

```yaml
tasks:
  - id: T-001
    title: My first governed task
    status: planned
    lifecycle_state: planned
    delivery_state: not_started
    verification_state: unverified
    requirement: FR-1
    estimated_days: 1
    description: |
      [Brief description of what needs to be done]
    acceptance_criteria:
      - The feature works as expected
      - Tests are written
```

---

## Part 2: Your First Bounded Session

### Step 1: Declare the session intent

Lite does not install `/naos-d-start`. Tell the operator/agent explicitly:

> Today I am working on T-001. Read the task registry and active card, keep
> changes within the declared scope, and report any missing context before work.

`@naos-plan` is instructed to review and cite:
- The governance constitution (9 rules)
- `naos/PROJECT_STATUS.md`
- `naos/TASK_REGISTRY.yaml` — will find T-001
- Your AI instruction files

Review the agent's Pre-Task Research Summary.

### Step 2: Start the task

```
/naos-task-start T-001
```

`@naos-plan` is instructed to:
1. Verify T-001 exists in the registry
2. Check `naos/active/` — no existing card
3. Create `naos/active/T-001_my-first-governed-task.md`

Review the story card. Verify the schemas and acceptance criteria sections are populated.

### Step 3: Implement

```
@naos-implement [describe what you need to build for T-001]
```

Work through the implementation. Reference the story card constraints explicitly.

When done:

```bash
git add [files]
git commit -m "feat(T-001): [description] (AC-1.1)"
```

The blocking-posture count shown above describes policy/human review, not hook
automation. Inspect the generated hook for its exact executable checks; it
contains no licence scanner.

### Step 4: Review

```
@naos-review Review the implementation of T-001 against the acceptance criteria in the story card
```

For `lite`, optional semantic/similarity evidence is not active by default. The review focuses on deterministic, file-first checks:
- Spec alignment
- Structural governance validation
- Documentation impact

Fix any findings before proceeding.

### Step 5: Complete the task

**Manually update the story card completion checklist**:

```markdown
## Completion Checklist
- [x] All acceptance criteria satisfied
- [x] Tests written and passing
- [x] No schema violations introduced
- [x] Traceability headers added to new files
```

Then:

```
/naos-task-complete T-001
```

Lite does not install `@naos-conformance`. Review the task-complete output,
story-card checklist, diff, tests, and applicable deterministic reports before a
human closes or archives the card.

```bash
make -f Makefile.naos gov-refresh
```

### Step 6: End the session

Lite does not install `/naos-d-end`. Record the completed work, remaining work,
blockers, changed paths, and evidence in the existing task card or handoff file;
do not create a duplicate session-summary file.

Run the closing commands from the agent's output.

---

## Part 3: Integrating the Weekly Cadence

Lite does not install `/naos-w-plan` or `/naos-w-review`. Use the following
plain-language review in the existing task/status source, or move to Standard
when the full cadence prompts are wanted.

**Monday morning (10 minutes)**:
Review the task registry and active cards. Record the week start, bounded focus,
dependencies, and evidence expected for each selected task.

**Friday afternoon (15 minutes)**:
Review completed and unfinished tasks, test/report evidence, blockers, and
accepted follow-up actions in the existing status source.

→ [Micro Tutorial 20: Weekly Cadence](./MICRO_TUTORIAL_20_NAOS_W_CADENCE.md) for full details.

---

## What You Have Now

| Capability | Status |
|-----------|--------|
| Documented blocking posture (3 rules) | ✅ |
| Three AI instruction files | ✅ |
| Lite-native task workflow (task-start → plan → implement → review → task-complete) | ✅ |
| Task registry and story cards | ✅ |
| Weekly planning cadence | Manual; weekly prompts are Standard/Assured |
| Full spec-driven development | Partial |
| Requirements traceability (FR→Task→Code→Test) | Partial |
| Optional semantic/similarity evidence | Not active by default; project-configured only |
| Behavioral Governance Readiness | Advisory readiness only; behavioral scoring/evaluator runtime remains project-configured |
| Governance dashboard + evidence metrics | Available where reports exist |
| Non-publishing NAOS readiness CI (ephemeral runner writes) | ✅ |

---

## What to Do Next

Ready for team-grade governance?

→ [Integral Tutorial: Standard from Scratch](./INTEGRAL_TUTORIAL_STANDARD_FROM_SCRATCH.md)

Or assess the `standard` target without applying a transition:

```bash
naos-governance upgrade . --tier standard --archetype custom --backend static_only --dry-run
```

The preview writes nothing to the project and does not prove a profile
transition. To apply, persist an external immutable plan, review its exact
`plan_sha256`, and invoke apply separately:

```bash
naos-governance upgrade . --tier standard --plan-out /tmp/naos-standard-plan.json
naos-governance upgrade . \
  --apply-plan /tmp/naos-standard-plan.json \
  --expect-plan-digest PLAN_DIGEST
```

Apply never replans, and legacy `--force` remains refused.
