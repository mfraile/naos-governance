# NAOS Portable Governance Kit — Phase 4 Maintenance Playbook

**Version**: 1.1.0
**Status**: Draft
**Applicable To**: All NAOS profiles (lite / standard / assured)

---

## Overview

Phase 4 maintenance is **lightweight governance health monitoring**. It runs on a schedule after your project is stable and active feature development has slowed. This is not continuous optimization; deterministic conformance is implemented today, while behavioral drift-style review is future/project-configured and requires a separately approved evaluator.

The kit does not publish a universal maintenance ROI. If cost or time matters
to a decision, record the adopter's commands, cadence, labor assumptions,
provider use, date, and repository scope so the calculation is reproducible.

**When to activate Phase 4**: After your project ships v1.0 and feature development cadence slows from sprint-by-sprint to maintenance mode.

The current control-plane outputs add two useful maintenance artifacts:

- `naos/evidence/evidence_pack.json` for consolidated evidence, gaps, waivers, and residual risks;
- `naos/reports/dashboard_summary.json` for machine-readable dashboard posture.

These files support review and audit/admissibility discussions. They do not prove legal/regulatory compliance, runtime safety, or complete test coverage.

---

## Table of Contents

1. [The 6 Maintenance Cadences](#the-6-maintenance-cadences)
2. [Cadence 1 — On-Demand Deterministic Conformance](#cadence-1--on-demand-deterministic-conformance)
3. [Cadence 2 — Behavioral Readiness Cadence](#cadence-2--behavioral-readiness-cadence)
4. [Cadence 3 — Quarterly Review Readiness](#cadence-3--quarterly-review-readiness)
5. [Cadence 4 — Dependency Audit](#cadence-4--dependency-audit)
6. [Cadence 5 — Toolchain Upgrade Audit](#cadence-5--toolchain-upgrade-audit)
7. [Cadence 6 — AI Quality Review](#cadence-6--ai-quality-review)
8. [User-Centralized Memory — Instinct 3-Tier Model](#user-centralized-memory--instinct-3-tier-model)
9. [CI Automation Examples](#ci-automation-examples)
10. [Alert Response Runbook](#alert-response-runbook)
11. [Phase 4 Activation Checklist](#phase-4-activation-checklist)

---

## The 6 Maintenance Cadences

| Cadence | Trigger | Dimensions | Cost posture | Enabled by default |
|---------|---------|-----------|---------|-------------------|
| On-demand deterministic conformance | Manual | 1–3 | no model/API cost; local labor/tooling varies | ✅ Yes (always available) |
| Behavioral readiness cadence | Cron (1st Monday) | 1, 2, 3 | project-configured | ❌ Future/project-configured |
| Quarterly review readiness | Cron (1st Monday of quarter) | 1–8 | project-configured | ❌ Future/project-configured |
| Dependency audit | After pip/npm major upgrade | 1, 3 | project-measured | ❌ Enable after v1.0 |
| Toolchain upgrade | After AI tool/IDE upgrade | 1–4 | project-measured | ❌ Enable after v1.0 |
| AI quality review | Monthly alongside Cadence 2 | 8 + evals | no default model runtime; project-measured | ❌ Enable when evals exist |

> **Note on costs**: Deterministic Conformance Review has no model cost. Any behavioral governance evaluator, provider, model, budget, or scenario cost is future/project-configured and outside the default kit.

---

## Cadence 1 — On-Demand Deterministic Conformance

**What**: Run the static conformance battery against your current governance files. Produces a structural fit snapshot without LLM calls or provider keys. Standard and assured projects also validate agent, skill, and instruction frontmatter; see [`docs/FRONTMATTER_CONFORMANCE.md`](docs/FRONTMATTER_CONFORMANCE.md).

`make -f Makefile.naos gov-refresh` also emits the current project AI surface catalogue to `configs/naos_ai_surface_catalogue.yaml` when `scripts/naos_emit_capabilities.py` is installed. This inventory is regenerated from the local `.github/agents`, `.github/skills`, and `.github/instructions` surfaces, so brownfield onboarding changes are reflected on the next refresh. It is separate from control-plane capability contracts under `capabilities/`.

**When to run manually**:
- Before a significant governance change (new rule, updated instruction file)
- After a major AI toolchain upgrade
- When team members report frequent governance reminder messages

**Command**:
```bash
# Check readiness first; unresolved specs/tasks block meaningful baselines
make -f Makefile.naos naos-readiness

# Static conformance (available now, free)
python .github/autoresearch/runner.py --conformance \
  --output naos/reports/conformance_latest.json
```

`--audit`, `--grader`, `--dimensions`, and `--model` belong to future/project-configured behavioral evaluator work. Keep them out of CI until a real evaluator is implemented, approved, and configured.

**Interpreting results**:
```
NAOS Conformance Check
  Loaded 49 scenarios
  Result: 77/77 checks passed
  Written → naos/reports/conformance_latest.json
```

Frontmatter failures name the file and missing field. Common fixes are adding
`model` or `tools` to `.agent.md`, adding `parameters: []` and a `## When to Use`
section to `SKILL.md`, or adding `applyTo` to `*.instructions.md`.

**Thresholds**:
| Score | Status | Action |
|-------|--------|--------|
| Static conformance passes | ✅ Healthy | Run `make -f Makefile.naos gov-refresh` |
| Readiness blocks | ⚠️ Not ready | Fill specs, registry anchors, or AI policy config |
| Static conformance fails | 🔴 Block | Fix missing governance files or frontmatter metadata before release |

---

## Cadence 2 — Behavioral Evaluator Cadence

**What**: Future/project-configured behavioral evaluator behavior. Behavioral Governance Readiness is shipped as deterministic readiness/impacter review; multiple behavioral runs would require a separately implemented evaluator and human-approved baseline. The default kit does not perform behavioral grading or drift-mode scoring.

**When**: 1st Monday of each month (or when a governance file changes).

**Spacing policy**: Never runs twice within 14 days unless `--force-drift` is passed.

**Trigger logic**:
1. Check time since last run (must be ≥14 days)
2. Check if any governance file changed since last run
3. If either condition is met → run; else → skip with cost notice

**Command**:
```bash
# Planned behavioral runtime example; not available in v1.0.x
# python .github/autoresearch/runner.py --drift --runs 5
```

**Interpreting results**:
```
Drift check: N=5 runs
Mean: [project-configured score] (baseline: [approved baseline])
Drift: [delta] — [review status]

Per-scenario grand means:
  rule7_deep_analysis:     [score] ([delta])
  instruction_following:   [score] ([delta])
  portability_fresh:       [score] ([delta])
  pii_boundary:            [score] ([delta])
```

**Alert thresholds** (configured in `naos_autoresearch.yaml`):
- `alert_threshold_pp: 5` — log ALERT, investigate before next sprint
- `block_threshold_pp: 10` — requires remediation sprint (regression fix)

**Pair with Cadence 6**: If your project has an `eval_log.jsonl`, run Cadence 6 on the same day as any project-configured behavioral evaluator cadence to compare deterministic governance evidence with output-quality evidence side by side.

---

## Cadence 3 — Quarterly Review Readiness

**What**: Future/project-configured behavioral evaluator behavior. Behavioral Governance Readiness can report deterministic prerequisites and impacters, but a full-battery behavioral assessment across all 8 governance dimensions would require a separately implemented evaluator, review criteria, cost controls, and human approval.

**When**: 1st Monday of each quarter (or after a major governance overhaul).

**Command**:
```bash
# Planned behavioral runtime example; not available in v1.0.x
# python .github/autoresearch/runner.py --assess --dimensions 1,2,3,4,5,6,7,8 --runs 3
```

**Reading the 8 dimensions**:

| Dim | Name | Tests |
|-----|------|-------|
| 1 | Rule Compliance | Are rules followed in coding tasks? |
| 2 | Agent Instructions | Do agents stay in their defined roles? |
| 3 | Scoped Instructions | Do domain-specific instructions activate correctly? |
| 4 | Prompt Templates | Do prompts produce correct protocol output? |
| 5 | Efficiency | Token usage, instruction load, compliance rate |
| 6 | Portability | Would this governance work in a fresh project context? |
| 7 | Session & Governance Hygiene | Session continuity, handoff, drift detection |
| 8 | AI Output Quality | TDD discipline, vertical slices, eval awareness, anti-duplication |

**When to use deep assessment results**:
- Dim 1 ↓ → rule bodies need updating or clarification
- Dim 2 ↓ → agent definitions need work (handoffs, persona drift)
- Dim 3 ↓ → instruction files may have stale paths or outdated examples
- Dim 4 ↓ → prompt templates may have project-specific content
- Dim 5 ↑ token trend → instruction budget approaching limit (check with `naos_validate_instruction_budget.py`)
- Dim 6 ↓ → governance has accumulated project-specific coupling; time to refactor

---

## Cadence 4 — Dependency Audit

**What**: After major package upgrades, some governance rules may become stale (e.g., patching an invariant's assumption after a library replacement).

**When to trigger**:
- After `pip install --upgrade` or `npm upgrade` for major library versions
- After adding a new LLM provider dependency
- After migrating databases or frameworks

**Command**:
```bash
# Available now: rerun static conformance and your dependency scanner
python .github/autoresearch/runner.py --conformance \
  --output naos/reports/conformance_latest.json
pip-audit -r requirements.txt
```

**What to look for**:
- Static conformance still validates scenario/reference shape; it does not test
  licence, resilience, or architecture runtime behavior
- Review the separately configured dependency-scanner result for Rule 10
- Run native resilience and architecture tests after the relevant library change

---

## Cadence 5 — Toolchain Upgrade Audit

**What**: When Claude Code, GitHub Copilot, or your IDE AI updates its model, the governance files (which act as system prompts) may become silently stale. This audit catches toolchain-induced governance drift.

**When to trigger manually**:
- After upgrading to a new Claude Code version
- After GitHub Copilot announces a model update
- After updating `configs/ai_models.yaml` with new model names
- After VS Code major version update

**Command**:
```bash
# Available now: verify static conformance after toolchain changes
python .github/autoresearch/runner.py --conformance \
  --output naos/reports/conformance_latest.json

# Planned behavioral runtime: comparison against a pre-upgrade baseline
```

**Toolchain upgrade log** (update when you run this audit):

```yaml
# .naos/toolchain_upgrade_log.yaml
audits:
  - date: YYYY-MM-DD
    trigger: "[ADAPT: AI toolchain or governance-surface change]"
    pre_score: "[ADAPT: approved baseline, if measured]"
    post_score: "[ADAPT: measured score, if measured]"
    delta: "[ADAPT: measured delta, if applicable]"
    action: |
      [ADAPT: mitigation, review action, or configuration decision]
    resolved: false
```

---

## Cadence 6 — AI Quality Review

**What**: Measures whether AI-generated code is functionally correct — distinct from governance compliance (D1–D8). Two inputs: the conformance structural check and your project's eval pass rates.

**When**: Monthly alongside Cadence 2 (same day), once your project has at least one eval dataset.

**Pre-condition**: At least one entry in `naos/reports/eval_log.jsonl` (written by the `cookbook-evals` skill).

**Commands**:

```bash
# 1. Run conformance check (writes naos/reports/conformance_latest.json)
make -f Makefile.naos naos-conformance

# 2. Append eval results after running your eval suite
# [ADAPT: your eval runner — Evalite, pytest-llm, or plain pytest]
echo '{"date":"'"$(date +%F)"'","feature":"[ADAPT: feature-name]","pass_rate":0.87,"cases":23,"model":"claude-sonnet-4-6"}' \
  >> naos/reports/eval_log.jsonl

# 3. Regenerate dashboard to see AI Quality section
make -f Makefile.naos gov-refresh
```

**Interpreting results**:

```
## AI Quality

### Conformance (conformance — 2026-05-01)
| Check     | Passed | Score  |
|-----------|-------:|-------:|
| Structural| [n/n]  | [score] |
| Battery   | [n/n]  | [score] |
| Overall   | —      | [score] |

### Eval Pass Rates (latest per feature)
| Feature          | Pass Rate | Cases | Date       |
|-----------------|----------:|------:|------------|
| [feature-name]   | [score]   | [n]   | YYYY-MM-DD |
| [feature-name]   | [score]   | [n]   | YYYY-MM-DD |
```

**Alert thresholds**:
- Eval pass rate < 80% → ⚠️ flag in dashboard; investigate prompt or feature logic
- Eval pass rate < 60% → treat as a failing test; block ship until resolved
- Conformance overall < 80% → run Cadence 1 (on-demand audit) to diagnose

**What to do when evals drop**:
1. Check if the eval dataset is stale (expected outputs out of date)
2. Check if a recent prompt or instruction change caused regression
3. Use `cookbook-observability` skill to trace the session that produced failing outputs
4. Fix the root cause — do not adjust pass thresholds downward

---

### VS Code 1.113 — Chat Customizations Editor

VS Code 1.113 ships a **Chat Customizations editor** (Preview) — a unified UI to browse and manage instructions, prompts, agents, and skills without editing `.md` files manually. Open via the gear icon in the Chat view or `Chat: Open Chat Customizations` in the Command Palette.

**NAOS compatibility**: The editor reads the same `.github/` directory structure that `naos init` scaffolds. Downstream users can use it as an alternative to manual file editing — useful for onboarding new team members.

### VS Code Future — Plugin Marketplace Distribution

VS Code 1.113 introduces plugin marketplace URL handlers (`vscode://chat-plugin/add-marketplace?ref=<github-owner/repo>`). This enables one-click installation of a chat plugin marketplace from a GitHub repo.

**Future opportunity**: The NAOS kit templates could be packaged as a VS Code chat plugin marketplace. A single URL would let downstream projects install all NAOS agents, skills, and prompts without running `naos init`. Track for a future NAOS release when the plugin marketplace API stabilises.

---

## User-Centralized Memory — Instinct 3-Tier Model

Instincts are crystallised governance patterns — observed behaviours that become permanent fixtures of how an AI agent works on your project.

### The 3 Tiers

```
Tier 3: mfraile/naos-governance (Universal)
   ↑ promoted if ≥10 confirmations across ≥2 projects

Tier 2: User-centralized memory (User-scoped)
  Engram via ENGRAM_DATA_DIR (default ~/.engram) or another approved provider
   ↑ promoted from Tier 1 if ≥5 confirmations across sessions

Tier 1: .github/instincts/INS-NNN.yaml (Project-scoped)
   ← git-committed to the repo
   ↑ created when pattern observed ≥3 times
```

### How Instincts Work with User-Centralized Memory

**Tier 2 instincts** live in user-scoped memory, preferably local-first Engram data under `ENGRAM_DATA_DIR` (default `~/.engram`). NAOS does not configure replication or Git memory sync; any backup or team replication requires separate approval and provider-specific controls. An `~/engram-memories` checkout is an optional management toolkit, not the live store.

This means an instinct you observe on Project A (for example, "agents must check memory state before assuming `mem_context` is callable") can become available in Project B without duplicating project-local files.

**Enabling centralized instincts**:

1. Run `naos memory check` to inspect existing Engram/MCP/storage metadata.
2. If needed, run `naos memory setup --disposition configure-local --write` to record the recommended local-first data directory without installing a provider or client.
3. Keep replication local/off unless separately reviewed; never store credentials, PII, customer data, regulated data, or connection strings.
4. Reference Tier 2 instincts in project guidance:
   ```markdown
   ## Tier 2 Instincts (cross-project patterns)
  See: approved user-scoped memory — patterns observed across ≥5 sessions
   ```

### Instinct Promotion Workflow

```
New observation → "I've seen this 3+ times" → Create INS-NNN.yaml at Tier 1
                                               ↓
5+ confirmations across sessions → Review with human → Promote to Tier 2
(record in user-centralized memory; remove from .github/instincts/ or keep both)
                                               ↓
10+ confirmations across ≥2 projects → Review with human → Submit PR to mfraile/naos-governance
(becomes a Tier 3 universal instinct)
```

**When to promote vs. keep at Tier 1**:
- Tier 1 → Tier 2: Pattern is about your personal AI workflow, not project-specific content
- Tier 2 → Tier 3: Pattern holds across multiple unrelated projects (different stacks, domains)
- **NEVER auto-promote** — human review required at every tier boundary

### Instinct Schema Reference

```yaml
# .github/instincts/INS-001.yaml (Tier 1 example)
id: INS-001
title: "Agents assume mem_context is callable without checking memory state"
tier: 1
observed_pattern: |
  When a session opens with an active compact file (.naos/active/<TASK-ID>_compact.md),
  agents may assume Engram tools are available without checking configs/naos_memory.yaml.
  This causes hard failures in projects where memory is deferred, disabled, or not connected.
evidence_count: 7
source_sessions:
  - session_2026_03_17
  - session_2026_03_19
  - session_2026_03_21
mitigation: |
  Add explicit memory-state checks before mem_context. If Engram is configured, call it;
  otherwise recover from compact file, task card, git state, and repo governance files.
status: active       # active | promoted | superseded
promoted_to: null    # INS-002 at Tier 2 | null if not yet promoted
created: 2026-03-22
```

---

## CI Automation Examples

### GitHub Actions

```yaml
# .github/workflows/naos-governance.yml
name: NAOS Governance (Static Conformance)

on:
  schedule:
    - cron: '0 9 1-7 * 1'  # 1st Monday of each month at 09:00 UTC
  workflow_dispatch:        # Allow manual triggering
    inputs:
      force:
        description: 'Force project-configured behavioral evaluator cadence (bypass cooldown)'
        type: boolean
        default: false

jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Run static conformance
        run: |
          make -f Makefile.naos naos-readiness
          make -f Makefile.naos naos-conformance

      - name: Upload drift report
        uses: actions/upload-artifact@v4
        with:
          name: conformance-report-${{ github.run_number }}
          path: naos/reports/conformance_latest.json

      - name: Comment on drift alert
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'NAOS Governance Conformance Failure',
              body: 'Static conformance or readiness failed. See workflow run for details.',
              labels: ['governance', 'conformance']
            })
```

### GitLab CI

```yaml
# .gitlab-ci.yml (governance stage addition)
stages:
  - test
  - governance   # Add this stage

naos-conformance:
  stage: governance
  image: python:3.11
  only:
    - schedules  # GitLab scheduled pipeline
  script:
    - pip install -r requirements-dev.txt
    - make -f Makefile.naos naos-readiness
    - make -f Makefile.naos naos-conformance
  artifacts:
    paths:
      - .github/autoresearch/results/
    expire_in: 30 days
  allow_failure: false  # Drift alert = pipeline failure
# Schedule: In GitLab UI → Build → Schedules → New schedule
# Cron: 0 9 * * 1  (every Monday at 09:00)
# Variable: MONTHLY_DRIFT=true (use to distinguish from other cron runs)
```

### Generic Shell (any CI system)

```bash
#!/bin/bash
# .naos/ci/static_conformance.sh — runs on any CI system
#
# Usage:
#   ./static_conformance.sh
#
# Exit codes: 0=pass, non-zero=readiness/conformance failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNNER="$PROJECT_ROOT/.github/autoresearch/runner.py"

echo "=== NAOS Static Conformance Check ==="
echo "Project: $PROJECT_ROOT"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Activate virtualenv if present
if [[ -f "$PROJECT_ROOT/.venv/bin/activate" ]]; then
    source "$PROJECT_ROOT/.venv/bin/activate"
fi

make -C "$PROJECT_ROOT" -f Makefile.naos naos-readiness
python "$RUNNER" --conformance --output "$PROJECT_ROOT/naos/reports/conformance_latest.json"
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "✅ Static conformance passed" ;;
  *) echo "❌ Static conformance failed (exit $EXIT_CODE)" ;;
esac

exit $EXIT_CODE
```

**Scheduling the shell script** (any CI system):

```bash
# crontab entry (runs at 09:00 on the 1st Monday of each month)
0 9 1-7 * 1 /path/to/project/.naos/ci/static_conformance.sh >> /var/log/naos-conformance.log 2>&1
```

### Jenkins Pipeline

```groovy
// Jenkinsfile (governance stage)
pipeline {
  agent any
  triggers {
    // 1st Monday of each month at 09:00
    cron('H 9 1-7 * 1')
  }
  stages {
    stage('Governance Conformance Check') {
      steps {
        sh 'pip install -r requirements-dev.txt'
        sh 'make -f Makefile.naos naos-readiness'
        sh 'make -f Makefile.naos naos-conformance'
      }
      post {
        failure {
          emailext(
            subject: 'NAOS Governance Conformance Failure',
            body: 'Readiness or static conformance failed. Check Jenkins for details.',
            to: '${DEFAULT_RECIPIENTS}'
          )
        }
      }
    }
  }
}
```

---

## Alert Response Runbook

### Alert Level: ⚠️ (5–10pp drift)

Drift is meaningful but not critical. Likely cause: a governance file update changed AI behaviour without comprehensive testing.

**Response steps**:
1. Run `make -f Makefile.naos naos-readiness` and `make -f Makefile.naos naos-conformance` — identify missing prerequisites or governance files
2. Check `git log --since="30 days ago" -- .ai/RULES.md .github/copilot-instructions.md .github/instructions/` — any recent changes?
3. If rule body changed recently → review affected scenario context files in `.github/autoresearch/task_battery/portable_scenarios.yaml`
4. Update rule wording if the change introduced ambiguity
5. Re-run static conformance to confirm recovery
6. Defer behavioral baseline updates until a project-approved behavioral governance evaluator exists

### Alert Level: 🔴 (>10pp drift)

Significant regression. Requires a governance remediation sprint before the next release.

**Response steps**:
1. Create a tracking issue: "NAOS Drift Regression — [date]"
2. Run readiness and static conformance to understand scope
3. Identify root cause per-dimension and per-scenario
4. Open a task card in `naos/active/` (use the story card template)
5. Fix affected governance files in a dedicated remediation PR
6. Re-run static conformance to verify recovery
7. Update baseline only after the behavioral governance evaluator is available and approved

### Common Root Causes

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Rule 7 score drops | Deep Analysis section in instructions became vague | Restore the 7-principle checklist table |
| Rule 26 score drops | Cognitive Checkpoint instruction or profile Rule 26 text was shortened | Restore trigger table and PAUL bracket behavior table |
| All Dim 3 scores drop | Instruction file `applyTo` glob broken after restructure | Check `applyTo:` patterns in scoped instruction files |
| Dim 6 (Portability) drops | Governance files accumulated project-specific references | Review portable scenario context files and strip project-specific references |
| Consistent SKIP inflation | `ide_only` scenarios running in API-compatible tier | Check `tier:` field in scenarios that produce SKIP |

---

## Phase 4 Activation Checklist

Use this checklist when activating Phase 4 for the first time:

```
□ v1.0 shipped (or equivalent "stable maintenance mode" milestone)
□ At least one static conformance run recorded in naos/reports/conformance_latest.json
□ `make -f Makefile.naos naos-readiness` passes without unresolved scaffold blockers
□ CI schedule configured for static conformance (GitHub Actions / GitLab / shell cron)
□ For future/project-configured behavioral evaluators only: provider env vars added to CI secrets after approval
□ Alert notification configured (email / Slack / GitHub Issue auto-create)
□ Quarterly review-readiness cron scheduled only if it starts disabled and has an approved evaluator path
□ Team briefed on alert response runbook (especially 🔴 block level)
□ Baseline values in naos_autoresearch.yaml are from a clean, stable state
  (NOT from a development sprint where governance was actively changing)
```

---

*Generated for the NAOS Portable Governance Kit*
*For updates, see: https://github.com/mfraile/naos-governance*
