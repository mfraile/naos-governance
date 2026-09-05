# Which NAOS Profile Should I Choose?

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> Use this guide to select the governance profile that fits your situation.
> Choose by project purpose. A later profile change is optional, not a maturity
> requirement or compulsory progression.

---

## Quick Decision

```
Are you evaluating NAOS or running a prototype?
  └─ YES → quickstart

Are you a solo developer or a team of 1–2 on an early-stage project?
  └─ YES → lite

Are you a team of 3+ working on a production project?
  └─ YES → standard

Are you in a regulated industry (finance, healthcare, government) or enterprise?
  └─ YES → assured
```

---

## Profile Comparison

| Attribute | `quickstart` | `lite` | `standard` | `assured` |
|-----------|:-----------:|:------:|:----------:|:---------:|
| **Rules** | 5 | 9 | 19 | 19 |
| **Blocking-posture rules** | 3 | 3 | 13 | 19 |
| **Generated surfaces** | Machine contract | Machine contract | Machine contract | Machine contract |
| **Spec-driven development** | Minimal | Partial | Full | Full + audit trail |
| **Traceability (FR→Task→Code→Test)** | ❌ | Partial | ✅ | ✅ |
| **Function-index / duplicate-risk evidence** | ❌ | Advisory | Configured | Configured + stronger review |
| **Behavioral Governance Readiness** | Optional advisory readiness | Optional advisory readiness | Recommended readiness/impacter review | Recommended readiness/impacter review |
| **Agent instruction files** | 1 (basic) | 3 | 3 (extended) | 3 (full) |
| **Dashboard / metrics** | Advisory when generated | Basic when configured | ✅ | ✅ |
| **Conformance mode** | Advisory/static where installed | Static where installed | Static + frontmatter checks | Static + frontmatter checks, stricter gates where configured |

Profile choice controls default enforcement posture. It does not mean every
capability is mature immediately after install. Capability maturity depends on
project readiness, configuration, validator outputs, and evidence freshness.
The posture counts are not counts of executable hook checks. The generated
hook and installed workflows define automation; no licence scanner is
installed by default.
Run `python scripts/validators/validate_profile_generated_surfaces.py` for
reproducible surface parity; the guide does not publish universal file-count,
setup-time, cost-saving, or ROI values.

> **See also.** For task-level recommendations (greenfield vs. long-horizon debugging vs. spec extraction, etc.), the **Task-Capability Matrix** in `CLAUDE.md` and `.github/copilot-instructions.md` maps task archetypes to recommended profile + PAUL bracket + preferred skills. Use the profile chooser here for repo-level posture; use the matrix for per-task selection.

After choosing a profile, run `naos setup-recommendations --profile <profile>` to review module choices, rationale, benefits, warnings, consequences, next actions, and deterministic profile guidance. The guidance can recommend staying on the selected profile or considering lite, standard, or assured based on local project signals, but it never upgrades automatically. Run `naos governance-bypass-posture --profile <profile>` to review hook/CI bypass posture and `naos external-evidence-ingest --source <scan.sarif> --profile <profile>` when local SARIF scanner output should be visible as unverified external review evidence. Run `naos memory-readiness --profile <profile>` for memory-governance posture, `naos memory-access --profile <profile>` before asking agents to claim memory or MCP access, and `naos memory-use-policy --profile <profile>` before treating any memory reference as supporting context or instruction-grade. Run `naos context-index --profile <profile>` when generated local candidate lookup would help, `naos context-query --query "<keywords>" --profile <profile>` when bounded candidate references would help, `naos semantic-candidates --profile <profile>` before discussing future semantic/vector candidates, `naos graph-context --profile <profile>` before discussing future graph traversal, `naos graph-query --task <TASK-ID> --profile <profile>` when bounded explicit-link relationship candidates would help, and `naos session-start|session-checkpoint|session-end --task <TASK-ID>` when lifecycle checklists would help a daily work session. These reports are guidance/evidence surfaces only; they do not automatically enable advanced modules, approve maturity, certify readiness, prevent bypasses, prove CI ran, verify external findings, make memory authoritative, prove MCP access, return answers, mutate task artifacts, write memory, enable sqlite-vec/embeddings/NetworkX/GraphML/graph databases, or turn semantic candidates, graph-query results, graph links, lifecycle reports, or the generated index into source truth.
>
> The matrix is especially useful after onboarding brownfield projects: once a repository has a selected profile, the matrix helps decide whether a particular task should stay in a lighter FRESH/MODERATE flow or escalate to DEEP/CRITICAL review with stronger skills and agents.

---

## Profile Details

### `quickstart` — Bounded Evaluation

**Best for**: First-time users evaluating NAOS, hackathons, throwaway projects, demos.

**What you get**:
- 5 governance rules (3 blocking-posture)
- Basic pre-commit hook
- One AI instruction file
- No spec infrastructure

**What you don't get**:
- Spec-driven development
- Requirements traceability
- Optional semantic/similarity evidence (disabled by default unless project-configured)

**Install**:
```bash
naos-governance init . --tier quickstart --activate
```

**Transition review**: compare against `lite` with `naos upgrade . --tier lite --dry-run`; persist and apply only through the separate digest-bound workflow below.

---

### `lite` — Minimal Friction, Real Governance

**Best for**: Solo developers, small two-person teams, early AI integration, greenfield projects.

**What you get**:
- 9 governance rules (3 blocking-posture)
- Pre-commit hook with structural validation
- 3 AI instruction files (Copilot, Cursor, Claude)
- Partial spec support
- Weekly planning prompts

**What you don't get**:
- Full requirements traceability
- Optional semantic/similarity evidence by default
- Behavioral scoring or evaluator runtime by default; Behavioral Governance Readiness stays deterministic/readiness-only and any evaluator must be separately approved

**Install**:
```bash
naos-governance init . --tier lite --archetype custom --backend static_only --activate
```

**Transition review**: compare against `standard` with `naos upgrade . --tier standard --dry-run`; persist and apply only through the separate digest-bound workflow below.

---

### `standard` — Team-Grade Governance

**Best for**: Teams of 3–10, production projects, projects where AI writes >30% of code.

**What you get**:
- 19 governance rules (13 blocking-posture)
- Full spec-driven development (FR/NFR + task registry)
- Requirements traceability (FR→Task→Code→Test)
- Function-index and duplicate-risk evidence where configured
- Deterministic Conformance Review and Behavioral Governance Readiness for first-baseline and impacter review
- Governance dashboard, validator reports, and evidence-pack summary
- All cadence rituals (daily, weekly, monthly)
- Full agent instruction files

**Install**:
```bash
naos-governance init . --tier standard --archetype custom --backend static_only --activate
```

**Transition review**: compare against `assured` with `naos upgrade . --tier assured --dry-run`; persist and apply only through the separate digest-bound workflow below.

---

### `assured` — Enterprise and Evidence-Heavy Governance

**Best for**: Regulated industries (finance, healthcare, government), enterprise projects, and environments where stronger evidence trails and reviewer handoff are needed.

**What you get**:
- Everything in `standard`
- Strongest evidence profile, with blocking gates where configured
- Audit/review trail for configured governance decisions
- Deterministic conformance mode: `@naos-conformance` runs file-first audit on task close
- Enhanced security standards instruction set
- Evidence-pack and exception/waiver visibility when configured

Assured supports stronger governance evidence and reviewer handoff. It does not by itself prove legal or regulatory compliance, runtime safety, complete test coverage, or secure code.

**Install**:
```bash
naos-governance init . --tier assured --archetype custom --backend static_only --activate
```

---

## How to Review a Profile Transition

Do not assume profiles are mechanically additive. Existing files may be
adopter-owned or semantically different, and adding missing files does not prove
that existing policy or instruction surfaces transitioned.

```bash
# Read-only examples
naos upgrade . --tier lite --dry-run
naos upgrade . --tier standard --dry-run
naos upgrade . --tier assured --dry-run
```

Planning and `--dry-run` write nothing to the adopter project. To apply a
managed transition, first persist an external immutable plan with
`naos upgrade . --tier PROFILE --plan-out FILE`, review its decisions and
`plan_sha256`, then invoke `naos upgrade . --apply-plan FILE
--expect-plan-digest SHA256`. Apply never replans, and legacy `--force` remains
refused. Use `naos init` for a new destination; on an already managed project,
direct `naos init --activate` routes to plan-only behavior.

See [Integral Tutorial: Standard → Assured Readiness and Upgrade Preview](./INTEGRAL_TUTORIAL_STANDARD_TO_ASSURED.md) for a walkthrough.

---

## Common Mistakes

**❌ Starting with `assured` when you meant `standard`**
The assured profile has the strongest evidence and blocking posture where configured. If your team is not yet familiar with the workflow, this can cause friction before the value is visible.

**❌ Staying on `quickstart` past the evaluation phase**
Quickstart is intentionally minimal. If you are using AI for production code, move to `lite` or `standard`.

**❌ Installing `standard` on a solo throwaway project**
The overhead is not worth it for projects where governance evidence is not a real concern.

---

## Next Step

Once you have chosen a profile:

- **quickstart** → [Integral Tutorial: Quickstart from Scratch](./INTEGRAL_TUTORIAL_QUICKSTART_FROM_SCRATCH.md)
- **lite** → [Micro Tutorial 10: naos-d-start](./MICRO_TUTORIAL_10_NAOS_D_START.md)
- **standard** → [Micro Tutorial 10: naos-d-start](./MICRO_TUTORIAL_10_NAOS_D_START.md), then [Integral Tutorial: Standard from Scratch](./INTEGRAL_TUTORIAL_STANDARD_FROM_SCRATCH.md)
- **assured** → Complete `standard` path first, then [Integral Tutorial: Standard → Assured](./INTEGRAL_TUTORIAL_STANDARD_TO_ASSURED.md)
