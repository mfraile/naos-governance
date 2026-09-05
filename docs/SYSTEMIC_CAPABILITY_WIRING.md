# Systemic Capability Wiring

**Status**: Public method summary
**Canonical AI-agent instruction**: `templates/skills/systemic-capability-wiring/SKILL.md`

In generated adopter projects, skills are copied under
`.github/skills/<skill-name>/SKILL.md` according to the selected profile.
Use `.github/skills/systemic-capability-wiring/SKILL.md` only when that skill
is installed, such as in assured/full-catalogue projects or after an explicit
`naos add skill systemic-capability-wiring`. Standard projects install
`.github/skills/systemic-wiring/SKILL.md`; use that skill plus
`naos systemic-impact` / `naos control-plane-review` for the same review
obligation when the expanded systemic-capability skill is absent.

The Systemic Capability Wiring Skill is the canonical NAOS method for adding
or changing capabilities, features, validators, reports, prompts, agents,
instructions, workflows, docs, project configuration, and app/system features
without creating orphan artifacts.

Core principle: a feature is not done when it works in isolation; it is done
when it is wired into the system's contracts, configuration, validation,
evidence, visibility, documentation, tests, and human decision boundaries.

## NAOS Pattern

Use the skill when a change should connect through:

```text
capability card
-> rules/config
-> schema
-> policy
-> validator/report
-> gates
-> evidence pack
-> dashboard
-> capability maturity
-> systemic impact
-> spec-pack contract where spec templates/files are involved
-> spec-cascade coherence where specs/tasks/source references or traceability are involved
-> module/source traceability where applicable
-> CLI/Make/CI
-> docs/tutorials/quick reference
-> tests
-> human decision boundary
```

Groups 12, 13, and 14 are examples of this pattern: capability maturity
readiness, systemic impact review, and module-header traceability review.
Spec-cascade coherence follows the same pattern for requirement/task/source
linkage and should be run or recommended when specs, task registry entries,
source headers, source spec references, or configured/inferred source roots
change.
Control-plane review routing extends the same method for governance-surface
changes and actionable research/autoresearch findings: declare structured
items, evaluate routing status, report missing routing, and leave disposition
to human governance review.

Adopter onboarding follows the same pattern: initialize a profile, run
`naos setup-recommendations` to review module choices, consequences, and
deterministic profile guidance,
run `naos governance-bypass-posture` to make hook/CI bypass posture visible,
run `naos external-evidence-ingest --source <scan.sarif>` when local SARIF
scanner output should enter review evidence as unverified external input,
run `naos memory-readiness` for memory-governance posture and `naos
memory-access` before agents claim memory or MCP access, and run `naos
learning-loop-review` before treating lessons as active guidance or using them
to change skills, prompts, workflows, baselines, gates, or maturity state,
use `naos task-context --task <TASK-ID>` for bounded active-task handoff
context when a task card exists, configure project-local rules and state, run
the deterministic readiness chain,
review evidence/dashboard output, and only then decide whether CI should
enforce stronger profile behavior. Lite is the first default CI-friendly tier;
quickstart remains local and low-friction unless a project opts in.

## AI Instruction Hygiene

The skill is the canonical place for NAOS capability and control-plane wiring
guidance. Generic cross-project wiring checks belong in `systemic-wiring`;
NAOS product/control-plane propagation checks belong here. Other AI surfaces
should reference it concisely for NAOS capability/control-plane guidance, or
reference `systemic-wiring` for generic cross-project wiring, instead of
copying either checklist. This reduces drift from long, duplicated, stale, or
conflicting prompts.

When prompts, agents, skills, instructions, workflows, or rules change, run or
recommend `naos systemic-impact` and check whether stale duplicated guidance
should be removed, replaced, or marked legacy.
When those changes create routing decisions or when research findings are
actionable, create or update `naos/control_plane_review_items.yaml` and run or
recommend `naos control-plane-review`.

## Boundary

The method supports bounded evidence and human review. It does not certify
maturity, compliance, runtime safety, complete coherence, universal
correctness, complete coverage, bypass prevention, CI proof, or external
finding verification.
