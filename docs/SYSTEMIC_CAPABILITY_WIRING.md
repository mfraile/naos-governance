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

## Repository-role applicability

Systemic artifact rules distinguish canonical kit sources from files generated
into adopter projects. A family may declare `repository_roles` with
`kit_source`, `adopter_project`, or both. An explicitly excluded role remains
visible as `not_applicable`, including on incoming relationships. Missing files
do not establish an exemption. Malformed role declarations remain unresolved.

Mixed families can declare `minimum_expected_by_role` and
`file_patterns_by_role`. For example, the policy minimum is
`policies/default_policy.yaml` in the kit and
`naos/policy/default_policy.yaml` in an adopter. The selected counterpart must
actually exist. Existing custom rules without role declarations retain their
previous applicability and patterns. These declarations do not approve an
integration, lower a gate, or settle a human review obligation.

## Adopter product changed-path review

The report's flat `findings` list counts an unmet artifact or unknown target
once per target and state. Each shared finding carries `target_family_id`,
`source_family_ids` and paired `source_severities`; its severity is the strongest
contributing severity. `family_id` retains a representative source for existing
consumers. Text summaries show all contributing sources and use the shared
severity for presentation. The summary records unique target-link findings,
original link occurrences and the number collapsed.

Every source family's review obligations, required outputs and evaluated state
remain visible. Consolidation follows exact family-review processing; separate
human review surfaces and independent missing, disabled or invalid family facts
are not merged. Nested family findings describe source-local facts, while the
flat list supplies the canonical finding counts. Removing duplicate links does
not waive missing evidence or make a fresh scaffold ready.

Changed-path routes keep three declarations distinct: `source_patterns` for kit
sources, `generated_patterns` for emitted or explicitly installed adopter files,
and optional `adopter_patterns` for adopter-authored source, tests and package
metadata. The shipped product route declares common source roots and manifests.
For another layout, extend the exact project routing declaration before review;
a transient source-root environment value does not silently change this scope.
Deleted paths still route through the same declaration.

Artifact matches use the active role's declared patterns and applicability.
Kit-only families do not become adopter product obligations merely because a
filename matches. A malformed role or product-pattern declaration remains a
failure, and an unknown changed path or relationship target remains unresolved.
Authored routes require a `route_[a-z0-9_]+` identifier and the declared routing
shape before matching or exclusions; a generic route cannot hide a malformed
specialized route. Generated root instructions, portable `.agents/skills/`
files, managed ignore templates and the shipped public-literal catalogue use
their existing instruction, skill, template and security review destinations.

Run the exact changed-file set, review every emitted target, then supply one
review record with the same complete set, rationale and evidence references.
`--require-resolved` requires that changed-path integrity and all obligations
are closed. This review declaration does not settle missing mandatory artifacts
or make the aggregate systemic report pass: applicable findings, profile exit
behavior and any separately bound family review remain in force. A fresh
scaffold can have legitimate review work while explicitly kit-only targets are
visible as inapplicable. Do not waive missing evidence to obtain a clean result.

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
