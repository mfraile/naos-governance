# START HERE — NAOS Overview and Learning Path

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-06-26_

> **Welcome to NAOS-Governance** — *Native AI Orchestration for SDLC*.
> This document is your entry point. Read it first, then follow the learning path that matches your situation.

---

## What Is NAOS?

NAOS is **governance-as-code** for AI-assisted software development and a file-first control plane for SDLC evidence. It is not an AI coding assistant, not a linter, and not a code review tool. It provides profiles, capability contracts, policy, validators, gates, evidence packs, and dashboard outputs around the existing command/prompt/agent workflow.

When you use an AI coding assistant (GitHub Copilot, Claude Code, Cursor, Continue.dev, Gemini CLI), NAOS helps keep the work aligned with your methodology and produces governance evidence for review. It does not prove legal or regulatory compliance, prove runtime safety, guarantee secure code, prove complete test coverage, or replace human review.

### The core problem NAOS solves

AI assistants write clean code. They pass tests. They follow style guidelines. But they also:

- Duplicate functions that exist three directories away
- Implement features that contradict requirements written last week
- Produce code untraceable to any requirement
- Introduce vulnerabilities that no linter was designed to catch

NAOS includes pre-commit checks where installed, but the current model is broader: preventive AI guidance, deterministic hygiene reports, profile-aware validators, gatekeeper readiness, evidence packs, dashboards, and remediation/waiver routing.

---

## What NAOS Is Not

| Not this | But this |
|----------|---------|
| A replacement for your AI assistant | A governance layer on top of it |
| A linter | A profile-aware governance control plane |
| A code reviewer | A review/evidence support layer |
| An opinion about which AI tool to use | A profile system compatible with all of them |
| A one-size-fits-all system | A tiered governance kit you scale to your needs |

---

## Choose Your Path In 2 Minutes

Start from your situation. Prompts and agents can help phrase the work in
natural language, but NAOS keeps the actual evidence steps explicit through
CLI/Make commands and reports.

| Your situation | First route | Main command or prompt | Main evidence |
| --- | --- | --- | --- |
| I have a new project | Greenfield adoption | `naos adopt . --mode greenfield --profile standard --dry-run` | intake, install plan, context challenge, decision record |
| I have an existing repo | Brownfield adoption | `naos adopt . --mode brownfield --profile standard --dry-run` | inventories, baseline, candidate requirements, traceability gaps |
| I want to start work today | Daily task lifecycle | `/naos-task-start <TASK-ID>` on Lite+; Quickstart states task ID/scope/constraints explicitly; Standard/Assured may add `/naos-d-start` | task context, lifecycle checklist, review handoff |
| I want to split a task into lanes | Parallel lane planning | record `parallel_lane_opportunity` and `parallel_lane_decision`; Lite can review its installed template manually, Standard/Assured may run the installed handoff script, and Quickstart keeps the alignment decision manual | advisory lane posture and profile-available local review evidence |
| I am reviewing a PR | PR evidence flow | `naos gate-evaluate`, `naos evidence-pack`, `naos dashboard` | gate, evidence, dashboard, PR-risk reports |
| I changed governance surfaces | Systemic impact flow | `naos systemic-impact` and `naos control-plane-review` | routed findings, residual risks, next actions |
| I changed plugin or IDE adapter guidance | Adapter coherence flow | `naos adapter-coherence` | adapter drift, propagation, and non-claim findings |
| I need more assurance | Profile/gate/maturity flow | profile chooser, `naos capability-maturity`, gate commands | readiness posture and human-review decisions |

Do not read every tutorial first. Choose the route above, run the visible
commands, inspect the reports, and let human review decide durable outcomes.

---

## The Four Governance Profiles

NAOS ships with four profiles. Choose one based on your team size, risk,
evidence needs, and tolerance for stronger configured governance posture:

| Profile | Default Posture | Purpose |
|---------|-----------------|---------|
| `quickstart` | Advisory, low-friction | Bounded evaluation and minimal guardrails |
| `lite` | Warnings and light checks | Reduced-governance real-project workflow |
| `standard` | Required evidence where configured | Broader team and SDLC evidence workflow |
| `assured` | Strongest evidence profile; blocking where configured | Stronger configured evidence and reviewer handoff |

Profile choice does not make every capability mature immediately. Choose by
purpose; the profiles are not compulsory progression stages. Projects activate
and mature capabilities through configuration, readiness gates, validator
outputs, and evidence freshness. Setup effort is repository-specific and is not
an ROI or time-saving claim.

If an existing project's purpose changes, compare it with another profile
without claiming or applying a transition:

```bash
naos upgrade . --tier lite --dry-run
naos upgrade . --tier standard --dry-run
naos upgrade . --tier assured --dry-run
```

These commands produce plan-only comparisons and write nothing to the adopter
project. For an eligible managed transition, persist an external immutable
plan and apply only its reviewed digest through the separate upgrade command;
`naos init --activate` is not a profile-transition substitute.

---

## The NAOS Workflow — At a Glance

The installed workflow depends on the selected profile. The full session
rhythm below is installed by Standard and Assured. Lite installs the bounded
`/naos-task-start` → `@naos-plan` → `@naos-implement` → `@naos-review` →
`/naos-task-complete` route, with manual opening, closing, and cadence notes;
it does not install `@naos-triage` or `@naos-conformance`. Quickstart installs
no lifecycle prompts and only `@naos-research`, so its task scope and review
handoff are recorded explicitly without slash-command routing.

```
/naos-d-start          ← Begin session (requests governance-context review)
  │
  └─ /naos-task-start  ← Request task/card review
       │
       ├─ @naos-implement    ← Write code, tests, fixes
       ├─ @naos-review       ← Review for spec alignment
       └─ /naos-task-complete ← Request governance/lifecycle review

/naos-d-end            ← Request status/memory closeout
```

### Command → Agent Mapping

| Command | Agent | Purpose | Installed profiles |
|---------|-------|---------|--------------------|
| `/naos-d-start` | `@naos-plan` | Request governance-context review and session recovery | Standard, Assured |
| `/naos-task-start` | `@naos-plan` (default); `@naos-triage` only where installed | Request a story-card and task-context review | Lite, Standard, Assured; triage only Standard/Assured |
| *(implementation)* | `@naos-implement` | Coding, testing, bounded fixes | Lite, Standard, Assured |
| *(review)* | `@naos-review` | Spec alignment, function-index, deterministic hygiene, and duplicate-intent review where evidence exists | Lite, Standard, Assured |
| `/naos-task-complete` | Human review in Lite; `@naos-conformance` in Standard/Assured | Request governance review and an explicit lifecycle transition | Lite, Standard, Assured |
| `/naos-d-end` | `@naos-plan` | Session wrap, next-day priorities | Standard, Assured |

Some prompts and handoff records include a `next_action` footer. Read it as advisory guidance for the next safe workflow step; it is not an automated router.

Parallel lane posture fits inside the same workflow. During task start or
pre-implementation alignment, record whether a task is `sequential`,
`declared`, or `deferred`. Suggestions such as `parallel_possible` do not
activate handoff. Lite installs `naos/lane_handoffs/_TEMPLATE.yaml` for manual
review but not the handoff script. Standard and Assured may pass a declared,
filled template to the installed local handoff script and then review its
report with `naos control-plane-review`. Quickstart installs neither the lane
template nor the handoff script; record only the manual alignment decision
there.

---

## The Cadence Layer

Standard and Assured install the cadence prompts below. Lite uses the manual
weekly review described by its integral tutorial; Quickstart installs no
cadence prompts.

| Rhythm | Command | Agent | Frequency |
|--------|---------|-------|-----------|
| Weekly planning | `/naos-w-plan` | `@naos-plan` | Monday morning |
| Weekly review | `/naos-w-review` | `@naos-review` | Friday afternoon |
| Monthly review | `/naos-m-review` | `@naos-review` | End of month |

---

## Learning Paths

### Path A: "I want to try NAOS in 10 minutes"

1. Read [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md)
2. Follow [Integral Tutorial: Quickstart from Scratch](./INTEGRAL_TUTORIAL_QUICKSTART_FROM_SCRATCH.md)
3. Return here when you want to go deeper

### Path B: "I'm a solo developer adopting NAOS properly"

1. [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md) → choose `lite`
2. [Is NAOS Right for My Project?](./IS_NAOS_RIGHT_FOR_MY_PROJECT.md)
3. [Professional Adoption Engine](./PROFESSIONAL_ADOPTION_ENGINE.md) → run preflight, intake, inventory, challenge, and decision-record reports
4. [Integral Tutorial: Lite from Scratch](./INTEGRAL_TUTORIAL_LITE_FROM_SCRATCH.md) → use its exact manual opening/closing and task-complete review
5. [Micro Tutorial 11: naos-task-start](./MICRO_TUTORIAL_11_NAOS_TASK_START.md) → use the `@naos-plan` route, not the Standard/Assured-only triage alternative
6. [Micro Tutorial 12: Implement](./MICRO_TUTORIAL_12_NAOS_IMPLEMENT_IN_PRACTICE.md)
7. [Micro Tutorial 13: Review](./MICRO_TUTORIAL_13_NAOS_REVIEW_IN_PRACTICE.md)

### Path C: "My team is adopting NAOS for a production project"

1. [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md) → choose `standard`
2. [Professional Adoption Engine](./PROFESSIONAL_ADOPTION_ENGINE.md) → run greenfield or brownfield adoption evidence
3. Complete all micro-tutorials (10–15, 20–21)
4. [Integral Tutorial: Standard from Scratch](./INTEGRAL_TUTORIAL_STANDARD_FROM_SCRATCH.md)
5. Review [CONTROL_PLANE.md](../CONTROL_PLANE.md), [NAOS roadmap](../../ROADMAP.md), and [advisory compliance mapping](../COMPLIANCE_MAPPING.md) for public methodology context

### Path D: "We're in a regulated environment"

1. Review the Path C concepts that apply; completing that path is not a prerequisite for selecting Assured
2. [Integral Tutorial: Standard → Assured Readiness and Upgrade Preview](./INTEGRAL_TUTORIAL_STANDARD_TO_ASSURED.md)
3. Review [NAOS claims and limitations](../CLAIMS_AND_LIMITATIONS.md) and [advisory compliance mapping](../COMPLIANCE_MAPPING.md)

The `assured` profile supports stronger governance evidence and review posture. It is not a legal/regulatory assurance guarantee.

---

## How This Tutorial Set Is Structured

This tutorial set uses two complementary formats:

**Micro-tutorials** isolate individual commands, roles, rituals, and activities. They answer: *"What does this specific thing do, and how do I do it?"*

**Integral tutorials** show the full real workflow end-to-end. They answer: *"What does a complete NAOS session look like in practice?"*

Both are needed. The micro-tutorials build precise understanding. The integral tutorials show how the pieces connect.

---

## What You Will Be Able to Do After This Tutorial Set

- Install and configure NAOS for any project
- Run a proper daily session: start → task → implement → review → complete → end
- Use the weekly and monthly cadence to maintain governance health
- Produce governance evidence and reviewable metrics instead of relying on assertion
- Assess profile-transition targets with a no-write preview, then use a separately persisted digest-bound plan when applying an eligible managed transition
- Understand why each command exists and what happens if you skip it

---

## Next Step

→ [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md)

For a generated-project quick reference, see the seeded [NAOS_QUICK_REFERENCE.md](../../templates/structural-seeds/naos/NAOS_QUICK_REFERENCE.md).
