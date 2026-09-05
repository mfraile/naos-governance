# Agentic Coding Playbook

This playbook describes NAOS-native operating practices for AI-assisted
software delivery. It is tool-neutral: the primary contract is repo files, CLI
commands, Make targets, schemas, reports, gates, and human review.

## Operating Model

- Keep work bounded to a task, feature, or vertical slice.
- Route natural-language intent to explicit NAOS commands: greenfield adoption,
  brownfield adoption, daily task lifecycle, PR/release evidence, or systemic
  impact review.
- Prefer a fresh session or clearly declared task boundary where practical.
- Use task context packs and repository evidence instead of relying on long chat
  accumulation.
- Treat compacted chat summaries as advisory notes, not authority.
- Run Pre-Implementation Alignment before non-trivial implementation.
- Prefer vertical slices and tracer-bullet delivery over broad horizontal work.
- Use tests, type checks, validators, gates, and evidence reports as feedback
  loops.
- Prefer deep modules with stable interfaces over shallow wrapper sprawl.
- Separate human-in-the-loop planning, architecture, risk acceptance, QA, and
  final review from bounded implementation tasks.
- Use task claims and explicit dependencies before parallel agent or operator
  work.
- Record `parallel_lane_opportunity` and `parallel_lane_decision` before
  splitting material work into logical or team lanes.
- Keep pull context and push checks distinct.

## Pull Context

Pull context is the bounded material an operator or assistant reads before work:

- `naos/NAOS_QUICK_REFERENCE.md`
- `naos/active/*.md`
- `naos/TASK_REGISTRY.yaml`
- `naos/AGENTIC_CODING_PLAYBOOK.md`
- `naos/PRE_IMPLEMENTATION_ALIGNMENT.md`
- `naos/PLANNING_BASELINES.yaml` (Lite, Standard, and Assured)
- `naos/reports/task_context_pack.json`
- relevant specs, capability contracts, and source files

Pull context does not silently inject itself into any assistant. Humans decide
what context to provide and when.

## Push Checks

Push checks are deterministic reports or validators run after decisions or code
changes:

- `make -f Makefile.naos naos-agentic-workflow-review`
- `make -f Makefile.naos naos-pre-implementation-alignment-review`
- `make -f Makefile.naos naos-plan-coherence`
- `make -f Makefile.naos naos-task-context TASK=T-123`
- `make -f Makefile.naos naos-task-claim TASK=T-123`
- `make -f Makefile.naos naos-gate-evaluate`
- `make -f Makefile.naos naos-evidence-pack`
- `make -f Makefile.naos naos-pr-risk-classify`
- `make -f Makefile.naos naos-pr-governance-summary`
- `make -f Makefile.naos naos-cross-harness-review-readiness`

Push checks are review evidence. They do not approve work, prove correctness,
prove requirements completeness, prove PR safety, approve pull requests, or
replace human review.

## Pre-Implementation Alignment

Use `naos/PRE_IMPLEMENTATION_ALIGNMENT.md` before greenfield setup, brownfield
onboarding, or non-trivial feature implementation. The alignment artifact should
declare:

- intended user and problem statement
- first vertical slice
- input/output contract
- edge cases and failure modes
- security and privacy assumptions
- existing interfaces touched and compatibility constraints
- test strategy and evidence required
- explicit out-of-scope items
- optional planned and out-of-scope path declarations for advisory
  plan-coherence diff review
- human review boundary

The alignment artifact is a disciplined planning record. It is not design
approval, implementation approval, requirements completeness proof, compliance
proof, semantic drift proof, or human review replacement.

## Implementation-Readiness Planning Baseline

Discovery notes, draft tasks, and draft plans may be created and revised while
the specifications evolve. The first plan that claims `implementation_ready`
has a stricter boundary recorded in `naos/PLANNING_BASELINES.yaml`:

- Lite binds `specs/03-requirements.md`, the stable planning projection of
  `naos/TASK_REGISTRY.yaml`, Pre-Implementation Alignment, passing structural
  spec-pack evidence, alignment-review evidence, and an attributable owner
  decision. Lite does not require or synthesize `specs/04-architecture.md`.
- Standard and Assured bind the same inputs plus
  `specs/04-architecture.md`.
- Every non-terminal task appears exactly once as a vertical slice or an
  allowed horizontal foundation.
- Hybrid planning is used, with vertical delivery as the default. A horizontal
  foundation must name a consuming vertical slice and the concrete consumed
  result it changes.

Run `naos plan-coherence` while the ledger is draft to obtain the current
`implementation_readiness.digest_candidates`. After the human records a
`planning_baseline` decision, update the ledger and rerun the command. G2 uses
the live result, so a stale or failing report file cannot make the gate ready.

Plans and specifications remain changeable. A structural change to requirements,
architecture where applicable, task decomposition, alignment, or bound evidence
requires a new version that supersedes the prior baseline. Routine task status,
delivery, or verification progress is excluded from the stable task-plan digest
and does not by itself require replanning.

A ready baseline proves only that these declared structural inputs converge. It
does not prove requirements or architecture quality, real-world authority,
implementation correctness, task closure, merge approval, release authority, or
publication authority.

## Context Hygiene

Model performance may degrade with excessive or poorly structured context.
Bounded task context improves auditability and makes evidence easier to review.
Fresh task context is recommended where practical. If a session has been heavily
compacted, verify important facts against repository files and NAOS reports.

## Vertical Slices And Feedback Loops

Prefer the smallest end-to-end slice that exercises real inputs, outputs,
tests, and evidence. A tracer-bullet slice should demonstrate the path through
the system before broader expansion. Where feasible, record red-green evidence
or an equivalent failing-then-passing feedback loop.

## Module Design

Favor modules that hide meaningful complexity behind stable interfaces. Avoid
adding shallow wrappers that merely shuffle names or duplicate intent. When an
interface changes, update tests, module-header traceability, spec-pack, spec-cascade
coherence when requirement/task/source links changed, function-index health,
and relevant evidence.

## Human / AI Work Split

Human-owned work includes planning, architecture, risk acceptance, QA, final
review, waiver decisions, and release decisions. Bounded implementation,
deterministic refactors, generated report review, and evidence updates can be
good candidates for assisted or unattended work when task claims, scope, tests,
and gates are clear.

## Kanban / DAG Discipline

Represent dependencies explicitly. Do not parallelize work that shares mutable
files, unclaimed tasks, or unresolved architectural decisions. Use task claims
to reduce duplicate work, and keep stale or conflicting claims visible.

## Parallel Lane Planning And Handoff

Use parallel lanes only when the task has independent acceptance criteria,
distinct path scopes, dependency-unlocked chunks, or context load that justifies
the overhead. For solo developers, lanes are usually logical checkpoints rather
than concurrent execution. For teams, each lane should link task/FR/NFR refs,
dependency state, planned paths, tests/checks, task claim posture,
operator/session metadata, residual risks, and human review.

`parallel_lane_opportunity` is advisory. `parallel_lane_decision` is the
human/project decision. Suggested lanes do not activate handoff. Declared lanes
can use `naos/lane_handoffs/_TEMPLATE.yaml` and
`python scripts/naos_parallel_lane_handoff.py --handoff ...` to produce local
review evidence, followed by `naos control-plane-review` for HITL routing. This
does not create branches or worktrees, dispatch agents, run tests, approve
work, merge, close tasks, release, certify, attest, or prove compliance.

## Cross-Harness / DSSE-Style Planning

Future cross-harness review or DSSE-style signing plans must stay
readiness-only unless the adopter separately designs, approves, and operates
them. Use `naos cross-harness-review-readiness` to inspect declared trust
boundaries and adopter-owned key-custody responsibilities. Do not treat the
report as execution, signing, attestation, approval, certification, or proof of
compliance.

## Non-Claims

NAOS does not claim:

- behavioral correctness proof
- hallucination prevention
- model attention guarantee
- autonomous approval
- design approval
- implementation approval
- requirements completeness proof
- compliance proof
- human review replacement
- memory write-back
- hidden context injection
