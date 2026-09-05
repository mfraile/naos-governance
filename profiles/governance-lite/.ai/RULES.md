# AI Assistant Rules - Governance Lite

**Version**: 1.0.0 | **Profile**: governance-lite | **NAOS Kit**: v1.0
**Applies To**: all AI assistants and humans using the kit

> Lite is the low-friction guardrail profile. It keeps essential guidance intended
> to reduce avoidable governance drift while leaving the full agent, traceability,
> and evidence workflow to standard/assured. It is guidance and review evidence,
> not approval, certification, compliance proof, behavioral proof, or
> hallucination prevention. Repository evidence remains authoritative.

Use this file as a compact rule index. See `naos/NAOS_QUICK_REFERENCE.md`.
Consider Standard for team or production use; plan first, then apply only through the separate digest-bound workflow.

## Enforcement Key

| Mark | Meaning |
| --- | --- |
| BLOCKING | Must be satisfied or explicitly waived by project policy/human review. |
| ADVISORY | Consider and document when relevant. |
| DEFERRED | Available in standard/assured; do not claim it is enforced in lite. |
| ADAPT | Project-specific details must be filled in before relying on the rule. |

## Active Lite Rules

| Rule | Lite posture |
| --- | --- |
| 1 Update existing files | BLOCKING |
| 2 No archive folders | BLOCKING |
| 5 Exploration notes only | ADVISORY |
| 7 Deep analysis protocol | ADVISORY |
| 10 License compliance | BLOCKING |
| 19 Memory governance | ADVISORY |
| 20 Dependency declaration | ADVISORY |
| 24 Work-item context brief | ADVISORY |
| 26 Cognitive checkpoint | ADVISORY |

Rules 3, 4, 12, 15, 16, 17, and 23 require project adaptation. Rules 6, 8,
9, 11, 13, 14, 18, 21, 22, and 25 are deferred to standard/assured unless a
project policy explicitly adopts them.

## Rule 1: Update Existing Files

Do not create throwaway summaries, final reports, or duplicate status files when
a canonical file exists. Update the current README, status, backlog, specs, or
existing doc instead.

**Policy-review patterns** (not comprehensively checked by pre-commit):
`*_SUMMARY.md`, `*_ANALYSIS.md`, `*_PLAN.md`, `*_FINAL*.md`; hook source is narrower.

## Rule 2: No Archive Folders

Do not create `archive/`, `old/`, `backup/`, or similar history folders. Git is
the archive. Remove obsolete tracked files with normal version-control review.

## Rule 5: Exploration Notes Only

`docs/exploration/` may contain POCs, research notes, tool evaluations, and
brainstorming. It is not authoritative for code/spec behavior unless promoted
through the project documentation and traceability flow. Research outputs should
state scope, evidence location, and next action.

## Rule 7: Deep Analysis Protocol

Use evidence-first analysis for analytical work, dependency decisions, bug
investigations, and non-trivial implementation.

Core principles: validate on real project data; search affected files; verify
claims at source; compare alternatives when risk justifies it; design fallback;
document evidence/risk; avoid scope drift.

Lite minimums: dependency changes require source/license verification; bug work
requires reproduction and impact search; feature work requires affected-file
search, tests/evidence, and explicit out-of-scope.

## Rule 10: License Compliance

Do not add AGPL/GPL/copyleft-risk dependencies without explicit project
approval. Verify license at source such as package metadata, PyPI, registry
metadata, or LICENSE files; do not rely only on README badges. Declare approved
dependencies where the project keeps manifests.

## Rule 19: Memory Governance

Memory is advisory recall, not evidence or authority. Do not store secrets,
PII, customer data, credentials, regulated content, or sensitive project data in
AI memory. Durable memory writes require configured, authorized, verified,
policy-permitted access plus explicit human approval. Repo evidence outranks
memory.

## Rule 20: Dependency Declaration

Every new runtime, dev, model, service, integration, MCP server, or tool
dependency should be declared in the proper manifest/config and represented in
docs/evidence when it changes behavior or risk.

## Rule 24: Work-Item Context Brief Protocol

Each active work item should be recoverable from repository files: goal, scope,
constraints, affected files, evidence, risks, decisions, current status, and
next action. Chat history and memory are advisory only.

## Rule 26: Cognitive Checkpoint Protocol

At phase transitions, long sessions, high context pressure, or before risky
changes, checkpoint status, changed files, evidence, decisions, risks, and next
action. Compacted chat is not authoritative; repository files and NAOS reports
are.

## Deferred or Adapted Rules

When Lite needs stronger governance, consider Standard instead of copying rule
text. Compare only: `naos upgrade . --tier standard --dry-run` (no apply).
Standard/Assured add README freshness, migration safety, scope, duplication,
resilience, schema, agent/skill, model, artifact, instinct, and control-plane controls.

Project-specific PM infrastructure, documentation impact, data-flow invariants,
module boundaries, spec alignment, pre-coding context, and project rule
lifecycle must be adapted locally before they are treated as enforced.
