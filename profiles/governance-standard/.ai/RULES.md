# AI Assistant Rules - Governance Standard

**Version**: 1.0.0 | **Profile**: governance-standard | **NAOS Kit**: v1.0
**Applies To**: all AI assistants and humans using the kit

> Standard is the balanced production profile. It activates the portable rule set,
> agents, skills, task registry, traceability, deterministic review commands, and
> evidence/dashboard refresh. It is governance guidance and review evidence, not
> approval, certification, compliance proof, behavioral proof, or hallucination
> prevention. Repository evidence remains authoritative.

Use this file as the compact rule index. For command details, use
`naos/NAOS_QUICK_REFERENCE.md`; for system wiring, use
`.github/skills/systemic-capability-wiring/SKILL.md`; for AI-surface budget
warnings, use `.github/skills/ai-surface-health-review/SKILL.md` where installed.

## Enforcement Key

| Mark | Meaning |
| --- | --- |
| BLOCKING | Must be satisfied or explicitly waived by project policy/human review. |
| ADVISORY | Must be considered and documented when relevant; may become stricter by team policy. |
| ADAPT | Project-specific details must be filled in before relying on the rule. |

## Quick Reference

| Rule | Standard posture |
| --- | --- |
| 1 Update existing files | BLOCKING |
| 2 No archive folders | BLOCKING |
| 3 PM infrastructure | ADAPT |
| 4 Documentation impact | ADAPT |
| 5 Exploration notes only | BLOCKING |
| 6 README/status freshness | ADVISORY |
| 7 Deep analysis protocol | BLOCKING |
| 8 Bulk migration safety | BLOCKING |
| 9 Enhancement scope control | ADVISORY |
| 10 License compliance | BLOCKING |
| 11 Anti-duplication | ADVISORY unless project policy requires blocking |
| 12 Data flow invariants | ADAPT |
| 13 Resilience and retry | BLOCKING |
| 14 Event schema evolution | BLOCKING |
| 15 Module boundaries | ADAPT |
| 16 Spec alignment | ADAPT |
| 17 Pre-coding context | ADAPT |
| 18 Agent and skill governance | BLOCKING |
| 19 Memory governance | BLOCKING |
| 20 Dependency declaration | BLOCKING |
| 21 ML model governance | ADVISORY unless ML is production-critical |
| 22 Artifact/resource management | ADVISORY |
| 23 Project rule lifecycle | ADAPT |
| 24 Work-item context brief | BLOCKING |
| 25 Instinct recording | ADVISORY |
| 26 Cognitive checkpoint | BLOCKING |

## Rule 1: Update Existing Files

Do not create throwaway summaries, final reports, or duplicate status files when a
canonical file already exists. Update the current status, backlog, registry,
README, changelog, specs, or existing doc instead.

**Policy-review patterns** (not comprehensively checked by pre-commit):
`*_SUMMARY.md`, `*_ANALYSIS.md`, `*_PLAN.md`, `*_FINAL*.md`; hook source is narrower.

## Rule 2: No Archive Folders

Do not create `archive/`, `old/`, `backup/`, or similar history folders. Git is
the archive. Remove obsolete tracked files with normal version-control review.

## Rule 3: Project PM Infrastructure - ADAPT

Define the project source of truth for task/status data: status document,
dashboard, task registry, issue tracker, sprint board, and atomic update order.
Agents must know where to read and where not to invent task state.

## Rule 4: Documentation Impact Checklist - ADAPT

Before code, configuration, workflow, policy, or governance-surface changes,
check whether root docs, specs, operations docs, quick references, manuals,
capability contracts, gates, dashboards, or evidence docs require updates.

## Rule 5: Exploration Notes Only

`docs/exploration/` may contain POCs, research notes, tool evaluations, and
brainstorming. It is not authoritative for code/spec behavior unless promoted
through the project documentation and traceability flow. Research story cards
must include scope, evidence location, output artifact, and Rule 7 completion.

## Rule 6: Refresh README/Status Before Main Push

Before pushing material changes to main, review README, current status,
changelog, dashboard, and quick-start docs. If changed behavior affects adopters,
refresh the relevant docs or record why no doc update is needed.

## Rule 7: Deep Analysis Protocol

Apply evidence-first analysis to analytical work, bug fixes, dependency choices,
and non-trivial implementation.

Principles: validate on real project data; search all affected files; verify
claims at source; compare alternatives when risk justifies it; design fallback;
document decision/evidence/risk; avoid scope drift.

Minimum triggers: dependency changes require license/source verification; bug
work requires reproduction and impact search; feature work requires affected-file
search, fallback, tests/evidence, and scope boundary; "think deeply" or
"ultrathink" requires the full protocol.

## Rule 8: Bulk Code Migration Safety

For broad replacements or changes touching many files: enumerate occurrences,
classify each occurrence, avoid corrupting comments/examples/string literals,
structurally validate modified source, remove dead imports, and test affected
backends or execution paths.

## Rule 9: Enhancement Scope Control

For new capabilities, compliance work, multi-surface changes, or scope expansion:
map impacts before implementation, evaluate viable alternatives, define fallback
and rollback posture, keep adjacent opportunities out of scope, and update
governance surfaces in the same change when behavior changes.

## Rule 10: License Compliance

Do not add AGPL/GPL/copyleft-risk dependencies without explicit project approval.
Verify license at source such as package metadata, PyPI, registry metadata, or
LICENSE files; do not rely only on README badges. Declare approved dependencies
with exact versions and update third-party/license records when applicable.

## Rule 11: Anti-Duplication Protocol

Before creating new functions, classes, scripts, validators, prompts, skills, or
docs, inspect the existing codebase and indexes where present. Reuse or extend
existing intent when practical. New overlap requires a short rationale.

## Rule 12: Data Flow Invariants - ADAPT

Project teams must encode schema boundaries, data ownership, privacy rules,
domain isolation, lifecycle routing, convergence points, and prohibited flows.
Until adapted, agents must not infer data-flow authority from this generic file.

## Rule 13: Resilience and Retry Conventions

External calls and failure paths need configured timeouts, retry only for
transient failures, backoff with jitter, fail-fast for validation/auth/client
errors, and no silent swallowing. Errors must be re-raised, logged at useful
severity, surfaced to DLQ/evidence, or explicitly justified.

## Rule 14: Event Schema Evolution

Event and message schemas should be additive within a version, preserve backward
compatibility, validate from raw payloads, maintain golden examples where useful,
and introduce a new version for breaking changes.

## Rule 15: Module Boundary Protocol - ADAPT

Document project layering, bounded contexts, public API surfaces, ownership,
cross-module call rules, async/job boundaries, and forbidden dependencies. Agents
must inspect existing boundaries before moving or adding code.

## Rule 16: Spec Alignment Protocol - ADAPT

Link code, tests, tasks, and specs using the project's chosen traceability
headers or registries. Missing traceability is missing evidence, not a pass.

## Rule 17: Pre-Coding Context Protocol - ADAPT

Before writing code, gather bounded task context: problem, user, first vertical
slice, IO contract, existing implementation to reuse, risks, tests, evidence,
and explicit out-of-scope. Use `naos/PRE_IMPLEMENTATION_ALIGNMENT.md` when the
work is ambiguous or high risk.

## Rule 18: Agent and Skill Governance

Agents, prompts, skills, instructions, and workflows are governed surfaces.
Keep frontmatter parseable, tools least-privilege, phase handoffs
human-mediated, and project specifics in project-context files or explicit
overlays. Changing these surfaces requires AI-surface budget, systemic impact,
and control-plane review routing as applicable.

## Rule 19: Memory Governance

Memory is advisory recall, not evidence or authority. Do not store secrets, PII,
customer data, credentials, regulated content, or sensitive project data in AI
memory. Durable memory writes require configured, authorized, verified,
policy-permitted access plus explicit human approval. Repo evidence outranks
memory.

## Rule 20: Dependency Declaration

Every new runtime, dev, model, service, integration, MCP server, or tool
dependency must be declared in the proper manifest/config, versioned where
appropriate, and represented in docs/evidence when it changes behavior or risk.

## Rule 21: ML Model Governance

For ML/model behavior: separate model tests from ordinary unit tests, record
model/provider/version/config metadata, document data exposure and bias/drift
risk, preserve human-in-the-loop review for consequential use, and avoid claims
of semantic safety without implemented evidence.

## Rule 22: Artifact and Resource Management

Do not commit oversized files, unmanaged checkpoints, generated caches, secrets,
or model artifacts unless explicitly approved and documented. Prefer manifests,
external storage, checksums, and reproducible generation instructions.

## Rule 23: Project Rule Lifecycle - ADAPT

Define how project-specific rules are proposed, reviewed, accepted, deprecated,
and enforced. New rules need ownership, affected surfaces, evidence expectations,
and rollback/deprecation handling.

## Rule 24: Work-Item Context Brief Protocol

Each active work item should be recoverable from repository files: goal, scope,
constraints, affected files, evidence, risks, decisions, current status, and next
action. Chat history and memory are advisory only.

## Rule 25: Instinct Recording Protocol

Recurring AI/human failure patterns may become instincts before they become
rules. Record the trigger, example, risk, proposed response, owner, and review
date. Do not duplicate existing rules.

## Rule 26: Cognitive Checkpoint Protocol

At phase transitions, long sessions, high context pressure, or before risky
changes, checkpoint status, changed files, evidence, decisions, risks, and next
action. Use session lifecycle commands where configured. Compacted chat is not
authoritative; repository files and NAOS reports are.

## Standard Review Routine

For meaningful implementation or governance-surface changes, run the smallest
relevant deterministic chain from `naos/NAOS_QUICK_REFERENCE.md`. Typical
standard review includes AI-surface budget, systemic impact, control-plane
review, self-check, static grader, grader assessment, gate status/evaluation,
evidence pack, and dashboard. Reports are deterministic review input and do not
approve work by themselves.
