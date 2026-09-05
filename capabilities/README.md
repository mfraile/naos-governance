# NAOS Capability Contracts

NAOS ships a portable, file-first capability-contract framework for SDLC
governance. It does not ship runtime governance, behavioral grading, or
compliance certification. Projects activate and mature capabilities
progressively through profiles, readiness gates, and evidence.

This directory contains kit-level capability contracts. They are not a second
NAOS product and they do not mean every adopting project is immediately fully
governed. A project reaches higher maturity only when it selects a profile,
configures the capability, runs validators, produces evidence, and accepts the
relevant gatekeeper policy.

`CAP-SYSTEMIC-IMPACT-REVIEW` adds a configurable artifact-family coherence
review. It identifies review obligations and missing/stale/not_configured
relationships; it does not prove perfect coherence or complete impact analysis.

`CAP-MODULE-HEADER-TRACEABILITY` adds deterministic review of configured Python
source module headers. It reports missing, legacy, stale, or duplicate
traceability metadata; it does not prove source correctness or complete
traceability.

`CAP-SPEC-CASCADE-COHERENCE` adds deterministic review of requirement, task,
source-header, and source-root linkage. It reports structural traceability gaps;
it does not prove complete traceability, code correctness, runtime behavior,
approval, certification, or compliance.

`CAP-AI-SURFACE-HEALTH` adds deterministic review of AI/governance instruction
surface context health. It reports context-budget pressure, required anchors,
combined loadout risk, and optional approved-baseline drift; it does not prevent
hallucinations, grade behavior, auto-tune thresholds, approve work, certify
prompt fidelity, or prove compliance.

`CAP-GOVERNED-LEARNING-LIFECYCLE` adds deterministic review of candidate,
active, and historical learning records. It supports reviewed promotion,
replacement, forgetting, redaction, and rollback posture; it does not write
memory, mutate governed artifacts, prevent hallucinations, approve work, or
prove semantic truth.

## Maturity Levels

| Level | Name | Meaning |
| --- | --- | --- |
| L0 | Scaffolded | Capability exists in the kit as files, templates, schemas, or docs. |
| L1 | Configured | Project has selected a profile and configured the capability. |
| L2 | Operational | Capability runs and produces evidence. |
| L3 | Enforced | Gatekeeper warns or blocks based on profile severity. |
| L4 | Measured | Dashboard tracks maturity, exceptions, drift, and trends. |
| L5 | Assured | Evidence is complete enough for regulated or audit-style review. |

## Profile Behavior

| Profile | Default stance |
| --- | --- |
| quickstart | Scaffold/advisory only. No blocking advanced gates. |
| lite | Warnings and lightweight checks. Minimal evidence expectations. |
| standard | Required evidence for normal SDLC work and stronger gates. |
| assured | Blocking gates where appropriate, evidence packs, exceptions, and approvals. |

Tier 3 capability tracks are marked `status: experimental`, default to `L0`,
and remain advisory unless a project deliberately configures and matures them.
