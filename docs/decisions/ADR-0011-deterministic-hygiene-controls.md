# ADR-0011: Deterministic Hygiene Controls

**Status**: Accepted
**Date**: 2026-06-07
**Scope**: Duplicate-function, secret, test-quality, dependency-integrity, package-reality, API-symbol reality, spec-pack, spec-cascade, and PR-risk deterministic controls

## Context

The Superpowers/OpenSpec forensic review exposed a recurring NAOS risk: several
important claims were true only for specific deterministic surfaces, while other
risk classes required future semantic or model-backed review. NAOS needs hygiene
controls that are useful today without overstating what static checks can prove.

## Decision

NAOS keeps deterministic hygiene controls as file-first review evidence:

- duplicate-function hygiene detects normalized duplicate function bodies;
- secret hygiene detects obvious secret-like literals and high-entropy strings;
- test-quality hygiene detects missing or trivial assertions;
- dependency-integrity detects undeclared or unresolved imports;
- package-reality reviews package names, lock-style pins, optional docs install
  snippets, configured local CycloneDX SBOM/provenance/hash evidence, and
  explicit opt-in registry metadata;
- API-symbol reality checks explicitly declared Python symbols through local
  source inspection without importing target modules;
- spec-pack contract detects template/file/anchor/marker contract drift;
- spec-cascade coherence detects requirement/task/source cascade gaps;
- PR-risk classification detects path, diff, workflow, dependency, AI-surface,
  and contributor-risk indicators.

These controls are wired through reports, policy paths, Make/CLI surfaces,
evidence packs, dashboards, gates, SARIF export where applicable, and tests.

## Boundaries

The controls do not prove:

- semantic correctness;
- absence of all duplicate behavior;
- absence of all secrets;
- API behavior, option compatibility, or endpoint behavior;
- package safety or supply-chain integrity;
- behavioral correctness;
- PR approval, release authorization, certification, or legal/regulatory compliance.

When a control reports a finding, the finding is a review input. When a control
does not report a finding, that is not a proof of safety.

## Consequences

Deterministic controls are appropriate for default and CI-friendly governance
because they are inspectable, reproducible, local, and cheap. Harder semantic
or behavioral judgments remain future/project-configured advisory layers unless
an adopter explicitly wires a judge, records residual risk, and keeps human
approval boundaries intact under `ADR-0010: Control-Plane Advisory Boundaries`.

This ADR also records the CI hygiene rule for tests that create temporary git
repositories: fixture commits should pass `--no-gpg-sign` so local or sandbox
commit-signing policies do not mask the behavior under test.
