# ADR-0012: Secure-Coding & Agentic-Coding Control Register

**Status**: Accepted, implemented through P3
**Date**: 2026-06-21
**Corrected**: 2026-06-21
**Implementation status**: P0 corrective baseline, P1 canonical
register/rendering contract, P2 bounded control-plane evidence routing, and P3
bounded multidimensional reporting are implemented.

## Context

Secure-coding guidance in NAOS is useful but duplicated across multiple
instruction, agent, and rule surfaces. Hand-maintained copies drift. A second
duplication risk appears when the same requirement is rewritten once for each
standard or framework.

NAOS already has bounded deterministic hygiene controls such as
`CAP-SECRET-HYGIENE`, `CAP-DEPENDENCY-INTEGRITY`, and
`CAP-PR-RISK-CLASSIFICATION`. Their contracts deliberately do not claim complete
security, package safety, semantic truth, or approval. The control register must
preserve those boundaries and must not become a second profile-policy or
gate-decision authority.

The original blueprint exposed referential and architectural defects: an
invalid combined detector reference, a stale dashboard path, unversioned or
outdated standard mappings, and use of adapter coherence for a responsibility it
does not own. P0 corrected those defects. P1 then promoted the approved active
register, introduced the reviewed render manifest, and made deterministic
reference and generated-section drift checks mandatory.

## Decision

NAOS adopts one canonical secure-coding and agentic-coding control register,
subject to the following authority and propagation rules.

1. **Author once, render many.** Each control has one stable id and one canonical
   normative statement. Consumer surfaces may use:
   - a stable control id;
   - a generated bounded summary when a bare id would be unsafe or unusable in
     the consumer's active context; and
   - a link or path back to the canonical register.

   Generated summaries are derivative output. They must be reproducible,
   identifiable as generated, and checked for drift. Hand-authored copies must
   not become competing authorities.

2. **The register owns requirements, not enforcement.** The register owns:
   control ids, normative statements, applicability, evaluation declarations,
   non-claims, and standards-mapping metadata. It does **not** own profile
   severity, blocking behavior, gate outcomes, exceptions, waivers, approvals,
   or exit-code policy. Those remain in centralized policy, capability
   contracts, gatekeeper configuration, evidence, and human decision records.

3. **Standards are versioned mapping columns.** Mappings do not create parallel
   control sets. Every framework has an explicit version or as-of date. Every
   mapping has a lifecycle state:
   - `draft` — relevant-looking but not independently verified;
   - `verified` — checked against the named version with `verified_on` recorded;
   - `deprecated` — retained only for migration or history.

   A mapping cell is a relevance claim, not a satisfaction or conformance claim.
   Individual mappings remain `draft` unless independent verification metadata
   is present.

4. **Two coding-time planes.**
   - **Secure coding** covers controls acted on while humans or AI agents create
     or modify application code.
   - **Agentic coding** covers controls acted on while AI agents plan, generate,
     inspect, or execute code and tool actions.

   Runtime-only and organization-only controls remain outside the register.
   Organizational frameworks such as ISO/IEC 27002 and PCI DSS may appear only
   where a specific provision is materially relevant to a coding-time control;
   the register does not imply framework-wide coverage.

5. **Evaluation coverage is multidimensional and bounded.** Each control records
   `none`, `indirect`, `partial`, or `direct` deterministic coverage, the
   detector ids involved, detector-specific boundary notes, advisory surfaces,
   and the remaining human review. A detector must not be described as directly
   evaluating a broader control than its contract supports.

6. **Dedicated register and reference validation.** The active register is
   schema-validated. A dedicated reference-integrity validator verifies the
   canonical register, reviewed manifest bindings, declared advisory surfaces,
   renderer presence, and generated-section drift. Adapter coherence remains
   limited to adapter/plugin propagation and is not repurposed as a generic
   security-control reference engine.

7. **No blended security score.** Reporting may show separate dimensions for
   register validity, consumer-reference integrity, detector evidence
   availability and freshness, mapping verification, and human-review state.
   NAOS must not collapse these into a single score that could be mistaken for
   security assurance.

## Implemented P1 contract

The active implementation consists of:

- `configs/secure_coding_control_register.yaml` as canonical requirement data;
- `configs/secure_coding_control_render_manifest.yaml` as the reviewed binding
  between controls and generated consumer sections;
- `schemas/naos/secure_coding_control_register.schema.json` as the structural
  register contract;
- `scripts/validators/validate_secure_coding_control_register.py` for register,
  mapping, detector, and authority-boundary validation;
- `scripts/naos_render_secure_coding_controls.py` for deterministic bounded
  generation and non-mutating `--check` drift detection;
- `scripts/validators/validate_secure_coding_control_references.py` for
  canonical-reference, bidirectional manifest-binding, repository-boundary, and
  generated-section validation.

The initial generated consumers are:

- `templates/instructions/security.instructions.md`;
- `templates/instructions/ai-pipeline.instructions.md`;
- `templates/cursor-rules/naos-security-standards.mdc`.

Generated sections are requirement summaries, not enforcement authority or
security evidence.

## Current standards baseline

The register records the following editions while keeping individual mappings
`draft` pending control-by-control verification:

- OWASP ASVS 5.0.0;
- NIST SP 800-218 SSDF 1.1;
- OWASP Top 10:2025;
- OWASP Top 10 for LLM Applications 2025;
- OWASP Top 10 for Agentic Applications 2026 (`ASI01`–`ASI10`);
- NIST AI RMF 1.0;
- ISO/IEC 27002:2022;
- PCI DSS 4.0.1;
- CWE as a rolling catalogue with an explicit as-of date.

ASVS references must use the version-qualified `v<version>-<identifier>` form.
Framework edition metadata and individual mappings require periodic freshness
review; a populated mapping is not evidence of satisfaction or conformance.

## Boundaries

The register, validators, generated summaries, evidence routes, and reporting
do not prove:

- that code is secure, secret-free, vulnerability-free, or privacy-compliant;
- that dependencies exist, are correctly identified, or are safe unless a
  separate bounded detector and evidence support that claim;
- resistance to prompt injection, context leakage, excessive agency, or
  deceptive completion;
- conformance with OWASP, NIST, CWE, ISO, PCI DSS, or any regulation;
- certification, audit approval, release approval, or legal compliance.

Absence of a finding remains absence of a finding, not proof of safety.

## Consequences and phased implementation

- **P0 — corrected baseline: complete.** Repaired references, authority
  boundaries, mapping versions/status, indexes, and dashboard path; added the
  schema, register validator, tests, CI execution, and bounded compliance view.
- **P1 — canonical data and rendering contract: complete.** Promoted the active
  register, added the reviewed manifest and deterministic renderer, migrated the
  initial duplicated consumers, and added mandatory reference/drift validation.
- **P2 — control-plane wiring: complete.** Added the bounded capability,
  schema-validated detector/evidence routing contract, deterministic routing
  report, G4/G6 evidence routes, systemic-impact/control-plane-review routes,
  adopter seeding, CLI/Make wrappers, tests, and CI without moving policy, gate,
  exception, approval, or release authority into the register.
- **P3 — bounded multidimensional reporting: complete.** Added a separately
  bounded reporting capability and exact five-dimension schema; invoked and
  persisted the authoritative P1/P2 results; added fail-closed source-contract
  checks, a non-mutating portable adopter path adapter, preflighted symlink-safe
  projection into existing dashboard/evidence artifacts, central policy paths,
  Lite+ seeding, CLI/Make exposure, package data, tests, and Python 3.11-3.13 CI.
  The P3 report remains derived presentation and is not a new G4/G6 gate input,
  approval signal, or composite security score.

Each phase requires its own review. P0/P1/P2/P3 validation confirms structural,
referential, generated-output, routing, source-contract, and bounded projection
coherence only. It does not activate adopter security enforcement or satisfy any
security, release, approval, certification, or compliance obligation.
