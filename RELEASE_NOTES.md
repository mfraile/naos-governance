# NAOS-Governance 1.1.0 Public Release Candidate Notes

These notes describe the sanitized NAOS 1.1.0 publication candidate prepared
for history-free repository import and hosted verification. Repository staging
and green hosted CI are not a publication event or release authorization.
Public visibility, a tag, a GitHub release, and package upload remain separately
gated.

The unreleased candidate corrections to task identity, staged Git checks,
gate inputs, attestations, report freshness, and trace validation are described
in [contract and migration guidance](docs/CONTRACT_REVALIDATION.md). The package
version remains 1.1.0 while this candidate is reviewed.

## Changes Since the 1.0.0 Candidate

After the historical 1.0.0 public release-candidate notes were written, NAOS added
`naos package-reality` and `make -f Makefile.naos naos-package-reality`.
The command writes deterministic review evidence for package names,
lock-style pins, optional docs install snippets, and registry existence only
when explicitly run with `--registry-mode online --allow-network`.
NAOS also added `naos api-symbol-reality` and `make -f Makefile.naos
naos-api-symbol-reality` for deterministic review of explicitly declared
Python API symbols by source inspection without importing target modules.
The kit also pins `requirements.txt` to `PyYAML==6.0.1` and
`jsonschema==4.19.2` for reproducible local validation while leaving
`pyproject.toml` package metadata ranges broader.

This delta is not a publication event, package approval, security assurance,
API behavior proof, vulnerability scan, supply-chain assurance,
registry-trust proof, certification, compliance proof, or release authorization.

The 1.1.0 claims are supported by current candidate files and executed
validation; historical development milestones are not reused as release proof.
Publication remains a separate maintainer action.

## Summary

NAOS is a file-first governance-as-code kit for AI-assisted software
development. It helps teams define repository truth, index bounded context,
query candidate references, package task context, review evidence, and record
decisions through deterministic artifacts and explicit human-review boundaries.

## Highlights

- Control-plane readiness: capability contracts, profile-aware policy, gates,
  self-checks, dashboard summaries, evidence pack export, and reviewer
  attestation.
- Advisory boundary contract: ADR-0010 keeps deterministic controls primary,
  advisory controls complementary, residual risks explicit, and durable
  decisions human-reviewed.
- Public interoperability: SARIF 2.1.0 findings export lets code-scanning and
  security-review tooling consume NAOS findings without turning them into
  approval, attestation, certification, or compliance proof.
- Static customization: adopter-local YAML policy overlays can adapt approved
  paths, thresholds, and preferences without plugin execution or protected
  invariant weakening.
- Behavioral grading foundation: agent trace validation, BaseGrader,
  StaticGrader, and audit/drift/assess assessment modes provide deterministic
  structural review inputs only.
- LLMGrader readiness: readiness-only configuration/reporting makes any future
  LLM-as-judge posture explicit, cost-aware, data-aware, bias/drift-aware, and
  advisory-only while runtime remains disabled.
- Generated adopter workflow: `naos init`, `naos add setup-module`, CLI helpers,
  `naos/NAOS_QUICK_REFERENCE.md`, and generated-adopter Make targets via
  `make -f Makefile.naos ...`.
- Memory/context architecture: memory readiness, memory provider/access posture,
  memory-use policy, task context packs, local context index/query, graph
  context readiness/query, semantic candidate readiness, and session lifecycle
  reports.
- Regulated team workflow foundations: session identity, operator attribution,
  SQLite write coordination, append-only audit log, evidence conflict detection,
  task claim/release coordination, team/operator overlays, multi-team gatekeeper
  posture, and PR-time governance CI evidence templates.
- Optional tool integration templates: Spec-Kit adapter templates, Claude Code
  hook templates, and tool-neutral usage documentation remain optional,
  dry-run-friendly convenience layers rather than core dependencies.
- Governed agentic coding workflow: deterministic, file-first agentic workflow
  review plus Pre-Implementation Alignment artifacts, schemas, reports, CLI
  commands, Make targets, setup-module wiring, and playbook guidance.
- Public docs and installer polish: public ADRs, audit playbook, threat model,
  assured-profile activation guidance, behavioral audit enablement guidance,
  cross-harness readiness guidance, and clearer install/init/add-module docs.
- Calibration and evidence classification: deterministic calibration-shadow
  checks over local report metadata and provenance classification for findings.
- Cross-harness and DSSE readiness: readiness-only metadata for future
  independent review, trust-boundary, artifact-hashing, and key-custody planning
  without harness execution, signing, verification, or key custody in core.
- Public-safety posture: sanitized export validation, public-candidate
  verification, clean install acceptance, archive integrity checks, and package
  file-list inspection.
- Public-candidate verification: a minimal, read-only hosted workflow builds
  the candidate, installs its wheel in a clean environment, validates the
  public regulatory matrix, generates Quickstart and Standard projects, checks
  the public receipt, and validates training, installation, and Mermaid-source
  consistency. It does not reproduce the wider maintainer test suite.

## Detailed Technical Notes

- Deterministic reports are reproducible, source-linked, bounded, and
  reviewable. They are not perfect proof and do not replace human review.
- Repository evidence remains authoritative. Context packs, local indexes, query
  reports, graph reports, semantic readiness reports, session reports, evidence
  packs, dashboards, grader reports, and SARIF files are derived artifacts.
- Local context query results are candidates, not answers.
- Graph query results are relationship candidates, not truth.
- Semantic/vector behavior is readiness-only by default and
  future/project-configured.
- Memory is advisory by default. Instruction-grade memory requires explicit
  approval, provenance, scope, reviewer, timestamp, freshness/expiry, and a
  human boundary.
- Agent trace events are declared records, not runtime capture, approval,
  memory writes, or proof of correctness.
- StaticGrader is deterministic and structural only. It costs 0.0 by default,
  calls no model/API/provider, and does not prove behavior, semantic
  correctness, runtime safety, legal/regulatory posture, or hallucination risk.
- Grader assessment audit mode is deterministic review input, drift mode
  compares deterministic reports without semantic drift inference, and assess
  mode summarizes posture rather than certification.
- LLMGrader readiness does not run an LLM, read API keys, call providers, or
  incur cost. Future advisory use requires budget, data exposure review,
  residual-risk review, and human approval.
- SARIF export is findings interoperability only. It does not approve work,
  certify compliance, attest evidence, promote maturity, or replace repository
  evidence.
- Calibration shadow monitors deterministic report stability only. It is not
  model calibration or behavioral correctness proof.
- Evidence classification is provenance classification for review. It is not
  truth proof, issue resolution, legal conclusion, or compliance proof.
- Cross-harness review readiness and DSSE readiness are planning metadata only.
  The v1.1.0 candidate does not execute external harnesses, sign artifacts, verify
  signatures, custody keys, create signed attestations, or serve as an
  attestation authority.

## Known Non-Claims

- NAOS does not prevent hallucinations.
- NAOS does not certify legal, regulatory, compliance, runtime, security, or
  test-completeness outcomes.
- NAOS reports, evidence packs, dashboards, grader assessments, and SARIF files
  are review inputs, not approval.
- NAOS does not provide tamper-proof evidence storage or cryptographic signing
  by default.
- NAOS does not enable Engram, MCP, cloud memory, sqlite-vec, embeddings, graph
  runtimes, model calls, provider installation, arbitrary plugin execution,
  automatic context injection, or memory write-back by default.
- NAOS does not provide full DSSE signing, signature verification, key custody,
  real cross-harness execution, attestation authority, release authorization, or
  automatic approval.

## Deferred Work

- Public publication, tag, and GitHub release.
- Optional wheel/sdist publication decision.
- Live MCP/Engram introspection.
- Durable memory write-back.
- Runtime recall trace and audit-event capture.
- Runtime trace capture.
- Semantic/vector runtime.
- Graph runtime/traversal algorithms.
- LLMGrader runtime.
- Private reference-project pilot validation.

## Publication Package Decision

This candidate keeps the sanitized archive as the primary public package:
`dist/naos-public-export.tar.gz`. Wheel and sdist artifacts are optional/manual
inspection artifacts unless a later publication decision explicitly includes
them. SHA-256 checksums are integrity metadata only; they are not signatures,
not attestations, not approval, and not release authorization.
