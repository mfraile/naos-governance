# Changelog

All notable public changes to NAOS are summarized here.

## [1.1.0] - 2026-09-16

- Preserve exact task ownership across lifecycle operations and revalidate
  persisted decision records in composed traceability.
- Validate indexed test and specification bytes together and run the full
  AC-reference check in generated Standard and Assured CI.
- Reject malformed gate inputs and unknown selectors with structured errors.
- Validate attestation inputs, separate integrity from coverage and signatures,
  and exclude configured signing outputs from their own evidence subjects.
- Reconcile model reports with current sources and validate canonical trace
  structure through the CLI and grading consumers.
- Correct the static MCP descriptor policy's nested and outer integrity pins
  after portable authority wording changed; activation remains separately gated.
- Record the maintainer-approved measured profile footprint allowances while
  preserving the existing warning and stop comparison behavior.
- Resolve the reviewed Ruff diagnostics and preserve explicit file, parser and
  subprocess error boundaries, with portable source/export/installed regressions.
- Add portable connected regressions and
  [compatibility guidance](docs/CONTRACT_REVALIDATION.md). These changes do not
  change profile enforcement transitions or grant human decision authority.

## [1.1.0] Publication Candidate - 2026-09-04

### Added

- A content-addressed public-candidate receipt and reproducible `tar.gz`
  archive produced through deterministic, fail-closed sanitization controls.
  The preparation controls are not distributed with the candidate.
- Public, offline regulatory claim/source-matrix validation that is usable from
  a history-free checkout containing only the distributed files.
- Governed architecture, AI-component inventory, sponsor registry, AICM
  mapping, MCP supply-chain review, AIVSS arithmetic review, continuous
  red-team evidence, and public scope/decision-boundary surfaces developed
  after the 1.0.0 candidate.

### Changed

- Generated-adopter seeds and the fresh-profile footprint baseline now use
  portable content provenance rather than private repository paths, project
  names, commits, or tree identifiers.
- Public release identity is aligned to the existing package version 1.1.0.
  The existing 1.0.0 tag and historical candidate records are preserved.
- Public repository URLs now identify `mfraile/naos-governance`, and the
  history-free candidate carries a minimal read-only hosted workflow plus a
  public-safe receipt, release-identity, documentation, regulatory, Quickstart,
  Standard, and Mermaid-source test slice.
- Greenfield Quickstart examples now bind preview and activation to the same
  explicit absent project path; the Lite tutorial now matches the Python 3.11
  package floor.

### Release boundary

- The candidate is prepared for history-free repository import and hosted
  verification. Repository staging or a green CI run is not a release or
  publication event.
- Candidate creation does not itself authorize public visibility, a tag,
  GitHub release, package upload, or change to the preserved 1.0.0 tag.
- SQLite/FTS remains the Standard-profile repository-intelligence baseline.
  NetworkX/GraphML remains conditional. This candidate adds no Standard-default
  semantic runtime, embedding provider, or automatic graph activation; the
  existing project-configured function-index similarity hook remains disabled
  by default and non-core.

## Post-1.0.0-Candidate Development Delta - 2026-07-02

### Added

- `naos package-reality` and `make -f Makefile.naos
  naos-package-reality` for deterministic package-name, lock-style-pin,
  optional docs install-snippet, and explicit opt-in registry-existence review
  evidence. Registry checks remain off by default and require
  `--registry-mode online --allow-network`.
- `naos api-symbol-reality` and `make -f Makefile.naos
  naos-api-symbol-reality` for deterministic review of explicitly declared
  Python API symbols by source inspection without importing target modules.

### Changed

- Evidence signing/verification claims now match implementation: NAOS recomputes local
  digests, reports signature-entry presence, and records best-effort Git HEAD metadata. It
  does not require signing, validate envelope signatures, independently establish trust in
  Git's commit-signature status, or authenticate signer, author, OIDC, or SSO identity.
- `requirements.txt` now pins `PyYAML==6.0.1` and `jsonschema==4.19.2` as the
  kit's reproducible local validation dependencies. `pyproject.toml` keeps
  broader package metadata compatibility ranges.

### Non-Claims

- Package-reality output is review evidence only. It does not prove package
  safety, malware absence, vulnerability absence, supply-chain assurance,
  registry trust, approval, certification, compliance, or runtime safety.
- API-symbol reality output is review evidence only. It does not prove API
  semantics, runtime behavior, option compatibility, endpoint behavior, package
  safety, approval, certification, compliance, or hallucination prevention.

## 1.0.0 Public Release Candidate - 2026-05-21

### Added

- Capability maturity, systemic impact, module-header traceability,
  control-plane review, setup recommendations, evidence attestation,
  onboarding/CI readiness, deterministic conformance, and guided setup-module
  surfaces.
- Memory/context readiness, task context packs, local context index/query,
  semantic candidate readiness, graph context readiness/query, memory
  provider/access verification, memory-use policy, and session lifecycle
  reports.
- ADR-0010 advisory control boundaries: deterministic controls remain primary,
  advisory controls may challenge but not replace them, and humans decide
  durable outcomes.
- Capability contract validator wired into CI for capability-card consistency
  and deterministic/advisory boundary checks.
- SARIF findings exporter for local SARIF 2.1.0 interoperability without upload,
  approval, attestation, or compliance-proof semantics.
- Static YAML policy override hooks with protected invariant checks and no
  plugin/code execution.
- Agent trace event schema and validation readiness for declared trace records.
- BaseGrader protocol, deterministic StaticGrader, and grader
  audit/drift/assess report modes.
- LLMGrader readiness controls with runtime disabled, no provider/API/model
  dependency, zero default cost, and advisory-only future posture.
- `naos/NAOS_QUICK_REFERENCE.md` as the generated-adopter quick reference.
- Public-safe sanitized export candidate, refreshed public-candidate
  verification, and publication-package refresh artifacts.
- Optional integration templates for Spec-Kit and Claude Code, plus
  tool-neutral integration guidance. These remain optional convenience layers,
  not mandatory dependencies or official third-party support.
- Governed agentic coding workflow and Pre-Implementation Alignment artifacts,
  schemas, deterministic review scripts, CLI/Make targets, setup modules, and
  playbook guidance.
- Public ADR promotion, audit playbook, threat model, assured-profile
  activation guide, behavioral audit enablement guide, cross-harness readiness
  guide, and install/init documentation polish.
- Calibration shadow and evidence classification reports for deterministic
  report-stability monitoring and finding-provenance review.
- Cross-Harness Review Readiness for future review/DSSE planning metadata
  without harness execution, signing, signature verification, key custody, or
  attestation authority in the core kit.
- Full source forensic re-audit, regenerated sanitized export, clean-install
  acceptance, and public-candidate verification reports.
- Two-dimensional control lattice (profile severity × capability maturity
  L0–L5): a capability enforces at its profile severity only once declared
  `current_maturity` reaches `target_maturity`, and downgrades to advisory
  below target ("never block a scaffold"). Enforcement posture, not approval.
- Graduated profile `exit_code` ramp (quickstart advisory through assured
  blocking) shipped in a `warn` transition mode by default, with an explicit
  `enforcement_transition: enforce` opt-in.
- `validate_profile_control_coherence.py` validator (wired into CI): asserts
  profile/maturity/exit-ramp monotonicity, that the lattice is consumed (not
  just declared), gatekeeper-reference validity, and RULES.md marker coherence.
- Maturity-gated gate severity (downgrade-only): gate severity reflects the
  maturity of the capabilities mapped to it via `gatekeepers`, and a
  `current_maturity` self-declaration unsupported by evidence is flagged for
  human review (advisory at lower profiles, blocking at assured).
- Per-task PR risk routing: deterministic risk-tier derivation that escalates an
  effective profile up-only and advisory (never auto-lowers, never changes exit
  codes), recorded on handoff and task-claim metadata for review.
- `AC-AUTONOMY-BOUNDARY-01` deterministic agent-trace detector and a
  plan-coherence report (parallel-overlap, dependency-readiness, unknown-task
  checks); a conflict-visibility floor locked as a tested invariant.
- Deterministic tamper-evidence root (`manifest_root_digest`, on by default), a
  DSSE-style signable evidence envelope (`naos evidence-sign`, with an empty
  `signatures` list because NAOS never signs), and `naos evidence-verify`
  (local digest recomputation, signature-entry presence, and best-effort Git HEAD
  metadata). NAOS does not require signing, validate envelope signatures,
  independently establish commit-signature trust, authenticate identities, hold
  keys, issue certificates, or provide non-repudiation.
- Singapore (Model/Agentic AI Framework, MAS FEAT), Canada, and China regulatory
  crosswalks in `docs/COMPLIANCE_MAPPING.md` (advisory mapping, not a compliance
  opinion).

### Changed

- Public README measurement language avoids private reference-codebase benchmark
  tables unless public provenance is available.
- Security posture states that API keys, providers, cloud services, memory
  payload reads, memory write-back, SARIF upload, plugin runtime, arbitrary code
  execution, and LLMGrader runtime are not enabled by default.
- Generated-adopter guidance uses `make -f Makefile.naos ...`.
- The older generated quick-reference seed was renamed to
  `NAOS_QUICK_REFERENCE.md`.
- Release package posture is archive-first. Wheel/sdist builds are inspected
  from the sanitized export, but package distribution remains optional.
- The regulated team-use readiness foundations now include:
  session identity, operator attribution, SQLite write coordination, append-only
  audit log, evidence conflict detection, task claim/release coordination,
  team/operator overlays, multi-team gatekeeper posture, and PR-time governance
  CI evidence templates. Current candidate checks cover their shipped
  interfaces; publication, tagging, and release remain separate maintainer actions.

### Deferred

- Publication/tag/release.
- Optional wheel/sdist publication decision.
- Private reference-project pilot validation.
- Semantic/vector runtime, graph runtime, sqlite-vec, embeddings, live
  MCP/Engram calls, durable memory write-back, runtime trace capture, runtime
  recall trace capture, runtime audit-event capture, real cross-harness
  execution, keyed DSSE signing by NAOS, key custody, certificate issuance,
  non-repudiation, arbitrary plugin runtime, LLMGrader runtime, and automatic
  context injection. (NAOS emits a signable envelope and recomputes local
  tamper-evidence; any signing and signature validation remain external and
  adopter-controlled.)

### Non-Claims

- NAOS does not prevent hallucinations.
- NAOS does not certify legal, regulatory, compliance, runtime, security, or
  behavioral outcomes.
- NAOS reports, evidence packs, dashboards, grader assessments, and SARIF files
  are reviewable evidence or candidate references, not approval.
- NAOS does not provide attestation authority, key custody, keyed DSSE signing
  on behalf of adopters, certificate issuance, non-repudiation,
  model/provider/API runtime, memory write-back, automatic context injection, or
  release authorization. (It emits a signable envelope, recomputes local
  tamper-evidence, and reports best-effort Git HEAD metadata; it does not
  authenticate identities or validate signatures.)
