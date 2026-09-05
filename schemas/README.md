# NAOS Schemas

`schemas/naos/` is the canonical schema namespace for public NAOS control-plane artifacts.

## Capability contracts

`schemas/naos/capability.schema.json` validates capability cards under `capabilities/*.yaml` through `scripts/validators/validate_capability_contracts.py`.

## Secure-coding control data

The active secure-coding and agentic-coding requirements register is `configs/secure_coding_control_register.yaml`. The retained `configs/secure_coding_control_register.sample.yaml` is an illustrative compatibility seed, not the active authority.

Both use `schemas/naos/secure_coding_control_register.schema.json`. Register structure, references, mapping states, detector boundaries, and authority separation are checked by `scripts/validators/validate_secure_coding_control_register.py`.

Consumer bindings are declared in `configs/secure_coding_control_render_manifest.yaml`, rendered or checked by `scripts/naos_render_secure_coding_controls.py`, and validated bidirectionally by `scripts/validators/validate_secure_coding_control_references.py`.

Passing these checks establishes structural, referential, and generated-output coherence only. It does not verify standards mappings, activate enforcement, prove code security, or approve a project.

## Other report schemas

`schemas/naos/` also contains dedicated report contracts for claims validation, capability-maturity readiness, evidence packs, dashboard summaries, gate status/evaluation, spec-pack contract, spec-pack materialization, spec assembly worksheet, spec-cascade, AI-surface context-budget, governed-learning, adapter-coherence, plan-coherence, evidence-envelope, and evidence-verification outputs. `capability_maturity.schema.json` is the capability-level configuration/model contract; the distinct `capability_maturity_report.schema.json` covers the emitted `naos.capability_maturity.v1` report.

These report schemas establish deterministic structural contracts for supported machine-readable output. They do not prove report completeness, evidence truth, operating effectiveness, approval, certification, compliance, or release readiness. Spec-pack schemas describe template contract conformance, profile applicability, deterministic reference resolution, missing-file materialization evidence, and review-only evidence-to-spec assembly only, not specification quality, requirements completeness, candidate promotion, approval, implementation, complete traceability, certification, or compliance proof. Plan-coherence schemas describe review evidence only, not work authorization or plan approval. Evidence-envelope and evidence-verification schemas describe signable-envelope and local tamper-evidence reports only, not NAOS signing, third-party signature validation, non-repudiation, certification, or compliance proof. Legacy or draft schemas outside this namespace are not authoritative unless a current public document explicitly says otherwise.

The `repository_intelligence_*` schemas define source-bound rules, immutable
plans, generation manifests, validation and activation receipts, enrollment,
status, apply and recovery results, transaction journals, the active-generation
pointer, validated consumer context, inventories, and bounded query candidates.
These artifacts are generated navigation evidence. They do not replace
repository source, approve requirements, declare maturity, prove complete
relationships, or authorize sqlite-vec/embedding use.

Systemic-impact uses three distinct contracts:

- `systemic_impact_rules.schema.json` for artifact families, typed review
  surfaces, and separate kit-source/adopter-generated routes;
- `systemic_impact_review.schema.json` for current-state and optional explicit
  changed-path report output;
- `systemic_impact_changed_path_review.schema.json` for human-authored
  obligation dispositions supplied to `--review-record`.

Those schemas establish structure and bounded referential integrity. They do
not prove semantic completeness, execute Git, edit affected files, or approve
closure.

## Managed upgrade contract

`schemas/naos/upgrade_contract.schema.json` validates managed provenance,
content-aware plans, journals, receipts, and recovery results. Content-aware
plan v2 records the selected operation scope and fixed in-process checks while
the transaction reader retains recovery compatibility with both original
no-checks v1 plans and later checks-bearing v1 plans. The plan digest binds RFC
8785 canonical JSON with SHA-256; it does not authenticate a reviewer.

Planning is target-read-only. Mutation requires a separate exact-digest apply,
valid provenance, regenerated fixed sources, and revalidated current state.
The contract does not authorize blanket force, project hooks, arbitrary
validators, cryptographic reviewer authentication, hostile-validator
isolation, network denial, or unsupported platform and metadata tuples.
