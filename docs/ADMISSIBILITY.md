# Admissibility

**Status**: Public evidence-pack definition, not a compliance opinion
**Audience**: NAOS adopters, reviewers, auditors, procurement teams, regulated principals
**Scope**: What NAOS evidence may be suitable to submit into a downstream review process

---

## Executive Summary

In NAOS, **admissibility** means the practical readiness of governance evidence to be handed to a reviewer, auditor, regulated principal, customer, or internal risk owner.

Admissibility is not certification. It does not mean the system is legally compliant, safe in production, approved by a regulator, or operationally resilient. It means the NAOS-governed project can package reviewable evidence about how the SDLC was governed: what was specified, what was built, what was checked, and which boundaries remain outside NAOS.

Use this document with [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md), [OSFI_E23_MAPPING.md](OSFI_E23_MAPPING.md), and [DORA_MAPPING.md](DORA_MAPPING.md).

---

## 1. What Admissibility Evidence Includes

An admissibility evidence set usually includes:

| Evidence Type | Typical Artefact | What It Supports |
| --- | --- | --- |
| Scope and intent | `specs/01-problem.md`, `specs/02-solution.md`, `project-context.md` | What the project claims to do and not do |
| Requirements | `specs/03-requirements.md`, acceptance criteria | What the implementation should satisfy |
| Architecture and boundaries | `specs/04-architecture.md`, `naos_architecture_boundaries.yaml` | How responsibilities and modules are separated |
| Delivery governance | `TASK_REGISTRY.yaml`, active cards, `DASHBOARD.md` | What work was planned, owned, and completed |
| Traceability | `TRACEABILITY_MATRIX.md`, `FUNCTION_INDEX.yaml`, `Implements: FR-XXX` headers, `naos/reports/spec_cascade_coherence.json` | How requirements connect to tasks, code, and tests |
| Conformance | Latest conformance report, validators, pre-commit outcomes | Which static governance checks passed |
| AI governance posture | `.ai/RULES.md`, profile selection, prompts, agents, skills, instructions, `naos/reports/ai_surface_context_budget.json` | Which AI-SDLC controls applied and whether AI/governance instruction surfaces stayed within reviewed context-health boundaries |
| AI-assisted code provenance review | `naos/ai_code_provenance.yaml`, `naos/reports/ai_artifact_inventory.json`, `naos/reports/ai_artifact_reconciliation.json`, `naos/reports/ai_code_provenance.json` | Which adopter-declared AI-use, human contribution, prompt/use-reference, reviewer, license-lineage, and unresolved-question signals are available for review |
| Compliance posture review | `naos/compliance_posture.yaml`, `naos/reports/compliance_posture.json` | Which adopter-declared regulated-context, evidence-reference, missing-evidence, and unresolved-question signals are available for review |
| Control-plane summary | `naos/evidence/evidence_pack.json`, `naos/reports/dashboard_summary.json`, `naos/reports/evidence_attestation.json` | Which capability, gate, claim, test-evidence, AC-completion evidence, digest, reviewer-metadata, exception, and residual-risk signals were present or missing |
| Compliance positioning | [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md), [OSFI_E23_MAPPING.md](OSFI_E23_MAPPING.md), [DORA_MAPPING.md](DORA_MAPPING.md) | How NAOS evidence maps to review frameworks |
| Known limits | Gap sections, no-op decisions, threat model, audit notes | What NAOS does not prove |

---

## 2. What Admissibility Evidence Does Not Prove

Admissibility evidence does **not** prove:

- Legal or regulatory compliance.
- Production safety or operational resilience.
- Model approval, model validation, or risk acceptance.
- Runtime monitoring, incident response, or post-deployment surveillance.
- Third-party-risk-register completeness.
- TLPT/TIBER-EU execution or regulator-facing test coordination.
- That a human reviewer performed substantive review rather than rubber-stamping.
- That generated metrics are correct if the underlying source artefacts were manipulated.
- Authorship, ownership, infringement clearance, copyright compliance, or license clearance for AI-assisted code.

The adopter remains responsible for legal, regulatory, operational, security, risk, and audit decisions.

---

## 3. How The Regulatory Maps Fit

The regulatory maps are admissibility aids:

- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) explains the general NAOS support posture for EU AI Act, NIST AI RMF, ISO 42001, and AIUC-1.
- [OSFI_E23_MAPPING.md](OSFI_E23_MAPPING.md) explains the vendor-cascade boundary for Canadian model-risk contexts.
- [DORA_MAPPING.md](DORA_MAPPING.md) explains where NAOS SDLC evidence may support DORA control discussions and where DORA operational controls remain outside NAOS.

These maps help a reviewer decide whether NAOS evidence is relevant. They do not decide whether the evidence is sufficient.

---

## 4. Admissibility Pack Target

Generated lite, standard, and assured projects include an evidence-bundle target for admissibility packaging:

```bash
make -f Makefile.naos admissibility-pack
```

The target bundles common evidence artefacts into a dated zip for vendor-cascade or audit handoff:

```text
naos/admissibility-YYYY-MM-DD.zip
```

Expected contents include:

- `naos/DASHBOARD.md`
- `naos/TRACEABILITY_MATRIX.md`
- `naos/reports/conformance_latest.json`, when available
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md)
- [OSFI_E23_MAPPING.md](OSFI_E23_MAPPING.md)
- [DORA_MAPPING.md](DORA_MAPPING.md)
- [ADMISSIBILITY.md](ADMISSIBILITY.md)

`naos/DASHBOARD.md`, `naos/TRACEABILITY_MATRIX.md`, and the public compliance/admissibility docs are required. If the latest conformance report is missing, the target still succeeds and adds `naos/reports/README-MISSING-CONFORMANCE.txt` to the zip so reviewers can see what was absent and how to regenerate it.

The pack improves handoff ergonomics; it does not change the evidentiary limits described above.

---

## 5. Control-Plane Evidence Pack

The current control-plane implementation adds a machine-readable evidence pack:

```bash
python scripts/naos_evidence_export.py --profile standard
```

Generated adopter output:

```text
naos/evidence/evidence_pack.json
```

The JSON pack is separate from the older zip handoff target. It consolidates:

- local digest and reviewer-metadata signals from `naos/reports/evidence_attestation.json` when generated;

Evidence attestation is bounded local evidence. It records SHA-256 digests and reviewer metadata; it is not cryptographic signing, signature verification, tamper-proof storage, legal/regulatory approval, compliance approval, or guaranteed integrity. Evidence attestation is local and repository-based: someone with repository write access can still edit evidence, reports, reviewer metadata, or manifests unless external controls such as protected branches, signed commits, external notarization, or independent archival are used.

> **Clarification — what is required vs what is over-scoped (not legal advice).**
> The "not cryptographic signing" boundary above is often over-read. What
> regimes such as the EU AI Act (Annex IV / Art. 11), 21 CFR Part 11, and eIDAS
> generally require is a **tamper-evident, time-stamped, uniquely-attributable
> record** plus a **named responsible-person signature at defined human gates** —
> i.e., **identity binding**, not a cryptographic certificate per developer or
> contributor. A per-individual *qualified* certificate applies only to the
> specific accountable signatory where a qualified/advanced electronic signature
> is mandated (eIDAS QES; Part 11 *open* systems). Developer/CI provenance
> (EO 14028/SSDF, SLSA, Sigstore) is signed at build/organisation identity,
> increasingly keyless-OIDC — not per contributor. NAOS supplies the
> attributable record, the digest, the signable artifact, and the named human
> gate; key custody and signing stay adopter-owned (ADR-0007). See
> `KNOWN_LIMITATIONS.md` → "What regulation actually requires here".

- validator reports under `naos/reports/`;
- claims validation status;
- self-check status;
- roadmap/crosswalk health;
- function-index health;
- gatekeeper status/evaluation snapshots when present;
- source-to-test map, test-evidence health, and declared AC/SCEN completion evidence where completion is claimed, including optional exact Git base/subject/tree binding, bounded subject-tree path-operand receipts, and preserved predecessor supersession posture;
- spec-pack contract findings for template structure conformance;
- spec-cascade coherence findings for requirement/task/source linkage;
- deterministic hygiene reports for duplicate-function, secret-like,
  test-quality, dependency-integrity, package-reality, and API-symbol reality
  review findings;
- AI code provenance review posture when `naos/reports/ai_code_provenance.json`
  is generated from `naos/ai_code_provenance.yaml` and AI artifact reports;
- compliance posture review metadata when
  `naos/reports/compliance_posture.json` is generated from
  `naos/compliance_posture.yaml`;
- exceptions/waivers;
- known gaps;
- residual risks;
- policy source, profile, NAOS root, and evidence freshness metadata.

External URLs remain unverified references unless explicitly marked verified in the evidence object. Missing validator reports are recorded as missing or not configured, not silently ignored.

AC-completion Git binding establishes only that declared local Git objects and
bounded path-shaped operands resolved. It does not establish that a command ran
against that tree, that execution was clean or independent, or that any person
or signer identity was authenticated. Supersession leaves the predecessor
visible and changes review posture only; it is not deletion, revocation,
approval, evidence admission, or release authority.

The dashboard consumes this evidence pack when present and writes:

```text
naos/reports/dashboard_summary.json
```

This supports reviewer navigation and residual-risk discussion. It does not create a legal or regulatory conclusion.

---

## 6. Reviewer Checklist

Before handing NAOS evidence to a reviewer:

- [ ] Confirm the selected NAOS profile matches the project's assurance need.
- [ ] Run the relevant static validators and conformance checks.
- [ ] Refresh dashboard and traceability artefacts.
- [ ] Run `naos spec-pack-contract --profile <profile>` and `naos spec-cascade --profile <profile>` when specs, task registry entries, source headers, source spec references, or configured/inferred source roots changed.
- [ ] Run `naos plan-coherence --profile <profile> --diff-base <ref>` when `PRE_IMPLEMENTATION_ALIGNMENT.md` declares planned or out-of-scope paths and changed-file scope evidence is useful for review.
- [ ] Run `naos ai-code-provenance --profile <profile>` when handing off AI-assisted code provenance evidence.
- [ ] Run `naos compliance-posture --profile <profile>` when handing off adopter-declared regulated-context evidence.
- [ ] Run `make -f Makefile.naos admissibility-pack` and test the zip integrity before handoff.
- [ ] Confirm requirements, code, and tests are linked.
- [ ] Attach the relevant compliance maps.
- [ ] Record known gaps and out-of-scope controls.
- [ ] Keep project-specific risk assessments, runtime controls, incident plans, vendor registers, and approvals outside the NAOS pack but linked from the adopter's own governance process.

Admissibility is strongest when the pack is complete, current, reproducible, and accompanied by an honest statement of what the evidence does not cover.
