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

External URLs remain unverified reference context even when the evidence object
declares `verified: true`; a flag alone cannot satisfy a claim's evidence
requirement. Supporting local evidence remains necessary. The evidence pack
distinguishes file collection from producer outcomes and unresolved review
evidence. Missing validator reports are recorded as missing or not configured,
not silently ignored.

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

### Aggregate collection format v2

New evidence packs and dashboard JSON use version 2 local source references,
with exact collected SHA256 and byte length. Include the selected original
reports with the aggregate handoff. A reference is historical collection
metadata, not evidence verification, approval, or proof of secret coverage.
`read_collection_entry` preserves legacy embedded payloads and resolves new
references only inside the supplied review root with exact collected bytes.
Missing, changed, unsafe, malformed, or oversized originals leave details
unavailable and requirements unresolved. No automatic retention or relocation
map is provided; byte-identical originals at the same relative paths can be
reviewed under a different supplied root.

Classification inventories use exact count, canonical collection digest, and
source bucket references; records remain in the original scanned report. The
finite maturity collection witness preserves the existing stable-state and L2
comparison, without authenticating its metadata or claiming promotion. Unknown
aggregate or witness versions are refused. Publication above 8 MiB fails before
replacing either aggregate output; original reports and detector/capture bounds
are unchanged. Explicit non-policy output aliases receive no claim allowance
without a separately established dispatch binding.

Secret-hygiene input inventories retain legacy `path`/`status` rows and accept
current successful-read rows with exact SHA256 and byte length. These fields
do not establish public-literal membership. Managed metadata paths receive an
entropy-only allowance at their exact inventory coordinates only after the
existing linked producer records and archived base bytes have been checked.
Malformed metadata, unknown fields, altered base bytes, findings and unrelated
strings retain the ordinary checks; assignment and provider detection remain active.

Exact directory inventory rows require observed proper parents of independently
proved files, including the final scan checkpoint; existence or a path prefix
is insufficient. This allowance does not extend to configured scan roots,
ordinary bodies or findings. See ADR-0011 for the bounded proof contract.

One committed Windows v2 new enrollment also permits exact raw-record path
coordinates after reconstructing its create-only rows, linked archives and
complete publication and staging-slot sequence. Updates, multiple receipts,
older operation versions and custom source-policy paths receive no added path
allowance. This proves constructor consistency, not native identity or authority.
For this single NEW enrollment, an identity matching `WIN-` plus 16 lowercase
hex digits qualifies only at the five linked project-ID values in root, owner,
manifest, receipt and nested plan, with both predecessor digests absent. The
linked directory journal's operation ID qualifies only after its envelope,
intent digest and saved-plan directory witnesses agree under the same NEW
condition. These six coordinate slots use the existing representation limit;
a refused optional directory addition preserves already proved coordinates.
Neither classification authenticates random generation. Other body values and
credential patterns retain their ordinary checks; rollback cleanup labels are
outside this single committed NEW contract.
For that same committed enrollment, inventory coordinates also recognize its
complete forward-marker sequence, linked directory witness and finite runtime
directory, template, lock and staging roles. Directory witnesses are checked
against the saved plan by pure JSON validation; the scanner imports no native
operation backend. Missing or inconsistent records, unsupported variants and
operand-cap overflow refuse this additional membership while preserving the
existing proved operands. These paths receive no allowance in ordinary bodies.
Declared public path members include their native relative spelling; this does
not make an arbitrary session ID or authored filename public. Session paths can
remain review findings even when they agree with their producer: excluding them
could remove the only entropy signal for a short or padded credential-like ID.
Selected, schema-validated ordinal task paths likewise include their native
relative spelling; unknown ordinals and authored task names remain excluded.

Repository-intelligence control labels qualify at exact JSON coordinates only
after the linked owner, scope, active generation, validation, transaction and
raw source records agree. For the current POSIX generation, this includes its
generation ID at six linked fields and its transaction ID at three linked fields.
A committed create-only managed-content plan can recognize either ID at two
saved consumer coordinates, when the typed current lifecycle and all 13 binding
fields match the proved current generation. Missing, mismatched or unsupported
input shapes add no allowance and preserve existing managed-content operands.
Authored copies, unproved predecessor labels and credential-pattern checks
retain ordinary detection.

Windows classification supports one committed genesis
activation with its enrollment, bootstrap, preparation, publication and complete
checkpoint chain; refresh, rollback and unknown histories retain ordinary
detection. After that complete Windows proof, exact bootstrap directory/file
map keys and preparation/saved-plan directory map keys receive the same
entropy-only allowance as proved values. Key positions remain distinct from
value positions; arbitrary keys, changed preimages and credential patterns
retain ordinary detection. The same complete proof derives exact runtime paths
at the four scanner inventory metadata arrays, including directory and file
templates, preparation and receipt records, committed markers, every forward
checkpoint, and the operation lock. Closed directory memberships are observed
and rechecked; file templates and the operation lock must have guarded empty
preimages. No path-prefix, ordinary report-body or credential-pattern allowance
is granted. Artifact/reference node labels are rederived from hash-bound source
bytes. These saved-record checks establish local consistency, not current native
ownership, authentication or review authorization. Arbitrary audit, session and
authored references remain review inputs. Credential-pattern checks stay active.

Finite public diagnostic labels, report paths and requirement references are
derived from shipped source declarations. Classifier ordinal aliases require
a complete selected diagnostic vector, pinned report schema and matching
project root and report path. This proves label derivation only: it does not
authenticate the producer, verify source findings or record human approval.
The caller does not independently bind the current profile or NAOS root; the
document profile is schema-constrained and its NAOS root must match the path.
Existing reference size and complexity limits remain in force. Unknown body
values, credential assignments and provider keys retain ordinary detection.

Selected canonical producer witnesses provide a bounded source of references
when unrelated report copies exhaust the generic context collectors. Only
selected self-check and classification reports under the supplied NAOS root,
and single-event JSONL audit files under its declared fallback audit root,
enter this projection. Complete existing vector and event constructors prove
the exact labels; audit files must occupy their recomputed filenames. Source
reads share the existing 32MiB proof budget and final scanner checkpoint. The
projection keeps finite count, value and byte limits; generic collectors retain
their existing exhaustion refusal. This proves structural consistency, not
producer authenticity. Ordinary bodies, unknown references, assignments and
provider keys retain detection.

Raw control-record entropy allowances within a secret scan are provisional until
all cached proof inputs pass a final observation before report publication.
An observed cached-input refusal remains fatal to that scan after restoration;
terminal refusal leaves any existing output untouched. Checks observe selected
endpoints, so transient changes restored between checkpoints are not guaranteed
to be detected. These local consistency checks establish no continuous custody.

PR-risk Git comparison operands receive an entropy-only allowance at the two
selected `diff_metadata.diff_args[0]` and `diff_line_metadata.diff_args[0]`
quote coordinates. Admission requires the pinned report schema, matching
project and NAOS roots, safe declared refs, a supported comparison mode and
two agreeing full-commit metadata tuples. The carrier must be the policy-selected
PR-risk report or an exact selected evidence reference in the single
policy-selected family-review record. A referenced carrier requires that
record's pinned complete schema, matching project, NAOS root and report profile,
the `pr_risk_classification` source-family role, and the current local byte hash.
The scanned text must match those bytes after newline normalization. A valid
unresolved review can identify a carrier; this does not close the review or
establish approval. Other files under the same directory receive no allowance.
Full hexadecimal declared refs
must match those tuples. The admission path never executes Git: it proves
constructor consistency, not commit existence, ref resolution, producer
authenticity or evidence truth. Invalid public vocabulary disables this
allowance. Unrelated strings, assignments and provider keys stay subject to
ordinary detection; reference size, depth and selected-file limits persist.

Native-only test fixtures are separate from mandatory synthetic refusal
checks. A Windows symlink privilege failure or an unobservable POSIX mode
change may prevent that specific fixture from running, while mandatory
metadata, reparse, unsafe-path and unreadable-source checks still execute.
Timestamp-change checks remain applicable where the change is observable.
A skipped native fixture does not qualify that native operation.
