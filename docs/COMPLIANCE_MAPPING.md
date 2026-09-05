# NAOS Compliance Mapping

**Version**: 1.2.0  
**Status**: Advisory mapping and review aid; not a compliance opinion  
**Correction date**: 2026-06-25

## Executive boundary

NAOS governs the AI-assisted software-development process. It can produce
repository-local specifications, traceability, deterministic findings, gate
status, evidence packages, and human-review records that may support a control
discussion. It does not by itself govern the deployed system, determine legal
classification, certify conformance, prove runtime safety, or transfer the
adopter's accountability.

The adopter remains responsible for scope, risk classification, project-specific
control selection, runtime and organizational controls, evidence accuracy,
professional interpretation, risk acceptance, and approval.

## Framework coverage summary

| Framework | NAOS contribution | Boundary retained by adopter |
| --- | --- | --- |
| EU AI Act Articles 9–17 | Supporting SDLC documentation, traceability, static checks, and human-review evidence | Legal classification, deployed-system obligations, logging adequacy, post-market monitoring, and conformity assessment |
| NIST AI RMF 1.0 | Supporting GOVERN, MAP, and selected MEASURE evidence | Organizational risk decisions, runtime measurement, treatment, and ongoing MANAGE activities |
| ISO/IEC 42001 | Supporting Plan, Do, and selected Check records | AI management-system ownership, internal audit, management review, corrective action, and certification |
| AIUC-1 | Supporting use-case, change, traceability, and review records | Deployment, operational access, incident, and use-case accountability |
| OSFI E-23 | Supporting lifecycle and vendor-cascade SDLC evidence | Model-risk classification, independent validation, monitoring, and regulated-principal accountability |
| DORA | Supporting development/change and ICT evidence discussions | Incident reporting, operational resilience, TLPT/TIBER-EU, third-party registers, and regulatory accountability |
| Singapore Model AI Governance Framework (incl. GenAI 2024, Agentic AI 2026) | Supporting accountability-chain, human-oversight, traceability, and agent-trace SDLC evidence | Voluntary-framework adoption decisions, deployment governance, operational override, and organizational accountability |
| Singapore MAS FEAT + TRM (financial sector) | Supporting development/change SDLC and review evidence | FI accountability, model validation, TRM cryptography/key custody, and regulated-principal obligations |
| Canada — Ontario Bill 194 / Quebec Law 25 (provincial; federal AIDA lapsed Jan 2025) | Supporting recordkeeping, transparency, and human-in-the-loop SDLC evidence | Public-sector/privacy obligations, personal-data protection (incl. encryption duties), and accountability |
| China — Generative AI Measures + AI-Generated-Content Labeling | Supporting SDLC traceability and review evidence | Algorithm registration, security self-assessment, and **output watermarking / encrypted-content-metadata labeling (out of NAOS scope — a runtime/output concern)** |

Detailed regulated-domain boundaries remain in
[OSFI_E23_MAPPING.md](OSFI_E23_MAPPING.md),
[DORA_MAPPING.md](DORA_MAPPING.md), and
[ADMISSIBILITY.md](ADMISSIBILITY.md).

## Additional jurisdiction mappings (advisory, as of 2026-06)

These mappings are newer and **draft**. They reflect public information as of
June 2026 and must be re-verified against primary sources before any reliance.
As with every row above, a populated cell means *relevance*, not satisfaction,
conformance, or a compliance opinion.

### Signature and encryption posture across regimes

A recurring adopter question is whether a cryptographic key-signature or
encryption is *mandatory* for AI-assisted / agentic coding governance. As of
June 2026 the obligation is **outcome-based, not mechanism-based** in the
AI-specific frameworks: they require attributable, tamper-evident, traceable
records with named human sign-off and human oversight — not cryptographic
signing or encryption of governance evidence. Cryptographic signing or
encryption becomes mandatory only through *adjacent* regimes, and then narrowly:

- **eIDAS Qualified Electronic Signature / 21 CFR Part 11 open systems** — a
  qualified or unique cryptographic signature for the *specific accountable
  signatory* (not every contributor).
- **Sector-financial security rules** (e.g., Singapore MAS TRM) — cryptography
  and key custody for financial-institution systems and records.
- **Data-protection law** (GDPR, Singapore PDPA, Quebec Law 25) — encryption to
  protect *personal data*, unrelated to governance signatures.
- **China AI-Generated-Content Labeling** — visible plus invisible
  (encrypted-metadata) labels on AI *output*; this is output watermarking, not
  SDLC-evidence signing, and is outside NAOS scope.

NAOS handles this regime-neutrally, consistent with ADR-0007 ("no keys in the
kit"): it provides keyless tamper-evidence (digests, append-only records),
reports best-effort local Git HEAD signature, signer, and author metadata, and
emits signable evidence envelopes that an adopter may sign with an external
mechanism if its regime requires one. NAOS does not validate envelope signatures;
independently establish trust in Git's commit-signature status; authenticate
identities, OIDC, or SSO; require signing; hold keys;
sign on behalf of adopters; act as a certificate authority; encrypt adopter
data; or watermark generated output. See
[KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) "Hashing and Signing Limits".

### Singapore Model AI Governance Framework for Agentic AI (Jan 2026)

This framework is the closest external alignment to NAOS's agent-governance
surfaces. The mapping below is advisory and draft.

| Framework theme | Supporting NAOS evidence (where configured) | Boundary retained by adopter |
| --- | --- | --- |
| Accountability chains | Operator attribution, session identity, module-header traceability, human-review gates | Organizational accountability and named-owner decisions |
| Delegation / autonomy boundaries | Profile policy, autonomy/authority-layer fields in `agent_trace_event`, default generated manifests that omit agent invocation, human-mediated handoff guidance, and optional `CAP-GOVERNED-DEBUG-ESCALATION` with an exact child that has no direct edit/create or agent-invocation tools, one-dispatch/no-recursion limits, host acknowledgement, and named approval (manifest/configuration posture only, not invocation proof, filesystem isolation, or host/runtime enforcement) | Real-world delegation authority, host behavior, secure inter-agent transport, and approval |
| Human override | Human-review-required routing; gate evaluation; `git --no-verify` and tier policy are adopter-CI-enforced | Operational override capability in the deployed system |
| Failure modes / traceability | Agent trace validation, audit-log event history, traceability gap register | Incident handling, runtime monitoring, and post-deployment response |
| Transparency | Evidence pack, dashboard, claims/limitations records | Disclosure adequacy and external communication |

Singapore's Model Framework, GenAI Framework, AI Verify, and the Agentic AI
Framework are **voluntary**. MAS FEAT/TRM is binding for financial institutions;
its cryptography and key-custody duties remain adopter-owned (NAOS holds no keys).

## Evidence posture by NAOS profile

| Profile | Intended evidence posture | Non-claim |
| --- | --- | --- |
| `quickstart` | Minimal orientation and advisory checks | Not production assurance |
| `lite` | Early or lower-assurance SDLC evidence | Not a regulatory risk tier |
| `standard` | Production-oriented deterministic governance and traceability | Not certification or approval |
| `assured` | Strongest kit-provided SDLC evidence and human-review gates | Not high-risk-system compliance or runtime assurance |

Profile behavior is governed by central policy, capability contracts,
gatekeepers, and human decisions. The control register does not duplicate that
authority.

## Secure-coding and agentic-coding control view

The active canonical requirements register is
[`configs/secure_coding_control_register.yaml`](../configs/secure_coding_control_register.yaml).
The retained
[`configs/secure_coding_control_register.sample.yaml`](../configs/secure_coding_control_register.sample.yaml)
is an illustrative compatibility seed, not the active authority.

Canonical control statements, applicability, bounded evaluation declarations,
mapping metadata, and non-claims are authored once in the active register.
Selected consumer surfaces receive deterministic bounded summaries through
[`configs/secure_coding_control_render_manifest.yaml`](../configs/secure_coding_control_render_manifest.yaml).
Generated sections do not own severity, blocking, waivers, approvals, or
compliance conclusions.

The design and authority boundaries are defined in
[ADR-0012](decisions/ADR-0012-secure-and-agentic-coding-control-register.md)
and [SECURE_CODING_CONTROL_MODEL.md](SECURE_CODING_CONTROL_MODEL.md).

| Plane | Canonical control ids | Deterministic coverage posture | Mapping state |
| --- | --- | --- | --- |
| Secure coding | `SC-SECRETS-01`, `SC-AUTHZ-01`, `SC-INJECTION-01`, `SC-SSRF-01`, `SC-CSRF-01`, `SC-ERRORS-01`, `SC-SECURITY-LOGGING-01`, `SC-CRYPTO-JWT-01`, `SC-PII-01`, `SC-DESERIAL-01`, `SC-DEPENDENCY-01` | Mixture of `direct`, `partial`, and `none`; detector boundaries apply | Draft |
| Agentic coding | `AC-PROMPT-INJECT-01`, `AC-TOOL-AUTHORITY-01`, `AC-DEP-HALLUCINATION-01`, `AC-CONTEXT-LEAK-01`, `AC-CLAIM-INTEGRITY-01`, `AC-AUTONOMY-BOUNDARY-01` | Mixture of `indirect` and `none`; hygiene evidence does not directly prove agent safety or truthfulness | Draft |

### Standards baseline

The active baseline records:

- OWASP ASVS 5.0.0;
- NIST SP 800-218 SSDF 1.1;
- OWASP Top 10:2025;
- OWASP Top 10 for LLM Applications 2025;
- OWASP Top 10 for Agentic Applications 2026;
- NIST AI RMF 1.0;
- CSA AICM public v1.1 / machine dataset v1.1.1, limited to the six
  build-time relevance IDs recorded in the canonical register;
- ISO/IEC 27002:2022;
- PCI DSS 4.0.1;
- CWE with an explicit as-of date.

All individual mappings remain `draft`. A mapping can become `verified` only
after checking the identifier against the named edition and recording
`verified_on`. A populated cell means relevance, not satisfaction or conformance.
ASVS references are version-qualified; wildcard references cannot be treated as
verified requirements.

The AICM selection is `AIS-04`, `AIS-11`, `AIS-12`, `GRC-04`, `GRC-06`, and
`GRC-15`. It supports adopter scoping only. It is not AICM applicability,
implementation, satisfaction, certification, compliance, runtime-security, or
operating-effectiveness evidence.

### Detector interpretation

| Detector | Bounded interpretation |
| --- | --- |
| `CAP-SECRET-HYGIENE` | Repository-local static secret-pattern hygiene; no prompt, provider, or runtime-memory coverage |
| `CAP-DEPENDENCY-INTEGRITY` | Local Python import/declaration/resolution hygiene; no registry, identity, provenance, malware, or package-safety proof |
| `CAP-PACKAGE-REALITY` | Local package, lock-style-pin, optional SBOM/provenance/hash evidence, and explicit opt-in registry metadata review; no malware, vulnerability, registry-trust, provenance-authenticity, SBOM-completeness, or package-safety proof |
| `CAP-PR-RISK-CLASSIFICATION` | Local diff-risk metadata; no test execution, semantic truth, or PR approval |
| `VALIDATOR-CLAIMS` | Claim/evidence structure, freshness, and overclaim checks; no factual-truth proof |
| `EXTERNAL-SARIF-INGEST` | Project-supplied external findings retained as bounded, unverified evidence |
| `VALIDATOR-AGENT-TRACE` | Deterministic checks over declared agent trace events (incl. autonomy-boundary violations); not a runtime sandbox, execution monitor, or autonomy-safety proof |

Consequently, dependency hallucination, context leakage, and claim integrity use
existing deterministic evidence only as **indirect** coverage. External SARIF
provides **partial**, tool-dependent coverage where relevant.

## Validation

Run:

```bash
python scripts/validators/validate_secure_coding_control_register.py \
  --register configs/secure_coding_control_register.yaml
python scripts/naos_render_secure_coding_controls.py --check
python scripts/validators/validate_secure_coding_control_references.py
python -m unittest tests.test_secure_coding_control_register
python -m unittest tests.test_secure_coding_control_rendering
```

A passing result means the active register, reviewed bindings, and generated
sections are structurally and referentially coherent. It does not mean:

- the standards mappings are independently verified;
- all possible guidance surfaces are covered;
- the application is secure, secret-free, or vulnerability-free;
- detector evidence is present or fresh for a specific adopter project;
- a profile or gate has passed;
- an auditor, regulator, customer, or accountable human has approved anything;
- legal or regulatory compliance has been achieved.

## Using this document

Use this page to frame an evidence review, then attach only current,
project-specific artifacts. Typical supporting items include the selected
profile rationale, specifications, task registry, traceability matrix,
conformance output, gate evaluation, dashboard, evidence pack, exceptions, and
human-review records.

Reviewers must assess provenance, freshness, project scope, unresolved findings,
waivers, runtime gaps, organizational controls, and the meaning of each artifact
in the applicable legal, regulatory, contractual, or audit context.

This document is not legal advice, a certification claim, a conformity
assessment, an audit opinion, a release authorization, or a substitute for
professional and accountable human judgement.
