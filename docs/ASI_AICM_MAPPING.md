# NAOS Agentic-Security Framework Mapping (OWASP ASI / AICM / MAESTRO / AIVSS / AST10)

**Version**: 0.2.0
**Status**: Advisory mapping, not a compliance opinion. Bounded crosswalk to
the 2026 agentic-security anchor frameworks; companion to `COMPLIANCE_MAPPING.md`.
**Guidance**: This document lets teams benchmark NAOS against the emerging
agentic-AI security spine (OWASP Top 10 for Agentic Applications, CSA AICM, CSA
MAESTRO, OWASP AIVSS, OWASP Agentic Skills Top 10). It does not guarantee
certification or runtime security.

---

## Executive Summary

NAOS maps its AI-assisted **SDLC** governance primitives to the major 2026
**agentic-security** frameworks. As with `COMPLIANCE_MAPPING.md`, this is a
practical crosswalk: which NAOS artifacts may support a control discussion,
which profile tiers are relevant, and where coverage remains outside the kit.

This is **not** legal advice, a certification claim, a conformity assessment, or
a security guarantee. The anchor frameworks are themselves recent and partly in
flux (several NIST/CSA/OWASP items were draft, RFI, or pre-1.0 as of mid-2026);
treat this as a starting point for review, not a final interpretation.

**Key positioning**: NAOS governs the **AI development process** — the agents
and humans that *write code*. The frameworks below govern the **deployed agentic
system** at runtime. NAOS provides development-phase evidence that
risk-appropriate controls were defined, followed, and checked; it does not by
itself secure a running agent. Many agentic risks therefore split into a
**build-time half** (in scope) and a **runtime half** (out of scope by design,
handed off to a runtime governance layer).

**Responsibility boundary**: the adopter, system owner, or operator remains
responsible for selecting the appropriate profile, configuring project-specific
controls, validating outputs, maintaining runtime and organizational controls,
and deciding whether NAOS-derived evidence is adequate for its own security,
legal, regulatory, contractual, or procurement context.

**Scope legend used throughout**:

| Tag | Meaning |
| --- | --- |
| **In scope** | NAOS provides build-time preventive and/or detective coverage. |
| **Partial** | Build-time coverage exists but is bounded (e.g. package-level, metadata-grade). |
| **OOS-by-design** | Runtime/deployed-agent control NAOS deliberately does not implement; provides ingest/handoff seams instead. |

---

## 1. Framework Coverage Summary

| Framework | NAOS Support | Profile Tier | Key Gap |
| --- | :--: | :--: | --- |
| OWASP Top 10 for Agentic Applications (ASI01–ASI10, 2026) | Supporting build-time SDLC evidence for most risks | `standard`–`assured` | Runtime hijack/tool/identity/drift enforcement out of scope |
| CSA AICM v1.1 / machine dataset v1.1.1 (247 controls / 18 domains) | Six-control SDLC relevance selection | `standard`–`assured` | Runtime, infrastructure, organizational operation, applicability, and control satisfaction remain adopter-owned |
| CSA MAESTRO (7 layers) | Design-review lens (L3/L5/L6) | all profiles | L1/L2/L4/L7 runtime layers mostly outside NAOS |
| OWASP AIVSS v0.8 (scoring) | Adoptable as finding-score vocabulary | all profiles | No native force-multiplier score yet (precursor only) |
| OWASP Agentic Skills Top 10 (AST10) | Partial via Rule 18 + frontmatter conformance | `standard`–`assured` | Not expressed as an AST-mapped taxonomy |

---

## 2. OWASP ASI01–ASI10 — Control-Level Mapping

Each risk lists NAOS **preventive** and **detective** primitives at the SDLC
boundary, then the scope tag. IDs are verbatim from `profiles/*/.ai/RULES.md`,
`capabilities/*.yaml`, and `gatekeepers.yaml`.

| ASI | Risk | NAOS Preventive | NAOS Detective | Scope |
| --- | --- | --- | --- | :--: |
| **ASI01** | Agent Goal / Behavior Hijack | Rule 7 (deep-analysis, no-drift, stay-in-scope); Rule 26 cognitive-checkpoint posture + a self-declared commit-time PAUL signal (not tool-call interception); Pre-Implementation Alignment (`CAP-GOVERNED-AGENTIC-CODING-WORKFLOW`); Rule 18 scoped instructions | `CAP-AGENT-TRACE-EVENT-SCHEMA` (declared trace + StaticGrader drift mode); `CAP-PR-RISK-CLASSIFICATION` (prompt-injection-like text) | Partial (build-time); runtime alignment guard OOS |
| **ASI02** | Tool Misuse & Exploitation | Rule 18 least-privilege tool declarations; per-capability `authority.may_read / may_write / prohibited_resources` | `CAP-PR-RISK-CLASSIFICATION` (protected paths, workflow changes); `CAP-ADAPTER-COHERENCE` | Partial; runtime tool-call interception OOS |
| **ASI03** | Identity & Privilege Abuse | Rule 18 model pinning + tool scope; default generated agent manifests omit agent invocation and document human-mediated handoff; optional `CAP-GOVERNED-DEBUG-ESCALATION` requires an exact parent/child allowlist, a child without direct edit/create or agent-invocation tools, profile/maturity eligibility, host acknowledgement, and named approval | `CAP-GOVERNANCE-BYPASS-POSTURE`; operator-attribution + session-identity (local metadata); `CAP-PR-RISK-CLASSIFICATION` contributor-trust metadata; governed-debug activation validator | Partial; generated tool-manifest and local activation posture only, not host/runtime identity, authentication, authorization, filesystem isolation, or invocation proof (see §7) |
| **ASI04** | Agentic Supply Chain (tools, MCP servers, agent cards, registries) | Rule 10 licence-review posture (no scanner installed by default); Rule 20 dependency declaration (pinned versions incl. MCP deps); `CAP-DEPENDENCY-INTEGRITY`; `CAP-PACKAGE-REALITY` | `CAP-DEPENDENCY-INTEGRITY` report; `CAP-PACKAGE-REALITY` report; `CAP-EXTERNAL-EVIDENCE-INGEST` (SARIF intake — seam for `mcp-scan`/AgentShield); `CAP-SECRET-HYGIENE` | Partial (package-level); MCP-descriptor scan / tool-pinning / AIBOM gap |
| **ASI05** | Unexpected Code Execution (**vibe coding**) | Rule 8 AST validation; Rule 7 evidence-first; governed-vibe-coding workflow; pre-commit hook; Rules 1–2 file hygiene; `CAP-DUPLICATE-FUNCTION-HYGIENE` | `CAP-PR-RISK-CLASSIFICATION`; `CAP-SECRET-HYGIENE`; `CAP-DETERMINISTIC-CONFORMANCE-REVIEW`; `CAP-TEST-QUALITY-HYGIENE` | **In scope (strongest)** |
| **ASI06** | Memory & Context Poisoning | Rule 19 memory-governance prohibition on PII/credentials/customer data plus human-approval posture for durable writes; `CAP-AI-CONTEXT-CONTINUITY-MEMORY`; no automatic context injection or storage-boundary enforcement proof | `CAP-AI-CONTEXT-CONTINUITY-MEMORY` readiness; memory-use-policy review; `CAP-GOVERNED-LEARNING-LIFECYCLE` | **In scope (build-time posture)**; runtime RAG/memory poisoning OOS |
| **ASI07** | Insecure Inter-Agent Communication | Default generated agent manifests omit agent invocation; Rule 18 documents human-mediated handoff; optional `CAP-GOVERNED-DEBUG-ESCALATION` allows only one stateless implementation-to-debug diagnostic request | `CAP-AGENT-TRACE-EVENT-SCHEMA` (declared handoff records); governed-debug activation validator | Partial for one host-specific manifest boundary; no A2A/AgentCard/mTLS, secure transport, runtime interception, or invocation proof |
| **ASI08** | Cascading Failures | Rule 13 resilience/retry; Rule 14 event-schema evolution; default generated agents omit invocation; optional governed debug escalation limits the target to one diagnostic child without direct edit/create tools, one dispatch, and no recursion; `CAP-SYSTEMIC-IMPACT-REVIEW` | `CAP-SYSTEMIC-IMPACT-REVIEW`; `CAP-SPEC-CASCADE-COHERENCE`; `CAP-CALIBRATION-SHADOW`; governed-debug activation validator | Partial; instruction/manifest limits only, with no host/runtime filesystem, blast-radius, or kill-switch enforcement |
| **ASI09** | Human-Agent Trust Exploitation | Rule 21 (AI-generated content labeled in UI; HITL for critical decisions); 4 assured HITL gates; `ADR-0010: Control-Plane Advisory Boundaries` + `not_claimed` fields | `CAP-CLAIMS-VALIDATION` (overclaim patterns); docs-consistency; threat-model "report-as-approval" controls | Partial–strong; deployed-agent social-engineering of end users OOS |
| **ASI10** | Rogue Agents (drift, collusion, self-replication) | Rule 25 ("NEVER auto-promote to Rule without human sign-off"); default generated agents omit invocation; the optional debug child has no direct edit/create or agent-invocation tools and is unavailable for general model invocation; Rule 26 CRITICAL bracket; no automatic approval | `CAP-CALIBRATION-SHADOW` (deterministic report-shape drift routed to human review, with no default numeric behavior threshold); `CAP-STATIC-GRADER` deterministic drift mode; `CAP-AGENT-TRACE-EVENT-SCHEMA`; governed-debug activation validator | Partial (build-time and manifest posture); no host/runtime filesystem or self-replication prevention and no intent-drift correlation |

**Reading.** At the SDLC boundary, NAOS provides both a preventive **and** a
detective primitive for ASI01, ASI02, ASI05, ASI06, ASI08, ASI09, and
metadata-grade ASI03. Deficits concentrate at the runtime edge (ASI03
cryptographic identity, ASI04 MCP/AIBOM, ASI07 A2A, ASI10 runtime drift) — see
§7.

The nested-agent entries above describe shipped tool-manifest defaults,
human-mediated guidance, and one optional VS Code-specific activation
contract. They do not establish host/runtime prevention, tool-call
interception, secure inter-agent transport, invocation proof, or control over
adopter-customized agents.

---

## 3. CSA AICM — Bounded Control-ID Selection

CSA's public AICM v1.1 release contains 247 control objectives across 18
domains. The machine-readable bundle released on 2026-08-04 identifies its
primary dataset as v1.1.1. The canonical register pins that dataset and selects
only the six IDs below. The selection informs one decision: which NAOS
**build-time** evidence may support an adopter's AICM scoping review, and which
responsibilities must be handed to the adopter or runtime-control owner.

| Selected AICM v1.1.1 ID | NAOS evidence with bounded relevance | Retained limitation |
| --- | --- | --- |
| `AIS-04` | Canonical secure/agentic control register, generated instruction summaries, tests, evidence routing, and review gates | Relevant only to the NAOS-supported planning, development, test, and review slice; no deployment or operation assurance |
| `AIS-11` | `AC-TOOL-AUTHORITY-01`, `AC-AUTONOMY-BOUNDARY-01`, governed-agent workflow declarations, and declared trace validation | No runtime access control, isolation, network boundary, tool-call interception, or boundary-effectiveness proof |
| `AIS-12` | Versioned register, repository change/evidence controls, review records, and bounded static-analysis/SARIF seams | No proof every review occurred, every source path is covered, or every analysis technology is present |
| `GRC-04` | Explicit authorization, escalation, waiver, and human-decision boundaries | NAOS does not operate or approve an enterprise policy-exception process |
| `GRC-06` | Separation of requirement, enforcement, rendering, gate, and human-decision responsibilities | Not an enterprise RACI or a complete lifecycle governance responsibility model |
| `GRC-15` | Required human-review routing, approval boundaries, and evidence reports | No proof that substantive supervision occurred or was effective, and no post-deployment oversight |

The mappings remain `draft`: the official identifiers and source edition are
deterministically pinned, while relevance is still a bounded interpretation.
NAOS does not claim AICM compliance, control satisfaction, certification,
runtime security, an operational enterprise exception process, a complete
enterprise responsibility model, or effective human supervision.

Controls outside this six-ID set are deliberately not mapped. In particular,
NAOS does not turn package checks into `STA-09` service-BOM evidence, advisory
PII/secret posture into `DSP-04` data classification, or declared records into
`LOG-01` runtime logging and monitoring. Infrastructure, deployed IAM,
operational resilience, incident response, model-provider governance, and
other adopter/vendor controls remain outside this mapping.

---

## 4. CSA MAESTRO — Seven-Layer Lens

MAESTRO is used here as a **design-review lens**, not a scored mapping. NAOS
operates primarily in three layers:

| MAESTRO layer | NAOS relevance |
| --- | --- |
| L1 Foundation Models | Out of scope (NAOS does not host/serve models). |
| L2 Data Operations | Partial — Rule 19, Rule 21 data/metadata governance at build time. |
| **L3 Agent Frameworks** | **Primary** — Rule 18 agent/skill governance, frontmatter conformance, `CAP-AI-SURFACE-HEALTH`. |
| L4 Deployment & Infrastructure | OOS-by-design (runtime). |
| **L5 Evaluation & Observability** | **Primary** — conformance review, `CAP-STATIC-GRADER`, behavioral-gate readiness (G7), 49-scenario metadata battery, and the separate internal 23-case deterministic adversarial CI regression. The latter is not model-backed behavioral red-team assurance. |
| **L6 Security & Compliance (cross-cutting)** | **Primary** — this document, `COMPLIANCE_MAPPING.md`, threat model, `CAP-CLAIMS-VALIDATION`. |
| L7 Agent Ecosystem | Partial — `CAP-ADAPTER-COHERENCE`, `CAP-EXTERNAL-EVIDENCE-INGEST`; runtime ecosystem OOS. |

Recommended use: apply MAESTRO L3/L5/L6 as the threat-modeling lens in NAOS
design reviews; defer L1/L4/L7 runtime layers to the deployed-system owner.

---

## 5. OWASP AIVSS — Scoring Adoption Posture

NAOS now provides an optional, separately installed arithmetic verifier for the
published AIVSS-Agentic v0.8 formula. It accepts assessor-supplied CVSS-v4 base
score, all ten factors (autonomy, tools, language, context, non-determinism,
opacity, persistence, identity, multi-agent, and self-modification), threat
maturity, mitigation strength, and evidence references. It pins the normative
PDF by URL and SHA-256, preserves exact finite-decimal intermediates, and rounds
only the final score half-up to one decimal. The PDF permits 0.0 but defines no
band for it, so NAOS preserves 0.0 as unbanded.

The named consumer is G2/G6 human security review. High/Critical bands create
score-review prompts; arithmetic mismatches and installed-evidence integrity
faults create separate advisory prompts. The verifier does not calculate or
validate CVSS, choose or verify subjective factor values, discover
vulnerabilities, assess risk or exploitability, observe runtime behavior, prove
mitigations or security, approve, block, prioritize, merge, release, accept
risk, certify, attest, publish, or prove compliance.

---

## 6. OWASP Agentic Skills Top 10 (AST10)

NAOS governs the "skill" layer at build time without expressing it as an
AST-mapped taxonomy:

| AST theme | NAOS primitive |
| --- | --- |
| AST01 Malicious Skills / AST02 Supply-chain compromise | Rule 18 skill governance + frontmatter conformance; `CAP-ADAPTER-COHERENCE`; `CAP-PR-RISK-CLASSIFICATION` |
| AST03 Excessive Permissions | Rule 18 least-privilege tools; per-capability `authority` block |
| AST09 No Governance | 4 profiles + gates G0–G8; `CAP-SELF-CONFORMANCE` |
| AST10 Cross-Platform Reuse (metadata loss) | Two-layer portable architecture (agnostic agents + `project-context.md`); `CAP-ADAPTER-COHERENCE` drift detection |

---

## 7. Gap Analysis — Honest Assessment

Consistent with `COMPLIANCE_MAPPING.md` §6 and `NAOS_THREAT_MODEL.md`, NAOS does
**not** provide the following. Items are split into **true build-time gaps**
(candidates for the kit) and **out-of-scope-by-design** (runtime, handoff-only).

**True build-time gaps (addressable additively):**

| Gap | Mapped risk | Status |
| --- | --- | --- |
| AICM mapping remains a six-ID relevance crosswalk, not control satisfaction | AICM | Implemented as a pinned draft selection; broader control selection requires a new consumer and source review |
| No standards-conformant AIBOM generator (CycloneDX ML-BOM / SPDX AI profile) | ASI04 | A bounded custom `ai_component_inventory.v1` declared-facts inventory is implemented and consumed by control-plane G2/G6 review; no CycloneDX/SPDX, runtime-discovery, completeness, signing, attestation, or supply-chain-assurance claim is made |
| No MCP-descriptor / tool-poisoning scan wired in; no tool-pinning | ASI04 | Ingest seam exists (`CAP-EXTERNAL-EVIDENCE-INGEST`); adapter pending |
| No bounded AIVSS arithmetic consumer | AIVSS | Implemented as the optional pinned-v0.8 arithmetic verifier and advisory G2/G6 consumer; subjective scoring, CVSS validation, vulnerability discovery, risk assessment, runtime evidence, security assurance, and decision authority remain out of scope |
| No agent registry tying each agent to a human sponsor; no short-lived-credential posture | ASI03 | Bounded build-time portion implemented as the opt-in `agent_sponsor_registry.v1` declaration and G2/G6 consumer. It checks current-agent coverage, opaque sponsor/owner references, categorical external credential posture, and registry-review expiry; it does not verify people, credentials, credential lifetime, authentication, authorization, or runtime identity. Crypto identity stays OOS. |

**Out-of-scope-by-design (runtime; handoff, not build):**

- Runtime goal-alignment / tool-call enforcement (ASI01/ASI02) — guardrail layer.
- Cryptographic agent identity (SPIFFE/SPIRE), OAuth On-Behalf-Of (ASI03).
- A2A / signed AgentCards / mTLS (ASI07).
- Runtime rogue-agent / intent-drift detection, kill-switch (ASI10/ASI08).
- Agent sandboxing (a harness property, e.g. Claude Code) — NAOS governs its
  *configuration* via `CAP-GOVERNANCE-BYPASS-POSTURE` + `CAP-PR-RISK-CLASSIFICATION`.

For all runtime items, `CAP-RUNTIME-HANDOFF` records runtime-governor identity,
policy-bundle version, decision-record location/hash, and runtime residual risks
— it does **not** execute runtime governance.

---

## 8. Using This Document

- Cite this crosswalk as evidence of **SDLC-side** alignment with the 2026
  agentic-security frameworks; pair it with `naos/DASHBOARD.md`,
  `naos/TASK_REGISTRY.yaml`, and the latest conformance report.
- Treat every "OOS-by-design" item as a **handoff boundary**, not a deficiency:
  the deployed-system owner supplies the runtime control, and NAOS ingests its
  evidence via `CAP-EXTERNAL-EVIDENCE-INGEST` / `CAP-RUNTIME-HANDOFF`.
- Re-baseline this mapping at each major OWASP/CSA/NIST revision; the anchor
  frameworks change frequently.
- The AICM v1.1.1 six-ID selection is pinned in the canonical register and
  remains draft as an applicability interpretation. The separate optional AIVSS
  capability verifies v0.8 arithmetic only; it does not establish control
  satisfaction, risk, exploitability, or approval.

---

## References — Frameworks & Standards

Canonical sources for the frameworks and standards referenced in this crosswalk
and the related agentic-security analysis. NIST items marked *(draft/RFI)* were
not finalized as of mid-2026 — navigate from the org page for current status.

**Agentic-security frameworks (benchmark spine)**
- OWASP GenAI Security Project (Agentic Top 10 / ASI, LLM Top 10, Agentic Skills Top 10) — https://genai.owasp.org/
- OWASP Top 10 for LLM Applications — https://genai.owasp.org/llm-top-10/
- OWASP AIVSS (AI Vulnerability Scoring System) — https://aivss.owasp.org/
- CSA AI Controls Matrix v1.1 (public release) — https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1
- CSA AICM machine-readable bundle — https://cloudsecurityalliance.org/artifacts/aicm-machine-readable-bundle-json-yaml-oscal
- CSA MAESTRO (via Cloud Security Alliance) — https://cloudsecurityalliance.org/

**Government standards (US)** *(several draft/RFI)*
- NIST AI Risk Management Framework (AI RMF 1.0) — https://www.nist.gov/itl/ai-risk-management-framework
- NIST Cybersecurity Framework 2.0 — https://www.nist.gov/cyberframework
- NIST CSRC (COSAiS overlays; Cyber AI Profile / NISTIR 8596 *draft*) — https://csrc.nist.gov/
- NIST CAISI (AI Agent security RFI) — https://www.nist.gov/caisi
- NIST NCCoE (agent identity & authorization concept paper *draft*) — https://www.nccoe.nist.gov/

**Regulatory frameworks**
- EU AI Act (Reg. (EU) 2024/1689) — https://artificialintelligenceact.eu/ · official: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- DORA (Reg. (EU) 2022/2554) — https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- ISO/IEC 42001 (AI management system) — https://www.iso.org/standard/81230.html
- ISO/IEC 27001 — https://www.iso.org/standard/27001
- OSFI Guideline E-23 (Model Risk Management, Canada) — https://www.osfi-bsif.gc.ca/
- US Fed SR 11-7 (model risk management) — https://www.federalreserve.gov/supervisionreg/srletters/sr1107.htm
- AIUC-1 (AI agent standard) — https://www.aiuc-1.com/

**Provenance / supply-chain standards**
- DSSE (Dead Simple Signing Envelope) — https://github.com/secure-systems-lab/dsse
- in-toto — https://in-toto.io/
- SLSA — https://slsa.dev/
- Sigstore — https://www.sigstore.dev/
- OpenSSF Scorecard — https://github.com/ossf/scorecard
- Ed25519 (RFC 8032) — https://datatracker.ietf.org/doc/html/rfc8032
- Certificate Transparency / Merkle (RFC 6962) — https://datatracker.ietf.org/doc/html/rfc6962
- CycloneDX (ML-BOM / AIBOM) — https://cyclonedx.org/
- SPDX (3.0 AI Profile) — https://spdx.dev/
- SARIF 2.1.0 (OASIS) — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

**Agent protocols & identity**
- Model Context Protocol (MCP) — https://modelcontextprotocol.io/
- Agent2Agent (A2A) — https://github.com/a2aproject/A2A (Linux Foundation)
- SPIFFE/SPIRE — https://spiffe.io/
- OpenID AuthZEN — https://openid.net/wg/authzen/

> AICM links re-verified 2026-08-31; other links were last verified June 2026. Standards mappings here are advisory; cite primary
> sources for conformity work.

---

*Companion documents*: `COMPLIANCE_MAPPING.md` (EU AI Act / NIST / ISO / AIUC /
OSFI / DORA), `NAOS_THREAT_MODEL.md`, `ADMISSIBILITY.md`.
