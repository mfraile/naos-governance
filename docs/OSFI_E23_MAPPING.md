# OSFI E-23 Mapping

**Status**: Verified primary-authority facts plus bounded NAOS relevance mapping; not legal advice, certification, control satisfaction, conformance, or a compliance opinion
**Audience**: NAOS adopters, federally regulated financial institutions, vendor-risk reviewers, and model-risk teams
**Scope**: OSFI Guideline E-23 model-risk-management expectations where the relevant component meets E-23's definition of a model

---

## Executive Summary

OSFI Guideline E-23 sets model-risk-management expectations for federally
regulated financial institutions. It is not a general AI-assisted software
delivery standard. This mapping applies only when the relevant system or
component meets the guideline's model definition and the institution determines
that E-23 is applicable.

NAOS does not make an institution conformant or compliant with E-23. Selected
NAOS development artifacts may be relevant inputs to an institution-owned
model-risk or third-party review. Relevance does not establish implementation,
control satisfaction, independent model review, approval, certification,
operating effectiveness, or legal compliance.

The canonical inventory is in the NAOS source repository at
`docs/REGULATORY_CLAIM_SOURCE_MATRIX.yaml`. Each claim identifier below resolves
to one row in that matrix. Generated-project copies of this mapping are bounded
snapshots; the matrix remains kit-source evidence and is deliberately not added
to generated-project surfaces.

Use this document with [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md),
[DORA_MAPPING.md](DORA_MAPPING.md), and [ADMISSIBILITY.md](ADMISSIBILITY.md).

---

## 1. Current Primary Authority And Applicability

`E23-SOURCE-001` — The current authority used here is OSFI's final
*Guideline E-23 – Model Risk Management (2027)*, published 11 September 2025
and effective 1 May 2027. OSFI's final-guideline letter confirms that the 2023
publication was a draft and states the revised effective date. Both official
OSFI pages were accessed on 22 August 2026. The final guideline is therefore
current but not yet effective on the access date.

`E23-SCOPE-001` — E-23 applies to the model-risk-management practices of
federally regulated financial institutions within its stated scope. Section A.3
addresses proportional implementation; Section A.4 defines a model. A generic
software system, AI-assisted delivery process, or repository artifact is not brought
within E-23 merely because it uses AI terminology. The institution owns the
applicability, model-identification, and risk-rating decisions.

---

## 2. Bounded Lifecycle Evidence Relationships

The authority locators below are current OSFI sections and principles. The NAOS
column identifies possible development evidence only; it is not an E-23
crosswalk endorsed by OSFI.

| Claim ID | E-23 locator | Authority area | Bounded NAOS relationship | Institution-owned boundary |
| --- | --- | --- | --- | --- |
| `E23-AREA-001` | B.1–B.2, Principles 1.1–1.2 | Organizational enablement and the model-risk-management framework | Responsibility records, governance rules, and project decisions may help explain the development process. | The institution owns its MRM framework, risk appetite, resourcing, reporting, and enterprise accountability. |
| `E23-AREA-002` | C.1–C.3, Principles 2.1–2.3, and Appendix 1 | Model identification, inventory, risk rating, and proportional MRM | Project inventories and scope records may be candidate inputs if the institution accepts them. | The institution identifies models, maintains its model inventory, assigns model risk ratings, and sets proportional governance. |
| `E23-AREA-003` | D.2, Principles 3.2–3.3 | Model rationale, data, development, documentation, and developer testing | Specifications, requirements, data-lineage records, tests, and limitations may be relevant development artifacts. | The institution determines fitness, data governance, methodological soundness, documentation sufficiency, and accepted use. |
| `E23-AREA-004` | D.2, Principle 3.4 | Independent model review | Review records and test outputs may be inputs to an independent reviewer. | NAOS does not perform or sign off the institution's independent assessment of conceptual soundness, performance, or fitness for purpose. |
| `E23-AREA-005` | D.2, Principle 3.5 | Model deployment, quality, and change control | Change records, deployment requirements, tests, and approvals may document development-time decisions. | The institution owns production approval, configuration, change control, exception handling, and operational risk assessment. |
| `E23-AREA-006` | D.2, Principle 3.6 | Model monitoring and decommissioning | Monitoring requirements and handoff records may specify intended interfaces. | NAOS does not monitor model performance or drift, set institution thresholds, escalate breaches, operate contingencies, or decommission models. |
| `E23-AREA-007` | B.2, C.1, Principle 3.4, and Appendix 1 | Models or data from external sources, including vendor and third-party models | A delivery team may provide project scope, provenance, limitations, tests, and review records for institution assessment. | E-23 does not create a NAOS “vendor-cascade” certification route; the institution governs external models and data within its own MRM and third-party-risk framework. |

---

## 3. External-Model Evidence Boundary

`E23-BOUNDARY-001` — Section B.2 requires the institution's MRM framework to
cover models or data sourced externally, and the guideline also addresses vendor
and third-party models in model identification and review. The guideline does
not prescribe a NAOS evidence pack, transfer responsibility to a delivery team,
or establish that a vendor's development artifacts satisfy E-23. Any requested
handoff is institution- and contract-specific.

A NAOS-governed delivery team may provide artifacts such as project scope,
requirements, architecture, data provenance, limitations, tests, change
records, and review evidence. The recipient must evaluate their authenticity,
scope, completeness, independence, and relevance.

---

## 4. Known E-23 Gaps

The following are institution-owned functions that NAOS does not provide. This
is a bounded limitation list, not a complete statement of E-23 expectations.

| Claim ID | E-23 locator | NAOS limitation |
| --- | --- | --- |
| `E23-GAP-001` | B.1–B.3 | NAOS does not provide institution-level model-risk governance, resourcing, risk appetite, or accountability. |
| `E23-GAP-002` | C.1–C.3 and Appendix 1 | NAOS does not own the institution's model identification, model inventory, model risk rating, or proportionality decisions. |
| `E23-GAP-003` | Principle 3.4 | NAOS does not provide independent model-review sign-off. |
| `E23-GAP-004` | Principles 3.5–3.6 | NAOS does not approve production deployment or operate model performance, drift, breach, contingency, or decommissioning processes. |
| `E23-GAP-005` | B.1 and Principle 3.5 | NAOS does not provide board, senior-management, model-owner, model-approver, or production accountability evidence beyond bounded project records. |
| `E23-GAP-006` | B.2, C.1, and Principle 3.4 | NAOS does not perform third-party contract management, external-model risk acceptance, or institutional vendor oversight. |
| `E23-GAP-007` | Entire guideline | NAOS does not provide OSFI, legal-professional, regulatory, or auditor approval. |

---

## 5. Unsupported Or Withdrawn Mapping Claims

The previous mapping attributed several NAOS mechanisms or recommendations to
E-23 without authority support. They are preserved here as negative evidence
and are not current E-23 mapping results.

| Claim ID | Former mapping claim | Current disposition |
| --- | --- | --- |
| `E23-WITHDRAWN-001` | Requirements-to-code-to-test traceability was presented as an E-23 expectation. | Withdrawn. E-23 requires model documentation and development standards, but does not prescribe NAOS traceability mechanics. |
| `E23-WITHDRAWN-002` | NAOS profile tiers and tier-gated pre-commit controls were presented as E-23 governance controls. | Withdrawn. E-23 uses institution-assigned model risk ratings, not NAOS profiles. |
| `E23-WITHDRAWN-003` | `assured`-profile human-in-the-loop gates were presented as E-23 independent review support. | Withdrawn as an authority-backed claim. Institution-owned independent model review is not replaced by NAOS HITL. |
| `E23-WITHDRAWN-004` | Pre-commit validation, conformance, and acceptance-criteria reference checks were presented as E-23 expectations. | Withdrawn as an authority-backed claim; they remain internal development controls. |
| `E23-WITHDRAWN-005` | Task ownership and delivery tracking were presented as E-23 model inventory evidence. | Withdrawn. Project task records are not the institution's model inventory. |
| `E23-WITHDRAWN-006` | Cross-session handoffs and cognitive checkpoints were presented as E-23 lifecycle expectations. | Withdrawn as an authority-backed claim. |
| `E23-WITHDRAWN-007` | An admissibility pack was presented as an E-23 vendor-review requirement. | Withdrawn. It may be an optional evidence bundle only. |
| `E23-WITHDRAWN-008` | The “vendor-cascade joint” was presented as an E-23-defined handoff. | Withdrawn. E-23 requires institution coverage of external models and data but does not use this term or prescribe this route. |

---

## 6. NAOS Profile Boundary

E-23 does not define NAOS profiles or determine their adequacy.

| Claim ID | Former profile recommendation | Current disposition |
| --- | --- | --- |
| `E23-PROFILE-001` | `quickstart` as familiarisation-only E-23 positioning | Withdrawn as an E-23 mapping; it is only an internal NAOS posture. |
| `E23-PROFILE-002` | `lite` for early or low-assurance E-23-adjacent work | Withdrawn as an authority-backed recommendation. |
| `E23-PROFILE-003` | `standard` as the default for E-23-adjacent production evidence | Withdrawn as an authority-backed recommendation. |
| `E23-PROFILE-004` | `assured` as the strongest E-23 vendor-evidence profile | Withdrawn as an authority-backed recommendation and not evidence of E-23 adequacy. |

Profile selection is not an E-23 model risk rating or approval decision.

---

## 7. Adopter Checklist

For an E-23-adjacent evidence review:

- [ ] Confirm with the institution whether the component meets E-23's model definition and what risk rating and governance apply.
- [ ] Use [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for the general NAOS posture and [ADMISSIBILITY.md](ADMISSIBILITY.md) for evidence-package limits.
- [ ] Review this mapping and the canonical matrix with a passing result from `python3 -B scripts/validators/validate_regulatory_claim_source_matrix.py --json` in the NAOS kit checkout.
- [ ] Obtain current project scope, requirements, data provenance, limitations, tests, change records, review evidence, and any requested sign-offs.
- [ ] Preserve the institution's own model inventory, risk rating, independent review, approval, monitoring, third-party-risk, and legal-interpretation evidence outside NAOS.

For generated lite, standard, and assured projects,
`make -f Makefile.naos admissibility-pack` packages common NAOS evidence
artifacts for optional handoff. It does not reproduce the canonical regulatory
matrix and is not an OSFI-defined or OSFI-approved evidence package.
