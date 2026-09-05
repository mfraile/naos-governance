# DORA Mapping

**Status**: Verified primary-authority facts plus bounded NAOS relevance mapping; not legal advice, certification, control satisfaction, conformance, or a compliance opinion
**Audience**: NAOS adopters, EU financial-services technology teams, ICT risk reviewers, and vendor-risk teams
**Scope**: Regulation (EU) 2022/2554 (DORA) and the limited relationship between selected DORA areas and NAOS development evidence

---

## Executive Summary

DORA imposes digital-operational-resilience obligations on in-scope financial
entities and establishes an oversight framework for critical ICT third-party
service providers. NAOS does not operate those obligations. NAOS artifacts may
be relevant to an adopter's development-process evidence, but relevance does
not establish implementation, control satisfaction, conformance, certification,
or legal compliance.

The canonical inventory and deterministic derivations are in the NAOS source
repository at `docs/REGULATORY_CLAIM_SOURCE_MATRIX.yaml`. Each claim identifier
below resolves to one row in that matrix. Generated-project copies of this
mapping are bounded snapshots; the canonical matrix remains kit-source evidence
and is deliberately not added to generated-project surfaces.

Use this document with [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md),
[OSFI_E23_MAPPING.md](OSFI_E23_MAPPING.md), and
[ADMISSIBILITY.md](ADMISSIBILITY.md).

---

## 1. Current Primary Authority

`DORA-SOURCE-001` — The current English authority used here is Regulation (EU)
2022/2554, CELEX `32022R2554`, published in OJ L 333 on 27 December 2022. It is
in force and, under Article 64, applies from 17 January 2025. The EUR-Lex
document-information record reviewed on 22 August 2026 showed the original
English legal act and language-specific corrigenda, none identified as affecting
the English version. This is a source-status observation, not a claim that no
future amendment can occur.

DORA's subject matter includes ICT risk management, ICT-related incident
reporting, digital operational resilience testing, ICT third-party risk,
information-sharing arrangements, and oversight of critical ICT third-party
service providers. Applicability, classification, proportionality, and legal
interpretation remain adopter and professional-adviser responsibilities.

`DORA-STRUCTURE-001` — The current English act contains Articles 1–64 in the
following nine-chapter structure:

| Chapter | Articles | Official subject |
| --- | --- | --- |
| I | 1–4 | General provisions |
| II | 5–16 | ICT risk management |
| III | 17–23 | ICT-related incident management, classification and reporting |
| IV | 24–27 | Digital operational resilience testing |
| V | 28–44 | Managing of ICT third-party risk |
| VI | 45 | Information-sharing arrangements |
| VII | 46–56 | Competent authorities |
| VIII | 57 | Delegated acts |
| IX | 58–64 | Transitional and final provisions |

The chapter and article numbers are legal identifiers. The matrix separately
derives the reported article and chapter counts; recitals, annexes, and paragraph
counts are excluded.

---

## 2. Bounded NAOS Evidence Relationships

The following rows map authority areas to potentially relevant NAOS artifacts.
They do not assert that the artifacts satisfy the cited provisions. Operational
effectiveness and entity-level evidence remain outside repository-only proof.

| Claim ID | DORA locator | Authority area | Bounded NAOS relationship | Evidence boundary |
| --- | --- | --- | --- | --- |
| `DORA-MAP-001` | Articles 5–6 | Governance and ICT risk-management framework | Governance profiles, project rules, responsibility records, and task registries may document development-process decisions. | They do not establish an entity-wide ICT risk-management framework or management-body accountability. |
| `DORA-MAP-002` | Articles 7–8 | ICT systems, protocols, tools, identification, inventories, and dependencies | Function indexes, inventories, architecture boundaries, and specifications may describe the governed project. | A project inventory is not the financial entity's complete ICT asset, dependency, or information-asset inventory. |
| `DORA-MAP-003` | Article 9 | Protection and prevention | Security instructions, dependency guidance, and pre-commit checks may evidence development-time precautions. | Static repository evidence cannot prove deployed protections or continuous control operation. |
| `DORA-MAP-004` | Article 10 | Detection | Validators, tests, and conformance reports may identify bounded source defects. | They do not prove operational anomaly detection, monitoring, alert thresholds, or response capability. |
| `DORA-MAP-005` | Article 11 | Response, recovery, and business continuity | Requirements, runbooks, and acceptance criteria may record intended recovery behavior. | They do not prove an entity's ICT business-continuity policy, business-impact analysis, execution, or testing. |
| `DORA-MAP-006` | Article 12 | Backup and restoration | Architecture and non-functional requirements may specify backup, restoration, segregation, or recovery objectives. | NAOS does not run backups, restore data, or prove recovery performance. |
| `DORA-MAP-007` | Article 13 | Learning and evolving | Closeout evidence and governance refreshes may document project-level lessons and corrective actions. | They do not establish entity-wide threat intelligence, staff capability, training, or continuous technology monitoring. |
| `DORA-MAP-008` | Article 14 | Communication | Handoffs and project records may document development-team communication. | They do not establish crisis-communication plans, designated functions, or external communications. |
| `DORA-MAP-009` | Articles 17–23 | ICT-related incident management, classification, and reporting | Project requirements may identify interfaces to adopter-owned incident processes. | NAOS does not classify or report the financial entity's live incidents. |
| `DORA-MAP-010` | Articles 24–27 | Digital operational resilience testing | Test plans, acceptance criteria, and conformance outputs may support development evidence. | They do not establish the required resilience-testing programme or threat-led penetration testing. |
| `DORA-MAP-011` | Articles 28–44 | ICT third-party risk and critical-provider oversight | Mapping and admissibility artifacts may support a vendor-evidence discussion. | They do not establish registers, pre-contract assessment, contractual compliance, monitoring, exit plans, designation, or oversight. |
| `DORA-MAP-012` | Article 45 and Articles 46–56 | Information-sharing arrangements and competent authorities | Project documentation may state adopter-owned interfaces or participation assumptions. | NAOS does not operate sector information sharing or competent-authority functions. |

No ISO/IEC 27001 or NIST CSF identifier is attributed to DORA in this table.
A future crosswalk would require its own frozen official framework editions,
row-level interpretation, and independent review.

---

## 3. Known DORA Gaps

These rows describe functions that NAOS does not close. They are limitations,
not a complete list of DORA obligations.

| Claim ID | DORA locator | Gap | Why it remains outside NAOS |
| --- | --- | --- | --- |
| `DORA-GAP-001` | Article 18(1)(a), (c), (e), and (f) | Customer or counterparty relevance, geographic spread, service criticality, and economic impact in major-incident classification | Requires live operational data and the financial entity's classification process. Article 18(3) concerns regulatory technical standards; it is not the locator for these factors. |
| `DORA-GAP-002` | Article 26 | Threat-led penetration testing | Eligibility, scope validation, independent testers, production-system coordination, third-party participation, and the applicable TIBER-EU-aligned framework are adopter and authority functions. |
| `DORA-GAP-003` | Articles 28–30 | Third-party register, pre-contract assessment, and contractual provisions | Requires the adopter's service inventory, risk process, contracts, register of information, and exit planning. |
| `DORA-GAP-004` | Articles 31–43 | Oversight framework for critical ICT third-party service providers | Designation and oversight are authority-level functions. Article 44 concerns international cooperation and is not included in this range. |
| `DORA-GAP-005` | Articles 10–14 and 17–23 | Operational monitoring, response, recovery, communication, and incident reporting | NAOS can specify and package development evidence but does not operate production systems. DORA does not supply the former mapping's standalone “24/7” wording. |

NAOS must not be presented as closing these gaps by itself.

---

## 4. Unsupported Or Withdrawn Exact Claims

The previous mapping stated the following results without a repository-owned
row-level crosswalk or reproducible source corpus. They are retained here only
as negative evidence and are not current mapping results.

| Claim ID | Former result | Current disposition |
| --- | --- | --- |
| `DORA-METRIC-001` | 64 DORA articles “mapped” | Unsupported as written and withdrawn. The act has Articles 1–64, but this document does not claim a one-row-per-article mapping. |
| `DORA-METRIC-002` | 78 of 93 ISO/IEC 27001:2022 controls, reported as 84% | Arithmetic is reproducible, but the official ISO corpus, inclusion rule, and row-level crosswalk were absent; withdrawn. |
| `DORA-METRIC-003` | 89 of 106 NIST CSF 2.0 subcategories, reported as 84% | Arithmetic is reproducible, but the official NIST corpus, inclusion rule, and row-level crosswalk were absent; withdrawn. |
| `DORA-METRIC-004` | 15 unique financial-sector-specific requirements | “Requirement” and the inclusion/exclusion rules were undefined; withdrawn. |
| `DORA-METRIC-005` | 71% ISO/NIST overlap | Numerator, denominator, comparison universe, and overlap rule were absent; withdrawn. |
| `DORA-CROSSWALK-001` | DORA-to-ISO/IEC 27001 and DORA-to-NIST CSF mappings | No allowed primary authority supplies this crosswalk, and no reproducible NAOS crosswalk supported it; withdrawn. |

The matrix reproducer fails closed if any unsupported row is treated as a
verified retained result.

---

## 5. NAOS Profile Boundary

DORA does not define NAOS profiles or determine their adequacy.

| Claim ID | Former profile recommendation | Current disposition |
| --- | --- | --- |
| `DORA-PROFILE-001` | `quickstart` as evaluation-only DORA positioning | Withdrawn as a DORA mapping; this is only an internal NAOS posture. |
| `DORA-PROFILE-002` | `lite` for early or low-assurance DORA planning | Withdrawn as a DORA mapping; DORA supplies no NAOS tier classification. |
| `DORA-PROFILE-003` | `standard` as a good default for DORA-adjacent production evidence | Withdrawn as an authority-backed recommendation. |
| `DORA-PROFILE-004` | `assured` as the strongest DORA-adjacent profile | Withdrawn as an authority-backed recommendation and not evidence of DORA adequacy. |

Profile selection remains an internal governance decision. It does not determine
DORA applicability, proportionality, implementation, control satisfaction,
conformance, certification, or compliance.

---

## 6. Adopter Checklist

For a DORA-adjacent review, start with:

- [ ] [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for the general NAOS posture.
- [ ] This mapping for the primary-authority and NAOS relevance boundary.
- [ ] [ADMISSIBILITY.md](ADMISSIBILITY.md) for evidence-package scope and limits.
- [ ] The canonical matrix and a passing result from `python3 -B scripts/validators/validate_regulatory_claim_source_matrix.py --json` in the NAOS kit checkout.
- [ ] Current project dashboard, traceability, conformance, and profile-selection evidence, treated only according to what each artifact proves.
- [ ] Project-specific ICT risk management, incident response, resilience testing, third-party-risk, and legal-interpretation evidence outside NAOS.

For generated lite, standard, and assured projects,
`make -f Makefile.naos admissibility-pack` packages common NAOS evidence
artifacts for handoff. That pack does not reproduce the canonical regulatory
matrix and does not replace DORA operational or legal evidence.
