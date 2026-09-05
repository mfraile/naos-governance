# Secure-Coding & Agentic-Coding Control Model

**Status**: P0, P1, P2, and P3 complete under
[ADR-0012](decisions/ADR-0012-secure-and-agentic-coding-control-register.md).

NAOS has an active canonical requirements register, deterministic generated
summaries for selected guidance surfaces, bounded detector-to-evidence routing,
and five-dimensional dashboard/evidence presentation. This does **not** activate
adopter security enforcement, approve standards mappings, prove secure code, or
replace policy, gatekeeper, evidence, exception, and human decision authority.

## Companion artifacts

- [`configs/secure_coding_control_register.yaml`](../configs/secure_coding_control_register.yaml)
  — active canonical requirement authority.
- [`configs/secure_coding_control_register.sample.yaml`](../configs/secure_coding_control_register.sample.yaml)
  — illustrative compatibility seed.
- [`configs/secure_coding_control_render_manifest.yaml`](../configs/secure_coding_control_render_manifest.yaml)
  — reviewed binding between controls and generated sections.
- [`schemas/naos/secure_coding_control_register.schema.json`](../schemas/naos/secure_coding_control_register.schema.json)
  — structural register contract.
- [`scripts/validators/validate_secure_coding_control_register.py`](../scripts/validators/validate_secure_coding_control_register.py)
  — register integrity and detector-boundary validation.
- [`scripts/naos_render_secure_coding_controls.py`](../scripts/naos_render_secure_coding_controls.py)
  — deterministic renderer and drift check.
- [`scripts/validators/validate_secure_coding_control_references.py`](../scripts/validators/validate_secure_coding_control_references.py)
  — canonical-reference, manifest-binding, and generated-section validation.
- [`capabilities/secure_coding_controls.yaml`](../capabilities/secure_coding_controls.yaml)
  — bounded P2 control-plane capability and authority contract.
- [`templates/structural-seeds/naos/secure_coding_control_evidence_routes.yaml`](../templates/structural-seeds/naos/secure_coding_control_evidence_routes.yaml)
  — detector-to-evidence routing contract.
- [`schemas/naos/secure_coding_control_evidence_routes.schema.json`](../schemas/naos/secure_coding_control_evidence_routes.schema.json)
  — structural routing contract.
- [`schemas/naos/secure_coding_controls.schema.json`](../schemas/naos/secure_coding_controls.schema.json)
  — bounded P2 report contract.
- [`scripts/naos_secure_coding_controls.py`](../scripts/naos_secure_coding_controls.py)
  — deterministic route, evidence-availability, freshness, mapping-state, and
  human-review report.
- [`capabilities/secure_coding_reporting.yaml`](../capabilities/secure_coding_reporting.yaml)
  — separately bounded P3 presentation capability with no gate authority.
- [`schemas/naos/secure_coding_reporting.schema.json`](../schemas/naos/secure_coding_reporting.schema.json)
  — exact five-dimension P3 report contract.
- [`scripts/naos_secure_coding_reporting.py`](../scripts/naos_secure_coding_reporting.py)
  — source consumption, report generation, and bounded projection command.
- [`scripts/secure_coding_reporting/portable_reference.py`](../scripts/secure_coding_reporting/portable_reference.py)
  — non-mutating adopter-path adapter that invokes the unchanged P1 validator in
  an isolated canonical-path view.
- [`templates/structural-seeds/naos/secure_coding_control_render_manifest.yaml`](../templates/structural-seeds/naos/secure_coding_control_render_manifest.yaml)
  — portable adopter mapping between project paths and canonical P1 targets.
- [SECURE_CODING_P3_REPORTING.md](SECURE_CODING_P3_REPORTING.md)
  — P3 operator workflow and explicit boundaries.
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md)
  — bounded control-first review view.

## 1. Objective

Repeated security prose across instructions, agent prompts, IDE rules, and
integration surfaces creates drift. Rewriting one requirement under several
framework identifiers creates a second duplication axis.

The implemented flow is:

```text
canonical requirement
  -> schema-validated active register
  -> reviewed render manifest
  -> bounded generated summaries + stable ids
  -> deterministic reference/drift validation
  -> bounded detector/evidence routing and freshness signals
  -> five independent source-backed reporting dimensions
  -> preflighted dashboard/evidence projection
  -> existing policy/capability/gate authority
  -> evidence, exception handling, and human decision
```

A bare id is insufficient where the consuming human or AI may not have the
register in active context. A hand-maintained paragraph becomes a competing
source. NAOS therefore uses **author once, render many**.

## 2. Authority separation

The active register owns stable control ids, normative statements,
applicability, bounded detector declarations, framework mapping metadata and
verification state, and explicit non-claims.

It does not own profile severity or blocking behavior, validator exit-code
policy, gate outcomes, waivers, exceptions, risk acceptance, human approval, or
release/deployment authorization. Those responsibilities remain in central
policy, capability contracts, gatekeeper configuration, evidence records, and
human decision artifacts.

The evidence-routing contract owns only the binding between canonical detector
ids, bounded report paths, applicability conditions, evidence kind, and review
gates. Evidence presence, freshness, or artifact status never becomes a control
satisfaction, security, conformance, compliance, approval, or release verdict.

P3 is derived presentation. It consumes the authoritative P1/P2 reports and may
write only its report plus bounded regions or objects in existing generated
dashboard and evidence artifacts. `CAP-SECURE-CODING-REPORTING` has no gatekeeper
assignment. G4/G6 continue to consume underlying evidence rather than the P3
presentation.

## 3. Register and render contracts

The register contains `authority`, `mapping_policy`, `standards`,
`detector_catalog`, `planes`, and `controls`. Each control contains its id,
plane, statement, applicability, bounded evaluation declaration, crosswalk
state, and explicit non-claims.

The render manifest separately declares the canonical register, renderer,
non-authority boundary, target file, generated-section id, title, and ordered
control ids. The renderer does not infer targets from repository contents.
Missing, duplicate, unknown, unsafe, or malformed references fail closed.

The portable adopter manifest does not create a second register or renderer. It
maps adopter-local paths to approved canonical P1 targets. The adapter builds a
temporary canonical-path view, copies only declared regular files, invokes the
unchanged P1 validator and renderer, and deletes the temporary view afterwards.

## 4. Generated-section rules

Generated sections use explicit markers:

```text
<!-- BEGIN NAOS GENERATED: <section-id> -->
...
<!-- END NAOS GENERATED: <section-id> -->
```

The renderer loads only the reviewed manifest and active register, validates
repository-relative paths and control references, produces deterministic ordered
summaries, changes only bounded marker regions, and provides non-mutating
`--check` drift detection.

Consumer-specific procedures, examples, architecture choices, and approval rules
remain outside generated regions. P1 binds three initial surfaces:

- `templates/instructions/security.instructions.md`;
- `templates/instructions/ai-pipeline.instructions.md`;
- `templates/cursor-rules/naos-security-standards.mdc`.

Additional surfaces must be added through the manifest and pass bidirectional
reference validation. Adapter coherence remains scoped to adapter/plugin
propagation.

## 5. Evaluation and reporting semantics

| Coverage | Meaning |
| --- | --- |
| `none` | No deterministic detector evaluates the control. |
| `indirect` | Existing evidence may expose related risk but does not evaluate the full control. |
| `partial` | A detector evaluates a defined subset or depends on project-supplied external evidence. |
| `direct` | A bounded detector directly evaluates the statement within its declared resource and language scope. |

“Direct” never means proof of security. Secret hygiene, dependency integrity,
package reality, PR-risk classification, claim validation, and external SARIF
retain their narrow contracts. Dependency hallucination, context leakage, and
claim integrity remain `indirect`; external SARIF remains `partial` for
applicable controls.

P2 reports each detector route independently. Required, conditional, optional,
not-applicable, missing, available, malformed, and stale states remain evidence
routing states, not control outcomes.

P3 exposes exactly five independent dimensions:

1. register validity;
2. reference integrity;
3. detector evidence availability and freshness;
4. mapping verification;
5. human review.

No dimension is converted into a control verdict. The dimensions are not summed,
weighted, averaged, or collapsed into a blended/composite security score.

## 6. Standards discipline

| Framework | Baseline | Role |
| --- | --- | --- |
| OWASP ASVS | 5.0.0 | secure-coding backbone |
| NIST SSDF | SP 800-218 v1.1 | secure-coding backbone |
| OWASP Top 10 | 2025 | secure-coding reference |
| OWASP LLM Top 10 | 2025 | agentic-coding backbone |
| OWASP Agentic Top 10 | 2026 | agentic-coding backbone |
| NIST AI RMF | 1.0 | agentic-coding backbone |
| CSA AICM | machine dataset 1.1.1 (public v1.1 release) | six-control build-time relevance reference |
| CWE | current as of 2026-06-21 | reference |
| ISO/IEC 27002 | 2022 | reference |
| PCI DSS | 4.0.1 | reference |

Framework baselines are versioned or explicitly dated. Every mapping is `draft`,
`verified`, or `deprecated`; verified mappings require a date and sufficiently
specific reference. Current mappings remain draft pending independent review. A
mapping means relevance, not satisfaction or conformance.

The AICM reference is intentionally limited to `AIS-04`, `AIS-11`, `AIS-12`,
`GRC-04`, `GRC-06`, and `GRC-15`. The P2 standards snapshot carries the exact
selection, source release, dataset digest, decision use, scope, and non-claims
from the canonical register; P3 preserves those fields. This does not import or
redistribute the AICM dataset and does not establish applicability, control
implementation, control satisfaction, certification, compliance, runtime
security, or operating effectiveness.

## 7. Wiring map

| Seam | Host | Responsibility |
| --- | --- | --- |
| Active register | `configs/secure_coding_control_register.yaml` | Canonical requirement data |
| Sample register | `configs/secure_coding_control_register.sample.yaml` | Illustrative compatibility seed only |
| Register schema | `schemas/naos/secure_coding_control_register.schema.json` | Structural contract |
| Register validator | `scripts/validators/validate_secure_coding_control_register.py` | Schema, mappings, detectors, and authority checks |
| Render manifest | `configs/secure_coding_control_render_manifest.yaml` | Reviewed consumer bindings |
| Renderer | `scripts/naos_render_secure_coding_controls.py` | Deterministic bounded generation and check mode |
| Reference validator | `scripts/validators/validate_secure_coding_control_references.py` | Active-register, binding, path-boundary, and drift checks |
| P2 capability | `capabilities/secure_coding_controls.yaml` | Detector/evidence-routing authority, resources, limits, and evidence |
| Evidence routes | `templates/structural-seeds/naos/secure_coding_control_evidence_routes.yaml` | Detector-to-report and G4/G6 routing contract |
| P2 control report | `scripts/naos_secure_coding_controls.py` | Register/route validity plus separate evidence, freshness, mapping, human-review dimensions, and a framework-version snapshot from the canonical register |
| P3 capability | `capabilities/secure_coding_reporting.yaml` | Derived presentation authority and explicit absence of gate authority |
| P3 report schema | `schemas/naos/secure_coding_reporting.schema.json` | Exact five-dimension structural contract plus a derived standards snapshot for future framework-version review |
| P3 command | `scripts/naos_secure_coding_reporting.py` | Consume P1/P2 reports, generate P3 report, and project bounded output |
| Portable P1 adapter | `scripts/secure_coding_reporting/portable_reference.py` | Map adopter paths through an isolated canonical P1 validation view |
| Central policy | `policies/default_policy.yaml` | Profile severity, exit codes, and report paths |
| Gatekeepers | `templates/structural-seeds/naos/gatekeepers.yaml` | Convergence and blocking decisions based on underlying evidence, not P3 |
| Dashboard/evidence projection | `scripts/secure_coding_reporting/projection.py` | Preflight, reject symlinks, and update only existing generated artifacts |
| Systemic-impact rules | `templates/structural-seeds/naos/systemic_impact_rules.yaml` | Review propagation for register, detector, mapping, evidence, and AI-surface changes |
| Control-plane review rules | `templates/structural-seeds/naos/control_plane_review_rules.yaml` | Human disposition routing without automatic remediation or approval |

## 8. Phased status

### P0 — corrected baseline: complete

Authority separation, versioned draft mappings, corrected detector references,
schema validation, tests, CI, indexes, and the bounded compliance view are in
place.

### P1 — canonical register and render contract: complete

- active canonical register and reviewed render manifest promoted and packaged;
- deterministic renderer and non-mutating check mode added;
- three duplicated guidance surfaces migrated to bounded generated sections;
- dedicated bidirectional reference-integrity validation added;
- repository-boundary and marker-corruption cases covered;
- active and illustrative registers both covered by tests;
- active-register, renderer, and reference checks enforced in CI.

P1 establishes canonical data and generated-reference integrity only. It does not
activate project security enforcement.

### P2 — control-plane wiring: complete

- bounded `CAP-SECURE-CODING-CONTROLS` authority and evidence contract added;
- schema-validated detector-to-evidence routes cover every canonical detector id;
- deterministic reporting separates register validity, route integrity, evidence
  availability/freshness, mapping state, and outstanding human review;
- G4/G6, systemic-impact, control-plane-review, adopter seeding, CLI/Make, tests,
  and CI are wired without moving policy, gate, exception, approval, or release
  authority into the register;
- evidence presence or freshness never becomes a control-satisfaction, security,
  framework-conformance, or compliance verdict;
- adapter propagation impact is recorded with a hash-backed reviewed disposition;
- graph-query sensitivity findings are scoped to returned relationship candidates,
  preventing unrelated sensitive index edges from contaminating a bounded query.

### P3 — bounded reporting: complete

- `CAP-SECURE-CODING-REPORTING` separates derived presentation from P2 gate
  evidence and has no gatekeeper assignment;
- an exact schema enforces five dimensions, mandatory human review, limitations,
  and explicit non-claims;
- P1/P2 source results are invoked and persisted rather than reimplemented;
- source type, schema contract, missing/malformed content, and symlink boundaries
  fail closed;
- a portable Lite+ manifest and isolated adapter validate adopter-local generated
  surfaces through the unchanged P1 validator and renderer;
- projection preflights every configured target, rejects symlinks, and changes
  only existing dashboard-summary, dashboard Markdown, and evidence-pack output;
- central policy paths, NAOS CLI, portable Make targets, package data, Lite+
  scaffolding, adopter CI, unit tests, and Python 3.11-3.13 CI are wired;
- no blended score, control-satisfaction verdict, framework-conformance claim,
  approval, waiver, gate decision, or release authorization is produced.

## 9. Verification

```bash
python scripts/validators/validate_secure_coding_control_register.py \
  --register configs/secure_coding_control_register.yaml
python scripts/naos_render_secure_coding_controls.py --check
python scripts/validators/validate_secure_coding_control_references.py
python scripts/naos_secure_coding_controls.py --profile quickstart --check
python scripts/naos_secure_coding_reporting.py \
  --profile quickstart \
  --refresh-sources \
  --check
python -m unittest tests.test_secure_coding_control_register
python -m unittest tests.test_secure_coding_control_rendering
python -m unittest tests.test_secure_coding_control_plane
python -m unittest tests.test_secure_coding_reporting
python -m unittest tests.test_secure_coding_reporting_fallback
python -m unittest tests.test_secure_coding_reporting_wiring
python scripts/validators/validate_docs_consistency.py
python scripts/validators/validate_implementation_reality.py
```

A pass means the register, reviewed bindings, generated sections,
evidence-routing contract, P1/P2 source contracts, five-dimension schema,
portable path adaptation, and bounded projection are structurally and
referentially coherent. It does not mean application code is secure, mappings
are verified, detector evidence is valid or complete, any control is satisfied,
or any gate, release, approval, certification, or compliance obligation is
satisfied.
