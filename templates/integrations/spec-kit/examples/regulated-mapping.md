# Regulated Spec-Kit To NAOS Mapping Example

This example is a conservative pattern for teams that use specification files in
regulated or audited delivery. It is review evidence only.

| Spec-Kit artifact | NAOS evidence surface | Review boundary |
| --- | --- | --- |
| `.specify/specs/control-requirements.md` | `naos/evidence/evidence_pack.json` | Evidence pack shows referenced artifacts; it is not proof of compliance. |
| `.specify/specs/control-requirements.md` | `naos/reports/evidence_conflict_detection.json` | Conflict detection flags disagreements; it does not resolve them. |
| `.specify/specs/model-risk-notes.md` | `naos/reports/control_plane_review.json` | Review routing records disposition candidates; humans decide. |
| `.specify/specs/release-constraints.md` | `naos/reports/gate_evaluation.json` | Gates provide review signals; they do not authorize release. |

Recommended regulated review steps:

1. Treat `.specify/specs/*.md` as source artifacts under repository control.
2. Generate NAOS evidence, gate, conflict, task-claim, and dashboard reports.
3. Route unresolved gaps to control-plane review, known gaps, residual risks, or waivers.
4. Keep approval, legal/regulatory decisions, and release authorization outside the adapter.

Non-claims:

- No regulatory mapping completeness.
- No certification.
- No proof of compliance.
- No separation-of-duties satisfaction.
- No approval or release authorization.
- No official Spec-Kit or Microsoft endorsement.
