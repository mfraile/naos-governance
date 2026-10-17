# Basic Spec-Kit To NAOS Mapping Example

This example shows a small, non-regulated mapping from `specs/<feature>/spec.md` files
to NAOS review evidence.

| Spec-Kit artifact | NAOS concept | Suggested NAOS action |
| --- | --- | --- |
| `specs/001-user-profile/spec.md` | Source artifact for task context | Run `naos task-context --task T-123 --profile lite` after linking the task to the spec. |
| `specs/001-user-profile/spec.md` | Evidence source | Include the spec path in an evidence pack or reviewer notes. |
| `specs/002-api-contract/spec.md` | Gate input | Run `naos gate-status --profile lite` and review missing evidence. |
| `specs/002-api-contract/spec.md` | Control-plane review candidate | Add a control-plane review item if the spec changes governance surfaces. |

Recommended flow:

1. Keep the spec as the source artifact.
2. Use NAOS reports as review evidence.
3. Record task coordination with `naos task-claim --task T-123`.
4. Review `naos/reports/pr_governance_summary.json` in PR workflows when CI is configured.

Non-claims:

- The mapping does not approve the spec.
- The mapping does not prove implementation correctness.
- The mapping does not prove compliance.
- The mapping does not replace human review.
