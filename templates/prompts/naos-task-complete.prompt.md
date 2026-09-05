# Complete Task — Native Lifecycle Transition

**Version**: 2.1.0
**Usage**: Record one exact task transition only after checking its declared evidence.

## Task

Complete exact registry task **{{input:task_id}}**. Plain IDs such as `T-202`
and namespaced IDs such as `LKB-T-202` are distinct; never shorten or infer an
ID from a substring.

## Evidence-first workflow

1. Inspect the exact record and its recovery state:

   ```bash
   naos task-lifecycle --task {{input:task_id}} --recovery-mode active
   ```

   An unknown task, unsupported legacy status, or active/completed recovery
   mismatch is a non-zero result. Stop and resolve it; do not create a
   replacement ID or silently map an unknown status to `planned`.

2. Re-read the active card, linked requirements, source changes, and tests.
   Check every acceptance criterion backwards from current repository evidence.
   Preserve failed, negative, partial, and inconclusive results. A checked box
   is a declaration by the editor, not proof.

3. Run the smallest relevant tests and governance checks. When applicable:

   ```bash
   naos spec-pack-contract
   naos spec-cascade
   naos module-headers
   naos ac-completion-evidence
   naos composed-traceability
   ```

   Reports are review evidence; they do not prove semantic correctness,
   sufficient coverage, compliance, or approval.

4. Preview the transition. Supply stable repository-relative references rather
   than prose-only completion claims:

   ```bash
   naos task-complete \
     --task {{input:task_id}} \
     --verification-state verified \
     --completion-provenance "Evidence reviewed against the active card" \
     --test-ref tests/path/to/test_file.py \
     --evidence-ref naos/reports/relevant_report.json \
     --decision-ref naos/human_decisions/DECISION-TASK-DELIVERY.yaml \
     --dry-run
   ```

   A verified request requires existing regular test, evidence, and decision
   files under the project root or configured NAOS root. The decision file
   must validate as `naos.human_decision_record.v1`, use
   `decision_type: task_delivery`, record `outcome: approved`, name the exact
   task in `subject_refs`, identify a non-placeholder `decided_by`, include
   time/rationale/scope, and link at least one supplied evidence artifact.
   Reviewer output, review readiness, agent output, generated reports, and
   experimental evaluator results are not task-delivery decisions.

5. If the preview is accurate, rerun without `--dry-run`. Invalid verified
   previews and executions both return non-zero without moving the card or
   changing registry/history. A valid native completion:

   - preserves the exact ID;
   - moves the active card to `naos/completed/`;
   - appends a structured record to `naos/completed_history.yaml`;
   - updates `TASK_REGISTRY.yaml` to the explicit lifecycle, delivery, and
     verification states;
   - records the active-card digest and supplied provenance; and
   - does not authorize merge, release, evidence admission, or an exception.

   Use `--verification-state verified` only when the prerequisite receipt is
   complete. The structural gate does not prove genuine review or semantic
   test sufficiency. An unverified or inconclusive completion is retained but
   is not counted as delivered and requires human review.

6. Recover and inspect the durable completed context:

   ```bash
   naos task-lifecycle --task {{input:task_id}} --recovery-mode completed
   naos task-context --task {{input:task_id}} --recovery-mode completed
   naos session-start --task {{input:task_id}} --recovery-mode completed
   ```

7. Refresh only the surfaces installed for the selected profile. In generated
   Quickstart projects, `gov-refresh` and `naos-readiness` explicitly report
   `not_applicable`; use `naos doctor` as the supported readiness alternative.
   In profiles that install derived governance workflows, run:

   ```bash
   make -f Makefile.naos gov-refresh
   make -f Makefile.naos naos-composed-traceability
   ```

8. Review the resulting diff and obtain an attributable human merge decision.
   Reviewer output may say `READY_FOR_ATTRIBUTABLE_HUMAN_MERGE_DECISION`; it is
   not merge approval. Commit only after the repository's named decision-maker
   accepts the change.

## Stop conditions

- The exact task is unknown or resolves only under the wrong recovery mode.
- The task contains an unsupported legacy status that has not been reconciled.
- Acceptance criteria lack implementation/test/evidence/decision references.
- Required tests failed or were not run.
- The proposed verification state overstates the observed evidence.
- A required human decision-maker is not identified.

For governance-surface changes, retain the canonical
`templates/skills/systemic-capability-wiring/SKILL.md` cross-surface checklist.
For bounded remediation and status classification, also follow
`templates/skills/systemic-wiring/SKILL.md` and record unresolved wiring gaps.
