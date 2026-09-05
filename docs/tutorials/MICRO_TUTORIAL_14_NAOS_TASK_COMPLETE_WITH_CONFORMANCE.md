# Micro Tutorial 14 — Native Task Completion and Conformance

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-07-17_

Lite, Standard, and Assured generate the `/naos-task-complete` prompt and the
native exact-ID lifecycle script. Lite does not generate the full conformance
agent; use the prompt plus CLI directly. Standard/Assured may add broader
conformance review, but that review still cannot approve merge or release.

## 1. Inspect the exact active task

```bash
naos task-lifecycle --task T-202 --recovery-mode active
```

`T-202` and a namespaced ID such as `LKB-T-202` are distinct. An unknown task,
unsupported legacy status, or recovery mismatch exits non-zero; do not shorten
or invent an ID, and do not treat an unknown status as an ordinary planned task.

## 2. Verify backwards from current evidence

- Re-read every acceptance criterion and preserve unchecked or inconclusive
  items.
- Run focused tests and the repository's canonical implementation-suite
  command.
- Record stable implementation, test, evidence, and human-decision references.
- Treat reviewer output as readiness for an attributable human decision, never
  as approval.

Where installed and applicable, run `naos ac-completion-evidence`,
`naos module-headers`, `naos spec-cascade`, and
`naos composed-traceability`. These are structural review inputs, not semantic
correctness or coverage proof.

## 3. Preview, then complete

```bash
naos task-complete \
  --task T-202 \
  --verification-state verified \
  --completion-provenance "Focused and full tests reviewed" \
  --implementation-ref src/auth/endpoint.py \
  --test-ref tests/test_auth.py \
  --evidence-ref naos/reports/auth-validation.json \
  --decision-ref naos/human_decisions/DECISION-202.yaml \
  --dry-run

# Re-run the same command without --dry-run after reviewing the preview.
```

Native completion atomically preserves the card content and digest, moves the
card from `naos/active/` to `naos/completed/`, appends
`naos/completed_history.yaml`, and updates `TASK_REGISTRY.yaml` with explicit
lifecycle, delivery, and verification states.

For `--verification-state verified`, all three supplied references must resolve
to existing regular files under the project root or configured NAOS root. The
decision YAML must validate against `naos.human_decision_record.v1` with
`decision_type: task_delivery`, `outcome: approved`, the exact task in
`subject_refs`, a non-placeholder decision-maker, timestamp, rationale,
authority scope, and a link to at least one supplied evidence artifact. A
reviewer report is not a substitute. Both an invalid dry run and an invalid
execution return non-zero with `mutated: false`.

Only `completed + delivered + verified` with a satisfied prerequisite receipt
counts as delivered. The validator establishes structural attribution, not
genuine human review or semantic test sufficiency. Legacy
`implemented` means implementation-complete but unverified. Deferred,
cancelled, absorbed, and superseded tasks are not delivered.

## 4. Recover completed context

```bash
naos task-lifecycle --task T-202 --recovery-mode completed
naos task-context --task T-202 --recovery-mode completed
naos session-start --task T-202 --recovery-mode completed
```

The structured history remains recoverable even if an archived Markdown card
is later unavailable. Completion never authorizes merge/release, admits
evidence, closes an exception, or represents human approval.

## 5. Refresh only applicable surfaces

```bash
make -f Makefile.naos gov-refresh
make -f Makefile.naos naos-composed-traceability
```

Use these targets only where installed. Quickstart explicitly reports
`gov-refresh` as `not_applicable` and routes readiness to `naos doctor`.

Finally review the diff. The task-delivery record remains separate from any
merge, release, or evidence-admission decision. Each authority requires its own
applicable decision type, scope, named human, time, evidence, and outcome.
