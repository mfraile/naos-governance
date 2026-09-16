# Task and evidence contract corrections

These corrections tighten existing local validation boundaries. They preserve
the file-first installation model, profile warning/enforcement transitions,
maturity limits, and human ownership of durable decisions.

## Task identity and persisted decisions

Task-card ownership comes from the task's declared identity and supported file
naming convention. A related-task reference in prose does not make that card
the referenced task's owner. Context, completion, recovery, registry validation,
and synchronization reject ambiguous or inconsistent ownership before changing
delivery records. Keep duplicate cards and mismatched identifiers for review;
correct them explicitly before retrying the operation.

A completion preview checks its target's prerequisites. The actual transaction
also checks the existing task/history collection again before writing, so an
unrelated inconsistent history record can still prevent a previewed completion.
A preview is not proof that the later transaction can commit.

Composed traceability validates persisted decisions using the same structural
and attribution requirements as lifecycle admission, with the appropriate
decision type, task, evidence, and historical-record bindings. Editing a decision
to an invalid timestamp or placeholder reviewer creates a review gap. Reading
that report does not complete or reopen a task, authenticate a reviewer, or
promote a structurally visible chain into an approved delivery.

## Git snapshot and CI

The Standard and Assured pre-commit AC-reference check captures the index tree
and reads test and specification blobs by their Git object IDs. Unstaged edits
cannot repair or invalidate the bytes being committed. A staged specification
change rechecks indexed tests, including unchanged tests affected by criterion
removal or renaming. A relevant unreadable or unresolved index produces exit 2.
Projects with no authored acceptance criteria retain the onboarding no-op;
removing the final previously authored criterion is still a contract change.
When current definitions are empty, Git history distinguishes removal from
initial onboarding. The generated workflow fetches full history. A shallow
checkout with referenced tests and no definitions returns exit 2 if it cannot
establish that the project was never configured. Full validation includes
tracked recognized tests colocated outside the tests directory.

The generated Standard and Assured readiness workflow also runs the full check
on its checked-out commit:

```sh
python scripts/validators/validate_test_ac_references.py
```

The non-staged command reads its checkout. Run it on a clean reviewed commit
when using its result as commit evidence. Existing customized hooks and CI are
adopter-owned; review their upgrade diff and retain this invocation explicitly.

## Gate input scopes

Both gate CLIs validate the published gatekeeper manifest structure. All gate
identifiers must be unique. Every explicit `--gate` selector must resolve,
including selectors supplied together with valid IDs; supported lowercase
selector normalization remains available.

Malformed input, missing explicit manifests, and unknown selectors return exit
2. JSON mode and an explicit output file receive `naos.gate_input_error.v1`
with `status: invalid_input`, diagnostic errors, and a review obligation. Such a
report is an input failure, not a successful empty evaluation. PR summaries
retain this failure as a gate review gap, and structured findings propagate
to SARIF with the review obligation.

A schema-valid `gates: []` remains supported and reports
`evaluation_scope.status: empty`. A selected scope containing only disabled or
non-applicable gates reports `not_applicable`; other valid scopes report
`evaluated`. `--strict-required` still fails required-but-missing gates; it does
not invent required gates in an intentionally empty configuration. Self-check's
separate expected-roster contract continues to apply to generated projects.
An absent implicit manifest still uses the kit template.

## Attestation inputs, coverage, and repeated cycles

Signing and verification validate supported attestation reports before reading
their subjects. Reports distinguish input validity, artifact digest checks,
manifest-root verification, subject count, required coverage, producer status,
and empty/disabled scope. Supported rootless reports retain digest verification
without claiming manifest-root verification. Signature-entry presence remains
distinct from cryptographic signature validation; NAOS performs no signature
authentication in this workflow.

The attestation producer excludes its own configured report, the configured
envelope, and the configured verification report from the subjects they
describe. This mandatory runtime boundary also applies to preserved older
attestation rules. Independent required evidence, including an explicitly
required evidence-pack snapshot, is retained. The documented evidence-pack
snapshot boundary still requires deliberate generation ordering.

For repeatable custom locations, set the existing policy report/evidence
directories and these path keys before generating the attestation:

```yaml
paths:
  evidence_attestation_report: evidence_attestation.json
  evidence_envelope_report: evidence_envelope.json
  evidence_verification_report: evidence_verification.json
```

The envelope filename resolves beneath the configured evidence directory;
attestation and verification filenames resolve beneath the configured reports
directory. A one-off signing/verification `--output` cannot overwrite a subject
of the attestation being processed. Configure repeated-flow output locations
before attesting so a previous output cannot become a future subject.

## Fresh model reports and trace review states

Control-plane review validates model-policy and telemetry report structure,
profile and source bindings, and reconciles them with current source-derived
producer results. A new timestamp alone does not refresh stale evidence.
Malformed, incompatible or stale inputs produce explicit review reasons.
Self-check regenerates these producers before the consumer; standalone
control-plane review also protects its own input boundary. Optional or disabled
model use remains distinguishable from missing required evidence.

Trace validation and StaticGrader apply the canonical event schema to current
events. A cached report cannot preserve a perfect schema grade for malformed
current trace data. A recorded review obligation is distinct from completed
approval: imported pending-review records can remain structurally reviewable,
with their review obligation visible. Action receipts that require approval
must separately record an approved state. Neither a review flag nor a declared
approved receipt authenticates a human or proves that an action was authorized.

## Existing projects and verification

Use the documented content-aware upgrade: create a plan outside the project,
review its changes and preservation findings, then apply that exact plan with
its digest. See [the installation manual](../INSTALLATION_MANUAL.md).
Modified or adopter-owned configuration is preserved, so review manual-action
findings for hooks, workflows, schemas, and locally modified scripts.

The distribution includes offline behavioral regressions under `public_tests/`.
Install the declared dependencies and run:

```sh
python -B -m unittest discover -s public_tests -p 'test_*.py'
```

Tests construct disposable projects, synthetic review declarations and local
Git repositories. They do not contact model providers, authenticate reviewers,
publish repositories, or establish general runtime safety or standards
compliance.
