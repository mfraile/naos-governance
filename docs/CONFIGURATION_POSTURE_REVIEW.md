# Declared review of configuration-only context posture

An adopter may record an explicit human review of three exact evidence identities:
`semantic_candidate_layer`, `graph_context_readiness`, and `local_context_index`.
The record is an additive `configuration_posture_reviews` array in the policy-selected
`evidence_review_attestations` YAML document. Ordinary `attestations` entries retain
their existing normalization and meaning. An absent array retains the previous
consumer behavior; a clean report or zero findings does not create review approval.

Each array entry must satisfy `schemas/naos/configuration_posture_review.schema.json`.
It declares an exact project root, NAOS root and profile, a nonblank reviewer identifier,
UTC review timestamp, rationale, and `reviewed_configuration_only` outcome. The
consumer records that declaration as metadata. It does not authenticate the reviewer,
prove that a human performed the review, or grant implementation, provider, memory,
release or runtime authority. Test-fixture reviewer declarations are not human approval.

The human reviews a separate immutable subject snapshot and nonempty local evidence
notes. The entry binds their exact bytes, the selected generating rules bytes, selected
policy bytes (or the existing unlocated-policy null marker), effective policy, and exact
current posture subject. Source/rules/policy or subject changes invalidate the matching
review. All review files must be local regular files with canonical relative references;
linked paths and aliases with selected source, record, reviewed canonical outputs,
aggregate output, snapshot or other review evidence are refused. Duplicate record
keys, duplicate scoped review identities, malformed entries and missing fields fail
closed. The record must remain outside the report being reviewed.

The existing public gate commands emit `configuration_posture_review_subject` in the
evidence result for a valid supported posture, including before review is recorded.
This deterministic metadata contains `scope`, `binding`, the exact `subject` object,
and `finding_bindings`. It contains no reviewer, review timestamp, review outcome or
approval. Save its `subject` as a separate immutable JSON snapshot and hash the saved
bytes; after explicit review, author the typed entry with that snapshot reference,
nonempty evidence-note hashes, and the exact declared finding acknowledgments.
The emitted gate requirement remains unresolved until a valid declaration is present.

`posture_subject(report, report_key, scope, generating_rules)` computes the reviewable
subject. Its canonical JSON SHA-256 is computed by `_digest`; the immutable snapshot
stores that object, and its separate byte SHA-256 binds the exact saved snapshot.
A maintainer may prepare these subjects and hash inventories for inspection. Reviewer
identity, timestamp, rationale, outcome and acknowledgments must be authored as an
explicit declaration after review; preparing a subject never creates approval.

Semantic and graph subjects bind all current report fields except `generated_at`.
Their profile posture must remain `readiness_only`; every supported runtime, graph
engine, vector, embedding, native extension and external embedding call flag must be
explicitly disabled in report and current rules. A new timestamp alone does not require
a new review. Missing/invalid/future timestamps and any enforced generation-age limit
remain independent consumer checks.

Local-index review covers deferred configuration and these named informational notices:

- `local_context_index.sensitive_paths_excluded`
- `sqlite_write_coordination.distributed_lock_not_provided`
- `sqlite_write_coordination.session_metadata_unavailable`

Every observed notice must appear exactly once in `acknowledged_findings`, in report
order, with a digest of the full finding object. Changed notice text/fields require a new
review. Unknown notices, adverse findings, inconsistent counts, and observed stale or
unknown indexed freshness cannot be reviewed closed. Local-index source contents,
chunks and source correctness are outside this review subject: arbitrary indexed-source
edits do not alone invalidate this configuration review. The producer's independent
index/source/freshness checks remain necessary, and `require_current_source` remains
unresolved by this contract. There is no source-correctness approval or provider enablement.

Gate, maturity and pack consumers retain raw producer status, findings, claim ceiling
and the human-review flag. An accepted exact declaration changes only the bounded
requirement disposition and adds declared-review metadata. A required/blocking/error
finding, stale or malformed artifact, wrong scope, missing human/evidence field,
unknown advisory or active runtime attempt remains unresolved.

A stored self-check can use the same declarations only for the exact nested producer
IDs `naos_semantic_candidate_readiness`, `naos_graph_context_readiness`, and
`naos_local_context_index`. Each nested status, summary, findings and explicit zero
return code must match the current canonical policy-selected producer report. That
report is classified and byte-checked against the recorded review. Aggregate counts
and status must equal the actual nested observations; duplicate identities, other
unclean checks and unexplained findings remain unresolved. The consumer preserves the
stored aggregate and all nested evidence, and records its scoped review decisions in
`configuration_posture_review_checks`. Three existing descriptors also support exact
nested memory observations: `memory_context_readiness`, `memory_provider_access`, and
`memory_use_policy`. The public gate caller passes the actual validated gate's declared
requirements for their canonical references; the consumer does not inherit a parent's
optional flag or hardcode optionality for other consumers. Disabled applicability is
accepted only when the existing classifier establishes current local disabled memory
configuration. An unregistered status, any unknown/advisory memory finding, malformed
or nonzero finding counter or changed canonical observation remains unresolved.
A disabled receipt cannot be excused under an explicit nonoptional requirement. `self_check_descriptor_checks` records the gate ID,
actual declared requirement and unchanged descriptor result. These memory decisions
are structural/applicability observations, never recorded human review or memory-access
proof. No memory/provider runtime is enabled. This is stored evidence consumption, not a
new self-check execution or a freshness guarantee for unrelated sources.

The focused tests use visibly labeled fixture declarations and a bounded aggregate
constructed by the actual self-check aggregation function. They author a fixture declaration from emitted public gate metadata and exercise gate
consumption, the aggregate boundary and output-schema validation. Complete installed workflow qualification
still requires actual installed producer/self-check operation under the adopter's policy.

## Exact budget-warning tradeoff review

An owner may declare `ai_surface_context_budget` with
`review_outcome: reviewed_budget_warnings_only` in the same typed
`configuration_posture_reviews` record. This acknowledges the measured warning
tradeoff; it does not change thresholds, approve a baseline automatically, rewrite
the producer, remove findings, or change its `--strict` exit behavior.

The review subject binds the actual measured file bytes and inventory, current
rules and policy, and the selected existing baseline. The consumer reproduces the
current deterministic report before offering a subject. Only named
`AI_SURFACE_FILE_BUDGET_WARNING` occurrences strictly below every configured hard
block limit can be acknowledged. Each acknowledgment includes `id`, `source`, and
`sha256`; warnings with the same ID on different paths require separate entries.
The entire exact occurrence list must match, including repeated occurrences when
declared families overlap on the same file. Both warning and block thresholds
must remain positive and ordered; disabled thresholds are not reviewable.

Missing baselines, changed or unsafe source files, stale declared freshness,
unknown or malformed findings, anchor failure, hard exceedances, baseline drift,
and unrelated nested checks remain unresolved. Snapshots and nonempty review notes
must be independent of the measured sources, selected baseline, rules, policy and
mutable output. Human identity and actual review are declared, not authenticated.
Synthetic test declarations never establish real adopter approval.

A self-check consumer may consume only the same reviewed canonical budget
observation with matching status, summary and findings. Raw nested warnings stay
visible; the consumer records the exact review and preserves other failures.

Explicit dependency acquisition may advance one additional raw diagnostic: the
exact policy-selected `ai-surface-budget` invocation returning 1 with a current
recorded `reviewed_budget_warnings_only` declaration. The invocation must publish
changed regular canonical output bytes. Before launch, guarded reads and exact
selected-policy comparison refuse aliases to policy, rules, baseline, measured
sources, review witnesses and other outputs. The policy path, bytes and effective
values must remain unchanged through production and classification. Existing
classification must reproduce
those same bytes and exact measured review subject. Missing, unchanged, unsafe or
invalid output, unrecorded/adverse review and every other independent failure refuse.
The receipt retains raw exit 1, warnings and failed acquisition status, and records
a bounded acquisition disposition; every final command, gate and complete current
dependency proof remains required. This does not alter strict exits, thresholds,
ordinary self-check consumption, or authenticate a reviewer. Synthetic test
declarations remain test fixtures, never genuine human approval.
