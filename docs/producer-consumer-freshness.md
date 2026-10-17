# Local producer and consumer freshness

Control-plane source reconciliation checks five optional families: failure-mode posture, failure-mode observations, OpenCode configuration hygiene, design traceability, and UI experience quality. An enabled source missing a report remains unresolved. A disabled absent source remains not applicable. Valid active reports are compared against a fresh read-only result from the trusted local producer, excluding the producer collection timestamp and operator attribution metadata. Stored producer outcomes, findings and provenance remain unchanged. Read-only reproduction disables provenance collection explicitly, so it does not invoke local Git or operating-system operator discovery. A mismatch creates unresolved stale evidence; malformed or unavailable current input remains unresolved.

This comparison establishes current deterministic producer semantics. It does not establish visual design quality, accessibility correctness, human approval, arbitrary referenced artifact byte freshness, external execution, provider readiness, or authenticity. The producer's own existing declaration digests and reference checks remain authoritative. No new opaque input hash is introduced.

Self-check and the installed generated CI runner schedule all five producers before control-plane reconciliation. Failure-mode observations follows the other four family producers; its existing configured cyclic-report exclusions remain unchanged. The full self-check dependency proof replays each added local producer and retains raw disabled and adverse outcomes. It does not substitute a successful status for historical producer failures.

Gate report evidence enforces the existing governed `evidence.default_staleness_days` policy through timezone-aware `generated_at`. A declared evidence requirement `freshness_window_days` overrides that default, including zero for no age ceiling. Missing, invalid, future or stale timestamps remain unresolved; filesystem modification time is not a report freshness source. Manual artifact contracts are unchanged. Generic `require_current_source` stays explicit and unresolved unless a supported current-source contract exists. Age is distinct from current producer semantic freshness.

Acceptance requires one affected native OS/Python group, combining five-family mutation and ordering tests, gate age tests, previous D03 complete40 regression selectors and affected full self-check dependency tests. An ordering test or prior substituted finite runner receipt does not establish complete generated runner acceptance; actual installed/generated full runner validation remains required before that clause can close.

Claims Validation now emits the existing controlled producer time as `generated_at`. Its schema permits that property without requiring it, preserving historical report schema compatibility. A historical Claims report without the timestamp remains unresolved under gate age checks; new valid regenerated reports can establish age. Claims was the sole existing schema in the finite shipped gate report registry without this property at the reviewed baseline.

Local file age is a separate, deliberately limited contract. Attestation artifact
freshness and function-index health now label their file-mtime basis and state
`source_freshness: not_established`. Equal bytes with a changed modification time
can change these local age or ordering results. A fresh clone therefore cannot
establish original evidence age or index/source equivalence. The gate retains
stale attestation and older-than-source index results as adverse; a clean local
age result alone cannot satisfy an explicit `require_current_source` requirement.
Regenerate reports and the function index in the receiving checkout when local
ordering is unresolved. Historical reports remain readable; report consumers
keep their schema, absolute project-root, profile, source and content checks.

The existing windows have different domains and boundary rules. This table
documents those rules; it does not reinterpret a configured zero across modules.

| Component | Time basis and stale boundary | Explicit zero |
| --- | --- | --- |
| Attestation artifact and session file | Local mtime; exact elapsed age greater than the window | Any positive elapsed age is stale; the exact boundary is fresh |
| Function-index health | Local mtime; exact elapsed age greater than `max_age_days`; source/index timestamp ordering is separate | Any positive index age is stale |
| Task context project artifact | Local mtime; completed elapsed days greater than the window | Stale after at least one completed day |
| Systemic artifact family | Local mtime; completed elapsed days greater than a positive window | Disables the family age check |
| Evidence pack file-age metadata | Local mtime; UTC calendar-day difference greater than a positive window | Disables the file-age check |
| Gate report generation age | Declared timezone-aware `generated_at`; exact elapsed age greater than a positive window | No age ceiling; invalid, missing or implausibly future timestamps still fail |

These rules apply on macOS, Ubuntu and Windows. They neither authenticate a
producer timestamp nor prove current source, human approval or portable
provenance. Content/source reconciliation and reviewer requirements remain
separate controls.
