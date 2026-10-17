# ADR-0011: Deterministic Hygiene Controls

**Status**: Accepted
**Date**: 2026-06-07
**Scope**: Duplicate-function, secret, test-quality, dependency-integrity, package-reality, API-symbol reality, spec-pack, spec-cascade, and PR-risk deterministic controls

## Context

The Superpowers/OpenSpec forensic review exposed a recurring NAOS risk: several
important claims were true only for specific deterministic surfaces, while other
risk classes required future semantic or model-backed review. NAOS needs hygiene
controls that are useful today without overstating what static checks can prove.

## Decision

NAOS keeps deterministic hygiene controls as file-first review evidence:

- duplicate-function hygiene detects normalized duplicate function bodies;
- secret hygiene detects obvious secret-like literals and high-entropy strings;
- test-quality hygiene detects missing or trivial assertions;
- dependency-integrity detects undeclared or unresolved imports;
- package-reality reviews package names, lock-style pins, optional docs install
  snippets, configured local CycloneDX SBOM/provenance/hash evidence, and
  explicit opt-in registry metadata;
- API-symbol reality checks explicitly declared Python symbols through local
  source inspection without importing target modules;
- spec-pack contract detects template/file/anchor/marker contract drift;
- spec-cascade coherence detects requirement/task/source cascade gaps;
- PR-risk classification detects path, diff, workflow, dependency, AI-surface,
  and contributor-risk indicators.

These controls are wired through reports, policy paths, Make/CLI surfaces,
evidence packs, dashboards, gates, SARIF export where applicable, and tests.

## Boundaries

The controls do not prove:

- semantic correctness;
- absence of all duplicate behavior;
- absence of all secrets;
- API behavior, option compatibility, or endpoint behavior;
- package safety or supply-chain integrity;
- behavioral correctness;
- PR approval, release authorization, certification, or legal/regulatory compliance.

When a control reports a finding, the finding is a review input. When a control
does not report a finding, that is not a proof of safety.

## Secret scan scope and waivers

Secret hygiene uses finite configured roots and case-insensitive suffixes,
including dotenv names and common extensionless private-key filenames. Adopter
selection overrides remain authoritative. `coverage_status: complete` describes
successful reads of selected files only. Reports show immediate root entries and
selected-root leaves: unselected directories are entry counts, and unselected or
excluded file counts cover discovered leaves only. They are not repository-wide
file totals. Unreadable, undecodable and selected symlink files remain unanalyzed
and make selected coverage incomplete.

A bounded reporting-only exception recognizes a direct root `AGENTS.md`,
`CLAUDE.md` or `GEMINI.md` symlink to another selected regular root instruction
file that was successfully scanned. No alias content or outside target is opened;
no `resolve()` follows a link. Link text, link metadata, root identity and target
metadata must remain stable at terminal observation. Windows requires an actual
symbolic link with the exact symbolic-link reparse tag; junctions and unknown
reparse types remain refused. Stale, unselected, chained, unread or observed
changed aliases retain profile severity. The advisory alias row carries the
already-scanned target path and digest; `files_scanned` counts actual reads and
`instruction_aliases` counts aliases. This does not add ownership or mutation
approval policy to the existing regular-file scan. Endpoint checks do not prove
continuous namespace custody or held-handle transactional safety.

Hygiene report paths use forward-slash separators on every platform; literal
backslashes in POSIX filenames remain filename characters.

The existing trailing `# naos: allow-secret` or `// naos: allow-secret` comment
waives assignment and entropy findings on that line only. The entire first
unquoted comment must equal the marker; nested comment delimiters, quoted markers
and arbitrary substrings do not waive anything. Escaped characters and paired
single/double/backtick literals are skipped when locating that first comment. Credential-prefix and private-key
patterns remain enforced. Every recognized comment produces an advisory finding
and a waiver entry with path, line and suppressed counts by rule, including
zero-match comments; values and comment content are never copied into evidence.
This narrows the former blanket suppression and requires review of existing
comments when upgrading. Rules and fallback defaults ship with no entropy literal exemptions. Public kit
identifiers remain subject to the separate digest-bound declaration mechanism;
no literal prefix, source path or filename grants an exemption.

Project coherence uses the same credential-pattern and filename contract,
including application `data/` files. It does not apply entropy detection or inline
waivers. Exact private kit fixture exceptions remain separate from adopter rules.

## Managed inventory operand classification

Secret hygiene recognizes exact independently derived managed metadata operands
only at JSON string value coordinates in `scans.input_files[*].path`,
`scans.scope_inventory[*].path`, `scans.unassessed_suffix_files[*]`, and
`scans.inventory_operand_proofs[*].path`. Diagnostic rows qualify only with
the exact producer fields `path`, `status`, `matches` and `proof_bytes`, a
`proved` status and bounded integer counters. These fields select a coordinate;
the existing complete committed-chain and raw-base proof independently
establishes operand membership. Refused, partial or malformed diagnostic rows
grant no allowance and do not change the treatment of the other inventory arrays.
The secret report envelope must bind the observed project and NAOS roots.
The same bounded coordinates may occur inside the exact evidence-pack artifact
and dashboard input carriers emitted by the current producers. Unknown fields,
findings paths, messages, neighboring values and identical body strings retain
ordinary detection. Exact raw managed manifest, receipt and journal control-ID
slots also qualify only after the complete committed-chain constructor proof,
including raw bases, and byte equality between scanned text and the proof read.
Legacy v1/v2 admits last/transaction/introduced/last-mutated IDs at their exact
manifest roles and root transaction IDs in the linked receipt and journal.
Windows v1/v2 admits exact transaction IDs in manifest receipt references,
linked receipts and bases, plus operation/transaction IDs in linked plan and
intent control slots. A single committed v2 new enrollment also admits exact
path coordinates after reconstructing its create-only content and evidence
publication sequence and complete staging-slot dictionary. Unsupported update,
history, v1 and custom-policy variants retain identifier admission without this
additional path allowance. Declared public paths include native relative
representations; arbitrary session namespaces remain outside that declaration.
For this single NEW enrollment, an identity matching `WIN-` plus 16 lowercase
hex digits qualifies only at the five linked project-ID values in root, owner,
manifest, receipt and nested plan, with both predecessor digests absent. The
linked directory journal's operation ID qualifies only after its envelope,
intent digest and saved-plan directory witnesses agree under the same NEW
condition. These six coordinate slots use the existing representation limit;
a refused optional directory addition preserves already proved coordinates.
Neither classification authenticates random generation. Other body values and
credential patterns retain their ordinary checks; rollback cleanup labels are
outside this single committed NEW contract.
The same single committed v2 enrollment derives inventory-only membership for
the contiguous forward markers, linked directory journal, and fixed runtime
directory, template, lock and staging roles. Pure saved-plan scope and witness
checks agree with the producer without importing native operation code.
Every forward marker binds the actual intent digest, direction and ordinal.
Invalid witnesses, missing markers or a combined old/new operand set exceeding
16,384 refuse only the additional membership. Existing proved operands survive;
ordinary body values do not gain exceptions. Selected schema-validated ordinal
task references also include the native relative spelling of their exact paths.
IDs in payloads, nested inputs or other files stay scanned;
portable sequential receipt IDs receive no new exception. These local
consistency proofs establish no ownership or authenticity. Assignment and
provider checks still scan the original text.

A `scope_inventory` row with exactly `path` and `status: directory` also
qualifies when its path is a proper native parent of a constructor-proved file.
The parent must come from that file's cached, contained, non-link and non-reparse
ancestry, and pass the existing identity/security observations and final scan
checkpoint. Directory existence, a claimed status, or a managed-path prefix
alone grants no allowance. The cumulative identity limit still applies. This
prevents repeated scans from flagging their own proved directory inventory;
identical strings in configured roots, unknown bodies and findings stay scanned.
The same proof boundary applies on macOS, Ubuntu and Windows; it establishes
local consistency rather than ownership or authorization.

Repository-intelligence labels use the same entropy-only coordinate boundary.
POSIX control records require the linked owner/scope and complete active,
generation, validation, activation and journal records; source/reference node
labels also require matching raw source bytes and independently rederived links.
Windows supports one committed genesis activation through a separate pure parser
for enrollment, bootstrap, preparation, publication and all forward checkpoints.
Only after that complete proof are exact bootstrap directory/file map keys and
preparation/saved-plan directory map keys admitted as entropy-only operands.
The offset parser keeps key and value coordinates distinct and charges captured
keys to the existing node budget. Whole-object duplicate-key refusal and
credential-pattern checks remain active; no arbitrary key or body allowance
is introduced.
That complete constructor also derives exact runtime paths for the four scanner
inventory metadata arrays. The finite set includes observed runtime directories,
guarded empty templates and operation lock, preparation and receipt records,
committed marker and all linked forward checkpoints. Namespace matching routes
candidates only; independent complete-chain membership and current custody grant
the entropy allowance. The same final checkpoint rechecks directory memberships
and raw preimages. Arbitrary finding bodies and credential patterns remain
subject to ordinary detection.
Refresh, rollback, mixed and unknown Windows histories remain unsupported.
Schema reads share the existing cumulative file-read budget. Required directory
membership is enumerated with a context-managed streaming reader, capped before
accumulation and rechecked at final admission. No native operation backend is
imported and these checks establish neither native ownership nor authorization.

CI readiness finalization for Lite, Standard and Assured refreshes the stored
gate-status and gate-evaluate reports after the final self-check producer pass,
then verifies the independently published dependency-resolution proof. Original
acquisition failures remain recorded. Required gate gaps, unchanged invalidated
outputs and missing resolution proof still refuse completion; Assured retains
its existing stricter selected-gate requirements.

The new managed proof domain permits at most 32MiB of cumulative unique contained
file reads, with sizes conservatively reserved before unbuffered reads and
refused attempts remaining charged. Stable reads are cached with before/after
observations; stable cache reuse is uncharged. Parent directory device, inode,
mode, available UID/GID and Windows attributes are re-observed, with directory,
no-link and no-reparse checks on every observation. Directory entry changes
(size and timestamps) are allowed; full leaf-file observations remain unchanged.
These endpoint checks do not establish a continuous namespace lock or native
custody guarantee. Cache reuse compares endpoint metadata without rereading
content. A same-length rewrite can leave every observed field unchanged, so
unchanged observations do not establish unchanged current bytes. Reads never
request a growth sentinel beyond the reserved size. The domain has an 8MiB per-file limit,
16,384 derived operands, and depth 64. Whole JSON syntax is validated, including
duplicate keys and nonfinite-number refusal; only the four metadata subtrees and optional exact raw control-ID slots
share the new 50,000-node budget. Existing collectors retain their own unchanged
limits. Proof-only reads never increase selected-file scan coverage.

Within one secret scan, raw control-record allowances remain provisional until
a terminal sweep re-observes every cached proof input before findings receive
IDs or a report is returned to the writer. Constructor checkpoints and individual
reads retain their checks; direct helper callers still sweep before each control
admission. Only the scanner's repeated control-admission sweeps are batched.
An observed cached-input refusal invalidates that scan permanently, even if the
input is subsequently restored. Terminal refusal produces no new report and
leaves an existing output untouched. Batching changes observation timing: a
transient change restored between retained checkpoints may escape detection.
It does not provide continuous custody or unchanged-byte assurance.

Legacy v1/v2 label derivation binds exact scope, manifest, plan, journal and
committed receipt hashes; base paths also require raw bytes matching their linked
SHA-256 digest and size. Windows-v1 label derivation additionally binds complete
retained WOP/WMC operation records. Portable-v3 derivation supports linked
new-enrollment receipts, policy/mode records and prior manifest heads; portable
legacy-authority variants remain unsupported. These are constructor consistency
proofs, never authenticity, authorization, ownership or secret-free claims.
Exact `rfc8785==0.1.4` distribution/module binding is loaded lazily. Missing, wrong
or shadowed dependencies refuse managed allowances while ordinary scanning
continues. Diagnostics and an entropy-only occurrence counter are additive report
fields; the report schema version remains v1.

## Consequences

Deterministic controls are appropriate for default and CI-friendly governance
because they are inspectable, reproducible, local, and cheap. Harder semantic
or behavioral judgments remain future/project-configured advisory layers unless
an adopter explicitly wires a judge, records residual risk, and keeps human
approval boundaries intact under `ADR-0010: Control-Plane Advisory Boundaries`.

This ADR also records the CI hygiene rule for tests that create temporary git
repositories: fixture commits should pass `--no-gpg-sign` so local or sandbox
commit-signing policies do not mask the behavior under test.

Task-claim IDs receive entropy-only classification at finite `claim_id` scalar
coordinates in selected default root/session claim reports and the current
evidence-pack/dashboard carriers. The selected contained `task_claims.yaml`
defining registry and reports must validate against exact shipped schemas.
Task/time fragments must match the public constructor and the suffix must be
exactly 12 lowercase hexadecimal characters; references must match the known
ID and its defining task, timestamp and claim source. The random nonce is not
recomputed. This establishes label-form consistency, never producer authenticity,
ownership, approval or evidence verification. Identical neighboring values,
unknown fields and provider/assignment checks retain ordinary detection.
The defining registry keeps the existing 1MiB/50,000-node/depth-64 reference
bounds; selected JSON carriers retain 8MiB/50,000-node/depth-64 bounds and the
claim proof cache uses the existing 32MiB conservative read domain.
Only the finite root and single-session carrier paths enter the claim proof
read domain; unrelated selected files retain ordinary scanning without charging
that domain. Parsed schema, root, session and registry bindings still apply.

Selected canonical producer witnesses provide a bounded source of references
when unrelated report copies exhaust the generic context collectors. Only
selected self-check and classification reports under the supplied NAOS root,
and single-event JSONL audit files under its declared fallback audit root,
enter this projection. Complete existing vector and event constructors prove
the exact labels; audit files must occupy their recomputed filenames. Source
reads share the existing 32MiB proof budget and final scanner checkpoint. The
projection keeps finite count, value and byte limits; generic collectors retain
their existing exhaustion refusal. This proves structural consistency, not
producer authenticity. Ordinary bodies, unknown references, assignments and
provider keys retain detection.


Dependency and duplicate checks default to `scan_roots: inferred`: flat Python
files, top-level Python packages, and common adopter roots (`src`, `app`, `apps`,
`packages`, `services`, `lib`, `libs`, `cmd`, `tests`). The local context source/test
metadata families share this inference and retain Python symbol summaries rather
than full raw code. Generated `scripts/` is not inferred merely because it exists;
an explicit selector or real top-level package can select it.

Explicit root lists remain authoritative. Omitted inferred Python inputs and
discovery/parse failures remain visible and adverse under required Assured policy.
Inference is bounded and prunes vendor/private exclusions; it does not establish
whole-repository coverage, arbitrary layout completeness or non-Python semantics.

Concrete pyproject package roots are also inferred from setuptools package-dir
and find.where, Poetry include/from entries, and Hatch wheel.packages. Unsafe or malformed roots remain adverse declarations. Valid broad `.` discovery
without exact package names is explicitly unassessed; exact finder include names
or named package-dir root mappings select only listed packages/root modules,
never arbitrary generated scripts.
this bounded static support does not establish runtime import resolution.
Non-Python implementation context uses path/suffix/size/hash metadata only.
Source bytes are checked for secret patterns before admission but are never
persisted as non-Python excerpts or raw bodies. Repository intelligence keeps
private snapshots for integrity checks and skips body relationship extraction
for this family; no language semantics are claimed.


Test-quality evidence uses a bounded Python structural predicate: skipped/xfail,
literal-trivial, visibly dead and possibly swallowed assertions do not by
themselves establish effective assertion evidence. Conditional early returns are
advisory review signals; a separate live assertion remains potentially useful.
Expected-exception contexts, assertion helpers and parameterized assertions retain
recognition. Neither a recognized assertion nor a clean report establishes that a
test executed or checked the right behavior. Existing approved native skips may
remain justified; static syntax cannot approve them or prove malicious intent.

Configured `non_python_test_globs` within `scan_roots` support supplementary
JS/TS disable calls, Java Disabled/Ignore annotations and C# Ignore/Skip markers.
Common quoted strings and comments are masked, UTF-8/CRLF is normalized and reads
are bounded to 2 MiB per file. Unsupported syntax, assertion quality and execution
remain unassessed. Non-Python inputs therefore keep assertion coverage incomplete,
even when marker scanning succeeds. An empty glob list disables this supplement.

Duplicate-function hygiene retains the original identifier-sensitive exact-AST
hashes and now groups multiple locations within one file. A separate advisory
`renamed_identifier_duplicate` tier normalizes local/argument bindings, including
comprehension target scope, while preserving external names, attributes, imports,
defaults, annotations and literals. `allowed_hashes` still waives exact hashes;
`allowed_renamed_hashes` independently waives renamed-tier hashes. Nested definitions,
lambdas, assignment expressions, pattern matching and direct dynamic-local inspection
remain unassessed by the renamed tier. Parameter names can be public keyword APIs;
these matches require review and do not establish semantic equivalence.
