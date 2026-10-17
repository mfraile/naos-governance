# Claims And Limitations

**Status**: Public claim-control policy
**Audience**: Maintainers, adopters, reviewers, and documentation contributors

NAOS documentation and dashboards must describe evidence under scope, profile, project maturity, toolchain context, evidence freshness, and revalidation triggers. Dogfood, pilot, reference implementation, research framework, model, IDE, or toolchain results are bounded evidence, not universal proof.

## Public-Safe Baseline

Use this wording when describing the control plane:

> NAOS ships a portable, file-first capability-contract framework for SDLC governance. It does not ship runtime governance, semantic/model-backed behavioral grading, or compliance certification. Projects activate and mature capabilities progressively through profiles, readiness gates, and evidence.

Do not imply that `naos init` makes every project fully governed immediately.

Use `assured` only as a profile name or maturity label. It means the project is configured for stronger evidence expectations and blocking behavior where implemented; it is not a promise of legal, regulatory, runtime, or security assurance.

## What NAOS Does

- Structures AI-assisted SDLC governance with file-first artifacts.
- Preserves the existing commands, prompts, agents, skills, workflows, task registry, memory flow, function index, readiness checks, and conformance checks.
- Provides profile-aware policy, validators, gatekeepers, evidence-pack export, and dashboard summaries.
- Supports review, governance traceability, admissibility discussions, and residual-risk review.

## What NAOS Does Not Do

- It does not prove legal or regulatory compliance.
- It does not certify secure code.
- It does not replace human review, accountable owners, or legal/audit judgement.
- It does not prove runtime safety.
- It does not prove complete test coverage unless source-specific evidence supports that claim.
- It does not prove semantic correctness, secret-free code, behavioral correctness, or package supply-chain safety from deterministic hygiene checks alone.
- It does not make every AI tool behave identically.
- It does not make Tier 3/experimental capabilities production-ready by default.
- It does not make control-plane self-review, spec-readiness review, research routing, or gate convergence fully automated unless an implemented validator/gate exists in the project.
- It does not make learning candidates or memory records authoritative without explicit evidence, scope, review, approval, and freshness/expiry metadata.

## Claims File Model

Claims validation is generic at kit level and project-local at adopter level.

The kit provides:

- schemas;
- categories;
- validators;
- safe wording;
- lifecycle rules;
- external-reference defaults.

The adopting project provides:

- actual claims;
- evidence;
- scope;
- toolchain context;
- validity period;
- owners;
- revalidation triggers.

## Supported Claim Statuses

The default policy supports these statuses:

- `candidate`
- `supported`
- `unsupported`
- `expired`
- `experimental`
- `needs_revalidation`

`supported` requires supporting evidence. An external URL, URI or identifier is
reference context even when its evidence object contains `verified: true`;
that declaration does not establish that NAOS checked the linked content.
Supply a regular project-local evidence artifact using a project-relative path
with forward slashes, such as `evidence/review.md`. Absolute paths, backslashes,
parent traversal, directories and symlink/reparse components are rejected.
Those checks establish reference availability and safety, not the
truth of a claim, evidence sufficiency or an authenticated human review.

## Revalidation Triggers

Claims may drift when any of these change:

- LLM/model version;
- IDE or agent tooling;
- profile or gatekeeper configuration;
- validator logic;
- repository architecture;
- dependencies;
- release boundary;
- evidence freshness;
- project scope.

The default policy names these as machine-readable triggers:

```text
model_version_change
ide_agent_change
profile_change
validator_change
repository_architecture_change
dependency_change
release_boundary
evidence_stale
project_scope_change
```

## Overclaim Controls

Do not publish claims that state or imply:

- claims of proving legal or regulatory compliance;
- runtime-safety proof;
- complete source-level test coverage without source-specific evidence;
- secret-free code, complete duplicate elimination, package safety, or behavioral correctness from deterministic hygiene reports alone;
- neuroscience validation;
- PETRI or runtime governance is fully implemented when it is only referenced, scaffolded, or inspirational;
- outcomes generalized from a single project, toolchain, model, IDE, or reference implementation.

Safe disclaimers are allowed and encouraged, for example:

- "does not prove legal or regulatory compliance";
- "does not prove runtime safety";
- "bounded evidence";
- "unless source-specific evidence supports it";
- "experimental/advisory unless configured and matured by the project".

## Professional Adoption Engine Claim Boundary

`naos adopt` and its supporting reports may claim that NAOS inspected local files, generated deterministic review evidence, preserved unknowns, and recorded human decision needs. They may not claim that adoption is complete, that the project is mature, that candidate requirements are authoritative, that candidate NFRs prove security/runtime safety/compliance, that memory/MCP context is trusted, that secure code was produced, or that legal/regulatory obligations are satisfied.

`naos mcp-resource-inventory` may claim that sanitized repo-local declaration
metadata matched, or did not match, an exact risk-owner policy tuple and pinned
policy digest. `allowlisted_pending_activation` is not an "authorized MCP"
claim: it does not verify the remote server identity, implementation, tool
list, safety, authentication, permissions, or behavior; configure or activate
a client; invoke a tool; or grant read/write authority. The shipped Figma rule
is limited to the recorded repo-local remote VS Code workspace declaration
subset. Other client
shapes, the desktop endpoint, and drift remain review-required.

Every user-facing adoption claim should map to a concrete command, report, schema, configuration file, generated artifact, test, or documented human decision boundary. A documented capability without source dispatch, report output, schema rationale, and tests is a ghost capability and must not be presented as complete.

`naos repository-intelligence` may claim source-bound deterministic inventory,
SQLite/FTS indexing, immutable digest-confirmed generation activation,
validation, and bounded exact/FTS query candidates. When the executed graph
eligibility checks pass and the exact optional dependency is present, it may
also claim a derived NetworkX/GraphML relationship lane. It may not claim
source authority, complete recall, semantic correctness, automatic context
injection, sqlite-vec/vector operation, approval, maturity, or that graph
navigation improved onboarding without comparative evidence.

Brownfield `naos init --activate` may claim one managed create-only transaction
created the exact receipt-bound scaffold, including the profile-required spec
pack, task registry, dashboard seed, rules, and provenance. It may not claim
that generated seeds are project-specific, that adoption reports activated the
scaffold, or that candidate requirements were promoted. For a valid already
managed project, NAOS may claim a profile transition only when an immutable
content-aware plan was separately applied with its exact supplied SHA-256
digest after provenance, source, topology, and current-state revalidation. Only
unchanged `kit_owned_derived` regular files are eligible; adopter-owned,
modified, ambiguous, unsafe, and out-of-scope content remains preserved. This
workflow does not authenticate a reviewer, isolate hostile validators, or prove
network denial. The bounded
`scripts/`-to-`naos_tools/` adapter may claim only the observed configured
pytest/recursive-host-test collision it rewrote before plan freeze. Managed
nested `.ruff.toml` markers may claim only that conventional, detected
repository-root Ruff discovery skips generated Python roots proved to contain
no pre-existing adopter Python. The `naos_tools/` marker is kit-owned and the
`.github/autoresearch/` marker is a create-once adopter-owned seed; neither
modifies a pre-existing adopter Ruff file. They do not claim protection from
later manual Python inside a reserved excluded root, explicit-file arguments,
`--config`, `--isolated`, aliases, wrappers, other lint engines, or mixed
adopter/generated Python roots; detected unsupported or mixed-root postures
refuse activation.

## Deterministic Hygiene Claim Boundary

`naos duplicate-function-hygiene`, `naos secret-hygiene`, `naos test-quality-hygiene`, `naos dependency-integrity`, `naos package-reality`, and `naos api-symbol-reality` may claim that NAOS inspected configured local files and produced deterministic review findings for normalized duplicate function bodies, obvious secret-like patterns, missing/trivial assertion evidence, undeclared/unresolved imports, package names, lock-style pins, optional docs install snippets, configured local CycloneDX SBOM/provenance/hash evidence, explicit opt-in registry metadata, and explicitly declared Python API symbols. They may not claim semantic correctness, behavioral correctness, API behavior, option compatibility, endpoint behavior, secret-free code, complete duplicate elimination, package safety, malware detection, vulnerability absence, SBOM completeness, provenance authenticity, supply-chain assurance, registry trust, approval, certification, proof of compliance, or runtime safety. Human review remains required for disposition, waivers, rotation decisions, dependency decisions, package suitability, API-symbol suitability, and test sufficiency.

Package-reality pin detection ignores comparisons after the requirement marker separator (`;`). It retains the existing lock-style treatment of equality specifiers and named direct references; that classification does not attest immutable artifacts. Documentation snippet parsing covers literal package arguments, quoted requirements, and recognized requirements, constraints, editable, index, destination and configuration options. File references, editable targets and option operands are skipped rather than followed or executed. Unknown option syntax, shell expansion, line continuations, and platform-specific shell grammar require human review; malformed quoting yields no parsed packages.

API-symbol results describe static source declarations. The retained `verified`
status means `static_resolution: declaration_found`, not guaranteed runtime
availability. Conditional bindings, star imports, recognized dynamic export
hooks and unresolved inherited/decorated members report `unresolved`, rather
than claiming the API is missing. Supported absence remains a review finding;
strict profile enforcement applies to unresolved declared symbols as well.
The bounded AST model does not execute conditions or imports and is not
exhaustive dynamic-Python analysis. Missing or empty declarations report
`not_configured`, not `pass`, and remain non-blocking by themselves. Malformed
configuration retains its adverse findings. Installed-distribution metadata
checks and no-import/no-network boundaries are unchanged.


`naos api-symbol-reality` may claim that NAOS read `naos/api_symbol_reality.yaml` when present and checked declared Python symbols through repo-local source or installed-distribution source-file AST inspection. It may not claim target modules were imported or executed, API semantics are correct, runtime behavior is verified, options/endpoints are compatible, generated API usage is correct, package safety is proven, provider/API calls occurred, approval was granted, certification exists, compliance is proven, or hallucinations are prevented.

`naos agent-traces` may claim that NAOS read declared records from `naos/agent_trace_events.yaml`, validated their schema shape, checked source-reference posture, lightweight forbidden-payload patterns, memory-reference posture, trace-as-authority wording, and optional `action_receipt` metadata, and wrote `naos/reports/agent_trace_validation.json`. It may not claim runtime capture, command execution, hook activation, provider/API or network use, permission enforcement, tool-call interception, memory write-back, private memory payload access, behavioral correctness proof, approval, certification, proof of compliance, or hallucination prevention.

`naos harness-trace-import` may claim that NAOS read an explicit repo-local JSONL/NDJSON file, normalized compatible records into declared agent trace event shape, and wrote `naos/reports/harness_trace_import.json`; with `--write-events`, it may append valid declared records to `naos/agent_trace_events.yaml` for later `naos agent-traces` validation. It may not claim runtime capture, harness execution, hook activation, provider/API or network use, command execution, memory write-back, private memory payload access, behavioral correctness proof, approval, certification, proof of compliance, or hallucination prevention.

## Governed Learning Lifecycle Claim Boundary

`naos learning-loop-review` may claim that NAOS inspected repo-local learning
lifecycle records and produced deterministic findings for candidate, active,
historical, stale, promotion-review, replacement, forgetting, and redaction
metadata. It may not claim self-learning model weights, semantic truth,
hallucination prevention, memory write-back, automatic context injection,
automatic skill/prompt/workflow/baseline/gate mutation, approval, certification,
maturity promotion, or proof of compliance. Human review remains required before
any lesson becomes durable guidance or changes governed artifacts.

## Spec-Pack Contract Claim Boundary

`naos spec-pack-contract` may claim that NAOS inspected repo-local
`spec_manifest.yaml`, profile-required spec files, not-applicable-by-profile
files, and manifest-declared reference codes, and produced deterministic
findings for missing files, missing required sections, missing anchors, missing
sync markers, unresolved references, missing reference sources, and filled-mode
unresolved placeholders. It may not claim specification quality, requirements
completeness, approval, implementation, test behavior, complete traceability,
certification, proof of compliance, or human-review replacement. Human review
remains required for disposition, waivers, and acceptance.

## Spec-Cascade Coherence Claim Boundary

`naos spec-cascade` may claim that NAOS inspected configured requirement,
task-registry, source-header, and source-root evidence and produced
deterministic structural findings for orphan headers, stale status links,
overloaded FRs, uncovered requirements, untraced source files, and unresolved
source-level FR/NFR/AC/SCEN references. It may not claim complete traceability,
code correctness, runtime behavior, requirements completeness, approval,
certification, proof of compliance, or human-review replacement. Human review
remains required for disposition, waivers, and acceptance.

## AC Completion Evidence Claim Boundary

`naos ac-completion-evidence` may claim that NAOS inspected the explicit
`naos/ac_completion_evidence.yaml` manifest, resolved declared AC/SCEN ids
against specs where definitions exist, and checked declared evidence paths,
commands, and outcomes for claimed-complete entries. When a record explicitly
declares full Git object ids, NAOS may also claim that the base and subject
commits resolved in the exact project repository, the declared subject tree
matched the subject commit, and conservative path-shaped command operands
resolved as supported objects in that tree. Bound deterministic evidence with
no recognized path-shaped operand remains unsatisfied. Shell comments,
environment assignments, variable/command/tilde/brace expansion, globs,
path-shaped values attached to options, direct `@file` response syntax,
URI/URL-bearing or otherwise unsupported colon forms, C0/DEL controls,
bang/history-negation forms, grouping, and compound commands are
outside the operand grammar and fail closed before receipt creation. A validated successor link may
identify an earlier same-AC record as superseded while preserving both records.
Missing or empty manifests mean no completion evidence is configured; they are
not completion proof. Git object and operand resolution does not prove the
recorded command ran, ran cleanly, ran independently, or used only that tree.
Supersession is review lineage, not deletion, revocation, approval, or release
authority. The report may not claim signing, signer identity, non-repudiation,
AC correctness, implementation correctness, complete test coverage, semantic
quality, approval, hallucination prevention, certification, proof of compliance,
or human-review replacement. Human review remains required for acceptance
decisions, waivers, corrections, and whether a completion claim is legitimate.

## PR Risk Classification Claim Boundary

`naos pr-risk-classify` may claim that NAOS inspected local git diff metadata and produced deterministic review findings for configured protected paths, workflow changes, dependency changes, AI instruction/prompt/agent surfaces, prompt-injection-like added text, secret-like added lines, and contributor-trust metadata supplied by local/CI environment. It is not PR approval, not security proof, not malware analysis, not sandbox execution, not authentication, not authorization, not proof of compliance, not release authorization, and not deployment authorization. Human review remains required for disposition, waivers, contributor/context interpretation, secret rotation decisions, dependency decisions, and branch-protection policy decisions.

## Parallel Lane Handoff Claim Boundary

`naos_parallel_lane_handoff.py` may claim that NAOS inspected an explicit
repo-local lane handoff input or CLI-supplied lane fields and produced local
review evidence for declared parallel-lane task/FR/NFR refs, dependency state,
claim conflicts, planned and changed paths, test/check evidence, NAOS report
refs, residual risks, non-claims, and human-review posture. `naos
control-plane-review` may claim that it reconciled declared handoff reports
with local PR-risk, plan-coherence, task-claim, and pre-implementation
alignment evidence and emitted deterministic HITL reason codes. These surfaces
may not claim automatic lane declaration, task authorization, dependency
unlocking, agent dispatch, branch/worktree creation, test execution, approval,
blocking gate authority, merge readiness, task closure, release/publication
authority, runtime orchestration, MCP/memory/hook/provider/model activation,
certification, attestation, legal advice, or proof of compliance. Human review
remains required for disposition, waivers, risk acceptance, and whether
parallel work should proceed.

## Governance Bypass Posture Claim Boundary

`naos governance-bypass-posture` may claim that NAOS inspected local git hook configuration, generated pre-commit hook presence, local workflow file indicators, recent commit-message bypass markers, and tier/profile mismatch signals. It may not claim bypass prevention, tamper-proof hook enforcement, proof that CI ran or passed, PR approval, authentication, authorization, non-repudiation, certification, proof of compliance, release authorization, or branch-protection enforcement. Human review remains required for compensating controls, branch-protection decisions, and bypass disposition.

## External Evidence Ingest Claim Boundary

`naos external-evidence-ingest` may claim that NAOS parsed a local SARIF 2.1.0 file and summarized tool metadata, result counts, levels, rules, and affected paths. Imported findings are unverified external review evidence. The command may not claim scanner execution, finding verification, vulnerability absence, security proof, approval, attestation, certification, proof of compliance, source-of-truth authority, maturity promotion, or release authorization. Human review remains required before remediation, waiver, release, audit, or compliance decisions.

## Dogfood And Reference Evidence

Reference projects can be useful examples, but they are not universal proof. Mention dogfood or pilot projects only in explicitly labelled examples, case studies, migration notes, or analysis documents. Generic capability contracts, schemas, validators, gates, dashboards, and portable docs should stay adopter-neutral.

### Audit event filenames

New audit event files encode each logical-ID filename component as a bounded
ASCII prefix plus a digest of the original value. Malformed timestamp fallback
text uses the same encoding; valid timestamp formatting stays unchanged.
Colons, separators, control characters and Unicode therefore do not enter the
filename directly. Logical IDs in event JSON and summary attribution retain
their existing meaning and redaction policy. Historical date-directory JSONL
files remain discoverable without renaming or rewriting them.

The digest is a naming discriminator, not an integrity proof or a mathematical
guarantee of collision freedom. Existing collision retries remain in place.
This change qualifies leaf naming only; it does not guarantee arbitrary full
path lengths or strengthen concurrent-writer, tamper-resistance or retention
assurances.

### Python source-scan exclusions

Quality and spec-drift exclusions match exact, case-sensitive project-relative directory components and file suffixes. Checkout parent names such as `migrations-review` do not suppress scans; `migrations_helpers.py` remains eligible. Actual `migrations/` and `__pycache__/` directories remain excluded; spec drift additionally excludes `alembic/` and initializer files under its existing policy. These lexical selection rules are not filesystem containment or symlink guards.

The function-length audit exposes selection, successful parse and read/parse-failure counts. Empty/function-free scans have no compliance percentage; incomplete scans cannot establish a complete quality conclusion. Spec drift exposes candidate/excluded/eligible selection counts and exclusion reasons. Its legacy `files_scanned` value counts eligible paths, not verified successful content reads. Empty selection produces advisory uncertainty while legitimate spec/task findings and profile exits remain applicable. Python-only selection does not establish coverage of other languages.

### Function-index roots and static import references

Index generation uses the shared inferred source roots (`src`, `app`, `apps`, `packages`, `lib`) or explicit comma-separated `SRC_ROOT`. Single-root module keys retain their existing shape; multiple roots retain their project-relative namespace. Every declaration leaf records `source_path`, which recursive query, similarity and health readers use instead of inventing a path under `src/`. Existing indexes without this field retain the legacy path fallback.

`used_by` resolves uniquely indexed project-relative and source-root-relative module aliases, including supported relative imports and package initializers. Ambiguous aliases are unresolved; no root is guessed. This is static Python reference analysis under the selected roots, not proof of runtime `sys.path`, import availability, conditional execution or non-Python coverage. Dynamic imports, wildcard symbol expansion and external/unindexed references remain unresolved. The YAML header records parse failures and up to 25 unresolved examples with an omitted-sample indicator. Initializers contribute import references but retain their existing exclusion from declaration leaves. Importer lists show the first five sorted identities plus an omitted count.

### Semantic audit compatibility and exact-pair exceptions

The old `make -f Makefile.naos semantic-audit` target advertised an LLM review that NAOS does not implement. It now returns `SEMANTIC_AUDIT_NOT_IMPLEMENTED` with exit 2, without calling a provider, running another audit, or writing an assessment. The Make-free equivalent on macOS, Ubuntu and Windows is `python scripts/naos_code_quality_audit.py --semantic-audit --report json`. The shipped quality-score snapshot remains an unassessed null placeholder.

`python scripts/naos_code_quality_audit.py --check-duplicates` is a separate exact/near-match check using source and an existing similarity index; it is not an LLM quality audit. `configs/naos_semantic_allowlist.yaml` accepts `semantic_allowlist` entries with `pair: [left_symbol_key, right_symbol_key]`, using the exact keys in `FUNCTION_SIMILARITY_INDEX.json`. A pair downgrades its high-confidence cosine error to a warning; it leaves the finding and log visible and does not suppress exact duplicates or unrelated pairs. Review metadata is descriptive, not authenticated approval.

Missing allowlist means no exceptions. A malformed present file, or the previous seed's unsupported `allowlist`/pattern or `auto_exempt_categories` format, returns `SEMANTIC_ALLOWLIST_INVALID` with exit 2. Migrate explicitly approved pairs using the shipped example; existing supported pair files remain valid. The seed no longer refers to an absent audit script. Fresh semantic-warning logs use the producer's five columns; existing logs are preserved and are not automatically migrated by this change.

### Duplicate exceptions and progress-history formats

Duplicate exceptions accept the shipped `allowlist: [{pattern: function_name, locations: [relative/file.py, ...]}]` format and the existing `allowed_duplicates: {function_name: [relative/file.py, ...]}` mapping. Use one format per file. Patterns are literal Python names, not regular expressions; locations are exact relative file paths, with Windows separators normalized. Missing configuration grants no exceptions. Malformed present configuration returns `DUPLICATE_ALLOWLIST_INVALID` with exit 2. An exception covers only its named locations: new copies remain findings. A semantic error-to-warning downgrade also requires the same name and both approved locations; it never hides the finding.

Fresh `TASK_PROGRESS_HISTORY.csv` files use `timestamp,done_percent,done,in_progress,total`. The dashboard reads known column names and validates counts and percentages, including reordered canonical columns. Valid legacy nine-column files are read using `done / total_tasks`, rather than treating task counts as percentages. Legacy histories are preserved without append and report `PROGRESS_HISTORY_MIGRATION_REQUIRED`; migrate deliberately while retaining the original data. Unknown headers, mixed-width rows or contradictory/nonfinite data produce `PROGRESS_HISTORY_INVALID`, no trend, and no append. Canonical appends retain existing rows and record at most one row per day, using UTF-8 and CSV-safe line endings. This is format/meaning validation, not a concurrent-writer or filesystem-race guarantee.

### Maturity-model validation

Self-check validates `maturity_levels.yaml` against the executing kit’s `capability_maturity.schema.json`, including required levels and profile policies. Optional `description` text and `status_values` descriptions are supported; these labels do not grant maturity or change enforcement. Unknown model/policy fields and invalid types produce findings at the selected profile’s severity. A missing or invalid canonical schema produces a visible validation error. Existing models without the optional descriptions remain supported.

### Team configuration validation

`schemas/team_config.schema.yaml` is a Draft 2020-12 schema applied to the registry document, validating its optional `team_config` block. It is not a replacement for the task-entry schema. Absent/null configuration disables filtering; omitted fields keep existing defaults. Team fields are `id`, `label`, `members` and `scope`; unknown fields and invalid types are rejected. Members are descriptive strings, not authenticated identities or access grants.

The registry validator, dashboard filter and backlog filter share deterministic structure and duplicate-ID checks, including when the optional schema library is unavailable to a filter. When enabled, task/phase/module scope entries must match registry task IDs, phases or owners respectively; invalid references are rejected rather than silently producing misleading filtered views. Disabled scope references remain inert. The schema alone does not prove these contextual relationships. Existing unknown-team and empty-scope fallback behavior is unchanged.

### Portable serialized paths

Agent orchestration scopes use forward-slash repository-relative paths and retain supported `*`, `?`, bracket and `**` glob semantics. Schemas and runtime reject drive/root/UNC forms, backslashes, colons, controls, `.git` roots, dot/traversal/empty segments and surrounding whitespace. Replace historical `./` prefixes, repeated separators and trailing separators with canonical paths before submission; scopes are no longer silently rewritten by the host path library. Concrete filesystem containment checks remain separate.

AC evidence paths accept relative Windows separators and serialize valid repository-relative report paths with `/`. Native absolute paths remain supported only when resolution stays inside the repository; foreign-platform anchors, parent traversal, controls and alternate-stream colons are rejected. Existing resolved containment is retained and evidence file contents/hashes are unchanged. Subject-tree command operands remain exact relative paths with the existing `.` and supported line/symbol selectors. Control-plane exclusions preserve leading dots in hidden directory names and remove only explicit `./` prefixes; traversing/rooted references are not silently ignored.

### Report discriminator and status validation

The SARIF export summary schema accepts only `naos.sarif_export.v1` with status `ready`; missing or unsupported inputs remain visible in source metadata and do not acquire an invented top-level status. Task-lifecycle reports retain their distinct inspection, completion, preview and failure states, including `registry_task`. Secure-coding reporting retains the shared severity-derived states `pass`, `advisory`, `warning`, `required_missing` and `blocked`. Their schemas reject unknown top-level statuses. Schema conformance checks report structure and vocabulary; it does not establish the truth of evidence or grant approval.
## AI pre-commit configuration validation

`python scripts/naos_ai_precommit.py --check-config` validates configuration
only. A present YAML document must be a mapping; present `ai_review`,
`stage2_fallback`, `grading` and `grading.llm_grader` sections must also be
mappings. Use `{}` for an empty section. `enabled` and `ai_review.enabled`
accept actual YAML Booleans, not quoted strings, numbers or null. Mode fields
must be strings; provider and API environment-variable metadata may be strings
or null. Errors return nonzero without a traceback or embedding-status writes.
The missing-file disabled fallback and documented legacy backend aliases remain
supported. Safe mode does not execute providers, including when policy is valid.
