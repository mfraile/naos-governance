# Behavioral Audit Enablement

**Status**: Public guidance
**Scope**: How NAOS frames behavioral and advisory review without turning it
into default runtime judgment

NAOS makes deterministic controls primary. Behavioral and advisory controls are
bounded review aids unless an adopter separately designs, configures, approves,
and governs a runtime evaluator.

## Primary Baseline

The default baseline is file-first and deterministic:

- capability contracts;
- policy and profile configuration;
- schemas and seed files;
- validators;
- gate status/evaluation;
- evidence pack;
- dashboard;
- SARIF findings export where useful.

These controls are inspectable and rerunnable. They still do not prove code
correctness, requirements completeness, runtime safety, or compliance.

## Advisory/Behavioral Surfaces

NAOS includes readiness and review surfaces that can support behavioral audit
planning:

- StaticGrader is structural and deterministic.
- Grader Assessment packages deterministic review input.
- LLMGrader Readiness records posture for a possible future advisory evaluator;
  runtime is disabled by default.
- Behavioral Governance Readiness reports first-baseline readiness, optional
  baseline metadata currency, and deterministic impacters; it does not create
  baselines, grade behavior, call models/providers/APIs, infer semantic drift,
  approve, certify, publish, or authorize releases.
- Agentic workflow review checks declared operating-model files.
- Pre-Implementation Alignment review checks structured alignment artifacts.
- Calibration shadow checks deterministic report metadata stability over a
  local frozen baseline; it is not model calibration.
  A valid configuration with `enabled: false` reports `disabled` rather than
  `ready`; malformed disabled configurations remain `invalid_config`.
- Evidence classification records finding provenance categories separately
  from severity.
- Cross-Harness Review Readiness records future independent-review and
  DSSE-style planning boundaries without executing harnesses, signing
  artifacts, verifying signatures, or custodying keys.
- Semantic and graph readiness reports keep future candidate layers bounded.

Advisory findings require residual-risk handling and human review. They may
challenge deterministic evidence, but they may not replace it.

## Maintainer Adversarial Regression Evidence

The NAOS source repository continuously re-runs one narrower control through
its existing pull-request and `main`-push unit-suite cadence. The internal
23-case deterministic SDLC-hygiene family includes malicious fixtures, clean
controls, four profile postures, and one named open identifier-renaming gap.
The continuous red-team policy requires zero false negatives, zero false positives, the
exact scenario set, schema-valid detector reports, no runner errors, no
model/provider/network use, and zero external API cost.

This evidence answers only whether the pinned deterministic adversarial
regression remains current. A threshold, scenario, schema, runtime-dependency,
or known-gap change fails the evidence contract and routes to the repository
maintainer/risk owner for human triage and explicit rebaseline. It never
approves a merge, accepts a new risk, or authorizes release or publication.

The control is not a shipped adopter behavioral evaluator and is not a
Promptfoo, PyRIT, Garak, model-backed, provider-backed, prompt-injection,
tool-use, or runtime-safety assessment. Those broader capabilities remain
separately designed and authorized work.

Evidence classification uses review provenance categories:

- `confirmed`: directly supported by a local file, schema, report, test,
  validator output, audit event, evidence pack, or SARIF finding.
- `deduced`: inferred from multiple local evidence points with a reasoning
  summary.
- `hypothesized`: plausible or advisory and requiring more evidence.
- `unknown`: not enough provenance is available.

Inferred classifications are candidates for human review. They are not final
truth, legal conclusions, issue resolution, approval, or proof of compliance.

All entries in `findings` and structured records in `known_gaps` or
`residual_risks` undergo provenance classification. Text-only gap/risk
entries cannot declare provenance fields under their producer schemas. They
remain verbatim in `unclassified_context`, with their report, bucket and index,
counts and a human-review requirement. Gate, maturity, evidence-pack and
dashboard summaries retain this context. A `ready` classification report means
its finding-classification checks passed; it does not resolve or approve those
disclosures or override the producer's findings. Malformed finding entries and
unknown provenance remain subject to the configured strict checks.

Explicit `evidence_classification` or `provenance_classification` fields take
precedence over the legacy `classification` field, which some producers use
for policy disposition. Invalid or conflicting explicit declarations remain
unknown and require review. Existing valid legacy provenance remains accepted
when no explicit provenance field is present.

Read `classification_scope` with the category. Producers can confirm their own
observed structural check failure, source digest mismatch, nonempty Git status
or pending review obligation without confirming the underlying domain claim
or resolving it. Default adapter risks declare hypothetical scenarios; custom
risk records do not inherit that classification. Source findings, severity and
human-review requirements remain independent of classification readiness.
PR summary gate-failure provenance confirms only the failure state declared by
the loaded gate report; required findings and human review remain in force.

Self-check refreshes the model policy, telemetry and optional inventory inputs
before control-plane routing and evidence classification. Aggregate producers
remain later to avoid classifying their copied findings again in a fresh run;
capability maturity projects the current classification and related reports last.
Prior reports already in the directory remain subject to the classifier's
existing scan contract. This fixes the routing one-run lag, without promising
that every existing report was generated in the same run or deduplicating
historical aggregate findings.

Shipped structured disclosures carry narrowly scoped declarations: factual
implementation limits and observations are distinct from possible risks.
Mutable rule records remain authored declarations. Editing a statement while
retaining its declaration does not make the new text independently verified;
human review and the report's non-claims still apply. New undeclared records
remain subject to the same strict checks.

AI-surface budget findings declare confirmed provenance only for configured
character-based token estimate comparisons and absence at the selected baseline
path. These observations do not verify provider tokenization, model behavior,
baseline approval or absence elsewhere. Their severities and enforcement exits
are unchanged; declared provenance does not clear a budget warning or block.

StaticGrader's six unsupported-dimension findings declare confirmed provenance
only for the tool's documented coverage limits, using the shipped source as a
reference. The dimensions remain unevaluated and advisory; no project behavior
or approval is inferred.

Selected input-state findings also declare bounded observations: missing state
entries, unassigned owner fields, absent report paths, and unavailable local
session/operator metadata. Those facts do not decide capability applicability,
assign accountability, validate audit events, or satisfy required inputs.
StaticGrader distinguishes physical path absence from reports it could not load;
present malformed inputs retain strict provenance handling. Possible effects of
AI-surface warnings on interpretation remain hypotheses requiring review.
Classification leaves the original findings and enforcement severities intact.

Candidate reconstruction and candidate-derived traceability gaps declare
`confirmed` only for the review obligation the producer emitted. Their
`classification_scope` and reason distinguish that observation from candidate
validity, requirement truth, owner approval, promotion or gap closure. An open
blocking gap stays open and blocking after provenance classification. A fallback
baseline-review gap still requires evidence; it is not confirmed merely because
candidate input was absent, malformed or contained no review candidates.

Classification records describe the source bytes observed during that scan;
the report at a referenced path may later change. Source-report and parsed-item
hashes, positions and timestamps keep that distinction visible. The classifier
retains original parsed values for inferred or unknown findings within limits
of 16 KiB per item and 256 KiB total, measured as canonical JSON payload bytes.
Omissions are explicit; declared findings and text disclosures retain projections
and hashes. This is not an archive of complete original reports. Downstream
projections carry lineage references without duplicating the retained payloads.

## Non-Claims

Behavioral audit enablement does not provide:

- behavioral correctness proof;
- hallucination prevention;
- model alignment certification;
- runtime safety proof;
- proof of compliance;
- requirements completeness proof;
- autonomous approval;
- human review replacement.

## Future Runtime Judging

Future runtime or model-backed judging, if ever introduced, must be designed as
a separate project-configured or future capability with:

- explicit provider/model/data exposure review;
- cost and repeatability limits;
- source hashes and input scope;
- bias, drift, and false-positive/false-negative limitations;
- residual-risk routing;
- human approval before durable decisions.

The v1 public core does not call model/provider APIs, write memory, run
LLMGrader, or make advisory outputs authoritative by default.

### Baseline metadata eligibility

A present baseline must declare `schema: naos.behavioral_baseline_state.v1`, a
supported profile, a mapping of string fingerprint keys to nonempty string
values, and a valid effective timestamp. Empty or malformed metadata is
`not_ready`; it is never evidence of a current baseline. Missing fingerprint
keys remain comparison inputs and can produce maintenance impacters; existing
fingerprint bytes and categories are unchanged. `baseline_validation` reports
`not_present`, `valid` or `invalid` plus issues. A missing optional baseline can
still be `ready_to_baseline` when prerequisites are satisfied.

The effective timestamp is `last_behavioral_baseline_at` when that key exists;
otherwise it is `generated_at`. A present null, empty or invalid override does
not fall back silently. Timestamps require an explicit UTC offset (`Z` or an
offset); date-only and naive values are rejected. Equivalent offset timestamps
compare by instant, and future baseline dates or an invalid comparison time
cannot count as fresh. Quoted and unquoted YAML timestamps retain their text
for validation and JSON reporting. Invalid metadata requires human repair;
this command never creates or refreshes the baseline automatically.

This metadata validation does not establish the substantive sufficiency of
prerequisite behavioral evidence, which remains a separate review obligation.

### Behavioral readiness prerequisite contracts

Required StaticGrader, Grader Assessment and LLMGrader Readiness reports must validate against their shipped report schemas before their statuses are considered. Missing or damaged schemas, status-only stubs and malformed authority/cost fields produce `not_ready` with `contract_issues`; regenerate the prerequisite report using its deterministic producer. Generated Lite/Standard/Assured projects and the optional readiness setup module include these schema files.

Conformance input must contain the deterministic runner's count/score structure. A supplied `status: pass` cannot override failed checks, and a rounded score of 1.0 does not erase a failed check. Null behavioral dimensions remain valid: they mean not evaluated. Existing safe disabled/readiness-only LLM states remain eligible; this command never enables runtime grading.

Contract validity does not prove that a report is authentic, fresh or substantively complete. Baseline approval and evidence review remain human responsibilities. Historical status-only conformance stubs must be regenerated rather than treated as completed checks.
