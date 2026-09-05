# NAOS Public Audit Playbook

**Status**: Public adopter guidance
**Scope**: How to run deterministic NAOS checks and use generated reports as
review evidence

This playbook is public, sanitized guidance for adopters. It does not expose or
depend on private maintainer audit skills or internal release procedures.

## Audit Goal

Use NAOS to produce a clear, repeatable evidence trail:

1. initialize or repair the adopter-local NAOS files;
2. run deterministic source and governance checks;
3. generate reports, evidence pack, dashboard, and SARIF where useful;
4. review missing, stale, waived, advisory, and residual-risk items;
5. decide remediation, waiver, or acceptance through the adopter's own
   governance process.

NAOS reports support review. They are not proof of compliance, not regulator
attestation, not legal advice, not runtime safety proof, not deployment
approval, not release approval, and not a replacement for human review.

## Recommended Local Audit Chain

Run from an initialized adopter project:

```bash
naos setup-recommendations --profile <profile>
naos session-id --profile <profile>
naos operator-attribution --profile <profile>
naos agentic-workflow-review --profile <profile>
naos pre-implementation-alignment-review --profile <profile>
naos calibration-shadow --profile <profile>
naos evidence-classification --profile <profile>
naos policy-overrides --profile <profile> --dry-run
naos governance-bypass-posture --profile <profile>
naos external-evidence-ingest --profile <profile>      # add --source <scan.sarif> when available
naos claims --profile <profile>
naos capability-maturity --profile <profile>
naos systemic-impact --profile <profile>
naos module-headers --profile <profile>
naos spec-pack-contract --profile <profile>
naos spec-pack-materialize . --profile <profile> --dry-run
naos spec-assembly-worksheet . --profile <profile>
naos spec-cascade --profile <profile>
naos control-plane-review --profile <profile>
naos evidence-attestation --profile <profile>
naos evidence-conflicts --profile <profile>
naos task-claims --profile <profile>
naos learning-loop-review --profile <profile>
naos ai-surface-budget --profile <profile>
naos ai-surface-budget --fresh-profiles --json
naos self-check --profile <profile>
naos gate-status --profile <profile>
naos gate-evaluate --profile <profile>
naos evidence-pack --profile <profile>
naos dashboard --profile <profile> --json-output naos/reports/dashboard_summary.json
naos sarif-export --profile <profile>
naos pr-risk-classify --profile <profile>
```

Use `make -f Makefile.naos <target>` equivalents when the generated project
includes `Makefile.naos`.

## Source Checks

Source-oriented checks are strongest when the project has adapted the relevant
rules:

- `naos function-index-health` checks function index presence and freshness.
- `naos test-evidence-map` builds source-to-test relationships where possible.
- `naos test-evidence` evaluates the test-evidence map.
- `naos ac-completion-evidence` checks declared AC/SCEN completion evidence
  paths and outcomes. Optional record-level `repository_binding` fields use
  full base/subject commit ids plus the subject-tree id; when present, the
  command's conservatively recognized path-shaped operands must resolve in that
  tree, and at least one such operand must be recognized for bound deterministic
  evidence to satisfy a completion record. Comment-bearing, environment-
  assignment, expansion-bearing, globbed, path-valued attached-option,
  direct-`@file`-response, URI/URL or otherwise unsupported colon-bearing,
  C0/DEL-control, bang/history-negation, grouped, or compound shell forms fail
  closed rather than being shortened or interpreted into a different path.
  Optional successor records preserve and supersede earlier same-AC
  records for human review. These checks do not re-run commands or prove clean
  or independent execution, signing, identity, approval, or release readiness.
- `naos duplicate-function-hygiene` detects normalized duplicate Python
  function bodies across configured local roots.
- `naos secret-hygiene` detects obvious secret-like local findings without
  reading remote systems or calling providers.
- `naos test-quality-hygiene` detects missing or trivial assertion evidence.
- `naos dependency-integrity` detects undeclared or unresolved Python imports
  using local declarations and allowlists.
- `naos package-reality` reviews declared package names, lock-style pins,
  optional docs install snippets, configured local CycloneDX
  SBOM/provenance/hash evidence, and explicit opt-in registry metadata.
- `naos api-symbol-reality` checks explicitly declared Python API symbols by
  local source inspection without importing or executing target modules.
- `naos pr-risk-classify` checks local git diff metadata for protected paths,
  workflow/dependency changes, AI instruction surfaces, prompt-injection-like
  added text, secret-like added lines, and contributor-trust posture.
- `naos governance-bypass-posture` checks local hook configuration, generated
  pre-commit hook presence, local NAOS CI indicators, commit-message bypass
  markers, and tier/profile mismatch.
- `naos external-evidence-ingest --source <scan.sarif>` summarizes local SARIF
  2.1.0 scanner output as unverified external review evidence.
- `naos module-headers` checks canonical module-header traceability for
  configured source roots.
- `naos spec-pack-contract` checks deterministic spec-pack template contract
  conformance for profile-required files, not-applicable-by-profile files,
  sections, anchors, manifest-declared reference codes, and sync markers.
- `naos spec-pack-materialize . --dry-run` previews missing profile-required
  spec-pack files, and without `--dry-run` copies missing template files while
  skipping existing specs unless `--force` is explicit.
- `naos spec-assembly-worksheet .` maps adoption evidence, candidate
  requirements, and traceability gaps to manifest-declared spec files for
  human review.
- `naos spec-cascade` checks deterministic requirement/task/source cascade
  coherence and reports orphan headers, stale status links, overloaded FRs,
  uncovered requirements, unresolved source spec references, and untraced
  source.

These checks do not prove source correctness, test sufficiency, secure code, or
runtime safety. The traceability and hygiene reports are review evidence only
and do not prove complete traceability,
semantic correctness, secret-free code, behavioral correctness, package safety,
API behavior, PR approval, security, approval, certification, compliance, or
runtime safety.
Bypass-posture evidence does not prevent bypasses or prove CI ran. External
SARIF ingest does not verify findings, run scanners, attest evidence, certify
controls, or prove compliance.
Spec materialization and assembly worksheet reports do not fill specs, promote
candidate requirements, prove applicability, approve requirements, or prove
complete traceability.

## Manual External Adopter Pilot

When verifying a kit upgrade or onboarding path before broader release, use a
temporary external repository and keep the route bounded to first-run evidence:

```bash
cd /tmp/example-naos-adopter
python -m naos_governance.cli doctor
naos-governance first-run --profile standard --mode brownfield
```

`first-run` performs doctor, adoption dry-run, setup recommendations,
profile-baseline setup-module dry-run, evidence pack, and dashboard generation.
Run additional setup-module dry runs only when the recommendation report
identifies a specific installable module worth previewing. Do not run
`naos init --activate` inside this dry-run pilot just to make `Makefile.naos`
appear; full scaffold activation is a separate generated-project smoke path.

Before interpreting results, confirm `python -m naos_governance.cli doctor`
reports the active package and command resolution. Local editor launcher
aliases, Conda base environments, old global scripts, or another tool named
`naos` can intercept bare commands. Use `naos-governance ...` or
`python -m naos_governance.cli ...` as the transparent fallback when command
resolution is ambiguous.

Record the manual pilot observations separately from remediation decisions:

- commands run and exact pass/fail result;
- missing commands, confusing wording, or unexpected prerequisites;
- generated reports under `naos/reports/` and evidence under `naos/evidence/`;
- any claim that sounds like approval, certification, proof of compliance,
  hallucination prevention, runtime safety proof, or automatic activation.

This pilot route produces review evidence only. It does not activate hooks,
call providers, write memory, approve work, certify controls, prove compliance,
prove runtime safety, or authorize release.

## Reading Gate Reports

`gate-status` answers what inputs are present, missing, stale, disabled, or
not configured. `gate-evaluate` applies the selected profile's gate posture.
Team context may change effective gatekeeper severity where configured, but it
is governance configuration only.

Gate reports do not approve work, prove compliance, prove requirements
completeness, satisfy separation of duties, or authorize deployment.

## Evidence Pack, Dashboard, and SARIF

Use:

- `naos evidence-pack --profile <profile>` for consolidated JSON evidence;
- `naos dashboard --profile <profile> --json-output naos/reports/dashboard_summary.json`
  for the human-readable dashboard file plus JSON posture summary;
- `naos ai-surface-budget --profile <profile>` for static AI-instruction
  context-health, profile/generated `.ai/RULES.md`, anchor,
  combined-loadout, and baseline-drift evidence;
- `naos ai-surface-budget --fresh-profiles --json` for complete isolated
  Quickstart, Lite, Standard, and Assured finding, resident-token,
  generated-file, and reachable-command measurements; add `--all` for every
  human-readable occurrence or `--output <path>` to persist the aggregate;
- `naos learning-loop-review --profile <profile>` for candidate, active, and
  historical learning lifecycle posture, including promotion, replacement,
  forgetting, and redaction controls;
- `naos sarif-export --profile <profile>` for findings interoperability.

If AI-surface posture is `warning` or `degraded`, use the
`ai-surface-health-review` skill where installed. Remediate by slimming repeated
always-loaded prose, preserving anchors, and routing residual risk; do not hide
the finding by inflating thresholds or auto-approving a baseline.

SARIF output is a findings export. It is not security attestation, compliance
approval, certification, or reviewer sign-off.

## Advisory and Readiness Reports

Advisory/readiness reports are useful because they keep gaps visible. Treat
them as review inputs:

- `llm_grader_readiness.json` is readiness-only; no LLMGrader runtime runs by
  default.
- `behavioral_governance_readiness.json` is deterministic readiness/impacter
  review only; it does not create baselines, grade behavior, call
  models/providers/APIs, or infer semantic drift.
- semantic and graph readiness reports do not enable vector or graph runtime.
- agentic workflow and Pre-Implementation Alignment reviews check files and
  declared practice, not actual model attention or implementation quality.
- calibration shadow checks deterministic report metadata stability; it is not
  model calibration, semantic correctness proof, release authorization, or
  approval.
- evidence classification separates provenance categories from severity:
  `confirmed` means direct local artifact support, `deduced` means inference
  from multiple local evidence points, `hypothesized` means advisory concern,
  and `unknown` means insufficient provenance. Inferred classifications are
  review candidates, not truth proof, issue resolution, or approval.
- cross-harness review readiness records future independent-review and
  DSSE-style planning boundaries. It does not execute harnesses, sign
  artifacts, verify signatures, custody keys, create attestations, approve
  work, certify outcomes, or prove compliance.

If an advisory finding challenges deterministic evidence, record the
discrepancy, route it through control-plane review, and require human
disposition before durable state changes.

## Preparing Reviewer-Facing Evidence

For a reviewer-facing evidence pack:

1. run the deterministic chain for the selected profile;
2. include `naos/evidence/evidence_pack.json`;
3. include relevant `naos/reports/*.json`;
4. include `DASHBOARD.md` and `dashboard_summary.json` where generated;
5. include SARIF only when the reviewer can interpret NAOS findings correctly;
6. document known gaps, waivers, residual risks, and human decisions.

Do not describe the package as NAOS approval, regulator acceptance, legal
advice, or proof that the system is compliant, safe, complete, or deployed
correctly.
