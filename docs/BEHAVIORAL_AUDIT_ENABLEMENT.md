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
