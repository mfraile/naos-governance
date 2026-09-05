# ADR-0010: Control-Plane Advisory Boundaries

**Status**: Accepted
**Date**: 2026-05-18
**Scope**: NAOS control-plane architecture, future advisory controls, and human decision boundaries

## 0. Context

NAOS combines deterministic reports with optional or future advisory review
surfaces. Without a clear boundary, adopters could mistake candidate findings,
memory recall, semantic similarity, graph hints, or model-backed second opinions
for authoritative project decisions.

## 1. Decision Summary

NAOS separates four layers:

1. **Deterministic primary controls**: file-first, reproducible, source-linked
   controls that form the baseline evidence trail.
2. **Advisory complementary controls**: optional or future/project-configured
   probabilistic, model-backed, memory-backed, graph-analytic, or heuristic
   controls that can produce candidates, warnings, discrepancy findings, or
   review prompts.
3. **Residual-risk handling**: explicit metadata that records what an advisory
   control did, where it may be wrong, what it compared against, and what
   remains unresolved.
4. **Human decision boundaries**: durable outcomes are approved by humans or by
   project governance mechanisms explicitly configured by humans.

Core invariant:

> Advisory controls may challenge deterministic controls. They may not replace them.

This ADR locks the balanced NAOS model: deterministic controls are primary;
advisory/probabilistic controls are complementary; residual risk remains
explicit; humans decide durable outcomes.

## 2. Deterministic Primary Controls

Deterministic primary controls include:

- current user/task instruction;
- specs and requirements;
- task registry, backlog, and active task cards;
- code, tests, schemas, configs, and source module headers;
- policies, capability cards, gatekeepers, and profile rules;
- static validators and deterministic conformance checks;
- module-header traceability;
- spec-pack contract conformance;
- spec-cascade coherence;
- explicit links among tasks, specs, capabilities, modules, tests, findings,
  gaps, residual risks, waivers, reports, and evidence;
- local context index exact/path/metadata/FTS baseline;
- evidence pack and dashboard outputs;
- reviewer attestation metadata and local digest coverage.

These controls can still be incomplete, stale, waived, or wrong. Their
advantage is that they are inspectable, repeatable, source-linked, and suitable
for review.

## 3. Advisory Complementary Controls

Advisory controls are optional or future/project-configured controls that may
supplement deterministic review. Examples include:

- semantic similarity, sqlite-vec, vector candidates, or embeddings;
- graph analytics, NetworkX, graph algorithms, centrality, PageRank, community
  detection, or traversal hints;
- memory recall or Engram discrepancy detection;
- LLMGrader or other model-backed second opinions.

Advisory controls may produce candidate references, warnings, discrepancy
findings, residual-risk prompts, review recommendations, or candidate evidence
for a human to inspect.

Advisory controls may not produce approval, proof of compliance, legal or
regulatory proof, maturity promotion, certification, task completion proof,
source-of-truth status, or sole pass/fail authority.

## 4. Residual-Risk Mechanism

Every advisory control that influences review must be represented by a residual
risk or advisory finding record with these fields or equivalent:

```yaml
advisory_control_id: null
advisory_type: null
deterministic_baseline: null
model_or_algorithm: null
version: null
parameters: {}
input_scope: []
source_hashes: []
generated_at: null
confidence: null
limitations: []
residual_risks: []
discrepancy_with_deterministic_baseline: null
human_review_required: true
can_promote_without_human: false
can_block_without_deterministic_support: false
not_claimed: []
```

Residual-risk categories include false positive, false negative, model drift,
version drift, stale source, sensitive data exposure, cost overrun, dependency
compromise, operator overtrust, automation bias, and
advisory-to-authority confusion.

If an advisory control lacks this metadata, its output is informal review
context only and must not be used for gating, maturity decisions, release
decisions, or durable project-state changes.

## 5. Interaction Pattern

The canonical interaction flow is:

1. Run the deterministic baseline first.
2. Run the advisory control second.
3. Compare outputs.
4. Produce discrepancy or candidate findings.
5. Route findings to control-plane review.
6. Human reviewers decide.
7. Only reviewed decisions update durable project state.

Examples:

- Deterministic duplicate check says no duplicate; semantic similarity finds a
  candidate. Result: candidate duplicate-intent finding, not an automatic block
  unless deterministic support or project policy confirms it.
- Explicit graph links say `A -> B`; graph analytics suggests `C` is adjacent.
  Result: graph-adjacency review prompt, not proof that `C` belongs in scope.
- Repository evidence says a policy is superseded; memory recalls the old
  policy. Result: memory discrepancy finding; repository evidence remains
  authoritative until humans decide otherwise.
- StaticGrader passes; LLMGrader advisory flags possible behavioral weakness.
  Result: behavioral review prompt; not proof of compliance, maturity promotion,
  or sole pass/fail authority.

## 6. sqlite-vec / Semantic Similarity Posture

Semantic similarity, sqlite-vec, vector search, KNN, vec0 tables, embeddings,
and semantic relevance scoring are not part of the deterministic primary layer.

If enabled in a future/project-configured group, semantic similarity must be
opt-in, disabled by default, local or explicitly risk-classified,
candidate-only, bounded by source/task/profile/result limits, invalidated when
source hashes change, and recorded with provider, model, version, dimension,
parameters, source hashes, and generated timestamp.

Extension loading and dependency trust must be explicitly reviewed before use.
No cloud embeddings are enabled by default.

No semantic result alone may promote maturity, block work, approve work,
certify evidence, override exact/path/metadata/FTS results, or override
repository evidence.

## 7. Graph Analytics Posture

Explicit links remain primary. Future graph algorithms may produce advisory
hints only.

If graph analytics is later enabled, it must start from explicit seed nodes,
obey bounded seed/depth/hop/edge limits, prohibit global graph scans by default,
record algorithm/version/parameters/input scope/source hashes/generated
timestamp, distinguish explicit source links from inferred graph hints, and
route discrepancies to control-plane review.

No graph score, PageRank, centrality value, community assignment, or graph
traversal result becomes proof, source authority, maturity evidence by itself,
or implementation correctness evidence.

## 8. Memory / Engram Posture

Memory recall is advisory. Memory discrepancy detection is allowed and useful
when it reveals a conflict between remembered context and current repository
evidence.

Memory may not become fact through a feedback loop. A memory reference must not
be treated as source truth merely because a previous session recorded it.

Memory write-back requires all of the following:

- configured provider;
- authorized surface;
- verified usable access;
- memory-use-policy-permitted action;
- explicit human approval for durable write use.

Future Engram runtime integration must provide evidence of local-only behavior
or explicit network/cloud risk classification. NAOS must not read private
memory payloads, read Engram databases, write memory, or call memory tools as a
default behavior.

## 9. LLMGrader Posture

StaticGrader deterministic grading is in scope when it evaluates files,
metadata, scenarios, and deterministic rules without calling an LLM.

LLMGrader readiness is in scope as a future/project-configured advisory track.
LLMGrader runtime is disabled by default.

If enabled later, LLMGrader must record provider, model, model version,
prompt version, rubric version, timestamp, cost budget, data exposure
classification, input scope, source hashes, bias/variance/repeatability
limitations, and human review boundary.

LLMGrader output cannot be proof of compliance, legal or regulatory approval,
maturity promotion, task completion proof, sole pass/fail authority,
certification, or deterministic evidence.

## 10. Hashing / Signing Posture

NAOS produces hashable and signable artifacts. NAOS does not sign on behalf of
adopters.

Adopters own signing decisions, keys, custody, notarization, timestamping,
certificate chains, attestation authority, and external archival.

Use a crypto-agile digest posture:

- New digest-oriented designs should default to SHA3-512 unless implementation
  constraints require otherwise.
- Preserve SHA-256 compatibility where existing reports, tooling, package
  ecosystems, or reviewer workflows already depend on it.
- Record algorithm, version, artifact scope, generated timestamp, and excluded
  paths.
- Use "checksum" or "digest" unless actual signing is implemented.
- Do not claim quantum-proof security.
- Do not call a digest a signature.

External signing, protected branches, signed commits, notarization, or
independent archival can strengthen evidence custody, but they remain adopter
responsibilities unless a future group explicitly implements and validates
signing support.

## 11. Human Decision Boundary

Humans approve durable decisions.

Reports are evidence aids, not verdicts. Evidence packs are not certification.
Advisory controls cannot approve. Recall traces are usage records, not
correctness proof. Audit events are records, not approvals.

Durable project state includes task closure, maturity promotion, waiver
acceptance, residual-risk acceptance, release approval, memory write-back,
compliance mapping disposition, public publication, and security exception
acceptance.

All durable state changes require human or project-governance approval
commensurate with the profile and risk.

## 12. Public Vocabulary

Public NAOS documentation should explain the system with this self-intuitive
model:

1. Define truth.
2. Index context.
3. Query candidates.
4. Package task context.
5. Review evidence.
6. Record decisions.

Cognitive/transformer theory belongs in whitepaper or article material, not as
primary README proof. Public README wording should stay practical:

- NAOS mitigates context drift and hallucination risk; it does not prevent
  hallucinations.
- Repository evidence remains authoritative.
- Deterministic means reproducible, source-linked, bounded, and reviewable; not
  perfect proof.
- Human review remains required for durable decisions.

## 13. Implications for Future Groups

Future groups must preserve this contract.

Required next groups:

- capability contract validator;
- SARIF exporter;
- static customization hooks;
- behavioral grading foundation;
- advisory runtime design only after the residual-risk contract is enforced.

Future advisory runtimes must not be implemented until they can emit the
residual-risk metadata described above and route discrepancies into
control-plane review.

## 14. Consequences

Positive consequences:

- Deterministic controls remain primary and reviewable.
- Advisory controls can still surface useful challenges, gaps, and review
  prompts.
- Human decision boundaries remain explicit in reports and docs.

Tradeoffs:

- Advisory capabilities need more metadata before they can influence durable
  decisions.
- Adopters must review discrepancies instead of treating any single report as a
  verdict.

## 15. Related Links/Files

- [docs/CONTROL_PLANE.md](../CONTROL_PLANE.md)
- [docs/CLAIMS_AND_LIMITATIONS.md](../CLAIMS_AND_LIMITATIONS.md)
- [docs/BEHAVIORAL_AUDIT_ENABLEMENT.md](../BEHAVIORAL_AUDIT_ENABLEMENT.md)
