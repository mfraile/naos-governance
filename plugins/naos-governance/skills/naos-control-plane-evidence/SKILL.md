---
name: "naos-control-plane-evidence"
description: "Use NAOS control-plane, evidence, gate, dashboard, and review-routing commands from Codex without overclaiming approval or compliance."
parameters: []
---

# NAOS Control-Plane Evidence

## When to Use

Use this skill when a change needs evidence refresh, gate posture, review item
routing, dashboard visibility, or residual-risk treatment.

## Commands

```bash
# Required before control-plane review for Standard and Assured only:
naos ai-component-inventory --profile <profile>
# Also run when the optional registry is installed:
naos agent-sponsor-registry --profile <profile>
# Also run when the optional AIVSS arithmetic module is installed:
naos aivss-verify --profile <profile>
naos control-plane-review --profile <profile>
naos systemic-impact --profile <profile>
naos plan-coherence --profile <profile>
# Optional only when comparing changed files to alignment path declarations:
naos plan-coherence --profile <profile> --diff-base <ref>
naos spec-pack-contract --profile <profile>
naos spec-pack-materialize . --profile <profile> --dry-run
naos spec-assembly-worksheet . --profile <profile>
naos ac-completion-evidence --profile <profile>
naos task-lifecycle --task <TASK-ID> --profile <profile>
naos task-complete --task <TASK-ID> --profile <profile>
naos research-record <record.yaml> --profile <profile>
naos composed-traceability --profile <profile>
naos harness-trace-import --source <repo-local.jsonl> --profile <profile>  # only when an explicit local harness export exists
naos behavioral-readiness --profile <profile>
naos ai-code-provenance --profile <profile>
naos compliance-posture --profile <profile>
naos design-traceability --profile <profile>  # optional when UI spec-object identity declarations exist
naos failure-mode-observations --profile <profile>  # optional when local report findings should be counted by failure mode
naos opencode-config-hygiene --profile <profile>  # optional when repo-local OpenCode config exists
naos package-reality --profile <profile>
naos api-symbol-reality --profile <profile>
naos memory-use-policy --profile <profile>
naos repository-intelligence status . --profile <profile>
naos repository-intelligence validate . --profile <profile>
naos ai-surface-budget --fresh-profiles --json
naos gate-status --profile <profile>
naos gate-evaluate --profile <profile>
naos evidence-attestation --profile <profile>
naos evidence-sign --profile <profile>
naos evidence-verify --profile <profile>
naos evidence-pack --profile <profile>
naos dashboard --profile <profile>
naos sarif-export --profile <profile>
```

## Boundary

AI Component Inventory is a custom declared-facts report. In Standard and
Assured, missing, malformed, stale, or incomplete required inventory routes to
G2/G6 human review before control-plane reliance. It is not CycloneDX, SPDX, a
software BOM, runtime discovery, completeness proof, signing, attestation,
supply-chain assurance, approval, release, or publication authority.

Agent Sponsor Registry is opt-in declared posture. When installed, gaps route
to G2/G6; it does not prove identity, credentials, authentication,
authorization, approval, or runtime behavior.

AIVSS arithmetic verification is opt-in assessor-supplied evidence. High or
Critical bands create score-review prompts; mismatches or integrity faults
create separate evidence-review prompts. All remain advisory G2/G6 input and
do not calculate CVSS, assess risk or exploitability, discover vulnerabilities,
observe runtime behavior, prove mitigation or security, approve, block,
prioritize, merge, release, accept risk, certify, publish, or prove compliance.

Evidence reports, gates, and dashboards are bounded review surfaces. Behavioral
readiness is baseline review input only; it does not create baselines. Plan
coherence is local coordination review only; optional diff-base path comparison
is advisory implementation-scope evidence only. It does not authorize, sequence,
approve, resolve work, or prove semantic drift. Evidence signing emits an
adopter-signable envelope and evidence verification recomputes local
tamper-evidence and reports signature-entry presence plus best-effort Git HEAD
metadata; NAOS does not sign, hold keys, validate third-party signatures,
authenticate identities, or
provide non-repudiation. AI Code Provenance is local evidence packaging only; it does not prove authorship,
ownership, legal sufficiency, publication readiness, or release readiness.
Compliance Posture is adopter-declared review metadata only; it does not decide
regulatory applicability, compliance status, certification, audit opinion, or
legal sufficiency. Package Reality is package, lock-style-pin, optional
docs-snippet, configured local SBOM/provenance/hash, and explicit opt-in
registry-metadata review evidence only; it does not prove package safety,
malware absence, vulnerability absence, SBOM completeness, provenance
authenticity, supply-chain assurance, registry trust, or dependency
suitability.
Design Traceability reviews local UI spec-object identity declarations only; it
does not inspect design tools, call MCP, synchronize code and design, mutate UI
tools, prove design quality, prove accessibility, approve implementation, or
activate provider/model/runtime behavior.
Failure-Mode Observations aggregate configured local report findings into
canonical failure-mode counts only. Dashboard, evidence-pack, SARIF,
gate-status, systemic-impact, and learning-loop consumers may surface those
counts as review evidence, but they do not read control-plane review as an
input, write learning records, mutate prompts/skills/workflows, use numeric
risk scores as authority, call providers/models, activate MCP/Engram/memory,
approve work, block gates, certify outcomes, authorize release, or prove
compliance.
OpenCode Config Hygiene reviews repo-local OpenCode configuration and
instruction surfaces only; it does not read global OpenCode settings, call
providers or models, enable MCP or memory, install plugins, validate
credentials, mutate OpenCode config, approve work, certify outcomes, or prove
runtime behavior.
API Symbol Reality checks explicitly declared Python symbols through source
inspection only; it does not import target modules or prove API semantics,
runtime behavior, option compatibility, endpoint behavior, package safety, or
dependency suitability.
AC Completion Evidence checks declared AC/SCEN evidence presence only; it does
not prove AC correctness, implementation correctness, complete coverage,
approval, certification, compliance, or hallucination prevention. Harness Trace
Import normalizes explicit local JSONL/NDJSON records into declared trace-event
shape; it does not execute harnesses, capture runtime events, activate hooks,
call providers/APIs, access the network, write memory, approve work, certify
outcomes, or prove behavior. These
surfaces are not release authorization, deployment
authorization, approval, certification, legal determination, or proof of
compliance.
Native completion preserves exact-id lifecycle history. A requested `verified`
transition is admitted only when explicit test, evidence, and schema-valid
approved `task_delivery` decision references pass the structural authority
checks; the resulting receipt remains structural evidence, not proof of genuine
human review or semantic test sufficiency. Unsupported legacy task statuses stay
review-required and cannot be silently normalized into delivery. Completion is
review-free only when it is delivered, verified, and has satisfied any recorded
verified-delivery prerequisites; canonical review reasons propagate through
lifecycle, gate, evidence, dashboard, task-context, and session projections.
Ordinary active and planned tasks are not review-routed by this completion
invariant. Completion is not merge, release, or evidence-admission authority.
Memory-use-policy evidence keeps policy-item validity separate from declared
access posture. Dashboard/evidence fields such as
`policy_item_valid_but_access_unverified` are review signals, never proof that
Engram, MCP tools, or the current project identity were live-verified.
Fresh-profile budget evidence is complete deterministic scaffold measurement,
not approval of a baseline, candidate, profile expansion, or pilot closure; it
writes nothing unless an explicit output path is supplied.
Research records remain candidates, and composed link presence is structural
evidence rather than semantic proof. Composed traceability keeps canonical
task-lifecycle review separate from traceability-quality review; its aggregate
human-review Boolean is only the logical OR of those dimensions and does not
turn traceability gaps into canonical lifecycle failures.
Repository-intelligence status and validation are source-binding and generated-
state checks only. FTS and graph results are retrieval candidates, not semantic
truth, requirements approval, complete coverage, or evidence of absence.
