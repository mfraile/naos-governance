---
name: naos-control-plane-evidence
description: Route Claude Code work through NAOS control-plane evidence. Use when the user asks what evidence, reports, gates, or dashboards should support a change.
---

# NAOS Control-Plane Evidence

Use this skill to choose evidence commands for a change.

## Steps

1. Identify the change type: adoption, implementation, audit, adapter, learning,
   security, docs, policy, release, or governance surface.
2. Recommend the narrowest relevant NAOS reports.
3. Keep evidence project-local under `naos/reports/`, `naos/evidence/`, or the
   configured NAOS root.
4. Explain limitations: reports are review aids, not approval or proof.

## Common Commands

```bash
naos self-check --profile standard
naos ai-component-inventory --profile standard
# Also run when the optional registry is installed:
naos agent-sponsor-registry --profile standard
# Also run when the optional AIVSS arithmetic module is installed:
naos aivss-verify --profile standard
naos control-plane-review --profile standard
naos plan-coherence --profile standard
# Optional only when comparing changed files to alignment path declarations:
naos plan-coherence --profile standard --diff-base <ref>
naos spec-pack-contract --profile standard
naos spec-pack-materialize . --profile standard --dry-run
naos spec-assembly-worksheet . --profile standard
naos ac-completion-evidence --profile standard
naos task-lifecycle --task T-001 --profile standard
naos task-complete --task T-001 --profile standard
naos research-record naos/research/RESEARCH-001.yaml --profile standard
naos composed-traceability --profile standard
naos harness-trace-import --source <repo-local.jsonl> --profile standard  # only when an explicit local harness export exists
naos behavioral-readiness --profile standard
naos ai-code-provenance --profile standard
naos compliance-posture --profile standard
naos design-traceability --profile standard  # optional when UI spec-object identity declarations exist
naos failure-mode-observations --profile standard  # optional when local report findings should be counted by failure mode
naos opencode-config-hygiene --profile standard  # optional when repo-local OpenCode config exists
naos package-reality --profile standard
naos api-symbol-reality --profile standard
naos memory-use-policy --profile standard
naos repository-intelligence status . --profile standard
naos repository-intelligence validate . --profile standard
naos ai-surface-budget --fresh-profiles --json
naos gate-status --profile standard
naos evidence-attestation --profile standard
naos evidence-sign --profile standard
naos evidence-verify --profile standard
naos evidence-pack --profile standard
naos dashboard --profile standard
naos sarif-export --profile standard
```

## Boundaries

AI Component Inventory is the required Standard/Assured custom declared-facts
input before control-plane review. Missing, malformed, stale, or incomplete
required inventory routes to G2/G6 human review. It is not CycloneDX, SPDX, a
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

Do not claim compliance, certification, approval, release authorization,
deployment authorization, behavioral baseline creation, legal sufficiency,
authorship proof, ownership proof, regulatory applicability, compliance status,
publication readiness, or release readiness from report existence alone. Plan
coherence does not authorize, sequence, approve, resolve work, or prove semantic
drift. Optional diff-base path comparison is advisory implementation-scope
evidence only. Package Reality can include configured local
SBOM/provenance/hash evidence but does not prove package safety, malware
absence, vulnerability absence, SBOM completeness, provenance authenticity,
supply-chain assurance, registry trust, or dependency suitability. AC
Completion Evidence checks declared AC/SCEN evidence presence
only; it does not prove AC correctness, implementation correctness, complete
coverage, approval, certification, compliance, or hallucination prevention.
API Symbol Reality checks explicitly declared Python symbols through source
inspection only; it does not import target modules or prove API semantics,
runtime behavior, option compatibility, endpoint behavior, package safety, or
dependency suitability.
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
Harness Trace Import normalizes explicit local JSONL/NDJSON records into
declared trace-event shape; it does not execute harnesses, capture runtime
events, activate hooks, call providers/APIs, access the network, write memory,
approve work, certify outcomes, or prove behavior.
Evidence signing emits an optionally signable envelope; evidence verification
recomputes local digests and reports signature-entry presence plus best-effort
Git HEAD metadata. These surfaces do not make NAOS a signer, key custodian,
third-party signature validator, identity authenticator, non-repudiation
provider, or compliance authority.
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
