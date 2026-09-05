---
name: "naos-forensic-review"
description: "Use a forensic, evidence-first review style for NAOS-governed repositories from Codex without treating advisory findings as truth."
parameters: []
---

# NAOS Forensic Review

## When to Use

Use this skill when reviewing a NAOS branch, feature, report, remediation,
optional integration, plugin surface, or release candidate.

## Method

1. Confirm branch, commit, clean state, and scope.
2. Read deterministic source artifacts before relying on summaries.
3. Classify the target: repo, branch, optional adapter, plugin, report, or release surface.
4. Build topology: scripts, schemas, CLI, Make targets, policies, docs, skills, agents, workflows, tests, evidence, dashboard, and adapter surfaces.
5. Run or recommend deterministic validators.
6. Challenge the result for ghosts: stale paths, orphan schemas, duplicated claims, false approvals, hidden runtime enablement, and adapter drift.
7. Confirm findings against source lines and command output.
8. Route unresolved items through `naos control-plane-review` or explicit remediation.

## NAOS Commands

```bash
naos self-check --profile <profile>
naos spec-pack-contract --profile <profile>
naos spec-pack-materialize . --profile <profile> --dry-run
naos spec-assembly-worksheet . --profile <profile>
naos package-reality --profile <profile>
naos api-symbol-reality --profile <profile>  # when API-symbol claims are declared
naos systemic-impact --profile <profile>
naos control-plane-review --profile <profile>
naos adapter-coherence --profile <profile>
```

## Boundaries

Findings are review inputs until confirmed. Reports do not approve work, certify
compliance, replace repository evidence, or substitute for human review.
Package Reality does not prove package safety, malware absence, vulnerability
absence, SBOM completeness, provenance authenticity, supply-chain assurance,
registry trust, or dependency suitability.
API Symbol Reality does not import target modules or prove API semantics,
runtime behavior, option compatibility, endpoint behavior, package safety, or
dependency suitability.
