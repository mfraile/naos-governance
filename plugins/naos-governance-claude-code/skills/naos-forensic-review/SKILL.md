---
name: naos-forensic-review
description: Perform NAOS-style forensic review from Claude Code. Use for branch, report, remediation, audit, or adapter review where evidence and boundaries must be challenged.
---

# NAOS Forensic Review

Use this skill for critical, evidence-backed review.

## Steps

1. Establish the target: branch, commit, report, plugin, integration, or project
   artifact.
2. Inspect local files, diffs, reports, and declared evidence before drawing
   conclusions.
3. Challenge whether findings were actually remediated or merely documented.
4. Separate confirmed facts, inferences, unknowns, residual risks, and out-of-
   scope items.
5. Recommend explicit NAOS commands when a deterministic report should support
   the review, including `naos spec-pack-contract --profile standard` when
   spec-pack template or generated-spec conformance is in scope,
   `naos spec-pack-materialize . --profile standard --dry-run` when
   profile-required spec files may be missing, and
   `naos spec-assembly-worksheet . --profile standard` when brownfield
   evidence, candidate requirements, or traceability gaps need spec mapping,
   and `naos package-reality --profile standard` when dependency/package
   reality is in scope, and `naos api-symbol-reality --profile standard` when
   declared API-symbol claims are in scope.

## Boundaries

Do not treat Claude memory, chat history, plugin presence, or hook output as
source authority. Project-local evidence and current user instructions outrank
advisory recall.
Do not treat Package Reality as package safety, malware absence, vulnerability
absence, SBOM completeness, provenance authenticity, supply-chain assurance,
registry trust, or dependency suitability.
Do not treat API Symbol Reality as API semantics, runtime behavior, option
compatibility, endpoint behavior, package safety, dependency suitability, or
proof that target modules were imported.
