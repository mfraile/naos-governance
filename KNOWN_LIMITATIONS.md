# Known Limitations

NAOS is a governance-as-code kit for AI-assisted software development. It is intentionally file-first and deterministic by default. These limitations are part of the public release posture.

## Candidate Status

- Version 1.1.0 is a publication candidate prepared for history-free repository
  verification, not a published release. The deterministic export receipt,
  artifact hashes, repository state, and hosted CI results are
  integrity and execution evidence, not signatures, attestations, approvals,
  public visibility, release, or publication authority.
- Maintainer-only records and source history are not part of the distributed
  candidate. Public validation therefore uses current content hashes and
  portable evidence rather than undistributed commit or tree identifiers.
- Public-candidate CI is a narrow Ubuntu/Python 3.11 build, clean-install,
  regulatory, Quickstart, Standard, documentation, and Mermaid-source smoke.
  It does not reproduce the wider maintainer suite or prove every supported
  operating system and Python combination.

## Assurance Limits

- NAOS mitigates context drift and hallucination risk; it does not prevent hallucinations.
- NAOS evidence does not certify legal, regulatory, compliance, runtime, security, or test-completeness outcomes.
- Deterministic means reproducible, source-linked, bounded, and reviewable; it does not mean perfect proof.
- Static/file-first controls do not fully prove runtime behavior in dynamic frameworks.
- Human review remains required for durable decisions.

## Runtime Limits

- No automatic context injection is enabled by default.
- No automatic memory write-back is enabled by default.
- No live Engram or MCP runtime is enabled by default.
- No sqlite-vec/vector runtime is enabled by default.
- No embeddings, provider/model calls, or API keys are required by default.
- No graph runtime, graph database, NetworkX, GraphML, PageRank, centrality, community detection, or global traversal is enabled by default.
- Brownfield repository intelligence uses deterministic SQLite/FTS as its baseline. Optional NetworkX/GraphML requires an eligible executed relationship model and the exact optional dependency; GraphML remains derived navigation evidence. No sqlite-vec workload is currently defined.
- For Standard-profile greenfield and brownfield adopters, SQLite/FTS remains the default local retrieval layer. The 1.1.0 candidate adds no Standard-default semantic runtime, embedding provider, or general-purpose graph activation. Its existing project-configured function-index similarity hook remains disabled by default and non-core.
- The repository-intelligence command and schemas remain in the installed NAOS package or kit checkout rather than being duplicated into each generated project. Project-local immutable generation state remains usable through that runtime; a copied scaffold alone is not a standalone repository-intelligence executable.

## Existing-Project Upgrade Limits

- Normal `naos upgrade PROJECT --tier T` and `--dry-run` are identical plan-only operations. They generate outside the adopter project, classify the complete managed inventory from recorded base/current/new identities, and do not mutate the target.
- `--plan-out` atomically creates an absent external immutable plan. Apply is a separate invocation requiring both that file and its exact SHA-256 digest; apply never replans and revalidates provenance, current content, topology, source policy, and regenerated sources before mutation.
- Only validated `kit_owned_derived` regular files whose current identity still equals their recorded base are eligible for replacement. Adopter-owned, ambiguous, modified, unsafe, and out-of-scope paths are preserved and reported. Equality, Git history, paths, headers, or template membership never bootstrap ownership.
- Projects without valid managed provenance are diagnostic-only and refuse apply. Existing v1 provenance is migrated without promoting adopter-owned entries, and source-policy versions remain bound to the provenance that recorded them.
- `naos upgrade --recover` resumes or rolls back managed transactions. Replacement support is limited to the executed Darwin regular-file metadata tuple, same-filesystem staging, and ordered atomic leaf replacement; it does not provide globally atomic multi-file visibility.
- Legacy `--force` is permanently refused. Fixed upgrade checks run in process and never execute project hooks or arbitrary project validators. NAOS makes no cryptographic-reviewer, hostile-validator-isolation, or network-denial guarantee for this workflow.
- Windows, Linux, network filesystems, ACL/xattr preservation, DACL/ADS/reparse-point behavior, and portable crash consistency are unsupported for mutation and fail closed where applicable.
- Initial unmanaged `naos init --activate` remains a provenance-bound create-only installation. On an already managed project, `init --activate` and profile changes route to the same plan-only upgrade workflow and cannot bypass the separate digest-bound apply invocation.
- Signal detection may follow symbolic links at recognized input paths such as `requirements.txt`; the preview is not a project-bounded confidentiality boundary.

## Professional Adoption Report-Write Limits

- `naos adopt --dry-run` writes deterministic review reports only when the host provides the secure directory-descriptor operations used to bind parent traversal, temporary creation, and replacement to an opened directory. If that primitive is unavailable, the command fails before report-path creation instead of using the portable fallback for strict writes.
- `naos adopt --no-write-preview` remains available on those hosts and evaluates the same phases without report or activation writes.
- This boundary does not claim crash consistency, hostile mount replacement protection, network-filesystem atomicity, Windows reparse-point/DACL/ADS coverage, or ACL/xattr preservation.

## Initialization Preview Limits

- `naos init --dry-run` builds in a unique external temporary directory, removes that directory on exit, and does not modify the target project. It cannot be combined with `--preview-dir`.
- A persistent `naos init --preview-dir` destination must be absent. Inside the target, only the direct `TARGET/.naos-preview` path is supported; any other persistent preview path must be outside the target so it cannot contaminate project detection. Existing files, directories, and symbolic links are preserved and refused because current previews have no provenance that authorizes replacement.
- Persistent preview generation is not transactional. If generation fails, the command reports `PREVIEW_FAILED` and leaves the partial preview for inspection; remove it explicitly or choose a new absent path before retrying.
- Default initial `naos init --activate` regenerates into separate external temporary staging and leaves any persistent review preview unchanged. The activation is not digest-bound to that earlier preview; rerun with the same reviewed kit source and arguments, and review the activation output. For a valid already managed project, init is plan-only and delegates the transition to `naos upgrade`.
- Initial scaffold activation preflights the complete generated source and destination set and refuses symbolic-link/non-directory ancestors, unsafe leaves, and every unproven existing destination; `--force` is refused. Apply uses an exclusive lock, same-filesystem staging, durable journal, atomic leaf publication, receipt, and restart recovery. It is not a single multi-path snapshot and is not an existing-content/profile-transition upgrade mechanism.
- For literal host `ruff check .` or `ruff format ... .` commands, brownfield activation can add nested managed `.ruff.toml` discovery markers inside generated roots proved to contain no pre-existing adopter Python. The `naos_tools/` marker is kit-owned; the `.github/autoresearch/` marker is a create-once adopter-owned seed. No pre-existing adopter Ruff file is modified. Mixed Python roots and detected `--config`/`--isolated` invocations refuse. Later manual Python placed inside a reserved excluded root, explicit generated-file arguments, aliases, wrappers, and non-Ruff lint engines remain outside this bounded compatibility adapter.
- Installed package resources may inherit an installation-directory group such as `wheel`; that installation GID is not treated as adopter-project ownership. Each transaction records the GID of its actual planned source (which may be a generated preview) and binds created managed leaves to the executing user's primary group.
- When an existing project owns a non-empty, unmanaged `scripts/` namespace and the setup catalogue could later add Python there, the generated preview, setup catalogue, and exact generated references are remapped to `naos_tools/` before the plan digest is frozen. Configured pytest paths and recursive host-test scans are retained as supporting collision evidence. Detection is bounded; other blocking host-collection collisions are preserved and refused.
- Normal completion and Python exceptions unwind temporary-preview cleanup. Process termination, machine loss, or filesystem cleanup failure can leave external temporary residue; none of those conditions authorizes target mutation.

## Progressive Add Limits

- `naos add` and setup-module operations require valid managed-content provenance. Genuinely absent single-file additions retain a simple provenance-bound atomic create route; trees and multi-action modules use one managed transaction.
- An existing collision is classified through the shared ownership contract. An eligible, unchanged `kit_owned_derived` replacement requires an external `--plan-out` file and the central digest-bound `naos upgrade --apply-plan ... --expect-plan-digest ...` invocation. Adopter-owned or modified paths, including `AGENTS.md` and configuration, are preserved with manual-action findings.
- `--force` is a refused legacy compatibility flag and never grants replacement authority. A deleted adopter-owned or otherwise ineligible path is preserved rather than silently recreated.
- One apply invocation uses the managed exclusive lock, same-filesystem staging, durable journal, receipt, rollback, and restart recovery. Multiple invocations are separate transactions, and multi-path publication is not a single visible snapshot.
- The executed adapter does not claim network-filesystem behavior, Windows reparse-point/DACL/ADS support, ACL/xattr preservation, or portable crash consistency outside the tested platform/metadata tuple.

## Spec-Pack Materialization Limits

- `naos spec-pack-materialize` validates the manifest schema, full profile-inheritance graph, path inventory, and complete selected source/destination plan before changing spec files. It does not cross-check `files[].required_profiles` metadata against every `profiles.*.required_files` membership; both the materializer and contract execute from the profile required-files lists. It also rejects symlinked in-project report ancestors, non-regular or multiply-hardlinked report leaves, and probes basic writability. Explicit external report paths are operator-selected and canonicalized; their existing ancestor symlinks are not treated as project-containment paths. A preflight refusal changes no spec file; when no report path is configured, evidence is stdout-only.
- `--force` replaces only a regular destination file inside the project. It does not authorize symbolic-link traversal, special-file replacement, path escape, missing-source substitution, or invalid-manifest acceptance.
- Apply is enabled only for the executed macOS/POSIX adapter tuple. Every other platform tuple, including Linux/POSIX, fails closed; dry-run/report evaluation remains available.
- Each copied leaf uses a same-directory temporary before link or replacement, but a multi-file run is sequential and has no rollback. A runtime filesystem failure can leave the current or earlier leaf copies in place and requires inspection before retry. If an absent target is installed but temporary cleanup then fails, the target remains counted as copied, the residue path is a blocking `copy_cleanup_failed` finding, and remaining copies stop.
- Report preflight cannot guarantee the later write against disk exhaustion, permission/topology changes, or other runtime failures. If a report write fails after apply, the command exits nonzero and emits a blocked stdout report that truthfully retains copied-file counts. A failed probe cleanup can leave a `.naos-spec-pack-report-probe-*` file for manual removal.
- The current checks do not prove protection against hostile concurrent ancestor replacement, mount or bind-mount changes, network-filesystem semantics, Windows reparse-point/DACL/ADS behavior, ACL or xattr preservation, or crash consistency.

## Memory Limits

- Memory is advisory by default.
- Reviewed and provenance-backed memory can support context, but repository evidence remains authoritative.
- Instruction-grade memory requires explicit approval, provenance, scope, reviewer, timestamp, freshness/expiry, and a human boundary.
- NAOS does not read private memory payloads or Engram databases by default.
- Durable memory writes require configured, authorized, verified, memory-use-policy-permitted access plus human approval.

## Evidence Limits

- Context packs, local indexes, query reports, graph reports, semantic readiness reports, session reports, evidence packs, and dashboards are derived artifacts.
- Local context query results are candidates, not answers.
- Graph query results are relationship candidates, not truth.
- Evidence attestation uses local digests and reviewer metadata; it is not cryptographic signing or tamper-proof storage.
- Evidence conflict detection flags deterministic review conflicts and metadata gaps; it does not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance.
- SARIF export is a findings interoperability format. It is not attestation, approval, certification, maturity promotion, compliance proof, or source authority.
- The custom `ai_component_inventory.v1` report inventories repository declarations and content digests only. It is not CycloneDX/SPDX conformance, a software BOM, runtime discovery, completeness proof, signing, attestation, provenance authentication, supply-chain assurance, compliance approval, release authority, or publication authority.
- The optional `agent_sponsor_registry.v1` report checks declared current-agent coverage, opaque sponsor/owner/control references, categorical credential posture, registry-review expiry, safe regular-file paths, and local content integrity. Its `generated_at` value is format-checked, bound by the report digest, and rejected when future-dated, but neither that past timestamp nor the unsigned report is independently authenticated. It does not verify a person, sponsor approval, authentication, authorization, delegation, separation of duties, credential existence or lifetime, runtime identity/enforcement, SPIFFE/SPIRE, OAuth/OBO, mTLS, signing, attestation, compliance, release, or publication authority.
- The optional AIVSS-Agentic v0.8 verifier recalculates assessor-supplied arithmetic against a PDF pinned by URL and SHA-256. It does not calculate or validate CVSS, select or verify subjective factors, discover vulnerabilities, assess risk or exploitability, observe runtime behavior, prove mitigation or security, approve, block, prioritize, merge, release, accept risk, certify, attest, publish, or prove compliance. High/Critical score prompts and separate arithmetic/integrity prompts are advisory G2/G6 review input only; 0.0 remains unbanded because the pinned PDF defines no band for it.

## Advisory Control Limits

- Advisory controls may challenge deterministic controls. They may not replace them.
- Semantic similarity, sqlite-vec/vector candidates, embeddings, graph analytics, memory discrepancy detection, and LLMGrader-style second opinions are optional or future/project-configured advisory controls.
- StaticGrader is deterministic and structural only; it does not prove semantic correctness, behavioral safety, runtime behavior, legal/regulatory posture, or hallucination risk.
- Deterministic hygiene reports reduce obvious duplicate-body, secret-like, weak-test, and undeclared-import risk classes; they do not prove semantic correctness, secret-free code, behavioral correctness, package safety, vulnerability absence, supply-chain assurance, approval, certification, compliance, or runtime safety.
- Control is a 2-D lattice (profile severity × capability maturity L0–L5): a capability enforces at its profile severity only once current maturity reaches target; below target it downgrades to advisory. This is enforcement posture, not approval or proof of correctness.
- The graduated profile `exit_code` ramp ships in a `warn` transition mode by default (v1-compatible exit codes while previewing what would block); full enforcement is an explicit opt-in (`enforcement_transition: enforce`).
- Capability `current_maturity` is an adopter self-declaration in `capability_state.yaml` ("not proof"); promotion remains a human governance decision. The kit evaluates readiness and flags unsupported declarations for review; it does not cryptographically bind or auto-promote maturity.
- Audit mode is deterministic review input, not audit approval.
- Drift mode compares deterministic reports; it does not infer semantic drift.
- Assess mode summarizes posture; it is not certification.
- LLMGrader readiness is configuration/reporting posture only in this release scope: runtime is disabled by default, StaticGrader remains primary, no provider/model/API dependency or credential handling is enabled, no default cost is incurred, and future advisory use requires cost, data exposure, bias/drift, residual-risk, and human-approval controls.
- Advisory controls can produce candidates, warnings, discrepancy findings, and review prompts; they cannot approve work, certify compliance, promote maturity, prove task completion, or become sole pass/fail authority.
- Future advisory controls must record residual-risk metadata and route discrepancies to human review before durable project state changes.

## Hashing and Signing Limits

- NAOS produces hashable/signable artifacts, but it does not sign on behalf of adopters.
- NAOS emits a deterministic tamper-evidence root (`manifest_root_digest`, on by default) and a DSSE-style **signable envelope** (`naos evidence-sign`). `naos evidence-verify` recomputes local digests and reports signature-entry presence plus best-effort Git HEAD metadata. It does not validate envelope signatures, apply an independent trust or acceptance policy to Git's commit-signature status, authenticate an identity, require signing, hold keys, issue certificates, or provide non-repudiation.
- Tamper-evidence detects post-hoc edits to covered artifacts. The compatibility-named `identity_binding` field reports Git's local HEAD signature status, signer text when Git supplies it, and commit-author metadata; NAOS does not treat those fields as verified identity. None of these outputs is a signature by NAOS, approval, certification, or a compliance opinion.
- Adopters own signing, keys, custody, notarization, timestamping, attestation authority, and external archival.
- Use "checksum" or "digest" unless actual signing exists.
- New digest-oriented designs should default to SHA3-512 unless implementation constraints require otherwise, while preserving SHA-256 compatibility where existing tooling or reviewer workflows depend on it.
- NAOS does not claim quantum-proof security.

### What regulation actually requires here (clarification)

This signing boundary is frequently over-read. To avoid confusion, the limitation
above and the underlying regulatory requirement are deliberately separated. This
describes regulatory *direction* and is **not legal advice**; it is not a claim
that NAOS satisfies any regime.

- **Commonly demanded across regimes** — EU AI Act Annex IV / Art. 11 ("test
  logs and reports dated and signed by the responsible persons", 10-year
  retention); 21 CFR Part 11 (audit trail time-stamped and append-only; each
  e-signature unique to one individual); eIDAS; and named sign-off in
  pharma/avionics/finance — is a **tamper-evident, time-stamped,
  uniquely-attributable record** plus a **named responsible-person signature at
  defined human gates**. This implies **identity binding**, not a cryptographic
  certificate issued to every developer, project manager, or contributor.
- **A per-individual qualified certificate** is required **only** where a regime
  mandates a qualified/advanced electronic signature (eIDAS Qualified Electronic
  Signature; 21 CFR Part 11 *open* systems) — and then only for the **specific
  accountable signatory** (e.g., the approver or Qualified Person), **not the
  whole team**.
- **Developer / CI-layer provenance** (US EO 14028 / NIST SSDF; SLSA; Sigstore)
  is signed at **build or organisation identity**, increasingly via **ephemeral
  keyless OIDC** — explicitly **not** a durable certificate per contributor.

What this means for NAOS, concretely:

- **Provided today:** reviewable evidence records; SHA-256/SHA3 digests; the
  signable artifact/envelope; and human sign-off metadata that names the
  declared reviewer.
- **Adopter-owned by design (ADR-0007, "no keys in kit"):** signing key
  material, signature validation, identity authentication, certificate custody,
  notarization, and timestamping. NAOS does not verify signed-commit, CI, SSO, or
  OIDC identities and does not issue or hold keys. When applicable, the adopter
  selects and operates the external signing and verification mechanism required
  by its own context.

## Publication Limits

- The public release candidate excludes internal audits, private project material, runtime reports, generated adopter `naos/` directories, memory payloads, local machine paths, and generated SQLite/database artifacts.
- Current candidate checks cover source review, sanitized export regeneration,
  clean-install acceptance, public regulatory validation, generated-profile
  smoke tests, documentation/tutorial consistency, and Mermaid-source linting.
  Publication, tagging, and GitHub release creation remain separate maintainer
  actions.
- Pilot validation against private reference projects is deferred and is not part of the default public kit.
- Package distribution format is a publication decision; the sanitized archive remains the primary candidate artifact unless the release explicitly includes wheel/sdist artifacts.
