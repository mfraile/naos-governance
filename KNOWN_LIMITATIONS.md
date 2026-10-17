# Known Limitations

NAOS is a governance-as-code kit for AI-assisted software development. It is intentionally file-first and deterministic by default. These limitations are part of the public release posture.

## Release and candidate scope

- Identify the exact source/export bytes and their release receipt separately.
  The historical release posture is described in `SECURITY.md`; later local
  changes are not automatically part of that release. A package version or
  prepared candidate alone does not establish publication of the current bytes.
  Export receipts, artifact hashes, repository state and hosted CI results are
  integrity/execution evidence, not signatures, attestations, approval, public
  visibility, release or publication authority.
- Maintainer-only records and source history are not part of the distributed
  candidate. Public validation therefore uses current content hashes and
  portable evidence rather than undistributed commit or tree identifiers.
- Public-candidate CI is a narrow Ubuntu/Python 3.11 build, clean-install,
  regulatory, Quickstart, Standard, documentation, and Mermaid-source smoke.
  It does not reproduce the wider maintainer suite or prove every supported
  operating system and Python combination.

## Current selected platform baseline

The selected D5 application baseline dated 17 October 2026 is documented in
[platform implementation and verification](docs/PLATFORM_ADAPTERS.md#selected-current-d5-baseline-17-october-2026).
That status applies only after root acceptance of all nine same-scenario current
J2 cells and only to the routes stated there. The 18 D5 artifact installations
and nine ordinary managed chains do not qualify every profile or history branch.
Any documentation successor requires its own source/artifact and installation
bindings. Qualification is artifact-specific; the original D5 hashes identify
only the original pair.

## Assurance Limits

- NAOS mitigates context drift and hallucination risk; it does not prevent hallucinations.
- NAOS evidence does not certify legal, regulatory, compliance, runtime, security, or test-completeness outcomes.
- Deterministic means reproducible, source-linked, bounded, and reviewable; it does not mean perfect proof.
- Static/file-first controls do not fully prove runtime behavior in dynamic frameworks.
- Human review remains required for durable decisions.

## Runtime Limits

- Audit-event storage uses compact ASCII SHA256 basenames derived from the four original naming inputs; logical event IDs and event JSON remain unchanged. Exact prior deterministic filenames remain readable without renaming. Compact names reduce Windows path pressure but do not guarantee support for arbitrarily long project paths; audit write failures remain explicit findings.
- No automatic context injection is enabled by default.
- No automatic memory write-back is enabled by default.
- No live Engram or MCP runtime is enabled by default.
- No sqlite-vec/vector runtime is enabled by default.
- No embeddings, provider/model calls, or API keys are required by default.
- No graph runtime, graph database, NetworkX, GraphML, PageRank, centrality, community detection, or global traversal is enabled by default.
- Repository-intelligence baseline enrollment/apply/query/recovery has bounded native macOS ARM64, Ubuntu x86_64 and Windows 11 x64/NTFS evidence on CPython 3.11–3.13. Actual brownfield activation and selected profile transitions pass on all three with Python 3.11. Source-candidate evidence remains separate from full workflow/minor/artifact qualification and optional GraphML. Incomplete unwitnessed enrollment/bootstrap/preparation objects remain preserved/refused; complete witnessed Windows preparation interrupted before journal creation has separate explicit rollback coverage. No universal automatic recovery is claimed.
- Brownfield repository intelligence uses deterministic SQLite/FTS as its baseline. Optional NetworkX/GraphML requires an eligible executed relationship model and the exact optional dependency; GraphML remains derived navigation evidence. No sqlite-vec workload is currently defined.
- For Standard-profile greenfield and brownfield adopters, SQLite/FTS remains the default local retrieval layer. The 1.1.0 candidate adds no Standard-default semantic runtime, embedding provider, or general-purpose graph activation. Its existing project-configured function-index similarity hook remains disabled by default and non-core.
- Reviewed RI engine refresh binds the exact prior state in `refresh_base`; only engine/public-reader hashes may change within the unchanged custody/runtime/schema contract. Public old-generation readers remain strict. Legacy plans cannot authorize an engine transition, and oversized prior witness capture (4096 files or 256 MiB) refuses. This is not native history migration or cross-version runtime qualification. A fresh Windows plan for exact current content may acknowledge existing activation under full native reader pins; it writes no new approval/receipt. The v2 result distinguishes the confirmed plan from the original persisted activation digest. Different reviewer/authorization, stale/corrupt state or a historical reservation cannot use this path; native qualification of this correction is pending.
- The repository-intelligence command and schemas remain in the installed NAOS package or kit checkout rather than being duplicated into each generated project. Project-local immutable generation state remains usable through that runtime; a copied scaffold alone is not a standalone repository-intelligence executable.

## Existing-Project Upgrade Limits

- Managed writes enforce the [filesystem metadata policy](docs/PLATFORM_ADAPTERS.md#filesystem-metadata-policy), separately from package installation. Linux transports only `user.*` source extended attributes and refuses other namespaces without copying preview security labels; extended/default ACLs and unsupported inherited inode flags remain refused. Exact destination metadata checks remain required. Windows cloud placeholders, reparse points and compressed/encrypted paths remain outside the qualified contract; a OneDrive folder name alone is not proof of refusal or support. Intel macOS, later Python minors, Linux aarch64 and live cloud hydration are not qualified by the executed native matrix.
- Normal `naos upgrade PROJECT --tier T` and `--dry-run` are identical plan-only operations. They generate outside the adopter project, classify the complete managed inventory from recorded base/current/new identities, and do not mutate the target.
- `--plan-out` atomically creates an absent external immutable plan. Apply is a separate invocation requiring both that file and its exact SHA-256 digest; apply never replans and revalidates provenance, current content, topology, source policy, and regenerated sources before mutation.
- External plan publication checks the held file's identity and bytes and its parent directory before reporting success on the executed macOS adapter. On failure, pending or destination entries may remain for inspection; NAOS does not delete uncertain entries. These checks establish a point-in-time observation, not protection against later changes by another writer. Inspect the reported paths before retrying with a new absent destination.
- Only validated `kit_owned_derived` regular files whose current identity still equals their recorded base are eligible for replacement. Adopter-owned, ambiguous, modified, unsafe, and out-of-scope paths are preserved and reported. Equality, Git history, paths, headers, or template membership never bootstrap ownership.
- Projects without valid managed provenance are diagnostic-only and refuse apply. Existing v1 provenance is migrated without promoting adopter-owned entries, and source-policy versions remain bound to the provenance that recorded them.
- Windows diagnostic plans use native observations and explicitly labeled default candidate inputs, without inferring preserved choices from adopter files. Their separate diagnostic schema cannot authorize apply, even with a recomputed digest. Optional plan files remain outside the project and use the native absent-only writer.
- Generated `.gitattributes` pins selected generated text to LF without normalizing existing bytes or historical hashes. Existing unmanaged or locally modified rules are preserved. Brownfield activation and managed profile regeneration require a tracked/staged unmanaged policy with effective LF rules for every generated text path in the working tree, index and portable index. Machine-global/system attributes cannot supply the portable proof; any repository-local `info/attributes` entry conservatively refuses it, including empty files and linked-worktree shared entries. Preview remains available. These are line-ending checks, not a classification of arbitrary Git content transformations. They do not remove machine/root binding from managed provenance or migrate legacy CRLF content.
- `naos upgrade --recover` resumes or rolls back managed transactions through the selected platform adapter. POSIX replacement uses same-filesystem staging and ordered atomic leaf exchange. Windows uses its separate held-handle, application-process-failure protocol. Neither provides globally atomic multi-file visibility. See [platform implementation and verification](docs/PLATFORM_ADAPTERS.md) for executed coverage.
- Portable v3 update support remains under development. Present v3 storage cannot fall back to legacy mutation. Supported completed same-root rebind/operation history permits explicitly selected reviewed v3 profile plans; existing public v2 approvals retain their original semantics. Read-only no-op and exact historical completed-plan retry create no receipt/journal and do not prove current files unchanged. Recovery requires exact private replay and native authority; portable history alone is insufficient. Managed v3 init and add/setup now use plan-only review and separate exact-plan apply on completed same-root history; their combined native qualification is pending. Explicit public receiving rebind is implemented only when both local and legacy stores are absent; it preserves existing edits/deletions and has macOS/Windows source evidence on Python 3.11–3.13, with Ubuntu and installed-artifact qualification pending. Completed migration predecessors are integrated with focused macOS evidence; their full native qualification remains pending. The explicit public migration plan/apply/recovery interface is implemented, with native qualification in progress. Completed populated-store receiving now has a separate explicit inspect/plan/apply/recovery route, preserving old evidence and requiring a new native binding. Three macOS Python 3.13 source scenarios and the 25-test receiving suite on Ubuntu Python 3.11–3.13 passed. Earlier Windows receiving and migration-origin managed-update failures are retained historical evidence. Source-bound installed receiving/rebind acceptance recorded on 2026-10-13 covers managed-project clone, controlled same-path restore and same-checkout Python-minor transitions on macOS, Ubuntu and Windows. Those later selected-route results do not by themselves establish resolution of the exact earlier failure cases. The separate selected D5 baseline documented in the platform guide adds only its named receiving-to-Quickstart J2 route and artifact/managed-chain scopes; it does not qualify every history variant or resolve those exact earlier failures. Any successor requires its own artifact bindings and installation qualification. Copied local controls must already meet receiving-user private-storage policy; ordinary Windows copies may lose it and correctly refuse. A security-preserving cross-account transfer is not yet qualified. Managed removal operations remain unfinished. Native inventory/replay limits and complete generated-profile/installed-artifact qualification remain explicit in [platform adapters](docs/PLATFORM_ADAPTERS.md).
- Legacy `--force` is permanently refused. Fixed upgrade checks run in process and never execute project hooks or arbitrary project validators. NAOS makes no cryptographic-reviewer, hostile-validator-isolation, or network-denial guarantee for this workflow.
- Linux and Windows mutation adapters are implemented; implementation and native qualification are separate. Bounded native Ubuntu/ext4 and Windows 11 x64/NTFS recovery probes have executed on CPython 3.11–3.13; The selected D5 artifact, ordinary managed-chain and receiving-to-Quickstart J2 evidence is scoped in [platform implementation and verification](docs/PLATFORM_ADAPTERS.md#selected-current-d5-baseline-17-october-2026); broader operation, profile and history coverage remains outside that qualification. Network filesystems, arbitrary ACL/xattr preservation, unsupported Windows attributes/ADS/reparse points, and power-loss consistency remain outside the qualified contract and are refused where applicable.
- Legacy Windows operation-v1 recovery requires provable saved identities and topology. Attribute restoration is limited to the NORMAL/ARCHIVE substitution that reproduces the complete original metadata digest. Missing original timestamp authority or unproven security changes stop automatic recovery and retain files and journals for manual recovery; no missing values are inferred. New production writes use operation-v2 metadata witnesses. Native legacy-refusal acceptance remains separate from this compatibility policy.
- Windows update staging preserves an approved unchanged NORMAL or ARCHIVE attribute under the existing protected-DACL policy. The selected Windows 11 CPython 3.11 J2 RULES route records ARCHIVE `0x20` before and after replacement/repair; this does not establish NORMAL `0x80`, all attribute branches, cross-account ACL transfer or arbitrary metadata. Historical attribute drift is still preserved as a conflict. Other write/close/publication combinations remain unverified; supported metadata classes and historical digest checks are unchanged.
- Initial unmanaged `naos init --activate` remains a provenance-bound create-only installation. On an already managed project, `init --activate` and profile changes route to the same plan-only upgrade workflow and cannot bypass the separate digest-bound apply invocation.
- Signal detection may follow symbolic links at recognized input paths such as `requirements.txt`; the preview is not a project-bounded confidentiality boundary.

## Professional Adoption Report-Write Limits

- `naos adopt --dry-run` writes deterministic review reports through anchored native directory operations: directory descriptors on POSIX, held no-follow parents and same-directory staging on Windows. Unsupported native platforms still refuse strict publication; there is no pathname-based fallback for strict writes.
- Windows report refresh preserves supported owner/group/DACL (including ordinary inherited DACLs) and NORMAL/ARCHIVE attributes, verifying after publication and close. Unsupported metadata, reparse parents, multiply-linked/nonregular leaves and preservation mismatches refuse. New report directories/files use ordinary inherited security; private managed-upgrade policies remain separate.
- Publication refreshes an authorized report name under its anchored parent; it is not compare-and-swap of a destination identity. Initial publication refuses an appearing foreign destination. Individual reports replace atomically; the complete multi-report adoption sequence is not one transaction.
- `naos adopt --no-write-preview` evaluates phases without report or activation writes. This boundary does not claim power-loss consistency, hostile volume/mount replacement protection, network-filesystem atomicity, arbitrary ACL/SACL/xattr preservation, or support for Windows ADS/reparse files.

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
- Apply implements native macOS, Linux and Windows operations on CPython 3.11–3.13. Qualification is bounded to the native hosts and cases recorded in `docs/PLATFORM_ADAPTERS.md`; other runtime families fail closed.
- Each copied leaf uses a same-directory temporary before POSIX link, Windows no-clobber rename, or explicit replacement, but a multi-file run is sequential and has no rollback. A runtime filesystem failure can leave the current or earlier leaf copies in place and requires inspection before retry. If an absent target is installed but temporary cleanup then fails, the target remains counted as copied, the residue path is a blocking `copy_cleanup_failed` finding, and remaining copies stop.
- Report preflight cannot guarantee the later write against disk exhaustion, permission/topology changes, or other runtime failures. If a report write fails after apply, the command exits nonzero and emits a blocked stdout report that truthfully retains copied-file counts. A failed probe cleanup can leave a `.naos-spec-pack-report-probe-*` file for manual removal.
- The current checks do not prove protection against hostile concurrent ancestor replacement, mount or bind-mount changes, network-filesystem semantics, Windows DACL/ADS preservation, ACL or xattr preservation, or crash consistency. Static Windows reparse points (including junctions) are refused. POSIX preserves mode bits; Windows preserves the source read-only attribute and inherits destination-directory ACLs. A read-only Windows destination is not made writable for `--force`.

## Memory Limits

- Memory is advisory by default.
- Reviewed and provenance-backed memory can support context, but repository evidence remains authoritative.
- Instruction-grade memory requires explicit approval, provenance, scope, reviewer, timestamp, freshness/expiry, and a human boundary.
- NAOS does not read private memory payloads or Engram databases by default.
- Durable memory writes require configured, authorized, verified, memory-use-policy-permitted access plus human approval.

## Evidence Limits

- Context packs, local indexes, query reports, graph reports, semantic readiness reports, session reports, evidence packs, and dashboards are derived artifacts.
- Local context query results are candidates, not answers.
- Local indexing excludes selected credential-like content before SQLite/chunk publication, and model-telemetry reports redact matching metadata before serialization. Detection covers known token shapes and secret-named assignments; unrecognized credentials can still escape detection.
- Graph query results are relationship candidates, not truth.
- Evidence attestation uses local digests and reviewer metadata; it is not cryptographic signing or tamper-proof storage.
- Evidence conflict detection flags deterministic review conflicts and metadata gaps; it does not resolve conflicts, adjudicate correctness, prove separation of duties, approve work, lock tasks, or prove compliance.
- SARIF export is a findings interoperability format. It is not attestation, approval, certification, maturity promotion, compliance proof, or source authority.
- SARIF file locations use URI-escaped paths relative to `%srcroot%`; configure that base in the consumer for the reviewed project. Paths from a different platform or outside the project are omitted when they cannot be mapped safely. Generic labels and references become physical locations only when they identify an existing local file. The finding remains present without a physical location.
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
- PR-risk classification reports an unavailable or incomplete Git comparison as `inconclusive` with an `unknown` risk tier. It must not be interpreted as a clean low-risk diff. Existing adopters retain their configured path rules and need an explicit reviewed rule update to cover newly added agent-execution surfaces.
- Drift mode compares deterministic reports; it does not infer semantic drift.
- Assess mode summarizes posture; it is not certification.
- LLMGrader readiness is configuration/reporting posture only in this release scope: runtime is disabled by default, StaticGrader remains primary, no provider/model/API dependency or credential handling is enabled, no default cost is incurred, and future advisory use requires cost, data exposure, bias/drift, residual-risk, and human-approval controls.
- Advisory controls can produce candidates, warnings, discrepancy findings, and review prompts; they cannot approve work, certify compliance, promote maturity, prove task completion, or become sole pass/fail authority.
- Future advisory controls must record residual-risk metadata and route discrepancies to human review before durable project state changes.

## Hashing and Signing Limits

- NAOS produces hashable/signable artifacts, but it does not sign on behalf of adopters.
- NAOS emits a deterministic tamper-evidence root (`manifest_root_digest`, on by default) and a DSSE-style **signable envelope** (`naos evidence-sign`). `naos evidence-verify` recomputes local digests and checks any supplied envelope payload against the independently recomputed manifest root and artifact count. Its `envelope_payload_validation` result is separate from signature-entry presence and best-effort Git HEAD metadata. Missing optional envelopes permit digest-only verification; malformed, stale or signature-only envelopes cannot establish payload binding. It does not validate envelope signatures, apply an independent trust or acceptance policy to Git's commit-signature status, authenticate an identity, require signing, hold keys, issue certificates, or provide non-repudiation.
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

- New migration defaults select the path-free v2-input route, which remains under native qualification. It preserves full supported history replay and exact raw evidence locally, but refuses unsupported path-bearing content. Small transcripts retain authority v2; larger ones use deterministic, bounded authority-v4 storage and the same full replay. Both reproduced valid-history capacity failures now pass focused macOS checks under unchanged budgets; this is not a proof of universal historical capacity parity or new-format native qualification. Historical v1 portable records and explicitly selected v1-input migrations retain their original path-carrying representation; existing history is never sanitized in place. A receiving clone validates derived history, not correspondence to raw originals it does not possess. The default is implemented; complete native and installed-artifact qualification remain pending. See [recovery boundaries](docs/UPGRADE_RECOVERY_BOUNDARIES.md).
