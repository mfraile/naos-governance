# Security Policy

## Scope

This file covers the **NAOS-Governance kit itself** (`mfraile/naos-governance`). It does not cover security of projects that *use* NAOS — for those, the adopter is responsible.

## Supported versions

| Version | Status | Security fixes |
| --- | --- | --- |
| 1.1.0 | Publication candidate; not yet released | Pre-publication fixes only |
| 1.0.0 | Historical private candidate | Not publicly supported |
| < 1.0 | Pre-release | Not supported |

No public support period begins until an owner-authorized publication action completes. Any future support window must be stated in the published release record rather than inferred from this candidate.

## Reporting a vulnerability

If you discover a vulnerability **in the kit itself** (e.g., a way to bypass the pre-commit hook from inside the kit's own templates; a path-traversal in a script; a deserialisation issue in YAML handling):

1. **Do not open a public issue.**
2. Open a private security advisory on the repository, or email the maintainer (contact via the repository's profile).
3. Include: affected files, reproduction steps, the impact you observed, and a suggested mitigation if you have one.

For vulnerabilities **in projects that use NAOS**, do not report here. The kit cannot fix code it does not own.

## What counts as a vulnerability

- A way to make `pre-commit` exit 0 when it should exit 1, without the user knowing.
- A way to make `autoresearch/runner.py` report passing checks for files that do not exist.
- A way to bypass the `NAOS_CONTEXT_REMAINING_PCT` guard at `<25%` without the user invoking the documented override.
- A way to fabricate a generated evidence bundle that appears to come from the kit but was hand-edited.
- A script in the kit that exfiltrates data (path traversal, hardcoded telemetry endpoint, etc.).
- An untrusted-input issue in any of the scripts under `scripts/` or `autoresearch/`.

## What does NOT count as a vulnerability

These are *limitations*, not vulnerabilities. They are intentional design choices and are also reflected in `ROADMAP.md` where they affect public direction:

- `git commit --no-verify` bypasses the pre-commit hook. This is git behaviour, not a NAOS defect. (Mitigation: adopter CI enforcement.)
- `NAOS_TIER` can be set to `lite` to skip standard/assured checks. Adopter CI must enforce the policy-required tier.
- `core.hooksPath` can be re-pointed. Outside NAOS scope.
- The `NAOS_CONTEXT_REMAINING_PCT=100` override is documented in the hook itself (`pre-commit:236`) and in `docs/tutorials/MICRO_TUTORIAL_31_PAUL_RUNTIME_GUARD.md`.
- Allowlist entries that the adopter has approved are not reportable as vulnerabilities. (Adopter review is the mitigation.)
- The kit does not cryptographically sign its outputs. Adopters who need signed evidence must sign externally.

## Security posture

The kit's primary threat model is **human carelessness, not adversarial humans with commit rights.** A determined attacker with commit rights to a NAOS-governed repository can defeat the kit's governance; the kit cannot fix that. Adopters who need stronger assurance should enforce the required profile in CI, protect branches, restrict who can modify hooks and governance configuration, and sign evidence externally when needed.

Default runtime posture:

- NAOS does not require API keys, provider credentials, cloud services, MCP servers, Engram, sqlite-vec, embeddings, graph runtimes, or model calls by default.
- NAOS does not read private memory payloads or Engram databases by default.
- NAOS does not write durable memory, enable cloud memory, or perform external sync by default.
- NAOS does not enable LLMGrader runtime, provider/model/API calls, or API-key reads by default.
- Static customization hooks use schema-validated YAML overlays only. They do not execute adopter-provided Python, shell hooks, plugins, provider setup, dependency installation, or arbitrary code.
- SARIF export writes local report artifacts only; NAOS does not upload SARIF to GitHub code scanning or any external service by default.
- NAOS seeds and generated reports should not contain secrets, private memory payloads, customer data, tenant data, provider credentials, certificates, or private keys.
- Memory/provider access must be configured, authorized, verified, policy-permitted, and human-approved before any durable memory action is allowed.
- Local context, query, graph, semantic, session, evidence, and dashboard outputs are generated evidence or candidate references; they do not replace repository evidence, human review, or external security controls.

Digest and signing posture:

- NAOS produces hashable/signable artifacts, but it does not sign on behalf of adopters.
- Adopters own keys, custody, notarization, timestamping, certificate chains, attestation authority, and external archival.
- Use "checksum" or "digest" unless actual signing exists.
- New digest-oriented designs should default to SHA3-512 unless implementation constraints require otherwise, while preserving SHA-256 compatibility where existing reports, package ecosystems, or reviewer workflows depend on it.
- NAOS does not claim quantum-proof security.

## Coordinated disclosure

If you report a real vulnerability:

- We acknowledge within 5 business days.
- We aim to fix within 30 days for severity ≥ medium, 90 days for low.
- We credit the reporter in the release notes if they wish.
- We do not pay bounties (the kit is a single-maintainer Apache-2.0-licensed project).

## What the kit does NOT promise

- We do not promise that NAOS-derived evidence is acceptable to every regulator. Public compliance positioning is advisory; see `docs/COMPLIANCE_MAPPING.md`.
- We do not promise that the kit is sufficient for high-stakes deployed financial-services agents. The kit governs SDLC; runtime governance belongs in a separate runtime-control layer.
- We do not promise zero-day responsiveness. Maintainer time is bounded.

## References

- `docs/COMPLIANCE_MAPPING.md` — advisory compliance mapping and limitations
- `ROADMAP.md` — public direction, constraints, and explicit non-goals
