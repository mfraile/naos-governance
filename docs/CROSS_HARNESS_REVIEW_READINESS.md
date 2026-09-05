# Cross-Harness Review Readiness

Cross-Harness Review Readiness is a readiness-only NAOS surface for planning
future independent review and DSSE-style attestation design. It records what
must be declared before any future cross-harness or signing workflow is safe to
consider; it does not run that workflow.

The report is generated with:

```bash
naos cross-harness-review-readiness --profile <profile>
make -f Makefile.naos naos-cross-harness-review-readiness
```

It reads `naos/cross_harness_review_readiness.yaml` and writes
`naos/reports/cross_harness_review_readiness.json`, with a session-scoped copy
when session identity exists.

## What It Checks

The readiness report checks local configuration for:

- declared harness inventory and trust boundaries;
- data-exposure and network/provider boundaries;
- minimum independent-review expectations;
- required evidence such as source diff, generated reports, gate evaluation,
  evidence pack, and human review record;
- adopter-owned key custody, signing authority, canonicalization, replay
  protection, signer identity, and verification-policy planning;
- unsafe flags that would enable runtime execution, provider/API access,
  signing, signature verification, or key custody in the core kit.

Unsafe flags are surfaced as review findings. The script does not crash when
configuration is unsafe; it writes a report requiring human review.

## DSSE-Style Boundary

NAOS v1.0.0 can emit an adopter-signable evidence envelope and recompute local
tamper-evidence through `naos evidence-sign` and `naos evidence-verify`. This
readiness surface is separate: it helps plan the evidence and governance
boundary for any future cross-harness DSSE-style workflow, but it does not
provide NAOS-owned signing, third-party signature validation, key custody, or
cross-harness attestation.

SHA-256 digests in NAOS evidence reports are integrity metadata. They are not
signatures. Key custody, signer identity, signing authority, verification
policy, and attestation authority remain adopter-owned responsibilities.

## Relationship To Evidence

Cross-harness readiness is related evidence for:

- gate evaluation;
- evidence pack;
- audit log;
- SARIF findings export;
- dashboard posture;
- human review and residual-risk disposition.

It remains advisory until deterministic controls, adopter policy, and human
review decide otherwise. A ready-looking report does not mean independent
review occurred.

## Non-Claims

This readiness surface does not provide:

- cross-harness execution;
- DSSE signing;
- signature verification;
- key custody;
- signed attestation;
- attestation authority;
- non-repudiation;
- proof of compliance;
- certification;
- approval;
- behavioral correctness proof;
- human review replacement.

## Before Future Activation

Before any future cross-harness execution or signing design is considered,
adopters should document:

1. harness inventory and ownership;
2. trust boundaries and data exposure;
3. deterministic evidence inputs and artifact scope;
4. human-review boundary and independence expectations;
5. key custody owner and signing authority;
6. canonicalization and hashing policy;
7. replay-protection and signer-identity requirements;
8. verification policy and failure handling;
9. residual risks and review owner.

Those decisions live outside the readiness report. NAOS records whether the
planning surface exists; it is not the signer, verifier, or approver.
