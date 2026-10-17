# Completed-card digest and checkout contract

`task-complete` copies the active card's bytes unchanged into the configured
NAOS root's direct `completed/` directory. Its new history records declare
`active_record_digest.canonicalization: crlf-to-lf-v1`: SHA-256 is computed after
replacing only the byte pair CRLF with LF. No decoding, whitespace trimming,
BOM removal, Unicode normalization or lone-CR conversion participates in this
digest. Registry validation, governance refresh and task context resolve the
same completed-card verifier. The exact task identity and path checks still
apply; a matching digest does not approve delivery, merge or release.

An absent `canonicalization` field, or the explicit value `raw-bytes-v1`, means
SHA-256 over the exact archived bytes. Unsupported values fail closed. The
verifier never tries alternate representations of an unmarked historical
record. The additive field does not change the history schema identifier or
the existing raw-digest interpretation. Older NAOS versions cannot verify a
new CRLF card against its canonical digest; update all consuming clients before
sharing the new format with such a client.

Review and commit the generated checkout policy before cloning onto another
host. Exact LF rules for generated scaffold files alone do not protect later
completed cards. Because the lifecycle resolver reads direct `*.md` cards,
the bounded archive rule is `/<configured-root>/completed/*.md -text -filter
-ident -working-tree-encoding`. It preserves raw archive bytes instead of
forcing old CRLF records to LF. Do not extend it to every adopter file or
renormalize existing archives. The generator selects this rule only where the
scaffold includes a completed-card template and its task registry. Quickstart
has no such task-card scaffold and receives no archive rule. The default root
is `naos`; separately
review equivalent rules for a customized root, and recognize that project Git
attributes cannot protect archives outside that Git worktree. Existing or
locally modified adopter attributes are preserved. Nested attributes,
`.git/info/attributes` and other effective overrides must be checked; a root
rule by itself does not prove byte preservation. New versioned digests remain
portable through LF/CRLF checkout changes even when that rule is absent.

When a historical raw digest fails, preserve the observed archive and history
unchanged while investigating. Retrieve original bytes from a trusted Git
blob or other retained custody when available, or reconstruct bounded newline
candidates in scratch: keep the observed bytes, replace CRLF pairs with LF,
and replace LF in that second candidate with CRLF. Compare each candidate's
raw SHA-256 with the existing recorded value. A candidate is eligible for a
reviewed restoration only if that exact digest and the task ownership/path
checks match. This can recover a uniformly CRLF original even if an earlier
Git commit stored LF. It does not authorize rewriting the digest, marking an
old hash as canonical, or automatically writing the archive. Mixed original
line endings, missing originals and unrelated content/BOM/whitespace changes
can leave every bounded candidate unmatched; retain the failed evidence and
seek original bytes rather than weakening verification. Generation and
upgrades do not perform this restoration.
