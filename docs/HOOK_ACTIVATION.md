# Explicit managed hook activation

Init copies a nonexecutable hook. It does not configure Git or run the hook.
Review the worktree and existing hook integration before selecting activation.
The documented chmod changes physical mode; it does not revise owned provenance.
Ordinary updates preserve that drift until an explicit activation review commits.

For a completed same-root portable v3 project with a kit-owned hook, inspect its
owner/head, select the exact current full POSIX mode, and create an external plan:

```text
naos upgrade PROJECT --plan-hook-activation --hook-mode-octal MODE \
  --expected-owner-sha256 OWNER --expected-head-sha256 HEAD --plan-out PLAN
naos upgrade PROJECT --apply-plan PLAN --expect-plan-digest SHA256_OF_PLAN
```

MODE is the observed four-digit full mode after the owner's deliberate chmod.
The plan accepts only the exact `.githooks/pre-commit` path, replay-owned history,
identical saved/current bytes, supported present native identity and execute-bit
changes. Other permission bits, ownership, identity or supported metadata drift,
byte edits, deletion and historically adopter-owned hooks refuse. Legacy projects
first require the existing separately approved migration; its saved modes and
history are preserved. Migration itself never approves activation.

Review the plan's full mode, current witness, portable head and owner. Apply
reacquires custody and regenerates the complete plan; its exact raw SHA-256 must
match. The existing v3 staged replacement, retained original object, journal and
recovery coordinator perform the operation. No special chmod writer exists.
After an interruption, use the existing `naos upgrade PROJECT --recover` route;
inspect the actual result. Pre-head rollback and post-head forward completion
retain the existing recovery semantics. Partial unwitnessed records still refuse.

Successful activation appends a same-byte executable-intent receipt. Subsequent
generated hook updates retain that explicit intent and still require their own
plan/apply approval. Dormant hooks keep the original nonexecutable declaration.
Ordinary adopter byte/mode/metadata conflicts remain preserved. Portable receipt
history proves internal consistency, not native write authority or human identity.

This POSIX reconciliation does not configure `core.hooksPath`, execute Git or
prove hook execution. Git for Windows has no observable POSIX execute mask; this
route refuses Windows. Its existing reviewed Bash/Python hook integration remains
separate. An adopter-owned Git wrapper is a separate future integration option,
not a way to silently rewrite an already changed owned hook.

The installed candidate with wheel SHA-256
`3a54380c821005da4496d375f37fab6ba0502ebb45ddfc94719b8f4d0b7a8920`
completed the selected macOS ARM64 CPython 3.13 Lite activation, upstream hook
update, actual first commit, and pre-head/post-head interrupted recovery checks.
Earlier failures remain recorded. This evidence covers that candidate and scope;
qualification of the current integrated candidate and other native cells remains
pending. Older readers that do not recognize the explicit operation refuse;
no historical receipt is rewritten to obtain compatibility.
