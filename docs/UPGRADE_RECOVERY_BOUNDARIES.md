# Legacy managed transaction recovery boundaries

A recorded `COMMITTED` transaction remains terminal. Recovery checks current
manifest, receipt, directory and managed-content evidence using the existing
native guards. A mismatch returns a `recovery_required` diagnostic and preserves
the committed journal; it does not rewrite historical commit evidence or grant
permission to mutate a drifted tree. Valid unfinished histories retain the
existing rollback or forward-completion behavior. Exact private cleanup after a
validated commit may complete without rewriting an already committed journal.

An entry named `.preparing-*` is unsealed private preparation. Its journal may be
present, absent or unreadable, but it does not contain complete durable ownership
witnesses for every created object. Recovery returns `recovery_required`, naming
the preserved path, and stops before automatic recovery mutation. Retrying the
same unresolved preparation returns the same bounded refusal. Owner review must
retain and inspect the preparation, corresponding transaction records, manifest
and receipts and establish an authorized reconciliation before retry. This
release provides no automatic deletion or adoption command for unwitnessed
preparation. Matching names, modes or bytes do not supply missing authority.

Content-aware v2 create rollback writes its existing exact rollback pending
action before moving the public leaf without replacement into the original
private staging slot. It verifies the moved object's recorded native identity
and content before exact private cleanup. A process exit between reverse move
and cleanup retains the pending action; fresh recovery reconciles both public
and private locations before clearing that intent. Substituted public content
is restored or retained in quarantine when restoration cannot complete.
Unexpected private content or simultaneous public/private leaves are preserved
as an explicit rollback conflict.

Historical v1/v2 journal schemas and minimum recovery version are unchanged. Existing
pending action fields bind the create leaf's public path, original private slot,
content plan and native identity; no historical records are rewritten. Scope
locks, ancestry, ownership, permissions, ACL and native identity checks remain
required. These controls do not promise atomic source-identity compare-and-swap
against a noncooperating same-user process.

Before new POSIX transaction preparation, NAOS checks the held staging and evidence parents for unsupported inode flags or ACLs. Linux permits only the existing kernel-managed extent/index flags; extended/default ACLs and other flags are refused before a new preparation directory is allocated. This does not broaden filesystem support, remove inherited metadata, or replace the later checks on each created object. Metadata changes after preflight can still leave preserved residue requiring review. Native filesystem-specific qualification is recorded separately.

Selected kit-owned content edits, absence, conflicts, or executable/native
metadata drift require governance review before a new operation. Legacy POSIX
planning reports `diagnostic_only` with the blocking `kit_owned_drift` check;
legacy Windows planning reports `refused`; current portable planning refuses
with `GOVERNANCE_DRIFT`. The public upgrade command returns a nonzero exit.
Intentional adopter-owned changes and unselected historical carry-forward remain
preserved within the selected operation's scope. Historical records retain their
recorded grammar and can be read for exact recovery or completed-operation
recognition; reading a historical record does not authorize a new operation.
Restore the selected kit-owned content/metadata to its recorded baseline or
review the discrepancy separately, then generate and approve a fresh plan.

Manifest/receipt replay checks recorded source-policy ownership, earlier receipt
state, exact output inventory and content digests. These checks detect
inconsistent ownership relabelling against the retained inputs. Their unkeyed
digests establish integrity relationships, not human identity or historical
authenticity. An actor able to replace the whole history, policies, bases and
all independently retained anchors can construct a different internally
consistent history; independent trusted source/decision evidence remains
necessary to judge that history. No ownership is inferred from equal bytes,
a path name or Git history.

POSIX lock observation leaves the persisted lock file unchanged but briefly
tries `LOCK_EX | LOCK_NB`. A writer racing that probe can fail closed with a
held-lock refusal and may retry after the probe releases. An `available`
observation is only a point-in-time result and gives no reservation or write
permission: each writer must independently acquire and retain its own kernel
lock. Persisted PID metadata is diagnostic only. This contract does not promise
contention-free status reads, fairness or starvation freedom.

New POSIX content-aware transactions use a distinct compact checkpoint schema and retain a canonical 0600 `plan.json` sidecar for the life of the history. Its exact bytes, SHA256 and size are bound to every journal; scope, namespace, ACL/flags and native leaf identity checks remain required. The plan is not rewritten at each checkpoint. Pending intents, completion checkpoints, durable replacement/fsync and cumulative inventories retain the same recovery semantics. Old unfinished v1/v2 transactions continue their existing writer; no historical record is relabeled or migrated.

Only a reader recognizing `naos.upgrade.content_transaction.compact.v1` can recover these new journals. The inherited 1.1.0 minimum is a semantic lower bound and does not mean every older 1.1.0 executable understands compact records; unknown schema must refuse and preserve evidence. A process exit after sidecar creation but before the initial journal remains unsealed preparation, preserved under the existing boundary above. Missing, changed or foreign sidecars refuse recovery. Validated terminal cleanup retains the sidecar as durable history. Compact payload reduction does not qualify an operating system or establish an elapsed-time guarantee.


## Path-free legacy replay migration

New migration defaults select `naos.upgrade.legacy_migration_inputs.v2` and a
versioned full replay projection. The public schema aliases and low-level
planner default select this format; an external inputs file still supplies the
explicit reviewed controls. The portable transcript replaces supported
historical locations with typed location tokens and validates the complete
recorded transitions and terminal journals. It preserves payload and policy
bytes; unsupported location roles and home-bearing free text refuse before
preparation. Transcripts up to 16 MiB retain the existing authority-v2 bytes.
Larger transcripts use authority v4: a deterministic string table and typed
tree encode the complete metadata in bounded content-addressed chunks, while
byte payloads remain exact blobs. Receiving validates encoded and expanded
commitments before full replay. No compression-library output determines an
approval digest. The 16 MiB record, 64 MiB blob, 256 MiB cumulative read and
existing replay limits remain enforced. Synthetic replay locations never
authorize native mutation.

The migration keeps exact raw source containers locally, retains the original
pointer object, and records `raw-lineage.json`, `raw-policy.json` and
`raw-modes.json` in the existing private migration journal. The approved v2 plan
binds these inputs and the complete derived candidate separately. Recovery
revalidates their correspondence under the existing locks: rollback before
portable-head publication, forward completion afterward. A portable clone can
replay the derived history without originals but cannot independently prove its
correspondence to unavailable raw bytes.

POSIX migration preparation gives newly created private directories and the
scope lock the uid and gid of the approved, currently held legacy lock. It
verifies their actual native ownership, private modes and absence of ACLs;
inherited parent groups do not determine migration storage ownership. Existing
ancestors and raw legacy controls are never normalized. An existing private
local parent with different ownership refuses before child creation. A kernel
refusal to assign the approved group preserves any partial preparation for
inspection. Ordinary rebind and Windows creation policies retain their existing
behavior.

The new authority names derived receipt digests explicitly. Historical v1
records retain their existing grammar and bytes, including any absolute
location text already present. Explicit v1 migration inputs still select that
historical format for planning, apply and recovery; this opt-in retains its
historical privacy limitation. Apply binds the input schema to the approved
plan schema, and recovery reconstructs according to that historical plan, never
according to current defaults. The path-free raw migration-input default is
implemented, but its native and artifact qualification remain open. The selected
D5 receiving-to-Quickstart J2 baseline is scoped separately in [platform
implementation and verification](PLATFORM_ADAPTERS.md#selected-current-d5-baseline-17-october-2026);
it does not qualify this `--plan-migration` default or large authority-v4
transcripts. An older reader must refuse an unknown authority kind or schema.
Neither format's hashes authenticate an author or replace native ownership and
permission checks.
