# Platform implementation and verification

NAOS targets native macOS, Windows 11 and Ubuntu workflows with CPython 3.11,
3.12 and 3.13. Package installation, preview generation and managed project
mutation are separate operations. Installing a wheel does not qualify a host's
filesystem transaction behavior.

## Reading platform support

Admission by an adapter and qualification of an exact candidate are separate.
The table below describes the implemented boundary; the scoped execution notes
later in this document describe what was actually tested. A passing older
candidate does not qualify subsequent source changes.

| Host and interpreter | Preview / package installation | Managed mutation admission | Native evidence boundary |
| --- | --- | --- | --- |
| macOS ARM64, CPython 3.11–3.13 | Separate from mutation admission | Darwin metadata and transaction adapters | Bounded ARM64/APFS lifecycle and recovery results below |
| Ubuntu x86_64, CPython 3.11–3.13 | Separate from mutation admission | Linux adapter, subject to required filesystem APIs and metadata | Bounded Ubuntu x86_64/ext4 results below |
| Linux aarch64, CPython 3.11–3.13 | Does not establish native qualification | Declared by the POSIX adapter | Native execution remains unverified |
| Windows 11 x64, CPython 3.11–3.13 | Separate from mutation admission | Native Windows adapter, 64-bit ABI and supported metadata required | Bounded Windows 11 x64/NTFS results below |
| Intel macOS or another Python minor | Installation alone grants no mutation eligibility | Outside the POSIX mutation tuple | No managed-mutation qualification claimed |
| Windows ARM64 | Installation alone grants no mutation eligibility | The Windows guard requires a 64-bit ABI; that is not ARM64 qualification | No native ARM64 execution claimed |

| Operation / profile scope | macOS ARM64 | Ubuntu x86_64 | Windows 11 x64 |
| --- | --- | --- | --- |
| Preview: Quickstart, Lite, Standard, Assured | Profile generation implemented | Same profile-generation contract | Same profile-generation contract |
| Brownfield activation and selected profile transitions | Four bounded workflows on Python 3.11 | Four bounded workflows on Python 3.11 | Four bounded workflows on Python 3.11 |
| Managed apply and interruption recovery | Scoped lifecycle results below | Scoped lifecycle results below | Scoped lifecycle results below |
| Selected D5 installed and J2 routes | See the dated baseline below for exact admitted cells and operation scope | See the dated baseline below for exact admitted cells and operation scope | See the dated baseline below for exact admitted cells and operation scope |

The four bounded workflows are not every profile × operation × Python
combination. Preview availability does not imply activation eligibility.
Unsupported metadata or missing native primitives still refuse the operation.
The table's selected D5 routes do not by themselves qualify the separate RI
diagnostic, profile-default or report-path changes.

## Selected current D5 baseline (17 October 2026)

All nine same-scenario D5 J2 cells were accepted on 17 October 2026:
macOS ARM64/APFS, Ubuntu x86_64/ext4 and Windows 11 x64/NTFS, each on
CPython 3.11, 3.12 and 3.13. This is acceptance of the bounded scenarios and
artifact identities below, not every operation on those hosts.
The selected D5 source map covers 2,094 paths and has SHA-256
`3baec3862d7bdd3cf8f067ed4137c7561162720a1cbda6b241eb5c7dc55a4fb3`. Its
accepted wheel is `5f7415ad826f3b9353c02b55775572815c669e53d1dff3ae072ea84c74d33932`;
its accepted sdist is `48ff5d3c7a5cb3cfd88e0d1415ca0c62721e21925b36be57f4d648e2aa00a52b`.
These hashes identify the original D5 baseline artifacts. Qualification is
specific to named source and artifact bindings; any documentation successor
requires its own source map and artifact/install qualification.

The D5 artifact route recorded 18 actual fresh wheel/sdist installations and
108 first-contact and hook smoke commands. The nine ordinary managed chains
recorded 63 commands: Lite initialization, Standard plan followed by two apply
attempts, instruction addition, and two recoveries.

In each accepted J2 cell, the selected receiving-to-Quickstart publication/recovery
route covered 98 requested files, 200 recorded publication slots and 13 nonempty
newly created directories. An actual pre-head move
interruption exited 86; fresh recovery rolled back and verified exact
preservation. An actual post-head manifest-move interruption also exited 86;
fresh recovery completed forward and verified terminal state, binding, read-only
recovery and retry.

This selected baseline does not claim a naturally uninterrupted J2 `apply=0`,
a pass of the whole 528-file suite, universal profile/history/metadata coverage,
power-loss consistency, cross-account transfer or human-authentication assurance.
The exact branch limits and preserved historical failures below remain in force.

## Portable commands, identifiers and report paths

Use `python -m naos_governance <command>` with the selected environment's Python
for native commands on all three operating systems. The shared `Makefile.naos`
requires GNU Make and a POSIX-compatible recipe shell; opening Git Bash alone
does not guarantee which shell Make selects. When using that optional route on
Windows, explicitly configure a compatible shell, for example `SHELL=sh`, and
ensure it is available. WSL is not required by the native Python interface.

The standalone secure-coding P3 Make wrapper has a narrower Python-only recipe:
it uses the selected profile and one quoted `PYTHON` executable. Its dispatcher
prefers the installed package, otherwise the configured copied script with its
existing supporting files. A broken importable package refuses rather than
silently falling back. The wrapper does not provision a missing reporting
runtime. See [P3 reporting](SECURE_CODING_P3_REPORTING.md#commands).

New session identifiers are 8–128 characters, lowercase ASCII letters,
digits, underscores or hyphens, optionally separated into nonempty dot
segments. The first character is a letter or digit. Windows device basenames
`con`, `prn`, `aux`, `nul`, `com1`–`com9` and `lpt1`–`lpt9`, including dotted
extensions, are refused. Existing noncanonical index records or differently
cased directory aliases are preserved and require explicit reviewed migration;
NAOS does not lowercase or merge them. Index replacement uses a unique
temporary file and retries Windows access-denied (5) and sharing/lock errors
(32/33), at most four attempts with 350 ms total backoff. A held target can
produce error 5; that code alone does not distinguish sharing from permissions.
Every retry repeats the same replacement without changing permissions, file
attributes or ownership. Persistent denial refuses; other errors do not retry.
This is not concurrent-writer locking.

Dashboard input and finding paths use project-relative `/` spelling where
possible, and redact external display paths. Traceability reports use portable
project-relative keys or opaque labels for external source paths. Those labels
are not cross-machine content identities. Native operands, project-root identity
and collection/source-reference authority remain unchanged; this is not a claim
that every absolute authority field is removed. Markdown output uses UTF-8/LF.

## Filesystem metadata policy

Installation and preview are separate from native mutation eligibility. The
POSIX mutation adapter admits Darwin ARM64 and Linux x86_64/aarch64 with
CPython 3.11–3.13; Intel macOS and later Python minors remain outside that
adapter's contract. Linux aarch64 has not been executed in this programme.
The Windows evidence is from Windows 11 x64/NTFS, not ARM64 or cloud storage.

Linux source transport admits only nonempty `user.*` extended-attribute names.
Planning and both staging paths refuse source `security.*`, `trusted.*`,
`system.*` and unknown namespaces before creating a destination. The low-level
copy independently refuses them before writing payload or attributes. It does
not transplant preview security labels or remove destination labels. Historical
observations still retain all namespaces, and source/destination metadata
equality remains exact: an inherited destination label can therefore refuse
staging. This is not SELinux/IMA reconciliation or enforcing-host qualification.
Readable historical records do not authorize copying a labelled legacy source
under the new policy. Source preconditions, no-op proposals and resumed staging
may conservatively refuse unsupported source namespaces without rewriting history.
Extended/default POSIX ACLs and inherited flags other than kernel-managed
INDEX/EXTENT remain unsupported; NAOS does not strip them or broaden permissions.

Windows managed file leaves admit NORMAL/ARCHIVE attributes. Ordinary ancestor
directories also admit READONLY, HIDDEN, SYSTEM and NOT_CONTENT_INDEXED; these
bits are observed, not changed. Compressed/encrypted directories, reparse points,
offline/recall placeholders and unsupported file-leaf attributes refuse.
OneDrive branding is not an eligibility test: ordinary fully local objects may
meet this policy, while placeholders or reparse paths do not. Native live
OneDrive/hydration and EFS behavior remain unqualified.

Attribute-policy refusals report the observed, permitted and unsupported masks
in hexadecimal, the observed file/directory role, and the exact recorded child
component relative to its held parent. Root or unrecorded handles report a null
component; no path is reconstructed or reopened for a diagnostic. Hard-link
count refusal is separate and reports observed/permitted counts. Reparse/device
refusal remains an earlier check with the same attribute context. These are
policy refusals, not invented Win32/NTSTATUS errors; native API failures retain
their actual error codes. This diagnostic detail does not expand eligibility.

The installed doctor and isolated memory-declaration write checks passed on
macOS, Ubuntu and Windows with all three Python minors (72 commands, no skips).
They reuse a previously qualified installed artifact whose five affected
modules match current source. This does not qualify other changed modules,
complete first-run workflows, crash durability or a new release artifact.

Completed populated-store receiving now has separate `--inspect-receiving-store`
and `--plan-receive-store` interfaces. The plan binds independently selected
owner/head digests, the exact retained inventory digest and a fresh binding ID.
Apply and recovery require the same external raw plan and exact SHA-256 approval.
Imported old evidence is preserved and checked separately from current native
mutation authority. Exact retained file/directory roles do not exempt control
records from private-store checks. Changed evidence during semantic validation
refuses before the next progress write.

Selected ordinary-history receiving, subsequent file/directory updates, and
interruption recovery before and after portable-head publication have accepted
evidence across all nine native OS/Python combinations. Earlier failed runs and
explicit fixture corrections remain part of that evidence.

The following dated component records retain their original packet context.
They are historical snapshots; the selected baseline above supersedes a status
only for the exact matching route and operation. It does not erase failed runs,
timeouts or unexercised branches.

Genuine migration-origin receiving and subsequent managed add passed on Ubuntu
with Python 3.11–3.13 for both legacy formats. After the receiving cost correction,
macOS Python 3.13 receiving and recovery passed for both legacy formats. With
the later imported-history correction, the full scenarios pass on Ubuntu
Python 3.11–3.13 and Windows Python 3.13. Windows 3.11/3.12 qualification is
running. macOS Windows-format managed add still exceeds the test's 180-second
command limit; fresh recovery completed that interrupted update and preserved
the earlier history and adopter edit. The timeout remains recorded. One bounded
longer diagnostic is measuring completion separately from the 180-second result.

The Windows tests use a same-user copy fixture that preserves required security
from creation. Ordinary copying previously lost private ACLs. Receiving does not
repair incoming security; secure transfer must establish current-user private
controls before inspection. Cross-account secure transfer, broader crash cuts,
large content and final installed artifacts remain unqualified.

The receiving implementation now reuses detached historical derivation only for
identical bytes and membership within the same held custody. Current opening and
closing native observations still run and must agree. Duplicate intermediate
legacy scans were removed. Subsequent imported-history replay also reuses only
exact detached inputs within one held custody; changed inputs derive afresh,
and every current native scan and closing proof still runs. The remaining native
qualification and macOS timing limits above still apply.
Earlier notes below calling this interface unfinished are superseded only for
implementation and these bounded scenarios; their remaining qualification
requirements are unchanged.

The public absent-store receiving adapter now connects the existing native
rebind planner, preparation, publication, checkpoint and rollback operations.
`upgrade --plan-rebind` requires explicit owner/head digests and a new binding
ID; exact saved-file SHA-256 approval is required for apply and receiving
recovery. Existing local/legacy stores refuse without fallback. Current edits
and deletions remain intact; partial records are preserved. A caught error after
a recovery write reports `recovery_required`. Focused macOS 3.13 source tests
exercise actual move/clone, catalogue add after rebind, read-only init/profile
review, process exits, rollback and forward recovery. The integrated public
receiving suite subsequently passed all 13 cases on macOS and Windows with each
of Python 3.11, 3.12 and 3.13 (78 passes, no skips), on source packet
`3dea5dc147ca90013d578dde61455edc01a5bc4152096d3d2ebe82399509855c`.
The named 13-case receiving receipt does not qualify that absent-store route
on Ubuntu or against installed artifacts; later migration history changes have
separate native checks. The internal-component sections below describe their
bounded evidence. Earlier notes saying public enrollment is unfinished are
superseded only for the named absent-store variant.

A final remediation package pair was subsequently accepted for 18 fresh
wheel/sdist installations and 108 first-contact/hook smoke commands across
macOS, Ubuntu and Windows 11 with Python 3.11–3.13. Those installation checks
do not qualify every absent-store or foreign populated-store receiving route.
The accepted source map is
`7cb95cf2792cad81e941f296e349b130a6284ab3c99faa4cf90058c2671f29a8`;
subsequent documentation changes do not relabel that exact tested artifact.
The public legacy migration interface has its own operation-specific native
evidence below.

Completed internal legacy migration history is now accepted by the subsequent
public update/recovery path. It holds legacy custody before local custody,
checks the original retained objects and installed fence, and keeps historical
content separate from current adopter edits. A real migration followed by a
catalogue addition, post-head process exit and fresh recovery has passed on
macOS. The separate native read-bound test accepts a 17 MiB portable object while
retaining the 16 MiB private-record limit and 256 MiB capture budget. These are
bounded source results; the integrated native matrix remains pending. The public
`--plan-migration` / `--migration-inputs` interface now binds the existing raw
migration plan approval to independently selected history and original evidence.
Recovery preserves legacy-before-local custody, rolls back before portable-head
publication and completes forward afterward. Its source review and pure reader
checks passed; native and installed-artifact qualification remain separate.
Earlier component notes describing public migration as unimplemented are
historical evidence snapshots, superseded by this interface implementation.

| Surface | macOS ARM64 | Ubuntu x86_64 / aarch64 | Windows 11 |
| --- | --- | --- | --- |
| Managed-content planning and mutation | Darwin adapter; bounded native lifecycle and recovery checks passed | Linux adapter; bounded native Ubuntu x86_64/ext4 lifecycle and recovery checks passed; aarch64 unexecuted | Native runtime and command dispatch integrated; bounded lifecycle and recovery checks passed; full qualification pending |
| Exclusive leaf publication | Darwin no-replace rename | `renameat2(RENAME_NOREPLACE)`, with no fallback | Held-handle no-overwrite publication; bounded native NTFS probes passed on Python 3.11–3.13 |
| Creation, replacement and recovery | Darwin no-replace publication, atomic leaf exchange and journal recovery | `renameat2(RENAME_NOREPLACE/RENAME_EXCHANGE)` through the shared journal engine; native process-interruption probes exercised | Bounded native NTFS operation/runtime recovery probes passed on Python 3.11–3.13; full qualification pending |
| Metadata | Selected owner/mode/xattr contract; unsupported metadata refused | Descriptor-based inode flags and xattr inventory; extended ACLs and unsupported flags refused | Native identity and protected security policy bound by runtime plans; unsupported metadata refused |
| Repository-intelligence baseline | Native enrollment/apply/query/recovery suite passed on Python 3.11–3.13 | Native Ubuntu x86_64 suite passed on Python 3.11–3.13; aarch64 unexecuted | Native public planning/enrollment/apply/validate/query/recovery passed on x64/NTFS Python 3.11–3.13 |
| Brownfield activation and selected profile transitions | Four source workflows passed on Python 3.11 | Four source workflows passed on Ubuntu x86_64 Python 3.11; aarch64 unexecuted | Four source workflows passed on x64/NTFS Python 3.11 |
| Spec-pack materialization | Native bounded leaf-copy suite passed on Python 3.11–3.13 | Native Ubuntu x86_64 suite passed on Python 3.11–3.13; aarch64 unexecuted | Native Windows 11 x64/NTFS suite passed on Python 3.11–3.13 |

The Linux tests executed on macOS validate API requests, error handling and
schema/dispatch contracts. Separate native Ubuntu 24.04 x86_64/ext4 runs on
2026-09-25 passed five application-process-interruption recovery cases and
seven CLI lifecycle cases on each of CPython 3.11.16, 3.12.3 and 3.13.15.
The same cases passed on macOS ARM64 with CPython 3.11.13, 3.12.7 and 3.13.5.
The later policy/planning batch also passed the preserved-file upgrade/recovery
case on every interpreter on both hosts, plus the formerly Darwin-only shared
replacement-recovery tests on Ubuntu. Maintainer evidence binds these runs to
source manifests `abbcb8aef12d39e212da668d916e55919645400f5722fed3456ec48048e56b62`
and `ccda86f25c7c0ab802baaa811fbcb53fbb12cff46333b3daccf481c0198966a9`.
These are bounded source results, not final wheel/sdist or full-workflow
qualification. Subsequent changes require validation against their actual bytes.
Native Windows 11 x64/NTFS runs on 2026-09-25 subsequently passed five native
primitive cases, two multi-file operation cases and the runtime upgrade/recovery
case on CPython 3.11.9, 3.12.10 and 3.13.15. These include real process exits,
metadata restoration, repeated recovery and a later successful update. Evidence
binds the repair to source snapshots
`c08eea5e0b16d6875fe00f6ad8f600f9a841e39eeb140da13121a484df672201`
and `cf109d3cfe99877557e655acf008f8ec6a59f59749d2af8dcfc602c687acbbc3`;
the latter corrects test instrumentation without changing production code.
Full package-installation and generated-workflow qualification remains pending.

On 2026-09-27 the nine-case native Ubuntu x86_64/ext4 primitive suite also
passed on CPython 3.11, 3.12 and 3.13 (27 passes, zero skips). It verifies
no-replace/exchange and xattr copy, collision refusal, symlink and held-ancestor
substitution refusal, hardlink refusal, real cross-device staging refusal,
competing-process locking and unsupported special-mode refusal. Outside
sentinels and owned objects remain intact. This is bounded native source
qualification; other filesystems, aarch64, power-loss durability and final
installed-artifact qualification remain unverified by this probe.

On 2026-09-27 the nine-case native NTFS primitive suite passed on CPython
3.11, 3.12 and 3.13 (27 passes, zero skips). It adds actual junction/reparse and
hardlink refusals, case-alias collision preservation and distinct composed/
decomposed Unicode names to the existing sharing, collision, private-creation
and restoring-move cases. Outside sentinels remain intact. This verifies the
bounded Windows primitive contract; it does not establish file-symlink
privileges, power-loss durability or final installed-artifact qualification.

External-plan publication was separately checked on 2026-09-27 with 51 native
source tests across the three operating systems and CPython 3.11–3.13, with no
skips. POSIX checks exercise real no-replace publication with destination
collisions, substituted pending files and detached parents. Windows CLI checks
require the native occupied-name refusal and preservation of the complete
disposable project, external plan and outside sentinel. Windows publishes by
exclusive creation and has no pending-file protocol. These source checks do not
qualify the final installed wheel or source distribution.

The four greenfield profile previews also produced identical path sets and file
bytes on these three hosts with Python 3.12, using the same source snapshot
`ea139733408595aaac35fe200f89df3b4df7bc9a4b1036d9c88cc5ad00636bee`.
That comparison used Custom/static-only projects with memory disabled and
source-origin collection enabled. It found and repaired native path separators
in recipe input identifiers and catalogue source references. The comparison did
not normalize output bytes or exempt platform differences. Other archetypes,
backends and brownfield layouts require their own coverage.

Windows request tests and in-memory interruption tests likewise do not establish
Windows filesystem durability, ACL inheritance or recovery behavior. Final
native runs must record the exact OS, architecture, filesystem and Python
version, and exercise install, collision preservation, upgrade, interruption,
rollback and repeat recovery. No GitHub Actions are required for these local runs.

Linux operations require filesystem support for the selected descriptor APIs,
inode flags and atomic rename flags. Unsupported operations fail explicitly;
there is no ordinary rename or overwrite fallback. Network filesystems and
arbitrary metadata preservation are not qualified by this implementation.

Linux filesystem-managed INDEX and EXTENT flags may change as a directory grows
or data is staged on another supported filesystem. Comparisons of a fresh held
object with a historical identity tolerate only those two already-supported
layout bits. Persisted journals, manifests and receipt digests remain unchanged;
device/inode, ownership, mode, xattrs, unsupported flags and ACL checks retain
their existing guards. This does not authorize additional inherited flags or
arbitrary default ACLs.

V3 publication uses a narrower rule for a directory already present in its
sealed target record: Linux INDEX may be added as that directory grows; removal
of INDEX and changes to EXTENT remain refused. The original witness is preserved.
Newly created directories, private staging directories, file witnesses and all
identity, ownership, permissions, ACL and xattr checks remain exact. Darwin and
Windows comparison rules remain exact. This implementation change requires
corrected-source native qualification; earlier native receipts retain their
original source identities.

## Windows rename metadata and recovery

Windows runtime operations now write version-2 operation journals. Each moved
file records its native identity, exact content and security, creation and
last-write times, and supported attributes. NTFS can substitute a previous
file's creation time when a name is reused and can add ARCHIVE when a rename
handle closes. The Windows adapter closes that handle, verifies the same file,
restores only the recorded creation time and NORMAL/ARCHIVE attributes through
a metadata-only handle, closes it, and verifies the full identity again.

Recovery can finish this restoration only for the next unrecorded move, after
checking the complete publication topology and journal. Changes to content,
security, last-write time or file identity are refused with the objects retained.
Legacy version-1 journals remain readable when their saved identities and
operation topology are provable. Only the existing NORMAL/ARCHIVE substitution
that reproduces the complete original metadata digest permits attribute
restoration. These journals do not retain the original timestamp values needed
to repair unwitnessed creation-time changes. Such changes, and unproven security
changes, stop automatic recovery and preserve the objects and journals for
manual recovery; NAOS does not guess missing values. New production writes use
the durable version-2 witness. This policy is Windows-specific and does not
change the Darwin or Linux adapters. Application-process recovery is separate
from power-loss durability; final Windows workflow qualification is still
required.

The subsequent-v3 writer under development has a separate, narrowly bounded
Windows repair primitive. Native tests observed a cross-parent move clearing
the inherited-ACE markers while preserving the other selected security bytes.
Its witness records the original descriptor and derives only that exact
transient. Repair checks the recorded file identity and content, restores the
original descriptor, and checks the full identity after closing the handle.
Unrelated ACL changes are refused. Ordinary, protected and mixed-inheritance
fixtures passed on Windows 11 with CPython 3.13; v1/v2 comparisons are unchanged.
The subsequent-v3 coordinator now persists and binds these witnesses before
publication moves. This implementation does not establish complete public
update qualification. These checks do not qualify other ACE types, SACLs, or
the final installed command workflows.

The bounded J1-rebind-to-J2 update also persists exact current, source and
rendered bytes in a protected private replay bundle before registration moves.
The public `upgrade --recover` route reconstructs the approved operation from
that bundle: it reverses publication before the witnessed portable-head change
and completes forward afterward, retaining any already recorded checkpoint
outcome. Missing, substituted or unsupported replay evidence refuses recovery;
it is never reconstructed from the current kit. Private replay may contain
project content and must stay outside portable history and public exports.
The public profile-update route accepts a completed same-root J1 rebind and
supported subsequent completed operations. New reviewed plans use v3 with an
explicit generated selection and preserved historical paths outside that
selection. Omission does not authorize deletion or invent an upstream output.
Apply regenerates current requested content and checks, compares the exact
approved plan, and independently validates complete native history. Previously
approved public v2 plans keep their original selection semantics.

An unchanged request returns a read-only `no_changes` review, not a mutation
plan. Reapplying the exact bytes of a previously committed approved plan returns
`already_completed` without rerendering or creating a receipt/journal. That
response proves historical completion, not that current adopter content still
matches the old result. Rolled-back or different historical approvals refuse.

A caught failure after registration is attempted reports `recovery_required`,
retaining the plan digest and transaction identifier; run `upgrade --recover`
to assess persisted native state. Earlier completed operations use their saved
private source/current bytes and original terminal captures, independently of
later adopter edits. The current native inventory reader can refuse histories
beyond 16 journals; cumulative retained replay also has a 256 MiB bound.

Managed v3 `init` now routes before legacy scanning and fresh enrollment. It
returns a reviewed profile transition or unchanged result; `--activate` cannot
apply it, and `--new` cannot re-enroll a managed root, including implicit cwd.
The init preview and scripts-bearing setup checks share a reader that excludes
only current managed bytes with matching native metadata and observable execute
intent. Merely appearing in portable history does not hide an adopter edit.

Managed v3 `add` and `add setup-module` produce an external review for exact-plan
apply through the same publication/recovery path. The request envelope retains
canonical source/options metadata, and apply regenerates source, catalogue and
required checks before comparing the entire approved plan. Unmanaged scripts
remain a refusal both at review and apply. Focused macOS tests cover real artifact
and catalogue requests, preserved edits, stale approvals and fresh-process recovery;
combined Windows/Ubuntu/Python qualification of this command integration is pending.

Migration predecessors, foreign populated stores and deletion authority remain
unfinished. Full generated-profile application and
final installed artifact qualification are separate from focused native
operation/recovery tests; a successful generated plan alone is not proof that
its full application succeeds on every supported platform.

### Publication-parent directory recovery

New Windows managed-runtime plans use `naos.upgrade.windows_runtime_plan.v2`.
The operation intent formats remain unchanged. A required `directories.json`
records native identities and supported security/attributes captured when the
operation exclusively creates content-parent directories. Its paths must
exactly match the approved plan's missing parents; existing parents retain
their saved identity bindings. Missing or malformed witnesses refuse recovery
before reversing files.

After file rollback releases its parent handles, recovery removes only these
witnessed empty directories, deepest first, through native delete handles.
Bound intent/completion records make each deletion restartable; the final
`directories-rolled-back.json` is required before namespace rollback counts as
complete. Foreign contents, replaced directories, changed permissions and
unexpected absence are preserved for diagnosis. No recursive deletion is used.
Pending directory cleanup blocks a subsequent managed apply.

Legacy runtime-plan-v1 journals retain their original file-only recovery
meaning and completed replay support. An uncommitted v1 plan must be regenerated
before applying; it cannot authorize inferred directory removal. These changes
are Windows-specific. Native process-interruption qualification is recorded
separately from injected-kernel tests and does not establish power-loss safety.

## Generated Git line-ending policy

The preview inventory supplies exact root-relative `text eol=lf` entries for
generated UTF-8 text of recognized types. The generated `.gitattributes` includes
itself; unrecognized text types and text already containing CR are reported as
coverage gaps. There is no blanket rule over adopter files or normalization of
the bytes used for provenance and evidence hashes.

The generated policy also disables Git text conversion, filters, identifier
expansion and working-tree encoding for `.naos/managed-content/v3/**`.
These portable history records and base blobs must retain their exact bytes,
including existing CRLF or binary content, through clone and checkout on every
OS. This rule does not replace an unmanaged adopter `.gitattributes` file.
Nested attributes and `.git/info/attributes` can override it; inconsistent
history remains subject to the portable reader's integrity checks. This
transport rule alone does not qualify moved-project mutation or recovery.

Source-policy snapshot `v3` adds the exact `.gitattributes` path as
`kit_owned_derived`, using the existing policy-version-2 semantics. Historical
`v1` and `v2` policies and their digests are unchanged, and prior manifest
ownership is preserved. A clean managed policy can therefore follow a reviewed
profile upgrade. Unmanaged or locally modified attributes are preserved by the
existing ownership and conflict rules.

Preserved unmanaged root rules must also protect every generated text path
before brownfield activation, closing preapply or managed profile regeneration.
The shared check requires effective LF rules in both the working tree and index,
plus a portable index query with global/system attributes excluded for that
child process. It conservatively refuses any repository-local `info/attributes`
entry, using Git's common-directory resolution for linked worktrees. Staged
policy cannot be masked by an unstaged working-tree edit or machine-local LF
fallback. The adopter must explicitly review and stage compatible policy;
NAOS does not rewrite local, global or adopter attributes. Preview remains
available. This adds no provenance normalization or arbitrary Git-filter proof.
The new unmanaged-policy guard still requires its separate native acceptance.

Preservation does not authorize an upgrade: a locally edited, selected
kit-owned `.gitattributes` policy requires governance review. Its conflict
remains visible and the public planning command returns a nonzero exit.

Read-only Git attribute inspection reports effective-rule gaps and an untracked
policy. Plan diagnostics use stderr so canonical plan JSON and its digest remain
unchanged. Canonical public plan stdout emits the existing UTF-8 plan bytes plus
one LF, independently of the selected human-console encoding. `--plan-out` keeps
the original canonical artifact bytes and digest. A proposed new policy is reported as pending until apply. Commit the
reviewed attributes with the scaffold to protect future clones; higher-priority
Git rules may still override them. This implementation is shared with Windows
command dispatch, whose native qualification remains pending. Legacy CRLF bytes
and moved-root provenance require separate reviewed migration.

## Portable history inspection

`naos upgrade PROJECT --inspect-provenance` uses a shared v3 history decoder with
separate POSIX descriptor and Windows handle readers. Readers restrict internal
paths and sizes before allocating, reject unsafe filesystem objects, and check
read dependencies again before returning. This is read-only consistency evidence,
not an atomic filesystem snapshot or authority to modify the checkout. The command
does not inspect current managed leaves, create local bindings or migrate v1/v2
history. Portable enrollment, local witnesses, rebind, migration and recoverable
mutation remain separate unfinished work; native Windows qualification is pending.

The internal `capture_portable_working_tree` reader now holds both native root
chains while replaying portable history and observing all historical managed
paths plus explicitly selected new paths. It cross-checks native root identity
and protection, then revalidates portable and working dependencies. Its detached
result preserves exact byte hashes and absent historical paths; it grants no
ownership or mutation authority. Ordered checks are not an atomic filesystem
snapshot. Complete local journal inspection, locking and lifecycle integration
remain prerequisites for v3 mutation. This internal reader does not change the
scope of `--inspect-provenance` above.

## Generated Git hook interpreter

The generated hook uses Git's Bash interpreter. Native Git for Windows includes
that interpreter; this does not require WSL. Select the Python executable
explicitly before committing on Windows. For a project-local `.venv`, run in
PowerShell in the project root:

```powershell
$env:NAOS_PYTHON = (Resolve-Path .venv\Scripts\python.exe).Path.Replace('\', '/')
```

For macOS or Ubuntu, an explicit environment can be selected with:

```bash
export NAOS_PYTHON="$PWD/.venv/bin/python"
```

`NAOS_PYTHON` is a single executable path. Spaces and Unicode are preserved;
shell command strings such as `conda run ...` require an explicit wrapper script.
POSIX retains its existing `python` default. Windows requires an explicit
absolute path and refuses missing or relative selections. Hook activation still
requires reviewing the generated hook and existing Git hook configuration;
an existing user hook is not replaced by this launcher change.

Validator stdout and stderr stay visible to the hook caller; duplicate checks
do not write a shared temporary report. A nonzero validator exit is reported as
a failed check with its observed status, not automatically as a governance
violation: launch failures and invalid input can use the same status as findings.
Existing profile severity remains unchanged, including advisory duplicate/Ruff
checks and blocking selected Assured checks.

## Interrupted preparation

An unpublished `.preparing-*` directory may contain a partial copy or a replaced
file. The legacy preparation journal records planned content but does not bind
every created file's identity. Recovery therefore preserves any unpublished
preparation, including an empty one, and returns `recovery_required`. Repeating recovery
keeps it preserved. This is an explicit review requirement, not a completed
rollback. Target files have not yet been published by that preparation.

Published transactions continue to use their recorded identities and journal
states for rollback or committed-state recovery. Do not remove preparation
residue merely because its filename, permissions or contents look familiar.

## Windows transaction boundary

The Windows components are import-safe on other hosts. Native functions are
loaded only on a supported Windows interpreter. Paths, reparse points, hard
links, unsupported attributes, extended attributes and alternate data streams
are checked explicitly. The initial metadata-copy primitive accepts a narrow
protected-DACL policy; it does not promise arbitrary security-descriptor copying.

Windows runtime plans use the shared action disposition contract: safe preserve
rows can coexist with eligible changes to other files. Preserved rows remain
bound to their approved observations and are revalidated before publication;
they do not authorize writes or new ownership records. Applying a plan with
only preserve/no-op rows returns `no_changes`. Collisions, unsupported metadata
and refusal actions still block publication. Simulated native-API tests cover
this behavior on CPython 3.11–3.13; native Windows verification is pending.
For an otherwise eligible existing-file update, the Windows implementation now
preserves exactly ARCHIVE or exactly NORMAL through held staging handles. The
approved source and staging identities, security and attributes are checked
before publication, including a staging observation after flush and close.
This does not reinterpret historical metadata digests: a NORMAL/ARCHIVE change
since the recorded baseline remains a preserved conflict. New private records
and newly created content retain the existing ARCHIVE policy. Other attributes,
combined NORMAL flags and unprotected DACLs remain outside this update route.
Injected tests and independent review cover the call contract and refusal
paths. The selected Windows 11 CPython 3.11 J2 RULES route records the actual
ARCHIVE `0x20` attribute before and after replacement/repair. This is evidence
for that observed ARCHIVE branch only; it does not qualify NORMAL `0x80`, every
attribute branch, cross-account ACL transfer or arbitrary metadata. Other
write/close/publication/recovery combinations remain unqualified unless their
own route-matched evidence is recorded.

Directory pins share child-add access so that nested publication and observation
handles can coexist; they deny delete sharing to prevent renaming or removing
the held directory. File pins continue to deny competing writes and deletion.
Existing intermediate directories are opened with read/traversal rights; only
the actual publication parent needs child-add rights. Creating a missing suffix
reopens and revalidates that exact held parent before exclusive creation.
Collision checks and no-replace publication protect individual children; holding
a directory is not a claim that its entire contents cannot change.

Windows replacement uses an explicit intermediate backup slot and no-overwrite
moves. Each possible intermediate topology has a defined rollback path, and an
unknown or changed object is preserved. This is not an atomic exchange. The
one-file coordinator uses `naos.upgrade.windows_transaction.v1` and declares
`application_crash_v1`: it flushes actual intent and checkpoint files, holds
managed-scope and transaction locks, and reconciles one interrupted move before
continuing or rolling back. It checks the bound identities and content on
replay. Caller-owned path and plan mappings are detached before the journal and
handle backend consume them. The existing POSIX v2 journal does not authorize
these additional Windows states.

Create-only publication has a distinct
`naos.upgrade.windows_creation_transaction.v1` journal. It moves an exactly
bound staged file to an absent target without replacing a collision. Recovery
returns that same file to staging; it preserves unfamiliar objects. This
primitive requires the caller to establish creation authority: absence alone
does not prove that an adopter never managed or deliberately deleted a file.

Private runtime bootstrap can create protected directories and files with
access granted only to the current process user. The descriptor is supplied in
the exclusive native create request and verified afterwards. This policy is
for runtime and journal templates; it does not change existing adopter ACLs.

Windows content planning uses its own root enrollment, ownership record,
manifest, receipt chain and archived base bytes. It validates their hashes,
native project-root identity and historical source-policy ownership before
classifying a change. These checks establish local consistency, not author
authentication. Missing or altered evidence refuses mutation; prior adopter
deletions and ownership are retained. Base archives are bounded to 64 MiB per
file. Transient timestamps remain exact revalidation preconditions but do not
by themselves make two content versions different.

Committed request records preserve initialization mode, archetype, backend,
memory choice and any brownfield repository-intelligence binding. A profile
transition can change the profile while retaining those choices. The shared
preview regenerator accepts a validated Windows snapshot directly; an empty
enrollment has no initialization inputs and cannot regenerate a managed upgrade.

The multi-file coordinator uses versioned records, one scope
lock and an ordered publication journal. It publishes content, then immutable
evidence, then the manifest. Replacement retains the original file in a private
backup slot. In record versions 1 and 2, only the global committed marker ends the operation. Before that
marker, recovery reverses a verified publication prefix. Unknown objects or
foreign collisions are retained and reported for recovery; this does not promise
completed rollback when another writer changes the recorded topology.

The explicitly selected `naos.upgrade.windows_operation.v3` variant instead
commits when the exact staged manifest object reaches its destination. Recovery
completes forward even if the last move's marker is missing. Only the single
journal-authorized pending rename may have its bounded metadata transient
restored; matching bytes on a substituted object do not establish that boundary.
Earlier record versions keep their original behavior, and the legacy Windows
archive validator refuses version 3. This variant is an internal component for
the portable-v3 writer; it does not by itself implement public command routing,
local-history validation, or the outer binding/state checkpoint.
Before this variant repairs metadata or writes checkpoints, it checks the
complete operation-directory namespace. Unknown entries and rollback markers
without valid rollback authorization are preserved and cause refusal.

The coordinator persists the canonical plan and intent, enabling another process
to reconstruct recovery without the original in-memory arguments. Plan and
intent records are bounded to 16 MiB; individual checkpoints remain bounded to
64 KiB. The integration tests combine actual planning, archived-base validation,
publication and restored history over an injected native kernel.

The native runtime connects initialization, profile upgrade, add/setup and recovery
commands. Plans bind current target identities, source bytes, intended installed
security, preserved initialization choices and fixed governance checks. Temporary
preview locations and file IDs may differ when regenerated bytes match. Initial
enrollment exclusively creates its control directory; a racing or unfamiliar
control directory is retained and refused. External plans are canonical files
created exclusively outside the project through held handles.

New installed files use the declared protected current-user security policy.
Updates preserve supported existing security only after unchanged-base checks.
Direct add/setup requires managed initialization, and existing updates require
separate external plan/apply. Windows plans expose `digest_sha256`. Recovery
locks the managed scope before selecting an unfinished operation, restores its
verified prefix, then validates the resulting receipt history. Historical
committed and rolled-back operations retain their recorded status without
replaying obsolete target identities. Partial or unknown preparation remains
visible and cannot grant ownership. Repeating identical initialization is a
read-only success only when the recorded request, fixed checks, source inventory
and current content match; changed or deleted files require separate review.
For an already-managed project's `init --activate` route, a successful plan
still returns `3` because activation was not performed; successful planning
without `--activate` retains `0`. This status rule applies on all three OSs.
Managed init requests compact plan output from each adapter: the JSON summary
contains status, requested profile, `mutation_authorized: false`, `plan_saved: false`, and the external-plan next action. Detailed plan rows and records stay
out of that summary. Direct upgrade retains its full plan output and separate
external-plan publication/apply workflow.
Source and injected-kernel tests alone do not qualify native Windows. The bounded
native results above cover the stated snapshots and operations.

The lower-level namespace-durability protocol keeps its explicit refusal: a file-buffer flush does not establish rename persistence
after a system crash or power loss. The application-process-failure coordinator
does not claim that stronger failure model.

Windows observation records encode volume serial numbers as fixed-width
hexadecimal strings and native 100 ns timestamps as decimal strings. These
native values can exceed canonical JSON's exact numeric range; string encoding
retains their identity without rounding.

Maintainers can run the component probe on Windows 11 with each selected native
Python using `python -B tests/native_windows_primitives.py` in the private source
checkout. Use a local NTFS temporary directory and record the host filesystem.
It exercises actual handle observation, no-overwrite moves, collision retention,
file flushing, competing-process write refusal and protected private bootstrap
in disposable files. It is
not a complete installer or process-kill recovery test. On other hosts it exits
2 with `NOT_RUN`; that result is not a native pass.

The separate `python -B tests/native_windows_operation.py` probe terminates a
child process after selected native publication moves, then starts fresh
processes to recover from journal records alone. It also checks committed replay.
Run it on the same local NTFS/Python matrix. The bounded native runs above
exercise this probe, but do not cover full installer activation or hardware
power loss.

`python -B tests/native_windows_operation_v3.py` checks the explicit
manifest-commit variant with fresh-process recovery immediately before and after
manifest installation, including interrupted rename-metadata restoration. It
also checks preservation/refusal for altered or same-byte substituted manifests.
Run it with each supported native Python on local NTFS. Its component result
does not replace end-to-end portable-v3 workflow acceptance.

The `python -B tests/native_windows_cli.py` probe exercises actual CLI initialization
for all four profiles, unchanged repeated initialization, external plan/apply
and repeated recovery. It uses disposable paths containing spaces and Unicode
and checks unmanaged sentinel preservation. Its `EXPECTED_CASE_IDS` declaration
is consumed by the same-platform packet: `naos.native_unittest_result.v1` requires
exact discovery, all declared cases executed, and no skips or expected failures.
This probe remains NOT_RUN without a current qualifying native receipt; the native operation probe supplies separate process-exit
coverage.

The `python -B tests/native_windows_runtime.py` probe uses the actual native runtime
and a small disposable managed project. It terminates a child after each update
move, recovers in fresh processes, repeats recovery and commits a subsequent
update. It verifies content, recorded private metadata and sentinel preservation.
It requires Windows 11 with a local NTFS temporary volume. The bounded native
runs above exercise this probe on each selected Python minor.

The private maintainer probe `tests/native_managed_cli.py` exercises the same
init, upgrade, add and setup commands on each selected native OS. It covers all
four profiles, unchanged repeat, external plans, a Lite-to-Standard transition,
repeated recovery, collision preservation and adopter deletion. It checks a
clean source commit or the sealed installed-package hashes around every command.
Qualification uses local APFS, fixed local NTFS or ext4; WSL and known containers
do not substitute for the selected native hosts.

If an adopter deletes a leaf from the latest committed Windows operation,
`upgrade --recover` refuses the changed committed topology. It does not recreate
that file or treat the deletion as an interrupted publication. The preservation
probe checks the refusal and unchanged project/control-record bytes. This does
not change the separate POSIX journal-version recovery contracts.

The private `tests/native_posix_runtime.py` probe covers macOS and Ubuntu process
interruption at content, receipt, manifest and rollback checkpoints. Recovery runs
in new processes, followed by repeated recovery and another update. It checks
content, file identity, supported metadata and an unmanaged sentinel. Two additional
cases publish 320 leaves in a nested directory, interrupt at full publication and
manifest commit, and verify rollback or commit followed by later reuse. On Linux
the receipt must show the actual ext4 index flag before claiming directory-growth
coverage. Both POSIX probes use the shared container-admission helper and record
its observed inputs. These probes
test application-process failure, not power loss. They belong to the maintainer
qualification packet and are not installed as product tests.

POSIX recovery distinguishes a historical committed transaction from the latest
version of each managed file. An authorized later commit can supersede its live
contents, while historical receipts and recoverable bases remain validated.
Modified current files or invalid historical evidence still require review;
recovery does not recreate old contents over a later committed version.

Recovery validates the complete journal inventory under the managed-scope lock.
It restores one unfinished successor before checking historical committed leaves;
multiple uncommitted candidates are preserved for review. If that rollback cannot
finish, recovery leaves historical committed journals unchanged.

## Spec-pack materialization qualification

On 2026-09-26, the bounded materialization suite passed on macOS ARM64, Ubuntu
x86_64 and Windows 11 x64/NTFS with CPython 3.11, 3.12 and 3.13. Each cell ran
24 test methods. POSIX cells skipped the two Windows-specific tests; Windows
recorded 11 skip events including symlink-privilege subtests and POSIX-only
hardlink cleanup. Windows junction refusal executed successfully without
symlink privileges. The generated Lite-project integration also passed on
macOS/Python 3.11. These are source-candidate results, not fresh installed
artifact qualification or completion of brownfield onboarding.

Coverage includes exact bytes (CRLF, LF, UTF-8 and Ctrl-Z), existing-file skips,
explicit replacement without changing another hardlink owner, late collisions,
source/target changes, read-only Windows behavior, invalid manifests and missing
late sources, unsafe report sinks, and truthful reports after runtime failures.
POSIX uses absent-only hardlink publication; Windows uses absent-only rename.
Windows compares creation time consistently across descriptor/path APIs and
uses the supported timestamp operation only on its unpublished temporary.
Multi-file copying remains sequential without rollback. Hostile concurrent
ancestor changes, network filesystems, ACL/ADS preservation and crash recovery
are not qualified.

## Repository-intelligence POSIX qualification

The repository-intelligence baseline now dispatches through the existing native
POSIX primitives on macOS ARM64 and Linux x86_64/aarch64. Native macOS ARM64 and
Ubuntu x86_64 runs passed the 29-method suite on CPython 3.11, 3.12 and 3.13; each
run skipped three optional GraphML cases because NetworkX 3.6.1 was absent.
That is 156 passed tests and 18 dependency skips across six cells. Linux aarch64
has implementation routing but no native qualification.

The suite covers source-bound plans, explicit enrollment, exact-bundle apply,
read-only queries, repeated activation, unsafe paths, source and bundle drift,
interrupted preparation/publication, recovery and foreign-content/pointer
preservation. Interruption cases in this suite inject exceptions; they do not
prove power-loss durability or every fresh-process crash boundary. These
source-candidate results do not qualify a newly built artifact, optional graphs
or the entire brownfield onboarding workflow. Runtime tuples remain bound into
plans; plans must be regenerated after implementation/runtime changes.

Windows RI public baseline lifecycle integration is described below. The earlier
storage and enrollment receipts establish their bounded component behavior;
they do not independently qualify the public lifecycle or installed artifacts.

### Windows RI private-storage dependency

The RI-specific private-storage component now uses held Windows directory/file
handles for exact private security, coherent bounded reads, native identity
records, exclusive creation, content-bound no-clobber file publication, directory
publication, identity/content-checked cleanup, and explicit locking. Its 11-case
suite passed on native Windows 11 x64/NTFS with CPython 3.11, 3.12 and 3.13
(33 tests, no skips), including abrupt-process-exit lock release and case-alias
publication refusal. Two portable record/path contract tests also passed on
each macOS Python minor.

This component checkpoint preceded RI lifecycle integration. By itself it neither enrolls a
governed scope nor implements RIT journal recovery or active-pointer replacement.
Directory identity is not a substitute for validating generation member bytes.
Full Windows brownfield onboarding and namespace power-loss durability are not
claimed by these storage component tests.

### Windows RI enrollment component

The internal native enrollment adapter publishes a single immutable RI-specific
owner/scope record separately from managed-content ownership. Its confirmed plan
binds the native project identity, observed parents, private security policy,
implementation hashes, Python minor and caller-supplied source authorization
digest. Parent handles remain pinned during preparation and publication; the
record stores the resulting native parent identities. An existing generated
root is refused. Enrollment alone never authorizes activation.

On 2026-09-26, the 14 enrollment tests and 11 storage tests passed on Windows 11
x64/NTFS with CPython 3.11, 3.12 and 3.13: 75 passes, no skips. Coverage includes
fresh-process exit before and after publication, exact completed retries,
cross-project copies, parent replacement, changed prerequisites and foreign
destinations. Incomplete pending files are preserved and refused, including
byte-identical files; automatic recovery is not implemented. Partial parent
creation can require a new plan.

The subsequent public integration now dispatches this adapter from RI planning
and enrollment. The existing source/rules, profile and reviewer gates are retained.
Windows uses a separately versioned enrollment result rather than POSIX owner
paths or digest fields. SQLite bundle generation happens in memory before native
private publication; native parent and leaf pins protect bundle validation and
enrollment from replacement or concurrent writes.

The public/native Windows suite passed 39 methods per Python 3.11–3.13 cell
(117 passes, no skips), including completed enrollment retry, process exit after
enrollment but before result reporting, source and rules drift, reviewer/profile
gates, ACL drift, junction substitution and foreign generated-root preservation.
These are source-candidate baseline results. Optional GraphML, final installed
artifacts and the entire brownfield workflow are not qualified by this suite.
The subsequent native lifecycle and public-command integration are described
below; this earlier enrollment suite alone does not establish activation.

### Windows RI lifecycle adapter: internal validation

The RI-specific runtime now uses `WindowsOperation` v2 for immutable generation
and receipt publication, final active-pointer creation/replacement, and explicit
prefix rollback. Its separate bootstrap binds private directories, templates and
an RI scope lock to the native enrollment record. A reader requires a committed
operation and a validated predecessor chain, then holds the scope lock and exact
native file pins throughout its read. Superseded committed operations are checked
as history rather than replayed against the newer active pointer.

The native lifecycle tests cover first activation, refresh, repeated requests,
superseded history, byte-identical object replacement, journal redirection,
missing checkpoints, preserved foreign objects, and fresh-process interruption
at each publication and rollback move. They use synthetic payloads and qualify
the internal publication mechanics. The public integration below adds real
generated-bundle validation and command dispatch. Incomplete bootstrap/enrollment
recovery and the full installed-artifact matrix remain open. Partial or unrecognized preparation objects are
preserved; automatic adoption or cleanup is not claimed. The recovery guarantee
is limited to application-process interruption with a complete valid intent.


### Windows RI public baseline lifecycle

On Windows 11 x64/NTFS with supported CPython 3.11–3.13, public planning and
explicit enrollment are followed by a new digest-confirmed activation plan.
Apply revalidates source, rules, runtime, profile, reviewer attribution and exact
bundle bytes before and under the RI lock. Reviewer attribution is retained in
the immutable native receipt; it does not authenticate the reviewer. Shared
macOS/Ubuntu dispatch and POSIX provenance formats are retained.

Validation, status, query, refresh and explicit recovery use the RI native
adapter. Query and adoption snapshots hold a native reader lease through
SQLite/GraphML reads and closing source validation. Windows context and apply
results use v2 schemas with `WOP-` operation identifiers and native bindings;
POSIX results retain v1 and `RIT-` identifiers. A stale but structurally valid
generation can be a refresh base. An uncommitted pointer cannot be consumed.

This source-candidate baseline qualification is separate from full brownfield
onboarding and final installed-artifact acceptance. Optional GraphML remains
dependency-gated. Incomplete enrollment, bootstrap and pre-intent preparation
objects are preserved/refused, and cross-version native history migration is
not qualified. Exact runtime and implementation bindings still apply.

RI `status` reports an otherwise integrity-valid generation as `stale` when its
exact runtime (including Python/SQLite patch and component identity) or producer
implementation differs, and names `identity_drift_fields`. It completes stored
member, receipt, database and graph validation first: corruption combined with
drift remains `invalid`. Setup reports `refresh_required` with continuation
refused and distinguishes this from ordinary source-stale refresh guidance.
Already-supported engine/public-reader-only changes may use the existing
explicitly reviewed refresh. Otherwise restore the bound environment, or obtain
a separately qualified, explicitly approved migration/rebind. This diagnostic
does not make runtime/component drift an eligible refresh base: strict
validation, query/snapshots and refresh leases retain their exact bindings.
Root/provenance mismatch remains `invalid`; restore the bound root or use that
separate rebind boundary. No path normalization, history rewrite, migration or
permission expansion is automatic.

A reviewed RI refresh plan now binds an optional `control.refresh_base` prior
witness. Fresh eligible plans record either the exact existing prior generation
or explicit absence. The digest covers prior pointer bytes/native identity,
manifest/control bindings, runtime/components/enrollment, immutable member
bytes and native metadata/security, and receipt membership. Under the existing
publisher lock, apply compares that approved baseline and keeps immutable prior
objects pinned through publication. ACTIVE is compared before its intentional
replacement and is not pinned across publish. POSIX parent membership permits
only the exact journalled new transaction/generation sibling; prior immutable
metadata remains exact. Windows retains complete HandleInfo, private-security
and file-ID witnesses and uses the unchanged native history/publisher runtime.

This prior-custody role permits only exact engine/public-reader digest changes
within implementation contract v1. Canonical/local-context implementations,
native enrollment/storage/runtime implementations, runtime/component identity,
and generation/receipt schema contracts remain unchanged. The witness binds
current strict schema-file digests, including the current plan schema, against
later plan/apply drift and completed retries. The schema snapshot has an exact
closed member list. Historical manifests contain schema IDs rather than historical
schema-file hashes; this operation validates them under the unchanged declared
contracts and does not reconstruct historical schema bytes. Public validation,
query and snapshots still reject old implementation identity; the newly
published generation must pass strict current-engine validation. No old source
ID or manifest is rewritten. Legacy plans without `refresh_base` retain strict
same-engine behavior and cannot authorize an engine transition. Exact completed
plan/bundle retries require strict current validation and do not replay the old
baseline approval. Changed pointer identity (even identical bytes), prior member
bytes/security/metadata, unsupported custody changes and target/source drift
refuse. A new plan is required after baseline drift. Witness capture is bounded
to 4096 immutable files and 256 MiB; larger histories refuse rather than truncate.
A fresh Windows plan for exact currently active content can be acknowledged
without a new native publication. This requires a non-null, exact reviewed
`refresh_base`, full native history/reader pins under the existing scope lock,
strict current implementation/source/runtime/schema validation, exact complete
approved member hashes and bundle identity, and identical full authorization
including reviewer attribution. Only the public plan digest may differ from
the original stored request. Missing, inactive, reserved, superseded, stale or
corrupt generations cannot authorize this acknowledgement. Native runtime,
request identity, original pointer, activation receipt and history are unchanged.

The Windows v2 apply result reports `already_active` and
`activation_effect: confirmed_existing_content_no_publication` for this case.
Its top-level `plan_sha256` acknowledges the actual newly confirmed plan;
`persisted_activation_plan_sha256` and `validation.generation.plan_sha256`
identify the original durable activation. No new approval, transaction or
activation receipt is written. `exact_bundle_bytes_promoted: true` means the
approved exact bundle bytes are already active, as for an exact retry; it does
not claim another promotion occurred. Consumers requiring durable attribution
for each new approval cannot infer it from this no-op. Ordinary exact request
retry and POSIX publication/result semantics remain unchanged.

Application-process interruption continues to use existing explicit recovery;
this contract does not extend native runtime/history migration or power-loss
qualification. Cross-host qualification is separate from local source tests.

Explicit recovery also handles a complete witnessed preparation whose operation
journal directory was never created. It verifies the exact staged identities,
empty destination, prior committed history and unchanged pointer before creating
a rollback-only journal. This path publishes no generation files and preserves
the staged evidence. A preexisting partial operation directory is not adopted;
interruption before a complete intent remains a preservation/refusal case.

During first managed-content activation, the final brownfield preflight can
observe the confirmed empty managed baseline while the same native operation
holds its locks and has not published content. This observation is restricted
to that root, source policy, operation and callback thread, and is revoked before
publication or on error. Ordinary provenance inspection still refuses incomplete
enrollment. A direct checkout CLI and its installed-style script imports may
share this observation only when both refer to the exact same source file.

## Brownfield workflow and package-version acceptance

On 2026-09-27, actual public brownfield activation followed by Quickstart-to-Lite,
Lite-to-Standard, Standard-to-Assured and Assured-to-Standard transitions passed
on macOS ARM64/APFS, Ubuntu x86_64/ext4 and Windows 11 x64/NTFS with CPython 3.11.
Each fixture used SQLite/FTS baseline enrollment and activation, external plans,
digest-confirmed apply, repeated apply and repeated recovery. Checks preserved
existing adopter files, staged/unstaged/untracked content, the adopter's Git hook
and an external sentinel. An unchanged POSIX refresh reports `no_changes` and
correctly refuses mutation; that refusal is not counted as a profile transition.
These source workflows do not qualify all Python minors, installed artifacts or
effective execution of every generated policy/hook.

Separately installed 1.1.0 and a disposable 1.1.1.dev0 test successor completed a
Lite upgrade on all three OSs with CPython 3.11. macOS and Ubuntu used frozen HEAD
1.1.0; Windows used a retained September 26 remediation-era 1.1.0 wheel because
the frozen HEAD baseline failed initialization at its old stream-enumeration
defect. The Windows result is therefore not released-baseline qualification.
Each successful upgrade applied actual upstream content changes while preserving
adopter edits and Git staging, then passed repeated apply and recovery. The test
successor is not a release, and no canonical version changed. Interrupted
cross-version recovery and the full artifact/minor matrix remain separate.

## Git and workflow text boundaries

Completion-evidence Git output is decoded as UTF-8 with reversible surrogate
escapes for invalid bytes. This avoids locale-dependent replacement of path
bytes; it does not normalize filenames, source content or evidence hashes.

Architecture/project coherence, spec validation, code-quality audit and
registry/spec synchronization keep the
selected console encoding and escape characters it cannot represent. Project
coherence requests UTF-8 output from its Python children and decodes it
reversibly, retaining partial diagnostics on timeout. Exit-status decisions
remain unchanged. These rules apply to human diagnostics, not artifact writes.
The console helper follows generated script remapping for Lite, Standard and
Assured; Quickstart retains its existing absence of automation scripts.

Windows existing-directory initialization retains source-bound RI prestart checks
when RI is not applicable. That diagnostic omits prospective native enrollment
parent observations, so preparing NAOS private directories does not change its
decision identity. It cannot authorize RI enrollment or apply. Applicable plans
retain exact native enrollment bindings; source changes and unowned generated
roots still refuse activation.


## Strict adoption report publication

Strict reports use POSIX directory descriptors or the native Windows report
adapter in `scripts/naos_windows_report.py`. Windows pins ancestor directories,
creates same-directory stages exclusively, verifies bytes and supported security,
and publishes through a held parent. Existing authorized report names may be
refreshed; first publication uses no-overwrite semantics. This report-specific
replacement does not change managed-upgrade `rename_no_replace` behavior.

Ordinary new outputs inherit parent security. Existing owner/group/DACL and
NORMAL/ARCHIVE attributes must be preserved exactly within the selected metadata
contract, including verification after rename/close. Unsupported preservation
fails closed. Report publication is not destination compare-and-swap, a multi-file
transaction, or a power-loss guarantee. `--no-write-preview` remains available.
Generated Lite/Standard/Assured scripts include a source-accounted copy of the
canonical native handle helper and need no installed `upgrade_contract` package.

### Native absent-store rebind planning component

The internal `upgrade_contract.rebind_planning.plan_absent_store_rebind` captures
portable history and current managed leaves while both native readers remain
open. It observes legacy-control absence through the same working-tree reader,
constructs the existing digest-bound rebind plan, and revalidates dependencies
before returning. Expected owner/head digests and a new binding ID are explicit
inputs; self-consistent history does not authenticate those expectations.

This variant requires absent v3 local storage and absent legacy control state.
It preserves the exact observed adopter edits and deletions in the proposed
plan. An existing store requires its separate migration/recovery path. Planning
creates no local record, directory or lock and grants no mutation authority.
The returned observation is detached and must be checked again during explicit
enrollment. Native store inspection, preparation, staging, publication and recovery are
separate internal operations below. Legacy migration and public CLI integration
remain unfinished; this component is not a new adopter workflow.

### Absent-store rebind journal inspection component

The internal `inspect_absent_store_rebind` validates an existing first-rebind
journal against an explicitly supplied expected plan digest. It holds the native
root readers and an exclusive, nonblocking existing scope lock while checking
private storage, complete bounded directory inventories, canonical operation
records, progress transitions, native publication identity and checkpoint state.
It creates no files and performs no recovery action.

A candidate observed at its published name with the recorded native identity
requires forward completion, even when the last progress record still says
`publish_pending`. A prepublication operation requires rollback. An exact final
checkpoint awaiting its terminal marker remains recoverable; an absent prior
checkpoint is allowed only when the complete history never registered one.
Unlisted files, missing registered state, changed pending working bytes, unsafe
objects and replaced binding identities are preserved and refused. Completed
checkpoints can report later adopter changes without rewriting them.

Results are detached and carry `mutation_authorized: false`. This inspector is
one lifecycle dependency; it is not a native writer, legacy migration, public
command or proof that the whole moved/cloned-project workflow is complete.

## Prepared binding publication boundary

The internal `rebind_publication.publish_prepared_rebind` operation accepts only
an explicitly selected `publish_pending` journal with a witnessed candidate.
It keeps one native exclusive lock across fresh, fully revalidated inspections,
then moves that exact candidate into the absent binding slot using native
no-replace publication. Retrying a completed rename performs no further writes.
Progress remains `publish_pending`; terminal checkpoint completion is a separate
operation below. Legacy migration and public enrollment remain unfinished.

POSIX custody pins directory identities and protection metadata separately from
read-only inventory snapshots, so expected file renames do not disable final
snapshot validation. Across a mutation window, ancestry custody permits changes
to directory link counts, while retaining positive-link validation and fresh,
bounded checks of exact path spellings, native identity and protection metadata.
Root ancestry checks disregard only positive directory link-count differences;
managed directory inventories and leaves retain strict observations. An incomplete
ancestor metadata observation is retried at most three times only when typed
native evidence shows link-count churn without identity or protection changes.
Each accepted attempt returns a fresh complete strict metadata observation; Linux
retains its link-count and change-time guards around ACL, xattr and flag inventory.
Unknown metadata failures, change-time-only drift, persistent churn, replaced or
unlinked roots and protection changes still refuse. Exact spelling checks and
inventory budgets remain unchanged. Linux replay
directory commitments use the same comparison policy for kernel layout flags as
local bindings; other flags, identity, permissions and recorded bytes remain exact.
Windows retains native directory handles and the same lock
through publication. This concurrency contract covers lock-cooperating writers
and process interruption. POSIX name-based rename is not atomic source-identity
compare-and-swap against a noncooperating same-user process; postchecks detect
substitution but cannot undo it. Failures never trigger foreign-file cleanup.

## Published binding checkpoint completion

The internal `rebind_checkpoint.complete_published_rebind` operation resumes an
already published binding through immutable `committed`, `finalize_pending` and
`finalized` progress records, a private `state.pending.json`, replacement of the
exact registered state, and a terminal marker. Each step starts from a fresh,
complete inspection under the same exclusive lock. Completed retries are
read-only and can report subsequent adopter edits. It does not publish an
unpublished candidate or execute prepublication rollback.

Only a complete, exact staged checkpoint at finalized progress, with its exact
registered predecessor, is admissible. An already present terminal marker must
also match the complete operation history exactly. Windows has a
separate private-checkpoint replacement primitive for reopening this stage;
existing report replacement behavior is unchanged. Native identity and bytes
are checked before replacement. The same cooperating-writer concurrency limit
applies: replacement is not atomic destination-identity compare-and-swap.
An interrupted partial progress, stage or terminal write is retained and refused;
this component does not claim automatic recovery from every byte-write boundary.

## Prepublication binding rollback

The internal `rebind_rollback.rollback_prepublication_rebind` operation persists
`rollback_pending` before deleting its staged binding. It checks the candidate's
journaled native identity and exact bytes immediately before deletion, then uses
a fresh inspection to prove absence before recording `rolled_back`. A published
binding always prevents rollback and requires forward completion instead.

Rollback preserves the portable history and managed working bytes. Its final
checkpoint has no local binding and retains the portable head. A previously
registered checkpoint uses checked replacement; a history-proven never-registered
checkpoint uses native no-replace publication. Missing registered state is not
accepted as an earlier absent predecessor. Complete persistence boundaries are
retryable, including candidate deletion; partial or foreign records are retained
and refused. Completed retries are read-only and can report later adopter edits.
The cooperating-writer concurrency limitation remains; POSIX unlink is not
atomic source-identity compare-and-swap against a noncooperating same-user process.

## Native private preparation and candidate staging

`rebind_preparation.prepare_absent_store_rebind` rechecks an explicitly approved
plan before creating private local directories and an empty lock. Created native
identities remain held through lock acquisition. It checks portable history,
managed working bytes, and legacy-control absence again before writing the
plan, intent and initial progress. Existing private `.naos/local` may be retained;
an existing managed store cannot be silently adopted.

`rebind_candidate.stage_prepared_rebind` registers the exact prepared operation,
writes its candidate binding, records the candidate's native identity and private
metadata, then advances to `publish_pending`. It does not publish the binding.
Complete registration and progress boundaries are retryable. A process exit
after candidate creation but before recording its witness leaves an unrecorded
candidate: subsequent operations preserve it and refuse to guess ownership.
Partial bootstrap directories or records are also retained and refused. These
operations do not claim automatic repair of every interrupted write.

Windows permission checks compare owner, group, DACL and protection against the
private policy. Native observed descriptors are compared with other native
observations; the SDDL converter's byte encoding can differ legitimately. File
timestamps are checked within read intervals, while reopened records retain
exact native identity, security and bytes across writer-handle closure.

These APIs connect the internal absent-store lifecycle on a supplied valid v3
portable history, including moved or cloned working trees with approved edits
or deletions. They are not public init/add/upgrade commands. Legacy migration,
existing-local-store handling and final installed-artifact acceptance remain
separate work.

## Legacy migration evidence boundary

Migration must identify the source format explicitly. POSIX managed history uses
`.naos/upgrade-v1/managed-content` and its scope record; Windows managed history
uses `.naos/upgrade-v1/windows-content` and its own owner record. The shared POSIX
`OWNER.json` and repository-intelligence scopes must remain separate.

Native probes of the current legacy source show that an extra migration marker
file alone does not stop managed mutation. An unsupported successor at the active
per-capability scope/owner path causes these apply/recovery paths to refuse.
This is a tested refusal point, not an enabled migration operation or a guarantee
about arbitrary historical installed binaries. A migration must first prove
complete source quiescence while holding the existing legacy scope lock; unfinished
Windows enrollment recovery has a different predecessor-validation path.

Retain the actual original scope/owner file under migration-journal custody before
installing a successor. Restoring its bytes after overwriting it is insufficient:
Windows legacy recovery also binds native metadata. The native probe recovered
successfully after restoring the retained original object, and required a fresh
update plan after rollback changed native observations. Partial/foreign state
must remain preserved and refused. Archive byte hashes alone do not establish
native rollback authority, source validity or ownership.

The internal `legacy_migration_records` codec binds a sorted, bounded inventory
of original archive bytes to explicitly expected owner/scope/head digests, the
unchanged legacy project identifier and a new portable UUID. Its successor record
binds the approved lineage digest and exact original scope/owner bytes. Inputs
are revalidated even when supplied through a typed record object. This codec
checks structure and byte consistency only: complete legacy replay, current
native custody, quiescence and permission to migrate must be established by the
migration inspector and journal before any record is published.


### Historical legacy archive replay

The internal legacy replay readers validate supplied archived bytes separately
from the current checkout. POSIX plan records retain their original absolute
POSIX root text; Windows records retain their original volume and file IDs.
Neither reader resolves those historical identities as the current root or
uses them to authorize a write. The existing live plan validators continue to
resolve and check the current native project root.

Replay requires an approved lineage digest, independently expected raw owner,
scope/root, manifest and source-policy digests, and the committed receipts and
recoverable bases. Historical source policy determines ownership; the current
active policy cannot silently reclassify it. Results distinguish records read
for semantic validation from other archived files such as transaction journals.
Those remaining files are preserved but do not establish completed recovery.

Successful byte replay alone proves neither complete native inventory nor
exclusive custody or source quiescence. Migration must still capture and
validate the source under its native scope lock, retain the exact original
pointer object, and publish/recover through the reviewed migration journal.
Public moved/clone commands and installed-artifact qualification remain separate
acceptance steps. Working edits and deletions are not reconstructed from bases.

POSIX chronological replay also has a deterministic admission limit: at most
256 transactions and a cumulative work charge of 256 MiB, calculated as the
transaction count times four complete manifest byte lengths plus all referenced
receipt byte lengths. Prefixes and cached reads are deliberately overcounted.
Exceeding a limit refuses replay; it never truncates history or permits mutation.
Policy resolution has a separate 64 MiB work charge: every uncached historical
policy binding is charged the complete policy bundle byte length before that
bundle is validated. Previously resolved bindings reuse the cached result.

### Held legacy capture and POSIX terminal journals

The internal `legacy_archive_capture` reader acquires the existing legacy scope
lock using the current host primitives, captures complete file and directory
inventories (including empty directories), and revalidates bytes, namespaces,
private protections and the lock before release. Either legacy layout can be
captured on macOS, Ubuntu or Windows. Existing unsafe protections, hardlinks,
unknown object types, changed evidence and exceeded limits are refused without
repairing or deleting the source. Limits include 1,024 directories, depth 64,
10,000 files, 64 MiB per file and 256 MiB total; underlying native-reader budgets
also apply. The read-only context does not authorize a migration write.

`legacy_posix_terminal` combines historical replay with shared pure journal
grammar, committed journal/manifest coverage and policy binding. It consumes the
actual directory-only capture inventory and treats old root/native IDs as
historical evidence. Unfinished, unknown and pending records, conflicting
rollback evidence and unexplained control objects are preserved and refused.
This conservative variant also refuses unreferenced legacy base blobs. It does
not repair or restore current working files from old journals. A returned value
is not continuing native custody or permission to mutate.

The combined component passed 126 checks: 14 test methods on each of macOS,
Ubuntu and Windows with Python 3.11, 3.12 and 3.13, with no failures/errors/skips.
The shared journal refactor also passed 39 existing macOS recovery tests. This
is internal dependency evidence: Windows-format operation terminal validation,
journaled migration, public moved/clone routing and final installed-artifact
acceptance remain pending. No user command or support claim is enabled here.

### Windows historical terminal journals

The internal `legacy_windows_terminal` reader now checks current runtime v2
histories with retained directory witnesses. It reuses canonical operation
decoding and checkpoint grammar, requires exact committed receipt/operation
coverage, and refuses unfinished or conflicting histories. Older histories
without the required directory witnesses remain unsupported by this reader.

Every saved publication slot is checked, including consumed stages. Historical
root containment, operation staging names, content targets, fixed manifest and
evidence roles must agree with the plan and replayed records. Retained backups
and rolled-back staged files are expected evidence whose exact bytes are
validated; they are not silently removed. Rolled-back staged control records
are replayed as a hypothetical projection only, with cumulative replay input
limited to 256 MiB. They confer no committed ownership or mutation authority.

Historical policy snapshots bind to the validated receipt and supplied policy
catalogue; a changed active catalogue does not erase supported older history.
Old root and file identities remain historical records. Current-host custody
comes from the separate held native capture, and working edits/deletions are
not repaired from old records.

The final combined component passed 387 checks: 43 methods on each of macOS,
Ubuntu and Windows with Python 3.11, 3.12 and 3.13, without failures/errors/skips.
It includes prior POSIX terminal, native capture, legacy apply/recovery refusal
and operation regression checks. An additional 29 injected Windows runtime
regressions passed on macOS. The following section records the subsequent
portable authority work. Journaled native migration, public command routing and
installed-artifact acceptance remain pending. These internal results do not
enable a user-facing command.

### Portable legacy genesis authority

The internal `legacy_authority` builder returns candidate bytes without modifying
any checkout. Its `legacy_projection` owner requires a first `naos-migrate`
receipt derived by replaying the complete preserved legacy archive and terminal
journals. Original project, transaction, receipt and policy identities remain in
lineage and the per-path origin map. Portable receipt `R00000001` denotes the
portable genesis, not the original creation date or transaction.

POSIX policy aliases and raw legacy policy bindings are retained alongside the
resolved canonical policy identity. Ownership and creation policy are preserved;
initialization inputs must be representable exactly or conversion refuses.
Executable intent must cover every seed path and bind the exact archived base
bytes. POSIX intent must match the recorded historical mode; Windows intent is
explicit supplied data, never inferred from filenames, suffixes or current files.
The inventory's source and output both identify the byte-identical archived base,
not an inferred template source. Portable readers recompute this projection,
check its origin map, and include the archive reads in existing byte budgets.

This establishes internal historical consistency only. Native custody, migration
approval, original-pointer retention, old-writer fencing, journaled publication
and public init/add/upgrade routing remain separate requirements. No end-user
migration command is enabled by this codec change. macOS, Ubuntu and Windows use
the same codec and their existing contained native readers.

The authority/reader component passed 396 focused checks: 44 methods on each
of macOS, Ubuntu and Windows with Python 3.11, 3.12 and 3.13, with no failures,
errors or skips. This includes native contained reading of both legacy source
formats and existing portable-history regressions. It does not qualify a native
migration writer or an installed public workflow.

### Native legacy migration planning

The internal `plan_legacy_migration` observes the selected legacy source under
its existing scope lock, derives the portable candidate, and captures every
managed working path through the same native reader. A plan binds the exact
candidate file inventory, source file/directory witnesses, separate lock witness,
fence bytes, current working edits/deletions and absent destinations. The other
legacy managed-content store must be absent; unrelated scopes are preserved.
The source format is independent of the current OS. Native control-file renames
must remain on one volume. Planning performs no writes and grants no continuing
custody. Execution must reacquire locks and revalidate the approved plan; native
journaled migration and public commands remain unfinished.

The native planning component passed 234 checks (26 methods on each of the nine
OS/Python cells), with no failures, errors or skips. Both legacy formats were
planned on all three OSs. The maintained native writers refused apply/recovery
while the original control pointer was absent, and resumed after restoration of
the same original object. This characterizes one publication interval; it does
not qualify the unfinished migration journal or writer.

### Native migration journal preparation

The internal `prepare_legacy_migration` now reconstructs the exact approved plan
under the existing legacy lock, closes its immutable observation window, then
creates a private v3 journal while holding legacy and v3 locks in that order.
Dedicated custody pins stable directory identity/protection and checks namespace
continuity. Fresh immutable readers verify persisted record bytes and actual
created identities, unchanged source history and current working files. Existing
legacy control objects are not moved or replaced at this preparation boundary.

Preparation passed the final selected 189 checks across macOS, Ubuntu and Windows
with CPython 3.11, 3.12 and 3.13, including 54 actual child-process exits. One
initial macOS 3.11 ancestry-change failure is retained: creating evidence files
above fixture TMPDIR changed APFS directory link count during observation. The
complete 21-method cell passed with unchanged source after ancestor writes
stopped. See `LEGACY_MIGRATION_PREPARATION_RESULT.json` in the portability audit.

Partial storage is preserved and retries refuse it. The subsequent retention
component below advances beyond this preparation boundary. The subsequently qualified fence is described below. Portable head/local
binding publication and complete migration recovery remain unimplemented. This component is not public migration or
installed-artifact acceptance, and makes no power-loss durability claim.

### Native prepared-journal resume and private candidate staging

A complete prepared migration journal can now be reopened under legacy-then-v3
locks, with exact approved-plan, source-history, working-tree, journal-inventory
and native-identity checks. The immutable observation window closes before the
mutation window. Initial preparation still refuses an existing local store;
resuming a journal is a distinct validated operation.

`stage_prepared_migration` copies the exact portable projection into the private
journal's `portable.pending` directory. Before writing `candidate_ready`, it
checks the complete directory/file inventory, exact bytes, actual native
identities and unchanged source/working state. A recorded complete stage can be
reopened and returned without additional mutation. A copy interrupted before
its native witnesses are journaled remains preserved and refused. Byte equality
alone does not permit adoption or cleanup of a substituted object.

This component passed 207 checks across macOS, Ubuntu and Windows with CPython
3.11, 3.12 and 3.13, including 81 actual process-exit cases (27 staging and 54
preparation regression cases), with no failures/errors/skips. Tests also cover
an explicitly allowed 17 MiB archive-blob write while the default journal-record
limit stays 16 MiB. Explicit larger leaf writes remain capped at 64 MiB.

The staging receipt covers `prepared` and `candidate_ready`. The subsequent
retention and fence receipts below extend native inspection through `fenced`.
Head/binding and complete migration recovery remain pending; later pure-codec
phases still refuse in native inspection.
No public migration or installed-artifact acceptance is claimed. See the audit's
`LEGACY_MIGRATION_STAGING_RESULT.json` for the exact candidate and native logs.

### Native original-pointer retention

`retain_original_pointer` now persists a pending record before moving the exact
original control object into the private migration journal. A fresh source scan
observes actual paths; it does not rewrite the immutable capture to pretend the
old pointer is still present. All other source records, working files, candidate
stage and both locks must remain exact. At either pending-move recovery state,
the original must exist at exactly one permitted location. Both-present,
both-absent, foreign identity or changed-byte states refuse without cleanup.

POSIX uses pinned descriptors and a native no-replace move. Windows persists
its complete pre-move rename identity and uses the existing restoring backend.
Only the bounded creation-time/ARCHIVE transition of that same original object
may be restored during `retain_pending`; exact original metadata is required
before recording `original_retained`. Repeat calls return the completed state.

The retention/inspection/staging component passed 198/198 native checks across
macOS, Ubuntu and Windows with CPython 3.11, 3.12 and 3.13. Process-exit tests
cover pending-record, completed-move and completion-marker boundaries, plus
Windows interruption before metadata restoration. These are application-process
recovery checks, not power-loss certification. Exact packet and logs are in
`LEGACY_MIGRATION_RETENTION_RESULT.json`.

This internal retention component does not expose a public migration command.
The fence is qualified below; atomic portable tree/head publication, local
binding, pre-head rollback and post-head recovery are still pending. Public moved/clone
workflows and final installed-artifact acceptance remain open.

### Native legacy-writer fence

`install_legacy_fence` now exclusively stages the approved unsupported-schema
successor, verifies its exact bytes and actual native identity, and persists a
`fence_pending` record before moving it to the legacy pointer. The same staged
object must exist at exactly one permitted location. Interrupted pending moves
resume without repeating completed publication; a complete `fenced` result is
idempotent. Unrecorded/partial staging, ambiguous locations, foreign native
objects or changed bytes refuse without cleanup.

The original control object stays retained and independently validated through
every fence state. Windows commits the fence's own pre-move RenameIdentity;
only a bounded pending rename-metadata state may be restored, and completion
requires the exact original staged-fence identity. This never weakens the
separate retained-original witness. POSIX uses pinned native descriptors and
no-replace rename. Fresh read snapshots keep actual namespace observations.

The frozen component passed 216/216 checks across macOS, Ubuntu and Windows,
CPython 3.11, 3.12 and 3.13: fence installation, retention, inspection and
maintained native legacy-writer refusal. Tests include real process exits at
stage-write, pending-record, native-move and completion-marker boundaries;
Windows also covers pre-restoration exit and injected permitted creation-time
drift. No failures/errors/skips occurred. macOS Python versions ran in parallel
only after separate fixture roots were created, preserving stable ancestors.
See `LEGACY_MIGRATION_FENCE_RESULT.json` for source identity and native logs.

Portable tree/head publication, local binding/checkpoint, complete pre-head
rollback and post-head forward recovery remain pending. The portable head is
still absent in these tests. This is internal component evidence, not public
migration, installed-artifact acceptance, arbitrary historical-writer support,
or power-loss certification.
