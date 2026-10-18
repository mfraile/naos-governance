# Selected task-context integrity

Task-context packs can optionally freeze an explicit selection of relevant source files and compare those bytes at a later checkpoint. This detects selected-input drift and project/task/session mismatches. It does not establish IDE delivery, model consumption, rule adherence or control effectiveness.

Start an existing task session and retain its reported session ID. The project identity is the exact `https://` or `ssh://` origin URL from local Git configuration, at the exact worktree root. This editable local binding is not authentication or authorization. A missing or ambiguous origin/session cannot match. Other remote URL syntaxes remain unsupported by this optional contract.

```sh
naos session-start --task T-001 --profile standard --new-session --json
naos task-context --task T-001 --profile standard --freeze-context \
  --project-id https://example.test/team/project.git --session-id SESSION-ID \
  --context-input specs/03-requirements.md --context-input src/component.py \
  --expected-output src/component.py --output naos/context_packs/T-001-start.json
python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('naos/context_packs/T-001-start.json').read_bytes()).hexdigest())"
naos task-context --task T-001 --profile standard \
  --check-context naos/context_packs/T-001-start.json --pack-sha256 PACK-SHA256 \
  --project-id https://example.test/team/project.git --session-id SESSION-ID --json
```

Replace the task, paths, origin, session and digest with the selected values. `SESSION-ID` and `PACK-SHA256` are placeholders; session IDs must follow the existing lowercase portable session grammar. Freezing requires a new project-relative output file and never overwrites an existing pack. Keep that exact file and its independently supplied digest. A mutable filename is not identity. The existing default pack and derived Markdown remain compatible; Markdown is outside the frozen byte contract. Freeze mode writes JSON only.

Only repeated `--context-input` files and the selected task-context rules file are compared. Selection completeness belongs to the operator: include each relevant constraint/source and review exclusions. The manifest does not claim to cover every source summarized by the pack. Inputs are read at freeze time, which is not an atomic snapshot of earlier generator reads. Report summaries can be truncated according to the existing pack rules; these summaries and unselected files are outside the comparison. Explicit file inputs are hashed whole or receive a nonmatching partial/oversized state, never a silently truncated hash.

Bounds are 128 unique inputs, 2 MiB per input, 16 MiB total and 4 MiB per selected pack. References use canonical relative POSIX paths on every OS; traversal, aliases, Windows reserved names/ADS, symlinks and reparse points are refused. Known memory-store path components are refused, and operators must not select private memory payloads or secrets at other paths. Descriptor reads and existing strict report writes preserve the local path boundary; this is not a hostile concurrent-process guarantee.

File hashes cover raw bytes, including LF/CRLF differences. There is no newline or filename-case folding. The selection digest covers UTF-8 JSON with sorted keys, compact separators, ASCII escaping and no nonfinite numbers. The domain uses strings, integers, booleans and null. The complete saved pack digest includes its JSON serialization and final newline; it lives outside the pack, avoiding a self-hash cycle. Rules use a project-relative or `kit://` reference and current file digest. Different package rules bytes require review or a new pack.

Results distinguish `matched`, `changed`, `missing`, `unsafe`, `unreadable`, `oversized`, `partial`, `scope_mismatch`, `superseded` and `unknown`. Inputs declared missing/partial at freeze cannot later become matched without a refresh. Preserving modification times does not hide drift; changes outside the selection do not invalidate it. Files declared with `--expected-output` still detect changes at checkpoints. At session end/completion their modified bytes are separately `expected_changed`, preserving the starting digest without making intended implementation edits an impossible completion condition. Deletions and unsafe outputs still require review. This allowance does not validate those outputs; existing Git subject/tree/path completion checks remain authoritative.

For a lifecycle checkpoint, pass `--check-context`, `--pack-sha256`, `--project-id` and the explicit existing `--session-id` to `naos session-checkpoint`, or inspect without writes:

```sh
naos session-checkpoint --task T-001 --profile standard --session-id SESSION-ID \
  --check-context naos/context_packs/T-001-start.json --pack-sha256 PACK-SHA256 \
  --project-id https://example.test/team/project.git --inspect-session --json
```

This selection never creates a session implicitly. Inspect/check the session-end context before separately closing the session. A refresh writes another new pack with `--supersedes-pack-sha256 OLD-PACK-SHA256`; preserve the predecessor and explicitly select the successor. There is no global latest-pack registry or claim of authenticated revocation.

For an opt-in completion join, add `selected_context` to the existing `naos/ac_completion_evidence.yaml` and `context_binding` to each completion:

```yaml
schema: naos.ac_completion_evidence_manifest.v1
selected_context:
  path: naos/context_packs/T-001-start.json
  project_id: https://example.test/team/project.git
  task_id: T-001
  session_id: session-001
  pack_sha256: REPLACE_WITH_COMPLETE_PACK_SHA256
  manifest_sha256: REPLACE_WITH_CONTEXT_INTEGRITY_MANIFEST_SHA256
completions:
  - ac_id: AC-001-1
    status: claimed_complete
    context_binding:
      project_id: https://example.test/team/project.git
      task_id: T-001
      session_id: session-001
      pack_sha256: REPLACE_WITH_COMPLETE_PACK_SHA256
      manifest_sha256: REPLACE_WITH_CONTEXT_INTEGRITY_MANIFEST_SHA256
    # Retain the existing repository_binding and passing evidence items here.
    evidence: []
```

The example is intentionally incomplete: fill existing repository binding/evidence before claiming deterministic completion. The consumer checks the selected pack and identity join, then retains all existing repository/commit/tree/path validations. A missing or mismatched selected binding cannot count as satisfied. A binding to the selected successor's declared predecessor is `superseded`; other wrong digests are `scope_mismatch`. Replay detection is relative to this explicit selection, not a guarantee against coordinated editing of the manifest and pack.

Old packs/manifests remain readable with explicit `unknown` context-integrity evidence; existing completion behavior and profile exit policy are retained when no context contract is selected. No new mandatory Quickstart/Lite policy is introduced. Existing completion findings and satisfied/unsatisfied summary feed their current consumers; no separate gate or readiness promotion is added.

The local deterministic CLI is the issuer, and selected bytes at check time are its observable. Prepared files, host discovery, retrieved files, actual delivered request context, agent-claimed use, bounded application and measured behavioral effectiveness remain separate evidence dimensions. The comparison always reports host delivery `not_observed`, model use `unknown` and behavioral effectiveness `not_evaluated`, even if an editable input claims otherwise. Trace declarations/imports keep their existing limits. Host invocation policies, runtime telemetry, shared-deployment authorization and personal memory remain separate scopes.
