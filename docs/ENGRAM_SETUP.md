# Engram Memory Setup

Engram is NAOS's recommended optional provider pattern for durable episodic memory. Memory remains advisory: repository source, tests, policy, deterministic reports, and human decisions retain authority.

NAOS does not install Engram, configure MCP clients, invoke provider installers, synchronize memory, or make network calls. Setup records a reviewed local disposition only. Provider access, MCP access, project identity, and durable-write authorization must be configured, authorized, and verified independently before use.

## Storage Model

Engram runtime data uses one per-user data directory outside project repositories:

```text
data directory: ~/.engram
database:       ~/.engram/engram.db
replication:    local
```

The effective data directory is selected in this order:

1. `ENGRAM_DATA_DIR`
2. `memory.data_dir` in `configs/naos_memory.yaml`
3. the provider default `~/.engram`

The database path is always derived as `data_dir/engram.db`; do not pass a database file as `data_dir`. NAOS checks directory and database-file metadata only and never reads the database payload.

`~/engram-memories` is not an Engram data directory or a synchronization repository. On machines where it exists, it is a separate project-registry and adapter toolkit. Do not point `data_dir` or legacy `store_path` at it.

The supported replication profile is `local`. A pre-existing non-local value is preserved as evidence, reported as unsafe/review-required, and never normalized to `local` by setup. This onboarding flow does not configure Git-based memory synchronization, cloud synchronization, provider-data imports, provider-data migrations, or upgrades.

Invalid user-home references such as an unknown `~user/path` are rejected by the setup CLI without a traceback. The metadata-only access report preserves the unresolved declaration, skips filesystem inspection for it, and emits a review-required finding instead of silently falling back to another directory.

## Inspect an Existing Installation

Run the read-only check first:

```bash
naos memory check
```

The check inspects only:

- known Engram executable names on `PATH`
- the effective data-directory and derived-database path metadata
- workspace MCP metadata locations registered in the shared MCP registry
- explicit user-scope MCP metadata locations registered in that same registry
- Engram server declarations, project declarations, and secret-like environment-key names
- optional output from `engram-memory resolve --cwd` when that command is already installed

The check does not install or configure anything, call an MCP server, read memory payloads, persist resolver output, or prove usable provider access. An absent `engram-memory` resolver is non-blocking; a detected resolver conflict fails closed.

The provider-access report records the exact registry descriptor IDs under `mcp_scan_scope`. User-scope rows are sanitized metadata: server names, fixed project declarations, environment-key names, and secret-like key names may be reported, but command arguments and environment values are not. User-scoped fixed projects are contamination risks only and never select the current workspace identity. An unrelated MCP file remains inventory metadata and does not make Engram MCP configured or produce `declared_only`; only an actual Engram server declaration does.

If provider signals already exist, record `use-existing` and then verify the active client's MCP tools and `mem_current_project`. Do not create a second store.

## Record a Setup Disposition

Every setup command is a dry run unless `--write` is added. Review the rendered YAML before writing.

### Configure a local provider externally

```bash
naos memory setup --disposition configure-local
naos memory setup --disposition configure-local --data-dir ~/.engram --write
```

This records `pending_external_verification`, `enabled: false`, and `scope: user-centralized`. It does not install or launch Engram.

### Use an existing provider

```bash
naos memory setup --disposition use-existing
naos memory setup --disposition use-existing --write
```

This records `pending_existing_verification`, `enabled: false`, and `scope: user-centralized`. It does not modify the existing provider or client configuration.

### Defer optional memory

```bash
naos memory setup --disposition defer --write
```

This records `deferred`, `enabled: false`, and `scope: none`.

### Decline optional memory

```bash
naos memory setup --disposition decline --write
```

This records `disabled`, `enabled: false`, and `scope: none`.

Legacy `--mode centralized`, `--mode local`, `--mode deferred`, and `--mode disabled` values remain accepted with an explicit compatibility warning. They map to the dispositions above; no legacy mode performs provider configuration.

## Legacy `store_path` Migration

`store_path` is an obsolete and ambiguous field. Runtime checks recognize it only to warn and ignore it; it never selects the data directory.

A reviewed setup dry run previews migration of an existing root `memory.store_path`. With `--write`, setup removes that active field and preserves its prior value only as metadata:

```yaml
memory:
  data_dir: ~/.engram
  migration:
    legacy_store_path: ~/engram-memories
    status: legacy_store_path_removed_from_active_config
```

Other existing memory fields, top-level fields, `mcp_project`, `mcp_namespace`, and notes are preserved. The unused `strict_required` and `last_check` fields are removed by a reviewed setup write: readiness strictness uses the explicit `--strict-memory` command option, and read-only checks never mutate configuration or invent a timestamp. Setup refuses unsafe destinations, invalid YAML, conflicting migration metadata, and `--store-path` combined with `--write`. Use `--data-dir` for the directory containing `engram.db`.

## Pending to Configured Evidence Boundary

`naos memory setup` only records `pending_external_verification` or `pending_existing_verification`; it never changes either state to `configured` and never sets `enabled: true`.

A maintainer may manually assert `state: configured` and `enabled: true` only after all of the following external evidence has been reviewed:

1. The provider was installed or selected by an authorized human-controlled process outside NAOS setup.
2. The active client actually exposes the intended Engram MCP server and required tools; config-file presence alone is insufficient.
3. `mem_current_project` in that active client returns the expected canonical project, consistent with the approved registry/resolver and any workspace declaration.
4. The effective `ENGRAM_DATA_DIR`/`data_dir` and derived `engram.db` location are confirmed outside the repository, with `replication_profile: local`.
5. The authorization matrix permits the intended read/write surface and any durable write has its required human-review boundary.

Even after that manual assertion, the config-only `naos memory-access` report remains `configured_unverified`: it makes no live provider/MCP call and cannot certify the external evidence. No automatic evidence receipt or verified/configured transition is claimed in this version.

## Workspace Project Identity

One per-user data directory can serve many repositories, but each active client must resolve the current workspace to the correct registered project. Do not derive identity from a folder name and do not configure one fixed user-global `ENGRAM_PROJECT` for every workspace.

The preferred model is dynamic resolution through the registered adapter. When available, the metadata-only check runs:

```bash
engram-memory resolve --cwd /absolute/path/to/current/workspace
```

The result is used only for the current check and is not persisted automatically. A fixed workspace declaration is optional; a dynamic adapter with no fixed `ENGRAM_PROJECT` is valid when the resolver and the active client's `mem_current_project` independently return the expected canonical project.

If a client requires an explicit workspace declaration, use the exact registered project ID or alias in that workspace's secret-free MCP server definition. Do not copy a project ID into user-global configuration. `naos memory check` compares workspace declarations through the shared MCP registry and reports conflicting or user-global fixed declarations.

You may record an already reviewed project assertion without inferring it:

```bash
naos memory setup --disposition use-existing --mcp-project registered-project-id --write
```

This records an assertion, not proof. Before recall or write, confirm the active client exposes the intended Engram tools and call `mem_current_project`. Stop on an unknown, ambiguous, or unexpected project.

## MCP Namespace

Clients may expose Engram under different server or tool namespaces. Do not assume `engram/*`. After inspecting declarations and verifying the active client, record an exact non-sensitive namespace if required:

```bash
naos memory setup --disposition use-existing --mcp-namespace engram --write
```

MCP file presence and configured provider metadata do not prove usable access. Run:

```bash
naos memory-readiness --profile standard
naos memory-access --profile standard
naos memory-use-policy --profile standard
```

The readiness report evaluates declared provider posture, authorization, fallback recovery, and context-pack readiness. The access report inventories safe provider and MCP metadata without reading memory payloads. The memory-use-policy report joins current schema-valid readiness and access reports with review/trust-ladder requirements. A policy-valid supporting-context or instruction-grade item remains `policy_item_valid_but_access_unverified` until those prerequisites support the required declared posture; config-only reports still do not prove live provider or MCP access. The report does not write memory or execute recall traces.

## Privacy and Authority

- Keep the live database outside every project repository.
- Never store credentials, API keys, tokens, passwords, certificates, private keys, connection strings, PII, customer or tenant data, regulated data, hidden approvals, or governance-override instructions.
- Do not write durable memory unless the authorization matrix permits that surface, `naos memory-access` evaluates the required declared posture, separate active-client verification confirms access and project identity, and the human-review boundary is satisfied.
- Treat unreviewed memory as advisory recall only.
- Memory never overrides current instructions, source, tests, schemas, policy, deterministic reports, or human decisions.

## Degraded Recovery

Pending, deferred, disabled, unavailable, or unverified memory uses file-first recovery: task cards, compact summaries, Git state, repository governance files, and deterministic NAOS reports. Lack of memory is not an automatic failure unless the selected project policy explicitly makes it required.

## What NAOS Does and Does Not Do

NAOS does:

- record an explicit disposition in `configs/naos_memory.yaml`
- derive `engram.db` from the effective external data directory
- inspect supported MCP configuration as declaration-only metadata
- optionally use an already installed resolver read-only
- preserve unknown configuration fields during safe writes
- support degraded recovery

NAOS does not:

- silently install, launch, upgrade, or configure Engram
- silently mutate user-level editor or MCP settings
- read Engram database payloads during onboarding checks
- call memory or MCP tools during setup
- configure Git or cloud synchronization
- infer a project from the local directory name
- set a fixed global project
- treat configuration presence as proof of access
- treat memory as evidence, approval, a compliance conclusion, or an authority override
