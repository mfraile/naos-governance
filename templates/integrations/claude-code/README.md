# NAOS Optional Claude Code Hook Bundle

This directory contains optional Claude Code hook templates that run local NAOS
reviews at session and tool events. The bundle is advisory. It does not approve
work or enforce a gate. NAOS remains usable through its CLI without these hooks.

## Installation and activation

Review the module before adding it to a project:

```bash
naos add setup-module claude_code_hooks --profile standard --dry-run
naos add setup-module claude_code_hooks --profile standard --confirm
```

The setup action copies this directory to `naos/integrations/claude-code/`. It
does not change `.claude/settings.json`, activate a hook, install Python or NAOS,
or add secrets. Review the copied files and merge **only the `hooks` object**
from the chosen template into Claude Code settings. The other top-level fields
are NAOS template metadata, not Claude Code settings. Use the assured template
only if that profile is intended. Review path and executable names for the
host: `command: "python"` must resolve to a real Python executable on `PATH`,
and the selected Python interpreter must have the `naos_governance` package
installed in its environment (a project-local `.venv` is supported). Use an
absolute Python executable path in the settings you activate if the host uses
another name. The selected interpreter and its installed environment must be
trusted; this bundle does not authenticate or repair that environment.

Keep the templates' leading `-I -B` arguments: they isolate dispatcher startup
as well as its CLI child. The POSIX compatibility wrappers use the same flags.
When migrating older registrations, replace their reviewed NAOS argument list
with the new template's list; updating the dispatcher alone does not isolate
an older parent invocation.

The command handlers use Claude Code's documented exec form (`command` plus
`args`) and `${CLAUDE_PROJECT_DIR}` placeholder. This keeps paths containing
spaces and task or team values as individual arguments. The settings are a
manual merge example; native Claude registration, native Windows execution,
and version-specific host behavior still require an adopter test.

## Event cadence

| Claude event | NAOS review |
| --- | --- |
| `SessionStart` | `naos session-id`, then `naos operator-attribution` |
| `PreToolUse` for `Edit`, `Write`, `MultiEdit` | `naos task-claims --action list` |
| `PreToolUse` for `Bash` or `PowerShell` | `naos gate-status` |
| `PostToolUse` for `Edit`, `Write`, `MultiEdit` | `naos self-check` |
| `PreCompact` | `naos session-checkpoint` when a task id is set |
| `SessionEnd` | `naos session-end` when a task id is set |

`NAOS_PROFILE` defaults to `standard`; the assured settings template fixes it
to `assured`. The gate review takes `NAOS_TEAM_ID` or `TEAM_ID` when set, and uses
`NAOS_ROOT` for its report location (default `naos`). Set
`NAOS_TASK_ID` or `TASK` for checkpoint and end reviews. The Python
dispatcher starts the selected interpreter with `-I -B` and a fixed bootstrap,
validates the package origin against that interpreter's installed
`naos-governance` distribution before importing it, and runs the CLI in the
same child. Project-local packages and inherited `PYTHONPATH` cannot select
the CLI. Regular environment installs, including project-local `.venv`
installs, are supported; editable installs must resolve to their installed
source outside the adopter tree. User-site-only or `PYTHONPATH`-only imports
are unavailable in isolated mode: install NAOS in the selected environment.
The project remains the working directory, and each value is one literal CLI
argument with no shell interpolation.
The old `.sh` names remain as thin manual compatibility wrappers for POSIX
hosts. Active settings call the Python dispatcher directly.

### Migrate an existing Stop registration

Remove the old NAOS `Stop` handler from active settings before merging the
`SessionEnd` entry from the reviewed template. Preserve unrelated adopter hooks
and permission rules. Adding `SessionEnd` without reviewing the old entry is not
an automatic migration. `Stop` is a per-response event, while `SessionEnd` is
session termination. For compatibility, the dispatcher still accepts the old
`stop` event (including `stop.sh`), but only prints an advisory reminder and
runs no NAOS command, even when a task id is set.

The `SessionEnd` review generates the existing end checklist/report, updates its
session context/report references, and records the lifecycle audit event. It
does not pass `--close-session` or automatically close NAOS session state. If no
task id is set, it warns and skips the review; run the manual CLI review when
needed. Manual governance duties remain in force whether hooks run or not.

The tool-event handlers remain optional, explicitly selected reviews. Selecting
the `Bash`/`PowerShell` handler writes a gate-status report when the configured
NAOS root exists; selecting the write handler runs live self-check inspection
after each matching tool event. The default self-check does not persist its
full report or refresh child reports; use the manual CLI with `--output` or
`--refresh` when that publication is intended. This can add repeated work.
Review that cadence and cost before merging these handlers, and run the
same checks manually if you do not select them. No performance measurement or
mandatory blocking gate is claimed.

The dispatcher ignores hook stdin. It discards NAOS command output, prints a
short status warning to stderr, and returns success even when a command is
missing, reports a finding, or reaches its time budget. Review local NAOS
reports and run the CLI manually for details. Hook output does not grant
permission, inject context, write memory, certify compliance, deploy, push, or
release. Other events retain a 15-second child budget and a 20-second outer
hook timeout, or 35 seconds for the two-command session-start handler.
The `SessionEnd` settings timeout remains explicitly 20 seconds.

Post-write self-check has a separate 120-second child budget and a matching
125-second `PostToolUse` timeout in both templates. Configure the dispatcher
with `--post-write-timeout-seconds <seconds>` (integer from 1 to 600). When
merging a different value into Claude settings, also set that handler's outer
`timeout` to at least the child budget plus 5 seconds; for example, use 180
and 185 respectively. Manual shell-wrapper launches can pass the same option
directly to `dispatch.py`. No global timeout environment setting is changed.
Larger budgets permit longer per-edit waits; they do not make a full check
faster or guarantee completion on every project or host.

## Disable or remove

Remove the merged references from Claude Code settings. The copied directory
can then be left in place or deleted. The bundle is not official Claude or
Anthropic support.

Vendor format reference: https://code.claude.com/docs/en/hooks
