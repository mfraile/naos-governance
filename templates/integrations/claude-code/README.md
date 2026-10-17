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
installed. Use an absolute Python executable path in the settings you activate
if the host uses another name.

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
dispatcher runs `sys.executable -m naos_governance` and passes each value as
one literal CLI argument, with no shell interpolation.
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
NAOS root exists; selecting the write handler runs self-check and writes its
report after each matching tool event. This can add repeated work and report
writes. Review that cadence and cost before merging these handlers, and run the
same checks manually if you do not select them. No performance measurement or
mandatory blocking gate is claimed.

The dispatcher ignores hook stdin. It discards NAOS command output, prints a
short status warning to stderr, and returns success even when a command is
missing, reports a finding, or times out after 15 seconds. Review local NAOS
reports and run the CLI manually for details. Hook output does not grant
permission, inject context, write memory, certify compliance, deploy, push, or
release. Claude Code's own hook timeout is set to 20 seconds per handler, or
35 seconds for the two-command session-start handler. The `SessionEnd`
settings timeout is explicitly 20 seconds, raising the shared termination-hook
budget for this handler; its child command remains bounded to 15 seconds. No
global timeout environment setting is changed.

## Disable or remove

Remove the merged references from Claude Code settings. The copied directory
can then be left in place or deleted. The bundle is not official Claude or
Anthropic support.

Vendor format reference: https://code.claude.com/docs/en/hooks
