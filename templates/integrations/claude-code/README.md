# NAOS Optional Claude Code Hook Bundle

This directory contains optional Claude Code hook templates for teams that want
Claude Code sessions to surface NAOS checks at useful moments.

The bundle is a convenience layer only. NAOS core remains file-first,
CLI-first, Makefile-first, schema/report-first, and tool-neutral. These
templates are not official Claude or Anthropic support and are not endorsed by
Anthropic.

## Installation

Recommended review-first path:

```bash
naos add setup-module claude_code_hooks --profile standard --dry-run
naos add setup-module claude_code_hooks --profile standard
```

The setup-module action copies templates into:

```text
naos/integrations/claude-code/
```

It does not overwrite `.claude/settings.json`, activate hooks, add secrets, or
install dependencies. To activate, review the copied templates and manually
merge the relevant settings into your own Claude Code configuration.

## Files

- `settings.template.json` - conservative hook references.
- `settings.assured.template.json` - stricter review cadence for teams using the
  assured profile.
- `hooks/pre-session.sh` - creates/reuses session identity and operator
  attribution when local NAOS Make targets are present.
- `hooks/pre-tool-edit.sh` - reminds the operator to check task claims before
  edits.
- `hooks/pre-tool-bash.sh` - surfaces gate posture before shell-heavy actions.
- `hooks/post-tool-write.sh` - runs a lightweight self-check after writes.
- `hooks/pre-compact.sh` - suggests a session checkpoint when `NAOS_TASK_ID` is
  available.
- `hooks/stop.sh` - suggests session-end review when `NAOS_TASK_ID` is
  available.

Each script fails safe: if `make`, `Makefile.naos`, or a target is unavailable,
it prints a warning and exits successfully.

## What Hooks May Run

The templates may call local NAOS session and governance commands such as:

```bash
make -f Makefile.naos naos-session-id
make -f Makefile.naos naos-operator-attribution
make -f Makefile.naos naos-task-claims
make -f Makefile.naos naos-agentic-workflow-review
make -f Makefile.naos naos-pre-implementation-alignment-review
make -f Makefile.naos naos-gate-status
make -f Makefile.naos naos-self-check
make -f Makefile.naos naos-session-checkpoint TASK=<task>
make -f Makefile.naos naos-session-end TASK=<task>
```

These commands produce or review local NAOS files and reports. They do not
approve work.

## Governed Agentic Coding Use

Hooks can support push-context checks by reminding operators to run
`naos-agentic-workflow-review` and `naos-pre-implementation-alignment-review`
before or after non-trivial implementation. Those commands validate declared
workflow and alignment artifacts; they do not silently inject context, write
memory, approve work, prove requirements completeness, or replace human review.

## Disable Or Remove

Remove the hook references from your Claude Code settings and leave or delete
the copied `naos/integrations/claude-code/` directory. The templates do not
modify NAOS core behavior.

## Non-Claims

The hook bundle does not provide:

- automatic hook activation;
- silent context injection;
- memory write-back;
- provider/model/API calls;
- secrets or API key handling;
- approval, certification, or proof of compliance;
- deployment, auto-push, auto-release, or publication;
- official Claude or Anthropic support;
- identity proof, authentication, authorization, or access control.
