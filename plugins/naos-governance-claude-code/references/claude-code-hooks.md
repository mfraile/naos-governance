# Claude Code Hook Relationship

Existing Claude Code hook templates remain separate and review-first under:

```text
templates/integrations/claude-code/
```

The Claude Code plugin v1 may reference those templates, but it does not package
or activate hooks.

To copy hook templates into an adopter project:

```bash
naos add setup-module claude_code_hooks --profile standard --dry-run
naos add setup-module claude_code_hooks --profile standard --confirm
```

After copying, manually review the generated `naos/integrations/claude-code/`
files before merging any settings into `.claude/settings.json`.

Hook output is review guidance only. It is not approval, certification, proof of
compliance, memory write-back, provider/API access, deployment, or release
authorization.

Copying the module requires explicit confirmation and still activates no hook.
Merge only the reviewed `hooks` object from the chosen settings template; other
top-level fields are NAOS metadata. The active example uses the Python dispatcher
and literal arguments; old shell names are manual POSIX compatibility wrappers.
Review executable paths for the host and separately test native registration.
Hook handlers discard command output, warn on failure or timeout, and return
success. Inspect NAOS reports and run the CLI for real findings; hook success is
neither gate readiness nor authorization. See the canonical
`templates/integrations/claude-code/README.md` before activation.
