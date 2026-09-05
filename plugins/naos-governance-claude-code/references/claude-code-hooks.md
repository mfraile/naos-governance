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
naos add setup-module claude_code_hooks --profile standard
```

After copying, manually review the generated `naos/integrations/claude-code/`
files before merging any settings into `.claude/settings.json`.

Hook output is review guidance only. It is not approval, certification, proof of
compliance, memory write-back, provider/API access, deployment, or release
authorization.
