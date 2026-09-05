# Frontmatter Conformance

NAOS validates agent, skill, and instruction metadata as part of static conformance for standard and assured projects.

These checks are deterministic. They do not call an LLM, grade behavior, or emit capability cards. They make the generated governance surface auditable and prepare the metadata contract used by later capability-emission work.

## Required Fields

| File type | Required metadata | Invocation guidance |
| --- | --- | --- |
| `.agent.md` | `model`, `tools` | Defined by the agent body and `AGENTS.md` handoff chain. |
| `SKILL.md` | `parameters` | Body heading such as `## When to Use` or `## When to Invoke...`. |
| `*.instructions.md` | `applyTo` | The `applyTo` glob controls when the instruction applies. |

ADAPT placeholders are allowed in generated templates when the required field shape is present. For example, `model: "[ADAPT: e.g. claude-sonnet-4-5]"` is valid because the field is declared as a YAML string.

## Agent Example

```yaml
---
model: "[ADAPT: e.g. claude-sonnet-4-5 | gpt-4o]"
description: "Implementation agent — code generation, file editing, test writing"
tools:
  - read/readFile
  - edit/editFiles
  - execute/runInTerminal
---
```

## Skill Example

```yaml
---
name: "function-discovery"
description: "Search the function index for existing implementations before writing new code."
parameters:
  - name: query
    description: "Natural language description of the function you need"
    required: false
    default: ""
---
```

The skill body must also explain when to invoke it:

```markdown
## When to Use

Use this skill before creating a new function or class.
```

Skills with no runtime arguments should declare `parameters: []` rather than omitting the field.

## Instruction Example

```yaml
---
applyTo: "**/*.py"
---
```

## Running The Checks

From a generated standard or assured project:

```bash
make -f Makefile.naos validate-all
make -f Makefile.naos naos-conformance
```

The conformance report includes a `frontmatter_checks` section with pass counts and per-check results.

## Fixing Failures

If a frontmatter check fails, edit the reported file and add the missing field or heading. Re-run the same command until the check passes.

Common fixes:

- Quote ADAPT model placeholders so they parse as YAML strings.
- Use a YAML list for `tools`.
- Add `parameters: []` to skills that do not accept parameters.
- Add a `## When to Use` or `## When to Invoke...` section to skill bodies.
- Add `applyTo` to instruction files.
