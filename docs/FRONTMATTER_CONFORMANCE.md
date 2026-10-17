# Frontmatter Conformance

NAOS validates agent, skill, and instruction metadata as part of static conformance for standard and assured projects.

These checks are deterministic. They do not call an LLM, grade behavior, or emit capability cards. They make the generated governance surface auditable and prepare the metadata contract used by later capability-emission work.

The requirements below are the **NAOS metadata contract**, not a universal
AI-host format. Unrelated adopter agents, skills and instructions may use
optional host metadata. Declare their exact paths in `naos/ai_metadata_scope.yaml`
as described in [AI metadata scope](AI_METADATA_SCOPE.md). The emitter,
validators and autoresearch share that declaration; undeclared files retain
strict checks and kit templates cannot be exempted. Declared host files are
listed separately and do not become NAOS capabilities or satisfy agent sponsor
requirements. These checks do not establish vendor compatibility or execution.

The default skill CLI also discovers immediate `.agents/skills/*/SKILL.md` and
`.claude/skills/*/SKILL.md` files. The former receives the separate Unicode-aware
portable identity floor; the latter receives optional host frontmatter parsing.
Neither receives NAOS-only `parameters` or invocation-heading requirements.
These host paths become separate catalogue declarations, never NAOS capabilities
or subagents. See the exact layouts, scope precedence, topology refusals and
limits in [AI metadata scope](AI_METADATA_SCOPE.md). Direct single-file NAOS
validator APIs remain strict; bulk validation with `root=` selects the format.

## Required Fields

| File type | Required metadata | Invocation guidance |
| --- | --- | --- |
| `.agent.md` | `description`, `model`, `tools` | Defined by the agent body and `AGENTS.md` handoff chain. |
| `SKILL.md` | `name`, `description`; optional `metadata.naos-parameters` | Body heading such as `## When to Use` or `## When to Invoke...`. |
| `*.instructions.md` | `applyTo` | The `applyTo` glob controls when the instruction applies. |

ADAPT model seeds retain structural shape acceptance but produce the explicit `model-placeholder-unresolved` warning in the validator and conformance report. A passing structural check does not establish an invocable model. Resolve the seed and verify model availability in the selected host before invocation. NAOS deliberately requires model/tools to keep model and tool authority explicit; vendor optionality does not loosen this contract. UTF-8 with or without a leading BOM is accepted.

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
metadata:
  naos-parameters: '[{"name":"query","description":"Natural language description of the function you need","required":false,"default":""}]'
---
```

The skill body must also explain when to invoke it:

```markdown
## When to Use

Use this skill before creating a new function or class.
```

NAOS-authored skills require a `name` matching their parent directory exactly:
1–64 lowercase ASCII letters or digits, with single internal hyphens. Leading,
trailing and consecutive hyphens are rejected. `description` must be a non-empty
string of at most 1024 characters; length counts characters, including whitespace.
These identity checks follow the project’s portable naming convention and the
[Agent Skills identity fields](https://agentskills.io/specification). They do not
establish complete specification conformance, host discovery or invocation.

NAOS-authored skills use only the standard top-level fields: `name`,
`description`, `license`, `compatibility`, `metadata`, and `allowed-tools`.
`metadata` maps string keys to string values. Optional `metadata.naos-parameters`
is a JSON-encoded list of parameter mappings. Each entry requires a non-empty
`name` and `description`; names are unique, `required` is boolean when present,
and defaults and extension fields retain their finite JSON values, including
lists and objects. Omission means no declared inputs; `naos-parameters: '[]'`
records that explicitly. Malformed declarations fail rather than becoming empty.
Optional `metadata.naos-extends` is a non-empty manual base reference. These
namespaced declarations do not grant tools, inheritance, automatic dispatch or
host-enforced arguments. Legacy top-level `parameters` and `extends` must be
migrated, not copied alongside the namespaced values.

This follows the [Agent Skills specification](https://agentskills.io/specification)
frontmatter fields and string-valued metadata, checked against its
[reference validator](https://github.com/agentskills/agentskills/blob/main/skills-ref/src/skills_ref/validator.py)
on 2026-10-16. Reference code inspection is not an executed external-validator
pass, upload acceptance, host discovery or successful invocation.

Generated `.agents/skills/naos-portable-*` and `naos-workflow-*` adapters use
portable `name` and `description` frontmatter. NAOS authoring inputs are
projected into a manual body table, with any manual base reference; they are not
copied into adapter frontmatter. Codex invocation policy is in each adapter's
`agents/openai.yaml`; Claude's manual invocation policy is in its command wrapper.
These host-specific controls do not become fields in the portable specification.

The Claude plugin's `naos-forensic-audit` and `naos-systemic-wiring` skills describe
their input defaults and base-skill composition in their bodies. Claude does not
enforce NAOS `parameters` types/defaults or an `extends` relationship: its current
[frontmatter contract](https://code.claude.com/docs/en/skills#frontmatter-reference)
ignores unrecognized fields. Check inputs and availability of the base skill
explicitly. Registration and successful execution require separate host evidence.

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

For files governed by the NAOS metadata contract, edit the reported file and add the missing field or heading. For unrelated host files, review the explicit metadata scope instead of adding NAOS-only fields to satisfy a different contract. Re-run the same command until the check passes.

Common fixes:

- Resolve ADAPT model seeds with a reviewed host selection; string shape does not validate availability.
- Supply a non-empty agent description.
- Use a YAML list for `tools`.
- Match each skill `name` to its directory and supply its bounded description.
- Migrate top-level `parameters` to JSON text in `metadata.naos-parameters`; use
  `naos-parameters: '[]'` for an explicit empty declaration.
- Add a `## When to Use` or `## When to Invoke...` section to skill bodies.
- Add `applyTo` to instruction files.
