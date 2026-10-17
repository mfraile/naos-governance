# AI metadata scope

Kit templates and unlisted `.github` agent, skill and instruction files retain
the strict NAOS authoring contract. Two separate skill formats are discovered
automatically, even when kit templates are present:

| Exact project path | Local metadata checks | Catalogue selection label |
| --- | --- | --- |
| `.agents/skills/<directory>/SKILL.md` | Required portable name/directory identity and description; no NAOS parameters or invocation heading required | `portable_skill` |
| `.claude/skills/<directory>/SKILL.md` | Readable optional frontmatter; present YAML must be a mapping | `claude_skill` |

Only these immediate skill-directory layouts are recognized. Discovery refuses
symlinks/reparse points in the selected root, directory or file and conflicting
NFKC/case-folded path aliases. The fixed `.agents`, `.claude`, `skills` and
`SKILL.md` components must match actual directory-entry spelling: case aliases
on a case-insensitive filesystem are refused; differently cased distinct paths
on a case-sensitive filesystem are outside this default layout. Adopter directory
identity still follows the Unicode/NFKC rules below. It grants no invocation or
agent authority.
The physical artifact inventory also includes `.agents/skills` in both its
built-in and shipped default patterns; an adopter's explicit pattern list remains
authoritative and is not merged with those defaults.

To select unrelated adopter host files for declaration-only metadata handling,
create `naos/ai_metadata_scope.yaml` in the project root:

```yaml
schema_version: 1
host_paths:
  - .github/agents/team-review.agent.md
  - .github/skills/team-process/SKILL.md
  - .github/instructions/team/testing.instructions.md
  - .agents/skills/team-process/SKILL.md
  - .claude/skills/host-process/SKILL.md
```

Each entry must be an existing regular file at an exact literal relative path.
Directories, globs, traversal, Windows anchors or alternate data streams, control
characters, trailing dot/space path components, symlinks/reparse points, missing files, duplicate
paths or mapping keys, unsupported paths, and malformed configuration fail
visibly. A configuration cannot exempt files in `templates/`. Correct the
configuration to recover; removing it restores strict `.github` defaults.
Listing a portable `.agents` skill never bypasses its identity floor; a listed
Claude skill retains its Claude parse-only handling. This
selects metadata handling only: it is adopter-declared scope, not proof of
ownership, custody, provenance, host compatibility, or permission to use tools.

The emitter, standalone validators, and autoresearch read the same file, so
ordinary Makefile calls need no additional flags. Direct low-level single-file
NAOS validator APIs remain strict. Bulk validator APIs take `root=` to consume
the project's declaration. Unlisted `.github` files remain strictly checked.

Explicitly declared `.github` host files and Claude skills permit absent
frontmatter and optional host fields. Portable `.agents` skills require `name`
and `description`: name is stripped then NFKC-normalized, at most 64 characters,
lowercase, alphanumeric Unicode or single internal hyphens, and must equal the
NFKC-normalized parent directory. Description is nonempty after stripping and
at most 1024 raw characters. This identity floor follows the retained reviewed
Agent Skills reference; it is not that reference validator's full field/type
validation and does not certify a loader. NAOS authoring retains its distinct
ASCII naming contract, optional namespaced JSON parameter declarations and invocation guidance.

Other optional metadata does not gain execution semantics. Claude dynamic fields
are recorded as declarations without asserting enforcement or portable validity. Present
frontmatter must still be readable UTF-8, valid YAML, and a mapping. These checks
do not certify any vendor profile. The catalogue places these files in a
separate `host_declarations` section with `status: declared_host`; they have no
NAOS capability ID and cannot satisfy agent sponsor requirements. The component
inventory preserves a separate section, sanitizes optional declarations, binds
source and scope-file digests, and excludes these rows from NAOS component
counts and component-policy evaluation. Selecting a previously governed agent
can consequently remove it from the set eligible for a sponsor record; the
existing missing/unknown-agent checks still apply.

Optional identity, model/tool, license/compatibility, metadata and host invocation
fields are recorded
when portable as JSON. Unsupported values are explicitly listed in
`nonportable_fields_omitted`; unrelated host metadata does not acquire NAOS
requirements. No NAOS description or model/tool authority is fabricated.
Without a scope declaration or either new host root, catalogue output remains
byte-compatible. Automatically discovered host records use their format label
instead of claiming an explicit adopter scope. These records remain separate
from governed capabilities, component-policy evaluation and sponsor identity.

Host formats differ. Current primary documentation inspected on 2026-10-01:
[VS Code agents](https://code.visualstudio.com/docs/agent-customization/custom-agents)
permit an optional header and optional model/tools, including model arrays;
[VS Code instructions](https://code.visualstudio.com/docs/agent-customization/custom-instructions)
permit omitted `applyTo` for manual attachment;
[GitHub cloud agents](https://docs.github.com/en/copilot/reference/custom-agents-configuration)
require a description and permit optional model/tools. Recording a declaration
does not establish discovery, execution, or validity under any of these hosts.
