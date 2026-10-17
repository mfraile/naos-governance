# Project context facts and archetype guidance

Generated `.github/project-context.md` separates NAOS configuration choices
from proposed architecture. Selecting an archetype chooses a scaffolder preset;
it does not verify that the adopter uses its database, authentication, queue,
infrastructure or module layout. This also applies to an explicit preset choice.

Repository detection can suggest a candidate such as `nextjs-supabase` from a
Next.js configuration file. Automatic selection keeps its existing behavior,
but the generated preset sections, fields and prose carry proposal or ADAPT
markers. Existing ADAPT blocks stay intact. Markdown lists, blockquotes and
table headers retain their structure, and the preset heading hierarchy appears
under one proposed guidance section. Code
blocks are proposed examples with an adjacent ADAPT instruction. Confirm or
replace this guidance using the project's specifications and actual source
before treating it as project facts. Profile and archetype values are labelled
as NAOS configuration choices, not architecture evidence.

Custom context templates are populated at their installed `.github` location.
Omitted, empty or greenfield signals use explicit ADAPT fallbacks. Unrecognized
`$signal_*` placeholders also receive ADAPT fallbacks; unrelated shell variables
are retained. Existing ADAPT instructions remain for the adopter to complete.

The same rendering applies to explicit and inferred presets, so regeneration
needs no hidden confirmation state or new provenance fields. Detection,
noninteractive selection, activation approval and managed replay inputs are
unchanged. This rendering does not execute or certify an application's stack.
