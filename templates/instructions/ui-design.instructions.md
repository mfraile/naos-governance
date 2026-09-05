---
applyTo: "frontend/**"
---

# UI/UX Design Guidelines

> Consult `.github/project-context.md` for full tech stack context.

## Tech Stack

- `[ADAPT: your frontend framework and version, e.g. Next.js 16 App Router + React 19 + TypeScript]`
- **Components**: `[ADAPT: your UI component library, e.g. Radix UI primitives in frontend/components/ui/]`
- **API client**: `[ADAPT: your API types file, e.g. frontend/lib/api.ts]` — the single source of TypeScript types
- **State**: React hooks — no Redux/Zustand unless already present

## Brand Standards

- **Primary**: `[ADAPT: your primary brand color]`
- **Accent**: `[ADAPT: your accent brand color]`
- **Typography**: `[ADAPT: your font choices — headings, body, monospace]`
- **Spacing**: 8px base unit — use multiples (8, 16, 24, 32, 48)
- **Border radius**: 8px buttons, 12px cards
- **Assets**: `[ADAPT: your logo and icon asset directories]`
- Never use external brand assets or introduce new icon libraries

## Accessibility (WCAG 2.1 AA — Mandatory)

- Colour contrast ≥ 4.5:1 for text; ≥ 3:1 for UI components
- All interactive elements keyboard-navigable (tab order, focus ring `2px outline`)
- ARIA labels on interactive elements without visible text
- Semantic HTML: `<button>`, `<nav>`, `<main>`, `<section>` — no `<div>` for interactive roles
- Alt text for all images and icon-only buttons

## Privacy (Customer-Facing Screens)

- Zero-knowledge pattern: no PII in URL params, localStorage, or console logs
- API calls use hashed IDs only — never send raw PII to the server
- See your governance rules for full PII governance requirements

## Design Workflow

1. Identify the design stage: `concept_exploration`, `wireframe_or_prototype`, `implementation_ready_design`, or `post_implementation_review`
2. Design with your approved workflow or generator; if using v0.dev or another generator, keep prompt/output provenance as local evidence
3. Check `[ADAPT: your UI components directory]` for existing primitives before creating new ones
4. Document in `docs/ui/screens/[name]-spec.md` before implementing
5. If optional `naos/design_traceability.yaml` is enabled, keep stable `object_id` entries aligned with screen specs, implementation paths, changed-file evidence, test/check evidence, and review disposition
6. If optional `naos/ui_experience_quality.yaml` is enabled, keep screen entries aligned with design stage, FR/NFR/task/AC refs, data/API/state refs, token refs, screenshot/state refs, accessibility/performance refs, provenance, and human-review disposition
7. Validate: branding ✓, accessibility ✓, privacy ✓ before PR

Design traceability is local declaration review only. It does not call Figma,
MCP, html.to.design, providers, models, memory tools, browsers, APIs, or
networks; it does not prove design quality, accessibility, privacy, brand
posture, approval, certification, or compliance.

UI experience quality review is local declaration review only. It does not call
Figma, MCP, Penpot, v0, Lovable, Bolt, providers, models, memory tools,
browsers, APIs, or networks; it does not generate screenshots, mutate design
tools, prove design quality, approve UI, certify accessibility, prove brand or
privacy posture, or prove compliance.

## Screen Inventory

- Active screen planning: use `[ADAPT: your UI design prompt slash command]`
- `[ADAPT: your screen catalog or v0 prompt catalog path, e.g. naos/active/T-XXX_ui_ux_catalog.md]`

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-ui/SKILL.md` — invoke via Copilot chat when you need patterns.
