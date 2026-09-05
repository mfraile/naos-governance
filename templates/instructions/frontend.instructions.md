---
applyTo: "frontend/**"
---

# Frontend Guidelines

> Consult `.github/project-context.md` for project-specific conventions (API types, component patterns).

## Tech Stack

- `[ADAPT: your frontend framework, e.g. Next.js App Router + React + TypeScript]`
- `[ADAPT: your UI component library, e.g. Radix UI primitives]`
- API client: `[ADAPT: your API client file, e.g. frontend/lib/api.ts]`

## Conventions

- Use TypeScript strict mode — no `any` types without justification.
- API types defined in `[ADAPT: your API types file]` — always import from there.
- Components live in `[ADAPT: your UI components directory]`.
- Pages use `[ADAPT: your page router convention, e.g. App Router in frontend/app/]`.

## State & Data Fetching

- Use React Server Components where possible.
- Client components marked with `"use client"` directive.
- API calls go through the typed client.

## Styling

- Follow existing patterns in the codebase.
- Use design tokens / CSS variables for theming consistency.

## Security

- Never expose API keys or secrets in client-side code.
- Sanitize user inputs before rendering (XSS prevention).
- CSRF tokens required for state-changing API calls.
- No PII in URL parameters, localStorage, or console logs.
- See `SECURITY.md` for full security requirements.

## Testing

- Run `npm run lint` before committing.
- Run `npm run build` to verify production builds.

## Before Coding

- Check existing components in `[ADAPT: your UI components directory]` before creating new ones.
- Check `[ADAPT: your API client file]` for existing API call functions.
- Consult project-context.md for backend API contracts and types.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-frontend/SKILL.md` — invoke via Copilot chat when you need patterns.
