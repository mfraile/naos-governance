# Project Context — Next.js + Supabase
# NAOS Portable Governance Kit
# ─────────────────────────────────────────────────────────────────────────────
# Pre-populated project-context.md template for Next.js + Supabase.
# Replace all [ADAPT: ...] blocks with your project's actual content.
# ─────────────────────────────────────────────────────────────────────────────

## Project Identity

| Field | Value |
|-------|-------|
| **Name** | [ADAPT: Your project name] |
| **Type** | Next.js full-stack application |
| **Primary Stack** | TypeScript / Next.js / Supabase (PostgreSQL + Auth + Storage) |
| **Status** | [ADAPT: Development / Production / Maintenance] |
| **Repository** | [ADAPT: github.com/org/repo] |

---

## Tech Stack

### Frontend / App Layer
- **Language**: TypeScript
- **Framework**: Next.js [ADAPT: version, e.g., 14+] (App Router)
- **UI Components**: [ADAPT: Shadcn/UI + Tailwind CSS / Radix UI / Chakra UI]
- **State Management**: [ADAPT: Zustand / Jotai / TanStack Query / None]
- **Forms**: [ADAPT: React Hook Form + Zod / None]

### Backend / Data Layer
- **BaaS**: Supabase
- **Database**: PostgreSQL (via Supabase)
- **Auth**: Supabase Auth ([ADAPT: email, OAuth providers])
- **Storage**: Supabase Storage
- **Realtime**: [ADAPT: Supabase Realtime subscriptions / None]
- **Edge Functions**: [ADAPT: Supabase Edge Functions (Deno) / Vercel Edge / None]
- **Vector Store**: [ADAPT: Supabase pgvector / None]

### AI Layer (if applicable)
- **SDK**: [ADAPT: Vercel AI SDK / LangChain.js / None]
- **LLM**: [ADAPT: OpenAI / Anthropic / None]
- **Embeddings**: [ADAPT: OpenAI text-embedding-3-small / None]

### Infrastructure
- **Deployment**: [ADAPT: Vercel / Netlify / self-hosted]
- **CI/CD**: [ADAPT: GitHub Actions / Vercel CI]

---

## Module Map

> [ADAPT: Replace with your actual directory structure]

```
src/
├── app/                    # Next.js App Router pages and layouts
│   ├── (auth)/             # [ADAPT: auth-gated routes group]
│   ├── api/                # API route handlers
│   └── layout.tsx
├── components/
│   ├── ui/                 # Primitive UI components (Shadcn, etc.)
│   └── [feature]/          # [ADAPT: feature-specific components]
├── lib/
│   ├── supabase/           # Supabase client setup (browser + server)
│   ├── api.ts              # API client types and fetch helpers
│   └── utils.ts
├── hooks/                  # Custom React hooks
├── types/                  # TypeScript type definitions
└── middleware.ts            # Auth + route protection middleware
```

**Module boundary rules** (ADAPT: specify forbidden imports):
- `components/` → MUST NOT import from `app/`
- Client Components → MUST NOT import server-only Supabase admin client

---

## Multi-Tenancy Model

**RLS (Row-Level Security)** is the primary tenant isolation mechanism:

```sql
-- [ADAPT: Example RLS policy — replace with your actual policies]
ALTER TABLE [table_name] ENABLE ROW LEVEL SECURITY;

CREATE POLICY "[table_name]_isolation"
  ON [table_name]
  USING (auth.uid() = user_id);         -- or: tenant_id = auth.jwt()->'tenant_id'
```

**Rules**:
- ALL tenant-scoped tables MUST have RLS enabled
- NEVER disable RLS for convenience — use service role key in server contexts only
- [ADAPT: describe your tenant model: user-level vs org-level]

---

## DB Schema

> [ADAPT: Describe your key tables and their relationships]

```
profiles      — user profile data (linked to auth.users via id)
  id (UUID, FK to auth.users)
  [ADAPT: other columns]

[table_name]  — [ADAPT: purpose]
  id (UUID, PK)
  user_id (UUID, FK to auth.users)
  [ADAPT: other columns]
```

**Supabase-specific rules**:
- `auth.users` is managed by Supabase Auth — NEVER modify directly
- Use `public.profiles` (or equivalent) for app-specific user data
- [ADAPT: describe any Supabase Storage bucket structure]

---

## API / Data Access Patterns

### Server Components (recommended for data fetching)
```typescript
// [ADAPT: update import path]
import { createServerClient } from '@/lib/supabase/server'

const supabase = createServerClient()
const { data } = await supabase.from('[ADAPT: table]').select('*')
```

### Client Components (user-initiated mutations)
```typescript
import { createBrowserClient } from '@/lib/supabase/client'

const supabase = createBrowserClient()
```

**Rule**: Server Components for reads, Mutations in Server Actions or Route Handlers.

---

## Auth Model

- **Provider**: Supabase Auth
- **Method**: [ADAPT: Email+Password / Magic Link / OAuth: GitHub, Google, etc.]
- **Session handling**: Supabase SSR utilities (`@supabase/ssr`)
- **Route protection**: `middleware.ts` redirects unauthenticated users

---

## Critical Constraints

1. **RLS everywhere**: Every user-scoped table must have RLS enabled — no exceptions
2. **Server-side service key**: Never expose `SUPABASE_SERVICE_ROLE_KEY` to the browser
3. **Type safety**: Always use generated types from `supabase gen types typescript`
4. **[ADAPT: add your project-specific constraints]**

---

## Test Execution

```bash
# [ADAPT: update for your test runner]
npm run test           # unit tests (Jest / Vitest)
npm run test:e2e       # end-to-end (Playwright / Cypress)
npm run lint           # ESLint
npm run type-check     # TypeScript compiler
```

---

## Key Reference Files

| Purpose | File | Editable? |
|---------|------|:---------:|
| **Active Task** | `naos/active/*.md` | ✅ Manual |
| **Task Registry** | `naos/TASK_REGISTRY.yaml` | ✅ Manual |
| **DB Types** | `[ADAPT: types/supabase.ts]` | 🚫 Auto-generated |
| **API Client** | `[ADAPT: src/lib/api.ts]` | ✅ Manual |
| **Supabase Config** | `[ADAPT: src/lib/supabase/]` | ✅ Manual |
