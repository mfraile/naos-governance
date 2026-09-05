---
applyTo: "{alembic/**,**/migrations/**,**/db/migrations/**,fly/**,prisma/migrations/**}"
---

# Database Migration Guidelines

> Consult `.github/project-context.md` for project-specific database schema conventions.

## Multi-Flavour: Choose Your Migration Tool

| Tool | Ecosystem | Key Commands |
|------|-----------|-------------|
| **Alembic** | Python / SQLAlchemy | `alembic upgrade head` / `alembic downgrade -1` |
| **Flyway** | JVM / polyglot | `flyway migrate` / `flyway undo` |
| **Prisma Migrate** | Node.js / TypeScript | `npx prisma migrate deploy` / `npx prisma migrate dev` |
| **Django Migrations** | Python / Django | `python manage.py migrate` / `showmigrations` |
| **golang-migrate** | Go | `migrate up` / `migrate down 1` |

## Two-Tier Schema (if applicable)

- `[ADAPT: if your project uses a global/tenant schema split, document here]`
- Example: **global schema** (shared reference data, no `tenant_id`) vs. **tenant schema** (tenant-owned data, `tenant_id` required + isolation policy).
- Never add `tenant_id` to global schema tables.

## Commands

```bash
# Apply all pending migrations
# [ADAPT: choose your tool]
alembic upgrade head         # Alembic (Python/SQLAlchemy)
flyway migrate               # Flyway (JVM)
npx prisma migrate deploy    # Prisma (Node.js)
python manage.py migrate     # Django

# Rollback one migration
alembic downgrade -1         # Alembic
flyway undo                  # Flyway (paid tier)
npx prisma migrate reset     # Prisma (dev only)

# Generate new migration
alembic revision --autogenerate -m "description"   # Alembic
npx prisma migrate dev --name "description"         # Prisma
python manage.py makemigrations                    # Django
```

## Conventions

- Migration messages: descriptive, lowercase with underscores.
- Always test migrations on your CI database backend AND your production database backend.
- Always use parameterized queries — no string interpolation in SQL.
- `[ADAPT: if using SQLAlchemy: enums MUST use values_callable=lambda obj: [e.value for e in obj]]`

## Before Creating Migrations

1. Check `[ADAPT: your ORM models file, e.g. src/db/models.py, prisma/schema.prisma]` for the current ORM state.
2. `[ADAPT: if using multi-schema, verify schema assignment for each table]`
3. Ensure new tables follow existing naming conventions.

## After Creating Migrations

1. Apply forward migration — verify it runs without error.
2. Roll back one step — verify rollback works.
3. Re-apply forward — confirm idempotency.
4. Run tests: `[ADAPT: pytest -q tests/ | npm test | go test ./...]`.

## Anti-Patterns

- Never use SQL with string interpolation — use parameterized statements or ORM methods.
- Never drop columns/tables without a verified rollback path.
- Never modify existing migration files — create new ones.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-migrations/SKILL.md` — invoke via Copilot chat when you need patterns.
