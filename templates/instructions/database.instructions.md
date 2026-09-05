---
applyTo: "{**/models.py,**/db/**/*.py,**/migrations/**/*.py,alembic/versions/**/*.py}"
---

# SQL Database Guidelines

> Consult `.github/project-context.md` for your schema design and data isolation strategy.

## Multi-Flavour: Choose Your Database Pattern

| Database | Tenant Isolation Strategy | Migration Tool |
|----------|--------------------------|----------------|
| **PostgreSQL** | Row-Level Security (RLS) on `tenant_id` | Alembic / Flyway / Prisma Migrate |
| **MySQL / MariaDB** | Application-enforced tenant filtering via `WHERE tenant_id = ?` | Flyway / Liquibase |
| **Supabase** | Built-in RLS policies via `auth.uid()` or custom JWT claims | Supabase CLI migrations |
| **SQLite** | Single-tenant only (CI/dev use) — no tenant isolation needed | Alembic / Django manage.py |

## Two-Tier Schema — Multi-Tenant Projects

> **This section applies only if your application serves multiple tenants.**
> Skip entirely for single-tenant or internal apps.

| Schema | tenant_id? | Purpose | ORM marker |
|--------|:----------:|---------|------------|
| `[ADAPT: your global schema name]` | ❌ No | Shared reference data (no tenant ownership) | `__table_args__ = {"schema": "[ADAPT]"}` |
| `public` / `[ADAPT: tenant schema]` | ✅ Required | Tenant-owned data | Default — must add `tenant_id` column + isolation |

- Never add `tenant_id` to global/shared schema tables.
- Never access shared reference data using tenant-scoped session context.

## Data Isolation Patterns (Multi-Tenant Only)

**Option A — PostgreSQL RLS** (preferred for PostgreSQL):
```sql
-- [ADAPT: replace {table} with your actual table name]
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
CREATE POLICY {table}_tenant_isolation ON {table}
  USING (tenant_id = current_setting('[ADAPT: your.session.variable]')::uuid);
```
- PgBouncer MUST use **session mode** — transaction mode breaks `current_setting`.

**Option B — Supabase RLS** (Supabase projects):
```sql
CREATE POLICY tenant_isolation ON {table}
  USING (tenant_id = auth.uid()  -- or: (current_setting('request.jwt.claims')::json->>'tenant_id')::uuid
  );
```

**Option C — Application-layer filtering** (MySQL, or when DB-level RLS is unavailable):
```python
# [ADAPT: always filter by tenant_id in every query — never return cross-tenant data]
tenant_id = get_tenant_from_session()
results = db.query(Item).filter(Item.tenant_id == tenant_id).all()
```

## Enum Pattern (Python/SQLAlchemy)

- `SQLEnum(..., create_type=False, values_callable=lambda obj: [e.value for e in obj])` — see `python-backend.instructions.md`.

## Score / Confidence Columns

- `sa.Numeric(precision=3, scale=2)`, clamped: `max(0.0, min(1.0, value))`.

## Pool Configuration

- `[ADAPT: your pool size config, e.g. DB_POOL_SIZE / DB_MAX_OVERFLOW from environment]`.
- PgBouncer: session mode only (transaction mode breaks RLS session variables).

## Test Compatibility

- `[ADAPT: your CI test DB backend, e.g. SQLite + StaticPool for CI, PostgreSQL for integration]`.
- Use `[ADAPT: your timezone utility, e.g. ensure_aware()]` for ORM-loaded timestamps (SQLite strips tzinfo).

## Migration Anti-Patterns

> See `migrations.instructions.md` — never use `op.execute(f"...")`, never modify existing migrations.

---

## Cookbook

### If: Creating a new tenant-owned table (multi-tenant project)
**Then**: Add `tenant_id` column + your chosen isolation strategy — see `migrations.instructions.md` for migration patterns

### If: Creating a global/shared reference table
**Then**: Do NOT add `tenant_id` — this table is shared across all tenants; place in your global schema if applicable
