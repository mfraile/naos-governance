---
name: "cookbook-migrations"
description: "If-then recipes for database migrations. Invoke when creating tenant-owned tables with isolation policies, adding enum types, or testing migration idempotency. Works with Alembic, Flyway, Prisma Migrate, and Django Migrations."
parameters: []
---

# Cookbook: Database Migrations

## When to Use

Use this skill when creating tenant-owned tables with isolation policies, adding
enum types, or testing migration idempotency.

> Extracted from `.github/instructions/migrations.instructions.md`. See that file for full domain rules.

### If: Creating a migration for a new tenant-owned table (multi-tenant project)
**Then**: Add `tenant_id`, enable your isolation strategy, test forward AND rollback
**Example — Alembic + PostgreSQL RLS**:
```python
def upgrade():
    op.create_table('[ADAPT: your_table_name]',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('tenant_id', UUID, nullable=False),
        # [ADAPT: ... add your business columns]
    )
    op.execute(sa.text("""
        ALTER TABLE [ADAPT: your_table_name] ENABLE ROW LEVEL SECURITY;
        ALTER TABLE [ADAPT: your_table_name] FORCE ROW LEVEL SECURITY;
        CREATE POLICY [ADAPT: your_table_name]_tenant_isolation
          ON [ADAPT: your_table_name]
          USING (tenant_id = current_setting('[ADAPT: your.session.var]')::uuid);
    """))

def downgrade():
    op.execute(sa.text("DROP POLICY IF EXISTS [ADAPT: your_table_name]_tenant_isolation ON [ADAPT: your_table_name];"))
    op.drop_table('[ADAPT: your_table_name]')
```
**Example — Prisma Migrate** (multi-tenant via application filtering):
```prisma
// [ADAPT: in prisma/schema.prisma]
model YourModel {
  id       String @id @default(uuid())
  tenantId String  // [ADAPT: always filter by tenantId in every service query]
  // ... your fields
}
```

### If: Adding a new enum type in a SQL migration
**Then**: Use parameterized DDL — never string-interpolate SQL
**Example — Alembic**:
```python
# Migration
op.execute(sa.text("CREATE TYPE [ADAPT: enum_name] AS ENUM ('[ADAPT: value1]', '[ADAPT: value2]')"))

# [ADAPT: SQLAlchemy model — if using Python + SQLAlchemy]
Column(SQLEnum(MyStatus, name='[ADAPT: enum_name]', create_type=False,
        values_callable=lambda obj: [e.value for e in obj]))
```
**Example — Prisma**:
```prisma
enum [ADAPT: StatusName] {
  [ADAPT: VALUE1]
  [ADAPT: VALUE2]
}
```

### If: Testing a migration you just wrote
**Then**: Run upgrade, then downgrade, then upgrade again to verify idempotency
**Example**:
```bash
# Alembic
alembic upgrade head && alembic downgrade -1 && alembic upgrade head

# Flyway
flyway migrate && flyway undo && flyway migrate

# Prisma
npx prisma migrate deploy && [ADAPT: prisma does not have rollback—restore from version control]

# Run tests after
[ADAPT: pytest -q tests/ | npm test | go test ./...]```
