---
applyTo: "{**/*.cypher,**/*neo4j*.py,**/*graph*.py,**/*neptune*.py,**/*arango*.py}"
---

# Graph Database Tenant Isolation Rules

> Consult `.github/project-context.md` for full graph schema context.

## Multi-Flavour: Graph Database Options

| Database | Tenant Pattern | Query Language |
|----------|---------------|----------------|
| **Neo4j** | Node property `{tenant_id: $tid}` on all tenant nodes | Cypher |
| **Amazon Neptune** | Node property filter on all tenant vertices | Gremlin / openCypher |
| **ArangoDB** | Collection-per-tenant or document `tenantId` field | AQL |

## Global vs. Tenant Node Taxonomy

> **This section applies only if your application serves multiple tenants.**
> Skip for single-tenant or internal apps.

| Node Type | Has `tenant_id`? | Examples |
|-----------|:----------------:|----------|
| Global | ❌ No | `[ADAPT: your shared reference node types, e.g. Category, Region, ProductType]` |
| Tenant | ✅ Required | `[ADAPT: your tenant-owned node types, e.g. Order, Customer, Invoice]` |

**Invariant**: Global nodes are shared across ALL tenants — they MUST NOT have `tenant_id`.
Tenant nodes are private — they MUST have `tenant_id` and EVERY query MUST filter by it.

## Mandatory Query Patterns

```cypher
// ✅ Correct — tenant isolation enforced
// [ADAPT: replace with your node types and relationship]
MATCH (t:[ADAPT: YourTenantNode] {tenant_id: $tenant_id})-[:[ADAPT: YOUR_REL]]->([ADAPT: GlobalNode])
WHERE [ADAPT: condition]
RETURN t

// ❌ WRONG — missing tenant filter on tenant node
MATCH (t:[ADAPT: YourTenantNode])-[:[ADAPT: YOUR_REL]]->(g:[ADAPT: GlobalNode]) RETURN t, g
```

## Python Cypher Conventions

```python
# Always pass tenant_id as a parameter — never interpolate into the query string
session.run(
    "MATCH (t:[ADAPT: YourTenantNode] {tenant_id: $tid}) RETURN t",
    tid=tenant_id          # parameterized — injection safe
)

# Never build Cypher by string concatenation
# WRONG: f"MATCH (t:Node {{tenant_id: '{tenant_id}'}})"
```

## Gremlin (Amazon Neptune) Pattern

```python
# [ADAPT: if using Neptune, filter by tenant partition key]
g.V().has('[ADAPT: NodeLabel]', 'tenantId', tenant_id).out('[ADAPT: EDGE_LABEL]').toList()
```

## Security Checklist

- [ ] Every write to a tenant node sets `tenant_id` from the authenticated session context
- [ ] Every read of tenant nodes filters `{tenant_id: $tid}` as a query parameter
- [ ] Global node queries never accept or filter by `tenant_id`
- [ ] Parameterized queries only — no f-strings or `.format()` in Cypher/AQL/Gremlin

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-neo4j/SKILL.md` — invoke via Copilot chat when you need patterns.
