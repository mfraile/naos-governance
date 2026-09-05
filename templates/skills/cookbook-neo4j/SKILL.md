---
name: "cookbook-neo4j"
description: "If-then recipes for graph database queries. Invoke when writing tenant-filtered Cypher/Gremlin/AQL, parameterized queries, global node queries, or creating tenant-owned nodes. Works with Neo4j, Amazon Neptune, and ArangoDB."
parameters: []
---

# Cookbook: Graph Database & Cypher

## When to Use

Use this skill when writing tenant-filtered Cypher, Gremlin, or AQL;
parameterized queries; global node queries; or tenant-owned nodes.

> Extracted from `.github/instructions/graph-database.instructions.md`. See that file for full domain rules.

### If: Writing a Cypher query that returns tenant data (multi-tenant project)
**Then**: Always filter tenant nodes by `{tenant_id: $tid}` — never return data across tenant boundaries
**Example**:
```cypher
-- WRONG — no tenant filter
MATCH (t:[ADAPT: YourTenantNode])-[:[ADAPT: REL]]->([ADAPT: GlobalNode]) RETURN t

-- RIGHT
MATCH (t:[ADAPT: YourTenantNode] {tenant_id: $tenant_id})-[:[ADAPT: REL]]->([ADAPT: GlobalNode]) RETURN t
```

### If: Writing a Cypher query in Python
**Then**: Use parameterized queries — never interpolate tenant_id or user input into the Cypher string
**Example**:
```python
# WRONG — injection risk
query = f"MATCH (t:[ADAPT: Node] {{tenant_id: '{tenant_id}'}}) RETURN t"

# RIGHT
session.run("MATCH (t:[ADAPT: Node] {tenant_id: $tid}) RETURN t", tid=tenant_id)
```

### If: Writing a query against global/shared reference nodes
**Then**: Do NOT add a `tenant_id` filter — global nodes are shared across all tenants
**Example**:
```cypher
-- CORRECT — shared reference node, no tenant filter needed
MATCH (ref:[ADAPT: YourGlobalNode] {code: $code}) RETURN ref
```

### If: Creating a new tenant-owned node (multi-tenant project)
**Then**: Always set `tenant_id` from the authenticated session context — never from the request body
**Example**:
```python
# WRONG — trusts client-provided tenant_id
tenant_id = request.json["tenant_id"]

# RIGHT — from authenticated session
tenant_id = Depends([ADAPT: your_get_current_tenant_id_dependency])
```

### If: Using Amazon Neptune (Gremlin)
**Then**: Filter by your tenant partition property on every traversal
**Example**:
```python
# [ADAPT: Neptune uses Gremlin — always add tenant filter]
g.V().has('[ADAPT: label]', '[ADAPT: tenantIdProperty]', tenant_id).out('[ADAPT: EDGE]').toList()
```
