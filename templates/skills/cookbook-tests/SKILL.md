---
name: cookbook-tests
description: If-then recipes for test writing. Invoke when running tests as an AI agent, writing timestamp-comparison tests, testing event bus/ASGI lifespan, or testing authenticated endpoints.
metadata:
  naos-parameters: '[]'
---

# Cookbook: Tests

## When to Use

Use this skill when running tests as an AI agent, writing timestamp-comparison
tests, testing event bus or ASGI lifespan, or testing authenticated endpoints.

> Extracted from `.github/instructions/tests.instructions.md`. See that file for full domain rules.

### If: Running the test suite as an AI agent or in a script
**Then**: Inspect the project's runner and environment setup, then invoke its documented test command in the selected environment. Do not assume a `.env` file, pytest installation or environment manager.
**Example**:
```text
[ADAPT: use the project's documented runner and existing test directories]
Python/pytest example if installed: python -m pytest -q tests/unit tests/acceptance
```
Do not source `.env` as shell code. Use a configured dotenv loader only if the
project implements it; use explicit Bash/PowerShell environment assignments for
reviewed test values when needed. No credential values belong in this example.

### If: Writing a test that uses timestamp comparison
**Then**: Use a timezone-aware comparison helper for ORM-loaded timestamps — SQLite strips tzinfo
**Example**:
```python
# [ADAPT: replace with your project's timezone utility, e.g. ensure_aware()]
from [ADAPT: your.utils.time] import ensure_aware

# WRONG — may fail on SQLite where tzinfo is stripped
assert record.created_at > datetime.now(UTC)

# RIGHT
assert ensure_aware(record.created_at) > datetime.now(UTC)
```

### If: Writing a test that touches the event bus or ASGI lifespan
**Then**: Gate with `TESTING=true` env var and use daemon threads for consumers
**Example**:
```python
# [ADAPT: your ASGI lifespan file and the TESTING guard location]
# In your ASGI startup: if os.environ.get("TESTING"): return
# In conftest.py: os.environ["TESTING"] = "true"
```

### If: Testing an endpoint that requires auth
**Then**: Use the `auth_headers` fixture from `tests/conftest.py` — never hardcode tokens
**Example**:
```python
def test_list_items(client, auth_headers):
    resp = client.get("/api/v1/items", headers=auth_headers)
    assert resp.status_code == 200
```
