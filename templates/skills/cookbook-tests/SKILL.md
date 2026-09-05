---
name: "cookbook-tests"
description: "If-then recipes for test writing. Invoke when running tests as an AI agent, writing timestamp-comparison tests, testing event bus/ASGI lifespan, or testing authenticated endpoints."
parameters: []
---

# Cookbook: Tests

## When to Use

Use this skill when running tests as an AI agent, writing timestamp-comparison
tests, testing event bus or ASGI lifespan, or testing authenticated endpoints.

> Extracted from `.github/instructions/tests.instructions.md`. See that file for full domain rules.

### If: Running the test suite as an AI agent or in a script
**Then**: Load env vars first, then call `pytest` directly — never use `conda run` (buffers stdout, creates zombie processes)
**Example**:
```bash
# WRONG — conda run buffers all stdout, creates zombie processes
# [ADAPT: your conda env name if applicable]
conda run -n your-env-name pytest -q tests/unit tests/acceptance

# RIGHT
# [ADAPT: your env setup command, e.g. source .env or conda activate + direct call]
set -a && source .env && set +a
pytest -q tests/unit tests/acceptance
```

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
