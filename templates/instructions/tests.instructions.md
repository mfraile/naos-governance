---
applyTo: "tests/**/*.py"
---

# Test Guidelines

> Consult `.github/project-context.md` for project-specific test patterns and fixture conventions.

## Running Tests

```bash
# Load env vars FIRST (required)
set -a && source .env && set +a
pytest -q tests/unit tests/acceptance        # recommended gate
pytest -m llm_smoke -q                       # LLM tests only
```

## NEVER Use `conda run` for Tests

`conda run` buffers all stdout, creates zombie processes. Always use direct `pytest`.

## Fixtures

- **Session-scoped**: `test_client`, `test_db_url`, `jwt_keys`
- **Request-scoped**: `client` (with CSRF), `csrf_token`, `auth_headers`
- Test data: Use pytest fixtures in `tests/conftest.py`, never hardcode UUIDs or emails.

## Markers

- `@pytest.mark.acceptance` — Integration/acceptance tests
- `@pytest.mark.llm_smoke` — LLM/AI model tests (require a running inference service)
- `@pytest.mark.stress` — Performance/stress tests

## Naming

- Test files: `test_<module>.py`
- Test functions: `test_<behavior>_<expected_outcome>`
- Fixtures: descriptive, lowercase with underscores

## Database Testing

- Tests use SQLite by default (CI). Use `[ADAPT: your timezone utility, e.g. ensure_aware()]` for timestamp comparisons (SQLite strips tzinfo). Test on both SQLite and PostgreSQL for ORM-backed code.

## ASGI / Event Bus Testing

- Set `TESTING=true` to skip blocking consumer loops. Never call blocking loops on the ASGI lifespan thread.

## Coverage

`pytest --cov=src --cov-report=html`

## Anti-Patterns

- Never use `time.sleep()` in tests — use async/fixtures.
- Never skip tests without `@pytest.mark.skip(reason="...")`.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-tests/SKILL.md` — invoke via Copilot chat when you need patterns.
