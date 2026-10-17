---
applyTo: "tests/**/*.py"
---

# Test Guidelines

> Consult `.github/project-context.md` for project-specific test patterns and fixture conventions.

## Running Tests

[ADAPT] Inspect the project's documented test runner, configuration, directories,
markers and environment-loading mechanism first. Do not execute a `.env` file as
shell code or assume it is required. Prefer the selected environment's Python;
use the project's configured dotenv loader only if it exists.

```text
Python/pytest example only when installed and these directories exist:
python -m pytest -q tests/unit tests/acceptance
Optional llm_smoke marker only when declared and provider access is authorized:
python -m pytest -m llm_smoke -q
```

## Selected test environment

Use the selected environment's documented test command directly when possible.
Do not assume an environment manager, pytest installation or buffering behavior
that has not been observed for this project.

## Fixtures

- [ADAPT] Inspect actual fixture definitions and scopes in `conftest.py` or the project's equivalent before using them.
- Example names such as `test_client`, `test_db_url`, `jwt_keys`, `csrf_token` and `auth_headers` are not shipped project APIs. Use them only if defined.
- Keep synthetic test identities and data explicit; do not reuse real customer data.

## Markers

- `@pytest.mark.acceptance` — Integration/acceptance tests
- `@pytest.mark.llm_smoke` — LLM/AI model tests (require a running inference service)
- `@pytest.mark.stress` — Performance/stress tests

## Naming

- Test files: `test_<module>.py`
- Test functions: `test_<behavior>_<expected_outcome>`
- Fixtures: descriptive, lowercase with underscores

## Database Testing

- [ADAPT] Inspect the project's actual CI database and timestamp behavior. Use its existing timezone-aware comparison helper if one exists; do not invent `ensure_aware()`. Test each supported backend when the change depends on backend behavior.

## ASGI / Event Bus Testing

- [ADAPT] Use `TESTING=true` only if the application implements that guard. For ASGI applications, avoid blocking the lifespan thread; use the project's supported test lifecycle controls.

## Coverage

`pytest --cov=src --cov-report=html`

## Anti-Patterns

- Never use `time.sleep()` in tests — use async/fixtures.
- Never skip tests without `@pytest.mark.skip(reason="...")`.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-tests/SKILL.md` — invoke via Copilot chat when you need patterns.
