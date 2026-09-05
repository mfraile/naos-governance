---
applyTo: "src/api/**/*.py"
---

# API Endpoint Guidelines

> Consult `.github/project-context.md` for full API conventions and auth patterns.

## Layering Rule (Mandatory)

- Routes → Services → DB. **Never** access the database directly from a route handler.
- `[ADAPT: if your project separates module boundaries, document which modules routes MUST NOT import from]`
- Routes call services; services own business logic and DB interactions.

## Authentication

- Every new endpoint MUST declare the auth dependency:
  ```python
  # [ADAPT: replace with your project's auth dependency module and function names]
  # FastAPI example:
  from [ADAPT: your.deps.module] import get_current_user  # required on all protected routes
  async def my_endpoint(
      user=Depends(get_current_user),
      # [ADAPT: if multi-tenant — also inject tenant context from session]
      # tenant_id=Depends(get_current_tenant_id),
  ): ...
  # Django example: use @login_required or DRF permission_classes = [IsAuthenticated]
  # Express example: router.use(authMiddleware) or passport.authenticate('jwt')
  ```
- No unauthenticated routes except explicitly listed public endpoints (health, docs, login).

## Request Validation

- Use Pydantic models for all request bodies — never access `request.body()` raw.
- Validate and sanitise path/query parameters with `Query()` / `Path()` annotated types.
- Reject unknown fields: use `model_config = ConfigDict(extra="forbid")` in request schemas.

## Error Responses

- Use a centralized error handler for all errors — never return raw tracebacks.
- Standard error shape: `{"detail": "<safe message>"}` — no internal stack info.
- HTTP status conventions: 400 validation, 401 unauthenticated, 403 unauthorised, 404 not found, 422 schema.

## CSRF Requirements

- All state-changing endpoints (POST/PUT/PATCH/DELETE) must validate the CSRF token.
- CSRF validation is handled by middleware — do not implement it per-endpoint.

## Performance

- Synchronous handlers must not call LLM models or long tasks inline — use `BackgroundTasks` or event bus for anything >1s.
- All DB queries must be bounded with `LIMIT` — never return unbounded result sets.

## Rate Limiting

- Apply rate-limit decorators for public-facing and LLM-backed endpoints (limits in `configs/integrations.yaml`).

## OpenAPI / Documentation

- Every endpoint: docstring (first line = summary), `response_model=`, `responses={}` for error codes.
- Tag by domain: `tags=["orders"]`, `tags=["users"]`, etc.

> **Security checklist**: auth deps, CSRF, SSRF, centralized error handler, bounded queries — see `security.instructions.md`.

---

## Cookbook

### If: Creating a new route endpoint
**Then**: Add both auth dependencies, a typed `response_model`, and bound all DB queries with `LIMIT`
**Example**:
```python
# WRONG — no auth, unbounded query
@router.get("/items")
async def list_items(db=Depends(get_db)):
    return db.query(Item).all()

# RIGHT — auth, service layer, bounded
@router.get("/items", response_model=list[ItemSchema])
async def list_items(
    user=Depends(get_current_user),
    # [ADAPT: add tenant context dependency if your app is multi-tenant]
    limit: int = Query(50, le=200),
):
    return await item_service.list_items(user.id, limit=limit)
```

### If: Accepting a user-provided URL
**Then**: Validate with your SSRF validator before any HTTP fetch — see `security.instructions.md` cookbook for the full pattern

### If: A route needs to call an LLM or long-running task
**Then**: Offload via `BackgroundTasks` — synchronous paths must never call LLM models directly
**Example**: Use `background_tasks.add_task(...)` pattern in your route handler
