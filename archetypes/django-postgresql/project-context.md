# Project Context — Django + PostgreSQL
# NAOS Portable Governance Kit
# ─────────────────────────────────────────────────────────────────────────────
# This is a pre-populated project-context.md template for Django + PostgreSQL.
# Replace all [ADAPT: ...] blocks with your project's actual content.
# ─────────────────────────────────────────────────────────────────────────────

# AI Coding Guidelines — Project Context

> **Purpose**: This file provides project-specific context to AI coding assistants.
> Host loading is client-dependent; configure and verify this file or reference it explicitly.
> Update this file whenever your stack, architecture, or constraints change.

---

## Project Identity

| Field | Value |
|-------|-------|
| **Name** | [ADAPT: Your project name] |
| **Type** | Django web application |
| **Primary Stack** | Python / Django / PostgreSQL |
| **Status** | [ADAPT: Development / Production / Maintenance] |
| **Repository** | [ADAPT: github.com/org/repo] |

---

## Tech Stack

### Backend
- **Language**: Python 3.11+
- **Framework**: Django [ADAPT: version, e.g., 5.1]
- **Database**: PostgreSQL [ADAPT: version]
- **ORM**: Django ORM
- **Task Queue**: [ADAPT: Celery with Redis / None]
- **Cache**: [ADAPT: Redis / Memcached / Django cache framework]

### API Layer
- **API Framework**: [ADAPT: Django REST Framework / Django Ninja / None (server-side rendered)]
- **Auth**: [ADAPT: Django built-in / JWT (djangorestframework-simplejwt) / OAuth2]
- **API Versioning**: [ADAPT: URL versioning (/api/v1/) / Header versioning / None]

### Frontend
- **Type**: [ADAPT: Server-side rendered (Django templates) / separate SPA]
- **Framework**: [ADAPT: HTMX / React / Vue / None]

### Infrastructure
- **Container**: Docker + docker-compose
- **CI/CD**: [ADAPT: GitHub Actions / GitLab CI / Jenkins]
- **Deployment**: [ADAPT: AWS / GCP / DigitalOcean / Heroku / self-hosted]

---

## Module Map

> [ADAPT: Describe your Django app structure. Example below — replace with your actual apps.]

```
[project-name]/
├── [app-name-1]/          # [ADAPT: what this app does]
│   ├── models.py
│   ├── views.py
│   ├── serializers.py     # (if using DRF)
│   └── urls.py
├── [app-name-2]/          # [ADAPT: what this app does]
├── config/                # Project settings
│   ├── settings/
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
│   ├── urls.py
│   └── wsgi.py
├── static/
├── templates/
└── manage.py
```

**App dependency rules** (ADAPT: specify forbidden imports):
- `[app-1]` → may NOT import from `[app-2]` (reason: [ADAPT])
- All apps → communicate via Django signals for cross-app events

---

## Database Schema

> [ADAPT: Describe your database schema. Key things to document:]
> - Which models hold sensitive / PII data
> - Multi-tenancy model (if applicable)
> - Index and constraint conventions
> - Any soft-delete patterns

```
[ADAPT: List key models and their table names]
AppName.ModelName  →  app_tablename

# Example:
# accounts.User    →  accounts_user  (PII: email, name — encrypted at rest)
# orders.Order     →  orders_order   (tenant_scoped via tenant_id FK)
```

**Schema conventions**:
- PII fields: [ADAPT: encrypted? hashed? which fields count as PII?]
- Soft delete: [ADAPT: is_deleted + deleted_at / permanent delete]
- Multi-tenancy: [ADAPT: single-schema with tenant_id / schema-per-tenant / separate DB]
- Audit trail: [ADAPT: audit log on which models?]

---

## Key Constraints

### Django-Specific Rules
- **Settings**: Never hard-code settings. Use `from django.conf import settings` or `environ`
- **Migrations**: Always generate with `manage.py makemigrations --name <descriptive_name>`
- **ORM queries**: All queries must be bounded with `.filter()` + pagination — no unbounded querysets
- **Signals**: Document all signals in `[app]/signals.py` — no anonymous signal receivers
- **CSRF**: Never disable CSRF middleware globally — use `@csrf_exempt` sparingly and with comment

### Database Rules
- Never write raw SQL unless using `RawQuerySet` with parameterized values
- Always use `select_related()` / `prefetch_related()` for FK/M2M in list views
- [ADAPT: any additional schema constraints, e.g., "no direct public schema access"]

### Security Rules
- Authentication: All API endpoints require `@login_required` or DRF `IsAuthenticated` permission
- Authorization: Object-level permissions via [ADAPT: django-guardian / custom / DRF policy]
- Input validation: Always use Form or Serializer validation — never trust `request.POST` directly
- File uploads: [ADAPT: allowed types, size limits, storage backend]

### Datetime Rules
- Always use `timezone.now()` from `django.utils.timezone`, not `datetime.datetime.now()`
- All `DateTimeField`s: `USE_TZ = True` (never set to False)
- Never store naive datetimes — all DB timestamps are UTC-aware

---

## Build Commands

> [ADAPT: Fill in your actual commands]

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Database
python manage.py migrate
python manage.py createsuperuser

# Development server
python manage.py runserver

# Tests
pytest -q tests/
pytest tests/unit/ -v --tb=short

# Code quality
ruff check .
mypy . --ignore-missing-imports

# Docker
docker-compose up -d
docker-compose exec web python manage.py migrate
```

---

## Key Workflows

### Adding a New Feature

1. Create or check relevant Django app (`python manage.py startapp myapp`)
2. Add models → generate migration → apply
3. Add views + serializers (if API) or templates (if server-rendered)
4. Register URLs in appropriate `urls.py`
5. Add tests (`tests/unit/` + `tests/integration/`)
6. Run `make -f Makefile.naos gov-refresh` to update function index

### Database Migration Workflow

1. Modify models in `models.py`
2. `python manage.py makemigrations --name <descriptive_name>`
3. Review generated migration: check for data migrations, index choices
4. `python manage.py migrate` (local) → reviewed in PR → applied to staging → production

### Deployment Checklist

```
□ All migrations applied: python manage.py showmigrations
□ Static files collected: python manage.py collectstatic --noinput
□ Environment variables set (see .env.template)
□ DEBUG = False in production settings
□ ALLOWED_HOSTS configured
□ Security headers enabled (SecurityMiddleware, HSTS, etc.)
```

---

*Template: Django + PostgreSQL Archetype — NAOS Portable Governance Kit*
