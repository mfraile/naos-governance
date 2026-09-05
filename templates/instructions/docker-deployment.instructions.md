---
applyTo: "{deploy/docker/Dockerfile*,docker-compose*.yml,**/*.dockerfile}"
---

# Docker & Deployment Guidelines

> Canonical source: `SECURITY.md`.
> Consult `.github/project-context.md` for service topology and environment variable conventions.

## Multi-Stage Builds

- Use multi-stage builds: `builder` stage installs deps, `runtime` stage copies artefacts only.
- Final image must NOT contain: build tools, test dependencies, source `.git` directory, `*.pyc` files.
- Pin base image versions (e.g. `python:3.12.3-slim`) — never use `latest`.

## Secrets & Sensitive Data

- NEVER embed secrets, API keys, or credentials in `Dockerfile` or `docker-compose*.yml`.
- Pass secrets via environment variables injected at runtime (Docker secrets or Kubernetes Secrets).
- Verify: `docker history <image>` must show no `ENV` layers containing keys or passwords.
- `[ADAPT: if you store model checksums, verify SHA256 on container startup]`

## Health Checks (Mandatory)

- Every long-running service must declare a `HEALTHCHECK`:
  ```dockerfile
  HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8000/health || exit 1
  ```
- API service: `/health` endpoint; DB: `pg_isready`; Redis: `redis-cli ping`.

## Environment Variables

- All configurable values via `ENV` — never hard-code ports, paths, or credentials.
- Document every `ENV` variable with a comment showing its purpose and default.
- Use `configs/*.yaml` at runtime — mount config directory as a read-only volume.

## Network Isolation

- Define explicit Docker networks; never use the default bridge for production services.
- Database and Redis containers must NOT expose ports to the host in production (`expose:` not `ports:`).
- Tenant separation: traffic between tenant services must traverse the auth/ingress layer.

## Volume Mounts

- Persistent data requires named volumes — never anonymous.
- Mount `configs/` as read-only: `- ./configs:/app/configs:ro`. `[ADAPT: your model cache env var if using Ollama or similar]`

## Compose Conventions

- `[ADAPT: your services list and their alphabetical order]`
- Set `restart: unless-stopped` for stateful services.
- Set `deploy.resources.limits` for memory-intensive services.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-docker/SKILL.md` — invoke via Copilot chat when you need patterns.
