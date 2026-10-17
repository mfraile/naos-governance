---
name: cookbook-docker
description: If-then recipes for Docker and docker-compose. Invoke when writing Dockerfiles, handling secrets, adding services, or mounting config files.
metadata:
  naos-parameters: '[]'
---

# Cookbook: Docker & Deployment

## When to Use

Use this skill when writing Dockerfiles, handling secrets, adding services, or
mounting config files.

> Extracted from `.github/instructions/docker-deployment.instructions.md`. See that file for full domain rules.

### If: Writing a new Dockerfile
**Then**: Use a reviewed multi-stage recipe with a non-root runtime.
The build context must contain `requirements.txt` and `src/`. Supply `PYTHON_IMAGE`
as the same approved digest-pinned Linux Python image in both stages; it must
support `python -m venv` and pip. Choose that image through the project's existing
image/dependency review. This example supplies no current image recommendation,
application entrypoint or permission to build/download anything.

```dockerfile
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
COPY requirements.txt ./requirements.txt
RUN python -m venv /opt/venv && /opt/venv/bin/python -m pip install --no-cache-dir -r requirements.txt

FROM ${PYTHON_IMAGE} AS runtime
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 src/ /app/src/
ENV PATH="/opt/venv/bin:$PATH"
USER 10001:10001
```

The copied environment uses the identical base/ABI in both stages. Keep the
runtime environment read-only where feasible and select the actual application
command, writable directories and health probe through project review. No
container build or runtime behavior is established by this illustrative recipe.

### If: A service needs a secret (API key, DB password)
**Then**: Inject via environment variable at runtime — never write it into a Dockerfile or compose file
**Example**:
```yaml
# WRONG
environment:
  DB_PASSWORD: replace-me  # illustrative placeholder; still wrong to hardcode

# RIGHT
environment:
  DB_PASSWORD: ${DB_PASSWORD}  # injected from .env or Docker secret
```

### If: Adding a long-running service to docker-compose
**Then**: Include a `HEALTHCHECK` and `restart: unless-stopped`
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 5s
  retries: 3
```

### If: Mounting config or model files into a container
**Then**: Use named volumes for persistent data; mount `configs/` as read-only
**Example**: See `docker-compose.yml` — `- ./configs:/app/configs:ro` pattern
