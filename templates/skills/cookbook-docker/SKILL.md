---
name: "cookbook-docker"
description: "If-then recipes for Docker and docker-compose. Invoke when writing Dockerfiles, handling secrets, adding services, or mounting config files."
parameters: []
---

# Cookbook: Docker & Deployment

## When to Use

Use this skill when writing Dockerfiles, handling secrets, adding services, or
mounting config files.

> Extracted from `.github/instructions/docker-deployment.instructions.md`. See that file for full domain rules.

### If: Writing a new Dockerfile
**Then**: Use multi-stage build; pin base image version; copy only artefacts in the runtime stage
```dockerfile
# multi-stage, pinned version
FROM python:3.12.3-slim AS builder
RUN pip install -r requirements.txt

FROM python:3.12.3-slim AS runtime
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY src/ /app/src/
```

### If: A service needs a secret (API key, DB password)
**Then**: Inject via environment variable at runtime — never write it into a Dockerfile or compose file
**Example**:
```yaml
# WRONG
environment:
  DB_PASSWORD: mysecret123

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
