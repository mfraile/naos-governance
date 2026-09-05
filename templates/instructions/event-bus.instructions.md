---
applyTo: "src/eventing/**/*.py"
---

# Event Bus Guidelines

> Consult `.github/project-context.md` for full event bus architecture.

## Publishing Events

```python
# [ADAPT: replace with your event bus module and event schema imports]
from src.eventing.event_bus import build_redis_event_bus
from src.schemas.event_schemas import MyEventV1

bus = build_redis_event_bus(redis_client)
bus.publish("my_stream.v1", event.model_dump())
```

- `[ADAPT: your stream naming convention, e.g. "{prefix}:{topic}"]` (prefix from `configs/event_bus.yaml`).
- Always use versioned schemas — never publish raw dicts.

## Consumer Groups

- Register consumers with `subscribe_group(topic, group_name, handler)`.
- Each consumer group must have a unique, descriptive name.
- **NEVER** call `subscribe_group()` on the ASGI lifespan thread — it runs an infinite loop.
- Spawn each consumer in a daemon thread: `threading.Thread(target=..., daemon=True).start()`.

## ASGI Lifespan Guard (Mandatory)

```python
import os
if os.getenv("TESTING") == "true":
    return  # skip consumer registration in tests
```

- Always gate consumer startup with `TESTING` env-var check.
- If `TestClient` instantiation takes >1s, a blocking consumer loop is the cause.

## Dead Letter Queue (DLQ)

- Failed events MUST be routed to DLQ — `[ADAPT: your DLQ topic naming, e.g. "{topic}.dlq"]` — never silently discard.
- DLQ suffix from `configs/event_bus.yaml` `dlq_suffix` key.
- Pattern:
  ```python
  try:
      handler(event)
  except Exception as exc:
      logger.error("Handler failed, routing to DLQ: %s", exc)
      bus.publish(f"{topic}.dlq", {"error": str(exc), "original": event})
  ```

## Idempotency

- Every handler must be idempotent — use `[ADAPT: your dedup module]` for deduplication keys.
- Key format: `{consumer_group}:{event_id}`. TTL from `configs/event_bus.yaml`.

## Retry Policy

- Retry ONLY transient errors: connection errors, timeouts, 5xx, 429.
- NEVER retry: 4xx (except 429), validation errors, schema mismatches.
- Backoff: exponential with jitter, capped at `max_delay` — values from `configs/event_bus.yaml`.

## Redis Connection

- `socket_connect_timeout=2.0` to avoid long hangs during test setup. Each consumer thread uses its own `SessionLocal()`.

## Schema Conventions

- Event schemas live in `[ADAPT: your event schemas module]` — never define inline in producers.
- Increment version suffix (`V1` → `V2`) for breaking changes; keep old version for 1 release.

---

## Cookbook

### If: Publishing an event from a service
**Then**: Use a versioned schema from your event schemas module — never publish raw dicts
```python
# [ADAPT: replace with your event bus publish pattern]
bus.publish("my_stream.v1", MyEventV1(...).model_dump())
```

### If: Registering a consumer in ASGI lifespan
**Then**: Guard with `TESTING` env check, then run in a daemon thread — never block lifespan thread.
See `[ADAPT: your ASGI file]` for the canonical pattern.

### If: A consumer handler fails to process an event
**Then**: Route to the DLQ — never silently discard. See DLQ section above for the pattern.

### If: Writing an idempotent event handler
**Then**: Use your dedup module with key format `{consumer_group}:{event_id}`
