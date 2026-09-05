# 05 - API Specification

**Version**: 0.1.0
**Status**: Draft
**Upstream**: [03-requirements.md](./03-requirements.md), [04-architecture.md](./04-architecture.md)
**Downstream**: [06-acceptance.md](./06-acceptance.md)

<!-- ADAPT: This spec file documents the external API surface of your system.
     For internal function signatures, see src/ code and docstrings. -->

---

## API Conventions

<!-- ADAPT: Define conventions that apply to all endpoints. -->

- **Base URL**: `[ADAPT: e.g. https://api.yourproject.com/v1]`
- **Auth**: [ADAPT: e.g. Bearer JWT in `Authorization` header]
- **Content-Type**: `application/json`
- **Errors**: [ADAPT: error response schema — e.g. `{"error": "code", "message": "detail"}`]
- **Pagination**: [ADAPT: e.g. cursor-based with `next_cursor` field, or offset/limit]

---

## Group 1: [ADAPT: Resource Name — e.g. "Items"] {#API-1}

### API-1.1: [ADAPT: e.g. "Create Item"] {#API-1.1}

**Method**: `POST`
**Path**: `/[ADAPT: resource-path]`
**Requires**: FR-001
**Auth**: Required

**Request**:
```json
{
  "[ADAPT: field]": "[ADAPT: type and description]",
  "[ADAPT: field]": "[ADAPT]"
}
```

**Response** (201 Created):
```json
{
  "id": "string (UUID)",
  "[ADAPT: field]": "[ADAPT]"
}
```

**Errors**:
| Code | Meaning |
|------|---------|
| 400 | Validation error |
| 401 | Missing or invalid token |
| 422 | [ADAPT: business rule violation] |

---

### API-1.2: [ADAPT: e.g. "List Items"] {#API-1.2}

**Method**: `GET`
**Path**: `/[ADAPT: resource-path]`
**Requires**: FR-001
**Auth**: Required

**Query Parameters**:
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 20 | Max items (1–100) |
| `cursor` | string | null | [ADAPT: pagination cursor] |

**Response** (200 OK):
```json
{
  "items": [],
  "next_cursor": "string | null"
}
```

---

<!-- ADAPT: Continue adding API-1.N, API-2.N, etc. for each resource group and endpoint -->

---

## Group 2: [ADAPT: Another Resource Name] {#API-2}

### API-2.1: [ADAPT] {#API-2.1}

<!-- ADAPT: Duplicate the endpoint block pattern from Group 1 -->

---

## Webhooks / Events {#API-W}

<!-- ADAPT: Document async events or webhooks if your system emits them.
     Delete this section if not applicable. -->

### [ADAPT: Event Name — e.g. "item.created"] {#API-W.1}

**Trigger**: [ADAPT: when it fires]
**Payload**:
```json
{
  "event": "[ADAPT: event type string]",
  "timestamp": "ISO 8601",
  "data": {}
}
```
