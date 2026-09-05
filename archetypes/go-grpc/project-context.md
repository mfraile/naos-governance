# Project Context — Go + gRPC
# NAOS Portable Governance Kit
# ─────────────────────────────────────────────────────────────────────────────
# Pre-populated project-context.md template for Go + gRPC microservices.
# Replace all [ADAPT: ...] blocks with your project's actual content.
# ─────────────────────────────────────────────────────────────────────────────

## Project Identity

| Field | Value |
|-------|-------|
| **Name** | [ADAPT: Your project name] |
| **Type** | Go microservices / gRPC API |
| **Primary Stack** | Go / gRPC / PostgreSQL (sqlc) / Kafka |
| **Status** | [ADAPT: Development / Production / Maintenance] |
| **Repository** | [ADAPT: github.com/org/repo] |

---

## Tech Stack

### Core
- **Language**: Go [ADAPT: version, e.g., 1.22+]
- **API Protocol**: gRPC ([ADAPT: version]) + protobuf
- **HTTP Gateway**: [ADAPT: grpc-gateway / None (gRPC only) / Echo for REST]
- **Database**: PostgreSQL [ADAPT: version]
- **ORM / Query**: sqlc (type-safe SQL codegen)
- **Migrations**: golang-migrate

### Infrastructure
- **Message Queue**: Kafka ([ADAPT: version or Confluent Platform])
- **Container**: Docker + kubernetes (k8s)
- **Service Mesh**: [ADAPT: Istio / Linkerd / None]
- **Observability**: [ADAPT: OpenTelemetry + Prometheus / Datadog / None]
- **CI/CD**: [ADAPT: GitHub Actions / ArgoCD / Tekton]

---

## Module Map

> [ADAPT: Replace with your actual service/package structure]

```
cmd/
├── [service-name]/         # Service entry point
│   └── main.go
internal/
├── [service-name]/
│   ├── handler/            # gRPC handler implementations
│   ├── service/            # Business logic
│   ├── repository/         # Database access (sqlc-generated + wrappers)
│   └── domain/             # Domain models and interfaces
├── shared/
│   ├── db/                 # DB connection, migrations
│   ├── kafka/              # Kafka producer/consumer setup
│   └── middleware/         # Auth, logging, trace interceptors
proto/
├── [service]/
│   └── v1/
│       └── service.proto   # gRPC service definitions
pkg/
└── [shared-pkg]/           # Public packages (if any)
```

**Module boundary rules** (ADAPT: specify forbidden imports):
- `handler/` → imports `service/` only, never `repository/` directly
- `repository/` → NO business logic, pure DB access
- Services communicate ONLY via gRPC interfaces or Kafka events (no direct imports across services)

---

## DB Schema

> [ADAPT: Describe your key tables. sqlc generates Go types from these.]

```sql
-- [ADAPT: paste representative schema fragments]
CREATE TABLE [table_name] (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    [column]   [type] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**sqlc rules**:
- ALL queries live in `internal/[service]/repository/queries/*.sql`
- NEVER write raw SQL outside of `.sql` query files
- After adding queries: `sqlc generate` (regenerates Go types)

---

## gRPC Service Definitions

> [ADAPT: list your services and key RPCs]

```protobuf
// [ADAPT: paste key service definition]
service [ServiceName] {
    rpc Create[Resource] (Create[Resource]Request) returns (Create[Resource]Response);
    rpc Get[Resource]    (Get[Resource]Request)    returns ([Resource]);
    rpc List[Resources]  (List[Resources]Request)  returns (List[Resources]Response);
}
```

**Proto rules**:
- ALL protobuf files in `proto/[service]/v1/`
- After modifying proto: `buf generate` (regenerates Go stubs)
- Versioning: never break v1 wire format — add new RPCs, don't modify existing

---

## Event Bus (Kafka)

```go
// [ADAPT: update topic names and message types]
// Producer: internal/shared/kafka/producer.go
// Consumer: internal/[service]/kafka/consumer.go

// Topics: [ADAPT: list your Kafka topics]
// e.g., "orders.created.v1", "payments.processed.v1"
```

**Rules**:
- Topic naming: `{domain}.{event}.{version}` (e.g., `orders.created.v1`)
- ALL events are idempotent — consumers must handle duplicate delivery
- Failed events → DLQ topic `{topic}.dlq`
- NEVER call sync HTTP in Kafka consumer hot path

---

## Auth Model

- **Protocol**: [ADAPT: JWT / mTLS / API keys]
- **Interceptor**: `internal/shared/middleware/auth_interceptor.go`
- **Enforcement**: Every unary method and stream beginning passes through auth interceptor

---

## Critical Constraints

1. **No business logic in handlers**: Handlers are thin — delegate to `service/` layer
2. **sqlc for all DB access**: No raw `database/sql` string queries in `service/` or `handler/`
3. **Proto first**: Schema changes start with `.proto` edit, then `buf generate`
4. **Context propagation**: Pass `context.Context` through ALL function calls — never store in struct
5. **[ADAPT: add your project-specific constraints]**

---

## Test Execution

```bash
# Unit tests
go test ./...

# With coverage
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

# Integration tests (requires running Postgres + Kafka)
go test -tags=integration ./...

# gRPC contract tests
[ADAPT: buf curl ... or grpcurl ...]
```

---

## Build Commands

```bash
# Generate code (proto stubs + sqlc types)
buf generate && sqlc generate

# Build all services
go build ./cmd/...

# Lint
golangci-lint run ./...

# Run a service locally
go run ./cmd/[ADAPT: service-name]/main.go
```

---

## Key Reference Files

| Purpose | File | Editable? |
|---------|------|:---------:|
| **Active Task** | `naos/active/*.md` | ✅ Manual |
| **Task Registry** | `naos/TASK_REGISTRY.yaml` | ✅ Manual |
| **Proto definitions** | `proto/` | ✅ Manual |
| **sqlc queries** | `internal/*/repository/queries/` | ✅ Manual |
| **Generated Go types** | `internal/*/repository/*.go` | 🚫 Auto-generated (`sqlc generate`) |
| **Generated gRPC stubs** | `internal/*/gen/` | 🚫 Auto-generated (`buf generate`) |
