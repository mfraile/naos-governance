# Project Context — Spring Boot + Kafka
# NAOS Portable Governance Kit
# ─────────────────────────────────────────────────────────────────────────────
# Pre-populated project-context.md template for Spring Boot + Kafka (enterprise).
# Replace all [ADAPT: ...] blocks with your project's actual content.
# ─────────────────────────────────────────────────────────────────────────────

## Project Identity

| Field | Value |
|-------|-------|
| **Name** | [ADAPT: Your project name] |
| **Type** | Spring Boot enterprise application |
| **Primary Stack** | Java / Spring Boot / PostgreSQL / Kafka |
| **NAOS Profile** | governance-assured (enterprise default) |
| **Status** | [ADAPT: Development / Staging / Production] |
| **Repository** | [ADAPT: github.com/org/repo] |

---

## Tech Stack

### Core
- **Language**: Java [ADAPT: version, e.g., 21 LTS]
- **Framework**: Spring Boot [ADAPT: version, e.g., 3.3+]
- **Build Tool**: [ADAPT: Maven / Gradle]
- **Database**: PostgreSQL [ADAPT: version]
- **ORM**: Spring Data JPA (Hibernate)
- **Migrations**: Flyway
- **Message Queue**: Apache Kafka ([ADAPT: version])
- **Kafka Client**: spring-kafka

### API
- **Style**: [ADAPT: REST (Spring MVC / Spring WebFlux) / GraphQL / gRPC]
- **Docs**: [ADAPT: SpringDoc OpenAPI / Swagger UI]
- **Auth**: [ADAPT: Spring Security + JWT / OAuth2 Resource Server / LDAP]

### Testing
- **Unit/Integration**: JUnit 5 + Mockito + AssertJ
- **DB Integration**: Testcontainers (real PostgreSQL in tests)
- **Kafka Testing**: EmbeddedKafka (spring-kafka-test) or Testcontainers

### Infrastructure
- **Container**: Docker + kubernetes (k8s)
- **CI/CD**: [ADAPT: GitHub Actions / Jenkins / GitLab CI]
- **Observability**: [ADAPT: Micrometer + Prometheus + Grafana / Datadog / Dynatrace]

---

## Module Map

> [ADAPT: Describe your package structure. Typically layered or domain-oriented.]

```
src/main/java/[com/org/project]/
├── api/
│   ├── controller/         # REST controllers / @RestController
│   └── dto/                # Request/response DTOs (records or classes)
├── domain/
│   ├── model/              # JPA @Entity classes
│   ├── repository/         # Spring Data JPA repositories
│   └── service/            # Business logic services (@Service)
├── infrastructure/
│   ├── kafka/              # Kafka producers, consumers (@KafkaListener)
│   ├── persistence/        # Custom queries, DB config
│   └── config/             # Spring @Configuration classes
└── [ProjectName]Application.java

src/main/resources/
├── application.yml          # Base config
├── application-dev.yml      # Dev overrides
├── application-prod.yml     # Prod overrides
└── db/migration/            # Flyway migration scripts (V{n}__{description}.sql)
```

**Layering rules** (DO NOT violate):
- `controller/` → calls `service/` ONLY — never `repository/` directly
- `service/` → calls `repository/` — no HTTP calls (async via Kafka for long ops)
- `kafka/` consumers → delegate to `service/` — never access `repository/` directly
- No circular imports between packages

---

## DB Schema

> [ADAPT: Describe your key tables. Flyway manages migration scripts in `db/migration/`.]

```sql
-- [ADAPT: paste representative table definition]
CREATE TABLE [table_name] (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    [column]    [type] NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

**Flyway rules**:
- Migration files: `V{n}__{snake_case_description}.sql` (e.g., `V3__add_user_preferences.sql`)
- NEVER rename or modify existing migration files (Flyway checksum validation)
- New columns: additive only — no `NOT NULL` without `DEFAULT` on populated tables
- Rollback = new migration (no `downgrade` in production)

---

## Kafka Event Schema

> [ADAPT: Describe your Kafka topics and event schemas]

```java
// [ADAPT: update topic constants and event class names]
// Topics defined in: src/main/java/[...]/infrastructure/kafka/Topics.java

// Example:
public class Topics {
    public static final String [DOMAIN]_CREATED = "[domain].created.v1";
    public static final String [DOMAIN]_UPDATED = "[domain].updated.v1";
    // DLQ: "[topic].dlq"
}
```

**Event rules**:
- Topic naming: `{domain}.{event}.{version}` (e.g., `orders.created.v1`)
- ALL events are idempotent — consumers must handle duplicate delivery
- Failed events route to DLQ (`{topic}.dlq`) after max retries
- Schema evolution: additive fields only — never remove/rename fields in v1

---

## Auth Model

- **Provider**: [ADAPT: Spring Security + JWT / OAuth2 Resource Server / Keycloak]
- **Multi-tenancy**: [ADAPT: describe tenant isolation if applicable]
- **Method-level security**: `@PreAuthorize("hasRole('...')")` on service methods (not just controllers)
- **Audit**: Spring Security `AuditApplicationEvent` or custom `@Audited`

---

## Critical Constraints

1. **Testcontainers for DB tests**: Never use H2 in-memory DB — always test against real PostgreSQL via Testcontainers
2. **No `@Transactional` on controllers**: Transaction management belongs in `service/` layer
3. **Flyway-only schema changes**: NEVER modify DB schema outside of Flyway migrations
4. **Config via `application.yml`**: No hard-coded values in `@Value` annotations — always use `@ConfigurationProperties`
5. **[ADAPT: add your project-specific constraints]**

---

## Test Execution

```bash
# [ADAPT: Maven or Gradle]
# Maven
./mvnw test                    # All unit tests
./mvnw verify -Pfull           # Unit + integration (requires Docker for Testcontainers)
./mvnw test -pl [module]       # Single module

# Gradle
./gradlew test
./gradlew integrationTest

# With coverage (JaCoCo)
./mvnw verify jacoco:report
```

**Note**: Integration tests require Docker running (Testcontainers starts PostgreSQL/Kafka automatically).

---

## Build Commands

```bash
# Build
./mvnw clean package -DskipTests   # Build JAR
./mvnw clean package                # Build + test

# Run locally
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev

# Lint / static analysis
./mvnw checkstyle:check pmd:check spotbugs:check
```

---

## Key Reference Files

| Purpose | File | Editable? |
|---------|------|:---------:|
| **Active Task** | `naos/active/*.md` | ✅ Manual |
| **Task Registry** | `naos/TASK_REGISTRY.yaml` | ✅ Manual |
| **DB Migrations** | `src/main/resources/db/migration/` | ✅ Manual |
| **App Config** | `src/main/resources/application*.yml` | ✅ Manual |
| **Kafka Topics** | `[ADAPT: infrastructure/kafka/Topics.java]` | ✅ Manual |
| **JPA Entities** | `[ADAPT: domain/model/]` | ✅ Manual |
