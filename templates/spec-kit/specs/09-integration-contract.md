# 09 - Integration Contracts

**Version**: 0.1.0
**Status**: Draft
**Upstream**: [03-requirements.md](./03-requirements.md), [04-architecture.md](./04-architecture.md)

<!-- ADAPT: Document every external system your product integrates with.
     Include data schemas, auth models, versioning policy and rate limits.
     Informs tests/contract/ for consumer-driven contract testing. -->

---

## Integration Inventory

| Integration | Purpose | Direction | Protocol | Auth |
|-------------|---------|-----------|----------|------|
| [ADAPT: e.g. "Stripe"] | [ADAPT: e.g. "Payment processing"] | Outbound | REST | API key |
| [ADAPT: e.g. "SendGrid"] | [ADAPT: e.g. "Transactional email"] | Outbound | REST | API key |
| [ADAPT: e.g. "Auth0 / Cognito"] | [ADAPT: e.g. "Identity management"] | Inbound | OAuth2/JWT | JWKS |

---

## Integration Detail: [ADAPT: System Name] {#INT-1}

**Base URL**: `[ADAPT]`
**Version**: [ADAPT: e.g. v1, v2024-01-01]
**Rate Limits**: [ADAPT: e.g. 1000 req/min]
**Auth**: [ADAPT: header name and format]

### Events / Webhooks Consumed {#INT-1.W}

<!-- ADAPT: If this integration sends events TO your system, document the payload schema. -->

**Event**: [ADAPT: event type]
```json
{
  "[ADAPT: field]": "[ADAPT: type]"
}
```

**Verification**: [ADAPT: e.g. HMAC signature in `X-Signature` header]

### API Calls Made {#INT-1.API}

<!-- ADAPT: Document each external API call your system makes. -->

**Endpoint**: `POST [ADAPT: path]`
**Request**:
```json
{ "[ADAPT: field]": "[ADAPT: type]" }
```
**Response**:
```json
{ "[ADAPT: field]": "[ADAPT: type]" }
```
**On failure**: [ADAPT: retry strategy — e.g. "3 retries with exponential backoff, route to DLQ on final failure"]

---

<!-- ADAPT: Repeat the "Integration Detail" block for each external system -->

---

## Versioning Policy

<!-- ADAPT: How do you handle breaking changes in external APIs? -->

- **Upstream breaking changes**: [ADAPT: e.g. "Pin to specific API version; create ADR before upgrading"]
- **Downstream consumers**: [ADAPT: e.g. "Semantic versioning for webhooks; 90-day deprecation notice"]

---

## Contract Test Coverage

<!-- ADAPT: Reference the contract test files that validate these integrations. -->

| Integration | Test File | Type |
|-------------|-----------|------|
| [ADAPT] | `tests/contract/test_[ADAPT].py` | Pact / Manual |
