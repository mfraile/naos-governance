---
name: "cookbook-observability"
description: "If-then recipes for AI session observability — tracing agent behavior, diagnosing failures, and building a feedback loop. Invoke when an agent produces unexpected output, when governance violations are hard to trace, or when setting up observability for a new AI feature."
parameters: []
---

# Cookbook: Observability

## When to Use

Use this skill when an agent produces unexpected output, governance violations
are hard to trace, or observability is needed for a new AI feature.

> Principle: AI agents do not reliably maintain full repository-wide situational awareness. Without traces, failures are difficult to diagnose. Observability turns opaque behavior into reviewable evidence.

### If: Setting up session tracing for an AI feature
**Then**: Choose a tracing backend, tag sessions with task context, and capture tool calls + model responses

```bash
# [ADAPT: Langfuse (open-source, self-hostable) or equivalent]
pip install langfuse                 # or: npm install langfuse
# Set env vars (never hardcode):
# LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST
```

**Minimum trace metadata to capture per session**:
```python
# [ADAPT: your tracing SDK call]
trace = client.trace(
    name="naos-session",
    metadata={
        "task": "T-XXX",          # NAOS task card ID
        "agent": "@naos-implement", # which agent ran
        "rule_set": "standard",    # governance profile
    }
)
```

### If: An agent produced unexpected output and you need to diagnose why
**Then**: Read the trace before touching the code — treat it like a stack trace

1. Open the trace for the failing session
2. Identify the tool call or prompt turn where behaviour diverged
3. Check: was context truncated? (token count spike) Did a rule fire? (look for rule-check tool calls)
4. Reproduce with the same inputs before proposing a fix

### If: Deciding which tracing tool to use
**Then**: Prefer self-hosted or zero-dependency options — match your data classification

| Option | When to use |
|--------|------------|
| **Langfuse** (open-source) | Full traces, LLM-as-judge evals, team dashboard |
| **OpenTelemetry** | Existing OTel stack in prod; use `opentelemetry-sdk` |
| **Structured logging** | Minimal setup; `logging.getLogger()` + JSON formatter |
| **NAOS memory/compact log** | Simplest — append `mem_save` checkpoints only when Engram/MCP write access is configured, authorized, verified, permitted by memory-use policy, and explicitly human-approved for durable write use; otherwise persist the same checkpoint in the active compact/task card |

### If: Integrating traces with NAOS governance
**Then**: Tag conformance failures in traces so you can correlate rule violations with session patterns

```python
# After a pre-commit block, log the context:
# [ADAPT: your tracing call]
span.event(name="governance-block", metadata={"rule": "Rule-11", "file": "src/x.py"})
```

## Anti-Patterns

| Pattern | Status |
|---------|--------|
| Debugging agent failures without a trace | **Avoid** |
| Storing PII / credentials in trace metadata | **FORBIDDEN** (Rule 19) |
| Tracing tool as the source of truth for governance | **FORBIDDEN** — RULES.md is ROM |
| Adding heavy tracing infrastructure before validating need | **Avoid** — start with structured logging |
