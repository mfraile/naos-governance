# MCP Roadmap

MCP support is phased.

## Phase 1: Readiness Only

The plugin has no active MCP server. NAOS can inventory MCP config declarations
and memory provider posture, but it does not call MCP tools.

## Phase 2: Read-Only MCP

Future MCP tools may inspect NAOS reports, command availability, adapter
coherence, and learning lifecycle posture. They must not mutate files.

## Phase 3: Governed Write Operations

Write-capable MCP tools require explicit human approval, audit evidence,
authorization boundaries, and command-specific governance. They remain disabled
until those controls exist.

Forbidden by default:

- memory writes;
- hidden context injection;
- provider/model/API calls;
- Git push or merge;
- hook activation;
- approval, certification, deployment, release, or compliance claims.
