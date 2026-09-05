# 07 - Cost Analysis

**Version**: 0.1.0
**Status**: Draft
**Upstream**: [03-requirements.md](./03-requirements.md)

<!-- ADAPT: Fill in real numbers as you approach production.
     This document justifies infrastructure spend and guides pricing decisions. -->

---

## Unit Economics {#COST-1}

| Component | Cost | Unit | Notes |
|-----------|------|------|-------|
| [ADAPT: e.g. Database (PostgreSQL)] | $[X] | /month | [ADAPT: e.g. shared across all tenants] |
| [ADAPT: e.g. Compute (API server)] | $[X] | /month | [ADAPT] |
| [ADAPT: e.g. AI inference] | $[X] | /1k requests | [ADAPT] |
| [ADAPT: e.g. Storage] | $[X] | /GB/month | [ADAPT] |
| **Total per customer** | **$[X]** | /month | [ADAPT: at N-customer baseline] |

---

## Cost Scaling Model {#COST-2}

<!-- ADAPT: Fill in how unit costs change at different scale milestones. -->

| Milestone | Customers | Infra Cost | Cost/Customer | Gross Margin |
|-----------|-----------|------------|--------------|--------------|
| MVP | [ADAPT: e.g. 10] | $[X]/mo | $[X] | [X]% |
| Growth | [ADAPT: e.g. 100] | $[X]/mo | $[X] | [X]% |
| Scale | [ADAPT: e.g. 1000] | $[X]/mo | $[X] | [X]% |

---

## AI/LLM Cost Breakdown {#COST-3}

<!-- ADAPT: If your product uses AI models, break down inference costs separately.
     Delete this section for non-AI projects. -->

| Model | Provider | Cost | Trigger | Volume Estimate |
|-------|----------|------|---------|-----------------|
| [ADAPT: model name] | [ADAPT: Ollama/OpenAI/Anthropic] | $[X]/[unit] | [ADAPT: when triggered] | [ADAPT: monthly] |

---

## Infrastructure Assumptions {#COST-4}

<!-- ADAPT: State the assumptions behind your cost model. -->

- Cloud provider: [ADAPT: AWS / GCP / Azure / self-hosted]
- Region: [ADAPT]
- [ADAPT: any other constraints — e.g. reserved instances, GPU type, data transfer]

---

## Cost Optimization Opportunities {#COST-5}

<!-- ADAPT: List known levers that could reduce costs. -->

1. [ADAPT: e.g. GPU sharing across tenants reduces per-tenant AI cost by ~40%]
2. [ADAPT: e.g. Caching frequent queries reduces DB read load]
