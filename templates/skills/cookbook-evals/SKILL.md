---
name: cookbook-evals
description: If-then recipes for evaluating AI output quality — distinct from governance compliance testing. Invoke when building or debugging an AI-backed feature and you need to know if the model output is actually correct, not just rule-compliant.
metadata:
  naos-parameters: '[]'
---

# Cookbook: Evals

## When to Use

Use this skill when building or debugging an AI-backed feature and you need to
know if model output is actually correct, not just rule-compliant.

> Principle: The shipped NAOS autoresearch runner produces deterministic static/readiness evidence, not observed model compliance. Separately authorized feature evals assess output correctness within their dataset and scoring scope; neither establishes the other.

### If: You need to know if an AI feature produces correct outputs
**Then**: Write a small eval — a dataset of inputs + expected outputs + a scoring function

```python
# [ADAPT: use your eval framework — Evalite, pytest-llm, or plain pytest]
# Minimal pattern (framework-agnostic):
CASES = [
    {"input": "...", "expected": "..."},
]

def score(output, expected) -> float:
    # exact match, substring, regex, or LLM-as-judge
    return 1.0 if expected in output else 0.0

for case in CASES:
    output = call_your_ai_feature(case["input"])
    assert score(output, case["expected"]) >= 0.8
```

### If: Exact-match scoring is too brittle for natural language outputs
**Then**: Consider a model-backed judge only after explicit project policy, provider/model selection, data, cost and human approval gates are satisfied. The following is illustrative, not a shipped invocation or authorization. A second model call can grade output against a rubric, with calibration and human review.

```python
# [ADAPT: your model call]
JUDGE_PROMPT = """
Rate this output 0–1 for correctness against the expected answer.
Output: {output}
Expected: {expected}
Return only a float.
"""
score = float(llm(JUDGE_PROMPT.format(output=output, expected=expected)))
```

**Rubric review**:
- Define what "good" means before writing the judge
- Keep rubrics single-concern — one criterion per judge call
- Validate judge calibration on an independently reviewed, representative set of known cases before interpreting scores

### If: Building a dataset for repeatable evals
**Then**: Store cases in a YAML file, never inline — regenerable, versionable

```yaml
# [ADAPT: path — e.g. tests/evals/feature_name_cases.yaml]
cases:
  - id: "case-001"
    input: "..."
    expected: "..."
    tags: ["happy-path"]
  - id: "case-002"
    input: "..."
    expected: "..."
    tags: ["edge-case"]
```

### If: Deciding when to run evals
**Then**: Match cadence to cost and signal

| Trigger | Eval type | Cost |
|---------|-----------|------|
| Every PR touching the AI feature | Fast deterministic cases only | Low |
| Weekly / pre-release | Full dataset + project-configured evaluator | Medium |
| After model upgrade | Full dataset + regression check | Medium |
| After prompt changes | Targeted cases for changed behaviour | Low–Medium |

### If: Retaining a separately authorized eval summary
**Then**: Append one real JSON object per line using portable Python. This is a
standalone advisory artifact: NAOS does not automatically ingest this file or add
its pass rate to a Dimension 8/governance score. Populate counts from actual eval
results; an unknown model identity remains null. A caller-reported model string
is metadata, not verification of provider identity, availability or policy approval.

```python
# Provider-free summary helper; does not run an eval or call a model.
import json
from pathlib import Path


def append_eval_summary(path, *, passed, total, run_id, reported_model=None):
    if type(passed) is not int or type(total) is not int:
        raise ValueError("passed and total must be integer counts")
    if total <= 0 or not 0 <= passed <= total:
        raise ValueError("counts must satisfy 0 <= passed <= total and total > 0")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must identify the actual authorized eval")
    if reported_model is not None and (
        not isinstance(reported_model, str) or not reported_model.strip()
    ):
        raise ValueError("reported_model must be a nonempty string or None")
    record = {
        "run_id": run_id,
        "passed": passed,
        "total": total,
        "eval_pass_rate": passed / total,
        "reported_model": reported_model,
    }
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
    return record


# After the authorized eval completes, call with its actual result variables:
# append_eval_summary("naos/reports/eval_log.jsonl", passed=passed_count,
#                     total=case_count, run_id=actual_run_id,
#                     reported_model=actual_model_or_none)
```

## Anti-Patterns

| Pattern | Status |
|---------|--------|
| Shipping an AI feature with no eval dataset | **Avoid** |
| Using a model-backed judge without validating judge calibration | **Avoid** |
| Storing large datasets in Git (>10 MB) | **FORBIDDEN** (Rule 22) |
| Treating eval pass rate as a governance compliance score | **Wrong framing** — they measure different things |
| Hardcoding model names in eval scripts | **FORBIDDEN** (Rule 18 Principle 2) |
