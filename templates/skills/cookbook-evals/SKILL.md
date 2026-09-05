---
name: "cookbook-evals"
description: "If-then recipes for evaluating AI output quality — distinct from governance compliance testing. Invoke when building or debugging an AI-backed feature and you need to know if the model output is actually correct, not just rule-compliant."
parameters: []
---

# Cookbook: Evals

## When to Use

Use this skill when building or debugging an AI-backed feature and you need to
know if model output is actually correct, not just rule-compliant.

> Principle: NAOS autoresearch measures **governance compliance** (did the AI follow the rules?). Evals measure **output correctness** (did the AI produce the right answer?). Both are needed; neither replaces the other.

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
**Then**: Use LLM-as-a-Judge — a second model call grades the output against a rubric

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

**Rubric principles (Karpathy: principles > rules)**:
- Define what "good" means before writing the judge
- Keep rubrics single-concern — one criterion per judge call
- Validate judge calibration on 10 known cases before trusting scores

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

### If: Connecting evals to NAOS conformance
**Then**: Treat eval pass rate as a Dimension 8 metric — log results alongside autoresearch output

```bash
# After running evals, append summary to autoresearch log:
# [ADAPT: your eval runner output]
echo "eval_pass_rate: 0.87  cases: 23  model: claude-sonnet-4-6" >> naos/reports/eval_log.jsonl
```

## Anti-Patterns

| Pattern | Status |
|---------|--------|
| Shipping an AI feature with no eval dataset | **Avoid** |
| Using a model-backed judge without validating judge calibration | **Avoid** |
| Storing large datasets in Git (>10 MB) | **FORBIDDEN** (Rule 22) |
| Treating eval pass rate as a governance compliance score | **Wrong framing** — they measure different things |
| Hardcoding model names in eval scripts | **FORBIDDEN** (Rule 18 Principle 2) |
