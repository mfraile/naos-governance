---
name: "cookbook-configs"
description: "If-then recipes for config YAML files. Invoke when adding config keys, editing primary config files, or reading config values in application code."
parameters: []
---

# Cookbook: Configuration Files

## When to Use

Use this skill when adding config keys, editing primary config files, or reading
config values in application code.

> Extracted from `.github/instructions/configs.instructions.md`. See that file for full domain rules.

### If: Adding a new config key to a YAML file
**Then**: Add with a comment explaining its purpose; use snake_case; never hard-code the value in source code
**Example**:
```yaml
# [ADAPT: replace with your relevant config file path]
# configs/ai_models.yaml
triage:
  model_name: your-model-name   # Model used for route classification
  timeout_seconds: 30            # Hard limit per inference call
  max_tokens: 4096
```

### If: Editing key config files (e.g. AI models or thresholds)
**Then**: Run `make -f Makefile.naos gov-refresh` afterwards — these files may feed SYNC blocks in instruction files
**Example**: See `<!-- BEGIN SYNC_AI_PIPELINE -->` blocks in project docs — editing the YAML source propagates changes everywhere

### If: Validating declared config shape
**Then**: Run `python scripts/validators/validate_configs.py`; use
`--configs-dir`, `--schema-dir`, and repeated `--required-config` flags when
the project does not use the default `configs/`, `schema/configs/`, or
`features.yaml` paths
**Boundary**: This checks parse validity and declared schema shape only. It does
not prove runtime config correctness or deployment safety.

### If: Reading a config value in application code
**Then**: Access via your settings object — never open the YAML file directly in source code
**Example**:
```python
# [ADAPT: replace with your project's config import and access pattern]
from src.core.config import settings

# WRONG
import yaml
with open("configs/ai_models.yaml") as f:
    config = yaml.safe_load(f)

# RIGHT
model = settings.ai_models["triage"]["model_name"]
```
