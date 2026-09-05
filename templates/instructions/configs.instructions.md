---
applyTo: "configs/**/*.yaml"
---

# Configuration Guidelines

> Consult `.github/project-context.md` for project-specific config conventions.

## Principles

- Configuration files are the **single source of truth** for application behavior.
- Code reads from configs — never hard-code values that belong in YAML.
- `[ADAPT: your config import, e.g. from src.core.config import settings]` — access via your settings object in Python code.

## Key Config Files

| File | Purpose |
|------|---------|
| `[ADAPT: your AI config file]` | AI model names, parameters, timeouts |
| `[ADAPT: your thresholds file]` | Confidence routing thresholds |
| `configs/event_bus.yaml` | Event bus configuration |
| `configs/features.yaml` | Feature flags |
| `configs/integrations.yaml` | External API settings |
| `configs/naos_architecture_boundaries.yaml` | Module boundary rules |

## SYNC Block Awareness

Some YAML values auto-sync into instruction files via `sync_instruction_files.py`:
- `[ADAPT: your AI models config file]` → `SYNC_AI_PIPELINE` blocks
- `[ADAPT: your thresholds config file]` → `SYNC_CONFIDENCE_ROUTING` blocks

When editing these files, run `make -f Makefile.naos gov-refresh` to propagate changes.

## Conventions

- Use descriptive keys with underscores: `max_retry_delay`, not `maxRetryDelay`.
- Include comments for non-obvious values.
- Group related settings under meaningful top-level keys.
- Threshold values must be in `[0.0, 1.0]` range for confidence scores.

## Validation

- Run `python scripts/validators/validate_configs.py` for declared config parse
  and schema-shape checks. Use `--configs-dir`, `--schema-dir`, and
  `--required-config` when your project stores config files outside the default
  `configs/` and `schema/configs/` paths.
- After editing, verify the config loads correctly: `[ADAPT: your config validation command, e.g. python -c "from src.core.config import settings; print('OK')"]`.
- Run `make -f Makefile.naos gov-refresh` to sync SYNC blocks.
- Run tests to verify no regressions: `pytest -q tests/unit`.

---

## Cookbook

> Extracted to skill: `.github/skills/cookbook-configs/SKILL.md` — invoke via Copilot chat when you need patterns.
