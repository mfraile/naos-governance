---
name: "cookbook-python"
description: "If-then recipes for Python backend code. Invoke when creating modules, recording datetimes, writing except blocks, reading config values, or adding Enum columns."
parameters: []
---

# Cookbook: Python Backend

## When to Use

Use this skill when creating Python modules, recording datetimes, writing except
blocks, reading config values, or adding enum columns.

> Extracted from `.github/instructions/python-backend.instructions.md`. See that file for full domain rules.

### If: Creating a new Python module in `[ADAPT: your source directory]`
**Then**: Add the standard module header with `Implements`, `Task`, `Specs`, `Rationale`

### If: Recording current datetime
**Then**: Use your project's timezone-aware utility — never `datetime.utcnow()` (deprecated + naive)
```python
# [ADAPT: replace with your project's datetime utility]
from src.utils.time import utc_now
now = utc_now()
```

### If: Writing an `except` block
**Then**: Log at WARNING+, re-raise, or route to DLQ — bare `except: pass` is forbidden
```python
try:
    result = risky_call()
except Exception as exc:
    logger.warning("risky_call failed: %s", exc)
    raise
```

### If: Reading a timeout, limit, or threshold
**Then**: Load from config files via your settings object — never hard-code numeric constants
```python
# [ADAPT: replace with your project's config import and access pattern]
from src.core.config import settings
timeout = settings.ai_models["triage"]["timeout_seconds"]
```

### If: Adding an Enum column to a database model
**Then**: Follow your ORM's best practice for enum type registration to avoid runtime errors
```python
# [ADAPT: replace with your ORM's enum column pattern]
# PostgreSQL + SQLAlchemy example — always use values_callable to avoid
# InvalidTextRepresentation errors when the enum type already exists
Column(SQLEnum(MyEnum, name='my_enum', create_type=False,
        values_callable=lambda obj: [e.value for e in obj]))
```
