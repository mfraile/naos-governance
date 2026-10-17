# QUICK START — [ADAPT: Project Name]

> Get from clone to a project-specific, testable setup. Record actual setup
> effort locally if it matters; this template makes no universal time claim.

## Prerequisites

- [ADAPT: list required tools, e.g. Python 3.11+, Node.js 20+, Docker, git]
- [ADAPT: any required accounts or credentials]

---

## 1. Environment Setup

```bash
# Clone the repo
git clone [ADAPT: your-repo-url]
cd [ADAPT: project-dir]

# [ADAPT: choose your environment manager]
# Option A: conda
conda create -n [ADAPT: env-name] python=[ADAPT: 3.12]
conda activate [ADAPT: env-name]

# Option B: venv
python -m venv .venv
# Bash only: source .venv/bin/activate
# PowerShell only: .\.venv\Scripts\Activate.ps1
# Activation is optional: invoke the selected environment's Python directly.

# Install dependencies
pip install -r requirements.txt          # [ADAPT: adjust if different]
pip install -r requirements-dev.txt      # Dev + test dependencies
```

---

## 2. Configuration

```bash
# Copy environment template
cp [ADAPT: .env.template | docker-compose.env.template] .env

# [ADAPT: list required env vars to set]
# Edit .env and set:
#   DATABASE_URL=...
#   SECRET_KEY=...
#   [other required vars]
```

---

## 3. Services

```bash
# [ADAPT: how to start required services]
# Option A: Docker Compose
docker compose up -d    # starts DB, cache, etc.

# Option B: Local
[ADAPT: e.g., brew services start postgresql]
```

---

## 4. Database

```bash
# Run migrations
[ADAPT: alembic upgrade head | python manage.py migrate | ...]
```

---

## 5. Run the Application

```bash
# [ADAPT: how to start your app]
[ADAPT: uvicorn src.api.main:app --reload | python -m src.main | npm run dev | ...]
```

---

## 6. Run Tests

```bash
# [ADAPT] Use only the project's documented environment-loading mechanism.
# Do not execute .env as shell code; use an existing configured dotenv loader.

# Run test suite
[ADAPT: pytest -q tests/unit tests/acceptance]

# Quick smoke test
[ADAPT: pytest -q tests/unit -x]
```

---

## 7. Daily Workflow

```bash
# Before starting work
git pull && [ADAPT: conda activate env-name]

# After changing TASK_REGISTRY.yaml
make -f Makefile.naos gov-refresh

# After adding new functions
make -f Makefile.naos function-index

# Before committing
make -f Makefile.naos validate-all  # runs all validators
git add ... && git commit -m "feat(T-XXX): description"
```

---

## Governance Commands

| Command | Purpose |
|---------|---------|
| `make -f Makefile.naos gov-refresh` | Sync derived PM files after task changes |
| `make -f Makefile.naos naos-plan-coherence` | Review task claims against registry/module linkage |
| `make -f Makefile.naos naos-evidence-sign` | Emit adopter-signable evidence envelope |
| `make -f Makefile.naos naos-evidence-verify` | Verify local tamper-evidence and report signature-entry presence |
| `make -f Makefile.naos gov-full` | gov-refresh + truth validation |
| `make -f Makefile.naos drift-check` | Check for governance drift |
| `make -f Makefile.naos function-index` | Regenerate function index |
| `make -f Makefile.naos validate-all` | Run all project validators |

---

## Common Issues

**Tests fail with missing env var**:
Confirm the required variable names and the project's documented test loader.
Do not execute `.env` as shell code. For reviewed non-secret test values only:

```bash
export TESTING=true  # Bash; only if the application implements this setting
```

```powershell
$env:TESTING = "true"  # PowerShell; same application-specific condition
```

**Pre-commit hook fails**:
```bash
cat .githooks/pre-commit  # read the error message
# Common fixes: run make -f Makefile.naos gov-refresh, add docs to DOCS_INDEX.md
```

**[ADAPT: add your project's common gotchas here]**
