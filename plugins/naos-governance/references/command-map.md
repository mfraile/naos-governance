# NAOS Command Map For Codex

Use visible local commands. Prefer `naos ...` when the package entrypoint is
available and `make -f Makefile.naos ...` when working in an adopter project
with the generated Makefile.

| Intent | Command |
| --- | --- |
| Confirm kit posture | `naos self-check --profile <profile>` |
| Choose setup modules | `naos setup-recommendations --profile <profile>` |
| Review memory posture | `naos memory-readiness --profile <profile>` |
| Verify memory/MCP access claims | `naos memory-access --profile <profile>` |
| Govern memory use | `naos memory-use-policy --profile <profile>` |
| Review learning lifecycle | `naos learning-loop-review --profile <profile>` |
| Review behavioral baseline readiness | `naos behavioral-readiness --profile <profile>` |
| Package AI-assisted code provenance evidence | `naos ai-code-provenance --profile <profile>` |
| Package compliance posture evidence | `naos compliance-posture --profile <profile>` |
| Review UI spec-object traceability | `naos design-traceability --profile <profile>` |
| Count local findings by failure mode | `naos failure-mode-observations --profile <profile>` |
| Review repo-local OpenCode config hygiene | `naos opencode-config-hygiene --profile <profile>` |
| Check AI surface health | `naos ai-surface-budget --profile <profile>` |
| Review systemic impact | `naos systemic-impact --profile <profile>` |
| Route governance findings | `naos control-plane-review --profile <profile>` |
| Review package/SBOM/provenance/hash evidence | `naos package-reality --profile <profile>` |
| Verify declared Python API symbols | `naos api-symbol-reality --profile <profile>` |
| Check source module traceability | `naos module-headers --profile <profile>` |
| Check spec-pack contract structure | `naos spec-pack-contract --profile <profile>` |
| Preview missing profile-required spec files | `naos spec-pack-materialize . --profile <profile> --dry-run` |
| Map brownfield evidence to specs for review | `naos spec-assembly-worksheet . --profile <profile>` |
| Check spec cascade coherence | `naos spec-cascade --profile <profile>` |
| Check declared AC/SCEN completion evidence | `naos ac-completion-evidence --profile <profile>` |
| Inspect one exact active/completed task | `naos task-lifecycle --task <TASK-ID> --profile <profile>` |
| Record native task completion | `naos task-complete --task <TASK-ID> --profile <profile>`; verified delivery additionally requires existing test/evidence refs and an approved exact-task `task_delivery` decision |
| Validate candidate research provenance | `naos research-record <record.yaml> --profile <profile>` |
| Compose explicit lifecycle evidence links | `naos composed-traceability --profile <profile>` |
| Import local harness traces as review evidence | `naos harness-trace-import --source naos/harness_traces/example.jsonl --profile <profile>` |
| Review plan/task coordination | `naos plan-coherence --profile <profile>`; add `--diff-base <ref>` only when comparing changed files to alignment path declarations |
| Propose an Assured human-gated agent plan | `naos agent-orchestration-plan --profile assured` |
| Hash reviewer evidence | `naos evidence-attestation --profile <profile>` |
| Emit adopter-signable evidence envelope | `naos evidence-sign --profile <profile>` |
| Verify local tamper-evidence and report signature-entry presence | `naos evidence-verify --profile <profile>` |
| Package review evidence | `naos evidence-pack --profile <profile>` |
| Export review findings for SARIF interop | `naos sarif-export --profile <profile>` |
| Check adapter drift | `naos adapter-coherence --profile <profile>` |
| Brownfield report-writing preview | `naos adopt . --mode brownfield --profile <profile> --dry-run` |
| Greenfield report-writing preview | `naos adopt . --mode greenfield --profile <profile> --dry-run` |
| Adoption preview without report or activation writes | `naos adopt . --mode brownfield --profile <profile> --no-write-preview` |

Reports are review evidence. They do not authorize work, approve plans, prove
semantic drift, sign on behalf of NAOS, validate third-party signatures,
certify, deploy, release, or prove compliance.
Task completion records repository state but does not authorize merge, release,
or evidence admission. Research validation does not promote candidate claims,
and composed structural links do not prove semantic correctness.
Agent-orchestration output is a local proposal only; it does not launch agents
or clients, write client configuration, mutate tasks or claims, or authorize
dispatch.
