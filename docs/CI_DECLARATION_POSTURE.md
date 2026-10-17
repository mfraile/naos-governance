# Local CI declaration posture

`naos governance-bypass-posture` inspects local declarations only. `naos_ci_present`
means at least one supported automatic trigger/job declares a recognized direct
NAOS command. It does not prove that the executable is installed or authentic,
that any filter matches a real change, that a job runs, that failures block merges,
or that branch protection is configured. `execution_verified` and
`enforcement_verified` remain false. Review the actual provider configuration and
run evidence before treating CI as a compensating control.

The existing `workflow_dir_present`, `workflow_files`, `naos_workflow_files`, and
`naos_ci_present` fields remain available. The file lists now include recognized
root GitLab/Azure/Jenkins declarations and use portable relative POSIX paths.
`declarations` records each path, provider, classification, and bounded reason.
`declaration_status` is `present`, `not_detected`, or `unknown`.
`inspection_complete` indicates whether every file received a supported presence
or absence classification; it is not exhaustive provider syntax validation.
A supported match in a file establishes declaration presence even when other
steps are outside this detector's finite scope. Unknown files remain visible
alongside supported files. Unsupported or unreadable declarations produce an
inspection finding, rather than being silently reported as missing CI.

Supported local files and syntax:

- GitHub `.github/workflows/*.yml` and `*.yaml`: `push` or `pull_request` in
  string/list/mapping form, ordinary jobs with `runs-on` and direct `steps.run`.
  Standard string-list branch/path/tag/type filters are declarations only and
  are not evaluated. Manual-only triggers do not count. Conditions, matrices,
  reusable workflows, and action-only jobs without a supported direct command
  remain unknown; literal `if: false` steps/jobs do not count.
- GitLab `.gitlab-ci.yml`: ordinary visible jobs with string/list `script`,
  default push eligibility or ordered rules restricted to equality comparisons
  of `CI_PIPELINE_SOURCE` with push/merge_request_event/schedule/web and
  `when` on_success/always/manual/never. Workflow/job source eligibility must
  intersect for push or merge requests. Hidden templates and manual/never jobs
  do not count. Includes, inherited defaults, extends, only/except, child
  pipelines, and other rule expressions remain unknown. Global/job
  `before_script`/`after_script` and job `run`/`hooks` declarations also remain
  unknown when no supported `script` declaration establishes presence.
- Root `azure-pipelines.yml`, `azure-pipelines.yaml`, and `Jenkinsfile` are
  recognized but unsupported, and explicitly unknown. Other providers and
  nonstandard configured file locations are outside discovery coverage.

Recognized command prefixes are `naos gate-evaluate`,
`make -f Makefile.naos validate-all`, `make -f Makefile.naos naos-gate-evaluate`,
`python cli.py gate-evaluate`, and
`python -m naos_governance.scripts.naos_ci_readiness`. Listed Python 3.11–3.13
launcher spellings and `python.exe` are accepted. Explicit `./` and `.\` relative
forms are normalized for these declared paths. Comments, echo/printf text, help/version requests, and make no-execution
options do not count. Shell control flow, operators, wrappers, heredocs, substitutions, and
unrecognized executable forms (including environment-assignment prefixes and
local wrapper scripts) or multi-command shell programs are unknown, not
interpreted as proof of absence. Known echo/printf/no-op commands can be
classified as absence. Simple direct
command sequences and backslash continuations are supported. This is not a
shell, Groovy, or provider validator. Invalid YAML, duplicate mapping keys,
nonmapping YAML, unreadable files, parser/structure recursion overflow, and symlink declaration
leaves are unknown;
raw parse excerpts and command arguments are not copied into the report.

For standard/assured, supported absence retains the existing policy-driven
`naos_ci_not_detected` severity. Unknown inspection is warning for those profiles
and advisory for earlier profiles, preserving the existing inspection-failure
convention. There is no new provider execution or merge-enforcement gate.

The supported structural rules are grounded in the current official
[GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
and [GitLab job rules](https://docs.gitlab.com/ci/jobs/job_rules/), reviewed on
2026-10-02. GitLab documents ordered first-match rules and default exclusion of
merge-request pipelines for jobs without rules. This detector intentionally
supports a smaller subset of those languages.
