# Is NAOS Right for My Project?

> _Tested with NAOS kit v1.0.0+ · Last verified 2026-08-27_
> Use this document to assess whether NAOS will deliver value for your specific situation.
> NAOS is not for every project — this guide will help you decide honestly.

---

## The Core Question

NAOS delivers value when **AI-generated code carries real risk** and you need a way to produce governance evidence, run profile-aware checks, and route review decisions — not just hope for alignment.

If AI-assisted changes are absent or immaterial, NAOS may add more process than
value. As AI-assisted change risk and evidence needs grow, evaluate NAOS against
the project's actual controls rather than a universal usage threshold.

---

## Fit Assessment

Answer each question. Count your "Yes" answers.

### AI Usage

- [ ] Your team uses AI coding assistants (Copilot, Claude Code, Cursor, Continue.dev, Gemini CLI) regularly
- [ ] AI-assisted changes are frequent or affect material production behavior
- [ ] You have more than one AI assistant in use across your team
- [ ] You have caught AI-generated duplicate code or requirement violations before

### Project Characteristics

- [ ] The project is in production or approaching production
- [ ] The codebase has more than ~5,000 lines of code
- [ ] You have written requirements, specs, or acceptance criteria
- [ ] More than one developer works on the project
- [ ] You have a code review process

### Risk and Compliance

- [ ] Code quality problems have reached production in the last 6 months
- [ ] You operate in a regulated industry (finance, healthcare, government, defense)
- [ ] You have a compliance requirement (SOC 2, ISO 27001, HIPAA, FedRAMP, etc.)
- [ ] A governance audit of your AI-assisted development would be uncomfortable today
- [ ] You cannot currently identify which AI-assisted changes have review evidence, gaps, waivers, or unresolved risk

---

## Interpreting the Assessment

No universal AI-code percentage or numeric score determines fit. Review the
signals above with the project's risk, evidence, and operating constraints:

| Observed need | Proportionate next check |
| --- | --- |
| Little AI-assisted change and no material evidence gap | Compare `quickstart` overhead with existing repository controls before installing. |
| Repeated AI-assisted changes or shared-team coordination gaps | Compare `lite` and `standard` generated surfaces against the exact workflow and evidence need. |
| Formal evidence, exception, or review obligations | Evaluate `standard` or `assured` configuration, but do not treat the profile name as approval, compliance, or operating-effectiveness evidence. |

Use [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md)
to select by purpose. Profiles are not a mandatory progression or a risk score.

---

## When NAOS Is Particularly Valuable

**Material AI-assisted change**: Frequent or high-impact AI-assisted changes can
increase the coordination and evidence burden. NAOS combines instruction
surfaces, deterministic checks, gates, evidence packs, and dashboard outputs to
surface repository-local issues before or during review; effectiveness must be
measured in the adopter project.

**Team environments**: Multiple developers using multiple AI tools without shared controls is a high-risk configuration. NAOS provides a shared file-first control plane across tool surfaces.

**Spec-driven projects**: If you have written requirements, NAOS provides surfaces for linking requirements to tasks, code, and tests. The links and their supporting evidence still require review; their presence does not prove requirements compliance.

**Projects undergoing audit**: NAOS produces repository-local governance
evidence and deterministic conformance results. The default kit does not ship a
behavioral score or universal benchmark. Your project needs its own profile,
evidence, review boundaries, and any separately designed behavioral baseline.
NAOS artifacts can support a structured explanation of the process; they are
not an audit opinion or proof of operating effectiveness.

---

## When NAOS May Not Be Worth It

**Prototype / throwaway project**: If the project will be discarded or the codebase is genuinely experimental, governance overhead is not warranted. Use `quickstart` at most.

**Fully human-written code**: NAOS is designed for AI-assisted development. If your team does not use AI coding tools, its configured guidance and evidence layer may add cost without a clear benefit.

**Very early-stage (pre-spec) project**: NAOS works best when you have at least a rough specification. If you are still in pure exploration mode, governance adds friction before value.

---

## Honest Limitations

NAOS publishes no universal behavioral or compliance score. If your adoption
requires assurance, review repository evidence alongside the project's own
controls, risk assessment, and qualified reviewer judgement.

What NAOS can provide when configured and operated: **a measurable evidence baseline, profile-aware findings, and a methodology for reviewing proposed improvements over time**. Operating effectiveness must be measured in the adopter project.

Plain instruction files may provide less structured measurement, but the comparison depends on the adopter's actual tools and controls.

---

## Next Step

If NAOS is a fit for your project:

→ [Which NAOS Profile Should I Choose?](./WHICH_NAOS_PROFILE_SHOULD_I_CHOOSE.md)

If you want to assess NAOS as a methodology kit (rather than as a tool for your project):

→ [NAOS roadmap](../../ROADMAP.md) and [compliance mapping](../COMPLIANCE_MAPPING.md)
