#!/usr/bin/env python3
"""
naos_governance_audit.py — Governance Completeness Checker
Inspired by ECC's harness-audit.js (27 checks, 0-10 normalized scores).
Adapted for NAOS: checks governance file completeness, not harness coverage.

IMPORTANT: This audit is TIER-AWARE. It detects which governance profile
(quickstart/lite/standard/assured) is installed and only checks for files
that profile is expected to have. A Lite project scoring 10/10 is just as
good as an Assured project scoring 10/10 — the expectations scale with the tier.

IMPORTANT: Costs, baselines, and scores are PROJECT-SPECIFIC. Run your own
autoresearch baseline to establish your project's governance posture.

Usage:
    python scripts/naos_governance_audit.py              # Full audit
    python scripts/naos_governance_audit.py --tier lite   # Override tier detection
    python scripts/naos_governance_audit.py --category rules  # Single category
    python scripts/naos_governance_audit.py --json       # JSON output

Categories (5 — universal across all tiers):
    1. Rules & Enforcement   — .ai/RULES.md, pre-commit hooks
    2. Instruction Surface   — CLAUDE.md + at least one other AI tool config
    3. Governance Artifacts   — Tier-appropriate PM files
    4. Automation Pipeline   — Makefile targets, scripts (tier-scaled)
    5. Session Management    — Context pressure, checkpoints (tier-scaled)

Output: Per-category score (0-10) + overall governance completeness score.
Note: Scores are relative to YOUR tier. A 10/10 on Lite means "fully configured
for Lite" — not "equivalent to Assured."
"""

import argparse
import json
import re
import sys
from pathlib import Path


def find_project_root() -> Path:
    """Walk up from CWD to find project root (has .ai/RULES.md or CLAUDE.md)."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        if (parent / ".ai" / "RULES.md").exists() or (parent / "CLAUDE.md").exists():
            return parent
    return cwd


def detect_tier(root: Path) -> str:
    """Detect installed governance tier from RULES.md content or profile config."""
    rules_path = root / ".ai" / "RULES.md"
    if not rules_path.exists():
        return "none"

    content = rules_path.read_text(errors="replace")
    rule_count = content.count("## Rule ")

    # Prefer the explicit marker in the generated/adapted RULES document. The
    # kit has no configs/naos_governance_profiles.yaml runtime source.
    marker = re.search(
        r"\*\*Profile\*\*:\s*`?governance-(quickstart|lite|standard|assured)`?",
        content,
        re.IGNORECASE,
    )
    if marker:
        return marker.group(1).lower()

    # Heuristic: count rules to estimate tier
    if rule_count >= 15:
        # Check if all rules are blocking (assured) or some advisory (standard)
        if "all blocking" in content.lower() or "assured" in content.lower():
            return "assured"
        return "standard"
    elif rule_count >= 7:
        return "lite"
    elif rule_count >= 3:
        return "quickstart"
    return "lite"  # Default if RULES.md exists but heuristic unclear


# ─── Tier Expectations ────────────────────────────────────────────────────────

# What each tier is EXPECTED to have. Audit only checks for tier-appropriate files.
TIER_EXPECTATIONS = {
    "quickstart": {
        "min_rules": 3,
        "needs_pre_commit": True,
        "needs_instruction_triple": False,  # Only CLAUDE.md
        "min_instructions": 0,
        "needs_task_registry": False,
        "needs_dashboard": False,
        "needs_traceability": False,
        "needs_specs": False,
        "needs_makefile": False,
        "needs_scripts": False,
        "needs_validators": False,
        "needs_function_index": False,
        "needs_truth_table": False,
        "needs_semantic_config": False,
        "needs_session_mgmt": False,
        "needs_agents": False,
    },
    "lite": {
        "min_rules": 7,
        "needs_pre_commit": True,
        "needs_instruction_triple": True,
        "min_instructions": 2,
        "needs_task_registry": True,
        "needs_dashboard": False,  # Optional for Lite
        "needs_traceability": False,
        "needs_specs": True,
        "needs_makefile": True,
        "needs_scripts": False,  # Lite uses Makefile but may not have all scripts
        "needs_validators": False,
        "needs_function_index": False,
        "needs_truth_table": False,
        "needs_semantic_config": False,
        "needs_session_mgmt": False,
        "needs_agents": True,
    },
    "standard": {
        "min_rules": 15,
        "needs_pre_commit": True,
        "needs_instruction_triple": True,
        "min_instructions": 5,
        "needs_task_registry": True,
        "needs_dashboard": True,
        "needs_traceability": True,
        "needs_specs": True,
        "needs_makefile": True,
        "needs_scripts": True,
        "needs_validators": True,
        "needs_function_index": True,
        "needs_truth_table": False,
        "needs_semantic_config": True,
        "needs_session_mgmt": True,
        "needs_agents": True,
    },
    "assured": {
        "min_rules": 15,
        "needs_pre_commit": True,
        "needs_instruction_triple": True,
        "min_instructions": 5,
        "needs_task_registry": True,
        "needs_dashboard": True,
        "needs_traceability": True,
        "needs_specs": True,
        "needs_makefile": True,
        "needs_scripts": True,
        "needs_validators": True,
        "needs_function_index": True,
        "needs_truth_table": True,
        "needs_semantic_config": True,
        "needs_session_mgmt": True,
        "needs_agents": True,
    },
}


# ─── Check Definitions ───────────────────────────────────────────────────────

def check_rules_enforcement(root: Path, expect: dict) -> dict:
    """Category 1: Rules & Enforcement."""
    checks = []

    rules_path = root / ".ai" / "RULES.md"
    checks.append({"name": "RULES.md exists", "pass": rules_path.exists()})

    if rules_path.exists():
        content = rules_path.read_text(errors="replace")
        rule_count = content.count("## Rule ")
        min_r = expect["min_rules"]
        checks.append({
            "name": f"RULES.md has >={min_r} rules ({rule_count} found)",
            "pass": rule_count >= min_r,
        })
    else:
        checks.append({"name": f"RULES.md has >={expect['min_rules']} rules", "pass": False})

    if expect["needs_pre_commit"]:
        pre_commit = root / ".githooks" / "pre-commit"
        pre_commit_alt = root / ".git" / "hooks" / "pre-commit"
        checks.append({
            "name": "Pre-commit hook exists",
            "pass": pre_commit.exists() or pre_commit_alt.exists(),
        })

    return {"category": "Rules & Enforcement", "checks": checks}


def check_instruction_surface(root: Path, expect: dict) -> dict:
    """Category 2: Instruction Surface (multi-tool)."""
    checks = []

    # CLAUDE.md is always expected
    checks.append({"name": "CLAUDE.md exists", "pass": (root / "CLAUDE.md").exists()})

    if expect["needs_instruction_triple"]:
        checks.append({
            "name": "copilot-instructions.md exists",
            "pass": (root / ".github" / "copilot-instructions.md").exists(),
        })
        checks.append({
            "name": ".cursorrules exists",
            "pass": (root / ".cursorrules").exists(),
        })

    min_inst = expect["min_instructions"]
    if min_inst > 0:
        instructions_dir = root / ".github" / "instructions"
        count = len(list(instructions_dir.glob("*.md"))) if instructions_dir.exists() else 0
        checks.append({
            "name": f"Scoped instructions (>={min_inst}, found {count})",
            "pass": count >= min_inst,
        })

    return {"category": "Instruction Surface", "checks": checks}


def check_governance_artifacts(root: Path, expect: dict) -> dict:
    """Category 3: Governance Artifacts (tier-scaled)."""
    checks = []
    naos_root = root / "naos"

    if expect["needs_task_registry"]:
        checks.append({
            "name": "TASK_REGISTRY.yaml exists",
            "pass": (naos_root / "TASK_REGISTRY.yaml").exists(),
        })

    if expect["needs_dashboard"]:
        checks.append({
            "name": "DASHBOARD.md exists",
            "pass": (naos_root / "DASHBOARD.md").exists(),
        })

    if expect["needs_traceability"]:
        checks.append({
            "name": "TRACEABILITY_MATRIX.md exists",
            "pass": (naos_root / "TRACEABILITY_MATRIX.md").exists(),
        })

    # Active task directory (useful from Lite upward)
    if expect["needs_task_registry"]:
        checks.append({
            "name": "Active task card directory exists",
            "pass": (naos_root / "active").is_dir(),
        })

    if expect["needs_specs"]:
        specs_dir = root / "specs"
        checks.append({"name": "specs/ directory exists", "pass": specs_dir.is_dir()})
        if specs_dir.is_dir():
            spec_count = len(list(specs_dir.glob("*.md")))
            checks.append({
                "name": f"Spec files present ({spec_count} found)",
                "pass": spec_count >= 2,
            })

    # If no checks were added (quickstart), add a pass-through
    if not checks:
        checks.append({"name": "No governance artifacts required for this tier", "pass": True})

    return {"category": "Governance Artifacts", "checks": checks}


def check_automation_pipeline(root: Path, expect: dict) -> dict:
    """Category 4: Automation Pipeline (tier-scaled)."""
    checks = []

    if expect["needs_makefile"]:
        has_makefile = (root / "Makefile.naos").exists()
        if not has_makefile and (root / "Makefile").exists():
            content = (root / "Makefile").read_text(errors="replace")
            has_makefile = "gov-refresh" in content
        checks.append({"name": "Makefile with governance targets", "pass": has_makefile})

    executing_tool_root = Path(__file__).resolve().parent
    tool_root = (
        executing_tool_root
        if executing_tool_root.parent == root.resolve()
        else next(
            (
                candidate
                for candidate in (root / "scripts", root / "naos_tools")
                if candidate.is_dir()
            ),
            root / "scripts",
        )
    )

    if expect["needs_scripts"]:
        has_scripts = tool_root.is_dir() and len(list(tool_root.glob("naos_*.py"))) >= 1
        checks.append({"name": "Governance scripts present", "pass": has_scripts})

    if expect["needs_validators"]:
        validators_dir = tool_root / "validators" if tool_root.exists() else None
        checks.append({
            "name": "Validator scripts present",
            "pass": validators_dir is not None and validators_dir.is_dir(),
        })

    if expect["needs_function_index"]:
        func_index = root / "naos" / "inventory" / "FUNCTION_INDEX.yaml"
        checks.append({"name": "FUNCTION_INDEX.yaml exists", "pass": func_index.exists()})

    if expect["needs_truth_table"]:
        truth_table = root / "naos" / "governance" / "GOVERNANCE_TRUTH_TABLE.md"
        checks.append({"name": "GOVERNANCE_TRUTH_TABLE.md exists", "pass": truth_table.exists()})

    if expect["needs_semantic_config"]:
        semantic = root / "configs" / "semantic_allowlist.yaml"
        thresholds = root / "configs" / "thresholds.yaml"
        checks.append({
            "name": "Semantic quality config exists",
            "pass": semantic.exists() or thresholds.exists(),
        })

    if not checks:
        checks.append({"name": "No automation required for this tier", "pass": True})

    return {"category": "Automation Pipeline", "checks": checks}


def check_session_management(root: Path, expect: dict) -> dict:
    """Category 5: Session Management (tier-scaled)."""
    checks = []

    if expect["needs_session_mgmt"]:
        ctx = root / ".github" / "instructions" / "context-pressure.instructions.md"
        checks.append({"name": "Context pressure instruction", "pass": ctx.exists()})

        session = root / ".github" / "instructions" / "session-management.instructions.md"
        checks.append({"name": "Session management instruction", "pass": session.exists()})

        skill = root / ".github" / "skills" / "cognitive-checkpoint" / "SKILL.md"
        checks.append({"name": "Cognitive checkpoint skill", "pass": skill.exists()})

    if expect["needs_agents"]:
        agents_dir = root / ".github" / "agents"
        checks.append({
            "name": "Agents directory with AGENTS.md",
            "pass": agents_dir.is_dir() and (agents_dir / "AGENTS.md").exists(),
        })

    if not checks:
        checks.append({"name": "No session management required for this tier", "pass": True})

    return {"category": "Session Management", "checks": checks}


# ─── Scoring ──────────────────────────────────────────────────────────────────

def score_category(result: dict) -> float:
    """Normalize category to 0-10 scale."""
    checks = result["checks"]
    if not checks:
        return 0.0
    passed = sum(1 for c in checks if c["pass"])
    return round((passed / len(checks)) * 10, 1)


def run_audit(root: Path, tier: str, category_filter: str | None = None) -> dict:
    """Run tier-appropriate checks and compute scores."""
    expect = TIER_EXPECTATIONS.get(tier, TIER_EXPECTATIONS["lite"])

    check_fns = [
        check_rules_enforcement,
        check_instruction_surface,
        check_governance_artifacts,
        check_automation_pipeline,
        check_session_management,
    ]

    results = []
    for check_fn in check_fns:
        result = check_fn(root, expect)
        if category_filter and category_filter.lower() not in result["category"].lower():
            continue
        result["score"] = score_category(result)
        results.append(result)

    total_passed = sum(sum(1 for c in r["checks"] if c["pass"]) for r in results)
    total_checks = sum(len(r["checks"]) for r in results)
    overall = round((total_passed / total_checks) * 10, 1) if total_checks > 0 else 0.0

    return {
        "project_root": str(root),
        "detected_tier": tier,
        "categories": results,
        "summary": {
            "total_checks": total_checks,
            "passed": total_passed,
            "failed": total_checks - total_passed,
            "overall_score": overall,
        },
    }


# ─── Display ──────────────────────────────────────────────────────────────────

def display_text(audit: dict) -> None:
    """Human-readable output."""
    tier = audit["detected_tier"]
    print(f"\n  NAOS Governance Audit (tier: {tier})")
    print(f"  Project: {audit['project_root']}")
    print(f"  Note: Checks are scaled to your tier. A 10/10 on {tier} means")
    print(f"        'fully configured for {tier}' — not 'equivalent to assured.'")
    print("  " + "-" * 60)

    for cat in audit["categories"]:
        score = cat["score"]
        bar = "#" * int(score) + "." * (10 - int(score))
        emoji = "OK" if score >= 7 else ("!!" if score >= 4 else "XX")
        print(f"\n  [{emoji}] {cat['category']:30s} [{bar}] {score}/10")
        for check in cat["checks"]:
            status = "  ok" if check["pass"] else "FAIL"
            print(f"       {status}  {check['name']}")

    s = audit["summary"]
    print("\n  " + "-" * 60)
    bar = "#" * int(s["overall_score"]) + "." * (10 - int(s["overall_score"]))
    print(f"  OVERALL  [{bar}] {s['overall_score']}/10  ({s['passed']}/{s['total_checks']} checks)")

    if s["overall_score"] < 5:
        print(f"\n  Recommendation: Review failed checks above. Your {tier} tier has gaps.")
    elif s["overall_score"] < 8:
        print(f"\n  Recommendation: Address remaining gaps for a complete {tier} setup.")
    else:
        print(f"\n  Governance posture for {tier}: STRONG.")

    if tier in ("quickstart", "lite"):
        next_tier = "lite" if tier == "quickstart" else "standard"
        print(
            "  Profile comparison: "
            f"`naos upgrade . --tier {next_tier} --dry-run` "
            "(plan only; persist an external plan and use separate digest-bound apply)."
        )
    print()
    print("  Note: Costs and compliance baselines are project-specific.")
    print("  Run `make -f Makefile.naos gov-refresh` then autoresearch to establish YOUR baseline.")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="NAOS Governance Completeness Audit")
    parser.add_argument("--tier", choices=["quickstart", "lite", "standard", "assured"],
                        help="Override tier detection (default: auto-detect from RULES.md)")
    parser.add_argument("--category", help="Filter to a single category (e.g., 'rules', 'session')")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--root", help="Project root (default: auto-detect)")
    args = parser.parse_args()

    root = Path(args.root) if args.root else find_project_root()
    tier = args.tier if args.tier else detect_tier(root)
    audit = run_audit(root, tier, args.category)

    if args.json:
        print(json.dumps(audit, indent=2))
    else:
        display_text(audit)

    sys.exit(0 if audit["summary"]["overall_score"] >= 7.0 else 1)


if __name__ == "__main__":
    main()
