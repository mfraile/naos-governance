#!/usr/bin/env python3
"""Generate reviewed declaration vocabulary; never read adopter scan findings.

Admission selectors are finite public contracts, not all Python literals.
The generator's output and selector changes require normal source review.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

import yaml

SCHEMA = "naos.secret_public_literals.v1"
QUOTED = re.compile(r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"")
NEW_MEMBERS = {"scripts/naos_report_composition.py",
               "schemas/naos/report_source_reference.schema.json",
               "schemas/naos/capability_maturity_collection_witness.schema.json",
               "public_tests/test_report_composition_contract.py","public_tests/test_secret_task_claim_labels_contract.py","scripts/naos_secret_managed_operands.py",
               "public_tests/test_secret_managed_inventory_contract.py","scripts/naos_secret_public_literals.py", "scripts/naos_secret_public_literals.json",
               "scripts/generate_naos_secret_public_literals.py", "schemas/naos/secret_public_literals.schema.json",
               "public_tests/test_secret_reference_operands_contract.py",
               "public_tests/test_secret_finding_feedback_contract.py",
               "public_tests/test_report_scoped_finding_ids_contract.py",
               "upgrade_contract/windows_planning.py",
               "upgrade_contract/windows_runtime_directories.py"}

# Reviewed noncredential parser grammars. This list selects named declarations,
# not values harvested from reports, matching filenames, or arbitrary AST nodes.
REGEX_DECLARATIONS = {
    "scripts/naos_secret_ri_windows_operands.py": {"BOOTSTRAP", "RUNTIME", "_REVIEWER_ID_PATTERN", "_SUPPORTED_TUPLE"},
    "scripts/naos_secret_managed_operands.py": {"_JSON_PRIMITIVE", "_PUBLIC_LINK_FIELDS", "_MANAGED_ROOT", "_WINDOWS_ROOT", "_PORTABLE_ROOT", "_WINDOWS_COMPONENT_RESERVED", "_RI_TRANSACTIONS", "_RI_WINDOWS_BOOTSTRAP", "_RI_LOCK", "_RI_SUPPORTED_TUPLES"},
    "scripts/naos_secret_public_literals.py": {"_TASK_PUBLIC_ID"},
    "scripts/naos_policy.py": {"OPERATOR_ID_PATTERN"},
    "scripts/naos_ac_completion_evidence.py": {"RECORD_ID_RE", "OID_RE"},
    "scripts/naos_model_provider_policy.py": {"SECRET_RE"},
    "scripts/naos_detect_spec_drift.py": {"_AC_SCEN_TOKEN_RE", "_FREE_FR_TOKEN_RE", "_FREE_AC_SCEN_TOKEN_RE"},
    "scripts/naos_local_context_index.py": {"SPEC_REF_RE"},
    "scripts/naos_ai_component_inventory.py": {"SECRET_LIKE_RE"},
    "scripts/naos_ai_surface_budget.py": {"FRESH_AUDIT_EVENT_RE"},
    "scripts/naos_audit_log.py": {"EVENT_ID_PATTERN", "PUBLIC_EVENT_ID_PATTERN", "PUBLIC_EVENT_NONCE_PATTERN", "PUBLIC_EVENT_ID_SCHEME"},
    "scripts/naos_code_quality_audit.py": {"_TASK_HEADER_RE"},
    "scripts/naos_hygiene_common.py": {"QUOTED_SECRET_LITERAL", "BARE_ENV_REFERENCE", "DOTENV_ASSIGNMENT", "SECRET_NAME_END"},
    "scripts/naos_module_header_traceability.py": {"REQ_TOKEN_RE", "SPEC_REF_RE"},
    "scripts/naos_opencode_config_hygiene.py": {"SECRET_RE"},
    "scripts/naos_package_reality.py": {"INSTALL_COMMAND_RE"},
    "scripts/naos_readiness.py": {"MCP_NAMESPACE_PATTERN"},
    "scripts/naos_secret_patterns.py": {"_SECRET_FIELD", "_SECRET_FIELD_NAME", "SECRET_CONTENT_PATTERNS"},
    "scripts/naos_task_lifecycle.py": {"TASK_ID_TEXT_PATTERN", "TASK_ID_FULL_PATTERN", "SPEC_REF_PATTERN", "PATH_REF_PATTERN"},
    "scripts/naos_validate_roadmap_crosswalk.py": {"ID_PATTERN"},
    "upgrade_contract/windows_handles.py": {"_RESERVED"},
    "scripts/spec_header.py": {"REQ_HEADER_RE", "REQ_STATUS_RE", "FR_TOKEN_RE"},
    "scripts/validators/validate_capability_contracts.py": {"MAKE_TARGET_RE"},
    "scripts/validators/validate_implementation_reality.py": {"SLASH_COMMAND_RE", "AGENT_RE", "MAKE_TARGET_RE", "SCRIPT_RE", "TEMPLATE_RE"},
    "scripts/validators/validate_skills.py": {"WHEN_TO_INVOKE_HEADING"},
    "scripts/validators/validate_traceability_headers.py": {"HEADER_RE", "TASK_RE"},
    "scripts/workflows/generate_naos_dashboard.py": {"REQ_HEADER_RE"},
}

# Reviewed public code templates. Only syntactic quote contents of these named
# assignments are admitted; their instantiated runtime outputs are NOT admitted.
CODE_TEMPLATES = {
    "scripts/naos_policy.py": {"candidate_name"},
    "scripts/naos_code_quality_audit.py": {"arch_id"},
    "scripts/naos_hygiene_common.py": set(),
    "scripts/naos_adoption_common.py": {"config_id", "state_root"},
    "scripts/naos_local_context_index.py": {"temp_db_path", "artifact_id", "chunk_id"},
    "scripts/naos_setup_recommendations.py": set(),
    "scripts/naos_task_claims.py": {"temp_path"},
}

# Finite reviewed parser-call and public-formatting declarations. A selected
# parser call contributes its first literal grammar argument; a selected
# formatter contributes source template syntax, never an instantiated value.
FUNCTION_REGEX = {
    "scripts/naos_secret_managed_operands.py": {"_legacy_operands", "_windows_operands", "_hex", "_control_record", "_ri_record"},
    "scripts/naos_ac_completion_evidence.py": {"command_path_operands"},
    "scripts/naos_adoption_common.py": {"makefile_targets"},
    "scripts/naos_code_quality_audit.py": {"_parse_implements_from_file"},
    "scripts/naos_governance_bypass_posture.py": {"_gitlab_sources"},
    "scripts/naos_hygiene_common.py": {"_local_document_reference"},
    "scripts/naos_opencode_config_hygiene.py": {"text_model_provider_refs"},
    "scripts/naos_plan_coherence.py": {"_git_name_status_paths"},
    "scripts/spec_header.py": {"section_for_anchor", "architecture_component_sections"},
    "scripts/validators/validate_capability_contracts.py": {"load_cli_commands"},
    "scripts/validators/validate_project_coherence.py": {"check_no_draft_files"},
    "scripts/validators/validate_task_coherence.py": {"validate_execution_spec"},
    "scripts/workflows/generate_naos_dashboard.py": {"parse_task_matrix"},
}
FUNCTION_FORMATTERS = {
    "scripts/naos_adoption_common.py": {"_fallback_scan_mcp_configs", "build_requirements_reconstruct"},
    "scripts/naos_ai_surface_budget.py": {"profile_raw_hash_declarations"},
    "scripts/naos_code_quality_audit.py": {"_log_semantic_warning"},
    "scripts/naos_hygiene_common.py": {"_scope_findings", "check_duplicate_function_hygiene"},
    "scripts/naos_local_context_index.py": {"temp_db_path", "build_artifact_records", "chunk_id_for"},
    "scripts/naos_overlay_coexistence.py": {"target_snapshot"},
    "scripts/naos_setup_recommendations.py": {"validate_catalog"},
    "scripts/naos_task_context_pack.py": {"collect_spec_refs"},
    "scripts/naos_task_lifecycle.py": {"portable_history_references", "complete_task"},
    "scripts/validators/validate_project_coherence.py": {"print_header"},
}
DICT_DECLARATIONS = {
    "scripts/naos_ai_precommit.py": {("rebuild_embeddings", "status")},
    "scripts/naos_sarif_export.py": {("build_sarif", "$schema")},
    "scripts/naos_package_reality.py": {("pypi_package_metadata", "User-Agent")},
    "upgrade_contract/transaction.py": {("_journal_value", "schema")},
    "scripts/naos_self_check_dependency_resolution.py": {("capture_dependency_inputs", "schema")},
    "scripts/validators/validate_profile_generated_surfaces.py": {("main", "schema")},
}
CALL_DECLARATIONS = {
    "scripts/naos_governance_bypass_posture.py": {("bypass_commit_messages", "run_git")},
    "scripts/naos_mcp_config_registry.py": {("review_mcp_descriptors", "projection.pop")},
    "scripts/naos_self_check_dependency_resolution.py": {("_collect_l3_gate_obligations", "_deny"), ("_validate_raw_aggregate", "finding.get")},
}
REGEX_DECLARATIONS.update({
    "scripts/naos_pr_risk_classification.py": {"DEFAULT_RULES.secret_like_patterns"},
    "scripts/validators/validate_architecture_coherence.py": {"HARDCODE_PATTERNS"},
    "scripts/validators/validate_governed_debug_escalation.py": {"_RFC3339_DATETIME"},
    "scripts/validators/validate_secure_coding_control_register.py": {"VERSION_PATTERNS"},
    "scripts/workflows/sync_spec_statuses.py": {"COMPLETE_PATTERN"},
})
REGEX_DECLARATIONS["scripts/naos_module_header_traceability.py"].update({"req_patterns", "task_patterns", "spec_patterns"})
REGEX_DECLARATIONS["scripts/naos_hygiene_common.py"].add("reference_key")
REGEX_DECLARATIONS["scripts/naos_code_quality_audit.py"].add("_REQ_HEADER_RE")

def encoded_values(values):
    result = set()
    for value in values:
        if isinstance(value, str) and value and not any(ord(c) < 32 for c in value):
            result.add(value)
            result.add(json.dumps(value, ensure_ascii=True)[1:-1])
            result.add(json.dumps(value, ensure_ascii=False)[1:-1])
    return sorted(result)

def reviewed_constructor_groups(source, members, add):
    """Finite producer contracts, with fail-closed constructor-shape checks."""
    def tree(relative):
        return ast.parse(source(relative).read_text(encoding='utf-8'))
    def function(relative, name):
        matches = [n for n in tree(relative).body if isinstance(n, ast.FunctionDef) and n.name == name]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous constructor: " + relative + ":" + name)
        return matches[0]
    def require(node, expression):
        expected = ast.dump(ast.parse(expression, mode="eval").body)
        if not any(ast.dump(n) == expected for n in ast.walk(node)):
            raise ValueError("public constructor changed; review: " + expression)
    policy_source = "scripts/naos_policy.py"
    require(function(policy_source, "evidence_default_path"), "safe_policy_path(candidate, value, field=key)")
    require(function(policy_source, "evidence_default_path"), "str(policy.get('paths', {}).get(key) or key)")
    require(function(policy_source, "report_default_path"), "safe_policy_path(candidate, reports_dir, filename, field=filename_key)")
    require(function(policy_source, "report_output_path"), "safe_policy_path(candidate, reports_dir, filename, field=filename_key)")
    require(function(policy_source, "evidence_pack_output_path"), "safe_policy_path(candidate, evidence_dir, filename, field='evidence_pack_report')")
    require(function(policy_source, "evidence_pack_output_path"), "str(policy.get('paths', {}).get('evidence_dir') or 'evidence')")
    require(function(policy_source, "evidence_pack_output_path"), "str(policy.get('paths', {}).get('evidence_pack_report') or 'evidence_pack.json')")
    evidence_keys = set()
    for relative in members:
        if not relative.startswith("scripts/") or not relative.endswith(".py") or not source(relative).is_file():
            continue
        for node in ast.walk(tree(relative)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "evidence_default_path":
                if len(node.args) != 4 or not isinstance(node.args[3], ast.Constant) or type(node.args[3].value) is not str:
                    raise ValueError("nonfinite evidence_default_path selector: " + relative)
                evidence_keys.add(node.args[3].value)
    if not evidence_keys or "evidence_pack_report" in evidence_keys:
        raise ValueError("ambiguous evidence policy selectors")

    relative = "templates/structural-seeds/naos/ai_component_inventory_rules.yaml"
    rules = yaml.safe_load(source(relative).read_text(encoding='utf-8'))
    value = rules["field_sources"]["source_sha256"]
    if value != "sha256_of_the_raw_declaring_file_bytes":
        raise ValueError("public source hash description changed")
    add("literal", relative, "field_sources.source_sha256.public_description", {value})
    relative = "configs/secure_coding_control_register.yaml"
    register = yaml.safe_load(source(relative).read_text(encoding='utf-8'))
    if register.get("schema") != "naos.secure_coding_control_register.v1":
        raise ValueError("unexpected canonical standards register")
    standards = register["standards"]
    if not isinstance(standards, dict) or any(not isinstance(v, dict) or type(v.get("source")) is not str for v in standards.values()):
        raise ValueError("malformed canonical standards sources")
    add("literal", relative, "standards.*.source.reviewed_canonical_register", {v["source"] for v in standards.values()})
    require(tree("naos_init.py"), "preview_dir / 'naos' / 'secure_coding_control_register.yaml'")
    add("project_path", "naos_init.py", "secure_coding_control_register.destination", {"naos/secure_coding_control_register.yaml"})
    relative = "scripts/naos_self_check.py"
    operands = []
    for node in ast.walk(tree(relative)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "first_existing_dir":
            if len(node.args) != 1 or not isinstance(node.args[0], ast.List):
                raise ValueError("nonfinite first_existing_dir operands")
            operands.extend(node.args[0].elts)
    if len(operands) != 5:
        raise ValueError("self-check directory selectors changed")
    def path_operand(node):
        if isinstance(node, ast.Name) and node.id == "root": return "project_path", ""
        if isinstance(node, ast.Call) and ast.unparse(node) == "kit_root()": return "kit_path", ""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            kind, prefix = path_operand(node.left)
            suffix = "naos" if isinstance(node.right, ast.Name) and node.right.id == "naos_root" else ast.literal_eval(node.right)
            if type(suffix) is not str or not suffix or "/" in suffix or suffix in {".", ".."}:
                raise ValueError("nonfinite self-check directory component")
            return kind, (prefix + "/" + suffix).lstrip("/")
        raise ValueError("unknown self-check directory operand")
    selected_operands = list(map(path_operand, operands))
    if selected_operands != [
        ("project_path", "naos/capabilities"),
        ("kit_path", "capabilities"),
        ("project_path", ".github/profiles"),
        ("project_path", "templates/profiles"),
        ("kit_path", "templates/profiles"),
    ]:
        raise ValueError("self-check directory selector contracts changed")
    for kind in ("project_path", "kit_path"):
        add(kind, relative, "first_existing_dir.actual_finite_operands", {v for k,v in selected_operands if k == kind})
    require(tree("scripts/naos_policy_overrides.py"), "root / naos_root / 'policy_overrides.d'")
    add("project_path", "scripts/naos_policy_overrides.py", "main.default_override_directory", {"naos/policy_overrides.d"})

    exporter = function("scripts/naos_evidence_export.py", "collect_external_references")
    require(exporter, "f'{location}.{key}'")
    require(exporter, "f'{location}[{index}]'")
    require(exporter, "enumerate(data)")
    index_tree = function("scripts/naos_local_context_index.py", "build_report")
    pairs = [(key, value) for node in ast.walk(index_tree) if isinstance(node, ast.Dict) for key, value in zip(node.keys, node.values) if isinstance(key, ast.Constant) and key.value == "artifact_chunks"]
    if len(pairs) != 1 or ast.unparse(pairs[0][1]) != "chunks[:200]":
        raise ValueError("local-context index collection cap changed")
    query_tree = tree("scripts/naos_local_context_query.py")
    limits = [ast.literal_eval(n.value) for n in query_tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MAX_LIMIT" for t in n.targets)]
    if limits != [50]:
        raise ValueError("local-context query cap changed; review finite admission")
    require(function("scripts/naos_local_context_query.py", "build_report"), "min(max(int(args.limit or DEFAULT_LIMIT), 1), MAX_LIMIT)")
    require(function("scripts/naos_local_context_query.py", "query_index"), "results[:limit]")
    require(function("scripts/naos_local_context_query.py", "build_report"), "query_index(args=args, index_data=index_data, index_report=index_report, sqlite_path=sqlite_path, limit=limit)")
    query_report = function("scripts/naos_local_context_query.py", "build_report")
    result_fields = [value for n in ast.walk(query_report) if isinstance(n, ast.Dict) for key,value in zip(n.keys,n.values) if isinstance(key, ast.Constant) and key.value == "results" and isinstance(value, ast.Name)]
    if len(result_fields) != 1 or result_fields[0].id != "results":
        raise ValueError("local-context query result collection changed")
    for name, collection, cap in (("local_context_index", "artifact_chunks", 200), ("local_context_query", "results", limits[0])):
        schema = json.loads(source("schemas/naos/" + name + ".schema.json").read_text(encoding='utf-8'))
        if schema["properties"]["schema"]["const"] != "naos." + name + ".v1":
            raise ValueError("local-context report schema identity changed")
        collection_schema = schema["properties"].get(collection)
        if collection_schema is None:
            # Index v1 intentionally permits this producer field as an additional property.
            if name != "local_context_index" or schema.get("additionalProperties") is not True:
                raise ValueError("local-context undeclared collection rejected by schema")
        elif collection_schema.get("type") != "array":
            raise ValueError("local-context collection schema changed")
        producer = function("scripts/naos_" + name + ".py", "build_artifact_records" if name == "local_context_index" else "result_record")
        if not any(isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "bounded_excerpt" for k in n.keys) for n in ast.walk(producer)):
            raise ValueError("bounded excerpt field missing")
        add("literal", "scripts/naos_evidence_export.py", "collect_external_references." + name + ".finite_locations", {"$." + collection + "[" + str(i) + "].bounded_excerpt" for i in range(cap)})
    relative = "scripts/naos_spec_assembly_worksheet.py"
    require(function(relative, "finding"), "f'spec_assembly_worksheet.{status}.{path or category}'")
    branches = [n for n in ast.walk(tree(relative)) if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and ast.unparse(n.test.left) == "rel_path" and len(n.test.comparators) == 1 and isinstance(n.test.comparators[0], ast.Set) and any(isinstance(x, ast.Constant) and x.value == "non_applicability_decision_needed" for statement in n.body for x in ast.walk(statement))]
    if len(branches) != 1:
        raise ValueError("non-applicability finite branch changed")
    files = ast.literal_eval(branches[0].test.comparators[0])
    if files != {"05-api.md", "06-acceptance.md", "07-cost-analysis.md", "08-market-analysis.md", "09-integration-contract.md"}:
        raise ValueError("non-applicability finite operands changed")
    add("literal", relative, "finding.non_applicability_decision_needed.finite_specs", {"spec_assembly_worksheet.non_applicability_decision_needed.specs/" + f for f in files})
    relative = "templates/structural-seeds/naos/gatekeepers.yaml"
    gates = yaml.safe_load(source(relative).read_text(encoding='utf-8'))["gates"]
    gate_paths = set()
    for gate in gates:
        for field in ("required_evidence", "outputs"):
            values = gate.get(field, [])
            if type(values) is not list or any(type(v) is not str for v in values):
                raise ValueError("malformed gate path declaration")
            for value in values:
                if value.startswith("naos/"):
                    parts = value.rstrip("/").split("/")
                    if any(part in {"", ".", ".."} for part in parts) or "\\" in value or ":" in value:
                        raise ValueError("unsafe gate path declaration")
                    gate_paths.add(value.rstrip("/"))
    add("project_path", relative, "gates.required_evidence_and_outputs.finite_declared_naos_operands", gate_paths)
    # Source finding identifiers are admitted only for finite shipped producers.
    # Dynamic EC report ordinals require separate linked structural proof.
    relative = "autoresearch/graders/static.py"
    static_tree = tree(relative)
    dimensions = [ast.literal_eval(n.value) for n in static_tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "FUTURE_BEHAVIORAL_DIMENSIONS" for t in n.targets)]
    if len(dimensions) != 1 or type(dimensions[0]) is not list or any(type(v) is not str for v in dimensions[0]):
        raise ValueError("ambiguous future behavioral dimensions")
    future = set(dimensions[0])
    loops = [n for n in ast.walk(static_tree) if isinstance(n, ast.For) and ast.unparse(n.target) == "dimension_id" and ast.unparse(n.iter) == "FUTURE_BEHAVIORAL_DIMENSIONS"]
    if len(loops) != 1:
        raise ValueError("static unsupported dimension loop changed")
    require(loops[0], "f'STATICGRADER_UNSUPPORTED_{dimension_id}'")
    require(function("scripts/naos_evidence_contracts.py", "_classify_one"), 'f"{check_id}/{item[\'id\']}"')
    require(function("scripts/naos_self_check.py", "run_json_script"), "Path(script).stem")
    for script in ("naos_static_grader.py", "naos_grader_assessment.py"):
        require(function("scripts/naos_self_check.py", "selected_script_checks"), repr((script, ["--mode", "assess"] if script == "naos_grader_assessment.py" else [])))
    assessment = function("scripts/naos_grader_assessment.py", "build_report")
    require(assessment, "[item for item in static_report.get('findings') or [] if isinstance(item, dict)]")
    require(assessment, "static_findings + findings")
    require(assessment, "deterministic_findings + advisory_findings")
    add("literal", relative, "finite_future_dimension_ids.self_check_namespaces", {name + "/STATICGRADER_UNSUPPORTED_" + dimension for name in ("naos_static_grader", "naos_grader_assessment") for dimension in future})

    controls = function("scripts/naos_secure_coding_controls.py", "build_report")
    require(controls, "f'stale-evidence:{detector_id}' if result['state'] == 'stale' else f'invalid-evidence:{detector_id}'")
    require(function("scripts/secure_coding_reporting/model.py", "build_report"), 'f"p2:{item.get(\'id\') or index}"')
    relative = "templates/structural-seeds/naos/secure_coding_control_evidence_routes.yaml"
    route_rows = yaml.safe_load(source(relative).read_text(encoding='utf-8'))["routes"]
    register = yaml.safe_load(source("configs/secure_coding_control_register.yaml").read_text(encoding='utf-8'))
    detectors = {row["detector_id"] for row in route_rows}
    if any(type(v) is not str for v in detectors) or not detectors <= set(register["detector_catalog"]):
        raise ValueError("unknown shipped secure-coding detector routes")
    add("literal", relative, "finite_canonical_detector_routes.invalid_or_stale_evidence_and_p2_projection", {prefix + status + ":" + detector for prefix in ("", "p2:") for status in ("invalid-evidence", "stale-evidence") for detector in detectors})

    require(function("scripts/naos_ci_readiness.py", "run_chain"), "safe_policy_path(state_root, policy['paths']['reports_dir'], 'ci_readiness.json', field='ci_readiness')")
    defaults = yaml.safe_load(source("policies/default_policy.yaml").read_text(encoding='utf-8'))["paths"]
    add("project_path", "scripts/naos_ci_readiness.py", "run_chain.default_readiness_receipt", {"naos/" + defaults["reports_dir"] + "/ci_readiness.json"})
    overrides = function("scripts/naos_policy_overrides.py", "collect_override_files")
    scope_tests = [n.test for n in ast.walk(overrides) if isinstance(n, ast.If) and ast.unparse(n.test) == "path.name in {'teams', 'operators'}"]
    if len(scope_tests) != 1:
        raise ValueError("override scope directories changed")
    scope_names = ast.literal_eval(scope_tests[0].comparators[0])
    add("project_path", "scripts/naos_policy_overrides.py", "collect_override_files.finite_scope_directory_names", {"naos/policy_overrides.d/" + v for v in scope_names})

    # Exact canonical template requirement headings through the actual task
    # reference constructor; arbitrary adopter requirements remain unknown.
    require(function("scripts/naos_task_context_pack.py", "collect_spec_refs"), "f'specs/03-requirements.md#{str(requirement).strip().lower()}'")
    relative = "templates/spec-kit/specs/03-requirements.md"
    headings = re.findall(r"^### ((?:FR|NFR)-[0-9]+):[^\n]+\{#(?:fr|nfr)-[a-z0-9-]+\}\s*$", source(relative).read_text(encoding='utf-8'), re.M)
    if not headings or len(headings) != len(set(headings)):
        raise ValueError("ambiguous canonical requirement headings")
    add("literal", relative, "canonical_requirement_heading_ids.task_context_reference_constructor", {"specs/03-requirements.md#" + v.lower() for v in headings})
    return evidence_keys

def build(source_root: Path, overlay_root: Path | None = None):
    groups = []
    def source(relative):
        overlay = overlay_root / relative if overlay_root else None
        return overlay if overlay is not None and overlay.is_file() else source_root / relative
    def add(kind, relative, selector, values):
        values = encoded_values(values) if kind == "literal" else sorted(set(values))
        if not values:
            return
        component = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode()
        groups.append({"kind": kind, "source": relative, "selector": selector,
                       "component_sha256": hashlib.sha256(component).hexdigest(), "values": values})
    declaration = json.loads(source("configs/source_modes.json").read_text(encoding='utf-8'))
    members = sorted({row["source"] for row in declaration["items"]} | NEW_MEMBERS)
    add("kit_path", "configs/source_modes.json", "reviewed_member_paths_and_new_scanner_members", members)
    # Actual installer operands: schema/docs are finite copy lists; scripts
    # are top-level files plus workflows, with the installer's exclusions.
    installer = ast.parse(source("naos_init.py").read_text(encoding='utf-8'))
    def declared_set(name):
        matches = [node.value for node in ast.walk(installer) if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous installer declaration: " + name)
        value = ast.literal_eval(matches[0])
        if type(value) is not set or any(type(item) is not str for item in value):
            raise ValueError("malformed installer declaration: " + name)
        return value
    excluded_scripts = set()
    for node in ast.walk(installer):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and ast.unparse(node.test.left) == "script_file.name"
                and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.In)
                and isinstance(node.test.comparators[0], ast.Set)
                and len(node.body) == 1 and isinstance(node.body[0], ast.Continue)):
            excluded_scripts.update(ast.literal_eval(node.test.comparators[0]))
    if not excluded_scripts:
        raise ValueError("installer exclusion declaration unavailable")
    project_paths = {"schemas/naos/" + name for name in declared_set("adopter_schema_names")}
    project_paths.update("docs/" + name for name in declared_set("evidence_docs"))
    project_paths.add("schemas/team_config.schema.yaml")
    project_paths.add("scripts/naos_windows_handles.py")
    for name in members:
        parts = name.split("/")
        if (len(parts) == 2 and parts[0] == "scripts" and parts[-1] not in excluded_scripts
                or len(parts) == 3 and parts[:2] == ["scripts", "workflows"]):
            project_paths.add(name)
    for name in members:
        if name.startswith("capabilities/") and len(name.split("/")) == 2 and name.endswith(".yaml"):
            project_paths.add("naos/" + name)
        if name.startswith("autoresearch/"):
            project_paths.add(".github/" + name)
        if name.startswith("task_battery/") and len(name.split("/")) == 2 and not name.endswith("/d4_grader_scenarios.yaml"):
            project_paths.add(".github/autoresearch/" + name)
        if name.startswith("templates/structural-seeds/") and name != "templates/structural-seeds/naos/repository_intelligence_rules.yaml":
            project_paths.add(name.removeprefix("templates/structural-seeds/"))
        if name.startswith("templates/spec-kit/specs/"):
            leaf = name.removeprefix("templates/spec-kit/specs/")
            project_paths.update({"specs/" + leaf, "naos/spec_templates/spec-kit/specs/" + leaf})
        if name.startswith("templates/instincts/"):
            project_paths.add(".github/instincts/" + name.removeprefix("templates/instincts/"))
        if name.startswith("templates/skills/") and name.endswith("/SKILL.md"):
            base = Path(name).parent.name
            public_name = "naos-portable-" + re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
            project_paths.update({".github/skills/" + base + "/SKILL.md", ".agents/skills/" + public_name + "/SKILL.md",
                                  ".agents/skills/" + public_name + "/agents/openai.yaml", ".claude/commands/" + public_name + ".md"})
    add("project_path", "naos_init.py", "adopter_schema_names_evidence_docs_and_reviewed_copy_loops", project_paths)
    # Exact shipped default hook operand; custom Git hook paths remain unknown.
    posture = ast.parse(source("scripts/naos_governance_bypass_posture.py").read_text(encoding='utf-8'))
    hook_functions = [node for node in posture.body if isinstance(node, ast.FunctionDef)
                      and node.name == "local_hook_posture"]
    if len(hook_functions) != 1:
        raise ValueError("missing default hook posture declaration")
    hook_assignments = {node.targets[0].id: node.value for node in hook_functions[0].body
                        if isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name)}
    expected = ast.literal_eval(hook_assignments["expected"])
    if (expected != ".githooks" or ast.unparse(hook_assignments["hook_file"])
            != "root / expected / 'pre-commit'"):
        raise ValueError("default hook operand changed; review declaration")
    add("project_path", "scripts/naos_governance_bypass_posture.py",
        "local_hook_posture.default_pre_commit_hook_operand", {expected + "/pre-commit"})
    add("literal", "naos_init.py", "declared_project_qualified_public_skill_identity",
        {"project:" + value for value in project_paths if value.startswith(".github/skills/") and value.endswith("/SKILL.md")})
    claim_tree = ast.parse(source("scripts/naos_validate_claims.py").read_text(encoding='utf-8'))
    for node in ast.walk(claim_tree):
        if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "candidate" for target in node.targets)
                and isinstance(node.value, ast.BinOp) and ast.unparse(node.value.left) == "root / naos_root"
                and isinstance(node.value.right, ast.Constant) and isinstance(node.value.right.value, str)):
            add("project_path", "scripts/naos_validate_claims.py", "declared_default_claims_operand", {"naos/" + node.value.right.value})
    transaction_tree = ast.parse(source("upgrade_contract/transaction.py").read_text(encoding='utf-8'))
    for node in transaction_tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_MANAGED_RUNTIME_RELATIVES" for target in node.targets):
            values = {call.args[0].value for call in ast.walk(node.value) if isinstance(call, ast.Call)
                      and ast.unparse(call.func) == "Path" and len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
                      and isinstance(call.args[0].value, str)}
            add("project_path", "upgrade_contract/transaction.py", "_MANAGED_RUNTIME_RELATIVES.public_control_operands", values)
    provenance_tree = ast.parse(source("upgrade_contract/provenance.py").read_text(encoding='utf-8'))
    declarations = {node.targets[0].id: node.value for node in provenance_tree.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)}
    def fixed_path(name):
        node = declarations[name]
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "Path" and len(node.args) == 1:
            return ast.literal_eval(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and isinstance(node.left, ast.Name):
            return fixed_path(node.left.id) + "/" + ast.literal_eval(node.right)
        raise ValueError("unsupported fixed path declaration: " + name)
    scope = fixed_path("MANAGED_CONTENT_SCOPE_RELATIVE")
    lock = fixed_path("CONTROL_ENROLLMENT_LOCK_RELATIVE")
    add("project_path", "upgrade_contract/provenance.py", "reviewed_managed_scope_and_control_enrollment_lock_operands",
        {scope, lock, lock.rsplit("/", 1)[0]})
    codec_tree = ast.parse(source("scripts/naos_secret_managed_operands.py").read_text(encoding='utf-8'))
    schema_declarations = [node.value for node in codec_tree.body if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "_SUPPORTED_SCHEMAS" for target in node.targets)]
    if len(schema_declarations) != 1:
        raise ValueError("missing or ambiguous managed codec schema declaration")
    codec_schemas = ast.literal_eval(schema_declarations[0])
    if type(codec_schemas) is not tuple or any(type(value) is not str or not re.fullmatch(r"naos\.[a-z0-9_.]+\.v[0-9]+", value) for value in codec_schemas):
        raise ValueError("malformed managed codec schema declaration")
    add("literal", "scripts/naos_secret_managed_operands.py", "reviewed_public_managed_codec_schemas", codec_schemas)
    journal_function = next(node for node in transaction_tree.body if isinstance(node, ast.FunctionDef) and node.name == "_journal_value")
    for node in ast.walk(journal_function):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "schema" and isinstance(value, ast.Constant)
                        and type(value.value) is str):
                    add("literal", "upgrade_contract/transaction.py", "_journal_value.declared_public_schema", {value.value})
    spec_relative = "templates/spec-kit/specs/spec_manifest.yaml"
    spec_declaration = yaml.safe_load(source(spec_relative).read_text(encoding='utf-8'))
    def declared_grammars(node, keys=()):
        if isinstance(node, dict):
            for key, item in node.items():
                if key.endswith("_patterns") and isinstance(item, list):
                    add("literal", spec_relative, "declared_parser_grammar:" + ".".join((*keys, key)), item)
                if key == "pattern" and type(item) is str:
                    add("literal", spec_relative, "declared_parser_grammar:" + ".".join((*keys, key)), {item})
                declared_grammars(item, (*keys, key))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                declared_grammars(item, (*keys, str(index)))
    declared_grammars(spec_declaration)
    example_relative = "templates/structural-seeds/naos/ui_experience_quality.yaml"
    example_refs = set()
    for line in source(example_relative).read_text(encoding='utf-8').splitlines():
        if re.match(r"^\s*#\s*(?:-\s*)?(?:ref:|prompt_log_ref:|[\"'])", line):
            for match in QUOTED.finditer(line):
                value = match.group(1) if match.group(1) is not None else match.group(2)
                if value.startswith(("specs/", "docs/")):
                    example_refs.add(value)
    add("literal", example_relative, "reviewed_commented_public_reference_examples", example_refs)
    add("literal", "upgrade_contract/transaction.py", "reviewed_public_integrity_link_field", {"previous_integrity_sha256"})
    render_tree = ast.parse(source("scripts/naos_render_secure_coding_controls.py").read_text(encoding='utf-8'))
    for node in ast.walk(render_tree):
        if isinstance(node, ast.Compare) and ast.unparse(node.left) == "manifest.get('schema')":
            add("literal", "scripts/naos_render_secure_coding_controls.py", "reviewed_render_manifest_schema_comparison",
                {item.value for item in node.comparators if isinstance(item, ast.Constant) and isinstance(item.value, str)})

    contract = json.loads(source("configs/profile_generated_surface_contract.json").read_text(encoding='utf-8'))
    surfaces = {s for profile in contract["profiles"].values() for key in ("required_surfaces", "prohibited_surfaces") for s in profile[key]}
    add("project_path", "configs/profile_generated_surface_contract.json", "required_and_prohibited_surfaces", surfaces)
    def schema_values(node):
        result = set()
        if isinstance(node, dict):
            for key in ("$id", "$schema", "const", "pattern"):
                if isinstance(node.get(key), str):
                    result.add(node[key])
            result.update(item for item in node.get("enum", []) if isinstance(item, str))
            result.update(node.get("properties", {}))
            for item in node.values():
                result.update(schema_values(item))
        elif isinstance(node, list):
            for item in node:
                result.update(schema_values(item))
        return result
    for name in members:
        if name.startswith("schemas/") and name.endswith(".json"):
            add("literal", name, "schema_public_keywords_id_dialect_const_enum_property_pattern", schema_values(json.loads(source(name).read_text(encoding='utf-8'))))
    evidence_keys = reviewed_constructor_groups(source, members, add)
    def policy_operands(paths):
        if not evidence_keys <= set(paths):
            raise ValueError("declared evidence selectors missing from policy")
        result = set()
        for key, value in paths.items():
            if not ("." in value or key == "audit_log_root") or value.startswith(("/", "../")):
                continue
            if key == "evidence_pack_report":
                result.add("naos/" + paths["evidence_dir"] + "/" + value)
            elif key in evidence_keys or not key.endswith("_report"):
                result.add("naos/" + value)
            else:
                result.add("naos/" + paths["reports_dir"] + "/" + value)
        return result
    policy = ast.parse(source("scripts/naos_policy.py").read_text(encoding='utf-8'))
    for node in policy.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "SAFE_FALLBACK_POLICY":
            paths = {key: value for key, value in ast.literal_eval(node.value)["paths"].items() if isinstance(value, str)}
            add("literal", "scripts/naos_policy.py", "SAFE_FALLBACK_POLICY.paths.keys_and_filenames", set(paths) | set(paths.values()))
            add("project_path", "scripts/naos_policy.py", "SAFE_FALLBACK_POLICY.paths.output_operands", policy_operands(paths))
    declared_policy = yaml.safe_load(source("policies/default_policy.yaml").read_text(encoding='utf-8'))
    policy_paths = {key: value for key, value in declared_policy["paths"].items() if type(value) is str}
    add("literal", "policies/default_policy.yaml", "declared_public_path_keys_and_filenames", set(policy_paths) | set(policy_paths.values()))
    add("project_path", "policies/default_policy.yaml", "declared_public_report_and_control_operands",
        policy_operands(policy_paths))
    for name in members:
        if not name.endswith(".py") or not source(name).exists() or name.endswith("generate_naos_secret_public_literals.py"):
            continue
        text = source(name).read_text(encoding='utf-8')
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = {target.id for target in targets if isinstance(target, ast.Name)}
                value = node.value
                if (any(n.endswith("SCHEMA") for n in names) and isinstance(value, ast.Constant)
                        and isinstance(value.value, str) and re.fullmatch(r"naos\.[a-z0-9_.]+\.v[0-9]+", value.value)):
                    add("literal", name, "declared_public_schema:" + ",".join(sorted(names)), {value.value})
                selected = []
                declarations = REGEX_DECLARATIONS.get(name, set()) | CODE_TEMPLATES.get(name, set())
                if names & declarations:
                    selected.append((",".join(sorted(names)), value))
                if isinstance(value, ast.Dict):
                    for key, item in zip(value.keys, value.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            for target in names:
                                if target + "." + key.value in declarations:
                                    selected.append((target + "." + key.value, item))
                for selector, item in selected:
                    segment = ast.get_source_segment(text, item) or ""
                    values = {m.group(1) if m.group(1) is not None else m.group(2) for line in segment.splitlines() for m in QUOTED.finditer(line)}
                    values.update(n.value for n in ast.walk(item) if isinstance(n, ast.Constant) and isinstance(n.value, str))
                    add("literal", name, "reviewed_public_grammar_or_code_template:" + selector, values)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            ancestor = node
            function = "module"
            while ancestor in parents:
                ancestor = parents[ancestor]
                if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    function = ancestor.name
                    break
            selected = None
            selector = None
            if (isinstance(node, ast.Call) and node.args and function in FUNCTION_REGEX.get(name, set())
                    and ast.unparse(node.func) in {"re.compile", "re.match", "re.fullmatch", "re.findall", "re.finditer"}):
                selected, selector = node.args[0], "reviewed_parser:" + function + ":" + ast.unparse(node.func)
            elif (isinstance(node, ast.JoinedStr) and function in FUNCTION_FORMATTERS.get(name, set())
                    and any(isinstance(value, ast.FormattedValue) for value in node.values)):
                selected, selector = node, "reviewed_source_format_template:" + function
            elif isinstance(node, ast.Dict):
                for key, item in zip(node.keys, node.values):
                    if (isinstance(key, ast.Constant) and (function, key.value) in DICT_DECLARATIONS.get(name, set())
                            and isinstance(item, ast.Constant) and isinstance(item.value, str)):
                        add("literal", name, "reviewed_public_field:" + function + ":" + key.value, {item.value})
            elif (isinstance(node, ast.Call) and (function, ast.unparse(node.func)) in CALL_DECLARATIONS.get(name, set())):
                # Reviewed command operands/control field identifiers only.
                selected, selector = node.args[0] if node.args else None, "reviewed_command_or_control_field:" + function + ":" + ast.unparse(node.func)
                if ast.unparse(node.func) == "run_git" and len(node.args) > 1:
                    selected = node.args[1]
            if selected is not None:
                segment = ast.get_source_segment(text, selected) or ""
                values = {match.group(1) if match.group(1) is not None else match.group(2) for line in segment.splitlines() for match in QUOTED.finditer(line)}
                if isinstance(selected, ast.Constant) and isinstance(selected.value, str):
                    values.add(selected.value)
                add("literal", name, selector, values)
    grader = source("autoresearch/graders/static.py").read_text(encoding='utf-8')
    dimensions = set()
    for node in ast.parse(grader).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {"SUPPORTED_DIMENSIONS", "FUTURE_BEHAVIORAL_DIMENSIONS"} for t in node.targets):
            dimensions.update(ast.literal_eval(node.value))
    add("literal", "autoresearch/graders/static.py", "declared_dimensions_and_STATICGRADER_UNSUPPORTED_identifiers", dimensions | {"STATICGRADER_UNSUPPORTED_" + d for d in dimensions})
    # One reviewed public hash-domain declaration, not arbitrary source literals.
    helper_name = "scripts/naos_secret_public_literals.py"
    helper_text = source(helper_name).read_text(encoding='utf-8')
    for node in ast.parse(helper_text).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_SECRET_FINDING_DOMAIN" for target in node.targets):
            if type(ast.literal_eval(node.value)) is not bytes:
                raise ValueError("public finding domain must be an explicit bytes declaration")
            segment = ast.get_source_segment(helper_text, node.value) or ""
            values = {match.group(1) if match.group(1) is not None else match.group(2) for match in QUOTED.finditer(segment)}
            add("literal", helper_name, "_SECRET_FINDING_DOMAIN.public_hash_domain", values)
    add("literal", "scripts/naos_secret_public_literals.py", "exact_public_OS_attribute_name", {"Y29tLmFwcGxlLnByb3ZlbmFuY2U="})
    merged = {}
    for group in groups:
        key = (group["source"], group["selector"], group["kind"])
        if key not in merged:
            merged[key] = {**group, "values": set(group["values"])}
        else:
            merged[key]["values"].update(group["values"])
    final = []
    for key, group in sorted(merged.items()):
        group["values"] = sorted(group["values"])
        group["component_sha256"] = hashlib.sha256(json.dumps(group["values"], ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        final.append(group)
    return {"schema": SCHEMA, "groups": final}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--overlay-root", type=Path)
    parser.add_argument("--output-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    # Regenerate exact reviewed schema declaration pins from selected source;
    # the catalog then observes the same helper bytes as the runtime.
    helper = args.output_root / "scripts/naos_secret_public_literals.py"
    helper_text = helper.read_text(encoding='utf-8')
    tree = ast.parse(helper_text)
    declaration = next(node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "_REFERENCE_SCHEMAS" for t in node.targets))
    pins = ast.literal_eval(declaration.value)
    for name in pins:
        relative = "schemas/naos/" + name + ".schema.json"
        selected = args.overlay_root / relative if args.overlay_root else None
        schema_source = selected if selected is not None and selected.is_file() else args.source_root / relative
        pins[name] = hashlib.sha256(schema_source.read_bytes()).hexdigest()
    lines = helper_text.splitlines(keepends=True)
    updated_pins = "_REFERENCE_SCHEMAS = " + repr(pins) + "\n"
    pin_text = "".join(lines[:declaration.lineno-1]) + updated_pins + "".join(lines[declaration.end_lineno:])
    if args.check:
        if pins != ast.literal_eval(declaration.value):raise ValueError("reference schema pins are stale")
    else:
        helper.write_text(pin_text, encoding='utf-8')
    catalog = build(args.source_root, args.overlay_root)
    raw = (json.dumps(catalog, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 1024 * 1024 or sum(len(g["values"]) for g in catalog["groups"]) > 16_384:
        raise ValueError("public vocabulary exceeds runtime bound")
    digest = hashlib.sha256(raw).hexdigest()
    target = args.output_root / "scripts/naos_secret_public_literals.json"
    helper = args.output_root / "scripts/naos_secret_public_literals.py"
    updated = re.sub(r'^CATALOG_SHA256 = "[^"\n]+"$', 'CATALOG_SHA256 = "' + digest + '"', helper.read_text(encoding='utf-8'), flags=re.M)
    if args.check:
        if target.read_bytes() != raw or helper.read_text(encoding='utf-8') != updated:
            raise ValueError("public vocabulary or bound digest is stale")
    else:
        target.write_bytes(raw)
        helper.write_text(updated, encoding='utf-8')
    print(json.dumps({"sha256": digest, "bytes": len(raw), "groups": len(catalog["groups"]), "entries": sum(len(g["values"]) for g in catalog["groups"]), "check": args.check}))

if __name__ == "__main__":
    main()
