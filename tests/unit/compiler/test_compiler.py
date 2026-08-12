from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from acc_core.compiler import compile_project


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _operation(operation_id: str) -> dict[str, object]:
    return {
        "schema_version": "2",
        "id": operation_id,
        "title": f"Call {operation_id}",
        "kind": "read",
        "input_schema": {
            "properties": {
                "z_field": {"type": "string"},
                "customer_id": {"type": "string"},
            },
            "type": "object",
            "additionalProperties": False,
        },
        "output_schema": {"type": "object"},
        "http": {
            "method": "GET",
            "path": "/customers/{customer_id}",
            "path_parameters": {"customer_id": "customer_id"},
            "query_parameters": {},
            "request": None,
            "success": {"statuses": [200], "body": "json"},
            "scopes": ["customer.read"],
            "timeout_seconds": 15,
            "max_response_bytes": 1_048_576,
            "safety": {
                "effect": "read",
                "risk": "low",
                "reversibility": "reversible",
                "retry": {"mode": "idempotent_only"},
                "idempotency": {"mode": "unsupported"},
                "concurrency": {"mode": "not_supported"},
            },
        },
        "context_bindings": {},
        "evidence": [
            {
                "source_id": "crm-backend",
                "locator": "app/api/customers.py#L42-L68",
                "digest": f"sha256:{'a' * 64}",
            }
        ],
    }


def _make_project(root: Path) -> Path:
    project = root / "acc-project"
    (root / "system").mkdir()
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "example-crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "CRM_BASE_URL",
                "auth": {"kind": "bearer_secret", "token_ref": "CRM_USER_TOKEN"},
            },
            "quality": {"profile": "standard"},
        },
    )
    _write_yaml(project / "operations" / "crm.get_customer.yaml", _operation("crm.get_customer"))
    _write_yaml(
        project / "policies" / "crm-sales-read.yaml",
        {
            "schema_version": "2",
            "id": "crm-sales-read",
            "required_scopes": ["customer.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["id", "name", "tenant_id"],
            "denied_fields": ["internal_note"],
            "redaction_rules": [],
        },
    )
    _write_yaml(
        project / "capabilities" / "get_customer.yaml",
        {
            "schema_version": "2",
            "kind": "read",
            "id": "get_customer",
            "title": "Get customer context",
            "description": "Get one customer's context.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"customer_id": {"type": "string"}},
            },
            "output_schema": {"type": "object"},
            "workflow": [
                {
                    "id": "customer",
                    "call": {
                        "operation": "crm.get_customer",
                        "arguments": {"customer_id": "$.input.customer_id"},
                    },
                },
                {"assert": {"condition": "$.steps.customer", "message": "missing"}},
                {"emit": {"value": "$.steps.customer"}},
            ],
            "policy": "crm-sales-read",
            "evals": ["get-customer-normal"],
        },
    )
    _write_yaml(
        project / "evals" / "get-customer-normal.yaml",
        {
            "schema_version": "2",
            "id": "get-customer-normal",
            "capability": "get_customer",
            "input": {"customer_id": "c-1"},
            "fixtures": {},
            "expected_calls": [
                {"operation": "crm.get_customer", "arguments": {"customer_id": "c-1"}}
            ],
            "expected_output_schema": {"type": "object"},
            "forbidden_fields": ["internal_note"],
        },
    )
    _write_yaml(
        project / "source-contracts" / "crm.get_customer.yaml",
        {
            "schema_version": "2",
            "id": "crm.get_customer.contract",
            "operation_id": "crm.get_customer",
            "request_schema": {"type": "object"},
            "response_schema": {"type": "object"},
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
        },
    )
    _write_yaml(
        project / "capability-quality" / "get_customer.yaml",
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "intent": {"action": "get", "resource_types": ["customer"]},
            "inputs": {
                "customer_id": {
                    "kind": "resource_selector",
                    "resource_type": "customer",
                    "acquisition": "caller",
                }
            },
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65536},
        },
    )
    return project


def _load_capability(project: Path) -> dict[str, Any]:
    capability = yaml.safe_load(
        (project / "capabilities" / "get_customer.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(capability, dict)
    return capability


def test_compiler_rejects_legacy_project_before_emitting_ir(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    path = project / "project.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["schema_version"] = "1"
    _write_yaml(path, document)

    report = compile_project(project)

    assert report.ir is None
    assert "ACC_FORMAT_VERSION_UNSUPPORTED" in {item.code for item in report.diagnostics}


def test_compiler_emits_independent_interaction_digest_for_current_ir(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    _write_yaml(
        project / "scope-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": ["crm"]},
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": [],
            "summary": {
                "discovered_routes": 0,
                "eligible_routes": 0,
                "planned": 0,
                "composed": 0,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        },
    )
    _write_yaml(
        project / "ui-interaction-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {
                "mode": "none",
                "evidence_sources": ["frontend-tree"],
                "rationale": "This project has no applicable interactive client surface.",
            },
            "surfaces": [],
            "interactions": [],
            "summary": {"surfaces": 0, "interactions": 0, "unresolved": 0},
        },
    )

    report = compile_project(project)

    assert report.ir is not None, report.diagnostics
    interactions = cast(dict[str, Any], report.ir["interactions"])
    assert report.ir["interaction_sha256"] == interactions["digest"]
    assert interactions["inventory"]["scope_mode"] == "none"
    assert interactions["inventory"]["interaction_ids"] == []
    assert set(interactions) == {
        "schema_version",
        "contracts",
        "dependencies",
        "digest",
        "inventory",
    }


def _write_capability(project: Path, capability: dict[str, Any]) -> None:
    _write_yaml(project / "capabilities" / "get_customer.yaml", capability)


def _configure_streamable_gateway_auth(
    project: Path,
    *,
    scopes_pointer: str | None = "/permissions",
    scope_mapping: dict[str, list[str]] | None = None,
) -> None:
    project_path = project / "project.yaml"
    document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    document["runtime"]["transport"] = ["streamable_http"]
    auth: dict[str, object] = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/api/auth/login",
        "identity_field": "email",
        "password_field": "password",
        "token_pointer": "/access_token",
    }
    if scopes_pointer is not None:
        auth["scopes_pointer"] = scopes_pointer
    if scope_mapping is not None:
        auth["scope_mapping"] = scope_mapping
    document["provider"]["auth"] = auth
    _write_yaml(project_path, document)


def _set_operation_context_binding(project: Path, target: str, source: str) -> None:
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["context_bindings"] = {target: source}
    _write_yaml(operation_path, operation)


def _set_context_binding_allowlist(project: Path, *sources: str) -> None:
    project_path = project / "project.yaml"
    document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    document["provider"]["context_binding_allowlist"] = sorted(sources)
    _write_yaml(project_path, document)


def test_compile_project_accepts_context_binding_not_exposed_by_capability(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    capability["workflow"][0]["call"]["arguments"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is True
    assert report.ir is not None
    operation = cast(dict[str, Any], report.ir)["operations"]["crm.get_customer"]
    assert operation["context_bindings"] == {"customer_id": "principal_id"}


@pytest.mark.parametrize(
    "source",
    ["tenant_context.session_id", "tenant_context.access_key"],
)
def test_compile_project_rejects_tenant_context_source_not_in_provider_allowlist(
    tmp_path: Path,
    source: str,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", source)
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    capability["workflow"][0]["call"]["arguments"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_SOURCE_NOT_ALLOWED"
    )
    assert diagnostic.pointer == "/context_bindings/customer_id"


@pytest.mark.parametrize(
    "source",
    [
        "tenant_context.customer_region",
        "tenant_context.secretary_id",
        "tenant_context.header_image",
        "tenant_context.tokenized_region",
    ],
)
def test_compile_project_accepts_explicit_provider_context_binding_allowlist(
    tmp_path: Path,
    source: str,
) -> None:
    project = _make_project(tmp_path)
    _set_context_binding_allowlist(project, source)
    _set_operation_context_binding(project, "customer_id", source)
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    capability["workflow"][0]["call"]["arguments"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is True
    assert not any(
        item.code == "ACC_COMPILE_CONTEXT_BINDING_SOURCE_NOT_ALLOWED" for item in report.diagnostics
    )


@pytest.mark.parametrize(
    ("configured_on", "expected_pointer"),
    [
        ("provider", "/provider/context_binding_allowlist/0"),
        ("operation", "/context_bindings/customer_id"),
    ],
)
def test_compile_project_rejects_sensitive_context_binding_before_ir(
    tmp_path: Path,
    configured_on: str,
    expected_pointer: str,
) -> None:
    project = _make_project(tmp_path)
    source = "tenant_context.profile.accessToken"
    if configured_on == "provider":
        _set_context_binding_allowlist(project, source)
    else:
        _set_operation_context_binding(project, "customer_id", source)

    report = compile_project(project)

    assert report.ok is False
    diagnostic = next(item for item in report.diagnostics if item.code == "ACC_SCHEMA_INVALID")
    assert diagnostic.pointer == expected_pointer


@pytest.mark.parametrize(
    "source",
    [
        "tenant_context.idToken",
        "tenant_context.oauthToken",
        "tenant_context.apiToken",
        "tenant_context.jwtToken",
        "tenant_context.passwordHash",
        "tenant_context.xApiKey",
        "tenant_context.authorizationHeader",
        "tenant_context.idtoken",
        "tenant_context.oauthtoken",
        "tenant_context.apikey",
        "tenant_context.xapikey",
        "tenant_context.passwordhash",
        "tenant_context.authorizationheader",
        "tenant_context.clientsecret",
        "tenant_context.privatekey",
        "tenant_context.setcookie",
        "tenant_context.privateRegionKey",
        "tenant_context.apiRegionKey",
    ],
)
def test_compile_project_rejects_sensitive_compound_context_binding_words(
    tmp_path: Path,
    source: str,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", source)

    report = compile_project(project)

    assert report.ok is False
    diagnostic = next(item for item in report.diagnostics if item.code == "ACC_SCHEMA_INVALID")
    assert diagnostic.pointer == "/context_bindings/customer_id"


def test_compile_project_rejects_context_binding_target_not_mapped_to_http(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "z_field", "principal_id")

    report = compile_project(project)

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_TARGET_INVALID"
    )
    assert report.ok is False
    assert diagnostic.pointer == "/context_bindings/z_field"


def test_compile_project_rejects_context_binding_field_from_capability_input(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")

    report = compile_project(project)

    assert report.ok is False
    assert any(
        item.code == "ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT" for item in report.diagnostics
    )


def test_compile_project_rejects_context_binding_field_from_workflow_arguments(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_ARGUMENT_OVERRIDE"
    )
    assert diagnostic.pointer == "/workflow/0/call/arguments/customer_id"


def test_compile_project_rejects_nested_context_binding_argument_overrides(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    bound_call = {
        "call": {
            "operation": "crm.get_customer",
            "arguments": {"customer_id": "forced"},
        }
    }
    capability["workflow"] = [
        {
            "branch": {
                "condition": "$.input.flag",
                "then": [bound_call],
                "else": [{"emit": {"value": {}}}],
            }
        },
        {"parallel": [bound_call]},
        {
            "foreach": {
                "items": "$.input.items",
                "item_name": "item",
                "max_items": 2,
                "workflow": [bound_call],
            }
        },
        {"emit": {"value": {}}},
    ]
    _write_capability(project, capability)

    report = compile_project(project)

    overrides = [
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_ARGUMENT_OVERRIDE"
    ]
    assert [item.pointer for item in overrides] == [
        "/workflow/0/branch/then/0/call/arguments/customer_id",
        "/workflow/1/parallel/0/call/arguments/customer_id",
        "/workflow/2/foreach/workflow/0/call/arguments/customer_id",
    ]


def test_compile_project_rejects_context_binding_with_open_capability_input(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    capability["input_schema"]["additionalProperties"] = True
    capability["workflow"][0]["call"]["arguments"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT"
    )
    assert diagnostic.pointer == "/input_schema/additionalProperties"


def test_compile_project_requires_root_object_for_context_binding_input(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")
    capability = _load_capability(project)
    capability["input_schema"] = {
        "type": "array",
        "items": {"type": "string"},
        "additionalProperties": False,
    }
    capability["workflow"][0]["call"]["arguments"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT"
    )
    assert diagnostic.pointer == "/input_schema/type"


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("patternProperties", {"^customer_id$": {"type": "string"}}),
        ("$ref", "#/$defs/input"),
        ("allOf", [{}]),
        ("anyOf", [{}]),
        ("oneOf", [{}]),
        ("if", {}),
        ("then", {}),
        ("else", {}),
        ("unevaluatedProperties", False),
    ],
)
def test_compile_project_rejects_context_binding_with_schema_keyword_bypass(
    tmp_path: Path,
    keyword: str,
    value: object,
) -> None:
    project = _make_project(tmp_path)
    _set_operation_context_binding(project, "customer_id", "principal_id")
    capability = _load_capability(project)
    capability["input_schema"]["properties"] = {}
    capability["input_schema"]["additionalProperties"] = False
    capability["input_schema"][keyword] = value
    if keyword == "$ref":
        capability["input_schema"]["$defs"] = {
            "input": {"type": "object", "additionalProperties": True}
        }
    capability["workflow"][0]["call"]["arguments"] = {}
    _write_capability(project, capability)

    report = compile_project(project)

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT"
    )
    assert diagnostic.pointer == f"/input_schema/{keyword}"


@pytest.mark.parametrize(
    ("scopes_pointer", "scope_mapping", "accepted"),
    [
        (None, {}, False),
        ("/permissions", {}, False),
        (None, {"customer:read": ["customer.read"]}, False),
        ("/permissions", {"customer:read": ["customer.read"]}, True),
    ],
)
def test_streamable_scoped_capability_requires_pointer_and_nonempty_scope_mapping(
    tmp_path: Path,
    scopes_pointer: str | None,
    scope_mapping: dict[str, list[str]],
    accepted: bool,
) -> None:
    project = _make_project(tmp_path)
    _configure_streamable_gateway_auth(
        project,
        scopes_pointer=scopes_pointer,
        scope_mapping=scope_mapping,
    )

    report = compile_project(project)

    assert report.ok is accepted
    gate_errors = [
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_SOURCE_SCOPE_MAPPING_REQUIRED"
    ]
    assert bool(gate_errors) is not accepted


@pytest.mark.parametrize("scope_source", ["policy", "operation"])
def test_streamable_scope_gate_checks_policy_and_operation_scopes(
    tmp_path: Path,
    scope_source: str,
) -> None:
    project = _make_project(tmp_path)
    _configure_streamable_gateway_auth(
        project,
        scopes_pointer=None,
        scope_mapping={},
    )
    policy_path = project / "policies" / "crm-sales-read.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["required_scopes"] = ["customer.read"] if scope_source == "policy" else []
    _write_yaml(policy_path, policy)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["http"]["scopes"] = ["customer.read"] if scope_source == "operation" else []
    _write_yaml(operation_path, operation)

    report = compile_project(project)

    assert any(
        item.code == "ACC_COMPILE_SOURCE_SCOPE_MAPPING_REQUIRED" for item in report.diagnostics
    )


def test_compile_project_emits_normalized_json_ir_and_operation_dependencies(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _write_yaml(project / "operations" / "crm.a_related.yaml", _operation("crm.a_related"))
    _write_yaml(
        project / "source-contracts" / "crm.a_related.yaml",
        {
            "schema_version": "2",
            "id": "crm.a_related.contract",
            "operation_id": "crm.a_related",
            "request_schema": {"type": "object"},
            "response_schema": {"type": "object"},
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
        },
    )
    capability = _load_capability(project)
    capability["workflow"].insert(
        1,
        {
            "id": "related",
            "parallel": [
                {"call": {"operation": "crm.get_customer", "arguments": {}}},
                {"call": {"operation": "crm.a_related", "arguments": {}}},
            ],
        },
    )
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is True
    assert [item.code for item in report.diagnostics] == ["ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"]
    assert report.ir is not None
    assert json.loads(json.dumps(report.ir)) == report.ir
    ir = cast(dict[str, Any], report.ir)
    assert ir["ir_version"] == "2"
    assert list(ir["operations"]) == ["crm.a_related", "crm.get_customer"]
    assert list(ir["operations"]["crm.a_related"]["input_schema"]["properties"]) == [
        "customer_id",
        "z_field",
    ]
    compiled_capability = ir["capabilities"]["get_customer"]
    assert compiled_capability["operation_dependencies"] == [
        "crm.a_related",
        "crm.get_customer",
    ]
    assert "assert" in compiled_capability["definition"]["workflow"][2]


def test_compile_project_accepts_a_locally_referenced_bounded_output(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["output_schema"] = {
        "$defs": {
            "customer": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "maxLength": 36},
                    "name": {"type": "string", "maxLength": 80},
                },
            }
        },
        "type": "array",
        "maxItems": 20,
        "items": {"$ref": "#/$defs/customer"},
    }
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is True
    assert all(item.code != "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN" for item in report.diagnostics)


def test_compile_project_reports_missing_operation_policy_and_eval_references(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"][0]["call"]["operation"] = "crm.missing"
    capability["policy"] = "missing-policy"
    capability["evals"] = ["missing-eval"]
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    assert report.ir is None
    assert [item.code for item in report.diagnostics if item.severity == "error"] == [
        "ACC_COMPILE_POLICY_NOT_FOUND",
        "ACC_COMPILE_EVAL_NOT_FOUND",
        "ACC_COMPILE_OPERATION_NOT_FOUND",
    ]
    assert [item.pointer for item in report.diagnostics if item.severity == "error"] == [
        "/policy",
        "/evals/0",
        "/workflow/0/call/operation",
    ]


def test_compile_project_checks_eval_targets_and_expected_operations(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    eval_path = project / "evals" / "get-customer-normal.yaml"
    eval_document = yaml.safe_load(eval_path.read_text(encoding="utf-8"))
    eval_document["capability"] = "missing-capability"
    eval_document["expected_calls"][0]["operation"] = "crm.missing"
    _write_yaml(eval_path, eval_document)

    report = compile_project(project)

    assert report.ok is False
    assert report.ir is None
    assert [item.code for item in report.diagnostics if item.severity == "error"] == [
        "ACC_COMPILE_EVAL_CAPABILITY_MISMATCH",
        "ACC_COMPILE_CAPABILITY_NOT_FOUND",
        "ACC_COMPILE_OPERATION_NOT_FOUND",
    ]


def test_compile_project_rejects_duplicate_step_ids_in_nested_workflows(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"].insert(
        1,
        {
            "id": "container",
            "branch": {
                "condition": "$.steps.customer",
                "then": [{"id": "customer", "emit": {"value": {}}}],
                "else": [{"emit": {"value": {}}}],
            },
        },
    )
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    duplicate = next(
        item for item in report.diagnostics if item.code == "ACC_COMPILE_STEP_ID_DUPLICATE"
    )
    assert duplicate.pointer == "/workflow/1/branch/then/0/id"


def test_compile_project_only_allows_references_to_prior_steps(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"] = [
        {
            "id": "first",
            "pick": {"value": "$.steps.later.name", "fields": ["name"]},
        },
        {"id": "later", "call": {"operation": "crm.get_customer", "arguments": {}}},
        {"emit": {"value": "$.steps.first"}},
    ]
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    reference = next(
        item for item in report.diagnostics if item.code == "ACC_COMPILE_STEP_REFERENCE_NOT_PRIOR"
    )
    assert reference.pointer == "/workflow/0/pick/value"
    assert "later" in reference.message


def test_compile_project_requires_a_final_emit(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"] = [
        {"id": "customer", "call": {"operation": "crm.get_customer", "arguments": {}}}
    ]
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    assert report.ir is None
    assert report.diagnostics[-1].code == "ACC_COMPILE_FINAL_EMIT_REQUIRED"
    assert report.diagnostics[-1].pointer == "/workflow"


def test_compile_project_rejects_code_like_and_interpolated_expressions(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"] = [
        {
            "id": "mapped",
            "map": {
                "items": "$.input.items",
                "expression": "__import__('os').system('whoami')",
                "max_items": 10,
            },
        },
        {"emit": {"value": "customer-${$.input.customer_id}"}},
    ]
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    assert report.ir is None
    invalid_references = [
        item for item in report.diagnostics if item.code == "ACC_COMPILE_REFERENCE_INVALID"
    ]
    assert [item.pointer for item in invalid_references] == [
        "/workflow/0/map/expression",
        "/workflow/1/emit/value",
    ]


def test_compile_project_propagates_parallel_and_foreach_bounds(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"] = [
        {
            "parallel": [
                {"call": {"operation": "crm.get_customer", "arguments": {}}} for _ in range(9)
            ]
        },
        {
            "foreach": {
                "items": "$.input.items",
                "item_name": "item",
                "max_items": 101,
                "workflow": [{"emit": {"value": "$.item"}}],
            }
        },
        {"emit": {"value": {}}},
    ]
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    assert report.ir is None
    assert {item.code for item in report.diagnostics if item.severity == "error"} == {
        "ACC_CAPABILITY_QUALITY_ORPHAN",
        "ACC_SCHEMA_INVALID",
    }
    assert {item.pointer for item in report.diagnostics} >= {
        "/workflow/0/ParallelStep/parallel",
        "/workflow/1/ForeachStep/foreach/max_items",
    }


def test_compile_project_allows_item_references_only_in_bounded_item_contexts(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    capability = _load_capability(project)
    capability["workflow"] = [
        {
            "id": "names",
            "foreach": {
                "items": "$.input.items",
                "item_name": "customer",
                "max_items": 10,
                "workflow": [{"emit": {"value": "$.item.name"}}],
            },
        },
        {"emit": {"value": "$.item.name"}},
    ]
    _write_capability(project, capability)

    report = compile_project(project)

    assert report.ok is False
    assert report.ir is None
    item_reference = next(
        item
        for item in report.diagnostics
        if item.code == "ACC_COMPILE_ITEM_REFERENCE_OUTSIDE_LOOP"
    )
    assert item_reference.pointer == "/workflow/1/emit/value"
