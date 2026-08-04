from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import yaml

from acc_core.compiler import compile_project


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _operation(operation_id: str) -> dict[str, object]:
    return {
        "schema_version": "1",
        "id": operation_id,
        "title": f"Call {operation_id}",
        "kind": "http",
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
            "credential_ref": "CRM_USER_TOKEN",
            "scopes": ["customer.read"],
            "timeout_seconds": 15,
            "max_response_bytes": 1_048_576,
        },
        "safety": {"effect": "read"},
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
            "schema_version": "1",
            "project": {"id": "example-crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
        },
    )
    _write_yaml(project / "operations" / "crm.get_customer.yaml", _operation("crm.get_customer"))
    _write_yaml(
        project / "policies" / "crm-sales-read.yaml",
        {
            "schema_version": "1",
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
            "schema_version": "1",
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
            "schema_version": "1",
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
    return project


def _load_capability(project: Path) -> dict[str, Any]:
    capability = yaml.safe_load(
        (project / "capabilities" / "get_customer.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(capability, dict)
    return capability


def _write_capability(project: Path, capability: dict[str, Any]) -> None:
    _write_yaml(project / "capabilities" / "get_customer.yaml", capability)


def test_compile_project_emits_normalized_json_ir_and_operation_dependencies(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path)
    _write_yaml(project / "operations" / "crm.a_related.yaml", _operation("crm.a_related"))
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
    assert report.diagnostics == []
    assert report.ir is not None
    assert json.loads(json.dumps(report.ir)) == report.ir
    ir = cast(dict[str, Any], report.ir)
    assert ir["ir_version"] == "1"
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
    assert [item.code for item in report.diagnostics] == [
        "ACC_COMPILE_POLICY_NOT_FOUND",
        "ACC_COMPILE_EVAL_NOT_FOUND",
        "ACC_COMPILE_OPERATION_NOT_FOUND",
    ]
    assert [item.pointer for item in report.diagnostics] == [
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
    assert [item.code for item in report.diagnostics] == [
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
    assert {item.code for item in report.diagnostics} == {"ACC_SCHEMA_INVALID"}
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
