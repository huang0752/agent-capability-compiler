from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from acc_core.validation.project import validate_project


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def make_valid_project(root: Path) -> Path:
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
    _write_yaml(
        project / "operations" / "crm.get_customer.yaml",
        {
            "schema_version": "2",
            "id": "crm.get_customer",
            "title": "Get customer",
            "kind": "read",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
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
                "max_response_bytes": 1048576,
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
        },
    )
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
                "required": ["customer_id"],
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


def _interaction_evidence() -> dict[str, object]:
    return {
        "source_id": "customer-page",
        "kind": "source_file",
        "path": "frontend/customers.ts",
        "line_start": 1,
        "line_end": 10,
        "digest": f"sha256:{'b' * 64}",
    }


def _write_ui_inventory(project: Path, *, mode: str = "discovered") -> None:
    document: dict[str, object]
    if mode == "none":
        document = {
            "schema_version": "2",
            "scope": {
                "mode": "none",
                "evidence_sources": ["frontend-tree"],
                "rationale": "The source has no applicable interactive client surface.",
            },
            "surfaces": [],
            "interactions": [],
            "summary": {"surfaces": 0, "interactions": 0, "unresolved": 0},
        }
    else:
        document = {
            "schema_version": "2",
            "scope": {"mode": mode, "evidence_sources": ["customer-page"]},
            "surfaces": [
                {
                    "id": "customers",
                    "kind": "page",
                    "route_or_entry": "/customers",
                    "business_purpose": "Inspect customers",
                    "evidence_sources": ["customer-page"],
                }
            ],
            "interactions": [
                {
                    "id": "customers.initial-load",
                    "surface_id": "customers",
                    "business_intent": "Load one selected customer",
                    "trigger": {"kind": "screen_load"},
                    "route_ids": ["GET /customers/{customer_id}"],
                    "call_order": "sequential",
                    "input_bindings": [],
                    "defaults": [],
                    "option_sources": [],
                    "conditions": [],
                    "related_data": [],
                    "result_consumption": [],
                    "states": [],
                    "evidence_claims": [
                        {
                            "target_pointer": "/interactions/0",
                            "evidence": _interaction_evidence(),
                            "evidence_pointer": "/customers/initial-load",
                            "authority": "implementation",
                        }
                    ],
                    "unknowns": [],
                }
            ],
            "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
        }
    _write_yaml(project / "ui-interaction-inventory.yaml", document)
    _write_scope_inventory(project, include_route=mode != "none")


def _write_scope_inventory(project: Path, *, include_route: bool = True) -> None:
    routes = (
        [
            {
                "id": "GET /customers/{customer_id}",
                "domain": "crm",
                "method": "GET",
                "kind": "read",
                "effect": "read",
                "path": "/customers/{customer_id}",
                "evidence_sources": ["crm-backend"],
                "usage_evidence_sources": ["customer-page"],
                "interaction_ids": ["customers.initial-load"],
                "eligibility": "eligible",
                "disposition": "planned",
                "operation_id": "crm.get_customer",
                "capability_ids": ["get_customer"],
            }
        ]
        if include_route
        else []
    )
    _write_yaml(
        project / "scope-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": ["crm"]},
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": routes,
            "summary": {
                "discovered_routes": len(routes),
                "eligible_routes": len(routes),
                "planned": len(routes),
                "composed": 0,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        },
    )


def _write_interaction_contract(
    project: Path,
    *,
    filename: str = "get_customer.yaml",
    capability_id: str = "get_customer",
    interaction_ids: list[str] | None = None,
    omitted_interaction_ids: list[str] | None = None,
) -> None:
    _write_yaml(
        project / "interaction-contracts" / filename,
        {
            "schema_version": "2",
            "capability_id": capability_id,
            "interaction_ids": (
                ["customers.initial-load"] if interaction_ids is None else interaction_ids
            ),
            "public_input_bindings": [],
            "trusted_input_bindings": [],
            "defaults": [],
            "option_sources": [],
            "conditions": [],
            "related_data": [],
            "result_consumption": [],
            "required_scenarios": ["customers.initial-load.success"],
            "omissions": [
                {
                    "interaction_id": interaction_id,
                    "justification": "The capability intentionally omits this client flow.",
                    "authority": "implementation",
                    "evidence": _interaction_evidence(),
                }
                for interaction_id in (omitted_interaction_ids or [])
            ],
        },
    )


def test_valid_project_loads_all_contracts(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)

    report = validate_project(project)

    assert report.ok is True
    assert report.project is not None
    assert list(report.operations) == ["crm.get_customer"]
    assert list(report.capabilities) == ["get_customer"]
    assert list(report.policies) == ["crm-sales-read"]
    assert list(report.evals) == ["get-customer-normal"]
    assert set(report.source_contracts) == {"crm.get_customer"}
    assert set(report.capability_quality) == {"get_customer"}
    assert [item.code for item in report.diagnostics] == ["ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"]
    assert report.diagnostics[0].severity == "warning"


def test_none_interaction_scope_loads_without_capability_contracts(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project, mode="none")

    report = validate_project(project)

    assert report.ui_interaction_inventory is not None
    assert report.ui_interaction_inventory.scope.mode == "none"
    assert report.ui_interaction_inventory_path == "ui-interaction-inventory.yaml"
    assert report.interaction_contracts == {}
    assert not any(
        item.code.startswith("ACC_UI_INTERACTION_CONTRACT") for item in report.diagnostics
    )


@pytest.mark.parametrize("mode", ["discovered", "complete"])
def test_frontend_scope_requires_one_contract_per_capability(tmp_path: Path, mode: str) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project, mode=mode)

    report = validate_project(project)

    missing = [
        item for item in report.diagnostics if item.code == "ACC_UI_INTERACTION_CONTRACT_MISSING"
    ]
    assert len(missing) == 1
    assert missing[0].path == "capabilities/get_customer.yaml"


def test_frontend_scope_loads_typed_contract_and_exact_paths(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    _write_interaction_contract(project)

    report = validate_project(project)

    assert report.ui_interaction_inventory is not None
    assert report.scope_inventory is not None
    assert report.scope_inventory_path == "scope-inventory.yaml"
    assert list(report.interaction_contracts) == ["get_customer"]
    assert report.interaction_contracts["get_customer"].interaction_ids == [
        "customers.initial-load"
    ]
    assert report.interaction_contract_paths == {
        "get_customer": "interaction-contracts/get_customer.yaml"
    }
    assert not any(item.code.startswith("ACC_UI_") for item in report.diagnostics)


def test_ui_inventory_requires_typed_scope_inventory(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    _write_interaction_contract(project)
    (project / "scope-inventory.yaml").unlink()

    report = validate_project(project)

    assert "ACC_UI_SCOPE_INVENTORY_MISSING" in {item.code for item in report.diagnostics}


def test_validation_runs_interaction_fidelity_for_route_and_default_authority(
    tmp_path: Path,
) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    _write_interaction_contract(project)
    inventory_path = project / "ui-interaction-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    inventory["interactions"][0]["route_ids"] = ["GET /missing"]
    _write_yaml(inventory_path, inventory)
    contract_path = project / "interaction-contracts" / "get_customer.yaml"
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    contract["defaults"] = [
        {
            "id": "unsafe-default",
            "target_pointer": "/customer_id",
            "source_kind": "literal",
            "value": 7,
            "authority": "observation",
            "precedence": "caller_over_default",
            "submission": "send",
            "override_policy": "caller_allowed",
            "evidence": _interaction_evidence(),
        }
    ]
    _write_yaml(contract_path, contract)

    report = validate_project(project)
    codes = {item.code for item in report.diagnostics}

    assert "ACC_UI_INTERACTION_ROUTE_UNKNOWN" in codes
    assert "ACC_UI_DEFAULT_AUTHORITY_UNPROVEN" in codes


def test_frontend_scope_rejects_orphan_and_duplicate_capability_contracts(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    _write_interaction_contract(project, filename="a.yaml", capability_id="unknown")
    _write_interaction_contract(project, filename="b.yaml", capability_id="unknown")

    report = validate_project(project)

    codes = [item.code for item in report.diagnostics]
    assert "ACC_UI_INTERACTION_CONTRACT_DUPLICATE" in codes
    assert "ACC_UI_INTERACTION_CONTRACT_ORPHAN" in codes


def test_frontend_scope_rejects_unknown_and_unclassified_interactions(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    _write_interaction_contract(project, interaction_ids=["customers.unknown"])

    report = validate_project(project)

    codes = {item.code for item in report.diagnostics}
    assert "ACC_UI_INTERACTION_REFERENCE_UNKNOWN" in codes
    assert "ACC_UI_INTERACTION_UNCLASSIFIED" in codes


def test_frontend_scope_accepts_evidence_backed_explicit_omission(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    _write_interaction_contract(
        project,
        interaction_ids=[],
        omitted_interaction_ids=["customers.initial-load"],
    )

    report = validate_project(project)

    assert [item.code for item in report.diagnostics if item.code.startswith("ACC_UI_")] == []


def test_frontend_scope_allows_one_capability_to_adopt_what_another_omits(
    tmp_path: Path,
) -> None:
    project = make_valid_project(tmp_path)
    _write_ui_inventory(project)
    capability_path = project / "capabilities" / "get_customer.yaml"
    capability = yaml.safe_load(capability_path.read_text(encoding="utf-8"))
    capability.update(
        id="list_customers",
        title="List customer context",
        description="List customer context through the shared source operation.",
        evals=["list-customers-normal"],
    )
    _write_yaml(project / "capabilities" / "list_customers.yaml", capability)
    eval_path = project / "evals" / "get-customer-normal.yaml"
    eval_document = yaml.safe_load(eval_path.read_text(encoding="utf-8"))
    eval_document.update(id="list-customers-normal", capability="list_customers")
    _write_yaml(project / "evals" / "list-customers-normal.yaml", eval_document)
    quality_path = project / "capability-quality" / "get_customer.yaml"
    quality = yaml.safe_load(quality_path.read_text(encoding="utf-8"))
    quality["capability_id"] = "list_customers"
    _write_yaml(project / "capability-quality" / "list_customers.yaml", quality)
    _write_interaction_contract(project, filename="get_customer.yaml")
    _write_interaction_contract(
        project,
        filename="list_customers.yaml",
        capability_id="list_customers",
        interaction_ids=[],
        omitted_interaction_ids=["customers.initial-load"],
    )

    report = validate_project(project)

    assert set(report.capabilities) == {"get_customer", "list_customers"}, report.diagnostics
    assert [item.code for item in report.diagnostics if item.code.startswith("ACC_UI_")] == []


def _set_provider_auth(project: Path, auth: dict[str, object]) -> None:
    project_path = project / "project.yaml"
    document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    document["provider"]["auth"] = auth
    _write_yaml(project_path, document)


def _password_auth(credential_kind: str) -> dict[str, object]:
    credentials: dict[str, object] = {"kind": credential_kind}
    if credential_kind == "environment_secret":
        credentials.update(identity_ref="CRM_USER_EMAIL", password_ref="CRM_USER_PASSWORD")
    return {
        "kind": "password_bearer",
        "credentials": credentials,
        "login_path": "/api/auth/login",
        "identity_field": "email",
        "password_field": "password",
        "token_pointer": "/access_token",
    }


@pytest.mark.parametrize(
    ("transport", "auth", "accepted"),
    [
        ("stdio", {"kind": "none"}, True),
        ("stdio", {"kind": "bearer_secret", "token_ref": "CRM_USER_TOKEN"}, True),
        ("stdio", _password_auth("environment_secret"), True),
        ("stdio", _password_auth("gateway_session"), False),
        ("streamable_http", _password_auth("gateway_session"), True),
        ("streamable_http", _password_auth("environment_secret"), False),
        ("streamable_http", {"kind": "none"}, False),
        (
            "streamable_http",
            {"kind": "bearer_secret", "token_ref": "CRM_USER_TOKEN"},
            False,
        ),
    ],
)
def test_transport_and_credential_source_cross_validation(
    tmp_path: Path,
    transport: str,
    auth: dict[str, object],
    accepted: bool,
) -> None:
    project = make_valid_project(tmp_path)
    project_path = project / "project.yaml"
    document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    document["runtime"]["transport"] = [transport]
    document["provider"]["auth"] = deepcopy(auth)
    _write_yaml(project_path, document)

    report = validate_project(project)

    assert report.ok is accepted
    transport_errors = [
        item for item in report.diagnostics if item.code == "ACC_AUTH_TRANSPORT_INCOMPATIBLE"
    ]
    assert bool(transport_errors) is not accepted


def test_operation_without_evidence_has_stable_diagnostic(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["evidence"] = []
    _write_yaml(operation_path, operation)

    report = validate_project(project)

    assert report.ok is False
    assert report.diagnostics[0].code == "ACC_OPERATION_EVIDENCE_MISSING"
    assert report.diagnostics[0].path == "operations/crm.get_customer.yaml"
    assert report.diagnostics[0].pointer == "/evidence"


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    project = make_valid_project(tmp_path)
    original = project / "operations" / "crm.get_customer.yaml"
    duplicate = project / "operations" / "duplicate.yaml"
    duplicate.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")

    report = validate_project(project)

    assert report.ok is False
    assert any(item.code == "ACC_OPERATION_ID_DUPLICATE" for item in report.diagnostics)
