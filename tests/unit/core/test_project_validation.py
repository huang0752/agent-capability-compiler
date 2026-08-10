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
