from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

import acc_core.models as models


def project_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "project": {"id": "example-crm", "version": "2.0.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "CRM_BASE_URL",
            "auth": {"kind": "bearer_secret", "token_ref": "CRM_TOKEN"},
        },
        "quality": {"profile": "standard"},
    }


def evidence_document() -> dict[str, object]:
    return {
        "source_id": "crm-backend",
        "kind": "source_file",
        "path": "app/api/customers.py",
        "line_start": 42,
        "line_end": 68,
        "digest": "sha256:" + "a" * 64,
    }


def operation_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "kind": "read",
        "id": "crm.get_customer",
        "title": "Get customer",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
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
        "evidence": [evidence_document()],
    }


def capability_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "kind": "read",
        "id": "get_customer",
        "title": "Get customer context",
        "description": "Get one customer.",
        "input_schema": {"type": "object"},
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
        "policy": "crm-read",
        "evals": ["normal"],
    }


def policy_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "id": "crm-read",
        "required_scopes": ["customer.read"],
        "tenant_mode": "none",
        "tenant_field": None,
        "readable_fields": ["id"],
        "denied_fields": [],
        "redaction_rules": [],
    }


def eval_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "id": "normal",
        "capability": "get_customer",
        "input": {"customer_id": "c-1"},
        "fixtures": {},
        "expected_calls": [{"operation": "crm.get_customer", "arguments": {"customer_id": "c-1"}}],
        "expected_output_schema": {"type": "object"},
        "expected_error": None,
        "forbidden_fields": [],
    }


def test_canonical_public_models_load_current_read_documents() -> None:
    project = models.Project.model_validate(project_document())
    operation: object = TypeAdapter(models.Operation).validate_python(operation_document())
    capability: object = TypeAdapter(models.Capability).validate_python(capability_document())
    policy = models.Policy.model_validate(policy_document())
    scenario = models.Eval.model_validate(eval_document())

    assert project.schema_version == "2"
    assert isinstance(operation, models.ReadOperationV2)
    assert isinstance(capability, models.ReadCapabilityV2)
    assert policy.schema_version == "2"
    assert scenario.schema_version == "2"


@pytest.mark.parametrize(
    ("validator", "document"),
    [
        (models.Project.model_validate, project_document()),
        (TypeAdapter(models.Operation).validate_python, operation_document()),
        (TypeAdapter(models.Capability).validate_python, capability_document()),
        (models.Policy.model_validate, policy_document()),
        (models.Eval.model_validate, eval_document()),
    ],
)
def test_every_top_level_contract_rejects_legacy_version(
    validator: Callable[[object], object],
    document: dict[str, object],
) -> None:
    document["schema_version"] = "1"

    with pytest.raises(ValidationError, match="schema_version"):
        validator(document)


def test_provider_accepts_only_sorted_unique_nonsensitive_context_bindings() -> None:
    document = project_document()
    provider = deepcopy(document["provider"])
    assert isinstance(provider, dict)
    provider["context_binding_allowlist"] = [
        "tenant_context.organization.region_id",
        "tenant_context.secretary_id",
    ]
    document["provider"] = provider

    project = models.Project.model_validate(document)

    assert project.provider.context_binding_allowlist == [
        "tenant_context.organization.region_id",
        "tenant_context.secretary_id",
    ]


@pytest.mark.parametrize(
    "allowlist",
    [
        ["tenant_context.tenant_id", "tenant_context.tenant_id"],
        ["principal_id"],
        ["tenant_context.z_field", "tenant_context.a_field"],
        ["tenant_context.profile.accessToken"],
        ["tenant_context.privateKey"],
    ],
)
def test_provider_rejects_duplicate_unsorted_or_sensitive_bindings(
    allowlist: list[str],
) -> None:
    document = project_document()
    provider = deepcopy(document["provider"])
    assert isinstance(provider, dict)
    provider["context_binding_allowlist"] = allowlist
    document["provider"] = provider

    with pytest.raises(ValidationError):
        models.Project.model_validate(document)


def test_password_bearer_auth_validates_paths_pointers_and_distinct_fields() -> None:
    auth = {
        "kind": "password_bearer",
        "credentials": {
            "kind": "environment_secret",
            "identity_ref": "CRM_USER",
            "password_ref": "CRM_PASSWORD",
        },
        "login_path": "/api/auth/login",
        "identity_field": "email",
        "password_field": "password",
        "token_pointer": "/data/access_token",
    }
    assert models.PasswordBearerAuthConfig.model_validate(auth).token_pointer == (
        "/data/access_token"
    )

    auth["login_path"] = "https://evil.example/login"
    with pytest.raises(ValidationError, match="origin-relative"):
        models.PasswordBearerAuthConfig.model_validate(auth)


def test_password_bearer_login_request_accepts_only_nonsecret_scalars_without_overrides() -> None:
    base = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/auth/login",
        "identity_field": "username",
        "password_field": "password",
        "login_request": {
            "static_fields": {
                "clientId": "public-client-id",
                "grantType": "password",
                "enabled": True,
            }
        },
        "token_pointer": "/data/access_token",
    }
    parsed = models.PasswordBearerAuthConfig.model_validate(base)
    assert parsed.login_request.static_fields["clientId"] == "public-client-id"

    for static_fields in (
        {"username": "override"},
        {"password": "override"},
        {"clientSecret": "embedded"},
        {"api_key": "embedded"},
        {"authorization": "embedded"},
        {"nested": {"not": "scalar"}},
        {"items": ["not", "scalar"]},
        {"\tbad": "value"},
    ):
        document = deepcopy(base)
        document["login_request"] = {"static_fields": static_fields}
        with pytest.raises(ValidationError):
            models.PasswordBearerAuthConfig.model_validate(document)


def test_space_delimited_scope_format_requires_a_pointer_and_default_is_array() -> None:
    base = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/auth/login",
        "identity_field": "username",
        "password_field": "password",
        "token_pointer": "/data/access_token",
    }
    assert models.PasswordBearerAuthConfig.model_validate(base).scopes_format == "json_array"
    with pytest.raises(ValidationError, match="require scopes_pointer"):
        models.PasswordBearerAuthConfig.model_validate({**base, "scopes_format": "space_delimited"})
    parsed = models.PasswordBearerAuthConfig.model_validate(
        {
            **base,
            "scopes_pointer": "/data/scope",
            "scopes_format": "space_delimited",
        }
    )
    assert parsed.scopes_format == "space_delimited"


def test_scope_discovery_rejects_cross_origin_paths_and_sensitive_or_nested_query() -> None:
    base = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/auth/login",
        "identity_field": "username",
        "password_field": "password",
        "token_pointer": "/data/access_token",
    }
    valid = {
        "path": "/system/user/getInfo",
        "static_query_fields": {"clientid": "public-client"},
        "scopes_pointer": "/data/permissions",
    }
    models.PasswordBearerAuthConfig.model_validate({**base, "scope_discovery": valid})
    for invalid in (
        {**valid, "path": "https://evil.example/scopes"},
        {**valid, "static_query_fields": {"token": "embedded"}},
        {**valid, "static_query_fields": {"cookie": "embedded"}},
        {**valid, "static_query_fields": {"nested": {"bad": True}}},
    ):
        with pytest.raises(ValidationError):
            models.PasswordBearerAuthConfig.model_validate({**base, "scope_discovery": invalid})


def test_operation_mapping_and_evidence_are_strict() -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["query_parameters"] = {"tenant": "missing_input"}
    document["http"] = http

    with pytest.raises(ValidationError, match="declared input"):
        TypeAdapter(models.Operation).validate_python(document)

    missing_evidence = operation_document()
    missing_evidence["evidence"] = []
    with pytest.raises(ValidationError, match="at least 1"):
        TypeAdapter(models.Operation).validate_python(missing_evidence)


def test_evidence_requires_a_locator_and_ordered_line_range() -> None:
    evidence = evidence_document()
    evidence["line_start"] = 70
    with pytest.raises(ValidationError, match="line_end"):
        models.Evidence.model_validate(evidence)

    no_locator = evidence_document()
    for field_name in ("path", "line_start", "line_end"):
        no_locator.pop(field_name)
    with pytest.raises(ValidationError, match="locator"):
        models.Evidence.model_validate(no_locator)


def test_policy_tenant_contract_is_explicit() -> None:
    required = policy_document()
    required["tenant_mode"] = "required"
    required["tenant_field"] = "tenant_id"
    assert models.Policy.model_validate(required).tenant_field == "tenant_id"

    required["tenant_field"] = None
    with pytest.raises(ValidationError, match="tenant_field"):
        models.Policy.model_validate(required)


def test_eval_requires_exactly_one_success_or_failure_expectation() -> None:
    neither = eval_document()
    neither["expected_output_schema"] = None
    with pytest.raises(ValidationError, match="exactly one"):
        models.Eval.model_validate(neither)

    both = eval_document()
    both["expected_error"] = {"code": "NOT_FOUND", "status": 404}
    with pytest.raises(ValidationError, match="exactly one"):
        models.Eval.model_validate(both)


def test_recursive_workflow_bounds_remain_enforced() -> None:
    with pytest.raises(ValidationError):
        models.ParallelStep.model_validate(
            {
                "parallel": [
                    {"call": {"operation": f"crm.op_{index}", "arguments": {}}}
                    for index in range(9)
                ]
            }
        )
    with pytest.raises(ValidationError):
        models.ForeachStep.model_validate(
            {
                "foreach": {
                    "items": "$.input.items",
                    "item_name": "item",
                    "max_items": 101,
                    "workflow": [{"emit": {"value": "$.item"}}],
                }
            }
        )


@pytest.mark.parametrize(
    ("adapter", "document"),
    [
        (TypeAdapter(models.Operation), operation_document()),
        (TypeAdapter(models.Capability), capability_document()),
    ],
)
def test_discriminated_documents_reject_unknown_fields(
    adapter: TypeAdapter[object],
    document: dict[str, object],
) -> None:
    document["unknown"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        adapter.validate_python(document)
