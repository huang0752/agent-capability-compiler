from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy

import pytest
from pydantic import ValidationError

import acc_core.models as models


def project_document() -> dict[str, object]:
    return {
        "schema_version": "1",
        "project": {"id": "example-crm", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
    }


def password_bearer_auth(*, credential_kind: str = "environment_secret") -> dict[str, object]:
    credentials: dict[str, object] = {"kind": credential_kind}
    if credential_kind == "environment_secret":
        credentials.update(
            identity_ref="CRM_USER_EMAIL",
            password_ref="CRM_USER_PASSWORD",
        )
    return {
        "kind": "password_bearer",
        "credentials": credentials,
        "login_path": "/api/auth/login",
        "identity_field": "email",
        "password_field": "password",
        "token_pointer": "/data/access_token",
    }


def evidence_document() -> dict[str, object]:
    return {
        "source_id": "crm-backend",
        "kind": "source_file",
        "path": "app/api/customers.py",
        "line_start": 42,
        "line_end": 68,
        "digest": f"sha256:{'a' * 64}",
    }


def operation_document() -> dict[str, object]:
    return {
        "schema_version": "1",
        "id": "crm.get_customer",
        "title": "Get customer",
        "kind": "http",
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
            "credential_ref": "CRM_USER_TOKEN",
            "scopes": ["customer.read"],
            "timeout_seconds": 15,
            "max_response_bytes": 1_048_576,
        },
        "safety": {"effect": "read"},
        "evidence": [evidence_document()],
    }


def test_project_models_the_milestone_one_contract() -> None:
    project = models.Project.model_validate(project_document())

    assert project.project.id == "example-crm"
    assert project.source_workspace.mode == "read_only"
    assert project.runtime.transport == ["stdio"]
    assert project.provider.base_url_ref == "CRM_BASE_URL"
    assert project.provider.context_binding_allowlist == []


def test_provider_accepts_sorted_unique_tenant_context_binding_allowlist() -> None:
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
        ["tenant_context"],
        ["tenant_context.z_field", "tenant_context.a_field"],
    ],
)
def test_provider_rejects_duplicate_invalid_or_unsorted_context_binding_allowlist(
    allowlist: list[str],
) -> None:
    document = project_document()
    provider = deepcopy(document["provider"])
    assert isinstance(provider, dict)
    provider["context_binding_allowlist"] = allowlist
    document["provider"] = provider

    with pytest.raises(ValidationError, match="context_binding_allowlist"):
        models.Project.model_validate(document)


@pytest.mark.parametrize(
    "source",
    [
        "tenant_context.token",
        "tenant_context.secret",
        "tenant_context.password",
        "tenant_context.header",
        "tenant_context.headers",
        "tenant_context.authorization",
        "tenant_context.credential",
        "tenant_context.credentials",
        "tenant_context.cookie",
        "tenant_context.cookies",
        "tenant_context.jwt",
        "tenant_context.bearer",
        "tenant_context.csrf",
        "tenant_context.profile.accessToken",
        "tenant_context.profile.refresh-token",
        "tenant_context.auth_token",
        "tenant_context.clientSecret",
        "tenant_context.session-token",
        "tenant_context.setCookie",
        "tenant_context.api-key",
        "tenant_context.privateKey",
        "tenant_context.idToken",
        "tenant_context.oauthToken",
        "tenant_context.apiToken",
        "tenant_context.jwtToken",
        "tenant_context.passwordHash",
        "tenant_context.xApiKey",
        "tenant_context.authorizationHeader",
    ],
)
def test_provider_rejects_sensitive_context_binding_allowlist_paths(source: str) -> None:
    document = project_document()
    provider = deepcopy(document["provider"])
    assert isinstance(provider, dict)
    provider["context_binding_allowlist"] = [source]
    document["provider"] = provider

    with pytest.raises(ValidationError, match="sensitive"):
        models.Project.model_validate(document)


@pytest.mark.parametrize(
    ("auth", "auth_type"),
    [
        ({"kind": "none"}, "NoAuthConfig"),
        (
            {"kind": "bearer_secret", "token_ref": "CRM_USER_TOKEN"},
            "BearerSecretAuthConfig",
        ),
        (password_bearer_auth(), "PasswordBearerAuthConfig"),
        (
            password_bearer_auth(credential_kind="gateway_session"),
            "PasswordBearerAuthConfig",
        ),
    ],
)
def test_project_accepts_strict_provider_auth_union(
    auth: dict[str, object], auth_type: str
) -> None:
    document = project_document()
    provider = deepcopy(document["provider"])
    assert isinstance(provider, dict)
    provider["auth"] = auth
    document["provider"] = provider

    project = models.Project.model_validate(document)

    assert type(project.provider.auth).__name__ == auth_type


def test_password_bearer_auth_defaults_are_bounded_and_safe() -> None:
    auth = models.PasswordBearerAuthConfig.model_validate(password_bearer_auth())

    assert isinstance(auth.credentials, models.EnvironmentSecretCredentials)
    assert auth.timeout_seconds == 10
    assert auth.max_response_bytes == 65_536
    assert auth.retry_on_unauthorized is False
    assert auth.scope_mapping == {}

    for field, value in (
        ("timeout_seconds", 0),
        ("timeout_seconds", 301),
        ("max_response_bytes", 0),
        ("max_response_bytes", 1_048_577),
    ):
        document = password_bearer_auth()
        document[field] = value
        with pytest.raises(ValidationError, match=field):
            models.PasswordBearerAuthConfig.model_validate(document)


@pytest.mark.parametrize(
    "path",
    [
        "https://crm.example.com/api/auth/login",
        "//crm.example.com/api/auth/login",
        "/api/auth/../admin",
        "api/auth/login",
        "/api/auth/login?next=/admin",
        "/api/auth/login#fragment",
        "/api\\auth\\login",
    ],
)
def test_password_bearer_rejects_unsafe_login_path(path: str) -> None:
    document = password_bearer_auth()
    document["login_path"] = path

    with pytest.raises(ValidationError, match="login_path"):
        models.PasswordBearerAuthConfig.model_validate(document)


@pytest.mark.parametrize(
    "pointer",
    ["", "data/token", "/data/~2token", "/data/token~"],
)
def test_password_bearer_rejects_invalid_absolute_json_pointer(pointer: str) -> None:
    document = password_bearer_auth()
    document["token_pointer"] = pointer

    with pytest.raises(ValidationError):
        models.PasswordBearerAuthConfig.model_validate(document)


def test_password_bearer_accepts_all_optional_json_pointers_and_scope_mapping() -> None:
    document = password_bearer_auth(credential_kind="gateway_session")
    document.update(
        token_type_pointer="/data/token~0type",
        expires_in_pointer="/data/expires~1in",
        principal_pointer="/data/user/id",
        scopes_pointer="/data/permissions",
        tenant_pointer="/data/tenant",
        scope_mapping={"customer:read": ["customer.read"]},
        timeout_seconds=300,
        max_response_bytes=1_048_576,
        retry_on_unauthorized=True,
    )

    auth = models.PasswordBearerAuthConfig.model_validate(document)

    assert isinstance(auth.credentials, models.GatewaySessionCredentials)
    assert auth.scope_mapping == {"customer:read": ["customer.read"]}


def test_password_bearer_requires_distinct_identity_and_password_fields() -> None:
    document = password_bearer_auth()
    document["password_field"] = "email"

    with pytest.raises(ValidationError, match="identity_field"):
        models.PasswordBearerAuthConfig.model_validate(document)


def test_runtime_transport_remains_a_single_selected_mode() -> None:
    assert models.RuntimeConfig.model_validate({"transport": ["streamable_http"]}).transport == [
        "streamable_http"
    ]
    with pytest.raises(ValidationError):
        models.RuntimeConfig.model_validate({"transport": ["stdio", "streamable_http"]})


def test_evidence_supports_source_lines_json_pointer_openapi_and_summary() -> None:
    evidence = models.Evidence.model_validate(
        {
            **evidence_document(),
            "json_pointer": "/paths/~1customers~1{customer_id}/get",
            "openapi_operation": "getCustomer",
            "summary": "GET route is protected by customer.read.",
        }
    )

    assert evidence.line_start == 42
    assert evidence.json_pointer is not None
    assert evidence.json_pointer.startswith("/")
    assert evidence.openapi_operation == "getCustomer"


def test_evidence_rejects_an_inverted_line_range() -> None:
    document = evidence_document()
    document["line_start"] = 68
    document["line_end"] = 42

    with pytest.raises(ValidationError, match="line_end"):
        models.Evidence.model_validate(document)


def test_operation_evidence_reference_can_use_a_digest_bound_locator() -> None:
    evidence = models.Evidence.model_validate(
        {
            "source_id": "crm-backend",
            "locator": "app/api/customers.py#L42-L68",
            "digest": f"sha256:{'a' * 64}",
        }
    )

    assert evidence.kind is None
    assert evidence.locator == "app/api/customers.py#L42-L68"


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_operation_accepts_only_supported_read_methods(method: str) -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["method"] = method
    document["http"] = http

    operation = models.Operation.model_validate(document)

    assert operation.http.method == method
    assert operation.safety.effect == "read"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_operation_rejects_write_methods(method: str) -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["method"] = method
    document["http"] = http

    with pytest.raises(ValidationError):
        models.Operation.model_validate(document)


@pytest.mark.parametrize(
    "path",
    [
        "https://crm.example.com/customers/1",
        "//crm.example.com/customers/1",
        "/customers/../admin",
        "customers/1",
    ],
)
def test_operation_rejects_non_origin_relative_or_traversing_paths(path: str) -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["path"] = path
    document["http"] = http

    with pytest.raises(ValidationError, match="path"):
        models.Operation.model_validate(document)


def test_operation_requires_evidence_input_output_schemas_and_read_effect() -> None:
    mutations: tuple[Callable[[dict[str, object]], object], ...] = (
        lambda document: document.update(evidence=[]),
        lambda document: document.pop("input_schema"),
        lambda document: document.pop("output_schema"),
        lambda document: document.update(safety={"effect": "write"}),
    )
    for mutation in mutations:
        document = operation_document()
        mutation(document)

        with pytest.raises(ValidationError):
            models.Operation.model_validate(document)


def test_operation_accepts_locator_only_evidence_reference() -> None:
    document = operation_document()
    document["evidence"] = [
        {
            "source_id": "crm-backend",
            "locator": "app/api/customers.py#L42-L68",
            "digest": f"sha256:{'b' * 64}",
        }
    ]

    operation = models.Operation.model_validate(document)

    assert operation.evidence[0].locator == "app/api/customers.py#L42-L68"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_schema", {"type": "not-a-json-schema-type"}),
        ("output_schema", {"required": "must-be-an-array"}),
    ],
)
def test_operation_rejects_invalid_json_schemas(field: str, value: object) -> None:
    document = operation_document()
    document[field] = value

    with pytest.raises(ValidationError, match="JSON Schema"):
        models.Operation.model_validate(document)


def test_operation_rejects_non_environment_secret_reference() -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["credential_ref"] = "token-from-user-input"
    document["http"] = http

    with pytest.raises(ValidationError, match="credential_ref"):
        models.Operation.model_validate(document)


def test_operation_supports_declared_query_parameters() -> None:
    document = operation_document()
    input_schema = deepcopy(document["input_schema"])
    assert isinstance(input_schema, dict)
    properties = input_schema["properties"]
    assert isinstance(properties, dict)
    properties["include_contacts"] = {"type": "boolean"}
    document["input_schema"] = input_schema
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["query_parameters"] = {"include_contacts": "include_contacts"}
    document["http"] = http

    operation = models.Operation.model_validate(document)

    assert operation.http.query_parameters == {"include_contacts": "include_contacts"}


def test_operation_supports_optional_legacy_credential_and_context_bindings() -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http.pop("credential_ref")
    document["http"] = http
    document["context_bindings"] = {
        "customer_id": "tenant_context.customer_id",
    }

    operation = models.Operation.model_validate(document)

    assert operation.http.credential_ref is None
    assert operation.context_bindings == {
        "customer_id": "tenant_context.customer_id",
    }


@pytest.mark.parametrize(
    "source",
    [
        "principal_id",
        "tenant_context.tenant_id",
        "tenant_context.organization.region-id",
    ],
)
def test_operation_accepts_only_safe_context_binding_sources(source: str) -> None:
    document = operation_document()
    document["context_bindings"] = {"customer_id": source}

    operation = models.Operation.model_validate(document)

    assert operation.context_bindings["customer_id"] == source


@pytest.mark.parametrize(
    "source",
    [
        "tenant_context.secretary_id",
        "tenant_context.header_image",
        "tenant_context.tokenized_region",
    ],
)
def test_operation_does_not_substring_block_safe_context_binding_sources(
    source: str,
) -> None:
    document = operation_document()
    document["context_bindings"] = {"customer_id": source}

    operation = models.Operation.model_validate(document)

    assert operation.context_bindings["customer_id"] == source


@pytest.mark.parametrize(
    "source",
    [
        "tenant_context.token",
        "tenant_context.profile.accessToken",
        "tenant_context.profile.refresh-token",
        "tenant_context.auth_token",
        "tenant_context.clientSecret",
        "tenant_context.session-token",
        "tenant_context.setCookie",
        "tenant_context.api-key",
        "tenant_context.privateKey",
        "tenant_context.idToken",
        "tenant_context.oauthToken",
        "tenant_context.apiToken",
        "tenant_context.jwtToken",
        "tenant_context.passwordHash",
        "tenant_context.xApiKey",
        "tenant_context.authorizationHeader",
    ],
)
def test_operation_rejects_sensitive_context_binding_paths(source: str) -> None:
    document = operation_document()
    document["context_bindings"] = {"customer_id": source}

    with pytest.raises(ValidationError, match="sensitive"):
        models.Operation.model_validate(document)


@pytest.mark.parametrize(
    "source",
    [
        "tenant_context",
        "tenant_context.",
        "tenant_context..tenant_id",
        "gateway_session_id",
        "target_system_id",
        "auth_state_handle",
        "source_scopes",
        "deployment_scope_ceiling",
        "effective_scopes",
        "token",
        "password",
        "header.authorization",
        "credential",
        "tenant_context._private",
    ],
)
def test_operation_rejects_untrusted_context_binding_sources(source: str) -> None:
    document = operation_document()
    document["context_bindings"] = {"customer_id": source}

    with pytest.raises(ValidationError, match="context_bindings"):
        models.Operation.model_validate(document)


def test_operation_parameter_mappings_must_reference_declared_inputs() -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["query_parameters"] = {"q": "undeclared"}
    document["http"] = http

    with pytest.raises(ValidationError, match="declared input"):
        models.Operation.model_validate(document)


def test_operation_path_placeholders_require_an_exact_mapping() -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["path_parameters"] = {}
    document["http"] = http

    with pytest.raises(ValidationError, match="path_parameters"):
        models.Operation.model_validate(document)


def test_evidence_digest_must_be_a_complete_sha256() -> None:
    document = evidence_document()
    document["digest"] = "sha256:abcd"

    with pytest.raises(ValidationError, match="digest"):
        models.Evidence.model_validate(document)


def test_policy_and_eval_cover_security_and_fake_system_expectations() -> None:
    policy = models.Policy.model_validate(
        {
            "schema_version": "1",
            "id": "crm-sales-read",
            "required_scopes": ["customer.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["id", "name", "email"],
            "denied_fields": ["internal_note"],
            "redaction_rules": [{"path": "$.email", "strategy": "mask"}],
        }
    )
    scenario = models.Eval.model_validate(
        {
            "schema_version": "1",
            "id": "get-customer-context-normal",
            "capability": "get_customer_context",
            "input": {"customer_id": "cus-1"},
            "fixtures": {"customers": [{"id": "cus-1", "tenant_id": "tenant-a"}]},
            "expected_calls": [
                {
                    "operation": "crm.get_customer",
                    "arguments": {"customer_id": "cus-1"},
                }
            ],
            "expected_output_schema": {"type": "object", "required": ["customer"]},
            "forbidden_fields": ["internal_note"],
        }
    )

    assert policy.tenant_mode == "required"
    assert policy.tenant_field == "tenant_id"
    assert policy.tenant_field == "tenant_id"
    assert scenario.expected_calls[0].operation == "crm.get_customer"
    assert scenario.expected_error is None


def test_eval_can_describe_an_expected_error() -> None:
    scenario = models.Eval.model_validate(
        {
            "schema_version": "1",
            "id": "get-customer-context-not-found",
            "capability": "get_customer_context",
            "input": {"customer_id": "missing"},
            "fixtures": {},
            "expected_calls": [],
            "expected_error": {"code": "NOT_FOUND", "status": 404},
            "forbidden_fields": [],
        }
    )

    assert scenario.expected_error is not None
    assert scenario.expected_error.status == 404


def test_capability_supports_the_bounded_workflow_step_union() -> None:
    capability = models.Capability.model_validate(
        {
            "schema_version": "1",
            "id": "get_customer_context",
            "title": "Get customer context",
            "description": "Combine customer information without exposing credentials.",
            "input_schema": {"type": "object", "additionalProperties": False},
            "output_schema": {"type": "object"},
            "workflow": [
                {
                    "id": "customer",
                    "call": {
                        "operation": "crm.get_customer",
                        "arguments": {"customer_id": "$.input.customer_id"},
                    },
                },
                {"id": "picked", "pick": {"value": "$.steps.customer", "fields": ["id"]}},
                {
                    "id": "mapped",
                    "map": {
                        "items": "$.steps.contacts",
                        "expression": "{id: id}",
                        "max_items": 100,
                    },
                },
                {
                    "id": "filtered",
                    "filter": {
                        "items": "$.steps.followups",
                        "condition": "status == 'overdue'",
                        "max_items": 100,
                    },
                },
                {"assert": {"condition": "$.steps.customer != null", "message": "missing"}},
                {"id": "safe", "redact": {"value": "$.steps.customer", "fields": ["email"]}},
                {
                    "branch": {
                        "condition": "$.input.include_contacts",
                        "then": [{"emit": {"value": "$.steps.safe"}}],
                        "else": [{"emit": {"value": {}}}],
                    }
                },
                {
                    "parallel": [
                        {"call": {"operation": "crm.list_contacts", "arguments": {}}},
                        {"call": {"operation": "crm.list_followups", "arguments": {}}},
                    ]
                },
                {
                    "id": "contact_names",
                    "foreach": {
                        "items": "$.steps.contacts",
                        "item_name": "contact",
                        "max_items": 100,
                        "workflow": [{"emit": {"value": "$.item.name"}}],
                    },
                },
                {"emit": {"value": {"customer": "$.steps.customer"}}},
            ],
            "policy": "crm-sales-read",
            "evals": ["get-customer-context-normal"],
        }
    )

    assert len(capability.workflow) == 10
    assert isinstance(capability.workflow[0], models.CallStep)
    assert isinstance(capability.workflow[-1], models.EmitStep)


def test_parallel_and_foreach_bounds_are_enforced() -> None:
    too_many_parallel_calls = [
        {"call": {"operation": f"crm.operation_{index}", "arguments": {}}} for index in range(9)
    ]

    with pytest.raises(ValidationError):
        models.ParallelStep.model_validate({"parallel": too_many_parallel_calls})
    with pytest.raises(ValidationError):
        models.ForeachStep.model_validate(
            {
                "foreach": {
                    "items": "$.items",
                    "item_name": "item",
                    "max_items": 101,
                    "workflow": [{"emit": {"value": "$.item"}}],
                }
            }
        )


@pytest.mark.parametrize(
    ("model_name", "document"),
    [
        ("Project", project_document()),
        ("Evidence", evidence_document()),
        ("Operation", operation_document()),
        (
            "Policy",
            {
                "schema_version": "1",
                "id": "crm-read",
                "required_scopes": [],
                "tenant_mode": "none",
                "readable_fields": [],
                "denied_fields": [],
                "redaction_rules": [],
            },
        ),
        (
            "Eval",
            {
                "schema_version": "1",
                "id": "normal",
                "capability": "search_customers",
                "input": {},
                "fixtures": {},
                "expected_calls": [],
                "expected_output_schema": {"type": "object"},
                "forbidden_fields": [],
            },
        ),
        (
            "Capability",
            {
                "schema_version": "1",
                "id": "search_customers",
                "title": "Search customers",
                "description": "Search visible customers.",
                "input_schema": {"type": "object"},
                "output_schema": {"type": "array"},
                "workflow": [{"emit": {"value": []}}],
                "policy": "crm-read",
                "evals": ["normal"],
            },
        ),
    ],
)
def test_all_public_models_reject_unknown_fields(
    model_name: str, document: dict[str, object]
) -> None:
    document["unknown"] = True
    model_type = getattr(models, model_name)

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model_type.model_validate(document)


def test_nested_public_models_also_reject_unknown_fields() -> None:
    document = operation_document()
    http = deepcopy(document["http"])
    assert isinstance(http, dict)
    http["headers"] = {"Authorization": "token"}
    document["http"] = http

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        models.Operation.model_validate(document)
