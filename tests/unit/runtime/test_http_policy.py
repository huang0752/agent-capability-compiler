from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from typing import Any

import httpx
import pytest
from pydantic import JsonValue

from acc_core.models import Operation, Policy
from acc_runtime.errors import RuntimeError as ACCRuntimeError
from acc_runtime.policies import PolicyEnforcer
from acc_runtime.providers import HttpProvider


class StaticSecretResolver:
    def __init__(self, values: Mapping[str, str]) -> None:
        self.values = values

    def resolve(self, reference: str) -> str:
        return self.values[reference]


def _operation(**http_overrides: Any) -> Operation:
    http = {
        "method": "GET",
        "path": "/customers/{customer_id}",
        "path_parameters": {"customer_id": "customer_id"},
        "query_parameters": {"include": "include"},
        "credential_ref": "CRM_USER_TOKEN",
        "scopes": ["customer.read"],
        "timeout_seconds": 15,
        "max_response_bytes": 1_048_576,
    }
    http.update(http_overrides)
    return Operation.model_validate(
        {
            "schema_version": "1",
            "id": "crm.get_customer",
            "title": "Get customer",
            "kind": "http",
            "input_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {
                    "customer_id": {"type": "string"},
                    "include": {"type": "string"},
                },
            },
            "output_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}},
            },
            "http": http,
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": "crm",
                    "locator": "openapi.json#/customers/{customer_id}",
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        }
    )


def _client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_http_provider_encodes_paths_maps_queries_and_injects_secret() -> None:
    captured: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured
        captured = request
        return httpx.Response(200, json={"id": "customer/one"})

    async with _client(handler) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        result = await provider.execute(
            _operation(), {"customer_id": "customer/one", "include": "contacts & notes"}
        )

    assert result == {"id": "customer/one"}
    assert captured is not None
    assert captured.url.raw_path == b"/customers/customer%2Fone?include=contacts%20%26%20notes"
    assert captured.url.host == "crm.example.test"
    assert captured.headers["authorization"] == "Bearer private-token"


@pytest.mark.asyncio
async def test_http_provider_call_accepts_compiled_operation_mapping() -> None:
    async with _client(lambda request: httpx.Response(200, json={"id": "one"})) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        result = await provider.call(
            _operation().model_dump(mode="json"),
            {"customer_id": "one"},
        )

    assert result == {"id": "one"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://crm.example.test",
        "https://user:password@crm.example.test",
        "https://crm.example.test/api",
        "https://crm.example.test?target=other",
        "https://crm.example.test#fragment",
        "//crm.example.test",
    ],
)
async def test_http_provider_rejects_base_urls_that_are_not_fixed_http_origins(
    base_url: str,
) -> None:
    client = _client(lambda request: httpx.Response(200, json={"id": "unused"}))
    provider = HttpProvider(
        base_url_ref="CRM_BASE_URL",
        environment={"CRM_BASE_URL": base_url},
        secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
        client=client,
    )

    with pytest.raises(ACCRuntimeError) as caught:
        await provider.execute(_operation(), {"customer_id": "one"})

    assert caught.value.code == "ACC_RUNTIME_HTTP_BASE_URL_INVALID"
    assert caught.value.status == 500
    assert "private-token" not in str(caught.value.to_dict())
    await client.aclose()


@pytest.mark.asyncio
async def test_http_provider_validates_declared_input_schema_before_network() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"id": "unused"})

    async with _client(handler) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(_operation(), {"customer_id": 42, "token": "attacker"})

    assert caught.value.code == "ACC_RUNTIME_INPUT_SCHEMA_INVALID"
    assert caught.value.status == 400
    assert called is False


@pytest.mark.asyncio
async def test_http_provider_rejects_non_finite_query_numbers_before_network() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"id": "unused"})

    operation = _operation().model_copy(
        update={
            "input_schema": {
                "type": "object",
                "required": ["customer_id", "include"],
                "properties": {
                    "customer_id": {"type": "string"},
                    "include": {"type": "number"},
                },
            }
        }
    )
    async with _client(handler) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(operation, {"customer_id": "one", "include": float("nan")})

    assert caught.value.code == "ACC_RUNTIME_INPUT_SCHEMA_INVALID"
    assert called is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected_code", "expected_status"),
    [
        (httpx.Response(403, text="secret response"), "ACC_RUNTIME_HTTP_FORBIDDEN", 403),
        (httpx.Response(404, text="secret response"), "ACC_RUNTIME_HTTP_NOT_FOUND", 404),
        (httpx.Response(500, text="secret response"), "ACC_RUNTIME_HTTP_UPSTREAM_ERROR", 502),
        (httpx.Response(200, text="not-json"), "ACC_RUNTIME_HTTP_INVALID_JSON", 502),
        (httpx.Response(200, json={"wrong": True}), "ACC_RUNTIME_OUTPUT_SCHEMA_INVALID", 502),
    ],
)
async def test_http_provider_maps_failures_without_logging_response_or_token(
    response: httpx.Response,
    expected_code: str,
    expected_status: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with _client(lambda request: response) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        with caplog.at_level(logging.WARNING), pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(_operation(), {"customer_id": "one"})

    assert caught.value.code == expected_code
    assert caught.value.status == expected_status
    assert "private-token" not in caplog.text
    assert "secret response" not in caplog.text
    assert "not-json" not in caplog.text


@pytest.mark.asyncio
async def test_http_provider_maps_timeout_to_stable_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("upstream included a secret", request=request)

    async with _client(handler) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(_operation(), {"customer_id": "one"})

    assert caught.value.code == "ACC_RUNTIME_HTTP_TIMEOUT"
    assert caught.value.status == 504
    assert "secret" not in str(caught.value.to_dict())


@pytest.mark.asyncio
async def test_http_provider_stops_when_streamed_response_exceeds_limit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"id":"too large"}')

    async with _client(handler) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(_operation(max_response_bytes=5), {"customer_id": "one"})

    assert caught.value.code == "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"
    assert caught.value.status == 502
    assert caught.value.details == {"operation": "crm.get_customer", "limit_bytes": 5}


@pytest.mark.asyncio
async def test_head_returns_an_empty_object_without_parsing_a_body() -> None:
    async with _client(lambda request: httpx.Response(200)) as client:
        provider = HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            secret_resolver=StaticSecretResolver({"CRM_USER_TOKEN": "private-token"}),
            client=client,
        )
        result = await provider.execute(
            _operation(
                method="HEAD",
                query_parameters={},
            ).model_copy(update={"output_schema": {"type": "object", "maxProperties": 0}}),
            {"customer_id": "one"},
        )

    assert result == {}


def _policy(**overrides: Any) -> Policy:
    document = {
        "schema_version": "1",
        "id": "crm-read",
        "required_scopes": ["customer.read", "tenant.read"],
        "tenant_mode": "required",
        "tenant_field": "context.tenant_id",
        "readable_fields": [
            "customer.id",
            "customer.name",
            "customer.email",
            "customer.profile",
            "contacts.name",
            "contacts.email",
        ],
        "denied_fields": ["customer.profile.ssn"],
        "redaction_rules": [
            {"path": "customer.email", "strategy": "mask"},
            {"path": "customer.profile.phone", "strategy": "hash"},
            {"path": "contacts.email", "strategy": "remove"},
        ],
    }
    document.update(overrides)
    return Policy.model_validate(document)


def test_policy_requires_every_scope_in_stable_order() -> None:
    with pytest.raises(ACCRuntimeError) as caught:
        PolicyEnforcer().authorize(
            _policy(),
            granted_scopes={"unrelated"},
            arguments={"context": {"tenant_id": "tenant-a"}},
            tenant_id="tenant-a",
        )

    assert caught.value.code == "ACC_RUNTIME_POLICY_SCOPE_DENIED"
    assert caught.value.status == 403
    assert caught.value.details == {
        "policy": "crm-read",
        "missing_scopes": ["customer.read", "tenant.read"],
    }


@pytest.mark.parametrize(
    "arguments",
    [{}, {"context": {}}, {"context": {"tenant_id": "tenant-b"}}],
)
def test_policy_rejects_missing_or_cross_tenant_input(arguments: Mapping[str, Any]) -> None:
    with pytest.raises(ACCRuntimeError) as caught:
        PolicyEnforcer().authorize(
            _policy(),
            granted_scopes={"customer.read", "tenant.read"},
            arguments=arguments,
            tenant_id="tenant-a",
        )

    assert caught.value.code == "ACC_RUNTIME_POLICY_TENANT_DENIED"
    assert caught.value.status == 403
    assert caught.value.details == {"policy": "crm-read", "tenant_field": "context.tenant_id"}


def test_policy_recursively_filters_denies_and_redacts_objects_and_arrays() -> None:
    source: dict[str, JsonValue] = {
        "unrelated": "drop",
        "contacts": [
            {"email": "one@example.test", "name": "One", "token": "drop"},
            {"email": "two@example.test", "name": "Two", "token": "drop"},
        ],
        "customer": {
            "profile": {"phone": "+86-123", "ssn": "drop", "note": "kept by parent"},
            "email": "customer@example.test",
            "name": "Customer",
            "id": "c-1",
            "token": "drop",
        },
    }

    filtered = PolicyEnforcer().filter_output(_policy(), source)

    phone_hash = hashlib.sha256(b'"+86-123"').hexdigest()
    assert filtered == {
        "contacts": [{"name": "One"}, {"name": "Two"}],
        "customer": {
            "email": "***",
            "id": "c-1",
            "name": "Customer",
            "profile": {
                "note": "kept by parent",
                "phone": f"sha256:{phone_hash}",
            },
        },
    }
    customer = source["customer"]
    assert isinstance(customer, dict)
    assert customer["email"] == "customer@example.test"


def test_policy_accepts_jsonpath_style_redaction_paths_from_the_public_model() -> None:
    policy = _policy(
        tenant_mode="none",
        tenant_field=None,
        required_scopes=[],
        readable_fields=["email"],
        denied_fields=[],
        redaction_rules=[{"path": "$.email", "strategy": "mask"}],
    )

    filtered = PolicyEnforcer().filter_output(policy, {"email": "private@example.test"})

    assert filtered == {"email": "***"}


def test_policy_enforce_authorizes_then_returns_filtered_copy() -> None:
    result = PolicyEnforcer().enforce(
        _policy(
            tenant_mode="none",
            tenant_field=None,
            required_scopes=[],
            readable_fields=["id"],
            denied_fields=[],
            redaction_rules=[],
        ),
        granted_scopes=set(),
        arguments={},
        tenant_id=None,
        output={"secret": "drop", "id": "c-1"},
    )

    assert result == {"id": "c-1"}
