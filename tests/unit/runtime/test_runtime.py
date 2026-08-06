from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue

import acc_runtime
from acc_runtime.auth import (
    BearerSecretAuthStrategy,
    NoAuthStrategy,
    PasswordBearerAuthStrategy,
)
from acc_runtime.context import PrincipalContext
from acc_runtime.policies import PolicyScopeDeniedError
from acc_runtime.providers import HttpProvider
from acc_runtime.runtime import ContextOperationProvider, GenericRuntime, RuntimeConfigurationError


def _ir() -> dict[str, Any]:
    operation = {
        "schema_version": "1",
        "id": "crm.get_customer",
        "title": "Get customer",
        "kind": "http",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["customer_id"],
            "properties": {
                "customer_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
        },
        "output_schema": {"type": "object"},
        "http": {
            "method": "GET",
            "path": "/customers/{customer_id}",
            "path_parameters": {"customer_id": "customer_id"},
            "query_parameters": {},
            "credential_ref": "CRM_TOKEN",
            "scopes": ["customer.read", "customer.detail"],
            "timeout_seconds": 15,
            "max_response_bytes": 1048576,
        },
        "safety": {"effect": "read"},
        "evidence": [
            {
                "source_id": "crm",
                "locator": "routes.py#L1-L5",
                "digest": f"sha256:{'a' * 64}",
            }
        ],
    }
    policy = {
        "schema_version": "1",
        "id": "crm-read",
        "required_scopes": ["customer.read"],
        "tenant_mode": "required",
        "tenant_field": "tenant_id",
        "readable_fields": ["id", "name", "tenant_id"],
        "denied_fields": ["secret"],
        "redaction_rules": [],
    }
    capability = {
        "schema_version": "1",
        "id": "get_customer",
        "title": "Get customer",
        "description": "Get one visible customer.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["customer_id"],
            "properties": {"customer_id": {"type": "string"}},
        },
        "output_schema": {
            "type": "object",
            "required": ["id", "name", "tenant_id"],
        },
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
        "evals": ["normal", "forbidden"],
    }
    return {
        "ir_version": "1",
        "project": {
            "schema_version": "1",
            "project": {"id": "crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_URL"},
        },
        "operations": {"crm.get_customer": operation},
        "policies": {"crm-read": policy},
        "evals": {},
        "capabilities": {
            "get_customer": {
                "definition": capability,
                "operation_dependencies": ["crm.get_customer"],
            }
        },
    }


def test_context_provider_protocol_is_available_from_the_runtime_package() -> None:
    assert acc_runtime.ContextOperationProvider is ContextOperationProvider


class FakeProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        self.calls.append((str(operation["id"]), dict(arguments)))
        return {
            "id": str(arguments["customer_id"]),
            "name": "Ada",
            "tenant_id": str(arguments["tenant_id"]),
            "secret": "must-not-leave-runtime",
        }


class ContextAwareProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []
        self.contexts: list[PrincipalContext] = []

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        self.contexts.append(principal_context)
        self.calls.append((str(operation["id"]), dict(arguments)))
        return {
            "id": str(arguments["customer_id"]),
            "name": "Ada",
            "tenant_id": str(arguments.get("tenant_id", "")),
            "secret": "must-not-leave-runtime",
        }


def _principal(
    principal_id: str,
    *,
    source_scopes: set[str] | None = None,
    ceiling: set[str] | None = None,
    tenant_context: Mapping[str, object] | None = None,
    scope_mapping: Mapping[str, set[str]] | None = None,
) -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal_id,
        gateway_session_id=None,
        target_system_id="crm",
        source_scopes=source_scopes,
        deployment_scope_ceiling=ceiling or {"customer.read", "customer.detail"},
        tenant_context=tenant_context,
        auth_state_handle=f"auth-{principal_id}",
        scope_mapping=scope_mapping,
    )


@pytest.mark.asyncio
async def test_generic_runtime_injects_context_enforces_scopes_and_filters_output() -> None:
    provider = FakeProvider()
    runtime = GenericRuntime(
        _ir(),
        provider=provider,
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="tenant-a",
    )

    result = await runtime.call("get_customer", {"customer_id": "c-1"})

    assert provider.calls == [
        (
            "crm.get_customer",
            {"customer_id": "c-1", "tenant_id": "tenant-a"},
        )
    ]
    assert result == {"id": "c-1", "name": "Ada", "tenant_id": "tenant-a"}
    assert "must-not-leave-runtime" not in repr(result)


@pytest.mark.asyncio
async def test_generic_runtime_filters_before_validating_public_output_schema() -> None:
    ir = _ir()
    policy = ir["policies"]["crm-read"]
    policy["readable_fields"] = ["id", "name"]
    capability = ir["capabilities"]["get_customer"]["definition"]
    capability["output_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "name"],
        "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
    }
    runtime = GenericRuntime(
        ir,
        provider=FakeProvider(),
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="tenant-a",
    )

    result = await runtime.call("get_customer", {"customer_id": "c-1"})

    assert result == {"id": "c-1", "name": "Ada"}


def test_generic_runtime_exposes_stable_tool_contracts() -> None:
    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="tenant-a",
    )

    assert runtime.tools() == [
        {
            "name": "get_customer",
            "title": "Get customer",
            "description": "Get one visible customer.",
            "input_schema": _ir()["capabilities"]["get_customer"]["definition"]["input_schema"],
            "output_schema": _ir()["capabilities"]["get_customer"]["definition"]["output_schema"],
        }
    ]


@pytest.mark.asyncio
async def test_generic_runtime_requires_operation_and_policy_scopes() -> None:
    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        granted_scopes={"customer.read"},
        tenant_id="tenant-a",
    )

    with pytest.raises(PolicyScopeDeniedError) as caught:
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert caught.value.details == {
        "policy": "crm-read",
        "missing_scopes": ["customer.detail"],
    }


@pytest.mark.asyncio
async def test_call_with_context_passes_the_explicit_principal_to_the_provider() -> None:
    provider = ContextAwareProvider()
    bound = _principal("bound", tenant_context={"tenant_id": "tenant-bound"})
    request = _principal("request", tenant_context={"tenant_id": "tenant-request"})
    runtime = GenericRuntime(_ir(), provider=provider, principal_context=bound)

    await runtime.call_with_context("get_customer", {"customer_id": "c-1"}, request)

    assert provider.contexts == [request]


@pytest.mark.asyncio
async def test_legacy_call_always_uses_the_principal_bound_at_construction() -> None:
    provider = ContextAwareProvider()
    bound = _principal("bound", tenant_context={"tenant_id": "tenant-bound"})
    runtime = GenericRuntime(_ir(), provider=provider, principal_context=bound)

    await runtime.call("get_customer", {"customer_id": "c-1"})

    assert provider.contexts == [bound]


@pytest.mark.asyncio
async def test_call_with_context_rejects_a_principal_for_another_target_system() -> None:
    principal = PrincipalContext(
        principal_id="user-a",
        gateway_session_id=None,
        target_system_id="another-system",
        source_scopes=None,
        deployment_scope_ceiling={"customer.read", "customer.detail"},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle="other-auth",
    )
    runtime = GenericRuntime(
        _ir(),
        provider=ContextAwareProvider(),
        principal_context=_principal("bound"),
    )

    with pytest.raises(RuntimeConfigurationError) as caught:
        await runtime.call_with_context("get_customer", {"customer_id": "c-1"}, principal)

    assert caught.value.details == {"reason": "principal_target_mismatch"}


@pytest.mark.asyncio
async def test_policy_uses_only_the_principal_effective_scopes() -> None:
    principal = _principal(
        "limited",
        source_scopes={"source.customer"},
        ceiling={"customer.read", "customer.detail"},
        scope_mapping={"source.customer": {"customer.read"}},
        tenant_context={"tenant_id": "tenant-a"},
    )
    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        principal_context=principal,
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="must-not-expand-the-principal",
    )

    with pytest.raises(PolicyScopeDeniedError) as caught:
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert caught.value.details == {
        "policy": "crm-read",
        "missing_scopes": ["customer.detail"],
    }


@pytest.mark.asyncio
async def test_operation_context_bindings_are_injected_from_the_trusted_principal() -> None:
    ir = _ir()
    ir["project"]["provider"]["context_binding_allowlist"] = ["tenant_context.tenant_id"]
    operation = ir["operations"]["crm.get_customer"]
    operation["context_bindings"] = {
        "actor_id": "principal_id",
        "tenant_id": "tenant_context.tenant_id",
    }
    operation["input_schema"]["properties"]["actor_id"] = {"type": "string"}
    operation["input_schema"]["required"] = ["customer_id", "actor_id", "tenant_id"]
    operation["http"]["query_parameters"] = {
        "actor": "actor_id",
        "tenant": "tenant_id",
    }
    provider = ContextAwareProvider()
    principal = _principal("user-a", tenant_context={"tenant_id": "tenant-a"})
    runtime = GenericRuntime(ir, provider=provider, principal_context=principal)

    await runtime.call("get_customer", {"customer_id": "c-1"})

    assert provider.calls == [
        (
            "crm.get_customer",
            {"customer_id": "c-1", "actor_id": "user-a", "tenant_id": "tenant-a"},
        )
    ]


@pytest.mark.asyncio
async def test_operation_context_binding_rejects_a_workflow_value_instead_of_overwriting_it() -> (
    None
):
    ir = _ir()
    operation = ir["operations"]["crm.get_customer"]
    operation["context_bindings"] = {"actor_id": "principal_id"}
    operation["input_schema"]["properties"]["actor_id"] = {"type": "string"}
    operation["http"]["query_parameters"] = {"actor": "actor_id"}
    capability = ir["capabilities"]["get_customer"]["definition"]
    capability["input_schema"]["properties"]["actor_id"] = {"type": "string"}
    capability["workflow"][0]["call"]["arguments"]["actor_id"] = "$.input.actor_id"
    runtime = GenericRuntime(
        ir,
        provider=ContextAwareProvider(),
        principal_context=_principal("user-a", tenant_context={"tenant_id": "tenant-a"}),
    )

    with pytest.raises(RuntimeConfigurationError, match="trusted context binding"):
        await runtime.call("get_customer", {"customer_id": "c-1", "actor_id": "user-b"})


@pytest.mark.asyncio
async def test_unbound_user_and_tenant_ids_remain_ordinary_business_arguments() -> None:
    ir = _ir()
    policy = ir["policies"]["crm-read"]
    policy["tenant_mode"] = "none"
    policy["tenant_field"] = None
    policy["readable_fields"] = ["id", "name", "tenant_id"]
    operation = ir["operations"]["crm.get_customer"]
    operation["input_schema"]["properties"]["user_id"] = {"type": "string"}
    operation["http"]["query_parameters"] = {
        "user": "user_id",
        "tenant": "tenant_id",
    }
    capability = ir["capabilities"]["get_customer"]["definition"]
    capability["input_schema"]["properties"].update(
        {"user_id": {"type": "string"}, "tenant_id": {"type": "string"}}
    )
    capability["workflow"][0]["call"]["arguments"].update(
        {"user_id": "$.input.user_id", "tenant_id": "$.input.tenant_id"}
    )
    provider = ContextAwareProvider()
    runtime = GenericRuntime(ir, provider=provider, principal_context=_principal("user-a"))

    await runtime.call(
        "get_customer",
        {"customer_id": "c-1", "user_id": "resource-user", "tenant_id": "resource-tenant"},
    )

    assert provider.calls[0][1] == {
        "customer_id": "c-1",
        "user_id": "resource-user",
        "tenant_id": "resource-tenant",
    }


def test_tools_do_not_expose_context_or_authentication_fields() -> None:
    ir = _ir()
    operation = ir["operations"]["crm.get_customer"]
    operation["context_bindings"] = {"actor_id": "principal_id"}
    operation["input_schema"]["properties"]["actor_id"] = {"type": "string"}
    operation["http"]["query_parameters"] = {"actor": "actor_id"}
    runtime = GenericRuntime(ir, provider=FakeProvider(), principal_context=_principal("user-a"))

    serialized = repr(runtime.tools()).casefold()

    assert "principal" not in serialized
    assert "jwt" not in serialized
    assert "credential" not in serialized
    assert "authorization" not in serialized


@pytest.mark.parametrize(
    ("auth", "expected_strategy"),
    [
        ({"kind": "none"}, NoAuthStrategy),
        (
            {"kind": "bearer_secret", "token_ref": "CRM_TOKEN"},
            BearerSecretAuthStrategy,
        ),
        (
            {
                "kind": "password_bearer",
                "credentials": {
                    "kind": "environment_secret",
                    "identity_ref": "CRM_USER",
                    "password_ref": "CRM_PASSWORD",
                },
                "login_path": "/auth/login",
                "identity_field": "username",
                "password_field": "password",
                "token_pointer": "/access_token",
            },
            PasswordBearerAuthStrategy,
        ),
    ],
)
def test_from_pack_builds_provider_auth_and_a_fixed_stdio_principal(
    monkeypatch: pytest.MonkeyPatch,
    auth: dict[str, object],
    expected_strategy: type[object],
) -> None:
    ir = _ir()
    ir["project"]["provider"]["auth"] = auth
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )

    runtime = GenericRuntime.from_pack(
        "runtime.accpkg",
        environment={
            "CRM_URL": "https://crm.example.test",
            "ACC_PRINCIPAL_ID": "stdio-user",
        },
        granted_scopes={"customer.read"},
        tenant_id="tenant-a",
    )

    provider = runtime.provider
    assert isinstance(provider, HttpProvider)
    assert isinstance(provider._auth_strategy, expected_strategy)
    assert runtime.principal_context.principal_id == "stdio-user"
    assert runtime.principal_context.gateway_session_id is None
    assert runtime.principal_context.target_system_id == "crm"
    assert runtime.principal_context.source_scopes is None
    assert runtime.principal_context.effective_scopes == frozenset({"customer.read"})
    assert runtime.principal_context.tenant_context == {"tenant_id": "tenant-a"}


def test_from_pack_rejects_gateway_credentials_in_stdio_with_a_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ir = _ir()
    ir["project"]["provider"]["auth"] = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/auth/login",
        "identity_field": "username",
        "password_field": "password",
        "token_pointer": "/access_token",
    }
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime.from_pack(
            "runtime.accpkg",
            environment={"CRM_URL": "https://crm.example.test"},
        )

    assert caught.value.code == "ACC_RUNTIME_CONFIGURATION_INVALID"
    assert caught.value.details == {"reason": "gateway_session_requires_streamable_http"}
