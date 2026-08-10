from __future__ import annotations

import asyncio
import copy
import types
from collections.abc import Mapping
from datetime import UTC
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import JsonValue

import acc_runtime
import acc_runtime.runtime as runtime_module
from acc_runtime.auth import (
    AuthAttempt,
    AuthenticationResult,
    BearerSecretAuthStrategy,
    NoAuthStrategy,
    PasswordBearerAuthStrategy,
)
from acc_runtime.auth.errors import AuthUnauthorizedError
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.execution import ExecutionError
from acc_runtime.gateway.audit import AuditCollector, AuditEvent, MemoryAuditSink
from acc_runtime.policies import PolicyScopeDeniedError
from acc_runtime.providers import HttpForbiddenError, HttpProvider
from acc_runtime.runtime import (
    ContextOperationProvider,
    GenericRuntime,
    OperationProvider,
    RuntimeConfigurationError,
)


def _ir() -> dict[str, Any]:
    operation = {
        "schema_version": "2",
        "kind": "read",
        "id": "crm.get_customer",
        "title": "Get customer",
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
            "request": None,
            "success": {"statuses": [200], "body": "json"},
            "scopes": ["customer.read", "customer.detail"],
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
                "source_id": "crm",
                "kind": "source_file",
                "path": "routes.py",
                "json_pointer": "/get_customer",
                "digest": f"sha256:{'a' * 64}",
            }
        ],
    }
    policy = {
        "schema_version": "2",
        "id": "crm-read",
        "required_scopes": ["customer.read"],
        "tenant_mode": "required",
        "tenant_field": "tenant_id",
        "readable_fields": ["id", "name", "tenant_id"],
        "denied_fields": ["secret"],
        "redaction_rules": [],
    }
    capability = {
        "schema_version": "2",
        "kind": "read",
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
        "ir_version": "2",
        "interaction_sha256": "17a5028f9592577c2c75ad5f20fe008559a4b4239ff54b4bea0a3a7907d0b3f4",
        "interactions": {
            "schema_version": "2",
            "digest": "17a5028f9592577c2c75ad5f20fe008559a4b4239ff54b4bea0a3a7907d0b3f4",
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        },
        "project": {
            "schema_version": "2",
            "project": {"id": "crm", "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_URL"},
            "quality": {"profile": "standard"},
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


class RecordingOperationObserver:
    def __init__(self) -> None:
        self.operation_ids: list[str] = []

    def observe(self, operation_id: str) -> None:
        self.operation_ids.append(operation_id)


class SensitiveStrategy:
    def __init__(self, other_users_token: str) -> None:
        self.other_users_token = SecretValue(other_users_token)
        self.close_calls = 0

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        authentication = AuthenticationResult(
            token=SecretValue("current-user-token"),
            token_type="Bearer",
        )
        assert authentication.authorization is not None
        return AuthAttempt(
            headers={"Authorization": authentication.authorization},
            state_key=context.auth_state_key,
            generation=1,
            authentication=authentication,
        )

    headers = authorize

    async def on_unauthorized(
        self,
        context: PrincipalContext,
        failed_attempt: AuthAttempt,
    ) -> bool:
        return False

    async def invalidate(self, auth_state_key: object) -> None:
        return None

    async def aclose(self) -> None:
        self.close_calls += 1


def _assert_runtime_exception_cannot_reach_secret(
    error: BaseException,
    *secrets: str,
) -> None:
    pending: list[object] = [error]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if value is None or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, str):
            assert all(secret not in value for secret in secrets)
            continue
        if isinstance(value, bytes):
            assert all(secret.encode() not in value for secret in secrets)
            continue
        if isinstance(value, SecretValue):
            pending.append(value.get_secret_value())
            continue
        if isinstance(value, httpx.Request):
            pending.extend([value.content, value.headers, str(value.url)])
            continue
        if isinstance(value, httpx.Response):
            pending.extend([value.headers, value.request])
            if value.is_closed:
                pending.append(value.content)
            continue
        if isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
            continue
        if isinstance(value, BaseException):
            pending.extend(
                [value.args, value.__cause__, value.__context__, getattr(value, "details", None)]
            )
            traceback = value.__traceback__
            while traceback is not None:
                if "/packages/acc-runtime/" in traceback.tb_frame.f_code.co_filename:
                    pending.extend(traceback.tb_frame.f_locals.values())
                traceback = traceback.tb_next
            continue
        if isinstance(
            value,
            (asyncio.Future, asyncio.Lock, types.FunctionType, types.MethodType, type),
        ):
            continue
        namespace = getattr(value, "__dict__", None)
        if isinstance(namespace, dict):
            pending.extend(namespace.values())
        slots = getattr(type(value), "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and hasattr(value, slot):
                pending.append(getattr(value, slot))


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


@pytest.mark.asyncio
async def test_bound_principal_is_read_only_and_call_keeps_using_the_original_identity() -> None:
    provider = ContextAwareProvider()
    original = _principal("original", tenant_context={"tenant_id": "tenant-a"})
    replacement = _principal("replacement", tenant_context={"tenant_id": "tenant-b"})
    runtime = GenericRuntime(_ir(), provider=provider, principal_context=original)

    with pytest.raises(AttributeError):
        runtime.principal_context = replacement  # type: ignore[misc]

    await runtime.call("get_customer", {"customer_id": "c-1"})
    await runtime.call("get_customer", {"customer_id": "c-2"})

    assert runtime.principal_context is original
    assert provider.contexts == [original, original]


def _authenticated_ir() -> dict[str, Any]:
    ir = _ir()
    ir["project"]["provider"]["auth"] = {"kind": "none"}
    return ir


def _sensitive_http_runtime(
    handler: object,
    *,
    principal: PrincipalContext,
    other_users_token: str,
) -> tuple[GenericRuntime, httpx.AsyncClient]:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        follow_redirects=False,
    )
    provider = HttpProvider(
        base_url_ref="CRM_URL",
        environment={"CRM_URL": "https://crm.example.test"},
        auth_strategy=SensitiveStrategy(other_users_token),
        client=client,
    )
    return GenericRuntime(
        _authenticated_ir(),
        provider=provider,
        principal_context=principal,
    ), client


@pytest.mark.asyncio
async def test_policy_error_traceback_cannot_reach_another_principals_auth_state() -> None:
    other_users_token = "other-user-policy-token-must-not-leak"
    principal = _principal(
        "limited",
        source_scopes={"source.customer"},
        scope_mapping={"source.customer": {"customer.read"}},
        tenant_context={"tenant_id": "tenant-a"},
    )
    runtime, client = _sensitive_http_runtime(
        lambda request: httpx.Response(200, json={"id": "c-1"}),
        principal=principal,
        other_users_token=other_users_token,
    )
    try:
        with pytest.raises(PolicyScopeDeniedError) as caught:
            await runtime.call("get_customer", {"customer_id": "c-1"})
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_POLICY_SCOPE_DENIED"
    _assert_runtime_exception_cannot_reach_secret(caught.value, other_users_token)


@pytest.mark.asyncio
@pytest.mark.parametrize("explicit_context", [False, True])
async def test_provider_error_traceback_cannot_reach_another_principals_auth_state(
    explicit_context: bool,
) -> None:
    other_users_token = "other-user-provider-token-must-not-leak"
    runtime, client = _sensitive_http_runtime(
        lambda request: httpx.Response(403, json={"private": "upstream"}),
        principal=_principal("current", tenant_context={"tenant_id": "tenant-a"}),
        other_users_token=other_users_token,
    )
    try:
        with pytest.raises(AccRuntimeError) as caught:
            if explicit_context:
                await runtime.call_with_context(
                    "get_customer",
                    {"customer_id": "c-1"},
                    runtime.principal_context,
                )
            else:
                await runtime.call("get_customer", {"customer_id": "c-1"})
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_HTTP_FORBIDDEN"
    assert isinstance(caught.value, HttpForbiddenError)
    assert caught.value.details == {"operation": "crm.get_customer"}
    _assert_runtime_exception_cannot_reach_secret(caught.value, other_users_token)


@pytest.mark.asyncio
async def test_output_schema_error_traceback_cannot_reach_unfiltered_upstream_output() -> None:
    raw_upstream_secret = "unfiltered-upstream-output-must-not-leak"
    other_users_token = "other-user-output-token-must-not-leak"
    runtime, client = _sensitive_http_runtime(
        lambda request: httpx.Response(
            200,
            json={
                "id": "c-1",
                "name": "Ada",
                "tenant_id": "tenant-a",
                "secret": raw_upstream_secret,
            },
        ),
        principal=_principal("current", tenant_context={"tenant_id": "tenant-a"}),
        other_users_token=other_users_token,
    )
    runtime.ir["capabilities"]["get_customer"]["definition"]["output_schema"] = {
        "type": "object",
        "required": ["missing_public_field"],
    }
    try:
        with pytest.raises(AccRuntimeError) as caught:
            await runtime.call("get_customer", {"customer_id": "c-1"})
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_OUTPUT_INVALID"
    assert isinstance(caught.value, ExecutionError)
    assert caught.value.details == {
        "capability_id": "get_customer",
        "schema_role": "filtered_capability_output",
    }
    _assert_runtime_exception_cannot_reach_secret(
        caught.value,
        raw_upstream_secret,
        other_users_token,
    )


@pytest.mark.asyncio
async def test_from_pack_closes_only_its_owned_auth_strategy_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ir = _authenticated_ir()
    strategy = SensitiveStrategy("owned-strategy-secret")
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )
    monkeypatch.setattr(
        "acc_runtime.runtime._auth_strategy_from_project",
        lambda project, environment: strategy,
    )
    runtime = GenericRuntime.from_pack(
        "runtime.accpkg",
        environment={"CRM_URL": "https://crm.example.test"},
    )

    await runtime.aclose()
    await runtime.aclose()

    assert strategy.close_calls == 1


@pytest.mark.asyncio
async def test_runtime_async_context_closes_owned_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ir = _authenticated_ir()
    strategy = SensitiveStrategy("context-owned-strategy-secret")
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )
    monkeypatch.setattr(
        "acc_runtime.runtime._auth_strategy_from_project",
        lambda project, environment: strategy,
    )

    async with GenericRuntime.from_pack(
        "runtime.accpkg",
        environment={"CRM_URL": "https://crm.example.test"},
    ):
        assert strategy.close_calls == 0

    assert strategy.close_calls == 1


@pytest.mark.asyncio
async def test_runtime_does_not_close_an_external_provider_or_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExternalProvider(FakeProvider):
        def __init__(self) -> None:
            super().__init__()
            self.close_calls = 0

        async def aclose(self) -> None:
            self.close_calls += 1

    external_provider = ExternalProvider()
    direct_runtime = GenericRuntime(_ir(), provider=external_provider)
    await direct_runtime.aclose()
    assert external_provider.close_calls == 0

    ir = _authenticated_ir()
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    packed_runtime = GenericRuntime.from_pack(
        "runtime.accpkg",
        environment={"CRM_URL": "https://crm.example.test"},
        client=client,
    )

    await packed_runtime.aclose()

    assert client.is_closed is False
    await client.aclose()


class BodyFailure(Exception):
    def __init__(self, secret: str) -> None:
        super().__init__("async context body failed")
        self.secret = secret


class CloseFailureStrategy(SensitiveStrategy):
    def __init__(self, close_secret: str, *, cancel: bool = False) -> None:
        super().__init__(close_secret)
        self.cancel = cancel

    async def aclose(self) -> None:
        self.close_calls += 1
        if self.cancel:
            raise asyncio.CancelledError
        raise RuntimeConfigurationError(
            "owned authentication cleanup failed",
            details={"reason": "owned_auth_cleanup_failed"},
        )


def _mock_packed_runtime(
    monkeypatch: pytest.MonkeyPatch,
    strategy: SensitiveStrategy,
) -> GenericRuntime:
    ir = _authenticated_ir()
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )
    monkeypatch.setattr(
        "acc_runtime.runtime._auth_strategy_from_project",
        lambda project, environment: strategy,
    )
    return GenericRuntime.from_pack(
        "runtime.accpkg",
        environment={"CRM_URL": "https://crm.example.test"},
    )


@pytest.mark.asyncio
async def test_async_context_preserves_body_error_when_owned_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    body_secret = "async-body-secret-must-not-enter-cleanup-error"
    close_secret = "async-close-secret-must-not-enter-body-error"
    body_error = BodyFailure(body_secret)
    strategy = CloseFailureStrategy(close_secret)
    runtime = _mock_packed_runtime(monkeypatch, strategy)

    with pytest.raises(BodyFailure) as caught:
        async with runtime:
            raise body_error

    assert caught.value is body_error
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert strategy.close_calls == 1
    assert body_secret not in caplog.text
    assert close_secret not in caplog.text
    _assert_runtime_exception_cannot_reach_secret(caught.value, close_secret)


@pytest.mark.asyncio
async def test_async_context_preserves_body_error_when_owned_cleanup_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_secret = "cancelled-close-secret-must-not-enter-body-error"
    body_error = BodyFailure("cancelled-cleanup-body-secret")
    strategy = CloseFailureStrategy(close_secret, cancel=True)
    runtime = _mock_packed_runtime(monkeypatch, strategy)

    with pytest.raises(BodyFailure) as caught:
        async with runtime:
            raise body_error

    assert caught.value is body_error
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert strategy.close_calls == 1
    _assert_runtime_exception_cannot_reach_secret(caught.value, close_secret)


@pytest.mark.asyncio
async def test_async_context_without_body_error_raises_safe_owned_cleanup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_secret = "standalone-close-secret-must-not-leak"
    strategy = CloseFailureStrategy(close_secret)
    runtime = _mock_packed_runtime(monkeypatch, strategy)

    with pytest.raises(RuntimeConfigurationError) as caught:
        async with runtime:
            pass

    assert caught.value.code == "ACC_RUNTIME_CONFIGURATION_INVALID"
    assert caught.value.details == {"reason": "owned_auth_cleanup_failed"}
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert strategy.close_calls == 1
    _assert_runtime_exception_cannot_reach_secret(caught.value, close_secret)


def _audited_runtime(
    provider: OperationProvider | ContextOperationProvider,
    *,
    principal: PrincipalContext | None = None,
    observer: RecordingOperationObserver | None = None,
) -> tuple[GenericRuntime, MemoryAuditSink]:
    sink = MemoryAuditSink()
    collector = AuditCollector(sink=sink, deployment_salt=b"runtime-audit-salt")
    runtime = GenericRuntime(
        _ir(),
        provider=provider,
        principal_context=principal
        or _principal("audited", tenant_context={"tenant_id": "tenant-a"}),
        audit_collector=collector,
        operation_observer=observer,
    )
    return runtime, sink


@pytest.mark.asyncio
async def test_audit_records_success_and_the_actual_provider_operation() -> None:
    observer = RecordingOperationObserver()
    runtime, sink = _audited_runtime(FakeProvider(), observer=observer)

    await runtime.call_with_context(
        "get_customer",
        {"customer_id": "c-1"},
        runtime.principal_context,
    )

    assert observer.operation_ids == ["crm.get_customer"]
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.project_id == "crm"
    assert event.capability_id == "get_customer"
    assert event.operation_ids == ("crm.get_customer",)
    assert event.result_category == "success"
    assert event.duration_ms >= 0
    assert event.timestamp.tzinfo is UTC


@pytest.mark.asyncio
async def test_audit_records_only_the_operation_selected_by_a_workflow_branch() -> None:
    ir = _ir()
    second = copy.deepcopy(ir["operations"]["crm.get_customer"])
    second["id"] = "crm.get_customer_fallback"
    ir["operations"]["crm.get_customer_fallback"] = second
    capability = ir["capabilities"]["get_customer"]["definition"]
    capability["input_schema"]["properties"]["primary"] = {"type": "boolean"}
    capability["workflow"] = [
        {
            "id": "selected",
            "branch": {
                "condition": "$.input.primary",
                "then": [
                    {
                        "id": "result",
                        "call": {
                            "operation": "crm.get_customer",
                            "arguments": {"customer_id": "$.input.customer_id"},
                        },
                    },
                    {"emit": {"value": "$.steps.result"}},
                ],
                "else": [
                    {
                        "id": "result",
                        "call": {
                            "operation": "crm.get_customer_fallback",
                            "arguments": {"customer_id": "$.input.customer_id"},
                        },
                    },
                    {"emit": {"value": "$.steps.result"}},
                ],
            },
        },
        {"emit": {"value": "$.steps.selected"}},
    ]
    sink = MemoryAuditSink()
    runtime = GenericRuntime(
        ir,
        provider=FakeProvider(),
        principal_context=_principal("audited", tenant_context={"tenant_id": "tenant-a"}),
        audit_collector=AuditCollector(sink=sink, deployment_salt=b"runtime-audit-salt"),
    )

    await runtime.call("get_customer", {"customer_id": "c-1", "primary": False})

    assert sink.events[0].operation_ids == ("crm.get_customer_fallback",)


@pytest.mark.asyncio
async def test_audit_classifies_policy_deny_before_any_provider_operation() -> None:
    limited = _principal(
        "limited",
        source_scopes={"source.customer"},
        scope_mapping={"source.customer": {"customer.read"}},
        tenant_context={"tenant_id": "tenant-a"},
    )
    runtime, sink = _audited_runtime(FakeProvider(), principal=limited)

    with pytest.raises(PolicyScopeDeniedError):
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert sink.events[0].operation_ids == ()
    assert sink.events[0].result_category == "policy_denied"


@pytest.mark.asyncio
async def test_audit_classifies_upstream_deny_after_observing_the_operation() -> None:
    class ForbiddenProvider(FakeProvider):
        async def call(
            self,
            operation: Mapping[str, object],
            arguments: Mapping[str, JsonValue],
        ) -> JsonValue:
            raise HttpForbiddenError("forbidden", details={"operation": operation["id"]})

    runtime, sink = _audited_runtime(ForbiddenProvider())

    with pytest.raises(HttpForbiddenError):
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert sink.events[0].operation_ids == ("crm.get_customer",)
    assert sink.events[0].result_category == "upstream_denied"


@pytest.mark.asyncio
async def test_audit_and_observer_failures_do_not_change_business_or_expose_secrets() -> None:
    secret = "audit-observer-private-secret"

    class FailingSink:
        def emit(self, event: AuditEvent) -> None:
            raise ValueError(secret)

    class FailingObserver:
        def observe(self, operation_id: str) -> None:
            raise ValueError(secret)

    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        principal_context=_principal("private-principal", tenant_context={"tenant_id": "tenant-a"}),
        audit_collector=AuditCollector(
            sink=FailingSink(),
            deployment_salt=b"runtime-audit-salt",
        ),
        operation_observer=FailingObserver(),
    )

    result = await runtime.call("get_customer", {"customer_id": "c-1"})

    assert result == {"id": "c-1", "name": "Ada", "tenant_id": "tenant-a"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_category"),
    [
        (AuthUnauthorizedError("reauth"), "reauth"),
        (ValueError("unstructured private failure"), "internal"),
    ],
)
async def test_audit_stably_classifies_reauth_and_internal_failures(
    failure: Exception,
    expected_category: str,
) -> None:
    class FailingProvider(FakeProvider):
        async def call(
            self,
            operation: Mapping[str, object],
            arguments: Mapping[str, JsonValue],
        ) -> JsonValue:
            raise failure

    runtime, sink = _audited_runtime(FailingProvider())

    with pytest.raises(AccRuntimeError):
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert sink.events[0].operation_ids == ("crm.get_customer",)
    assert sink.events[0].result_category == expected_category


def test_from_pack_accepts_optional_audit_and_operation_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ir = _authenticated_ir()
    monkeypatch.setattr(
        "acc_runtime.runtime.load_pack",
        lambda path: type("Pack", (), {"ir": ir, "path": Path(path)})(),
    )
    sink = MemoryAuditSink()
    collector = AuditCollector(sink=sink, deployment_salt=b"runtime-audit-salt")
    observer = RecordingOperationObserver()

    runtime = GenericRuntime.from_pack(
        "runtime.accpkg",
        environment={"CRM_URL": "https://crm.example.test"},
        audit_collector=collector,
        operation_observer=observer,
    )

    assert runtime._audit_collector is collector
    assert runtime._operation_observer is observer


@pytest.mark.asyncio
async def test_failing_audit_sink_is_absent_from_business_error_traceback() -> None:
    sink_secret = "failing-audit-sink-secret-must-not-reach-runtime-error"

    class SecretFailingSink:
        def __init__(self) -> None:
            self.secret = sink_secret

        def emit(self, event: AuditEvent) -> None:
            raise ValueError(self.secret)

    class ForbiddenProvider(FakeProvider):
        async def call(
            self,
            operation: Mapping[str, object],
            arguments: Mapping[str, JsonValue],
        ) -> JsonValue:
            raise HttpForbiddenError("forbidden", details={"operation": operation["id"]})

    runtime = GenericRuntime(
        _ir(),
        provider=ForbiddenProvider(),
        principal_context=_principal("private-principal", tenant_context={"tenant_id": "tenant-a"}),
        audit_collector=AuditCollector(
            sink=SecretFailingSink(),
            deployment_salt=b"runtime-audit-salt",
        ),
    )

    with pytest.raises(HttpForbiddenError) as caught:
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    _assert_runtime_exception_cannot_reach_secret(caught.value, sink_secret)


@pytest.mark.asyncio
async def test_audit_sink_cancellation_cancels_business_with_a_safe_traceback() -> None:
    principal_secret = "cancelled-audit-principal-secret"
    session_secret = "cancelled-audit-session-secret"
    salt_secret = "cancelled-audit-deployment-salt"
    sink_secret = "cancelled-audit-sink-secret"

    class CancellingSink:
        def __init__(self) -> None:
            self.secret = sink_secret

        def emit(self, event: AuditEvent) -> None:
            raise asyncio.CancelledError

    principal = PrincipalContext(
        principal_id=principal_secret,
        gateway_session_id=session_secret,
        target_system_id="crm",
        source_scopes={"customer.read", "customer.detail"},
        deployment_scope_ceiling={"customer.read", "customer.detail"},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle="cancelled-audit-handle",
        scope_mapping={
            "customer.read": {"customer.read"},
            "customer.detail": {"customer.detail"},
        },
    )
    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        principal_context=principal,
        audit_collector=AuditCollector(
            sink=CancellingSink(),
            deployment_salt=salt_secret.encode(),
        ),
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    _assert_runtime_exception_cannot_reach_secret(
        caught.value,
        principal_secret,
        session_secret,
        salt_secret,
        sink_secret,
    )


@pytest.mark.asyncio
async def test_business_cancellation_cannot_reach_a_secret_bearing_audit_sink() -> None:
    principal_secret = "business-cancel-principal-secret"
    sink_secret = "business-cancel-sink-secret"

    class SecretSink:
        def __init__(self) -> None:
            self.secret = sink_secret
            self.events: list[AuditEvent] = []

        def emit(self, event: AuditEvent) -> None:
            self.events.append(event)

    class CancellingProvider(FakeProvider):
        async def call(
            self,
            operation: Mapping[str, object],
            arguments: Mapping[str, JsonValue],
        ) -> JsonValue:
            raise asyncio.CancelledError

    sink = SecretSink()
    runtime = GenericRuntime(
        _ir(),
        provider=CancellingProvider(),
        principal_context=_principal(
            principal_secret,
            tenant_context={"tenant_id": "tenant-a"},
        ),
        audit_collector=AuditCollector(
            sink=sink,
            deployment_salt=b"business-cancel-salt",
        ),
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert sink.events[0].result_category == "cancelled"
    _assert_runtime_exception_cannot_reach_secret(
        caught.value,
        principal_secret,
        sink_secret,
    )


def test_audit_category_table_exhaustively_classifies_current_stable_codes() -> None:
    expected = {
        "ACC_GATEWAY_REAUTH_REQUIRED": "reauth",
        "ACC_GATEWAY_SESSION_CAPACITY_REACHED": "internal",
        "ACC_GATEWAY_SESSION_EXPIRED": "reauth",
        "ACC_GATEWAY_SESSION_INVALID": "reauth",
        "ACC_RUNTIME_ASSERTION_FAILED": "internal",
        "ACC_RUNTIME_AUTH_CONFIGURATION_INVALID": "internal",
        "ACC_RUNTIME_AUTH_LOGIN_FAILED": "authentication_failed",
        "ACC_RUNTIME_AUTH_RESPONSE_INVALID": "authentication_failed",
        "ACC_RUNTIME_AUTH_SECRET_MISSING": "internal",
        "ACC_RUNTIME_AUTH_UNAUTHORIZED": "reauth",
        "ACC_RUNTIME_BOUND_EXCEEDED": "invalid_request",
        "ACC_RUNTIME_CAPABILITY_NOT_FOUND": "invalid_request",
        "ACC_RUNTIME_CONFIGURATION_INVALID": "internal",
        "ACC_RUNTIME_DEFINITION_NOT_FOUND": "internal",
        "ACC_RUNTIME_ERROR": "internal",
        "ACC_RUNTIME_FINAL_EMIT_REQUIRED": "internal",
        "ACC_RUNTIME_HTTP_BASE_URL_INVALID": "internal",
        "ACC_RUNTIME_HTTP_FORBIDDEN": "upstream_denied",
        "ACC_RUNTIME_HTTP_INVALID_JSON": "upstream_error",
        "ACC_RUNTIME_HTTP_METHOD_DENIED": "internal",
        "ACC_RUNTIME_HTTP_NOT_FOUND": "upstream_denied",
        "ACC_RUNTIME_HTTP_OPERATION_INVALID": "internal",
        "ACC_RUNTIME_HTTP_REQUEST_FAILED": "upstream_error",
        "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE": "upstream_error",
        "ACC_RUNTIME_HTTP_TIMEOUT": "upstream_error",
        "ACC_RUNTIME_HTTP_UPSTREAM_ERROR": "upstream_error",
        "ACC_RUNTIME_INPUT_INVALID": "invalid_request",
        "ACC_RUNTIME_INPUT_SCHEMA_INVALID": "invalid_request",
        "ACC_RUNTIME_INTERNAL": "internal",
        "ACC_RUNTIME_IR_INVALID": "internal",
        "ACC_RUNTIME_IR_MISSING": "internal",
        "ACC_RUNTIME_IR_TOO_LARGE": "internal",
        "ACC_RUNTIME_OPERATION_FAILED": "internal",
        "ACC_RUNTIME_OPERATION_INPUT_INVALID": "invalid_request",
        "ACC_RUNTIME_OPERATION_NOT_FOUND": "internal",
        "ACC_RUNTIME_OPERATION_OUTPUT_INVALID": "upstream_error",
        "ACC_RUNTIME_OUTPUT_INVALID": "internal",
        "ACC_RUNTIME_OUTPUT_SCHEMA_INVALID": "upstream_error",
        "ACC_RUNTIME_PACK_VERIFICATION_FAILED": "internal",
        "ACC_RUNTIME_POLICY_OUTPUT_INVALID": "internal",
        "ACC_RUNTIME_POLICY_SCOPE_DENIED": "policy_denied",
        "ACC_RUNTIME_POLICY_TENANT_DENIED": "policy_denied",
        "ACC_RUNTIME_REFERENCE_INVALID": "internal",
        "ACC_RUNTIME_REFERENCE_UNAVAILABLE": "internal",
        "ACC_RUNTIME_SECRET_NOT_FOUND": "internal",
        "ACC_RUNTIME_SECRET_REF_INVALID": "internal",
        "ACC_RUNTIME_STEP_INVALID": "internal",
        "ACC_RUNTIME_VALUE_TYPE_INVALID": "invalid_request",
    }

    assert expected == runtime_module._AUDIT_CODE_CATEGORIES

    for code, category in expected.items():
        error = AccRuntimeError("safe")
        error.__dict__["code"] = code
        assert runtime_module._audit_category(error) == category

    unknown = AccRuntimeError("safe")
    unknown.__dict__["code"] = "ACC_RUNTIME_FUTURE_UNKNOWN"
    assert runtime_module._audit_category(unknown) == "internal"
