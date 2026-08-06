from __future__ import annotations

from collections.abc import Mapping

import pytest
from mcp.server.auth.provider import AccessToken
from pydantic import JsonValue

from acc_runtime.context import PrincipalContext
from acc_runtime.gateway.sessions import GatewaySessionInvalidError
from acc_runtime.mcp import PrincipalCapabilityMcpServer


class ContextualRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, JsonValue], PrincipalContext]] = []

    def tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": "get_customer",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"customer_id": {"type": "string"}},
                },
                "output_schema": {"type": "object"},
            }
        ]

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        self.calls.append((capability_id, arguments, principal_context))
        return {
            "principal": principal_context.principal_id,
            "arguments": dict(arguments),
        }


def _principal(user: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=user,
        gateway_session_id=f"session-{user}",
        target_system_id="project-a",
        source_scopes={"source.read"},
        deployment_scope_ceiling={"customer.read"},
        scope_mapping={"source.read": {"customer.read"}},
        tenant_context={"tenant_id": user},
        auth_state_handle=f"auth-{user}",
    )


class Resolver:
    def __init__(self) -> None:
        self.calls: list[AccessToken | None] = []

    async def resolve(self, access_token: AccessToken | None = None) -> PrincipalContext:
        self.calls.append(access_token)
        if access_token is None or access_token.subject is None:
            raise GatewaySessionInvalidError("missing")
        return _principal(access_token.subject.removeprefix("session-"))


def _access(user: str) -> AccessToken:
    return AccessToken(
        token=f"opaque-{user}",
        client_id="project-a",
        scopes=["customer.read"],
        subject=f"session-{user}",
        claims={"iss": "acc-gateway"},
    )


@pytest.mark.asyncio
async def test_principal_mcp_resolves_each_call_and_passes_context_explicitly() -> None:
    runtime = ContextualRuntime()
    resolver = Resolver()
    adapter = PrincipalCapabilityMcpServer(runtime, resolver=resolver)

    result_a = await adapter.call_tool(
        "get_customer", {"customer_id": "c-a"}, access_token=_access("a")
    )
    result_b = await adapter.call_tool(
        "get_customer", {"customer_id": "c-b"}, access_token=_access("b")
    )
    result_c = await adapter.call_tool(
        "get_customer", {"customer_id": "c-c"}, access_token=_access("c")
    )

    assert [call[2].principal_id for call in runtime.calls] == ["a", "b", "c"]
    assert len(resolver.calls) == 3
    assert result_a.structuredContent == {
        "result": {"principal": "a", "arguments": {"customer_id": "c-a"}}
    }
    assert result_b.isError is False
    assert result_c.isError is False


@pytest.mark.asyncio
async def test_principal_mcp_returns_safe_session_error_without_runtime_call() -> None:
    runtime = ContextualRuntime()
    result = await PrincipalCapabilityMcpServer(runtime, resolver=Resolver()).call_tool(
        "get_customer", {}, access_token=None
    )
    assert result.isError is True
    assert result.structuredContent == {
        "error": {
            "code": "ACC_GATEWAY_SESSION_INVALID",
            "status": 401,
            "details": {},
        }
    }
    assert runtime.calls == []


def test_principal_mcp_tools_do_not_add_identity_scope_or_credentials() -> None:
    tools = PrincipalCapabilityMcpServer(ContextualRuntime(), resolver=Resolver()).list_tools()
    schema = tools[0].inputSchema
    serialized = repr(schema).lower()
    assert "principal" not in serialized
    assert "scope" not in serialized
    assert "credential" not in serialized


@pytest.mark.asyncio
async def test_principal_mcp_arguments_cannot_choose_the_resolved_identity() -> None:
    runtime = ContextualRuntime()
    adapter = PrincipalCapabilityMcpServer(runtime, resolver=Resolver())
    # Direct adapter calls do not bypass identity resolution: these are ordinary
    # business arguments and cannot affect the trusted context selected by bearer.
    result = await adapter.call_tool(
        "get_customer",
        {"principal_id": "b", "scope": "admin", "credential": "secret"},
        access_token=_access("a"),
    )
    assert result.isError is False
    assert runtime.calls[0][2].principal_id == "a"


def test_principal_server_uses_public_sdk_server_without_private_owner_maps() -> None:
    adapter = PrincipalCapabilityMcpServer(ContextualRuntime(), resolver=Resolver())
    server = adapter.create_server()
    assert server is not None
    assert not hasattr(adapter, "_session_owners")
    assert not hasattr(adapter, "_server_instances")
