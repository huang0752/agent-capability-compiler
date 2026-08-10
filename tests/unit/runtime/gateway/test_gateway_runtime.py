from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import JsonValue
from starlette.applications import Starlette

from acc_runtime.auth import AuthUnauthorizedError
from acc_runtime.context import PrincipalContext
from acc_runtime.gateway.models import GatewayRuntimeInfo, GatewaySettings
from acc_runtime.gateway.runtime import (
    GatewayRuntimeComposition,
    _OwnedGatewayService,
    _ReauthCoordinatingRuntime,
    _tool_schema_sha256,
    create_gateway_runtime,
)
from acc_runtime.runtime import GenericRuntime


def _context(session_id: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=f"user-{session_id}",
        gateway_session_id=session_id,
        target_system_id="crm",
        source_scopes={"source.read"},
        deployment_scope_ceiling={"customer.read"},
        scope_mapping={"source.read": {"customer.read"}},
        tenant_context={"tenant_id": session_id},
        auth_state_handle=f"auth-{session_id}",
    )


class _Runtime:
    def __init__(self, failure: AuthUnauthorizedError | None = None) -> None:
        self.failure = failure

    def tools(self) -> list[dict[str, object]]:
        return [{"name": "customer.get"}]

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        del capability_id, arguments, principal_context
        if self.failure is not None:
            raise self.failure
        return {"ok": True}


class _Service:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.marked: list[str] = []

    async def mark_reauth_required(self, session_id: str) -> None:
        self.marked.append(session_id)
        if self.failure is not None:
            raise self.failure


def test_tool_schema_sha256_is_canonical_and_ignores_presentation_metadata() -> None:
    tools = [
        {
            "name": "zeta",
            "title": "Presentation title",
            "description": "Presentation description",
            "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
            "output_schema": {"type": "array", "items": {"type": "string"}},
        },
        {
            "name": "alpha",
            "input_schema": {"type": "object", "properties": {}},
            "output_schema": {"type": "object", "properties": {}},
        },
    ]

    digest = _tool_schema_sha256(tools)

    assert digest == _tool_schema_sha256(list(reversed(tools)))
    assert digest == _tool_schema_sha256(
        [{**tool, "title": "changed", "description": "changed"} for tool in tools]
    )
    assert digest != _tool_schema_sha256(
        [{**tools[0], "output_schema": {"type": "null"}}, tools[1]]
    )


def test_gateway_composition_exposes_only_immutable_runtime_info() -> None:
    info = GatewayRuntimeInfo(
        pack_sha256="a" * 64,
        project_id="project-a",
        project_version="1.2.3",
        tool_schema_sha256="b" * 64,
        transport="streamable_http",
    )
    composition = GatewayRuntimeComposition(
        app=Starlette(),
        owned_service=cast(_OwnedGatewayService, object()),
        runtime=cast(GenericRuntime, _Runtime()),
        runtime_info=info,
    )

    assert composition.runtime_info() is info
    assert composition.runtime_info().model_dump(mode="json") == info.model_dump(mode="json")


def test_create_gateway_runtime_dispatches_a_v2_project_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import acc_runtime.gateway.runtime as gateway_runtime_module
    import acc_runtime.runtime as runtime_module

    project = {
        "schema_version": "2",
        "project": {"id": "gateway-v2", "version": "2.0.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "SOURCE_BASE_URL",
            "auth": {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/auth/login",
                "identity_field": "identity",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/scopes",
                "scope_mapping": {"source:read": ["records.read"]},
            },
        },
        "quality": {"profile": "standard"},
    }
    loaded = SimpleNamespace(
        ir={"project": project, "capabilities": {}, "operations": {}, "policies": {}},
        manifest=SimpleNamespace(project_id="gateway-v2", project_version="2.0.0"),
        verification=SimpleNamespace(sha256="a" * 64),
    )

    class FakeGenericRuntime:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def tools(self) -> list[dict[str, object]]:
            return []

    monkeypatch.setattr(gateway_runtime_module, "load_pack", lambda path: loaded)
    monkeypatch.setattr(runtime_module, "GenericRuntime", FakeGenericRuntime)

    composition = create_gateway_runtime(
        pack_path="v2.accpkg",
        settings=GatewaySettings(allowed_hosts=("gateway.test",)),
        environment={"SOURCE_BASE_URL": "https://source.test"},
        audit_deployment_salt=b"test-only-deployment-salt",
    )

    assert composition.runtime_info().project_id == "gateway-v2"
    assert composition.runtime_info().transport == "streamable_http"


@pytest.mark.asyncio
async def test_reauth_coordinator_marks_only_the_failing_gateway_session() -> None:
    failure = AuthUnauthorizedError("source rejected bearer")
    runtime = _Runtime(failure)
    service = _Service()
    coordinated = _ReauthCoordinatingRuntime(runtime, service=service)

    with pytest.raises(AuthUnauthorizedError) as raised:
        await coordinated.call_with_context("customer.get", {}, _context("session-a"))

    assert raised.value is failure
    assert service.marked == ["session-a"]

    runtime.failure = None
    assert await coordinated.call_with_context("customer.get", {}, _context("session-b")) == {
        "ok": True
    }
    assert service.marked == ["session-a"]


@pytest.mark.asyncio
async def test_reauth_coordinator_preserves_original_unauthorized_if_marking_fails() -> None:
    failure = AuthUnauthorizedError("source rejected bearer")
    coordinated = _ReauthCoordinatingRuntime(
        _Runtime(failure),
        service=_Service(RuntimeError("store failure")),
    )

    with pytest.raises(AuthUnauthorizedError) as raised:
        await coordinated.call_with_context("customer.get", {}, _context("session-a"))

    assert raised.value is failure
    assert raised.value.__cause__ is None


@pytest.mark.asyncio
async def test_reauth_coordinator_does_not_swallow_cancellation() -> None:
    coordinated = _ReauthCoordinatingRuntime(
        _Runtime(AuthUnauthorizedError("source rejected bearer")),
        service=_Service(asyncio.CancelledError()),
    )

    with pytest.raises(asyncio.CancelledError):
        await coordinated.call_with_context("customer.get", {}, _context("session-a"))
