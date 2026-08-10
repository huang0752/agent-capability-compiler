from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import cast

import httpx
import pytest
from mcp import types
from pydantic import JsonValue, SecretStr
from starlette.applications import Starlette

from acc_core.compiler.actions import ActionProof
from acc_core.models.v2 import ActionCapabilityV2
from acc_runtime.actions import (
    ActionRuntimeDependencies,
    InMemoryActionStore,
    InMemoryApprovalAuthority,
)
from acc_runtime.actions.coordinator import (
    ActionCommitExecution,
    ActionCoordinator,
    ActionPreviewExecution,
    ActionWorkflowExecutor,
    CompiledActionDefinition,
)
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.deployment import DeploymentPolicy
from acc_runtime.gateway.app import create_gateway_app
from acc_runtime.gateway.auth import GatewayPrincipalResolver, GatewayTokenVerifier
from acc_runtime.gateway.models import GatewayRuntimeInfo, GatewaySettings, SessionCreateResponse
from acc_runtime.gateway.runtime import create_gateway_runtime
from acc_runtime.gateway.sessions import InMemoryGatewaySessionStore
from acc_runtime.mcp import PrincipalCapabilityMcpServer
from acc_runtime.runtime import RuntimeConfigurationError
from acc_testkit import GatewaySessionClient

PACK_DIGEST = "sha256:" + "a" * 64
PRIVATE_IDEMPOTENCY_KEY = "private-idempotency-key"


class _ReadRuntime:
    def __init__(self, tools: list[dict[str, object]] | None = None) -> None:
        self._tools = tools or []

    def interaction_manifest(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "2",
            "digest": "c" * 64,
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        }

    def tools(self) -> list[dict[str, object]]:
        return self._tools

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        del capability_id, arguments, principal_context
        raise AssertionError("ordinary Read dispatch is not used by this Action fixture")


class _SessionService:
    def __init__(self, store: InMemoryGatewaySessionStore) -> None:
        self.store = store
        self.counts: dict[str, int] = {}

    async def create_session(self, *, identity: str, password: str) -> SessionCreateResponse:
        if identity not in {"a", "b"} or password != "correct-password":
            raise ValueError("login failed")
        count = self.counts.get(identity, 0) + 1
        self.counts[identity] = count
        session_id = f"gateway-{identity}-{count}"
        scopes = {"orders.read", "orders.write"}
        creation = await self.store.create(
            session_id=session_id,
            principal_context=PrincipalContext(
                principal_id=f"principal-{identity}",
                gateway_session_id=session_id,
                target_system_id="orders-system",
                source_scopes=scopes,
                deployment_scope_ceiling=scopes,
                scope_mapping={scope: {scope} for scope in scopes},
                tenant_context={"tenant_id": f"tenant-{identity}"},
                auth_state_handle=f"auth-{identity}-{count}",
            ),
        )
        return SessionCreateResponse(
            gateway_token=SecretStr(creation.token.get_secret_value()),
            expires_in_seconds=60,
        )

    async def delete_current(self, token: str) -> None:
        await self.store.revoke_token(SecretValue(token))

    async def aclose(self) -> None:
        await self.store.close()


@dataclass
class _Executor(ActionWorkflowExecutor):
    definitions: dict[str, CompiledActionDefinition] = field(default_factory=dict)
    commit_calls: list[ActionCommitExecution] = field(default_factory=list)

    def verified_definition(self, capability_id: str) -> CompiledActionDefinition:
        return self.definitions[capability_id]

    async def preview(
        self,
        capability: ActionCapabilityV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionPreviewExecution:
        assert capability.id == "orders.update"
        return ActionPreviewExecution(
            value={
                "order_id": arguments["order_id"],
                "status": "pending",
                "owner": principal_context.principal_id,
            },
            concurrency_token="etag-v1",
        )

    async def commit(
        self,
        capability: ActionCapabilityV2,
        execution: ActionCommitExecution,
        principal_context: PrincipalContext,
    ) -> JsonValue:
        assert capability.id == "orders.update"
        self.commit_calls.append(execution)
        return {
            "status": "approved",
            "owner": principal_context.principal_id,
        }


def _coordinator() -> tuple[ActionCoordinator, InMemoryApprovalAuthority, _Executor]:
    capability = ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.update",
            "title": "Update order",
            "description": "Preview and update one order.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "output_schema": {"type": "object"},
            "action": {
                "execution_mode": "single",
                "approval": {"mode": "required"},
                "expires_in_seconds": 300,
            },
            "preview_workflow": [{"emit": {"value": None}}],
            "commit_workflow": [{"emit": {"value": None}}],
            "policy": "orders-write",
            "evals": ["orders-update-success"],
        }
    )
    definition = CompiledActionDefinition(
        capability=capability,
        proof=ActionProof(
            diagnostics=(),
            mutation_operation_ids=("orders.update",),
            effects=("update",),
            maximum_risk="medium",
            required_scopes=("orders.read", "orders.write"),
            approval_required=True,
        ),
    )
    executor = _Executor(definitions={capability.id: definition})
    action_handles = iter(("h" * 43, "i" * 43))
    approvals = iter(("p" * 43, "q" * 43))
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: 100.0,
        handle_generator=lambda: next(approvals),
    )
    coordinator = ActionCoordinator(
        definitions={capability.id: definition},
        pack_digest=PACK_DIGEST,
        deployment_policy=DeploymentPolicy(
            allowed_effects=frozenset({"read", "update"}),
            max_risk="medium",
            capability_allowlist=frozenset({capability.id}),
            require_durable_action_store=False,
            action_audit_mode="best_effort",
        ),
        store=InMemoryActionStore(
            development_only=True,
            deployment_salt=b"action-mcp-gateway-test-salt",
            clock=lambda: 100.0,
            handle_generator=lambda: next(action_handles),
        ),
        approval_authority=authority,
        executor=executor,
        idempotency_key_generator=lambda: PRIVATE_IDEMPOTENCY_KEY,
    )
    return coordinator, authority, executor


def _token(seed: int) -> str:
    return base64.urlsafe_b64encode(bytes([seed]) * 32).rstrip(b"=").decode()


def _build_app(
    coordinator: ActionCoordinator,
) -> Starlette:
    tokens = iter((_token(1), _token(2)))
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        token_generator=lambda: next(tokens),
    )
    service = _SessionService(store)
    resolver = GatewayPrincipalResolver(store=store, project_id="orders-system")
    server = PrincipalCapabilityMcpServer(
        _ReadRuntime(),
        resolver=resolver,
        action_coordinator=coordinator,
    )
    return create_gateway_app(
        settings=GatewaySettings(
            allowed_hosts=("gateway.test",),
            allowed_origins=("http://gateway.test",),
        ),
        service=service,
        token_verifier=GatewayTokenVerifier(store=store, project_id="orders-system"),
        mcp_server=server,
        runtime_info=GatewayRuntimeInfo(
            pack_sha256="a" * 64,
            project_id="orders-system",
            project_version="2.0.0",
            interaction_sha256="c" * 64,
            tool_schema_sha256="b" * 64,
            transport="streamable_http",
        ),
    )


def _principal(identity: str) -> PrincipalContext:
    scopes = {"orders.read", "orders.write"}
    return PrincipalContext(
        principal_id=f"principal-{identity}",
        gateway_session_id=f"gateway-{identity}-1",
        target_system_id="orders-system",
        source_scopes=scopes,
        deployment_scope_ceiling=scopes,
        scope_mapping={scope: {scope} for scope in scopes},
        tenant_context={"tenant_id": f"tenant-{identity}"},
        auth_state_handle=f"auth-{identity}-1",
    )


def _result(value: types.CallToolResult) -> dict[str, JsonValue]:
    assert isinstance(value.structuredContent, dict)
    result = value.structuredContent.get("result")
    assert isinstance(result, dict)
    return cast(dict[str, JsonValue], result)


@pytest.mark.parametrize(
    "conflicting_name",
    [
        "orders.update.prepare",
        "acc_action_approve",
        "acc_action_commit",
        "acc_action_status",
    ],
)
def test_action_lifecycle_rejects_a_conflicting_read_tool_name(conflicting_name: str) -> None:
    coordinator, _, _ = _coordinator()
    runtime = _ReadRuntime(
        [
            {
                "name": conflicting_name,
                "input_schema": {"type": "object"},
                "output_schema": {"type": "object"},
            }
        ]
    )
    server = PrincipalCapabilityMcpServer(
        runtime,
        resolver=cast(GatewayPrincipalResolver, object()),
        action_coordinator=coordinator,
    )

    with pytest.raises(TypeError, match="Action lifecycle tool name collision"):
        server.list_tools()


def test_gateway_runtime_rejects_action_dependencies_for_a_read_only_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import acc_runtime.gateway.runtime as gateway_runtime_module
    import acc_runtime.runtime as runtime_module

    project = {
        "schema_version": "2",
        "project": {"id": "orders-system", "version": "2.0.0"},
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
                "scope_mapping": {"orders:read": ["orders.read"]},
            },
        },
        "quality": {"profile": "standard"},
    }
    loaded = SimpleNamespace(
        ir={"project": project, "capabilities": {}, "operations": {}, "policies": {}},
        manifest=SimpleNamespace(project_id="orders-system", project_version="2.0.0"),
        verification=SimpleNamespace(sha256="a" * 64),
    )

    class _GenericRuntime:
        interaction_sha256 = "c" * 64

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def tools(self) -> list[dict[str, object]]:
            return []

        def interaction_manifest(self) -> dict[str, JsonValue]:
            return {
                "schema_version": "2",
                "digest": self.interaction_sha256,
                "inventory": {"status": "not_declared"},
                "contracts": {},
                "dependencies": [],
            }

    monkeypatch.setattr(gateway_runtime_module, "load_pack", lambda path: loaded)
    monkeypatch.setattr(runtime_module, "GenericRuntime", _GenericRuntime)

    with pytest.raises(RuntimeConfigurationError) as captured:
        create_gateway_runtime(
            pack_path="read-only.accpkg",
            settings=GatewaySettings(allowed_hosts=("gateway.test",)),
            environment={"SOURCE_BASE_URL": "https://source.test"},
            audit_deployment_salt=b"test-only-deployment-salt",
            action_dependencies=cast(ActionRuntimeDependencies, object()),
        )

    assert captured.value.details == {"reason": "action_ir_binding_mismatch"}


@pytest.mark.anyio
async def test_official_sdk_executes_action_lifecycle_with_replay_and_owner_isolation() -> None:
    coordinator, authority, executor = _coordinator()
    app = _build_app(coordinator)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        GatewaySessionClient("http://gateway.test", transport=transport) as gateway_a,
        GatewaySessionClient("http://gateway.test", transport=transport) as gateway_b,
    ):
        token_a = await gateway_a.login(
            identity=SecretValue("a"), password=SecretValue("correct-password")
        )
        await gateway_b.login(identity=SecretValue("b"), password=SecretValue("correct-password"))
        async with gateway_a.mcp_client() as client_a, gateway_b.mcp_client() as client_b:
            assert client_a.initialized.protocolVersion == types.LATEST_PROTOCOL_VERSION
            listed = await client_a.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            assert set(tools) == {
                "orders.update.prepare",
                "acc_action_approve",
                "acc_action_commit",
                "acc_action_status",
            }
            assert tools["orders.update.prepare"].inputSchema == {
                "type": "object",
                "additionalProperties": False,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            }
            assert tools["orders.update.prepare"].annotations == types.ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            )
            assert tools["acc_action_commit"].annotations == types.ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            )
            assert tools["acc_action_status"].annotations == types.ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            )
            for name, required in {
                "orders.update.prepare": {
                    "action_handle",
                    "approval_required",
                    "capability_id",
                    "expires_at",
                    "preview",
                    "status",
                },
                "acc_action_approve": {"capability_id", "result", "status"},
                "acc_action_commit": {"capability_id", "replayed", "result", "status"},
                "acc_action_status": {"capability_id", "result", "status"},
            }.items():
                output_schema = tools[name].outputSchema
                assert output_schema is not None
                result_schema = output_schema["properties"]["result"]
                assert result_schema["additionalProperties"] is False
                assert set(result_schema["required"]) == required

            prepared_result = await client_a.call_tool(
                "orders.update.prepare",
                {"order_id": "order-1"},
            )
            prepared = _result(prepared_result)
            action_handle = prepared["action_handle"]
            assert isinstance(action_handle, str)
            assert prepared["status"] == "prepared"
            assert prepared["approval_required"] is True

            owner_denied = await client_b.call_tool(
                "acc_action_status", {"action_handle": action_handle}
            )
            assert owner_denied.isError is True
            assert owner_denied.structuredContent == {
                "error": {
                    "code": "ACC_RUNTIME_ACTION_BINDING_MISMATCH",
                    "status": 403,
                    "details": {},
                }
            }

            binding = await coordinator.approval_binding_for_trusted_host(
                action_handle, _principal("a")
            )
            invalid_approval_secret = "s" * 43
            invalid_approval = await client_a.call_tool(
                "acc_action_approve",
                {
                    "action_handle": action_handle,
                    "approval_handle": invalid_approval_secret,
                },
            )
            assert invalid_approval.isError is True
            assert invalid_approval.structuredContent == {
                "error": {
                    "code": "ACC_RUNTIME_ACTION_APPROVAL_INVALID",
                    "status": 403,
                    "details": {},
                }
            }
            assert invalid_approval_secret not in repr(invalid_approval)
            approval = await authority.issue_for_testing(binding, expires_in_seconds=30)
            approved = _result(
                await client_a.call_tool(
                    "acc_action_approve",
                    {
                        "action_handle": action_handle,
                        "approval_handle": approval.get_secret_value(),
                    },
                )
            )
            assert approved["status"] == "approved"

            first = _result(
                await client_a.call_tool("acc_action_commit", {"action_handle": action_handle})
            )
            replay = _result(
                await client_a.call_tool("acc_action_commit", {"action_handle": action_handle})
            )
            status = _result(
                await client_a.call_tool("acc_action_status", {"action_handle": action_handle})
            )
            assert first == {
                "capability_id": "orders.update",
                "status": "succeeded",
                "result": {"status": "approved", "owner": "principal-a"},
                "replayed": False,
            }
            assert replay == {**first, "replayed": True}
            assert status == {
                "capability_id": "orders.update",
                "status": "succeeded",
                "result": {"status": "approved", "owner": "principal-a"},
            }
            assert len(executor.commit_calls) == 1
            assert PRIVATE_IDEMPOTENCY_KEY not in repr(
                [prepared_result, owner_denied, first, replay, status]
            )

            owner_probe = await gateway_b.probe_raw_mcp_session_owner_rejection(
                cast(str, client_a.session_id)
            )
            assert owner_probe.rejected is True

        logout = await gateway_a.logout()
        assert logout.logout_status == 204
        assert logout.old_token_status == 401
        async with gateway_b.mcp_client() as survivor:
            assert {tool.name for tool in (await survivor.list_tools()).tools} == set(tools)

        leaked = repr((owner_denied, logout, token_a))
        assert action_handle not in repr(owner_denied)
        assert approval.get_secret_value() not in leaked
        assert PRIVATE_IDEMPOTENCY_KEY not in leaked
