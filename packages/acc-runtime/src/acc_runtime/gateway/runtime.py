"""Public composition root for one single-process HTTP Gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from collections.abc import Awaitable, Callable, Collection, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

import httpx
from pydantic import JsonValue, ValidationError
from starlette.applications import Starlette

from acc_core.models import PasswordBearerAuthConfig, load_project_document
from acc_runtime.actions import (
    ActionRuntimeDependencies,
    ActionStore,
    InMemoryApprovalAuthority,
    SQLiteActionStore,
    SQLiteApprovalAuthority,
    create_runtime_action_coordinator,
)
from acc_runtime.auth import AuthUnauthorizedError, PasswordBearerAuthStrategy
from acc_runtime.auth.strategies import AsyncClientFactory
from acc_runtime.context import PrincipalContext
from acc_runtime.gateway.app import (
    DEFAULT_GATEWAY_BODY_LIMIT,
    DEFAULT_MCP_SESSION_IDLE_TIMEOUT_SECONDS,
    create_gateway_app,
)
from acc_runtime.gateway.audit import AuditCollector, AuditSink, LoggingAuditSink
from acc_runtime.gateway.auth import GatewayPrincipalResolver, GatewayTokenVerifier
from acc_runtime.gateway.models import GatewayRuntimeInfo, GatewaySettings, SessionCreateResponse
from acc_runtime.gateway.operator import (
    LocalDevelopmentOperatorApprovalConfig,
    LocalDevelopmentOperatorApprovalService,
    ProductionOperatorApprovalConfig,
    ProductionOperatorApprovalService,
)
from acc_runtime.gateway.service import GatewaySessionService
from acc_runtime.gateway.sessions import InMemoryGatewaySessionStore
from acc_runtime.gateway.sqlite_vault import (
    GatewaySessionVaultConfig,
    SQLiteGatewaySessionVault,
)
from acc_runtime.loader import load_pack
from acc_runtime.mcp import (
    PrincipalCapabilityMcpServer,
    listed_tools_sha256,
    project_mcp_output_schema,
)
from acc_runtime.providers import HttpProvider, JsonApplicationSuccessPolicy

if TYPE_CHECKING:
    from acc_runtime.runtime import GenericRuntime


class _ContextualRuntime(Protocol):
    def tools(self) -> list[dict[str, object]]: ...

    def interaction_manifest(self) -> dict[str, JsonValue]: ...

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue: ...


class _ReauthService(Protocol):
    async def mark_reauth_required(self, session_id: str) -> None: ...


class _ReauthCoordinatingRuntime:
    """Translate a source 401 into reauthentication for exactly one Gateway session."""

    __slots__ = ("_runtime", "_service")

    def __init__(self, runtime: _ContextualRuntime, *, service: _ReauthService) -> None:
        self._runtime = runtime
        self._service = service

    def tools(self) -> list[dict[str, object]]:
        return self._runtime.tools()

    def interaction_manifest(self) -> dict[str, JsonValue]:
        return self._runtime.interaction_manifest()

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        try:
            return await self._runtime.call_with_context(
                capability_id,
                arguments,
                principal_context,
            )
        except AuthUnauthorizedError as error:
            session_id = principal_context.gateway_session_id
            if session_id is not None:
                try:
                    await self._service.mark_reauth_required(session_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
            raise error from None


class _OwnedGatewayService:
    """Give the ASGI lifespan sole, idempotent ownership of runtime resources."""

    __slots__ = ("_action_resources", "_close_lock", "_closed", "_runtime", "_service")

    def __init__(
        self,
        service: GatewaySessionService,
        runtime: GenericRuntime,
        *,
        action_store: ActionStore | None = None,
        action_resources: Collection[object] = (),
    ) -> None:
        self._service = service
        self._runtime = runtime
        resources = ((action_store,) if action_store is not None else ()) + tuple(action_resources)
        self._action_resources = tuple(
            resource
            for index, resource in enumerate(resources)
            if all(resource is not previous for previous in resources[:index])
        )
        self._close_lock = asyncio.Lock()
        self._closed = False

    async def create_session(self, *, identity: str, password: str) -> SessionCreateResponse:
        return await self._service.create_session(identity=identity, password=password)

    async def startup(self) -> None:
        await self._service.startup()

    async def delete_current(self, token: str) -> None:
        await self._service.delete_current(token)

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
        failures: list[BaseException] = []
        for close in (self._service.aclose, self._runtime.aclose):
            try:
                await close()
            except BaseException as error:
                failures.append(error)
        for resource in reversed(self._action_resources):
            close_action = cast(
                Callable[[], Awaitable[object]] | None, getattr(resource, "close", None)
            )
            if close_action is None:
                continue
            try:
                await close_action()
            except BaseException as error:
                failures.append(error)
        if failures:
            raise failures[0]


class GatewayRuntimeComposition:
    """One safe public handle for an assembled Gateway and its lifecycle."""

    __slots__ = ("_owned_service", "_runtime", "_runtime_info", "app")

    def __init__(
        self,
        *,
        app: Starlette,
        owned_service: _OwnedGatewayService,
        runtime: GenericRuntime,
        runtime_info: GatewayRuntimeInfo,
    ) -> None:
        self.app = app
        self._owned_service = owned_service
        self._runtime = runtime
        self._runtime_info = runtime_info

    def __repr__(self) -> str:
        return "GatewayRuntimeComposition(app=<protected>)"

    def tools(self) -> list[dict[str, object]]:
        """Return only the Runtime's public MCP tool projection."""

        return self._runtime.tools()

    def runtime_info(self) -> GatewayRuntimeInfo:
        """Return immutable Pack, tool-schema, and interaction attestation metadata."""

        return self._runtime_info

    async def aclose(self) -> None:
        """Close resources if startup failed before ASGI lifespan entered."""

        await self._owned_service.aclose()


def _tool_schema_sha256(tools: Collection[Mapping[str, object]]) -> str:
    """Digest the public MCP tool-schema projection deterministically."""

    schemas: list[dict[str, object]] = []
    for tool in tools:
        name = tool.get("name")
        input_schema = tool.get("input_schema")
        output_schema = tool.get("output_schema")
        if (
            not isinstance(name, str)
            or not isinstance(input_schema, Mapping)
            or not isinstance(output_schema, Mapping)
        ):
            raise TypeError("runtime tool metadata is invalid")
        schemas.append(
            {
                "name": name,
                "input_schema": dict(input_schema),
                "output_schema": project_mcp_output_schema(name, output_schema),
            }
        )
    schemas.sort(key=lambda item: str(item["name"]))
    encoded = json.dumps(
        schemas,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_gateway_runtime(
    *,
    pack_path: str | Path,
    settings: GatewaySettings,
    environment: Mapping[str, str] | None = None,
    deployment_scope_ceiling: Collection[str] = (),
    mcp_session_idle_timeout_seconds: float = DEFAULT_MCP_SESSION_IDLE_TIMEOUT_SECONDS,
    max_request_body_size: int = DEFAULT_GATEWAY_BODY_LIMIT,
    audit_sink: AuditSink | None = None,
    audit_deployment_salt: bytes | None = None,
    auth_client_factory: AsyncClientFactory | None = None,
    provider_client: httpx.AsyncClient | None = None,
    action_dependencies: ActionRuntimeDependencies | None = None,
    operator_approval: LocalDevelopmentOperatorApprovalConfig | None = None,
    production_operator_approval: ProductionOperatorApprovalConfig | None = None,
    application_success_policy: JsonApplicationSuccessPolicy | None = None,
    session_vault: GatewaySessionVaultConfig | None = None,
) -> GatewayRuntimeComposition:
    """Assemble a verified Gateway and own any supplied Action deployment Store."""

    from acc_runtime.runtime import GenericRuntime, RuntimeConfigurationError

    loaded = load_pack(pack_path)
    try:
        project = load_project_document(loaded.ir.get("project"))
    except ValidationError:
        raise RuntimeConfigurationError("compiled project contract is invalid") from None
    if project.runtime.transport != ["streamable_http"]:
        raise RuntimeConfigurationError(
            "Gateway requires a streamable HTTP Pack.",
            details={"reason": "gateway_transport_invalid"},
        )
    auth = project.provider.auth
    if not isinstance(auth, PasswordBearerAuthConfig) or auth.credentials.kind != "gateway_session":
        raise RuntimeConfigurationError(
            "Gateway requires password bearer session authentication.",
            details={"reason": "gateway_auth_invalid"},
        )
    source = os.environ if environment is None else environment
    base_url = source.get(project.provider.base_url_ref)
    if not isinstance(base_url, str) or not base_url:
        raise RuntimeConfigurationError(
            "Gateway source base URL is required.",
            details={"reason": "authentication_base_url_missing"},
        )

    gateway_clock = time.time if session_vault is not None else time.monotonic
    strategy = PasswordBearerAuthStrategy(
        config=auth,
        base_url=base_url,
        credential_source=None,
        client_factory=auth_client_factory,
        clock=gateway_clock,
    )
    declared_success = project.provider.application_success
    effective_success_policy = application_success_policy or (
        JsonApplicationSuccessPolicy.from_config(declared_success)
        if declared_success is not None
        else None
    )
    provider = HttpProvider(
        base_url_ref=project.provider.base_url_ref,
        auth_strategy=strategy,
        environment=source,
        application_success_policy=effective_success_policy,
        client=provider_client,
    )
    collector = AuditCollector(
        sink=audit_sink or LoggingAuditSink(),
        deployment_salt=audit_deployment_salt or secrets.token_bytes(32),
    )
    runtime = GenericRuntime(
        loaded.ir,
        provider=provider,
        loaded_pack=loaded,
        audit_collector=collector,
    )
    has_actions = _compiled_ir_has_actions(loaded.ir)
    if has_actions and action_dependencies is None:
        raise RuntimeConfigurationError(
            "Action Pack requires explicit deployment dependencies.",
            details={"reason": "action_deployment_missing"},
        )
    if not has_actions and action_dependencies is not None:
        raise RuntimeConfigurationError(
            "Action deployment dependencies require an Action Pack.",
            details={"reason": "action_ir_binding_mismatch"},
        )
    if operator_approval is not None:
        if action_dependencies is None:
            raise RuntimeConfigurationError(
                "Operator approval requires development Action dependencies.",
                details={"reason": "operator_approval_actions_required"},
            )
        if not settings.listen_host.startswith("127.") and settings.listen_host != "::1":
            raise RuntimeConfigurationError(
                "Development operator approval requires a loopback listener.",
                details={"reason": "operator_approval_loopback_required"},
            )
        if not isinstance(action_dependencies.approval_authority, InMemoryApprovalAuthority):
            raise RuntimeConfigurationError(
                "Development operator approval requires the in-memory authority.",
                details={"reason": "operator_approval_authority_invalid"},
            )
    if operator_approval is not None and production_operator_approval is not None:
        raise RuntimeConfigurationError(
            "Development and production operator approval are mutually exclusive.",
            details={"reason": "operator_approval_modes_conflict"},
        )
    if production_operator_approval is not None:
        if action_dependencies is None or session_vault is None:
            raise RuntimeConfigurationError(
                "Production operator approval requires production Action dependencies.",
                details={"reason": "production_operator_dependencies_required"},
            )
        if not settings.listen_host.startswith("127.") and settings.listen_host != "::1":
            raise RuntimeConfigurationError(
                "Production operator approval requires a loopback listener.",
                details={"reason": "production_operator_loopback_required"},
            )
        if not isinstance(action_dependencies.approval_authority, SQLiteApprovalAuthority):
            raise RuntimeConfigurationError(
                "Production operator approval requires the durable SQLite authority.",
                details={"reason": "production_operator_authority_invalid"},
            )
        action_dependencies.validate_production(session_vault=session_vault)
    action_coordinator = None
    if action_dependencies is not None:
        action_coordinator = create_runtime_action_coordinator(
            loaded.ir,
            pack_digest="sha256:" + loaded.verification.sha256,
            provider=provider,
            dependencies=action_dependencies,
        )
    scope_mapping_bytes = json.dumps(
        auth.model_dump(mode="json").get("scope_mapping", {}),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    scope_ceiling_bytes = json.dumps(
        sorted(deployment_scope_ceiling), separators=(",", ":")
    ).encode()
    store = (
        InMemoryGatewaySessionStore(
            max_sessions=settings.max_sessions,
            ttl_seconds=settings.session_ttl_seconds,
        )
        if session_vault is None
        else SQLiteGatewaySessionVault(
            session_vault.db_path,
            project_id=project.project.id,
            pack_sha256=loaded.verification.sha256,
            scope_mapping_sha256=hashlib.sha256(scope_mapping_bytes).hexdigest(),
            scope_ceiling_sha256=hashlib.sha256(scope_ceiling_bytes).hexdigest(),
            kek=session_vault.kek,
            deployment_salt=session_vault.deployment_salt,
            max_sessions=settings.max_sessions,
            ttl_seconds=settings.session_ttl_seconds,
            clock=gateway_clock,
        )
    )
    service = GatewaySessionService(
        auth_strategy=strategy,
        auth_config=auth,
        store=store,
        target_system_id=project.project.id,
        deployment_scope_ceiling=deployment_scope_ceiling,
        clock=gateway_clock,
    )
    owned_service = _OwnedGatewayService(
        service,
        runtime,
        action_store=(None if action_dependencies is None else action_dependencies.store),
        action_resources=(
            ()
            if action_dependencies is None
            else (
                action_dependencies.approval_authority,
                action_dependencies.audit_sink,
            )
        ),
    )
    resolver = GatewayPrincipalResolver(store=store, project_id=project.project.id)
    token_verifier = GatewayTokenVerifier(store=store, project_id=project.project.id)
    coordinated_runtime = _ReauthCoordinatingRuntime(runtime, service=service)
    development_operator_service = (
        None
        if operator_approval is None or action_coordinator is None or action_dependencies is None
        else LocalDevelopmentOperatorApprovalService(
            config=operator_approval,
            coordinator=action_coordinator,
            authority=cast(
                InMemoryApprovalAuthority,
                action_dependencies.approval_authority,
            ),
            session_store=store,
            clock=(
                time.time
                if isinstance(action_dependencies.store, SQLiteActionStore)
                else time.monotonic
            ),
        )
    )
    production_operator_service = (
        None
        if production_operator_approval is None
        or action_coordinator is None
        or action_dependencies is None
        or not isinstance(store, SQLiteGatewaySessionVault)
        else ProductionOperatorApprovalService(
            config=production_operator_approval,
            coordinator=action_coordinator,
            authority=cast(SQLiteApprovalAuthority, action_dependencies.approval_authority),
            session_store=store,
        )
    )
    operator_observer = production_operator_service or development_operator_service
    mcp_server = PrincipalCapabilityMcpServer(
        coordinated_runtime,
        resolver=resolver,
        action_coordinator=action_coordinator,
        action_prepare_observer=operator_observer,
    )
    runtime_info = GatewayRuntimeInfo(
        pack_sha256=loaded.verification.sha256,
        project_id=loaded.manifest.project_id,
        project_version=loaded.manifest.project_version,
        interaction_sha256=runtime.interaction_sha256,
        tool_schema_sha256=listed_tools_sha256(mcp_server.list_tools()),
        transport="streamable_http",
    )
    app = create_gateway_app(
        settings=settings,
        service=owned_service,
        token_verifier=token_verifier,
        mcp_server=mcp_server,
        runtime_info=runtime_info,
        max_request_body_size=max_request_body_size,
        mcp_session_idle_timeout_seconds=mcp_session_idle_timeout_seconds,
        operator_approval_service=development_operator_service,
        production_operator_approval_service=production_operator_service,
    )
    return GatewayRuntimeComposition(
        app=app,
        owned_service=owned_service,
        runtime=runtime,
        runtime_info=runtime_info,
    )


def _compiled_ir_has_actions(compiled_ir: object) -> bool:
    if not isinstance(compiled_ir, Mapping):
        return False
    capabilities = compiled_ir.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return False
    return any(
        isinstance(compiled, Mapping)
        and isinstance(compiled.get("definition"), Mapping)
        and compiled["definition"].get("kind") == "action"
        for compiled in capabilities.values()
    )


__all__ = ["GatewayRuntimeComposition", "create_gateway_runtime"]
