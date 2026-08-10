from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, cast

import pytest
from mcp import types
from mcp.server.lowlevel import Server
from pydantic import JsonValue, SecretStr
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.types import Message

from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway.app import create_gateway_app
from acc_runtime.gateway.auth import GatewayPrincipalResolver, GatewayTokenVerifier
from acc_runtime.gateway.models import (
    GatewayRuntimeInfo,
    GatewaySettings,
    SessionCreateResponse,
)
from acc_runtime.gateway.sessions import InMemoryGatewaySessionStore
from acc_runtime.mcp import PrincipalCapabilityMcpServer

_RUNTIME_INFO = GatewayRuntimeInfo(
    pack_sha256="a" * 64,
    project_id="project-a",
    project_version="1.2.3",
    tool_schema_sha256="b" * 64,
    transport="streamable_http",
)


def _token(seed: int) -> str:
    return base64.urlsafe_b64encode(bytes([seed]) * 32).rstrip(b"=").decode()


class FakeSessionService:
    def __init__(self, store: InMemoryGatewaySessionStore) -> None:
        self.store = store
        self.closed = False
        self.created = 0

    async def create_session(self, *, identity: str, password: str) -> SessionCreateResponse:
        if password != "correct-password" or identity not in {"a", "b", "c"}:
            raise ValueError("login failed")
        self.created += 1
        session_id = f"gateway-{identity}-{self.created}"
        context = PrincipalContext(
            principal_id=f"principal-{identity}",
            gateway_session_id=session_id,
            target_system_id="project-a",
            source_scopes={"records:read"},
            deployment_scope_ceiling={"records:read"},
            tenant_context={"tenant_id": identity},
            auth_state_handle=f"auth-{identity}-{self.created}",
        )
        creation = await self.store.create(
            session_id=session_id,
            principal_context=context,
        )
        raw_token = creation.token.get_secret_value()
        password = ""
        identity = ""
        return SessionCreateResponse(
            gateway_token=SecretStr(raw_token),
            expires_in_seconds=60,
        )

    async def delete_current(self, token: str) -> None:
        await self.store.revoke_token(SecretValue(token))
        token = ""

    async def aclose(self) -> None:
        self.closed = True
        await self.store.close()


class CancelledSessionService(FakeSessionService):
    async def create_session(self, *, identity: str, password: str) -> SessionCreateResponse:
        del identity, password
        raise asyncio.CancelledError()


class ContextRuntime:
    def tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": "records_list",
                "title": "Records",
                "description": "List visible records",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
                "output_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["principal"],
                    "properties": {"principal": {"type": "string"}},
                },
            }
        ]

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        assert capability_id == "records_list"
        assert arguments == {}
        return {"principal": principal_context.principal_id}


class TrackingPrincipalMcpServer(PrincipalCapabilityMcpServer):
    def __init__(
        self,
        runtime: ContextRuntime,
        *,
        resolver: GatewayPrincipalResolver,
    ) -> None:
        super().__init__(runtime, resolver=resolver)
        self.active_runs = 0
        self.max_active_runs = 0
        self.finished_runs = 0

    def create_server(self) -> Server[object]:
        server = super().create_server()
        original_run = server.run

        async def tracked_run(*args: Any, **kwargs: Any) -> None:
            self.active_runs += 1
            self.max_active_runs = max(self.max_active_runs, self.active_runs)
            try:
                await original_run(*args, **kwargs)
            finally:
                self.active_runs -= 1
                self.finished_runs += 1

        server.run = tracked_run  # type: ignore[method-assign]
        return server


def _build_app(
    *, seeds: tuple[int, ...] = (1, 2, 3), max_sessions: int = 3
) -> tuple[Starlette, FakeSessionService]:
    token_values = iter(_token(seed) for seed in seeds)
    store = InMemoryGatewaySessionStore(
        max_sessions=max_sessions,
        ttl_seconds=60,
        token_generator=lambda: next(token_values),
    )
    service = FakeSessionService(store)
    verifier = GatewayTokenVerifier(store=store, project_id="project-a")
    resolver = GatewayPrincipalResolver(store=store, project_id="project-a")
    mcp_server = PrincipalCapabilityMcpServer(ContextRuntime(), resolver=resolver)
    settings = GatewaySettings(
        allowed_hosts=("gateway.test",),
        allowed_origins=("https://agent.test",),
    )
    app = create_gateway_app(
        settings=settings,
        service=service,
        token_verifier=verifier,
        mcp_server=mcp_server,
        runtime_info=_RUNTIME_INFO,
        max_request_body_size=4096,
    )
    return app, service


def _login(client: TestClient, identity: str) -> str:
    response = client.post(
        "/runtime/sessions",
        headers={"origin": "https://agent.test"},
        json={"identity": identity, "password": "correct-password"},
    )
    assert response.status_code == 201, response.text
    token = response.json().get("token")
    assert isinstance(token, str)
    return token


def _mcp_headers(token: str, session_id: str | None = None) -> dict[str, str]:
    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "origin": "https://agent.test",
    }
    if session_id is not None:
        headers["mcp-session-id"] = session_id
    return headers


def _initialize(client: TestClient, token: str) -> str:
    response = client.post(
        "/mcp",
        headers=_mcp_headers(token),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": types.LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "gateway-test", "version": "1"},
            },
        },
    )
    assert response.status_code == 200, response.text
    session_id = response.headers.get("mcp-session-id")
    assert isinstance(session_id, str) and session_id
    initialized = client.post(
        "/mcp",
        headers=_mcp_headers(token, session_id),
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert initialized.status_code == 202, initialized.text
    return session_id


def test_session_login_is_public_but_strict_and_all_mcp_requests_are_authenticated() -> None:
    app, service = _build_app()
    with TestClient(app, base_url="http://gateway.test") as client:
        malformed = client.post(
            "/runtime/sessions",
            json={
                "identity": "a",
                "password": "correct-password",
                "role": "admin",
            },
        )
        assert malformed.status_code == 400
        assert "correct-password" not in malformed.text

        token_a = _login(client, "a")
        unauthenticated = client.post(
            "/mcp",
            headers={"content-type": "application/json"},
            json={},
        )
        assert unauthenticated.status_code == 401

        session_a = _initialize(client, token_a)
        tools = client.post(
            "/mcp",
            headers=_mcp_headers(token_a, session_a),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools.status_code == 200
        assert tools.json()["result"]["tools"][0]["name"] == "records_list"

        called = client.post(
            "/mcp",
            headers=_mcp_headers(token_a, session_a),
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "records_list", "arguments": {}},
            },
        )
        assert called.status_code == 200
        structured = called.json()["result"]["structuredContent"]
        assert structured == {"result": {"principal": "principal-a"}}

        assert client.get("/mcp").status_code == 401
        assert client.delete("/mcp").status_code == 401
        terminated = client.delete(
            "/mcp",
            headers=_mcp_headers(token_a, session_a),
        )
        assert terminated.status_code == 200

    assert service.closed is True


def test_runtime_info_is_authenticated_host_origin_protected_and_contains_no_identity() -> None:
    app, _ = _build_app()
    with TestClient(app, base_url="http://gateway.test") as client:
        assert client.get("/runtime/info").status_code == 401
        token = _login(client, "a")
        headers = {
            "authorization": f"Bearer {token}",
            "origin": "https://agent.test",
        }

        response = client.get("/runtime/info", headers=headers)

        assert response.status_code == 200
        assert response.json() == _RUNTIME_INFO.model_dump(mode="json")
        for forbidden in (
            "principal-a",
            "tenant_id",
            token,
            "authorization",
            "jwt",
        ):
            assert forbidden.casefold() not in response.text.casefold()
        assert (
            client.get(
                "/runtime/info",
                headers={**headers, "host": "evil.test"},
            ).status_code
            == 421
        )
        assert (
            client.get(
                "/runtime/info",
                headers={**headers, "origin": "https://evil.test"},
            ).status_code
            == 403
        )


@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
def test_mcp_session_owner_is_checked_for_every_method(method: str) -> None:
    app, _ = _build_app()
    with TestClient(app, base_url="http://gateway.test") as client:
        token_a = _login(client, "a")
        token_b = _login(client, "b")
        session_a = _initialize(client, token_a)
        response = client.request(
            method,
            "/mcp",
            headers=_mcp_headers(token_b, session_a),
            json=(
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
                if method == "POST"
                else None
            ),
        )

        assert response.status_code == 404
        assert response.json()["error"]["message"] == "Session not found"


def test_logout_and_app_restart_invalidate_gateway_and_mcp_sessions() -> None:
    app, service = _build_app(seeds=(4, 5, 6))
    with TestClient(app, base_url="http://gateway.test") as client:
        token = _login(client, "a")
        session_id = _initialize(client, token)
        logout = client.delete(
            "/runtime/sessions/current",
            headers={
                "authorization": f"Bearer {token}",
                "origin": "https://agent.test",
            },
        )
        assert logout.status_code == 204
        assert (
            client.get(
                "/mcp",
                headers=_mcp_headers(token, session_id),
            ).status_code
            == 401
        )

    assert service.closed is True

    restarted_app, _ = _build_app(seeds=(7, 8, 9))
    with TestClient(restarted_app, base_url="http://gateway.test") as restarted:
        assert (
            restarted.post(
                "/mcp",
                headers=_mcp_headers(token, session_id),
                json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
            ).status_code
            == 401
        )


def test_capacity_and_security_failures_are_safe() -> None:
    app, _ = _build_app(seeds=(10,), max_sessions=1)
    with TestClient(app, base_url="http://gateway.test") as client:
        _login(client, "a")
        capacity = client.post(
            "/runtime/sessions",
            json={"identity": "b", "password": "correct-password"},
        )
        assert capacity.status_code == 503
        assert "correct-password" not in capacity.text

        bad_host = client.post(
            "/runtime/sessions",
            headers={"host": "evil.test"},
            json={"identity": "b", "password": "correct-password"},
        )
        assert bad_host.status_code == 421
        assert "evil.test" not in bad_host.text
        assert "correct-password" not in bad_host.text


@pytest.mark.anyio
async def test_login_cancellation_traceback_does_not_retain_credentials() -> None:
    identity = "traceback-identity-secret"
    password = "traceback-password-secret"
    token_values = iter((_token(20),))
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        token_generator=lambda: next(token_values),
    )
    service = CancelledSessionService(store)
    verifier = GatewayTokenVerifier(store=store, project_id="project-a")
    resolver = GatewayPrincipalResolver(store=store, project_id="project-a")
    app = create_gateway_app(
        settings=GatewaySettings(allowed_hosts=("gateway.test",)),
        service=service,
        token_verifier=verifier,
        mcp_server=PrincipalCapabilityMcpServer(ContextRuntime(), resolver=resolver),
        runtime_info=_RUNTIME_INFO,
    )
    route = app.routes[0]
    assert isinstance(route, Route)
    endpoint = cast(Callable[[Request], Awaitable[Response]], route.endpoint)
    body = f'{{"identity":"{identity}","password":"{password}"}}'.encode()
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/runtime/sessions",
            "raw_path": b"/runtime/sessions",
            "query_string": b"",
            "headers": [
                (b"host", b"gateway.test"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
            "client": ("127.0.0.1", 1),
            "server": ("gateway.test", 80),
        },
        receive,
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        await endpoint(request)

    traceback_text = ""
    traceback = caught.value.__traceback__
    while traceback is not None:
        if "/packages/acc-runtime/" in traceback.tb_frame.f_code.co_filename:
            traceback_text += repr(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert identity not in traceback_text
    assert password not in traceback_text


def _wait_for_no_active_mcp_runs(adapter: TrackingPrincipalMcpServer) -> None:
    deadline = time.monotonic() + 2.0
    while adapter.active_runs and time.monotonic() < deadline:
        time.sleep(0.01)
    assert adapter.active_runs == 0


def _build_tracking_app(
    *,
    seeds: range,
    max_sessions: int,
    ttl_seconds: int,
    idle_timeout_seconds: float,
) -> tuple[Starlette, FakeSessionService, TrackingPrincipalMcpServer]:
    token_values = iter(_token(seed) for seed in seeds)
    store = InMemoryGatewaySessionStore(
        max_sessions=max_sessions,
        ttl_seconds=ttl_seconds,
        token_generator=lambda: next(token_values),
    )
    service = FakeSessionService(store)
    verifier = GatewayTokenVerifier(store=store, project_id="project-a")
    resolver = GatewayPrincipalResolver(store=store, project_id="project-a")
    adapter = TrackingPrincipalMcpServer(ContextRuntime(), resolver=resolver)
    app = create_gateway_app(
        settings=GatewaySettings(
            allowed_hosts=("gateway.test",),
            allowed_origins=("https://agent.test",),
            session_ttl_seconds=ttl_seconds,
            max_sessions=max_sessions,
        ),
        service=service,
        token_verifier=verifier,
        mcp_server=adapter,
        runtime_info=_RUNTIME_INFO,
        mcp_session_idle_timeout_seconds=idle_timeout_seconds,
    )
    return app, service, adapter


def test_logout_reaps_transport_within_idle_bound_and_reuses_capacity() -> None:
    app, _, adapter = _build_tracking_app(
        seeds=range(30, 40),
        max_sessions=1,
        ttl_seconds=60,
        idle_timeout_seconds=0.03,
    )

    with TestClient(app, base_url="http://gateway.test") as client:
        for _ in range(5):
            token = _login(client, "a")
            _initialize(client, token)
            logout = client.delete(
                "/runtime/sessions/current",
                headers={"authorization": f"Bearer {token}"},
            )
            assert logout.status_code == 204
        _wait_for_no_active_mcp_runs(adapter)

    assert adapter.finished_runs == 5


def test_active_sse_is_cancelled_by_the_same_finite_idle_bound() -> None:
    app, _, adapter = _build_tracking_app(
        seeds=range(60, 64),
        max_sessions=1,
        ttl_seconds=60,
        idle_timeout_seconds=0.04,
    )

    with TestClient(app, base_url="http://gateway.test") as client:
        token = _login(client, "a")
        session_id = _initialize(client, token)
        started = time.monotonic()
        sse = client.get(
            "/mcp",
            headers=_mcp_headers(token, session_id),
        )
        elapsed = time.monotonic() - started
        assert sse.status_code == 200
        assert elapsed < 1.0
        _wait_for_no_active_mcp_runs(adapter)

    assert adapter.finished_runs == 1


def test_reauth_session_cannot_refresh_or_keep_transport_alive() -> None:
    app, service, adapter = _build_tracking_app(
        seeds=range(40, 44),
        max_sessions=1,
        ttl_seconds=60,
        idle_timeout_seconds=0.04,
    )

    with TestClient(app, base_url="http://gateway.test") as client:
        token = _login(client, "a")
        session_id = _initialize(client, token)
        assert client.portal is not None
        record = client.portal.call(service.store.resolve_token, token)
        client.portal.call(service.store.mark_reauth_required, record.session_id)
        denied = client.get(
            "/mcp",
            headers=_mcp_headers(token, session_id),
        )
        assert denied.status_code == 401
        _wait_for_no_active_mcp_runs(adapter)

    assert adapter.finished_runs == 1


def test_expired_gateway_session_and_mcp_transport_share_finite_upper_bound() -> None:
    app, _, adapter = _build_tracking_app(
        seeds=range(50, 54),
        max_sessions=1,
        ttl_seconds=1,
        idle_timeout_seconds=1.0,
    )

    with TestClient(app, base_url="http://gateway.test") as client:
        token = _login(client, "a")
        session_id = _initialize(client, token)
        _wait_for_no_active_mcp_runs(adapter)
        expired = client.get(
            "/mcp",
            headers=_mcp_headers(token, session_id),
        )
        assert expired.status_code == 401

    assert adapter.finished_runs == 1
