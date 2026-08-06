from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.client.stdio import StdioServerParameters

from acc_runtime.credentials import SecretValue
from acc_testkit.mcp_client import McpStdioTestClient, McpStreamableHttpTestClient

ROOT = Path(__file__).resolve().parents[3]


class _TrackingTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler: httpx.AsyncBaseTransport) -> None:
        self.handler = handler
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.handler.handle_async_request(request)

    async def aclose(self) -> None:
        self.closed = True
        await self.handler.aclose()


def _assert_testkit_traceback_has_no_raw_secret(error: BaseException, *secrets: str) -> None:
    pending: list[object] = []
    traceback = error.__traceback__
    while traceback is not None:
        if "/packages/acc-testkit/" in traceback.tb_frame.f_code.co_filename:
            pending.extend(traceback.tb_frame.f_locals.values())
        traceback = traceback.tb_next

    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if value is None or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, str):
            assert all(secret not in value for secret in secrets)
        elif isinstance(value, bytes):
            assert all(secret.encode() not in value for secret in secrets)
        elif isinstance(value, SecretValue):
            continue
        elif isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
        elif isinstance(value, httpx.AsyncClient):
            pending.append(value.headers)
        elif isinstance(value, McpStreamableHttpTestClient):
            pending.extend(vars(value).values())
        elif isinstance(value, BaseException):
            pending.extend([value.args, value.__cause__, value.__context__])


SERVER_CODE = """
from __future__ import annotations

from collections.abc import Mapping

import anyio
from pydantic import JsonValue

from acc_runtime.mcp import CapabilityMcpServer


class Runtime:
    def tools(self) -> list[dict[str, object]]:
        return [{
            "name": "example.echo",
            "title": "Echo",
            "description": "Return the supplied value.",
            "input_schema": {
                "type": "object",
                "required": ["value"],
                "properties": {"value": {}},
            },
            "output_schema": {"type": "object"},
        }]

    async def call(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        return {"capability": capability_id, "value": arguments["value"]}


anyio.run(CapabilityMcpServer(Runtime()).run_stdio)
"""


@pytest.mark.asyncio
async def test_mcp_stdio_client_initializes_lists_and_calls_tools() -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(ROOT / "packages" / "acc-core" / "src"),
            str(ROOT / "packages" / "acc-runtime" / "src"),
            environment.get("PYTHONPATH", ""),
        ]
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", SERVER_CODE],
        env=environment,
        cwd=ROOT,
    )

    async with McpStdioTestClient(parameters) as client:
        assert client.initialized.serverInfo.name == "acc-runtime"
        tools = await client.list_tools()
        result = await client.call_tool("example.echo", {"value": "hello"})

    assert [tool.name for tool in tools.tools] == ["example.echo"]
    assert result.isError is False
    assert result.structuredContent == {"result": {"capability": "example.echo", "value": "hello"}}


@pytest.mark.asyncio
async def test_mcp_stdio_client_requires_an_active_context() -> None:
    client = McpStdioTestClient(StdioServerParameters(command=sys.executable, args=["-c", "pass"]))

    with pytest.raises(RuntimeError, match="not connected"):
        await client.list_tools()


def _jsonrpc_response(request: httpx.Request) -> httpx.Response:
    payload = __import__("json").loads(request.content)
    method = payload.get("method")
    request_id = payload.get("id")
    headers = {"content-type": "application/json"}
    result: dict[str, Any]
    if method == "initialize":
        headers["mcp-session-id"] = "mcp-session-a"
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "serverInfo": {"name": "fake-gateway", "version": "1"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "example.echo",
                    "description": "Echo",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
    elif method == "tools/call":
        result = {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"value": payload["params"]["arguments"]["value"]},
            "isError": False,
        }
    else:
        return httpx.Response(202, request=request)
    return httpx.Response(
        200,
        headers=headers,
        json={"jsonrpc": "2.0", "id": request_id, "result": result},
        request=request,
    )


@pytest.mark.asyncio
async def test_mcp_streamable_http_client_initializes_lists_calls_and_deletes_with_bearer() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204, request=request)
        if request.method == "GET":
            return httpx.Response(405, request=request)
        if request.url.host == "evil.test":
            return httpx.Response(204, request=request)
        return _jsonrpc_response(request)

    shared_transport = _TrackingTransport(httpx.MockTransport(handler))
    injected = httpx.AsyncClient(
        transport=shared_transport,
        headers={
            "Origin": "https://evil.test",
            "Cookie": "session=client-default-cookie",
            "X-Default-Secret": "client-default-secret",
        },
        auth=httpx.BasicAuth("default-user", "client-basic-secret"),
        follow_redirects=True,
    )
    token = SecretValue("gateway-token-private")
    try:
        async with McpStreamableHttpTestClient(
            "https://gateway.test/mcp",
            token,
            transport=shared_transport,
        ) as client:
            assert client.initialized.serverInfo.name == "fake-gateway"
            assert client.session_id == "mcp-session-a"
            tools = await client.list_tools()
            result = await client.call_tool("example.echo", {"value": "hello"})

        assert [tool.name for tool in tools.tools] == ["example.echo"]
        assert result.structuredContent == {"value": "hello"}
        assert injected.is_closed is False
        assert shared_transport.closed is False
        assert requests[-1].method == "DELETE"
        assert all(
            request.headers["authorization"] == "Bearer gateway-token-private"
            for request in requests
        )
        assert all(request.headers["origin"] == "https://gateway.test" for request in requests)
        assert all(request.url == httpx.URL("https://gateway.test/mcp") for request in requests)
        assert requests[-1].headers["mcp-session-id"] == "mcp-session-a"
        assert all("x-default-secret" not in request.headers for request in requests)
        assert all("cookie" not in request.headers for request in requests)
        assert "gateway-token-private" not in repr(client)
        assert injected.headers["origin"] == "https://evil.test"
        assert injected.headers["cookie"] == "session=client-default-cookie"

        await injected.get("https://evil.test/outside")
        outside = requests[-1]
        assert outside.url == httpx.URL("https://evil.test/outside")
        assert outside.headers["authorization"] != "Bearer gateway-token-private"
        assert outside.headers["origin"] == "https://evil.test"
    finally:
        await injected.aclose()


@pytest.mark.asyncio
async def test_mcp_streamable_http_client_requires_secret_and_active_context() -> None:
    with pytest.raises(TypeError, match="SecretValue"):
        McpStreamableHttpTestClient("https://gateway.test/mcp", "raw-token")  # type: ignore[arg-type]

    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue("gateway-token-private")
    )
    assert client.session_id is None
    with pytest.raises(RuntimeError, match="not connected"):
        await client.list_tools()


@pytest.mark.parametrize(
    "url",
    [
        "gateway.test/mcp",
        "ftp://gateway.test/mcp",
        "https://user:password@gateway.test/mcp",
        "https://gateway.test/mcp?token=private",
        "https://gateway.test/mcp#fragment",
    ],
)
def test_mcp_streamable_http_client_rejects_non_fixed_or_secret_bearing_urls(url: str) -> None:
    with pytest.raises(ValueError, match="absolute HTTP\\(S\\) endpoint"):
        McpStreamableHttpTestClient(url, SecretValue("gateway-token-private"))


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_mcp_streamable_http_client_closes_its_own_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204, request=request)
        if request.method == "GET":
            return httpx.Response(405, request=request)
        return _jsonrpc_response(request)

    owned = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    def client_factory(**kwargs: object) -> httpx.AsyncClient:
        assert kwargs["follow_redirects"] is False
        owned.headers.update(kwargs["headers"])  # type: ignore[arg-type]
        return owned

    monkeypatch.setattr("acc_testkit.mcp_client.streamable_http.httpx.AsyncClient", client_factory)

    async with McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue("gateway-token-private")
    ):
        pass

    assert owned.is_closed is True
    assert requests[-1].method == "DELETE"
    assert requests[-1].headers["authorization"] == "Bearer gateway-token-private"


@pytest.mark.asyncio
async def test_mcp_streamable_http_connection_error_traceback_drops_raw_client_secrets() -> None:
    token = "gateway-token-private"
    other_secret = "preconfigured-client-secret"

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"{token} {other_secret}", request=request)

    transport = _TrackingTransport(httpx.MockTransport(fail))
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue(token), transport=transport
    )
    try:
        with pytest.raises(RuntimeError, match="connection failed") as caught:
            async with client:
                pass
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        _assert_testkit_traceback_has_no_raw_secret(caught.value, token)
        assert transport.closed is False
    finally:
        await transport.aclose()


@pytest.mark.asyncio
async def test_cancelled_http_open_does_not_close_borrowed_transport() -> None:
    token = "gateway-token-private"
    started = asyncio.Event()

    async def wait_forever(_request: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    transport = _TrackingTransport(httpx.MockTransport(wait_forever))
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue(token), transport=transport
    )

    async def connect() -> None:
        async with client:
            pass

    task = asyncio.create_task(connect())
    try:
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        _assert_testkit_traceback_has_no_raw_secret(caught.value, token)
        assert transport.closed is False
    finally:
        if not task.done():
            task.cancel()
        await transport.aclose()


@pytest.mark.asyncio
async def test_failed_http_open_keeps_borrowed_transport_for_a_clean_retry() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        if request.method == "GET":
            return httpx.Response(405, request=request)
        if request.method == "DELETE":
            return httpx.Response(204, request=request)
        payload = __import__("json").loads(request.content)
        if payload.get("method") == "initialize":
            attempts += 1
            if attempts == 1:
                raise httpx.ConnectError("temporary failure", request=request)
        return _jsonrpc_response(request)

    transport = _TrackingTransport(httpx.MockTransport(handler))
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp",
        SecretValue("gateway-token-private"),
        transport=transport,
    )
    try:
        with pytest.raises(RuntimeError, match="connection failed"):
            async with client:
                pass
        async with client:
            assert client.session_id == "mcp-session-a"
        assert attempts == 2
        assert transport.closed is False
    finally:
        await transport.aclose()


@pytest.mark.asyncio
async def test_http_client_rejects_concurrent_enter_before_first_await_completes() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = __import__("json").loads(request.content) if request.content else {}
        if payload.get("method") == "initialize":
            started.set()
            await release.wait()
        if request.method == "GET":
            return httpx.Response(405, request=request)
        if request.method == "DELETE":
            return httpx.Response(204, request=request)
        return _jsonrpc_response(request)

    transport = _TrackingTransport(httpx.MockTransport(handler))
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue("gateway-token-private"), transport=transport
    )
    close_first = asyncio.Event()

    async def first_context() -> None:
        async with client:
            await close_first.wait()

    first = asyncio.create_task(first_context())
    try:
        await started.wait()
        with pytest.raises(RuntimeError, match="already connected"):
            await client.__aenter__()
        release.set()
        close_first.set()
        await first
    finally:
        release.set()
        if not first.done():
            first.cancel()
        await transport.aclose()


@pytest.mark.asyncio
async def test_two_gateway_clients_share_transport_without_token_or_default_leaks() -> None:
    seen: list[tuple[str, str | None, str | None]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        authorization = request.headers.get("authorization", "")
        seen.append(
            (
                authorization,
                request.headers.get("cookie"),
                request.headers.get("x-default-secret"),
            )
        )
        await asyncio.sleep(0)
        if request.method == "GET":
            return httpx.Response(405, request=request)
        if request.method == "DELETE":
            return httpx.Response(204, request=request)
        response = _jsonrpc_response(request)
        if "token-a" in authorization and "mcp-session-id" in response.headers:
            response.headers["mcp-session-id"] = "session-a"
        elif "token-b" in authorization and "mcp-session-id" in response.headers:
            response.headers["mcp-session-id"] = "session-b"
        return response

    shared_transport = _TrackingTransport(httpx.MockTransport(handler))
    external = httpx.AsyncClient(
        transport=shared_transport,
        headers={"Cookie": "default=cookie", "X-Default-Secret": "do-not-send"},
        auth=httpx.BasicAuth("default", "secret"),
        follow_redirects=True,
    )
    client_a = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue("token-a"), transport=shared_transport
    )
    client_b = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue("token-b"), transport=shared_transport
    )
    try:

        async def exercise(client: McpStreamableHttpTestClient) -> str | None:
            async with client:
                session_id = client.session_id
                await client.list_tools()
                return session_id

        session_a, session_b = await asyncio.gather(exercise(client_a), exercise(client_b))
        assert session_a == "session-a"
        assert session_b == "session-b"
        assert {authorization for authorization, _, _ in seen} == {
            "Bearer token-a",
            "Bearer token-b",
        }
        assert all(cookie is None and default_secret is None for _, cookie, default_secret in seen)
        assert external.headers["cookie"] == "default=cookie"
        assert external.headers["x-default-secret"] == "do-not-send"
        assert external.is_closed is False
        assert shared_transport.closed is False
    finally:
        await external.aclose()


@pytest.mark.asyncio
async def test_gateway_requests_never_follow_redirects_to_another_origin() -> None:
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            307, headers={"Location": "https://evil.test/capture"}, request=request
        )

    transport = _TrackingTransport(httpx.MockTransport(redirect))
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp",
        SecretValue("gateway-token-private"),
        transport=transport,
    )
    try:
        with pytest.raises(RuntimeError, match="connection failed"):
            async with client:
                pass
        assert [request.url for request in requests] == [httpx.URL("https://gateway.test/mcp")]
        assert requests[0].headers["origin"] == "https://gateway.test"
    finally:
        await transport.aclose()


@pytest.mark.asyncio
async def test_gateway_bearer_never_reaches_borrowed_client_request_hooks() -> None:
    hook_headers: list[httpx.Headers] = []
    transport_requests: list[httpx.Request] = []

    async def malicious_hook(request: httpx.Request) -> None:
        hook_headers.append(request.headers)
        request.url = httpx.URL("https://evil.test/capture")

    def handler(request: httpx.Request) -> httpx.Response:
        transport_requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204, request=request)
        if request.method == "GET":
            return httpx.Response(405, request=request)
        return _jsonrpc_response(request)

    shared_transport = _TrackingTransport(httpx.MockTransport(handler))
    hooked_client = httpx.AsyncClient(
        transport=shared_transport,
        event_hooks={"request": [malicious_hook]},
    )
    with pytest.raises(ValueError, match="AsyncBaseTransport via transport"):
        McpStreamableHttpTestClient(
            "https://gateway.test/mcp",
            SecretValue("gateway-token-private"),
            http_client=hooked_client,
        )
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp",
        SecretValue("gateway-token-private"),
        transport=shared_transport,
    )
    try:
        async with client:
            pass
        assert hook_headers == []
        assert all(request.url.host == "gateway.test" for request in transport_requests)
        assert hooked_client.is_closed is False
        assert shared_transport.closed is False
    finally:
        await hooked_client.aclose()


@pytest.mark.asyncio
async def test_gateway_client_rejects_async_client_injection_with_safe_migration() -> None:
    injected = httpx.AsyncClient()
    try:
        with pytest.raises(ValueError, match="AsyncBaseTransport via transport"):
            McpStreamableHttpTestClient(
                "https://gateway.test/mcp",
                SecretValue("gateway-token-private"),
                http_client=injected,
            )
        assert injected.is_closed is False
    finally:
        await injected.aclose()


@pytest.mark.asyncio
async def test_http_client_rejects_a_second_exit_while_the_owner_is_closing() -> None:
    entered = asyncio.Event()
    close = asyncio.Event()
    deleting = asyncio.Event()
    release_delete = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deleting.set()
            await release_delete.wait()
            return httpx.Response(204, request=request)
        if request.method == "GET":
            return httpx.Response(405, request=request)
        return _jsonrpc_response(request)

    transport = _TrackingTransport(httpx.MockTransport(handler))
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp",
        SecretValue("gateway-token-private"),
        transport=transport,
    )

    async def owner() -> None:
        await client.__aenter__()
        entered.set()
        await close.wait()
        await client.__aexit__(None, None, None)

    task = asyncio.create_task(owner())
    try:
        await entered.wait()
        close.set()
        await deleting.wait()
        with pytest.raises(RuntimeError, match="not connected"):
            await client.__aexit__(None, None, None)
        release_delete.set()
        await task
    finally:
        release_delete.set()
        if not task.done():
            task.cancel()
        await transport.aclose()
