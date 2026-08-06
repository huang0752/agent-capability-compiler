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
        return _jsonrpc_response(request)

    injected = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    token = SecretValue("gateway-token-private")
    try:
        async with McpStreamableHttpTestClient(
            "https://gateway.test/mcp",
            token,
            http_client=injected,
        ) as client:
            assert client.initialized.serverInfo.name == "fake-gateway"
            assert client.session_id == "mcp-session-a"
            tools = await client.list_tools()
            result = await client.call_tool("example.echo", {"value": "hello"})

        assert [tool.name for tool in tools.tools] == ["example.echo"]
        assert result.structuredContent == {"value": "hello"}
        assert injected.is_closed is False
        assert requests[-1].method == "DELETE"
        assert all(
            request.headers["authorization"] == "Bearer gateway-token-private"
            for request in requests
        )
        assert all(request.headers["origin"] == "https://gateway.test" for request in requests)
        assert all(request.url == httpx.URL("https://gateway.test/mcp") for request in requests)
        assert requests[-1].headers["mcp-session-id"] == "mcp-session-a"
        assert "gateway-token-private" not in repr(client)
        assert "authorization" not in injected.headers
        assert "origin" not in injected.headers
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
async def test_mcp_streamable_http_client_rejects_redirecting_injected_client() -> None:
    injected = httpx.AsyncClient(follow_redirects=True)
    try:
        with pytest.raises(ValueError, match="redirect"):
            McpStreamableHttpTestClient(
                "https://gateway.test/mcp",
                SecretValue("gateway-token-private"),
                http_client=injected,
            )
        assert injected.is_closed is False
    finally:
        await injected.aclose()


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

    injected = httpx.AsyncClient(
        transport=httpx.MockTransport(fail),
        headers={"X-Unrelated-Secret": other_secret},
        follow_redirects=False,
    )
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue(token), http_client=injected
    )
    try:
        with pytest.raises(RuntimeError, match="connection failed") as caught:
            async with client:
                pass
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        _assert_testkit_traceback_has_no_raw_secret(caught.value, token, other_secret)
        assert "authorization" not in injected.headers
        assert "origin" not in injected.headers
        assert injected.is_closed is False
    finally:
        await injected.aclose()


@pytest.mark.asyncio
async def test_cancelled_http_open_cleans_headers_without_closing_injected_client() -> None:
    token = "gateway-token-private"
    other_secret = "preconfigured-client-secret"
    started = asyncio.Event()

    async def wait_forever(_request: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    injected = httpx.AsyncClient(
        transport=httpx.MockTransport(wait_forever),
        headers={"X-Unrelated-Secret": other_secret},
        follow_redirects=False,
    )
    client = McpStreamableHttpTestClient(
        "https://gateway.test/mcp", SecretValue(token), http_client=injected
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
        _assert_testkit_traceback_has_no_raw_secret(caught.value, token, other_secret)
        assert "authorization" not in injected.headers
        assert "origin" not in injected.headers
        assert injected.is_closed is False
    finally:
        if not task.done():
            task.cancel()
        await injected.aclose()
