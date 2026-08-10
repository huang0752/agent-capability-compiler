from __future__ import annotations

import httpx
import pytest

from acc_runtime.credentials import SecretValue
from acc_testkit import (
    GatewayRawMcpSessionOwnerProbe,
    GatewaySessionClient,
    McpStreamableHttpTestClient,
)


@pytest.mark.asyncio
async def test_gateway_session_client_logs_in_attests_builds_mcp_and_verifies_logout() -> None:
    requests: list[httpx.Request] = []
    logged_out = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal logged_out
        requests.append(request)
        if request.url.path == "/runtime/sessions" and request.method == "POST":
            return httpx.Response(
                201,
                json={"token": "gateway-token-private", "expires_in_seconds": 60},
                request=request,
            )
        if request.url.path == "/runtime/info" and request.method == "GET":
            if logged_out:
                return httpx.Response(401, request=request)
            return httpx.Response(
                200,
                json={
                    "pack_sha256": "a" * 64,
                    "project_id": "project-a",
                    "project_version": "1.0.0",
                    "tool_schema_sha256": "b" * 64,
                    "transport": "streamable_http",
                },
                request=request,
            )
        if request.url.path == "/runtime/sessions/current" and request.method == "DELETE":
            logged_out = True
            return httpx.Response(204, request=request)
        if request.url.path == "/mcp":
            return httpx.Response(404, request=request)
        return httpx.Response(404, request=request)

    transport = httpx.MockTransport(handler)
    client = GatewaySessionClient("https://gateway.test", transport=transport)

    async with client:
        token = await client.login(
            identity=SecretValue("identity-private"),
            password=SecretValue("password-private"),
        )
        assert isinstance(token, SecretValue)
        info = await client.runtime_info()
        mcp = client.mcp_client()
        assert isinstance(mcp, McpStreamableHttpTestClient)
        assert info.project_id == "project-a"
        assert info.pack_sha256 == "a" * 64
        owner_probe = await client.probe_raw_mcp_session_owner_rejection("mcp-session-a")
        assert owner_probe == GatewayRawMcpSessionOwnerProbe(
            post_status=404,
            get_status=404,
            delete_status=404,
        )
        await client.logout()

    assert [request.url.path for request in requests] == [
        "/runtime/sessions",
        "/runtime/info",
        "/mcp",
        "/mcp",
        "/mcp",
        "/runtime/sessions/current",
        "/runtime/info",
    ]
    assert all(request.headers["origin"] == "https://gateway.test" for request in requests)
    assert requests[1].headers["authorization"] == "Bearer gateway-token-private"
    assert requests[2].headers["authorization"] == "Bearer gateway-token-private"
    owner_requests = requests[2:5]
    assert [request.method for request in owner_requests] == ["POST", "GET", "DELETE"]
    assert all(request.headers["mcp-session-id"] == "mcp-session-a" for request in owner_requests)
    assert "identity-private" not in repr(client)
    assert "password-private" not in repr(client)
    assert "gateway-token-private" not in repr(client)


def test_gateway_session_client_requires_secret_values_and_fixed_base_url() -> None:
    with pytest.raises(ValueError, match="Gateway base URL"):
        GatewaySessionClient("https://user:secret@gateway.test")

    client = GatewaySessionClient("https://gateway.test")
    with pytest.raises(TypeError, match="SecretValue"):
        client._validate_credentials("raw", SecretValue("password"))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_gateway_session_connection_failure_drops_raw_credentials_and_exception_chain() -> (
    None
):
    identity = "identity-traceback-private"
    password = "password-traceback-private"

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"{identity} {password}", request=request)

    client = GatewaySessionClient(
        "https://gateway.test",
        transport=httpx.MockTransport(fail),
    )
    async with client:
        with pytest.raises(RuntimeError, match="login failed") as caught:
            await client.login(
                identity=SecretValue(identity),
                password=SecretValue(password),
            )

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    traceback = caught.value.__traceback__
    while traceback is not None:
        if "/packages/acc-testkit/" in traceback.tb_frame.f_code.co_filename:
            rendered = repr(traceback.tb_frame.f_locals)
            assert identity not in rendered
            assert password not in rendered
        traceback = traceback.tb_next


@pytest.mark.asyncio
async def test_owner_probe_failure_drops_token_session_id_and_exception_chain() -> None:
    token = "gateway-owner-probe-token-private"
    session_id = "mcp-owner-probe-session-private"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runtime/sessions":
            return httpx.Response(
                201,
                json={"token": token, "expires_in_seconds": 60},
                request=request,
            )
        raise httpx.ConnectError(f"{token} {session_id}", request=request)

    client = GatewaySessionClient(
        "https://gateway.test",
        transport=httpx.MockTransport(handler),
    )
    async with client:
        await client.login(
            identity=SecretValue("identity-private"),
            password=SecretValue("password-private"),
        )
        with pytest.raises(RuntimeError, match="Gateway request failed") as caught:
            await client.probe_raw_mcp_session_owner_rejection(session_id)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    traceback = caught.value.__traceback__
    while traceback is not None:
        if "/packages/acc-testkit/" in traceback.tb_frame.f_code.co_filename:
            rendered = repr(traceback.tb_frame.f_locals)
            assert token not in rendered
            assert session_id not in rendered
        traceback = traceback.tb_next
