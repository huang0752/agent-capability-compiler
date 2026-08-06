from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import httpx
import pytest
from starlette.types import Message, Receive, Scope, Send

from acc_runtime.gateway.security import RequestSecurityMiddleware


async def _echo(scope: object, receive: object, send: object) -> None:
    assert isinstance(scope, dict)
    assert callable(receive)
    assert callable(send)
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        body.extend(message.get("body", b""))
        if not message.get("more_body", False):
            break
    payload = json.dumps({"size": len(body)}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", str(len(payload)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _client(*, limit: int = 8) -> httpx.AsyncClient:
    app = RequestSecurityMiddleware(
        _echo,
        allowed_hosts=("gateway.test",),
        allowed_origins=("https://agent.test",),
        max_body_size=limit,
    )
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway.test",
    )


async def _raw_call(headers: list[tuple[bytes, bytes]]) -> tuple[int, bytes]:
    app = RequestSecurityMiddleware(
        _echo,
        allowed_hosts=("gateway.test",),
        allowed_origins=("https://agent.test",),
        max_body_size=8,
    )
    requests = iter([{"type": "http.request", "body": b"", "more_body": False}])
    sent: list[Message] = []

    async def receive() -> Message:
        return next(requests)

    async def send(message: Message) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1),
            "server": ("gateway.test", 80),
        },
        receive,
        send,
    )
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    body_parts = [
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    ]
    assert all(isinstance(part, bytes) for part in body_parts)
    body = b"".join(body_parts)
    assert isinstance(status, int)
    return status, body


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ([(b"host", b"")], 421),
        ([(b"host", b"gateway.test"), (b"host", b"gateway.test")], 421),
        ([(b"host", b"evil.test")], 421),
        ([(b"host", b"gateway.test"), (b"origin", b"https://evil.test")], 403),
        (
            [
                (b"host", b"gateway.test"),
                (b"origin", b"https://agent.test"),
                (b"origin", b"https://agent.test"),
            ],
            403,
        ),
    ],
)
async def test_host_and_origin_are_single_exact_values(
    headers: list[tuple[bytes, bytes]], status: int
) -> None:
    async with _client() as client:
        request = httpx.Request("GET", "http://gateway.test/mcp", headers=headers)
        response = await client.send(request)

    assert response.status_code == status
    assert "evil.test" not in response.text
    assert "agent.test" not in response.text


@pytest.mark.anyio
async def test_missing_origin_is_allowed() -> None:
    async with _client() as client:
        response = await client.get("/mcp")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_missing_or_non_ascii_host_is_rejected_without_echo() -> None:
    missing_status, _ = await _raw_call([])
    invalid_status, invalid_body = await _raw_call([(b"host", b"secret-\xff")])

    assert missing_status == 421
    assert invalid_status == 421
    assert b"secret" not in invalid_body


@pytest.mark.anyio
@pytest.mark.parametrize(
    "content_length",
    ["-1", "not-a-number", "+1", "1.0", " 1", "1 "],
)
async def test_malformed_content_length_is_rejected_without_echo(content_length: str) -> None:
    async with _client() as client:
        request = httpx.Request(
            "PUT",
            "http://gateway.test/runtime/sessions",
            headers={"content-length": content_length},
            content=b"x",
        )
        response = await client.send(request)

    assert response.status_code == 400
    assert content_length.strip() not in response.text


@pytest.mark.anyio
async def test_duplicate_content_length_is_rejected() -> None:
    async with _client() as client:
        request = httpx.Request(
            "POST",
            "http://gateway.test/runtime/sessions",
            headers=[(b"content-length", b"1"), (b"content-length", b"1")],
            content=b"x",
        )
        response = await client.send(request)

    assert response.status_code == 400


@pytest.mark.anyio
async def test_declared_and_streamed_bodies_are_bounded_for_every_method() -> None:
    secret = b"password-must-not-be-reflected"
    async with _client(limit=8) as client:
        declared = httpx.Request(
            "DELETE",
            "http://gateway.test/mcp",
            headers={"content-length": str(len(secret))},
            content=secret,
        )
        declared_response = await client.send(declared)

        async def chunks() -> AsyncIterator[bytes]:
            yield secret[:8]
            yield secret[8:]

        streamed_response = await client.request("PATCH", "/mcp", content=chunks())

    assert declared_response.status_code == 413
    assert streamed_response.status_code == 413
    assert secret.decode() not in declared_response.text
    assert secret.decode() not in streamed_response.text


@pytest.mark.anyio
async def test_exact_limit_body_is_replayed_unchanged() -> None:
    async with _client(limit=8) as client:
        response = await client.post("/runtime/sessions", content=b"12345678")

    assert response.status_code == 200
    assert response.json() == {"size": 8}


@pytest.mark.anyio
async def test_cancellation_traceback_does_not_retain_body_or_bearer() -> None:
    password = "traceback-password-secret"
    gateway_token = "traceback-gateway-token-secret"

    async def cancelled(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, send
        await receive()
        raise asyncio.CancelledError()

    app = RequestSecurityMiddleware(
        cancelled,
        allowed_hosts=("gateway.test",),
        max_body_size=1024,
    )
    request_sent = False

    async def receive() -> Message:
        nonlocal request_sent
        if request_sent:
            return {"type": "http.disconnect"}
        request_sent = True
        return {
            "type": "http.request",
            "body": password.encode(),
            "more_body": False,
        }

    async def send(message: Message) -> None:
        del message

    with pytest.raises(asyncio.CancelledError) as caught:
        await app(
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
                    (b"authorization", f"Bearer {gateway_token}".encode()),
                    (b"content-length", str(len(password)).encode()),
                ],
                "client": ("127.0.0.1", 1),
                "server": ("gateway.test", 80),
            },
            receive,
            send,
        )

    traceback_text = ""
    traceback = caught.value.__traceback__
    while traceback is not None:
        if "/packages/acc-runtime/" in traceback.tb_frame.f_code.co_filename:
            traceback_text += repr(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert password not in traceback_text
    assert gateway_token not in traceback_text
