"""Official-SDK Streamable HTTP client for isolated Gateway tests."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import GetSessionIdCallback, streamable_http_client

from acc_runtime.credentials import SecretValue


@dataclass(frozen=True, slots=True)
class _OpenFailure:
    cancelled_type: type[BaseException] | None = None


class McpStreamableHttpTestClient:
    """Connect to a protected MCP Streamable HTTP endpoint for test assertions."""

    def __init__(
        self,
        url: str,
        gateway_token: SecretValue,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not isinstance(gateway_token, SecretValue):
            raise TypeError("gateway_token must be a SecretValue")
        if http_client is not None and http_client.follow_redirects:
            raise ValueError("injected HTTP client must disable redirects")
        self.url = _validated_endpoint(url)
        self.gateway_token = gateway_token
        self.http_client = http_client
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._initialized: types.InitializeResult | None = None
        self._get_session_id: GetSessionIdCallback | None = None

    @property
    def initialized(self) -> types.InitializeResult:
        if self._initialized is None:
            raise RuntimeError("MCP Streamable HTTP client is not connected")
        return self._initialized

    @property
    def session_id(self) -> str | None:
        callback = self._get_session_id
        return callback() if callback is not None else None

    async def __aenter__(self) -> McpStreamableHttpTestClient:
        if self._stack is not None:
            raise RuntimeError("MCP Streamable HTTP client is already connected")
        failure = await self._open()
        if failure is not None and failure.cancelled_type is not None:
            raise failure.cancelled_type() from None
        if failure is not None:
            raise RuntimeError("MCP Streamable HTTP client connection failed") from None
        return self

    async def _open(self) -> _OpenFailure | None:
        stack = AsyncExitStack()
        client: httpx.AsyncClient | None = None
        raw_token: str | None = None
        try:
            client = self.http_client
            raw_token = self.gateway_token.get_secret_value()
            if client is None:
                client = await stack.enter_async_context(
                    httpx.AsyncClient(
                        headers=_gateway_headers(self.url, raw_token),
                        follow_redirects=False,
                    )
                )
            else:
                _install_gateway_headers(client, self.url, raw_token)
                stack.callback(_remove_gateway_headers, client)

            read_stream, write_stream, get_session_id = await stack.enter_async_context(
                streamable_http_client(self.url, http_client=client, terminate_on_close=True)
            )
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            initialized = await session.initialize()
        except BaseException as error:
            is_cancelled = isinstance(error, anyio.get_cancelled_exc_class())
            transport_scope_cancel = str(error).startswith("Cancelled via cancel scope")
            with anyio.CancelScope(shield=True):
                with suppress(BaseException):
                    await stack.aclose()
            cancelled_type = (
                type(error)
                if is_cancelled and _task_is_cancelling() and not transport_scope_cancel
                else None
            )
            self.http_client = None
            return _OpenFailure(cancelled_type=cancelled_type)
        finally:
            raw_token = None

        self._stack = stack
        self._session = session
        self._initialized = initialized
        self._get_session_id = get_session_id
        return None

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        stack = self._stack
        self._stack = None
        self._session = None
        self._initialized = None
        self._get_session_id = None
        if stack is not None:
            await stack.aclose()

    async def list_tools(self) -> types.ListToolsResult:
        return await self._active_session().list_tools()

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> types.CallToolResult:
        return await self._active_session().call_tool(name, dict(arguments or {}))

    def _active_session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("MCP Streamable HTTP client is not connected")
        return self._session


def _validated_endpoint(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("MCP Streamable HTTP URL must be an absolute HTTP(S) endpoint")
    return url


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _gateway_headers(url: str, raw_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw_token}", "Origin": _origin(url)}


def _install_gateway_headers(client: httpx.AsyncClient, url: str, raw_token: str) -> None:
    if "authorization" in client.headers or "origin" in client.headers:
        raise ValueError("injected HTTP client must not define Authorization or Origin headers")
    client.headers.update(_gateway_headers(url, raw_token))


def _remove_gateway_headers(client: httpx.AsyncClient) -> None:
    client.headers.pop("Authorization", None)
    client.headers.pop("Origin", None)


def _task_is_cancelling() -> bool:
    try:
        task = asyncio.current_task()
    except RuntimeError:  # pragma: no cover - non-asyncio anyio backend
        return True
    return task is None or task.cancelling() > 0


__all__ = ["McpStreamableHttpTestClient"]
