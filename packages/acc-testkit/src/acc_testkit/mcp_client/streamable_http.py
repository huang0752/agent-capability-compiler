"""Official-SDK Streamable HTTP client for isolated Gateway tests."""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlsplit

import anyio
import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import GetSessionIdCallback, streamable_http_client

from acc_runtime.credentials import SecretValue


@dataclass(frozen=True, slots=True)
class _OpenFailure:
    cancelled_type: type[BaseException] | None = None


class _BorrowedTransport(httpx.AsyncBaseTransport):
    """Use a caller-owned pure transport without transferring close ownership."""

    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        self._transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        """The caller owns the borrowed transport."""


class McpStreamableHttpTestClient:
    """Connect with an owned clean client; an injected pure transport remains caller-owned."""

    def __init__(
        self,
        url: str,
        gateway_token: SecretValue,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not isinstance(gateway_token, SecretValue):
            raise TypeError("gateway_token must be a SecretValue")
        if http_client is not None:
            rejection = ValueError(
                "injecting AsyncClient is unsafe; pass its pure AsyncBaseTransport via transport"
            )
            del http_client
            raise rejection from None
        self.url = _validated_endpoint(url)
        self.gateway_token = gateway_token
        self.transport = transport
        self._state: Literal["idle", "opening", "active", "closing"] = "idle"
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
        if self._state != "idle":
            raise RuntimeError("MCP Streamable HTTP client is already connected")
        self._state = "opening"
        failure = await self._open()
        if failure is not None and failure.cancelled_type is not None:
            self._state = "idle"
            raise failure.cancelled_type() from None
        if failure is not None:
            self._state = "idle"
            raise RuntimeError("MCP Streamable HTTP client connection failed") from None
        self._state = "active"
        return self

    async def _open(self) -> _OpenFailure | None:
        stack = AsyncExitStack()
        try:
            client = await stack.enter_async_context(self._new_clean_client())

            read_stream, write_stream, get_session_id = await stack.enter_async_context(
                streamable_http_client(self.url, http_client=client, terminate_on_close=True)
            )
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            initialized = await session.initialize()
        except BaseException as error:
            is_cancelled = isinstance(error, anyio.get_cancelled_exc_class())
            transport_scope_cancel = str(error).startswith("Cancelled via cancel scope")
            with suppress(BaseException):
                await stack.aclose()
            cancelled_type = (
                type(error)
                if is_cancelled and _task_is_cancelling() and not transport_scope_cancel
                else None
            )
            return _OpenFailure(cancelled_type=cancelled_type)

        self._stack = stack
        self._session = session
        self._initialized = initialized
        self._get_session_id = get_session_id
        return None

    def _new_clean_client(self) -> httpx.AsyncClient:
        raw_token = self.gateway_token.get_secret_value()
        try:
            transport = _BorrowedTransport(self.transport) if self.transport is not None else None
            return httpx.AsyncClient(
                transport=transport,
                headers=_gateway_headers(self.url, raw_token),
                cookies=None,
                auth=None,
                follow_redirects=False,
            )
        finally:
            del raw_token

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self._state != "active":
            raise RuntimeError("MCP Streamable HTTP client is not connected")
        self._state = "closing"
        stack = self._stack
        self._stack = None
        self._session = None
        self._initialized = None
        self._get_session_id = None
        try:
            if stack is not None:
                await stack.aclose()
        finally:
            self._state = "idle"

    async def list_tools(self) -> types.ListToolsResult:
        return await self._active_session().list_tools()

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> types.CallToolResult:
        return await self._active_session().call_tool(name, dict(arguments or {}))

    async def list_resources(self) -> types.ListResourcesResult:
        return await self._active_session().list_resources()

    async def read_resource(self, uri: Any) -> types.ReadResourceResult:
        return await self._active_session().read_resource(uri)

    async def list_prompts(self) -> types.ListPromptsResult:
        return await self._active_session().list_prompts()

    async def get_prompt(
        self,
        name: str,
        arguments: Mapping[str, str] | None = None,
    ) -> types.GetPromptResult:
        return await self._active_session().get_prompt(name, dict(arguments or {}))

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


def _task_is_cancelling() -> bool:
    try:
        task = asyncio.current_task()
    except RuntimeError:  # pragma: no cover - non-asyncio anyio backend
        return True
    return task is None or task.cancelling() > 0


def _install_live_transport_registry() -> Callable[
    [McpStreamableHttpTestClient], tuple[int, int, int, str] | None
]:
    live: dict[
        int,
        tuple[
            weakref.ReferenceType[McpStreamableHttpTestClient],
            ClientSession,
            AsyncExitStack,
            int,
        ],
    ] = {}
    generation = 0
    original_enter = McpStreamableHttpTestClient.__aenter__
    original_exit = McpStreamableHttpTestClient.__aexit__

    async def enter(client: McpStreamableHttpTestClient) -> McpStreamableHttpTestClient:
        nonlocal generation
        result = await original_enter(client)
        session = client._session
        stack = client._stack
        assert session is not None and stack is not None
        generation += 1
        identity = id(client)

        def discard(_reference: object) -> None:
            live.pop(identity, None)

        live[identity] = (weakref.ref(client, discard), session, stack, generation)
        return result

    async def exit(
        client: McpStreamableHttpTestClient,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        live.pop(id(client), None)
        try:
            await original_exit(client, exc_type, exc_value, traceback)
        finally:
            live.pop(id(client), None)

    def inspect(client: McpStreamableHttpTestClient) -> tuple[int, int, int, str] | None:
        record = live.get(id(client))
        if (
            record is None
            or record[0]() is not client
            or client._session is not record[1]
            or client._stack is not record[2]
            or client._state != "active"
        ):
            return None
        return id(record[1]), id(record[2]), record[3], "streamable_http"

    type.__setattr__(McpStreamableHttpTestClient, "__aenter__", enter)
    type.__setattr__(McpStreamableHttpTestClient, "__aexit__", exit)
    return inspect


_inspect_live_transport = _install_live_transport_registry()
del _install_live_transport_registry


__all__ = ["McpStreamableHttpTestClient"]
