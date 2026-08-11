"""Official-SDK MCP stdio client with reliable asynchronous cleanup."""

from __future__ import annotations

import sys
import weakref
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack
from types import TracebackType
from typing import Any, TextIO

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client


class McpStdioTestClient:
    """Connect to an MCP subprocess for tools/list and tools/call assertions."""

    def __init__(
        self,
        parameters: StdioServerParameters,
        *,
        error_log: TextIO | None = None,
    ) -> None:
        self.parameters = parameters
        self.error_log = error_log or sys.stderr
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._initialized: types.InitializeResult | None = None

    @property
    def initialized(self) -> types.InitializeResult:
        if self._initialized is None:
            raise RuntimeError("MCP stdio client is not connected")
        return self._initialized

    async def __aenter__(self) -> McpStdioTestClient:
        if self._stack is not None:
            raise RuntimeError("MCP stdio client is already connected")
        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(
                stdio_client(self.parameters, errlog=self.error_log)
            )
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            initialized = await session.initialize()
        except BaseException:
            await stack.aclose()
            raise
        self._stack = stack
        self._session = session
        self._initialized = initialized
        return self

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
            raise RuntimeError("MCP stdio client is not connected")
        return self._session


def _install_live_transport_registry() -> Callable[
    [McpStdioTestClient], tuple[int, int, int, str] | None
]:
    live: dict[
        int,
        tuple[
            weakref.ReferenceType[McpStdioTestClient],
            ClientSession,
            AsyncExitStack,
            int,
        ],
    ] = {}
    generation = 0
    original_enter = McpStdioTestClient.__aenter__
    original_exit = McpStdioTestClient.__aexit__

    async def enter(client: McpStdioTestClient) -> McpStdioTestClient:
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
        client: McpStdioTestClient,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        live.pop(id(client), None)
        try:
            await original_exit(client, exc_type, exc_value, traceback)
        finally:
            live.pop(id(client), None)

    def inspect(client: McpStdioTestClient) -> tuple[int, int, int, str] | None:
        record = live.get(id(client))
        if (
            record is None
            or record[0]() is not client
            or client._session is not record[1]
            or client._stack is not record[2]
        ):
            return None
        return id(record[1]), id(record[2]), record[3], "stdio"

    type.__setattr__(McpStdioTestClient, "__aenter__", enter)
    type.__setattr__(McpStdioTestClient, "__aexit__", exit)
    return inspect


_inspect_live_transport = _install_live_transport_registry()
del _install_live_transport_registry


__all__ = ["McpStdioTestClient"]
