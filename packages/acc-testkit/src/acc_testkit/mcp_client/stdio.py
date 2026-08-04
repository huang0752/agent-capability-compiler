"""Official-SDK MCP stdio client with reliable asynchronous cleanup."""

from __future__ import annotations

import sys
from collections.abc import Mapping
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

    def _active_session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("MCP stdio client is not connected")
        return self._session


__all__ = ["McpStdioTestClient"]
