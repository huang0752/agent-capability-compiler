"""Model Context Protocol adapter for the generic ACC runtime."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Protocol, cast

from mcp import types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from pydantic import JsonValue

from acc_runtime.errors import RuntimeError as AccRuntimeError


class McpRuntime(Protocol):
    """Minimal runtime surface consumed by the protocol adapter."""

    def tools(self) -> list[dict[str, object]]: ...

    async def call(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue: ...


class CapabilityMcpServer:
    """Expose ACC capabilities as MCP tools over the official low-level SDK."""

    def __init__(self, runtime: McpRuntime) -> None:
        self.runtime = runtime

    def list_tools(self) -> list[types.Tool]:
        """Translate stable runtime tool metadata to MCP tool definitions."""

        tools: list[types.Tool] = []
        for definition in self.runtime.tools():
            name = definition.get("name")
            input_schema = definition.get("input_schema")
            output_schema = definition.get("output_schema")
            if (
                not isinstance(name, str)
                or not isinstance(input_schema, dict)
                or not isinstance(output_schema, dict)
            ):
                raise TypeError("runtime tool metadata is invalid")
            title = definition.get("title")
            description = definition.get("description")
            tools.append(
                types.Tool(
                    name=name,
                    title=title if isinstance(title, str) else None,
                    description=description if isinstance(description, str) else None,
                    inputSchema=cast(dict[str, Any], input_schema),
                    outputSchema={
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["result"],
                        "properties": {"result": cast(dict[str, Any], output_schema)},
                    },
                )
            )
        return tools

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object] | None,
    ) -> types.CallToolResult:
        """Execute one tool and return only public, JSON-safe result structures."""

        try:
            result = await self.runtime.call(
                name,
                cast(Mapping[str, JsonValue], dict(arguments or {})),
            )
            payload: dict[str, Any] = {"result": result}
            return self._result(payload, is_error=False)
        except AccRuntimeError as exc:
            return self._result({"error": exc.to_dict()}, is_error=True)
        except Exception:
            return self._result(
                {
                    "error": {
                        "code": "ACC_RUNTIME_INTERNAL",
                        "status": 500,
                        "details": {},
                    }
                },
                is_error=True,
            )

    @staticmethod
    def _result(payload: dict[str, Any], *, is_error: bool) -> types.CallToolResult:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)],
            structuredContent=payload,
            isError=is_error,
        )

    def create_server(self) -> Server[object]:
        """Create the SDK server without touching process standard streams."""

        server: Server[object] = Server("acc-runtime", version="0.1.0")

        @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_tools() -> list[types.Tool]:
            return self.list_tools()

        @server.call_tool(validate_input=True)  # type: ignore[untyped-decorator]
        async def call_tool(
            name: str,
            arguments: dict[str, object] | None,
        ) -> types.CallToolResult:
            return await self.call_tool(name, arguments)

        return server

    async def run_stdio(self) -> None:
        """Serve MCP on stdin/stdout without writing non-protocol output."""

        server = self.create_server()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(NotificationOptions(), {}),
            )


__all__ = ["CapabilityMcpServer", "McpRuntime"]
