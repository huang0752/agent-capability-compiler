from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp.client.stdio import StdioServerParameters

from acc_testkit.mcp_client import McpStdioTestClient

ROOT = Path(__file__).resolve().parents[3]

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
