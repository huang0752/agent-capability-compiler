from __future__ import annotations

import json
from collections.abc import Mapping

import pytest
from mcp import types
from pydantic import JsonValue

from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.mcp import CapabilityMcpServer


class FakeRuntime:
    def tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": "get_customer",
                "title": "Get customer",
                "description": "Get one customer.",
                "input_schema": {"type": "object", "additionalProperties": False},
                "output_schema": {"type": "object"},
            }
        ]

    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        assert capability_id == "get_customer"
        return {"id": "c-1", "arguments": dict(arguments)}


class Denied(AccRuntimeError):
    code = "ACC_RUNTIME_POLICY_SCOPE_DENIED"
    status = 403


class DeniedRuntime(FakeRuntime):
    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        raise Denied("private diagnostic", details={"missing_scopes": ["customer.read"]})


def test_mcp_lists_capabilities_as_tools_with_wrapped_output_schema() -> None:
    adapter = CapabilityMcpServer(FakeRuntime())

    tools = adapter.list_tools()

    assert len(tools) == 1
    assert isinstance(tools[0], types.Tool)
    assert tools[0].name == "get_customer"
    assert tools[0].inputSchema == {"type": "object", "additionalProperties": False}
    assert tools[0].outputSchema == {
        "type": "object",
        "additionalProperties": False,
        "required": ["result"],
        "properties": {"result": {"type": "object"}},
    }


@pytest.mark.asyncio
async def test_mcp_call_returns_protocol_content_and_structured_result() -> None:
    result = await CapabilityMcpServer(FakeRuntime()).call_tool(
        "get_customer", {"customer_id": "c-1"}
    )

    assert result.isError is False
    assert result.structuredContent == {
        "result": {"id": "c-1", "arguments": {"customer_id": "c-1"}}
    }
    assert len(result.content) == 1
    assert isinstance(result.content[0], types.TextContent)
    assert json.loads(result.content[0].text) == result.structuredContent


@pytest.mark.asyncio
async def test_mcp_call_returns_only_safe_structured_runtime_errors() -> None:
    result = await CapabilityMcpServer(DeniedRuntime()).call_tool("get_customer", {})

    assert result.isError is True
    assert result.structuredContent == {
        "error": {
            "code": "ACC_RUNTIME_POLICY_SCOPE_DENIED",
            "status": 403,
            "details": {"missing_scopes": ["customer.read"]},
        }
    }
    text = result.content[0]
    assert isinstance(text, types.TextContent)
    assert "private diagnostic" not in text.text
