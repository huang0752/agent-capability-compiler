from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import pytest
from mcp import types

from acc_runtime.mcp import listed_tools_sha256


def _tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="zeta",
            title="Presentation title",
            description="Presentation description",
            inputSchema={
                "type": "object",
                "properties": {"q": {"type": "string"}},
            },
            outputSchema={"type": "array", "items": {"type": "string"}},
        ),
        types.Tool(
            name="alpha",
            inputSchema={"type": "object", "additionalProperties": False},
            outputSchema={"type": "object"},
        ),
    ]


def test_listed_tools_sha256_preserves_the_gateway_wire_digest() -> None:
    digest = listed_tools_sha256(_tools())

    assert digest == "815f95441087cd58b5b86244e25d8664ebcded1211cd4340200271a8412a6d3e"
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_listed_tools_sha256_sorts_tools_and_ignores_presentation_metadata() -> None:
    tools = _tools()
    changed_presentation = [
        tool.model_copy(update={"title": "changed", "description": "changed"}) for tool in tools
    ]

    assert listed_tools_sha256(tools) == listed_tools_sha256(list(reversed(tools)))
    assert listed_tools_sha256(tools) == listed_tools_sha256(changed_presentation)


def test_listed_tools_sha256_changes_when_a_listed_schema_changes() -> None:
    tools = _tools()
    changed = [
        tools[0].model_copy(update={"outputSchema": {"type": "null"}}),
        tools[1],
    ]

    assert listed_tools_sha256(tools) != listed_tools_sha256(changed)


@dataclass(frozen=True)
class _MalformedTool:
    name: object
    inputSchema: object
    outputSchema: object


@pytest.mark.parametrize(
    "tool",
    [
        object(),
        _MalformedTool(name=7, inputSchema={}, outputSchema={}),
        _MalformedTool(name="tool", inputSchema="not-a-schema", outputSchema={}),
        _MalformedTool(name="tool", inputSchema={}, outputSchema=None),
        _MalformedTool(
            name="tool",
            inputSchema={"secret-schema-marker": object()},
            outputSchema={},
        ),
    ],
)
def test_listed_tools_sha256_rejects_malformed_tools_without_echoing_schema(
    tool: Any,
) -> None:
    with pytest.raises((TypeError, ValueError)) as exc_info:
        listed_tools_sha256([tool])

    assert "secret-schema-marker" not in str(exc_info.value)
