"""Canonical digests for the final MCP ``tools/list`` projection."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from mcp.types import Tool

from acc_core.quality.output_size import canonical_json_bytes


def listed_tools_sha256(tools: Sequence[Tool]) -> str:
    """Return the Gateway-compatible digest of listed MCP Tool schemas.

    Tool order and presentation-only metadata do not affect the digest. The
    result intentionally remains the bare 64-character hexadecimal wire value
    used by Runtime attestation.
    """

    schemas: list[dict[str, object]] = []
    for value in tools:
        name = getattr(value, "name", None)
        input_schema = getattr(value, "inputSchema", None)
        output_schema = getattr(value, "outputSchema", None)
        if (
            not isinstance(name, str)
            or not isinstance(input_schema, Mapping)
            or not isinstance(output_schema, Mapping)
        ):
            raise TypeError("MCP tool metadata is invalid")
        try:
            schemas.append(
                {
                    "name": name,
                    "input_schema": dict(input_schema),
                    "output_schema": dict(output_schema),
                }
            )
        except (TypeError, ValueError):
            raise TypeError("MCP tool metadata is invalid") from None

    schemas.sort(key=lambda item: str(item["name"]))
    return hashlib.sha256(canonical_json_bytes(schemas)).hexdigest()


__all__ = ["listed_tools_sha256"]
