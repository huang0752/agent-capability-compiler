"""JSON Schema projection for MCP structured tool results."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from acc_runtime.errors import RuntimeError as AccRuntimeError


class McpSchemaProjectionError(AccRuntimeError):
    """An ACC output schema cannot be represented safely as an MCP tool schema."""

    code = "ACC_RUNTIME_MCP_SCHEMA_PROJECTION_INVALID"
    status = 500


def project_mcp_output_schema(
    tool_name: str,
    output_schema: Mapping[str, Any],
) -> dict[str, Any]:
    """Wrap one output schema without changing the resource root of local references."""

    if not isinstance(tool_name, str) or not tool_name:
        raise McpSchemaProjectionError(
            "MCP tool name is invalid.",
            details={"reason": "tool_name_invalid"},
        )
    if not isinstance(output_schema, Mapping):
        raise McpSchemaProjectionError(
            "MCP output schema is invalid.",
            details={"reason": "schema_not_object"},
        )

    projected_result = copy.deepcopy(dict(output_schema))
    reference_state = _inspect_references(projected_result, root_resource=True)
    if reference_state.external:
        raise McpSchemaProjectionError(
            "MCP output schema uses an unsupported external reference.",
            details={"reason": "external_reference_unsupported"},
        )
    if reference_state.root_fragment and "$id" not in projected_result:
        try:
            schema_bytes = json.dumps(
                projected_result,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise McpSchemaProjectionError(
                "MCP output schema is not JSON-compatible.",
                details={"reason": "schema_not_json_compatible"},
            ) from None
        digest = hashlib.sha256(tool_name.encode("utf-8") + b"\0" + schema_bytes).hexdigest()
        projected_result["$id"] = f"urn:acc:mcp-output:{digest}"

    wrapper: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["result"],
        "properties": {"result": projected_result},
    }
    try:
        Draft202012Validator.check_schema(wrapper)
    except SchemaError:
        raise McpSchemaProjectionError(
            "MCP output schema projection is invalid.",
            details={"reason": "projected_schema_invalid"},
        ) from None
    return wrapper


class _ReferenceState:
    __slots__ = ("external", "root_fragment")

    def __init__(self) -> None:
        self.external = False
        self.root_fragment = False


def _inspect_references(value: object, *, root_resource: bool) -> _ReferenceState:
    state = _ReferenceState()

    def visit(node: object, *, belongs_to_root: bool, document_root: bool = False) -> None:
        if isinstance(node, Mapping):
            owns_resource = not document_root and "$id" in node
            current_belongs_to_root = belongs_to_root and not owns_resource
            for key, child in node.items():
                if key in {"$ref", "$dynamicRef"} and isinstance(child, str):
                    if child.startswith("#"):
                        if current_belongs_to_root:
                            state.root_fragment = True
                    else:
                        state.external = True
                else:
                    visit(child, belongs_to_root=current_belongs_to_root)
        elif isinstance(node, (list, tuple)):
            for child in node:
                visit(child, belongs_to_root=belongs_to_root)

    visit(value, belongs_to_root=root_resource, document_root=True)
    return state


__all__ = ["McpSchemaProjectionError", "project_mcp_output_schema"]
