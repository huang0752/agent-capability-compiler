from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from acc_runtime.mcp import McpSchemaProjectionError, project_mcp_output_schema


def test_projection_preserves_simple_wire_schema_without_synthetic_identifier() -> None:
    projected = project_mcp_output_schema(
        "get_customer",
        {"type": "object", "properties": {"id": {"type": "string"}}},
    )

    assert projected == {
        "type": "object",
        "additionalProperties": False,
        "required": ["result"],
        "properties": {"result": {"type": "object", "properties": {"id": {"type": "string"}}}},
    }


def test_projection_keeps_recursive_defs_references_bound_to_the_result_resource() -> None:
    output_schema = {
        "type": "object",
        "$defs": {
            "node": {
                "type": "object",
                "required": ["value", "next"],
                "properties": {
                    "value": {"type": "string"},
                    "next": {"anyOf": [{"$ref": "#/$defs/node"}, {"type": "null"}]},
                },
            }
        },
        "required": ["root"],
        "properties": {"root": {"$ref": "#/$defs/node"}},
    }

    projected = project_mcp_output_schema("get_tree", output_schema)

    result_schema = projected["properties"]["result"]
    assert isinstance(result_schema, dict)
    assert result_schema["$id"].startswith("urn:acc:mcp-output:")
    Draft202012Validator(projected).validate(
        {"result": {"root": {"value": "root", "next": {"value": "leaf", "next": None}}}}
    )


@pytest.mark.parametrize(
    "keyword",
    ["allOf", "anyOf", "oneOf"],
)
def test_projection_finds_root_references_inside_composition_keywords(keyword: str) -> None:
    output_schema = {
        "$defs": {"identifier": {"type": "string", "pattern": "^id-"}},
        keyword: [{"type": "object", "properties": {"id": {"$ref": "#/$defs/identifier"}}}],
    }

    projected = project_mcp_output_schema("composed", output_schema)

    result_schema = projected["properties"]["result"]
    assert isinstance(result_schema, dict)
    assert result_schema["$id"].startswith("urn:acc:mcp-output:")
    Draft202012Validator(projected).validate({"result": {"id": "id-1"}})


def test_projection_supports_root_property_refs_and_escaped_json_pointer_tokens() -> None:
    output_schema = {
        "type": "object",
        "properties": {
            "a/b~c": {"type": "string"},
            "copy": {"$ref": "#/properties/a~1b~0c"},
        },
        "required": ["a/b~c", "copy"],
    }

    projected = project_mcp_output_schema("escaped", output_schema)

    Draft202012Validator(projected).validate({"result": {"a/b~c": "one", "copy": "two"}})


def test_projection_preserves_an_existing_absolute_root_identifier() -> None:
    output_schema = {
        "$id": "urn:example:customer-output",
        "$defs": {"identifier": {"type": "string"}},
        "$ref": "#/$defs/identifier",
    }

    projected = project_mcp_output_schema("customer", output_schema)

    result_schema = projected["properties"]["result"]
    assert isinstance(result_schema, dict)
    assert result_schema["$id"] == "urn:example:customer-output"
    Draft202012Validator(projected).validate({"result": "customer-1"})


def test_projection_does_not_rebind_references_owned_by_a_nested_resource() -> None:
    output_schema = {
        "type": "object",
        "properties": {
            "nested": {
                "$id": "urn:example:nested-output",
                "$defs": {"identifier": {"type": "string"}},
                "$ref": "#/$defs/identifier",
            }
        },
    }

    projected = project_mcp_output_schema("nested", output_schema)

    result_schema = projected["properties"]["result"]
    assert isinstance(result_schema, dict)
    assert "$id" not in result_schema
    Draft202012Validator(projected).validate({"result": {"nested": "nested-1"}})


@pytest.mark.parametrize("reference_keyword", ["$ref", "$dynamicRef"])
def test_projection_rejects_non_self_contained_references_without_echoing_schema(
    reference_keyword: str,
) -> None:
    secret = "https://schemas.example/private-customer-schema"

    with pytest.raises(McpSchemaProjectionError) as caught:
        project_mcp_output_schema("private_tool", {reference_keyword: secret})

    assert caught.value.code == "ACC_RUNTIME_MCP_SCHEMA_PROJECTION_INVALID"
    assert caught.value.details == {"reason": "external_reference_unsupported"}
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value.details)


def test_projection_is_deterministic_and_does_not_mutate_the_input() -> None:
    output_schema = {
        "$defs": {"value": {"type": "integer"}},
        "$ref": "#/$defs/value",
    }
    original = copy.deepcopy(output_schema)

    first = project_mcp_output_schema("stable", output_schema)
    second = project_mcp_output_schema("stable", output_schema)
    other = project_mcp_output_schema("other", output_schema)

    assert first == second
    assert first != other
    assert output_schema == original


def test_projection_resource_identifier_changes_when_the_schema_changes() -> None:
    first = project_mcp_output_schema(
        "stable",
        {"$defs": {"value": {"type": "integer"}}, "$ref": "#/$defs/value"},
    )
    second = project_mcp_output_schema(
        "stable",
        {"$defs": {"value": {"type": "string"}}, "$ref": "#/$defs/value"},
    )

    first_result = first["properties"]["result"]
    second_result = second["properties"]["result"]
    assert isinstance(first_result, dict)
    assert isinstance(second_result, dict)
    assert first_result["$id"] != second_result["$id"]
