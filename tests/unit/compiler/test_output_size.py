from __future__ import annotations

import json

import pytest

from acc_core.models import JsonObject
from acc_core.quality import OutputBudget
from acc_core.quality.output_size import (
    OutputSizeEstimate,
    analyze_output_budget,
    canonical_json_bytes,
    estimate_output_size,
)


def _budget(
    max_bytes: int = 65_536,
    *,
    acknowledged: bool | None = None,
) -> OutputBudget:
    disclosures: list[dict[str, object]] = []
    if acknowledged is not None:
        disclosure: dict[str, object] = {
            "path": "/properties/prompt",
            "acknowledged": acknowledged,
        }
        if acknowledged:
            disclosure["reason"] = "The complete prompt is explicitly required."
        disclosures.append(disclosure)
    return OutputBudget.model_validate(
        {
            "max_bytes": max_bytes,
            "long_text_disclosures": disclosures,
        }
    )


def test_canonical_json_bytes_match_compact_sorted_utf8_json() -> None:
    value = {"z": "中文", "a": [True, None]}

    encoded = canonical_json_bytes(value)

    assert encoded == json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def test_canonical_json_bytes_reject_non_json_numbers() -> None:
    with pytest.raises(ValueError, match="JSON-compatible"):
        canonical_json_bytes({"value": float("nan")})


def test_canonical_json_bytes_reject_unencodable_unicode_without_leaking_content() -> None:
    with pytest.raises(ValueError, match="JSON-compatible"):
        canonical_json_bytes("\ud800")


def test_unbounded_permission_array_is_unknown_without_inventing_max_items() -> None:
    schema: JsonObject = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "permissions": {
                "type": "array",
                "items": {"type": "string", "maxLength": 64},
            }
        },
    }

    estimate = estimate_output_size(schema)

    assert estimate == OutputSizeEstimate(
        status="unknown",
        max_bytes=None,
        unknown_pointers=("/properties/permissions/maxItems",),
    )


def test_open_object_is_unknown_even_when_known_properties_are_bounded() -> None:
    estimate = estimate_output_size(
        {
            "type": "object",
            "properties": {"id": {"type": "string", "maxLength": 36}},
        }
    )

    assert estimate.status == "unknown"
    assert estimate.unknown_pointers == ("/additionalProperties",)


def test_pattern_properties_keep_an_object_unknown_despite_additional_properties_false() -> None:
    estimate = estimate_output_size(
        {
            "type": "object",
            "additionalProperties": False,
            "patternProperties": {
                "^x-": {"type": "string", "maxLength": 10},
            },
        }
    )

    assert estimate == OutputSizeEstimate(
        status="unknown",
        max_bytes=None,
        unknown_pointers=("/patternProperties",),
    )


def test_recursive_schema_returns_unknown_without_recursing_forever() -> None:
    schema: JsonObject = {
        "$defs": {
            "node": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string", "maxLength": 20},
                    "child": {"$ref": "#/$defs/node"},
                },
            }
        },
        "$ref": "#/$defs/node",
    }

    estimate = estimate_output_size(schema)

    assert estimate.status == "unknown"
    assert estimate.unknown_pointers == ("/properties/child/$ref",)


def test_local_refs_prove_a_bounded_paginated_projection() -> None:
    schema: JsonObject = {
        "$defs": {
            "projected_customer": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "maxLength": 36},
                    "name": {"type": "string", "maxLength": 80},
                },
            }
        },
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "items": {
                "type": "array",
                "maxItems": 20,
                "items": {"$ref": "#/$defs/projected_customer"},
            },
            "total": {"type": "integer", "minimum": 0, "maximum": 999_999},
        },
    }

    estimate = estimate_output_size(schema)

    assert estimate.status == "proven_bounded"
    assert estimate.max_bytes is not None


def test_local_ref_annotations_do_not_count_as_bound_evidence_or_block_it() -> None:
    estimate = estimate_output_size(
        {
            "$defs": {"identifier": {"type": "string", "maxLength": 36}},
            "$ref": "#/$defs/identifier",
            "description": "Public identifier.",
            "examples": ["short-example"],
        }
    )

    assert estimate == OutputSizeEstimate(
        status="proven_bounded",
        max_bytes=218,
        unknown_pointers=(),
    )


def test_all_of_requires_every_reachable_branch_to_be_bounded() -> None:
    estimate = estimate_output_size(
        {
            "allOf": [
                {"type": "string", "maxLength": 12},
                {"type": "string"},
            ]
        }
    )

    assert estimate == OutputSizeEstimate(
        status="unknown",
        max_bytes=None,
        unknown_pointers=("/allOf/1/maxLength",),
    )


def test_all_of_uses_the_tightest_bound_only_when_every_branch_is_bounded() -> None:
    estimate = estimate_output_size(
        {
            "allOf": [
                {"type": "string", "maxLength": 12},
                {"type": "string", "maxLength": 4},
            ]
        }
    )

    assert estimate == OutputSizeEstimate(
        status="proven_bounded",
        max_bytes=26,
        unknown_pointers=(),
    )


def test_one_of_is_unknown_when_any_reachable_branch_is_unbounded() -> None:
    estimate = estimate_output_size(
        {
            "oneOf": [
                {"type": "string", "maxLength": 12},
                {"type": "array", "items": {"const": 1}},
            ]
        }
    )

    assert estimate == OutputSizeEstimate(
        status="unknown",
        max_bytes=None,
        unknown_pointers=("/oneOf/1/maxItems",),
    )


def test_unused_unbounded_definitions_do_not_taint_a_closed_projection() -> None:
    estimate = estimate_output_size(
        {
            "$defs": {"source_record": {"type": "object", "additionalProperties": True}},
            "type": "object",
            "additionalProperties": False,
            "properties": {"id": {"type": "string", "maxLength": 36}},
        }
    )

    assert estimate.status == "proven_bounded"


def test_binary_body_is_unknown_even_when_a_string_length_is_declared() -> None:
    estimate = estimate_output_size({"type": "string", "format": "binary", "maxLength": 1024})

    assert estimate == OutputSizeEstimate(
        status="unknown",
        max_bytes=None,
        unknown_pointers=("/format",),
    )


def test_examples_and_page_size_names_do_not_invent_schema_bounds() -> None:
    estimate = estimate_output_size(
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 20},
                    "examples": [["one", "two"]],
                },
                "page_size": {"type": "integer", "examples": [20]},
            },
        }
    )

    assert estimate == OutputSizeEstimate(
        status="unknown",
        max_bytes=None,
        unknown_pointers=(
            "/properties/items/maxItems",
            "/properties/page_size/maximum",
            "/properties/page_size/minimum",
        ),
    )


def test_bounded_array_of_objects_has_a_proven_canonical_upper_bound() -> None:
    schema: JsonObject = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "codes": {
                "type": "array",
                "maxItems": 2,
                "items": {"enum": [1, 999]},
            },
            "flag": {"type": "boolean"},
        },
    }

    estimate = estimate_output_size(schema)
    largest = canonical_json_bytes({"codes": [999, 999], "flag": False})

    assert estimate == OutputSizeEstimate(
        status="proven_bounded",
        max_bytes=len(largest),
        unknown_pointers=(),
    )


def test_unicode_string_estimate_is_conservative_for_canonical_utf8() -> None:
    estimate = estimate_output_size({"type": "string", "maxLength": 2})

    assert estimate.status == "proven_bounded"
    assert estimate.max_bytes is not None
    assert estimate.max_bytes >= len(canonical_json_bytes("中文"))


def test_static_bound_over_budget_emits_a_stable_diagnostic() -> None:
    diagnostics = analyze_output_budget(
        "inspect_prompt",
        {"type": "string", "maxLength": 22_000},
        _budget(),
    )

    assert [item.code for item in diagnostics] == ["ACC_CAPABILITY_OUTPUT_BUDGET_EXCEEDED"]
    assert diagnostics[0].severity == "warning"
    assert diagnostics[0].path == "capability-quality/inspect_prompt.yaml"
    assert diagnostics[0].pointer == "/output_budget/max_bytes"


def test_unknown_bound_is_reported_without_adding_schema_limits() -> None:
    diagnostics = analyze_output_budget(
        "inspect_permissions",
        {
            "type": "array",
            "items": {"type": "string", "maxLength": 64},
        },
        _budget(),
    )

    assert [item.code for item in diagnostics] == ["ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"]
    assert diagnostics[0].severity == "warning"
    assert diagnostics[0].path == "capabilities/inspect_permissions.yaml"
    assert diagnostics[0].pointer == "/output_schema/maxItems"


def test_unacknowledged_long_text_is_an_error_independent_of_size_estimate() -> None:
    diagnostics = analyze_output_budget(
        "inspect_prompt",
        {"type": "string"},
        _budget(acknowledged=False),
    )

    assert {item.code for item in diagnostics} == {
        "ACC_CAPABILITY_LONG_TEXT_DISCLOSURE_UNACKNOWLEDGED",
        "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN",
    }
    disclosure = next(
        item
        for item in diagnostics
        if item.code == "ACC_CAPABILITY_LONG_TEXT_DISCLOSURE_UNACKNOWLEDGED"
    )
    assert disclosure.severity == "error"
    assert disclosure.path == "capability-quality/inspect_prompt.yaml"
    assert disclosure.pointer == "/output_budget/long_text_disclosures/0/acknowledged"


def test_acknowledged_long_text_does_not_hide_an_unknown_size_bound() -> None:
    diagnostics = analyze_output_budget(
        "inspect_prompt",
        {"type": "string"},
        _budget(acknowledged=True),
    )

    assert [item.code for item in diagnostics] == ["ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"]


def test_nested_schema_resource_ref_is_not_resolved_against_document_root() -> None:
    estimate = estimate_output_size(
        {
            "$defs": {"payload": {"type": "string", "maxLength": 1}},
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "value": {
                    "$id": "nested-resource",
                    "$defs": {"payload": {"type": "string"}},
                    "$ref": "#/$defs/payload",
                }
            },
        }
    )

    assert estimate.status == "unknown"
    assert estimate.max_bytes is None


def test_empty_all_of_is_not_a_static_bound() -> None:
    estimate = estimate_output_size({"allOf": []})

    assert estimate.status == "unknown"
