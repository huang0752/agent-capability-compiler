from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import cast

import pytest

from acc_core.contracts import SourceContract
from acc_core.contracts.fidelity import analyze_operation_schema_fidelity
from acc_core.contracts.schema_relation import (
    RelationReport,
    SchemaRelation,
    compare_operation_input,
    compare_operation_output,
)
from acc_core.models import JsonObject, ReadOperationV2


def _evidence() -> dict[str, object]:
    return {
        "source_id": "crm-openapi",
        "kind": "openapi",
        "path": "openapi.json",
        "json_pointer": "/paths/~1permissions/get",
        "digest": f"sha256:{'a' * 64}",
    }


def _operation(output_schema: JsonObject) -> ReadOperationV2:
    return ReadOperationV2.model_validate(
        {
            "schema_version": "2",
            "kind": "read",
            "id": "crm.get_permissions",
            "title": "Get permissions",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "keyword": {"type": "string", "maxLength": 20},
                },
            },
            "output_schema": output_schema,
            "http": {
                "method": "GET",
                "path": "/permissions",
                "path_parameters": {},
                "query_parameters": {"keyword": "keyword"},
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": ["crm.permissions.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 65_536,
                "safety": {
                    "effect": "read",
                    "risk": "low",
                    "reversibility": "reversible",
                    "retry": {"mode": "never"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "context_bindings": {},
            "evidence": [_evidence()],
        }
    )


def _contract(
    response_schema: JsonObject,
    *,
    request_schema: JsonObject | None = None,
    provenance: list[dict[str, object]] | None = None,
) -> SourceContract:
    all_provenance = [
        {
            "target_pointer": "/request_schema/properties/keyword/maxLength",
            "evidence": _evidence(),
            "evidence_schema_pointer": (
                "/components/schemas/PermissionQuery/properties/keyword/maxLength"
            ),
            "authority": "contract",
        },
        *(provenance or []),
    ]
    return SourceContract.model_validate(
        {
            "schema_version": "2",
            "id": "crm.get_permissions.contract",
            "operation_id": "crm.get_permissions",
            "request_schema": request_schema
            or {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "keyword": {"type": "string", "maxLength": 20},
                },
            },
            "response_schema": response_schema,
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": all_provenance,
        }
    )


def _permissions_schema(max_items: int | None = None) -> JsonObject:
    permissions: JsonObject = {
        "type": "array",
        "items": {"type": "string"},
    }
    if max_items is not None:
        permissions["maxItems"] = max_items
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["permissions"],
        "properties": {"permissions": permissions},
    }


def test_output_comparison_rejects_an_unevidenced_array_upper_bound() -> None:
    report = compare_operation_output(_permissions_schema(), _permissions_schema(100))

    assert report.relation is SchemaRelation.CONFLICT
    assert [finding.pointer for finding in report.findings] == ["/properties/permissions/maxItems"]


def test_output_comparison_allows_a_declared_schema_wider_than_the_source() -> None:
    report = compare_operation_output(_permissions_schema(100), _permissions_schema(200))

    assert report.relation is SchemaRelation.PROVEN
    assert report.findings == ()


@pytest.mark.parametrize(
    ("declared_max_length", "expected"),
    [
        (5, SchemaRelation.PROVEN),
        (20, SchemaRelation.PROVEN),
        (25, SchemaRelation.CONFLICT),
    ],
)
def test_input_comparison_uses_declared_subset_of_source_direction(
    declared_max_length: int,
    expected: SchemaRelation,
) -> None:
    source: JsonObject = {"type": "string", "maxLength": 20}
    declared: JsonObject = {"type": "string", "maxLength": declared_max_length}

    assert compare_operation_input(declared, source).relation is expected


def test_numeric_inclusive_and_exclusive_bounds_compare_across_keywords() -> None:
    assert (
        compare_operation_output(
            {"type": "number", "exclusiveMaximum": 10},
            {"type": "number", "maximum": 10},
        ).relation
        is SchemaRelation.PROVEN
    )


@pytest.mark.parametrize(
    "compare",
    [compare_operation_input, compare_operation_output],
)
def test_integer_is_a_proven_subset_of_number_in_both_directions(
    compare: Callable[[JsonObject, JsonObject], RelationReport],
) -> None:
    report = compare({"type": "integer"}, {"type": "number"})

    assert report.relation is SchemaRelation.PROVEN
    assert report.findings == ()


@pytest.mark.parametrize(
    "compare",
    [compare_operation_input, compare_operation_output],
)
def test_integer_subset_of_number_is_preserved_inside_a_union(
    compare: Callable[[JsonObject, JsonObject], RelationReport],
) -> None:
    report = compare(
        {"anyOf": [{"type": "integer"}, {"type": "string"}]},
        {"type": ["number", "string"]},
    )

    assert report.relation is SchemaRelation.PROVEN
    assert report.findings == ()
    assert (
        compare_operation_output(
            {"type": "number", "maximum": 10},
            {"type": "number", "exclusiveMaximum": 10},
        ).relation
        is SchemaRelation.CONFLICT
    )
    assert (
        compare_operation_input(
            {"type": "number", "exclusiveMinimum": 0},
            {"type": "number", "minimum": 0},
        ).relation
        is SchemaRelation.PROVEN
    )


def test_comparison_handles_required_properties_and_closed_objects() -> None:
    source: JsonObject = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id"],
        "properties": {"id": {"type": "string"}},
    }
    declared: JsonObject = deepcopy(source)
    assert compare_operation_output(source, declared).relation is SchemaRelation.PROVEN

    declared["required"] = ["id", "name"]
    declared["properties"] = {
        "id": {"type": "string"},
        "name": {"type": "string"},
    }
    assert compare_operation_output(source, declared).relation is SchemaRelation.CONFLICT


def test_comparison_returns_unknown_for_an_undecidable_not_constraint() -> None:
    report = compare_operation_output(
        {"type": "string"},
        {"type": "string", "not": {"const": "private"}},
    )

    assert report.relation is SchemaRelation.UNKNOWN
    assert report.findings[0].pointer == "/not"


def test_recursive_local_refs_terminate_and_preserve_directionality() -> None:
    source: JsonObject = {
        "$defs": {
            "node": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "children": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/node"},
                    },
                },
            }
        },
        "$ref": "#/$defs/node",
    }
    assert compare_operation_output(source, deepcopy(source)).relation is SchemaRelation.PROVEN

    declared: JsonObject = deepcopy(source)
    definitions = cast(JsonObject, declared["$defs"])
    node = cast(JsonObject, definitions["node"])
    properties = cast(JsonObject, node["properties"])
    children = cast(JsonObject, properties["children"])
    children["maxItems"] = 10
    report = compare_operation_output(source, declared)
    assert report.relation is SchemaRelation.CONFLICT
    assert report.findings[0].pointer.endswith("/properties/children/maxItems")


def test_fidelity_reports_narrow_output_and_missing_constraint_provenance() -> None:
    operation = _operation(_permissions_schema(100))
    contract = _contract(_permissions_schema())

    diagnostics = analyze_operation_schema_fidelity(operation, contract)

    assert {item.code for item in diagnostics} >= {
        "ACC_SCHEMA_OUTPUT_NARROWER_THAN_EVIDENCE",
        "ACC_SCHEMA_CONSTRAINT_PROVENANCE_MISSING",
    }
    assert all(item.path == "operations/crm.get_permissions.yaml" for item in diagnostics)
    assert {item.pointer for item in diagnostics} >= {
        "/output_schema/properties/permissions/maxItems"
    }


def test_observation_cannot_prove_an_output_upper_bound() -> None:
    source = _permissions_schema(100)
    contract = _contract(
        source,
        provenance=[
            {
                "target_pointer": "/response_schema/properties/permissions/maxItems",
                "evidence": _evidence(),
                "evidence_schema_pointer": (
                    "/components/schemas/PermissionList/properties/permissions/maxItems"
                ),
                "authority": "observation",
            }
        ],
    )

    diagnostics = analyze_operation_schema_fidelity(_operation(source), contract)

    assert [item.code for item in diagnostics] == ["ACC_SCHEMA_OBSERVATION_USED_AS_BOUND"]
    assert diagnostics[0].pointer == "/output_schema/properties/permissions/maxItems"


def test_contract_provenance_can_prove_an_output_upper_bound() -> None:
    source = _permissions_schema(100)
    contract = _contract(
        source,
        provenance=[
            {
                "target_pointer": "/response_schema/properties/permissions/maxItems",
                "evidence": _evidence(),
                "evidence_schema_pointer": (
                    "/components/schemas/PermissionList/properties/permissions/maxItems"
                ),
                "authority": "contract",
            }
        ],
    )

    assert analyze_operation_schema_fidelity(_operation(source), contract) == ()


def test_fidelity_preserves_unknown_comparison_as_a_warning() -> None:
    operation = _operation({"type": "string", "not": {"const": "private"}})
    contract = _contract({"type": "string"})

    diagnostics = analyze_operation_schema_fidelity(operation, contract)

    unknown = next(
        item for item in diagnostics if item.code == "ACC_SCHEMA_EVIDENCE_COMPARISON_UNKNOWN"
    )
    assert unknown.severity == "warning"
    assert unknown.pointer == "/output_schema/not"
