from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from acc_core.interactions import CapabilityInteractionContract
from acc_core.interactions.expressions import ConditionExpression


def _evidence(source_id: str = "customer-page") -> dict[str, object]:
    return {
        "source_id": source_id,
        "kind": "source_file",
        "path": "frontend/customers.ts",
        "line_start": 1,
        "line_end": 40,
        "digest": "sha256:" + "b" * 64,
    }


def _binding(
    binding_id: str,
    target_pointer: str,
    *,
    source_kind: str = "user_input",
) -> dict[str, object]:
    return {
        "id": binding_id,
        "source_kind": source_kind,
        "source_pointer": target_pointer,
        "target_pointer": target_pointer,
        "cardinality": "one",
        "mapping": {"kind": "identity"},
        "evidence": _evidence(),
    }


def _contract_document() -> dict[str, Any]:
    return {
        "schema_version": "2",
        "capability_id": "get_customer",
        "interaction_ids": ["customers.select"],
        "public_input_bindings": [_binding("customer-id", "/customer_id")],
        "trusted_input_bindings": [],
        "defaults": [],
        "option_sources": [],
        "conditions": [
            {
                "id": "customer-present",
                "target": "enabled",
                "target_pointer": "/customer_id",
                "expression": {
                    "operator": "all",
                    "operands": [
                        {
                            "operator": "present",
                            "operand": {
                                "kind": "reference",
                                "pointer": "/customer_id",
                            },
                        },
                        {
                            "operator": "ne",
                            "left": {
                                "kind": "reference",
                                "pointer": "/customer_id",
                            },
                            "right": {"kind": "literal", "value": "blocked"},
                        },
                    ],
                },
                "evidence": _evidence(),
            }
        ],
        "related_data": [
            {
                "id": "selected-customer",
                "producer_kind": "capability",
                "producer_id": "search_customers",
                "output_pointer": "/items/0/id",
                "target_pointer": "/customer_id",
                "cardinality": "one",
                "identity_pointer": "/id",
                "ordering": "source",
                "freshness": "request",
                "failure_isolation": "fail_fast",
                "evidence": _evidence(),
            }
        ],
        "result_consumption": [],
        "required_scenarios": ["customer-selected"],
        "overrides": [
            {
                "id": "select-binding",
                "interaction_id": "customers.select",
                "target_pointer": "/input_bindings/customer-id",
                "justification": "Expose the selected customer as an Agent input.",
                "authority": "implementation",
                "evidence": _evidence(),
            }
        ],
        "omissions": [
            {
                "interaction_id": "customers.export",
                "justification": "Binary export is outside this capability boundary.",
                "authority": "contract",
                "evidence": _evidence(),
            }
        ],
    }


def test_interaction_contract_binds_a_producer_value_to_consumer_input() -> None:
    contract = CapabilityInteractionContract.model_validate(_contract_document())

    binding = contract.related_data[0]
    assert binding.producer_id == "search_customers"
    assert binding.output_pointer == "/items/0/id"
    assert binding.target_pointer == "/customer_id"
    assert contract.overrides[0].interaction_id == "customers.select"


def test_condition_ast_accepts_only_bounded_platform_neutral_nodes() -> None:
    condition = CapabilityInteractionContract.model_validate(_contract_document()).conditions[0]

    assert condition.expression.operator == "all"
    dumped = condition.expression.model_dump(mode="python")
    assert "window" not in repr(dumped)


def test_condition_ast_uses_one_canonical_wire_shape() -> None:
    expression = (
        CapabilityInteractionContract.model_validate(_contract_document()).conditions[0].expression
    )

    assert expression.model_dump(mode="python") == {
        "operator": "all",
        "operands": [
            {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/customer_id"},
            },
            {
                "operator": "ne",
                "left": {"kind": "reference", "pointer": "/customer_id"},
                "right": {"kind": "literal", "value": "blocked"},
            },
        ],
    }
    assert ConditionExpression is not None


@pytest.mark.parametrize(
    "expression",
    [
        {
            "operator": "all",
            "expressions": [
                {
                    "operator": "present",
                    "operand": {"kind": "reference", "pointer": "/customer_id"},
                }
            ],
        },
        {
            "operator": "not",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/customer_id"},
            },
        },
    ],
)
def test_condition_ast_rejects_noncanonical_expression_field_names(
    expression: dict[str, object],
) -> None:
    document = _contract_document()
    document["conditions"][0]["expression"] = expression

    with pytest.raises(ValidationError):
        CapabilityInteractionContract.model_validate(document)


def test_condition_ast_rejects_arbitrary_source_expression() -> None:
    document = _contract_document()
    document["conditions"] = [
        {
            "id": "unsafe",
            "target": "visible",
            "target_pointer": "/customer_id",
            "expression": "window.user.admin",
            "evidence": _evidence(),
        }
    ]

    with pytest.raises(ValidationError):
        CapabilityInteractionContract.model_validate(document)


@pytest.mark.parametrize(
    "expression",
    [
        {"operator": "script", "source": "window.user.admin"},
        {
            "operator": "eq",
            "left": {"kind": "framework", "expression": "store.user"},
            "right": {"kind": "literal", "value": True},
        },
        {
            "operator": "present",
            "operand": {"kind": "reference", "pointer": "$.input.customer_id"},
        },
    ],
)
def test_condition_ast_rejects_unknown_operators_operands_and_non_pointers(
    expression: dict[str, object],
) -> None:
    document = _contract_document()
    document["conditions"][0]["expression"] = expression

    with pytest.raises(ValidationError):
        CapabilityInteractionContract.model_validate(document)


def test_trusted_and_public_bindings_cannot_cross_the_input_boundary() -> None:
    document = _contract_document()
    document["public_input_bindings"] = [
        _binding("tenant", "/tenant_id", source_kind="trusted_context")
    ]

    with pytest.raises(ValidationError, match="public input bindings cannot use trusted_context"):
        CapabilityInteractionContract.model_validate(document)

    document = _contract_document()
    document["trusted_input_bindings"] = [_binding("tenant", "/tenant_id")]
    with pytest.raises(ValidationError, match="trusted input bindings must use trusted_context"):
        CapabilityInteractionContract.model_validate(document)


def test_contract_rejects_an_undeclared_condition_target() -> None:
    document = _contract_document()
    document["conditions"][0]["target_pointer"] = "/undeclared"

    with pytest.raises(ValidationError, match="declared capability input"):
        CapabilityInteractionContract.model_validate(document)


def test_related_data_can_target_a_semantic_view() -> None:
    document = _contract_document()
    document["related_data"][0]["target_pointer"] = "/view/customer_detail"

    contract = CapabilityInteractionContract.model_validate(document)

    assert contract.related_data[0].target_pointer == "/view/customer_detail"


def test_condition_reference_must_resolve_to_a_declared_capability_input() -> None:
    document = _contract_document()
    document["conditions"][0]["expression"]["operands"][0]["operand"]["pointer"] = "/undeclared"

    with pytest.raises(ValidationError, match="condition reference"):
        CapabilityInteractionContract.model_validate(document)


def test_adopt_override_and_omit_decisions_are_disjoint_and_evidenced() -> None:
    document = _contract_document()
    document["omissions"][0]["interaction_id"] = "customers.select"
    with pytest.raises(ValidationError, match="both adopted and omitted"):
        CapabilityInteractionContract.model_validate(document)

    document = _contract_document()
    document["overrides"][0]["interaction_id"] = "customers.missing"
    with pytest.raises(ValidationError, match="adopted interaction"):
        CapabilityInteractionContract.model_validate(document)

    for section in ("overrides", "omissions"):
        for missing in ("justification", "evidence"):
            document = _contract_document()
            document[section][0].pop(missing)
            with pytest.raises(ValidationError):
                CapabilityInteractionContract.model_validate(document)


@pytest.mark.parametrize(
    ("field", "values"),
    [
        ("interaction_ids", ["z", "a"]),
        ("required_scenarios", ["z", "a"]),
    ],
)
def test_contract_rejects_unsorted_stable_references(field: str, values: list[str]) -> None:
    document = _contract_document()
    document[field] = values

    with pytest.raises(ValidationError, match="sorted"):
        CapabilityInteractionContract.model_validate(document)


def test_contract_rejects_duplicate_input_targets() -> None:
    document = _contract_document()
    duplicate = deepcopy(document["public_input_bindings"][0])
    duplicate["id"] = "duplicate-customer-id"
    document["public_input_bindings"].append(duplicate)

    with pytest.raises(ValidationError, match="target pointers must be unique"):
        CapabilityInteractionContract.model_validate(document)


def _nested_condition_expression(max_depth: int) -> dict[str, object]:
    expression: dict[str, object] = {
        "operator": "present",
        "operand": {"kind": "reference", "pointer": "/customer_id"},
    }
    for _ in range(max_depth - 2):
        expression = {"operator": "not", "operand": expression}
    return expression


def _wide_condition_expression(present_operands: int) -> dict[str, object]:
    return {
        "operator": "all",
        "operands": [
            {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/customer_id"},
            }
            for _ in range(present_operands)
        ],
    }


def test_condition_ast_accepts_the_depth_and_node_budget_boundaries() -> None:
    depth_document = _contract_document()
    depth_document["conditions"][0]["expression"] = _nested_condition_expression(64)
    assert CapabilityInteractionContract.model_validate(depth_document)

    node_document = _contract_document()
    node_document["conditions"][0]["expression"] = _wide_condition_expression(2_047)
    assert CapabilityInteractionContract.model_validate(node_document)


def test_condition_ast_rejects_depth_above_64_without_echoing_expression() -> None:
    document = _contract_document()
    document["conditions"][0]["expression"] = _nested_condition_expression(65)

    with pytest.raises(ValidationError) as captured:
        CapabilityInteractionContract.model_validate(document)

    message = str(captured.value)
    assert "condition expression exceeds maximum depth" in message
    assert "input_value" not in message


def test_condition_ast_rejects_more_than_4096_nodes_without_echoing_literals() -> None:
    document = _contract_document()
    expression = _wide_condition_expression(2_048)
    operands = expression["operands"]
    assert isinstance(operands, list)
    operands.append(
        {
            "operator": "eq",
            "left": {"kind": "reference", "pointer": "/customer_id"},
            "right": {"kind": "literal", "value": "DO_NOT_ECHO_EXPRESSION"},
        }
    )
    document["conditions"][0]["expression"] = expression

    with pytest.raises(ValidationError) as captured:
        CapabilityInteractionContract.model_validate(document)

    message = str(captured.value)
    assert "condition expression exceeds maximum node count" in message
    assert "DO_NOT_ECHO_EXPRESSION" not in message
    assert "input_value" not in message
