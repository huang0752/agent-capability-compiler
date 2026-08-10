from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from acc_core.interactions import UIInteractionInventory


def _evidence(source_id: str = "customer-page") -> dict[str, object]:
    return {
        "source_id": source_id,
        "kind": "source_file",
        "path": "frontend/customers.ts",
        "line_start": 1,
        "line_end": 40,
        "digest": "sha256:" + "a" * 64,
    }


def _complete_inventory_document() -> dict[str, Any]:
    return {
        "schema_version": "2",
        "scope": {"mode": "complete", "evidence_sources": ["frontend-tree"]},
        "surfaces": [
            {
                "id": "customers",
                "kind": "page",
                "route_or_entry": "/customers",
                "business_purpose": "Manage customers",
                "evidence_sources": ["customer-page"],
            }
        ],
        "interactions": [
            {
                "id": "customers.initial-load",
                "surface_id": "customers",
                "business_intent": "Load visible customers",
                "trigger": {"kind": "screen_load"},
                "route_ids": ["GET /api/customers"],
                "call_order": "sequential",
                "input_bindings": [],
                "defaults": [],
                "option_sources": [],
                "conditions": [],
                "related_data": [],
                "result_consumption": [],
                "states": [],
                "evidence_claims": [],
                "unknowns": [],
            }
        ],
        "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
    }


def test_complete_inventory_has_a_surface_interaction_denominator() -> None:
    inventory = UIInteractionInventory.model_validate(_complete_inventory_document())

    assert inventory.scope.mode == "complete"
    assert inventory.interactions[0].trigger.kind == "screen_load"


def test_inventory_accepts_platform_neutral_nested_interaction_facts() -> None:
    document = _complete_inventory_document()
    interaction = document["interactions"][0]
    interaction.update(
        {
            "trigger": {"kind": "change", "source_pointer": "/country_id"},
            "input_bindings": [
                {
                    "id": "selected-customer",
                    "source_kind": "selected_record",
                    "source_id": "customer-table",
                    "source_pointer": "/id",
                    "target_pointer": "/customer_id",
                    "cardinality": "one",
                    "mapping": {"kind": "identity"},
                    "evidence": _evidence(),
                }
            ],
            "defaults": [
                {
                    "id": "active-only",
                    "target_pointer": "/active",
                    "source_kind": "literal",
                    "value": True,
                    "authority": "implementation",
                    "precedence": "caller_over_default",
                    "submission": "send",
                    "override_policy": "caller_allowed",
                    "evidence": _evidence(),
                }
            ],
            "option_sources": [
                {
                    "id": "country-options",
                    "target_pointer": "/country_id",
                    "source_kind": "operation",
                    "producer_id": "crm.list_countries",
                    "request_bindings": [],
                    "items_pointer": "/items",
                    "value_pointer": "/id",
                    "label_pointer": "/name",
                    "cascade_dependencies": [],
                    "search": {"mode": "server", "query_pointer": "/keyword"},
                    "pagination": {"mode": "none"},
                    "cache": {"mode": "none"},
                    "freshness": "request",
                    "empty_behavior": "empty_options",
                    "error_behavior": "fail_closed",
                    "evidence": _evidence(),
                }
            ],
            "conditions": [
                {
                    "id": "country-visible",
                    "target": "visible",
                    "target_pointer": "/country_id",
                    "expression": {
                        "operator": "present",
                        "operand": {"kind": "reference", "pointer": "/country_id"},
                    },
                    "evidence": _evidence(),
                }
            ],
            "related_data": [
                {
                    "id": "customer-detail",
                    "producer_kind": "capability",
                    "producer_id": "get_customer",
                    "output_pointer": "/customer",
                    "target_pointer": "/detail",
                    "cardinality": "optional",
                    "identity_pointer": "/id",
                    "ordering": "source",
                    "freshness": "request",
                    "failure_isolation": "fail_fast",
                    "evidence": _evidence(),
                }
            ],
            "result_consumption": [
                {
                    "id": "customer-table",
                    "role": "table",
                    "source_pointer": "/items",
                    "field_pointers": ["/id", "/name"],
                    "ordering": "source",
                    "formatting_class": "identifier_and_text",
                    "pagination": "server",
                    "state_ids": ["ready"],
                    "evidence": _evidence(),
                }
            ],
            "states": [
                {
                    "id": "ready",
                    "kind": "ready",
                    "entry_condition_id": "country-visible",
                    "allowed_next_events": ["refresh"],
                    "evidence": _evidence(),
                }
            ],
            "evidence_claims": [
                {
                    "target_pointer": "/interactions/0/defaults/0",
                    "evidence": _evidence(),
                    "evidence_pointer": "/defaults/active",
                    "authority": "implementation",
                }
            ],
        }
    )

    inventory = UIInteractionInventory.model_validate(document)

    assert inventory.interactions[0].defaults[0].value is True
    assert inventory.interactions[0].related_data[0].producer_id == "get_customer"
    with pytest.raises(ValidationError, match="Instance is frozen"):
        inventory.scope.mode = "none"


def test_complete_inventory_rejects_divergent_summary() -> None:
    document = _complete_inventory_document()
    document["summary"]["interactions"] = 2

    with pytest.raises(ValidationError, match="summary must exactly match"):
        UIInteractionInventory.model_validate(document)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document["surfaces"].append(deepcopy(document["surfaces"][0])),
        lambda document: document["interactions"].append(deepcopy(document["interactions"][0])),
        lambda document: document["interactions"][0]["route_ids"].extend(["POST /z", "GET /a"]),
    ],
)
def test_inventory_rejects_duplicate_or_unsorted_stable_identifiers(mutate: Any) -> None:
    document = _complete_inventory_document()
    mutate(document)

    with pytest.raises(ValidationError, match=r"unique|sorted"):
        UIInteractionInventory.model_validate(document)


def test_inventory_rejects_an_unknown_surface_reference() -> None:
    document = _complete_inventory_document()
    document["interactions"][0]["surface_id"] = "missing"

    with pytest.raises(ValidationError, match="existing surface"):
        UIInteractionInventory.model_validate(document)


@pytest.mark.parametrize("missing", ["rationale", "evidence_sources"])
def test_none_scope_requires_empty_denominators_and_evidence_backed_rationale(
    missing: str,
) -> None:
    document = _complete_inventory_document()
    document["scope"] = {
        "mode": "none",
        "evidence_sources": ["frontend-tree"],
        "rationale": "No applicable interactive client exists.",
    }
    document["surfaces"] = []
    document["interactions"] = []
    document["summary"] = {"surfaces": 0, "interactions": 0, "unresolved": 0}
    document["scope"].pop(missing)

    with pytest.raises(ValidationError, match=r"evidence|rationale"):
        UIInteractionInventory.model_validate(document)


def test_none_scope_rejects_a_surface_or_interaction_denominator() -> None:
    document = _complete_inventory_document()
    document["scope"] = {
        "mode": "none",
        "evidence_sources": ["frontend-tree"],
        "rationale": "No applicable interactive client exists.",
    }

    with pytest.raises(ValidationError, match="empty surfaces and interactions"):
        UIInteractionInventory.model_validate(document)


def test_unresolved_summary_counts_declared_unknowns() -> None:
    document = _complete_inventory_document()
    document["interactions"][0]["unknowns"] = ["dynamic client expression"]

    with pytest.raises(ValidationError, match="summary must exactly match"):
        UIInteractionInventory.model_validate(document)

    document["summary"]["unresolved"] = 1
    inventory = UIInteractionInventory.model_validate(document)
    assert inventory.summary.unresolved == 1


def test_nested_models_forbid_unknown_fields() -> None:
    document = _complete_inventory_document()
    document["interactions"][0]["trigger"]["framework_hook"] = "mounted"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        UIInteractionInventory.model_validate(document)


def _nested_condition_expression(max_depth: int) -> dict[str, object]:
    expression: dict[str, object] = {
        "operator": "present",
        "operand": {"kind": "literal", "value": "INVENTORY_SECRET"},
    }
    for _ in range(max_depth - 2):
        expression = {"operator": "not", "operand": expression}
    return expression


def test_inventory_rejects_condition_depth_without_echoing_literals() -> None:
    document = _complete_inventory_document()
    document["interactions"][0]["conditions"] = [
        {
            "id": "too-deep",
            "target": "visible",
            "target_pointer": "/customer_id",
            "expression": _nested_condition_expression(65),
            "evidence": _evidence(),
        }
    ]

    with pytest.raises(ValidationError) as captured:
        UIInteractionInventory.model_validate(document)

    message = str(captured.value)
    assert "condition expression exceeds maximum depth" in message
    assert "INVENTORY_SECRET" not in message
    assert "input_value" not in message


def test_inventory_rejects_condition_node_budget_without_echoing_input() -> None:
    document = _complete_inventory_document()
    document["interactions"][0]["conditions"] = [
        {
            "id": "too-wide",
            "target": "enabled",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "all",
                "operands": [
                    {
                        "operator": "present",
                        "operand": {"kind": "reference", "pointer": "/customer_id"},
                    }
                    for _ in range(2_048)
                ],
            },
            "evidence": _evidence(),
        }
    ]

    with pytest.raises(ValidationError) as captured:
        UIInteractionInventory.model_validate(document)

    message = str(captured.value)
    assert "condition expression exceeds maximum node count" in message
    assert "input_value" not in message
