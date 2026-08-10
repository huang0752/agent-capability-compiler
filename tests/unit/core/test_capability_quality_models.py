from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from acc_core.quality import (
    CapabilityInputQuality,
    CapabilityIntent,
    CapabilityQuality,
    CompositionQuality,
    LongTextDisclosure,
    OutputBudget,
)


def _quality_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "capability_id": "get_customer",
        "intent": {
            "action": "get",
            "resource_types": ["customer"],
        },
        "inputs": {
            "customer_id": {
                "kind": "resource_selector",
                "resource_type": "customer",
                "acquisition": "capability_output",
                "producers": ["search_customers"],
            }
        },
        "composition": {
            "failure_mode": "fail_fast",
            "justification": "Fetch one customer selected from a search result.",
        },
        "output_budget": {
            "max_bytes": 65_536,
            "long_text_disclosures": [
                {
                    "path": "/properties/notes",
                    "acknowledged": True,
                    "reason": "Customer notes are explicitly required by this capability.",
                }
            ],
        },
    }


def test_capability_quality_accepts_a_constructible_selector_contract() -> None:
    quality = CapabilityQuality.model_validate(_quality_document())

    selector = quality.inputs["customer_id"]
    assert selector.kind == "resource_selector"
    assert selector.resource_type == "customer"
    assert selector.producers == ["search_customers"]
    assert quality.output_budget.max_bytes == 65_536


@pytest.mark.parametrize("action", ["create", "update", "delete", "transition", "execute"])
def test_capability_quality_supports_action_capability_intents(action: str) -> None:
    document = _quality_document()
    intent = deepcopy(document["intent"])
    assert isinstance(intent, dict)
    intent["action"] = action
    document["intent"] = intent

    quality = CapabilityQuality.model_validate(document)

    assert quality.intent.action == action


@pytest.mark.parametrize(
    ("acquisition", "producers"),
    [
        ("caller", []),
        ("default", []),
        ("upstream_step", []),
        ("capability_output", ["search_customers"]),
    ],
)
def test_capability_input_accepts_supported_acquisition_modes(
    acquisition: str,
    producers: list[str],
) -> None:
    quality = CapabilityInputQuality.model_validate(
        {
            "kind": "resource_selector",
            "resource_type": "customer",
            "acquisition": acquisition,
            "producers": producers,
        }
    )

    assert quality.acquisition == acquisition


def test_resource_selector_requires_a_resource_type() -> None:
    with pytest.raises(ValidationError, match="resource_type"):
        CapabilityInputQuality.model_validate(
            {
                "kind": "resource_selector",
                "acquisition": "caller",
            }
        )


@pytest.mark.parametrize(
    ("acquisition", "producers", "message"),
    [
        ("capability_output", [], "requires at least one producer"),
        ("caller", ["search_customers"], "only allowed for capability_output"),
    ],
)
def test_producers_are_consistent_with_capability_output_acquisition(
    acquisition: str,
    producers: list[str],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        CapabilityInputQuality.model_validate(
            {
                "kind": "resource_selector",
                "resource_type": "customer",
                "acquisition": acquisition,
                "producers": producers,
            }
        )


@pytest.mark.parametrize(
    ("kind", "acquisition"),
    [
        ("trusted_context", "caller"),
        ("query", "trusted_context"),
    ],
)
def test_trusted_context_kind_and_acquisition_must_agree(kind: str, acquisition: str) -> None:
    with pytest.raises(ValidationError, match="trusted_context"):
        CapabilityInputQuality.model_validate(
            {
                "kind": kind,
                "acquisition": acquisition,
            }
        )


@pytest.mark.parametrize(
    "producers",
    [
        ["search_customers", "search_customers"],
        ["z_search", "a_search"],
    ],
)
def test_producer_ids_must_be_unique_and_sorted(producers: list[str]) -> None:
    with pytest.raises(ValidationError, match="producers"):
        CapabilityInputQuality.model_validate(
            {
                "kind": "resource_selector",
                "resource_type": "customer",
                "acquisition": "capability_output",
                "producers": producers,
            }
        )


def test_capability_quality_rejects_itself_as_a_selector_producer() -> None:
    document = _quality_document()
    inputs = deepcopy(document["inputs"])
    assert isinstance(inputs, dict)
    assert isinstance(inputs["customer_id"], dict)
    inputs["customer_id"]["producers"] = ["get_customer"]
    document["inputs"] = inputs

    with pytest.raises(ValidationError, match="cannot produce its own required input"):
        CapabilityQuality.model_validate(document)


@pytest.mark.parametrize("max_bytes", [False, 0, 100 * 1024 * 1024 + 1])
def test_output_budget_has_a_strict_bounded_byte_limit(max_bytes: object) -> None:
    with pytest.raises(ValidationError, match="max_bytes"):
        OutputBudget.model_validate(
            {
                "max_bytes": max_bytes,
                "long_text_disclosures": [],
            }
        )


def test_acknowledged_long_text_requires_a_reason() -> None:
    with pytest.raises(ValidationError, match="reason"):
        LongTextDisclosure.model_validate(
            {
                "path": "/properties/prompt",
                "acknowledged": True,
            }
        )


def test_unacknowledged_long_text_remains_representable_for_quality_diagnostics() -> None:
    disclosure = LongTextDisclosure.model_validate(
        {
            "path": "/properties/prompt",
            "acknowledged": False,
        }
    )

    assert disclosure.acknowledged is False
    assert disclosure.reason is None


def test_output_budget_rejects_duplicate_or_unsorted_disclosure_paths() -> None:
    duplicate = {
        "path": "/properties/content",
        "acknowledged": False,
    }
    for disclosures in (
        [duplicate, deepcopy(duplicate)],
        [
            {"path": "/properties/z", "acknowledged": False},
            {"path": "/properties/a", "acknowledged": False},
        ],
    ):
        with pytest.raises(ValidationError, match="long_text_disclosures"):
            OutputBudget.model_validate(
                {
                    "max_bytes": 65_536,
                    "long_text_disclosures": disclosures,
                }
            )


def test_intent_resource_types_must_be_nonempty_unique_and_sorted() -> None:
    for resource_types in ([], ["customer", "customer"], ["zeta", "alpha"]):
        with pytest.raises(ValidationError, match="resource_types"):
            CapabilityIntent.model_validate(
                {
                    "action": "get",
                    "resource_types": resource_types,
                }
            )


def test_composition_is_fail_fast_and_uses_a_nonempty_optional_justification() -> None:
    composition = CompositionQuality.model_validate({"failure_mode": "fail_fast"})
    assert composition.justification is None

    with pytest.raises(ValidationError, match="fail_fast"):
        CompositionQuality.model_validate({"failure_mode": "best_effort"})
    with pytest.raises(ValidationError, match="at least 1 character"):
        CompositionQuality.model_validate(
            {
                "failure_mode": "fail_fast",
                "justification": "",
            }
        )


def test_capability_quality_is_strict_and_requires_schema_version_two() -> None:
    extra_document = _quality_document()
    extra_document["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CapabilityQuality.model_validate(extra_document)

    old_document = _quality_document()
    old_document["schema_version"] = "1"
    with pytest.raises(ValidationError, match="Input should be '2'"):
        CapabilityQuality.model_validate(old_document)


def test_capability_quality_json_schema_generation_is_stable() -> None:
    first = CapabilityQuality.model_json_schema(mode="validation")
    second = CapabilityQuality.model_json_schema(mode="validation")

    assert first == second
    assert first["additionalProperties"] is False
    assert "CapabilityInputQuality" in first["$defs"]
    assert "OutputBudget" in first["$defs"]
