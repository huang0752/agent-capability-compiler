from __future__ import annotations

import pytest
from pydantic import ValidationError

from acc_core.models import BranchAction


def _branch(condition: object) -> dict[str, object]:
    return {
        "condition": condition,
        "then": [{"emit": {"value": {"selected": True}}}],
        "else": [{"emit": {"value": {"selected": False}}}],
    }


def test_branch_accepts_legacy_truthiness_and_bounded_condition_ast() -> None:
    legacy = BranchAction.model_validate(_branch("$.input.enabled"))
    condition = {
        "operator": "all",
        "conditions": [
            {
                "operator": "eq",
                "left": {"kind": "reference", "value": "$.input.state"},
                "right": {"kind": "literal", "value": "open"},
            },
            {
                "operator": "not",
                "condition": {
                    "operator": "in",
                    "item": {"kind": "reference", "value": "$.input.state"},
                    "values": {"kind": "literal", "value": ["closed", "cancelled"]},
                },
            },
        ],
    }
    structured = BranchAction.model_validate(_branch(condition))

    assert legacy.condition == "$.input.enabled"
    assert structured.model_dump(mode="json", by_alias=True)["condition"] == condition


@pytest.mark.parametrize(
    "condition",
    [
        {"operator": "python", "expression": "input.state == 'open'"},
        {
            "operator": "eq",
            "left": {"kind": "dynamic", "value": "input.state"},
            "right": {"kind": "literal", "value": "open"},
        },
        {
            "operator": "eq",
            "left": {"kind": "reference", "value": "$.input.state", "eval": True},
            "right": {"kind": "literal", "value": "open"},
        },
    ],
)
def test_branch_rejects_dynamic_or_undeclared_condition_shapes(condition: object) -> None:
    with pytest.raises(ValidationError):
        BranchAction.model_validate(_branch(condition))
