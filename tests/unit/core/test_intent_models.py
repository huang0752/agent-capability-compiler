from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from acc_core.intents import IntentPlan
from acc_core.schemas import schema_for


def _evidence(ref: str = "orders-router") -> list[dict[str, str]]:
    return [{"evidence_ref": ref, "supports": "The route serves this user goal."}]


def _blocked_read() -> dict[str, object]:
    return {
        "id": "orders.search",
        "domain_id": "orders",
        "resource": "order",
        "user_goal": "Find orders that match business filters.",
        "route_ids": ["GET /orders"],
        "interaction_ids": [],
        "candidate_ids": [],
        "capability_ids": [],
        "kind": "read",
        "effect": "read",
        "rationale": {"summary": "One bounded search goal."},
        "evidence": _evidence(),
        "confidence": "medium",
        "gaps": [
            {
                "code": "response_schema",
                "summary": "The response shape is not proven.",
                "required_evidence": "A source response schema.",
            }
        ],
        "recommendation": "blocked_on_evidence",
        "action_safety": None,
    }


def _safety() -> dict[str, object]:
    def claim(name: str) -> dict[str, object]:
        return {
            "status": "proven",
            "rationale": f"{name} is source-enforced.",
            "evidence_refs": ["orders-service"],
        }

    return {
        "authorization": claim("Authorization"),
        "idempotency": claim("Idempotency"),
        "concurrency": claim("Concurrency"),
        "approval": claim("Approval policy"),
        "outcome_resolution": claim("Outcome resolution"),
    }


def test_intent_plan_accepts_blocked_read_without_prescribing_a_tool_count() -> None:
    plan = IntentPlan.model_validate(
        {"schema_version": "2", "intents": [_blocked_read()], "relationships": []}
    )

    assert plan.intents[0].recommendation == "blocked_on_evidence"
    properties = schema_for("intent-plan")["properties"]
    assert "target_tool_count" not in properties
    assert "portfolio_projection" not in properties


def test_publishable_action_requires_closed_safety_and_capability_binding() -> None:
    action = _blocked_read()
    action.update(
        {
            "id": "orders.cancel",
            "route_ids": ["POST /orders/{id}/cancel"],
            "kind": "action",
            "effect": "transition",
            "confidence": "high",
            "gaps": [],
            "recommendation": "materialize",
            "capability_ids": ["orders.cancel"],
            "action_safety": _safety(),
        }
    )

    plan = IntentPlan.model_validate(
        {"schema_version": "2", "intents": [action], "relationships": []}
    )
    assert plan.intents[0].action_safety is not None

    unsafe = copy.deepcopy(action)
    unsafe["action_safety"]["idempotency"] = {
        "status": "missing",
        "rationale": "No source key.",
        "evidence_refs": [],
    }
    with pytest.raises(ValidationError, match="closed action_safety"):
        IntentPlan.model_validate({"schema_version": "2", "intents": [unsafe], "relationships": []})

    unsafe = copy.deepcopy(action)
    unsafe["action_safety"]["approval"] = {
        "status": "not_applicable",
        "rationale": "No approval is claimed to be necessary.",
        "evidence_refs": [],
    }
    with pytest.raises(ValidationError, match="closed action_safety"):
        IntentPlan.model_validate({"schema_version": "2", "intents": [unsafe], "relationships": []})


def test_blocked_intent_requires_gaps_and_cannot_bind_a_capability() -> None:
    intent = _blocked_read()
    intent["gaps"] = []
    with pytest.raises(ValidationError, match="at least one gap"):
        IntentPlan.model_validate({"schema_version": "2", "intents": [intent], "relationships": []})

    intent = _blocked_read()
    intent["capability_ids"] = ["orders.search"]
    with pytest.raises(ValidationError, match="cannot bind Capabilities"):
        IntentPlan.model_validate({"schema_version": "2", "intents": [intent], "relationships": []})


def test_shared_route_requires_an_explicit_relationship() -> None:
    first = _blocked_read()
    second = _blocked_read()
    second["id"] = "orders.export_preview"

    with pytest.raises(ValidationError, match="without an explicit relationship"):
        IntentPlan.model_validate(
            {"schema_version": "2", "intents": [second, first], "relationships": []}
        )

    with pytest.raises(ValidationError, match="without an explicit relationship"):
        IntentPlan.model_validate(
            {
                "schema_version": "2",
                "intents": [second, first],
                "relationships": [
                    {
                        "kind": "split",
                        "intent_ids": ["orders.export_preview", "orders.search"],
                        "route_ids": ["GET /orders"],
                        "rationale": "A split does not justify sharing one route.",
                        "evidence_refs": ["orders-router"],
                    }
                ],
            }
        )

    plan = IntentPlan.model_validate(
        {
            "schema_version": "2",
            "intents": [second, first],
            "relationships": [
                {
                    "kind": "shared_support",
                    "intent_ids": ["orders.export_preview", "orders.search"],
                    "route_ids": ["GET /orders"],
                    "rationale": "Both goals use the same filtered source read.",
                    "evidence_refs": ["orders-router"],
                }
            ],
        }
    )
    assert plan.relationships[0].kind == "shared_support"


def test_intent_plan_is_strict_and_deterministically_ordered() -> None:
    document = {"schema_version": "2", "intents": [_blocked_read()], "relationships": []}
    document["target_tool_count"] = 15
    with pytest.raises(ValidationError, match="Extra inputs"):
        IntentPlan.model_validate(document)

    first = _blocked_read()
    first["id"] = "z.intent"
    second = _blocked_read()
    second["id"] = "a.intent"
    second["route_ids"] = ["GET /other"]
    with pytest.raises(ValidationError, match="sorted order"):
        IntentPlan.model_validate(
            {"schema_version": "2", "intents": [first, second], "relationships": []}
        )
