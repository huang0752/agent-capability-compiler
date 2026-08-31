from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import TypeAdapter

from acc_core.domains import CapabilityCandidateLedger, DomainMap
from acc_core.intents import IntentPlan
from acc_core.models import Capability, ReadCapabilityV2
from acc_core.quality import (
    CapabilityQuality,
    audit_intent_plan,
    capability_operation_dependencies,
)
from acc_core.scope import ScopeInventory

_FIXTURE = Path("tests/fixtures/domains/content")


def _load(name: str) -> object:
    return yaml.safe_load((_FIXTURE / name).read_text(encoding="utf-8"))


def _plan(*, route_ids: list[str] | None = None) -> IntentPlan:
    proven = {
        "status": "proven",
        "rationale": "The source contract proves this safety boundary.",
        "evidence_refs": ["content-source-contract"],
    }
    return IntentPlan.model_validate(
        {
            "schema_version": "2",
            "intents": [
                {
                    "id": "content.transition",
                    "domain_id": "content_publication",
                    "resource": "content",
                    "user_goal": "Transition content to a permitted publication state.",
                    "route_ids": route_ids
                    or [
                        "GET /content/{entity_id}",
                        "PATCH /content/{entity_id}/transition",
                    ],
                    "interaction_ids": [],
                    "candidate_ids": ["content.transition"],
                    "capability_ids": ["content.transition"],
                    "kind": "action",
                    "effect": "transition",
                    "rationale": {
                        "summary": "One bounded user goal owns preview and mutation.",
                        "compose": "The read establishes state for the guarded transition.",
                    },
                    "evidence": [
                        {
                            "evidence_ref": "content-source-contract",
                            "supports": "Route dependency and Action lifecycle.",
                        }
                    ],
                    "confidence": "high",
                    "gaps": [],
                    "recommendation": "compose",
                    "action_safety": {
                        "authorization": proven,
                        "idempotency": proven,
                        "concurrency": proven,
                        "approval": proven,
                        "outcome_resolution": proven,
                    },
                }
            ],
            "relationships": [],
        }
    )


def _inputs() -> tuple[
    ScopeInventory,
    CapabilityCandidateLedger,
    DomainMap,
    dict[str, Capability],
    dict[str, CapabilityQuality],
]:
    capability: Capability = TypeAdapter(Capability).validate_python(
        _load("capabilities/content.transition.yaml")
    )
    quality = CapabilityQuality.model_validate(_load("capability-quality/content.transition.yaml"))
    return (
        ScopeInventory.model_validate(_load("scope-inventory.yaml")),
        CapabilityCandidateLedger.model_validate(_load("capability-candidates.yaml")),
        DomainMap.model_validate(_load("domain-map.yaml")),
        {capability.id: capability},
        {quality.capability_id: quality},
    )


def test_audit_accepts_evidence_closed_plan_without_a_tool_count_target() -> None:
    scope, ledger, domain_map, capabilities, qualities = _inputs()
    dependencies = capability_operation_dependencies(capabilities)

    result = audit_intent_plan(
        scope_inventory=scope,
        candidate_ledger=ledger,
        domain_map=domain_map,
        capabilities=capabilities,
        qualities=qualities,
        operation_dependencies=dependencies,
        intent_plan=_plan(),
    )

    assert result.accepted
    assert result.route_accounting.discovered == 2
    assert result.route_accounting.unassigned == ()
    assert result.route_accounting.materializable == (
        "GET /content/{entity_id}",
        "PATCH /content/{entity_id}/transition",
    )
    assert result.tool_portfolio.projected_mcp_tool_count == 4
    assert dependencies == {"content.transition": ("content.status", "content.transition")}


def test_audit_fails_closed_when_any_discovered_route_is_unassigned() -> None:
    scope, ledger, domain_map, capabilities, qualities = _inputs()

    result = audit_intent_plan(
        scope_inventory=scope,
        candidate_ledger=ledger,
        domain_map=domain_map,
        capabilities=capabilities,
        qualities=qualities,
        operation_dependencies=capability_operation_dependencies(capabilities),
        intent_plan=_plan(route_ids=["GET /content/{entity_id}"]),
    )

    assert not result.accepted
    assert result.route_accounting.unassigned == ("PATCH /content/{entity_id}/transition",)
    assert "ACC_INTENT_PLAN_DENOMINATOR_UNASSIGNED" in {item.code for item in result.diagnostics}


def test_merge_requires_every_conflicting_permission_evidence_ref() -> None:
    scope, _ledger, domain_map, capabilities, qualities = _inputs()
    ledger_document = cast(dict[str, Any], copy.deepcopy(_load("capability-candidates.yaml")))
    alternate = copy.deepcopy(ledger_document["candidates"][0])
    alternate["id"] = "content.transition.secondary"
    alternate["claims"]["authorization_boundary"]["evidence_refs"] = [
        "alternate-authorization-boundary"
    ]
    ledger_document["candidates"].append(alternate)
    merged_ledger = CapabilityCandidateLedger.model_validate(ledger_document)
    plan_document = _plan().model_dump(mode="json")
    plan_document["intents"][0]["candidate_ids"] = [
        "content.transition",
        "content.transition.secondary",
    ]

    rejected = audit_intent_plan(
        scope_inventory=scope,
        candidate_ledger=merged_ledger,
        domain_map=domain_map,
        capabilities=capabilities,
        qualities=qualities,
        operation_dependencies=capability_operation_dependencies(capabilities),
        intent_plan=IntentPlan.model_validate(plan_document),
    )

    assert "ACC_INTENT_PLAN_PERMISSION_INCOMPATIBLE" in {item.code for item in rejected.diagnostics}

    plan_document["intents"][0]["evidence"].extend(
        [
            {
                "evidence_ref": "alternate-authorization-boundary",
                "supports": "The secondary route uses the same effective permission boundary.",
            },
            {
                "evidence_ref": "content-authorization-boundary",
                "supports": "The primary route permission is compared explicitly.",
            },
        ]
    )
    accepted = audit_intent_plan(
        scope_inventory=scope,
        candidate_ledger=merged_ledger,
        domain_map=domain_map,
        capabilities=capabilities,
        qualities=qualities,
        operation_dependencies=capability_operation_dependencies(capabilities),
        intent_plan=IntentPlan.model_validate(plan_document),
    )

    assert "ACC_INTENT_PLAN_PERMISSION_INCOMPATIBLE" not in {
        item.code for item in accepted.diagnostics
    }


def test_dependency_helper_walks_nested_branch_parallel_and_foreach() -> None:
    capability = ReadCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "read",
            "id": "nested",
            "title": "Nested",
            "description": "Exercise recursive dependency extraction.",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "workflow": [
                {
                    "branch": {
                        "condition": "$.input.enabled == true",
                        "then": [{"call": {"operation": "one", "arguments": {}}}],
                        "else": [
                            {
                                "parallel": [
                                    {"call": {"operation": "two", "arguments": {}}},
                                    {
                                        "foreach": {
                                            "items": [],
                                            "item_name": "item",
                                            "max_items": 1,
                                            "workflow": [
                                                {
                                                    "call": {
                                                        "operation": "three",
                                                        "arguments": {},
                                                    }
                                                }
                                            ],
                                        }
                                    },
                                ]
                            }
                        ],
                    }
                }
            ],
            "policy": "read",
            "evals": ["nested-positive"],
        }
    )

    assert capability_operation_dependencies({"nested": capability}) == {
        "nested": ("one", "three", "two")
    }
