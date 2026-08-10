from __future__ import annotations

import pytest
from pydantic import ValidationError

from acc_core.scope import ScopeInventory


def _inventory() -> dict[str, object]:
    return {
        "schema_version": "2",
        "scope": {
            "mode": "system_complete",
            "user_confirmation": None,
            "selected_domains": [],
            "exclusion_approval": {
                "approved_route_ids": [],
                "approval_text": None,
            },
        },
        "discovery": {
            "source_commit": "git:0123456789abcdef",
            "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
            "include_paths": ["backend/app/api"],
            "evidence_sources": ["api-router"],
        },
        "domains": [{"id": "customers", "status": "selected"}],
        "exclusion_rules": [],
        "routes": [
            {
                "id": "crm.route.list_customers",
                "domain": "customers",
                "method": "GET",
                "kind": "read",
                "effect": "read",
                "path": "/api/customers",
                "evidence_sources": ["api-router"],
                "usage_evidence_sources": ["frontend/api/customers.ts:10"],
                "eligibility": "eligible",
                "disposition": "planned",
                "operation_id": "crm.list_customers",
                "capability_ids": ["crm.search_customers"],
                "reason": None,
                "exclusion_rule_id": None,
                "exclusion_decision": None,
            }
        ],
        "summary": {
            "discovered_routes": 1,
            "eligible_routes": 1,
            "planned": 1,
            "composed": 0,
            "excluded": 0,
            "blocked_on_evidence": 0,
            "out_of_scope": 0,
            "unresolved": 0,
        },
    }


def _unknown_inventory() -> dict[str, object]:
    value = _inventory()
    routes = value["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.update(
        kind="unknown",
        effect="unknown",
        eligibility="undetermined",
        disposition="blocked_on_evidence",
        candidate_id="crm.candidate.customer_export",
        operation_id=None,
        capability_ids=[],
        reason="Response and authorization semantics need evidence.",
    )
    value["summary"] = {
        "discovered_routes": 1,
        "eligible_routes": 0,
        "planned": 0,
        "composed": 0,
        "excluded": 0,
        "blocked_on_evidence": 1,
        "out_of_scope": 0,
        "unresolved": 1,
    }
    return value


def test_scope_inventory_parses_the_platform_neutral_route_denominator() -> None:
    inventory = ScopeInventory.model_validate(_inventory())

    assert inventory.scope.mode == "system_complete"
    assert inventory.routes[0].operation_id == "crm.list_customers"
    assert inventory.summary.eligible_routes == 1


def test_scope_route_defaults_frontend_usage_and_interaction_links_to_empty() -> None:
    value = _inventory()
    routes = value["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.pop("usage_evidence_sources")

    inventory = ScopeInventory.model_validate(value)

    assert inventory.routes[0].usage_evidence_sources == []
    assert inventory.routes[0].interaction_ids == []


@pytest.mark.parametrize(
    "interaction_ids",
    [["customers.load", "customers.load"], ["customers.submit", "customers.load"]],
)
def test_scope_route_rejects_duplicate_or_unsorted_interaction_ids(
    interaction_ids: list[str],
) -> None:
    value = _inventory()
    routes = value["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["interaction_ids"] = interaction_ids

    with pytest.raises(ValidationError, match="interaction_ids"):
        ScopeInventory.model_validate(value)


def test_scope_inventory_rejects_unknown_fields() -> None:
    value = _inventory()
    value["customer_specific_setting"] = True

    with pytest.raises(ValidationError, match="customer_specific_setting"):
        ScopeInventory.model_validate(value)


def test_scope_inventory_accepts_action_discovery_methods() -> None:
    value = _inventory()
    discovery = value["discovery"]
    assert isinstance(discovery, dict)
    discovery["methods"] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

    inventory = ScopeInventory.model_validate(value)
    assert inventory.discovery is not None
    assert inventory.discovery.methods == ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]


def test_scope_inventory_accepts_evidence_declared_action_effect() -> None:
    value = _inventory()
    routes = value["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.update(method="POST", kind="action", effect="transition")

    inventory = ScopeInventory.model_validate(value)
    assert inventory.routes[0].effect == "transition"


def test_scope_inventory_accepts_discovery_only_unknown_route() -> None:
    inventory = ScopeInventory.model_validate(_unknown_inventory())

    route = inventory.routes[0]
    assert route.kind == "unknown"
    assert route.effect == "unknown"
    assert route.eligibility == "undetermined"
    assert route.candidate_id == "crm.candidate.customer_export"
    assert inventory.summary.eligible_routes == 0
    assert inventory.summary.unresolved == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("effect", "read", "unknown routes"),
        ("eligibility", "eligible", "unknown routes"),
        ("disposition", "excluded", "unknown routes"),
        ("candidate_id", None, "candidate_id"),
    ],
)
def test_scope_unknown_route_requires_fail_closed_discovery_state(
    field: str,
    value: object,
    message: str,
) -> None:
    document = _unknown_inventory()
    routes = document["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route[field] = value

    with pytest.raises(ValidationError, match=message):
        ScopeInventory.model_validate(document)


def test_scope_known_routes_reject_unknown_effect_and_undetermined_must_be_blocked() -> None:
    unknown_effect = _inventory()
    routes = unknown_effect["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["effect"] = "unknown"
    with pytest.raises(ValidationError, match="read routes"):
        ScopeInventory.model_validate(unknown_effect)

    unresolved_planned = _inventory()
    routes = unresolved_planned["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["eligibility"] = "undetermined"
    route["disposition"] = "excluded"
    route["operation_id"] = None
    route["capability_ids"] = []
    with pytest.raises(ValidationError, match="undetermined routes"):
        ScopeInventory.model_validate(unresolved_planned)


@pytest.mark.parametrize("eligibility", ["eligible", "ineligible"])
def test_scope_blocked_on_evidence_is_always_undetermined(eligibility: str) -> None:
    document = _inventory()
    routes = document["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.update(
        eligibility=eligibility,
        disposition="blocked_on_evidence",
        operation_id=None,
        capability_ids=[],
    )
    document["summary"] = {
        "discovered_routes": 1,
        "eligible_routes": int(eligibility == "eligible"),
        "planned": 0,
        "composed": 0,
        "excluded": 0,
        "blocked_on_evidence": 1,
        "out_of_scope": 0,
        "unresolved": 0,
    }

    with pytest.raises(ValidationError, match="blocked_on_evidence routes"):
        ScopeInventory.model_validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [("operation_id", "crm.list_customers"), ("capability_ids", ["crm.search_customers"])],
)
def test_scope_non_executable_dispositions_reject_executable_trace_fields(
    field: str,
    value: object,
) -> None:
    document = _inventory()
    routes = document["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.update(
        method="POST",
        kind="action",
        effect="transition",
        eligibility="ineligible",
        disposition="excluded",
        operation_id=None,
        capability_ids=[],
    )
    route[field] = value
    document["summary"] = {
        "discovered_routes": 1,
        "eligible_routes": 0,
        "planned": 0,
        "composed": 0,
        "excluded": 1,
        "blocked_on_evidence": 0,
        "out_of_scope": 0,
        "unresolved": 0,
    }

    with pytest.raises(ValidationError, match="only planned or composed routes"):
        ScopeInventory.model_validate(document)


def test_scope_unknown_route_rejects_stale_executable_trace_fields() -> None:
    document = _unknown_inventory()
    routes = document["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["operation_id"] = "crm.list_customers"

    with pytest.raises(ValidationError, match="only planned or composed routes"):
        ScopeInventory.model_validate(document)


def test_scope_known_action_candidate_link_remains_optional_until_cross_doc_validation() -> None:
    document = _inventory()
    routes = document["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.update(method="POST", kind="action", effect="transition")

    inventory = ScopeInventory.model_validate(document)

    assert inventory.routes[0].candidate_id is None


@pytest.mark.parametrize("eligibility", ["ineligible", "undetermined"])
def test_scope_planned_or_composed_route_must_be_known_and_eligible(
    eligibility: str,
) -> None:
    document = _inventory()
    routes = document["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["eligibility"] = eligibility

    with pytest.raises(ValidationError, match="planned or composed routes must be eligible"):
        ScopeInventory.model_validate(document)


def test_scope_summary_counts_only_eligible_and_exactly_all_undetermined_routes() -> None:
    document = _unknown_inventory()
    summary = document["summary"]
    assert isinstance(summary, dict)
    summary["eligible_routes"] = 1
    summary["unresolved"] = 0

    with pytest.raises(ValidationError, match="summary"):
        ScopeInventory.model_validate(document)


def test_scope_inventory_rejects_kind_effect_mismatch() -> None:
    value = _inventory()
    routes = value["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route.update(kind="action", effect="read")

    with pytest.raises(ValidationError, match="mutation effect"):
        ScopeInventory.model_validate(value)


def test_scope_inventory_requires_planned_routes_to_reference_an_operation() -> None:
    value = _inventory()
    routes = value["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["operation_id"] = None

    with pytest.raises(ValidationError, match="operation_id"):
        ScopeInventory.model_validate(value)


def test_scope_inventory_rejects_summary_that_does_not_match_routes() -> None:
    value = _inventory()
    summary = value["summary"]
    assert isinstance(summary, dict)
    summary["planned"] = 0

    with pytest.raises(ValidationError, match="summary"):
        ScopeInventory.model_validate(value)


def test_scope_inventory_accepts_the_minimal_current_document_shape() -> None:
    value = _inventory()
    value.pop("discovery")
    scope = value["scope"]
    assert isinstance(scope, dict)
    scope["mode"] = "pilot"
    scope["user_confirmation"] = "Approved pilot."
    scope.pop("exclusion_approval")
    value["domains"] = [{"id": "customers"}]

    inventory = ScopeInventory.model_validate(value)

    assert inventory.discovery is None
    assert inventory.scope.exclusion_approval.approved_route_ids == []
    assert inventory.domains[0].status is None
