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


def test_scope_inventory_parses_the_platform_neutral_route_denominator() -> None:
    inventory = ScopeInventory.model_validate(_inventory())

    assert inventory.scope.mode == "system_complete"
    assert inventory.routes[0].operation_id == "crm.list_customers"
    assert inventory.summary.eligible_routes == 1


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
