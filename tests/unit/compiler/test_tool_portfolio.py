from __future__ import annotations

from acc_core.models import ActionCapabilityV2, Capability, ReadCapabilityV2
from acc_core.quality import CapabilityQuality, analyze_tool_portfolio
from acc_core.scope import ScopeInventory


def _quality(capability_id: str, action: str, resource: str) -> CapabilityQuality:
    return CapabilityQuality.model_validate(
        {
            "schema_version": "2",
            "capability_id": capability_id,
            "intent": {"action": action, "resource_types": [resource]},
            "inputs": {},
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65_536, "long_text_disclosures": []},
        }
    )


def _scope(*, capability_id: str = "find_orders", blocked: bool = False) -> ScopeInventory:
    routes: list[dict[str, object]] = [
        {
            "id": "GET /orders",
            "domain": "orders",
            "method": "GET",
            "kind": "read",
            "effect": "read",
            "path": "/orders",
            "evidence_sources": ["routes.py"],
            "eligibility": "eligible",
            "disposition": "composed",
            "operation_id": "orders.list",
            "capability_ids": [capability_id],
        }
    ]
    if blocked:
        routes.append(
            {
                "id": "POST /orders",
                "domain": "orders",
                "method": "POST",
                "kind": "action",
                "effect": "create",
                "path": "/orders",
                "evidence_sources": ["routes.py"],
                "eligibility": "undetermined",
                "disposition": "blocked_on_evidence",
                "reason": "Write sandbox and idempotency evidence are not available.",
            }
        )
    return ScopeInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {
                "mode": "system_complete" if blocked else "domain_complete",
                "selected_domains": ["orders"],
                "exclusion_approval": {},
            },
            "discovery": {
                "source_commit": "git:0123456789abcdef",
                "methods": ["DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"],
                "include_paths": ["app"],
                "evidence_sources": ["routes.py"],
            },
            "domains": [{"id": "orders", "status": "selected"}],
            "routes": routes,
            "summary": {
                "discovered_routes": len(routes),
                "eligible_routes": 1,
                "planned": 0,
                "composed": 1,
                "excluded": 0,
                "blocked_on_evidence": int(blocked),
                "out_of_scope": 0,
                "unresolved": int(blocked),
            },
        }
    )


def _capabilities(*ids: str) -> dict[str, Capability]:
    return {
        identifier: ReadCapabilityV2.model_validate(
            {
                "schema_version": "2",
                "kind": "read",
                "id": identifier,
                "title": identifier,
                "description": f"Exercise {identifier} for portfolio analysis.",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
                "output_schema": {"type": "object"},
                "workflow": [{"emit": {"value": {}}}],
                "policy": "read",
                "evals": [f"{identifier}-positive"],
            }
        )
        for identifier in ids
    }


def _action(capability_id: str) -> ActionCapabilityV2:
    return ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": capability_id,
            "title": capability_id,
            "description": f"Prepare and commit {capability_id}.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {"type": "object"},
            "action": {
                "execution_mode": "single",
                "approval": {"mode": "required"},
                "expires_in_seconds": 300,
            },
            "preview_workflow": [{"emit": {"value": {}}}],
            "commit_workflow": [{"emit": {"value": {}}}],
            "policy": "write",
            "evals": [f"{capability_id}-positive"],
        }
    )


def test_detects_budget_and_same_intent_duplicate_without_route_per_tool_assumption() -> None:
    capabilities = _capabilities("find_orders", "search_orders")
    qualities = {identifier: _quality(identifier, "search", "order") for identifier in capabilities}

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "find_orders": ["orders.list"],
            "search_orders": ["orders.list"],
        },
        _scope(),
        tool_budget=1,
    )

    assert [(item.left, item.right, item.kind) for item in result.overlaps] == [
        ("find_orders", "search_orders", "duplicate")
    ]
    assert {item.code for item in result.diagnostics} == {
        "ACC_TOOL_PORTFOLIO_BUDGET_EXCEEDED",
        "ACC_TOOL_PORTFOLIO_DUPLICATE",
    }


def test_detects_high_overlap_only_within_one_business_intent() -> None:
    capabilities = _capabilities("inspect_order", "inspect_order_history", "list_customers")
    qualities = {
        "inspect_order": _quality("inspect_order", "inspect", "order"),
        "inspect_order_history": _quality("inspect_order_history", "inspect", "order"),
        "list_customers": _quality("list_customers", "list", "customer"),
    }
    dependencies = {
        "inspect_order": ["orders.get", "orders.items", "orders.status"],
        "inspect_order_history": [
            "orders.get",
            "orders.items",
            "orders.status",
            "orders.history",
        ],
        # Identical mechanics are legitimate for a different business intent.
        "list_customers": ["orders.get", "orders.items", "orders.status"],
    }

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        dependencies,
        _scope(capability_id="inspect_order"),
    )

    assert [(item.left, item.right, item.kind) for item in result.overlaps] == [
        ("inspect_order", "inspect_order_history", "high_overlap")
    ]


def test_flags_isolated_mutation_unknown_assignment_and_preserves_blocked_denominator() -> None:
    capabilities = _capabilities("update_order")
    qualities = {"update_order": _quality("update_order", "update", "order")}

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {"update_order": ["orders.update"]},
        _scope(capability_id="missing_capability", blocked=True),
    )

    assert result.isolated_mutation_ids == ("update_order",)
    assert result.uncovered_materialized_route_ids == ("GET /orders",)
    assert result.blocked_route_count == 1
    assert {item.code for item in result.diagnostics} == {
        "ACC_TOOL_PORTFOLIO_BUSINESS_SURFACE_BLOCKED",
        "ACC_TOOL_PORTFOLIO_ISOLATED_MUTATION",
        "ACC_TOOL_PORTFOLIO_UNDER_COVERED",
    }


def test_read_anchor_and_composed_route_form_a_reachable_compact_portfolio() -> None:
    capabilities = _capabilities("find_orders", "update_order")
    qualities = {
        "find_orders": _quality("find_orders", "search", "order"),
        "update_order": _quality("update_order", "update", "order"),
    }

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "find_orders": ["orders.list"],
            "update_order": ["orders.update"],
        },
        _scope(),
    )

    assert result.covered_route_ids == ("GET /orders",)
    assert result.isolated_mutation_ids == ()
    assert result.diagnostics == ()


def test_empty_dependencies_are_unknown_and_interface_differences_prevent_overlap() -> None:
    capabilities = _capabilities("find_orders", "search_orders")
    search = capabilities["search_orders"]
    assert isinstance(search, ReadCapabilityV2)
    capabilities["search_orders"] = search.model_copy(
        update={"output_schema": {"type": "array", "items": {"type": "object"}}}
    )
    qualities = {identifier: _quality(identifier, "search", "order") for identifier in capabilities}

    empty = analyze_tool_portfolio(
        capabilities,
        qualities,
        {"find_orders": [], "search_orders": []},
        _scope(),
    )
    projected = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "find_orders": ["orders.list"],
            "search_orders": ["orders.list"],
        },
        _scope(),
    )

    assert empty.overlaps == ()
    assert [item.code for item in empty.diagnostics] == [
        "ACC_TOOL_PORTFOLIO_DEPENDENCIES_INCOMPLETE",
        "ACC_TOOL_PORTFOLIO_DEPENDENCIES_INCOMPLETE",
    ]
    assert projected.overlaps == ()
    assert projected.diagnostics == ()


def test_projects_actual_mcp_tools_list_for_action_capabilities() -> None:
    capabilities = _capabilities("find_orders")
    capabilities["update_order"] = _action("update_order")
    qualities = {
        "find_orders": _quality("find_orders", "search", "order"),
        "update_order": _quality("update_order", "update", "order"),
    }

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "find_orders": ["orders.list"],
            "update_order": ["orders.get", "orders.update"],
        },
        _scope(),
        tool_budget=4,
    )

    assert result.projected_mcp_tool_names == (
        "acc_action_approve",
        "acc_action_commit",
        "acc_action_status",
        "find_orders",
        "update_order.prepare",
    )
    assert result.projected_mcp_tool_count == 5
    assert result.projected_mcp_tool_collisions == ()
    assert {item.code for item in result.diagnostics} == {"ACC_TOOL_PORTFOLIO_BUDGET_EXCEEDED"}
    assert "2 Capabilities and projects 5 MCP tools" in result.diagnostics[0].message


def test_warns_on_transition_fragmentation_despite_const_and_dependency_differences() -> None:
    capabilities = _capabilities("find_orders")
    close = _action("close_order").model_copy(
        update={
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"target_status": {"const": "closed"}},
            }
        }
    )
    cancel = _action("cancel_order").model_copy(
        update={
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"target_status": {"const": "cancelled"}},
            }
        }
    )
    capabilities.update({"close_order": close, "cancel_order": cancel})
    qualities = {
        "find_orders": _quality("find_orders", "search", "order"),
        "close_order": _quality("close_order", "transition", "order"),
        "cancel_order": _quality("cancel_order", "transition", "order"),
    }

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "find_orders": ["orders.list"],
            "close_order": ["orders.close"],
            "cancel_order": ["orders.cancel", "audit.write"],
        },
        _scope(),
    )

    assert result.overlaps == ()
    assert "ACC_TOOL_PORTFOLIO_TRANSITION_FRAGMENTATION" in {
        item.code for item in result.diagnostics
    }
    assert result.projected_mcp_tool_names.count("acc_action_commit") == 1


def test_one_bounded_transition_action_is_not_fragmented() -> None:
    capabilities = _capabilities("find_orders")
    capabilities["transition_order"] = _action("transition_order").model_copy(
        update={
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target_status": {"enum": ["closed", "cancelled"]},
                },
            }
        }
    )
    qualities = {
        "find_orders": _quality("find_orders", "search", "order"),
        "transition_order": _quality("transition_order", "transition", "order"),
    }

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "find_orders": ["orders.list"],
            "transition_order": ["orders.transition"],
        },
        _scope(),
    )

    assert "ACC_TOOL_PORTFOLIO_TRANSITION_FRAGMENTATION" not in {
        item.code for item in result.diagnostics
    }


def test_detects_read_name_collision_with_action_prepare_and_shared_lifecycle() -> None:
    capabilities = _capabilities("orders.update.prepare", "acc_action_commit")
    capabilities["orders.update"] = _action("orders.update")
    qualities = {
        "orders.update.prepare": _quality("orders.update.prepare", "get", "order"),
        "acc_action_commit": _quality("acc_action_commit", "monitor", "action"),
        "orders.update": _quality("orders.update", "update", "order"),
    }

    result = analyze_tool_portfolio(
        capabilities,
        qualities,
        {
            "orders.update.prepare": ["orders.get"],
            "acc_action_commit": ["actions.status"],
            "orders.update": ["orders.get", "orders.update"],
        },
        _scope(capability_id="orders.update.prepare"),
    )

    assert result.projected_mcp_tool_count == 6
    assert result.projected_mcp_tool_collisions == (
        "acc_action_commit",
        "orders.update.prepare",
    )
    assert "ACC_TOOL_PORTFOLIO_MCP_NAME_COLLISION" in {item.code for item in result.diagnostics}
