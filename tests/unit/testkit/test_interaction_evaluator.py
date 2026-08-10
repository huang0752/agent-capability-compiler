from __future__ import annotations

import asyncio
import copy
from typing import Any, Literal, cast

import pytest
from pydantic import JsonValue, ValidationError

from acc_testkit.interactions import (
    ActionPhaseRecord,
    ClientAdapterConformanceProbe,
    ClientAdapterConformanceReport,
    ClientAdapterConformanceStep,
    HeadlessInteractionEvaluator,
    InteractionCallerError,
    InteractionEvaluationError,
    evaluate_condition,
)


def _contract() -> dict[str, object]:
    manifest = _manifest_contract()
    contract = _manifest_capability(manifest)
    contract["public_input_bindings"] = [
        {
            "id": f"{name}-input",
            "source_kind": "user_input",
            "target_pointer": f"/{name}",
            "cardinality": "optional",
        }
        for name in ("explicit", "missing", "nullable")
    ]
    contract["defaults"] = [
        {
            "id": f"default-{name}",
            "source_kind": "literal",
            "target_pointer": f"/{name}",
            "value": "fallback",
        }
        for name in ("explicit", "missing", "nullable")
    ]
    contract["option_sources"] = []
    return manifest


TEST_IDENTITY_SALT = b"offline-interaction-test-salt"
INTERACTION_DIGEST = "a" * 64


def _manifest_contract() -> dict[str, object]:
    evidence_free_option = {
        "id": "customer-options",
        "target_pointer": "/customer_id",
        "source_kind": "operation",
        "producer_id": "list_customers",
        "static_options": [],
        "request_bindings": [
            {
                "id": "region-binding",
                "source_kind": "user_input",
                "source_id": None,
                "source_pointer": "/filters/0/region",
                "target_pointer": "/filters/0/region",
                "cardinality": "one",
                "mapping": None,
                "literal_value": None,
            }
        ],
        "items_pointer": "/items",
        "value_pointer": "/id",
        "label_pointer": "/name",
        "disabled_pointer": None,
        "group_pointer": None,
        "cascade_dependencies": ["/filters/0/region"],
        "search": {"mode": "server", "query_pointer": "/query"},
        "pagination": {
            "mode": "cursor",
            "request_pointer": "/cursor",
            "response_pointer": "/next_cursor",
        },
        "cache": {"mode": "session", "max_age_seconds": 60},
        "freshness": "request",
        "empty_behavior": "clear_selection",
        "error_behavior": "fail_closed",
    }
    contract = {
        "action_lifecycle": None,
        "capability_id": "search_customers",
        "conditions": [],
        "defaults": [
            {
                "id": "default-limit",
                "source_kind": "literal",
                "target_pointer": "/limit",
                "value": 20,
            }
        ],
        "inherited_interactions": {
            "customers.search": {
                "call_order": "sequential",
                "option_behaviors": [],
                "result_consumption": [],
                "states": [
                    {
                        "allowed_next_events": ["refresh"],
                        "entry_condition_id": None,
                        "id": "ready",
                        "kind": "ready",
                    }
                ],
                "trigger": {"kind": "submit", "source_pointer": None},
            }
        },
        "interaction_ids": ["customers.search"],
        "omitted_interaction_ids": [],
        "option_sources": [evidence_free_option],
        "overridden_interaction_ids": [],
        "public_input_bindings": [
            {
                "id": "region-input",
                "source_kind": "user_input",
                "source_id": None,
                "source_pointer": "/filters/0/region",
                "target_pointer": "/filters/0/region",
                "cardinality": "one",
                "mapping": None,
                "literal_value": None,
            },
            {
                "id": "customer-input",
                "source_kind": "user_input",
                "source_id": None,
                "source_pointer": "/customer_id",
                "target_pointer": "/customer_id",
                "cardinality": "optional",
                "mapping": None,
                "literal_value": None,
            },
        ],
        "related_data": [],
        "required_scenarios": ["customers.search.success"],
        "result_consumption": [],
        "sidecar_sha256": "b" * 64,
    }
    return {
        "schema_version": "2",
        "digest": INTERACTION_DIGEST,
        "inventory": {"status": "declared"},
        "contracts": {"search_customers": contract},
        "dependencies": [["list_customers", "search_customers"]],
    }


def _manifest_capability(manifest: dict[str, object]) -> dict[str, Any]:
    contracts = cast(dict[str, object], manifest["contracts"])
    return cast(dict[str, Any], contracts["search_customers"])


def test_evaluator_consumes_manifest_contract_and_rejects_undeclared_initial_fields() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert evaluator.values == {"filters": [{"region": "east"}], "limit": 20}
    with pytest.raises(InteractionEvaluationError, match="undeclared initial field"):
        HeadlessInteractionEvaluator(
            _manifest_contract(),
            capability_id="search_customers",
            initial_values={"filters": [{"region": "east"}], "private": "no"},
            principal_id="principal-a",
            tenant_id="tenant-a",
            identity_salt=TEST_IDENTITY_SALT,
        )


@pytest.mark.asyncio
async def test_trace_keeps_public_state_but_hashes_caller_arguments_and_results() -> None:
    secret_result = "result-private"

    async def caller(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        return {"private": secret_result}

    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    await evaluator.call_consumer(caller)

    rendered = repr(evaluator.trace)
    assert secret_result not in rendered
    assert evaluator.trace[-3].arguments_sha256 is not None
    assert evaluator.trace[-1].result_sha256 is not None


@pytest.mark.asyncio
async def test_consumer_exception_is_data_free_source_error_and_cancellation_propagates() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    async def failed(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        raise RuntimeError("consumer-secret-message")

    with pytest.raises(InteractionEvaluationError, match="consumer source_error") as caught:
        await evaluator.call_consumer(failed)
    assert caught.value.__cause__ is None
    assert "consumer-secret-message" not in repr(caught.value)
    assert evaluator.interaction_state == "source_error"

    async def cancelled(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await evaluator.call_consumer(cancelled)


def test_action_assessment_consumes_observed_records_and_never_self_verifies() -> None:
    phases: tuple[Literal["prepare", "approve", "commit", "status"], ...] = (
        "prepare",
        "approve",
        "commit",
        "status",
    )
    records = tuple(
        ActionPhaseRecord(
            phase=phase,
            correlation_id="corr-1",
            idempotency_key="idem-1",
            audit_id=f"audit-{phase}",
        )
        for phase in phases
    )

    manifest = copy.deepcopy(_manifest_contract())
    _manifest_capability(manifest)["action_lifecycle"] = {
        "interaction_id": "customers.search",
        "phases": ["prepare", "approve", "commit", "status"],
    }
    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    assessment = evaluator.assess_action_protocol(records)

    assert assessment.shape_valid is True
    assert assessment.status == "not_verified"
    assert assessment.verified is False
    broken = evaluator.assess_action_protocol(records[:-1])
    assert broken.shape_valid is False
    assert broken.status == "not_provisioned"

    read_evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    assert read_evaluator.assess_action_protocol(records).status == "not_provisioned"


@pytest.mark.asyncio
async def test_generic_caller_failure_is_data_free_and_cancellation_propagates() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    async def failed(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        raise RuntimeError("source-secret-message")

    assert not await evaluator.request_options("/customer_id", failed, search="", page="")
    assert evaluator.interaction_state == "source_error"
    assert "source-secret-message" not in repr(evaluator.trace)

    async def cancelled(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await evaluator.request_options("/customer_id", cancelled, search="", page="")


def test_cache_key_binds_manifest_capability_producer_identity_tenant_and_arguments() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    key = evaluator.option_cache_key("/customer_id", {"query": "acme"})

    assert key[:3] == (INTERACTION_DIGEST, "search_customers", "list_customers")
    assert "principal-a" not in repr(key)
    assert "tenant-a" not in repr(key)


@pytest.mark.asyncio
async def test_static_options_need_no_caller_and_cursor_token_is_retained() -> None:
    static_manifest = copy.deepcopy(_manifest_contract())
    source = _manifest_capability(static_manifest)["option_sources"][0]
    source.update(
        {
            "source_kind": "static",
            "producer_id": None,
            "static_options": [{"value": "c-1", "label": "Acme", "disabled": False}],
            "request_bindings": [],
            "search": {"mode": "none", "query_pointer": None},
            "pagination": {
                "mode": "none",
                "request_pointer": None,
                "response_pointer": None,
            },
        }
    )
    evaluator = HeadlessInteractionEvaluator(
        static_manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    assert evaluator.static_options("/customer_id") == (
        {"value": "c-1", "label": "Acme", "disabled": False},
    )

    dynamic = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    async def caller(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        return {"items": [], "next_cursor": "cursor-2"}

    assert await dynamic.request_options("/customer_id", caller, search="", page="cursor-1")
    assert dynamic.paging_token("/customer_id") == "cursor-2"


def test_conditions_states_and_reset_are_derived_from_manifest() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    contract = _manifest_capability(manifest)
    contract["public_input_bindings"].append(
        {
            "id": "temporary-input",
            "source_kind": "user_input",
            "source_pointer": "/temporary",
            "target_pointer": "/temporary",
            "cardinality": "optional",
        }
    )
    contract["conditions"] = [
        {
            "id": "customer-visible",
            "target": "visible",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "eq",
                "left": {"kind": "reference", "pointer": "/filters/0/region"},
                "right": {"kind": "literal", "value": "east"},
            },
        },
        {
            "id": "temporary-reset",
            "target": "reset",
            "target_pointer": "/temporary",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/temporary"},
            },
        },
    ]
    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}], "temporary": "discard"},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    semantics = evaluator.apply_conditions()

    assert semantics["/customer_id"] == {
        "visible": True,
        "enabled": True,
        "required": False,
    }
    assert "temporary" not in evaluator.values
    assert evaluator.declared_states == ("ready",)


def test_cascade_clear_selection_invalidates_transitive_dependents() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    contract = _manifest_capability(manifest)
    downstream = copy.deepcopy(contract["option_sources"][0])
    downstream.update(
        {
            "id": "order-options",
            "target_pointer": "/order_id",
            "producer_id": "list_orders",
            "cascade_dependencies": ["/customer_id"],
            "request_bindings": [
                {
                    "id": "customer-binding",
                    "source_kind": "user_input",
                    "source_pointer": "/customer_id",
                    "target_pointer": "/customer_id",
                    "cardinality": "one",
                }
            ],
        }
    )
    contract["option_sources"].append(downstream)
    contract["public_input_bindings"].append(
        {
            "id": "order-input",
            "source_kind": "user_input",
            "source_pointer": "/order_id",
            "target_pointer": "/order_id",
            "cardinality": "optional",
        }
    )
    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={
            "filters": [{"region": "east"}],
            "customer_id": "c-1",
            "order_id": "o-1",
        },
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    evaluator.set_value("/filters/0/region", "west")

    assert "customer_id" not in evaluator.values
    assert "order_id" not in evaluator.values


@pytest.mark.asyncio
async def test_related_data_and_result_consumption_form_a_minimal_manifest_trace() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    contract = _manifest_capability(manifest)
    contract["public_input_bindings"].append(
        {
            "id": "account-input",
            "source_kind": "prior_response",
            "source_pointer": "/account",
            "target_pointer": "/account",
            "cardinality": "optional",
        }
    )
    contract["related_data"] = [
        {
            "id": "account-related",
            "producer_kind": "operation",
            "producer_id": "get_account",
            "output_pointer": "/account",
            "target_pointer": "/account",
            "cardinality": "optional",
            "identity_pointer": None,
            "ordering": "none",
            "freshness": "request",
            "failure_isolation": "independent",
        }
    ]
    contract["result_consumption"] = [
        {
            "id": "customer-summary",
            "role": "summary",
            "source_pointer": "/customer",
            "field_pointers": ["/id"],
            "ordering": "none",
            "formatting_class": None,
            "pagination": "none",
            "state_ids": ["ready"],
        }
    ]

    async def caller(producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        assert producer_id == "get_account"
        return {"account": {"id": "a-1"}}

    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert await evaluator.load_related_data(caller) == {"account-related": "resolved"}
    assert evaluator.values["account"] == {"id": "a-1"}
    assert evaluator.consume_result({"customer": {"id": "c-1", "private": "hidden"}}) == {
        "customer-summary": {"id": "c-1"}
    }


def test_table_result_consumption_projects_each_array_item() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    _manifest_capability(manifest)["result_consumption"] = [
        {
            "id": "customer-table",
            "role": "table",
            "source_pointer": "/customers",
            "field_pointers": ["/id", "/name"],
            "ordering": "source",
            "formatting_class": None,
            "pagination": "server",
            "state_ids": ["ready"],
        }
    ]
    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    projected = evaluator.consume_result(
        {
            "customers": [
                {"id": "c-1", "name": "Acme", "private": "hidden-1"},
                {"id": "c-2", "name": "Beta", "private": "hidden-2"},
            ]
        }
    )

    assert projected == {
        "customer-table": [
            {"id": "c-1", "name": "Acme"},
            {"id": "c-2", "name": "Beta"},
        ]
    }


def test_defaults_distinguish_missing_null_and_explicit_values() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _contract(),
        capability_id="search_customers",
        initial_values={"nullable": None, "explicit": "caller"},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert evaluator.values == {
        "missing": "fallback",
        "nullable": None,
        "explicit": "caller",
    }
    assert [entry.event for entry in evaluator.trace] == ["initialized"]


def test_compiled_safe_defaults_are_submitted_with_explicit_null_and_caller_values() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _contract(),
        capability_id="search_customers",
        initial_values={"nullable": None, "explicit": "caller"},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert evaluator.submission() == {
        "missing": "fallback",
        "nullable": None,
        "explicit": "caller",
    }


def test_safe_condition_evaluator_uses_the_canonical_typed_ast() -> None:
    state: dict[str, JsonValue] = {
        "mode": "advanced",
        "region": {"id": "east"},
        "archived": False,
    }
    condition = {
        "operator": "all",
        "operands": [
            {
                "operator": "eq",
                "left": {"kind": "reference", "pointer": "/mode"},
                "right": {"kind": "literal", "value": "advanced"},
            },
            {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/region/id"},
            },
            {
                "operator": "not",
                "operand": {
                    "operator": "ne",
                    "left": {"kind": "reference", "pointer": "/archived"},
                    "right": {"kind": "literal", "value": False},
                },
            },
            {
                "operator": "any",
                "operands": [
                    {
                        "operator": "in",
                        "left": {"kind": "reference", "pointer": "/mode"},
                        "right": {
                            "kind": "literal",
                            "value": ["advanced", "expert"],
                        },
                    }
                ],
            },
        ],
    }

    assert evaluate_condition(condition, state) is True
    with pytest.raises(InteractionEvaluationError, match="unsupported condition operator"):
        evaluate_condition({"op": "and", "args": []}, state)


@pytest.mark.parametrize("operator", ["eq", "ne", "in"])
def test_comparisons_fail_closed_when_a_required_operand_is_missing(operator: str) -> None:
    right: dict[str, JsonValue]
    if operator == "in":
        right = {"kind": "literal", "value": ["advanced"]}
    else:
        right = {"kind": "literal", "value": "advanced"}
    condition = {
        "operator": operator,
        "left": {"kind": "reference", "pointer": "/missing"},
        "right": right,
    }

    assert evaluate_condition(condition, {}) is False


@pytest.mark.parametrize("operator", ["all", "any"])
def test_boolean_combinations_reject_empty_operands(operator: str) -> None:
    with pytest.raises(InteractionEvaluationError, match="condition operands must be nonempty"):
        evaluate_condition({"operator": operator, "operands": []}, {})


def test_safe_condition_evaluator_enforces_core_depth_and_node_budgets() -> None:
    too_deep: dict[str, object] = {
        "operator": "present",
        "operand": {"kind": "literal", "value": True},
    }
    for _ in range(64):
        too_deep = {"operator": "not", "operand": too_deep}

    too_wide = {
        "operator": "all",
        "operands": [
            {
                "operator": "present",
                "operand": {"kind": "literal", "value": True},
            }
            for _ in range(2_048)
        ],
    }

    with pytest.raises(InteractionEvaluationError, match="maximum depth"):
        evaluate_condition(too_deep, {})
    with pytest.raises(InteractionEvaluationError, match="maximum node count"):
        evaluate_condition(too_wide, {})


def test_stale_option_generation_cannot_replace_newer_options() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    first = evaluator.begin_option_request("/customer_id")
    second = evaluator.begin_option_request("/customer_id")

    assert evaluator.resolve_option_request("/customer_id", first, [{"id": "old"}]) is False
    assert evaluator.resolve_option_request("/customer_id", second, [{"id": "new"}]) is True
    assert evaluator.options("/customer_id") == ({"id": "new"},)
    assert [entry.event for entry in evaluator.trace] == [
        "initialized",
        "options_requested",
        "options_requested",
        "options_stale",
        "options_resolved",
    ]


def _async_contract() -> dict[str, object]:
    return _manifest_contract()


@pytest.mark.asyncio
async def test_async_option_flow_maps_search_page_and_value_label_then_calls_consumer() -> None:
    calls: list[tuple[str, dict[str, JsonValue]]] = []

    async def caller(producer_id: str, arguments: dict[str, JsonValue]) -> JsonValue:
        calls.append((producer_id, arguments))
        if producer_id == "list_customers":
            return {"items": [{"id": "c-1", "name": "Acme"}], "next_cursor": "cursor-2"}
        return {"selected": arguments["customer_id"]}

    evaluator = HeadlessInteractionEvaluator(
        _async_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert (
        await evaluator.request_options("/customer_id", caller, search="acme", page="cursor-1")
        is True
    )
    assert evaluator.options("/customer_id") == ({"value": "c-1", "label": "Acme"},)
    assert evaluator.interaction_state == "ready"
    evaluator.set_value("/customer_id", "c-1")
    result = await evaluator.call_consumer(caller)

    assert calls == [
        (
            "list_customers",
            {"filters": [{"region": "east"}], "query": "acme", "cursor": "cursor-1"},
        ),
        (
            "search_customers",
            {"filters": [{"region": "east"}], "customer_id": "c-1", "limit": 20},
        ),
    ]
    assert result == {"selected": "c-1"}
    assert [entry.event for entry in evaluator.trace][-3:] == [
        "consumer_requested",
        "consumer_resolved",
        "result_consumed",
    ]


@pytest.mark.asyncio
async def test_dynamic_option_projection_includes_declared_disabled_and_group_values() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    source = _manifest_capability(manifest)["option_sources"][0]
    source["disabled_pointer"] = "/disabled"
    source["group_pointer"] = "/group"
    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    async def caller(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        return {
            "items": [
                {
                    "id": "c-1",
                    "name": "Acme",
                    "disabled": True,
                    "group": "preferred",
                }
            ],
            "next_cursor": "cursor-2",
        }

    assert await evaluator.request_options("/customer_id", caller, search="", page="cursor-1")
    assert evaluator.options("/customer_id") == (
        {
            "value": "c-1",
            "label": "Acme",
            "disabled": True,
            "group": "preferred",
        },
    )


@pytest.mark.asyncio
async def test_request_bindings_apply_mapping_and_cardinality_or_fail_not_provisioned() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    binding = _manifest_capability(manifest)["option_sources"][0]["request_bindings"][0]
    binding["mapping"] = {"kind": "enum", "mapping": {"east": "E"}}
    binding["cardinality"] = "one"
    observed: list[dict[str, JsonValue]] = []

    async def caller(_producer_id: str, arguments: dict[str, JsonValue]) -> JsonValue:
        observed.append(arguments)
        return {"items": [], "next_cursor": "cursor-2"}

    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    assert await evaluator.request_options("/customer_id", caller, search="", page="cursor-1")
    assert observed[0]["filters"] == [{"region": "E"}]

    unsupported = copy.deepcopy(_manifest_contract())
    unsupported_binding = _manifest_capability(unsupported)["option_sources"][0][
        "request_bindings"
    ][0]
    unsupported_binding["mapping"] = {"kind": "script", "mapping": {}}
    invalid = HeadlessInteractionEvaluator(
        unsupported,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    with pytest.raises(InteractionEvaluationError, match="transform is not provisioned"):
        await invalid.request_options("/customer_id", caller, search="", page="cursor-1")


@pytest.mark.asyncio
async def test_many_mapping_transforms_each_item_and_optional_missing_is_omitted() -> None:
    manifest = copy.deepcopy(_manifest_contract())
    contract = _manifest_capability(manifest)
    contract["public_input_bindings"].append(
        {
            "id": "tags-input",
            "source_kind": "user_input",
            "target_pointer": "/tags",
            "cardinality": "many",
        }
    )
    bindings = contract["option_sources"][0]["request_bindings"]
    bindings[:] = [
        {
            "id": "tags-binding",
            "source_kind": "user_input",
            "source_pointer": "/tags",
            "target_pointer": "/tags",
            "cardinality": "many",
            "mapping": {"kind": "text", "mapping": {}},
        },
        {
            "id": "optional-binding",
            "source_kind": "user_input",
            "source_pointer": "/customer_id",
            "target_pointer": "/customer_id",
            "cardinality": "optional",
            "mapping": None,
        },
    ]
    observed: list[dict[str, JsonValue]] = []

    async def caller(_producer_id: str, arguments: dict[str, JsonValue]) -> JsonValue:
        observed.append(arguments)
        return {"items": [], "next_cursor": "cursor-2"}

    evaluator = HeadlessInteractionEvaluator(
        manifest,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}], "tags": ["a", "b"]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    assert await evaluator.request_options("/customer_id", caller, search="", page="cursor-1")
    assert observed[0]["tags"] == ["a", "b"]
    assert "customer_id" not in observed[0]


@pytest.mark.asyncio
async def test_cascade_change_rejects_in_flight_option_response_as_stale() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def caller(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        started.set()
        await release.wait()
        return {"items": [{"id": "old", "name": "Old"}], "next_cursor": "cursor-2"}

    evaluator = HeadlessInteractionEvaluator(
        _async_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    pending = asyncio.create_task(
        evaluator.request_options("/customer_id", caller, search="", page="cursor-1")
    )
    await started.wait()
    evaluator.set_value("/filters/0/region", "west")
    release.set()

    assert await pending is False
    assert evaluator.options("/customer_id") == ()
    assert evaluator.interaction_state == "stale"
    assert evaluator.trace[-1].event == "options_stale"


def test_cascade_change_invalidates_already_resolved_options() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _async_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    generation = evaluator.begin_option_request("/customer_id")
    assert evaluator.resolve_option_request(
        "/customer_id", generation, [{"value": "c-1", "label": "Acme"}]
    )

    evaluator.set_value("/filters/0/region", "west")

    assert evaluator.options("/customer_id") == ()
    assert evaluator.interaction_state == "stale"


@pytest.mark.asyncio
async def test_option_producer_may_return_a_root_items_array() -> None:
    contract = _manifest_contract()
    source = _manifest_capability(contract)["option_sources"][0]
    source.update(
        {
            "request_bindings": [],
            "cascade_dependencies": [],
            "search": {"mode": "none", "query_pointer": None},
            "pagination": {
                "mode": "none",
                "request_pointer": None,
                "response_pointer": None,
            },
            "items_pointer": None,
        }
    )

    async def caller(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        return [{"id": "c-1", "name": "Acme"}]

    evaluator = HeadlessInteractionEvaluator(
        contract,
        capability_id="search_customers",
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert await evaluator.request_options("/customer_id", caller)
    assert evaluator.options("/customer_id") == ({"value": "c-1", "label": "Acme"},)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "failure", "expected_state"),
    [
        ({"items": [], "next_cursor": "cursor-2"}, None, "empty"),
        (None, "source_error", "source_error"),
        (None, "forbidden", "forbidden"),
    ],
)
async def test_option_flow_reports_loading_empty_error_and_forbidden_states(
    response: JsonValue | None,
    failure: str | None,
    expected_state: str,
) -> None:
    async def caller(_producer_id: str, _arguments: dict[str, JsonValue]) -> JsonValue:
        if failure is not None:
            raise InteractionCallerError(failure)
        assert response is not None
        return response

    evaluator = HeadlessInteractionEvaluator(
        _async_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    accepted = await evaluator.request_options("/customer_id", caller, search="", page="cursor-1")

    assert accepted is (failure is None)
    assert "loading" in [entry.interaction_state for entry in evaluator.trace]
    assert evaluator.interaction_state == expected_state


def test_selector_cache_key_is_partitioned_by_principal_and_tenant() -> None:
    contract = _manifest_contract()
    first = HeadlessInteractionEvaluator(
        contract,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    other_principal = HeadlessInteractionEvaluator(
        contract,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-b",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    other_tenant = HeadlessInteractionEvaluator(
        contract,
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-b",
        identity_salt=TEST_IDENTITY_SALT,
    )

    first_key = first.option_cache_key("/customer_id", {"q": "acme"})
    assert first_key != other_principal.option_cache_key("/customer_id", {"q": "acme"})
    assert first_key != other_tenant.option_cache_key("/customer_id", {"q": "acme"})
    assert first_key == first.option_cache_key("/customer_id", {"q": "acme"})
    assert "principal-a" not in repr(first_key)
    assert "tenant-a" not in repr(first_key)
    assert all(len(digest) == 64 for digest in first_key[3:5])


def test_state_trace_records_value_changes_without_mutating_prior_entries() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _contract(),
        capability_id="search_customers",
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    evaluator.set_value("/missing", "updated")

    assert evaluator.trace[0].state == {
        "explicit": "fallback",
        "missing": "fallback",
        "nullable": "fallback",
    }
    assert evaluator.trace[1].event == "value_changed"
    assert evaluator.trace[1].field == "/missing"
    assert evaluator.trace[1].state["missing"] == "updated"


def test_required_skipped_conformance_step_prevents_verified_report() -> None:
    report = ClientAdapterConformanceReport.from_steps(
        [
            ClientAdapterConformanceStep(id="defaults", required=True, status="passed"),
            ClientAdapterConformanceStep(id="selector", required=True, status="skipped"),
            ClientAdapterConformanceStep(id="empty-state", required=False, status="skipped"),
        ],
        adapter_id="reference-web-adapter",
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults", "selector"),
        evidence_sources=("adapter-test-suite",),
    )

    assert report.model_dump(mode="json") == {
        "schema_version": "2",
        "adapter_id": "reference-web-adapter",
        "interaction_digest": INTERACTION_DIGEST,
        "required_scenarios": ["defaults", "selector"],
        "passed_scenarios": ["defaults"],
        "failed_scenarios": [],
        "skipped_scenarios": ["empty-state", "selector"],
        "not_provisioned_scenarios": [],
        "not_verified_scenarios": [],
        "evidence_sources": ["adapter-test-suite"],
        "trace_sha256": None,
    }
    assert report.planned == 3
    assert report.executed == 1
    assert report.verified is False


def test_manual_passed_steps_cannot_self_attest_adapter_verification() -> None:
    report = ClientAdapterConformanceReport.from_steps(
        [ClientAdapterConformanceStep(id="defaults", required=True, status="passed")],
        adapter_id="headless-client-adapter",
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults",),
        evidence_sources=("source-contract",),
    )

    assert report.verified is False

    forged = report.model_copy(update={"trace_sha256": "f" * 64})
    assert forged.verified is False


def test_conformance_factory_derives_passed_and_not_provisioned_from_actual_trace() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _manifest_contract(),
        capability_id="search_customers",
        initial_values={"filters": [{"region": "east"}]},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    report = ClientAdapterConformanceReport.from_trace(
        evaluator.trace,
        probes=(
            ClientAdapterConformanceProbe(
                id="initialized", required=True, expected_event="initialized"
            ),
            ClientAdapterConformanceProbe(
                id="selector", required=True, expected_event="options_resolved"
            ),
        ),
        adapter_id="headless-client-adapter",
        interaction_digest=INTERACTION_DIGEST,
        evidence_sources=("captured-adapter-trace",),
    )

    assert report.passed_scenarios == ("initialized",)
    assert report.not_provisioned_scenarios == ("selector",)
    assert report.verified is False

    passed_only = ClientAdapterConformanceReport.from_trace(
        evaluator.trace,
        probes=(
            ClientAdapterConformanceProbe(
                id="initialized", required=True, expected_event="initialized"
            ),
        ),
        adapter_id="headless-client-adapter",
        interaction_digest=INTERACTION_DIGEST,
        evidence_sources=("captured-adapter-trace",),
    )
    assert passed_only.verified is True
    forged = passed_only.model_copy(
        update={
            "required_scenarios": ("forged",),
            "passed_scenarios": ("forged",),
        }
    )
    assert forged.verified is False


def test_report_verification_binds_digest_and_exact_required_scenarios() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _contract(),
        capability_id="search_customers",
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    report = ClientAdapterConformanceReport.from_trace(
        evaluator.trace,
        probes=(
            ClientAdapterConformanceProbe(
                id="defaults", required=True, expected_event="initialized"
            ),
        ),
        adapter_id="reference-web-adapter",
        interaction_digest=INTERACTION_DIGEST,
        evidence_sources=("adapter-test-suite",),
    )

    assert report.is_verified_for(
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults",),
    )
    assert not report.is_verified_for(
        interaction_digest="b" * 64,
        required_scenarios=("defaults",),
    )
    assert not report.is_verified_for(
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults", "empty-state"),
    )


def test_report_factory_rejects_required_scenario_metadata_mismatch() -> None:
    with pytest.raises(ValueError, match="required scenarios must match required steps"):
        ClientAdapterConformanceReport.from_steps(
            [ClientAdapterConformanceStep(id="selector", required=True, status="skipped")],
            adapter_id="reference-web-adapter",
            interaction_digest=INTERACTION_DIGEST,
            required_scenarios=(),
            evidence_sources=("adapter-test-suite",),
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("adapter_id", " reference-web-adapter "),
        ("required_scenarios", ()),
        ("evidence_sources", ()),
    ],
)
def test_report_model_rejects_identity_or_verification_denominator_gaps(
    field: str, invalid_value: object
) -> None:
    document: dict[str, object] = {
        "schema_version": "2",
        "adapter_id": "reference-web-adapter",
        "interaction_digest": INTERACTION_DIGEST,
        "required_scenarios": ("defaults",),
        "passed_scenarios": ("defaults",),
        "failed_scenarios": (),
        "skipped_scenarios": (),
        "evidence_sources": ("adapter-test-suite",),
    }
    document[field] = invalid_value

    with pytest.raises(ValidationError):
        ClientAdapterConformanceReport.model_validate(document)


@pytest.mark.parametrize(
    ("adapter_id", "required_scenarios", "evidence_sources"),
    [
        (" reference-web-adapter ", ("defaults",), ("adapter-test-suite",)),
        ("reference-web-adapter", (), ("adapter-test-suite",)),
        ("reference-web-adapter", ("defaults",), ()),
    ],
)
def test_report_factory_rejects_identity_or_verification_denominator_gaps(
    adapter_id: str,
    required_scenarios: tuple[str, ...],
    evidence_sources: tuple[str, ...],
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        ClientAdapterConformanceReport.from_steps(
            [ClientAdapterConformanceStep(id="defaults", required=True, status="passed")],
            adapter_id=adapter_id,
            interaction_digest=INTERACTION_DIGEST,
            required_scenarios=required_scenarios,
            evidence_sources=evidence_sources,
        )
