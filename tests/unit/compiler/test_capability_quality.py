from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from pydantic import JsonValue

from acc_core.models import Capability, JsonObject
from acc_core.quality import CapabilityQuality
from acc_core.quality.analyze import analyze_capability_quality


def _call(operation: str, arguments: Mapping[str, object], *, step_id: str) -> dict[str, object]:
    return {
        "id": step_id,
        "call": {
            "operation": operation,
            "arguments": dict(arguments),
        },
    }


def _capability(
    capability_id: str,
    workflow: list[dict[str, object]],
    *,
    properties: JsonObject | None = None,
    required: list[str] | None = None,
) -> Capability:
    input_schema: JsonObject = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties or {},
    }
    if required:
        input_schema["required"] = cast(JsonValue, required)
    return Capability.model_validate(
        {
            "schema_version": "1",
            "id": capability_id,
            "title": capability_id,
            "description": capability_id,
            "input_schema": input_schema,
            "output_schema": {"type": "object"},
            "workflow": [*workflow, {"emit": {"value": {}}}],
            "policy": "read",
            "evals": [f"{capability_id}-positive"],
        }
    )


def _quality(
    capability_id: str,
    *,
    action: str,
    resources: list[str],
    inputs: dict[str, dict[str, object]] | None = None,
    justification: str | None = None,
) -> CapabilityQuality:
    return CapabilityQuality.model_validate(
        {
            "schema_version": "2",
            "capability_id": capability_id,
            "intent": {
                "action": action,
                "resource_types": resources,
            },
            "inputs": inputs or {},
            "composition": {
                "failure_mode": "fail_fast",
                **({"justification": justification} if justification else {}),
            },
            "output_budget": {
                "max_bytes": 65_536,
                "long_text_disclosures": [],
            },
        }
    )


def _selector(
    resource_type: str,
    *,
    acquisition: str = "caller",
    producers: list[str] | None = None,
) -> dict[str, object]:
    return {
        "kind": "resource_selector",
        "resource_type": resource_type,
        "acquisition": acquisition,
        "producers": producers or [],
    }


def test_crm_search_output_makes_detail_selector_discoverable() -> None:
    capabilities = {
        "search_customers": _capability(
            "search_customers",
            [_call("crm.search_customers", {"keyword": "$.input.keyword"}, step_id="search")],
            properties={"keyword": {"type": "string"}},
        ),
        "get_customer": _capability(
            "get_customer",
            [_call("crm.get_customer", {"customer_id": "$.input.customer_id"}, step_id="get")],
            properties={"customer_id": {"type": "string"}},
            required=["customer_id"],
        ),
    }
    qualities = {
        "search_customers": _quality(
            "search_customers",
            action="search",
            resources=["customer"],
            inputs={
                "keyword": {
                    "kind": "query",
                    "acquisition": "caller",
                    "producers": [],
                }
            },
        ),
        "get_customer": _quality(
            "get_customer",
            action="get",
            resources=["customer"],
            inputs={
                "customer_id": _selector(
                    "customer",
                    acquisition="capability_output",
                    producers=["search_customers"],
                )
            },
        ),
    }

    report = analyze_capability_quality(capabilities, qualities)

    assert report.diagnostics == ()
    assert report.graph.entrypoints == ("search_customers",)
    assert report.graph.reachable == ("get_customer", "search_customers")
    assert [(edge.producer, edge.consumer, edge.input_name) for edge in report.graph.edges] == [
        ("search_customers", "get_customer", "customer_id")
    ]


def test_missing_declared_selector_producer_is_a_discovery_dead_end() -> None:
    capability = _capability(
        "get_customer",
        [_call("crm.get_customer", {"customer_id": "$.input.customer_id"}, step_id="get")],
        properties={"customer_id": {"type": "string"}},
        required=["customer_id"],
    )
    quality = _quality(
        "get_customer",
        action="get",
        resources=["customer"],
        inputs={
            "customer_id": _selector(
                "customer",
                acquisition="capability_output",
                producers=["search_customers"],
            )
        },
    )

    report = analyze_capability_quality({"get_customer": capability}, {"get_customer": quality})

    assert {item.code for item in report.diagnostics} == {
        "ACC_CAPABILITY_REQUIRED_SELECTOR_UNDISCOVERABLE",
        "ACC_COVERAGE_DISCOVERY_DEAD_END",
    }
    assert report.graph.dead_ends == ("get_customer",)


def test_erp_aggregate_calls_sharing_order_id_are_one_composition_component() -> None:
    capability = _capability(
        "inspect_order",
        [
            _call("erp.get_order", {"order_id": "$.input.order_id"}, step_id="order"),
            _call("erp.list_order_lines", {"order_id": "$.input.order_id"}, step_id="lines"),
            _call("erp.list_order_payments", {"order_id": "$.input.order_id"}, step_id="payments"),
        ],
        properties={"order_id": {"type": "string"}},
        required=["order_id"],
    )
    quality = _quality(
        "inspect_order",
        action="aggregate",
        resources=["order"],
        inputs={"order_id": _selector("order")},
    )

    report = analyze_capability_quality({"inspect_order": capability}, {"inspect_order": quality})

    assert report.diagnostics == ()
    assert report.composition_components == {"inspect_order": 1}


def test_independent_finance_ids_trigger_fanin_and_operation_budget_diagnostics() -> None:
    identifiers = [
        "cashflow_id",
        "cost_id",
        "invoice_id",
        "payment_id",
        "receipt_id",
        "refund_id",
        "reversal_id",
        "settlement_id",
        "statement_id",
    ]
    capability = _capability(
        "inspect_finance",
        [
            _call(
                f"finance.get_{name.removesuffix('_id')}",
                {name: f"$.input.{name}"},
                step_id=f"get_{index}",
            )
            for index, name in enumerate(identifiers)
        ],
        properties={name: {"type": "string"} for name in identifiers},
        required=identifiers,
    )
    quality = _quality(
        "inspect_finance",
        action="inspect",
        resources=["finance_record"],
        inputs={name: _selector("finance_record") for name in identifiers},
    )

    report = analyze_capability_quality(
        {"inspect_finance": capability},
        {"inspect_finance": quality},
        operation_budget=8,
    )

    assert {item.code for item in report.diagnostics} == {
        "ACC_CAPABILITY_INDEPENDENT_CALL_FANIN",
        "ACC_CAPABILITY_OPERATION_BUDGET_EXCEEDED",
    }
    assert report.composition_components == {"inspect_finance": 9}


def test_single_job_monitor_is_valid_and_single_operation_is_not_a_risk() -> None:
    capability = _capability(
        "monitor_job",
        [_call("jobs.get_job", {"job_id": "$.input.job_id"}, step_id="job")],
        properties={"job_id": {"type": "string"}},
        required=["job_id"],
    )
    quality = _quality(
        "monitor_job",
        action="monitor",
        resources=["job"],
        inputs={"job_id": _selector("job")},
    )

    report = analyze_capability_quality({"monitor_job": capability}, {"monitor_job": quality})

    assert report.diagnostics == ()
    assert report.graph.entrypoints == ("monitor_job",)


def test_compare_two_same_resource_ids_is_valid_with_explicit_justification() -> None:
    capability = _capability(
        "compare_orders",
        [
            _call("erp.get_order", {"order_id": "$.input.left_id"}, step_id="left"),
            _call("erp.get_order", {"order_id": "$.input.right_id"}, step_id="right"),
        ],
        properties={
            "left_id": {"type": "string"},
            "right_id": {"type": "string"},
        },
        required=["left_id", "right_id"],
    )
    quality = _quality(
        "compare_orders",
        action="compare",
        resources=["order"],
        inputs={
            "left_id": _selector("order"),
            "right_id": _selector("order"),
        },
        justification="Compare two caller-selected orders.",
    )

    report = analyze_capability_quality({"compare_orders": capability}, {"compare_orders": quality})

    assert report.diagnostics == ()
    assert report.composition_components == {"compare_orders": 2}


def test_list_with_mandatory_independent_detail_has_no_empty_success_path() -> None:
    capability = _capability(
        "list_and_get_invoice",
        [
            _call("finance.list_invoices", {}, step_id="listed"),
            _call(
                "finance.get_invoice",
                {"invoice_id": "$.input.invoice_id"},
                step_id="detail",
            ),
        ],
        properties={"invoice_id": {"type": "string"}},
        required=["invoice_id"],
    )
    quality = _quality(
        "list_and_get_invoice",
        action="list",
        resources=["invoice"],
        inputs={"invoice_id": _selector("invoice")},
    )

    report = analyze_capability_quality(
        {"list_and_get_invoice": capability}, {"list_and_get_invoice": quality}
    )

    assert {item.code for item in report.diagnostics} == {
        "ACC_CAPABILITY_EMPTY_SUCCESS_PATH_MISSING",
        "ACC_CAPABILITY_INDEPENDENT_CALL_FANIN",
        "ACC_CAPABILITY_LIST_DETAIL_COUPLED",
    }


def test_branching_detail_call_retains_an_empty_list_success_path() -> None:
    capability = _capability(
        "list_and_optionally_get_invoice",
        [
            _call("finance.list_invoices", {}, step_id="listed"),
            {
                "branch": {
                    "condition": "$.steps.listed",
                    "then": [
                        _call(
                            "finance.get_invoice",
                            {"invoice_id": "$.input.invoice_id"},
                            step_id="detail",
                        )
                    ],
                    "else": [{"emit": {"value": {}}}],
                }
            },
        ],
        properties={"invoice_id": {"type": "string"}},
        required=["invoice_id"],
    )
    quality = _quality(
        "list_and_optionally_get_invoice",
        action="list",
        resources=["invoice"],
        inputs={"invoice_id": _selector("invoice")},
    )

    report = analyze_capability_quality(
        {"list_and_optionally_get_invoice": capability},
        {"list_and_optionally_get_invoice": quality},
    )

    assert "ACC_CAPABILITY_EMPTY_SUCCESS_PATH_MISSING" not in {
        item.code for item in report.diagnostics
    }
