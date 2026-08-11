from __future__ import annotations

import hashlib
from dataclasses import replace
from types import MappingProxyType
from typing import Any, cast

from acc_core.interactions.expressions import PresentExpression
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage import (
    DomainUsageContract,
    UsageActionLifecycle,
    UsageBusinessGoal,
    UsageConditionRef,
    UsageDefaultRef,
    UsageErrorBranch,
    UsageOptionItem,
    UsageOptionSourceRef,
    UsageRelatedDataRef,
    UsageResultConsumption,
    UsageStepBinding,
    UsageToolRoute,
    UsageToolStep,
)
from acc_core.usage.acceptance import McpReleaseAcceptanceVerification
from acc_core.usage.analyze import UsageAnalysisReport, analyze_usage_contract
from acc_core.usage.project import UsageProjectReport


def _object_schema(
    properties: dict[str, Any] | None = None,
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties or {},
        "required": required or [],
    }


def _interaction_envelope(capability_ids: list[str]) -> tuple[dict[str, Any], str]:
    payload = {
        "schema_version": "2",
        "inventory": {"status": "declared"},
        "contracts": {capability_id: {} for capability_id in capability_ids},
        "dependencies": [],
    }
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return {**payload, "digest": digest}, digest


def _tool(name: str, input_schema: dict[str, Any], output_schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "inputSchema": input_schema,
        "outputSchema": _object_schema({"result": output_schema}, required=["result"]),
    }


def _read_contract(*, binding_pointer: str = "/items/0/id") -> DomainUsageContract:
    search = UsageToolStep.model_construct(
        id="search",
        capability_id="crm.search",
        tool_name="crm.search",
        depends_on_step_ids=[],
        binding_ids=[],
        condition=None,
        retry="safe",
        action_phase=None,
    )
    detail = UsageToolStep.model_construct(
        id="detail",
        capability_id="crm.detail",
        tool_name="crm.detail",
        depends_on_step_ids=["search"],
        binding_ids=["customer-id"],
        condition=None,
        retry="safe",
        action_phase=None,
    )
    route = UsageToolRoute.model_construct(
        id="search-detail",
        business_goal_id="inspect-customer",
        preconditions=[],
        steps=[search, detail],
        error_branch_ids=["http-errors"],
        result_step_id="detail",
        result_pointer="/customer",
        action_lifecycle_id=None,
    )
    binding = UsageStepBinding.model_construct(
        id="customer-id",
        source_kind="prior_step_output",
        source_step_id="search",
        consumer_step_id="detail",
        source_pointer=binding_pointer,
        target_pointer="/customer_id",
        mapping=None,
        value_kind="public_value",
    )
    branch = UsageErrorBranch.model_construct(
        id="http-errors",
        outcomes=["forbidden", "not_found", "timeout", "unauthorized"],
        behavior="stop",
        description="Stop on source authorization, lookup, or timeout failures.",
        step_ids=["detail", "search"],
        retry_policy="never",
        evidence_claim_ids=["claim-errors"],
    )
    return DomainUsageContract.model_construct(
        schema_version="2",
        domain_id="crm",
        pack_digest="sha256:" + "a" * 64,
        ir_digest="sha256:" + "b" * 64,
        tool_schema_digest="sha256:" + "c" * 64,
        test_report_digest="sha256:" + "d" * 64,
        source_snapshot_digest="sha256:" + "e" * 64,
        business_goals=[
            UsageBusinessGoal.model_construct(
                id="inspect-customer", description="Inspect one customer.", evidence_claim_ids=[]
            )
        ],
        tool_routes=[route],
        input_bindings=[binding],
        defaults=[],
        conditions=[],
        option_sources=[],
        related_data=[],
        result_consumption=[],
        error_handling=[branch],
        action_lifecycles=[],
        prohibited_behaviors=["Do not infer authorization."],
        required_scenario_ids=["crm-happy"],
        evidence_claims=[],
    )


def _read_release(
    contract: DomainUsageContract,
) -> tuple[UsageProjectReport, McpReleaseAcceptanceVerification]:
    identifier = _object_schema({"id": {"type": "string"}}, required=["id"])
    search_output = _object_schema(
        {
            "items": {
                "type": "array",
                "minItems": 1,
                "items": identifier,
            }
        },
        required=["items"],
    )
    detail_input = _object_schema({"customer_id": {"type": "string"}}, required=["customer_id"])
    detail_output = _object_schema({"customer": identifier}, required=["customer"])
    interactions, digest = _interaction_envelope(["crm.detail", "crm.search"])
    ir = {
        "ir_version": "2",
        "interaction_sha256": digest,
        "interactions": interactions,
        "capabilities": {
            "crm.detail": {
                "definition": {
                    "kind": "read",
                    "input_schema": detail_input,
                    "output_schema": detail_output,
                }
            },
            "crm.search": {
                "definition": {
                    "kind": "read",
                    "input_schema": _object_schema(),
                    "output_schema": search_output,
                }
            },
        },
    }
    tools = {
        "tools": [
            _tool("crm.detail", detail_input, detail_output),
            _tool("crm.search", _object_schema(), search_output),
        ]
    }
    report = UsageProjectReport(
        root=None,  # type: ignore[arg-type]
        project=None,
        acceptance=None,
        source_snapshot=None,
        domain_index=None,
        domain_contracts=MappingProxyType({"crm": contract}),
        scenarios=MappingProxyType({}),
        decisions=MappingProxyType({}),
        releases=MappingProxyType({}),
        evidence_registry=MappingProxyType({}),
        diagnostics=(),
    )
    verified = McpReleaseAcceptanceVerification(
        ok=True,
        code="ACC_USAGE_ACCEPTANCE_VERIFIED",
        message="verified",
        runtime_attested=True,
        accepted_domain_ids=("crm",),
        compiled_ir=MappingProxyType(ir),
        tool_snapshot=MappingProxyType(tools),
    )
    return report, verified


def _codes(result: Any) -> set[str]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def test_analyzer_proves_exact_cross_tool_route_and_interaction_digest() -> None:
    report, verified = _read_release(_read_contract())

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert result.ok
    assert not verified.trusted
    assert not result.trusted
    assert result.capability_ids == ("crm.detail", "crm.search")
    assert result.tool_names == ("crm.detail", "crm.search")


def test_caller_authored_analysis_report_is_not_trusted() -> None:
    assert not UsageAnalysisReport(domain_id="crm", diagnostics=()).trusted


def test_analyzer_rejects_unguaranteed_array_binding() -> None:
    contract = _read_contract()
    report, verified = _read_release(contract)
    ir = dict(verified.compiled_ir or {})
    capabilities = dict(ir["capabilities"])
    search = dict(capabilities["crm.search"])
    definition = dict(search["definition"])
    output_schema = dict(definition["output_schema"])
    items = dict(output_schema["properties"]["items"])
    items.pop("minItems")
    output_schema["properties"] = {"items": items}
    definition["output_schema"] = output_schema
    search["definition"] = definition
    capabilities["crm.search"] = search
    ir["capabilities"] = capabilities
    verified = replace(verified, compiled_ir=MappingProxyType(ir))

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert "ACC_USAGE_BINDING_SOURCE_NOT_GUARANTEED" in _codes(result)


def test_analyzer_rejects_schema_conflict_and_missing_required_constructability() -> None:
    contract = _read_contract().model_copy(
        update={
            "input_bindings": [],
            "tool_routes": [
                _read_contract()
                .tool_routes[0]
                .model_copy(
                    update={
                        "steps": [
                            _read_contract().tool_routes[0].steps[0],
                            _read_contract()
                            .tool_routes[0]
                            .steps[1]
                            .model_copy(update={"binding_ids": []}),
                        ]
                    }
                )
            ],
        }
    )
    report, verified = _read_release(contract)

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert "ACC_USAGE_REQUIRED_INPUT_UNCONSTRUCTABLE" in _codes(result)


def test_analyzer_rejects_incompatible_producer_and_consumer_schemas() -> None:
    report, verified = _read_release(_read_contract())
    ir = dict(verified.compiled_ir or {})
    capabilities = dict(ir["capabilities"])
    search = dict(capabilities["crm.search"])
    definition = dict(search["definition"])
    output_schema = dict(definition["output_schema"])
    items = dict(output_schema["properties"]["items"])
    item_schema = dict(items["items"])
    item_schema["properties"] = {"id": {"type": "integer"}}
    items["items"] = item_schema
    output_schema["properties"] = {"items": items}
    definition["output_schema"] = output_schema
    search["definition"] = definition
    capabilities["crm.search"] = search
    ir["capabilities"] = capabilities
    verified = replace(verified, compiled_ir=MappingProxyType(ir))

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert "ACC_USAGE_BINDING_SCHEMA_UNPROVEN" in _codes(result)


def test_analyzer_requires_normalized_http_failure_branches_and_empty_stop() -> None:
    contract = _read_contract().model_copy(update={"error_handling": []})
    contract = contract.model_copy(
        update={
            "tool_routes": [contract.tool_routes[0].model_copy(update={"error_branch_ids": []})],
            "option_sources": [
                UsageOptionSourceRef.model_construct(
                    id="customers",
                    capability_id="crm.detail",
                    consumer_step_id="detail",
                    target_pointer="/customer_id",
                    source="producer_step",
                    producer_step_id="search",
                    static_items=[],
                    items_pointer="/items",
                    value_pointer="/id",
                    label_pointer="/name",
                    search="supported",
                    paging="supported",
                    empty_behavior="stop",
                    error_behavior="stop",
                    evidence_claim_ids=[],
                )
            ],
        }
    )
    report, verified = _read_release(contract)

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert {
        "ACC_USAGE_ERROR_BRANCH_MISSING",
        "ACC_USAGE_EMPTY_STOP_UNHANDLED",
    } <= _codes(result)


def test_analyzer_rejects_interaction_digest_and_ambiguous_tool_selection() -> None:
    report, verified = _read_release(_read_contract())
    ir = dict(verified.compiled_ir or {})
    ir["interaction_sha256"] = "0" * 64
    tools = dict(verified.tool_snapshot or {})
    tools["tools"] = [*tools["tools"], tools["tools"][0]]
    verified = replace(
        verified,
        compiled_ir=MappingProxyType(ir),
        tool_snapshot=MappingProxyType(tools),
    )

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert {
        "ACC_USAGE_INTERACTION_DIGEST_INVALID",
        "ACC_USAGE_TOOL_SELECTION_AMBIGUOUS",
    } <= _codes(result)


def test_analyzer_rejects_public_handle_binding() -> None:
    contract = _read_contract()
    binding = contract.input_bindings[0].model_copy(
        update={
            "source_kind": "public_input",
            "source_step_id": None,
            "value_kind": "action_handle",
        }
    )
    contract = contract.model_copy(update={"input_bindings": [binding]})
    report, verified = _read_release(contract)

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert "ACC_USAGE_TRUST_BOUNDARY_INVALID" in _codes(result)


def test_analyzer_requires_compiler_action_proof_and_complete_lifecycle() -> None:
    prepare = UsageToolStep.model_construct(
        id="prepare",
        capability_id="orders.create",
        tool_name="orders.create.prepare",
        depends_on_step_ids=[],
        binding_ids=[],
        condition=None,
        retry="never",
        action_phase="prepare",
    )
    commit = UsageToolStep.model_construct(
        id="commit",
        capability_id="orders.create",
        tool_name="acc_action_commit",
        depends_on_step_ids=["prepare"],
        binding_ids=[],
        condition=None,
        retry="never",
        action_phase="commit",
    )
    status = UsageToolStep.model_construct(
        id="status",
        capability_id="orders.create",
        tool_name="acc_action_status",
        depends_on_step_ids=["prepare"],
        binding_ids=[],
        condition=None,
        retry="status_only",
        action_phase="status",
    )
    lifecycle = UsageActionLifecycle.model_construct(
        id="create-order",
        action_id="orders.create",
        prepare_step_id="prepare",
        approve_action_handle_binding_id=None,
        commit_action_handle_binding_id="commit-handle",
        status_action_handle_binding_id="status-handle",
        approval="conditional",
        approval_condition=cast(Any, {"op": "eq"}),
        approve_step_id=None,
        approval_handle_binding_id=None,
        commit_step_id="commit",
        status_step_id="status",
        outcome_unknown_behavior="query_status",
    )
    route = UsageToolRoute.model_construct(
        id="create",
        business_goal_id="create-order",
        preconditions=[],
        steps=[commit, prepare, status],
        error_branch_ids=[],
        result_step_id="status",
        result_pointer="/result",
        action_lifecycle_id="create-order",
    )
    contract = _read_contract().model_copy(
        update={
            "business_goals": [
                UsageBusinessGoal.model_construct(
                    id="create-order", description="Create.", evidence_claim_ids=[]
                )
            ],
            "tool_routes": [route],
            "input_bindings": [],
            "error_handling": [],
            "action_lifecycles": [lifecycle],
        }
    )
    report, verified = _read_release(contract)
    ir = dict(verified.compiled_ir or {})
    interactions, digest = _interaction_envelope(["orders.create"])
    action_input = _object_schema()
    ir.update(
        interaction_sha256=digest,
        interactions=interactions,
        capabilities={
            "orders.create": {
                "definition": {
                    "kind": "action",
                    "input_schema": action_input,
                    "output_schema": _object_schema(),
                },
            }
        },
    )
    action_tools = {
        "tools": [
            _tool("orders.create.prepare", action_input, _object_schema()),
            _tool(
                "acc_action_commit",
                _object_schema({"action_handle": {"type": "string"}}, required=["action_handle"]),
                _object_schema(),
            ),
            _tool(
                "acc_action_status",
                _object_schema({"action_handle": {"type": "string"}}, required=["action_handle"]),
                _object_schema(),
            ),
        ]
    }
    action_tools["tools"][2]["inputSchema"]["additionalProperties"] = True
    verified = replace(
        verified,
        compiled_ir=MappingProxyType(ir),
        tool_snapshot=MappingProxyType(action_tools),
    )

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert {
        "ACC_USAGE_ACTION_PROOF_MISSING",
        "ACC_USAGE_ACTION_APPROVAL_PHASE_INVALID",
        "ACC_USAGE_ACTION_TOOL_SCHEMA_INVALID",
        "ACC_USAGE_OUTCOME_UNKNOWN_UNHANDLED",
    } <= _codes(result)


def test_analyzer_fails_closed_with_secret_safe_diagnostics() -> None:
    report, verified = _read_release(_read_contract())
    result = analyze_usage_contract(report, verified, domain_id="missing-bearer-secret-token")

    assert not result.ok
    rendered = " ".join(item.message for item in result.diagnostics).lower()
    assert "bearer" not in rendered
    assert "secret-token" not in rendered


def test_analyzer_proves_typed_defaults_options_related_results_and_conditions() -> None:
    contract = _read_contract()
    contract = contract.model_copy(
        update={
            "defaults": [
                UsageDefaultRef.model_construct(
                    id="page-size",
                    capability_id="crm.search",
                    step_id="search",
                    target_pointer="/page_size",
                    source="literal",
                    value=20,
                    reference_binding_id=None,
                    precedence=1,
                    submission="when_missing",
                    evidence_claim_ids=[],
                )
            ],
            "option_sources": [
                UsageOptionSourceRef.model_construct(
                    id="customers",
                    capability_id="crm.detail",
                    consumer_step_id="detail",
                    target_pointer="/customer_id",
                    source="producer_step",
                    producer_step_id="search",
                    static_items=[],
                    items_pointer="/items",
                    value_pointer="/id",
                    label_pointer="/name",
                    search="supported",
                    paging="supported",
                    empty_behavior="return_empty",
                    error_behavior="stop",
                    evidence_claim_ids=[],
                )
            ],
            "related_data": [
                UsageRelatedDataRef.model_construct(
                    id="selected-customer",
                    producer_step_id="search",
                    producer_pointer="/items/0/id",
                    consumer_step_id="detail",
                    target_pointer="/customer_id",
                    cardinality="one",
                    consistency="current",
                    evidence_claim_ids=[],
                )
            ],
            "result_consumption": [
                UsageResultConsumption.model_construct(
                    id="return-customer",
                    capability_id="crm.detail",
                    step_id="detail",
                    kind="return",
                    field_pointers=["/customer"],
                    order=1,
                    evidence_claim_ids=[],
                )
            ],
            "conditions": [
                UsageConditionRef.model_construct(
                    id="has-customer",
                    kind="execute",
                    scope="step",
                    route_id="search-detail",
                    step_id="detail",
                    target_pointer="/customer_id",
                    expression=PresentExpression.model_validate(
                        {
                            "operator": "present",
                            "operand": {"kind": "reference", "pointer": "/items/0/id"},
                        }
                    ),
                    evidence_claim_ids=[],
                )
            ],
        }
    )
    report, verified = _read_release(contract)
    ir = dict(verified.compiled_ir or {})
    capabilities = dict(ir["capabilities"])
    search = dict(capabilities["crm.search"])
    definition = dict(search["definition"])
    definition["input_schema"] = _object_schema(
        {
            "page_size": {"type": "integer", "minimum": 1},
            "query": {"type": "string"},
            "page": {"type": "integer"},
        }
    )
    output = dict(definition["output_schema"])
    items = dict(output["properties"]["items"])
    item = dict(items["items"])
    item["properties"] = {"id": {"type": "string"}, "name": {"type": "string"}}
    item["required"] = ["id", "name"]
    items["items"] = item
    output["properties"] = {"items": items}
    definition["output_schema"] = output
    search["definition"] = definition
    capabilities["crm.search"] = search
    ir["capabilities"] = capabilities
    tools = dict(verified.tool_snapshot or {})
    tools["tools"] = [
        tools["tools"][0],
        _tool("crm.search", definition["input_schema"], definition["output_schema"]),
    ]
    verified = replace(
        verified,
        compiled_ir=MappingProxyType(ir),
        tool_snapshot=MappingProxyType(tools),
    )

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert result.ok, result.diagnostics


def test_analyzer_rejects_unproven_typed_usage_semantics() -> None:
    contract = _read_contract().model_copy(
        update={
            "defaults": [
                UsageDefaultRef.model_construct(
                    id="bad-default",
                    capability_id="crm.detail",
                    step_id="detail",
                    target_pointer="/missing",
                    source="source_default",
                    value=None,
                    reference_binding_id=None,
                    precedence=1,
                    submission="when_missing",
                    evidence_claim_ids=[],
                )
            ],
            "related_data": [
                UsageRelatedDataRef.model_construct(
                    id="bad-related",
                    producer_step_id="search",
                    producer_pointer="/optional/id",
                    consumer_step_id="detail",
                    target_pointer="/customer_id",
                    cardinality="many",
                    consistency="current",
                    evidence_claim_ids=[],
                )
            ],
            "result_consumption": [
                UsageResultConsumption.model_construct(
                    id="bad-result",
                    capability_id="crm.detail",
                    step_id="detail",
                    kind="return",
                    field_pointers=["/internal/secret"],
                    order=1,
                    evidence_claim_ids=[],
                )
            ],
        }
    )
    report, verified = _read_release(contract)

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert {
        "ACC_USAGE_DEFAULT_TARGET_INVALID",
        "ACC_USAGE_RELATED_SOURCE_UNPROVEN",
        "ACC_USAGE_RESULT_POINTER_INVALID",
    } <= _codes(result)


def test_analyzer_rejects_unproven_option_values_controls_and_condition_scope() -> None:
    condition = UsageConditionRef.model_construct(
        id="future-value",
        kind="execute",
        scope="step",
        route_id="search-detail",
        step_id="detail",
        target_pointer="/customer_id",
        expression=PresentExpression.model_validate(
            {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/future/value"},
            }
        ),
        evidence_claim_ids=[],
    )
    option = UsageOptionSourceRef.model_construct(
        id="customers",
        capability_id="crm.detail",
        consumer_step_id="detail",
        target_pointer="/customer_id",
        source="producer_step",
        producer_step_id="search",
        static_items=[],
        items_pointer="/items",
        value_pointer="/id",
        label_pointer="/name",
        search="required",
        paging="required",
        empty_behavior="return_empty",
        error_behavior="stop",
        evidence_claim_ids=[],
    )
    contract = _read_contract().model_copy(
        update={"conditions": [condition], "option_sources": [option]}
    )
    report, verified = _read_release(contract)
    ir = dict(verified.compiled_ir or {})
    capabilities = dict(ir["capabilities"])
    search = dict(capabilities["crm.search"])
    definition = dict(search["definition"])
    output = dict(definition["output_schema"])
    items = dict(output["properties"]["items"])
    item = dict(items["items"])
    item["properties"] = {"id": {"type": "integer"}, "name": {"type": "string"}}
    item["required"] = ["id", "name"]
    items["items"] = item
    output["properties"] = {"items": items}
    definition["output_schema"] = output
    search["definition"] = definition
    capabilities["crm.search"] = search
    ir["capabilities"] = capabilities
    verified = replace(verified, compiled_ir=MappingProxyType(ir))

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert {
        "ACC_USAGE_OPTION_VALUE_SCHEMA_UNPROVEN",
        "ACC_USAGE_OPTION_CONTROL_UNCONSTRUCTABLE",
        "ACC_USAGE_CONDITION_REFERENCE_UNAVAILABLE",
    } <= _codes(result)


def test_analyzer_rejects_static_option_value_and_unattested_source_default() -> None:
    option = UsageOptionSourceRef.model_construct(
        id="static-customer",
        capability_id="crm.detail",
        consumer_step_id="detail",
        target_pointer="/customer_id",
        source="static",
        producer_step_id=None,
        static_items=[UsageOptionItem.model_construct(value=42, label="Invalid")],
        items_pointer=None,
        value_pointer=None,
        label_pointer=None,
        search="unsupported",
        paging="unsupported",
        empty_behavior="return_empty",
        error_behavior="stop",
        evidence_claim_ids=[],
    )
    default = UsageDefaultRef.model_construct(
        id="source-customer",
        capability_id="crm.detail",
        step_id="detail",
        target_pointer="/customer_id",
        source="source_default",
        reference_binding_id=None,
        precedence=1,
        submission="when_missing",
        evidence_claim_ids=[],
    )
    contract = _read_contract().model_copy(
        update={"defaults": [default], "option_sources": [option]}
    )
    report, verified = _read_release(contract)

    result = analyze_usage_contract(report, verified, domain_id="crm")

    assert {
        "ACC_USAGE_OPTION_STATIC_VALUE_INVALID",
        "ACC_USAGE_SOURCE_DEFAULT_UNPROVEN",
    } <= _codes(result)
