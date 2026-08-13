from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from acc_core.interactions import (
    ActionLifecycleBinding,
    ActionLifecyclePhaseBinding,
    CapabilityInteractionContract,
    InputBinding,
    InteractionCondition,
    InteractionDefault,
    OptionSource,
    RelatedDataBinding,
    ResultConsumption,
    UIInteraction,
    UIInteractionInventory,
)
from acc_core.interactions.validate import analyze_interaction_fidelity
from acc_core.models import (
    ActionCapabilityV2,
    Policy,
    Project,
    ReadCapabilityV2,
    ReadOperationV2,
)
from acc_core.scope import ScopeInventory


def _evidence(source_id: str = "customer-page") -> dict[str, object]:
    return {
        "source_id": source_id,
        "kind": "source_file",
        "path": "frontend/customers.ts",
        "line_start": 1,
        "line_end": 80,
        "digest": "sha256:" + "c" * 64,
    }


def _project() -> Project:
    return Project.model_validate(
        {
            "schema_version": "2",
            "project": {"id": "crm", "version": "2.0.0"},
            "source_workspace": {"path": "/srv/crm", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
            "quality": {"profile": "standard"},
        }
    )


def _operation(
    operation_id: str = "crm.get_customer",
    *,
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
) -> ReadOperationV2:
    return ReadOperationV2.model_validate(
        {
            "schema_version": "2",
            "kind": "read",
            "id": operation_id,
            "title": operation_id,
            "input_schema": input_schema
            or {
                "type": "object",
                "additionalProperties": False,
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            },
            "output_schema": output_schema
            or {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["id", "name"],
            },
            "http": {
                "method": "GET",
                "path": "/api/customers/{customer_id}",
                "path_parameters": {"customer_id": "customer_id"},
                "query_parameters": {},
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": ["customer.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 65_536,
                "safety": {
                    "effect": "read",
                    "risk": "low",
                    "reversibility": "reversible",
                    "retry": {"mode": "never"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "context_bindings": {},
            "evidence": [_evidence("crm-route")],
        }
    )


def _capability(
    capability_id: str = "get_customer",
    *,
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
) -> ReadCapabilityV2:
    return ReadCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "read",
            "id": capability_id,
            "title": capability_id,
            "description": "Get one customer.",
            "input_schema": input_schema
            or {
                "type": "object",
                "additionalProperties": False,
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            },
            "output_schema": output_schema
            or {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["id", "name"],
            },
            "workflow": [
                {
                    "id": "customer",
                    "call": {
                        "operation": "crm.get_customer",
                        "arguments": {"customer_id": "$.input.customer_id"},
                    },
                },
                {"emit": {"value": "$.steps.customer"}},
            ],
            "policy": "customer-read",
            "evals": ["get-customer-positive"],
        }
    )


def _policy(*, scopes: list[str] | None = None) -> Policy:
    return Policy.model_validate(
        {
            "schema_version": "2",
            "id": "customer-read",
            "required_scopes": scopes if scopes is not None else ["customer.read"],
            "tenant_mode": "none",
            "readable_fields": ["id", "name"],
            "denied_fields": [],
            "redaction_rules": [],
        }
    )


def _scope_inventory() -> ScopeInventory:
    return ScopeInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": ["crm"]},
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": [
                {
                    "id": "GET /api/customers/{customer_id}",
                    "domain": "crm",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/api/customers/{customer_id}",
                    "evidence_sources": ["crm-route"],
                    "usage_evidence_sources": ["customer-page"],
                    "interaction_ids": ["customers.select"],
                    "eligibility": "eligible",
                    "disposition": "planned",
                    "operation_id": "crm.get_customer",
                    "capability_ids": ["get_customer"],
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
    )


def _input_binding(
    binding_id: str = "customer-id",
    target_pointer: str = "/customer_id",
    *,
    source_kind: str = "selected_record",
) -> InputBinding:
    return InputBinding.model_validate(
        {
            "id": binding_id,
            "source_kind": source_kind,
            "source_id": "customer-table",
            "source_pointer": "/id",
            "target_pointer": target_pointer,
            "cardinality": "one",
            "mapping": {"kind": "identity"},
            "evidence": _evidence(),
        }
    )


def _inventory() -> UIInteractionInventory:
    return UIInteractionInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "complete", "evidence_sources": ["customer-page"]},
            "surfaces": [
                {
                    "id": "customers",
                    "kind": "page",
                    "route_or_entry": "/customers",
                    "usage_context": "customer-selection-page",
                    "business_purpose": "Manage customers",
                    "evidence_sources": ["customer-page"],
                    "entry_evidence": _evidence(),
                }
            ],
            "interactions": [
                {
                    "id": "customers.select",
                    "surface_id": "customers",
                    "business_intent": "Select and inspect one customer",
                    "trigger": {"kind": "select", "source_pointer": "/customer_id"},
                    "route_ids": ["GET /api/customers/{customer_id}"],
                    "call_order": "sequential",
                    "input_bindings": [
                        _input_binding().model_dump(mode="json", exclude_unset=True)
                    ],
                    "defaults": [],
                    "option_sources": [],
                    "conditions": [],
                    "related_data": [],
                    "result_consumption": [],
                    "states": [],
                    "dimension_dispositions": [
                        {
                            "dimension": dimension,
                            "applicability": (
                                "applicable" if dimension == "input_bindings" else "not_applicable"
                            ),
                            "rationale": f"Selection context disposition for {dimension}.",
                            "evidence": _evidence(),
                        }
                        for dimension in (
                            "conditions",
                            "defaults",
                            "input_bindings",
                            "option_sources",
                            "related_data",
                            "result_consumption",
                            "states",
                        )
                    ],
                    "evidence_claims": [
                        {
                            "target_pointer": "/interactions/0",
                            "evidence": _evidence(),
                            "evidence_pointer": "/customer/select",
                            "authority": "implementation",
                        }
                    ],
                    "unknowns": [],
                }
            ],
            "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
        }
    )


def _result_consumption(source_pointer: str = "/id") -> ResultConsumption:
    return ResultConsumption.model_validate(
        {
            "id": "customer-detail",
            "role": "detail",
            "source_pointer": source_pointer,
            "field_pointers": [],
            "ordering": "none",
            "pagination": "none",
            "state_ids": [],
            "evidence": _evidence(),
        }
    )


def _contract() -> CapabilityInteractionContract:
    return CapabilityInteractionContract.model_validate(
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "interaction_ids": ["customers.select"],
            "public_input_bindings": [_input_binding().model_dump(mode="json", exclude_unset=True)],
            "trusted_input_bindings": [],
            "defaults": [],
            "option_sources": [],
            "conditions": [],
            "related_data": [],
            "result_consumption": [_result_consumption().model_dump(mode="json")],
            "required_scenarios": ["customer-selected"],
            "overrides": [],
            "omissions": [],
        }
    )


def _valid_documents() -> dict[str, Any]:
    return {
        "project": _project(),
        "scope_inventory": _scope_inventory(),
        "ui_inventory": _inventory(),
        "contracts": {"get_customer": _contract()},
        "capabilities": {"get_customer": _capability()},
        "operations": {"crm.get_customer": _operation()},
        "policies": {"customer-read": _policy()},
    }


def _replace_interaction(
    documents: dict[str, Any], mutate: Callable[[UIInteraction], UIInteraction]
) -> None:
    inventory = documents["ui_inventory"]
    interaction = mutate(inventory.interactions[0])
    documents["ui_inventory"] = inventory.model_copy(update={"interactions": [interaction]})


def _unknown_route(documents: dict[str, Any]) -> dict[str, Any]:
    _replace_interaction(
        documents,
        lambda interaction: interaction.model_copy(update={"route_ids": ["GET /missing"]}),
    )
    return documents


def _missing_evidence(documents: dict[str, Any]) -> dict[str, Any]:
    _replace_interaction(
        documents,
        lambda interaction: interaction.model_copy(update={"evidence_claims": []}),
    )
    return documents


def _invalid_default(documents: dict[str, Any]) -> dict[str, Any]:
    invalid = InteractionDefault.model_validate(
        {
            "id": "customer-default",
            "target_pointer": "/customer_id",
            "source_kind": "literal",
            "value": 7,
            "authority": "observation",
            "precedence": "caller_over_default",
            "submission": "send",
            "override_policy": "caller_allowed",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {"get_customer": contract.model_copy(update={"defaults": [invalid]})}
    return documents


def _bad_option_pointer(documents: dict[str, Any]) -> dict[str, Any]:
    option = OptionSource.model_validate(
        {
            "id": "customer-options",
            "target_pointer": "/customer_id",
            "source_kind": "operation",
            "producer_id": "crm.get_customer",
            "request_bindings": [],
            "items_pointer": "/missing",
            "value_pointer": "/id",
            "label_pointer": "/name",
            "cascade_dependencies": [],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "empty_options",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"option_sources": [option]})
    }
    return documents


def _bad_option_producer(documents: dict[str, Any]) -> dict[str, Any]:
    documents = _bad_option_pointer(documents)
    option = documents["contracts"]["get_customer"].option_sources[0]
    documents["contracts"] = {
        "get_customer": documents["contracts"]["get_customer"].model_copy(
            update={
                "option_sources": [
                    option.model_copy(
                        update={"producer_id": "crm.missing", "items_pointer": "/items"}
                    )
                ]
            }
        )
    }
    return documents


def _bad_option_binding(documents: dict[str, Any]) -> dict[str, Any]:
    documents = _bad_option_pointer(documents)
    option = documents["contracts"]["get_customer"].option_sources[0]
    request_binding = _input_binding("option-request", "/missing")
    documents["contracts"] = {
        "get_customer": documents["contracts"]["get_customer"].model_copy(
            update={
                "option_sources": [
                    option.model_copy(
                        update={
                            "items_pointer": None,
                            "request_bindings": [request_binding],
                        }
                    )
                ]
            }
        )
    }
    return documents


def _condition_cycle(documents: dict[str, Any]) -> dict[str, Any]:
    bindings = [_input_binding("a", "/a"), _input_binding("b", "/b")]
    conditions = [
        InteractionCondition.model_validate(
            {
                "id": "a-from-b",
                "target": "enabled",
                "target_pointer": "/a",
                "expression": {
                    "operator": "present",
                    "operand": {"kind": "reference", "pointer": "/b"},
                },
                "evidence": _evidence(),
            }
        ),
        InteractionCondition.model_validate(
            {
                "id": "b-from-a",
                "target": "enabled",
                "target_pointer": "/b",
                "expression": {
                    "operator": "present",
                    "operand": {"kind": "reference", "pointer": "/a"},
                },
                "evidence": _evidence(),
            }
        ),
    ]
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(
            update={"public_input_bindings": bindings, "conditions": conditions}
        )
    }
    return documents


def _broken_join(documents: dict[str, Any]) -> dict[str, Any]:
    related = RelatedDataBinding.model_validate(
        {
            "id": "broken-customer",
            "producer_kind": "operation",
            "producer_id": "crm.get_customer",
            "output_pointer": "/id",
            "target_pointer": "/customer_id",
            "cardinality": "one",
            "ordering": "none",
            "freshness": "request",
            "failure_isolation": "fail_fast",
            "evidence": _evidence(),
        }
    )
    integer_input = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"customer_id": {"type": "integer"}},
        "required": ["customer_id"],
    }
    documents["capabilities"] = {"get_customer": _capability(input_schema=integer_input)}
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"related_data": [related]})
    }
    return documents


def _hidden_permission(documents: dict[str, Any]) -> dict[str, Any]:
    trusted = _input_binding("is-admin", "/is_admin", source_kind="trusted_context")
    condition = InteractionCondition.model_validate(
        {
            "id": "admin-visible",
            "target": "visible",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/is_admin"},
            },
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(
            update={"trusted_input_bindings": [trusted], "conditions": [condition]}
        )
    }
    documents["policies"] = {"customer-read": _policy(scopes=[])}
    documents["operations"] = {
        "crm.get_customer": _operation().model_copy(
            update={
                "http": _operation().http.model_copy(update={"scopes": []}),
            }
        )
    }
    return documents


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (_unknown_route, "ACC_UI_INTERACTION_ROUTE_UNKNOWN"),
        (_missing_evidence, "ACC_UI_INTERACTION_EVIDENCE_MISSING"),
        (_invalid_default, "ACC_UI_DEFAULT_AUTHORITY_UNPROVEN"),
        (_bad_option_pointer, "ACC_UI_OPTION_SOURCE_UNTRACED"),
        (_bad_option_producer, "ACC_UI_OPTION_SOURCE_UNTRACED"),
        (_bad_option_binding, "ACC_UI_OPTION_SOURCE_UNTRACED"),
        (_condition_cycle, "ACC_UI_CONDITION_CYCLE"),
        (_broken_join, "ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN"),
        (_hidden_permission, "ACC_UI_HIDDEN_NOT_AUTHORIZATION"),
    ],
)
def test_interaction_fidelity_fails_closed(
    mutate: Callable[[dict[str, Any]], dict[str, Any]], code: str
) -> None:
    report = analyze_interaction_fidelity(**mutate(_valid_documents()))
    assert code in {item.code for item in report.diagnostics}


def test_valid_interaction_contract_is_deterministic_and_clean() -> None:
    report = analyze_interaction_fidelity(**_valid_documents())

    assert report.diagnostics == ()


def test_complete_legacy_wrapper_inventory_gets_stable_migration_diagnostics() -> None:
    documents = _valid_documents()
    inventory = documents["ui_inventory"]
    legacy_surface = inventory.surfaces[0].model_copy(
        update={"usage_context": None, "entry_evidence": None}
    )
    legacy_interaction = inventory.interactions[0].model_copy(update={"dimension_dispositions": []})
    documents["ui_inventory"] = inventory.model_copy(
        update={"surfaces": [legacy_surface], "interactions": [legacy_interaction]}
    )

    report = analyze_interaction_fidelity(**documents)

    assert {
        "ACC_UI_DIMENSION_DISPOSITION_REQUIRED",
        "ACC_UI_SURFACE_ENTRY_EVIDENCE_REQUIRED",
    } <= {diagnostic.code for diagnostic in report.diagnostics}
    assert report.interaction_ids == ("customers.select",)
    assert report.dependency_edges == ()


def test_dimension_disposition_evidence_must_close_through_interaction_and_surface() -> None:
    documents = _valid_documents()
    inventory = documents["ui_inventory"]
    interaction = inventory.interactions[0]
    orphan = interaction.dimension_dispositions[0].model_copy(
        update={
            "evidence": interaction.dimension_dispositions[0].evidence.model_copy(
                update={"source_id": "orphan-source"}
            )
        }
    )
    documents["ui_inventory"] = inventory.model_copy(
        update={
            "interactions": [
                interaction.model_copy(
                    update={
                        "dimension_dispositions": [
                            orphan,
                            *interaction.dimension_dispositions[1:],
                        ]
                    }
                )
            ]
        }
    )

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_DIMENSION_EVIDENCE_UNRESOLVED" in {
        diagnostic.code for diagnostic in report.diagnostics
    }


def test_condition_reference_and_type_must_match_capability_input_schema() -> None:
    documents = _valid_documents()
    condition = InteractionCondition.model_validate(
        {
            "id": "bad-type",
            "target": "enabled",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "in",
                "left": {"kind": "reference", "pointer": "/customer_id"},
                "right": {"kind": "literal", "value": 7},
            },
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"conditions": [condition]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_CONDITION_AUTHORITY_UNPROVEN" in {item.code for item in report.diagnostics}


def test_condition_in_accepts_scalar_against_local_ref_array_items() -> None:
    documents = _valid_documents()
    documents["capabilities"] = {
        "get_customer": _capability(
            input_schema={
                "type": "object",
                "properties": {
                    "customer_id": {"$ref": "#/$defs/id"},
                    "selected_ids": {"$ref": "#/$defs/id-list"},
                },
                "$defs": {
                    "id": {"type": "string"},
                    "id-list": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/id"},
                    },
                },
            }
        )
    }
    condition = InteractionCondition.model_validate(
        {
            "id": "selected-customer",
            "target": "enabled",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "in",
                "left": {"kind": "reference", "pointer": "/customer_id"},
                "right": {"kind": "reference", "pointer": "/selected_ids"},
            },
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"conditions": [condition]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_CONDITION_AUTHORITY_UNPROVEN" not in {item.code for item in report.diagnostics}


@pytest.mark.parametrize(
    "selected_schema",
    [
        {"type": "string"},
        {"$ref": "#/$defs/id-list", "maxItems": 1},
    ],
)
def test_condition_in_rejects_non_array_or_constraining_ref_sibling(
    selected_schema: dict[str, Any],
) -> None:
    documents = _valid_documents()
    documents["capabilities"] = {
        "get_customer": _capability(
            input_schema={
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string"},
                    "selected_ids": selected_schema,
                },
                "$defs": {"id-list": {"type": "array", "items": {"type": "string"}}},
            }
        )
    }
    condition = InteractionCondition.model_validate(
        {
            "id": "selected-customer",
            "target": "enabled",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "in",
                "left": {"kind": "reference", "pointer": "/customer_id"},
                "right": {"kind": "reference", "pointer": "/selected_ids"},
            },
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"conditions": [condition]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_CONDITION_AUTHORITY_UNPROVEN" in {item.code for item in report.diagnostics}


def test_presentation_pointer_must_exist_and_be_policy_visible() -> None:
    documents = _valid_documents()
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(
            update={"result_consumption": [_result_consumption("/secret")]}
        )
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_PRESENTATION_FIELD_UNPROVEN" in {item.code for item in report.diagnostics}


def test_complete_inventory_cannot_keep_unresolved_interactions() -> None:
    documents = _valid_documents()
    inventory = documents["ui_inventory"]
    unresolved = inventory.interactions[0].model_copy(update={"unknowns": ["dynamic rule"]})
    documents["ui_inventory"] = inventory.model_copy(
        update={
            "interactions": [unresolved],
            "summary": inventory.summary.model_copy(update={"unresolved": 1}),
        }
    )

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_SURFACE_COVERAGE_INCOMPLETE" in {item.code for item in report.diagnostics}


def test_related_data_semantic_view_target_is_not_treated_as_an_input_pointer() -> None:
    documents = _valid_documents()
    documents["capabilities"] = {
        "get_customer": _capability(
            output_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "view": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"customer_id": {"type": "string"}},
                        "required": ["customer_id"],
                    }
                },
                "required": ["view"],
            }
        )
    }
    related = RelatedDataBinding.model_validate(
        {
            "id": "customer-view",
            "producer_kind": "operation",
            "producer_id": "crm.get_customer",
            "output_pointer": "/id",
            "target_pointer": "/view/customer_id",
            "cardinality": "one",
            "ordering": "none",
            "freshness": "request",
            "failure_isolation": "fail_fast",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"related_data": [related]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN" not in {item.code for item in report.diagnostics}
    assert report.dependency_edges == (("crm.get_customer", "get_customer"),)


def test_related_data_unknown_semantic_view_is_not_silently_proven() -> None:
    documents = _valid_documents()
    related = RelatedDataBinding.model_validate(
        {
            "id": "unknown-view",
            "producer_kind": "operation",
            "producer_id": "crm.get_customer",
            "output_pointer": "/id",
            "target_pointer": "/view/customer_id",
            "cardinality": "one",
            "ordering": "none",
            "freshness": "request",
            "failure_isolation": "fail_fast",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"related_data": [related]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN" in {item.code for item in report.diagnostics}


def test_capability_related_data_requires_policy_visible_producer_output() -> None:
    documents = _valid_documents()
    producer = _capability(
        "get_owner",
        output_schema={
            "type": "object",
            "properties": {
                "owner": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                }
            },
        },
    )
    consumer = _capability(
        input_schema={
            "type": "object",
            "properties": {"owner_id": {"type": "string"}},
        }
    )
    documents["capabilities"] = {
        "get_customer": consumer,
        "get_owner": producer,
    }
    related = RelatedDataBinding.model_validate(
        {
            "id": "owner-view",
            "producer_kind": "capability",
            "producer_id": "get_owner",
            "output_pointer": "/owner/id",
            "target_pointer": "/owner_id",
            "cardinality": "one",
            "ordering": "none",
            "freshness": "request",
            "failure_isolation": "independent",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"related_data": [related]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN" in {item.code for item in report.diagnostics}


def test_state_entry_condition_must_be_in_public_capability_contract() -> None:
    documents = _valid_documents()
    inventory_document = documents["ui_inventory"].model_dump(
        mode="json", by_alias=True, exclude_unset=True
    )
    interaction = inventory_document["interactions"][0]
    interaction["conditions"] = [
        {
            "id": "internal-condition",
            "target": "visible",
            "target_pointer": "/customer_id",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/customer_id"},
            },
            "evidence": _evidence(),
        }
    ]
    interaction["states"] = [
        {
            "id": "ready",
            "kind": "ready",
            "entry_condition_id": "internal-condition",
            "allowed_next_events": ["refresh"],
            "evidence": _evidence(),
        }
    ]
    documents["ui_inventory"] = UIInteractionInventory.model_validate(inventory_document)

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_INTERACTION_STATE_CONDITION_UNPROVEN" in {
        item.code for item in report.diagnostics
    }


def test_state_requires_matching_authoritative_evidence_claim() -> None:
    documents = _valid_documents()
    inventory_document = documents["ui_inventory"].model_dump(
        mode="json", by_alias=True, exclude_unset=True
    )
    interaction = inventory_document["interactions"][0]
    interaction["states"] = [
        {
            "id": "ready",
            "kind": "ready",
            "allowed_next_events": ["refresh"],
            "evidence": {
                **_evidence(),
                "digest": "sha256:" + "d" * 64,
            },
        }
    ]
    documents["ui_inventory"] = UIInteractionInventory.model_validate(inventory_document)

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_INTERACTION_STATE_EVIDENCE_UNPROVEN" in {
        item.code for item in report.diagnostics
    }


def test_presentation_checks_composed_leaves_not_array_container() -> None:
    documents = _valid_documents()
    output_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                    },
                    "required": ["id", "name"],
                },
            }
        },
        "required": ["items"],
    }
    documents["capabilities"] = {"get_customer": _capability(output_schema=output_schema)}
    documents["policies"] = {
        "customer-read": _policy().model_copy(
            update={"readable_fields": ["items.id", "items.name"]}
        )
    }
    consumption = _result_consumption("/items").model_copy(
        update={"field_pointers": ["/id", "/name"]}
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"result_consumption": [consumption]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_PRESENTATION_FIELD_UNPROVEN" not in {item.code for item in report.diagnostics}


def test_local_defs_refs_and_array_items_are_schema_resolved() -> None:
    documents = _valid_documents()
    input_schema = {
        "$ref": "#/$defs/input",
        "$defs": {
            "input": {
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            }
        },
    }
    output_schema = {
        "$ref": "#/$defs/output",
        "$defs": {
            "output": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/customer"},
                    }
                },
                "required": ["items"],
            },
            "customer": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        },
    }
    documents["capabilities"] = {
        "get_customer": _capability(input_schema=input_schema, output_schema=output_schema)
    }
    documents["policies"] = {
        "customer-read": _policy().model_copy(update={"readable_fields": ["items.id"]})
    }
    consumption = _result_consumption("/items").model_copy(update={"field_pointers": ["/id"]})
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"result_consumption": [consumption]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert not {
        "ACC_UI_INPUT_SOURCE_UNRESOLVED",
        "ACC_UI_PRESENTATION_FIELD_UNPROVEN",
    } & {item.code for item in report.diagnostics}


def test_nested_local_ref_static_option_is_validated_from_schema_root() -> None:
    documents = _valid_documents()
    documents["capabilities"] = {
        "get_customer": _capability(
            input_schema={
                "type": "object",
                "properties": {
                    "customer_id": {
                        "type": "object",
                        "properties": {"id": {"$ref": "#/$defs/id"}},
                        "required": ["id"],
                    }
                },
                "$defs": {"id": {"type": "string"}},
            }
        )
    }
    option = OptionSource.model_validate(
        {
            "id": "static-customer",
            "target_pointer": "/customer_id",
            "source_kind": "static",
            "static_options": [{"value": {"id": "c-1"}, "label": "Customer 1"}],
            "request_bindings": [],
            "value_pointer": "/id",
            "label_pointer": "/id",
            "cascade_dependencies": [],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "empty_options",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"option_sources": [option]})
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_OPTION_SOURCE_UNTRACED" not in {item.code for item in report.diagnostics}


def test_route_ownership_and_capability_workflow_must_close_bidirectionally() -> None:
    documents = _valid_documents()
    route = (
        documents["scope_inventory"]
        .routes[0]
        .model_copy(
            update={"interaction_ids": [], "capability_ids": [], "operation_id": "crm.unrelated"}
        )
    )
    documents["scope_inventory"] = documents["scope_inventory"].model_copy(
        update={"routes": [route]}
    )

    report = analyze_interaction_fidelity(**documents)
    codes = {item.code for item in report.diagnostics}

    assert "ACC_UI_INTERACTION_ROUTE_OWNERSHIP_MISMATCH" in codes
    assert "ACC_UI_INTERACTION_ROUTE_CAPABILITY_MISMATCH" in codes


def test_inventory_and_surface_evidence_sources_must_close_to_claims() -> None:
    documents = _valid_documents()
    inventory = documents["ui_inventory"]
    documents["ui_inventory"] = inventory.model_copy(
        update={
            "scope": inventory.scope.model_copy(
                update={"evidence_sources": ["missing-scope-source"]}
            ),
            "surfaces": [
                inventory.surfaces[0].model_copy(
                    update={"evidence_sources": ["missing-surface-source"]}
                )
            ],
        }
    )

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_EVIDENCE_SOURCE_UNRESOLVED" in {item.code for item in report.diagnostics}


def test_evidence_claim_must_belong_to_the_current_interaction_subtree() -> None:
    documents = _valid_documents()
    _replace_interaction(
        documents,
        lambda interaction: interaction.model_copy(
            update={
                "evidence_claims": [
                    interaction.evidence_claims[0].model_copy(
                        update={"target_pointer": "/interactions/99"}
                    )
                ]
            }
        ),
    )

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_INTERACTION_EVIDENCE_MISSING" in {item.code for item in report.diagnostics}


def test_observation_claim_cannot_be_upgraded_to_authoritative_contract_fact() -> None:
    documents = _valid_documents()
    _replace_interaction(
        documents,
        lambda interaction: interaction.model_copy(
            update={
                "evidence_claims": [
                    interaction.evidence_claims[0].model_copy(update={"authority": "observation"})
                ]
            }
        ),
    )
    default = InteractionDefault.model_validate(
        {
            "id": "customer-default",
            "target_pointer": "/customer_id",
            "source_kind": "literal",
            "value": "customer-1",
            "authority": "implementation",
            "precedence": "caller_over_default",
            "submission": "send",
            "override_policy": "caller_allowed",
            "evidence": _evidence(),
        }
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {"get_customer": contract.model_copy(update={"defaults": [default]})}

    report = analyze_interaction_fidelity(**documents)
    codes = {item.code for item in report.diagnostics}

    assert "ACC_UI_INTERACTION_EVIDENCE_MISSING" in codes
    assert "ACC_UI_DEFAULT_AUTHORITY_UNPROVEN" in codes


def test_unrelated_operation_scope_cannot_authorize_hidden_ui() -> None:
    documents = _hidden_permission(_valid_documents())
    documents["operations"]["crm.unrelated"] = _operation("crm.unrelated")

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_HIDDEN_NOT_AUTHORIZATION" in {item.code for item in report.diagnostics}


def test_hidden_ui_authority_is_bound_to_the_trusted_binding_source_operation() -> None:
    documents = _hidden_permission(_valid_documents())
    contract = documents["contracts"]["get_customer"]
    trusted = contract.trusted_input_bindings[0].model_copy(
        update={"source_id": "crm.get_customer"}
    )
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"trusted_input_bindings": [trusted]})
    }
    documents["operations"] = {"crm.get_customer": _operation()}

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_HIDDEN_NOT_AUTHORIZATION" not in {item.code for item in report.diagnostics}


def _action_capability() -> ActionCapabilityV2:
    return ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "get_customer",
            "title": "Update customer",
            "description": "Preview and update one customer.",
            "input_schema": _capability().input_schema,
            "output_schema": _capability().output_schema,
            "action": {
                "execution_mode": "single",
                "approval": {"mode": "required"},
                "expires_in_seconds": 300,
            },
            "preview_workflow": [
                {
                    "id": "customer",
                    "call": {
                        "operation": "crm.get_customer",
                        "arguments": {"customer_id": "$.input.customer_id"},
                    },
                },
                {"emit": {"value": "$.steps.customer"}},
            ],
            "commit_workflow": [
                {
                    "id": "update",
                    "call": {
                        "operation": "crm.update_customer",
                        "arguments": {"customer_id": "$.prepared.input.customer_id"},
                    },
                },
                {"emit": {"value": "$.steps.update"}},
            ],
            "policy": "customer-read",
            "evals": ["update-customer-positive"],
        }
    )


def test_action_lifecycle_cannot_be_proven_by_scenario_name_suffixes() -> None:
    documents = _valid_documents()
    documents["capabilities"] = {"get_customer": _action_capability()}
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(
            update={
                "required_scenarios": [
                    "ui.approve",
                    "ui.commit",
                    "ui.prepare",
                    "ui.status",
                ]
            }
        )
    }

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" in {item.code for item in report.diagnostics}


def test_action_lifecycle_requires_typed_adopted_evidence() -> None:
    documents = _valid_documents()
    documents["capabilities"] = {"get_customer": _action_capability()}
    inventory = documents["ui_inventory"]
    root_claim = inventory.interactions[0].evidence_claims[0]
    phase_evidence = {
        phase: root_claim.evidence.model_copy(update={"source_id": f"lifecycle-{phase}"})
        for phase in ("approve", "commit", "prepare", "status")
    }
    phase_claims = [
        root_claim,
        *[
            root_claim.model_copy(
                update={
                    "target_pointer": f"/interactions/0/lifecycle/{phase}",
                    "evidence": phase_evidence[phase],
                }
            )
            for phase in ("approve", "commit", "prepare", "status")
        ],
    ]
    _replace_interaction(
        documents,
        lambda interaction: interaction.model_copy(update={"evidence_claims": phase_claims}),
    )
    source_ids = ["customer-page", *sorted(item.source_id for item in phase_evidence.values())]
    documents["ui_inventory"] = documents["ui_inventory"].model_copy(
        update={
            "scope": inventory.scope.model_copy(update={"evidence_sources": source_ids}),
            "surfaces": [inventory.surfaces[0].model_copy(update={"evidence_sources": source_ids})],
        }
    )
    lifecycle = ActionLifecycleBinding(
        interaction_id="customers.select",
        prepare=ActionLifecyclePhaseBinding(
            target_pointer="/interactions/0/lifecycle/prepare",
            evidence=phase_evidence["prepare"],
        ),
        approve=ActionLifecyclePhaseBinding(
            target_pointer="/interactions/0/lifecycle/approve",
            evidence=phase_evidence["approve"],
        ),
        commit=ActionLifecyclePhaseBinding(
            target_pointer="/interactions/0/lifecycle/commit",
            evidence=phase_evidence["commit"],
        ),
        status=ActionLifecyclePhaseBinding(
            target_pointer="/interactions/0/lifecycle/status",
            evidence=phase_evidence["status"],
        ),
    )
    contract = documents["contracts"]["get_customer"]
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"action_lifecycle": lifecycle})
    }
    action_route = (
        documents["scope_inventory"]
        .routes[0]
        .model_copy(
            update={
                "id": "PATCH /api/customers/{customer_id}",
                "method": "PATCH",
                "kind": "action",
                "effect": "update",
            }
        )
    )
    documents["scope_inventory"] = documents["scope_inventory"].model_copy(
        update={"routes": [action_route]}
    )
    _replace_interaction(
        documents,
        lambda interaction: interaction.model_copy(update={"route_ids": [action_route.id]}),
    )

    report = analyze_interaction_fidelity(**documents)

    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" not in {item.code for item in report.diagnostics}

    blocked_route = action_route.model_copy(
        update={
            "eligibility": "undetermined",
            "disposition": "blocked_on_evidence",
        }
    )
    documents["scope_inventory"] = documents["scope_inventory"].model_copy(
        update={"routes": [blocked_route]}
    )
    report = analyze_interaction_fidelity(**documents)
    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" in {item.code for item in report.diagnostics}

    documents["scope_inventory"] = documents["scope_inventory"].model_copy(
        update={"routes": [action_route]}
    )

    untrusted = lifecycle.model_copy(
        update={
            "commit": lifecycle.commit.model_copy(update={"evidence": _operation().evidence[0]})
        }
    )
    documents["contracts"] = {
        "get_customer": contract.model_copy(update={"action_lifecycle": untrusted})
    }
    report = analyze_interaction_fidelity(**documents)
    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" in {item.code for item in report.diagnostics}
