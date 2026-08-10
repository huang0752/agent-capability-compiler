from __future__ import annotations

import hashlib
import json
from typing import Any, cast

import pytest
from pydantic import TypeAdapter

from acc_core.interactions import (
    CapabilityInteractionContract,
    UIInteractionInventory,
)
from acc_core.interactions.compile import InteractionCompilationError, compile_interactions
from acc_core.models import Capability, Policy
from acc_core.validation import ValidationReport


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _evidence() -> dict[str, object]:
    return {
        "source_id": "customer-page",
        "kind": "source_file",
        "path": "frontend/customers.ts",
        "line_start": 1,
        "line_end": 10,
        "digest": f"sha256:{'b' * 64}",
    }


def _policy(
    policy_id: str,
    *,
    readable_fields: list[str],
    denied_fields: list[str] | None = None,
) -> Policy:
    return Policy.model_validate(
        {
            "schema_version": "2",
            "id": policy_id,
            "required_scopes": [],
            "tenant_mode": "none",
            "readable_fields": readable_fields,
            "denied_fields": denied_fields or [],
            "redaction_rules": [],
        }
    )


def _capability(
    capability_id: str,
    *,
    policy_id: str,
    input_schema: dict[str, object],
    output_schema: dict[str, object],
) -> Capability:
    return TypeAdapter(Capability).validate_python(
        {
            "schema_version": "2",
            "kind": "read",
            "id": capability_id,
            "title": capability_id,
            "description": capability_id,
            "input_schema": input_schema,
            "output_schema": output_schema,
            "workflow": [{"emit": {"value": None}}],
            "policy": policy_id,
            "evals": [f"{capability_id}.success"],
        }
    )


def _inventory(*, mode: str = "discovered", with_states: bool = False) -> UIInteractionInventory:
    if mode == "none":
        return UIInteractionInventory.model_validate(
            {
                "schema_version": "2",
                "scope": {
                    "mode": "none",
                    "evidence_sources": ["frontend-tree"],
                    "rationale": "There is no applicable interactive client surface.",
                },
                "surfaces": [],
                "interactions": [],
                "summary": {"surfaces": 0, "interactions": 0, "unresolved": 0},
            }
        )
    return UIInteractionInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": mode, "evidence_sources": ["frontend-tree"]},
            "surfaces": [
                {
                    "id": "customers",
                    "kind": "page",
                    "route_or_entry": "/customers",
                    "business_purpose": "Inspect customers",
                    "evidence_sources": ["customer-page"],
                }
            ],
            "interactions": [
                {
                    "id": "customers.initial-load",
                    "surface_id": "customers",
                    "business_intent": "Load the selected customer",
                    "trigger": {"kind": "screen_load"},
                    "route_ids": ["GET /customers/{customer_id}"],
                    "call_order": "sequential",
                    "input_bindings": [],
                    "defaults": [],
                    "option_sources": (
                        [
                            {
                                "id": "customer-status-options",
                                "target_pointer": "/status",
                                "source_kind": "static",
                                "static_options": [{"value": "active", "label": "Active"}],
                                "request_bindings": [],
                                "value_pointer": "/value",
                                "label_pointer": "/label",
                                "cascade_dependencies": [],
                                "search": {"mode": "none"},
                                "pagination": {"mode": "none"},
                                "cache": {"mode": "none"},
                                "freshness": "request",
                                "empty_behavior": "clear_selection",
                                "error_behavior": "fail_closed",
                                "evidence": _evidence(),
                            }
                        ]
                        if with_states
                        else []
                    ),
                    "conditions": [],
                    "related_data": [],
                    "result_consumption": (
                        [
                            {
                                "id": "customer-detail",
                                "role": "detail",
                                "source_pointer": "/customer",
                                "field_pointers": ["/id"],
                                "ordering": "none",
                                "pagination": "none",
                                "state_ids": ["ready"],
                                "evidence": _evidence(),
                            }
                        ]
                        if with_states
                        else []
                    ),
                    "states": (
                        [
                            {
                                "id": "ready",
                                "kind": "ready",
                                "allowed_next_events": ["refresh"],
                                "evidence": _evidence(),
                            }
                        ]
                        if with_states
                        else []
                    ),
                    "evidence_claims": (
                        [
                            {
                                "target_pointer": "/interactions/0/states/0",
                                "evidence": _evidence(),
                                "authority": "implementation",
                            }
                        ]
                        if with_states
                        else []
                    ),
                    "unknowns": [],
                }
            ],
            "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
        }
    )


def _contract(
    *,
    submission: str = "send",
    with_private_values: bool = False,
    state_id: str | None = None,
    with_action_lifecycle: bool = False,
) -> CapabilityInteractionContract:
    public_input_bindings: list[dict[str, object]] = [
        {
            "id": "locale-input",
            "source_kind": "user_input",
            "source_id": "locale-control",
            "source_pointer": "/locale",
            "target_pointer": "/locale",
            "cardinality": "optional",
            "evidence": _evidence(),
        },
        {
            "id": "status-input",
            "source_kind": "user_input",
            "source_id": "status-control",
            "source_pointer": "/status",
            "target_pointer": "/status",
            "cardinality": "optional",
            "evidence": _evidence(),
        },
    ]
    defaults: list[dict[str, object]] = [
        {
            "id": "default-locale",
            "target_pointer": "/locale",
            "source_kind": "literal",
            "value": "zh-CN",
            "authority": "implementation",
            "precedence": "caller_over_default",
            "submission": submission,
            "override_policy": "caller_allowed",
            "evidence": _evidence(),
        }
    ]
    trusted_input_bindings: list[dict[str, object]] = []
    conditions: list[dict[str, object]] = []
    option_sources: list[dict[str, object]] = []
    related_data: list[dict[str, object]] = []
    if with_private_values:
        defaults.append(
            {
                "id": "internal-default",
                "target_pointer": "/INTERNAL_TENANT_POINTER",
                "source_kind": "literal",
                "value": "INTERNAL_DEFAULT_VALUE",
                "authority": "implementation",
                "precedence": "caller_over_default",
                "submission": "send",
                "override_policy": "caller_allowed",
                "evidence": _evidence(),
            }
        )
        defaults.append(
            {
                "id": "internal-source-default",
                "target_pointer": "/INTERNAL_SECOND_POINTER",
                "source_kind": "trusted_context",
                "source_reference": "INTERNAL_SOURCE_REFERENCE",
                "authority": "implementation",
                "precedence": "source_default",
                "submission": "omit",
                "override_policy": "runtime_only",
                "evidence": _evidence(),
            }
        )
        trusted_input_bindings.append(
            {
                "id": "tenant-context",
                "source_kind": "trusted_context",
                "source_id": "INTERNAL_TENANT_REFERENCE",
                "source_pointer": "/internal/tenant",
                "target_pointer": "/INTERNAL_TENANT_POINTER",
                "cardinality": "one",
                "evidence": _evidence(),
            }
        )
        trusted_input_bindings.append(
            {
                "id": "tenant-source",
                "source_kind": "trusted_context",
                "source_id": "INTERNAL_SECOND_REFERENCE",
                "source_pointer": "/internal/second",
                "target_pointer": "/INTERNAL_SECOND_POINTER",
                "cardinality": "one",
                "evidence": _evidence(),
            }
        )
        conditions.append(
            {
                "id": "internal-condition",
                "target": "visible",
                "target_pointer": "/INTERNAL_TENANT_POINTER",
                "expression": {
                    "operator": "present",
                    "operand": {
                        "kind": "reference",
                        "pointer": "/INTERNAL_TENANT_POINTER",
                    },
                },
                "evidence": _evidence(),
            }
        )
        option_sources.append(
            {
                "id": "internal-options",
                "target_pointer": "/INTERNAL_TENANT_POINTER",
                "source_kind": "static",
                "static_options": [{"value": "internal", "label": "INTERNAL_OPTION_LABEL"}],
                "request_bindings": [],
                "value_pointer": "/value",
                "label_pointer": "/label",
                "cascade_dependencies": [],
                "search": {"mode": "none"},
                "pagination": {"mode": "none"},
                "cache": {"mode": "none"},
                "freshness": "request",
                "empty_behavior": "clear_selection",
                "error_behavior": "fail_closed",
                "evidence": _evidence(),
            }
        )
        related_data.append(
            {
                "id": "internal-related",
                "producer_kind": "operation",
                "producer_id": "INTERNAL_PRODUCER",
                "output_pointer": "/internal/output",
                "target_pointer": "/INTERNAL_TENANT_POINTER",
                "cardinality": "one",
                "ordering": "none",
                "freshness": "request",
                "failure_isolation": "fail_fast",
                "evidence": _evidence(),
            }
        )
    return CapabilityInteractionContract.model_validate(
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "interaction_ids": ["customers.initial-load"],
            "public_input_bindings": public_input_bindings,
            "trusted_input_bindings": trusted_input_bindings,
            "defaults": defaults,
            "option_sources": option_sources,
            "conditions": conditions,
            "related_data": related_data,
            "result_consumption": (
                [
                    {
                        "id": "customer-result",
                        "role": "detail",
                        "source_pointer": "/customer",
                        "field_pointers": ["/id"],
                        "ordering": "none",
                        "pagination": "none",
                        "state_ids": [state_id],
                        "evidence": _evidence(),
                    }
                ]
                if state_id is not None
                else []
            ),
            "required_scenarios": ["customers.initial-load.success"],
            "omissions": [],
            "action_lifecycle": (
                {
                    "interaction_id": "customers.initial-load",
                    "prepare": {
                        "target_pointer": "/action/prepare",
                        "evidence": _evidence(),
                    },
                    "approve": {
                        "target_pointer": "/action/approve",
                        "evidence": _evidence(),
                    },
                    "commit": {
                        "target_pointer": "/action/commit",
                        "evidence": _evidence(),
                    },
                    "status": {
                        "target_pointer": "/action/status",
                        "evidence": _evidence(),
                    },
                }
                if with_action_lifecycle
                else None
            ),
        }
    )


def test_compiler_emits_canonical_interaction_attestation_without_evidence_body() -> None:
    report = ValidationReport(
        ui_interaction_inventory=_inventory(),
        ui_interaction_inventory_path="ui-interaction-inventory.yaml",
        interaction_contracts={"get_customer": _contract()},
        interaction_contract_paths={"get_customer": "interaction-contracts/get_customer.yaml"},
    )

    attestation = compile_interactions(report)
    wire = cast(dict[str, Any], attestation.to_dict())
    inventory = report.ui_interaction_inventory
    assert inventory is not None

    assert set(wire) == {
        "schema_version",
        "digest",
        "inventory",
        "contracts",
        "dependencies",
    }
    assert wire["schema_version"] == "2"
    assert wire["digest"] == _canonical_digest(
        {
            "schema_version": "2",
            "inventory": wire["inventory"],
            "contracts": wire["contracts"],
            "dependencies": wire["dependencies"],
        }
    )
    assert wire["inventory"] == {
        "evidence_sha256": _canonical_digest(["frontend-tree"]),
        "interaction_ids": ["customers.initial-load"],
        "scope_mode": "discovered",
        "sidecar_sha256": _canonical_digest(inventory.model_dump(mode="json", by_alias=True)),
        "status": "declared",
        "summary": {"interactions": 1, "surfaces": 1, "unresolved": 0},
        "surface_ids": ["customers"],
    }
    compiled_contract = wire["contracts"]["get_customer"]
    assert compiled_contract["defaults"][0]["value"] == "zh-CN"
    assert compiled_contract["sidecar_sha256"] == _canonical_digest(
        report.interaction_contracts["get_customer"].model_dump(mode="json", by_alias=True)
    )
    serialized = json.dumps(wire, ensure_ascii=False, sort_keys=True)
    assert '"evidence"' not in serialized
    assert "frontend/customers.ts" not in serialized


def test_compiler_digest_changes_for_interaction_semantics_only() -> None:
    first = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": _contract(submission="send")},
        )
    )
    second = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": _contract(submission="send_if_changed")},
        )
    )

    assert first.digest != second.digest


def test_compiler_keeps_safe_default_without_public_input_binding() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["public_input_bindings"] = []
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    assert attestation.contracts["get_customer"]["defaults"] == [
        {
            "id": "default-locale",
            "source_kind": "literal",
            "target_pointer": "/locale",
            "value": "zh-CN",
        }
    ]


def test_compiler_keeps_option_without_public_input_binding() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["public_input_bindings"] = []
    document["defaults"] = []
    document["option_sources"] = [
        {
            "id": "status-options",
            "target_pointer": "/status",
            "source_kind": "static",
            "static_options": [{"value": "active", "label": "Active"}],
            "request_bindings": [],
            "value_pointer": "/value",
            "label_pointer": "/label",
            "cascade_dependencies": [],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "clear_selection",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    options = cast(
        list[dict[str, Any]],
        attestation.contracts["get_customer"]["option_sources"],
    )
    assert options[0]["target_pointer"] == "/status"


def test_compiler_trusted_collision_removes_default_only_target() -> None:
    document = _contract().model_dump(mode="json", by_alias=True)
    document["public_input_bindings"] = []
    document["trusted_input_bindings"] = [
        {
            "id": "trusted-locale",
            "source_kind": "trusted_context",
            "source_id": "INTERNAL_COLLISION_SOURCE",
            "source_pointer": "/INTERNAL_COLLISION_POINTER",
            "target_pointer": "/locale",
            "cardinality": "one",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    assert attestation.contracts["get_customer"]["defaults"] == []
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "INTERNAL_COLLISION_SOURCE" not in serialized
    assert "INTERNAL_COLLISION_POINTER" not in serialized


def test_compiler_cascade_dependency_does_not_create_public_target() -> None:
    document = _contract().model_dump(mode="json", by_alias=True)
    document["public_input_bindings"] = []
    document["defaults"] = []
    document["option_sources"] = [
        {
            "id": "status-options",
            "target_pointer": "/status",
            "source_kind": "static",
            "static_options": [{"value": "active", "label": "Active"}],
            "request_bindings": [],
            "value_pointer": "/value",
            "label_pointer": "/label",
            "cascade_dependencies": ["/INTERNAL_CASCADE_POINTER"],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "clear_selection",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    assert attestation.contracts["get_customer"]["option_sources"] == []
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "INTERNAL_CASCADE_POINTER" not in serialized


def test_compiler_option_literal_request_binding_is_not_public() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["option_sources"] = [
        {
            "id": "secret-options",
            "target_pointer": "/status",
            "source_kind": "capability",
            "producer_id": "SECRET_OPTION_PRODUCER",
            "static_options": [],
            "request_bindings": [
                {
                    "id": "secret-literal",
                    "source_kind": "literal",
                    "target_pointer": "/query",
                    "cardinality": "one",
                    "literal_value": "SECRET_OPTION_LITERAL",
                    "evidence": _evidence(),
                }
            ],
            "items_pointer": "/items",
            "value_pointer": "/value",
            "label_pointer": "/label",
            "cascade_dependencies": [],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "clear_selection",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    assert attestation.contracts["get_customer"]["option_sources"] == []
    assert attestation.dependencies == ()
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "SECRET_OPTION_LITERAL" not in serialized
    assert "SECRET_OPTION_PRODUCER" not in serialized


def test_compiler_sanitizes_public_capability_option_request_binding() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["option_sources"] = [
        {
            "id": "status-options",
            "target_pointer": "/status",
            "source_kind": "capability",
            "producer_id": "list_status_options",
            "static_options": [],
            "request_bindings": [
                {
                    "id": "status-query",
                    "source_kind": "user_input",
                    "source_id": "SECRET_BINDING_SOURCE_ID",
                    "source_pointer": "/status",
                    "target_pointer": "/query",
                    "cardinality": "optional",
                    "mapping": {"kind": "text"},
                    "evidence": _evidence(),
                }
            ],
            "items_pointer": "/items",
            "value_pointer": "/value",
            "label_pointer": "/label",
            "cascade_dependencies": ["/status"],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "clear_selection",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    option = cast(
        list[dict[str, Any]],
        attestation.contracts["get_customer"]["option_sources"],
    )[0]
    assert option["request_bindings"] == [
        {
            "cardinality": "optional",
            "id": "status-query",
            "mapping": {"kind": "text", "mapping": {}},
            "source_kind": "user_input",
            "source_pointer": "/status",
            "target_pointer": "/query",
        }
    ]
    assert attestation.dependencies == (("list_status_options", "get_customer"),)
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "SECRET_BINDING_SOURCE_ID" not in serialized
    assert '"evidence"' not in serialized


def test_compiler_operation_option_producer_is_not_public() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["option_sources"] = [
        {
            "id": "internal-operation-options",
            "target_pointer": "/status",
            "source_kind": "operation",
            "producer_id": "SECRET_OPERATION_PRODUCER",
            "static_options": [],
            "request_bindings": [],
            "items_pointer": "/items",
            "value_pointer": "/value",
            "label_pointer": "/label",
            "cascade_dependencies": [],
            "search": {"mode": "none"},
            "pagination": {"mode": "none"},
            "cache": {"mode": "none"},
            "freshness": "request",
            "empty_behavior": "clear_selection",
            "error_behavior": "fail_closed",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    assert attestation.contracts["get_customer"]["option_sources"] == []
    assert attestation.dependencies == ()
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "SECRET_OPERATION_PRODUCER" not in serialized


def test_compiler_public_manifest_excludes_trusted_and_non_public_defaults() -> None:
    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": _contract(with_private_values=True)},
        )
    )

    compiled = cast(dict[str, Any], attestation.contracts["get_customer"])
    assert "trusted_input_bindings" not in compiled
    assert compiled["defaults"] == [
        {
            "id": "default-locale",
            "source_kind": "literal",
            "target_pointer": "/locale",
            "value": "zh-CN",
        }
    ]
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "INTERNAL_DEFAULT_REFERENCE" not in serialized
    assert "INTERNAL_DEFAULT_VALUE" not in serialized
    assert "INTERNAL_SOURCE_REFERENCE" not in serialized
    assert "INTERNAL_TENANT_REFERENCE" not in serialized
    assert "INTERNAL_TENANT_POINTER" not in serialized
    assert "INTERNAL_SECOND_REFERENCE" not in serialized
    assert "INTERNAL_SECOND_POINTER" not in serialized
    assert "INTERNAL_OPTION_LABEL" not in serialized
    assert "INTERNAL_PRODUCER" not in serialized
    assert "/internal/tenant" not in serialized
    assert "/internal/output" not in serialized
    assert "frontend/customers.ts" not in serialized


def test_compiler_inherits_only_safe_trigger_and_empty_error_semantics() -> None:
    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(with_states=True),
            interaction_contracts={"get_customer": _contract(state_id="ready")},
        )
    )

    inherited = cast(
        dict[str, Any],
        attestation.contracts["get_customer"]["inherited_interactions"],
    )
    assert inherited == {
        "customers.initial-load": {
            "call_order": "sequential",
            "states": [
                {
                    "allowed_next_events": ["refresh"],
                    "id": "ready",
                    "kind": "ready",
                }
            ],
            "trigger": {"kind": "screen_load"},
        }
    }
    assert attestation.contracts["get_customer"]["result_consumption"] == []


def test_compiler_rejects_state_without_matching_authoritative_evidence_claim() -> None:
    document = _inventory(with_states=True).model_dump(
        mode="json", by_alias=True, exclude_unset=True
    )
    document["interactions"][0]["states"][0]["evidence"] = {
        **_evidence(),
        "digest": "sha256:" + "d" * 64,
    }
    inventory = UIInteractionInventory.model_validate(document)

    with pytest.raises(
        InteractionCompilationError,
        match="state evidence is not authoritatively claimed",
    ) as caught:
        compile_interactions(
            ValidationReport(
                ui_interaction_inventory=inventory,
                interaction_contracts={"get_customer": _contract(state_id="ready")},
            )
        )

    assert caught.value.code == "ACC_UI_INTERACTION_STATE_EVIDENCE_UNPROVEN"
    assert "sha256:" + "d" * 64 not in repr(caught.value.__dict__)


def test_compiler_publishes_policy_proven_presentation_and_sanitized_states() -> None:
    capability = _capability(
        "get_customer",
        policy_id="customer-read",
        input_schema={"type": "object"},
        output_schema={
            "type": "object",
            "properties": {
                "customer": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                }
            },
        },
    )
    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(with_states=True),
            interaction_contracts={"get_customer": _contract(state_id="ready")},
            capabilities={"get_customer": capability},
            policies={
                "customer-read": _policy(
                    "customer-read",
                    readable_fields=["customer.id"],
                )
            },
        )
    )

    compiled = cast(dict[str, Any], attestation.contracts["get_customer"])
    assert compiled["result_consumption"] == [
        {
            "field_pointers": ["/id"],
            "formatting_class": None,
            "id": "customer-result",
            "ordering": "none",
            "pagination": "none",
            "role": "detail",
            "source_pointer": "/customer",
            "state_ids": ["ready"],
        }
    ]
    assert compiled["inherited_interactions"]["customers.initial-load"]["states"] == [
        {
            "allowed_next_events": ["refresh"],
            "id": "ready",
            "kind": "ready",
        }
    ]
    serialized = json.dumps(compiled, ensure_ascii=False, sort_keys=True)
    assert '"evidence"' not in serialized
    assert "frontend/customers.ts" not in serialized


def test_compiler_rejects_state_whose_entry_condition_is_not_public() -> None:
    document = _inventory(with_states=True).model_dump(mode="json", by_alias=True)
    interaction = document["interactions"][0]
    interaction["conditions"] = [
        {
            "id": "SECRET_INTERNAL_CONDITION",
            "target": "visible",
            "target_pointer": "/locale",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/locale"},
            },
            "evidence": _evidence(),
        }
    ]
    interaction["states"][0]["entry_condition_id"] = "SECRET_INTERNAL_CONDITION"
    inventory = UIInteractionInventory.model_validate(document)

    with pytest.raises(
        InteractionCompilationError,
        match="state entry condition is not public",
    ) as caught:
        compile_interactions(
            ValidationReport(
                ui_interaction_inventory=inventory,
                interaction_contracts={"get_customer": _contract(state_id="ready")},
            )
        )

    assert caught.value.code == "ACC_UI_INTERACTION_STATE_CONDITION_UNPROVEN"
    assert "SECRET_INTERNAL_CONDITION" not in repr(caught.value.__dict__)


def test_compiler_publishes_only_policy_proven_capability_related_data() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["related_data"] = [
        {
            "id": "customer-owner",
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
    ]
    contract = CapabilityInteractionContract.model_validate(document)
    consumer = _capability(
        "get_customer",
        policy_id="customer-read",
        input_schema={
            "type": "object",
            "properties": {"owner_id": {"type": "string"}},
        },
        output_schema={"type": "object"},
    )
    producer = _capability(
        "get_owner",
        policy_id="owner-read",
        input_schema={"type": "object"},
        output_schema={
            "type": "object",
            "properties": {
                "owner": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "SECRET_INTERNAL_FIELD": {"type": "string"},
                    },
                }
            },
        },
    )
    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
            capabilities={"get_customer": consumer, "get_owner": producer},
            policies={
                "customer-read": _policy("customer-read", readable_fields=[]),
                "owner-read": _policy(
                    "owner-read",
                    readable_fields=["owner.id"],
                    denied_fields=["owner.SECRET_INTERNAL_FIELD"],
                ),
            },
        )
    )

    assert attestation.contracts["get_customer"]["related_data"] == [
        {
            "cardinality": "one",
            "failure_isolation": "independent",
            "freshness": "request",
            "id": "customer-owner",
            "output_pointer": "/owner/id",
            "producer_id": "get_owner",
            "producer_kind": "capability",
            "target_pointer": "/owner_id",
        }
    ]
    assert attestation.dependencies == (("get_owner", "get_customer"),)
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "SECRET_INTERNAL_FIELD" not in serialized
    assert '"evidence"' not in serialized


def test_compiler_inherited_details_do_not_expose_unproven_references() -> None:
    inventory_document = _inventory(with_states=True).model_dump(mode="json", by_alias=True)
    interaction = inventory_document["interactions"][0]
    interaction["trigger"] = {
        "kind": "select",
        "source_pointer": "/SECRET_TRIGGER_POINTER",
    }
    interaction["states"][0]["id"] = "alternate-ready"
    interaction["result_consumption"][0]["state_ids"] = ["alternate-ready"]
    inventory = UIInteractionInventory.model_validate(inventory_document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=inventory,
            interaction_contracts={"get_customer": _contract(state_id="alternate-ready")},
        )
    )

    inherited = cast(
        dict[str, Any],
        attestation.contracts["get_customer"]["inherited_interactions"],
    )
    assert inherited["customers.initial-load"]["trigger"] == {"kind": "select"}
    assert attestation.contracts["get_customer"]["result_consumption"] == []
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "SECRET_TRIGGER_POINTER" not in serialized
    assert '"id": "alternate-ready"' in serialized


def test_compiler_related_data_fails_closed_without_public_classification() -> None:
    document = _contract().model_dump(mode="json", by_alias=True, exclude_unset=True)
    document["related_data"] = [
        {
            "id": "customer-orders",
            "producer_kind": "operation",
            "producer_id": "SECRET_RELATED_PRODUCER",
            "output_pointer": "/SECRET_RELATED_OUTPUT",
            "target_pointer": "/orders",
            "cardinality": "many",
            "ordering": "source",
            "freshness": "request",
            "failure_isolation": "independent",
            "evidence": _evidence(),
        }
    ]
    contract = CapabilityInteractionContract.model_validate(document)

    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": contract},
        )
    )

    assert attestation.contracts["get_customer"]["related_data"] == []
    assert attestation.dependencies == ()
    serialized = json.dumps(attestation.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "SECRET_RELATED_PRODUCER" not in serialized
    assert "SECRET_RELATED_OUTPUT" not in serialized


def test_compiler_action_lifecycle_exposes_only_fixed_phases() -> None:
    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(),
            interaction_contracts={"get_customer": _contract(with_action_lifecycle=True)},
        )
    )

    lifecycle = attestation.contracts["get_customer"]["action_lifecycle"]
    assert lifecycle == {
        "interaction_id": "customers.initial-load",
        "phases": ["prepare", "approve", "commit", "status"],
    }
    serialized = json.dumps(lifecycle, ensure_ascii=False, sort_keys=True)
    assert "frontend/customers.ts" not in serialized
    assert '"evidence"' not in serialized


def test_compiler_rejects_untraceable_contract_result_state() -> None:
    report = ValidationReport(
        ui_interaction_inventory=_inventory(with_states=True),
        interaction_contracts={"get_customer": _contract(state_id="missing")},
    )

    with pytest.raises(InteractionCompilationError, match="result state is not declared") as caught:
        compile_interactions(report)

    assert caught.value.code == "ACC_UI_INTERACTION_STATE_UNTRACED"
    assert caught.value.capability_id == "get_customer"
    assert caught.value.consumption_index == 0


def test_compiler_uses_explicit_empty_manifest_when_inventory_is_not_declared() -> None:
    attestation = compile_interactions(ValidationReport())

    assert attestation.inventory == {"status": "not_declared"}
    assert attestation.schema_version == "2"
    assert attestation.contracts == {}
    assert attestation.dependencies == ()
    assert len(attestation.digest) == 64


def test_none_scope_attests_evidence_without_fabricating_interactions() -> None:
    attestation = compile_interactions(
        ValidationReport(
            ui_interaction_inventory=_inventory(mode="none"),
            interaction_contracts={"get_customer": _contract()},
        )
    )

    assert attestation.inventory["status"] == "declared"
    assert attestation.inventory["scope_mode"] == "none"
    assert attestation.inventory["interaction_ids"] == []
    assert attestation.inventory["surface_ids"] == []
    assert len(cast(str, attestation.inventory["evidence_sha256"])) == 64
    assert attestation.contracts == {}
    assert attestation.dependencies == ()
