from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, cast

import pytest

from acc_core.compiler import actions as action_compiler
from acc_core.compiler import ir as compiler_ir
from acc_core.compiler.actions import ActionProof, prove_action_capability
from acc_core.contracts import ActionSemantics, SourceContract
from acc_core.diagnostics import Diagnostic
from acc_core.models import Policy
from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionOperationV2,
    OperationV2,
    ReadOperationV2,
)


def _evidence() -> list[dict[str, object]]:
    return [
        {
            "source_id": "order-source",
            "path": "src/orders.py",
            "line_start": 1,
            "line_end": 20,
            "digest": "sha256:" + "a" * 64,
        }
    ]


def _operation(
    operation_id: str,
    *,
    effect: str,
    risk: str = "low",
    reversibility: str = "reversible",
    scopes: list[str] | None = None,
    idempotency: str = "source_key",
    concurrency: str = "required",
    method: str | None = None,
    retry_mode: str | None = None,
    idempotency_contract: dict[str, object] | None = None,
    concurrency_contract: dict[str, object] | None = None,
) -> ReadOperationV2 | ActionOperationV2:
    read = effect == "read"
    safety: dict[str, object] = {
        "effect": effect,
        "risk": risk,
        "reversibility": reversibility,
        "retry": {
            "mode": retry_mode
            or ("idempotent_only" if read or idempotency == "source_key" else "never")
        },
        "idempotency": idempotency_contract
        or (
            {"mode": "unsupported"}
            if read or idempotency == "unsupported"
            else {
                "mode": "source_key",
                "target": {"kind": "header", "name": "Idempotency-Key"},
            }
        ),
        "concurrency": concurrency_contract
        or (
            {"mode": "not_supported"}
            if read or concurrency == "not_supported"
            else {
                "mode": "required",
                "token": {"kind": "response_header", "name": "ETag"},
                "precondition": {"kind": "header", "name": "If-Match"},
            }
        ),
    }
    document = {
        "schema_version": "2",
        "kind": "read" if read else "action",
        "id": operation_id,
        "title": operation_id,
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
        },
        "output_schema": {"type": "object"},
        "http": {
            "method": method or ("GET" if read else "POST"),
            "path": "/orders/{order_id}" if read else "/orders/{order_id}/action",
            "path_parameters": {"order_id": "order_id"},
            "query_parameters": {},
            "request": None,
            "success": {"statuses": [200], "body": "json"},
            "scopes": scopes or (["orders.read"] if read else ["orders.write"]),
            "timeout_seconds": 15,
            "max_response_bytes": 1024,
            "safety": safety,
        },
        "context_bindings": {},
        "evidence": _evidence(),
    }
    return (
        ReadOperationV2.model_validate(document)
        if read
        else ActionOperationV2.model_validate(document)
    )


def _call(operation: str, reference: str = "$.prepared.input.order_id") -> dict[str, object]:
    return {
        "id": operation.replace(".", "_"),
        "call": {"operation": operation, "arguments": {"order_id": reference}},
    }


def _capability(
    *,
    preview: list[dict[str, object]] | None = None,
    commit: list[dict[str, object]] | None = None,
    approval: str = "required",
    execution_mode: str = "single",
) -> ActionCapabilityV2:
    return ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.change",
            "title": "Change order",
            "description": "Preview and change one order.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "output_schema": {"type": "object"},
            "action": {
                "execution_mode": execution_mode,
                "approval": {"mode": approval},
                "expires_in_seconds": 300,
            },
            "preview_workflow": preview
            or [
                _call("orders.get", "$.input.order_id"),
                {"emit": {"value": "$.steps.orders_get"}},
            ],
            "commit_workflow": commit
            or [_call("orders.update"), {"emit": {"value": "$.steps.orders_update"}}],
            "policy": "orders-write",
            "evals": ["orders-change-success"],
        }
    )


def _codes(report: ActionProof) -> set[str]:
    return {item.code for item in report.diagnostics}


def _policy(
    *,
    readable_fields: list[str] | None = None,
    denied_fields: list[str] | None = None,
    redaction_rules: list[dict[str, str]] | None = None,
) -> Policy:
    return Policy.model_validate(
        {
            "schema_version": "2",
            "id": "orders-write",
            "required_scopes": [],
            "tenant_mode": "none",
            "tenant_field": None,
            "readable_fields": readable_fields or ["data", "routing"],
            "denied_fields": denied_fields or [],
            "redaction_rules": redaction_rules or [],
        }
    )


def _server_serialized_semantics(operation: ActionOperationV2) -> ActionSemantics:
    fields = [
        "conflict_control",
        "effect",
        "idempotency",
        "outcome_resolution",
        "reversibility",
        "retry",
        "risk",
    ]
    evidence = operation.evidence[0].model_dump(mode="json")
    return ActionSemantics.model_validate(
        {
            "method": operation.http.method,
            **operation.http.safety.model_dump(mode="json"),
            "outcome_resolution": {
                "mode": "status_query",
                "operation_id": "jobs.status",
            },
            "evidence": evidence,
            "authority": "implementation",
            "provenance": [
                {
                    "field": field,
                    "evidence": evidence,
                    "evidence_pointer": f"/action/{field}",
                    "authority": "implementation",
                }
                for field in fields
            ],
        }
    )


def _server_serialized_operation(*, retry_mode: str = "never") -> ActionOperationV2:
    operation = _operation(
        "jobs.cancel",
        effect="transition",
        retry_mode="never",
        idempotency_contract={
            "mode": "state_idempotent",
            "state_pointer": "/data/status",
            "terminal_values": ["cancelled"],
        },
        concurrency_contract={
            "mode": "server_serialized_state_predicate",
            "read_operation_id": "jobs.status",
            "state_pointer": "/data/status",
            "allowed_values": ["queued", "running"],
        },
    )
    assert isinstance(operation, ActionOperationV2)
    if retry_mode != "never":
        retry = operation.http.safety.retry.model_copy(update={"mode": retry_mode})
        safety = operation.http.safety.model_copy(update={"retry": retry})
        operation = operation.model_copy(
            update={"http": operation.http.model_copy(update={"safety": safety})}
        )
    return operation


def _valid_operations() -> Mapping[str, OperationV2]:
    return {
        "orders.get": _operation("orders.get", effect="read"),
        "orders.update": _operation("orders.update", effect="update"),
    }


def test_legal_single_action_produces_deterministic_derived_inventory() -> None:
    report = prove_action_capability(_capability(), _valid_operations())

    assert report.ok
    assert report.diagnostics == ()
    assert report.mutation_operation_ids == ("orders.update",)
    assert report.effects == ("update",)
    assert report.maximum_risk == "low"
    assert report.required_scopes == ("orders.read", "orders.write")
    assert report.approval_required is True


def test_server_serialized_transition_requires_preview_status_and_trusted_semantics() -> None:
    mutation = _server_serialized_operation()
    operations = {
        "jobs.status": _operation("jobs.status", effect="read"),
        "jobs.cancel": mutation,
    }
    capability = _capability(
        preview=[_call("jobs.status", "$.input.order_id"), {"emit": {"value": None}}],
        commit=[_call("jobs.cancel"), {"emit": {"value": None}}],
    )

    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": _server_serialized_semantics(mutation)},
    )

    assert proof.ok
    assert proof.approval_required
    assert proof.strategy_operation_ids == ("jobs.status",)


def test_server_serialized_transition_rejects_retry_or_missing_provenance() -> None:
    valid = _server_serialized_operation()
    retrying = _server_serialized_operation(retry_mode="idempotent_only")
    operations = {
        "jobs.status": _operation("jobs.status", effect="read"),
        "jobs.cancel": retrying,
    }
    capability = _capability(
        preview=[_call("jobs.status", "$.input.order_id"), {"emit": {"value": None}}],
        commit=[_call("jobs.cancel"), {"emit": {"value": None}}],
    )

    retry_proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": _server_serialized_semantics(valid)},
    )
    missing_proof = prove_action_capability(capability, operations)

    assert "ACC_COMPILE_ACTION_SERVER_SERIALIZED_RETRY_FORBIDDEN" in _codes(retry_proof)
    assert "ACC_COMPILE_ACTION_SAFETY_PROVENANCE_REQUIRED" in _codes(missing_proof)


def test_server_serialized_strategy_cannot_waive_approval_or_use_contract_only_proof() -> None:
    mutation = _server_serialized_operation()
    semantics = _server_serialized_semantics(mutation)
    claims = list(semantics.provenance)
    claims[0] = claims[0].model_copy(update={"authority": "contract"})
    contract_only = semantics.model_copy(update={"provenance": claims})
    operations = {
        "jobs.status": _operation("jobs.status", effect="read"),
        "jobs.cancel": mutation,
    }
    capability = _capability(
        approval="not_required",
        preview=[_call("jobs.status", "$.input.order_id"), {"emit": {"value": None}}],
        commit=[_call("jobs.cancel"), {"emit": {"value": None}}],
    )

    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": contract_only},
    )

    assert "ACC_COMPILE_ACTION_APPROVAL_REQUIRED" in _codes(proof)
    assert "ACC_COMPILE_ACTION_SAFETY_PROVENANCE_REQUIRED" in _codes(proof)


def test_server_serialized_provenance_must_bind_every_claim_to_operation_evidence() -> None:
    mutation = _server_serialized_operation()
    semantics = _server_serialized_semantics(mutation)
    foreign_evidence = semantics.provenance[0].evidence.model_copy(
        update={"digest": "sha256:" + "b" * 64}
    )
    claims = list(semantics.provenance)
    claims[0] = claims[0].model_copy(update={"evidence": foreign_evidence})
    unbound = semantics.model_copy(update={"provenance": claims})

    with pytest.raises(ValueError, match="bound Operation"):
        action_compiler.compile_action_semantics_attestation(mutation, unbound)


def test_ir_includes_server_serialized_preview_and_status_dependencies() -> None:
    mutation = _server_serialized_operation()
    status = _operation("jobs.status", effect="read")
    capability = _capability(
        preview=[_call("jobs.status", "$.input.order_id"), {"emit": {"value": None}}],
        commit=[_call("jobs.cancel"), {"emit": {"value": None}}],
    )
    semantics = _server_serialized_semantics(mutation)
    contract = SourceContract.model_validate(
        {
            "schema_version": "2",
            "id": "jobs.cancel.contract",
            "operation_id": "jobs.cancel",
            "request_schema": {"type": "object"},
            "response_schema": {"type": "object"},
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
            "action_semantics": semantics.model_dump(mode="json"),
        }
    )
    diagnostics: list[Diagnostic] = []

    dependencies, proof = compiler_ir._compile_action_capability(
        capability,
        operations={"jobs.status": status, "jobs.cancel": mutation},
        source_contracts={"jobs.cancel": contract},
        operation_bindings={"jobs.status": set(), "jobs.cancel": set()},
        policies={"orders-write": _policy()},
        evals={"orders-change-success": "orders.change"},
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert dependencies == {"jobs.cancel", "jobs.status"}
    proof_value = cast(dict[str, Any], proof)
    assert proof_value["operation_semantics"]["jobs.cancel"]["summary"]["outcome_resolution"] == {
        "mode": "status_query",
        "operation_id": "jobs.status",
    }


def test_action_semantics_attestation_is_canonical_and_evidence_bound() -> None:
    operation = _operation("orders.update", effect="update")
    assert isinstance(operation, ActionOperationV2)
    semantics = ActionSemantics.model_validate(
        {
            "method": operation.http.method,
            **operation.http.safety.model_dump(mode="json"),
            "evidence": operation.evidence[0].model_dump(mode="json"),
            "authority": "implementation",
        }
    )

    attestation = action_compiler.compile_action_semantics_attestation(
        operation,
        semantics,
    )

    expected_summary = semantics.model_dump(mode="json")
    expected_payload = json.dumps(
        expected_summary,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    assert attestation == {
        "summary": expected_summary,
        "digest": "sha256:" + hashlib.sha256(expected_payload).hexdigest(),
    }


def test_preview_must_not_call_an_action_operation() -> None:
    capability = _capability(
        preview=[_call("orders.update", "$.input.order_id"), {"emit": {"value": None}}]
    )
    report = prove_action_capability(capability, _valid_operations())

    assert not report.ok
    assert "ACC_COMPILE_ACTION_PREVIEW_MUTATION" in _codes(report)


@pytest.mark.parametrize(
    "commit",
    [
        [_call("orders.get"), {"emit": {"value": None}}],
        [
            _call("orders.update"),
            _call("orders.delete"),
            {"emit": {"value": None}},
        ],
    ],
)
def test_single_mode_requires_exactly_one_mutation_on_every_path(
    commit: list[dict[str, object]],
) -> None:
    operations = {
        **_valid_operations(),
        "orders.delete": _operation("orders.delete", effect="delete"),
    }
    report = prove_action_capability(_capability(commit=commit), operations)

    assert "ACC_COMPILE_ACTION_SINGLE_MUTATION_REQUIRED" in _codes(report)


def test_one_mutation_in_each_branch_is_one_mutation_per_execution_path() -> None:
    commit: list[dict[str, object]] = [
        {
            "branch": {
                "condition": "$.prepared.preview.allowed",
                "then": [_call("orders.update")],
                "else": [_call("orders.transition")],
            }
        },
        {"emit": {"value": None}},
    ]
    operations = {
        **_valid_operations(),
        "orders.transition": _operation("orders.transition", effect="transition"),
    }

    report = prove_action_capability(_capability(commit=commit), operations)

    assert report.ok
    assert report.mutation_operation_ids == ("orders.transition", "orders.update")
    assert report.effects == ("transition", "update")


@pytest.mark.parametrize(
    ("commit", "code"),
    [
        (
            [
                {"parallel": [_call("orders.update"), {"emit": {"value": None}}]},
                {"emit": {"value": None}},
            ],
            "ACC_COMPILE_ACTION_MUTATION_IN_PARALLEL",
        ),
        (
            [
                {
                    "foreach": {
                        "items": "$.prepared.preview.items",
                        "item_name": "item",
                        "max_items": 10,
                        "workflow": [_call("orders.update")],
                    }
                },
                {"emit": {"value": None}},
            ],
            "ACC_COMPILE_ACTION_MUTATION_IN_FOREACH",
        ),
    ],
)
def test_mutations_are_forbidden_in_unbounded_action_topologies(
    commit: list[dict[str, object]], code: str
) -> None:
    report = prove_action_capability(_capability(commit=commit), _valid_operations())
    assert code in _codes(report)


def test_effect_risk_and_scopes_are_derived_from_reachable_operations() -> None:
    operations = {
        "orders.get": _operation("orders.get", effect="read", scopes=["orders.read"]),
        "orders.update": _operation(
            "orders.update", effect="update", risk="medium", scopes=["orders.update"]
        ),
        "orders.delete": _operation(
            "orders.delete",
            effect="delete",
            risk="critical",
            reversibility="irreversible",
            scopes=["orders.delete"],
        ),
    }
    commit: list[dict[str, object]] = [
        {
            "branch": {
                "condition": "$.prepared.preview.delete",
                "then": [_call("orders.delete")],
                "else": [_call("orders.update")],
            }
        },
        {"emit": {"value": None}},
    ]
    report = prove_action_capability(_capability(commit=commit), operations)

    assert report.effects == ("delete", "update")
    assert report.maximum_risk == "critical"
    assert report.required_scopes == ("orders.delete", "orders.read", "orders.update")


def test_approval_cannot_be_waived_for_high_risk_or_irreversible_action() -> None:
    operations = {
        "orders.get": _operation("orders.get", effect="read"),
        "orders.update": _operation(
            "orders.update",
            effect="update",
            risk="high",
            reversibility="irreversible",
        ),
    }
    report = prove_action_capability(_capability(approval="not_required"), operations)

    assert "ACC_COMPILE_ACTION_APPROVAL_REQUIRED" in _codes(report)
    assert report.approval_required is True


@pytest.mark.parametrize("effect", ["create", "execute"])
def test_create_and_execute_require_source_idempotency(effect: str) -> None:
    operations = {
        "orders.get": _operation("orders.get", effect="read"),
        "orders.update": _operation(
            "orders.update",
            effect=effect,
            idempotency="unsupported",
            concurrency="not_supported",
        ),
    }
    report = prove_action_capability(_capability(), operations)

    assert "ACC_COMPILE_ACTION_SOURCE_IDEMPOTENCY_REQUIRED" in _codes(report)


@pytest.mark.parametrize("effect", ["update", "delete", "transition"])
def test_update_delete_and_transition_require_optimistic_concurrency(effect: str) -> None:
    operations = {
        "orders.get": _operation("orders.get", effect="read"),
        "orders.update": _operation("orders.update", effect=effect, concurrency="not_supported"),
    }
    report = prove_action_capability(_capability(), operations)

    assert "ACC_COMPILE_ACTION_CONCURRENCY_REQUIRED" in _codes(report)


@pytest.mark.parametrize(
    ("preview_reference", "commit_reference", "code"),
    [
        (
            "$.prepared.input.order_id",
            "$.prepared.input.order_id",
            "ACC_COMPILE_ACTION_PREPARED_REFERENCE_IN_PREVIEW",
        ),
        (
            "$.input.order_id",
            "$.prepared.secret.order_id",
            "ACC_COMPILE_ACTION_PREPARED_REFERENCE_INVALID",
        ),
        (
            "$.input.order_id",
            "$.input.order_id",
            "ACC_COMPILE_ACTION_UNPREPARED_MUTATION_INPUT",
        ),
    ],
)
def test_prepared_references_are_phase_and_namespace_restricted(
    preview_reference: str,
    commit_reference: str,
    code: str,
) -> None:
    capability = _capability(
        preview=[_call("orders.get", preview_reference), {"emit": {"value": None}}],
        commit=[_call("orders.update", commit_reference), {"emit": {"value": None}}],
    )
    report = prove_action_capability(capability, _valid_operations())
    assert code in _codes(report)


def test_unknown_operations_remain_visible_and_fail_the_proof() -> None:
    report = prove_action_capability(
        _capability(commit=[_call("orders.missing"), {"emit": {"value": None}}]),
        _valid_operations(),
    )
    assert "ACC_COMPILE_ACTION_OPERATION_NOT_FOUND" in _codes(report)
    assert not report.ok


def test_mutation_arguments_cannot_depend_on_fresh_commit_step_output() -> None:
    commit: list[dict[str, object]] = [
        _call("orders.get", "$.prepared.input.order_id"),
        _call("orders.update", "$.steps.orders_get.order_id"),
        {"emit": {"value": "$.steps.orders_update"}},
    ]

    report = prove_action_capability(_capability(commit=commit), _valid_operations())

    assert "ACC_COMPILE_ACTION_FRESH_STEP_MUTATION_INPUT" in _codes(report)
    assert not report.ok


def test_delete_risk_is_not_inferred_from_http_method_but_still_requires_approval() -> None:
    operations = {
        "orders.get": _operation("orders.get", effect="read"),
        "orders.update": _operation(
            "orders.update",
            effect="delete",
            risk="low",
            reversibility="reversible",
            method="DELETE",
        ),
    }

    report = prove_action_capability(_capability(approval="not_required"), operations)

    assert "ACC_COMPILE_ACTION_SAFETY_PROVENANCE_REQUIRED" not in _codes(report)
    assert "ACC_COMPILE_ACTION_APPROVAL_REQUIRED" in _codes(report)
    assert not report.ok


@pytest.mark.parametrize("mode", ["source_transaction", "saga"])
def test_future_multi_mutation_modes_fail_closed_until_implemented(mode: str) -> None:
    report = prove_action_capability(_capability(execution_mode=mode), _valid_operations())
    assert "ACC_COMPILE_ACTION_EXECUTION_MODE_UNSUPPORTED" in _codes(report)


def _with_operation_schemas(
    operation: ReadOperationV2 | ActionOperationV2,
    *,
    input_schema: dict[str, object],
    output_schema: dict[str, object] | None = None,
    context_bindings: dict[str, str] | None = None,
) -> ReadOperationV2 | ActionOperationV2:
    document = operation.model_dump(mode="json", by_alias=True)
    document["input_schema"] = input_schema
    if output_schema is not None:
        document["output_schema"] = output_schema
    document["context_bindings"] = context_bindings or {}
    http = cast(dict[str, Any], document["http"])
    properties = cast(dict[str, object], input_schema.get("properties", {}))
    http["path"] = "/jobs/status"
    http["path_parameters"] = {}
    http["query_parameters"] = {name: name for name in properties}
    return (
        ReadOperationV2.model_validate(document)
        if isinstance(operation, ReadOperationV2)
        else ActionOperationV2.model_validate(document)
    )


def _status_binding_fixture(
    bindings: list[dict[str, str]],
    *,
    status_input_schema: dict[str, object] | None = None,
    context_bindings: dict[str, str] | None = None,
) -> tuple[ActionCapabilityV2, dict[str, OperationV2], ActionSemantics]:
    mutation = _server_serialized_operation()
    preview_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "data": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
            },
            "routing": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"region": {"type": "string"}},
                "required": ["region"],
            },
        },
        "required": ["data", "routing"],
    }
    status = _with_operation_schemas(
        _operation("jobs.status", effect="read"),
        input_schema=status_input_schema
        or {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "job_id": {"type": "string"},
                "region": {"type": "string"},
            },
            "required": ["job_id", "region"],
        },
        output_schema=preview_schema,
        context_bindings=context_bindings,
    )
    capability_document = _capability(
        preview=[
            {
                "id": "jobs_status",
                "call": {
                    "operation": "jobs.status",
                    "arguments": {
                        "job_id": "$.input.item_id",
                        "region": "$.input.requested_region",
                    },
                },
            },
            {"emit": {"value": "$.steps.jobs_status"}},
        ],
        commit=[_call("jobs.cancel"), {"emit": {"value": None}}],
    ).model_dump(mode="json", by_alias=True)
    capability_document["input_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "item_id": {"type": "string"},
            "requested_region": {"type": "string"},
        },
        "required": ["item_id", "requested_region"],
    }
    capability_document["output_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"result": {"type": "string"}},
        "required": ["result"],
    }
    capability = ActionCapabilityV2.model_validate(capability_document)
    semantics_document = _server_serialized_semantics(mutation).model_dump(mode="json")
    outcome = cast(dict[str, object], semantics_document["outcome_resolution"])
    outcome["request_bindings"] = bindings
    semantics = ActionSemantics.model_validate(semantics_document)
    return capability, {"jobs.status": status, "jobs.cancel": mutation}, semantics


def test_status_query_explicit_bindings_support_renamed_and_preview_derived_inputs() -> None:
    capability, operations, semantics = _status_binding_fixture(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/item_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/routing/region",
            },
        ]
    )

    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": semantics},
        policy=_policy(),
    )

    assert proof.ok
    attestation = action_compiler.compile_action_semantics_attestation(
        cast(ActionOperationV2, operations["jobs.cancel"]),
        semantics,
    )
    summary = cast(dict[str, Any], attestation["summary"])
    outcome = cast(dict[str, Any], summary["outcome_resolution"])
    assert outcome["request_bindings"][0]["source_pointer"] == "/item_id"


def test_status_query_binding_proof_is_not_limited_to_server_serialized_actions() -> None:
    mutation = _operation("orders.update", effect="update")
    assert isinstance(mutation, ActionOperationV2)
    semantics_document: dict[str, Any] = {
        "method": mutation.http.method,
        **mutation.http.safety.model_dump(mode="json"),
        "outcome_resolution": {
            "mode": "status_query",
            "operation_id": "orders.get",
        },
        "evidence": mutation.evidence[0].model_dump(mode="json"),
        "authority": "implementation",
    }
    semantics = ActionSemantics.model_validate(semantics_document)

    proof = prove_action_capability(
        _capability(),
        {
            "orders.get": _operation("orders.get", effect="read"),
            "orders.update": mutation,
        },
        action_semantics={"orders.update": semantics},
    )

    assert proof.ok
    assert proof.strategy_operation_ids == ("orders.get",)


def test_status_query_rejects_optional_binding_sources_even_for_optional_targets() -> None:
    capability, operations, semantics = _status_binding_fixture(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/item_id",
            },
            {
                "target": "region",
                "source": "capability_input",
                "source_pointer": "/requested_region",
            },
        ],
        status_input_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "job_id": {"type": "string"},
                "region": {"type": "string"},
            },
            "required": ["job_id"],
        },
    )
    capability_document = capability.model_dump(mode="json", by_alias=True)
    input_schema = cast(dict[str, Any], capability_document["input_schema"])
    input_schema["required"] = ["item_id"]
    capability = ActionCapabilityV2.model_validate(capability_document)

    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": semantics},
        policy=_policy(),
    )

    assert "ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_SOURCE_INVALID" in _codes(proof)
    assert not proof.ok


@pytest.mark.parametrize(
    "policy",
    [
        None,
        _policy(readable_fields=["data"], denied_fields=["routing"]),
        _policy(
            redaction_rules=[
                {"path": "routing.region", "strategy": "remove"},
            ]
        ),
        _policy(
            redaction_rules=[
                {"path": "routing.region", "strategy": "mask"},
            ]
        ),
        _policy(
            redaction_rules=[
                {"path": "routing.region", "strategy": "hash"},
            ]
        ),
    ],
)
def test_prepared_preview_binding_requires_unmodified_policy_disclosure(
    policy: Policy | None,
) -> None:
    capability, operations, semantics = _status_binding_fixture(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/item_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/routing/region",
            },
        ]
    )

    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": semantics},
        policy=policy,
    )

    assert "ACC_COMPILE_ACTION_STATUS_QUERY_PREVIEW_NOT_PUBLIC" in _codes(proof)
    assert not proof.ok


@pytest.mark.parametrize(
    ("bindings", "status_input_schema", "context_bindings", "code"),
    [
        (
            [
                {
                    "target": "missing",
                    "source": "capability_input",
                    "source_pointer": "/item_id",
                }
            ],
            None,
            None,
            "ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_TARGET_INVALID",
        ),
        (
            [
                {
                    "target": "tenant_id",
                    "source": "capability_input",
                    "source_pointer": "/item_id",
                }
            ],
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"tenant_id": {"type": "string"}},
                "required": ["tenant_id"],
            },
            {"tenant_id": "tenant_context.tenant_id"},
            "ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_CONTEXT_FORBIDDEN",
        ),
        (
            [
                {
                    "target": "job_id",
                    "source": "capability_input",
                    "source_pointer": "/unknown",
                },
                {
                    "target": "region",
                    "source": "prepared_preview",
                    "source_pointer": "/routing/region",
                },
            ],
            None,
            None,
            "ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_SOURCE_INVALID",
        ),
        (
            [
                {
                    "target": "job_id",
                    "source": "capability_input",
                    "source_pointer": "/item_id",
                },
                {
                    "target": "region",
                    "source": "capability_input",
                    "source_pointer": "/item_id",
                },
            ],
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "job_id": {"type": "string"},
                    "region": {"type": "integer"},
                },
                "required": ["job_id", "region"],
            },
            None,
            "ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_SCHEMA_UNPROVEN",
        ),
        (
            [
                {
                    "target": "job_id",
                    "source": "capability_input",
                    "source_pointer": "/item_id",
                }
            ],
            None,
            None,
            "ACC_COMPILE_ACTION_STATUS_QUERY_REQUIRED_INPUT_UNBOUND",
        ),
    ],
)
def test_status_query_bindings_fail_closed_when_not_constructible(
    bindings: list[dict[str, str]],
    status_input_schema: dict[str, object] | None,
    context_bindings: dict[str, str] | None,
    code: str,
) -> None:
    capability, operations, semantics = _status_binding_fixture(
        bindings,
        status_input_schema=status_input_schema,
        context_bindings=context_bindings,
    )

    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"jobs.cancel": semantics},
    )

    assert code in _codes(proof)
    assert not proof.ok
