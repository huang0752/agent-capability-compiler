from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

import pytest

from acc_core.compiler import actions as action_compiler
from acc_core.compiler.actions import ActionProof, prove_action_capability
from acc_core.contracts import ActionSemantics
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
) -> ReadOperationV2 | ActionOperationV2:
    read = effect == "read"
    safety: dict[str, object] = {
        "effect": effect,
        "risk": risk,
        "reversibility": reversibility,
        "retry": {"mode": "idempotent_only" if read or idempotency == "source_key" else "never"},
        "idempotency": (
            {"mode": "unsupported"}
            if read or idempotency == "unsupported"
            else {
                "mode": "source_key",
                "target": {"kind": "header", "name": "Idempotency-Key"},
            }
        ),
        "concurrency": (
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
