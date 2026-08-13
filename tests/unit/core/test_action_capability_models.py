from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionContractV2,
    ActionOperationV2,
    ApprovalContractV2,
    CapabilityV2,
    OperationV2,
    ReadCapabilityV2,
    ReadOperationV2,
)
from acc_core.schemas.export import schema_for

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _evidence() -> list[dict[str, object]]:
    return [
        {
            "source_id": "orders-controller",
            "path": "src/orders.py",
            "line_start": 10,
            "line_end": 30,
            "digest": "sha256:" + "a" * 64,
        }
    ]


def _read_safety() -> dict[str, object]:
    return {
        "effect": "read",
        "risk": "low",
        "reversibility": "reversible",
        "retry": {"mode": "idempotent_only"},
        "idempotency": {"mode": "unsupported"},
        "concurrency": {"mode": "not_supported"},
    }


def _action_safety(effect: str = "transition") -> dict[str, object]:
    return {
        "effect": effect,
        "risk": "high",
        "reversibility": "irreversible",
        "retry": {"mode": "idempotent_only"},
        "idempotency": {
            "mode": "source_key",
            "target": {"kind": "header", "name": "Idempotency-Key"},
        },
        "concurrency": {
            "mode": "required",
            "token": {"kind": "response_header", "name": "ETag"},
            "precondition": {"kind": "header", "name": "If-Match"},
        },
    }


def _http(
    *,
    method: str,
    path: str,
    safety: dict[str, object],
    request: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "method": method,
        "path": path,
        "path_parameters": ({"order_id": "order_id"} if "{order_id}" in path else {}),
        "query_parameters": {},
        "request": request,
        "success": {"statuses": [200], "body": "json"},
        "scopes": ["orders.read"] if safety["effect"] == "read" else ["orders.approve"],
        "timeout_seconds": 15,
        "max_response_bytes": 1_048_576,
        "safety": safety,
    }


def _operation_document(*, kind: str, effect: str) -> dict[str, object]:
    action = effect != "read"
    return {
        "schema_version": "2",
        "kind": kind,
        "id": "orders.approve" if action else "orders.get",
        "title": "Approve order" if action else "Get order",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
        },
        "http": _http(
            method="POST" if action else "GET",
            path="/api/orders/{order_id}/approve" if action else "/api/orders/{order_id}",
            safety=_action_safety(effect) if action else _read_safety(),
        ),
        "context_bindings": {},
        "evidence": _evidence(),
    }


def _read_capability_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "kind": "read",
        "id": "orders.inspect",
        "title": "Inspect order",
        "description": "Read the current order state.",
        "input_schema": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
        },
        "output_schema": {"type": "object"},
        "workflow": [
            {
                "id": "current",
                "call": {
                    "operation": "orders.get",
                    "arguments": {"order_id": "$.input.order_id"},
                },
            },
            {"emit": {"value": "$.steps.current"}},
        ],
        "policy": "orders-read",
        "evals": ["orders-inspect-success"],
    }


def _action_capability_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "kind": "action",
        "id": "orders.approve",
        "title": "Approve order",
        "description": "Preview and approve one order.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
        },
        "output_schema": {"type": "object"},
        "action": {
            "execution_mode": "single",
            "approval": {"mode": "required"},
            "expires_in_seconds": 300,
        },
        "preview_workflow": [
            {
                "id": "current",
                "call": {
                    "operation": "orders.get",
                    "arguments": {"order_id": "$.input.order_id"},
                },
            },
            {"emit": {"value": "$.steps.current"}},
        ],
        "commit_workflow": [
            {
                "id": "approved",
                "call": {
                    "operation": "orders.approve",
                    "arguments": {"order_id": "$.prepared.input.order_id"},
                },
            },
            {"emit": {"value": "$.steps.approved"}},
        ],
        "policy": "orders-approve",
        "evals": ["orders-approve-success"],
    }


def test_read_and_action_operations_are_explicitly_discriminated() -> None:
    read: OperationV2 = TypeAdapter(OperationV2).validate_python(
        _operation_document(kind="read", effect="read")
    )
    action: OperationV2 = TypeAdapter(OperationV2).validate_python(
        _operation_document(kind="action", effect="transition")
    )

    assert isinstance(read, ReadOperationV2)
    assert isinstance(action, ActionOperationV2)
    assert read.http.safety.effect == "read"
    assert action.http.safety.effect == "transition"


@pytest.mark.parametrize("effect", ["create", "update", "delete", "transition", "execute"])
def test_action_operation_accepts_every_platform_neutral_mutation_effect(effect: str) -> None:
    operation = ActionOperationV2.model_validate(_operation_document(kind="action", effect=effect))
    assert operation.http.safety.effect == effect


def test_operation_kind_cannot_understate_or_overstate_the_effect() -> None:
    with pytest.raises(ValidationError, match="read Operation"):
        ReadOperationV2.model_validate(_operation_document(kind="read", effect="transition"))
    with pytest.raises(ValidationError, match="Action Operation"):
        ActionOperationV2.model_validate(_operation_document(kind="action", effect="read"))


def test_operation_mappings_must_reference_declared_inputs() -> None:
    document = _operation_document(kind="action", effect="update")
    http = document["http"]
    assert isinstance(http, dict)
    http["request"] = {
        "kind": "json",
        "body_parameters": {"/comment": "undeclared_comment"},
        "max_request_bytes": 4096,
    }

    with pytest.raises(ValidationError, match="declared input"):
        ActionOperationV2.model_validate(document)


def test_operation_requires_valid_draft_2020_12_schemas_and_evidence() -> None:
    document = _operation_document(kind="read", effect="read")
    document["input_schema"] = {"type": "not-a-json-schema-type"}
    with pytest.raises(ValidationError, match="Draft 2020-12"):
        ReadOperationV2.model_validate(document)

    no_evidence = _operation_document(kind="read", effect="read")
    no_evidence["evidence"] = []
    with pytest.raises(ValidationError):
        ReadOperationV2.model_validate(no_evidence)


def test_read_capability_has_only_one_read_workflow_shape() -> None:
    capability: CapabilityV2 = TypeAdapter(CapabilityV2).validate_python(
        _read_capability_document()
    )

    assert isinstance(capability, ReadCapabilityV2)
    assert capability.kind == "read"
    assert len(capability.workflow) == 2

    with pytest.raises(ValidationError):
        ReadCapabilityV2.model_validate(
            {**_read_capability_document(), "preview_workflow": [{"emit": {"value": None}}]}
        )


def test_action_capability_requires_separate_nonempty_preview_and_commit_workflows() -> None:
    capability: CapabilityV2 = TypeAdapter(CapabilityV2).validate_python(
        _action_capability_document()
    )

    assert isinstance(capability, ActionCapabilityV2)
    assert capability.action.execution_mode == "single"
    assert capability.action.approval.mode == "required"
    assert len(capability.preview_workflow) == 2
    assert len(capability.commit_workflow) == 2

    for field in ("preview_workflow", "commit_workflow"):
        document = _action_capability_document()
        document[field] = []
        with pytest.raises(ValidationError):
            ActionCapabilityV2.model_validate(document)

    with pytest.raises(ValidationError):
        ActionCapabilityV2.model_validate(
            {**_action_capability_document(), "workflow": [{"emit": {"value": None}}]}
        )


def test_action_contract_has_no_implicit_execution_or_approval_defaults() -> None:
    complete = {
        "execution_mode": "single",
        "approval": {"mode": "required"},
        "expires_in_seconds": 300,
    }
    contract = ActionContractV2.model_validate(complete)
    assert contract.approval == ApprovalContractV2(mode="required")

    for required in ("execution_mode", "approval", "expires_in_seconds"):
        document = dict(complete)
        document.pop(required)
        with pytest.raises(ValidationError):
            ActionContractV2.model_validate(document)


@pytest.mark.parametrize("mode", ["single", "source_transaction", "saga"])
def test_action_contract_preserves_future_execution_modes_for_compiler_proofs(mode: str) -> None:
    contract = ActionContractV2.model_validate(
        {
            "execution_mode": mode,
            "approval": {"mode": "required"},
            "expires_in_seconds": 300,
        }
    )
    assert contract.execution_mode == mode


def test_model_layer_allows_explicit_no_approval_but_does_not_infer_it() -> None:
    contract = ActionContractV2(
        execution_mode="single",
        approval=ApprovalContractV2(mode="not_required"),
        expires_in_seconds=60,
    )
    assert contract.approval.mode == "not_required"


def test_capability_schemas_are_strict_draft_2020_12_documents() -> None:
    document = _action_capability_document()
    document["output_schema"] = {"required": "not-an-array"}
    with pytest.raises(ValidationError, match="Draft 2020-12"):
        ActionCapabilityV2.model_validate(document)


def test_checked_in_capability_schema_matches_current_model() -> None:
    checked_in = json.loads(
        (REPOSITORY_ROOT / "schemas" / "capability.schema.json").read_text(encoding="utf-8")
    )

    assert checked_in == schema_for("capability")
    assert "local_development_state_guard" in json.dumps(checked_in)


def test_missing_action_discriminator_or_contract_never_defaults_to_write() -> None:
    missing_kind = _action_capability_document()
    missing_kind.pop("kind")
    with pytest.raises(ValidationError):
        TypeAdapter(CapabilityV2).validate_python(missing_kind)

    missing_contract = _action_capability_document()
    missing_contract.pop("action")
    with pytest.raises(ValidationError):
        ActionCapabilityV2.model_validate(missing_contract)

    operation = _operation_document(kind="action", effect="update")
    operation.pop("kind")
    with pytest.raises(ValidationError):
        TypeAdapter(OperationV2).validate_python(operation)


def test_action_shape_retains_operation_ids_and_prepared_references_for_compiler() -> None:
    capability = ActionCapabilityV2.model_validate(_action_capability_document())
    preview = capability.preview_workflow[0].model_dump(mode="python", by_alias=True)
    commit = capability.commit_workflow[0].model_dump(mode="python", by_alias=True)

    assert preview["call"]["operation"] == "orders.get"
    assert commit["call"]["operation"] == "orders.approve"
    assert commit["call"]["arguments"]["order_id"] == "$.prepared.input.order_id"


def test_all_v2_models_reject_unknown_fields_and_scalar_coercion() -> None:
    with pytest.raises(ValidationError):
        ApprovalContractV2.model_validate({"mode": "required", "extra": True})

    document: dict[str, Any] = _action_capability_document()
    action = document["action"]
    assert isinstance(action, dict)
    action["expires_in_seconds"] = "300"
    with pytest.raises(ValidationError):
        ActionCapabilityV2.model_validate(document)


def test_v2_models_are_available_from_the_public_models_package() -> None:
    from acc_core.models import ActionCapabilityV2 as PublicActionCapabilityV2
    from acc_core.models import OperationV2 as PublicOperationV2

    assert PublicActionCapabilityV2 is ActionCapabilityV2
    assert PublicOperationV2 is OperationV2
