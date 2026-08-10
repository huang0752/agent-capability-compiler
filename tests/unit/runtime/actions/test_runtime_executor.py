from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

import pytest
from pydantic import JsonValue

from acc_core.compiler.actions import (
    compile_action_semantics_attestation,
    prove_action_capability,
)
from acc_core.contracts import ActionSemantics
from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionOperationV2,
    OperationV2,
    ReadOperationV2,
)
from acc_runtime.actions.coordinator import ActionCommitExecution
from acc_runtime.actions.runtime_executor import (
    ActionOperationProvider,
    ActionReadResult,
    ActionRuntimeConfigurationError,
    RuntimeActionWorkflowExecutor,
)
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.execution import ExecutionError
from acc_runtime.policies import PolicyScopeDeniedError


def test_runtime_action_executor_has_public_action_api_exports() -> None:
    import acc_runtime.actions as public_actions

    assert public_actions.ActionOperationProvider is ActionOperationProvider
    assert public_actions.ActionReadResult is ActionReadResult
    assert public_actions.ActionRuntimeConfigurationError is ActionRuntimeConfigurationError
    assert public_actions.RuntimeActionWorkflowExecutor is RuntimeActionWorkflowExecutor


def test_runtime_executor_exposes_only_ir_verified_action_definition() -> None:
    executor = RuntimeActionWorkflowExecutor(_ir(), provider=_Provider())

    definition = executor.verified_definition("orders.change")

    assert definition.capability.id == "orders.change"
    assert definition.proof.effects == ("update",)
    assert definition.proof.maximum_risk == "medium"
    assert definition.proof.required_scopes == ("orders.read", "orders.write")
    assert definition.proof_digest.startswith("sha256:")


def _evidence() -> list[dict[str, object]]:
    return [
        {
            "source_id": "orders-source",
            "kind": "source_file",
            "path": "src/orders.py",
            "line_start": 1,
            "line_end": 20,
            "digest": "sha256:" + "a" * 64,
        }
    ]


def _safety(*, read: bool) -> dict[str, object]:
    if read:
        return {
            "effect": "read",
            "risk": "low",
            "reversibility": "reversible",
            "retry": {"mode": "idempotent_only"},
            "idempotency": {"mode": "unsupported"},
            "concurrency": {"mode": "not_supported"},
        }
    return {
        "effect": "update",
        "risk": "medium",
        "reversibility": "reversible",
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


def _operation(*, read: bool) -> dict[str, object]:
    operation_id = "orders.get" if read else "orders.update"
    properties: dict[str, object] = {
        "order_id": {"type": "string"},
        "tenant_id": {"type": "string"},
    }
    required = ["order_id", "tenant_id"]
    if not read:
        properties["expected_status"] = {"type": "string"}
        required.append("expected_status")
    return {
        "schema_version": "2",
        "kind": "read" if read else "action",
        "id": operation_id,
        "title": operation_id,
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "order_id": {"type": "string"},
                "status": {"type": "string"},
                "version": {"type": "integer"},
                "internal": {"type": "string"},
            },
            "required": ["order_id", "status", "version"],
        },
        "http": {
            "method": "GET" if read else "POST",
            "path": "/orders/{order_id}" if read else "/orders/{order_id}/status",
            "path_parameters": {"order_id": "order_id"},
            "query_parameters": {"tenant": "tenant_id"},
            "request": (
                None
                if read
                else {
                    "kind": "json",
                    "body_parameters": {"/expected_status": "expected_status"},
                    "max_request_bytes": 1024,
                }
            ),
            "success": {"statuses": [200], "body": "json"},
            "scopes": ["orders.read" if read else "orders.write"],
            "timeout_seconds": 15,
            "max_response_bytes": 4096,
            "safety": _safety(read=read),
        },
        "context_bindings": {"tenant_id": "tenant_context.tenant_id"},
        "evidence": _evidence(),
    }


def _capability_document() -> dict[str, object]:
    output_schema = cast(dict[str, object], _operation(read=False)["output_schema"])
    return {
        "schema_version": "2",
        "kind": "action",
        "id": "orders.change",
        "title": "Change order",
        "description": "Preview and change one order.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "order_id": {"type": "string"},
                "idempotency_key": {"type": "string"},
                "concurrency_token": {"type": "string"},
            },
            "required": ["order_id"],
        },
        "output_schema": output_schema,
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
                "id": "changed",
                "call": {
                    "operation": "orders.update",
                    "arguments": {
                        "order_id": "$.prepared.input.order_id",
                        "expected_status": "$.prepared.preview.status",
                    },
                },
            },
            {"emit": {"value": "$.steps.changed"}},
        ],
        "policy": "orders-write",
        "evals": ["orders-change-success"],
    }


def _action_proof() -> dict[str, object]:
    capability = ActionCapabilityV2.model_validate(_capability_document())
    operations: dict[str, OperationV2] = {
        "orders.get": ReadOperationV2.model_validate(_operation(read=True)),
        "orders.update": ActionOperationV2.model_validate(_operation(read=False)),
    }
    proof = prove_action_capability(capability, operations)
    mutation = operations["orders.update"]
    assert isinstance(mutation, ActionOperationV2)
    semantics = ActionSemantics.model_validate(
        {
            "method": mutation.http.method,
            **mutation.http.safety.model_dump(mode="json"),
            "evidence": mutation.evidence[0].model_dump(mode="json"),
            "authority": "implementation",
        }
    )
    return {
        "approval_required": proof.approval_required,
        "effects": list(proof.effects),
        "maximum_risk": proof.maximum_risk,
        "mutation_operation_ids": list(proof.mutation_operation_ids),
        "operation_semantics": {
            "orders.update": compile_action_semantics_attestation(mutation, semantics)
        },
        "required_scopes": list(proof.required_scopes),
    }


def _ir() -> dict[str, Any]:
    capability = _capability_document()
    return {
        "ir_version": "2",
        "project": {
            "schema_version": "2",
            "project": {"id": "orders-system", "version": "2.0.0"},
            "source_workspace": {"path": "/srv/orders", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "ORDERS_URL",
                "context_binding_allowlist": ["tenant_context.tenant_id"],
            },
            "quality": {"profile": "standard"},
        },
        "operations": {
            "orders.get": _operation(read=True),
            "orders.update": _operation(read=False),
        },
        "policies": {
            "orders-write": {
                "schema_version": "2",
                "id": "orders-write",
                "required_scopes": [],
                "tenant_mode": "required",
                "tenant_field": "tenant_id",
                "readable_fields": ["order_id", "status", "version"],
                "denied_fields": ["internal"],
                "redaction_rules": [],
            }
        },
        "capabilities": {
            "orders.change": {
                "definition": capability,
                "operation_dependencies": ["orders.get", "orders.update"],
                "action_proof": _action_proof(),
            }
        },
    }


def _principal(*, scopes: set[str] | None = None) -> PrincipalContext:
    granted = {"orders.read", "orders.write"} if scopes is None else scopes
    return PrincipalContext(
        principal_id="user-a",
        gateway_session_id="session-a",
        target_system_id="orders-system",
        source_scopes=granted,
        deployment_scope_ceiling=granted,
        scope_mapping={scope: {scope} for scope in granted},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle="auth-user-a",
    )


@dataclass
class _Provider(ActionOperationProvider):
    read_calls: list[tuple[ReadOperationV2, dict[str, JsonValue], PrincipalContext]] = field(
        default_factory=list
    )
    action_calls: list[
        tuple[
            ActionOperationV2,
            dict[str, JsonValue],
            PrincipalContext,
            SecretValue,
            JsonValue,
        ]
    ] = field(default_factory=list)

    async def call_read(
        self,
        operation: ReadOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionReadResult:
        self.read_calls.append((operation, dict(arguments), principal_context))
        return ActionReadResult(
            value={
                "order_id": arguments["order_id"],
                "status": "pending",
                "version": 3,
                "internal": "provider-private",
            },
            response_headers={"ETag": "etag-v3"},
        )

    async def call_action(
        self,
        operation: ActionOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
        *,
        idempotency_key: SecretValue,
        concurrency_token: JsonValue,
    ) -> JsonValue:
        self.action_calls.append(
            (
                operation,
                dict(arguments),
                principal_context,
                idempotency_key,
                concurrency_token,
            )
        )
        return {
            "order_id": arguments["order_id"],
            "status": "approved",
            "version": 4,
            "internal": "provider-private",
        }


@pytest.mark.asyncio
async def test_preview_executes_compiled_read_workflow_with_policy_and_context() -> None:
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(_ir(), provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())

    preview = await executor.preview(capability, {"order_id": "order-1"}, _principal())

    assert preview.value == {"order_id": "order-1", "status": "pending", "version": 3}
    assert preview.concurrency_token == "etag-v3"
    operation, arguments, principal = provider.read_calls[0]
    assert operation.id == "orders.get"
    assert arguments == {"order_id": "order-1", "tenant_id": "tenant-a"}
    assert principal.principal_id == "user-a"


@pytest.mark.asyncio
async def test_commit_uses_prepared_context_and_separate_runtime_controls() -> None:
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(_ir(), provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())
    execution = ActionCommitExecution(
        input_value={
            "order_id": "order-1",
            "idempotency_key": "agent-evil",
            "concurrency_token": "agent-evil",
        },
        preview_value={"order_id": "order-1", "status": "pending", "version": 3},
        concurrency_token="etag-v3",
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    result = await executor.commit(capability, execution, _principal())

    assert result == {"order_id": "order-1", "status": "approved", "version": 4}
    operation, arguments, principal, idempotency_key, concurrency_token = provider.action_calls[0]
    assert operation.id == "orders.update"
    assert arguments == {
        "order_id": "order-1",
        "expected_status": "pending",
        "tenant_id": "tenant-a",
    }
    assert principal.principal_id == "user-a"
    assert idempotency_key.get_secret_value() == "runtime-idempotency"
    assert concurrency_token == "etag-v3"
    assert "agent-evil" not in repr(provider.action_calls[0])


@pytest.mark.asyncio
async def test_operation_scope_is_enforced_before_provider_call() -> None:
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(_ir(), provider=provider)

    with pytest.raises(PolicyScopeDeniedError):
        await executor.preview(
            ActionCapabilityV2.model_validate(_capability_document()),
            {"order_id": "order-1"},
            _principal(scopes={"orders.write"}),
        )

    assert provider.read_calls == []


@pytest.mark.asyncio
async def test_unknown_or_malformed_compiled_ir_fails_closed() -> None:
    malformed = _ir()
    malformed["operations"]["orders.get"]["kind"] = "unknown"
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(malformed, provider=provider)

    with pytest.raises(ActionRuntimeConfigurationError) as captured:
        await executor.preview(
            ActionCapabilityV2.model_validate(_capability_document()),
            {"order_id": "order-1"},
            _principal(),
        )

    assert captured.value.code == "ACC_RUNTIME_ACTION_CONFIGURATION_INVALID"
    assert provider.read_calls == []


@pytest.mark.asyncio
async def test_runtime_rejects_compiled_action_semantics_that_do_not_match_operation() -> None:
    malformed = _ir()
    malformed["capabilities"]["orders.change"]["action_proof"] = {
        "approval_required": True,
        "effects": ["delete"],
        "maximum_risk": "low",
        "mutation_operation_ids": ["orders.update"],
        "required_scopes": ["orders.read", "orders.write"],
        "operation_semantics": {
            "orders.update": {
                "summary": {
                    "method": "POST",
                    "effect": "delete",
                    "risk": "low",
                    "reversibility": "irreversible",
                    "retry": {"mode": "never"},
                    "idempotency": {"mode": "unsupported", "target": None},
                    "concurrency": {
                        "mode": "not_supported",
                        "token": None,
                        "precondition": None,
                    },
                    "evidence": _evidence()[0],
                    "authority": "contract",
                },
                "digest": "sha256:" + "c" * 64,
            }
        },
    }
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(malformed, provider=provider)

    with pytest.raises(ActionRuntimeConfigurationError):
        await executor.preview(
            ActionCapabilityV2.model_validate(_capability_document()),
            {"order_id": "order-1"},
            _principal(),
        )

    assert provider.read_calls == []
    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_preview_mutation_in_untrusted_ir_is_never_executed() -> None:
    malformed = _ir()
    definition = malformed["capabilities"]["orders.change"]["definition"]
    definition["preview_workflow"][0]["call"]["operation"] = "orders.update"
    capability = ActionCapabilityV2.model_validate(definition)
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(malformed, provider=provider)

    with pytest.raises(ActionRuntimeConfigurationError):
        await executor.preview(capability, {"order_id": "order-1"}, _principal())

    assert provider.read_calls == []
    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_missing_prepared_reference_fails_without_leaking_payload() -> None:
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(_ir(), provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())
    secret = "payload-private"
    execution = ActionCommitExecution(
        input_value={"idempotency_key": secret},
        preview_value={"status": "pending"},
        concurrency_token="etag-v3",
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    with pytest.raises(ExecutionError) as captured:
        await executor.commit(capability, execution, _principal())

    assert secret not in str(captured.value)
    assert secret not in repr(captured.value.to_dict())
    assert provider.action_calls == []
