from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import httpx
import pytest
from pydantic import JsonValue

from acc_core.compiler.actions import (
    compile_action_semantics_attestation,
    prove_action_capability,
)
from acc_core.contracts import ActionSemantics
from acc_core.models import Policy
from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionOperationV2,
    OperationV2,
    ReadOperationV2,
)
from acc_runtime.actions.approval import InMemoryApprovalAuthority
from acc_runtime.actions.audit import ActionAuditEvent, ActionAuditSink
from acc_runtime.actions.coordinator import ActionCommitExecution
from acc_runtime.actions.errors import ActionStateConflictError
from acc_runtime.actions.models import PreparedActionStatus
from acc_runtime.actions.resource_lock import (
    ActionResourceLockCapacityError,
    InMemoryActionResourceLock,
)
from acc_runtime.actions.runtime import (
    ActionRuntimeDependencies,
    create_runtime_action_coordinator,
)
from acc_runtime.actions.runtime_executor import (
    ActionOperationProvider,
    ActionReadResult,
    ActionRuntimeConfigurationError,
    RuntimeActionWorkflowExecutor,
)
from acc_runtime.actions.store import InMemoryActionStore
from acc_runtime.auth import NoAuthStrategy
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.deployment import DeploymentPolicy
from acc_runtime.execution import ExecutionError
from acc_runtime.policies import PolicyScopeDeniedError
from acc_runtime.providers import HttpProvider, HttpUpstreamError


def test_runtime_action_executor_has_public_action_api_exports() -> None:
    import acc_runtime.actions as public_actions

    assert public_actions.ActionOperationProvider is ActionOperationProvider
    assert public_actions.ActionReadResult is ActionReadResult
    assert public_actions.ActionRuntimeConfigurationError is ActionRuntimeConfigurationError
    assert public_actions.RuntimeActionWorkflowExecutor is RuntimeActionWorkflowExecutor
    assert public_actions.ActionRuntimeDependencies is ActionRuntimeDependencies
    assert public_actions.create_runtime_action_coordinator is create_runtime_action_coordinator


@dataclass
class _ActionAudit(ActionAuditSink):
    events: list[ActionAuditEvent] = field(default_factory=list)

    async def emit(self, event: ActionAuditEvent) -> None:
        self.events.append(event)


def test_runtime_action_factory_derives_definitions_only_from_compiled_ir() -> None:
    coordinator = create_runtime_action_coordinator(
        _ir(),
        pack_digest="sha256:" + "a" * 64,
        provider=_Provider(),
        dependencies=ActionRuntimeDependencies(
            deployment_policy=DeploymentPolicy(
                allowed_effects=frozenset({"read", "update"}),
                max_risk="medium",
                capability_allowlist=frozenset({"orders.change"}),
                require_durable_action_store=False,
                action_audit_mode="required",
            ),
            store=InMemoryActionStore(development_only=True),
            approval_authority=InMemoryApprovalAuthority(development_only=True),
            audit_sink=_ActionAudit(),
            audit_salt=b"test-action-audit-identity-salt",
        ),
    )

    manifest = coordinator.public_manifest()
    capabilities = cast(list[dict[str, JsonValue]], manifest["capabilities"])

    assert [item["capability_id"] for item in capabilities] == ["orders.change"]
    assert manifest["pack_digest"] == "sha256:" + "a" * 64


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


def _server_serialized_ir() -> dict[str, Any]:
    ir = _ir()
    mutation_document = ir["operations"]["orders.update"]
    mutation_document["http"]["safety"] = {
        "effect": "transition",
        "risk": "medium",
        "reversibility": "reversible",
        "retry": {"mode": "never"},
        "idempotency": {
            "mode": "state_idempotent",
            "state_pointer": "/status",
            "terminal_values": ["approved"],
        },
        "concurrency": {
            "mode": "server_serialized_state_predicate",
            "read_operation_id": "orders.get",
            "state_pointer": "/status",
            "allowed_values": ["pending"],
        },
    }
    capability = ActionCapabilityV2.model_validate(
        ir["capabilities"]["orders.change"]["definition"]
    )
    operations: dict[str, OperationV2] = {
        "orders.get": ReadOperationV2.model_validate(ir["operations"]["orders.get"]),
        "orders.update": ActionOperationV2.model_validate(mutation_document),
    }
    mutation = operations["orders.update"]
    assert isinstance(mutation, ActionOperationV2)
    evidence = mutation.evidence[0].model_dump(mode="json")
    fields = [
        "conflict_control",
        "effect",
        "idempotency",
        "outcome_resolution",
        "reversibility",
        "retry",
        "risk",
    ]
    semantics = ActionSemantics.model_validate(
        {
            "method": mutation.http.method,
            **mutation.http.safety.model_dump(mode="json"),
            "outcome_resolution": {
                "mode": "status_query",
                "operation_id": "orders.get",
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
    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"orders.update": semantics},
        policy=Policy.model_validate(ir["policies"]["orders-write"]),
    )
    assert proof.ok
    ir["capabilities"]["orders.change"]["action_proof"] = {
        "approval_required": proof.approval_required,
        "effects": list(proof.effects),
        "maximum_risk": proof.maximum_risk,
        "mutation_operation_ids": list(proof.mutation_operation_ids),
        "operation_semantics": {
            "orders.update": compile_action_semantics_attestation(mutation, semantics)
        },
        "required_scopes": list(proof.required_scopes),
    }
    ir["capabilities"]["orders.change"]["operation_dependencies"] = [
        "orders.get",
        "orders.update",
    ]
    return ir


def _source_key_outcome_ir() -> dict[str, Any]:
    ir = _ir()
    status_document = _operation(read=True)
    status_document["id"] = "orders.outcome"
    status_document["title"] = "orders.outcome"
    status_document["input_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "idempotency_key": {"type": "string"},
            "tenant_id": {"type": "string"},
        },
        "required": ["idempotency_key", "tenant_id"],
    }
    status_http = cast(dict[str, object], status_document["http"])
    status_http["path"] = "/action-outcomes/{idempotency_key}"
    status_http["path_parameters"] = {"idempotency_key": "idempotency_key"}
    status_http["query_parameters"] = {"tenant": "tenant_id"}
    ir["operations"]["orders.outcome"] = status_document
    capability = ActionCapabilityV2.model_validate(
        ir["capabilities"]["orders.change"]["definition"]
    )
    operations: dict[str, OperationV2] = {
        operation_id: (
            ReadOperationV2.model_validate(document)
            if document["kind"] == "read"
            else ActionOperationV2.model_validate(document)
        )
        for operation_id, document in ir["operations"].items()
    }
    mutation = operations["orders.update"]
    assert isinstance(mutation, ActionOperationV2)
    semantics = ActionSemantics.model_validate(
        {
            "method": mutation.http.method,
            **mutation.http.safety.model_dump(mode="json"),
            "outcome_resolution": {
                "mode": "status_query",
                "operation_id": "orders.outcome",
                "request_bindings": [
                    {
                        "target": "idempotency_key",
                        "source": "runtime_idempotency_key",
                    }
                ],
                "success_pointer": "/status",
                "success_values": ["approved"],
            },
            "evidence": mutation.evidence[0].model_dump(mode="json"),
            "authority": "implementation",
        }
    )
    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"orders.update": semantics},
        policy=Policy.model_validate(ir["policies"]["orders-write"]),
    )
    assert proof.ok
    ir["capabilities"]["orders.change"]["operation_dependencies"] = [
        "orders.get",
        "orders.outcome",
        "orders.update",
    ]
    ir["capabilities"]["orders.change"]["action_proof"] = {
        "approval_required": proof.approval_required,
        "effects": list(proof.effects),
        "maximum_risk": proof.maximum_risk,
        "mutation_operation_ids": list(proof.mutation_operation_ids),
        "operation_semantics": {
            "orders.update": compile_action_semantics_attestation(mutation, semantics)
        },
        "required_scopes": list(proof.required_scopes),
    }
    return ir


def _local_development_guard_ir() -> dict[str, Any]:
    ir = _ir()
    capability_document = cast(dict[str, Any], ir["capabilities"]["orders.change"]["definition"])
    action = cast(dict[str, Any], capability_document["action"])
    action["local_development_state_guard"] = {
        "mode": "local_development_runtime_guard",
        "resource_key_pointer": "/order_id",
        "read_operation_id": "orders.get",
        "state_pointer": "/status",
        "allowed_values": ["pending", "processing"],
        "terminal_values": ["approved"],
    }
    mutation_document = cast(dict[str, Any], ir["operations"]["orders.update"])
    mutation_document["http"]["safety"] = {
        "effect": "update",
        "risk": "low",
        "reversibility": "reversible",
        "retry": {"mode": "never"},
        "idempotency": {"mode": "runtime_deduplicate"},
        "concurrency": {"mode": "not_supported"},
    }
    capability = ActionCapabilityV2.model_validate(capability_document)
    operations: dict[str, OperationV2] = {
        "orders.get": ReadOperationV2.model_validate(ir["operations"]["orders.get"]),
        "orders.update": ActionOperationV2.model_validate(mutation_document),
    }
    mutation = cast(ActionOperationV2, operations["orders.update"])
    semantics = ActionSemantics.model_validate(
        {
            "method": mutation.http.method,
            **mutation.http.safety.model_dump(mode="json"),
            "evidence": mutation.evidence[0].model_dump(mode="json"),
            "authority": "implementation",
        }
    )
    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"orders.update": semantics},
        policy=Policy.model_validate(ir["policies"]["orders-write"]),
    )
    assert proof.ok
    ir["capabilities"]["orders.change"]["action_proof"] = {
        "approval_required": proof.approval_required,
        "effects": list(proof.effects),
        "maximum_risk": proof.maximum_risk,
        "mutation_operation_ids": list(proof.mutation_operation_ids),
        "operation_semantics": {
            "orders.update": compile_action_semantics_attestation(mutation, semantics)
        },
        "required_scopes": list(proof.required_scopes),
    }
    return ir


def _bound_status_query_ir(
    bindings: list[dict[str, str]],
    *,
    include_region: bool = True,
    include_selectors: bool = False,
) -> dict[str, Any]:
    ir = _server_serialized_ir()
    status_document = cast(dict[str, Any], ir["operations"]["orders.get"])
    status_properties: dict[str, object] = {
        "job_id": {"type": "string"},
        "tenant_id": {"type": "string"},
    }
    required = ["job_id", "tenant_id"]
    if include_region:
        status_properties["region"] = {"type": "string"}
        required.append("region")
    status_document["input_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": status_properties,
        "required": required,
    }
    status_output = cast(dict[str, Any], status_document["output_schema"])
    status_output_properties = cast(dict[str, object], status_output["properties"])
    status_output_properties["routing"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"region": {"type": "string"}},
        "required": ["region"],
    }
    cast(list[str], status_output["required"]).append("routing")
    cast(list[str], status_output["required"]).append("internal")
    if include_selectors:
        status_output_properties["selectors"] = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        }
        cast(list[str], status_output["required"]).append("selectors")
    status_http = cast(dict[str, Any], status_document["http"])
    status_http["path_parameters"] = {"order_id": "job_id"}
    status_http["query_parameters"] = {"tenant": "tenant_id"}
    if include_region:
        status_http["query_parameters"]["region"] = "region"

    capability_document = cast(dict[str, Any], ir["capabilities"]["orders.change"]["definition"])
    output_schema = cast(dict[str, Any], capability_document["output_schema"])
    output_properties = cast(dict[str, object], output_schema["properties"])
    output_properties["routing"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"region": {"type": "string"}},
        "required": ["region"],
    }
    cast(list[str], output_schema["required"]).append("routing")
    if include_selectors:
        output_properties["selectors"] = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        }
        cast(list[str], output_schema["required"]).append("selectors")
    policy_document = cast(dict[str, Any], ir["policies"]["orders-write"])
    cast(list[str], policy_document["readable_fields"]).extend(["routing", "selectors"])

    capability = ActionCapabilityV2.model_validate(capability_document)
    operations: dict[str, OperationV2] = {
        "orders.get": ReadOperationV2.model_validate(status_document),
        "orders.update": ActionOperationV2.model_validate(ir["operations"]["orders.update"]),
    }
    mutation = operations["orders.update"]
    assert isinstance(mutation, ActionOperationV2)
    prior_attestation = cast(
        dict[str, Any],
        ir["capabilities"]["orders.change"]["action_proof"]["operation_semantics"]["orders.update"],
    )
    semantics_document = cast(dict[str, Any], prior_attestation["summary"])
    outcome = cast(dict[str, Any], semantics_document["outcome_resolution"])
    outcome["request_bindings"] = bindings
    semantics = ActionSemantics.model_validate(semantics_document)
    proof = prove_action_capability(
        capability,
        operations,
        action_semantics={"orders.update": semantics},
        policy=Policy.model_validate(ir["policies"]["orders-write"]),
    )
    assert proof.ok
    ir["capabilities"]["orders.change"]["action_proof"] = {
        "approval_required": proof.approval_required,
        "effects": list(proof.effects),
        "maximum_risk": proof.maximum_risk,
        "mutation_operation_ids": list(proof.mutation_operation_ids),
        "operation_semantics": {
            "orders.update": compile_action_semantics_attestation(mutation, semantics)
        },
        "required_scopes": list(proof.required_scopes),
    }
    return ir


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
    read_statuses: list[str] = field(default_factory=lambda: ["pending"])
    action_error: BaseException | None = None
    read_error_on_call: int | None = None
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
        if self.read_error_on_call == len(self.read_calls):
            raise RuntimeError("private-status-query-failure")
        status = self.read_statuses[min(len(self.read_calls) - 1, len(self.read_statuses) - 1)]
        resource_id = arguments.get("order_id", arguments.get("job_id"))
        value: dict[str, JsonValue] = {
            "order_id": resource_id,
            "status": status,
            "version": 3,
            "internal": "provider-private",
        }
        if "region" in arguments:
            value["routing"] = {"region": arguments["region"]}
        return ActionReadResult(
            value=value,
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
        if self.action_error is not None:
            raise self.action_error
        return {
            "order_id": arguments["order_id"],
            "status": "approved",
            "version": 4,
            "internal": "provider-private",
        }


@dataclass
class _StatefulLocalProvider(_Provider):
    status: str = "pending"

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
                "status": self.status,
                "version": 3,
                "internal": "provider-private",
            }
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
        result = await super().call_action(
            operation,
            arguments,
            principal_context,
            idempotency_key=idempotency_key,
            concurrency_token=concurrency_token,
        )
        self.status = "approved"
        return result


@dataclass
class _OutcomeLedgerProvider(_Provider):
    ledger_status: str = "not_found"
    lose_mutation_response: bool = True

    async def call_read(
        self,
        operation: ReadOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionReadResult:
        if operation.id != "orders.outcome":
            return await super().call_read(operation, arguments, principal_context)
        self.read_calls.append((operation, dict(arguments), principal_context))
        return ActionReadResult(
            value={
                "order_id": "order-1",
                "status": self.ledger_status,
                "version": 4,
                "internal": "provider-private",
            }
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
        self.ledger_status = "approved"
        if self.lose_mutation_response:
            raise RuntimeError("private-lost-mutation-response")
        return {
            "order_id": "order-1",
            "status": "approved",
            "version": 4,
            "internal": "provider-private",
        }


def _local_execution(*, key: str = "runtime-idempotency") -> ActionCommitExecution:
    return ActionCommitExecution(
        input_value={"order_id": "order-1"},
        preview_value={"order_id": "order-1", "status": "pending", "version": 3},
        concurrency_token=None,
        idempotency_key=SecretValue(key),
    )


def _local_executor(
    provider: ActionOperationProvider,
) -> tuple[RuntimeActionWorkflowExecutor, ActionCapabilityV2]:
    ir = _local_development_guard_ir()
    executor = RuntimeActionWorkflowExecutor(
        ir,
        provider=provider,
        action_sandbox_mode="local_development",
        resource_lock=InMemoryActionResourceLock(max_entries=8),
    )
    capability = ActionCapabilityV2.model_validate(
        ir["capabilities"]["orders.change"]["definition"]
    )
    return executor, capability


def test_local_development_guard_is_rejected_at_startup_by_default() -> None:
    ir = _local_development_guard_ir()
    executor = RuntimeActionWorkflowExecutor(ir, provider=_Provider())

    with pytest.raises(ActionRuntimeConfigurationError):
        executor.verified_definition("orders.change")


def test_local_development_pack_requires_explicit_deployment_sandbox() -> None:
    with pytest.raises(ActionRuntimeConfigurationError):
        create_runtime_action_coordinator(
            _local_development_guard_ir(),
            pack_digest="sha256:" + "a" * 64,
            provider=_Provider(),
            dependencies=ActionRuntimeDependencies(
                deployment_policy=DeploymentPolicy(
                    allowed_effects=frozenset({"read", "update"}),
                    max_risk="low",
                    require_durable_action_store=False,
                    action_audit_mode="best_effort",
                ),
                store=InMemoryActionStore(development_only=True),
                approval_authority=InMemoryApprovalAuthority(development_only=True),
                audit_sink=_ActionAudit(),
                audit_salt=b"local-development-audit-salt",
                resource_lock=InMemoryActionResourceLock(),
            ),
        )


def test_local_development_pack_loads_with_explicit_sandbox_and_lock() -> None:
    coordinator = create_runtime_action_coordinator(
        _local_development_guard_ir(),
        pack_digest="sha256:" + "a" * 64,
        provider=_Provider(),
        dependencies=ActionRuntimeDependencies(
            deployment_policy=DeploymentPolicy(
                allowed_effects=frozenset({"read", "update"}),
                max_risk="low",
                require_durable_action_store=False,
                action_audit_mode="best_effort",
                action_sandbox_mode="local_development",
            ),
            store=InMemoryActionStore(development_only=True),
            approval_authority=InMemoryApprovalAuthority(development_only=True),
            audit_sink=_ActionAudit(),
            audit_salt=b"local-development-audit-salt",
            resource_lock=InMemoryActionResourceLock(),
        ),
    )

    assert coordinator.public_manifest()["capabilities"]


@pytest.mark.asyncio
async def test_local_development_resource_lock_is_bounded_and_cleans_up() -> None:
    lock = InMemoryActionResourceLock(max_entries=1)
    async with lock.hold("capability:one"):
        with pytest.raises(ActionResourceLockCapacityError):
            async with lock.hold("capability:two"):
                raise AssertionError("capacity guard must fail before entry")
    async with lock.hold("capability:two"):
        pass


@pytest.mark.asyncio
async def test_local_development_commit_rejects_state_drift_before_mutation() -> None:
    provider = _Provider(read_statuses=["processing"])
    executor, capability = _local_executor(provider)

    with pytest.raises(ActionStateConflictError, match="changed after prepare"):
        await executor.commit(capability, _local_execution(), _principal())

    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_local_development_commit_returns_fresh_terminal_without_mutation() -> None:
    provider = _Provider(read_statuses=["approved"])
    executor, capability = _local_executor(provider)

    result = await executor.commit(capability, _local_execution(), _principal())

    assert cast(dict[str, JsonValue], result)["status"] == "approved"
    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_local_development_commit_fails_closed_on_fresh_read_error() -> None:
    provider = _Provider(read_error_on_call=1)
    executor, capability = _local_executor(provider)

    with pytest.raises(ExecutionError, match="Operation caller failed"):
        await executor.commit(capability, _local_execution(), _principal())

    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_local_development_lock_serializes_two_handles_for_same_resource() -> None:
    provider = _StatefulLocalProvider()
    executor, capability = _local_executor(provider)

    first, second = await asyncio.gather(
        executor.commit(capability, _local_execution(key="first"), _principal()),
        executor.commit(capability, _local_execution(key="second"), _principal()),
    )

    assert cast(dict[str, JsonValue], first)["status"] == "approved"
    assert cast(dict[str, JsonValue], second)["status"] == "approved"
    assert len(provider.action_calls) == 1
    assert len(provider.read_calls) == 2


@pytest.mark.asyncio
async def test_local_development_guard_over_real_http_serializes_and_rechecks() -> None:
    class Handler(BaseHTTPRequestHandler):
        state = "pending"
        get_count = 0
        post_count = 0
        fail_reads = False
        state_lock = threading.Lock()

        def do_GET(self) -> None:
            with self.state_lock:
                type(self).get_count += 1
                if type(self).fail_reads:
                    self.send_response(503)
                    self.end_headers()
                    return
                body: dict[str, JsonValue] = {
                    "order_id": "order-1",
                    "status": self.state,
                    "version": 3,
                    "internal": "source-private",
                }
            self._json(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            json.loads(self.rfile.read(length))
            with self.state_lock:
                type(self).post_count += 1
                type(self).state = "approved"
                body: dict[str, JsonValue] = {
                    "order_id": "order-1",
                    "status": "approved",
                    "version": 4,
                    "internal": "source-private",
                }
            self._json(body)

        def _json(self, value: dict[str, JsonValue]) -> None:
            payload = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        async with httpx.AsyncClient() as client:
            provider = HttpProvider(
                base_url_ref="LOCAL_ACTION_URL",
                environment={"LOCAL_ACTION_URL": base_url},
                auth_strategy=NoAuthStrategy(),
                client=client,
            )
            executor, capability = _local_executor(provider)
            first, second = await asyncio.gather(
                executor.commit(capability, _local_execution(key="http-first"), _principal()),
                executor.commit(capability, _local_execution(key="http-second"), _principal()),
            )
            Handler.state = "pending"
            Handler.fail_reads = True
            with pytest.raises(HttpUpstreamError):
                await executor.commit(
                    capability,
                    _local_execution(key="http-error"),
                    _principal(),
                )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert cast(dict[str, JsonValue], first)["status"] == "approved"
    assert cast(dict[str, JsonValue], second)["status"] == "approved"
    assert Handler.post_count == 1
    assert Handler.get_count == 3


@pytest.mark.asyncio
async def test_server_serialized_preview_checks_allowed_state_without_fake_token() -> None:
    provider = _Provider(read_statuses=["pending"])
    executor = RuntimeActionWorkflowExecutor(_server_serialized_ir(), provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())

    preview = await executor.preview(capability, {"order_id": "order-1"}, _principal())

    preview_value = cast(dict[str, JsonValue], preview.value)
    assert preview_value["status"] == "pending"
    assert preview.concurrency_token is None


@pytest.mark.asyncio
async def test_server_serialized_preview_rejects_state_outside_allowed_values() -> None:
    provider = _Provider(read_statuses=["failed"])
    executor = RuntimeActionWorkflowExecutor(_server_serialized_ir(), provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())

    with pytest.raises(ActionStateConflictError, match="state"):
        await executor.preview(capability, {"order_id": "order-1"}, _principal())

    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_server_serialized_runtime_requires_attested_status_dependency() -> None:
    malformed = _server_serialized_ir()
    malformed["capabilities"]["orders.change"]["operation_dependencies"] = ["orders.update"]
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
async def test_server_serialized_commit_mutates_once_then_reads_declared_status() -> None:
    provider = _Provider(read_statuses=["approved"])
    executor = RuntimeActionWorkflowExecutor(_server_serialized_ir(), provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())
    execution = ActionCommitExecution(
        input_value={"order_id": "order-1"},
        preview_value={"order_id": "order-1", "status": "pending", "version": 3},
        concurrency_token=None,
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    result = await executor.commit(capability, execution, _principal())

    result_value = cast(dict[str, JsonValue], result)
    assert result_value["status"] == "approved"
    assert len(provider.action_calls) == 1
    assert provider.action_calls[0][-1] is None
    assert [call[0].id for call in provider.read_calls] == ["orders.get"]


@pytest.mark.asyncio
async def test_status_query_uses_explicit_renamed_and_public_preview_bindings() -> None:
    ir = _bound_status_query_ir(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/order_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/routing/region",
            },
        ]
    )
    provider = _Provider(read_statuses=["approved"])
    executor = RuntimeActionWorkflowExecutor(ir, provider=provider)
    capability = ActionCapabilityV2.model_validate(_capability_document())
    capability = capability.model_copy(
        update={"output_schema": ir["capabilities"]["orders.change"]["definition"]["output_schema"]}
    )
    execution = ActionCommitExecution(
        input_value={"order_id": "order-1"},
        preview_value={
            "order_id": "order-1",
            "status": "pending",
            "version": 3,
            "routing": {"region": "cn-east"},
        },
        concurrency_token=None,
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    result = await executor.commit(capability, execution, _principal())

    assert cast(dict[str, JsonValue], result)["status"] == "approved"
    assert provider.read_calls[0][1] == {
        "job_id": "order-1",
        "region": "cn-east",
        "tenant_id": "tenant-a",
    }


@pytest.mark.asyncio
async def test_status_query_missing_preview_binding_fails_closed_without_data_leak() -> None:
    ir = _bound_status_query_ir(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/order_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/routing/region",
            },
        ]
    )
    provider = _Provider(read_statuses=["approved"])
    executor = RuntimeActionWorkflowExecutor(ir, provider=provider)
    capability = ActionCapabilityV2.model_validate(
        ir["capabilities"]["orders.change"]["definition"]
    )
    private = "private-preview-selector"
    execution = ActionCommitExecution(
        input_value={"order_id": "order-1"},
        preview_value={
            "order_id": "order-1",
            "status": "pending",
            "version": 3,
            "untrusted": private,
        },
        concurrency_token=None,
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    with pytest.raises(ActionRuntimeConfigurationError) as captured:
        await executor.commit(capability, execution, _principal())

    assert private not in str(captured.value)
    assert provider.read_calls == []


@pytest.mark.asyncio
async def test_status_query_cannot_bind_policy_denied_preview_fields() -> None:
    ir = _bound_status_query_ir(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/order_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/routing/region",
            },
        ]
    )
    proof_document = cast(dict[str, Any], ir["capabilities"]["orders.change"]["action_proof"])
    attestations = cast(dict[str, Any], proof_document["operation_semantics"])
    attestation = cast(dict[str, Any], attestations["orders.update"])
    summary = cast(dict[str, Any], attestation["summary"])
    outcome = cast(dict[str, Any], summary["outcome_resolution"])
    bindings = cast(list[dict[str, Any]], outcome["request_bindings"])
    bindings[1]["source_pointer"] = "/internal"
    mutation = ActionOperationV2.model_validate(ir["operations"]["orders.update"])
    attestations["orders.update"] = compile_action_semantics_attestation(
        mutation,
        ActionSemantics.model_validate(summary),
    )
    provider = _Provider(read_statuses=["approved"])
    executor = RuntimeActionWorkflowExecutor(ir, provider=provider)
    capability = ActionCapabilityV2.model_validate(
        ir["capabilities"]["orders.change"]["definition"]
    )
    private = "private-preview-selector"
    execution = ActionCommitExecution(
        input_value={"order_id": "order-1"},
        preview_value={
            "order_id": "order-1",
            "status": "pending",
            "version": 3,
            "routing": {"region": "cn-east"},
            "internal": private,
        },
        concurrency_token=None,
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    with pytest.raises(ActionRuntimeConfigurationError) as captured:
        await executor.commit(capability, execution, _principal())

    assert private not in str(captured.value)
    assert provider.read_calls == []
    assert provider.action_calls == []


@pytest.mark.asyncio
async def test_status_query_array_pointer_fails_closed_when_element_is_missing() -> None:
    ir = _bound_status_query_ir(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/order_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/selectors/0",
            },
        ],
        include_selectors=True,
    )
    provider = _Provider(read_statuses=["approved"])
    executor = RuntimeActionWorkflowExecutor(ir, provider=provider)
    capability = ActionCapabilityV2.model_validate(
        ir["capabilities"]["orders.change"]["definition"]
    )
    execution = ActionCommitExecution(
        input_value={"order_id": "order-1"},
        preview_value={
            "order_id": "order-1",
            "status": "pending",
            "version": 3,
            "selectors": [],
        },
        concurrency_token=None,
        idempotency_key=SecretValue("runtime-idempotency"),
    )

    with pytest.raises(ActionRuntimeConfigurationError):
        await executor.commit(capability, execution, _principal())

    assert provider.read_calls == []


def test_status_query_binding_attestation_tamper_fails_before_provider_call() -> None:
    ir = _bound_status_query_ir(
        [
            {
                "target": "job_id",
                "source": "capability_input",
                "source_pointer": "/order_id",
            },
            {
                "target": "region",
                "source": "prepared_preview",
                "source_pointer": "/routing/region",
            },
        ]
    )
    attestation = ir["capabilities"]["orders.change"]["action_proof"]["operation_semantics"][
        "orders.update"
    ]
    attestation["summary"]["outcome_resolution"]["request_bindings"][0]["source_pointer"] = "/other"
    provider = _Provider()
    executor = RuntimeActionWorkflowExecutor(ir, provider=provider)

    with pytest.raises(ActionRuntimeConfigurationError):
        executor.verified_definition("orders.change")

    assert provider.read_calls == []
    assert provider.action_calls == []


def _server_serialized_coordinator(
    provider: _Provider,
) -> tuple[Any, InMemoryApprovalAuthority]:
    authority = InMemoryApprovalAuthority(development_only=True)
    coordinator = create_runtime_action_coordinator(
        _server_serialized_ir(),
        pack_digest="sha256:" + "a" * 64,
        provider=provider,
        dependencies=ActionRuntimeDependencies(
            deployment_policy=DeploymentPolicy(
                allowed_effects=frozenset({"read", "transition"}),
                max_risk="medium",
                capability_allowlist=frozenset({"orders.change"}),
                require_durable_action_store=False,
                action_audit_mode="best_effort",
            ),
            store=InMemoryActionStore(development_only=True),
            approval_authority=authority,
            audit_sink=_ActionAudit(),
            audit_salt=b"server-serialized-audit-salt",
        ),
    )
    return coordinator, authority


def _source_key_outcome_coordinator(
    provider: _OutcomeLedgerProvider,
    *,
    store: InMemoryActionStore | None = None,
    authority: InMemoryApprovalAuthority | None = None,
) -> tuple[Any, InMemoryApprovalAuthority]:
    selected_authority = authority or InMemoryApprovalAuthority(development_only=True)
    coordinator = create_runtime_action_coordinator(
        _source_key_outcome_ir(),
        pack_digest="sha256:" + "a" * 64,
        provider=provider,
        dependencies=ActionRuntimeDependencies(
            deployment_policy=DeploymentPolicy(
                allowed_effects=frozenset({"read", "update"}),
                max_risk="medium",
                capability_allowlist=frozenset({"orders.change"}),
                require_durable_action_store=False,
                action_audit_mode="best_effort",
            ),
            store=store or InMemoryActionStore(development_only=True),
            approval_authority=selected_authority,
            audit_sink=_ActionAudit(),
            audit_salt=b"source-key-outcome-audit-salt",
        ),
    )
    return coordinator, selected_authority


@pytest.mark.asyncio
async def test_source_key_lost_response_recovers_from_sealed_key_without_replay() -> None:
    provider = _OutcomeLedgerProvider()
    store = InMemoryActionStore(development_only=True)
    coordinator, authority = _source_key_outcome_coordinator(provider, store=store)
    principal = _principal()
    prepared = await coordinator.prepare("orders.change", {"order_id": "order-1"}, principal)
    binding = await coordinator.approval_binding_for_trusted_host(prepared.action_handle, principal)
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)

    with pytest.raises(ActionStateConflictError) as captured:
        await coordinator.commit(prepared.action_handle, principal)

    assert "private-lost-mutation-response" not in str(captured.value)
    assert len(provider.action_calls) == 1
    # Reconstructing the coordinator simulates a Gateway restart; recovery has
    # no caller-provided mutation arguments or idempotency material.
    restarted, _ = _source_key_outcome_coordinator(provider, store=store, authority=authority)
    recovered = await restarted.status(prepared.action_handle, principal)

    assert recovered.status is PreparedActionStatus.SUCCEEDED
    assert recovered.result == {
        "order_id": "order-1",
        "status": "approved",
        "version": 4,
    }
    assert len(provider.action_calls) == 1
    outcome_call = [call for call in provider.read_calls if call[0].id == "orders.outcome"]
    sealed_key = provider.action_calls[0][3].get_secret_value()
    assert outcome_call[-1][1]["idempotency_key"] == sealed_key
    assert sealed_key not in repr(recovered)


@pytest.mark.asyncio
@pytest.mark.parametrize("ledger_status", ["pending", "not_found"])
async def test_source_key_unresolved_ledger_status_stays_unknown(
    ledger_status: str,
) -> None:
    provider = _OutcomeLedgerProvider()
    coordinator, authority = _source_key_outcome_coordinator(provider)
    principal = _principal()
    prepared = await coordinator.prepare("orders.change", {"order_id": "order-1"}, principal)
    binding = await coordinator.approval_binding_for_trusted_host(prepared.action_handle, principal)
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)
    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)
    provider.ledger_status = ledger_status

    unresolved = await coordinator.status(prepared.action_handle, principal)

    assert unresolved.status is PreparedActionStatus.OUTCOME_UNKNOWN
    assert unresolved.result is None
    assert len(provider.action_calls) == 1


@pytest.mark.asyncio
async def test_server_serialized_coordinator_needs_no_token_and_persists_unknown_once() -> None:
    private = "private-server-serialized-failure"
    provider = _Provider(read_statuses=["pending"], action_error=RuntimeError(private))
    coordinator, authority = _server_serialized_coordinator(provider)
    principal = _principal()
    prepared = await coordinator.prepare(
        "orders.change",
        {"order_id": "order-1"},
        principal,
    )
    assert prepared.status is PreparedActionStatus.PREPARED
    binding = await coordinator.approval_binding_for_trusted_host(
        prepared.action_handle,
        principal,
    )
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)

    with pytest.raises(ActionStateConflictError) as captured:
        await coordinator.commit(prepared.action_handle, principal)

    assert private not in str(captured.value)
    assert (await coordinator.status(prepared.action_handle, principal)).status is (
        PreparedActionStatus.OUTCOME_UNKNOWN
    )
    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)
    assert len(provider.action_calls) == 1


@pytest.mark.asyncio
async def test_server_serialized_nonterminal_status_is_unknown_and_never_replayed() -> None:
    provider = _Provider(read_statuses=["pending", "pending"])
    coordinator, authority = _server_serialized_coordinator(provider)
    principal = _principal()
    prepared = await coordinator.prepare(
        "orders.change",
        {"order_id": "order-1"},
        principal,
    )
    binding = await coordinator.approval_binding_for_trusted_host(
        prepared.action_handle,
        principal,
    )
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)

    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)

    assert (await coordinator.status(prepared.action_handle, principal)).status is (
        PreparedActionStatus.OUTCOME_UNKNOWN
    )
    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)
    assert len(provider.action_calls) == 1


@pytest.mark.asyncio
async def test_server_serialized_terminal_preview_is_idempotent_without_mutation() -> None:
    provider = _Provider(read_statuses=["approved"])
    coordinator, authority = _server_serialized_coordinator(provider)
    principal = _principal()
    prepared = await coordinator.prepare(
        "orders.change",
        {"order_id": "order-1"},
        principal,
    )
    binding = await coordinator.approval_binding_for_trusted_host(
        prepared.action_handle,
        principal,
    )
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)

    committed = await coordinator.commit(prepared.action_handle, principal)
    replayed = await coordinator.commit(prepared.action_handle, principal)

    assert committed.status is PreparedActionStatus.SUCCEEDED
    assert replayed.replayed is True
    assert provider.action_calls == []
    assert len(provider.read_calls) == 1


@pytest.mark.asyncio
async def test_server_serialized_status_query_failure_is_unknown_without_replay() -> None:
    provider = _Provider(read_statuses=["pending"], read_error_on_call=2)
    coordinator, authority = _server_serialized_coordinator(provider)
    principal = _principal()
    prepared = await coordinator.prepare(
        "orders.change",
        {"order_id": "order-1"},
        principal,
    )
    binding = await coordinator.approval_binding_for_trusted_host(
        prepared.action_handle,
        principal,
    )
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)

    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)
    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)

    assert (await coordinator.status(prepared.action_handle, principal)).status is (
        PreparedActionStatus.OUTCOME_UNKNOWN
    )
    assert len(provider.action_calls) == 1


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
