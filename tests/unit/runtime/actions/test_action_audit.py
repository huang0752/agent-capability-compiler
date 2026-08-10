from __future__ import annotations

import traceback
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import cast

import pytest
from pydantic import JsonValue

from acc_core.compiler.actions import ActionProof
from acc_core.models.v2 import ActionCapabilityV2
from acc_runtime.actions import (
    ActionAuditEvent,
    ActionAuditSink,
    ActionAuditUnavailableError,
    ActionCommitExecution,
    ActionCoordinator,
    ActionDeploymentConfigurationError,
    ActionPreviewExecution,
    ActionStateConflictError,
    ActionWorkflowExecutor,
    CompiledActionDefinition,
    InMemoryActionStore,
    InMemoryApprovalAuthority,
    PreparedActionStatus,
)
from acc_runtime.context import PrincipalContext
from acc_runtime.deployment import DeploymentPolicy

PACK_DIGEST = "sha256:" + "a" * 64


def _capability() -> ActionCapabilityV2:
    return ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.update",
            "title": "Update order",
            "description": "Preview and update one order.",
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
            "preview_workflow": [{"emit": {"value": None}}],
            "commit_workflow": [{"emit": {"value": None}}],
            "policy": "orders-write",
            "evals": ["orders-update-success"],
        }
    )


def _proof() -> ActionProof:
    return ActionProof(
        diagnostics=(),
        mutation_operation_ids=("orders.update",),
        effects=("update",),
        maximum_risk="medium",
        required_scopes=("orders.write",),
        approval_required=True,
    )


def _principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="user-private",
        gateway_session_id="session-private",
        target_system_id="orders",
        source_scopes={"orders.write"},
        deployment_scope_ceiling={"orders.write"},
        scope_mapping={"orders.write": {"orders.write"}},
        tenant_context=None,
        auth_state_handle="auth-private",
    )


@dataclass
class _Executor(ActionWorkflowExecutor):
    fail_commit: bool = False
    commit_calls: list[ActionCommitExecution] = field(default_factory=list)
    verified_definitions: dict[str, CompiledActionDefinition] = field(default_factory=dict)

    def verified_definition(self, capability_id: str) -> CompiledActionDefinition:
        return self.verified_definitions[capability_id]

    async def preview(
        self,
        capability: ActionCapabilityV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionPreviewExecution:
        del capability, arguments, principal_context
        return ActionPreviewExecution(
            value={"status": "pending", "business_secret": "preview-private"},
            concurrency_token="etag-private",
        )

    async def commit(
        self,
        capability: ActionCapabilityV2,
        execution: ActionCommitExecution,
        principal_context: PrincipalContext,
    ) -> JsonValue:
        del capability, principal_context
        self.commit_calls.append(execution)
        if self.fail_commit:
            raise RuntimeError("provider-private")
        return cast(JsonValue, {"status": "approved", "result_secret": "result-private"})


@dataclass
class _Sink(ActionAuditSink):
    events: list[ActionAuditEvent] = field(default_factory=list)
    fail: bool = False
    fail_categories: set[str] = field(default_factory=set)
    fail_events: set[tuple[str, str]] = field(default_factory=set)

    async def emit(self, event: ActionAuditEvent) -> None:
        if (
            self.fail
            or event.result_category in self.fail_categories
            or (event.lifecycle, event.result_category) in self.fail_events
        ):
            raise RuntimeError("audit-private")
        self.events.append(event)


def _store() -> InMemoryActionStore:
    return InMemoryActionStore(
        development_only=True,
        deployment_salt=b"audit-store-development-salt",
        clock=lambda: 100.0,
        handle_generator=lambda: "z" * 43,
    )


def _coordinator(
    *,
    policy: DeploymentPolicy,
    sink: ActionAuditSink | None = None,
    executor: _Executor | None = None,
    store: InMemoryActionStore | None = None,
) -> ActionCoordinator:
    capability = _capability()
    definition = CompiledActionDefinition(capability=capability, proof=_proof())
    selected_executor = executor or _Executor()
    selected_executor.verified_definitions[capability.id] = definition
    return ActionCoordinator(
        definitions={capability.id: definition},
        pack_digest=PACK_DIGEST,
        deployment_policy=policy,
        store=store or _store(),
        approval_authority=InMemoryApprovalAuthority(
            development_only=True,
            clock=lambda: 100.0,
            handle_generator=lambda: "y" * 43,
        ),
        executor=selected_executor,
        idempotency_key_generator=lambda: "idempotency-private",
        action_audit_sink=sink,
        action_audit_salt=(None if sink is None else b"audit-identity-deployment-salt"),
    )


def _development_policy(*, audit_mode: str = "best_effort") -> DeploymentPolicy:
    return DeploymentPolicy(
        allowed_effects=frozenset({"read", "update"}),
        max_risk="medium",
        capability_allowlist=frozenset({"orders.update"}),
        require_durable_action_store=False,
        action_audit_mode=audit_mode,  # type: ignore[arg-type]
    )


def test_coordinator_fails_closed_for_nondurable_store_or_missing_required_audit() -> None:
    with pytest.raises(ActionDeploymentConfigurationError):
        _coordinator(policy=DeploymentPolicy())

    with pytest.raises(ActionDeploymentConfigurationError):
        _coordinator(policy=_development_policy(audit_mode="required"))


async def _prepare_and_approve(
    coordinator: ActionCoordinator,
    principal: PrincipalContext,
) -> object:
    prepared = await coordinator.prepare("orders.update", {"order_id": "order-1"}, principal)
    binding = await coordinator.approval_binding_for_trusted_host(prepared.action_handle, principal)
    authority = coordinator._approval_authority
    assert isinstance(authority, InMemoryApprovalAuthority)
    approval = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval, principal)
    return prepared


@pytest.mark.asyncio
async def test_action_lifecycle_emits_only_minimized_stable_events() -> None:
    sink = _Sink()
    coordinator = _coordinator(
        policy=_development_policy(audit_mode="required"),
        sink=sink,
    )
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, principal)
    handle = prepared.action_handle  # type: ignore[attr-defined]
    await coordinator.commit(handle, principal)
    await coordinator.status(handle, principal)

    assert [(event.lifecycle, event.result_category) for event in sink.events] == [
        ("prepare", "started"),
        ("prepare", "success"),
        ("approve", "started"),
        ("approve", "success"),
        ("commit", "started"),
        ("commit", "success"),
        ("status", "started"),
        ("status", "success"),
    ]
    for event in sink.events:
        payload = event.to_dict()
        assert set(payload) == {
            "lifecycle",
            "capability_id",
            "status",
            "result_category",
            "pack_digest",
            "principal_digest",
            "session_digest",
        }
        rendered = repr(event) + repr(payload)
        for secret in (
            "user-private",
            "session-private",
            "order-1",
            "preview-private",
            "result-private",
            "etag-private",
            "idempotency-private",
            "z" * 43,
        ):
            assert secret not in rendered


@pytest.mark.asyncio
async def test_required_audit_start_failure_blocks_mutation() -> None:
    sink = _Sink()
    executor = _Executor()
    store = _store()
    coordinator = _coordinator(
        policy=_development_policy(audit_mode="required"),
        sink=sink,
        executor=executor,
        store=store,
    )
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, principal)
    sink.fail = True

    with pytest.raises(ActionAuditUnavailableError):
        await coordinator.commit(prepared.action_handle, principal)  # type: ignore[attr-defined]

    assert executor.commit_calls == []
    record = await store.inspect_for_testing(prepared.action_handle)  # type: ignore[attr-defined]
    assert record.status is PreparedActionStatus.APPROVED


@pytest.mark.asyncio
async def test_required_final_audit_failure_never_reports_commit_success() -> None:
    sink = _Sink(fail_events={("commit", "success")})
    executor = _Executor()
    store = _store()
    coordinator = _coordinator(
        policy=_development_policy(audit_mode="required"),
        sink=sink,
        executor=executor,
        store=store,
    )
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, principal)

    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)  # type: ignore[attr-defined]

    assert len(executor.commit_calls) == 1
    record = await store.inspect_for_testing(prepared.action_handle)  # type: ignore[attr-defined]
    assert record.status is PreparedActionStatus.SUCCEEDED
    sink.fail_events.clear()
    replay = await coordinator.commit(prepared.action_handle, principal)  # type: ignore[attr-defined]
    assert replay.replayed is True
    assert len(executor.commit_calls) == 1


@pytest.mark.asyncio
async def test_unknown_outcome_is_audited_without_provider_secret() -> None:
    sink = _Sink()
    coordinator = _coordinator(
        policy=_development_policy(audit_mode="required"),
        sink=sink,
        executor=_Executor(fail_commit=True),
    )
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, principal)

    with pytest.raises(ActionStateConflictError) as captured:
        await coordinator.commit(prepared.action_handle, principal)  # type: ignore[attr-defined]

    event = sink.events[-1]
    assert event.lifecycle == "commit"
    assert event.status is PreparedActionStatus.OUTCOME_UNKNOWN
    assert event.result_category == "outcome_unknown"
    assert "provider-private" not in repr(event)
    assert "provider-private" not in "".join(traceback.format_exception(captured.value))


@pytest.mark.asyncio
async def test_best_effort_audit_failure_does_not_change_business_result() -> None:
    sink = _Sink(fail=True)
    executor = _Executor()
    coordinator = _coordinator(
        policy=_development_policy(audit_mode="best_effort"),
        sink=sink,
        executor=executor,
    )
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, principal)
    result = await coordinator.commit(prepared.action_handle, principal)  # type: ignore[attr-defined]

    assert result.status is PreparedActionStatus.SUCCEEDED
    assert len(executor.commit_calls) == 1


@pytest.mark.asyncio
async def test_required_audit_error_and_traceback_never_echo_sink_secret() -> None:
    sink = _Sink(fail=True)
    coordinator = _coordinator(
        policy=_development_policy(audit_mode="required"),
        sink=sink,
    )
    business_secret = "order-" + "1"

    with pytest.raises(ActionAuditUnavailableError) as captured:
        await coordinator.prepare("orders.update", {"order_id": business_secret}, _principal())

    rendered = str(captured.value) + "".join(traceback.format_exception(captured.value))
    assert "audit-private" not in rendered
    assert business_secret not in rendered
