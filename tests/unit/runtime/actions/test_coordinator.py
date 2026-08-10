from __future__ import annotations

import asyncio
import traceback
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import cast

import pytest
from pydantic import JsonValue

from acc_core.compiler.actions import ActionProof
from acc_core.models.v2 import ActionCapabilityV2
from acc_runtime.actions import (
    ActionBindingMismatchError,
    ActionStateConflictError,
    InMemoryActionStore,
    InMemoryApprovalAuthority,
    PreparedActionStatus,
)
from acc_runtime.actions.coordinator import (
    ActionCommitExecution,
    ActionCoordinator,
    ActionDeploymentConfigurationError,
    ActionDeploymentDeniedError,
    ActionPreviewExecution,
    ActionPreviewInvalidError,
    ActionScopeDeniedError,
    ActionWorkflowExecutor,
    CompiledActionDefinition,
    PreparedActionPublic,
)
from acc_runtime.actions.errors import ActionExpiredError
from acc_runtime.context import PrincipalContext
from acc_runtime.deployment import DeploymentPolicy

PACK_DIGEST = "sha256:" + "a" * 64
OTHER_PACK_DIGEST = "sha256:" + "b" * 64


def _principal(
    principal_id: str = "user-a",
    *,
    session_id: str = "session-a",
    scopes: set[str] | None = None,
) -> PrincipalContext:
    granted = {"orders.read", "orders.write"} if scopes is None else scopes
    return PrincipalContext(
        principal_id=principal_id,
        gateway_session_id=session_id,
        target_system_id="orders-system",
        source_scopes=granted,
        deployment_scope_ceiling=granted,
        scope_mapping={scope: {scope} for scope in granted},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle=f"auth-{principal_id}-{session_id}",
    )


def _capability(*, approval: str = "required") -> ActionCapabilityV2:
    return ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.update",
            "title": "Update order",
            "description": "Preview and update one order.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "comment": {"type": "string"},
                },
                "required": ["order_id", "comment"],
            },
            "output_schema": {"type": "object"},
            "action": {
                "execution_mode": "single",
                "approval": {"mode": approval},
                "expires_in_seconds": 300,
            },
            "preview_workflow": [{"emit": {"value": None}}],
            "commit_workflow": [{"emit": {"value": None}}],
            "policy": "orders-write",
            "evals": ["orders-update-success"],
        }
    )


def _proof(*, approval_required: bool = True) -> ActionProof:
    return ActionProof(
        diagnostics=(),
        mutation_operation_ids=("orders.update",),
        effects=("update",),
        maximum_risk="medium",
        required_scopes=("orders.read", "orders.write"),
        approval_required=approval_required,
    )


@dataclass
class FakeExecutor(ActionWorkflowExecutor):
    preview_result: ActionPreviewExecution = field(
        default_factory=lambda: ActionPreviewExecution(
            value={"status": "pending", "version": 3},
            concurrency_token="etag-v3",
        )
    )
    commit_result: JsonValue = field(
        default_factory=lambda: cast(JsonValue, {"status": "approved", "version": 4})
    )
    fail_commit: BaseException | None = None
    preview_calls: list[tuple[str, Mapping[str, JsonValue], str]] = field(default_factory=list)
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
        self.preview_calls.append((capability.id, dict(arguments), principal_context.principal_id))
        return self.preview_result

    async def commit(
        self,
        capability: ActionCapabilityV2,
        execution: ActionCommitExecution,
        principal_context: PrincipalContext,
    ) -> JsonValue:
        del capability, principal_context
        self.commit_calls.append(execution)
        if self.fail_commit is not None:
            raise self.fail_commit
        return self.commit_result


def _store(*, now: list[float] | None = None) -> InMemoryActionStore:
    return InMemoryActionStore(
        development_only=True,
        deployment_salt=b"coordinator-store-test-salt",
        max_actions=20,
        clock=(lambda: now[0]) if now is not None else (lambda: 100.0),
        handle_generator=lambda: "z" * 43,
    )


def _authority(*, now: list[float] | None = None) -> InMemoryApprovalAuthority:
    return InMemoryApprovalAuthority(
        development_only=True,
        clock=(lambda: now[0]) if now is not None else (lambda: 100.0),
        handle_generator=lambda: "y" * 43,
    )


def _coordinator(
    *,
    executor: FakeExecutor | None = None,
    store: InMemoryActionStore | None = None,
    authority: InMemoryApprovalAuthority | None = None,
    policy: DeploymentPolicy | None = None,
    approval: str = "required",
    approval_required: bool = True,
    pack_digest: str = PACK_DIGEST,
) -> ActionCoordinator:
    capability = _capability(approval=approval)
    selected_executor = executor or FakeExecutor()
    definition = CompiledActionDefinition(
        capability=capability,
        proof=_proof(approval_required=approval_required),
    )
    selected_executor.verified_definitions[capability.id] = definition
    return ActionCoordinator(
        definitions={capability.id: definition},
        pack_digest=pack_digest,
        deployment_policy=policy
        or DeploymentPolicy(
            allowed_effects=frozenset({"read", "update"}),
            max_risk="medium",
            capability_allowlist=frozenset({"orders.update"}),
            require_durable_action_store=False,
            action_audit_mode="best_effort",
        ),
        store=store or _store(),
        approval_authority=authority or _authority(),
        executor=selected_executor,
        idempotency_key_generator=lambda: "idem-private-value",
    )


@pytest.mark.parametrize(
    "forged_proof",
    [
        ActionProof(
            diagnostics=(),
            mutation_operation_ids=("orders.delete",),
            effects=("update",),
            maximum_risk="medium",
            required_scopes=("orders.read", "orders.write"),
            approval_required=True,
        ),
        ActionProof(
            diagnostics=(),
            mutation_operation_ids=("orders.update",),
            effects=("delete",),
            maximum_risk="medium",
            required_scopes=("orders.read", "orders.write"),
            approval_required=True,
        ),
        ActionProof(
            diagnostics=(),
            mutation_operation_ids=("orders.update",),
            effects=("update",),
            maximum_risk="critical",
            required_scopes=("orders.read", "orders.write"),
            approval_required=True,
        ),
        ActionProof(
            diagnostics=(),
            mutation_operation_ids=("orders.update",),
            effects=("update",),
            maximum_risk="medium",
            required_scopes=("admin.all",),
            approval_required=True,
        ),
        ActionProof(
            diagnostics=(),
            mutation_operation_ids=("orders.update",),
            effects=("update",),
            maximum_risk="medium",
            required_scopes=("orders.read", "orders.write"),
            approval_required=False,
        ),
    ],
)
def test_coordinator_rejects_host_forged_action_proof_before_preview(
    forged_proof: ActionProof,
) -> None:
    capability = _capability(approval="not_required")
    trusted = CompiledActionDefinition(capability=capability, proof=_proof())
    forged = CompiledActionDefinition(capability=capability, proof=forged_proof)
    executor = FakeExecutor(verified_definitions={capability.id: trusted})

    with pytest.raises(ActionDeploymentConfigurationError):
        ActionCoordinator(
            definitions={capability.id: forged},
            pack_digest=PACK_DIGEST,
            deployment_policy=DeploymentPolicy(
                allowed_effects=frozenset({"read", "update", "delete"}),
                max_risk="critical",
                capability_allowlist=frozenset({capability.id}),
                require_durable_action_store=False,
                action_audit_mode="best_effort",
            ),
            store=_store(),
            approval_authority=_authority(),
            executor=executor,
            idempotency_key_generator=lambda: "idem-private-value",
        )

    assert executor.preview_calls == []


@pytest.mark.asyncio
async def test_default_deployment_policy_denies_action_before_preview() -> None:
    executor = FakeExecutor()
    coordinator = _coordinator(
        executor=executor,
        policy=DeploymentPolicy(
            require_durable_action_store=False,
            action_audit_mode="best_effort",
        ),
    )

    with pytest.raises(ActionDeploymentDeniedError):
        await coordinator.prepare(
            "orders.update",
            {"order_id": "order-1", "comment": "approve"},
            _principal(),
        )
    assert executor.preview_calls == []


@pytest.mark.asyncio
async def test_prepare_runs_preview_and_returns_only_safe_public_state() -> None:
    executor = FakeExecutor()
    coordinator = _coordinator(executor=executor)
    secret_input = "business-private-comment"

    prepared = await coordinator.prepare(
        "orders.update",
        {"order_id": "order-1", "comment": secret_input},
        _principal(),
    )

    assert prepared.status is PreparedActionStatus.PREPARED
    assert prepared.preview == {"status": "pending", "version": 3}
    assert prepared.approval_required is True
    assert prepared.expires_at == 400.0
    assert executor.preview_calls[0][1]["comment"] == secret_input
    rendered = repr(prepared)
    assert secret_input not in rendered
    assert "etag-v3" not in rendered
    assert "idem-private-value" not in rendered


@pytest.mark.asyncio
async def test_prepare_requires_concurrency_token_for_update_effect() -> None:
    executor = FakeExecutor(
        preview_result=ActionPreviewExecution(value={"status": "pending"}, concurrency_token=None)
    )
    with pytest.raises(ActionPreviewInvalidError):
        await _coordinator(executor=executor).prepare(
            "orders.update",
            {"order_id": "order-1", "comment": "approve"},
            _principal(),
        )


@pytest.mark.asyncio
async def test_approval_is_bound_to_exact_action_and_transitions_once() -> None:
    authority = _authority()
    coordinator = _coordinator(authority=authority)
    principal = _principal()
    prepared = await coordinator.prepare(
        "orders.update",
        {"order_id": "order-1", "comment": "approve"},
        principal,
    )
    binding = await coordinator.approval_binding_for_trusted_host(prepared.action_handle, principal)
    approval_handle = await authority.issue_for_testing(binding, expires_in_seconds=60)

    approved = await coordinator.approve(prepared.action_handle, approval_handle, principal)
    assert approved.status is PreparedActionStatus.APPROVED
    with pytest.raises(ActionStateConflictError):
        await coordinator.approve(prepared.action_handle, approval_handle, principal)


@pytest.mark.asyncio
async def test_action_handle_rejects_cross_principal_session_and_pack() -> None:
    store = _store()
    coordinator = _coordinator(store=store)
    prepared = await coordinator.prepare(
        "orders.update",
        {"order_id": "order-1", "comment": "approve"},
        _principal(),
    )

    for principal in (
        _principal("user-b"),
        _principal(session_id="session-b"),
    ):
        with pytest.raises(ActionBindingMismatchError):
            await coordinator.status(prepared.action_handle, principal)

    other_pack = _coordinator(store=store, pack_digest=OTHER_PACK_DIGEST)
    with pytest.raises(ActionBindingMismatchError):
        await other_pack.status(prepared.action_handle, _principal())


async def _prepare_and_approve(
    coordinator: ActionCoordinator,
    authority: InMemoryApprovalAuthority,
    principal: PrincipalContext,
) -> PreparedActionPublic:
    prepared = await coordinator.prepare(
        "orders.update",
        {"order_id": "order-1", "comment": "approve"},
        principal,
    )
    binding = await coordinator.approval_binding_for_trusted_host(prepared.action_handle, principal)
    approval_handle = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval_handle, principal)
    return prepared


@pytest.mark.asyncio
async def test_commit_is_exactly_once_and_replays_stored_success() -> None:
    executor = FakeExecutor()
    authority = _authority()
    coordinator = _coordinator(executor=executor, authority=authority)
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, authority, principal)

    first = await coordinator.commit(prepared.action_handle, principal)
    second = await coordinator.commit(prepared.action_handle, principal)

    assert first.status is PreparedActionStatus.SUCCEEDED
    assert first.result == {"status": "approved", "version": 4}
    assert first.replayed is False
    assert second.result == first.result
    assert second.replayed is True
    assert len(executor.commit_calls) == 1
    execution = executor.commit_calls[0]
    assert execution.input_value == {"order_id": "order-1", "comment": "approve"}
    assert execution.preview_value == {"status": "pending", "version": 3}
    assert execution.concurrency_token == "etag-v3"
    assert execution.idempotency_key.get_secret_value() == "idem-private-value"
    assert "idem-private-value" not in repr(execution)


@pytest.mark.asyncio
async def test_new_coordinator_reuses_store_for_commit_status_and_result_replay() -> None:
    store = _store()
    authority = _authority()
    principal = _principal()
    preparing = _coordinator(store=store, authority=authority)
    prepared = await _prepare_and_approve(preparing, authority, principal)

    committing_executor = FakeExecutor()
    committing = _coordinator(
        store=store,
        authority=authority,
        executor=committing_executor,
    )
    committed = await committing.commit(prepared.action_handle, principal)
    assert committed.status is PreparedActionStatus.SUCCEEDED
    assert len(committing_executor.commit_calls) == 1

    restarted_executor = FakeExecutor()
    restarted = _coordinator(
        store=store,
        authority=authority,
        executor=restarted_executor,
    )
    status = await restarted.status(prepared.action_handle, principal)
    replay = await restarted.commit(prepared.action_handle, principal)
    assert status.status is PreparedActionStatus.SUCCEEDED
    assert status.result == committed.result
    assert replay.result == committed.result
    assert replay.replayed is True
    assert restarted_executor.commit_calls == []


@pytest.mark.asyncio
async def test_commit_uses_sealed_input_even_when_original_mapping_changes() -> None:
    executor = FakeExecutor()
    authority = _authority()
    coordinator = _coordinator(executor=executor, authority=authority)
    principal = _principal()
    arguments = {"order_id": "order-1", "comment": "original"}
    prepared = await coordinator.prepare("orders.update", arguments, principal)
    arguments["comment"] = "tampered"
    binding = await coordinator.approval_binding_for_trusted_host(prepared.action_handle, principal)
    approval_handle = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await coordinator.approve(prepared.action_handle, approval_handle, principal)
    await coordinator.commit(prepared.action_handle, principal)
    committed_input = executor.commit_calls[0].input_value
    assert isinstance(committed_input, dict)
    assert committed_input["comment"] == "original"


@pytest.mark.asyncio
async def test_commit_rechecks_effect_and_scope_after_prepare() -> None:
    authority = _authority()
    coordinator = _coordinator(authority=authority)
    prepared = await _prepare_and_approve(coordinator, authority, _principal())

    with pytest.raises(ActionScopeDeniedError):
        await coordinator.commit(
            prepared.action_handle,
            _principal(scopes={"orders.read"}),
        )


@pytest.mark.asyncio
async def test_unknown_commit_failure_becomes_outcome_unknown_and_is_never_retried() -> None:
    private = "private-provider-failure"
    executor = FakeExecutor(fail_commit=RuntimeError(private))
    authority = _authority()
    coordinator = _coordinator(executor=executor, authority=authority)
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, authority, principal)

    with pytest.raises(ActionStateConflictError) as captured:
        await coordinator.commit(prepared.action_handle, principal)
    rendered = (
        str(captured.value)
        + repr(captured.value.to_dict())
        + "".join(traceback.format_exception(captured.value))
    )
    assert private not in rendered
    status = await coordinator.status(prepared.action_handle, principal)
    assert status.status is PreparedActionStatus.OUTCOME_UNKNOWN
    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)
    assert len(executor.commit_calls) == 1


@pytest.mark.asyncio
async def test_expired_action_cannot_be_approved_committed_or_inspected() -> None:
    now = [100.0]
    store = _store(now=now)
    authority = _authority(now=now)
    coordinator = _coordinator(store=store, authority=authority)
    principal = _principal()
    prepared = await coordinator.prepare(
        "orders.update",
        {"order_id": "order-1", "comment": "approve"},
        principal,
    )
    now[0] = 401.0
    with pytest.raises(ActionExpiredError):
        await coordinator.status(prepared.action_handle, principal)


@pytest.mark.asyncio
async def test_no_approval_contract_transitions_to_approved_during_prepare() -> None:
    coordinator = _coordinator(approval="not_required", approval_required=False)
    prepared = await coordinator.prepare(
        "orders.update",
        {"order_id": "order-1", "comment": "approve"},
        _principal(),
    )
    assert prepared.status is PreparedActionStatus.APPROVED
    assert prepared.approval_required is False


@pytest.mark.asyncio
async def test_concurrent_commit_never_invokes_provider_twice() -> None:
    class BlockingExecutor(FakeExecutor):
        entered = asyncio.Event()
        release = asyncio.Event()

        async def commit(
            self,
            capability: ActionCapabilityV2,
            execution: ActionCommitExecution,
            principal_context: PrincipalContext,
        ) -> JsonValue:
            self.commit_calls.append(execution)
            self.entered.set()
            await self.release.wait()
            return self.commit_result

    executor = BlockingExecutor()
    authority = _authority()
    coordinator = _coordinator(executor=executor, authority=authority)
    principal = _principal()
    prepared = await _prepare_and_approve(coordinator, authority, principal)
    first = asyncio.create_task(coordinator.commit(prepared.action_handle, principal))
    await executor.entered.wait()
    with pytest.raises(ActionStateConflictError):
        await coordinator.commit(prepared.action_handle, principal)
    executor.release.set()
    await first
    assert len(executor.commit_calls) == 1
