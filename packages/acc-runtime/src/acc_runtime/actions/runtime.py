"""Verified composition of compiler-attested Action runtime dependencies."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from acc_runtime.actions.approval import ApprovalAuthority
from acc_runtime.actions.audit import ActionAuditSink
from acc_runtime.actions.coordinator import ActionCoordinator
from acc_runtime.actions.resource_lock import ActionResourceLock
from acc_runtime.actions.runtime_executor import (
    ActionOperationProvider,
    ActionRuntimeConfigurationError,
    RuntimeActionWorkflowExecutor,
)
from acc_runtime.actions.store import ActionStore
from acc_runtime.deployment import DeploymentPolicy


@dataclass(frozen=True, slots=True)
class ActionRuntimeDependencies:
    """Operator-owned dependencies required before an Action Pack can be deployed."""

    deployment_policy: DeploymentPolicy
    store: ActionStore
    approval_authority: ApprovalAuthority
    audit_sink: ActionAuditSink
    audit_salt: bytes = field(repr=False)
    resource_lock: ActionResourceLock | None = None

    def validate_production(self, *, session_vault: object) -> None:
        """Reject development substitutes in the built-in single-node production profile."""

        from acc_runtime.actions.sqlite_approval import SQLiteApprovalAuthority
        from acc_runtime.actions.sqlite_audit import SQLiteActionAuditSink
        from acc_runtime.actions.sqlite_store import SQLiteActionStore
        from acc_runtime.gateway.sqlite_vault import GatewaySessionVaultConfig

        policy = self.deployment_policy
        if not isinstance(self.store, SQLiteActionStore) or self.store.is_durable is not True:
            raise ActionRuntimeConfigurationError(
                "Production Actions require the durable SQLite Action Store"
            )
        if (
            not isinstance(self.approval_authority, SQLiteApprovalAuthority)
            or self.approval_authority.is_durable is not True
        ):
            raise ActionRuntimeConfigurationError(
                "Production Actions require the durable SQLite Approval Authority"
            )
        if (
            not isinstance(self.audit_sink, SQLiteActionAuditSink)
            or self.audit_sink.is_durable is not True
        ):
            raise ActionRuntimeConfigurationError(
                "Production Actions require the durable SQLite Action audit sink"
            )
        if not isinstance(session_vault, GatewaySessionVaultConfig):
            raise ActionRuntimeConfigurationError(
                "Production Actions require an encrypted SQLite Gateway session vault"
            )
        if (
            policy.require_durable_action_store is not True
            or policy.action_audit_mode != "required"
            or policy.action_sandbox_mode != "disabled"
            or self.resource_lock is not None
        ):
            raise ActionRuntimeConfigurationError(
                "Production Action deployment policy cannot use development safety modes"
            )


def create_runtime_action_coordinator(
    compiled_ir: Mapping[str, Any],
    *,
    pack_digest: str,
    provider: ActionOperationProvider,
    dependencies: ActionRuntimeDependencies,
) -> ActionCoordinator:
    """Build one Coordinator exclusively from the loaded IR and shared Provider."""

    if not isinstance(dependencies, ActionRuntimeDependencies):
        raise TypeError("dependencies must be ActionRuntimeDependencies")
    executor = RuntimeActionWorkflowExecutor(
        compiled_ir,
        provider=provider,
        action_sandbox_mode=dependencies.deployment_policy.action_sandbox_mode,
        resource_lock=dependencies.resource_lock,
    )
    definitions = {
        capability_id: executor.verified_definition(capability_id)
        for capability_id in _compiled_action_capability_ids(compiled_ir)
    }
    if not definitions:
        raise ActionRuntimeConfigurationError("Compiled IR contains no Action capabilities")
    return ActionCoordinator(
        definitions=definitions,
        pack_digest=pack_digest,
        deployment_policy=dependencies.deployment_policy,
        store=dependencies.store,
        approval_authority=dependencies.approval_authority,
        executor=executor,
        idempotency_key_generator=_new_idempotency_key,
        action_audit_sink=dependencies.audit_sink,
        action_audit_salt=dependencies.audit_salt,
    )


def _compiled_action_capability_ids(compiled_ir: Mapping[str, Any]) -> tuple[str, ...]:
    capabilities = compiled_ir.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise ActionRuntimeConfigurationError("Compiled Action IR failed runtime validation")
    action_ids: list[str] = []
    for capability_id, compiled in capabilities.items():
        if not isinstance(capability_id, str) or not isinstance(compiled, Mapping):
            raise ActionRuntimeConfigurationError("Compiled Action IR failed runtime validation")
        definition = compiled.get("definition")
        if isinstance(definition, Mapping) and definition.get("kind") == "action":
            action_ids.append(capability_id)
    return tuple(sorted(action_ids))


def _new_idempotency_key() -> str:
    return secrets.token_urlsafe(32)


__all__ = ["ActionRuntimeDependencies", "create_runtime_action_coordinator"]
