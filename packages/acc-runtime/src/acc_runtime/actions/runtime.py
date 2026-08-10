"""Verified composition of compiler-attested Action runtime dependencies."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from acc_runtime.actions.approval import ApprovalAuthority
from acc_runtime.actions.audit import ActionAuditSink
from acc_runtime.actions.coordinator import ActionCoordinator
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
    executor = RuntimeActionWorkflowExecutor(compiled_ir, provider=provider)
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
