from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from acc_runtime.actions import (
    ActionRuntimeDependencies,
    InMemoryActionResourceLock,
    InMemoryActionStore,
    InMemoryApprovalAuthority,
    LoggingActionAuditSink,
    SQLiteActionAuditSink,
    SQLiteActionStore,
    SQLiteApprovalAuthority,
)
from acc_runtime.actions.runtime_executor import ActionRuntimeConfigurationError
from acc_runtime.credentials import SecretValue
from acc_runtime.deployment import DeploymentPolicy
from acc_runtime.gateway import GatewaySessionVaultConfig


def _production_dependencies(tmp_path: Path) -> tuple[ActionRuntimeDependencies, object]:
    dependencies = ActionRuntimeDependencies(
        deployment_policy=DeploymentPolicy(
            allowed_effects=frozenset({"update"}),
            max_risk="medium",
            capability_allowlist=frozenset({"orders.update"}),
            require_durable_action_store=True,
            action_audit_mode="required",
            action_sandbox_mode="disabled",
        ),
        store=SQLiteActionStore(
            tmp_path / "actions.db",
            operator_secret=SecretValue("a" * 48),
            deployment_salt=b"b" * 24,
        ),
        approval_authority=SQLiteApprovalAuthority(
            tmp_path / "approvals.db",
            authority_secret=SecretValue("c" * 48),
            deployment_salt=b"d" * 24,
        ),
        audit_sink=SQLiteActionAuditSink(
            tmp_path / "audit.db",
            operator_secret=SecretValue("e" * 48),
            deployment_salt=b"f" * 24,
        ),
        audit_salt=b"g" * 32,
    )
    vault = GatewaySessionVaultConfig(
        db_path=tmp_path / "sessions.db",
        kek=SecretValue("h" * 48),
        deployment_salt=b"i" * 24,
    )
    return dependencies, vault


def _close(dependencies: ActionRuntimeDependencies) -> None:
    for resource in (
        dependencies.audit_sink,
        dependencies.approval_authority,
        dependencies.store,
    ):
        close = getattr(resource, "close", None)
        if close is not None:
            asyncio.run(close())


def test_validate_production_accepts_complete_durable_profile(tmp_path: Path) -> None:
    dependencies, vault = _production_dependencies(tmp_path)
    try:
        dependencies.validate_production(session_vault=vault)
    finally:
        _close(dependencies)


@pytest.mark.parametrize("unsafe_kind", ("store", "authority", "audit", "guard", "vault"))
def test_validate_production_rejects_development_substitutes(
    tmp_path: Path, unsafe_kind: str
) -> None:
    dependencies, vault = _production_dependencies(tmp_path)
    try:
        if unsafe_kind == "store":
            candidate = replace(
                dependencies,
                store=InMemoryActionStore(development_only=True, deployment_salt=b"j" * 24),
            )
        elif unsafe_kind == "authority":
            candidate = replace(
                dependencies,
                approval_authority=InMemoryApprovalAuthority(development_only=True),
            )
        elif unsafe_kind == "audit":
            candidate = replace(dependencies, audit_sink=LoggingActionAuditSink())
        elif unsafe_kind == "guard":
            candidate = replace(dependencies, resource_lock=InMemoryActionResourceLock())
        else:
            candidate = dependencies
            vault = object()
        with pytest.raises(ActionRuntimeConfigurationError, match="Production"):
            candidate.validate_production(session_vault=vault)
    finally:
        _close(dependencies)
