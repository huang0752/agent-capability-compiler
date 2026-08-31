from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from argparse import Namespace
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml
from pydantic import JsonValue

from acc_core.cli.main import (
    EXIT_RUNTIME,
    EXIT_SUCCESS,
    _close_untransferred_action_dependencies,
    _parser,
    _production_operator_approval,
    _run_runtime_eval_report,
)
from acc_core.cli.main import _run_command as run_pack_command
from acc_core.compiler import compile_project
from acc_runtime import GenericRuntime
from acc_runtime.errors import RuntimeError as AccRuntimeError

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ACC_CORE_SRC = REPOSITORY_ROOT / "packages" / "acc-core" / "src"
JSON_SCHEMA_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
EXPORTED_SCHEMAS = {
    "capability.schema.json",
    "capability-quality.schema.json",
    "eval.schema.json",
    "evidence.schema.json",
    "operation.schema.json",
    "policy.schema.json",
    "project.schema.json",
    "scope-inventory.schema.json",
    "source-contract.schema.json",
    "interaction-contract.schema.json",
    "intent-plan.schema.json",
    "live-observation-artifact.schema.json",
    "ui-interaction-inventory.schema.json",
    "domain-map.schema.json",
    "capability-candidates.schema.json",
    "domain-decision.schema.json",
    "domain-change-request.schema.json",
    "domain-evidence-change-set.schema.json",
    "domain-action-report.schema.json",
    "usage-domain-contract.schema.json",
    "usage-domain-index.schema.json",
    "usage-mcp-release-acceptance.schema.json",
    "usage-project.schema.json",
    "usage-release.schema.json",
    "usage-scenario.schema.json",
    "usage-source-snapshot.schema.json",
}
PROJECT_DIRECTORIES = {
    "capabilities",
    "capability-quality",
    "evals",
    "evidence",
    "operations",
    "policies",
    "source-contracts",
    "interaction-contracts",
    "domain-decisions",
    "domain-change-requests",
}


class _FakeRuntime:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.close_error = close_error
        self.close_calls = 0

    def tools(self) -> list[dict[str, object]]:
        return [{"name": "safe-tool"}]

    async def aclose(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error

    async def __aenter__(self) -> _FakeRuntime:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, traceback
        self.close_calls += 1
        if exc_value is None and self.close_error is not None:
            raise self.close_error


class _FakeAdapter:
    def __init__(self, *, run_error: Exception | None = None) -> None:
        self.run_error = run_error
        self.run_calls = 0

    async def run_stdio(self) -> None:
        self.run_calls += 1
        if self.run_error is not None:
            raise self.run_error


class _FakeStdioError(AccRuntimeError):
    code = "ACC_RUNTIME_FAKE_STDIO_FAILED"
    status = 500


class _FakeGatewayComposition:
    def __init__(self) -> None:
        self.app = object()
        self.close_calls = 0

    def tools(self) -> list[dict[str, object]]:
        return [{"name": "safe-gateway-tool"}]

    async def aclose(self) -> None:
        self.close_calls += 1


class _CloseResource:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self.calls = calls
        self.fail = fail

    async def close(self) -> None:
        self.calls.append(self.name)
        if self.fail:
            raise RuntimeError("close failed")


@pytest.mark.asyncio
async def test_untransferred_action_dependencies_close_in_reverse_and_continue() -> None:
    calls: list[str] = []
    dependencies = SimpleNamespace(
        store=_CloseResource("store", calls),
        approval_authority=_CloseResource("approval", calls, fail=True),
        audit_sink=_CloseResource("audit", calls),
    )

    await _close_untransferred_action_dependencies(dependencies)

    assert calls == ["audit", "approval", "store"]


def _minimal_ir(project: Mapping[str, object]) -> dict[str, object]:
    provider = dict(cast(Mapping[str, object], project["provider"]))
    provider.setdefault("auth", {"kind": "none"})
    normalized_project = {
        **project,
        "schema_version": "2",
        "provider": provider,
        "quality": {"profile": "standard"},
    }
    return {
        "ir_version": "2",
        "project": normalized_project,
        "operations": {},
        "policies": {},
        "capabilities": {},
    }


def _scoped_ir(project: Mapping[str, object]) -> dict[str, object]:
    return {
        **_minimal_ir(project),
        "capabilities": {
            "inspect_records": {
                "scope_requirements": {
                    "policy_always_required": ["records.read"],
                    "always_required": ["records.read"],
                    "conditionally_required": ["records.detail"],
                    "all_referenced": ["records.detail", "records.read"],
                    "completion_alternatives": [["records.read"]],
                }
            }
        },
    }


def _gateway_project() -> dict[str, object]:
    return {
        "schema_version": "2",
        "project": {"id": "fake-gateway", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "FAKE_BASE_URL",
            "auth": {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/auth/login",
                "identity_field": "identity",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/scopes",
                "scope_mapping": {
                    "source:records:read": ["records.read"],
                    "source:records:detail": ["records.detail"],
                },
            },
        },
        "quality": {"profile": "standard"},
    }


def _v2_project(*, transport: str) -> dict[str, object]:
    project = (
        _gateway_project()
        if transport == "streamable_http"
        else {
            "schema_version": "2",
            "project": {"id": "fake-v2", "version": "0.2.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "FAKE_BASE_URL"},
        }
    )
    return {
        **project,
        "schema_version": "2",
        "quality": {"profile": "standard"},
    }


def _patch_scoped_gateway(
    monkeypatch: pytest.MonkeyPatch,
    composition: _FakeGatewayComposition,
) -> dict[str, object]:
    import acc_runtime.gateway
    import acc_runtime.loader

    project = _gateway_project()
    captured: dict[str, object] = {}

    def create_gateway_runtime(**kwargs: object) -> _FakeGatewayComposition:
        captured.update(kwargs)
        return composition

    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_scoped_ir(project)),
    )
    monkeypatch.setattr(acc_runtime.gateway, "create_gateway_runtime", create_gateway_runtime)
    return captured


def _patch_run_composition(
    monkeypatch: pytest.MonkeyPatch,
    *,
    runtime: _FakeRuntime,
    adapter: _FakeAdapter,
) -> None:
    import acc_runtime
    import acc_runtime.loader
    import acc_runtime.mcp

    project = {
        "schema_version": "2",
        "project": {"id": "fake-runtime", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "FAKE_BASE_URL",
            "auth": {"kind": "none"},
        },
        "quality": {"profile": "standard"},
    }

    class FakeGenericRuntime:
        @classmethod
        def from_pack(cls, *args: object, **kwargs: object) -> _FakeRuntime:
            del cls, args, kwargs
            return runtime

    monkeypatch.setattr(acc_runtime, "GenericRuntime", FakeGenericRuntime)
    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_minimal_ir(project)),
    )
    monkeypatch.setattr(acc_runtime.mcp, "CapabilityMcpServer", lambda value: adapter)


def _run_arguments(*, json_output: bool) -> Namespace:
    return Namespace(
        pack="offline.accpkg",
        scope=[],
        scope_ceiling_from_pack=False,
        strict_scope=False,
        tenant_id=None,
        host="127.0.0.1",
        port=8000,
        allowed_host=[],
        allowed_origin=[],
        session_ttl=3600,
        max_sessions=1000,
        mcp_idle_timeout=60.0,
        body_limit=4 * 1024 * 1024,
        workers=1,
        tls_certfile=None,
        tls_keyfile=None,
        production_actions=False,
        development_actions=False,
        local_development_action_guards=False,
        development_action_operator_approval=False,
        action_operator_secret_ref=None,
        development_action_store="memory",
        action_store_path=None,
        action_store_secret_ref=None,
        action_store_salt_ref=None,
        session_vault_path=None,
        session_vault_key_ref=None,
        session_vault_salt_ref=None,
        approval_db_path=None,
        approval_secret_ref=None,
        approval_salt_ref=None,
        audit_db_path=None,
        audit_secret_ref=None,
        audit_salt_ref=None,
        action_capability=[],
        action_effect=[],
        action_max_risk=None,
        json_output=json_output,
    )


def test_run_dispatches_streamable_http_and_json_only_inspects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    import acc_runtime.gateway
    import acc_runtime.loader

    project = {
        "schema_version": "1",
        "project": {"id": "fake-gateway", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "FAKE_BASE_URL",
            "auth": {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/auth/login",
                "identity_field": "identity",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/scopes",
            },
        },
    }
    composition = _FakeGatewayComposition()
    captured: dict[str, object] = {}

    def create_gateway_runtime(**kwargs: object) -> _FakeGatewayComposition:
        captured.update(kwargs)
        return composition

    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_minimal_ir(project)),
    )
    monkeypatch.setattr(acc_runtime.gateway, "create_gateway_runtime", create_gateway_runtime)
    monkeypatch.setattr(
        uvicorn,
        "run",
        lambda *args, **kwargs: pytest.fail("JSON inspection must not start uvicorn"),
    )
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["gateway.test:8443"]
    arguments.allowed_origin = ["https://agent.test"]
    arguments.scope = ["customer.read"]

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert envelope.result is not None
    assert envelope.result["transport"] == "streamable_http"
    assert envelope.result["tools"] == [{"name": "safe-gateway-tool"}]
    assert "token" not in repr(envelope).casefold()
    settings = cast(acc_runtime.gateway.GatewaySettings, captured["settings"])
    assert settings.allowed_hosts == ("gateway.test:8443",)
    assert captured["deployment_scope_ceiling"] == frozenset({"customer.read"})
    assert composition.close_calls == 1


def test_run_development_actions_injects_explicit_bounded_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from acc_runtime.actions import (
        ActionRuntimeDependencies,
        InMemoryActionResourceLock,
        InMemoryActionStore,
        InMemoryApprovalAuthority,
        LoggingActionAuditSink,
    )

    composition = _FakeGatewayComposition()
    captured = _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = True
    arguments.local_development_action_guards = True
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "medium"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    dependencies = cast(ActionRuntimeDependencies, captured["action_dependencies"])
    assert isinstance(dependencies, ActionRuntimeDependencies)
    assert isinstance(dependencies.store, InMemoryActionStore)
    assert dependencies.store.is_durable is False
    assert isinstance(dependencies.approval_authority, InMemoryApprovalAuthority)
    assert isinstance(dependencies.audit_sink, LoggingActionAuditSink)
    assert isinstance(dependencies.resource_lock, InMemoryActionResourceLock)
    assert dependencies.deployment_policy.allowed_effects == frozenset({"update"})
    assert dependencies.deployment_policy.max_risk == "medium"
    assert dependencies.deployment_policy.capability_allowlist == frozenset({"orders.update"})
    assert dependencies.deployment_policy.require_durable_action_store is False
    assert dependencies.deployment_policy.action_audit_mode == "required"
    assert dependencies.deployment_policy.action_sandbox_mode == "local_development"
    assert envelope.result is not None
    assert envelope.result["actions"] == {
        "mode": "development_test_only",
        "store": "in_memory",
        "store_durable": False,
        "approval_authority": "in_memory_trusted_host",
        "audit": "logging_required",
        "local_development_action_guards": "process_local_only",
        "allowed_capabilities": ["orders.update"],
        "allowed_effects": ["update"],
        "max_risk": "medium",
    }
    assert "salt" not in repr(envelope).casefold()
    assert composition.close_calls == 1


def test_run_development_actions_constructs_durable_sqlite_store_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from acc_runtime.actions import (
        ActionRuntimeDependencies,
        PreparedActionStatus,
        SQLiteActionStore,
    )
    from acc_runtime.credentials import SecretValue

    composition = _FakeGatewayComposition()
    captured = _patch_scoped_gateway(monkeypatch, composition)
    database = tmp_path / "actions.db"
    monkeypatch.setenv("ACC_TEST_STORE_SECRET", "s" * 48)
    monkeypatch.setenv("ACC_TEST_STORE_SALT", "t" * 24)
    monkeypatch.setenv("ACC_TEST_OPERATOR_SECRET", "o" * 48)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = True
    arguments.development_action_store = "sqlite"
    arguments.action_store_path = str(database)
    arguments.action_store_secret_ref = "ACC_TEST_STORE_SECRET"
    arguments.action_store_salt_ref = "ACC_TEST_STORE_SALT"
    arguments.development_action_operator_approval = True
    arguments.action_operator_secret_ref = "ACC_TEST_OPERATOR_SECRET"
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "low"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    dependencies = cast(ActionRuntimeDependencies, captured["action_dependencies"])
    assert isinstance(dependencies.store, SQLiteActionStore)
    assert dependencies.store.is_durable is True
    assert dependencies.deployment_policy.require_durable_action_store is True
    assert captured["operator_approval"] is not None
    assert envelope.result is not None
    assert envelope.result["actions"]["store"] == "sqlite"
    assert envelope.result["actions"]["store_durable"] is True
    assert str(database) not in repr(envelope)
    creation = asyncio.run(
        dependencies.store.create(
            capability_id="orders.update",
            principal_id="user-a",
            session_id="session-a",
            pack_digest="sha256:" + "a" * 64,
            input_value={"order_id": "one"},
            preview_value={"status": "pending"},
            expires_in_seconds=300,
        )
    )
    asyncio.run(dependencies.store.close())
    reopened = SQLiteActionStore(
        database,
        operator_secret=SecretValue("s" * 48),
        deployment_salt=("t" * 24).encode(),
    )
    recovered = asyncio.run(
        reopened.resolve(
            creation.handle,
            principal_id="user-a",
            session_id="session-a",
            pack_digest="sha256:" + "a" * 64,
        )
    )
    assert recovered.record.status is PreparedActionStatus.PREPARED
    asyncio.run(reopened.close())


def _configure_production_actions(
    monkeypatch: pytest.MonkeyPatch, arguments: Namespace, tmp_path: Path
) -> None:
    secret_fields = (
        ("action_store_secret_ref", "ACC_PROD_STORE_SECRET", "a"),
        ("action_store_salt_ref", "ACC_PROD_STORE_SALT", "b"),
        ("session_vault_key_ref", "ACC_PROD_VAULT_KEY", "c"),
        ("session_vault_salt_ref", "ACC_PROD_VAULT_SALT", "d"),
        ("approval_secret_ref", "ACC_PROD_APPROVAL_SECRET", "e"),
        ("approval_salt_ref", "ACC_PROD_APPROVAL_SALT", "f"),
        ("audit_secret_ref", "ACC_PROD_AUDIT_SECRET", "g"),
        ("audit_salt_ref", "ACC_PROD_AUDIT_SALT", "h"),
    )
    for attribute, reference, marker in secret_fields:
        setattr(arguments, attribute, reference)
        monkeypatch.setenv(reference, marker * 48)
    arguments.production_actions = True
    arguments.action_store_path = str(tmp_path / "actions.db")
    arguments.session_vault_path = str(tmp_path / "sessions.db")
    arguments.approval_db_path = str(tmp_path / "approvals.db")
    arguments.audit_db_path = str(tmp_path / "audit.db")
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "medium"


def test_run_production_actions_injects_only_durable_single_node_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from acc_runtime.actions import (
        ActionRuntimeDependencies,
        SQLiteActionAuditSink,
        SQLiteActionStore,
        SQLiteApprovalAuthority,
    )
    from acc_runtime.gateway import GatewaySessionVaultConfig

    composition = _FakeGatewayComposition()
    captured = _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    _configure_production_actions(monkeypatch, arguments, tmp_path)

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    dependencies = cast(ActionRuntimeDependencies, captured["action_dependencies"])
    assert isinstance(dependencies.store, SQLiteActionStore)
    assert isinstance(dependencies.approval_authority, SQLiteApprovalAuthority)
    assert isinstance(dependencies.audit_sink, SQLiteActionAuditSink)
    assert dependencies.resource_lock is None
    assert dependencies.deployment_policy.require_durable_action_store is True
    assert dependencies.deployment_policy.action_audit_mode == "required"
    assert dependencies.deployment_policy.action_sandbox_mode == "disabled"
    assert isinstance(captured["session_vault"], GatewaySessionVaultConfig)
    assert captured["operator_approval"] is None
    assert envelope.result is not None
    assert envelope.result["actions"]["mode"] == "production_single_node"
    assert envelope.result["session_vault"] == {
        "mode": "sqlite_single_node",
        "durable": True,
    }
    rendered = repr(envelope)
    assert str(tmp_path) not in rendered
    assert "ACC_PROD_" not in rendered
    for marker in "abcdefgh":
        assert marker * 32 not in rendered
    asyncio.run(dependencies.audit_sink.close())
    asyncio.run(dependencies.approval_authority.close())
    asyncio.run(dependencies.store.close())


@pytest.mark.parametrize(
    "unsafe_change",
    ("development", "operator", "reused_ref", "reused_value", "missing", "shared_path"),
)
def test_run_production_actions_rejects_incomplete_or_development_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unsafe_change: str,
) -> None:
    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    _configure_production_actions(monkeypatch, arguments, tmp_path)
    if unsafe_change == "development":
        arguments.development_actions = True
    elif unsafe_change == "operator":
        arguments.development_action_operator_approval = True
        arguments.action_operator_secret_ref = "ACC_PROD_OPERATOR_SECRET"
        monkeypatch.setenv("ACC_PROD_OPERATOR_SECRET", "z" * 48)
    elif unsafe_change == "reused_ref":
        arguments.audit_salt_ref = arguments.audit_secret_ref
    elif unsafe_change == "reused_value":
        monkeypatch.setenv("ACC_PROD_AUDIT_SALT", "g" * 48)
    elif unsafe_change == "missing":
        arguments.approval_db_path = None
    else:
        arguments.audit_db_path = arguments.approval_db_path

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert composition.close_calls == 0


@pytest.mark.parametrize(
    ("path", "secret_ref", "salt_ref"),
    [
        (None, "ACC_TEST_STORE_SECRET", "ACC_TEST_STORE_SALT"),
        ("actions.db", None, "ACC_TEST_STORE_SALT"),
        ("actions.db", "ACC_TEST_STORE_SECRET", None),
        ("actions.db", "ACC_TEST_STORE_SECRET", "ACC_TEST_STORE_SECRET"),
    ],
)
def test_run_development_sqlite_store_rejects_incomplete_or_reused_refs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path: str | None,
    secret_ref: str | None,
    salt_ref: str | None,
) -> None:
    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    monkeypatch.setenv("ACC_TEST_STORE_SECRET", "s" * 48)
    monkeypatch.setenv("ACC_TEST_STORE_SALT", "t" * 24)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = True
    arguments.development_action_store = "sqlite"
    arguments.action_store_path = None if path is None else str(tmp_path / path)
    arguments.action_store_secret_ref = secret_ref
    arguments.action_store_salt_ref = salt_ref
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "low"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert composition.close_calls == 0


def test_run_development_sqlite_store_rejects_reused_secret_values_and_operator_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    monkeypatch.setenv("ACC_TEST_STORE_SECRET", "same-secret-value-" + "s" * 32)
    monkeypatch.setenv("ACC_TEST_STORE_SALT", "same-secret-value-" + "s" * 32)
    monkeypatch.setenv("ACC_TEST_OPERATOR_SECRET", "same-secret-value-" + "s" * 32)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = True
    arguments.development_action_store = "sqlite"
    arguments.action_store_path = str(tmp_path / "actions.db")
    arguments.action_store_secret_ref = "ACC_TEST_STORE_SECRET"
    arguments.action_store_salt_ref = "ACC_TEST_STORE_SALT"
    arguments.development_action_operator_approval = True
    arguments.action_operator_secret_ref = "ACC_TEST_OPERATOR_SECRET"
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "low"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert composition.close_calls == 0


@pytest.mark.parametrize(
    ("enabled", "capabilities", "effects", "risk"),
    [
        (False, ["orders.update"], ["update"], "medium"),
        (True, [], ["update"], "medium"),
        (True, ["orders.update"], [], "medium"),
        (True, ["orders.update"], ["update"], None),
    ],
)
def test_run_development_actions_rejects_missing_opt_in_or_ceiling(
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
    capabilities: list[str],
    effects: list[str],
    risk: str | None,
) -> None:
    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = enabled
    arguments.action_capability = capabilities
    arguments.action_effect = effects
    arguments.action_max_risk = risk

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert composition.close_calls == 0


def test_run_local_development_action_guards_require_development_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = False
    arguments.local_development_action_guards = True
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "low"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert composition.close_calls == 0


def test_run_development_operator_approval_uses_env_secret_and_safe_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from acc_runtime.gateway.operator import LocalDevelopmentOperatorApprovalConfig

    composition = _FakeGatewayComposition()
    captured = _patch_scoped_gateway(monkeypatch, composition)
    monkeypatch.setenv("ACC_TEST_OPERATOR_SECRET", "o" * 48)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = True
    arguments.development_action_operator_approval = True
    arguments.action_operator_secret_ref = "ACC_TEST_OPERATOR_SECRET"
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "low"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    config = cast(LocalDevelopmentOperatorApprovalConfig, captured["operator_approval"])
    assert isinstance(config, LocalDevelopmentOperatorApprovalConfig)
    assert config.secret_ref == "ACC_TEST_OPERATOR_SECRET"
    assert envelope.result is not None
    assert envelope.result["operator_approval"] == {
        "mode": "local_development_loopback_only",
        "path": "/operator/actions/approve",
        "secret_ref": "ACC_TEST_OPERATOR_SECRET",
        "request_body_limit": 1024,
    }
    assert "o" * 48 not in repr(envelope)


@pytest.mark.parametrize(
    ("enabled", "reference"),
    [(False, "ACC_TEST_OPERATOR_SECRET"), (True, None), (True, "MISSING_OPERATOR_SECRET")],
)
def test_run_development_operator_approval_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
    reference: str | None,
) -> None:
    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.development_actions = True
    arguments.development_action_operator_approval = enabled
    arguments.action_operator_secret_ref = reference
    arguments.action_capability = ["orders.update"]
    arguments.action_effect = ["update"]
    arguments.action_max_risk = "low"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert composition.close_calls == 0


def test_production_operator_approval_uses_independent_secret_and_safe_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from acc_runtime.gateway.operator import ProductionOperatorApprovalConfig

    monkeypatch.setenv("PRODUCTION_OPERATOR_SECRET", "p" * 48)
    arguments = _run_arguments(json_output=True)
    arguments.production_actions = True
    arguments.production_action_operator_approval = True
    arguments.production_action_operator_secret_ref = "PRODUCTION_OPERATOR_SECRET"

    config, safe = _production_operator_approval(arguments)

    assert isinstance(config, ProductionOperatorApprovalConfig)
    assert config.secret_ref == "PRODUCTION_OPERATOR_SECRET"
    assert safe == {
        "operator_approval": {
            "mode": "production_loopback_process_bound",
            "path": "/operator/actions/approve",
            "request_body_limit": 1024,
            "restart_behavior": "prepared_actions_must_be_reprepared",
        }
    }
    assert "p" * 48 not in repr((config, safe))


@pytest.mark.parametrize(
    ("enabled", "reference", "production"),
    [
        (False, "PRODUCTION_OPERATOR_SECRET", True),
        (True, None, True),
        (True, "MISSING", True),
        (True, "PRODUCTION_OPERATOR_SECRET", False),
    ],
)
def test_production_operator_approval_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
    reference: str | None,
    production: bool,
) -> None:
    arguments = _run_arguments(json_output=True)
    arguments.production_actions = production
    arguments.production_action_operator_approval = enabled
    arguments.production_action_operator_secret_ref = reference

    with pytest.raises(AccRuntimeError):
        _production_operator_approval(arguments)


def test_run_stdio_rejects_development_operator_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _FakeRuntime()
    adapter = _FakeAdapter()
    _patch_run_composition(monkeypatch, runtime=runtime, adapter=adapter)
    monkeypatch.setenv("ACC_TEST_OPERATOR_SECRET", "o" * 48)
    arguments = _run_arguments(json_output=True)
    arguments.development_actions = True
    arguments.development_action_operator_approval = True
    arguments.action_operator_secret_ref = "ACC_TEST_OPERATOR_SECRET"

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert runtime.close_calls == 0


def test_run_json_dispatches_v2_stdio_pack_with_scope_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import acc_runtime
    import acc_runtime.loader

    runtime = _FakeRuntime()
    project = _v2_project(transport="stdio")
    project["provider"]["application_success"] = {
        "kind": "json_pointer",
        "pointer": "/code",
        "allowed_values": [200],
    }
    from_pack_kwargs: dict[str, object] = {}

    class FakeGenericRuntime:
        @classmethod
        def from_pack(cls, *args: object, **kwargs: object) -> _FakeRuntime:
            del cls, args
            from_pack_kwargs.update(kwargs)
            return runtime

    monkeypatch.setattr(acc_runtime, "GenericRuntime", FakeGenericRuntime)
    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_scoped_ir(project)),
    )
    arguments = _run_arguments(json_output=True)
    arguments.scope = ["records.read", "records.detail"]

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert envelope.ok is True
    assert isinstance(envelope.result, dict)
    assert envelope.result["transport"] == "stdio"
    assert envelope.result["scope_analysis"]["summary"] == {
        "callable": 1,
        "conditional": 0,
        "denied": 0,
    }
    assert "application_success_policy" not in from_pack_kwargs


def test_run_json_dispatches_v2_streamable_http_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import acc_runtime.gateway
    import acc_runtime.loader

    composition = _FakeGatewayComposition()
    captured: dict[str, object] = {}

    def create_gateway_runtime(**kwargs: object) -> _FakeGatewayComposition:
        captured.update(kwargs)
        return composition

    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_scoped_ir(_v2_project(transport="streamable_http"))),
    )
    monkeypatch.setattr(acc_runtime.gateway, "create_gateway_runtime", create_gateway_runtime)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert isinstance(envelope.result, dict)
    assert envelope.result["transport"] == "streamable_http"
    assert captured["pack_path"] == Path("offline.accpkg")
    assert composition.close_calls == 1


def test_run_json_reports_scope_callability_without_expanding_empty_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    composition = _FakeGatewayComposition()
    captured = _patch_scoped_gateway(monkeypatch, composition)
    monkeypatch.setattr(
        uvicorn,
        "run",
        lambda *args, **kwargs: pytest.fail("JSON inspection must not start uvicorn"),
    )
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert envelope.result is not None
    analysis = cast(dict[str, Any], envelope.result["scope_analysis"])
    assert analysis["deployment_scope_ceiling"] == []
    assert analysis["summary"] == {"callable": 0, "conditional": 0, "denied": 1}
    capability = cast(list[dict[str, Any]], analysis["capabilities"])[0]
    assert capability["capability"] == "inspect_records"
    assert capability["deployment"]["status"] == "denied"
    assert capability["user"]["status"] == "unknown"
    assert capability["effective"]["status"] == "unknown"
    assert [item.code for item in envelope.diagnostics] == [
        "ACC_RUN_SCOPE_CEILING_EMPTY",
        "ACC_RUN_CAPABILITY_SCOPE_DENIED",
    ]
    assert {item.severity for item in envelope.diagnostics} == {"warning"}
    assert captured["deployment_scope_ceiling"] == frozenset()


def test_run_scope_ceiling_from_pack_is_explicit_and_makes_full_scope_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composition = _FakeGatewayComposition()
    captured = _patch_scoped_gateway(monkeypatch, composition)
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.scope_ceiling_from_pack = True

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert envelope.result is not None
    analysis = cast(dict[str, Any], envelope.result["scope_analysis"])
    assert analysis["deployment_scope_ceiling"] == ["records.detail", "records.read"]
    assert analysis["summary"] == {"callable": 1, "conditional": 0, "denied": 0}
    assert envelope.diagnostics == []
    assert captured["deployment_scope_ceiling"] == frozenset({"records.detail", "records.read"})


def test_run_strict_scope_refuses_to_start_when_capability_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import acc_runtime.gateway
    import acc_runtime.loader

    project = _gateway_project()
    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_scoped_ir(project)),
    )
    monkeypatch.setattr(
        acc_runtime.gateway,
        "create_gateway_runtime",
        lambda **kwargs: pytest.fail("strict scope must stop before Gateway composition"),
    )
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    arguments.strict_scope = True

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert envelope.result is None
    denied = [
        item for item in envelope.diagnostics if item.code == "ACC_RUN_CAPABILITY_SCOPE_DENIED"
    ]
    assert len(denied) == 1
    assert denied[0].severity == "error"


def test_run_non_json_emits_scope_warning_before_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import uvicorn

    composition = _FakeGatewayComposition()
    _patch_scoped_gateway(monkeypatch, composition)
    observed: list[str] = []

    def run_uvicorn(*args: object, **kwargs: object) -> None:
        del args, kwargs
        observed.append(capsys.readouterr().err)

    monkeypatch.setattr(uvicorn, "run", run_uvicorn)
    arguments = _run_arguments(json_output=False)
    arguments.allowed_host = ["127.0.0.1:8000"]

    exit_code, _ = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert len(observed) == 1
    assert "ACC_RUN_SCOPE_CEILING_EMPTY" in observed[0]
    assert "ACC_RUN_CAPABILITY_SCOPE_DENIED" in observed[0]


def test_run_streamable_http_starts_single_worker_and_closes_after_server_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    import acc_runtime.gateway
    import acc_runtime.loader

    project = {
        "schema_version": "1",
        "project": {"id": "fake-gateway", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "FAKE_BASE_URL",
            "auth": {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/auth/login",
                "identity_field": "identity",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/scopes",
            },
        },
    }
    composition = _FakeGatewayComposition()
    calls: list[tuple[object, dict[str, object]]] = []
    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_minimal_ir(project)),
    )
    monkeypatch.setattr(
        acc_runtime.gateway,
        "create_gateway_runtime",
        lambda **kwargs: composition,
    )
    monkeypatch.setattr(
        uvicorn,
        "run",
        lambda app, **kwargs: calls.append((app, kwargs)),
    )
    arguments = _run_arguments(json_output=False)
    arguments.allowed_host = ["127.0.0.1:8000"]

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_SUCCESS
    assert envelope.result is not None
    assert calls == [
        (
            composition.app,
            {
                "host": "127.0.0.1",
                "port": 8000,
                "workers": 1,
                "ssl_certfile": None,
                "ssl_keyfile": None,
            },
        )
    ]
    assert composition.close_calls == 1


def test_run_streamable_http_maps_uvicorn_system_exit_to_stable_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    import acc_runtime.gateway
    import acc_runtime.loader

    project = {
        "schema_version": "1",
        "project": {"id": "fake-gateway", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "FAKE_BASE_URL",
            "auth": {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/auth/login",
                "identity_field": "identity",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/scopes",
            },
        },
    }
    composition = _FakeGatewayComposition()
    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_minimal_ir(project)),
    )
    monkeypatch.setattr(
        acc_runtime.gateway,
        "create_gateway_runtime",
        lambda **kwargs: composition,
    )
    monkeypatch.setattr(
        uvicorn,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(SystemExit(3)),
    )
    arguments = _run_arguments(json_output=False)
    arguments.allowed_host = ["127.0.0.1:8000"]

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert envelope.diagnostics[0].code == "ACC_RUNTIME_CONFIGURATION_INVALID"
    assert envelope.diagnostics[0].message == "ACC runtime could not start."
    assert composition.close_calls == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allowed_host", []),
        ("workers", 2),
        ("port", 0),
        ("host", "0.0.0.0"),
    ],
)
def test_run_streamable_http_rejects_unsafe_gateway_configuration(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    import acc_runtime.loader

    project = {
        "schema_version": "1",
        "project": {"id": "fake-gateway", "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "FAKE_BASE_URL",
            "auth": {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/auth/login",
                "identity_field": "identity",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/scopes",
            },
        },
    }
    monkeypatch.setattr(
        acc_runtime.loader,
        "load_pack",
        lambda path: SimpleNamespace(ir=_minimal_ir(project)),
    )
    arguments = _run_arguments(json_output=True)
    arguments.allowed_host = ["127.0.0.1:8000"]
    setattr(arguments, field, value)

    exit_code, envelope = run_pack_command(arguments)

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert envelope.diagnostics[0].code == "ACC_RUNTIME_CONFIGURATION_INVALID"


@pytest.mark.parametrize("json_output", [False, True])
def test_run_composition_closes_runtime_on_stdio_and_inspect_success(
    monkeypatch: pytest.MonkeyPatch,
    json_output: bool,
) -> None:
    runtime = _FakeRuntime()
    adapter = _FakeAdapter()
    _patch_run_composition(monkeypatch, runtime=runtime, adapter=adapter)

    exit_code, envelope = run_pack_command(_run_arguments(json_output=json_output))

    assert exit_code == EXIT_SUCCESS
    assert envelope.ok is True
    assert runtime.close_calls == 1
    assert adapter.run_calls == (0 if json_output else 1)


def test_run_composition_closes_runtime_when_stdio_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _FakeRuntime()
    adapter = _FakeAdapter(run_error=_FakeStdioError("private stdio failure"))
    _patch_run_composition(monkeypatch, runtime=runtime, adapter=adapter)

    exit_code, envelope = run_pack_command(_run_arguments(json_output=False))

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert runtime.close_calls == 1
    assert envelope.diagnostics[0].code == "ACC_RUNTIME_FAKE_STDIO_FAILED"
    assert "private stdio failure" not in repr(envelope)


def test_run_composition_preserves_body_error_when_close_also_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body_secret = "body-secret-must-not-leak"
    close_secret = "secondary-close-secret-must-not-leak"
    body_error = _FakeStdioError(body_secret)
    runtime = _FakeRuntime(close_error=ValueError(close_secret))
    adapter = _FakeAdapter(run_error=body_error)
    _patch_run_composition(monkeypatch, runtime=runtime, adapter=adapter)

    exit_code, envelope = run_pack_command(_run_arguments(json_output=False))

    assert exit_code == EXIT_RUNTIME
    assert runtime.close_calls == 1
    assert envelope.diagnostics[0].code == body_error.code
    assert body_error.__cause__ is None
    assert body_error.__context__ is None
    assert body_secret not in repr(envelope)
    assert close_secret not in repr(envelope)


@pytest.mark.parametrize("json_output", [False, True])
def test_run_composition_maps_close_failure_to_a_stable_safe_error(
    monkeypatch: pytest.MonkeyPatch,
    json_output: bool,
) -> None:
    close_secret = "close-secret-must-not-leak"
    runtime = _FakeRuntime(close_error=ValueError(close_secret))
    adapter = _FakeAdapter()
    _patch_run_composition(monkeypatch, runtime=runtime, adapter=adapter)

    exit_code, envelope = run_pack_command(_run_arguments(json_output=json_output))

    assert exit_code == EXIT_RUNTIME
    assert envelope.ok is False
    assert runtime.close_calls == 1
    assert envelope.diagnostics[0].code == "ACC_RUNTIME_START_FAILED"
    assert envelope.diagnostics[0].message == "ACC runtime could not start."
    assert close_secret not in repr(envelope)


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path = REPOSITORY_ROOT,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    current_pythonpath = env.get("PYTHONPATH")
    pythonpath_entries = [str(ACC_CORE_SRC)]
    if current_pythonpath:
        pythonpath_entries.append(current_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )


def _run_acc(*arguments: str, cwd: Path = REPOSITORY_ROOT) -> subprocess.CompletedProcess[str]:
    return _run_command(
        [sys.executable, "-m", "acc_core.cli.main", *arguments],
        cwd=cwd,
    )


def _json_envelope(
    completed: subprocess.CompletedProcess[str],
    *,
    command: str,
    ok: bool,
    allow_warnings: bool = False,
) -> dict[str, Any]:
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        pytest.fail(
            "CLI --json output is not one JSON document:\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )

    assert set(payload) == {"ok", "command", "result", "diagnostics"}
    assert payload["ok"] is ok
    assert payload["command"] == command
    assert isinstance(payload["diagnostics"], list)
    if ok:
        assert isinstance(payload["result"], dict)
        if allow_warnings:
            assert all(item["severity"] != "error" for item in payload["diagnostics"])
        else:
            assert payload["diagnostics"] == []
    else:
        assert payload["result"] is None
        assert payload["diagnostics"]
    return cast(dict[str, Any], payload)


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _make_valid_project(root: Path) -> Path:
    project = root / "acc-project"
    (root / "system").mkdir()
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "example-crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "CRM_BASE_URL",
                "auth": {"kind": "none"},
            },
            "quality": {"profile": "standard"},
        },
    )
    _write_yaml(
        project / "operations" / "crm.get_customer.yaml",
        {
            "schema_version": "2",
            "id": "crm.get_customer",
            "title": "Get customer",
            "kind": "read",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
            },
            "output_schema": {"type": "object"},
            "http": {
                "method": "GET",
                "path": "/customers/{customer_id}",
                "path_parameters": {"customer_id": "customer_id"},
                "query_parameters": {},
                "scopes": ["customer.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 1_048_576,
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "safety": {
                    "effect": "read",
                    "risk": "low",
                    "reversibility": "reversible",
                    "retry": {"mode": "idempotent_only"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "context_bindings": {},
            "evidence": [
                {
                    "source_id": "crm-backend",
                    "kind": "source_file",
                    "path": "app/api/customers.py",
                    "line_start": 42,
                    "line_end": 68,
                    "digest": f"sha256:{'a' * 64}",
                }
            ],
        },
    )
    _write_yaml(
        project / "policies" / "crm-sales-read.yaml",
        {
            "schema_version": "2",
            "id": "crm-sales-read",
            "required_scopes": ["customer.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["id", "name", "tenant_id"],
            "denied_fields": ["internal_note"],
            "redaction_rules": [],
        },
    )
    _write_yaml(
        project / "capabilities" / "get_customer.yaml",
        {
            "schema_version": "2",
            "kind": "read",
            "id": "get_customer",
            "title": "Get customer context",
            "description": "Get one customer's context.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
            },
            "output_schema": {"type": "object"},
            "workflow": [
                {
                    "id": "customer",
                    "call": {
                        "operation": "crm.get_customer",
                        "arguments": {"customer_id": "$.input.customer_id"},
                    },
                },
                {"emit": {"value": "$.steps.customer"}},
            ],
            "policy": "crm-sales-read",
            "evals": ["get-customer-normal"],
        },
    )
    _write_yaml(
        project / "evals" / "get-customer-normal.yaml",
        {
            "schema_version": "2",
            "id": "get-customer-normal",
            "capability": "get_customer",
            "input": {"customer_id": "c-1"},
            "fixtures": {},
            "expected_calls": [
                {"operation": "crm.get_customer", "arguments": {"customer_id": "c-1"}}
            ],
            "expected_output_schema": {"type": "object"},
            "forbidden_fields": ["internal_note"],
        },
    )
    _write_yaml(
        project / "source-contracts" / "crm.get_customer.yaml",
        {
            "schema_version": "2",
            "id": "crm.get_customer.contract",
            "operation_id": "crm.get_customer",
            "request_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
            },
            "response_schema": {"type": "object"},
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
        },
    )
    _write_yaml(
        project / "capability-quality" / "get_customer.yaml",
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "intent": {"action": "get", "resource_types": ["customer"]},
            "inputs": {
                "customer_id": {
                    "kind": "resource_selector",
                    "resource_type": "customer",
                    "acquisition": "caller",
                }
            },
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65_536, "long_text_disclosures": []},
        },
    )
    _write_yaml(
        project / "scope-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {
                "mode": "system_complete",
                "selected_domains": [],
                "exclusion_approval": {},
            },
            "discovery": {
                "source_commit": "git:0123456789abcdef",
                "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
                "include_paths": ["app"],
                "evidence_sources": ["routes"],
            },
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": [
                {
                    "id": "GET /customers/{customer_id}",
                    "domain": "crm",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/customers/{customer_id}",
                    "evidence_sources": ["routes"],
                    "eligibility": "eligible",
                    "disposition": "composed",
                    "operation_id": "crm.get_customer",
                    "capability_ids": ["get_customer"],
                }
            ],
            "summary": {
                "discovered_routes": 1,
                "eligible_routes": 1,
                "planned": 0,
                "composed": 1,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        },
    )
    return project


@pytest.mark.parametrize("through_mcp", [False, True])
def test_runtime_eval_composition_closes_every_created_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    through_mcp: bool,
) -> None:
    import anyio

    project = _make_valid_project(tmp_path)
    compilation = compile_project(project)
    assert compilation.ok is True
    assert compilation.ir is not None
    close_calls = 0
    original_close_outcome = GenericRuntime._close_outcome

    async def counted_close_outcome(runtime: GenericRuntime) -> object:
        nonlocal close_calls
        close_calls += 1
        return await original_close_outcome(runtime)

    monkeypatch.setattr(GenericRuntime, "_close_outcome", counted_close_outcome)
    monkeypatch.setenv("CRM_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("CRM_USER_TOKEN", "offline-token")

    anyio.run(
        _run_runtime_eval_report,
        cast(dict[str, Any], compilation.ir),
        project,
        through_mcp,
    )

    assert close_calls == 1


@pytest.mark.parametrize("suite", ["runtime", "e2e"])
def test_cli_eval_reports_project_fixture_runner_as_not_provisioned(
    tmp_path: Path,
    suite: str,
) -> None:
    project = _make_valid_project(tmp_path)
    eval_path = project / "evals" / "get-customer-normal.yaml"
    eval_document = yaml.safe_load(eval_path.read_text(encoding="utf-8"))
    eval_document["fixtures"] = {
        "project_http": {"responses": [{"status": 200, "json": {"id": "c-1"}}]}
    }
    _write_yaml(eval_path, eval_document)

    arguments = _parser().parse_args(["test", suite, str(project), "--json"])
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.ok is False
    assert envelope.result == {
        "kind": "runtime",
        "suite": suite,
        "ok": False,
        "status": "not_provisioned",
        "summary": {
            "total": 1,
            "passed": 0,
            "failed": 0,
            "not_provisioned": 1,
            "not_run": 0,
            "calls": 0,
        },
        "diagnostics": [],
        "cases": [
            {
                "id": "get-customer-normal",
                "capability": "get_customer",
                "ok": False,
                "status": "not_provisioned",
                "calls": 0,
                "diagnostics": [
                    {
                        "code": "ACC_TEST_RUNNER_NOT_PROVISIONED",
                        "message": (
                            "Eval case requires a project fixture adapter that was not provided."
                        ),
                    }
                ],
            }
        ],
    }
    assert [item.model_dump(mode="json") for item in envelope.diagnostics] == [
        {
            "code": "ACC_TEST_RUNNER_NOT_PROVISIONED",
            "severity": "error",
            "message": "The evaluation suite requires a project runner that was not provided.",
            "path": "evals/get-customer-normal",
            "pointer": "/fixtures/project_http",
        }
    ]


def test_cli_eval_keeps_malformed_builtin_fixture_as_failed(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)
    eval_path = project / "evals" / "get-customer-normal.yaml"
    eval_document = yaml.safe_load(eval_path.read_text(encoding="utf-8"))
    eval_document["fixtures"] = {
        "runtime_context": {"granted_scopes": "customer.read", "tenant_id": None}
    }
    _write_yaml(eval_path, eval_document)

    arguments = _parser().parse_args(["test", "runtime", str(project), "--json"])
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.ok is False
    assert envelope.result is None
    assert [item.code for item in envelope.diagnostics] == ["ACC_EVAL_FIXTURE_LOAD_FAILED"]


@pytest.mark.parametrize("through_mcp", [False, True])
def test_runtime_eval_preserves_body_error_when_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    through_mcp: bool,
) -> None:
    import anyio

    project = _make_valid_project(tmp_path)
    eval_path = project / "evals" / "get-customer-normal.yaml"
    eval_document = yaml.safe_load(eval_path.read_text(encoding="utf-8"))
    eval_document.pop("expected_output_schema")
    eval_document["expected_calls"] = []
    eval_document["expected_error"] = {
        "code": _FakeStdioError.code,
        "status": _FakeStdioError.status,
    }
    _write_yaml(eval_path, eval_document)
    compilation = compile_project(project)
    assert compilation.ok is True
    assert compilation.ir is not None
    body_secret = "eval-body-secret-must-not-leak"
    close_secret = "eval-close-secret-must-not-leak"
    body_error = _FakeStdioError(body_secret)

    class UnusedProvider:
        async def call(self, *args: object, **kwargs: object) -> JsonValue:
            del self, args, kwargs
            return {}

    class FakeEvalRuntime(_FakeRuntime):
        def __init__(self) -> None:
            super().__init__(close_error=ValueError(close_secret))
            self.provider = UnusedProvider()

        async def call(self, *args: object, **kwargs: object) -> JsonValue:
            del self, args, kwargs
            raise body_error

    runtime = FakeEvalRuntime()

    def fake_from_pack(cls: object, /, *args: object, **kwargs: object) -> FakeEvalRuntime:
        del cls, args, kwargs
        return runtime

    monkeypatch.setattr(GenericRuntime, "from_pack", classmethod(fake_from_pack))

    report = anyio.run(
        _run_runtime_eval_report,
        cast(dict[str, Any], compilation.ir),
        project,
        through_mcp,
    )

    assert report.ok is True
    assert runtime.close_calls == 1
    assert body_error.__cause__ is None
    assert body_error.__context__ is None
    assert body_secret not in repr(report)
    assert close_secret not in repr(report)


def test_acc_console_entrypoint_help_lists_milestone_one_commands() -> None:
    completed = _run_command(["uv", "run", "--frozen", "acc", "--help"])

    assert completed.returncode == 0, completed.stderr
    help_text = completed.stdout.lower()
    assert "usage: acc" in help_text
    for command in ("init", "doctor", "schema", "validate"):
        assert command in help_text


def test_run_scope_flags_are_mutually_exclusive() -> None:
    completed = _run_acc(
        "run",
        "missing.accpkg",
        "--scope",
        "records.read",
        "--scope-ceiling-from-pack",
        "--json",
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert payload["diagnostics"][0]["code"] == "ACC_CLI_USAGE"
    assert "not allowed with argument" in payload["diagnostics"][0]["message"]


def test_init_creates_minimal_project_and_never_overwrites(tmp_path: Path) -> None:
    project = tmp_path / "my-acc-project"

    completed = _run_acc("init", str(project), "--json")

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(completed, command="init", ok=True)
    assert Path(payload["result"]["path"]) == project.resolve()
    assert (project / "project.yaml").is_file()
    project_document = yaml.safe_load((project / "project.yaml").read_text(encoding="utf-8"))
    assert project_document["schema_version"] == "2"
    assert project_document["quality"] == {"profile": "standard"}
    assert project_document["provider"]["auth"] == {"kind": "none"}
    assert {entry.name for entry in project.iterdir() if entry.is_dir()} >= PROJECT_DIRECTORIES
    assert not (project / "ui-interaction-inventory.yaml").exists()
    assert not (project / "domain-map.yaml").exists()
    assert not (project / "capability-candidates.yaml").exists()
    assert not any((project / "domain-decisions").iterdir())
    assert not any((project / "domain-change-requests").iterdir())

    original = (project / "project.yaml").read_text(encoding="utf-8")
    protected_content = f"{original}\n# this existing project must not be overwritten\n"
    (project / "project.yaml").write_text(protected_content, encoding="utf-8")

    repeated = _run_acc("init", str(project), "--json")

    assert repeated.returncode == 3
    repeated_payload = _json_envelope(repeated, command="init", ok=False)
    assert repeated_payload["diagnostics"][0]["code"] == "ACC_PROJECT_EXISTS"
    assert (project / "project.yaml").read_text(encoding="utf-8") == protected_content


def test_doctor_reports_environment_and_project_checks(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("doctor", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="doctor",
        ok=True,
        allow_warnings=True,
    )
    checks = {check["name"]: check for check in payload["result"]["checks"]}
    assert {"python", "project"} <= checks.keys()
    assert checks["python"]["ok"] is True
    assert checks["project"]["ok"] is True
    assert [item["code"] for item in payload["diagnostics"]] == [
        "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"
    ]


def test_schema_exports_all_models_as_draft_2020_12(tmp_path: Path) -> None:
    output = tmp_path / "schemas"

    completed = _run_acc("schema", "--output", str(output), "--json")

    assert completed.returncode == 0, completed.stderr
    _json_envelope(completed, command="schema", ok=True)
    assert {entry.name for entry in output.iterdir()} == EXPORTED_SCHEMAS
    for schema_path in output.iterdir():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["$schema"] == JSON_SCHEMA_DRAFT_2020_12

    project_schema = json.loads((output / "project.schema.json").read_text(encoding="utf-8"))

    def discriminators(value: object) -> list[dict[str, object]]:
        if isinstance(value, dict):
            found = [value["discriminator"]] if "discriminator" in value else []
            return found + [item for child in value.values() for item in discriminators(child)]
        if isinstance(value, list):
            return [item for child in value for item in discriminators(child)]
        return []

    kind_discriminators = [
        item for item in discriminators(project_schema) if item["propertyName"] == "kind"
    ]
    assert len(kind_discriminators) >= 2
    allowlist_schema = project_schema["$defs"]["ProviderConfig"]["properties"][
        "context_binding_allowlist"
    ]
    assert allowlist_schema["uniqueItems"] is True
    assert allowlist_schema["items"]["pattern"].startswith("^tenant_context")
    application_success = project_schema["$defs"]["ProviderConfig"]["properties"][
        "application_success"
    ]
    assert application_success["anyOf"][0]["$ref"].endswith("/JsonPointerApplicationSuccessConfig")

    operation_schema = json.loads((output / "operation.schema.json").read_text(encoding="utf-8"))
    binding_schema = operation_schema["$defs"]["ReadOperationV2"]["properties"]["context_bindings"][
        "additionalProperties"
    ]
    assert "principal_id" in binding_schema["pattern"]
    assert "tenant_context" in binding_schema["pattern"]
    concurrency_schema = operation_schema["$defs"]["ConcurrencyContractV2"]
    assert concurrency_schema["discriminator"]["propertyName"] == "mode"
    assert set(concurrency_schema["discriminator"]["mapping"]) == {
        "not_supported",
        "required",
        "server_serialized_state_predicate",
    }
    idempotency_schema = operation_schema["$defs"]["IdempotencyContractV2"]
    assert idempotency_schema["discriminator"]["propertyName"] == "mode"
    assert "state_idempotent" in idempotency_schema["discriminator"]["mapping"]

    source_contract_schema = json.loads(
        (output / "source-contract.schema.json").read_text(encoding="utf-8")
    )
    assert source_contract_schema["properties"]["schema_version"]["const"] == "2"
    outcome_schema = source_contract_schema["$defs"]["OutcomeResolutionContractV2"]
    assert outcome_schema["discriminator"]["propertyName"] == "mode"
    assert "status_query" in outcome_schema["discriminator"]["mapping"]
    provenance_schema = source_contract_schema["$defs"]["ActionSemanticsProvenance"]
    assert set(provenance_schema["properties"]["field"]["enum"]) == {
        "conflict_control",
        "effect",
        "idempotency",
        "outcome_resolution",
        "reversibility",
        "retry",
        "risk",
    }
    scope_inventory_schema = json.loads(
        (output / "scope-inventory.schema.json").read_text(encoding="utf-8")
    )
    assert scope_inventory_schema["properties"]["schema_version"]["const"] == "2"
    ui_inventory_schema = json.loads(
        (output / "ui-interaction-inventory.schema.json").read_text(encoding="utf-8")
    )
    assert ui_inventory_schema["properties"]["schema_version"]["const"] == "2"
    for filename in (
        "domain-map.schema.json",
        "capability-candidates.schema.json",
        "domain-decision.schema.json",
        "domain-change-request.schema.json",
        "domain-evidence-change-set.schema.json",
    ):
        domain_schema = json.loads((output / filename).read_text(encoding="utf-8"))
        assert domain_schema["properties"]["schema_version"]["const"] == "2"
    change_input_schema = json.loads(
        (output / "domain-evidence-change-set.schema.json").read_text(encoding="utf-8")
    )
    assert change_input_schema["properties"]["changed_evidence"]["minItems"] == 1
    assert change_input_schema["properties"]["changed_evidence"]["maxItems"] == 1000
    interaction_contract_schema = json.loads(
        (output / "interaction-contract.schema.json").read_text(encoding="utf-8")
    )
    assert interaction_contract_schema["properties"]["schema_version"]["const"] == "2"
    for filename in EXPORTED_SCHEMAS:
        assert (output / filename).read_bytes() == (
            REPOSITORY_ROOT / "schemas" / filename
        ).read_bytes()


def test_validate_accepts_an_evidence_bound_project(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("validate", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="validate",
        ok=True,
        allow_warnings=True,
    )
    assert payload["result"]["project_id"] == "example-crm"
    assert payload["result"]["counts"] == {
        "operations": 1,
        "capabilities": 1,
        "policies": 1,
        "evals": 1,
    }
    assert [item["code"] for item in payload["diagnostics"]] == [
        "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"
    ]


def test_compile_check_preserves_quality_warning(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("compile", "--check", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="compile",
        ok=True,
        allow_warnings=True,
    )
    assert [item["code"] for item in payload["diagnostics"]] == [
        "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"
    ]


def test_successful_default_output_writes_warnings_to_stderr(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("validate", cwd=project)

    assert completed.returncode == 0
    assert "validate: ok" in completed.stdout
    assert "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN" in completed.stderr


@pytest.mark.parametrize("json_output", [False, True])
def test_pack_success_preserves_compile_warnings(
    tmp_path: Path,
    json_output: bool,
) -> None:
    project = _make_valid_project(tmp_path)
    arguments = ["pack", "--output", "build/test.accpkg"]
    if json_output:
        arguments.append("--json")

    completed = _run_acc(*arguments, cwd=project)

    assert completed.returncode == 0, completed.stderr
    if json_output:
        payload = _json_envelope(
            completed,
            command="pack",
            ok=True,
            allow_warnings=True,
        )
        assert [item["code"] for item in payload["diagnostics"]] == [
            "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"
        ]
    else:
        assert "pack: ok" in completed.stdout
        assert "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN" in completed.stderr


def test_coverage_success_preserves_validation_warning(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("coverage", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="coverage",
        ok=True,
        allow_warnings=True,
    )
    assert [item["code"] for item in payload["diagnostics"]] == [
        "ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN"
    ]


def test_validate_rejects_an_operation_without_evidence(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["evidence"] = []
    _write_yaml(operation_path, operation)

    completed = _run_acc("validate", "--json", cwd=project)

    assert completed.returncode == 3
    payload = _json_envelope(completed, command="validate", ok=False)
    assert payload["diagnostics"][0] == {
        "code": "ACC_OPERATION_EVIDENCE_MISSING",
        "severity": "error",
        "message": "Operation requires at least one evidence reference.",
        "path": "operations/crm.get_customer.yaml",
        "pointer": "/evidence",
    }


def test_cli_usage_error_has_json_envelope_and_exit_code_two() -> None:
    completed = _run_acc("validate", "--unknown-option", "--json")

    assert completed.returncode == 2
    payload = _json_envelope(completed, command="validate", ok=False)
    assert payload["diagnostics"][0]["code"] == "ACC_CLI_USAGE"
    assert payload["diagnostics"][0]["severity"] == "error"


def test_adapter_init_creates_isolated_read_only_adapter_skeleton(tmp_path: Path) -> None:
    target = tmp_path / "customer-adapter"

    completed = _run_acc("adapter", "init", str(target), "--json")

    payload = _json_envelope(completed, command="adapter init", ok=True)
    assert payload["result"]["path"] == str(target.resolve())
    assert (target / "pyproject.toml").is_file()
    assert (target / "contract.yaml").is_file()
    contract = yaml.safe_load((target / "contract.yaml").read_text(encoding="utf-8"))
    assert contract["schema_version"] == "2"
    assert contract["base_path"] == "/adapter/v2"
    main = (target / "src" / "customer_adapter" / "main.py").read_text(encoding="utf-8")
    assert "AdapterServer" in main
    assert "POST" not in main

    repeated = _run_acc("adapter", "init", str(target), "--json")
    repeated_payload = _json_envelope(repeated, command="adapter init", ok=False)
    assert repeated.returncode == 3
    assert repeated_payload["diagnostics"][0]["code"] == "ACC_ADAPTER_EXISTS"

    occupied_file = tmp_path / "occupied"
    occupied_file.write_text("keep", encoding="utf-8")
    occupied = _run_acc("adapter", "init", str(occupied_file), "--json")
    occupied_payload = _json_envelope(occupied, command="adapter init", ok=False)
    assert occupied.returncode == 3
    assert occupied_payload["diagnostics"][0]["code"] == "ACC_ADAPTER_EXISTS"
    assert occupied_file.read_text(encoding="utf-8") == "keep"
