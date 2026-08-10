from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import JsonValue

from acc_runtime.context import PrincipalContext
from acc_runtime.execution import ExecutionError
from acc_runtime.runtime import GenericRuntime


class _Provider:
    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        del operation, arguments
        return {"message": "你好世界"}


def _v2_ir(*, max_output_bytes: int) -> dict[str, Any]:
    operation = {
        "schema_version": "2",
        "kind": "read",
        "id": "messages.get",
        "title": "Get message",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "output_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["message"],
            "properties": {"message": {"type": "string"}},
        },
        "http": {
            "method": "GET",
            "path": "/message",
            "path_parameters": {},
            "query_parameters": {},
            "request": None,
            "success": {"statuses": [200], "body": "json"},
            "scopes": [],
            "timeout_seconds": 15,
            "max_response_bytes": 1024,
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
                "source_id": "messages",
                "kind": "openapi",
                "path": "openapi.json",
                "json_pointer": "/paths/~1message/get",
                "digest": "sha256:" + "a" * 64,
            }
        ],
    }
    capability = {
        "schema_version": "2",
        "kind": "read",
        "id": "messages.inspect",
        "title": "Inspect message",
        "description": "Inspect one message.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "output_schema": operation["output_schema"],
        "workflow": [
            {
                "id": "message",
                "call": {"operation": "messages.get", "arguments": {}},
            },
            {"emit": {"value": "$.steps.message"}},
        ],
        "policy": "messages-read",
        "evals": ["messages-inspect"],
    }
    return {
        "ir_version": "2",
        "project": {
            "schema_version": "2",
            "project": {"id": "messages", "version": "2.0.0"},
            "source_workspace": {"path": "/srv/messages", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "MESSAGES_URL"},
            "quality": {"profile": "standard"},
        },
        "operations": {"messages.get": operation},
        "policies": {
            "messages-read": {
                "schema_version": "1",
                "id": "messages-read",
                "required_scopes": [],
                "tenant_mode": "none",
                "tenant_field": None,
                "readable_fields": ["message"],
                "denied_fields": [],
                "redaction_rules": [],
            }
        },
        "evals": {},
        "capabilities": {
            "messages.inspect": {
                "definition": capability,
                "operation_dependencies": ["messages.get"],
                "quality": {"max_output_bytes": max_output_bytes},
            }
        },
    }


def _principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="user-1",
        gateway_session_id=None,
        target_system_id="messages",
        source_scopes=None,
        deployment_scope_ceiling=frozenset(),
        tenant_context=None,
        auth_state_handle="auth-user-1",
    )


@pytest.mark.asyncio
async def test_v2_read_capability_executes_without_changing_v1_contracts() -> None:
    ir = _v2_ir(max_output_bytes=1024)
    ir["capabilities"]["messages.change"] = {
        "definition": {
            "schema_version": "2",
            "kind": "action",
            "id": "messages.change",
        }
    }
    runtime = GenericRuntime(
        ir,
        provider=_Provider(),
        principal_context=_principal(),
    )

    assert [tool["name"] for tool in runtime.tools()] == ["messages.inspect"]
    assert await runtime.call("messages.inspect", {}) == {"message": "你好世界"}


@pytest.mark.asyncio
async def test_v2_output_budget_is_enforced_after_policy_and_schema_validation() -> None:
    runtime = GenericRuntime(
        _v2_ir(max_output_bytes=1),
        provider=_Provider(),
        principal_context=_principal(),
    )

    with pytest.raises(ExecutionError) as captured:
        await runtime.call("messages.inspect", {})

    assert captured.value.code == "ACC_RUNTIME_CAPABILITY_OUTPUT_TOO_LARGE"
    assert captured.value.details == {
        "capability_id": "messages.inspect",
        "actual_bytes": 26,
        "limit_bytes": 1,
    }
    assert "你好世界" not in repr(captured.value)
