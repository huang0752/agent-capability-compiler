from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import JsonValue

from acc_runtime.policies import PolicyScopeDeniedError
from acc_runtime.runtime import GenericRuntime


def _ir() -> dict[str, Any]:
    operation = {
        "schema_version": "1",
        "id": "crm.get_customer",
        "title": "Get customer",
        "kind": "http",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["customer_id"],
            "properties": {
                "customer_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
        },
        "output_schema": {"type": "object"},
        "http": {
            "method": "GET",
            "path": "/customers/{customer_id}",
            "path_parameters": {"customer_id": "customer_id"},
            "query_parameters": {},
            "credential_ref": "CRM_TOKEN",
            "scopes": ["customer.read", "customer.detail"],
            "timeout_seconds": 15,
            "max_response_bytes": 1048576,
        },
        "safety": {"effect": "read"},
        "evidence": [
            {
                "source_id": "crm",
                "locator": "routes.py#L1-L5",
                "digest": f"sha256:{'a' * 64}",
            }
        ],
    }
    policy = {
        "schema_version": "1",
        "id": "crm-read",
        "required_scopes": ["customer.read"],
        "tenant_mode": "required",
        "tenant_field": "tenant_id",
        "readable_fields": ["id", "name", "tenant_id"],
        "denied_fields": ["secret"],
        "redaction_rules": [],
    }
    capability = {
        "schema_version": "1",
        "id": "get_customer",
        "title": "Get customer",
        "description": "Get one visible customer.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["customer_id"],
            "properties": {"customer_id": {"type": "string"}},
        },
        "output_schema": {
            "type": "object",
            "required": ["id", "name", "tenant_id"],
        },
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
        "policy": "crm-read",
        "evals": ["normal", "forbidden"],
    }
    return {
        "ir_version": "1",
        "project": {
            "schema_version": "1",
            "project": {"id": "crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_URL"},
        },
        "operations": {"crm.get_customer": operation},
        "policies": {"crm-read": policy},
        "evals": {},
        "capabilities": {
            "get_customer": {
                "definition": capability,
                "operation_dependencies": ["crm.get_customer"],
            }
        },
    }


class FakeProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        self.calls.append((str(operation["id"]), dict(arguments)))
        return {
            "id": str(arguments["customer_id"]),
            "name": "Ada",
            "tenant_id": str(arguments["tenant_id"]),
            "secret": "must-not-leave-runtime",
        }


@pytest.mark.asyncio
async def test_generic_runtime_injects_context_enforces_scopes_and_filters_output() -> None:
    provider = FakeProvider()
    runtime = GenericRuntime(
        _ir(),
        provider=provider,
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="tenant-a",
    )

    result = await runtime.call("get_customer", {"customer_id": "c-1"})

    assert provider.calls == [
        (
            "crm.get_customer",
            {"customer_id": "c-1", "tenant_id": "tenant-a"},
        )
    ]
    assert result == {"id": "c-1", "name": "Ada", "tenant_id": "tenant-a"}
    assert "must-not-leave-runtime" not in repr(result)


@pytest.mark.asyncio
async def test_generic_runtime_filters_before_validating_public_output_schema() -> None:
    ir = _ir()
    policy = ir["policies"]["crm-read"]
    policy["readable_fields"] = ["id", "name"]
    capability = ir["capabilities"]["get_customer"]["definition"]
    capability["output_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "name"],
        "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
    }
    runtime = GenericRuntime(
        ir,
        provider=FakeProvider(),
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="tenant-a",
    )

    result = await runtime.call("get_customer", {"customer_id": "c-1"})

    assert result == {"id": "c-1", "name": "Ada"}


def test_generic_runtime_exposes_stable_tool_contracts() -> None:
    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        granted_scopes={"customer.read", "customer.detail"},
        tenant_id="tenant-a",
    )

    assert runtime.tools() == [
        {
            "name": "get_customer",
            "title": "Get customer",
            "description": "Get one visible customer.",
            "input_schema": _ir()["capabilities"]["get_customer"]["definition"]["input_schema"],
            "output_schema": _ir()["capabilities"]["get_customer"]["definition"]["output_schema"],
        }
    ]


@pytest.mark.asyncio
async def test_generic_runtime_requires_operation_and_policy_scopes() -> None:
    runtime = GenericRuntime(
        _ir(),
        provider=FakeProvider(),
        granted_scopes={"customer.read"},
        tenant_id="tenant-a",
    )

    with pytest.raises(PolicyScopeDeniedError) as caught:
        await runtime.call("get_customer", {"customer_id": "c-1"})

    assert caught.value.details == {
        "policy": "crm-read",
        "missing_scopes": ["customer.detail"],
    }
