from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import JsonValue

from acc_runtime.context import PrincipalContext
from acc_runtime.execution import ExecutionError
from acc_runtime.runtime import GenericRuntime, RuntimeConfigurationError


class _Provider:
    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        del operation, arguments
        return {"message": "你好世界"}


def _interaction_attestation(
    *, defaults: list[dict[str, object]] | None = None
) -> tuple[dict[str, object], str]:
    contract: dict[str, object] = {
        "action_lifecycle": None,
        "capability_id": "messages.inspect",
        "conditions": [],
        "defaults": defaults or [],
        "inherited_interactions": {},
        "interaction_ids": [],
        "omitted_interaction_ids": [],
        "option_sources": [],
        "overridden_interaction_ids": [],
        "public_input_bindings": [],
        "related_data": [],
        "required_scenarios": [],
        "result_consumption": [],
        "sidecar_sha256": "d" * 64,
    }
    payload: dict[str, object] = {
        "schema_version": "2",
        "inventory": {"status": "not_declared"},
        "contracts": ({"messages.inspect": contract} if defaults is not None else {}),
        "dependencies": [],
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return {**payload, "digest": digest}, digest


def _rehash_interactions(ir: dict[str, Any]) -> None:
    interactions = ir["interactions"]
    assert isinstance(interactions, dict)
    payload = {key: value for key, value in interactions.items() if key != "digest"}
    digest = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    interactions["digest"] = digest
    ir["interaction_sha256"] = digest


def _v2_ir(*, max_output_bytes: int) -> dict[str, Any]:
    interactions, interaction_sha256 = _interaction_attestation()
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
        "interactions": interactions,
        "interaction_sha256": interaction_sha256,
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
                "schema_version": "2",
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


def test_generic_runtime_rejects_a_legacy_project_before_exposing_tools() -> None:
    legacy = _v2_ir(max_output_bytes=1024)
    legacy["ir_version"] = "1"
    legacy["project"] = {
        "schema_version": "1",
        "project": {"id": "messages", "version": "1.0.0"},
        "source_workspace": {"path": "/srv/messages", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {"kind": "http", "base_url_ref": "MESSAGES_URL"},
    }

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime(legacy, provider=_Provider(), principal_context=_principal())

    assert caught.value.details == {"reason": "ir_version_invalid"}


def test_generic_runtime_exposes_a_defensive_copy_of_verified_interactions() -> None:
    runtime = GenericRuntime(
        _v2_ir(max_output_bytes=1024),
        provider=_Provider(),
        principal_context=_principal(),
    )

    first = runtime.interaction_manifest()
    first["inventory"] = {"status": "tampered"}

    assert runtime.interaction_manifest()["inventory"] == {"status": "not_declared"}
    assert runtime.interaction_sha256 == runtime.interaction_manifest()["digest"]


@pytest.mark.parametrize(
    "mutation", ["missing", "schema", "manifest_digest", "root_digest", "private"]
)
def test_generic_runtime_rejects_malformed_or_tampered_interactions_without_echoing(
    mutation: str,
) -> None:
    ir = _v2_ir(max_output_bytes=1024)
    interactions = ir["interactions"]
    assert isinstance(interactions, dict)
    if mutation == "missing":
        ir.pop("interactions")
        ir.pop("interaction_sha256")
    elif mutation == "schema":
        interactions["schema_version"] = "SECRET_SCHEMA"
    elif mutation == "manifest_digest":
        interactions["digest"] = "a" * 64
    elif mutation == "root_digest":
        ir["interaction_sha256"] = "b" * 64
    else:
        unsafe, _ = _interaction_attestation(
            defaults=[
                {
                    "id": "unsafe",
                    "source_kind": "trusted_context",
                    "target_pointer": "/SECRET_INTERNAL_POINTER",
                    "source_reference": "SECRET_REFERENCE",
                }
            ]
        )
        ir["interactions"] = unsafe
        _rehash_interactions(ir)

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime(ir, provider=_Provider(), principal_context=_principal())

    assert caught.value.details == {"reason": "interaction_manifest_invalid"}
    rendered = repr(caught.value)
    assert "SECRET" not in rendered


@pytest.mark.parametrize(
    "mutation",
    [
        "contract_field_deleted",
        "inventory_extra",
        "inventory_unsorted",
        "dependency_unknown",
        "dependency_unsorted",
        "dependency_duplicate",
    ],
)
def test_generic_runtime_rejects_rehashed_noncanonical_interaction_shapes(
    mutation: str,
) -> None:
    ir = _v2_ir(max_output_bytes=1024)
    interactions = ir["interactions"]
    assert isinstance(interactions, dict)
    if mutation == "contract_field_deleted":
        manifest, _ = _interaction_attestation(defaults=[])
        contracts = manifest["contracts"]
        assert isinstance(contracts, dict)
        contract = contracts["messages.inspect"]
        assert isinstance(contract, dict)
        contract.pop("required_scenarios")
        ir["interactions"] = manifest
    elif mutation.startswith("inventory_"):
        inventory: dict[str, object] = {
            "evidence_sha256": "a" * 64,
            "interaction_ids": ["b", "a"] if mutation == "inventory_unsorted" else [],
            "scope_mode": "discovered",
            "sidecar_sha256": "b" * 64,
            "status": "declared",
            "summary": {
                "interactions": 2 if mutation == "inventory_unsorted" else 0,
                "surfaces": 0,
                "unresolved": 0,
            },
            "surface_ids": [],
        }
        if mutation == "inventory_extra":
            inventory["SECRET_EXTRA"] = "SECRET_VALUE"
        interactions["inventory"] = inventory
    else:
        if mutation == "dependency_unknown":
            interactions["dependencies"] = [["SECRET_CAPABILITY", "messages.inspect"]]
        elif mutation == "dependency_unsorted":
            ir["capabilities"]["alpha"] = ir["capabilities"]["messages.inspect"]
            interactions["dependencies"] = [
                ["messages.inspect", "alpha"],
                ["alpha", "messages.inspect"],
            ]
        else:
            interactions["dependencies"] = [
                ["messages.inspect", "messages.inspect"],
                ["messages.inspect", "messages.inspect"],
            ]
    _rehash_interactions(ir)

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime(ir, provider=_Provider(), principal_context=_principal())

    assert caught.value.details == {"reason": "interaction_manifest_invalid"}
    assert "SECRET" not in repr(caught.value)


@pytest.mark.parametrize("target", ["/profile/unknown", "/rows/0/unknown"])
def test_generic_runtime_rejects_rehashed_default_for_unknown_nested_schema_pointer(
    target: str,
) -> None:
    ir = _v2_ir(max_output_bytes=1024)
    capability = ir["capabilities"]["messages.inspect"]["definition"]
    capability["input_schema"] = {
        "type": "object",
        "properties": {
            "profile": {"$ref": "#/$defs/profile"},
            "rows": {"type": "array", "items": {"$ref": "#/$defs/profile"}},
        },
        "$defs": {"profile": {"type": "object", "properties": {"locale": {"type": "string"}}}},
    }
    interactions, digest = _interaction_attestation(
        defaults=[
            {"id": "nested", "source_kind": "literal", "target_pointer": target, "value": "x"}
        ]
    )
    ir["interactions"] = interactions
    ir["interaction_sha256"] = digest

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime(ir, provider=_Provider(), principal_context=_principal())

    assert caught.value.details == {"reason": "interaction_manifest_invalid"}


def test_generic_runtime_accepts_default_target_resolved_through_local_ref() -> None:
    ir = _v2_ir(max_output_bytes=1024)
    capability = ir["capabilities"]["messages.inspect"]["definition"]
    capability["input_schema"] = {
        "type": "object",
        "properties": {
            "profile": {"$ref": "#/$defs/profile"},
            "rows": {"type": "array", "items": {"$ref": "#/$defs/profile"}},
        },
        "$defs": {"profile": {"type": "object", "properties": {"locale": {"type": "string"}}}},
    }
    interactions, digest = _interaction_attestation(
        defaults=[
            {
                "id": "nested",
                "source_kind": "literal",
                "target_pointer": "/profile/locale",
                "value": "x",
            }
        ]
    )
    ir["interactions"] = interactions
    ir["interaction_sha256"] = digest

    runtime = GenericRuntime(ir, provider=_Provider(), principal_context=_principal())

    assert runtime.interaction_sha256 == digest


def test_generic_runtime_rejects_rehashed_default_that_crosses_an_array() -> None:
    ir = _v2_ir(max_output_bytes=1024)
    capability = ir["capabilities"]["messages.inspect"]["definition"]
    capability["input_schema"] = {
        "type": "object",
        "properties": {
            "rows": {
                "type": "array",
                "items": {"type": "object", "properties": {"locale": {"type": "string"}}},
            }
        },
    }
    interactions, digest = _interaction_attestation(
        defaults=[
            {
                "id": "nested-array",
                "source_kind": "literal",
                "target_pointer": "/rows/0/locale",
                "value": "x",
            }
        ]
    )
    ir["interactions"] = interactions
    ir["interaction_sha256"] = digest

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime(ir, provider=_Provider(), principal_context=_principal())

    assert caught.value.details == {"reason": "interaction_manifest_invalid"}


def test_generic_runtime_rejects_rehashed_default_through_ref_with_asserting_sibling() -> None:
    ir = _v2_ir(max_output_bytes=1024)
    capability = ir["capabilities"]["messages.inspect"]["definition"]
    capability["input_schema"] = {
        "type": "object",
        "properties": {
            "profile": {"$ref": "#/$defs/profile", "type": "object"},
        },
        "$defs": {"profile": {"type": "object", "properties": {"locale": {"type": "string"}}}},
    }
    interactions, digest = _interaction_attestation(
        defaults=[
            {
                "id": "asserting-ref",
                "source_kind": "literal",
                "target_pointer": "/profile/locale",
                "value": "x",
            }
        ]
    )
    ir["interactions"] = interactions
    ir["interaction_sha256"] = digest

    with pytest.raises(RuntimeConfigurationError) as caught:
        GenericRuntime(ir, provider=_Provider(), principal_context=_principal())

    assert caught.value.details == {"reason": "interaction_manifest_invalid"}


class _CapturingProvider(_Provider):
    def __init__(self) -> None:
        self.arguments: list[dict[str, JsonValue]] = []

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        del operation
        self.arguments.append(dict(arguments))
        return {"message": "你好世界"}


def _default_ir() -> dict[str, Any]:
    ir = _v2_ir(max_output_bytes=1024)
    operation = ir["operations"]["messages.get"]
    operation["input_schema"]["properties"]["locale"] = {}
    capability = ir["capabilities"]["messages.inspect"]["definition"]
    capability["input_schema"]["properties"]["locale"] = {}
    capability["workflow"][0]["call"]["arguments"] = {"locale": "$.input.locale"}
    interactions, digest = _interaction_attestation(
        defaults=[
            {
                "id": "default-locale",
                "source_kind": "literal",
                "target_pointer": "/locale",
                "value": "zh-CN",
            }
        ]
    )
    ir["interactions"] = interactions
    ir["interaction_sha256"] = digest
    return ir


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("arguments", "expected"),
    [({}, "zh-CN"), ({"locale": None}, None), ({"locale": "en-US"}, "en-US")],
)
async def test_public_default_applies_only_when_argument_is_missing(
    arguments: dict[str, JsonValue], expected: JsonValue
) -> None:
    provider = _CapturingProvider()
    runtime = GenericRuntime(
        _default_ir(),
        provider=provider,
        principal_context=_principal(),
    )

    await runtime.call("messages.inspect", arguments)

    assert provider.arguments == [{"locale": expected}]


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
