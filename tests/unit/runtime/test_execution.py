from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.execution import ExecutionError, WorkflowExecutor

JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None


def _operation(operation_id: str, *, output_schema: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "id": operation_id,
        "title": operation_id,
        "kind": "http",
        "input_schema": {"type": "object"},
        "output_schema": output_schema or {},
        "http": {},
        "safety": {"effect": "read"},
        "evidence": [],
    }


def _compiled_ir(workflow: list[dict[str, Any]], operations: list[str]) -> dict[str, Any]:
    return {
        "ir_version": "1",
        "operations": {operation_id: _operation(operation_id) for operation_id in operations},
        "capabilities": {
            "customer_context": {
                "definition": {
                    "schema_version": "1",
                    "id": "customer_context",
                    "title": "Customer context",
                    "description": "Exercise the bounded workflow executor.",
                    "input_schema": {
                        "type": "object",
                        "required": ["customer_id", "include"],
                        "properties": {
                            "customer_id": {"type": "string"},
                            "include": {"type": "boolean"},
                        },
                        "additionalProperties": False,
                    },
                    "output_schema": {"type": "object"},
                    "workflow": workflow,
                    "policy": "crm-read",
                    "evals": ["normal"],
                },
                "operation_dependencies": sorted(operations),
            }
        },
    }


class FakeOperationCaller:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []
        self.completions: list[str] = []

    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        operation_id = str(operation["id"])
        self.calls.append((operation_id, dict(arguments)))
        if operation_id == "crm.get_customer":
            return {
                "id": arguments["customer_id"],
                "name": "Ada",
                "ok": True,
                "secret": "never-return-this",
                "contacts": [
                    {"name": "first", "active": True, "rank": 3},
                    {"name": "second", "active": False, "rank": 2},
                    {"name": "third", "active": True, "rank": 1},
                ],
            }
        if operation_id == "crm.parallel_slow":
            await asyncio.sleep(0.02)
            self.completions.append("parallel-slow")
            return "parallel-slow"
        if operation_id == "crm.parallel_fast":
            self.completions.append("parallel-fast")
            return "parallel-fast"
        if operation_id == "crm.lookup":
            name = str(arguments["name"])
            await asyncio.sleep({"first": 0.02, "second": 0.01, "third": 0}[name])
            self.completions.append(name)
            return {"found": name}
        raise AssertionError(f"unexpected operation: {operation_id}")


@pytest.mark.asyncio
async def test_executor_runs_all_bounded_steps_and_preserves_async_result_order() -> None:
    workflow: list[dict[str, Any]] = [
        {
            "id": "customer",
            "call": {
                "operation": "crm.get_customer",
                "arguments": {"customer_id": "$.input.customer_id"},
            },
        },
        {
            "id": "picked",
            "pick": {"value": "$.steps.customer", "fields": ["id", "name"]},
        },
        {
            "id": "names",
            "map": {
                "items": "$.steps.customer.contacts",
                "expression": "$.item.name",
                "max_items": 3,
            },
        },
        {
            "id": "active",
            "filter": {
                "items": "$.steps.customer.contacts",
                "condition": "$.item.active",
                "max_items": 3,
            },
        },
        {"assert": {"condition": "$.steps.customer.ok", "message": "customer unavailable"}},
        {
            "id": "safe",
            "redact": {"value": "$.steps.customer", "fields": ["secret", "contacts"]},
        },
        {
            "id": "selected",
            "branch": {
                "condition": "$.input.include",
                "then": [{"emit": {"value": "$.steps.safe"}}],
                "else": [{"emit": {"value": "$.steps.picked"}}],
            },
        },
        {
            "id": "parallel_results",
            "parallel": [
                {"call": {"operation": "crm.parallel_slow", "arguments": {}}},
                {"call": {"operation": "crm.parallel_fast", "arguments": {}}},
            ],
        },
        {
            "id": "lookups",
            "foreach": {
                "items": "$.steps.customer.contacts",
                "item_name": "contact",
                "max_items": 3,
                "workflow": [
                    {
                        "id": "lookup",
                        "call": {
                            "operation": "crm.lookup",
                            "arguments": {"name": "$.item.name"},
                        },
                    },
                    {"emit": {"value": "$.steps.lookup"}},
                ],
            },
        },
        {
            "emit": {
                "value": {
                    "picked": "$.steps.picked",
                    "names": "$.steps.names",
                    "active": "$.steps.active",
                    "selected": "$.steps.selected",
                    "parallel": "$.steps.parallel_results",
                    "lookups": "$.steps.lookups",
                }
            }
        },
    ]
    operations = [
        "crm.get_customer",
        "crm.lookup",
        "crm.parallel_fast",
        "crm.parallel_slow",
    ]
    caller = FakeOperationCaller()

    result = await WorkflowExecutor(caller).execute(
        _compiled_ir(workflow, operations),
        "customer_context",
        {"customer_id": "c-1", "include": True},
    )

    assert result == {
        "picked": {"id": "c-1", "name": "Ada"},
        "names": ["first", "second", "third"],
        "active": [
            {"name": "first", "active": True, "rank": 3},
            {"name": "third", "active": True, "rank": 1},
        ],
        "selected": {"id": "c-1", "name": "Ada", "ok": True},
        "parallel": ["parallel-slow", "parallel-fast"],
        "lookups": [
            {"found": "first"},
            {"found": "second"},
            {"found": "third"},
        ],
    }
    assert caller.completions[:2] == ["parallel-fast", "parallel-slow"]
    assert caller.completions[2:] == ["third", "second", "first"]
    assert "never-return-this" not in repr(result)


class _NeverCalled:
    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        raise AssertionError("operation caller must not run")


@pytest.mark.asyncio
async def test_executor_rejects_capability_input_without_exposing_its_values() -> None:
    ir = _compiled_ir([{"emit": {"value": {}}}], [])
    secret = "top-secret-input"

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_NeverCalled()).execute(
            ir,
            "customer_context",
            {"customer_id": secret, "include": "not-a-boolean"},
        )

    error = caught.value
    assert error.code == "ACC_RUNTIME_INPUT_INVALID"
    assert error.to_dict()["code"] == "ACC_RUNTIME_INPUT_INVALID"
    assert secret not in repr(error)
    assert secret not in repr(error.to_dict())


class _BadOutputCaller:
    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        return {"customer_id": 17}


@pytest.mark.asyncio
async def test_executor_validates_operation_output_schema_before_storing_step_result() -> None:
    workflow: list[dict[str, Any]] = [
        {
            "id": "customer",
            "call": {
                "operation": "crm.get_customer",
                "arguments": {"customer_id": "$.input.customer_id"},
            },
        },
        {"emit": {"value": "$.steps.customer"}},
    ]
    ir = _compiled_ir(workflow, ["crm.get_customer"])
    ir["operations"]["crm.get_customer"]["output_schema"] = {
        "type": "object",
        "required": ["customer_id"],
        "properties": {"customer_id": {"type": "string"}},
    }

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_BadOutputCaller()).execute(
            ir,
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )

    assert caught.value.code == "ACC_RUNTIME_OPERATION_OUTPUT_INVALID"
    assert caught.value.details == {
        "capability_id": "customer_context",
        "operation_id": "crm.get_customer",
        "step_id": "customer",
        "schema_role": "operation_output",
    }


@pytest.mark.asyncio
async def test_executor_validates_operation_input_before_calling_provider() -> None:
    workflow: list[dict[str, Any]] = [
        {
            "call": {
                "operation": "crm.get_customer",
                "arguments": {"customer_id": "$.input.customer_id"},
            }
        },
        {"emit": {"value": {}}},
    ]
    ir = _compiled_ir(workflow, ["crm.get_customer"])
    ir["operations"]["crm.get_customer"]["input_schema"] = {
        "type": "object",
        "required": ["customer_id"],
        "properties": {"customer_id": {"type": "integer"}},
    }

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_NeverCalled()).execute(
            ir,
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )

    assert caught.value.code == "ACC_RUNTIME_OPERATION_INPUT_INVALID"


class _ObjectOutputCaller:
    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        return {"id": "c-1"}


@pytest.mark.asyncio
async def test_executor_validates_final_emit_against_capability_output_schema() -> None:
    workflow: list[dict[str, Any]] = [
        {"id": "customer", "call": {"operation": "crm.get_customer", "arguments": {}}},
        {"emit": {"value": "$.steps.customer"}},
    ]
    ir = _compiled_ir(workflow, ["crm.get_customer"])
    ir["capabilities"]["customer_context"]["definition"]["output_schema"] = {"type": "array"}

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_ObjectOutputCaller()).execute(
            ir,
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )

    assert caught.value.code == "ACC_RUNTIME_OUTPUT_INVALID"


class _ExplodingCaller:
    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        raise ValueError(f"credential=secret-token arguments={arguments!r}")


@pytest.mark.asyncio
async def test_executor_sanitizes_unstructured_operation_exceptions() -> None:
    workflow: list[dict[str, Any]] = [
        {
            "call": {
                "operation": "crm.get_customer",
                "arguments": {"customer_id": "$.input.customer_id"},
            }
        },
        {"emit": {"value": {}}},
    ]

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_ExplodingCaller()).execute(
            _compiled_ir(workflow, ["crm.get_customer"]),
            "customer_context",
            {"customer_id": "customer-secret", "include": True},
        )

    assert caught.value.code == "ACC_RUNTIME_OPERATION_FAILED"
    public_error = repr(caught.value.to_dict())
    assert "secret-token" not in repr(caught.value)
    assert "customer-secret" not in repr(caught.value)
    assert "secret-token" not in public_error
    assert "customer-secret" not in public_error


class _ProviderNotFound(AccRuntimeError):
    code = "ACC_PROVIDER_NOT_FOUND"
    status = 404


class _StructuredFailureCaller:
    def __init__(self, failure: AccRuntimeError) -> None:
        self.failure = failure

    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        raise self.failure


@pytest.mark.asyncio
async def test_executor_preserves_structured_provider_failures() -> None:
    workflow: list[dict[str, Any]] = [
        {"call": {"operation": "crm.get_customer", "arguments": {}}},
        {"emit": {"value": {}}},
    ]
    failure = _ProviderNotFound("upstream detail", details={"operation_id": "crm.get_customer"})

    with pytest.raises(_ProviderNotFound) as caught:
        await WorkflowExecutor(_StructuredFailureCaller(failure)).execute(
            _compiled_ir(workflow, ["crm.get_customer"]),
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )

    assert caught.value is failure
    assert caught.value.to_dict() == {
        "code": "ACC_PROVIDER_NOT_FOUND",
        "status": 404,
        "details": {"operation_id": "crm.get_customer"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("action_name", ["map", "filter", "foreach"])
async def test_executor_rejects_collection_values_above_declared_max_items(
    action_name: str,
) -> None:
    if action_name == "map":
        bounded_action: dict[str, Any] = {
            "items": "$.input.items",
            "expression": "$.item",
            "max_items": 2,
        }
    elif action_name == "filter":
        bounded_action = {
            "items": "$.input.items",
            "condition": "$.item",
            "max_items": 2,
        }
    else:
        bounded_action = {
            "items": "$.input.items",
            "item_name": "item",
            "max_items": 2,
            "workflow": [{"emit": {"value": "$.item"}}],
        }
    workflow: list[dict[str, Any]] = [
        {"id": "bounded", action_name: bounded_action},
        {"emit": {"value": "$.steps.bounded"}},
    ]
    ir = _compiled_ir(workflow, [])
    ir["capabilities"]["customer_context"]["definition"]["input_schema"] = {
        "type": "object",
        "required": ["items"],
        "properties": {"items": {"type": "array"}},
    }

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_NeverCalled()).execute(
            ir,
            "customer_context",
            {"items": [1, 2, 3]},
        )

    assert caught.value.code == "ACC_RUNTIME_BOUND_EXCEEDED"
    assert caught.value.details["limit"] == 2


@pytest.mark.asyncio
async def test_executor_only_resolves_compiler_allowed_static_references() -> None:
    ir = _compiled_ir([{"emit": {"value": "${$.input.customer_id}"}}], [])

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_NeverCalled()).execute(
            ir,
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )

    assert caught.value.code == "ACC_RUNTIME_REFERENCE_INVALID"


@pytest.mark.asyncio
async def test_executor_rejects_failed_assertion_without_exposing_declared_message() -> None:
    sensitive_message = "secret-token should never be public"
    workflow: list[dict[str, Any]] = [
        {
            "assert": {
                "condition": "$.input.include",
                "message": sensitive_message,
            }
        },
        {"emit": {"value": {}}},
    ]

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_NeverCalled()).execute(
            _compiled_ir(workflow, []),
            "customer_context",
            {"customer_id": "c-1", "include": False},
        )

    assert caught.value.code == "ACC_RUNTIME_ASSERTION_FAILED"
    assert sensitive_message not in repr(caught.value)
    assert sensitive_message not in repr(caught.value.to_dict())


@pytest.mark.asyncio
async def test_executor_defensively_enforces_parallel_and_final_emit_bounds() -> None:
    too_wide: list[dict[str, Any]] = [{"emit": {"value": index}} for index in range(9)]
    workflow: list[dict[str, Any]] = [
        {"parallel": too_wide},
        {"emit": {"value": {}}},
    ]

    with pytest.raises(ExecutionError) as caught:
        await WorkflowExecutor(_NeverCalled()).execute(
            _compiled_ir(workflow, []),
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )

    assert caught.value.code == "ACC_RUNTIME_BOUND_EXCEEDED"
    assert caught.value.details["limit"] == 8

    without_emit = _compiled_ir([{"pick": {"value": {}, "fields": ["id"]}}], [])
    with pytest.raises(ExecutionError) as missing_emit:
        await WorkflowExecutor(_NeverCalled()).execute(
            without_emit,
            "customer_context",
            {"customer_id": "c-1", "include": True},
        )
    assert missing_emit.value.code == "ACC_RUNTIME_FINAL_EMIT_REQUIRED"
