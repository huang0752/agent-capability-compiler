"""Asynchronous execution of compiler-validated ACC workflows."""

from __future__ import annotations

import asyncio
import copy
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from jsonschema import Draft202012Validator, SchemaError

from acc_runtime.errors import RuntimeError as AccRuntimeError

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None

_REFERENCE_SEGMENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_REFERENCE_PATTERN = re.compile(
    rf"^\$\.(?:(?P<root>input|item)(?P<root_path>(?:\.{_REFERENCE_SEGMENT})*)"
    rf"|steps\.(?P<step>{_REFERENCE_SEGMENT})(?P<step_path>(?:\.{_REFERENCE_SEGMENT})*))$"
)
_KNOWN_ACTIONS = {
    "call",
    "pick",
    "map",
    "filter",
    "assert",
    "redact",
    "branch",
    "parallel",
    "foreach",
    "emit",
}
_MAX_PARALLEL_STEPS = 8
_MAX_COLLECTION_ITEMS = 100
_MAX_CONDITION_DEPTH = 16
_MAX_CONDITION_NODES = 64
_MISSING = object()


class ExecutionError(AccRuntimeError):
    """A stable runtime failure that never embeds workflow data in its message."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, str | int | None] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        # RuntimeError exposes a fixed class-level default. Execution errors use
        # one public type with several stable per-instance workflow codes.
        self.__dict__["code"] = code
        self.message = message


@runtime_checkable
class AsyncOperationCaller(Protocol):
    """Boundary between declarative workflow execution and an operation provider."""

    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        """Invoke one compiled operation and return its JSON result."""


@dataclass(slots=True)
class _ExecutionContext:
    input_data: JsonValue
    steps: dict[str, JsonValue]
    item: JsonValue | object = _MISSING

    def isolated(self, *, item: JsonValue | object = _MISSING) -> _ExecutionContext:
        return _ExecutionContext(
            input_data=self.input_data,
            steps=copy.deepcopy(self.steps),
            item=item,
        )


class WorkflowExecutor:
    """Execute one capability from deterministic compiler IR."""

    def __init__(
        self,
        operation_caller: AsyncOperationCaller,
        *,
        validate_output: bool = True,
        validate_operation_input: bool = True,
    ) -> None:
        self._operation_caller = operation_caller
        self._validate_output = validate_output
        self._validate_operation_input = validate_operation_input

    async def execute(
        self,
        compiled_ir: Mapping[str, Any],
        capability_id: str,
        input_data: JsonValue,
    ) -> JsonValue:
        """Validate and execute a capability, returning the value from its final emit."""

        safe_input = _copy_json(input_data, code="ACC_RUNTIME_INPUT_INVALID")
        capability = _capability_definition(compiled_ir, capability_id)
        _validate_schema(
            capability.get("input_schema"),
            safe_input,
            code="ACC_RUNTIME_INPUT_INVALID",
            capability_id=capability_id,
            schema_role="capability_input",
        )
        workflow = _required_list(
            capability.get("workflow"),
            code="ACC_RUNTIME_IR_INVALID",
            details={"capability_id": capability_id},
        )
        if not workflow or not isinstance(workflow[-1], Mapping) or "emit" not in workflow[-1]:
            raise ExecutionError(
                "ACC_RUNTIME_FINAL_EMIT_REQUIRED",
                "Capability workflow must end with an emit step.",
                details={"capability_id": capability_id},
            )

        operations = _required_mapping(
            compiled_ir.get("operations"),
            code="ACC_RUNTIME_IR_INVALID",
            details={"capability_id": capability_id},
        )
        result = await self._run_workflow(
            workflow,
            _ExecutionContext(input_data=safe_input, steps={}),
            operations,
            capability_id,
        )
        safe_result = _copy_json(result, code="ACC_RUNTIME_OUTPUT_INVALID")
        if self._validate_output:
            _validate_schema(
                capability.get("output_schema"),
                safe_result,
                code="ACC_RUNTIME_OUTPUT_INVALID",
                capability_id=capability_id,
                schema_role="capability_output",
            )
        return safe_result

    async def _run_workflow(
        self,
        workflow: Sequence[Any],
        context: _ExecutionContext,
        operations: Mapping[str, Any],
        capability_id: str,
    ) -> JsonValue:
        result: JsonValue = None
        for raw_step in workflow:
            step = _required_mapping(
                raw_step,
                code="ACC_RUNTIME_STEP_INVALID",
                details={"capability_id": capability_id},
            )
            step_id = step.get("id")
            if step_id is not None and not isinstance(step_id, str):
                raise ExecutionError(
                    "ACC_RUNTIME_STEP_INVALID",
                    "Workflow step id must be a string.",
                    details={"capability_id": capability_id},
                )
            result = await self._run_step(
                step,
                context,
                operations,
                capability_id,
                step_id=step_id,
            )
            if step_id is not None:
                context.steps[step_id] = copy.deepcopy(result)
        return result

    async def _run_step(
        self,
        step: Mapping[str, Any],
        context: _ExecutionContext,
        operations: Mapping[str, Any],
        capability_id: str,
        *,
        step_id: str | None,
    ) -> JsonValue:
        actions = [name for name in _KNOWN_ACTIONS if name in step]
        details = {"capability_id": capability_id, "step_id": step_id}
        if len(actions) != 1:
            raise ExecutionError(
                "ACC_RUNTIME_STEP_INVALID",
                "Workflow step must contain exactly one supported action.",
                details=details,
            )

        action_name = actions[0]
        action = step[action_name]
        if action_name == "call":
            return await self._call(action, context, operations, capability_id, step_id)
        if action_name == "pick":
            return _pick(action, context, details)
        if action_name == "map":
            return _map(action, context, details)
        if action_name == "filter":
            return _filter(action, context, details)
        if action_name == "assert":
            _assert(action, context, details)
            return None
        if action_name == "redact":
            return _redact(action, context, details)
        if action_name == "branch":
            branch = _required_mapping(action, code="ACC_RUNTIME_STEP_INVALID", details=details)
            condition = _evaluate_condition(branch.get("condition"), context, details)
            selected = branch.get("then" if condition else "else")
            workflow = _required_list(selected, code="ACC_RUNTIME_STEP_INVALID", details=details)
            return await self._run_workflow(
                workflow,
                context.isolated(item=context.item),
                operations,
                capability_id,
            )
        if action_name == "parallel":
            children = _required_list(action, code="ACC_RUNTIME_STEP_INVALID", details=details)
            if not 1 <= len(children) <= _MAX_PARALLEL_STEPS:
                raise ExecutionError(
                    "ACC_RUNTIME_BOUND_EXCEEDED",
                    "Parallel workflow exceeds its fixed execution bound.",
                    details={**details, "limit": _MAX_PARALLEL_STEPS},
                )
            return list(
                await asyncio.gather(
                    *(
                        self._run_workflow(
                            [child],
                            context.isolated(item=context.item),
                            operations,
                            capability_id,
                        )
                        for child in children
                    )
                )
            )
        if action_name == "foreach":
            foreach = _required_mapping(action, code="ACC_RUNTIME_STEP_INVALID", details=details)
            items = _resolve_value(foreach.get("items"), context, details)
            sequence = _bounded_items(items, foreach.get("max_items"), details)
            item_workflow = _required_list(
                foreach.get("workflow"), code="ACC_RUNTIME_STEP_INVALID", details=details
            )
            return list(
                await asyncio.gather(
                    *(
                        self._run_workflow(
                            item_workflow,
                            context.isolated(item=item),
                            operations,
                            capability_id,
                        )
                        for item in sequence
                    )
                )
            )
        if action_name == "emit":
            emit = _required_mapping(action, code="ACC_RUNTIME_STEP_INVALID", details=details)
            return _resolve_value(emit.get("value"), context, details)
        raise AssertionError("unreachable workflow action")

    async def _call(
        self,
        raw_action: Any,
        context: _ExecutionContext,
        operations: Mapping[str, Any],
        capability_id: str,
        step_id: str | None,
    ) -> JsonValue:
        details = {"capability_id": capability_id, "step_id": step_id}
        action = _required_mapping(raw_action, code="ACC_RUNTIME_STEP_INVALID", details=details)
        operation_id = action.get("operation")
        if not isinstance(operation_id, str) or not operation_id:
            raise ExecutionError(
                "ACC_RUNTIME_STEP_INVALID",
                "Call step requires a declared operation id.",
                details=details,
            )
        call_details = {**details, "operation_id": operation_id}
        operation = operations.get(operation_id)
        operation_definition = _required_mapping(
            operation,
            code="ACC_RUNTIME_OPERATION_NOT_FOUND",
            details=call_details,
        )
        raw_arguments = _resolve_value(action.get("arguments"), context, call_details)
        arguments = _required_mapping(
            raw_arguments,
            code="ACC_RUNTIME_OPERATION_INPUT_INVALID",
            details=call_details,
        )
        safe_arguments = _copy_json(
            dict(arguments),
            code="ACC_RUNTIME_OPERATION_INPUT_INVALID",
            details=call_details,
        )
        if not isinstance(safe_arguments, dict):  # pragma: no cover - mapping copied above
            raise AssertionError("operation arguments must remain a JSON object")
        if self._validate_operation_input:
            _validate_schema(
                operation_definition.get("input_schema"),
                safe_arguments,
                code="ACC_RUNTIME_OPERATION_INPUT_INVALID",
                capability_id=capability_id,
                operation_id=operation_id,
                step_id=step_id,
                schema_role="operation_input",
            )
        try:
            raw_result = await self._operation_caller.call(
                copy.deepcopy(dict(operation_definition)),
                copy.deepcopy(safe_arguments),
            )
        except AccRuntimeError:
            raise
        except Exception:
            raise ExecutionError(
                "ACC_RUNTIME_OPERATION_FAILED",
                "Operation caller failed.",
                details=call_details,
            ) from None
        result = _copy_json(
            raw_result,
            code="ACC_RUNTIME_OPERATION_OUTPUT_INVALID",
            details=call_details,
        )
        _validate_schema(
            operation_definition.get("output_schema"),
            result,
            code="ACC_RUNTIME_OPERATION_OUTPUT_INVALID",
            capability_id=capability_id,
            operation_id=operation_id,
            step_id=step_id,
            schema_role="operation_output",
        )
        return result


def _capability_definition(compiled_ir: Mapping[str, Any], capability_id: str) -> Mapping[str, Any]:
    capabilities = _required_mapping(
        compiled_ir.get("capabilities"),
        code="ACC_RUNTIME_IR_INVALID",
        details={"capability_id": capability_id},
    )
    compiled_capability = _required_mapping(
        capabilities.get(capability_id),
        code="ACC_RUNTIME_CAPABILITY_NOT_FOUND",
        details={"capability_id": capability_id},
    )
    return _required_mapping(
        compiled_capability.get("definition"),
        code="ACC_RUNTIME_IR_INVALID",
        details={"capability_id": capability_id},
    )


def _validate_schema(
    raw_schema: Any,
    instance: JsonValue,
    *,
    code: str,
    capability_id: str,
    schema_role: str,
    operation_id: str | None = None,
    step_id: str | None = None,
) -> None:
    details: dict[str, str | int | None] = {
        "capability_id": capability_id,
        "operation_id": operation_id,
        "step_id": step_id,
        "schema_role": schema_role,
    }
    schema = _required_mapping(raw_schema, code="ACC_RUNTIME_IR_INVALID", details=details)
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
    except SchemaError:
        raise ExecutionError(
            "ACC_RUNTIME_IR_INVALID",
            "Compiled IR contains an invalid JSON Schema.",
            details=details,
        ) from None
    if next(validator.iter_errors(instance), None) is not None:
        raise ExecutionError(
            code,
            "JSON value does not match its declared schema.",
            details=details,
        )


def _resolve_value(
    value: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float)):
        return _copy_json(value, code="ACC_RUNTIME_STEP_INVALID", details=details)
    if isinstance(value, str):
        match = _REFERENCE_PATTERN.fullmatch(value)
        if match is not None:
            return _resolve_match(match, context, details)
        if value.startswith("$") or "$." in value or "${" in value:
            raise ExecutionError(
                "ACC_RUNTIME_REFERENCE_INVALID",
                "Workflow contains an invalid dynamic reference.",
                details=details,
            )
        return value
    if isinstance(value, list):
        return [_resolve_value(item, context, details) for item in value]
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {str(key): _resolve_value(item, context, details) for key, item in value.items()}
    raise ExecutionError(
        "ACC_RUNTIME_STEP_INVALID",
        "Workflow value is not JSON-compatible.",
        details=details,
    )


def _resolve_required_reference(
    value: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    if not isinstance(value, str) or _REFERENCE_PATTERN.fullmatch(value) is None:
        raise ExecutionError(
            "ACC_RUNTIME_REFERENCE_INVALID",
            "Workflow condition must be one static reference.",
            details=details,
        )
    return _resolve_value(value, context, details)


def _evaluate_condition(
    raw_condition: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
    *,
    depth: int = 1,
    budget: list[int] | None = None,
) -> bool:
    if isinstance(raw_condition, str):
        return bool(_resolve_required_reference(raw_condition, context, details))
    if depth > _MAX_CONDITION_DEPTH:
        raise ExecutionError(
            "ACC_RUNTIME_BOUND_EXCEEDED",
            "Workflow condition depth exceeds the runtime bound.",
            details=details,
        )
    remaining = [_MAX_CONDITION_NODES] if budget is None else budget
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ExecutionError(
            "ACC_RUNTIME_BOUND_EXCEEDED",
            "Workflow condition size exceeds the runtime bound.",
            details=details,
        )
    condition = _required_mapping(raw_condition, code="ACC_RUNTIME_STEP_INVALID", details=details)
    operator = condition.get("operator")
    if operator in {"eq", "in"}:
        expected = (
            {"operator", "left", "right"}
            if operator == "eq"
            else {
                "operator",
                "item",
                "values",
            }
        )
        if set(condition) != expected:
            raise ExecutionError(
                "ACC_RUNTIME_STEP_INVALID",
                "Workflow condition has an invalid shape.",
                details=details,
            )
        left_key, right_key = ("left", "right") if operator == "eq" else ("item", "values")
        left = _resolve_condition_operand(condition[left_key], context, details)
        right = _resolve_condition_operand(condition[right_key], context, details)
        if operator == "eq":
            return _json_equal(left, right)
        if not isinstance(right, list):
            raise ExecutionError(
                "ACC_RUNTIME_STEP_INVALID",
                "Workflow in condition requires a JSON array operand.",
                details=details,
            )
        return any(_json_equal(left, item) for item in right)
    if operator in {"all", "any"}:
        if set(condition) != {"operator", "conditions"}:
            raise ExecutionError(
                "ACC_RUNTIME_STEP_INVALID",
                "Workflow condition has an invalid shape.",
                details=details,
            )
        children = _required_list(
            condition.get("conditions"), code="ACC_RUNTIME_STEP_INVALID", details=details
        )
        if not 1 <= len(children) <= 16:
            raise ExecutionError(
                "ACC_RUNTIME_BOUND_EXCEEDED",
                "Workflow condition fan-out exceeds the runtime bound.",
                details=details,
            )
        results = [
            _evaluate_condition(child, context, details, depth=depth + 1, budget=remaining)
            for child in children
        ]
        return all(results) if operator == "all" else any(results)
    if operator == "not":
        if set(condition) != {"operator", "condition"}:
            raise ExecutionError(
                "ACC_RUNTIME_STEP_INVALID",
                "Workflow condition has an invalid shape.",
                details=details,
            )
        return not _evaluate_condition(
            condition.get("condition"),
            context,
            details,
            depth=depth + 1,
            budget=remaining,
        )
    raise ExecutionError(
        "ACC_RUNTIME_STEP_INVALID",
        "Workflow condition operator is not supported.",
        details=details,
    )


def _resolve_condition_operand(
    raw_operand: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    operand = _required_mapping(raw_operand, code="ACC_RUNTIME_STEP_INVALID", details=details)
    if set(operand) != {"kind", "value"}:
        raise ExecutionError(
            "ACC_RUNTIME_STEP_INVALID",
            "Workflow condition operand has an invalid shape.",
            details=details,
        )
    kind = operand.get("kind")
    if kind == "reference":
        return _resolve_required_reference(operand.get("value"), context, details)
    if kind == "literal":
        return _copy_json(operand.get("value"), code="ACC_RUNTIME_STEP_INVALID", details=details)
    raise ExecutionError(
        "ACC_RUNTIME_STEP_INVALID",
        "Workflow condition operand kind is not supported.",
        details=details,
    )


def _json_equal(left: JsonValue, right: JsonValue) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        return isinstance(left, (int, float)) and isinstance(right, (int, float)) and left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and left.keys() == right.keys()
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    return left == right


def _resolve_match(
    match: re.Match[str],
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    root = match.group("root")
    if root == "input":
        current: Any = context.input_data
        path = match.group("root_path")
    elif root == "item":
        if context.item is _MISSING:
            raise ExecutionError(
                "ACC_RUNTIME_REFERENCE_UNAVAILABLE",
                "Workflow reference is unavailable in this execution context.",
                details=details,
            )
        current = context.item
        path = match.group("root_path")
    else:
        step_id = match.group("step")
        if step_id not in context.steps:
            raise ExecutionError(
                "ACC_RUNTIME_REFERENCE_UNAVAILABLE",
                "Workflow reference is unavailable in this execution context.",
                details=details,
            )
        current = context.steps[step_id]
        path = match.group("step_path")

    for segment in path.split(".") if path else ():
        if not segment:
            continue
        if not isinstance(current, Mapping) or segment not in current:
            raise ExecutionError(
                "ACC_RUNTIME_REFERENCE_UNAVAILABLE",
                "Workflow reference is unavailable in this execution context.",
                details=details,
            )
        current = current[segment]
    return _copy_json(current, code="ACC_RUNTIME_REFERENCE_INVALID", details=details)


def _pick(
    raw_action: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    action = _required_mapping(raw_action, code="ACC_RUNTIME_STEP_INVALID", details=details)
    value = _resolve_value(action.get("value"), context, details)
    source = _required_mapping(value, code="ACC_RUNTIME_VALUE_TYPE_INVALID", details=details)
    fields = _required_string_list(action.get("fields"), details)
    return {field: copy.deepcopy(source[field]) for field in fields if field in source}


def _redact(
    raw_action: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    action = _required_mapping(raw_action, code="ACC_RUNTIME_STEP_INVALID", details=details)
    value = _resolve_value(action.get("value"), context, details)
    source = _required_mapping(value, code="ACC_RUNTIME_VALUE_TYPE_INVALID", details=details)
    fields = set(_required_string_list(action.get("fields"), details))
    return {str(key): copy.deepcopy(item) for key, item in source.items() if key not in fields}


def _map(
    raw_action: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    action = _required_mapping(raw_action, code="ACC_RUNTIME_STEP_INVALID", details=details)
    items = _resolve_value(action.get("items"), context, details)
    sequence = _bounded_items(items, action.get("max_items"), details)
    expression = action.get("expression")
    return [
        _resolve_required_reference(expression, context.isolated(item=item), details)
        for item in sequence
    ]


def _filter(
    raw_action: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> JsonValue:
    action = _required_mapping(raw_action, code="ACC_RUNTIME_STEP_INVALID", details=details)
    items = _resolve_value(action.get("items"), context, details)
    sequence = _bounded_items(items, action.get("max_items"), details)
    condition = action.get("condition")
    return [
        copy.deepcopy(item)
        for item in sequence
        if bool(_resolve_required_reference(condition, context.isolated(item=item), details))
    ]


def _assert(
    raw_action: Any,
    context: _ExecutionContext,
    details: Mapping[str, str | int | None],
) -> None:
    action = _required_mapping(raw_action, code="ACC_RUNTIME_STEP_INVALID", details=details)
    condition = _resolve_required_reference(action.get("condition"), context, details)
    if not bool(condition):
        raise ExecutionError(
            "ACC_RUNTIME_ASSERTION_FAILED",
            "Workflow assertion failed.",
            details=details,
        )


def _bounded_items(
    value: JsonValue,
    raw_limit: Any,
    details: Mapping[str, str | int | None],
) -> list[JsonValue]:
    if not isinstance(raw_limit, int) or isinstance(raw_limit, bool):
        raise ExecutionError(
            "ACC_RUNTIME_STEP_INVALID",
            "Collection step requires an integer max_items bound.",
            details=details,
        )
    if not 1 <= raw_limit <= _MAX_COLLECTION_ITEMS:
        raise ExecutionError(
            "ACC_RUNTIME_BOUND_EXCEEDED",
            "Collection step declares an invalid execution bound.",
            details={**details, "limit": _MAX_COLLECTION_ITEMS},
        )
    if not isinstance(value, list):
        raise ExecutionError(
            "ACC_RUNTIME_VALUE_TYPE_INVALID",
            "Collection step requires an array value.",
            details=details,
        )
    if len(value) > raw_limit:
        raise ExecutionError(
            "ACC_RUNTIME_BOUND_EXCEEDED",
            "Collection exceeds its declared execution bound.",
            details={**details, "limit": raw_limit},
        )
    return value


def _required_mapping(
    value: Any,
    *,
    code: str,
    details: Mapping[str, str | int | None],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ExecutionError(code, "Required object is missing or invalid.", details=details)
    return value


def _required_list(
    value: Any,
    *,
    code: str,
    details: Mapping[str, str | int | None],
) -> list[Any]:
    if not isinstance(value, list):
        raise ExecutionError(code, "Required array is missing or invalid.", details=details)
    return value


def _required_string_list(value: Any, details: Mapping[str, str | int | None]) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ExecutionError(
            "ACC_RUNTIME_STEP_INVALID",
            "Field selection requires one or more field names.",
            details=details,
        )
    return value


def _copy_json(
    value: Any,
    *,
    code: str,
    details: Mapping[str, str | int | None] | None = None,
) -> JsonValue:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, list):
        return [_copy_json(item, code=code, details=details) for item in value]
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {
            str(key): _copy_json(item, code=code, details=details) for key, item in value.items()
        }
    raise ExecutionError(code, "Value is not JSON-compatible.", details=details)


__all__ = ["AsyncOperationCaller", "ExecutionError", "JsonValue", "WorkflowExecutor"]
