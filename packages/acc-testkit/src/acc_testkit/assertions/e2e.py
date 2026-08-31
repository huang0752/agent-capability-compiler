"""Domain-neutral assertions for ACC runtime and MCP end-to-end tests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import JsonValue

from acc_runtime.providers import JsonApplicationSuccessPolicy

_UNSET = object()


class E2EAssertionError(AssertionError):
    """A deterministic assertion failure that avoids dumping protected values."""


class OperationCallLike(Protocol):
    operation: str | None
    arguments: Mapping[str, JsonValue]


def assert_expected_calls(
    expected: Sequence[object],
    actual: Sequence[object],
) -> None:
    """Assert exact logical operation order and arguments without printing values."""

    if len(expected) != len(actual):
        raise E2EAssertionError(
            f"operation call count mismatch: expected {len(expected)}, actual {len(actual)}"
        )
    for index, (expected_call, actual_call) in enumerate(zip(expected, actual, strict=True)):
        expected_operation = _field(expected_call, "operation")
        actual_operation = _field(actual_call, "operation")
        if expected_operation != actual_operation:
            raise E2EAssertionError(f"call {index} operation mismatch")
        expected_arguments = _mapping_field(expected_call, "arguments")
        actual_arguments = _mapping_field(actual_call, "arguments")
        if dict(expected_arguments) != dict(actual_arguments):
            raise E2EAssertionError(f"call {index} arguments mismatch")


def assert_output_schema(
    output: JsonValue,
    schema: Mapping[str, object],
    *,
    application_success_policy: JsonApplicationSuccessPolicy | None = None,
) -> None:
    """Validate an output and an optional JSON-envelope success contract."""

    try:
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(output),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except SchemaError as exc:
        raise E2EAssertionError("expected output schema is invalid") from exc
    if errors:
        first = errors[0]
        path = _json_path(tuple(str(part) for part in first.absolute_path))
        raise E2EAssertionError(f"output schema mismatch at {path}")
    if application_success_policy is not None and not application_success_policy.matches(output):
        raise E2EAssertionError("application success contract mismatch")


def assert_stable_error(actual: object, expected: object) -> None:
    """Assert public runtime/MCP error code and optional status/message fragment."""

    payload, message = _error_payload(actual)
    expected_code = _field(expected, "code")
    expected_status = _field(expected, "status", None)
    expected_message = _field(expected, "message_contains", None)
    if payload.get("code") != expected_code:
        raise E2EAssertionError("stable error code mismatch")
    if expected_status is not None and payload.get("status") != expected_status:
        raise E2EAssertionError("stable error status mismatch")
    if expected_message is not None and (
        not isinstance(expected_message, str) or expected_message not in message
    ):
        raise E2EAssertionError("stable error message mismatch")


def assert_forbidden_fields_absent(output: JsonValue, forbidden_fields: Sequence[str]) -> None:
    """Reject forbidden keys anywhere, or declared paths through objects and arrays."""

    for field in forbidden_fields:
        if _is_bare_field(field):
            location = _find_key(output, field, ())
        else:
            location = _find_path(output, _parse_path(field), ())
        if location is not None:
            raise E2EAssertionError(f"forbidden field is present at {_json_path(location)}")


def assert_e2e(
    scenario: object,
    *,
    calls: Sequence[object],
    output: object = _UNSET,
    error: object = _UNSET,
    application_success_policy: JsonApplicationSuccessPolicy | None = None,
) -> None:
    """Apply an Eval-like expected-call and success/error contract in one step."""

    expected_calls = _field(scenario, "expected_calls")
    if not isinstance(expected_calls, Sequence) or isinstance(expected_calls, (str, bytes)):
        raise E2EAssertionError("scenario expected_calls must be a sequence")
    assert_expected_calls(expected_calls, calls)

    expected_error = _field(scenario, "expected_error", None)
    if expected_error is not None:
        if error is _UNSET:
            raise E2EAssertionError("scenario expected an error but none was supplied")
        assert_stable_error(error, expected_error)
        return

    if output is _UNSET:
        raise E2EAssertionError("scenario expected output but none was supplied")
    schema = _field(scenario, "expected_output_schema", None)
    if not isinstance(schema, Mapping):
        raise E2EAssertionError("scenario expected_output_schema must be an object")
    assert_output_schema(
        cast(JsonValue, output),
        cast(Mapping[str, object], schema),
        application_success_policy=application_success_policy,
    )
    forbidden = _field(scenario, "forbidden_fields", ())
    if not isinstance(forbidden, Sequence) or isinstance(forbidden, (str, bytes)):
        raise E2EAssertionError("scenario forbidden_fields must be a sequence")
    if not all(isinstance(item, str) for item in forbidden):
        raise E2EAssertionError("scenario forbidden_fields must contain strings")
    assert_forbidden_fields_absent(cast(JsonValue, output), cast(Sequence[str], forbidden))


def _field(value: object, name: str, default: object = _UNSET) -> object:
    if isinstance(value, Mapping):
        result = value.get(name, default)
    else:
        result = getattr(value, name, default)
    if result is _UNSET:
        raise E2EAssertionError(f"assertion input is missing field: {name}")
    return result


def _mapping_field(value: object, name: str) -> Mapping[str, object]:
    result = _field(value, name)
    if not isinstance(result, Mapping) or not all(isinstance(key, str) for key in result):
        raise E2EAssertionError(f"assertion field must be an object: {name}")
    return cast(Mapping[str, object], result)


def _error_payload(value: object) -> tuple[Mapping[str, object], str]:
    message = str(value) if isinstance(value, BaseException) else ""
    to_dict = getattr(value, "to_dict", None)
    candidate = to_dict() if callable(to_dict) else getattr(value, "structuredContent", value)
    if not isinstance(candidate, Mapping):
        raise E2EAssertionError("actual error has no stable public structure")
    nested = candidate.get("error", candidate)
    if not isinstance(nested, Mapping):
        raise E2EAssertionError("actual error payload must be an object")
    mapped = cast(Mapping[str, object], nested)
    candidate_message = mapped.get("message")
    if not message and isinstance(candidate_message, str):
        message = candidate_message
    return mapped, message


def _is_bare_field(field: str) -> bool:
    return not field.startswith(("/", "$")) and "." not in field


def _parse_path(field: str) -> tuple[str, ...]:
    if field.startswith("/"):
        return tuple(part.replace("~1", "/").replace("~0", "~") for part in field[1:].split("/"))
    value = field[2:] if field.startswith("$.") else field
    return tuple(part for part in value.split(".") if part)


def _find_key(
    value: JsonValue,
    key: str,
    location: tuple[str | int, ...],
) -> tuple[str | int, ...] | None:
    if isinstance(value, dict):
        for candidate in sorted(value):
            child_location = (*location, candidate)
            if candidate == key:
                return child_location
            found = _find_key(value[candidate], key, child_location)
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _find_key(item, key, (*location, index))
            if found is not None:
                return found
    return None


def _find_path(
    value: JsonValue,
    path: tuple[str, ...],
    location: tuple[str | int, ...],
) -> tuple[str | int, ...] | None:
    if not path:
        return location
    if isinstance(value, list):
        for index, item in enumerate(value):
            found = _find_path(item, path, (*location, index))
            if found is not None:
                return found
        return None
    if not isinstance(value, dict) or path[0] not in value:
        return None
    return _find_path(value[path[0]], path[1:], (*location, path[0]))


def _json_path(parts: tuple[str | int, ...]) -> str:
    result = "$"
    for part in parts:
        if isinstance(part, int):
            result += f"[{part}]"
        else:
            result += f".{part}"
    return result


__all__ = [
    "E2EAssertionError",
    "OperationCallLike",
    "assert_e2e",
    "assert_expected_calls",
    "assert_forbidden_fields_absent",
    "assert_output_schema",
    "assert_stable_error",
]
