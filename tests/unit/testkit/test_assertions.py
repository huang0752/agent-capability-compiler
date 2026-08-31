from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

import pytest
from pydantic import JsonValue

from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.providers import JsonApplicationSuccessPolicy
from acc_testkit.assertions import (
    E2EAssertionError,
    assert_e2e,
    assert_expected_calls,
    assert_forbidden_fields_absent,
    assert_output_schema,
    assert_stable_error,
)
from acc_testkit.fake_system import CallRecord


class Forbidden(AccRuntimeError):
    code: ClassVar[str] = "ACC_RUNTIME_POLICY_SCOPE_DENIED"
    status: ClassVar[int] = 403


def _calls() -> list[CallRecord]:
    return [
        CallRecord(
            sequence=1,
            operation="example.get_entity",
            method="GET",
            path="/entities/e-1",
            arguments={"entity_id": "e-1"},
        )
    ]


def test_expected_calls_accepts_eval_mappings_and_operation_call_records() -> None:
    assert_expected_calls(
        [{"operation": "example.get_entity", "arguments": {"entity_id": "e-1"}}],
        _calls(),
    )


def test_expected_calls_reports_ordered_mismatch_without_dumping_arguments() -> None:
    with pytest.raises(E2EAssertionError, match="call 0 operation mismatch") as caught:
        assert_expected_calls(
            [{"operation": "example.other", "arguments": {"secret": "expected-secret"}}],
            _calls(),
        )

    assert "expected-secret" not in str(caught.value)


def test_output_schema_uses_draft_2020_12() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"type": "string"}},
        "unevaluatedProperties": False,
    }

    assert_output_schema({"name": "Example"}, schema)
    with pytest.raises(E2EAssertionError, match="output schema mismatch"):
        assert_output_schema({"name": "Example", "internal": True}, schema)


def test_assert_output_schema_rejects_configured_application_error() -> None:
    schema = {
        "type": "object",
        "required": ["code", "message", "data"],
        "properties": {
            "code": {"type": "integer"},
            "message": {"type": "string"},
            "data": {},
        },
    }

    with pytest.raises(E2EAssertionError, match="application success contract mismatch"):
        assert_output_schema(
            {"code": 403, "message": "forbidden", "data": None},
            schema,
            application_success_policy=JsonApplicationSuccessPolicy(
                pointer="/code", allowed_values=(200,)
            ),
        )


def test_assert_output_schema_leaves_non_envelope_apis_unchanged_by_default() -> None:
    assert_output_schema(
        {"code": 500},
        {
            "type": "object",
            "required": ["code"],
            "properties": {"code": {"type": "integer"}},
        },
    )


def test_stable_error_accepts_runtime_errors_and_mcp_structured_content() -> None:
    error = Forbidden("private message", details={"missing_scopes": ["entity.read"]})
    assert_stable_error(
        error,
        {
            "code": "ACC_RUNTIME_POLICY_SCOPE_DENIED",
            "status": 403,
            "message_contains": "private message",
        },
    )
    assert_stable_error(
        {
            "error": {
                "code": "ACC_RUNTIME_HTTP_NOT_FOUND",
                "status": 404,
                "details": {"operation": "example.get_entity"},
            }
        },
        {"code": "ACC_RUNTIME_HTTP_NOT_FOUND", "status": 404},
    )


def test_forbidden_fields_are_found_recursively_through_arrays() -> None:
    output: dict[str, JsonValue] = {
        "items": [
            {"name": "safe"},
            {"credentials": {"token": "nested-secret"}},
        ]
    }

    with pytest.raises(E2EAssertionError, match=r"\$\.items\[1\]\.credentials\.token"):
        assert_forbidden_fields_absent(output, ["token"])
    with pytest.raises(E2EAssertionError, match="forbidden field is present"):
        assert_forbidden_fields_absent(output, ["items.credentials.token"])
    assert_forbidden_fields_absent(output, ["items.credentials.password"])


@dataclass(frozen=True)
class Scenario:
    expected_calls: list[dict[str, object]]
    expected_output_schema: dict[str, object] | None
    expected_error: dict[str, object] | None
    forbidden_fields: list[str]


def test_assert_e2e_combines_calls_output_schema_and_forbidden_fields() -> None:
    scenario = Scenario(
        expected_calls=[{"operation": "example.get_entity", "arguments": {"entity_id": "e-1"}}],
        expected_output_schema={
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
        },
        expected_error=None,
        forbidden_fields=["secret"],
    )

    assert_e2e(scenario, calls=_calls(), output={"id": "e-1"})


def test_assert_e2e_checks_expected_stable_error() -> None:
    scenario: dict[str, object] = {
        "expected_calls": [],
        "expected_output_schema": None,
        "expected_error": {"code": "ACC_RUNTIME_HTTP_NOT_FOUND", "status": 404},
        "forbidden_fields": [],
    }

    assert_e2e(
        scenario,
        calls=[],
        error={"code": "ACC_RUNTIME_HTTP_NOT_FOUND", "status": 404, "details": {}},
    )
