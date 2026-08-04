from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from acc_core.evals import ContractEvalRunner, RuntimeEvalRunner


def _operation(operation_id: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "id": operation_id,
        "input_schema": {
            "type": "object",
            "required": ["customer_id"],
            "properties": {"customer_id": {"type": "string"}},
            "additionalProperties": False,
        },
        "output_schema": {"type": "object"},
    }


def _capability(eval_ids: list[str]) -> dict[str, Any]:
    return {
        "definition": {
            "schema_version": "1",
            "id": "get_customer",
            "title": "Get customer",
            "description": "Get one customer.",
            "input_schema": {
                "type": "object",
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
                "additionalProperties": False,
            },
            "output_schema": {"type": "object"},
            "workflow": [{"emit": {"value": {}}}],
            "policy": "crm-read",
            "evals": eval_ids,
        },
        "operation_dependencies": ["crm.get_customer"],
    }


def _success_eval() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "id": "normal",
        "capability": "get_customer",
        "input": {"customer_id": "c-1"},
        "fixtures": {},
        "expected_calls": [{"operation": "crm.get_customer", "arguments": {"customer_id": "c-1"}}],
        "expected_output_schema": {"type": "object", "required": ["id"]},
        "forbidden_fields": ["internal_note"],
    }


def _error_eval() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "id": "forbidden",
        "capability": "get_customer",
        "input": {"customer_id": "other-tenant"},
        "fixtures": {},
        "expected_calls": [],
        "expected_error": {"code": "FORBIDDEN", "status": 403},
        "forbidden_fields": [],
    }


def _compiled_ir() -> dict[str, Any]:
    return {
        "ir_version": "1",
        "operations": {"crm.get_customer": _operation("crm.get_customer")},
        "capabilities": {"get_customer": _capability(["normal", "forbidden"])},
        "policies": {
            "crm-read": {
                "schema_version": "1",
                "id": "crm-read",
                "required_scopes": ["customer.read"],
                "tenant_mode": "required",
                "tenant_field": "tenant_id",
                "readable_fields": ["id"],
                "denied_fields": ["internal_note"],
                "redaction_rules": [],
            }
        },
        "evals": {"normal": _success_eval(), "forbidden": _error_eval()},
    }


def test_contract_eval_accepts_bound_positive_and_permission_negative_cases() -> None:
    report = ContractEvalRunner().run(_compiled_ir())

    assert report.ok is True
    assert [case.case_id for case in report.cases] == ["forbidden", "normal"]
    assert report.to_dict() == {
        "kind": "contract",
        "ok": True,
        "summary": {"total": 2, "passed": 2, "failed": 0},
        "diagnostics": [],
        "cases": [
            {
                "id": "forbidden",
                "capability": "get_customer",
                "ok": True,
                "diagnostics": [],
            },
            {
                "id": "normal",
                "capability": "get_customer",
                "ok": True,
                "diagnostics": [],
            },
        ],
    }


def test_contract_eval_reports_case_binding_dependency_and_schema_failures() -> None:
    ir = _compiled_ir()
    ir["operations"]["crm.unused"] = _operation("crm.unused")
    normal = ir["evals"]["normal"]
    normal["input"] = {"customer_id": 17}
    normal["expected_calls"] = [{"operation": "crm.unused", "arguments": {"customer_id": 17}}]
    ir["capabilities"]["get_customer"]["definition"]["evals"] = ["forbidden"]

    report = ContractEvalRunner().run(ir)

    normal_result = next(case for case in report.cases if case.case_id == "normal")
    assert normal_result.ok is False
    assert [item.code for item in normal_result.diagnostics] == [
        "ACC_EVAL_EXPECTED_CALL_SCHEMA_MISMATCH",
        "ACC_EVAL_INPUT_SCHEMA_MISMATCH",
        "ACC_EVAL_NOT_DECLARED",
        "ACC_EVAL_OPERATION_NOT_DEPENDENCY",
    ]
    serialized = repr(report.to_dict())
    assert "17" not in serialized
    assert "c-1" not in serialized


def test_contract_eval_requires_positive_and_permission_negative_coverage() -> None:
    no_negative = _compiled_ir()
    no_negative["evals"].pop("forbidden")
    no_negative["capabilities"]["get_customer"]["definition"]["evals"] = ["normal"]

    negative_report = ContractEvalRunner().run(no_negative)

    assert [item.code for item in negative_report.diagnostics] == [
        "ACC_EVAL_PERMISSION_NEGATIVE_REQUIRED"
    ]

    no_positive = _compiled_ir()
    no_positive["evals"].pop("normal")
    no_positive["capabilities"]["get_customer"]["definition"]["evals"] = ["forbidden"]

    positive_report = ContractEvalRunner().run(no_positive)

    assert [item.code for item in positive_report.diagnostics] == ["ACC_EVAL_POSITIVE_REQUIRED"]


def test_contract_eval_does_not_count_non_permission_error_as_permission_negative() -> None:
    ir = _compiled_ir()
    ir["evals"]["forbidden"]["expected_error"] = {
        "code": "NOT_FOUND",
        "status": 404,
    }

    report = ContractEvalRunner().run(ir)

    assert [item.code for item in report.diagnostics] == ["ACC_EVAL_PERMISSION_NEGATIVE_REQUIRED"]


def test_contract_eval_checks_case_key_identity_and_declared_case_existence() -> None:
    ir = _compiled_ir()
    ir["evals"]["normal"]["id"] = "renamed"
    ir["capabilities"]["get_customer"]["definition"]["evals"].append("missing")

    report = ContractEvalRunner().run(ir)

    normal = next(case for case in report.cases if case.case_id == "normal")
    assert [item.code for item in normal.diagnostics] == ["ACC_EVAL_ID_MISMATCH"]
    assert "ACC_EVAL_DECLARED_CASE_NOT_FOUND" in [item.code for item in report.diagnostics]


class _Recorder:
    def __init__(self) -> None:
        self.recorded: list[dict[str, Any]] = []
        self.reset_count = 0

    def reset(self) -> None:
        self.recorded.clear()
        self.reset_count += 1

    def snapshot(self) -> Sequence[Mapping[str, object]]:
        return list(self.recorded)


class _FixtureLoader:
    def __init__(self) -> None:
        self.loaded: list[dict[str, Any]] = []

    async def load(self, fixtures: Mapping[str, object]) -> None:
        self.loaded.append(dict(fixtures))


class _SuccessCaller:
    def __init__(self, recorder: _Recorder, output: Any) -> None:
        self.recorder = recorder
        self.output = output

    async def call(self, capability_id: str, input_data: Mapping[str, object]) -> Any:
        assert capability_id == "get_customer"
        self.recorder.recorded.append(
            {
                "operation": "crm.get_customer",
                "arguments": {"customer_id": input_data["customer_id"]},
            }
        )
        return self.output


@pytest.mark.asyncio
async def test_runtime_eval_loads_fixtures_and_checks_calls_schema_and_forbidden_fields() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"normal": ir["evals"]["normal"]}
    ir["evals"]["normal"]["fixtures"] = {"customers": [{"id": "c-1"}]}
    recorder = _Recorder()
    fixture_loader = _FixtureLoader()
    runner = RuntimeEvalRunner(
        _SuccessCaller(recorder, {"id": "c-1"}),
        fixture_loader=fixture_loader,
        call_recorder=recorder,
    )

    report = await runner.run(ir)

    assert report.ok is True
    assert fixture_loader.loaded == [{"customers": [{"id": "c-1"}]}]
    assert recorder.reset_count == 1
    assert report.to_dict() == {
        "kind": "runtime",
        "ok": True,
        "summary": {"total": 1, "passed": 1, "failed": 0},
        "diagnostics": [],
        "cases": [
            {
                "id": "normal",
                "capability": "get_customer",
                "ok": True,
                "diagnostics": [],
            }
        ],
    }


@pytest.mark.asyncio
async def test_runtime_eval_reports_output_contract_failures_without_output_values() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"normal": ir["evals"]["normal"]}
    recorder = _Recorder()
    secret = "never-expose-this-output"
    runner = RuntimeEvalRunner(
        _SuccessCaller(recorder, {"internal_note": secret}),
        call_recorder=recorder,
    )

    report = await runner.run(ir)

    assert report.ok is False
    assert [item.code for item in report.cases[0].diagnostics] == [
        "ACC_EVAL_FORBIDDEN_FIELD_PRESENT",
        "ACC_EVAL_OUTPUT_SCHEMA_MISMATCH",
    ]
    assert secret not in repr(report.to_dict())


class _CapabilityFailure(Exception):
    def __init__(self, code: str, status: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class _FailureCaller:
    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    async def call(self, capability_id: str, input_data: Mapping[str, object]) -> Any:
        raise self.failure


@pytest.mark.asyncio
async def test_runtime_eval_matches_expected_structured_error() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"forbidden": ir["evals"]["forbidden"]}
    failure = _CapabilityFailure("FORBIDDEN", 403, "tenant access denied")

    report = await RuntimeEvalRunner(_FailureCaller(failure)).run(ir)

    assert report.ok is True
    assert report.cases[0].case_id == "forbidden"


@pytest.mark.asyncio
async def test_runtime_eval_reports_all_expected_error_mismatches_without_exception_text() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"forbidden": ir["evals"]["forbidden"]}
    ir["evals"]["forbidden"]["expected_error"]["message_contains"] = "access denied"
    secret = "credential=never-expose-runtime-error"
    failure = _CapabilityFailure("UPSTREAM_ERROR", 500, secret)

    report = await RuntimeEvalRunner(_FailureCaller(failure)).run(ir)

    assert [item.code for item in report.cases[0].diagnostics] == [
        "ACC_EVAL_ERROR_CODE_MISMATCH",
        "ACC_EVAL_ERROR_MESSAGE_MISMATCH",
        "ACC_EVAL_ERROR_STATUS_MISMATCH",
    ]
    assert secret not in repr(report.to_dict())


class _WrongCallCaller(_SuccessCaller):
    async def call(self, capability_id: str, input_data: Mapping[str, object]) -> Any:
        self.recorder.recorded.append(
            {"operation": "crm.wrong", "arguments": {"customer_id": "wrong"}}
        )
        return self.output


@pytest.mark.asyncio
async def test_runtime_eval_compares_expected_calls_in_declared_order() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"normal": ir["evals"]["normal"]}
    recorder = _Recorder()

    report = await RuntimeEvalRunner(
        _WrongCallCaller(recorder, {"id": "c-1"}),
        call_recorder=recorder,
    ).run(ir)

    assert [item.code for item in report.cases[0].diagnostics] == ["ACC_EVAL_CALLS_MISMATCH"]


@pytest.mark.asyncio
async def test_runtime_eval_converts_unresolvable_schema_reference_to_stable_failure() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"normal": ir["evals"]["normal"]}
    ir["evals"]["normal"]["expected_output_schema"] = {"$ref": "#/$defs/missing"}
    recorder = _Recorder()

    report = await RuntimeEvalRunner(
        _SuccessCaller(recorder, {"id": "c-1"}),
        call_recorder=recorder,
    ).run(ir)

    assert [item.code for item in report.cases[0].diagnostics] == [
        "ACC_EVAL_OUTPUT_SCHEMA_MISMATCH"
    ]


@pytest.mark.asyncio
async def test_runtime_eval_requires_hooks_when_case_declares_fixtures_or_calls() -> None:
    ir = _compiled_ir()
    ir["evals"] = {"normal": ir["evals"]["normal"]}
    ir["evals"]["normal"]["fixtures"] = {"secret": "fixture-secret"}

    report = await RuntimeEvalRunner(_FailureCaller(AssertionError("must not run"))).run(ir)

    assert [item.code for item in report.cases[0].diagnostics] == [
        "ACC_EVAL_CALL_RECORDER_REQUIRED",
        "ACC_EVAL_FIXTURE_LOADER_REQUIRED",
    ]
    assert "fixture-secret" not in repr(report.to_dict())
