"""Runtime evaluation of compiled ACC capability scenarios."""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from jsonschema import Draft202012Validator, SchemaError
from pydantic import JsonValue, ValidationError

from acc_core.evals.results import CaseResult, EvalDiagnostic, EvalReport
from acc_core.models import Eval


@runtime_checkable
class AsyncCapabilityCaller(Protocol):
    """Injected boundary for running one capability without coupling to Runtime."""

    async def call(
        self,
        capability_id: str,
        input_data: Mapping[str, JsonValue],
    ) -> JsonValue:
        """Run one capability with JSON input."""


@runtime_checkable
class AsyncFixtureLoader(Protocol):
    """Optional hook for installing a case's fake-system state."""

    async def load(self, fixtures: Mapping[str, JsonValue]) -> None:
        """Install fixtures before the case is invoked."""


@runtime_checkable
class CallRecorder(Protocol):
    """Optional hook exposing operation calls made by a capability."""

    def reset(self) -> None:
        """Clear calls before a case starts."""

    def snapshot(self) -> Sequence[Mapping[str, object]]:
        """Return calls in observed order without clearing them."""


class RuntimeEvalRunner:
    """Run eval cases through an injected async capability boundary."""

    def __init__(
        self,
        capability_caller: AsyncCapabilityCaller,
        *,
        fixture_loader: AsyncFixtureLoader | None = None,
        call_recorder: CallRecorder | None = None,
    ) -> None:
        self._capability_caller = capability_caller
        self._fixture_loader = fixture_loader
        self._call_recorder = call_recorder

    async def run(
        self,
        compiled_ir: Mapping[str, Any],
        eval_ids: Iterable[str] | None = None,
    ) -> EvalReport:
        if compiled_ir.get("ir_version") != "2":
            return EvalReport(
                kind="runtime",
                cases=(),
                diagnostics=(
                    EvalDiagnostic(
                        code="ACC_EVAL_IR_INVALID",
                        message="Eval accepts only current compiled IR version 2.",
                    ),
                ),
            )
        raw_evals = _mapping(compiled_ir.get("evals"))
        if raw_evals is None:
            return EvalReport(
                kind="runtime",
                cases=(),
                diagnostics=(
                    EvalDiagnostic(
                        code="ACC_EVAL_IR_INVALID",
                        message="Compiled IR does not contain eval cases.",
                    ),
                ),
            )

        selected_ids = sorted(set(eval_ids) if eval_ids is not None else raw_evals)
        cases: list[CaseResult] = []
        for case_id in selected_ids:
            raw_case = raw_evals.get(case_id)
            if raw_case is None:
                cases.append(
                    CaseResult(
                        case_id=case_id,
                        capability_id="",
                        diagnostics=(
                            EvalDiagnostic(
                                code="ACC_EVAL_CASE_NOT_FOUND",
                                message="Requested eval case is unavailable.",
                            ),
                        ),
                    )
                )
                continue
            cases.append(await self._run_case(case_id, raw_case))
        return EvalReport(kind="runtime", cases=tuple(cases))

    async def _run_case(self, case_id: str, raw_case: Any) -> CaseResult:
        try:
            scenario = Eval.model_validate(raw_case)
        except ValidationError:
            return CaseResult(
                case_id=case_id,
                capability_id=_string_value(raw_case, "capability"),
                diagnostics=(
                    EvalDiagnostic(
                        code="ACC_EVAL_CASE_INVALID",
                        message="Eval case does not match the declared Eval contract.",
                    ),
                ),
            )

        diagnostics: list[EvalDiagnostic] = []
        if scenario.fixtures and self._fixture_loader is None:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_FIXTURE_LOADER_REQUIRED",
                    message="Eval case declares fixtures but no fixture loader was provided.",
                )
            )
        if scenario.expected_calls and self._call_recorder is None:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_CALL_RECORDER_REQUIRED",
                    message="Eval case declares expected calls but no call recorder was provided.",
                )
            )
        if diagnostics:
            return CaseResult(
                case_id=case_id,
                capability_id=scenario.capability,
                diagnostics=_sorted_diagnostics(diagnostics),
            )

        if self._call_recorder is not None:
            try:
                self._call_recorder.reset()
            except Exception:
                return _failed_hook_case(
                    case_id,
                    scenario.capability,
                    "ACC_EVAL_CALL_RECORDER_FAILED",
                    "Call recorder failed while preparing an eval case.",
                )
        if scenario.fixtures and self._fixture_loader is not None:
            try:
                await self._fixture_loader.load(copy.deepcopy(scenario.fixtures))
            except Exception:
                return _failed_hook_case(
                    case_id,
                    scenario.capability,
                    "ACC_EVAL_FIXTURE_LOAD_FAILED",
                    "Fixture loader failed while preparing an eval case.",
                )

        output: JsonValue = None
        failure: Exception | None = None
        try:
            output = await self._capability_caller.call(
                scenario.capability,
                copy.deepcopy(scenario.input),
            )
        except Exception as exc:
            failure = exc

        if self._call_recorder is not None:
            try:
                actual_calls = self._call_recorder.snapshot()
            except Exception:
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_CALL_RECORDER_FAILED",
                        message="Call recorder failed while reading an eval case.",
                    )
                )
            else:
                if not _calls_match(scenario, actual_calls):
                    diagnostics.append(
                        EvalDiagnostic(
                            code="ACC_EVAL_CALLS_MISMATCH",
                            message="Observed operation calls do not match the eval contract.",
                        )
                    )

        if scenario.expected_error is not None:
            diagnostics.extend(_check_expected_error(scenario, failure))
        elif failure is not None:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_UNEXPECTED_ERROR",
                    message="Capability raised an error for a successful eval case.",
                )
            )
        else:
            if not _matches_schema(scenario.expected_output_schema, output):
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_OUTPUT_SCHEMA_MISMATCH",
                        message="Capability output does not match the eval output schema.",
                    )
                )
            if _contains_forbidden_field(output, set(scenario.forbidden_fields)):
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_FORBIDDEN_FIELD_PRESENT",
                        message="Capability output contains a forbidden field.",
                    )
                )

        return CaseResult(
            case_id=case_id,
            capability_id=scenario.capability,
            diagnostics=_sorted_diagnostics(diagnostics),
        )


def _check_expected_error(scenario: Eval, failure: Exception | None) -> list[EvalDiagnostic]:
    expected = scenario.expected_error
    if expected is None:  # pragma: no cover - guarded by caller
        return []
    if failure is None:
        return [
            EvalDiagnostic(
                code="ACC_EVAL_EXPECTED_ERROR_NOT_RAISED",
                message="Capability did not raise the error required by the eval contract.",
            )
        ]

    diagnostics: list[EvalDiagnostic] = []
    if getattr(failure, "code", None) != expected.code:
        diagnostics.append(
            EvalDiagnostic(
                code="ACC_EVAL_ERROR_CODE_MISMATCH",
                message="Capability error code does not match the eval contract.",
            )
        )
    if expected.status is not None and getattr(failure, "status", None) != expected.status:
        diagnostics.append(
            EvalDiagnostic(
                code="ACC_EVAL_ERROR_STATUS_MISMATCH",
                message="Capability error status does not match the eval contract.",
            )
        )
    if expected.message_contains is not None and expected.message_contains not in str(failure):
        diagnostics.append(
            EvalDiagnostic(
                code="ACC_EVAL_ERROR_MESSAGE_MISMATCH",
                message="Capability error message does not match the eval contract.",
            )
        )
    return diagnostics


def _calls_match(scenario: Eval, actual_calls: Sequence[Mapping[str, object]]) -> bool:
    if len(actual_calls) != len(scenario.expected_calls):
        return False
    for expected, actual in zip(scenario.expected_calls, actual_calls, strict=True):
        if actual.get("operation") != expected.operation:
            return False
        arguments = actual.get("arguments")
        if not isinstance(arguments, Mapping) or dict(arguments) != expected.arguments:
            return False
    return True


def _contains_forbidden_field(value: Any, forbidden: set[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in forbidden or _contains_forbidden_field(item, forbidden)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_field(item, forbidden) for item in value)
    return False


def _matches_schema(raw_schema: Any, instance: Any) -> bool:
    schema = _mapping(raw_schema)
    if schema is None:
        return False
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        return False
    try:
        return Draft202012Validator(schema).is_valid(instance)
    except Exception:
        # Resolution errors are stable case failures, not public exceptions.
        return False


def _mapping(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        return None
    return value


def _string_value(value: Any, key: str) -> str:
    mapping = _mapping(value)
    item = mapping.get(key) if mapping is not None else None
    return item if isinstance(item, str) else ""


def _failed_hook_case(
    case_id: str,
    capability_id: str,
    code: str,
    message: str,
) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        capability_id=capability_id,
        diagnostics=(EvalDiagnostic(code=code, message=message),),
    )


def _sorted_diagnostics(
    diagnostics: Sequence[EvalDiagnostic],
) -> tuple[EvalDiagnostic, ...]:
    return tuple(sorted(diagnostics, key=lambda item: (item.code, item.message)))


__all__ = [
    "AsyncCapabilityCaller",
    "AsyncFixtureLoader",
    "CallRecorder",
    "RuntimeEvalRunner",
]
