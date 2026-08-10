"""Static contract checks for compiled ACC evaluation cases."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from jsonschema import Draft202012Validator, SchemaError
from pydantic import ValidationError

from acc_core.evals.results import CaseResult, EvalDiagnostic, EvalReport
from acc_core.models import Eval


class ContractEvalRunner:
    """Check the static shape and bindings of eval cases in compiled IR."""

    def run(self, compiled_ir: Mapping[str, Any]) -> EvalReport:
        if compiled_ir.get("ir_version") != "2":
            return EvalReport(
                kind="contract",
                cases=(),
                diagnostics=(
                    EvalDiagnostic(
                        code="ACC_EVAL_IR_INVALID",
                        message="Eval accepts only current compiled IR version 2.",
                    ),
                ),
            )
        raw_evals = _mapping(compiled_ir.get("evals"))
        capabilities = _mapping(compiled_ir.get("capabilities"))
        operations = _mapping(compiled_ir.get("operations"))
        policies = _mapping(compiled_ir.get("policies"))
        report_diagnostics: list[EvalDiagnostic] = []
        if raw_evals is None or capabilities is None or operations is None or policies is None:
            report_diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_IR_INVALID",
                    message="Compiled IR is missing an evaluation contract section.",
                )
            )

        evals = raw_evals or {}
        capability_map = capabilities or {}
        operation_map = operations or {}
        policy_map = policies or {}
        cases = tuple(
            self._check_case(
                case_id,
                evals[case_id],
                capability_map,
                operation_map,
            )
            for case_id in sorted(key for key in evals if isinstance(key, str))
        )
        report_diagnostics.extend(_coverage_diagnostics(capability_map, evals, policy_map))
        return EvalReport(
            kind="contract",
            cases=cases,
            diagnostics=_sorted_diagnostics(report_diagnostics),
        )

    def _check_case(
        self,
        case_id: str,
        raw_case: Any,
        capabilities: Mapping[str, Any],
        operations: Mapping[str, Any],
    ) -> CaseResult:
        capability_id = _string_value(raw_case, "capability")
        diagnostics: list[EvalDiagnostic] = []
        try:
            scenario = Eval.model_validate(raw_case)
        except ValidationError:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_CASE_INVALID",
                    message="Eval case does not match the declared Eval contract.",
                )
            )
            return CaseResult(
                case_id=case_id,
                capability_id=capability_id,
                diagnostics=tuple(diagnostics),
            )
        if scenario.id != case_id:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_ID_MISMATCH",
                    message="Eval map key does not match the declared case id.",
                )
            )

        compiled_capability = _mapping(capabilities.get(scenario.capability))
        definition = (
            _mapping(compiled_capability.get("definition"))
            if compiled_capability is not None
            else None
        )
        if definition is None:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_CAPABILITY_NOT_FOUND",
                    message="Eval case references an unavailable capability.",
                )
            )
            return CaseResult(
                case_id=case_id,
                capability_id=scenario.capability,
                diagnostics=tuple(diagnostics),
            )
        assert compiled_capability is not None

        declared_evals = _string_sequence(definition.get("evals"))
        if case_id not in declared_evals:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_NOT_DECLARED",
                    message="Eval case is not declared by its capability.",
                )
            )
        if not _matches_schema(definition.get("input_schema"), scenario.input):
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_INPUT_SCHEMA_MISMATCH",
                    message="Eval input does not match the capability input schema.",
                )
            )

        dependencies = set(_string_sequence(compiled_capability.get("operation_dependencies")))
        for expected_call in scenario.expected_calls:
            operation = _mapping(operations.get(expected_call.operation))
            if operation is None:
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_OPERATION_NOT_FOUND",
                        message="Expected call references an unavailable operation.",
                    )
                )
                continue
            if expected_call.operation not in dependencies:
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_OPERATION_NOT_DEPENDENCY",
                        message="Expected call is not a capability operation dependency.",
                    )
                )
            if not _matches_schema(operation.get("input_schema"), expected_call.arguments):
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_EXPECTED_CALL_SCHEMA_MISMATCH",
                        message="Expected call arguments do not match the operation input schema.",
                    )
                )

        return CaseResult(
            case_id=case_id,
            capability_id=scenario.capability,
            diagnostics=_sorted_diagnostics(diagnostics),
        )


def _coverage_diagnostics(
    capabilities: Mapping[str, Any],
    evals: Mapping[str, Any],
    policies: Mapping[str, Any],
) -> list[EvalDiagnostic]:
    diagnostics: list[EvalDiagnostic] = []
    for capability_id in sorted(key for key in capabilities if isinstance(key, str)):
        compiled = _mapping(capabilities[capability_id])
        definition = _mapping(compiled.get("definition")) if compiled is not None else None
        if definition is None:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_CAPABILITY_INVALID",
                    message=f"Capability contract is invalid: {capability_id}",
                )
            )
            continue

        declared_ids = _string_sequence(definition.get("evals"))
        for eval_id in declared_ids:
            if eval_id not in evals:
                diagnostics.append(
                    EvalDiagnostic(
                        code="ACC_EVAL_DECLARED_CASE_NOT_FOUND",
                        message=(
                            "Capability declares an unavailable eval case: "
                            f"{capability_id}/{eval_id}"
                        ),
                    )
                )
        scenarios = [
            scenario
            for eval_id in declared_ids
            if (scenario := _validated_eval(evals.get(eval_id))) is not None
            and scenario.capability == capability_id
            and scenario.id == eval_id
        ]
        if not any(scenario.expected_output_schema is not None for scenario in scenarios):
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_POSITIVE_REQUIRED",
                    message=f"Capability requires a positive eval case: {capability_id}",
                )
            )

        policy_id = definition.get("policy")
        policy = _mapping(policies.get(policy_id)) if isinstance(policy_id, str) else None
        if policy is None:
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_POLICY_NOT_FOUND",
                    message=f"Capability references an unavailable policy: {capability_id}",
                )
            )
            continue
        requires_permission = bool(_string_sequence(policy.get("required_scopes"))) or (
            policy.get("tenant_mode") == "required"
        )
        if requires_permission and not any(
            scenario.expected_error is not None and scenario.expected_error.status in {401, 403}
            for scenario in scenarios
        ):
            diagnostics.append(
                EvalDiagnostic(
                    code="ACC_EVAL_PERMISSION_NEGATIVE_REQUIRED",
                    message=(
                        "Permission-bearing capability requires a negative eval case: "
                        f"{capability_id}"
                    ),
                )
            )
    return diagnostics


def _validated_eval(value: Any) -> Eval | None:
    try:
        return Eval.model_validate(value)
    except ValidationError:
        return None


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
        # Resolution errors are contract mismatches, not runner crashes.
        return False


def _mapping(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        return None
    return value


def _string_sequence(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _string_value(value: Any, key: str) -> str:
    mapping = _mapping(value)
    item = mapping.get(key) if mapping is not None else None
    return item if isinstance(item, str) else ""


def _sorted_diagnostics(
    diagnostics: Sequence[EvalDiagnostic],
) -> tuple[EvalDiagnostic, ...]:
    return tuple(sorted(diagnostics, key=lambda item: (item.code, item.message)))


__all__ = ["ContractEvalRunner"]
