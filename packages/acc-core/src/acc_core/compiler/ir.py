"""Deterministic validation and compilation of ACC capability workflows."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from acc_core.compiler.actions import (
    compile_action_semantics_attestation,
    prove_action_capability,
)
from acc_core.contracts import SourceContract
from acc_core.diagnostics import Diagnostic
from acc_core.models import (
    ActionCapabilityV2,
    ActionOperationV2,
    AssertStep,
    BranchStep,
    CallStep,
    EmitStep,
    FilterStep,
    ForeachStep,
    MapStep,
    ParallelStep,
    PasswordBearerAuthConfig,
    PickStep,
    ReadCapabilityV2,
    RedactStep,
    StrictModel,
    WorkflowStep,
)
from acc_core.scope import (
    CapabilityScopeRequirements,
    analyze_capability_scope_requirements,
)
from acc_core.validation import validate_project

type CompiledIR = dict[str, JsonValue]

_REFERENCE_SEGMENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_REFERENCE_PATTERN = re.compile(
    rf"^\$\.(?:(?P<root>input|item|prepared)(?:\.{_REFERENCE_SEGMENT})*"
    rf"|steps\.(?P<step>{_REFERENCE_SEGMENT})(?:\.{_REFERENCE_SEGMENT})*)$"
)


@dataclass(slots=True)
class CompilationReport:
    """A compiled IR or stable diagnostics explaining why compilation failed."""

    ir: CompiledIR | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Return whether compilation produced an error-free IR."""

        return self.ir is not None and not any(
            item.severity == "error" for item in self.diagnostics
        )


def _normalize_json(value: Any) -> JsonValue:
    """Recursively sort object keys while preserving semantically ordered arrays."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {
            str(key): _normalize_json(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item) for item in value]
    raise TypeError(f"compiler input is not JSON-compatible: {type(value).__name__}")


def _model_json(model: StrictModel) -> dict[str, JsonValue]:
    dumped = _normalize_json(model.model_dump(mode="json", by_alias=True))
    if not isinstance(dumped, dict):  # pragma: no cover - Pydantic models always dump objects
        raise TypeError("ACC models must serialize to JSON objects")
    return dumped


def _diagnostic(
    diagnostics: list[Diagnostic],
    *,
    code: str,
    message: str,
    path: str,
    pointer: str,
) -> None:
    diagnostics.append(
        Diagnostic(
            code=code,
            severity="error",
            message=message,
            path=path,
            pointer=pointer,
        )
    )


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _validate_reference(
    value: str,
    *,
    available_steps: set[str],
    allow_item: bool,
    allow_input: bool,
    allow_prepared: bool,
    require_reference: bool,
    path: str,
    pointer: str,
    diagnostics: list[Diagnostic],
) -> None:
    match = _REFERENCE_PATTERN.fullmatch(value)
    looks_dynamic = value.startswith("$") or "$." in value or "${" in value
    if match is None:
        if require_reference or looks_dynamic:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_REFERENCE_INVALID",
                message=(
                    "Workflow expressions must be one static reference rooted at "
                    "$.input, $.prepared, $.steps.<prior-step>, or $.item."
                ),
                path=path,
                pointer=pointer,
            )
        return

    root = match.group("root")
    if root == "item" and not allow_item:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ITEM_REFERENCE_OUTSIDE_LOOP",
            message="$.item is only available inside a bounded item workflow.",
            path=path,
            pointer=pointer,
        )
        return

    if root == "input" and not allow_input:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_INPUT_REFERENCE_UNAVAILABLE",
            message="$.input is not available in this workflow phase.",
            path=path,
            pointer=pointer,
        )
        return

    if root == "prepared" and not allow_prepared:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_PREPARED_REFERENCE_UNAVAILABLE",
            message="$.prepared is available only in an Action commit workflow.",
            path=path,
            pointer=pointer,
        )
        return

    step_id = match.group("step")
    if step_id is not None and step_id not in available_steps:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_STEP_REFERENCE_NOT_PRIOR",
            message=f"Workflow reference must target a prior step id: {step_id}",
            path=path,
            pointer=pointer,
        )


def _validate_value(
    value: JsonValue,
    *,
    available_steps: set[str],
    allow_item: bool,
    allow_input: bool,
    allow_prepared: bool,
    require_reference: bool = False,
    path: str,
    pointer: str,
    diagnostics: list[Diagnostic],
) -> None:
    if isinstance(value, str):
        _validate_reference(
            value,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            require_reference=require_reference,
            path=path,
            pointer=pointer,
            diagnostics=diagnostics,
        )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(
                item,
                available_steps=available_steps,
                allow_item=allow_item,
                allow_input=allow_input,
                allow_prepared=allow_prepared,
                require_reference=False,
                path=path,
                pointer=f"{pointer}/{index}",
                diagnostics=diagnostics,
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_value(
                item,
                available_steps=available_steps,
                allow_item=allow_item,
                allow_input=allow_input,
                allow_prepared=allow_prepared,
                require_reference=False,
                path=path,
                pointer=f"{pointer}/{_pointer_token(key)}",
                diagnostics=diagnostics,
            )


def _register_step_id(
    step: WorkflowStep,
    *,
    seen_step_ids: set[str],
    path: str,
    pointer: str,
    diagnostics: list[Diagnostic],
) -> None:
    if step.id is None:
        return
    if step.id in seen_step_ids:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_STEP_ID_DUPLICATE",
            message=f"Workflow step ids must be unique: {step.id}",
            path=path,
            pointer=f"{pointer}/id",
        )
        return
    seen_step_ids.add(step.id)


def _validate_step(
    step: WorkflowStep,
    *,
    available_steps: set[str],
    seen_step_ids: set[str],
    operations: set[str],
    operation_bindings: dict[str, set[str]],
    dependencies: set[str],
    allow_item: bool,
    allow_input: bool,
    allow_prepared: bool,
    path: str,
    pointer: str,
    diagnostics: list[Diagnostic],
) -> None:
    _register_step_id(
        step,
        seen_step_ids=seen_step_ids,
        path=path,
        pointer=pointer,
        diagnostics=diagnostics,
    )

    if isinstance(step, CallStep):
        operation_id = step.call.operation
        dependencies.add(operation_id)
        if operation_id not in operations:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_OPERATION_NOT_FOUND",
                message=f"Capability references an unknown operation: {operation_id}",
                path=path,
                pointer=f"{pointer}/call/operation",
            )
        for argument in sorted(
            set(step.call.arguments) & operation_bindings.get(operation_id, set())
        ):
            escaped_argument = argument.replace("~", "~0").replace("/", "~1")
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_CONTEXT_BINDING_ARGUMENT_OVERRIDE",
                message=(
                    f"Workflow arguments cannot provide a context-bound Operation input: {argument}"
                ),
                path=path,
                pointer=f"{pointer}/call/arguments/{escaped_argument}",
            )
        _validate_value(
            step.call.arguments,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/call/arguments",
            diagnostics=diagnostics,
        )
    elif isinstance(step, PickStep):
        _validate_value(
            step.pick.value,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/pick/value",
            diagnostics=diagnostics,
        )
    elif isinstance(step, MapStep):
        _validate_value(
            step.map.items,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/map/items",
            diagnostics=diagnostics,
        )
        _validate_value(
            step.map.expression,
            available_steps=available_steps,
            allow_item=True,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            require_reference=True,
            path=path,
            pointer=f"{pointer}/map/expression",
            diagnostics=diagnostics,
        )
    elif isinstance(step, FilterStep):
        _validate_value(
            step.filter.items,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/filter/items",
            diagnostics=diagnostics,
        )
        _validate_value(
            step.filter.condition,
            available_steps=available_steps,
            allow_item=True,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            require_reference=True,
            path=path,
            pointer=f"{pointer}/filter/condition",
            diagnostics=diagnostics,
        )
    elif isinstance(step, AssertStep):
        _validate_value(
            step.assert_.condition,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            require_reference=True,
            path=path,
            pointer=f"{pointer}/assert/condition",
            diagnostics=diagnostics,
        )
    elif isinstance(step, RedactStep):
        _validate_value(
            step.redact.value,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/redact/value",
            diagnostics=diagnostics,
        )
    elif isinstance(step, BranchStep):
        _validate_value(
            step.branch.condition,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            require_reference=True,
            path=path,
            pointer=f"{pointer}/branch/condition",
            diagnostics=diagnostics,
        )
        _validate_workflow(
            step.branch.then_steps,
            available_steps=set(available_steps),
            seen_step_ids=seen_step_ids,
            operations=operations,
            operation_bindings=operation_bindings,
            dependencies=dependencies,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/branch/then",
            diagnostics=diagnostics,
        )
        _validate_workflow(
            step.branch.else_steps,
            available_steps=set(available_steps),
            seen_step_ids=seen_step_ids,
            operations=operations,
            operation_bindings=operation_bindings,
            dependencies=dependencies,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/branch/else",
            diagnostics=diagnostics,
        )
    elif isinstance(step, ParallelStep):
        for index, child in enumerate(step.parallel):
            _validate_step(
                child,
                available_steps=set(available_steps),
                seen_step_ids=seen_step_ids,
                operations=operations,
                operation_bindings=operation_bindings,
                dependencies=dependencies,
                allow_item=allow_item,
                allow_input=allow_input,
                allow_prepared=allow_prepared,
                path=path,
                pointer=f"{pointer}/parallel/{index}",
                diagnostics=diagnostics,
            )
    elif isinstance(step, ForeachStep):
        _validate_value(
            step.foreach.items,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/foreach/items",
            diagnostics=diagnostics,
        )
        _validate_workflow(
            step.foreach.workflow,
            available_steps=set(available_steps),
            seen_step_ids=seen_step_ids,
            operations=operations,
            operation_bindings=operation_bindings,
            dependencies=dependencies,
            allow_item=True,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/foreach/workflow",
            diagnostics=diagnostics,
        )
    elif isinstance(step, EmitStep):
        _validate_value(
            step.emit.value,
            available_steps=available_steps,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/emit/value",
            diagnostics=diagnostics,
        )


def _validate_workflow(
    workflow: list[WorkflowStep],
    *,
    available_steps: set[str],
    seen_step_ids: set[str],
    operations: set[str],
    operation_bindings: dict[str, set[str]],
    dependencies: set[str],
    allow_item: bool,
    allow_input: bool,
    allow_prepared: bool,
    path: str,
    pointer: str,
    diagnostics: list[Diagnostic],
) -> None:
    for index, step in enumerate(workflow):
        _validate_step(
            step,
            available_steps=available_steps,
            seen_step_ids=seen_step_ids,
            operations=operations,
            operation_bindings=operation_bindings,
            dependencies=dependencies,
            allow_item=allow_item,
            allow_input=allow_input,
            allow_prepared=allow_prepared,
            path=path,
            pointer=f"{pointer}/{index}",
            diagnostics=diagnostics,
        )
        if step.id is not None:
            available_steps.add(step.id)


def _compile_capability(
    capability: ReadCapabilityV2,
    *,
    operations: set[str],
    operation_bindings: dict[str, set[str]],
    policies: set[str],
    evals: dict[str, str],
    diagnostics: list[Diagnostic],
) -> set[str]:
    path = f"capabilities/{capability.id}.yaml"
    if capability.policy not in policies:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_POLICY_NOT_FOUND",
            message=f"Capability references an unknown policy: {capability.policy}",
            path=path,
            pointer="/policy",
        )
    for index, eval_id in enumerate(capability.evals):
        eval_capability = evals.get(eval_id)
        if eval_capability is None:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_EVAL_NOT_FOUND",
                message=f"Capability references an unknown eval: {eval_id}",
                path=path,
                pointer=f"/evals/{index}",
            )
        elif eval_capability != capability.id:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_EVAL_CAPABILITY_MISMATCH",
                message=(
                    f"Eval {eval_id} targets {eval_capability}, not capability {capability.id}."
                ),
                path=path,
                pointer=f"/evals/{index}",
            )

    dependencies: set[str] = set()
    _validate_workflow(
        capability.workflow,
        available_steps=set(),
        seen_step_ids=set(),
        operations=operations,
        operation_bindings=operation_bindings,
        dependencies=dependencies,
        allow_item=False,
        allow_input=True,
        allow_prepared=False,
        path=path,
        pointer="/workflow",
        diagnostics=diagnostics,
    )
    if not isinstance(capability.workflow[-1], EmitStep):
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_FINAL_EMIT_REQUIRED",
            message="A capability workflow must end with an emit step.",
            path=path,
            pointer="/workflow",
        )
    properties = capability.input_schema.get("properties", {})
    public_inputs = set(properties) if isinstance(properties, dict) else set()
    dependency_bindings = {
        target
        for operation_id in dependencies
        for target in operation_bindings.get(operation_id, set())
    }
    unsafe_root_keywords = (
        "$ref",
        "allOf",
        "anyOf",
        "oneOf",
        "if",
        "then",
        "else",
        "patternProperties",
        "unevaluatedProperties",
    )
    if dependency_bindings and capability.input_schema.get("type") != "object":
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT",
            message="A Capability using context bindings requires a root object input schema.",
            path=path,
            pointer="/input_schema/type",
        )
    if dependency_bindings and capability.input_schema.get("additionalProperties") is not False:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT",
            message=(
                "Capability input schemas must set additionalProperties to false when "
                "a dependency uses context bindings."
            ),
            path=path,
            pointer="/input_schema/additionalProperties",
        )
    if dependency_bindings:
        for keyword in unsafe_root_keywords:
            if keyword not in capability.input_schema:
                continue
            escaped_keyword = keyword.replace("~", "~0").replace("/", "~1")
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT",
                message=(
                    "A Capability using context bindings cannot use root input schema "
                    f"keyword: {keyword}"
                ),
                path=path,
                pointer=f"/input_schema/{escaped_keyword}",
            )
    for target in sorted(public_inputs & dependency_bindings):
        escaped_target = target.replace("~", "~0").replace("/", "~1")
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_CONTEXT_BINDING_PUBLIC_INPUT",
            message=(f"Capability input cannot expose a context-bound Operation input: {target}"),
            path=path,
            pointer=f"/input_schema/properties/{escaped_target}",
        )
    return dependencies


def _compile_action_capability(
    capability: ActionCapabilityV2,
    *,
    operations: dict[str, object],
    source_contracts: dict[str, SourceContract],
    operation_bindings: dict[str, set[str]],
    policies: set[str],
    evals: dict[str, str],
    diagnostics: list[Diagnostic],
) -> tuple[set[str], dict[str, JsonValue]]:
    """Prove and compile one current-format Action."""

    path = f"capabilities/{capability.id}.yaml"
    if capability.policy not in policies:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_POLICY_NOT_FOUND",
            message=f"Capability references an unknown policy: {capability.policy}",
            path=path,
            pointer="/policy",
        )
    for index, eval_id in enumerate(capability.evals):
        target = evals.get(eval_id)
        if target is None:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_EVAL_NOT_FOUND",
                message=f"Capability references an unknown eval: {eval_id}",
                path=path,
                pointer=f"/evals/{index}",
            )
        elif target != capability.id:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_EVAL_CAPABILITY_MISMATCH",
                message=f"Eval {eval_id} targets {target}, not capability {capability.id}.",
                path=path,
                pointer=f"/evals/{index}",
            )
    proof = prove_action_capability(
        capability,
        cast(dict[str, Any], operations),
        path=path,
    )
    diagnostics.extend(proof.diagnostics)
    dependencies: set[str] = set()
    _validate_workflow(
        capability.preview_workflow,
        available_steps=set(),
        seen_step_ids=set(),
        operations=set(operations),
        operation_bindings=operation_bindings,
        dependencies=dependencies,
        allow_item=False,
        allow_input=True,
        allow_prepared=False,
        path=path,
        pointer="/preview_workflow",
        diagnostics=diagnostics,
    )
    _validate_workflow(
        capability.commit_workflow,
        available_steps=set(),
        seen_step_ids=set(),
        operations=set(operations),
        operation_bindings=operation_bindings,
        dependencies=dependencies,
        allow_item=False,
        allow_input=False,
        allow_prepared=True,
        path=path,
        pointer="/commit_workflow",
        diagnostics=diagnostics,
    )
    if not isinstance(capability.preview_workflow[-1], EmitStep):
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_FINAL_EMIT_REQUIRED",
            message="An Action preview_workflow must end with an emit step.",
            path=path,
            pointer="/preview_workflow",
        )
    if not isinstance(capability.commit_workflow[-1], EmitStep):
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_FINAL_EMIT_REQUIRED",
            message="An Action commit_workflow must end with an emit step.",
            path=path,
            pointer="/commit_workflow",
        )
    operation_semantics: dict[str, JsonValue] = {}
    for operation_id in proof.mutation_operation_ids:
        operation = operations.get(operation_id)
        contract = source_contracts.get(operation_id)
        if not isinstance(operation, ActionOperationV2) or contract is None:
            continue
        semantics = contract.action_semantics
        if semantics is None:
            continue
        operation_semantics[operation_id] = compile_action_semantics_attestation(
            operation,
            semantics,
        )
    return dependencies, {
        "approval_required": proof.approval_required,
        "effects": list(proof.effects),
        "maximum_risk": proof.maximum_risk,
        "mutation_operation_ids": list(proof.mutation_operation_ids),
        "operation_semantics": operation_semantics,
        "required_scopes": list(proof.required_scopes),
    }


def _scope_requirements_json(
    requirements: CapabilityScopeRequirements,
) -> dict[str, JsonValue]:
    normalized = _normalize_json(
        {
            "policy_always_required": sorted(requirements.policy_always_required),
            "always_required": sorted(requirements.always_required),
            "conditionally_required": sorted(requirements.conditionally_required),
            "all_referenced": sorted(requirements.all_referenced),
            "completion_alternatives": [
                sorted(alternative) for alternative in requirements.completion_alternatives
            ],
        }
    )
    assert isinstance(normalized, dict)
    return normalized


def compile_project(project_root: str | Path = ".") -> CompilationReport:
    """Compile a validated project into deterministic, JSON-compatible IR."""

    validation = validate_project(project_root)
    diagnostics = list(validation.diagnostics)
    report = CompilationReport(diagnostics=diagnostics)
    if not validation.ok or validation.project is None:
        return report

    operation_ids = set(validation.operations)
    operation_bindings = {
        operation_id: set(operation.context_bindings)
        for operation_id, operation in validation.operations.items()
    }
    context_binding_allowlist = set(validation.project.provider.context_binding_allowlist)
    for operation_id, operation in sorted(validation.operations.items()):
        properties = operation.input_schema.get("properties", {})
        declared_inputs = set(properties) if isinstance(properties, dict) else set()
        mapped_inputs = set(operation.http.path_parameters.values()) | set(
            operation.http.query_parameters.values()
        )
        request = getattr(operation.http, "request", None)
        if request is not None:
            mapped_inputs.update(request.body_parameters.values())
        for target, source in sorted(operation.context_bindings.items()):
            escaped_target = target.replace("~", "~0").replace("/", "~1")
            if target not in declared_inputs or target not in mapped_inputs:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_CONTEXT_BINDING_TARGET_INVALID",
                    message=(
                        "A context binding target must be a declared Operation input mapped "
                        f"to an HTTP path, query, or body parameter: {target}"
                    ),
                    path=validation.operation_paths[operation_id],
                    pointer=f"/context_bindings/{escaped_target}",
                )
            if source != "principal_id" and source not in context_binding_allowlist:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_CONTEXT_BINDING_SOURCE_NOT_ALLOWED",
                    message=(
                        "A tenant context binding source must be explicitly listed in "
                        f"provider.context_binding_allowlist: {source}"
                    ),
                    path=validation.operation_paths[operation_id],
                    pointer=f"/context_bindings/{escaped_target}",
                )
    policy_ids = set(validation.policies)
    eval_targets = {eval_id: scenario.capability for eval_id, scenario in validation.evals.items()}
    dependencies: dict[str, set[str]] = {}
    action_proofs: dict[str, dict[str, JsonValue]] = {}
    for capability_id in sorted(validation.capabilities):
        capability = validation.capabilities[capability_id]
        if isinstance(capability, ActionCapabilityV2):
            dependencies[capability_id], action_proofs[capability_id] = _compile_action_capability(
                capability,
                operations=cast(dict[str, object], validation.operations),
                source_contracts=validation.source_contracts,
                operation_bindings=operation_bindings,
                policies=policy_ids,
                evals=eval_targets,
                diagnostics=diagnostics,
            )
        else:
            dependencies[capability_id] = _compile_capability(
                capability,
                operations=operation_ids,
                operation_bindings=operation_bindings,
                policies=policy_ids,
                evals=eval_targets,
                diagnostics=diagnostics,
            )

    if validation.project.runtime.transport == ["streamable_http"]:
        auth = validation.project.provider.auth
        if isinstance(auth, PasswordBearerAuthConfig):
            for capability_id in sorted(validation.capabilities):
                capability = validation.capabilities[capability_id]
                policy = validation.policies.get(capability.policy)
                policy_scopes = set(policy.required_scopes) if policy is not None else set()
                operation_scopes = {
                    scope
                    for operation_id in dependencies[capability_id]
                    if operation_id in validation.operations
                    for scope in validation.operations[operation_id].http.scopes
                }
                if (policy_scopes or operation_scopes) and (
                    auth.scopes_pointer is None or not auth.scope_mapping
                ):
                    _diagnostic(
                        diagnostics,
                        code="ACC_COMPILE_SOURCE_SCOPE_MAPPING_REQUIRED",
                        message=(
                            "A scoped streamable_http capability requires scopes_pointer "
                            "and a non-empty scope_mapping."
                        ),
                        path=f"capabilities/{capability_id}.yaml",
                        pointer="/policy",
                    )

    for eval_id in sorted(validation.evals):
        scenario = validation.evals[eval_id]
        path = f"evals/{eval_id}.yaml"
        if scenario.capability not in validation.capabilities:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_CAPABILITY_NOT_FOUND",
                message=f"Eval references an unknown capability: {scenario.capability}",
                path=path,
                pointer="/capability",
            )
        for index, expected_call in enumerate(scenario.expected_calls):
            if expected_call.operation not in validation.operations:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_OPERATION_NOT_FOUND",
                    message=f"Eval references an unknown operation: {expected_call.operation}",
                    path=path,
                    pointer=f"/expected_calls/{index}/operation",
                )

    if any(item.severity == "error" for item in diagnostics):
        return report

    compiled_capabilities: dict[str, JsonValue] = {}
    for capability_id in sorted(validation.capabilities):
        compiled = cast(
            dict[str, JsonValue],
            _normalize_json(
                {
                    "definition": _model_json(validation.capabilities[capability_id]),
                    "operation_dependencies": sorted(dependencies[capability_id]),
                }
            ),
        )
        quality = validation.capability_quality.get(capability_id)
        if quality is not None:
            compiled["quality"] = _normalize_json(
                {
                    "max_output_bytes": quality.output_budget.max_bytes,
                    "long_text_disclosures": [
                        item.model_dump(mode="json")
                        for item in quality.output_budget.long_text_disclosures
                    ],
                    "intent": quality.intent.model_dump(mode="json"),
                    "inputs": {
                        name: item.model_dump(mode="json")
                        for name, item in sorted(quality.inputs.items())
                    },
                    "composition": quality.composition.model_dump(mode="json"),
                }
            )
        if capability_id in action_proofs:
            compiled["action_proof"] = action_proofs[capability_id]
            action_policy_scopes = frozenset(
                validation.policies[validation.capabilities[capability_id].policy].required_scopes
            )
            proof_scopes = cast(
                list[str],
                action_proofs[capability_id]["required_scopes"],
            )
            action_scopes = frozenset(proof_scopes) | action_policy_scopes
            compiled["scope_requirements"] = _scope_requirements_json(
                CapabilityScopeRequirements(
                    capability_id=capability_id,
                    policy_always_required=action_policy_scopes,
                    always_required=action_scopes,
                    conditionally_required=frozenset(),
                    all_referenced=action_scopes,
                    completion_alternatives=(action_scopes,),
                )
            )
        else:
            capability = cast(
                ReadCapabilityV2,
                validation.capabilities[capability_id],
            )
            compiled["scope_requirements"] = _scope_requirements_json(
                analyze_capability_scope_requirements(
                    capability=capability,
                    policy=validation.policies[capability.policy],
                    operations=validation.operations,
                )
            )
        compiled_capabilities[capability_id] = _normalize_json(compiled)

    raw_ir: dict[str, JsonValue] = {
        "ir_version": "2",
        "project": _model_json(validation.project),
        "operations": {
            operation_id: _model_json(validation.operations[operation_id])
            for operation_id in sorted(validation.operations)
        },
        "policies": {
            policy_id: _model_json(validation.policies[policy_id])
            for policy_id in sorted(validation.policies)
        },
        "evals": {
            eval_id: _model_json(validation.evals[eval_id]) for eval_id in sorted(validation.evals)
        },
        "capabilities": compiled_capabilities,
    }
    report.ir = cast(CompiledIR, _normalize_json(raw_ir))
    return report


__all__ = ["CompilationReport", "CompiledIR", "compile_project"]
