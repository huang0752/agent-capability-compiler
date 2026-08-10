"""Pure safety proofs and derived inventory for current Action Capabilities."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from pydantic import JsonValue, ValidationError

from acc_core.contracts import ActionSemantics
from acc_core.diagnostics import Diagnostic
from acc_core.models import BranchStep, CallStep, ForeachStep, ParallelStep, WorkflowStep
from acc_core.models.actions import Effect, Risk
from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionOperationV2,
    OperationV2,
)

_RISK_ORDER: dict[Risk, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
_PREPARED_REFERENCE = re.compile(r"^\$\.prepared\.(?:input|preview)(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$")
_DIRECT_INPUT_REFERENCE = re.compile(r"^\$\.input(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$")
_FRESH_STEP_REFERENCE = re.compile(
    r"^\$\.steps\.[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$"
)


def _risk_rank(risk: Risk) -> int:
    return _RISK_ORDER[risk]


def _operation_semantics(operation: ActionOperationV2) -> dict[str, JsonValue]:
    safety = cast(dict[str, JsonValue], operation.http.safety.model_dump(mode="json"))
    return {"method": operation.http.method, **safety}


def _semantics_digest(summary: Mapping[str, JsonValue]) -> str:
    payload = json.dumps(
        summary,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def compile_action_semantics_attestation(
    operation: ActionOperationV2,
    semantics: ActionSemantics,
) -> dict[str, JsonValue]:
    """Seal trusted source semantics into deterministic compiler metadata."""

    summary = cast(dict[str, JsonValue], semantics.model_dump(mode="json"))
    claimed = {key: summary[key] for key in _operation_semantics(operation)}
    if claimed != _operation_semantics(operation) or semantics.evidence not in operation.evidence:
        raise ValueError("Action semantics do not match their bound Operation")
    return {"summary": summary, "digest": _semantics_digest(summary)}


def verify_action_semantics_attestation(
    operation: ActionOperationV2,
    value: object,
) -> bool:
    """Verify compiler metadata against the executable Operation and bound Evidence."""

    if not isinstance(value, Mapping) or set(value) != {"summary", "digest"}:
        return False
    summary = value.get("summary")
    digest = value.get("digest")
    if not isinstance(summary, Mapping) or not isinstance(digest, str):
        return False
    try:
        semantics = ActionSemantics.model_validate(dict(summary))
        expected = compile_action_semantics_attestation(operation, semantics)
    except (TypeError, ValueError, ValidationError):
        return False
    return dict(value) == expected


@dataclass(frozen=True, slots=True)
class ActionProof:
    """Deterministic Action inventory plus every failed safety proof."""

    diagnostics: tuple[Diagnostic, ...]
    mutation_operation_ids: tuple[str, ...]
    effects: tuple[Effect, ...]
    maximum_risk: Risk | None
    required_scopes: tuple[str, ...]
    approval_required: bool

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


@dataclass(frozen=True, slots=True)
class _CallSite:
    operation_id: str
    arguments: Mapping[str, JsonValue]
    pointer: str
    containers: tuple[Literal["parallel", "foreach"], ...]


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


def _call_sites(
    workflow: Sequence[WorkflowStep],
    *,
    pointer: str,
    containers: tuple[Literal["parallel", "foreach"], ...] = (),
) -> tuple[_CallSite, ...]:
    sites: list[_CallSite] = []
    for index, step in enumerate(workflow):
        step_pointer = f"{pointer}/{index}"
        if isinstance(step, CallStep):
            sites.append(
                _CallSite(
                    operation_id=step.call.operation,
                    arguments=step.call.arguments,
                    pointer=f"{step_pointer}/call",
                    containers=containers,
                )
            )
        elif isinstance(step, BranchStep):
            sites.extend(
                _call_sites(
                    step.branch.then_steps,
                    pointer=f"{step_pointer}/branch/then",
                    containers=containers,
                )
            )
            sites.extend(
                _call_sites(
                    step.branch.else_steps,
                    pointer=f"{step_pointer}/branch/else",
                    containers=containers,
                )
            )
        elif isinstance(step, ParallelStep):
            for child_index, child in enumerate(step.parallel):
                sites.extend(
                    _call_sites(
                        [child],
                        pointer=f"{step_pointer}/parallel/{child_index}",
                        containers=(*containers, "parallel"),
                    )
                )
        elif isinstance(step, ForeachStep):
            sites.extend(
                _call_sites(
                    step.foreach.workflow,
                    pointer=f"{step_pointer}/foreach/workflow",
                    containers=(*containers, "foreach"),
                )
            )
    return tuple(sites)


def _sum_counts(left: set[int], right: set[int]) -> set[int]:
    return {left_count + right_count for left_count in left for right_count in right}


def _mutation_path_counts(
    workflow: Sequence[WorkflowStep],
    operations: Mapping[str, OperationV2],
) -> set[int]:
    counts = {0}
    for step in workflow:
        step_counts = {0}
        if isinstance(step, CallStep):
            operation = operations.get(step.call.operation)
            step_counts = {1} if isinstance(operation, ActionOperationV2) else {0}
        elif isinstance(step, BranchStep):
            step_counts = _mutation_path_counts(
                step.branch.then_steps, operations
            ) | _mutation_path_counts(step.branch.else_steps, operations)
        elif isinstance(step, ParallelStep):
            step_counts = {0}
            for child in step.parallel:
                step_counts = _sum_counts(
                    step_counts,
                    _mutation_path_counts([child], operations),
                )
        elif isinstance(step, ForeachStep):
            item_counts = _mutation_path_counts(step.foreach.workflow, operations)
            step_counts = {0}
            for item_count in item_counts:
                step_counts.add(item_count)
                step_counts.add(item_count * step.foreach.max_items)
        counts = _sum_counts(counts, step_counts)
    return counts


def _walk_strings(value: JsonValue, pointer: str) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        return ((value, pointer),)
    if isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_walk_strings(item, f"{pointer}/{index}"))
    elif isinstance(value, dict):
        for key, item in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            found.extend(_walk_strings(item, f"{pointer}/{escaped}"))
    return tuple(found)


def _workflow_strings(
    workflow: Sequence[WorkflowStep],
    *,
    pointer: str,
) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    for index, step in enumerate(workflow):
        dumped = cast(JsonValue, step.model_dump(mode="json", by_alias=True))
        found.extend(_walk_strings(dumped, f"{pointer}/{index}"))
    return tuple(found)


def _derived_approval_required(operations: Sequence[ActionOperationV2]) -> bool:
    return any(
        operation.http.safety.risk in {"high", "critical"}
        or operation.http.safety.reversibility != "reversible"
        or operation.http.safety.effect in {"delete", "execute"}
        or operation.http.safety.idempotency.mode != "source_key"
        for operation in operations
    )


def prove_action_capability(
    capability: ActionCapabilityV2,
    operations: Mapping[str, OperationV2],
    *,
    path: str | None = None,
) -> ActionProof:
    """Prove one Action Capability without reading files or mutating compiler state."""

    diagnostic_path = path or f"capabilities/{capability.id}.yaml"
    diagnostics: list[Diagnostic] = []
    preview_sites = _call_sites(capability.preview_workflow, pointer="/preview_workflow")
    commit_sites = _call_sites(capability.commit_workflow, pointer="/commit_workflow")
    all_sites = (*preview_sites, *commit_sites)

    for site in all_sites:
        if site.operation_id not in operations:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_OPERATION_NOT_FOUND",
                message=f"Action workflow references an unknown Operation: {site.operation_id}",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )

    for site in preview_sites:
        if isinstance(operations.get(site.operation_id), ActionOperationV2):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_PREVIEW_MUTATION",
                message="Action preview_workflow may call only read Operations.",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )

    mutation_sites = tuple(
        site
        for site in commit_sites
        if isinstance(operations.get(site.operation_id), ActionOperationV2)
    )
    for site in mutation_sites:
        if "parallel" in site.containers:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_MUTATION_IN_PARALLEL",
                message="A mutating Operation cannot execute inside a parallel Action step.",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )
        if "foreach" in site.containers:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_MUTATION_IN_FOREACH",
                message="A mutating Operation cannot execute inside an Action foreach step.",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )

    if capability.action.execution_mode != "single":
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_EXECUTION_MODE_UNSUPPORTED",
            message="Action execution mode is declared but not implemented by this compiler.",
            path=diagnostic_path,
            pointer="/action/execution_mode",
        )
    elif _mutation_path_counts(capability.commit_workflow, operations) != {1}:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_SINGLE_MUTATION_REQUIRED",
            message="single Action mode requires exactly one mutation on every commit path.",
            path=diagnostic_path,
            pointer="/commit_workflow",
        )

    for value, pointer in _workflow_strings(
        capability.preview_workflow, pointer="/preview_workflow"
    ):
        if value == "$.prepared" or value.startswith("$.prepared."):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_PREPARED_REFERENCE_IN_PREVIEW",
                message="preview_workflow cannot reference commit-time prepared state.",
                path=diagnostic_path,
                pointer=pointer,
            )

    for value, pointer in _workflow_strings(capability.commit_workflow, pointer="/commit_workflow"):
        if (value == "$.prepared" or value.startswith("$.prepared.")) and (
            _PREPARED_REFERENCE.fullmatch(value) is None
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_PREPARED_REFERENCE_INVALID",
                message=(
                    "commit prepared references must be rooted at "
                    "$.prepared.input or $.prepared.preview."
                ),
                path=diagnostic_path,
                pointer=pointer,
            )

    for site in mutation_sites:
        for value, pointer in _walk_strings(
            cast(JsonValue, dict(site.arguments)),
            f"{site.pointer}/arguments",
        ):
            if _DIRECT_INPUT_REFERENCE.fullmatch(value) is not None:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_UNPREPARED_MUTATION_INPUT",
                    message=(
                        "A mutating Operation must consume the immutable prepared snapshot, "
                        "not live Agent input."
                    ),
                    path=diagnostic_path,
                    pointer=pointer,
                )
            if _FRESH_STEP_REFERENCE.fullmatch(value) is not None:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_FRESH_STEP_MUTATION_INPUT",
                    message=(
                        "A mutating Operation cannot consume a fresh commit-time step result; "
                        "use only the immutable prepared snapshot or deterministic literals."
                    ),
                    path=diagnostic_path,
                    pointer=pointer,
                )

    mutation_operations_by_id = {
        site.operation_id: cast(ActionOperationV2, operations[site.operation_id])
        for site in mutation_sites
    }
    mutation_operations = tuple(
        mutation_operations_by_id[operation_id]
        for operation_id in sorted(mutation_operations_by_id)
    )

    for operation in mutation_operations:
        safety = operation.http.safety
        if safety.effect in {"create", "execute"} and safety.idempotency.mode != "source_key":
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_SOURCE_IDEMPOTENCY_REQUIRED",
                message=f"{safety.effect} Action requires evidenced source-key idempotency.",
                path=diagnostic_path,
                pointer="/commit_workflow",
            )
        if safety.effect in {"update", "delete", "transition"} and (
            safety.concurrency.mode != "required"
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_CONCURRENCY_REQUIRED",
                message=f"{safety.effect} Action requires an optimistic concurrency contract.",
                path=diagnostic_path,
                pointer="/commit_workflow",
            )

    safety_requires_approval = _derived_approval_required(mutation_operations)
    approval_required = capability.action.approval.mode == "required" or safety_requires_approval
    if safety_requires_approval and capability.action.approval.mode != "required":
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_APPROVAL_REQUIRED",
            message="The derived Action risk requires an explicit approval grant.",
            path=diagnostic_path,
            pointer="/action/approval/mode",
        )

    used_operations = {
        site.operation_id: operations[site.operation_id]
        for site in all_sites
        if site.operation_id in operations
    }
    effects = tuple(sorted({operation.http.safety.effect for operation in mutation_operations}))
    risks: set[Risk] = {operation.http.safety.risk for operation in mutation_operations}
    maximum_risk: Risk | None = None
    if risks:
        derived_maximum: Risk = sorted(risks, key=_risk_rank)[-1]
        maximum_risk = derived_maximum
    required_scopes = tuple(
        sorted({scope for operation in used_operations.values() for scope in operation.http.scopes})
    )
    return ActionProof(
        diagnostics=tuple(diagnostics),
        mutation_operation_ids=tuple(sorted(mutation_operations_by_id)),
        effects=effects,
        maximum_risk=maximum_risk,
        required_scopes=required_scopes,
        approval_required=approval_required,
    )


__all__ = [
    "ActionProof",
    "compile_action_semantics_attestation",
    "prove_action_capability",
    "verify_action_semantics_attestation",
]
