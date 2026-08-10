"""Path-sensitive capability scope requirement analysis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from acc_core.models import (
    BranchStep,
    CallStep,
    Capability,
    ForeachStep,
    Operation,
    OperationV2,
    ParallelStep,
    Policy,
    ReadCapabilityV2,
    WorkflowStep,
)

type ScopeSet = frozenset[str]


@dataclass(frozen=True, slots=True)
class CapabilityScopeRequirements:
    """Deterministic scope facts for all successful workflow paths."""

    capability_id: str
    policy_always_required: ScopeSet
    always_required: ScopeSet
    conditionally_required: ScopeSet
    all_referenced: ScopeSet
    completion_alternatives: tuple[ScopeSet, ...]


@dataclass(frozen=True, slots=True)
class _PathRequirements:
    alternatives: tuple[ScopeSet, ...]
    always: ScopeSet
    feasible_union: ScopeSet
    structural_union: ScopeSet


_EMPTY_PATH = _PathRequirements(
    alternatives=(frozenset(),),
    always=frozenset(),
    feasible_union=frozenset(),
    structural_union=frozenset(),
)


def analyze_capability_scope_requirements(
    *,
    capability: Capability | ReadCapabilityV2,
    policy: Policy,
    operations: Mapping[str, Operation | OperationV2],
) -> CapabilityScopeRequirements:
    """Analyze scope alternatives without flattening mutually exclusive branches."""

    workflow = _analyze_steps(capability.workflow, operations)
    policy_scopes = frozenset(policy.required_scopes)
    alternatives = _minimal_antichain(
        tuple(alternative | policy_scopes for alternative in workflow.alternatives)
    )
    always = workflow.always | policy_scopes
    feasible_union = workflow.feasible_union | policy_scopes
    return CapabilityScopeRequirements(
        capability_id=capability.id,
        policy_always_required=policy_scopes,
        always_required=always,
        conditionally_required=feasible_union - always,
        all_referenced=workflow.structural_union | policy_scopes,
        completion_alternatives=alternatives,
    )


def _analyze_steps(
    steps: Sequence[WorkflowStep],
    operations: Mapping[str, Operation | OperationV2],
) -> _PathRequirements:
    result = _EMPTY_PATH
    for step in steps:
        result = _combine_required(result, _analyze_step(step, operations))
    return result


def _analyze_step(
    step: WorkflowStep,
    operations: Mapping[str, Operation | OperationV2],
) -> _PathRequirements:
    if isinstance(step, CallStep):
        operation_id = step.call.operation
        operation = operations.get(operation_id)
        if operation is None:
            raise ValueError(f"scope analysis references an unknown operation: {operation_id}")
        scopes = frozenset(operation.http.scopes)
        return _PathRequirements(
            alternatives=(scopes,),
            always=scopes,
            feasible_union=scopes,
            structural_union=scopes,
        )
    if isinstance(step, BranchStep):
        then_requirements = _analyze_steps(step.branch.then_steps, operations)
        else_requirements = _analyze_steps(step.branch.else_steps, operations)
        return _PathRequirements(
            alternatives=_minimal_antichain(
                then_requirements.alternatives + else_requirements.alternatives
            ),
            always=then_requirements.always & else_requirements.always,
            feasible_union=(then_requirements.feasible_union | else_requirements.feasible_union),
            structural_union=(
                then_requirements.structural_union | else_requirements.structural_union
            ),
        )
    if isinstance(step, ParallelStep):
        return _analyze_steps(step.parallel, operations)
    if isinstance(step, ForeachStep):
        body = _analyze_steps(step.foreach.workflow, operations)
        items = step.foreach.items
        if isinstance(items, list) and not items:
            return _PathRequirements(
                alternatives=(frozenset(),),
                always=frozenset(),
                feasible_union=frozenset(),
                structural_union=body.structural_union,
            )
        if isinstance(items, list):
            return body
        return _PathRequirements(
            alternatives=_minimal_antichain((frozenset(), *body.alternatives)),
            always=frozenset(),
            feasible_union=body.feasible_union,
            structural_union=body.structural_union,
        )
    return _EMPTY_PATH


def _combine_required(left: _PathRequirements, right: _PathRequirements) -> _PathRequirements:
    return _PathRequirements(
        alternatives=_minimal_antichain(
            tuple(
                left_alternative | right_alternative
                for left_alternative in left.alternatives
                for right_alternative in right.alternatives
            )
        ),
        always=left.always | right.always,
        feasible_union=left.feasible_union | right.feasible_union,
        structural_union=left.structural_union | right.structural_union,
    )


def _minimal_antichain(candidates: Sequence[ScopeSet]) -> tuple[ScopeSet, ...]:
    ordered = sorted(set(candidates), key=lambda item: (len(item), tuple(sorted(item))))
    minimal: list[ScopeSet] = []
    for candidate in ordered:
        if any(existing <= candidate for existing in minimal):
            continue
        minimal.append(candidate)
    return tuple(minimal)


__all__ = ["CapabilityScopeRequirements", "analyze_capability_scope_requirements"]
