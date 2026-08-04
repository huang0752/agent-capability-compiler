"""Deterministic, side-effect-free capability coverage analysis."""

from __future__ import annotations

from collections.abc import Iterable

from acc_core.models import BranchStep, CallStep, ForeachStep, ParallelStep, WorkflowStep
from acc_core.validation import ValidationReport


def _called_operations(steps: Iterable[WorkflowStep]) -> set[str]:
    dependencies: set[str] = set()
    for step in steps:
        if isinstance(step, CallStep):
            dependencies.add(step.call.operation)
        elif isinstance(step, BranchStep):
            dependencies.update(_called_operations(step.branch.then_steps))
            dependencies.update(_called_operations(step.branch.else_steps))
        elif isinstance(step, ParallelStep):
            dependencies.update(_called_operations(step.parallel))
        elif isinstance(step, ForeachStep):
            dependencies.update(_called_operations(step.foreach.workflow))
    return dependencies


def _is_permission_negative(code: str, status: int | None) -> bool:
    if status in {401, 403}:
        return True
    normalized = code.upper()
    return any(
        token in normalized for token in ("AUTH", "FORBIDDEN", "PERMISSION", "SCOPE", "TENANT")
    )


def analyze_coverage(report: ValidationReport) -> dict[str, object]:
    """Return stable JSON data for the coverage risks visible in ``report``.

    Only evals both declared by a capability and pointing back to that same
    capability count as linked coverage. This prevents an unrelated or orphaned
    eval from hiding a missing scenario.
    """

    dependencies_by_capability = {
        capability_id: _called_operations(capability.workflow)
        for capability_id, capability in sorted(report.capabilities.items())
    }
    used_operations = set().union(*dependencies_by_capability.values())
    orphan_operations = sorted(set(report.operations) - used_operations)

    capabilities_without_evals: list[str] = []
    capabilities_without_negative_evals: list[str] = []
    capabilities_without_permission_negative_evals: list[str] = []
    one_interface_one_tool_risks: list[str] = []

    for capability_id, capability in sorted(report.capabilities.items()):
        linked_evals = [
            report.evals[eval_id]
            for eval_id in capability.evals
            if eval_id in report.evals and report.evals[eval_id].capability == capability_id
        ]
        negative_evals = [item for item in linked_evals if item.expected_error is not None]

        if not linked_evals:
            capabilities_without_evals.append(capability_id)
        if not negative_evals:
            capabilities_without_negative_evals.append(capability_id)

        policy = report.policies.get(capability.policy)
        permission_protected = policy is not None and (
            bool(policy.required_scopes) or policy.tenant_mode == "required"
        )
        has_permission_negative = any(
            item.expected_error is not None
            and _is_permission_negative(item.expected_error.code, item.expected_error.status)
            for item in negative_evals
        )
        if permission_protected and not has_permission_negative:
            capabilities_without_permission_negative_evals.append(capability_id)

        if len(dependencies_by_capability[capability_id]) == 1:
            one_interface_one_tool_risks.append(capability_id)

    finding_count = sum(
        len(items)
        for items in (
            orphan_operations,
            capabilities_without_evals,
            capabilities_without_negative_evals,
            capabilities_without_permission_negative_evals,
            one_interface_one_tool_risks,
        )
    )
    return {
        "coverage_version": "1",
        "summary": {
            "operations": len(report.operations),
            "capabilities": len(report.capabilities),
            "evals": len(report.evals),
            "findings": finding_count,
        },
        "orphan_operations": orphan_operations,
        "capabilities_without_evals": capabilities_without_evals,
        "capabilities_without_negative_evals": capabilities_without_negative_evals,
        "capabilities_without_permission_negative_evals": (
            capabilities_without_permission_negative_evals
        ),
        "one_interface_one_tool_risks": one_interface_one_tool_risks,
    }


__all__ = ["analyze_coverage"]
