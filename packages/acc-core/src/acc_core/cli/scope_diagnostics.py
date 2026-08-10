"""CLI rendering for Runtime scope callability without importing Runtime eagerly."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from acc_core.diagnostics import Diagnostic


@dataclass(frozen=True, slots=True)
class RunScopeConfiguration:
    """Resolved deployment ceiling plus safe startup diagnostics."""

    deployment_scope_ceiling: frozenset[str]
    analysis: dict[str, Any]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def has_errors(self) -> bool:
        return any(item.severity == "error" for item in self.diagnostics)


class _Dimension(Protocol):
    @property
    def status(self) -> object: ...

    @property
    def available_scopes(self) -> frozenset[str] | None: ...

    @property
    def missing_always(self) -> frozenset[str]: ...

    @property
    def missing_conditional(self) -> frozenset[str]: ...

    @property
    def unmet_alternatives(self) -> tuple[frozenset[str], ...]: ...


def analyze_run_scope_configuration(
    ir: Mapping[str, object],
    *,
    requested_scopes: Collection[str],
    ceiling_from_pack: bool,
    strict: bool,
) -> RunScopeConfiguration:
    """Resolve an explicit deployment ceiling and render stable callability JSON."""

    from acc_runtime.callability import CallabilityStatus, analyze_scope_callability

    requested = frozenset(requested_scopes)
    if ceiling_from_pack:
        discovery = analyze_scope_callability(ir, deployment_scope_ceiling=frozenset())
        ceiling = frozenset(
            scope for capability in discovery.capabilities for scope in capability.all_referenced
        )
    else:
        ceiling = requested
    report = analyze_scope_callability(ir, deployment_scope_ceiling=ceiling)
    diagnostics: list[Diagnostic] = []
    declared_scopes = frozenset(
        scope for capability in report.capabilities for scope in capability.all_referenced
    )
    if not ceiling and declared_scopes:
        diagnostics.append(
            Diagnostic(
                code="ACC_RUN_SCOPE_CEILING_EMPTY",
                severity="warning",
                message=(
                    "The deployment scope ceiling is empty while the Pack declares scoped "
                    "capabilities."
                ),
                path=None,
                pointer=None,
            )
        )
    for capability in report.capabilities:
        status = capability.deployment.status
        if status is CallabilityStatus.DENIED:
            diagnostics.append(
                Diagnostic(
                    code="ACC_RUN_CAPABILITY_SCOPE_DENIED",
                    severity="error" if strict else "warning",
                    message=(
                        f"Capability {capability.capability_id} has no callable path under the "
                        "deployment scope ceiling."
                    ),
                    path=None,
                    pointer=None,
                )
            )
        elif status is CallabilityStatus.CONDITIONAL:
            diagnostics.append(
                Diagnostic(
                    code="ACC_RUN_CAPABILITY_SCOPE_CONDITIONAL",
                    severity="warning",
                    message=(
                        f"Capability {capability.capability_id} is only conditionally callable "
                        "under the deployment scope ceiling."
                    ),
                    path=None,
                    pointer=None,
                )
            )

    counts = {
        status.value: 0 for status in CallabilityStatus if status is not CallabilityStatus.UNKNOWN
    }
    for capability in report.capabilities:
        counts[capability.deployment.status.value] += 1
    analysis = {
        "deployment_scope_ceiling": sorted(ceiling),
        "summary": counts,
        "capabilities": [
            {
                "capability": capability.capability_id,
                "always_required": sorted(capability.always_required),
                "conditionally_required": sorted(capability.conditionally_required),
                "all_referenced": sorted(capability.all_referenced),
                "completion_alternatives": [
                    sorted(alternative) for alternative in capability.completion_alternatives
                ],
                "deployment": _dimension_json(capability.deployment),
                "user": _dimension_json(capability.user),
                "effective": _dimension_json(capability.effective),
            }
            for capability in report.capabilities
        ],
    }
    return RunScopeConfiguration(
        deployment_scope_ceiling=ceiling,
        analysis=analysis,
        diagnostics=tuple(diagnostics),
    )


def _dimension_json(dimension: _Dimension) -> dict[str, Any]:
    available = dimension.available_scopes
    return {
        "status": str(dimension.status),
        "available_scopes": None if available is None else sorted(available),
        "missing_always": sorted(dimension.missing_always),
        "missing_conditional": sorted(dimension.missing_conditional),
        "unmet_alternatives": [sorted(alternative) for alternative in dimension.unmet_alternatives],
    }


__all__ = ["RunScopeConfiguration", "analyze_run_scope_configuration"]
