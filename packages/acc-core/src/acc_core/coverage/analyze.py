"""Deterministic, side-effect-free capability coverage analysis."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Literal

from acc_core.contracts.fidelity import analyze_operation_schema_fidelity
from acc_core.coverage.interaction import analyze_interaction_coverage
from acc_core.coverage.models import (
    ClientAdapterObservation,
    CompositionCoverage,
    ConstructabilityCoverage,
    CoverageReportV2,
    DiscoverabilityEdge,
    DiscoverabilityGraphCoverage,
    LiveObservation,
    LiveObservationCoverage,
    OperationTraceCoverage,
    OutputBudgetCoverage,
    RouteDispositionCoverage,
    ScenarioCoverage,
    SchemaFidelityCoverage,
)
from acc_core.diagnostics import Diagnostic
from acc_core.models import (
    BranchStep,
    CallStep,
    ForeachStep,
    ParallelStep,
    ReadCapabilityV2,
    WorkflowStep,
)
from acc_core.quality.analyze import analyze_capability_quality
from acc_core.quality.output_size import analyze_output_budget, estimate_output_size
from acc_core.scope import ScopeInventory
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


def _normalized_capabilities(report: ValidationReport) -> dict[str, ReadCapabilityV2]:
    normalized: dict[str, ReadCapabilityV2] = {}
    for capability_id, capability in report.capabilities.items():
        if isinstance(capability, ReadCapabilityV2):
            normalized[capability_id] = capability
            continue
        workflow = [*capability.preview_workflow, *capability.commit_workflow]
        normalized[capability_id] = ReadCapabilityV2.model_construct(
            schema_version="2",
            kind="read",
            id=capability.id,
            title=capability.title,
            description=capability.description,
            input_schema=capability.input_schema,
            output_schema=capability.output_schema,
            workflow=workflow,
            policy=capability.policy,
            evals=capability.evals,
        )
    return normalized


def _route_disposition(inventory: ScopeInventory) -> RouteDispositionCoverage:
    def identifiers(disposition: str) -> list[str]:
        return sorted(route.id for route in inventory.routes if route.disposition == disposition)

    return RouteDispositionCoverage(
        eligible_route_ids=sorted(
            route.id for route in inventory.routes if route.eligibility == "eligible"
        ),
        planned=identifiers("planned"),
        composed=identifiers("composed"),
        excluded=identifiers("excluded"),
        blocked_on_evidence=identifiers("blocked_on_evidence"),
        out_of_scope=identifiers("out_of_scope"),
    )


def _operation_trace(
    report: ValidationReport,
    inventory: ScopeInventory,
    capabilities: dict[str, ReadCapabilityV2],
) -> OperationTraceCoverage:
    dependencies = {
        capability_id: _called_operations(capability.workflow)
        for capability_id, capability in capabilities.items()
    }
    traced: list[str] = []
    broken: list[str] = []
    referenced_operations: set[str] = set()
    for route in sorted(inventory.routes, key=lambda item: item.id):
        if route.disposition not in {"planned", "composed"}:
            continue
        operation_id = route.operation_id
        operation = report.operations.get(operation_id) if operation_id is not None else None
        has_operation = operation is not None
        has_exact_http_mapping = (
            operation is not None
            and operation.http.method == route.method
            and operation.http.path == route.path
            and operation.kind == route.kind
            and operation.http.safety.effect == route.effect
        )
        if operation_id is not None and has_exact_http_mapping:
            referenced_operations.add(operation_id)
        existing_capabilities = [
            capability_id for capability_id in route.capability_ids if capability_id in capabilities
        ]
        has_call_trace = operation_id is not None and any(
            operation_id in dependencies[capability_id] for capability_id in existing_capabilities
        )
        all_capabilities_exist = len(existing_capabilities) == len(route.capability_ids)
        target = (
            traced
            if has_operation
            and has_exact_http_mapping
            and all_capabilities_exist
            and has_call_trace
            else broken
        )
        target.append(route.id)
    return OperationTraceCoverage(
        traced_route_ids=traced,
        broken_route_ids=broken,
        operations_without_routes=sorted(set(report.operations) - referenced_operations),
    )


def _scenario_coverage(
    report: ValidationReport,
    capabilities: dict[str, ReadCapabilityV2],
) -> ScenarioCoverage:
    with_success: list[str] = []
    with_negative: list[str] = []
    for capability_id, capability in sorted(capabilities.items()):
        linked = [
            report.evals[eval_id]
            for eval_id in capability.evals
            if eval_id in report.evals and report.evals[eval_id].capability == capability_id
        ]
        if any(item.expected_output_schema is not None for item in linked):
            with_success.append(capability_id)
        if any(item.expected_error is not None for item in linked):
            with_negative.append(capability_id)
    capability_ids = set(capabilities)
    return ScenarioCoverage(
        with_success=with_success,
        with_negative=with_negative,
        without_success=sorted(capability_ids - set(with_success)),
        without_negative=sorted(capability_ids - set(with_negative)),
    )


def _quality_axes(
    report: ValidationReport,
    capabilities: dict[str, ReadCapabilityV2],
    *,
    operation_budget: int,
) -> tuple[
    ConstructabilityCoverage,
    DiscoverabilityGraphCoverage,
    CompositionCoverage,
]:
    analysis = analyze_capability_quality(
        capabilities,
        report.capability_quality,
        operation_budget=operation_budget,
    )
    constructability_codes = {
        "ACC_CAPABILITY_REQUIRED_SELECTOR_UNDISCOVERABLE",
        "ACC_COVERAGE_DISCOVERY_DEAD_END",
    }
    constructability_diagnostics = [
        item for item in analysis.diagnostics if item.code in constructability_codes
    ]
    composition_diagnostics = [
        item for item in analysis.diagnostics if item.code not in constructability_codes
    ]
    constructability = ConstructabilityCoverage(
        entrypoints=list(analysis.graph.entrypoints),
        reachable=list(analysis.graph.reachable),
        dead_ends=list(analysis.graph.dead_ends),
        diagnostics=constructability_diagnostics,
    )
    discoverability = DiscoverabilityGraphCoverage(
        nodes=list(analysis.graph.nodes),
        edges=[
            DiscoverabilityEdge(
                producer=edge.producer,
                consumer=edge.consumer,
                input_name=edge.input_name,
            )
            for edge in analysis.graph.edges
        ],
    )
    composition = CompositionCoverage(
        components=analysis.composition_components,
        diagnostics=composition_diagnostics,
    )
    return constructability, discoverability, composition


def _schema_fidelity(report: ValidationReport) -> SchemaFidelityCoverage:
    analyzed = sorted(set(report.operations) & set(report.source_contracts))
    diagnostics = [
        diagnostic
        for operation_id in analyzed
        for diagnostic in analyze_operation_schema_fidelity(
            report.operations[operation_id],
            report.source_contracts[operation_id],
            operation_path=report.operation_paths.get(operation_id),
        )
    ]
    diagnostics.sort(key=lambda item: (item.path or "", item.pointer or "", item.code))
    return SchemaFidelityCoverage(
        analyzed_operation_ids=analyzed,
        unanalyzed_operation_ids=sorted(set(report.operations) - set(analyzed)),
        diagnostics=diagnostics,
    )


def _output_budget(
    report: ValidationReport,
    capabilities: dict[str, ReadCapabilityV2],
) -> OutputBudgetCoverage:
    statuses: dict[
        str,
        Literal["proven_bounded", "unknown", "exceeds_budget"],
    ] = {}
    diagnostics: list[Diagnostic] = []
    for capability_id, capability in sorted(capabilities.items()):
        quality = report.capability_quality.get(capability_id)
        if quality is None:
            continue
        estimate = estimate_output_size(capability.output_schema)
        if estimate.status == "unknown":
            statuses[capability_id] = "unknown"
        elif (
            estimate.max_bytes is not None and estimate.max_bytes > quality.output_budget.max_bytes
        ):
            statuses[capability_id] = "exceeds_budget"
        else:
            statuses[capability_id] = "proven_bounded"
        diagnostics.extend(
            analyze_output_budget(
                capability_id,
                capability.output_schema,
                quality.output_budget,
                capability_path=None,
                quality_path=report.capability_quality_paths.get(capability_id),
            )
        )
    diagnostics.sort(key=lambda item: (item.path or "", item.pointer or "", item.code))
    return OutputBudgetCoverage(
        status_by_capability=statuses,
        diagnostics=diagnostics,
    )


def _live_observations(
    capability_ids: set[str],
    observations: Sequence[LiveObservation],
) -> LiveObservationCoverage:
    ordered = sorted(observations, key=lambda item: item.capability_id)
    observed_ids = {item.capability_id for item in ordered}
    unknown = observed_ids - capability_ids
    if unknown:
        raise ValueError(
            "live observations reference unknown capabilities: " + ", ".join(sorted(unknown))
        )
    unobserved = sorted(capability_ids - observed_ids)
    status: Literal["not_observed", "partially_observed", "observed"]
    if not ordered:
        status = "not_observed"
    elif unobserved:
        status = "partially_observed"
    else:
        status = "observed"
    return LiveObservationCoverage(
        status=status,
        observations=ordered,
        unobserved_capability_ids=unobserved,
    )


def analyze_coverage(
    report: ValidationReport,
    scope_inventory: ScopeInventory,
    *,
    live_observations: Sequence[LiveObservation] = (),
    client_adapter_observations: Sequence[ClientAdapterObservation] = (),
    operation_budget: int = 8,
) -> CoverageReportV2:
    """Return independent evidence axes without converting route closure into usability."""

    capabilities = _normalized_capabilities(report)
    constructability, discoverability, composition = _quality_axes(
        report,
        capabilities,
        operation_budget=operation_budget,
    )
    (
        surface_disposition,
        interaction_trace,
        input_binding_fidelity,
        default_provenance,
        option_resolution,
        condition_coverage,
        related_data_graph,
        state_scenarios,
        presentation_projection,
        client_adapter_evidence,
    ) = analyze_interaction_coverage(
        report,
        scope_inventory,
        client_adapter_observations=client_adapter_observations,
    )
    return CoverageReportV2(
        coverage_version="2",
        route_disposition=_route_disposition(scope_inventory),
        operation_trace=_operation_trace(report, scope_inventory, capabilities),
        scenario_coverage=_scenario_coverage(report, capabilities),
        constructability=constructability,
        discoverability_graph=discoverability,
        composition=composition,
        schema_fidelity=_schema_fidelity(report),
        output_budget=_output_budget(report, capabilities),
        live_observations=_live_observations(set(capabilities), live_observations),
        surface_disposition=surface_disposition,
        interaction_trace=interaction_trace,
        input_binding_fidelity=input_binding_fidelity,
        default_provenance=default_provenance,
        option_resolution=option_resolution,
        condition_coverage=condition_coverage,
        related_data_graph=related_data_graph,
        state_scenarios=state_scenarios,
        presentation_projection=presentation_projection,
        client_adapter_evidence=client_adapter_evidence,
    )


__all__ = ["analyze_coverage"]
