"""Strict models for the independent current Coverage quality axes."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from acc_core.diagnostics import Diagnostic
from acc_core.models import NonEmptyString, StrictModel


class RouteDispositionCoverage(StrictModel):
    """Exact route disposition facts; this axis does not claim runtime usability."""

    eligible_route_ids: list[NonEmptyString]
    planned: list[NonEmptyString]
    composed: list[NonEmptyString]
    excluded: list[NonEmptyString]
    blocked_on_evidence: list[NonEmptyString]
    out_of_scope: list[NonEmptyString]


class OperationTraceCoverage(StrictModel):
    """Trace source routes to compiled Operations and calling Capabilities."""

    traced_route_ids: list[NonEmptyString]
    broken_route_ids: list[NonEmptyString]
    operations_without_routes: list[NonEmptyString]


class ScenarioCoverage(StrictModel):
    """Report linked success and negative scenarios independently."""

    with_success: list[NonEmptyString]
    with_negative: list[NonEmptyString]
    without_success: list[NonEmptyString]
    without_negative: list[NonEmptyString]


class ConstructabilityCoverage(StrictModel):
    """Capability reachability from caller-constructible entrypoints."""

    entrypoints: list[NonEmptyString]
    reachable: list[NonEmptyString]
    dead_ends: list[NonEmptyString]
    diagnostics: list[Diagnostic]


class DiscoverabilityEdge(StrictModel):
    producer: NonEmptyString
    consumer: NonEmptyString
    input_name: NonEmptyString


class DiscoverabilityGraphCoverage(StrictModel):
    """Declared cross-Capability producer edges, without a synthetic score."""

    nodes: list[NonEmptyString]
    edges: list[DiscoverabilityEdge]


class CompositionCoverage(StrictModel):
    """Independent workflow component counts and composition diagnostics."""

    components: dict[NonEmptyString, Annotated[int, Field(ge=0)]]
    diagnostics: list[Diagnostic]


class SchemaFidelityCoverage(StrictModel):
    """Evidence-backed schema comparison results."""

    analyzed_operation_ids: list[NonEmptyString]
    unanalyzed_operation_ids: list[NonEmptyString]
    diagnostics: list[Diagnostic]


class OutputBudgetCoverage(StrictModel):
    """Static output-bound state, separate from observed response sizes."""

    status_by_capability: dict[
        NonEmptyString,
        Literal["proven_bounded", "unknown", "exceeds_budget"],
    ]
    diagnostics: list[Diagnostic]


class LiveObservation(StrictModel):
    """Aggregated, non-authoritative runtime response-size evidence."""

    capability_id: NonEmptyString
    verification_level: Literal[
        "contract_verified",
        "offline_candidate",
        "gateway_offline_verified",
        "source_connected_verified",
    ]
    sample_count: Annotated[int, Field(ge=1)]
    response_bytes_p50: Annotated[int, Field(ge=0)]
    response_bytes_p95: Annotated[int, Field(ge=0)]
    response_bytes_max: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_percentiles(self) -> LiveObservation:
        if not self.response_bytes_p50 <= self.response_bytes_p95 <= self.response_bytes_max:
            raise ValueError("response byte observations must satisfy p50 <= p95 <= max")
        return self


class LiveObservationCoverage(StrictModel):
    """Availability of live evidence; observations never become static schema bounds."""

    status: Literal["not_observed", "partially_observed", "observed"]
    observations: list[LiveObservation]
    unobserved_capability_ids: list[NonEmptyString]

    @field_validator("observations")
    @classmethod
    def validate_unique_capabilities(cls, value: list[LiveObservation]) -> list[LiveObservation]:
        identifiers = [item.capability_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("live observations must contain at most one item per capability")
        if identifiers != sorted(identifiers):
            raise ValueError("live observations must use capability_id order")
        return value


class CoverageReportV2(StrictModel):
    """Multi-axis coverage report with deliberately no aggregate score."""

    coverage_version: Literal["2"]
    route_disposition: RouteDispositionCoverage
    operation_trace: OperationTraceCoverage
    scenario_coverage: ScenarioCoverage
    constructability: ConstructabilityCoverage
    discoverability_graph: DiscoverabilityGraphCoverage
    composition: CompositionCoverage
    schema_fidelity: SchemaFidelityCoverage
    output_budget: OutputBudgetCoverage
    live_observations: LiveObservationCoverage


__all__ = [
    "CompositionCoverage",
    "ConstructabilityCoverage",
    "CoverageReportV2",
    "DiscoverabilityEdge",
    "DiscoverabilityGraphCoverage",
    "LiveObservation",
    "LiveObservationCoverage",
    "OperationTraceCoverage",
    "OutputBudgetCoverage",
    "RouteDispositionCoverage",
    "ScenarioCoverage",
    "SchemaFidelityCoverage",
]
