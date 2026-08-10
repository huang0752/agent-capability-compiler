"""Strict models for the independent current Coverage quality axes."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from acc_core.diagnostics import Diagnostic
from acc_core.domains import DomainStatus, VerificationLevel
from acc_core.models import NonEmptyString, StrictModel

RawSha256Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


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


type InteractionAxisStatus = Literal["not_declared", "explicit_none", "analyzed"]


class SurfaceDispositionCoverage(StrictModel):
    """Source surfaces and explicit interaction adoption dispositions."""

    status: InteractionAxisStatus
    surface_ids: list[NonEmptyString]
    adopted_interaction_ids: list[NonEmptyString]
    omitted_interaction_ids: list[NonEmptyString]
    unclassified_interaction_ids: list[NonEmptyString]


class InteractionTraceCoverage(StrictModel):
    """Bidirectional UI interaction to Scope route trace facts only."""

    status: InteractionAxisStatus
    traced_interaction_ids: list[NonEmptyString]
    broken_interaction_ids: list[NonEmptyString]
    client_only_interaction_ids: list[NonEmptyString]


class InteractionFidelityAxisCoverage(StrictModel):
    """One independent declared/proven/unproven interaction fact family."""

    status: InteractionAxisStatus
    declared_interaction_ids: list[NonEmptyString]
    proven_interaction_ids: list[NonEmptyString]
    unproven_interaction_ids: list[NonEmptyString]


class RelatedDataEdgeCoverage(StrictModel):
    producer: NonEmptyString
    consumer: NonEmptyString
    interaction_id: NonEmptyString


class RelatedDataGraphCoverage(InteractionFidelityAxisCoverage):
    """Related-data dependency facts without implying runtime availability."""

    nodes: list[NonEmptyString]
    edges: list[RelatedDataEdgeCoverage]


class StateScenarioCoverage(StrictModel):
    """Required scenarios remain separate from headless execution evidence."""

    status: InteractionAxisStatus
    required_scenario_ids: list[NonEmptyString]
    headless_verified_interaction_ids: list[NonEmptyString]
    not_verified_interaction_ids: list[NonEmptyString]


class ClientAdapterEvidenceCoverage(StrictModel):
    """Client-adapter evidence is never inferred from source connectivity."""

    status: Literal[
        "not_declared",
        "explicit_none",
        "not_verified",
        "client_adapter_verified",
    ]
    verified_interaction_ids: list[NonEmptyString]
    not_verified_interaction_ids: list[NonEmptyString]
    verified_adapter_ids: list[NonEmptyString]


class ClientAdapterObservation(StrictModel):
    """Digest-bound, framework-neutral adapter conformance evidence."""

    interaction_digest: RawSha256Digest
    adapter_id: NonEmptyString
    verified_interaction_ids: list[NonEmptyString]
    verified_scenario_ids: list[NonEmptyString]
    evidence_sources: Annotated[list[NonEmptyString], Field(min_length=1)]
    required_scenarios_passed: bool

    @field_validator(
        "verified_interaction_ids",
        "verified_scenario_ids",
        "evidence_sources",
    )
    @classmethod
    def validate_sorted_unique_values(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("client adapter observation lists must be sorted and unique")
        return value


type DomainAxisStatus = Literal["not_declared", "analyzed"]


class DomainDispositionCoverage(StrictModel):
    """User dispositions remain separate from evidence-derived blockers."""

    status: DomainAxisStatus
    status_by_domain: dict[NonEmptyString, DomainStatus]
    accepted_candidate_ids: list[NonEmptyString]
    deferred_candidate_ids: list[NonEmptyString]
    rejected_candidate_ids: list[NonEmptyString]
    blocked_candidate_ids: list[NonEmptyString]


class BusinessGoalCoverage(StrictModel):
    """Declared business policy facts without source authorization semantics."""

    status: DomainAxisStatus
    goals_by_domain: dict[NonEmptyString, list[NonEmptyString]]
    excluded_intents_by_domain: dict[NonEmptyString, list[NonEmptyString]]
    approval_required_by_domain: dict[NonEmptyString, list[NonEmptyString]]
    domains_without_decisions: list[NonEmptyString]


class CandidateClassificationCoverage(StrictModel):
    """Candidate denominator classification independent of route closure."""

    status: DomainAxisStatus
    read_candidate_ids: list[NonEmptyString]
    action_candidate_ids: list[NonEmptyString]
    unknown_candidate_ids: list[NonEmptyString]
    unclassified_candidate_ids: list[NonEmptyString]


class CandidateEvidenceCoverage(StrictModel):
    """One evidence-derived candidate fact family without an aggregate result."""

    status: DomainAxisStatus
    proven_candidate_ids: list[NonEmptyString]
    unproven_candidate_ids: list[NonEmptyString]
    not_applicable_candidate_ids: list[NonEmptyString]


class IdentityAuthorizationCoverage(StrictModel):
    """Upstream authorization, identity, and context-isolation evidence state."""

    status: DomainAxisStatus
    source_final_candidate_ids: list[NonEmptyString]
    unknown_candidate_ids: list[NonEmptyString]
    contradicted_candidate_ids: list[NonEmptyString]
    stale_candidate_ids: list[NonEmptyString]


class VerificationCoverage(StrictModel):
    """Raw verification levels; higher labels never upgrade independent safety axes."""

    status: DomainAxisStatus
    level_by_candidate: dict[NonEmptyString, VerificationLevel]


class CrossDomainDependencyEdge(StrictModel):
    domain_id: NonEmptyString
    dependency_domain_id: NonEmptyString
    status: Literal["resolved", "unresolved", "stale"]


class CrossDomainDependencyCoverage(StrictModel):
    """Dependency resolution facts derived from exact DomainDecision references."""

    status: DomainAxisStatus
    edges: list[CrossDomainDependencyEdge]
    resolved_domain_ids: list[NonEmptyString]
    unresolved_domain_ids: list[NonEmptyString]
    stale_domain_ids: list[NonEmptyString]


class UserDecisionTraceCoverage(StrictModel):
    """Confirmation and disposition facts without treating deferral as a safety failure."""

    status: DomainAxisStatus
    confirmed_domain_ids: list[NonEmptyString]
    pending_domain_ids: list[NonEmptyString]
    deferred_candidate_ids: list[NonEmptyString]


class DomainCoverageAxes(StrictModel):
    """Twelve independent Domain and Action axes with no aggregate status."""

    domain_disposition: DomainDispositionCoverage
    business_goals: BusinessGoalCoverage
    candidate_classification: CandidateClassificationCoverage
    semantics_provenance: CandidateEvidenceCoverage
    identity_authorization: IdentityAuthorizationCoverage
    action_lifecycle: CandidateEvidenceCoverage
    conflict_control: CandidateEvidenceCoverage
    idempotency: CandidateEvidenceCoverage
    outcome_resolution: CandidateEvidenceCoverage
    verification: VerificationCoverage
    cross_domain_dependency: CrossDomainDependencyCoverage
    user_decision_trace: UserDecisionTraceCoverage


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
    domain_disposition: DomainDispositionCoverage
    business_goals: BusinessGoalCoverage
    candidate_classification: CandidateClassificationCoverage
    semantics_provenance: CandidateEvidenceCoverage
    identity_authorization: IdentityAuthorizationCoverage
    action_lifecycle: CandidateEvidenceCoverage
    conflict_control: CandidateEvidenceCoverage
    idempotency: CandidateEvidenceCoverage
    outcome_resolution: CandidateEvidenceCoverage
    verification: VerificationCoverage
    cross_domain_dependency: CrossDomainDependencyCoverage
    user_decision_trace: UserDecisionTraceCoverage
    surface_disposition: SurfaceDispositionCoverage
    interaction_trace: InteractionTraceCoverage
    input_binding_fidelity: InteractionFidelityAxisCoverage
    default_provenance: InteractionFidelityAxisCoverage
    option_resolution: InteractionFidelityAxisCoverage
    condition_coverage: InteractionFidelityAxisCoverage
    related_data_graph: RelatedDataGraphCoverage
    state_scenarios: StateScenarioCoverage
    presentation_projection: InteractionFidelityAxisCoverage
    client_adapter_evidence: ClientAdapterEvidenceCoverage


__all__ = [
    "BusinessGoalCoverage",
    "CandidateClassificationCoverage",
    "CandidateEvidenceCoverage",
    "ClientAdapterEvidenceCoverage",
    "ClientAdapterObservation",
    "CompositionCoverage",
    "ConstructabilityCoverage",
    "CoverageReportV2",
    "CrossDomainDependencyCoverage",
    "CrossDomainDependencyEdge",
    "DiscoverabilityEdge",
    "DiscoverabilityGraphCoverage",
    "DomainAxisStatus",
    "DomainCoverageAxes",
    "DomainDispositionCoverage",
    "IdentityAuthorizationCoverage",
    "InteractionFidelityAxisCoverage",
    "InteractionTraceCoverage",
    "LiveObservation",
    "LiveObservationCoverage",
    "OperationTraceCoverage",
    "OutputBudgetCoverage",
    "RelatedDataEdgeCoverage",
    "RelatedDataGraphCoverage",
    "RouteDispositionCoverage",
    "ScenarioCoverage",
    "SchemaFidelityCoverage",
    "StateScenarioCoverage",
    "SurfaceDispositionCoverage",
    "UserDecisionTraceCoverage",
    "VerificationCoverage",
]
