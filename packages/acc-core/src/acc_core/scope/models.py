"""Platform-neutral source-route inventory models."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from acc_core.models import NonEmptyString, StrictModel

SUPPORTED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})


class ExclusionApproval(StrictModel):
    """Explicit approval for exact excluded route identifiers."""

    approved_route_ids: list[NonEmptyString] = Field(default_factory=list)
    approval_text: NonEmptyString | None = None


class ScopeSelection(StrictModel):
    """Declared route-discovery scope."""

    mode: Literal["pilot", "domain_complete", "system_complete"]
    user_confirmation: NonEmptyString | None = None
    selected_domains: list[NonEmptyString] = Field(default_factory=list)
    exclusion_approval: ExclusionApproval = Field(default_factory=ExclusionApproval)


class ScopeDiscovery(StrictModel):
    """Evidence sources used to establish the route denominator."""

    source_commit: NonEmptyString
    methods: list[Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]]
    include_paths: list[NonEmptyString]
    evidence_sources: list[NonEmptyString]


class ScopeDomain(StrictModel):
    """A discovered source-system domain."""

    id: NonEmptyString
    status: Literal["selected", "excluded", "blocked_on_evidence", "out_of_scope"] | None = None


class ExclusionRule(StrictModel):
    """Shared authority for an exact set of excluded routes."""

    id: NonEmptyString
    category: Literal[
        "binary_or_download",
        "sensitive_configuration",
        "alternate_identity_boundary",
        "unsafe_dynamic_authorization",
        "unavailable_or_disabled",
        "operational_polling",
        "duplicate_or_subsumed",
        "low_business_value",
    ]
    route_ids: list[NonEmptyString]
    rationale: NonEmptyString
    evidence_sources: list[NonEmptyString]


class ScopeRoute(StrictModel):
    """One discovered source route with evidence-declared effect and disposition."""

    id: NonEmptyString
    domain: NonEmptyString
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
    kind: Literal["unknown", "read", "action"]
    effect: Literal["unknown", "read", "create", "update", "delete", "transition", "execute"]
    path: NonEmptyString
    evidence_sources: list[NonEmptyString]
    usage_evidence_sources: list[NonEmptyString] = Field(default_factory=list)
    interaction_ids: list[NonEmptyString] = Field(default_factory=list)
    eligibility: Literal["undetermined", "eligible", "ineligible"]
    disposition: Literal["planned", "composed", "excluded", "blocked_on_evidence", "out_of_scope"]
    operation_id: NonEmptyString | None = None
    capability_ids: list[NonEmptyString] = Field(default_factory=list)
    candidate_id: NonEmptyString | None = None
    reason: NonEmptyString | None = None
    exclusion_rule_id: NonEmptyString | None = None
    exclusion_decision: dict[str, object] | None = None

    @field_validator("interaction_ids")
    @classmethod
    def validate_interaction_ids(cls, value: list[str]) -> list[str]:
        """Keep interaction cross-references deterministic without interpreting UI semantics."""

        if len(value) != len(set(value)) or value != sorted(value):
            raise ValueError("interaction_ids entries must be unique and sorted")
        return value

    @model_validator(mode="after")
    def validate_planned_trace(self) -> ScopeRoute:
        """Require executable trace references for planned/composed routes."""

        if self.disposition in {"planned", "composed"}:
            if self.eligibility != "eligible" or self.kind == "unknown":
                raise ValueError("planned or composed routes must be eligible and known")
            if self.operation_id is None:
                raise ValueError("operation_id is required for planned or composed routes")
            if not self.capability_ids:
                raise ValueError("capability_ids are required for planned or composed routes")
        elif self.operation_id is not None or self.capability_ids:
            raise ValueError(
                "only planned or composed routes may reference Operations or Capabilities"
            )
        if self.kind == "unknown":
            if (
                self.effect != "unknown"
                or self.eligibility != "undetermined"
                or self.disposition != "blocked_on_evidence"
            ):
                raise ValueError(
                    "unknown routes require effect=unknown, eligibility=undetermined, "
                    "and disposition=blocked_on_evidence"
                )
            if self.candidate_id is None:
                raise ValueError("candidate_id is required for unknown routes")
        elif (self.kind == "read" and self.effect != "read") or (
            self.kind == "action"
            and self.effect
            not in {
                "create",
                "update",
                "delete",
                "transition",
                "execute",
            }
        ):
            raise ValueError(
                "read routes require effect=read; action routes require a mutation effect"
            )
        if self.eligibility == "undetermined" and self.disposition != "blocked_on_evidence":
            raise ValueError("undetermined routes must be blocked_on_evidence")
        if self.disposition == "blocked_on_evidence" and self.eligibility != "undetermined":
            raise ValueError("blocked_on_evidence routes must be undetermined")
        return self


class ScopeSummary(StrictModel):
    """Deterministic counters derived from routes."""

    discovered_routes: int = Field(ge=0)
    eligible_routes: int = Field(ge=0)
    planned: int = Field(ge=0)
    composed: int = Field(ge=0)
    excluded: int = Field(ge=0)
    blocked_on_evidence: int = Field(ge=0)
    out_of_scope: int = Field(ge=0)
    unresolved: int = Field(ge=0)


class ScopeInventory(StrictModel):
    """Typed source-route denominator shared by Core and the Engineer Skill."""

    schema_version: Literal["2"]
    scope: ScopeSelection
    discovery: ScopeDiscovery | None = None
    domains: list[ScopeDomain]
    exclusion_rules: list[ExclusionRule] = Field(default_factory=list)
    routes: list[ScopeRoute]
    summary: ScopeSummary

    @model_validator(mode="after")
    def validate_summary(self) -> ScopeInventory:
        """Reject hand-maintained counters that diverge from route facts."""

        if self.scope.mode in {"domain_complete", "system_complete"}:
            if self.discovery is None:
                raise ValueError("complete scope requires discovery metadata")
            if len(self.discovery.methods) != len(set(self.discovery.methods)):
                raise ValueError("complete scope discovery methods must be unique")
            if set(self.discovery.methods) != SUPPORTED_METHODS:
                raise ValueError("complete scope discovery must include every supported method")

        expected = {
            "discovered_routes": len(self.routes),
            "eligible_routes": sum(route.eligibility == "eligible" for route in self.routes),
            "planned": sum(route.disposition == "planned" for route in self.routes),
            "composed": sum(route.disposition == "composed" for route in self.routes),
            "excluded": sum(route.disposition == "excluded" for route in self.routes),
            "blocked_on_evidence": sum(
                route.disposition == "blocked_on_evidence" for route in self.routes
            ),
            "out_of_scope": sum(route.disposition == "out_of_scope" for route in self.routes),
            "unresolved": sum(route.eligibility == "undetermined" for route in self.routes),
        }
        if self.summary.model_dump() != expected:
            raise ValueError("summary must exactly match the route inventory")
        return self


__all__ = [
    "SUPPORTED_METHODS",
    "ExclusionApproval",
    "ExclusionRule",
    "ScopeDiscovery",
    "ScopeDomain",
    "ScopeInventory",
    "ScopeRoute",
    "ScopeSelection",
    "ScopeSummary",
]
