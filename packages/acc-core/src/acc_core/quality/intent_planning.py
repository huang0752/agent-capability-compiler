"""Deterministic, fail-closed audit for AI-authored intent plans.

The planner is deliberately outside this module: an AI may propose business
boundaries, but this audit only accepts boundaries that are traceable to the
route denominator and compatible evidence claims.  No target tool count is
encoded here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from acc_core.diagnostics import Diagnostic
from acc_core.domains import CapabilityCandidate, CapabilityCandidateLedger, DomainMap
from acc_core.domains.analyze import analyze_candidate_readiness
from acc_core.intents import DomainIntentCandidate, IntentPlan
from acc_core.models import Capability
from acc_core.quality.models import CapabilityQuality
from acc_core.quality.portfolio import ToolPortfolioAnalysis, analyze_tool_portfolio
from acc_core.scope import ScopeInventory


@dataclass(frozen=True, slots=True)
class RouteDenominatorAccounting:
    discovered: int
    assigned: tuple[str, ...]
    unassigned: tuple[str, ...]
    multiply_assigned: tuple[str, ...]
    materializable: tuple[str, ...]
    blocked_on_evidence: tuple[str, ...]
    excluded: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DomainPlanningSuggestion:
    domain_id: str
    dependency_domain_ids: tuple[str, ...]
    ready_candidate_ids: tuple[str, ...]
    blocked_candidate_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IntentPlanningAnalysis:
    route_accounting: RouteDenominatorAccounting
    orphan_candidate_ids: tuple[str, ...]
    orphan_capability_ids: tuple[str, ...]
    fragmented_business_intents: dict[str, tuple[str, ...]]
    suggested_next_domains: tuple[DomainPlanningSuggestion, ...]
    tool_portfolio: ToolPortfolioAnalysis
    diagnostics: tuple[Diagnostic, ...]

    @property
    def accepted(self) -> bool:
        """Return whether the plan passed every fail-closed error gate."""

        return not any(item.severity == "error" for item in self.diagnostics)


def _diagnostic(
    code: str,
    message: str,
    *,
    path: str = "intent-plan",
    pointer: str | None = None,
    severity: Literal["error", "warning", "info"] = "error",
) -> Diagnostic:
    return Diagnostic(code=code, severity=severity, message=message, path=path, pointer=pointer)


def _claim_signature(candidate: CapabilityCandidate, axis: str) -> tuple[str, tuple[str, ...]]:
    claim = getattr(candidate.claims, axis)
    return claim.status, tuple(claim.evidence_refs)


def _compatibility_signature(candidate: CapabilityCandidate) -> tuple[object, ...]:
    return (
        candidate.kind_claim,
        candidate.effect_claim,
        _claim_signature(candidate, "authorization_boundary"),
        _claim_signature(candidate, "risk"),
        _claim_signature(candidate, "approval"),
        _claim_signature(candidate, "retry"),
        _claim_signature(candidate, "conflict_control"),
        _claim_signature(candidate, "idempotency"),
        _claim_signature(candidate, "outcome_resolution"),
        _claim_signature(candidate, "lifecycle"),
    )


def _intent_candidates(
    intent: DomainIntentCandidate,
    candidates: Mapping[str, CapabilityCandidate],
) -> tuple[CapabilityCandidate, ...]:
    return tuple(
        candidates[candidate_id]
        for candidate_id in intent.candidate_ids
        if candidate_id in candidates
    )


def _suggest_domains(
    domain_map: DomainMap,
    candidate_index: Mapping[str, CapabilityCandidate],
) -> tuple[DomainPlanningSuggestion, ...]:
    completed = {domain.id for domain in domain_map.domains if domain.status == "completed"}
    by_id = {domain.id: domain for domain in domain_map.domains}
    order = domain_map.preferred_order or sorted(by_id)
    suggestions: list[DomainPlanningSuggestion] = []
    for domain_id in order:
        domain = by_id[domain_id]
        if domain.status == "completed" or not set(domain.dependency_domain_ids) <= completed:
            continue
        ready: list[str] = []
        blocked: list[str] = []
        for candidate_id in domain.candidate_ids:
            candidate = candidate_index.get(candidate_id)
            if candidate is None or analyze_candidate_readiness(candidate).blocking_gaps:
                blocked.append(candidate_id)
            else:
                ready.append(candidate_id)
        suggestions.append(
            DomainPlanningSuggestion(
                domain_id,
                tuple(domain.dependency_domain_ids),
                tuple(ready),
                tuple(blocked),
            )
        )
    return tuple(suggestions)


def audit_intent_plan(
    *,
    scope_inventory: ScopeInventory,
    candidate_ledger: CapabilityCandidateLedger,
    domain_map: DomainMap,
    capabilities: Mapping[str, Capability],
    qualities: Mapping[str, CapabilityQuality],
    operation_dependencies: Mapping[str, Sequence[str]],
    intent_plan: IntentPlan | None = None,
) -> IntentPlanningAnalysis:
    """Audit an optional AI plan without choosing or budgeting its tool count."""

    diagnostics: list[Diagnostic] = []
    candidate_index = {candidate.id: candidate for candidate in candidate_ledger.candidates}
    domain_index = {domain.id: domain for domain in domain_map.domains}
    route_index = {route.id: route for route in scope_inventory.routes}
    proposals = tuple(intent_plan.intents if intent_plan is not None else ())

    route_assignments: Counter[str] = Counter()
    planned_candidates: set[str] = set()
    planned_capabilities: set[str] = set()
    active_by_intent: dict[str, list[str]] = defaultdict(list)
    proposal_signatures: dict[str, tuple[object, ...]] = {}
    for index, proposal in enumerate(proposals):
        pointer = f"/intents/{index}"
        route_assignments.update(proposal.route_ids)
        known_candidates = _intent_candidates(proposal, candidate_index)
        planned_candidates.update(candidate.id for candidate in known_candidates)
        traced_capabilities = set(proposal.capability_ids)
        planned_capabilities.update(traced_capabilities)
        if proposal.recommendation in {"materialize", "compose"}:
            active_by_intent[proposal.user_goal].append(proposal.id)

        if proposal.domain_id not in domain_index:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_UNKNOWN_DOMAIN",
                    "Intent proposal references an unknown domain.",
                    pointer=f"{pointer}/domain",
                )
            )
        unknown_routes = sorted(set(proposal.route_ids) - route_index.keys())
        unknown_candidates = sorted(set(proposal.candidate_ids) - candidate_index.keys())
        unknown_capabilities = sorted(set(proposal.capability_ids) - capabilities.keys())
        for suffix, values, code in (
            ("route_ids", unknown_routes, "ACC_INTENT_PLAN_UNKNOWN_ROUTE"),
            ("candidate_ids", unknown_candidates, "ACC_INTENT_PLAN_UNKNOWN_CANDIDATE"),
            ("capability_ids", unknown_capabilities, "ACC_INTENT_PLAN_UNKNOWN_CAPABILITY"),
        ):
            if values:
                diagnostics.append(
                    _diagnostic(
                        code,
                        f"Intent proposal references unknown {suffix}: {', '.join(values)}.",
                        pointer=f"{pointer}/{suffix}",
                    )
                )
        if not known_candidates and proposal.recommendation != "exclude":
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_ORPHAN_INTENT",
                    "Every intent must trace to at least one Candidate Ledger entry.",
                    pointer=pointer,
                )
            )
        if any(candidate.domain_id != proposal.domain_id for candidate in known_candidates):
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_CROSS_DOMAIN_GOD_TOOL",
                    "One intent cannot hide candidates from different domain boundaries.",
                    pointer=f"{pointer}/candidate_ids",
                )
            )
        route_domains = {
            route.domain
            for route_id in proposal.route_ids
            if (route := route_index.get(route_id)) is not None
        }
        if route_domains - {proposal.domain_id}:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_CROSS_DOMAIN_GOD_TOOL",
                    "One intent cannot hide routes from different domain boundaries.",
                    pointer=f"{pointer}/route_ids",
                )
            )
        candidate_routes = {
            route_id for candidate in known_candidates for route_id in candidate.route_ids
        }
        if proposal.recommendation != "exclude" and set(proposal.route_ids) - candidate_routes:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_ROUTE_TRACE_MISMATCH",
                    "Intent routes must be traceable to its candidate ledger entries.",
                    pointer=f"{pointer}/route_ids",
                )
            )
        if proposal.recommendation in {"blocked_on_evidence", "exclude"} and traced_capabilities:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_BLOCKED_MATERIALIZED",
                    "A blocked or excluded intent cannot retain materialized Capability traces.",
                    pointer=f"{pointer}/route_ids",
                )
            )
        scope_capabilities = {
            capability_id
            for route_id in proposal.route_ids
            if (route := route_index.get(route_id)) is not None
            for capability_id in route.capability_ids
        }
        if traced_capabilities != scope_capabilities:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_CAPABILITY_TRACE_MISMATCH",
                    "Intent capability_ids must exactly match ScopeInventory route traces.",
                    pointer=f"{pointer}/capability_ids",
                )
            )
        if proposal.recommendation in {"materialize", "compose"}:
            if not traced_capabilities:
                diagnostics.append(
                    _diagnostic(
                        "ACC_INTENT_PLAN_MATERIALIZATION_UNPROVEN",
                        "Materialized intents require Capability bindings through ScopeInventory.",
                        pointer=pointer,
                    )
                )
            blocked = [
                candidate.id
                for candidate in known_candidates
                if analyze_candidate_readiness(candidate).blocking_gaps
            ]
            if blocked:
                diagnostics.append(
                    _diagnostic(
                        "ACC_INTENT_PLAN_BLOCKED_EVIDENCE",
                        "Blocked candidates cannot be promoted by an AI plan: "
                        + ", ".join(blocked)
                        + ".",
                        pointer=f"{pointer}/route_ids",
                    )
                )
        if proposal.recommendation == "compose" and len(proposal.route_ids) < 2:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_FALSE_COMPOSITION",
                    "A composed intent must trace at least two source routes.",
                    pointer=f"{pointer}/route_ids",
                )
            )

        expected_recommendations = {
            route.disposition: (
                {"materialize", "compose"}
                if route.disposition in {"planned", "composed"}
                else {"blocked_on_evidence"}
                if route.disposition == "blocked_on_evidence"
                else {"exclude"}
            )
            for route_id in proposal.route_ids
            if (route := route_index.get(route_id)) is not None
        }
        if any(
            proposal.recommendation not in allowed for allowed in expected_recommendations.values()
        ):
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_DISPOSITION_MISMATCH",
                    "Intent recommendation must preserve each ScopeInventory disposition.",
                    pointer=f"{pointer}/recommendation",
                )
            )

        signatures = {_compatibility_signature(candidate) for candidate in known_candidates}
        if signatures:
            proposal_signatures[proposal.id] = min(signatures, key=repr)
        if len(signatures) > 1:
            declared_evidence = {item.evidence_ref for item in proposal.evidence}
            safety_evidence = (
                {
                    evidence_ref
                    for claim in (
                        proposal.action_safety.authorization,
                        proposal.action_safety.idempotency,
                        proposal.action_safety.concurrency,
                        proposal.action_safety.approval,
                        proposal.action_safety.outcome_resolution,
                    )
                    for evidence_ref in claim.evidence_refs
                }
                if proposal.action_safety is not None
                else set()
            )
            compatibility_refs = declared_evidence | safety_evidence
            kind_effect_values: set[object] = {
                (
                    candidate.kind_claim,
                    candidate.effect_claim,
                )
                for candidate in known_candidates
            }
            axis_signatures: tuple[tuple[str, tuple[str, ...], set[object]], ...] = (
                (
                    "ACC_INTENT_PLAN_PERMISSION_INCOMPATIBLE",
                    ("authorization_boundary", "identity_binding", "context_isolation"),
                    {_claim_signature(item, "authorization_boundary") for item in known_candidates},
                ),
                (
                    "ACC_INTENT_PLAN_RISK_INCOMPATIBLE",
                    ("risk",),
                    {_claim_signature(item, "risk") for item in known_candidates},
                ),
                (
                    "ACC_INTENT_PLAN_LIFECYCLE_INCOMPATIBLE",
                    (
                        "approval",
                        "retry",
                        "conflict_control",
                        "idempotency",
                        "outcome_resolution",
                        "lifecycle",
                    ),
                    {
                        tuple(
                            _claim_signature(item, axis)
                            for axis in (
                                "approval",
                                "retry",
                                "conflict_control",
                                "idempotency",
                                "outcome_resolution",
                                "lifecycle",
                            )
                        )
                        for item in known_candidates
                    },
                ),
            )
            if len(kind_effect_values) > 1:
                diagnostics.append(
                    _diagnostic(
                        "ACC_INTENT_PLAN_KIND_EFFECT_INCOMPATIBLE",
                        "An intent cannot merge different Read/Action or mutation-effect "
                        "boundaries.",
                        pointer=f"{pointer}/candidate_ids",
                    )
                )
            for code, axes, axis_values in axis_signatures:
                required_refs = {
                    evidence_ref
                    for candidate in known_candidates
                    for axis in axes
                    for evidence_ref in getattr(candidate.claims, axis).evidence_refs
                }
                if len(axis_values) > 1 and (
                    not required_refs or not required_refs <= compatibility_refs
                ):
                    diagnostics.append(
                        _diagnostic(
                            code,
                            "Merged candidates have incompatible evidence boundaries without a "
                            "source-evidenced compatibility proof.",
                            pointer=f"{pointer}/evidence",
                        )
                    )

    denominator_route_ids = {route.id for route in scope_inventory.routes}
    assigned = tuple(sorted(route_id for route_id in route_assignments if route_id in route_index))
    unassigned = tuple(sorted(denominator_route_ids - route_assignments.keys()))
    multiply_assigned = tuple(
        sorted(route_id for route_id, count in route_assignments.items() if count > 1)
    )
    if intent_plan is not None and unassigned:
        diagnostics.append(
            _diagnostic(
                "ACC_INTENT_PLAN_DENOMINATOR_UNASSIGNED",
                "Every discovered source route must be assigned, including excluded and "
                "out-of-scope routes.",
                pointer="/intents",
            )
        )
    if multiply_assigned:
        explained_routes = (
            {
                route_id
                for relationship in intent_plan.relationships
                for route_id in relationship.route_ids
            }
            if intent_plan is not None
            else set()
        )
        unexplained = sorted(set(multiply_assigned) - explained_routes)
        if unexplained:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_ROUTE_MULTIPLY_ASSIGNED",
                    "A route may occur in multiple intents only through an explicit relationship.",
                    pointer="/relationships",
                )
            )

    fragmented: dict[str, tuple[str, ...]] = {}
    for business_intent, proposal_members in sorted(active_by_intent.items()):
        if len(proposal_members) < 2:
            continue
        member_signatures = {
            proposal_signatures[proposal_id]
            for proposal_id in proposal_members
            if proposal_id in proposal_signatures
        }
        if len(member_signatures) <= 1:
            fragmented[business_intent] = tuple(sorted(proposal_members))
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_ROUTE_PER_TOOL_FRAGMENTATION",
                    "Equivalent business intent and lifecycle evidence were split across tools; "
                    "merge them or prove distinct outcomes.",
                    pointer="/intents",
                    severity="warning",
                )
            )

    orphan_candidates = tuple(sorted(candidate_index.keys() - planned_candidates))
    orphan_capabilities = tuple(sorted(capabilities.keys() - planned_capabilities))
    if intent_plan is not None and orphan_candidates:
        diagnostics.append(
            _diagnostic(
                "ACC_INTENT_PLAN_ORPHAN_CANDIDATE",
                "Candidate ledger entries must be planned, deferred, or evidence-blocked.",
                pointer="/intents",
            )
        )
    if intent_plan is not None and orphan_capabilities:
        diagnostics.append(
            _diagnostic(
                "ACC_INTENT_PLAN_ORPHAN_CAPABILITY",
                "Existing Capabilities must remain represented in the intent plan.",
                pointer="/intents",
            )
        )

    for candidate_id in domain_map.unclassified_candidate_ids:
        if candidate_id in candidate_index:
            diagnostics.append(
                _diagnostic(
                    "ACC_INTENT_PLAN_UNCLASSIFIED_CANDIDATE",
                    "A candidate remains outside every business domain.",
                    path="domain-map.yaml",
                    pointer="/unclassified_candidate_ids",
                    severity="warning",
                )
            )

    portfolio = analyze_tool_portfolio(
        capabilities,
        qualities,
        operation_dependencies,
        scope_inventory,
    )
    diagnostics.extend(portfolio.diagnostics)
    diagnostics.sort(key=lambda item: (item.path or "", item.pointer or "", item.code))
    accounting = RouteDenominatorAccounting(
        discovered=len(scope_inventory.routes),
        assigned=assigned,
        unassigned=unassigned,
        multiply_assigned=multiply_assigned,
        materializable=tuple(
            sorted(
                route.id
                for route in scope_inventory.routes
                if route.disposition in {"planned", "composed"}
            )
        ),
        blocked_on_evidence=tuple(
            sorted(
                route.id
                for route in scope_inventory.routes
                if route.disposition == "blocked_on_evidence"
            )
        ),
        excluded=tuple(
            sorted(
                route.id
                for route in scope_inventory.routes
                if route.disposition in {"excluded", "out_of_scope"}
            )
        ),
    )
    return IntentPlanningAnalysis(
        accounting,
        orphan_candidates,
        orphan_capabilities,
        fragmented,
        _suggest_domains(domain_map, candidate_index),
        portfolio,
        tuple(diagnostics),
    )


__all__ = [
    "DomainPlanningSuggestion",
    "IntentPlanningAnalysis",
    "RouteDenominatorAccounting",
    "audit_intent_plan",
]
