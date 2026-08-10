"""Independent Domain and Action coverage axes."""

from __future__ import annotations

from collections.abc import Iterable

from acc_core.coverage.models import (
    BusinessGoalCoverage,
    CandidateClassificationCoverage,
    CandidateEvidenceCoverage,
    CrossDomainDependencyCoverage,
    CrossDomainDependencyEdge,
    DomainCoverageAxes,
    DomainDispositionCoverage,
    IdentityAuthorizationCoverage,
    UserDecisionTraceCoverage,
    VerificationCoverage,
)
from acc_core.domains import (
    CapabilityCandidate,
    DomainDecision,
    analyze_candidate_readiness,
    analyze_domain_readiness,
    domain_decision_digest,
)
from acc_core.validation import ValidationReport


def _candidate_axis(
    candidates: Iterable[CapabilityCandidate],
    *,
    claim_name: str,
) -> CandidateEvidenceCoverage:
    proven: list[str] = []
    unproven: list[str] = []
    not_applicable: list[str] = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        if candidate.kind_claim == "read":
            not_applicable.append(candidate.id)
            continue
        claim = getattr(candidate.claims, claim_name)
        (
            proven if candidate.kind_claim == "action" and claim.status == "proven" else unproven
        ).append(candidate.id)
    return CandidateEvidenceCoverage(
        status="analyzed",
        proven_candidate_ids=proven,
        unproven_candidate_ids=unproven,
        not_applicable_candidate_ids=not_applicable,
    )


def _semantics_axis(candidates: Iterable[CapabilityCandidate]) -> CandidateEvidenceCoverage:
    proven: list[str] = []
    unproven: list[str] = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        expected_effects = (
            {"read"}
            if candidate.kind_claim == "read"
            else {"create", "update", "delete", "transition", "execute"}
        )
        required = [candidate.claims.schema_, candidate.claims.effect]
        if candidate.kind_claim == "action":
            required.extend(
                [
                    candidate.claims.risk,
                    candidate.claims.reversibility,
                    candidate.claims.approval,
                    candidate.claims.retry,
                ]
            )
        is_proven = (
            candidate.kind_claim in {"read", "action"}
            and candidate.effect_claim in expected_effects
            and all(claim.status == "proven" for claim in required)
        )
        (proven if is_proven else unproven).append(candidate.id)
    return CandidateEvidenceCoverage(
        status="analyzed",
        proven_candidate_ids=proven,
        unproven_candidate_ids=unproven,
        not_applicable_candidate_ids=[],
    )


def _active_decisions(report: ValidationReport) -> dict[str, DomainDecision]:
    assert report.domain_map is not None
    decisions_by_domain: dict[str, list[DomainDecision]] = {}
    for decision in report.domain_decisions.values():
        decisions_by_domain.setdefault(decision.domain_id, []).append(decision)
    active_decisions: dict[str, DomainDecision] = {}
    for domain in report.domain_map.domains:
        active = domain.active_decision_ref
        if active is None:
            continue
        exact = next(
            (
                decision
                for decision in decisions_by_domain.get(domain.id, [])
                if decision.revision == active.revision
                and domain_decision_digest(decision) == active.decision_digest
            ),
            None,
        )
        if exact is not None:
            active_decisions[domain.id] = exact
    return active_decisions


def _selected_decisions(report: ValidationReport) -> dict[str, DomainDecision]:
    assert report.domain_map is not None
    decisions_by_domain: dict[str, list[DomainDecision]] = {}
    for decision in report.domain_decisions.values():
        decisions_by_domain.setdefault(decision.domain_id, []).append(decision)
    active_decisions = _active_decisions(report)
    selected: dict[str, DomainDecision] = {}
    for domain in report.domain_map.domains:
        if domain.active_decision_ref is not None:
            if domain.id in active_decisions:
                selected[domain.id] = active_decisions[domain.id]
            continue
        available = decisions_by_domain.get(domain.id, [])
        if available:
            selected[domain.id] = max(available, key=lambda item: item.revision)
    return selected


def _not_declared() -> DomainCoverageAxes:
    candidate_axis = {
        "status": "not_declared",
        "proven_candidate_ids": [],
        "unproven_candidate_ids": [],
        "not_applicable_candidate_ids": [],
    }
    return DomainCoverageAxes.model_validate(
        {
            "domain_disposition": {
                "status": "not_declared",
                "status_by_domain": {},
                "accepted_candidate_ids": [],
                "deferred_candidate_ids": [],
                "rejected_candidate_ids": [],
                "blocked_candidate_ids": [],
            },
            "business_goals": {
                "status": "not_declared",
                "goals_by_domain": {},
                "excluded_intents_by_domain": {},
                "approval_required_by_domain": {},
                "domains_without_decisions": [],
            },
            "candidate_classification": {
                "status": "not_declared",
                "read_candidate_ids": [],
                "action_candidate_ids": [],
                "unknown_candidate_ids": [],
                "unclassified_candidate_ids": [],
            },
            "semantics_provenance": candidate_axis,
            "identity_authorization": {
                "status": "not_declared",
                "source_final_candidate_ids": [],
                "unknown_candidate_ids": [],
                "contradicted_candidate_ids": [],
                "stale_candidate_ids": [],
            },
            "action_lifecycle": candidate_axis,
            "conflict_control": candidate_axis,
            "idempotency": candidate_axis,
            "outcome_resolution": candidate_axis,
            "verification": {"status": "not_declared", "level_by_candidate": {}},
            "cross_domain_dependency": {
                "status": "not_declared",
                "edges": [],
                "resolved_domain_ids": [],
                "unresolved_domain_ids": [],
                "stale_domain_ids": [],
            },
            "user_decision_trace": {
                "status": "not_declared",
                "confirmed_domain_ids": [],
                "pending_domain_ids": [],
                "deferred_candidate_ids": [],
            },
        }
    )


def analyze_domain_coverage(report: ValidationReport) -> DomainCoverageAxes:
    """Analyze twelve independent axes without inferring deployability or a score."""

    domain_map = report.domain_map
    ledger = report.capability_candidate_ledger
    if domain_map is None or ledger is None:
        return _not_declared()

    candidates = sorted(ledger.candidates, key=lambda item: item.id)
    selected = _selected_decisions(report)
    active_decisions = _active_decisions(report)
    readiness_by_domain = {}
    for domain in domain_map.domains:
        readiness_by_domain[domain.id] = analyze_domain_readiness(
            domain=domain,
            candidate_ledger=ledger,
            decision=selected.get(domain.id),
            dependency_decisions={
                dependency_id: active_decisions[dependency_id]
                for dependency_id in domain.dependency_domain_ids
                if dependency_id in active_decisions
            },
        )

    dispositions = [
        disposition
        for decision in selected.values()
        for disposition in decision.candidate_dispositions
    ]
    classification = CandidateClassificationCoverage(
        status="analyzed",
        read_candidate_ids=[item.id for item in candidates if item.kind_claim == "read"],
        action_candidate_ids=[item.id for item in candidates if item.kind_claim == "action"],
        unknown_candidate_ids=[item.id for item in candidates if item.kind_claim == "unknown"],
        unclassified_candidate_ids=domain_map.unclassified_candidate_ids,
    )

    identity_states: dict[str, list[str]] = {
        "source_final": [],
        "unknown": [],
        "contradicted": [],
        "stale": [],
    }
    for candidate in candidates:
        identity_states[analyze_candidate_readiness(candidate).authorization_status].append(
            candidate.id
        )

    edges = [
        CrossDomainDependencyEdge(
            domain_id=domain.id,
            dependency_domain_id=dependency.domain_id,
            status=dependency.status,
        )
        for domain in domain_map.domains
        for dependency in readiness_by_domain[domain.id].dependencies
    ]
    dependency_ids_by_status = {
        status: sorted({edge.dependency_domain_id for edge in edges if edge.status == status})
        for status in ("resolved", "unresolved", "stale")
    }
    confirmed = sorted(
        domain_id
        for domain_id, decision in active_decisions.items()
        if decision.status == "completed" and decision.user_confirmation is not None
    )
    domain_ids = {domain.id for domain in domain_map.domains}

    return DomainCoverageAxes(
        domain_disposition=DomainDispositionCoverage(
            status="analyzed",
            status_by_domain={
                domain_id: readiness.status
                for domain_id, readiness in sorted(readiness_by_domain.items())
            },
            accepted_candidate_ids=sorted(
                item.candidate_id for item in dispositions if item.disposition == "accepted"
            ),
            deferred_candidate_ids=sorted(
                item.candidate_id for item in dispositions if item.disposition == "deferred"
            ),
            rejected_candidate_ids=sorted(
                item.candidate_id for item in dispositions if item.disposition == "rejected"
            ),
            blocked_candidate_ids=sorted(
                {
                    candidate_id
                    for readiness in readiness_by_domain.values()
                    for candidate_id in readiness.blocked_candidate_ids
                }
            ),
        ),
        business_goals=BusinessGoalCoverage(
            status="analyzed",
            goals_by_domain={key: value.policy.goals for key, value in sorted(selected.items())},
            excluded_intents_by_domain={
                key: value.policy.excluded_intents for key, value in sorted(selected.items())
            },
            approval_required_by_domain={
                key: value.policy.approval_required_for for key, value in sorted(selected.items())
            },
            domains_without_decisions=sorted(domain_ids - set(selected)),
        ),
        candidate_classification=classification,
        semantics_provenance=_semantics_axis(candidates),
        identity_authorization=IdentityAuthorizationCoverage(
            status="analyzed",
            source_final_candidate_ids=identity_states["source_final"],
            unknown_candidate_ids=identity_states["unknown"],
            contradicted_candidate_ids=identity_states["contradicted"],
            stale_candidate_ids=identity_states["stale"],
        ),
        action_lifecycle=_candidate_axis(candidates, claim_name="lifecycle"),
        conflict_control=_candidate_axis(candidates, claim_name="conflict_control"),
        idempotency=_candidate_axis(candidates, claim_name="idempotency"),
        outcome_resolution=_candidate_axis(candidates, claim_name="outcome_resolution"),
        verification=VerificationCoverage(
            status="analyzed",
            level_by_candidate={item.id: item.verification_level for item in candidates},
        ),
        cross_domain_dependency=CrossDomainDependencyCoverage(
            status="analyzed",
            edges=edges,
            resolved_domain_ids=dependency_ids_by_status["resolved"],
            unresolved_domain_ids=dependency_ids_by_status["unresolved"],
            stale_domain_ids=dependency_ids_by_status["stale"],
        ),
        user_decision_trace=UserDecisionTraceCoverage(
            status="analyzed",
            confirmed_domain_ids=confirmed,
            pending_domain_ids=sorted(domain_ids - set(confirmed)),
            deferred_candidate_ids=sorted(
                item.candidate_id for item in dispositions if item.disposition == "deferred"
            ),
        ),
    )


__all__ = ["analyze_domain_coverage"]
