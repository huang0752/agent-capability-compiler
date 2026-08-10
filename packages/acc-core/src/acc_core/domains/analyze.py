"""Deterministic readiness analysis for domain-guided capability discovery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from acc_core.diagnostics import Diagnostic
from acc_core.domains.models import (
    CapabilityCandidate,
    CapabilityCandidateLedger,
    DomainDecision,
    DomainEntry,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)

type AuthorizationStatus = Literal["source_final", "unknown", "contradicted", "stale"]
type DependencyReadinessStatus = Literal["resolved", "unresolved", "stale"]
type ReadinessStatus = Literal[
    "not_started",
    "in_progress",
    "awaiting_user",
    "validation_failed",
    "ready_for_review",
    "completed",
    "stale",
]


@dataclass(frozen=True, slots=True)
class CandidateReadiness:
    """Evidence-derived readiness facts for one candidate."""

    candidate_id: str
    blocking_gaps: tuple[str, ...]
    authorization_status: AuthorizationStatus


@dataclass(frozen=True, slots=True)
class DependencyReadiness:
    """Resolution state for one declared domain dependency."""

    domain_id: str
    status: DependencyReadinessStatus
    decision_revision: int | None


@dataclass(frozen=True, slots=True)
class DomainReadiness:
    """Independent domain readiness facts without a synthetic score."""

    domain_id: str
    status: ReadinessStatus
    accepted_candidate_ids: tuple[str, ...]
    blocked_candidate_ids: tuple[str, ...]
    deferred_candidate_ids: tuple[str, ...]
    rejected_candidate_ids: tuple[str, ...]
    dependencies: tuple[DependencyReadiness, ...]
    diagnostics: tuple[Diagnostic, ...]


def analyze_candidate_readiness(candidate: CapabilityCandidate) -> CandidateReadiness:
    """Derive readiness from typed claims, never from the declared gap summary alone."""

    claims = candidate.claims
    statuses = (
        claims.authorization_boundary.status,
        claims.identity_binding.status,
        claims.context_isolation.status,
    )
    if statuses == (
        "upstream_authoritative",
        "identity_binding_proven",
        "context_isolation_proven",
    ):
        authorization_status: AuthorizationStatus = "source_final"
    elif "contradicted" in statuses:
        authorization_status = "contradicted"
    elif "stale" in statuses:
        authorization_status = "stale"
    else:
        authorization_status = "unknown"

    blocking_gaps = set(candidate.gaps)
    if claims.authorization_boundary.status != "upstream_authoritative":
        blocking_gaps.add("authorization_boundary")
    if claims.identity_binding.status != "identity_binding_proven":
        blocking_gaps.add("identity_binding")
    if claims.context_isolation.status != "context_isolation_proven":
        blocking_gaps.add("context_isolation")

    if candidate.kind_claim == "unknown":
        blocking_gaps.add("kind")
    else:
        if claims.schema_.status != "proven":
            blocking_gaps.add("schema")
        expected_effects = (
            {"read"}
            if candidate.kind_claim == "read"
            else {"create", "update", "delete", "transition", "execute"}
        )
        if claims.effect.status != "proven" or candidate.effect_claim not in expected_effects:
            blocking_gaps.add("effect")

    if candidate.kind_claim == "action":
        action_claims = {
            "approval": claims.approval,
            "conflict_control": claims.conflict_control,
            "idempotency": claims.idempotency,
            "lifecycle": claims.lifecycle,
            "outcome_resolution": claims.outcome_resolution,
            "reversibility": claims.reversibility,
            "retry": claims.retry,
            "risk": claims.risk,
        }
        blocking_gaps.update(
            axis for axis, claim in action_claims.items() if claim.status != "proven"
        )
    return CandidateReadiness(
        candidate_id=candidate.id,
        blocking_gaps=tuple(sorted(blocking_gaps)),
        authorization_status=authorization_status,
    )


def _dependency_readiness(
    domain_id: str,
    *,
    decision: DomainDecision | None,
    dependency_decisions: Mapping[str, DomainDecision],
) -> DependencyReadiness:
    target = dependency_decisions.get(domain_id)
    if target is None:
        return DependencyReadiness(domain_id, "unresolved", None)
    if target.status == "stale":
        return DependencyReadiness(domain_id, "stale", target.revision)
    if target.status != "completed" or target.user_confirmation is None:
        return DependencyReadiness(domain_id, "unresolved", target.revision)
    if decision is not None:
        references = {item.domain_id: item for item in decision.dependency_decisions}
        reference = references.get(domain_id)
        if (
            reference is None
            or reference.revision != target.revision
            or reference.decision_digest != domain_decision_digest(target)
        ):
            return DependencyReadiness(domain_id, "unresolved", target.revision)
    return DependencyReadiness(domain_id, "resolved", target.revision)


def _diagnostic(
    code: str,
    message: str,
    *,
    pointer: str,
    severity: Literal["error", "warning", "info"] = "error",
) -> Diagnostic:
    return Diagnostic(
        code=code,
        severity=severity,
        message=message,
        path=None,
        pointer=pointer,
    )


def analyze_domain_readiness(
    *,
    domain: DomainEntry,
    candidate_ledger: CapabilityCandidateLedger,
    decision: DomainDecision | None,
    dependency_decisions: Mapping[str, DomainDecision] | None = None,
) -> DomainReadiness:
    """Derive domain readiness without trusting AI-authored summary fields."""

    diagnostics: list[Diagnostic] = []
    all_candidates = {candidate.id: candidate for candidate in candidate_ledger.candidates}
    ledger_index_by_id = {
        candidate.id: index for index, candidate in enumerate(candidate_ledger.candidates)
    }
    domain_candidates = {
        candidate_id: all_candidates[candidate_id]
        for candidate_id in domain.candidate_ids
        if candidate_id in all_candidates
    }
    readiness_by_id = {
        candidate_id: analyze_candidate_readiness(candidate)
        for candidate_id, candidate in sorted(domain_candidates.items())
    }
    authority_diagnostics = {
        "authorization_boundary": {
            "contradicted": "ACC_DOMAIN_SOURCE_AUTHORITY_OVERRIDDEN",
            "stale": "ACC_DOMAIN_AUTHORIZATION_BOUNDARY_STALE",
        },
        "identity_binding": {
            "contradicted": "ACC_DOMAIN_IDENTITY_BINDING_CONTRADICTED",
            "stale": "ACC_DOMAIN_IDENTITY_BINDING_STALE",
        },
        "context_isolation": {
            "contradicted": "ACC_DOMAIN_CONTEXT_ISOLATION_CONTRADICTED",
            "stale": "ACC_DOMAIN_CONTEXT_ISOLATION_STALE",
        },
    }
    for candidate_id in domain.candidate_ids:
        if candidate_id not in readiness_by_id:
            continue
        candidate = domain_candidates[candidate_id]
        candidate_claim_statuses = (
            ("authorization_boundary", candidate.claims.authorization_boundary.status),
            ("identity_binding", candidate.claims.identity_binding.status),
            ("context_isolation", candidate.claims.context_isolation.status),
        )
        for axis, claim_status in candidate_claim_statuses:
            code = authority_diagnostics[axis].get(claim_status)
            if code is None:
                continue
            diagnostics.append(
                _diagnostic(
                    code,
                    "A source authority claim is contradicted or stale and requires new evidence.",
                    pointer=(f"/candidates/{ledger_index_by_id[candidate_id]}/claims/{axis}"),
                )
            )

    dependencies = tuple(
        _dependency_readiness(
            domain_id,
            decision=decision,
            dependency_decisions=dependency_decisions or {},
        )
        for domain_id in domain.dependency_domain_ids
    )
    decision_dependency_indexes = (
        {item.domain_id: index for index, item in enumerate(decision.dependency_decisions)}
        if decision is not None
        else {}
    )
    emitted_dependency_pointers: set[str] = set()
    for domain_index, dependency in enumerate(dependencies):
        if dependency.status != "resolved":
            dependency_index = decision_dependency_indexes.get(dependency.domain_id)
            if decision is None:
                pointer = f"/dependency_domain_ids/{domain_index}"
            elif dependency_index is not None:
                pointer = f"/dependency_decisions/{dependency_index}"
            else:
                pointer = "/dependency_decisions"
            if pointer in emitted_dependency_pointers:
                continue
            emitted_dependency_pointers.add(pointer)
            diagnostics.append(
                _diagnostic(
                    "ACC_DOMAIN_DEPENDENCY_UNRESOLVED",
                    "A declared domain dependency is not bound to a completed active decision.",
                    pointer=pointer,
                )
            )

    accepted: list[str] = []
    blocked: list[str] = []
    deferred: list[str] = []
    rejected: list[str] = []
    if decision is not None:
        for index, disposition in enumerate(decision.candidate_dispositions):
            candidate_id = disposition.candidate_id
            if disposition.disposition == "accepted":
                accepted.append(candidate_id)
                accepted_readiness = readiness_by_id.get(candidate_id)
                if accepted_readiness is None or accepted_readiness.blocking_gaps:
                    blocked.append(candidate_id)
                    diagnostics.append(
                        _diagnostic(
                            "ACC_DOMAIN_CANDIDATE_BLOCKED",
                            "An accepted candidate retains unresolved blocking evidence.",
                            pointer=f"/candidate_dispositions/{index}",
                        )
                    )
            elif disposition.disposition == "blocked":
                blocked.append(candidate_id)
                diagnostics.append(
                    _diagnostic(
                        "ACC_DOMAIN_CANDIDATE_BLOCKED",
                        "A candidate remains blocked on evidence.",
                        pointer=f"/candidate_dispositions/{index}",
                        severity="warning",
                    )
                )
            elif disposition.disposition == "deferred":
                deferred.append(candidate_id)
            else:
                rejected.append(candidate_id)

        facts_stale = (
            decision.candidate_snapshot_ids != domain.candidate_ids
            or decision.candidate_ledger_digest
            != capability_candidate_ledger_digest(candidate_ledger)
        )
        if decision.status == "stale" or facts_stale:
            diagnostics.append(
                _diagnostic(
                    "ACC_DOMAIN_DECISION_STALE",
                    "DomainDecision no longer matches the current candidate denominator.",
                    pointer="/candidate_ledger_digest",
                    severity="error" if facts_stale else "warning",
                )
            )
        if decision.status == "completed" and decision.user_confirmation is None:
            diagnostics.append(
                _diagnostic(
                    "ACC_DOMAIN_DECISION_UNCONFIRMED",
                    "A completed DomainDecision requires an exact user confirmation.",
                    pointer="/user_confirmation",
                )
            )

    diagnostics.sort(key=lambda item: (item.code, item.pointer or "", item.message))
    has_errors = any(item.severity == "error" for item in diagnostics)
    if decision is not None and decision.status == "stale":
        status: ReadinessStatus = "stale"
    elif has_errors:
        status = "validation_failed"
    elif decision is None:
        if not domain.candidate_ids:
            status = "not_started"
        elif all(
            candidate_id in readiness_by_id and not readiness_by_id[candidate_id].blocking_gaps
            for candidate_id in domain.candidate_ids
        ):
            status = "awaiting_user"
        else:
            status = "in_progress"
    elif decision.status == "completed":
        status = "completed"
    elif decision.unresolved_questions:
        status = "awaiting_user"
    elif blocked:
        status = "in_progress"
    else:
        status = "ready_for_review"

    return DomainReadiness(
        domain_id=domain.id,
        status=status,
        accepted_candidate_ids=tuple(accepted),
        blocked_candidate_ids=tuple(sorted(set(blocked))),
        deferred_candidate_ids=tuple(deferred),
        rejected_candidate_ids=tuple(rejected),
        dependencies=dependencies,
        diagnostics=tuple(diagnostics),
    )


__all__ = [
    "AuthorizationStatus",
    "CandidateReadiness",
    "DependencyReadiness",
    "DependencyReadinessStatus",
    "DomainReadiness",
    "ReadinessStatus",
    "analyze_candidate_readiness",
    "analyze_domain_readiness",
]
