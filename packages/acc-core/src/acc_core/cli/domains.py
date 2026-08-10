"""Deterministic, offline Domain workflow commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from acc_core.diagnostics import Diagnostic
from acc_core.domains import (
    CapabilityCandidate,
    DomainDecision,
    DomainReadiness,
    analyze_candidate_readiness,
    analyze_domain_readiness,
    domain_decision_digest,
)
from acc_core.io import ProjectIOError, load_project_object
from acc_core.validation import (
    ValidationReport,
    validate_project,
    validate_proposed_domain_decision,
)


def _diagnostic(code: str, message: str, *, path: str | None, pointer: str | None) -> Diagnostic:
    return Diagnostic(code=code, severity="error", message=message, path=path, pointer=pointer)


def _domain_report(project: Path) -> tuple[ValidationReport, list[Diagnostic]]:
    report = validate_project(project)
    diagnostics: list[Diagnostic] = []
    if report.domain_map is None:
        diagnostics.append(
            _diagnostic(
                "ACC_DOMAIN_MAP_REQUIRED",
                "Domain workflow requires a valid domain-map.yaml.",
                path="domain-map.yaml",
                pointer=None,
            )
        )
    if report.capability_candidate_ledger is None:
        diagnostics.append(
            _diagnostic(
                "ACC_DOMAIN_CANDIDATE_LEDGER_REQUIRED",
                "Domain workflow requires a valid capability-candidates.yaml.",
                path="capability-candidates.yaml",
                pointer=None,
            )
        )
    return report, diagnostics


def _candidate_risk(candidate: CapabilityCandidate) -> int:
    if candidate.kind_claim == "read":
        return 0
    if candidate.kind_claim == "action":
        return 1
    return 2


def _verified_completed_domain_ids(report: ValidationReport) -> set[str]:
    """Resolve completion only through an exact confirmed active decision."""

    assert report.domain_map is not None
    completed: set[str] = set()
    for domain in report.domain_map.domains:
        reference = domain.active_decision_ref
        if reference is None:
            continue
        decision = report.domain_decisions.get((reference.domain_id, reference.revision))
        if (
            decision is not None
            and decision.domain_id == domain.id
            and decision.status == "completed"
            and decision.user_confirmation is not None
            and domain_decision_digest(decision) == reference.decision_digest
        ):
            completed.add(domain.id)
    return completed


def _domain_readiness(report: ValidationReport, domain_id: str) -> DomainReadiness:
    assert report.domain_map is not None
    assert report.capability_candidate_ledger is not None
    domain = next(item for item in report.domain_map.domains if item.id == domain_id)
    decisions = sorted(
        (item for item in report.domain_decisions.values() if item.domain_id == domain_id),
        key=lambda item: item.revision,
    )
    if domain.active_decision_ref is None:
        decision = decisions[-1] if decisions else None
    else:
        reference = domain.active_decision_ref
        candidate = report.domain_decisions.get((reference.domain_id, reference.revision))
        decision = (
            candidate
            if candidate is not None
            and domain_decision_digest(candidate) == reference.decision_digest
            else None
        )
    domains = {item.id: item for item in report.domain_map.domains}
    dependency_decisions: dict[str, DomainDecision] = {}
    for dependency_id in domain.dependency_domain_ids:
        dependency = domains[dependency_id]
        dependency_reference = dependency.active_decision_ref
        if dependency_reference is None:
            continue
        candidate = report.domain_decisions.get(
            (dependency_reference.domain_id, dependency_reference.revision)
        )
        if (
            candidate is not None
            and domain_decision_digest(candidate) == dependency_reference.decision_digest
        ):
            dependency_decisions[dependency_id] = candidate
    return analyze_domain_readiness(
        domain=domain,
        candidate_ledger=report.capability_candidate_ledger,
        decision=decision,
        dependency_decisions=dependency_decisions,
    )


def status_domains(project: Path) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    """Return stable domain state and one deterministic next-domain recommendation."""

    report, diagnostics = _domain_report(project)
    if diagnostics:
        return None, diagnostics
    if not report.ok:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_PROJECT_INVALID",
                "Domain workflow requires a structurally valid Project.",
                path=None,
                pointer=None,
            )
        ]
    assert report.domain_map is not None
    assert report.capability_candidate_ledger is not None
    candidates = {
        candidate.id: candidate for candidate in report.capability_candidate_ledger.candidates
    }
    domains = {domain.id: domain for domain in report.domain_map.domains}
    preferred = {
        domain_id: index for index, domain_id in enumerate(report.domain_map.preferred_order)
    }
    verified_completed = _verified_completed_domain_ids(report)
    output_domains: list[dict[str, Any]] = []
    selectable: list[tuple[int, int, str]] = []
    for domain in report.domain_map.domains:
        domain_candidates = [
            candidates[candidate_id]
            for candidate_id in domain.candidate_ids
            if candidate_id in candidates
        ]
        blocked = sum(
            bool(analyze_candidate_readiness(candidate).blocking_gaps)
            for candidate in domain_candidates
        )
        dependencies_completed = all(
            dependency_id in domains and dependency_id in verified_completed
            for dependency_id in domain.dependency_domain_ids
        )
        readiness = _domain_readiness(report, domain.id)
        output_domains.append(
            {
                "id": domain.id,
                "status": readiness.status,
                "candidate_count": len(domain_candidates),
                "blocked_candidate_count": blocked,
                "dependencies_completed": dependencies_completed,
                "verified_completed": domain.id in verified_completed,
            }
        )
        if domain.id not in verified_completed and dependencies_completed:
            risk = max((_candidate_risk(candidate) for candidate in domain_candidates), default=2)
            selectable.append((preferred.get(domain.id, len(preferred)), risk, domain.id))
    next_domain = min(selectable)[2] if selectable else None
    return {"domains": output_domains, "next_domain": next_domain}, []


def _decision_for_domain(report: ValidationReport, domain_id: str) -> DomainDecision | None:
    decisions = sorted(
        (item for item in report.domain_decisions.values() if item.domain_id == domain_id),
        key=lambda item: item.revision,
    )
    return decisions[-1] if decisions else None


def show_domain(
    project: Path, domain_id: str
) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    """Show one bounded domain summary without evidence contents or free-form gap text."""

    report, diagnostics = _domain_report(project)
    if diagnostics:
        return None, diagnostics
    if not report.ok:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_PROJECT_INVALID",
                "Domain workflow requires a structurally valid Project.",
                path=None,
                pointer=None,
            )
        ]
    assert report.domain_map is not None
    assert report.capability_candidate_ledger is not None
    domain = next((item for item in report.domain_map.domains if item.id == domain_id), None)
    if domain is None:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_UNKNOWN",
                "Requested domain does not exist.",
                path=report.domain_map_path,
                pointer="/domains",
            )
        ]
    candidates = {
        item.id: item for item in report.capability_candidate_ledger.candidates
    }
    candidate_summaries: list[dict[str, Any]] = []
    for candidate_id in domain.candidate_ids:
        candidate = candidates.get(candidate_id)
        if candidate is None:
            continue
        readiness = analyze_candidate_readiness(candidate)
        candidate_summaries.append(
            {
                "id": candidate.id,
                "business_intent": candidate.business_intent,
                "kind": candidate.kind_claim,
                "effect": candidate.effect_claim,
                "blocking_gap_count": len(readiness.blocking_gaps),
                "authorization_status": readiness.authorization_status,
            }
        )
    decision = _decision_for_domain(report, domain_id)
    domain_readiness = _domain_readiness(report, domain_id)
    return {
        "id": domain.id,
        "title": domain.title,
        "status": domain_readiness.status,
        "dependency_domain_ids": domain.dependency_domain_ids,
        "candidates": candidate_summaries,
        "latest_decision_revision": decision.revision if decision is not None else None,
    }, []


def check_domain_review(
    project: Path, review_path: str
) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    """Validate an external structured DomainDecision without writing it."""

    report, diagnostics = _domain_report(project)
    if diagnostics:
        return None, diagnostics
    try:
        document = load_project_object(project, review_path)
        decision = DomainDecision.model_validate(document)
    except ProjectIOError as exc:
        return None, [_diagnostic(exc.code, str(exc), path=review_path, pointer=None)]
    except ValidationError:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_REVIEW_INVALID",
                "Review document does not satisfy the DomainDecision contract.",
                path=review_path,
                pointer="/",
            )
        ]
    assert report.domain_map is not None
    assert report.capability_candidate_ledger is not None
    domain = next(
        (item for item in report.domain_map.domains if item.id == decision.domain_id), None
    )
    if domain is None:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_UNKNOWN",
                "Review document references an unknown domain.",
                path=review_path,
                pointer="/domain_id",
            )
        ]
    candidates = {
        item.id: item for item in report.capability_candidate_ledger.candidates
    }
    route_ids = {
        route_id
        for item in report.capability_candidate_ledger.candidates
        for route_id in item.route_ids
    }
    for index, disposition in enumerate(decision.candidate_dispositions):
        if disposition.candidate_id in route_ids:
            return None, [
                _diagnostic(
                    "ACC_DOMAIN_REVIEW_ROUTE_ID_FORBIDDEN",
                    "Review choices must reference Candidates, not source route identifiers.",
                    path=review_path,
                    pointer=f"/candidate_dispositions/{index}/candidate_id",
                )
            ]
        if disposition.candidate_id not in candidates:
            return None, [
                _diagnostic(
                    "ACC_DOMAIN_REVIEW_CANDIDATE_UNKNOWN",
                    "Review choice must reference a known Candidate.",
                    path=review_path,
                    pointer=f"/candidate_dispositions/{index}/candidate_id",
                )
            ]
    for index, goal in enumerate(decision.policy.goals):
        if goal in route_ids:
            return None, [
                _diagnostic(
                    "ACC_DOMAIN_REVIEW_ROUTE_ID_FORBIDDEN",
                    "Review goals must be business goals, not source route identifiers.",
                    path=review_path,
                    pointer=f"/policy/goals/{index}",
                )
            ]
    closure_diagnostics = validate_proposed_domain_decision(report, decision, review_path)
    if not report.ok:
        closure_diagnostics.insert(
            0,
            _diagnostic(
                "ACC_DOMAIN_REVIEW_PROJECT_INVALID",
                "Domain review requires a structurally closed Project baseline.",
                path=None,
                pointer=None,
            ),
        )
    if closure_diagnostics:
        return None, closure_diagnostics
    return {"domain_id": decision.domain_id, "revision": decision.revision, "valid": True}, []


def impact_domain_change(
    project: Path, request_id: str
) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    """Return a bounded impact report from a typed change request without writing state."""

    report = validate_project(project)
    request = report.domain_change_requests.get(request_id)
    if request is None:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_CHANGE_UNKNOWN",
                "Requested domain change does not exist.",
                path="domain-change-requests",
                pointer=None,
            )
        ]
    if not report.ok:
        return None, [
            _diagnostic(
                "ACC_DOMAIN_IMPACT_PROJECT_INVALID",
                "Domain impact requires a structurally closed Project and ChangeRequest.",
                path=report.domain_change_request_paths.get(request_id),
                pointer=None,
            )
        ]
    return {
        "id": request.id,
        "domain_id": request.domain_id,
        "status": request.status,
        "impact_class": request.impact_class,
        "deployment_effect": request.deployment_effect,
        "recommended_domain_status": request.recommended_domain_status,
        "affected_candidate_ids": request.affected_candidate_ids,
        "affected_capability_ids": request.affected_capability_ids,
        "changed_evidence": [
            {"evidence_ref": item.evidence_ref, "change": item.change}
            for item in request.changed_evidence
        ],
    }, []


__all__ = [
    "check_domain_review",
    "impact_domain_change",
    "show_domain",
    "status_domains",
]
