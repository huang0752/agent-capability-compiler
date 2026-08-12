"""Deterministic Action candidate reporting without self-certified release claims."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Literal

from pydantic import Field

from acc_core.domains.models import (
    CapabilityCandidate,
    DomainDecision,
    DomainModel,
    VerificationLevel,
    domain_decision_digest,
)

if TYPE_CHECKING:
    from acc_core.validation import ValidationReport

type ActionAxisStatus = Literal["proven", "unresolved", "contradicted", "stale"]
type VerificationStatus = Literal["proven", "claimed", "not_provisioned", "blocked"]


class ActionClaimAxis(DomainModel):
    """One independent source-backed Action safety fact."""

    status: ActionAxisStatus
    evidence_refs: list[str]


class ActionSafetyReport(DomainModel):
    """Safety axes remain independent; there is intentionally no aggregate score."""

    schema_: ActionClaimAxis = Field(alias="schema")
    effect: ActionClaimAxis
    risk: ActionClaimAxis
    reversibility: ActionClaimAxis
    approval: ActionClaimAxis
    retry: ActionClaimAxis
    conflict_control: ActionClaimAxis
    idempotency: ActionClaimAxis
    outcome_resolution: ActionClaimAxis
    lifecycle: ActionClaimAxis
    authorization_boundary: ActionClaimAxis
    identity_binding: ActionClaimAxis
    context_isolation: ActionClaimAxis


class ActionVerificationReport(DomainModel):
    """Evidence maturity; declaration and execution proof are deliberately distinct."""

    discovered: VerificationStatus
    semantics_evidenced: VerificationStatus
    contract_ready: VerificationStatus
    offline_verified: VerificationStatus
    gateway_offline_verified: VerificationStatus
    source_connected_verified: VerificationStatus
    user_accepted: VerificationStatus
    production_ready: VerificationStatus


class ActionCandidateReport(DomainModel):
    candidate_id: str
    domain_id: str | None
    business_intent: str
    route_ids: list[str]
    effect: str
    disposition: Literal["accepted", "deferred", "rejected", "blocked", "undecided"]
    materialized_capability_ids: list[str]
    declared_verification_level: VerificationLevel
    safety: ActionSafetyReport
    verification: ActionVerificationReport
    materialized: bool
    blockers: list[str]


class ActionReportSummary(DomainModel):
    action_candidates: int
    materialized_candidates: int
    blocked_candidates: int


class ActionCandidateInventoryReport(DomainModel):
    schema_version: Literal["2"] = "2"
    project_valid: bool
    summary: ActionReportSummary
    candidates: list[ActionCandidateReport]


def _axis(status: str, evidence_refs: list[str]) -> ActionClaimAxis:
    if status in {
        "proven",
        "upstream_authoritative",
        "identity_binding_proven",
        "context_isolation_proven",
    }:
        normalized: ActionAxisStatus = "proven"
    elif status == "contradicted":
        normalized = "contradicted"
    elif status == "stale":
        normalized = "stale"
    else:
        normalized = "unresolved"
    return ActionClaimAxis(status=normalized, evidence_refs=evidence_refs)


def _safety(candidate: CapabilityCandidate) -> ActionSafetyReport:
    claims = candidate.claims
    return ActionSafetyReport.model_validate(
        {
            "schema": _axis(claims.schema_.status, claims.schema_.evidence_refs),
            "effect": _axis(claims.effect.status, claims.effect.evidence_refs),
            "risk": _axis(claims.risk.status, claims.risk.evidence_refs),
            "reversibility": _axis(claims.reversibility.status, claims.reversibility.evidence_refs),
            "approval": _axis(claims.approval.status, claims.approval.evidence_refs),
            "retry": _axis(claims.retry.status, claims.retry.evidence_refs),
            "conflict_control": _axis(
                claims.conflict_control.status, claims.conflict_control.evidence_refs
            ),
            "idempotency": _axis(claims.idempotency.status, claims.idempotency.evidence_refs),
            "outcome_resolution": _axis(
                claims.outcome_resolution.status, claims.outcome_resolution.evidence_refs
            ),
            "lifecycle": _axis(claims.lifecycle.status, claims.lifecycle.evidence_refs),
            "authorization_boundary": _axis(
                claims.authorization_boundary.status,
                claims.authorization_boundary.evidence_refs,
            ),
            "identity_binding": _axis(
                claims.identity_binding.status, claims.identity_binding.evidence_refs
            ),
            "context_isolation": _axis(
                claims.context_isolation.status, claims.context_isolation.evidence_refs
            ),
        }
    )


def _selected_decision(report: ValidationReport, domain_id: str | None) -> DomainDecision | None:
    if domain_id is None:
        return None
    if report.domain_map is not None:
        domain = next((item for item in report.domain_map.domains if item.id == domain_id), None)
        if domain is not None and domain.active_decision_ref is not None:
            reference = domain.active_decision_ref
            decision = report.domain_decisions.get((reference.domain_id, reference.revision))
            if (
                decision is not None
                and domain_decision_digest(decision) == reference.decision_digest
            ):
                return decision
            return None
    decisions = sorted(
        (item for item in report.domain_decisions.values() if item.domain_id == domain_id),
        key=lambda item: item.revision,
    )
    if decisions and decisions[-1].status != "completed":
        return decisions[-1]
    return None


def _called_operations(value: object) -> set[str]:
    called: set[str] = set()
    if isinstance(value, Mapping):
        call = value.get("call")
        if isinstance(call, Mapping) and isinstance(call.get("operation"), str):
            called.add(call["operation"])
        for nested in value.values():
            called.update(_called_operations(nested))
    elif isinstance(value, list):
        for nested in value:
            called.update(_called_operations(nested))
    return called


def _capabilities_close_candidate_routes(
    report: ValidationReport,
    candidate: CapabilityCandidate,
    capability_ids: list[str],
) -> bool:
    if not capability_ids or report.scope_inventory is None:
        return False
    routes = {route.id: route for route in report.scope_inventory.routes}
    action_routes = []
    for route_id in candidate.route_ids:
        route = routes.get(route_id)
        if route is None or route.kind != "action":
            continue
        if (
            route.candidate_id != candidate.id
            or route.disposition not in {"planned", "composed"}
            or route.eligibility != "eligible"
            or route.operation_id is None
        ):
            return False
        operation = report.operations.get(route.operation_id)
        if (
            operation is None
            or operation.kind != "action"
            or route.operation_id not in report.source_contracts
        ):
            return False
        action_routes.append(route)
    if not action_routes:
        return False
    for capability_id in capability_ids:
        capability = report.capabilities.get(capability_id)
        if capability is None or capability.kind != "action":
            return False
        commit_operations = _called_operations(
            [step.model_dump(mode="python", by_alias=True) for step in capability.commit_workflow]
        )
        bound_routes = [route for route in action_routes if capability_id in route.capability_ids]
        if not bound_routes or any(
            route.operation_id not in commit_operations for route in bound_routes
        ):
            return False
    return all(
        any(capability_id in route.capability_ids for capability_id in capability_ids)
        for route in action_routes
    )


def _candidate_report(
    report: ValidationReport,
    candidate: CapabilityCandidate,
) -> ActionCandidateReport:
    decision = _selected_decision(report, candidate.domain_id)
    disposition = None
    if decision is not None:
        disposition = next(
            (item for item in decision.candidate_dispositions if item.candidate_id == candidate.id),
            None,
        )
    disposition_name = disposition.disposition if disposition is not None else "undecided"
    capability_ids = disposition.materialized_capability_ids if disposition is not None else []
    safety = _safety(candidate)
    safety_statuses = [getattr(safety, name).status for name in safety.__class__.model_fields]
    semantics_proven = all(status == "proven" for status in safety_statuses)
    capabilities_closed = _capabilities_close_candidate_routes(report, candidate, capability_ids)
    contract_proven = report.ok and disposition_name == "accepted" and capabilities_closed
    user_accepted = bool(
        report.ok
        and disposition_name == "accepted"
        and decision is not None
        and decision.status == "completed"
        and decision.user_confirmation is not None
    )
    declared = candidate.verification_level
    offline: VerificationStatus = "claimed" if declared == "offline_verified" else "not_provisioned"
    source: VerificationStatus = (
        "claimed" if declared == "source_connected_verified" else "not_provisioned"
    )
    blockers = set(candidate.gaps)
    if disposition_name != "accepted":
        blockers.add(f"decision_{disposition_name}")
    if not semantics_proven:
        blockers.add("action_semantics_unresolved")
    if not capabilities_closed and disposition_name == "accepted":
        blockers.add("materialized_action_contract_missing")
    if not report.ok:
        blockers.add("project_validation_failed")
    materialized = contract_proven
    return ActionCandidateReport(
        candidate_id=candidate.id,
        domain_id=candidate.domain_id,
        business_intent=candidate.business_intent,
        route_ids=candidate.route_ids,
        effect=candidate.effect_claim,
        disposition=disposition_name,
        materialized_capability_ids=capability_ids,
        declared_verification_level=declared,
        safety=safety,
        verification=ActionVerificationReport(
            discovered="proven",
            semantics_evidenced="proven" if semantics_proven else "blocked",
            contract_ready="proven" if contract_proven else "blocked",
            offline_verified=offline,
            gateway_offline_verified="not_provisioned",
            source_connected_verified=source,
            user_accepted=(
                "proven" if user_accepted else "blocked" if not report.ok else "not_provisioned"
            ),
            production_ready="not_provisioned",
        ),
        materialized=materialized,
        blockers=sorted(blockers),
    )


def analyze_action_candidates(report: ValidationReport) -> ActionCandidateInventoryReport:
    """Report every typed Action candidate without upgrading declared verification claims."""

    candidates = (
        []
        if report.capability_candidate_ledger is None
        else [
            item
            for item in report.capability_candidate_ledger.candidates
            if item.kind_claim == "action"
        ]
    )
    items = [_candidate_report(report, candidate) for candidate in candidates]
    materialized = sum(item.materialized for item in items)
    return ActionCandidateInventoryReport(
        project_valid=report.ok,
        summary=ActionReportSummary(
            action_candidates=len(items),
            materialized_candidates=materialized,
            blocked_candidates=len(items) - materialized,
        ),
        candidates=items,
    )


__all__ = [
    "ActionCandidateInventoryReport",
    "ActionCandidateReport",
    "ActionClaimAxis",
    "ActionReportSummary",
    "ActionSafetyReport",
    "ActionVerificationReport",
    "analyze_action_candidates",
]
