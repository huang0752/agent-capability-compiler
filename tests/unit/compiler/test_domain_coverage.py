from __future__ import annotations

import json

from acc_core.coverage import analyze_domain_coverage
from acc_core.domains import (
    CapabilityCandidate,
    CapabilityCandidateLedger,
    DomainDecision,
    DomainMap,
    aggregate_reference_digest,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)
from acc_core.scope import ScopeInventory
from acc_core.validation import ValidationReport


def _claim(status: str, *, evidence: bool = True) -> dict[str, object]:
    return {
        "status": status,
        "evidence_refs": ["source-contract"] if evidence else [],
    }


def _candidate(
    candidate_id: str,
    *,
    domain_id: str,
    kind: str,
    effect: str,
    proven: bool,
    verification_level: str,
) -> CapabilityCandidate:
    fact_status = "proven" if proven else "unknown"
    fact = _claim(fact_status, evidence=proven)
    return CapabilityCandidate.model_validate(
        {
            "id": candidate_id,
            "domain_id": domain_id,
            "business_intent": candidate_id.replace(".", "_"),
            "route_ids": [],
            "interaction_ids": [],
            "kind_claim": kind,
            "effect_claim": effect,
            "claims": {
                "schema": fact,
                "effect": fact,
                "risk": fact,
                "reversibility": fact,
                "approval": fact,
                "retry": fact,
                "conflict_control": fact,
                "idempotency": fact,
                "outcome_resolution": fact,
                "lifecycle": fact,
                "authorization_boundary": _claim(
                    "upstream_authoritative" if proven else "unknown",
                    evidence=proven,
                ),
                "identity_binding": _claim(
                    "identity_binding_proven" if proven else "unknown",
                    evidence=proven,
                ),
                "context_isolation": _claim(
                    "context_isolation_proven" if proven else "unknown",
                    evidence=proven,
                ),
            },
            "verification_level": verification_level,
            "gaps": [] if proven else ["lifecycle"],
        }
    )


def _domain_report() -> ValidationReport:
    action = _candidate(
        "crm.customer.update",
        domain_id="crm",
        kind="action",
        effect="update",
        proven=False,
        verification_level="source_connected_verified",
    )
    read = _candidate(
        "crm.customer.read",
        domain_id="crm",
        kind="read",
        effect="read",
        proven=True,
        verification_level="contract_ready",
    )
    identity = _candidate(
        "identity.current_user",
        domain_id="identity",
        kind="read",
        effect="read",
        proven=True,
        verification_level="contract_ready",
    )
    ledger = CapabilityCandidateLedger(
        schema_version="2",
        candidates=sorted([action, read, identity], key=lambda item: item.id),
    )
    crm_candidate_ids = ["crm.customer.read", "crm.customer.update"]
    decision_document: dict[str, object] = {
        "schema_version": "2",
        "domain_id": "crm",
        "revision": 1,
        "status": "ready_for_review",
        "policy": {
            "goals": ["manage_customers"],
            "allowed_effects": ["read", "update"],
            "maximum_risk": "high",
            "approval_required_for": ["manage_customers"],
            "excluded_intents": ["delete_customers"],
        },
        "candidate_dispositions": [
            {
                "candidate_id": "crm.customer.read",
                "disposition": "accepted",
                "materialized_capability_ids": ["customer.read"],
                "rationale": "Accepted by reviewer.",
            },
            {
                "candidate_id": "crm.customer.update",
                "disposition": "deferred",
                "materialized_capability_ids": [],
                "rationale": "Deferred until safety evidence exists.",
            },
        ],
        "candidate_snapshot_ids": crm_candidate_ids,
        "candidate_snapshot_digest": aggregate_reference_digest(crm_candidate_ids),
        "candidate_ledger_digest": capability_candidate_ledger_digest(ledger),
        "unresolved_questions": [],
        "dependency_decisions": [],
        "evidence_snapshot": [],
        "dependency_snapshot_digest": aggregate_reference_digest([]),
        "evidence_digest": aggregate_reference_digest([]),
        "user_confirmation": None,
    }
    decision = DomainDecision.model_validate(decision_document)
    domain_map = DomainMap.model_validate(
        {
            "schema_version": "2",
            "domains": [
                {
                    "id": "crm",
                    "title": "CRM",
                    "status": "ready_for_review",
                    "candidate_ids": crm_candidate_ids,
                    "route_ids": ["GET /customers"],
                    "interaction_ids": [],
                    "dependency_domain_ids": ["identity"],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                },
                {
                    "id": "identity",
                    "title": "Identity",
                    "status": "in_progress",
                    "candidate_ids": ["identity.current_user"],
                    "route_ids": [],
                    "interaction_ids": [],
                    "dependency_domain_ids": [],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                },
            ],
            "unclassified_candidate_ids": [],
            "preferred_order": ["identity", "crm"],
        }
    )
    scope_inventory = ScopeInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {
                "mode": "domain_complete",
                "selected_domains": ["crm"],
                "exclusion_approval": {},
            },
            "discovery": {
                "source_commit": "git:0123456789abcdef",
                "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
                "include_paths": ["app"],
                "evidence_sources": ["routes.py"],
            },
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": [
                {
                    "id": "GET /customers",
                    "domain": "crm",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/customers",
                    "evidence_sources": ["routes.py"],
                    "eligibility": "eligible",
                    "disposition": "composed",
                    "operation_id": "crm.customer.read",
                    "capability_ids": ["customer.read"],
                }
            ],
            "summary": {
                "discovered_routes": 1,
                "eligible_routes": 1,
                "planned": 0,
                "composed": 1,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        }
    )
    return ValidationReport(
        scope_inventory=scope_inventory,
        domain_map=domain_map,
        capability_candidate_ledger=ledger,
        domain_decisions={("crm", 1): decision},
    )


def _completed_identity_decision(report: ValidationReport) -> DomainDecision:
    assert report.capability_candidate_ledger is not None
    candidate_ids = ["identity.current_user"]
    document: dict[str, object] = {
        "schema_version": "2",
        "domain_id": "identity",
        "revision": 1,
        "status": "completed",
        "policy": {
            "goals": ["identify_current_user"],
            "allowed_effects": ["read"],
            "maximum_risk": "low",
            "approval_required_for": [],
            "excluded_intents": [],
        },
        "candidate_dispositions": [
            {
                "candidate_id": "identity.current_user",
                "disposition": "accepted",
                "materialized_capability_ids": ["identity.current_user"],
                "rationale": "Accepted by reviewer.",
            }
        ],
        "candidate_snapshot_ids": candidate_ids,
        "candidate_snapshot_digest": aggregate_reference_digest(candidate_ids),
        "candidate_ledger_digest": capability_candidate_ledger_digest(
            report.capability_candidate_ledger
        ),
        "unresolved_questions": [],
        "dependency_decisions": [],
        "evidence_snapshot": [
            {"evidence_ref": "identity-confirmation", "digest": "sha256:" + "7" * 64}
        ],
        "dependency_snapshot_digest": aggregate_reference_digest([]),
        "evidence_digest": aggregate_reference_digest(
            [{"evidence_ref": "identity-confirmation", "digest": "sha256:" + "7" * 64}]
        ),
        "user_confirmation": None,
    }
    document["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed identity domain completion.",
        "source_evidence_ref": "identity-confirmation",
        "source_text_digest": "sha256:" + "7" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(document),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": "identity",
                "decision": "confirmed",
                "rationale": "Reviewed identity domain.",
            }
        ],
    }
    return DomainDecision.model_validate(document)


def test_domain_coverage_has_twelve_independent_not_declared_axes() -> None:
    axes = analyze_domain_coverage(ValidationReport())
    document = axes.model_dump(mode="json")

    assert list(document) == [
        "domain_disposition",
        "business_goals",
        "candidate_classification",
        "semantics_provenance",
        "identity_authorization",
        "action_lifecycle",
        "conflict_control",
        "idempotency",
        "outcome_resolution",
        "verification",
        "cross_domain_dependency",
        "user_decision_trace",
    ]
    assert {axis["status"] for axis in document.values()} == {"not_declared"}
    serialized = json.dumps(document)
    assert "score" not in serialized
    assert "usable" not in serialized
    assert "overall" not in serialized


def test_domain_coverage_keeps_deferred_action_safety_and_verification_orthogonal() -> None:
    axes = analyze_domain_coverage(_domain_report())

    assert axes.domain_disposition.accepted_candidate_ids == ["crm.customer.read"]
    assert axes.domain_disposition.deferred_candidate_ids == ["crm.customer.update"]
    assert axes.domain_disposition.blocked_candidate_ids == []
    assert axes.candidate_classification.action_candidate_ids == ["crm.customer.update"]
    assert axes.semantics_provenance.unproven_candidate_ids == ["crm.customer.update"]
    assert axes.action_lifecycle.unproven_candidate_ids == ["crm.customer.update"]
    assert axes.conflict_control.unproven_candidate_ids == ["crm.customer.update"]
    assert axes.idempotency.unproven_candidate_ids == ["crm.customer.update"]
    assert axes.outcome_resolution.unproven_candidate_ids == ["crm.customer.update"]
    assert axes.verification.level_by_candidate["crm.customer.update"] == (
        "source_connected_verified"
    )
    assert axes.identity_authorization.unknown_candidate_ids == ["crm.customer.update"]
    assert axes.user_decision_trace.deferred_candidate_ids == ["crm.customer.update"]


def test_read_route_closure_does_not_hide_an_accepted_but_blocked_action() -> None:
    report = _domain_report()
    decision = report.domain_decisions[("crm", 1)]
    document = decision.model_dump(mode="json", by_alias=True)
    document["candidate_dispositions"][1] = {
        "candidate_id": "crm.customer.update",
        "disposition": "accepted",
        "materialized_capability_ids": ["customer.update"],
        "rationale": "Accepted before safety evidence was complete.",
    }
    report.domain_decisions[("crm", 1)] = DomainDecision.model_validate(document)

    axes = analyze_domain_coverage(report)

    assert axes.domain_disposition.accepted_candidate_ids == [
        "crm.customer.read",
        "crm.customer.update",
    ]
    assert axes.domain_disposition.blocked_candidate_ids == ["crm.customer.update"]


def test_domain_coverage_reports_business_authority_and_dependency_facts_without_summary() -> None:
    axes = analyze_domain_coverage(_domain_report())

    assert axes.business_goals.goals_by_domain == {"crm": ["manage_customers"]}
    assert axes.identity_authorization.source_final_candidate_ids == [
        "crm.customer.read",
        "identity.current_user",
    ]
    assert axes.cross_domain_dependency.unresolved_domain_ids == ["identity"]
    assert axes.user_decision_trace.pending_domain_ids == ["crm", "identity"]


def test_domain_coverage_does_not_fall_back_when_active_decision_ref_is_invalid() -> None:
    report = _domain_report()
    assert report.domain_map is not None
    document = report.domain_map.model_dump(mode="json")
    document["domains"][0]["status"] = "completed"
    document["domains"][0]["active_decision_ref"] = {
        "domain_id": "crm",
        "revision": 1,
        "decision_digest": "sha256:" + "0" * 64,
    }
    report.domain_map = DomainMap.model_validate(document)

    axes = analyze_domain_coverage(report)

    assert axes.business_goals.goals_by_domain == {}
    assert axes.business_goals.domains_without_decisions == ["crm", "identity"]
    assert axes.user_decision_trace.pending_domain_ids == ["crm", "identity"]


def test_dependency_and_confirmation_require_an_exact_active_completed_decision() -> None:
    report = _domain_report()
    identity = _completed_identity_decision(report)
    report.domain_decisions[("identity", 1)] = identity
    crm_document = report.domain_decisions[("crm", 1)].model_dump(mode="json", by_alias=True)
    dependency_refs = [
        {
            "domain_id": "identity",
            "revision": 1,
            "decision_digest": domain_decision_digest(identity),
        }
    ]
    crm_document["dependency_decisions"] = dependency_refs
    crm_document["dependency_snapshot_digest"] = aggregate_reference_digest(dependency_refs)
    report.domain_decisions[("crm", 1)] = DomainDecision.model_validate(crm_document)

    axes = analyze_domain_coverage(report)

    assert axes.cross_domain_dependency.resolved_domain_ids == []
    assert axes.cross_domain_dependency.unresolved_domain_ids == ["identity"]
    assert axes.user_decision_trace.confirmed_domain_ids == []
    assert axes.user_decision_trace.pending_domain_ids == ["crm", "identity"]
