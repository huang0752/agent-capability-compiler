from __future__ import annotations

import copy
import hashlib

import pytest
from pydantic import ValidationError

from acc_core.domains import (
    CapabilityCandidateLedger,
    DomainChangeRequest,
    DomainDecision,
    DomainMap,
    aggregate_reference_digest,
    domain_decision_digest,
)


def _domain_map() -> dict[str, object]:
    return {
        "schema_version": "2",
        "domains": [
            {
                "id": "identity",
                "title": "Identity",
                "status": "completed",
                "candidate_ids": ["identity.current_user"],
                "route_ids": ["GET /api/me"],
                "interaction_ids": [],
                "dependency_domain_ids": [],
                "evidence_refs": ["identity-router"],
                "active_decision_ref": {
                    "domain_id": "identity",
                    "revision": 2,
                    "decision_digest": "sha256:" + "1" * 64,
                },
            },
            {
                "id": "orders",
                "title": "Orders",
                "status": "not_started",
                "candidate_ids": ["orders.cancel"],
                "route_ids": ["POST /api/orders/{order_id}/cancel"],
                "interaction_ids": ["orders.cancel.button"],
                "dependency_domain_ids": ["identity"],
                "evidence_refs": ["orders-router"],
                "active_decision_ref": None,
            },
        ],
        "unclassified_candidate_ids": ["unknown.operation"],
        "preferred_order": ["identity", "orders"],
    }


def _unknown_fact() -> dict[str, object]:
    return {"status": "unknown", "evidence_refs": []}


def _claims() -> dict[str, object]:
    return {
        "schema": {"status": "proven", "evidence_refs": ["orders-schema"]},
        "effect": {"status": "candidate", "evidence_refs": ["orders-service"]},
        "risk": _unknown_fact(),
        "reversibility": _unknown_fact(),
        "approval": _unknown_fact(),
        "retry": _unknown_fact(),
        "conflict_control": {"status": "missing", "evidence_refs": []},
        "idempotency": _unknown_fact(),
        "outcome_resolution": _unknown_fact(),
        "lifecycle": _unknown_fact(),
        "authorization_boundary": {
            "status": "upstream_authoritative",
            "evidence_refs": ["orders-auth"],
        },
        "identity_binding": {
            "status": "identity_binding_proven",
            "evidence_refs": ["orders-auth"],
        },
        "context_isolation": {
            "status": "context_isolation_proven",
            "evidence_refs": ["orders-auth"],
        },
    }


def _candidate_ledger(*, domain_id: str | None = "orders") -> dict[str, object]:
    return {
        "schema_version": "2",
        "candidates": [
            {
                "id": "orders.cancel",
                "domain_id": domain_id,
                "business_intent": "cancel_order",
                "route_ids": ["POST /api/orders/{order_id}/cancel"],
                "interaction_ids": ["orders.cancel.button"],
                "kind_claim": "action",
                "effect_claim": "transition",
                "claims": _claims(),
                "verification_level": "action_discovered",
                "gaps": ["conflict_control"],
            }
        ],
    }


def _dependency_refs() -> list[dict[str, object]]:
    return [
        {
            "domain_id": "identity",
            "revision": 2,
            "decision_digest": "sha256:" + "c" * 64,
        }
    ]


def _evidence_refs() -> list[dict[str, object]]:
    return [
        {"evidence_ref": "orders-auth", "digest": "sha256:" + "d" * 64},
        {"evidence_ref": "orders-service", "digest": "sha256:" + "e" * 64},
    ]


def _decision(*, status: str = "ready_for_review") -> dict[str, object]:
    dependencies = _dependency_refs()
    evidence = _evidence_refs()
    document: dict[str, object] = {
        "schema_version": "2",
        "domain_id": "orders",
        "revision": 1,
        "status": status,
        "policy": {
            "goals": ["cancel_order", "search_orders"],
            "allowed_effects": ["read", "transition"],
            "maximum_risk": "high",
            "approval_required_for": ["cancel_order"],
            "excluded_intents": [],
        },
        "candidate_dispositions": [
            {
                "candidate_id": "orders.cancel",
                "disposition": "accepted",
                "materialized_capability_ids": ["orders.cancel"],
                "rationale": "Contract is ready for review.",
            }
        ],
        "candidate_snapshot_ids": ["orders.cancel"],
        "candidate_snapshot_digest": aggregate_reference_digest(["orders.cancel"]),
        "candidate_ledger_digest": "sha256:" + "f" * 64,
        "unresolved_questions": [],
        "dependency_decisions": dependencies,
        "evidence_snapshot": evidence,
        "dependency_snapshot_digest": aggregate_reference_digest(dependencies),
        "evidence_digest": aggregate_reference_digest(evidence),
        "user_confirmation": None,
    }
    return document


def _confirmation(decision: dict[str, object]) -> dict[str, object]:
    raw_source_text = "RAW-CONFIRMATION-SENTINEL"
    return {
        "confirmer_ref": "user:reviewer-1",
        "authority": "authenticated_user",
        "confirmation_summary": "Reviewer confirmed the complete domain decision.",
        "source_evidence_ref": "user-confirmation-orders-1",
        "source_text_digest": "sha256:" + hashlib.sha256(raw_source_text.encode()).hexdigest(),
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(decision),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": "orders",
                "decision": "confirmed",
                "rationale": "Reviewed the complete domain result.",
            }
        ],
    }


def test_domain_models_are_frozen_hide_inputs_and_bound_strings() -> None:
    document = DomainMap.model_validate(_domain_map())
    with pytest.raises(ValidationError):
        document.preferred_order = []

    invalid = _domain_map()
    invalid["domains"][0]["title"] = " secret\u0000value "  # type: ignore[index]
    with pytest.raises(ValidationError) as captured:
        DomainMap.model_validate(invalid)
    assert "secret" not in str(captured.value)

    whitespace = _domain_map()
    whitespace["domains"][0]["id"] = " identity "  # type: ignore[index]
    with pytest.raises(ValidationError):
        DomainMap.model_validate(whitespace)


def test_domain_map_rejects_unknown_dependency_cycle_and_partial_preferred_order() -> None:
    unknown = _domain_map()
    unknown["domains"][1]["dependency_domain_ids"] = ["missing"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="known domains"):
        DomainMap.model_validate(unknown)

    cyclic = _domain_map()
    cyclic["domains"][0]["dependency_domain_ids"] = ["orders"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="cycle"):
        DomainMap.model_validate(cyclic)

    partial = _domain_map()
    partial["preferred_order"] = ["orders"]
    with pytest.raises(ValidationError, match="complete domain permutation"):
        DomainMap.model_validate(partial)

    reordered = _domain_map()
    reordered["preferred_order"] = ["orders", "identity"]
    assert DomainMap.model_validate(reordered).preferred_order == ["orders", "identity"]


def test_domain_map_tracks_route_and_interaction_denominators() -> None:
    document = DomainMap.model_validate(_domain_map())
    assert document.domains[1].route_ids == ["POST /api/orders/{order_id}/cancel"]
    assert document.domains[1].interaction_ids == ["orders.cancel.button"]


def test_domain_entry_active_decision_ref_tracks_completed_or_stale_state() -> None:
    completed_without_ref = _domain_map()
    completed_without_ref["domains"][0]["active_decision_ref"] = None  # type: ignore[index]
    with pytest.raises(ValidationError, match="completed or stale domain"):
        DomainMap.model_validate(completed_without_ref)

    wrong_domain = _domain_map()
    wrong_domain["domains"][0]["active_decision_ref"]["domain_id"] = "orders"  # type: ignore[index]
    with pytest.raises(ValidationError, match="same domain"):
        DomainMap.model_validate(wrong_domain)

    premature_ref = _domain_map()
    premature_ref["domains"][1]["active_decision_ref"] = {  # type: ignore[index]
        "domain_id": "orders",
        "revision": 1,
        "decision_digest": "sha256:" + "2" * 64,
    }
    with pytest.raises(ValidationError, match="completed or stale domain"):
        DomainMap.model_validate(premature_ref)


def test_candidate_domain_may_remain_unclassified_without_a_second_disposition_truth() -> None:
    candidate = CapabilityCandidateLedger.model_validate(
        _candidate_ledger(domain_id=None)
    ).candidates[0]
    assert candidate.domain_id is None
    assert not hasattr(candidate, "user_disposition")
    assert candidate.verification_level == "action_discovered"


def test_candidate_claim_axes_are_fixed_and_statuses_are_typed() -> None:
    arbitrary = _candidate_ledger()
    arbitrary["candidates"][0]["claims"]["custom_axis"] = _unknown_fact()  # type: ignore[index]
    with pytest.raises(ValidationError):
        CapabilityCandidateLedger.model_validate(arbitrary)

    invalid_fact = _candidate_ledger()
    invalid_fact["candidates"][0]["claims"]["risk"] = {  # type: ignore[index]
        "status": "upstream_authoritative",
        "evidence_refs": ["orders-auth"],
    }
    with pytest.raises(ValidationError):
        CapabilityCandidateLedger.model_validate(invalid_fact)

    contradicted = _candidate_ledger()
    contradicted["candidates"][0]["claims"]["effect"] = {  # type: ignore[index]
        "status": "contradicted",
        "evidence_refs": ["orders-service"],
    }
    assert (
        CapabilityCandidateLedger.model_validate(contradicted).candidates[0].claims.effect.status
        == "contradicted"
    )


def test_authoritative_claim_requires_evidence_and_deployment_ready_is_rejected() -> None:
    no_evidence = _candidate_ledger()
    no_evidence["candidates"][0]["claims"]["authorization_boundary"][  # type: ignore[index]
        "evidence_refs"
    ] = []
    with pytest.raises(ValidationError, match="authoritative claim requires evidence"):
        CapabilityCandidateLedger.model_validate(no_evidence)

    self_promoted = _candidate_ledger()
    self_promoted["candidates"][0]["verification_level"] = "deployment_ready"  # type: ignore[index]
    with pytest.raises(ValidationError):
        CapabilityCandidateLedger.model_validate(self_promoted)


def test_domain_policy_is_business_only_and_has_set_consistency() -> None:
    permission_policy = _decision()
    permission_policy["policy"]["source_permissions"] = ["orders:write"]  # type: ignore[index]
    with pytest.raises(ValidationError):
        DomainDecision.model_validate(permission_policy)

    overlap = _decision()
    overlap["policy"]["excluded_intents"] = ["cancel_order"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="disjoint"):
        DomainDecision.model_validate(overlap)

    invalid_approval = _decision()
    invalid_approval["policy"]["approval_required_for"] = ["unknown_goal"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="subset of goals"):
        DomainDecision.model_validate(invalid_approval)


def test_candidate_dispositions_are_one_sorted_mutually_exclusive_truth() -> None:
    duplicate = _decision()
    duplicate["candidate_dispositions"] = [
        {
            "candidate_id": "orders.cancel",
            "disposition": "accepted",
            "materialized_capability_ids": ["orders.cancel"],
            "rationale": "Accepted.",
        },
        {
            "candidate_id": "orders.cancel",
            "disposition": "blocked",
            "materialized_capability_ids": [],
            "rationale": "Blocked.",
        },
    ]
    with pytest.raises(ValidationError, match="sorted unique candidate"):
        DomainDecision.model_validate(duplicate)

    materialized_rejection = _decision()
    materialized_rejection["candidate_dispositions"] = [
        {
            "candidate_id": "orders.cancel",
            "disposition": "rejected",
            "materialized_capability_ids": ["orders.cancel"],
            "rationale": "Rejected.",
        }
    ]
    with pytest.raises(ValidationError, match="accepted candidates"):
        DomainDecision.model_validate(materialized_rejection)

    unmaterialized_acceptance = _decision()
    unmaterialized_acceptance["candidate_dispositions"][0][  # type: ignore[index]
        "materialized_capability_ids"
    ] = []
    with pytest.raises(ValidationError, match="accepted candidate must materialize"):
        DomainDecision.model_validate(unmaterialized_acceptance)


def test_reference_aggregate_digests_must_match_details() -> None:
    stale_dependency_digest = _decision()
    stale_dependency_digest["dependency_snapshot_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="dependency snapshot digest"):
        DomainDecision.model_validate(stale_dependency_digest)

    stale_evidence_digest = _decision()
    stale_evidence_digest["evidence_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="evidence snapshot digest"):
        DomainDecision.model_validate(stale_evidence_digest)


def test_candidate_snapshot_is_nonempty_exact_and_digest_bound() -> None:
    empty = _decision()
    empty["candidate_snapshot_ids"] = []
    empty["candidate_snapshot_digest"] = aggregate_reference_digest([])
    with pytest.raises(ValidationError, match="candidate snapshot must not be empty"):
        DomainDecision.model_validate(empty)

    missing_disposition = _decision()
    missing_disposition["candidate_snapshot_ids"] = ["orders.cancel", "orders.search"]
    missing_disposition["candidate_snapshot_digest"] = aggregate_reference_digest(
        ["orders.cancel", "orders.search"]
    )
    with pytest.raises(ValidationError, match="exactly match candidate snapshot"):
        DomainDecision.model_validate(missing_disposition)

    stale_digest = _decision()
    stale_digest["candidate_snapshot_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="candidate snapshot digest"):
        DomainDecision.model_validate(stale_digest)


def test_completed_decision_requires_utc_confirmation_bound_to_canonical_digest() -> None:
    document = _decision(status="completed")
    document["user_confirmation"] = _confirmation(document)
    completed = DomainDecision.model_validate(document)
    assert completed.status == "completed"
    assert "RAW-CONFIRMATION-SENTINEL" not in str(completed.model_dump(mode="json"))

    raw_text = copy.deepcopy(document)
    raw_text["user_confirmation"]["source_text"] = "RAW-CONFIRMATION-SENTINEL"  # type: ignore[index]
    with pytest.raises(ValidationError):
        DomainDecision.model_validate(raw_text)

    non_utc = copy.deepcopy(document)
    non_utc["user_confirmation"]["confirmed_at"] = "2026-08-10T08:00:00+08:00"  # type: ignore[index]
    with pytest.raises(ValidationError, match="UTC"):
        DomainDecision.model_validate(non_utc)

    changed_policy = copy.deepcopy(document)
    changed_policy["policy"]["maximum_risk"] = "critical"  # type: ignore[index]
    with pytest.raises(ValidationError, match="confirmed decision digest"):
        DomainDecision.model_validate(changed_policy)

    changed_disposition = copy.deepcopy(document)
    changed_disposition["candidate_dispositions"][0]["rationale"] = "Changed."  # type: ignore[index]
    with pytest.raises(ValidationError, match="confirmed decision digest"):
        DomainDecision.model_validate(changed_disposition)


def test_domain_confirmation_is_completed_only_and_has_exact_completion_decision() -> None:
    ready = _decision()
    ready["user_confirmation"] = _confirmation(ready)
    with pytest.raises(ValidationError, match="only completed"):
        DomainDecision.model_validate(ready)

    completed = _decision(status="completed")
    completed["user_confirmation"] = _confirmation(completed)
    wrong_use = copy.deepcopy(completed)
    wrong_use["user_confirmation"]["decisions"] = [  # type: ignore[index]
        {
            "kind": "domain_policy",
            "subject_ref": "orders",
            "decision": "confirmed",
            "rationale": "Confirmed policy only.",
        }
    ]
    with pytest.raises(ValidationError, match="domain completion decision"):
        DomainDecision.model_validate(wrong_use)

    wrong_subject = copy.deepcopy(completed)
    wrong_subject["user_confirmation"]["decisions"][0]["subject_ref"] = "identity"  # type: ignore[index]
    with pytest.raises(ValidationError, match="domain completion decision"):
        DomainDecision.model_validate(wrong_subject)

    smuggled_use = copy.deepcopy(completed)
    smuggled_use["user_confirmation"]["decisions"].append(  # type: ignore[index]
        {
            "kind": "domain_policy",
            "subject_ref": "orders",
            "decision": "confirmed",
            "rationale": "Smuggled an unrelated confirmation.",
        }
    )
    with pytest.raises(ValidationError, match="unique domain completion decision"):
        DomainDecision.model_validate(smuggled_use)


def _change_request() -> dict[str, object]:
    return {
        "schema_version": "2",
        "id": "orders-change-2",
        "domain_id": "orders",
        "status": "proposed",
        "created_at": "2026-08-10T00:00:00Z",
        "previous_decision": {
            "domain_id": "orders",
            "revision": 1,
            "decision_digest": "sha256:" + "a" * 64,
        },
        "affected_candidate_ids": ["orders.cancel"],
        "affected_capability_ids": ["orders.cancel"],
        "changed_evidence": [
            {
                "evidence_ref": "orders-service",
                "change": "modified",
                "old_digest": "sha256:" + "b" * 64,
                "new_digest": "sha256:" + "c" * 64,
            }
        ],
        "impact_class": "security_relevant",
        "recommended_domain_status": "stale",
        "recommended_decision_digest": "sha256:" + "d" * 64,
        "deployment_effect": "disable_affected_capabilities",
        "impact_summary": "Conflict-control evidence changed.",
        "confirmation": None,
        "applied_decision_ref": None,
    }


def test_change_request_tracks_incremental_evidence_and_fails_closed() -> None:
    request = DomainChangeRequest.model_validate(_change_request())
    assert request.previous_decision.revision == 1
    assert request.changed_evidence[0].change == "modified"

    unsafe = _change_request()
    unsafe["deployment_effect"] = "audit_warning"
    with pytest.raises(ValidationError, match="security classification"):
        DomainChangeRequest.model_validate(unsafe)

    malformed_delta = _change_request()
    malformed_delta["changed_evidence"][0]["old_digest"] = None  # type: ignore[index]
    with pytest.raises(ValidationError, match="modified evidence"):
        DomainChangeRequest.model_validate(malformed_delta)

    unsafe_status = _change_request()
    unsafe_status["recommended_domain_status"] = "ready_for_review"
    with pytest.raises(ValidationError, match="security-relevant change"):
        DomainChangeRequest.model_validate(unsafe_status)


def test_applied_change_requires_bound_confirmation_and_decision_ref() -> None:
    document = _change_request()
    document["status"] = "applied"
    confirmation_basis = {"confirmed_decision_digest": document["recommended_decision_digest"]}
    document["confirmation"] = {
        "confirmer_ref": "user:reviewer-1",
        "authority": "authenticated_user",
        "confirmation_summary": "Reviewer approved the security change.",
        "source_evidence_ref": "user-confirmation-change-2",
        "source_text_digest": "sha256:" + "e" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        **confirmation_basis,
        "decisions": [
            {
                "kind": "change_request",
                "subject_ref": "orders-change-2",
                "decision": "approved",
                "rationale": "Reviewed the security impact.",
            }
        ],
    }
    document["applied_decision_ref"] = {
        "domain_id": "orders",
        "revision": 2,
        "decision_digest": document["recommended_decision_digest"],
    }
    assert DomainChangeRequest.model_validate(document).status == "applied"

    missing_confirmation = copy.deepcopy(document)
    missing_confirmation["confirmation"] = None
    with pytest.raises(ValidationError, match="applied change request"):
        DomainChangeRequest.model_validate(missing_confirmation)

    wrong_use = copy.deepcopy(document)
    wrong_use["confirmation"]["decisions"] = [  # type: ignore[index]
        {
            "kind": "domain_completion",
            "subject_ref": "orders",
            "decision": "confirmed",
            "rationale": "Confirmed the domain instead.",
        }
    ]
    with pytest.raises(ValidationError, match="change request approval"):
        DomainChangeRequest.model_validate(wrong_use)

    wrong_subject = copy.deepcopy(document)
    wrong_subject["confirmation"]["decisions"][0]["subject_ref"] = "other-change"  # type: ignore[index]
    with pytest.raises(ValidationError, match="change request approval"):
        DomainChangeRequest.model_validate(wrong_subject)

    smuggled_use = copy.deepcopy(document)
    smuggled_use["confirmation"]["decisions"].append(  # type: ignore[index]
        {
            "kind": "domain_policy",
            "subject_ref": "orders",
            "decision": "confirmed",
            "rationale": "Smuggled an unrelated confirmation.",
        }
    )
    with pytest.raises(ValidationError, match="unique change request approval"):
        DomainChangeRequest.model_validate(smuggled_use)

    wrong_digest = copy.deepcopy(document)
    wrong_digest["confirmation"]["confirmed_decision_digest"] = "sha256:" + "0" * 64  # type: ignore[index]
    with pytest.raises(ValidationError, match="recommended decision"):
        DomainChangeRequest.model_validate(wrong_digest)


@pytest.mark.parametrize("field", ["confirmation", "applied_decision_ref"])
def test_superseded_change_rejects_confirmation_and_applied_decision_ref(field: str) -> None:
    document = _change_request()
    document["status"] = "superseded"
    if field == "confirmation":
        document[field] = {
            "confirmer_ref": "user:reviewer-1",
            "authority": "authenticated_user",
            "confirmation_summary": "This request was superseded.",
            "source_evidence_ref": "user-confirmation-change-2",
            "source_text_digest": "sha256:" + "e" * 64,
            "confirmed_at": "2026-08-10T00:00:00Z",
            "confirmed_decision_digest": document["recommended_decision_digest"],
            "decisions": [
                {
                    "kind": "change_request",
                    "subject_ref": "orders-change-2",
                    "decision": "approved",
                    "rationale": "Previously approved.",
                }
            ],
        }
    else:
        document[field] = {
            "domain_id": "orders",
            "revision": 2,
            "decision_digest": document["recommended_decision_digest"],
        }
    with pytest.raises(ValidationError, match="proposed or superseded"):
        DomainChangeRequest.model_validate(document)
