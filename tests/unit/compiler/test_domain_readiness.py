from __future__ import annotations

import pytest

from acc_core.domains import (
    CapabilityCandidate,
    CapabilityCandidateLedger,
    DomainDecision,
    DomainEntry,
    aggregate_reference_digest,
    analyze_candidate_readiness,
    analyze_domain_readiness,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)


def _fact(status: str = "unknown", *evidence_refs: str) -> dict[str, object]:
    return {"status": status, "evidence_refs": sorted(evidence_refs)}


def _candidate(
    candidate_id: str,
    *,
    gaps: list[str] | None = None,
    authorization: str = "upstream_authoritative",
    identity: str = "identity_binding_proven",
    context: str = "context_isolation_proven",
) -> CapabilityCandidate:
    evidence = ["source-auth"]
    proven = _fact("proven", "source-contract")
    claims = {
        "schema": proven,
        "effect": proven,
        "risk": proven,
        "reversibility": proven,
        "approval": proven,
        "retry": proven,
        "conflict_control": proven,
        "idempotency": proven,
        "outcome_resolution": proven,
        "lifecycle": proven,
        "authorization_boundary": _fact(
            authorization, *(evidence if authorization != "unknown" else [])
        ),
        "identity_binding": _fact(
            identity,
            *(evidence if identity in {"identity_binding_proven", "contradicted", "stale"} else []),
        ),
        "context_isolation": _fact(
            context,
            *(evidence if context in {"context_isolation_proven", "contradicted", "stale"} else []),
        ),
    }
    return CapabilityCandidate.model_validate(
        {
            "id": candidate_id,
            "domain_id": "orders",
            "business_intent": candidate_id.replace(".", "_"),
            "route_ids": [],
            "interaction_ids": [],
            "kind_claim": "action" if candidate_id.endswith("cancel") else "read",
            "effect_claim": "transition" if candidate_id.endswith("cancel") else "read",
            "claims": claims,
            "verification_level": "action_discovered",
            "gaps": sorted(gaps or []),
        }
    )


def _ledger(candidates: list[CapabilityCandidate]) -> CapabilityCandidateLedger:
    return CapabilityCandidateLedger(
        schema_version="2", candidates=sorted(candidates, key=lambda item: item.id)
    )


def _domain(
    candidate_ids: list[str],
    *,
    dependencies: list[str] | None = None,
    status: str = "ready_for_review",
) -> DomainEntry:
    return DomainEntry.model_validate(
        {
            "id": "orders",
            "title": "Orders",
            "status": status,
            "candidate_ids": sorted(candidate_ids),
            "route_ids": [],
            "interaction_ids": [],
            "dependency_domain_ids": sorted(dependencies or []),
            "evidence_refs": [],
            "active_decision_ref": None,
        }
    )


def _decision(
    ledger: CapabilityCandidateLedger,
    dispositions: dict[str, str],
    *,
    status: str = "ready_for_review",
    dependencies: dict[str, DomainDecision] | None = None,
) -> DomainDecision:
    dependency_decisions = [
        {
            "domain_id": domain_id,
            "revision": target.revision,
            "decision_digest": domain_decision_digest(target),
        }
        for domain_id, target in sorted((dependencies or {}).items())
    ]
    candidate_ids = sorted(dispositions)
    document: dict[str, object] = {
        "schema_version": "2",
        "domain_id": "orders",
        "revision": 1,
        "status": status,
        "policy": {
            "goals": ["manage_orders"],
            "allowed_effects": ["read", "transition"],
            "maximum_risk": "high",
            "approval_required_for": [],
            "excluded_intents": [],
        },
        "candidate_dispositions": [
            {
                "candidate_id": candidate_id,
                "disposition": disposition,
                "materialized_capability_ids": (
                    [candidate_id] if disposition == "accepted" else []
                ),
                "rationale": f"{disposition} by reviewer.",
            }
            for candidate_id, disposition in sorted(dispositions.items())
        ],
        "candidate_snapshot_ids": candidate_ids,
        "candidate_snapshot_digest": aggregate_reference_digest(candidate_ids),
        "candidate_ledger_digest": capability_candidate_ledger_digest(ledger),
        "unresolved_questions": [],
        "dependency_decisions": dependency_decisions,
        "evidence_snapshot": [],
        "dependency_snapshot_digest": aggregate_reference_digest(dependency_decisions),
        "evidence_digest": aggregate_reference_digest([]),
        "user_confirmation": None,
    }
    return DomainDecision.model_validate(document)


def _completed_dependency(domain_id: str, candidate_id: str) -> DomainDecision:
    candidate = _candidate(candidate_id)
    candidate = candidate.model_copy(update={"domain_id": domain_id})
    ledger = _ledger([candidate])
    decision = _decision(ledger, {candidate_id: "accepted"})
    document = decision.model_dump(mode="json", by_alias=True)
    document["domain_id"] = domain_id
    document["status"] = "completed"
    document["evidence_snapshot"] = [
        {"evidence_ref": f"confirmation-{domain_id}", "digest": "sha256:" + "a" * 64}
    ]
    document["evidence_digest"] = aggregate_reference_digest(document["evidence_snapshot"])
    document["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed dependency domain completion.",
        "source_evidence_ref": f"confirmation-{domain_id}",
        "source_text_digest": "sha256:" + "a" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(document),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": domain_id,
                "decision": "confirmed",
                "rationale": "Reviewed dependency domain.",
            }
        ],
    }
    return DomainDecision.model_validate(document)


def test_candidate_source_authority_is_final_only_with_all_three_proofs() -> None:
    complete = analyze_candidate_readiness(_candidate("orders.search"))
    missing_context = analyze_candidate_readiness(_candidate("orders.search", context="unknown"))

    assert complete.authorization_status == "source_final"
    assert complete.blocking_gaps == ()
    assert missing_context.authorization_status == "unknown"


@pytest.mark.parametrize(
    ("axis", "status", "code"),
    [
        (
            "authorization_boundary",
            "contradicted",
            "ACC_DOMAIN_SOURCE_AUTHORITY_OVERRIDDEN",
        ),
        (
            "authorization_boundary",
            "stale",
            "ACC_DOMAIN_AUTHORIZATION_BOUNDARY_STALE",
        ),
        (
            "identity_binding",
            "contradicted",
            "ACC_DOMAIN_IDENTITY_BINDING_CONTRADICTED",
        ),
        ("identity_binding", "stale", "ACC_DOMAIN_IDENTITY_BINDING_STALE"),
        (
            "context_isolation",
            "contradicted",
            "ACC_DOMAIN_CONTEXT_ISOLATION_CONTRADICTED",
        ),
        ("context_isolation", "stale", "ACC_DOMAIN_CONTEXT_ISOLATION_STALE"),
    ],
)
def test_candidate_authority_claim_diagnostics_identify_the_exact_axis(
    axis: str, status: str, code: str
) -> None:
    candidate = _candidate("orders.search")
    document = candidate.model_dump(mode="json", by_alias=True)
    document["claims"][axis] = {"status": status, "evidence_refs": ["source-auth"]}
    candidate = CapabilityCandidate.model_validate(document)
    ledger = _ledger([candidate])

    report = analyze_domain_readiness(
        domain=_domain([candidate.id]),
        candidate_ledger=ledger,
        decision=_decision(ledger, {candidate.id: "accepted"}),
    )

    diagnostic = next(item for item in report.diagnostics if item.code == code)
    assert diagnostic.pointer == f"/candidates/0/claims/{axis}"


def test_candidate_readiness_derives_blocking_axes_when_ai_declares_no_gaps() -> None:
    document = _candidate("orders.search").model_dump(mode="json", by_alias=True)
    document["claims"]["schema"] = {"status": "unknown", "evidence_refs": []}
    candidate = CapabilityCandidate.model_validate(document)

    readiness = analyze_candidate_readiness(candidate)

    assert readiness.blocking_gaps == ("schema",)


def test_action_readiness_derives_every_safety_axis_from_typed_claims() -> None:
    document = _candidate("orders.cancel").model_dump(mode="json", by_alias=True)
    for axis in (
        "approval",
        "conflict_control",
        "idempotency",
        "lifecycle",
        "outcome_resolution",
        "retry",
        "reversibility",
        "risk",
    ):
        document["claims"][axis] = {"status": "unknown", "evidence_refs": []}
    candidate = CapabilityCandidate.model_validate(document)

    readiness = analyze_candidate_readiness(candidate)

    assert readiness.blocking_gaps == (
        "approval",
        "conflict_control",
        "idempotency",
        "lifecycle",
        "outcome_resolution",
        "retry",
        "reversibility",
        "risk",
    )


def test_unknown_candidate_kind_is_always_blocked() -> None:
    document = _candidate("orders.search").model_dump(mode="json", by_alias=True)
    document["kind_claim"] = "unknown"
    document["effect_claim"] = "unknown"
    candidate = CapabilityCandidate.model_validate(document)

    assert analyze_candidate_readiness(candidate).blocking_gaps == ("kind",)


def test_domain_readiness_separates_accepted_gaps_from_user_deferral() -> None:
    search = _candidate("orders.search")
    cancel = _candidate("orders.cancel", gaps=["conflict_control"])
    ledger = _ledger([cancel, search])
    deferred = _decision(
        ledger,
        {"orders.cancel": "deferred", "orders.search": "accepted"},
    )

    report = analyze_domain_readiness(
        domain=_domain(["orders.cancel", "orders.search"]),
        candidate_ledger=ledger,
        decision=deferred,
    )

    assert report.status == "ready_for_review"
    assert report.accepted_candidate_ids == ("orders.search",)
    assert report.deferred_candidate_ids == ("orders.cancel",)
    assert report.blocked_candidate_ids == ()
    assert "ACC_DOMAIN_CANDIDATE_BLOCKED" not in {item.code for item in report.diagnostics}

    accepted = _decision(
        ledger,
        {"orders.cancel": "accepted", "orders.search": "accepted"},
    )
    report = analyze_domain_readiness(
        domain=_domain(["orders.cancel", "orders.search"]),
        candidate_ledger=ledger,
        decision=accepted,
    )
    assert report.status == "validation_failed"
    assert report.blocked_candidate_ids == ("orders.cancel",)
    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_DOMAIN_CANDIDATE_BLOCKED"
    )
    assert diagnostic.pointer == "/candidate_dispositions/0"
    assert "conflict_control" not in diagnostic.message


def test_domain_readiness_reports_deterministic_dependency_states() -> None:
    candidate = _candidate("orders.search")
    ledger = _ledger([candidate])
    identity = _completed_dependency("identity", "identity.current_user")
    billing = _completed_dependency("billing", "billing.invoice")
    billing = billing.model_copy(update={"status": "stale"})
    decision = _decision(
        ledger,
        {"orders.search": "accepted"},
        dependencies={"billing": billing, "identity": identity},
    )

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"], dependencies=["accounting", "billing", "identity"]),
        candidate_ledger=ledger,
        decision=decision,
        dependency_decisions={"billing": billing, "identity": identity},
    )

    assert [(item.domain_id, item.status) for item in report.dependencies] == [
        ("accounting", "unresolved"),
        ("billing", "stale"),
        ("identity", "resolved"),
    ]
    assert report.status == "validation_failed"
    assert [item.code for item in report.diagnostics].count("ACC_DOMAIN_DEPENDENCY_UNRESOLVED") == 2


def test_dependency_diagnostics_use_exact_distinct_decision_pointers() -> None:
    candidate = _candidate("orders.search")
    ledger = _ledger([candidate])
    billing = _completed_dependency("billing", "billing.invoice").model_copy(
        update={"status": "stale"}
    )
    identity = _completed_dependency("identity", "identity.current_user").model_copy(
        update={"status": "stale"}
    )
    decision = _decision(
        ledger,
        {"orders.search": "accepted"},
        dependencies={"billing": billing, "identity": identity},
    )

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"], dependencies=["billing", "identity"]),
        candidate_ledger=ledger,
        decision=decision,
        dependency_decisions={"billing": billing, "identity": identity},
    )

    assert [
        item.pointer
        for item in report.diagnostics
        if item.code == "ACC_DOMAIN_DEPENDENCY_UNRESOLVED"
    ] == ["/dependency_decisions/0", "/dependency_decisions/1"]


def test_dependency_diagnostics_without_decision_point_to_domain_map_entries() -> None:
    candidate = _candidate("orders.search")
    ledger = _ledger([candidate])

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"], dependencies=["billing", "identity"]),
        candidate_ledger=ledger,
        decision=None,
    )

    assert [
        item.pointer
        for item in report.diagnostics
        if item.code == "ACC_DOMAIN_DEPENDENCY_UNRESOLVED"
    ] == ["/dependency_domain_ids/0", "/dependency_domain_ids/1"]


def test_stale_ledger_unconfirmed_completion_and_authority_contradiction_fail_closed() -> None:
    candidate = _candidate("orders.search", authorization="contradicted")
    ledger = _ledger([candidate])
    decision = _decision(ledger, {"orders.search": "accepted"})
    stale = decision.model_copy(update={"candidate_ledger_digest": "sha256:" + "0" * 64})
    unconfirmed = decision.model_copy(update={"status": "completed"})

    stale_report = analyze_domain_readiness(
        domain=_domain(["orders.search"]),
        candidate_ledger=ledger,
        decision=stale,
    )
    unconfirmed_report = analyze_domain_readiness(
        domain=_domain(["orders.search"]),
        candidate_ledger=ledger,
        decision=unconfirmed,
    )

    assert {
        "ACC_DOMAIN_DECISION_STALE",
        "ACC_DOMAIN_SOURCE_AUTHORITY_OVERRIDDEN",
    } <= {item.code for item in stale_report.diagnostics}
    assert "ACC_DOMAIN_DECISION_UNCONFIRMED" in {
        item.code for item in unconfirmed_report.diagnostics
    }
    assert stale_report.status == "validation_failed"
    assert unconfirmed_report.status == "validation_failed"


def test_explicit_stale_decision_remains_stale_while_emitting_a_gate_diagnostic() -> None:
    candidate = _candidate("orders.search")
    ledger = _ledger([candidate])
    decision = _decision(ledger, {"orders.search": "accepted"}).model_copy(
        update={"status": "stale"}
    )

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"]),
        candidate_ledger=ledger,
        decision=decision,
    )

    assert report.status == "stale"
    assert "ACC_DOMAIN_DECISION_STALE" in {item.code for item in report.diagnostics}


def test_readiness_uses_full_ledger_digest_without_cross_domain_diagnostic_leakage() -> None:
    orders = _candidate("orders.search")
    identity = _candidate("identity.current_user", authorization="contradicted").model_copy(
        update={"domain_id": "identity"}
    )
    ledger = _ledger([identity, orders])
    decision = _decision(ledger, {"orders.search": "accepted"})

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"]),
        candidate_ledger=ledger,
        decision=decision,
    )

    assert report.status == "ready_for_review"
    assert not {
        "ACC_DOMAIN_DECISION_STALE",
        "ACC_DOMAIN_SOURCE_AUTHORITY_OVERRIDDEN",
    } & {item.code for item in report.diagnostics}


def test_typed_unresolved_questions_make_readiness_await_user() -> None:
    candidate = _candidate("orders.search")
    ledger = _ledger([candidate])
    decision = _decision(ledger, {"orders.search": "accepted"}).model_copy(
        update={"unresolved_questions": ["Choose the retention policy."]}
    )

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"]),
        candidate_ledger=ledger,
        decision=decision,
    )

    assert report.status == "awaiting_user"


def test_no_decision_readiness_is_derived_instead_of_trusting_domain_status() -> None:
    blocked = _candidate("orders.search", gaps=["schema"])
    blocked_ledger = _ledger([blocked])
    blocked_report = analyze_domain_readiness(
        domain=_domain(["orders.search"], status="awaiting_user"),
        candidate_ledger=blocked_ledger,
        decision=None,
    )

    ready = _candidate("orders.search")
    ready_ledger = _ledger([ready])
    ready_report = analyze_domain_readiness(
        domain=_domain(["orders.search"], status="in_progress"),
        candidate_ledger=ready_ledger,
        decision=None,
    )

    assert blocked_report.status == "in_progress"
    assert ready_report.status == "awaiting_user"


def test_authority_diagnostic_pointer_uses_the_full_ledger_index() -> None:
    identity = _candidate("identity.current_user").model_copy(update={"domain_id": "identity"})
    orders = _candidate("orders.search", authorization="contradicted")
    ledger = _ledger([identity, orders])
    decision = _decision(ledger, {"orders.search": "accepted"})

    report = analyze_domain_readiness(
        domain=_domain(["orders.search"]),
        candidate_ledger=ledger,
        decision=decision,
    )

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_DOMAIN_SOURCE_AUTHORITY_OVERRIDDEN"
    )
    assert diagnostic.pointer == "/candidates/1/claims/authorization_boundary"
