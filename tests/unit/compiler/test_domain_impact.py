from __future__ import annotations

import pytest

from acc_core.domains import (
    CapabilityCandidateLedger,
    ChangedEvidenceRef,
    DomainDecision,
    DomainMap,
    aggregate_reference_digest,
    analyze_domain_impact,
    build_change_request,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)
from acc_core.interactions import UIInteractionInventory
from acc_core.models import ActionCapabilityV2, ActionOperationV2
from acc_core.scope import ScopeInventory


def _fact(status: str, *evidence_refs: str) -> dict[str, object]:
    return {"status": status, "evidence_refs": sorted(evidence_refs)}


def _candidate(
    candidate_id: str,
    domain_id: str,
    *,
    evidence_ref: str,
    evidence_axis: str,
    kind: str = "read",
) -> dict[str, object]:
    claims: dict[str, object] = {
        "schema": _fact("proven", f"{candidate_id}-schema"),
        "effect": _fact("proven", f"{candidate_id}-effect"),
        "risk": _fact("proven", f"{candidate_id}-risk"),
        "reversibility": _fact("proven", f"{candidate_id}-reversibility"),
        "approval": _fact("proven", f"{candidate_id}-approval"),
        "retry": _fact("proven", f"{candidate_id}-retry"),
        "conflict_control": _fact("proven", f"{candidate_id}-conflict"),
        "idempotency": _fact("proven", f"{candidate_id}-idempotency"),
        "outcome_resolution": _fact("proven", f"{candidate_id}-outcome"),
        "lifecycle": _fact("proven", f"{candidate_id}-lifecycle"),
        "authorization_boundary": _fact("upstream_authoritative", f"{candidate_id}-authorization"),
        "identity_binding": _fact("identity_binding_proven", f"{candidate_id}-identity"),
        "context_isolation": _fact("context_isolation_proven", f"{candidate_id}-context"),
    }
    claims[evidence_axis] = _fact(
        {
            "authorization_boundary": "upstream_authoritative",
            "identity_binding": "identity_binding_proven",
            "context_isolation": "context_isolation_proven",
        }.get(evidence_axis, "proven"),
        evidence_ref,
    )
    return {
        "id": candidate_id,
        "domain_id": domain_id,
        "business_intent": candidate_id.replace(".", "_"),
        "route_ids": [],
        "interaction_ids": [],
        "kind_claim": kind,
        "effect_claim": "transition" if kind == "action" else "read",
        "claims": claims,
        "verification_level": "semantics_evidenced",
        "gaps": [],
    }


def _completed_decision(
    *,
    domain_id: str,
    candidate_id: str,
    capability_id: str,
    ledger: CapabilityCandidateLedger,
    evidence_ref: str,
    evidence_digest: str,
) -> DomainDecision:
    candidate_ids = [candidate_id]
    evidence_snapshot = sorted(
        [
            {"evidence_ref": evidence_ref, "digest": evidence_digest},
            {
                "evidence_ref": f"confirmation-{domain_id}",
                "digest": "sha256:" + "f" * 64,
            },
        ],
        key=lambda item: item["evidence_ref"],
    )
    document: dict[str, object] = {
        "schema_version": "2",
        "domain_id": domain_id,
        "revision": 1,
        "status": "completed",
        "policy": {
            "goals": [f"manage_{domain_id}"],
            "allowed_effects": ["read", "transition"],
            "maximum_risk": "high",
            "approval_required_for": [],
            "excluded_intents": [],
        },
        "candidate_dispositions": [
            {
                "candidate_id": candidate_id,
                "disposition": "accepted",
                "materialized_capability_ids": [capability_id],
                "rationale": "Accepted after evidence review.",
            }
        ],
        "candidate_snapshot_ids": candidate_ids,
        "candidate_snapshot_digest": aggregate_reference_digest(candidate_ids),
        "candidate_ledger_digest": capability_candidate_ledger_digest(ledger),
        "unresolved_questions": [],
        "dependency_decisions": [],
        "evidence_snapshot": evidence_snapshot,
        "dependency_snapshot_digest": aggregate_reference_digest([]),
        "evidence_digest": aggregate_reference_digest(evidence_snapshot),
        "user_confirmation": None,
    }
    document["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed the completed business domain.",
        "source_evidence_ref": f"confirmation-{domain_id}",
        "source_text_digest": "sha256:" + "f" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(document),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": domain_id,
                "decision": "confirmed",
                "rationale": "Reviewed the exact domain decision.",
            }
        ],
    }
    return DomainDecision.model_validate(document)


def _foundation() -> tuple[
    DomainMap,
    CapabilityCandidateLedger,
    dict[str, DomainDecision],
]:
    orders_digest = "sha256:" + "1" * 64
    candidates = CapabilityCandidateLedger.model_validate(
        {
            "schema_version": "2",
            "candidates": [
                _candidate(
                    "content.search",
                    "content",
                    evidence_ref="content-schema",
                    evidence_axis="schema",
                ),
                _candidate(
                    "identity.current_user",
                    "identity",
                    evidence_ref="identity-binding",
                    evidence_axis="identity_binding",
                ),
                _candidate(
                    "orders.cancel",
                    "orders",
                    evidence_ref="orders-service",
                    evidence_axis="effect",
                    kind="action",
                ),
            ],
        }
    )
    decisions = {
        "content": _completed_decision(
            domain_id="content",
            candidate_id="content.search",
            capability_id="content.search",
            ledger=candidates,
            evidence_ref="content-schema",
            evidence_digest="sha256:" + "2" * 64,
        ),
        "identity": _completed_decision(
            domain_id="identity",
            candidate_id="identity.current_user",
            capability_id="identity.current_user",
            ledger=candidates,
            evidence_ref="identity-binding",
            evidence_digest="sha256:" + "3" * 64,
        ),
        "orders": _completed_decision(
            domain_id="orders",
            candidate_id="orders.cancel",
            capability_id="orders.cancel",
            ledger=candidates,
            evidence_ref="orders-service",
            evidence_digest=orders_digest,
        ),
    }
    domains: list[dict[str, object]] = []
    for domain_id, candidate_id, dependencies, evidence_ref in (
        ("content", "content.search", [], "content-schema"),
        ("identity", "identity.current_user", [], "identity-binding"),
        ("orders", "orders.cancel", ["identity"], "orders-service"),
    ):
        decision = decisions[domain_id]
        domains.append(
            {
                "id": domain_id,
                "title": domain_id.title(),
                "status": "completed",
                "candidate_ids": [candidate_id],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": dependencies,
                "evidence_refs": [evidence_ref],
                "active_decision_ref": {
                    "domain_id": domain_id,
                    "revision": decision.revision,
                    "decision_digest": domain_decision_digest(decision),
                },
            }
        )
    domain_map = DomainMap.model_validate(
        {
            "schema_version": "2",
            "domains": domains,
            "unclassified_candidate_ids": [],
            "preferred_order": ["identity", "orders", "content"],
        }
    )
    return domain_map, candidates, decisions


def test_changed_evidence_marks_only_dependent_domains_stale() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence_ids={"orders-service"},
    )

    assert impact.stale_domain_ids == ("orders",)
    assert impact.unaffected_domain_ids == ("content", "identity")
    assert impact.domains[0].affected_candidate_ids == ("orders.cancel",)
    assert impact.domains[0].affected_capability_ids == ("orders.cancel",)
    assert impact.domains[0].security_axes == ("effect",)


def test_security_change_produces_fail_closed_change_request() -> None:
    domain_map, candidates, decisions = _foundation()
    delta = ChangedEvidenceRef.model_validate(
        {
            "evidence_ref": "orders-service",
            "change": "modified",
            "old_digest": "sha256:" + "1" * 64,
            "new_digest": "sha256:" + "4" * 64,
        }
    )
    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence=[delta],
    )

    request = build_change_request(
        impact=impact.domain("orders"),
        previous_decision=decisions["orders"],
        changed_evidence=impact.changed_evidence,
        created_at="2026-08-10T01:00:00Z",
    )

    assert request.deployment_effect == "disable_affected_capabilities"
    assert request.affected_capability_ids == ["orders.cancel"]
    assert request.affected_candidate_ids == ["orders.cancel"]
    assert request.previous_decision.revision == 1
    assert request.recommended_domain_status == "stale"


def test_structured_delta_digest_cannot_invalidate_another_evidence_id() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence=[
            ChangedEvidenceRef.model_validate(
                {
                    "evidence_ref": "orders-service",
                    "change": "modified",
                    "old_digest": "sha256:" + "1" * 64,
                    "new_digest": "sha256:" + "2" * 64,
                }
            )
        ],
    )

    assert impact.stale_domain_ids == ("orders",)


def test_known_evidence_id_with_unbound_digests_is_not_treated_as_changed() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence=[
            ChangedEvidenceRef.model_validate(
                {
                    "evidence_ref": "orders-service",
                    "change": "modified",
                    "old_digest": "sha256:" + "8" * 64,
                    "new_digest": "sha256:" + "9" * 64,
                }
            )
        ],
    )

    assert impact.stale_domain_ids == ()
    assert impact.unmatched_evidence_ids == ("orders-service",)


def test_descriptive_change_emits_audit_warning_without_security_upgrade() -> None:
    domain_map, candidates, decisions = _foundation()
    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence=[
            ChangedEvidenceRef.model_validate(
                {
                    "evidence_ref": "content-schema",
                    "change": "modified",
                    "old_digest": "sha256:" + "2" * 64,
                    "new_digest": "sha256:" + "5" * 64,
                }
            )
        ],
    )

    request = build_change_request(
        impact=impact.domain("content"),
        previous_decision=decisions["content"],
        changed_evidence=impact.changed_evidence,
        created_at="2026-08-10T01:00:00Z",
    )

    assert request.impact_class == "descriptive_only"
    assert request.deployment_effect == "audit_warning"
    assert request.recommended_domain_status == "stale"


def test_open_domain_is_affected_without_claiming_an_active_decision_is_stale() -> None:
    domain_map, candidates, decisions = _foundation()
    document = domain_map.model_dump(mode="json")
    content = next(item for item in document["domains"] if item["id"] == "content")
    content["status"] = "in_progress"
    content["active_decision_ref"] = None
    domain_map = DomainMap.model_validate(document)

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence_ids={"content-schema"},
    )

    assert impact.affected_domain_ids == ("content",)
    assert impact.stale_domain_ids == ()
    assert impact.unaffected_domain_ids == ("identity", "orders")


def test_security_change_propagates_only_to_transitive_dependents() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence_ids={"identity-binding"},
    )

    assert impact.stale_domain_ids == ("identity", "orders")
    assert impact.unaffected_domain_ids == ("content",)
    orders = impact.domain("orders")
    assert orders.direct is False
    assert orders.upstream_domain_ids == ("identity",)
    assert orders.security_axes == ("dependency:identity_binding",)


def test_changed_snapshot_digest_resolves_exact_evidence_reference() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence_digests={"sha256:" + "1" * 64},
    )

    assert impact.stale_domain_ids == ("orders",)
    assert impact.matched_evidence_ids == ("orders-service",)
    assert impact.unmatched_evidence_digests == ()


def test_unknown_evidence_is_reported_without_broad_domain_invalidation() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence_ids={"unrelated-source"},
    )

    assert impact.stale_domain_ids == ()
    assert impact.unaffected_domain_ids == ("content", "identity", "orders")
    assert impact.unmatched_evidence_ids == ("unrelated-source",)


def test_unknown_structured_delta_is_reported_without_broad_invalidation() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence=[
            ChangedEvidenceRef.model_validate(
                {
                    "evidence_ref": "unrelated-source",
                    "change": "added",
                    "old_digest": None,
                    "new_digest": "sha256:" + "9" * 64,
                }
            )
        ],
    )

    assert impact.stale_domain_ids == ()
    assert impact.unmatched_evidence_ids == ("unrelated-source",)


def _action_operation() -> ActionOperationV2:
    return ActionOperationV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.cancel.operation",
            "title": "Cancel order",
            "input_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object"},
            "http": {
                "method": "POST",
                "path": "/orders/{order_id}/cancel",
                "path_parameters": {"order_id": "order_id"},
                "query_parameters": {},
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": [],
                "timeout_seconds": 15,
                "max_response_bytes": 4096,
                "safety": {
                    "effect": "transition",
                    "risk": "high",
                    "reversibility": "compensatable",
                    "retry": {"mode": "never"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "context_bindings": {},
            "evidence": [
                {
                    "source_id": "orders-mutation-contract",
                    "path": "src/orders/service.py",
                    "line_start": 10,
                    "line_end": 25,
                    "digest": "sha256:" + "6" * 64,
                }
            ],
        }
    )


def _action_capability() -> ActionCapabilityV2:
    return ActionCapabilityV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.cancel",
            "title": "Cancel order",
            "description": "Preview and cancel one order.",
            "input_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object"},
            "action": {
                "execution_mode": "single",
                "approval": {"mode": "required"},
                "expires_in_seconds": 300,
            },
            "preview_workflow": [{"emit": {"value": {"ready": True}}}],
            "commit_workflow": [
                {
                    "call": {
                        "operation": "orders.cancel.operation",
                        "arguments": {"order_id": "$.prepared.input.order_id"},
                    }
                }
            ],
            "policy": "orders-write",
            "evals": ["orders-cancel-success"],
        }
    )


def test_action_operation_evidence_traces_through_materialized_capability() -> None:
    domain_map, candidates, decisions = _foundation()

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        capabilities={"orders.cancel": _action_capability()},
        operations={"orders.cancel.operation": _action_operation()},
        changed_evidence_ids={"orders-mutation-contract"},
    )

    assert impact.stale_domain_ids == ("orders",)
    orders = impact.domain("orders")
    assert orders.affected_candidate_ids == ("orders.cancel",)
    assert orders.affected_capability_ids == ("orders.cancel",)
    assert orders.security_axes == ("operation_safety",)


def test_scope_route_maps_to_distinct_operation_id_without_guessing() -> None:
    domain_map, candidates, decisions = _foundation()
    document = candidates.model_dump(mode="json", by_alias=True)
    orders = next(item for item in document["candidates"] if item["id"] == "orders.cancel")
    orders["route_ids"] = ["POST /orders/{order_id}/cancel"]
    candidates = CapabilityCandidateLedger.model_validate(document)
    scope_inventory = ScopeInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": ["orders"]},
            "domains": [{"id": "orders", "status": "selected"}],
            "routes": [
                {
                    "id": "POST /orders/{order_id}/cancel",
                    "domain": "orders",
                    "method": "POST",
                    "kind": "action",
                    "effect": "transition",
                    "path": "/orders/{order_id}/cancel",
                    "evidence_sources": ["orders-route"],
                    "usage_evidence_sources": [],
                    "interaction_ids": [],
                    "eligibility": "eligible",
                    "disposition": "planned",
                    "operation_id": "orders.cancel.operation",
                    "capability_ids": ["orders.cancel"],
                    "candidate_id": "orders.cancel",
                }
            ],
            "summary": {
                "discovered_routes": 1,
                "eligible_routes": 1,
                "planned": 1,
                "composed": 0,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        }
    )

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        operations={"orders.cancel.operation": _action_operation()},
        scope_inventory=scope_inventory,
        changed_evidence_ids={"orders-mutation-contract"},
    )

    assert impact.domain("orders").affected_capability_ids == ("orders.cancel",)
    assert impact.domain("orders").security_axes == ("operation_safety",)


def test_action_interaction_evidence_is_security_relevant() -> None:
    domain_map, candidates, decisions = _foundation()
    candidate_document = candidates.model_dump(mode="json", by_alias=True)
    orders_candidate = next(
        item for item in candidate_document["candidates"] if item["id"] == "orders.cancel"
    )
    orders_candidate["interaction_ids"] = ["orders.cancel.confirm"]
    candidates = CapabilityCandidateLedger.model_validate(candidate_document)
    inventory = UIInteractionInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "complete", "evidence_sources": ["orders-page"]},
            "surfaces": [
                {
                    "id": "orders-page",
                    "kind": "page",
                    "route_or_entry": "/orders",
                    "business_purpose": "Manage orders",
                    "evidence_sources": ["orders-page"],
                }
            ],
            "interactions": [
                {
                    "id": "orders.cancel.confirm",
                    "surface_id": "orders-page",
                    "business_intent": "cancel_order",
                    "trigger": {"kind": "confirm"},
                    "route_ids": [],
                    "call_order": "sequential",
                    "input_bindings": [],
                    "defaults": [],
                    "option_sources": [],
                    "conditions": [],
                    "related_data": [],
                    "result_consumption": [],
                    "states": [],
                    "evidence_claims": [
                        {
                            "target_pointer": "/interactions/0/trigger",
                            "evidence": {
                                "source_id": "orders-confirm-dialog",
                                "path": "ui/orders/cancel-dialog.ts",
                                "line_start": 1,
                                "line_end": 20,
                                "digest": "sha256:" + "7" * 64,
                            },
                            "authority": "implementation",
                        }
                    ],
                    "unknowns": [],
                }
            ],
            "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
        }
    )

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        interactions=inventory,
        changed_evidence_ids={"orders-confirm-dialog"},
    )

    assert impact.domain("orders").security_axes == ("interaction_semantics",)


@pytest.mark.parametrize("axis", ["lifecycle", "retry", "reversibility", "schema"])
def test_action_contract_axes_fail_closed_while_read_schema_stays_descriptive(
    axis: str,
) -> None:
    domain_map, candidates, decisions = _foundation()
    document = candidates.model_dump(mode="json", by_alias=True)
    orders = next(item for item in document["candidates"] if item["id"] == "orders.cancel")
    orders["claims"][axis] = {
        "status": "proven",
        "evidence_refs": [f"orders-{axis}-contract"],
    }
    candidates = CapabilityCandidateLedger.model_validate(document)

    impact = analyze_domain_impact(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        changed_evidence_ids={f"orders-{axis}-contract"},
    )

    assert impact.domain("orders").security_axes == (axis,)
