from __future__ import annotations

import copy
from pathlib import Path

import yaml

from acc_core.domains import (
    DomainDecision,
    aggregate_reference_digest,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)
from acc_core.validation import validate_project


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _write_evidence(
    project: Path,
    source_id: str,
    digest: str,
    *,
    filename: str | None = None,
) -> None:
    _write(
        project / "evidence" / (filename or f"{source_id}.yaml"),
        {
            "source_id": source_id,
            "kind": "content_summary",
            "summary": f"Independent audit artifact for {source_id}.",
            "digest": digest,
            "size_bytes": 123,
            "audit": {"captured_by": "test-fixture"},
        },
    )


def _reference_digest(value: object) -> str:
    assert isinstance(value, list)
    return aggregate_reference_digest(value)


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    _write(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "domain-project", "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "TARGET_BASE_URL",
                "auth": {"kind": "none"},
            },
            "quality": {"profile": "standard"},
        },
    )
    return project


def _unknown_claims() -> dict[str, object]:
    fact = {"status": "unknown", "evidence_refs": []}
    return {
        "schema": dict(fact),
        "effect": dict(fact),
        "risk": dict(fact),
        "reversibility": dict(fact),
        "approval": dict(fact),
        "retry": dict(fact),
        "conflict_control": dict(fact),
        "idempotency": dict(fact),
        "outcome_resolution": dict(fact),
        "lifecycle": dict(fact),
        "authorization_boundary": {"status": "unknown", "evidence_refs": []},
        "identity_binding": {"status": "unknown", "evidence_refs": []},
        "context_isolation": {"status": "unknown", "evidence_refs": []},
    }


def _ledger(*, domain_id: str | None = "orders") -> dict[str, object]:
    return {
        "schema_version": "2",
        "candidates": [
            {
                "id": "orders.search",
                "domain_id": domain_id,
                "business_intent": "search_orders",
                "route_ids": [],
                "interaction_ids": [],
                "kind_claim": "read",
                "effect_claim": "read",
                "claims": _unknown_claims(),
                "verification_level": "discovered",
                "gaps": [],
            }
        ],
    }


def _decision(ledger: dict[str, object], *, revision: int = 1) -> dict[str, object]:
    candidate_ids = ["orders.search"]
    decision = {
        "schema_version": "2",
        "domain_id": "orders",
        "revision": revision,
        "status": "stale",
        "policy": {
            "goals": ["search_orders"],
            "allowed_effects": ["read"],
            "maximum_risk": "low",
            "approval_required_for": [],
            "excluded_intents": [],
        },
        "candidate_dispositions": [
            {
                "candidate_id": "orders.search",
                "disposition": "deferred",
                "materialized_capability_ids": [],
                "rationale": "Deferred for later source verification.",
            }
        ],
        "candidate_snapshot_ids": candidate_ids,
        "candidate_snapshot_digest": aggregate_reference_digest(candidate_ids),
        "candidate_ledger_digest": capability_candidate_ledger_digest(ledger),
        "unresolved_questions": [],
        "dependency_decisions": [],
        "evidence_snapshot": [],
        "dependency_snapshot_digest": aggregate_reference_digest([]),
        "evidence_digest": aggregate_reference_digest([]),
        "user_confirmation": None,
    }
    DomainDecision.model_validate(decision)
    return decision


def _domain_map(decision: dict[str, object] | None = None) -> dict[str, object]:
    active_ref = None
    status = "not_started"
    if decision is not None:
        status = "stale"
        active_ref = {
            "domain_id": "orders",
            "revision": decision["revision"],
            "decision_digest": domain_decision_digest(decision),
        }
    return {
        "schema_version": "2",
        "domains": [
            {
                "id": "orders",
                "title": "Orders",
                "status": status,
                "candidate_ids": ["orders.search"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": [],
                "evidence_refs": [],
                "active_decision_ref": active_ref,
            }
        ],
        "unclassified_candidate_ids": [],
        "preferred_order": ["orders"],
    }


def _write_domain_set(project: Path, *, with_decision: bool = True) -> dict[str, object]:
    ledger = _ledger()
    decision = _decision(ledger) if with_decision else None
    _write(project / "domain-map.yaml", _domain_map(decision))
    _write(project / "capability-candidates.yaml", ledger)
    if decision is not None:
        _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", decision)
    return decision or {}


def _codes(project: Path) -> set[str]:
    return {item.code for item in validate_project(project).diagnostics}


def test_project_without_domain_sidecars_has_no_domain_diagnostics(tmp_path: Path) -> None:
    report = validate_project(_project(tmp_path))

    assert report.ok
    assert report.domain_map is None
    assert report.capability_candidate_ledger is None
    assert report.domain_decisions == {}
    assert report.domain_change_requests == {}
    assert not any(item.code.startswith("ACC_DOMAIN_") for item in report.diagnostics)


def test_evidence_registry_loads_core_fields_and_rejects_duplicate_source_id(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    digest = "sha256:" + "a" * 64
    _write_evidence(project, "orders-service", digest, filename="first.yaml")

    report = validate_project(project)

    assert report.ok
    assert report.evidence_registry["orders-service"].digest == digest
    assert report.evidence_paths["orders-service"] == "evidence/first.yaml"

    _write_evidence(project, "orders-service", digest, filename="second.yaml")
    assert "ACC_EVIDENCE_SOURCE_ID_DUPLICATE" in _codes(project)


def test_domain_sidecars_load_typed_paths_and_multiple_revisions(tmp_path: Path) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    first = _decision(ledger, revision=1)
    second = _decision(ledger, revision=2)
    _write(project / "domain-map.yaml", _domain_map(first))
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "first.yaml", first)
    _write(project / "domain-decisions" / "second.yaml", second)

    report = validate_project(project)

    assert report.ok
    assert report.domain_map_path == "domain-map.yaml"
    assert report.capability_candidate_ledger_path == "capability-candidates.yaml"
    assert set(report.domain_decisions) == {("orders", 1), ("orders", 2)}
    assert report.domain_decision_paths[("orders", 2)] == "domain-decisions/second.yaml"


def test_domain_map_and_candidate_ledger_are_an_optional_pair(tmp_path: Path) -> None:
    map_only = _project(tmp_path / "map")
    _write(map_only / "domain-map.yaml", _domain_map())
    ledger_only = _project(tmp_path / "ledger")
    _write(ledger_only / "capability-candidates.yaml", _ledger())

    assert "ACC_DOMAIN_CANDIDATE_LEDGER_MISSING" in _codes(map_only)
    assert "ACC_DOMAIN_MAP_MISSING" in _codes(ledger_only)

    decision_only = _project(tmp_path / "decision")
    _write(
        decision_only / "domain-decisions" / "decision.yaml",
        _decision(_ledger()),
    )
    assert {
        "ACC_DOMAIN_MAP_MISSING",
        "ACC_DOMAIN_CANDIDATE_LEDGER_MISSING",
    } <= _codes(decision_only)


def test_domain_candidate_assignment_is_exact_and_complete(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _write_domain_set(project, with_decision=False)
    ledger = _ledger(domain_id=None)
    _write(project / "capability-candidates.yaml", ledger)

    assert "ACC_DOMAIN_CANDIDATE_DOMAIN_MISMATCH" in _codes(project)

    domain_map = _domain_map()
    domain_map["domains"][0]["candidate_ids"] = []  # type: ignore[index]
    domain_map["unclassified_candidate_ids"] = ["orders.search"]
    _write(project / "domain-map.yaml", domain_map)
    assert validate_project(project).ok

    orphan = copy.deepcopy(ledger)
    orphan["candidates"][0]["id"] = "orders.orphan"  # type: ignore[index]
    _write(project / "capability-candidates.yaml", orphan)
    assert {"ACC_DOMAIN_CANDIDATE_MISSING", "ACC_DOMAIN_CANDIDATE_ORPHAN"} <= _codes(project)


def test_candidate_claim_evidence_must_resolve_through_independent_registry(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    ledger["candidates"][0]["claims"]["schema"] = {  # type: ignore[index]
        "status": "proven",
        "evidence_refs": ["orders-schema"],
    }
    _write(project / "domain-map.yaml", _domain_map())
    _write(project / "capability-candidates.yaml", ledger)

    assert "ACC_DOMAIN_EVIDENCE_UNKNOWN" in _codes(project)


def test_decision_requires_canonical_ledger_active_ref_and_current_completed_revision(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    first = _write_domain_set(project)
    stale_digest = copy.deepcopy(first)
    stale_digest["candidate_ledger_digest"] = "sha256:" + "0" * 64
    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", stale_digest)
    assert "ACC_DOMAIN_DECISION_LEDGER_DIGEST_MISMATCH" in _codes(project)

    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", first)
    domain_map = _domain_map(first)
    domain_map["domains"][0]["active_decision_ref"]["decision_digest"] = (  # type: ignore[index]
        "sha256:" + "1" * 64
    )
    _write(project / "domain-map.yaml", domain_map)
    assert "ACC_DOMAIN_ACTIVE_DECISION_MISMATCH" in _codes(project)

    # A later completed decision supersedes an older active revision; a later draft does not.
    second = _decision(_ledger(), revision=2)
    second["status"] = "completed"
    second["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed the domain completion.",
        "source_evidence_ref": "confirmation-source",
        "source_text_digest": "sha256:" + "a" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(second),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": "orders",
                "decision": "confirmed",
                "rationale": "Reviewed the complete domain.",
            }
        ],
    }
    second["evidence_snapshot"] = [
        {"evidence_ref": "confirmation-source", "digest": "sha256:" + "a" * 64}
    ]
    second["evidence_digest"] = _reference_digest(second["evidence_snapshot"])
    second["user_confirmation"]["confirmed_decision_digest"] = domain_decision_digest(second)  # type: ignore[index]
    DomainDecision.model_validate(second)
    _write(project / "domain-map.yaml", _domain_map(first))
    _write(project / "domain-decisions" / "second.yaml", second)
    assert "ACC_DOMAIN_ACTIVE_DECISION_SUPERSEDED" in _codes(project)


def test_invalid_active_decision_does_not_fallback_to_latest_for_readiness(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    decision = _decision(ledger)
    decision["candidate_dispositions"][0] = {  # type: ignore[index]
        "candidate_id": "orders.search",
        "disposition": "accepted",
        "materialized_capability_ids": ["orders.search"],
        "rationale": "Accepted only in the untrusted latest document.",
    }
    DomainDecision.model_validate(decision)
    domain_map = _domain_map(decision)
    domain_map["domains"][0]["active_decision_ref"]["decision_digest"] = (  # type: ignore[index]
        "sha256:" + "1" * 64
    )
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "latest.yaml", decision)

    codes = _codes(project)

    assert "ACC_DOMAIN_ACTIVE_DECISION_MISMATCH" in codes
    assert "ACC_DOMAIN_CANDIDATE_BLOCKED" not in codes


def test_no_decision_dependency_readiness_maps_to_exact_domain_map_entry(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    identity_candidate = copy.deepcopy(ledger["candidates"][0])  # type: ignore[index]
    identity_candidate["id"] = "identity.search"
    identity_candidate["domain_id"] = "identity"
    ledger["candidates"] = [identity_candidate, ledger["candidates"][0]]  # type: ignore[index]
    domain_map = {
        "schema_version": "2",
        "domains": [
            {
                "id": "identity",
                "title": "Identity",
                "status": "not_started",
                "candidate_ids": ["identity.search"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": [],
                "evidence_refs": [],
                "active_decision_ref": None,
            },
            {
                "id": "orders",
                "title": "Orders",
                "status": "not_started",
                "candidate_ids": ["orders.search"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": ["identity"],
                "evidence_refs": [],
                "active_decision_ref": None,
            },
        ],
        "unclassified_candidate_ids": [],
        "preferred_order": ["identity", "orders"],
    }
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "capability-candidates.yaml", ledger)

    report = validate_project(project)

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_DOMAIN_DEPENDENCY_UNRESOLVED"
    )
    assert diagnostic.path == "domain-map.yaml"
    assert diagnostic.pointer == "/domains/1/dependency_domain_ids/0"


def test_decision_closes_dispositions_dependencies_evidence_and_confirmation(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    decision = _write_domain_set(project)
    missing_capability = copy.deepcopy(decision)
    missing_capability["candidate_dispositions"][0] = {  # type: ignore[index]
        "candidate_id": "orders.search",
        "disposition": "accepted",
        "materialized_capability_ids": ["orders.search"],
        "rationale": "Accepted.",
    }
    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", missing_capability)
    assert "ACC_DOMAIN_MATERIALIZED_CAPABILITY_UNKNOWN" in _codes(project)

    unknown_dependency = copy.deepcopy(decision)
    dependency = {
        "domain_id": "identity",
        "revision": 1,
        "decision_digest": "sha256:" + "b" * 64,
    }
    unknown_dependency["dependency_decisions"] = [dependency]
    unknown_dependency["dependency_snapshot_digest"] = aggregate_reference_digest([dependency])
    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", unknown_dependency)
    assert "ACC_DOMAIN_DEPENDENCY_DECISION_UNKNOWN" in _codes(project)
    assert "ACC_DOMAIN_DEPENDENCY_ACTIVE_DECISION_MISMATCH" in _codes(project)

    completed = copy.deepcopy(decision)
    completed["status"] = "completed"
    completed["evidence_snapshot"] = [
        {"evidence_ref": "confirmation-source", "digest": "sha256:" + "a" * 64}
    ]
    completed["evidence_digest"] = _reference_digest(completed["evidence_snapshot"])
    completed["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed the domain completion.",
        "source_evidence_ref": "confirmation-source",
        "source_text_digest": "sha256:" + "a" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(completed),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": "orders",
                "decision": "confirmed",
                "rationale": "Reviewed the complete domain.",
            }
        ],
    }
    completed["user_confirmation"]["confirmed_decision_digest"] = domain_decision_digest(completed)  # type: ignore[index]
    DomainDecision.model_validate(completed)
    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", completed)
    assert "ACC_DOMAIN_EVIDENCE_UNKNOWN" in _codes(project)

    _write_evidence(project, "confirmation-source", "sha256:" + "b" * 64)
    assert "ACC_DOMAIN_EVIDENCE_DIGEST_MISMATCH" in _codes(project)
    assert "ACC_DOMAIN_CONFIRMATION_EVIDENCE_MISMATCH" in _codes(project)

    incomplete_evidence = copy.deepcopy(decision)
    domain_map = _domain_map(decision)
    domain_map["domains"][0]["evidence_refs"] = ["orders-service"]  # type: ignore[index]
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", incomplete_evidence)
    assert "ACC_DOMAIN_EVIDENCE_SNAPSHOT_INCOMPLETE" in _codes(project)


def test_dependency_ref_matches_active_ref_by_normalized_fields(tmp_path: Path) -> None:
    project = _project(tmp_path)
    orders_candidate = _ledger()["candidates"][0]  # type: ignore[index]
    identity_candidate = copy.deepcopy(orders_candidate)
    identity_candidate["id"] = "identity.me"
    identity_candidate["domain_id"] = "identity"
    identity_candidate["business_intent"] = "inspect_identity"
    ledger: dict[str, object] = {
        "schema_version": "2",
        "candidates": [identity_candidate, orders_candidate],
    }
    identity = _decision(ledger)
    identity["domain_id"] = "identity"
    identity["candidate_dispositions"][0]["candidate_id"] = "identity.me"  # type: ignore[index]
    identity["candidate_snapshot_ids"] = ["identity.me"]
    identity["candidate_snapshot_digest"] = aggregate_reference_digest(["identity.me"])
    identity_ref = {
        "domain_id": "identity",
        "revision": 1,
        "decision_digest": domain_decision_digest(identity),
    }
    orders = _decision(ledger)
    orders["dependency_decisions"] = [identity_ref]
    orders["dependency_snapshot_digest"] = aggregate_reference_digest([identity_ref])
    orders_ref = {
        "domain_id": "orders",
        "revision": 1,
        "decision_digest": domain_decision_digest(orders),
    }
    domain_map = {
        "schema_version": "2",
        "domains": [
            {
                "id": "identity",
                "title": "Identity",
                "status": "stale",
                "candidate_ids": ["identity.me"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": [],
                "evidence_refs": [],
                "active_decision_ref": identity_ref,
            },
            {
                "id": "orders",
                "title": "Orders",
                "status": "stale",
                "candidate_ids": ["orders.search"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": ["identity"],
                "evidence_refs": [],
                "active_decision_ref": orders_ref,
            },
        ],
        "unclassified_candidate_ids": [],
        "preferred_order": ["identity", "orders"],
    }
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "identity.yaml", identity)
    _write(project / "domain-decisions" / "orders.yaml", orders)

    report = validate_project(project)
    codes = {item.code for item in report.diagnostics}
    assert "ACC_DOMAIN_DEPENDENCY_ACTIVE_DECISION_MISMATCH" not in codes
    assert "ACC_DOMAIN_DEPENDENCY_UNRESOLVED" in codes


def test_change_request_references_are_fully_closed(tmp_path: Path) -> None:
    project = _project(tmp_path)
    decision = _write_domain_set(project)
    request: dict[str, object] = {
        "schema_version": "2",
        "id": "orders-change-1",
        "domain_id": "orders",
        "status": "proposed",
        "created_at": "2026-08-10T00:00:00Z",
        "previous_decision": {
            "domain_id": "orders",
            "revision": 1,
            "decision_digest": domain_decision_digest(decision),
        },
        "affected_candidate_ids": ["orders.missing"],
        "affected_capability_ids": ["orders.missing"],
        "changed_evidence": [
            {
                "evidence_ref": "orders-service",
                "change": "modified",
                "old_digest": "sha256:" + "a" * 64,
                "new_digest": "sha256:" + "b" * 64,
            }
        ],
        "impact_class": "security_relevant",
        "recommended_domain_status": "stale",
        "recommended_decision_digest": "sha256:" + "c" * 64,
        "deployment_effect": "disable_affected_capabilities",
        "impact_summary": "Order authorization evidence changed.",
        "confirmation": None,
        "applied_decision_ref": None,
    }
    _write(project / "domain-change-requests" / "arbitrary-safe-name.yaml", request)

    assert {
        "ACC_DOMAIN_CHANGE_CANDIDATE_UNKNOWN",
        "ACC_DOMAIN_CHANGE_CAPABILITY_UNKNOWN",
        "ACC_DOMAIN_EVIDENCE_UNKNOWN",
    } <= _codes(project)

    previous_decision = request["previous_decision"]
    assert isinstance(previous_decision, dict)
    previous_decision["decision_digest"] = "sha256:" + "0" * 64
    _write(project / "domain-change-requests" / "arbitrary-safe-name.yaml", request)
    assert "ACC_DOMAIN_CHANGE_PREVIOUS_DECISION_MISMATCH" in _codes(project)

    decision["evidence_snapshot"] = [
        {"evidence_ref": "confirmation-source", "digest": "sha256:" + "a" * 64}
    ]
    decision["evidence_digest"] = _reference_digest(decision["evidence_snapshot"])
    _write(project / "domain-decisions" / "arbitrary-safe-name.yaml", decision)
    _write(project / "domain-map.yaml", _domain_map(decision))
    request["status"] = "confirmed"
    previous_decision["decision_digest"] = domain_decision_digest(decision)
    request["confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Approved the proposed domain change.",
        "source_evidence_ref": "confirmation-source",
        "source_text_digest": "sha256:" + "d" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": request["recommended_decision_digest"],
        "decisions": [
            {
                "kind": "change_request",
                "subject_ref": "orders-change-1",
                "decision": "approved",
                "rationale": "Reviewed the source evidence change.",
            }
        ],
    }
    _write(project / "domain-change-requests" / "arbitrary-safe-name.yaml", request)
    assert "ACC_DOMAIN_CONFIRMATION_EVIDENCE_MISMATCH" in _codes(project)


def test_confirmed_change_must_start_from_the_current_active_decision(tmp_path: Path) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    first = _decision(ledger, revision=1)
    second = _decision(ledger, revision=2)
    _write(project / "domain-map.yaml", _domain_map(second))
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "first.yaml", first)
    _write(project / "domain-decisions" / "second.yaml", second)
    _write_evidence(project, "orders-service", "sha256:" + "a" * 64)
    request = {
        "schema_version": "2",
        "id": "orders-change-stale-baseline",
        "domain_id": "orders",
        "status": "proposed",
        "created_at": "2026-08-10T00:00:00Z",
        "previous_decision": {
            "domain_id": "orders",
            "revision": 1,
            "decision_digest": domain_decision_digest(first),
        },
        "affected_candidate_ids": ["orders.search"],
        "affected_capability_ids": [],
        "changed_evidence": [
            {
                "evidence_ref": "orders-service",
                "change": "modified",
                "old_digest": "sha256:" + "b" * 64,
                "new_digest": "sha256:" + "a" * 64,
            }
        ],
        "impact_class": "descriptive_only",
        "recommended_domain_status": "stale",
        "recommended_decision_digest": "sha256:" + "c" * 64,
        "deployment_effect": "audit_warning",
        "impact_summary": "Based on an obsolete decision revision.",
        "confirmation": None,
        "applied_decision_ref": None,
    }
    _write(project / "domain-change-requests" / "stale.yaml", request)

    assert "ACC_DOMAIN_CHANGE_PREVIOUS_NOT_ACTIVE" in _codes(project)


def test_applied_change_confirmation_cannot_borrow_another_domain_snapshot(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    orders_candidate = _ledger()["candidates"][0]  # type: ignore[index]
    identity_candidate = copy.deepcopy(orders_candidate)
    identity_candidate["id"] = "identity.me"
    identity_candidate["domain_id"] = "identity"
    identity_candidate["business_intent"] = "inspect_identity"
    ledger: dict[str, object] = {
        "schema_version": "2",
        "candidates": [identity_candidate, orders_candidate],
    }
    first = _decision(ledger, revision=1)
    second = _decision(ledger, revision=2)
    identity = _decision(ledger)
    identity["domain_id"] = "identity"
    identity["candidate_dispositions"][0]["candidate_id"] = "identity.me"  # type: ignore[index]
    identity["candidate_snapshot_ids"] = ["identity.me"]
    identity["candidate_snapshot_digest"] = aggregate_reference_digest(["identity.me"])
    identity["evidence_snapshot"] = [
        {"evidence_ref": "confirmation-source", "digest": "sha256:" + "a" * 64}
    ]
    identity["evidence_digest"] = _reference_digest(identity["evidence_snapshot"])
    identity_ref = {
        "domain_id": "identity",
        "revision": 1,
        "decision_digest": domain_decision_digest(identity),
    }
    second_ref = {
        "domain_id": "orders",
        "revision": 2,
        "decision_digest": domain_decision_digest(second),
    }
    domain_map = {
        "schema_version": "2",
        "domains": [
            {
                "id": "identity",
                "title": "Identity",
                "status": "stale",
                "candidate_ids": ["identity.me"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": [],
                "evidence_refs": [],
                "active_decision_ref": identity_ref,
            },
            {
                "id": "orders",
                "title": "Orders",
                "status": "stale",
                "candidate_ids": ["orders.search"],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": [],
                "evidence_refs": [],
                "active_decision_ref": second_ref,
            },
        ],
        "unclassified_candidate_ids": [],
        "preferred_order": ["identity", "orders"],
    }
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "identity.yaml", identity)
    _write(project / "domain-decisions" / "orders-1.yaml", first)
    _write(project / "domain-decisions" / "orders-2.yaml", second)
    _write_evidence(project, "confirmation-source", "sha256:" + "a" * 64)
    request = {
        "schema_version": "2",
        "id": "orders-change-applied",
        "domain_id": "orders",
        "status": "applied",
        "created_at": "2026-08-10T00:00:00Z",
        "previous_decision": {
            "domain_id": "orders",
            "revision": 1,
            "decision_digest": domain_decision_digest(first),
        },
        "affected_candidate_ids": ["orders.search"],
        "affected_capability_ids": [],
        "changed_evidence": [
            {
                "evidence_ref": "confirmation-source",
                "change": "modified",
                "old_digest": "sha256:" + "b" * 64,
                "new_digest": "sha256:" + "a" * 64,
            }
        ],
        "impact_class": "descriptive_only",
        "recommended_domain_status": "stale",
        "recommended_decision_digest": second_ref["decision_digest"],
        "deployment_effect": "audit_warning",
        "impact_summary": "Applied with cross-domain confirmation evidence.",
        "confirmation": {
            "confirmer_ref": "user:reviewer",
            "authority": "authenticated_user",
            "confirmation_summary": "Approved the applied decision.",
            "source_evidence_ref": "confirmation-source",
            "source_text_digest": "sha256:" + "a" * 64,
            "confirmed_at": "2026-08-10T00:00:00Z",
            "confirmed_decision_digest": second_ref["decision_digest"],
            "decisions": [
                {
                    "kind": "change_request",
                    "subject_ref": "orders-change-applied",
                    "decision": "approved",
                    "rationale": "Reviewed the applied decision.",
                }
            ],
        },
        "applied_decision_ref": second_ref,
    }
    _write(project / "domain-change-requests" / "applied.yaml", request)

    assert "ACC_DOMAIN_CONFIRMATION_EVIDENCE_MISMATCH" in _codes(project)


def test_applied_change_request_resolves_both_decision_revisions(tmp_path: Path) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    first = _decision(ledger, revision=1)
    second = _decision(ledger, revision=2)
    second["evidence_snapshot"] = [
        {"evidence_ref": "confirmation-source", "digest": "sha256:" + "a" * 64}
    ]
    second["evidence_digest"] = _reference_digest(second["evidence_snapshot"])
    _write(project / "domain-map.yaml", _domain_map(second))
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "first.yaml", first)
    _write(project / "domain-decisions" / "second.yaml", second)
    wrong_applied_digest = "sha256:" + "9" * 64
    request = {
        "schema_version": "2",
        "id": "orders-change-applied",
        "domain_id": "orders",
        "status": "applied",
        "created_at": "2026-08-10T00:00:00Z",
        "previous_decision": {
            "domain_id": "orders",
            "revision": 1,
            "decision_digest": domain_decision_digest(first),
        },
        "affected_candidate_ids": ["orders.search"],
        "affected_capability_ids": [],
        "changed_evidence": [
            {
                "evidence_ref": "confirmation-source",
                "change": "modified",
                "old_digest": "sha256:" + "b" * 64,
                "new_digest": "sha256:" + "a" * 64,
            }
        ],
        "impact_class": "descriptive_only",
        "recommended_domain_status": "stale",
        "recommended_decision_digest": wrong_applied_digest,
        "deployment_effect": "audit_warning",
        "impact_summary": "Description changed without changing authorization.",
        "confirmation": {
            "confirmer_ref": "user:reviewer",
            "authority": "authenticated_user",
            "confirmation_summary": "Approved the revised domain decision.",
            "source_evidence_ref": "confirmation-source",
            "source_text_digest": "sha256:" + "a" * 64,
            "confirmed_at": "2026-08-10T00:00:00Z",
            "confirmed_decision_digest": wrong_applied_digest,
            "decisions": [
                {
                    "kind": "change_request",
                    "subject_ref": "orders-change-applied",
                    "decision": "approved",
                    "rationale": "Reviewed the revised decision.",
                }
            ],
        },
        "applied_decision_ref": {
            "domain_id": "orders",
            "revision": 2,
            "decision_digest": wrong_applied_digest,
        },
    }
    _write(project / "domain-change-requests" / "applied.yaml", request)

    assert "ACC_DOMAIN_CHANGE_APPLIED_DECISION_MISMATCH" in _codes(project)


def test_domain_collections_reject_duplicate_symlink_and_oversized_documents(
    tmp_path: Path,
) -> None:
    duplicate = _project(tmp_path / "duplicate")
    decision = _write_domain_set(duplicate)
    _write(duplicate / "domain-decisions" / "second-name.yaml", decision)
    assert "ACC_DOMAIN_DECISION_DUPLICATE" in _codes(duplicate)

    symlink = _project(tmp_path / "symlink")
    _write_domain_set(symlink, with_decision=False)
    outside = tmp_path / "outside.yaml"
    _write(outside, _ledger())
    (symlink / "domain-decisions").mkdir()
    (symlink / "domain-decisions" / "linked.yaml").symlink_to(outside)
    assert "ACC_IO_SYMLINK_REJECTED" in _codes(symlink)

    linked_directory = _project(tmp_path / "linked-directory")
    _write_domain_set(linked_directory, with_decision=False)
    missing_directory = tmp_path / "missing-decisions"
    (linked_directory / "domain-decisions").symlink_to(missing_directory)
    assert "ACC_IO_SYMLINK_REJECTED" in _codes(linked_directory)

    oversized = _project(tmp_path / "oversized")
    _write(oversized / "domain-map.yaml", {"padding": "x" * 1_048_576})
    assert "ACC_IO_FILE_TOO_LARGE" in _codes(oversized)


def test_completed_domain_requires_completed_active_decision(tmp_path: Path) -> None:
    project = _project(tmp_path)
    decision = _write_domain_set(project)
    domain_map = _domain_map(decision)
    domain_map["domains"][0]["status"] = "completed"  # type: ignore[index]
    _write(project / "domain-map.yaml", domain_map)

    assert "ACC_DOMAIN_ACTIVE_DECISION_STATUS_MISMATCH" in _codes(project)


def test_stale_domain_may_reference_completed_active_decision(tmp_path: Path) -> None:
    project = _project(tmp_path)
    decision = _decision(_ledger())
    decision["status"] = "completed"
    decision["evidence_snapshot"] = [
        {"evidence_ref": "confirmation-source", "digest": "sha256:" + "a" * 64}
    ]
    decision["evidence_digest"] = _reference_digest(decision["evidence_snapshot"])
    decision["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed the completed decision.",
        "source_evidence_ref": "confirmation-source",
        "source_text_digest": "sha256:" + "a" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(decision),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": "orders",
                "decision": "confirmed",
                "rationale": "Reviewed the completed decision.",
            }
        ],
    }
    decision["user_confirmation"]["confirmed_decision_digest"] = domain_decision_digest(decision)  # type: ignore[index]
    DomainDecision.model_validate(decision)
    _write_evidence(project, "confirmation-source", "sha256:" + "a" * 64)
    _write(project / "domain-map.yaml", _domain_map(decision))
    _write(project / "capability-candidates.yaml", _ledger())
    _write(project / "domain-decisions" / "completed.yaml", decision)

    assert validate_project(project).ok


def test_project_merges_domain_readiness_diagnostics_without_exposing_gap_text(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    ledger = _ledger()
    ledger["candidates"][0]["gaps"] = ["PRIVATE-CONFLICT-SENTINEL"]  # type: ignore[index]
    decision = _decision(ledger)
    decision["candidate_dispositions"][0] = {  # type: ignore[index]
        "candidate_id": "orders.search",
        "disposition": "accepted",
        "materialized_capability_ids": ["orders.search"],
        "rationale": "Accepted pending final implementation.",
    }
    DomainDecision.model_validate(decision)
    _write(project / "domain-map.yaml", _domain_map(decision))
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "orders-1.yaml", decision)

    report = validate_project(project)

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_DOMAIN_CANDIDATE_BLOCKED"
    )
    assert diagnostic.path == "domain-decisions/orders-1.yaml"
    assert diagnostic.pointer == "/candidate_dispositions/0"
    assert "PRIVATE-CONFLICT-SENTINEL" not in str(diagnostic)
