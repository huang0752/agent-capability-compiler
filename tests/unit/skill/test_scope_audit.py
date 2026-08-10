from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "scope_audit.py"


def _route(
    route_id: str,
    *,
    domain: str = "customer",
    disposition: str = "planned",
    method: str = "GET",
    kind: str = "read",
    effect: str = "read",
    evidence_sources: list[str] | None = None,
    reason: str | None = None,
    operation_id: str | None = "customer.search",
    eligibility: str = "eligible",
    usage_evidence_sources: list[str] | None = None,
    interaction_ids: list[str] | None = None,
    exclusion_rule_id: str | None = None,
    exclusion_decision: dict[str, object] | None = None,
    candidate_id: str | None = None,
    capability_ids: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": route_id,
        "domain": domain,
        "method": method,
        "kind": kind,
        "effect": effect,
        "path": f"/api/{route_id.replace('.', '/')}",
        "evidence_sources": (["customer-routes"] if evidence_sources is None else evidence_sources),
        "eligibility": eligibility,
        "disposition": disposition,
        "operation_id": operation_id,
        "capability_ids": (
            (["search_customers"] if disposition in {"planned", "composed"} else [])
            if capability_ids is None
            else capability_ids
        ),
        **({"candidate_id": candidate_id} if candidate_id is not None else {}),
        "reason": reason,
        **(
            {"usage_evidence_sources": usage_evidence_sources}
            if usage_evidence_sources is not None
            else {}
        ),
        **({"interaction_ids": interaction_ids} if interaction_ids is not None else {}),
        **({"exclusion_rule_id": exclusion_rule_id} if exclusion_rule_id is not None else {}),
        **({"exclusion_decision": exclusion_decision} if exclusion_decision is not None else {}),
    }


def _candidate(
    candidate_id: str,
    route_ids: list[str],
    *,
    proven: bool = False,
    gaps: list[str] | None = None,
    ineligibility_claim: dict[str, object] | None = None,
    kind_claim: str = "action",
    effect_claim: str = "update",
) -> dict[str, object]:
    evidence_refs = ["source-action"] if proven else []
    fact_status = "proven" if proven else "unknown"
    return {
        "id": candidate_id,
        "domain_id": "customer",
        "business_intent": "Update a customer record",
        "route_ids": route_ids,
        "interaction_ids": [],
        "kind_claim": kind_claim,
        "effect_claim": effect_claim,
        "claims": {
            "schema": {"status": fact_status, "evidence_refs": evidence_refs},
            "effect": {"status": fact_status, "evidence_refs": evidence_refs},
            "risk": {"status": fact_status, "evidence_refs": evidence_refs},
            "reversibility": {"status": fact_status, "evidence_refs": evidence_refs},
            "approval": {"status": fact_status, "evidence_refs": evidence_refs},
            "retry": {"status": fact_status, "evidence_refs": evidence_refs},
            "conflict_control": {"status": fact_status, "evidence_refs": evidence_refs},
            "idempotency": {"status": fact_status, "evidence_refs": evidence_refs},
            "outcome_resolution": {"status": fact_status, "evidence_refs": evidence_refs},
            "lifecycle": {"status": fact_status, "evidence_refs": evidence_refs},
            "authorization_boundary": {
                "status": "upstream_authoritative" if proven else "unknown",
                "evidence_refs": evidence_refs,
            },
            "identity_binding": {
                "status": "identity_binding_proven" if proven else "unknown",
                "evidence_refs": evidence_refs,
            },
            "context_isolation": {
                "status": "context_isolation_proven" if proven else "unknown",
                "evidence_refs": evidence_refs,
            },
        },
        "verification_level": "contract_ready" if proven else "action_discovered",
        "gaps": [] if gaps is None else gaps,
        **({"ineligibility_claim": ineligibility_claim} if ineligibility_claim is not None else {}),
    }


def _decision(
    rationale: str,
    *,
    evidence_sources: list[str] | None = None,
    capability_ids: list[str] | None = None,
    replacement_route_ids: list[str] | None = None,
) -> dict[str, object]:
    return {
        "rationale": rationale,
        "evidence_sources": ["route-decision"] if evidence_sources is None else evidence_sources,
        "capability_ids": [] if capability_ids is None else capability_ids,
        "replacement_route_ids": ([] if replacement_route_ids is None else replacement_route_ids),
    }


def _rule(
    rule_id: str,
    route_ids: list[str],
    *,
    category: str = "binary_or_download",
    rationale: str = "Shared technical exclusion",
    evidence_sources: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": rule_id,
        "category": category,
        "route_ids": route_ids,
        "rationale": rationale,
        "evidence_sources": ["rule-evidence"] if evidence_sources is None else evidence_sources,
    }


def _summary(routes: list[object]) -> dict[str, int]:
    result = {
        "discovered_routes": len(routes),
        "eligible_routes": 0,
        "planned": 0,
        "composed": 0,
        "excluded": 0,
        "blocked_on_evidence": 0,
        "out_of_scope": 0,
        "unresolved": 0,
    }
    for route in routes:
        if not isinstance(route, dict):
            result["unresolved"] += 1
            continue
        if route.get("eligibility") == "eligible":
            result["eligible_routes"] += 1
        elif route.get("eligibility") == "undetermined":
            result["unresolved"] += 1
        disposition = route.get("disposition")
        if isinstance(disposition, str) and disposition in result:
            result[disposition] += 1
        else:
            result["unresolved"] += 1
    return result


def _source_scope(routes: list[object]) -> dict[str, int]:
    summary = _summary(
        [
            route
            for route in routes
            if isinstance(route, dict) and route.get("eligibility") == "eligible"
        ]
    )
    return {
        "eligible_routes": summary["eligible_routes"],
        "planned_or_composed": summary["planned"] + summary["composed"],
        "excluded": summary["excluded"],
        "blocked_on_evidence": summary["blocked_on_evidence"],
        "unresolved": summary["unresolved"],
    }


def _write_project(
    tmp_path: Path,
    *,
    mode: str | None = "system_complete",
    user_confirmation: str | None = None,
    selected_domains: list[str] | None = None,
    declared_domains: list[str] | None = None,
    routes: list[object] | None = None,
    summary_overrides: dict[str, int] | None = None,
    system_operations: list[str] | None = None,
    plan_dependencies: list[str] | None = None,
    baseline_source_scope: dict[str, int] | None = None,
    exclusion_rules: list[dict[str, object]] | None = None,
    approved_route_ids: list[str] | None = None,
    approval_text: str | None = None,
    system_operation_records: list[dict[str, object]] | None = None,
    plan_capabilities: list[dict[str, object]] | None = None,
    plan_coverage: dict[str, object] | None = None,
    candidates: list[dict[str, object]] | None = None,
    evidence: list[dict[str, object]] | None = None,
) -> Path:
    project = tmp_path / "acc-project"
    project.mkdir()
    actual_routes: list[object] = routes if routes is not None else [_route("customer.search")]
    scope: dict[str, object] = {
        "user_confirmation": user_confirmation,
        "selected_domains": selected_domains or [],
    }
    if mode is not None:
        scope["mode"] = mode
    if approved_route_ids is not None or approval_text is not None:
        scope["exclusion_approval"] = {
            "approved_route_ids": approved_route_ids or [],
            "approval_text": approval_text,
        }
    summary = _summary(actual_routes)
    summary.update(summary_overrides or {})
    inventory = {
        "schema_version": "2",
        "scope": scope,
        "discovery": {
            "source_commit": "git:0123456789abcdef",
            "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
            "include_paths": ["app"],
            "evidence_sources": ["routes"],
        },
        "domains": [
            {"id": domain}
            for domain in (
                declared_domains
                if declared_domains is not None
                else sorted(
                    {
                        str(route["domain"])
                        for route in actual_routes
                        if isinstance(route, dict)
                        and isinstance(route.get("domain"), str)
                        and route["domain"]
                    }
                )
            )
        ],
        "routes": actual_routes,
        "exclusion_rules": exclusion_rules or [],
        "summary": summary,
    }
    (project / "scope-inventory.yaml").write_text(
        yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8"
    )
    operation_ids = sorted(
        {
            str(route["operation_id"])
            for route in actual_routes
            if isinstance(route, dict)
            and route.get("disposition") in {"planned", "composed"}
            and isinstance(route.get("operation_id"), str)
            and route["operation_id"]
        }
    )
    actual_system_operations = operation_ids if system_operations is None else system_operations
    route_ids_by_operation: dict[str, list[str]] = {}
    for route in actual_routes:
        if not isinstance(route, dict):
            continue
        operation_id = route.get("operation_id")
        route_id = route.get("id")
        if (
            route.get("disposition") in {"planned", "composed"}
            and isinstance(operation_id, str)
            and isinstance(route_id, str)
        ):
            route_ids_by_operation.setdefault(operation_id, []).append(route_id)
    actual_operation_records = (
        system_operation_records
        if system_operation_records is not None
        else [
            {"id": operation_id, "scope_route_ids": route_ids_by_operation.get(operation_id, [])}
            for operation_id in actual_system_operations
        ]
    )
    (project / "system-map.yaml").write_text(
        yaml.safe_dump({"candidate_operations": actual_operation_records}),
        encoding="utf-8",
    )
    actual_plan_dependencies = operation_ids if plan_dependencies is None else plan_dependencies
    actual_capabilities = (
        plan_capabilities
        if plan_capabilities is not None
        else [{"id": "scope-capability", "operation_dependencies": actual_plan_dependencies}]
    )
    actual_route_dispositions: dict[str, list[str]] = {
        disposition: []
        for disposition in (
            "planned",
            "composed",
            "excluded",
            "blocked_on_evidence",
            "out_of_scope",
        )
    }
    exclusion_decision_refs: list[str] = []
    for index, route in enumerate(actual_routes):
        if not isinstance(route, dict):
            continue
        route_id = route.get("id")
        disposition = route.get("disposition")
        if isinstance(route_id, str) and disposition in actual_route_dispositions:
            actual_route_dispositions[str(disposition)].append(route_id)
        if (
            route.get("eligibility") == "eligible"
            and disposition == "excluded"
            and isinstance(route.get("exclusion_decision"), dict)
        ):
            exclusion_decision_refs.append(f"/routes/{index}/exclusion_decision")
    actual_coverage = (
        plan_coverage
        if plan_coverage is not None
        else {
            "scope_mode": mode,
            "scope_inventory": "scope-inventory.yaml",
            "route_dispositions": actual_route_dispositions,
            "exclusion_decision_refs": exclusion_decision_refs,
        }
    )
    (project / "capability-plan.yaml").write_text(
        yaml.safe_dump({"capabilities": actual_capabilities, "coverage": actual_coverage}),
        encoding="utf-8",
    )
    (project / "coverage-baseline.json").write_text(
        json.dumps(
            {
                "source_scope": (
                    _source_scope(actual_routes)
                    if baseline_source_scope is None
                    else baseline_source_scope
                )
            }
        ),
        encoding="utf-8",
    )
    if candidates is not None:
        (project / "capability-candidates.yaml").write_text(
            yaml.safe_dump({"schema_version": "2", "candidates": candidates}, sort_keys=False),
            encoding="utf-8",
        )
    if evidence is not None:
        evidence_dir = project / "evidence"
        evidence_dir.mkdir()
        for index, artifact in enumerate(evidence):
            (evidence_dir / f"evidence-{index}.yaml").write_text(
                yaml.safe_dump(artifact, sort_keys=False), encoding="utf-8"
            )
    return project


def _run(project: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--project", str(project)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    payload = json.loads(completed.stdout) if completed.stdout else {}
    return completed, payload


def test_system_complete_accepts_a_fully_disposed_inventory(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="system_complete")

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "system_complete"


@pytest.mark.parametrize(
    ("kind", "effect"),
    [("unknown", "unknown"), ("action", "update")],
)
def test_unknown_and_action_routes_require_candidate_references(
    tmp_path: Path, kind: str, effect: str
) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind=kind,
                effect=effect,
                eligibility="undetermined",
                disposition="blocked_on_evidence",
                operation_id=None,
                capability_ids=[],
                reason="Safety contract remains unknown.",
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_CANDIDATE_REFERENCE_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_candidate_route_references_must_match_bidirectionally(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind="action",
                effect="update",
                candidate_id="candidate.customer.update",
            )
        ],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.other"],
                proven=True,
            )
        ],
        evidence=[
            {
                "source_id": "source-action",
                "kind": "source_file",
                "path": "backend/customer.py",
                "digest": "sha256:" + "1" * 64,
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH" in {item["code"] for item in payload["diagnostics"]}


def test_action_safety_gaps_cannot_be_reclassified_as_ineligible(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind="action",
                effect="update",
                eligibility="ineligible",
                disposition="excluded",
                operation_id=None,
                capability_ids=[],
                candidate_id="candidate.customer.update",
                reason="The user did not select this action.",
            )
        ],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.update"],
                gaps=["authorization_boundary", "idempotency"],
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {
        "ACC_SCOPE_ACTION_GAP_MISCLASSIFIED",
        "ACC_SCOPE_ACTION_INELIGIBILITY_UNPROVEN",
    } <= {item["code"] for item in payload["diagnostics"]}


def test_action_safety_gaps_require_undetermined_blocked_disposition(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind="action",
                effect="update",
                candidate_id="candidate.customer.update",
            )
        ],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.update"],
                gaps=["conflict_control"],
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_ACTION_GAP_MISCLASSIFIED" in {item["code"] for item in payload["diagnostics"]}


def test_action_ineligibility_claim_requires_independent_evidence(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind="action",
                effect="update",
                eligibility="ineligible",
                disposition="excluded",
                operation_id=None,
                capability_ids=[],
                candidate_id="candidate.customer.update",
                reason="Source route is objectively unavailable.",
            )
        ],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.update"],
                ineligibility_claim={
                    "status": "proven",
                    "evidence_refs": ["missing-source"],
                },
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_ACTION_INELIGIBILITY_UNPROVEN" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_evidence_backed_objective_ineligibility_closes_action_route(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind="action",
                effect="update",
                eligibility="ineligible",
                disposition="excluded",
                operation_id=None,
                capability_ids=[],
                candidate_id="candidate.customer.update",
                reason="Source route is objectively unavailable.",
            )
        ],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.update"],
                gaps=["idempotency"],
                ineligibility_claim={
                    "status": "proven",
                    "evidence_refs": ["source-ineligible"],
                },
            )
        ],
        evidence=[
            {
                "source_id": "source-ineligible",
                "kind": "source_file",
                "path": "backend/customer.py",
                "digest": "sha256:" + "2" * 64,
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


def test_declared_malformed_candidate_ledger_is_an_explicit_error(tmp_path: Path) -> None:
    project = _write_project(tmp_path)
    secret = "malformed-candidate-secret-never-output"
    (project / "capability-candidates.yaml").write_text(
        yaml.safe_dump({"schema_version": "2", "candidates": secret}), encoding="utf-8"
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_CANDIDATE_LEDGER_INVALID"
    }
    assert secret not in completed.stdout


def test_declared_malformed_evidence_artifact_is_an_explicit_error(tmp_path: Path) -> None:
    project = _write_project(tmp_path, evidence=[{"source_id": "missing-contract-fields"}])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_EVIDENCE_ARTIFACT_INVALID"
    }
    assert payload["diagnostics"][0]["path"] == "evidence/evidence-0.yaml"


def test_duplicate_evidence_source_id_is_not_trusted_for_action_ineligibility(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.update",
                method="POST",
                kind="action",
                effect="update",
                eligibility="ineligible",
                disposition="excluded",
                operation_id=None,
                capability_ids=[],
                candidate_id="candidate.customer.update",
                reason="Source route is objectively unavailable.",
            )
        ],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.update"],
                ineligibility_claim={
                    "status": "proven",
                    "evidence_refs": ["duplicate-source"],
                },
            )
        ],
        evidence=[
            {
                "source_id": "duplicate-source",
                "kind": "source_file",
                "path": "backend/first.py",
                "digest": "sha256:" + "3" * 64,
            },
            {
                "source_id": "duplicate-source",
                "kind": "source_file",
                "path": "backend/second.py",
                "digest": "sha256:" + "4" * 64,
            },
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {
        "ACC_SCOPE_EVIDENCE_SOURCE_ID_DUPLICATE",
        "ACC_SCOPE_ACTION_INELIGIBILITY_UNPROVEN",
    } <= {item["code"] for item in payload["diagnostics"]}


def test_read_candidate_reference_is_optional_but_validated_when_declared(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[_route("customer.search", candidate_id="candidate.customer.missing")],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH"
    }


def test_action_candidate_cannot_be_disguised_as_an_explicit_read_candidate(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[_route("customer.search", candidate_id="candidate.customer.update")],
        candidates=[
            _candidate(
                "candidate.customer.update",
                ["customer.search"],
                proven=True,
            )
        ],
        evidence=[
            {
                "source_id": "source-action",
                "kind": "source_file",
                "path": "backend/customer.py",
                "digest": "sha256:" + "5" * 64,
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH"
    }


def test_explicit_read_candidate_with_exact_read_semantics_is_accepted(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[_route("customer.search", candidate_id="candidate.customer.search")],
        candidates=[
            _candidate(
                "candidate.customer.search",
                ["customer.search"],
                proven=True,
                kind_claim="read",
                effect_claim="read",
            )
        ],
        evidence=[
            {
                "source_id": "source-action",
                "kind": "source_file",
                "path": "backend/customer.py",
                "digest": "sha256:" + "6" * 64,
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


def test_broken_evidence_symlink_returns_a_stable_path_diagnostic(tmp_path: Path) -> None:
    project = _write_project(tmp_path)
    evidence_dir = project / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "broken.yaml").symlink_to(project / "does-not-exist.yaml")

    completed, payload = _run(project)

    assert completed.returncode in {2, 3}
    assert completed.stderr == ""
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"


def test_pilot_requires_explicit_user_confirmation(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="pilot", user_confirmation=None)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_CONFIRMATION_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/user_confirmation"


def test_system_complete_rejects_out_of_scope_and_evidence_blockers(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route("customer.search", disposition="out_of_scope", reason="not selected"),
            _route(
                "report.get",
                disposition="blocked_on_evidence",
                reason="scope unknown",
            ),
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_OUT_OF_SCOPE_FORBIDDEN",
        "ACC_SCOPE_EVIDENCE_BLOCKED",
    }


def test_missing_mode_is_rejected(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode=None)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_MODE_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/scope/mode"


def test_confirmed_pilot_is_valid(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="User explicitly approved a bounded pilot.",
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "pilot"


def test_domain_complete_requires_a_selected_domain(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="domain_complete")

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/selected_domains"


def test_route_contract_violations_have_stable_codes(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[
            _route("customer.search"),
            _route(
                "customer.search",
                disposition="excluded",
                method="POST",
                evidence_sources=[],
                reason=None,
            ),
            _route("report.get", operation_id=None),
        ],
        summary_overrides={"planned": 99},
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_ROUTE_DUPLICATE",
        "ACC_SCOPE_EVIDENCE_REQUIRED",
        "ACC_SCOPE_REASON_REQUIRED",
        "ACC_SCOPE_OPERATION_REQUIRED",
        "ACC_SCOPE_SUMMARY_MISMATCH",
    }
    assert all(item["path"] == "scope-inventory.yaml" for item in payload["diagnostics"])
    assert all(item["pointer"].startswith("/") for item in payload["diagnostics"])


def test_diagnostics_never_echo_input_secrets(tmp_path: Path) -> None:
    secret = "production-secret-never-output"
    project = _write_project(tmp_path, mode=secret)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_MODE_INVALID"
    assert secret not in completed.stdout


def test_schema_version_must_be_one_without_echoing_input(tmp_path: Path) -> None:
    secret = "production-secret-never-output"
    project = _write_project(tmp_path)
    inventory_path = project / "scope-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    inventory["schema_version"] = secret
    inventory_path.write_text(yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8")

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_SCHEMA_VERSION_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/schema_version"
    assert secret not in completed.stdout


def test_route_domain_must_be_a_non_empty_string(tmp_path: Path) -> None:
    route = _route("customer.search")
    route["domain"] = ""
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/domain"


@pytest.mark.parametrize(
    "invalid_path",
    [
        "api/customers",
        "//api/customers",
        "/api//customers",
        "/api/customers?limit=1",
        "/api/customers#details",
        "/api\\customers",
        "/api/../customers",
    ],
)
def test_route_path_must_be_a_safe_origin_relative_path(tmp_path: Path, invalid_path: str) -> None:
    route = _route("customer.search")
    route["path"] = invalid_path
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_PATH_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/path"


def test_route_eligibility_must_be_declared_without_echoing_input(tmp_path: Path) -> None:
    secret = "production-secret-never-output"
    route = _route("customer.search")
    route["eligibility"] = secret
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_ELIGIBILITY_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/eligibility"
    assert secret not in completed.stdout


@pytest.mark.parametrize("disposition", ["planned", "composed"])
def test_ineligible_routes_cannot_be_planned_or_composed(tmp_path: Path, disposition: str) -> None:
    route = _route("customer.search", disposition=disposition)
    route["eligibility"] = "ineligible"
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_INELIGIBLE_DISPOSITION"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/disposition"


def test_ineligible_routes_are_not_counted_as_eligible(tmp_path: Path) -> None:
    route = _route(
        "customer.search",
        disposition="excluded",
        reason="write-only route",
        operation_id=None,
    )
    route["eligibility"] = "ineligible"
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["result"]["source_scope"]["eligible_routes"] == 0


def test_source_scope_counts_only_eligible_route_dispositions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    routes: list[object] = [
        _route("customer.search"),
        {
            **_route(
                "internal.write",
                disposition="excluded",
                operation_id=None,
                reason="write-only route",
            ),
            "eligibility": "ineligible",
        },
    ]
    project = _write_project(tmp_path, routes=routes)
    inventory = yaml.safe_load((project / "scope-inventory.yaml").read_text(encoding="utf-8"))
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    script = runpy.run_path(str(SCRIPT))

    result, diagnostics = script["audit_inventory"](inventory, path="scope-inventory.yaml")

    assert diagnostics == []
    assert inventory["summary"]["excluded"] == 1
    assert result["source_scope"]["eligible_routes"] == 1
    assert result["source_scope"]["planned"] == 1
    assert result["source_scope"]["composed"] == 0
    assert result["source_scope"]["excluded"] == 0
    assert result["source_scope"]["blocked_on_evidence"] == 0
    assert result["source_scope"]["unresolved"] == 0
    assert script["coverage_source_scope"](result["source_scope"]) == {
        "eligible_routes": 1,
        "planned_or_composed": 1,
        "excluded": 0,
        "blocked_on_evidence": 0,
        "unresolved": 0,
    }


def test_scope_audit_parses_valid_inventory_through_the_core_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _write_project(tmp_path)
    inventory = yaml.safe_load((project / "scope-inventory.yaml").read_text(encoding="utf-8"))
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    script = runpy.run_path(str(SCRIPT))

    typed = script["parse_core_inventory"](inventory)

    assert typed.summary.model_dump() == inventory["summary"]
    assert typed.routes[0].id == "customer.search"


def test_scope_audit_rejects_inventory_outside_the_core_contract(tmp_path: Path) -> None:
    project = _write_project(tmp_path)
    path = project / "scope-inventory.yaml"
    inventory = yaml.safe_load(path.read_text(encoding="utf-8"))
    inventory["customer_specific_setting"] = True
    path.write_text(yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8")

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert [item["code"] for item in payload["diagnostics"]] == ["ACC_SCOPE_CORE_CONTRACT_INVALID"]


def test_planned_and_composed_routes_must_exist_in_system_map_and_plan(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route("customer.search", operation_id="customer.search"),
            _route(
                "customer.context",
                disposition="composed",
                operation_id="customer.context",
            ),
        ],
        system_operations=[],
        plan_dependencies=[],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert [item["code"] for item in payload["diagnostics"]].count(
        "ACC_SCOPE_SYSTEM_MAP_MISSING_OPERATION"
    ) == 2
    assert [item["code"] for item in payload["diagnostics"]].count(
        "ACC_SCOPE_PLAN_MISSING_OPERATION"
    ) == 2


def test_coverage_baseline_source_scope_must_match_inventory_denominator(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        baseline_source_scope={
            "eligible_routes": 99,
            "planned_or_composed": 1,
            "excluded": 0,
            "blocked_on_evidence": 0,
            "unresolved": 0,
        },
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_COVERAGE_MISMATCH"
    assert payload["diagnostics"][0]["path"] == "coverage-baseline.json"
    assert payload["diagnostics"][0]["pointer"] == "/source_scope"


def test_domain_complete_rejects_an_undeclared_selected_domain(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        declared_domains=["report"],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_UNDECLARED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/selected_domains/0"


def test_domain_complete_requires_selected_domain_routes_to_be_complete(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        routes=[
            _route(
                "customer.search",
                disposition="blocked_on_evidence",
                operation_id=None,
                reason="missing permission evidence",
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_INCOMPLETE"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/disposition"


def test_domain_complete_requires_outside_routes_to_be_explicitly_out_of_scope(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        routes=[
            _route("customer.search"),
            _route("report.get", domain="report", operation_id="report.get"),
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_BOUNDARY_AMBIGUOUS"
    assert payload["diagnostics"][0]["pointer"] == "/routes/1/disposition"


@pytest.mark.parametrize(
    ("mode", "confirmation", "selected_domains", "routes"),
    [
        ("pilot", "Approved bounded pilot.", [], [_route("customer.search")]),
        (
            "domain_complete",
            None,
            ["customer"],
            [
                _route("customer.search"),
                _route(
                    "report.get",
                    domain="report",
                    disposition="out_of_scope",
                    operation_id=None,
                    reason="outside selected domain",
                ),
            ],
        ),
        ("system_complete", None, [], [_route("customer.search")]),
    ],
)
def test_all_three_scope_modes_accept_consistent_artifacts(
    tmp_path: Path,
    mode: str,
    confirmation: str | None,
    selected_domains: list[str],
    routes: list[object],
) -> None:
    project = _write_project(
        tmp_path,
        mode=mode,
        user_confirmation=confirmation,
        selected_domains=selected_domains,
        routes=routes,
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == mode


def _excluded_route(
    route_id: str,
    *,
    rule_id: str = "binary-rule",
    domain: str = "customer",
    rationale: str | None = None,
    category: str = "binary_or_download",
    usage: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    decision_rationale = rationale or f"Exclude {route_id} based on route-specific evidence"
    route = _route(
        route_id,
        domain=domain,
        disposition="excluded",
        operation_id=None,
        reason="legacy-compatible exclusion reason",
        usage_evidence_sources=["frontend-client"] if usage else None,
        exclusion_rule_id=rule_id,
        exclusion_decision=_decision(decision_rationale),
    )
    rule = _rule(
        rule_id,
        [route_id],
        category=category,
        rationale=f"Shared rationale for {rule_id}",
    )
    return route, rule


def test_warning_diagnostic_is_non_blocking_and_preserves_result(tmp_path: Path) -> None:
    routes: list[object] = []
    rules: list[dict[str, object]] = []
    for index in range(7):
        route, rule = _excluded_route(f"customer.excluded{index}", rule_id=f"rule-{index}")
        routes.append(route)
        rules.append(rule)
    routes.extend(
        _route(f"customer.planned{index}", operation_id=f"customer.planned{index}")
        for index in range(3)
    )
    project = _write_project(tmp_path, routes=routes, exclusion_rules=rules)

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "system_complete"
    assert payload["diagnostics"] == [
        {
            "code": "ACC_SCOPE_HIGH_EXCLUSION_RATIO",
            "message": "eligible route exclusion ratio is unusually high",
            "path": "scope-inventory.yaml",
            "pointer": "/summary/excluded",
            "severity": "warning",
        }
    ]


@pytest.mark.parametrize(
    ("eligible_count", "excluded_count", "expects_warning"),
    [(9, 9, False), (10, 6, False), (10, 7, True), (20, 14, True)],
)
def test_high_exclusion_ratio_uses_locked_eligible_route_thresholds(
    tmp_path: Path,
    eligible_count: int,
    excluded_count: int,
    expects_warning: bool,
) -> None:
    routes: list[object] = [
        _route(
            f"customer.route{index}",
            disposition="excluded" if index < excluded_count else "planned",
            operation_id=None if index < excluded_count else f"customer.route{index}",
            reason="pilot omission" if index < excluded_count else None,
        )
        for index in range(eligible_count)
    ]
    routes.append(
        _route(
            "internal.write",
            disposition="excluded",
            operation_id=None,
            eligibility="ineligible",
            reason="write route",
        )
    )
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=routes,
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    codes = [item["code"] for item in payload["diagnostics"]]
    assert ("ACC_SCOPE_HIGH_EXCLUSION_RATIO" in codes) is expects_warning


def test_error_still_fails_while_preserving_warning_diagnostics(tmp_path: Path) -> None:
    routes: list[object] = []
    rules: list[dict[str, object]] = []
    for index in range(7):
        route, rule = _excluded_route(f"customer.excluded{index}", rule_id=f"rule-{index}")
        routes.append(route)
        rules.append(rule)
    routes.extend(
        _route(f"customer.planned{index}", operation_id=f"customer.planned{index}")
        for index in range(3)
    )
    project = _write_project(
        tmp_path,
        routes=routes,
        exclusion_rules=rules,
        summary_overrides={"planned": 99},
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["ok"] is False
    assert {item["severity"] for item in payload["diagnostics"]} == {"error", "warning"}
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_SUMMARY_MISMATCH",
        "ACC_SCOPE_HIGH_EXCLUSION_RATIO",
    }


def test_system_complete_requires_structured_exclusion_rule_and_decision(
    tmp_path: Path,
) -> None:
    route = _route(
        "customer.download",
        disposition="excluded",
        operation_id=None,
        reason="legacy reason is insufficient",
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_EXCLUSION_RULE_REQUIRED",
        "ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED",
        "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY",
        "ACC_SCOPE_PLAN_EXCLUSION_DECISION_REFS_INVALID",
    }


def test_valid_structured_system_exclusion_does_not_require_legacy_reason(
    tmp_path: Path,
) -> None:
    route, rule = _excluded_route("customer.download")
    route["reason"] = None
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


def test_malformed_structured_system_exclusion_still_requires_legacy_reason(
    tmp_path: Path,
) -> None:
    route, rule = _excluded_route("customer.download")
    route["reason"] = None
    assert isinstance(route["exclusion_decision"], dict)
    route["exclusion_decision"]["evidence_sources"] = []
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
        "ACC_SCOPE_REASON_REQUIRED",
    }


@pytest.mark.parametrize(
    ("rule_id", "route_rule_id"),
    [("   ", "   "), (" binary-rule ", " binary-rule ")],
)
def test_blank_or_padded_rule_identity_cannot_waive_legacy_reason(
    tmp_path: Path, rule_id: str, route_rule_id: str
) -> None:
    route, rule = _excluded_route("customer.download")
    route.update(reason=None, exclusion_rule_id=route_rule_id)
    rule["id"] = rule_id
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_REASON_REQUIRED",
        "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
    }


def test_subsumed_authority_missing_dedicated_fields_cannot_waive_reason(
    tmp_path: Path,
) -> None:
    route, rule = _excluded_route("customer.duplicate", category="duplicate_or_subsumed")
    route["reason"] = None
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_REASON_REQUIRED",
        "ACC_SCOPE_SUBSUMED_CAPABILITY_REQUIRED",
        "ACC_SCOPE_SUBSUMED_REPLACEMENT_REQUIRED",
    }


def test_reused_decisions_cannot_waive_reason_for_either_route(tmp_path: Path) -> None:
    first, first_rule = _excluded_route(
        "customer.download", rule_id="first", rationale=" Reused  authority "
    )
    second, second_rule = _excluded_route(
        "report.download", rule_id="second", rationale="reused authority", domain="report"
    )
    first["reason"] = None
    second["reason"] = None
    project = _write_project(
        tmp_path,
        routes=[
            first,
            second,
            _route("customer.search"),
            _route("report.list", domain="report", operation_id="report.list"),
        ],
        exclusion_rules=[first_rule, second_rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    reason_diagnostics = [
        item for item in payload["diagnostics"] if item["code"] == "ACC_SCOPE_REASON_REQUIRED"
    ]
    assert len(reason_diagnostics) == 2


def test_duplicate_raw_route_ids_cannot_borrow_structured_authority(
    tmp_path: Path,
) -> None:
    first, rule = _excluded_route("customer.download")
    first["reason"] = None
    second = _route(
        "customer.download",
        disposition="excluded",
        operation_id=None,
        reason=None,
        exclusion_rule_id="binary-rule",
    )
    project = _write_project(
        tmp_path,
        routes=[first, second, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    codes = {item["code"] for item in payload["diagnostics"]}
    assert codes >= {
        "ACC_SCOPE_ROUTE_DUPLICATE",
        "ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED",
        "ACC_SCOPE_REASON_REQUIRED",
    }
    assert any(
        item["code"] == "ACC_SCOPE_REASON_REQUIRED" and item["pointer"] == "/routes/1/reason"
        for item in payload["diagnostics"]
    )


def test_exclusion_rule_must_exist_match_route_and_have_evidence(tmp_path: Path) -> None:
    route, _ = _excluded_route("customer.download", rule_id="missing")
    project = _write_project(
        tmp_path,
        routes=[route],
        exclusion_rules=[_rule("other", ["unknown.route"], evidence_sources=[])],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_EXCLUSION_RULE_UNKNOWN",
        "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
        "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
    }


def test_exclusion_rule_cannot_assign_the_same_route_twice(tmp_path: Path) -> None:
    route, first = _excluded_route("customer.download", rule_id="first")
    second = _rule("second", ["customer.download"])
    project = _write_project(tmp_path, routes=[route], exclusion_rules=[first, second])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize(
    "mutator",
    [
        lambda route, rule: rule.update(route_ids=[]),
        lambda route, rule: rule.update(route_ids=["customer.download", "customer.download"]),
        lambda route, rule: rule.update(category="not-a-category"),
        lambda route, rule: rule.update(rationale="   "),
        lambda route, rule: rule.update(route_ids=["customer.other"]),
        lambda route, rule: route.update(disposition="planned", operation_id="customer.download"),
    ],
)
def test_exclusion_rule_fields_and_bidirectional_relation_are_strict(
    tmp_path: Path, mutator: Any
) -> None:
    route, rule = _excluded_route("customer.download")
    mutator(route, rule)
    project = _write_project(tmp_path, routes=[route], exclusion_rules=[rule])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_exclusion_rule_ids_must_be_unique(tmp_path: Path) -> None:
    route, rule = _excluded_route("customer.download")
    project = _write_project(
        tmp_path,
        routes=[route],
        exclusion_rules=[rule, {**rule, "route_ids": ["customer.download"]}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_route_exclusion_decision_requires_unique_rationale_and_evidence(
    tmp_path: Path,
) -> None:
    first, first_rule = _excluded_route(
        "customer.download", rule_id="first", rationale=" Reused   Decision "
    )
    second, second_rule = _excluded_route(
        "report.download", rule_id="second", rationale="reused decision"
    )
    assert isinstance(second["exclusion_decision"], dict)
    second["exclusion_decision"]["evidence_sources"] = []
    project = _write_project(
        tmp_path,
        routes=[first, second, _route("customer.search")],
        exclusion_rules=[first_rule, second_rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_EXCLUSION_DECISION_REUSED",
        "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
    }


def test_ineligible_still_requires_reason_and_route_evidence(tmp_path: Path) -> None:
    route = _route(
        "internal.write",
        disposition="excluded",
        operation_id=None,
        eligibility="ineligible",
        evidence_sources=[],
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_EVIDENCE_REQUIRED",
        "ACC_SCOPE_REASON_REQUIRED",
    }


def test_ineligible_route_rejects_whitespace_only_evidence(tmp_path: Path) -> None:
    route = _route(
        "internal.write",
        disposition="excluded",
        operation_id=None,
        eligibility="ineligible",
        evidence_sources=["   "],
        reason="write route",
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_EVIDENCE_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/evidence_sources"


def test_system_complete_still_rejects_blocked_on_evidence(tmp_path: Path) -> None:
    route = _route(
        "customer.blocked",
        disposition="blocked_on_evidence",
        operation_id=None,
        reason="permission evidence missing",
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EVIDENCE_BLOCKED" in {item["code"] for item in payload["diagnostics"]}


@pytest.mark.parametrize(
    ("operation_record", "expected_code"),
    [
        ({"id": "customer.search"}, "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED"),
        (
            {"id": "customer.search", "scope_route_ids": ["unknown.route"]},
            "ACC_SCOPE_OPERATION_ROUTE_TRACE_ROUTE_UNKNOWN",
        ),
    ],
)
def test_operation_route_trace_is_required_and_must_exist(
    tmp_path: Path,
    operation_record: dict[str, object],
    expected_code: str,
) -> None:
    project = _write_project(tmp_path, system_operation_records=[operation_record])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert expected_code in {item["code"] for item in payload["diagnostics"]}


@pytest.mark.parametrize("trace", [[], "customer.search", [""]])
def test_operation_route_trace_rejects_empty_non_list_or_empty_ids(
    tmp_path: Path, trace: object
) -> None:
    project = _write_project(
        tmp_path,
        system_operation_records=[{"id": "customer.search", "scope_route_ids": trace}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize("disposition", ["excluded", "blocked_on_evidence"])
def test_operation_trace_rejects_non_planned_routes(tmp_path: Path, disposition: str) -> None:
    traced = _route(
        "customer.traced",
        disposition=disposition,
        operation_id=None,
        reason="not available as an operation",
    )
    if disposition == "excluded":
        traced["eligibility"] = "ineligible"
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[traced, _route("customer.search")],
        system_operation_records=[
            {"id": "customer.search", "scope_route_ids": ["customer.traced"]}
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_INVALID" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_operation_trace_requires_matching_route_operation_id(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        system_operation_records=[
            {"id": "different.operation", "scope_route_ids": ["customer.search"]}
        ],
        plan_capabilities=[
            {"id": "scope-capability", "operation_dependencies": ["different.operation"]}
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_OPERATION_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_every_planned_route_must_be_traced_by_its_operation(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route("customer.search", operation_id="customer.read"),
            _route("customer.detail", operation_id="customer.read"),
        ],
        system_operation_records=[{"id": "customer.read", "scope_route_ids": ["customer.search"]}],
        plan_capabilities=[{"id": "read_customers", "operation_dependencies": ["customer.read"]}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_candidate_operation_ids_must_be_unique(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        system_operation_records=[
            {"id": "customer.search", "scope_route_ids": ["customer.search"]},
            {"id": "customer.search", "scope_route_ids": ["unknown.route"]},
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_capability_ids_must_be_unique(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        plan_capabilities=[
            {"id": "read", "operation_dependencies": ["customer.search"]},
            {"id": "read", "operation_dependencies": ["unknown.operation"]},
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_CAPABILITY_DEPENDENCY_UNKNOWN" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_capability_dependency_must_exist_in_system_map(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        plan_capabilities=[
            {
                "id": "scope-capability",
                "operation_dependencies": ["customer.search", "unknown.operation"],
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_CAPABILITY_DEPENDENCY_UNKNOWN" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_duplicate_or_subsumed_requires_capability_and_replacement_closure(
    tmp_path: Path,
) -> None:
    excluded, rule = _excluded_route(
        "customer.duplicate", rule_id="duplicate", category="duplicate_or_subsumed"
    )
    excluded["exclusion_decision"] = _decision(
        "Customer duplicate is represented by the search capability"
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_SUBSUMED_CAPABILITY_REQUIRED",
        "ACC_SCOPE_SUBSUMED_REPLACEMENT_REQUIRED",
    }


def test_duplicate_or_subsumed_accepts_a_complete_replacement_closure(tmp_path: Path) -> None:
    excluded, rule = _excluded_route(
        "legacy.lookup", rule_id="duplicate", category="duplicate_or_subsumed", domain="legacy"
    )
    excluded["exclusion_decision"] = _decision(
        "Legacy lookup is represented by customer search",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        plan_capabilities=[
            {
                "id": "search_customers",
                "operation_dependencies": ["customer.search"],
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


def test_duplicate_or_subsumed_rejects_invalid_replacement_closure(tmp_path: Path) -> None:
    excluded, rule = _excluded_route(
        "customer.duplicate", rule_id="duplicate", category="duplicate_or_subsumed"
    )
    excluded["exclusion_decision"] = _decision(
        "Duplicate route is replaced",
        capability_ids=["missing-capability"],
        replacement_route_ids=["customer.duplicate"],
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID" in {item["code"] for item in payload["diagnostics"]}


@pytest.mark.parametrize("replacement_disposition", ["excluded", "blocked_on_evidence"])
def test_subsumed_replacement_must_be_planned_or_composed(
    tmp_path: Path, replacement_disposition: str
) -> None:
    excluded, rule = _excluded_route(
        "legacy.lookup", rule_id="duplicate", category="duplicate_or_subsumed", domain="legacy"
    )
    excluded["exclusion_decision"] = _decision(
        "Legacy lookup is replaced",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    replacement = _route(
        "customer.search",
        disposition=replacement_disposition,
        operation_id=None,
        reason="not an operation",
    )
    if replacement_disposition == "excluded":
        replacement["eligibility"] = "ineligible"
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[excluded, replacement],
        exclusion_rules=[rule],
        plan_capabilities=[{"id": "search_customers", "operation_dependencies": []}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID" in {item["code"] for item in payload["diagnostics"]}


def test_subsumed_capability_dependency_must_cover_replacement_operation(
    tmp_path: Path,
) -> None:
    excluded, rule = _excluded_route(
        "legacy.lookup", rule_id="duplicate", category="duplicate_or_subsumed", domain="legacy"
    )
    excluded["exclusion_decision"] = _decision(
        "Legacy lookup is replaced",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        plan_capabilities=[{"id": "search_customers", "operation_dependencies": []}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID" in {item["code"] for item in payload["diagnostics"]}


def test_excluded_route_cannot_appear_in_an_ordinary_operation_trace(tmp_path: Path) -> None:
    excluded, rule = _excluded_route("customer.duplicate")
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        system_operation_records=[
            {
                "id": "customer.search",
                "scope_route_ids": ["customer.search", "customer.duplicate"],
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_INVALID" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize("category", ["operational_polling", "low_business_value"])
def test_subjective_exclusion_requires_exact_non_empty_approval(
    tmp_path: Path, category: str
) -> None:
    route, rule = _excluded_route("platform.health", rule_id="subjective", category=category)
    project = _write_project(
        tmp_path,
        routes=[route, _route("platform.status")],
        exclusion_rules=[rule],
        approved_route_ids=["different.route"],
        approval_text="",
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_APPROVAL_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_frontend_used_exclusion_requires_approval_in_system_complete(tmp_path: Path) -> None:
    route, rule = _excluded_route("customer.visible", usage=True)
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    frontend_diagnostics = [
        item
        for item in payload["diagnostics"]
        if item["code"] == "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED"
    ]
    assert {item["severity"] for item in frontend_diagnostics} == {"error", "warning"}


def test_approved_frontend_used_exclusion_remains_a_warning(tmp_path: Path) -> None:
    route, rule = _excluded_route("customer.visible", usage=True)
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
        approved_route_ids=["customer.visible"],
        approval_text="User approved excluding this exact frontend-used route.",
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    frontend_diagnostics = [
        item
        for item in payload["diagnostics"]
        if item["code"] == "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED"
    ]
    assert [item["severity"] for item in frontend_diagnostics] == ["warning"]


def test_frontend_used_exclusion_is_warning_in_pilot(tmp_path: Path) -> None:
    route = _route(
        "customer.visible",
        disposition="excluded",
        operation_id=None,
        reason="approved pilot omission",
        usage_evidence_sources=["frontend-client"],
    )
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[route, _route("customer.search")],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED"
    assert payload["diagnostics"][0]["severity"] == "warning"


def test_malformed_frontend_usage_evidence_cannot_disable_the_risk_signal(
    tmp_path: Path,
) -> None:
    route = _route(
        "customer.visible",
        disposition="excluded",
        operation_id=None,
        reason="approved pilot omission",
        usage_evidence_sources=[""],
    )
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[route, _route("customer.search")],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_EVIDENCE_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/usage_evidence_sources"


def test_empty_frontend_usage_evidence_does_not_fabricate_a_usage_signal(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route(
                "customer.search",
                usage_evidence_sources=[],
                interaction_ids=[],
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


@pytest.mark.parametrize(
    "interaction_ids",
    [["customers.load", "customers.load"], ["customers.submit", "customers.load"], [""]],
)
def test_scope_audit_rejects_malformed_interaction_ids(
    tmp_path: Path, interaction_ids: list[str]
) -> None:
    project = _write_project(
        tmp_path,
        routes=[_route("customer.search", interaction_ids=interaction_ids)],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_INTERACTION_IDS_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/interaction_ids"


def test_domain_with_eligible_routes_requires_a_capability(tmp_path: Path) -> None:
    route, rule = _excluded_route("report.download", domain="report")
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY" in {item["code"] for item in payload["diagnostics"]}


def test_domain_complete_selected_domain_cannot_have_zero_capabilities(tmp_path: Path) -> None:
    route = _route(
        "customer.download",
        disposition="excluded",
        operation_id=None,
        reason="legacy domain exclusion",
    )
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        routes=[route],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY" in {item["code"] for item in payload["diagnostics"]}


def test_zero_capability_exception_requires_every_route_to_be_validly_subsumed(
    tmp_path: Path,
) -> None:
    valid, valid_rule = _excluded_route(
        "legacy.lookup", rule_id="valid", category="duplicate_or_subsumed", domain="legacy"
    )
    valid["exclusion_decision"] = _decision(
        "Legacy lookup is replaced cross-domain",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    invalid, invalid_rule = _excluded_route("legacy.export", rule_id="invalid", domain="legacy")
    project = _write_project(
        tmp_path,
        routes=[valid, invalid, _route("customer.search")],
        exclusion_rules=[valid_rule, invalid_rule],
        plan_capabilities=[
            {"id": "search_customers", "operation_dependencies": ["customer.search"]}
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY" in {item["code"] for item in payload["diagnostics"]}


def test_scope_diagnostics_do_not_echo_malicious_structured_values(tmp_path: Path) -> None:
    secret = "structured-secret-never-output"
    route, rule = _excluded_route(secret, rule_id=secret)
    rule.update(
        category=secret,
        rationale=secret,
        evidence_sources=[secret],
        route_ids=[secret],
    )
    assert isinstance(route["exclusion_decision"], dict)
    route["exclusion_decision"].update(
        rationale=secret,
        evidence_sources=[secret],
        capability_ids=[secret],
        replacement_route_ids=[secret],
    )
    project = _write_project(tmp_path, routes=[route], exclusion_rules=[rule])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"]
    assert secret not in completed.stdout


def test_cross_domain_rule_rationale_reuse_is_a_warning(tmp_path: Path) -> None:
    first, first_rule = _excluded_route("customer.download", rule_id="customer-rule")
    second, second_rule = _excluded_route("report.download", rule_id="report-rule", domain="report")
    second_rule["rationale"] = first_rule["rationale"]
    project = _write_project(
        tmp_path,
        routes=[
            first,
            second,
            _route("customer.search"),
            _route("report.list", domain="report", operation_id="report.list"),
        ],
        exclusion_rules=[first_rule, second_rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    warning = next(
        item
        for item in payload["diagnostics"]
        if item["code"] == "ACC_SCOPE_EXCLUSION_TEMPLATE_REUSED"
    )
    assert warning["severity"] == "warning"


def test_system_complete_plan_coverage_matches_inventory_and_decisions(
    tmp_path: Path,
) -> None:
    excluded, rule = _excluded_route("customer.download")
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


@pytest.mark.parametrize(
    "route_dispositions",
    [
        {
            "planned": [],
            "composed": [],
            "excluded": ["customer.download"],
            "blocked_on_evidence": [],
            "out_of_scope": [],
        },
        {
            "planned": ["customer.search", "unknown.route"],
            "composed": [],
            "excluded": ["customer.download"],
            "blocked_on_evidence": [],
            "out_of_scope": [],
        },
        {
            "planned": ["customer.search", "customer.search"],
            "composed": [],
            "excluded": ["customer.download"],
            "blocked_on_evidence": [],
            "out_of_scope": [],
        },
        {
            "planned": ["customer.search", "   "],
            "composed": [],
            "excluded": ["customer.download"],
            "blocked_on_evidence": [],
            "out_of_scope": [],
        },
    ],
)
def test_system_complete_rejects_inexact_plan_route_dispositions(
    tmp_path: Path, route_dispositions: dict[str, list[str]]
) -> None:
    excluded, rule = _excluded_route("customer.download")
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        plan_coverage={
            "scope_mode": "system_complete",
            "scope_inventory": "scope-inventory.yaml",
            "route_dispositions": route_dispositions,
            "exclusion_decision_refs": ["/routes/0/exclusion_decision"],
        },
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_PLAN_ROUTE_DISPOSITIONS_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize(
    "decision_refs",
    [
        [],
        ["/routes/1/exclusion_decision"],
        ["/routes/0/exclusion_decision", "/routes/0/exclusion_decision"],
        ["customer.download"],
        ["   "],
    ],
)
def test_system_complete_rejects_inexact_exclusion_decision_refs(
    tmp_path: Path, decision_refs: list[str]
) -> None:
    excluded, rule = _excluded_route("customer.download")
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        plan_coverage={
            "scope_mode": "system_complete",
            "scope_inventory": "scope-inventory.yaml",
            "route_dispositions": {
                "planned": ["customer.search"],
                "composed": [],
                "excluded": ["customer.download"],
                "blocked_on_evidence": [],
                "out_of_scope": [],
            },
            "exclusion_decision_refs": decision_refs,
        },
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_PLAN_EXCLUSION_DECISION_REFS_INVALID" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_system_complete_rejects_legacy_free_text_plan_exclusions(tmp_path: Path) -> None:
    project = _write_project(tmp_path)
    plan_path = project / "capability-plan.yaml"
    plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    plan["coverage"]["deliberately_excluded"] = [
        {"item": "customer.download", "reason": "duplicate authority"}
    ]
    plan_path.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_PLAN_FREE_TEXT_EXCLUSION_FORBIDDEN" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_system_complete_requires_structured_plan_coverage(tmp_path: Path) -> None:
    project = _write_project(tmp_path)
    plan_path = project / "capability-plan.yaml"
    plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    del plan["coverage"]
    plan_path.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_PLAN_ROUTE_DISPOSITIONS_MISMATCH",
        "ACC_SCOPE_PLAN_EXCLUSION_DECISION_REFS_INVALID",
    }


def test_plan_coverage_diagnostic_does_not_echo_invalid_pointer_value(
    tmp_path: Path,
) -> None:
    secret = "decision-ref-secret-never-output"
    project = _write_project(
        tmp_path,
        plan_coverage={
            "scope_mode": "system_complete",
            "scope_inventory": "scope-inventory.yaml",
            "route_dispositions": {
                "planned": ["customer.search"],
                "composed": [],
                "excluded": [],
                "blocked_on_evidence": [],
                "out_of_scope": [],
            },
            "exclusion_decision_refs": [secret],
        },
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == ("ACC_SCOPE_PLAN_EXCLUSION_DECISION_REFS_INVALID")
    assert secret not in completed.stdout


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope_mode", None),
        ("scope_mode", "pilot"),
        ("scope_inventory", None),
        ("scope_inventory", "other-inventory.yaml"),
    ],
)
def test_system_complete_plan_coverage_requires_exact_inventory_binding(
    tmp_path: Path, field: str, value: object
) -> None:
    coverage: dict[str, object] = {
        "scope_mode": "system_complete",
        "scope_inventory": "scope-inventory.yaml",
        "route_dispositions": {
            "planned": ["customer.search"],
            "composed": [],
            "excluded": [],
            "blocked_on_evidence": [],
            "out_of_scope": [],
        },
        "exclusion_decision_refs": [],
    }
    if value is None:
        del coverage[field]
    else:
        coverage[field] = value
    project = _write_project(tmp_path, plan_coverage=coverage)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_PLAN_COVERAGE_BINDING_INVALID"
    }


def test_plan_coverage_binding_diagnostic_does_not_echo_invalid_value(
    tmp_path: Path,
) -> None:
    secret = "coverage-binding-secret-never-output"
    project = _write_project(
        tmp_path,
        plan_coverage={
            "scope_mode": secret,
            "scope_inventory": secret,
            "route_dispositions": {
                "planned": ["customer.search"],
                "composed": [],
                "excluded": [],
                "blocked_on_evidence": [],
                "out_of_scope": [],
            },
            "exclusion_decision_refs": [],
        },
    )

    completed, _payload = _run(project)

    assert completed.returncode == 3
    assert secret not in completed.stdout


def test_legacy_pilot_plan_without_structured_coverage_remains_compatible(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
    )
    plan_path = project / "capability-plan.yaml"
    plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    del plan["coverage"]
    plan_path.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
