from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from acc_core.cli.domains import status_domains
from acc_core.compiler import compile_project
from acc_core.coverage import analyze_coverage
from acc_core.domains import analyze_candidate_readiness
from acc_core.validation import validate_project

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "domains"


def _expected_facts(root: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads((root / "expected-facts.json").read_text(encoding="utf-8")),
    )


def _artifact_digest(value: object) -> str:
    import hashlib

    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _assert_evidence_has_real_artifact_digests(root: Path) -> None:
    for path in sorted((root / "evidence").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["digest"] == _artifact_digest(document["artifact"]), path


def _resolve_json_pointer(document: object, pointer: str) -> object:
    current = document
    for raw_token in pointer.removeprefix("/").split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        assert isinstance(current, dict) and token in current, pointer
        current = current[token]
    return current


def _assert_provenance_pointers_resolve(root: Path, report: object) -> None:
    validated = cast(Any, report)
    evidence_documents = {
        document["source_id"]: document
        for path in sorted((root / "evidence").glob("*.json"))
        if (document := json.loads(path.read_text(encoding="utf-8")))
    }
    for contract in validated.source_contracts.values():
        for claim in contract.provenance:
            _resolve_json_pointer(
                evidence_documents[claim.evidence.source_id], claim.evidence_schema_pointer
            )
        if contract.action_semantics is not None:
            for claim in contract.action_semantics.provenance:
                _resolve_json_pointer(
                    evidence_documents[claim.evidence.source_id], claim.evidence_pointer
                )


def _copy_fixture(tmp_path: Path, fixture: str) -> Path:
    target = tmp_path / fixture
    shutil.copytree(FIXTURES / fixture, target)
    return target


def _mutate_yaml(path: Path, mutation: Callable[[dict[str, Any]], None]) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(document)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _assert_rejected(root: Path, *expected_codes: str) -> set[str]:
    report = validate_project(root)
    codes = {item.code for item in report.diagnostics}
    assert not report.ok
    assert set(expected_codes) <= codes
    compilation = compile_project(root)
    assert not compilation.ok
    assert compilation.ir is None
    return codes


@pytest.mark.parametrize(
    ("fixture", "expected_domain", "expected_fact"),
    [
        ("crm", "customer_management", "search_to_detail"),
        ("erp", "order_fulfillment", "cross_module_workflow"),
        ("finance", "financial_controls", "optimistic_high_risk_action"),
        ("content", "content_publication", "server_serialized_transition"),
        ("jobs", "job_operations", "outcome_resolution"),
        ("permissions", "access_governance", "upstream_authoritative"),
        ("mobile", "mobile_experience", "client_only_candidate"),
    ],
)
def test_domain_fixture_validates_compiles_and_reports_independent_axes(
    fixture: str,
    expected_domain: str,
    expected_fact: str,
) -> None:
    root = FIXTURES / fixture

    report = validate_project(root)
    assert report.ok, report.diagnostics
    compilation = compile_project(root)
    assert compilation.ok, compilation.diagnostics
    assert compilation.ir is not None
    assert report.scope_inventory is not None
    assert report.capability_candidate_ledger is not None
    ledger = report.capability_candidate_ledger
    ir = cast(dict[str, Any], compilation.ir)

    coverage = analyze_coverage(report, report.scope_inventory)
    assert coverage.domain_disposition.status_by_domain[expected_domain] == "completed"
    assert expected_domain in coverage.user_decision_trace.confirmed_domain_ids
    assert coverage.domain_disposition.status == "analyzed"
    assert coverage.business_goals.status == "analyzed"
    assert coverage.candidate_classification.status == "analyzed"
    assert coverage.semantics_provenance.status == "analyzed"
    assert coverage.identity_authorization.status == "analyzed"
    assert coverage.action_lifecycle.status == "analyzed"
    assert coverage.conflict_control.status == "analyzed"
    assert coverage.idempotency.status == "analyzed"
    assert coverage.outcome_resolution.status == "analyzed"
    assert coverage.verification.status == "analyzed"
    assert coverage.cross_domain_dependency.status == "analyzed"
    assert coverage.user_decision_trace.status == "analyzed"

    status, diagnostics = status_domains(root)
    assert diagnostics == []
    assert status is not None
    assert status["next_domain"] is None
    assert status["domains"] == [
        {
            "id": expected_domain,
            "status": "completed",
            "candidate_count": len(ledger.candidates),
            "blocked_candidate_count": sum(
                bool(analyze_candidate_readiness(candidate).blocking_gaps)
                for candidate in ledger.candidates
            ),
            "dependencies_completed": True,
            "verified_completed": True,
        }
    ]

    facts = _expected_facts(root)
    assert facts[expected_fact] is True
    assert facts["independent_coverage_axes"] == 12
    _assert_evidence_has_real_artifact_digests(root)
    _assert_provenance_pointers_resolve(root, report)

    assert all(
        candidate.verification_level != "source_connected_verified"
        for candidate in ledger.candidates
    )
    assert coverage.identity_authorization.source_final_candidate_ids == [
        candidate.id for candidate in ledger.candidates if candidate.route_ids
    ]
    decision = next(iter(report.domain_decisions.values()))
    assert decision.user_confirmation is not None
    confirmation = decision.user_confirmation
    assert confirmation.source_evidence_ref in report.evidence_registry
    assert (
        report.evidence_registry[confirmation.source_evidence_ref].digest
        == confirmation.source_text_digest
    )

    if fixture in {"crm", "erp"}:
        compiled_capabilities = cast(dict[str, Any], ir["capabilities"])
        compiled_capability = cast(
            dict[str, Any], compiled_capabilities[next(iter(report.capabilities))]
        )
        assert len(compiled_capability["operation_dependencies"]) == 2
        details = facts["fact_details"]
        assert isinstance(details, dict)
        assert details["producer"] in compiled_capability["operation_dependencies"]
        assert details["consumer"] in compiled_capability["operation_dependencies"]
    elif fixture in {"finance", "content", "jobs"}:
        compiled_capabilities = cast(dict[str, Any], ir["capabilities"])
        compiled_capability = cast(
            dict[str, Any], compiled_capabilities[next(iter(report.capabilities))]
        )
        proof = cast(dict[str, Any], compiled_capability["action_proof"])
        operation_semantics = cast(dict[str, Any], proof["operation_semantics"])
        attestation = cast(dict[str, Any], next(iter(operation_semantics.values())))
        semantics = cast(dict[str, Any], attestation["summary"])
        if fixture == "finance":
            assert proof["maximum_risk"] == "high"
            assert semantics["concurrency"]["mode"] == "required"
        elif fixture == "content":
            assert semantics["concurrency"]["mode"] == ("server_serialized_state_predicate")
            assert semantics["outcome_resolution"]["mode"] == "status_query"
        else:
            assert semantics["outcome_resolution"]["mode"] == "outcome_unknown"
    elif fixture == "permissions":
        assert report.project is not None
        auth = report.project.provider.auth
        assert auth is not None and auth.kind == "password_bearer"
        assert auth.scopes_pointer is None
        assert auth.scope_mapping == {}
        assert all(operation.http.scopes == [] for operation in report.operations.values())
        assert all(policy.required_scopes == [] for policy in report.policies.values())
        document_text = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(root.rglob("*")) if path.is_file()
        )
        assert "grant_by_acc" not in document_text
        assert "permissions_granted_by_acc" not in document_text
    else:
        client_candidate = next(
            item for item in ledger.candidates if item.id == "mobile.client.refresh"
        )
        assert client_candidate.route_ids == []
        assert client_candidate.interaction_ids == ["mobile.dashboard.pull_to_refresh"]
        assert analyze_candidate_readiness(client_candidate).authorization_status == "unknown"
        assert analyze_candidate_readiness(client_candidate).blocking_gaps
        disposition = next(
            item
            for item in decision.candidate_dispositions
            if item.candidate_id == client_candidate.id
        )
        assert disposition.disposition == "deferred"
        assert disposition.materialized_capability_ids == []


def test_action_candidate_missing_one_required_claim_is_rejected(tmp_path: Path) -> None:
    project = _copy_fixture(tmp_path, "finance")

    def remove_retry(document: dict[str, Any]) -> None:
        del document["candidates"][0]["claims"]["retry"]

    _mutate_yaml(project / "capability-candidates.yaml", remove_retry)

    _assert_rejected(project, "ACC_SCHEMA_INVALID")


def test_source_permission_cannot_be_promoted_to_an_acc_grant(tmp_path: Path) -> None:
    project = _copy_fixture(tmp_path, "permissions")

    def add_acc_grant(document: dict[str, Any]) -> None:
        document["policy"]["permissions_granted_by_acc"] = ["access.admin"]

    _mutate_yaml(project / "domain-decisions" / "access_governance.yaml", add_acc_grant)

    _assert_rejected(project, "ACC_SCHEMA_INVALID")


def test_forged_ineligibility_cannot_hide_missing_action_evidence(tmp_path: Path) -> None:
    project = _copy_fixture(tmp_path, "finance")

    def forge_ineligibility(document: dict[str, Any]) -> None:
        candidate = document["candidates"][0]
        candidate["claims"]["lifecycle"] = {"status": "unknown", "evidence_refs": []}
        candidate["ineligibility_claim"] = {
            "status": "proven",
            "evidence_refs": ["forged-ineligibility"],
        }

    _mutate_yaml(project / "capability-candidates.yaml", forge_ineligibility)

    _assert_rejected(
        project,
        "ACC_DOMAIN_EVIDENCE_UNKNOWN",
        "ACC_DOMAIN_CANDIDATE_BLOCKED",
    )


def test_completed_decision_becomes_stale_when_candidate_ledger_changes(tmp_path: Path) -> None:
    project = _copy_fixture(tmp_path, "crm")

    def change_ledger(document: dict[str, Any]) -> None:
        document["candidates"][0]["verification_level"] = "sandbox_verified"

    _mutate_yaml(project / "capability-candidates.yaml", change_ledger)

    _assert_rejected(
        project,
        "ACC_DOMAIN_DECISION_LEDGER_DIGEST_MISMATCH",
        "ACC_DOMAIN_DECISION_STALE",
    )


def test_domain_dependency_cycle_is_rejected_before_guidance(tmp_path: Path) -> None:
    project = _copy_fixture(tmp_path, "crm")

    def add_cycle(document: dict[str, Any]) -> None:
        main = document["domains"][0]
        main["dependency_domain_ids"] = ["supporting_records"]
        document["domains"].append(
            {
                "id": "supporting_records",
                "title": "Supporting records",
                "status": "not_started",
                "candidate_ids": [],
                "route_ids": [],
                "interaction_ids": [],
                "dependency_domain_ids": [main["id"]],
                "evidence_refs": [],
                "active_decision_ref": None,
            }
        )
        document["domains"] = sorted(document["domains"], key=lambda item: item["id"])
        document["preferred_order"] = [main["id"], "supporting_records"]

    _mutate_yaml(project / "domain-map.yaml", add_cycle)

    _assert_rejected(project, "ACC_SCHEMA_INVALID")


def test_project_specific_conflict_strategy_enum_is_rejected(tmp_path: Path) -> None:
    project = _copy_fixture(tmp_path, "content")

    def inject_strategy(document: dict[str, Any]) -> None:
        document["http"]["safety"]["concurrency"]["mode"] = "content_publisher_serialized"

    _mutate_yaml(project / "operations" / "content.transition.yaml", inject_strategy)

    _assert_rejected(project, "ACC_SCHEMA_INVALID")
