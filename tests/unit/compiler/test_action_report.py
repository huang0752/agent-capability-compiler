from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from acc_core.domains import analyze_action_candidates
from acc_core.domains.models import DomainDecision, domain_decision_digest
from acc_core.validation import validate_project

FIXTURE = Path("tests/fixtures/domains/jobs")


def test_action_report_keeps_safety_axes_and_verification_levels_independent(
    tmp_path: Path,
) -> None:
    project = tmp_path / "jobs"
    shutil.copytree(FIXTURE, project)
    validation = validate_project(project)
    assert validation.ok

    report = analyze_action_candidates(validation)

    assert report.project_valid is True
    assert report.summary.action_candidates == 1
    assert report.summary.materialized_candidates == 1
    assert report.summary.blocked_candidates == 0
    [candidate] = report.candidates
    assert candidate.candidate_id == "jobs.transition"
    assert candidate.disposition == "accepted"
    assert candidate.materialized_capability_ids == ["jobs.transition"]
    assert candidate.materialized is True
    assert candidate.blockers == []
    assert candidate.safety.effect.status == "proven"
    assert candidate.safety.authorization_boundary.status == "proven"
    assert candidate.safety.lifecycle.status == "proven"
    assert candidate.verification.discovered == "proven"
    assert candidate.verification.semantics_evidenced == "proven"
    assert candidate.verification.contract_ready == "proven"
    assert candidate.verification.offline_verified == "not_provisioned"
    assert candidate.verification.gateway_offline_verified == "not_provisioned"
    assert candidate.verification.source_connected_verified == "not_provisioned"
    assert candidate.verification.user_accepted == "proven"
    assert candidate.verification.production_ready == "not_provisioned"


def test_action_report_does_not_turn_declared_offline_level_into_live_proof(
    tmp_path: Path,
) -> None:
    project = tmp_path / "jobs"
    shutil.copytree(FIXTURE, project)
    ledger = project / "capability-candidates.yaml"
    ledger.write_text(
        ledger.read_text(encoding="utf-8").replace(
            "verification_level: semantics_evidenced",
            "verification_level: offline_verified",
        ),
        encoding="utf-8",
    )
    validation = validate_project(project)
    assert not validation.ok  # the decision digest correctly becomes stale

    report = analyze_action_candidates(validation)

    [candidate] = report.candidates
    assert candidate.declared_verification_level == "offline_verified"
    assert candidate.verification.offline_verified == "claimed"
    assert candidate.verification.gateway_offline_verified == "not_provisioned"
    assert candidate.verification.source_connected_verified == "not_provisioned"
    assert candidate.verification.production_ready == "not_provisioned"
    assert candidate.materialized is False
    assert "project_validation_failed" in candidate.blockers


def test_action_report_keeps_deferred_action_in_the_denominator(tmp_path: Path) -> None:
    project = tmp_path / "jobs"
    shutil.copytree(FIXTURE, project)
    decision = project / "domain-decisions" / "job_operations.yaml"
    document = yaml.safe_load(decision.read_text(encoding="utf-8"))
    document["status"] = "ready_for_review"
    document["candidate_dispositions"][0]["disposition"] = "deferred"
    document["candidate_dispositions"][0]["materialized_capability_ids"] = []
    document["user_confirmation"] = None
    decision.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    domain_map_path = project / "domain-map.yaml"
    domain_map = yaml.safe_load(domain_map_path.read_text(encoding="utf-8"))
    domain_map["domains"][0]["status"] = "ready_for_review"
    domain_map["domains"][0]["active_decision_ref"] = None
    domain_map_path.write_text(yaml.safe_dump(domain_map, sort_keys=False), encoding="utf-8")
    validation = validate_project(project)

    report = analyze_action_candidates(validation)

    assert report.summary.action_candidates == 1
    assert report.summary.materialized_candidates == 0
    assert report.summary.blocked_candidates == 1
    [candidate] = report.candidates
    assert candidate.disposition == "deferred"
    assert candidate.materialized is False
    assert "decision_deferred" in candidate.blockers


def test_action_report_rejects_unrelated_materialized_action(tmp_path: Path) -> None:
    project = tmp_path / "jobs"
    shutil.copytree(FIXTURE, project)
    capability = project / "capabilities" / "jobs.transition.yaml"
    (project / "capabilities" / "jobs.decoy.yaml").write_text(
        capability.read_text(encoding="utf-8").replace("id: jobs.transition", "id: jobs.decoy", 1),
        encoding="utf-8",
    )
    quality = project / "capability-quality" / "jobs.transition.yaml"
    (project / "capability-quality" / "jobs.decoy.yaml").write_text(
        quality.read_text(encoding="utf-8").replace(
            "capability_id: jobs.transition", "capability_id: jobs.decoy", 1
        ),
        encoding="utf-8",
    )
    decision_path = project / "domain-decisions" / "job_operations.yaml"
    decision_document = yaml.safe_load(decision_path.read_text(encoding="utf-8"))
    decision_document["candidate_dispositions"][0]["materialized_capability_ids"] = ["jobs.decoy"]
    decision_path.write_text(yaml.safe_dump(decision_document, sort_keys=False), encoding="utf-8")
    digest = domain_decision_digest(decision_document)
    decision_document["user_confirmation"]["confirmed_decision_digest"] = digest
    decision_path.write_text(yaml.safe_dump(decision_document, sort_keys=False), encoding="utf-8")
    DomainDecision.model_validate(decision_document)
    domain_map_path = project / "domain-map.yaml"
    domain_map = yaml.safe_load(domain_map_path.read_text(encoding="utf-8"))
    domain_map["domains"][0]["active_decision_ref"]["decision_digest"] = digest
    domain_map_path.write_text(yaml.safe_dump(domain_map, sort_keys=False), encoding="utf-8")

    validation = validate_project(project)
    assert validation.ok
    [candidate] = analyze_action_candidates(validation).candidates
    assert candidate.verification.contract_ready == "blocked"
    assert candidate.materialized is False
    assert "materialized_action_contract_missing" in candidate.blockers


def test_action_report_does_not_fallback_from_invalid_active_decision(tmp_path: Path) -> None:
    project = tmp_path / "jobs"
    shutil.copytree(FIXTURE, project)
    domain_map_path = project / "domain-map.yaml"
    domain_map = yaml.safe_load(domain_map_path.read_text(encoding="utf-8"))
    domain_map["domains"][0]["active_decision_ref"]["decision_digest"] = f"sha256:{'0' * 64}"
    domain_map_path.write_text(yaml.safe_dump(domain_map, sort_keys=False), encoding="utf-8")

    validation = validate_project(project)
    assert not validation.ok
    [candidate] = analyze_action_candidates(validation).candidates
    assert candidate.disposition == "undecided"
    assert candidate.verification.user_accepted == "blocked"
    assert candidate.materialized is False
