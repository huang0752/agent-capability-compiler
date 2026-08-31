from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path
from typing import cast

import pytest
import yaml

from acc_core.cli.domains import (
    action_candidates,
    analyze_domain_changes,
    check_domain_review,
    show_domain,
    status_domains,
)
from acc_core.cli.main import main
from acc_core.domains import (
    aggregate_reference_digest,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)
from acc_core.validation import validate_project
from fs_links import create_link


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _claims() -> dict[str, object]:
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


def _candidate(candidate_id: str, domain_id: str, *, kind: str = "read") -> dict[str, object]:
    return {
        "id": candidate_id,
        "domain_id": domain_id,
        "business_intent": f"manage_{domain_id}",
        "route_ids": [f"route.{candidate_id}"],
        "interaction_ids": [],
        "kind_claim": kind,
        "effect_claim": "read" if kind == "read" else "update",
        "claims": _claims(),
        "verification_level": "discovered",
        "gaps": [],
    }


def _project(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    project = tmp_path / "project"
    _write(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "domain-cli", "version": "2.0.0"},
            "source_workspace": {"path": "../source", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "BASE_URL", "auth": {"kind": "none"}},
            "quality": {"profile": "standard"},
        },
    )
    candidates = [
        _candidate("alpha.search", "alpha"),
        _candidate("beta.update", "beta", kind="action"),
        _candidate("core.search", "core"),
    ]
    ledger: dict[str, object] = {"schema_version": "2", "candidates": candidates}
    _write(project / "capability-candidates.yaml", ledger)
    _write(
        project / "domain-map.yaml",
        {
            "schema_version": "2",
            "domains": [
                {
                    "id": "alpha",
                    "title": "Alpha",
                    "status": "in_progress",
                    "candidate_ids": ["alpha.search"],
                    "route_ids": ["route.alpha.search"],
                    "interaction_ids": [],
                    "dependency_domain_ids": [],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                },
                {
                    "id": "beta",
                    "title": "Beta",
                    "status": "in_progress",
                    "candidate_ids": ["beta.update"],
                    "route_ids": ["route.beta.update"],
                    "interaction_ids": [],
                    "dependency_domain_ids": [],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                },
                {
                    "id": "core",
                    "title": "Core",
                    "status": "in_progress",
                    "candidate_ids": ["core.search"],
                    "route_ids": ["route.core.search"],
                    "interaction_ids": [],
                    "dependency_domain_ids": [],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                },
            ],
            "unclassified_candidate_ids": [],
            "preferred_order": ["core", "beta", "alpha"],
        },
    )
    return project, ledger


def _review(ledger: dict[str, object]) -> dict[str, object]:
    candidate_ids = ["alpha.search"]
    return {
        "schema_version": "2",
        "domain_id": "alpha",
        "revision": 1,
        "status": "ready_for_review",
        "policy": {
            "goals": ["manage_alpha"],
            "allowed_effects": ["read"],
            "maximum_risk": "low",
            "approval_required_for": [],
            "excluded_intents": [],
        },
        "candidate_dispositions": [
            {
                "candidate_id": "alpha.search",
                "disposition": "deferred",
                "materialized_capability_ids": [],
                "rationale": "Awaiting source evidence.",
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


def test_status_recommends_one_ready_domain_deterministically(
    tmp_path: Path,
) -> None:
    project, _ledger = _project(tmp_path)

    result, diagnostics = status_domains(project)

    assert diagnostics == []
    assert result is not None
    assert result["next_domain"] == "core"
    alpha = next(item for item in result["domains"] if item["id"] == "alpha")
    assert alpha["dependencies_completed"] is True
    assert [item["id"] for item in result["domains"]] == ["alpha", "beta", "core"]


def test_actions_reports_every_action_without_self_certifying_live_verification() -> None:
    project = Path("tests/fixtures/domains/jobs")

    result, diagnostics = action_candidates(project)

    assert diagnostics == []
    assert result is not None
    assert result["summary"] == {
        "action_candidates": 1,
        "materialized_candidates": 1,
        "blocked_candidates": 0,
    }
    [candidate] = result["candidates"]
    assert candidate["candidate_id"] == "jobs.transition"
    assert candidate["verification"]["contract_ready"] == "proven"
    assert candidate["verification"]["offline_verified"] == "not_provisioned"
    assert candidate["verification"]["production_ready"] == "not_provisioned"


def test_domains_actions_cli_emits_the_typed_report(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["domains", "actions", "tests/fixtures/domains/jobs", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["command"] == "domains actions"
    assert payload["result"]["summary"]["action_candidates"] == 1


def test_domains_actions_cli_fails_closed_on_invalid_project(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "jobs"
    shutil.copytree(Path("tests/fixtures/domains/jobs"), project)
    (project / "capabilities" / "jobs.transition.yaml").unlink()

    exit_code = main(["domains", "actions", str(project), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code != 0
    assert payload["ok"] is False
    assert [item["code"] for item in payload["diagnostics"]] == [
        "ACC_DOMAIN_ACTION_PROJECT_INVALID"
    ]
    assert "jobs.transition" not in json.dumps(payload)


def test_show_is_bounded_and_does_not_return_evidence_or_gap_text(tmp_path: Path) -> None:
    project, _ledger = _project(tmp_path)

    result, diagnostics = show_domain(project, "alpha")

    assert diagnostics == []
    assert result is not None
    assert result["id"] == "alpha"
    assert result["candidates"] == [
        {
            "id": "alpha.search",
            "business_intent": "manage_alpha",
            "kind": "read",
            "effect": "read",
            "blocking_gap_count": 5,
            "authorization_status": "unknown",
        }
    ]
    assert "evidence" not in str(result).lower()


def test_status_uses_preference_before_risk_and_stable_id(tmp_path: Path) -> None:
    project, _ledger = _project(tmp_path)
    domain_map = yaml.safe_load((project / "domain-map.yaml").read_text(encoding="utf-8"))
    domain_map["preferred_order"] = ["beta", "alpha", "core"]
    _write(project / "domain-map.yaml", domain_map)
    result, diagnostics = status_domains(project)

    assert diagnostics == []
    assert result is not None
    assert result["next_domain"] == "beta"


def test_status_derives_state_instead_of_echoing_domain_map_status(tmp_path: Path) -> None:
    project, _ledger = _project(tmp_path)
    domain_map = yaml.safe_load((project / "domain-map.yaml").read_text(encoding="utf-8"))
    domain_map["domains"][0]["status"] = "awaiting_user"
    _write(project / "domain-map.yaml", domain_map)

    result, diagnostics = status_domains(project)

    assert diagnostics == []
    assert result is not None
    alpha = next(item for item in result["domains"] if item["id"] == "alpha")
    assert alpha["status"] == "in_progress"


def test_status_and_show_fail_closed_on_invalid_project_baseline(tmp_path: Path) -> None:
    project, ledger = _project(tmp_path)
    domain_map = yaml.safe_load((project / "domain-map.yaml").read_text(encoding="utf-8"))
    domain_map["domains"][2]["status"] = "completed"
    domain_map["domains"][2]["active_decision_ref"] = {
        "domain_id": "core",
        "revision": 1,
        "decision_digest": "sha256:" + "1" * 64,
    }
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "review.yaml", _review(ledger))

    status_result, status_diagnostics = status_domains(project)
    show_result, show_diagnostics = show_domain(project, "core")
    review_result, review_diagnostics = check_domain_review(project, "review.yaml")

    assert status_result is None
    assert show_result is None
    assert review_result is None
    assert [item.code for item in status_diagnostics] == ["ACC_DOMAIN_PROJECT_INVALID"]
    assert [item.code for item in show_diagnostics] == ["ACC_DOMAIN_PROJECT_INVALID"]
    assert "ACC_DOMAIN_REVIEW_PROJECT_INVALID" in {item.code for item in review_diagnostics}


def test_review_check_accepts_candidate_and_goal_but_rejects_route_ids(tmp_path: Path) -> None:
    project, ledger = _project(tmp_path)
    domain_map = yaml.safe_load((project / "domain-map.yaml").read_text(encoding="utf-8"))
    domain_map["domains"][0]["dependency_domain_ids"] = []
    domain_map["domains"][1]["dependency_domain_ids"] = []
    domain_map["domains"][2]["status"] = "in_progress"
    domain_map["domains"][2]["active_decision_ref"] = None
    _write(project / "domain-map.yaml", domain_map)
    review = _review(ledger)
    _write(project / "review.yaml", review)

    result, diagnostics = check_domain_review(project, "review.yaml")

    assert diagnostics == []
    assert result == {"domain_id": "alpha", "revision": 1, "valid": True}

    route_choice = copy.deepcopy(review)
    route_choice["candidate_dispositions"][0]["candidate_id"] = "route.alpha.search"  # type: ignore[index]
    route_choice["candidate_snapshot_ids"] = ["route.alpha.search"]
    route_choice["candidate_snapshot_digest"] = aggregate_reference_digest(["route.alpha.search"])
    _write(project / "review.yaml", route_choice)
    _result, diagnostics = check_domain_review(project, "review.yaml")
    assert [item.code for item in diagnostics] == ["ACC_DOMAIN_REVIEW_ROUTE_ID_FORBIDDEN"]
    assert diagnostics[0].path == "review.yaml"


def test_review_rejects_duplicate_revision_and_forged_confirmation(tmp_path: Path) -> None:
    project, ledger = _project(tmp_path)
    review = _review(ledger)
    _write(project / "domain-decisions" / "alpha-1.yaml", review)
    _write(project / "review.yaml", review)

    _result, diagnostics = check_domain_review(project, "review.yaml")
    assert "ACC_DOMAIN_REVIEW_REVISION_INVALID" in {item.code for item in diagnostics}

    forged = copy.deepcopy(review)
    forged["revision"] = 2
    forged["status"] = "completed"
    forged_snapshot: list[object] = [
        {"evidence_ref": "forged-confirmation", "digest": "sha256:" + "9" * 64}
    ]
    forged["evidence_snapshot"] = forged_snapshot
    forged["evidence_digest"] = aggregate_reference_digest(forged_snapshot)
    forged["user_confirmation"] = {
        "confirmer_ref": "user:reviewer",
        "authority": "authenticated_user",
        "confirmation_summary": "Confirmed outside the Evidence registry.",
        "source_evidence_ref": "forged-confirmation",
        "source_text_digest": "sha256:" + "9" * 64,
        "confirmed_at": "2026-08-10T00:00:00Z",
        "confirmed_decision_digest": domain_decision_digest(forged),
        "decisions": [
            {
                "kind": "domain_completion",
                "subject_ref": "alpha",
                "decision": "confirmed",
                "rationale": "Approved.",
            }
        ],
    }
    _write(project / "review.yaml", forged)

    _result, diagnostics = check_domain_review(project, "review.yaml")
    assert "ACC_DOMAIN_EVIDENCE_UNKNOWN" in {item.code for item in diagnostics}


def test_review_rejects_stale_active_dependency(tmp_path: Path) -> None:
    project, ledger = _project(tmp_path)
    dependency = _review(ledger)
    dependency["domain_id"] = "core"
    dependency["status"] = "stale"
    dependency["policy"]["goals"] = ["manage_core"]  # type: ignore[index]
    dependency["candidate_dispositions"] = [
        {
            "candidate_id": "core.search",
            "disposition": "deferred",
            "materialized_capability_ids": [],
            "rationale": "Dependency is stale.",
        }
    ]
    dependency["candidate_snapshot_ids"] = ["core.search"]
    dependency["candidate_snapshot_digest"] = aggregate_reference_digest(["core.search"])
    dependency_digest = domain_decision_digest(dependency)
    domain_map = yaml.safe_load((project / "domain-map.yaml").read_text(encoding="utf-8"))
    domain_map["domains"][0]["dependency_domain_ids"] = ["core"]
    domain_map["domains"][2]["status"] = "stale"
    domain_map["domains"][2]["active_decision_ref"] = {
        "domain_id": "core",
        "revision": 1,
        "decision_digest": dependency_digest,
    }
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "domain-decisions" / "core.yaml", dependency)
    review = _review(ledger)
    dependency_ref = {
        "domain_id": "core",
        "revision": 1,
        "decision_digest": dependency_digest,
    }
    review["dependency_decisions"] = [dependency_ref]
    review["dependency_snapshot_digest"] = aggregate_reference_digest([dependency_ref])
    _write(project / "review.yaml", review)

    _result, diagnostics = check_domain_review(project, "review.yaml")

    assert "ACC_DOMAIN_DEPENDENCY_NOT_COMPLETED" in {item.code for item in diagnostics}


def test_review_missing_domain_candidate_fails_closed_without_crashing(tmp_path: Path) -> None:
    project, ledger = _project(tmp_path)
    review = _review(ledger)
    candidates = cast(list[dict[str, object]], ledger["candidates"])
    ledger["candidates"] = [item for item in candidates if item["id"] != "alpha.search"]
    _write(project / "capability-candidates.yaml", ledger)
    _write(project / "domain-decisions" / "alpha.yaml", review)

    report = validate_project(project)

    assert {
        "ACC_DOMAIN_CANDIDATE_MISSING",
        "ACC_DOMAIN_DECISION_CANDIDATE_UNKNOWN",
    } <= {item.code for item in report.diagnostics}


def test_domains_cli_emits_one_stable_json_envelope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project, _ledger = _project(tmp_path)

    exit_code = main(["domains", "status", str(project), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert payload["command"] == "domains status"
    assert payload["result"]["next_domain"] == "core"


def test_domains_review_cli_requires_explicit_check_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project, ledger = _project(tmp_path)
    _write(project / "review.yaml", _review(ledger))

    exit_code = main(["domains", "review", "review.yaml", "--project", str(project), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 2
    assert payload["diagnostics"][0]["code"] == "ACC_CLI_USAGE"
    assert "--check" in payload["diagnostics"][0]["message"]


def _incremental_impact_project(tmp_path: Path) -> Path:
    project, ledger = _project(tmp_path)
    candidates = cast(list[dict[str, object]], ledger["candidates"])
    alpha = next(item for item in candidates if item["id"] == "alpha.search")
    claims = cast(dict[str, object], alpha["claims"])
    claims["schema"] = {"status": "proven", "evidence_refs": ["alpha-source"]}
    _write(project / "capability-candidates.yaml", ledger)
    _write(
        project / "evidence" / "alpha-source.yaml",
        {
            "source_id": "alpha-source",
            "kind": "content_summary",
            "summary": "Bounded source contract evidence.",
            "digest": "sha256:" + "6" * 64,
        },
    )
    decision = _review(ledger)
    decision["status"] = "stale"
    decision["evidence_snapshot"] = [
        {"evidence_ref": "alpha-source", "digest": "sha256:" + "6" * 64}
    ]
    decision["evidence_digest"] = aggregate_reference_digest(
        cast(list[object], decision["evidence_snapshot"])
    )
    decision_digest = domain_decision_digest(decision)
    domain_map = yaml.safe_load((project / "domain-map.yaml").read_text(encoding="utf-8"))
    domain_map["domains"][0]["status"] = "stale"
    domain_map["domains"][0]["active_decision_ref"] = {
        "domain_id": "alpha",
        "revision": 1,
        "decision_digest": decision_digest,
    }
    _write(project / "domain-map.yaml", domain_map)
    _write(project / "domain-decisions" / "alpha.yaml", decision)
    _write_json(
        project / "changes.json",
        {
            "schema_version": "2",
            "observed_at": "2026-08-10T02:00:00Z",
            "changed_evidence": [
                {
                    "evidence_ref": "alpha-source",
                    "change": "modified",
                    "old_digest": "sha256:" + "6" * 64,
                    "new_digest": "sha256:" + "7" * 64,
                }
            ],
        },
    )
    return project


def test_domains_impact_analyzes_bounded_change_input_from_full_project_graph(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _incremental_impact_project(tmp_path)

    exit_code = main(
        [
            "domains",
            "impact",
            str(project),
            "--changed-evidence",
            "changes.json",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["result"]["evidence_graph_scope"] == "validated_project"
    assert payload["result"]["stale_domain_ids"] == ["alpha"]
    assert payload["result"]["unaffected_domain_ids"] == ["beta", "core"]
    assert len(payload["result"]["proposed_change_requests"]) == 1
    request = payload["result"]["proposed_change_requests"][0]
    assert request["impact_class"] == "descriptive_only"
    assert request["deployment_effect"] == "audit_warning"


def test_domains_impact_write_is_atomic_and_idempotent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _incremental_impact_project(tmp_path)
    arguments = [
        "domains",
        "impact",
        str(project),
        "--changed-evidence",
        "changes.json",
        "--write",
        "--json",
    ]

    assert main(arguments) == 0
    first_payload = json.loads(capsys.readouterr().out)
    written = list((project / "domain-change-requests").glob("*.json"))
    assert len(written) == 1
    first_bytes = written[0].read_bytes()

    assert main(arguments) == 0
    second_payload = json.loads(capsys.readouterr().out)
    assert list((project / "domain-change-requests").glob("*.json")) == written
    assert written[0].read_bytes() == first_bytes
    assert second_payload["result"] == first_payload["result"]


def test_domains_impact_rejects_unbounded_shape_without_echoing_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _incremental_impact_project(tmp_path)
    _write_json(
        project / "bad-change.json",
        {
            "schema_version": "2",
            "observed_at": "2026-08-10T02:00:00Z",
            "changed_evidence": [],
            "private_token": "DO-NOT-ECHO-THIS",
        },
    )

    exit_code = main(
        [
            "domains",
            "impact",
            str(project),
            "--changed-evidence",
            "bad-change.json",
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 3
    assert "DO-NOT-ECHO-THIS" not in captured.out
    assert json.loads(captured.out)["diagnostics"][0]["code"] == ("ACC_DOMAIN_IMPACT_INPUT_INVALID")


def test_domains_impact_rejects_symlink_change_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _incremental_impact_project(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text((project / "changes.json").read_text(encoding="utf-8"), encoding="utf-8")
    create_link(project / "linked-change.json", outside)

    exit_code = main(
        [
            "domains",
            "impact",
            str(project),
            "--changed-evidence",
            "linked-change.json",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ACC_IO_SYMLINK_REJECTED"


def test_domains_impact_write_rejects_symlink_output_directory(tmp_path: Path) -> None:
    project = _incremental_impact_project(tmp_path)
    outside = tmp_path / "outside-requests"
    outside.mkdir()
    create_link(
        project / "domain-change-requests",
        outside,
        target_is_directory=True,
    )

    result, diagnostics = analyze_domain_changes(project, "changes.json", write=True)

    assert result is None
    assert [item.code for item in diagnostics] == ["ACC_DOMAIN_IMPACT_PROJECT_INVALID"]
    assert list(outside.iterdir()) == []
