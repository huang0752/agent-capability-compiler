from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from acc_core.usage import validate_usage_project

_FIXTURE = Path(__file__).parents[2] / "fixtures" / "usage" / "finance"
_CONTRACT_DIGEST = "9f1d827a45d70771b26a62df95044724b6bfefebe43f2c929f09bb56fd9dbda3"
_DECISION_DIGEST = "43fa36400178acbbede65dd6ae2684a2bbd371b8d6a1e074dc4585d1dede1607"


def _finance_project(tmp_path: Path) -> Path:
    project = tmp_path / "finance"
    shutil.copytree(_FIXTURE, project)
    return project


def _codes(project: Path) -> set[str]:
    return {item.code for item in validate_usage_project(project).diagnostics}


def test_capability_project_is_not_a_usage_project(tmp_path: Path) -> None:
    (tmp_path / "project.yaml").write_text(
        "schema_version: '2'\nproject:\n  id: capability-only\n  version: 1.0.0\n",
        encoding="utf-8",
    )

    report = validate_usage_project(tmp_path)

    assert not report.ok
    assert any(item.code == "ACC_USAGE_PROJECT_INVALID" for item in report.diagnostics)


def test_finance_usage_project_loads_complete_independent_closure(tmp_path: Path) -> None:
    report = validate_usage_project(_finance_project(tmp_path))

    assert report.ok
    assert report.project is not None and report.project.kind == "agent_usage"
    assert report.domain_contracts["finance"].domain_id == "finance"
    assert report.domain_index is not None
    assert report.domain_index.domain_ids == ["finance"]
    assert report.domain_index.domains[0].dependency_domain_ids == []
    assert report.domain_index.preferred_order == ["finance"]
    assert report.scenarios["finance-list-happy"].route_id == "invoice-list"
    assert ("finance", 1) in report.decisions
    assert report.releases["finance-usage-1"].release_status == "released"
    assert set(report.evidence_registry) == {
        "client:finance-screen",
        "mcp:finance-invoice-list",
    }


@pytest.mark.parametrize(
    "relative_path",
    [
        "mcp-release-acceptance.yaml",
        "source-snapshot.yaml",
        "domain-index.yaml",
    ],
)
def test_missing_fixed_document_keeps_exact_path(
    tmp_path: Path,
    relative_path: str,
) -> None:
    project = _finance_project(tmp_path)
    (project / relative_path).unlink()

    report = validate_usage_project(project)

    assert ("ACC_IO_NOT_FOUND", relative_path) in {
        (item.code, item.path) for item in report.diagnostics
    }


def test_duplicate_contract_identity_is_rejected_at_second_path(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    contracts = project / "domain-usage-contracts"
    shutil.copyfile(contracts / "finance.yaml", contracts / "finance-copy.yaml")

    report = validate_usage_project(project)

    assert ("ACC_USAGE_CONTRACT_DUPLICATE", "domain-usage-contracts/finance.yaml") in {
        (item.code, item.path) for item in report.diagnostics
    }


def test_published_domain_requires_contract_decision_and_release(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    (project / "domain-usage-contracts" / "finance.yaml").unlink()
    (project / "domain-decisions" / "finance-1.yaml").unlink()
    (project / "releases" / "finance-1.yaml").unlink()

    report = validate_usage_project(project)
    assert {
        "ACC_USAGE_CONTRACT_MISSING",
        "ACC_USAGE_DECISION_MISSING",
        "ACC_USAGE_RELEASE_GATE_FAILED",
    } <= {item.code for item in report.diagnostics}
    assert {
        item.pointer
        for item in report.diagnostics
        if item.code in {"ACC_USAGE_DECISION_MISSING", "ACC_USAGE_RELEASE_GATE_FAILED"}
    } == {"/published_releases"}


def test_required_scenario_must_exist_in_contract_domain(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    (project / "scenarios" / "finance-list-happy.yaml").unlink()

    assert "ACC_USAGE_SCENARIO_UNKNOWN" in _codes(project)


def test_domain_must_be_in_exact_mcp_acceptance(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    acceptance = project / "mcp-release-acceptance.yaml"
    acceptance.write_text(
        acceptance.read_text(encoding="utf-8").replace(
            "accepted_domain_ids:\n- finance", "accepted_domain_ids: []"
        ),
        encoding="utf-8",
    )

    assert "ACC_USAGE_DOMAIN_NOT_ACCEPTED" in _codes(project)


def test_evidence_claim_requires_independent_evidence_identity(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    (project / "usage-evidence" / "client" / "finance-screen.json").unlink()

    report = validate_usage_project(project)

    matches = [
        item for item in report.diagnostics if item.code == "ACC_USAGE_EVIDENCE_CLAIM_UNRESOLVED"
    ]
    assert len(matches) == 1
    assert matches[0].path == "domain-usage-contracts/finance.yaml"
    assert matches[0].pointer == "/evidence_claims/0/evidence_refs"


def test_evidence_claim_rejects_same_source_id_with_changed_digest(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    contract = project / "domain-usage-contracts" / "finance.yaml"
    contents = contract.read_text(encoding="utf-8").replace(
        "digest: sha256:" + "4" * 64,
        "digest: sha256:" + "7" * 64,
        1,
    )
    contract.write_text(contents, encoding="utf-8")

    assert "ACC_USAGE_EVIDENCE_CLAIM_UNRESOLVED" in _codes(project)


def test_changed_artifact_breaks_claim_and_source_layer_digest(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    artifact = project / "usage-evidence" / "client" / "finance-screen.json"
    artifact.write_text(
        artifact.read_text(encoding="utf-8").replace(
            '"digest": "sha256:' + "4" * 64,
            '"digest": "sha256:' + "7" * 64,
        ),
        encoding="utf-8",
    )

    assert {
        "ACC_USAGE_EVIDENCE_CLAIM_UNRESOLVED",
        "ACC_USAGE_EVIDENCE_LAYER_DIGEST_MISMATCH",
    } <= _codes(project)


def test_wrong_layer_and_unknown_layer_artifacts_are_rejected(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    client_artifact = project / "usage-evidence" / "client" / "finance-screen.json"
    service = project / "usage-evidence" / "service"
    service.mkdir()
    shutil.copyfile(client_artifact, service / "wrong-layer.json")
    service_artifact = {
        "source_id": "service:finance-api",
        "kind": "content",
        "locator": "embedded-artifact:finance-api",
        "digest": "sha256:" + "8" * 64,
        "domain_id": "finance",
        "source_layer": "service",
        "size_bytes": 12,
    }
    (service / "unknown-status.json").write_text(
        json.dumps(service_artifact),
        encoding="utf-8",
    )

    assert {
        "ACC_USAGE_EVIDENCE_AUDIT_INVALID",
        "ACC_USAGE_EVIDENCE_LAYER_STATUS_INVALID",
    } <= _codes(project)


def test_fixed_baseline_and_snapshot_are_digest_bound(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    index = project / "domain-index.yaml"
    contents = index.read_text(encoding="utf-8")
    contents = contents.replace(
        "pack_digest: sha256:" + "a" * 64,
        "pack_digest: sha256:" + "f" * 64,
    )
    snapshot_digest = "fe726b25191cb7c9aebe9f35ea644061ac4ed5ab873ae4388638f5cd46bb1759"
    contents = contents.replace(
        "source_snapshot_digest: sha256:" + snapshot_digest,
        "source_snapshot_digest: sha256:" + "e" * 64,
    )
    index.write_text(contents, encoding="utf-8")

    assert {
        "ACC_USAGE_BASELINE_MISMATCH",
        "ACC_USAGE_SOURCE_SNAPSHOT_MISMATCH",
    } <= _codes(project)


def test_contract_scenario_and_release_orphans_are_reported(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    index = project / "domain-index.yaml"
    contents = index.read_text(encoding="utf-8")
    contents = contents.replace(
        "domains:\n- id: finance\n  dependency_domain_ids: []\npreferred_order:\n- finance",
        "domains: []\npreferred_order: []",
    )
    contents = contents.replace(
        "published_releases:\n- domain_id: finance\n  usage_release_id: finance-usage-1",
        "published_releases: []",
    )
    index.write_text(contents, encoding="utf-8")

    assert {
        "ACC_USAGE_CONTRACT_ORPHAN",
        "ACC_USAGE_RELEASE_ORPHAN",
    } <= _codes(project)


def test_historical_releases_do_not_replace_explicit_active_release(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    releases = project / "releases"
    active = (releases / "finance-1.yaml").read_text(encoding="utf-8")
    (releases / "finance-history.yaml").write_text(
        active.replace("usage_release_id: finance-usage-1", "usage_release_id: finance-usage-0")
        .replace(
            "contract_digest: sha256:" + _CONTRACT_DIGEST,
            "contract_digest: sha256:" + "8" * 64,
        )
        .replace(
            "decision_digest: sha256:" + _DECISION_DIGEST,
            "decision_digest: sha256:" + "7" * 64,
        )
        .replace("- inspect-invoices", "- historical-goal")
        .replace("- invoice-list", "- historical-route"),
        encoding="utf-8",
    )

    report = validate_usage_project(project)

    assert report.ok
    assert set(report.releases) == {"finance-usage-0", "finance-usage-1"}


def test_active_release_reference_must_resolve_exact_id(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    index = project / "domain-index.yaml"
    index.write_text(
        index.read_text(encoding="utf-8").replace(
            "usage_release_id: finance-usage-1",
            "usage_release_id: finance-usage-missing",
        ),
        encoding="utf-8",
    )

    report = validate_usage_project(project)

    matches = [item for item in report.diagnostics if item.code == "ACC_USAGE_RELEASE_GATE_FAILED"]
    assert len(matches) == 1
    assert matches[0].pointer == "/published_releases"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "contract_digest: sha256:" + _CONTRACT_DIGEST,
            "contract_digest: sha256:" + "8" * 64,
        ),
        (
            "decision_digest: sha256:" + _DECISION_DIGEST,
            "decision_digest: sha256:" + "8" * 64,
        ),
        ("business_goal_ids:\n- inspect-invoices", "business_goal_ids:\n- other-goal"),
        ("route_ids:\n- invoice-list", "route_ids:\n- other-route"),
    ],
)
def test_active_release_exactly_binds_current_accepted_decision(
    tmp_path: Path,
    old: str,
    new: str,
) -> None:
    project = _finance_project(tmp_path)
    release = project / "releases" / "finance-1.yaml"
    release.write_text(release.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")

    report = validate_usage_project(project)

    matches = [item for item in report.diagnostics if item.code == "ACC_USAGE_RELEASE_GATE_FAILED"]
    assert len(matches) == 1
    assert matches[0].pointer == "/published_releases"
    assert matches[0].message == "Published Usage domain requires its exact active release."


def test_active_release_cannot_bind_an_older_accepted_decision(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    decisions = project / "domain-decisions"
    revision_two_digest = "0e591e58e9c956a9e84c91973f22c4bf55347214f733438aa74dc31b969a99f1"
    revision_two = (decisions / "finance-1.yaml").read_text(encoding="utf-8")
    revision_two = revision_two.replace("revision: 1", "revision: 2").replace(
        _DECISION_DIGEST,
        revision_two_digest,
    )
    (decisions / "finance-2.yaml").write_text(revision_two, encoding="utf-8")

    report = validate_usage_project(project)

    matches = [item for item in report.diagnostics if item.code == "ACC_USAGE_RELEASE_GATE_FAILED"]
    assert len(matches) == 1
    assert matches[0].pointer == "/published_releases"


def test_active_release_scenarios_cannot_cover_an_unselected_route(tmp_path: Path) -> None:
    project = _finance_project(tmp_path)
    release = project / "releases" / "finance-1.yaml"
    release.write_text(
        release.read_text(encoding="utf-8").replace(
            "route_ids:\n- invoice-list",
            "route_ids:\n- other-route",
        ),
        encoding="utf-8",
    )

    assert "ACC_USAGE_RELEASE_GATE_FAILED" in _codes(project)
