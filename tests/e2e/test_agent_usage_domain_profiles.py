from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from acc_core.usage.packaging import build_usage_package, verify_usage_package
from acc_core.usage.project import validate_usage_project
from acc_core.usage.render import GenericMarkdownRenderer

FIXTURES = Path("tests/fixtures/usage")


def _fixture(domain_id: str) -> Path:
    if domain_id == "finance":
        return FIXTURES / "finance/conditional-action"
    return FIXTURES / domain_id


@pytest.mark.parametrize(
    "domain_id",
    ["cms", "crm", "erp", "finance", "mobile", "monitoring", "permissions"],
)
def test_untraced_cross_industry_profiles_stay_limited_and_unpublished(
    tmp_path: Path, domain_id: str
) -> None:
    source = _fixture(domain_id)
    project = tmp_path / domain_id
    shutil.copytree(source, project)

    report = validate_usage_project(project)
    assert report.ok, [(item.code, item.path, item.pointer) for item in report.diagnostics]
    contract = report.domain_contracts[domain_id]
    release = report.releases[f"{domain_id}-usage-1"]
    assert release.release_status == "limited"
    assert not release.verification.real_mcp_verified
    assert not release.verification.host_adapter_verified
    assert {claim.source_layer for claim in contract.evidence_claims} <= {
        "client",
        "mcp",
        "service",
        "test",
    }

    built = build_usage_package(project, tmp_path / f"{domain_id}.accusage")
    package = verify_usage_package(built.path)
    assert package.manifest.released_domain_ids == ()
    assert not package.trusted
    with pytest.raises(ValueError, match="live trusted"):
        GenericMarkdownRenderer().render(release, package)


def test_crm_profile_is_search_then_detail() -> None:
    contract = validate_usage_project(FIXTURES / "crm").domain_contracts["crm"]
    route = contract.tool_routes[0]
    assert [step.id for step in route.steps] == ["detail", "search"]
    assert route.steps[0].depends_on_step_ids == ["search"]
    assert contract.input_bindings[0].source_kind == "prior_step_output"
    assert contract.input_bindings[0].source_step_id == "search"


def test_erp_profile_reuses_one_shared_identifier() -> None:
    contract = validate_usage_project(FIXTURES / "erp").domain_contracts["erp"]
    related = contract.related_data[0]
    binding = contract.input_bindings[0]
    assert related.producer_pointer == "/id"
    assert related.target_pointer == "/record_id"
    assert binding.source_pointer == "/id"
    assert binding.target_pointer == "/record_id"


def test_finance_profile_is_conditional_approval_action() -> None:
    contract = validate_usage_project(_fixture("finance")).domain_contracts["finance"]
    lifecycle = contract.action_lifecycles[0]
    phases = [step.action_phase for step in contract.tool_routes[0].steps]
    assert lifecycle.approval == "conditional"
    assert phases == ["approve", "commit", "prepare", "status"]
    assert lifecycle.outcome_unknown_behavior == "query_status"


def test_monitoring_profile_preserves_stale_status() -> None:
    report = validate_usage_project(FIXTURES / "monitoring")
    contract = report.domain_contracts["monitoring"]
    assert contract.related_data[0].consistency == "stale_check_required"
    assert any(
        report.scenarios[scenario_id].kind == "stale_input"
        for scenario_id in contract.required_scenario_ids
    )


def test_cms_profile_retains_long_text_without_payload_fixture() -> None:
    contract = validate_usage_project(FIXTURES / "cms").domain_contracts["cms"]
    goal = contract.business_goals[0]
    assert len(goal.description) >= 1024
    assert contract.result_consumption[0].field_pointers == ["/content"]
    encoded = json.dumps(contract.model_dump(mode="json"), ensure_ascii=False)
    assert "Authorization:" not in encoded
    assert '"payload"' not in encoded


def test_permissions_profile_keeps_source_jwt_as_final_authority() -> None:
    contract = validate_usage_project(FIXTURES / "permissions").domain_contracts["permissions"]
    safety = " ".join(contract.prohibited_behaviors).lower()
    assert "source jwt" in safety
    assert "final authority" in safety
    assert "acc cannot grant" in safety


def test_mobile_profile_is_client_only_and_remains_limited() -> None:
    source = FIXTURES / "mobile"
    report = validate_usage_project(source)
    assert report.ok, [(item.code, item.path, item.pointer) for item in report.diagnostics]
    contract = report.domain_contracts["mobile"]
    release = report.releases["mobile-usage-1"]
    assert {claim.source_layer for claim in contract.evidence_claims} == {"client"}
    assert release.release_status == "limited"
    assert not release.verification.real_mcp_verified
    assert not release.verification.host_adapter_verified
    assert report.source_snapshot is not None
    client_layer = next(
        layer for layer in report.source_snapshot.evidence_layers if layer.source_layer == "client"
    )
    assert client_layer.client_surface == "mobile"
