from __future__ import annotations

import importlib
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from acc_core.usage import (
    AgentUsageProject,
    AgentUsageRelease,
    DomainUsageContract,
    DomainUsageIndex,
    McpReleaseAcceptance,
    SourceSnapshot,
    UsageActionLifecycle,
    UsageBusinessGoal,
    UsageConditionRef,
    UsageDefaultRef,
    UsageDomainDecision,
    UsageErrorBranch,
    UsageEvidenceClaim,
    UsageEvidenceLayer,
    UsageEvidenceRef,
    UsageEvidenceTarget,
    UsageOptionSourceRef,
    UsagePublishedReleaseRef,
    UsageRelatedDataRef,
    UsageResultConsumption,
    UsageScenario,
    UsageStepBinding,
    UsageToolRoute,
    UsageToolStep,
    UsageUserConfirmation,
    UsageVerification,
    usage_domain_decision_digest,
)

_DIGEST = "sha256:" + "a" * 64
_OTHER_DIGEST = "sha256:" + "b" * 64


def _evidence_ref(source_id: str, digest: str = _DIGEST) -> dict[str, str]:
    return {"source_id": source_id, "digest": digest}


def _acceptance() -> dict[str, Any]:
    return {
        "schema_version": "2",
        "release_id": "mcp-release-2026-08-11",
        "pack_digest": _DIGEST,
        "ir_digest": _OTHER_DIGEST,
        "tool_schema_digest": "sha256:" + "c" * 64,
        "accepted_domain_ids": ["finance", "reports"],
        "test_report_digest": "sha256:" + "d" * 64,
        "known_limitations": ["Real MCP verification remains pending."],
        "accepted_by": "reviewer-1",
        "accepted_at": "2026-08-11T00:00:00Z",
    }


def _binding() -> dict[str, Any]:
    return {
        "id": "bind-customer-id",
        "source_kind": "prior_step_output",
        "source_step_id": "search",
        "consumer_step_id": "detail",
        "source_pointer": "/items/0/id",
        "target_pointer": "/customer_id",
        "mapping": {"kind": "identifier", "mapping": {}},
        "value_kind": "public_value",
    }


def _route() -> dict[str, Any]:
    return {
        "id": "customer-search-detail",
        "business_goal_id": "search-detail",
        "preconditions": ["The caller supplies a search term."],
        "steps": [
            {
                "id": "detail",
                "capability_id": "crm.customer.detail",
                "tool_name": "crm_customer_detail",
                "depends_on_step_ids": ["search"],
                "binding_ids": ["bind-customer-id"],
                "condition": None,
                "retry": "safe",
                "action_phase": None,
            },
            {
                "id": "search",
                "capability_id": "crm.customer.search",
                "tool_name": "crm_customer_search",
                "depends_on_step_ids": [],
                "binding_ids": [],
                "condition": None,
                "retry": "safe",
                "action_phase": None,
            },
        ],
        "error_branch_ids": ["not-found"],
        "result_step_id": "detail",
        "result_pointer": "/customer",
        "action_lifecycle_id": None,
    }


def _contract() -> dict[str, Any]:
    return {
        "schema_version": "2",
        "domain_id": "crm",
        "pack_digest": _DIGEST,
        "ir_digest": _OTHER_DIGEST,
        "tool_schema_digest": "sha256:" + "c" * 64,
        "test_report_digest": "sha256:" + "d" * 64,
        "source_snapshot_digest": _OTHER_DIGEST,
        "business_goals": [
            {
                "id": "search-detail",
                "description": "Find a customer and inspect its details.",
                "evidence_claim_ids": ["claim-business-goal"],
            }
        ],
        "tool_routes": [_route()],
        "input_bindings": [_binding()],
        "defaults": [
            {
                "id": "default-page-size",
                "capability_id": "crm.customer.search",
                "step_id": "search",
                "target_pointer": "/page_size",
                "source": "literal",
                "value": 20,
                "reference_binding_id": None,
                "precedence": 10,
                "submission": "when_missing",
                "evidence_claim_ids": ["claim-default-page-size"],
            }
        ],
        "conditions": [],
        "option_sources": [
            {
                "id": "option-customer",
                "capability_id": "crm.customer.detail",
                "consumer_step_id": "detail",
                "target_pointer": "/customer_id",
                "source": "producer_step",
                "producer_step_id": "search",
                "static_items": [],
                "items_pointer": "/items",
                "value_pointer": "/id",
                "label_pointer": "/name",
                "search": "supported",
                "paging": "supported",
                "empty_behavior": "return_empty",
                "error_behavior": "stop",
                "evidence_claim_ids": ["claim-customer-options"],
            }
        ],
        "related_data": [
            {
                "id": "related-customer-detail",
                "producer_step_id": "search",
                "producer_pointer": "/items/0/id",
                "consumer_step_id": "detail",
                "target_pointer": "/customer_id",
                "cardinality": "one",
                "consistency": "stale_check_required",
                "evidence_claim_ids": ["claim-route-order"],
            }
        ],
        "result_consumption": [
            {
                "id": "consume-customer",
                "capability_id": "crm.customer.detail",
                "step_id": "detail",
                "kind": "return",
                "field_pointers": ["/customer"],
                "order": 1,
                "evidence_claim_ids": ["claim-result-customer"],
            }
        ],
        "error_handling": [
            {
                "id": "not-found",
                "outcomes": ["not_found"],
                "behavior": "stop",
                "description": "Report that the selected customer no longer exists.",
                "step_ids": ["detail"],
                "retry_policy": "never",
                "evidence_claim_ids": ["claim-route-order"],
            }
        ],
        "action_lifecycles": [],
        "prohibited_behaviors": ["Do not broaden source authorization after a denial."],
        "required_scenario_ids": ["crm-empty", "crm-happy"],
        "evidence_claims": [
            {
                "id": "claim-business-goal",
                "statement": "The source client exposes the search-detail goal.",
                "target": {
                    "target_kind": "business_goal",
                    "target_id": "search-detail",
                    "field_pointer": "/description",
                },
                "authority": "observation",
                "source_layer": "client",
                "evidence_refs": [_evidence_ref("client:customer-page")],
            },
            {
                "id": "claim-customer-options",
                "statement": "Search results are the evidenced customer options.",
                "target": {
                    "target_kind": "option_source",
                    "target_id": "option-customer",
                    "field_pointer": "/items_pointer",
                },
                "authority": "test",
                "source_layer": "test",
                "evidence_refs": [_evidence_ref("tests:customer-flow")],
            },
            {
                "id": "claim-default-page-size",
                "statement": "The source client supplies a page-size default.",
                "target": {
                    "target_kind": "default",
                    "target_id": "default-page-size",
                    "field_pointer": "/value",
                },
                "authority": "implementation",
                "source_layer": "client",
                "evidence_refs": [_evidence_ref("client:customer-page")],
            },
            {
                "id": "claim-result-customer",
                "statement": "The detail result is returned to the caller.",
                "target": {
                    "target_kind": "result_consumption",
                    "target_id": "consume-customer",
                    "field_pointer": "/field_pointers",
                },
                "authority": "contract",
                "source_layer": "mcp",
                "evidence_refs": [_evidence_ref("mcp:crm.customer.detail")],
            },
            {
                "id": "claim-route-order",
                "statement": "Search precedes detail in the source client.",
                "target": {
                    "target_kind": "tool_route",
                    "target_id": "customer-search-detail",
                    "field_pointer": "/steps",
                },
                "authority": "implementation",
                "source_layer": "client",
                "evidence_refs": [
                    _evidence_ref("client:customer-page"),
                    _evidence_ref("tests:customer-flow", _OTHER_DIGEST),
                ],
            },
        ],
    }


def _limited_release() -> dict[str, Any]:
    return {
        "schema_version": "2",
        "usage_release_id": "finance-2026-08-11",
        "domain_id": "finance",
        "mcp_release_id": "mcp-release-2026-08-11",
        "pack_digest": _DIGEST,
        "ir_digest": "sha256:" + "e" * 64,
        "tool_schema_digest": _OTHER_DIGEST,
        "test_report_digest": "sha256:" + "d" * 64,
        "source_snapshot_digest": "sha256:" + "c" * 64,
        "contract_digest": "sha256:" + "f" * 64,
        "decision_digest": "sha256:" + "9" * 64,
        "business_goal_ids": ["review-payment"],
        "route_ids": ["payment-review"],
        "scenario_ids": ["finance-action", "finance-read"],
        "capability_ids": ["finance.invoice.get", "finance.payment.prepare"],
        "verification": {
            "source_usage_traced": True,
            "usage_contract_verified": True,
            "headless_agent_verified": True,
            "host_adapter_verified": False,
            "real_mcp_verified": False,
            "user_accepted": True,
        },
        "release_status": "limited",
        "known_limitations": ["Real MCP verification remains pending."],
        "host_adapters": [],
        "released_at": "2026-08-11T00:00:00+00:00",
    }


def test_usage_models_are_current_strict_frozen_and_platform_neutral() -> None:
    acceptance = McpReleaseAcceptance.model_validate(_acceptance())
    assert acceptance.schema_version == "2"
    assert acceptance.pack_digest.startswith("sha256:")
    with pytest.raises(ValidationError):
        McpReleaseAcceptance.model_validate({**_acceptance(), "codex_skill": {}})
    with pytest.raises(ValidationError):
        McpReleaseAcceptance.model_validate({**_acceptance(), "schema_version": "1"})
    with pytest.raises(ValidationError):
        acceptance.release_id = "changed"

    project = AgentUsageProject.model_validate(
        {
            "schema_version": "2",
            "kind": "agent_usage",
            "project": {"id": "example", "version": "1.0.0"},
            "source_workspace": {"path": "/source/example", "mode": "read_only"},
        }
    )
    assert project.kind == "agent_usage"
    assert "codex" not in str(AgentUsageProject.model_json_schema()).lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pack_digest", "a" * 64),
        ("ir_digest", "sha256:" + "A" * 64),
        ("accepted_at", "2026-08-11T08:00:00+08:00"),
        ("accepted_by", " reviewer-1"),
        ("known_limitations", ["line\nbreak"]),
        ("accepted_domain_ids", ["reports", "finance"]),
        ("accepted_domain_ids", ["finance", "finance"]),
    ],
)
def test_acceptance_rejects_noncanonical_values(field: str, value: object) -> None:
    document = _acceptance()
    document[field] = value
    with pytest.raises(ValidationError):
        McpReleaseAcceptance.model_validate(document)


def test_source_snapshot_binds_all_read_only_evidence_classes() -> None:
    snapshot = SourceSnapshot.model_validate(
        {
            "schema_version": "2",
            "source_revision": "git:0123456789abcdef",
            "evidence_layers": [
                {
                    "source_layer": "client",
                    "status": "provided",
                    "digest": _DIGEST,
                    "client_surface": "web",
                },
                {
                    "source_layer": "mcp",
                    "status": "provided",
                    "digest": _OTHER_DIGEST,
                    "client_surface": None,
                },
                {
                    "source_layer": "runtime_observation",
                    "status": "not_applicable",
                    "digest": None,
                    "client_surface": None,
                },
                {
                    "source_layer": "service",
                    "status": "unknown",
                    "digest": None,
                    "client_surface": None,
                },
                {
                    "source_layer": "test",
                    "status": "provided",
                    "digest": "sha256:" + "c" * 64,
                    "client_surface": None,
                },
            ],
            "captured_at": "2026-08-11T00:00:00Z",
        }
    )
    assert snapshot.source_revision == "git:0123456789abcdef"
    with pytest.raises(ValidationError):
        SourceSnapshot.model_validate(
            {**snapshot.model_dump(), "authorization": "Bearer should-never-be-a-field"}
        )


def test_source_evidence_layers_are_platform_neutral_and_status_bound() -> None:
    assert (
        UsageEvidenceLayer.model_validate(
            {
                "source_layer": "client",
                "status": "provided",
                "digest": _DIGEST,
                "client_surface": "mobile",
            }
        ).client_surface
        == "mobile"
    )
    with pytest.raises(ValidationError):
        UsageEvidenceLayer.model_validate(
            {
                "source_layer": "service",
                "status": "provided",
                "digest": None,
                "client_surface": None,
            }
        )
    with pytest.raises(ValidationError):
        UsageEvidenceLayer.model_validate(
            {
                "source_layer": "test",
                "status": "unknown",
                "digest": _DIGEST,
                "client_surface": None,
            }
        )
    with pytest.raises(ValidationError):
        UsageEvidenceLayer.model_validate(
            {
                "source_layer": "service",
                "status": "provided",
                "digest": _DIGEST,
                "client_surface": "desktop",
            }
        )


def test_step_binding_requires_valid_pointer_and_matching_source_step() -> None:
    binding = UsageStepBinding.model_validate(_binding())
    assert binding.mapping is not None

    invalid_pointer = {**_binding(), "source_pointer": "items/0/id"}
    with pytest.raises(ValidationError):
        UsageStepBinding.model_validate(invalid_pointer)

    missing_producer = {**_binding(), "source_step_id": None}
    with pytest.raises(ValidationError):
        UsageStepBinding.model_validate(missing_producer)

    public_input = {
        **_binding(),
        "source_kind": "public_input",
        "source_step_id": "search",
    }
    with pytest.raises(ValidationError):
        UsageStepBinding.model_validate(public_input)


def test_route_is_a_closed_acyclic_dag_with_unique_sorted_step_ids() -> None:
    route = UsageToolRoute.model_validate(_route())
    assert [step.id for step in route.steps] == ["detail", "search"]

    duplicate = deepcopy(_route())
    duplicate["steps"] = [duplicate["steps"][0], duplicate["steps"][0]]
    with pytest.raises(ValidationError):
        UsageToolRoute.model_validate(duplicate)

    unknown = deepcopy(_route())
    unknown["steps"][0]["depends_on_step_ids"] = ["missing"]
    with pytest.raises(ValidationError):
        UsageToolRoute.model_validate(unknown)

    cyclic = deepcopy(_route())
    cyclic["steps"][1]["depends_on_step_ids"] = ["detail"]
    with pytest.raises(ValidationError):
        UsageToolRoute.model_validate(cyclic)

    unsorted = deepcopy(_route())
    unsorted["steps"] = list(reversed(unsorted["steps"]))
    with pytest.raises(ValidationError):
        UsageToolRoute.model_validate(unsorted)


def test_step_condition_is_inert_and_action_phase_is_explicit() -> None:
    step = UsageToolStep.model_validate(
        {
            "id": "approve",
            "capability_id": "finance.payment.approve",
            "tool_name": "finance_payment_approve",
            "depends_on_step_ids": ["prepare"],
            "binding_ids": [],
            "condition": {
                "operator": "eq",
                "left": {"kind": "reference", "pointer": "/prepared/requires_approval"},
                "right": {"kind": "literal", "value": True},
            },
            "retry": "never",
            "action_phase": "approve",
        }
    )
    assert step.action_phase == "approve"
    assert "script" not in step.model_dump()


def test_conditional_action_approval_requires_condition_and_approve_step() -> None:
    lifecycle = UsageActionLifecycle.model_validate(
        {
            "id": "payment-action",
            "prepare_step_id": "prepare",
            "action_id": "finance.payment.create",
            "approve_action_handle_binding_id": "bind-approve-action",
            "commit_action_handle_binding_id": "bind-commit-action",
            "status_action_handle_binding_id": "bind-status-action",
            "approval": "conditional",
            "approval_condition": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/prepared/approval_handle"},
            },
            "approve_step_id": "approve",
            "approval_handle_binding_id": "bind-approval-handle",
            "commit_step_id": "commit",
            "status_step_id": "status",
            "outcome_unknown_behavior": "query_status",
        }
    )
    assert lifecycle.approval == "conditional"

    for field in ("approval_condition", "approve_step_id"):
        document = lifecycle.model_dump()
        document[field] = None
        with pytest.raises(ValidationError):
            UsageActionLifecycle.model_validate(document)

    never = lifecycle.model_dump()
    never.update(
        approval="never",
        approval_condition=None,
        approve_step_id=None,
        approve_action_handle_binding_id=None,
        approval_handle_binding_id=None,
    )
    assert UsageActionLifecycle.model_validate(never).approve_step_id is None


def test_domain_contract_closes_binding_error_action_and_scenario_references() -> None:
    contract = DomainUsageContract.model_validate(_contract())
    assert contract.required_scenario_ids == ["crm-empty", "crm-happy"]

    missing_binding = deepcopy(_contract())
    missing_binding["input_bindings"] = []
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(missing_binding)

    missing_error = deepcopy(_contract())
    missing_error["error_handling"] = []
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(missing_error)

    duplicate_claim = deepcopy(_contract())
    duplicate_claim["evidence_claims"].append(deepcopy(duplicate_claim["evidence_claims"][0]))
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(duplicate_claim)


def test_evidence_and_error_models_are_bounded_and_secret_safe() -> None:
    claim = UsageEvidenceClaim.model_validate(
        {
            "id": "claim-1",
            "statement": "The frontend maps the selected record identifier.",
            "target": {
                "target_kind": "input_binding",
                "target_id": "bind-customer-id",
                "field_pointer": "/target_pointer",
            },
            "authority": "implementation",
            "source_layer": "client",
            "evidence_refs": [
                _evidence_ref("client:list"),
                _evidence_ref("tests:list-detail", _OTHER_DIGEST),
            ],
        }
    )
    branch = UsageErrorBranch.model_validate(
        {
            "id": "denied",
            "outcomes": ["forbidden", "unauthorized"],
            "behavior": "stop",
            "description": "Preserve the source authorization decision.",
            "step_ids": ["read"],
            "retry_policy": "never",
            "evidence_claim_ids": ["claim-1"],
        }
    )
    assert [item.source_id for item in claim.evidence_refs] == ["client:list", "tests:list-detail"]
    assert branch.behavior == "stop"
    wire_schema = str(DomainUsageContract.model_json_schema()).casefold()
    for secret_name in ("password", "authorization", "jwt", "cookie", "secret"):
        assert secret_name not in wire_schema


def test_evidence_claim_requires_typed_authority_layer_and_target() -> None:
    document = {
        "id": "claim-1",
        "statement": "The backend enforces the source contract.",
        "target": {
            "target_kind": "tool_route",
            "target_id": "read",
            "field_pointer": "/steps",
        },
        "authority": "contract",
        "source_layer": "service",
        "evidence_refs": [_evidence_ref("service:read-route")],
    }
    assert UsageEvidenceClaim.model_validate(document).authority == "contract"

    for missing in ("target", "authority", "source_layer"):
        invalid = {key: value for key, value in document.items() if key != missing}
        with pytest.raises(ValidationError):
            UsageEvidenceClaim.model_validate(invalid)

    for field, value in (("authority", "user"), ("source_layer", "frontend")):
        invalid = {**document, field: value}
        with pytest.raises(ValidationError):
            UsageEvidenceClaim.model_validate(invalid)


def test_evidence_reference_identity_includes_digest_and_source_ids_are_unique() -> None:
    first = UsageEvidenceRef.model_validate(_evidence_ref("service:read-route", _DIGEST))
    changed = UsageEvidenceRef.model_validate(_evidence_ref("service:read-route", _OTHER_DIGEST))
    assert first != changed
    assert first.digest == _DIGEST
    assert changed.digest == _OTHER_DIGEST

    claim = {
        "id": "claim-identity",
        "statement": "The route identity is digest bound.",
        "target": {
            "target_kind": "tool_route",
            "target_id": "read",
            "field_pointer": "",
        },
        "authority": "contract",
        "source_layer": "service",
        "evidence_refs": [first.model_dump(), changed.model_dump()],
    }
    with pytest.raises(ValidationError):
        UsageEvidenceClaim.model_validate(claim)


def test_usage_semantics_are_typed_pointer_bound_evidence_refs() -> None:
    default = UsageDefaultRef.model_validate(_contract()["defaults"][0])
    option = UsageOptionSourceRef.model_validate(_contract()["option_sources"][0])
    related = UsageRelatedDataRef.model_validate(_contract()["related_data"][0])
    consumption = UsageResultConsumption.model_validate(_contract()["result_consumption"][0])
    condition = UsageConditionRef.model_validate(
        {
            "id": "condition-has-selection",
            "kind": "execute",
            "scope": "step",
            "route_id": "customer-search-detail",
            "step_id": "detail",
            "target_pointer": "/condition",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/items/0/id"},
            },
            "evidence_claim_ids": ["claim-route-order"],
        }
    )
    assert default.target_pointer == "/page_size"
    assert default.source == "literal"
    assert option.consumer_step_id == "detail"
    assert related.producer_pointer == "/items/0/id"
    assert consumption.field_pointers == ["/customer"]
    assert condition.expression.operator == "present"

    for field in ("defaults", "option_sources", "related_data", "result_consumption"):
        invalid = _contract()
        invalid[field] = ["free-form prose is not a contract"]
        with pytest.raises(ValidationError):
            DomainUsageContract.model_validate(invalid)


def test_contract_rejects_unknown_evidence_claim_references() -> None:
    for field in ("defaults", "option_sources", "related_data", "result_consumption"):
        invalid = _contract()
        invalid[field][0]["evidence_claim_ids"] = ["claim-missing"]
        with pytest.raises(ValidationError):
            DomainUsageContract.model_validate(invalid)

    invalid_condition = _contract()
    invalid_condition["conditions"] = [
        {
            "id": "condition-missing-claim",
            "kind": "execute",
            "scope": "route",
            "route_id": "customer-search-detail",
            "step_id": None,
            "target_pointer": "/steps",
            "expression": {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/items"},
            },
            "evidence_claim_ids": ["claim-missing"],
        }
    ]
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(invalid_condition)


def test_business_goals_are_typed_and_evidence_bound() -> None:
    goal = UsageBusinessGoal.model_validate(_contract()["business_goals"][0])
    assert goal.id == "search-detail"
    invalid = _contract()
    invalid["business_goals"] = ["free-form goal"]
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(invalid)


def test_evidence_targets_close_over_typed_objects_and_real_fields() -> None:
    target = UsageEvidenceTarget.model_validate(
        {
            "target_kind": "tool_route",
            "target_id": "customer-search-detail",
            "field_pointer": "/steps",
        }
    )
    assert target.target_id == "customer-search-detail"

    root_target = UsageEvidenceTarget.model_validate(
        {
            "target_kind": "tool_route",
            "target_id": "customer-search-detail",
            "field_pointer": "",
        }
    )
    root_claim = _contract()
    root_claim["evidence_claims"][-1]["target"] = root_target.model_dump()
    assert (
        DomainUsageContract.model_validate(root_claim).evidence_claims[-1].target.field_pointer
        == ""
    )

    unknown_object = _contract()
    unknown_object["evidence_claims"][-1]["target"]["target_id"] = "missing-route"
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(unknown_object)

    unknown_field = _contract()
    unknown_field["evidence_claims"][-1]["target"]["field_pointer"] = "/steps/missing-id"
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(unknown_field)


def test_route_business_goal_reference_must_close_over_typed_goals() -> None:
    assert DomainUsageContract.model_validate(_contract()).tool_routes[0].business_goal_id == (
        "search-detail"
    )
    orphaned = _contract()
    orphaned["tool_routes"][0]["business_goal_id"] = "missing-goal"
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(orphaned)


def test_contract_baseline_requires_all_four_immutable_digests() -> None:
    for model_document, model in (
        (_contract(), DomainUsageContract),
        (
            {
                "schema_version": "2",
                "mcp_release_id": "release-1",
                "pack_digest": _DIGEST,
                "ir_digest": _OTHER_DIGEST,
                "tool_schema_digest": "sha256:" + "c" * 64,
                "test_report_digest": "sha256:" + "d" * 64,
                "source_snapshot_digest": "sha256:" + "e" * 64,
                "domains": [{"id": "crm", "dependency_domain_ids": []}],
                "preferred_order": ["crm"],
                "published_releases": [],
            },
            DomainUsageIndex,
        ),
        (_limited_release(), AgentUsageRelease),
    ):
        digest_names = ("pack_digest", "ir_digest", "tool_schema_digest", "test_report_digest")
        for digest_name in digest_names:
            missing = deepcopy(model_document)
            missing.pop(digest_name)
            with pytest.raises(ValidationError):
                model.model_validate(missing)


def test_binding_producer_must_be_same_route_ancestor_of_consumer() -> None:
    assert DomainUsageContract.model_validate(_contract()).input_bindings[0].consumer_step_id == (
        "detail"
    )

    future = _contract()
    future["input_bindings"][0].update(
        source_step_id="detail",
        consumer_step_id="search",
    )
    future["tool_routes"][0]["steps"][0]["binding_ids"] = []
    future["tool_routes"][0]["steps"][1]["binding_ids"] = ["bind-customer-id"]
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(future)

    cross_route = _contract()
    cross_route["tool_routes"].append(
        {
            "id": "other-route",
            "business_goal_id": "search-detail",
            "preconditions": [],
            "steps": [
                {
                    "id": "other",
                    "capability_id": "other.read",
                    "tool_name": "other_read",
                    "depends_on_step_ids": [],
                    "binding_ids": ["bind-customer-id"],
                    "condition": None,
                    "retry": "safe",
                    "action_phase": None,
                }
            ],
            "error_branch_ids": [],
            "result_step_id": "other",
            "result_pointer": "/item",
            "action_lifecycle_id": None,
        }
    )
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(cross_route)


def test_option_and_related_producers_must_precede_consumers() -> None:
    future_option = _contract()
    future_option["option_sources"][0].update(
        capability_id="crm.customer.search",
        consumer_step_id="search",
        producer_step_id="detail",
    )
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(future_option)

    future_related = _contract()
    future_related["related_data"][0].update(
        producer_step_id="detail",
        consumer_step_id="search",
    )
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(future_related)


def _action_contract() -> dict[str, Any]:
    contract = _contract()
    contract["tool_routes"].append(
        {
            "id": "payment-action",
            "business_goal_id": "search-detail",
            "preconditions": [],
            "steps": [
                {
                    "id": "approve",
                    "capability_id": "payment.approve",
                    "tool_name": "payment_approve",
                    "depends_on_step_ids": ["prepare"],
                    "binding_ids": ["bind-approval-action", "bind-approval-handle"],
                    "condition": None,
                    "retry": "never",
                    "action_phase": "approve",
                },
                {
                    "id": "commit",
                    "capability_id": "payment.commit",
                    "tool_name": "payment_commit",
                    "depends_on_step_ids": ["approve", "prepare"],
                    "binding_ids": ["bind-commit-action"],
                    "condition": None,
                    "retry": "never",
                    "action_phase": "commit",
                },
                {
                    "id": "prepare",
                    "capability_id": "payment.prepare",
                    "tool_name": "payment_prepare",
                    "depends_on_step_ids": [],
                    "binding_ids": [],
                    "condition": None,
                    "retry": "never",
                    "action_phase": "prepare",
                },
                {
                    "id": "status",
                    "capability_id": "payment.status",
                    "tool_name": "payment_status",
                    "depends_on_step_ids": ["prepare"],
                    "binding_ids": ["bind-status-action"],
                    "condition": None,
                    "retry": "status_only",
                    "action_phase": "status",
                },
            ],
            "error_branch_ids": [],
            "result_step_id": "commit",
            "result_pointer": "/result",
            "action_lifecycle_id": "payment-action",
        }
    )
    handles = [
        ("bind-approval-action", "prior_step_output", "prepare", "approve", "action_handle"),
        ("bind-approval-handle", "trusted_context", None, "approve", "approval_handle"),
        ("bind-commit-action", "prior_step_output", "prepare", "commit", "action_handle"),
        ("bind-status-action", "prior_step_output", "prepare", "status", "action_handle"),
    ]
    for binding_id, source_kind, source_step_id, consumer_step_id, value_kind in handles:
        contract["input_bindings"].append(
            {
                "id": binding_id,
                "source_kind": source_kind,
                "source_step_id": source_step_id,
                "consumer_step_id": consumer_step_id,
                "source_pointer": f"/handles/{value_kind}",
                "target_pointer": f"/{value_kind}",
                "mapping": None,
                "value_kind": value_kind,
            }
        )
    contract["input_bindings"] = sorted(contract["input_bindings"], key=lambda item: item["id"])
    contract["action_lifecycles"] = [
        {
            "id": "payment-action",
            "action_id": "finance.payment.create",
            "prepare_step_id": "prepare",
            "approve_action_handle_binding_id": "bind-approval-action",
            "commit_action_handle_binding_id": "bind-commit-action",
            "status_action_handle_binding_id": "bind-status-action",
            "approval": "always",
            "approval_condition": None,
            "approve_step_id": "approve",
            "approval_handle_binding_id": "bind-approval-handle",
            "commit_step_id": "commit",
            "status_step_id": "status",
            "outcome_unknown_behavior": "query_status",
        }
    ]
    return contract


def test_action_handles_are_trusted_and_phases_are_dependency_ordered() -> None:
    assert DomainUsageContract.model_validate(_action_contract()).action_lifecycles

    public_approval = _action_contract()
    approval = next(
        item for item in public_approval["input_bindings"] if item["id"] == "bind-approval-handle"
    )
    approval["source_kind"] = "public_input"
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(public_approval)

    wrong_order = _action_contract()
    commit = next(step for step in wrong_order["tool_routes"][1]["steps"] if step["id"] == "commit")
    commit["depends_on_step_ids"] = ["prepare"]
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(wrong_order)


def test_no_approval_action_is_prepare_then_commit_with_independent_status() -> None:
    no_approval = _action_contract()
    route = no_approval["tool_routes"][1]
    route["steps"] = [step for step in route["steps"] if step["id"] != "approve"]
    commit = next(step for step in route["steps"] if step["id"] == "commit")
    commit["depends_on_step_ids"] = ["prepare"]
    no_approval["input_bindings"] = [
        binding
        for binding in no_approval["input_bindings"]
        if binding["id"] not in {"bind-approval-action", "bind-approval-handle"}
    ]
    lifecycle = no_approval["action_lifecycles"][0]
    lifecycle.update(
        approval="never",
        approval_condition=None,
        approve_step_id=None,
        approve_action_handle_binding_id=None,
        approval_handle_binding_id=None,
    )
    validated = DomainUsageContract.model_validate(no_approval)
    action_route = validated.tool_routes[1]
    assert next(step for step in action_route.steps if step.id == "status").depends_on_step_ids == [
        "prepare"
    ]


def test_mutation_retry_policy_fails_closed_to_independent_status() -> None:
    mutation_retry = _action_contract()
    mutation_retry["error_handling"].append(
        {
            "id": "retry-commit",
            "outcomes": ["timeout"],
            "behavior": "retry",
            "description": "Retry the mutation directly.",
            "step_ids": ["commit"],
            "retry_policy": "idempotent",
            "evidence_claim_ids": ["claim-route-order"],
        }
    )
    mutation_retry["tool_routes"][1]["error_branch_ids"] = ["retry-commit"]
    with pytest.raises(ValidationError):
        DomainUsageContract.model_validate(mutation_retry)


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        "Cookie: session=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    ],
)
def test_free_text_rejects_credential_shaped_or_high_entropy_values(unsafe_text: str) -> None:
    with pytest.raises(ValidationError):
        UsageBusinessGoal.model_validate(
            {
                "id": "goal",
                "description": unsafe_text,
                "evidence_claim_ids": ["claim-1"],
            }
        )
    assert McpReleaseAcceptance.model_validate(_acceptance()).pack_digest == _DIGEST


@pytest.mark.parametrize(
    "unsafe_value",
    [
        {"nested": ["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sigvalue"]},
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        {"Cookie: session": "safe-looking-value"},
        ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"],
    ],
)
def test_default_json_value_recursively_rejects_secret_shapes(unsafe_value: Any) -> None:
    document = deepcopy(_contract()["defaults"][0])
    document["value"] = unsafe_value
    with pytest.raises(ValidationError):
        UsageDefaultRef.model_validate(document)


@pytest.mark.parametrize(
    "unsafe_value",
    [
        {"password": "secret123!"},
        {"authorization": "Basic abc123"},
        {"nested": {"api_key": "short-secret"}},
        {"client-secret": "ordinary-looking-value"},
    ],
)
def test_default_json_value_rejects_credential_named_fields(unsafe_value: Any) -> None:
    document = deepcopy(_contract()["defaults"][0])
    document["value"] = unsafe_value
    with pytest.raises(ValidationError):
        UsageDefaultRef.model_validate(document)


def test_option_item_value_recursively_rejects_secret_shapes_but_allows_enum() -> None:
    option = deepcopy(_contract()["option_sources"][0])
    option.update(
        source="static",
        producer_step_id=None,
        items_pointer=None,
        value_pointer=None,
        label_pointer=None,
        static_items=[
            {
                "value": {"token": "Cookie: session=abcdefghijklmnopqrstuvwxyz0123456789"},
                "label": "Unsafe",
            }
        ],
    )
    with pytest.raises(ValidationError):
        UsageOptionSourceRef.model_validate(option)

    option["static_items"] = [{"value": "active", "label": "Active"}]
    assert UsageOptionSourceRef.model_validate(option).static_items[0].value == "active"


def test_binding_mapping_recursively_rejects_secret_shapes_and_allows_json_scalars() -> None:
    unsafe = _binding()
    unsafe["mapping"]["mapping"] = {
        "alias": ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"]
    }
    with pytest.raises(ValidationError):
        UsageStepBinding.model_validate(unsafe)

    safe = _binding()
    safe["mapping"]["mapping"] = {"active": 1, "empty": None, "flags": [True, False]}
    assert UsageStepBinding.model_validate(safe).mapping is not None


def test_default_json_value_allows_number_null_enum_and_typed_sha_digest() -> None:
    for value in (20, None, "active", _DIGEST):
        document = deepcopy(_contract()["defaults"][0])
        document["value"] = value
        assert UsageDefaultRef.model_validate(document).value == value


def test_scenario_index_and_decision_bind_one_domain_without_route_questionnaire() -> None:
    scenario = UsageScenario.model_validate(
        {
            "schema_version": "2",
            "scenario_id": "crm-happy",
            "domain_id": "crm",
            "route_id": "customer-search-detail",
            "title": "Search then inspect one customer",
            "kind": "happy_path",
            "public_input_ids": ["search_term"],
            "expected_outcomes": ["details_returned"],
            "prohibited_behaviors": ["Do not select an unrelated customer."],
        }
    )
    index = DomainUsageIndex.model_validate(
        {
            "schema_version": "2",
            "mcp_release_id": "mcp-release-2026-08-11",
            "pack_digest": _DIGEST,
            "ir_digest": "sha256:" + "e" * 64,
            "tool_schema_digest": _OTHER_DIGEST,
            "test_report_digest": "sha256:" + "d" * 64,
            "source_snapshot_digest": _OTHER_DIGEST,
            "domains": [
                {"id": "crm", "dependency_domain_ids": []},
                {"id": "finance", "dependency_domain_ids": []},
            ],
            "preferred_order": ["crm", "finance"],
            "published_releases": [
                {"domain_id": "crm", "usage_release_id": "crm-usage-2026-08-11"}
            ],
        }
    )
    decision_content = {
        "schema_version": "2",
        "domain_id": "crm",
        "revision": 1,
        "disposition": "accepted",
        "business_goal_ids": ["search-detail"],
        "included_route_ids": ["customer-search-detail"],
        "known_limitations": [],
        "contract_digest": "sha256:" + "c" * 64,
    }
    decision_digest = usage_domain_decision_digest(decision_content)
    decision = UsageDomainDecision.model_validate(
        {
            **decision_content,
            "decision_digest": decision_digest,
            "user_confirmation": {
                "confirmed_by": "reviewer-1",
                "confirmed_at": "2026-08-11T00:00:00Z",
                "source_text_digest": "sha256:" + "d" * 64,
                "confirmed_decision_digest": decision_digest,
            },
        }
    )
    assert scenario.domain_id in index.published_domain_ids
    assert decision.disposition == "accepted"

    invalid_index = index.model_dump()
    invalid_index["published_releases"] = [
        {"domain_id": "unknown", "usage_release_id": "unknown-release"}
    ]
    with pytest.raises(ValidationError):
        DomainUsageIndex.model_validate(invalid_index)


def test_domain_index_binds_each_published_domain_to_one_active_release() -> None:
    reference = UsagePublishedReleaseRef.model_validate(
        {"domain_id": "crm", "usage_release_id": "crm-usage-2"}
    )
    index = DomainUsageIndex.model_validate(
        {
            "schema_version": "2",
            "mcp_release_id": "mcp-release-1",
            "pack_digest": _DIGEST,
            "ir_digest": _OTHER_DIGEST,
            "tool_schema_digest": "sha256:" + "c" * 64,
            "test_report_digest": "sha256:" + "d" * 64,
            "source_snapshot_digest": "sha256:" + "e" * 64,
            "domains": [
                {"id": "crm", "dependency_domain_ids": []},
                {"id": "finance", "dependency_domain_ids": []},
            ],
            "preferred_order": ["crm", "finance"],
            "published_releases": [reference.model_dump()],
        }
    )
    assert index.published_domain_ids == ["crm"]
    assert index.published_releases[0].usage_release_id == "crm-usage-2"
    assert "published_domain_ids" not in index.model_dump()

    duplicate_domain = index.model_dump()
    duplicate_domain["published_releases"] = [
        {"domain_id": "crm", "usage_release_id": "crm-usage-1"},
        {"domain_id": "crm", "usage_release_id": "crm-usage-2"},
    ]
    with pytest.raises(ValidationError):
        DomainUsageIndex.model_validate(duplicate_domain)


def test_domain_index_models_independent_domains_without_implicit_blocking() -> None:
    usage_module = importlib.import_module("acc_core.usage")
    assert hasattr(usage_module, "UsageDomainEntry")

    index = DomainUsageIndex.model_validate(
        {
            "schema_version": "2",
            "mcp_release_id": "mcp-release-1",
            "pack_digest": _DIGEST,
            "ir_digest": _OTHER_DIGEST,
            "tool_schema_digest": "sha256:" + "c" * 64,
            "test_report_digest": "sha256:" + "d" * 64,
            "source_snapshot_digest": "sha256:" + "e" * 64,
            "domains": [
                {"id": "crm", "dependency_domain_ids": []},
                {"id": "finance", "dependency_domain_ids": []},
                {"id": "reports", "dependency_domain_ids": ["crm"]},
            ],
            "preferred_order": ["finance", "crm", "reports"],
            "published_releases": [],
        }
    )

    assert index.domain_ids == ["crm", "finance", "reports"]
    assert index.domains[0].dependency_domain_ids == []
    assert index.domains[1].dependency_domain_ids == []
    assert index.domains[2].dependency_domain_ids == ["crm"]
    assert "domain_ids" not in index.model_dump()


@pytest.mark.parametrize(
    "domains",
    [
        [
            {"id": "crm", "dependency_domain_ids": ["missing"]},
            {"id": "finance", "dependency_domain_ids": []},
        ],
        [
            {"id": "crm", "dependency_domain_ids": ["crm"]},
            {"id": "finance", "dependency_domain_ids": []},
        ],
        [
            {"id": "crm", "dependency_domain_ids": ["finance"]},
            {"id": "finance", "dependency_domain_ids": ["crm"]},
        ],
    ],
)
def test_domain_index_rejects_invalid_dependency_graph(
    domains: list[dict[str, object]],
) -> None:
    with pytest.raises(ValidationError):
        DomainUsageIndex.model_validate(
            {
                "schema_version": "2",
                "mcp_release_id": "mcp-release-1",
                "pack_digest": _DIGEST,
                "ir_digest": _OTHER_DIGEST,
                "tool_schema_digest": "sha256:" + "c" * 64,
                "test_report_digest": "sha256:" + "d" * 64,
                "source_snapshot_digest": "sha256:" + "e" * 64,
                "domains": domains,
                "preferred_order": ["crm", "finance"],
                "published_releases": [],
            }
        )


@pytest.mark.parametrize(
    "preferred_order",
    [
        ["crm"],
        ["crm", "crm"],
        ["crm", "missing"],
    ],
)
def test_domain_index_requires_preferred_order_to_be_exact_domain_permutation(
    preferred_order: list[str],
) -> None:
    with pytest.raises(ValidationError):
        DomainUsageIndex.model_validate(
            {
                "schema_version": "2",
                "mcp_release_id": "mcp-release-1",
                "pack_digest": _DIGEST,
                "ir_digest": _OTHER_DIGEST,
                "tool_schema_digest": "sha256:" + "c" * 64,
                "test_report_digest": "sha256:" + "d" * 64,
                "source_snapshot_digest": "sha256:" + "e" * 64,
                "domains": [
                    {"id": "crm", "dependency_domain_ids": []},
                    {"id": "finance", "dependency_domain_ids": []},
                ],
                "preferred_order": preferred_order,
                "published_releases": [],
            }
        )


def test_domain_decision_digest_and_confirmation_bind_exact_content() -> None:
    content = {
        "schema_version": "2",
        "domain_id": "finance",
        "revision": 2,
        "disposition": "accepted",
        "business_goal_ids": ["review-payment"],
        "included_route_ids": ["payment-review"],
        "known_limitations": ["Real MCP test is pending."],
        "contract_digest": _DIGEST,
    }
    digest = usage_domain_decision_digest(content)
    confirmation = UsageUserConfirmation.model_validate(
        {
            "confirmed_by": "reviewer-1",
            "confirmed_at": "2026-08-11T00:00:00Z",
            "source_text_digest": _OTHER_DIGEST,
            "confirmed_decision_digest": digest,
        }
    )
    document: dict[str, Any] = {
        **content,
        "decision_digest": digest,
        "user_confirmation": confirmation.model_dump(),
    }
    decision = UsageDomainDecision.model_validate(document)
    assert decision.decision_digest == confirmation.confirmed_decision_digest
    assert "source_text" not in decision.model_dump()

    changed = deepcopy(document)
    changed["included_route_ids"] = ["payment-create"]
    with pytest.raises(ValidationError):
        UsageDomainDecision.model_validate(changed)

    rebound = deepcopy(document)
    rebound["user_confirmation"]["confirmed_decision_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError):
        UsageDomainDecision.model_validate(rebound)


def test_usage_verification_axes_do_not_imply_one_another() -> None:
    release = AgentUsageRelease.model_validate(_limited_release())
    assert release.verification.user_accepted is True
    assert release.verification.real_mcp_verified is False
    assert release.release_status == "limited"

    every_axis_false = UsageVerification.model_validate(
        {
            "source_usage_traced": False,
            "usage_contract_verified": False,
            "headless_agent_verified": False,
            "host_adapter_verified": False,
            "real_mcp_verified": False,
            "user_accepted": False,
        }
    )
    assert not any(every_axis_false.model_dump().values())


def test_release_wire_binds_exact_decision_contract_goals_and_routes() -> None:
    release = AgentUsageRelease.model_validate(_limited_release())
    for required_field in (
        "contract_digest",
        "decision_digest",
        "business_goal_ids",
        "route_ids",
    ):
        missing = _limited_release()
        missing.pop(required_field)
        with pytest.raises(ValidationError):
            AgentUsageRelease.model_validate(missing)

    changed_route = _limited_release()
    changed_route["route_ids"] = ["payment-create"]
    changed_decision = _limited_release()
    changed_decision["decision_digest"] = "sha256:" + "8" * 64
    assert AgentUsageRelease.model_validate(changed_route).model_dump() != release.model_dump()
    assert AgentUsageRelease.model_validate(changed_decision).model_dump() != release.model_dump()

    for field in ("business_goal_ids", "route_ids"):
        empty = _limited_release()
        empty[field] = []
        with pytest.raises(ValidationError):
            AgentUsageRelease.model_validate(empty)


def test_full_release_requires_core_axes_but_not_a_host_adapter() -> None:
    full = _limited_release()
    full["release_status"] = "released"
    full["known_limitations"] = []
    full["verification"].update(real_mcp_verified=True)
    assert AgentUsageRelease.model_validate(full).release_status == "released"

    adapter_verified = deepcopy(full)
    adapter_verified["verification"]["host_adapter_verified"] = True
    with pytest.raises(ValidationError):
        AgentUsageRelease.model_validate(adapter_verified)

    invalid = deepcopy(full)
    invalid["verification"]["real_mcp_verified"] = False
    with pytest.raises(ValidationError):
        AgentUsageRelease.model_validate(invalid)
