from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from acc_core.diagnostics import Diagnostic
from acc_core.usage import (
    DomainUsageContract,
    DomainUsageIndex,
    UsageImpactStatus,
    UsageProjectReport,
    UsageScenario,
    UsageSnapshot,
    UsageToolSchema,
    analyze_usage_impact,
    validate_usage_project,
)

_D = "sha256:" + "d" * 64


def _report() -> UsageProjectReport:
    report = validate_usage_project(Path("tests/fixtures/usage/finance"))
    index = DomainUsageIndex.model_validate(
        {
            "schema_version": "2",
            "mcp_release_id": "finance-mcp-1",
            "pack_digest": "sha256:" + "a" * 64,
            "ir_digest": "sha256:" + "b" * 64,
            "tool_schema_digest": "sha256:" + "c" * 64,
            "test_report_digest": "sha256:" + "d" * 64,
            "source_snapshot_digest": "sha256:" + "e" * 64,
            "domains": [{"id": "finance", "dependency_domain_ids": []}],
            "preferred_order": ["finance"],
            "published_releases": [],
        }
    )
    return UsageProjectReport(
        root=report.root,
        project=report.project,
        acceptance=report.acceptance,
        source_snapshot=report.source_snapshot,
        domain_index=index,
        domain_contracts=report.domain_contracts,
        scenarios=report.scenarios,
        decisions=report.decisions,
        releases=report.releases,
        evidence_registry=report.evidence_registry,
        diagnostics=(),
    )


def _schema(
    *,
    input_properties: dict[str, object] | None = None,
    output_properties: dict[str, object] | None = None,
    output_required: list[str] | None = None,
) -> UsageToolSchema:
    return UsageToolSchema.model_validate(
        {
            "input_schema": {
                "type": "object",
                "properties": input_properties or {},
                "required": [],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": output_properties or {"items": {"type": "array"}},
                "required": output_required or ["items"],
                "additionalProperties": False,
            },
        }
    )


def _snapshot(**changes: object) -> UsageSnapshot:
    payload: dict[str, object] = {
        "schema_version": "2",
        "pack_digest": "sha256:" + "a" * 64,
        "tool_schema_digest": "sha256:" + "b" * 64,
        "test_report_digest": "sha256:" + "c" * 64,
        "source_snapshot_digest": _D,
        "contract_digests": {"finance": "sha256:" + "e" * 64},
        "capability_ids": ["finance.invoice.list"],
        "tool_schemas": {"finance_invoice_list": _schema()},
        "evidence_digests": {
            "client:finance-screen": "sha256:" + "4" * 64,
            "mcp:finance-invoice-list": "sha256:" + "5" * 64,
        },
        "action_proof_digests": {},
    }
    payload.update(changes)
    return UsageSnapshot.model_validate(payload)


def _status(before: UsageSnapshot, after: UsageSnapshot) -> UsageImpactStatus:
    result = analyze_usage_impact(before=before, after=after, report=_report())
    return result.domain("finance").status


def _copy_report(
    report: UsageProjectReport,
    *,
    contract: DomainUsageContract | None = None,
    diagnostics: tuple[Diagnostic, ...] | None = None,
    scenarios: Mapping[str, UsageScenario] | None = None,
) -> UsageProjectReport:
    return UsageProjectReport(
        root=report.root,
        project=report.project,
        acceptance=report.acceptance,
        source_snapshot=report.source_snapshot,
        domain_index=report.domain_index,
        domain_contracts=MappingProxyType(
            {"finance": contract or report.domain_contracts["finance"]}
        ),
        scenarios=report.scenarios if scenarios is None else scenarios,
        decisions=report.decisions,
        releases=report.releases,
        evidence_registry=report.evidence_registry,
        diagnostics=report.diagnostics if diagnostics is None else diagnostics,
    )


def _action_report() -> UsageProjectReport:
    report = _report()
    payload = report.domain_contracts["finance"].model_dump(mode="json")
    route = payload["tool_routes"][0]
    route["steps"] = [
        {
            "id": "commit",
            "capability_id": "finance.invoice.list",
            "tool_name": "finance_invoice_commit",
            "depends_on_step_ids": ["prepare"],
            "binding_ids": ["commit-handle"],
            "condition": None,
            "retry": "never",
            "action_phase": "commit",
        },
        {
            "id": "prepare",
            "capability_id": "finance.invoice.list",
            "tool_name": "finance_invoice_prepare",
            "depends_on_step_ids": [],
            "binding_ids": [],
            "condition": None,
            "retry": "never",
            "action_phase": "prepare",
        },
        {
            "id": "status",
            "capability_id": "finance.invoice.list",
            "tool_name": "finance_invoice_status",
            "depends_on_step_ids": ["prepare"],
            "binding_ids": ["status-handle"],
            "condition": None,
            "retry": "status_only",
            "action_phase": "status",
        },
    ]
    route["result_step_id"] = "status"
    route["action_lifecycle_id"] = "invoice-action"
    payload["input_bindings"] = [
        {
            "id": "commit-handle",
            "source_kind": "prior_step_output",
            "source_step_id": "prepare",
            "consumer_step_id": "commit",
            "source_pointer": "/action_handle",
            "target_pointer": "/action_handle",
            "mapping": None,
            "value_kind": "action_handle",
        },
        {
            "id": "status-handle",
            "source_kind": "prior_step_output",
            "source_step_id": "prepare",
            "consumer_step_id": "status",
            "source_pointer": "/action_handle",
            "target_pointer": "/action_handle",
            "mapping": None,
            "value_kind": "action_handle",
        },
    ]
    payload["result_consumption"][0]["step_id"] = "status"
    payload["action_lifecycles"] = [
        {
            "id": "invoice-action",
            "action_id": "invoice-action",
            "prepare_step_id": "prepare",
            "approve_action_handle_binding_id": None,
            "commit_action_handle_binding_id": "commit-handle",
            "status_action_handle_binding_id": "status-handle",
            "approval": "never",
            "approval_condition": None,
            "approve_step_id": None,
            "approval_handle_binding_id": None,
            "commit_step_id": "commit",
            "status_step_id": "status",
            "outcome_unknown_behavior": "query_status",
        }
    ]
    contract = DomainUsageContract.model_validate(payload)
    return _copy_report(report, contract=contract)


def test_optional_output_addition_only_revalidates() -> None:
    before = _snapshot()
    after = _snapshot(
        tool_schema_digest="sha256:" + "9" * 64,
        tool_schemas={
            "finance_invoice_list": _schema(
                output_properties={
                    "items": {"type": "array"},
                    "next_cursor": {"type": "string"},
                }
            )
        },
    )

    assert _status(before, after) is UsageImpactStatus.REVALIDATE


def test_input_or_consumed_output_rename_requires_regeneration() -> None:
    input_before = _snapshot(
        tool_schemas={
            "finance_invoice_list": _schema(input_properties={"query": {"type": "string"}})
        }
    )
    input_after = _snapshot(
        tool_schema_digest="sha256:" + "8" * 64,
        tool_schemas={
            "finance_invoice_list": _schema(input_properties={"keyword": {"type": "string"}})
        },
    )
    output_after = _snapshot(
        tool_schema_digest="sha256:" + "7" * 64,
        tool_schemas={
            "finance_invoice_list": _schema(
                output_properties={"records": {"type": "array"}},
                output_required=["records"],
            )
        },
    )

    assert _status(input_before, input_after) is UsageImpactStatus.REGENERATE
    assert _status(_snapshot(), output_after) is UsageImpactStatus.REGENERATE


def test_capability_removal_and_action_proof_or_evidence_drift_block() -> None:
    assert _status(_snapshot(), _snapshot(capability_ids=[])) is UsageImpactStatus.BLOCKED
    assert (
        _status(
            _snapshot(action_proof_digests={"finance.invoice.list": _D}),
            _snapshot(
                action_proof_digests={
                    "finance.invoice.list": "sha256:" + "0" * 64,
                }
            ),
        )
        is UsageImpactStatus.BLOCKED
    )


def test_missing_evidence_on_both_sides_is_blocked() -> None:
    before = _snapshot(evidence_digests={})
    after = _snapshot(evidence_digests={})

    assert _status(before, after) is UsageImpactStatus.BLOCKED
    assert (
        _status(
            _snapshot(),
            _snapshot(evidence_digests={}),
        )
        is UsageImpactStatus.BLOCKED
    )


def test_action_capability_requires_an_unchanged_proof_on_both_sides() -> None:
    report = _action_report()
    schemas = {
        "finance_invoice_prepare": _schema(),
        "finance_invoice_commit": _schema(),
        "finance_invoice_status": _schema(),
    }
    missing = _snapshot(tool_schemas=schemas)

    result = analyze_usage_impact(before=missing, after=missing, report=report)

    assert result.domain("finance").status is UsageImpactStatus.BLOCKED
    assert result.domain("finance").action_capability_ids == ("finance.invoice.list",)

    proven = _snapshot(
        tool_schemas=schemas,
        action_proof_digests={"finance.invoice.list": _D},
    )
    assert (
        analyze_usage_impact(before=proven, after=proven, report=report).domain("finance").status
        is UsageImpactStatus.UNAFFECTED
    )


def test_invalid_report_or_unclosed_report_graph_fails_closed() -> None:
    report = _report()
    invalid = _copy_report(
        report,
        diagnostics=(
            Diagnostic(
                code="ACC_USAGE_SCHEMA_INVALID",
                severity="error",
                message="Usage project is invalid.",
                path="domain-index.yaml",
            ),
        ),
    )
    unclosed = _copy_report(
        report,
        scenarios=MappingProxyType({}),
    )

    invalid_result = analyze_usage_impact(before=_snapshot(), after=_snapshot(), report=invalid)
    unclosed_result = analyze_usage_impact(before=_snapshot(), after=_snapshot(), report=unclosed)

    assert invalid_result.graph_status == "invalid"
    assert invalid_result.domain("finance").status is UsageImpactStatus.BLOCKED
    assert unclosed_result.graph_status == "invalid"
    assert unclosed_result.domain("finance").status is UsageImpactStatus.BLOCKED
    assert (
        _status(
            _snapshot(),
            _snapshot(
                source_snapshot_digest="sha256:" + "1" * 64,
                evidence_digests={
                    "client:finance-screen": "sha256:" + "6" * 64,
                    "mcp:finance-invoice-list": "sha256:" + "5" * 64,
                },
            ),
        )
        is UsageImpactStatus.BLOCKED
    )


def test_contract_pack_source_tool_and_test_digests_are_not_silently_ignored() -> None:
    assert (
        _status(
            _snapshot(),
            _snapshot(contract_digests={"finance": "sha256:" + "1" * 64}),
        )
        is UsageImpactStatus.REGENERATE
    )
    assert (
        _status(_snapshot(), _snapshot(pack_digest="sha256:" + "1" * 64))
        is UsageImpactStatus.REVALIDATE
    )
    assert (
        _status(_snapshot(), _snapshot(test_report_digest="sha256:" + "1" * 64))
        is UsageImpactStatus.REVALIDATE
    )
    assert (
        _status(_snapshot(), _snapshot(source_snapshot_digest="sha256:" + "1" * 64))
        is UsageImpactStatus.REVALIDATE
    )
    assert (
        _status(_snapshot(), _snapshot(tool_schema_digest="sha256:" + "1" * 64))
        is UsageImpactStatus.REVALIDATE
    )


def test_unrelated_domain_is_unaffected_and_direct_dependency_propagates() -> None:
    base = _report()
    finance = base.domain_contracts["finance"]
    scenario = base.scenarios["finance-list-happy"]
    orders = finance.model_copy(
        update={"domain_id": "orders", "required_scenario_ids": ["orders-list-happy"]}
    )
    orders_scenario = scenario.model_copy(
        update={"domain_id": "orders", "scenario_id": "orders-list-happy"}
    )
    index = DomainUsageIndex.model_validate(
        {
            **base.domain_index.model_dump(mode="json"),  # type: ignore[union-attr]
            "domains": [
                {"id": "finance", "dependency_domain_ids": []},
                {"id": "orders", "dependency_domain_ids": ["finance"]},
            ],
            "preferred_order": ["finance", "orders"],
        }
    )
    report = UsageProjectReport(
        root=base.root,
        project=base.project,
        acceptance=base.acceptance,
        source_snapshot=base.source_snapshot,
        domain_index=index,
        domain_contracts=MappingProxyType({"finance": finance, "orders": orders}),
        scenarios=MappingProxyType(
            {
                "finance-list-happy": scenario,
                "orders-list-happy": orders_scenario,
            }
        ),
        decisions=base.decisions,
        releases=base.releases,
        evidence_registry=base.evidence_registry,
        diagnostics=base.diagnostics,
    )
    before = _snapshot(contract_digests={"finance": _D, "orders": _D})
    after = before.model_copy(
        update={"contract_digests": {"finance": "sha256:" + "1" * 64, "orders": _D}}
    )

    result = analyze_usage_impact(before=before, after=after, report=report)

    assert result.domain("finance").status is UsageImpactStatus.REGENERATE
    assert result.domain("orders").status is UsageImpactStatus.REGENERATE
    assert result.domain("orders").upstream_domain_ids == ("finance",)

    unrelated_after = before.model_copy(
        update={"contract_digests": {"finance": _D, "orders": "sha256:" + "2" * 64}}
    )
    unrelated = analyze_usage_impact(before=before, after=unrelated_after, report=report)
    assert unrelated.domain("finance").status is UsageImpactStatus.UNAFFECTED


def test_unknown_schema_relation_fails_closed_without_echoing_schemas() -> None:
    after = _snapshot(
        tool_schema_digest="sha256:" + "1" * 64,
        tool_schemas={
            "finance_invoice_list": {
                "input_schema": {"$ref": "https://example.invalid/schema"},
                "output_schema": {"type": "object"},
            }
        },
    )

    result = analyze_usage_impact(before=_snapshot(), after=after, report=_report())
    item = result.domain("finance")

    assert item.status is UsageImpactStatus.BLOCKED
    assert item.domain_id == "finance"
    assert item.scenario_ids == ("finance-list-happy",)
    assert item.route_ids == ("invoice-list",)
    assert item.step_ids == ("list",)
    assert item.capability_ids == ("finance.invoice.list",)
    assert item.tool_names == ("finance_invoice_list",)
    assert item.evidence_source_ids == (
        "client:finance-screen",
        "mcp:finance-invoice-list",
    )
    rendered = repr(result)
    assert "properties" not in rendered
    assert "example.invalid" not in rendered
