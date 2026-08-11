from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

import acc_core.usage.verification as verification_module
from acc_core.usage.analyze import UsageAnalysisReport
from acc_core.usage.project import validate_usage_project
from acc_core.usage.verification import (
    UsageAxisReport,
    UsageVerificationAxis,
    UsageVerificationTraceEntry,
    VerifiedUsageReleaseBundle,
    build_agent_usage_release,
    derive_usage_verification,
    ingest_source_usage_evidence,
    ingest_usage_contract_analysis,
    ingest_user_acceptance,
)

_D1 = "sha256:" + "1" * 64
_D2 = "sha256:" + "2" * 64
_D3 = "sha256:" + "3" * 64
_D4 = "sha256:" + "4" * 64


def _canonical_digest(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
    )


def _trace(
    axis: UsageVerificationAxis,
    scenario_id: str,
    *,
    status: str = "passed",
    sequence: int = 1,
    call_number: int = 1,
    adapter_id: str | None = None,
) -> UsageVerificationTraceEntry:
    return UsageVerificationTraceEntry.model_validate(
        {
            "axis": axis,
            "adapter_id": adapter_id,
            "sequence": sequence,
            "scenario_id": scenario_id,
            "route_id": "route.main",
            "tool_name": "records.find",
            "phase": "status" if axis == "real_mcp_verified" else None,
            "call_number": call_number,
            "status": status,
            "artifact_digest": _D1,
        }
    )


def _report(
    axis: UsageVerificationAxis,
    *,
    status: str = "passed",
    adapter_id: str | None = None,
) -> UsageAxisReport:
    return UsageAxisReport.from_trace(
        axis=axis,
        domain_id="records",
        required_scenario_ids=("scenario.main",),
        trace=(_trace(axis, "scenario.main", status=status, adapter_id=adapter_id),),
        evidence_references=(_D2,),
        contract_digest="sha256:" + "6" * 64,
        scenario_digests={"scenario.main": _D3},
        package_digest=_D1,
        decision_digest="sha256:" + "7" * 64,
        adapter_id=adapter_id,
    )


def test_public_caller_authored_trace_cannot_create_a_verified_axis_report() -> None:
    """A valid-looking, all-passed trace is data, not a verification authority."""

    assert not _report("real_mcp_verified").verified


def test_module_does_not_export_a_reusable_axis_capability() -> None:
    assert not hasattr(verification_module, "_AXIS_EVIDENCE_CAPABILITIES")
    assert not hasattr(UsageAxisReport, "_from_trusted_trace")
    assert not hasattr(verification_module, "_ingest_headless_agent_trace")
    assert not hasattr(verification_module, "_ingest_real_mcp_trace")
    assert not hasattr(verification_module, "_ingest_host_adapter_trace")


def test_module_does_not_expose_a_trusted_release_mint() -> None:
    assert not hasattr(verification_module, "_build_trusted_agent_usage_release")


def test_serialized_hand_authored_or_copied_release_bundle_is_never_trusted() -> None:
    project = validate_usage_project(Path(__file__).parents[2] / "fixtures" / "usage" / "finance")
    release = project.releases["finance-usage-1"]
    scenario_digests = {
        scenario_id: _canonical_digest(project.scenarios[scenario_id].model_dump(mode="json"))
        for scenario_id in release.scenario_ids
    }
    content: dict[str, object] = {
        "schema_version": "2",
        "release": release.model_dump(mode="json"),
        "report_digests": {
            "source_usage_traced": _D1,
            "usage_contract_verified": _D1,
            "headless_agent_verified": _D1,
            "host_adapter_verified:reference-host": _D1,
            "real_mcp_verified": _D1,
            "user_accepted": _D1,
        },
        "contract_digest": release.contract_digest,
        "scenario_digests": scenario_digests,
        "pack_digest": release.pack_digest,
        "decision_digest": release.decision_digest,
        "release_digest": _canonical_digest(release.model_dump(mode="json")),
    }
    forged = VerifiedUsageReleaseBundle.model_validate(
        {**content, "bundle_digest": _canonical_digest(content)}
    )
    assert not forged.trusted
    assert not VerifiedUsageReleaseBundle.model_validate_json(forged.model_dump_json()).trusted
    assert not forged.model_copy().trusted


def test_exact_denominator_and_all_nonpassed_states_block_axis() -> None:
    for status in ("not_run", "failed", "stale", "blocked"):
        assert not _report("headless_agent_verified", status=status).verified

    with pytest.raises(ValueError, match="exact denominator"):
        UsageAxisReport.from_trace(
            axis="headless_agent_verified",
            domain_id="records",
            required_scenario_ids=("scenario.main", "scenario.missing"),
            trace=(_trace("headless_agent_verified", "scenario.main"),),
            evidence_references=(_D2,),
            contract_digest="sha256:" + "6" * 64,
            scenario_digests={"scenario.main": _D3, "scenario.missing": _D4},
            package_digest=_D1,
            decision_digest="sha256:" + "7" * 64,
        )


def test_trace_is_ordered_and_call_counts_are_exact() -> None:
    with pytest.raises(ValueError, match="sequence"):
        UsageAxisReport.from_trace(
            axis="headless_agent_verified",
            domain_id="records",
            required_scenario_ids=("scenario.main",),
            trace=(
                _trace("headless_agent_verified", "scenario.main", sequence=2),
                _trace("headless_agent_verified", "scenario.main", sequence=1, call_number=2),
            ),
            evidence_references=(_D2,),
            contract_digest="sha256:" + "6" * 64,
            scenario_digests={"scenario.main": _D3},
            package_digest=_D1,
            decision_digest="sha256:" + "7" * 64,
        )


def test_report_digest_is_stable_but_serialized_report_cannot_self_verify() -> None:
    report = _report("usage_contract_verified")
    same = _report("usage_contract_verified")
    assert report.report_digest == same.report_digest
    assert not report.verified

    reloaded = UsageAxisReport.model_validate_json(report.model_dump_json())
    assert reloaded.report_digest == report.report_digest
    assert not reloaded.verified

    reingested = UsageAxisReport.from_trace(
        axis=reloaded.axis,
        domain_id=reloaded.domain_id,
        required_scenario_ids=reloaded.required_scenario_ids,
        trace=report.trace,
        evidence_references=reloaded.evidence_references,
        contract_digest=reloaded.contract_digest,
        scenario_digests=reloaded.scenario_digests,
        package_digest=reloaded.package_digest,
        decision_digest=reloaded.decision_digest,
        adapter_id=reloaded.adapter_id,
    )
    assert not reingested.verified


def test_source_and_acceptance_upgrade_only_their_own_axes() -> None:
    projection = derive_usage_verification(
        reports=(
            _report("source_usage_traced"),
            _report("user_accepted"),
        ),
        domain_id="records",
        required_scenario_ids=("scenario.main",),
    )
    assert not projection.verification.source_usage_traced
    assert not projection.verification.user_accepted
    assert not projection.verification.usage_contract_verified
    assert not projection.verification.headless_agent_verified
    assert not projection.verification.real_mcp_verified
    assert projection.report_digests == {
        "source_usage_traced": _report("source_usage_traced").report_digest,
        "user_accepted": _report("user_accepted").report_digest,
    }

    with pytest.raises(ValueError, match="exact scenario denominator"):
        derive_usage_verification(
            reports=(_report("source_usage_traced"),),
            domain_id="records",
            required_scenario_ids=("scenario.main", "scenario.other"),
        )


def test_axis_specific_ingestors_consume_typed_artifacts_and_keep_axes_independent() -> None:
    project = validate_usage_project(Path(__file__).parents[2] / "fixtures" / "usage" / "finance")
    assert project.ok
    contract = project.domain_contracts["finance"]
    scenarios = tuple(project.scenarios[item] for item in contract.required_scenario_ids)
    decision = project.decisions[("finance", 1)]
    source = ingest_source_usage_evidence(
        project=project,
        contract=contract,
        scenarios=scenarios,
        decision=decision,
    )
    analyzed = ingest_usage_contract_analysis(
        analysis=UsageAnalysisReport(domain_id="finance", diagnostics=()),
        contract=contract,
        scenarios=scenarios,
        decision=decision,
    )
    accepted = ingest_user_acceptance(
        contract=contract,
        scenarios=scenarios,
        decision=decision,
    )
    assert source.verified and not analyzed.verified and accepted.verified
    assert not source.model_copy().verified
    assert not accepted.model_copy().verified
    projection = derive_usage_verification(
        reports=(source, analyzed, accepted),
        domain_id="finance",
        required_scenario_ids=contract.required_scenario_ids,
    )
    assert projection.verification.source_usage_traced
    assert not projection.verification.usage_contract_verified
    assert projection.verification.user_accepted
    assert not projection.verification.headless_agent_verified
    assert not projection.verification.real_mcp_verified


def _release_without_verification() -> dict[str, object]:
    return {
        "schema_version": "2",
        "usage_release_id": "usage-records-1",
        "domain_id": "records",
        "mcp_release_id": "mcp-1",
        "pack_digest": _D1,
        "ir_digest": _D2,
        "tool_schema_digest": "sha256:" + "3" * 64,
        "test_report_digest": "sha256:" + "4" * 64,
        "source_snapshot_digest": "sha256:" + "5" * 64,
        "contract_digest": "sha256:" + "6" * 64,
        "decision_digest": "sha256:" + "7" * 64,
        "business_goal_ids": ["goal.main"],
        "route_ids": ["route.main"],
        "scenario_ids": ["scenario.main"],
        "capability_ids": ["cap.records.find"],
        "release_status": "released",
        "known_limitations": [],
        "host_adapters": [],
        "released_at": "2026-08-11T00:00:00Z",
    }


def test_release_builder_ignores_no_caller_boolean_and_requires_verified_reports() -> None:
    axes: tuple[UsageVerificationAxis, ...] = (
        "source_usage_traced",
        "usage_contract_verified",
        "headless_agent_verified",
        "real_mcp_verified",
        "user_accepted",
    )
    reports = tuple(_report(axis) for axis in axes)
    with pytest.raises(ValueError, match="verified reports"):
        build_agent_usage_release(
            release_document=_release_without_verification(),
            reports=reports,
            scenario_digests={"scenario.main": _D3},
        )

    forged = deepcopy(_release_without_verification())
    forged["verification"] = {axis: True for axis in axes} | {"host_adapter_verified": True}
    with pytest.raises(ValueError, match="caller-supplied verification"):
        build_agent_usage_release(
            release_document=forged,
            reports=reports,
            scenario_digests={"scenario.main": _D3},
        )

    serialized = tuple(
        UsageAxisReport.model_validate_json(report.model_dump_json()) for report in reports
    )
    with pytest.raises(ValueError, match="verified reports"):
        build_agent_usage_release(
            release_document=_release_without_verification(),
            reports=serialized,
            scenario_digests={"scenario.main": _D3},
        )


def test_release_host_adapter_list_must_match_independently_verified_reports() -> None:
    document = _release_without_verification()
    document["host_adapters"] = ["codex"]
    axes: tuple[UsageVerificationAxis, ...] = (
        "source_usage_traced",
        "usage_contract_verified",
        "headless_agent_verified",
        "real_mcp_verified",
        "user_accepted",
    )
    reports = tuple(_report(axis) for axis in axes)
    with pytest.raises(ValueError, match="verified reports"):
        build_agent_usage_release(
            release_document=document,
            reports=reports,
            scenario_digests={"scenario.main": _D3},
            required_host_adapter_ids=("codex",),
        )

    with pytest.raises(ValueError, match="must match"):
        build_agent_usage_release(
            release_document=document,
            reports=reports,
            scenario_digests={"scenario.main": _D3},
            required_host_adapter_ids=("claude",),
        )
