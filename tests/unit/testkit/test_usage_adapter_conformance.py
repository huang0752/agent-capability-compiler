from __future__ import annotations

import pytest

from acc_testkit.usage import (
    HostAdapterConformanceReport,
    HostAdapterTraceEntry,
    derive_host_adapter_axis,
)

_D1 = "sha256:" + "a" * 64
_D2 = "sha256:" + "b" * 64
_CONTRACT_DIGEST = "sha256:" + "c" * 64
_SCENARIO_DIGESTS = {"scenario.main": "sha256:" + "d" * 64}
_PACKAGE_DIGEST = "sha256:" + "e" * 64
_DECISION_DIGEST = "sha256:" + "f" * 64


def _entry(
    adapter_id: str,
    scenario_id: str,
    *,
    status: str = "passed",
    sequence: int = 1,
) -> HostAdapterTraceEntry:
    return HostAdapterTraceEntry.model_validate(
        {
            "adapter_id": adapter_id,
            "sequence": sequence,
            "scenario_id": scenario_id,
            "route_id": "route.main",
            "tool_name": "records.find",
            "phase": None,
            "call_number": 1,
            "status": status,
            "artifact_digest": _D1,
        }
    )


@pytest.mark.parametrize("status", ["skipped", "not_provisioned", "stale", "failed"])
def test_required_nonpass_blocks_adapter(status: str) -> None:
    report = HostAdapterConformanceReport._from_runner_trace(
        adapter_id="claude",
        domain_id="records",
        required_scenario_ids=("scenario.main",),
        trace=(_entry("claude", "scenario.main", status=status),),
        evidence_references=(_D2,),
    )
    assert not report.verified
    assert not derive_host_adapter_axis(
        reports=(report,),
        domain_id="records",
        required_adapter_ids=("claude",),
        required_scenario_ids=("scenario.main",),
        contract_digest=_CONTRACT_DIGEST,
        scenario_digests=_SCENARIO_DIGESTS,
        package_digest=_PACKAGE_DIGEST,
        decision_digest=_DECISION_DIGEST,
    ).verification.host_adapter_verified


def test_each_adapter_has_an_independent_exact_denominator() -> None:
    claude = HostAdapterConformanceReport._from_runner_trace(
        adapter_id="claude",
        domain_id="records",
        required_scenario_ids=("scenario.main",),
        trace=(_entry("claude", "scenario.main"),),
        evidence_references=(_D2,),
    )
    assert claude.verified
    projection = derive_host_adapter_axis(
        reports=(claude,),
        domain_id="records",
        required_adapter_ids=("claude", "codex"),
        required_scenario_ids=("scenario.main",),
        contract_digest=_CONTRACT_DIGEST,
        scenario_digests=_SCENARIO_DIGESTS,
        package_digest=_PACKAGE_DIGEST,
        decision_digest=_DECISION_DIGEST,
    )
    assert not projection.verification.host_adapter_verified

    with pytest.raises(ValueError, match="adapter_id"):
        HostAdapterConformanceReport._from_runner_trace(
            adapter_id="codex",
            domain_id="records",
            required_scenario_ids=("scenario.main",),
            trace=(_entry("claude", "scenario.main"),),
            evidence_references=(_D2,),
        )


def test_adapter_trace_preserves_order_counts_route_tool_phase_and_artifact_digest() -> None:
    report = HostAdapterConformanceReport._from_runner_trace(
        adapter_id="codex",
        domain_id="records",
        required_scenario_ids=("scenario.main",),
        trace=(_entry("codex", "scenario.main"),),
        evidence_references=(_D2,),
    )
    entry = report.trace[0]
    assert (
        entry.sequence,
        entry.call_number,
        entry.route_id,
        entry.tool_name,
        entry.phase,
        entry.artifact_digest,
    ) == (1, 1, "route.main", "records.find", None, _D1)


def test_serialized_adapter_report_requires_trace_reingestion() -> None:
    report = HostAdapterConformanceReport._from_runner_trace(
        adapter_id="codex",
        domain_id="records",
        required_scenario_ids=("scenario.main",),
        trace=(_entry("codex", "scenario.main"),),
        evidence_references=(_D2,),
    )
    reloaded = HostAdapterConformanceReport.model_validate_json(report.model_dump_json())
    assert reloaded.report_digest == report.report_digest
    assert not reloaded.verified
    projection = derive_host_adapter_axis(
        reports=(reloaded,),
        domain_id="records",
        required_adapter_ids=("codex",),
        required_scenario_ids=("scenario.main",),
        contract_digest=_CONTRACT_DIGEST,
        scenario_digests=_SCENARIO_DIGESTS,
        package_digest=_PACKAGE_DIGEST,
        decision_digest=_DECISION_DIGEST,
    )
    assert not projection.verification.host_adapter_verified


def test_caller_authored_host_trace_has_no_public_trust_escalator() -> None:
    assert not hasattr(HostAdapterConformanceReport, "from_trace")
