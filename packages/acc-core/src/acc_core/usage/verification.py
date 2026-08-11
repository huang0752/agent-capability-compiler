"""Trace-derived, independent verification axes for Agent Usage releases."""

from __future__ import annotations

import hashlib
import json
import sys
import weakref
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, PrivateAttr, field_validator, model_validator

from acc_core.models import Sha256Digest
from acc_core.usage.acceptance import McpReleaseAcceptanceVerification, _is_live_acceptance
from acc_core.usage.analyze import UsageAnalysisReport, _is_live_analysis
from acc_core.usage.models import (
    AgentUsageRelease,
    DomainUsageContract,
    Identifier,
    SourceSnapshot,
    UsageDomainDecision,
    UsageModel,
    UsageScenario,
    UsageVerification,
)
from acc_core.usage.project import UsageProjectReport

type UsageVerificationAxis = Literal[
    "source_usage_traced",
    "usage_contract_verified",
    "headless_agent_verified",
    "host_adapter_verified",
    "real_mcp_verified",
    "user_accepted",
]
type UsageVerificationStatus = Literal["not_run", "passed", "failed", "stale", "blocked"]
type UsageActionPhase = Literal["prepare", "approve", "commit", "status"]

_AXES: tuple[UsageVerificationAxis, ...] = (
    "source_usage_traced",
    "usage_contract_verified",
    "headless_agent_verified",
    "host_adapter_verified",
    "real_mcp_verified",
    "user_accepted",
)


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _stable_ids(values: Sequence[str], *, name: str, allow_empty: bool = False) -> tuple[str, ...]:
    result = tuple(values)
    if not allow_empty and not result:
        raise ValueError(f"{name} must not be empty")
    if any(not item or item != item.strip() for item in result):
        raise ValueError(f"{name} must contain exact nonempty identifiers")
    if result != tuple(sorted(set(result))):
        raise ValueError(f"{name} must be sorted and unique")
    return result


class UsageVerificationTraceEntry(UsageModel):
    """One ordered, payload-free observation used to derive an axis report."""

    axis: UsageVerificationAxis
    adapter_id: Identifier | None = None
    sequence: int = Field(ge=1)
    scenario_id: Identifier
    route_id: Identifier
    tool_name: Identifier
    phase: UsageActionPhase | None = None
    call_number: int = Field(ge=1)
    status: UsageVerificationStatus
    artifact_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_adapter_scope(self) -> Self:
        if (self.axis == "host_adapter_verified") != (self.adapter_id is not None):
            raise ValueError("adapter_id is required only for the host adapter axis")
        return self


class UsageAxisReport(UsageModel):
    """Exact-denominator report whose verification state exists only after trace ingestion."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    schema_version: Literal["2"] = "2"
    axis: UsageVerificationAxis
    domain_id: Identifier
    adapter_id: Identifier | None = None
    contract_digest: Sha256Digest
    scenario_digests: dict[Identifier, Sha256Digest]
    package_digest: Sha256Digest
    decision_digest: Sha256Digest
    required_scenario_ids: tuple[Identifier, ...] = Field(min_length=1)
    scenario_statuses: dict[Identifier, UsageVerificationStatus]
    trace: tuple[UsageVerificationTraceEntry, ...] = Field(min_length=1)
    call_count: int = Field(ge=1)
    evidence_references: tuple[Sha256Digest, ...] = Field(min_length=1)
    report_digest: Sha256Digest
    _trace_derived: bool = PrivateAttr(default=False)
    _verification_fingerprint: str | None = PrivateAttr(default=None)

    @field_validator("required_scenario_ids")
    @classmethod
    def validate_required_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _stable_ids(value, name="required_scenario_ids")

    @field_validator("evidence_references")
    @classmethod
    def validate_evidence_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _stable_ids(value, name="evidence_references")

    @model_validator(mode="after")
    def validate_public_report(self) -> Self:
        if (self.axis == "host_adapter_verified") != (self.adapter_id is not None):
            raise ValueError("adapter_id is required only for the host adapter axis")
        if tuple(sorted(self.scenario_statuses)) != self.required_scenario_ids:
            raise ValueError("scenario statuses must match the exact denominator")
        if tuple(sorted(self.scenario_digests)) != self.required_scenario_ids:
            raise ValueError("scenario digests must match the exact denominator")
        _validate_trace(
            self.trace,
            axis=self.axis,
            adapter_id=self.adapter_id,
            required_scenario_ids=self.required_scenario_ids,
        )
        if self.call_count != len(self.trace):
            raise ValueError("call_count must equal the ordered trace length")
        last_status = {entry.scenario_id: entry.status for entry in self.trace}
        if last_status != self.scenario_statuses:
            raise ValueError("scenario statuses must equal terminal trace statuses")
        if self.report_digest != self._calculated_digest():
            raise ValueError("report_digest must match canonical report content")
        return self

    @classmethod
    def from_trace(
        cls,
        *,
        axis: UsageVerificationAxis,
        domain_id: str,
        required_scenario_ids: Sequence[str],
        trace: Sequence[UsageVerificationTraceEntry],
        evidence_references: Sequence[str],
        contract_digest: str,
        scenario_digests: Mapping[str, str],
        package_digest: str,
        decision_digest: str,
        adapter_id: str | None = None,
    ) -> UsageAxisReport:
        """Parse caller-authored trace as an unverified diagnostic report.

        Trace shape and digests are validated, but data alone never grants a
        release gate.  Axis-specific ingestors must consume live typed results.
        """

        return cls._from_trace_data(
            axis=axis,
            domain_id=domain_id,
            required_scenario_ids=required_scenario_ids,
            trace=trace,
            evidence_references=evidence_references,
            contract_digest=contract_digest,
            scenario_digests=scenario_digests,
            package_digest=package_digest,
            decision_digest=decision_digest,
            adapter_id=adapter_id,
        )

    @classmethod
    def _from_trace_data(
        cls,
        *,
        axis: UsageVerificationAxis,
        domain_id: str,
        required_scenario_ids: Sequence[str],
        trace: Sequence[UsageVerificationTraceEntry],
        evidence_references: Sequence[str],
        contract_digest: str,
        scenario_digests: Mapping[str, str],
        package_digest: str,
        decision_digest: str,
        adapter_id: str | None = None,
    ) -> UsageAxisReport:
        required = _stable_ids(required_scenario_ids, name="required_scenario_ids")
        evidence = _stable_ids(evidence_references, name="evidence_references")
        captured = tuple(trace)
        _validate_trace(
            captured,
            axis=axis,
            adapter_id=adapter_id,
            required_scenario_ids=required,
        )
        statuses = {entry.scenario_id: entry.status for entry in captured}
        content: dict[str, object] = {
            "schema_version": "2",
            "axis": axis,
            "domain_id": domain_id,
            "adapter_id": adapter_id,
            "contract_digest": contract_digest,
            "scenario_digests": dict(sorted(scenario_digests.items())),
            "package_digest": package_digest,
            "decision_digest": decision_digest,
            "required_scenario_ids": required,
            "scenario_statuses": statuses,
            "trace": tuple(entry.model_dump(mode="json") for entry in captured),
            "call_count": len(captured),
            "evidence_references": evidence,
        }
        report = cls.model_validate({**content, "report_digest": _canonical_digest(content)})
        return report

    def _calculated_digest(self) -> str:
        return _canonical_digest(self.model_dump(mode="json", exclude={"report_digest"}))

    def _public_fingerprint(self) -> str:
        return _canonical_digest(self.model_dump(mode="json"))

    @property
    def verified(self) -> bool:
        return (
            _is_live_axis_report(self)
            and self._trace_derived
            and self._verification_fingerprint == self._public_fingerprint()
            and all(status == "passed" for status in self.scenario_statuses.values())
        )


def _validate_trace(
    trace: Sequence[UsageVerificationTraceEntry],
    *,
    axis: UsageVerificationAxis,
    adapter_id: str | None,
    required_scenario_ids: Sequence[str],
) -> None:
    if not trace:
        raise ValueError("trace must not be empty")
    if [entry.sequence for entry in trace] != list(range(1, len(trace) + 1)):
        raise ValueError("trace sequence must be contiguous and ordered")
    required = set(required_scenario_ids)
    observed = {entry.scenario_id for entry in trace}
    if observed != required:
        raise ValueError("trace scenarios must match the exact denominator")
    if any(entry.axis != axis or entry.adapter_id != adapter_id for entry in trace):
        raise ValueError("trace axis and adapter_id must match the report")
    calls: Counter[str] = Counter()
    for entry in trace:
        calls[entry.scenario_id] += 1
        if entry.call_number != calls[entry.scenario_id]:
            raise ValueError("trace call_number must be contiguous per scenario")


def _build_host_adapter_trace_report(
    *,
    domain_id: str,
    adapter_id: str,
    required_scenario_ids: Sequence[str],
    trace: Sequence[UsageVerificationTraceEntry],
    evidence_references: Sequence[str],
    contract_digest: str,
    scenario_digests: Mapping[str, str],
    package_digest: str,
    decision_digest: str,
) -> UsageAxisReport:
    """Internal boundary used only after a host runner validates its live result."""

    report = UsageAxisReport._from_trace_data(
        axis="host_adapter_verified",
        domain_id=domain_id,
        adapter_id=adapter_id,
        required_scenario_ids=required_scenario_ids,
        trace=trace,
        evidence_references=evidence_references,
        contract_digest=contract_digest,
        scenario_digests=scenario_digests,
        package_digest=package_digest,
        decision_digest=decision_digest,
    )
    object.__setattr__(report, "_trace_derived", True)
    object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
    return report


def _build_headless_agent_trace_report(
    *,
    domain_id: str,
    required_scenario_ids: Sequence[str],
    trace: Sequence[UsageVerificationTraceEntry],
    evidence_references: Sequence[str],
    contract_digest: str,
    scenario_digests: Mapping[str, str],
    package_digest: str,
    decision_digest: str,
) -> UsageAxisReport:
    """Internal boundary used after Testkit validates evaluator provenance."""

    report = UsageAxisReport._from_trace_data(
        axis="headless_agent_verified",
        domain_id=domain_id,
        required_scenario_ids=required_scenario_ids,
        trace=trace,
        evidence_references=evidence_references,
        contract_digest=contract_digest,
        scenario_digests=scenario_digests,
        package_digest=package_digest,
        decision_digest=decision_digest,
    )
    object.__setattr__(report, "_trace_derived", True)
    object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
    return report


def _build_real_mcp_trace_report(
    *,
    domain_id: str,
    required_scenario_ids: Sequence[str],
    trace: Sequence[UsageVerificationTraceEntry],
    evidence_references: Sequence[str],
    contract_digest: str,
    scenario_digests: Mapping[str, str],
    package_digest: str,
    decision_digest: str,
) -> UsageAxisReport:
    report = UsageAxisReport._from_trace_data(
        axis="real_mcp_verified",
        domain_id=domain_id,
        required_scenario_ids=required_scenario_ids,
        trace=trace,
        evidence_references=evidence_references,
        contract_digest=contract_digest,
        scenario_digests=scenario_digests,
        package_digest=package_digest,
        decision_digest=decision_digest,
    )
    object.__setattr__(report, "_trace_derived", True)
    object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
    return report


def _artifact_context(
    *,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    decision: UsageDomainDecision,
) -> tuple[tuple[str, ...], dict[str, str]]:
    required = _stable_ids(contract.required_scenario_ids, name="required_scenario_ids")
    scenario_by_id = {item.scenario_id: item for item in scenarios}
    if tuple(sorted(scenario_by_id)) != required:
        raise ValueError("typed scenarios must match the exact contract denominator")
    if any(item.domain_id != contract.domain_id for item in scenarios):
        raise ValueError("typed scenario domain does not match the contract")
    contract_digest = _canonical_digest(contract.model_dump(mode="json"))
    if (
        decision.domain_id != contract.domain_id
        or decision.disposition != "accepted"
        or decision.contract_digest != contract_digest
    ):
        raise ValueError("accepted decision must bind the exact typed contract")
    if set(decision.included_route_ids) != {item.route_id for item in scenarios}:
        raise ValueError("accepted decision routes must match the scenario routes")
    return required, {
        item.scenario_id: _canonical_digest(item.model_dump(mode="json"))
        for item in sorted(scenarios, key=lambda value: value.scenario_id)
    }


def _artifact_trace(
    *,
    axis: UsageVerificationAxis,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    artifact_digest: str,
) -> tuple[UsageVerificationTraceEntry, ...]:
    routes = {route.id: route for route in contract.tool_routes}
    entries: list[UsageVerificationTraceEntry] = []
    for sequence, scenario in enumerate(sorted(scenarios, key=lambda item: item.scenario_id), 1):
        route = routes.get(scenario.route_id)
        if route is None or not route.steps:
            raise ValueError("typed scenario route must resolve to a Tool step")
        step = route.steps[0]
        entries.append(
            UsageVerificationTraceEntry(
                axis=axis,
                sequence=sequence,
                scenario_id=scenario.scenario_id,
                route_id=route.id,
                tool_name=step.tool_name,
                phase=step.action_phase,
                call_number=1,
                status="passed",
                artifact_digest=artifact_digest,
            )
        )
    return tuple(entries)


def ingest_source_usage_evidence(
    *,
    project: UsageProjectReport,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    decision: UsageDomainDecision,
) -> UsageAxisReport:
    """Verify the source axis from the independently loaded typed project only."""

    if not project.ok or project.source_snapshot is None:
        raise ValueError("source Usage ingestion requires a valid typed project")
    loaded_contract = project.domain_contracts.get(contract.domain_id)
    if loaded_contract is None or loaded_contract != contract:
        raise ValueError("source Usage ingestion requires the exact loaded contract")
    snapshot: SourceSnapshot = project.source_snapshot
    snapshot_digest = _canonical_digest(snapshot.model_dump(mode="json"))
    if contract.source_snapshot_digest != snapshot_digest:
        raise ValueError("source snapshot does not match the exact contract binding")
    evidence_refs = {
        reference.source_id: reference.digest
        for claim in contract.evidence_claims
        for reference in claim.evidence_refs
    }
    if not evidence_refs or any(
        source_id not in project.evidence_registry
        or project.evidence_registry[source_id].digest != digest
        for source_id, digest in evidence_refs.items()
    ):
        raise ValueError("contract evidence closure must match loaded typed Evidence")
    required, scenario_digests = _artifact_context(
        contract=contract, scenarios=scenarios, decision=decision
    )
    report = UsageAxisReport._from_trace_data(
        axis="source_usage_traced",
        domain_id=contract.domain_id,
        required_scenario_ids=required,
        trace=_artifact_trace(
            axis="source_usage_traced",
            contract=contract,
            scenarios=scenarios,
            artifact_digest=snapshot_digest,
        ),
        evidence_references=tuple(sorted(set(evidence_refs.values()))),
        contract_digest=_canonical_digest(contract.model_dump(mode="json")),
        scenario_digests=scenario_digests,
        package_digest=contract.pack_digest,
        decision_digest=decision.decision_digest,
    )
    object.__setattr__(report, "_trace_derived", True)
    object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
    return report


def ingest_usage_contract_analysis(
    *,
    analysis: UsageAnalysisReport,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    decision: UsageDomainDecision,
) -> UsageAxisReport:
    """Verify only a successful deterministic analysis of the exact contract."""

    if not analysis.ok or analysis.domain_id != contract.domain_id:
        raise ValueError("contract axis requires a successful exact-domain analysis")
    required, scenario_digests = _artifact_context(
        contract=contract, scenarios=scenarios, decision=decision
    )
    artifact_digest = _canonical_digest(
        {
            "domain_id": analysis.domain_id,
            "diagnostics": [item.model_dump(mode="json") for item in analysis.diagnostics],
            "capability_ids": analysis.capability_ids,
            "tool_names": analysis.tool_names,
        }
    )
    report = UsageAxisReport._from_trace_data(
        axis="usage_contract_verified",
        domain_id=contract.domain_id,
        required_scenario_ids=required,
        trace=_artifact_trace(
            axis="usage_contract_verified",
            contract=contract,
            scenarios=scenarios,
            artifact_digest=artifact_digest,
        ),
        evidence_references=(artifact_digest,),
        contract_digest=_canonical_digest(contract.model_dump(mode="json")),
        scenario_digests=scenario_digests,
        package_digest=contract.pack_digest,
        decision_digest=decision.decision_digest,
    )
    if analysis.trusted:
        object.__setattr__(report, "_trace_derived", True)
        object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
    return report


def ingest_user_acceptance(
    *,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    decision: UsageDomainDecision,
) -> UsageAxisReport:
    """Verify only the typed accepted decision and its digest-bound confirmation."""

    required, scenario_digests = _artifact_context(
        contract=contract, scenarios=scenarios, decision=decision
    )
    report = UsageAxisReport._from_trace_data(
        axis="user_accepted",
        domain_id=contract.domain_id,
        required_scenario_ids=required,
        trace=_artifact_trace(
            axis="user_accepted",
            contract=contract,
            scenarios=scenarios,
            artifact_digest=decision.decision_digest,
        ),
        evidence_references=tuple(
            sorted(
                {
                    decision.decision_digest,
                    decision.user_confirmation.source_text_digest,
                }
            )
        ),
        contract_digest=_canonical_digest(contract.model_dump(mode="json")),
        scenario_digests=scenario_digests,
        package_digest=contract.pack_digest,
        decision_digest=decision.decision_digest,
    )
    object.__setattr__(report, "_trace_derived", True)
    object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
    return report


def _make_live_axis_ingestors(
    functions: tuple[Callable[..., UsageAxisReport], ...],
) -> tuple[
    tuple[Callable[..., UsageAxisReport], ...],
    Callable[[UsageAxisReport], bool],
    Callable[[UsageAxisReport], UsageAxisReport],
]:
    live: dict[int, tuple[weakref.ReferenceType[UsageAxisReport], str]] = {}

    def wrap(
        function: Callable[..., UsageAxisReport],
    ) -> Callable[..., UsageAxisReport]:
        def ingest(*args: object, **kwargs: object) -> UsageAxisReport:
            report = function(*args, **kwargs)
            identity = id(report)

            def discard(_reference: object) -> None:
                live.pop(identity, None)

            live[identity] = (weakref.ref(report, discard), report._public_fingerprint())
            return report

        return ingest

    def is_live(report: UsageAxisReport) -> bool:
        record = live.get(id(report))
        return (
            record is not None
            and record[0]() is report
            and record[1] == report._public_fingerprint()
        )

    def register_execution(report: UsageAxisReport) -> UsageAxisReport:
        identity = id(report)

        def discard(_reference: object) -> None:
            live.pop(identity, None)

        live[identity] = (weakref.ref(report, discard), report._public_fingerprint())
        return report

    return tuple(wrap(function) for function in functions), is_live, register_execution


(
    (
        ingest_source_usage_evidence,
        ingest_usage_contract_analysis,
        ingest_user_acceptance,
    ),
    _is_live_axis_report,
    _register_execution_axis_report,
) = _make_live_axis_ingestors(
    (
        ingest_source_usage_evidence,
        ingest_usage_contract_analysis,
        ingest_user_acceptance,
    )
)
del _make_live_axis_ingestors


class UsageVerificationProjection(UsageModel):
    """Derived release wire fields plus the exact reports that supplied them."""

    domain_id: Identifier
    verification: UsageVerification
    report_digests: dict[str, Sha256Digest]


class VerifiedUsageReleaseBundle(UsageModel):
    """Live release authority; serialized content is only an untrusted claim."""

    schema_version: Literal["2"] = "2"
    release: AgentUsageRelease
    report_digests: dict[str, Sha256Digest]
    contract_digest: Sha256Digest
    scenario_digests: dict[Identifier, Sha256Digest]
    pack_digest: Sha256Digest
    decision_digest: Sha256Digest
    release_digest: Sha256Digest
    bundle_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if (
            self.contract_digest != self.release.contract_digest
            or self.pack_digest != self.release.pack_digest
            or self.decision_digest != self.release.decision_digest
        ):
            raise ValueError("verified bundle bindings must match the exact release")
        if tuple(sorted(self.scenario_digests)) != tuple(self.release.scenario_ids):
            raise ValueError("verified bundle scenarios must match the exact release denominator")
        expected_release_digest = _canonical_digest(self.release.model_dump(mode="json"))
        if self.release_digest != expected_release_digest:
            raise ValueError("release_digest must match the exact release")
        expected_bundle_digest = _canonical_digest(
            self.model_dump(mode="json", exclude={"bundle_digest"})
        )
        if self.bundle_digest != expected_bundle_digest:
            raise ValueError("bundle_digest must match the exact bundle")
        required_report_keys: set[str] = {
            axis
            for axis in _AXES
            if axis != "host_adapter_verified" and getattr(self.release.verification, axis)
        }
        if self.release.verification.host_adapter_verified:
            required_report_keys.update(
                f"host_adapter_verified:{adapter_id}" for adapter_id in self.release.host_adapters
            )
        if not required_report_keys <= set(self.report_digests):
            raise ValueError("verified bundle is missing an enabled axis report digest")
        return self

    def _public_fingerprint(self) -> str:
        return _canonical_digest(self.model_dump(mode="json"))

    @property
    def trusted(self) -> bool:
        return _is_live_bundle(self)


def derive_usage_verification(
    *,
    reports: Sequence[UsageAxisReport],
    domain_id: str,
    required_scenario_ids: Sequence[str],
    required_host_adapter_ids: Sequence[str] = (),
    contract_digest: str | None = None,
    scenario_digests: Mapping[str, str] | None = None,
    package_digest: str | None = None,
    decision_digest: str | None = None,
) -> UsageVerificationProjection:
    """Project only live trace-derived reports; one axis never upgrades another."""

    required_adapters = _stable_ids(
        required_host_adapter_ids, name="required_host_adapter_ids", allow_empty=True
    )
    required_scenarios = _stable_ids(required_scenario_ids, name="required_scenario_ids")
    ordinary: dict[UsageVerificationAxis, UsageAxisReport] = {}
    adapters: dict[str, UsageAxisReport] = {}
    digests: dict[str, str] = {}
    for report in reports:
        if report.domain_id != domain_id:
            raise ValueError("verification report domain does not match release domain")
        if report.required_scenario_ids != required_scenarios:
            raise ValueError("verification report must match the exact scenario denominator")
        expected_scenario_digests = (
            dict(sorted(scenario_digests.items()))
            if scenario_digests is not None
            else reports[0].scenario_digests
        )
        expected_contract = contract_digest or reports[0].contract_digest
        expected_package = package_digest or reports[0].package_digest
        expected_decision = decision_digest or reports[0].decision_digest
        if (
            report.contract_digest != expected_contract
            or report.scenario_digests != expected_scenario_digests
            or report.package_digest != expected_package
            or report.decision_digest != expected_decision
        ):
            raise ValueError("verification report artifact bindings do not match")
        if report.axis == "host_adapter_verified":
            assert report.adapter_id is not None
            if report.adapter_id in adapters:
                raise ValueError("duplicate host adapter verification report")
            adapters[report.adapter_id] = report
            digests[f"host_adapter_verified:{report.adapter_id}"] = report.report_digest
        else:
            if report.axis in ordinary:
                raise ValueError("duplicate verification axis report")
            ordinary[report.axis] = report
            digests[report.axis] = report.report_digest

    values: dict[str, bool] = {}
    for axis in _AXES:
        if axis == "host_adapter_verified":
            continue
        axis_report = ordinary.get(axis)
        values[axis] = axis_report is not None and axis_report.verified
    values["host_adapter_verified"] = bool(required_adapters) and all(
        adapter_id in adapters and adapters[adapter_id].verified for adapter_id in required_adapters
    )
    return UsageVerificationProjection(
        domain_id=domain_id,
        verification=UsageVerification.model_validate(values),
        report_digests=dict(sorted(digests.items())),
    )


def _build_agent_usage_release_content(
    *,
    release_document: Mapping[str, object],
    reports: Sequence[UsageAxisReport],
    scenario_digests: Mapping[str, str],
    required_host_adapter_ids: Sequence[str] = (),
) -> VerifiedUsageReleaseBundle:
    """Build a release while rejecting any caller-authored verification booleans."""

    if "verification" in release_document:
        raise ValueError("caller-supplied verification is not evidence")
    domain_id = release_document.get("domain_id")
    if not isinstance(domain_id, str):
        raise ValueError("release domain_id must be an exact string")
    required_adapters = _stable_ids(
        required_host_adapter_ids, name="required_host_adapter_ids", allow_empty=True
    )
    declared_scenarios = release_document.get("scenario_ids")
    if not isinstance(declared_scenarios, list) or any(
        not isinstance(scenario_id, str) for scenario_id in declared_scenarios
    ):
        raise ValueError("release scenario_ids must be an explicit string list")
    required_scenarios = _stable_ids(declared_scenarios, name="release scenario_ids")
    declared_adapters = release_document.get("host_adapters")
    if not isinstance(declared_adapters, list) or any(
        not isinstance(adapter_id, str) for adapter_id in declared_adapters
    ):
        raise ValueError("release host_adapters must be an explicit string list")
    if tuple(declared_adapters) != required_adapters:
        raise ValueError("release host_adapters must match required host adapter ids")
    projection = derive_usage_verification(
        reports=reports,
        domain_id=domain_id,
        required_scenario_ids=required_scenarios,
        required_host_adapter_ids=required_adapters,
        contract_digest=str(release_document.get("contract_digest", "")),
        scenario_digests=scenario_digests,
        package_digest=str(release_document.get("pack_digest", "")),
        decision_digest=str(release_document.get("decision_digest", "")),
    )
    required_axes = {
        "source_usage_traced",
        "usage_contract_verified",
        "headless_agent_verified",
        "user_accepted",
    }
    if release_document.get("release_status") == "released":
        required_axes.add("real_mcp_verified")
    if required_adapters:
        required_axes.add("host_adapter_verified")
    if not all(getattr(projection.verification, axis) for axis in required_axes):
        raise ValueError("Agent Usage release requires verified reports for every release gate")
    release = AgentUsageRelease.model_validate(
        {**release_document, "verification": projection.verification.model_dump(mode="json")}
    )
    content: dict[str, object] = {
        "schema_version": "2",
        "release": release.model_dump(mode="json"),
        "report_digests": projection.report_digests,
        "contract_digest": release.contract_digest,
        "scenario_digests": dict(sorted(scenario_digests.items())),
        "pack_digest": release.pack_digest,
        "decision_digest": release.decision_digest,
        "release_digest": _canonical_digest(release.model_dump(mode="json")),
    }
    bundle = VerifiedUsageReleaseBundle.model_validate(
        {**content, "bundle_digest": _canonical_digest(content)}
    )
    return bundle


class _ReleaseBundleFinalizer(Protocol):
    def __call__(
        self,
        *,
        project: UsageProjectReport,
        accepted_mcp_release: McpReleaseAcceptanceVerification,
        analysis: UsageAnalysisReport,
        domain_id: str,
        contract: DomainUsageContract,
        scenarios: Sequence[UsageScenario],
        decision: UsageDomainDecision,
        reports: Sequence[UsageAxisReport],
        headless_results: Sequence[object],
        real_mcp_results: Sequence[object],
        headless_attestations: Mapping[str, object],
        real_mcp_attestations: Mapping[str, object],
        required_host_adapter_ids: Sequence[str] = (),
    ) -> VerifiedUsageReleaseBundle: ...


class _LiveBundleChecker(Protocol):
    def __call__(self, bundle: VerifiedUsageReleaseBundle) -> bool: ...


def build_agent_usage_release(
    *,
    release_document: Mapping[str, object],
    reports: Sequence[UsageAxisReport],
    scenario_digests: Mapping[str, str],
    required_host_adapter_ids: Sequence[str] = (),
) -> VerifiedUsageReleaseBundle:
    """Build an untrusted diagnostic bundle from caller-supplied low-level reports."""

    return _build_agent_usage_release_content(
        release_document=release_document,
        reports=reports,
        scenario_digests=scenario_digests,
        required_host_adapter_ids=required_host_adapter_ids,
    )


class _ExecutionTraceLike(Protocol):
    tool_name: str
    phase: UsageActionPhase | None


class _ScenarioResultLike(Protocol):
    scenario_id: str
    domain_id: str
    route_id: str
    status: str
    trace: Sequence[_ExecutionTraceLike]

    @property
    def evaluator_derived(self) -> bool: ...

    def model_dump_json(self) -> str: ...


class _RealMcpResultLike(Protocol):
    result: _ScenarioResultLike
    runtime_tool_schema_digest: str

    @property
    def runner_derived(self) -> bool: ...


class _AttestationLike(Protocol):
    pack_digest: str
    ir_digest: str
    tool_schema_digest: str
    test_report_digest: str
    source_snapshot_digest: str
    contract_digest: str
    scenario_digest: str
    execution_mode: str


def _make_live_bundle_finalizer(
    register_execution_axis_report: Callable[[UsageAxisReport], UsageAxisReport],
) -> tuple[_ReleaseBundleFinalizer, _LiveBundleChecker]:
    live: dict[int, tuple[weakref.ReferenceType[VerifiedUsageReleaseBundle], str]] = {}

    def finalize_verified_usage_release(
        *,
        project: UsageProjectReport,
        accepted_mcp_release: McpReleaseAcceptanceVerification,
        analysis: UsageAnalysisReport,
        domain_id: str,
        contract: DomainUsageContract,
        scenarios: Sequence[UsageScenario],
        decision: UsageDomainDecision,
        reports: Sequence[UsageAxisReport],
        headless_results: Sequence[object],
        real_mcp_results: Sequence[object],
        headless_attestations: Mapping[str, object],
        real_mcp_attestations: Mapping[str, object],
        required_host_adapter_ids: Sequence[str] = (),
    ) -> VerifiedUsageReleaseBundle:
        if (
            not project.ok
            or project.acceptance is None
            or not _is_live_acceptance(accepted_mcp_release, project.acceptance)
            or not analysis.ok
            or not _is_live_analysis(
                analysis,
                project=project,
                release=accepted_mcp_release,
                domain_id=domain_id,
            )
        ):
            raise ValueError("release finalization requires exact live trusted analysis inputs")
        if project.domain_contracts.get(domain_id) is not contract:
            raise ValueError("release finalization requires the exact loaded contract")
        required_scenarios, scenario_digests = _artifact_context(
            contract=contract,
            scenarios=scenarios,
            decision=decision,
        )
        if any(project.scenarios.get(item.scenario_id) is not item for item in scenarios):
            raise ValueError("release finalization requires the exact loaded scenarios")
        if not any(item is decision for item in project.decisions.values()):
            raise ValueError("release finalization requires the exact loaded decision")
        if project.domain_index is None:
            raise ValueError("release finalization requires a loaded release index")
        references = tuple(
            item for item in project.domain_index.published_releases if item.domain_id == domain_id
        )
        if len(references) != 1:
            raise ValueError("release finalization requires exactly one active release")
        template = project.releases.get(references[0].usage_release_id)
        contract_digest = _canonical_digest(contract.model_dump(mode="json"))
        if (
            template is None
            or template.domain_id != domain_id
            or template.contract_digest != contract_digest
            or template.decision_digest != decision.decision_digest
            or template.pack_digest != contract.pack_digest
            or template.ir_digest != contract.ir_digest
            or template.tool_schema_digest != contract.tool_schema_digest
            or template.test_report_digest != contract.test_report_digest
            or template.source_snapshot_digest != contract.source_snapshot_digest
            or tuple(template.scenario_ids) != required_scenarios
        ):
            raise ValueError(
                "release finalization template does not match the exact artifact closure"
            )

        expected_reports: dict[UsageVerificationAxis, str] = {
            "source_usage_traced": ingest_source_usage_evidence(
                project=project,
                contract=contract,
                scenarios=scenarios,
                decision=decision,
            ).report_digest,
            "usage_contract_verified": ingest_usage_contract_analysis(
                analysis=analysis,
                contract=contract,
                scenarios=scenarios,
                decision=decision,
            ).report_digest,
            "user_accepted": ingest_user_acceptance(
                contract=contract,
                scenarios=scenarios,
                decision=decision,
            ).report_digest,
        }
        ordinary = {report.axis: report for report in reports if report.adapter_id is None}
        if len(ordinary) != len([report for report in reports if report.adapter_id is None]):
            raise ValueError("release finalization rejects duplicate axis reports")
        if set(ordinary) != {
            "source_usage_traced",
            "usage_contract_verified",
            "user_accepted",
        }:
            raise ValueError("release finalization requires the exact release report closure")
        if any(
            not ordinary[axis].verified or ordinary[axis].report_digest != digest
            for axis, digest in expected_reports.items()
        ):
            raise ValueError("release finalization report does not match its trusted input")

        def execution_report(
            *,
            axis: Literal["headless_agent_verified", "real_mcp_verified"],
            result_values: Sequence[object],
            attestation_values: Mapping[str, object],
        ) -> UsageAxisReport:
            models_module = sys.modules.get("acc_testkit.usage.models")
            if models_module is None:
                raise ValueError("Testkit execution proof types are not loaded")

            def expected_type(name: str) -> type[object]:
                value = getattr(models_module, name, None)
                if not isinstance(value, type):
                    raise ValueError("Testkit execution proof type is unavailable")
                return value

            if axis == "headless_agent_verified":
                scenario_result_type = expected_type("UsageScenarioResult")
                if any(type(item) is not scenario_result_type for item in result_values):
                    raise ValueError("headless execution proof has an unsupported concrete type")
                scenario_results = tuple(cast(_ScenarioResultLike, item) for item in result_values)
                if any(not item.evaluator_derived for item in scenario_results):
                    raise ValueError("headless execution proof is not live evaluator output")
            else:
                real_mcp_result_type = expected_type("RealMcpUsageScenarioResult")
                if any(type(item) is not real_mcp_result_type for item in result_values):
                    raise ValueError("real MCP execution proof has an unsupported concrete type")
                real_results = tuple(cast(_RealMcpResultLike, item) for item in result_values)
                if any(
                    not item.runner_derived
                    or not item.result.evaluator_derived
                    or item.runtime_tool_schema_digest != contract.tool_schema_digest
                    for item in real_results
                ):
                    raise ValueError("real MCP execution proof is not live runner output")
                scenario_results = tuple(item.result for item in real_results)
            result_by_id = {item.scenario_id: item for item in scenario_results}
            if (
                tuple(sorted(result_by_id)) != required_scenarios
                or tuple(sorted(attestation_values)) != required_scenarios
            ):
                raise ValueError("execution proof must match the exact scenario denominator")
            trace: list[UsageVerificationTraceEntry] = []
            evidence: list[str] = []
            expected_mode = "fake" if axis == "headless_agent_verified" else "real_mcp"
            for sequence, scenario_id in enumerate(required_scenarios, 1):
                scenario = project.scenarios[scenario_id]
                result = result_by_id[scenario_id]
                attestation_value = attestation_values[scenario_id]
                if type(attestation_value) is not expected_type("UsageAttestation"):
                    raise ValueError("execution attestation has an unsupported concrete type")
                attestation = cast(_AttestationLike, attestation_value)
                scenario_digest = scenario_digests[scenario_id]
                if (
                    result.domain_id != domain_id
                    or result.route_id != scenario.route_id
                    or result.status != "passed"
                    or not result.trace
                    or attestation.execution_mode != expected_mode
                    or attestation.contract_digest != contract_digest
                    or attestation.scenario_digest != scenario_digest
                    or any(
                        getattr(attestation, field_name) != getattr(contract, field_name)
                        for field_name in (
                            "pack_digest",
                            "ir_digest",
                            "tool_schema_digest",
                            "test_report_digest",
                            "source_snapshot_digest",
                        )
                    )
                ):
                    raise ValueError("execution proof does not match exact artifacts")
                artifact_digest = (
                    "sha256:" + hashlib.sha256(result.model_dump_json().encode()).hexdigest()
                )
                terminal = result.trace[-1]
                trace.append(
                    UsageVerificationTraceEntry(
                        axis=axis,
                        sequence=sequence,
                        scenario_id=scenario_id,
                        route_id=result.route_id,
                        tool_name=terminal.tool_name,
                        phase=terminal.phase,
                        call_number=1,
                        status="passed",
                        artifact_digest=artifact_digest,
                    )
                )
                evidence.append(artifact_digest)
            builder = (
                _build_headless_agent_trace_report
                if axis == "headless_agent_verified"
                else _build_real_mcp_trace_report
            )
            return register_execution_axis_report(
                builder(
                    domain_id=domain_id,
                    required_scenario_ids=required_scenarios,
                    trace=trace,
                    evidence_references=tuple(sorted(evidence)),
                    contract_digest=contract_digest,
                    scenario_digests=scenario_digests,
                    package_digest=contract.pack_digest,
                    decision_digest=decision.decision_digest,
                )
            )

        execution_reports = (
            execution_report(
                axis="headless_agent_verified",
                result_values=headless_results,
                attestation_values=headless_attestations,
            ),
            execution_report(
                axis="real_mcp_verified",
                result_values=real_mcp_results,
                attestation_values=real_mcp_attestations,
            ),
        )

        required_adapters = _stable_ids(
            required_host_adapter_ids,
            name="required_host_adapter_ids",
            allow_empty=True,
        )
        adapter_ids = tuple(
            sorted(report.adapter_id for report in reports if report.adapter_id is not None)
        )
        if adapter_ids != required_adapters:
            raise ValueError("release finalization requires the exact host adapter report closure")
        release_document = template.model_dump(mode="json", exclude={"verification"})
        release_document["host_adapters"] = list(required_adapters)
        bundle = _build_agent_usage_release_content(
            release_document=release_document,
            reports=(*reports, *execution_reports),
            scenario_digests=scenario_digests,
            required_host_adapter_ids=required_adapters,
        )
        identity = id(bundle)

        def discard(_reference: object) -> None:
            live.pop(identity, None)

        live[identity] = (weakref.ref(bundle, discard), bundle._public_fingerprint())
        return bundle

    def is_live_bundle(bundle: VerifiedUsageReleaseBundle) -> bool:
        record = live.get(id(bundle))
        return (
            record is not None
            and record[0]() is bundle
            and record[1] == bundle._public_fingerprint()
        )

    return finalize_verified_usage_release, is_live_bundle


finalize_verified_usage_release, _is_live_bundle = _make_live_bundle_finalizer(
    _register_execution_axis_report
)
del _make_live_bundle_finalizer
del _register_execution_axis_report


__all__ = [
    "UsageAxisReport",
    "UsageVerificationAxis",
    "UsageVerificationProjection",
    "UsageVerificationStatus",
    "UsageVerificationTraceEntry",
    "VerifiedUsageReleaseBundle",
    "build_agent_usage_release",
    "derive_usage_verification",
    "finalize_verified_usage_release",
    "ingest_source_usage_evidence",
    "ingest_usage_contract_analysis",
    "ingest_user_acceptance",
]
