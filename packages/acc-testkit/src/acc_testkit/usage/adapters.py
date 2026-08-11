"""Trace-derived host adapter conformance for platform-neutral Usage scenarios."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from acc_core.usage.verification import (
    UsageAxisReport,
    UsageVerificationProjection,
    UsageVerificationStatus,
    UsageVerificationTraceEntry,
    derive_usage_verification,
)

type HostAdapterStatus = Literal[
    "passed", "failed", "skipped", "not_provisioned", "stale", "blocked"
]
type HostAdapterPhase = Literal["prepare", "approve", "commit", "status"]


def _digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _stable(values: Sequence[str], *, name: str) -> tuple[str, ...]:
    result = tuple(values)
    if not result or any(not item or item != item.strip() for item in result):
        raise ValueError(f"{name} must contain exact nonempty identifiers")
    if result != tuple(sorted(set(result))):
        raise ValueError(f"{name} must be sorted and unique")
    return result


class _AdapterModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class HostAdapterTraceEntry(_AdapterModel):
    """One payload-free call observation captured from exactly one host adapter."""

    adapter_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    scenario_id: str = Field(min_length=1)
    route_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    phase: HostAdapterPhase | None = None
    call_number: int = Field(ge=1)
    status: HostAdapterStatus
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("adapter_id", "scenario_id", "route_id", "tool_name")
    @classmethod
    def validate_exact_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("adapter trace identifiers must be exact")
        return value


class HostAdapterConformanceReport(_AdapterModel):
    """One adapter's exact scenario denominator, derived only from captured trace."""

    schema_version: Literal["2"] = "2"
    adapter_id: str = Field(min_length=1)
    domain_id: str = Field(min_length=1)
    required_scenario_ids: tuple[str, ...] = Field(min_length=1)
    scenario_statuses: dict[str, HostAdapterStatus]
    trace: tuple[HostAdapterTraceEntry, ...] = Field(min_length=1)
    call_count: int = Field(ge=1)
    evidence_references: tuple[str, ...] = Field(min_length=1)
    report_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    _trace_derived: bool = PrivateAttr(default=False)
    _verification_fingerprint: str | None = PrivateAttr(default=None)

    @field_validator("adapter_id", "domain_id")
    @classmethod
    def validate_exact_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("adapter report identifiers must be exact")
        return value

    @field_validator("required_scenario_ids", "evidence_references")
    @classmethod
    def validate_stable_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _stable(value, name="adapter report identifiers")

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        _validate_trace(
            self.trace,
            adapter_id=self.adapter_id,
            required_scenario_ids=self.required_scenario_ids,
        )
        if self.call_count != len(self.trace):
            raise ValueError("call_count must equal the ordered trace length")
        terminal = {entry.scenario_id: entry.status for entry in self.trace}
        if terminal != self.scenario_statuses:
            raise ValueError("scenario statuses must equal terminal trace statuses")
        if tuple(sorted(self.scenario_statuses)) != self.required_scenario_ids:
            raise ValueError("scenario statuses must match the exact denominator")
        if self.report_digest != self._calculated_digest():
            raise ValueError("report_digest must match canonical report content")
        return self

    @classmethod
    def _from_runner_trace(
        cls,
        *,
        adapter_id: str,
        domain_id: str,
        required_scenario_ids: Sequence[str],
        trace: Sequence[HostAdapterTraceEntry],
        evidence_references: Sequence[str],
    ) -> HostAdapterConformanceReport:
        required = _stable(required_scenario_ids, name="required_scenario_ids")
        evidence = _stable(evidence_references, name="evidence_references")
        captured = tuple(trace)
        _validate_trace(captured, adapter_id=adapter_id, required_scenario_ids=required)
        content: dict[str, object] = {
            "schema_version": "2",
            "adapter_id": adapter_id,
            "domain_id": domain_id,
            "required_scenario_ids": required,
            "scenario_statuses": {entry.scenario_id: entry.status for entry in captured},
            "trace": tuple(entry.model_dump(mode="json") for entry in captured),
            "call_count": len(captured),
            "evidence_references": evidence,
        }
        report = cls.model_validate({**content, "report_digest": _digest(content)})
        object.__setattr__(report, "_trace_derived", True)
        object.__setattr__(report, "_verification_fingerprint", report._public_fingerprint())
        return report

    def _calculated_digest(self) -> str:
        return _digest(self.model_dump(mode="json", exclude={"report_digest"}))

    def _public_fingerprint(self) -> str:
        return _digest(self.model_dump(mode="json"))

    @property
    def trace_ingested(self) -> bool:
        return self._trace_derived and self._verification_fingerprint == self._public_fingerprint()

    @property
    def verified(self) -> bool:
        return self.trace_ingested and all(
            status == "passed" for status in self.scenario_statuses.values()
        )

    def _to_axis_report(
        self,
        *,
        contract_digest: str,
        scenario_digests: dict[str, str],
        package_digest: str,
        decision_digest: str,
    ) -> UsageAxisReport:
        """Re-ingest this live trace as the Core host-adapter axis."""

        if not self.trace_ingested:
            raise ValueError("serialized adapter report requires trace re-ingestion")
        statuses: dict[HostAdapterStatus, UsageVerificationStatus] = {
            "passed": "passed",
            "failed": "failed",
            "stale": "stale",
            "skipped": "blocked",
            "not_provisioned": "blocked",
            "blocked": "blocked",
        }
        core_trace = tuple(
            UsageVerificationTraceEntry(
                axis="host_adapter_verified",
                adapter_id=entry.adapter_id,
                sequence=entry.sequence,
                scenario_id=entry.scenario_id,
                route_id=entry.route_id,
                tool_name=entry.tool_name,
                phase=entry.phase,
                call_number=entry.call_number,
                status=statuses[entry.status],
                artifact_digest=entry.artifact_digest,
            )
            for entry in self.trace
        )
        return UsageAxisReport.from_trace(
            axis="host_adapter_verified",
            domain_id=self.domain_id,
            adapter_id=self.adapter_id,
            required_scenario_ids=self.required_scenario_ids,
            trace=core_trace,
            evidence_references=self.evidence_references,
            contract_digest=contract_digest,
            scenario_digests=scenario_digests,
            package_digest=package_digest,
            decision_digest=decision_digest,
        )


def _validate_trace(
    trace: Sequence[HostAdapterTraceEntry],
    *,
    adapter_id: str,
    required_scenario_ids: Sequence[str],
) -> None:
    if not trace:
        raise ValueError("adapter trace must not be empty")
    if [entry.sequence for entry in trace] != list(range(1, len(trace) + 1)):
        raise ValueError("adapter trace sequence must be contiguous and ordered")
    if any(entry.adapter_id != adapter_id for entry in trace):
        raise ValueError("trace adapter_id must match the report adapter_id")
    if {entry.scenario_id for entry in trace} != set(required_scenario_ids):
        raise ValueError("adapter trace scenarios must match the exact denominator")
    calls: Counter[str] = Counter()
    for entry in trace:
        calls[entry.scenario_id] += 1
        if entry.call_number != calls[entry.scenario_id]:
            raise ValueError("adapter trace call_number must be contiguous per scenario")


def derive_host_adapter_axis(
    *,
    reports: Sequence[HostAdapterConformanceReport],
    domain_id: str,
    required_adapter_ids: Sequence[str],
    required_scenario_ids: Sequence[str],
    contract_digest: str,
    scenario_digests: dict[str, str],
    package_digest: str,
    decision_digest: str,
) -> UsageVerificationProjection:
    """Project each named adapter independently; no adapter can stand in for another."""

    required = _stable(required_adapter_ids, name="required_adapter_ids")
    required_scenarios = _stable(required_scenario_ids, name="required_scenario_ids")
    seen: set[str] = set()
    core_reports = []
    for report in reports:
        if report.adapter_id in seen:
            raise ValueError("duplicate adapter conformance report")
        seen.add(report.adapter_id)
        if report.domain_id != domain_id:
            raise ValueError("adapter report domain does not match")
        if report.required_scenario_ids != required_scenarios:
            raise ValueError("adapter report must match the exact scenario denominator")
        if report.trace_ingested:
            core_reports.append(
                report._to_axis_report(
                    contract_digest=contract_digest,
                    scenario_digests=scenario_digests,
                    package_digest=package_digest,
                    decision_digest=decision_digest,
                )
            )
    return derive_usage_verification(
        reports=tuple(core_reports),
        domain_id=domain_id,
        required_scenario_ids=required_scenarios,
        required_host_adapter_ids=required,
        contract_digest=contract_digest,
        scenario_digests=scenario_digests,
        package_digest=package_digest,
        decision_digest=decision_digest,
    )


__all__ = [
    "HostAdapterConformanceReport",
    "HostAdapterTraceEntry",
    "derive_host_adapter_axis",
]
