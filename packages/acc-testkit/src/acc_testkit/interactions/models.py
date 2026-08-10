"""Platform-neutral models for headless client interaction conformance."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    PrivateAttr,
    field_validator,
    model_validator,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class InteractionTraceEntry(_StrictModel):
    """One immutable, secret-free state transition from the reference evaluator."""

    event: Literal[
        "initialized",
        "value_changed",
        "state_changed",
        "options_requested",
        "options_stale",
        "options_resolved",
        "producer_requested",
        "producer_failed",
        "consumer_requested",
        "consumer_resolved",
        "result_consumed",
        "action_protocol_observed",
    ]
    state: dict[str, JsonValue]
    field: str | None = None
    generation: int | None = None
    interaction_state: Literal[
        "initial",
        "loading",
        "ready",
        "empty",
        "source_error",
        "forbidden",
        "stale",
    ] = "initial"
    producer_id: str | None = None
    arguments_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ActionPhaseRecord(_StrictModel):
    """One externally observed Action phase; Testkit never executes it."""

    phase: Literal["prepare", "approve", "commit", "status"]
    correlation_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    audit_id: str = Field(min_length=1)


class ActionProtocolAssessment(_StrictModel):
    """Shape-only result which deliberately cannot claim runtime verification."""

    status: Literal["not_provisioned", "not_verified"]
    shape_valid: bool
    verified: Literal[False] = False
    codes: tuple[str, ...]


class ClientAdapterConformanceStep(_StrictModel):
    """One independently reportable adapter conformance probe."""

    id: str
    required: bool
    status: Literal["passed", "failed", "skipped", "not_provisioned", "not_verified"]
    code: str | None = None


class ClientAdapterConformanceProbe(_StrictModel):
    """One event expected in an actually captured adapter trace."""

    id: str = Field(min_length=1)
    required: bool
    expected_event: str = Field(min_length=1)


class ClientAdapterConformanceReport(_StrictModel):
    """Truthful adapter report where required skips cannot count as verification."""

    schema_version: Literal["2"] = "2"
    adapter_id: str = Field(min_length=1)
    interaction_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_scenarios: tuple[str, ...] = Field(min_length=1)
    passed_scenarios: tuple[str, ...]
    failed_scenarios: tuple[str, ...]
    skipped_scenarios: tuple[str, ...]
    not_provisioned_scenarios: tuple[str, ...] = ()
    not_verified_scenarios: tuple[str, ...] = ()
    evidence_sources: tuple[str, ...] = Field(min_length=1)
    trace_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    _trace_derived: bool = PrivateAttr(default=False)
    _verification_fingerprint: str | None = PrivateAttr(default=None)

    @field_validator("adapter_id")
    @classmethod
    def _validate_adapter_id(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("adapter_id must be a nonempty exact value")
        return value

    @field_validator(
        "required_scenarios",
        "passed_scenarios",
        "failed_scenarios",
        "skipped_scenarios",
        "not_provisioned_scenarios",
        "not_verified_scenarios",
        "evidence_sources",
    )
    @classmethod
    def _validate_stable_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or item != item.strip() for item in value):
            raise ValueError("conformance identifiers must be nonempty exact values")
        if len(value) != len(set(value)) or tuple(sorted(value)) != value:
            raise ValueError("conformance identifiers must be unique and sorted")
        return value

    @model_validator(mode="after")
    def _validate_disjoint_outcomes(self) -> ClientAdapterConformanceReport:
        passed = set(self.passed_scenarios)
        failed = set(self.failed_scenarios)
        skipped = set(self.skipped_scenarios)
        not_provisioned = set(self.not_provisioned_scenarios)
        not_verified = set(self.not_verified_scenarios)
        outcomes = (passed, failed, skipped, not_provisioned, not_verified)
        overlaps = any(
            left & right
            for index, left in enumerate(outcomes)
            for right in outcomes[index + 1 :]
        )
        if overlaps:
            raise ValueError("conformance scenario outcomes must be disjoint")
        return self

    @classmethod
    def from_steps(
        cls,
        steps: list[ClientAdapterConformanceStep],
        *,
        adapter_id: str,
        interaction_digest: str,
        required_scenarios: tuple[str, ...],
        evidence_sources: tuple[str, ...],
    ) -> ClientAdapterConformanceReport:
        identifiers = [step.id for step in steps]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("conformance step ids must be unique")
        declared_required = tuple(sorted(required_scenarios))
        observed_required = tuple(sorted(step.id for step in steps if step.required))
        if declared_required != observed_required:
            raise ValueError("required scenarios must match required steps")
        return cls(
            adapter_id=adapter_id,
            interaction_digest=interaction_digest,
            required_scenarios=declared_required,
            passed_scenarios=tuple(sorted(step.id for step in steps if step.status == "passed")),
            failed_scenarios=tuple(sorted(step.id for step in steps if step.status == "failed")),
            skipped_scenarios=tuple(sorted(step.id for step in steps if step.status == "skipped")),
            not_provisioned_scenarios=tuple(
                sorted(step.id for step in steps if step.status == "not_provisioned")
            ),
            not_verified_scenarios=tuple(
                sorted(step.id for step in steps if step.status == "not_verified")
            ),
            evidence_sources=tuple(sorted(evidence_sources)),
        )

    @classmethod
    def from_trace(
        cls,
        trace: tuple[InteractionTraceEntry, ...],
        *,
        probes: tuple[ClientAdapterConformanceProbe, ...],
        adapter_id: str,
        interaction_digest: str,
        evidence_sources: tuple[str, ...],
    ) -> ClientAdapterConformanceReport:
        """Derive outcomes from immutable observed events instead of caller-reported status."""

        if not trace:
            raise ValueError("adapter trace must be nonempty")
        events = {entry.event for entry in trace}
        steps = [
            ClientAdapterConformanceStep(
                id=probe.id,
                required=probe.required,
                status="passed" if probe.expected_event in events else "not_provisioned",
            )
            for probe in probes
        ]
        payload = [entry.model_dump(mode="json") for entry in trace]
        trace_sha256 = hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        report = cls.from_steps(
            steps,
            adapter_id=adapter_id,
            interaction_digest=interaction_digest,
            required_scenarios=tuple(sorted(probe.id for probe in probes if probe.required)),
            evidence_sources=evidence_sources,
        )
        traced = report.model_copy(update={"trace_sha256": trace_sha256})
        object.__setattr__(traced, "_trace_derived", True)
        object.__setattr__(traced, "_verification_fingerprint", traced._public_fingerprint())
        return traced

    def _public_fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @property
    def planned(self) -> int:
        return sum(
            len(values)
            for values in (
                self.passed_scenarios,
                self.failed_scenarios,
                self.skipped_scenarios,
                self.not_provisioned_scenarios,
                self.not_verified_scenarios,
            )
        )

    @property
    def executed(self) -> int:
        return len(self.passed_scenarios) + len(self.failed_scenarios)

    @property
    def passed(self) -> int:
        return len(self.passed_scenarios)

    @property
    def failed(self) -> int:
        return len(self.failed_scenarios)

    @property
    def skipped(self) -> int:
        return len(self.skipped_scenarios)

    @property
    def verified(self) -> bool:
        required = set(self.required_scenarios)
        unsuccessful = (
            set(self.failed_scenarios)
            | set(self.skipped_scenarios)
            | set(self.not_provisioned_scenarios)
            | set(self.not_verified_scenarios)
        )
        return (
            self._trace_derived
            and self._verification_fingerprint == self._public_fingerprint()
            and self.trace_sha256 is not None
            and required <= set(self.passed_scenarios)
            and not required & unsuccessful
        )

    def is_verified_for(
        self,
        *,
        interaction_digest: str,
        required_scenarios: tuple[str, ...],
    ) -> bool:
        """Bind verification to one exact manifest digest and required scenario set."""

        return (
            self.interaction_digest == interaction_digest
            and self.required_scenarios == tuple(sorted(required_scenarios))
            and self.verified
        )


__all__ = [
    "ActionPhaseRecord",
    "ActionProtocolAssessment",
    "ClientAdapterConformanceProbe",
    "ClientAdapterConformanceReport",
    "ClientAdapterConformanceStep",
    "InteractionTraceEntry",
]
