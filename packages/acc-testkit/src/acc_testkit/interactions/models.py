"""Platform-neutral models for headless client interaction conformance."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class InteractionTraceEntry(_StrictModel):
    """One immutable, secret-free state transition from the reference evaluator."""

    event: Literal[
        "initialized",
        "value_changed",
        "options_requested",
        "options_stale",
        "options_resolved",
    ]
    state: dict[str, JsonValue]
    field: str | None = None
    generation: int | None = None


class ClientAdapterConformanceStep(_StrictModel):
    """One independently reportable adapter conformance probe."""

    id: str
    required: bool
    status: Literal["passed", "failed", "skipped"]
    code: str | None = None


class ClientAdapterConformanceReport(_StrictModel):
    """Truthful adapter report where required skips cannot count as verification."""

    schema_version: Literal["2"] = "2"
    adapter_id: str = Field(min_length=1)
    interaction_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_scenarios: tuple[str, ...] = Field(min_length=1)
    passed_scenarios: tuple[str, ...]
    failed_scenarios: tuple[str, ...]
    skipped_scenarios: tuple[str, ...]
    evidence_sources: tuple[str, ...] = Field(min_length=1)

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
        if passed & failed or passed & skipped or failed & skipped:
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
            evidence_sources=tuple(sorted(evidence_sources)),
        )

    @property
    def planned(self) -> int:
        return len(self.passed_scenarios) + len(self.failed_scenarios) + len(self.skipped_scenarios)

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
        return required <= set(self.passed_scenarios) and not required & (
            set(self.failed_scenarios) | set(self.skipped_scenarios)
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
    "ClientAdapterConformanceReport",
    "ClientAdapterConformanceStep",
    "InteractionTraceEntry",
]
