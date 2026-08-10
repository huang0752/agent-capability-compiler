"""Strict quality metadata for Agent-facing capabilities."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from acc_core.contracts import JsonPointer
from acc_core.models import NonEmptyString, StrictModel


class CapabilityIntent(StrictModel):
    """Describe the business action and resources of a capability."""

    action: Literal[
        "search",
        "list",
        "get",
        "aggregate",
        "monitor",
        "compare",
        "inspect",
        "create",
        "update",
        "delete",
        "transition",
        "execute",
    ]
    resource_types: Annotated[list[NonEmptyString], Field(min_length=1)]

    @field_validator("resource_types")
    @classmethod
    def validate_resource_types(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("resource_types entries must be unique")
        if value != sorted(value):
            raise ValueError("resource_types entries must use sorted order")
        return value


class CapabilityInputQuality(StrictModel):
    """Describe how one public capability input can be obtained safely."""

    kind: Literal["query", "filter", "resource_selector", "trusted_context", "literal"]
    resource_type: NonEmptyString | None = None
    acquisition: Literal[
        "caller",
        "trusted_context",
        "default",
        "upstream_step",
        "capability_output",
    ]
    producers: list[NonEmptyString] = Field(default_factory=list)

    @field_validator("producers")
    @classmethod
    def validate_producers(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("producers entries must be unique")
        if value != sorted(value):
            raise ValueError("producers entries must use sorted order")
        return value

    @model_validator(mode="after")
    def validate_acquisition(self) -> CapabilityInputQuality:
        if self.kind == "resource_selector" and self.resource_type is None:
            raise ValueError("resource_selector inputs require resource_type")
        if self.acquisition == "capability_output" and not self.producers:
            raise ValueError("capability_output acquisition requires at least one producer")
        if self.acquisition != "capability_output" and self.producers:
            raise ValueError("producers are only allowed for capability_output acquisition")
        if (self.kind == "trusted_context") != (self.acquisition == "trusted_context"):
            raise ValueError("trusted_context kind and acquisition must be used together")
        return self


class CompositionQuality(StrictModel):
    """Record the supported workflow failure behavior and any composition rationale."""

    failure_mode: Literal["fail_fast"]
    justification: NonEmptyString | None = None


class LongTextDisclosure(StrictModel):
    """Record human review of one potentially context-heavy output field."""

    path: JsonPointer
    acknowledged: bool
    reason: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_acknowledgement(self) -> LongTextDisclosure:
        if self.acknowledged and self.reason is None:
            raise ValueError("acknowledged long-text disclosure requires a reason")
        return self


class OutputBudget(StrictModel):
    """Bound one complete capability result independently of provider responses."""

    max_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    long_text_disclosures: list[LongTextDisclosure] = Field(default_factory=list)

    @field_validator("long_text_disclosures")
    @classmethod
    def validate_disclosures(cls, value: list[LongTextDisclosure]) -> list[LongTextDisclosure]:
        paths = [item.path for item in value]
        if len(paths) != len(set(paths)):
            raise ValueError("long_text_disclosures paths must be unique")
        if paths != sorted(paths):
            raise ValueError("long_text_disclosures must use sorted path order")
        return value


class CapabilityQuality(StrictModel):
    """Constructability, composition, and output-budget contract for one Capability."""

    schema_version: Literal["2"]
    capability_id: NonEmptyString
    intent: CapabilityIntent
    inputs: dict[NonEmptyString, CapabilityInputQuality]
    composition: CompositionQuality
    output_budget: OutputBudget

    @model_validator(mode="after")
    def validate_producer_graph(self) -> CapabilityQuality:
        if any(
            self.capability_id in input_quality.producers for input_quality in self.inputs.values()
        ):
            raise ValueError("a capability cannot produce its own required input")
        return self


__all__ = [
    "CapabilityInputQuality",
    "CapabilityIntent",
    "CapabilityQuality",
    "CompositionQuality",
    "LongTextDisclosure",
    "OutputBudget",
]
