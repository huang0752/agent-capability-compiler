"""Strict, platform-neutral source UI interaction inventory models."""

from __future__ import annotations

from typing import Literal, Protocol, Self

from pydantic import ConfigDict, Field, JsonValue, ValidationInfo, field_validator, model_validator

from acc_core.contracts import JsonPointer
from acc_core.models import Evidence, NonEmptyString, StrictModel

type InteractionTriggerKind = Literal[
    "screen_load",
    "submit",
    "change",
    "select",
    "confirm",
    "refresh",
    "paginate",
    "sort",
    "navigate",
    "system_event",
]


def _validate_unique_sorted(values: list[str], *, field_name: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} entries must be unique")
    if values != sorted(values):
        raise ValueError(f"{field_name} entries must use sorted order")
    return values


class _Identified(Protocol):
    id: str


def _validate_models_by_id[T: _Identified](values: list[T], *, field_name: str) -> list[T]:
    identifiers = [value.id for value in values]
    _validate_unique_sorted(identifiers, field_name=f"{field_name} ids")
    return values


def _validation_field_name(info: ValidationInfo) -> str:
    return info.field_name or "values"


class InteractionModel(StrictModel):
    """Frozen base for interaction documents and every nested value object."""

    model_config = ConfigDict(frozen=True)


class InteractionScope(InteractionModel):
    """Declare whether the selected client-surface denominator is absent or known."""

    mode: Literal["none", "discovered", "complete"]
    evidence_sources: list[NonEmptyString] = Field(default_factory=list)
    rationale: NonEmptyString | None = None

    @field_validator("evidence_sources")
    @classmethod
    def validate_evidence_sources(cls, value: list[str]) -> list[str]:
        return _validate_unique_sorted(value, field_name="evidence_sources")

    @model_validator(mode="after")
    def validate_none_authority(self) -> Self:
        if self.mode == "none" and (not self.evidence_sources or self.rationale is None):
            raise ValueError("mode=none requires evidence sources and an explicit rationale")
        return self


class UISurface(InteractionModel):
    """One semantic user-visible or client-visible business entry point."""

    id: NonEmptyString
    kind: Literal["page", "dialog", "panel", "mobile_screen", "command", "embedded_flow"]
    route_or_entry: NonEmptyString
    business_purpose: NonEmptyString
    evidence_sources: list[NonEmptyString]

    @field_validator("evidence_sources")
    @classmethod
    def validate_evidence_sources(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("a UI surface requires at least one evidence source")
        return _validate_unique_sorted(value, field_name="evidence_sources")


class InteractionTrigger(InteractionModel):
    """A framework-independent event that begins one interaction."""

    kind: InteractionTriggerKind
    source_pointer: JsonPointer | None = None


class InputMapping(InteractionModel):
    """A bounded declarative value mapping recorded by discovery."""

    kind: Literal[
        "identity",
        "date",
        "datetime",
        "enum",
        "identifier",
        "locale",
        "null",
        "number",
        "text",
    ]
    mapping: dict[NonEmptyString, JsonValue] = Field(default_factory=dict)


class InputBinding(InteractionModel):
    """Map one consumer input to an evidenced client-side source."""

    id: NonEmptyString
    source_kind: Literal[
        "user_input",
        "route_parameter",
        "selected_record",
        "prior_response",
        "trusted_context",
        "literal",
        "computed",
        "user_preference",
    ]
    source_id: NonEmptyString | None = None
    source_pointer: JsonPointer | None = None
    target_pointer: JsonPointer
    cardinality: Literal["one", "optional", "many"]
    mapping: InputMapping | None = None
    literal_value: JsonValue | None = None
    evidence: Evidence

    @model_validator(mode="after")
    def validate_literal_source(self) -> Self:
        has_literal = "literal_value" in self.model_fields_set
        if self.source_kind == "literal" and not has_literal:
            raise ValueError("a literal input binding requires literal_value")
        if self.source_kind != "literal" and has_literal:
            raise ValueError("literal_value is only allowed for a literal input binding")
        return self


class InteractionDefault(InteractionModel):
    """An evidenced default including authority, precedence, and submission behavior."""

    id: NonEmptyString
    target_pointer: JsonPointer
    source_kind: Literal[
        "literal",
        "source_response",
        "trusted_context",
        "user_preference",
        "computed",
    ]
    value: JsonValue | None = None
    source_reference: NonEmptyString | None = None
    authority: Literal["contract", "implementation", "test", "observation"]
    precedence: Literal["caller_over_default", "default_over_caller", "source_default"]
    submission: Literal["omit", "send", "send_if_changed"]
    override_policy: Literal["caller_allowed", "runtime_only", "forbidden"]
    evidence: Evidence

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        has_value = "value" in self.model_fields_set
        if self.source_kind == "literal":
            if not has_value:
                raise ValueError("a literal interaction default requires value")
            if self.source_reference is not None:
                raise ValueError("source_reference is not allowed for a literal default")
        else:
            if has_value:
                raise ValueError("value is only allowed for a literal interaction default")
            if self.source_reference is None:
                raise ValueError("a non-literal interaction default requires source_reference")
        return self


class OptionSearch(InteractionModel):
    """Search behavior for an option producer."""

    mode: Literal["none", "client", "server"]
    query_pointer: JsonPointer | None = None

    @model_validator(mode="after")
    def validate_query_pointer(self) -> Self:
        if self.mode == "server" and self.query_pointer is None:
            raise ValueError("server option search requires query_pointer")
        if self.mode != "server" and self.query_pointer is not None:
            raise ValueError("query_pointer is only allowed for server option search")
        return self


class OptionPagination(InteractionModel):
    """Pagination semantics for an option producer."""

    mode: Literal["none", "offset", "cursor", "page"]
    request_pointer: JsonPointer | None = None
    response_pointer: JsonPointer | None = None

    @model_validator(mode="after")
    def validate_pointers(self) -> Self:
        has_pointers = self.request_pointer is not None or self.response_pointer is not None
        if self.mode == "none" and has_pointers:
            raise ValueError("pagination pointers are not allowed when pagination mode is none")
        if self.mode != "none" and (self.request_pointer is None or self.response_pointer is None):
            raise ValueError("paginated option sources require request and response pointers")
        return self


class OptionCache(InteractionModel):
    """Cache policy without assuming a client framework or storage implementation."""

    mode: Literal["none", "interaction", "session"]
    max_age_seconds: int | None = Field(default=None, ge=1, le=86_400)

    @model_validator(mode="after")
    def validate_max_age(self) -> Self:
        if self.mode == "none" and self.max_age_seconds is not None:
            raise ValueError("max_age_seconds is not allowed when cache mode is none")
        return self


class StaticOption(InteractionModel):
    """One static option preserving JSON value identity and a human label."""

    value: JsonValue
    label: NonEmptyString
    disabled: bool = False
    group: NonEmptyString | None = None


class OptionSource(InteractionModel):
    """Describe how a consumer input obtains selectable values."""

    id: NonEmptyString
    target_pointer: JsonPointer
    source_kind: Literal["static", "capability", "operation"]
    producer_id: NonEmptyString | None = None
    static_options: list[StaticOption] = Field(default_factory=list)
    request_bindings: list[InputBinding]
    items_pointer: JsonPointer | None = None
    value_pointer: JsonPointer
    label_pointer: JsonPointer
    disabled_pointer: JsonPointer | None = None
    group_pointer: JsonPointer | None = None
    cascade_dependencies: list[JsonPointer] = Field(default_factory=list)
    search: OptionSearch
    pagination: OptionPagination
    cache: OptionCache
    freshness: Literal["request", "interaction", "session", "source_defined"]
    empty_behavior: Literal["empty_options", "preserve_selection", "clear_selection"]
    error_behavior: Literal["fail_closed", "empty_options", "preserve_previous"]
    evidence: Evidence

    @field_validator("cascade_dependencies")
    @classmethod
    def validate_dependencies(cls, value: list[str]) -> list[str]:
        return _validate_unique_sorted(value, field_name="cascade_dependencies")

    @field_validator("request_bindings")
    @classmethod
    def validate_request_bindings(cls, value: list[InputBinding]) -> list[InputBinding]:
        return _validate_models_by_id(value, field_name="request_bindings")

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.source_kind == "static":
            if self.producer_id is not None or not self.static_options:
                raise ValueError("static option sources require options and forbid producer_id")
        elif self.producer_id is None or self.static_options:
            raise ValueError("dynamic option sources require producer_id and forbid static options")
        return self


class InteractionCondition(InteractionModel):
    """Evidence-bound placeholder for a condition normalized in the next model layer."""

    id: NonEmptyString
    target: Literal["visible", "enabled", "required", "reset"]
    target_pointer: JsonPointer
    source_expression: NonEmptyString
    evidence: Evidence


class RelatedDataBinding(InteractionModel):
    """Bind producer output to a consumer or semantic view target."""

    id: NonEmptyString
    producer_kind: Literal["capability", "operation"]
    producer_id: NonEmptyString
    output_pointer: JsonPointer
    target_pointer: JsonPointer
    cardinality: Literal["one", "optional", "many"]
    identity_pointer: JsonPointer | None = None
    ordering: Literal["source", "explicit", "none"]
    freshness: Literal["request", "interaction", "session", "source_defined"]
    failure_isolation: Literal["fail_fast", "independent"]
    evidence: Evidence


class ResultConsumption(InteractionModel):
    """Describe a business presentation role without rendering instructions."""

    id: NonEmptyString
    role: Literal[
        "table",
        "detail",
        "summary",
        "status",
        "option",
        "navigation",
        "download_link",
    ]
    source_pointer: JsonPointer
    field_pointers: list[JsonPointer]
    ordering: Literal["source", "explicit", "none"]
    formatting_class: NonEmptyString | None = None
    pagination: Literal["none", "client", "server"]
    state_ids: list[NonEmptyString] = Field(default_factory=list)
    evidence: Evidence

    @field_validator("field_pointers", "state_ids")
    @classmethod
    def validate_sorted_values(cls, value: list[str], info: ValidationInfo) -> list[str]:
        return _validate_unique_sorted(value, field_name=_validation_field_name(info))


class InteractionState(InteractionModel):
    """One semantic client state available to headless verification."""

    id: NonEmptyString
    kind: Literal[
        "initial",
        "loading",
        "ready",
        "empty",
        "no_results",
        "forbidden",
        "source_error",
        "stale",
    ]
    entry_condition_id: NonEmptyString | None = None
    allowed_next_events: list[InteractionTriggerKind]
    evidence: Evidence

    @field_validator("allowed_next_events")
    @classmethod
    def validate_events(cls, value: list[str]) -> list[str]:
        return _validate_unique_sorted(value, field_name="allowed_next_events")


class InteractionEvidenceClaim(InteractionModel):
    """Bind one inventory claim to immutable source evidence."""

    target_pointer: JsonPointer
    evidence: Evidence
    evidence_pointer: JsonPointer | None = None
    authority: Literal["contract", "implementation", "test", "observation"]


class UIInteraction(InteractionModel):
    """One business-relevant source-client transition or data consumption path."""

    id: NonEmptyString
    surface_id: NonEmptyString
    business_intent: NonEmptyString
    trigger: InteractionTrigger
    route_ids: list[NonEmptyString]
    call_order: Literal["sequential", "parallel", "independent"]
    input_bindings: list[InputBinding]
    defaults: list[InteractionDefault]
    option_sources: list[OptionSource]
    conditions: list[InteractionCondition]
    related_data: list[RelatedDataBinding]
    result_consumption: list[ResultConsumption]
    states: list[InteractionState]
    evidence_claims: list[InteractionEvidenceClaim]
    unknowns: list[NonEmptyString]

    @field_validator("route_ids", "unknowns")
    @classmethod
    def validate_sorted_strings(cls, value: list[str], info: ValidationInfo) -> list[str]:
        return _validate_unique_sorted(value, field_name=_validation_field_name(info))

    @field_validator(
        "input_bindings",
        "defaults",
        "option_sources",
        "conditions",
        "related_data",
        "result_consumption",
        "states",
    )
    @classmethod
    def validate_sorted_models(
        cls, value: list[_Identified], info: ValidationInfo
    ) -> list[_Identified]:
        return _validate_models_by_id(value, field_name=_validation_field_name(info))

    @field_validator("evidence_claims")
    @classmethod
    def validate_evidence_claims(
        cls, value: list[InteractionEvidenceClaim]
    ) -> list[InteractionEvidenceClaim]:
        pointers = [claim.target_pointer for claim in value]
        _validate_unique_sorted(pointers, field_name="evidence_claim target pointers")
        return value

    @model_validator(mode="after")
    def validate_internal_references(self) -> Self:
        condition_ids = {condition.id for condition in self.conditions}
        state_ids = {state.id for state in self.states}
        for state in self.states:
            if (
                state.entry_condition_id is not None
                and state.entry_condition_id not in condition_ids
            ):
                raise ValueError("state entry_condition_id must reference an existing condition")
        for consumption in self.result_consumption:
            if not set(consumption.state_ids) <= state_ids:
                raise ValueError("result consumption must reference existing interaction states")
        return self


class InteractionSummary(InteractionModel):
    """Deterministic counters derived from the interaction inventory."""

    surfaces: int = Field(ge=0)
    interactions: int = Field(ge=0)
    unresolved: int = Field(ge=0)


class UIInteractionInventory(InteractionModel):
    """Evidence-backed denominator of source client surfaces and interactions."""

    schema_version: Literal["2"]
    scope: InteractionScope
    surfaces: list[UISurface]
    interactions: list[UIInteraction]
    summary: InteractionSummary

    @field_validator("surfaces", "interactions")
    @classmethod
    def validate_denominator_order(
        cls, value: list[_Identified], info: ValidationInfo
    ) -> list[_Identified]:
        return _validate_models_by_id(value, field_name=_validation_field_name(info))

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        if self.scope.mode == "none" and (self.surfaces or self.interactions):
            raise ValueError("mode=none requires empty surfaces and interactions")
        if self.scope.mode == "complete" and (not self.surfaces or not self.interactions):
            raise ValueError("mode=complete requires a surface and interaction denominator")

        surface_ids = {surface.id for surface in self.surfaces}
        if any(interaction.surface_id not in surface_ids for interaction in self.interactions):
            raise ValueError("every interaction must reference an existing surface")

        expected = {
            "surfaces": len(self.surfaces),
            "interactions": len(self.interactions),
            "unresolved": sum(len(interaction.unknowns) for interaction in self.interactions),
        }
        if self.summary.model_dump() != expected:
            raise ValueError("summary must exactly match the interaction inventory")
        return self


__all__ = [
    "InputBinding",
    "InputMapping",
    "InteractionCondition",
    "InteractionDefault",
    "InteractionEvidenceClaim",
    "InteractionScope",
    "InteractionState",
    "InteractionSummary",
    "InteractionTrigger",
    "InteractionTriggerKind",
    "OptionCache",
    "OptionPagination",
    "OptionSearch",
    "OptionSource",
    "RelatedDataBinding",
    "ResultConsumption",
    "StaticOption",
    "UIInteraction",
    "UIInteractionInventory",
    "UISurface",
]
