"""Strict platform-neutral contracts for the independent Agent Usage pipeline."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    JsonValue,
    PositiveInt,
    ValidationInfo,
    field_validator,
    model_validator,
)

from acc_core.contracts import JsonPointer
from acc_core.interactions import ConditionExpression, InputMapping, validate_condition_complexity
from acc_core.models import ProjectIdentity, Sha256Digest, SourceWorkspace, StrictModel

_CREDENTIAL_FIELD_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "jwt",
        "passwd",
        "password",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "set_cookie",
    }
)


def _reject_secret_shaped_text(value: str) -> None:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return
    if re.search(r"(?i)\b(?:cookie|set-cookie)\s*:", value):
        raise ValueError("value must not contain credential-shaped text")
    if re.search(r"(?i)\b(?:bearer|cookie|set-cookie)\s*[: ]\s*\S{12,}", value):
        raise ValueError("value must not contain credential-shaped text")
    if re.search(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", value):
        raise ValueError("value must not contain a JWT-shaped value")
    for token in re.findall(r"\b[A-Za-z0-9_-]{48,}\b", value):
        character_classes = sum(
            bool(re.search(pattern, token)) for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]")
        )
        if character_classes == 3:
            raise ValueError("value must not contain a high-entropy token-shaped value")


def _clean_string(value: str) -> str:
    if value != value.strip():
        raise ValueError("value must not contain surrounding whitespace")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise ValueError("value must not contain control or surrogate characters")
    _reject_secret_shaped_text(value)
    return value


def _validate_secret_safe_json(value: JsonValue) -> JsonValue:
    pending: list[object] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            _reject_secret_shaped_text(item)
        elif isinstance(item, Mapping):
            for key in item:
                _reject_secret_shaped_text(key)
                normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
                if normalized in _CREDENTIAL_FIELD_NAMES:
                    raise ValueError("value must not contain credential fields")
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return value


def _validate_usage_field_pointer(value: str) -> str:
    if value == "":
        return value
    if not value.startswith("/"):
        raise ValueError("value must be an RFC 6901 JSON Pointer")
    for token in value.split("/")[1:]:
        index = 0
        while index < len(token):
            if token[index] != "~":
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                raise ValueError("value must be an RFC 6901 JSON Pointer")
            index += 2
    return value


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=512),
    AfterValidator(_clean_string),
]
BoundedText = Annotated[
    str,
    Field(min_length=1, max_length=16_384),
    AfterValidator(_clean_string),
]
UsageFieldPointer = Annotated[str, AfterValidator(_validate_usage_field_pointer)]


def _utc_timestamp(value: str) -> str:
    _clean_string(value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be an RFC 3339 UTC time") from None
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return value


UtcTimestamp = Annotated[
    str,
    Field(min_length=20, max_length=40),
    AfterValidator(_utc_timestamp),
]


def _sorted_unique(values: Sequence[str], *, field_name: str) -> list[str]:
    if values != sorted(set(values)):
        raise ValueError(f"{field_name} must be sorted and unique")
    return list(values)


class _Identified(Protocol):
    id: str


class _EvidenceClaimBound(Protocol):
    evidence_claim_ids: list[str]


class _CapabilityStepBound(_EvidenceClaimBound, Protocol):
    capability_id: str
    step_id: str


class UsageModel(StrictModel):
    """Frozen base shared only by Agent Usage documents."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)


class AgentUsageProject(UsageModel):
    """Identity and immutable read-only source boundary of one Usage project."""

    schema_version: Literal["2"]
    kind: Literal["agent_usage"]
    project: ProjectIdentity
    source_workspace: SourceWorkspace


class McpReleaseAcceptance(UsageModel):
    """User acceptance of one exact MCP baseline for Usage analysis."""

    schema_version: Literal["2"]
    release_id: Identifier
    pack_digest: Sha256Digest
    ir_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    accepted_domain_ids: list[Identifier]
    test_report_digest: Sha256Digest
    known_limitations: list[BoundedText]
    accepted_by: Identifier
    accepted_at: UtcTimestamp

    @field_validator("accepted_domain_ids")
    @classmethod
    def validate_accepted_domain_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="accepted_domain_ids")


class UsageEvidenceLayer(UsageModel):
    """Availability of one platform-neutral source evidence layer."""

    source_layer: Literal["client", "service", "test", "mcp", "runtime_observation"]
    status: Literal["provided", "unknown", "not_applicable"]
    digest: Sha256Digest | None
    client_surface: Literal["web", "mobile", "desktop", "cli", "automation", "other"] | None

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if (self.status == "provided") != (self.digest is not None):
            raise ValueError("only provided evidence layers carry a digest")
        if self.client_surface is not None and self.source_layer != "client":
            raise ValueError("client_surface is only valid for client evidence")
        return self


class SourceSnapshot(UsageModel):
    """Digest-bound source materials read while reconstructing Usage semantics."""

    schema_version: Literal["2"]
    source_revision: Identifier
    evidence_layers: Annotated[list[UsageEvidenceLayer], Field(min_length=1)]
    captured_at: UtcTimestamp

    @field_validator("evidence_layers")
    @classmethod
    def validate_layers(cls, value: list[UsageEvidenceLayer]) -> list[UsageEvidenceLayer]:
        layer_ids = [layer.source_layer for layer in value]
        _sorted_unique(layer_ids, field_name="source layers")
        return value


class UsageEvidenceTarget(UsageModel):
    """Typed contract object and field targeted by one evidence claim."""

    target_kind: Literal[
        "business_goal",
        "tool_route",
        "input_binding",
        "default",
        "condition",
        "option_source",
        "related_data",
        "result_consumption",
        "error_branch",
        "action_lifecycle",
    ]
    target_id: Identifier
    field_pointer: UsageFieldPointer


class UsageEvidenceRef(UsageModel):
    """Immutable identity of one independently loaded Evidence artifact."""

    source_id: Identifier
    digest: Sha256Digest


class UsageEvidenceClaim(UsageModel):
    """One bounded statement backed by independently loaded Evidence identities."""

    id: Identifier
    statement: BoundedText
    target: UsageEvidenceTarget
    authority: Literal["contract", "implementation", "test", "observation"]
    source_layer: Literal["client", "service", "test", "mcp", "runtime_observation"]
    evidence_refs: Annotated[list[UsageEvidenceRef], Field(min_length=1)]

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, value: list[UsageEvidenceRef]) -> list[UsageEvidenceRef]:
        source_ids = [reference.source_id for reference in value]
        _sorted_unique(source_ids, field_name="evidence reference source_ids")
        return value


class UsageBusinessGoal(UsageModel):
    """Stable business goal adopted by one domain contract."""

    id: Identifier
    description: BoundedText
    evidence_claim_ids: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("evidence_claim_ids")
    @classmethod
    def validate_evidence_claim_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="evidence_claim_ids")


class _UsageCapabilityStepRef(UsageModel):
    id: Identifier
    capability_id: Identifier
    step_id: Identifier
    evidence_claim_ids: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("evidence_claim_ids")
    @classmethod
    def validate_evidence_claim_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="evidence_claim_ids")


class UsageDefaultRef(_UsageCapabilityStepRef):
    """Evidence-bound default applied to one declared tool input."""

    target_pointer: JsonPointer
    source: Literal["literal", "binding", "source_default"]
    value: JsonValue | None = None
    reference_binding_id: Identifier | None = None
    precedence: PositiveInt
    submission: Literal["always", "when_missing", "omit_when_absent"]

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: JsonValue | None) -> JsonValue | None:
        if value is not None:
            _validate_secret_safe_json(value)
        return value

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        has_value = "value" in self.model_fields_set
        if self.source == "literal" and (not has_value or self.reference_binding_id is not None):
            raise ValueError("literal defaults require a value and no binding reference")
        if self.source == "binding" and (has_value or self.reference_binding_id is None):
            raise ValueError("binding defaults require only a binding reference")
        if self.source == "source_default" and (has_value or self.reference_binding_id is not None):
            raise ValueError("source defaults cannot embed a value or binding reference")
        return self


class UsageOptionItem(UsageModel):
    value: JsonValue
    label: BoundedText

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: JsonValue) -> JsonValue:
        return _validate_secret_safe_json(value)


class UsageOptionSourceRef(UsageModel):
    """Evidence-bound producer or static source for one consumer option input."""

    id: Identifier
    capability_id: Identifier
    consumer_step_id: Identifier
    target_pointer: JsonPointer
    source: Literal["producer_step", "static"]
    producer_step_id: Identifier | None = None
    static_items: list[UsageOptionItem]
    items_pointer: JsonPointer | None = None
    value_pointer: JsonPointer | None = None
    label_pointer: JsonPointer | None = None
    search: Literal["unsupported", "supported", "required"]
    paging: Literal["unsupported", "supported", "required"]
    empty_behavior: Literal["return_empty", "stop"]
    error_behavior: Literal["stop", "retry"]
    evidence_claim_ids: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("evidence_claim_ids")
    @classmethod
    def validate_evidence_claim_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="evidence_claim_ids")

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        pointer_values = (self.items_pointer, self.value_pointer, self.label_pointer)
        if self.source == "producer_step":
            if self.producer_step_id is None or any(value is None for value in pointer_values):
                raise ValueError("producer options require a step and item/value/label pointers")
            if self.static_items:
                raise ValueError("producer options cannot contain static items")
        elif self.producer_step_id is not None or any(
            value is not None for value in pointer_values
        ):
            raise ValueError("static options cannot reference a producer response")
        elif not self.static_items:
            raise ValueError("static options require at least one item")
        return self


class UsageRelatedDataRef(UsageModel):
    """Evidence-bound relationship between one producer and one consumer step."""

    id: Identifier
    producer_step_id: Identifier
    producer_pointer: JsonPointer
    consumer_step_id: Identifier
    target_pointer: JsonPointer
    cardinality: Literal["one", "optional", "many"]
    consistency: Literal["current", "snapshot", "stale_check_required"]
    evidence_claim_ids: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("evidence_claim_ids")
    @classmethod
    def validate_evidence_claim_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="evidence_claim_ids")


class UsageResultConsumption(_UsageCapabilityStepRef):
    """Evidence-bound public consumption of declared result fields."""

    kind: Literal["return", "display", "navigate", "download", "store_reference"]
    field_pointers: Annotated[list[JsonPointer], Field(min_length=1)]
    order: PositiveInt

    @field_validator("field_pointers")
    @classmethod
    def validate_field_pointers(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="field_pointers")


class UsageConditionRef(UsageModel):
    """Evidence-bound inert condition scoped to a route or step."""

    id: Identifier
    kind: Literal["visible", "enabled", "required", "reset", "execute"]
    scope: Literal["route", "step"]
    route_id: Identifier
    step_id: Identifier | None
    target_pointer: JsonPointer
    expression: ConditionExpression
    evidence_claim_ids: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("evidence_claim_ids")
    @classmethod
    def validate_evidence_claim_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="evidence_claim_ids")

    @model_validator(mode="after")
    def validate_expression(self) -> Self:
        if (self.scope == "step") != (self.step_id is not None):
            raise ValueError("step-scoped conditions require exactly one step_id")
        validate_condition_complexity(self.expression)
        return self


class UsageStepBinding(UsageModel):
    """Declaratively map one public or prior-step value into a tool input."""

    id: Identifier
    source_kind: Literal["public_input", "route_input", "prior_step_output", "trusted_context"]
    source_step_id: Identifier | None = None
    consumer_step_id: Identifier
    source_pointer: JsonPointer
    target_pointer: JsonPointer
    mapping: InputMapping | None = None
    value_kind: Literal["public_value", "action_handle", "approval_handle", "status_handle"]

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.mapping is not None:
            _validate_secret_safe_json(self.mapping.mapping)
        if self.source_kind == "prior_step_output" and self.source_step_id is None:
            raise ValueError("prior_step_output requires source_step_id")
        if self.source_kind != "prior_step_output" and self.source_step_id is not None:
            raise ValueError("source_step_id is only valid for prior_step_output")
        return self


class UsageToolStep(UsageModel):
    """One capability-backed tool call in a declarative route."""

    id: Identifier
    capability_id: Identifier
    tool_name: Identifier
    depends_on_step_ids: list[Identifier]
    binding_ids: list[Identifier]
    condition: ConditionExpression | None = None
    retry: Literal["never", "safe", "status_only"]
    action_phase: Literal["prepare", "approve", "commit", "status"] | None = None

    @field_validator("depends_on_step_ids", "binding_ids")
    @classmethod
    def validate_sorted_ids(cls, value: list[str], info: ValidationInfo) -> list[str]:
        field_name = info.field_name or "identifiers"
        return _sorted_unique(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_step(self) -> Self:
        if self.id in self.depends_on_step_ids:
            raise ValueError("a tool step cannot depend on itself")
        if self.condition is not None:
            validate_condition_complexity(self.condition)
        return self


class UsageErrorBranch(UsageModel):
    """Deterministic behavior for one or more normalized failure outcomes."""

    id: Identifier
    outcomes: Annotated[list[Identifier], Field(min_length=1)]
    behavior: Literal["stop", "return_empty", "retry", "query_status"]
    description: BoundedText
    step_ids: Annotated[list[Identifier], Field(min_length=1)]
    retry_policy: Literal["never", "safe_read", "idempotent", "status_only"]
    evidence_claim_ids: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("outcomes", "step_ids", "evidence_claim_ids")
    @classmethod
    def validate_identifier_lists(cls, value: list[str], info: ValidationInfo) -> list[str]:
        return _sorted_unique(value, field_name=info.field_name or "identifiers")

    @model_validator(mode="after")
    def validate_retry(self) -> Self:
        if (self.behavior == "retry") != (self.retry_policy in {"safe_read", "idempotent"}):
            raise ValueError("retry behavior and retry policy must agree")
        if self.behavior == "query_status" and self.retry_policy != "status_only":
            raise ValueError("query_status requires status_only policy")
        if self.behavior not in {"retry", "query_status"} and self.retry_policy != "never":
            raise ValueError("non-retry behavior requires retry_policy=never")
        return self


class UsageActionLifecycle(UsageModel):
    """References for the runtime-owned prepare, approval, commit, and status phases."""

    id: Identifier
    action_id: Identifier
    prepare_step_id: Identifier
    approve_action_handle_binding_id: Identifier | None = None
    commit_action_handle_binding_id: Identifier
    status_action_handle_binding_id: Identifier
    approval: Literal["never", "always", "conditional"]
    approval_condition: ConditionExpression | None = None
    approve_step_id: Identifier | None = None
    approval_handle_binding_id: Identifier | None = None
    commit_step_id: Identifier
    status_step_id: Identifier
    outcome_unknown_behavior: Literal["query_status"]

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        if self.approval == "conditional":
            if (
                self.approval_condition is None
                or self.approve_step_id is None
                or self.approve_action_handle_binding_id is None
                or self.approval_handle_binding_id is None
            ):
                raise ValueError("conditional approval requires a condition, step, and handle")
        elif self.approval == "always":
            if (
                self.approve_step_id is None
                or self.approve_action_handle_binding_id is None
                or self.approval_handle_binding_id is None
                or self.approval_condition is not None
            ):
                raise ValueError("always approval requires an approve step and handle")
        elif (
            self.approve_step_id is not None
            or self.approve_action_handle_binding_id is not None
            or self.approval_handle_binding_id is not None
            or self.approval_condition is not None
        ):
            raise ValueError("approval=never cannot reference approval work")
        if self.approval_condition is not None:
            validate_condition_complexity(self.approval_condition)
        phase_steps = [self.prepare_step_id, self.commit_step_id, self.status_step_id]
        if self.approve_step_id is not None:
            phase_steps.append(self.approve_step_id)
        if len(phase_steps) != len(set(phase_steps)):
            raise ValueError("action lifecycle phases must reference distinct steps")
        return self


class UsageToolRoute(UsageModel):
    """One closed acyclic graph that achieves a bounded business goal."""

    id: Identifier
    business_goal_id: Identifier
    preconditions: list[BoundedText]
    steps: Annotated[list[UsageToolStep], Field(min_length=1)]
    error_branch_ids: list[Identifier]
    result_step_id: Identifier
    result_pointer: JsonPointer
    action_lifecycle_id: Identifier | None = None

    @field_validator("error_branch_ids")
    @classmethod
    def validate_error_branch_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="error_branch_ids")

    @field_validator("steps")
    @classmethod
    def validate_steps_sorted(cls, value: list[UsageToolStep]) -> list[UsageToolStep]:
        step_ids = [step.id for step in value]
        _sorted_unique(step_ids, field_name="step ids")
        return value

    @model_validator(mode="after")
    def validate_route_graph(self) -> Self:
        step_by_id = {step.id: step for step in self.steps}
        if self.result_step_id not in step_by_id:
            raise ValueError("result_step_id must reference a route step")
        for step in self.steps:
            if not set(step.depends_on_step_ids) <= step_by_id.keys():
                raise ValueError("step dependency must reference a route step")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise ValueError("tool route must be acyclic")
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency_id in step_by_id[step_id].depends_on_step_ids:
                visit(dependency_id)
            visiting.remove(step_id)
            visited.add(step_id)

        for route_step_id in step_by_id:
            visit(route_step_id)
        return self


def _pointer_exists(document: object, pointer: str) -> bool:
    if pointer == "":
        return True
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdecimal() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False
    return True


class DomainUsageContract(UsageModel):
    """Platform-neutral Usage facts and routes for exactly one business domain."""

    schema_version: Literal["2"]
    domain_id: Identifier
    pack_digest: Sha256Digest
    ir_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    test_report_digest: Sha256Digest
    source_snapshot_digest: Sha256Digest
    business_goals: Annotated[list[UsageBusinessGoal], Field(min_length=1)]
    tool_routes: Annotated[list[UsageToolRoute], Field(min_length=1)]
    input_bindings: list[UsageStepBinding]
    defaults: list[UsageDefaultRef]
    conditions: list[UsageConditionRef]
    option_sources: list[UsageOptionSourceRef]
    related_data: list[UsageRelatedDataRef]
    result_consumption: Annotated[list[UsageResultConsumption], Field(min_length=1)]
    error_handling: list[UsageErrorBranch]
    action_lifecycles: list[UsageActionLifecycle]
    prohibited_behaviors: Annotated[list[BoundedText], Field(min_length=1)]
    required_scenario_ids: Annotated[list[Identifier], Field(min_length=1)]
    evidence_claims: Annotated[list[UsageEvidenceClaim], Field(min_length=1)]

    @field_validator("required_scenario_ids")
    @classmethod
    def validate_required_scenario_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="required_scenario_ids")

    @field_validator(
        "tool_routes",
        "business_goals",
        "input_bindings",
        "defaults",
        "conditions",
        "option_sources",
        "related_data",
        "result_consumption",
        "error_handling",
        "action_lifecycles",
        "evidence_claims",
    )
    @classmethod
    def validate_models_sorted(
        cls, value: list[_Identified], info: ValidationInfo
    ) -> list[_Identified]:
        identifiers = [item.id for item in value]
        field_name = info.field_name or "model ids"
        _sorted_unique(identifiers, field_name=field_name)
        return value

    @model_validator(mode="after")
    def validate_contract_closure(self) -> Self:
        binding_by_id = {binding.id: binding for binding in self.input_bindings}
        business_goal_ids = {goal.id for goal in self.business_goals}
        error_ids = {branch.id for branch in self.error_handling}
        lifecycle_by_id = {lifecycle.id: lifecycle for lifecycle in self.action_lifecycles}
        claim_ids = {claim.id for claim in self.evidence_claims}
        semantics: tuple[_EvidenceClaimBound, ...] = (
            *self.business_goals,
            *self.defaults,
            *self.conditions,
            *self.option_sources,
            *self.related_data,
            *self.result_consumption,
            *self.error_handling,
        )
        for semantic in semantics:
            if not set(semantic.evidence_claim_ids) <= claim_ids:
                raise ValueError("Usage semantic references an unknown evidence claim")

        targets: dict[str, Mapping[str, UsageModel]] = {
            "business_goal": {item.id: item for item in self.business_goals},
            "tool_route": {item.id: item for item in self.tool_routes},
            "input_binding": binding_by_id,
            "default": {item.id: item for item in self.defaults},
            "condition": {item.id: item for item in self.conditions},
            "option_source": {item.id: item for item in self.option_sources},
            "related_data": {item.id: item for item in self.related_data},
            "result_consumption": {item.id: item for item in self.result_consumption},
            "error_branch": {item.id: item for item in self.error_handling},
            "action_lifecycle": lifecycle_by_id,
        }
        for claim in self.evidence_claims:
            target = targets[claim.target.target_kind].get(claim.target.target_id)
            if target is None:
                raise ValueError("evidence claim target must reference a declared object")
            if not _pointer_exists(target.model_dump(mode="json"), claim.target.field_pointer):
                raise ValueError("evidence claim field_pointer must reference a real target field")

        route_by_step: dict[str, UsageToolRoute] = {}
        step_by_id: dict[str, UsageToolStep] = {}
        for route in self.tool_routes:
            for step in route.steps:
                if step.id in route_by_step:
                    raise ValueError("step ids must be globally unique across domain routes")
                route_by_step[step.id] = route
                step_by_id[step.id] = step

        def is_ancestor(producer_step_id: str, consumer_step_id: str) -> bool:
            if (
                producer_step_id not in route_by_step
                or consumer_step_id not in route_by_step
                or route_by_step[producer_step_id] is not route_by_step[consumer_step_id]
            ):
                return False
            ancestors: set[str] = set()
            pending = list(step_by_id[consumer_step_id].depends_on_step_ids)
            while pending:
                ancestor_id = pending.pop()
                if ancestor_id in ancestors:
                    continue
                ancestors.add(ancestor_id)
                pending.extend(step_by_id[ancestor_id].depends_on_step_ids)
            return producer_step_id in ancestors

        binding_routes: dict[str, set[str]] = {binding_id: set() for binding_id in binding_by_id}
        for route in self.tool_routes:
            if route.business_goal_id not in business_goal_ids:
                raise ValueError("tool route must reference a declared business goal")
            route_binding_ids = {
                binding_id for step in route.steps for binding_id in step.binding_ids
            }
            if not route_binding_ids <= binding_by_id.keys():
                raise ValueError("route binding_ids must reference declared input bindings")
            if not set(route.error_branch_ids) <= error_ids:
                raise ValueError("route error_branch_ids must reference declared error handling")
            route_step_ids = {step.id for step in route.steps}
            for step in route.steps:
                for binding_id in step.binding_ids:
                    binding = binding_by_id[binding_id]
                    binding_routes[binding_id].add(route.id)
                    if binding.consumer_step_id != step.id:
                        raise ValueError("binding must be attached only to its consumer step")
                    if binding.source_step_id is not None and not is_ancestor(
                        binding.source_step_id, binding.consumer_step_id
                    ):
                        raise ValueError("binding producer must be an ancestor of its consumer")

            for branch_id in route.error_branch_ids:
                branch = next(item for item in self.error_handling if item.id == branch_id)
                if not set(branch.step_ids) <= route_step_ids:
                    raise ValueError("error branch steps must belong to their route")
                branch_steps = [step_by_id[step_id] for step_id in branch.step_ids]
                if branch.behavior == "retry" and any(
                    step.action_phase is not None for step in branch_steps
                ):
                    raise ValueError("mutation phases cannot be retried directly")
                if branch.behavior == "query_status" and any(
                    step.action_phase != "status" for step in branch_steps
                ):
                    raise ValueError("outcome_unknown resolution may call only status steps")

            if route.action_lifecycle_id is None:
                if any(step.action_phase is not None for step in route.steps):
                    raise ValueError("action steps require an action lifecycle")
                continue
            lifecycle = lifecycle_by_id.get(route.action_lifecycle_id)
            if lifecycle is None:
                raise ValueError("route action_lifecycle_id must reference a declared lifecycle")
            action_step_by_id = {step.id: step for step in route.steps}
            expected_phases = {
                lifecycle.prepare_step_id: "prepare",
                lifecycle.commit_step_id: "commit",
                lifecycle.status_step_id: "status",
            }
            if lifecycle.approve_step_id is not None:
                expected_phases[lifecycle.approve_step_id] = "approve"
            if not expected_phases.keys() <= action_step_by_id.keys():
                raise ValueError("action lifecycle steps must belong to their tool route")
            if any(
                action_step_by_id[step_id].action_phase != phase
                for step_id, phase in expected_phases.items()
            ):
                raise ValueError("action lifecycle step phases must match their declarations")
            approve_dependencies = (
                set(action_step_by_id[lifecycle.approve_step_id].depends_on_step_ids)
                if lifecycle.approve_step_id is not None
                else set()
            )
            if (
                lifecycle.approve_step_id is not None
                and lifecycle.prepare_step_id not in approve_dependencies
            ):
                raise ValueError("approve must depend on prepare")
            commit_dependencies = set(
                action_step_by_id[lifecycle.commit_step_id].depends_on_step_ids
            )
            required_commit_dependencies = {lifecycle.prepare_step_id}
            if lifecycle.approve_step_id is not None:
                required_commit_dependencies.add(lifecycle.approve_step_id)
            if not required_commit_dependencies <= commit_dependencies:
                raise ValueError("commit must depend on all required prior action phases")
            if lifecycle.prepare_step_id not in set(
                action_step_by_id[lifecycle.status_step_id].depends_on_step_ids
            ):
                raise ValueError("status must depend on prepare, not mutation completion")

            action_handle_requirements = {
                lifecycle.commit_action_handle_binding_id: lifecycle.commit_step_id,
                lifecycle.status_action_handle_binding_id: lifecycle.status_step_id,
            }
            if (
                lifecycle.approve_action_handle_binding_id is not None
                and lifecycle.approve_step_id is not None
            ):
                action_handle_requirements[lifecycle.approve_action_handle_binding_id] = (
                    lifecycle.approve_step_id
                )
            for binding_id, consumer_step_id in action_handle_requirements.items():
                handle_binding = binding_by_id.get(binding_id)
                if (
                    handle_binding is None
                    or handle_binding.source_kind != "prior_step_output"
                    or handle_binding.source_step_id != lifecycle.prepare_step_id
                    or handle_binding.consumer_step_id != consumer_step_id
                    or handle_binding.value_kind != "action_handle"
                ):
                    raise ValueError("action handles must flow from prepare to each consumer phase")
            if lifecycle.approval_handle_binding_id is not None:
                approval_binding = binding_by_id.get(lifecycle.approval_handle_binding_id)
                if (
                    approval_binding is None
                    or approval_binding.source_kind != "trusted_context"
                    or approval_binding.consumer_step_id != lifecycle.approve_step_id
                    or approval_binding.value_kind != "approval_handle"
                ):
                    raise ValueError("approval handle requires a trusted_context approve binding")

        if any(len(routes) != 1 for routes in binding_routes.values()):
            raise ValueError("every binding must be used by exactly one route")

        for default in self.defaults:
            default_step = step_by_id.get(default.step_id)
            if default_step is None or default_step.capability_id != default.capability_id:
                raise ValueError("default must reference a declared capability step")
            if (
                default.reference_binding_id is not None
                and default.reference_binding_id not in binding_by_id
            ):
                raise ValueError("default binding reference must exist")
        for option in self.option_sources:
            consumer = step_by_id.get(option.consumer_step_id)
            if consumer is None or consumer.capability_id != option.capability_id:
                raise ValueError("option source must reference its consumer capability step")
            if option.producer_step_id is not None and not is_ancestor(
                option.producer_step_id, option.consumer_step_id
            ):
                raise ValueError("option producer must be an ancestor of its consumer")
        for related in self.related_data:
            if not is_ancestor(related.producer_step_id, related.consumer_step_id):
                raise ValueError("related data producer must be an ancestor of its consumer")
        for consumption in self.result_consumption:
            consumption_step = step_by_id.get(consumption.step_id)
            if (
                consumption_step is None
                or consumption_step.capability_id != consumption.capability_id
            ):
                raise ValueError("result consumption must reference a declared capability step")
        for condition in self.conditions:
            condition_route = next(
                (item for item in self.tool_routes if item.id == condition.route_id), None
            )
            if condition_route is None or (
                condition.step_id is not None
                and condition.step_id not in {step.id for step in condition_route.steps}
            ):
                raise ValueError("condition scope must reference a declared route or step")
        referenced_lifecycles = {
            route.action_lifecycle_id
            for route in self.tool_routes
            if route.action_lifecycle_id is not None
        }
        if referenced_lifecycles != lifecycle_by_id.keys():
            raise ValueError("every action lifecycle must be referenced by exactly one route")
        return self


class UsageScenario(UsageModel):
    """One deterministic route scenario in the exact domain test denominator."""

    schema_version: Literal["2"]
    scenario_id: Identifier
    domain_id: Identifier
    route_id: Identifier
    title: BoundedText
    kind: Literal[
        "happy_path",
        "empty_result",
        "missing_input",
        "related_not_found",
        "unauthorized",
        "forbidden",
        "not_found",
        "timeout",
        "source_error",
        "stale_input",
        "tool_selection",
        "prohibited_behavior",
        "action_lifecycle",
        "conflict",
        "outcome_unknown",
        "digest_mismatch",
    ]
    public_input_ids: list[Identifier]
    expected_outcomes: Annotated[list[Identifier], Field(min_length=1)]
    prohibited_behaviors: list[BoundedText]

    @field_validator("public_input_ids", "expected_outcomes")
    @classmethod
    def validate_identifier_lists(cls, value: list[str], info: ValidationInfo) -> list[str]:
        field_name = info.field_name or "identifiers"
        return _sorted_unique(value, field_name=field_name)


class UsagePublishedReleaseRef(UsageModel):
    """The exact active Usage release selected for one published domain."""

    domain_id: Identifier
    usage_release_id: Identifier


class UsageDomainEntry(UsageModel):
    """One Usage domain and only its explicit cross-domain dependencies."""

    id: Identifier
    dependency_domain_ids: list[Identifier]

    @field_validator("dependency_domain_ids")
    @classmethod
    def validate_dependency_domain_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, field_name="dependency_domain_ids")


class DomainUsageIndex(UsageModel):
    """Top-level domain denominator and the subset released for Agent routing."""

    schema_version: Literal["2"]
    mcp_release_id: Identifier
    pack_digest: Sha256Digest
    ir_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    test_report_digest: Sha256Digest
    source_snapshot_digest: Sha256Digest
    domains: list[UsageDomainEntry]
    preferred_order: list[Identifier]
    published_releases: list[UsagePublishedReleaseRef]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[UsageDomainEntry]) -> list[UsageDomainEntry]:
        _sorted_unique([domain.id for domain in value], field_name="domain ids")
        return value

    @field_validator("published_releases")
    @classmethod
    def validate_published_releases(
        cls, value: list[UsagePublishedReleaseRef]
    ) -> list[UsagePublishedReleaseRef]:
        domain_ids = [reference.domain_id for reference in value]
        _sorted_unique(domain_ids, field_name="published release domain_ids")
        return value

    @property
    def published_domain_ids(self) -> list[str]:
        """Return active domain IDs without adding a second wire authority."""

        return [reference.domain_id for reference in self.published_releases]

    @property
    def domain_ids(self) -> list[str]:
        """Return domain IDs without adding a second wire authority."""

        return [domain.id for domain in self.domains]

    @model_validator(mode="after")
    def validate_domain_graph(self) -> Self:
        domain_ids = set(self.domain_ids)
        if (
            len(self.preferred_order) != len(self.domain_ids)
            or set(self.preferred_order) != domain_ids
        ):
            raise ValueError("preferred_order must be an exact permutation of domain ids")

        dependency_ids_by_domain = {
            domain.id: domain.dependency_domain_ids for domain in self.domains
        }
        for domain_id, dependency_ids in dependency_ids_by_domain.items():
            if domain_id in dependency_ids:
                raise ValueError("a domain cannot depend on itself")
            if not set(dependency_ids) <= domain_ids:
                raise ValueError("domain dependencies must reference declared domains")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(domain_id: str) -> None:
            if domain_id in visiting:
                raise ValueError("domain dependency graph must be acyclic")
            if domain_id in visited:
                return
            visiting.add(domain_id)
            for dependency_id in dependency_ids_by_domain[domain_id]:
                visit(dependency_id)
            visiting.remove(domain_id)
            visited.add(domain_id)

        for domain_id in self.domain_ids:
            visit(domain_id)

        if not set(self.published_domain_ids) <= set(self.domain_ids):
            raise ValueError("published release domains must be a subset of domain_ids")
        return self


_DECISION_CONTENT_FIELDS = (
    "schema_version",
    "domain_id",
    "revision",
    "disposition",
    "business_goal_ids",
    "included_route_ids",
    "known_limitations",
    "contract_digest",
)


def usage_domain_decision_digest(value: Mapping[str, Any]) -> str:
    """Return the canonical digest of decision content, excluding its confirmation."""

    content = {field: value[field] for field in _DECISION_CONTENT_FIELDS}
    payload = json.dumps(
        content,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class UsageUserConfirmation(UsageModel):
    """Digest-only user confirmation bound to one exact domain decision."""

    confirmed_by: Identifier
    confirmed_at: UtcTimestamp
    source_text_digest: Sha256Digest
    confirmed_decision_digest: Sha256Digest


class UsageDomainDecision(UsageModel):
    """One versioned user decision for a complete business-domain review."""

    schema_version: Literal["2"]
    domain_id: Identifier
    revision: PositiveInt
    disposition: Literal["accepted", "deferred", "excluded"]
    business_goal_ids: list[Identifier]
    included_route_ids: list[Identifier]
    known_limitations: list[BoundedText]
    contract_digest: Sha256Digest | None
    decision_digest: Sha256Digest
    user_confirmation: UsageUserConfirmation

    @field_validator("business_goal_ids", "included_route_ids")
    @classmethod
    def validate_decision_ids(cls, value: list[str], info: ValidationInfo) -> list[str]:
        field_name = info.field_name or "decision ids"
        return _sorted_unique(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.disposition == "accepted":
            if (
                not self.business_goal_ids
                or not self.included_route_ids
                or self.contract_digest is None
            ):
                raise ValueError("accepted decisions require goals, routes, and a contract digest")
        elif self.included_route_ids or self.contract_digest is not None:
            raise ValueError("deferred or excluded decisions cannot publish routes or a contract")
        content = self.model_dump(
            mode="json",
            exclude={"decision_digest", "user_confirmation"},
        )
        expected_digest = usage_domain_decision_digest(content)
        if self.decision_digest != expected_digest:
            raise ValueError("decision_digest must match the canonical decision content")
        if self.user_confirmation.confirmed_decision_digest != self.decision_digest:
            raise ValueError("user confirmation must bind the exact decision digest")
        return self


class UsageVerification(UsageModel):
    """Six independent facts; no field is derived from another field."""

    source_usage_traced: bool
    usage_contract_verified: bool
    headless_agent_verified: bool
    host_adapter_verified: bool
    real_mcp_verified: bool
    user_accepted: bool


class AgentUsageRelease(UsageModel):
    """Published or limited Usage release for exactly one business domain."""

    schema_version: Literal["2"]
    usage_release_id: Identifier
    domain_id: Identifier
    mcp_release_id: Identifier
    pack_digest: Sha256Digest
    ir_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    test_report_digest: Sha256Digest
    source_snapshot_digest: Sha256Digest
    contract_digest: Sha256Digest
    decision_digest: Sha256Digest
    business_goal_ids: Annotated[list[Identifier], Field(min_length=1)]
    route_ids: Annotated[list[Identifier], Field(min_length=1)]
    scenario_ids: Annotated[list[Identifier], Field(min_length=1)]
    capability_ids: Annotated[list[Identifier], Field(min_length=1)]
    verification: UsageVerification
    release_status: Literal["limited", "released"]
    known_limitations: list[BoundedText]
    host_adapters: list[Identifier]
    released_at: UtcTimestamp

    @field_validator(
        "business_goal_ids",
        "route_ids",
        "scenario_ids",
        "capability_ids",
        "host_adapters",
    )
    @classmethod
    def validate_release_ids(cls, value: list[str], info: ValidationInfo) -> list[str]:
        field_name = info.field_name or "release ids"
        return _sorted_unique(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_release_gate(self) -> Self:
        required = (
            self.verification.source_usage_traced,
            self.verification.usage_contract_verified,
            self.verification.headless_agent_verified,
            self.verification.user_accepted,
        )
        if not all(required):
            raise ValueError(
                "every Usage release requires traced, contract, headless, and user gates"
            )
        if self.verification.host_adapter_verified and not self.host_adapters:
            raise ValueError("host adapter verification requires a named host adapter")
        if self.release_status == "released":
            core_axes = (
                self.verification.source_usage_traced,
                self.verification.usage_contract_verified,
                self.verification.headless_agent_verified,
                self.verification.real_mcp_verified,
                self.verification.user_accepted,
            )
            if not all(core_axes):
                raise ValueError("released status requires every core verification axis")
        elif not self.known_limitations:
            raise ValueError("limited status requires an explicit known limitation")
        return self


__all__ = [
    "AgentUsageProject",
    "AgentUsageRelease",
    "BoundedText",
    "DomainUsageContract",
    "DomainUsageIndex",
    "Identifier",
    "McpReleaseAcceptance",
    "SourceSnapshot",
    "UsageActionLifecycle",
    "UsageBusinessGoal",
    "UsageConditionRef",
    "UsageDefaultRef",
    "UsageDomainDecision",
    "UsageDomainEntry",
    "UsageErrorBranch",
    "UsageEvidenceClaim",
    "UsageEvidenceLayer",
    "UsageEvidenceRef",
    "UsageEvidenceTarget",
    "UsageModel",
    "UsageOptionItem",
    "UsageOptionSourceRef",
    "UsagePublishedReleaseRef",
    "UsageRelatedDataRef",
    "UsageResultConsumption",
    "UsageScenario",
    "UsageStepBinding",
    "UsageToolRoute",
    "UsageToolStep",
    "UsageUserConfirmation",
    "UsageVerification",
    "UtcTimestamp",
    "usage_domain_decision_digest",
]
