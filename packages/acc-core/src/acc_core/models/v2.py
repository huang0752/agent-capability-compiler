"""Strict current-format Operation and Capability document models.

The current shape makes read and action documents explicit. This module validates
their public structure only; cross-document workflow safety proofs remain a
compiler responsibility.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal, Self

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import Field, JsonValue, TypeAdapter, field_validator, model_validator

from acc_core.models import (
    ContextBindingReference,
    Evidence,
    JsonObject,
    NonEmptyString,
    ProjectIdentity,
    ProviderConfig,
    RuntimeConfig,
    SourceWorkspace,
    StrictModel,
    WorkflowStep,
)
from acc_core.models.actions import BodyTokenSourceV2, ExecutionMode, HttpOperationV2


def _checked_json_schema(value: JsonObject) -> JsonObject:
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as exc:
        raise ValueError(f"invalid Draft 2020-12 JSON Schema: {exc.message}") from exc
    return value


class _OperationDocumentV2(StrictModel):
    """Fields shared by explicitly classified current Operations."""

    schema_version: Literal["2"]
    id: NonEmptyString
    title: NonEmptyString
    input_schema: JsonObject
    output_schema: JsonObject
    http: HttpOperationV2
    context_bindings: dict[NonEmptyString, ContextBindingReference]
    evidence: Annotated[list[Evidence], Field(min_length=1)]

    @field_validator("input_schema", "output_schema")
    @classmethod
    def validate_json_schema(cls, value: JsonObject) -> JsonObject:
        return _checked_json_schema(value)

    @model_validator(mode="after")
    def validate_parameter_mappings(self) -> Self:
        properties = self.input_schema.get("properties", {})
        declared_inputs = set(properties) if isinstance(properties, dict) else set()
        mapped_inputs = set(self.http.path_parameters.values()) | set(
            self.http.query_parameters.values()
        )
        if self.http.request is not None:
            mapped_inputs.update(self.http.request.body_parameters.values())
        undeclared = sorted(mapped_inputs - declared_inputs)
        if undeclared:
            raise ValueError(
                "HTTP parameter mappings must reference a declared input: " + ", ".join(undeclared)
            )
        return self


class ReadOperationV2(_OperationDocumentV2):
    """An explicitly read-only current Operation."""

    kind: Literal["read"]

    @model_validator(mode="after")
    def validate_read_effect(self) -> Self:
        if self.http.safety.effect != "read":
            raise ValueError("a read Operation must declare the read effect")
        return self


class ActionOperationV2(_OperationDocumentV2):
    """An explicitly mutating current Operation with a complete safety contract."""

    kind: Literal["action"]

    @model_validator(mode="after")
    def validate_action_effect(self) -> Self:
        if self.http.safety.effect == "read":
            raise ValueError("an Action Operation must declare a mutating effect")
        return self


type Operation = Annotated[
    ReadOperationV2 | ActionOperationV2,
    Field(discriminator="kind"),
]
OperationV2 = Operation


class ApprovalContractV2(StrictModel):
    """Declare whether a trusted approval grant is required before commit."""

    mode: Literal["required", "not_required"]


class LocalDevelopmentStateGuardV2(StrictModel):
    """Runtime-only state guard for an explicitly local development sandbox.

    This declaration does not assert source-system atomicity. It only permits
    cooperating ACC runtime calls to lock, re-read, and deduplicate locally.
    """

    mode: Literal["local_development_runtime_guard"]
    resource_key_pointer: NonEmptyString
    read_operation_id: NonEmptyString
    state_pointer: NonEmptyString
    allowed_values: Annotated[list[JsonValue], Field(min_length=1)]
    terminal_values: Annotated[list[JsonValue], Field(min_length=1)]

    @field_validator("resource_key_pointer", "state_pointer")
    @classmethod
    def validate_pointer(cls, value: str) -> str:
        # Reuse the current strict RFC 6901 validation without creating a
        # second, subtly different pointer language.
        return BodyTokenSourceV2(kind="body", pointer=value).pointer

    @field_validator("allowed_values", "terminal_values")
    @classmethod
    def validate_state_values(cls, value: list[JsonValue]) -> list[JsonValue]:
        encoded = [
            json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            for item in value
        ]
        if encoded != sorted(set(encoded)):
            raise ValueError("state values must be canonical, sorted, and unique")
        return value

    @model_validator(mode="after")
    def validate_disjoint_states(self) -> Self:
        allowed = {
            json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False)
            for item in self.allowed_values
        }
        terminal = {
            json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False)
            for item in self.terminal_values
        }
        if allowed & terminal:
            raise ValueError("allowed and terminal state values must be disjoint")
        return self


class ActionContractV2(StrictModel):
    """Lifecycle controls that every Action Capability must state explicitly."""

    execution_mode: ExecutionMode
    approval: ApprovalContractV2
    expires_in_seconds: Annotated[int, Field(ge=1, le=86_400)]
    local_development_state_guard: LocalDevelopmentStateGuardV2 | None = None


class _CapabilityDocumentV2(StrictModel):
    """Agent-facing fields shared by read and Action Capability documents."""

    schema_version: Literal["2"]
    id: NonEmptyString
    title: NonEmptyString
    description: NonEmptyString
    input_schema: JsonObject
    output_schema: JsonObject
    policy: NonEmptyString
    evals: Annotated[list[NonEmptyString], Field(min_length=1)]

    @field_validator("input_schema", "output_schema")
    @classmethod
    def validate_json_schema(cls, value: JsonObject) -> JsonObject:
        return _checked_json_schema(value)


class ReadCapabilityV2(_CapabilityDocumentV2):
    """One deterministic read workflow."""

    kind: Literal["read"]
    workflow: Annotated[list[WorkflowStep], Field(min_length=1)]


class ActionCapabilityV2(_CapabilityDocumentV2):
    """Separate preview and commit workflows for a business Action.

    The compiler later proves that preview is read-only, commit contains the
    permitted mutation topology, and references such as ``$.prepared`` cannot
    be supplied by an Agent.
    """

    kind: Literal["action"]
    action: ActionContractV2
    preview_workflow: Annotated[list[WorkflowStep], Field(min_length=1)]
    commit_workflow: Annotated[list[WorkflowStep], Field(min_length=1)]


type Capability = Annotated[
    ReadCapabilityV2 | ActionCapabilityV2,
    Field(discriminator="kind"),
]
CapabilityV2 = Capability


class QualityProfileV2(StrictModel):
    """Select the compile-time quality gate for a current project."""

    profile: Literal["standard", "release"]


class Project(StrictModel):
    """The sole current project contract with explicit quality controls."""

    schema_version: Literal["2"]
    project: ProjectIdentity
    source_workspace: SourceWorkspace
    runtime: RuntimeConfig
    provider: ProviderConfig
    quality: QualityProfileV2


ProjectV2 = Project
ProjectDocument = Project
_PROJECT_DOCUMENT_ADAPTER: TypeAdapter[Project] = TypeAdapter(ProjectDocument)


def load_project_document(value: object) -> Project:
    """Validate one current Project document and reject every other format."""

    return _PROJECT_DOCUMENT_ADAPTER.validate_python(value)


__all__ = [
    "ActionCapabilityV2",
    "ActionContractV2",
    "ActionOperationV2",
    "ApprovalContractV2",
    "Capability",
    "CapabilityV2",
    "Operation",
    "OperationV2",
    "Project",
    "ProjectDocument",
    "ProjectV2",
    "QualityProfileV2",
    "ReadCapabilityV2",
    "ReadOperationV2",
    "load_project_document",
]
