"""Strict v2 Operation and Capability document models.

The v2 shape makes read and action documents explicit.  This module validates
their public structure only; cross-document workflow safety proofs remain a
compiler responsibility.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import Field, TypeAdapter, field_validator, model_validator

from acc_core.models import (
    ContextBindingReference,
    Evidence,
    JsonObject,
    NonEmptyString,
    Project,
    ProjectIdentity,
    ProviderConfig,
    RuntimeConfig,
    SourceWorkspace,
    StrictModel,
    WorkflowStep,
)
from acc_core.models.actions import ExecutionMode, HttpOperationV2


def _checked_json_schema(value: JsonObject) -> JsonObject:
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as exc:
        raise ValueError(f"invalid Draft 2020-12 JSON Schema: {exc.message}") from exc
    return value


class _OperationDocumentV2(StrictModel):
    """Fields shared by explicitly classified v2 Operations."""

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
    """An explicitly read-only v2 Operation."""

    kind: Literal["read"]

    @model_validator(mode="after")
    def validate_read_effect(self) -> Self:
        if self.http.safety.effect != "read":
            raise ValueError("a read Operation must declare the read effect")
        return self


class ActionOperationV2(_OperationDocumentV2):
    """An explicitly mutating v2 Operation with a complete safety contract."""

    kind: Literal["action"]

    @model_validator(mode="after")
    def validate_action_effect(self) -> Self:
        if self.http.safety.effect == "read":
            raise ValueError("an Action Operation must declare a mutating effect")
        return self


type OperationV2 = Annotated[
    ReadOperationV2 | ActionOperationV2,
    Field(discriminator="kind"),
]


class ApprovalContractV2(StrictModel):
    """Declare whether a trusted approval grant is required before commit."""

    mode: Literal["required", "not_required"]


class ActionContractV2(StrictModel):
    """Lifecycle controls that every Action Capability must state explicitly."""

    execution_mode: ExecutionMode
    approval: ApprovalContractV2
    expires_in_seconds: Annotated[int, Field(ge=1, le=86_400)]


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


type CapabilityV2 = Annotated[
    ReadCapabilityV2 | ActionCapabilityV2,
    Field(discriminator="kind"),
]


class QualityProfileV2(StrictModel):
    """Select the compile-time quality gate for a v2 project."""

    profile: Literal["standard", "release"]


class ProjectV2(StrictModel):
    """A v2 project that explicitly opts into quality contracts."""

    schema_version: Literal["2"]
    project: ProjectIdentity
    source_workspace: SourceWorkspace
    runtime: RuntimeConfig
    provider: ProviderConfig
    quality: QualityProfileV2


type ProjectDocument = Annotated[
    Project | ProjectV2,
    Field(discriminator="schema_version"),
]
_PROJECT_DOCUMENT_ADAPTER: TypeAdapter[Project | ProjectV2] = TypeAdapter(ProjectDocument)


def load_project_document(value: object) -> Project | ProjectV2:
    """Validate and dispatch one public v1 or v2 Project document."""

    return _PROJECT_DOCUMENT_ADAPTER.validate_python(value)


__all__ = [
    "ActionCapabilityV2",
    "ActionContractV2",
    "ActionOperationV2",
    "ApprovalContractV2",
    "CapabilityV2",
    "OperationV2",
    "ProjectDocument",
    "ProjectV2",
    "QualityProfileV2",
    "ReadCapabilityV2",
    "ReadOperationV2",
    "load_project_document",
]
