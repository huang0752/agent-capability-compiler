"""Strict public data contracts for ACC milestone one."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    PositiveInt,
    field_validator,
    model_validator,
)

NonEmptyString = Annotated[str, Field(min_length=1)]
JsonObject = dict[str, JsonValue]
SchemaVersion = Literal["1"]
Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
EnvironmentReference = Annotated[
    str,
    Field(min_length=1, pattern=r"^[A-Z][A-Z0-9_]*$"),
]
_TENANT_CONTEXT_BINDING_PATTERN = (
    r"^tenant_context\.[A-Za-z][A-Za-z0-9_-]*"
    r"(?:\.[A-Za-z][A-Za-z0-9_-]*)*$"
)
_DIRECT_SENSITIVE_CONTEXT_NAMES = frozenset(
    {
        "authorization",
        "bearer",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "csrf",
        "header",
        "headers",
        "jwt",
        "password",
        "secret",
        "token",
    }
)
_COMPOSITE_SENSITIVE_CONTEXT_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "auth_token",
        "client_secret",
        "private_key",
        "refresh_token",
        "session_token",
        "set_cookie",
    }
)


def _normalize_context_segment(segment: str) -> str:
    words: list[str] = []
    for chunk in re.split(r"[_-]+", segment):
        words.extend(
            match.group(0).lower()
            for match in re.finditer(
                r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+",
                chunk,
            )
        )
    return "_".join(words)


def _validate_tenant_context_binding_reference(value: str) -> str:
    for segment in value.removeprefix("tenant_context.").split("."):
        normalized = _normalize_context_segment(segment)
        if normalized in (_DIRECT_SENSITIVE_CONTEXT_NAMES | _COMPOSITE_SENSITIVE_CONTEXT_NAMES):
            raise ValueError("tenant context binding path contains a sensitive segment")
    return value


TenantContextBindingReference = Annotated[
    str,
    Field(pattern=_TENANT_CONTEXT_BINDING_PATTERN),
    AfterValidator(_validate_tenant_context_binding_reference),
]
ContextBindingReference = Annotated[
    str,
    Field(
        pattern=(
            r"^(?:principal_id|tenant_context\.[A-Za-z][A-Za-z0-9_-]*"
            r"(?:\.[A-Za-z][A-Za-z0-9_-]*)*)$"
        )
    ),
    AfterValidator(
        lambda value: (
            value if value == "principal_id" else _validate_tenant_context_binding_reference(value)
        )
    ),
]


def _checked_json_schema(value: JsonObject) -> JsonObject:
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as exc:
        raise ValueError(f"invalid Draft 2020-12 JSON Schema: {exc.message}") from exc
    return value


class StrictModel(BaseModel):
    """Base class for every public ACC contract.

    ACC definitions are compiler inputs, so silently accepting a misspelled or
    future field would be unsafe. Strict scalar validation also keeps YAML and
    JSON inputs deterministic.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        populate_by_name=True,
    )


class ProjectIdentity(StrictModel):
    """Stable identity of an ACC project."""

    id: NonEmptyString
    version: NonEmptyString


class SourceWorkspace(StrictModel):
    """Source system location, which milestone one always treats as read-only."""

    path: NonEmptyString
    mode: Literal["read_only"]


class RuntimeConfig(StrictModel):
    """Runtime transports emitted by the first ACC release."""

    transport: Annotated[
        list[Literal["stdio", "streamable_http"]],
        Field(min_length=1, max_length=1),
    ]


def _validate_origin_relative_path(value: str, *, field_name: str) -> str:
    parsed = urlsplit(value)
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in decoded_path
        or ".." in decoded_path.split("/")
    ):
        raise ValueError(
            f"{field_name} must be an origin-relative URL path without "
            "traversal, query, or fragment"
        )
    return value


def _validate_absolute_json_pointer(value: str) -> str:
    if not value.startswith("/"):
        raise ValueError("value must be an absolute RFC 6901 JSON Pointer")
    for token in value.split("/")[1:]:
        index = 0
        while index < len(token):
            if token[index] == "~":
                if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                    raise ValueError("value must be a valid RFC 6901 JSON Pointer")
                index += 2
            else:
                index += 1
    return value


class NoAuthConfig(StrictModel):
    """Explicitly declare that the provider requires no authentication."""

    kind: Literal["none"]


class BearerSecretAuthConfig(StrictModel):
    """Resolve one fixed bearer token from the deployment environment."""

    kind: Literal["bearer_secret"]
    token_ref: EnvironmentReference


class EnvironmentSecretCredentials(StrictModel):
    """Resolve a renewable username/password pair from environment secrets."""

    kind: Literal["environment_secret"]
    identity_ref: EnvironmentReference
    password_ref: EnvironmentReference


class GatewaySessionCredentials(StrictModel):
    """Accept a one-shot username/password pair from a trusted Gateway session."""

    kind: Literal["gateway_session"]


type PasswordBearerCredentials = Annotated[
    EnvironmentSecretCredentials | GatewaySessionCredentials,
    Field(discriminator="kind"),
]


class PasswordBearerAuthConfig(StrictModel):
    """Exchange a bounded credential source for a bearer token."""

    kind: Literal["password_bearer"]
    credentials: PasswordBearerCredentials
    login_path: NonEmptyString
    identity_field: NonEmptyString
    password_field: NonEmptyString
    token_pointer: NonEmptyString
    token_type_pointer: NonEmptyString | None = None
    expires_in_pointer: NonEmptyString | None = None
    principal_pointer: NonEmptyString | None = None
    scopes_pointer: NonEmptyString | None = None
    tenant_pointer: NonEmptyString | None = None
    scope_mapping: dict[
        NonEmptyString,
        Annotated[list[NonEmptyString], Field(min_length=1)],
    ] = Field(default_factory=dict)
    timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 10
    max_response_bytes: Annotated[int, Field(ge=1, le=1_048_576)] = 65_536
    retry_on_unauthorized: bool = False

    @field_validator("login_path")
    @classmethod
    def validate_login_path(cls, value: str) -> str:
        return _validate_origin_relative_path(value, field_name="login_path")

    @field_validator(
        "token_pointer",
        "token_type_pointer",
        "expires_in_pointer",
        "principal_pointer",
        "scopes_pointer",
        "tenant_pointer",
    )
    @classmethod
    def validate_json_pointer(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_absolute_json_pointer(value)

    @model_validator(mode="after")
    def validate_distinct_login_fields(self) -> PasswordBearerAuthConfig:
        if self.identity_field == self.password_field:
            raise ValueError("identity_field and password_field must be distinct")
        return self


type ProviderAuthConfig = Annotated[
    NoAuthConfig | BearerSecretAuthConfig | PasswordBearerAuthConfig,
    Field(discriminator="kind"),
]


class ProviderConfig(StrictModel):
    """Reference to the target REST provider without embedding its URL."""

    kind: Literal["http"]
    base_url_ref: EnvironmentReference
    auth: ProviderAuthConfig | None = None
    context_binding_allowlist: list[TenantContextBindingReference] = Field(
        default_factory=list,
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("context_binding_allowlist")
    @classmethod
    def validate_context_binding_allowlist(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("context_binding_allowlist entries must be unique")
        if value != sorted(value):
            raise ValueError("context_binding_allowlist entries must use sorted order")
        return value


class Project(StrictModel):
    """An isolated ACC integration project."""

    schema_version: SchemaVersion
    project: ProjectIdentity
    source_workspace: SourceWorkspace
    runtime: RuntimeConfig
    provider: ProviderConfig


EvidenceKind = Literal[
    "source_file",
    "json_document",
    "openapi",
    "openapi_operation",
    "content",
    "content_summary",
]


class Evidence(StrictModel):
    """A digest-bound locator supporting the milestone one evidence forms."""

    source_id: NonEmptyString
    kind: EvidenceKind | None = None
    path: NonEmptyString | None = None
    line_start: PositiveInt | None = None
    line_end: PositiveInt | None = None
    json_pointer: str | None = None
    openapi_operation: NonEmptyString | None = None
    locator: NonEmptyString | None = None
    summary: NonEmptyString | None = None
    digest: Sha256Digest

    @model_validator(mode="after")
    def validate_locator(self) -> Evidence:
        """Require a meaningful locator and a complete, ordered line range."""

        if (self.line_start is None) != (self.line_end is None):
            raise ValueError("line_start and line_end must be provided together")
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end must be greater than or equal to line_start")
        json_pointer = self.json_pointer
        if json_pointer is not None and json_pointer != "" and not json_pointer.startswith("/"):
            raise ValueError("json_pointer must be an RFC 6901 pointer")
        if not any(
            (
                self.path,
                self.json_pointer is not None,
                self.openapi_operation,
                self.locator,
                self.summary,
            )
        ):
            raise ValueError("evidence requires a source locator or content summary")
        return self


class HttpOperation(StrictModel):
    """A bounded HTTP request description for an existing REST system."""

    method: Literal["GET", "HEAD"]
    path: NonEmptyString
    path_parameters: dict[NonEmptyString, NonEmptyString] = Field(default_factory=dict)
    query_parameters: dict[NonEmptyString, NonEmptyString] = Field(default_factory=dict)
    credential_ref: EnvironmentReference | None = None
    scopes: list[NonEmptyString] = Field(default_factory=list)
    timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 15
    max_response_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)] = 1_048_576

    @model_validator(mode="after")
    def validate_origin_relative_path(self) -> HttpOperation:
        """Reject absolute URLs, authority-relative paths, and traversal."""

        _validate_origin_relative_path(self.path, field_name="path")
        return self


class OperationSafety(StrictModel):
    """Milestone one permits read effects only."""

    effect: Literal["read"]


class Operation(StrictModel):
    """An evidence-bound atomic REST operation."""

    schema_version: SchemaVersion
    id: NonEmptyString
    title: NonEmptyString
    kind: Literal["http"]
    input_schema: JsonObject
    output_schema: JsonObject
    http: HttpOperation
    context_bindings: dict[NonEmptyString, ContextBindingReference] = Field(default_factory=dict)
    safety: OperationSafety
    evidence: Annotated[list[Evidence], Field(min_length=1)]

    @field_validator("input_schema", "output_schema")
    @classmethod
    def validate_json_schema(cls, value: JsonObject) -> JsonObject:
        return _checked_json_schema(value)

    @model_validator(mode="after")
    def validate_parameter_mappings(self) -> Operation:
        properties = self.input_schema.get("properties", {})
        declared_inputs = set(properties) if isinstance(properties, dict) else set()
        mapped_inputs = set(self.http.path_parameters.values()) | set(
            self.http.query_parameters.values()
        )
        undeclared = sorted(mapped_inputs - declared_inputs)
        if undeclared:
            raise ValueError(
                "HTTP parameter mappings must reference a declared input: " + ", ".join(undeclared)
            )
        placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}", self.http.path))
        if placeholders != set(self.http.path_parameters):
            raise ValueError("path_parameters must exactly match HTTP path placeholders")
        return self


class RedactionRule(StrictModel):
    """A deterministic field redaction rule."""

    path: NonEmptyString
    strategy: Literal["remove", "mask", "hash"]


class Policy(StrictModel):
    """Read authorization and disclosure policy for a capability."""

    schema_version: SchemaVersion
    id: NonEmptyString
    required_scopes: list[NonEmptyString]
    tenant_mode: Literal["none", "required"]
    tenant_field: NonEmptyString | None = None
    readable_fields: list[NonEmptyString]
    denied_fields: list[NonEmptyString]
    redaction_rules: list[RedactionRule]

    @model_validator(mode="after")
    def validate_tenant_field(self) -> Policy:
        if self.tenant_mode == "required" and self.tenant_field is None:
            raise ValueError("tenant_field is required when tenant_mode is required")
        if self.tenant_mode == "none" and self.tenant_field is not None:
            raise ValueError("tenant_field is not allowed when tenant_mode is none")
        return self


class ExpectedCall(StrictModel):
    """An operation invocation expected during an eval scenario."""

    operation: NonEmptyString
    arguments: JsonObject


class ExpectedError(StrictModel):
    """A stable structured error expected from an eval scenario."""

    code: NonEmptyString
    status: Annotated[int, Field(ge=100, le=599)] | None = None
    message_contains: NonEmptyString | None = None


class Eval(StrictModel):
    """A capability scenario backed by fake-system fixtures."""

    schema_version: SchemaVersion
    id: NonEmptyString
    capability: NonEmptyString
    input: JsonObject
    fixtures: JsonObject
    expected_calls: list[ExpectedCall]
    expected_output_schema: JsonObject | None = None
    expected_error: ExpectedError | None = None
    forbidden_fields: list[NonEmptyString]

    @model_validator(mode="after")
    def validate_expected_result(self) -> Eval:
        """A scenario must describe exactly one success or failure result."""

        output_expected = self.expected_output_schema is not None
        error_expected = self.expected_error is not None
        if output_expected == error_expected:
            raise ValueError(
                "exactly one of expected_output_schema and expected_error must be provided"
            )
        return self


class WorkflowStepBase(StrictModel):
    """Common optional identifier for workflow results."""

    id: NonEmptyString | None = None


class CallAction(StrictModel):
    """Invoke a declared operation using declarative arguments."""

    operation: NonEmptyString
    arguments: JsonObject


class CallStep(WorkflowStepBase):
    call: CallAction


class PickAction(StrictModel):
    """Select an allow-list of fields from a value."""

    value: JsonValue
    fields: Annotated[list[NonEmptyString], Field(min_length=1)]


class PickStep(WorkflowStepBase):
    pick: PickAction


class MapAction(StrictModel):
    """Apply a bounded declarative mapping expression to a collection."""

    items: JsonValue
    expression: NonEmptyString
    max_items: Annotated[int, Field(ge=1, le=100)]


class MapStep(WorkflowStepBase):
    map: MapAction


class FilterAction(StrictModel):
    """Apply a bounded declarative predicate to a collection."""

    items: JsonValue
    condition: NonEmptyString
    max_items: Annotated[int, Field(ge=1, le=100)]


class FilterStep(WorkflowStepBase):
    filter: FilterAction


class AssertAction(StrictModel):
    """Assert a declarative condition without executing code."""

    condition: NonEmptyString
    message: NonEmptyString


class AssertStep(WorkflowStepBase):
    assert_: AssertAction = Field(alias="assert")


class RedactAction(StrictModel):
    """Remove fields from a workflow value."""

    value: JsonValue
    fields: Annotated[list[NonEmptyString], Field(min_length=1)]


class RedactStep(WorkflowStepBase):
    redact: RedactAction


class EmitAction(StrictModel):
    """Emit a deterministic JSON-compatible value."""

    value: JsonValue


class EmitStep(WorkflowStepBase):
    emit: EmitAction


class BranchAction(StrictModel):
    """Choose between two statically declared workflow branches."""

    condition: NonEmptyString
    then_steps: Annotated[list[WorkflowStep], Field(min_length=1)] = Field(alias="then")
    else_steps: Annotated[list[WorkflowStep], Field(min_length=1)] = Field(alias="else")


class BranchStep(WorkflowStepBase):
    branch: BranchAction


class ParallelStep(WorkflowStepBase):
    """Run one to eight statically declared workflow steps concurrently."""

    parallel: Annotated[list[WorkflowStep], Field(min_length=1, max_length=8)]


class ForeachAction(StrictModel):
    """Run a workflow for at most one hundred input items."""

    items: JsonValue
    item_name: NonEmptyString
    max_items: Annotated[int, Field(ge=1, le=100)]
    workflow: Annotated[list[WorkflowStep], Field(min_length=1)]


class ForeachStep(WorkflowStepBase):
    foreach: ForeachAction


type WorkflowStep = (
    CallStep
    | PickStep
    | MapStep
    | FilterStep
    | AssertStep
    | RedactStep
    | BranchStep
    | ParallelStep
    | ForeachStep
    | EmitStep
)


class Capability(StrictModel):
    """An Agent-facing business capability composed from operations."""

    schema_version: SchemaVersion
    id: NonEmptyString
    title: NonEmptyString
    description: NonEmptyString
    input_schema: JsonObject
    output_schema: JsonObject
    workflow: Annotated[list[WorkflowStep], Field(min_length=1)]
    policy: NonEmptyString
    evals: Annotated[list[NonEmptyString], Field(min_length=1)]

    @field_validator("input_schema", "output_schema")
    @classmethod
    def validate_json_schema(cls, value: JsonObject) -> JsonObject:
        return _checked_json_schema(value)


_RECURSIVE_MODELS = (
    BranchAction,
    BranchStep,
    ParallelStep,
    ForeachAction,
    ForeachStep,
    Capability,
)
for _model in _RECURSIVE_MODELS:
    _model.model_rebuild(_types_namespace={"WorkflowStep": WorkflowStep})


__all__ = [
    "AssertAction",
    "AssertStep",
    "BearerSecretAuthConfig",
    "BranchAction",
    "BranchStep",
    "CallAction",
    "CallStep",
    "Capability",
    "ContextBindingReference",
    "EmitAction",
    "EmitStep",
    "EnvironmentSecretCredentials",
    "Eval",
    "Evidence",
    "ExpectedCall",
    "ExpectedError",
    "FilterAction",
    "FilterStep",
    "ForeachAction",
    "ForeachStep",
    "GatewaySessionCredentials",
    "HttpOperation",
    "MapAction",
    "MapStep",
    "NoAuthConfig",
    "Operation",
    "OperationSafety",
    "ParallelStep",
    "PasswordBearerAuthConfig",
    "PasswordBearerCredentials",
    "PickAction",
    "PickStep",
    "Policy",
    "Project",
    "ProjectIdentity",
    "ProviderAuthConfig",
    "ProviderConfig",
    "RedactAction",
    "RedactStep",
    "RedactionRule",
    "RuntimeConfig",
    "SourceWorkspace",
    "StrictModel",
    "TenantContextBindingReference",
    "WorkflowStep",
]
