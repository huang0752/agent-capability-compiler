"""Strict, platform-neutral model foundations for ACC Action contracts.

This module defines the reusable safety and HTTP value objects for the sole
current ACC format.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import Field, JsonValue, field_validator, model_validator

from acc_core.models import NonEmptyString, StrictModel

type Effect = Literal["read", "create", "update", "delete", "transition", "execute"]
type Risk = Literal["low", "medium", "high", "critical"]
type Reversibility = Literal["reversible", "compensatable", "irreversible", "unknown"]
type ExecutionMode = Literal["single", "source_transaction", "saga"]

HttpMethodV2 = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
_SAFE_METHODS = frozenset({"GET", "HEAD"})
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_PATH_PARAMETER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}")
_FORBIDDEN_INJECTION_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authenticate",
        "set-cookie",
        "www-authenticate",
    }
)


def _validate_json_pointer(value: str) -> str:
    if not value or not value.startswith("/"):
        raise ValueError("value must be an absolute RFC 6901 JSON Pointer")
    for token in value.split("/")[1:]:
        index = 0
        while index < len(token):
            if token[index] != "~":
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                raise ValueError("value must be a valid RFC 6901 JSON Pointer")
            index += 2
    return value


def _validate_header_name(value: str, *, sensitive_response: bool = False) -> str:
    if _HEADER_NAME.fullmatch(value) is None:
        raise ValueError("header name must use valid HTTP token syntax")
    normalized = value.casefold()
    forbidden = _SENSITIVE_RESPONSE_HEADERS if sensitive_response else _FORBIDDEN_INJECTION_HEADERS
    if normalized in forbidden:
        raise ValueError("header is forbidden at the ACC runtime injection boundary")
    return value


def _validate_origin_relative_path(value: str) -> str:
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
        raise ValueError("path must be origin-relative without traversal, query, or fragment")
    return value


class HeaderInjectionTargetV2(StrictModel):
    """A Runtime-owned value injected into one non-sensitive HTTP header."""

    kind: Literal["header"]
    name: NonEmptyString

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validate_header_name(value)


class BodyInjectionTargetV2(StrictModel):
    """A Runtime-owned value injected at one JSON request-body pointer."""

    kind: Literal["body"]
    pointer: NonEmptyString

    @field_validator("pointer")
    @classmethod
    def validate_pointer(cls, value: str) -> str:
        return _validate_json_pointer(value)


type RuntimeInjectionTargetV2 = Annotated[
    HeaderInjectionTargetV2 | BodyInjectionTargetV2,
    Field(discriminator="kind"),
]


class ResponseHeaderTokenSourceV2(StrictModel):
    """Capture an allowlisted response header as an optimistic-lock token."""

    kind: Literal["response_header"]
    name: NonEmptyString

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validate_header_name(value, sensitive_response=True)


class BodyTokenSourceV2(StrictModel):
    """Capture an optimistic-lock token from a preview response body."""

    kind: Literal["body"]
    pointer: NonEmptyString

    @field_validator("pointer")
    @classmethod
    def validate_pointer(cls, value: str) -> str:
        return _validate_json_pointer(value)


type ConcurrencyTokenSourceV2 = Annotated[
    ResponseHeaderTokenSourceV2 | BodyTokenSourceV2,
    Field(discriminator="kind"),
]


class RetryContractV2(StrictModel):
    """Declare whether a mutation is ever eligible for a controlled replay."""

    mode: Literal["never", "idempotent_only"]


def _validate_state_values(value: list[JsonValue]) -> list[JsonValue]:
    encoded = [
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        for item in value
    ]
    if encoded != sorted(set(encoded)):
        raise ValueError("state values must be canonical, sorted, and unique")
    return value


class UnsupportedIdempotencyV2(StrictModel):
    """Declare that the source exposes no usable idempotency strategy."""

    mode: Literal["unsupported", "runtime_deduplicate"]


class SourceKeyIdempotencyV2(StrictModel):
    """Inject a Runtime-owned source idempotency key."""

    mode: Literal["source_key"]
    target: RuntimeInjectionTargetV2


class StateIdempotencyV2(StrictModel):
    """Treat already-terminal source state as an idempotent outcome."""

    mode: Literal["state_idempotent"]
    state_pointer: NonEmptyString
    terminal_values: Annotated[list[JsonValue], Field(min_length=1)]

    @field_validator("state_pointer")
    @classmethod
    def validate_state_pointer(cls, value: str) -> str:
        return _validate_json_pointer(value)

    @field_validator("terminal_values")
    @classmethod
    def validate_terminal_values(cls, value: list[JsonValue]) -> list[JsonValue]:
        return _validate_state_values(value)


type IdempotencyContractV2 = Annotated[
    UnsupportedIdempotencyV2 | SourceKeyIdempotencyV2 | StateIdempotencyV2,
    Field(discriminator="mode"),
]


class OptimisticTokenConcurrencyV2(StrictModel):
    """Capture and inject an optimistic-lock token using the legacy wire mode."""

    mode: Literal["required"]
    token: ConcurrencyTokenSourceV2
    precondition: RuntimeInjectionTargetV2


class UnsupportedConcurrencyV2(StrictModel):
    """Declare that no accepted conflict-control strategy is available."""

    mode: Literal["not_supported"]


class ServerSerializedStatePredicateV2(StrictModel):
    """Rely on an evidenced source-serialized transition from allowed state."""

    mode: Literal["server_serialized_state_predicate"]
    read_operation_id: NonEmptyString
    state_pointer: NonEmptyString
    allowed_values: Annotated[list[JsonValue], Field(min_length=1)]

    @field_validator("state_pointer")
    @classmethod
    def validate_state_pointer(cls, value: str) -> str:
        return _validate_json_pointer(value)

    @field_validator("allowed_values")
    @classmethod
    def validate_allowed_values(cls, value: list[JsonValue]) -> list[JsonValue]:
        return _validate_state_values(value)


type ConcurrencyContractV2 = Annotated[
    OptimisticTokenConcurrencyV2 | ServerSerializedStatePredicateV2 | UnsupportedConcurrencyV2,
    Field(discriminator="mode"),
]


class SynchronousOutcomeResolutionV2(StrictModel):
    """Treat the definitive mutation response as the source outcome."""

    mode: Literal["synchronous_result"]


class StatusQueryRequestBindingV2(StrictModel):
    """Map one sealed Action value into a declared status-query input."""

    target: NonEmptyString
    source: Literal["capability_input", "prepared_preview", "runtime_idempotency_key"]
    source_pointer: NonEmptyString | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.source == "runtime_idempotency_key":
            if self.source_pointer is not None:
                raise ValueError("runtime idempotency key binding cannot use a source pointer")
        elif self.source_pointer is None:
            raise ValueError("sealed value binding requires a source pointer")
        else:
            _validate_json_pointer(self.source_pointer)
        return self


class StatusQueryOutcomeResolutionV2(StrictModel):
    """Resolve a mutation outcome through one declared read Operation."""

    mode: Literal["status_query"]
    operation_id: NonEmptyString
    request_bindings: list[StatusQueryRequestBindingV2] = Field(
        default_factory=list,
        exclude_if=lambda value: not value,
    )
    success_pointer: NonEmptyString | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    success_values: list[JsonValue] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @field_validator("success_pointer")
    @classmethod
    def validate_success_pointer(cls, value: str | None) -> str | None:
        return None if value is None else _validate_json_pointer(value)

    @field_validator("success_values")
    @classmethod
    def validate_success_values(cls, value: list[JsonValue] | None) -> list[JsonValue] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("success values must not be empty")
        return _validate_state_values(value)

    @field_validator("request_bindings")
    @classmethod
    def validate_request_bindings(
        cls,
        value: list[StatusQueryRequestBindingV2],
    ) -> list[StatusQueryRequestBindingV2]:
        targets = [binding.target for binding in value]
        if len(targets) != len(set(targets)):
            raise ValueError("status query binding targets must be unique")
        if targets != sorted(targets):
            raise ValueError("status query bindings must be sorted by target")
        return value


class UnknownOutcomeResolutionV2(StrictModel):
    """Declare that ambiguous mutation outcomes cannot be resolved automatically."""

    mode: Literal["outcome_unknown"]


type OutcomeResolutionContractV2 = Annotated[
    SynchronousOutcomeResolutionV2 | StatusQueryOutcomeResolutionV2 | UnknownOutcomeResolutionV2,
    Field(discriminator="mode"),
]


class OperationSafetyV2(StrictModel):
    """Complete, non-defaulted safety contract for one current Operation."""

    effect: Effect
    risk: Risk
    reversibility: Reversibility
    retry: RetryContractV2
    idempotency: IdempotencyContractV2
    concurrency: ConcurrencyContractV2

    @model_validator(mode="after")
    def validate_replay_contract(self) -> Self:
        if (
            self.effect != "read"
            and self.retry.mode == "idempotent_only"
            and self.idempotency.mode != "source_key"
        ):
            raise ValueError("idempotent_only mutation retry requires source_key idempotency")
        server_serialized = isinstance(self.concurrency, ServerSerializedStatePredicateV2)
        state_idempotent = isinstance(self.idempotency, StateIdempotencyV2)
        if server_serialized != state_idempotent:
            raise ValueError("server-serialized concurrency and state idempotency must be paired")
        if isinstance(self.concurrency, ServerSerializedStatePredicateV2) and isinstance(
            self.idempotency, StateIdempotencyV2
        ):
            if self.concurrency.state_pointer != self.idempotency.state_pointer:
                raise ValueError("state strategies must use the same state pointer")
            allowed = {
                json.dumps(
                    item,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                for item in self.concurrency.allowed_values
            }
            terminal = {
                json.dumps(
                    item,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                for item in self.idempotency.terminal_values
            }
            if allowed & terminal:
                raise ValueError("allowed and terminal state values must be disjoint")
        return self


class JsonRequestV2(StrictModel):
    """Bounded JSON request-body construction from Operation inputs."""

    kind: Literal["json"]
    body_parameters: dict[NonEmptyString, NonEmptyString]
    max_request_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]

    @field_validator("body_parameters")
    @classmethod
    def validate_body_parameters(cls, value: dict[str, str]) -> dict[str, str]:
        for pointer in value:
            _validate_json_pointer(pointer)
        return value


class HttpSuccessV2(StrictModel):
    """Explicit successful statuses and response-body decoding contract."""

    statuses: Annotated[list[Annotated[int, Field(ge=200, le=299)]], Field(min_length=1)]
    body: Literal["json", "empty", "json_or_empty"]

    @field_validator("statuses")
    @classmethod
    def validate_statuses(cls, value: list[int]) -> list[int]:
        if len(value) != len(set(value)):
            raise ValueError("success statuses must be unique")
        if value != sorted(value):
            raise ValueError("success statuses must use sorted order")
        return value


class HttpOperationV2(StrictModel):
    """A bounded current HTTP transport contract with explicit safety semantics."""

    method: HttpMethodV2
    path: NonEmptyString
    path_parameters: dict[NonEmptyString, NonEmptyString]
    query_parameters: dict[NonEmptyString, NonEmptyString]
    request: JsonRequestV2 | None
    success: HttpSuccessV2
    scopes: list[NonEmptyString]
    timeout_seconds: Annotated[int, Field(ge=1, le=300)]
    max_response_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    safety: OperationSafetyV2
    unsafe_read_evidence_classification: NonEmptyString | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_origin_relative_path(value)

    @model_validator(mode="after")
    def validate_transport_semantics(self) -> Self:
        placeholders = set(_PATH_PARAMETER.findall(self.path))
        if placeholders != set(self.path_parameters):
            raise ValueError("path_parameters must exactly match HTTP path placeholders")

        if self.method in _SAFE_METHODS:
            if self.safety.effect != "read":
                raise ValueError("GET and HEAD operations must have the read effect")
            if self.request is not None:
                raise ValueError("GET and HEAD operations cannot declare a request body")
            if self.unsafe_read_evidence_classification is not None:
                raise ValueError(
                    "safe read methods cannot declare unsafe read evidence classification"
                )
        elif self.safety.effect == "read":
            if self.unsafe_read_evidence_classification is None:
                raise ValueError(
                    "an unsafe HTTP method with read effect requires an evidence classification"
                )
        elif self.unsafe_read_evidence_classification is not None:
            raise ValueError("unsafe read evidence classification is only valid for a read effect")
        if self.method == "DELETE" and self.safety.effect != "delete":
            raise ValueError("DELETE operations must declare the delete effect")
        return self


__all__ = [
    "BodyInjectionTargetV2",
    "BodyTokenSourceV2",
    "ConcurrencyContractV2",
    "ConcurrencyTokenSourceV2",
    "Effect",
    "ExecutionMode",
    "HeaderInjectionTargetV2",
    "HttpMethodV2",
    "HttpOperationV2",
    "HttpSuccessV2",
    "IdempotencyContractV2",
    "JsonRequestV2",
    "OperationSafetyV2",
    "OptimisticTokenConcurrencyV2",
    "OutcomeResolutionContractV2",
    "ResponseHeaderTokenSourceV2",
    "RetryContractV2",
    "Reversibility",
    "Risk",
    "RuntimeInjectionTargetV2",
    "ServerSerializedStatePredicateV2",
    "SourceKeyIdempotencyV2",
    "StateIdempotencyV2",
    "StatusQueryOutcomeResolutionV2",
    "StatusQueryRequestBindingV2",
    "SynchronousOutcomeResolutionV2",
    "UnknownOutcomeResolutionV2",
    "UnsupportedConcurrencyV2",
    "UnsupportedIdempotencyV2",
]
