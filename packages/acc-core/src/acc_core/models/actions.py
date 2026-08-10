"""Strict, platform-neutral model foundations for ACC Action contracts.

This module is deliberately independent from public package exports and version
dispatch.  It defines only the reusable v2 safety and HTTP value objects; v1
models remain unchanged and read-only.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import Field, field_validator, model_validator

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


class IdempotencyContractV2(StrictModel):
    """Separate source idempotency from Runtime-local duplicate suppression."""

    mode: Literal["unsupported", "runtime_deduplicate", "source_key"]
    target: RuntimeInjectionTargetV2 | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.mode == "source_key" and self.target is None:
            raise ValueError("target is required when idempotency mode is source_key")
        if self.mode != "source_key" and self.target is not None:
            raise ValueError("target is not allowed without source_key idempotency")
        return self


class ConcurrencyContractV2(StrictModel):
    """Describe capture and Runtime-owned injection of a concurrency token."""

    mode: Literal["required", "not_supported"]
    token: ConcurrencyTokenSourceV2 | None = None
    precondition: RuntimeInjectionTargetV2 | None = None

    @model_validator(mode="after")
    def validate_required_parts(self) -> Self:
        if self.mode == "required" and (self.token is None or self.precondition is None):
            raise ValueError(
                "token and precondition are required when concurrency mode is required"
            )
        if self.mode == "not_supported" and (
            self.token is not None or self.precondition is not None
        ):
            raise ValueError(
                "token and precondition are not allowed when concurrency is not supported"
            )
        return self


class OperationSafetyV2(StrictModel):
    """Complete, non-defaulted safety contract for one v2 Operation."""

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
    """A bounded v2 HTTP transport contract with explicit safety semantics."""

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
    "ResponseHeaderTokenSourceV2",
    "RetryContractV2",
    "Reversibility",
    "Risk",
    "RuntimeInjectionTargetV2",
]
