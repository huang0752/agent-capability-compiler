"""Strict contracts for out-of-process ACC adapters."""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NonEmptyString = Annotated[str, Field(min_length=1)]
AdapterMethod = Literal["GET", "HEAD"]
AdapterActionMethod = Literal["POST", "PUT", "PATCH", "DELETE"]
_ROUTE_PARAMETER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FORBIDDEN_CONTROL_HEADERS = frozenset(
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


class StrictAdapterModel(BaseModel):
    """Base model that rejects unknown fields and scalar coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


def _validate_path(value: str, *, static: bool) -> str:
    parsed = urlsplit(value)
    decoded = unquote(parsed.path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not value.startswith("/")
        or value.startswith("//")
        or decoded.startswith("//")
        or "\\" in decoded
        or ".." in decoded.split("/")
        or any(ord(character) < 32 for character in decoded)
    ):
        raise ValueError(
            "adapter paths must be origin-relative without traversal, query, or fragment"
        )
    if static and ("{" in decoded or "}" in decoded):
        raise ValueError("adapter path must be static")
    if not static:
        without_parameters = _ROUTE_PARAMETER.sub("", decoded)
        if "{" in without_parameters or "}" in without_parameters:
            raise ValueError("adapter operation path contains an invalid route parameter")
    return value


def join_adapter_path(base_path: str, operation_path: str) -> str:
    """Join two already validated adapter paths without URL normalization."""

    return operation_path if base_path == "/" else f"{base_path}{operation_path}"


class AdapterOperation(StrictAdapterModel):
    """One statically declared read-only adapter route."""

    id: NonEmptyString
    method: AdapterMethod
    path: NonEmptyString
    summary: NonEmptyString

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_path(value, static=False)


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


class AdapterHeaderTarget(StrictAdapterModel):
    """A Runtime-owned Action control carried in a non-sensitive header."""

    kind: Literal["header"]
    name: NonEmptyString

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if _HEADER_NAME.fullmatch(value) is None or value.casefold() in _FORBIDDEN_CONTROL_HEADERS:
            raise ValueError("Action control header is invalid or reserved")
        return value


class AdapterBodyTarget(StrictAdapterModel):
    """A Runtime-owned Action control carried at a JSON body pointer."""

    kind: Literal["body"]
    pointer: NonEmptyString

    @field_validator("pointer")
    @classmethod
    def validate_pointer(cls, value: str) -> str:
        return _validate_json_pointer(value)


type AdapterControlTarget = Annotated[
    AdapterHeaderTarget | AdapterBodyTarget,
    Field(discriminator="kind"),
]


class AdapterResponseHeaderToken(StrictAdapterModel):
    """Capture an optimistic token from a preview response header."""

    kind: Literal["response_header"]
    name: NonEmptyString

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if _HEADER_NAME.fullmatch(value) is None:
            raise ValueError("concurrency token header is invalid")
        return value


class AdapterResponseBodyToken(StrictAdapterModel):
    """Capture an optimistic token from a preview response body."""

    kind: Literal["body"]
    pointer: NonEmptyString

    @field_validator("pointer")
    @classmethod
    def validate_pointer(cls, value: str) -> str:
        return _validate_json_pointer(value)


type AdapterConcurrencyToken = Annotated[
    AdapterResponseHeaderToken | AdapterResponseBodyToken,
    Field(discriminator="kind"),
]


class AdapterSourceKeyIdempotency(StrictAdapterModel):
    """Require a Runtime-owned key that the source transaction deduplicates."""

    mode: Literal["source_key"]
    target: AdapterControlTarget


class AdapterRequiredConcurrency(StrictAdapterModel):
    """Require preview token capture and commit-time precondition injection."""

    mode: Literal["required"]
    token: AdapterConcurrencyToken
    precondition: AdapterControlTarget


class AdapterActionSafety(StrictAdapterModel):
    """Non-optional production invariants for one mutating adapter route."""

    idempotency: AdapterSourceKeyIdempotency
    concurrency: AdapterRequiredConcurrency
    transactional_outcome: Literal[True]
    authorization: Literal["source_revalidated"]
    max_request_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    max_response_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]

    @model_validator(mode="after")
    def validate_control_targets(self) -> Self:
        if self.idempotency.target == self.concurrency.precondition:
            raise ValueError("idempotency and concurrency controls must use distinct targets")
        return self


class AdapterActionOperation(StrictAdapterModel):
    """One fixed mutation route with complete production safety metadata."""

    id: NonEmptyString
    method: AdapterActionMethod
    path: NonEmptyString
    summary: NonEmptyString
    safety: AdapterActionSafety

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_path(value, static=False)


class AdapterHealth(StrictAdapterModel):
    """Health endpoint location and public, static service metadata."""

    path: NonEmptyString
    metadata: dict[str, NonEmptyString] = Field(default_factory=dict)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_path(value, static=True)


class AdapterContract(StrictAdapterModel):
    """Versioned contract for one fixed, read-only adapter surface."""

    schema_version: Literal["2"]
    id: NonEmptyString
    version: NonEmptyString
    base_path: NonEmptyString
    health: AdapterHealth = Field(
        default_factory=lambda: AdapterHealth(path="/healthz", metadata={})
    )
    operations: list[AdapterOperation | AdapterActionOperation]

    @field_validator("base_path")
    @classmethod
    def validate_base_path(cls, value: str) -> str:
        _validate_path(value, static=True)
        if value != "/" and value.endswith("/"):
            raise ValueError("adapter base_path must not end with a slash")
        return value

    @model_validator(mode="after")
    def validate_operation_index(self) -> Self:
        ids = [operation.id for operation in self.operations]
        if len(ids) != len(set(ids)):
            raise ValueError("adapter operation ids must be unique")
        routes = [(operation.method, operation.path) for operation in self.operations]
        if len(routes) != len(set(routes)):
            raise ValueError("adapter operation routes must be unique")
        full_paths = {
            join_adapter_path(self.base_path, operation.path) for operation in self.operations
        }
        if self.health.path in full_paths:
            raise ValueError("adapter health path must not collide with an operation route")
        return self


__all__ = [
    "AdapterActionMethod",
    "AdapterActionOperation",
    "AdapterActionSafety",
    "AdapterBodyTarget",
    "AdapterConcurrencyToken",
    "AdapterContract",
    "AdapterControlTarget",
    "AdapterHeaderTarget",
    "AdapterHealth",
    "AdapterMethod",
    "AdapterOperation",
    "AdapterRequiredConcurrency",
    "AdapterResponseBodyToken",
    "AdapterResponseHeaderToken",
    "AdapterSourceKeyIdempotency",
    "StrictAdapterModel",
    "join_adapter_path",
]
