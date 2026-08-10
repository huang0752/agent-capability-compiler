"""Strict, read-only contracts for out-of-process ACC adapters."""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NonEmptyString = Annotated[str, Field(min_length=1)]
AdapterMethod = Literal["GET", "HEAD"]
_ROUTE_PARAMETER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


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
    operations: list[AdapterOperation]

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
    "AdapterContract",
    "AdapterHealth",
    "AdapterMethod",
    "AdapterOperation",
    "StrictAdapterModel",
    "join_adapter_path",
]
