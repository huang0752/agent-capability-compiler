"""Stable diagnostics and command result envelopes."""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

type DiagnosticCode = Annotated[
    str,
    StringConstraints(pattern=r"^ACC_[A-Z][A-Z0-9_]*$"),
]
type DiagnosticSeverity = Literal["error", "warning", "info"]


class Diagnostic(BaseModel):
    """A machine-readable problem with an optional project-file location."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    code: DiagnosticCode
    severity: DiagnosticSeverity
    message: Annotated[str, StringConstraints(min_length=1)]
    path: str | None = None
    pointer: str | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or "\\" in value:
            raise ValueError("diagnostic path must be a non-empty POSIX project-relative path")

        path = PurePosixPath(value)
        windows_path = PureWindowsPath(value)
        if path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
            raise ValueError("diagnostic path must be project-relative")
        if path == PurePosixPath(".") or ".." in path.parts:
            raise ValueError("diagnostic path cannot contain '.' or '..' segments")
        return value

    @field_validator("pointer")
    @classmethod
    def validate_pointer(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        if not value.startswith("/"):
            raise ValueError("diagnostic pointer must be a JSON Pointer")
        for token in value.split("/")[1:]:
            index = 0
            while index < len(token):
                if token[index] == "~":
                    if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                        raise ValueError("diagnostic pointer contains an invalid escape")
                    index += 2
                else:
                    index += 1
        return value


class ResultEnvelope(BaseModel):
    """The stable JSON envelope returned by every ACC command."""

    model_config = ConfigDict(extra="forbid", strict=True)

    ok: bool
    command: Annotated[str, StringConstraints(min_length=1)]
    result: Any | None
    diagnostics: list[Diagnostic] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_status(self) -> ResultEnvelope:
        has_error = any(item.severity == "error" for item in self.diagnostics)
        if self.ok and has_error:
            raise ValueError("a successful result cannot contain error diagnostics")
        if not self.ok:
            if self.result is not None:
                raise ValueError("a failed result must use a null result")
            if not has_error:
                raise ValueError("a failed result requires an error diagnostic")
        return self


__all__ = ["Diagnostic", "DiagnosticCode", "DiagnosticSeverity", "ResultEnvelope"]
