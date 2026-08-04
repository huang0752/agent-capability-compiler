"""Deterministic HTTP faults used by fake REST systems."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class Fault:
    """One synthetic outcome with no clocks, sockets, or random values."""

    kind: Literal["http_status", "timeout", "oversize"]
    status_code: int | None = None
    code: str | None = None
    size_bytes: int | None = None

    def __post_init__(self) -> None:
        if self.kind == "http_status":
            if self.status_code is None or not 100 <= self.status_code <= 599:
                raise ValueError("HTTP status faults require a status between 100 and 599")
            if not self.code:
                raise ValueError("HTTP status faults require a stable error code")
        elif self.kind == "oversize":
            if self.size_bytes is None or self.size_bytes < 1:
                raise ValueError("oversize faults require a positive byte count")

    @classmethod
    def http_status(cls, status_code: int, *, code: str = "UPSTREAM_ERROR") -> Fault:
        return cls(kind="http_status", status_code=status_code, code=code)

    @classmethod
    def forbidden(cls) -> Fault:
        return cls.http_status(403, code="FORBIDDEN")

    @classmethod
    def not_found(cls) -> Fault:
        return cls.http_status(404, code="NOT_FOUND")

    @classmethod
    def timeout(cls) -> Fault:
        return cls(kind="timeout")

    @classmethod
    def oversize(cls, size_bytes: int) -> Fault:
        return cls(kind="oversize", size_bytes=size_bytes)


__all__ = ["Fault"]
