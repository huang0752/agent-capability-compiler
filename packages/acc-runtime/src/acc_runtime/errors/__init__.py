"""Stable, JSON-safe errors returned by the generic runtime."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar


class RuntimeError(Exception):
    """Base class for errors crossing the ACC runtime boundary.

    Human-readable exception messages are deliberately separate from the
    stable public structure. Callers should return :meth:`to_dict` at protocol
    boundaries and reserve the exception message for local diagnostics.
    """

    code: ClassVar[str] = "ACC_RUNTIME_ERROR"
    status: ClassVar[int] = 500

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.details = _json_safe_details(details)

    def to_dict(self) -> dict[str, object]:
        """Return a fresh JSON-compatible public error structure."""

        return {
            "code": self.code,
            "status": self.status,
            "details": _json_safe_details(self.details),
        }


def _json_safe_details(details: Mapping[str, object] | None) -> dict[str, Any]:
    if details is None:
        return {}
    if not isinstance(details, Mapping) or not all(isinstance(key, str) for key in details):
        raise TypeError("runtime error details must be a string-keyed JSON-compatible mapping")
    try:
        serialized = json.dumps(
            dict(details),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except TypeError as exc:
        raise TypeError("runtime error details must be JSON-compatible") from exc
    except ValueError as exc:
        raise ValueError("runtime error details must contain finite JSON values") from exc
    value = json.loads(serialized)
    if not isinstance(value, dict):  # pragma: no cover - guarded by the mapping requirement
        raise TypeError("runtime error details must be a JSON object")
    return value


__all__ = ["RuntimeError"]
