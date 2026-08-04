"""Environment-backed secret references with redacted values."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

from acc_runtime.errors import RuntimeError

_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
_REDACTED = "[REDACTED]"


class SecretReferenceError(RuntimeError, ValueError):
    """A secret reference is not a supported environment variable name."""

    code = "ACC_RUNTIME_SECRET_REF_INVALID"
    status = 400


class SecretNotFoundError(RuntimeError, LookupError):
    """A required environment-backed secret is absent."""

    code = "ACC_RUNTIME_SECRET_NOT_FOUND"
    status = 500


class SecretValue:
    """A secret whose normal string representations are always redacted."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        self.__value = value

    def get_secret_value(self) -> str:
        """Explicitly unwrap the secret at the provider boundary."""

        return self.__value

    def __str__(self) -> str:
        return _REDACTED

    def __repr__(self) -> str:
        return f"{type(self).__name__}({_REDACTED!r})"


@dataclass(frozen=True, slots=True)
class SecretRef:
    """A validated reference to one process environment variable."""

    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _ENVIRONMENT_NAME.fullmatch(self.name) is None:
            safe_name = self.name if isinstance(self.name, str) else type(self.name).__name__
            raise SecretReferenceError(
                "secret reference must be an uppercase environment variable name",
                details={"name": safe_name},
            )

    def resolve(self, environment: Mapping[str, str] | None = None) -> SecretValue:
        """Resolve this reference from an explicit mapping or ``os.environ``."""

        return resolve_secret(self, environment)


def resolve_secret(
    reference: SecretRef | str,
    environment: Mapping[str, str] | None = None,
) -> SecretValue:
    """Resolve a secret without falling back when a mapping is supplied."""

    ref = reference if isinstance(reference, SecretRef) else SecretRef(reference)
    source = os.environ if environment is None else environment
    if ref.name not in source:
        raise SecretNotFoundError(
            f"required secret is not configured: {ref.name}",
            details={"name": ref.name},
        )
    value = source[ref.name]
    if not isinstance(value, str):
        raise SecretReferenceError(
            "secret environment values must be strings",
            details={"name": ref.name},
        )
    return SecretValue(value)


__all__ = [
    "SecretNotFoundError",
    "SecretRef",
    "SecretReferenceError",
    "SecretValue",
    "resolve_secret",
]
