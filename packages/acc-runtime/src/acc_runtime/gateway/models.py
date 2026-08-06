"""Strict, secret-aware models for the multi-user HTTP Gateway."""

from __future__ import annotations

import ipaddress
import math
import unicodedata
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from acc_runtime.context import PrincipalContext


def _exact_text(value: str, *, field_name: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty exact value")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    if "*" in value:
        raise ValueError(f"{field_name} must not contain wildcards")
    return value


def _exact_host(value: str) -> str:
    value = _exact_text(value, field_name="allowed host")
    if any(marker in value for marker in ("/", "?", "#", "@", "\\")):
        raise ValueError("allowed host must contain only an exact host and optional port")
    parsed = urlsplit(f"//{value}")
    if parsed.username is not None or parsed.password is not None or parsed.hostname is None:
        raise ValueError("allowed host must not contain credentials or an ambiguous host")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("allowed host contains an invalid port") from exc
    return value


def _exact_origin(value: str) -> str:
    value = _exact_text(value, field_name="allowed origin")
    if "\\" in value:
        raise ValueError("allowed origin must not contain backslashes")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("allowed origin must be an exact HTTP origin without credentials or path")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("allowed origin contains an invalid port") from exc
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GatewaySettings(_StrictModel):
    """Deployment settings whose allowlists are exact, never pattern based."""

    listen_host: str = "127.0.0.1"
    tls_enabled: bool = False
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()
    session_ttl_seconds: int = Field(default=3600, ge=1, le=86400)
    max_sessions: int = Field(default=1000, gt=0)

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("at least one exact allowed host is required")
        validated = tuple(_exact_host(value) for value in values)
        if len(frozenset(validated)) != len(validated):
            raise ValueError("allowed hosts must be unique")
        return validated

    @field_validator("allowed_origins")
    @classmethod
    def _validate_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(_exact_origin(value) for value in values)
        if len(frozenset(validated)) != len(validated):
            raise ValueError("allowed origins must be unique")
        return validated

    @model_validator(mode="after")
    def _validate_listener(self) -> GatewaySettings:
        try:
            listen_address = ipaddress.ip_address(self.listen_host)
        except ValueError as exc:
            raise ValueError("listen_host must be an explicit IP address") from exc
        if not listen_address.is_loopback and not self.tls_enabled:
            raise ValueError("non-loopback Gateway listeners require TLS")
        return self


class SessionCreateRequest(_StrictModel):
    """One-shot credentials accepted only by the trusted session endpoint."""

    identity: str
    password: SecretStr = Field(repr=False, exclude=True)

    @field_validator("identity")
    @classmethod
    def _validate_identity(cls, value: str) -> str:
        return _exact_text(value, field_name="identity")

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value():
            raise ValueError("password must be nonempty")
        return value


class SessionCreateResponse(_StrictModel):
    """One-shot Gateway token response; generic serialization remains redacted."""

    gateway_token: SecretStr = Field(repr=False, exclude=True)
    expires_in_seconds: int = Field(gt=0, le=86400)

    def one_time_payload(self) -> dict[str, str | int]:
        """Reveal the token only at the dedicated session-creation boundary."""

        return {
            "token": self.gateway_token.get_secret_value(),
            "expires_in_seconds": self.expires_in_seconds,
        }


class GatewaySessionStatus(StrEnum):
    ACTIVE = "active"
    REAUTH_REQUIRED = "reauth_required"
    REVOKED = "revoked"
    EXPIRED = "expired"


class GatewaySessionRecord(_StrictModel):
    """In-memory session state with all identity and auth material non-public."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        arbitrary_types_allowed=True,
    )

    session_id: str
    token_digest: str = Field(repr=False, exclude=True, pattern=r"^[0-9a-f]{64}$")
    principal_context: PrincipalContext = Field(repr=False, exclude=True)
    created_at: float
    expires_at: float
    status: GatewaySessionStatus = GatewaySessionStatus.ACTIVE

    @field_validator("session_id")
    @classmethod
    def _validate_session_id(cls, value: str) -> str:
        return _exact_text(value, field_name="session_id")

    @field_validator("created_at", "expires_at")
    @classmethod
    def _validate_time(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("session timestamps must be finite")
        return value

    @model_validator(mode="after")
    def _validate_lifetime(self) -> GatewaySessionRecord:
        if self.expires_at <= self.created_at:
            raise ValueError("session expiry must be after creation")
        if self.principal_context.gateway_session_id != self.session_id:
            raise ValueError("PrincipalContext must be bound to the Gateway session id")
        return self


__all__ = [
    "GatewaySessionRecord",
    "GatewaySessionStatus",
    "GatewaySettings",
    "SessionCreateRequest",
    "SessionCreateResponse",
]
