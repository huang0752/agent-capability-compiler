"""Immutable public and trusted-side Action state models."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import JsonValue

from acc_runtime.credentials import SecretValue

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PACK_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def exact_identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty exact value")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise ValueError(f"{field_name} cannot contain control or surrogate characters")
    return value


def finite_time(value: object, *, field_name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{field_name} must be a finite number")
    return float(value)


def canonical_json_bytes(value: JsonValue) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Action values must contain finite canonical JSON") from exc


def json_digest(value: JsonValue) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def binding_digest(value: str, *, namespace: bytes, salt: bytes) -> str:
    return hmac.new(salt, namespace + b"\x00" + value.encode("utf-8"), hashlib.sha256).hexdigest()


def validate_digest(value: str, *, field_name: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def validate_pack_digest(value: str) -> None:
    if _PACK_DIGEST.fullmatch(value) is None:
        raise ValueError("pack_digest must use sha256:<lowercase hex> format")


class PreparedActionStatus(StrEnum):
    PREPARED = "prepared"
    APPROVED = "approved"
    COMMITTING = "committing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class PreparedActionRecord:
    """Payload-free binding metadata indexed only by an opaque-handle digest."""

    handle_digest: str = field(repr=False)
    capability_id: str
    principal_digest: str = field(repr=False)
    session_digest: str | None = field(repr=False)
    pack_digest: str
    input_digest: str = field(repr=False)
    preview_digest: str = field(repr=False)
    created_at: float
    expires_at: float
    status: PreparedActionStatus

    def __post_init__(self) -> None:
        validate_digest(self.handle_digest, field_name="handle_digest")
        exact_identifier(self.capability_id, field_name="capability_id")
        validate_digest(self.principal_digest, field_name="principal_digest")
        if self.session_digest is not None:
            validate_digest(self.session_digest, field_name="session_digest")
        validate_pack_digest(self.pack_digest)
        validate_digest(self.input_digest, field_name="input_digest")
        validate_digest(self.preview_digest, field_name="preview_digest")
        created = finite_time(self.created_at, field_name="created_at")
        expires = finite_time(self.expires_at, field_name="expires_at")
        if expires <= created:
            raise ValueError("expires_at must be later than created_at")
        if not isinstance(self.status, PreparedActionStatus):
            raise TypeError("status must be PreparedActionStatus")


@dataclass(frozen=True, slots=True)
class PreparedActionState:
    """A defensive trusted-side payload snapshot paired with immutable metadata."""

    record: PreparedActionRecord
    input_value: JsonValue = field(repr=False)
    preview_value: JsonValue = field(repr=False)
    result_value: JsonValue = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class PreparedActionCreation:
    handle: SecretValue = field(repr=False)
    state: PreparedActionState


__all__ = [
    "PreparedActionCreation",
    "PreparedActionRecord",
    "PreparedActionState",
    "PreparedActionStatus",
    "binding_digest",
    "canonical_json_bytes",
    "exact_identifier",
    "finite_time",
    "json_digest",
    "validate_digest",
    "validate_pack_digest",
]
