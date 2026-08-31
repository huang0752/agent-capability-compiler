"""Approval binding protocol and an explicitly test-only authority."""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from acc_runtime.actions.errors import (
    ActionApprovalExpiredError,
    ActionApprovalInvalidError,
)
from acc_runtime.actions.models import (
    PreparedActionRecord,
    exact_identifier,
    finite_time,
    validate_digest,
    validate_pack_digest,
)
from acc_runtime.credentials import SecretValue

_HANDLE = re.compile(r"^[A-Za-z0-9_-]{43,}$")


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    action_digest: str = field(repr=False)
    capability_id: str
    principal_digest: str = field(repr=False)
    session_digest: str | None = field(repr=False)
    pack_digest: str
    input_digest: str = field(repr=False)
    preview_digest: str = field(repr=False)
    action_expires_at: float

    def __post_init__(self) -> None:
        validate_digest(self.action_digest, field_name="action_digest")
        exact_identifier(self.capability_id, field_name="capability_id")
        validate_digest(self.principal_digest, field_name="principal_digest")
        if self.session_digest is not None:
            validate_digest(self.session_digest, field_name="session_digest")
        validate_pack_digest(self.pack_digest)
        validate_digest(self.input_digest, field_name="input_digest")
        validate_digest(self.preview_digest, field_name="preview_digest")
        finite_time(self.action_expires_at, field_name="action_expires_at")

    @classmethod
    def from_record(cls, record: PreparedActionRecord) -> ApprovalBinding:
        return cls(
            action_digest=record.handle_digest,
            capability_id=record.capability_id,
            principal_digest=record.principal_digest,
            session_digest=record.session_digest,
            pack_digest=record.pack_digest,
            input_digest=record.input_digest,
            preview_digest=record.preview_digest,
            action_expires_at=record.expires_at,
        )


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    approval_digest: str = field(repr=False)
    binding: ApprovalBinding
    approved_at: float
    expires_at: float
    decision_id: str | None = None
    approver_id: str | None = None

    def __post_init__(self) -> None:
        validate_digest(self.approval_digest, field_name="approval_digest")
        approved = finite_time(self.approved_at, field_name="approved_at")
        expires = finite_time(self.expires_at, field_name="expires_at")
        if expires <= approved or expires > self.binding.action_expires_at:
            raise ValueError("approval expiry must be within the prepared Action lifetime")
        if (self.decision_id is None) != (self.approver_id is None):
            raise ValueError("decision_id and approver_id must be provided together")
        if self.decision_id is not None:
            exact_identifier(self.decision_id, field_name="decision_id")
            exact_identifier(self.approver_id, field_name="approver_id")


@runtime_checkable
class ApprovalAuthority(Protocol):
    async def verify(
        self,
        approval_handle: str | SecretValue,
        expected: ApprovalBinding,
    ) -> ApprovalGrant: ...


@dataclass(frozen=True, slots=True)
class _ApprovalRecord:
    digest: str
    binding: ApprovalBinding
    created_at: float
    expires_at: float


class InMemoryApprovalAuthority:
    """One-time approval handles for deterministic development and tests only."""

    def __init__(
        self,
        *,
        development_only: bool,
        clock: Callable[[], float] = time.monotonic,
        handle_generator: Callable[[], str] | None = None,
    ) -> None:
        if development_only is not True:
            raise ValueError("in-memory Approval Authority is for development/test only")
        self._clock = clock
        self._handle_generator = handle_generator or (lambda: secrets.token_urlsafe(32))
        self._records: dict[str, _ApprovalRecord] = {}
        self._lock = asyncio.Lock()

    async def issue_for_testing(
        self,
        binding: ApprovalBinding,
        *,
        expires_in_seconds: int,
    ) -> SecretValue:
        if not isinstance(binding, ApprovalBinding):
            raise TypeError("binding must be ApprovalBinding")
        if (
            not isinstance(expires_in_seconds, int)
            or isinstance(expires_in_seconds, bool)
            or expires_in_seconds <= 0
        ):
            raise ValueError("expires_in_seconds must be a positive integer")
        now = finite_time(self._clock(), field_name="clock")
        expires_at = now + expires_in_seconds
        if expires_at > binding.action_expires_at:
            raise ValueError("approval cannot outlive the prepared Action")
        raw = self._handle_generator()
        if not isinstance(raw, str) or _HANDLE.fullmatch(raw) is None:
            raise ActionApprovalInvalidError("approval handle generation failed")
        digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
        async with self._lock:
            if digest in self._records:
                raise ActionApprovalInvalidError("approval handle generation failed")
            self._records[digest] = _ApprovalRecord(
                digest=digest,
                binding=binding,
                created_at=now,
                expires_at=expires_at,
            )
        return SecretValue(raw)

    async def verify(
        self,
        approval_handle: str | SecretValue,
        expected: ApprovalBinding,
    ) -> ApprovalGrant:
        if not isinstance(expected, ApprovalBinding):
            raise TypeError("expected must be ApprovalBinding")
        digest = _approval_digest(approval_handle)
        async with self._lock:
            record = self._records.pop(digest, None)
        if record is None or record.binding != expected:
            raise ActionApprovalInvalidError("approval is invalid")
        now = finite_time(self._clock(), field_name="clock")
        if now >= record.expires_at or now >= expected.action_expires_at:
            raise ActionApprovalExpiredError("approval has expired")
        return ApprovalGrant(
            approval_digest=record.digest,
            binding=record.binding,
            approved_at=record.created_at,
            expires_at=record.expires_at,
        )


def _approval_digest(handle: str | SecretValue) -> str:
    raw: object = handle.get_secret_value() if isinstance(handle, SecretValue) else handle
    if not isinstance(raw, str) or _HANDLE.fullmatch(raw) is None:
        raise ActionApprovalInvalidError("approval is invalid")
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


__all__ = [
    "ApprovalAuthority",
    "ApprovalBinding",
    "ApprovalGrant",
    "InMemoryApprovalAuthority",
]
