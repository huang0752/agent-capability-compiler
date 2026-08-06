"""Single-process, digest-indexed Gateway session storage."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import math
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Never, Protocol

from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError
from acc_runtime.gateway.models import GatewaySessionRecord, GatewaySessionStatus


class GatewaySessionInvalidError(RuntimeError):
    code = "ACC_GATEWAY_SESSION_INVALID"
    status = 401


class GatewaySessionExpiredError(RuntimeError):
    code = "ACC_GATEWAY_SESSION_EXPIRED"
    status = 401


class GatewayReauthRequiredError(RuntimeError):
    code = "ACC_GATEWAY_REAUTH_REQUIRED"
    status = 401


class GatewaySessionCapacityError(RuntimeError):
    code = "ACC_GATEWAY_SESSION_CAPACITY_REACHED"
    status = 503


class GatewaySessionStore(Protocol):
    async def create(
        self,
        *,
        session_id: str,
        principal_context: PrincipalContext,
        source_expires_at: float | None = None,
    ) -> tuple[SecretValue, GatewaySessionRecord]: ...

    async def resolve_token(self, token: str | SecretValue) -> GatewaySessionRecord: ...

    async def resolve_session_id(self, session_id: str) -> GatewaySessionRecord: ...

    async def revoke(self, session_id: str) -> None: ...

    async def mark_reauth_required(self, session_id: str) -> GatewaySessionRecord: ...

    async def purge_expired(self) -> int: ...

    async def close(self) -> None: ...


_URLSAFE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43,}$")


@dataclass(frozen=True, slots=True)
class _SessionFailure:
    kind: Literal["invalid", "expired", "reauth", "capacity"]
    reason: str


type _RecordOutcome = GatewaySessionRecord | _SessionFailure
type _CreateOutcome = tuple[SecretValue, GatewaySessionRecord] | _SessionFailure


class InMemoryGatewaySessionStore:
    """Concurrency-safe v1 Store; restarting the process invalidates every session."""

    def __init__(
        self,
        *,
        max_sessions: int,
        ttl_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        token_generator: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(max_sessions, int) or isinstance(max_sessions, bool) or max_sessions <= 0:
            raise ValueError("max_sessions must be a positive integer")
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 1 <= ttl_seconds <= 86400
        ):
            raise ValueError("ttl_seconds must be between 1 and 86400")
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._token_generator = token_generator or (lambda: secrets.token_urlsafe(32))
        self._by_digest: dict[str, GatewaySessionRecord] = {}
        self._digest_by_session_id: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def create(
        self,
        *,
        session_id: str,
        principal_context: PrincipalContext,
        source_expires_at: float | None = None,
    ) -> tuple[SecretValue, GatewaySessionRecord]:
        outcome = await self._create_outcome(
            session_id=session_id,
            principal_context=principal_context,
            source_expires_at=source_expires_at,
        )
        del self, principal_context
        return _unwrap_create(outcome)

    async def _create_outcome(
        self,
        *,
        session_id: str,
        principal_context: PrincipalContext,
        source_expires_at: float | None,
    ) -> _CreateOutcome:
        now = self._clock()
        expires_at = now + self._ttl_seconds
        if source_expires_at is not None:
            if not isinstance(source_expires_at, (int, float)) or not math.isfinite(
                source_expires_at
            ):
                return _SessionFailure("expired", "source_expiry_invalid")
            expires_at = min(expires_at, float(source_expires_at))
        if expires_at <= now:
            return _SessionFailure("expired", "source_authentication_expired")

        async with self._lock:
            if self._closed:
                return _SessionFailure("invalid", "store_closed")
            self._purge_expired_locked(now)
            if len(self._by_digest) >= self._max_sessions:
                return _SessionFailure("capacity", "capacity_reached")
            if session_id in self._digest_by_session_id:
                return _SessionFailure("invalid", "duplicate_session_id")

            try:
                raw_token = self._token_generator()
            except Exception:
                return _SessionFailure("invalid", "token_generation_failed")
            if not _is_256_bit_urlsafe_token(raw_token):
                return _SessionFailure("invalid", "token_generation_invalid")
            digest = _token_digest(raw_token)
            if digest in self._by_digest:
                return _SessionFailure("invalid", "token_generation_duplicate")
            try:
                record = GatewaySessionRecord(
                    session_id=session_id,
                    token_digest=digest,
                    principal_context=principal_context,
                    created_at=now,
                    expires_at=expires_at,
                )
            except (TypeError, ValueError):
                return _SessionFailure("invalid", "session_record_invalid")
            self._by_digest[digest] = record
            self._digest_by_session_id[session_id] = digest
            return SecretValue(raw_token), record

    async def resolve_token(self, token: str | SecretValue) -> GatewaySessionRecord:
        raw_token: object = token.get_secret_value() if isinstance(token, SecretValue) else token
        if not isinstance(raw_token, str):
            outcome: _RecordOutcome = _SessionFailure("invalid", "token_invalid")
        else:
            digest = _token_digest(raw_token)
            outcome = await self._resolve_digest_outcome(digest)
        del token, raw_token, self
        return _unwrap_record(outcome)

    async def _resolve_digest_outcome(self, digest: str) -> _RecordOutcome:
        async with self._lock:
            if self._closed:
                return _SessionFailure("invalid", "store_closed")
            return self._resolve_digest_locked(digest, self._clock())

    async def resolve_session_id(self, session_id: str) -> GatewaySessionRecord:
        outcome = await self._resolve_session_id_outcome(session_id)
        del self
        return _unwrap_record(outcome)

    async def _resolve_session_id_outcome(self, session_id: str) -> _RecordOutcome:
        async with self._lock:
            if self._closed:
                return _SessionFailure("invalid", "store_closed")
            digest = self._digest_by_session_id.get(session_id)
            if digest is None:
                return _SessionFailure("invalid", "session_unknown")
            return self._resolve_digest_locked(digest, self._clock())

    async def revoke(self, session_id: str) -> None:
        async with self._lock:
            digest = self._digest_by_session_id.pop(session_id, None)
            if digest is not None:
                self._by_digest.pop(digest, None)

    async def mark_reauth_required(self, session_id: str) -> GatewaySessionRecord:
        outcome = await self._mark_reauth_outcome(session_id)
        del self
        return _unwrap_record(outcome)

    async def _mark_reauth_outcome(self, session_id: str) -> _RecordOutcome:
        async with self._lock:
            if self._closed:
                return _SessionFailure("invalid", "store_closed")
            digest = self._digest_by_session_id.get(session_id)
            if digest is None:
                return _SessionFailure("invalid", "session_unknown")
            record = self._resolve_digest_locked(digest, self._clock(), allow_reauth=True)
            if isinstance(record, _SessionFailure):
                return record
            marked = record.model_copy(update={"status": GatewaySessionStatus.REAUTH_REQUIRED})
            self._by_digest[digest] = marked
            return marked

    async def purge_expired(self) -> int:
        async with self._lock:
            return self._purge_expired_locked(self._clock())

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._by_digest.clear()
            self._digest_by_session_id.clear()

    def _resolve_digest_locked(
        self,
        digest: str,
        now: float,
        *,
        allow_reauth: bool = False,
    ) -> _RecordOutcome:
        record = self._by_digest.get(digest)
        if record is None:
            return _SessionFailure("invalid", "token_unknown")
        if record.expires_at <= now:
            self._remove_locked(record)
            return _SessionFailure("expired", "session_expired")
        if record.status is GatewaySessionStatus.REAUTH_REQUIRED and not allow_reauth:
            return _SessionFailure("reauth", "reauth_required")
        return record

    def _purge_expired_locked(self, now: float) -> int:
        expired = [record for record in self._by_digest.values() if record.expires_at <= now]
        for record in expired:
            self._remove_locked(record)
        return len(expired)

    def _remove_locked(self, record: GatewaySessionRecord) -> None:
        self._by_digest.pop(record.token_digest, None)
        self._digest_by_session_id.pop(record.session_id, None)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_256_bit_urlsafe_token(token: object) -> bool:
    if not isinstance(token, str) or _URLSAFE_TOKEN.fullmatch(token) is None:
        return False
    try:
        decoded = base64.b64decode(
            token + "=" * (-len(token) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 32


def _unwrap_create(outcome: _CreateOutcome) -> tuple[SecretValue, GatewaySessionRecord]:
    if isinstance(outcome, _SessionFailure):
        _raise_failure(outcome)
    return outcome


def _unwrap_record(outcome: _RecordOutcome) -> GatewaySessionRecord:
    if isinstance(outcome, _SessionFailure):
        _raise_failure(outcome)
    return outcome


def _raise_failure(failure: _SessionFailure) -> Never:
    if failure.kind == "expired":
        raise GatewaySessionExpiredError("Gateway session has expired.")
    if failure.kind == "reauth":
        raise GatewayReauthRequiredError("Gateway session requires reauthentication.")
    if failure.kind == "capacity":
        raise GatewaySessionCapacityError("Gateway session capacity has been reached.")
    raise GatewaySessionInvalidError("Gateway session is invalid.")


__all__ = [
    "GatewayReauthRequiredError",
    "GatewaySessionCapacityError",
    "GatewaySessionExpiredError",
    "GatewaySessionInvalidError",
    "GatewaySessionStore",
    "InMemoryGatewaySessionStore",
]
