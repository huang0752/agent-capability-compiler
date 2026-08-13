"""Loopback-only trusted operator approval for local development Actions."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from acc_runtime.actions import (
    ActionCoordinator,
    InMemoryApprovalAuthority,
    SQLiteApprovalAuthority,
)
from acc_runtime.actions.models import PreparedActionStatus
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.gateway.auth import GatewaySessionLookup
from acc_runtime.gateway.models import GatewaySessionRecord

OPERATOR_APPROVAL_BODY_LIMIT = 1024


class OperatorApprovalUnauthorizedError(AccRuntimeError):
    code = "ACC_GATEWAY_OPERATOR_UNAUTHORIZED"
    status = 401


class OperatorActionNotFoundError(AccRuntimeError):
    code = "ACC_GATEWAY_OPERATOR_ACTION_NOT_FOUND"
    status = 404


class OperatorApprovalCapacityError(AccRuntimeError):
    code = "ACC_GATEWAY_OPERATOR_CAPACITY"
    status = 503


@dataclass(frozen=True, slots=True, repr=False)
class LocalDevelopmentOperatorApprovalConfig:
    """Secret-bearing config that cannot be inferred from a Pack."""

    secret: SecretValue
    secret_ref: str
    max_pending_actions: int = 1000

    def __post_init__(self) -> None:
        if not isinstance(self.secret, SecretValue):
            raise TypeError("operator secret must be SecretValue")
        raw = self.secret.get_secret_value()
        if len(raw.encode("utf-8")) < 32:
            raise ValueError("operator secret must contain at least 32 bytes")
        if not isinstance(self.secret_ref, str) or not self.secret_ref:
            raise ValueError("operator secret_ref must be nonempty")
        if (
            not isinstance(self.max_pending_actions, int)
            or isinstance(self.max_pending_actions, bool)
            or self.max_pending_actions < 1
        ):
            raise ValueError("max_pending_actions must be positive")


@dataclass(frozen=True, slots=True, repr=False)
class ProductionOperatorApprovalConfig:
    """Independent production operator credential and bounded registry config."""

    secret: SecretValue
    secret_ref: str
    max_pending_actions: int = 1000

    def __post_init__(self) -> None:
        if not isinstance(self.secret, SecretValue):
            raise TypeError("production operator secret must be SecretValue")
        if len(self.secret.get_secret_value().encode("utf-8")) < 32:
            raise ValueError("production operator secret must contain at least 32 bytes")
        if not isinstance(self.secret_ref, str) or not self.secret_ref:
            raise ValueError("production operator secret_ref must be nonempty")
        if (
            not isinstance(self.max_pending_actions, int)
            or isinstance(self.max_pending_actions, bool)
            or self.max_pending_actions < 1
        ):
            raise ValueError("max_pending_actions must be positive")


@dataclass(frozen=True, slots=True, repr=False)
class _PendingApproval:
    session_id: str
    expires_at: float


class ProductionOperatorSessionLookup(Protocol):
    """Digest-only session lookup exposed by the encrypted production vault."""

    def session_digest(self, session_id: str) -> str: ...

    async def resolve_session_digest(self, digest: str) -> GatewaySessionRecord: ...


class LocalDevelopmentOperatorApprovalService:
    """Approve only prepared handles observed from this Gateway process."""

    def __init__(
        self,
        *,
        config: LocalDevelopmentOperatorApprovalConfig,
        coordinator: ActionCoordinator,
        authority: InMemoryApprovalAuthority,
        session_store: GatewaySessionLookup,
        clock: Callable[[], float] = time.monotonic,
        pending_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._coordinator = coordinator
        self._authority = authority
        self._session_store = session_store
        # ``expires_at`` belongs to the ActionStore clock domain (monotonic for
        # the in-memory store, wall time for SQLite).  Pending registry cleanup
        # always uses a process-local monotonic deadline derived at observation
        # time, so persisted wall timestamps are never compared with monotonic
        # values directly.
        self._clock = clock
        self._pending_clock = pending_clock
        self._pending: dict[str, _PendingApproval] = {}
        self._lock = asyncio.Lock()

    def authenticate(self, candidate: bytes) -> None:
        expected = self._config.secret.get_secret_value().encode("utf-8")
        if not secrets.compare_digest(candidate, expected):
            raise OperatorApprovalUnauthorizedError("Operator authentication failed")

    async def observe_prepared(
        self,
        action_handle: SecretValue,
        principal: PrincipalContext,
        *,
        approval_required: bool,
        expires_at: float,
    ) -> None:
        if not approval_required:
            return
        session_id = principal.gateway_session_id
        if session_id is None:
            raise OperatorActionNotFoundError("Operator Action was not found")
        digest = _handle_digest(action_handle.get_secret_value())
        remaining = expires_at - self._clock()
        if remaining <= 0:
            raise OperatorActionNotFoundError("Operator Action was not found")
        pending_expires_at = self._pending_clock() + remaining
        async with self._lock:
            self._expire_locked(self._pending_clock())
            if (
                digest not in self._pending
                and len(self._pending) >= self._config.max_pending_actions
            ):
                raise OperatorApprovalCapacityError("Operator approval capacity is exhausted")
            self._pending[digest] = _PendingApproval(
                session_id=session_id,
                expires_at=pending_expires_at,
            )

    async def approve(self, action_handle: str) -> tuple[str, str]:
        digest = _handle_digest(action_handle)
        async with self._lock:
            self._expire_locked(self._pending_clock())
            pending = self._pending.get(digest)
        if pending is None:
            raise OperatorActionNotFoundError("Operator Action was not found")
        try:
            session = await self._session_store.resolve_session_id(pending.session_id)
            principal = session.principal_context
            binding = await self._coordinator.approval_binding_for_trusted_host(
                action_handle,
                principal,
            )
            remaining = int(binding.action_expires_at - self._clock())
            if remaining < 1:
                raise ValueError
            approval = await self._authority.issue_for_testing(
                binding,
                expires_in_seconds=min(30, remaining),
            )
            result = await self._coordinator.approve(
                action_handle,
                approval,
                principal,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            async with self._lock:
                self._pending.pop(digest, None)
            raise OperatorActionNotFoundError("Operator Action was not found") from None
        async with self._lock:
            self._pending.pop(digest, None)
        if result.status is not PreparedActionStatus.APPROVED:
            raise OperatorActionNotFoundError("Operator Action was not found")
        return result.capability_id, result.status.value

    def _expire_locked(self, now: float) -> None:
        for digest in tuple(self._pending):
            if self._pending[digest].expires_at <= now:
                self._pending.pop(digest, None)


class ProductionOperatorApprovalService:
    """Issue and consume one durable approval from a process-bound observation."""

    def __init__(
        self,
        *,
        config: ProductionOperatorApprovalConfig,
        coordinator: ActionCoordinator,
        authority: SQLiteApprovalAuthority,
        session_store: ProductionOperatorSessionLookup,
        clock: Callable[[], float] = time.time,
        pending_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._coordinator = coordinator
        self._authority = authority
        self._session_store = session_store
        self._clock = clock
        self._pending_clock = pending_clock
        self._pending: dict[str, _PendingApproval] = {}
        self._lock = asyncio.Lock()

    def authenticate(self, candidate: bytes) -> None:
        expected = self._config.secret.get_secret_value().encode("utf-8")
        if not secrets.compare_digest(candidate, expected):
            raise OperatorApprovalUnauthorizedError("Operator authentication failed")

    async def observe_prepared(
        self,
        action_handle: SecretValue,
        principal: PrincipalContext,
        *,
        approval_required: bool,
        expires_at: float,
    ) -> None:
        if not approval_required:
            return
        session_id = principal.gateway_session_id
        if session_id is None:
            raise OperatorActionNotFoundError("Operator Action was not found")
        handle_digest = _handle_digest(action_handle.get_secret_value())
        session_digest = self._session_store.session_digest(session_id)
        remaining = expires_at - self._clock()
        if remaining <= 0:
            raise OperatorActionNotFoundError("Operator Action was not found")
        async with self._lock:
            self._expire_locked(self._pending_clock())
            if (
                handle_digest not in self._pending
                and len(self._pending) >= self._config.max_pending_actions
            ):
                raise OperatorApprovalCapacityError("Operator approval capacity is exhausted")
            self._pending[handle_digest] = _PendingApproval(
                session_id=session_digest,
                expires_at=self._pending_clock() + remaining,
            )

    async def approve(
        self,
        action_handle: str,
        *,
        decision_id: str,
        approver_id: str,
        expires_in_seconds: int,
    ) -> tuple[str, str]:
        digest = _handle_digest(action_handle)
        async with self._lock:
            self._expire_locked(self._pending_clock())
            pending = self._pending.get(digest)
        if pending is None:
            raise OperatorActionNotFoundError("Operator Action was not found")
        try:
            session = await self._session_store.resolve_session_digest(pending.session_id)
            principal = session.principal_context
            binding = await self._coordinator.approval_binding_for_trusted_host(
                action_handle, principal
            )
            approval = await self._authority.issue(
                binding,
                decision_id=decision_id,
                approver_id=approver_id,
                expires_in_seconds=expires_in_seconds,
            )
            result = await self._coordinator.approve(action_handle, approval, principal)
        except asyncio.CancelledError:
            raise
        except Exception:
            async with self._lock:
                self._pending.pop(digest, None)
            raise OperatorActionNotFoundError("Operator Action was not found") from None
        async with self._lock:
            self._pending.pop(digest, None)
        if result.status is not PreparedActionStatus.APPROVED:
            raise OperatorActionNotFoundError("Operator Action was not found")
        return result.capability_id, result.status.value

    def _expire_locked(self, now: float) -> None:
        for digest in tuple(self._pending):
            if self._pending[digest].expires_at <= now:
                self._pending.pop(digest, None)


def _handle_digest(value: str) -> str:
    if not isinstance(value, str) or len(value) < 43 or not value.isascii():
        raise OperatorActionNotFoundError("Operator Action was not found")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


__all__ = [
    "OPERATOR_APPROVAL_BODY_LIMIT",
    "LocalDevelopmentOperatorApprovalConfig",
    "LocalDevelopmentOperatorApprovalService",
    "OperatorActionNotFoundError",
    "OperatorApprovalUnauthorizedError",
    "ProductionOperatorApprovalConfig",
    "ProductionOperatorApprovalService",
]
