"""Action Store protocol and an explicitly development-only memory implementation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol, runtime_checkable

from pydantic import JsonValue

from acc_runtime.actions.errors import (
    ActionBindingMismatchError,
    ActionExpiredError,
    ActionHandleInvalidError,
    ActionStateConflictError,
)
from acc_runtime.actions.models import (
    PreparedActionCreation,
    PreparedActionRecord,
    PreparedActionState,
    PreparedActionStatus,
    binding_digest,
    canonical_json_bytes,
    exact_identifier,
    finite_time,
    validate_pack_digest,
)
from acc_runtime.credentials import SecretValue

_HANDLE = re.compile(r"^[A-Za-z0-9_-]{43,}$")
_ALLOWED_TRANSITIONS = {
    PreparedActionStatus.PREPARED: frozenset({PreparedActionStatus.APPROVED}),
    PreparedActionStatus.APPROVED: frozenset({PreparedActionStatus.COMMITTING}),
    PreparedActionStatus.COMMITTING: frozenset(
        {
            PreparedActionStatus.SUCCEEDED,
            PreparedActionStatus.FAILED,
            PreparedActionStatus.OUTCOME_UNKNOWN,
        }
    ),
}


@runtime_checkable
class ActionStore(Protocol):
    is_durable: bool

    async def create(
        self,
        *,
        capability_id: str,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
        input_value: JsonValue,
        preview_value: JsonValue,
        expires_in_seconds: int,
    ) -> PreparedActionCreation: ...

    async def resolve(
        self,
        handle: str | SecretValue,
        *,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
    ) -> PreparedActionState: ...

    async def transition(
        self,
        handle: str | SecretValue,
        *,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
        expected: PreparedActionStatus,
        target: PreparedActionStatus,
        result_value: JsonValue = None,
    ) -> PreparedActionState: ...

    async def close(self) -> tuple[PreparedActionRecord, ...]: ...


class InMemoryActionStore:
    """Concurrency-safe memory Store that cannot be mistaken for durable storage."""

    is_durable = False
    deployment_safety = "development_test_only"

    def __init__(
        self,
        *,
        development_only: bool,
        deployment_salt: bytes = b"development-action-store-salt",
        max_actions: int = 1000,
        clock: Callable[[], float] = time.monotonic,
        handle_generator: Callable[[], str] | None = None,
    ) -> None:
        if development_only is not True:
            raise ValueError("in-memory Action Store is for development/test only")
        if not isinstance(deployment_salt, bytes) or len(deployment_salt) < 16:
            raise ValueError("deployment_salt must contain at least 16 bytes")
        if not isinstance(max_actions, int) or isinstance(max_actions, bool) or max_actions <= 0:
            raise ValueError("max_actions must be a positive integer")
        self._salt = bytes(deployment_salt)
        self._max_actions = max_actions
        self._clock = clock
        self._handle_generator = handle_generator or (lambda: secrets.token_urlsafe(32))
        self._records: dict[str, PreparedActionRecord] = {}
        self._payloads: dict[str, tuple[bytes, bytes, bytes | None]] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def create(
        self,
        *,
        capability_id: str,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
        input_value: JsonValue,
        preview_value: JsonValue,
        expires_in_seconds: int,
    ) -> PreparedActionCreation:
        checked_capability = exact_identifier(capability_id, field_name="capability_id")
        checked_principal = exact_identifier(principal_id, field_name="principal_id")
        checked_session = (
            None if session_id is None else exact_identifier(session_id, field_name="session_id")
        )
        validate_pack_digest(pack_digest)
        if (
            not isinstance(expires_in_seconds, int)
            or isinstance(expires_in_seconds, bool)
            or not 1 <= expires_in_seconds <= 86_400
        ):
            raise ValueError("expires_in_seconds must be between 1 and 86400")
        input_bytes = canonical_json_bytes(input_value)
        preview_bytes = canonical_json_bytes(preview_value)
        raw_handle = self._handle_generator()
        if not isinstance(raw_handle, str) or _HANDLE.fullmatch(raw_handle) is None:
            raise ActionStateConflictError("Action handle generation failed")
        handle_digest = hashlib.sha256(raw_handle.encode("ascii")).hexdigest()
        async with self._lock:
            if self._closed:
                raise ActionHandleInvalidError("Action handle is invalid")
            now = finite_time(self._clock(), field_name="clock")
            self._expire_locked(now)
            if len(self._records) >= self._max_actions or handle_digest in self._records:
                raise ActionStateConflictError("Action Store cannot create a new state")
            record = PreparedActionRecord(
                handle_digest=handle_digest,
                capability_id=checked_capability,
                principal_digest=binding_digest(
                    checked_principal, namespace=b"principal", salt=self._salt
                ),
                session_digest=(
                    None
                    if checked_session is None
                    else binding_digest(checked_session, namespace=b"session", salt=self._salt)
                ),
                pack_digest=pack_digest,
                input_digest=hashlib.sha256(input_bytes).hexdigest(),
                preview_digest=hashlib.sha256(preview_bytes).hexdigest(),
                created_at=now,
                expires_at=now + expires_in_seconds,
                status=PreparedActionStatus.PREPARED,
            )
            self._records[handle_digest] = record
            self._payloads[handle_digest] = (input_bytes, preview_bytes, None)
            state = self._state_locked(record)
        return PreparedActionCreation(handle=SecretValue(raw_handle), state=state)

    async def resolve(
        self,
        handle: str | SecretValue,
        *,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
    ) -> PreparedActionState:
        async with self._lock:
            record = self._resolve_bound_locked(
                handle,
                principal_id=principal_id,
                session_id=session_id,
                pack_digest=pack_digest,
            )
            return self._state_locked(record)

    async def transition(
        self,
        handle: str | SecretValue,
        *,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
        expected: PreparedActionStatus,
        target: PreparedActionStatus,
        result_value: JsonValue = None,
    ) -> PreparedActionState:
        if not isinstance(expected, PreparedActionStatus) or not isinstance(
            target, PreparedActionStatus
        ):
            raise TypeError("Action transition statuses must be PreparedActionStatus")
        async with self._lock:
            record = self._resolve_bound_locked(
                handle,
                principal_id=principal_id,
                session_id=session_id,
                pack_digest=pack_digest,
            )
            if record.status is not expected or target not in _ALLOWED_TRANSITIONS.get(
                expected, frozenset()
            ):
                raise ActionStateConflictError("Action state transition conflicts")
            if target is not PreparedActionStatus.SUCCEEDED and result_value is not None:
                raise ActionStateConflictError("Only a successful Action can persist a result")
            input_bytes, preview_bytes, existing_result = self._payloads[record.handle_digest]
            result_bytes = (
                canonical_json_bytes(result_value)
                if target is PreparedActionStatus.SUCCEEDED
                else existing_result
            )
            updated = replace(record, status=target)
            self._records[record.handle_digest] = updated
            self._payloads[record.handle_digest] = (
                input_bytes,
                preview_bytes,
                result_bytes,
            )
            return self._state_locked(updated)

    async def inspect_for_testing(self, handle: str | SecretValue) -> PreparedActionRecord:
        """Inspect payload-free state only; unavailable through the Store protocol."""

        digest = _handle_digest(handle)
        async with self._lock:
            record = self._records.get(digest)
            if record is None:
                raise ActionHandleInvalidError("Action handle is invalid")
            return record

    async def close(self) -> tuple[PreparedActionRecord, ...]:
        async with self._lock:
            if self._closed:
                return ()
            self._closed = True
            records = tuple(self._records[key] for key in sorted(self._records))
            self._records.clear()
            self._payloads.clear()
            return records

    def _resolve_bound_locked(
        self,
        handle: str | SecretValue,
        *,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
    ) -> PreparedActionRecord:
        if self._closed:
            raise ActionHandleInvalidError("Action handle is invalid")
        digest = _handle_digest(handle)
        record = self._records.get(digest)
        if record is None:
            raise ActionHandleInvalidError("Action handle is invalid")
        checked_principal = exact_identifier(principal_id, field_name="principal_id")
        checked_session = (
            None if session_id is None else exact_identifier(session_id, field_name="session_id")
        )
        validate_pack_digest(pack_digest)
        supplied_principal = binding_digest(
            checked_principal, namespace=b"principal", salt=self._salt
        )
        supplied_session = (
            None
            if checked_session is None
            else binding_digest(checked_session, namespace=b"session", salt=self._salt)
        )
        if (
            record.principal_digest != supplied_principal
            or record.session_digest != supplied_session
            or record.pack_digest != pack_digest
        ):
            raise ActionBindingMismatchError("Action binding does not match")
        now = finite_time(self._clock(), field_name="clock")
        if now >= record.expires_at or record.status is PreparedActionStatus.EXPIRED:
            expired = replace(record, status=PreparedActionStatus.EXPIRED)
            self._records[digest] = expired
            raise ActionExpiredError("Prepared Action has expired")
        return record

    def _state_locked(self, record: PreparedActionRecord) -> PreparedActionState:
        input_bytes, preview_bytes, result_bytes = self._payloads[record.handle_digest]
        return PreparedActionState(
            record=record,
            input_value=json.loads(input_bytes),
            preview_value=json.loads(preview_bytes),
            result_value=(None if result_bytes is None else json.loads(result_bytes)),
        )

    def _expire_locked(self, now: float) -> None:
        for digest, record in tuple(self._records.items()):
            if now >= record.expires_at and record.status is not PreparedActionStatus.EXPIRED:
                self._records[digest] = replace(record, status=PreparedActionStatus.EXPIRED)


def _handle_digest(handle: str | SecretValue) -> str:
    raw: object = handle.get_secret_value() if isinstance(handle, SecretValue) else handle
    if not isinstance(raw, str) or _HANDLE.fullmatch(raw) is None:
        raise ActionHandleInvalidError("Action handle is invalid")
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


__all__ = ["ActionStore", "InMemoryActionStore"]
