"""Minimal, secret-safe audit events for Gateway and Runtime activity."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

type AuditEventKind = Literal["capability_call", "session_create", "session_delete"]
type AuditResultCategory = Literal[
    "success",
    "policy_denied",
    "upstream_denied",
    "reauth",
    "upstream_error",
    "invalid_request",
    "internal",
    "cancelled",
]
_EVENT_KINDS = frozenset({"capability_call", "session_create", "session_delete"})
_RESULT_CATEGORIES = frozenset(
    {
        "success",
        "policy_denied",
        "upstream_denied",
        "reauth",
        "upstream_error",
        "invalid_request",
        "internal",
        "cancelled",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _monotonic() -> float:
    return time.monotonic()


def _public_identifier(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value.strip() or any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError(f"{field_name} must be nonempty and contain no control characters")
    return value


def _digest(value: str, *, namespace: bytes, salt: bytes) -> str:
    identifier = _public_identifier(value, field_name="audit identity")
    return hmac.new(salt, namespace + b"\x00" + identifier.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """An immutable event containing only approved audit metadata."""

    timestamp: datetime
    duration_ms: float
    project_id: str
    event_kind: AuditEventKind
    capability_id: str | None
    operation_ids: tuple[str, ...]
    result_category: AuditResultCategory
    principal_digest: str | None = field(repr=False)
    session_digest: str | None = field(repr=False)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() != timedelta(0):
            raise ValueError("audit timestamp must use UTC")
        if not math.isfinite(self.duration_ms) or self.duration_ms < 0:
            raise ValueError("audit duration must be finite and nonnegative")
        _public_identifier(self.project_id, field_name="project_id")
        if self.event_kind not in _EVENT_KINDS:
            raise ValueError("audit event kind is invalid")
        if self.result_category not in _RESULT_CATEGORIES:
            raise ValueError("audit result category is invalid")
        if self.capability_id is not None:
            _public_identifier(self.capability_id, field_name="capability_id")
        for operation_id in self.operation_ids:
            _public_identifier(operation_id, field_name="operation_id")
        if len(set(self.operation_ids)) != len(self.operation_ids):
            raise ValueError("audit operation ids must be unique")
        for digest in (self.principal_digest, self.session_digest):
            if digest is not None and (
                len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError("audit identity digests must be lowercase SHA-256 hex")
        if self.event_kind == "capability_call" and self.capability_id is None:
            raise ValueError("capability audit events require capability_id")
        if self.event_kind != "capability_call" and (
            self.capability_id is not None or self.operation_ids
        ):
            raise ValueError("session audit events cannot contain capability metadata")

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "duration_ms": self.duration_ms,
            "project_id": self.project_id,
            "event_kind": self.event_kind,
            "capability_id": self.capability_id,
            "operation_ids": list(self.operation_ids),
            "result_category": self.result_category,
            "principal_digest": self.principal_digest,
            "session_digest": self.session_digest,
        }


class AuditSink(Protocol):
    """Accept already-minimized audit events."""

    def emit(self, event: AuditEvent) -> None: ...


class OperationObserver(Protocol):
    """Observe only the identifier of an Operation entering its provider boundary."""

    def observe(self, operation_id: str) -> None: ...


class AuditSpan(OperationObserver, Protocol):
    """A request-local observer completed with one result category."""

    def finish(self, result_category: AuditResultCategory) -> None: ...


class NoopAuditSink:
    def emit(self, event: AuditEvent) -> None:
        del event


class MemoryAuditSink:
    """Small in-memory sink intended for tests and embedded diagnostics."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class LoggingAuditSink:
    """Write one compact JSON object per event without logging sink failures."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("acc_runtime.audit")

    def emit(self, event: AuditEvent) -> None:
        self._logger.info(
            json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        )


class _AuditSpan:
    __slots__ = (
        "_capability_id",
        "_collector",
        "_finished",
        "_operation_ids",
        "_principal_digest",
        "_project_id",
        "_session_digest",
        "_started_at",
        "_started_monotonic",
    )

    def __init__(
        self,
        collector: AuditCollector,
        *,
        project_id: str,
        capability_id: str,
        principal_digest: str,
        session_digest: str | None,
    ) -> None:
        self._collector = collector
        self._project_id = project_id
        self._capability_id = capability_id
        self._principal_digest = principal_digest
        self._session_digest = session_digest
        self._started_at = _utc_now()
        self._started_monotonic = _monotonic()
        self._operation_ids: list[str] = []
        self._finished = False

    def observe(self, operation_id: str) -> None:
        if self._finished:
            return
        normalized = _public_identifier(operation_id, field_name="operation_id")
        if normalized not in self._operation_ids:
            self._operation_ids.append(normalized)

    def finish(self, result_category: AuditResultCategory) -> None:
        if self._finished:
            return
        self._finished = True
        elapsed = max(0.0, (_monotonic() - self._started_monotonic) * 1000.0)
        event = AuditEvent(
            timestamp=self._started_at,
            duration_ms=elapsed,
            project_id=self._project_id,
            event_kind="capability_call",
            capability_id=self._capability_id,
            operation_ids=tuple(self._operation_ids),
            result_category=result_category,
            principal_digest=self._principal_digest,
            session_digest=self._session_digest,
        )
        self._collector._safe_emit(event)


class AuditCollector:
    """Create per-call spans and anonymize identities with a deployment salt."""

    __slots__ = ("_salt", "_sink")

    def __init__(self, *, sink: AuditSink, deployment_salt: bytes) -> None:
        if not isinstance(deployment_salt, bytes):
            raise TypeError("audit deployment salt must be bytes")
        if len(deployment_salt) < 16:
            raise ValueError("audit deployment salt must contain at least 16 bytes")
        self._sink = sink
        self._salt = bytes(deployment_salt)

    def start_capability(
        self,
        *,
        project_id: str,
        capability_id: str,
        principal_id: str,
        session_id: str | None,
    ) -> AuditSpan:
        return _AuditSpan(
            self,
            project_id=_public_identifier(project_id, field_name="project_id"),
            capability_id=_public_identifier(capability_id, field_name="capability_id"),
            principal_digest=_digest(principal_id, namespace=b"principal", salt=self._salt),
            session_digest=(
                None
                if session_id is None
                else _digest(session_id, namespace=b"session", salt=self._salt)
            ),
        )

    def emit_session_event(
        self,
        *,
        project_id: str,
        event_kind: Literal["session_create", "session_delete"],
        result_category: AuditResultCategory,
        principal_id: str | None,
        session_id: str | None,
        duration_ms: float,
    ) -> None:
        event = AuditEvent(
            timestamp=_utc_now(),
            duration_ms=duration_ms,
            project_id=project_id,
            event_kind=event_kind,
            capability_id=None,
            operation_ids=(),
            result_category=result_category,
            principal_digest=(
                None
                if principal_id is None
                else _digest(principal_id, namespace=b"principal", salt=self._salt)
            ),
            session_digest=(
                None
                if session_id is None
                else _digest(session_id, namespace=b"session", salt=self._salt)
            ),
        )
        self._safe_emit(event)

    def _safe_emit(self, event: AuditEvent) -> None:
        try:
            self._sink.emit(event)
        except BaseException:
            # Auditing must never affect or become exception context for business calls.
            return


def observe_operation(observer: OperationObserver | None, operation_id: str) -> None:
    """Invoke an observer defensively at the provider boundary."""

    if observer is None:
        return
    try:
        observer.observe(operation_id)
    except BaseException:
        return


__all__ = [
    "AuditCollector",
    "AuditEvent",
    "AuditEventKind",
    "AuditResultCategory",
    "AuditSink",
    "AuditSpan",
    "LoggingAuditSink",
    "MemoryAuditSink",
    "NoopAuditSink",
    "OperationObserver",
]
