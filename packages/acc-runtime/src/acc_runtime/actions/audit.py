"""Secret-safe Action lifecycle audit contracts and coordinator spans."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

from acc_runtime.actions.models import (
    PreparedActionStatus,
    binding_digest,
    exact_identifier,
    finite_time,
    validate_digest,
    validate_pack_digest,
)
from acc_runtime.deployment import ActionAuditMode
from acc_runtime.errors import RuntimeError as AccRuntimeError

type ActionAuditLifecycle = Literal["prepare", "approve", "commit", "status"]
type ActionAuditResultCategory = Literal[
    "started",
    "success",
    "replayed",
    "denied",
    "invalid",
    "internal",
    "cancelled",
    "outcome_unknown",
]

_LIFECYCLES = frozenset({"prepare", "approve", "commit", "status"})
_RESULT_CATEGORIES = frozenset(
    {
        "started",
        "success",
        "replayed",
        "denied",
        "invalid",
        "internal",
        "cancelled",
        "outcome_unknown",
    }
)


class ActionAuditUnavailableError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_AUDIT_UNAVAILABLE"
    status = 503


@dataclass(frozen=True, slots=True)
class ActionAuditEvent:
    """One minimized event that cannot contain Action business material."""

    lifecycle: ActionAuditLifecycle
    capability_id: str
    status: PreparedActionStatus | None
    result_category: ActionAuditResultCategory
    pack_digest: str
    principal_digest: str = field(repr=False)
    session_digest: str | None = field(repr=False)
    event_id: str = field(default_factory=lambda: secrets.token_hex(32))
    occurred_at: float = field(default_factory=time.time)
    action_digest: str | None = field(default=None, repr=False)
    approval_decision_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.lifecycle not in _LIFECYCLES:
            raise ValueError("Action audit lifecycle is invalid")
        exact_identifier(self.capability_id, field_name="capability_id")
        if self.status is not None and not isinstance(self.status, PreparedActionStatus):
            raise TypeError("Action audit status must be PreparedActionStatus or None")
        if self.result_category not in _RESULT_CATEGORIES:
            raise ValueError("Action audit result category is invalid")
        if self.result_category == "started" and self.status is not None:
            raise ValueError("A started Action audit event cannot contain status")
        if self.result_category in {"success", "replayed", "outcome_unknown"} and (
            self.status is None
        ):
            raise ValueError("A completed Action audit event requires status")
        validate_pack_digest(self.pack_digest)
        validate_digest(self.principal_digest, field_name="principal_digest")
        if self.session_digest is not None:
            validate_digest(self.session_digest, field_name="session_digest")
        validate_digest(self.event_id, field_name="event_id")
        finite_time(self.occurred_at, field_name="occurred_at")
        if self.action_digest is not None:
            validate_digest(self.action_digest, field_name="action_digest")
        if self.approval_decision_id is not None:
            exact_identifier(self.approval_decision_id, field_name="approval_decision_id")
            if self.lifecycle != "approve" or self.result_category != "success":
                raise ValueError("approval_decision_id is only valid for successful approval")
        if self.action_digest is None and self.lifecycle != "prepare":
            raise ValueError("Action audit event requires action_digest")
        if (
            self.lifecycle == "prepare"
            and self.result_category in {"success", "replayed", "outcome_unknown"}
            and self.action_digest is None
        ):
            raise ValueError("Completed prepare audit event requires action_digest")

    def to_dict(self) -> dict[str, str | float | None]:
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "lifecycle": self.lifecycle,
            "capability_id": self.capability_id,
            "status": None if self.status is None else self.status.value,
            "result_category": self.result_category,
            "pack_digest": self.pack_digest,
            "principal_digest": self.principal_digest,
            "session_digest": self.session_digest,
            "action_digest": self.action_digest,
            "approval_decision_id": self.approval_decision_id,
        }


@runtime_checkable
class ActionAuditSink(Protocol):
    async def emit(self, event: ActionAuditEvent) -> None: ...


class LoggingActionAuditSink:
    """Emit minimized Action lifecycle events to an operator-visible logger."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("acc_runtime.action_audit")

    async def emit(self, event: ActionAuditEvent) -> None:
        if not isinstance(event, ActionAuditEvent):
            raise TypeError("event must be ActionAuditEvent")
        self._logger.info(
            "ACC_ACTION_AUDIT %s",
            json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")),
        )


@runtime_checkable
class ActionAuditSpan(Protocol):
    async def finish(
        self,
        *,
        status: PreparedActionStatus | None,
        result_category: ActionAuditResultCategory,
        action_digest: str | None = None,
        approval_decision_id: str | None = None,
    ) -> None: ...


@dataclass(slots=True)
class _NoopActionAuditSpan:
    async def finish(
        self,
        *,
        status: PreparedActionStatus | None,
        result_category: ActionAuditResultCategory,
        action_digest: str | None = None,
        approval_decision_id: str | None = None,
    ) -> None:
        del status, result_category, action_digest, approval_decision_id


@dataclass(slots=True)
class _SinkActionAuditSpan:
    sink: ActionAuditSink
    mode: ActionAuditMode
    lifecycle: ActionAuditLifecycle
    capability_id: str
    pack_digest: str
    principal_digest: str
    session_digest: str | None
    action_digest: str | None
    clock: Callable[[], float]
    event_id_generator: Callable[[], str]
    finished: bool = False

    async def finish(
        self,
        *,
        status: PreparedActionStatus | None,
        result_category: ActionAuditResultCategory,
        action_digest: str | None = None,
        approval_decision_id: str | None = None,
    ) -> None:
        if self.finished:
            return
        self.finished = True
        event = self._event(
            status=status,
            result_category=result_category,
            action_digest=action_digest if action_digest is not None else self.action_digest,
            approval_decision_id=approval_decision_id,
        )
        try:
            await self.sink.emit(event)
        except asyncio.CancelledError:
            raise
        except BaseException:
            if self.mode == "required":
                raise ActionAuditUnavailableError(
                    "Required Action audit could not be recorded"
                ) from None

    def _event(
        self,
        *,
        status: PreparedActionStatus | None,
        result_category: ActionAuditResultCategory,
        action_digest: str | None = None,
        approval_decision_id: str | None = None,
    ) -> ActionAuditEvent:
        return ActionAuditEvent(
            lifecycle=self.lifecycle,
            capability_id=self.capability_id,
            status=status,
            result_category=result_category,
            pack_digest=self.pack_digest,
            principal_digest=self.principal_digest,
            session_digest=self.session_digest,
            event_id=self.event_id_generator(),
            occurred_at=self.clock(),
            action_digest=action_digest,
            approval_decision_id=approval_decision_id,
        )


async def start_action_audit_span(
    *,
    sink: ActionAuditSink | None,
    mode: ActionAuditMode,
    salt: bytes | None,
    lifecycle: ActionAuditLifecycle,
    capability_id: str,
    pack_digest: str,
    principal_id: str,
    session_id: str | None,
    action_digest: str | None = None,
    clock: Callable[[], float] = time.time,
    event_id_generator: Callable[[], str] | None = None,
) -> ActionAuditSpan:
    """Preflight the sink before a lifecycle can reach a business mutation."""

    if sink is None:
        return _NoopActionAuditSpan()
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ActionAuditUnavailableError("Action audit identity salt is unavailable")
    span = _SinkActionAuditSpan(
        sink=sink,
        mode=mode,
        lifecycle=lifecycle,
        capability_id=exact_identifier(capability_id, field_name="capability_id"),
        pack_digest=pack_digest,
        principal_digest=binding_digest(
            exact_identifier(principal_id, field_name="principal_id"),
            namespace=b"action-audit-principal",
            salt=salt,
        ),
        session_digest=(
            None
            if session_id is None
            else binding_digest(
                exact_identifier(session_id, field_name="session_id"),
                namespace=b"action-audit-session",
                salt=salt,
            )
        ),
        action_digest=action_digest,
        clock=clock,
        event_id_generator=event_id_generator or (lambda: secrets.token_hex(32)),
    )
    started = span._event(
        status=None,
        result_category="started",
        action_digest=action_digest,
    )
    try:
        await sink.emit(started)
    except asyncio.CancelledError:
        raise
    except BaseException:
        if mode == "required":
            raise ActionAuditUnavailableError(
                "Required Action audit could not be started"
            ) from None
        return _NoopActionAuditSpan()
    return span


__all__ = [
    "ActionAuditEvent",
    "ActionAuditLifecycle",
    "ActionAuditResultCategory",
    "ActionAuditSink",
    "ActionAuditSpan",
    "ActionAuditUnavailableError",
    "LoggingActionAuditSink",
]
