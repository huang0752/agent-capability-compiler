from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from acc_runtime.gateway.audit import (
    AuditCollector,
    AuditEvent,
    LoggingAuditSink,
    MemoryAuditSink,
    NoopAuditSink,
)


def test_collector_emits_an_immutable_minimal_event_with_salted_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = MemoryAuditSink()
    collector = AuditCollector(sink=sink, deployment_salt=b"deployment-audit-salt")
    started_at = datetime(2026, 8, 6, 3, 4, 5, tzinfo=UTC)
    monotonic_values = iter((100.0, 100.125))
    monkeypatch.setattr("acc_runtime.gateway.audit._utc_now", lambda: started_at)
    monkeypatch.setattr("acc_runtime.gateway.audit._monotonic", lambda: next(monotonic_values))

    span = collector.start_capability(
        project_id="crm",
        capability_id="get_customer",
        principal_id="user-a@example.test",
        session_id="gateway-session-secret",
    )
    span.observe("crm.get_customer")
    span.finish("success")

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event == AuditEvent(
        timestamp=started_at,
        duration_ms=125.0,
        project_id="crm",
        event_kind="capability_call",
        capability_id="get_customer",
        operation_ids=("crm.get_customer",),
        result_category="success",
        principal_digest=hmac.new(
            b"deployment-audit-salt", b"principal\x00user-a@example.test", hashlib.sha256
        ).hexdigest(),
        session_digest=hmac.new(
            b"deployment-audit-salt", b"session\x00gateway-session-secret", hashlib.sha256
        ).hexdigest(),
    )
    with pytest.raises(FrozenInstanceError):
        event.project_id = "changed"  # type: ignore[misc]


def test_session_events_are_minimal_and_do_not_expose_raw_identifiers() -> None:
    sink = MemoryAuditSink()
    collector = AuditCollector(sink=sink, deployment_salt=b"salt-at-least-sixteen")

    collector.emit_session_event(
        project_id="crm",
        event_kind="session_create",
        result_category="success",
        principal_id="private-account",
        session_id="private-session-token",
        duration_ms=4.5,
    )

    serialized = repr(sink.events[0]) + json.dumps(sink.events[0].to_dict())
    assert "private-account" not in serialized
    assert "private-session-token" not in serialized
    assert "password" not in sink.events[0].to_dict()
    assert "authorization" not in sink.events[0].to_dict()
    assert "request" not in sink.events[0].to_dict()
    assert "response" not in sink.events[0].to_dict()


def test_logging_sink_writes_only_structured_public_event_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    event = AuditEvent(
        timestamp=datetime(2026, 8, 6, tzinfo=UTC),
        duration_ms=1.25,
        project_id="crm",
        event_kind="capability_call",
        capability_id="get_customer",
        operation_ids=("crm.get_customer",),
        result_category="success",
        principal_digest="a" * 64,
        session_digest="b" * 64,
    )
    sink = LoggingAuditSink(logging.getLogger("acc.audit.test"))

    with caplog.at_level(logging.INFO, logger="acc.audit.test"):
        sink.emit(event)

    payload = json.loads(caplog.records[-1].message)
    assert payload == event.to_dict()


def test_noop_and_failing_sinks_never_break_collection() -> None:
    class FailingSink:
        def emit(self, event: AuditEvent) -> None:
            raise RuntimeError("sink-private-failure")

    for sink in (NoopAuditSink(), FailingSink()):
        collector = AuditCollector(sink=sink, deployment_salt=b"salt-at-least-sixteen")
        span = collector.start_capability(
            project_id="crm",
            capability_id="get_customer",
            principal_id="private-principal",
            session_id="private-session",
        )
        span.observe("crm.get_customer")
        span.finish("internal")


def test_event_rejects_non_utc_timestamps_and_unknown_categories() -> None:
    values = {
        "timestamp": datetime(2026, 8, 6, tzinfo=timezone(timedelta(hours=8))),
        "duration_ms": 1.0,
        "project_id": "crm",
        "event_kind": "capability_call",
        "capability_id": "get_customer",
        "operation_ids": (),
        "result_category": "success",
        "principal_digest": None,
        "session_digest": None,
    }
    with pytest.raises(ValueError, match="UTC"):
        AuditEvent(**values)  # type: ignore[arg-type]

    values["timestamp"] = datetime(2026, 8, 6, tzinfo=UTC)
    values["result_category"] = "secret-result"
    with pytest.raises(ValueError, match="result category"):
        AuditEvent(**values)  # type: ignore[arg-type]


def test_collector_keeps_interleaved_request_operations_isolated() -> None:
    sink = MemoryAuditSink()
    collector = AuditCollector(sink=sink, deployment_salt=b"salt-at-least-sixteen")
    first = collector.start_capability(
        project_id="crm",
        capability_id="first",
        principal_id="principal-a",
        session_id="session-a",
    )
    second = collector.start_capability(
        project_id="crm",
        capability_id="second",
        principal_id="principal-b",
        session_id="session-b",
    )

    first.observe("crm.first")
    second.observe("crm.second")
    first.finish("success")
    second.finish("upstream_denied")

    assert [event.operation_ids for event in sink.events] == [("crm.first",), ("crm.second",)]
    assert sink.events[0].principal_digest != sink.events[1].principal_digest
    assert sink.events[0].session_digest != sink.events[1].session_digest


def test_event_constructor_does_not_accept_payload_or_secret_fields() -> None:
    safe = {
        "timestamp": datetime(2026, 8, 6, tzinfo=UTC),
        "duration_ms": 1.0,
        "project_id": "crm",
        "event_kind": "capability_call",
        "capability_id": "get_customer",
        "operation_ids": (),
        "result_category": "success",
        "principal_digest": None,
        "session_digest": None,
    }
    for forbidden in ("request", "response", "arguments", "authorization", "secret"):
        with pytest.raises(TypeError):
            AuditEvent(**safe, **{forbidden: "private"})  # type: ignore[arg-type]
