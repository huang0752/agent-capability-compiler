from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from acc_runtime.actions import (
    ActionAuditEvent,
    ActionAuditSink,
    ActionAuditUnavailableError,
    PreparedActionStatus,
    SQLiteActionAuditSink,
)

PACK_DIGEST = "sha256:" + "a" * 64
SECRET = b"durable-action-audit-operator-secret-32-bytes"
SALT = b"durable-action-audit-deployment-salt"


def _event(index: int) -> ActionAuditEvent:
    return ActionAuditEvent(
        lifecycle="commit",
        capability_id="orders.update",
        status=PreparedActionStatus.SUCCEEDED,
        result_category="success",
        pack_digest=PACK_DIGEST,
        principal_digest="b" * 64,
        session_digest="c" * 64,
        event_id=f"{index:064x}",
        occurred_at=1_700_000_000.0 + index,
        action_digest="d" * 64,
    )


def _sink(path: Path, *, secret: bytes = SECRET) -> SQLiteActionAuditSink:
    return SQLiteActionAuditSink(
        path,
        operator_secret=secret,
        deployment_salt=SALT,
        busy_timeout_seconds=2,
    )


def test_sqlite_audit_conforms_and_rejects_unsafe_configuration(tmp_path: Path) -> None:
    sink = _sink(tmp_path / "audit.db")
    assert isinstance(sink, ActionAuditSink)
    assert sink.is_durable is True

    with pytest.raises(ValueError, match="32 bytes"):
        SQLiteActionAuditSink(
            tmp_path / "short.db",
            operator_secret=b"short",
            deployment_salt=SALT,
        )
    with pytest.raises(ValueError, match="16 bytes"):
        SQLiteActionAuditSink(
            tmp_path / "salt.db",
            operator_secret=SECRET,
            deployment_salt=b"short",
        )


@pytest.mark.asyncio
async def test_emit_acknowledges_committed_append_and_restart_verifies_chain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.db"
    first = _sink(path)
    await first.emit(_event(1))

    # A separate connection can observe the row immediately after await: emit
    # does not acknowledge a buffered or uncommitted event.
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (1,)
    closed = await first.close()
    assert [record.sequence for record in closed] == [1]

    reopened = _sink(path)
    await reopened.emit(_event(2))
    records = await reopened.records()
    assert [record.event.event_id for record in records] == [f"{1:064x}", f"{2:064x}"]
    assert records[0].chain_digest != records[1].chain_digest


@pytest.mark.asyncio
async def test_wrong_key_and_row_tampering_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    sink = _sink(path)
    await sink.emit(_event(1))
    await sink.close()

    with pytest.raises(ActionAuditUnavailableError):
        _sink(path, secret=b"a-different-operator-secret-that-is-long-enough")

    with sqlite3.connect(path) as connection:
        triggers = connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).fetchall()
        for name, _ in triggers:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute("UPDATE audit_events SET occurred_at=occurred_at+1 WHERE sequence=1")
        for _, sql in triggers:
            connection.execute(sql)
        connection.commit()

    with pytest.raises(ActionAuditUnavailableError, match="integrity"):
        _sink(path)


@pytest.mark.asyncio
async def test_append_only_triggers_and_concurrent_instances_preserve_one_chain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.db"
    first = _sink(path)
    second = _sink(path)

    await asyncio.gather(
        *(
            first.emit(_event(index)) if index % 2 else second.emit(_event(index))
            for index in range(1, 21)
        )
    )
    records = await first.records()
    assert len(records) == 20
    assert {record.event.event_id for record in records} == {
        f"{index:064x}" for index in range(1, 21)
    }

    with (
        sqlite3.connect(path) as connection,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        connection.execute("DELETE FROM audit_events WHERE sequence=1")


@pytest.mark.asyncio
async def test_journal_contains_no_business_payload_or_raw_handles(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    sink = _sink(path)
    await sink.emit(_event(1))
    await sink.close()

    rendered = path.read_bytes()
    for forbidden in (
        b"order-private",
        b"preview-private",
        b"result-private",
        b"action-handle-private",
        b"approval-handle-private",
        SECRET,
    ):
        assert forbidden not in rendered
