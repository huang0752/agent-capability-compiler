from __future__ import annotations

import asyncio
import itertools
import multiprocessing
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue

from acc_runtime.actions import (
    ActionBindingMismatchError,
    ActionExpiredError,
    ActionHandleInvalidError,
    ActionStateConflictError,
    ActionStore,
    PreparedActionStatus,
    SQLiteActionStore,
)
from fs_links import create_link

PACK_DIGEST = "sha256:" + "a" * 64
SECRET = b"operator-secret-for-sqlite-tests-32-bytes"
SALT = b"deployment-salt-for-tests"


def _store(
    path: Path,
    *,
    now: list[float] | None = None,
    secret: bytes = SECRET,
    max_actions: int = 10,
    busy_timeout_seconds: float = 1.0,
    fixed_handle: str | None = None,
) -> SQLiteActionStore:
    counter = itertools.count()
    return SQLiteActionStore(
        path,
        operator_secret=secret,
        deployment_salt=SALT,
        max_actions=max_actions,
        clock=(lambda: now[0]) if now is not None else (lambda: 100.0),
        handle_generator=(
            (lambda: fixed_handle)
            if fixed_handle is not None
            else (lambda: f"{'z' * 43}{next(counter)}")
        ),
        busy_timeout_seconds=busy_timeout_seconds,
    )


async def _create(store: SQLiteActionStore) -> Any:
    return await store.create(
        capability_id="orders.approve",
        principal_id="user-a",
        session_id="session-a",
        pack_digest=PACK_DIGEST,
        input_value={"b": 2, "a": 1},
        preview_value={"status": "pending", "version": 3},
        expires_in_seconds=300,
    )


def _bindings() -> dict[str, str]:
    return {
        "principal_id": "user-a",
        "session_id": "session-a",
        "pack_digest": PACK_DIGEST,
    }


def _process_transition(
    database: str,
    raw_handle: str,
    start: Any,
    outcomes: Any,
) -> None:
    async def run() -> None:
        store = _store(Path(database))
        start.wait(timeout=10)
        try:
            await store.transition(
                raw_handle,
                expected=PreparedActionStatus.PREPARED,
                target=PreparedActionStatus.APPROVED,
                **_bindings(),
            )
        except ActionStateConflictError:
            outcomes.put("conflict")
        else:
            outcomes.put("success")

    asyncio.run(run())


def test_sqlite_store_requires_operator_material_and_secure_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        SQLiteActionStore(tmp_path / "short.db", operator_secret=b"short", deployment_salt=SALT)
    with pytest.raises(ValueError, match="16 bytes"):
        SQLiteActionStore(tmp_path / "salt.db", operator_secret=SECRET, deployment_salt=b"short")
    with pytest.raises(ValueError, match="parent directory"):
        _store(tmp_path / "missing" / "actions.db")
    (tmp_path / "directory.db").mkdir()
    with pytest.raises(ValueError, match="regular non-link"):
        _store(tmp_path / "directory.db")


def test_sqlite_store_rejects_linked_database_path(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    target.touch()
    linked = tmp_path / "linked.db"
    create_link(linked, target)
    with pytest.raises(ValueError, match="regular non-link"):
        _store(linked)


def test_sqlite_store_rejects_linked_parent_path(tmp_path: Path) -> None:
    target = tmp_path / "real-parent"
    target.mkdir()
    linked = tmp_path / "linked-parent"
    create_link(linked, target, target_is_directory=True)
    with pytest.raises(ValueError, match="cannot traverse links"):
        _store(linked / "actions.db")


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not Windows ACLs")
def test_sqlite_store_rejects_group_readable_existing_file(tmp_path: Path) -> None:
    database = tmp_path / "insecure.db"
    database.touch(mode=0o640)
    with pytest.raises(ValueError, match="owner-only"):
        _store(database)


@pytest.mark.asyncio
async def test_restart_recovery_bindings_and_terminal_replay(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    first = _store(database)
    assert isinstance(first, ActionStore)
    assert first.is_durable is True
    creation = await _create(first)
    handle = creation.handle
    records = await first.close()
    assert len(records) == 1
    with pytest.raises(ActionHandleInvalidError):
        await first.resolve(handle, **_bindings())

    second = _store(database)
    resolved = await second.resolve(handle, **_bindings())
    assert resolved.input_value == {"a": 1, "b": 2}
    with pytest.raises(ActionBindingMismatchError):
        await second.resolve(handle, **{**_bindings(), "principal_id": "user-b"})
    for expected, target in (
        (PreparedActionStatus.PREPARED, PreparedActionStatus.APPROVED),
        (PreparedActionStatus.APPROVED, PreparedActionStatus.COMMITTING),
        (PreparedActionStatus.COMMITTING, PreparedActionStatus.SUCCEEDED),
    ):
        result: JsonValue = {"receipt": "ok"} if target is PreparedActionStatus.SUCCEEDED else None
        state = await second.transition(
            handle, expected=expected, target=target, result_value=result, **_bindings()
        )
    assert state.result_value == {"receipt": "ok"}
    await second.close()

    third = _store(database)
    replay = await third.resolve(handle, **_bindings())
    assert replay.record.status is PreparedActionStatus.SUCCEEDED
    assert replay.result_value == {"receipt": "ok"}


@pytest.mark.asyncio
async def test_payload_is_canonical_and_secrets_are_not_persisted(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    store = _store(database)
    creation = await _create(store)
    raw_handle = creation.handle.get_secret_value()
    await store.close()
    connection = sqlite3.connect(database)
    row = connection.execute(
        "SELECT input_payload,principal_digest,session_digest FROM actions"
    ).fetchone()
    connection.close()
    assert row is not None
    assert bytes(row[0]) == b'{"a":1,"b":2}'
    persisted = database.read_bytes()
    assert raw_handle.encode() not in persisted
    assert SECRET not in persisted
    assert SALT not in persisted
    assert b"user-a" not in persisted
    assert b"session-a" not in persisted


@pytest.mark.asyncio
async def test_unknown_outcome_can_recover_to_succeeded_after_reopen(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    first = _store(database)
    creation = await _create(first)
    handle = creation.handle
    for expected, target in (
        (PreparedActionStatus.PREPARED, PreparedActionStatus.APPROVED),
        (PreparedActionStatus.APPROVED, PreparedActionStatus.COMMITTING),
        (PreparedActionStatus.COMMITTING, PreparedActionStatus.OUTCOME_UNKNOWN),
    ):
        await first.transition(handle, expected=expected, target=target, **_bindings())
    await first.close()

    restarted = _store(database)
    recovered = await restarted.transition(
        handle,
        expected=PreparedActionStatus.OUTCOME_UNKNOWN,
        target=PreparedActionStatus.SUCCEEDED,
        result_value={"receipt": "source-ledger"},
        **_bindings(),
    )

    assert recovered.record.status is PreparedActionStatus.SUCCEEDED
    assert recovered.result_value == {"receipt": "source-ledger"}
    await restarted.close()


@pytest.mark.asyncio
async def test_expiry_is_persisted_across_restart(tmp_path: Path) -> None:
    now = [100.0]
    database = tmp_path / "actions.db"
    store = _store(database, now=now)
    creation = await _create(store)
    now[0] = 401.0
    with pytest.raises(ActionExpiredError):
        await store.resolve(creation.handle, **_bindings())
    await store.close()
    restarted = _store(database, now=now)
    with pytest.raises(ActionExpiredError):
        await restarted.resolve(creation.handle, **_bindings())


@pytest.mark.asyncio
async def test_max_actions_and_unique_handle_digest_are_enforced(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    store = _store(database, max_actions=1)
    await _create(store)
    with pytest.raises(ActionStateConflictError):
        await _create(store)

    duplicate_db = tmp_path / "duplicate.db"
    duplicate = _store(duplicate_db, fixed_handle="x" * 43)
    await _create(duplicate)
    with pytest.raises(ActionStateConflictError):
        await _create(duplicate)


@pytest.mark.asyncio
async def test_two_store_instances_have_one_cas_winner(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    first = _store(database)
    creation = await _create(first)
    second = _store(database)
    kwargs: dict[str, Any] = {
        **_bindings(),
        "expected": PreparedActionStatus.PREPARED,
        "target": PreparedActionStatus.APPROVED,
    }
    outcomes = await asyncio.gather(
        first.transition(creation.handle, **kwargs),
        second.transition(creation.handle, **kwargs),
        return_exceptions=True,
    )
    assert sum(not isinstance(item, BaseException) for item in outcomes) == 1
    assert sum(isinstance(item, ActionStateConflictError) for item in outcomes) == 1


@pytest.mark.asyncio
async def test_two_processes_are_serialized_with_one_cas_winner(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    creation = await _create(_store(database))
    raw_handle = creation.handle.get_secret_value()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    outcomes = context.Queue()
    processes = [
        context.Process(
            target=_process_transition,
            args=(str(database), raw_handle, start, outcomes),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0
    assert sorted(outcomes.get(timeout=2) for _ in processes) == ["conflict", "success"]


@pytest.mark.asyncio
async def test_external_write_lock_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "actions.db"
    store = _store(database, busy_timeout_seconds=0.05)
    lock = sqlite3.connect(database, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(ActionStateConflictError, match="locked"):
            await _create(store)
    finally:
        lock.rollback()
        lock.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("statement", "parameters"),
    [
        ("UPDATE actions SET input_payload=?", (b'{"tampered":true}',)),
        ("UPDATE actions SET row_mac=?", (b"x" * 32,)),
    ],
)
async def test_row_tampering_is_rejected(
    tmp_path: Path, statement: str, parameters: tuple[bytes, ...]
) -> None:
    database = tmp_path / "actions.db"
    store = _store(database)
    creation = await _create(store)
    await store.close()
    connection = sqlite3.connect(database)
    connection.execute(statement, parameters)
    connection.commit()
    connection.close()
    restarted = _store(database)
    with pytest.raises(ActionStateConflictError, match="integrity"):
        await restarted.resolve(creation.handle, **_bindings())
    with pytest.raises(ActionStateConflictError, match="integrity"):
        await restarted.close()


@pytest.mark.asyncio
async def test_close_fails_closed_when_database_exceeds_configured_bound(
    tmp_path: Path,
) -> None:
    database = tmp_path / "actions.db"
    writer = _store(database, max_actions=2)
    await _create(writer)
    await _create(writer)
    await writer.close()
    bounded_reader = _store(database, max_actions=1)
    with pytest.raises(ActionStateConflictError, match="too many"):
        await bounded_reader.close()


def test_schema_metadata_version_and_operator_secret_tampering_fail_closed(
    tmp_path: Path,
) -> None:
    for name, mutate in (
        ("metadata", "UPDATE store_metadata SET value=zeroblob(32)"),
        ("schema", "CREATE TABLE injected(value TEXT)"),
        ("version", "PRAGMA user_version=999"),
    ):
        database = tmp_path / f"{name}.db"
        _store(database)
        connection = sqlite3.connect(database)
        connection.execute(mutate)
        connection.commit()
        connection.close()
        with pytest.raises(ActionStateConflictError):
            _store(database)

    database = tmp_path / "wrong-secret.db"
    _store(database)
    with pytest.raises(ActionStateConflictError, match="authentication"):
        _store(database, secret=b"different-operator-secret-32-bytes!!")


def test_authenticated_sqlite_master_definition_rejects_semantic_rewrite(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rewritten-schema.db"
    _store(database)
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA writable_schema=ON")
    cursor = connection.execute(
        "UPDATE sqlite_master SET sql=replace(sql, ?, ?) WHERE type='table' AND name='actions'",
        ("capability_id TEXT NOT NULL", "capability_id TEXT"),
    )
    assert cursor.rowcount == 1
    connection.execute("PRAGMA writable_schema=OFF")
    connection.commit()
    connection.close()

    with pytest.raises(ActionStateConflictError, match="authentication"):
        _store(database)
