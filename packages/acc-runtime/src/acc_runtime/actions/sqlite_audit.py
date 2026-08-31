"""Durable, append-only and authenticated SQLite Action audit journal."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import sqlite3
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from acc_runtime.actions.audit import ActionAuditEvent, ActionAuditUnavailableError
from acc_runtime.actions.models import canonical_json_bytes, finite_time, validate_digest
from acc_runtime.credentials import SecretValue

_APPLICATION_ID = 0x41434355
_SCHEMA_VERSION = 1
_ZERO_MAC = bytes(32)
_EVENT_COLUMNS = (
    "sequence",
    "event_id",
    "occurred_at",
    "event_payload",
    "previous_mac",
    "event_mac",
)
_SCHEMA_STATEMENTS = (
    """CREATE TABLE audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE CHECK(length(event_id)=64),
        occurred_at REAL NOT NULL,
        event_payload BLOB NOT NULL,
        previous_mac BLOB NOT NULL CHECK(length(previous_mac)=32),
        event_mac BLOB NOT NULL CHECK(length(event_mac)=32)
    ) STRICT""",
    """CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END""",
    """CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END""",
    "CREATE TABLE audit_metadata (name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT",
)


@dataclass(frozen=True, slots=True)
class DurableActionAuditRecord:
    """A verified journal entry; MAC fields remain implementation-private."""

    sequence: int
    event: ActionAuditEvent
    chain_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence <= 0
        ):
            raise ValueError("sequence must be a positive integer")
        if not isinstance(self.event, ActionAuditEvent):
            raise TypeError("event must be ActionAuditEvent")
        validate_digest(self.chain_digest, field_name="chain_digest")


class SQLiteActionAuditSink:
    """A platform-neutral reference sink that acknowledges only committed events."""

    is_durable = True
    deployment_safety = "operator_secret_required"

    def __init__(
        self,
        db_path: str | Path,
        *,
        operator_secret: bytes | SecretValue,
        deployment_salt: bytes,
        max_events: int = 1_000_000,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        secret = (
            operator_secret.get_secret_value().encode()
            if isinstance(operator_secret, SecretValue)
            else operator_secret
        )
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("operator_secret must contain at least 32 bytes")
        if not isinstance(deployment_salt, bytes) or len(deployment_salt) < 16:
            raise ValueError("deployment_salt must contain at least 16 bytes")
        if not isinstance(max_events, int) or isinstance(max_events, bool) or max_events <= 0:
            raise ValueError("max_events must be a positive integer")
        if (
            not isinstance(busy_timeout_seconds, (int, float))
            or isinstance(busy_timeout_seconds, bool)
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be positive")
        self._path = _secure_database_path(Path(db_path))
        self._integrity_key = _derive_key(secret, deployment_salt)
        self._max_events = max_events
        self._busy_timeout_ms = max(1, int(float(busy_timeout_seconds) * 1000))
        self._lock = asyncio.Lock()
        self._closed = False
        self._initialize()

    async def emit(self, event: ActionAuditEvent) -> None:
        if not isinstance(event, ActionAuditEvent):
            raise TypeError("event must be ActionAuditEvent")
        payload = canonical_json_bytes(cast(JsonValue, event.to_dict()))
        async with self._lock:
            self._ensure_open()
            try:
                await asyncio.to_thread(self._append_sync, event, payload)
            except asyncio.CancelledError:
                raise
            except ActionAuditUnavailableError:
                raise
            except BaseException:
                raise ActionAuditUnavailableError("Durable Action audit append failed") from None

    async def records(self) -> tuple[DurableActionAuditRecord, ...]:
        async with self._lock:
            self._ensure_open()
            try:
                return await asyncio.to_thread(self._records_sync)
            except ActionAuditUnavailableError:
                raise
            except BaseException:
                raise ActionAuditUnavailableError(
                    "Durable Action audit verification failed"
                ) from None

    async def close(self) -> tuple[DurableActionAuditRecord, ...]:
        async with self._lock:
            if self._closed:
                return ()
            try:
                records = await asyncio.to_thread(self._records_sync)
            except ActionAuditUnavailableError:
                raise
            except BaseException:
                raise ActionAuditUnavailableError(
                    "Durable Action audit verification failed"
                ) from None
            self._closed = True
            return records

    def _initialize(self) -> None:
        try:
            with self._transaction() as connection:
                application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_events'"
                ).fetchone()
                if application_id == 0 and version == 0 and exists is None:
                    connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                    for statement in _SCHEMA_STATEMENTS:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO audit_metadata(name,value) VALUES('schema_mac',?)",
                        (self._schema_mac(connection),),
                    )
                elif application_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
                    raise ActionAuditUnavailableError("Action audit schema version is unsupported")
                self._validate_schema(connection)
                self._verify_chain(connection)
        except ActionAuditUnavailableError:
            raise
        except BaseException:
            raise ActionAuditUnavailableError("Action audit initialization failed") from None

    def _append_sync(self, event: ActionAuditEvent, payload: bytes) -> None:
        with self._transaction() as connection:
            self._validate_schema(connection)
            sequence, previous = self._verify_chain(connection)
            if sequence >= self._max_events:
                raise ActionAuditUnavailableError("Action audit journal is full")
            next_sequence = sequence + 1
            event_mac = self._event_mac(next_sequence, event.event_id, payload, previous)
            connection.execute(
                "INSERT INTO audit_events("
                "event_id,occurred_at,event_payload,previous_mac,event_mac) "
                "VALUES(?,?,?,?,?)",
                (event.event_id, event.occurred_at, payload, previous, event_mac),
            )

    def _records_sync(self) -> tuple[DurableActionAuditRecord, ...]:
        with self._transaction() as connection:
            self._validate_schema(connection)
            self._verify_chain(connection)
            rows = connection.execute(
                "SELECT sequence,event_payload,event_mac FROM audit_events ORDER BY sequence"
            ).fetchall()
            return tuple(
                DurableActionAuditRecord(
                    sequence=int(row["sequence"]),
                    event=_decode_event(bytes(row["event_payload"])),
                    chain_digest=bytes(row["event_mac"]).hex(),
                )
                for row in rows
            )

    def _verify_chain(self, connection: sqlite3.Connection) -> tuple[int, bytes]:
        rows = connection.execute(
            "SELECT sequence,event_id,occurred_at,event_payload,previous_mac,event_mac "
            "FROM audit_events ORDER BY sequence LIMIT ?",
            (self._max_events + 1,),
        ).fetchall()
        if len(rows) > self._max_events:
            raise ActionAuditUnavailableError("Action audit journal exceeds its configured bound")
        previous = _ZERO_MAC
        expected_sequence = 1
        for row in rows:
            payload = bytes(row["event_payload"])
            if (
                int(row["sequence"]) != expected_sequence
                or bytes(row["previous_mac"]) != previous
                or not hmac.compare_digest(
                    bytes(row["event_mac"]),
                    self._event_mac(expected_sequence, row["event_id"], payload, previous),
                )
            ):
                raise ActionAuditUnavailableError("Action audit chain integrity check failed")
            event = _decode_event(payload)
            if event.event_id != row["event_id"] or event.occurred_at != finite_time(
                row["occurred_at"], field_name="occurred_at"
            ):
                raise ActionAuditUnavailableError("Action audit row integrity check failed")
            previous = bytes(row["event_mac"])
            expected_sequence += 1
        return expected_sequence - 1, previous

    def _event_mac(self, sequence: int, event_id: str, payload: bytes, previous: bytes) -> bytes:
        material = canonical_json_bytes(
            {
                "sequence": sequence,
                "event_id": event_id,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "previous_mac": previous.hex(),
            }
        )
        return hmac.new(self._integrity_key, material, hashlib.sha256).digest()

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        objects = connection.execute(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        expected = [
            ("table", "audit_events"),
            ("table", "audit_metadata"),
            ("trigger", "audit_events_no_delete"),
            ("trigger", "audit_events_no_update"),
        ]
        if [(row["type"], row["name"]) for row in objects] != expected:
            raise ActionAuditUnavailableError("Action audit schema is invalid")
        columns = connection.execute("PRAGMA table_info(audit_events)").fetchall()
        if tuple(row["name"] for row in columns) != _EVENT_COLUMNS:
            raise ActionAuditUnavailableError("Action audit schema is invalid")
        metadata = connection.execute(
            "SELECT name,value FROM audit_metadata ORDER BY name"
        ).fetchall()
        if (
            len(metadata) != 1
            or metadata[0]["name"] != "schema_mac"
            or not hmac.compare_digest(bytes(metadata[0]["value"]), self._schema_mac(connection))
        ):
            raise ActionAuditUnavailableError("Action audit schema authentication failed")

    def _schema_mac(self, connection: sqlite3.Connection) -> bytes:
        rows = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        definition = canonical_json_bytes(
            {
                "application_id": _APPLICATION_ID,
                "schema_version": _SCHEMA_VERSION,
                "objects": [[r["type"], r["name"], r["tbl_name"], r["sql"]] for r in rows],
            }
        )
        return hmac.new(self._integrity_key, definition, hashlib.sha256).digest()

    def _connection(self) -> sqlite3.Connection:
        _validate_secure_file(self._path)
        _secure_sidecars(self._path)
        connection = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        _secure_sidecars(self._path)
        return connection

    def _transaction(self) -> _Transaction:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
        except BaseException:
            connection.close()
            raise
        return _Transaction(connection)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ActionAuditUnavailableError("Action audit sink is closed")


class _Transaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> sqlite3.Connection:
        return self._connection

    def __exit__(self, error_type: object, error: object, traceback: object) -> None:
        try:
            self._connection.rollback() if error_type is not None else self._connection.commit()
        finally:
            self._connection.close()


def _decode_event(payload: bytes) -> ActionAuditEvent:
    import json

    try:
        value = json.loads(payload)
        if not isinstance(value, dict) or set(value) != {
            "event_id",
            "occurred_at",
            "lifecycle",
            "capability_id",
            "status",
            "result_category",
            "pack_digest",
            "principal_digest",
            "session_digest",
            "action_digest",
            "approval_decision_id",
        }:
            raise ValueError
        status = value.pop("status")
        from acc_runtime.actions.models import PreparedActionStatus

        value["status"] = None if status is None else PreparedActionStatus(status)
        event = ActionAuditEvent(**value)
        if canonical_json_bytes(cast(JsonValue, event.to_dict())) != payload:
            raise ValueError
        return event
    except (TypeError, UnicodeDecodeError, ValueError):
        raise ActionAuditUnavailableError("Action audit event payload is invalid") from None


def _derive_key(secret: bytes, salt: bytes) -> bytes:
    return hmac.new(
        secret, b"acc-sqlite-action-audit-v1\0" + salt + b"\0integrity", hashlib.sha256
    ).digest()


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _secure_database_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError("Action audit parent directory must already exist")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        if current.is_symlink() or _is_reparse(current) or not current.is_dir():
            raise ValueError("Action audit path cannot traverse links or non-directories")
    if absolute.exists() or absolute.is_symlink():
        _validate_secure_file(absolute)
    else:
        descriptor = os.open(absolute, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        os.chmod(absolute, 0o600)
        _validate_secure_file(absolute)
    return absolute


def _validate_secure_file(path: Path) -> None:
    details = path.lstat()
    if path.is_symlink() or _is_reparse(path) or not stat.S_ISREG(details.st_mode):
        raise ValueError("Action audit database must be a regular non-link file")
    if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Action audit database permissions must be owner-only")


def _secure_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            if sidecar.is_symlink() or _is_reparse(sidecar) or not sidecar.is_file():
                raise ValueError("Action audit SQLite sidecar is unsafe")
            os.chmod(sidecar, 0o600)


__all__ = ["DurableActionAuditRecord", "SQLiteActionAuditSink"]
