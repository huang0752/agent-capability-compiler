"""Durable SQLite-backed Action state with authenticated persisted rows."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

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
    canonical_json_bytes,
    exact_identifier,
    finite_time,
    validate_pack_digest,
)
from acc_runtime.credentials import SecretValue

_HANDLE = re.compile(r"^[A-Za-z0-9_-]{43,}$")
_APPLICATION_ID = 0x41434341
_SCHEMA_VERSION = 1
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
_EXPECTED_COLUMNS = (
    "handle_digest",
    "capability_id",
    "principal_digest",
    "session_digest",
    "pack_digest",
    "input_digest",
    "preview_digest",
    "created_at",
    "expires_at",
    "status",
    "input_payload",
    "preview_payload",
    "result_payload",
    "row_mac",
)
_SCHEMA_STATEMENTS = (
    """CREATE TABLE actions (
        handle_digest TEXT PRIMARY KEY CHECK(length(handle_digest)=64),
        capability_id TEXT NOT NULL,
        principal_digest TEXT NOT NULL CHECK(length(principal_digest)=64),
        session_digest TEXT CHECK(session_digest IS NULL OR length(session_digest)=64),
        pack_digest TEXT NOT NULL CHECK(length(pack_digest)=71),
        input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
        preview_digest TEXT NOT NULL CHECK(length(preview_digest)=64),
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        status TEXT NOT NULL CHECK(status IN (
            'prepared','approved','committing','succeeded','failed',
            'outcome_unknown','expired'
        )),
        input_payload BLOB NOT NULL,
        preview_payload BLOB NOT NULL,
        result_payload BLOB,
        row_mac BLOB NOT NULL CHECK(length(row_mac)=32)
    ) STRICT""",
    "CREATE INDEX actions_expiry ON actions(expires_at, status)",
    "CREATE TABLE store_metadata (name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT",
)
_COLUMN_LIST = ",".join(_EXPECTED_COLUMNS)
_UPDATE_ASSIGNMENTS = ",".join(f"{name}=?" for name in _EXPECTED_COLUMNS[1:])
_INSERT_PLACEHOLDERS = ",".join("?" for _ in _EXPECTED_COLUMNS)


class SQLiteActionStore:
    """Restart-safe Action Store using authenticated rows and SQLite CAS transitions."""

    is_durable = True
    deployment_safety = "operator_secret_required"

    def __init__(
        self,
        db_path: str | Path,
        *,
        operator_secret: bytes | SecretValue,
        deployment_salt: bytes,
        max_actions: int = 100_000,
        clock: Callable[[], float] = time.time,
        handle_generator: Callable[[], str] | None = None,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        raw_secret = (
            operator_secret.get_secret_value().encode()
            if isinstance(operator_secret, SecretValue)
            else operator_secret
        )
        if not isinstance(raw_secret, bytes) or len(raw_secret) < 32:
            raise ValueError("operator_secret must contain at least 32 bytes")
        if not isinstance(deployment_salt, bytes) or len(deployment_salt) < 16:
            raise ValueError("deployment_salt must contain at least 16 bytes")
        if not isinstance(max_actions, int) or isinstance(max_actions, bool) or max_actions <= 0:
            raise ValueError("max_actions must be a positive integer")
        if (
            not isinstance(busy_timeout_seconds, (int, float))
            or isinstance(busy_timeout_seconds, bool)
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be positive")
        self._path = _secure_database_path(Path(db_path))
        self._binding_key = _derive_key(raw_secret, deployment_salt, b"binding-v1")
        self._integrity_key = _derive_key(raw_secret, deployment_salt, b"integrity-v1")
        self._max_actions = max_actions
        self._clock = clock
        self._handle_generator = handle_generator or _random_handle
        self._busy_timeout_ms = max(1, int(float(busy_timeout_seconds) * 1000))
        self._closed = False
        self._instance_lock = asyncio.Lock()
        self._initialize()

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
        async with self._instance_lock:
            self._ensure_open()
            state = await asyncio.to_thread(
                self._create_sync,
                raw_handle,
                checked_capability,
                checked_principal,
                checked_session,
                pack_digest,
                input_bytes,
                preview_bytes,
                expires_in_seconds,
            )
        return PreparedActionCreation(handle=SecretValue(raw_handle), state=state)

    async def resolve(
        self,
        handle: str | SecretValue,
        *,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
    ) -> PreparedActionState:
        digest = _handle_digest(handle)
        bindings = self._checked_bindings(principal_id, session_id, pack_digest)
        async with self._instance_lock:
            self._ensure_open()
            return await asyncio.to_thread(self._resolve_sync, digest, *bindings)

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
        if target not in _ALLOWED_TRANSITIONS.get(expected, frozenset()):
            raise ActionStateConflictError("Action state transition conflicts")
        if target is not PreparedActionStatus.SUCCEEDED and result_value is not None:
            raise ActionStateConflictError("Only a successful Action can persist a result")
        digest = _handle_digest(handle)
        bindings = self._checked_bindings(principal_id, session_id, pack_digest)
        result_bytes = (
            canonical_json_bytes(result_value) if target is PreparedActionStatus.SUCCEEDED else None
        )
        async with self._instance_lock:
            self._ensure_open()
            return await asyncio.to_thread(
                self._transition_sync,
                digest,
                *bindings,
                expected,
                target,
                result_bytes,
            )

    async def close(self) -> tuple[PreparedActionRecord, ...]:
        async with self._instance_lock:
            if self._closed:
                return ()
            records = await asyncio.to_thread(self._records_sync)
            self._closed = True
            return records

    def _initialize(self) -> None:
        with self._transaction() as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            table_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='actions'"
            ).fetchone()
            if application_id == 0 and version == 0 and table_exists is None:
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                for statement in _SCHEMA_STATEMENTS:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO store_metadata(name,value) VALUES('schema_mac',?)",
                    (self._schema_mac(connection),),
                )
            elif application_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
                raise ActionStateConflictError("Action Store schema version is unsupported")
            self._validate_schema(connection)

    def _create_sync(
        self,
        raw_handle: str,
        capability_id: str,
        principal_id: str,
        session_id: str | None,
        pack_digest: str,
        input_bytes: bytes,
        preview_bytes: bytes,
        expires_in_seconds: int,
    ) -> PreparedActionState:
        now = finite_time(self._clock(), field_name="clock")
        handle_digest = hashlib.sha256(raw_handle.encode("ascii")).hexdigest()
        record = PreparedActionRecord(
            handle_digest=handle_digest,
            capability_id=capability_id,
            principal_digest=self._binding_digest(principal_id, b"principal"),
            session_digest=(
                None if session_id is None else self._binding_digest(session_id, b"session")
            ),
            pack_digest=pack_digest,
            input_digest=hashlib.sha256(input_bytes).hexdigest(),
            preview_digest=hashlib.sha256(preview_bytes).hexdigest(),
            created_at=now,
            expires_at=now + expires_in_seconds,
            status=PreparedActionStatus.PREPARED,
        )
        row = _row_values(record, input_bytes, preview_bytes, None)
        mac = self._row_mac(row)
        try:
            with self._transaction() as connection:
                self._expire(connection, now)
                count = int(connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0])
                if count >= self._max_actions:
                    raise ActionStateConflictError("Action Store cannot create a new state")
                connection.execute(
                    f"INSERT INTO actions ({_COLUMN_LIST}) VALUES ({_INSERT_PLACEHOLDERS})",
                    (*row, mac),
                )
        except sqlite3.IntegrityError:
            raise ActionStateConflictError("Action Store cannot create a new state") from None
        return PreparedActionState(
            record=record,
            input_value=json.loads(input_bytes),
            preview_value=json.loads(preview_bytes),
            result_value=None,
        )

    def _resolve_sync(
        self,
        digest: str,
        principal_digest: str,
        session_digest: str | None,
        pack_digest: str,
    ) -> PreparedActionState:
        resolved: PreparedActionState | None = None
        expired = False
        with self._transaction() as connection:
            row = self._bound_row(connection, digest, principal_digest, session_digest, pack_digest)
            record, input_bytes, preview_bytes, result_bytes = self._decode_row(row)
            now = finite_time(self._clock(), field_name="clock")
            if now >= record.expires_at or record.status is PreparedActionStatus.EXPIRED:
                expired_record = replace(record, status=PreparedActionStatus.EXPIRED)
                self._update_row(
                    connection, expired_record, input_bytes, preview_bytes, result_bytes
                )
                expired = True
            else:
                resolved = _state(record, input_bytes, preview_bytes, result_bytes)
        if expired:
            raise ActionExpiredError("Prepared Action has expired")
        if resolved is None:  # pragma: no cover - defensive invariant
            raise ActionStateConflictError("Action Store state is invalid")
        return resolved

    def _transition_sync(
        self,
        digest: str,
        principal_digest: str,
        session_digest: str | None,
        pack_digest: str,
        expected: PreparedActionStatus,
        target: PreparedActionStatus,
        result_bytes: bytes | None,
    ) -> PreparedActionState:
        transitioned: PreparedActionState | None = None
        expired = False
        with self._transaction() as connection:
            row = self._bound_row(connection, digest, principal_digest, session_digest, pack_digest)
            record, input_bytes, preview_bytes, existing_result = self._decode_row(row)
            now = finite_time(self._clock(), field_name="clock")
            if now >= record.expires_at or record.status is PreparedActionStatus.EXPIRED:
                expired_record = replace(record, status=PreparedActionStatus.EXPIRED)
                self._update_row(
                    connection,
                    expired_record,
                    input_bytes,
                    preview_bytes,
                    existing_result,
                )
                expired = True
            elif record.status is not expected:
                raise ActionStateConflictError("Action state transition conflicts")
            else:
                persisted_result = (
                    result_bytes if target is PreparedActionStatus.SUCCEEDED else existing_result
                )
                updated = replace(record, status=target)
                values = _row_values(updated, input_bytes, preview_bytes, persisted_result)
                cursor = connection.execute(
                    f"UPDATE actions SET {_UPDATE_ASSIGNMENTS} WHERE handle_digest=? AND status=?",
                    (*values[1:], self._row_mac(values), digest, expected.value),
                )
                if cursor.rowcount != 1:
                    raise ActionStateConflictError("Action state transition conflicts")
                transitioned = _state(updated, input_bytes, preview_bytes, persisted_result)
        if expired:
            raise ActionExpiredError("Prepared Action has expired")
        if transitioned is None:  # pragma: no cover - defensive invariant
            raise ActionStateConflictError("Action Store state is invalid")
        return transitioned

    def _records_sync(self) -> tuple[PreparedActionRecord, ...]:
        records: list[PreparedActionRecord] = []
        with self._transaction() as connection:
            cursor = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM actions ORDER BY handle_digest LIMIT ?",
                (self._max_actions + 1,),
            )
            for index, row in enumerate(cursor):
                if index >= self._max_actions:
                    raise ActionStateConflictError("Action Store contains too many states")
                # Verify and decode one row at a time.  Payload BLOBs remain
                # bounded by the per-record schemas and are released before
                # SQLite advances, while only payload-free records accumulate.
                records.append(self._decode_row(row)[0])
        return tuple(records)

    def _checked_bindings(
        self, principal_id: str, session_id: str | None, pack_digest: str
    ) -> tuple[str, str | None, str]:
        principal = exact_identifier(principal_id, field_name="principal_id")
        session = (
            None if session_id is None else exact_identifier(session_id, field_name="session_id")
        )
        validate_pack_digest(pack_digest)
        return (
            self._binding_digest(principal, b"principal"),
            None if session is None else self._binding_digest(session, b"session"),
            pack_digest,
        )

    def _bound_row(
        self,
        connection: sqlite3.Connection,
        digest: str,
        principal_digest: str,
        session_digest: str | None,
        pack_digest: str,
    ) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                f"SELECT {_COLUMN_LIST} FROM actions WHERE handle_digest=?",
                (digest,),
            ).fetchone(),
        )
        if row is None:
            raise ActionHandleInvalidError("Action handle is invalid")
        self._verify_row(row)
        if (
            row["principal_digest"] != principal_digest
            or row["session_digest"] != session_digest
            or row["pack_digest"] != pack_digest
        ):
            raise ActionBindingMismatchError("Action binding does not match")
        return row

    def _decode_row(
        self, row: sqlite3.Row
    ) -> tuple[PreparedActionRecord, bytes, bytes, bytes | None]:
        self._verify_row(row)
        input_bytes = bytes(row["input_payload"])
        preview_bytes = bytes(row["preview_payload"])
        result_bytes = None if row["result_payload"] is None else bytes(row["result_payload"])
        try:
            input_value = json.loads(input_bytes)
            preview_value = json.loads(preview_bytes)
            result_value = None if result_bytes is None else json.loads(result_bytes)
            record = PreparedActionRecord(
                handle_digest=row["handle_digest"],
                capability_id=row["capability_id"],
                principal_digest=row["principal_digest"],
                session_digest=row["session_digest"],
                pack_digest=row["pack_digest"],
                input_digest=row["input_digest"],
                preview_digest=row["preview_digest"],
                created_at=finite_time(row["created_at"], field_name="created_at"),
                expires_at=finite_time(row["expires_at"], field_name="expires_at"),
                status=PreparedActionStatus(row["status"]),
            )
            if (
                canonical_json_bytes(input_value) != input_bytes
                or canonical_json_bytes(preview_value) != preview_bytes
                or (result_bytes is not None and canonical_json_bytes(result_value) != result_bytes)
                or hashlib.sha256(input_bytes).hexdigest() != row["input_digest"]
                or hashlib.sha256(preview_bytes).hexdigest() != row["preview_digest"]
            ):
                raise ValueError("non-canonical Action Store payload")
        except (TypeError, ValueError):
            raise ActionStateConflictError("Action Store row integrity check failed") from None
        return record, input_bytes, preview_bytes, result_bytes

    def _verify_row(self, row: sqlite3.Row) -> None:
        values = tuple(row[name] for name in _EXPECTED_COLUMNS[:-1])
        if not hmac.compare_digest(bytes(row["row_mac"]), self._row_mac(values)):
            raise ActionStateConflictError("Action Store row integrity check failed")

    def _update_row(
        self,
        connection: sqlite3.Connection,
        record: PreparedActionRecord,
        input_bytes: bytes,
        preview_bytes: bytes,
        result_bytes: bytes | None,
    ) -> None:
        values = _row_values(record, input_bytes, preview_bytes, result_bytes)
        connection.execute(
            f"UPDATE actions SET {_UPDATE_ASSIGNMENTS} WHERE handle_digest=?",
            (*values[1:], self._row_mac(values), record.handle_digest),
        )

    def _expire(self, connection: sqlite3.Connection, now: float) -> None:
        rows = connection.execute(
            f"SELECT {_COLUMN_LIST} FROM actions WHERE expires_at<=? AND status!='expired'",
            (now,),
        ).fetchall()
        for row in rows:
            record, input_bytes, preview_bytes, result_bytes = self._decode_row(row)
            self._update_row(
                connection,
                replace(record, status=PreparedActionStatus.EXPIRED),
                input_bytes,
                preview_bytes,
                result_bytes,
            )

    def _binding_digest(self, value: str, namespace: bytes) -> str:
        return hmac.new(
            self._binding_key, namespace + b"\0" + value.encode(), hashlib.sha256
        ).hexdigest()

    def _row_mac(self, values: tuple[object, ...]) -> bytes:
        encoded = canonical_json_bytes([_mac_value(value) for value in values])
        return hmac.new(self._integrity_key, encoded, hashlib.sha256).digest()

    def _connection(self) -> sqlite3.Connection:
        _validate_secure_file(self._path)
        _secure_sqlite_sidecars(self._path)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            _secure_sqlite_sidecars(self._path)
            return connection
        except sqlite3.OperationalError as exc:
            if connection is not None:
                connection.close()
            if _is_lock_error(exc):
                raise ActionStateConflictError("Action Store is locked") from exc
            raise

    def _transaction(self) -> _TransactionConnection:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            connection.close()
            if _is_lock_error(exc):
                raise ActionStateConflictError("Action Store is locked") from exc
            raise
        return _TransactionConnection(connection)

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        objects = connection.execute(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        if [(row["type"], row["name"]) for row in objects] != [
            ("index", "actions_expiry"),
            ("table", "actions"),
            ("table", "store_metadata"),
        ]:
            raise ActionStateConflictError("Action Store schema is invalid")
        columns = connection.execute("PRAGMA table_info(actions)").fetchall()
        if tuple(row["name"] for row in columns) != _EXPECTED_COLUMNS:
            raise ActionStateConflictError("Action Store schema is invalid")
        metadata_columns = connection.execute("PRAGMA table_info(store_metadata)").fetchall()
        if tuple(row["name"] for row in metadata_columns) != ("name", "value"):
            raise ActionStateConflictError("Action Store schema is invalid")
        metadata = connection.execute(
            "SELECT name,value FROM store_metadata ORDER BY name"
        ).fetchall()
        if (
            len(metadata) != 1
            or metadata[0]["name"] != "schema_mac"
            or not hmac.compare_digest(bytes(metadata[0]["value"]), self._schema_mac(connection))
        ):
            raise ActionStateConflictError("Action Store schema authentication failed")

    def _schema_mac(self, connection: sqlite3.Connection) -> bytes:
        objects = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        definition = canonical_json_bytes(
            {
                "application_id": _APPLICATION_ID,
                "schema_version": _SCHEMA_VERSION,
                "objects": [
                    [row["type"], row["name"], row["tbl_name"], row["sql"]] for row in objects
                ],
            }
        )
        return hmac.new(self._integrity_key, definition, hashlib.sha256).digest()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ActionHandleInvalidError("Action handle is invalid")


class _TransactionConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> sqlite3.Connection:
        return self._connection

    def __exit__(self, error_type: object, error: object, traceback: object) -> None:
        try:
            self._connection.rollback() if error_type is not None else self._connection.commit()
        finally:
            self._connection.close()


def _derive_key(secret: bytes, salt: bytes, purpose: bytes) -> bytes:
    return hmac.new(
        secret, b"acc-sqlite-action-store-v1\0" + salt + b"\0" + purpose, hashlib.sha256
    ).digest()


def _is_lock_error(error: sqlite3.OperationalError) -> bool:
    message = str(error).lower()
    return "locked" in message or "busy" in message


def _random_handle() -> str:
    import secrets

    return secrets.token_urlsafe(32)


def _handle_digest(handle: str | SecretValue) -> str:
    raw: object = handle.get_secret_value() if isinstance(handle, SecretValue) else handle
    if not isinstance(raw, str) or _HANDLE.fullmatch(raw) is None:
        raise ActionHandleInvalidError("Action handle is invalid")
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _row_values(
    record: PreparedActionRecord,
    input_bytes: bytes,
    preview_bytes: bytes,
    result_bytes: bytes | None,
) -> tuple[object, ...]:
    return (
        record.handle_digest,
        record.capability_id,
        record.principal_digest,
        record.session_digest,
        record.pack_digest,
        record.input_digest,
        record.preview_digest,
        record.created_at,
        record.expires_at,
        record.status.value,
        input_bytes,
        preview_bytes,
        result_bytes,
    )


def _state(
    record: PreparedActionRecord,
    input_bytes: bytes,
    preview_bytes: bytes,
    result_bytes: bytes | None,
) -> PreparedActionState:
    return PreparedActionState(
        record=record,
        input_value=json.loads(input_bytes),
        preview_value=json.loads(preview_bytes),
        result_value=None if result_bytes is None else json.loads(result_bytes),
    )


def _mac_value(value: object) -> JsonValue:
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("unsupported SQLite Action Store MAC value")


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def _secure_database_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError("Action Store parent directory must already exist")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        if current.is_symlink() or _is_reparse(current) or not current.is_dir():
            raise ValueError("Action Store path cannot traverse links or non-directories")
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
        raise ValueError("Action Store database must be a regular non-link file")
    if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Action Store database permissions must be owner-only")


def _secure_sqlite_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            if sidecar.is_symlink() or _is_reparse(sidecar) or not sidecar.is_file():
                raise ValueError("Action Store SQLite sidecar is unsafe")
            os.chmod(sidecar, 0o600)


__all__ = ["SQLiteActionStore"]
