"""Durable, one-time external approval authority reference implementation."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from acc_runtime.actions.approval import (
    ApprovalBinding,
    ApprovalGrant,
    _approval_digest,
)
from acc_runtime.actions.errors import (
    ActionApprovalExpiredError,
    ActionApprovalInvalidError,
    ApprovalAuthorityIntegrityError,
)
from acc_runtime.actions.models import canonical_json_bytes, exact_identifier, finite_time
from acc_runtime.credentials import SecretValue

_APPLICATION_ID = 0x41434350
_SCHEMA_VERSION = 1
_MAX_TTL_SECONDS = 900
_COLUMNS = (
    "approval_digest",
    "decision_id",
    "approver_id",
    "action_digest",
    "capability_id",
    "principal_digest",
    "session_digest",
    "pack_digest",
    "input_digest",
    "preview_digest",
    "action_expires_at",
    "approved_at",
    "expires_at",
    "status",
    "consumed_at",
    "revoked_at",
    "revoked_by",
    "row_mac",
)
_COLUMN_LIST = ",".join(_COLUMNS)
_PLACEHOLDERS = ",".join("?" for _ in _COLUMNS)
_SCHEMA = (
    """CREATE TABLE approvals (
        approval_digest TEXT PRIMARY KEY CHECK(length(approval_digest)=64),
        decision_id TEXT NOT NULL UNIQUE,
        approver_id TEXT NOT NULL,
        action_digest TEXT NOT NULL CHECK(length(action_digest)=64),
        capability_id TEXT NOT NULL,
        principal_digest TEXT NOT NULL CHECK(length(principal_digest)=64),
        session_digest TEXT CHECK(session_digest IS NULL OR length(session_digest)=64),
        pack_digest TEXT NOT NULL CHECK(length(pack_digest)=71),
        input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
        preview_digest TEXT NOT NULL CHECK(length(preview_digest)=64),
        action_expires_at REAL NOT NULL,
        approved_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('approved','consumed','revoked','expired')),
        consumed_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        row_mac BLOB NOT NULL CHECK(length(row_mac)=32)
    ) STRICT""",
    "CREATE INDEX approvals_expiry ON approvals(expires_at,status)",
    "CREATE TABLE authority_metadata (name TEXT PRIMARY KEY,value BLOB NOT NULL) STRICT",
)


class ApprovalDecisionStatus(StrEnum):
    APPROVED = "approved"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class ApprovalDecisionRecord:
    """Durable audit fact. Sensitive binding digests stay out of its repr."""

    decision_id: str
    approver_id: str
    binding: ApprovalBinding = field(repr=False)
    approved_at: float
    expires_at: float
    status: ApprovalDecisionStatus
    consumed_at: float | None = None
    revoked_at: float | None = None
    revoked_by: str | None = None

    def __post_init__(self) -> None:
        _audit_identifier(self.decision_id, field_name="decision_id")
        _audit_identifier(self.approver_id, field_name="approver_id")
        approved = finite_time(self.approved_at, field_name="approved_at")
        expires = finite_time(self.expires_at, field_name="expires_at")
        if expires <= approved or expires > self.binding.action_expires_at:
            raise ValueError("approval decision expiry is invalid")
        if not isinstance(self.status, ApprovalDecisionStatus):
            raise TypeError("status must be ApprovalDecisionStatus")
        if self.consumed_at is not None:
            finite_time(self.consumed_at, field_name="consumed_at")
        if self.revoked_at is not None:
            finite_time(self.revoked_at, field_name="revoked_at")
        if self.revoked_by is not None:
            _audit_identifier(self.revoked_by, field_name="revoked_by")
        if self.status is ApprovalDecisionStatus.CONSUMED:
            if self.consumed_at is None or self.revoked_at is not None:
                raise ValueError("consumed approval decision state is invalid")
        elif self.status is ApprovalDecisionStatus.REVOKED:
            if self.revoked_at is None or self.revoked_by is None or self.consumed_at is not None:
                raise ValueError("revoked approval decision state is invalid")
        elif (
            self.consumed_at is not None
            or self.revoked_at is not None
            or self.revoked_by is not None
        ):
            raise ValueError("approval decision terminal fields are invalid")


class SQLiteApprovalAuthority:
    """Operator-side durable authority; issue/revoke stay outside Agent transports."""

    is_durable = True
    max_approval_ttl_seconds = _MAX_TTL_SECONDS

    def __init__(
        self,
        db_path: str | Path,
        *,
        authority_secret: SecretValue,
        deployment_salt: bytes,
        max_decisions: int = 100_000,
        clock: Callable[[], float] = time.time,
        handle_generator: Callable[[], str] | None = None,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not isinstance(authority_secret, SecretValue):
            raise TypeError("authority_secret must be SecretValue")
        raw_secret = authority_secret.get_secret_value().encode()
        if len(raw_secret) < 32:
            raise ValueError("authority_secret must contain at least 32 bytes")
        if not isinstance(deployment_salt, bytes) or len(deployment_salt) < 16:
            raise ValueError("deployment_salt must contain at least 16 bytes")
        if (
            not isinstance(max_decisions, int)
            or isinstance(max_decisions, bool)
            or max_decisions <= 0
        ):
            raise ValueError("max_decisions must be a positive integer")
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be positive")
        self._path = _secure_database_path(Path(db_path))
        self._integrity_key = hmac.new(
            raw_secret,
            b"acc-sqlite-approval-authority-v1\0" + deployment_salt,
            hashlib.sha256,
        ).digest()
        self._max_decisions = max_decisions
        self._clock = clock
        self._handle_generator = handle_generator or (lambda: secrets.token_urlsafe(32))
        self._busy_timeout_ms = max(1, int(float(busy_timeout_seconds) * 1000))
        self._lock = asyncio.Lock()
        self._closed = False
        self._initialize()

    async def issue(
        self,
        binding: ApprovalBinding,
        *,
        decision_id: str,
        approver_id: str,
        expires_in_seconds: int,
    ) -> SecretValue:
        if not isinstance(binding, ApprovalBinding):
            raise TypeError("binding must be ApprovalBinding")
        decision = _audit_identifier(decision_id, field_name="decision_id")
        approver = _audit_identifier(approver_id, field_name="approver_id")
        if (
            not isinstance(expires_in_seconds, int)
            or isinstance(expires_in_seconds, bool)
            or not 1 <= expires_in_seconds <= _MAX_TTL_SECONDS
        ):
            raise ValueError("expires_in_seconds must be between 1 and 900")
        now = finite_time(self._clock(), field_name="clock")
        expires_at = now + expires_in_seconds
        if expires_at > binding.action_expires_at:
            raise ValueError("approval cannot outlive the prepared Action")
        raw_handle = self._handle_generator()
        try:
            digest = _approval_digest(raw_handle)
        except ActionApprovalInvalidError:
            raise ActionApprovalInvalidError("approval handle generation failed") from None
        async with self._lock:
            self._ensure_open()
            await asyncio.to_thread(
                self._issue_sync, digest, decision, approver, binding, now, expires_at
            )
        return SecretValue(raw_handle)

    async def verify(
        self,
        approval_handle: str | SecretValue,
        expected: ApprovalBinding,
    ) -> ApprovalGrant:
        if not isinstance(expected, ApprovalBinding):
            raise TypeError("expected must be ApprovalBinding")
        digest = _approval_digest(approval_handle)
        async with self._lock:
            self._ensure_open()
            record = await asyncio.to_thread(self._verify_sync, digest, expected)
        return ApprovalGrant(
            approval_digest=digest,
            binding=record.binding,
            approved_at=record.approved_at,
            expires_at=record.expires_at,
            decision_id=record.decision_id,
            approver_id=record.approver_id,
        )

    async def revoke(
        self, approval_handle: str | SecretValue, *, revoked_by: str
    ) -> ApprovalDecisionRecord:
        digest = _approval_digest(approval_handle)
        actor = _audit_identifier(revoked_by, field_name="revoked_by")
        async with self._lock:
            self._ensure_open()
            return await asyncio.to_thread(self._revoke_sync, digest, actor)

    async def decision(self, decision_id: str) -> ApprovalDecisionRecord:
        checked = _audit_identifier(decision_id, field_name="decision_id")
        async with self._lock:
            self._ensure_open()
            return await asyncio.to_thread(self._decision_sync, checked)

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    def _initialize(self) -> None:
        with self._transaction() as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='approvals'"
            ).fetchone()
            if application_id == 0 and version == 0 and exists is None:
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                for statement in _SCHEMA:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO authority_metadata(name,value) VALUES('schema_mac',?)",
                    (self._schema_mac(connection),),
                )
            elif application_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
                raise ApprovalAuthorityIntegrityError("Approval Authority schema is unsupported")
            self._validate_schema(connection)

    def _issue_sync(
        self,
        digest: str,
        decision_id: str,
        approver_id: str,
        binding: ApprovalBinding,
        approved_at: float,
        expires_at: float,
    ) -> None:
        record = ApprovalDecisionRecord(
            decision_id=decision_id,
            approver_id=approver_id,
            binding=binding,
            approved_at=approved_at,
            expires_at=expires_at,
            status=ApprovalDecisionStatus.APPROVED,
        )
        values = self._row_values(digest, record)
        try:
            with self._transaction() as connection:
                self._expire(connection, approved_at)
                count = int(connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
                if count >= self._max_decisions:
                    raise ActionApprovalInvalidError("approval decision capacity is exhausted")
                connection.execute(
                    f"INSERT INTO approvals ({_COLUMN_LIST}) VALUES ({_PLACEHOLDERS})",
                    (*values, self._row_mac(values)),
                )
        except sqlite3.IntegrityError:
            raise ActionApprovalInvalidError("approval decision is not unique") from None

    def _verify_sync(self, digest: str, expected: ApprovalBinding) -> ApprovalDecisionRecord:
        consumed: ApprovalDecisionRecord | None = None
        expired = False
        with self._transaction() as connection:
            row = self._row_by_digest(connection, digest)
            record = self._decode(row)
            now = finite_time(self._clock(), field_name="clock")
            if record.status is ApprovalDecisionStatus.APPROVED and (
                now >= record.expires_at or now >= record.binding.action_expires_at
            ):
                record = self._replace_status(record, ApprovalDecisionStatus.EXPIRED)
                self._update(connection, digest, record)
                expired = True
            elif record.binding != expected or record.status is not ApprovalDecisionStatus.APPROVED:
                raise ActionApprovalInvalidError("approval is invalid")
            else:
                consumed = self._replace_status(
                    record, ApprovalDecisionStatus.CONSUMED, consumed_at=now
                )
                self._update(connection, digest, consumed)
        if expired:
            raise ActionApprovalExpiredError("approval has expired")
        if consumed is None:  # pragma: no cover - defensive transaction invariant
            raise ApprovalAuthorityIntegrityError("Approval Authority transition failed")
        return consumed

    def _revoke_sync(self, digest: str, revoked_by: str) -> ApprovalDecisionRecord:
        with self._transaction() as connection:
            record = self._decode(self._row_by_digest(connection, digest))
            now = finite_time(self._clock(), field_name="clock")
            if record.status is not ApprovalDecisionStatus.APPROVED:
                raise ActionApprovalInvalidError("approval is invalid")
            revoked = self._replace_status(
                record, ApprovalDecisionStatus.REVOKED, revoked_at=now, revoked_by=revoked_by
            )
            self._update(connection, digest, revoked)
            return revoked

    def _decision_sync(self, decision_id: str) -> ApprovalDecisionRecord:
        with self._transaction() as connection:
            row = cast(
                sqlite3.Row | None,
                connection.execute(
                    f"SELECT {_COLUMN_LIST} FROM approvals WHERE decision_id=?", (decision_id,)
                ).fetchone(),
            )
            if row is None:
                raise ActionApprovalInvalidError("approval decision was not found")
            return self._decode(row)

    def _expire(self, connection: sqlite3.Connection, now: float) -> None:
        rows = connection.execute(
            f"SELECT {_COLUMN_LIST} FROM approvals WHERE status='approved' AND expires_at<=?",
            (now,),
        ).fetchall()
        for row in rows:
            record = self._decode(row)
            self._update(
                connection,
                row["approval_digest"],
                self._replace_status(record, ApprovalDecisionStatus.EXPIRED),
            )

    def _row_by_digest(self, connection: sqlite3.Connection, digest: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                f"SELECT {_COLUMN_LIST} FROM approvals WHERE approval_digest=?", (digest,)
            ).fetchone(),
        )
        if row is None:
            raise ActionApprovalInvalidError("approval is invalid")
        self._verify_row(row)
        return row

    def _decode(self, row: sqlite3.Row) -> ApprovalDecisionRecord:
        self._verify_row(row)
        try:
            binding = ApprovalBinding(
                action_digest=row["action_digest"],
                capability_id=row["capability_id"],
                principal_digest=row["principal_digest"],
                session_digest=row["session_digest"],
                pack_digest=row["pack_digest"],
                input_digest=row["input_digest"],
                preview_digest=row["preview_digest"],
                action_expires_at=row["action_expires_at"],
            )
            return ApprovalDecisionRecord(
                decision_id=_audit_identifier(row["decision_id"], field_name="decision_id"),
                approver_id=_audit_identifier(row["approver_id"], field_name="approver_id"),
                binding=binding,
                approved_at=finite_time(row["approved_at"], field_name="approved_at"),
                expires_at=finite_time(row["expires_at"], field_name="expires_at"),
                status=ApprovalDecisionStatus(row["status"]),
                consumed_at=(
                    None
                    if row["consumed_at"] is None
                    else finite_time(row["consumed_at"], field_name="consumed_at")
                ),
                revoked_at=(
                    None
                    if row["revoked_at"] is None
                    else finite_time(row["revoked_at"], field_name="revoked_at")
                ),
                revoked_by=(
                    None
                    if row["revoked_by"] is None
                    else _audit_identifier(row["revoked_by"], field_name="revoked_by")
                ),
            )
        except (TypeError, ValueError):
            raise ApprovalAuthorityIntegrityError("Approval Authority row is invalid") from None

    @staticmethod
    def _replace_status(
        record: ApprovalDecisionRecord,
        status: ApprovalDecisionStatus,
        *,
        consumed_at: float | None = None,
        revoked_at: float | None = None,
        revoked_by: str | None = None,
    ) -> ApprovalDecisionRecord:
        return ApprovalDecisionRecord(
            decision_id=record.decision_id,
            approver_id=record.approver_id,
            binding=record.binding,
            approved_at=record.approved_at,
            expires_at=record.expires_at,
            status=status,
            consumed_at=consumed_at,
            revoked_at=revoked_at,
            revoked_by=revoked_by,
        )

    @staticmethod
    def _row_values(digest: str, record: ApprovalDecisionRecord) -> tuple[object, ...]:
        binding = record.binding
        return (
            digest,
            record.decision_id,
            record.approver_id,
            binding.action_digest,
            binding.capability_id,
            binding.principal_digest,
            binding.session_digest,
            binding.pack_digest,
            binding.input_digest,
            binding.preview_digest,
            binding.action_expires_at,
            record.approved_at,
            record.expires_at,
            record.status.value,
            record.consumed_at,
            record.revoked_at,
            record.revoked_by,
        )

    def _update(
        self, connection: sqlite3.Connection, digest: str, record: ApprovalDecisionRecord
    ) -> None:
        values = self._row_values(digest, record)
        assignments = ",".join(f"{name}=?" for name in _COLUMNS[1:])
        connection.execute(
            f"UPDATE approvals SET {assignments} WHERE approval_digest=?",
            (*values[1:], self._row_mac(values), digest),
        )

    def _verify_row(self, row: sqlite3.Row) -> None:
        values = tuple(row[name] for name in _COLUMNS[:-1])
        if not hmac.compare_digest(bytes(row["row_mac"]), self._row_mac(values)):
            raise ApprovalAuthorityIntegrityError("Approval Authority row authentication failed")

    def _row_mac(self, values: tuple[object, ...]) -> bytes:
        serializable = cast(JsonValue, list(values))
        return hmac.new(
            self._integrity_key, canonical_json_bytes(serializable), hashlib.sha256
        ).digest()

    def _connection(self) -> sqlite3.Connection:
        _validate_secure_file(self._path)
        _secure_sidecars(self._path)
        connection = sqlite3.connect(
            self._path, timeout=self._busy_timeout_ms / 1000, isolation_level=None
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

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        objects = connection.execute(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        if [(row["type"], row["name"]) for row in objects] != [
            ("index", "approvals_expiry"),
            ("table", "approvals"),
            ("table", "authority_metadata"),
        ]:
            raise ApprovalAuthorityIntegrityError("Approval Authority schema is invalid")
        columns = connection.execute("PRAGMA table_info(approvals)").fetchall()
        if tuple(row["name"] for row in columns) != _COLUMNS:
            raise ApprovalAuthorityIntegrityError("Approval Authority schema is invalid")
        metadata = connection.execute(
            "SELECT name,value FROM authority_metadata ORDER BY name"
        ).fetchall()
        if (
            len(metadata) != 1
            or metadata[0]["name"] != "schema_mac"
            or not hmac.compare_digest(bytes(metadata[0]["value"]), self._schema_mac(connection))
        ):
            raise ApprovalAuthorityIntegrityError("Approval Authority schema authentication failed")

    def _schema_mac(self, connection: sqlite3.Connection) -> bytes:
        rows = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        payload: JsonValue = {
            "application_id": _APPLICATION_ID,
            "schema_version": _SCHEMA_VERSION,
            "objects": [[row["type"], row["name"], row["tbl_name"], row["sql"]] for row in rows],
        }
        return hmac.new(self._integrity_key, canonical_json_bytes(payload), hashlib.sha256).digest()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ActionApprovalInvalidError("approval authority is closed")


class _Transaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> sqlite3.Connection:
        return self._connection

    def __exit__(self, kind: object, error: object, traceback: object) -> None:
        try:
            self._connection.rollback() if kind is not None else self._connection.commit()
        finally:
            self._connection.close()


def _audit_identifier(value: object, *, field_name: str) -> str:
    checked = exact_identifier(value, field_name=field_name)
    if len(checked.encode("utf-8")) > 256:
        raise ValueError(f"{field_name} cannot exceed 256 UTF-8 bytes")
    return checked


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _secure_database_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError("Approval Authority parent directory must already exist")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        if current.is_symlink() or _is_reparse(current) or not current.is_dir():
            raise ValueError("Approval Authority path cannot traverse links or non-directories")
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
        raise ValueError("Approval Authority database must be a regular non-link file")
    if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Approval Authority database permissions must be owner-only")


def _secure_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            if sidecar.is_symlink() or _is_reparse(sidecar) or not sidecar.is_file():
                raise ValueError("Approval Authority SQLite sidecar is unsafe")
            os.chmod(sidecar, 0o600)


__all__ = [
    "ApprovalDecisionRecord",
    "ApprovalDecisionStatus",
    "SQLiteApprovalAuthority",
]
