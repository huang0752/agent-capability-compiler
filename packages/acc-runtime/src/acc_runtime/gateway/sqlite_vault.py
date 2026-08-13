"""Encrypted, single-node SQLite persistence for Gateway sessions."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import JsonValue

from acc_runtime.auth import AuthenticationResult
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway.models import (
    GatewaySessionCreation,
    GatewaySessionRecord,
    GatewaySessionStatus,
)
from acc_runtime.gateway.sessions import (
    GatewayReauthRequiredError,
    GatewaySessionInvalidError,
    InMemoryGatewaySessionStore,
)

_APPLICATION_ID = 0x41434347
_SCHEMA_VERSION = 1
_CHECK_AAD = b"acc-gateway-session-vault-check-v1"
_EXPECTED_COLUMNS = ("token_digest", "session_digest", "nonce", "ciphertext")


@dataclass(frozen=True, slots=True, repr=False)
class GatewaySessionVaultConfig:
    """Secret-bearing deployment input; never serialized into runtime metadata."""

    db_path: str | Path
    kek: SecretValue
    deployment_salt: bytes


class SQLiteGatewaySessionVault:
    """AEAD-protected Gateway Session Store for one process and one SQLite file."""

    is_durable = True

    def __init__(
        self,
        db_path: str | Path,
        *,
        project_id: str,
        pack_sha256: str,
        scope_mapping_sha256: str,
        scope_ceiling_sha256: str,
        kek: SecretValue,
        deployment_salt: bytes,
        max_sessions: int,
        ttl_seconds: int,
        clock: Callable[[], float] = time.time,
        token_generator: Callable[[], str] | None = None,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not isinstance(kek, SecretValue):
            raise TypeError("kek must be a SecretValue")
        raw_kek = kek.get_secret_value().encode("utf-8")
        if len(raw_kek) < 32:
            raise ValueError("kek must contain at least 32 bytes")
        if not isinstance(deployment_salt, bytes) or len(deployment_salt) < 16:
            raise ValueError("deployment_salt must contain at least 16 bytes")
        if not isinstance(project_id, str) or not project_id.strip():
            raise ValueError("project_id must be nonempty")
        if (
            not isinstance(busy_timeout_seconds, (int, float))
            or isinstance(busy_timeout_seconds, bool)
            or not math.isfinite(float(busy_timeout_seconds))
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be positive")
        self._path = _secure_database_path(Path(db_path))
        self._project_id = project_id
        if any(
            len(value) != 64 for value in (pack_sha256, scope_mapping_sha256, scope_ceiling_sha256)
        ):
            raise ValueError("Deployment binding digests must be SHA-256 hex values")
        self._pack_sha256 = pack_sha256
        self._scope_mapping_sha256 = scope_mapping_sha256
        self._scope_ceiling_sha256 = scope_ceiling_sha256
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=deployment_salt,
            info=b"acc-gateway-session-vault-aead-v1",
        ).derive(raw_kek)
        self._index_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=deployment_salt,
            info=b"acc-gateway-session-vault-index-v1",
        ).derive(raw_kek)
        self._aead = AESGCM(self._key)
        self._clock = clock
        self._busy_timeout_ms = max(1, int(float(busy_timeout_seconds) * 1000))
        self._inner = InMemoryGatewaySessionStore(
            max_sessions=max_sessions,
            ttl_seconds=ttl_seconds,
            clock=clock,
            token_generator=token_generator,
        )
        self._lock = asyncio.Lock()
        self._closed = False
        self._restored = self._initialize_and_load()
        raw_kek = b""

    async def restore_authentications(
        self,
    ) -> tuple[tuple[GatewaySessionRecord, AuthenticationResult], ...]:
        async with self._lock:
            self._ensure_open()
            restored = self._restored
            self._restored = ()
            for record, _ in restored:
                await self._inner.restore_record(record)
            return restored

    async def create(
        self,
        *,
        session_id: str,
        principal_context: PrincipalContext,
        source_expires_at: float | None = None,
        source_refresh_at: float | None = None,
        authentication: AuthenticationResult | None = None,
    ) -> GatewaySessionCreation:
        if not isinstance(authentication, AuthenticationResult):
            raise GatewaySessionInvalidError("Durable Gateway session authentication is missing.")
        async with self._lock:
            self._ensure_open()
            creation = await self._inner.create(
                session_id=session_id,
                principal_context=principal_context,
                source_expires_at=source_expires_at,
                source_refresh_at=source_refresh_at,
            )
            try:
                await asyncio.to_thread(self._insert_sync, creation.record, authentication)
            except BaseException:
                await self._inner.revoke_session(session_id)
                raise
            return creation

    async def resolve_token(self, token: str | SecretValue) -> GatewaySessionRecord:
        async with self._lock:
            self._ensure_open()
            try:
                return await self._inner.resolve_token(token)
            except GatewayReauthRequiredError:
                await asyncio.to_thread(self._persist_reauth_token_sync, token)
                raise

    async def resolve_session_id(self, session_id: str) -> GatewaySessionRecord:
        async with self._lock:
            self._ensure_open()
            try:
                return await self._inner.resolve_session_id(session_id)
            except GatewayReauthRequiredError:
                await asyncio.to_thread(self._persist_reauth_session_sync, session_id)
                raise

    def session_digest(self, session_id: str) -> str:
        """Return the keyed, deployment-bound session index used by operator registries."""

        if not isinstance(session_id, str) or not session_id:
            raise GatewaySessionInvalidError("Gateway session is invalid.")
        self._ensure_open()
        return self._session_digest(session_id)

    async def resolve_session_digest(self, digest: str) -> GatewaySessionRecord:
        """Resolve only a registry-bound keyed digest, never an unbound identifier."""

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise GatewaySessionInvalidError("Gateway session is invalid.")
        async with self._lock:
            self._ensure_open()
            record = await asyncio.to_thread(self._record_by_session_digest_sync, digest)
            return await self._inner.resolve_session_id(record.session_id)

    async def revoke(self, session_id: str) -> GatewaySessionRecord | None:
        return await self.revoke_session(session_id)

    async def revoke_session(self, session_id: str) -> GatewaySessionRecord | None:
        async with self._lock:
            self._ensure_open()
            await asyncio.to_thread(self._delete_session_sync, session_id)
            return await self._inner.revoke_session(session_id)

    async def revoke_token(self, token: str | SecretValue) -> GatewaySessionRecord | None:
        digest = _token_digest(token)
        async with self._lock:
            self._ensure_open()
            await asyncio.to_thread(self._delete_digest_sync, digest)
            return await self._inner.revoke_token(token)

    async def mark_reauth_required(self, session_id: str) -> GatewaySessionRecord:
        async with self._lock:
            self._ensure_open()
            record = await self._inner.resolve_session_id(session_id)
            marked = record.model_copy(update={"status": GatewaySessionStatus.REAUTH_REQUIRED})
            await asyncio.to_thread(self._rewrite_record_sync, marked)
            return await self._inner.mark_reauth_required(session_id)

    async def pop_expired_records(self) -> tuple[GatewaySessionRecord, ...]:
        return await self.purge_expired()

    async def purge_expired(self) -> tuple[GatewaySessionRecord, ...]:
        async with self._lock:
            self._ensure_open()
            removed = await self._inner.purge_expired()
            if removed:
                await asyncio.to_thread(
                    self._delete_digests_sync, tuple(item.token_digest for item in removed)
                )
            return removed

    async def close(self) -> tuple[GatewaySessionRecord, ...]:
        """Fatal close: durably revoke every session before clearing memory."""

        async with self._lock:
            if self._closed:
                return ()
            await asyncio.to_thread(self._delete_all_sync)
            removed = await self._inner.close()
            self._finish_close()
            return removed

    async def checkpoint_close(self) -> tuple[GatewaySessionRecord, ...]:
        """Graceful process shutdown: preserve durable rows for restart."""

        async with self._lock:
            if self._closed:
                return ()
            self._closed = True
            removed = await self._inner.close()
            self._finish_close()
            return removed

    def _initialize_and_load(
        self,
    ) -> tuple[tuple[GatewaySessionRecord, AuthenticationResult], ...]:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                app_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
                version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
                has_schema = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions'"
                ).fetchone()
                if not has_schema:
                    if app_id not in (0, _APPLICATION_ID) or version not in (0, _SCHEMA_VERSION):
                        raise GatewaySessionInvalidError("Gateway Session Vault schema is invalid.")
                    connection.execute(
                        "CREATE TABLE sessions ("
                        "token_digest TEXT PRIMARY KEY CHECK(length(token_digest)=64),"
                        "session_digest TEXT NOT NULL UNIQUE CHECK(length(session_digest)=64),"
                        "nonce BLOB NOT NULL CHECK(length(nonce)=12),"
                        "ciphertext BLOB NOT NULL) STRICT"
                    )
                    connection.execute(
                        "CREATE TABLE vault_metadata "
                        "(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT"
                    )
                    connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                    nonce = os.urandom(12)
                    check = nonce + self._aead.encrypt(nonce, b"ok", self._check_aad())
                    connection.execute(
                        "INSERT INTO vault_metadata(name,value) VALUES('key_check',?)", (check,)
                    )
                else:
                    self._validate_schema(connection, app_id, version)
                    row = connection.execute(
                        "SELECT value FROM vault_metadata WHERE name='key_check'"
                    ).fetchone()
                    if row is None or not isinstance(row[0], bytes) or len(row[0]) < 29:
                        raise GatewaySessionInvalidError(
                            "Gateway Session Vault metadata is invalid."
                        )
                    try:
                        checked = self._aead.decrypt(row[0][:12], row[0][12:], self._check_aad())
                    except InvalidTag:
                        raise GatewaySessionInvalidError(
                            "Gateway Session Vault key or metadata is invalid."
                        ) from None
                    if checked != b"ok":
                        raise GatewaySessionInvalidError(
                            "Gateway Session Vault metadata is invalid."
                        )
                restored: list[tuple[GatewaySessionRecord, AuthenticationResult]] = []
                expired: list[str] = []
                now = self._clock()
                for digest, session_digest, nonce, ciphertext in connection.execute(
                    "SELECT token_digest,session_digest,nonce,ciphertext FROM sessions"
                ):
                    record, authentication = self._decrypt_row(
                        cast(str, digest),
                        cast(str, session_digest),
                        cast(bytes, nonce),
                        cast(bytes, ciphertext),
                    )
                    gateway_expiry = record.gateway_expires_at or record.expires_at
                    if gateway_expiry <= now:
                        expired.append(record.token_digest)
                    else:
                        restored.append((record, authentication))
                if expired:
                    connection.executemany(
                        "DELETE FROM sessions WHERE token_digest=?", ((item,) for item in expired)
                    )
                connection.commit()
                return tuple(restored)
            except BaseException:
                connection.rollback()
                raise

    def _validate_schema(self, connection: sqlite3.Connection, app_id: int, version: int) -> None:
        if app_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
            raise GatewaySessionInvalidError("Gateway Session Vault version is unsupported.")
        columns = tuple(row[1] for row in connection.execute("PRAGMA table_info(sessions)"))
        if columns != _EXPECTED_COLUMNS:
            raise GatewaySessionInvalidError("Gateway Session Vault schema is invalid.")
        expected_tables = {"sessions", "vault_metadata"}
        actual_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if actual_tables != expected_tables:
            raise GatewaySessionInvalidError("Gateway Session Vault schema is invalid.")

    def _insert_sync(
        self, record: GatewaySessionRecord, authentication: AuthenticationResult
    ) -> None:
        nonce, ciphertext = self._encrypt(record, authentication)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO sessions(token_digest,session_digest,nonce,ciphertext) "
                    "VALUES(?,?,?,?)",
                    (
                        record.token_digest,
                        self._session_digest(record.session_id),
                        nonce,
                        ciphertext,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _rewrite_record_sync(self, record: GatewaySessionRecord) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT session_digest,nonce,ciphertext FROM sessions WHERE token_digest=?",
                    (record.token_digest,),
                ).fetchone()
                if row is None:
                    raise GatewaySessionInvalidError("Gateway session is invalid.")
                _, authentication = self._decrypt_row(
                    record.token_digest, cast(str, row[0]), cast(bytes, row[1]), cast(bytes, row[2])
                )
                nonce, ciphertext = self._encrypt(record, authentication)
                connection.execute(
                    "UPDATE sessions SET nonce=?,ciphertext=? WHERE token_digest=?",
                    (nonce, ciphertext, record.token_digest),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _persist_reauth_token_sync(self, token: str | SecretValue) -> None:
        digest = _token_digest(token)
        self._persist_reauth_digest_sync(digest)

    def _persist_reauth_session_sync(self, session_id: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT token_digest FROM sessions WHERE session_digest=?",
                (self._session_digest(session_id),),
            ).fetchone()
        if row is not None:
            self._persist_reauth_digest_sync(cast(str, row[0]))

    def _persist_reauth_digest_sync(self, digest: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT session_digest,nonce,ciphertext FROM sessions WHERE token_digest=?",
                (digest,),
            ).fetchone()
        if row is None:
            return
        record, _ = self._decrypt_row(
            digest, cast(str, row[0]), cast(bytes, row[1]), cast(bytes, row[2])
        )
        if record.status is not GatewaySessionStatus.REAUTH_REQUIRED:
            self._rewrite_record_sync(
                record.model_copy(update={"status": GatewaySessionStatus.REAUTH_REQUIRED})
            )

    def _delete_session_sync(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM sessions WHERE session_digest=?",
                (self._session_digest(session_id),),
            )
            connection.commit()

    def _delete_digest_sync(self, digest: str) -> None:
        self._delete_digests_sync((digest,))

    def _delete_digests_sync(self, digests: tuple[str, ...]) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "DELETE FROM sessions WHERE token_digest=?", ((item,) for item in digests)
            )
            connection.commit()

    def _delete_all_sync(self) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM sessions")
            connection.commit()

    def _finish_close(self) -> None:
        self._closed = True
        self._key = b""
        self._index_key = b""
        self._aead = cast(AESGCM, None)
        self._restored = ()

    def _encrypt(
        self, record: GatewaySessionRecord, authentication: AuthenticationResult
    ) -> tuple[bytes, bytes]:
        payload = json.dumps(
            {
                "schema_version": _SCHEMA_VERSION,
                "record": _record_json(record),
                "authentication": _authentication_json(authentication),
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = os.urandom(12)
        return nonce, self._aead.encrypt(
            nonce,
            payload,
            self._row_aad(self._session_digest(record.session_id), record.token_digest),
        )

    def _decrypt_row(
        self, digest: str, session_digest: str, nonce: bytes, ciphertext: bytes
    ) -> tuple[GatewaySessionRecord, AuthenticationResult]:
        if len(nonce) != 12:
            raise GatewaySessionInvalidError("Gateway Session Vault row is invalid.")
        try:
            raw = self._aead.decrypt(nonce, ciphertext, self._row_aad(session_digest, digest))
            payload = json.loads(raw)
            if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
                raise ValueError
            record = _record_from_json(payload["record"])
            authentication = _authentication_from_json(payload["authentication"])
        except (InvalidTag, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise GatewaySessionInvalidError("Gateway Session Vault row is invalid.") from None
        if record.token_digest != digest or not hmac.compare_digest(
            self._session_digest(record.session_id), session_digest
        ):
            raise GatewaySessionInvalidError("Gateway Session Vault row binding is invalid.")
        _validate_semantic_binding(record, authentication)
        return record, authentication

    def _row_aad(self, session_digest: str, digest: str) -> bytes:
        return (
            f"v{_SCHEMA_VERSION}\0{self._project_id}\0{self._pack_sha256}\0"
            f"{self._scope_mapping_sha256}\0{self._scope_ceiling_sha256}\0"
            f"{session_digest}\0{digest}"
        ).encode()

    def _session_digest(self, session_id: str) -> str:
        return hmac.new(self._index_key, session_id.encode(), hashlib.sha256).hexdigest()

    def _record_by_session_digest_sync(self, session_digest: str) -> GatewaySessionRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT token_digest,nonce,ciphertext FROM sessions WHERE session_digest=?",
                (session_digest,),
            ).fetchone()
        if row is None:
            raise GatewaySessionInvalidError("Gateway session is invalid.")
        record, _ = self._decrypt_row(
            cast(str, row[0]),
            session_digest,
            cast(bytes, row[1]),
            cast(bytes, row[2]),
        )
        return record

    def _check_aad(self) -> bytes:
        return b"\0".join(
            (
                _CHECK_AAD,
                self._project_id.encode(),
                self._pack_sha256.encode(),
                self._scope_mapping_sha256.encode(),
                self._scope_ceiling_sha256.encode(),
            )
        )

    def _connect(self) -> sqlite3.Connection:
        _secure_sqlite_sidecars(self._path)
        connection = sqlite3.connect(self._path, timeout=self._busy_timeout_ms / 1000)
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        _secure_sqlite_sidecars(self._path)
        return connection

    def _ensure_open(self) -> None:
        if self._closed:
            raise GatewaySessionInvalidError("Gateway Session Vault is closed.")


def _record_json(record: GatewaySessionRecord) -> dict[str, object]:
    context = record.principal_context
    return {
        "session_id": record.session_id,
        "token_digest": record.token_digest,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "gateway_expires_at": record.gateway_expires_at,
        "source_expires_at": record.source_expires_at,
        "source_refresh_at": record.source_refresh_at,
        "status": record.status.value,
        "principal": {
            "principal_id": context.principal_id,
            "target_system_id": context.target_system_id,
            "source_scopes": sorted(context.source_scopes or ()),
            "deployment_scope_ceiling": sorted(context.deployment_scope_ceiling),
            "effective_scopes": sorted(context.effective_scopes),
            "tenant_context": _json_plain(context.tenant_context),
            "auth_state_handle": context.auth_state_handle,
        },
    }


def _record_from_json(value: object) -> GatewaySessionRecord:
    if not isinstance(value, dict) or not isinstance(value.get("principal"), dict):
        raise ValueError
    principal = value["principal"]
    source_scopes = _string_list(principal.get("source_scopes"))
    effective = _string_list(principal.get("effective_scopes"))
    scope_mapping = {scope: effective for scope in source_scopes}
    context = PrincipalContext(
        principal_id=cast(str, principal["principal_id"]),
        gateway_session_id=cast(str, value["session_id"]),
        target_system_id=cast(str, principal["target_system_id"]),
        source_scopes=source_scopes,
        deployment_scope_ceiling=_string_list(principal.get("deployment_scope_ceiling")),
        tenant_context=cast(Mapping[str, object] | None, principal.get("tenant_context")),
        auth_state_handle=cast(str, principal["auth_state_handle"]),
        scope_mapping=scope_mapping,
    )
    if context.effective_scopes != frozenset(effective):
        raise ValueError
    return GatewaySessionRecord(
        session_id=cast(str, value["session_id"]),
        token_digest=cast(str, value["token_digest"]),
        principal_context=context,
        created_at=cast(float, value["created_at"]),
        expires_at=cast(float, value["expires_at"]),
        gateway_expires_at=cast(float, value["gateway_expires_at"]),
        source_expires_at=cast(float | None, value.get("source_expires_at")),
        source_refresh_at=cast(float | None, value.get("source_refresh_at")),
        status=GatewaySessionStatus(cast(str, value["status"])),
    )


def _authentication_json(result: AuthenticationResult) -> dict[str, object]:
    return {
        "token": None if result.token is None else result.token.get_secret_value(),
        "token_type": result.token_type,
        "principal_id": result.principal_id,
        "source_scopes": None if result.source_scopes is None else sorted(result.source_scopes),
        "tenant_context": _json_plain(result.tenant_context),
        "expires_at": result.expires_at,
        "refresh_at": result.refresh_at,
    }


def _authentication_from_json(value: object) -> AuthenticationResult:
    if not isinstance(value, dict):
        raise ValueError
    token = value.get("token")
    return AuthenticationResult(
        token=None if token is None else SecretValue(cast(str, token)),
        token_type=cast(str | None, value.get("token_type")),
        principal_id=cast(str | None, value.get("principal_id")),
        source_scopes=(
            None
            if value.get("source_scopes") is None
            else frozenset(_string_list(value.get("source_scopes")))
        ),
        tenant_context=cast(Mapping[str, JsonValue] | None, value.get("tenant_context")),
        expires_at=cast(float | None, value.get("expires_at")),
        refresh_at=cast(float | None, value.get("refresh_at")),
    )


def _validate_semantic_binding(
    record: GatewaySessionRecord, authentication: AuthenticationResult
) -> None:
    context = record.principal_context
    if (
        authentication.principal_id is not None
        and authentication.principal_id != context.principal_id
    ):
        raise GatewaySessionInvalidError("Gateway Session Vault authentication binding is invalid.")
    if authentication.source_scopes != context.source_scopes:
        raise GatewaySessionInvalidError("Gateway Session Vault authentication binding is invalid.")
    if _json_plain(authentication.tenant_context) != _json_plain(context.tenant_context):
        raise GatewaySessionInvalidError("Gateway Session Vault authentication binding is invalid.")
    if authentication.expires_at != record.source_expires_at:
        raise GatewaySessionInvalidError("Gateway Session Vault authentication binding is invalid.")
    if authentication.refresh_at != record.source_refresh_at:
        raise GatewaySessionInvalidError("Gateway Session Vault authentication binding is invalid.")


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError
    return cast(list[str], value)


def _json_plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_plain(item) for item in value]
    return value


def _token_digest(token: str | SecretValue) -> str:
    raw = token.get_secret_value() if isinstance(token, SecretValue) else token
    if not isinstance(raw, str):
        raise GatewaySessionInvalidError("Gateway token is invalid.")
    return hashlib.sha256(raw.encode()).hexdigest()


def _secure_database_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError("Gateway Session Vault parent directory must already exist")
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        if current.is_symlink() or _is_reparse(current) or not current.is_dir():
            raise ValueError("Gateway Session Vault path cannot traverse links")
    if absolute.exists() or absolute.is_symlink():
        _validate_secure_file(absolute)
    else:
        descriptor = os.open(absolute, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        os.chmod(absolute, 0o600)
        _validate_secure_file(absolute)
    return absolute


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def _validate_secure_file(path: Path) -> None:
    details = path.lstat()
    if path.is_symlink() or _is_reparse(path) or not stat.S_ISREG(details.st_mode):
        raise ValueError("Gateway Session Vault must be a regular non-link file")
    if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Gateway Session Vault permissions must be owner-only")


def _secure_sqlite_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            if sidecar.is_symlink() or _is_reparse(sidecar) or not sidecar.is_file():
                raise ValueError("Gateway Session Vault SQLite sidecar is unsafe")
            os.chmod(sidecar, 0o600)


__all__ = ["GatewaySessionVaultConfig", "SQLiteGatewaySessionVault"]
