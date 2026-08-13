from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from acc_core.models import PasswordBearerAuthConfig
from acc_runtime.auth import AuthenticationResult, PasswordBearerAuthStrategy
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import (
    GatewayReauthRequiredError,
    GatewaySessionInvalidError,
    GatewaySessionStatus,
    SQLiteGatewaySessionVault,
)
from acc_runtime.gateway.service import GatewaySessionService

NOW = 2_000_000_000.0
TOKEN = "A" * 43
SOURCE_TOKEN = "source-secret-token"
KEK = SecretValue("k" * 32)
SALT = b"s" * 16


def _vault(
    path: Path, *, kek: SecretValue = KEK, pack_sha256: str = "a" * 64
) -> SQLiteGatewaySessionVault:
    return SQLiteGatewaySessionVault(
        path,
        project_id="project-a",
        pack_sha256=pack_sha256,
        scope_mapping_sha256="b" * 64,
        scope_ceiling_sha256="c" * 64,
        kek=kek,
        deployment_salt=SALT,
        max_sessions=10,
        ttl_seconds=600,
        clock=lambda: NOW,
        token_generator=lambda: TOKEN,
    )


def _context() -> PrincipalContext:
    return PrincipalContext(
        principal_id="user-1",
        gateway_session_id="session-1",
        target_system_id="project-a",
        source_scopes={"source.read"},
        deployment_scope_ceiling={"read"},
        scope_mapping={"source.read": {"read"}},
        tenant_context={"tenant_id": 7},
        auth_state_handle="auth-1",
    )


def _authentication() -> AuthenticationResult:
    return AuthenticationResult(
        token=SecretValue(SOURCE_TOKEN),
        token_type="Bearer",
        principal_id="user-1",
        source_scopes=frozenset({"source.read"}),
        tenant_context={"tenant_id": 7},
        expires_at=NOW + 500,
        refresh_at=NOW + 400,
    )


async def _create(vault: SQLiteGatewaySessionVault) -> None:
    assert await vault.restore_authentications() == ()
    await vault.create(
        session_id="session-1",
        principal_context=_context(),
        source_expires_at=NOW + 500,
        source_refresh_at=NOW + 400,
        authentication=_authentication(),
    )


@pytest.mark.asyncio
async def test_restart_restores_session_and_authentication_without_raw_gateway_token(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions.db"
    first = _vault(path)
    await _create(first)
    await first.checkpoint_close()

    database = path.read_bytes()
    assert TOKEN.encode() not in database
    assert SOURCE_TOKEN.encode() not in database
    assert b"session-1" not in database
    assert b"user-1" not in database
    assert b"tenant_id" not in database

    second = _vault(path)
    restored = await second.restore_authentications()
    assert len(restored) == 1
    record, authentication = restored[0]
    assert record.session_id == "session-1"
    assert record.principal_context.effective_scopes == frozenset({"read"})
    assert authentication.token is not None
    assert authentication.token.get_secret_value() == SOURCE_TOKEN
    assert (await second.resolve_token(TOKEN)).session_id == "session-1"
    await second.checkpoint_close()


@pytest.mark.asyncio
async def test_service_startup_rebinds_restored_authentication_before_use(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    first = _vault(path)
    await _create(first)
    await first.checkpoint_close()

    config = PasswordBearerAuthConfig.model_validate(
        {
            "kind": "password_bearer",
            "credentials": {"kind": "gateway_session"},
            "login_path": "/login",
            "identity_field": "identity",
            "password_field": "password",
            "token_pointer": "/access_token",
            "principal_pointer": "/user/id",
            "scopes_pointer": "/permissions",
            "tenant_pointer": "/tenant",
            "scope_mapping": {"source.read": ["read"]},
        }
    )
    strategy = PasswordBearerAuthStrategy(
        config=config,
        base_url="https://source.example",
        credential_source=None,
        clock=lambda: NOW,
    )
    second = _vault(path)
    service = GatewaySessionService(
        auth_strategy=strategy,
        auth_config=config,
        store=second,
        target_system_id="project-a",
        deployment_scope_ceiling={"read"},
        clock=lambda: NOW,
    )
    await service.startup()
    record = await second.resolve_token(TOKEN)
    attempt = await strategy.authorize(record.principal_context)
    assert attempt.authentication.token is not None
    assert attempt.authentication.token.get_secret_value() == SOURCE_TOKEN
    await service.aclose()


def test_wrong_key_fails_closed_before_restore(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"

    async def prepare() -> None:
        first = _vault(path)
        await _create(first)
        await first.checkpoint_close()

    import asyncio

    asyncio.run(prepare())
    with pytest.raises(GatewaySessionInvalidError):
        _vault(path, kek=SecretValue("x" * 32))


def test_changed_pack_binding_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"

    async def prepare() -> None:
        first = _vault(path)
        await _create(first)
        await first.checkpoint_close()

    import asyncio

    asyncio.run(prepare())
    with pytest.raises(GatewaySessionInvalidError):
        _vault(path, pack_sha256="d" * 64)


def test_tampered_ciphertext_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"

    async def prepare() -> None:
        first = _vault(path)
        await _create(first)
        await first.checkpoint_close()

    import asyncio

    asyncio.run(prepare())
    with sqlite3.connect(path) as connection:
        ciphertext = connection.execute("SELECT ciphertext FROM sessions").fetchone()[0]
        changed = bytearray(ciphertext)
        changed[-1] ^= 1
        connection.execute("UPDATE sessions SET ciphertext=?", (bytes(changed),))
    with pytest.raises(GatewaySessionInvalidError):
        _vault(path)


def test_unknown_schema_version_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    first = _vault(path)

    import asyncio

    asyncio.run(first.checkpoint_close())
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(GatewaySessionInvalidError):
        _vault(path)


@pytest.mark.asyncio
async def test_revoke_is_durable_before_restart(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    first = _vault(path)
    await _create(first)
    assert await first.revoke_token(TOKEN) is not None
    await first.checkpoint_close()

    second = _vault(path)
    assert await second.restore_authentications() == ()
    with pytest.raises(GatewaySessionInvalidError):
        await second.resolve_token(TOKEN)
    await second.checkpoint_close()


@pytest.mark.asyncio
async def test_reauth_required_is_persisted_and_never_rebindable(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    first = _vault(path)
    await _create(first)
    marked = await first.mark_reauth_required("session-1")
    assert marked.status is GatewaySessionStatus.REAUTH_REQUIRED
    await first.checkpoint_close()

    second = _vault(path)
    restored = await second.restore_authentications()
    assert restored[0][0].status is GatewaySessionStatus.REAUTH_REQUIRED
    with pytest.raises(GatewayReauthRequiredError):
        await second.resolve_token(TOKEN)
    await second.checkpoint_close()


@pytest.mark.asyncio
async def test_fatal_close_revokes_persisted_sessions(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    first = _vault(path)
    await _create(first)
    removed = await first.close()
    assert [record.session_id for record in removed] == ["session-1"]

    second = _vault(path)
    assert await second.restore_authentications() == ()
    await second.checkpoint_close()
