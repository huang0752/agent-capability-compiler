from __future__ import annotations

import asyncio
import types
from collections.abc import Mapping

import httpx
import pytest

from acc_core.models import PasswordBearerAuthConfig
from acc_runtime.auth import PasswordBearerAuthStrategy
from acc_runtime.auth.errors import AuthLoginRejectedError
from acc_runtime.context import AuthStateKey
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway.service import GatewaySessionService
from acc_runtime.gateway.sessions import (
    GatewayReauthRequiredError,
    GatewaySessionInvalidError,
    InMemoryGatewaySessionStore,
)


class Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _config(*, principal_pointer: str | None = "/user/id") -> PasswordBearerAuthConfig:
    return PasswordBearerAuthConfig.model_validate(
        {
            "kind": "password_bearer",
            "credentials": {"kind": "gateway_session"},
            "login_path": "/login",
            "identity_field": "identity",
            "password_field": "password",
            "token_pointer": "/access_token",
            "expires_in_pointer": "/expires_in",
            "principal_pointer": principal_pointer,
            "scopes_pointer": "/permissions",
            "tenant_pointer": "/tenant",
            "scope_mapping": {
                "source.read": ["documents.read"],
                "source.admin": ["documents.read", "documents.delete"],
            },
        }
    )


def _strategy(
    config: PasswordBearerAuthConfig,
    handler: httpx.MockTransport,
    clock: Clock,
) -> PasswordBearerAuthStrategy:
    return PasswordBearerAuthStrategy(
        config=config,
        base_url="https://source.example",
        credential_source=None,
        client_factory=lambda: httpx.AsyncClient(transport=handler),
        clock=clock,
    )


def _store(clock: Clock, *tokens: str) -> InMemoryGatewaySessionStore:
    remaining = iter(tokens or ("g" * 43,))
    return InMemoryGatewaySessionStore(
        max_sessions=20,
        ttl_seconds=3600,
        clock=clock,
        token_generator=lambda: next(remaining),
    )


def _service(
    *,
    config: PasswordBearerAuthConfig,
    strategy: PasswordBearerAuthStrategy,
    store: InMemoryGatewaySessionStore,
    clock: Clock,
    ids: list[str] | None = None,
    handles: list[str] | None = None,
    anonymous_ids: list[str] | None = None,
) -> GatewaySessionService:
    session_ids = iter(ids or ["session-a"])
    auth_handles = iter(handles or ["auth-a"])
    anonymous_principals = iter(anonymous_ids or ["anonymous-a"])
    return GatewaySessionService(
        auth_strategy=strategy,
        auth_config=config,
        store=store,
        target_system_id="system-a",
        deployment_scope_ceiling={"documents.read"},
        clock=clock,
        session_id_generator=lambda: next(session_ids),
        auth_state_handle_generator=lambda: next(auth_handles),
        anonymous_principal_generator=lambda: next(anonymous_principals),
    )


def _assert_traceback_cannot_reach_secret(error: BaseException, *secrets: str) -> None:
    pending: list[object] = []
    traceback = error.__traceback__
    while traceback is not None:
        if "/packages/acc-runtime/" in traceback.tb_frame.f_code.co_filename:
            pending.extend(traceback.tb_frame.f_locals.values())
        traceback = traceback.tb_next
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if value is None or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, str):
            assert all(secret not in value for secret in secrets)
        elif isinstance(value, bytes):
            assert all(secret.encode() not in value for secret in secrets)
        elif isinstance(value, SecretValue):
            assert all(secret not in value.get_secret_value() for secret in secrets)
        elif isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
        elif isinstance(value, BaseException):
            pending.extend((value.args, value.__cause__, value.__context__))
        elif not isinstance(value, (types.FunctionType, types.MethodType, type)):
            namespace = getattr(value, "__dict__", None)
            if isinstance(namespace, dict):
                pending.extend(namespace.values())
            slots = getattr(type(value), "__slots__", ())
            for slot in (slots,) if isinstance(slots, str) else slots:
                if isinstance(slot, str) and hasattr(value, slot):
                    pending.append(getattr(value, slot))


def _gateway_token(response: object) -> str:
    payload = response.one_time_payload()  # type: ignore[attr-defined]
    token = payload["token"]
    assert isinstance(token, str)
    return token


@pytest.mark.anyio
async def test_create_session_logs_in_once_and_builds_trusted_context() -> None:
    clock = Clock()
    requests: list[httpx.Request] = []

    def login(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "access_token": "source-token-a",
                "expires_in": 120,
                "user": {"id": "principal-a"},
                "permissions": ["source.read", "source.unknown"],
                "tenant": {"tenant_id": "tenant-a"},
            },
            request=request,
        )

    config = _config()
    store = _store(clock)
    service = _service(
        config=config,
        strategy=_strategy(config, httpx.MockTransport(login), clock),
        store=store,
        clock=clock,
    )

    response = await service.create_session(identity="account-a", password="password-a")
    record = await store.resolve_token(_gateway_token(response))

    assert len(requests) == 1
    assert requests[0].read() == b'{"identity":"account-a","password":"password-a"}'
    assert record.principal_context.principal_id == "principal-a"
    assert record.principal_context.source_scopes == frozenset({"source.read", "source.unknown"})
    assert record.principal_context.effective_scopes == frozenset({"documents.read"})
    assert record.principal_context.tenant_context == {"tenant_id": "tenant-a"}
    assert record.source_expires_at == 220.0
    assert record.source_refresh_at == 208.0
    assert record.expires_at == 208.0
    assert response.expires_in_seconds == 108
    assert "source-token-a" not in repr(service)
    assert "password-a" not in repr(service)

    clock.value = 208.0
    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(_gateway_token(response))


@pytest.mark.anyio
async def test_abc_concurrent_sessions_keep_auth_state_isolated() -> None:
    clock = Clock()
    config = _config()

    async def login(request: httpx.Request) -> httpx.Response:
        identity = request.read().decode().split('"identity":"', 1)[1].split('"', 1)[0]
        await asyncio.sleep(0)
        return httpx.Response(
            200,
            json={
                "access_token": f"token-{identity}",
                "expires_in": 300,
                "user": {"id": f"principal-{identity}"},
                "permissions": ["source.read"],
                "tenant": {"tenant_id": f"tenant-{identity}"},
            },
            request=request,
        )

    store = _store(clock, "a" * 43, "b" * 43, "c" * 43)
    service = _service(
        config=config,
        strategy=_strategy(config, httpx.MockTransport(login), clock),
        store=store,
        clock=clock,
        ids=["session-a", "session-b", "session-c"],
        handles=["auth-a", "auth-b", "auth-c"],
    )

    responses = await asyncio.gather(
        *(service.create_session(identity=user, password=f"pw-{user}") for user in "abc")
    )

    records = [await store.resolve_token(_gateway_token(response)) for response in responses]
    assert {record.principal_context.principal_id for record in records} == {
        "principal-a",
        "principal-b",
        "principal-c",
    }
    assert len({record.principal_context.auth_state_key for record in records}) == 3


@pytest.mark.anyio
async def test_anonymous_principal_is_session_random_not_derived_from_identity() -> None:
    clock = Clock()
    config = _config(principal_pointer=None)

    def login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "token",
                "expires_in": 300,
                "permissions": ["source.read"],
                "tenant": {},
            },
            request=request,
        )

    store = _store(clock, "a" * 43, "b" * 43)
    service = _service(
        config=config,
        strategy=_strategy(config, httpx.MockTransport(login), clock),
        store=store,
        clock=clock,
        ids=["session-a", "session-b"],
        handles=["auth-a", "auth-b"],
        anonymous_ids=["anonymous-random-a", "anonymous-random-b"],
    )

    first = await service.create_session(identity="same-account", password="same-password")
    second = await service.create_session(identity="same-account", password="same-password")
    first_record = await store.resolve_token(_gateway_token(first))
    second_record = await store.resolve_token(_gateway_token(second))

    assert first_record.principal_context.principal_id == "anonymous-random-a"
    assert second_record.principal_context.principal_id == "anonymous-random-b"
    assert (
        first_record.principal_context.principal_id != second_record.principal_context.principal_id
    )
    assert "same-account" not in first_record.principal_context.principal_id


@pytest.mark.anyio
async def test_missing_source_scopes_fails_closed_without_session_or_bound_state() -> None:
    clock = Clock()
    config = _config().model_copy(update={"scopes_pointer": None})

    def login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "private-source-token",
                "expires_in": 300,
                "user": {"id": "principal-a"},
                "tenant": {},
            },
            request=request,
        )

    store = _store(clock)
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(config=config, strategy=strategy, store=store, clock=clock)

    with pytest.raises(GatewaySessionInvalidError) as caught:
        await service.create_session(identity="account-secret", password="password-secret")

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    _assert_traceback_cannot_reach_secret(
        caught.value,
        "account-secret",
        "password-secret",
        "private-source-token",
    )


class _StoreFailsAfterCreate(InMemoryGatewaySessionStore):
    async def create(self, **kwargs: object):  # type: ignore[no-untyped-def]
        await super().create(**kwargs)  # type: ignore[arg-type]
        raise GatewaySessionInvalidError("synthetic store failure")


class _BindFailsAfterBinding(PasswordBearerAuthStrategy):
    async def bind_state(self, auth_state_key: AuthStateKey, result: object) -> None:
        await super().bind_state(auth_state_key, result)  # type: ignore[arg-type]
        raise GatewaySessionInvalidError("synthetic bind failure")


@pytest.mark.anyio
async def test_store_failure_rolls_back_ghost_record_and_auth_state() -> None:
    clock = Clock()
    config = _config()

    def login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "private-token",
                "expires_in": 300,
                "user": {"id": "principal-a"},
                "permissions": ["source.read"],
                "tenant": {},
            },
            request=request,
        )

    store = _StoreFailsAfterCreate(
        max_sessions=2,
        ttl_seconds=3600,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(config=config, strategy=strategy, store=store, clock=clock)

    with pytest.raises(GatewaySessionInvalidError):
        await service.create_session(identity="account-a", password="password-a")

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    key = AuthStateKey("principal-a", "system-a", "session-a", "auth-a")
    assert key not in strategy._states


@pytest.mark.anyio
async def test_bind_failure_rolls_back_partial_auth_state_without_creating_record() -> None:
    clock = Clock()
    config = _config()

    def login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "private-token",
                "expires_in": 300,
                "user": {"id": "principal-a"},
                "permissions": ["source.read"],
                "tenant": {},
            },
            request=request,
        )

    strategy = _BindFailsAfterBinding(
        config=config,
        base_url="https://source.example",
        credential_source=None,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(login)),
        clock=clock,
    )
    store = _store(clock)
    service = _service(config=config, strategy=strategy, store=store, clock=clock)

    with pytest.raises(GatewaySessionInvalidError):
        await service.create_session(identity="account-a", password="password-a")

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    key = AuthStateKey("principal-a", "system-a", "session-a", "auth-a")
    assert key not in strategy._states


@pytest.mark.anyio
async def test_login_failure_does_not_expose_credentials_or_another_users_state() -> None:
    clock = Clock()
    config = _config()

    def login(request: httpx.Request) -> httpx.Response:
        if b'"identity":"account-b"' in request.read():
            return httpx.Response(
                200,
                json={
                    "access_token": "other-user-source-token",
                    "expires_in": 300,
                    "user": {"id": "principal-b"},
                    "permissions": ["source.read"],
                    "tenant": {},
                },
                request=request,
            )
        return httpx.Response(401, request=request)

    store = _store(clock, "b" * 43)
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(
        config=config,
        strategy=strategy,
        store=store,
        clock=clock,
        ids=["session-b", "session-a"],
        handles=["auth-b", "auth-a"],
    )
    response_b = await service.create_session(identity="account-b", password="password-b")

    with pytest.raises(AuthLoginRejectedError) as caught:
        await service.create_session(identity="account-a-secret", password="password-a-secret")

    record_b = await store.resolve_token(_gateway_token(response_b))
    assert record_b.principal_context.principal_id == "principal-b"
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    _assert_traceback_cannot_reach_secret(
        caught.value,
        "account-a-secret",
        "password-a-secret",
        "other-user-source-token",
    )


@pytest.mark.anyio
async def test_delete_and_reauth_only_invalidate_selected_session() -> None:
    clock = Clock()
    config = _config()
    calls = 0

    def login(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "access_token": f"private-token-{calls}",
                "expires_in": 300,
                "user": {"id": f"principal-{calls}"},
                "permissions": ["source.read"],
                "tenant": {},
            },
            request=request,
        )

    store = _store(clock, "a" * 43, "b" * 43)
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(
        config=config,
        strategy=strategy,
        store=store,
        clock=clock,
        ids=["session-a", "session-b"],
        handles=["auth-a", "auth-b"],
    )
    first = await service.create_session(identity="a", password="a")
    second = await service.create_session(identity="b", password="b")
    first_record = await store.resolve_token(_gateway_token(first))
    second_record = await store.resolve_token(_gateway_token(second))

    await service.mark_reauth_required(first_record.session_id)

    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(_gateway_token(first))
    assert await store.resolve_token(_gateway_token(second)) == second_record
    assert first_record.principal_context.auth_state_key not in strategy._states
    assert second_record.principal_context.auth_state_key in strategy._states

    await service.delete_current(second_record.session_id)
    await service.delete_current(second_record.session_id)
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(_gateway_token(second))
    assert second_record.principal_context.auth_state_key not in strategy._states


@pytest.mark.anyio
async def test_close_is_idempotent_and_closes_store_and_strategy() -> None:
    clock = Clock()
    config = _config()

    def login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "private-token",
                "expires_in": 300,
                "user": {"id": "principal-a"},
                "permissions": ["source.read"],
                "tenant": {},
            },
            request=request,
        )

    store = _store(clock)
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(config=config, strategy=strategy, store=store, clock=clock)
    response = await service.create_session(identity="a", password="b")

    await service.aclose()
    await service.aclose()

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(_gateway_token(response))
    with pytest.raises(GatewaySessionInvalidError):
        await service.create_session(identity="a", password="b")


@pytest.mark.anyio
async def test_cancelled_store_create_rolls_back_inserted_record() -> None:
    clock = Clock()
    config = _config()
    inserted = asyncio.Event()
    release = asyncio.Event()

    class PausingStore(InMemoryGatewaySessionStore):
        async def create(self, **kwargs: object):  # type: ignore[no-untyped-def]
            result = await super().create(**kwargs)  # type: ignore[arg-type]
            inserted.set()
            await release.wait()
            return result

    def login(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "private-token",
                "expires_in": 300,
                "user": {"id": "principal-a"},
                "permissions": ["source.read"],
                "tenant": {},
            },
            request=request,
        )

    store = PausingStore(
        max_sessions=2,
        ttl_seconds=3600,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(config=config, strategy=strategy, store=store, clock=clock)
    task = asyncio.create_task(service.create_session(identity="a", password="b"))
    await inserted.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    key = AuthStateKey("principal-a", "system-a", "session-a", "auth-a")
    assert key not in strategy._states


@pytest.mark.anyio
async def test_cancelled_login_does_not_publish_session_or_keep_auth_state() -> None:
    clock = Clock()
    config = _config()
    started = asyncio.Event()
    release = asyncio.Event()

    async def login(request: httpx.Request) -> httpx.Response:
        started.set()
        await release.wait()
        return httpx.Response(500, request=request)

    store = _store(clock)
    strategy = _strategy(config, httpx.MockTransport(login), clock)
    service = _service(config=config, strategy=strategy, store=store, clock=clock)
    task = asyncio.create_task(
        service.create_session(identity="account-secret", password="password-secret")
    )
    await started.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    assert not strategy._states


def test_service_rejects_non_gateway_auth_configuration() -> None:
    values = _config().model_dump(mode="python")
    values["credentials"] = {
        "kind": "environment_secret",
        "identity_ref": "IDENTITY",
        "password_ref": "PASSWORD",
    }
    config = PasswordBearerAuthConfig.model_validate(values)
    clock = Clock()
    strategy = object()

    with pytest.raises(ValueError, match="gateway_session"):
        GatewaySessionService(
            auth_strategy=strategy,  # type: ignore[arg-type]
            auth_config=config,
            store=_store(clock),
            target_system_id="system-a",
            deployment_scope_ceiling=set(),
        )
