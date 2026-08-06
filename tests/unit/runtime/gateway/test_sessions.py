from __future__ import annotations

import asyncio
import base64
import types
from collections.abc import Iterator, Mapping

import pytest

from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway.models import GatewaySessionStatus
from acc_runtime.gateway.sessions import (
    GatewayReauthRequiredError,
    GatewaySessionCapacityError,
    GatewaySessionExpiredError,
    GatewaySessionInvalidError,
    InMemoryGatewaySessionStore,
)


class Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class TokenGenerator:
    __slots__ = ("index", "tokens")

    def __init__(self, *tokens: str) -> None:
        self.tokens = list(tokens)
        self.index = 0

    def __call__(self) -> str:
        token = self.tokens[self.index]
        self.index += 1
        return token


def _assert_runtime_traceback_cannot_reach_secret(
    error: BaseException,
    secret: str,
) -> None:
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
            assert secret not in value
            continue
        if isinstance(value, bytes):
            assert secret.encode(errors="surrogatepass") not in value
            continue
        if isinstance(value, SecretValue):
            assert secret not in value.get_secret_value()
            continue
        if isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
            continue
        if isinstance(value, BaseException):
            pending.extend([value.args, value.__cause__, value.__context__])
            continue
        if isinstance(value, (types.FunctionType, types.MethodType, type)):
            continue
        namespace = getattr(value, "__dict__", None)
        if isinstance(namespace, dict):
            pending.extend(namespace.values())
        slots = getattr(type(value), "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and hasattr(value, slot):
                pending.append(getattr(value, slot))


def _tokens(*tokens: str) -> Iterator[str]:
    yield from tokens


def _context(user: str, session_id: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=user,
        gateway_session_id=session_id,
        target_system_id="system-a",
        source_scopes={f"{user}.read"},
        deployment_scope_ceiling={"documents.read"},
        scope_mapping={f"{user}.read": {"documents.read"}},
        tenant_context={"tenant_id": f"tenant-{user}"},
        auth_state_handle=f"auth-{user}",
    )


@pytest.mark.anyio
async def test_create_returns_opaque_token_but_record_only_keeps_digest() -> None:
    gateway_token = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode("ascii")
    store = InMemoryGatewaySessionStore(
        max_sessions=10,
        ttl_seconds=3600,
        clock=Clock(),
        token_generator=lambda: gateway_token,
    )

    token, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )

    assert token.get_secret_value() == gateway_token
    assert record.token_digest != gateway_token
    assert len(record.token_digest) == 64
    assert gateway_token not in repr(store)
    assert gateway_token not in repr(record)
    assert await store.resolve_token(gateway_token) == record


@pytest.mark.anyio
async def test_default_generator_produces_a_256_bit_urlsafe_token() -> None:
    store = InMemoryGatewaySessionStore(max_sessions=1, ttl_seconds=60)

    token, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )

    raw = token.get_secret_value()
    assert len(raw) >= 43
    assert all(character.isalnum() or character in "-_" for character in raw)
    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    assert len(decoded) == 32


@pytest.mark.anyio
async def test_create_caps_ttl_at_source_token_expiry() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=3600,
        clock=clock,
        token_generator=lambda: "g" * 43,
    )

    _, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        source_expires_at=130.0,
    )

    assert record.expires_at == 130.0


@pytest.mark.anyio
async def test_expired_source_token_requires_reauthentication_before_session_creation() -> None:
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: "g" * 43,
    )

    with pytest.raises(GatewayReauthRequiredError) as caught:
        await store.create(
            session_id="session-a",
            principal_context=_context("a", "session-a"),
            source_expires_at=100.0,
        )

    assert caught.value.code == "ACC_GATEWAY_REAUTH_REQUIRED"
    assert "source-a" not in str(caught.value)


@pytest.mark.anyio
async def test_capacity_rejects_new_session_without_evicting_active() -> None:
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: next(generator),
    )
    token_a, record_a = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )

    with pytest.raises(GatewaySessionCapacityError) as caught:
        await store.create(
            session_id="session-b",
            principal_context=_context("b", "session-b"),
        )

    assert caught.value.code == "ACC_GATEWAY_SESSION_CAPACITY_REACHED"
    assert await store.resolve_token(token_a) == record_a


@pytest.mark.anyio
async def test_abc_sessions_resolve_only_their_own_context() -> None:
    generator = _tokens("a" * 43, "b" * 43, "c" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=3,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: next(generator),
    )
    created = await asyncio.gather(
        *(
            store.create(
                session_id=f"session-{user}",
                principal_context=_context(user, f"session-{user}"),
            )
            for user in ("a", "b", "c")
        )
    )

    for user, (token, _) in zip(("a", "b", "c"), created, strict=True):
        resolved = await store.resolve_token(token)
        assert resolved.principal_context.principal_id == user
        assert (await store.resolve_session_id(f"session-{user}")) == resolved


@pytest.mark.anyio
async def test_revoke_invalidates_both_indexes_and_is_idempotent() -> None:
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: "a" * 43,
    )
    token, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )

    assert await store.revoke("session-a") == record
    assert await store.revoke("session-a") is None

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token)
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    assert await store.pop_expired_records() == ()


@pytest.mark.anyio
async def test_reauth_required_has_distinct_stable_error_and_only_marks_one_session() -> None:
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: next(generator),
    )
    token_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    token_b, record_b = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )

    marked = await store.mark_reauth_required("session-a")

    assert marked.status is GatewaySessionStatus.REAUTH_REQUIRED
    with pytest.raises(GatewayReauthRequiredError) as caught:
        await store.resolve_token(token_a)
    assert caught.value.code == "ACC_GATEWAY_REAUTH_REQUIRED"
    assert await store.resolve_token(token_b) == record_b


@pytest.mark.anyio
async def test_expired_session_is_removed_and_capacity_can_be_reused() -> None:
    clock = Clock()
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=10,
        clock=clock,
        token_generator=lambda: next(generator),
    )
    token_a, record_a = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 110.0

    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_token(token_a)
    assert await store.purge_expired() == (record_a,)
    assert await store.pop_expired_records() == ()

    await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )


@pytest.mark.anyio
async def test_concurrent_creation_respects_capacity() -> None:
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: next(generator),
    )

    results = await asyncio.gather(
        store.create(
            session_id="session-a",
            principal_context=_context("a", "session-a"),
        ),
        store.create(
            session_id="session-b",
            principal_context=_context("b", "session-b"),
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(result, GatewaySessionCapacityError) for result in results) == 1


@pytest.mark.anyio
async def test_close_is_idempotent_and_invalidates_all_tokens() -> None:
    gateway_token = "a" * 43
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: gateway_token,
    )
    token, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )

    await store.close()
    await store.close()

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token)
    with pytest.raises(GatewaySessionInvalidError):
        await store.create(
            session_id="session-b",
            principal_context=_context("b", "session-b"),
        )


@pytest.mark.anyio
async def test_new_store_does_not_accept_token_from_previous_process() -> None:
    gateway_token = "a" * 43
    first = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: gateway_token,
    )
    token, _ = await first.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    second = InMemoryGatewaySessionStore(max_sessions=1, ttl_seconds=60, clock=Clock())

    with pytest.raises(GatewaySessionInvalidError):
        await second.resolve_token(token)


@pytest.mark.anyio
async def test_stable_resolve_error_traceback_cannot_reach_any_gateway_token() -> None:
    token_a = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
    token_b = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
    generator = TokenGenerator(token_a, token_b)
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=generator,
    )
    returned_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    await store.close()

    with pytest.raises(GatewaySessionInvalidError) as caught:
        await store.resolve_token(returned_a)

    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_a)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_b)


@pytest.mark.anyio
async def test_create_error_traceback_drops_invalid_generated_token_and_store() -> None:
    invalid_token = "invalid-generated-gateway-token-secret"
    other_users_token = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=TokenGenerator(invalid_token, other_users_token),
    )

    with pytest.raises(GatewaySessionInvalidError) as caught:
        await store.create(
            session_id="session-a",
            principal_context=_context("a", "session-a"),
        )

    _assert_runtime_traceback_cannot_reach_secret(caught.value, invalid_token)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, other_users_token)


@pytest.mark.anyio
async def test_cancelled_token_resolution_drops_raw_tokens_and_store_graph() -> None:
    token_a = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
    token_b = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=TokenGenerator(token_a, token_b),
    )
    returned_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    await store._lock.acquire()
    resolving = asyncio.create_task(store.resolve_token(returned_a))
    await asyncio.sleep(0)
    resolving.cancel()
    store._lock.release()

    with pytest.raises(asyncio.CancelledError) as caught:
        await resolving

    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_a)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_b)


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["resolve", "revoke"])
async def test_non_utf8_gateway_token_is_stably_rejected_without_leaking(
    operation: str,
) -> None:
    invalid_token = "surrogate-token-secret-\ud800"
    store = InMemoryGatewaySessionStore(max_sessions=1, ttl_seconds=60, clock=Clock())

    if operation == "resolve":
        with pytest.raises(GatewaySessionInvalidError) as caught:
            await store.resolve_token(SecretValue(invalid_token))
        assert caught.value.code == "ACC_GATEWAY_SESSION_INVALID"
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        _assert_runtime_traceback_cannot_reach_secret(caught.value, invalid_token)
    else:
        assert await store.revoke_token(SecretValue(invalid_token)) is None


@pytest.mark.anyio
async def test_create_uses_fresh_clock_inside_linearization_lock() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    await store._lock.acquire()
    creating = asyncio.create_task(
        store.create(
            session_id="session-a",
            principal_context=_context("a", "session-a"),
            source_expires_at=105.0,
        )
    )
    await asyncio.sleep(0)
    clock.value = 110.0
    store._lock.release()

    with pytest.raises(GatewayReauthRequiredError):
        await creating


@pytest.mark.anyio
async def test_source_expiry_marks_only_that_session_reauth_required() -> None:
    clock = Clock()
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=clock,
        token_generator=lambda: next(generator),
    )
    token_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        source_expires_at=105.0,
    )
    token_b, record_b = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
        source_expires_at=130.0,
    )
    clock.value = 105.0

    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(token_a)
    assert (await store.resolve_token(token_b)) == record_b
    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_session_id("session-a")


@pytest.mark.anyio
async def test_source_refresh_boundary_requires_reauthentication_before_expiry() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    token, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        source_refresh_at=104.0,
        source_expires_at=110.0,
    )
    assert record.source_refresh_at == 104.0
    assert record.source_expires_at == 110.0
    clock.value = 104.0

    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(token)


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["mark_reauth", "revoke", "revoke_token"])
async def test_cancelled_session_mutation_drops_store_token_graph(operation: str) -> None:
    token_a = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
    token_b = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=TokenGenerator(token_a, token_b),
    )
    returned_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    await store._lock.acquire()
    task: asyncio.Task[object]
    if operation == "mark_reauth":
        task = asyncio.create_task(store.mark_reauth_required("session-a"))
    elif operation == "revoke":
        task = asyncio.create_task(store.revoke("session-a"))
    else:
        task = asyncio.create_task(store.revoke_token(returned_a))
    await asyncio.sleep(0)
    task.cancel()
    store._lock.release()

    with pytest.raises(asyncio.CancelledError) as caught:
        await task

    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_a)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_b)


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["purge", "close"])
async def test_cancelled_store_lifecycle_drops_token_graph(operation: str) -> None:
    token_a = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
    token_b = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=TokenGenerator(token_a, token_b),
    )
    returned_a, record_a = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    await store._lock.acquire()
    call = store.purge_expired() if operation == "purge" else store.close()
    task = asyncio.create_task(call)
    await asyncio.sleep(0)
    task.cancel()
    store._lock.release()

    with pytest.raises(asyncio.CancelledError) as caught:
        await task

    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_a)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_b)
    assert await store.resolve_token(returned_a) == record_a


@pytest.mark.anyio
async def test_source_boundary_wins_when_gateway_ttl_expires_at_same_instant() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    token, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        source_expires_at=105.0,
    )
    clock.value = 105.0

    assert await store.purge_expired() == ()
    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(token)


@pytest.mark.anyio
@pytest.mark.parametrize("invalid_now", [float("nan"), float("inf"), float("-inf")])
async def test_nonfinite_clock_fails_closed_for_resolve_mark_and_purge(
    invalid_now: float,
) -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=60,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    token, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = invalid_now

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token)
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")
    with pytest.raises(GatewaySessionInvalidError):
        await store.mark_reauth_required("session-a")
    with pytest.raises(GatewaySessionInvalidError):
        await store.purge_expired()

    clock.value = 100.0
    assert await store.resolve_token(token) == record


@pytest.mark.anyio
async def test_revoke_session_returns_record_without_active_resolution() -> None:
    clock = Clock()
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=10,
        clock=clock,
        token_generator=lambda: next(generator),
    )
    token_a, record_a = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        source_expires_at=105.0,
    )
    token_b, record_b = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )
    await store.mark_reauth_required("session-a")
    clock.value = 111.0

    revoked_a = await store.revoke_session("session-a")
    revoked_b = await store.revoke_session("session-b")

    assert revoked_a is not None
    assert revoked_a.principal_context.auth_state_key == record_a.principal_context.auth_state_key
    assert revoked_b == record_b
    assert await store.revoke_session("session-a") is None
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token_a)
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token_b)


@pytest.mark.anyio
@pytest.mark.parametrize("boundary_kind", ["expiry", "refresh", "manual"])
async def test_reauth_wins_at_gateway_tie_but_expires_after_tie(
    boundary_kind: str,
) -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    source_arguments: dict[str, float] = {}
    if boundary_kind == "expiry":
        source_arguments["source_expires_at"] = 105.0
    elif boundary_kind == "refresh":
        source_arguments["source_refresh_at"] = 105.0
        source_arguments["source_expires_at"] = 110.0
    token, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        **source_arguments,
    )
    clock.value = 105.0
    if boundary_kind == "manual":
        marked = await store.mark_reauth_required("session-a")
        assert marked.status is GatewaySessionStatus.REAUTH_REQUIRED

    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(token)

    clock.value = 105.000001
    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_token(token)
    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_session_id("session-a")
    collected = await store.pop_expired_records()
    assert [record.session_id for record in collected] == ["session-a"]
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")


@pytest.mark.anyio
async def test_purge_removes_old_reauth_session_and_create_recovers_capacity() -> None:
    clock = Clock()
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=10,
        clock=clock,
        token_generator=lambda: next(generator),
    )
    token_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
        source_refresh_at=105.0,
        source_expires_at=108.0,
    )
    clock.value = 105.0
    with pytest.raises(GatewayReauthRequiredError):
        await store.resolve_token(token_a)
    clock.value = 111.0

    token_b, record_b = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )

    assert await store.resolve_token(token_b) == record_b


@pytest.mark.anyio
async def test_mark_reauth_after_gateway_ttl_expires_but_retains_for_collection() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    token, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 105.000001

    with pytest.raises(GatewaySessionExpiredError):
        await store.mark_reauth_required("session-a")
    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_token(token)
    assert await store.pop_expired_records() == (record,)


@pytest.mark.anyio
async def test_expired_resolve_retains_record_until_revoke_token_collects_it() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    token, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 106.0

    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_token(token)
    assert await store.revoke_token(token) == record
    assert await store.revoke_token(token) is None
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token)


@pytest.mark.anyio
async def test_expired_session_id_resolve_retains_record_for_lifecycle_revoke() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    _, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 106.0

    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_session_id("session-a")
    assert await store.revoke_session("session-a") == record


@pytest.mark.anyio
async def test_purge_and_create_capacity_return_every_removed_record_directly() -> None:
    clock = Clock()
    generator = _tokens("a" * 43, "b" * 43, "c" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: next(generator),
    )
    _, record_a = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 106.0
    assert await store.purge_expired() == (record_a,)
    assert await store.pop_expired_records() == ()

    _, record_b = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )
    clock.value = 112.0
    creation_c = await store.create(
        session_id="session-c",
        principal_context=_context("c", "session-c"),
    )

    assert creation_c.removed_records == (record_b,)
    assert await store.pop_expired_records() == ()
    assert (await store.resolve_session_id("session-c")) == creation_c.record


@pytest.mark.anyio
async def test_close_returns_all_removed_records_once_directly() -> None:
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: next(generator),
    )
    _, record_a = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    _, record_b = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )

    collected = await store.close()
    assert {record.session_id for record in collected} == {"session-a", "session-b"}
    assert record_a in collected
    assert record_b in collected
    assert await store.close() == ()
    assert await store.pop_expired_records() == ()


@pytest.mark.anyio
async def test_cancelled_expired_collector_drops_store_token_graph() -> None:
    token_a = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
    token_b = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=TokenGenerator(token_a, token_b),
    )
    await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    await store._lock.acquire()
    collecting = asyncio.create_task(store.pop_expired_records())
    await asyncio.sleep(0)
    collecting.cancel()
    store._lock.release()

    with pytest.raises(asyncio.CancelledError) as caught:
        await collecting

    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_a)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_b)


@pytest.mark.anyio
async def test_nonfinite_clock_does_not_collect_or_lose_expired_record() -> None:
    clock = Clock()
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: "a" * 43,
    )
    _, record = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = float("nan")
    with pytest.raises(GatewaySessionInvalidError):
        await store.pop_expired_records()

    clock.value = 106.0
    assert await store.pop_expired_records() == (record,)


@pytest.mark.anyio
async def test_create_atomically_returns_each_expired_same_id_generation() -> None:
    clock = Clock()
    generator = _tokens("a" * 43, "b" * 43, "c" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=lambda: next(generator),
    )
    first = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 106.0
    second = await store.create(
        session_id="session-a",
        principal_context=_context("a2", "session-a"),
    )
    clock.value = 112.0
    third = await store.create(
        session_id="session-a",
        principal_context=_context("a3", "session-a"),
    )

    assert first.removed_records == ()
    assert second.removed_records == (first.record,)
    assert third.removed_records == (second.record,)
    assert not hasattr(store, "_removed_records")
    assert len(store._by_digest) == 1
    assert await store.pop_expired_records() == ()


@pytest.mark.anyio
async def test_failed_create_does_not_remove_expired_record_without_handoff() -> None:
    clock = Clock()
    generator = TokenGenerator("a" * 43, "invalid-next-generation-token")
    store = InMemoryGatewaySessionStore(
        max_sessions=1,
        ttl_seconds=5,
        clock=clock,
        token_generator=generator,
    )
    first = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 106.0

    with pytest.raises(GatewaySessionInvalidError):
        await store.create(
            session_id="session-b",
            principal_context=_context("b", "session-b"),
        )

    assert await store.pop_expired_records() == (first.record,)


@pytest.mark.anyio
async def test_close_and_revoke_return_removed_records_directly() -> None:
    generator = _tokens("a" * 43, "b" * 43)
    store = InMemoryGatewaySessionStore(
        max_sessions=2,
        ttl_seconds=60,
        clock=Clock(),
        token_generator=lambda: next(generator),
    )
    first = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    second = await store.create(
        session_id="session-b",
        principal_context=_context("b", "session-b"),
    )

    assert await store.revoke("session-a") == first.record
    assert await store.revoke("session-a") is None
    assert await store.close() == (second.record,)
    assert await store.close() == ()
