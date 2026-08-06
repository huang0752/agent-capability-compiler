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
    token, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )

    await store.revoke("session-a")
    await store.revoke("session-a")

    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_token(token)
    with pytest.raises(GatewaySessionInvalidError):
        await store.resolve_session_id("session-a")


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
    token_a, _ = await store.create(
        session_id="session-a",
        principal_context=_context("a", "session-a"),
    )
    clock.value = 110.0

    with pytest.raises(GatewaySessionExpiredError):
        await store.resolve_token(token_a)
    assert await store.purge_expired() == 0

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
async def test_non_utf8_gateway_token_is_stably_rejected_without_leaking() -> None:
    invalid_token = "surrogate-token-secret-\ud800"
    store = InMemoryGatewaySessionStore(max_sessions=1, ttl_seconds=60, clock=Clock())

    with pytest.raises(GatewaySessionInvalidError) as caught:
        await store.resolve_token(SecretValue(invalid_token))

    assert caught.value.code == "ACC_GATEWAY_SESSION_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    _assert_runtime_traceback_cannot_reach_secret(caught.value, invalid_token)


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
@pytest.mark.parametrize("operation", ["mark_reauth", "revoke"])
async def test_cancelled_session_mutation_drops_store_token_graph(operation: str) -> None:
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
    call = (
        store.mark_reauth_required("session-a")
        if operation == "mark_reauth"
        else store.revoke("session-a")
    )
    task = asyncio.create_task(call)
    await asyncio.sleep(0)
    task.cancel()
    store._lock.release()

    with pytest.raises(asyncio.CancelledError) as caught:
        await task

    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_a)
    _assert_runtime_traceback_cannot_reach_secret(caught.value, token_b)
