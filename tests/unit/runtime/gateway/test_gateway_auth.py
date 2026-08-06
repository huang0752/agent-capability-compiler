from __future__ import annotations

import asyncio
import types
from collections.abc import Iterator, Mapping

import pytest
from mcp.server.auth.provider import AccessToken, TokenVerifier

from acc_runtime.context import PrincipalContext
from acc_runtime.gateway.auth import GatewayPrincipalResolver, GatewayTokenVerifier
from acc_runtime.gateway.models import GatewaySessionRecord, GatewaySessionStatus
from acc_runtime.gateway.sessions import (
    GatewayReauthRequiredError,
    GatewaySessionExpiredError,
    GatewaySessionInvalidError,
)


def _context(session_id: str, principal: str = "user-a") -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal,
        gateway_session_id=session_id,
        target_system_id="project-a",
        source_scopes={"source.read"},
        deployment_scope_ceiling={"customer.read"},
        scope_mapping={"source.read": {"customer.read"}},
        tenant_context={"tenant_id": principal},
        auth_state_handle=f"auth-{session_id}",
    )


def _record(session_id: str, *, expires_at: float = 140.0) -> GatewaySessionRecord:
    return GatewaySessionRecord(
        session_id=session_id,
        token_digest="a" * 64,
        principal_context=_context(session_id),
        created_at=100.0,
        expires_at=expires_at,
        status=GatewaySessionStatus.ACTIVE,
    )


class FakeStore:
    def __init__(self, record: GatewaySessionRecord) -> None:
        self.record = record
        self.token_calls: list[str] = []
        self.session_calls: list[str] = []
        self.token_error: Exception | None = None
        self.session_error: Exception | None = None

    async def resolve_token(self, token: str) -> GatewaySessionRecord:
        self.token_calls.append(token)
        if self.token_error:
            raise self.token_error
        return self.record

    async def resolve_session_id(self, session_id: str) -> GatewaySessionRecord:
        self.session_calls.append(session_id)
        if self.session_error:
            raise self.session_error
        return self.record


@pytest.mark.asyncio
async def test_gateway_verifier_uses_public_sdk_contract_and_wall_clock_expiry() -> None:
    store = FakeStore(_record("session-a", expires_at=140.0))
    verifier: TokenVerifier = GatewayTokenVerifier(
        store=store,
        project_id="project-a",
        monotonic_clock=lambda: 110.0,
        wall_clock=lambda: 1_800_000_000.0,
    )

    access = await verifier.verify_token("opaque-gateway-token")

    assert access is not None
    assert access.token == "opaque-gateway-token"
    assert access.client_id == "project-a"
    assert access.subject == "session-a"
    assert access.scopes == ["customer.read"]
    assert access.expires_at == 1_800_000_030
    assert access.claims == {"iss": "acc-gateway"}
    assert access.resource is None
    assert store.token_calls == ["opaque-gateway-token"]
    dumped = access.model_dump()
    assert "principal" not in repr(dumped).lower()
    assert "tenant" not in repr(dumped).lower()
    assert "source.read" not in repr(dumped)


@pytest.mark.asyncio
async def test_gateway_verifier_rechecks_store_and_maps_session_failures_to_none() -> None:
    store = FakeStore(_record("session-a"))
    verifier = GatewayTokenVerifier(
        store=store,
        project_id="project-a",
        monotonic_clock=lambda: 110.0,
        wall_clock=lambda: 1_800_000_000.0,
    )

    assert await verifier.verify_token("one") is not None
    store.token_error = GatewayReauthRequiredError("private")
    assert await verifier.verify_token("one") is None
    store.token_error = GatewaySessionInvalidError("private")
    assert await verifier.verify_token("one") is None
    store.token_error = GatewaySessionExpiredError("private")
    assert await verifier.verify_token("one") is None
    assert store.token_calls == ["one", "one", "one", "one"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_type"),
    [
        (GatewaySessionInvalidError("private"), GatewaySessionInvalidError),
        (GatewaySessionExpiredError("private"), GatewaySessionExpiredError),
        (GatewayReauthRequiredError("private"), GatewayReauthRequiredError),
    ],
)
async def test_principal_resolver_preserves_stable_session_error_semantics(
    error: Exception,
    expected_type: type[Exception],
) -> None:
    store = FakeStore(_record("session-a"))
    store.session_error = error
    access = AccessToken(
        token="opaque",
        client_id="project-a",
        scopes=[],
        subject="session-a",
        claims={"iss": "acc-gateway"},
    )
    with pytest.raises(expected_type) as caught:
        await GatewayPrincipalResolver(store=store, project_id="project-a").resolve(access)
    assert caught.value.to_dict()["details"] == {}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_gateway_verifier_rejects_record_for_another_project_or_session() -> None:
    store = FakeStore(_record("session-b"))
    verifier = GatewayTokenVerifier(
        store=store,
        project_id="project-a",
        monotonic_clock=lambda: 110.0,
        wall_clock=lambda: 1_800_000_000.0,
    )
    assert await verifier.verify_token("opaque") is not None

    store.record = store.record.model_copy(update={"session_id": "session-a"})
    assert await verifier.verify_token("opaque") is None

    store.record = store.record.model_copy(
        update={
            "session_id": "session-a",
            "principal_context": PrincipalContext(
                principal_id="user-a",
                gateway_session_id="session-a",
                target_system_id="project-b",
                source_scopes={"source.read"},
                deployment_scope_ceiling={"customer.read"},
                scope_mapping={"source.read": {"customer.read"}},
                tenant_context=None,
                auth_state_handle="auth-a",
            ),
        }
    )
    assert await verifier.verify_token("opaque") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"client_id": "project-b"},
        {"subject": "session-b"},
        {"claims": {"iss": "other"}},
        {"claims": None},
    ],
)
async def test_principal_resolver_rejects_wrong_access_token_identity(
    change: dict[str, object],
) -> None:
    store = FakeStore(_record("session-a"))
    resolver = GatewayPrincipalResolver(store=store, project_id="project-a")
    values: dict[str, object] = {
        "token": "opaque",
        "client_id": "project-a",
        "scopes": ["customer.read"],
        "subject": "session-a",
        "claims": {"iss": "acc-gateway"},
    }
    values.update(change)

    with pytest.raises(GatewaySessionInvalidError):
        await resolver.resolve(AccessToken.model_validate(values))

    assert store.session_calls == (["session-b"] if change.get("subject") == "session-b" else [])


@pytest.mark.asyncio
async def test_principal_resolver_rechecks_store_every_time_and_never_uses_claim_context() -> None:
    store = FakeStore(_record("session-a"))
    resolver = GatewayPrincipalResolver(store=store, project_id="project-a")
    access = AccessToken(
        token="opaque",
        client_id="project-a",
        scopes=["forged.scope"],
        subject="session-a",
        claims={"iss": "acc-gateway"},
    )

    first = await resolver.resolve(access)
    store.record = _record("session-a")
    second = await resolver.resolve(access)

    assert first.principal_id == second.principal_id == "user-a"
    assert first.effective_scopes == second.effective_scopes == frozenset({"customer.read"})
    assert store.session_calls == ["session-a", "session-a"]


@pytest.mark.asyncio
async def test_principal_resolver_rejects_store_record_bound_to_another_session_or_project() -> (
    None
):
    access = AccessToken(
        token="opaque",
        client_id="project-a",
        scopes=[],
        subject="session-a",
        claims={"iss": "acc-gateway"},
    )
    wrong_session = FakeStore(_record("session-b"))
    with pytest.raises(GatewaySessionInvalidError):
        await GatewayPrincipalResolver(store=wrong_session, project_id="project-a").resolve(access)

    wrong_project_record = _record("session-a").model_copy(
        update={
            "principal_context": _context("session-a").__class__(
                principal_id="user-a",
                gateway_session_id="session-a",
                target_system_id="project-b",
                source_scopes={"source.read"},
                deployment_scope_ceiling={"customer.read"},
                scope_mapping={"source.read": {"customer.read"}},
                tenant_context=None,
                auth_state_handle="auth-a",
            )
        }
    )
    with pytest.raises(GatewaySessionInvalidError):
        await GatewayPrincipalResolver(
            store=FakeStore(wrong_project_record), project_id="project-a"
        ).resolve(access)


def _reachable_values(error: BaseException) -> Iterator[object]:
    pending: list[object] = []
    traceback = error.__traceback__
    while traceback:
        if "/packages/acc-runtime/" in traceback.tb_frame.f_code.co_filename:
            pending.extend(traceback.tb_frame.f_locals.values())
        traceback = traceback.tb_next
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        yield value
        if isinstance(value, (str, bytes, bytearray, int, float, bool, type(None))):
            continue
        if isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
        elif isinstance(value, BaseException):
            pending.extend((value.args, value.__cause__, value.__context__))
        elif isinstance(value, (types.FunctionType, types.MethodType, type)):
            continue
        else:
            namespace = getattr(value, "__dict__", None)
            if isinstance(namespace, dict):
                pending.extend(namespace.values())
            slots = getattr(type(value), "__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            for slot in slots:
                if isinstance(slot, str) and hasattr(value, slot):
                    pending.append(getattr(value, slot))


@pytest.mark.asyncio
async def test_cancel_traceback_cannot_reach_token_or_other_context() -> None:
    secret = "cancelled-raw-gateway-token"
    other_secret = "other-users-secret-context-marker"

    class CancellingStore(FakeStore):
        async def resolve_token(self, token: str) -> GatewaySessionRecord:
            raise asyncio.CancelledError

        async def resolve_session_id(self, session_id: str) -> GatewaySessionRecord:
            raise asyncio.CancelledError

    store = CancellingStore(_record("session-b"))
    # Make the store object graph itself sensitive, as a realistic multi-user store is.
    store.other_user = {"secret": other_secret}  # type: ignore[attr-defined]
    verifier = GatewayTokenVerifier(store=store, project_id="project-a")
    with pytest.raises(asyncio.CancelledError) as verify_caught:
        await verifier.verify_token(secret)
    reachable = tuple(_reachable_values(verify_caught.value))
    assert not any(secret in value for value in reachable if isinstance(value, str))
    assert not any(other_secret in value for value in reachable if isinstance(value, str))

    access = AccessToken(
        token=secret,
        client_id="project-a",
        scopes=[],
        subject="session-a",
        claims={"iss": "acc-gateway"},
    )
    resolver = GatewayPrincipalResolver(store=store, project_id="project-a")
    with pytest.raises(asyncio.CancelledError) as resolve_caught:
        await resolver.resolve(access)
    reachable = tuple(_reachable_values(resolve_caught.value))
    assert access not in reachable
    assert not any(secret in value for value in reachable if isinstance(value, str))
    assert not any(other_secret in value for value in reachable if isinstance(value, str))
