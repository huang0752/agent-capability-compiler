from __future__ import annotations

import asyncio
import gzip
import json
import logging
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from typing import cast

import httpx
import pytest
from pydantic import ValidationError

from acc_core.models import (
    EnvironmentSecretCredentials,
    PasswordBearerAuthConfig,
)
from acc_runtime.auth import (
    AuthAttempt,
    AuthCredentialError,
    AuthenticationResult,
    AuthInvalidResponseError,
    AuthLoginRejectedError,
    AuthReauthenticationRequiredError,
    AuthRequestError,
    AuthResponseTooLargeError,
    AuthTimeoutError,
    AuthUpstreamError,
    BearerSecretAuthStrategy,
    CredentialPair,
    CredentialSource,
    EnvironmentCredentialSource,
    HttpAuthStrategy,
    NoAuthStrategy,
    OneShotCredentialSource,
    PasswordBearerAuthStrategy,
)
from acc_runtime.context import AuthStateKey, PrincipalContext
from acc_runtime.credentials import SecretValue


class _Clock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class _CredentialSource:
    def __init__(
        self,
        *,
        identity: str = "alice@example.test",
        password: str = "private-password",
        renewable: bool = True,
    ) -> None:
        self.renewable = renewable
        self.calls: list[AuthStateKey] = []
        self._identity = identity
        self._password = password

    def __repr__(self) -> str:
        return "_CredentialSource([REDACTED])"

    async def acquire(self, auth_state_key: AuthStateKey) -> CredentialPair:
        self.calls.append(auth_state_key)
        return CredentialPair(
            identity=SecretValue(self._identity),
            password=SecretValue(self._password),
        )


def _context(
    principal_id: str = "user-a",
    *,
    session_id: str | None = None,
    auth_state_handle: str = "auth-state-a",
) -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal_id,
        gateway_session_id=session_id,
        target_system_id="crm",
        source_scopes=set(),
        deployment_scope_ceiling=set(),
        tenant_context=None,
        auth_state_handle=auth_state_handle,
    )


def _config(**changes: object) -> PasswordBearerAuthConfig:
    values: dict[str, object] = {
        "kind": "password_bearer",
        "credentials": {
            "kind": "environment_secret",
            "identity_ref": "CRM_IDENTITY",
            "password_ref": "CRM_PASSWORD",
        },
        "login_path": "/api/auth/login",
        "identity_field": "email",
        "password_field": "password",
        "token_pointer": "/access_token",
    }
    values.update(changes)
    return PasswordBearerAuthConfig.model_validate(values)


def _client_factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[[], httpx.AsyncClient]:
    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return factory


def _password_strategy(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    config: PasswordBearerAuthConfig | None = None,
    source: CredentialSource | None = None,
    clock: Callable[[], float] | None = None,
) -> PasswordBearerAuthStrategy:
    return PasswordBearerAuthStrategy(
        config=config or _config(),
        base_url="https://crm.example.test",
        credential_source=source or _CredentialSource(),
        client_factory=_client_factory(handler),
        clock=clock,
    )


def _authorization(result: AuthenticationResult | AuthAttempt) -> str | None:
    authorization = (
        result.authorization
        if isinstance(result, AuthenticationResult)
        else result.headers.get("Authorization")
    )
    if authorization is None:
        return None
    return authorization.get_secret_value()


@pytest.mark.asyncio
async def test_no_auth_strategy_returns_no_headers_or_identity_metadata() -> None:
    strategy: HttpAuthStrategy = NoAuthStrategy()

    result = await strategy.headers(_context())

    assert result.headers == {}
    assert result.state_key == _context().auth_state_key
    assert result.generation == 0
    assert await strategy.on_unauthorized(_context(), result) is False


@pytest.mark.asyncio
async def test_bearer_secret_strategy_resolves_environment_each_time() -> None:
    environment = {"CRM_TOKEN": "token-one"}
    strategy = BearerSecretAuthStrategy("CRM_TOKEN", environment=environment)

    first = await strategy.headers(_context())
    environment["CRM_TOKEN"] = "token-two"
    second = await strategy.headers(_context())

    assert _authorization(first) == "Bearer token-one"
    assert _authorization(second) == "Bearer token-two"
    assert await strategy.on_unauthorized(_context(), first) is True


@pytest.mark.asyncio
async def test_auth_strategies_wrap_missing_environment_secrets_in_auth_error_family() -> None:
    bearer = BearerSecretAuthStrategy("CRM_TOKEN", environment={})
    password = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=EnvironmentCredentialSource(
            EnvironmentSecretCredentials(
                kind="environment_secret",
                identity_ref="CRM_IDENTITY",
                password_ref="CRM_PASSWORD",
            ),
            environment={},
        ),
        client_factory=_client_factory(
            lambda _request: httpx.Response(200, json={"access_token": "token"})
        ),
    )

    for strategy in (bearer, password):
        with pytest.raises(AuthCredentialError) as caught:
            await strategy.headers(_context())
        assert caught.value.code == "ACC_RUNTIME_AUTH_CREDENTIAL_INVALID"
        assert caught.value.details == {}


@pytest.mark.asyncio
async def test_environment_credential_source_is_renewable_and_reloads_both_secrets() -> None:
    environment = {"CRM_IDENTITY": "alice", "CRM_PASSWORD": "first-password"}
    source = EnvironmentCredentialSource(
        EnvironmentSecretCredentials(
            kind="environment_secret",
            identity_ref="CRM_IDENTITY",
            password_ref="CRM_PASSWORD",
        ),
        environment=environment,
    )
    key = _context().auth_state_key

    first = await source.acquire(key)
    environment["CRM_IDENTITY"] = "bob"
    environment["CRM_PASSWORD"] = "second-password"
    second = await source.acquire(key)

    assert source.renewable is True
    assert first.identity.get_secret_value() == "alice"
    assert first.password.get_secret_value() == "first-password"
    assert second.identity.get_secret_value() == "bob"
    assert second.password.get_secret_value() == "second-password"


def test_gateway_one_shot_source_is_an_interface_not_a_runtime_store() -> None:
    assert CredentialSource in OneShotCredentialSource.__mro__
    assert "consume" in OneShotCredentialSource.__dict__
    assert "acquire" not in OneShotCredentialSource.__dict__
    assert not hasattr(OneShotCredentialSource, "save")
    assert not hasattr(OneShotCredentialSource, "get_session")


@pytest.mark.asyncio
async def test_password_login_sends_only_the_two_declared_fields() -> None:
    source = _CredentialSource(identity="alice@example.test", password="private-password")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == "https://crm.example.test/api/auth/login"
        assert json.loads(request.content) == {
            "account": "alice@example.test",
            "passcode": "private-password",
        }
        assert request.headers.get("authorization") is None
        return httpx.Response(200, json={"access_token": "source-token"})

    strategy = _password_strategy(
        handler,
        config=_config(identity_field="account", password_field="passcode"),
        source=source,
    )

    result = await strategy.headers(_context())

    assert _authorization(result) == "Bearer source-token"
    assert source.calls == [_context().auth_state_key]


@pytest.mark.asyncio
async def test_password_login_resolves_every_configured_json_pointer() -> None:
    response = {
        "payload": {
            "items": [{"access/token": "source-token"}],
            "meta": {"token~type": "bearer", "expires": 120},
            "user": {
                "id": "user-from-source",
                "permissions": ["customer:read", "customer:audit"],
                "tenant": {"tenant_id": "tenant-a", "region": {"id": 7}},
            },
        }
    }

    strategy = _password_strategy(
        lambda _request: httpx.Response(200, json=response),
        config=_config(
            token_pointer="/payload/items/0/access~1token",
            token_type_pointer="/payload/meta/token~0type",
            expires_in_pointer="/payload/meta/expires",
            principal_pointer="/payload/user/id",
            scopes_pointer="/payload/user/permissions",
            tenant_pointer="/payload/user/tenant",
        ),
        clock=_Clock(500.0),
    )

    result = await strategy.headers(_context())

    assert _authorization(result) == "Bearer source-token"
    assert result.authentication.principal_id == "user-from-source"
    assert result.authentication.source_scopes == frozenset({"customer:read", "customer:audit"})
    assert result.authentication.tenant_context == {
        "tenant_id": "tenant-a",
        "region": {"id": 7},
    }
    assert result.authentication.expires_at == 620.0


def test_password_auth_response_size_defaults_to_64_kib_and_is_capped_at_1_mib() -> None:
    assert _config().max_response_bytes == 65_536
    assert _config(max_response_bytes=1_048_576).max_response_bytes == 1_048_576
    with pytest.raises(ValidationError):
        _config(max_response_bytes=1_048_577)


@pytest.mark.parametrize(
    ("expires_in", "before_refresh", "at_refresh"),
    [(100, 89.999, 90.0), (400, 369.999, 370.0)],
)
@pytest.mark.asyncio
async def test_password_token_refresh_margin_is_minimum_of_30_seconds_and_ten_percent(
    expires_in: int,
    before_refresh: float,
    at_refresh: float,
) -> None:
    clock = _Clock(1_000.0)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={"access_token": f"token-{calls}", "expires_in": expires_in},
        )

    strategy = _password_strategy(
        handler,
        config=_config(expires_in_pointer="/expires_in"),
        clock=clock,
    )
    context = _context()

    first = await strategy.headers(context)
    clock.now = 1_000.0 + before_refresh
    cached = await strategy.headers(context)
    clock.now = 1_000.0 + at_refresh
    refreshed_attempts = await asyncio.gather(*(strategy.headers(context) for _ in range(8)))

    assert _authorization(first) == "Bearer token-1"
    assert cached is first
    assert _authorization(refreshed_attempts[0]) == "Bearer token-2"
    assert len({id(attempt) for attempt in refreshed_attempts}) == 1
    assert calls == 2


@pytest.mark.asyncio
async def test_concurrent_first_login_is_single_flight_per_auth_state_key() -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return httpx.Response(200, json={"access_token": "shared-token"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    context = _context()

    results = await asyncio.gather(*(strategy.headers(context) for _ in range(12)))

    assert calls == 1
    assert len({id(result) for result in results}) == 1
    assert all(isinstance(result, AuthAttempt) for result in results)
    assert results[0].state_key == context.auth_state_key
    assert results[0].generation == 1
    assert "shared-token" not in repr(results[0])


@pytest.mark.asyncio
async def test_concurrent_401_refreshes_once_and_old_generation_cannot_clear_new_token() -> None:
    login_calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        login_calls += 1
        await asyncio.sleep(0.01)
        return httpx.Response(200, json={"access_token": f"token-{login_calls}"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    context = _context()
    failed_attempt = await strategy.headers(context)

    retryable = await asyncio.gather(
        *(strategy.on_unauthorized(context, failed_attempt) for _ in range(8))
    )
    refreshed = await asyncio.gather(*(strategy.headers(context) for _ in range(8)))
    stale_retryable = await strategy.on_unauthorized(context, failed_attempt)
    still_current = await strategy.headers(context)

    assert all(retryable)
    assert stale_retryable is True
    assert failed_attempt.generation == 1
    assert refreshed[0].generation == 2
    assert len({id(attempt) for attempt in refreshed}) == 1
    assert still_current is refreshed[0]
    assert login_calls == 2


@pytest.mark.asyncio
async def test_different_auth_state_keys_can_login_in_parallel() -> None:
    active = 0
    maximum_active = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.03)
        active -= 1
        return httpx.Response(200, json={"access_token": "token"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )

    await asyncio.gather(
        strategy.headers(_context("user-a", auth_state_handle="state-a")),
        strategy.headers(_context("user-b", auth_state_handle="state-b")),
    )

    assert maximum_active == 2


@pytest.mark.asyncio
async def test_auth_state_is_isolated_by_full_auth_state_key() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"access_token": f"token-{calls}"})

    strategy = _password_strategy(handler)
    contexts = [
        _context("user-a", session_id="session-a", auth_state_handle="shared"),
        _context("user-b", session_id="session-a", auth_state_handle="shared"),
        _context("user-a", session_id="session-b", auth_state_handle="shared"),
    ]

    results = [await strategy.headers(context) for context in contexts]

    assert [_authorization(result) for result in results] == [
        "Bearer token-1",
        "Bearer token-2",
        "Bearer token-3",
    ]
    assert calls == 3


@pytest.mark.parametrize("status_code", [400, 401, 403, 429])
@pytest.mark.asyncio
async def test_password_login_maps_4xx_to_safe_rejected_error(status_code: int) -> None:
    strategy = _password_strategy(
        lambda _request: httpx.Response(status_code, text="private-password source-token")
    )

    with pytest.raises(AuthLoginRejectedError) as caught:
        await strategy.headers(_context())

    assert caught.value.code == "ACC_RUNTIME_AUTH_LOGIN_REJECTED"
    assert caught.value.status == 401
    assert caught.value.to_dict()["details"] == {"upstream_status": status_code}
    assert "private-password" not in str(caught.value)
    assert "source-token" not in str(caught.value)


@pytest.mark.parametrize("status_code", [500, 502, 503])
@pytest.mark.asyncio
async def test_password_login_maps_5xx_to_safe_upstream_error(status_code: int) -> None:
    strategy = _password_strategy(lambda _request: httpx.Response(status_code))

    with pytest.raises(AuthUpstreamError) as caught:
        await strategy.headers(_context())

    assert caught.value.code == "ACC_RUNTIME_AUTH_UPSTREAM_ERROR"
    assert caught.value.status == 502
    assert caught.value.to_dict()["details"] == {"upstream_status": status_code}


@pytest.mark.asyncio
async def test_password_login_maps_timeout_and_request_failures_to_stable_errors() -> None:
    timeout = _password_strategy(
        lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("secret", request=request))
    )
    request_failure = _password_strategy(
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("secret", request=request))
    )

    with pytest.raises(AuthTimeoutError) as timeout_caught:
        await timeout.headers(_context())
    with pytest.raises(AuthRequestError) as request_caught:
        await request_failure.headers(_context())

    assert timeout_caught.value.code == "ACC_RUNTIME_AUTH_TIMEOUT"
    assert timeout_caught.value.status == 504
    assert timeout_caught.value.details == {}
    assert request_caught.value.code == "ACC_RUNTIME_AUTH_REQUEST_FAILED"
    assert request_caught.value.status == 502
    assert request_caught.value.details == {}


@pytest.mark.asyncio
async def test_password_login_rejects_declared_and_streamed_oversize_responses() -> None:
    declared = _password_strategy(
        lambda _request: httpx.Response(
            200,
            headers={"Content-Length": "65"},
            content=b"{}",
        ),
        config=_config(max_response_bytes=64),
    )
    streamed = _password_strategy(
        lambda _request: httpx.Response(200, content=b"x" * 65),
        config=_config(max_response_bytes=64),
    )

    for strategy in (declared, streamed):
        with pytest.raises(AuthResponseTooLargeError) as caught:
            await strategy.headers(_context())
        assert caught.value.code == "ACC_RUNTIME_AUTH_RESPONSE_TOO_LARGE"
        assert caught.value.details == {"limit_bytes": 64}


@pytest.mark.asyncio
async def test_password_login_limits_decompressed_bytes_and_stops_at_limit_plus_one() -> None:
    expanded = json.dumps({"access_token": "x" * 200}).encode()
    compressed = gzip.compress(expanded)
    assert len(compressed) < len(expanded)
    compressed_strategy = _password_strategy(
        lambda _request: httpx.Response(
            200,
            content=compressed,
            headers={"Content-Encoding": "gzip"},
        ),
        config=_config(max_response_bytes=128),
    )

    with pytest.raises(AuthResponseTooLargeError):
        await compressed_strategy.headers(_context())

    class CountingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.yields = 0

        async def __aiter__(self):  # type: ignore[no-untyped-def]
            for _ in range(4):
                self.yields += 1
                yield b"x" * 32

    stream = CountingStream()
    streamed_strategy = _password_strategy(
        lambda _request: httpx.Response(200, stream=stream),
        config=_config(max_response_bytes=64),
    )

    with pytest.raises(AuthResponseTooLargeError):
        await streamed_strategy.headers(_context("user-b", auth_state_handle="state-b"))
    assert stream.yields == 3


@pytest.mark.parametrize("body", [b"not-json private-password", b'{"value": NaN}'])
@pytest.mark.asyncio
async def test_password_login_rejects_non_json_without_echoing_body(body: bytes) -> None:
    strategy = _password_strategy(lambda _request: httpx.Response(200, content=body))

    with pytest.raises(AuthInvalidResponseError) as caught:
        await strategy.headers(_context())

    assert caught.value.code == "ACC_RUNTIME_AUTH_INVALID_RESPONSE"
    assert caught.value.details == {"reason": "invalid_json"}
    assert "private-password" not in str(caught.value)


@pytest.mark.parametrize(
    ("config_changes", "response", "reason"),
    [
        ({}, {}, "missing_token"),
        ({}, {"access_token": 7}, "invalid_token"),
        ({}, {"access_token": ""}, "invalid_token"),
        (
            {"token_type_pointer": "/token_type"},
            {"access_token": "token"},
            "missing_token_type",
        ),
        (
            {"token_type_pointer": "/token_type"},
            {"access_token": "token", "token_type": 7},
            "invalid_token_type",
        ),
        (
            {"token_type_pointer": "/token_type"},
            {"access_token": "token", "token_type": "Basic"},
            "invalid_token_type",
        ),
        (
            {"expires_in_pointer": "/expires_in"},
            {"access_token": "token"},
            "missing_expiry",
        ),
        (
            {"expires_in_pointer": "/expires_in"},
            {"access_token": "token", "expires_in": True},
            "invalid_expiry",
        ),
        (
            {"expires_in_pointer": "/expires_in"},
            {"access_token": "token", "expires_in": 0},
            "invalid_expiry",
        ),
        (
            {"expires_in_pointer": "/expires_in"},
            {"access_token": "token", "expires_in": "60"},
            "invalid_expiry",
        ),
        (
            {"principal_pointer": "/user/id"},
            {"access_token": "token", "user": {"id": 7}},
            "invalid_principal",
        ),
        (
            {"scopes_pointer": "/permissions"},
            {"access_token": "token", "permissions": "customer:read"},
            "invalid_scopes",
        ),
        (
            {"scopes_pointer": "/permissions"},
            {"access_token": "token", "permissions": ["customer:read", 7]},
            "invalid_scopes",
        ),
        (
            {"tenant_pointer": "/tenant"},
            {"access_token": "token", "tenant": "tenant-a"},
            "invalid_tenant",
        ),
    ],
)
@pytest.mark.asyncio
async def test_password_login_rejects_missing_or_wrong_typed_pointer_values(
    config_changes: Mapping[str, object],
    response: object,
    reason: str,
) -> None:
    strategy = _password_strategy(
        lambda _request: httpx.Response(200, json=response),
        config=_config(**config_changes),
    )

    with pytest.raises(AuthInvalidResponseError) as caught:
        await strategy.headers(_context())

    assert caught.value.details == {"reason": reason}


@pytest.mark.parametrize("expires_in", [float("inf"), float("nan"), -1.0])
@pytest.mark.asyncio
async def test_password_login_rejects_non_finite_or_negative_expiry(expires_in: float) -> None:
    strategy = _password_strategy(
        lambda _request: httpx.Response(
            200,
            content=json.dumps({"access_token": "token", "expires_in": expires_in}).encode(),
        ),
        config=_config(expires_in_pointer="/expires_in"),
    )

    with pytest.raises(AuthInvalidResponseError) as caught:
        await strategy.headers(_context())

    assert caught.value.details == {
        "reason": "invalid_json" if expires_in != -1 else "invalid_expiry"
    }


@pytest.mark.asyncio
async def test_password_login_does_not_follow_redirects_and_validates_final_origin() -> None:
    calls: list[str] = []

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil.example/token"})

    redirect_strategy = _password_strategy(redirect_handler)
    with pytest.raises(AuthLoginRejectedError) as redirect_caught:
        await redirect_strategy.headers(_context())
    assert redirect_caught.value.details == {"upstream_status": 302}
    assert calls == ["https://crm.example.test/api/auth/login"]

    class WrongOriginClient:
        async def __aenter__(self) -> WrongOriginClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        @asynccontextmanager
        async def stream(self, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            assert kwargs["follow_redirects"] is False
            yield httpx.Response(
                200,
                json={"access_token": "token"},
                request=httpx.Request("POST", "https://evil.example/token"),
            )

    wrong_origin_strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=cast(
            Callable[[], httpx.AsyncClient],
            lambda: WrongOriginClient(),
        ),
    )
    with pytest.raises(AuthInvalidResponseError) as origin_caught:
        await wrong_origin_strategy.headers(_context())
    assert origin_caught.value.details == {"reason": "origin_mismatch"}


@pytest.mark.asyncio
async def test_password_login_closes_each_fresh_httpx_client() -> None:
    clients: list[httpx.AsyncClient] = []

    def factory() -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json={"access_token": "token"})
            )
        )
        clients.append(client)
        return client

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=factory,
    )

    await strategy.headers(_context())

    assert len(clients) == 1
    assert clients[0].is_closed is True


@pytest.mark.asyncio
async def test_password_login_never_persists_response_cookies_between_attempts() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers.get("cookie") is None
        return httpx.Response(
            200,
            json={"access_token": f"token-{calls}"},
            headers={"Set-Cookie": "source_session=private-cookie; Path=/"},
        )

    strategy = _password_strategy(handler)
    context = _context()
    first = await strategy.headers(context)
    assert await strategy.on_unauthorized(context, first) is True
    await strategy.headers(context)

    assert calls == 2


@pytest.mark.asyncio
async def test_gateway_authenticates_before_principal_context_then_binds_full_key() -> None:
    login_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        login_calls += 1
        return httpx.Response(
            200,
            json={
                "access_token": "source-token",
                "principal": "source-user-a",
                "permissions": ["customer:read"],
                "tenant": {"tenant_id": "tenant-a"},
            },
        )

    strategy = PasswordBearerAuthStrategy(
        config=_config(
            principal_pointer="/principal",
            scopes_pointer="/permissions",
            tenant_pointer="/tenant",
        ),
        base_url="https://crm.example.test",
        credential_source=None,
        client_factory=_client_factory(handler),
    )
    credentials = CredentialPair(
        identity=SecretValue("alice"),
        password=SecretValue("private-password"),
    )

    login_result = await strategy.authenticate_once(credentials)
    assert isinstance(login_result.token, SecretValue)
    assert login_result.token.get_secret_value() == "source-token"
    assert "source-token" not in repr(login_result)
    assert login_result.principal_id == "source-user-a"
    assert login_result.source_scopes == frozenset({"customer:read"})
    assert login_result.tenant_context == {"tenant_id": "tenant-a"}

    context = _context("user-a", session_id="session-a")
    await strategy.bind_state(context.auth_state_key, login_result, renewable=False)
    bound_result = await strategy.headers(context)

    assert bound_result.authentication is login_result
    assert bound_result.state_key == context.auth_state_key
    assert bound_result.generation == 1
    assert login_calls == 1


@pytest.mark.asyncio
async def test_gateway_bind_rejects_bare_auth_state_handle() -> None:
    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=None,
        client_factory=_client_factory(
            lambda _request: httpx.Response(200, json={"access_token": "source-token"})
        ),
    )
    result = await strategy.authenticate_once(
        CredentialPair(identity=SecretValue("alice"), password=SecretValue("password"))
    )

    with pytest.raises(TypeError, match="AuthStateKey"):
        await strategy.bind_state("auth-state-a", result, renewable=False)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_one_shot_401_marks_reauthentication_required_without_another_login() -> None:
    login_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        login_calls += 1
        return httpx.Response(200, json={"access_token": "source-token"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=None,
        client_factory=_client_factory(handler),
    )
    result = await strategy.authenticate_once(
        CredentialPair(identity=SecretValue("alice"), password=SecretValue("private-password"))
    )
    context = _context("user-a", session_id="session-a")
    await strategy.bind_state(context.auth_state_key, result, renewable=False)

    bound_attempt = await strategy.headers(context)
    retryable = await strategy.on_unauthorized(context, bound_attempt)

    assert retryable is False
    with pytest.raises(AuthReauthenticationRequiredError) as caught:
        await strategy.headers(context)
    assert caught.value.code == "ACC_RUNTIME_AUTH_REAUTHENTICATION_REQUIRED"
    assert login_calls == 1


@pytest.mark.asyncio
async def test_failed_login_keeps_no_partial_state_and_renewable_source_can_retry() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(502)
        return httpx.Response(200, json={"access_token": "recovered-token"})

    source = _CredentialSource()
    strategy = _password_strategy(handler, source=source)
    with pytest.raises(AuthUpstreamError):
        await strategy.headers(_context())

    recovered = await strategy.headers(_context())

    assert _authorization(recovered) == "Bearer recovered-token"
    assert calls == 2
    assert len(source.calls) == 2


@pytest.mark.asyncio
async def test_auth_secrets_do_not_enter_repr_logs_or_errors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    identity = "private-identity@example.test"
    password = "private-password"
    token = "private-source-token"
    source = _CredentialSource(identity=identity, password=password)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": token})

    strategy = _password_strategy(handler, source=source)
    with caplog.at_level(logging.INFO):
        result = await strategy.headers(_context())
        logging.getLogger("acc-runtime-auth-test").info(
            "source=%r strategy=%r result=%r auth=%s",
            source,
            strategy,
            result,
            result.headers.get("Authorization"),
        )

    combined = "\n".join([repr(source), repr(strategy), repr(result), caplog.text])
    assert identity not in combined
    assert password not in combined
    assert token not in combined
    assert "[REDACTED]" in combined
