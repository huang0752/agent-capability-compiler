from __future__ import annotations

import asyncio
import gzip
import json
import logging
import types
from collections.abc import Callable, Mapping
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
    AuthConfigurationError,
    AuthCredentialError,
    AuthenticationResult,
    AuthInvalidResponseError,
    AuthLoginFailedError,
    AuthLoginRejectedError,
    AuthReauthenticationRequiredError,
    AuthRequestError,
    AuthResponseInvalidError,
    AuthResponseTooLargeError,
    AuthSecretMissingError,
    AuthTimeoutError,
    AuthUnauthorizedError,
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
from acc_runtime.credentials import SecretNotFoundError, SecretValue


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


def _assert_exception_graph_has_no_secret(error: BaseException, secret: str) -> None:
    pending: list[object] = [error]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, str):
            assert secret not in value
            continue
        if isinstance(value, bytes):
            assert secret.encode() not in value
            continue
        if isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
            continue
        if isinstance(value, httpx.Request):
            pending.extend([value.headers, value.content, str(value.url)])
            continue
        if isinstance(value, httpx.Response):
            pending.extend([value.headers, value.request])
            if value.is_closed:
                pending.append(value.content)
            continue
        if isinstance(value, BaseException):
            pending.extend(
                [
                    value.args,
                    value.__cause__,
                    value.__context__,
                    getattr(value, "details", None),
                    getattr(value, "request", None),
                    getattr(value, "response", None),
                    getattr(value, "doc", None),
                ]
            )


def _assert_runtime_traceback_locals_have_no_secret(
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
            assert secret.encode() not in value
            continue
        if isinstance(value, SecretValue):
            assert secret not in value.get_secret_value()
            continue
        if isinstance(value, CredentialPair):
            pending.extend([value.identity, value.password])
            continue
        if isinstance(value, json.JSONDecodeError):
            pending.extend([value.doc, value.args])
            continue
        if isinstance(value, httpx.Request):
            pending.extend([value.content, value.headers, str(value.url)])
            continue
        if isinstance(value, httpx.Response):
            pending.extend([value.headers, value.request])
            if value.is_closed:
                pending.append(value.content)
            continue
        if isinstance(value, Mapping):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
            continue
        if isinstance(value, BaseException):
            pending.extend(
                [
                    value.args,
                    value.__cause__,
                    value.__context__,
                    getattr(value, "details", None),
                ]
            )
            continue
        if isinstance(value, asyncio.Task):
            for frame in value.get_stack():
                pending.extend(frame.f_locals.values())
            pending.append(value.get_coro())
            continue
        if isinstance(value, types.CoroutineType):
            if value.cr_frame is not None:
                pending.extend(value.cr_frame.f_locals.values())
            pending.append(value.cr_await)
            continue
        if isinstance(
            value,
            (
                asyncio.Future,
                asyncio.Lock,
                types.FunctionType,
                types.MethodType,
                type,
            ),
        ):
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


def test_auth_error_codes_are_limited_to_the_reviewed_public_taxonomy() -> None:
    assert AuthConfigurationError.code == "ACC_RUNTIME_AUTH_CONFIGURATION_INVALID"
    assert AuthSecretMissingError.code == "ACC_RUNTIME_AUTH_SECRET_MISSING"
    assert AuthCredentialError.code == "ACC_RUNTIME_AUTH_SECRET_MISSING"
    assert AuthLoginFailedError.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
    assert AuthLoginRejectedError.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
    assert AuthUpstreamError.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
    assert AuthRequestError.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
    assert AuthResponseInvalidError.code == "ACC_RUNTIME_AUTH_RESPONSE_INVALID"
    assert AuthInvalidResponseError.code == "ACC_RUNTIME_AUTH_RESPONSE_INVALID"
    assert AuthUnauthorizedError.code == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    assert AuthReauthenticationRequiredError.code == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    assert AuthTimeoutError.code == "ACC_RUNTIME_HTTP_TIMEOUT"
    assert AuthResponseTooLargeError.code == "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"


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
    assert await strategy.on_unauthorized(_context(), first) is False


@pytest.mark.asyncio
async def test_bearer_public_errors_cannot_reach_environment_secret() -> None:
    secret = "bearer-environment-secret-must-not-reach-traceback"
    strategy = BearerSecretAuthStrategy("TOKEN", environment={"TOKEN": secret})
    context_a = _context("user-a", auth_state_handle="state-a")
    context_b = _context("user-b", auth_state_handle="state-b")
    secret_result = AuthenticationResult(token=SecretValue(secret), token_type="Bearer")
    mismatched_attempt = AuthAttempt(
        headers={"Authorization": SecretValue(f"Bearer {secret}")},
        state_key=context_b.auth_state_key,
        generation=1,
        authentication=secret_result,
    )

    with pytest.raises(TypeError) as authorize_caught:
        await strategy.authorize("invalid-context")  # type: ignore[arg-type]
    with pytest.raises(TypeError) as headers_caught:
        await strategy.headers("invalid-context")  # type: ignore[arg-type]
    with pytest.raises(ValueError) as ownership_caught:
        await strategy.on_unauthorized(context_a, mismatched_attempt)
    with pytest.raises(TypeError) as invalidate_caught:
        await strategy.invalidate("invalid-state-key")  # type: ignore[arg-type]

    for error in (
        authorize_caught.value,
        headers_caught.value,
        ownership_caught.value,
        invalidate_caught.value,
    ):
        _assert_runtime_traceback_locals_have_no_secret(error, secret)


@pytest.mark.asyncio
async def test_bearer_credential_error_cannot_reach_invalid_environment_secret() -> None:
    secret = "bearer-invalid-environment-secret"
    strategy = BearerSecretAuthStrategy(
        "TOKEN",
        environment={"TOKEN": f"{secret}\n"},
    )

    with pytest.raises(AuthCredentialError) as caught:
        await strategy.authorize(_context())

    _assert_runtime_traceback_locals_have_no_secret(caught.value, secret)


@pytest.mark.asyncio
async def test_no_auth_public_errors_clear_strategy_and_arguments() -> None:
    secret = "no-auth-strategy-sensitive-marker"

    class SensitiveNoAuthStrategy(NoAuthStrategy):
        def __init__(self) -> None:
            self.sensitive_marker = secret

    strategy = SensitiveNoAuthStrategy()
    context_a = _context("user-a", auth_state_handle="state-a")
    context_b = _context("user-b", auth_state_handle="state-b")
    secret_result = AuthenticationResult(token=SecretValue(secret), token_type="Bearer")
    mismatched_attempt = AuthAttempt(
        headers={"Authorization": SecretValue(f"Bearer {secret}")},
        state_key=context_b.auth_state_key,
        generation=1,
        authentication=secret_result,
    )

    with pytest.raises(TypeError) as authorize_caught:
        await strategy.authorize("invalid-context")  # type: ignore[arg-type]
    with pytest.raises(TypeError) as headers_caught:
        await strategy.headers("invalid-context")  # type: ignore[arg-type]
    with pytest.raises(ValueError) as ownership_caught:
        await strategy.on_unauthorized(context_a, mismatched_attempt)
    with pytest.raises(TypeError) as invalidate_caught:
        await strategy.invalidate("invalid-state-key")  # type: ignore[arg-type]

    for error in (
        authorize_caught.value,
        headers_caught.value,
        ownership_caught.value,
        invalidate_caught.value,
    ):
        _assert_runtime_traceback_locals_have_no_secret(error, secret)


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
        assert caught.value.code == "ACC_RUNTIME_AUTH_SECRET_MISSING"
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
        config=_config(retry_on_unauthorized=True),
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
        config=_config(retry_on_unauthorized=True),
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

    assert caught.value.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
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

    assert caught.value.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
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

    assert timeout_caught.value.code == "ACC_RUNTIME_HTTP_TIMEOUT"
    assert timeout_caught.value.status == 504
    assert timeout_caught.value.details == {"phase": "login"}
    assert request_caught.value.code == "ACC_RUNTIME_AUTH_LOGIN_FAILED"
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
        assert caught.value.code == "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"
        assert caught.value.details == {"limit_bytes": 64, "phase": "login"}


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

    assert caught.value.code == "ACC_RUNTIME_AUTH_RESPONSE_INVALID"
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

        async def send(self, *args: object, **kwargs: object) -> httpx.Response:
            assert kwargs["follow_redirects"] is False
            assert kwargs["auth"] is None
            return httpx.Response(
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

    context = _context()
    strategy = _password_strategy(
        handler,
        config=_config(retry_on_unauthorized=True),
    )
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
            credentials={"kind": "gateway_session"},
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
    await strategy.bind_state(context.auth_state_key, login_result)
    bound_result = await strategy.headers(context)

    assert bound_result.authentication is login_result
    assert bound_result.state_key == context.auth_state_key
    assert bound_result.generation == 1
    assert login_calls == 1


@pytest.mark.asyncio
async def test_gateway_bind_rejects_bare_auth_state_handle() -> None:
    strategy = PasswordBearerAuthStrategy(
        config=_config(credentials={"kind": "gateway_session"}),
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
        await strategy.bind_state("auth-state-a", result)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_one_shot_401_marks_reauthentication_required_without_another_login() -> None:
    login_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        login_calls += 1
        return httpx.Response(200, json={"access_token": "source-token"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(credentials={"kind": "gateway_session"}),
        base_url="https://crm.example.test",
        credential_source=None,
        client_factory=_client_factory(handler),
    )
    result = await strategy.authenticate_once(
        CredentialPair(identity=SecretValue("alice"), password=SecretValue("private-password"))
    )
    context = _context("user-a", session_id="session-a")
    await strategy.bind_state(context.auth_state_key, result)

    bound_attempt = await strategy.headers(context)
    retryable = await strategy.on_unauthorized(context, bound_attempt)

    assert retryable is False
    with pytest.raises(AuthReauthenticationRequiredError) as caught:
        await strategy.headers(context)
    assert caught.value.code == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    assert login_calls == 1


@pytest.mark.asyncio
async def test_reauthentication_error_traceback_cannot_reach_another_users_token() -> None:
    other_users_token = "other-user-token-must-not-cross-boundary"
    strategy = PasswordBearerAuthStrategy(
        config=_config(credentials={"kind": "gateway_session"}),
        base_url="https://crm.example.test",
        credential_source=None,
    )
    context_a = _context("user-a", session_id="session-a", auth_state_handle="state-a")
    context_b = _context("user-b", session_id="session-b", auth_state_handle="state-b")
    await strategy.bind_state(
        context_b.auth_state_key,
        AuthenticationResult(
            token=SecretValue(other_users_token),
            token_type="Bearer",
        ),
    )
    with pytest.raises(AuthReauthenticationRequiredError):
        await strategy.authorize(context_a)

    with pytest.raises(AuthReauthenticationRequiredError) as caught:
        await strategy.authorize(context_a)

    _assert_runtime_traceback_locals_have_no_secret(caught.value, other_users_token)


@pytest.mark.asyncio
async def test_closed_authorize_error_traceback_cannot_reach_credential_source() -> None:
    secret = "closed-strategy-credential-source-secret"
    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(identity=secret, password=secret),
    )
    await strategy.aclose()

    with pytest.raises(AuthConfigurationError) as caught:
        await strategy.authorize(_context())

    _assert_runtime_traceback_locals_have_no_secret(caught.value, secret)


@pytest.mark.asyncio
async def test_public_parameter_errors_do_not_retain_secret_arguments_or_strategy_state() -> None:
    secret = "public-boundary-secret-argument"
    strategy = PasswordBearerAuthStrategy(
        config=_config(credentials={"kind": "gateway_session"}),
        base_url="https://crm.example.test",
        credential_source=None,
    )
    result = AuthenticationResult(token=SecretValue(secret), token_type="Bearer")
    context_a = _context("user-a", session_id="session-a", auth_state_handle="state-a")
    context_b = _context("user-b", session_id="session-b", auth_state_handle="state-b")
    failed_attempt = AuthAttempt(
        headers={"Authorization": SecretValue(f"Bearer {secret}")},
        state_key=context_b.auth_state_key,
        generation=1,
        authentication=result,
    )
    await strategy.bind_state(context_b.auth_state_key, result)

    with pytest.raises(TypeError) as bind_caught:
        await strategy.bind_state("invalid-state-key", result)  # type: ignore[arg-type]
    with pytest.raises(TypeError) as authenticate_caught:
        await strategy.authenticate_once(failed_attempt)  # type: ignore[arg-type]
    with pytest.raises(ValueError) as ownership_caught:
        await strategy.on_unauthorized(context_a, failed_attempt)
    with pytest.raises(TypeError) as invalidate_caught:
        await strategy.invalidate("invalid-state-key")  # type: ignore[arg-type]

    _assert_runtime_traceback_locals_have_no_secret(bind_caught.value, secret)
    _assert_runtime_traceback_locals_have_no_secret(authenticate_caught.value, secret)
    _assert_runtime_traceback_locals_have_no_secret(ownership_caught.value, secret)
    _assert_runtime_traceback_locals_have_no_secret(invalidate_caught.value, secret)


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


@pytest.mark.asyncio
async def test_safe_auth_errors_detach_secret_bearing_exception_graphs() -> None:
    secret = "private-exception-secret"

    class LeakySecretSource:
        @property
        def renewable(self) -> bool:
            return True

        async def acquire(self, _key: AuthStateKey) -> CredentialPair:
            raise SecretNotFoundError(secret, details={"unsafe": secret})

    secret_strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=LeakySecretSource(),
        client_factory=_client_factory(
            lambda _request: httpx.Response(200, json={"access_token": "token"})
        ),
    )

    def network_failure(_request: httpx.Request) -> httpx.Response:
        unsafe_request = httpx.Request(
            "POST",
            "https://crm.example.test/api/auth/login",
            headers={"Authorization": f"Bearer {secret}"},
            content=secret,
        )
        raise httpx.ConnectError(secret, request=unsafe_request)

    network_strategy = _password_strategy(network_failure)
    timeout_strategy = _password_strategy(
        lambda _request: (_ for _ in ()).throw(
            httpx.ReadTimeout(
                secret,
                request=httpx.Request(
                    "POST",
                    "https://crm.example.test/api/auth/login",
                    content=secret,
                ),
            )
        )
    )
    json_strategy = _password_strategy(
        lambda _request: httpx.Response(
            200,
            content=f'{{"access_token":"{secret}", broken'.encode(),
        )
    )

    errors: list[BaseException] = []
    with pytest.raises(AuthConfigurationError) as configuration_caught:
        PasswordBearerAuthStrategy(
            config=_config(),
            base_url=f"https://crm.example.test:{secret}",
            credential_source=_CredentialSource(),
        )
    errors.append(configuration_caught.value)
    for strategy in (secret_strategy, network_strategy, timeout_strategy, json_strategy):
        with pytest.raises(
            (
                AuthSecretMissingError,
                AuthLoginFailedError,
                AuthResponseInvalidError,
                AuthTimeoutError,
            )
        ) as caught:
            await strategy.headers(_context())
        errors.append(caught.value)

    for error in errors:
        assert error.__cause__ is None
        assert error.__context__ is None
        _assert_exception_graph_has_no_secret(error, secret)


@pytest.mark.parametrize("failure_kind", ["network", "json"])
@pytest.mark.asyncio
async def test_authenticate_once_traceback_locals_do_not_retain_secrets(
    failure_kind: str,
) -> None:
    secret = f"authenticate-once-traceback-{failure_kind}"

    def handler(request: httpx.Request) -> httpx.Response:
        if failure_kind == "network":
            raise httpx.ConnectError(secret, request=request)
        return httpx.Response(
            200,
            content=f'{{"access_token":"{secret}", broken'.encode(),
        )

    strategy = PasswordBearerAuthStrategy(
        config=_config(credentials={"kind": "gateway_session"}),
        base_url="https://crm.example.test",
        credential_source=None,
        client_factory=_client_factory(handler),
    )
    credentials = CredentialPair(
        identity=SecretValue(secret),
        password=SecretValue(secret),
    )

    with pytest.raises((AuthLoginFailedError, AuthResponseInvalidError)) as caught:
        await strategy.authenticate_once(credentials)

    _assert_runtime_traceback_locals_have_no_secret(caught.value, secret)


@pytest.mark.asyncio
async def test_renewable_authorize_traceback_locals_do_not_retain_secrets() -> None:
    secret = "renewable-authorize-traceback-secret"
    source = _CredentialSource(identity=secret, password=secret)
    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=source,
        client_factory=_client_factory(
            lambda _request: httpx.Response(
                200,
                content=f'{{"access_token":"{secret}", broken'.encode(),
            )
        ),
    )

    with pytest.raises(AuthResponseInvalidError) as caught:
        await strategy.headers(_context())

    _assert_runtime_traceback_locals_have_no_secret(caught.value, secret)


@pytest.mark.asyncio
async def test_failed_single_flight_shares_one_safe_error_then_allows_a_new_retry() -> None:
    calls = 0
    should_fail = True

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        if should_fail:
            return httpx.Response(503)
        return httpx.Response(200, json={"access_token": "recovered-token"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    context = _context()

    first_batch = await asyncio.gather(
        *(strategy.headers(context) for _ in range(8)),
        return_exceptions=True,
    )
    failures = [item for item in first_batch if isinstance(item, BaseException)]

    assert len(failures) == 8
    assert all(isinstance(item, AuthLoginFailedError) for item in failures)
    assert len({id(item) for item in failures}) == 1
    assert calls == 1

    should_fail = False
    recovered = await strategy.headers(context)

    assert _authorization(recovered) == "Bearer recovered-token"
    assert calls == 2


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_cancel_shared_login_for_same_key() -> None:
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return httpx.Response(200, json={"access_token": "shared-token"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    context = _context()
    cancelled = asyncio.create_task(strategy.headers(context))
    survivor = asyncio.create_task(strategy.headers(context))
    await started.wait()

    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    release.set()
    result = await survivor

    assert _authorization(result) == "Bearer shared-token"
    assert calls == 1


def test_password_strategy_requires_credential_source_matching_config_kind() -> None:
    factory = _client_factory(lambda _request: httpx.Response(200, json={"access_token": "token"}))
    with pytest.raises(AuthConfigurationError):
        PasswordBearerAuthStrategy(
            config=_config(),
            base_url="https://crm.example.test",
            credential_source=None,
            client_factory=factory,
        )
    with pytest.raises(AuthConfigurationError):
        PasswordBearerAuthStrategy(
            config=_config(),
            base_url="https://crm.example.test",
            credential_source=_CredentialSource(renewable=False),
            client_factory=factory,
        )
    with pytest.raises(AuthConfigurationError):
        PasswordBearerAuthStrategy(
            config=_config(credentials={"kind": "gateway_session"}),
            base_url="https://crm.example.test",
            credential_source=_CredentialSource(),
            client_factory=factory,
        )


@pytest.mark.asyncio
async def test_default_password_401_does_not_replay_but_next_call_may_reauthenticate() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"access_token": f"token-{calls}"})

    strategy = _password_strategy(handler, config=_config(retry_on_unauthorized=False))
    context = _context()
    failed_attempt = await strategy.headers(context)

    assert await strategy.on_unauthorized(context, failed_attempt) is False
    next_attempt = await strategy.headers(context)

    assert next_attempt.generation == 2
    assert _authorization(next_attempt) == "Bearer token-2"
    assert calls == 2


@pytest.mark.asyncio
async def test_login_request_does_not_inherit_factory_headers_cookies_or_auth() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert "x-factory-default" not in request.headers
        assert request.headers["accept"] == "application/json"
        assert request.headers["content-type"] == "application/json"
        assert set(request.headers) == {
            "accept",
            "content-length",
            "content-type",
            "host",
        }
        assert json.loads(request.content) == {
            "email": "alice@example.test",
            "password": "private-password",
        }
        return httpx.Response(200, json={"access_token": "token"})

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Authorization": "Bearer inherited-token",
                "X-Factory-Default": "unsafe",
            },
            cookies={"source_session": "inherited-cookie"},
            auth=("inherited-user", "inherited-password"),
            transport=httpx.MockTransport(handler),
        )

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=factory,
    )

    result = await strategy.headers(_context())

    assert _authorization(result) == "Bearer token"


@pytest.mark.asyncio
async def test_all_cancelled_waiters_are_cleaned_and_a_later_call_can_retry() -> None:
    calls = 0
    started = asyncio.Event()
    upstream_cancelled = asyncio.Event()
    never_release = asyncio.Event()
    clients: list[httpx.AsyncClient] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            try:
                await never_release.wait()
            except asyncio.CancelledError:
                upstream_cancelled.set()
                raise
        return httpx.Response(200, json={"access_token": "retried-token"})

    def factory() -> httpx.AsyncClient:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        clients.append(client)
        return client

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=factory,
    )
    context = _context()
    waiters = [asyncio.create_task(strategy.headers(context)) for _ in range(2)]
    await started.wait()
    for waiter in waiters:
        waiter.cancel()
    await asyncio.gather(*waiters, return_exceptions=True)
    await asyncio.wait_for(upstream_cancelled.wait(), timeout=0.5)

    assert clients[0].is_closed is True

    retried = await strategy.headers(context)

    assert _authorization(retried) == "Bearer retried-token"
    assert calls == 2


@pytest.mark.asyncio
async def test_zero_waiter_cancelled_error_traceback_cannot_reach_credential_source() -> None:
    secret = "zero-waiter-cancel-credential-source-secret"
    started = asyncio.Event()
    upstream_cancelled = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            upstream_cancelled.set()
            raise
        raise AssertionError("blocked login unexpectedly resumed")

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(identity=secret, password=secret),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    pending = asyncio.create_task(strategy.authorize(_context()))
    await started.wait()

    pending.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await pending
    await asyncio.wait_for(upstream_cancelled.wait(), timeout=0.5)

    _assert_runtime_traceback_locals_have_no_secret(caught.value, secret)


@pytest.mark.asyncio
async def test_gateway_state_invalidate_and_aclose_are_idempotent() -> None:
    strategy = PasswordBearerAuthStrategy(
        config=_config(credentials={"kind": "gateway_session"}),
        base_url="https://crm.example.test",
        credential_source=None,
        client_factory=_client_factory(
            lambda _request: httpx.Response(200, json={"access_token": "source-token"})
        ),
    )
    result = await strategy.authenticate_once(
        CredentialPair(identity=SecretValue("alice"), password=SecretValue("password"))
    )
    context = _context("user-a", session_id="session-a")
    await strategy.bind_state(context.auth_state_key, result)

    await strategy.invalidate(context.auth_state_key)
    await strategy.invalidate(context.auth_state_key)
    with pytest.raises(AuthUnauthorizedError):
        await strategy.headers(context)

    await strategy.aclose()
    await strategy.aclose()
    with pytest.raises(AuthConfigurationError):
        await strategy.headers(context)


@pytest.mark.asyncio
async def test_aclose_cancels_active_login_and_closes_its_fresh_client() -> None:
    started = asyncio.Event()
    never_release = asyncio.Event()
    clients: list[httpx.AsyncClient] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        started.set()
        await never_release.wait()
        return httpx.Response(200, json={"access_token": "unreachable"})

    def factory() -> httpx.AsyncClient:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        clients.append(client)
        return client

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(),
        client_factory=factory,
    )
    pending = asyncio.create_task(strategy.headers(_context()))
    await started.wait()

    await strategy.aclose()

    with pytest.raises(asyncio.CancelledError):
        await pending
    assert clients[0].is_closed is True


@pytest.mark.asyncio
async def test_aclose_cancelled_error_traceback_cannot_reach_credential_source() -> None:
    secret = "aclose-cancel-credential-source-secret"
    started = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.Event().wait()
        return httpx.Response(200, json={"access_token": "unreachable"})

    strategy = PasswordBearerAuthStrategy(
        config=_config(),
        base_url="https://crm.example.test",
        credential_source=_CredentialSource(identity=secret, password=secret),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    pending = asyncio.create_task(strategy.authorize(_context()))
    await started.wait()

    await strategy.aclose()

    with pytest.raises(asyncio.CancelledError) as caught:
        await pending
    _assert_runtime_traceback_locals_have_no_secret(caught.value, secret)
