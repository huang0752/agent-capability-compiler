from __future__ import annotations

import asyncio
import types
from collections.abc import Mapping
from typing import Any

import httpx
import pytest

from acc_core.models import ReadOperationV2
from acc_runtime.auth import (
    AuthAttempt,
    AuthenticationResult,
    AuthUnauthorizedError,
    HttpAuthStrategy,
)
from acc_runtime.context import AuthStateKey, PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError as ACCRuntimeError
from acc_runtime.providers import HttpProvider


def _operation(**http_overrides: Any) -> ReadOperationV2:
    http = {
        "method": "GET",
        "path": "/customers/{customer_id}",
        "path_parameters": {"customer_id": "customer_id"},
        "query_parameters": {},
        "request": None,
        "success": {"statuses": [200], "body": "json"},
        "scopes": ["customer.read"],
        "timeout_seconds": 15,
        "max_response_bytes": 1_048_576,
        "safety": {
            "effect": "read",
            "risk": "low",
            "reversibility": "reversible",
            "retry": {"mode": "idempotent_only"},
            "idempotency": {"mode": "unsupported"},
            "concurrency": {"mode": "not_supported"},
        },
    }
    http.update(http_overrides)
    return ReadOperationV2.model_validate(
        {
            "schema_version": "2",
            "kind": "read",
            "id": "crm.get_customer",
            "title": "Get customer",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
            },
            "output_schema": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}},
            },
            "http": http,
            "context_bindings": {},
            "evidence": [
                {
                    "source_id": "crm",
                    "kind": "openapi",
                    "path": "openapi.json",
                    "json_pointer": "/paths/~1customers~1{id}/get",
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        }
    )


def _context(principal_id: str, *, handle: str | None = None) -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal_id,
        gateway_session_id=None,
        target_system_id="crm",
        source_scopes=None,
        deployment_scope_ceiling={"customer.read"},
        tenant_context=None,
        auth_state_handle=handle or f"auth-{principal_id}",
    )


class _RecordingStrategy(HttpAuthStrategy):
    def __init__(self, *, retry: bool = False) -> None:
        self.retry = retry
        self.authorized: list[PrincipalContext] = []
        self.unauthorized: list[tuple[PrincipalContext, AuthAttempt]] = []
        self.generations: dict[AuthStateKey, int] = {}
        self.active_generations: dict[AuthStateKey, int] = {}

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        self.authorized.append(context)
        key = context.auth_state_key
        generation = self.active_generations.get(key)
        if generation is None:
            generation = self.generations.get(key, 0) + 1
            self.generations[key] = generation
            self.active_generations[key] = generation
        token = SecretValue(f"token-{context.principal_id}-{generation}")
        authentication = AuthenticationResult(token=token, token_type="Bearer")
        assert authentication.authorization is not None
        return AuthAttempt(
            headers={"Authorization": authentication.authorization},
            state_key=context.auth_state_key,
            generation=generation,
            authentication=authentication,
        )

    headers = authorize

    async def on_unauthorized(
        self,
        context: PrincipalContext,
        failed_attempt: AuthAttempt,
    ) -> bool:
        self.unauthorized.append((context, failed_attempt))
        if self.active_generations.get(context.auth_state_key) == failed_attempt.generation:
            self.active_generations.pop(context.auth_state_key, None)
        return self.retry

    async def invalidate(self, auth_state_key: AuthStateKey) -> None:
        self.active_generations.pop(auth_state_key, None)

    async def aclose(self) -> None:
        return None


class _SensitiveStrategy(_RecordingStrategy):
    def __init__(self, other_users_token: str, *, retry: bool = False) -> None:
        super().__init__(retry=retry)
        self.other_users_token = SecretValue(other_users_token)


def _assert_runtime_exception_cannot_reach_secret(
    error: BaseException,
    *secrets: str,
) -> None:
    pending: list[object] = [error]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if value is None or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, str):
            for secret in secrets:
                assert secret not in value
            continue
        if isinstance(value, bytes):
            for secret in secrets:
                assert secret.encode() not in value
            continue
        if isinstance(value, SecretValue):
            pending.append(value.get_secret_value())
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
            traceback = value.__traceback__
            while traceback is not None:
                if "/packages/acc-runtime/" in traceback.tb_frame.f_code.co_filename:
                    pending.extend(traceback.tb_frame.f_locals.values())
                traceback = traceback.tb_next
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


def _provider(
    strategy: HttpAuthStrategy,
    handler: Any,
    *,
    client_headers: Mapping[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> tuple[HttpProvider, httpx.AsyncClient]:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers=client_headers,
        cookies=cookies,
        follow_redirects=True,
    )
    return (
        HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment={"CRM_BASE_URL": "https://crm.example.test"},
            auth_strategy=strategy,
            client=client,
        ),
        client,
    )


@pytest.mark.asyncio
async def test_provider_injects_strategy_headers_for_explicit_trusted_context() -> None:
    captured: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured
        captured = request
        return httpx.Response(200, json={"id": "one"})

    strategy = _RecordingStrategy()
    provider, client = _provider(strategy, handler)
    context = _context("user-a")
    try:
        result = await provider.execute(
            _operation(),
            {"customer_id": "one"},
            principal_context=context,
        )
    finally:
        await client.aclose()

    assert result == {"id": "one"}
    assert strategy.authorized == [context]
    assert captured is not None
    assert captured.headers["authorization"] == "Bearer token-user-a-1"


@pytest.mark.asyncio
async def test_provider_requires_context_for_provider_level_auth_without_using_arguments() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"id": "one"})

    provider, client = _provider(_RecordingStrategy(), handler)
    try:
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(_operation(), {"customer_id": "user-a"})
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_HTTP_OPERATION_INVALID"
    assert called is False


@pytest.mark.asyncio
async def test_provider_replays_only_once_after_retryable_401() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(401)
        return httpx.Response(200, json={"id": "one"})

    strategy = _RecordingStrategy(retry=True)
    provider, client = _provider(strategy, handler)
    context = _context("user-a")
    try:
        result = await provider.execute(
            _operation(),
            {"customer_id": "one"},
            principal_context=context,
        )
    finally:
        await client.aclose()

    assert result == {"id": "one"}
    assert len(requests) == 2
    assert requests[0].headers["authorization"] == "Bearer token-user-a-1"
    assert requests[1].headers["authorization"] == "Bearer token-user-a-2"
    assert len(strategy.unauthorized) == 1
    assert strategy.unauthorized[0][1].generation == 1


@pytest.mark.asyncio
async def test_provider_maps_second_401_to_stable_unauthorized_without_looping() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(401, text="secret upstream body")

    strategy = _RecordingStrategy(retry=True)
    provider, client = _provider(strategy, handler)
    try:
        with pytest.raises(AuthUnauthorizedError) as caught:
            await provider.execute(
                _operation(),
                {"customer_id": "one"},
                principal_context=_context("user-a"),
            )
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    assert caught.value.details == {"operation": "crm.get_customer"}
    assert len(requests) == 2
    assert len(strategy.authorized) == 2
    assert [attempt.generation for _, attempt in strategy.unauthorized] == [1, 2]
    next_attempt = await strategy.authorize(_context("user-a"))
    assert next_attempt.generation == 3
    assert "secret upstream body" not in str(caught.value.to_dict())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "through_compiled_call"),
    [(401, False), (403, False), (403, True)],
)
async def test_provider_public_error_traceback_cannot_reach_any_principal_token(
    status: int,
    through_compiled_call: bool,
) -> None:
    current_token = "current-principal-token-must-not-leak"
    other_users_token = "other-principal-token-must-not-leak"

    class FixedSensitiveStrategy(_SensitiveStrategy):
        async def authorize(self, context: PrincipalContext) -> AuthAttempt:
            self.authorized.append(context)
            authentication = AuthenticationResult(
                token=SecretValue(current_token),
                token_type="Bearer",
            )
            assert authentication.authorization is not None
            return AuthAttempt(
                headers={"Authorization": authentication.authorization},
                state_key=context.auth_state_key,
                generation=1,
                authentication=authentication,
            )

    strategy = FixedSensitiveStrategy(other_users_token)
    provider, client = _provider(
        strategy,
        lambda request: httpx.Response(status, text="private upstream response"),
    )
    try:
        with pytest.raises(ACCRuntimeError) as caught:
            if through_compiled_call:
                await provider.call(
                    _operation().model_dump(mode="json"),
                    {"customer_id": "one"},
                    _context("user-a"),
                )
            else:
                await provider.execute(
                    _operation(),
                    {"customer_id": "one"},
                    principal_context=_context("user-a"),
                )
    finally:
        await client.aclose()

    _assert_runtime_exception_cannot_reach_secret(
        caught.value,
        current_token,
        other_users_token,
    )


@pytest.mark.asyncio
async def test_provider_does_not_replay_when_strategy_requires_user_reauthentication() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(401)

    strategy = _RecordingStrategy(retry=False)
    provider, client = _provider(strategy, handler)
    try:
        with pytest.raises(AuthUnauthorizedError):
            await provider.execute(
                _operation(),
                {"customer_id": "one"},
                principal_context=_context("gateway-user", handle="one-shot"),
            )
    finally:
        await client.aclose()

    assert len(requests) == 1
    assert len(strategy.authorized) == 1
    assert len(strategy.unauthorized) == 1


@pytest.mark.asyncio
async def test_provider_does_not_inherit_client_headers_cookies_or_redirect_policy() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/customers/one":
            return httpx.Response(302, headers={"location": "https://evil.example.test/stolen"})
        return httpx.Response(200, json={"id": "redirected"})

    provider, client = _provider(
        _RecordingStrategy(),
        handler,
        client_headers={"X-Principal": "wrong-user"},
        cookies={"source-session": "wrong-session"},
    )
    try:
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(
                _operation(),
                {"customer_id": "one"},
                principal_context=_context("user-a"),
            )
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_HTTP_UPSTREAM_ERROR"
    assert len(requests) == 1
    assert "cookie" not in requests[0].headers
    assert "x-principal" not in requests[0].headers
    assert requests[0].url.host == "crm.example.test"


@pytest.mark.asyncio
async def test_provider_rejects_response_whose_final_url_changes_origin() -> None:
    async def send(request: httpx.Request, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            200,
            json={"id": "one"},
            request=httpx.Request("GET", "https://evil.example.test/customers/one"),
        )

    client = httpx.AsyncClient()
    client.send = send  # type: ignore[method-assign]
    provider = HttpProvider(
        base_url_ref="CRM_BASE_URL",
        environment={"CRM_BASE_URL": "https://crm.example.test"},
        auth_strategy=_RecordingStrategy(),
        client=client,
    )
    try:
        with pytest.raises(ACCRuntimeError) as caught:
            await provider.execute(
                _operation(),
                {"customer_id": "one"},
                principal_context=_context("user-a"),
            )
    finally:
        await client.aclose()

    assert caught.value.code == "ACC_RUNTIME_HTTP_REQUEST_FAILED"
    assert "evil.example.test" not in str(caught.value.to_dict())


@pytest.mark.asyncio
async def test_provider_keeps_concurrent_principal_headers_and_cookies_isolated() -> None:
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        customer_id = request.url.path.rsplit("/", 1)[-1]
        captured[customer_id] = request
        return httpx.Response(200, json={"id": customer_id})

    provider, client = _provider(
        _RecordingStrategy(),
        handler,
        cookies={"source-session": "must-not-leak"},
    )
    try:
        results = await asyncio.gather(
            provider.execute(
                _operation(),
                {"customer_id": "a"},
                principal_context=_context("user-a"),
            ),
            provider.execute(
                _operation(),
                {"customer_id": "b"},
                principal_context=_context("user-b"),
            ),
        )
    finally:
        await client.aclose()

    assert results[0] == {"id": "a"}
    assert results[1] == {"id": "b"}
    assert captured["a"].headers["authorization"] == "Bearer token-user-a-1"
    assert captured["b"].headers["authorization"] == "Bearer token-user-b-1"
    assert "cookie" not in captured["a"].headers
    assert "cookie" not in captured["b"].headers


@pytest.mark.asyncio
async def test_provider_operation_timeout_and_size_errors_identify_operation_phase() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("private query", request=request)

    provider, client = _provider(_RecordingStrategy(), timeout_handler)
    try:
        with pytest.raises(ACCRuntimeError) as timeout_caught:
            await provider.execute(
                _operation(),
                {"customer_id": "one"},
                principal_context=_context("user-a"),
            )
    finally:
        await client.aclose()
    assert timeout_caught.value.details == {
        "operation": "crm.get_customer",
        "phase": "operation",
    }

    provider, client = _provider(
        _RecordingStrategy(),
        lambda request: httpx.Response(200, content=b'{"id":"too large"}'),
    )
    try:
        with pytest.raises(ACCRuntimeError) as size_caught:
            await provider.execute(
                _operation(max_response_bytes=5),
                {"customer_id": "one"},
                principal_context=_context("user-a"),
            )
    finally:
        await client.aclose()
    assert size_caught.value.details == {
        "operation": "crm.get_customer",
        "limit_bytes": 5,
        "phase": "operation",
    }
