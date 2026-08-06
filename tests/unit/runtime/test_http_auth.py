from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import httpx
import pytest

from acc_core.models import Operation
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


def _operation(**http_overrides: Any) -> Operation:
    http = {
        "method": "GET",
        "path": "/customers/{customer_id}",
        "path_parameters": {"customer_id": "customer_id"},
        "query_parameters": {},
        "scopes": ["customer.read"],
        "timeout_seconds": 15,
        "max_response_bytes": 1_048_576,
    }
    http.update(http_overrides)
    return Operation.model_validate(
        {
            "schema_version": "1",
            "id": "crm.get_customer",
            "title": "Get customer",
            "kind": "http",
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
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": "crm",
                    "locator": "openapi.json#/customers/{customer_id}",
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

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        self.authorized.append(context)
        generation = self.generations.get(context.auth_state_key, 0) + 1
        self.generations[context.auth_state_key] = generation
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
        return self.retry

    async def invalidate(self, auth_state_key: AuthStateKey) -> None:
        self.generations.pop(auth_state_key, None)

    async def aclose(self) -> None:
        return None


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
    assert len(strategy.unauthorized) == 1
    assert "secret upstream body" not in str(caught.value.to_dict())


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
