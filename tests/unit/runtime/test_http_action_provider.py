from __future__ import annotations

import json
import traceback
from typing import Any

import httpx
import pytest

from acc_core.models.v2 import ActionOperationV2
from acc_runtime.actions import ActionOperationProvider, ActionReadResult
from acc_runtime.auth import NoAuthStrategy
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError as ACCRuntimeError
from acc_runtime.providers import HttpProvider


def _evidence() -> list[dict[str, object]]:
    return [
        {
            "source_id": "orders",
            "kind": "openapi",
            "path": "openapi.json",
            "json_pointer": "/paths/~1orders~1{id}/put",
            "digest": "sha256:" + "a" * 64,
        }
    ]


def _action_operation(
    *,
    success_body: str = "json",
    success_statuses: list[int] | None = None,
    max_response_bytes: int = 4096,
    max_request_bytes: int = 4096,
    idempotency_target: dict[str, str] | None = None,
    concurrency_target: dict[str, str] | None = None,
    body_parameters: dict[str, str] | None = None,
    output_schema: dict[str, object] | None = None,
) -> ActionOperationV2:
    return ActionOperationV2.model_validate(
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.update",
            "title": "Update order",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "order_id": {"type": "string"},
                    "tenant": {"type": "string"},
                    "status": {"type": "string"},
                    "agent_idempotency": {"type": "string"},
                    "agent_concurrency": {"type": "string"},
                    "collision": {},
                },
                "required": ["order_id", "status"],
            },
            "output_schema": output_schema
            or {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "order_id": {"type": "string"},
                    "status": {"type": "string"},
                },
                "required": ["order_id", "status"],
            },
            "http": {
                "method": "PUT",
                "path": "/orders/{order_id}",
                "path_parameters": {"order_id": "order_id"},
                "query_parameters": {"tenant": "tenant"},
                "request": {
                    "kind": "json",
                    "body_parameters": body_parameters
                    or {
                        "/change/status": "status",
                        "/metadata/agent_note": "agent_idempotency",
                    },
                    "max_request_bytes": max_request_bytes,
                },
                "success": {
                    "statuses": success_statuses or [200],
                    "body": success_body,
                },
                "scopes": ["orders.write"],
                "timeout_seconds": 15,
                "max_response_bytes": max_response_bytes,
                "safety": {
                    "effect": "update",
                    "risk": "medium",
                    "reversibility": "reversible",
                    "retry": {"mode": "idempotent_only"},
                    "idempotency": {
                        "mode": "source_key",
                        "target": idempotency_target
                        or {"kind": "header", "name": "Idempotency-Key"},
                    },
                    "concurrency": {
                        "mode": "required",
                        "token": {"kind": "response_header", "name": "ETag"},
                        "precondition": concurrency_target
                        or {"kind": "header", "name": "If-Match"},
                    },
                },
            },
            "context_bindings": {},
            "evidence": _evidence(),
        }
    )


def _principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="user-a",
        gateway_session_id="session-a",
        target_system_id="orders",
        source_scopes={"orders.write"},
        deployment_scope_ceiling={"orders.write"},
        scope_mapping={"orders.write": {"orders.write"}},
        tenant_context=None,
        auth_state_handle="auth-user-a",
    )


def _provider(client: httpx.AsyncClient) -> HttpProvider:
    provider = HttpProvider(
        base_url_ref="ORDERS_URL",
        environment={"ORDERS_URL": "https://orders.example.test"},
        auth_strategy=NoAuthStrategy(),
        client=client,
    )
    assert isinstance(provider, ActionOperationProvider)
    return provider


def _client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_action_injects_runtime_headers_and_builds_bounded_nested_json() -> None:
    captured: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured
        captured = request
        return httpx.Response(200, json={"order_id": "order/1", "status": "approved"})

    async with _client(handler) as client:
        result = await _provider(client).call_action(
            _action_operation(),
            {
                "order_id": "order/1",
                "tenant": "tenant a",
                "status": "approved",
                "agent_idempotency": "agent-evil",
                "agent_concurrency": "agent-evil",
            },
            _principal(),
            idempotency_key=SecretValue("runtime-key"),
            concurrency_token="etag-v3",
        )

    assert result == {"order_id": "order/1", "status": "approved"}
    assert captured is not None
    assert captured.url.raw_path == b"/orders/order%2F1?tenant=tenant%20a"
    assert captured.headers["idempotency-key"] == "runtime-key"
    assert captured.headers["if-match"] == "etag-v3"
    assert captured.headers["content-type"] == "application/json"
    assert json.loads(captured.content) == {
        "change": {"status": "approved"},
        "metadata": {"agent_note": "agent-evil"},
    }


@pytest.mark.asyncio
async def test_action_runtime_controls_can_be_injected_into_nested_body() -> None:
    captured: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured
        captured = request
        return httpx.Response(200, json={"order_id": "one", "status": "approved"})

    operation = _action_operation(
        idempotency_target={"kind": "body", "pointer": "/controls/idempotency/key"},
        concurrency_target={"kind": "body", "pointer": "/controls/concurrency/version"},
    )
    async with _client(handler) as client:
        await _provider(client).call_action(
            operation,
            {"order_id": "one", "status": "approved"},
            _principal(),
            idempotency_key=SecretValue("runtime-key"),
            concurrency_token={"version": 3},
        )

    assert captured is not None
    assert json.loads(captured.content) == {
        "change": {"status": "approved"},
        "controls": {
            "idempotency": {"key": "runtime-key"},
            "concurrency": {"version": {"version": 3}},
        },
    }
    assert "idempotency-key" not in captured.headers
    assert "if-match" not in captured.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body_parameters", "idempotency_target"),
    [
        (
            {"/controls/idempotency": "collision"},
            {"kind": "body", "pointer": "/controls/idempotency"},
        ),
        ({"/controls": "collision"}, {"kind": "body", "pointer": "/controls/idempotency"}),
    ],
)
async def test_action_body_pointer_collisions_fail_before_network(
    body_parameters: dict[str, str],
    idempotency_target: dict[str, str],
) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"order_id": "one", "status": "approved"})

    async with _client(handler) as client:
        with pytest.raises(ACCRuntimeError) as captured:
            await _provider(client).call_action(
                _action_operation(
                    body_parameters=body_parameters,
                    idempotency_target=idempotency_target,
                ),
                {"order_id": "one", "status": "approved", "collision": "agent-evil"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )

    assert captured.value.code == "ACC_RUNTIME_HTTP_OPERATION_INVALID"
    assert called is False
    assert "agent-evil" not in repr(captured.value.to_dict())


@pytest.mark.asyncio
async def test_action_header_target_conflicts_with_auth_fail_closed() -> None:
    operation = _action_operation(idempotency_target={"kind": "header", "name": "Accept"})
    async with _client(lambda request: httpx.Response(200)) as client:
        with pytest.raises(ACCRuntimeError) as captured:
            await _provider(client).call_action(
                operation,
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )

    assert captured.value.code == "ACC_RUNTIME_HTTP_OPERATION_INVALID"


@pytest.mark.asyncio
async def test_action_uses_exact_success_status_and_never_replays_401() -> None:
    calls = 0

    def wrong_status(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(201, json={"order_id": "one", "status": "approved"})

    async with _client(wrong_status) as client:
        with pytest.raises(ACCRuntimeError) as captured:
            await _provider(client).call_action(
                _action_operation(success_statuses=[200]),
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )
    assert captured.value.code == "ACC_RUNTIME_HTTP_UPSTREAM_ERROR"
    assert calls == 1

    calls = 0

    def unauthorized(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, text="secret response")

    async with _client(unauthorized) as client:
        with pytest.raises(ACCRuntimeError) as captured:
            await _provider(client).call_action(
                _action_operation(),
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )
    assert captured.value.code == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("body_mode", ["empty", "json_or_empty"])
async def test_action_explicit_empty_success_body_returns_null(body_mode: str) -> None:
    async with _client(lambda request: httpx.Response(204)) as client:
        result = await _provider(client).call_action(
            _action_operation(
                success_body=body_mode,
                success_statuses=[204],
                output_schema={"type": "null"},
            ),
            {"order_id": "one", "status": "approved"},
            _principal(),
            idempotency_key=SecretValue("runtime-key"),
            concurrency_token="etag-v3",
        )

    assert result is None


@pytest.mark.asyncio
async def test_action_enforces_request_and_response_size_and_output_schema() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=b'{"order_id":"one","status":"approved"}')

    async with _client(handler) as client:
        with pytest.raises(ACCRuntimeError) as request_error:
            await _provider(client).call_action(
                _action_operation(max_request_bytes=2),
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )
    assert request_error.value.code == "ACC_RUNTIME_HTTP_REQUEST_TOO_LARGE"
    assert called is False

    async with _client(handler) as client:
        with pytest.raises(ACCRuntimeError) as response_error:
            await _provider(client).call_action(
                _action_operation(max_response_bytes=2),
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )
    assert response_error.value.code == "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"

    async with _client(
        lambda request: httpx.Response(200, json={"order_id": "one", "wrong": True})
    ) as client:
        with pytest.raises(ACCRuntimeError) as schema_error:
            await _provider(client).call_action(
                _action_operation(),
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )
    assert schema_error.value.code == "ACC_RUNTIME_OUTPUT_SCHEMA_INVALID"


@pytest.mark.asyncio
async def test_action_read_returns_only_nonsensitive_response_metadata() -> None:
    read_http = _action_operation().http.model_copy(update={"method": "GET"})
    read_operation = _action_operation().model_copy(update={"kind": "read", "http": read_http})
    read_document = read_operation.model_dump(mode="json")
    read_document["http"]["request"] = None
    read_document["http"]["safety"] = {
        "effect": "read",
        "risk": "low",
        "reversibility": "reversible",
        "retry": {"mode": "idempotent_only"},
        "idempotency": {"mode": "unsupported"},
        "concurrency": {"mode": "not_supported"},
    }
    from acc_core.models.v2 import ReadOperationV2

    operation = ReadOperationV2.model_validate(read_document)
    async with _client(
        lambda request: httpx.Response(
            200,
            json={"order_id": "one", "status": "pending"},
            headers={
                "ETag": "etag-v3",
                "Set-Cookie": "session=secret",
                "X-Api-Token": "secret-token",
            },
        )
    ) as client:
        result = await _provider(client).call_read(
            operation,
            {"order_id": "one", "status": "pending"},
            _principal(),
        )

    assert isinstance(result, ActionReadResult)
    assert result.value == {"order_id": "one", "status": "pending"}
    normalized = {name.casefold(): value for name, value in result.response_headers.items()}
    assert normalized["etag"] == "etag-v3"
    assert "set-cookie" not in normalized
    assert "x-api-token" not in normalized
    assert "secret" not in repr(result)


@pytest.mark.asyncio
async def test_action_failure_and_traceback_do_not_retain_runtime_controls() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("runtime-key etag-v3", request=request)

    async with _client(handler) as client:
        with pytest.raises(ACCRuntimeError) as captured:
            await _provider(client).call_action(
                _action_operation(),
                {"order_id": "one", "status": "approved"},
                _principal(),
                idempotency_key=SecretValue("runtime-key"),
                concurrency_token="etag-v3",
            )

    rendered = "".join(traceback.format_exception(captured.value))
    assert "runtime-key" not in rendered
    assert "etag-v3" not in rendered
