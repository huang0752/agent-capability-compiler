"""Starlette assembly for the protected multi-user Streamable HTTP Gateway."""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
from collections.abc import AsyncIterator
from typing import Protocol

from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import (
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.gateway.auth import GatewayTokenVerifier
from acc_runtime.gateway.models import GatewaySettings, SessionCreateRequest, SessionCreateResponse
from acc_runtime.gateway.security import RequestSecurityMiddleware
from acc_runtime.mcp import PrincipalCapabilityMcpServer

DEFAULT_GATEWAY_BODY_LIMIT = 4 * 1024 * 1024
DEFAULT_MCP_SESSION_IDLE_TIMEOUT_SECONDS = 60.0


class _Cancelled:
    __slots__ = ()


_CANCELLED = _Cancelled()


class GatewaySessionApplicationService(Protocol):
    async def create_session(self, *, identity: str, password: str) -> SessionCreateResponse: ...

    async def delete_current(self, token: str) -> None: ...

    async def aclose(self) -> None: ...


class _McpEndpoint:
    """Class endpoint keeps the manager's public ASGI method unwrapped."""

    __slots__ = ("_app",)

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)


def create_gateway_app(
    *,
    settings: GatewaySettings,
    service: GatewaySessionApplicationService,
    token_verifier: GatewayTokenVerifier,
    mcp_server: PrincipalCapabilityMcpServer,
    max_request_body_size: int = DEFAULT_GATEWAY_BODY_LIMIT,
    mcp_session_idle_timeout_seconds: float | None = None,
) -> Starlette:
    """Create one single-use Gateway app and bind all lifecycle-owned resources."""

    if (
        not isinstance(max_request_body_size, int)
        or isinstance(max_request_body_size, bool)
        or max_request_body_size <= 0
    ):
        raise ValueError("max_request_body_size must be a positive integer")
    idle_timeout = (
        min(float(settings.session_ttl_seconds), DEFAULT_MCP_SESSION_IDLE_TIMEOUT_SECONDS)
        if mcp_session_idle_timeout_seconds is None
        else mcp_session_idle_timeout_seconds
    )
    if (
        not isinstance(idle_timeout, (int, float))
        or isinstance(idle_timeout, bool)
        or not math.isfinite(idle_timeout)
        or idle_timeout <= 0
        or idle_timeout > settings.session_ttl_seconds
    ):
        raise ValueError(
            "mcp_session_idle_timeout_seconds must be positive and no greater than session TTL"
        )

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(settings.allowed_hosts),
        allowed_origins=list(settings.allowed_origins),
    )
    manager = StreamableHTTPSessionManager(
        mcp_server.create_server(),
        json_response=True,
        stateless=False,
        security_settings=transport_security,
        session_idle_timeout=float(idle_timeout),
        max_request_body_size=max_request_body_size,
    )

    async def create_session(request: Request) -> Response:
        parsed: SessionCreateRequest | None = None
        identity = ""
        password = ""
        outcome: Response | _Cancelled
        try:
            parsed = await _parse_session_request(request)
            if parsed is None:
                outcome = _error_response(400, "ACC_GATEWAY_SESSION_REQUEST_INVALID")
            else:
                identity = parsed.identity
                password = parsed.password.get_secret_value()
                parsed = None
                response = await service.create_session(identity=identity, password=password)
                outcome = JSONResponse(response.one_time_payload(), status_code=201)
        except asyncio.CancelledError:
            outcome = _CANCELLED
        except AccRuntimeError as error:
            outcome = JSONResponse({"error": error.to_dict()}, status_code=error.status)
        except Exception:
            outcome = _error_response(500, "ACC_GATEWAY_INTERNAL")
        finally:
            password = ""
            identity = ""
            parsed = None
            request = None  # type: ignore[assignment]
        if isinstance(outcome, _Cancelled):
            raise asyncio.CancelledError() from None
        return outcome

    async def delete_session(request: Request) -> Response:
        token = _single_bearer_token(request.scope)
        if token is None:
            return _error_response(401, "ACC_GATEWAY_SESSION_INVALID")
        outcome: Response | _Cancelled
        try:
            await service.delete_current(token)
            outcome = Response(status_code=204)
        except asyncio.CancelledError:
            outcome = _CANCELLED
        except AccRuntimeError as error:
            outcome = JSONResponse({"error": error.to_dict()}, status_code=error.status)
        except Exception:
            outcome = _error_response(500, "ACC_GATEWAY_INTERNAL")
        finally:
            token = ""
            request = None  # type: ignore[assignment]
        if isinstance(outcome, _Cancelled):
            raise asyncio.CancelledError() from None
        return outcome

    protected = [Middleware(RequireAuthMiddleware, required_scopes=[])]
    routes = [
        Route("/runtime/sessions", create_session, methods=["POST"]),
        Route(
            "/runtime/sessions/current",
            delete_session,
            methods=["DELETE"],
            middleware=protected,
        ),
        Route(
            "/mcp",
            _McpEndpoint(manager.handle_request),
            methods=["POST", "GET", "DELETE"],
            middleware=protected,
        ),
    ]

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            async with manager.run():
                yield
        finally:
            await service.aclose()

    middleware = [
        Middleware(
            RequestSecurityMiddleware,
            allowed_hosts=settings.allowed_hosts,
            allowed_origins=settings.allowed_origins,
            max_body_size=max_request_body_size,
        ),
        Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(token_verifier)),
        Middleware(AuthContextMiddleware),
    ]
    return Starlette(
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
        debug=False,
    )


async def _parse_session_request(request: Request) -> SessionCreateRequest | None:
    if not _is_json_content_type(request.scope):
        return None
    raw_body = bytearray(await request.body())
    try:
        payload = json.loads(raw_body)
        if not isinstance(payload, dict):
            return None
        return SessionCreateRequest.model_validate(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError, ValueError):
        return None
    finally:
        raw_body.clear()


def _is_json_content_type(scope: Scope) -> bool:
    values = _raw_header_values(scope, b"content-type")
    if len(values) != 1:
        return False
    try:
        value = values[0].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return False
    media_type, separator, parameters = value.partition(";")
    if media_type.strip().casefold() != "application/json":
        return False
    if not separator:
        return True
    return parameters.strip().casefold() == "charset=utf-8"


def _single_bearer_token(scope: Scope) -> str | None:
    values = _raw_header_values(scope, b"authorization")
    if len(values) != 1:
        return None
    try:
        value = values[0].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    if value[:7].casefold() != "bearer " or value.count(" ") != 1:
        return None
    token = value[7:]
    return token if token and token == token.strip() else None


def _raw_header_values(scope: Scope, name: bytes) -> list[bytes]:
    return [value for key, value in scope.get("headers", ()) if key.lower() == name]


def _error_response(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "status": status_code, "details": {}}},
        status_code=status_code,
    )


__all__ = [
    "DEFAULT_GATEWAY_BODY_LIMIT",
    "DEFAULT_MCP_SESSION_IDLE_TIMEOUT_SECONDS",
    "GatewaySessionApplicationService",
    "create_gateway_app",
]
