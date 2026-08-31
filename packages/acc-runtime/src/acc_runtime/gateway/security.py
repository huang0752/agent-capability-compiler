"""Fail-closed request validation for the multi-user HTTP Gateway."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Iterable, Mapping

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestSecurityMiddleware:
    """Validate exact authorities and buffer every finite HTTP request body."""

    __slots__ = (
        "_allowed_hosts",
        "_allowed_origins",
        "_app",
        "_max_body_size",
        "_path_body_limits",
    )

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Iterable[str],
        allowed_origins: Iterable[str] = (),
        max_body_size: int,
        path_body_limits: Mapping[str, int] | None = None,
    ) -> None:
        hosts = frozenset(allowed_hosts)
        origins = frozenset(allowed_origins)
        if not hosts or any(not isinstance(value, str) or not value for value in hosts):
            raise ValueError("at least one exact allowed host is required")
        if any(not isinstance(value, str) or not value for value in origins):
            raise ValueError("allowed origins must be exact nonempty values")
        if (
            not isinstance(max_body_size, int)
            or isinstance(max_body_size, bool)
            or max_body_size <= 0
        ):
            raise ValueError("max_body_size must be a positive integer")
        self._app = app
        self._allowed_hosts = hosts
        self._allowed_origins = origins
        self._max_body_size = max_body_size
        limits = dict(path_body_limits or {})
        if any(
            not isinstance(path, str)
            or not path.startswith("/")
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit <= 0
            or limit > max_body_size
            for path, limit in limits.items()
        ):
            raise ValueError("path body limits must be positive and within max_body_size")
        self._path_body_limits = limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        body_limit = self._path_body_limits.get(scope.get("path", ""), self._max_body_size)

        headers = scope.get("headers", ())
        host_values = _header_values(headers, b"host")
        if len(host_values) != 1 or _decoded_header(host_values[0]) not in self._allowed_hosts:
            await _safe_error(421, "invalid_host")(scope, receive, send)
            return

        origin_values = _header_values(headers, b"origin")
        if len(origin_values) > 1:
            await _safe_error(403, "invalid_origin")(scope, receive, send)
            return
        if origin_values:
            origin = _decoded_header(origin_values[0])
            if origin is None or origin not in self._allowed_origins:
                await _safe_error(403, "invalid_origin")(scope, receive, send)
                return

        content_lengths = _header_values(headers, b"content-length")
        transfer_encodings = _header_values(headers, b"transfer-encoding")
        if len(content_lengths) > 1 or len(transfer_encodings) > 1:
            await _safe_error(400, "invalid_request_framing")(scope, receive, send)
            return
        if content_lengths and transfer_encodings:
            await _safe_error(400, "invalid_request_framing")(scope, receive, send)
            return
        if (
            transfer_encodings
            and (_decoded_header(transfer_encodings[0]) or "").casefold() != "chunked"
        ):
            await _safe_error(400, "invalid_request_framing")(scope, receive, send)
            return
        declared: int | None = None
        if content_lengths:
            declared = _strict_content_length(content_lengths[0])
            if declared is None:
                await _safe_error(400, "invalid_content_length")(scope, receive, send)
                return
            if declared > body_limit:
                await _safe_error(413, "request_body_too_large")(scope, receive, send)
                return

        authorization_values = _header_values(headers, b"authorization")
        if len(authorization_values) > 1:
            await _safe_error(400, "invalid_authorization_header")(scope, receive, send)
            return

        buffered = bytearray()
        cached: deque[Message] = deque()
        cancelled = False
        try:
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    cached.append(message)
                    break
                chunk = message.get("body", b"")
                if len(buffered) + len(chunk) > body_limit:
                    await _safe_error(413, "request_body_too_large")(scope, receive, send)
                    return
                buffered.extend(chunk)
                if not message.get("more_body", False):
                    break
            if declared is not None and len(buffered) != declared:
                await _safe_error(400, "content_length_mismatch")(scope, receive, send)
                return
            cached.appendleft({"type": "http.request", "body": bytes(buffered), "more_body": False})

            async def replay() -> Message:
                if cached:
                    return cached.popleft()
                return await receive()

            await self._app(scope, replay, send)
        except asyncio.CancelledError:
            cancelled = True
        finally:
            buffered.clear()
            cached.clear()
            headers = ()
            host_values = []
            origin_values = []
            content_lengths = []
            transfer_encodings = []
            authorization_values = []
            message = {"type": "http.disconnect"}
            chunk = b""
            scope = _redacted_scope(scope)
            receive = _disconnected_receive
        if cancelled:
            raise asyncio.CancelledError() from None


def _header_values(headers: object, name: bytes) -> list[bytes]:
    if not isinstance(headers, (list, tuple)):
        return []
    return [
        value
        for key, value in headers
        if isinstance(key, bytes) and isinstance(value, bytes) and key.lower() == name
    ]


def _decoded_header(value: bytes) -> str | None:
    try:
        decoded = value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    if not decoded or decoded != decoded.strip():
        return None
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in decoded):
        return None
    return decoded


def _strict_content_length(value: bytes) -> int | None:
    decoded = _decoded_header(value)
    if decoded is None or not decoded.isascii() or not decoded.isdecimal():
        return None
    try:
        return int(decoded)
    except ValueError:  # pragma: no cover - guarded by isdecimal
        return None


def _safe_error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status_code)


def _redacted_scope(scope: Scope) -> Scope:
    safe_scope = dict(scope)
    safe_scope["headers"] = [(key, b"<redacted>") for key, _value in scope.get("headers", ())]
    return safe_scope


async def _disconnected_receive() -> Message:
    return {"type": "http.disconnect"}


__all__ = ["RequestSecurityMiddleware"]
