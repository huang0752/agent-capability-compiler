"""FastAPI server primitives for fixed ACC adapter contracts."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import yaml
from fastapi import Depends, FastAPI
from pydantic import ValidationError
from starlette.routing import compile_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from acc_adapter_sdk.contracts import (
    AdapterActionOperation,
    AdapterActionSafety,
    AdapterBodyTarget,
    AdapterContract,
    AdapterHeaderTarget,
    AdapterOperation,
    join_adapter_path,
)

_READ_ONLY_METHODS = {"GET", "HEAD"}
_ACTION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AdapterRegistrationError(ValueError):
    """An adapter route cannot be safely registered from its fixed contract."""


class AdapterServer:
    """A small FastAPI wrapper that registers only declared GET/HEAD routes."""

    def __init__(self, contract: AdapterContract) -> None:
        try:
            validated_contract = AdapterContract.model_validate(contract.model_dump(mode="python"))
        except ValidationError as exc:
            raise AdapterRegistrationError("adapter contract is invalid") from exc

        self.contract = validated_contract
        self.app = FastAPI(
            title=validated_contract.id,
            version=validated_contract.version,
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )
        self._action_limits = _ActionLimitsMiddleware(self.app)
        self.app.add_middleware(_InstalledActionLimitsMiddleware, limits=self._action_limits)
        self._operation_index = {
            operation.id: operation for operation in validated_contract.operations
        }
        self._registered: set[str] = set()
        self._health_adapter = {
            "id": validated_contract.id,
            "version": validated_contract.version,
        }
        self._health_metadata = dict(validated_contract.health.metadata)
        self.app.add_api_route(
            validated_contract.health.path,
            self._health,
            methods=["GET"],
            include_in_schema=False,
            name="adapter-health",
        )

    @classmethod
    def from_contract_file(
        cls,
        path: str | os.PathLike[str],
    ) -> AdapterServer:
        """Load a strict adapter contract from one UTF-8 YAML file."""

        contract_path = Path(path)
        try:
            document = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise AdapterRegistrationError("cannot read adapter contract YAML") from exc
        if not isinstance(document, dict):
            raise AdapterRegistrationError("adapter contract YAML must contain an object")
        try:
            contract = AdapterContract.model_validate(document)
        except ValidationError as exc:
            raise AdapterRegistrationError("adapter contract YAML is invalid") from exc
        return cls(contract)

    @property
    def registered_operation_ids(self) -> tuple[str, ...]:
        """Return registered operation ids in deterministic order."""

        return tuple(sorted(self._registered))

    def register_operation(
        self,
        operation_id: str,
        handler: Callable[..., Any],
    ) -> None:
        """Bind a handler to one operation already declared by the contract."""

        operation = self._operation_index.get(operation_id)
        if operation is None:
            raise AdapterRegistrationError(f"adapter operation is not declared: {operation_id}")
        if operation_id in self._registered:
            raise AdapterRegistrationError(
                f"adapter operation is already registered: {operation_id}"
            )
        if (
            not isinstance(operation, AdapterOperation)
            or operation.method not in _READ_ONLY_METHODS
        ):
            raise AdapterRegistrationError(f"adapter operation must be read-only: {operation_id}")
        if not callable(handler):
            raise AdapterRegistrationError("adapter operation handler must be callable")

        self.app.add_api_route(
            join_adapter_path(self.contract.base_path, operation.path),
            handler,
            methods=[operation.method],
            summary=operation.summary,
            operation_id=operation.id,
            name=operation.id,
        )
        self._registered.add(operation_id)

    def register_action(
        self,
        operation_id: str,
        handler: Callable[..., Any],
        *,
        source_authorizer: Callable[..., Any],
    ) -> None:
        """Bind one declared Action and require source authorization on every request."""

        operation = self._operation_index.get(operation_id)
        if operation is None:
            raise AdapterRegistrationError(f"adapter Action is not declared: {operation_id}")
        if operation_id in self._registered:
            raise AdapterRegistrationError(
                f"adapter operation is already registered: {operation_id}"
            )
        if (
            not isinstance(operation, AdapterActionOperation)
            or operation.method not in _ACTION_METHODS
        ):
            raise AdapterRegistrationError(f"adapter operation is not an Action: {operation_id}")
        if not callable(handler):
            raise AdapterRegistrationError("adapter Action handler must be callable")
        if not callable(source_authorizer):
            raise AdapterRegistrationError("adapter Action requires a source authorizer")

        full_path = join_adapter_path(self.contract.base_path, operation.path)
        self._action_limits.register(operation.method, full_path, operation.safety)
        self.app.add_api_route(
            full_path,
            handler,
            methods=[operation.method],
            dependencies=[Depends(source_authorizer)],
            summary=operation.summary,
            operation_id=operation.id,
            name=operation.id,
        )
        self._registered.add(operation_id)

    async def _health(self) -> dict[str, object]:
        return {
            "status": "ok",
            "schema_version": self.contract.schema_version,
            "adapter": dict(self._health_adapter),
            "metadata": dict(self._health_metadata),
        }


class _ActionLimitsMiddleware:
    """Bound Action bodies and require both trusted runtime controls."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._routes: list[tuple[str, Any, AdapterActionSafety]] = []

    def register(self, method: str, path: str, safety: AdapterActionSafety) -> None:
        regex, _, _ = compile_path(path)
        self._routes.append((method, regex, safety))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        safety = self._safety(scope)
        if safety is None:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > safety.max_request_bytes:
                await _send_error(send, 413, "adapter Action request exceeds its contract limit")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        if not _controls_present(scope, bytes(body), safety):
            await _send_error(send, 400, "adapter Action controls are missing or invalid")
            return

        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        messages: list[Message] = []
        response_bytes = 0
        exceeded = False

        async def bounded_send(message: Message) -> None:
            nonlocal exceeded, response_bytes
            if message["type"] == "http.response.body":
                response_bytes += len(message.get("body", b""))
                exceeded = exceeded or response_bytes > safety.max_response_bytes
            if not exceeded:
                messages.append(message)

        await self.app(scope, replay, bounded_send)
        if exceeded:
            await _send_error(send, 502, "adapter Action response exceeds its contract limit")
            return
        for message in messages:
            await send(message)

    def _safety(self, scope: Scope) -> AdapterActionSafety | None:
        if scope["type"] != "http":
            return None
        method = cast(str, scope.get("method", ""))
        path = cast(str, scope.get("path", ""))
        for expected_method, regex, safety in self._routes:
            if method == expected_method and regex.fullmatch(path):
                return safety
        return None


class _InstalledActionLimitsMiddleware:
    """Install the mutable Action limiter owned by one AdapterServer."""

    def __init__(self, app: ASGIApp, *, limits: _ActionLimitsMiddleware) -> None:
        limits.app = app
        self._limits = limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._limits(scope, receive, send)


def _controls_present(scope: Scope, body: bytes, safety: AdapterActionSafety) -> bool:
    headers = {
        key.decode("latin-1").casefold(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }
    document: object = None
    targets = (safety.idempotency.target, safety.concurrency.precondition)
    if any(isinstance(target, AdapterBodyTarget) for target in targets):
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
    for target in targets:
        if isinstance(target, AdapterHeaderTarget):
            if not headers.get(target.name.casefold()):
                return False
        elif not _body_pointer_present(document, target.pointer):
            return False
    return True


def _body_pointer_present(document: object, pointer: str) -> bool:
    current = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdecimal() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False
    return current is not None and current != ""


async def _send_error(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}, separators=(",", ":")).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


__all__ = ["AdapterRegistrationError", "AdapterServer"]
