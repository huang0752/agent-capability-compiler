"""Bounded asynchronous REST provider for compiled HTTP operations."""

from __future__ import annotations

import json
import logging
import math
import os
from collections.abc import Mapping
from typing import Protocol, cast
from urllib.parse import quote, urlencode, urlsplit

import httpx
from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.models import Operation
from acc_runtime.auth import AuthAttempt, AuthUnauthorizedError, HttpAuthStrategy
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue, resolve_secret
from acc_runtime.errors import RuntimeError

LOGGER = logging.getLogger(__name__)


class HttpBaseUrlError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_BASE_URL_INVALID"
    status = 500


class HttpMethodDeniedError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_METHOD_DENIED"
    status = 500


class HttpOperationError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_OPERATION_INVALID"
    status = 500


class InputSchemaError(RuntimeError):
    code = "ACC_RUNTIME_INPUT_SCHEMA_INVALID"
    status = 400


class OutputSchemaError(RuntimeError):
    code = "ACC_RUNTIME_OUTPUT_SCHEMA_INVALID"
    status = 502


class HttpTimeoutError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_TIMEOUT"
    status = 504


class HttpForbiddenError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_FORBIDDEN"
    status = 403


class HttpNotFoundError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_NOT_FOUND"
    status = 404


class HttpUpstreamError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_UPSTREAM_ERROR"
    status = 502


class HttpRequestError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_REQUEST_FAILED"
    status = 502


class HttpInvalidJsonError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_INVALID_JSON"
    status = 502


class HttpResponseTooLargeError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"
    status = 502


class ResolvedSecret(Protocol):
    """Minimal redacted secret value accepted at the provider boundary."""

    def get_secret_value(self) -> str:
        """Explicitly unwrap the secret for the Authorization header."""


class SecretResolver(Protocol):
    """Small adapter seam for environment or external secret stores."""

    def resolve(self, reference: str) -> str | ResolvedSecret:
        """Resolve one named credential without exposing it in arguments."""


class EnvironmentSecretResolver:
    """Resolve credentials using ACC's redacted environment abstraction."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = environment

    def resolve(self, reference: str) -> SecretValue:
        return resolve_secret(reference, self._environment)


class HttpProvider:
    """Execute a statically declared GET/HEAD operation against one fixed origin."""

    def __init__(
        self,
        *,
        base_url_ref: str,
        secret_resolver: SecretResolver | None = None,
        auth_strategy: HttpAuthStrategy | None = None,
        environment: Mapping[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url_ref = base_url_ref
        self._environment = environment
        self._secret_resolver = secret_resolver or EnvironmentSecretResolver(environment)
        self._auth_strategy = auth_strategy
        self.client = client

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext | None = None,
    ) -> JsonValue:
        """Operation-caller protocol used by the generic workflow executor."""

        try:
            definition = Operation.model_validate(operation)
        except ValidationError as exc:
            raise HttpOperationError("compiled HTTP operation is invalid") from exc
        return await self.execute(
            definition,
            arguments,
            principal_context=principal_context,
        )

    async def execute(
        self,
        operation: Operation,
        arguments: Mapping[str, JsonValue],
        *,
        principal_context: PrincipalContext | None = None,
    ) -> JsonValue:
        """Validate, execute, bound, decode, and validate one HTTP response."""

        self._validate_schema(operation.input_schema, arguments, operation, input_value=True)
        base_url = self._fixed_base_url(operation)
        if operation.http.method not in {"GET", "HEAD"}:
            raise HttpMethodDeniedError(
                "runtime permits only GET and HEAD operations",
                details={"operation": operation.id},
            )

        url = self._request_url(base_url, operation, arguments)
        attempt = await self._authentication_attempt(operation, principal_context)
        headers = self._request_headers(operation, attempt)
        try:
            if self.client is not None:
                result = await self._send_with_retry(
                    self.client,
                    operation,
                    url,
                    headers,
                    principal_context,
                    attempt,
                )
            else:
                async with httpx.AsyncClient(follow_redirects=False) as client:
                    result = await self._send_with_retry(
                        client,
                        operation,
                        url,
                        headers,
                        principal_context,
                        attempt,
                    )
        except httpx.TimeoutException as exc:
            LOGGER.warning("HTTP operation timed out operation=%s", operation.id)
            raise HttpTimeoutError(
                "upstream request timed out",
                details={"operation": operation.id, "phase": "operation"},
            ) from exc
        except httpx.RequestError as exc:
            LOGGER.warning("HTTP operation failed operation=%s", operation.id)
            raise HttpRequestError(
                "upstream request failed",
                details={"operation": operation.id},
            ) from exc

        self._validate_schema(operation.output_schema, result, operation, input_value=False)
        return result

    async def _authentication_attempt(
        self,
        operation: Operation,
        principal_context: PrincipalContext | None,
    ) -> AuthAttempt | None:
        if self._auth_strategy is not None:
            if not isinstance(principal_context, PrincipalContext):
                raise HttpOperationError(
                    "provider authentication requires a trusted PrincipalContext",
                    details={"operation": operation.id},
                )
            if operation.http.credential_ref is not None:
                raise HttpOperationError(
                    "operation credential conflicts with provider authentication",
                    details={"operation": operation.id},
                )
            attempt = await self._auth_strategy.authorize(principal_context)
            if attempt.state_key != principal_context.auth_state_key:
                raise HttpOperationError(
                    "authentication attempt does not belong to the PrincipalContext",
                    details={"operation": operation.id},
                )
            return attempt

        credential_ref = operation.http.credential_ref
        if credential_ref is None:
            raise HttpOperationError(
                "operation credential is required without provider authentication",
                details={"operation": operation.id},
            )
        return None

    def _request_headers(
        self,
        operation: Operation,
        attempt: AuthAttempt | None,
    ) -> dict[str, str]:
        if attempt is None:
            credential_ref = operation.http.credential_ref
            assert credential_ref is not None
            credential = self._secret_resolver.resolve(credential_ref)
            token = credential if isinstance(credential, str) else credential.get_secret_value()
            if not isinstance(token, str) or not token:
                raise HttpRequestError(
                    "resolved credential is empty or invalid",
                    details={"operation": operation.id},
                )
            return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        headers = {"Accept": "application/json"}
        for name, secret in attempt.headers.items():
            if name.casefold() == "cookie":
                raise HttpOperationError(
                    "cookie authentication is not supported by this provider",
                    details={"operation": operation.id},
                )
            headers[name] = secret.get_secret_value()
        return headers

    async def _send_with_retry(
        self,
        client: httpx.AsyncClient,
        operation: Operation,
        url: str,
        headers: Mapping[str, str],
        principal_context: PrincipalContext | None,
        attempt: AuthAttempt | None,
    ) -> JsonValue:
        try:
            return await self._send(client, operation, url, headers)
        except _OperationUnauthorized:
            if (
                self._auth_strategy is None
                or principal_context is None
                or attempt is None
                or not await self._auth_strategy.on_unauthorized(
                    principal_context,
                    attempt,
                )
            ):
                raise AuthUnauthorizedError(
                    "source authentication is unauthorized",
                    details={"operation": operation.id},
                ) from None

        retry_attempt = await self._auth_strategy.authorize(principal_context)
        if retry_attempt.state_key != principal_context.auth_state_key:
            raise HttpOperationError(
                "authentication attempt does not belong to the PrincipalContext",
                details={"operation": operation.id},
            )
        retry_headers = self._request_headers(operation, retry_attempt)
        try:
            return await self._send(client, operation, url, retry_headers)
        except _OperationUnauthorized:
            raise AuthUnauthorizedError(
                "source authentication is unauthorized",
                details={"operation": operation.id},
            ) from None

    def _fixed_base_url(self, operation: Operation) -> str:
        source = os.environ if self._environment is None else self._environment
        raw = source.get(self.base_url_ref)
        if not isinstance(raw, str):
            raise HttpBaseUrlError(
                "HTTP base URL is not configured",
                details={"operation": operation.id, "reference": self.base_url_ref},
            )
        try:
            parsed = urlsplit(raw)
            # Accessing port performs strict port validation.
            _validated_port = parsed.port
        except ValueError as exc:
            raise HttpBaseUrlError(
                "HTTP base URL is invalid",
                details={"operation": operation.id, "reference": self.base_url_ref},
            ) from exc
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or any(character.isspace() for character in raw)
        ):
            raise HttpBaseUrlError(
                "HTTP base URL must be a fixed HTTP(S) origin",
                details={"operation": operation.id, "reference": self.base_url_ref},
            )
        return raw.rstrip("/")

    @staticmethod
    def _request_url(
        base_url: str,
        operation: Operation,
        arguments: Mapping[str, JsonValue],
    ) -> str:
        path = operation.http.path
        for placeholder, input_name in operation.http.path_parameters.items():
            value = HttpProvider._scalar_parameter(arguments, input_name, operation)
            if value in {".", ".."}:
                raise InputSchemaError(
                    "path parameter cannot be a traversal segment",
                    details={"operation": operation.id, "parameter": input_name},
                )
            path = path.replace("{" + placeholder + "}", quote(value, safe=""))

        query_items: list[tuple[str, str]] = []
        for query_name, input_name in operation.http.query_parameters.items():
            if input_name not in arguments or arguments[input_name] is None:
                continue
            raw_value = arguments[input_name]
            if isinstance(raw_value, list):
                query_items.extend(
                    (query_name, HttpProvider._query_scalar(item, input_name, operation))
                    for item in raw_value
                )
            else:
                query_items.append(
                    (query_name, HttpProvider._query_scalar(raw_value, input_name, operation))
                )
        query = urlencode(query_items, doseq=True, safe="", quote_via=quote)
        url = f"{base_url}{path}"
        return f"{url}?{query}" if query else url

    @staticmethod
    def _scalar_parameter(
        arguments: Mapping[str, JsonValue],
        input_name: str,
        operation: Operation,
    ) -> str:
        if input_name not in arguments:
            raise InputSchemaError(
                "required mapped input is missing",
                details={"operation": operation.id, "parameter": input_name},
            )
        return HttpProvider._query_scalar(arguments[input_name], input_name, operation)

    @staticmethod
    def _query_scalar(value: JsonValue, input_name: str, operation: Operation) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, float) and not math.isfinite(value):
            raise InputSchemaError(
                "mapped HTTP inputs must contain finite numbers",
                details={"operation": operation.id, "parameter": input_name},
            )
        if isinstance(value, (str, int, float)):
            return str(value)
        raise InputSchemaError(
            "mapped HTTP inputs must be scalar values",
            details={"operation": operation.id, "parameter": input_name},
        )

    async def _send(
        self,
        client: httpx.AsyncClient,
        operation: Operation,
        url: str,
        headers: Mapping[str, str],
    ) -> JsonValue:
        timeout = httpx.Timeout(operation.http.timeout_seconds)
        request = httpx.Request(
            operation.http.method,
            url,
            headers=headers,
            extensions={"timeout": timeout.as_dict()},
        )
        response = await client.send(
            request,
            auth=None,
            follow_redirects=False,
            stream=True,
        )
        try:
            if self._response_origin(response) != self._response_origin(request):
                raise HttpRequestError(
                    "upstream response origin did not match the configured target",
                    details={"operation": operation.id},
                )
            if response.status_code == 401:
                self._log_status(operation, response.status_code)
                raise _OperationUnauthorized
            if response.status_code == 403:
                self._log_status(operation, response.status_code)
                raise HttpForbiddenError(
                    "upstream denied the request",
                    details={"operation": operation.id},
                )
            if response.status_code == 404:
                self._log_status(operation, response.status_code)
                raise HttpNotFoundError(
                    "upstream resource was not found",
                    details={"operation": operation.id},
                )
            if not 200 <= response.status_code < 300:
                self._log_status(operation, response.status_code)
                raise HttpUpstreamError(
                    "upstream returned a non-success status",
                    details={
                        "operation": operation.id,
                        "upstream_status": response.status_code,
                    },
                )

            if operation.http.method == "HEAD":
                return {}

            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = 0
                if declared_length > operation.http.max_response_bytes:
                    raise self._response_too_large(operation)

            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > operation.http.max_response_bytes:
                    raise self._response_too_large(operation)
        finally:
            await response.aclose()

        try:
            value = json.loads(body, parse_constant=self._reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            LOGGER.warning("HTTP operation returned invalid JSON operation=%s", operation.id)
            raise HttpInvalidJsonError(
                "upstream returned invalid JSON",
                details={"operation": operation.id},
            ) from exc
        return cast(JsonValue, value)

    @staticmethod
    def _response_too_large(operation: Operation) -> HttpResponseTooLargeError:
        LOGGER.warning("HTTP response exceeded limit operation=%s", operation.id)
        return HttpResponseTooLargeError(
            "upstream response exceeded the configured size limit",
            details={
                "operation": operation.id,
                "limit_bytes": operation.http.max_response_bytes,
                "phase": "operation",
            },
        )

    @staticmethod
    def _response_origin(message: httpx.Request | httpx.Response) -> tuple[str, str, int | None]:
        url = message.url
        return (url.scheme, url.host, url.port)

    @staticmethod
    def _reject_json_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    @staticmethod
    def _validate_schema(
        schema: Mapping[str, object],
        value: object,
        operation: Operation,
        *,
        input_value: bool,
    ) -> None:
        errors = sorted(
            Draft202012Validator(schema).iter_errors(value),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if not errors:
            return
        error = errors[0]
        details: dict[str, object] = {
            "operation": operation.id,
            "path": [str(part) for part in error.absolute_path],
            "schema_path": [str(part) for part in error.absolute_schema_path],
        }
        error_type = InputSchemaError if input_value else OutputSchemaError
        raise error_type(
            "operation input does not match its schema"
            if input_value
            else "upstream output does not match the operation schema",
            details=details,
        )

    @staticmethod
    def _log_status(operation: Operation, status: int) -> None:
        LOGGER.warning(
            "HTTP operation returned status operation=%s status=%d", operation.id, status
        )


__all__ = [
    "EnvironmentSecretResolver",
    "HttpBaseUrlError",
    "HttpForbiddenError",
    "HttpInvalidJsonError",
    "HttpMethodDeniedError",
    "HttpNotFoundError",
    "HttpOperationError",
    "HttpProvider",
    "HttpRequestError",
    "HttpResponseTooLargeError",
    "HttpTimeoutError",
    "HttpUpstreamError",
    "InputSchemaError",
    "OutputSchemaError",
    "ResolvedSecret",
    "SecretResolver",
]


class _OperationUnauthorized(Exception):
    """Internal response signal that never retains response content."""
