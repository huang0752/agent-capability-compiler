"""Bounded asynchronous REST provider for compiled HTTP operations."""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Never, Protocol, cast
from urllib.parse import quote, urlencode, urlsplit

import httpx
from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.models import (
    ActionOperationV2,
    JsonPointerApplicationSuccessConfig,
    ReadOperationV2,
)
from acc_core.models.actions import BodyInjectionTargetV2, HeaderInjectionTargetV2
from acc_runtime.actions.runtime_executor import ActionReadResult
from acc_runtime.auth import AuthAttempt, AuthUnauthorizedError, HttpAuthStrategy, NoAuthStrategy
from acc_runtime.context import PrincipalContext, sensitive_auth_name_marker
from acc_runtime.credentials import SecretValue, resolve_secret
from acc_runtime.errors import RuntimeError

LOGGER = logging.getLogger(__name__)


def _parse_json_pointer(pointer: str) -> tuple[str, ...]:
    parts: list[str] = []
    for raw in pointer.split("/")[1:]:
        index = 0
        decoded: list[str] = []
        while index < len(raw):
            if raw[index] != "~":
                decoded.append(raw[index])
                index += 1
                continue
            if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                raise ValueError("application success pointer contains an invalid escape")
            decoded.append("~" if raw[index + 1] == "0" else "/")
            index += 2
        parts.append("".join(decoded))
    return tuple(parts)


def _resolve_json_pointer(value: JsonValue, pointer: str) -> tuple[bool, JsonValue]:
    current: JsonValue = value
    for part in _parse_json_pointer(pointer):
        if isinstance(current, dict):
            if part not in current:
                return False, None
            current = current[part]
            continue
        if isinstance(current, list):
            if not part.isdecimal():
                return False, None
            index = int(part)
            if index >= len(current):
                return False, None
            current = current[index]
            continue
        return False, None
    return True, current


@dataclass(frozen=True, slots=True)
class _ProviderFailure:
    error_type: type[RuntimeError]
    message: str
    details: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _Cancelled:
    pass


_CANCELLED = _Cancelled()
type _ProviderOutcome = JsonValue | _ProviderFailure | _Cancelled
type _ExecutableReadOperation = ReadOperationV2
type _ExecutableHttpOperation = ReadOperationV2 | ActionOperationV2


@dataclass(frozen=True, slots=True)
class _DecodedResponse:
    value: JsonValue
    response_headers: Mapping[str, str]


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


class HttpApplicationError(RuntimeError):
    """A successful HTTP response failed its configured application-success contract."""

    code = "ACC_RUNTIME_HTTP_APPLICATION_ERROR"
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


class HttpRequestTooLargeError(RuntimeError):
    code = "ACC_RUNTIME_HTTP_REQUEST_TOO_LARGE"
    status = 400


class ResolvedSecret(Protocol):
    """Minimal redacted secret value accepted at the provider boundary."""

    def get_secret_value(self) -> str:
        """Explicitly unwrap the secret for the Authorization header."""


class SecretResolver(Protocol):
    """Small adapter seam for environment or external secret stores."""

    def resolve(self, reference: str) -> str | ResolvedSecret:
        """Resolve one named credential without exposing it in arguments."""


type JsonScalar = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class JsonApplicationSuccessPolicy:
    """Opt-in application-level success check for JSON envelope APIs.

    ``pointer`` is an RFC 6901 JSON Pointer and ``allowed_values`` contains the
    exact scalar values that represent application success. A missing pointer
    is a contract failure. The policy is deliberately opt-in so ordinary APIs
    and domain payloads with a field named ``code`` retain their existing
    semantics.
    """

    pointer: str
    allowed_values: tuple[JsonScalar, ...]

    @classmethod
    def from_config(
        cls, config: JsonPointerApplicationSuccessConfig
    ) -> JsonApplicationSuccessPolicy:
        """Create the runtime policy from the Pack's validated declaration."""

        return cls(pointer=config.pointer, allowed_values=tuple(config.allowed_values))

    def __post_init__(self) -> None:
        if not self.pointer.startswith("/"):
            raise ValueError("application success pointer must be a non-root JSON Pointer")
        _parse_json_pointer(self.pointer)
        if not self.allowed_values:
            raise ValueError("application success allowed_values must not be empty")
        seen: set[tuple[type[object], JsonScalar]] = set()
        for allowed in self.allowed_values:
            if isinstance(allowed, float) and not math.isfinite(allowed):
                raise ValueError("application success values must be finite JSON scalars")
            key = (type(allowed), allowed)
            if key in seen:
                raise ValueError("application success values must be type-exact unique")
            seen.add(key)

    def observed_value(self, value: JsonValue) -> tuple[bool, JsonValue]:
        found, observed = _resolve_json_pointer(value, self.pointer)
        return found, observed

    def matches(self, value: JsonValue) -> bool:
        found, observed = self.observed_value(value)
        return found and any(
            type(observed) is type(allowed) and observed == allowed
            for allowed in self.allowed_values
        )


class EnvironmentSecretResolver:
    """Resolve credentials using ACC's redacted environment abstraction."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = environment

    def resolve(self, reference: str) -> SecretValue:
        return resolve_secret(reference, self._environment)


def _load_read_operation(value: Mapping[str, object]) -> _ExecutableReadOperation:
    if value.get("kind") == "action":
        try:
            action = ActionOperationV2.model_validate(value)
        except ValidationError:
            raise HttpOperationError(
                "compiled HTTP operation is invalid",
                details={},
            ) from None
        raise HttpMethodDeniedError(
            "Action operations require the Action lifecycle",
            details={"operation": action.id},
        )
    try:
        return ReadOperationV2.model_validate(value)
    except ValidationError:
        raise HttpOperationError(
            "compiled HTTP operation is invalid",
            details={},
        ) from None


class HttpProvider:
    """Execute a statically declared GET/HEAD operation against one fixed origin."""

    def __init__(
        self,
        *,
        base_url_ref: str,
        secret_resolver: SecretResolver | None = None,
        auth_strategy: HttpAuthStrategy | None = None,
        environment: Mapping[str, str] | None = None,
        application_success_policy: JsonApplicationSuccessPolicy | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url_ref = base_url_ref
        self._environment = environment
        self._secret_resolver = secret_resolver or EnvironmentSecretResolver(environment)
        self._auth_strategy = auth_strategy or NoAuthStrategy()
        self._application_success_policy = application_success_policy
        self.client = client

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext | None = None,
    ) -> JsonValue:
        """Operation-caller protocol used by the generic workflow executor."""

        provider = self
        outcome = await provider._call_outcome(
            operation,
            arguments,
            principal_context,
        )
        if not isinstance(outcome, (_ProviderFailure, _Cancelled)):
            return outcome
        failure = outcome
        del outcome
        del operation
        del arguments
        del principal_context
        del provider
        del self
        _raise_provider_failure(failure)

    async def call_read(
        self,
        operation: ReadOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionReadResult:
        """Execute a current read while retaining only non-sensitive response metadata."""

        provider = self
        outcome = await provider._call_read_outcome(
            operation,
            arguments,
            principal_context,
        )
        if isinstance(outcome, ActionReadResult):
            return outcome
        failure = outcome
        del outcome
        del operation
        del arguments
        del principal_context
        del provider
        del self
        _raise_provider_failure(failure)

    async def call_action(
        self,
        operation: ActionOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
        *,
        idempotency_key: SecretValue,
        concurrency_token: JsonValue,
    ) -> JsonValue:
        """Execute one mutation once with Runtime-owned source controls."""

        provider = self
        outcome = await provider._call_action_outcome(
            operation,
            arguments,
            principal_context,
            idempotency_key=idempotency_key,
            concurrency_token=concurrency_token,
        )
        if not isinstance(outcome, (_ProviderFailure, _Cancelled)):
            return outcome
        failure = outcome
        del outcome
        del operation
        del arguments
        del principal_context
        del idempotency_key
        del concurrency_token
        del provider
        del self
        _raise_provider_failure(failure)

    async def _call_read_outcome(
        self,
        operation: ReadOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionReadResult | _ProviderFailure | _Cancelled:
        try:
            decoded = await self._execute_v2_read(operation, arguments, principal_context)
            return ActionReadResult(
                value=decoded.value,
                response_headers=_nonsensitive_response_headers(decoded.response_headers),
            )
        except asyncio.CancelledError:
            return _CANCELLED
        except RuntimeError as error:
            return _ProviderFailure(
                error_type=type(error),
                message="runtime request failed",
                details=dict(error.details),
            )
        except httpx.TimeoutException:
            return _ProviderFailure(
                error_type=HttpTimeoutError,
                message="upstream request timed out",
                details={"operation": operation.id, "phase": "operation"},
            )
        except Exception:
            return _ProviderFailure(
                error_type=HttpRequestError,
                message="upstream request failed",
                details={"operation": operation.id},
            )

    async def _call_action_outcome(
        self,
        operation: ActionOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
        *,
        idempotency_key: SecretValue,
        concurrency_token: JsonValue,
    ) -> _ProviderOutcome:
        try:
            return await self._execute_action(
                operation,
                arguments,
                principal_context,
                idempotency_key=idempotency_key,
                concurrency_token=concurrency_token,
            )
        except asyncio.CancelledError:
            return _CANCELLED
        except RuntimeError as error:
            return _ProviderFailure(
                error_type=type(error),
                message="runtime request failed",
                details=dict(error.details),
            )
        except httpx.TimeoutException:
            return _ProviderFailure(
                error_type=HttpTimeoutError,
                message="upstream request timed out",
                details={"operation": operation.id, "phase": "operation"},
            )
        except Exception:
            return _ProviderFailure(
                error_type=HttpRequestError,
                message="upstream request failed",
                details={"operation": operation.id},
            )

    async def _call_outcome(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext | None,
    ) -> _ProviderOutcome:
        try:
            definition = _load_read_operation(operation)
        except ValidationError:
            return _ProviderFailure(
                error_type=HttpOperationError,
                message="compiled HTTP operation is invalid",
                details={},
            )
        return await self._execute_outcome(
            definition,
            arguments,
            principal_context,
        )

    async def execute(
        self,
        operation: _ExecutableReadOperation,
        arguments: Mapping[str, JsonValue],
        *,
        principal_context: PrincipalContext | None = None,
    ) -> JsonValue:
        """Validate, execute, bound, decode, and validate one HTTP response."""

        provider = self
        outcome = await provider._execute_outcome(
            operation,
            arguments,
            principal_context,
        )
        if not isinstance(outcome, (_ProviderFailure, _Cancelled)):
            return outcome
        failure = outcome
        del outcome
        del operation
        del arguments
        del principal_context
        del provider
        del self
        _raise_provider_failure(failure)

    async def _execute_outcome(
        self,
        operation: _ExecutableReadOperation,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext | None,
    ) -> _ProviderOutcome:
        try:
            return await self._execute_operation(operation, arguments, principal_context)
        except asyncio.CancelledError:
            return _CANCELLED
        except RuntimeError as error:
            return _ProviderFailure(
                error_type=type(error),
                message="runtime request failed",
                details=dict(error.details),
            )
        except httpx.TimeoutException:
            LOGGER.warning("HTTP operation timed out operation=%s", operation.id)
            return _ProviderFailure(
                error_type=HttpTimeoutError,
                message="upstream request timed out",
                details={"operation": operation.id, "phase": "operation"},
            )
        except httpx.RequestError:
            LOGGER.warning("HTTP operation failed operation=%s", operation.id)
            return _ProviderFailure(
                error_type=HttpRequestError,
                message="upstream request failed",
                details={"operation": operation.id},
            )
        except Exception:
            LOGGER.warning("HTTP operation failed operation=%s", operation.id)
            return _ProviderFailure(
                error_type=HttpRequestError,
                message="upstream request failed",
                details={"operation": operation.id},
            )

    async def _execute_operation(
        self,
        operation: _ExecutableReadOperation,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext | None,
    ) -> JsonValue:
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

    async def _execute_v2_read(
        self,
        operation: ReadOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> _DecodedResponse:
        if not isinstance(operation, ReadOperationV2):
            raise HttpOperationError("compiled HTTP read operation is invalid", details={})
        self._validate_schema(operation.input_schema, arguments, operation, input_value=True)
        base_url = self._fixed_base_url(operation)
        if operation.http.method not in {"GET", "HEAD"}:
            raise HttpMethodDeniedError(
                "read provider permits only GET and HEAD operations",
                details={"operation": operation.id},
            )
        url = self._request_url(base_url, operation, arguments)
        attempt = await self._authentication_attempt(operation, principal_context)
        headers = self._request_headers(operation, attempt)
        if self.client is not None:
            decoded = await self._send_decoded_with_retry(
                self.client,
                operation,
                url,
                headers,
                principal_context,
                attempt,
            )
        else:
            async with httpx.AsyncClient(follow_redirects=False) as client:
                decoded = await self._send_decoded_with_retry(
                    client,
                    operation,
                    url,
                    headers,
                    principal_context,
                    attempt,
                )
        self._validate_schema(
            operation.output_schema,
            decoded.value,
            operation,
            input_value=False,
        )
        return decoded

    async def _execute_action(
        self,
        operation: ActionOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
        *,
        idempotency_key: SecretValue,
        concurrency_token: JsonValue,
    ) -> JsonValue:
        if not isinstance(operation, ActionOperationV2):
            raise HttpOperationError("compiled HTTP Action operation is invalid", details={})
        if not isinstance(idempotency_key, SecretValue):
            raise HttpOperationError(
                "Action idempotency key must be Runtime-owned",
                details={"operation": operation.id},
            )
        self._validate_schema(operation.input_schema, arguments, operation, input_value=True)
        base_url = self._fixed_base_url(operation)
        url = self._request_url(base_url, operation, arguments)
        attempt = await self._authentication_attempt(operation, principal_context)
        headers = self._request_headers(operation, attempt)
        body = self._request_body(operation, arguments)
        self._inject_action_controls(
            operation,
            headers,
            body,
            idempotency_key=idempotency_key,
            concurrency_token=concurrency_token,
        )
        encoded_body = self._encode_request_body(operation, body)
        if encoded_body is not None:
            self._inject_header(headers, "Content-Type", "application/json", operation)

        try:
            if self.client is not None:
                decoded = await self._send_decoded(
                    self.client,
                    operation,
                    url,
                    headers,
                    body=encoded_body,
                )
            else:
                async with httpx.AsyncClient(follow_redirects=False) as client:
                    decoded = await self._send_decoded(
                        client,
                        operation,
                        url,
                        headers,
                        body=encoded_body,
                    )
        except _OperationUnauthorized:
            raise AuthUnauthorizedError(
                "source authentication is unauthorized",
                details={"operation": operation.id},
            ) from None

        self._validate_schema(
            operation.output_schema,
            decoded.value,
            operation,
            input_value=False,
        )
        return decoded.value

    async def _authentication_attempt(
        self,
        operation: _ExecutableHttpOperation,
        principal_context: PrincipalContext | None,
    ) -> AuthAttempt:
        if not isinstance(principal_context, PrincipalContext):
            raise HttpOperationError(
                "provider authentication requires a trusted PrincipalContext",
                details={"operation": operation.id},
            )
        attempt = await self._auth_strategy.authorize(principal_context)
        if attempt.state_key != principal_context.auth_state_key:
            raise HttpOperationError(
                "authentication attempt does not belong to the PrincipalContext",
                details={"operation": operation.id},
            )
        return attempt

    def _request_headers(
        self,
        operation: _ExecutableHttpOperation,
        attempt: AuthAttempt,
    ) -> dict[str, str]:
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
        operation: _ExecutableReadOperation,
        url: str,
        headers: Mapping[str, str],
        principal_context: PrincipalContext | None,
        attempt: AuthAttempt,
    ) -> JsonValue:
        return (
            await self._send_decoded_with_retry(
                client,
                operation,
                url,
                headers,
                principal_context,
                attempt,
            )
        ).value

    async def _send_decoded_with_retry(
        self,
        client: httpx.AsyncClient,
        operation: _ExecutableReadOperation,
        url: str,
        headers: Mapping[str, str],
        principal_context: PrincipalContext | None,
        attempt: AuthAttempt,
    ) -> _DecodedResponse:
        try:
            return await self._send_decoded(client, operation, url, headers)
        except _OperationUnauthorized:
            if principal_context is None or not await self._auth_strategy.on_unauthorized(
                principal_context,
                attempt,
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
            return await self._send_decoded(client, operation, url, retry_headers)
        except _OperationUnauthorized:
            await self._auth_strategy.on_unauthorized(
                principal_context,
                retry_attempt,
            )
            raise AuthUnauthorizedError(
                "source authentication is unauthorized",
                details={"operation": operation.id},
            ) from None

    def _fixed_base_url(self, operation: _ExecutableHttpOperation) -> str:
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
        operation: _ExecutableHttpOperation,
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
        operation: _ExecutableHttpOperation,
    ) -> str:
        if input_name not in arguments:
            raise InputSchemaError(
                "required mapped input is missing",
                details={"operation": operation.id, "parameter": input_name},
            )
        return HttpProvider._query_scalar(arguments[input_name], input_name, operation)

    @staticmethod
    def _query_scalar(
        value: JsonValue,
        input_name: str,
        operation: _ExecutableHttpOperation,
    ) -> str:
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

    @staticmethod
    def _request_body(
        operation: ActionOperationV2,
        arguments: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue] | None:
        request = operation.http.request
        if request is None:
            return None
        body: dict[str, JsonValue] = {}
        for pointer, input_name in request.body_parameters.items():
            if input_name not in arguments:
                continue
            HttpProvider._inject_body_pointer(
                body,
                pointer,
                copy.deepcopy(arguments[input_name]),
                operation,
            )
        return body

    def _inject_action_controls(
        self,
        operation: ActionOperationV2,
        headers: dict[str, str],
        body: dict[str, JsonValue] | None,
        *,
        idempotency_key: SecretValue,
        concurrency_token: JsonValue,
    ) -> None:
        idempotency = operation.http.safety.idempotency
        if idempotency.mode == "source_key":
            target = idempotency.target
            assert target is not None
            self._inject_runtime_target(
                operation,
                headers,
                body,
                target,
                idempotency_key.get_secret_value(),
            )

        concurrency = operation.http.safety.concurrency
        if concurrency.mode == "required":
            if concurrency_token is None:
                raise HttpOperationError(
                    "required Action concurrency token is unavailable",
                    details={"operation": operation.id},
                )
            target = concurrency.precondition
            assert target is not None
            self._inject_runtime_target(
                operation,
                headers,
                body,
                target,
                copy.deepcopy(concurrency_token),
            )

    @staticmethod
    def _inject_runtime_target(
        operation: ActionOperationV2,
        headers: dict[str, str],
        body: dict[str, JsonValue] | None,
        target: HeaderInjectionTargetV2 | BodyInjectionTargetV2,
        value: JsonValue,
    ) -> None:
        if isinstance(target, HeaderInjectionTargetV2):
            rendered = HttpProvider._header_scalar(value, operation)
            HttpProvider._inject_header(headers, target.name, rendered, operation)
            return
        if body is None:
            raise HttpOperationError(
                "Action body injection requires a declared JSON request",
                details={"operation": operation.id},
            )
        HttpProvider._inject_body_pointer(body, target.pointer, value, operation)

    @staticmethod
    def _inject_header(
        headers: dict[str, str],
        name: str,
        value: str,
        operation: _ExecutableHttpOperation,
    ) -> None:
        if any(existing.casefold() == name.casefold() for existing in headers):
            raise HttpOperationError(
                "Runtime-owned Action header conflicts with an existing header",
                details={"operation": operation.id},
            )
        headers[name] = value

    @staticmethod
    def _header_scalar(value: JsonValue, operation: ActionOperationV2) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, float) and not math.isfinite(value):
            raise HttpOperationError(
                "Runtime-owned Action header value is invalid",
                details={"operation": operation.id},
            )
        if isinstance(value, (str, int, float)):
            return str(value)
        raise HttpOperationError(
            "Runtime-owned Action header value must be scalar",
            details={"operation": operation.id},
        )

    @staticmethod
    def _inject_body_pointer(
        body: dict[str, JsonValue],
        pointer: str,
        value: JsonValue,
        operation: ActionOperationV2,
    ) -> None:
        tokens = tuple(
            token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]
        )
        if not tokens:
            raise HttpOperationError(
                "Action request body pointer is invalid",
                details={"operation": operation.id},
            )
        current = body
        for token in tokens[:-1]:
            existing = current.get(token)
            if existing is None and token not in current:
                child: dict[str, JsonValue] = {}
                current[token] = child
                current = child
            elif isinstance(existing, dict):
                current = existing
            else:
                raise HttpOperationError(
                    "Action request body mappings conflict",
                    details={"operation": operation.id},
                )
        final = tokens[-1]
        if final in current:
            raise HttpOperationError(
                "Action request body mappings conflict",
                details={"operation": operation.id},
            )
        current[final] = copy.deepcopy(value)

    @staticmethod
    def _encode_request_body(
        operation: ActionOperationV2,
        body: dict[str, JsonValue] | None,
    ) -> bytes | None:
        request = operation.http.request
        if request is None:
            return None
        try:
            encoded = json.dumps(
                body,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise HttpOperationError(
                "Action request body is not valid JSON",
                details={"operation": operation.id},
            ) from None
        if len(encoded) > request.max_request_bytes:
            raise HttpRequestTooLargeError(
                "Action request body exceeded its configured size limit",
                details={
                    "operation": operation.id,
                    "limit_bytes": request.max_request_bytes,
                    "phase": "operation",
                },
            )
        return encoded

    async def _send(
        self,
        client: httpx.AsyncClient,
        operation: _ExecutableReadOperation,
        url: str,
        headers: Mapping[str, str],
    ) -> JsonValue:
        return (await self._send_decoded(client, operation, url, headers)).value

    async def _send_decoded(
        self,
        client: httpx.AsyncClient,
        operation: _ExecutableHttpOperation,
        url: str,
        headers: Mapping[str, str],
        *,
        body: bytes | None = None,
    ) -> _DecodedResponse:
        timeout = httpx.Timeout(operation.http.timeout_seconds)
        request = httpx.Request(
            operation.http.method,
            url,
            headers=headers,
            content=body,
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
            successful = response.status_code in operation.http.success.statuses
            if not successful:
                self._log_status(operation, response.status_code)
                raise HttpUpstreamError(
                    "upstream returned a non-success status",
                    details={
                        "operation": operation.id,
                        "upstream_status": response.status_code,
                    },
                )

            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = 0
                if declared_length > operation.http.max_response_bytes:
                    raise self._response_too_large(operation)

            response_body = bytearray()
            async for chunk in response.aiter_bytes():
                response_body.extend(chunk)
                if len(response_body) > operation.http.max_response_bytes:
                    raise self._response_too_large(operation)
            response_headers = dict(response.headers)
        finally:
            await response.aclose()

        body_mode = operation.http.success.body
        if body_mode == "empty":
            if response_body:
                raise HttpInvalidJsonError(
                    "upstream returned a body forbidden by the success contract",
                    details={"operation": operation.id},
                )
            value: JsonValue = None
        elif body_mode == "json_or_empty" and not response_body:
            value = None
        else:
            value = self._decode_json_body(operation, response_body)
        self._enforce_application_success(operation, value)
        return _DecodedResponse(value=value, response_headers=response_headers)

    def _decode_json_body(
        self,
        operation: _ExecutableHttpOperation,
        body: bytes | bytearray,
    ) -> JsonValue:
        try:
            value = json.loads(body, parse_constant=self._reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            LOGGER.warning("HTTP operation returned invalid JSON operation=%s", operation.id)
            raise HttpInvalidJsonError(
                "upstream returned invalid JSON",
                details={"operation": operation.id},
            ) from exc
        return cast(JsonValue, value)

    def _enforce_application_success(
        self,
        operation: _ExecutableHttpOperation,
        value: JsonValue,
    ) -> None:
        policy = self._application_success_policy
        if policy is None or policy.matches(value):
            return
        found, observed = policy.observed_value(value)
        details: dict[str, object] = {"operation": operation.id}
        if not found:
            details["application_code"] = "missing"
        elif type(observed) in {int, float, bool} or observed is None:
            details["application_code"] = observed
        else:
            details["application_code"] = "redacted"
        LOGGER.warning("HTTP application success contract failed operation=%s", operation.id)
        raise HttpApplicationError(
            "upstream returned an application-level error",
            details=details,
        )

    @staticmethod
    def _response_too_large(
        operation: _ExecutableHttpOperation,
    ) -> HttpResponseTooLargeError:
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
        operation: _ExecutableHttpOperation,
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
    def _log_status(operation: _ExecutableHttpOperation, status: int) -> None:
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
    "HttpRequestTooLargeError",
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


def _nonsensitive_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    forbidden = {
        "connection",
        "proxy-authenticate",
        "set-cookie",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "www-authenticate",
    }
    return {
        name: value
        for name, value in headers.items()
        if name.casefold() not in forbidden and sensitive_auth_name_marker(name) is None
    }


def _raise_provider_failure(failure: _ProviderFailure | _Cancelled) -> Never:
    if isinstance(failure, _Cancelled):
        raise asyncio.CancelledError from None
    raise failure.error_type(failure.message, details=failure.details) from None
