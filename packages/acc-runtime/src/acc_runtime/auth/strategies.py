"""Provider-level HTTP authentication with isolated, bounded token state."""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import math
import re
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Literal, Never, Protocol, cast
from urllib.parse import urlsplit

import httpx
from pydantic import JsonValue

from acc_core.models import PasswordBearerAuthConfig
from acc_runtime.auth.credentials import (
    CredentialPair,
    CredentialSource,
    RenewableCredentialSource,
)
from acc_runtime.auth.errors import (
    AuthConfigurationError,
    AuthCredentialError,
    AuthError,
    AuthInvalidResponseError,
    AuthLoginRejectedError,
    AuthReauthenticationRequiredError,
    AuthRequestError,
    AuthResponseTooLargeError,
    AuthTimeoutError,
    AuthUpstreamError,
)
from acc_runtime.context import AuthStateKey, PrincipalContext
from acc_runtime.credentials import (
    SecretValue,
    resolve_secret,
)

LOGGER = logging.getLogger(__name__)
_MISSING = object()
_BEARER_TOKEN_TYPE = re.compile(r"bearer", re.IGNORECASE)
_MAX_LOGIN_REQUEST_BYTES = 65_536
_MAX_SCOPE_DISCOVERY_REQUEST_BYTES = 8_192
_MAX_SPACE_DELIMITED_SCOPE_BYTES = 8_192
_MAX_SPACE_DELIMITED_SCOPES = 1_024
_ASCII_SCOPE_WHITESPACE = re.compile(r"[ \t\r\n\v\f]+")


class _LoginRequestTooLargeError(Exception):
    pass


type AsyncClientFactory = Callable[[], httpx.AsyncClient]
type _FailureKind = Literal[
    "configuration",
    "secret_missing",
    "login_rejected",
    "upstream",
    "request",
    "response_invalid",
    "timeout",
    "response_too_large",
    "unauthorized",
    "invalid_credentials",
    "invalid_context",
    "invalid_state_key",
    "invalid_result",
    "invalid_attempt",
    "attempt_mismatch",
]


def _freeze_json(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return cast(
            JsonValue,
            MappingProxyType({key: _freeze_json(item) for key, item in value.items()}),
        )
    if isinstance(value, list):
        return cast(JsonValue, tuple(_freeze_json(item) for item in value))
    return value


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationResult:
    """Redacted login material plus public claims needed to build a Principal."""

    token: SecretValue | None
    token_type: str | None = None
    principal_id: str | None = None
    source_scopes: frozenset[str] | None = None
    tenant_context: Mapping[str, JsonValue] | None = None
    expires_at: float | None = None
    refresh_at: float | None = None

    def __post_init__(self) -> None:
        if self.token is not None and not isinstance(self.token, SecretValue):
            raise TypeError("token must be a SecretValue")
        if (self.token is None) != (self.token_type is None):
            raise ValueError("token and token_type must be provided together")
        if self.source_scopes is not None:
            object.__setattr__(self, "source_scopes", frozenset(self.source_scopes))
        if self.tenant_context is not None:
            copied = cast(JsonValue, copy.deepcopy(dict(self.tenant_context)))
            frozen = _freeze_json(copied)
            if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
                raise TypeError("tenant context must be a mapping")
            object.__setattr__(self, "tenant_context", frozen)

    @property
    def authorization(self) -> SecretValue | None:
        """Build the redacted request header value without exposing the token."""

        if self.token is None or self.token_type is None:
            return None
        return SecretValue(f"{self.token_type} {self.token.get_secret_value()}")


@dataclass(frozen=True, slots=True)
class _FailureDescriptor:
    """Secret-free authentication failure passed across the execution boundary."""

    kind: _FailureKind
    upstream_status: int | None = None
    reason: str | None = None
    limit_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class _CancelledDescriptor:
    """Marker used to recreate cancellation beyond the secret-bearing boundary."""


_CANCELLED = _CancelledDescriptor()
type _PublicFailure = (
    _FailureDescriptor
    | _CancelledDescriptor
    | AuthError
    | AuthTimeoutError
    | AuthResponseTooLargeError
)


@dataclass(frozen=True, slots=True, repr=False)
class AuthAttempt:
    """One generation-bound request attempt safe to feed back after a 401."""

    headers: Mapping[str, SecretValue]
    state_key: AuthStateKey
    generation: int
    authentication: AuthenticationResult

    def __post_init__(self) -> None:
        if not isinstance(self.state_key, AuthStateKey):
            raise TypeError("authentication attempt requires an AuthStateKey")
        if not isinstance(self.generation, int) or self.generation < 0:
            raise TypeError("authentication attempt generation must be a nonnegative integer")
        _require_result(self.authentication)
        copied_headers = dict(self.headers)
        if any(
            not isinstance(name, str) or not isinstance(value, SecretValue)
            for name, value in copied_headers.items()
        ):
            raise TypeError("authentication attempt headers must contain SecretValue values")
        object.__setattr__(self, "headers", MappingProxyType(copied_headers))


class HttpAuthStrategy(Protocol):
    """Return request authentication and react to an explicit 401 signal."""

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        """Return a generation-bound attempt for the trusted Principal."""

    async def headers(self, context: PrincipalContext) -> AuthAttempt:
        """Alias used by the stdio composition root."""

    async def on_unauthorized(
        self,
        context: PrincipalContext,
        failed_attempt: AuthAttempt,
    ) -> bool:
        """Invalidate only the failed generation and report whether retry is possible."""

    async def invalidate(self, auth_state_key: AuthStateKey) -> None:
        """Release all state for one complete authentication-state key."""

    async def aclose(self) -> None:
        """Release all strategy-owned authentication state."""


class NoAuthStrategy:
    """Explicit no-auth strategy that never touches credentials."""

    _RESULT = AuthenticationResult(token=None)

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        strategy = self
        outcome = strategy._authorize_outcome(context)
        if isinstance(outcome, AuthAttempt):
            return outcome
        failure = outcome
        del outcome
        del context
        del strategy
        del self
        _raise_public_failure(failure)

    def _authorize_outcome(self, context: object) -> AuthAttempt | _FailureDescriptor:
        if not isinstance(context, PrincipalContext):
            return _FailureDescriptor(kind="invalid_context")
        try:
            return AuthAttempt(
                headers={},
                state_key=context.auth_state_key,
                generation=0,
                authentication=self._RESULT,
            )
        except Exception:
            return _FailureDescriptor(kind="configuration")

    headers = authorize

    async def on_unauthorized(
        self,
        context: PrincipalContext,
        failed_attempt: AuthAttempt,
    ) -> bool:
        outcome = _no_retry_feedback_outcome(context, failed_attempt)
        if isinstance(outcome, bool):
            return outcome
        failure = outcome
        del context
        del failed_attempt
        del self
        _raise_public_failure(failure)

    async def invalidate(self, auth_state_key: AuthStateKey) -> None:
        failure = _state_key_failure(auth_state_key)
        if failure is None:
            return
        del auth_state_key
        del self
        _raise_public_failure(failure)

    async def aclose(self) -> None:
        return None


class BearerSecretAuthStrategy:
    """Resolve a fixed Bearer secret afresh for every request."""

    __slots__ = ("_environment", "_token_ref")

    def __init__(
        self,
        token_ref: str,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._token_ref = token_ref
        self._environment = environment

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        strategy = self
        outcome = strategy._authorize_outcome(context)
        if isinstance(outcome, AuthAttempt):
            return outcome
        failure = outcome
        del outcome
        del context
        del strategy
        del self
        _raise_public_failure(failure)

    def _authorize_outcome(self, context: object) -> AuthAttempt | _FailureDescriptor:
        if not isinstance(context, PrincipalContext):
            return _FailureDescriptor(kind="invalid_context")
        token: SecretValue | None = None
        raw_token: str | None = None
        try:
            token = resolve_secret(self._token_ref, self._environment)
            raw_token = _secret_text(token, field="token")
            result = AuthenticationResult(token=SecretValue(raw_token), token_type="Bearer")
            assert result.authorization is not None
            return AuthAttempt(
                headers={"Authorization": result.authorization},
                state_key=context.auth_state_key,
                generation=0,
                authentication=result,
            )
        except Exception:
            return _FailureDescriptor(kind="secret_missing")
        finally:
            token = None
            raw_token = None

    headers = authorize

    async def on_unauthorized(
        self,
        context: PrincipalContext,
        failed_attempt: AuthAttempt,
    ) -> bool:
        outcome = _no_retry_feedback_outcome(context, failed_attempt)
        if isinstance(outcome, bool):
            return outcome
        failure = outcome
        del context
        del failed_attempt
        del self
        _raise_public_failure(failure)

    async def invalidate(self, auth_state_key: AuthStateKey) -> None:
        failure = _state_key_failure(auth_state_key)
        if failure is None:
            return
        del auth_state_key
        del self
        _raise_public_failure(failure)

    async def aclose(self) -> None:
        return None


@dataclass(slots=True)
class _BoundState:
    attempt: AuthAttempt | None
    renewable: bool
    reauthentication_required: bool = False


@dataclass(slots=True)
class _InFlight:
    task: asyncio.Task[AuthAttempt]
    waiters: int = 0


class PasswordBearerAuthStrategy:
    """Exchange bounded credentials for isolated in-memory Bearer state."""

    __slots__ = (
        "_base_url",
        "_client_factory",
        "_clock",
        "_closed",
        "_configuration",
        "_credential_source",
        "_generations",
        "_inflight",
        "_origin",
        "_state_lock",
        "_states",
    )

    def __init__(
        self,
        *,
        config: PasswordBearerAuthConfig,
        base_url: str,
        credential_source: CredentialSource | None,
        client_factory: AsyncClientFactory | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._configuration = config
        self._origin = _fixed_origin(base_url)
        self._base_url = base_url.rstrip("/")
        credentials_kind = config.credentials.kind
        if credentials_kind == "environment_secret":
            if (
                credential_source is None
                or not credential_source.renewable
                or not callable(getattr(credential_source, "acquire", None))
            ):
                raise AuthConfigurationError(
                    "environment authentication requires a renewable credential source"
                )
        elif credential_source is not None:
            raise AuthConfigurationError(
                "gateway session authentication accepts credentials only at login"
            )
        self._credential_source = credential_source
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(follow_redirects=False))
        self._clock = clock or time.monotonic
        self._states: dict[AuthStateKey, _BoundState] = {}
        self._generations: dict[AuthStateKey, int] = {}
        self._inflight: dict[AuthStateKey, _InFlight] = {}
        self._state_lock = asyncio.Lock()
        self._closed = False

    async def authenticate_once(
        self,
        credentials: CredentialPair,
    ) -> AuthenticationResult:
        """Login without a Principal so Gateway session creation has no identity cycle."""

        strategy = self
        outcome: AuthenticationResult | _PublicFailure
        if strategy._closed:
            outcome = _FailureDescriptor(kind="configuration")
        elif not isinstance(cast(object, credentials), CredentialPair):
            outcome = _FailureDescriptor(kind="invalid_credentials")
        else:
            try:
                outcome = await strategy._authentication_outcome(credentials)
            except asyncio.CancelledError:
                outcome = _CANCELLED
        if isinstance(outcome, AuthenticationResult):
            return outcome
        failure = outcome
        del outcome
        del credentials
        del strategy
        del self
        _raise_public_failure(failure)

    async def _authentication_outcome(
        self,
        credentials: CredentialPair,
    ) -> AuthenticationResult | _FailureDescriptor:
        """Perform one login while containing every secret-bearing object."""

        identity: str | None = None
        password: str | None = None
        body: bytes | None = None
        request: httpx.Request | None = None
        response: httpx.Response | None = None
        payload: JsonValue | object = _MISSING
        client: httpx.AsyncClient | None = None
        result: AuthenticationResult | None = None
        failure: _FailureDescriptor | None = None
        try:
            identity = _secret_text(credentials.identity, field="identity")
            password = _secret_text(credentials.password, field="password")
            body = json.dumps(
                {
                    **self._configuration.login_request.static_fields,
                    self._configuration.identity_field: identity,
                    self._configuration.password_field: password,
                },
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode()
            if len(body) > _MAX_LOGIN_REQUEST_BYTES:
                raise _LoginRequestTooLargeError
            request = httpx.Request(
                "POST",
                f"{self._base_url}{self._configuration.login_path}",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                content=body,
                extensions={
                    "timeout": httpx.Timeout(self._configuration.timeout_seconds).as_dict()
                },
            )
            client = self._client_factory()
            async with client:
                response = await client.send(
                    request,
                    auth=None,
                    follow_redirects=False,
                    stream=True,
                )
                try:
                    if _origin(response.url) != self._origin:
                        failure = _FailureDescriptor(
                            kind="response_invalid",
                            reason="origin_mismatch",
                        )
                    elif 300 <= response.status_code < 500:
                        LOGGER.warning(
                            "source login was rejected status=%s",
                            response.status_code,
                        )
                        failure = _FailureDescriptor(
                            kind="login_rejected",
                            upstream_status=response.status_code,
                        )
                    elif response.status_code >= 500 or response.status_code < 200:
                        LOGGER.warning(
                            "source login returned an upstream failure status=%s",
                            response.status_code,
                        )
                        failure = _FailureDescriptor(
                            kind="upstream",
                            upstream_status=response.status_code,
                        )
                    else:
                        payload = await self._bounded_json(response)
                        result = self._authentication_result(payload)
                finally:
                    await response.aclose()
                if failure is None and result is not None and self._configuration.scope_discovery:
                    discovered = await self._discover_scopes(client, result)
                    result = replace(result, source_scopes=discovered)
        except asyncio.CancelledError:
            raise
        except AuthResponseTooLargeError:
            failure = _FailureDescriptor(
                kind="response_too_large",
                limit_bytes=self._configuration.max_response_bytes,
            )
        except AuthInvalidResponseError as error:
            reason = error.details.get("reason")
            failure = _FailureDescriptor(
                kind="response_invalid",
                reason=reason if isinstance(reason, str) else "invalid_response",
            )
        except AuthCredentialError:
            failure = _FailureDescriptor(kind="secret_missing")
        except _LoginRequestTooLargeError:
            failure = _FailureDescriptor(kind="configuration")
        except httpx.TimeoutException:
            failure = _FailureDescriptor(kind="timeout")
        except httpx.RequestError:
            failure = _FailureDescriptor(kind="request")
        except Exception:
            failure = _FailureDescriptor(kind="request")
        finally:
            del credentials
            identity = None
            password = None
            body = None
            request = None
            response = None
            payload = _MISSING
            client = None

        if failure is not None:
            return failure
        if result is None:  # pragma: no cover - every non-cancelled branch classifies an outcome
            return _FailureDescriptor(kind="request")
        return result

    async def bind_state(
        self,
        auth_state_key: AuthStateKey,
        result: AuthenticationResult,
    ) -> None:
        """Bind a pre-context login result only after Gateway builds the final Principal."""

        strategy = self
        try:
            failure = await strategy._bind_state_outcome(auth_state_key, result)
        except asyncio.CancelledError:
            failure = _CANCELLED
        if failure is None:
            return
        del auth_state_key
        del result
        del strategy
        del self
        _raise_public_failure(failure)

    async def _bind_state_outcome(
        self,
        auth_state_key: object,
        result: object,
    ) -> _PublicFailure | None:
        if self._closed:
            return _FailureDescriptor(kind="configuration")
        if not isinstance(auth_state_key, AuthStateKey):
            return _FailureDescriptor(kind="invalid_state_key")
        if not isinstance(result, AuthenticationResult):
            return _FailureDescriptor(kind="invalid_result")
        try:
            async with self._state_lock:
                attempt = self._new_attempt(auth_state_key, result)
                self._states[auth_state_key] = _BoundState(
                    attempt=attempt,
                    renewable=self._configuration.credentials.kind == "environment_secret",
                )
        except asyncio.CancelledError:
            return _CANCELLED
        except Exception:
            return _FailureDescriptor(kind="configuration")
        return None

    async def authorize(self, context: PrincipalContext) -> AuthAttempt:
        strategy = self
        try:
            outcome = await strategy._authorize_outcome(context)
        except asyncio.CancelledError:
            outcome = _CANCELLED
        if isinstance(outcome, AuthAttempt):
            return outcome
        failure = outcome
        del outcome
        del context
        del strategy
        del self
        _raise_public_failure(failure)

    async def _authorize_outcome(
        self,
        context: object,
    ) -> AuthAttempt | _PublicFailure:
        if self._closed:
            return _FailureDescriptor(kind="configuration")
        if not isinstance(context, PrincipalContext):
            return _FailureDescriptor(kind="invalid_context")
        key = context.auth_state_key
        try:
            async with self._state_lock:
                state = self._states.get(key)
                if state is not None and state.reauthentication_required:
                    return _FailureDescriptor(kind="unauthorized")
                if state is not None and state.attempt is not None:
                    if _result_is_fresh(state.attempt.authentication, self._clock()):
                        return state.attempt
                    if not state.renewable:
                        state.attempt = None
                        state.reauthentication_required = True
                        return _FailureDescriptor(kind="unauthorized")

                source = self._credential_source
                if source is None or not source.renewable:
                    if state is None:
                        self._states[key] = _BoundState(
                            attempt=None,
                            renewable=False,
                            reauthentication_required=True,
                        )
                    else:
                        state.attempt = None
                        state.reauthentication_required = True
                    return _FailureDescriptor(kind="unauthorized")
                flight = self._inflight.get(key)
                if flight is None:
                    task = asyncio.create_task(self._renew_state(key))
                    flight = _InFlight(task=task)
                    self._inflight[key] = flight

                    def completed(_completed: asyncio.Future[AuthAttempt]) -> None:
                        self._flight_done(key, flight)

                    task.add_done_callback(completed)
                flight.waiters += 1
        except asyncio.CancelledError:
            return _CANCELLED
        except Exception:
            return _FailureDescriptor(kind="configuration")

        outcome = await _await_shared_attempt(flight.task)
        if isinstance(outcome, AuthAttempt):
            attempt = outcome
            failure: _PublicFailure | None = None
        else:
            attempt = None
            failure = outcome
        try:
            await self._release_waiter(key, flight)
        except asyncio.CancelledError:
            attempt = None
            failure = _CANCELLED
        except Exception:
            attempt = None
            failure = _FailureDescriptor(kind="configuration")
        if failure is not None:
            return failure
        if attempt is None:  # pragma: no cover - the shared task returns or raises
            return _FailureDescriptor(kind="request")
        return attempt

    headers = authorize

    async def on_unauthorized(
        self,
        context: PrincipalContext,
        failed_attempt: AuthAttempt,
    ) -> bool:
        strategy = self
        try:
            outcome = await strategy._unauthorized_outcome(context, failed_attempt)
        except asyncio.CancelledError:
            outcome = _CANCELLED
        if isinstance(outcome, bool):
            return outcome
        failure = outcome
        del outcome
        del context
        del failed_attempt
        del strategy
        del self
        _raise_public_failure(failure)

    async def _unauthorized_outcome(
        self,
        context: object,
        failed_attempt: object,
    ) -> bool | _PublicFailure:
        if self._closed:
            return _FailureDescriptor(kind="configuration")
        if not isinstance(context, PrincipalContext):
            return _FailureDescriptor(kind="invalid_context")
        key = context.auth_state_key
        if not isinstance(failed_attempt, AuthAttempt):
            return _FailureDescriptor(kind="invalid_attempt")
        if failed_attempt.state_key != key:
            return _FailureDescriptor(kind="attempt_mismatch")
        try:
            async with self._state_lock:
                state = self._states.get(key)
                if state is None:
                    return self._retry_on_unauthorized()
                if state.attempt is None or state.attempt.generation != failed_attempt.generation:
                    return state.renewable and self._retry_on_unauthorized()
                if state.renewable:
                    del self._states[key]
                    return self._retry_on_unauthorized()
                state.attempt = None
                state.reauthentication_required = True
                return False
        except asyncio.CancelledError:
            return _CANCELLED
        except Exception:
            return _FailureDescriptor(kind="configuration")

    async def invalidate(self, auth_state_key: AuthStateKey) -> None:
        """Release a Principal's token, generation, and in-flight login."""

        strategy = self
        try:
            failure = await strategy._invalidate_outcome(auth_state_key)
        except asyncio.CancelledError:
            failure = _CANCELLED
        if failure is None:
            return
        del auth_state_key
        del strategy
        del self
        _raise_public_failure(failure)

    async def _invalidate_outcome(
        self,
        auth_state_key: object,
    ) -> _PublicFailure | None:
        if not isinstance(auth_state_key, AuthStateKey):
            return _FailureDescriptor(kind="invalid_state_key")
        if self._closed:
            return None
        try:
            async with self._state_lock:
                self._states.pop(auth_state_key, None)
                self._generations.pop(auth_state_key, None)
                flight = self._inflight.pop(auth_state_key, None)
            if flight is not None and not flight.task.done():
                flight.task.cancel()
                await asyncio.gather(flight.task, return_exceptions=True)
        except asyncio.CancelledError:
            return _CANCELLED
        except Exception:
            return _FailureDescriptor(kind="configuration")
        return None

    async def aclose(self) -> None:
        """Cancel outstanding logins and erase all in-memory authentication state."""

        strategy = self
        try:
            failure = await strategy._close_outcome()
        except asyncio.CancelledError:
            failure = _CANCELLED
        if failure is None:
            return
        del strategy
        del self
        _raise_public_failure(failure)

    async def _close_outcome(self) -> _PublicFailure | None:
        try:
            async with self._state_lock:
                if self._closed and not self._inflight:
                    return None
                self._closed = True
                flights = tuple(self._inflight.values())
                self._inflight.clear()
                self._states.clear()
                self._generations.clear()
            tasks = tuple(flight.task for flight in flights if not flight.task.done())
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            return _CANCELLED
        except Exception:
            return _FailureDescriptor(kind="configuration")
        return None

    async def _renew_state(self, key: AuthStateKey) -> AuthAttempt:
        strategy = self
        source: RenewableCredentialSource | None = cast(
            RenewableCredentialSource | None,
            strategy._credential_source,
        )
        credentials: CredentialPair | None = None
        outcome: AuthenticationResult | _FailureDescriptor | None = None
        result: AuthenticationResult | None = None
        failure: _FailureDescriptor | None = None
        if source is None:
            failure = _FailureDescriptor(kind="secret_missing")
        else:
            try:
                credentials = await source.acquire(key)
            except asyncio.CancelledError:
                credentials = None
                source = None
                del strategy
                del self
                raise
            except Exception:
                failure = _FailureDescriptor(kind="secret_missing")
        if failure is None and not isinstance(credentials, CredentialPair):
            failure = _FailureDescriptor(kind="secret_missing")
        if failure is None:
            assert credentials is not None
            try:
                outcome = await strategy._authentication_outcome(credentials)
            except asyncio.CancelledError:
                credentials = None
                source = None
                del strategy
                del self
                raise
            if isinstance(outcome, _FailureDescriptor):
                failure = outcome
            else:
                result = outcome
        credentials = None
        source = None
        outcome = None
        if failure is not None:
            del strategy
            del self
            _raise_failure(failure)
        assert result is not None

        attempt: AuthAttempt | None = None
        try:
            async with strategy._state_lock:
                if strategy._closed:
                    failure = _FailureDescriptor(kind="configuration")
                else:
                    attempt = strategy._new_attempt(key, result)
                    strategy._states[key] = _BoundState(attempt=attempt, renewable=True)
        except asyncio.CancelledError:
            result = None
            attempt = None
            del strategy
            del self
            raise
        except Exception:
            failure = _FailureDescriptor(kind="configuration")
        if failure is not None:
            result = None
            attempt = None
            del strategy
            del self
            _raise_failure(failure)
        assert attempt is not None
        return attempt

    async def _release_waiter(self, key: AuthStateKey, flight: _InFlight) -> None:
        if self._closed:
            return
        task_to_cancel: asyncio.Task[AuthAttempt] | None = None
        async with self._state_lock:
            current = self._inflight.get(key)
            if current is not flight:
                return
            flight.waiters -= 1
            if flight.waiters == 0:
                self._inflight.pop(key, None)
                if not flight.task.done():
                    task_to_cancel = flight.task
        if task_to_cancel is not None:
            task_to_cancel.cancel()
            await asyncio.gather(task_to_cancel, return_exceptions=True)

    def _flight_done(self, key: AuthStateKey, flight: _InFlight) -> None:
        with suppress(asyncio.CancelledError):
            flight.task.exception()
        if not self._closed:
            asyncio.get_running_loop().create_task(self._cleanup_completed_flight(key, flight))

    async def _cleanup_completed_flight(
        self,
        key: AuthStateKey,
        flight: _InFlight,
    ) -> None:
        if self._closed:
            return
        async with self._state_lock:
            if self._inflight.get(key) is flight and flight.waiters == 0:
                self._inflight.pop(key, None)

    def _retry_on_unauthorized(self) -> bool:
        return (
            self._configuration.credentials.kind == "environment_secret"
            and self._configuration.retry_on_unauthorized
        )

    def _new_attempt(
        self,
        key: AuthStateKey,
        result: AuthenticationResult,
    ) -> AuthAttempt:
        generation = self._generations.get(key, 0) + 1
        self._generations[key] = generation
        headers = {} if result.authorization is None else {"Authorization": result.authorization}
        return AuthAttempt(
            headers=headers,
            state_key=key,
            generation=generation,
            authentication=result,
        )

    async def _bounded_json(
        self, response: httpx.Response, *, limit: int | None = None
    ) -> JsonValue:
        limit = self._configuration.max_response_bytes if limit is None else limit
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0
            if declared_length > limit:
                raise _response_too_large(limit)

        body = bytearray()
        async for chunk in response.aiter_bytes():
            remaining = limit + 1 - len(body)
            body.extend(chunk[:remaining])
            if len(body) > limit:
                raise _response_too_large(limit)
        invalid_json = False
        try:
            parsed = cast(
                JsonValue,
                json.loads(body, parse_constant=_reject_json_constant),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            invalid_json = True
            parsed = None
        if invalid_json:
            LOGGER.warning("source login returned invalid JSON")
            raise _invalid_response("invalid_json")
        return parsed

    async def _discover_scopes(
        self,
        client: httpx.AsyncClient,
        result: AuthenticationResult,
    ) -> frozenset[str]:
        configuration = self._configuration.scope_discovery
        authorization = result.authorization
        if configuration is None or authorization is None:
            raise _invalid_response("scope_discovery_configuration")
        raw_authorization = authorization.get_secret_value()
        request: httpx.Request | None = None
        response: httpx.Response | None = None
        payload: JsonValue | object = _MISSING
        try:
            request = httpx.Request(
                "GET",
                f"{self._base_url}{configuration.path}",
                params=configuration.static_query_fields,
                headers={
                    "Accept": "application/json",
                    "Authorization": raw_authorization,
                },
                extensions={"timeout": httpx.Timeout(configuration.timeout_seconds).as_dict()},
            )
            if len(str(request.url).encode("utf-8")) > _MAX_SCOPE_DISCOVERY_REQUEST_BYTES:
                raise _invalid_response("scope_discovery_request_too_large")
            response = await client.send(
                request,
                auth=None,
                follow_redirects=False,
                stream=True,
            )
            if _origin(response.url) != self._origin or 300 <= response.status_code < 400:
                raise _invalid_response("scope_discovery_origin")
            if response.status_code < 200 or response.status_code >= 300:
                raise _invalid_response("scope_discovery_status")
            payload = await self._bounded_json(response, limit=configuration.max_response_bytes)
            policy = configuration.application_success
            if policy is not None:
                application_value = _pointer_value(payload, policy.pointer)
                if application_value is _MISSING or not any(
                    type(application_value) is type(allowed) and application_value == allowed
                    for allowed in policy.allowed_values
                ):
                    raise _invalid_response("scope_discovery_application")
            raw_scopes = _pointer_value(payload, configuration.scopes_pointer)
            if raw_scopes is _MISSING:
                raise _invalid_response("missing_scopes")
            if configuration.scopes_format == "space_delimited":
                return _space_delimited_scopes(raw_scopes)
            if not isinstance(raw_scopes, list) or any(
                not _is_safe_nonempty_text(scope) for scope in raw_scopes
            ):
                raise _invalid_response("invalid_scopes")
            return frozenset(cast(list[str], raw_scopes))
        finally:
            raw_authorization = ""
            if response is not None:
                await response.aclose()
            request = None
            response = None
            payload = _MISSING

    def _authentication_result(self, payload: JsonValue) -> AuthenticationResult:
        token = _pointer_value(payload, self._configuration.token_pointer)
        if token is _MISSING:
            raise _invalid_response("missing_token")
        if not _is_safe_nonempty_text(token):
            raise _invalid_response("invalid_token")

        token_type = "Bearer"
        if self._configuration.token_type_pointer is not None:
            raw_type = _pointer_value(payload, self._configuration.token_type_pointer)
            if raw_type is _MISSING:
                raise _invalid_response("missing_token_type")
            if not isinstance(raw_type, str) or _BEARER_TOKEN_TYPE.fullmatch(raw_type) is None:
                raise _invalid_response("invalid_token_type")

        now = self._clock()
        expires_at: float | None = None
        refresh_at: float | None = None
        if self._configuration.expires_in_pointer is not None:
            raw_expiry = _pointer_value(payload, self._configuration.expires_in_pointer)
            if raw_expiry is _MISSING:
                raise _invalid_response("missing_expiry")
            if (
                isinstance(raw_expiry, bool)
                or not isinstance(raw_expiry, (int, float))
                or not math.isfinite(raw_expiry)
                or raw_expiry <= 0
            ):
                raise _invalid_response("invalid_expiry")
            lifetime = float(raw_expiry)
            expires_at = now + lifetime
            refresh_at = expires_at - min(30.0, lifetime * 0.1)

        principal_id: str | None = None
        if self._configuration.principal_pointer is not None:
            raw_principal = _pointer_value(payload, self._configuration.principal_pointer)
            if raw_principal is _MISSING:
                raise _invalid_response("missing_principal")
            if not _is_safe_nonempty_text(raw_principal):
                raise _invalid_response("invalid_principal")
            principal_id = cast(str, raw_principal)

        source_scopes: frozenset[str] | None = None
        if self._configuration.scopes_pointer is not None:
            raw_scopes = _pointer_value(payload, self._configuration.scopes_pointer)
            if raw_scopes is _MISSING:
                raise _invalid_response("missing_scopes")
            if self._configuration.scopes_format == "json_array":
                if not isinstance(raw_scopes, list) or any(
                    not _is_safe_nonempty_text(scope) for scope in raw_scopes
                ):
                    raise _invalid_response("invalid_scopes")
                source_scopes = frozenset(cast(list[str], raw_scopes))
            else:
                source_scopes = _space_delimited_scopes(raw_scopes)

        tenant_context: Mapping[str, JsonValue] | None = None
        if self._configuration.tenant_pointer is not None:
            raw_tenant = _pointer_value(payload, self._configuration.tenant_pointer)
            if raw_tenant is _MISSING:
                raise _invalid_response("missing_tenant")
            if not isinstance(raw_tenant, dict):
                raise _invalid_response("invalid_tenant")
            tenant_context = raw_tenant

        return AuthenticationResult(
            token=SecretValue(cast(str, token)),
            token_type=token_type,
            principal_id=principal_id,
            source_scopes=source_scopes,
            tenant_context=tenant_context,
            expires_at=expires_at,
            refresh_at=refresh_at,
        )


def _fixed_origin(base_url: str) -> tuple[str, str, int]:
    invalid_url = False
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except (TypeError, ValueError):
        invalid_url = True
        parsed = None
        port = None
    if invalid_url or parsed is None:
        raise AuthConfigurationError("authentication base URL is invalid")
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in base_url)
    ):
        raise AuthConfigurationError("authentication base URL must be a fixed HTTP origin")
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.casefold(), effective_port


def _origin(url: httpx.URL) -> tuple[str, str, int]:
    effective_port = url.port or (443 if url.scheme == "https" else 80)
    return url.scheme, url.host.casefold(), effective_port


def _pointer_value(document: JsonValue, pointer: str) -> JsonValue | object:
    current: JsonValue = document
    for encoded_token in pointer.split("/")[1:]:
        token = encoded_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return _MISSING
            current = current[token]
            continue
        if isinstance(current, list):
            if not token.isdecimal() or (len(token) > 1 and token.startswith("0")):
                return _MISSING
            index = int(token)
            if index >= len(current):
                return _MISSING
            current = current[index]
            continue
        return _MISSING
    return current


def _secret_text(secret: SecretValue, *, field: str) -> str:
    if not isinstance(secret, SecretValue):
        raise TypeError(f"{field} must be a SecretValue")
    value = secret.get_secret_value()
    if not _is_safe_nonempty_text(value):
        raise AuthCredentialError("credential source returned invalid secret material")
    return value


def _is_safe_nonempty_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not any(character in value for character in "\r\n\x00")
    )


def _space_delimited_scopes(value: object) -> frozenset[str]:
    if not isinstance(value, str):
        raise _invalid_response("invalid_scopes")
    if len(value.encode("utf-8")) > _MAX_SPACE_DELIMITED_SCOPE_BYTES:
        raise _invalid_response("invalid_scopes")
    if any(character.isspace() and character not in " \t\r\n\v\f" for character in value):
        raise _invalid_response("invalid_scopes")
    tokens = [token for token in _ASCII_SCOPE_WHITESPACE.split(value) if token]
    if len(tokens) > _MAX_SPACE_DELIMITED_SCOPES or any(
        not _is_safe_nonempty_text(token)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in token)
        for token in tokens
    ):
        raise _invalid_response("invalid_scopes")
    return frozenset(sorted(set(tokens)))


def _no_retry_feedback_outcome(
    context: object,
    failed_attempt: object,
) -> bool | _FailureDescriptor:
    if not isinstance(context, PrincipalContext):
        return _FailureDescriptor(kind="invalid_context")
    if not isinstance(failed_attempt, AuthAttempt):
        return _FailureDescriptor(kind="invalid_attempt")
    if failed_attempt.state_key != context.auth_state_key:
        return _FailureDescriptor(kind="attempt_mismatch")
    return False


def _state_key_failure(auth_state_key: object) -> _FailureDescriptor | None:
    if not isinstance(auth_state_key, AuthStateKey):
        return _FailureDescriptor(kind="invalid_state_key")
    return None


def _require_result(result: AuthenticationResult) -> None:
    if not isinstance(result, AuthenticationResult):
        raise TypeError("authentication invalidation requires an AuthenticationResult")


def _result_is_fresh(result: AuthenticationResult, now: float) -> bool:
    return result.refresh_at is None or now < result.refresh_at


async def _await_shared_attempt(
    task: asyncio.Task[AuthAttempt],
) -> AuthAttempt | _PublicFailure:
    """Await shared work without adding a strategy-bearing frame to its error."""

    try:
        outcome = await asyncio.shield(task)
    except asyncio.CancelledError:
        failure: _PublicFailure = _CANCELLED
    except (AuthError, AuthTimeoutError, AuthResponseTooLargeError) as error:
        failure = error
    except Exception:
        failure = _FailureDescriptor(kind="request")
    else:
        del task
        return outcome
    del task
    return failure


def _raise_failure(failure: _FailureDescriptor) -> Never:
    """Raise one public, secret-free error without receiving execution objects."""

    if failure.kind == "configuration":
        raise AuthConfigurationError("authentication strategy is closed")
    if failure.kind == "invalid_credentials":
        raise TypeError("authentication requires a CredentialPair")
    if failure.kind == "invalid_context":
        raise TypeError("authentication requires a PrincipalContext")
    if failure.kind == "invalid_state_key":
        raise TypeError("authentication state operation requires an AuthStateKey")
    if failure.kind == "invalid_result":
        raise TypeError("authentication invalidation requires an AuthenticationResult")
    if failure.kind == "invalid_attempt":
        raise TypeError("401 feedback requires an AuthAttempt")
    if failure.kind == "attempt_mismatch":
        raise ValueError("authentication attempt does not belong to this PrincipalContext")
    if failure.kind == "unauthorized":
        raise AuthReauthenticationRequiredError("source session requires reauthentication")
    if failure.kind == "secret_missing":
        raise AuthCredentialError("provider authentication credential is unavailable")
    if failure.kind == "login_rejected":
        raise AuthLoginRejectedError(
            "source login was rejected",
            details={"upstream_status": failure.upstream_status},
        )
    if failure.kind == "upstream":
        raise AuthUpstreamError(
            "source login returned an upstream failure",
            details={"upstream_status": failure.upstream_status},
        )
    if failure.kind == "response_invalid":
        raise AuthInvalidResponseError(
            "source login returned an invalid response",
            details={"reason": failure.reason},
        )
    if failure.kind == "timeout":
        LOGGER.warning("source login timed out")
        raise AuthTimeoutError(
            "source login timed out",
            details={"phase": "login"},
        )
    if failure.kind == "response_too_large":
        LOGGER.warning("source login response exceeded configured size limit")
        raise AuthResponseTooLargeError(
            "source login response exceeded configured size limit",
            details={"limit_bytes": failure.limit_bytes, "phase": "login"},
        )
    LOGGER.warning("source login request failed")
    raise AuthRequestError("source login request failed")


def _raise_public_failure(failure: _PublicFailure) -> Never:
    if isinstance(failure, _CancelledDescriptor):
        raise asyncio.CancelledError
    if isinstance(failure, _FailureDescriptor):
        _raise_failure(failure)
    raise failure


def _response_too_large(limit: int) -> AuthResponseTooLargeError:
    LOGGER.warning("source login response exceeded configured size limit")
    return AuthResponseTooLargeError(
        "source login response exceeded configured size limit",
        details={"limit_bytes": limit, "phase": "login"},
    )


def _invalid_response(reason: str) -> AuthInvalidResponseError:
    return AuthInvalidResponseError(
        "source login returned an invalid response",
        details={"reason": reason},
    )


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constant")


__all__ = [
    "AsyncClientFactory",
    "AuthAttempt",
    "AuthenticationResult",
    "BearerSecretAuthStrategy",
    "HttpAuthStrategy",
    "NoAuthStrategy",
    "PasswordBearerAuthStrategy",
]
