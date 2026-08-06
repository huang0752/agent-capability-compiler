"""Transactional login and lifecycle service for isolated Gateway sessions."""

from __future__ import annotations

import asyncio
import math
import secrets
import time
from collections.abc import Callable, Collection
from contextlib import suppress
from dataclasses import dataclass
from typing import Never

from pydantic import SecretStr

from acc_core.models import PasswordBearerAuthConfig
from acc_runtime.auth import AuthenticationResult, CredentialPair, PasswordBearerAuthStrategy
from acc_runtime.context import AuthStateKey, PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError
from acc_runtime.gateway.models import SessionCreateResponse
from acc_runtime.gateway.sessions import (
    GatewaySessionInvalidError,
    GatewaySessionStore,
)


@dataclass(frozen=True, slots=True)
class _ServiceFailure:
    error_type: type[RuntimeError]
    details: dict[str, object]


@dataclass(frozen=True, slots=True)
class _Cancelled:
    pass


_CANCELLED = _Cancelled()
type _Outcome = SessionCreateResponse | _ServiceFailure | _Cancelled


class GatewaySessionService:
    """Exchange one-shot credentials for a short-lived, isolated Gateway session."""

    __slots__ = (
        "_anonymous_principal_generator",
        "_auth_config",
        "_auth_state_handle_generator",
        "_auth_strategy",
        "_clock",
        "_closed",
        "_deployment_scope_ceiling",
        "_lifecycle_lock",
        "_session_id_generator",
        "_store",
        "_target_system_id",
    )

    def __init__(
        self,
        *,
        auth_strategy: PasswordBearerAuthStrategy,
        auth_config: PasswordBearerAuthConfig,
        store: GatewaySessionStore,
        target_system_id: str,
        deployment_scope_ceiling: Collection[str],
        clock: Callable[[], float] = time.monotonic,
        session_id_generator: Callable[[], str] | None = None,
        auth_state_handle_generator: Callable[[], str] | None = None,
        anonymous_principal_generator: Callable[[], str] | None = None,
    ) -> None:
        if auth_config.credentials.kind != "gateway_session":
            raise ValueError("GatewaySessionService requires gateway_session credentials")
        if not isinstance(auth_strategy, PasswordBearerAuthStrategy):
            raise TypeError("auth_strategy must be PasswordBearerAuthStrategy")
        self._auth_strategy = auth_strategy
        self._auth_config = auth_config
        self._store = store
        self._target_system_id = target_system_id
        self._deployment_scope_ceiling = frozenset(deployment_scope_ceiling)
        self._clock = clock
        self._session_id_generator = session_id_generator or (
            lambda: f"gateway-{secrets.token_urlsafe(24)}"
        )
        self._auth_state_handle_generator = auth_state_handle_generator or (
            lambda: f"auth-{secrets.token_urlsafe(24)}"
        )
        self._anonymous_principal_generator = anonymous_principal_generator or (
            lambda: f"anonymous-{secrets.token_urlsafe(24)}"
        )
        self._lifecycle_lock = asyncio.Lock()
        self._closed = False

    async def create_session(
        self,
        *,
        identity: str | SecretValue,
        password: str | SecretValue,
    ) -> SessionCreateResponse:
        """Authenticate exactly once and atomically publish the resulting session."""

        service = self
        outcome = await service._create_outcome(identity, password)
        if isinstance(outcome, SessionCreateResponse):
            return outcome
        failure = outcome
        del outcome
        del identity
        del password
        del service
        del self
        _raise_failure(failure)

    async def _create_outcome(
        self,
        identity_input: str | SecretValue,
        password_input: str | SecretValue,
    ) -> _Outcome:
        credentials: CredentialPair | None = None
        result: AuthenticationResult | None = None
        context: PrincipalContext | None = None
        state_key: AuthStateKey | None = None
        gateway_token: SecretValue | None = None
        session_id: str | None = None
        auth_state_handle: str | None = None
        anonymous_principal: str | None = None
        bound = False
        published = False
        raw_gateway_token: str | None = None
        failure: _ServiceFailure | None = None
        cancelled = False
        try:
            if await self._is_closed():
                return _invalid_failure("service_closed")
            session_id = self._session_id_generator()
            auth_state_handle = self._auth_state_handle_generator()
            if not _is_safe_generated_value(session_id) or not _is_safe_generated_value(
                auth_state_handle
            ):
                return _invalid_failure("identifier_generation_failed")

            credentials = CredentialPair(
                identity=_as_secret(identity_input),
                password=_as_secret(password_input),
            )
            result = await self._auth_strategy.authenticate_once(credentials)
            credentials = None
            identity_input = ""
            password_input = ""

            if result.source_scopes is None:
                failure = _invalid_failure("source_scopes_unavailable")
            else:
                principal_id = (
                    result.principal_id if self._auth_config.principal_pointer is not None else None
                )
                if principal_id is None:
                    anonymous_principal = self._anonymous_principal_generator()
                    if not _is_safe_generated_value(anonymous_principal):
                        failure = _invalid_failure("anonymous_principal_generation_failed")
                    else:
                        principal_id = anonymous_principal
                if failure is None:
                    assert principal_id is not None
                    context = PrincipalContext(
                        principal_id=principal_id,
                        gateway_session_id=session_id,
                        target_system_id=self._target_system_id,
                        source_scopes=result.source_scopes,
                        deployment_scope_ceiling=self._deployment_scope_ceiling,
                        scope_mapping=self._auth_config.scope_mapping,
                        tenant_context=(
                            result.tenant_context
                            if self._auth_config.tenant_pointer is not None
                            else None
                        ),
                        auth_state_handle=auth_state_handle,
                    )
                    state_key = context.auth_state_key

            if failure is None and await self._is_closed():
                failure = _invalid_failure("service_closed")
            if failure is None:
                assert state_key is not None
                assert result is not None
                await self._auth_strategy.bind_state(state_key, result)
                bound = True
                assert context is not None
                gateway_token, record = await self._store.create(
                    session_id=session_id,
                    principal_context=context,
                    source_expires_at=result.expires_at,
                    source_refresh_at=result.refresh_at,
                )
                published = True
                raw_gateway_token = gateway_token.get_secret_value()
                remaining = record.expires_at - self._clock()
                if not math.isfinite(remaining) or remaining <= 0:
                    failure = _invalid_failure("session_lifetime_invalid")
                else:
                    response = SessionCreateResponse(
                        gateway_token=SecretStr(raw_gateway_token),
                        expires_in_seconds=max(1, math.floor(remaining)),
                    )
                    return response
        except asyncio.CancelledError:
            cancelled = True
        except RuntimeError as error:
            failure = _runtime_failure(error)
        except Exception:
            failure = _invalid_failure("session_creation_failed")
        finally:
            credentials = None
            identity_input = ""
            password_input = ""
            gateway_token = None
            raw_gateway_token = None
            result = None
            context = None
            anonymous_principal = None

        if session_id is not None and (published or bound or failure is not None or cancelled):
            await self._rollback(session_id, state_key)
        state_key = None
        session_id = None
        auth_state_handle = None
        if cancelled:
            return _CANCELLED
        return failure or _invalid_failure("session_creation_failed")

    async def _rollback(
        self,
        session_id: str,
        state_key: AuthStateKey | None,
    ) -> None:
        """Finish cleanup in its own task so caller cancellation cannot leave ghost state."""

        async def cleanup() -> None:
            with suppress(BaseException):
                await self._store.revoke(session_id)
            if state_key is not None:
                with suppress(BaseException):
                    await self._auth_strategy.invalidate(state_key)

        task = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await asyncio.gather(task, return_exceptions=True)

    async def delete_current(self, session_id: str) -> None:
        """Revoke one current session and erase only its authentication state."""

        service = self
        failure = await service._delete_outcome(session_id)
        if failure is None:
            return
        del session_id
        del service
        del self
        _raise_failure(failure)

    async def _delete_outcome(self, session_id: str) -> _ServiceFailure | _Cancelled | None:
        try:
            record = await self._store.resolve_session_id(session_id)
        except GatewaySessionInvalidError:
            return None
        except asyncio.CancelledError:
            return _CANCELLED
        except RuntimeError as error:
            failure = _runtime_failure(error)
            return failure
        except Exception:
            return _invalid_failure("session_delete_failed")
        key = record.principal_context.auth_state_key
        del record
        try:
            await self._store.revoke(session_id)
            await self._auth_strategy.invalidate(key)
        except asyncio.CancelledError:
            await self._rollback(session_id, key)
            return _CANCELLED
        except RuntimeError as error:
            await self._rollback(session_id, key)
            failure = _runtime_failure(error)
            return failure
        except Exception:
            await self._rollback(session_id, key)
            return _invalid_failure("session_delete_failed")
        return None

    async def mark_reauth_required(self, session_id: str) -> None:
        """Fail closed for one source 401 without disturbing any other user."""

        service = self
        failure = await service._reauth_outcome(session_id)
        if failure is None:
            return
        del session_id
        del service
        del self
        _raise_failure(failure)

    async def _reauth_outcome(self, session_id: str) -> _ServiceFailure | _Cancelled | None:
        key: AuthStateKey | None = None
        try:
            record = await self._store.resolve_session_id(session_id)
            key = record.principal_context.auth_state_key
            del record
            await self._store.mark_reauth_required(session_id)
            await self._auth_strategy.invalidate(key)
        except asyncio.CancelledError:
            if key is not None:
                await self._rollback(session_id, key)
            return _CANCELLED
        except RuntimeError as error:
            if key is not None:
                await self._rollback(session_id, key)
            failure = _runtime_failure(error)
            return failure
        except Exception:
            if key is not None:
                await self._rollback(session_id, key)
            return _invalid_failure("session_reauth_failed")
        return None

    async def aclose(self) -> None:
        """Idempotently erase all sessions and all source authentication state."""

        service = self
        failure = await service._close_outcome()
        if failure is None:
            return
        del service
        del self
        _raise_failure(failure)

    async def _close_outcome(self) -> _ServiceFailure | _Cancelled | None:
        async with self._lifecycle_lock:
            self._closed = True
        store_failure: _ServiceFailure | None = None
        try:
            await self._store.close()
        except asyncio.CancelledError:
            store_failure = _invalid_failure("service_close_cancelled")
        except RuntimeError as error:
            store_failure = _runtime_failure(error)
        except Exception:
            store_failure = _invalid_failure("service_close_failed")
        try:
            await self._auth_strategy.aclose()
        except asyncio.CancelledError:
            return _CANCELLED
        except RuntimeError as error:
            return store_failure or _runtime_failure(error)
        except Exception:
            return store_failure or _invalid_failure("service_close_failed")
        return store_failure

    async def _is_closed(self) -> bool:
        async with self._lifecycle_lock:
            return self._closed


def _as_secret(value: str | SecretValue) -> SecretValue:
    if isinstance(value, SecretValue):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError("credential must be a nonempty string")
    return SecretValue(value)


def _is_safe_generated_value(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not any(character.isspace() for character in value)
    )


def _runtime_failure(error: RuntimeError) -> _ServiceFailure:
    return _ServiceFailure(type(error), dict(error.details))


def _invalid_failure(reason: str) -> _ServiceFailure:
    return _ServiceFailure(GatewaySessionInvalidError, {"reason": reason})


def _raise_failure(failure: _ServiceFailure | _Cancelled) -> Never:
    if isinstance(failure, _Cancelled):
        raise asyncio.CancelledError from None
    raise failure.error_type("Gateway session operation failed.", details=failure.details) from None


__all__ = ["GatewaySessionService"]
