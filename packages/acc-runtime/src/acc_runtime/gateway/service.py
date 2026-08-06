"""Transactional login and lifecycle service for isolated Gateway sessions."""

from __future__ import annotations

import asyncio
import math
import secrets
import time
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass
from typing import Never

from pydantic import SecretStr

from acc_core.models import PasswordBearerAuthConfig
from acc_runtime.auth import AuthenticationResult, CredentialPair, PasswordBearerAuthStrategy
from acc_runtime.context import AuthStateKey, PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError
from acc_runtime.gateway.models import GatewaySessionRecord, SessionCreateResponse
from acc_runtime.gateway.sessions import (
    GatewaySessionExpiredError,
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
            cleanup_failed, cleanup_cancelled = await self._drain_removed_auth_states()
            if cleanup_cancelled:
                return _CANCELLED
            if cleanup_failed:
                async with self._lifecycle_lock:
                    self._closed = True
                _, close_cancelled = await self._close_resources()
                if close_cancelled:
                    return _CANCELLED
                return _invalid_failure("expired_state_cleanup_failed")
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
                creation = await self._store.create(
                    session_id=session_id,
                    principal_context=context,
                    source_expires_at=result.expires_at,
                    source_refresh_at=result.refresh_at,
                )
                gateway_token, record = creation
                published = True
                cleanup_failed, cleanup_cancelled = await self._invalidate_records(
                    creation.removed_records
                )
                cancelled = cancelled or cleanup_cancelled
                if cleanup_failed:
                    async with self._lifecycle_lock:
                        self._closed = True
                    _, close_cancelled = await self._close_resources()
                    cancelled = cancelled or close_cancelled
                    failure = _invalid_failure("expired_state_cleanup_failed")
                if failure is None and not cancelled:
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
            cleanup_failed, cleanup_cancelled = await self._rollback(session_id, state_key)
            cancelled = cancelled or cleanup_cancelled
            if cleanup_failed:
                failure = _invalid_failure("session_cleanup_failed")
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
    ) -> tuple[bool, bool]:
        """Finish cleanup in its own task so caller cancellation cannot leave ghost state."""

        _, revoke_failure, revoke_cancelled = await _complete_value_action(
            lambda: self._store.revoke_session(session_id)
        )
        invalidate_failed = False
        invalidate_cancelled = False
        if state_key is not None:
            invalidate_failed, invalidate_cancelled = await _complete_action(
                lambda: self._auth_strategy.invalidate(state_key)
            )
        cleanup_failed = revoke_failure is not None or invalidate_failed
        cleanup_cancelled = revoke_cancelled or invalidate_cancelled
        if cleanup_failed:
            async with self._lifecycle_lock:
                self._closed = True
            _, close_cancelled = await self._close_resources()
            cleanup_cancelled = cleanup_cancelled or close_cancelled
        return cleanup_failed, cleanup_cancelled

    async def delete_current(self, token: str | SecretValue) -> None:
        """Revoke one current session and erase only its authentication state."""

        service = self
        failure = await service._delete_outcome(token)
        if failure is None:
            return
        del token
        del service
        del self
        _raise_failure(failure)

    async def _delete_outcome(
        self, token: str | SecretValue
    ) -> _ServiceFailure | _Cancelled | None:
        record, revoke_failure, cancelled = await _complete_value_action(
            lambda: self._store.revoke_token(token)
        )
        token = ""
        if revoke_failure is not None:
            async with self._lifecycle_lock:
                self._closed = True
            _, close_cancelled = await self._close_resources()
            if cancelled or close_cancelled:
                return _CANCELLED
            return _invalid_failure("session_delete_failed")
        if record is not None:
            key = record.principal_context.auth_state_key
            del record
            invalidate_failed, invalidate_cancelled = await _complete_action(
                lambda: self._auth_strategy.invalidate(key)
            )
            cancelled = cancelled or invalidate_cancelled
        else:
            invalidate_failed = False
        drain_failed, drain_cancelled = await self._drain_removed_auth_states()
        cancelled = cancelled or drain_cancelled
        if invalidate_failed or drain_failed:
            async with self._lifecycle_lock:
                self._closed = True
            _, close_cancelled = await self._close_resources()
            if cancelled or close_cancelled:
                return _CANCELLED
            return _invalid_failure("session_delete_failed")
        return _CANCELLED if cancelled else None

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
        record, mark_failure, cancelled = await _complete_value_action(
            lambda: self._store.mark_reauth_required(session_id)
        )
        drain_failed, drain_cancelled = await self._drain_removed_auth_states()
        cancelled = cancelled or drain_cancelled
        if drain_failed:
            async with self._lifecycle_lock:
                self._closed = True
            _, close_cancelled = await self._close_resources()
            if cancelled or close_cancelled:
                return _CANCELLED
            return _invalid_failure("session_reauth_failed")
        expected_session_failure = mark_failure in {
            GatewaySessionExpiredError,
            GatewaySessionInvalidError,
        }
        if expected_session_failure:
            if cancelled:
                return _CANCELLED
            local_error = (
                GatewaySessionExpiredError
                if mark_failure is GatewaySessionExpiredError
                else GatewaySessionInvalidError
            )
            return _ServiceFailure(local_error, {})
        if mark_failure is not None or record is None:
            async with self._lifecycle_lock:
                self._closed = True
            _, close_cancelled = await self._close_resources()
            if cancelled or close_cancelled:
                return _CANCELLED
            return _invalid_failure("session_reauth_failed")
        key = record.principal_context.auth_state_key
        del record
        invalidate_failed, invalidate_cancelled = await _complete_action(
            lambda: self._auth_strategy.invalidate(key)
        )
        if invalidate_failed:
            async with self._lifecycle_lock:
                self._closed = True
            _, close_cancelled = await self._close_resources()
            if cancelled or invalidate_cancelled or close_cancelled:
                return _CANCELLED
            return _invalid_failure("session_reauth_failed")
        return _CANCELLED if cancelled or invalidate_cancelled else None

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
        failed, cancelled = await self._close_resources()
        if cancelled:
            return _CANCELLED
        if failed:
            return _invalid_failure("service_close_failed")
        return None

    async def _close_resources(self) -> tuple[bool, bool]:
        store_failed = False
        store_cancelled = False
        removed_records: tuple[GatewaySessionRecord, ...] | None = ()
        strategy_failed = False
        strategy_cancelled = False
        try:
            removed_records, store_failure, store_cancelled = await _complete_value_action(
                self._store.close
            )
            store_failed = store_failure is not None or removed_records is None
            if store_failed:
                removed_records, retry_failure, retry_cancelled = await _complete_value_action(
                    self._store.close
                )
                store_failed = retry_failure is not None or removed_records is None
                store_cancelled = store_cancelled or retry_cancelled
        finally:
            drain_failed, drain_cancelled = await self._invalidate_records(removed_records or ())
            strategy_failed, strategy_cancelled = await _complete_action(self._auth_strategy.aclose)
            if strategy_failed:
                strategy_failed, retry_cancelled = await _complete_action(
                    self._auth_strategy.aclose
                )
                strategy_cancelled = strategy_cancelled or retry_cancelled
        return (
            store_failed or drain_failed or strategy_failed,
            store_cancelled or drain_cancelled or strategy_cancelled,
        )

    async def _is_closed(self) -> bool:
        async with self._lifecycle_lock:
            return self._closed

    async def _drain_removed_auth_states(self) -> tuple[bool, bool]:
        records, collect_failure, cancelled = await _complete_value_action(
            self._store.pop_expired_records
        )
        if collect_failure is not None or records is None:
            return True, cancelled
        failed, invalidate_cancelled = await self._invalidate_records(records)
        return failed, cancelled or invalidate_cancelled

    async def _invalidate_records(
        self, records: Collection[GatewaySessionRecord]
    ) -> tuple[bool, bool]:
        failed = False
        cancelled = False
        for record in records:
            key = record.principal_context.auth_state_key
            del record

            async def invalidate_removed(
                key: AuthStateKey = key,
            ) -> None:
                await self._auth_strategy.invalidate(key)

            state_failed, state_cancelled = await _complete_action(invalidate_removed)
            failed = failed or state_failed
            cancelled = cancelled or state_cancelled
        return failed, cancelled


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


async def _complete_action(action: Callable[[], Awaitable[None]]) -> tuple[bool, bool]:
    """Run one cleanup to completion despite caller cancellation.

    Ordinary failures are reduced to a boolean. Process-control exceptions are
    deliberately not caught and therefore keep their native semantics.
    """

    _, failure_type, caller_cancelled = await _complete_value_action(action)
    return failure_type is not None, caller_cancelled


async def _complete_value_action[T](
    action: Callable[[], Awaitable[T]],
) -> tuple[T | None, type[BaseException] | None, bool]:
    """Return a cleanup result without retaining an ordinary exception object."""

    task: asyncio.Future[T] = asyncio.ensure_future(action())
    caller_cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                caller_cancelled = True
            if task.done():
                break
        except Exception as error:
            return None, type(error), caller_cancelled
    try:
        result = task.result()
    except asyncio.CancelledError:
        return None, asyncio.CancelledError, caller_cancelled
    except Exception as error:
        return None, type(error), caller_cancelled
    return result, None, caller_cancelled


def _raise_failure(failure: _ServiceFailure | _Cancelled) -> Never:
    if isinstance(failure, _Cancelled):
        raise asyncio.CancelledError from None
    raise failure.error_type("Gateway session operation failed.", details=failure.details) from None


__all__ = ["GatewaySessionService"]
