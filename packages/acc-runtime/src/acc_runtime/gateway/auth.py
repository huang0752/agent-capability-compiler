"""Bearer verification and trusted Principal recovery for the HTTP Gateway."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Never, Protocol

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from acc_runtime.context import PrincipalContext
from acc_runtime.gateway.models import GatewaySessionRecord
from acc_runtime.gateway.sessions import (
    GatewayReauthRequiredError,
    GatewaySessionExpiredError,
    GatewaySessionInvalidError,
)


class GatewaySessionLookup(Protocol):
    """The narrow, read-only Store surface used at authentication boundaries."""

    async def resolve_token(self, token: str) -> GatewaySessionRecord: ...

    async def resolve_session_id(self, session_id: str) -> GatewaySessionRecord: ...


@dataclass(frozen=True, slots=True)
class _Cancelled:
    pass


@dataclass(frozen=True, slots=True)
class _ResolveFailure:
    kind: str


_CANCELLED = _Cancelled()
type _VerifyOutcome = AccessToken | _Cancelled | None
type _ResolveOutcome = PrincipalContext | _ResolveFailure | _Cancelled


class GatewayTokenVerifier(TokenVerifier):
    """Verify an opaque Gateway bearer against current Store state on every request."""

    __slots__ = ("_monotonic_clock", "_project_id", "_store", "_wall_clock")

    def __init__(
        self,
        *,
        store: GatewaySessionLookup,
        project_id: str,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(project_id, str) or not project_id.strip():
            raise ValueError("project_id must be a nonempty string")
        self._store = store
        self._project_id = project_id
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return SDK auth data only for an active, freshly resolved session."""

        verifier = self
        outcome = await verifier._verify_outcome(token)
        token = ""
        del verifier
        del self
        if isinstance(outcome, _Cancelled):
            _raise_cancelled()
        return outcome

    async def _verify_outcome(self, token: str) -> _VerifyOutcome:
        try:
            record = await self._store.resolve_token(token)
            monotonic_now = float(self._monotonic_clock())
            wall_now = float(self._wall_clock())
            remaining = record.expires_at - monotonic_now
            context = record.principal_context
            if (
                not math.isfinite(monotonic_now)
                or not math.isfinite(wall_now)
                or not math.isfinite(remaining)
                or remaining <= 0
                or context.gateway_session_id != record.session_id
                or context.target_system_id != self._project_id
            ):
                return None
            return AccessToken(
                token=token,
                client_id=self._project_id,
                scopes=sorted(context.effective_scopes),
                expires_at=int(wall_now + remaining),
                subject=record.session_id,
                claims={"iss": "acc-gateway"},
            )
        except asyncio.CancelledError:
            return _CANCELLED
        except (
            GatewaySessionInvalidError,
            GatewaySessionExpiredError,
            GatewayReauthRequiredError,
        ):
            return None
        except Exception:
            return None


class GatewayPrincipalResolver:
    """Recover a Principal from Store state, never from MCP arguments or token claims."""

    __slots__ = ("_project_id", "_store")

    def __init__(self, *, store: GatewaySessionLookup, project_id: str) -> None:
        if not isinstance(project_id, str) or not project_id.strip():
            raise ValueError("project_id must be a nonempty string")
        self._store = store
        self._project_id = project_id

    async def resolve(self, access_token: AccessToken | None = None) -> PrincipalContext:
        """Resolve current auth context and recheck the subject's live Store record."""

        resolver = self
        token = access_token if access_token is not None else get_access_token()
        outcome = await resolver._resolve_outcome(token)
        token = None
        access_token = None
        del resolver
        del self
        if isinstance(outcome, _Cancelled):
            _raise_cancelled()
        if isinstance(outcome, _ResolveFailure):
            _raise_resolve_failure(outcome)
        return outcome

    async def _resolve_outcome(self, token: AccessToken | None) -> _ResolveOutcome:
        if not _valid_access_identity(token, self._project_id):
            return _ResolveFailure("invalid")
        assert token is not None
        assert token.subject is not None
        try:
            record = await self._store.resolve_session_id(token.subject)
        except asyncio.CancelledError:
            return _CANCELLED
        except GatewaySessionExpiredError:
            return _ResolveFailure("expired")
        except GatewayReauthRequiredError:
            return _ResolveFailure("reauth")
        except GatewaySessionInvalidError:
            return _ResolveFailure("invalid")
        except Exception:
            return _ResolveFailure("invalid")
        context = record.principal_context
        if (
            record.session_id != token.subject
            or context.gateway_session_id != token.subject
            or context.target_system_id != self._project_id
        ):
            return _ResolveFailure("invalid")
        return context


def _valid_access_identity(token: AccessToken | None, project_id: str) -> bool:
    return bool(
        isinstance(token, AccessToken)
        and token.client_id == project_id
        and isinstance(token.subject, str)
        and token.subject
        and token.claims == {"iss": "acc-gateway"}
    )


def _raise_cancelled() -> Never:
    raise asyncio.CancelledError() from None


def _raise_resolve_failure(failure: _ResolveFailure) -> Never:
    if failure.kind == "expired":
        raise GatewaySessionExpiredError("Gateway session has expired.") from None
    if failure.kind == "reauth":
        raise GatewayReauthRequiredError("Gateway session requires reauthentication.") from None
    raise GatewaySessionInvalidError("Gateway session is invalid.") from None


__all__ = [
    "GatewayPrincipalResolver",
    "GatewaySessionLookup",
    "GatewayTokenVerifier",
]
