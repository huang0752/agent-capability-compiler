from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest
from pydantic import JsonValue

from acc_runtime.auth import AuthUnauthorizedError
from acc_runtime.context import PrincipalContext
from acc_runtime.gateway.runtime import _ReauthCoordinatingRuntime


def _context(session_id: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=f"user-{session_id}",
        gateway_session_id=session_id,
        target_system_id="crm",
        source_scopes={"source.read"},
        deployment_scope_ceiling={"customer.read"},
        scope_mapping={"source.read": {"customer.read"}},
        tenant_context={"tenant_id": session_id},
        auth_state_handle=f"auth-{session_id}",
    )


class _Runtime:
    def __init__(self, failure: AuthUnauthorizedError | None = None) -> None:
        self.failure = failure

    def tools(self) -> list[dict[str, object]]:
        return [{"name": "customer.get"}]

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        del capability_id, arguments, principal_context
        if self.failure is not None:
            raise self.failure
        return {"ok": True}


class _Service:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.marked: list[str] = []

    async def mark_reauth_required(self, session_id: str) -> None:
        self.marked.append(session_id)
        if self.failure is not None:
            raise self.failure


@pytest.mark.asyncio
async def test_reauth_coordinator_marks_only_the_failing_gateway_session() -> None:
    failure = AuthUnauthorizedError("source rejected bearer")
    runtime = _Runtime(failure)
    service = _Service()
    coordinated = _ReauthCoordinatingRuntime(runtime, service=service)

    with pytest.raises(AuthUnauthorizedError) as raised:
        await coordinated.call_with_context("customer.get", {}, _context("session-a"))

    assert raised.value is failure
    assert service.marked == ["session-a"]

    runtime.failure = None
    assert await coordinated.call_with_context("customer.get", {}, _context("session-b")) == {
        "ok": True
    }
    assert service.marked == ["session-a"]


@pytest.mark.asyncio
async def test_reauth_coordinator_preserves_original_unauthorized_if_marking_fails() -> None:
    failure = AuthUnauthorizedError("source rejected bearer")
    coordinated = _ReauthCoordinatingRuntime(
        _Runtime(failure),
        service=_Service(RuntimeError("store failure")),
    )

    with pytest.raises(AuthUnauthorizedError) as raised:
        await coordinated.call_with_context("customer.get", {}, _context("session-a"))

    assert raised.value is failure
    assert raised.value.__cause__ is None


@pytest.mark.asyncio
async def test_reauth_coordinator_does_not_swallow_cancellation() -> None:
    coordinated = _ReauthCoordinatingRuntime(
        _Runtime(AuthUnauthorizedError("source rejected bearer")),
        service=_Service(asyncio.CancelledError()),
    )

    with pytest.raises(asyncio.CancelledError):
        await coordinated.call_with_context("customer.get", {}, _context("session-a"))
