from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from acc_runtime.actions import (
    ActionBindingMismatchError,
    ActionExpiredError,
    ActionHandleInvalidError,
    ActionStateConflictError,
    ActionStore,
    InMemoryActionStore,
    PreparedActionCreation,
    PreparedActionStatus,
)


def test_action_values_reject_unpaired_surrogates_without_echoing_content() -> None:
    from acc_runtime.actions.models import canonical_json_bytes

    secret = "sentinel-\ud800"
    with pytest.raises(ValueError) as captured:
        canonical_json_bytes({"value": secret})

    assert secret not in str(captured.value)
    assert secret not in repr(captured.value)


PACK_DIGEST = "sha256:" + "a" * 64


def _store(*, now: list[float] | None = None) -> InMemoryActionStore:
    clock = (lambda: now[0]) if now is not None else (lambda: 100.0)
    return InMemoryActionStore(
        development_only=True,
        deployment_salt=b"action-store-test-salt-value",
        max_actions=10,
        clock=clock,
        handle_generator=lambda: "z" * 43,
    )


async def _create(store: InMemoryActionStore) -> PreparedActionCreation:
    return await store.create(
        capability_id="orders.approve",
        principal_id="user-a",
        session_id="session-a",
        pack_digest=PACK_DIGEST,
        input_value={"order_id": "order-1"},
        preview_value={"status": "pending", "version": 3},
        expires_in_seconds=300,
    )


def test_in_memory_store_is_explicitly_development_only_and_not_durable() -> None:
    with pytest.raises(ValueError, match="development/test"):
        InMemoryActionStore(
            development_only=False,
            deployment_salt=b"action-store-test-salt-value",
            max_actions=10,
        )

    store = _store()
    assert isinstance(store, ActionStore)
    assert store.is_durable is False
    assert store.deployment_safety == "development_test_only"


@pytest.mark.asyncio
async def test_create_stores_only_handle_digest_and_returns_redacted_secret() -> None:
    creation = await _create(_store())
    raw_handle = creation.handle.get_secret_value()

    assert raw_handle == "z" * 43
    assert raw_handle not in repr(creation)
    assert raw_handle not in repr(creation.state.record)
    assert creation.state.record.handle_digest != raw_handle
    assert len(creation.state.record.handle_digest) == 64
    assert str(creation.handle) == "[REDACTED]"
    assert creation.state.record.status is PreparedActionStatus.PREPARED
    assert creation.state.record.created_at == 100.0
    assert creation.state.record.expires_at == 400.0


@pytest.mark.asyncio
async def test_resolve_requires_exact_binding_and_returns_sealed_input() -> None:
    store = _store()
    creation = await _create(store)
    handle = creation.handle

    resolved = await store.resolve(
        handle,
        principal_id="user-a",
        session_id="session-a",
        pack_digest=PACK_DIGEST,
    )
    assert resolved.record == creation.state.record
    assert resolved.input_value == {"order_id": "order-1"}
    assert resolved.preview_value == {"status": "pending", "version": 3}

    mismatches = (
        {"principal_id": "user-b"},
        {"session_id": "session-b"},
        {"pack_digest": "sha256:" + "b" * 64},
    )
    base: dict[str, Any] = {
        "principal_id": "user-a",
        "session_id": "session-a",
        "pack_digest": PACK_DIGEST,
    }
    for mismatch in mismatches:
        with pytest.raises(ActionBindingMismatchError) as captured:
            await store.resolve(handle, **{**base, **mismatch})
        rendered = str(captured.value) + repr(captured.value.to_dict())
        assert "user-b" not in rendered
        assert "session-b" not in rendered


@pytest.mark.asyncio
async def test_invalid_handle_and_handle_repr_do_not_create_an_oracle() -> None:
    store = _store()
    await _create(store)

    with pytest.raises(ActionHandleInvalidError) as captured:
        await store.resolve(
            "not-a-valid-handle",
            principal_id="user-a",
            session_id="session-a",
            pack_digest=PACK_DIGEST,
        )
    assert "not-a-valid-handle" not in str(captured.value)
    assert "not-a-valid-handle" not in repr(captured.value.to_dict())


@pytest.mark.asyncio
async def test_expiry_is_terminal_and_uses_the_store_clock() -> None:
    now = [100.0]
    store = _store(now=now)
    creation = await _create(store)
    now[0] = 401.0

    with pytest.raises(ActionExpiredError):
        await store.resolve(
            creation.handle,
            principal_id="user-a",
            session_id="session-a",
            pack_digest=PACK_DIGEST,
        )
    record = await store.inspect_for_testing(creation.handle)
    assert record.status is PreparedActionStatus.EXPIRED


@pytest.mark.asyncio
async def test_transition_is_binding_checked_and_compare_and_swap_safe() -> None:
    store = _store()
    creation = await _create(store)
    kwargs: dict[str, Any] = {
        "principal_id": "user-a",
        "session_id": "session-a",
        "pack_digest": PACK_DIGEST,
    }
    approved = await store.transition(
        creation.handle,
        expected=PreparedActionStatus.PREPARED,
        target=PreparedActionStatus.APPROVED,
        **kwargs,
    )
    assert approved.record.status is PreparedActionStatus.APPROVED

    with pytest.raises(ActionStateConflictError):
        await store.transition(
            creation.handle,
            expected=PreparedActionStatus.PREPARED,
            target=PreparedActionStatus.APPROVED,
            **kwargs,
        )


@pytest.mark.asyncio
async def test_concurrent_compare_and_swap_has_one_winner() -> None:
    store = _store()
    creation = await _create(store)
    kwargs: dict[str, Any] = {
        "principal_id": "user-a",
        "session_id": "session-a",
        "pack_digest": PACK_DIGEST,
        "expected": PreparedActionStatus.PREPARED,
        "target": PreparedActionStatus.APPROVED,
    }
    outcomes = await asyncio.gather(
        store.transition(creation.handle, **kwargs),
        store.transition(creation.handle, **kwargs),
        return_exceptions=True,
    )
    assert sum(not isinstance(item, BaseException) for item in outcomes) == 1
    assert sum(isinstance(item, ActionStateConflictError) for item in outcomes) == 1


@pytest.mark.asyncio
async def test_payloads_are_defensive_copies_and_record_is_immutable() -> None:
    store = _store()
    creation = await _create(store)
    assert isinstance(creation.state.input_value, dict)
    assert isinstance(creation.state.preview_value, dict)
    creation.state.input_value["order_id"] = "tampered"
    creation.state.preview_value["version"] = 999

    resolved = await store.resolve(
        creation.handle,
        principal_id="user-a",
        session_id="session-a",
        pack_digest=PACK_DIGEST,
    )
    assert resolved.input_value == {"order_id": "order-1"}
    assert resolved.preview_value == {"status": "pending", "version": 3}
    with pytest.raises(FrozenInstanceError):
        resolved.record.status = PreparedActionStatus.APPROVED  # type: ignore[misc]


@pytest.mark.asyncio
async def test_store_rejects_duplicate_generated_handles_and_capacity_overflow() -> None:
    store = InMemoryActionStore(
        development_only=True,
        deployment_salt=b"action-store-test-salt-value",
        max_actions=1,
        clock=lambda: 100.0,
        handle_generator=lambda: "z" * 43,
    )
    await _create(store)
    with pytest.raises(ActionStateConflictError):
        await _create(store)


@pytest.mark.asyncio
async def test_close_is_idempotent_and_invalidates_all_handles() -> None:
    store = _store()
    creation = await _create(store)
    records = await store.close()
    assert len(records) == 1
    assert await store.close() == ()
    with pytest.raises(ActionHandleInvalidError):
        await store.resolve(
            creation.handle,
            principal_id="user-a",
            session_id="session-a",
            pack_digest=PACK_DIGEST,
        )
