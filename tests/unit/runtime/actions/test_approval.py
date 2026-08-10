from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from acc_runtime.actions import (
    ActionApprovalExpiredError,
    ActionApprovalInvalidError,
    ApprovalAuthority,
    ApprovalBinding,
    InMemoryActionStore,
    InMemoryApprovalAuthority,
)

PACK_DIGEST = "sha256:" + "a" * 64


def _store() -> InMemoryActionStore:
    return InMemoryActionStore(
        development_only=True,
        deployment_salt=b"action-store-test-salt-value",
        max_actions=10,
        clock=lambda: 100.0,
        handle_generator=lambda: "a" * 43,
    )


async def _binding() -> ApprovalBinding:
    creation = await _store().create(
        capability_id="orders.approve",
        principal_id="user-a",
        session_id="session-a",
        pack_digest=PACK_DIGEST,
        input_value={"order_id": "order-1"},
        preview_value={"status": "pending"},
        expires_in_seconds=300,
    )
    return ApprovalBinding.from_record(creation.state.record)


def test_approval_authority_is_a_runtime_checkable_protocol() -> None:
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: 100.0,
        handle_generator=lambda: "y" * 43,
    )
    assert isinstance(authority, ApprovalAuthority)


def test_in_memory_approval_authority_is_explicitly_test_only() -> None:
    with pytest.raises(ValueError, match="development/test"):
        InMemoryApprovalAuthority(development_only=False)


@pytest.mark.asyncio
async def test_issue_and_verify_bind_exact_action_without_exposing_handle() -> None:
    binding = await _binding()
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: 100.0,
        handle_generator=lambda: "y" * 43,
    )
    handle = await authority.issue_for_testing(binding, expires_in_seconds=60)
    raw = handle.get_secret_value()

    grant = await authority.verify(handle, binding)
    assert grant.binding == binding
    assert grant.approved_at == 100.0
    assert grant.expires_at == 160.0
    assert len(grant.approval_digest) == 64
    assert raw not in repr(grant)
    assert raw not in repr(handle)
    with pytest.raises(FrozenInstanceError):
        grant.expires_at = 999.0  # type: ignore[misc]


@pytest.mark.asyncio
async def test_approval_handle_is_one_time_and_replay_safe() -> None:
    binding = await _binding()
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: 100.0,
        handle_generator=lambda: "y" * 43,
    )
    handle = await authority.issue_for_testing(binding, expires_in_seconds=60)
    await authority.verify(handle, binding)
    with pytest.raises(ActionApprovalInvalidError):
        await authority.verify(handle, binding)


@pytest.mark.asyncio
async def test_approval_rejects_cross_action_binding_without_leaking_values() -> None:
    binding = await _binding()
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: 100.0,
        handle_generator=lambda: "y" * 43,
    )
    handle = await authority.issue_for_testing(binding, expires_in_seconds=60)
    wrong = ApprovalBinding(
        action_digest="c" * 64,
        capability_id=binding.capability_id,
        principal_digest=binding.principal_digest,
        session_digest=binding.session_digest,
        pack_digest=binding.pack_digest,
        input_digest=binding.input_digest,
        preview_digest=binding.preview_digest,
        action_expires_at=binding.action_expires_at,
    )
    with pytest.raises(ActionApprovalInvalidError) as captured:
        await authority.verify(handle, wrong)
    rendered = str(captured.value) + repr(captured.value.to_dict())
    assert "y" * 43 not in rendered
    assert "c" * 64 not in rendered


@pytest.mark.asyncio
async def test_expired_approval_is_distinct_but_still_redacted() -> None:
    now = [100.0]
    binding = await _binding()
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: now[0],
        handle_generator=lambda: "y" * 43,
    )
    handle = await authority.issue_for_testing(binding, expires_in_seconds=10)
    now[0] = 111.0
    with pytest.raises(ActionApprovalExpiredError) as captured:
        await authority.verify(handle, binding)
    assert "y" * 43 not in str(captured.value)


@pytest.mark.asyncio
async def test_approval_cannot_outlive_prepared_action() -> None:
    binding = await _binding()
    authority = InMemoryApprovalAuthority(
        development_only=True,
        clock=lambda: 100.0,
        handle_generator=lambda: "y" * 43,
    )
    with pytest.raises(ValueError, match="prepared Action"):
        await authority.issue_for_testing(binding, expires_in_seconds=301)
