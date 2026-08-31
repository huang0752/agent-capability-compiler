from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest

from acc_runtime.actions import (
    ActionApprovalExpiredError,
    ActionApprovalInvalidError,
    ApprovalAuthority,
    ApprovalAuthorityIntegrityError,
    ApprovalBinding,
    ApprovalDecisionStatus,
    SQLiteApprovalAuthority,
)
from acc_runtime.credentials import SecretValue

PACK_DIGEST = "sha256:" + "a" * 64
SECRET = SecretValue("authority-secret-that-is-at-least-32-bytes")
SALT = b"approval-deployment-salt"


def _binding(**changes: object) -> ApprovalBinding:
    values: dict[str, object] = {
        "action_digest": "1" * 64,
        "capability_id": "orders.approve",
        "principal_digest": "2" * 64,
        "session_digest": "3" * 64,
        "pack_digest": PACK_DIGEST,
        "input_digest": "4" * 64,
        "preview_digest": "5" * 64,
        "action_expires_at": 1000.0,
    }
    values.update(changes)
    return ApprovalBinding(**values)  # type: ignore[arg-type]


def _authority(
    path: Path,
    now: list[float],
    *,
    handle: str = "h" * 43,
    secret: SecretValue = SECRET,
) -> SQLiteApprovalAuthority:
    return SQLiteApprovalAuthority(
        path,
        authority_secret=secret,
        deployment_salt=SALT,
        clock=lambda: now[0],
        handle_generator=lambda: handle,
    )


def test_authority_requires_explicit_strong_distinct_material(tmp_path: Path) -> None:
    path = tmp_path / "approval.db"
    with pytest.raises(ValueError, match="at least 32"):
        SQLiteApprovalAuthority(path, authority_secret=SecretValue("short"), deployment_salt=SALT)
    with pytest.raises(TypeError, match="SecretValue"):
        SQLiteApprovalAuthority(
            path,
            authority_secret=cast(Any, b"not-a-secret-value-at-all-00000000"),
            deployment_salt=SALT,
        )
    with pytest.raises(ValueError, match="at least 16"):
        SQLiteApprovalAuthority(path, authority_secret=SECRET, deployment_salt=b"short")


@pytest.mark.asyncio
async def test_durable_issue_restart_verify_and_audit(tmp_path: Path) -> None:
    now = [100.0]
    path = tmp_path / "approval.db"
    first = _authority(path, now)
    assert isinstance(first, ApprovalAuthority)
    handle = await first.issue(
        _binding(),
        decision_id="change-2026-0001",
        approver_id="operator:alice",
        expires_in_seconds=60,
    )
    assert "h" * 43 not in repr(handle)
    await first.close()

    second = _authority(path, now, handle="unused" * 7)
    grant = await second.verify(handle, _binding())
    assert grant.decision_id == "change-2026-0001"
    assert grant.approver_id == "operator:alice"
    decision = await second.decision("change-2026-0001")
    assert decision.status is ApprovalDecisionStatus.CONSUMED
    assert decision.consumed_at == 100.0
    assert "1" * 64 not in repr(decision)
    with sqlite3.connect(path) as connection:
        stored = connection.execute("SELECT approval_digest FROM approvals").fetchone()[0]
    assert stored != handle.get_secret_value()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action_digest", "9" * 64),
        ("capability_id", "orders.reject"),
        ("principal_digest", "9" * 64),
        ("session_digest", None),
        ("pack_digest", "sha256:" + "9" * 64),
        ("input_digest", "9" * 64),
        ("preview_digest", "9" * 64),
        ("action_expires_at", 999.0),
    ],
)
async def test_every_binding_field_is_exact_and_mismatch_does_not_consume(
    tmp_path: Path, field: str, value: object
) -> None:
    now = [100.0]
    authority = _authority(tmp_path / "approval.db", now)
    handle = await authority.issue(
        _binding(), decision_id="decision-1", approver_id="alice", expires_in_seconds=30
    )
    with pytest.raises(ActionApprovalInvalidError):
        await authority.verify(handle, _binding(**{field: value}))
    assert (await authority.decision("decision-1")).status is ApprovalDecisionStatus.APPROVED
    await authority.verify(handle, _binding())


@pytest.mark.asyncio
async def test_concurrent_verify_is_one_time_across_instances(tmp_path: Path) -> None:
    now = [100.0]
    path = tmp_path / "approval.db"
    first = _authority(path, now)
    handle = await first.issue(
        _binding(), decision_id="decision-1", approver_id="alice", expires_in_seconds=30
    )
    second = _authority(path, now, handle="j" * 43)
    results = await asyncio.gather(
        first.verify(handle, _binding()),
        second.verify(handle, _binding()),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert sum(isinstance(result, ActionApprovalInvalidError) for result in results) == 1


@pytest.mark.asyncio
async def test_revoke_is_durable_and_auditable(tmp_path: Path) -> None:
    now = [100.0]
    path = tmp_path / "approval.db"
    authority = _authority(path, now)
    handle = await authority.issue(
        _binding(), decision_id="decision-1", approver_id="alice", expires_in_seconds=30
    )
    now[0] = 101.0
    revoked = await authority.revoke(handle, revoked_by="operator:bob")
    assert revoked.status is ApprovalDecisionStatus.REVOKED
    assert revoked.revoked_by == "operator:bob"
    await authority.close()
    reopened = _authority(path, now, handle="j" * 43)
    with pytest.raises(ActionApprovalInvalidError):
        await reopened.verify(handle, _binding())
    assert (await reopened.decision("decision-1")).revoked_at == 101.0


@pytest.mark.asyncio
async def test_expiry_is_short_bounded_and_persisted(tmp_path: Path) -> None:
    now = [100.0]
    authority = _authority(tmp_path / "approval.db", now)
    with pytest.raises(ValueError, match="between 1 and 900"):
        await authority.issue(
            _binding(), decision_id="too-long", approver_id="alice", expires_in_seconds=901
        )
    handle = await authority.issue(
        _binding(), decision_id="decision-1", approver_id="alice", expires_in_seconds=10
    )
    now[0] = 110.0
    with pytest.raises(ActionApprovalExpiredError):
        await authority.verify(handle, _binding())
    assert (await authority.decision("decision-1")).status is ApprovalDecisionStatus.EXPIRED


@pytest.mark.asyncio
async def test_duplicate_decision_id_and_handle_fail_closed(tmp_path: Path) -> None:
    now = [100.0]
    authority = _authority(tmp_path / "approval.db", now)
    await authority.issue(
        _binding(), decision_id="decision-1", approver_id="alice", expires_in_seconds=10
    )
    with pytest.raises(ActionApprovalInvalidError, match="not unique"):
        await authority.issue(
            _binding(action_digest="9" * 64),
            decision_id="decision-1",
            approver_id="alice",
            expires_in_seconds=10,
        )


@pytest.mark.asyncio
async def test_wrong_secret_and_row_tampering_fail_before_use(tmp_path: Path) -> None:
    now = [100.0]
    path = tmp_path / "approval.db"
    authority = _authority(path, now)
    await authority.issue(
        _binding(), decision_id="decision-1", approver_id="alice", expires_in_seconds=10
    )
    await authority.close()
    with pytest.raises(ApprovalAuthorityIntegrityError, match="authentication"):
        _authority(
            path,
            now,
            secret=SecretValue("different-authority-secret-at-least-32-bytes"),
        )
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE approvals SET approver_id='mallory'")
    reopened = _authority(path, now)
    with pytest.raises(ApprovalAuthorityIntegrityError, match="authentication"):
        await reopened.decision("decision-1")
