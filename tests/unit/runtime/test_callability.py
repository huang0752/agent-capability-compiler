from __future__ import annotations

from typing import Any

import pytest

from acc_core.scope import CapabilityScopeRequirements
from acc_runtime.callability import (
    CallabilityAnalysisError,
    CallabilityStatus,
    analyze_scope_callability,
)
from acc_runtime.context import PrincipalContext


def _requirements(
    capability_id: str,
    *,
    always: set[str],
    conditional: set[str],
    alternatives: tuple[set[str], ...],
) -> CapabilityScopeRequirements:
    all_scopes = frozenset(always | conditional)
    return CapabilityScopeRequirements(
        capability_id=capability_id,
        policy_always_required=frozenset(),
        always_required=frozenset(always),
        conditionally_required=frozenset(conditional),
        all_referenced=all_scopes,
        completion_alternatives=tuple(frozenset(item) for item in alternatives),
    )


def _project(*, mapping: dict[str, list[str]] | None = None) -> dict[str, Any]:
    auth: dict[str, Any] = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/auth/login",
        "identity_field": "email",
        "password_field": "password",
        "token_pointer": "/access_token",
        "scopes_pointer": "/permissions",
        "scope_mapping": mapping or {},
    }
    return {
        "schema_version": "2",
        "project": {"id": "system", "version": "0.1.0"},
        "source_workspace": {"path": "../source", "mode": "read_only"},
        "runtime": {"transport": ["streamable_http"]},
        "provider": {"kind": "http", "base_url_ref": "SYSTEM_URL", "auth": auth},
        "quality": {"profile": "standard"},
    }


def _project_v2(*, mapping: dict[str, list[str]] | None = None) -> dict[str, Any]:
    return _project(mapping=mapping)


def _principal(
    *,
    source_scopes: set[str] | None,
    ceiling: set[str],
    mapping: dict[str, list[str]] | None = None,
) -> PrincipalContext:
    return PrincipalContext(
        principal_id="private-principal",
        gateway_session_id=None if source_scopes is None else "private-gateway-session",
        target_system_id="system",
        source_scopes=source_scopes,
        deployment_scope_ceiling=ceiling,
        scope_mapping=mapping,
        tenant_context={"private_tenant": "tenant-a"},
        auth_state_handle="private-auth-state",
    )


@pytest.mark.parametrize(
    ("ceiling", "expected"),
    [
        (set(), CallabilityStatus.DENIED),
        ({"records.base"}, CallabilityStatus.CONDITIONAL),
        ({"records.base", "records.extra"}, CallabilityStatus.CALLABLE),
    ],
)
def test_deployment_status_distinguishes_denied_conditional_and_callable(
    ceiling: set[str],
    expected: CallabilityStatus,
) -> None:
    requirement = _requirements(
        "records",
        always={"records.base"},
        conditional={"records.extra"},
        alternatives=({"records.base"},),
    )

    report = analyze_scope_callability(
        {"ir_version": "2", "capabilities": {}},
        deployment_scope_ceiling=ceiling,
        requirements_by_capability={"records": requirement},
    )

    capability = report.capabilities[0]
    assert capability.deployment.status is expected
    assert capability.user.status is CallabilityStatus.UNKNOWN
    assert capability.effective.status is CallabilityStatus.UNKNOWN
    assert capability.deployment.missing_always == frozenset({"records.base"} - ceiling)
    assert capability.deployment.missing_conditional == frozenset({"records.extra"} - ceiling)


def test_legacy_ir_version_is_rejected_before_scope_analysis() -> None:
    requirement = _requirements(
        "records",
        always={"records.read"},
        conditional=set(),
        alternatives=({"records.read"},),
    )

    with pytest.raises(CallabilityAnalysisError) as caught:
        analyze_scope_callability(
            {"ir_version": "1", "capabilities": {}},
            deployment_scope_ceiling={"records.read"},
            requirements_by_capability={"records": requirement},
        )

    assert caught.value.reason == "ir_version_invalid"


def test_user_and_effective_status_are_separate_from_deployment_ceiling() -> None:
    mapping = {
        "source:base": ["records.base"],
        "source:detail": ["records.detail"],
    }
    requirement = _requirements(
        "records",
        always={"records.base", "records.detail"},
        conditional=set(),
        alternatives=({"records.base", "records.detail"},),
    )
    principal = _principal(
        source_scopes={"source:base", "source:detail"},
        ceiling={"records.base"},
        mapping=mapping,
    )

    report = analyze_scope_callability(
        {
            "ir_version": "2",
            "project": _project_v2(mapping=mapping),
            "capabilities": {},
        },
        deployment_scope_ceiling={"records.base"},
        principal_context=principal,
        requirements_by_capability={"records": requirement},
    )

    capability = report.capabilities[0]
    assert capability.deployment.status is CallabilityStatus.DENIED
    assert capability.user.status is CallabilityStatus.CALLABLE
    assert capability.user.available_scopes == frozenset({"records.base", "records.detail"})
    assert capability.effective.status is CallabilityStatus.DENIED
    assert capability.effective.available_scopes == frozenset({"records.base"})
    assert "private-principal" not in repr(report)
    assert "private-gateway-session" not in repr(report)
    assert "tenant-a" not in repr(report)


def test_v2_project_dispatch_preserves_principal_scope_mapping() -> None:
    mapping = {"source:records": ["records.read"]}
    requirement = _requirements(
        "records",
        always={"records.read"},
        conditional=set(),
        alternatives=({"records.read"},),
    )
    principal = _principal(
        source_scopes={"source:records"},
        ceiling={"records.read"},
        mapping=mapping,
    )

    report = analyze_scope_callability(
        {
            "ir_version": "2",
            "project": _project_v2(mapping=mapping),
            "capabilities": {},
        },
        deployment_scope_ceiling={"records.read"},
        principal_context=principal,
        requirements_by_capability={"records": requirement},
    )

    assert report.capabilities[0].user.status is CallabilityStatus.CALLABLE
    assert report.capabilities[0].effective.status is CallabilityStatus.CALLABLE


def test_stdio_principal_with_unavailable_source_scopes_keeps_user_unknown() -> None:
    requirement = _requirements(
        "records",
        always={"records.read"},
        conditional=set(),
        alternatives=({"records.read"},),
    )
    principal = _principal(source_scopes=None, ceiling={"records.read"})

    report = analyze_scope_callability(
        {"ir_version": "2", "project": _project_v2(), "capabilities": {}},
        deployment_scope_ceiling={"records.read"},
        principal_context=principal,
        requirements_by_capability={"records": requirement},
    )

    capability = report.capabilities[0]
    assert capability.user.status is CallabilityStatus.UNKNOWN
    assert capability.user.available_scopes is None
    assert capability.effective.status is CallabilityStatus.CALLABLE


def test_current_ir_without_compiled_requirements_fails_closed() -> None:
    ir = {
        "ir_version": "2",
        "capabilities": {"records": {}},
    }

    with pytest.raises(CallabilityAnalysisError) as caught:
        analyze_scope_callability(ir, deployment_scope_ceiling=set())

    assert caught.value.reason == "scope_requirements_invalid"


def test_embedded_v2_requirements_do_not_require_v1_definition_reconstruction() -> None:
    ir = {
        "ir_version": "2",
        "capabilities": {
            "records": {
                "scope_requirements": {
                    "policy_always_required": ["records.policy"],
                    "always_required": ["records.policy"],
                    "conditionally_required": ["records.extra"],
                    "all_referenced": ["records.extra", "records.policy"],
                    "completion_alternatives": [["records.policy"]],
                }
            }
        },
    }

    report = analyze_scope_callability(
        ir,
        deployment_scope_ceiling={"records.policy"},
    )

    assert report.ir_version == "2"
    assert report.capabilities[0].deployment.status is CallabilityStatus.CONDITIONAL


def test_malformed_embedded_requirements_fail_closed_without_identity_details() -> None:
    ir = {
        "ir_version": "2",
        "capabilities": {"records": {"scope_requirements": {"always_required": "secret"}}},
    }

    with pytest.raises(CallabilityAnalysisError) as caught:
        analyze_scope_callability(ir, deployment_scope_ceiling=set())

    assert caught.value.reason == "scope_requirements_invalid"
    assert "secret" not in str(caught.value)
