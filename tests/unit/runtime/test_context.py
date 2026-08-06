from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError

import pytest

from acc_runtime.context import (
    PrincipalContext,
    map_effective_scopes,
    resolve_context_binding,
)


def _context(
    *,
    tenant_context: dict[str, object] | None = None,
    auth_state_handle: str = "auth-state:user-a",
) -> PrincipalContext:
    ceiling = frozenset({"customer.read", "customer.write"})
    return PrincipalContext(
        principal_id="user-a",
        gateway_session_id="gateway-session-a",
        target_system_id="crm",
        source_scopes=frozenset({"customer:read", "unmapped:admin"}),
        deployment_scope_ceiling=ceiling,
        tenant_context=tenant_context,
        auth_state_handle=auth_state_handle,
        scope_mapping={"customer:read": {"customer.read", "customer.delete"}},
    )


def test_map_effective_scopes_maps_then_intersects_with_deployment_ceiling() -> None:
    effective = map_effective_scopes(
        {"customer:read", "customer:write"},
        {"customer.read", "customer.audit"},
        {
            "customer:read": {"customer.read", "customer.audit"},
            "customer:write": {"customer.write"},
        },
    )

    assert effective == frozenset({"customer.read", "customer.audit"})


def test_map_effective_scopes_drops_unmapped_source_scopes() -> None:
    effective = map_effective_scopes(
        {"customer:read", "system:admin"},
        {"customer.read", "system.admin"},
        {"customer:read": {"customer.read"}},
    )

    assert effective == frozenset({"customer.read"})


def test_map_effective_scopes_uses_ceiling_when_source_scopes_are_unavailable() -> None:
    effective = map_effective_scopes(
        None,
        {"customer.read", "customer.write"},
        {"customer:read": {"customer.read"}},
    )

    assert effective == frozenset({"customer.read", "customer.write"})


def test_map_effective_scopes_returns_empty_when_source_scopes_are_known_empty() -> None:
    effective = map_effective_scopes(
        set(),
        {"customer.read", "customer.write"},
        {"customer:read": {"customer.read"}},
    )

    assert effective == frozenset()


def test_principal_context_is_frozen_and_normalizes_scope_sets() -> None:
    context = PrincipalContext(
        principal_id="user-a",
        gateway_session_id=None,
        target_system_id="crm",
        source_scopes=["customer:read"],
        deployment_scope_ceiling=["customer.read"],
        tenant_context=None,
        auth_state_handle="auth-state:user-a",
        scope_mapping={"customer:read": ["customer.read"]},
    )

    assert context.source_scopes == frozenset({"customer:read"})
    assert context.deployment_scope_ceiling == frozenset({"customer.read"})
    assert context.effective_scopes == frozenset({"customer.read"})
    with pytest.raises(FrozenInstanceError):
        context.principal_id = "user-b"  # type: ignore[misc]


def test_principal_context_preserves_unavailable_source_scopes() -> None:
    context = PrincipalContext(
        principal_id="stdio-local",
        gateway_session_id=None,
        target_system_id="crm",
        source_scopes=None,
        deployment_scope_ceiling={"customer.read"},
        tenant_context=None,
        auth_state_handle="auth-state:stdio-local",
    )

    assert context.source_scopes is None


def test_gateway_principal_rejects_unavailable_source_scopes() -> None:
    with pytest.raises(ValueError, match=r"gateway.*source_scopes"):
        PrincipalContext(
            principal_id="user-a",
            gateway_session_id="gateway-session-a",
            target_system_id="crm",
            source_scopes=None,
            deployment_scope_ceiling={"customer.read"},
            tenant_context=None,
            auth_state_handle="auth-state:user-a",
        )


def test_principal_context_derives_effective_scopes_and_rejects_spoofed_value() -> None:
    context = _context()

    assert context.effective_scopes == frozenset({"customer.read"})
    with pytest.raises(TypeError, match="effective_scopes"):
        PrincipalContext(
            principal_id="user-a",
            gateway_session_id=None,
            target_system_id="crm",
            source_scopes=set(),
            deployment_scope_ceiling={"system.admin"},
            effective_scopes={"system.admin"},  # type: ignore[call-arg]
            tenant_context=None,
            auth_state_handle="auth-state:user-a",
        )


@pytest.mark.parametrize("auth_state_handle", [None, "", [], {}])
def test_principal_context_requires_nonempty_hashable_auth_state_handle(
    auth_state_handle: object,
) -> None:
    with pytest.raises((TypeError, ValueError), match="auth_state_handle"):
        PrincipalContext(
            principal_id="user-a",
            gateway_session_id=None,
            target_system_id="crm",
            source_scopes=None,
            deployment_scope_ceiling=set(),
            tenant_context=None,
            auth_state_handle=auth_state_handle,
        )


def test_tenant_context_is_defensively_copied_and_deeply_read_only() -> None:
    original: dict[str, object] = {
        "organization": {"region_id": "north"},
        "labels": ["priority"],
    }
    context = _context(tenant_context=original)

    original["organization"] = {"region_id": "south"}
    original["labels"] = ["changed"]

    assert context.tenant_context is not None
    organization = context.tenant_context["organization"]
    assert isinstance(organization, Mapping)
    assert organization["region_id"] == "north"
    assert context.tenant_context["labels"] == ("priority",)
    with pytest.raises(TypeError):
        organization["region_id"] = "south"  # type: ignore[index]
    with pytest.raises(TypeError):
        context.tenant_context["new_field"] = "value"  # type: ignore[index]


def test_resolve_context_binding_reads_principal_and_allowlisted_deep_tenant_path() -> None:
    context = _context(
        tenant_context={
            "organization": {
                "region": {"region_id": "north"},
            }
        }
    )
    allowed = {"tenant_context.organization.region.region_id"}

    assert resolve_context_binding(context, "principal_id", allowed) == "user-a"
    assert (
        resolve_context_binding(
            context,
            "tenant_context.organization.region.region_id",
            allowed,
        )
        == "north"
    )


def test_resolve_context_binding_requires_exact_provider_allowlist_entry() -> None:
    context = _context(tenant_context={"organization": {"region_id": "north"}})

    with pytest.raises(ValueError, match="not allowlisted"):
        resolve_context_binding(
            context,
            "tenant_context.organization.region_id",
            {"tenant_context.organization"},
        )


@pytest.mark.parametrize(
    ("reference", "allowed"),
    [
        ("tenant_context.organization.missing", {"tenant_context.organization.missing"}),
        ("tenant_context.regions.first", {"tenant_context.regions.first"}),
    ],
)
def test_resolve_context_binding_fails_closed_for_missing_or_non_mapping_path(
    reference: str,
    allowed: set[str],
) -> None:
    context = _context(
        tenant_context={"organization": {"region_id": "north"}, "regions": ["north"]}
    )

    with pytest.raises(ValueError, match="cannot be resolved"):
        resolve_context_binding(context, reference, allowed)


@pytest.mark.parametrize(
    "reference",
    [
        "auth_state_handle",
        "source_scopes",
        "effective_scopes",
        "gateway_session_id",
        "tenant_context.access_token",
        "tenant_context.identity.password",
        "tenant_context.request.authorization",
    ],
)
def test_resolve_context_binding_rejects_auth_scope_and_secret_paths(reference: str) -> None:
    context = _context(
        tenant_context={
            "access_token": "source-jwt",
            "identity": {"password": "secret"},
            "request": {"authorization": "Bearer source-jwt"},
        }
    )

    with pytest.raises(ValueError, match="not permitted"):
        resolve_context_binding(context, reference, {reference})


@pytest.mark.parametrize(
    "safe_segment",
    ["secretary_id", "header_image", "tokenized_region"],
)
def test_resolve_context_binding_denylist_uses_exact_case_insensitive_segments(
    safe_segment: str,
) -> None:
    reference = f"tenant_context.{safe_segment}"
    context = _context(tenant_context={safe_segment: "safe-business-value"})

    assert resolve_context_binding(context, reference, {reference}) == "safe-business-value"


def test_resolve_context_binding_denylist_is_case_insensitive() -> None:
    reference = "tenant_context.identity.Access_Token"
    context = _context(tenant_context={"identity": {"Access_Token": "source-jwt"}})

    with pytest.raises(ValueError, match="not permitted"):
        resolve_context_binding(context, reference, {reference})


def test_resolve_context_binding_returns_a_defensive_json_copy() -> None:
    context = _context(tenant_context={"filters": {"regions": ["north"]}})
    reference = "tenant_context.filters"

    first = resolve_context_binding(context, reference, {reference})
    assert first == {"regions": ["north"]}
    assert isinstance(first, dict)
    first["regions"].append("south")  # type: ignore[union-attr]

    assert resolve_context_binding(context, reference, {reference}) == {"regions": ["north"]}


def test_repr_and_public_serialization_do_not_expose_auth_state_handle() -> None:
    context = _context(
        tenant_context={"private_tenant_marker": "tenant-secret"},
        auth_state_handle="source-jwt-secret-handle",
    )

    assert "source-jwt-secret-handle" not in repr(context)
    assert "gateway-session-a" not in repr(context)
    assert "tenant-secret" not in repr(context)
    serialized = context.to_public_dict()
    assert "source-jwt-secret-handle" not in str(serialized)
    assert "gateway-session-a" not in str(serialized)
    assert "tenant-secret" not in str(serialized)
    assert "auth_state_handle" not in serialized
    assert "gateway_session_id" not in serialized
    assert "tenant_context" not in serialized
