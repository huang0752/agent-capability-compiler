"""Trusted, request-scoped identity context for the generic runtime."""

from __future__ import annotations

import copy
import math
from collections.abc import Collection, Hashable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

from pydantic import JsonValue

type FrozenJsonValue = (
    bool
    | int
    | float
    | str
    | tuple["FrozenJsonValue", ...]
    | Mapping[str, "FrozenJsonValue"]
    | None
)

_DENIED_TENANT_SEGMENTS = frozenset(
    {
        "secret",
        "token",
        "access_token",
        "password",
        "header",
        "headers",
        "authorization",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "jwt",
        "bearer",
        "api_key",
        "private_key",
        "csrf",
    }
)


def _scope_set(scopes: Collection[str], *, field_name: str) -> frozenset[str]:
    if isinstance(scopes, (str, bytes)) or any(not isinstance(scope, str) for scope in scopes):
        raise TypeError(f"{field_name} must be a collection of strings")
    return frozenset(scopes)


def map_effective_scopes(
    source_scopes: Collection[str] | None,
    deployment_scope_ceiling: Collection[str],
    scope_mapping: Mapping[str, Collection[str]],
) -> frozenset[str]:
    """Map source permissions and intersect them with the deployment ceiling.

    ``None`` means that source permissions are unavailable in a fixed stdio
    deployment. It is intentionally distinct from a known empty permission set.
    """

    ceiling = _scope_set(
        deployment_scope_ceiling,
        field_name="deployment_scope_ceiling",
    )
    if source_scopes is None:
        return ceiling

    normalized_source = _scope_set(source_scopes, field_name="source_scopes")
    mapped: set[str] = set()
    for source_scope in normalized_source:
        targets = scope_mapping.get(source_scope, ())
        mapped.update(_scope_set(targets, field_name=f"scope_mapping[{source_scope!r}]"))
    return frozenset(mapped & ceiling)


@dataclass(frozen=True, slots=True, init=False)
class PrincipalContext:
    """Immutable identity state created only by a trusted transport resolver."""

    principal_id: str
    gateway_session_id: str | None = field(repr=False)
    target_system_id: str
    source_scopes: frozenset[str] | None = field(repr=False)
    deployment_scope_ceiling: frozenset[str]
    effective_scopes: frozenset[str]
    tenant_context: Mapping[str, FrozenJsonValue] | None = field(repr=False)
    auth_state_handle: Hashable = field(repr=False)

    def __init__(
        self,
        *,
        principal_id: str,
        gateway_session_id: str | None,
        target_system_id: str,
        source_scopes: Collection[str] | None,
        deployment_scope_ceiling: Collection[str],
        tenant_context: Mapping[str, object] | None,
        auth_state_handle: Hashable,
        scope_mapping: Mapping[str, Collection[str]] | None = None,
    ) -> None:
        if not isinstance(principal_id, str) or not principal_id:
            raise ValueError("principal_id must be a nonempty string")
        if gateway_session_id is not None and (
            not isinstance(gateway_session_id, str) or not gateway_session_id
        ):
            raise ValueError("gateway_session_id must be a nonempty string when present")
        if not isinstance(target_system_id, str) or not target_system_id:
            raise ValueError("target_system_id must be a nonempty string")
        if gateway_session_id is not None and source_scopes is None:
            raise ValueError("gateway PrincipalContext requires available source_scopes")
        if not isinstance(auth_state_handle, Hashable) or not auth_state_handle:
            raise ValueError("auth_state_handle must be nonempty and hashable")

        ceiling = _scope_set(
            deployment_scope_ceiling,
            field_name="deployment_scope_ceiling",
        )
        normalized_source = (
            None if source_scopes is None else _scope_set(source_scopes, field_name="source_scopes")
        )
        effective = map_effective_scopes(
            normalized_source,
            ceiling,
            {} if scope_mapping is None else scope_mapping,
        )

        frozen_tenant: Mapping[str, FrozenJsonValue] | None = None
        if tenant_context is not None:
            copied_tenant = copy.deepcopy(dict(tenant_context))
            frozen = _freeze_json(copied_tenant)
            assert isinstance(frozen, Mapping)
            frozen_tenant = frozen

        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "gateway_session_id", gateway_session_id)
        object.__setattr__(self, "target_system_id", target_system_id)
        object.__setattr__(self, "source_scopes", normalized_source)
        object.__setattr__(self, "deployment_scope_ceiling", ceiling)
        object.__setattr__(self, "effective_scopes", effective)
        object.__setattr__(self, "tenant_context", frozen_tenant)
        object.__setattr__(self, "auth_state_handle", auth_state_handle)

    def to_public_dict(self) -> dict[str, JsonValue]:
        """Return non-sensitive identity metadata suitable for diagnostics."""

        return {
            "principal_id": self.principal_id,
            "target_system_id": self.target_system_id,
            "effective_scopes": cast(JsonValue, sorted(self.effective_scopes)),
        }


def resolve_context_binding(
    context: PrincipalContext,
    reference: str,
    allowed_tenant_context_bindings: Collection[str],
) -> JsonValue:
    """Resolve one compiler-approved binding without exposing auth state."""

    if reference == "principal_id":
        return context.principal_id
    if not reference.startswith("tenant_context."):
        raise ValueError(f"context binding is not permitted: {reference}")

    path = reference.split(".")[1:]
    if not path or any(segment.casefold() in _DENIED_TENANT_SEGMENTS for segment in path):
        raise ValueError(f"context binding is not permitted: {reference}")
    if reference not in allowed_tenant_context_bindings:
        raise ValueError(f"tenant context binding is not allowlisted: {reference}")

    current: FrozenJsonValue = context.tenant_context
    for segment in path:
        if not isinstance(current, Mapping) or segment not in current:
            raise ValueError(f"tenant context binding cannot be resolved: {reference}")
        current = current[segment]
    return _thaw_json(current)


def _freeze_json(value: object) -> FrozenJsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("tenant_context must contain finite JSON values")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("tenant_context object keys must be strings")
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    raise TypeError("tenant_context must contain JSON-compatible values")


def _thaw_json(value: FrozenJsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


__all__ = [
    "PrincipalContext",
    "map_effective_scopes",
    "resolve_context_binding",
]
