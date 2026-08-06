"""Trusted, request-scoped identity context for the generic runtime."""

from __future__ import annotations

import copy
import math
import re
import unicodedata
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

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

_TENANT_CONTEXT_PATH = re.compile(
    r"^tenant_context\.[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)*$"
)
_CAMEL_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_WORD_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_SEPARATOR_RUN = re.compile(r"[_-]+")
_DENIED_TENANT_WORDS = frozenset(
    {
        "secret",
        "token",
        "password",
        "authorization",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "jwt",
        "bearer",
        "csrf",
    }
)
_DENIED_TENANT_COMPACT_MARKERS = frozenset(
    {
        "accesstoken",
        "refreshtoken",
        "authtoken",
        "oauthtoken",
        "idtoken",
        "apitoken",
        "jwttoken",
        "sessiontoken",
        "passwordhash",
        "authorizationheader",
        "clientsecret",
        "apisecret",
        "apikey",
        "privatekey",
        "setcookie",
    }
)


def _validated_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value.strip() or any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError(f"{field_name} must be nonempty and contain no control characters")
    return value


def _scope_set(scopes: Collection[str], *, field_name: str) -> frozenset[str]:
    if not isinstance(scopes, Collection) or isinstance(scopes, (str, bytes, Mapping)):
        raise TypeError(f"{field_name} must be a collection of strings")
    return frozenset(_validated_text(scope, field_name=field_name) for scope in scopes)


def _validated_scope_mapping(
    scope_mapping: Mapping[str, Collection[str]],
) -> Mapping[str, frozenset[str]]:
    if not isinstance(scope_mapping, Mapping):
        raise TypeError("scope_mapping must be a mapping of scope collections")
    validated: dict[str, frozenset[str]] = {}
    for source_scope, target_scopes in scope_mapping.items():
        source = _validated_text(source_scope, field_name="scope_mapping source scope")
        validated[source] = _scope_set(
            target_scopes,
            field_name=f"scope_mapping target scopes for {source!r}",
        )
    return validated


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
    validated_mapping = _validated_scope_mapping(scope_mapping)
    if source_scopes is None:
        return ceiling

    normalized_source = _scope_set(source_scopes, field_name="source_scopes")
    mapped: set[str] = set()
    for source_scope in normalized_source:
        mapped.update(validated_mapping.get(source_scope, ()))
    return frozenset(mapped & ceiling)


@dataclass(frozen=True, slots=True, repr=False)
class AuthStateKey:
    """Composite key that isolates authentication state between Principals."""

    principal_id: str = field(repr=False)
    target_system_id: str = field(repr=False)
    gateway_session_id: str | None = field(repr=False)
    auth_state_handle: str = field(repr=False)


@dataclass(frozen=True, slots=True, init=False)
class PrincipalContext:
    """Immutable identity state created only by a trusted transport resolver."""

    principal_id: str = field(repr=False)
    gateway_session_id: str | None = field(repr=False)
    target_system_id: str
    source_scopes: frozenset[str] | None = field(repr=False)
    deployment_scope_ceiling: frozenset[str] = field(repr=False)
    effective_scopes: frozenset[str] = field(repr=False)
    tenant_context: Mapping[str, FrozenJsonValue] | None = field(repr=False)
    auth_state_handle: str = field(repr=False)

    def __init__(
        self,
        *,
        principal_id: str,
        gateway_session_id: str | None,
        target_system_id: str,
        source_scopes: Collection[str] | None,
        deployment_scope_ceiling: Collection[str],
        tenant_context: Mapping[str, object] | None,
        auth_state_handle: str,
        scope_mapping: Mapping[str, Collection[str]] | None = None,
    ) -> None:
        validated_principal_id = _validated_text(principal_id, field_name="principal_id")
        validated_gateway_session_id = (
            None
            if gateway_session_id is None
            else _validated_text(gateway_session_id, field_name="gateway_session_id")
        )
        validated_target_system_id = _validated_text(
            target_system_id,
            field_name="target_system_id",
        )
        if gateway_session_id is not None and source_scopes is None:
            raise ValueError("gateway PrincipalContext requires available source_scopes")
        validated_auth_state_handle = _validated_text(
            auth_state_handle,
            field_name="auth_state_handle",
        )

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

        object.__setattr__(self, "principal_id", validated_principal_id)
        object.__setattr__(self, "gateway_session_id", validated_gateway_session_id)
        object.__setattr__(self, "target_system_id", validated_target_system_id)
        object.__setattr__(self, "source_scopes", normalized_source)
        object.__setattr__(self, "deployment_scope_ceiling", ceiling)
        object.__setattr__(self, "effective_scopes", effective)
        object.__setattr__(self, "tenant_context", frozen_tenant)
        object.__setattr__(self, "auth_state_handle", validated_auth_state_handle)

    @property
    def auth_state_key(self) -> AuthStateKey:
        """Return the only supported key for authentication-state storage."""

        return AuthStateKey(
            principal_id=self.principal_id,
            target_system_id=self.target_system_id,
            gateway_session_id=self.gateway_session_id,
            auth_state_handle=self.auth_state_handle,
        )


def resolve_context_binding(
    context: PrincipalContext,
    reference: str,
    allowed_tenant_context_bindings: Collection[str],
) -> JsonValue:
    """Resolve one compiler-approved binding without exposing auth state."""

    if reference == "principal_id":
        return context.principal_id
    if _TENANT_CONTEXT_PATH.fullmatch(reference) is None:
        raise ValueError(f"context binding is not permitted: {reference}")

    path = reference.split(".")[1:]
    if any(_segment_is_sensitive(segment) for segment in path):
        raise ValueError(f"context binding is not permitted: {reference}")
    if not isinstance(allowed_tenant_context_bindings, Collection) or isinstance(
        allowed_tenant_context_bindings,
        (str, bytes, Mapping),
    ):
        raise TypeError("tenant context binding allowlist must be a collection of strings")
    if any(not isinstance(item, str) for item in allowed_tenant_context_bindings):
        raise TypeError("tenant context binding allowlist must contain only strings")
    if reference not in frozenset(allowed_tenant_context_bindings):
        raise ValueError(f"tenant context binding is not allowlisted: {reference}")

    current: FrozenJsonValue = context.tenant_context
    for segment in path:
        if not isinstance(current, Mapping) or segment not in current:
            raise ValueError(f"tenant context binding cannot be resolved: {reference}")
        current = current[segment]
    return _thaw_json(current)


def _normalized_segment(segment: str) -> str:
    with_acronym_boundaries = _CAMEL_ACRONYM_BOUNDARY.sub(r"\1_\2", segment)
    with_word_boundaries = _CAMEL_WORD_BOUNDARY.sub(r"\1_\2", with_acronym_boundaries)
    return _SEPARATOR_RUN.sub("_", with_word_boundaries).casefold()


def _segment_is_sensitive(segment: str) -> bool:
    normalized = _normalized_segment(segment)
    words = frozenset(normalized.split("_"))
    compact = "".join(character for character in segment if character.isalnum()).casefold()
    return (
        normalized in {"header", "headers"}
        or bool(words & _DENIED_TENANT_WORDS)
        or any(marker in compact for marker in _DENIED_TENANT_COMPACT_MARKERS)
        or {"api", "key"} <= words
        or {"private", "key"} <= words
        or {"set", "cookie"} <= words
    )


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
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    raise TypeError("tenant_context must contain JSON-compatible values")


def _thaw_json(value: FrozenJsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


__all__ = [
    "AuthStateKey",
    "PrincipalContext",
    "map_effective_scopes",
    "resolve_context_binding",
]
