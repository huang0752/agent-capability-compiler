"""Deterministic authorization and recursive output disclosure policies."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping
from typing import cast

from pydantic import JsonValue

from acc_core.models import Policy, RedactionRule
from acc_runtime.errors import RuntimeError

type FieldPath = tuple[str, ...]
_MISSING = object()
_REMOVED = object()


class PolicyScopeDeniedError(RuntimeError):
    code = "ACC_RUNTIME_POLICY_SCOPE_DENIED"
    status = 403


class PolicyTenantDeniedError(RuntimeError):
    code = "ACC_RUNTIME_POLICY_TENANT_DENIED"
    status = 403


class PolicyOutputError(RuntimeError):
    code = "ACC_RUNTIME_POLICY_OUTPUT_INVALID"
    status = 500


class PolicyEnforcer:
    """Enforce caller context and return a recursively filtered output copy."""

    def authorize(
        self,
        policy: Policy,
        *,
        granted_scopes: Collection[str],
        arguments: Mapping[str, JsonValue],
        tenant_id: JsonValue | None,
    ) -> None:
        """Require every declared scope and an exact tenant-field match."""

        available = set(granted_scopes)
        missing = sorted(set(policy.required_scopes) - available)
        if missing:
            raise PolicyScopeDeniedError(
                "caller lacks scopes required by the policy",
                details={"policy": policy.id, "missing_scopes": missing},
            )

        if policy.tenant_mode == "required":
            field = policy.tenant_field
            assert field is not None  # guaranteed by the Policy model
            actual = _lookup(arguments, _parse_path(field))
            if tenant_id is None or actual is _MISSING or actual != tenant_id:
                raise PolicyTenantDeniedError(
                    "request tenant does not match the runtime tenant",
                    details={"policy": policy.id, "tenant_field": field},
                )

    def filter_output(self, policy: Policy, output: JsonValue) -> JsonValue:
        """Apply allowlist, denylist, and redaction rules without mutating input."""

        readable = tuple(_parse_path(path) for path in policy.readable_fields)
        denied = tuple(_parse_path(path) for path in policy.denied_fields)
        redactions = {_parse_path(rule.path): rule for rule in policy.redaction_rules}
        value = _filter_node(
            output,
            (),
            readable=readable,
            denied=denied,
            redactions=redactions,
        )
        if value is _REMOVED:
            # A top-level JSON object is the useful and least surprising empty result.
            return {}
        return cast(JsonValue, value)

    def enforce(
        self,
        policy: Policy,
        *,
        granted_scopes: Collection[str],
        arguments: Mapping[str, JsonValue],
        tenant_id: JsonValue | None,
        output: JsonValue,
    ) -> JsonValue:
        """Authorize first so denied callers never receive a partially filtered result."""

        self.authorize(
            policy,
            granted_scopes=granted_scopes,
            arguments=arguments,
            tenant_id=tenant_id,
        )
        return self.filter_output(policy, output)


def _parse_path(value: str) -> FieldPath:
    if value.startswith("$."):
        value = value[2:]
    if value.startswith("/"):
        return tuple(part.replace("~1", "/").replace("~0", "~") for part in value[1:].split("/"))
    return tuple(part for part in value.split(".") if part)


def _lookup(value: object, path: FieldPath) -> object:
    current = value
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _filter_node(
    value: JsonValue,
    path: FieldPath,
    *,
    readable: tuple[FieldPath, ...],
    denied: tuple[FieldPath, ...],
    redactions: Mapping[FieldPath, RedactionRule],
) -> JsonValue | object:
    if _has_ancestor(path, denied):
        return _REMOVED
    if path and not _is_readable(path, readable):
        return _REMOVED

    redaction = redactions.get(path)
    if redaction is not None:
        if redaction.strategy == "remove":
            return _REMOVED
        if redaction.strategy == "mask":
            return "***"
        return _stable_hash(value)

    if isinstance(value, dict):
        filtered: dict[str, JsonValue] = {}
        for key in sorted(value):
            child = _filter_node(
                value[key],
                (*path, key),
                readable=readable,
                denied=denied,
                redactions=redactions,
            )
            if child is not _REMOVED:
                filtered[key] = cast(JsonValue, child)
        return filtered
    if isinstance(value, list):
        items: list[JsonValue] = []
        for item in value:
            filtered_item = _filter_node(
                item,
                path,
                readable=readable,
                denied=denied,
                redactions=redactions,
            )
            if filtered_item is not _REMOVED:
                items.append(cast(JsonValue, filtered_item))
        return items
    return value


def _has_ancestor(path: FieldPath, candidates: tuple[FieldPath, ...]) -> bool:
    return any(
        len(candidate) <= len(path) and path[: len(candidate)] == candidate
        for candidate in candidates
    )


def _is_readable(path: FieldPath, readable: tuple[FieldPath, ...]) -> bool:
    return any(
        (len(rule) <= len(path) and path[: len(rule)] == rule)
        or (len(path) < len(rule) and rule[: len(path)] == path)
        for rule in readable
    )


def _stable_hash(value: JsonValue) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyOutputError("redaction hash input is not valid JSON") from exc
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


__all__ = [
    "PolicyEnforcer",
    "PolicyOutputError",
    "PolicyScopeDeniedError",
    "PolicyTenantDeniedError",
]
