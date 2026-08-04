"""Composition root for the fixed, model-free ACC generic runtime."""

from __future__ import annotations

import copy
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any, Protocol, cast

import httpx
from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.models import Capability, Operation, Policy, Project
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.execution import ExecutionError, WorkflowExecutor
from acc_runtime.loader import LoadedPack, load_pack
from acc_runtime.policies import PolicyEnforcer
from acc_runtime.providers import HttpProvider


class RuntimeConfigurationError(AccRuntimeError):
    code = "ACC_RUNTIME_CONFIGURATION_INVALID"
    status = 500


class OperationProvider(Protocol):
    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue: ...


class _PolicyOperationCaller:
    def __init__(
        self,
        provider: OperationProvider,
        policy: Policy,
        granted_scopes: Collection[str],
        tenant_id: JsonValue | None,
    ) -> None:
        self.provider = provider
        self.policy = policy
        self.granted_scopes = frozenset(granted_scopes)
        self.tenant_id = tenant_id
        self.enforcer = PolicyEnforcer()

    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        try:
            definition = Operation.model_validate(operation)
        except ValidationError:
            raise RuntimeConfigurationError(
                "compiled operation is invalid",
                details={"operation_id": str(operation.get("id", "unknown"))},
            ) from None

        effective_policy = self.policy.model_copy(
            update={
                "required_scopes": sorted(
                    set(self.policy.required_scopes) | set(definition.http.scopes)
                )
            }
        )
        enriched = copy.deepcopy(dict(arguments))
        if effective_policy.tenant_mode == "required":
            field = effective_policy.tenant_field
            assert field is not None
            _inject_context_value(enriched, field, self.tenant_id)
        self.enforcer.authorize(
            effective_policy,
            granted_scopes=self.granted_scopes,
            arguments=enriched,
            tenant_id=self.tenant_id,
        )
        return await self.provider.call(
            cast(Mapping[str, object], operation),
            cast(Mapping[str, JsonValue], enriched),
        )


class GenericRuntime:
    """Expose compiled capabilities over a fixed provider and policy context."""

    def __init__(
        self,
        compiled_ir: Mapping[str, Any],
        *,
        provider: OperationProvider,
        granted_scopes: Collection[str] = (),
        tenant_id: JsonValue | None = None,
        loaded_pack: LoadedPack | None = None,
    ) -> None:
        self.ir = copy.deepcopy(dict(compiled_ir))
        self.provider = provider
        self.granted_scopes = frozenset(granted_scopes)
        self.tenant_id = tenant_id
        self.loaded_pack = loaded_pack
        self.project = self._load_project()

    @classmethod
    def from_pack(
        cls,
        pack_path: str | Path,
        *,
        environment: Mapping[str, str] | None = None,
        granted_scopes: Collection[str] = (),
        tenant_id: JsonValue | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> GenericRuntime:
        loaded = load_pack(pack_path)
        project_value = loaded.ir.get("project")
        try:
            project = Project.model_validate(project_value)
        except ValidationError:
            raise RuntimeConfigurationError("compiled project contract is invalid") from None
        provider = HttpProvider(
            base_url_ref=project.provider.base_url_ref,
            environment=environment,
            client=client,
        )
        return cls(
            loaded.ir,
            provider=provider,
            granted_scopes=granted_scopes,
            tenant_id=tenant_id,
            loaded_pack=loaded,
        )

    def _load_project(self) -> Project:
        try:
            return Project.model_validate(self.ir.get("project"))
        except ValidationError:
            raise RuntimeConfigurationError("compiled project contract is invalid") from None

    def _capability(self, capability_id: str) -> Capability:
        capabilities = self.ir.get("capabilities")
        if not isinstance(capabilities, Mapping):
            raise RuntimeConfigurationError("compiled capabilities are missing")
        compiled = capabilities.get(capability_id)
        if not isinstance(compiled, Mapping):
            raise ExecutionError(
                "ACC_RUNTIME_CAPABILITY_NOT_FOUND",
                "capability is not present in the loaded pack",
                details={"capability_id": capability_id},
            )
        try:
            return Capability.model_validate(compiled.get("definition"))
        except ValidationError:
            raise RuntimeConfigurationError(
                "compiled capability is invalid",
                details={"capability_id": capability_id},
            ) from None

    def _policy(self, policy_id: str) -> Policy:
        policies = self.ir.get("policies")
        if not isinstance(policies, Mapping):
            raise RuntimeConfigurationError("compiled policies are missing")
        try:
            return Policy.model_validate(policies.get(policy_id))
        except ValidationError:
            raise RuntimeConfigurationError(
                "compiled policy is invalid",
                details={"policy_id": policy_id},
            ) from None

    def tools(self) -> list[dict[str, object]]:
        capabilities = self.ir.get("capabilities")
        if not isinstance(capabilities, Mapping):
            raise RuntimeConfigurationError("compiled capabilities are missing")
        tools: list[dict[str, object]] = []
        for capability_id in sorted(capabilities):
            if not isinstance(capability_id, str):
                raise RuntimeConfigurationError("capability ids must be strings")
            capability = self._capability(capability_id)
            tools.append(
                {
                    "name": capability.id,
                    "title": capability.title,
                    "description": capability.description,
                    "input_schema": copy.deepcopy(capability.input_schema),
                    "output_schema": copy.deepcopy(capability.output_schema),
                }
            )
        return tools

    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        capability = self._capability(capability_id)
        policy = self._policy(capability.policy)
        scope_only_policy = policy.model_copy(update={"tenant_mode": "none", "tenant_field": None})
        PolicyEnforcer().authorize(
            scope_only_policy,
            granted_scopes=self.granted_scopes,
            arguments={},
            tenant_id=None,
        )
        caller = _PolicyOperationCaller(
            self.provider,
            policy,
            self.granted_scopes,
            self.tenant_id,
        )
        result = await WorkflowExecutor(caller).execute(
            self.ir,
            capability_id,
            cast(JsonValue, copy.deepcopy(dict(arguments))),
        )
        filtered = PolicyEnforcer().filter_output(policy, result)
        if next(Draft202012Validator(capability.output_schema).iter_errors(filtered), None):
            raise ExecutionError(
                "ACC_RUNTIME_OUTPUT_INVALID",
                "policy-filtered output does not match the capability schema",
                details={
                    "capability_id": capability_id,
                    "schema_role": "filtered_capability_output",
                },
            )
        return filtered


def _field_path(field: str) -> tuple[str, ...]:
    value = field[2:] if field.startswith("$.") else field
    if value.startswith("/"):
        return tuple(
            token.replace("~1", "/").replace("~0", "~") for token in value[1:].split("/") if token
        )
    return tuple(token for token in value.split(".") if token)


def _inject_context_value(
    arguments: dict[str, JsonValue],
    field: str,
    value: JsonValue | None,
) -> None:
    path = _field_path(field)
    if not path or value is None:
        return
    current: dict[str, JsonValue] = arguments
    for token in path[:-1]:
        existing = current.get(token)
        if existing is None:
            child: dict[str, JsonValue] = {}
            current[token] = child
            current = child
        elif isinstance(existing, dict):
            current = existing
        else:
            return
    current.setdefault(path[-1], copy.deepcopy(value))


__all__ = ["GenericRuntime", "OperationProvider", "RuntimeConfigurationError"]
