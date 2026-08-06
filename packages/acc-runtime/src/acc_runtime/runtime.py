"""Composition root for the fixed, model-free ACC generic runtime."""

from __future__ import annotations

import asyncio
import copy
import inspect
import os
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, Protocol, cast

import httpx
from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.models import (
    BearerSecretAuthConfig,
    Capability,
    NoAuthConfig,
    Operation,
    PasswordBearerAuthConfig,
    Policy,
    Project,
)
from acc_runtime.auth import (
    BearerSecretAuthStrategy,
    EnvironmentCredentialSource,
    HttpAuthStrategy,
    NoAuthStrategy,
    PasswordBearerAuthStrategy,
)
from acc_runtime.context import PrincipalContext, resolve_context_binding
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.execution import ExecutionError, WorkflowExecutor
from acc_runtime.loader import LoadedPack, load_pack
from acc_runtime.policies import PolicyEnforcer
from acc_runtime.providers import HttpProvider


class RuntimeConfigurationError(AccRuntimeError):
    code = "ACC_RUNTIME_CONFIGURATION_INVALID"
    status = 500


@dataclass(frozen=True, slots=True)
class _RuntimeFailure:
    error_type: type[AccRuntimeError]
    code: str
    message: str
    details: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _RuntimeSuccess:
    value: JsonValue


@dataclass(frozen=True, slots=True)
class _RuntimeCancelled:
    pass


_RUNTIME_CANCELLED = _RuntimeCancelled()
type _RuntimeOutcome = _RuntimeSuccess | _RuntimeFailure | _RuntimeCancelled


class OperationProvider(Protocol):
    """Legacy two-argument provider contract kept for embedded runtimes."""

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue: ...


class ContextOperationProvider(Protocol):
    """Provider contract that receives the trusted request Principal explicitly."""

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue: ...


class _PolicyOperationCaller:
    def __init__(
        self,
        provider: OperationProvider | ContextOperationProvider,
        policy: Policy,
        principal_context: PrincipalContext,
        allowed_context_bindings: Collection[str],
    ) -> None:
        self.provider = provider
        self.policy = policy
        self.principal_context = principal_context
        self.allowed_context_bindings = frozenset(allowed_context_bindings)
        self.tenant_id = _legacy_tenant_id(principal_context)
        self._provider_accepts_context = _accepts_principal_context(provider)
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
        for target, reference in definition.context_bindings.items():
            if target in enriched:
                raise RuntimeConfigurationError(
                    "workflow arguments cannot override a trusted context binding",
                    details={"operation_id": definition.id, "binding_target": target},
                )
            try:
                enriched[target] = resolve_context_binding(
                    self.principal_context,
                    reference,
                    self.allowed_context_bindings,
                )
            except (TypeError, ValueError):
                raise RuntimeConfigurationError(
                    "compiled context binding cannot be resolved",
                    details={"operation_id": definition.id, "binding_target": target},
                ) from None
        if effective_policy.tenant_mode == "required":
            field = effective_policy.tenant_field
            assert field is not None
            _inject_context_value(enriched, field, self.tenant_id)
        if next(Draft202012Validator(definition.input_schema).iter_errors(enriched), None):
            raise ExecutionError(
                "ACC_RUNTIME_OPERATION_INPUT_INVALID",
                "trusted context and workflow arguments do not match the operation schema",
                details={"operation_id": definition.id, "schema_role": "operation_input"},
            )
        self.enforcer.authorize(
            effective_policy,
            granted_scopes=self.principal_context.effective_scopes,
            arguments=enriched,
            tenant_id=self.tenant_id,
        )
        if self._provider_accepts_context:
            contextual_provider = cast(ContextOperationProvider, self.provider)
            return await contextual_provider.call(
                cast(Mapping[str, object], operation),
                cast(Mapping[str, JsonValue], enriched),
                principal_context=self.principal_context,
            )
        legacy_provider = cast(OperationProvider, self.provider)
        return await legacy_provider.call(
            cast(Mapping[str, object], operation),
            cast(Mapping[str, JsonValue], enriched),
        )


class GenericRuntime:
    """Expose compiled capabilities over a fixed provider and policy context."""

    def __init__(
        self,
        compiled_ir: Mapping[str, Any],
        *,
        provider: OperationProvider | ContextOperationProvider,
        principal_context: PrincipalContext | None = None,
        granted_scopes: Collection[str] = (),
        tenant_id: JsonValue | None = None,
        loaded_pack: LoadedPack | None = None,
    ) -> None:
        self.ir = copy.deepcopy(dict(compiled_ir))
        self.provider = provider
        self.loaded_pack = loaded_pack
        self._owned_auth_strategy: HttpAuthStrategy | None = None
        self._closed = False
        self.project = self._load_project()
        if principal_context is None:
            principal_context = _stdio_principal_context(
                self.project,
                environment=None,
                granted_scopes=granted_scopes,
                tenant_id=tenant_id,
            )
        elif principal_context.target_system_id != self.project.project.id:
            raise RuntimeConfigurationError(
                "PrincipalContext belongs to another target system",
                details={"reason": "principal_target_mismatch"},
            )
        self._principal_context = principal_context

    @property
    def principal_context(self) -> PrincipalContext:
        """Return the immutable Principal fixed at construction without permitting replacement."""

        return self._principal_context

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
        principal_context = _stdio_principal_context(
            project,
            environment=environment,
            granted_scopes=granted_scopes,
            tenant_id=tenant_id,
        )
        auth_strategy = _auth_strategy_from_project(project, environment=environment)
        provider = HttpProvider(
            base_url_ref=project.provider.base_url_ref,
            auth_strategy=auth_strategy,
            environment=environment,
            client=client,
        )
        runtime = cls(
            loaded.ir,
            provider=provider,
            principal_context=principal_context,
            loaded_pack=loaded,
        )
        runtime._owned_auth_strategy = auth_strategy
        return runtime

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
        """Execute using only the Principal fixed at runtime construction."""

        runtime = self
        outcome = await runtime._call_outcome(
            capability_id,
            arguments,
            runtime._principal_context,
        )
        if isinstance(outcome, _RuntimeSuccess):
            return outcome.value
        failure = outcome
        del outcome
        del arguments
        del capability_id
        del runtime
        del self
        _raise_runtime_failure(failure)

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        """Execute one request with a Principal supplied by a trusted transport."""

        runtime = self
        outcome = await runtime._call_outcome(
            capability_id,
            arguments,
            principal_context,
        )
        if isinstance(outcome, _RuntimeSuccess):
            return outcome.value
        failure = outcome
        del outcome
        del principal_context
        del arguments
        del capability_id
        del runtime
        del self
        _raise_runtime_failure(failure)

    async def _call_outcome(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> _RuntimeOutcome:
        if self._closed:
            return _RuntimeFailure(
                error_type=RuntimeConfigurationError,
                code=RuntimeConfigurationError.code,
                message="runtime is closed",
                details={"reason": "runtime_closed"},
            )
        try:
            value = await self._execute_call(capability_id, arguments, principal_context)
        except asyncio.CancelledError:
            return _RUNTIME_CANCELLED
        except AccRuntimeError as error:
            return _runtime_failure(error)
        except Exception:
            return _RuntimeFailure(
                error_type=RuntimeConfigurationError,
                code=RuntimeConfigurationError.code,
                message="runtime execution failed",
                details={"reason": "runtime_internal_failure"},
            )
        return _RuntimeSuccess(value)

    async def _execute_call(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        if not isinstance(principal_context, PrincipalContext):
            raise RuntimeConfigurationError(
                "runtime requires a trusted PrincipalContext",
                details={"reason": "principal_context_invalid"},
            )
        if principal_context.target_system_id != self.project.project.id:
            raise RuntimeConfigurationError(
                "PrincipalContext belongs to another target system",
                details={"reason": "principal_target_mismatch"},
            )
        capability = self._capability(capability_id)
        policy = self._policy(capability.policy)
        scope_only_policy = policy.model_copy(update={"tenant_mode": "none", "tenant_field": None})
        PolicyEnforcer().authorize(
            scope_only_policy,
            granted_scopes=principal_context.effective_scopes,
            arguments={},
            tenant_id=None,
        )
        caller = _PolicyOperationCaller(
            self.provider,
            policy,
            principal_context,
            self.project.provider.context_binding_allowlist,
        )
        # Capability output schemas are public contracts. Apply disclosure policy
        # before validating them so an upstream-only field can never be required
        # or advertised merely to make the raw workflow result validate.
        result = await WorkflowExecutor(
            caller,
            validate_output=False,
            validate_operation_input=False,
        ).execute(
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

    async def aclose(self) -> None:
        """Idempotently close only authentication state created by ``from_pack``."""

        runtime = self
        outcome = await runtime._close_outcome()
        if outcome is None:
            return
        failure = outcome
        del outcome
        del runtime
        del self
        _raise_runtime_failure(failure)

    async def _close_outcome(self) -> _RuntimeFailure | _RuntimeCancelled | None:
        if self._closed:
            return None
        self._closed = True
        strategy = self._owned_auth_strategy
        self._owned_auth_strategy = None
        if strategy is None:
            return None
        try:
            await strategy.aclose()
        except asyncio.CancelledError:
            return _RUNTIME_CANCELLED
        except AccRuntimeError as error:
            return _runtime_failure(error)
        except Exception:
            return _RuntimeFailure(
                error_type=RuntimeConfigurationError,
                code=RuntimeConfigurationError.code,
                message="runtime close failed",
                details={"reason": "runtime_close_failed"},
            )
        return None

    async def __aenter__(self) -> GenericRuntime:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        runtime = self
        outcome = await runtime._close_outcome()
        if outcome is None:
            return
        failure = outcome
        del outcome
        del traceback
        del exc_value
        del exc_type
        del runtime
        del self
        _raise_runtime_failure(failure)


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


def _accepts_principal_context(
    provider: OperationProvider | ContextOperationProvider,
) -> bool:
    try:
        inspect.signature(provider.call).bind(
            {},
            {},
            principal_context=object(),
        )
    except (TypeError, ValueError):
        return False
    return True


def _legacy_tenant_id(context: PrincipalContext) -> JsonValue | None:
    try:
        return resolve_context_binding(
            context,
            "tenant_context.tenant_id",
            {"tenant_context.tenant_id"},
        )
    except ValueError:
        return None


def _stdio_principal_context(
    project: Project,
    *,
    environment: Mapping[str, str] | None,
    granted_scopes: Collection[str],
    tenant_id: JsonValue | None,
) -> PrincipalContext:
    source = os.environ if environment is None else environment
    principal_id = source.get("ACC_PRINCIPAL_ID", "stdio-local")
    tenant_context = None if tenant_id is None else {"tenant_id": tenant_id}
    return PrincipalContext(
        principal_id=principal_id,
        gateway_session_id=None,
        target_system_id=project.project.id,
        source_scopes=None,
        deployment_scope_ceiling=granted_scopes,
        tenant_context=tenant_context,
        auth_state_handle=f"stdio:{project.project.id}",
    )


def _auth_strategy_from_project(
    project: Project,
    *,
    environment: Mapping[str, str] | None,
) -> HttpAuthStrategy | None:
    auth = project.provider.auth
    if auth is None:
        return None
    if isinstance(auth, NoAuthConfig):
        return NoAuthStrategy()
    if isinstance(auth, BearerSecretAuthConfig):
        return BearerSecretAuthStrategy(auth.token_ref, environment=environment)
    if not isinstance(auth, PasswordBearerAuthConfig):  # pragma: no cover - discriminated union
        raise RuntimeConfigurationError(
            "compiled provider authentication is invalid",
            details={"reason": "provider_auth_invalid"},
        )
    if auth.credentials.kind == "gateway_session":
        if project.runtime.transport == ["stdio"]:
            raise RuntimeConfigurationError(
                "Gateway session credentials require streamable HTTP",
                details={"reason": "gateway_session_requires_streamable_http"},
            )
        return PasswordBearerAuthStrategy(
            config=auth,
            base_url=_authentication_base_url(project, environment),
            credential_source=None,
        )
    return PasswordBearerAuthStrategy(
        config=auth,
        base_url=_authentication_base_url(project, environment),
        credential_source=EnvironmentCredentialSource(
            auth.credentials,
            environment=environment,
        ),
    )


def _authentication_base_url(
    project: Project,
    environment: Mapping[str, str] | None,
) -> str:
    source = os.environ if environment is None else environment
    value = source.get(project.provider.base_url_ref)
    if not isinstance(value, str) or not value:
        raise RuntimeConfigurationError(
            "HTTP base URL is required for password authentication",
            details={"reason": "authentication_base_url_missing"},
        )
    return value


def _runtime_failure(error: AccRuntimeError) -> _RuntimeFailure:
    return _RuntimeFailure(
        error_type=type(error),
        code=str(error.code),
        message=str(error),
        details=copy.deepcopy(error.details),
    )


def _raise_runtime_failure(failure: _RuntimeFailure | _RuntimeCancelled) -> Never:
    if isinstance(failure, _RuntimeCancelled):
        raise asyncio.CancelledError from None
    if issubclass(failure.error_type, ExecutionError):
        raise ExecutionError(
            failure.code,
            failure.message,
            details=cast(Mapping[str, str | int | None], failure.details),
        ) from None
    raise failure.error_type(failure.message, details=failure.details) from None


__all__ = [
    "ContextOperationProvider",
    "GenericRuntime",
    "OperationProvider",
    "RuntimeConfigurationError",
]
