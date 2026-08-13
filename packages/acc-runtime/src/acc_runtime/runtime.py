"""Composition root for the fixed, model-free ACC generic runtime."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import inspect
import json
import os
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, Protocol, cast

import httpx
from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.models import (
    ActionCapabilityV2,
    ActionOperationV2,
    BearerSecretAuthConfig,
    NoAuthConfig,
    PasswordBearerAuthConfig,
    Policy,
    ProjectV2,
    ReadCapabilityV2,
    ReadOperationV2,
)
from acc_core.quality.output_size import canonical_json_bytes
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
from acc_runtime.gateway.audit import (
    AuditCollector,
    AuditResultCategory,
    AuditSpan,
    OperationObserver,
    observe_operation,
)
from acc_runtime.loader import LoadedPack, load_pack
from acc_runtime.policies import PolicyEnforcer
from acc_runtime.providers import HttpProvider, JsonApplicationSuccessPolicy


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
    """Two-argument provider contract for trusted embedded runtimes."""

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
        audit_observer: OperationObserver | None = None,
        operation_observer: OperationObserver | None = None,
    ) -> None:
        self.provider = provider
        self.policy = policy
        self.principal_context = principal_context
        self.allowed_context_bindings = frozenset(allowed_context_bindings)
        self.tenant_id = _tenant_id(principal_context)
        self._provider_accepts_context = _accepts_principal_context(provider)
        self.enforcer = PolicyEnforcer()
        self.audit_observer = audit_observer
        self.operation_observer = operation_observer

    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        try:
            definition = _load_operation(operation)
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
        observe_operation(self.audit_observer, definition.id)
        observe_operation(self.operation_observer, definition.id)
        if self._provider_accepts_context:
            contextual_provider = cast(ContextOperationProvider, self.provider)
            return await contextual_provider.call(
                cast(Mapping[str, object], operation),
                cast(Mapping[str, JsonValue], enriched),
                principal_context=self.principal_context,
            )
        embedded_provider = cast(OperationProvider, self.provider)
        return await embedded_provider.call(
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
        audit_collector: AuditCollector | None = None,
        operation_observer: OperationObserver | None = None,
    ) -> None:
        self.ir = copy.deepcopy(dict(compiled_ir))
        self.provider = provider
        self.loaded_pack = loaded_pack
        self._owned_auth_strategy: HttpAuthStrategy | None = None
        self._closed = False
        self._audit_collector = audit_collector
        self._operation_observer = operation_observer
        if self.ir.get("ir_version") != "2":
            raise RuntimeConfigurationError(
                "compiled IR version is unsupported",
                details={"reason": "ir_version_invalid"},
            )
        self.project = self._load_project()
        self._interaction_manifest, self._public_defaults = _load_interactions(self.ir)
        self.interaction_sha256 = cast(str, self._interaction_manifest["digest"])
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

    def interaction_manifest(self) -> dict[str, JsonValue]:
        """Return a defensive copy of the verified public interaction manifest."""

        return copy.deepcopy(self._interaction_manifest)

    @classmethod
    def from_pack(
        cls,
        pack_path: str | Path,
        *,
        environment: Mapping[str, str] | None = None,
        granted_scopes: Collection[str] = (),
        tenant_id: JsonValue | None = None,
        client: httpx.AsyncClient | None = None,
        audit_collector: AuditCollector | None = None,
        operation_observer: OperationObserver | None = None,
        application_success_policy: JsonApplicationSuccessPolicy | None = None,
    ) -> GenericRuntime:
        loaded = load_pack(pack_path)
        project_value = loaded.ir.get("project")
        try:
            project = _load_project_document(project_value)
        except ValidationError:
            raise RuntimeConfigurationError("compiled project contract is invalid") from None
        principal_context = _stdio_principal_context(
            project,
            environment=environment,
            granted_scopes=granted_scopes,
            tenant_id=tenant_id,
        )
        auth_strategy = _auth_strategy_from_project(project, environment=environment)
        declared_success = project.provider.application_success
        effective_success_policy = application_success_policy or (
            JsonApplicationSuccessPolicy.from_config(declared_success)
            if declared_success is not None
            else None
        )
        provider = HttpProvider(
            base_url_ref=project.provider.base_url_ref,
            auth_strategy=auth_strategy,
            environment=environment,
            application_success_policy=effective_success_policy,
            client=client,
        )
        runtime = cls(
            loaded.ir,
            provider=provider,
            principal_context=principal_context,
            loaded_pack=loaded,
            audit_collector=audit_collector,
            operation_observer=operation_observer,
        )
        runtime._owned_auth_strategy = auth_strategy
        return runtime

    def _load_project(self) -> ProjectV2:
        return _load_project_document(self.ir.get("project"))

    def _capability(self, capability_id: str) -> ReadCapabilityV2:
        compiled = self._compiled_capability(capability_id)
        definition = compiled.get("definition")
        try:
            if isinstance(definition, Mapping) and definition.get("kind") == "action":
                action = ActionCapabilityV2.model_validate(definition)
                raise RuntimeConfigurationError(
                    "Action capability requires the Action lifecycle",
                    details={
                        "capability_id": action.id,
                        "reason": "action_lifecycle_required",
                    },
                )
            return ReadCapabilityV2.model_validate(definition)
        except RuntimeConfigurationError:
            raise
        except ValidationError:
            raise RuntimeConfigurationError(
                "compiled capability is invalid",
                details={"capability_id": capability_id},
            ) from None

    def _compiled_capability(self, capability_id: str) -> Mapping[str, Any]:
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
        return compiled

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
            compiled = capabilities.get(capability_id)
            definition = compiled.get("definition") if isinstance(compiled, Mapping) else None
            if isinstance(definition, Mapping) and definition.get("kind") == "action":
                # Action capabilities are projected only by the explicit lifecycle
                # runtime.  Keeping them out of the read surface prevents a mixed
                # Pack from breaking or accidentally enabling mutations.
                continue
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
        audit_span = _start_audit_span(
            self._audit_collector,
            project_id=self.project.project.id,
            capability_id=capability_id,
            principal_context=principal_context,
        )
        if self._closed:
            closed_outcome: _RuntimeOutcome = _RuntimeFailure(
                error_type=RuntimeConfigurationError,
                code=RuntimeConfigurationError.code,
                message="runtime is closed",
                details={"reason": "runtime_closed"},
            )
            if _finish_audit_span(audit_span, "internal"):
                return _RUNTIME_CANCELLED
            return closed_outcome
        try:
            value = await self._execute_call(
                capability_id,
                arguments,
                principal_context,
                audit_observer=audit_span,
            )
        except asyncio.CancelledError:
            _finish_audit_span(audit_span, "cancelled")
            return _RUNTIME_CANCELLED
        except AccRuntimeError as error:
            if _finish_audit_span(audit_span, _audit_category(error)):
                return _RUNTIME_CANCELLED
            return _runtime_failure(error)
        except Exception:
            if _finish_audit_span(audit_span, "internal"):
                return _RUNTIME_CANCELLED
            return _RuntimeFailure(
                error_type=RuntimeConfigurationError,
                code=RuntimeConfigurationError.code,
                message="runtime execution failed",
                details={"reason": "runtime_internal_failure"},
            )
        if _finish_audit_span(audit_span, "success"):
            return _RUNTIME_CANCELLED
        return _RuntimeSuccess(value)

    async def _execute_call(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
        *,
        audit_observer: OperationObserver | None = None,
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
        effective_arguments = _apply_public_defaults(
            arguments,
            self._public_defaults.get(capability_id, ()),
        )
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
            audit_observer=audit_observer,
            operation_observer=self._operation_observer,
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
            cast(JsonValue, effective_arguments),
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
        compiled = self._compiled_capability(capability_id)
        quality = compiled.get("quality")
        if isinstance(quality, Mapping):
            limit = quality.get("max_output_bytes")
            if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise RuntimeConfigurationError(
                    "compiled output budget is invalid",
                    details={"capability_id": capability_id, "reason": "output_budget_invalid"},
                )
            try:
                actual_bytes = len(canonical_json_bytes(filtered))
            except (TypeError, ValueError):
                raise RuntimeConfigurationError(
                    "capability output could not be encoded",
                    details={"capability_id": capability_id, "reason": "output_encoding_invalid"},
                ) from None
            if actual_bytes > limit:
                raise ExecutionError(
                    "ACC_RUNTIME_CAPABILITY_OUTPUT_TOO_LARGE",
                    "capability output exceeded its declared budget",
                    details={
                        "capability_id": capability_id,
                        "actual_bytes": actual_bytes,
                        "limit_bytes": limit,
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
        if exc_value is not None:
            # The body exception is already the caller's chosen propagation
            # boundary. Cleanup has run, but a secondary close failure or
            # cancellation must not replace it or acquire it as __context__.
            del outcome
            del traceback
            del exc_value
            del exc_type
            del runtime
            del self
            return
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


def _load_project_document(value: object) -> ProjectV2:
    try:
        return ProjectV2.model_validate(value)
    except ValidationError:
        raise RuntimeConfigurationError("compiled project contract is invalid") from None


_INTERACTION_CONTRACT_FIELDS = frozenset(
    {
        "action_lifecycle",
        "capability_id",
        "conditions",
        "defaults",
        "inherited_interactions",
        "interaction_ids",
        "omitted_interaction_ids",
        "option_sources",
        "overridden_interaction_ids",
        "public_input_bindings",
        "related_data",
        "required_scenarios",
        "result_consumption",
        "sidecar_sha256",
    }
)
_DECLARED_INVENTORY_FIELDS = frozenset(
    {
        "evidence_sha256",
        "dimension_dispositions",
        "interaction_ids",
        "scope_mode",
        "sidecar_sha256",
        "status",
        "summary",
        "surface_ids",
        "surface_contexts",
    }
)
_INVENTORY_SUMMARY_FIELDS = frozenset({"interactions", "surfaces", "unresolved"})
_NON_ASSERTING_REF_SIBLINGS = frozenset(
    {
        "$anchor",
        "$comment",
        "$defs",
        "$id",
        "$schema",
        "default",
        "deprecated",
        "description",
        "examples",
        "readOnly",
        "title",
        "writeOnly",
    }
)


def _canonical_interaction_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_interactions(
    ir: Mapping[str, Any],
) -> tuple[
    dict[str, JsonValue],
    dict[str, tuple[tuple[tuple[str, ...], JsonValue], ...]],
]:
    """Verify the compiler-owned interaction envelope and safe default subset."""

    try:
        raw = ir.get("interactions")
        root_digest = ir.get("interaction_sha256")
        if not isinstance(raw, Mapping) or set(raw) != {
            "schema_version",
            "digest",
            "inventory",
            "contracts",
            "dependencies",
        }:
            raise ValueError
        if raw.get("schema_version") != "2":
            raise ValueError
        digest = raw.get("digest")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or root_digest != digest
        ):
            raise ValueError
        payload = {key: value for key, value in raw.items() if key != "digest"}
        if _canonical_interaction_digest(payload) != digest:
            raise ValueError
        _validate_interaction_inventory(raw.get("inventory"))
        dependencies = raw.get("dependencies")
        if not isinstance(dependencies, list) or any(
            not isinstance(edge, list)
            or len(edge) != 2
            or any(not isinstance(item, str) or not item for item in edge)
            for edge in dependencies
        ):
            raise ValueError
        capabilities = ir.get("capabilities")
        if not isinstance(capabilities, Mapping) or any(
            not isinstance(capability_id, str) or not capability_id
            for capability_id in capabilities
        ):
            raise ValueError
        known_capability_ids = frozenset(capabilities)
        dependency_edges = [tuple(edge) for edge in dependencies]
        if (
            dependency_edges != sorted(dependency_edges)
            or len(dependency_edges) != len(set(dependency_edges))
            or any(
                source not in known_capability_ids or target not in known_capability_ids
                for source, target in dependency_edges
            )
        ):
            raise ValueError
        contracts = raw.get("contracts")
        if not isinstance(contracts, Mapping):
            raise ValueError
        public_defaults: dict[str, tuple[tuple[tuple[str, ...], JsonValue], ...]] = {}
        for capability_id, contract in contracts.items():
            if (
                not isinstance(capability_id, str)
                or not capability_id
                or not isinstance(contract, Mapping)
                or set(contract) != _INTERACTION_CONTRACT_FIELDS
                or contract.get("capability_id") != capability_id
                or capability_id not in known_capability_ids
            ):
                raise ValueError
            defaults = contract.get("defaults", [])
            if not isinstance(defaults, list):
                raise ValueError
            parsed: list[tuple[tuple[str, ...], JsonValue]] = []
            seen_targets: set[tuple[str, ...]] = set()
            for default in defaults:
                if not isinstance(default, Mapping) or set(default) != {
                    "id",
                    "source_kind",
                    "target_pointer",
                    "value",
                }:
                    raise ValueError
                if (
                    not isinstance(default.get("id"), str)
                    or not default.get("id")
                    or default.get("source_kind") != "literal"
                    or not isinstance(default.get("target_pointer"), str)
                ):
                    raise ValueError
                tokens = _json_pointer_tokens(cast(str, default["target_pointer"]))
                if not tokens or tokens in seen_targets:
                    raise ValueError
                _validate_public_default_target(ir, capability_id, tokens)
                value = cast(JsonValue, copy.deepcopy(default.get("value")))
                _canonical_interaction_digest({"value": value})
                parsed.append((tokens, value))
                seen_targets.add(tokens)
            public_defaults[capability_id] = tuple(parsed)
        normalized = json.loads(
            json.dumps(
                dict(raw),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        if not isinstance(normalized, dict):
            raise ValueError
        return cast(dict[str, JsonValue], normalized), public_defaults
    except (TypeError, ValueError, OverflowError):
        raise RuntimeConfigurationError(
            "compiled interaction manifest is invalid",
            details={"reason": "interaction_manifest_invalid"},
        ) from None


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_sorted_unique_ids(value: object) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(value)
        or len(value) != len(set(value))
    ):
        raise ValueError
    return value


def _validate_interaction_inventory(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError
    status = value.get("status")
    if status == "not_declared":
        if set(value) != {"status"}:
            raise ValueError
        return
    if status != "declared" or set(value) != _DECLARED_INVENTORY_FIELDS:
        raise ValueError
    if (
        not _is_sha256(value.get("evidence_sha256"))
        or not _is_sha256(value.get("sidecar_sha256"))
        or value.get("scope_mode") not in {"none", "discovered", "complete"}
    ):
        raise ValueError
    interaction_ids = _validate_sorted_unique_ids(value.get("interaction_ids"))
    surface_ids = _validate_sorted_unique_ids(value.get("surface_ids"))
    dispositions = value.get("dimension_dispositions")
    if not isinstance(dispositions, Mapping) or set(dispositions) != set(interaction_ids):
        raise ValueError
    valid_dimensions = {
        "conditions",
        "defaults",
        "input_bindings",
        "option_sources",
        "related_data",
        "result_consumption",
        "states",
    }
    for interaction_id in interaction_ids:
        interaction_dispositions = dispositions.get(interaction_id)
        if not isinstance(interaction_dispositions, Mapping) or any(
            dimension not in valid_dimensions
            or applicability not in {"applicable", "not_applicable"}
            for dimension, applicability in interaction_dispositions.items()
        ):
            raise ValueError
    surface_contexts = value.get("surface_contexts")
    if not isinstance(surface_contexts, Mapping) or set(surface_contexts) != set(surface_ids):
        raise ValueError
    for surface_id in surface_ids:
        context = surface_contexts.get(surface_id)
        if (
            not isinstance(context, Mapping)
            or set(context) != {"kind", "route_or_entry", "usage_context"}
            or not isinstance(context.get("kind"), str)
            or not context.get("kind")
            or not isinstance(context.get("route_or_entry"), str)
            or not context.get("route_or_entry")
            or (
                context.get("usage_context") is not None
                and (
                    not isinstance(context.get("usage_context"), str)
                    or not context.get("usage_context")
                )
            )
        ):
            raise ValueError
    summary = value.get("summary")
    if (
        not isinstance(summary, Mapping)
        or set(summary) != _INVENTORY_SUMMARY_FIELDS
        or any(
            isinstance(summary.get(field), bool)
            or not isinstance(summary.get(field), int)
            or cast(int, summary[field]) < 0
            for field in _INVENTORY_SUMMARY_FIELDS
        )
        or summary.get("interactions") != len(interaction_ids)
        or summary.get("surfaces") != len(surface_ids)
        or (
            value.get("scope_mode") == "none"
            and (interaction_ids or surface_ids or summary.get("unresolved") != 0)
        )
    ):
        raise ValueError


def _json_pointer_tokens(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise ValueError
    tokens: list[str] = []
    for raw_token in pointer[1:].split("/"):
        index = 0
        while index < len(raw_token):
            if raw_token[index] == "~" and (
                index + 1 >= len(raw_token) or raw_token[index + 1] not in {"0", "1"}
            ):
                raise ValueError
            index += 2 if raw_token[index] == "~" else 1
        tokens.append(raw_token.replace("~1", "/").replace("~0", "~"))
    if any(not token for token in tokens):
        raise ValueError
    return tuple(tokens)


def _validate_public_default_target(
    ir: Mapping[str, Any], capability_id: str, tokens: tuple[str, ...]
) -> None:
    capabilities = ir.get("capabilities")
    compiled = capabilities.get(capability_id) if isinstance(capabilities, Mapping) else None
    definition = compiled.get("definition") if isinstance(compiled, Mapping) else None
    input_schema = definition.get("input_schema") if isinstance(definition, Mapping) else None
    if not isinstance(input_schema, Mapping):
        raise ValueError
    root = input_schema
    current: Mapping[str, object] = root
    for token in tokens:
        current = _resolve_local_schema_reference(root, current)
        if current.get("type") == "array" or "items" in current:
            raise ValueError
        properties = current.get("properties")
        child = properties.get(token) if isinstance(properties, Mapping) else None
        if not isinstance(child, Mapping):
            raise ValueError
        current = cast(Mapping[str, object], child)
    _resolve_local_schema_reference(root, current)


def _resolve_local_schema_reference(
    root: Mapping[str, object], schema: Mapping[str, object]
) -> Mapping[str, object]:
    current = schema
    visited: set[str] = set()
    for _ in range(64):
        reference = current.get("$ref")
        if reference is None:
            return current
        if (
            not isinstance(reference, str)
            or not reference.startswith("#/")
            or reference in visited
            or set(current) - {"$ref"} - _NON_ASSERTING_REF_SIBLINGS
        ):
            raise ValueError
        visited.add(reference)
        target: object = root
        for token in _json_pointer_tokens(reference[1:]):
            if not isinstance(target, Mapping) or token not in target:
                raise ValueError
            target = target[token]
        if not isinstance(target, Mapping):
            raise ValueError
        current = cast(Mapping[str, object], target)
    raise ValueError


def _apply_public_defaults(
    arguments: Mapping[str, JsonValue],
    defaults: tuple[tuple[tuple[str, ...], JsonValue], ...],
) -> dict[str, JsonValue]:
    enriched = copy.deepcopy(dict(arguments))
    for tokens, value in defaults:
        current: dict[str, JsonValue] = enriched
        for token in tokens[:-1]:
            existing = current.get(token)
            if token not in current:
                child: dict[str, JsonValue] = {}
                current[token] = child
                current = child
            elif isinstance(existing, dict):
                current = existing
            else:
                current = {}
                break
        else:
            if tokens[-1] not in current:
                current[tokens[-1]] = copy.deepcopy(value)
    return enriched


def _load_operation(value: Mapping[str, object]) -> ReadOperationV2:
    try:
        if value.get("kind") == "action":
            action = ActionOperationV2.model_validate(value)
            raise RuntimeConfigurationError(
                "Action operation requires the Action lifecycle",
                details={
                    "operation_id": action.id,
                    "reason": "action_lifecycle_required",
                },
            )
        return ReadOperationV2.model_validate(value)
    except RuntimeConfigurationError:
        raise
    except ValidationError:
        raise RuntimeConfigurationError(
            "compiled operation is invalid",
            details={"operation_id": str(value.get("id", "unknown"))},
        ) from None


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


def _tenant_id(context: PrincipalContext) -> JsonValue | None:
    try:
        return resolve_context_binding(
            context,
            "tenant_context.tenant_id",
            {"tenant_context.tenant_id"},
        )
    except ValueError:
        return None


def _stdio_principal_context(
    project: ProjectV2,
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
    project: ProjectV2,
    *,
    environment: Mapping[str, str] | None,
) -> HttpAuthStrategy | None:
    auth = project.provider.auth
    if auth is None:
        return NoAuthStrategy()
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
    project: ProjectV2,
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


def _start_audit_span(
    collector: AuditCollector | None,
    *,
    project_id: str,
    capability_id: str,
    principal_context: object,
) -> AuditSpan | None:
    if collector is None or not isinstance(principal_context, PrincipalContext):
        return None
    try:
        return collector.start_capability(
            project_id=project_id,
            capability_id=capability_id,
            principal_id=principal_context.principal_id,
            session_id=principal_context.gateway_session_id,
        )
    except Exception:
        return None


def _finish_audit_span(
    span: AuditSpan | None,
    category: AuditResultCategory,
) -> bool:
    if span is None:
        return False
    try:
        span.finish(category)
    except asyncio.CancelledError:
        return True
    except Exception:
        return False
    return False


_AUDIT_CODE_CATEGORIES: dict[str, AuditResultCategory] = {
    "ACC_GATEWAY_REAUTH_REQUIRED": "reauth",
    "ACC_GATEWAY_SESSION_CAPACITY_REACHED": "internal",
    "ACC_GATEWAY_SESSION_EXPIRED": "reauth",
    "ACC_GATEWAY_SESSION_INVALID": "reauth",
    "ACC_RUNTIME_ASSERTION_FAILED": "internal",
    "ACC_RUNTIME_AUTH_CONFIGURATION_INVALID": "internal",
    "ACC_RUNTIME_AUTH_LOGIN_FAILED": "authentication_failed",
    "ACC_RUNTIME_AUTH_RESPONSE_INVALID": "authentication_failed",
    "ACC_RUNTIME_AUTH_SECRET_MISSING": "internal",
    "ACC_RUNTIME_AUTH_UNAUTHORIZED": "reauth",
    "ACC_RUNTIME_BOUND_EXCEEDED": "invalid_request",
    "ACC_RUNTIME_CAPABILITY_NOT_FOUND": "invalid_request",
    "ACC_RUNTIME_CONFIGURATION_INVALID": "internal",
    "ACC_RUNTIME_DEFINITION_NOT_FOUND": "internal",
    "ACC_RUNTIME_ERROR": "internal",
    "ACC_RUNTIME_FINAL_EMIT_REQUIRED": "internal",
    "ACC_RUNTIME_HTTP_BASE_URL_INVALID": "internal",
    "ACC_RUNTIME_HTTP_FORBIDDEN": "upstream_denied",
    "ACC_RUNTIME_HTTP_INVALID_JSON": "upstream_error",
    "ACC_RUNTIME_HTTP_METHOD_DENIED": "internal",
    "ACC_RUNTIME_HTTP_NOT_FOUND": "upstream_denied",
    "ACC_RUNTIME_HTTP_OPERATION_INVALID": "internal",
    "ACC_RUNTIME_HTTP_REQUEST_FAILED": "upstream_error",
    "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE": "upstream_error",
    "ACC_RUNTIME_HTTP_TIMEOUT": "upstream_error",
    "ACC_RUNTIME_HTTP_UPSTREAM_ERROR": "upstream_error",
    "ACC_RUNTIME_INPUT_INVALID": "invalid_request",
    "ACC_RUNTIME_INPUT_SCHEMA_INVALID": "invalid_request",
    "ACC_RUNTIME_INTERNAL": "internal",
    "ACC_RUNTIME_IR_INVALID": "internal",
    "ACC_RUNTIME_IR_MISSING": "internal",
    "ACC_RUNTIME_IR_TOO_LARGE": "internal",
    "ACC_RUNTIME_OPERATION_FAILED": "internal",
    "ACC_RUNTIME_OPERATION_INPUT_INVALID": "invalid_request",
    "ACC_RUNTIME_OPERATION_NOT_FOUND": "internal",
    "ACC_RUNTIME_OPERATION_OUTPUT_INVALID": "upstream_error",
    "ACC_RUNTIME_OUTPUT_INVALID": "internal",
    "ACC_RUNTIME_OUTPUT_SCHEMA_INVALID": "upstream_error",
    "ACC_RUNTIME_PACK_VERIFICATION_FAILED": "internal",
    "ACC_RUNTIME_POLICY_OUTPUT_INVALID": "internal",
    "ACC_RUNTIME_POLICY_SCOPE_DENIED": "policy_denied",
    "ACC_RUNTIME_POLICY_TENANT_DENIED": "policy_denied",
    "ACC_RUNTIME_REFERENCE_INVALID": "internal",
    "ACC_RUNTIME_REFERENCE_UNAVAILABLE": "internal",
    "ACC_RUNTIME_SECRET_NOT_FOUND": "internal",
    "ACC_RUNTIME_SECRET_REF_INVALID": "internal",
    "ACC_RUNTIME_STEP_INVALID": "internal",
    "ACC_RUNTIME_VALUE_TYPE_INVALID": "invalid_request",
}


def _audit_category(error: AccRuntimeError) -> AuditResultCategory:
    return _AUDIT_CODE_CATEGORIES.get(str(error.code), "internal")


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
