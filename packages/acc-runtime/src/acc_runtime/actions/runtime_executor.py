"""Generic workflow adapter for compiler-proven Action capabilities."""

from __future__ import annotations

import copy
import hashlib
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast, runtime_checkable

from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.compiler.actions import (
    ActionProof,
    prove_action_capability,
    verify_action_semantics_attestation,
)
from acc_core.contracts import ActionSemantics
from acc_core.models import Policy, WorkflowStep
from acc_core.models.actions import (
    BodyTokenSourceV2,
    ResponseHeaderTokenSourceV2,
    ServerSerializedStatePredicateV2,
    StateIdempotencyV2,
    StatusQueryOutcomeResolutionV2,
    StatusQueryRequestBindingV2,
)
from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionOperationV2,
    OperationV2,
    ProjectV2,
    ReadOperationV2,
)
from acc_runtime.actions.coordinator import (
    ActionCommitExecution,
    ActionPreviewExecution,
    CompiledActionDefinition,
)
from acc_runtime.actions.errors import ActionStateConflictError
from acc_runtime.actions.models import canonical_json_bytes
from acc_runtime.actions.resource_lock import ActionResourceLock
from acc_runtime.context import PrincipalContext, resolve_context_binding
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.execution import ExecutionError, WorkflowExecutor
from acc_runtime.policies import PolicyEnforcer


class ActionRuntimeConfigurationError(AccRuntimeError):
    """A stable fail-closed error for malformed or unproven Action IR."""

    code = "ACC_RUNTIME_ACTION_CONFIGURATION_INVALID"
    status = 500


@dataclass(frozen=True, slots=True)
class ActionReadResult:
    """One read result plus transport metadata usable only for token capture."""

    value: JsonValue = field(repr=False)
    response_headers: Mapping[str, str] = field(default_factory=dict, repr=False)


@runtime_checkable
class ActionOperationProvider(Protocol):
    """Provider seam that keeps mutation controls outside workflow arguments."""

    async def call_read(
        self,
        operation: ReadOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionReadResult: ...

    async def call_action(
        self,
        operation: ActionOperationV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
        *,
        idempotency_key: SecretValue,
        concurrency_token: JsonValue,
    ) -> JsonValue: ...


@dataclass(frozen=True, slots=True)
class _LoadedAction:
    capability: ActionCapabilityV2
    operations: Mapping[str, OperationV2]
    proof: ActionProof
    mutation_operation_ids: tuple[str, ...]
    policy: Policy
    project: ProjectV2
    semantics: Mapping[str, ActionSemantics]


class _ActionOperationCaller:
    def __init__(
        self,
        *,
        provider: ActionOperationProvider,
        operations: Mapping[str, OperationV2],
        policy: Policy,
        principal_context: PrincipalContext,
        allowed_context_bindings: Sequence[str],
        phase: str,
        idempotency_key: SecretValue | None = None,
        concurrency_token: JsonValue = None,
    ) -> None:
        self._provider = provider
        self._operations = operations
        self._policy = policy
        self._principal_context = principal_context
        self._allowed_context_bindings = frozenset(allowed_context_bindings)
        self._phase = phase
        self._idempotency_key = idempotency_key
        self._concurrency_token = copy.deepcopy(concurrency_token)
        self._enforcer = PolicyEnforcer()
        self.response_headers: list[dict[str, str]] = []
        self.action_operation_ids: list[str] = []

    async def call(
        self,
        operation: Mapping[str, JsonValue],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        operation_id = operation.get("id")
        if not isinstance(operation_id, str):
            raise ActionRuntimeConfigurationError("Compiled Action Operation is invalid")
        definition = self._operations.get(operation_id)
        if definition is None or definition.model_dump(mode="json", by_alias=True) != dict(
            operation
        ):
            raise ActionRuntimeConfigurationError("Compiled Action Operation is invalid")

        enriched = copy.deepcopy(dict(arguments))
        for target, reference in definition.context_bindings.items():
            if target in enriched:
                raise ActionRuntimeConfigurationError(
                    "Workflow arguments cannot override trusted context"
                )
            try:
                enriched[target] = resolve_context_binding(
                    self._principal_context,
                    reference,
                    self._allowed_context_bindings,
                )
            except (TypeError, ValueError):
                raise ActionRuntimeConfigurationError(
                    "Compiled context binding cannot be resolved"
                ) from None

        tenant_id = _tenant_id(self._principal_context)
        if self._policy.tenant_mode == "required":
            tenant_field = self._policy.tenant_field
            assert tenant_field is not None
            _inject_context_value(enriched, tenant_field, tenant_id)

        effective_policy = self._policy.model_copy(
            update={
                "required_scopes": sorted(
                    set(self._policy.required_scopes) | set(definition.http.scopes)
                )
            }
        )
        if next(Draft202012Validator(definition.input_schema).iter_errors(enriched), None):
            raise ExecutionError(
                "ACC_RUNTIME_OPERATION_INPUT_INVALID",
                "Trusted Action arguments do not match the Operation schema.",
                details={"operation_id": definition.id},
            )
        self._enforcer.authorize(
            effective_policy,
            granted_scopes=self._principal_context.effective_scopes,
            arguments=enriched,
            tenant_id=tenant_id,
        )

        if isinstance(definition, ReadOperationV2):
            result = await self._provider.call_read(
                definition,
                cast(Mapping[str, JsonValue], copy.deepcopy(enriched)),
                self._principal_context,
            )
            if not isinstance(result, ActionReadResult):
                raise ActionRuntimeConfigurationError("Action read provider result is invalid")
            self.response_headers.append(_validated_headers(result.response_headers))
            return copy.deepcopy(result.value)

        if self._phase != "commit" or self._idempotency_key is None:
            raise ActionRuntimeConfigurationError(
                "A mutation cannot execute outside the trusted commit phase"
            )
        if (
            definition.http.safety.concurrency.mode == "required"
            and self._concurrency_token is None
        ):
            raise ActionRuntimeConfigurationError(
                "A required optimistic concurrency token is unavailable"
            )
        self.action_operation_ids.append(definition.id)
        return await self._provider.call_action(
            definition,
            cast(Mapping[str, JsonValue], copy.deepcopy(enriched)),
            self._principal_context,
            idempotency_key=self._idempotency_key,
            concurrency_token=copy.deepcopy(self._concurrency_token),
        )


class RuntimeActionWorkflowExecutor:
    """Execute compiled Action workflows over a transport-neutral provider."""

    def __init__(
        self,
        compiled_ir: Mapping[str, Any],
        *,
        provider: ActionOperationProvider,
        action_sandbox_mode: Literal["disabled", "local_development"] = "disabled",
        resource_lock: ActionResourceLock | None = None,
    ) -> None:
        if not isinstance(compiled_ir, Mapping):
            raise TypeError("compiled_ir must be a mapping")
        if not isinstance(provider, ActionOperationProvider):
            raise TypeError("provider must implement ActionOperationProvider")
        if action_sandbox_mode not in {"disabled", "local_development"}:
            raise ValueError("action_sandbox_mode is invalid")
        if resource_lock is not None and not isinstance(resource_lock, ActionResourceLock):
            raise TypeError("resource_lock must implement ActionResourceLock")
        self._ir = copy.deepcopy(dict(compiled_ir))
        self._provider = provider
        self._action_sandbox_mode = action_sandbox_mode
        self._resource_lock = resource_lock

    async def preview(
        self,
        capability: ActionCapabilityV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionPreviewExecution:
        loaded = self._load(capability, principal_context)
        caller = _ActionOperationCaller(
            provider=self._provider,
            operations=loaded.operations,
            policy=loaded.policy,
            principal_context=principal_context,
            allowed_context_bindings=loaded.project.provider.context_binding_allowlist,
            phase="preview",
        )
        raw_preview = await WorkflowExecutor(
            caller,
            validate_output=False,
            validate_operation_input=False,
        ).execute(
            _workflow_ir(loaded, loaded.capability.preview_workflow),
            loaded.capability.id,
            cast(JsonValue, copy.deepcopy(dict(arguments))),
        )
        idempotent_terminal = _validate_server_serialized_preview(loaded, raw_preview)
        token = _capture_concurrency_token(loaded, raw_preview, caller.response_headers)
        public_preview = PolicyEnforcer().filter_output(loaded.policy, raw_preview)
        _validate_local_development_preview(loaded, public_preview)
        return ActionPreviewExecution(
            value=public_preview,
            concurrency_token=token,
            concurrency_token_required=_requires_optimistic_token(loaded),
            idempotent_terminal=idempotent_terminal,
            idempotent_result=public_preview if idempotent_terminal else None,
        )

    async def commit(
        self,
        capability: ActionCapabilityV2,
        execution: ActionCommitExecution,
        principal_context: PrincipalContext,
    ) -> JsonValue:
        loaded = self._load(capability, principal_context)
        if not isinstance(execution, ActionCommitExecution):
            raise TypeError("execution must be ActionCommitExecution")
        guard = loaded.capability.action.local_development_state_guard
        if guard is not None:
            if not isinstance(execution.input_value, Mapping) or self._resource_lock is None:
                raise ActionRuntimeConfigurationError(
                    "Local development Action state guard is not safely configured"
                )
            found, resource_key = _resolve_json_pointer(
                execution.input_value,
                guard.resource_key_pointer,
            )
            if (
                not found
                or not isinstance(resource_key, (str, int))
                or isinstance(resource_key, bool)
            ):
                raise ActionRuntimeConfigurationError(
                    "Local development Action resource key is invalid"
                )
            lock_digest = hashlib.sha256(canonical_json_bytes(resource_key)).hexdigest()
            lock_key = f"{loaded.capability.id}:sha256:{lock_digest}"
            async with self._resource_lock.hold(lock_key):
                # The input comes exclusively from the sealed prepared record;
                # no commit-time Agent arguments participate in this fresh read.
                fresh = await self.preview(
                    loaded.capability,
                    cast(Mapping[str, JsonValue], copy.deepcopy(execution.input_value)),
                    principal_context,
                )
                classification = _validate_local_development_recheck(
                    loaded,
                    execution.preview_value,
                    fresh.value,
                )
                if classification == "terminal":
                    _validate_action_output(loaded, fresh.value)
                    return copy.deepcopy(fresh.value)
                refreshed = ActionCommitExecution(
                    input_value=copy.deepcopy(execution.input_value),
                    preview_value=copy.deepcopy(fresh.value),
                    concurrency_token=copy.deepcopy(execution.concurrency_token),
                    idempotency_key=execution.idempotency_key,
                )
                return await self._commit_loaded(loaded, refreshed, principal_context)
        return await self._commit_loaded(loaded, execution, principal_context)

    async def _commit_loaded(
        self,
        loaded: _LoadedAction,
        execution: ActionCommitExecution,
        principal_context: PrincipalContext,
    ) -> JsonValue:
        if execution.idempotent_terminal:
            result = copy.deepcopy(execution.idempotent_result)
            if not _is_terminal_result(loaded, result):
                raise ActionRuntimeConfigurationError(
                    "Prepared Action idempotent result is invalid"
                )
            if next(
                Draft202012Validator(loaded.capability.output_schema).iter_errors(result),
                None,
            ):
                raise ActionRuntimeConfigurationError(
                    "Prepared Action idempotent result is invalid"
                )
            return result
        caller = _ActionOperationCaller(
            provider=self._provider,
            operations=loaded.operations,
            policy=loaded.policy,
            principal_context=principal_context,
            allowed_context_bindings=loaded.project.provider.context_binding_allowlist,
            phase="commit",
            idempotency_key=execution.idempotency_key,
            concurrency_token=execution.concurrency_token,
        )
        public_prepared_preview = PolicyEnforcer().filter_output(
            loaded.policy,
            execution.preview_value,
        )
        prepared: JsonValue = {
            "prepared": {
                "input": copy.deepcopy(execution.input_value),
                "preview": copy.deepcopy(execution.preview_value),
            }
        }
        raw_result = await WorkflowExecutor(
            caller,
            validate_output=False,
            validate_operation_input=False,
        ).execute(
            _workflow_ir(
                loaded,
                loaded.capability.commit_workflow,
                prepared=True,
            ),
            loaded.capability.id,
            prepared,
        )
        if len(caller.action_operation_ids) != 1:
            raise ActionRuntimeConfigurationError("Compiled Action mutation execution is invalid")
        semantics = loaded.semantics.get(caller.action_operation_ids[0])
        if semantics is not None and isinstance(
            semantics.outcome_resolution, StatusQueryOutcomeResolutionV2
        ):
            raw_result = await _resolve_status_query(
                loaded,
                semantics,
                execution.input_value,
                public_prepared_preview,
                principal_context,
                self._provider,
            )
        public_result = PolicyEnforcer().filter_output(loaded.policy, raw_result)
        _validate_action_output(loaded, public_result)
        return public_result

    def _load(
        self,
        capability: ActionCapabilityV2,
        principal_context: PrincipalContext,
    ) -> _LoadedAction:
        if not isinstance(capability, ActionCapabilityV2) or not isinstance(
            principal_context, PrincipalContext
        ):
            raise TypeError("Action execution requires trusted typed inputs")
        loaded = self._load_compiled(capability.id)
        if (
            loaded.capability != capability
            or principal_context.target_system_id != loaded.project.project.id
        ):
            raise ActionRuntimeConfigurationError("Compiled Action IR failed runtime validation")
        return loaded

    def verified_definition(self, capability_id: str) -> CompiledActionDefinition:
        """Return the Action definition only after complete compiled-IR attestation."""

        if not isinstance(capability_id, str) or not capability_id:
            raise TypeError("capability_id must be a nonempty string")
        loaded = self._load_compiled(capability_id)
        return CompiledActionDefinition(capability=loaded.capability, proof=loaded.proof)

    def _load_compiled(self, capability_id: str) -> _LoadedAction:
        try:
            if self._ir.get("ir_version") != "2":
                raise ValueError
            project = ProjectV2.model_validate(self._ir.get("project"))
            raw_operations = _mapping(self._ir.get("operations"))
            operations: dict[str, OperationV2] = {}
            for operation_id, raw_operation in raw_operations.items():
                if not isinstance(operation_id, str) or not isinstance(raw_operation, Mapping):
                    raise ValueError
                if raw_operation.get("kind") == "read":
                    operation: OperationV2 = ReadOperationV2.model_validate(raw_operation)
                elif raw_operation.get("kind") == "action":
                    operation = ActionOperationV2.model_validate(raw_operation)
                else:
                    raise ValueError
                if operation.id != operation_id:
                    raise ValueError
                operations[operation_id] = operation

            capabilities = _mapping(self._ir.get("capabilities"))
            compiled = _mapping(capabilities.get(capability_id))
            stored = ActionCapabilityV2.model_validate(compiled.get("definition"))
            if stored.id != capability_id:
                raise ValueError
            compiled_proof = _mapping(compiled.get("action_proof"))
            compiled_semantics = _mapping(compiled_proof.get("operation_semantics"))
            semantics_by_operation: dict[str, ActionSemantics] = {}
            for operation_id, attestation in compiled_semantics.items():
                mutation_operation = operations.get(operation_id)
                if not isinstance(mutation_operation, ActionOperationV2) or not (
                    verify_action_semantics_attestation(mutation_operation, attestation)
                ):
                    raise ValueError
                attestation_mapping = _mapping(attestation)
                semantics_by_operation[operation_id] = ActionSemantics.model_validate(
                    attestation_mapping.get("summary")
                )
            policies = _mapping(self._ir.get("policies"))
            policy = Policy.model_validate(policies.get(stored.policy))
            proof = prove_action_capability(
                stored,
                operations,
                action_semantics=semantics_by_operation,
                policy=policy,
            )
            if not proof.ok:
                raise ValueError
            guard = stored.action.local_development_state_guard
            if guard is not None and (
                self._action_sandbox_mode != "local_development"
                or self._resource_lock is None
                or self._resource_lock.development_only is not True
            ):
                raise ValueError
            expected_proof: dict[str, Any] = {
                "approval_required": proof.approval_required,
                "effects": list(proof.effects),
                "maximum_risk": proof.maximum_risk,
                "mutation_operation_ids": list(proof.mutation_operation_ids),
                "required_scopes": list(proof.required_scopes),
            }
            if set(compiled_proof) != {*expected_proof, "operation_semantics"}:
                raise ValueError
            if any(compiled_proof.get(key) != value for key, value in expected_proof.items()):
                raise ValueError
            if set(compiled_semantics) != set(proof.mutation_operation_ids):
                raise ValueError
            dependencies = set(_string_sequence(compiled.get("operation_dependencies")))
            if not set(proof.strategy_operation_ids) <= dependencies:
                raise ValueError
            for operation_id in proof.mutation_operation_ids:
                if operation_id not in semantics_by_operation:
                    raise ValueError
            return _LoadedAction(
                capability=stored,
                operations=operations,
                proof=proof,
                mutation_operation_ids=proof.mutation_operation_ids,
                policy=policy,
                project=project,
                semantics=semantics_by_operation,
            )
        except (TypeError, ValueError, ValidationError):
            raise ActionRuntimeConfigurationError(
                "Compiled Action IR failed runtime validation"
            ) from None


def _validate_local_development_recheck(
    loaded: _LoadedAction,
    prepared_preview: JsonValue,
    fresh_preview: JsonValue,
) -> Literal["allowed", "terminal"]:
    """Validate a local re-read without claiming source-side serialization.

    The surrounding process-local lock only coordinates callers using this ACC
    runtime. An external writer can still race after the read because the source
    exposes no atomic precondition; this mode is therefore development-only.
    """

    guard = loaded.capability.action.local_development_state_guard
    if guard is None:
        raise ActionRuntimeConfigurationError("Local development Action state guard is unavailable")
    prepared_found, prepared_state = _resolve_json_pointer(
        prepared_preview,
        guard.state_pointer,
    )
    fresh_found, fresh_state = _resolve_json_pointer(fresh_preview, guard.state_pointer)
    if not prepared_found or not fresh_found:
        raise ActionStateConflictError("Action state cannot be safely rechecked before commit")
    allowed = {canonical_json_bytes(value) for value in guard.allowed_values}
    terminal = {canonical_json_bytes(value) for value in guard.terminal_values}
    prepared_encoded = canonical_json_bytes(prepared_state)
    fresh_encoded = canonical_json_bytes(fresh_state)
    if prepared_encoded not in allowed | terminal:
        raise ActionStateConflictError(
            "Prepared Action state does not permit the requested mutation"
        )
    if fresh_encoded in terminal:
        return "terminal"
    if fresh_encoded not in allowed or fresh_encoded != prepared_encoded:
        raise ActionStateConflictError("Action state changed after prepare")
    return "allowed"


def _validate_local_development_preview(loaded: _LoadedAction, preview: JsonValue) -> None:
    guard = loaded.capability.action.local_development_state_guard
    if guard is None:
        return
    found, state = _resolve_json_pointer(preview, guard.state_pointer)
    permitted = {
        canonical_json_bytes(value) for value in (*guard.allowed_values, *guard.terminal_values)
    }
    if not found or canonical_json_bytes(state) not in permitted:
        raise ActionStateConflictError(
            "Action preview state does not permit the requested mutation"
        )


def _validate_action_output(loaded: _LoadedAction, value: JsonValue) -> None:
    if next(
        Draft202012Validator(loaded.capability.output_schema).iter_errors(value),
        None,
    ):
        raise ExecutionError(
            "ACC_RUNTIME_OUTPUT_INVALID",
            "Policy-filtered Action output does not match its schema.",
            details={"capability_id": loaded.capability.id},
        )


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ValueError
    return cast(Mapping[str, Any], value)


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError
    return tuple(value)


def _workflow_ir(
    loaded: _LoadedAction,
    workflow: Sequence[WorkflowStep],
    *,
    prepared: bool = False,
) -> dict[str, Any]:
    raw_workflow = [step.model_dump(mode="json", by_alias=True) for step in workflow]
    if prepared:
        raw_workflow = cast(list[dict[str, Any]], _rewrite_prepared(raw_workflow))
        input_schema: dict[str, Any] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "prepared": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "input": loaded.capability.input_schema,
                        "preview": {},
                    },
                    "required": ["input", "preview"],
                }
            },
            "required": ["prepared"],
        }
    else:
        input_schema = cast(dict[str, Any], copy.deepcopy(loaded.capability.input_schema))
    definition = loaded.capability.model_dump(mode="json", by_alias=True)
    definition["input_schema"] = input_schema
    definition["workflow"] = raw_workflow
    return {
        "operations": {
            operation_id: operation.model_dump(mode="json", by_alias=True)
            for operation_id, operation in loaded.operations.items()
        },
        "capabilities": {loaded.capability.id: {"definition": definition}},
    }


def _rewrite_prepared(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("$.prepared."):
        return "$.input.prepared." + value.removeprefix("$.prepared.")
    if isinstance(value, list):
        return [_rewrite_prepared(item) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_prepared(item) for key, item in value.items()}
    return copy.deepcopy(value)


def _requires_optimistic_token(loaded: _LoadedAction) -> bool:
    return any(
        isinstance(loaded.operations[operation_id], ActionOperationV2)
        and loaded.operations[operation_id].http.safety.concurrency.mode == "required"
        for operation_id in loaded.mutation_operation_ids
    )


def _validate_server_serialized_preview(
    loaded: _LoadedAction,
    preview: JsonValue,
) -> bool:
    classifications: list[str] = []
    non_state_operations = 0
    for operation_id in loaded.mutation_operation_ids:
        operation = loaded.operations[operation_id]
        if not isinstance(operation, ActionOperationV2) or not isinstance(
            operation.http.safety.concurrency,
            ServerSerializedStatePredicateV2,
        ):
            non_state_operations += 1
            continue
        strategy = operation.http.safety.concurrency
        found, state = _resolve_json_pointer(preview, strategy.state_pointer)
        allowed = {canonical_json_bytes(value) for value in strategy.allowed_values}
        idempotency = operation.http.safety.idempotency
        if not isinstance(idempotency, StateIdempotencyV2) or not found:
            raise ActionStateConflictError(
                "Action preview state does not permit the requested transition"
            )
        encoded = canonical_json_bytes(state)
        terminal_values = {canonical_json_bytes(value) for value in idempotency.terminal_values}
        if encoded in terminal_values:
            classifications.append("terminal")
        elif encoded in allowed:
            classifications.append("allowed")
        else:
            raise ActionStateConflictError(
                "Action preview state does not permit the requested transition"
            )
    if not classifications:
        return False
    if len(set(classifications)) != 1:
        raise ActionStateConflictError(
            "Action preview state does not permit the requested transition"
        )
    is_terminal = classifications[0] == "terminal"
    if is_terminal and non_state_operations:
        raise ActionStateConflictError(
            "Action preview state does not permit the requested transition"
        )
    return is_terminal


def _is_terminal_result(loaded: _LoadedAction, value: JsonValue) -> bool:
    strategy_count = 0
    for operation_id in loaded.mutation_operation_ids:
        operation = loaded.operations[operation_id]
        if not isinstance(operation, ActionOperationV2) or not isinstance(
            operation.http.safety.idempotency,
            StateIdempotencyV2,
        ):
            continue
        strategy_count += 1
        strategy = operation.http.safety.idempotency
        found, state = _resolve_json_pointer(value, strategy.state_pointer)
        terminal = {canonical_json_bytes(item) for item in strategy.terminal_values}
        if not found or canonical_json_bytes(state) not in terminal:
            return False
    return strategy_count == len(loaded.mutation_operation_ids)


async def _resolve_status_query(
    loaded: _LoadedAction,
    semantics: ActionSemantics,
    input_value: JsonValue,
    preview_value: JsonValue,
    principal_context: PrincipalContext,
    provider: ActionOperationProvider,
) -> JsonValue:
    outcome = semantics.outcome_resolution
    if not isinstance(outcome, StatusQueryOutcomeResolutionV2):
        raise ActionRuntimeConfigurationError("Compiled Action status query is invalid")
    operation = loaded.operations.get(outcome.operation_id)
    if not isinstance(operation, ReadOperationV2) or not isinstance(input_value, Mapping):
        raise ActionRuntimeConfigurationError("Compiled Action status query is invalid")
    required = _string_sequence(operation.input_schema.get("required", []))
    bindings = list(outcome.request_bindings)
    if not bindings:
        bindings = [
            StatusQueryRequestBindingV2(
                target=target,
                source="capability_input",
                source_pointer=f"/{target.replace('~', '~0').replace('/', '~1')}",
            )
            for target in sorted(set(required) - set(operation.context_bindings))
        ]
    arguments: dict[str, JsonValue] = {}
    for binding in bindings:
        if binding.target in operation.context_bindings:
            raise ActionRuntimeConfigurationError("Compiled Action status query is invalid")
        source = input_value if binding.source == "capability_input" else preview_value
        found, resolved = _resolve_json_pointer(source, binding.source_pointer)
        if not found:
            raise ActionRuntimeConfigurationError("Compiled Action status query is invalid")
        arguments[binding.target] = resolved
    caller = _ActionOperationCaller(
        provider=provider,
        operations=loaded.operations,
        policy=loaded.policy,
        principal_context=principal_context,
        allowed_context_bindings=loaded.project.provider.context_binding_allowlist,
        phase="status",
    )
    value = await caller.call(
        operation.model_dump(mode="json", by_alias=True),
        arguments,
    )
    idempotency = semantics.idempotency
    if not isinstance(idempotency, StateIdempotencyV2):
        raise ActionRuntimeConfigurationError("Compiled Action status query is invalid")
    found, state = _resolve_json_pointer(value, idempotency.state_pointer)
    terminal = {canonical_json_bytes(item) for item in idempotency.terminal_values}
    if not found or canonical_json_bytes(state) not in terminal:
        raise ActionStateConflictError("Action commit outcome is unknown")
    return PolicyEnforcer().filter_output(loaded.policy, value)


def _capture_concurrency_token(
    loaded: _LoadedAction,
    preview: JsonValue,
    response_headers: Sequence[Mapping[str, str]],
) -> JsonValue:
    required_sources = {
        repr(operation.http.safety.concurrency.token): operation.http.safety.concurrency.token
        for operation_id in loaded.mutation_operation_ids
        if isinstance((operation := loaded.operations[operation_id]), ActionOperationV2)
        and operation.http.safety.concurrency.mode == "required"
    }
    if not required_sources:
        return None
    if len(required_sources) != 1:
        raise ActionRuntimeConfigurationError(
            "Action mutations require incompatible concurrency token sources"
        )
    source = next(iter(required_sources.values()))
    if isinstance(source, BodyTokenSourceV2):
        return _json_pointer(preview, source.pointer)
    if isinstance(source, ResponseHeaderTokenSourceV2):
        values = {
            value
            for headers in response_headers
            for name, value in headers.items()
            if name.casefold() == source.name.casefold()
        }
        if len(values) > 1:
            raise ActionRuntimeConfigurationError("Preview returned ambiguous concurrency tokens")
        return None if not values else next(iter(values))
    raise ActionRuntimeConfigurationError("Concurrency token source is invalid")


def _json_pointer(value: JsonValue, pointer: str) -> JsonValue:
    found, resolved = _resolve_json_pointer(value, pointer)
    return resolved if found else None


def _resolve_json_pointer(value: JsonValue, pointer: str) -> tuple[bool, JsonValue]:
    current: JsonValue = value
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif (
            isinstance(current, list)
            and token.isdecimal()
            and (token == "0" or not token.startswith("0"))
            and int(token) < len(current)
        ):
            current = current[int(token)]
        else:
            return False, None
    return True, copy.deepcopy(current)


def _validated_headers(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ActionRuntimeConfigurationError("Action read response headers are invalid")
    headers: dict[str, str] = {}
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not isinstance(item, str)
            or not name
            or any(unicodedata.category(character) in {"Cc", "Cs"} for character in name + item)
        ):
            raise ActionRuntimeConfigurationError("Action read response headers are invalid")
        headers[name] = item
    return headers


def _tenant_id(context: PrincipalContext) -> JsonValue:
    try:
        return resolve_context_binding(
            context,
            "tenant_context.tenant_id",
            {"tenant_context.tenant_id"},
        )
    except ValueError:
        return None


def _inject_context_value(
    arguments: dict[str, JsonValue],
    field_name: str,
    value: JsonValue,
) -> None:
    if value is None:
        return
    path = field_name[2:] if field_name.startswith("$.") else field_name
    tokens = tuple(token for token in path.split(".") if token)
    if not tokens:
        raise ActionRuntimeConfigurationError("Policy tenant field is invalid")
    current = arguments
    for token in tokens[:-1]:
        child = current.get(token)
        if child is None:
            created: dict[str, JsonValue] = {}
            current[token] = created
            current = created
        elif isinstance(child, dict):
            current = child
        else:
            raise ActionRuntimeConfigurationError("Policy tenant field conflicts with input")
    current.setdefault(tokens[-1], copy.deepcopy(value))


__all__ = [
    "ActionOperationProvider",
    "ActionReadResult",
    "ActionRuntimeConfigurationError",
    "RuntimeActionWorkflowExecutor",
]
