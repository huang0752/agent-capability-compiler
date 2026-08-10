"""Generic workflow adapter for compiler-proven Action capabilities."""

from __future__ import annotations

import copy
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, cast, runtime_checkable

from jsonschema import Draft202012Validator
from pydantic import JsonValue, ValidationError

from acc_core.compiler.actions import (
    ActionProof,
    prove_action_capability,
    verify_action_semantics_attestation,
)
from acc_core.models import Policy, WorkflowStep
from acc_core.models.actions import BodyTokenSourceV2, ResponseHeaderTokenSourceV2
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
    ) -> None:
        if not isinstance(compiled_ir, Mapping):
            raise TypeError("compiled_ir must be a mapping")
        if not isinstance(provider, ActionOperationProvider):
            raise TypeError("provider must implement ActionOperationProvider")
        self._ir = copy.deepcopy(dict(compiled_ir))
        self._provider = provider

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
        token = _capture_concurrency_token(loaded, raw_preview, caller.response_headers)
        public_preview = PolicyEnforcer().filter_output(loaded.policy, raw_preview)
        return ActionPreviewExecution(
            value=public_preview,
            concurrency_token=token,
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
        public_result = PolicyEnforcer().filter_output(loaded.policy, raw_result)
        if next(
            Draft202012Validator(loaded.capability.output_schema).iter_errors(public_result),
            None,
        ):
            raise ExecutionError(
                "ACC_RUNTIME_OUTPUT_INVALID",
                "Policy-filtered Action output does not match its schema.",
                details={"capability_id": loaded.capability.id},
            )
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
            proof = prove_action_capability(stored, operations)
            if not proof.ok:
                raise ValueError
            compiled_proof = _mapping(compiled.get("action_proof"))
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
            compiled_semantics = _mapping(compiled_proof.get("operation_semantics"))
            if set(compiled_semantics) != set(proof.mutation_operation_ids):
                raise ValueError
            for operation_id in proof.mutation_operation_ids:
                mutation_operation = operations.get(operation_id)
                if not isinstance(mutation_operation, ActionOperationV2) or not (
                    verify_action_semantics_attestation(
                        mutation_operation,
                        compiled_semantics.get(operation_id),
                    )
                ):
                    raise ValueError
            policies = _mapping(self._ir.get("policies"))
            policy = Policy.model_validate(policies.get(stored.policy))
            return _LoadedAction(
                capability=stored,
                operations=operations,
                proof=proof,
                mutation_operation_ids=proof.mutation_operation_ids,
                policy=policy,
                project=project,
            )
        except (TypeError, ValueError, ValidationError):
            raise ActionRuntimeConfigurationError(
                "Compiled Action IR failed runtime validation"
            ) from None


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ValueError
    return cast(Mapping[str, Any], value)


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
    current: JsonValue = value
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return None
    return copy.deepcopy(current)


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
