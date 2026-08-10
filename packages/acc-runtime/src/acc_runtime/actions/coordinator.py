"""Transport-neutral prepare, approve, commit and status orchestration."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, cast, runtime_checkable

from jsonschema import Draft202012Validator
from pydantic import JsonValue

from acc_core.compiler.actions import ActionProof
from acc_core.models.v2 import ActionCapabilityV2
from acc_runtime.actions.approval import ApprovalAuthority, ApprovalBinding
from acc_runtime.actions.audit import (
    ActionAuditLifecycle,
    ActionAuditResultCategory,
    ActionAuditSink,
    ActionAuditSpan,
    ActionAuditUnavailableError,
    start_action_audit_span,
)
from acc_runtime.actions.errors import ActionStateConflictError
from acc_runtime.actions.models import (
    PreparedActionState,
    PreparedActionStatus,
    canonical_json_bytes,
    validate_pack_digest,
)
from acc_runtime.actions.store import ActionStore
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.deployment import DeploymentPolicy
from acc_runtime.errors import RuntimeError as AccRuntimeError

_SEALED_VERSION = "acc.action.prepared.v1"


class ActionCapabilityNotFoundError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_CAPABILITY_NOT_FOUND"
    status = 404


class ActionDeploymentDeniedError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_DEPLOYMENT_DENIED"
    status = 403


class ActionDeploymentConfigurationError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_DEPLOYMENT_INVALID"
    status = 500


class ActionScopeDeniedError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_SCOPE_DENIED"
    status = 403


class ActionPreviewInvalidError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_PREVIEW_INVALID"
    status = 502


class ActionInputInvalidError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_INPUT_INVALID"
    status = 400


@dataclass(frozen=True, slots=True)
class ActionPreviewExecution:
    """Provider-independent preview result and captured concurrency token."""

    value: JsonValue = field(repr=False)
    concurrency_token: JsonValue = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ActionCommitExecution:
    """Trusted commit inputs; none are sourced from a second Agent request."""

    input_value: JsonValue = field(repr=False)
    preview_value: JsonValue = field(repr=False)
    concurrency_token: JsonValue = field(repr=False)
    idempotency_key: SecretValue = field(repr=False)


@runtime_checkable
class ActionWorkflowExecutor(Protocol):
    def verified_definition(self, capability_id: str) -> CompiledActionDefinition: ...

    async def preview(
        self,
        capability: ActionCapabilityV2,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> ActionPreviewExecution: ...

    async def commit(
        self,
        capability: ActionCapabilityV2,
        execution: ActionCommitExecution,
        principal_context: PrincipalContext,
    ) -> JsonValue: ...


@dataclass(frozen=True, slots=True)
class CompiledActionDefinition:
    capability: ActionCapabilityV2
    proof: ActionProof
    proof_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.proof.ok:
            raise ValueError("compiled Action proof contains errors")
        if not self.proof.mutation_operation_ids or not self.proof.effects:
            raise ValueError("compiled Action proof has no mutation inventory")
        if self.proof.maximum_risk is None:
            raise ValueError("compiled Action proof has no derived risk")
        if self.capability.action.approval.mode == "required" and not self.proof.approval_required:
            raise ValueError("compiled Action proof understates approval requirements")
        payload: JsonValue = {
            "capability_id": self.capability.id,
            "approval_required": self.proof.approval_required,
            "effects": list(self.proof.effects),
            "maximum_risk": self.proof.maximum_risk,
            "mutation_operation_ids": list(self.proof.mutation_operation_ids),
            "required_scopes": list(self.proof.required_scopes),
        }
        object.__setattr__(
            self,
            "proof_digest",
            "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class PreparedActionPublic:
    action_handle: SecretValue = field(repr=False)
    capability_id: str
    status: PreparedActionStatus
    preview: JsonValue = field(repr=False)
    approval_required: bool
    expires_at: float


@dataclass(frozen=True, slots=True)
class ActionStatusPublic:
    capability_id: str
    status: PreparedActionStatus
    result: JsonValue = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ActionCommitResult:
    capability_id: str
    status: PreparedActionStatus
    result: JsonValue = field(repr=False)
    replayed: bool


class ActionCoordinator:
    """Coordinate one compiled Pack without exposing approval or commit material."""

    def __init__(
        self,
        *,
        definitions: Mapping[str, CompiledActionDefinition],
        pack_digest: str,
        deployment_policy: DeploymentPolicy,
        store: ActionStore,
        approval_authority: ApprovalAuthority,
        executor: ActionWorkflowExecutor,
        idempotency_key_generator: Callable[[], str],
        action_audit_sink: ActionAuditSink | None = None,
        action_audit_salt: bytes | None = None,
    ) -> None:
        validate_pack_digest(pack_digest)
        if not isinstance(deployment_policy, DeploymentPolicy):
            raise TypeError("deployment_policy must be DeploymentPolicy")
        if not isinstance(store, ActionStore):
            raise TypeError("store must implement ActionStore")
        if not isinstance(approval_authority, ApprovalAuthority):
            raise TypeError("approval_authority must implement ApprovalAuthority")
        if not isinstance(executor, ActionWorkflowExecutor):
            raise TypeError("executor must implement ActionWorkflowExecutor")
        if deployment_policy.require_durable_action_store and not store.is_durable:
            raise ActionDeploymentConfigurationError("Deployment requires a durable Action Store")
        if action_audit_sink is not None and not isinstance(action_audit_sink, ActionAuditSink):
            raise TypeError("action_audit_sink must implement ActionAuditSink")
        if deployment_policy.action_audit_mode == "required" and action_audit_sink is None:
            raise ActionDeploymentConfigurationError("Deployment requires an Action audit sink")
        if action_audit_sink is not None and (
            not isinstance(action_audit_salt, bytes) or len(action_audit_salt) < 16
        ):
            raise ActionDeploymentConfigurationError(
                "Deployment requires an Action audit identity salt"
            )
        checked: dict[str, CompiledActionDefinition] = {}
        for capability_id, definition in definitions.items():
            if not isinstance(capability_id, str) or not isinstance(
                definition, CompiledActionDefinition
            ):
                raise TypeError("definitions must contain compiled Action definitions")
            if capability_id != definition.capability.id:
                raise ValueError("compiled Action definition key does not match capability id")
            try:
                verified = executor.verified_definition(capability_id)
            except Exception:
                raise ActionDeploymentConfigurationError(
                    "Action definition is not bound to verified compiled IR"
                ) from None
            if not isinstance(verified, CompiledActionDefinition) or verified != definition:
                raise ActionDeploymentConfigurationError(
                    "Action definition does not match verified compiled IR"
                )
            checked[capability_id] = verified
        self._definitions = checked
        self._pack_digest = pack_digest
        self._deployment_policy = deployment_policy
        self._store = store
        self._approval_authority = approval_authority
        self._executor = executor
        self._idempotency_key_generator = idempotency_key_generator
        self._action_audit_sink = action_audit_sink
        self._action_audit_salt = action_audit_salt

    async def prepare(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> PreparedActionPublic:
        definition = self._definition(capability_id)
        span = await self._start_audit("prepare", definition.capability.id, principal_context)
        try:
            result = await self._prepare(capability_id, arguments, principal_context)
        except asyncio.CancelledError:
            await _finish_cancelled_audit(span, status=None)
            raise
        except BaseException as error:
            await span.finish(status=None, result_category=_audit_error_category(error))
            raise
        await span.finish(status=result.status, result_category="success")
        return result

    async def _prepare(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> PreparedActionPublic:
        definition = self._definition(capability_id)
        self._authorize(definition, principal_context)
        safe_input = _canonical_copy(dict(arguments), error_type=ActionInputInvalidError)
        if not isinstance(safe_input, dict):  # pragma: no cover - copied from a mapping
            raise AssertionError("Action input must remain an object")
        if next(
            Draft202012Validator(definition.capability.input_schema).iter_errors(safe_input),
            None,
        ):
            raise ActionInputInvalidError("Action input does not match its schema")
        try:
            preview = await self._executor.preview(
                definition.capability,
                safe_input,
                principal_context,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ActionPreviewInvalidError("Action preview failed") from None
        if not isinstance(preview, ActionPreviewExecution):
            raise ActionPreviewInvalidError("Action preview result is invalid")
        safe_preview = _canonical_copy(
            preview.value,
            error_type=ActionPreviewInvalidError,
        )
        safe_token = _canonical_copy(
            preview.concurrency_token,
            error_type=ActionPreviewInvalidError,
        )
        if (
            set(definition.proof.effects) & {"update", "delete", "transition"}
            and safe_token is None
        ):
            raise ActionPreviewInvalidError(
                "Action preview did not capture a required concurrency token"
            )
        idempotency_key = self._new_idempotency_key()
        sealed_preview: JsonValue = {
            "version": _SEALED_VERSION,
            "preview": safe_preview,
            "concurrency_token": safe_token,
            "idempotency_key": idempotency_key.get_secret_value(),
        }
        creation = await self._store.create(
            capability_id=definition.capability.id,
            principal_id=principal_context.principal_id,
            session_id=principal_context.gateway_session_id,
            pack_digest=self._pack_digest,
            input_value=safe_input,
            preview_value=sealed_preview,
            expires_in_seconds=definition.capability.action.expires_in_seconds,
        )
        state = creation.state
        if not definition.proof.approval_required:
            state = await self._store.transition(
                creation.handle,
                principal_id=principal_context.principal_id,
                session_id=principal_context.gateway_session_id,
                pack_digest=self._pack_digest,
                expected=PreparedActionStatus.PREPARED,
                target=PreparedActionStatus.APPROVED,
            )
        return PreparedActionPublic(
            action_handle=creation.handle,
            capability_id=definition.capability.id,
            status=state.record.status,
            preview=_canonical_copy(safe_preview, error_type=ActionPreviewInvalidError),
            approval_required=definition.proof.approval_required,
            expires_at=state.record.expires_at,
        )

    async def approval_binding_for_trusted_host(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ApprovalBinding:
        state = await self._resolve(action_handle, principal_context)
        definition = self._definition(state.record.capability_id)
        self._authorize(definition, principal_context)
        if not definition.proof.approval_required:
            raise ActionStateConflictError("Action does not require approval")
        if state.record.status is not PreparedActionStatus.PREPARED:
            raise ActionStateConflictError("Action is not awaiting approval")
        return ApprovalBinding.from_record(state.record)

    async def approve(
        self,
        action_handle: str | SecretValue,
        approval_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ActionStatusPublic:
        existing = await self._resolve(action_handle, principal_context)
        span = await self._start_audit("approve", existing.record.capability_id, principal_context)
        try:
            result = await self._approve(action_handle, approval_handle, principal_context)
        except asyncio.CancelledError:
            await _finish_cancelled_audit(span, status=existing.record.status)
            raise
        except BaseException as error:
            await span.finish(
                status=existing.record.status,
                result_category=_audit_error_category(error),
            )
            raise
        await span.finish(status=result.status, result_category="success")
        return result

    async def _approve(
        self,
        action_handle: str | SecretValue,
        approval_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ActionStatusPublic:
        state = await self._resolve(action_handle, principal_context)
        definition = self._definition(state.record.capability_id)
        self._authorize(definition, principal_context)
        if not definition.proof.approval_required:
            raise ActionStateConflictError("Action does not require approval")
        if state.record.status is not PreparedActionStatus.PREPARED:
            raise ActionStateConflictError("Action is not awaiting approval")
        await self._approval_authority.verify(
            approval_handle,
            ApprovalBinding.from_record(state.record),
        )
        approved = await self._store.transition(
            action_handle,
            principal_id=principal_context.principal_id,
            session_id=principal_context.gateway_session_id,
            pack_digest=self._pack_digest,
            expected=PreparedActionStatus.PREPARED,
            target=PreparedActionStatus.APPROVED,
        )
        return _public_status(approved, result=None)

    async def commit(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ActionCommitResult:
        existing = await self._resolve(action_handle, principal_context)
        span = await self._start_audit("commit", existing.record.capability_id, principal_context)
        try:
            result = await self._commit(action_handle, principal_context)
        except asyncio.CancelledError:
            await _finish_cancelled_audit(
                span,
                status=await self._resolved_status_or_none(action_handle, principal_context),
            )
            raise
        except BaseException as error:
            status = await self._resolved_status_or_none(action_handle, principal_context)
            category: ActionAuditResultCategory = (
                "outcome_unknown"
                if status is PreparedActionStatus.OUTCOME_UNKNOWN
                else _audit_error_category(error)
            )
            await span.finish(status=status, result_category=category)
            raise
        try:
            await span.finish(
                status=result.status,
                result_category="replayed" if result.replayed else "success",
            )
        except ActionAuditUnavailableError:
            raise ActionStateConflictError(
                "Action commit completed but required audit was unavailable"
            ) from None
        return result

    async def _commit(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ActionCommitResult:
        state = await self._resolve(action_handle, principal_context)
        definition = self._definition(state.record.capability_id)
        self._authorize(definition, principal_context)
        if state.record.status is PreparedActionStatus.SUCCEEDED:
            return ActionCommitResult(
                capability_id=state.record.capability_id,
                status=PreparedActionStatus.SUCCEEDED,
                result=copy.deepcopy(state.result_value),
                replayed=True,
            )
        if state.record.status is not PreparedActionStatus.APPROVED:
            raise ActionStateConflictError("Action cannot be committed from its current state")
        committing = await self._store.transition(
            action_handle,
            principal_id=principal_context.principal_id,
            session_id=principal_context.gateway_session_id,
            pack_digest=self._pack_digest,
            expected=PreparedActionStatus.APPROVED,
            target=PreparedActionStatus.COMMITTING,
        )
        preview_value, token, idempotency_key = _unseal_preview(committing.preview_value)
        execution = ActionCommitExecution(
            input_value=_canonical_copy(
                committing.input_value, error_type=ActionStateConflictError
            ),
            preview_value=preview_value,
            concurrency_token=token,
            idempotency_key=SecretValue(idempotency_key),
        )
        try:
            raw_result = await self._executor.commit(
                definition.capability,
                execution,
                principal_context,
            )
            result = _canonical_copy(raw_result, error_type=ActionStateConflictError)
        except asyncio.CancelledError:
            await asyncio.shield(
                self._mark_outcome_unknown(action_handle, principal_context, committing)
            )
            raise
        except BaseException:
            await self._mark_outcome_unknown(action_handle, principal_context, committing)
            raise ActionStateConflictError("Action commit outcome is unknown") from None
        try:
            succeeded = await self._store.transition(
                action_handle,
                principal_id=principal_context.principal_id,
                session_id=principal_context.gateway_session_id,
                pack_digest=self._pack_digest,
                expected=PreparedActionStatus.COMMITTING,
                target=PreparedActionStatus.SUCCEEDED,
                result_value=result,
            )
        except asyncio.CancelledError:
            await asyncio.shield(
                self._mark_outcome_unknown(action_handle, principal_context, committing)
            )
            raise
        except BaseException:
            await self._mark_outcome_unknown(action_handle, principal_context, committing)
            raise ActionStateConflictError("Action commit outcome is unknown") from None
        return ActionCommitResult(
            capability_id=succeeded.record.capability_id,
            status=succeeded.record.status,
            result=copy.deepcopy(succeeded.result_value),
            replayed=False,
        )

    async def status(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ActionStatusPublic:
        existing = await self._resolve(action_handle, principal_context)
        span = await self._start_audit("status", existing.record.capability_id, principal_context)
        try:
            result = await self._status(action_handle, principal_context)
        except asyncio.CancelledError:
            await _finish_cancelled_audit(span, status=existing.record.status)
            raise
        except BaseException as error:
            await span.finish(
                status=existing.record.status,
                result_category=_audit_error_category(error),
            )
            raise
        await span.finish(status=result.status, result_category="success")
        return result

    async def _status(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> ActionStatusPublic:
        state = await self._resolve(action_handle, principal_context)
        definition = self._definition(state.record.capability_id)
        self._authorize(definition, principal_context)
        result: JsonValue = None
        if state.record.status is PreparedActionStatus.SUCCEEDED:
            result = copy.deepcopy(state.result_value)
        return _public_status(state, result=result)

    async def _start_audit(
        self,
        lifecycle: ActionAuditLifecycle,
        capability_id: str,
        principal_context: PrincipalContext,
    ) -> ActionAuditSpan:
        return await start_action_audit_span(
            sink=self._action_audit_sink,
            mode=self._deployment_policy.action_audit_mode,
            salt=self._action_audit_salt,
            lifecycle=lifecycle,
            capability_id=capability_id,
            pack_digest=self._pack_digest,
            principal_id=principal_context.principal_id,
            session_id=principal_context.gateway_session_id,
        )

    async def _resolved_status_or_none(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> PreparedActionStatus | None:
        try:
            return (await self._resolve(action_handle, principal_context)).record.status
        except BaseException:
            return None

    async def _resolve(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
    ) -> PreparedActionState:
        return await self._store.resolve(
            action_handle,
            principal_id=principal_context.principal_id,
            session_id=principal_context.gateway_session_id,
            pack_digest=self._pack_digest,
        )

    async def _mark_outcome_unknown(
        self,
        action_handle: str | SecretValue,
        principal_context: PrincipalContext,
        state: PreparedActionState,
    ) -> None:
        try:
            await self._store.transition(
                action_handle,
                principal_id=principal_context.principal_id,
                session_id=principal_context.gateway_session_id,
                pack_digest=self._pack_digest,
                expected=PreparedActionStatus.COMMITTING,
                target=PreparedActionStatus.OUTCOME_UNKNOWN,
            )
        except BaseException:
            # The original mutation outcome remains unknown. Never replay it.
            return

    def _definition(self, capability_id: str) -> CompiledActionDefinition:
        definition = self._definitions.get(capability_id)
        if definition is None:
            raise ActionCapabilityNotFoundError("Action capability was not found")
        return definition

    def _authorize(
        self,
        definition: CompiledActionDefinition,
        principal_context: PrincipalContext,
    ) -> None:
        risk = definition.proof.maximum_risk
        assert risk is not None
        decision = self._deployment_policy.evaluate(
            capability_id=definition.capability.id,
            effects=definition.proof.effects,
            risk=risk,
        )
        if not decision.allowed:
            raise ActionDeploymentDeniedError(
                "Action is denied by deployment policy",
                details={"capability_id": definition.capability.id, "reasons": decision.reasons},
            )
        missing_scopes = sorted(
            set(definition.proof.required_scopes) - principal_context.effective_scopes
        )
        if missing_scopes:
            raise ActionScopeDeniedError(
                "Action is denied by effective scopes",
                details={
                    "capability_id": definition.capability.id,
                    "missing_scopes": missing_scopes,
                },
            )

    def _new_idempotency_key(self) -> SecretValue:
        try:
            value = self._idempotency_key_generator()
        except Exception:
            raise ActionPreviewInvalidError("Action idempotency key generation failed") from None
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or any(unicodedata.category(character) in {"Cc", "Cs"} for character in value)
        ):
            raise ActionPreviewInvalidError("Action idempotency key generation failed")
        return SecretValue(value)


def _canonical_copy(
    value: JsonValue,
    *,
    error_type: type[AccRuntimeError],
) -> JsonValue:
    try:
        return cast(JsonValue, json.loads(canonical_json_bytes(value)))
    except (TypeError, ValueError):
        raise error_type("Action value is not canonical JSON") from None


def _unseal_preview(value: JsonValue) -> tuple[JsonValue, JsonValue, str]:
    if not isinstance(value, dict) or value.get("version") != _SEALED_VERSION:
        raise ActionStateConflictError("Prepared Action state is invalid")
    idempotency_key = value.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not idempotency_key:
        raise ActionStateConflictError("Prepared Action state is invalid")
    return (
        copy.deepcopy(value.get("preview")),
        copy.deepcopy(value.get("concurrency_token")),
        idempotency_key,
    )


def _public_status(state: PreparedActionState, *, result: JsonValue) -> ActionStatusPublic:
    return ActionStatusPublic(
        capability_id=state.record.capability_id,
        status=state.record.status,
        result=copy.deepcopy(result),
    )


def _audit_error_category(error: BaseException) -> ActionAuditResultCategory:
    if isinstance(error, (ActionDeploymentDeniedError, ActionScopeDeniedError)):
        return "denied"
    if isinstance(error, AccRuntimeError):
        return "invalid"
    return "internal"


async def _finish_cancelled_audit(
    span: ActionAuditSpan,
    *,
    status: PreparedActionStatus | None,
) -> None:
    try:
        await asyncio.shield(span.finish(status=status, result_category="cancelled"))
    except BaseException:
        return


__all__ = [
    "ActionCapabilityNotFoundError",
    "ActionCommitExecution",
    "ActionCommitResult",
    "ActionCoordinator",
    "ActionDeploymentConfigurationError",
    "ActionDeploymentDeniedError",
    "ActionInputInvalidError",
    "ActionPreviewExecution",
    "ActionPreviewInvalidError",
    "ActionScopeDeniedError",
    "ActionStatusPublic",
    "ActionWorkflowExecutor",
    "CompiledActionDefinition",
    "PreparedActionPublic",
]
