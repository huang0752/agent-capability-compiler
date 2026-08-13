"""Pure safety proofs and derived inventory for current Action Capabilities."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from pydantic import JsonValue, ValidationError

from acc_core.contracts import ActionSemantics
from acc_core.contracts.schema_relation import SchemaRelation, compare_operation_output
from acc_core.diagnostics import Diagnostic
from acc_core.models import (
    BranchStep,
    CallStep,
    EmitStep,
    ForeachStep,
    JsonObject,
    ParallelStep,
    Policy,
    WorkflowStep,
)
from acc_core.models.actions import (
    Effect,
    Risk,
    ServerSerializedStatePredicateV2,
    StateIdempotencyV2,
    StatusQueryOutcomeResolutionV2,
    StatusQueryRequestBindingV2,
)
from acc_core.models.v2 import (
    ActionCapabilityV2,
    ActionOperationV2,
    OperationV2,
    ReadOperationV2,
)

_RISK_ORDER: dict[Risk, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
_PREPARED_REFERENCE = re.compile(r"^\$\.prepared\.(?:input|preview)(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$")
_DIRECT_INPUT_REFERENCE = re.compile(r"^\$\.input(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$")
_FRESH_STEP_REFERENCE = re.compile(
    r"^\$\.steps\.[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$"
)
_NON_ASSERTING_REF_SIBLINGS = frozenset(
    {"$comment", "$id", "$schema", "default", "deprecated", "description", "title"}
)


def _risk_rank(risk: Risk) -> int:
    return _RISK_ORDER[risk]


def _operation_semantics(operation: ActionOperationV2) -> dict[str, JsonValue]:
    safety = cast(dict[str, JsonValue], operation.http.safety.model_dump(mode="json"))
    return {"method": operation.http.method, **safety}


def _semantics_digest(summary: Mapping[str, JsonValue]) -> str:
    payload = json.dumps(
        summary,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def compile_action_semantics_attestation(
    operation: ActionOperationV2,
    semantics: ActionSemantics,
) -> dict[str, JsonValue]:
    """Seal trusted source semantics into deterministic compiler metadata."""

    summary = cast(dict[str, JsonValue], semantics.model_dump(mode="json"))
    claimed = {key: summary[key] for key in _operation_semantics(operation)}
    bound_evidence = operation.evidence
    if (
        claimed != _operation_semantics(operation)
        or semantics.evidence not in bound_evidence
        or any(claim.evidence not in bound_evidence for claim in semantics.provenance)
    ):
        raise ValueError("Action semantics do not match their bound Operation")
    return {"summary": summary, "digest": _semantics_digest(summary)}


def verify_action_semantics_attestation(
    operation: ActionOperationV2,
    value: object,
) -> bool:
    """Verify compiler metadata against the executable Operation and bound Evidence."""

    if not isinstance(value, Mapping) or set(value) != {"summary", "digest"}:
        return False
    summary = value.get("summary")
    digest = value.get("digest")
    if not isinstance(summary, Mapping) or not isinstance(digest, str):
        return False
    try:
        semantics = ActionSemantics.model_validate(dict(summary))
        expected = compile_action_semantics_attestation(operation, semantics)
    except (TypeError, ValueError, ValidationError):
        return False
    return dict(value) == expected


@dataclass(frozen=True, slots=True)
class ActionProof:
    """Deterministic Action inventory plus every failed safety proof."""

    diagnostics: tuple[Diagnostic, ...]
    mutation_operation_ids: tuple[str, ...]
    effects: tuple[Effect, ...]
    maximum_risk: Risk | None
    required_scopes: tuple[str, ...]
    approval_required: bool
    strategy_operation_ids: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


@dataclass(frozen=True, slots=True)
class _CallSite:
    operation_id: str
    arguments: Mapping[str, JsonValue]
    pointer: str
    containers: tuple[Literal["parallel", "foreach"], ...]


def _diagnostic(
    diagnostics: list[Diagnostic],
    *,
    code: str,
    message: str,
    path: str,
    pointer: str,
) -> None:
    diagnostics.append(
        Diagnostic(
            code=code,
            severity="error",
            message=message,
            path=path,
            pointer=pointer,
        )
    )


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _dereference_schema(root: JsonObject, schema: object) -> JsonObject | None:
    current = schema
    seen: set[str] = set()
    while isinstance(current, dict) and "$ref" in current:
        reference = current.get("$ref")
        if (
            not isinstance(reference, str)
            or not reference.startswith("#/")
            or reference in seen
            or set(current) - {"$ref"} - _NON_ASSERTING_REF_SIBLINGS
        ):
            return None
        seen.add(reference)
        resolved: object = root
        for token in _pointer_tokens(reference[1:]):
            if not isinstance(resolved, dict) or token not in resolved:
                return None
            resolved = resolved[token]
        current = resolved
    return cast(JsonObject, current) if isinstance(current, dict) else None


def _schema_at_data_pointer(schema: JsonObject, pointer: str) -> JsonObject | None:
    current: object = schema
    for token in _pointer_tokens(pointer):
        current = _dereference_schema(schema, current)
        if current is None:
            return None
        if current.get("type") == "array":
            if not token.isdecimal() or (len(token) > 1 and token.startswith("0")):
                return None
            items = current.get("items")
            if not isinstance(items, dict):
                return None
            current = items
            continue
        properties = current.get("properties")
        if not isinstance(properties, dict) or not isinstance(properties.get(token), dict):
            return None
        current = properties[token]
    return _dereference_schema(schema, current)


def _schema_pointer_is_guaranteed(schema: JsonObject, pointer: str) -> bool:
    current: object = schema
    for token in _pointer_tokens(pointer):
        current = _dereference_schema(schema, current)
        if current is None:
            return False
        if current.get("type") == "array":
            if not token.isdecimal() or (len(token) > 1 and token.startswith("0")):
                return False
            minimum = current.get("minItems")
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum <= int(token):
                return False
            items = current.get("items")
            if not isinstance(items, dict):
                return False
            current = items
            continue
        properties = current.get("properties")
        required = current.get("required")
        if (
            not isinstance(properties, dict)
            or not isinstance(properties.get(token), dict)
            or not isinstance(required, list)
            or token not in required
        ):
            return False
        current = properties[token]
    return _dereference_schema(schema, current) is not None


def _escaped_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _policy_path_tokens(value: str) -> tuple[str, ...]:
    if value.startswith("$."):
        value = value[2:]
    if value.startswith("/"):
        return _pointer_tokens(value)
    return tuple(token for token in value.split(".") if token)


def _paths_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    common = min(len(left), len(right))
    return left[:common] == right[:common]


def _policy_discloses_unmodified(policy: Policy, pointer: str) -> bool:
    source = _pointer_tokens(pointer)
    readable = tuple(_policy_path_tokens(path) for path in policy.readable_fields)
    if not any(len(rule) <= len(source) and source[: len(rule)] == rule for rule in readable):
        return False
    denied = tuple(_policy_path_tokens(path) for path in policy.denied_fields)
    redacted = tuple(_policy_path_tokens(rule.path) for rule in policy.redaction_rules)
    return not any(_paths_overlap(source, rule) for rule in (*denied, *redacted))


def _preview_result_schema(
    capability: ActionCapabilityV2,
    operations: Mapping[str, OperationV2],
) -> JsonObject | None:
    final_step = capability.preview_workflow[-1]
    if not isinstance(final_step, EmitStep) or not isinstance(final_step.emit.value, str):
        return None
    reference = final_step.emit.value
    if not reference.startswith("$.steps."):
        return None
    tokens = reference.removeprefix("$.steps.").split(".")
    if not tokens or any(not token for token in tokens):
        return None
    step_id, *value_tokens = tokens
    producers = [
        step
        for step in capability.preview_workflow
        if isinstance(step, CallStep) and step.id == step_id
    ]
    if len(producers) != 1:
        return None
    operation = operations.get(producers[0].call.operation)
    if not isinstance(operation, ReadOperationV2):
        return None
    if not value_tokens:
        return operation.output_schema
    pointer = "/" + "/".join(_escaped_pointer_token(token) for token in value_tokens)
    if not _schema_pointer_is_guaranteed(operation.output_schema, pointer):
        return None
    return _schema_at_data_pointer(operation.output_schema, pointer)


def _prove_status_query_bindings(
    capability: ActionCapabilityV2,
    operation: ReadOperationV2,
    outcome: StatusQueryOutcomeResolutionV2,
    preview_schema: JsonObject | None,
    policy: Policy | None,
    diagnostics: list[Diagnostic],
    *,
    path: str,
) -> None:
    properties = operation.input_schema.get("properties")
    required_value = operation.input_schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required_value, list):
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_TARGET_INVALID",
            message="Status query bindings require a declared object input schema.",
            path=path,
            pointer="/commit_workflow",
        )
        return
    required = {
        item
        for item in required_value
        if isinstance(item, str) and item not in operation.context_bindings
    }
    explicit = bool(outcome.request_bindings)
    bindings = list(outcome.request_bindings)
    if not explicit:
        bindings = [
            StatusQueryRequestBindingV2(
                target=target,
                source="capability_input",
                source_pointer=f"/{_escaped_pointer_token(target)}",
            )
            for target in sorted(required)
        ]

    constructed: set[str] = set()
    for index, binding in enumerate(bindings):
        binding_pointer = f"/commit_workflow/status_query/request_bindings/{index}"
        target_schema = properties.get(binding.target)
        if not isinstance(target_schema, dict):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_TARGET_INVALID",
                message="A status query binding target must be a declared input field.",
                path=path,
                pointer=f"{binding_pointer}/target",
            )
            continue
        if binding.target in operation.context_bindings:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_CONTEXT_FORBIDDEN",
                message="Status query bindings cannot override Runtime-owned context inputs.",
                path=path,
                pointer=f"{binding_pointer}/target",
            )
            continue
        source_root = (
            capability.input_schema if binding.source == "capability_input" else preview_schema
        )
        if binding.source == "prepared_preview" and (
            policy is None
            or policy.id != capability.policy
            or not _policy_discloses_unmodified(policy, binding.source_pointer)
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_STATUS_QUERY_PREVIEW_NOT_PUBLIC",
                message=(
                    "A prepared-preview status selector must survive its Capability policy "
                    "without denial or redaction."
                ),
                path=path,
                pointer=f"{binding_pointer}/source_pointer",
            )
            continue
        if source_root is None:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_SOURCE_INVALID",
                message="A prepared-preview binding requires a statically proven public preview.",
                path=path,
                pointer=f"{binding_pointer}/source_pointer",
            )
            continue
        source_schema = _schema_at_data_pointer(source_root, binding.source_pointer)
        if source_schema is None or not _schema_pointer_is_guaranteed(
            source_root, binding.source_pointer
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_SOURCE_INVALID",
                message="A status query binding source must be present in its sealed schema.",
                path=path,
                pointer=f"{binding_pointer}/source_pointer",
            )
            continue
        if (
            compare_operation_output(source_schema, target_schema).relation
            is not SchemaRelation.PROVEN
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_STATUS_QUERY_BINDING_SCHEMA_UNPROVEN",
                message="A status query binding source is not proven compatible with its target.",
                path=path,
                pointer=binding_pointer,
            )
            continue
        constructed.add(binding.target)

    for target in sorted(required - constructed):
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_STATUS_QUERY_REQUIRED_INPUT_UNBOUND",
            message="Every required status query input must be constructible from sealed values.",
            path=path,
            pointer=f"/commit_workflow/status_query/required/{_escaped_pointer_token(target)}",
        )


def _call_sites(
    workflow: Sequence[WorkflowStep],
    *,
    pointer: str,
    containers: tuple[Literal["parallel", "foreach"], ...] = (),
) -> tuple[_CallSite, ...]:
    sites: list[_CallSite] = []
    for index, step in enumerate(workflow):
        step_pointer = f"{pointer}/{index}"
        if isinstance(step, CallStep):
            sites.append(
                _CallSite(
                    operation_id=step.call.operation,
                    arguments=step.call.arguments,
                    pointer=f"{step_pointer}/call",
                    containers=containers,
                )
            )
        elif isinstance(step, BranchStep):
            sites.extend(
                _call_sites(
                    step.branch.then_steps,
                    pointer=f"{step_pointer}/branch/then",
                    containers=containers,
                )
            )
            sites.extend(
                _call_sites(
                    step.branch.else_steps,
                    pointer=f"{step_pointer}/branch/else",
                    containers=containers,
                )
            )
        elif isinstance(step, ParallelStep):
            for child_index, child in enumerate(step.parallel):
                sites.extend(
                    _call_sites(
                        [child],
                        pointer=f"{step_pointer}/parallel/{child_index}",
                        containers=(*containers, "parallel"),
                    )
                )
        elif isinstance(step, ForeachStep):
            sites.extend(
                _call_sites(
                    step.foreach.workflow,
                    pointer=f"{step_pointer}/foreach/workflow",
                    containers=(*containers, "foreach"),
                )
            )
    return tuple(sites)


def _sum_counts(left: set[int], right: set[int]) -> set[int]:
    return {left_count + right_count for left_count in left for right_count in right}


def _mutation_path_counts(
    workflow: Sequence[WorkflowStep],
    operations: Mapping[str, OperationV2],
) -> set[int]:
    counts = {0}
    for step in workflow:
        step_counts = {0}
        if isinstance(step, CallStep):
            operation = operations.get(step.call.operation)
            step_counts = {1} if isinstance(operation, ActionOperationV2) else {0}
        elif isinstance(step, BranchStep):
            step_counts = _mutation_path_counts(
                step.branch.then_steps, operations
            ) | _mutation_path_counts(step.branch.else_steps, operations)
        elif isinstance(step, ParallelStep):
            step_counts = {0}
            for child in step.parallel:
                step_counts = _sum_counts(
                    step_counts,
                    _mutation_path_counts([child], operations),
                )
        elif isinstance(step, ForeachStep):
            item_counts = _mutation_path_counts(step.foreach.workflow, operations)
            step_counts = {0}
            for item_count in item_counts:
                step_counts.add(item_count)
                step_counts.add(item_count * step.foreach.max_items)
        counts = _sum_counts(counts, step_counts)
    return counts


def _walk_strings(value: JsonValue, pointer: str) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        return ((value, pointer),)
    if isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_walk_strings(item, f"{pointer}/{index}"))
    elif isinstance(value, dict):
        for key, item in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            found.extend(_walk_strings(item, f"{pointer}/{escaped}"))
    return tuple(found)


def _workflow_strings(
    workflow: Sequence[WorkflowStep],
    *,
    pointer: str,
) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    for index, step in enumerate(workflow):
        dumped = cast(JsonValue, step.model_dump(mode="json", by_alias=True))
        found.extend(_walk_strings(dumped, f"{pointer}/{index}"))
    return tuple(found)


def _derived_approval_required(operations: Sequence[ActionOperationV2]) -> bool:
    return any(
        operation.http.safety.risk in {"high", "critical"}
        or operation.http.safety.reversibility != "reversible"
        or operation.http.safety.effect in {"delete", "execute"}
        or operation.http.safety.idempotency.mode != "source_key"
        for operation in operations
    )


def prove_action_capability(
    capability: ActionCapabilityV2,
    operations: Mapping[str, OperationV2],
    *,
    path: str | None = None,
    action_semantics: Mapping[str, ActionSemantics] | None = None,
    policy: Policy | None = None,
) -> ActionProof:
    """Prove one Action Capability without reading files or mutating compiler state."""

    diagnostic_path = path or f"capabilities/{capability.id}.yaml"
    diagnostics: list[Diagnostic] = []
    preview_sites = _call_sites(capability.preview_workflow, pointer="/preview_workflow")
    commit_sites = _call_sites(capability.commit_workflow, pointer="/commit_workflow")
    all_sites = (*preview_sites, *commit_sites)

    for site in all_sites:
        if site.operation_id not in operations:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_OPERATION_NOT_FOUND",
                message=f"Action workflow references an unknown Operation: {site.operation_id}",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )

    for site in preview_sites:
        if isinstance(operations.get(site.operation_id), ActionOperationV2):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_PREVIEW_MUTATION",
                message="Action preview_workflow may call only read Operations.",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )

    mutation_sites = tuple(
        site
        for site in commit_sites
        if isinstance(operations.get(site.operation_id), ActionOperationV2)
    )
    for site in mutation_sites:
        if "parallel" in site.containers:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_MUTATION_IN_PARALLEL",
                message="A mutating Operation cannot execute inside a parallel Action step.",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )
        if "foreach" in site.containers:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_MUTATION_IN_FOREACH",
                message="A mutating Operation cannot execute inside an Action foreach step.",
                path=diagnostic_path,
                pointer=f"{site.pointer}/operation",
            )

    if capability.action.execution_mode != "single":
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_EXECUTION_MODE_UNSUPPORTED",
            message="Action execution mode is declared but not implemented by this compiler.",
            path=diagnostic_path,
            pointer="/action/execution_mode",
        )
    elif _mutation_path_counts(capability.commit_workflow, operations) != {1}:
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_SINGLE_MUTATION_REQUIRED",
            message="single Action mode requires exactly one mutation on every commit path.",
            path=diagnostic_path,
            pointer="/commit_workflow",
        )

    for value, pointer in _workflow_strings(
        capability.preview_workflow, pointer="/preview_workflow"
    ):
        if value == "$.prepared" or value.startswith("$.prepared."):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_PREPARED_REFERENCE_IN_PREVIEW",
                message="preview_workflow cannot reference commit-time prepared state.",
                path=diagnostic_path,
                pointer=pointer,
            )

    for value, pointer in _workflow_strings(capability.commit_workflow, pointer="/commit_workflow"):
        if (value == "$.prepared" or value.startswith("$.prepared.")) and (
            _PREPARED_REFERENCE.fullmatch(value) is None
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_PREPARED_REFERENCE_INVALID",
                message=(
                    "commit prepared references must be rooted at "
                    "$.prepared.input or $.prepared.preview."
                ),
                path=diagnostic_path,
                pointer=pointer,
            )

    for site in mutation_sites:
        for value, pointer in _walk_strings(
            cast(JsonValue, dict(site.arguments)),
            f"{site.pointer}/arguments",
        ):
            if _DIRECT_INPUT_REFERENCE.fullmatch(value) is not None:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_UNPREPARED_MUTATION_INPUT",
                    message=(
                        "A mutating Operation must consume the immutable prepared snapshot, "
                        "not live Agent input."
                    ),
                    path=diagnostic_path,
                    pointer=pointer,
                )
            if _FRESH_STEP_REFERENCE.fullmatch(value) is not None:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_FRESH_STEP_MUTATION_INPUT",
                    message=(
                        "A mutating Operation cannot consume a fresh commit-time step result; "
                        "use only the immutable prepared snapshot or deterministic literals."
                    ),
                    path=diagnostic_path,
                    pointer=pointer,
                )

    mutation_operations_by_id = {
        site.operation_id: cast(ActionOperationV2, operations[site.operation_id])
        for site in mutation_sites
    }
    mutation_operations = tuple(
        mutation_operations_by_id[operation_id]
        for operation_id in sorted(mutation_operations_by_id)
    )

    strategy_operation_ids: set[str] = set()
    semantics_by_operation = action_semantics or {}
    preview_operation_ids = {site.operation_id for site in preview_sites}
    preview_schema = _preview_result_schema(capability, operations)
    local_guard = capability.action.local_development_state_guard
    local_guard_valid = local_guard is not None
    if local_guard is not None:
        resource_schema = _schema_at_data_pointer(
            capability.input_schema,
            local_guard.resource_key_pointer,
        )
        if (
            resource_schema is None
            or not _schema_pointer_is_guaranteed(
                capability.input_schema,
                local_guard.resource_key_pointer,
            )
            or resource_schema.get("type") not in {"string", "integer"}
        ):
            local_guard_valid = False
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_LOCAL_DEVELOPMENT_RESOURCE_KEY_INVALID",
                message=(
                    "A local development state guard requires a required scalar "
                    "resource key in the sealed capability input."
                ),
                path=diagnostic_path,
                pointer="/action/local_development_state_guard/resource_key_pointer",
            )
        read_operation = operations.get(local_guard.read_operation_id)
        if local_guard.read_operation_id not in preview_operation_ids or not isinstance(
            read_operation, ReadOperationV2
        ):
            local_guard_valid = False
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_LOCAL_DEVELOPMENT_PREVIEW_READ_REQUIRED",
                message=(
                    "A local development state guard requires its declared Read "
                    "Operation in preview."
                ),
                path=diagnostic_path,
                pointer="/preview_workflow",
            )
        else:
            strategy_operation_ids.add(local_guard.read_operation_id)
        if (
            preview_schema is None
            or not _schema_pointer_is_guaranteed(preview_schema, local_guard.state_pointer)
            or policy is None
            or not _policy_discloses_unmodified(policy, local_guard.state_pointer)
        ):
            local_guard_valid = False
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_LOCAL_DEVELOPMENT_STATE_INVALID",
                message=(
                    "A local development state guard requires a guaranteed, "
                    "unmodified public preview state."
                ),
                path=diagnostic_path,
                pointer="/action/local_development_state_guard/state_pointer",
            )
    for operation in mutation_operations:
        safety = operation.http.safety
        semantics = semantics_by_operation.get(operation.id)
        outcome = semantics.outcome_resolution if semantics is not None else None
        status_query_valid = False
        if isinstance(outcome, StatusQueryOutcomeResolutionV2):
            status_operation = operations.get(outcome.operation_id)
            if not isinstance(status_operation, ReadOperationV2):
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_STATUS_QUERY_INVALID",
                    message="A status query outcome must reference a declared read Operation.",
                    path=diagnostic_path,
                    pointer="/commit_workflow",
                )
            else:
                _prove_status_query_bindings(
                    capability,
                    status_operation,
                    outcome,
                    preview_schema,
                    policy,
                    diagnostics,
                    path=diagnostic_path,
                )
                strategy_operation_ids.add(outcome.operation_id)
                status_query_valid = True
        if safety.effect in {"create", "execute"} and safety.idempotency.mode != "source_key":
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_SOURCE_IDEMPOTENCY_REQUIRED",
                message=f"{safety.effect} Action requires evidenced source-key idempotency.",
                path=diagnostic_path,
                pointer="/commit_workflow",
            )
        uses_local_development_guard = (
            local_guard_valid
            and local_guard is not None
            and safety.effect in {"update", "delete", "transition"}
            and safety.risk == "low"
            and safety.retry.mode == "never"
            and safety.idempotency.mode == "runtime_deduplicate"
            and safety.concurrency.mode == "not_supported"
        )
        if local_guard is not None and not uses_local_development_guard:
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_LOCAL_DEVELOPMENT_SAFETY_INVALID",
                message=(
                    "A local development state guard supports only low-risk update, "
                    "delete, or transition Operations with runtime_deduplicate, "
                    "retry never, and explicitly unsupported source concurrency."
                ),
                path=diagnostic_path,
                pointer="/action/local_development_state_guard",
            )
        if (
            safety.effect in {"update", "delete", "transition"}
            and safety.concurrency.mode not in {"required", "server_serialized_state_predicate"}
            and not uses_local_development_guard
        ):
            _diagnostic(
                diagnostics,
                code="ACC_COMPILE_ACTION_CONCURRENCY_REQUIRED",
                message=f"{safety.effect} Action requires an optimistic concurrency contract.",
                path=diagnostic_path,
                pointer="/commit_workflow",
            )
        if isinstance(safety.concurrency, ServerSerializedStatePredicateV2):
            if safety.effect not in {"delete", "transition"}:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_SERVER_SERIALIZED_EFFECT_UNSUPPORTED",
                    message="Server-serialized state predicates support only delete or transition.",
                    path=diagnostic_path,
                    pointer="/commit_workflow",
                )
            if safety.retry.mode != "never":
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_SERVER_SERIALIZED_RETRY_FORBIDDEN",
                    message="Server-serialized mutations must never be retried automatically.",
                    path=diagnostic_path,
                    pointer="/commit_workflow",
                )
            if not isinstance(safety.idempotency, StateIdempotencyV2):
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_STATE_IDEMPOTENCY_REQUIRED",
                    message="Server-serialized mutations require state-idempotent semantics.",
                    path=diagnostic_path,
                    pointer="/commit_workflow",
                )
            if safety.concurrency.read_operation_id not in preview_operation_ids or not isinstance(
                operations.get(safety.concurrency.read_operation_id), ReadOperationV2
            ):
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_STATE_PREVIEW_READ_REQUIRED",
                    message="Server-serialized strategy requires its declared read in preview.",
                    path=diagnostic_path,
                    pointer="/preview_workflow",
                )
            else:
                strategy_operation_ids.add(safety.concurrency.read_operation_id)
            semantics_valid = False
            if semantics is not None:
                try:
                    compile_action_semantics_attestation(operation, semantics)
                except (TypeError, ValueError, ValidationError):
                    pass
                else:
                    semantics_valid = True
            required_implementation_fields = {
                "conflict_control",
                "idempotency",
                "outcome_resolution",
            }
            provenance_authorities: dict[str, str] = (
                {claim.field: claim.authority for claim in semantics.provenance}
                if semantics is not None
                else {}
            )
            if not semantics_valid or any(
                provenance_authorities.get(field) not in {"implementation", "test"}
                for field in required_implementation_fields
            ):
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_SAFETY_PROVENANCE_REQUIRED",
                    message="Server-serialized safety requires trusted field-level provenance.",
                    path=diagnostic_path,
                    pointer="/commit_workflow",
                )
            if not status_query_valid:
                _diagnostic(
                    diagnostics,
                    code="ACC_COMPILE_ACTION_STATUS_QUERY_REQUIRED",
                    message="Server-serialized safety requires a declared read status query.",
                    path=diagnostic_path,
                    pointer="/commit_workflow",
                )

    safety_requires_approval = _derived_approval_required(mutation_operations)
    approval_required = capability.action.approval.mode == "required" or safety_requires_approval
    if safety_requires_approval and capability.action.approval.mode != "required":
        _diagnostic(
            diagnostics,
            code="ACC_COMPILE_ACTION_APPROVAL_REQUIRED",
            message="The derived Action risk requires an explicit approval grant.",
            path=diagnostic_path,
            pointer="/action/approval/mode",
        )

    used_operations = {
        site.operation_id: operations[site.operation_id]
        for site in all_sites
        if site.operation_id in operations
    }
    used_operations.update(
        {
            operation_id: operations[operation_id]
            for operation_id in strategy_operation_ids
            if operation_id in operations
        }
    )
    effects = tuple(sorted({operation.http.safety.effect for operation in mutation_operations}))
    risks: set[Risk] = {operation.http.safety.risk for operation in mutation_operations}
    maximum_risk: Risk | None = None
    if risks:
        derived_maximum: Risk = sorted(risks, key=_risk_rank)[-1]
        maximum_risk = derived_maximum
    required_scopes = tuple(
        sorted({scope for operation in used_operations.values() for scope in operation.http.scopes})
    )
    return ActionProof(
        diagnostics=tuple(diagnostics),
        mutation_operation_ids=tuple(sorted(mutation_operations_by_id)),
        effects=effects,
        maximum_risk=maximum_risk,
        required_scopes=required_scopes,
        approval_required=approval_required,
        strategy_operation_ids=tuple(sorted(strategy_operation_ids)),
    )


__all__ = [
    "ActionProof",
    "compile_action_semantics_attestation",
    "prove_action_capability",
    "verify_action_semantics_attestation",
]
