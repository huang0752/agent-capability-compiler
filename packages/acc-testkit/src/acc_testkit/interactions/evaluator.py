"""Data-only reference evaluator for platform-neutral interaction contracts."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import cast

from pydantic import JsonValue

from acc_testkit.interactions.models import (
    ActionPhaseRecord,
    ActionProtocolAssessment,
    InteractionTraceEntry,
)

_MISSING = object()
_SUBMISSION_POLICIES = frozenset({"omit", "send", "send_if_changed"})
MAX_CONDITION_DEPTH = 64
MAX_CONDITION_NODES = 4_096


class InteractionEvaluationError(ValueError):
    """A stable failure for malformed or unsafe interaction input."""


class InteractionCallerError(RuntimeError):
    """A classified, data-free failure returned by a generic async caller."""

    def __init__(self, kind: str) -> None:
        if kind not in {"source_error", "forbidden"}:
            raise ValueError("interaction caller error kind must be source_error or forbidden")
        self.kind = kind
        super().__init__(kind)


type InteractionCaller = Callable[[str, dict[str, JsonValue]], Awaitable[JsonValue]]


class HeadlessInteractionEvaluator:
    """Evaluate deterministic field state without depending on a UI framework."""

    def __init__(
        self,
        manifest: Mapping[str, object],
        *,
        capability_id: str,
        initial_values: Mapping[str, JsonValue],
        principal_id: str,
        tenant_id: str,
        identity_salt: bytes,
    ) -> None:
        principal_id = _exact_identity(principal_id, "principal_id")
        tenant_id = _exact_identity(tenant_id, "tenant_id")
        if not isinstance(identity_salt, bytes) or not identity_salt:
            raise InteractionEvaluationError("identity_salt must be nonempty bytes")
        capability_id = _exact_identity(capability_id, "capability_id")
        digest = manifest.get("digest")
        contracts = manifest.get("contracts")
        if (
            manifest.get("schema_version") != "2"
            or not isinstance(digest, str)
            or len(digest) != 64
            or not isinstance(contracts, Mapping)
        ):
            raise InteractionEvaluationError("interaction manifest is invalid")
        contract = contracts.get(capability_id)
        if not isinstance(contract, Mapping) or contract.get("capability_id") != capability_id:
            raise InteractionEvaluationError("interaction capability contract is not provisioned")
        self._contract = copy.deepcopy(dict(contract))
        self._interaction_digest = digest
        self._capability_id = capability_id
        self._principal_digest = _identity_digest(identity_salt, "principal", principal_id)
        self._tenant_digest = _identity_digest(identity_salt, "tenant", tenant_id)
        principal_id = ""
        tenant_id = ""
        self._fields: dict[str, Mapping[str, object]] = {}
        for binding in _mapping_sequence(contract.get("public_input_bindings"), "input bindings"):
            pointer = binding.get("target_pointer")
            if not isinstance(pointer, str):
                raise InteractionEvaluationError("input binding target pointer must be a string")
            _pointer_tokens(pointer)
            self._fields[pointer] = {"submission": "send"}
        for default in _mapping_sequence(contract.get("defaults"), "defaults"):
            pointer = default.get("target_pointer")
            if not isinstance(pointer, str) or "value" not in default:
                raise InteractionEvaluationError("compiled default must have target and value")
            _pointer_tokens(pointer)
            self._fields[pointer] = {
                **self._fields.get(pointer, {}),
                "default": copy.deepcopy(default["value"]),
                "submission": "send",
            }
        for source in _mapping_sequence(contract.get("option_sources"), "option sources"):
            pointer = source.get("target_pointer")
            if not isinstance(pointer, str):
                raise InteractionEvaluationError("option target pointer must be a string")
            _pointer_tokens(pointer)
            self._fields[pointer] = {
                **self._fields.get(pointer, {}),
                "option_source": source,
                "submission": "send",
            }

        self._values = copy.deepcopy(dict(initial_values))
        undeclared = sorted(
            pointer
            for pointer in _leaf_pointers(self._values)
            if not any(
                pointer == declared or pointer.startswith(f"{declared}/")
                for declared in self._fields
            )
        )
        if undeclared:
            raise InteractionEvaluationError("undeclared initial field")
        for pointer, definition in self._fields.items():
            if _read_pointer(self._values, pointer) is _MISSING and "default" in definition:
                _write_pointer(
                    self._values,
                    pointer,
                    cast(JsonValue, copy.deepcopy(definition["default"])),
                )
        self._baseline = copy.deepcopy(self._values)
        self._trace: list[InteractionTraceEntry] = []
        self._option_generations: dict[str, int] = {}
        self._option_snapshots: dict[tuple[str, int], dict[str, object]] = {}
        self._options: dict[str, tuple[dict[str, JsonValue], ...]] = {}
        self._paging_tokens: dict[str, JsonValue] = {}
        self._interaction_state = "initial"
        self._record("initialized")

    @property
    def values(self) -> dict[str, JsonValue]:
        return copy.deepcopy(self._values)

    @property
    def trace(self) -> tuple[InteractionTraceEntry, ...]:
        return tuple(self._trace)

    @property
    def interaction_state(self) -> str:
        return self._interaction_state

    def set_value(self, field: str, value: JsonValue) -> None:
        self._require_field(field)
        _write_pointer(self._values, field, copy.deepcopy(value))
        self._record("value_changed", field=field)
        self._invalidate_cascade(field)

    def submission(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for pointer, definition in self._fields.items():
            policy = definition.get("submission", "send")
            current = _read_pointer(self._values, pointer)
            if current is _MISSING or policy == "omit":
                continue
            if policy == "send_if_changed" and current == _read_pointer(self._baseline, pointer):
                continue
            _write_pointer(result, pointer, cast(JsonValue, copy.deepcopy(current)))
        return result

    def begin_option_request(self, field: str) -> int:
        self._require_field(field)
        generation = self._option_generations.get(field, 0) + 1
        self._option_generations[field] = generation
        self._record("options_requested", field=field, generation=generation)
        return generation

    async def request_options(
        self,
        field: str,
        caller: InteractionCaller,
        *,
        search: str | None = None,
        page: int | str | None = None,
    ) -> bool:
        """Execute one declared option producer and reject stale cascade responses."""

        definition = self._require_field(field)
        option_source = definition.get("option_source")
        if not isinstance(option_source, Mapping):
            raise InteractionEvaluationError("interaction field has no option source")
        producer_id = option_source.get("producer_id")
        if not isinstance(producer_id, str) or not producer_id:
            raise InteractionEvaluationError("option source producer_id must be nonempty")
        dependencies = _pointer_sequence(option_source.get("cascade_dependencies", ()))
        generation = self.begin_option_request(field)
        self._option_snapshots[(field, generation)] = {
            pointer: copy.deepcopy(_read_pointer(self._values, pointer)) for pointer in dependencies
        }
        arguments = self._option_arguments(option_source, search=search, page=page)
        self._transition("loading", field=field, generation=generation)
        self._record(
            "producer_requested",
            field=field,
            generation=generation,
            producer_id=producer_id,
            arguments=arguments,
        )
        try:
            response = await caller(producer_id, copy.deepcopy(arguments))
        except asyncio.CancelledError:
            self._option_snapshots.pop((field, generation), None)
            raise
        except InteractionCallerError as exc:
            self._option_snapshots.pop((field, generation), None)
            self._transition(exc.kind, field=field, generation=generation)
            self._record(
                "producer_failed",
                field=field,
                generation=generation,
                producer_id=producer_id,
            )
            return False
        except Exception:
            self._option_snapshots.pop((field, generation), None)
            self._transition("source_error", field=field, generation=generation)
            self._record(
                "producer_failed",
                field=field,
                generation=generation,
                producer_id=producer_id,
            )
            return False
        if not isinstance(response, (Mapping, list)):
            self._transition("source_error", field=field, generation=generation)
            self._record(
                "producer_failed",
                field=field,
                generation=generation,
                producer_id=producer_id,
            )
            return False
        snapshot = self._option_snapshots.pop((field, generation), {})
        if generation != self._option_generations.get(field) or any(
            snapshot[pointer] != _read_pointer(self._values, pointer) for pointer in dependencies
        ):
            self._transition("stale", field=field, generation=generation)
            self._record("options_stale", field=field, generation=generation)
            return False
        try:
            options = _project_options(option_source, response)
            paging_token = _pagination_response(option_source, response)
        except InteractionEvaluationError:
            self._transition("source_error", field=field, generation=generation)
            self._record(
                "producer_failed",
                field=field,
                generation=generation,
                producer_id=producer_id,
            )
            return False
        if not self.resolve_option_request(field, generation, options):
            self._transition("stale", field=field, generation=generation)
            return False
        if paging_token is not None:
            self._paging_tokens[field] = paging_token
        self._transition("empty" if not options else "ready", field=field, generation=generation)
        return True

    def static_options(self, field: str) -> tuple[dict[str, JsonValue], ...]:
        definition = self._require_field(field)
        source = definition.get("option_source")
        if not isinstance(source, Mapping) or source.get("source_kind") != "static":
            raise InteractionEvaluationError("static options are not provisioned")
        values = source.get("static_options")
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise InteractionEvaluationError("static options must be a sequence")
        projected: list[dict[str, JsonValue]] = []
        for value in values:
            if not isinstance(value, Mapping):
                raise InteractionEvaluationError("static option must be a mapping")
            projected.append(cast(dict[str, JsonValue], copy.deepcopy(dict(value))))
        return tuple(projected)

    def paging_token(self, field: str) -> JsonValue | None:
        self._require_field(field)
        return copy.deepcopy(self._paging_tokens.get(field))

    async def call_consumer(self, caller: InteractionCaller) -> JsonValue:
        """Submit normalized consumer arguments through the same generic async caller."""

        consumer_id = self._contract_consumer_id()
        arguments = self.submission()
        self._record("consumer_requested", producer_id=consumer_id, arguments=arguments)
        try:
            result = await caller(consumer_id, copy.deepcopy(arguments))
        except asyncio.CancelledError:
            raise
        except Exception:
            self._transition("source_error")
            self._record("producer_failed", producer_id=consumer_id)
            raise InteractionEvaluationError("consumer source_error") from None
        self._record("consumer_resolved", producer_id=consumer_id)
        self._record("result_consumed", producer_id=consumer_id, result=result)
        return copy.deepcopy(result)

    def assess_action_protocol(
        self, records: Sequence[ActionPhaseRecord]
    ) -> ActionProtocolAssessment:
        """Assess externally captured Action records without executing mutation."""

        lifecycle = self._contract.get("action_lifecycle")
        if not isinstance(lifecycle, Mapping) or lifecycle.get("phases") != [
            "prepare",
            "approve",
            "commit",
            "status",
        ]:
            assessment = ActionProtocolAssessment(
                status="not_provisioned",
                shape_valid=False,
                codes=("ACC_TESTKIT_ACTION_LIFECYCLE_NOT_PROVISIONED",),
            )
        else:
            assessment = _assess_action_records(records)
        self._record(
            "action_protocol_observed",
            result=assessment.model_dump(mode="json"),
        )
        return assessment

    @property
    def declared_states(self) -> tuple[str, ...]:
        inherited = self._contract.get("inherited_interactions")
        if not isinstance(inherited, Mapping):
            return ()
        identifiers: set[str] = set()
        for interaction in inherited.values():
            if not isinstance(interaction, Mapping):
                continue
            states = interaction.get("states", ())
            if not isinstance(states, Sequence) or isinstance(states, (str, bytes)):
                continue
            identifiers.update(
                state["id"]
                for state in states
                if isinstance(state, Mapping) and isinstance(state.get("id"), str)
            )
        return tuple(sorted(identifiers))

    def apply_conditions(self) -> dict[str, dict[str, bool]]:
        """Apply compiled safe conditions to public fields, including reset semantics."""

        semantics = {
            pointer: {"visible": True, "enabled": True, "required": False}
            for pointer in self._fields
        }
        for condition in _mapping_sequence(self._contract.get("conditions"), "conditions"):
            target = condition.get("target")
            pointer = condition.get("target_pointer")
            expression = condition.get("expression")
            if (
                target not in {"visible", "enabled", "required", "reset"}
                or not isinstance(pointer, str)
                or pointer not in self._fields
                or not isinstance(expression, Mapping)
            ):
                raise InteractionEvaluationError("compiled condition is not provisioned")
            matched = evaluate_condition(cast(Mapping[str, object], expression), self._values)
            if target == "reset":
                if matched:
                    _delete_pointer(self._values, pointer)
                continue
            semantics[pointer][target] = matched
        return semantics

    async def load_related_data(self, caller: InteractionCaller) -> dict[str, str]:
        """Resolve manifest-declared related data with fixed, data-free outcomes."""

        outcomes: dict[str, str] = {}
        bindings = _mapping_sequence(self._contract.get("related_data"), "related data")
        for binding in bindings:
            identifier = binding.get("id")
            producer_id = binding.get("producer_id")
            output_pointer = binding.get("output_pointer")
            target_pointer = binding.get("target_pointer")
            if not all(
                isinstance(value, str)
                for value in (identifier, producer_id, output_pointer, target_pointer)
            ):
                raise InteractionEvaluationError("related data binding is not provisioned")
            self._record("producer_requested", producer_id=cast(str, producer_id), arguments={})
            try:
                response = await caller(cast(str, producer_id), {})
            except asyncio.CancelledError:
                raise
            except Exception:
                outcomes[cast(str, identifier)] = "source_error"
                self._record("producer_failed", producer_id=cast(str, producer_id))
                if binding.get("failure_isolation") == "fail_fast":
                    break
                continue
            value = _read_pointer(response, cast(str, output_pointer))
            if value is _MISSING:
                outcomes[cast(str, identifier)] = "not_provisioned"
                continue
            _write_pointer(
                self._values,
                cast(str, target_pointer),
                cast(JsonValue, copy.deepcopy(value)),
            )
            outcomes[cast(str, identifier)] = "resolved"
            self._record("consumer_resolved", producer_id=cast(str, producer_id), result=response)
        return outcomes

    def consume_result(self, result: JsonValue) -> dict[str, JsonValue]:
        """Project only manifest-declared result fields and record a digest."""

        projected: dict[str, JsonValue] = {}
        consumptions = _mapping_sequence(
            self._contract.get("result_consumption"), "result consumption"
        )
        for consumption in consumptions:
            identifier = consumption.get("id")
            source_pointer = consumption.get("source_pointer")
            field_pointers = consumption.get("field_pointers")
            if (
                not isinstance(identifier, str)
                or not isinstance(source_pointer, str)
                or not isinstance(field_pointers, Sequence)
                or isinstance(field_pointers, (str, bytes))
            ):
                raise InteractionEvaluationError("result consumption is not provisioned")
            source = _read_pointer(result, source_pointer)
            if source is _MISSING:
                continue
            item: JsonValue
            if not field_pointers:
                item = cast(JsonValue, copy.deepcopy(source))
            elif isinstance(source, list):
                item = [
                    _project_result_fields(source_item, field_pointers) for source_item in source
                ]
            else:
                item = _project_result_fields(source, field_pointers)
            projected[identifier] = item
        self._record("result_consumed", result=result)
        return projected

    def resolve_option_request(
        self,
        field: str,
        generation: int,
        options: Sequence[Mapping[str, JsonValue]],
    ) -> bool:
        self._require_field(field)
        if generation != self._option_generations.get(field):
            self._record("options_stale", field=field, generation=generation)
            return False
        self._options[field] = tuple(copy.deepcopy(dict(option)) for option in options)
        self._record("options_resolved", field=field, generation=generation)
        return True

    def options(self, field: str) -> tuple[dict[str, JsonValue], ...]:
        self._require_field(field)
        return tuple(copy.deepcopy(self._options.get(field, ())))

    def option_cache_key(
        self, field: str, request: Mapping[str, JsonValue]
    ) -> tuple[str, str, str, str, str, str, str]:
        definition = self._require_field(field)
        source = definition.get("option_source")
        producer_id = source.get("producer_id") if isinstance(source, Mapping) else None
        if not isinstance(producer_id, str) or not producer_id:
            raise InteractionEvaluationError("dynamic option producer is not provisioned")
        try:
            canonical_request = json.dumps(
                dict(request),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise InteractionEvaluationError("option request must be canonical JSON") from exc
        return (
            self._interaction_digest,
            self._capability_id,
            producer_id,
            self._principal_digest,
            self._tenant_digest,
            field,
            canonical_request,
        )

    def _require_field(self, field: str) -> Mapping[str, object]:
        if field not in self._fields:
            raise InteractionEvaluationError("interaction field is not declared")
        return self._fields[field]

    def _contract_consumer_id(self) -> str:
        return self._capability_id

    def _cascade_dependents(self, changed_field: str) -> tuple[str, ...]:
        dependents: list[str] = []
        for pointer, definition in self._fields.items():
            option_source = definition.get("option_source")
            if not isinstance(option_source, Mapping):
                continue
            dependencies = _pointer_sequence(option_source.get("cascade_dependencies", ()))
            if changed_field in dependencies:
                dependents.append(pointer)
        return tuple(sorted(dependents))

    def _invalidate_cascade(self, changed_field: str) -> None:
        pending = [changed_field]
        visited: set[str] = set()
        while pending:
            changed = pending.pop(0)
            for dependent in self._cascade_dependents(changed):
                if dependent in visited:
                    continue
                visited.add(dependent)
                generation = self._option_generations.get(dependent, 0) + 1
                self._option_generations[dependent] = generation
                self._options.pop(dependent, None)
                definition = self._fields[dependent]
                source = definition.get("option_source")
                if (
                    isinstance(source, Mapping)
                    and source.get("empty_behavior") == "clear_selection"
                ):
                    _delete_pointer(self._values, dependent)
                    pending.append(dependent)
                self._transition("stale", field=dependent, generation=generation)
                self._record("options_stale", field=dependent, generation=generation)

    def _option_arguments(
        self,
        source: Mapping[str, object],
        *,
        search: str | None,
        page: int | str | None,
    ) -> dict[str, JsonValue]:
        arguments: dict[str, JsonValue] = {}
        bindings = source.get("request_bindings", ())
        if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
            raise InteractionEvaluationError("option request_bindings must be a sequence")
        for binding in bindings:
            if not isinstance(binding, Mapping):
                raise InteractionEvaluationError("option request binding must be a mapping")
            target_pointer = binding.get("target_pointer")
            if not isinstance(target_pointer, str):
                raise InteractionEvaluationError("option request target pointer must be a string")
            value = _request_binding_value(binding, self._values)
            if value is _MISSING:
                continue
            _write_pointer(arguments, target_pointer, cast(JsonValue, copy.deepcopy(value)))
        search_config = source.get("search", {"mode": "none"})
        if isinstance(search_config, Mapping) and search_config.get("mode") == "server":
            pointer = search_config.get("query_pointer")
            if not isinstance(pointer, str) or search is None:
                raise InteractionEvaluationError("server option search requires query and pointer")
            _write_pointer(arguments, pointer, search)
        pagination = source.get("pagination", {"mode": "none"})
        if isinstance(pagination, Mapping) and pagination.get("mode") != "none":
            pointer = pagination.get("request_pointer")
            if not isinstance(pointer, str) or page is None:
                raise InteractionEvaluationError("option pagination requires page and pointer")
            _write_pointer(arguments, pointer, cast(JsonValue, page))
        return arguments

    def _transition(
        self,
        state: str,
        *,
        field: str | None = None,
        generation: int | None = None,
    ) -> None:
        self._interaction_state = state
        self._record("state_changed", field=field, generation=generation)

    def _record(
        self,
        event: str,
        *,
        field: str | None = None,
        generation: int | None = None,
        producer_id: str | None = None,
        arguments: dict[str, JsonValue] | None = None,
        result: JsonValue | None = None,
    ) -> None:
        self._trace.append(
            InteractionTraceEntry.model_validate(
                {
                    "event": event,
                    "state": copy.deepcopy(self._values),
                    "field": field,
                    "generation": generation,
                    "interaction_state": self._interaction_state,
                    "producer_id": producer_id,
                    "arguments_sha256": _json_digest(arguments),
                    "result_sha256": _json_digest(result),
                }
            )
        )


def evaluate_condition(condition: Mapping[str, object], state: Mapping[str, JsonValue]) -> bool:
    """Evaluate an allowlisted condition AST without evaluating source code."""

    _validate_condition_budget(condition)
    return _evaluate_condition(condition, state)


def _assess_action_records(
    records: Sequence[ActionPhaseRecord],
) -> ActionProtocolAssessment:
    """Validate Action observation shape while never claiming execution verification."""

    expected = ("prepare", "approve", "commit", "status")
    phases = tuple(record.phase for record in records)
    codes: list[str] = []
    if phases != expected:
        codes.append("ACC_TESTKIT_ACTION_PHASES_NOT_PROVISIONED")
    correlation_ids = {record.correlation_id for record in records}
    if len(correlation_ids) != 1:
        codes.append("ACC_TESTKIT_ACTION_CORRELATION_MISMATCH")
    idempotency_keys = {record.idempotency_key for record in records}
    if len(idempotency_keys) != 1:
        codes.append("ACC_TESTKIT_ACTION_IDEMPOTENCY_MISMATCH")
    audit_ids = [record.audit_id for record in records]
    if len(audit_ids) != len(set(audit_ids)):
        codes.append("ACC_TESTKIT_ACTION_AUDIT_DUPLICATE")
    shape_valid = not codes
    return ActionProtocolAssessment(
        status="not_verified" if shape_valid else "not_provisioned",
        shape_valid=shape_valid,
        codes=tuple(sorted(codes)),
    )


def _evaluate_condition(condition: Mapping[str, object], state: Mapping[str, JsonValue]) -> bool:
    operator = condition.get("operator")
    if operator in {"all", "any"}:
        _require_keys(condition, {"operator", "operands"})
        operands = condition.get("operands")
        if not isinstance(operands, Sequence) or isinstance(operands, (str, bytes)):
            raise InteractionEvaluationError("condition operands must be a sequence")
        if not operands:
            raise InteractionEvaluationError("condition operands must be nonempty")
        values = [_evaluate_condition(_condition(item), state) for item in operands]
        return all(values) if operator == "all" else any(values)
    if operator == "not":
        _require_keys(condition, {"operator", "operand"})
        return not _evaluate_condition(_condition(condition.get("operand")), state)
    if operator == "present":
        _require_keys(condition, {"operator", "operand"})
        return _expression(condition.get("operand"), state) is not _MISSING
    if operator in {"eq", "ne", "in"}:
        _require_keys(condition, {"operator", "left", "right"})
        left = _expression(condition.get("left"), state)
        right = _expression(condition.get("right"), state)
        if left is _MISSING or right is _MISSING:
            return False
        if operator == "in":
            if not isinstance(right, (list, tuple, set, frozenset, str)):
                return False
            return left in right
        equal = left == right
        return equal if operator == "eq" else not equal
    raise InteractionEvaluationError("unsupported condition operator")


def _validate_condition_budget(condition: Mapping[str, object]) -> None:
    stack: list[tuple[object, int]] = [(condition, 1)]
    node_count = 0
    while stack:
        node, depth = stack.pop()
        if depth > MAX_CONDITION_DEPTH:
            raise InteractionEvaluationError("condition expression exceeds maximum depth")
        node_count += 1
        if node_count > MAX_CONDITION_NODES:
            raise InteractionEvaluationError("condition expression exceeds maximum node count")
        if not isinstance(node, Mapping):
            continue
        operator = node.get("operator")
        child_depth = depth + 1
        if operator in {"all", "any"}:
            operands = node.get("operands")
            if isinstance(operands, Sequence) and not isinstance(operands, (str, bytes)):
                stack.extend((operand, child_depth) for operand in reversed(operands))
        elif operator == "not":
            stack.append((node.get("operand"), child_depth))
        elif operator in {"eq", "ne", "in"}:
            stack.append((node.get("right"), child_depth))
            stack.append((node.get("left"), child_depth))
        elif operator == "present":
            stack.append((node.get("operand"), child_depth))


def _condition(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InteractionEvaluationError("nested condition must be a mapping")
    return cast(Mapping[str, object], value)


def _expression(value: object, state: Mapping[str, JsonValue]) -> object:
    if not isinstance(value, Mapping):
        raise InteractionEvaluationError("condition expression must be a mapping")
    kind = value.get("kind")
    if (
        kind == "reference"
        and set(value) == {"kind", "pointer"}
        and isinstance(value.get("pointer"), str)
    ):
        return _read_pointer(state, cast(str, value["pointer"]))
    if kind == "literal" and set(value) == {"kind", "value"}:
        return value.get("value")
    raise InteractionEvaluationError("condition expression must be a field or literal")


def _require_keys(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise InteractionEvaluationError("condition contains unexpected fields")


def _exact_identity(value: str, field_name: str) -> str:
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise InteractionEvaluationError(f"{field_name} must be an exact nonempty value")
    return value


def _identity_digest(salt: bytes, identity_kind: str, value: str) -> str:
    message = f"acc-testkit:{identity_kind}\0{value}".encode()
    return hmac.new(salt, message, hashlib.sha256).hexdigest()


def _json_digest(value: JsonValue | None) -> str | None:
    if value is None:
        return None
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise InteractionEvaluationError("trace value must be canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/") or pointer == "/":
        raise InteractionEvaluationError("interaction field must be an absolute JSON Pointer")
    tokens: list[str] = []
    for raw in pointer[1:].split("/"):
        index = 0
        while index < len(raw):
            if raw[index] == "~":
                if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                    raise InteractionEvaluationError("interaction field has invalid JSON Pointer")
                index += 2
            else:
                index += 1
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def _read_pointer(value: object, pointer: str) -> object:
    current: object = value
    for token in _pointer_tokens(pointer):
        if isinstance(current, Mapping):
            if token not in current:
                return _MISSING
            current = current[token]
            continue
        if isinstance(current, list) and token.isdecimal():
            index = int(token)
            if index >= len(current):
                return _MISSING
            current = current[index]
            continue
        else:
            return _MISSING
    return current


def _write_pointer(target: dict[str, JsonValue], pointer: str, value: JsonValue) -> None:
    tokens = _pointer_tokens(pointer)
    current: object = target
    for offset, token in enumerate(tokens[:-1]):
        next_is_index = tokens[offset + 1].isdecimal()
        if isinstance(current, dict):
            child = current.get(token)
            if child is None:
                child = [] if next_is_index else {}
                current[token] = cast(JsonValue, child)
            if not isinstance(child, (dict, list)):
                raise InteractionEvaluationError("interaction field crosses a scalar value")
            current = child
            continue
        if isinstance(current, list) and token.isdecimal():
            index = int(token)
            while len(current) <= index:
                current.append(None)
            child = current[index]
            if child is None:
                child = [] if next_is_index else {}
                current[index] = cast(JsonValue, child)
            if not isinstance(child, (dict, list)):
                raise InteractionEvaluationError("interaction field crosses a scalar value")
            current = child
            continue
        raise InteractionEvaluationError("interaction field crosses a non-container value")
    final = tokens[-1]
    if isinstance(current, dict):
        current[final] = value
        return
    if isinstance(current, list) and final.isdecimal():
        index = int(final)
        while len(current) <= index:
            current.append(None)
        current[index] = value
        return
    raise InteractionEvaluationError("interaction field target is not writable")


def _delete_pointer(target: dict[str, JsonValue], pointer: str) -> None:
    tokens = _pointer_tokens(pointer)
    current: object = target
    for token in tokens[:-1]:
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdecimal() and int(token) < len(current):
            current = current[int(token)]
        else:
            return
    final = tokens[-1]
    if isinstance(current, dict):
        current.pop(final, None)
    elif isinstance(current, list) and final.isdecimal() and int(final) < len(current):
        current[int(final)] = None


def _mapping_sequence(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise InteractionEvaluationError(f"compiled {label} must be a sequence")
    result: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise InteractionEvaluationError(f"compiled {label} entries must be mappings")
        result.append(cast(Mapping[str, object], item))
    return tuple(result)


def _leaf_pointers(value: object, pointer: str = "") -> tuple[str, ...]:
    if isinstance(value, Mapping) and value:
        pointers: list[str] = []
        for key, child in value.items():
            token = str(key).replace("~", "~0").replace("/", "~1")
            pointers.extend(_leaf_pointers(child, f"{pointer}/{token}"))
        return tuple(pointers)
    if isinstance(value, list) and value:
        pointers = []
        for index, child in enumerate(value):
            pointers.extend(_leaf_pointers(child, f"{pointer}/{index}"))
        return tuple(pointers)
    if pointer == "" and isinstance(value, (Mapping, list)):
        return ()
    return (pointer,)


def _pointer_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise InteractionEvaluationError("pointer collection must be a sequence")
    pointers: list[str] = []
    for pointer in value:
        if not isinstance(pointer, str):
            raise InteractionEvaluationError("pointer collection entries must be strings")
        _pointer_tokens(pointer)
        pointers.append(pointer)
    return tuple(pointers)


def _request_binding_value(binding: Mapping[str, object], state: Mapping[str, JsonValue]) -> object:
    source_kind = binding.get("source_kind")
    if source_kind == "trusted_context":
        raise InteractionEvaluationError("request binding source is not provisioned")
    if source_kind == "literal":
        if "literal_value" not in binding:
            raise InteractionEvaluationError("request binding literal is not provisioned")
        value: object = binding["literal_value"]
    else:
        source_pointer = binding.get("source_pointer")
        if not isinstance(source_pointer, str):
            raise InteractionEvaluationError("request binding source is not provisioned")
        value = _read_pointer(state, source_pointer)

    cardinality = binding.get("cardinality")
    if cardinality not in {"one", "optional", "many"}:
        raise InteractionEvaluationError("request binding cardinality is not provisioned")
    if value is _MISSING:
        if cardinality == "optional":
            return _MISSING
        raise InteractionEvaluationError("request binding source is not provisioned")
    if cardinality == "many" and not isinstance(value, list):
        raise InteractionEvaluationError("request binding cardinality is not provisioned")
    if cardinality == "one" and isinstance(value, list):
        raise InteractionEvaluationError("request binding cardinality is not provisioned")
    if cardinality == "many":
        assert isinstance(value, list)
        return [_apply_input_mapping(item, binding.get("mapping")) for item in value]
    return _apply_input_mapping(value, binding.get("mapping"))


def _apply_input_mapping(value: object, mapping_value: object) -> object:
    if mapping_value is None:
        return value
    if not isinstance(mapping_value, Mapping):
        raise InteractionEvaluationError("request binding transform is not provisioned")
    kind = mapping_value.get("kind")
    allowed = {
        "identity",
        "date",
        "datetime",
        "enum",
        "identifier",
        "locale",
        "null",
        "number",
        "text",
    }
    if kind not in allowed:
        raise InteractionEvaluationError("request binding transform is not provisioned")
    value_mapping = mapping_value.get("mapping", {})
    if not isinstance(value_mapping, Mapping):
        raise InteractionEvaluationError("request binding transform is not provisioned")
    if value_mapping:
        key = _mapping_key(value)
        if key not in value_mapping:
            raise InteractionEvaluationError("request binding transform is not provisioned")
        value = value_mapping[key]
    elif kind == "enum":
        raise InteractionEvaluationError("request binding transform is not provisioned")

    type_valid = (
        kind == "identity"
        or (kind in {"date", "datetime", "identifier", "locale", "text"} and isinstance(value, str))
        or (kind == "null" and value is None)
        or (kind == "number" and isinstance(value, (int, float)) and not isinstance(value, bool))
        or kind == "enum"
    )
    if not type_valid:
        raise InteractionEvaluationError("request binding transform is not provisioned")
    return value


def _mapping_key(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value, allow_nan=False)
    raise InteractionEvaluationError("request binding transform is not provisioned")


def _project_result_fields(source: object, field_pointers: Sequence[object]) -> JsonValue:
    if not isinstance(source, Mapping):
        raise InteractionEvaluationError("result item is not provisioned")
    mapped: dict[str, JsonValue] = {}
    for pointer in field_pointers:
        if not isinstance(pointer, str):
            raise InteractionEvaluationError("result field pointer must be a string")
        value = _read_pointer(source, pointer)
        if value is _MISSING:
            raise InteractionEvaluationError("result field is not provisioned")
        _write_pointer(mapped, pointer, cast(JsonValue, copy.deepcopy(value)))
    return mapped


def _project_options(
    source: Mapping[str, object], response: JsonValue
) -> list[dict[str, JsonValue]]:
    items_pointer = source.get("items_pointer")
    value_pointer = source.get("value_pointer")
    label_pointer = source.get("label_pointer")
    disabled_pointer = source.get("disabled_pointer")
    group_pointer = source.get("group_pointer")
    if not all(isinstance(pointer, str) for pointer in (value_pointer, label_pointer)):
        raise InteractionEvaluationError("option projection pointers must be strings")
    items: object
    if items_pointer is None:
        items = response
    elif isinstance(items_pointer, str) and isinstance(response, Mapping):
        items = _read_pointer(response, items_pointer)
    else:
        raise InteractionEvaluationError("option items pointer cannot resolve")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise InteractionEvaluationError("option items must be a sequence")
    projected: list[dict[str, JsonValue]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise InteractionEvaluationError("option item must be a mapping")
        mapped_item = cast(Mapping[str, JsonValue], item)
        value = _read_pointer(mapped_item, cast(str, value_pointer))
        label = _read_pointer(mapped_item, cast(str, label_pointer))
        if value is _MISSING or not isinstance(label, str):
            raise InteractionEvaluationError("option value and label must resolve")
        option: dict[str, JsonValue] = {
            "value": cast(JsonValue, copy.deepcopy(value)),
            "label": label,
        }
        if disabled_pointer is not None:
            if not isinstance(disabled_pointer, str):
                raise InteractionEvaluationError("option disabled pointer is not provisioned")
            disabled = _read_pointer(mapped_item, disabled_pointer)
            if not isinstance(disabled, bool):
                raise InteractionEvaluationError("option disabled value is not provisioned")
            option["disabled"] = disabled
        if group_pointer is not None:
            if not isinstance(group_pointer, str):
                raise InteractionEvaluationError("option group pointer is not provisioned")
            group = _read_pointer(mapped_item, group_pointer)
            if not isinstance(group, str):
                raise InteractionEvaluationError("option group value is not provisioned")
            option["group"] = group
        projected.append(option)
    return projected


def _pagination_response(source: Mapping[str, object], response: JsonValue) -> JsonValue | None:
    pagination = source.get("pagination", {"mode": "none"})
    if not isinstance(pagination, Mapping):
        raise InteractionEvaluationError("option pagination must be a mapping")
    if pagination.get("mode") == "none":
        return None
    response_pointer = pagination.get("response_pointer")
    if (
        not isinstance(response, Mapping)
        or not isinstance(response_pointer, str)
        or _read_pointer(response, response_pointer) is _MISSING
    ):
        raise InteractionEvaluationError("option pagination response pointer must resolve")
    return cast(JsonValue, copy.deepcopy(_read_pointer(response, response_pointer)))


__all__ = [
    "MAX_CONDITION_DEPTH",
    "MAX_CONDITION_NODES",
    "HeadlessInteractionEvaluator",
    "InteractionCaller",
    "InteractionCallerError",
    "InteractionEvaluationError",
    "evaluate_condition",
]
