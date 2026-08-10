"""Data-only reference evaluator for platform-neutral interaction contracts."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import JsonValue

from acc_testkit.interactions.models import InteractionTraceEntry

_MISSING = object()
_SUBMISSION_POLICIES = frozenset({"omit", "send", "send_if_changed"})


class InteractionEvaluationError(ValueError):
    """A stable failure for malformed or unsafe interaction input."""


class HeadlessInteractionEvaluator:
    """Evaluate deterministic field state without depending on a UI framework."""

    def __init__(
        self,
        contract: Mapping[str, object],
        *,
        initial_values: Mapping[str, JsonValue],
        principal_id: str,
        tenant_id: str,
        identity_salt: bytes,
    ) -> None:
        principal_id = _exact_identity(principal_id, "principal_id")
        tenant_id = _exact_identity(tenant_id, "tenant_id")
        if not isinstance(identity_salt, bytes) or not identity_salt:
            raise InteractionEvaluationError("identity_salt must be nonempty bytes")
        self._principal_digest = _identity_digest(identity_salt, "principal", principal_id)
        self._tenant_digest = _identity_digest(identity_salt, "tenant", tenant_id)
        principal_id = ""
        tenant_id = ""
        fields = contract.get("fields")
        if not isinstance(fields, Mapping):
            raise InteractionEvaluationError("interaction contract fields must be a mapping")
        self._fields: dict[str, Mapping[str, object]] = {}
        for pointer, definition in fields.items():
            if not isinstance(pointer, str) or not isinstance(definition, Mapping):
                raise InteractionEvaluationError("interaction fields must map pointers to mappings")
            _pointer_tokens(pointer)
            policy = definition.get("submission", "send")
            if policy not in _SUBMISSION_POLICIES:
                raise InteractionEvaluationError("unsupported submission policy")
            self._fields[pointer] = definition

        self._values = copy.deepcopy(dict(initial_values))
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
        self._options: dict[str, tuple[dict[str, JsonValue], ...]] = {}
        self._record("initialized")

    @property
    def values(self) -> dict[str, JsonValue]:
        return copy.deepcopy(self._values)

    @property
    def trace(self) -> tuple[InteractionTraceEntry, ...]:
        return tuple(self._trace)

    def set_value(self, field: str, value: JsonValue) -> None:
        self._require_field(field)
        _write_pointer(self._values, field, copy.deepcopy(value))
        self._record("value_changed", field=field)

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
    ) -> tuple[str, str, str, str]:
        self._require_field(field)
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
        return self._principal_digest, self._tenant_digest, field, canonical_request

    def _require_field(self, field: str) -> None:
        if field not in self._fields:
            raise InteractionEvaluationError("interaction field is not declared")

    def _record(
        self,
        event: str,
        *,
        field: str | None = None,
        generation: int | None = None,
    ) -> None:
        self._trace.append(
            InteractionTraceEntry.model_validate(
                {
                    "event": event,
                    "state": copy.deepcopy(self._values),
                    "field": field,
                    "generation": generation,
                }
            )
        )


def evaluate_condition(condition: Mapping[str, object], state: Mapping[str, JsonValue]) -> bool:
    """Evaluate an allowlisted condition AST without evaluating source code."""

    operator = condition.get("operator")
    if operator in {"all", "any"}:
        _require_keys(condition, {"operator", "operands"})
        operands = condition.get("operands")
        if not isinstance(operands, Sequence) or isinstance(operands, (str, bytes)):
            raise InteractionEvaluationError("condition operands must be a sequence")
        if not operands:
            raise InteractionEvaluationError("condition operands must be nonempty")
        values = [evaluate_condition(_condition(item), state) for item in operands]
        return all(values) if operator == "all" else any(values)
    if operator == "not":
        _require_keys(condition, {"operator", "operand"})
        return not evaluate_condition(_condition(condition.get("operand")), state)
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


def _read_pointer(value: Mapping[str, JsonValue], pointer: str) -> object:
    current: object = value
    for token in _pointer_tokens(pointer):
        if not isinstance(current, Mapping) or token not in current:
            return _MISSING
        current = current[token]
    return current


def _write_pointer(target: dict[str, JsonValue], pointer: str, value: JsonValue) -> None:
    tokens = _pointer_tokens(pointer)
    current = target
    for token in tokens[:-1]:
        child = current.get(token)
        if child is None:
            mapped: dict[str, JsonValue] = {}
            current[token] = mapped
            current = mapped
            continue
        if not isinstance(child, dict):
            raise InteractionEvaluationError("interaction field crosses a non-object value")
        current = child
    current[tokens[-1]] = value


__all__ = [
    "HeadlessInteractionEvaluator",
    "InteractionEvaluationError",
    "evaluate_condition",
]
