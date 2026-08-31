"""Bounded, platform-neutral condition expressions for interaction contracts."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, JsonValue, ValidatorFunctionWrapHandler, WrapValidator

from acc_core.contracts import JsonPointer
from acc_core.models import StrictModel

MAX_CONDITION_DEPTH = 64
MAX_CONDITION_NODES = 4_096


class ExpressionModel(StrictModel):
    """Frozen base for inert condition AST nodes."""

    model_config = ConfigDict(frozen=True)


class ReferenceOperand(ExpressionModel):
    """Read one declared value by an absolute JSON Pointer."""

    kind: Literal["reference"]
    pointer: JsonPointer


class LiteralOperand(ExpressionModel):
    """Use one inert JSON-compatible literal in a condition."""

    kind: Literal["literal"]
    value: JsonValue


type ConditionOperand = Annotated[
    ReferenceOperand | LiteralOperand,
    Field(discriminator="kind"),
]


class AllExpression(ExpressionModel):
    """Require every nested safe expression to hold."""

    operator: Literal["all"]
    operands: Annotated[list[ConditionExpression], Field(min_length=1)]


class AnyExpression(ExpressionModel):
    """Require at least one nested safe expression to hold."""

    operator: Literal["any"]
    operands: Annotated[list[ConditionExpression], Field(min_length=1)]


class NotExpression(ExpressionModel):
    """Negate one nested safe expression."""

    operator: Literal["not"]
    operand: ConditionExpression


class ComparisonExpression(ExpressionModel):
    """Compare two safe operands without executing source code."""

    operator: Literal["eq", "ne", "in"]
    left: ConditionOperand
    right: ConditionOperand


class PresentExpression(ExpressionModel):
    """Test whether one safe operand is present."""

    operator: Literal["present"]
    operand: ConditionOperand


def _parse_condition_expression(value: object) -> object:
    """Parse a bounded expression without relying on pydantic-core recursion.

    Pydantic's recursive tagged-union validator has a lower implementation
    recursion ceiling than ACC's public 64-level condition budget on some
    releases.  Build the already-bounded tree bottom-up so the public contract
    remains stable across pydantic-core versions.
    """

    if isinstance(
        value,
        (AllExpression, AnyExpression, NotExpression, ComparisonExpression, PresentExpression),
    ):
        return value
    if not isinstance(value, dict):
        return value

    stack: list[tuple[dict[object, object], bool, int]] = [(value, False, 1)]
    parsed: dict[int, object] = {}
    total_nodes = 0
    while stack:
        node, visited, depth = stack.pop()
        if not visited:
            if depth > MAX_CONDITION_DEPTH:
                raise ValueError("condition expression exceeds maximum depth")
            total_nodes += 1
            if total_nodes > MAX_CONDITION_NODES:
                raise ValueError("condition expression exceeds maximum node count")
            operator = node.get("operator")
            stack.append((node, True, depth))
            if operator in {"all", "any"}:
                operands = node.get("operands")
                if isinstance(operands, list):
                    for child in reversed(operands):
                        if isinstance(child, dict):
                            stack.append((child, False, depth + 1))
            elif operator == "not":
                child = node.get("operand")
                if isinstance(child, dict):
                    stack.append((child, False, depth + 1))
            continue

        operator = node.get("operator")
        operands = node.get("operands")
        if operator in {"all", "any"} and isinstance(operands, list):
            children = [parsed.get(id(child), child) for child in operands]
            document = {**node, "operands": children}
            model = AllExpression if operator == "all" else AnyExpression
            parsed[id(node)] = model.model_validate(document)
        elif operator == "not" and isinstance(node.get("operand"), dict):
            parsed[id(node)] = NotExpression.model_validate(
                {**node, "operand": parsed.get(id(node["operand"]), node["operand"])}
            )
        elif operator in {"eq", "ne", "in"}:
            parsed[id(node)] = ComparisonExpression.model_validate(node)
        elif operator == "present":
            parsed[id(node)] = PresentExpression.model_validate(node)
        else:
            return value
    return parsed.get(id(value), value)


def _condition_expression_wrap(value: object, handler: ValidatorFunctionWrapHandler) -> object:
    parsed = _parse_condition_expression(value)
    if isinstance(
        parsed,
        (AllExpression, AnyExpression, NotExpression, ComparisonExpression, PresentExpression),
    ):
        return parsed
    return handler(parsed)


type ConditionExpression = Annotated[
    AllExpression | AnyExpression | NotExpression | ComparisonExpression | PresentExpression,
    Field(discriminator="operator"),
    WrapValidator(_condition_expression_wrap),
]


def iter_condition_references(expression: ConditionExpression) -> Iterator[str]:
    """Yield reference pointers from a validated condition without evaluating it."""

    if isinstance(expression, (AllExpression, AnyExpression)):
        for child in expression.operands:
            yield from iter_condition_references(child)
        return
    if isinstance(expression, NotExpression):
        yield from iter_condition_references(expression.operand)
        return
    if isinstance(expression, ComparisonExpression):
        for operand in (expression.left, expression.right):
            if isinstance(operand, ReferenceOperand):
                yield operand.pointer
        return
    if isinstance(expression.operand, ReferenceOperand):
        yield expression.operand.pointer


def validate_condition_complexity(expression: ConditionExpression) -> None:
    """Reject an AST beyond the fixed Core resource budget without recursion."""

    stack: list[tuple[ConditionExpression | ConditionOperand, int]] = [(expression, 1)]
    total_nodes = 0
    while stack:
        node, depth = stack.pop()
        if depth > MAX_CONDITION_DEPTH:
            raise ValueError("condition expression exceeds maximum depth")
        total_nodes += 1
        if total_nodes > MAX_CONDITION_NODES:
            raise ValueError("condition expression exceeds maximum node count")

        child_depth = depth + 1
        if isinstance(node, (AllExpression, AnyExpression)):
            stack.extend((operand, child_depth) for operand in reversed(node.operands))
        elif isinstance(node, NotExpression):
            stack.append((node.operand, child_depth))
        elif isinstance(node, ComparisonExpression):
            stack.append((node.right, child_depth))
            stack.append((node.left, child_depth))
        elif isinstance(node, PresentExpression):
            stack.append((node.operand, child_depth))


for _expression_model in (AllExpression, AnyExpression, NotExpression):
    _expression_model.model_rebuild(_types_namespace={"ConditionExpression": ConditionExpression})


__all__ = [
    "MAX_CONDITION_DEPTH",
    "MAX_CONDITION_NODES",
    "AllExpression",
    "AnyExpression",
    "ComparisonExpression",
    "ConditionExpression",
    "ConditionOperand",
    "LiteralOperand",
    "NotExpression",
    "PresentExpression",
    "ReferenceOperand",
    "iter_condition_references",
    "validate_condition_complexity",
]
