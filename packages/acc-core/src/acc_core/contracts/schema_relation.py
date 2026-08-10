"""Sound, conservative subset checks for the supported JSON Schema vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from jsonschema import Draft202012Validator

from acc_core.models import JsonObject


class SchemaRelation(StrEnum):
    """Whether one schema is proven to accept a subset of another schema."""

    PROVEN = "proven"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RelationFinding:
    """One deterministic reason a subset relation failed or was undecidable."""

    pointer: str
    message: str


@dataclass(frozen=True, slots=True)
class RelationReport:
    """Tri-state schema relation with stable, declaration-side findings."""

    relation: SchemaRelation
    findings: tuple[RelationFinding, ...] = ()


_ANNOTATION_KEYWORDS = frozenset(
    {
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
_HANDLED_KEYWORDS = frozenset(
    {
        "$ref",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "oneOf",
        "properties",
        "required",
        "type",
    }
)


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _child(pointer: str, token: str) -> str:
    return f"{pointer}/{_escape(token)}"


def _finding(relation: SchemaRelation, pointer: str, message: str) -> RelationReport:
    return RelationReport(relation, (RelationFinding(pointer or "", message),))


def _combine(reports: list[RelationReport]) -> RelationReport:
    relation = SchemaRelation.PROVEN
    findings: list[RelationFinding] = []
    seen: set[tuple[str, str]] = set()
    for report in reports:
        if report.relation is SchemaRelation.CONFLICT:
            relation = SchemaRelation.CONFLICT
        elif report.relation is SchemaRelation.UNKNOWN and relation is SchemaRelation.PROVEN:
            relation = SchemaRelation.UNKNOWN
        for finding in report.findings:
            identity = (finding.pointer, finding.message)
            if identity not in seen:
                findings.append(finding)
                seen.add(identity)
    return RelationReport(relation, tuple(findings))


def _resolve_local_ref(root: JsonObject, reference: object) -> object | None:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    current: object = root
    for raw_token in reference[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            return None
        current = current[token]
    return current


def _types(schema: dict[str, Any]) -> frozenset[str] | None:
    value = schema.get("type")
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    return None


def _contains_reference(value: object) -> bool:
    if isinstance(value, dict):
        return "$ref" in value or any(_contains_reference(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_reference(item) for item in value)
    return False


def _compare_finite_left(
    left: dict[str, Any], right: dict[str, Any], pointer: str
) -> RelationReport | None:
    if "const" in left:
        candidates = [left["const"]]
    elif isinstance(left.get("enum"), list):
        candidates = left["enum"]
    else:
        return None
    if _contains_reference(left) or _contains_reference(right):
        return None
    left_validator = Draft202012Validator(left)
    right_validator = Draft202012Validator(right)
    possible = [candidate for candidate in candidates if left_validator.is_valid(candidate)]
    rejected = [candidate for candidate in possible if not right_validator.is_valid(candidate)]
    if not rejected:
        return RelationReport(SchemaRelation.PROVEN)
    return _finding(
        SchemaRelation.CONFLICT,
        pointer,
        "declared schema rejects a value permitted by the finite left schema",
    )


def _compare_types(left: dict[str, Any], right: dict[str, Any], pointer: str) -> RelationReport:
    left_types = _types(left)
    right_types = _types(right)
    if right_types is None:
        return RelationReport(SchemaRelation.PROVEN)
    if left_types is None:
        return _finding(
            SchemaRelation.UNKNOWN,
            _child(pointer, "type"),
            "left schema has no type bound that proves the declared type constraint",
        )
    if all(
        left_type in right_types or (left_type == "integer" and "number" in right_types)
        for left_type in left_types
    ):
        return RelationReport(SchemaRelation.PROVEN)
    return _finding(
        SchemaRelation.CONFLICT,
        _child(pointer, "type"),
        "left schema permits JSON types rejected by the declared schema",
    )


def _compare_lower_bound(
    left: dict[str, Any], right: dict[str, Any], keyword: str, pointer: str
) -> RelationReport:
    right_value = right.get(keyword)
    if not isinstance(right_value, (int, float)) or isinstance(right_value, bool):
        return RelationReport(SchemaRelation.PROVEN)
    left_value = left.get(keyword)
    if not isinstance(left_value, (int, float)) or isinstance(left_value, bool):
        return _finding(
            SchemaRelation.CONFLICT,
            _child(pointer, keyword),
            f"left schema has no {keyword} bound",
        )
    if left_value >= right_value:
        return RelationReport(SchemaRelation.PROVEN)
    return _finding(
        SchemaRelation.CONFLICT,
        _child(pointer, keyword),
        f"left schema {keyword} is less restrictive than the declared bound",
    )


def _compare_upper_bound(
    left: dict[str, Any], right: dict[str, Any], keyword: str, pointer: str
) -> RelationReport:
    right_value = right.get(keyword)
    if not isinstance(right_value, (int, float)) or isinstance(right_value, bool):
        return RelationReport(SchemaRelation.PROVEN)
    left_value = left.get(keyword)
    if not isinstance(left_value, (int, float)) or isinstance(left_value, bool):
        return _finding(
            SchemaRelation.CONFLICT,
            _child(pointer, keyword),
            f"left schema has no {keyword} bound",
        )
    if left_value <= right_value:
        return RelationReport(SchemaRelation.PROVEN)
    return _finding(
        SchemaRelation.CONFLICT,
        _child(pointer, keyword),
        f"left schema {keyword} exceeds the declared bound",
    )


def _numeric_bound(schema: dict[str, Any], *, lower: bool) -> tuple[int | float, bool, str] | None:
    inclusive_keyword = "minimum" if lower else "maximum"
    exclusive_keyword = "exclusiveMinimum" if lower else "exclusiveMaximum"
    candidates: list[tuple[int | float, bool, str]] = []
    for keyword, exclusive in (
        (inclusive_keyword, False),
        (exclusive_keyword, True),
    ):
        value = schema.get(keyword)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            candidates.append((value, exclusive, keyword))
    if not candidates:
        return None
    if lower:
        return max(candidates, key=lambda item: (item[0], item[1]))
    return min(candidates, key=lambda item: (item[0], not item[1]))


def _compare_numeric_bound(
    left: dict[str, Any], right: dict[str, Any], *, lower: bool, pointer: str
) -> RelationReport:
    right_bound = _numeric_bound(right, lower=lower)
    if right_bound is None:
        return RelationReport(SchemaRelation.PROVEN)
    left_bound = _numeric_bound(left, lower=lower)
    right_value, right_exclusive, right_keyword = right_bound
    if left_bound is None:
        return _finding(
            SchemaRelation.CONFLICT,
            _child(pointer, right_keyword),
            f"left schema has no {right_keyword} bound",
        )
    left_value, left_exclusive, _ = left_bound
    if lower:
        contained = left_value > right_value or (
            left_value == right_value and (not right_exclusive or left_exclusive)
        )
    else:
        contained = left_value < right_value or (
            left_value == right_value and (not right_exclusive or left_exclusive)
        )
    if contained:
        return RelationReport(SchemaRelation.PROVEN)
    return _finding(
        SchemaRelation.CONFLICT,
        _child(pointer, right_keyword),
        "left numeric bound is less restrictive than the declared bound",
    )


def _compare_required(left: dict[str, Any], right: dict[str, Any], pointer: str) -> RelationReport:
    right_required = right.get("required", [])
    left_required = left.get("required", [])
    if not isinstance(right_required, list) or not all(
        isinstance(item, str) for item in right_required
    ):
        return _finding(SchemaRelation.UNKNOWN, _child(pointer, "required"), "invalid required")
    if not isinstance(left_required, list) or not all(
        isinstance(item, str) for item in left_required
    ):
        return _finding(SchemaRelation.UNKNOWN, _child(pointer, "required"), "invalid required")
    missing = sorted(set(right_required) - set(left_required))
    if not missing:
        return RelationReport(SchemaRelation.PROVEN)
    return _finding(
        SchemaRelation.CONFLICT,
        _child(pointer, "required"),
        "left schema does not require declared properties: " + ", ".join(missing),
    )


def _additional_schema(schema: dict[str, Any]) -> object:
    return schema.get("additionalProperties", True)


def _compare_objects(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_root: JsonObject,
    right_root: JsonObject,
    pointer: str,
    visited: set[tuple[int, int]],
) -> list[RelationReport]:
    reports = [_compare_required(left, right, pointer)]
    left_properties = left.get("properties", {})
    right_properties = right.get("properties", {})
    if not isinstance(left_properties, dict) or not isinstance(right_properties, dict):
        return [
            _finding(
                SchemaRelation.UNKNOWN,
                _child(pointer, "properties"),
                "properties comparison is not decidable",
            )
        ]
    left_additional = _additional_schema(left)
    right_additional = _additional_schema(right)

    for name, right_property in sorted(right_properties.items()):
        left_property = left_properties.get(name, left_additional)
        if left_property is False:
            continue
        reports.append(
            _compare(
                left_property,
                right_property,
                left_root=left_root,
                right_root=right_root,
                pointer=_child(_child(pointer, "properties"), name),
                visited=visited,
            )
        )

    for name, left_property in sorted(left_properties.items()):
        if name in right_properties:
            continue
        if right_additional is False:
            reports.append(
                _finding(
                    SchemaRelation.CONFLICT,
                    _child(pointer, "additionalProperties"),
                    f"declared schema rejects left property: {name}",
                )
            )
        elif isinstance(right_additional, dict):
            reports.append(
                _compare(
                    left_property,
                    right_additional,
                    left_root=left_root,
                    right_root=right_root,
                    pointer=_child(_child(pointer, "properties"), name),
                    visited=visited,
                )
            )

    if right_additional is False and left_additional is not False:
        reports.append(
            _finding(
                SchemaRelation.CONFLICT,
                _child(pointer, "additionalProperties"),
                "left schema permits undeclared properties",
            )
        )
    elif isinstance(right_additional, dict) and left_additional is not False:
        reports.append(
            _compare(
                left_additional,
                right_additional,
                left_root=left_root,
                right_root=right_root,
                pointer=_child(pointer, "additionalProperties"),
                visited=visited,
            )
        )
    return reports


def _compare_combinations(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_root: JsonObject,
    right_root: JsonObject,
    pointer: str,
    visited: set[tuple[int, int]],
) -> RelationReport | None:
    for keyword in ("anyOf", "oneOf"):
        branches = left.get(keyword)
        if isinstance(branches, list):
            return _combine(
                [
                    _compare(
                        branch,
                        right,
                        left_root=left_root,
                        right_root=right_root,
                        pointer=pointer,
                        visited=visited,
                    )
                    for branch in branches
                ]
            )
    right_all = right.get("allOf")
    if isinstance(right_all, list):
        return _combine(
            [
                _compare(
                    left,
                    branch,
                    left_root=left_root,
                    right_root=right_root,
                    pointer=pointer,
                    visited=visited,
                )
                for branch in right_all
            ]
        )
    left_all = left.get("allOf")
    if isinstance(left_all, list):
        branch_reports = [
            _compare(
                branch,
                right,
                left_root=left_root,
                right_root=right_root,
                pointer=pointer,
                visited=visited,
            )
            for branch in left_all
        ]
        if any(report.relation is SchemaRelation.PROVEN for report in branch_reports):
            return RelationReport(SchemaRelation.PROVEN)
        return _finding(
            SchemaRelation.UNKNOWN,
            _child(pointer, "allOf"),
            "allOf intersection is not provably contained by the declared schema",
        )
    if "anyOf" in right or "oneOf" in right:
        return _finding(
            SchemaRelation.UNKNOWN,
            _child(pointer, "anyOf" if "anyOf" in right else "oneOf"),
            "declared union containment is not decidable for this schema",
        )
    return None


def _compare(
    left: object,
    right: object,
    *,
    left_root: JsonObject,
    right_root: JsonObject,
    pointer: str,
    visited: set[tuple[int, int]],
) -> RelationReport:
    if left is False or right is True:
        return RelationReport(SchemaRelation.PROVEN)
    if left is True:
        if right is False:
            return _finding(SchemaRelation.CONFLICT, pointer, "declared schema rejects all values")
        return _finding(
            SchemaRelation.UNKNOWN,
            pointer,
            "unbounded left schema cannot prove the declared constraint",
        )
    if right is False:
        return _finding(SchemaRelation.CONFLICT, pointer, "declared schema rejects all values")
    if not isinstance(left, dict) or not isinstance(right, dict):
        return _finding(SchemaRelation.UNKNOWN, pointer, "schema form is not comparable")
    if left == right:
        return RelationReport(SchemaRelation.PROVEN)

    pair = (id(left), id(right))
    if pair in visited:
        return RelationReport(SchemaRelation.PROVEN)
    visited.add(pair)

    if "$ref" in left or "$ref" in right:
        left_resolved = _resolve_local_ref(left_root, left.get("$ref")) if "$ref" in left else left
        right_resolved = (
            _resolve_local_ref(right_root, right.get("$ref")) if "$ref" in right else right
        )
        if left_resolved is None or right_resolved is None:
            return _finding(
                SchemaRelation.UNKNOWN,
                _child(pointer, "$ref"),
                "only resolvable local schema references can be compared",
            )
        left_siblings = set(left) - {"$ref"} - _ANNOTATION_KEYWORDS
        right_siblings = set(right) - {"$ref"} - _ANNOTATION_KEYWORDS
        if left_siblings or right_siblings:
            return _finding(
                SchemaRelation.UNKNOWN,
                _child(pointer, "$ref"),
                "schema references with assertion siblings are not decidable",
            )
        return _compare(
            left_resolved,
            right_resolved,
            left_root=left_root,
            right_root=right_root,
            pointer=pointer,
            visited=visited,
        )

    unsupported = sorted((set(left) | set(right)) - _HANDLED_KEYWORDS - _ANNOTATION_KEYWORDS)
    if unsupported:
        keyword = unsupported[0]
        return _finding(
            SchemaRelation.UNKNOWN,
            _child(pointer, keyword),
            f"schema keyword is not supported by the conservative comparator: {keyword}",
        )

    combination = _compare_combinations(
        left,
        right,
        left_root=left_root,
        right_root=right_root,
        pointer=pointer,
        visited=visited,
    )
    if combination is not None:
        return combination

    finite = _compare_finite_left(left, right, pointer)
    if finite is not None:
        return finite

    reports = [_compare_types(left, right, pointer)]
    reports.append(_compare_numeric_bound(left, right, lower=True, pointer=pointer))
    reports.append(_compare_numeric_bound(left, right, lower=False, pointer=pointer))
    for keyword in ("minLength", "minItems"):
        reports.append(_compare_lower_bound(left, right, keyword, pointer))
    for keyword in ("maxLength", "maxItems"):
        reports.append(_compare_upper_bound(left, right, keyword, pointer))

    if "const" in right and left.get("const", object()) != right["const"]:
        reports.append(
            _finding(
                SchemaRelation.CONFLICT,
                _child(pointer, "const"),
                "left schema does not prove the declared constant",
            )
        )
    if "enum" in right:
        left_values = left.get("enum")
        right_values = right.get("enum")
        if not isinstance(left_values, list) or not isinstance(right_values, list):
            reports.append(
                _finding(
                    SchemaRelation.UNKNOWN,
                    _child(pointer, "enum"),
                    "enum containment is not decidable",
                )
            )
        elif any(value not in right_values for value in left_values):
            reports.append(
                _finding(
                    SchemaRelation.CONFLICT,
                    _child(pointer, "enum"),
                    "left enum contains values rejected by the declared enum",
                )
            )

    left_types = _types(left) or frozenset()
    right_types = _types(right) or frozenset()
    if "object" in left_types or "object" in right_types:
        reports.extend(
            _compare_objects(
                left,
                right,
                left_root=left_root,
                right_root=right_root,
                pointer=pointer,
                visited=visited,
            )
        )
    if "array" in left_types or "array" in right_types:
        left_items = left.get("items", True)
        right_items = right.get("items", True)
        reports.append(
            _compare(
                left_items,
                right_items,
                left_root=left_root,
                right_root=right_root,
                pointer=_child(pointer, "items"),
                visited=visited,
            )
        )

    return _combine(reports)


def _compare_subset(left: JsonObject, right: JsonObject) -> RelationReport:
    return _compare(
        left,
        right,
        left_root=left,
        right_root=right,
        pointer="",
        visited=set(),
    )


def compare_operation_input(declared: JsonObject, source: JsonObject) -> RelationReport:
    """Prove that the declared request is a subset of the source-accepted request."""

    return _compare_subset(declared, source)


def compare_operation_output(source: JsonObject, declared: JsonObject) -> RelationReport:
    """Prove that every source response is accepted by the declared output schema."""

    return _compare_subset(source, declared)


__all__ = [
    "RelationFinding",
    "RelationReport",
    "SchemaRelation",
    "compare_operation_input",
    "compare_operation_output",
]
