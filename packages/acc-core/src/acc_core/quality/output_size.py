"""Conservative static output-size estimates and capability budget diagnostics."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from pydantic import JsonValue

from acc_core.diagnostics import Diagnostic
from acc_core.models import JsonObject
from acc_core.quality.models import OutputBudget

_NON_ASSERTION_REF_SIBLINGS = frozenset(
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


@dataclass(frozen=True, slots=True)
class OutputSizeEstimate:
    """A proven canonical byte bound or stable pointers explaining uncertainty."""

    status: Literal["proven_bounded", "unknown"]
    max_bytes: int | None
    unknown_pointers: tuple[str, ...]


def canonical_json_bytes(value: object) -> bytes:
    """Serialize one result using the canonical convention shared with Runtime."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("value must be JSON-compatible for canonical encoding") from exc
    return encoded


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _child(pointer: str, token: str) -> str:
    return f"{pointer}/{_escape(token)}"


def _bounded(max_bytes: int) -> OutputSizeEstimate:
    return OutputSizeEstimate("proven_bounded", max_bytes, ())


def _unknown(*pointers: str) -> OutputSizeEstimate:
    return OutputSizeEstimate("unknown", None, tuple(sorted(set(pointers))))


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


def _largest_canonical(values: list[JsonValue], pointer: str) -> OutputSizeEstimate:
    sizes: list[int] = []
    for value in values:
        try:
            sizes.append(len(canonical_json_bytes(value)))
        except ValueError:
            return _unknown(pointer)
    if not sizes:
        return _bounded(0)
    return _bounded(max(sizes))


def _combine_union(estimates: list[OutputSizeEstimate]) -> OutputSizeEstimate:
    unknown_pointers = tuple(
        sorted({pointer for estimate in estimates for pointer in estimate.unknown_pointers})
    )
    if unknown_pointers:
        return _unknown(*unknown_pointers)
    bounds = [estimate.max_bytes for estimate in estimates if estimate.max_bytes is not None]
    return _bounded(max(bounds, default=0))


def _estimate_integer(schema: dict[str, object], pointer: str) -> OutputSizeEstimate:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if (
        not isinstance(minimum, int)
        or isinstance(minimum, bool)
        or not isinstance(maximum, int)
        or isinstance(maximum, bool)
    ):
        return _unknown(_child(pointer, "minimum"), _child(pointer, "maximum"))
    if minimum > maximum:
        return _bounded(0)
    return _bounded(max(len(str(minimum)), len(str(maximum))))


def _estimate_object(
    schema: dict[str, object],
    *,
    root: JsonObject,
    pointer: str,
    resolving: frozenset[str],
) -> OutputSizeEstimate:
    if schema.get("additionalProperties", True) is not False:
        return _unknown(_child(pointer, "additionalProperties"))
    pattern_properties = schema.get("patternProperties")
    if isinstance(pattern_properties, dict) and pattern_properties:
        return _unknown(_child(pointer, "patternProperties"))
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return _unknown(_child(pointer, "properties"))
    total = 2
    unknown_pointers: set[str] = set()
    for index, (name, property_schema) in enumerate(sorted(properties.items())):
        estimate = _estimate(
            property_schema,
            root=root,
            pointer=_child(_child(pointer, "properties"), str(name)),
            resolving=resolving,
        )
        unknown_pointers.update(estimate.unknown_pointers)
        if estimate.max_bytes is not None:
            total += len(canonical_json_bytes(str(name))) + 1 + estimate.max_bytes
            if index:
                total += 1
    if unknown_pointers:
        return _unknown(*unknown_pointers)
    return _bounded(total)


def _estimate_array(
    schema: dict[str, object],
    *,
    root: JsonObject,
    pointer: str,
    resolving: frozenset[str],
) -> OutputSizeEstimate:
    max_items = schema.get("maxItems")
    if not isinstance(max_items, int) or isinstance(max_items, bool) or max_items < 0:
        return _unknown(_child(pointer, "maxItems"))
    if max_items == 0 or schema.get("items") is False:
        return _bounded(2)
    item_estimate = _estimate(
        schema.get("items", True),
        root=root,
        pointer=_child(pointer, "items"),
        resolving=resolving,
    )
    if item_estimate.status == "unknown" or item_estimate.max_bytes is None:
        return item_estimate
    commas = max_items - 1
    return _bounded(2 + max_items * item_estimate.max_bytes + commas)


def _estimate(
    raw_schema: object,
    *,
    root: JsonObject,
    pointer: str,
    resolving: frozenset[str],
) -> OutputSizeEstimate:
    if raw_schema is False:
        return _bounded(0)
    if raw_schema is True or not isinstance(raw_schema, dict):
        return _unknown(pointer or "/type")
    if pointer and "$id" in raw_schema:
        # A nested $id starts a new schema resource. This conservative estimator
        # does not maintain a resource registry, so resolving its fragments
        # against the outer document root would be unsound.
        return _unknown(_child(pointer, "$id"))

    if "const" in raw_schema:
        value = raw_schema["const"]
        if value is not None and not isinstance(value, (bool, int, float, str, list, dict)):
            return _unknown(_child(pointer, "const"))
        return _largest_canonical([value], _child(pointer, "const"))
    enum = raw_schema.get("enum")
    if isinstance(enum, list):
        return _largest_canonical(enum, _child(pointer, "enum"))

    if "$ref" in raw_schema:
        reference = raw_schema.get("$ref")
        ref_pointer = _child(pointer, "$ref")
        assertion_siblings = set(raw_schema) - {"$ref"} - _NON_ASSERTION_REF_SIBLINGS
        if not isinstance(reference, str) or assertion_siblings or reference in resolving:
            return _unknown(ref_pointer)
        resolved = _resolve_local_ref(root, reference)
        if resolved is None:
            return _unknown(ref_pointer)
        return _estimate(
            resolved,
            root=root,
            pointer=pointer,
            resolving=resolving | {reference},
        )

    for keyword in ("anyOf", "oneOf"):
        branches = raw_schema.get(keyword)
        if isinstance(branches, list):
            return _combine_union(
                [
                    _estimate(
                        branch,
                        root=root,
                        pointer=_child(_child(pointer, keyword), str(index)),
                        resolving=resolving,
                    )
                    for index, branch in enumerate(branches)
                ]
            )
    all_of = raw_schema.get("allOf")
    if isinstance(all_of, list):
        if not all_of:
            return _unknown(_child(pointer, "allOf"))
        estimates = [
            _estimate(
                branch,
                root=root,
                pointer=_child(_child(pointer, "allOf"), str(index)),
                resolving=resolving,
            )
            for index, branch in enumerate(all_of)
        ]
        unknown_pointers = tuple(pointer for item in estimates for pointer in item.unknown_pointers)
        if unknown_pointers:
            return _unknown(*unknown_pointers)
        bounded = [item.max_bytes for item in estimates if item.max_bytes is not None]
        return _bounded(min(bounded, default=0))

    schema_type = raw_schema.get("type")
    if isinstance(schema_type, list) and all(isinstance(item, str) for item in schema_type):
        return _combine_union(
            [
                _estimate(
                    {**raw_schema, "type": item},
                    root=root,
                    pointer=pointer,
                    resolving=resolving,
                )
                for item in schema_type
            ]
        )
    if schema_type == "null":
        return _bounded(4)
    if schema_type == "boolean":
        return _bounded(5)
    if schema_type == "string":
        if raw_schema.get("format") == "binary":
            return _unknown(_child(pointer, "format"))
        max_length = raw_schema.get("maxLength")
        if not isinstance(max_length, int) or isinstance(max_length, bool) or max_length < 0:
            return _unknown(_child(pointer, "maxLength"))
        return _bounded(2 + 6 * max_length)
    if schema_type == "integer":
        return _estimate_integer(raw_schema, pointer)
    if schema_type == "number":
        return _unknown(_child(pointer, "type"))
    if schema_type == "array":
        return _estimate_array(raw_schema, root=root, pointer=pointer, resolving=resolving)
    if schema_type == "object":
        return _estimate_object(raw_schema, root=root, pointer=pointer, resolving=resolving)
    return _unknown(_child(pointer, "type"))


def estimate_output_size(schema: JsonObject) -> OutputSizeEstimate:
    """Estimate a safe upper bound for canonical JSON output without adding constraints."""

    return _estimate(schema, root=schema, pointer="", resolving=frozenset())


def analyze_output_budget(
    capability_id: str,
    output_schema: JsonObject,
    budget: OutputBudget,
    *,
    capability_path: str | None = None,
    quality_path: str | None = None,
) -> tuple[Diagnostic, ...]:
    """Report unknown/exceeded bounds and unacknowledged long-text disclosure."""

    capability_document = capability_path or f"capabilities/{capability_id}.yaml"
    quality_document = quality_path or f"capability-quality/{capability_id}.yaml"
    estimate = estimate_output_size(output_schema)
    diagnostics: list[Diagnostic] = []
    if estimate.status == "unknown":
        diagnostics.extend(
            Diagnostic(
                code="ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN",
                severity="warning",
                message="Capability output size has no proven static upper bound.",
                path=capability_document,
                pointer=f"/output_schema{pointer}",
            )
            for pointer in estimate.unknown_pointers
        )
    elif estimate.max_bytes is not None and estimate.max_bytes > budget.max_bytes:
        diagnostics.append(
            Diagnostic(
                code="ACC_CAPABILITY_OUTPUT_BUDGET_EXCEEDED",
                severity="warning",
                message="Capability static output bound exceeds its declared byte budget.",
                path=quality_document,
                pointer="/output_budget/max_bytes",
            )
        )
    diagnostics.extend(
        Diagnostic(
            code="ACC_CAPABILITY_LONG_TEXT_DISCLOSURE_UNACKNOWLEDGED",
            severity="error",
            message="Long-text output disclosure requires explicit acknowledgement.",
            path=quality_document,
            pointer=f"/output_budget/long_text_disclosures/{index}/acknowledged",
        )
        for index, disclosure in enumerate(budget.long_text_disclosures)
        if not disclosure.acknowledged
    )
    return tuple(
        sorted(
            diagnostics,
            key=lambda item: (item.path or "", item.pointer or "", item.code),
        )
    )


__all__ = [
    "OutputSizeEstimate",
    "analyze_output_budget",
    "canonical_json_bytes",
    "estimate_output_size",
]
